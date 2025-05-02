# Copyright 2025 Dhiego Cassiano Fogaça Barbosa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
from argparse import ArgumentParser
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor
import logging
from os import getenv
from signal import SIGINT, SIGTERM, signal
from threading import Event
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import Response
import h11
from starlette.types import Receive, Send
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol, RequestResponseCycle

from dproxy import DProxyHandshakeInit
from dproxy.tcp import DProxyConnectionWrapper, DProxyTCPServer, TCPHandler
from dproxy.crypt.ec import read_private_key

from lib.db import connect_db, init_db, get_client, get_public_key
from lib.http import router
from lib.log import DisableLogFilter, configure_logging
from lib.utils import CustomFastAPI, ProxyHTTPSProtocol, mount_http_str


logger = logging.getLogger(__name__)
event = Event()
app = CustomFastAPI()
app.include_router(router)


async def _https_return(_scope: dict, _receive: Receive, _send: Send):
    conn: DProxyConnectionWrapper = _scope['conn']
    cycle: RequestResponseCycle = _scope['RequestResponseCycle']
    if cycle.response_started or cycle.conn.our_state == h11.ERROR:
        return

    # Switching protocols...
    cycle.response_started = True
    cycle.conn.send(h11.Response(status_code=200, headers=[], reason="Connection established", http_version=_scope['http_version']))
    cycle.transport.write(f"HTTP/{_scope['http_version']} 200 Connection established\r\n\r\n".encode('iso-8859-1'))
    h11_proto: H11Protocol = cycle.transport.get_protocol()  # type: ignore
    h11_proto.connections.discard(h11_proto)
    cycle.transport.set_protocol(ProxyHTTPSProtocol(logger, conn, cycle))
    conn.set_cycle(cycle)

    await _receive()
    while conn.is_alive():
        if cycle.disconnected:
            conn.close()
            return

        await asyncio.sleep(1)

    cycle.response_complete = True
    cycle.transport.close()


async def _http_return(_scope: dict, _receive: Receive, _send: Send):
    conn: DProxyConnectionWrapper = _scope['conn']
    cycle: RequestResponseCycle = _scope['RequestResponseCycle']
    if cycle.response_started or cycle.conn.our_state == h11.ERROR:
        return

    conn.set_cycle(cycle)

    await _receive()
    while conn.is_alive():
        if cycle.conn.our_state == h11.ERROR:
            break

        if cycle.disconnected:
            conn.close()
            return

        await asyncio.sleep(1)

    if conn.is_alive():
        conn.close()

    if cycle.response_started:
        await _send({"type": "http.response.body", "body": b"", "more_body": False})


@app.middleware("http")
async def proxy_handler(request: Request, call_next):
    if any(request.scope['path'].startswith(scheme) for scheme in ["http://", "ws://"]) or request.method == "CONNECT":
        # Proxy Request
        if not request.headers.get("Proxy-Authorization"):
            logger.debug("No Proxy-Authorization header found.")
            return Response(status_code=407, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

        scheme, credentials = request.headers["Proxy-Authorization"].split(" ", 1)
        if scheme != "Basic":
            logger.debug(f"Invalid scheme: {scheme}")
            return Response(status_code=407, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

        username, password = b64decode(credentials).decode('utf-8').split(":", 1)
        with connect_db() as db:
            if not (client := get_client(db, username)) or not client.enabled or password != app.http_proxy_password:
                logger.debug(f"Client {username} is not registered or the password {password} is invalid.")
                return Response(status_code=407, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

        if username not in DProxyConnectionWrapper.clients:
            logger.debug(f"Client {username} is not connected.")
            return Response(status_code=503, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

        if request.method == "CONNECT":
            # CONNECT method
            url = urlparse('https://' + request.scope['path'])
            if url.hostname:
                try:
                    conn = await DProxyConnectionWrapper.connect_to(username, url.hostname, url.port or 80, 30)
                except BrokenPipeError:
                    return Response(status_code=503, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})
                except TimeoutError:
                    return Response(status_code=504, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

                if request.scope['http_version'] != "1.1":
                    logger.debug(f"Invalid HTTP version: {request.scope['http_version']}")
                    return Response(status_code=505, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

                request.scope['conn'] = conn

                return _https_return

        # Client is authenticated, send the request to the queue and wait for the response
        url = urlparse(request.scope['path'])
        if url.hostname:
            http_req = mount_http_str(request, url).encode('utf-8')

            try:
                conn = await DProxyConnectionWrapper.connect_to(username, url.hostname, url.port or 80, 30)

                conn.write(http_req)
                async for chunk in request.stream():
                    conn.write(chunk)
            except BrokenPipeError:
                return Response(status_code=503, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})
            except TimeoutError:
                return Response(status_code=504, headers={"Proxy-Authenticate": "Basic realm=\"dproxy\""})

            request.scope['conn'] = conn

            return _http_return

    return await call_next(request)


def handshake_hook(handshake_init: DProxyHandshakeInit) -> str | None:
    with connect_db() as db:
        pub_key = get_public_key(db, handshake_init.public_key)
        if pub_key is None:
            logger.debug(f"Public key {handshake_init.public_key.hex()} not found.")
            return None

        if not pub_key.enabled:
            logger.debug(f"Public key {handshake_init.public_key.hex()} is disabled.")
            return None

        client = get_client(db, pub_key.client_id)
        if client is None or not client.enabled:
            logger.debug(f"Client {pub_key.client_id} not found or disabled.")
            return None

        return client.id


def start_tcp_server(server: DProxyTCPServer) -> None:
    with server:
        server.serve_forever()


async def main() -> None:
    arg_parser = ArgumentParser(description="DProxy Server")
    arg_parser.add_argument("--address", default=getenv("LISTEN_ADDRESS", "0.0.0.0"), type=str, help="The address to listen on")
    arg_parser.add_argument("--http-port", "-p", default=int(getenv("LISTEN_HTTP_PORT", 8080)), type=int, help="The port to listen on HTTP")
    arg_parser.add_argument("--tcp-port", "-P", default=int(getenv("LISTEN_TCP_PORT", 8081)), type=int, help="The port to listen on TCP")
    arg_parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    arg_parser.add_argument("--key-path", default=getenv("KEY_PATH", "./keys"), type=str, help="EC keys path")
    arg_parser.add_argument("--db-path", default=getenv("DB_PATH", "./db"), type=str, help="SQLite database path")

    args = arg_parser.parse_args()

    configure_logging(args.debug)

    signal(SIGINT, lambda sig, frame: event.set())
    signal(SIGTERM, lambda sig, frame: event.set())

    app.private_key = read_private_key(args.key_path)
    http_server = uvicorn.Server(uvicorn.Config(app, host=args.address, port=args.http_port))
    dproxy_server = DProxyTCPServer((args.address, args.tcp_port), TCPHandler, event, handshake_hook, app.private_key)
    init_db(args.db_path)

    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    uvicorn_access_logger.addFilter(DisableLogFilter())

    with ThreadPoolExecutor() as executor:
        http_future = executor.submit(http_server.run)
        tcp_future = executor.submit(start_tcp_server, dproxy_server)

        logger.info("Press Ctrl+C to exit.")
        try:
            while http_future.running() or tcp_future.running():
                if event.is_set():
                    http_server.should_exit = True
                    dproxy_server.server_close()
                    dproxy_server.shutdown()
                    break

                await asyncio.sleep(1)
        except KeyboardInterrupt:
            event.set()


if __name__ == "__main__":
    asyncio.run(main())
