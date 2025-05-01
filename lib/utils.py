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
from logging import Logger, getLogger
from urllib.parse import ParseResult

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
import jwt
from starlette.types import Receive, Send
from uvicorn.protocols.http.h11_impl import RequestResponseCycle

from dproxy.tcp import DProxyConnectionWrapper


class CustomFastAPI(FastAPI):
    logger = getLogger(__name__)
    private_key: ec.EllipticCurvePrivateKey
    '''
    Stores the private key used to establish the shared secret key with the clients.
    '''

    http_proxy_password: str = "__SUPER_SECRET_PASSWORD__"

    async def __call__(self, scope: dict, receive: Receive, send: Send) -> None:
        scope['RequestResponseCycle'] = send.__self__
        await super().__call__(scope, receive, send)


class CustomRequest(Request):
    app: CustomFastAPI


class PEMResponse(PlainTextResponse):
    media_type = "application/x-pem-file"
    charset    = 'utf-8'


class JWTBearer(HTTPBearer):
    async def __call__(self, request: CustomRequest) -> HTTPAuthorizationCredentials | None:
        auth_credentials = await super().__call__(request)
        if auth_credentials:
            token = auth_credentials.credentials
            if not (user := jwt.decode(token, algorithms=["ES384"], key=request.app.private_key.public_key())):
                raise HTTPException(401, "Invalid token")

            request.scope['user'] = user

        return auth_credentials


class ProxyHTTPSProtocol(asyncio.Protocol):
    def __init__(self, logger: Logger, conn: DProxyConnectionWrapper, cycle: RequestResponseCycle):
        self.logger = logger
        self.conn = conn
        self.cycle = cycle

    def data_received(self, data: bytes):
        # Send the request to the client
        self.logger.debug(f"Sending HTTPS data to the client: {len(data)} bytes.")
        try:
            self.conn.write(data)
        except:
            pass

    def connection_lost(self, exc):
        if self.cycle and not self.cycle.response_complete:
            self.cycle.disconnected = True

        try:
            self.conn.close()
        except:
            pass


def mount_http_str(request: Request, url: ParseResult) -> str:
    http_str = f"{request.method} {url.path if url.path else '/'}{'?' + request.url.query if request.url.query else ''} HTTP/{request.scope['http_version']}\r\n"
    headers = request.headers.mutablecopy()
    headers["Connection"] = "close"  # Always close the connection to avoid problems with the proxy client
    for header, value in headers.items():
        if header.lower() in ["proxy-authorization", "proxy-connection"]:
            continue

        http_str += f"{header}: {value}\r\n"
    http_str += "\r\n"

    return http_str
