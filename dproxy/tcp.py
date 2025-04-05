# Copyright 2024 Dhiego Cassiano Fogaça Barbosa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from asyncio import Semaphore, wait_for
from collections.abc import Callable
import logging
import os
from queue import Queue
from select import select, error as SelectError
from socket import socket
from socketserver import ThreadingTCPServer, BaseRequestHandler
from time import time
from threading import Event
from typing import Any, override, Self

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from dproxy.crypt.aesgcm import aes_gcm_encrypt, aes_gcm_decrypt
from dproxy import (
    DProxyPacketType,
    DProxyError,
    DProxyHeader,
    DProxyHandshakeInit,
    DProxyHandshakeResponse,
    DProxyHandshakeFinal,
    DProxyHandshakeFinalized,
    DProxyConnect,
    DProxyConnected,
    DProxyDisconnect,
    DProxyDisconnected,
    DProxyData,
    DProxyHeartbeat,
    DProxyHeartbeatResponse,
    DProxyErrorPacket,
    recv_or_none
)


logger = logging.getLogger(__name__)


class DProxyConnectionWrapper:
    clients: dict[str, tuple[socket, bytes, dict[int, tuple[Semaphore, Queue[bytes]]], dict[int, Event]]] = {}
    last_connection_id: dict[str, int] = {}

    def __init__(self, username: str, sock: socket, connection_id: int) -> None:
        self.username = username
        self.sock = sock
        self.connection_id = connection_id

    def is_alive(self) -> bool:
        return self.is_connected(self.username, self.connection_id)

    async def read(self, timeout: float | None = None) -> bytes | None:
        if self.username not in DProxyConnectionWrapper.clients:
            raise ValueError("DProxyClient not connected.")

        _, _, recv, _ = DProxyConnectionWrapper.clients[self.username]
        if self.connection_id not in recv:
            raise ValueError("Connection not established.")

        await wait_for(recv[self.connection_id][0].acquire(), timeout)

        if not self.is_alive():
            raise ConnectionError("Connection closed.")

        return recv[self.connection_id][1].get_nowait()

    def write(self, data: bytes) -> None:
        if self.username not in DProxyConnectionWrapper.clients:
            raise ValueError("DProxyClient not connected.")

        sock, cek, _, _ = DProxyConnectionWrapper.clients[self.username]
        for chunk in [data[i:i + 32768] for i in range(0, len(data), 32768)]:
            iv = os.urandom(12)
            ciphertext, auth_tag = aes_gcm_encrypt(cek, iv, chunk)

            for attempt in range(5):
                try:
                    select([], [sock], [])
                    sock.send(DProxyData(1, DProxyPacketType.DATA, len(iv) + 2 + len(ciphertext) + len(auth_tag), DProxyError.NO_ERROR, self.connection_id, iv, ciphertext, auth_tag).to_bytes())
                    break
                except Exception as ex:
                    if attempt == 4:
                        raise ex

                    logger.exception("An error occurred while trying to send data to the client.", exc_info=ex)

    def close(self) -> None:
        if self.username not in DProxyConnectionWrapper.clients:
            raise ValueError("DProxyClient already disconnected.")

        sock, _, recv, _ = DProxyConnectionWrapper.clients[self.username]
        if self.connection_id not in recv:
            raise ValueError("Connection not established.")

        select([], [sock], [])
        sock.send(DProxyDisconnect(1, DProxyPacketType.DISCONNECT, 4, DProxyError.NO_ERROR, self.connection_id).to_bytes())
        recv[self.connection_id][0].release()
        del recv[self.connection_id]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.close()
        except Exception as ex:
            logger.exception("An error occurred while closing the connection", exc_info=ex)

    @classmethod
    def is_connected(cls, username: str, connection_id: int) -> bool:
        if username not in cls.clients:
            return False

        return connection_id in cls.clients[username][2]

    @classmethod
    def connect_to(cls, username: str, host: str, port: int, timeout: float | None = None) -> Self:
        if username not in cls.clients:
            raise ValueError("DProxyClient not connected.")

        sock, _, _, conn_event = cls.clients[username]
        connection_id = cls.get_next_connection_id(username)
        select([], [sock], [])
        sock.send(DProxyConnect(1, DProxyPacketType.CONNECT, 4 + 2 + len(host) + 2, DProxyError.NO_ERROR, connection_id, host, port).to_bytes())

        conn_event[connection_id] = Event()

        if not conn_event[connection_id].wait(timeout):
            raise TimeoutError("Timeout while waiting for connection.")

        del conn_event[connection_id]

        return cls(username, sock, connection_id)

    @classmethod
    def get_next_connection_id(cls, username: str) -> int:
        if username not in cls.last_connection_id:
            cls.last_connection_id[username] = 0

        cls.last_connection_id[username] += 1
        return cls.last_connection_id[username]


class DProxyTCPServer(ThreadingTCPServer):
    daemon_threads = True
    stop_event: Event
    handshake_hook: Callable[[DProxyHandshakeInit], str | None]
    private_key: ec.EllipticCurvePrivateKey
    ticks: int = 0

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseRequestHandler],
        event: Event,
        handshake_hook: Callable[[DProxyHandshakeInit], str | None],
        private_key: ec.EllipticCurvePrivateKey,
        bind_and_activate: bool = True,
        *args, **kwargs
    ):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate, *args, **kwargs)
        self.stop_event = event
        self.handshake_hook = handshake_hook
        self.private_key = private_key

        logger.info(f"TCP listening on {self.server_address[0]}:{self.server_address[1]}")

    @override
    def server_close(self) -> None:
        super().server_close()
        logger.info("Closing TCP server...")
        try:
            for username, (sock, _, _, _) in DProxyConnectionWrapper.clients.items():
                sock.close()

            DProxyConnectionWrapper.clients.clear()
            DProxyConnectionWrapper.last_connection_id.clear()
        except Exception as ex:
            logger.exception("An error occurred while closing the TCP server", exc_info=ex)

    @override
    def service_actions(self) -> None:
        try:
            if self.stop_event.is_set():
                return

            self.ticks += 1

            if self.ticks % 10 == 0:
                self.ticks = 0
                to_delete: list[str] = []
                for username, (sock, _, _, _) in DProxyConnectionWrapper.clients.items():
                    try:
                        # Send a heartbeat packet to the client
                        select([], [sock], [])
                        sock.send(DProxyHeartbeat(1, DProxyPacketType.HEARTBEAT, 8, DProxyError.NO_ERROR, round(time() * 1000)).to_bytes())
                    except ConnectionError:
                        sock.close()
                        to_delete.append(username)
                    except Exception as ex:
                        logger.exception("An error occurred while sending the heartbeat packet", exc_info=ex)
                        sock.close()
                        to_delete.append(username)

                for username in to_delete:
                    del DProxyConnectionWrapper.clients[username]
                    del DProxyConnectionWrapper.last_connection_id[username]
        except Exception as ex:
            logger.exception("An unexpected error occurred", exc_info=ex)


class TCPHandler(BaseRequestHandler):
    server: DProxyTCPServer
    client_address: tuple[str, int]
    request: socket
    cek: bytes
    iv: bytes
    plaintext: bytes
    auth_tag: bytes
    last_connection_id: int = 0
    username: str

    def __init__(self, request: socket | tuple[bytes, socket], client_address: Any, server: DProxyTCPServer) -> None:
        super().__init__(request, client_address, server)

    @override
    def handle(self) -> None:
        try:
            logger.debug(f"Connection from {self.client_address}")

            data = self.receive_data(5)
            if not data:
                return

            ok, response = self.process_handshake_init(data)
            self.send_packet(response)
            if not ok:
                return

            data = self.receive_data(5)
            if not data:
                return

            ok, response = self.process_handshake_finalization(data)
            self.send_packet(response)
            if not ok:
                return

            # Add the connection to the server connections map
            DProxyConnectionWrapper.clients[self.username] = (self.request, self.cek, {}, {})
            self.run_loop()
        except Exception as ex:
            logger.exception("An unexpected error occurred while handling the connection", exc_info=ex)

    def receive_data(self, max_length: int) -> bytes | None:
        """Receive data from the client with a maximum length."""
        return recv_or_none(self.request, max_length)

    def send_packet(self, packet: DProxyHeader | None) -> None:
        """Send data to the client."""
        if not packet:
            return

        select([], [self.request], [])
        self.request.send(packet.to_bytes())

    def process_handshake_init(self, data: bytes) -> tuple[bool, DProxyHandshakeResponse | DProxyErrorPacket]:
        """Process the initial handshake packet."""
        header = DProxyHeader.from_bytes(data)

        if header.version != 1:
            logger.debug("Invalid version")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_VERSION, "")

        if header.type != DProxyPacketType.HANDSHAKE_INIT:
            logger.debug("Invalid packet type")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_PACKET_TYPE, "")

        remaining_data = self.receive_data(header.length)
        if not remaining_data or len(remaining_data) != header.length:
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_PACKET_LENGTH, "")

        handshake_init = DProxyHandshakeInit.from_bytes(data + remaining_data)
        logger.debug(f"{handshake_init=}")

        if not handshake_init.public_key:
            logger.debug("Invalid handshake information")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_HANDSHAKE_INFO, "")

        if not (username := self.server.handshake_hook(handshake_init)):
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.HANDSHAKE_FAILED, "")

        self.username = username
        if username in DProxyConnectionWrapper.clients:
            # return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.ALREADY_AUTHENTICATED, 0, "")
            sock, _, recv, conn_event = DProxyConnectionWrapper.clients[username]
            try:
                sock.close()
                for _, (sem, _) in recv.items():
                    sem.release()
            except Exception as ex:
                logger.exception(f"An error occoured while closing previous connected {username} client", exc_info=ex)

        public_key: ec.EllipticCurvePublicKey = serialization.load_der_public_key(handshake_init.public_key) # type: ignore

        # Get the shared secret key and the content encryption key
        shared_secret = self.server.private_key.exchange(ec.ECDH(), public_key)
        self.cek = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"").derive(shared_secret)
        logger.debug(f"Shared secret key: {shared_secret.hex()}")
        logger.debug(f"CEK: {self.cek.hex()}")

        # Generate the required information for the handshake response.
        self.plaintext = os.urandom(1024)
        self.iv = os.urandom(12)
        ciphertext, self.auth_tag = aes_gcm_encrypt(self.cek, self.iv, self.plaintext)

        return True, DProxyHandshakeResponse(1, DProxyPacketType.HANDSHAKE_RESPONSE, len(self.iv) + 2 + len(ciphertext) + len(self.auth_tag), DProxyError.NO_ERROR, self.iv, ciphertext, self.auth_tag)

    def process_handshake_finalization(self, data: bytes) -> tuple[bool, DProxyHandshakeFinalized | DProxyErrorPacket]:
        """Process the finalization handshake packet."""
        header = DProxyHeader.from_bytes(data)

        if header.version != 1:
            logger.debug("Invalid version")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_VERSION, "")

        if header.type != DProxyPacketType.HANDSHAKE_FINAL:
            logger.debug("Invalid packet type")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_PACKET_TYPE, "")

        remaining_data = self.receive_data(header.length)
        if not remaining_data or len(remaining_data) != header.length:
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.INVALID_PACKET_LENGTH, "")

        handshake_final = DProxyHandshakeFinal.from_bytes(data + remaining_data)
        logger.debug(f"{handshake_final=}")

        if not handshake_final.plaintext:
            logger.debug("Invalid handshake information")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.HANDSHAKE_FAILED, "")

        if handshake_final.plaintext != self.plaintext:
            logger.debug("Invalid handshake information")
            return False, DProxyErrorPacket(1, DProxyPacketType.ERROR, 0, DProxyError.HANDSHAKE_FAILED, "")

        return True, DProxyHandshakeFinalized(1, DProxyPacketType.HANDSHAKE_FINALIZED, 0, DProxyError.NO_ERROR)

    def run_loop(self) -> None:
        while True:
            if self.server.stop_event.is_set():
                break

            if not self.username in DProxyConnectionWrapper.clients:
                break

            if self.request.fileno() == -1:
                break

            try:
                rlist, _, _ = select([self.request], [], [])
                if self.request in rlist: # Receive packets from the client
                    data = self.receive_data(5)
                    if not data:
                        break

                    header = DProxyHeader.from_bytes(data)

                    remaining_data = self.receive_data(header.length)
                    if not remaining_data:
                        break

                    recv = DProxyConnectionWrapper.clients[self.username][2]
                    conn_event = DProxyConnectionWrapper.clients[self.username][3]

                    if header.type == DProxyPacketType.CONNECTED: # New connection established
                        packet = DProxyConnected.from_bytes(data + remaining_data)
                        logger.debug(f"New connection established, connection_id: {packet.connection_id}")
                        recv[packet.connection_id] = (Semaphore(0), Queue())
                        conn_event[packet.connection_id].set()
                    elif header.type == DProxyPacketType.DISCONNECTED: # Connection closed
                        packet = DProxyDisconnected.from_bytes(data + remaining_data)
                        logger.debug(f"Connection closed, connection_id: {packet.connection_id}")
                        if packet.connection_id in recv:
                            sem = recv[packet.connection_id][0]
                            del recv[packet.connection_id]
                            sem.release()
                    elif header.type == DProxyPacketType.DATA: # Data received
                        packet = DProxyData.from_bytes(data + remaining_data)
                        # Decrypt the data
                        plaintext = aes_gcm_decrypt(self.cek, packet.iv, packet.ciphertext, packet.auth_tag)
                        # logger.debug(f"Data received, connection_id: {packet.connection_id}, data: {plaintext}")
                        if packet.connection_id in recv:
                            recv[packet.connection_id][1].put_nowait(plaintext)
                            recv[packet.connection_id][0].release()
                    elif header.type == DProxyPacketType.HEARTBEAT:
                        packet = DProxyHeartbeatResponse(1, DProxyPacketType.HEARTBEAT_RESPONSE, 8, DProxyError.NO_ERROR, round(time() * 1000))
                        self.send_packet(packet)
                    elif header.type == DProxyPacketType.HEARTBEAT_RESPONSE: # Heartbeat response
                        packet = DProxyHeartbeatResponse.from_bytes(data + remaining_data)
                        # logger.debug(f"Heartbeat response received: {packet.timestamp}")
                    elif header.type == DProxyPacketType.ERROR: # Error packet
                        packet = DProxyErrorPacket.from_bytes(data + remaining_data)
                        logger.debug(f"Error packet received: {packet.error_code}")
                    else:
                        logger.debug(f"Invalid packet type: {header.type}")
                        continue
            except ValueError as ex:
                logger.warning(f"Invalid packet received from {self.username}, ignoring...", exc_info=ex)
                continue
            except SelectError as ex:
                logger.exception("An error occurred while selecting the socket.", exc_info=ex)
                break
            except Exception as ex:
                logger.exception("An unexpected error occurred, ignoring...", exc_info=ex)
                continue

    @override
    def finish(self) -> None:
        if hasattr(self, "username") and self.username in DProxyConnectionWrapper.clients:
            logger.debug(f"Connection from {self.username} closed.")
            _, _, recv, conn_event = DProxyConnectionWrapper.clients[self.username]
            del DProxyConnectionWrapper.clients[self.username]

            for _, (sem, _) in recv.items():
                sem.release()

        return super().finish()
