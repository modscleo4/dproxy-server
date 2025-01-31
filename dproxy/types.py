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

from enum import IntEnum
from dataclasses import dataclass
from socket import socket
from struct import pack, unpack


class DProxyPacketType(IntEnum):
    HANDSHAKE_INIT = 0      # Client -> Server (start handshake)
    HANDSHAKE_RESPONSE = 1  # Server -> Client (response to handshake)
    HANDSHAKE_FINAL = 2     # Client -> Server (finish handshake)
    HANDSHAKE_FINALIZED = 3 # Server -> Client (handshake finalized)
    CONNECT = 4             # Server -> Client (start a TCP connection)
    CONNECTED = 5           # Client -> Server (connection established)
    DISCONNECT = 6          # Server -> Client (close a TCP connection)
    DISCONNECTED = 7        # Client -> Server (connection closed)
    DATA = 8                # Server <-> Client (data exchange)
    HEARTBEAT = 9           # Server <-> Client (keep connection alive)
    HEARTBEAT_RESPONSE = 10 # Server <-> Client (response to heartbeat)
    ERROR = 11              # Server <-> Client (error)


class DProxyError(IntEnum):
    NO_ERROR = 0
    INVALID_VERSION = 1
    INVALID_PACKET_TYPE = 2
    INVALID_PACKET_LENGTH = 3
    INVALID_HANDSHAKE_INFO = 4
    HANDSHAKE_FAILED = 5
    ALREADY_AUTHENTICATED = 6
    INVALID_DESTINATION = 7
    CONNECTION_FAILED = 8
    CONNECTION_CLOSED = 9
    CONNECTION_TIMEOUT = 10
    INVALID_CONNECTION = 11


@dataclass
class DProxyHeader:
    version: int            # protocol version
    type: DProxyPacketType  # packet type
    length: int             # payload length
    error_code: DProxyError # error code (or NO_ERROR)

    @classmethod
    def from_bytes(cls, data: bytes):
        version = unpack('>B', data[0:1])[0]
        type = DProxyPacketType(unpack('>B', data[1:2])[0])
        length = unpack('>H', data[2:4])[0]
        error_code = DProxyError(unpack('>B', data[4:5])[0])

        return cls(
            version=version,
            type=type,
            length=length,
            error_code=error_code
        )

    def to_bytes(self) -> bytes:
        return pack('>BBHB', self.version, self.type, self.length, self.error_code)


@dataclass
class DProxyHandshakeInit(DProxyHeader):
    """
    The client sends this packet to the server to start the handshake.
    """
    public_key: bytes # DER encoded public key

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        pk_len = unpack('>H', _data[0:2])[0]
        public_key = _data[2:2+pk_len]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            public_key=public_key
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>H', len(self.public_key)) + self.public_key


@dataclass
class DProxyHandshakeResponse(DProxyHeader):
    """
    The server sends this packet to the client in response to the handshake.
    """
    iv: bytes         # 12 bytes long
    ciphertext: bytes # encrypted data
    auth_tag: bytes   # 16 bytes long

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        iv = _data[0:12]
        ct_len = unpack('>H', _data[12:14])[0]
        ciphertext = _data[12+2:12+2+ct_len]
        auth_tag = _data[12+2+ct_len:12+2+ct_len+16]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            iv=iv,
            ciphertext=ciphertext,
            auth_tag=auth_tag
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + self.iv + pack('>H', len(self.ciphertext)) + self.ciphertext + self.auth_tag


@dataclass
class DProxyHandshakeFinal(DProxyHeader):
    """
    The client sends this packet to the server to finish the handshake.
    """
    plaintext: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        pt_len = unpack('>H', _data[0:2])[0]
        plaintext = _data[2:2+pt_len]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            plaintext=plaintext
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>H', len(self.plaintext)) + self.plaintext


@dataclass
class DProxyHandshakeFinalized(DProxyHeader):
    """
    The server sends this packet to the client to confirm the handshake.
    """


@dataclass
class DProxyConnect(DProxyHeader):
    """
    The server sends this packet to the client to start a TCP connection.
    """
    connection_id: int # connection identifier
    destination: str   # destination address (host, ipv4, ipv6)
    port: int          # destination port

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        connection_id = unpack('>I', _data[0:4])[0]
        dst_len = unpack('>H', _data[4:6])[0]
        destination = _data[6:6+dst_len].decode('utf-8')
        port = unpack('>H', _data[6+dst_len:6+dst_len+2])[0]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            connection_id=connection_id,
            destination=destination,
            port=port
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>L', self.connection_id) + pack('>H', len(self.destination)) + self.destination.encode('utf-8') + pack('>H', self.port)


@dataclass
class DProxyConnected(DProxyHeader):
    """
    The client sends this packet to the server to confirm the connection.
    """
    connection_id: int # connection identifier

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        connection_id = unpack('>I', _data[0:4])[0]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            connection_id=connection_id
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>I', self.connection_id)


@dataclass
class DProxyDisconnect(DProxyHeader):
    """
    The server sends this packet to the client to close a TCP connection.
    """
    connection_id: int # connection identifier

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        connection_id = unpack('>I', _data[0:4])[0]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            connection_id=connection_id
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>I', self.connection_id)


@dataclass
class DProxyDisconnected(DProxyHeader):
    """
    The client sends this packet to the server to confirm the disconnection.
    """
    connection_id: int # connection identifier

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        connection_id = unpack('>I', _data[0:4])[0]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            connection_id=connection_id
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>I', self.connection_id)


@dataclass
class DProxyData(DProxyHeader):
    """
    The server and the client use this packet to exchange data.
    """
    connection_id: int # connection identifier
    iv: bytes         # 12 bytes long
    ciphertext: bytes # encrypted data
    auth_tag: bytes   # 16 bytes long

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        connection_id = unpack('>I', _data[0:4])[0]
        iv = _data[4:4+12]
        ct_len = unpack('>H', _data[4+12:4+12+2])[0]
        ciphertext = _data[4+12+2:4+12+2+ct_len]
        auth_tag = _data[4+12+2+ct_len:4+12+2+ct_len+16]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            connection_id=connection_id,
            iv=iv,
            ciphertext=ciphertext,
            auth_tag=auth_tag
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>I', self.connection_id) + self.iv + pack('>H', len(self.ciphertext)) + self.ciphertext + self.auth_tag


@dataclass
class DProxyHeartbeat(DProxyHeader):
    """
    The server and the client use this packet to keep the connection alive.
    """
    timestamp: int # UNIX timestamp

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        timestamp = unpack('>Q', _data[0:8])[0]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            timestamp=timestamp
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>Q', self.timestamp)


@dataclass
class DProxyHeartbeatResponse(DProxyHeader):
    """
    The server and the client use this packet to respond to the heartbeat.
    """
    timestamp: int # UNIX timestamp

    @classmethod
    def from_bytes(cls, data: bytes):
        timestamp = unpack('>Q', data[0:8])[0]

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            timestamp=timestamp
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>Q', self.timestamp)


@dataclass
class DProxyErrorPacket(DProxyHeader):
    """
    The server and the client use this packet to exchange errors.
    """
    message: str

    @classmethod
    def from_bytes(cls, data: bytes):
        _data = data[5:]
        message_len = unpack('>H', _data[0:2])[0]
        message = _data[2:2+message_len].decode('utf-8')

        return cls(
            **DProxyHeader.from_bytes(data).__dict__,
            message=message
        )

    def to_bytes(self) -> bytes:
        return super().to_bytes() + pack('>H', len(self.message)) + self.message.encode('utf-8')


def recv_or_none(sock: socket, size: int) -> bytes | None:
    try:
        buf = b''
        while len(buf) < size:
            buf += sock.recv(size - len(buf))

        return buf
    except:
        return None
