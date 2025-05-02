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


from typing import Iterable
from urllib.parse import ParseResult

from fastapi import Request


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


def chunk_bytes(data: bytes, size: int) -> Iterable[bytes]:
    for i in range(0, len(data), size):
        yield data[i:i + size]
