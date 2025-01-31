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

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, HTTPException, APIRouter
from fastapi.responses import Response

from lib.db import add_client, add_public_key, connect_db, get_client, get_public_key
from lib.utils import CustomRequest, JWTBearer, PEMResponse


router = APIRouter()


@router.get("/key-exchange", response_class=PEMResponse)
def get_server_public_key(request: CustomRequest):
    request.app.logger.debug("Sending server public key.")
    return request.app.private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


@router.post("/key-exchange", status_code=201, response_class=Response, dependencies=[Depends(JWTBearer())])
async def register_client_public_key(request: CustomRequest):
    if not request.headers.get("Content-Type", "").startswith("application/x-pem-file"):
        raise HTTPException(415, "Invalid Content-Type")

    username = request.user['sub']
    public_key: ec.EllipticCurvePublicKey = serialization.load_pem_public_key(await request.body()) # type: ignore
    der_public_key = public_key.public_bytes(
        serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with connect_db() as db:
        client = get_client(db, username)
        if not client:
            add_client(db, username)
        elif not client.enabled:
            raise HTTPException(403, "Client is disabled.")

        if get_public_key(db, der_public_key):
            raise HTTPException(304)

        request.app.logger.debug(f"Adding public key for {username}.")
        add_public_key(db, der_public_key, username)
