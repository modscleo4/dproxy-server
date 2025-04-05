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

import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    private_key = ec.generate_private_key(ec.SECP384R1())

    return private_key


def read_private_key(key_path: str) -> ec.EllipticCurvePrivateKey:
    with open(f"{key_path}/private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), None) # type: ignore


def write_key_pair(key_path: str, private_key: ec.EllipticCurvePrivateKey):
    public_key = private_key.public_key()

    with open(f"{key_path}/private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))

    with open(f"{key_path}/public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
