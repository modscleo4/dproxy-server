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

from dataclasses import dataclass
from datetime import datetime
from os import path, makedirs
import sqlite3


@dataclass
class Client:
    id: str
    enabled: bool
    created_at: datetime
    updated_at: datetime | None = None


@dataclass
class PublicKey:
    key: bytes
    client_id: str
    enabled: bool
    last_connected_at: datetime | None = None
    created_at: datetime = datetime.now()
    updated_at: datetime | None = None


DATABASE_PATH: str = './db'


def connect_db() -> sqlite3.Connection:
    db = sqlite3.connect(f"{DATABASE_PATH}/dproxy.db", detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = WAL")

    return db


def init_db(database_path: str) -> None:
    global DATABASE_PATH

    if not path.exists(database_path):
        makedirs(database_path)

    DATABASE_PATH = database_path
    with connect_db() as db:
        with open("schema.sql") as f:
            db.executescript(f.read())
        db.commit()


def get_client(db: sqlite3.Connection, client_id: str) -> Client | None:
    cursor = db.cursor()
    cursor.execute("SELECT * FROM clients WHERE id = ?", (client_id,))
    row: sqlite3.Row | None = cursor.fetchone()
    if row is None:
        return None

    return Client(*row)


def add_client(db: sqlite3.Connection, client_id: str) -> None:
    cursor = db.cursor()
    cursor.execute("INSERT INTO clients (id) VALUES (?)", (client_id,))
    db.commit()


def get_public_key(db: sqlite3.Connection, key: bytes) -> PublicKey | None:
    cursor = db.cursor()
    cursor.execute("SELECT * FROM public_keys WHERE key = ?", (key,))
    row: sqlite3.Row | None = cursor.fetchone()
    if row is None:
        return None

    return PublicKey(*row)


def add_public_key(db: sqlite3.Connection, key: bytes, client_id: str) -> None:
    cursor = db.cursor()
    cursor.execute("INSERT INTO public_keys (key, client_id) VALUES (?, ?)", (key, client_id))
    db.commit()
