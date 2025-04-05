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

from argparse import ArgumentParser
from os import getenv, path, makedirs

from dproxy.crypt.ec import generate_private_key, write_key_pair


def main() -> None:
    arg_parser = ArgumentParser(description="DProxy Web Server")
    arg_parser.add_argument("--key-path", default=getenv("KEY_PATH", "./keys"), type=str, help="EC keys path")

    args = arg_parser.parse_args()

    if not path.exists(args.key_path):
        makedirs(args.key_path)

    private_key = generate_private_key()
    write_key_pair(args.key_path, private_key)


if __name__ == "__main__":
    main()
