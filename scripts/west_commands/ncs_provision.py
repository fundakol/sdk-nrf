#!/usr/bin/env python3
# Copyright (c) 2024 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import json
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from west.commands import WestCommand

KEY_SLOTS: dict[str, list[int]] = {
    "UROT_PUBKEY": [226, 228, 230],
    "BL_PUBKEY": [242, 244, 246],
    "APP_PUBKEY": [202, 204, 206],
}
KEY_SLOT_METADATA: str = "0x10ba0030"
KMU_KEY_SLOT_DEST_ADDR: str = "0x20000000"
ALGORITHM: str = "ED25519"
NRF54L15_KEY_POLICIES: dict[str, str] = {"revokable": "REVOKED", "lock": "LOCKED"}


@dataclass
class SlotParams:
    id: int
    value: str
    rpolicy: str
    algorithm: str = ALGORITHM
    dest: str = KMU_KEY_SLOT_DEST_ADDR
    metadata: str = KEY_SLOT_METADATA

    def asdict(self) -> dict[str, str]:
        return asdict(self)


class NrfutilWrapper:

    def __init__(
        self,
        slots: list[SlotParams],
        device_id: str | None = None,
        output_dir: str | None = None,
        *,
        dry_run: bool = False
    ) -> None:
        self.device_id = device_id
        self.dry_run = dry_run
        self.data = {
            "version": 0,
            "keyslots": [slot.asdict() for slot in slots]
        }
        self.output_dir = output_dir or tempfile.mkdtemp(prefix="nrfutil_")

    def run_command(self):
        command = self._build_command()
        print(' '.join(command), file=sys.stderr)
        if self.dry_run:
            return
        result = subprocess.run(command, stderr=subprocess.PIPE, text=True)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            sys.exit("Uploading failed!")

    def _make_json_file(self) -> str:
        """Create JSON file and return path to it."""
        json_file = Path(self.output_dir).joinpath("keyfile.json").resolve().expanduser()
        with open(json_file, "w") as file:
            json.dump(self.data, file, indent=2)
        print(f"Keys file saved as {json_file}", file=sys.stderr)
        return str(json_file)

    def _build_command(self) -> list[str]:
        json_file_path = self._make_json_file()
        command = [
            "nrfutil",
            "device",
            "x-provision-nrf54l-keys",
            "--key-file",
            json_file_path,
            "--verify",
        ]
        if self.device_id:
            command += ["--serial-number", self.device_id]

        return command


class NcsProvision(WestCommand):

    def __init__(self):
        super().__init__(
            name="ncs-provision",
            help="NCS provision",
            description="NCS provision utility tool.",
        )

    def do_add_parser(self, parser_adder):
        parser = parser_adder.add_parser(
            self.name, help=self.help, description=self.description)

        subparsers = parser.add_subparsers(dest="command")
        upload_parser = subparsers.add_parser("upload", help="Send to KMU")
        upload_parser.add_argument(
            "-k",
            "--key",
            type=Path,
            action="append",
            dest="keys",
            help="Input .pem file with ED25519 private key",
        )
        upload_parser.add_argument(
            "--keyname",
            choices=KEY_SLOTS.keys(),
            # default value for backward compatibility
            default="UROT_PUBKEY",
            type=lambda x: x.upper(),
            help="Key name to upload (default: %(default)s)",
        )
        upload_parser.add_argument(
            "-p",
            "--policy",
            type=str,
            choices=["revokable", "lock", "lock-last"],
            default="lock-last",
            help="Policy applied to the given set of keys. "
                 "revokable: keys can be revoked each by one. "
                 "lock: all keys stay as they are. "
                 "lock-last: last key is uploaded as locked, "
                 "others as revokable (default=%(default)s)",
        )
        upload_parser.add_argument(
            "-s", "--soc", type=str, help="SoC",
            choices=["nrf54l05", "nrf54l10", "nrf54l15"], required=True
        )
        upload_parser.add_argument("--dev-id", help="Device serial number")
        upload_parser.add_argument(
            "--build-dir", metavar="PATH",
            help="Path to output directory where keyfile.json will be saved. "
                 "If not specified, temporary directory will be used.",
        )
        upload_parser.add_argument(
            "--dry-run", default=False, action="store_true",
            help="Generate upload command and keyfile without executing the command"
        )

        return parser

    def do_run(self, args, unknown_args):
        if args.command == "upload":
            if args.soc in ["nrf54l05", "nrf54l10", "nrf54l15"]:
                self._upload_keys(args)

    def _upload_keys(self, args) -> None:
        slots: list[SlotParams] = []
        keyname = args.keyname
        if len(args.keys) > len(KEY_SLOTS[keyname]):
            sys.exit(
                "Error: requested upload of more keys than there are designated slots."
            )
        for slot_idx, keyfile in enumerate(args.keys):
            pub_key_hex = self._get_public_key_hex(keyfile)
            if args.policy == "lock-last":
                if slot_idx == (len(args.keys) - 1):
                    key_policy = NRF54L15_KEY_POLICIES["lock"]
                else:
                    key_policy = NRF54L15_KEY_POLICIES["revokable"]
            else:
                key_policy = NRF54L15_KEY_POLICIES[args.policy]
            slot_id = KEY_SLOTS[keyname][slot_idx]
            slots.append(SlotParams(id=slot_id, value=pub_key_hex, rpolicy=key_policy))

        runner = NrfutilWrapper(
            slots=slots, device_id=args.dev_id, output_dir=args.build_dir, dry_run=args.dry_run
        )
        runner.run_command()

    @staticmethod
    def _get_public_key_hex(keyfile: str) -> str:
        with open(keyfile, "rb") as f:
            priv_key = load_pem_private_key(f.read(), password=None)
        pub_key = priv_key.public_key()
        pub_key_hex = f'0x{pub_key.public_bytes_raw().hex()}'
        return pub_key_hex
