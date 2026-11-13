# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
from pathlib import Path
from subprocess import getstatusoutput

from twister_harness.helpers.mcumgr import MCUmgr, MCUmgrException, MCUmgrImage

from twister_harness_ext.adapters.cmd import run_command

logger = logging.getLogger(__name__)

__all__ = [
    'MCUmgrException',
    'MCUmgrImage',
    'NrfutilMCUmgr',
    'NrfutilMCUmgrBle',
]


class NrfutilMCUmgr:
    """Wrapper for ``nrfutil mcu-manager serial`` with an MCUmgr-compatible API."""

    nrfutil_exec = 'nrfutil'
    transport = 'serial'

    def __init__(self, serial_port: str):
        self.serial_port = serial_port

    @classmethod
    def create_for_serial(cls, serial_port: str) -> NrfutilMCUmgr:
        return cls(serial_port=serial_port)

    @classmethod
    def is_available(cls) -> bool:
        exitcode, output = getstatusoutput(
            shlex.join([shutil.which(cls.nrfutil_exec) or cls.nrfutil_exec, 'mcu-manager', '--version'])
        )
        if exitcode != 0:
            logger.warning('nrfutil mcu-manager not available: %s', output)
            return False
        return True

    def _mcu_manager_command(self, *args: str, timeout: int = 30) -> str:
        command = [
            self.nrfutil_exec,
            'mcu-manager',
            self.transport,
            *args,
            '--serial-port',
            self.serial_port,
            '--log-output',
            'stdout',
            '--log-level',
            'warn',
        ]
        logger.info('CMD: %s', shlex.join(command))
        return run_command(command, timeout=timeout).stdout

    def run_command(self, cmd: str) -> str:
        """Execute an MCUmgr-style command string (for compatibility with tests and mcumgr CLI)."""
        tokens = shlex.split(cmd)
        if not tokens:
            raise MCUmgrException(f'Empty command: {cmd!r}')

        timeout = 30
        index = 0
        if tokens[0] == '-t':
            timeout = int(tokens[1])
            index = 2

        operation = tokens[index]
        if operation == 'reset':
            return self._mcu_manager_command('reset', '--timeout', str(timeout), timeout=timeout)

        if operation == 'image' and len(tokens) > index + 1:
            subcommand = tokens[index + 1]
            if subcommand == 'list':
                return self._mcu_manager_command(
                    'image-list', '--timeout', str(timeout), timeout=timeout
                )
            if subcommand == 'upload':
                return self._run_image_upload(tokens[index + 2 :], timeout=timeout)
            if subcommand == 'test':
                return self._mcu_manager_command(
                    'image-test',
                    '--hash',
                    tokens[index + 2],
                    '--timeout',
                    str(timeout),
                    timeout=timeout,
                )
            if subcommand == 'confirm':
                return self._mcu_manager_command(
                    'image-confirm',
                    '--hash',
                    tokens[index + 2],
                    '--timeout',
                    str(timeout),
                    timeout=timeout,
                )

        raise MCUmgrException(f'Unsupported mcumgr-style command: {cmd!r}')

    def _run_image_upload(self, tokens: list[str], timeout: int) -> str:
        firmware: str | None = None
        slot: int | None = None
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in {'-e', '-u', '-w'}:
                index += 2 if token == '-w' and index + 1 < len(tokens) else 1
                continue
            if token == '-n' and index + 1 < len(tokens):
                slot = int(tokens[index + 1])
                index += 2
                continue
            if firmware is None:
                firmware = token
            index += 1

        if firmware is None:
            raise MCUmgrException(f'No firmware path in upload command: {tokens!r}')
        self.image_upload(firmware, slot=slot, timeout=timeout)
        return ''

    def reset_device(self) -> None:
        self._mcu_manager_command('reset')

    def image_upload(self, image: Path | str, slot: int | None = None, timeout: int = 30) -> None:
        firmware, parsed_slot = _parse_upload_image_argument(image)
        if slot is None:
            slot = parsed_slot

        command = [
            'image-upload',
            '--firmware',
            firmware,
            '--timeout',
            str(timeout),
        ]
        if slot is not None:
            command.extend(['--image-number', str(slot)])

        self._mcu_manager_command(*command, timeout=timeout)
        logger.info('Image successfully uploaded')

    def get_image_list(self) -> list[MCUmgrImage]:
        output = self._mcu_manager_command('image-list', '--json', '--skip-overhead')
        try:
            return _parse_nrfutil_image_list(output)
        except ValueError:
            logger.debug('Falling back to mcumgr-style image list parser')
            return MCUmgr._parse_image_list(output)

    @staticmethod
    def _parse_image_list(cmd_output: str) -> list[MCUmgrImage]:
        return MCUmgr._parse_image_list(cmd_output)

    def get_hash_to_test(self) -> str:
        image_list = self.get_image_list()
        for image in image_list:
            if 'active' not in image.flags:
                return image.hash
        logger.warning('Images returned by nrfutil mcu-manager (no not active):\n%s', image_list)
        raise MCUmgrException('No not active image found')

    def get_hash_to_confirm(self) -> str:
        image_list = self.get_image_list()
        for image in image_list:
            if 'confirmed' not in image.flags:
                return image.hash
        logger.warning('Images returned by nrfutil mcu-manager (no not confirmed):\n%s', image_list)
        raise MCUmgrException('No not confirmed image found')

    def image_test(self, hash: str | None = None) -> None:
        if not hash:
            hash = self.get_hash_to_test()
        self._mcu_manager_command('image-test', '--hash', hash)

    def image_confirm(self, hash: str | None = None) -> None:
        if not hash:
            hash = self.get_hash_to_confirm()
        self._mcu_manager_command('image-confirm', '--hash', hash)


class NrfutilMCUmgrBle(NrfutilMCUmgr):
    """MCUmgr-compatible wrapper for ``nrfutil mcu-manager ble``."""

    transport = 'ble'

    def __init__(self, hci_serial_port: str, peer_name: str):
        self.hci_serial_port = hci_serial_port
        self.peer_name = peer_name
        self.serial_port = ''

    @classmethod
    def create_for_ble(cls, hci_index: int, peer_name: str) -> NrfutilMCUmgrBle:
        hci_serial_port = os.environ.get(f'NRFUTIL_HCI_SERIAL_PORT_{hci_index}') or os.environ.get(
            'NRFUTIL_HCI_SERIAL_PORT'
        )
        if not hci_serial_port:
            raise MCUmgrException(
                'Set NRFUTIL_HCI_SERIAL_PORT or NRFUTIL_HCI_SERIAL_PORT_<index> for BLE transport'
            )
        return cls(hci_serial_port=hci_serial_port, peer_name=peer_name)

    @classmethod
    def is_available(cls) -> bool:
        return NrfutilMCUmgr.is_available()

    def _mcu_manager_command(self, *args: str, timeout: int = 30) -> str:
        command = [
            self.nrfutil_exec,
            'mcu-manager',
            self.transport,
            *args,
            '--hci-serial-port',
            self.hci_serial_port,
            '--device-name',
            self.peer_name,
            '--log-output',
            'stdout',
            '--log-level',
            'warn',
        ]
        logger.info('CMD: %s', shlex.join(command))
        return run_command(command, timeout=timeout).stdout


def _parse_nrfutil_image_list(output: str) -> list[MCUmgrImage]:
    """Parse ``nrfutil mcu-manager`` image list output (JSON or text)."""
    output = output.strip()
    if not output:
        return []

    if output.startswith('{'):
        data = json.loads(output)
        images = data.get('images', data)
        if not isinstance(images, list):
            raise ValueError('Unexpected JSON image list structure')
        return [_nrfutil_json_image(entry) for entry in images]

    return _parse_nrfutil_image_list_text(output)


def _nrfutil_json_image(entry: dict) -> MCUmgrImage:
    image_index = entry.get('image')
    if image_index is None:
        image_index = 0

    hash_value = entry.get('hash', '')
    if isinstance(hash_value, list):
        hash_value = ''.join(f'{byte:02x}' for byte in hash_value)

    return MCUmgrImage(
        image=int(image_index),
        slot=int(entry['slot']),
        version=str(entry.get('version', '')),
        flags=_nrfutil_flags_string(entry),
        hash=str(hash_value),
    )


def _nrfutil_flags_string(entry: dict) -> str:
    flags: list[str] = []
    if entry.get('pending'):
        flags.append('pending')
    if entry.get('active'):
        flags.append('active')
    if entry.get('confirmed'):
        flags.append('confirmed')
    return ' '.join(flags)


def _parse_nrfutil_image_list_text(output: str) -> list[MCUmgrImage]:
    image_list: list[MCUmgrImage] = []
    current: dict[str, str] = {}
    re_slot = re.compile(r'slot:\s*(\d+)')
    re_version = re.compile(r'version:\s*(\S+)')
    re_hash = re.compile(r'hash:\s*(\w+)')
    re_bool = re.compile(r'(pending|confirmed|active):\s*(true|false)')

    def flush() -> None:
        if not current or 'slot' not in current:
            return
        image_list.append(
            MCUmgrImage(
                image=int(current.get('image', 0)),
                slot=int(current['slot']),
                version=current.get('version', ''),
                flags=_nrfutil_flags_string(
                    {
                        'pending': current.get('pending') == 'true',
                        'active': current.get('active') == 'true',
                        'confirmed': current.get('confirmed') == 'true',
                    }
                ),
                hash=current.get('hash', ''),
            )
        )

    for line in output.splitlines():
        if line.strip() == 'Image':
            flush()
            current = {}
            continue
        if match := re_slot.search(line):
            current['slot'] = match.group(1)
        elif match := re_version.search(line):
            current['version'] = match.group(1)
        elif match := re_hash.search(line):
            current['hash'] = match.group(1)
        elif match := re_bool.search(line):
            current[match.group(1)] = match.group(2)

    flush()
    return image_list


def _parse_upload_image_argument(image: Path | str) -> tuple[str, int | None]:
    """Support firmware paths with embedded mcumgr upload options (used in upgrade tests)."""
    tokens = shlex.split(str(image))
    if len(tokens) == 1:
        return tokens[0], None

    firmware = tokens[0]
    slot: int | None = None
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == '-n' and index + 1 < len(tokens):
            slot = int(tokens[index + 1])
            index += 2
            continue
        if token in {'-e', '-u'}:
            index += 1
            continue
        if token == '-w' and index + 1 < len(tokens):
            index += 2
            continue
        index += 1
    return firmware, slot
