# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from twister_harness.device.device_adapter import DeviceAdapter
from twister_harness.helpers.utils import find_in_config
from twister_harness_ext.helpers.nrfutil_mcumgr import NrfutilMCUmgr, NrfutilMCUmgrBle


@pytest.fixture()
def nrfutil(device_object: DeviceAdapter) -> Generator[NrfutilMCUmgr, None, None]:
    """Fixture to create an NrfutilMCUmgr instance for serial SMP/DFU."""
    if not NrfutilMCUmgr.is_available():
        pytest.skip('nrfutil mcu-manager not available')
    yield NrfutilMCUmgr.create_for_serial(device_object.device_config.serial_configs[0].port)


@pytest.fixture()
def nrfutil_ble(device_object: DeviceAdapter) -> Generator[NrfutilMCUmgrBle, None, None]:
    """Fixture to create an NrfutilMCUmgrBle instance for BLE SMP/DFU."""
    if not NrfutilMCUmgrBle.is_available():
        pytest.skip('nrfutil mcu-manager for ble not available')

    for fixture in device_object.device_config.fixtures:
        if fixture.startswith('usb_hci:'):
            hci_name = fixture.split(':', 1)[1]
            break
    else:
        pytest.skip('usb_hci fixture not found')

    try:
        hci_index = int(hci_name.split('hci')[-1])
    except ValueError:
        pytest.skip(f'Invalid HCI name: {hci_name}. Expected format is "hciX".')

    peer_name = find_in_config(
        Path(device_object.device_config.app_build_dir) / 'zephyr' / '.config', 'CONFIG_BT_DEVICE_NAME'
    ) or 'Zephyr'

    yield NrfutilMCUmgrBle.create_for_ble(hci_index, peer_name)
