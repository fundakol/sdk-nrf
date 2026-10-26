# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

"""E2E NSIB tests for FW_INFO discovery."""

from __future__ import annotations

from pathlib import Path

import pytest
from fw_info_hex_utils import FW_INFO_ALLOWED_OFFSETS, edt_pickle_for_build
from twister_harness import DeviceAdapter
from twister_harness_ext.adapters.nrfutil import flash_with_nrfutil
from twister_harness_ext.utils.required_build import (
    RequiredBuildException,
    get_required_build,
)


def _variant_build_dir(dut: DeviceAdapter, suffix: str) -> Path:
    return Path(str(dut.device_config.build_dir) + suffix)


@pytest.mark.parametrize(
    "fw_info_offset",
    [hex(offset) for offset in FW_INFO_ALLOWED_OFFSETS],
    ids=[hex(offset) for offset in FW_INFO_ALLOWED_OFFSETS],
)
def test_boot_with_fw_info_at_each_allowed_offset(
    unlaunched_dut: DeviceAdapter, fw_info_offset: str
):
    """Signed application boots when fw_info is linked at each permitted offset.

    Not every documented discovery offset fits the b0_hello_world partition layout on
    every SoC (linker may reject CONFIG_FW_INFO_OFFSET). Those cases are skipped.
    """
    assert unlaunched_dut.device_config.app_build_dir is not None
    app_name = unlaunched_dut.device_config.app_build_dir.name
    suffix = f"_off_{fw_info_offset.lower().replace('0x', '')}"

    try:
        build_dir = get_required_build(
            unlaunched_dut, extra_args=f"-- -DCONFIG_FW_INFO_OFFSET={fw_info_offset}", suffix=suffix
        )
    except RequiredBuildException:
        # For 0x0, 0x200, and 0x400, extra builds with -DCONFIG_FW_INFO_OFFSET=...
        # fail at link time on nRF54L15: `cannot move location counter backwards`
        # That happens in the `b0_hello_world_s1_variant` sysbuild image:
        # fw_info is placed at CONFIG_FW_INFO_OFFSET + CONFIG_ROM_START_OFFSET (fw_info.ld),
        # and some Kconfig-legal offsets do not fit this app/partition layout.
        # Discovery still supports those offsets in general; this sample simply
        # cannot be linked at every one.
        variant_dir = _variant_build_dir(unlaunched_dut, suffix)
        build_log = variant_dir / "_build_log.txt"
        search_msg = "cannot move location counter backwards"
        if build_log.exists() and search_msg in build_log.read_text():
            (variant_dir / "build.error").unlink(missing_ok=True)
            pytest.skip(
                f"CONFIG_FW_INFO_OFFSET={fw_info_offset} is not linkable for b0_hello_world "
                f"on {unlaunched_dut.device_config.platform}"
            )
        else:
            raise

    hex_path = build_dir / f"signed_by_b0_{app_name}.hex"
    assert hex_path.is_file(), f"Missing signed image {hex_path}"
    assert edt_pickle_for_build(unlaunched_dut, build_dir).is_file()

    flash_with_nrfutil(
        hex_path,
        unlaunched_dut.device_config.id,
        erase_mode="ERASE_RANGES_TOUCHED_BY_FIRMWARE",
    )
    unlaunched_dut.launch()

    lines = unlaunched_dut.readlines_until(regex="Hello World!", timeout=60)
    pytest.LineMatcher(lines).fnmatch_lines(
        [
            "*Attempting to boot slot 0*",
            "*Firmware version *",
        ]
    )
