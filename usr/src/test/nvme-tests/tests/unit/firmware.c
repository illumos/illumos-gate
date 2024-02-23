/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * NVMe Firmware unit tests covering both download and activate, support, and
 * related.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvme_unit.h"

/*
 * The offset and length change depending on the granularity.
 */
static const nvme_unit_field_test_t firmware_field_tests[] = { {
	.nu_desc = "invalid fw load numd 4K gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd 4K gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd 4K gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1001,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd 4K gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xfff,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw load numd 4K gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load numd 4K gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1000000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load numd 4K gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x43000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw load offset 4K gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset 4K gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset 4K gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1001,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset 4K gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xfff,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw load offset 4K gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset 4K gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1000000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset 4K gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x43000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset 4K gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw load numd no gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd no gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd no gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x1001,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd no gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0xfff,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw load numd no gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x24,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load numd no gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x280,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load numd no gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x43000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw load offset no gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset no gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset no gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x77,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset no gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x79,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw load offset no gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset no gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x78,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset no gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x4300c,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset no gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw load numd 8k gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd 8k gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd 8k gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x1000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load numd 8k gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x4004,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw load numd 8k gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x2000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load numd 8k gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x88000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load numd 8k gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_NUMD,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x42000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw load offset 8k gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset 8k gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset 8k gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x77,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw load offset 8k gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x79,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw load offset 8k gran (1)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x2000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset 8k gran (2)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x3cc2000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset 8k gran (3)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x18000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw load offset 8k gran (4)",
	.nu_fields = nvme_fw_load_fields,
	.nu_index = NVME_FW_LOAD_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw slot (1 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw slot (1 slot) (2)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw slot (7 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw slot (7 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x8,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw slot (7 slot) (2)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw slot (3 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw slot (1 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw slot (7 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x7,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw slot (7 slot) (2)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_8kgran_1v3,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw slot (3 slot) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw slot (3 slot) (2)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid fw action (1.0) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_FWC_ACTIVATE_IMMED,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid fw action (1.0) (2)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_SLOT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid fw action (1.0) (1)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_ACT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw action (1.0) (2)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_ACT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid fw action (1.3)",
	.nu_fields = nvme_fw_commit_fields,
	.nu_index = NVME_FW_COMMIT_REQ_FIELD_ACT,
	.nu_data = &nvme_ctrl_nogran_1v3,
	.nu_value = NVME_FWC_ACTIVATE_IMMED,
	.nu_ret = NVME_FIELD_ERR_OK
} };

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(firmware_field_tests,
	    ARRAY_SIZE(firmware_field_tests))) {
		ret = EXIT_FAILURE;
	}

	if (nvme_fw_cmds_supported(&nvme_ctrl_nocmds_1v0)) {
		warnx("TEST FAILED: erroneously found firmware command "
		    "support on a controller without it");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: successfully determined controller "
		    "doesn't support firmware commands\n");
	}

	if (!nvme_fw_cmds_supported(&nvme_ctrl_base_1v0)) {
		warnx("TEST FAILED: erroneously found firmware commands aren't "
		    "supported on a controller that should advertise it");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: successfully determined controller "
		    "supports firmware commands\n");
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
