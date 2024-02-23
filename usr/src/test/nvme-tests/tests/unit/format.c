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
 * NVMe format field testing. Note, the valid lba formats are not constrained by
 * the controller at this time. That is a future direction.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvme_unit.h"

static const nvme_unit_field_test_t format_field_tests[] = { {
	.nu_desc = "invalid LBA format (1)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_LBAF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x10,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid LBA format (2)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_LBAF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid LBA format (1)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_LBAF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid LBA format (2)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_LBAF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xf,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid LBA format (3)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_LBAF,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x7,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid SES (1)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_SES,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid SES (2)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_SES,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x33,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid SES (1)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_SES,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid SES (2)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_SES,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid NSID (1)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid NSID (2)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid NSID (1)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid NSID (2)",
	.nu_fields = nvme_format_fields,
	.nu_index = NVME_FORMAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
} };

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(format_field_tests,
	    ARRAY_SIZE(format_field_tests))) {
		ret = EXIT_FAILURE;
	}

	if (nvme_format_cmds_supported(&nvme_ctrl_nocmds_1v0)) {
		warnx("TEST FAILED: erroneously found format command "
		    "support on a controller without it");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: successfully determined controller "
		    "doesn't support format commands\n");
	}

	if (!nvme_format_cmds_supported(&nvme_ctrl_base_1v0)) {
		warnx("TEST FAILED: erroneously found format commands aren't "
		    "supported on a controller that should advertise it");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: successfully determined controller "
		    "supports format commands\n");
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
