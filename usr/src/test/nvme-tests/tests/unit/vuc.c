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
 * Validate fields for the various VUC fields. Note, these do not change with
 * the controller itself. These have been the same since NVMe 1.0.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvme_unit.h"

static const nvme_unit_field_test_t vuc_field_tests[] = { {
	.nu_desc = "invalid opcode (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_OPC,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xbf,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid opcode (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_OPC,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid opcode (3)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_OPC,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid opcode (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_OPC,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xc0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid opcode (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_OPC,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid opcode (3)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_OPC,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xde,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid namespace (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x33,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid namespace (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid namespace (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid namespace (3)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid cdw12",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid cdw12",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid cdw13",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid cdw13",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x6666,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid cdw14",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW14,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid cdw14",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW14,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x5555,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid cdw15",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid cdw15",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x4444,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid ndt (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NDT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid ndt (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NDT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid ndt (3)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NDT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x17,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid ndt (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NDT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x3fffffffc,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid ndt (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NDT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid ndt (3)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_NDT,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1234,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid timeout (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_TO,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid timeout (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_TO,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid timeout (1)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_TO,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid timeout (2)",
	.nu_fields = nvme_vuc_fields,
	.nu_index = NVME_VUC_REQ_FIELD_TO,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x101,
	.nu_ret = NVME_FIELD_ERR_OK
} };

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(vuc_field_tests,
	    ARRAY_SIZE(vuc_field_tests))) {
		ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
