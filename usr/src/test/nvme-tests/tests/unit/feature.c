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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Unit tests for the common feature code. Covering fields and whether or not
 * specific features are supported. Vendor-specific features are not tested
 * here.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <err.h>

#include "nvme_unit.h"

static const nvme_unit_field_test_t get_feature_field_tests[] = { {
	.nu_desc = "get invalid FID (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid FID (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x54321,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get valid FID (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid FID (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x78,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid FID (3)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xaa,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid FID (4)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xc0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid FID (5)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get invalid sel (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_FEATURE_SEL_DEFAULT,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid sel (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_base_2v0,
	.nu_value = NVME_FEATURE_SEL_DEFAULT,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid sel (3)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid sel (4)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x11,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get valid sel (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid sel (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid sel (3)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid sel (4)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_SEL,
	.nu_data = &nvme_ctrl_base_2v0,
	.nu_value = NVME_FEATURE_SEL_CURRENT,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get invalid cdw11 (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100000000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid cdw11 (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x8765445678,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get valid cdw11 (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid cdw11 (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xffffffff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid cdw11 (3)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x6543210,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get invalid nsid (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid nsid (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xfffffffe,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get invalid nsid (3)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "get valid nsid (1)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid nsid (2)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "get valid nsid (3)",
	.nu_fields = nvme_get_feat_fields,
	.nu_index = NVME_GET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x80,
	.nu_ret = NVME_FIELD_ERR_OK
} };

static const nvme_unit_field_test_t set_feature_field_tests[] = { {
	.nu_desc = "set invalid FID (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid FID (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x54321,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid FID (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid FID (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x78,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid FID (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xaa,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid FID (4)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xc0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid FID (5)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_FID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set invalid save (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid save (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_base_1v1,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid save (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid save (4)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid save (5)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0xf,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid save (6)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid save (7)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = INT32_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid save (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid save (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_ns_1v2,
	.nu_value = 1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid save (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid save (4)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_SAVE,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = 0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set invalid cdw11 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw11 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_2v0,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw11 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = INT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid cdw11 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw11 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = UINT32_MAX,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw11 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW11,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set unsupported cdw12 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x42,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "set invalid cdw12 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw12 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_2v0,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw12 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = INT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid cdw12 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw12 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = UINT32_MAX,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw12 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW12,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set unsupported cdw13 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x42,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "set invalid cdw13 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw13 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_2v0,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw13 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = INT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid cdw13 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw13 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = UINT32_MAX,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw13 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW13,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set unsupported cdw15 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x42,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "set invalid cdw15 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw15 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_2v0,
	.nu_value = 1ULL << 32,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid cdw15 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = INT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid cdw15 (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw15 (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_1v2,
	.nu_value = UINT32_MAX,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid cdw15 (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_CDW15,
	.nu_data = &nvme_ctrl_base_2v2,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set invalid nsid (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid nsid (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xfffffffe,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set invalid nsid (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "set valid nsid (1)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid nsid (2)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = NVME_NSID_BCAST,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "set valid nsid (3)",
	.nu_fields = nvme_set_feat_fields,
	.nu_index = NVME_SET_FEAT_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x80,
	.nu_ret = NVME_FIELD_ERR_OK
} };

typedef struct feature_impl_test {
	const char *fit_desc;
	uint32_t fit_fid;
	const nvme_valid_ctrl_data_t *fit_data;
	nvme_feat_impl_t fit_impl;
} feature_impl_test_t;

static const feature_impl_test_t feature_impl_tests[] = { {
	.fit_desc = "arbitration supported (1.0)",
	.fit_fid = NVME_FEAT_ARBITRATION,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "arbitration supported (2.0)",
	.fit_fid = NVME_FEAT_ARBITRATION,
	.fit_data =  &nvme_ctrl_ns_2v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "power management supported (1.0)",
	.fit_fid = NVME_FEAT_POWER_MGMT,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "power management supported (2.0)",
	.fit_fid = NVME_FEAT_POWER_MGMT,
	.fit_data =  &nvme_ctrl_ns_2v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "LBA range type unknown (1.0)",
	.fit_fid = NVME_FEAT_LBA_RANGE,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_UNKNOWN
}, {
	.fit_desc = "LBA range type unknown (1.4)",
	.fit_fid = NVME_FEAT_LBA_RANGE,
	.fit_data =  &nvme_ctrl_ns_1v4,
	.fit_impl = NVME_FEAT_IMPL_UNKNOWN
}, {
	.fit_desc = "temp supported (1.0)",
	.fit_fid = NVME_FEAT_TEMPERATURE,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "temp supported (1.2)",
	.fit_fid = NVME_FEAT_TEMPERATURE,
	.fit_data =  &nvme_ctrl_base_1v2,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "temp supported (1.3)",
	.fit_fid = NVME_FEAT_TEMPERATURE,
	.fit_data =  &nvme_ctrl_nogran_1v3,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "VWC unsupported (1)",
	.fit_fid = NVME_FEAT_WRITE_CACHE,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_UNSUPPORTED
}, {
	.fit_desc = "VWC unsupported (2)",
	.fit_fid = NVME_FEAT_WRITE_CACHE,
	.fit_data =  &nvme_ctrl_base_2v0,
	.fit_impl = NVME_FEAT_IMPL_UNSUPPORTED
}, {
	.fit_desc = "VWC supported (1)",
	.fit_fid = NVME_FEAT_WRITE_CACHE,
	.fit_data =  &nvme_ctrl_ns_1v2,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "VWC supported (2)",
	.fit_fid = NVME_FEAT_WRITE_CACHE,
	.fit_data =  &nvme_ctrl_ns_1v4,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "VWC supported (3)",
	.fit_fid = NVME_FEAT_WRITE_CACHE,
	.fit_data =  &nvme_ctrl_ns_2v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "queues supported (1)",
	.fit_fid = NVME_FEAT_NQUEUES,
	.fit_data =  &nvme_ctrl_ns_2v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "queues supported (2)",
	.fit_fid = NVME_FEAT_NQUEUES,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "interrupt coalescing supported (1)",
	.fit_fid = NVME_FEAT_INTR_COAL,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "interrupt coalescing supported (2)",
	.fit_fid = NVME_FEAT_INTR_COAL,
	.fit_data =  &nvme_ctrl_base_1v2,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "interrupt coalescing supported (3)",
	.fit_fid = NVME_FEAT_INTR_COAL,
	.fit_data =  &nvme_ctrl_ns_1v4,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "interrupt vector config supported (1)",
	.fit_fid = NVME_FEAT_INTR_VECT,
	.fit_data =  &nvme_ctrl_base_1v1,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "interrupt vector config supported (2)",
	.fit_fid = NVME_FEAT_INTR_VECT,
	.fit_data =  &nvme_ctrl_ns_1v3,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "interrupt vector config supported (3)",
	.fit_fid = NVME_FEAT_INTR_VECT,
	.fit_data =  &nvme_ctrl_ns_2v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "write atomicity supported (1)",
	.fit_fid = NVME_FEAT_WRITE_ATOM,
	.fit_data =  &nvme_ctrl_base_1v1,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "write atomicity supported (2)",
	.fit_fid = NVME_FEAT_WRITE_ATOM,
	.fit_data =  &nvme_ctrl_ns_1v3,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "write atomicity supported (3)",
	.fit_fid = NVME_FEAT_WRITE_ATOM,
	.fit_data =  &nvme_ctrl_ns_2v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "async event config supported (1)",
	.fit_fid = NVME_FEAT_ASYNC_EVENT,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "async event config supported (2)",
	.fit_fid = NVME_FEAT_ASYNC_EVENT,
	.fit_data =  &nvme_ctrl_base_1v2,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "async event config supported (3)",
	.fit_fid = NVME_FEAT_ASYNC_EVENT,
	.fit_data =  &nvme_ctrl_ns_1v4,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "apst unsupported",
	.fit_fid = NVME_FEAT_AUTO_PST,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_UNSUPPORTED
}, {
	.fit_desc = "apst supported",
	.fit_fid = NVME_FEAT_AUTO_PST,
	.fit_data =  &nvme_ctrl_ns_1v2,
	.fit_impl = NVME_FEAT_IMPL_SUPPORTED
}, {
	.fit_desc = "software progress marker unknown (1)",
	.fit_fid = NVME_FEAT_PROGRESS,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_UNKNOWN
}, {
	.fit_desc = "software progress marker unknown (2)",
	.fit_fid = NVME_FEAT_PROGRESS,
	.fit_data =  &nvme_ctrl_base_2v0,
	.fit_impl = NVME_FEAT_IMPL_UNKNOWN
}, {
	.fit_desc = "host behavior unsupported",
	.fit_fid = NVME_FEAT_HOST_BEHAVE,
	.fit_data =  &nvme_ctrl_base_1v0,
	.fit_impl = NVME_FEAT_IMPL_UNSUPPORTED
}, {
	.fit_desc = "host behavior unknown (1)",
	.fit_fid = NVME_FEAT_HOST_BEHAVE,
	.fit_data =  &nvme_ctrl_ns_1v4,
	.fit_impl = NVME_FEAT_IMPL_UNKNOWN
}, {
	.fit_desc = "host behavior unknown (2)",
	.fit_fid = NVME_FEAT_HOST_BEHAVE,
	.fit_data =  &nvme_ctrl_base_2v2,
	.fit_impl = NVME_FEAT_IMPL_UNKNOWN
}  };

static bool
feature_impl_test_one(const feature_impl_test_t *test)
{
	const nvme_feat_info_t *info = NULL;
	nvme_feat_impl_t impl;

	for (size_t i = 0; i < nvme_std_nfeats; i++) {
		if (nvme_std_feats[i].nfeat_fid == test->fit_fid) {
			info = &nvme_std_feats[i];
			break;
		}
	}

	if (info == NULL) {
		errx(EXIT_FAILURE, "malformed test %s: cannot find FID %u",
		    test->fit_desc, test->fit_fid);
	}

	impl = nvme_feat_supported(info, test->fit_data);
	if (impl != test->fit_impl) {
		warnx("TEST FAILED: %s: expected impl %u, found %u",
		    test->fit_desc, test->fit_impl, impl);
		return (false);
	}

	(void) printf("TEST PASSED: %s: got correct impl\n", test->fit_desc);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(get_feature_field_tests,
	    ARRAY_SIZE(get_feature_field_tests))) {
		ret = EXIT_FAILURE;
	}

	if (!nvme_unit_field_test(set_feature_field_tests,
	    ARRAY_SIZE(set_feature_field_tests))) {
		ret = EXIT_FAILURE;
	}

	for (size_t i = 0; i < ARRAY_SIZE(feature_impl_tests); i++) {
		if (!feature_impl_test_one(&feature_impl_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
