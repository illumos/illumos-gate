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
 * Various unit tests of the common NVMe log validation code. We focus on field
 * validation, scope determination, size, and support determination.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <stdio.h>
#include <strings.h>
#include <err.h>

#include "nvme_unit.h"

static const nvme_unit_field_test_t log_field_tests[] = { {
	.nu_desc = "invalid lid value (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x123456,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid lid value (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid lid (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x00,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lid (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid lsp (vers)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "unsupported lsp",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "invalid lsp (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid lsp (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7777,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid lsp (1.x)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x10,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid lsp (2.x)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid lsp (2.x)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x80,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid lsp (1.x) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x7,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (1.x) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (1.x) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (2.x) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (2.x) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (2.x) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (2.x) (4)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x7f,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsp (2.x) (4)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSP,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "unsupported lsi",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSI,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "invalid lsi (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x10000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid lsi (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x123321,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid lsi (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsi (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0xffff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid lsi (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_LSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x5445,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid size (1.0) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x4004,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.0) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x76543210,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.0) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "bad alignment (1.0) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "bad alignment (1.0) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0xf7,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.4, No LPA) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x4004,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.4, No LPA) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x76543210,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.4, No LPA) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.4, LPA) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x123456789a0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.4, LPA) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x400000004,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid size (1.4, LPA) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid size (1.0) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x4000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.0) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.0) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1234,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, No LPA) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x4000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, No LPA) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, No LPA) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x1234,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, LPA) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x4000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, LPA) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, LPA) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x1234,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, LPA) (4)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x400000000,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid size (1.4, LPA) (5)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_SIZE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x7777777c,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "unsupported CSI (1.0)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "unsupported CSI (1.4)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "invalid CSI (2.0) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x100,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid CSI (2.0) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = UINT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid CSI (2.0) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid CSI (2.0) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_CSI,
	.nu_data = &nvme_ctrl_ns_2v0,
	.nu_value = 0xff,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "unsupported rae (1.0)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_RAE,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "invalid rae (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_RAE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x2,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid rae (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_RAE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x34,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid rae (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_RAE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid rae (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_RAE,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "unsupported offset (1.0)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_UNSUP_VERSION
}, {
	.nu_desc = "unsupported offset (1.4 No LPA)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_nolpa_1v4,
	.nu_value = 0x4,
	.nu_ret = NVME_FIELD_ERR_UNSUP_FIELD
}, {
	.nu_desc = "unaligned offset (1.4) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "unaligned offset (1.4) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = UINT64_MAX,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "unaligned offset (1.4) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x3,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid offset (1.4) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid offset (1.4) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x4444,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid offset (1.4) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_OFFSET,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0xfffffffffffffffc,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "invalid nsid (1.4) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x0,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid nsid (1.4) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x1000,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "invalid nsid (1.4) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x81,
	.nu_ret = NVME_FIELD_ERR_BAD_VALUE
}, {
	.nu_desc = "valid nsid (1.0)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_base_1v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid nsid (1.4) (1)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid nsid (1.4) (2)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x80,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid nsid (1.4) (3)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_ns_1v4,
	.nu_value = 0x23,
	.nu_ret = NVME_FIELD_ERR_OK
}, {
	.nu_desc = "valid nsid (2.0 No NS)",
	.nu_fields = nvme_log_fields,
	.nu_index = NVME_LOG_REQ_FIELD_NSID,
	.nu_data = &nvme_ctrl_nons_2v0,
	.nu_value = 0x1,
	.nu_ret = NVME_FIELD_ERR_OK
} };

typedef struct log_scope_test {
	const char *lst_desc;
	const char *lst_short;
	const nvme_valid_ctrl_data_t *lst_data;
	nvme_log_disc_scope_t lst_exp_scope;
} log_scope_test_t;

static const log_scope_test_t log_scope_tests[] = { {
	.lst_desc = "error log (1.0)",
	.lst_short = "error",
	.lst_data = &nvme_ctrl_base_1v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "error log (2.0)",
	.lst_short = "error",
	.lst_data = &nvme_ctrl_ns_2v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "health log (1.0)",
	.lst_short = "health",
	.lst_data = &nvme_ctrl_base_1v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "health log (1.4 No LPA)",
	.lst_short = "health",
	.lst_data = &nvme_ctrl_nolpa_1v4,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "health log (1.0 NS Health)",
	.lst_short = "health",
	.lst_data = &nvme_ctrl_health_1v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NS
}, {
	.lst_desc = "health log (1.4 LPA)",
	.lst_short = "health",
	.lst_data = &nvme_ctrl_ns_1v4,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NS
}, {
	.lst_desc = "health log (2.0 LPA)",
	.lst_short = "health",
	.lst_data = &nvme_ctrl_ns_2v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NS
}, {
	.lst_desc = "firmware log (1.0)",
	.lst_short = "firmware",
	.lst_data = &nvme_ctrl_base_1v0,
	.lst_exp_scope = NVME_LOG_SCOPE_NVM
}, {
	.lst_desc = "firmware log (2.0)",
	.lst_short = "firmware",
	.lst_data = &nvme_ctrl_ns_2v0,
	.lst_exp_scope = NVME_LOG_SCOPE_NVM
}, {
	.lst_desc = "changed namespace log (2.0)",
	.lst_short = "changens",
	.lst_data = &nvme_ctrl_ns_2v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "supported logs log (2.0)",
	.lst_short = "suplog",
	.lst_data = &nvme_ctrl_ns_2v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "commands supported and effects log (1.2)",
	.lst_short = "cmdeff",
	.lst_data = &nvme_ctrl_ns_1v2,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
}, {
	.lst_desc = "commands supported and effects log (2.0)",
	.lst_short = "cmdeff",
	.lst_data = &nvme_ctrl_ns_2v0,
	.lst_exp_scope = NVME_LOG_SCOPE_CTRL
} };

typedef struct log_size_test {
	const char *lt_desc;
	const char *lt_short;
	const nvme_valid_ctrl_data_t *lt_data;
	uint64_t lt_size;
	bool lt_var;
} log_size_test_t;

static const log_size_test_t log_size_tests[] = { {
	.lt_desc = "error log (4 entries)",
	.lt_short = "error",
	.lt_data = &nvme_ctrl_base_1v0,
	.lt_size = 4 * sizeof (nvme_error_log_entry_t),
	.lt_var = false
}, {
	.lt_desc = "error log (1 entries)",
	.lt_short = "error",
	.lt_data = &nvme_ctrl_ns_1v4,
	.lt_size = sizeof (nvme_error_log_entry_t),
	.lt_var = false
}, {
	.lt_desc = "health log (1.0)",
	.lt_short = "health",
	.lt_data = &nvme_ctrl_base_1v0,
	.lt_size = sizeof (nvme_health_log_t),
	.lt_var = false
}, {
	.lt_desc = "health log (1.4)",
	.lt_short = "health",
	.lt_data = &nvme_ctrl_ns_1v4,
	.lt_size = sizeof (nvme_health_log_t),
	.lt_var = false
}, {
	.lt_desc = "firmware log (1.0)",
	.lt_short = "firmware",
	.lt_data = &nvme_ctrl_base_1v0,
	.lt_size = sizeof (nvme_fwslot_log_t),
	.lt_var = false
}, {
	.lt_desc = "firmware log (1.4)",
	.lt_short = "firmware",
	.lt_data = &nvme_ctrl_ns_1v4,
	.lt_size = sizeof (nvme_fwslot_log_t),
	.lt_var = false
}, {
	.lt_desc = "changed namespace log (1.0)",
	.lt_short = "changens",
	.lt_data = &nvme_ctrl_base_1v0,
	.lt_size = sizeof (nvme_nschange_list_t),
	.lt_var = false
}, {
	.lt_desc = "changed namespace log (1.4)",
	.lt_short = "changens",
	.lt_data = &nvme_ctrl_ns_1v4,
	.lt_size = sizeof (nvme_nschange_list_t),
	.lt_var = false
}, {
	.lt_desc = "commands supported and effects log (1.2)",
	.lt_short = "cmdeff",
	.lt_data = &nvme_ctrl_ns_1v2,
	.lt_size = sizeof (nvme_cmdeff_log_t),
	.lt_var = false
}, {
	.lt_desc = "commands supported and effects log (1.4)",
	.lt_short = "cmdeff",
	.lt_data = &nvme_ctrl_ns_1v4,
	.lt_size = sizeof (nvme_cmdeff_log_t),
	.lt_var = false
}, {
	.lt_desc = "supported logs log (2.0)",
	.lt_short = "suplog",
	.lt_data = &nvme_ctrl_ns_2v0,
	.lt_size = sizeof (nvme_suplog_log_t),
	.lt_var = false
} };

typedef struct log_impl_test {
	const char *lit_desc;
	const char *lit_short;
	const nvme_valid_ctrl_data_t *lit_data;
	bool lit_impl;
} log_impl_test_t;

static const log_impl_test_t log_impl_tests[] = { {
	.lit_desc = "supported logs (1.0)",
	.lit_short = "suplog",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = false
}, {
	.lit_desc = "supported logs (2.0)",
	.lit_short = "suplog",
	.lit_data = &nvme_ctrl_base_2v0,
	.lit_impl = true
}, {
	.lit_desc = "error (1.0)",
	.lit_short = "error",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = true
}, {
	.lit_desc = "error (1.4)",
	.lit_short = "error",
	.lit_data = &nvme_ctrl_ns_1v4,
	.lit_impl = true
}, {
	.lit_desc = "health (1.0)",
	.lit_short = "health",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = true
}, {
	.lit_desc = "health (1.4)",
	.lit_short = "health",
	.lit_data = &nvme_ctrl_ns_1v4,
	.lit_impl = true
}, {
	.lit_desc = "firmware (1.0)",
	.lit_short = "firmware",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = true
}, {
	.lit_desc = "firmware (1.4)",
	.lit_short = "firmware",
	.lit_data = &nvme_ctrl_ns_1v4,
	.lit_impl = true
}, {
	.lit_desc = "changed namespace (1.0)",
	.lit_short = "changens",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = false
}, {
	.lit_desc = "changed namespace (1.4 No LPA)",
	.lit_short = "changens",
	.lit_data = &nvme_ctrl_ns_1v4,
	.lit_impl = true
}, {
	.lit_desc = "changed namespace (1.2 No OAES)",
	.lit_short = "changens",
	.lit_data = &nvme_ctrl_base_1v2,
	.lit_impl = false
}, {
	.lit_desc = "commands supported and effects (1.0)",
	.lit_short = "cmdeff",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = false
}, {
	.lit_desc = "commands supported and effects (1.4 LPA)",
	.lit_short = "cmdeff",
	.lit_data = &nvme_ctrl_ns_1v4,
	.lit_impl = true
}, {
	.lit_desc = "commands supported and effects (2.0 No LPA)",
	.lit_short = "cmdeff",
	.lit_data = &nvme_ctrl_base_2v0,
	.lit_impl = false
}, {
	.lit_desc = "persistent event log (1.0)",
	.lit_short = "pev",
	.lit_data = &nvme_ctrl_base_1v0,
	.lit_impl = false
}, {
	.lit_desc = "persistent event log (1.4 LPA)",
	.lit_short = "pev",
	.lit_data = &nvme_ctrl_ns_1v4,
	.lit_impl = true
}, {
	.lit_desc = "persistent event log (2.0 No LPA)",
	.lit_short = "pev",
	.lit_data = &nvme_ctrl_base_2v0,
	.lit_impl = false
} };

static const nvme_log_page_info_t *
log_test_find_info(const char *desc, const char *name)
{
	for (size_t i = 0; i < nvme_std_log_npages; i++) {
		if (strcmp(nvme_std_log_pages[i].nlpi_short, name) == 0) {
			return (&nvme_std_log_pages[i]);
		}
	}

	errx(EXIT_FAILURE, "malformed test: %s: cannot find log page %s",
	    desc, name);
}

static bool
log_scope_test_one(const log_scope_test_t *test)
{
	nvme_log_disc_scope_t scope;
	const nvme_log_page_info_t *info;

	info = log_test_find_info(test->lst_desc, test->lst_short);
	scope = nvme_log_page_info_scope(info, test->lst_data);
	if (scope != test->lst_exp_scope) {
		warnx("TEST FAILED: %s: found scope 0x%x, expected 0x%x",
		    test->lst_desc, scope, test->lst_exp_scope);
		return (false);
	}

	(void) printf("TEST PASSED: %s: correct scope\n", test->lst_desc);
	return (true);
}

static bool
log_size_test_one(const log_size_test_t *test)
{
	const nvme_log_page_info_t *info;
	uint64_t len;
	bool var, ret = true;

	info = log_test_find_info(test->lt_desc, test->lt_short);
	len = nvme_log_page_info_size(info, test->lt_data, &var);

	if (len != test->lt_size) {
		warnx("TEST FAILED: %s: expected size %" PRIu64 ", found %"
		    PRIu64, test->lt_desc, test->lt_size, len);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: found correct size\n",
		    test->lt_desc);
	}

	if (var != test->lt_var) {
		warnx("TEST FAILED: %s: expected var %u, found %u",
		    test->lt_desc, test->lt_var, var);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: variable length flag correct\n",
		    test->lt_desc);
	}

	return (ret);
}

static bool
log_impl_test_one(const log_impl_test_t *test)
{
	const nvme_log_page_info_t *info;
	bool impl;

	info = log_test_find_info(test->lit_desc, test->lit_short);
	impl = nvme_log_page_info_supported(info, test->lit_data);
	if (impl != test->lit_impl) {
		warnx("TEST FAILED: %s: expected impl %u, found %u",
		    test->lit_desc, test->lit_impl, impl);
		return (false);
	}

	(void) printf("TEST PASSED: %s: got correct impl\n", test->lit_desc);
	return (true);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	if (!nvme_unit_field_test(log_field_tests,
	    ARRAY_SIZE(log_field_tests))) {
		ret = EXIT_FAILURE;
	}

	for (size_t i = 0; i < ARRAY_SIZE(log_scope_tests); i++) {
		if (!log_scope_test_one(&log_scope_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(log_size_tests); i++) {
		if (!log_size_test_one(&log_size_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(log_impl_tests); i++) {
		if (!log_impl_test_one(&log_impl_tests[i])) {
			ret = EXIT_FAILURE;
		}
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}

	return (ret);
}
