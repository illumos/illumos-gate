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
 * Common field and validation for NVMe Format NVM operations. This covers what
 * nvmeadm(8) calls both secure-erase and format.
 */

#include "nvme_common.h"

#include <sys/sysmacros.h>

const nvme_field_info_t nvme_format_fields[] = {
	[NVME_FORMAT_REQ_FIELD_LBAF] = {
		.nlfi_vers = &nvme_vers_1v0,
		/*
		 * In the future we should plumb through enough information that
		 * we can check this against the common namespace information.
		 */
		.nlfi_max_size = NVME_FRMT_MAX_LBAF,
		.nlfi_spec = "lbaf",
		.nlfi_human = "LBA format",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_FORMAT_REQ_FIELD_SES] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = NVME_FRMT_MAX_SES,
		.nlfi_spec = "ses",
		.nlfi_human = "secure erase settings",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_FORMAT_REQ_FIELD_NSID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_field_valid_nsid,
		.nlfi_spec = "nsid",
		.nlfi_human = "namespace ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	}
};

size_t nvme_format_nfields = ARRAY_SIZE(nvme_format_fields);

bool
nvme_format_cmds_supported(const nvme_valid_ctrl_data_t *data)
{
	return (data->vcd_id->id_oacs.oa_format != 0);
}
