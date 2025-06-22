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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Information about supported NVMe identify commands that can be issued.
 */

#include "nvme_common.h"

#include <sys/sysmacros.h>

static bool
nvme_identify_field_valid_cns(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t cns, char *msg, size_t msglen)
{
	uint64_t max;

	if (nvme_field_atleast(data, &nvme_vers_1v2)) {
		max = NVME_IDENTIFY_MAX_CNS_1v2;
	} else if (nvme_field_atleast(data, &nvme_vers_1v1)) {
		max = NVME_IDENTIFY_MAX_CNS_1v1;
	} else {
		max = NVME_IDENTIFY_MAX_CNS;
	}

	return (nvme_field_range_check(field, 0, max, msg, msglen, cns));
}

static bool
nvme_identify_field_valid_buf(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t len, char *msg, size_t msglen)
{
	return (nvme_field_range_check(field, NVME_IDENTIFY_BUFSIZE,
	    NVME_IDENTIFY_BUFSIZE, msg, msglen, len));
}

const nvme_field_info_t nvme_identify_fields[] = {
	[NVME_ID_REQ_F_CNS] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_identify_field_valid_cns,
		.nlfi_spec = "cns",
		.nlfi_human = "Controller or Namespace Structure",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_ID_REQ_F_NSID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_spec = "nsid",
		/*
		 * The NSID for an identify command can have several different
		 * forms.
		 */
		.nlfi_max_size = NVME_IDENTIFY_MAX_NSID,
		.nlfi_human = "namespace ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_ID_REQ_F_CTRLID] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_max_size = NVME_IDENTIFY_MAX_CTRLID,
		.nlfi_spec = "cntid",
		.nlfi_human = "Controller ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_ID_REQ_F_BUF] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_identify_field_valid_buf,
		.nlfi_spec = "dptr",
		.nlfi_human = "output",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	}
};

const size_t nvme_identify_nfields = ARRAY_SIZE(nvme_identify_fields);

static bool
nvme_identify_support_nsid(const nvme_valid_ctrl_data_t *data)
{
	return (data->vcd_id->id_oacs.oa_nsmgmt != 0);
}

const nvme_identify_info_t nvme_identify_cmds[] = { {
	.nii_name = "identify namespace",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_NSID,
	.nii_vers = &nvme_vers_1v0,
	.nii_fields = 1 << NVME_ID_REQ_F_NSID,
	.nii_flags = NVME_IDENTIFY_INFO_F_NS_OK | NVME_IDENTIFY_INFO_F_BCAST
}, {
	.nii_name = "identify controller",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_CTRL,
	.nii_vers = &nvme_vers_1v0,
}, {
	.nii_name = "active namespace ID list",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_NSID_LIST,
	.nii_vers = &nvme_vers_1v1,
	.nii_fields = 1 << NVME_ID_REQ_F_NSID,
	.nii_flags = NVME_IDENTIFY_INFO_F_NSID_LIST
}, {
	.nii_name = "namespace identification descriptor list",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_NSID_DESC,
	.nii_vers = &nvme_vers_1v3,
	.nii_fields = (1 << NVME_ID_REQ_F_NSID),
	.nii_flags = NVME_IDENTIFY_INFO_F_NS_OK
}, {
	.nii_name = "allocated namespace id list",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_NSID_ALLOC_LIST,
	.nii_vers = &nvme_vers_1v2,
	.nii_sup_func = nvme_identify_support_nsid,
	.nii_fields = 1 << NVME_ID_REQ_F_NSID,
	.nii_flags = NVME_IDENTIFY_INFO_F_NSID_LIST
}, {
	.nii_name = "identify allocated namespace",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_NSID_ALLOC,
	.nii_vers = &nvme_vers_1v2,
	.nii_sup_func = nvme_identify_support_nsid,
	.nii_fields = 1 << NVME_ID_REQ_F_NSID,
	.nii_flags = NVME_IDENTIFY_INFO_F_NS_OK
}, {
	.nii_name = "namespace attached controller list",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_NSID_CTRL_LIST,
	.nii_vers = &nvme_vers_1v2,
	.nii_sup_func = nvme_identify_support_nsid,
	.nii_fields = (1 << NVME_ID_REQ_F_NSID) | (1 << NVME_ID_REQ_F_CTRLID),
	.nii_flags = NVME_IDENTIFY_INFO_F_NS_OK
}, {
	.nii_name = "nvm subsystem controller list",
	.nii_csi = NVME_CSI_NVM,
	.nii_cns = NVME_IDENTIFY_CTRL_LIST,
	.nii_vers = &nvme_vers_1v2,
	.nii_sup_func = nvme_identify_support_nsid,
	.nii_fields = (1 << NVME_ID_REQ_F_CTRLID)
} };

const size_t nvme_identify_ncmds = ARRAY_SIZE(nvme_identify_cmds);

bool
nvme_identify_info_supported(const nvme_identify_info_t *info,
    const nvme_valid_ctrl_data_t *data)
{
	if (info->nii_vers != NULL && !nvme_field_atleast(data,
	    info->nii_vers)) {
		return (false);
	}

	if (info->nii_sup_func != NULL && !info->nii_sup_func(data)) {
		return (false);
	}

	return (true);
}
