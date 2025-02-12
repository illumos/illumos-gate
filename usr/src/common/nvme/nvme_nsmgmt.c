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
 * Common field and validation for NVMe Namespace related commands. This covers
 * attaching and detaching controllers to namespaces as well as creating and
 * deleting namespaces.
 */

#include "nvme_common.h"

#include <sys/sysmacros.h>

static bool
nvme_ns_attach_field_valid_sel(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t act, char *msg, size_t msglen)
{
	const uint64_t min = NVME_NS_ATTACH_CTRL_ATTACH;
	const uint64_t max = NVME_NS_ATTACH_CTRL_DETACH;

	return (nvme_field_range_check(field, min, max, msg, msglen, act));
}

const nvme_field_info_t nvme_ns_attach_fields[] = {
	[NVME_NS_ATTACH_REQ_FIELD_SEL] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_valid = nvme_ns_attach_field_valid_sel,
		.nlfi_spec = "sel",
		.nlfi_human = "select",
		.nlfi_def_req = true,
		.nlfi_def_allow = false
	},
	[NVME_NS_ATTACH_REQ_FIELD_NSID] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_valid = nvme_field_valid_nsid,
		.nlfi_spec = "nsid",
		.nlfi_human = "namespace ID",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	/*
	 * The interpretation of the data pointer is technically specific to the
	 * select command. As we don't actually accept any data, right now this
	 * is here just for libnvme tracking purposes.
	 */
	[NVME_NS_ATTACH_REQ_FIELD_DPTR] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_spec = "dptr",
		.nlfi_human = "data pointer",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	}
};

const size_t nvme_ns_attach_nfields = ARRAY_SIZE(nvme_ns_attach_fields);

const nvme_field_info_t nvme_ns_delete_fields[] = {
	[NVME_NS_DELETE_REQ_FIELD_NSID] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_valid = nvme_field_valid_nsid,
		.nlfi_spec = "nsid",
		.nlfi_human = "namespace ID",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	}
};

const size_t nvme_ns_delete_nfields = ARRAY_SIZE(nvme_ns_delete_fields);

/*
 * This is an integer which currently has only a single bit defined, bit 0.
 * Though NVMe 2.1 will change this.
 */
static bool
nvme_ns_create_field_valid_nmic(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t act, char *msg, size_t msglen)
{
	return (nvme_field_mask_check(field, NVME_NS_MGMT_NMIC_MASK, msg,
	    msglen, act));
}

/*
 * The NSZE and NCAP fields are related. Because these are in terms of a
 * formatted LBA which we don't have quite at this moment, we can't confirm the
 * maximum value; however, we do know enough to know a value of zero is wrong.
 */
static bool
nvme_ns_attach_field_valid_nsze(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t act, char *msg, size_t msglen)
{
	return (nvme_field_range_check(field, 1, UINT64_MAX, msg, msglen, act));
}

/*
 * The set of fields that are required to be allowed or defaults varies based
 * upon the CSI that is used. For example the NVM and K/V command sets have
 * different required fields. As such, the notion of what's required and
 * settable is something that is determined by the CSI, hence why the required
 * and allowed fields are missing for everything that isn't the CSI.
 */
const nvme_field_info_t nvme_ns_create_fields[] = {
	[NVME_NS_CREATE_REQ_FIELD_CSI] = {
		/*
		 * The libnvme APIs require that a CSI is passed to create this,
		 * so this 2.0 isn't quite truly enforced.
		 */
		.nlfi_vers = &nvme_vers_2v0,
		.nlfi_max_size = NVME_NS_MGMT_MAX_CSI,
		.nlfi_spec = "csi",
		.nlfi_human = "command set ID",
		.nlfi_def_req = true,
		.nlfi_def_allow = false
	},
	[NVME_NS_CREATE_REQ_FIELD_NSZE] = {
		.nlfi_vers = &nvme_vers_1v2,
		/*
		 * The NSZE and NCAP fields are required to be related by a
		 * namespace granularity record; however, this was not
		 * introduced until NVMe 1.4. Absent this information, the main
		 * constraint is that the two are equivalent unless thin
		 * provisioning is supported. In addition, when setting the
		 * field, we don't know what LBA size someone has selected, so
		 * this can only be checked at command execution time.
		 */
		.nlfi_valid = nvme_ns_attach_field_valid_nsze,
		.nlfi_spec = "nsze",
		.nlfi_human = "namespace size"
	},
	[NVME_NS_CREATE_REQ_FIELD_NCAP] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_valid = nvme_ns_attach_field_valid_nsze,
		.nlfi_spec = "ncap",
		.nlfi_human = "namespace capacity"
	},
	[NVME_NS_CREATE_REQ_FIELD_FLBAS] = {
		.nlfi_vers = &nvme_vers_1v2,
		/*
		 * See the notes in common/nvme/nvme_format.c around this choice
		 * of maximum.
		 */
		.nlfi_max_size = NVME_NS_MGMT_MAX_FLBAS,
		.nlfi_spec = "flbas",
		.nlfi_human = "formatted LBA size"
	},
	[NVME_NS_CREATE_REQ_FIELD_NMIC] = {
		.nlfi_vers = &nvme_vers_1v2,
		.nlfi_valid = nvme_ns_create_field_valid_nmic,
		.nlfi_max_size = NVME_NS_MGMT_MAX_FLBAS,
		.nlfi_spec = "nmic",
		.nlfi_human = "namespace multi-path I/O and namespace sharing "
		    "capabilities"
	}
};

const size_t nvme_ns_create_nfields = ARRAY_SIZE(nvme_ns_create_fields);

/*
 * These are the default fields that are required for an NVM command. The CSI
 * cannot be set. The we allow to default to zero, unshared, and therefore is
 * optional.
 */
const nvme_ns_create_req_field_t nvme_ns_create_fields_nvm_req[] = {
	NVME_NS_CREATE_REQ_FIELD_NSZE, NVME_NS_CREATE_REQ_FIELD_NCAP,
	NVME_NS_CREATE_REQ_FIELD_FLBAS
};
const size_t nvme_ns_create_fields_nvm_nreq =
    ARRAY_SIZE(nvme_ns_create_fields_nvm_req);

const nvme_ns_create_req_field_t nvme_ns_create_fields_nvm_allow[] = {
	NVME_NS_CREATE_REQ_FIELD_NSZE, NVME_NS_CREATE_REQ_FIELD_NCAP,
	NVME_NS_CREATE_REQ_FIELD_FLBAS, NVME_NS_CREATE_REQ_FIELD_NMIC
};
const size_t nvme_ns_create_fields_nvm_nallow =
    ARRAY_SIZE(nvme_ns_create_fields_nvm_allow);

bool
nvme_nsmgmt_cmds_supported(const nvme_valid_ctrl_data_t *data)
{
	if (nvme_vers_atleast(data->vcd_vers, &nvme_vers_1v2)) {
		return (data->vcd_id->id_oacs.oa_nsmgmt != 0);
	}

	return (false);
}
