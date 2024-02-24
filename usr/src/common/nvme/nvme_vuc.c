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
 * Common field and validation pieces for NVMe Vendor Unique Admin and NVM
 * commands.
 */

#include "nvme_common.h"

#include <sys/sysmacros.h>
#ifdef	_KERNEL
#include <sys/sunddi.h>
#include <sys/stdint.h>
#else
#include <stdio.h>
#include <inttypes.h>
#endif

/*
 * Right now this mainly checks for a valid admin command set operation code.
 * When we end up supporting commands that are meant to be submitted to NVM
 * queues, we'll likely need to add a way to know what type of command set we're
 * targeting.
 */
static bool
nvme_vuc_field_valid_opc(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t opcode, char *msg,
    size_t msglen)
{
	return (nvme_field_range_check(field, NVME_PASSTHRU_MIN_ADMIN_OPC,
	    NVME_PASSTHRU_MAX_ADMIN_OPC, msg, msglen, opcode));
}

/*
 * Unlike with log pages, identify commands, features, etc. we do not know how
 * the namespace will be used. It may be zero, it may need to be the broadcast
 * namespace, or it may target a device specific namespace. As such, we accept
 * all of these, which isn't normally the case.
 */
static bool
nvme_vuc_field_valid_nsid(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t nsid, char *msg, size_t msglen)
{
	if (nsid == 0) {
		return (true);
	}

	return (nvme_field_valid_nsid(field, data, nsid, msg, msglen));
}

/*
 * A VUC data length is in dwords. It's our responsibility to make sure that
 * this is properly aligned. Though zero is a valid value.
 */
static bool
nvme_vuc_field_valid_ndt(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t len, char *msg, size_t msglen)
{
	uint64_t max = (uint64_t)UINT32_MAX << NVME_DWORD_SHIFT;

	if ((len % NVME_DWORD_SIZE) != 0) {
		(void) snprintf(msg, msglen, "%s (%s) value 0x%" PRIx64 " is "
		    "invalid: value must be %u-byte aligned", field->nlfi_human,
		    field->nlfi_spec, len, NVME_DWORD_SIZE);
		return (false);
	}

	return (nvme_field_range_check(field, 0, max, msg, msglen, len));
}

/*
 * The maximum timeout is controlled by the kernel. The only real constraint
 * right now is that it fit into the ioctl size and is non-zero.
 */
static bool
nvme_vuc_field_valid_to(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t to, char *msg, size_t msglen)
{
	return (nvme_field_range_check(field, 1, UINT32_MAX, msg, msglen, to));
}

const nvme_field_info_t nvme_vuc_fields[] = {
	[NVME_VUC_REQ_FIELD_OPC] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_vuc_field_valid_opc,
		.nlfi_spec = "opc",
		.nlfi_human = "opcode",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_NSID] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_vuc_field_valid_nsid,
		.nlfi_spec = "nsid",
		.nlfi_human = "namespace ID",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_CDW12] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT32_MAX,
		.nlfi_spec = "cdw12",
		.nlfi_human = "command dword 12",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_CDW13] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT32_MAX,
		.nlfi_spec = "cdw13",
		.nlfi_human = "command dword 13",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_CDW14] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT32_MAX,
		.nlfi_spec = "cdw14",
		.nlfi_human = "command dword 14",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_CDW15] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_max_size = UINT32_MAX,
		.nlfi_spec = "cdw15",
		.nlfi_human = "command dword 15",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_NDT] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_vuc_field_valid_ndt,
		.nlfi_spec = "ndt",
		.nlfi_human = "number of dwords in data transfer",
		.nlfi_def_req = false,
		.nlfi_def_allow = true
	},
	[NVME_VUC_REQ_FIELD_TO] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_vuc_field_valid_to,
		.nlfi_spec = "to",
		.nlfi_human = "timeout",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	}
};

size_t nvme_vuc_nfields = ARRAY_SIZE(nvme_vuc_fields);
