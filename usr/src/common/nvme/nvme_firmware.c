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
 * Common field and validation for NVMe firmware related pieces.
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
 * The default granularity we enforce prior to the 1.3 spec's introduction of
 * the FWUG (firmware update granularity).
 */
#define	NVME_DEFAULT_FWUG	4096

/*
 * The FWUG is in multiples of 4 KiB.
 */
#define	NVME_FWUG_MULT	4096

/*
 * Answers the question of are firmware commands supported or not in a way
 * that is a bit easier for us to unit test.
 */
bool
nvme_fw_cmds_supported(const nvme_valid_ctrl_data_t *data)
{
	return (data->vcd_id->id_oacs.oa_firmware != 0);
}

/*
 * Validate a length/offset for an NVMe firmware download request.
 * These fields in the NVMe specification are in units of uint32_t values but,
 * since the ioctl interfaces deal with byte counts, so do these validation
 * functions. According to the specification the same constraints hold for
 * both the length and offset fields; experience has shown, however, that we
 * need to be more relaxed when validating the length -- see the comment in the
 * validation function below.
 *
 * Starting in NVMe 1.3, additional constraints about the granularity were
 * added through the FWUG field in the identify controller data structure. This
 * indicates the required alignment in 4 KiB chunks. The controller is allowed
 * to indicate a value of 0 to indicate that this is unknown (which is not
 * particularly helpful) or that it may be 0xff which indicates that there is
 * no alignment constraint other than the natural uint32_t alignment.
 *
 * For devices that exist prior to NVMe 1.3, we assume that we probably need at
 * least 4 KiB granularity for the time being. This may need to change in the
 * future.
 */
uint32_t
nvme_fw_load_granularity(const nvme_valid_ctrl_data_t *data)
{
	uint32_t gran = NVME_DEFAULT_FWUG;

	if (nvme_vers_atleast(data->vcd_vers, &nvme_vers_1v3)) {
		const uint8_t fwug = data->vcd_id->ap_fwug;
		if (fwug == 0xff) {
			gran = NVME_DWORD_SIZE;
		} else if (fwug != 0) {
			gran = fwug * NVME_FWUG_MULT;
		}
	}

	return (gran);
}

static bool
nvme_fw_load_field_valid_len(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t len, char *msg, size_t msglen)
{
	/*
	 * While we would like to validate that the length is consistent with
	 * the firmware upgrade granularity, we have encountered drives where
	 * the vendor's firmware update file sizes are not a multiple of the
	 * required granularity, and where the strategy of padding the last
	 * block out to that required granularity does not always result in a
	 * file that the drive will accept.
	 *
	 * The best we can do is ensure that it is a whole number of dwords.
	 */
	if ((len & NVME_DWORD_MASK) != 0) {
		(void) snprintf(msg, msglen, "%s (%s) value 0x%" PRIx64 " must "
		    "be aligned to the firmware update granularity 0x%x",
		    field->nlfi_human, field->nlfi_spec, len, NVME_DWORD_SIZE);
		return (false);
	}
	return (nvme_field_range_check(field, NVME_DWORD_SIZE,
	    NVME_FW_LENB_MAX, msg, msglen, len));
}

static bool
nvme_fw_load_field_valid_offset(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t off, char *msg, size_t msglen)
{
	uint32_t gran = nvme_fw_load_granularity(data);

	if ((off % gran) != 0) {
		(void) snprintf(msg, msglen, "%s (%s) value 0x%" PRIx64 " must "
		    "be aligned to the firmware update granularity 0x%x",
		    field->nlfi_human, field->nlfi_spec, off, gran);
		return (false);
	}

	return (nvme_field_range_check(field, 0, NVME_FW_OFFSETB_MAX, msg,
	    msglen, off));
}

const nvme_field_info_t nvme_fw_load_fields[] = {
	[NVME_FW_LOAD_REQ_FIELD_NUMD] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_fw_load_field_valid_len,
		.nlfi_spec = "numd",
		.nlfi_human = "number of dwords",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_FW_LOAD_REQ_FIELD_OFFSET] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_fw_load_field_valid_offset,
		.nlfi_spec = "ofst",
		.nlfi_human = "offset",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	}
};

size_t nvme_fw_load_nfields = ARRAY_SIZE(nvme_fw_load_fields);

static bool
nvme_fw_commit_field_valid_slot(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t slot, char *msg, size_t msglen)
{
	return (nvme_field_range_check(field, NVME_FW_SLOT_MIN,
	    data->vcd_id->id_frmw.fw_nslot, msg, msglen, slot));
}

/*
 * This validation function represents an area of improvement that we'd like to
 * figure out in the future. Immediate firmware activations are only supported
 * in NVMe 1.3, so while it's a bad value prior to NVMe 1.3, that is a somewhat
 * confusing error. In addition, the various boot partition updates are not
 * supported, so it's not a bad value to the spec, but just to us.
 */
static bool
nvme_fw_commit_field_valid_act(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t act, char *msg, size_t msglen)
{
	uint64_t max = NVME_FWC_ACTIVATE;

	if (nvme_vers_atleast(data->vcd_vers, &nvme_vers_1v3)) {
		max = NVME_FWC_ACTIVATE_IMMED;
	}

	return (nvme_field_range_check(field, 0, max, msg, msglen, act));
}

const nvme_field_info_t nvme_fw_commit_fields[] = {
	[NVME_FW_COMMIT_REQ_FIELD_SLOT] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_fw_commit_field_valid_slot,
		.nlfi_spec = "fs",
		.nlfi_human = "firmware slot",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	},
	[NVME_FW_COMMIT_REQ_FIELD_ACT] = {
		.nlfi_vers = &nvme_vers_1v0,
		.nlfi_valid = nvme_fw_commit_field_valid_act,
		.nlfi_spec = "ca",
		.nlfi_human = "commit action",
		.nlfi_def_req = true,
		.nlfi_def_allow = true
	}
};

size_t nvme_fw_commit_nfields = ARRAY_SIZE(nvme_fw_commit_fields);
