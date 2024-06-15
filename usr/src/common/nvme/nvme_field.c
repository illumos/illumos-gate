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
 * This file contains shared pieces of the NVMe field validation logic and has
 * shared pieces that are used between different parts.
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

bool
nvme_field_atleast(const nvme_valid_ctrl_data_t *data,
    const nvme_version_t *targ)
{
	return (nvme_vers_atleast(data->vcd_vers, targ));
}

/*
 * Note, we rely on external logic to determine if the broadcast nsid is valid.
 * We always accept it.
 */
bool
nvme_field_valid_nsid(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t nsid, char *msg, size_t msglen)
{
	if ((nsid != 0 && nsid <= data->vcd_id->id_nn) ||
	    nsid == NVME_NSID_BCAST) {
		return (true);
	}

	(void) snprintf(msg, msglen, "namespace id %" PRIu64 "is outside the "
	    "valid range [0x%x, 0x%x], the broadcast nsid (0x%x) may be valid",
	    nsid, NVME_NSID_MIN, NVME_NSID_BCAST, data->vcd_id->id_nn);
	return (false);
}

bool
nvme_field_range_check(const nvme_field_info_t *field, uint64_t min,
    uint64_t max, char *msg, size_t msglen, uint64_t value)
{
	if (value >= min && value <= max) {
		return (true);
	}

	(void) snprintf(msg, msglen, "field %s (%s) value 0x%"
	    PRIx64 " is outside the valid range: [0x%" PRIx64 ", 0x%" PRIx64
	    "]", field->nlfi_human, field->nlfi_spec, value, min, max);
	return (false);
}

/*
 * This is a general validation function for fields that are part of a command.
 * It will check if the field is supported by the controller and if so, that its
 * value is within the expected range. On error, an optional message will be
 * written that explains the error. This is intended to be shared between
 * userland and the kernel. The kernel should pass NULL/0 for msg/msglen because
 * there is no message translation capability in the kernel.
 */
nvme_field_error_t
nvme_field_validate(const nvme_field_info_t *field,
    const nvme_valid_ctrl_data_t *data, uint64_t value, char *msg,
    size_t msglen)
{
	ASSERT3P(field->nlfi_vers, !=, NULL);

	if (!nvme_field_atleast(data, field->nlfi_vers)) {
		(void) snprintf(msg, msglen, "field %s (%s) requires "
		    "version %u.%u, but device is at %u.%u", field->nlfi_human,
		    field->nlfi_spec, data->vcd_vers->v_major,
		    data->vcd_vers->v_minor, field->nlfi_vers->v_major,
		    field->nlfi_vers->v_minor);
		return (NVME_FIELD_ERR_UNSUP_VERSION);
	}

	if (field->nlfi_sup != NULL && !field->nlfi_sup(field, data, msg,
	    msglen)) {
		(void) snprintf(msg, msglen, "field %s (%s) is not "
		    "supported by the controller", field->nlfi_human,
		    field->nlfi_spec);
		return (NVME_FIELD_ERR_UNSUP_FIELD);
	}

	if (field->nlfi_valid != NULL) {
		if (!field->nlfi_valid(field, data, value, msg, msglen)) {
			(void) snprintf(msg, msglen, "field %s (%s) "
			    "value 0x%" PRIx64 " is invalid", field->nlfi_human,
			    field->nlfi_spec, value);
			return (NVME_FIELD_ERR_BAD_VALUE);
		}
	} else if (!nvme_field_range_check(field, 0, field->nlfi_max_size, msg,
	    msglen, value)) {
		return (NVME_FIELD_ERR_BAD_VALUE);
	}

	return (NVME_FIELD_ERR_OK);
}
