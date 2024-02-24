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
 * This file implements support for Format NVM.
 */

#include <string.h>
#include <unistd.h>

#include "libnvme_impl.h"

void
nvme_format_req_fini(nvme_format_req_t *req)
{
	free(req);
}

bool
nvme_format_req_init(nvme_ctrl_t *ctrl, nvme_format_req_t **reqp)
{
	nvme_format_req_t *req;
	nvme_valid_ctrl_data_t ctrl_data;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_format_req_t output pointer: %p",
		    reqp));
	}

	ctrl_data.vcd_vers = &ctrl->nc_vers;
	ctrl_data.vcd_id = &ctrl->nc_info;

	if (!nvme_format_cmds_supported(&ctrl_data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_FORMAT_UNSUP_BY_DEV, 0,
		    "controller does not support format NVM"));
	}

	req = calloc(1, sizeof (nvme_format_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_log_req_t: %s",
		    strerror(e)));
	}

	req->nfr_ctrl = ctrl;
	req->nfr_nsid = NVME_NSID_BCAST;

	for (size_t i = 0; i < nvme_format_nfields; i++) {
		if (nvme_format_fields[i].nlfi_def_req) {
			req->nfr_need |= 1 << i;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_format_req_clear_need(nvme_format_req_t *req,
    nvme_format_req_field_t field)
{
	req->nfr_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_format_check_ses = {
	nvme_format_fields, NVME_FORMAT_REQ_FIELD_SES,
	NVME_ERR_FORMAT_SES_RANGE, 0, 0
};

bool
nvme_format_req_set_ses(nvme_format_req_t *req, uint32_t ses)
{
	if (!nvme_field_check_one(req->nfr_ctrl, ses, "format NVM",
	    &nvme_format_check_ses, 0)) {
		return (false);
	}

	req->nfr_ses = ses;
	nvme_format_req_clear_need(req, NVME_FORMAT_REQ_FIELD_SES);
	return (nvme_ctrl_success(req->nfr_ctrl));
}

static const nvme_field_check_t nvme_format_check_lbaf = {
	nvme_format_fields, NVME_FORMAT_REQ_FIELD_LBAF,
	NVME_ERR_FORMAT_LBAF_RANGE, 0, 0
};

/*
 * We don't try to check the range of the actual LBA formats that are here and
 * instead leave that to the kernel which always has valid common namespace
 * information. It would be nice to fold that in to the common logic in the
 * future.
 */
bool
nvme_format_req_set_lbaf(nvme_format_req_t *req, uint32_t lbaf)
{
	if (!nvme_field_check_one(req->nfr_ctrl, lbaf, "format NVM",
	    &nvme_format_check_lbaf, 0)) {
		return (false);
	}

	req->nfr_lbaf = lbaf;
	nvme_format_req_clear_need(req, NVME_FORMAT_REQ_FIELD_LBAF);
	return (nvme_ctrl_success(req->nfr_ctrl));
}

static const nvme_field_check_t nvme_format_check_nsid = {
	nvme_format_fields, NVME_FORMAT_REQ_FIELD_NSID,
	NVME_ERR_NS_RANGE, 0, 0
};

bool
nvme_format_req_set_nsid(nvme_format_req_t *req, uint32_t nsid)
{
	if (!nvme_field_check_one(req->nfr_ctrl, nsid, "format NVM",
	    &nvme_format_check_nsid, 0)) {
		return (false);
	}

	req->nfr_nsid = nsid;
	nvme_format_req_clear_need(req, NVME_FORMAT_REQ_FIELD_NSID);
	return (nvme_ctrl_success(req->nfr_ctrl));
}

/*
 * All error checking with respect to whether or not the controller supports
 * operating on a single namespace is left to the kernel and translated back
 * here.
 */
bool
nvme_format_req_exec(nvme_format_req_t *req)
{
	nvme_ctrl_t *ctrl = req->nfr_ctrl;
	nvme_ioctl_format_t format;

	if (req->nfr_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_format_fields,
		    nvme_format_nfields, NVME_ERR_FORMAT_REQ_MISSING_FIELDS,
		    "format", req->nfr_need));
	}

	(void) memset(&format, 0, sizeof (format));
	format.nif_common.nioc_nsid = req->nfr_nsid;
	format.nif_lbaf = req->nfr_lbaf;
	format.nif_ses = req->nfr_ses;

	if (ioctl(ctrl->nc_fd, NVME_IOC_FORMAT, &format) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "format"));
	}

	if (format.nif_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &format.nif_common, "format"));
	}

	return (nvme_ctrl_success(ctrl));
}
