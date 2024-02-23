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
 * This file implements the firmware download and commit pieces of libnvme.
 */

#include <string.h>
#include <unistd.h>

#include "libnvme_impl.h"

static const nvme_field_check_t nvme_fw_load_check_numd = {
	nvme_fw_load_fields, NVME_FW_LOAD_REQ_FIELD_NUMD,
	NVME_ERR_FW_LOAD_LEN_RANGE, 0, 0
};

static const nvme_field_check_t nvme_fw_load_check_offset = {
	nvme_fw_load_fields, NVME_FW_LOAD_REQ_FIELD_OFFSET,
	NVME_ERR_FW_LOAD_OFFSET_RANGE, 0, 0
};

bool
nvme_fw_load(nvme_ctrl_t *ctrl, const void *buf, size_t len, uint64_t off)
{
	nvme_ioctl_fw_load_t fw;
	nvme_valid_ctrl_data_t data;

	if (buf == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid data buffer pointer: %p", buf));
	}

	data.vcd_vers = &ctrl->nc_vers;
	data.vcd_id = &ctrl->nc_info;

	if (!nvme_fw_cmds_supported(&data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_FW_UNSUP_BY_DEV, 0,
		    "controller does not support firmware download"));
	}

	if (!nvme_field_check_one(ctrl, len, "firmware download",
	    &nvme_fw_load_check_numd, 0)) {
		return (false);
	}

	if (!nvme_field_check_one(ctrl, off, "firmware download",
	    &nvme_fw_load_check_offset, 0)) {
		return (false);
	}

	(void) memset(&fw, 0, sizeof (fw));
	fw.fwl_buf = (uintptr_t)buf;
	fw.fwl_len = len;
	fw.fwl_off = off;

	if (ioctl(ctrl->nc_fd, NVME_IOC_FIRMWARE_DOWNLOAD, &fw) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "firmware load"));
	}

	if (fw.fwl_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &fw.fwl_common,
		    "firmware load"));
	}

	return (nvme_ctrl_success(ctrl));
}

void
nvme_fw_commit_req_fini(nvme_fw_commit_req_t *req)
{
	free(req);
}

bool
nvme_fw_commit_req_init(nvme_ctrl_t *ctrl, nvme_fw_commit_req_t **reqp)
{
	nvme_fw_commit_req_t *req;
	nvme_valid_ctrl_data_t data;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_commit_req_t output pointer: %p",
		    reqp));
	}

	data.vcd_vers = &ctrl->nc_vers;
	data.vcd_id = &ctrl->nc_info;

	if (!nvme_fw_cmds_supported(&data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_FW_UNSUP_BY_DEV, 0,
		    "controller does not support firmware download"));
	}

	req = calloc(1, sizeof (nvme_fw_commit_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_log_req_t: %s",
		    strerror(e)));
	}

	req->fwc_ctrl = ctrl;

	for (size_t i = 0; i < nvme_fw_commit_nfields; i++) {
		if (nvme_fw_commit_fields[i].nlfi_def_req) {
			req->fwc_need |= 1 << i;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_fw_commit_req_clear_need(nvme_fw_commit_req_t *req,
    nvme_fw_commit_req_field_t field)
{
	req->fwc_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_fw_commit_check_slot = {
	nvme_fw_commit_fields, NVME_FW_COMMIT_REQ_FIELD_SLOT,
	NVME_ERR_FW_COMMIT_SLOT_RANGE, 0, 0
};

bool
nvme_fw_commit_req_set_slot(nvme_fw_commit_req_t *req, uint32_t slot)
{
	if (!nvme_field_check_one(req->fwc_ctrl, slot, "firmware commit",
	    &nvme_fw_commit_check_slot, 0)) {
		return (false);
	}

	req->fwc_slot = slot;
	nvme_fw_commit_req_clear_need(req, NVME_FW_COMMIT_REQ_FIELD_SLOT);
	return (nvme_ctrl_success(req->fwc_ctrl));
}

static const nvme_field_check_t nvme_fw_commit_check_act = {
	nvme_fw_commit_fields, NVME_FW_COMMIT_REQ_FIELD_ACT,
	NVME_ERR_FW_COMMIT_ACTION_RANGE, 0, 0
};

bool
nvme_fw_commit_req_set_action(nvme_fw_commit_req_t *req, uint32_t act)
{
	if (!nvme_field_check_one(req->fwc_ctrl, act, "firmware commit",
	    &nvme_fw_commit_check_act, 0)) {
		return (false);
	}

	req->fwc_action = act;
	nvme_fw_commit_req_clear_need(req, NVME_FW_COMMIT_REQ_FIELD_ACT);
	return (nvme_ctrl_success(req->fwc_ctrl));
}

bool
nvme_fw_commit_req_exec(nvme_fw_commit_req_t *req)
{
	nvme_ctrl_t *ctrl = req->fwc_ctrl;
	nvme_ioctl_fw_commit_t fw;

	if (req->fwc_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_fw_commit_fields,
		    nvme_fw_commit_nfields,
		    NVME_ERR_FW_COMMIT_REQ_MISSING_FIELDS, "firmware commit",
		    req->fwc_need));
	}

	(void) memset(&fw, 0, sizeof (fw));
	fw.fwc_slot = req->fwc_slot;
	fw.fwc_action = req->fwc_action;

	if (ioctl(ctrl->nc_fd, NVME_IOC_FIRMWARE_COMMIT, &fw) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "firmware commit"));
	}

	if (fw.fwc_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &fw.fwc_common,
		    "firmware commit"));
	}

	return (nvme_ctrl_success(ctrl));
}
