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
 * NVMe Vendor Unique Command (VUC) support. The NVMe standard offers support
 * for a 'standard' format for vendor unique admin and NVMe commands. We provide
 * both a discovery mechanism and a way to construct and execute vendor unique
 * commands. Unlike with log page and feature discovery there is not a way to
 * turn the discovery information into a request structure. Rather, our
 * expectation is that more intrinsic library functions for these would be added
 * based on the specifics of the unique commands.
 */

#include <strings.h>
#include <unistd.h>

#include "libnvme_impl.h"

void
nvme_vuc_disc_free(nvme_vuc_disc_t *disc)
{
	free(disc);
}

bool
nvme_vuc_disc_dup(nvme_ctrl_t *ctrl, const nvme_vuc_disc_t *src,
    nvme_vuc_disc_t **discp)
{
	nvme_vuc_disc_t *disc;

	if (src == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_vuc_disc_t pointer to duplicate: "
		    "%p", discp));
	}

	if (discp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_vuc_disc_t output pointer: %p",
		    discp));
	}

	disc = calloc(1, sizeof (nvme_vuc_disc_t));
	if (disc == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_vuc_disc_t: %s",
		    strerror(e)));
	}

	(void) memcpy(disc, src, sizeof (nvme_vuc_disc_t));
	*discp = disc;
	return (nvme_ctrl_success(ctrl));

}

const char *
nvme_vuc_disc_name(const nvme_vuc_disc_t *disc)
{
	return (disc->nvd_short);
}

const char *
nvme_vuc_disc_desc(const nvme_vuc_disc_t *disc)
{
	return (disc->nvd_desc);
}

uint32_t
nvme_vuc_disc_opcode(const nvme_vuc_disc_t *disc)
{
	return (disc->nvd_opc);
}

nvme_vuc_disc_io_t
nvme_vuc_disc_dt(const nvme_vuc_disc_t *disc)
{
	return (disc->nvd_dt);
}

nvme_vuc_disc_impact_t
nvme_vuc_disc_impact(const nvme_vuc_disc_t *disc)
{
	return (disc->nvd_impact);
}

nvme_vuc_disc_lock_t
nvme_vuc_disc_lock(const nvme_vuc_disc_t *disc)
{
	return (disc->nvd_lock);
}

void
nvme_vuc_discover_fini(nvme_vuc_iter_t *iter)
{
	free(iter);
}

nvme_iter_t
nvme_vuc_discover_step(nvme_vuc_iter_t *iter, const nvme_vuc_disc_t **outp)
{
	nvme_ctrl_t *ctrl = iter->nvi_ctrl;

	if (ctrl->nc_vsd == NULL) {
		return (NVME_ITER_DONE);
	}

	if (iter->nvi_cur_idx >= ctrl->nc_vsd->nvd_nvuc) {
		return (NVME_ITER_DONE);
	}

	*outp = &ctrl->nc_vsd->nvd_vuc[iter->nvi_cur_idx];
	iter->nvi_cur_idx++;
	return (NVME_ITER_VALID);
}

bool
nvme_vuc_discover_init(nvme_ctrl_t *ctrl, uint32_t flags,
    nvme_vuc_iter_t **iterp)
{
	nvme_vuc_iter_t *iter;

	if (flags != 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0,
		    "encountered invalid discovery flags: 0x%x", flags));
	}

	if (iterp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_vuc_iter_t output pointer: %p",
		    iterp));
	}

	iter = calloc(1, sizeof (nvme_vuc_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_vuc_iter_t: %s",
		    strerror(e)));
	}

	iter->nvi_ctrl = ctrl;

	*iterp = iter;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_vuc_discover(nvme_ctrl_t *ctrl, uint32_t flags, nvme_vuc_disc_f func,
    void *arg)
{
	nvme_vuc_iter_t *iter;
	nvme_iter_t ret;
	const nvme_vuc_disc_t *disc;

	if (func == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_vuc_disc_f function pointer: %p",
		    func));
	}

	if (!nvme_vuc_discover_init(ctrl, flags, &iter)) {
		return (false);
	}

	while ((ret = nvme_vuc_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		if (!func(ctrl, disc, arg))
			break;
	}

	nvme_vuc_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}

bool
nvme_vuc_discover_by_name(nvme_ctrl_t *ctrl, const char *name, uint32_t flags,
    nvme_vuc_disc_t **discp)
{
	nvme_vuc_iter_t *iter;
	nvme_iter_t ret;
	const nvme_vuc_disc_t *disc;

	if (discp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_vuc_disc_t output pointer: %p",
		    discp));
	}

	if (name == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid pointer for name: %p", name));
	}

	if (!nvme_vuc_discover_init(ctrl, flags, &iter)) {
		return (false);
	}

	*discp = NULL;
	while ((ret = nvme_vuc_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		if (strcmp(name, nvme_vuc_disc_name(disc)) == 0) {
			break;
		}
	}

	if (ret == NVME_ITER_VALID && !nvme_vuc_disc_dup(ctrl, disc, discp)) {
		nvme_err_data_t err;

		nvme_ctrl_err_save(ctrl, &err);
		nvme_vuc_discover_fini(iter);
		nvme_ctrl_err_set(ctrl, &err);
		return (false);
	}

	nvme_vuc_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		return (false);
	}

	if (*discp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_VUC_UNKNOWN, 0, "failed "
		    "to map %s to a known vendor unique command", name));
	}

	return (nvme_ctrl_success(ctrl));
}

void
nvme_vuc_req_fini(nvme_vuc_req_t *req)
{
	free(req);
}

bool
nvme_vuc_req_init(nvme_ctrl_t *ctrl, nvme_vuc_req_t **reqp)
{
	nvme_vuc_req_t *req;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_vuc_req_t output pointer: %p",
		    reqp));
	}

	if (ctrl->nc_info.id_nvscc.nv_spec == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_VUC_UNSUP_BY_DEV, 0,
		    "cannot create vuc request because the controller does "
		    "not support the NVMe standard vendor unique command "
		    "interface"));
	}

	req = calloc(1, sizeof (nvme_vuc_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_vuc_req_t: %s",
		    strerror(e)));
	}

	req->nvr_ctrl = ctrl;

	for (size_t i = 0; i < nvme_vuc_nfields; i++) {
		if (nvme_vuc_fields[i].nlfi_def_req) {
			req->nvr_need |= 1 << i;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_vuc_req_clear_need(nvme_vuc_req_t *req, nvme_vuc_req_field_t field)
{
	req->nvr_need &= ~(1 << field);
}

/*
 * We have no way to validate any of the cdw1[2-5] values as these are all
 * vendor-specific commands and the semantics of these are not something we can
 * know. Therefore there are no calls to validate these fields.
 */
bool
nvme_vuc_req_set_cdw12(nvme_vuc_req_t *req, uint32_t cdw12)
{
	req->nvr_cdw12 = cdw12;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_CDW12);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_set_cdw13(nvme_vuc_req_t *req, uint32_t cdw13)
{
	req->nvr_cdw13 = cdw13;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_CDW13);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_set_cdw14(nvme_vuc_req_t *req, uint32_t cdw14)
{
	req->nvr_cdw14 = cdw14;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_CDW14);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_set_cdw15(nvme_vuc_req_t *req, uint32_t cdw15)
{
	req->nvr_cdw15 = cdw15;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_CDW15);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

static const nvme_field_check_t nvme_vuc_check_opcode = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_OPC,
	NVME_ERR_VUC_OPCODE_RANGE, 0, 0
};

bool
nvme_vuc_req_set_opcode(nvme_vuc_req_t *req, uint32_t opc)
{
	if (!nvme_field_check_one(req->nvr_ctrl, opc, "vendor unique command",
	    &nvme_vuc_check_opcode, 0)) {
		return (false);
	}

	req->nvr_opcode = opc;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_OPC);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

static const nvme_field_check_t nvme_vuc_check_nsid = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_NSID,
	NVME_ERR_NS_RANGE, 0, 0
};

bool
nvme_vuc_req_set_nsid(nvme_vuc_req_t *req, uint32_t nsid)
{
	if (!nvme_field_check_one(req->nvr_ctrl, nsid, "vendor unique command",
	    &nvme_vuc_check_nsid, 0)) {
		return (false);
	}

	req->nvr_nsid = nsid;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_NSID);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

static const nvme_field_check_t nvme_vuc_check_to = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_TO,
	NVME_ERR_VUC_TIMEOUT_RANGE, 0, 0
};

bool
nvme_vuc_req_set_timeout(nvme_vuc_req_t *req, uint32_t to)
{
	if (!nvme_field_check_one(req->nvr_ctrl, to, "vendor unique command",
	    &nvme_vuc_check_to, 0)) {
		return (false);
	}

	req->nvr_timeout = to;
	nvme_vuc_req_clear_need(req, NVME_VUC_REQ_FIELD_TO);
	return (nvme_ctrl_success(req->nvr_ctrl));
}

/*
 * Check common parts of a VUC data transfer. While the kernel is going to
 * further constrain our length, we will still check the specified length
 * against the actual specification max.
 */
static const nvme_field_check_t nvme_vuc_check_ndt = {
	nvme_vuc_fields, NVME_VUC_REQ_FIELD_NDT,
	NVME_ERR_VUC_NDT_RANGE, 0, 0
};

static bool
nvme_vuc_req_data_validate(nvme_vuc_req_t *req, const void *buf, size_t len,
    bool in)
{
	nvme_ctrl_t *ctrl = req->nvr_ctrl;
	const char *dir = in ? "input" : "output";
	const char *alt_dir = in ? "output" : "input";
	const void *alt_buf = in ? req->nvr_output : req->nvr_input;

	if (buf == NULL && len > 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0, "vendor "
		    "unique command output output buffer cannot be NULL when "
		    "the length is non-zero"));
	} else if (buf != NULL && len == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_VUC_NDT_RANGE, 0,
		    "vendor unique command buffer size may not be zero when "
		    "given a non-NULL pointer (%p)", buf));
	}

	if (alt_buf != NULL && buf != NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_VUC_CANNOT_RW, 0,
		    "an %s buffer is already set and therefore an %s buffer "
		    "cannot also be added", alt_dir, dir));

	}

	/*
	 * This takes care of alignment and the upper bound.
	 */
	if (!nvme_field_check_one(req->nvr_ctrl, len, "vendor unique command",
	    &nvme_vuc_check_ndt, 0)) {
		return (false);
	}

	return (true);
}

/*
 * The impact values are a libnvme specific item which maps things to the
 * kernel's values. Therefore we don't use the standard validation routines.
 */
bool
nvme_vuc_req_set_impact(nvme_vuc_req_t *req, nvme_vuc_disc_impact_t impact)
{
	const nvme_vuc_disc_impact_t all_impact = NVME_VUC_DISC_IMPACT_DATA |
	    NVME_VUC_DISC_IMPACT_NS;

	if ((impact & ~all_impact) != 0) {
		return (nvme_ctrl_error(req->nvr_ctrl,
		    NVME_ERR_VUC_IMPACT_RANGE, 0, "encountered unknown impact "
		    "flags: 0x%x", impact & ~all_impact));
	}

	req->nvr_impact = impact;
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_set_output(nvme_vuc_req_t *req, void *buf, size_t len)
{
	if (!nvme_vuc_req_data_validate(req, buf, len, false)) {
		return (false);
	}

	req->nvr_output = buf;
	req->nvr_outlen = len;
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_set_input(nvme_vuc_req_t *req, const void *buf, size_t len)
{
	if (!nvme_vuc_req_data_validate(req, buf, len, true)) {
		return (false);
	}

	req->nvr_input = buf;
	req->nvr_inlen = len;
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_get_cdw0(nvme_vuc_req_t *req, uint32_t *cdw0)
{
	if (cdw0 == NULL) {
		return (nvme_ctrl_error(req->nvr_ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid cdw0 output pointer: %p", cdw0));
	}

	if (!req->nvr_results_valid) {
		return (nvme_ctrl_error(req->nvr_ctrl, NVME_ERR_VUC_NO_RESULTS,
		    0, "vendor unique command results are not currently valid "
		    "and cannot be returned"));
	}

	*cdw0 = req->nvr_cdw0;
	return (nvme_ctrl_success(req->nvr_ctrl));
}

bool
nvme_vuc_req_exec(nvme_vuc_req_t *req)
{
	nvme_ctrl_t *ctrl = req->nvr_ctrl;
	nvme_ioctl_passthru_t pass;

	/*
	 * Immediately invalidate our stored data.
	 */
	req->nvr_results_valid = false;
	req->nvr_cdw0 = 0;

	if (req->nvr_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_vuc_fields,
		    nvme_vuc_nfields, NVME_ERR_VUC_REQ_MISSING_FIELDS,
		    "vendor unique command", req->nvr_need));
	}

	(void) memset(&pass, 0, sizeof (nvme_ioctl_passthru_t));
	pass.npc_common.nioc_nsid = req->nvr_nsid;
	pass.npc_opcode = req->nvr_opcode;
	pass.npc_timeout = req->nvr_timeout;
	pass.npc_cdw12 = req->nvr_cdw12;
	pass.npc_cdw13 = req->nvr_cdw13;
	pass.npc_cdw14 = req->nvr_cdw14;
	pass.npc_cdw15 = req->nvr_cdw14;

	if (req->nvr_input != NULL) {
		pass.npc_buflen = req->nvr_inlen;
		pass.npc_buf = (uintptr_t)req->nvr_input;
		pass.npc_flags = NVME_PASSTHRU_WRITE;
	} else if (req->nvr_output != NULL) {
		pass.npc_buflen = req->nvr_outlen;
		pass.npc_buf = (uintptr_t)req->nvr_output;
		pass.npc_flags = NVME_PASSTHRU_READ;
	}

	if ((req->nvr_impact & NVME_VUC_DISC_IMPACT_NS) != 0) {
		pass.npc_impact |= NVME_IMPACT_NS;
	}

	if (ioctl(ctrl->nc_fd, NVME_IOC_PASSTHRU, &pass) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "vendor unique command"));
	}

	if (pass.npc_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &pass.npc_common,
		    "vendor unique command"));
	}

	req->nvr_results_valid = true;
	req->nvr_cdw0 = pass.npc_cdw0;

	return (nvme_ctrl_success(ctrl));
}
