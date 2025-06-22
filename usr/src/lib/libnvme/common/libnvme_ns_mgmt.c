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
 * This implements support for Namespace Management and Namespace Attach
 * commands.
 */

#include <string.h>
#include <unistd.h>

#include "libnvme_impl.h"

void
nvme_ns_attach_req_fini(nvme_ns_attach_req_t *req)
{
	free(req);
}

static void
nvme_ns_attach_req_clear_need(nvme_ns_attach_req_t *req,
    nvme_ns_attach_req_field_t field)
{
	req->nar_need &= ~(1 << field);
}

bool
nvme_ns_attach_req_init_by_sel(nvme_ctrl_t *ctrl, uint32_t sel,
    nvme_ns_attach_req_t **reqp)
{
	nvme_ns_attach_req_t *req;
	nvme_valid_ctrl_data_t ctrl_data;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_attach_req_t output pointer: "
		    "%p", reqp));
	}

	ctrl_data.vcd_vers = &ctrl->nc_vers;
	ctrl_data.vcd_id = &ctrl->nc_info;

	if (!nvme_nsmgmt_cmds_supported(&ctrl_data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_MGMT_UNSUP_BY_DEV, 0,
		    "controller does not support namespace management"));
	}

	/*
	 * See discussion in nvme_ns_create_req_init_by_csi() down below for
	 * rationale around the single error here.
	 */
	if (sel != NVME_NS_ATTACH_CTRL_ATTACH &&
	    sel != NVME_NS_ATTACH_CTRL_DETACH) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_ATTACH_BAD_SEL, 0,
		    "the system (and possibly device) does not support "
		    "attaching namespaces with selector 0x%x", sel));
	}

	req = calloc(1, sizeof (nvme_ns_attach_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_attach_req_t: %s",
		    strerror(e)));
	}

	req->nar_ctrl = ctrl;
	req->nar_sel = sel;
	for (size_t i = 0; i < nvme_ns_attach_nfields; i++) {
		if (nvme_ns_attach_fields[i].nlfi_def_req) {
			req->nar_need |= 1 << i;
		}
	}
	nvme_ns_attach_req_clear_need(req, NVME_NS_ATTACH_REQ_FIELD_SEL);

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static const nvme_field_check_t nvme_ns_attach_check_nsid = {
	nvme_ns_attach_fields, NVME_NS_ATTACH_REQ_FIELD_NSID,
	NVME_ERR_NS_RANGE, 0, 0
};

bool
nvme_ns_attach_req_set_nsid(nvme_ns_attach_req_t *req, uint32_t nsid)
{
	if (!nvme_field_check_one(req->nar_ctrl, nsid, "namespace attach",
	    &nvme_ns_attach_check_nsid, 0)) {
		return (false);
	}

	req->nar_nsid = nsid;
	nvme_ns_attach_req_clear_need(req, NVME_NS_ATTACH_REQ_FIELD_NSID);
	return (nvme_ctrl_success(req->nar_ctrl));
}

/*
 * Right now we don't support setting an explicit controller list in the kernel
 * so this is a short-hand for saying just do it for my current controller
 * without requiring us to actually set anything here, we just need to clear
 * that this has been explicitly set that way the target is not implicit.
 */
bool
nvme_ns_attach_req_set_ctrlid_self(nvme_ns_attach_req_t *req)
{
	nvme_ns_attach_req_clear_need(req, NVME_NS_ATTACH_REQ_FIELD_DPTR);
	return (nvme_ctrl_success(req->nar_ctrl));
}

bool
nvme_ns_attach_req_exec(nvme_ns_attach_req_t *req)
{
	nvme_ctrl_t *ctrl = req->nar_ctrl;
	nvme_ioctl_common_t common;
	int code;

	if (req->nar_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_ns_attach_fields,
		    nvme_ns_attach_nfields,
		    NVME_ERR_NS_ATTACH_REQ_MISSING_FIELDS, "namespace attach",
		    req->nar_need));
	}

	(void) memset(&common, 0, sizeof (common));
	common.nioc_nsid = req->nar_nsid;

	code = req->nar_sel == NVME_NS_ATTACH_CTRL_ATTACH ?
	    NVME_IOC_CTRL_ATTACH : NVME_IOC_CTRL_DETACH;
	if (ioctl(ctrl->nc_fd, code, &common) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "namespace attach"));
	}

	if (common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &common, "namespace attach"));
	}

	return (nvme_ctrl_success(ctrl));
}

void
nvme_ns_delete_req_fini(nvme_ns_delete_req_t *req)
{
	free(req);
}

bool
nvme_ns_delete_req_init(nvme_ctrl_t *ctrl, nvme_ns_delete_req_t **reqp)
{
	nvme_ns_delete_req_t *req;
	nvme_valid_ctrl_data_t ctrl_data;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_delete_req_t output pointer: "
		    "%p", reqp));
	}

	ctrl_data.vcd_vers = &ctrl->nc_vers;
	ctrl_data.vcd_id = &ctrl->nc_info;

	if (!nvme_nsmgmt_cmds_supported(&ctrl_data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_MGMT_UNSUP_BY_DEV, 0,
		    "controller does not support namespace management"));
	}

	req = calloc(1, sizeof (nvme_ns_delete_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_delete_req_t: %s",
		    strerror(e)));
	}

	req->ndr_ctrl = ctrl;
	for (size_t i = 0; i < nvme_ns_delete_nfields; i++) {
		if (nvme_ns_delete_fields[i].nlfi_def_req) {
			req->ndr_need |= 1 << i;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_ns_delete_req_clear_need(nvme_ns_delete_req_t *req,
    nvme_ns_delete_req_field_t field)
{
	req->ndr_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_ns_delete_check_nsid = {
	nvme_ns_delete_fields, NVME_NS_DELETE_REQ_FIELD_NSID,
	NVME_ERR_NS_RANGE, 0, 0
};

bool
nvme_ns_delete_req_set_nsid(nvme_ns_delete_req_t *req, uint32_t nsid)
{
	if (!nvme_field_check_one(req->ndr_ctrl, nsid, "namespace delete",
	    &nvme_ns_delete_check_nsid, 0)) {
		return (false);
	}

	req->ndr_nsid = nsid;
	nvme_ns_delete_req_clear_need(req, NVME_NS_DELETE_REQ_FIELD_NSID);
	return (nvme_ctrl_success(req->ndr_ctrl));
}

bool
nvme_ns_delete_req_exec(nvme_ns_delete_req_t *req)
{
	nvme_ctrl_t *ctrl = req->ndr_ctrl;
	nvme_ioctl_common_t common;

	if (req->ndr_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_ns_delete_fields,
		    nvme_ns_delete_nfields,
		    NVME_ERR_NS_DELETE_REQ_MISSING_FIELDS, "namespace delete",
		    req->ndr_need));
	}

	(void) memset(&common, 0, sizeof (common));
	common.nioc_nsid = req->ndr_nsid;

	if (ioctl(ctrl->nc_fd, NVME_IOC_NS_DELETE, &common) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "namespace delete"));
	}

	if (common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &common, "namespace delete"));
	}

	return (nvme_ctrl_success(ctrl));
}

void
nvme_ns_create_req_fini(nvme_ns_create_req_t *req)
{
	free(req);
}

bool
nvme_ns_create_req_init_by_csi(nvme_ctrl_t *ctrl, nvme_csi_t csi,
    nvme_ns_create_req_t **reqp)
{
	nvme_ns_create_req_t *req;
	nvme_valid_ctrl_data_t ctrl_data;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_create_req_t output pointer: "
		    "%p", reqp));
	}

	ctrl_data.vcd_vers = &ctrl->nc_vers;
	ctrl_data.vcd_id = &ctrl->nc_info;

	if (!nvme_nsmgmt_cmds_supported(&ctrl_data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_MGMT_UNSUP_BY_DEV, 0,
		    "controller does not support namespace management"));
	}

	/*
	 * The CSI determines what fields are supported and required. Not all
	 * CSIs support namespace creation and in addition, we only support the
	 * NVM CSI. The notion of CSIs was added in NVMe 2.0. There are several
	 * things that could go wrong here:
	 *
	 * - We could have an NVMe controller that is pre-2.0 and therefore
	 *   anything other than the NVM CSI is invalid (it's implicit pre-2.0).
	 * - We could have a CSI that's just not defined by any version of the
	 *   spec.
	 * - We could have a CSI that's defined by a spec that's newer than the
	 *   device.
	 * - The CSI may not support namespace creation. The device may not even
	 *   support the CSI!
	 *
	 * In addition, the kernel doesn't support anything other than the NVM
	 * CSI today. Rather than break these all apart, we give a generic error
	 * message about this. We can make this higher fidelity in the future.
	 */
	if (csi != NVME_CSI_NVM) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_CREATE_BAD_CSI, 0,
		    "the system (and possibly device) does not support "
		    "creating namespaces with CSI 0x%x", csi));
	}

	req = calloc(1, sizeof (nvme_ns_create_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_create_req_t: %s",
		    strerror(e)));
	}

	for (size_t i = 0; i < nvme_ns_create_fields_nvm_nreq; i++) {
		req->ncr_need |= 1 << nvme_ns_create_fields_nvm_req[i];
	}

	for (size_t i = 0; i < nvme_ns_create_fields_nvm_nallow; i++) {
		req->ncr_allow |= 1 << nvme_ns_create_fields_nvm_allow[i];
	}

	req->ncr_ctrl = ctrl;
	req->ncr_csi = csi;

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_ns_create_req_clear_need(nvme_ns_create_req_t *req,
    nvme_ns_create_req_field_t field)
{
	req->ncr_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_ns_create_check_flbas = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_FLBAS,
	NVME_ERR_NS_CREATE_FLBAS_RANGE, 0, 0
};

bool
nvme_ns_create_req_set_flbas(nvme_ns_create_req_t *req, uint32_t flbas)
{
	if (!nvme_field_check_one(req->ncr_ctrl, flbas, "namespace create",
	    &nvme_ns_create_check_flbas, req->ncr_allow)) {
		return (false);
	}

	req->ncr_flbas = flbas;
	nvme_ns_create_req_clear_need(req, NVME_NS_CREATE_REQ_FIELD_FLBAS);
	return (nvme_ctrl_success(req->ncr_ctrl));
}

static const nvme_field_check_t nvme_ns_create_check_nsze = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_NSZE,
	NVME_ERR_NS_CREATE_NSZE_RANGE, 0, 0
};

bool
nvme_ns_create_req_set_nsze(nvme_ns_create_req_t *req, uint64_t nsze)
{
	if (!nvme_field_check_one(req->ncr_ctrl, nsze, "namespace create",
	    &nvme_ns_create_check_nsze, req->ncr_allow)) {
		return (false);
	}

	req->ncr_nsze = nsze;
	nvme_ns_create_req_clear_need(req, NVME_NS_CREATE_REQ_FIELD_NSZE);
	return (nvme_ctrl_success(req->ncr_ctrl));
}

static const nvme_field_check_t nvme_ns_create_check_ncap = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_NCAP,
	NVME_ERR_NS_CREATE_NCAP_RANGE, 0, 0
};

bool
nvme_ns_create_req_set_ncap(nvme_ns_create_req_t *req, uint64_t ncap)
{
	if (!nvme_field_check_one(req->ncr_ctrl, ncap, "namespace create",
	    &nvme_ns_create_check_ncap, req->ncr_allow)) {
		return (false);
	}

	req->ncr_ncap = ncap;
	nvme_ns_create_req_clear_need(req, NVME_NS_CREATE_REQ_FIELD_NCAP);
	return (nvme_ctrl_success(req->ncr_ctrl));
}

static const nvme_field_check_t nvme_ns_create_check_nmic = {
	nvme_ns_create_fields, NVME_NS_CREATE_REQ_FIELD_NMIC,
	NVME_ERR_NS_CREATE_NMIC_RANGE, 0, 0
};

bool
nvme_ns_create_req_set_nmic(nvme_ns_create_req_t *req, uint32_t nmic)
{
	if (!nvme_field_check_one(req->ncr_ctrl, nmic, "namespace create",
	    &nvme_ns_create_check_nmic, req->ncr_allow)) {
		return (false);
	}

	req->ncr_nmic = nmic;
	nvme_ns_create_req_clear_need(req, NVME_NS_CREATE_REQ_FIELD_NMIC);
	return (nvme_ctrl_success(req->ncr_ctrl));
}

bool
nvme_ns_create_req_get_nsid(nvme_ns_create_req_t *req, uint32_t *nsid)
{
	if (nsid == NULL) {
		return (nvme_ctrl_error(req->ncr_ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nsid output pointer: %p", nsid));
	}

	if (!req->ncr_results_valid) {
		return (nvme_ctrl_error(req->ncr_ctrl,
		    NVME_ERR_NS_CREATE_NO_RESULTS, 0, "namespace create "
		    "results are not currently valid and cannot be returned"));
	}

	*nsid = req->ncr_nsid;
	return (nvme_ctrl_success(req->ncr_ctrl));
}

bool
nvme_ns_create_req_exec(nvme_ns_create_req_t *req)
{
	nvme_ctrl_t *ctrl = req->ncr_ctrl;
	nvme_ioctl_ns_create_t create;

	/*
	 * Immediately invalidate our results if someone calls this again.
	 */
	req->ncr_results_valid = false;
	req->ncr_nsid = 0;

	if (req->ncr_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_ns_create_fields,
		    nvme_ns_create_nfields,
		    NVME_ERR_NS_CREATE_REQ_MISSING_FIELDS, "namespace create",
		    req->ncr_need));
	}

	(void) memset(&create, 0, sizeof (create));
	create.nnc_nsze = req->ncr_nsze;
	create.nnc_ncap = req->ncr_ncap;
	create.nnc_csi = req->ncr_csi;
	create.nnc_flbas = req->ncr_flbas;
	create.nnc_nmic = req->ncr_nmic;

	if (ioctl(ctrl->nc_fd, NVME_IOC_NS_CREATE, &create) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "namespace create"));
	}

	if (create.nnc_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &create.nnc_common,
		    "namespace create"));
	}

	req->ncr_results_valid = true;
	req->ncr_nsid = create.nnc_nsid;
	return (nvme_ctrl_success(ctrl));
}
