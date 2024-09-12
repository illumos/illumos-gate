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
 * This implements iterators for the various NVMe identify related features that
 * return lists of information (rather than the basic data structures). These
 * are all phrased as iterators to the user so that way we can abstract around
 * the fact that there may be additional commands required to make this happen
 * or eventually a number of namespaces that exceeds the basic amount supported
 * here.
 */

#include <string.h>
#include <unistd.h>

#include "libnvme_impl.h"

void
nvme_id_req_fini(nvme_id_req_t *idreq)
{
	free(idreq);
}

bool
nvme_id_req_init_by_cns(nvme_ctrl_t *ctrl, nvme_csi_t csi, uint32_t cns,
    nvme_id_req_t **idreqp)
{
	const nvme_identify_info_t *info = NULL;
	nvme_id_req_t *req;
	nvme_valid_ctrl_data_t ctrl_data;

	if (idreqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_id_req_t output pointer: %p",
		    idreqp));
	}

	for (size_t i = 0; i < nvme_identify_ncmds; i++) {
		if (nvme_identify_cmds[i].nii_csi == csi &&
		    nvme_identify_cmds[i].nii_cns == cns) {
			info = &nvme_identify_cmds[i];
			break;
		}
	}

	if (info == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_IDENTIFY_UNKNOWN, 0,
		    "unknown identify command CSI/CNS 0x%x/0x%x", csi, cns));
	}

	ctrl_data.vcd_vers = &ctrl->nc_vers;
	ctrl_data.vcd_id = &ctrl->nc_info;

	if (!nvme_identify_info_supported(info, &ctrl_data)) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_IDENTIFY_UNSUP_BY_DEV, 0,
		    "device does not support identify command %s (CSI/CNS "
		    "0x%x/0x%x)", info->nii_name, info->nii_csi,
		    info->nii_cns));
	}

	req = calloc(1, sizeof (nvme_id_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e,
		    "failed to allocate memory for a new nvme_id_req_t: %s",
		    strerror(e)));
	}

	req->nir_ctrl = ctrl;
	req->nir_info = info;

	/*
	 * The identify command always wants to write a 4 KiB buffer
	 * (NVME_IDENTIFY_BUFSIZE) out and therefore we manually tack this onto
	 * to the need and allow list.
	 */
	req->nir_need = info->nii_fields | (1 << NVME_ID_REQ_F_BUF);
	req->nir_allow = info->nii_fields | (1 << NVME_ID_REQ_F_BUF);

	*idreqp = req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_id_req_set_need(nvme_id_req_t *req, nvme_identify_req_field_t field)
{
	req->nir_need |= 1 << field;
}

static void
nvme_id_req_clear_need(nvme_id_req_t *req, nvme_identify_req_field_t field)
{
	req->nir_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_identify_check_nsid = {
	nvme_identify_fields, NVME_ID_REQ_F_NSID,
	NVME_ERR_NS_RANGE, 0, NVME_ERR_NS_UNUSE
};

bool
nvme_id_req_set_nsid(nvme_id_req_t *req, uint32_t nsid)
{
	nvme_ctrl_t *ctrl = req->nir_ctrl;
	nvme_identify_info_flags_t flags = req->nir_info->nii_flags;

	/*
	 * In some contexts the NSID here must refer to an actual valid
	 * namespace. In other cases it's referring to a search index and
	 * therefore all we care about is the value. Finally, sometimes the
	 * broadcast address is used to access things that are common across all
	 * namespaces. If we have a list operation, we just pass this through to
	 * the kernel. This unfortunately requires a bit more manual checking.
	 */
	if ((flags & NVME_IDENTIFY_INFO_F_NSID_LIST) == 0 &&
	    !nvme_field_check_one(req->nir_ctrl, nsid, "identify",
	    &nvme_identify_check_nsid, req->nir_allow)) {
		return (false);
	}

	if ((flags & NVME_IDENTIFY_INFO_F_NSID_LIST) == 0 &&
	    (req->nir_allow & (1 << NVME_ID_REQ_F_NSID)) != 0) {
		if (nsid == 0) {
			return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0,
			    "namespaces id 0x%x is invalid, valid namespaces "
			    "are [0x%x, 0x%x]", nsid, NVME_NSID_MIN,
			    req->nir_ctrl->nc_info.id_nn));
		}

		if (nsid == NVME_NSID_BCAST &&
		    (flags & NVME_IDENTIFY_INFO_F_BCAST) == 0) {
			return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0,
			    "the all namespaces/controller nsid (0x%x) is not "
			    "allowed for this identify command, valid "
			    "namespaces are [0x%x, 0x%x]", nsid,
			    NVME_NSID_MIN, req->nir_ctrl->nc_info.id_nn));

		}
	}

	req->nir_nsid = nsid;
	nvme_id_req_clear_need(req, NVME_ID_REQ_F_NSID);
	return (nvme_ctrl_success(req->nir_ctrl));
}

static const nvme_field_check_t nvme_identify_check_ctrlid = {
	nvme_identify_fields, NVME_ID_REQ_F_CTRLID,
	NVME_ERR_IDENTIFY_CTRLID_RANGE, NVME_ERR_IDENTIFY_CTRLID_UNSUP,
	NVME_ERR_IDENTIFY_CTRLID_UNUSE
};

bool
nvme_id_req_set_ctrlid(nvme_id_req_t *req, uint32_t ctrlid)
{
	if (!nvme_field_check_one(req->nir_ctrl, ctrlid, "identify",
	    &nvme_identify_check_ctrlid, req->nir_allow)) {
		return (false);
	}

	req->nir_ctrlid = ctrlid;
	nvme_id_req_clear_need(req, NVME_ID_REQ_F_CTRLID);
	return (nvme_ctrl_success(req->nir_ctrl));
}

bool
nvme_id_req_set_output(nvme_id_req_t *req, void *buf, size_t len)
{
	nvme_ctrl_t *ctrl = req->nir_ctrl;

	if (buf == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "identify output buffer cannot be NULL"));
	}

	if (len < NVME_IDENTIFY_BUFSIZE) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_IDENTIFY_OUTPUT_RANGE, 0,
		    "identify buffer size must be at least %u bytes large",
		    NVME_IDENTIFY_BUFSIZE));
	}

	req->nir_buf = buf;
	nvme_id_req_clear_need(req, NVME_ID_REQ_F_BUF);
	return (nvme_ctrl_success(req->nir_ctrl));
}

bool
nvme_id_req_clear_output(nvme_id_req_t *req)
{
	req->nir_buf = NULL;

	/*
	 * This field is always required so we can just toss a blanket set need
	 * on here.
	 */
	nvme_id_req_set_need(req, NVME_ID_REQ_F_BUF);
	return (nvme_ctrl_success(req->nir_ctrl));
}

bool
nvme_id_req_exec(nvme_id_req_t *req)
{
	nvme_ctrl_t *ctrl = req->nir_ctrl;
	nvme_ioctl_identify_t id;

	if (req->nir_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_identify_fields,
		    nvme_identify_nfields, NVME_ERR_IDENTIFY_REQ_MISSING_FIELDS,
		    "identify", req->nir_need));
	}

	(void) memset(&id, 0, sizeof (nvme_ioctl_identify_t));
	id.nid_common.nioc_nsid = req->nir_nsid;
	id.nid_cns = req->nir_info->nii_cns;
	id.nid_ctrlid = req->nir_ctrlid;
	id.nid_data = (uintptr_t)req->nir_buf;

	if (ioctl(req->nir_ctrl->nc_fd, NVME_IOC_IDENTIFY, &id) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "identify"));
	}

	if (id.nid_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &id.nid_common, "identify"));
	}

	return (nvme_ctrl_success(ctrl));
}
