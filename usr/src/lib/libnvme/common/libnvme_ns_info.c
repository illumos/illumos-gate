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
 * Namespace information.
 */

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "libnvme_impl.h"

bool
nvme_ns_info_error(nvme_ns_info_t *info, nvme_info_err_t err, int32_t sys,
    const char *fmt, ...)
{
	int ret;
	va_list ap;

	info->nni_err = err;
	info->nni_syserr = sys;
	va_start(ap, fmt);
	ret = vsnprintf(info->nni_errmsg, sizeof (info->nni_errmsg), fmt, ap);
	va_end(ap);
	if (ret >= sizeof (info->nni_errmsg)) {
		info->nni_errlen = sizeof (info->nni_errmsg) - 1;
	} else if (ret <= 0) {
		info->nni_errlen = 0;
		info->nni_errmsg[0] = '\0';
	} else {
		info->nni_errlen = (size_t)ret;
	}

	return (false);
}

bool
nvme_ns_info_success(nvme_ns_info_t *info)
{
	info->nni_err = NVME_INFO_ERR_OK;
	info->nni_syserr = 0;
	info->nni_errmsg[0] = '\0';
	info->nni_errlen = 0;

	return (true);
}

nvme_info_err_t
nvme_ns_info_err(nvme_ns_info_t *info)
{
	return (info->nni_err);
}

int32_t
nvme_ns_info_syserr(nvme_ns_info_t *info)
{
	return (info->nni_syserr);
}

const char *
nvme_ns_info_errmsg(nvme_ns_info_t *info)
{
	return (info->nni_errmsg);
}

size_t
nvme_ns_info_errlen(nvme_ns_info_t *info)
{
	return (info->nni_errlen);
}

const char *
nvme_ns_info_errtostr(nvme_ns_info_t *info, nvme_info_err_t err)
{
	return (nvme_ctrl_info_errtostr(NULL, err));
}

void
nvme_ns_info_free(nvme_ns_info_t *info)
{
	free(info);
}

bool
nvme_ns_info_snap(nvme_ns_t *ns, nvme_ns_info_t **infop)
{
	nvme_ctrl_t *ctrl = ns->nn_ctrl;
	nvme_ns_info_t *info;

	if (infop == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_info_t output pointer: %p",
		    infop));
	}

	info = calloc(1, sizeof (nvme_ns_info_t));
	if (info == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_info_t: %s",
		    strerror(e)));
	}

	info->nni_nsid = ns->nn_nsid;
	if (!nvme_ioc_ns_info(ns->nn_ctrl, ns->nn_nsid, &info->nni_info)) {
		nvme_ns_info_free(info);
		return (false);
	}
	info->nni_vers = ns->nn_ctrl->nc_vers;
	info->nni_level = nvme_ns_state_to_disc_level(info->nni_info.nni_state);

	*infop = info;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_ctrl_ns_info_snap(nvme_ctrl_t *ctrl, uint32_t nsid, nvme_ns_info_t **infop)
{
	nvme_ns_info_t *info;

	if (infop == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_ns_info_t output pointer: %p",
		    infop));
	}

	if (nsid < NVME_NSID_MIN || nsid > ctrl->nc_info.id_nn) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0, "requested "
		    "namespace %u is invalid, valid namespaces are [0x%x, "
		    "0x%x]", nsid, NVME_NSID_MIN, ctrl->nc_info.id_nn));
	}

	info = calloc(1, sizeof (nvme_ns_info_t));
	if (info == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_ns_info_t: %s",
		    strerror(e)));
	}

	info->nni_nsid = nsid;
	if (!nvme_ioc_ns_info(ctrl, nsid, &info->nni_info)) {
		nvme_ns_info_free(info);
		return (false);
	}
	info->nni_vers = ctrl->nc_vers;
	info->nni_level = nvme_ns_state_to_disc_level(info->nni_info.nni_state);

	*infop = info;
	return (nvme_ctrl_success(ctrl));
}

uint32_t
nvme_ns_info_nsid(nvme_ns_info_t *info)
{
	return (info->nni_nsid);
}

const nvme_identify_nsid_t *
nvme_ns_info_identify(nvme_ns_info_t *info)
{
	return (&info->nni_info.nni_id);
}

nvme_ns_disc_level_t
nvme_ns_info_level(nvme_ns_info_t *info)
{
	return (info->nni_level);
}

static bool
nvme_ns_info_req_active(nvme_ns_info_t *info, const nvme_version_t *vers)
{
	if (info->nni_level < NVME_NS_DISC_F_ACTIVE) {
		return (nvme_ns_info_error(info, NVME_INFO_ERR_NS_INACTIVE, 0,
		    "information cannot be provided for inactive namespaces: "
		    "namespace is %s (0x%x)",
		    nvme_nsleveltostr(info->nni_level), info->nni_level));
	}

	if (!nvme_vers_ns_info_atleast(info, vers)) {
		return (nvme_ns_info_error(info, NVME_INFO_ERR_VERSION, 0,
		    "cannot provide information, device must be at least "
		    "version %u.%u, but is %u.%u", vers->v_major, vers->v_minor,
		    info->nni_vers.v_major, info->nni_vers.v_minor));
	}

	return (true);
}

bool
nvme_ns_info_nguid(nvme_ns_info_t *info, uint8_t nguid[16])
{
	const uint8_t zero_guid[16] = { 0 };

	if (!nvme_ns_info_req_active(info, &nvme_vers_1v2)) {
		return (false);
	}

	if (memcmp(zero_guid, info->nni_info.nni_id.id_nguid,
	    sizeof (zero_guid)) == 0) {
		return (nvme_ns_info_error(info, NVME_INFO_ERR_MISSING_CAP, 0,
		    "Namespace GUID invalid: found all 0s"));
	}

	(void) memcpy(nguid, info->nni_info.nni_id.id_nguid,
	    sizeof (info->nni_info.nni_id.id_nguid));

	return (nvme_ns_info_success(info));
}

bool
nvme_ns_info_eui64(nvme_ns_info_t *info, uint8_t eui64[8])
{
	const uint8_t zero_eui64[8] = { 0 };

	if (!nvme_ns_info_req_active(info, &nvme_vers_1v1)) {
		return (false);
	}

	if (memcmp(zero_eui64, info->nni_info.nni_id.id_eui64,
	    sizeof (zero_eui64)) == 0) {
		return (nvme_ns_info_error(info, NVME_INFO_ERR_MISSING_CAP, 0,
		    "Namespace EUI64 invalid: found all 0s"));
	}

	(void) memcpy(eui64, info->nni_info.nni_id.id_eui64,
	    sizeof (info->nni_info.nni_id.id_eui64));

	return (nvme_ns_info_success(info));
}

bool
nvme_ns_info_size(nvme_ns_info_t *info, uint64_t *sizep)
{
	if (!nvme_ns_info_req_active(info, &nvme_vers_1v0)) {
		return (false);
	}

	*sizep = info->nni_info.nni_id.id_nsize;
	return (nvme_ns_info_success(info));
}

bool
nvme_ns_info_cap(nvme_ns_info_t *info, uint64_t *capp)
{
	if (!nvme_ns_info_req_active(info, &nvme_vers_1v0)) {
		return (false);
	}

	*capp = info->nni_info.nni_id.id_ncap;
	return (nvme_ns_info_success(info));
}

bool
nvme_ns_info_use(nvme_ns_info_t *info, uint64_t *usep)
{
	if (!nvme_ns_info_req_active(info, &nvme_vers_1v0)) {
		return (false);
	}

	*usep = info->nni_info.nni_id.id_nuse;
	return (nvme_ns_info_success(info));
}

bool
nvme_ns_info_nformats(nvme_ns_info_t *info, uint32_t *nfmtp)
{
	if (!nvme_ns_info_req_active(info, &nvme_vers_1v0)) {
		return (false);
	}

	*nfmtp = info->nni_info.nni_id.id_nlbaf + 1;
	return (nvme_ns_info_success(info));
}

bool
nvme_ns_info_format(nvme_ns_info_t *info, uint32_t idx,
    const nvme_nvm_lba_fmt_t **fmtp)
{
	uint32_t max;
	const nvme_identify_nsid_t *nsid = &info->nni_info.nni_id;

	if (!nvme_ns_info_nformats(info, &max)) {
		return (false);
	}

	if (idx >= max) {
		return (nvme_ns_info_error(info, NVME_INFO_ERR_BAD_FMT, 0,
		    "requested index %u is invalid: valid range is [0, %u]",
		    idx, max - 1));
	}

	if (!info->nni_lbaf_valid[idx]) {
		uint8_t lbads = nsid->id_lbaf[idx].lbaf_lbads;

		if (lbads == 0) {
			return (nvme_ns_info_error(info, NVME_INFO_ERR_BAD_FMT,
			    0, "format %u is not actually valid due to 0 LBA "
			    "data size even though it is considered a valid "
			    "LBA format by NLBAF", lbads));
		}

		if (lbads < 9) {
			return (nvme_ns_info_error(info,
			    NVME_INFO_ERR_BAD_FMT_DATA, 0, "NVMe devices are "
			    "not allowed to have a LBA data size of less than "
			    "512 bytes, found raw shift value of %u for "
			    "format %u", lbads, idx));
		}

		if (lbads >= 64) {
			return (nvme_ns_info_error(info,
			    NVME_INFO_ERR_BAD_FMT_DATA, 0, "LBA format %u has "
			    "LBA data size greater " "than 64 (%u), cannot be "
			    "represented as a byte size", idx, lbads));
		}

		info->nni_lbaf[idx].nnlf_id = idx;
		info->nni_lbaf[idx].nnlf_ms = nsid->id_lbaf[idx].lbaf_ms;
		info->nni_lbaf[idx].nnlf_lbasz = 1ULL << lbads;
		info->nni_lbaf[idx].nnlf_rel = nsid->id_lbaf[idx].lbaf_rp;
		info->nni_lbaf_valid[idx] = true;
	}

	*fmtp = &info->nni_lbaf[idx];
	return (nvme_ns_info_success(info));
}


bool
nvme_ns_info_curformat(nvme_ns_info_t *info, const nvme_nvm_lba_fmt_t **fmtp)
{
	uint32_t idx;

	if (!nvme_ns_info_req_active(info, &nvme_vers_1v0)) {
		return (false);
	}

	idx = info->nni_info.nni_id.id_flbas.lba_format;
	return (nvme_ns_info_format(info, idx, fmtp));
}

bool
nvme_ns_info_bd_addr(nvme_ns_info_t *info, const char **addrp)
{
	if (info->nni_level < NVME_NS_DISC_F_BLKDEV) {
		return (nvme_ns_info_error(info, NVME_INFO_ERR_NS_NO_BLKDEV, 0,
		    "the blkdev address cannot be provided for namespaces "
		    "without blkdev attached: namespace is %s (0x%x)",
		    nvme_nsleveltostr(info->nni_level), info->nni_level));
	}

	*addrp = info->nni_info.nni_addr;
	return (nvme_ns_info_success(info));
}
