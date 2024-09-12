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
 * Manage NVMe feature detection and feature queries.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnvme_impl.h"

const char *
nvme_feat_disc_short(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_short);
}

const char *
nvme_feat_disc_spec(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_spec);
}

uint32_t
nvme_feat_disc_fid(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_fid);
}

nvme_feat_scope_t
nvme_feat_disc_scope(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_scope);
}

nvme_feat_kind_t
nvme_feat_disc_kind(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_kind);
}

nvme_feat_csi_t
nvme_feat_disc_csi(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_csi);
}

nvme_feat_flags_t
nvme_feat_disc_flags(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_flags);
}

nvme_get_feat_fields_t
nvme_feat_disc_fields_get(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_in_get);
}

nvme_set_feat_fields_t
nvme_feat_disc_fields_set(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_in_set);
}

nvme_feat_output_t
nvme_feat_disc_output_get(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_out_get);
}

nvme_feat_output_t
nvme_feat_disc_output_set(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_out_set);
}

uint64_t
nvme_feat_disc_data_size(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_len);
}

static bool
nvme_feat_discover_validate(nvme_ctrl_t *ctrl, nvme_feat_scope_t scopes,
    uint32_t flags)
{
	const nvme_feat_scope_t valid_scopes = NVME_FEAT_SCOPE_CTRL |
	    NVME_FEAT_SCOPE_NS;

	/*
	 * See the note in nvme_log_discover_validate() on why we don't support
	 * a zeroed scope.
	 */
	if (scopes == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0,  "no "
		    "feature scope specified (given 0), a scope must be "
		    "requested"));
	}

	if ((scopes & ~valid_scopes) != 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0,
		    "encountered invalid scope for the nvme_feat_disc_scope_t: "
		    "0x%x", scopes & ~valid_scopes));
	}

	/*
	 * The flags are meant for future expansion here, hence the all zero
	 * requirement.
	 */
	if (flags != 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0,
		    "encountered invalid feature discovery flags: 0x%x",
		    flags));
	}

	return (true);
}

nvme_feat_impl_t
nvme_feat_disc_impl(const nvme_feat_disc_t *disc)
{
	return (disc->nfd_impl);
}

void
nvme_feat_disc_free(nvme_feat_disc_t *disc)
{
	free(disc);
}

bool
nvme_feat_disc_dup(nvme_ctrl_t *ctrl, const nvme_feat_disc_t *src,
    nvme_feat_disc_t **discp)
{
	nvme_feat_disc_t *disc;

	if (src == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_feat_disc_t pointer to "
		    "duplicate: %p", src));
	}

	if (discp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_feat_disc_t output pointer: %p",
		    discp));
	}

	disc = calloc(1, sizeof (nvme_feat_disc_t));
	if (disc == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_feat_disc_t: %s",
		    strerror(e)));
	}

	(void) memcpy(disc, src, sizeof (nvme_feat_disc_t));
	*discp = disc;
	return (nvme_ctrl_success(ctrl));
}

void
nvme_feat_discover_fini(nvme_feat_iter_t *iter)
{
	free(iter);
}

static bool
nvme_feat_discover_one(nvme_feat_iter_t *iter, const nvme_feat_info_t *info)
{
	nvme_feat_disc_t *disc = &iter->nfi_disc;
	nvme_valid_ctrl_data_t data;

	data.vcd_vers = &iter->nfi_ctrl->nc_vers;
	data.vcd_id = &iter->nfi_ctrl->nc_info;

	/*
	 * The user is not interested in this feature. Do not include it.
	 */
	if ((iter->nfi_scope & info->nfeat_scope) == 0) {
		return (false);
	}

	(void) memset(disc, 0, sizeof (nvme_feat_disc_t));

	disc->nfd_short = info->nfeat_short;
	disc->nfd_spec = info->nfeat_spec;
	disc->nfd_fid = info->nfeat_fid;
	disc->nfd_kind = info->nfeat_kind;
	disc->nfd_scope = info->nfeat_scope;
	disc->nfd_flags = info->nfeat_flags;
	disc->nfd_csi = info->nfeat_csi;
	disc->nfd_in_get = info->nfeat_in_get;
	disc->nfd_in_set = info->nfeat_in_set;
	disc->nfd_out_get = info->nfeat_out_get;
	disc->nfd_out_set = info->nfeat_out_set;
	disc->nfd_len = info->nfeat_len;
	disc->nfd_impl = nvme_feat_supported(info, &data);

	return (true);
}

nvme_iter_t
nvme_feat_discover_step(nvme_feat_iter_t *iter, const nvme_feat_disc_t **outp)
{
	*outp = NULL;

	if (iter->nfi_cur_idx == nvme_std_nfeats) {
		return (NVME_ITER_DONE);
	}

	while (iter->nfi_cur_idx < nvme_std_nfeats) {
		const nvme_feat_info_t *feat =
		    &nvme_std_feats[iter->nfi_cur_idx];
		iter->nfi_cur_idx++;

		if (nvme_feat_discover_one(iter, feat)) {
			*outp = &iter->nfi_disc;
			return (NVME_ITER_VALID);
		}
	}

	/*
	 * When we add support for vendor-specific features, then we will want
	 * to check NVME_LOG_DISC_F_NO_DB here and if it is not set, proceed to
	 * move past the standard features onto the vendor-specific features
	 * like we do in the log page work right now.
	 */
	ASSERT3U(iter->nfi_cur_idx, ==, nvme_std_nfeats);
	return (NVME_ITER_DONE);
}

bool
nvme_feat_discover_init(nvme_ctrl_t *ctrl, nvme_feat_scope_t scope,
    uint32_t flags, nvme_feat_iter_t **iterp)
{
	nvme_feat_iter_t *iter;

	if (!nvme_feat_discover_validate(ctrl, scope, flags)) {
		return (false);
	}

	if (iterp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_feat_iter_t output pointer: %p",
		    iterp));
	}

	iter = calloc(1, sizeof (nvme_feat_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_feat_iter_t: %s",
		    strerror(e)));
	}

	iter->nfi_ctrl = ctrl;
	iter->nfi_scope = scope;

	*iterp = iter;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_feat_discover(nvme_ctrl_t *ctrl, nvme_feat_scope_t scope, uint32_t flags,
    nvme_feat_disc_f func, void *arg)
{
	nvme_feat_iter_t *iter;
	nvme_iter_t ret;
	const nvme_feat_disc_t *disc;


	if (func == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_feat_disc_f function pointer: %p",
		    func));
	}

	if (!nvme_feat_discover_init(ctrl, scope, flags, &iter)) {
		return (false);
	}

	while ((ret = nvme_feat_discover_step(iter, &disc)) ==
	    NVME_ITER_VALID) {
		if (!func(ctrl, disc, arg))
			break;
	}

	nvme_feat_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}

void
nvme_get_feat_req_fini(nvme_get_feat_req_t *req)
{
	free(req);
}

/*
 * This instantiates a simple get features request that allows most fields to be
 * specified.
 */
bool
nvme_get_feat_req_init(nvme_ctrl_t *ctrl, nvme_get_feat_req_t **reqp)
{
	nvme_get_feat_req_t *req;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_get_feat_req_t output pointer: "
		    "%p", reqp));
	}

	req = calloc(1, sizeof (nvme_get_feat_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_get_feat_req_t: %s",
		    strerror(e)));
	}

	req->gfr_ctrl = ctrl;
	for (size_t i = 0; i < nvme_get_feat_nfields; i++) {
		if (nvme_get_feat_fields[i].nlfi_def_req) {
			req->gfr_need |= 1 << i;
		}

		if (nvme_get_feat_fields[i].nlfi_def_allow) {
			req->gfr_allow |= 1 << i;
		}
	}

	/*
	 * For a generic get feature request, we don't know if this is true or
	 * not. Even though none of the features the kernel supports at this
	 * moment support this, we still want to enable this for the future for
	 * when they do. The kernel will enforce this.
	 */
	req->gfr_flags = NVME_FEAT_F_GET_BCAST_NSID;

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_get_feat_req_init_by_disc(nvme_ctrl_t *ctrl, const nvme_feat_disc_t *disc,
    nvme_get_feat_req_t **reqp)
{
	nvme_get_feat_req_t *req;

	if (disc == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_feat_disc_t pointer: %p", disc));
	}

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_get_feat_req_t output pointer: "
		    "%p", reqp));
	}

	if (disc->nfd_impl == NVME_FEAT_IMPL_UNSUPPORTED) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_FEAT_UNSUP_BY_DEV, 0,
		    "cannot create get feature request for feature %s "
		    "(FID 0x%x) because it is not supported by the device",
		    disc->nfd_short, disc->nfd_fid));

	}

	req = calloc(1, sizeof (nvme_get_feat_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_get_feat_req_t: %s",
		    strerror(e)));
	}

	req->gfr_ctrl = ctrl;

	/*
	 * Unlike the more generic get feature initialization, we only allow
	 * items to be set if they're actually required. We do not require a
	 * selector to be set and will default to just getting the current
	 * value. Otherwise every other field that is settable is required. We
	 * don't let someone change the fid on us, because that would be quite
	 * confusing.
	 */
	req->gfr_fid = disc->nfd_fid;
	req->gfr_flags = disc->nfd_flags;
	req->gfr_targ_len = disc->nfd_len;
	req->gfr_allow |= 1 << NVME_GET_FEAT_REQ_FIELD_SEL;

	if ((disc->nfd_in_get & NVME_GET_FEAT_F_CDW11) != 0) {
		req->gfr_need |= 1 << NVME_GET_FEAT_REQ_FIELD_CDW11;
		req->gfr_allow |= 1 << NVME_GET_FEAT_REQ_FIELD_CDW11;
	}

	if ((disc->nfd_in_get & NVME_GET_FEAT_F_DATA) != 0) {
		req->gfr_need |= 1 << NVME_GET_FEAT_REQ_FIELD_DPTR;
		req->gfr_allow |= 1 << NVME_GET_FEAT_REQ_FIELD_DPTR;
	}

	if ((disc->nfd_in_get & NVME_GET_FEAT_F_NSID) != 0) {
		req->gfr_need |= 1 << NVME_GET_FEAT_REQ_FIELD_NSID;
		req->gfr_allow |= 1 << NVME_GET_FEAT_REQ_FIELD_NSID;
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

typedef struct {
	bool ngfi_found;
	const char *ngfi_name;
	nvme_get_feat_req_t *ngfi_req;
	nvme_feat_disc_t **ngfi_discp;
	nvme_err_data_t ngfi_err;
} nvme_get_feat_init_arg_t;

static bool
nvme_get_feat_req_init_by_name_cb(nvme_ctrl_t *ctrl,
    const nvme_feat_disc_t *disc, void *arg)
{
	nvme_get_feat_init_arg_t *init = arg;

	if (strcmp(init->ngfi_name, disc->nfd_short) != 0 &&
	    strcmp(init->ngfi_name, disc->nfd_spec) != 0) {
		return (true);
	}

	init->ngfi_found = true;
	if (!nvme_get_feat_req_init_by_disc(ctrl, disc, &init->ngfi_req)) {
		nvme_ctrl_err_save(ctrl, &init->ngfi_err);
		init->ngfi_req = NULL;
	} else if (init->ngfi_discp != NULL) {
		if (!nvme_feat_disc_dup(ctrl, disc, init->ngfi_discp)) {
			nvme_ctrl_err_save(ctrl, &init->ngfi_err);
			nvme_get_feat_req_fini(init->ngfi_req);
			init->ngfi_req = NULL;
		}
	}

	return (false);
}

bool
nvme_get_feat_req_init_by_name(nvme_ctrl_t *ctrl, const char *name,
    uint32_t df, nvme_feat_disc_t **discp, nvme_get_feat_req_t **reqp)
{
	nvme_get_feat_init_arg_t init;

	/*
	 * Note, we consider discp optional unlikely the name and reqp. The
	 * discover flags, df, will be validated by the discover functions we
	 * call.
	 */
	if (name == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid pointer for log page name: %p", name));
	}

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_get_feat_req_t output pointer: "
		    "%p", reqp));
	}

	(void) memset(&init, 0, sizeof (init));
	init.ngfi_name = name;
	init.ngfi_discp = discp;

	if (!nvme_feat_discover(ctrl, NVME_FEAT_SCOPE_CTRL | NVME_FEAT_SCOPE_NS,
	    df, nvme_get_feat_req_init_by_name_cb, &init)) {
		return (false);
	}

	if (!init.ngfi_found) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_FEAT_NAME_UNKNOWN, 0,
		    "failed to find feature with name %s", name));
	}

	if (init.ngfi_req == NULL) {
		nvme_ctrl_err_set(ctrl, &init.ngfi_err);
		return (false);
	}

	*reqp = init.ngfi_req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_get_feat_req_set_need(nvme_get_feat_req_t *req,
    nvme_get_feat_req_field_t field)
{
	req->gfr_need |= 1 << field;
}

static void
nvme_get_feat_req_clear_need(nvme_get_feat_req_t *req,
    nvme_get_feat_req_field_t field)
{
	req->gfr_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_get_feat_check_fid = {
	nvme_get_feat_fields, NVME_GET_FEAT_REQ_FIELD_FID,
	NVME_ERR_FEAT_FID_RANGE, 0, 0
};

bool
nvme_get_feat_req_set_fid(nvme_get_feat_req_t *req, uint32_t fid)
{
	if (!nvme_field_check_one(req->gfr_ctrl, fid, "get feature",
	    &nvme_get_feat_check_fid, req->gfr_allow)) {
		return (false);
	}

	req->gfr_fid = fid;
	nvme_get_feat_req_clear_need(req, NVME_GET_FEAT_REQ_FIELD_FID);
	return (nvme_ctrl_success(req->gfr_ctrl));
}

static const nvme_field_check_t nvme_get_feat_check_sel = {
	nvme_get_feat_fields, NVME_GET_FEAT_REQ_FIELD_SEL,
	NVME_ERR_FEAT_SEL_RANGE, NVME_ERR_FEAT_SEL_UNSUP, 0
};

bool
nvme_get_feat_req_set_sel(nvme_get_feat_req_t *req, uint32_t sel)
{
	if (!nvme_field_check_one(req->gfr_ctrl, sel, "get feature",
	    &nvme_get_feat_check_sel, req->gfr_allow)) {
		return (false);
	}

	if (sel == NVME_FEATURE_SEL_SUPPORTED) {
		return (nvme_ctrl_error(req->gfr_ctrl,
		    NVME_ERR_FEAT_SEL_RANGE, 0, "the get feature APIs do "
		    "not support supported capabilities selector"));
	}

	req->gfr_sel = sel;
	nvme_get_feat_req_clear_need(req, NVME_GET_FEAT_REQ_FIELD_SEL);
	return (nvme_ctrl_success(req->gfr_ctrl));
}

static const nvme_field_check_t nvme_get_feat_check_cdw11 = {
	nvme_get_feat_fields, NVME_GET_FEAT_REQ_FIELD_CDW11,
	NVME_ERR_FEAT_CDW11_RANGE, 0, NVME_ERR_FEAT_CDW11_UNUSE
};

bool
nvme_get_feat_req_set_cdw11(nvme_get_feat_req_t *req, uint32_t cdw11)
{
	if (!nvme_field_check_one(req->gfr_ctrl, cdw11, "get feature",
	    &nvme_get_feat_check_cdw11, req->gfr_allow)) {
		return (false);
	}

	req->gfr_cdw11 = cdw11;
	nvme_get_feat_req_clear_need(req, NVME_GET_FEAT_REQ_FIELD_CDW11);
	return (nvme_ctrl_success(req->gfr_ctrl));
}

static const nvme_field_check_t nvme_get_feat_check_nsid = {
	nvme_get_feat_fields, NVME_GET_FEAT_REQ_FIELD_NSID,
	NVME_ERR_NS_RANGE, 0, NVME_ERR_NS_UNUSE
};

bool
nvme_get_feat_req_set_nsid(nvme_get_feat_req_t *req, uint32_t nsid)
{
	nvme_ctrl_t *ctrl = req->gfr_ctrl;

	/*
	 * Check the NSID first before we go into the generic validation code so
	 * we can get a better error message.
	 */
	if (nsid == NVME_NSID_BCAST &&
	    (req->gfr_flags & NVME_FEAT_F_GET_BCAST_NSID) == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0, "the all "
		    "namespaces/controller nsid (0x%x) is not allowed for this "
		    "feature, valid namespaces are [0x%x, 0x%x]", nsid,
		    NVME_NSID_MIN, req->gfr_ctrl->nc_info.id_nn));
	}

	if (!nvme_field_check_one(req->gfr_ctrl, nsid, "get feature",
	    &nvme_get_feat_check_nsid, req->gfr_allow)) {
		return (false);
	}

	req->gfr_nsid = nsid;
	nvme_get_feat_req_clear_need(req, NVME_GET_FEAT_REQ_FIELD_NSID);
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_get_feat_req_set_output(nvme_get_feat_req_t *req, void *buf, size_t len)
{
	if (buf == NULL) {
		return (nvme_ctrl_error(req->gfr_ctrl, NVME_ERR_BAD_PTR, 0,
		    "get feature output buffer cannot be NULL"));
	}

	if (len == 0) {
		return (nvme_ctrl_error(req->gfr_ctrl,
		    NVME_ERR_FEAT_DATA_RANGE, 0, "get feature output length "
		    "cannot be zero"));
	}

	/*
	 * Something to consider for the future here is that we know the fixed
	 * size data that we're expecting for the feature. It would be nice if
	 * we validated that we have that size now versus later. Related,
	 * because there is no field check logic for this, we must manually
	 * check that it is allowed and cannot use nvme_field_check_one().
	 */
	if ((req->gfr_allow & (1 << NVME_GET_FEAT_REQ_FIELD_DPTR)) == 0) {
		return (nvme_ctrl_error(req->gfr_ctrl, NVME_ERR_FEAT_DATA_UNUSE,
		    0, "field output (dptr) cannot be set in this get feature "
		    "request"));
	}

	req->gfr_buf = buf;
	req->gfr_len = len;
	nvme_get_feat_req_clear_need(req, NVME_GET_FEAT_REQ_FIELD_DPTR);
	return (nvme_ctrl_success(req->gfr_ctrl));
}

bool
nvme_get_feat_req_clear_output(nvme_get_feat_req_t *req)
{
	if ((req->gfr_allow & (1 << NVME_GET_FEAT_REQ_FIELD_DPTR)) == 0) {
		return (nvme_ctrl_error(req->gfr_ctrl, NVME_ERR_FEAT_DATA_UNUSE,
		    0, "field output (dptr) cannot be cleared in this get "
		    "feature request"));
	}

	req->gfr_buf = NULL;
	req->gfr_len = 0;
	nvme_get_feat_req_set_need(req, NVME_GET_FEAT_REQ_FIELD_DPTR);
	return (nvme_ctrl_success(req->gfr_ctrl));
}

bool
nvme_get_feat_req_get_cdw0(nvme_get_feat_req_t *req, uint32_t *cdw0)
{
	if (cdw0 == NULL) {
		return (nvme_ctrl_error(req->gfr_ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid cdw0 output pointer: %p", cdw0));
	}

	if (!req->gfr_results_valid) {
		return (nvme_ctrl_error(req->gfr_ctrl,
		    NVME_ERR_FEAT_NO_RESULTS, 0, "get feature results are not "
		    "currently valid and cannot be returned"));
	}

	*cdw0 = req->gfr_cdw0;
	return (nvme_ctrl_success(req->gfr_ctrl));
}

bool
nvme_get_feat_req_exec(nvme_get_feat_req_t *req)
{
	nvme_ctrl_t *ctrl = req->gfr_ctrl;
	nvme_ioctl_get_feature_t feat;

	/*
	 * Because this has been called, we need to immediately invalidate our
	 * stored cdw0 results. We do this as a precaution regardless of whether
	 * or not it is valid.
	 */
	req->gfr_results_valid = false;
	req->gfr_cdw0 = 0;

	if (req->gfr_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_get_feat_fields,
		    nvme_get_feat_nfields, NVME_ERR_GET_FEAT_REQ_MISSING_FIELDS,
		    "get feature", req->gfr_need));
	}

	(void) memset(&feat, 0, sizeof (nvme_ioctl_get_feature_t));
	feat.nigf_common.nioc_nsid = req->gfr_nsid;
	feat.nigf_fid = req->gfr_fid;
	feat.nigf_sel = req->gfr_sel;
	feat.nigf_cdw11 = req->gfr_cdw11;
	if (req->gfr_buf != NULL) {
		feat.nigf_data = (uintptr_t)req->gfr_buf;
		feat.nigf_len = req->gfr_len;
	}

	if (ioctl(ctrl->nc_fd, NVME_IOC_GET_FEATURE, &feat) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "get feature"));
	}

	if (feat.nigf_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &feat.nigf_common,
		    "get feature"));
	}

	req->gfr_results_valid = true;
	req->gfr_cdw0 = feat.nigf_cdw0;

	return (nvme_ctrl_success(ctrl));
}
