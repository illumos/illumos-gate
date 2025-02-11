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
 * This implements all of the libnvme log discovery and log page execution
 * functions.
 *
 * In NVMe 1.0 there were just three mandatory log pages. These are the classic
 * Error, SMART, and firmware log pages. NVMe 1.1 added an optional log page for
 * NVM devices. Specifically this is the Reservation Log page. This was
 * indicated by the controller's ONCS field. Version 1.1 also introduced the Log
 * Page Attributes (LPA) field which is how additional pages were indicated as
 * being supported when not part of something like ONCS.
 *
 * Beginning in NVMe 1.2, many more log pages were added that were optional. In
 * particular, the changed namespace list and command effects log. The former
 * has support indicated via a bit in OAES (though this was not clarified until
 * NVMe 1.3) while the latter is in the LPA field. NVMe 1.2 also added the
 * ability for the Get Log Page to support larger amounts of data. The last
 * major piece of 1.2 was the addition of fabrics related log pages. Those are
 * not currently supported here.
 *
 * NVMe 1.3 and 1.4 continued the trend of adding log pages that are generally
 * optional, but may be required given a specific set of features being enabled.
 *
 * The largest change for log pages is in NVMe 2.0. It added a specific means of
 * indicating a command set for a given log page and also added the ability to
 * query all the supported log pages. This has existed previously, but only
 * through vendor specific means.
 */

#include <string.h>
#include <upanic.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <unistd.h>

#include "libnvme_impl.h"

void
nvme_log_disc_free(nvme_log_disc_t *disc)
{
	free(disc);
}

const char *
nvme_log_disc_name(const nvme_log_disc_t *disc)
{
	return (disc->nld_short);
}

const char *
nvme_log_disc_desc(const nvme_log_disc_t *disc)
{
	return (disc->nld_desc);
}

nvme_csi_t
nvme_log_disc_csi(const nvme_log_disc_t *disc)
{
	return (disc->nld_csi);
}

uint32_t
nvme_log_disc_lid(const nvme_log_disc_t *disc)
{
	return (disc->nld_lid);
}

nvme_log_disc_kind_t
nvme_log_disc_kind(const nvme_log_disc_t *disc)
{
	return (disc->nld_kind);
}

nvme_log_disc_source_t
nvme_log_disc_sources(const nvme_log_disc_t *disc)
{
	return (disc->nld_srcs);
}

nvme_log_disc_fields_t
nvme_log_disc_fields(const nvme_log_disc_t *disc)
{
	return (disc->nld_fields);
}

nvme_log_disc_scope_t
nvme_log_disc_scopes(const nvme_log_disc_t *disc)
{
	return (disc->nld_scope);
}

bool
nvme_log_disc_impl(const nvme_log_disc_t *disc)
{
	return ((disc->nld_flags & NVME_LOG_DISC_F_IMPL) != 0);
}

nvme_log_size_kind_t
nvme_log_disc_size(const nvme_log_disc_t *disc, uint64_t *sizep)
{
	*sizep = disc->nld_alloc_len;
	return (disc->nld_size_kind);
}

/*
 * For a variable length log page, presuming we've been given sufficient data
 * actually determine the overall length that should now be used to get all
 * data in the log.
 */
bool
nvme_log_disc_calc_size(const nvme_log_disc_t *disc, uint64_t *act,
    const void *buf, size_t buflen)
{
	if (disc->nld_var_func == NULL) {
		*act = disc->nld_alloc_len;
	}

	return (disc->nld_var_func(act, buf, buflen));
}

bool
nvme_log_disc_dup(nvme_ctrl_t *ctrl, const nvme_log_disc_t *src,
    nvme_log_disc_t **discp)
{
	nvme_log_disc_t *disc;

	if (src == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_disc_t pointer to duplicate: "
		    "%p", src));
	}

	if (discp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_disc_t output pointer: %p",
		    discp));
	}

	disc = calloc(1, sizeof (nvme_log_disc_t));
	if (disc == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_log_disc_t: %s",
		    strerror(e)));
	}

	(void) memcpy(disc, src, sizeof (nvme_log_disc_t));
	*discp = disc;
	return (nvme_ctrl_success(ctrl));
}

/*
 * Log Page Discovery logic
 */
static bool
nvme_log_discover_validate(nvme_ctrl_t *ctrl, nvme_log_disc_scope_t scopes,
    uint32_t flags)
{
	const nvme_log_disc_scope_t valid_scopes = NVME_LOG_SCOPE_CTRL |
	    NVME_LOG_SCOPE_NVM | NVME_LOG_SCOPE_NS;

	/*
	 * For now require an explicit scope. Perhaps 0 should be an alias for
	 * allow all. That means if something gets added no one has to update to
	 * get new things, but on the other hand that means they might see
	 * unexpected scopes.
	 */
	if (scopes == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0, "no log "
		    "scope specified (given 0), a scope must be requested"));
	}

	if ((scopes & ~valid_scopes) != 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0,
		    "encountered invalid scope for the nvme_log_disc_scope_t: "
		    "0x%x", scopes & ~valid_scopes));
	}

	if (flags != 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_FLAG, 0,
		    "encountered invalid log discovery flags: 0x%x", flags));
	}

	return (true);
}

/*
 * The NVMe 2.0 specification adds a mandatory log page that describes which log
 * pages are actually implemented, though not as much information as we use in
 * discovery. We will attempt once per controller handle to get this log page
 * and use it to augment the supported information in the discovery process.
 * This log page is the first entry of the nvme_std_log_pages array.
 */
static void
nvme_log_discover_fetch_sup_logs(nvme_ctrl_t *ctrl)
{
	const nvme_log_page_info_t *sup_info = &nvme_std_log_pages[0];
	nvme_suplog_log_t *sup = NULL;
	nvme_log_req_t *req = NULL;
	nvme_valid_ctrl_data_t data;

	VERIFY3U(sup_info->nlpi_lid, ==, NVME_LOGPAGE_SUP);

	/*
	 * Mark the data in the nvme_ctrl_t as valid at this point. If this
	 * fails, we swallow this error and just will have slightly less
	 * information available on certain log pages. In general, this only
	 * impacts the detection of vendor defined log pages where our built-in
	 * information is not as accurate due to the lack of firmware
	 * information.
	 */
	ctrl->nc_sup_logs = NULL;
	ctrl->nc_flags |= NVME_CTRL_F_SUP_LOGS_VALID;

	data.vcd_vers = &ctrl->nc_vers;
	data.vcd_id = &ctrl->nc_info;

	if (!nvme_log_page_info_supported(sup_info, &data)) {
		return;
	}

	sup = calloc(1, sizeof (nvme_suplog_log_t));
	if (sup == NULL) {
		int e = errno;
		(void) nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for internal log page info: %s",
		    strerror(e));
		goto err;
	}

	if (!nvme_log_req_init(ctrl, &req)) {
		goto err;
	}

	if (!nvme_log_req_set_lid(req, sup_info->nlpi_lid) ||
	    !nvme_log_req_set_csi(req, sup_info->nlpi_csi) ||
	    !nvme_log_req_set_output(req, sup, sizeof (nvme_suplog_log_t)) ||
	    !nvme_log_req_exec(req)) {
		goto err;
	}

	ctrl->nc_sup_logs = sup;
	nvme_log_req_fini(req);
	return;

err:
	/*
	 * Flag this as failed and attempt to save the error that got us here.
	 * If a memory allocation failure occurs here, then there's not much
	 * more we can do, but at least this flag set and no error information
	 * does indicate a memory problem. Regardless, we clear out the error
	 * from the nvme_ctrl_t.
	 */
	ctrl->nc_flags |= NVME_CTRL_F_SUP_LOGS_FAILED;
	if ((ctrl->nc_sup_logs_err = calloc(1, sizeof (nvme_err_data_t))) !=
	    NULL) {
		nvme_ctrl_err_save(ctrl, ctrl->nc_sup_logs_err);
	}
	(void) nvme_ctrl_success(ctrl);
	nvme_log_req_fini(req);
	free(sup);
}

void
nvme_log_discover_fini(nvme_log_iter_t *iter)
{
	free(iter);
}

static bool
nvme_log_discover_one(nvme_log_iter_t *iter, const nvme_log_page_info_t *info)
{
	bool var;
	nvme_log_disc_t *disc = &iter->nli_nld;
	nvme_ctrl_t *ctrl = iter->nli_ctrl;
	nvme_log_disc_scope_t scope;
	nvme_valid_ctrl_data_t data;

	data.vcd_vers = &iter->nli_ctrl->nc_vers;
	data.vcd_id = &iter->nli_ctrl->nc_info;

	/*
	 * Determine the scope of the log page so we can understand if the user
	 * cares about this or not.
	 */
	scope = nvme_log_page_info_scope(info, &data);
	if ((iter->nli_scope & scope) == 0) {
		return (false);
	}

	(void) memset(disc, 0, sizeof (nvme_log_disc_t));

	/*
	 * Now that we know that this applies, fill in the remaining information
	 * that we need.
	 */
	disc->nld_short = info->nlpi_short;
	disc->nld_desc = info->nlpi_human;
	disc->nld_lid = info->nlpi_lid;
	disc->nld_csi = info->nlpi_csi;
	disc->nld_kind = info->nlpi_kind;
	disc->nld_srcs = info->nlpi_source;
	disc->nld_scope = scope;
	disc->nld_fields = info->nlpi_disc;

	disc->nld_alloc_len = nvme_log_page_info_size(info, &data, &var);
	if (disc->nld_alloc_len != 0) {
		if (var) {
			disc->nld_var_func = info->nlpi_var_func;
			disc->nld_size_kind = NVME_LOG_SIZE_K_VAR;
		} else {
			disc->nld_size_kind = NVME_LOG_SIZE_K_FIXED;
		}
	} else {
		disc->nld_size_kind = NVME_LOG_SIZE_K_UNKNOWN;
		disc->nld_alloc_len = NVME_LOG_MAX_SIZE;
	}

	/*
	 * Determine if a log page is supported. This uses the per-log knowledge
	 * built into the nvme_log_page_info_t structures by default. When we
	 * have the NVMe 2.0 Supported Log Pages log, then we require both that
	 * and the internal bits fire. We've encountered some cases where the
	 * datasheet indicates something is supported, but firmware does not for
	 * some surprising reason. We haven't yet found cases where our logic
	 * says something is implemented but the log page information is wrong.
	 * That will likely come some day and we'll need a quirks list.
	 */
	if (nvme_log_page_info_supported(info, &data) &&
	    (ctrl->nc_sup_logs == NULL ||
	    ctrl->nc_sup_logs->nl_logs[info->nlpi_lid].ns_lsupp) != 0) {
		disc->nld_flags |= NVME_LOG_DISC_F_IMPL;
	}

	return (true);
}

nvme_iter_t
nvme_log_discover_step(nvme_log_iter_t *iter, const nvme_log_disc_t **outp)
{
	*outp = NULL;
	nvme_ctrl_t *ctrl = iter->nli_ctrl;

	if (iter->nli_std_done && iter->nli_vs_done) {
		return (NVME_ITER_DONE);
	}

	/*
	 * We start by walking the list of spec pages and then check the device
	 * specific ones. While we may have the NVMe 2.0 Supported Log Page
	 * information, we don't really use that in discovery right now as it's
	 * rather hard to communicate useful discovery information with that. We
	 * mostly use this as a check on whether or not the log page is actually
	 * implemented based on our knowledge.
	 */
	if (!iter->nli_std_done) {
		while (iter->nli_cur_idx < nvme_std_log_npages) {
			const nvme_log_page_info_t *info =
			    &nvme_std_log_pages[iter->nli_cur_idx];
			iter->nli_cur_idx++;
			if (nvme_log_discover_one(iter, info)) {
				*outp = &iter->nli_nld;
				return (NVME_ITER_VALID);
			}
		}
		iter->nli_std_done = true;
		iter->nli_cur_idx = 0;
	}

	if (ctrl->nc_vsd == NULL) {
		iter->nli_vs_done = true;
		return (NVME_ITER_DONE);
	}

	while (iter->nli_cur_idx < ctrl->nc_vsd->nvd_nlogs) {
		const nvme_log_page_info_t *info =
		    ctrl->nc_vsd->nvd_logs[iter->nli_cur_idx];
		iter->nli_cur_idx++;
		if (nvme_log_discover_one(iter, info)) {
			*outp = &iter->nli_nld;
			return (NVME_ITER_VALID);
		}
	}

	iter->nli_vs_done = true;
	iter->nli_cur_idx = 0;
	return (NVME_ITER_DONE);
}

bool
nvme_log_discover_init(nvme_ctrl_t *ctrl, nvme_log_disc_scope_t scopes,
    uint32_t flags, nvme_log_iter_t **iterp)
{
	nvme_log_iter_t *iter;

	if (!nvme_log_discover_validate(ctrl, scopes, flags)) {
		return (false);
	}

	if (iterp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_iter_t output pointer: %p",
		    iterp));
	}

	iter = calloc(1, sizeof (nvme_log_iter_t));
	if (iter == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_log_iter_t: %s",
		    strerror(e)));
	}

	if ((ctrl->nc_flags & NVME_CTRL_F_SUP_LOGS_VALID) == 0) {
		nvme_log_discover_fetch_sup_logs(ctrl);
	}

	iter->nli_ctrl = ctrl;
	iter->nli_scope = scopes;

	*iterp = iter;
	return (nvme_ctrl_success(ctrl));
}

/*
 * Walk all of the requested log pages that match and fill out the information
 * for the discovery form.
 */
bool
nvme_log_discover(nvme_ctrl_t *ctrl, nvme_log_disc_scope_t scopes,
    uint32_t flags, nvme_log_disc_f func, void *arg)
{
	nvme_log_iter_t *iter;
	nvme_iter_t ret;
	const nvme_log_disc_t *disc;

	if (func == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_disc_f function pointer: %p",
		    func));
	}

	if (!nvme_log_discover_init(ctrl, scopes, flags, &iter)) {
		return (false);
	}

	while ((ret = nvme_log_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		if (!func(ctrl, disc, arg))
			break;
	}

	nvme_log_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		return (false);
	}

	return (nvme_ctrl_success(ctrl));
}


void
nvme_log_req_fini(nvme_log_req_t *req)
{
	free(req);
}

/*
 * This is the totally manual path that occurs. When this is used, we require
 * that people specify a subset of the fields here, primarily just the actual
 * log page, output, and CSI. We don't try to be clever here and use the
 * discovery information to know what to set. That's reserved for creating this
 * request based upon discovery information.
 */
bool
nvme_log_req_init(nvme_ctrl_t *ctrl, nvme_log_req_t **reqp)
{
	nvme_log_req_t *req;

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_req_t output pointer: %p",
		    reqp));
	}

	req = calloc(1, sizeof (nvme_log_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_log_req_t: %s",
		    strerror(e)));
	}

	req->nlr_ctrl = ctrl;
	for (size_t i = 0; i < nvme_log_nfields; i++) {
		if (nvme_log_fields[i].nlfi_def_req) {
			req->nlr_need |= 1 << i;
		}

		if (nvme_log_fields[i].nlfi_def_allow) {
			req->nlr_allow |= 1 << i;
		}
	}

	/*
	 * Because we don't know anything about this log request, indicate that
	 * if we're given the all namespaces nsid that's fine. We'll still
	 * check the controller version when this is set first.
	 */
	req->nlr_flags |= NVME_LOG_REQ_F_BCAST_NS_OK;

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

bool
nvme_log_req_init_by_disc(nvme_ctrl_t *ctrl, const nvme_log_disc_t *disc,
    nvme_log_req_t **reqp)
{
	nvme_log_req_t *req;

	if (disc == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_disc_t pointer: %p", disc));
	}

	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_req_t output pointer: %p",
		    reqp));
	}

	if ((disc->nld_flags & NVME_LOG_DISC_F_IMPL) == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_LOG_UNSUP_BY_DEV, 0,
		    "cannot create log request for log %s (CSI/LID 0x%x/0x%x) "
		    "because it is not supported by the device",
		    disc->nld_short, disc->nld_csi, disc->nld_lid));
	}

	req = calloc(1, sizeof (nvme_log_req_t));
	if (req == NULL) {
		int e = errno;
		return (nvme_ctrl_error(ctrl, NVME_ERR_NO_MEM, e, "failed to "
		    "allocate memory for a new nvme_log_req_t: %s",
		    strerror(e)));
	}

	req->nlr_ctrl = ctrl;
	req->nlr_lid = disc->nld_lid;
	req->nlr_csi = disc->nld_csi;

	/*
	 * Setting the size is always required here, because this is how we
	 * track that the output pointer is actually set. We will always allow
	 * setting the offset though it's possible the controller won't support
	 * that.
	 */
	req->nlr_need = req->nlr_allow = 1 << NVME_LOG_REQ_FIELD_SIZE;
	req->nlr_allow |= 1 << NVME_LOG_REQ_FIELD_OFFSET;

	/*
	 * Initialize our needed and allowed fields. Because we have the actual
	 * lid/csi from the above, we don't allow the user to overwrite them at
	 * all. For the LSP and LSI, right now these are all our nothing, but
	 * this may break. RAE is a bit special and discussed below.
	 */
	if ((disc->nld_fields & NVME_LOG_DISC_F_NEED_LSP) != 0) {
		req->nlr_need |= 1 << NVME_LOG_REQ_FIELD_LSP;
		req->nlr_allow |= 1 << NVME_LOG_REQ_FIELD_LSP;
	}

	if ((disc->nld_fields & NVME_LOG_DISC_F_NEED_LSI) != 0) {
		req->nlr_need |= 1 << NVME_LOG_REQ_FIELD_LSI;
		req->nlr_allow |= 1 << NVME_LOG_REQ_FIELD_LSI;
	}

	/*
	 * Because RAE wasn't added until NVMe 1.3, we can't do much with it
	 * before that. However, once it's here we definitely want to default to
	 * setting it by default so that way we can minimize the chance that
	 * we'll steal an alert that the kernel needs to read and acknowledge.
	 */
	if ((disc->nld_fields & NVME_LOG_DISC_F_NEED_RAE) != 0 &&
	    nvme_vers_ctrl_atleast(ctrl,
	    nvme_log_fields[NVME_LOG_REQ_FIELD_RAE].nlfi_vers)) {
		req->nlr_flags |= NVME_LOG_REQ_F_RAE;
		req->nlr_allow |= 1 << NVME_LOG_REQ_FIELD_RAE;
	}

	/*
	 * Check the log page scope setting. If the log is said to be namespace
	 * scoped, then we'll allow the namespace to be specified. If it
	 * supports a different scope as well, then we'll default to the
	 * controller scope and this field is optional. Otherwise, it'll be
	 * required and it will be a mandatory field.
	 */
	if ((disc->nld_scope & NVME_LOG_SCOPE_NS) != 0) {
		req->nlr_allow |= 1 << NVME_LOG_REQ_FIELD_NSID;
		if ((disc->nld_scope & ~NVME_LOG_SCOPE_NS) != 0) {
			req->nlr_flags |= NVME_LOG_REQ_F_BCAST_NS_OK;
			req->nlr_nsid = NVME_NSID_BCAST;
		} else {
			req->nlr_need |= 1 << NVME_LOG_REQ_FIELD_NSID;
		}
	}

	*reqp = req;
	return (nvme_ctrl_success(ctrl));
}

typedef struct {
	bool nlia_found;
	const char *nlia_name;
	nvme_log_req_t *nlia_req;
	nvme_log_disc_t **nlia_discp;
	nvme_err_data_t nlia_err;
} nvme_log_init_arg_t;

static bool
nvme_log_req_init_by_name_cb(nvme_ctrl_t *ctrl, const nvme_log_disc_t *disc,
    void *arg)
{
	nvme_log_init_arg_t *init = arg;

	if (strcmp(init->nlia_name, disc->nld_short) != 0) {
		return (true);
	}

	init->nlia_found = true;
	if (!nvme_log_req_init_by_disc(ctrl, disc, &init->nlia_req)) {
		nvme_ctrl_err_save(ctrl, &init->nlia_err);
		init->nlia_req = NULL;
	} else if (init->nlia_discp != NULL) {
		if (!nvme_log_disc_dup(ctrl, disc, init->nlia_discp)) {
			nvme_ctrl_err_save(ctrl, &init->nlia_err);
			nvme_log_req_fini(init->nlia_req);
			init->nlia_req = NULL;
		}
	}

	return (false);
}

bool
nvme_log_req_init_by_name(nvme_ctrl_t *ctrl, const char *name, uint32_t flags,
    nvme_log_disc_t **discp, nvme_log_req_t **reqp)
{
	nvme_log_init_arg_t init;

	/*
	 * We consider discp an optional argument and therefore do not check it
	 * unlike name and reqp.
	 */
	if (reqp == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid nvme_log_req_t output pointer: %p",
		    reqp));
	}

	if (name == NULL) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_BAD_PTR, 0,
		    "encountered invalid pointer for log page name: %p", name));
	}

	(void) memset(&init, 0, sizeof (init));
	init.nlia_name = name;
	init.nlia_discp = discp;

	if (!nvme_log_discover(ctrl, NVME_LOG_SCOPE_CTRL |
	    NVME_LOG_SCOPE_NVM | NVME_LOG_SCOPE_NS, flags,
	    nvme_log_req_init_by_name_cb, &init)) {
		return (false);
	}

	if (!init.nlia_found) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_LOG_NAME_UNKNOWN, 0,
		    "failed to find log page with name %s", name));
	}

	/*
	 * If we failed to create the request, but we did find it, then that
	 * means something went wrong and we can go ahead and already return an
	 * error.
	 */
	if (init.nlia_req == NULL) {
		nvme_ctrl_err_set(ctrl, &init.nlia_err);
		return (false);
	}

	*reqp = init.nlia_req;
	return (nvme_ctrl_success(ctrl));
}

static void
nvme_log_req_set_need(nvme_log_req_t *req, nvme_log_req_field_t field)
{
	req->nlr_need |= 1 << field;
}

static void
nvme_log_req_clear_need(nvme_log_req_t *req, nvme_log_req_field_t field)
{
	req->nlr_need &= ~(1 << field);
}

static const nvme_field_check_t nvme_log_check_lid = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_LID,
	NVME_ERR_LOG_LID_RANGE, 0, 0
};

bool
nvme_log_req_set_lid(nvme_log_req_t *req, uint32_t lid)
{
	if (!nvme_field_check_one(req->nlr_ctrl, lid, "get log page",
	    &nvme_log_check_lid, req->nlr_allow)) {
		return (false);
	}

	req->nlr_lid = lid;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_LID);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_lsp = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_LSP,
	NVME_ERR_LOG_LSP_RANGE, NVME_ERR_LOG_LSP_UNSUP,
	NVME_ERR_LOG_LSP_UNUSE
};

bool
nvme_log_req_set_lsp(nvme_log_req_t *req, uint32_t lsp)
{
	if (!nvme_field_check_one(req->nlr_ctrl, lsp, "get log page",
	    &nvme_log_check_lsp, req->nlr_allow)) {
		return (false);
	}

	req->nlr_lsp = lsp;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_LSP);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_lsi = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_LSI,
	NVME_ERR_LOG_LSI_RANGE, NVME_ERR_LOG_LSI_UNSUP,
	NVME_ERR_LOG_LSI_UNUSE
};

bool
nvme_log_req_set_lsi(nvme_log_req_t *req, uint32_t lsi)
{
	if (!nvme_field_check_one(req->nlr_ctrl, lsi, "get log page",
	    &nvme_log_check_lsi, req->nlr_allow)) {
		return (false);
	}

	req->nlr_lsi = lsi;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_LSI);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_csi = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_CSI,
	NVME_ERR_LOG_CSI_RANGE, NVME_ERR_LOG_CSI_UNSUP, 0
};

bool
nvme_log_req_set_csi(nvme_log_req_t *req, nvme_csi_t csi)
{
	if (!nvme_field_check_one(req->nlr_ctrl, csi, "get log page",
	    &nvme_log_check_csi, req->nlr_allow)) {
		return (false);
	}

	req->nlr_csi = csi;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_CSI);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_size = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_SIZE,
	NVME_ERR_LOG_SIZE_RANGE, 0, 0
};

bool
nvme_log_req_set_output(nvme_log_req_t *req, void *buf, size_t buflen)
{
	if (buf == NULL) {
		return (nvme_ctrl_error(req->nlr_ctrl, NVME_ERR_BAD_PTR, 0,
		    "log request output buffer cannot be NULL"));
	}

	if (!nvme_field_check_one(req->nlr_ctrl, buflen, "get log page",
	    &nvme_log_check_size, req->nlr_allow)) {
		return (false);
	}

	req->nlr_output = buf;
	req->nlr_output_len = buflen;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_SIZE);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

bool
nvme_log_req_clear_output(nvme_log_req_t *req)
{
	req->nlr_output = NULL;
	req->nlr_output_len = 0;

	/*
	 * We can always set that we need this again as every log page requires
	 * a size being set. See the default allow settings for the field in
	 * nvme_log_fields[] and nvme_log_req_init_by_disc().
	 */
	nvme_log_req_set_need(req, NVME_LOG_REQ_FIELD_SIZE);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_offset = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_OFFSET,
	NVME_ERR_LOG_OFFSET_RANGE, 0, 0
};

bool
nvme_log_req_set_offset(nvme_log_req_t *req, uint64_t off)
{
	if (!nvme_field_check_one(req->nlr_ctrl, off, "get log page",
	    &nvme_log_check_offset, req->nlr_allow)) {
		return (false);
	}

	req->nlr_offset = off;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_OFFSET);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_nsid = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_NSID, NVME_ERR_NS_RANGE, 0, 0
};

bool
nvme_log_req_set_nsid(nvme_log_req_t *req, uint32_t nsid)
{
	nvme_ctrl_t *ctrl = req->nlr_ctrl;

	if (nsid == NVME_NSID_BCAST &&
	    (req->nlr_flags & NVME_LOG_REQ_F_BCAST_NS_OK) == 0) {
		return (nvme_ctrl_error(ctrl, NVME_ERR_NS_RANGE, 0, "the all "
		    "namespaces/controller nsid (0x%x) is not allowed for this "
		    "log page, valid namespaces are [0x%x, 0x%x]", nsid,
		    NVME_NSID_MIN, req->nlr_ctrl->nc_info.id_nn));
	}

	if (!nvme_field_check_one(req->nlr_ctrl, nsid, "get log page",
	    &nvme_log_check_nsid, req->nlr_allow)) {
		return (false);
	}

	req->nlr_nsid = nsid;
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_NSID);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

static const nvme_field_check_t nvme_log_check_rae = {
	nvme_log_fields, NVME_LOG_REQ_FIELD_RAE,
	NVME_ERR_LOG_RAE_RANGE, NVME_ERR_LOG_RAE_UNSUP,
	NVME_ERR_LOG_RAE_UNUSE
};

bool
nvme_log_req_set_rae(nvme_log_req_t *req, bool rae)
{
	if (!nvme_field_check_one(req->nlr_ctrl, rae, "get log page",
	    &nvme_log_check_rae, req->nlr_allow)) {
		return (false);
	}

	if (rae) {
		req->nlr_flags |= NVME_LOG_REQ_F_RAE;
	} else {
		req->nlr_flags &= ~NVME_LOG_REQ_F_RAE;
	}
	nvme_log_req_clear_need(req, NVME_LOG_REQ_FIELD_RAE);
	return (nvme_ctrl_success(req->nlr_ctrl));
}

bool
nvme_log_req_exec(nvme_log_req_t *req)
{
	nvme_ctrl_t *ctrl = req->nlr_ctrl;
	nvme_ioctl_get_logpage_t log;

	if (req->nlr_need != 0) {
		return (nvme_field_miss_err(ctrl, nvme_log_fields,
		    nvme_log_nfields, NVME_ERR_LOG_REQ_MISSING_FIELDS,
		    "get log page", req->nlr_need));
	}

	(void) memset(&log, 0, sizeof (nvme_ioctl_get_logpage_t));
	log.nigl_common.nioc_nsid = req->nlr_nsid;
	log.nigl_csi = req->nlr_csi;
	log.nigl_lid = req->nlr_lid;
	log.nigl_lsp = req->nlr_lsp;
	log.nigl_lsi = req->nlr_lsi;
	if ((req->nlr_flags & NVME_LOG_REQ_F_RAE) != 0) {
		log.nigl_rae = 1;
	}
	log.nigl_len = req->nlr_output_len;
	log.nigl_offset = req->nlr_offset;
	log.nigl_data = (uintptr_t)req->nlr_output;

	if (ioctl(ctrl->nc_fd, NVME_IOC_GET_LOGPAGE, &log) != 0) {
		int e = errno;
		return (nvme_ioctl_syserror(ctrl, e, "get log page"));
	}

	if (log.nigl_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		return (nvme_ioctl_error(ctrl, &log.nigl_common,
		    "get log page"));
	}

	return (nvme_ctrl_success(ctrl));
}
