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
 * Verify that we generate the appropriate missing field error for the
 * non-vendor-specific request types. Destructive requests are in
 * missing-field-destruct.c.
 */

#include <err.h>
#include <string.h>

#include "libnvme_test_common.h"

static bool
missing_field_err(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp_err)
{
	nvme_err_t err = nvme_ctrl_err(ctrl);

	if (err == exp_err) {
		return (true);
	}

	warnx("TEST FAILED: %s returned wrong error %s (0x%x), not %s (0x%x)",
	    desc, nvme_ctrl_errtostr(ctrl, err), err,
	    nvme_ctrl_errtostr(ctrl, exp_err), exp_err);
	return (false);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_id_req_t *id_req = NULL;
	nvme_log_req_t *log_req = NULL;
	nvme_get_feat_req_t *get_feat_req = NULL;
	nvme_vuc_req_t *vuc_req = NULL;

	libnvme_test_init(&nvme, &ctrl);

	if (!nvme_id_req_init_by_cns(ctrl, NVME_CSI_NVM, NVME_IDENTIFY_CTRL,
	    &id_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize identify "
		    "request");
		ret = EXIT_FAILURE;
	} else if (nvme_id_req_exec(id_req)) {
		warnx("TEST FAILED: identify request succeeded despite missing "
		    "fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "identify request",
	    NVME_ERR_IDENTIFY_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: identify request generated missing "
		    "fields error\n");
	}
	nvme_id_req_fini(id_req);

	if (!nvme_log_req_init(ctrl, &log_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize log "
		    "request");
		ret = EXIT_FAILURE;
	} else if (nvme_log_req_exec(log_req)) {
		warnx("TEST FAILED: log request succeeded despite missing "
		    "fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "log request",
	    NVME_ERR_LOG_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: log request generated missing "
		    "fields error\n");
	}
	nvme_log_req_fini(log_req);

	if (!nvme_get_feat_req_init(ctrl, &get_feat_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize get feature "
		    "request");
		ret = EXIT_FAILURE;
	} else if (nvme_get_feat_req_exec(get_feat_req)) {
		warnx("TEST FAILED: get feature request succeeded despite "
		    "missing fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "get feature request",
	    NVME_ERR_GET_FEAT_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: get feature request generated "
		    "missing fields error\n");
	}
	nvme_get_feat_req_fini(get_feat_req);

	if (!nvme_vuc_req_init(ctrl, &vuc_req)) {
		if (nvme_ctrl_err(ctrl) == NVME_ERR_VUC_UNSUP_BY_DEV) {
			warnx("TEST SKIPPED: device does not support VUC "
			    "requests");
		} else {
			libnvme_test_ctrl_warn(ctrl, "failed to initialize vuc "
			    "request");
			ret = EXIT_FAILURE;
		}
	} else if (nvme_vuc_req_exec(vuc_req)) {
		warnx("TEST FAILED: vuc request succeeded despite missing "
		    "fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "vuc request",
	    NVME_ERR_VUC_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: vuc request generated missing "
		    "fields error\n");
	}
	nvme_vuc_req_fini(vuc_req);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);
	return (ret);
}
