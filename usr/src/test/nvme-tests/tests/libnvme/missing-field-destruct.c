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
 * Verify that we generate the appropriate missing field error for destructive
 * tests.
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
	nvme_fw_commit_req_t *fw_commit_req = NULL;
	nvme_format_req_t *format_req = NULL;
	nvme_ns_create_req_t *create_req = NULL;
	nvme_ns_delete_req_t *delete_req = NULL;
	nvme_ns_attach_req_t *attach_req = NULL;

	libnvme_test_init(&nvme, &ctrl);

	if (!nvme_fw_commit_req_init(ctrl, &fw_commit_req)) {
		if (nvme_ctrl_err(ctrl) == NVME_ERR_FW_UNSUP_BY_DEV) {
			warnx("TEST SKIPPED: device does not support firmware "
			    "requests");
		} else {
			libnvme_test_ctrl_warn(ctrl, "failed to initialize fw "
			    "commit request");
			ret = EXIT_FAILURE;
		}
	} else if (nvme_fw_commit_req_exec(fw_commit_req)) {
		warnx("TEST FAILED: fw commit request succeeded despite "
		    "missing fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "fw commit request",
	    NVME_ERR_FW_COMMIT_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: fw commit request generated "
		    "missing fields error\n");
	}
	nvme_fw_commit_req_fini(fw_commit_req);

	if (!nvme_format_req_init(ctrl, &format_req)) {
		if (nvme_ctrl_err(ctrl) == NVME_ERR_FORMAT_UNSUP_BY_DEV) {
			warnx("TEST SKIPPED: device does not support format "
			    "requests");
		} else {
			libnvme_test_ctrl_warn(ctrl, "failed to initialize "
			    "format request");
			ret = EXIT_FAILURE;
		}
	} else if (nvme_format_req_exec(format_req)) {
		warnx("TEST FAILED: format request succeeded despite missing "
		    "fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "format request",
	    NVME_ERR_FORMAT_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: format request generated missing "
		    "fields error\n");
	}
	nvme_format_req_fini(format_req);

	if (!nvme_ns_create_req_init_by_csi(ctrl, NVME_CSI_NVM, &create_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "create request");
		ret = EXIT_FAILURE;
	} else if (nvme_ns_create_req_exec(create_req)) {
		warnx("TEST FAILED: namespace create request succeeded despite "
		    "missing fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "namespace create",
	    NVME_ERR_NS_CREATE_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: namespace create generated missing "
		    "fields error\n");
	}
	nvme_ns_create_req_fini(create_req);

	if (!nvme_ns_delete_req_init(ctrl, &delete_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "delete request");
		ret = EXIT_FAILURE;
	} else if (nvme_ns_delete_req_exec(delete_req)) {
		warnx("TEST FAILED: namespace delete request succeeded despite "
		    "missing fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "namespace delete",
	    NVME_ERR_NS_DELETE_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: namespace delete generated missing "
		    "fields error\n");
	}
	nvme_ns_delete_req_fini(delete_req);

	if (!nvme_ns_attach_req_init_by_sel(ctrl, NVME_NS_ATTACH_CTRL_ATTACH,
	    &attach_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "attach request");
		ret = EXIT_FAILURE;
	} else if (nvme_ns_attach_req_exec(attach_req)) {
		warnx("TEST FAILED: namespace attach request succeeded despite "
		    "missing fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "namespace attach",
	    NVME_ERR_NS_ATTACH_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: namespace attach generated missing "
		    "fields error\n");
	}
	nvme_ns_attach_req_fini(attach_req);

	if (!nvme_ns_attach_req_init_by_sel(ctrl, NVME_NS_ATTACH_CTRL_DETACH,
	    &attach_req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to initialize namespace "
		    "detach request");
		ret = EXIT_FAILURE;
	} else if (nvme_ns_attach_req_exec(attach_req)) {
		warnx("TEST FAILED: namespace detach request succeeded despite "
		    "missing fields");
		ret = EXIT_FAILURE;
	} else if (!missing_field_err(ctrl, "namespace detach",
	    NVME_ERR_NS_ATTACH_REQ_MISSING_FIELDS)) {
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: namespace detach generated missing "
		    "fields error\n");
	}
	nvme_ns_attach_req_fini(attach_req);



	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
