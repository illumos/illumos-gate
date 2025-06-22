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
 * Go through the various controller request initialization routines and try to
 * force various bad arguments in them.
 */

#include <err.h>
#include <string.h>
#include <umem.h>

#include "libnvme_test_common.h"

static bool
bad_id_req(nvme_ctrl_t *ctrl, nvme_csi_t csi, uint32_t cns,
    nvme_id_req_t **reqp, nvme_err_t exp_err, const char *desc)
{
	if (nvme_id_req_init_by_cns(ctrl, csi, cns, reqp)) {
		warnx("TEST FAILED: nvme_id_req_init_by_cns() erroneously "
		    "passed despite %s", desc);
		nvme_id_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_id_req_init_by_cns() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_id_req_init_by_cns() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_log_req(nvme_ctrl_t *ctrl, nvme_log_req_t **reqp, nvme_err_t exp_err,
    const char *desc)
{
	if (nvme_log_req_init(ctrl, reqp)) {
		warnx("TEST FAILED: nvme_log_req_init() erroneously "
		    "passed despite %s", desc);
		nvme_log_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_log_req_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_log_req_init() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_log_req_by_name(nvme_ctrl_t *ctrl, const char *name, uint32_t flags,
    nvme_log_req_t **reqp, nvme_err_t exp_err, const char *desc)
{
	if (nvme_log_req_init_by_name(ctrl, name, flags, NULL, reqp)) {
		warnx("TEST FAILED: nvme_log_req_init_by_name() erroneously "
		    "passed despite %s", desc);
		nvme_log_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_log_req_init_by_name() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_log_req_init_by_name() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_get_feat_req(nvme_ctrl_t *ctrl, nvme_get_feat_req_t **reqp,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_get_feat_req_init(ctrl, reqp)) {
		warnx("TEST FAILED: nvme_get_feat_req_init() erroneously "
		    "passed despite %s", desc);
		nvme_get_feat_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_get_feat_req_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_get_feat_req_init() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_get_feat_req_by_name(nvme_ctrl_t *ctrl, const char *name, uint32_t flags,
    nvme_get_feat_req_t **reqp, nvme_err_t exp_err, const char *desc)
{
	if (nvme_get_feat_req_init_by_name(ctrl, name, flags, NULL, reqp)) {
		warnx("TEST FAILED: nvme_get_feat_req_init_by_name() "
		    "erroneously passed despite %s", desc);
		nvme_get_feat_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_get_feat_req_init_by_name() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_get_feat_req_init_by_name() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_vuc_req(nvme_ctrl_t *ctrl, nvme_vuc_req_t **reqp, nvme_err_t exp_err,
    const char *desc)
{
	if (nvme_vuc_req_init(ctrl, reqp)) {
		warnx("TEST FAILED: nvme_vuc_req_init() erroneously "
		    "passed despite %s", desc);
		nvme_vuc_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		/*
		 * We don't have any vendor unique commands for some devices.
		 * Swallow those rather than error.
		 */
		if (nvme_ctrl_err(ctrl) == NVME_ERR_VUC_UNSUP_BY_DEV) {
			warnx("TEST IGNORED: nvme_vuc_req_init() returned "
			    "%s (0x%x), not %s (0x%x) due to lack of VUC "
			    "support",
			    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
			    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
			    exp_err), exp_err);
			return (true);
		}
		warnx("TEST FAILED: nvme_vuc_req_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_vuc_req_init() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_fw_commit_req(nvme_ctrl_t *ctrl, nvme_fw_commit_req_t **reqp,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_fw_commit_req_init(ctrl, reqp)) {
		warnx("TEST FAILED: nvme_fw_commit_req_init() erroneously "
		    "passed despite %s", desc);
		nvme_fw_commit_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_fw_commit_req_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_fw_commit_req_init() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_format_req(nvme_ctrl_t *ctrl, nvme_format_req_t **reqp, nvme_err_t exp_err,
    const char *desc)
{
	if (nvme_format_req_init(ctrl, reqp)) {
		warnx("TEST FAILED: nvme_format_req_init() erroneously "
		    "passed despite %s", desc);
		nvme_format_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_format_req_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_format_req_init() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_id_req_t *id_req;
	nvme_log_req_t *log_req;
	nvme_get_feat_req_t *feat_req;
	nvme_vuc_req_t *vuc_req;
	nvme_fw_commit_req_t *fw_commit_req;
	nvme_format_req_t *format_req;

	libnvme_test_init(&nvme, &ctrl);

	if (!bad_id_req(ctrl, NVME_CSI_NVM, NVME_IDENTIFY_CTRL, NULL,
	    NVME_ERR_BAD_PTR, "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_id_req(ctrl, 0xff, NVME_IDENTIFY_CTRL, &id_req,
	    NVME_ERR_IDENTIFY_UNKNOWN, "unknown identify (bad csi)")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_id_req(ctrl, NVME_CSI_NVM, UINT32_MAX, &id_req,
	    NVME_ERR_IDENTIFY_UNKNOWN, "unknown identify (bad cns)")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req(ctrl, NULL, NVME_ERR_BAD_PTR, "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req_by_name(ctrl, "health", 0, NULL, NVME_ERR_BAD_PTR,
	    "bad output pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req_by_name(ctrl, NULL, 0, &log_req, NVME_ERR_BAD_PTR,
	    "bad name pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req_by_name(ctrl, NULL, 0x12345678, &log_req,
	    NVME_ERR_BAD_PTR, "bad flags")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req_by_name(ctrl, "elbereth", 0, &log_req,
	    NVME_ERR_LOG_NAME_UNKNOWN, "unknown log")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req(ctrl, NULL, NVME_ERR_BAD_PTR,
	    "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req_by_name(ctrl, "health", 0, NULL, NVME_ERR_BAD_PTR,
	    "bad output pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req_by_name(ctrl, NULL, 0, &feat_req,
	    NVME_ERR_BAD_PTR, "bad name pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req_by_name(ctrl, NULL, 0x87654321, &feat_req,
	    NVME_ERR_BAD_PTR, "bad flags")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req_by_name(ctrl, "elbereth", 0, &feat_req,
	    NVME_ERR_FEAT_NAME_UNKNOWN, "unknown feat")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_vuc_req(ctrl, NULL, NVME_ERR_BAD_PTR, "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_fw_commit_req(ctrl, NULL, NVME_ERR_BAD_PTR,
	    "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_format_req(ctrl, NULL, NVME_ERR_BAD_PTR,
	    "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	umem_setmtbf(1);
	if (!bad_id_req(ctrl, NVME_CSI_NVM, NVME_IDENTIFY_CTRL, &id_req,
	    NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req(ctrl, &log_req, NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_log_req_by_name(ctrl, "health", 0, &log_req, NVME_ERR_NO_MEM,
	    "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req(ctrl, &feat_req, NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_get_feat_req_by_name(ctrl, "health", 0, &feat_req,
	    NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_vuc_req(ctrl, &vuc_req, NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_fw_commit_req(ctrl, &fw_commit_req, NVME_ERR_NO_MEM,
	    "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_format_req(ctrl, &format_req, NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	umem_setmtbf(0);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);
	return (ret);
}
