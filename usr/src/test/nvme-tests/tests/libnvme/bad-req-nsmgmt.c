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
 * Variant of the bad-req.c tests that covers items that require namespace
 * management support.
 */

#include <err.h>
#include <umem.h>

#include "libnvme_test_common.h"

static bool
bad_ns_attach_req(nvme_ctrl_t *ctrl, nvme_ns_attach_req_t **reqp, uint32_t sel,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_ns_attach_req_init_by_sel(ctrl, sel, reqp)) {
		warnx("TEST FAILED: nvme_ns_attach_req_init_by_sel() "
		    "erroneously passed despite %s", desc);
		nvme_ns_attach_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_ns_attach_req_init_by_sel() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ns_attach_req_init_by_sel() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_ns_create_req(nvme_ctrl_t *ctrl, nvme_ns_create_req_t **reqp, uint32_t csi,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_ns_create_req_init_by_csi(ctrl, csi, reqp)) {
		warnx("TEST FAILED: nvme_ns_create_req_init_by_csi() "
		    "erroneously passed despite %s", desc);
		nvme_ns_create_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_ns_create_req_init_by_csi() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ns_create_req_init_by_csi() "
		    "correctly failed for %s\n", desc);
		return (true);
	}
}

static bool
bad_ns_delete_req(nvme_ctrl_t *ctrl, nvme_ns_delete_req_t **reqp,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_ns_delete_req_init(ctrl, reqp)) {
		warnx("TEST FAILED: nvme_ns_delete_req_init() "
		    "erroneously passed despite %s", desc);
		nvme_ns_delete_req_fini(*reqp);
		return (false);
	} else if (nvme_ctrl_err(ctrl) != exp_err) {
		warnx("TEST FAILED: nvme_ns_delete_req_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_ctrl_errtostr(ctrl, nvme_ctrl_err(ctrl)),
		    nvme_ctrl_err(ctrl), nvme_ctrl_errtostr(ctrl,
		    exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ns_delete_req_init() "
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
	nvme_ns_attach_req_t *ns_attach_req;
	nvme_ns_create_req_t *ns_create_req;
	nvme_ns_delete_req_t *ns_delete_req;

	libnvme_test_init(&nvme, &ctrl);

	if (!bad_ns_attach_req(ctrl, &ns_attach_req, UINT32_MAX,
	    NVME_ERR_NS_ATTACH_BAD_SEL, "invalid sel value")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_ns_attach_req(ctrl, NULL, NVME_NS_ATTACH_CTRL_ATTACH,
	    NVME_ERR_BAD_PTR, "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_ns_create_req(ctrl, &ns_create_req, UINT32_MAX,
	    NVME_ERR_NS_CREATE_BAD_CSI, "invalid csi value")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_ns_create_req(ctrl, NULL, NVME_CSI_NVM, NVME_ERR_BAD_PTR,
	    "invalid req pointer")) {
		ret = EXIT_FAILURE;
	}

	umem_setmtbf(1);

	if (!bad_ns_attach_req(ctrl, &ns_attach_req, NVME_NS_ATTACH_CTRL_ATTACH,
	    NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_ns_create_req(ctrl, &ns_create_req, NVME_CSI_NVM,
	    NVME_ERR_NO_MEM, "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!bad_ns_delete_req(ctrl, &ns_delete_req, NVME_ERR_NO_MEM,
	    "no memory")) {
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
