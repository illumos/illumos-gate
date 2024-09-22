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
 * Test various aspects of reading the persistent event log from a device and
 * verify that we properly handle certain error conditions. In particular, we
 * want to verify the following:
 *
 * 1) Issuing a reset context while it's already reset is fine.
 * 2) Issuing a read without establish fails
 * 3) Issuing an establish context with one fails
 * 4) Otherwise basic read / establish / release works
 *
 * Because this requires device specific behavior is it not part of the default
 * non-destructive run.
 */

#include <err.h>

#include "libnvme_test_common.h"

static bool
pev_action(nvme_t *nvme, nvme_ctrl_t *ctrl, nvme_pev_log_lsp_t pev, bool exp,
    const char *desc)
{
	nvme_log_disc_t *disc;
	nvme_log_req_t *req;
	uint8_t *buf;
	size_t buflen = 512;
	bool ret = true, lret;

	if ((buf = calloc(buflen, sizeof (uint8_t))) == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to allocate "
		    "%zu bytes for internal buffer", buflen);
	}

	if (!nvme_log_req_init_by_name(ctrl, "pev", 0, &disc, &req)) {
		libnvme_test_ctrl_fatal(ctrl, "%s: failed to initialize "
		    "persistent event log request", desc);
	}

	if (!nvme_log_req_set_output(req, buf, buflen)) {
		libnvme_test_ctrl_warn(ctrl, "%s: failed to set output buffer",
		    desc);
		ret = false;
		goto done;
	}

	if (!nvme_log_req_set_lsp(req, pev)) {
		libnvme_test_ctrl_warn(ctrl, "%s: failed to set lsp to 0x%x",
		    desc, pev);
		ret = false;
		goto done;
	}

	lret = nvme_log_req_exec(req);
	if (exp && !lret) {
		libnvme_test_ctrl_warn(ctrl, "%s: log request failed, but "
		    "expected success", desc);
		ret = false;
	} else if (!exp && lret) {
		warnx("TEST FAILED: %s: log request succeeded, but expected "
		    "failure", desc);
		ret = false;
	} else if (!lret) {
		nvme_err_t err;
		uint32_t sct, sc;

		err = nvme_ctrl_err(ctrl);
		nvme_ctrl_deverr(ctrl, &sct, &sc);

		if (err != NVME_ERR_CONTROLLER) {
			warnx("TEST FAILED: %s: found controller error %s "
			    "(0x%x), but expected %s (0x%x)", desc,
			    nvme_errtostr(nvme, err), err,
			    nvme_errtostr(nvme, NVME_ERR_CONTROLLER),
			    NVME_ERR_CONTROLLER);
			ret = false;
		} else if (sct != NVME_CQE_SCT_GENERIC) {
			warnx("TEST FAILED: %s: found device sct %s (0x%x), "
			    "but expected %s (0x%x)", desc,
			    nvme_scttostr(ctrl, sct), sct,
			    nvme_scttostr(ctrl, NVME_CQE_SCT_GENERIC),
			    NVME_CQE_SCT_GENERIC);
			ret = false;
		} else if (sc != NVME_CQE_SC_GEN_CMD_SEQ_ERR) {
			warnx("TEST FAILED: %s: found device sc %s (0x%x), "
			    "but expected %s (0x%x)", desc,
			    nvme_sctostr(ctrl, NVME_CSI_NVM, sct, sc), sc,
			    nvme_sctostr(ctrl, NVME_CSI_NVM, sct,
			    NVME_CQE_SC_GEN_CMD_SEQ_ERR),
			    NVME_CQE_SC_GEN_CMD_SEQ_ERR);
			ret = false;
		}
	} else if (pev == NVME_PEV_LSP_READ ||
	    pev == NVME_PEV_LSP_EST_CTX_READ) {
		if (*buf != NVME_LOGPAGE_PEV) {
			warnx("TEST FAILED: %s: returned data does not have "
			    "correct LID in byte 0, found 0x%x, expected 0x%x",
			    desc, *buf, NVME_LOGPAGE_PEV);
			ret = false;
		}
	}

	if (ret) {
		(void) printf("TEST PASSED: %s\n", desc);
	}
done:
	nvme_log_disc_free(disc);
	nvme_log_req_fini(req);
	free(buf);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;

	libnvme_test_init(&nvme, &ctrl);
	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_REL_CTX, true,
	    "initial release context works")) {
		ret = EXIT_FAILURE;
	}

	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_REL_CTX, true,
	    "second release context works")) {
		ret = EXIT_FAILURE;
	}

	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_READ, false,
	    "read without context fails")) {
		ret = EXIT_FAILURE;
	}

	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_EST_CTX_READ, true,
	    "establish context and read works")) {
		ret = EXIT_FAILURE;
	}

	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_EST_CTX_READ, false,
	    "second establish context and read fails")) {
		ret = EXIT_FAILURE;
	}

	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_READ, true,
	    "read with context works")) {
		ret = EXIT_FAILURE;
	}

	if (!pev_action(nvme, ctrl, NVME_PEV_LSP_REL_CTX, true,
	    "release after read works")) {
		ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
