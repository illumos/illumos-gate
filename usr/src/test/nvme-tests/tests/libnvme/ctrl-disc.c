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
 * Test controller discovery. Because we've been given a controller, we expect
 * to be able to find a controller with the same devi while performing
 * controller discovery. Its minor should point to the same devi that the normal
 * discovery and controller do.
 */

#include <err.h>
#include <string.h>
#include <umem.h>
#include <sys/stat.h>

#include "libnvme_test_common.h"

static bool
ctrl_disc_count_cb(nvme_t *nvme, const nvme_ctrl_disc_t *disc, void *arg)
{
	uint32_t *valp = arg;
	*valp = *valp + 1;
	return (true);
}

static bool
ctrl_check_disc(const nvme_ctrl_disc_t *disc)
{
	bool ret = true;
	di_node_t ctrl_devi, minor_devi;
	di_minor_t minor;
	const char *mname;

	ctrl_devi = nvme_ctrl_disc_devi(disc);
	minor = nvme_ctrl_disc_minor(disc);
	minor_devi = di_minor_devinfo(minor);
	mname = di_minor_name(minor);

	if (di_minor_spectype(minor) != S_IFCHR) {
		warnx("TEST FAILED: %s minor is not a character device, found "
		    "0x%x\n", mname, di_minor_spectype(minor));
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: minor is a character device\n",
		    mname);
	}

	if (strcmp(di_minor_nodetype(minor), DDI_NT_NVME_NEXUS) != 0) {
		warnx("TEST FAILED: %s minor has wrong node type %s, expected "
		    "%s", mname, di_minor_nodetype(minor), DDI_NT_NVME_NEXUS);
	} else {
		(void) printf("TEST PASSED: %s minor has correct node types\n",
		    mname);
	}

	if (minor_devi != ctrl_devi) {
		warnx("TEST FAILED: %s minor devi does not match the "
		    "controller devi", mname);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s minor devi matches its "
		    "controller\n", mname);
	}

	return (ret);
}

static bool
ctrl_match(nvme_t *nvme, nvme_ctrl_t *targ)
{
	bool ret = true, match = false;
	nvme_ctrl_iter_t *iter = NULL;
	const nvme_ctrl_disc_t *disc;
	nvme_iter_t iret;
	di_node_t targ_di;

	if (!nvme_ctrl_devi(targ, &targ_di)) {
		libnvme_test_ctrl_warn(targ, "failed to obtain di_node_t from "
		    "controller");
		return (false);
	}

	if (!nvme_ctrl_discover_init(nvme, &iter)) {
		libnvme_test_hdl_warn(nvme, "failed to initialize controller "
		    "discovery");
		return (false);
	}

	while ((iret = nvme_ctrl_discover_step(iter, &disc)) ==
	    NVME_ITER_VALID) {
		if (!ctrl_check_disc(disc)) {
			ret = false;
		}

		if (nvme_ctrl_disc_devi(disc) == targ_di) {
			match = true;
		}
	}

	if (iret != NVME_ITER_DONE) {
		libnvme_test_hdl_warn(nvme, "failed to iterate controllers");
		ret = false;
	}

	if (!match) {
		warnx("TEST FAILED: failed to find matching controller");
		ret = false;
	} else {
		(void) printf("TEST PASSED: found matching controller in "
		    "discovery for device %s\n", getenv(NVME_TEST_DEV_ENVVAR));
	}

	nvme_ctrl_discover_fini(iter);
	return (ret);
}

static bool
ctrl_disc_nop_cb(nvme_t *nvme, const nvme_ctrl_disc_t *disc, void *arg)
{
	return (true);
}

static bool
ctrl_disc_bad_disc_init(nvme_t *nvme, nvme_ctrl_iter_t **iterp,
    nvme_err_t exp_err, const char *desc)
{
	if (nvme_ctrl_discover_init(nvme, iterp)) {
		warnx("TEST FAILED: nvme_ctrl_discover_init() erroneously "
		    "passed despite %s\n", desc);
		return (false);
	} else if (nvme_err(nvme) != exp_err) {
		warnx("TEST FAILED: nvme_ctrl_discover_init() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_errtostr(nvme, nvme_err(nvme)), nvme_err(nvme),
		    nvme_errtostr(nvme, exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ctrl_discover_init() failed "
		    "correctly for %s\n", desc);
		return (true);
	}
}

static bool
ctrl_disc_bad_disc(nvme_t *nvme, nvme_ctrl_disc_f func, nvme_err_t exp_err,
    const char *desc)
{
	if (nvme_ctrl_discover(nvme, func, NULL)) {
		warnx("TEST FAILED: nvme_ctrl_discover() erroneously "
		    "passed despite %s\n", desc);
		return (false);
	} else if (nvme_err(nvme) != exp_err) {
		warnx("TEST FAILED: nvme_ctrl_discover() returned "
		    "wrong error %s (0x%x), not %s (0x%x)",
		    nvme_errtostr(nvme, nvme_err(nvme)), nvme_err(nvme),
		    nvme_errtostr(nvme, exp_err), exp_err);
		return (false);
	} else {
		(void) printf("TEST PASSED: nvme_ctrl_discover() failed "
		    "correctly for %s\n", desc);
		return (true);
	}
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	uint32_t nctrl = 0;
	nvme_ctrl_iter_t *iter;

	libnvme_test_init(&nvme, &ctrl);

	if (!nvme_ctrl_discover(nvme, ctrl_disc_count_cb, &nctrl)) {
		libnvme_test_hdl_warn(nvme, "failed to discover controllers");
		ret = EXIT_FAILURE;
	} else if (nctrl == 0) {
		warnx("TEST FAILED: discovered zero controllers somehow!");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: discovered some number of "
		    "controllers");
	}

	if (!ctrl_match(nvme, ctrl)) {
		ret = EXIT_FAILURE;
	}

	if (!ctrl_disc_bad_disc_init(nvme, NULL, NVME_ERR_BAD_PTR,
	    "invalid iter pointer")) {
		ret = EXIT_FAILURE;
	}

	if (!ctrl_disc_bad_disc(nvme, NULL, NVME_ERR_BAD_PTR,
	    "invalid function pointer")) {
		ret = EXIT_FAILURE;
	}

	umem_setmtbf(1);
	if (!ctrl_disc_bad_disc_init(nvme, &iter, NVME_ERR_NO_MEM,
	    "no memory")) {
		ret = EXIT_FAILURE;
	}

	if (!ctrl_disc_bad_disc(nvme, ctrl_disc_nop_cb, NVME_ERR_NO_MEM,
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
