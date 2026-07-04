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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Go through and test the basics of our set feature functionality. This is
 * designed to be run against a device that supports the requisite OCP features:
 *
 * - Error Injection (0xc0)
 * - PLP Health Check Interval (c6h)
 *
 * In this test we make sure that we can do:
 *
 * - Verify that we can't set a feature without the controller lock
 * - Verify we aren't allowed to set a standard feature
 * - A basic get feature / set feature loop without data
 * - Test the missing fields and basics of the libnvme ocp error injection
 *   features which wraps set feature. This also gives us a basic set feature
 *   with data tests.
 */

#include <err.h>
#include <sys/sysmacros.h>
#include <sys/nvme/ocp.h>

#include "libnvme_test_common.h"

static void
set_feats_supported(nvme_ctrl_t *ctrl)
{
	nvme_set_feat_req_t *req;
	const char *feats[] = { "ocp/plphealth", "ocp/errinj" };

	for (size_t i = 0; i < ARRAY_SIZE(feats); i++) {
		if (!nvme_set_feat_req_init_by_name(ctrl, feats[i], 0, NULL,
		    &req)) {
			libnvme_test_ctrl_fatal(ctrl, "missing required "
			    "feature %s: test cannot proceed", feats[i]);
		}

		nvme_set_feat_req_fini(req);
	}
}

static bool
set_feat_fail(nvme_ctrl_t *ctrl, const char *feat, const char *desc,
    uint32_t cdw11, nvme_err_t exp)
{
	nvme_err_t err;
	bool ret = false;
	nvme_set_feat_req_t *set = NULL;

	if (!nvme_set_feat_req_init_by_name(ctrl, feat, 0, NULL, &set)) {
		libnvme_test_ctrl_warn(ctrl, "set feature %s: failed to "
		    "create %s request", desc, feat);
		goto done;
	}

	if (!nvme_set_feat_req_set_cdw11(set, cdw11)) {
		libnvme_test_ctrl_warn(ctrl, "set feature %s: failed to set "
		    "%s cdw11 value", desc, feat);
		goto done;
	}

	if (nvme_set_feat_req_exec(set)) {
		warnx("TEST FAILED: set feature %s unexpectedly passed: "
		    "expected failure", desc);
		goto done;
	}

	err = nvme_ctrl_err(ctrl);
	if (err != exp) {
		warnx("TEST FAILED: expected set feature %s to fail with %s "
		    "(0x%x), but found %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, exp), exp,
		    nvme_ctrl_errtostr(ctrl, err), err);
		goto done;
	}

	ret = true;
	(void) printf("TEST PASSED: set feature %s correctly failed with "
	    "%s\n", desc, nvme_ctrl_errtostr(ctrl, exp));
done:
	nvme_set_feat_req_fini(set);
	return (ret);
}

static bool
get_plp(nvme_ctrl_t *ctrl, nvme_get_feat_req_t *get, uint32_t *valp)
{
	if (!nvme_get_feat_req_exec(get)) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute PLP get "
		    "feature request");
		return (false);
	}

	if (!nvme_get_feat_req_get_cdw0(get, valp)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get PLP cdw0 value");
		return (false);
	}

	*valp &= UINT16_MAX;
	return (true);
}

static bool
set_plp(nvme_ctrl_t *ctrl, nvme_set_feat_req_t *set, uint16_t val)
{
	/*
	 * The PLP value is actually in the upper 16 bits when one performs a
	 * GET FEATURE.
	 */
	if (!nvme_set_feat_req_set_cdw11(set, val << 16)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set PLP cdw11 value");
		return (false);
	}

	if (!nvme_set_feat_req_exec(set)) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute PLP set "
		    "feature request");
		return (false);
	}

	return (true);
}

/*
 * Using the PLP Health Interval Checking, perform round-trip getting and
 * setting of the feature and verify our values hold.
 */
static bool
roundtrip_plp(nvme_ctrl_t *ctrl)
{
	nvme_get_feat_req_t *get = NULL;
	nvme_set_feat_req_t *set = NULL;
	bool ret = true;
	uint32_t cdw0, new;

	if (!nvme_get_feat_req_init_by_name(ctrl, "ocp/plphealth", 0, NULL,
	    &get)) {
		libnvme_test_ctrl_warn(ctrl, "failed to create PLP get feature "
		    "request");
		ret = false;
		goto done;
	}

	if (!nvme_set_feat_req_init_by_name(ctrl, "ocp/plphealth", 0, NULL,
	    &set)) {
		libnvme_test_ctrl_warn(ctrl, "failed to create PLP set feature "
		    "request");
		ret = false;
		goto done;
	}

	if (!get_plp(ctrl, get, &cdw0)) {
		ret = false;
		goto done;
	}

	if (!set_plp(ctrl, set, cdw0 + 1)) {
		ret = false;
		goto done;
	}

	if (!get_plp(ctrl, get, &new)) {
		ret = false;
		goto done;
	}

	if (cdw0 + 1 != new) {
		warnx("setting ocp/plphealth didn't work, originally had 0x%x, "
		    "expected 0x%x, found 0x%x", cdw0, cdw0 + 1, new);
		ret = false;
	}

	if (!set_plp(ctrl, set, cdw0)) {
		ret = false;
		goto done;
	}

	if (!get_plp(ctrl, get, &new)) {
		ret = false;
		goto done;
	}

	if (cdw0 != new) {
		warnx("TEST FAILED: failed to restore ocp/plphealth back to "
		    "0x%x: found 0x%x", cdw0, new);
		ret = false;
	}

	if (ret) {
		(void) printf("TEST PASSED: ocp/plphealth set feature round "
		    "trip\n");
	}

done:
	nvme_get_feat_req_fini(get);
	nvme_set_feat_req_fini(set);
	return (ret);
}

static bool
errinj_req_fail(nvme_ctrl_t *ctrl, nvme_ocp_errinj_req_t *req, const char *desc,
    nvme_err_t exp)
{
	const char *exps = nvme_ctrl_errtostr(ctrl, exp);
	nvme_err_t err;

	if (nvme_ocp_errinj_req_exec(req)) {
		warnx("TEST FAILED: %s unexpectedly succeeded, but expected %s",
		    desc, exps);
		return (false);
	}

	err = nvme_ctrl_err(ctrl);
	if (err != exp) {
		warnx("TEST FAILED: expected %s to fail with %s (0x%x), but "
		    "found %s (0x%x)", desc, nvme_ctrl_errtostr(ctrl, exp), exp,
		    nvme_ctrl_errtostr(ctrl, err), err);
		return (false);
	}


	(void) printf("TEST PASSED: %s correctly failed with %s\n", desc, exps);
	return (true);
}

static bool
errinj_set_fail(nvme_ctrl_t *ctrl, const char *desc, nvme_err_t exp, bool res)
{
	if (res) {
		warnx("TEST FAILED: setting error injection field %s to bad "
		    "value incorrectly worked: expected %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, exp), exp);
		return (false);
	}

	nvme_err_t err = nvme_ctrl_err(ctrl);
	if (err != exp) {
		warnx("TEST FAILED: expected bad error injection field %s "
		    "value to fail with %s (0x%x): found %s (0x%x)", desc,
		    nvme_ctrl_errtostr(ctrl, exp), exp,
		    nvme_ctrl_errtostr(ctrl, err), err);
		return (false);
	}

	(void) printf("TEST PASSED: bad error injection field %s value "
	    "correctly failed with %s\n", desc, nvme_ctrl_errtostr(ctrl, exp));
	return (true);
}

/*
 * Go through and verify that various different errors are caught:
 *
 *  - Missing fields
 *  - Invalid values for type, number of reads, delay
 *  - Delay value unsupported
 */
static bool
errinj_errors(nvme_ctrl_t *ctrl)
{
	bool ret = true;
	nvme_ocp_errinj_req_t *req = NULL;

	if (!nvme_ocp_errinj_req_init(ctrl, &req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to create error injection "
		    "request");
		ret = false;
		goto done;
	}

	if (!errinj_req_fail(ctrl, req, "error injection with missing fields",
	    NVME_ERR_OCP_ERRINJ_REQ_MISSING_FIELDS)) {
		ret = false;
	}

	if (!errinj_set_fail(ctrl, "type", NVME_ERR_OCP_ERRINJ_TYPE_RANGE,
	    nvme_ocp_errinj_req_set_type(req, 0xb22b7777)))
		ret = false;

	if (!errinj_set_fail(ctrl, "nrtde", NVME_ERR_OCP_ERRINJ_NRTDE_RANGE,
	    nvme_ocp_errinj_req_set_nrtde(req, 0x12345)))
		ret = false;

	/*
	 * Set us up for an unusable error on exec when we set an ld value with
	 * a different type.
	 */
	if (!nvme_ocp_errinj_req_set_type(req, OCP_ERRINJ_T_CPU_HANG) ||
	    !nvme_ocp_errinj_req_set_ld(req, 0x23)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set fields for error "
		    "injection duration not settable");
		ret = false;
	} else if (!errinj_req_fail(ctrl, req, "error injection duration not "
	    "settable", NVME_ERR_OCP_ERRINJ_LD_UNUSE)) {
		ret = false;
	}

done:
	nvme_ocp_errinj_req_fini(req);
	return (ret);
}

/*
 * Test error injection by creating something with a high rate of reads required
 * that we shouldn't trigger. Verify we can see it with a GET FEATURE. Then
 * clear it. Verify it's not there in a GET.
 */
static bool
roundtrip_errinj(nvme_ctrl_t *ctrl)
{
	bool ret = true;
	nvme_ocp_errinj_req_t *req = NULL;
	nvme_get_feat_req_t *get = NULL;
	nvme_feat_disc_t *disc = NULL;
	void *buf = NULL;
	uint64_t len;
	uint32_t cdw0;

	if (!nvme_get_feat_req_init_by_name(ctrl, "ocp/errinj", 0, &disc,
	    &get)) {
		libnvme_test_ctrl_warn(ctrl, "failed to create error injection "
		    "get feature request");
		ret = false;
		goto done;
	}

	len = nvme_feat_disc_data_size(disc);
	buf = calloc(len, sizeof (uint8_t));
	if (buf == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILED: failed to alloc %"
		    PRIu64 "bytes for error injection buffer", len);
	}
	if (!nvme_get_feat_req_set_output(get, buf, len)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set get feature output "
		    "buffer");
		ret = false;
		goto done;
	}

	if (!nvme_ocp_errinj_req_init(ctrl, &req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to create error injection "
		    "request");
		ret = false;
		goto done;
	}

	if (!nvme_ocp_errinj_req_set_type(req, OCP_ERRINJ_T_CPU_HANG) ||
	    !nvme_ocp_errinj_req_set_nrtde(req, 0x7777)) {
		libnvme_test_ctrl_warn(ctrl, "failed to set basic error "
		    "injection fields");
		ret = false;
		goto done;
	}

	if (!nvme_ocp_errinj_req_exec(req)) {
		libnvme_test_ctrl_warn(ctrl, "failed to execute error "
		    "injection request");
		ret = false;
		goto done;
	}

	if (!nvme_get_feat_req_exec(get) || !nvme_get_feat_req_get_cdw0(get,
	    &cdw0)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get error injection "
		    "request and data");
		ret = false;
		goto done;
	}

	if (cdw0 != 1) {
		warnx("TEST FAILED: error injection pending count is 0x%x, but "
		    "expected it to be 1", cdw0);
		ret = false;
	}

	const volatile ocp_vuf_errinj_t *err = buf;
	if (err[0].oei_flags != (OCP_ERRINJ_F_ENABLE | OCP_ERRINJ_F_SINGLE)) {
		warnx("TEST FAILED: found unexpected error flags 0x%x, "
		    "expected 0x%x", err[0].oei_flags, OCP_ERRINJ_F_ENABLE |
		    OCP_ERRINJ_F_SINGLE);
		ret = false;
	}

	if (err[0].oei_type != OCP_ERRINJ_T_CPU_HANG) {
		warnx("TEST FAILED: found unexpected error type 0x%x, expected "
		    "0x%x", err[0].oei_type, OCP_ERRINJ_T_CPU_HANG);
		ret = false;
	}

	/*
	 * Assume that there is some number of reads potentially going on in the
	 * background, but hopefully not too much.
	 */
	if (err[0].oei_nrtde < 0x6666) {
		warnx("TEST FAILED: found unexpected nrtde value: 0x%x",
		    err[0].oei_nrtde);
		ret = false;
	}

	if (!nvme_ocp_errinj_clear(ctrl)) {
		libnvme_test_ctrl_warn(ctrl, "failed to clear error injection "
		    "request");
		ret = false;
		goto done;
	}

	if (!nvme_get_feat_req_exec(get) || !nvme_get_feat_req_get_cdw0(get,
	    &cdw0)) {
		libnvme_test_ctrl_warn(ctrl, "failed to get error injection "
		    "request and data");
		ret = false;
		goto done;
	}

	if (cdw0 != 0) {
		warnx("TEST FAILED: error injection pending count is 0x%x "
		    "after clear, but expected 0", cdw0);
		ret = false;
	}

	if (err[0].oei_flags != 0) {
		warnx("TEST FAILED: found unexpected error flags 0x%x after "
		    "clear, but expected 0", err[0].oei_flags);
		ret = false;
	}

	if (err[0].oei_type != 0) {
		warnx("TEST FAILED: found unexpected error type 0x%x after "
		    "clear, but expected 0", err[0].oei_type);
		ret = false;
	}

	if (err[0].oei_nrtde != 0) {
		warnx("TEST FAILED: found unexpected nrtde 0x%x after "
		    "clear, but expected 0", err[0].oei_nrtde);
		ret = false;
	}

	if (ret) {
		(void) printf("TEST PASSED: error injection roundtrip\n");
	}

done:
	nvme_ocp_errinj_req_fini(req);
	free(buf);
	nvme_feat_disc_free(disc);
	nvme_get_feat_req_fini(get);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	nvme_t *nvme;
	nvme_ctrl_t *ctrl;

	libnvme_test_init(&nvme, &ctrl);
	set_feats_supported(ctrl);

	/*
	 * Verify that if we try to set a feature without a lock this fails.
	 */
	if (!set_feat_fail(ctrl, "ocp/plphealth", "without control lock", 0x23,
	    NVME_ERR_NEED_CTRL_WRLOCK)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Setting a standard feature should fail.
	 */
	if (!set_feat_fail(ctrl, "queues", "standard feature", 0x7777,
	    NVME_ERR_NEED_CTRL_WRLOCK)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Take a controller lock for all the remaining tests.
	 */
	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, 0)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to take a write lock: "
		    "cannot continue");
	}

	if (!roundtrip_plp(ctrl))
		ret = EXIT_FAILURE;

	if (!errinj_errors(ctrl))
		ret = EXIT_FAILURE;

	if (!roundtrip_errinj(ctrl))
		ret = EXIT_FAILURE;

	nvme_ctrl_unlock(ctrl);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests exited successfully\n");
	}

	return (ret);
}
