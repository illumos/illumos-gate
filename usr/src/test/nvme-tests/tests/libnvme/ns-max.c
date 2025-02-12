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
 * This is a basic test that goes through and creates as many namespaces as
 * possible, each sized at 1 GiB. It ensures that we can create them all, attach
 * them to the controller, and with blkdev. We verify the basic properties of
 * the namespaces that we get back.
 *
 * This test expects to start from the device-empty profile.
 */

#include <err.h>
#include <stdlib.h>
#include "libnvme_test_common.h"

typedef struct {
	uint32_t nc_lbaf;
	uint32_t nc_nns;
	bool nc_pass;
} ns_cb_t;

static int
nsid_comp(const void *left, const void *right)
{
	uint32_t l = *(const uint32_t *)left;
	uint32_t r = *(const uint32_t *)right;

	if (l > r)
		return (1);
	if (l < r)
		return (-1);
	return (0);
}

static bool
ns_max_fail_ns(nvme_ctrl_t *ctrl, uint32_t lbaf)
{
	nvme_err_t err;
	const uint64_t size = NVME_TEST_NS_SIZE / NVME_TEST_LBA_SIZE;

	if (!libnvme_test_ns_create(ctrl, size, lbaf, NULL, &err)) {
		warnx("TEST FAILED: failed to initialize namespace create "
		    "request when out of namesapces");
		return (false);
	} else if (!libnvme_test_ctrl_err(ctrl, NVME_CQE_SCT_SPECIFIC,
	    NVME_CQE_SC_SPC_NS_NO_ID, "running out of namespace IDs")) {
		return (false);
	}

	return (true);
}

static bool
ns_max_alloc_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc,
    void *arg)
{
	ns_cb_t *cb = arg;
	const uint32_t nsid = nvme_ns_disc_nsid(disc);

	cb->nc_nns++;
	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ACTIVE, nsid,
	    cb->nc_lbaf)) {
		cb->nc_pass = false;
	}
	return (true);
}

static bool
ns_max_active_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc,
    void *arg)
{
	ns_cb_t *cb = arg;
	const uint32_t nsid = nvme_ns_disc_nsid(disc);

	cb->nc_nns++;
	if (nvme_ns_disc_level(disc) != NVME_NS_DISC_F_NOT_IGNORED) {
		warnx("TEST FAILED: encountered unusable namespace %u", nsid);
		cb->nc_pass = false;
		return (true);
	}

	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_BLKDEV, nsid,
	    cb->nc_lbaf)) {
		cb->nc_pass = false;
	}

	return (true);
}

static bool
ns_max_blkdev_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc,
    void *arg)
{
	ns_cb_t *cb = arg;
	const uint32_t nsid = nvme_ns_disc_nsid(disc);

	cb->nc_nns++;
	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ALL, nsid,
	    cb->nc_lbaf)) {
		cb->nc_pass = false;
	}

	return (true);
}

static bool
ns_max_cb_check(const ns_cb_t *cb, const char *desc, uint32_t nns)
{
	bool ret = true;

	if (cb->nc_nns != nns) {
		ret = false;
		warnx("TEST FAILED: only iterated over %u/%u namespaces "
		    "during %s pass", cb->nc_nns, nns, desc);
	}

	if (!cb->nc_pass) {
		ret = false;
		warnx("TEST FAILED: %s iteration did not work on all "
		    "devices", desc);
	}

	if (ret) {
		(void) printf("TEST PASSED: successfully processed all %u %s "
		    "namespaces\n", nns, desc);
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	uint32_t nns, lbaf, *nsids;
	ns_cb_t cb;

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to obtain write lock");
	}

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get info snapshot");
	}

	if (!libnvme_test_lbaf(info, NVME_TEST_LBA_SIZE, &lbaf)) {
		errx(EXIT_FAILURE, "failed to find 4K LBA format, cannot "
		    "continue");
	}

	nns = nvme_ctrl_info_nns(info);
	nsids = calloc(nns, sizeof (uint32_t));
	if (nsids == NULL) {
		errx(EXIT_FAILURE, "failed to allocate space to store %u NSIDs",
		    nns);
	}

	for (uint32_t i = 0; i < nns; i++) {
		const uint64_t size = NVME_TEST_NS_SIZE /
		    NVME_TEST_LBA_SIZE;
		if (!libnvme_test_ns_create(ctrl, size, lbaf,
		    &nsids[i], NULL)) {
			errx(EXIT_FAILURE, "failed to create namespace %u", i);
		}
		if (((i + 1) % 10) == 0) {
			(void) printf("Created %u/%u namespaces\n", i + 1, nns);
		}
	}
	(void) printf("TEST PASSED: successfully created all namespaces (%u)\n",
	    nns);

	/*
	 * Sort all of the IDs. They should be in the range [1, nns]. They
	 * should be all off by one from the array index.
	 */
	bool valid = true;
	qsort(nsids, nns, sizeof (uint32_t), nsid_comp);
	for (uint32_t i = 0; i < nns; i++) {
		if (nsids[i] != i + 1) {
			warnx("TEST FAILED: returned namespace ID %u is not %u",
			    nsids[i], i + 1);
			valid = false;
		}
	}
	if (valid) {
		(void) printf("TEST PASSED: all namespaces have unique IDs\n");
	}

	/*
	 * At this point creating one more namespace should fail with an error.
	 */
	if (!ns_max_fail_ns(ctrl, lbaf))
		ret = EXIT_FAILURE;

	/*
	 * Now go through and attach everything to the point that it exists with
	 * blkdev. We do this in a few passes to make sure that properly refer
	 * to it all.
	 */
	cb.nc_lbaf = lbaf;
	cb.nc_nns = 0;
	cb.nc_pass = true;
	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL, ns_max_alloc_cb, &cb)) {
		libnvme_test_ctrl_warn(ctrl, "failed to iterate allocated "
		    "namespaces");
		ret = EXIT_FAILURE;
	}

	if (!ns_max_cb_check(&cb, "allocated", nns))
		ret = EXIT_FAILURE;

	cb.nc_nns = 0;
	cb.nc_pass = true;
	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL, ns_max_active_cb,
	    &cb)) {
		libnvme_test_ctrl_warn(ctrl, "failed to iterate active "
		    "namespaces");
		ret = EXIT_FAILURE;
	}

	if (!ns_max_cb_check(&cb, "active", nns))
		ret = EXIT_FAILURE;

	cb.nc_nns = 0;
	cb.nc_pass = true;
	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL, ns_max_blkdev_cb,
	    &cb)) {
		libnvme_test_ctrl_warn(ctrl, "failed to iterate blkdev "
		    "namespaces");
		ret = EXIT_FAILURE;
	}

	if (!ns_max_cb_check(&cb, "blkdev", nns))
		ret = EXIT_FAILURE;

	free(nsids);
	nvme_ctrl_info_free(info);
	nvme_ctrl_unlock(ctrl);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
