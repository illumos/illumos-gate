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
 * Basic test to verify that we can run a namespace out of capacity. We do this
 * in two ways:
 *
 * 1) A single namespace creation that uses all of the device's capacity.
 * 2) Creating a second namespace where the first has already used up
 *    everything.
 *
 * This test starts from the device-empty profile.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include "libnvme_test_common.h"

int
main(void)
{
	int ret = EXIT_SUCCESS;
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;
	nvme_ctrl_info_t *info;
	uint32_t lbaf;
	nvme_uint128_t cap;
	uint64_t size;
	nvme_err_t err;

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

	if (!nvme_ctrl_info_cap(info, &cap)) {
		libnvme_test_ctrl_info_fatal(info, "failed to get device "
		    "capacity");
	}

	if (cap.hi != 0) {
		errx(EXIT_FAILURE, "encountered device with > uint64_t "
		    "capacity, this program needs to be updated to deal with "
		    "that");
	}

	size = cap.lo / NVME_TEST_LBA_SIZE;
	size += NVME_TEST_NS_SIZE / NVME_TEST_LBA_SIZE;

	if (!libnvme_test_ns_create(ctrl, size, lbaf, NULL, &err)) {
		warnx("TEST FAILED: failed to initialize create namespace for "
		    "namespace larger than the device's capacity (0x%"
		    PRIx64 ")", size);
		ret = EXIT_FAILURE;
	} else if (!libnvme_test_ctrl_err(ctrl, NVME_CQE_SCT_SPECIFIC,
	    NVME_CQE_SC_SPC_NS_INSUF_CAP, "namespace exceeds device "
	    "capacity")) {
		ret = EXIT_FAILURE;
	}

	size = cap.lo / NVME_TEST_LBA_SIZE;
	size -= NVME_TEST_NS_SIZE / NVME_TEST_LBA_SIZE;

	if (!libnvme_test_ns_create(ctrl, size, lbaf, NULL, NULL)) {
		exit(EXIT_FAILURE);
	}

	size = 2 * (NVME_TEST_NS_SIZE / NVME_TEST_LBA_SIZE);
	if (!libnvme_test_ns_create(ctrl, size, lbaf, NULL, &err)) {
		warnx("TEST FAILED: failed to initialize create namespace "
		    "request for namespace with insufficient device capacity "
		    "(0x%" PRIx64 ")", size);
		ret = EXIT_FAILURE;
	} else if (!libnvme_test_ctrl_err(ctrl, NVME_CQE_SCT_SPECIFIC,
	    NVME_CQE_SC_SPC_NS_INSUF_CAP, "insufficient device capacity")) {
		ret = EXIT_FAILURE;
	}

	nvme_ctrl_info_free(info);
	nvme_ctrl_unlock(ctrl);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
