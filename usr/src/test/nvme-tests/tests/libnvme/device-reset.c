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
 * Reset an NVMe device back to a simple state.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include "libnvme_test_common.h"

typedef enum {
	RESET_ACT_EMPTY = 0,
	RESET_ACT_DEFAULT
} reset_action_t;

static bool
device_reset_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc,
    void *arg)
{
	const uint32_t nsid = nvme_ns_disc_nsid(disc);

	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ALL, nsid,
	    UINT32_MAX)) {
		exit(EXIT_FAILURE);
	}

	return (true);
}

/*
 * Create a single namespace with all of the device capacity. We default to the
 * best 4 KiB namespace format we can that has no metadata. If that doesn't
 * exist, use the remaining best that we can support.
 */
static void
device_reset_create(nvme_ctrl_t *ctrl)
{
	nvme_ctrl_info_t *info;
	uint32_t lba, nsid;
	uint64_t size;
	nvme_uint128_t cap;

	if (!nvme_ctrl_info_snap(ctrl, &info)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to get info snapshot");
	}

	if (!libnvme_test_lbaf(info, NVME_TEST_LBA_SIZE, &lba)) {
		errx(EXIT_FAILURE, "failed to find 4K LBA format, cannot "
		    "continue");
	}

	if (!nvme_ctrl_info_cap(info, &cap)) {
		libnvme_test_ctrl_info_fatal(info, "failed to get device "
		    "capacity");
	}

	/*
	 * We need to convert the capacity of the device to a number of logical
	 * blocks. The device's capacity is phrased in bytes. For now, just
	 * divide the capacity in bytes by the LBA size. If we encounter a
	 * device with more than a uint64_t worth of bytes in it, for now punt.
	 */
	if (cap.hi != 0) {
		errx(EXIT_FAILURE, "encountered device with > uint64_t "
		    "capacity, this program needs to be updated to deal with "
		    "that");
	}
	size = cap.lo / NVME_TEST_LBA_SIZE;

	if (!libnvme_test_ns_create(ctrl, size, lba, &nsid, NULL)) {
		exit(EXIT_FAILURE);
	}

	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ACTIVE, nsid,
	    UINT32_MAX)) {
		exit(EXIT_FAILURE);
	}

	nvme_ctrl_info_free(info);
}

int
main(void)
{
	nvme_t *nvme;
	nvme_ctrl_t *ctrl;

	libnvme_test_init(&nvme, &ctrl);
	if (!nvme_ctrl_lock(ctrl, NVME_LOCK_L_WRITE, NVME_LOCK_F_DONT_BLOCK)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to obtain write lock");
	}

	if (!nvme_ns_discover(ctrl, NVME_NS_DISC_F_ALL,
	    device_reset_cb, NULL)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to iterate namespaces");
	}

	device_reset_create(ctrl);

	nvme_ctrl_unlock(ctrl);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	return (EXIT_SUCCESS);
}
