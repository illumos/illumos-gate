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
 * Destroy all namsepaces on an NVMe device. This is used for test setup.
 */

#include <err.h>
#include "libnvme_test_common.h"

static bool
device_empty_cb(nvme_ctrl_t *ctrl, const nvme_ns_disc_t *disc,
    void *arg)
{
	const uint32_t nsid = nvme_ns_disc_nsid(disc);

	if (!libnvme_test_setup_ns(ctrl, NVME_NS_DISC_F_ALL, nsid,
	    UINT32_MAX)) {
		exit(EXIT_FAILURE);
	}

	return (true);
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
	    device_empty_cb, NULL)) {
		libnvme_test_ctrl_fatal(ctrl, "failed to iterate namespaces");
	}

	nvme_ctrl_unlock(ctrl);
	nvme_ctrl_fini(ctrl);
	nvme_fini(nvme);

	return (EXIT_SUCCESS);
}
