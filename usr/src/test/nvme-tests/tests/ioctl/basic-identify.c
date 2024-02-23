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
 * Perform basic NVMe identify tests on a device. This goes through and issues
 * an identify controller on a device and then attempts to identify each
 * namespace present. If namespace management is present, then attempt to get
 * the generic namespace information. We only attempt to get namespace
 * information via the namespace fd for ns 1.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stdbool.h>

#include "nvme_ioctl_util.h"

static void
basic_id_determine_ns_sup(const void *data, uint32_t *nnsp, bool *hasns)
{
	const nvme_identify_ctrl_t *ctrl = data;
	*nnsp = ctrl->id_nn;
	*hasns = ctrl->id_oacs.oa_nsmgmt != 0;
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	int fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_identify_t id;
	void *data;
	bool hasns;
	uint32_t nns;

	if ((data = malloc(NVME_IDENTIFY_BUFSIZE)) == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: could not initialize identify "
		    "data buffer");
	}

	(void) memset(&id, 0, sizeof (id));
	id.nid_cns = NVME_IDENTIFY_CTRL;
	id.nid_data = (uintptr_t)data;

	if (ioctl(fd, NVME_IOC_IDENTIFY, &id) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: cannot proceed with tests "
		    "due to failure to issue basic identify controller ioctl");
	} else if (id.nid_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		errx(EXIT_FAILURE, "TEST FAILED: cannot proceed with tests "
		    "due to failure to obtain basic identify controller data, "
		    "got 0x%x", id.nid_common.nioc_drv_err);
	}

	basic_id_determine_ns_sup(data, &nns, &hasns);
	if (nns == 0) {
		errx(EXIT_FAILURE, "TEST FAILED: somehow identified that "
		    "zero namespaces exist");
	}
	(void) printf("TEST PASSED: successfully retrieved identify controller "
	    "data\n");

	for (uint32_t i = 1; i < nns; i++) {
		(void) memset(&id, 0, sizeof (id));
		id.nid_common.nioc_nsid = i;
		id.nid_cns = NVME_IDENTIFY_NSID;
		id.nid_data = (uintptr_t)data;

		if (ioctl(fd, NVME_IOC_IDENTIFY, &id) != 0) {
			warn("TEST FAILED: failed to issue identify namespace "
			    "0x%x ioctl", i);
			ret = EXIT_FAILURE;
		} else if (id.nid_common.nioc_drv_err != NVME_IOCTL_E_OK) {
			warnx("TEST FAILED: failed to obtain identify "
			    "namespace data for ns 0x%x, got error 0x%x", i,
			    id.nid_common.nioc_drv_err);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: retrieved identify "
			    "namespace 0x%x data\n", i);
		}
	}

	if (hasns) {
		(void) memset(&id, 0, sizeof (id));
		id.nid_common.nioc_nsid = NVME_NSID_BCAST;
		id.nid_cns = NVME_IDENTIFY_NSID;
		id.nid_data = (uintptr_t)data;

		if (ioctl(fd, NVME_IOC_IDENTIFY, &id) != 0) {
			warn("TEST FAILED: failed to issue identify common "
			    "namespace ioctl");
			ret = EXIT_FAILURE;
		} else if (id.nid_common.nioc_drv_err != NVME_IOCTL_E_OK) {
			warnx("TEST FAILED: failed to obtain common identify "
			    "namespace data, got error 0x%x",
			    id.nid_common.nioc_drv_err);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: retrieved common identify "
			    "namespace data\n");
		}
	}

	VERIFY0(close(fd));
	fd = nvme_ioctl_test_get_fd(1);
	(void) memset(&id, 0, sizeof (id));
	id.nid_cns = NVME_IDENTIFY_NSID;
	id.nid_data = (uintptr_t)data;

	if (ioctl(fd, NVME_IOC_IDENTIFY, &id) != 0) {
		warn("TEST FAILED: failed to issue identify namespace ioctl "
		    "on ns fd");
		ret = EXIT_FAILURE;
	} else if (id.nid_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		warnx("TEST FAILED: failed to obtain identify namespace data "
		    "on ns fd, got error 0x%x", id.nid_common.nioc_drv_err);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: retrieved identify namespace data"
		    "on ns fd\n");
	}
	VERIFY0(close(fd));

	return (ret);
}
