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
 * Perform a GET FEATURES commands that should work on all devices since NVMe
 * 1.0 (though may fail on some emulated cases). We use the temperature
 * threshold feature because its output value is generally expected to be
 * non-zero and the default is 0xFFFF (as of NVMe 1.2). If we find devices that
 * actually return a default of zero, we should probably put them in an ignore
 * list in here.
 */

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nvme_ioctl_util.h"

int
main(void)
{
	int fd = nvme_ioctl_test_get_fd(0);
	nvme_ioctl_get_feature_t get;

	(void) memset(&get, 0, sizeof (get));
	get.nigf_fid = NVME_FEAT_TEMPERATURE;

	if (ioctl(fd, NVME_IOC_GET_FEATURE, &get) != 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to issue NVMe get "
		    "features ioctl");
	} else if (get.nigf_common.nioc_drv_err != NVME_IOCTL_E_OK) {
		errx(EXIT_FAILURE, "TEST FAILED: failed to get temperature "
		    "threshold feature: found error 0x%x, but expected success",
		    get.nigf_common.nioc_drv_err);
	}

	if (get.nigf_cdw0 == 0) {
		errx(EXIT_FAILURE, "TEST FAILED: found zeroed cdw0 value for "
		    "composite temperature threshold");
	} else {
		(void) printf("TEST PASSED: successfully read composite "
		    "temperature threshold\n");
	}

	VERIFY0(close(fd));
	return (0);
}
