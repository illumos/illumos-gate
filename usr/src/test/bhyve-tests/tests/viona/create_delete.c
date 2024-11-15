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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/vmm.h>
#include <sys/viona_io.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"
#include "viona_suite.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = test_initialize_plain(suite_name);
	if (ctx == NULL) {
		test_fail_errno(errno, "could not open test VM");
	}

	int vfd = open_viona();
	if (vfd < 0) {
		test_fail_errno(errno, "could not open viona device");
	}

	datalink_id_t dlid;
	dladm_status_t dls = query_dlid(VIONA_TEST_IFACE_NAME, &dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_IFACE_NAME, dladm_status2str(dls, errbuf));
	}

	vioc_create_t create_ioc = {
		.c_linkid = dlid,
		.c_vmfd = vm_get_device_fd(ctx),
	};
	if (ioctl(vfd, VNA_IOC_CREATE, &create_ioc) != 0) {
		test_fail_errno(errno, "failed to create link on viona device");
	}

	if (ioctl(vfd, VNA_IOC_DELETE, 0) != 0) {
		test_fail_errno(errno, "failed to delete link on viona device");
	}

	test_pass();
	return (EXIT_SUCCESS);
}
