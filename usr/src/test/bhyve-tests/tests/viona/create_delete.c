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
 * Tests for VNA_IOC_CREATE and VNA_IOC_DELETE: creation on a non-Ethernet
 * datalink (an iptun) must fail with ENOTSUP and leave no state behind,
 * while a create/delete cycle on the Ethernet simnet must succeed.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>

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

	datalink_id_t iptun_dlid;
	dladm_status_t dls = query_dlid(VIONA_TEST_IPTUN_NAME, &iptun_dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_IPTUN_NAME, dladm_status2str(dls, errbuf));
	}

	vioc_create_t create_ioc = {
		.c_linkid = iptun_dlid,
		.c_vmfd = vm_get_device_fd(ctx),
	};
	if (ioctl(vfd, VNA_IOC_CREATE, &create_ioc) == 0) {
		delete_link(vfd);
		test_fail_msg("unexpectedly created viona link on "
		    "non-Ethernet datalink %s", VIONA_TEST_IPTUN_NAME);
	}
	if (errno != ENOTSUP) {
		test_fail_msg("create on non-Ethernet datalink %s: "
		    "expected ENOTSUP, got %s", VIONA_TEST_IPTUN_NAME,
		    strerrorname_np(errno));
	}

	datalink_id_t dlid;
	dls = query_dlid(VIONA_TEST_IFACE_NAME, &dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_IFACE_NAME, dladm_status2str(dls, errbuf));
	}

	/*
	 * Creating a link on the same descriptor proves that the rejected
	 * creation did not leave the instance's ss_link occupied, which
	 * would fail this attempt with EEXIST.
	 */
	create_link(vfd, ctx, dlid);
	delete_link(vfd);

	test_pass();
	return (EXIT_SUCCESS);
}
