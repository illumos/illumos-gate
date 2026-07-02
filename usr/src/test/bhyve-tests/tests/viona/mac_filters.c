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
 * Tests for VNA_IOC_SET_MAC_FILTERS and VNA_IOC_GET_MAC_FILTERS, which
 * install and inspect the guest's multicast MAC address table
 * (vioc_mac_filters_t in sys/viona_io.h, populated from
 * VIRTIO_NET_CTRL_MAC_TABLE_SET requests) on the underlying MAC client.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

#include <sys/vmm.h>
#include <sys/viona_io.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"
#include "viona_suite.h"

/* 224.0.0.1 all-hosts (mapped per RFC 1112 section 6.4) */
static const uint8_t mcast_a[ETHERADDRL] = {
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x01
};
/* ff02::1 all-nodes (mapped per RFC 2464 section 7) */
static const uint8_t mcast_b[ETHERADDRL] = {
	0x33, 0x33, 0x00, 0x00, 0x00, 0x01
};
/* Locally administered unicast (default dladm VNIC prefix) */
static const uint8_t ucast_other[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x01
};

/*
 * Issue VNA_IOC_SET_MAC_FILTERS with the caller-provided request, requiring
 * the ioctl itself to succeed and the semantic error copied out through
 * vmf_err to match.  The request is left in place for the caller to inspect
 * the fields the ioctl writes back (vmf_erraddr, a rewritten vmf_nmcast).
 */
static void
expect_set_filters(int vfd, vioc_mac_filters_t *vmf,
    vioc_mac_filter_err_t exp_vmf_err, const char *label)
{
	if (ioctl(vfd, VNA_IOC_SET_MAC_FILTERS, vmf) != 0) {
		test_fail_errno(errno, label);
	}
	if (vmf->vmf_err != (uint32_t)exp_vmf_err) {
		test_fail_msg("%s: expected vmf_err %s, got %s",
		    label, vmf_err_name(exp_vmf_err),
		    vmf_err_name(vmf->vmf_err));
	}
}

/*
 * Read back the installed table with VNA_IOC_GET_MAC_FILTERS and require it
 * to match the expected entries.  Installed order is not part of the
 * interface, so with distinct expected entries, an equal count plus
 * membership amounts to a set comparison.
 */
static void
verify_installed(int vfd, uint32_t exp_count,
    const uint8_t exp[][ETHERADDRL], const char *label)
{
	vioc_mac_filters_t vmf;
	uint8_t got[VIONA_MAX_MCAST_FILTERS][ETHERADDRL];

	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memset(got, 0, sizeof (got));
	vmf.vmf_nmcast = VIONA_MAX_MCAST_FILTERS;
	vmf.vmf_addrs = (uintptr_t)got;
	if (ioctl(vfd, VNA_IOC_GET_MAC_FILTERS, &vmf) != 0) {
		test_fail_errno(errno, label);
	}
	if (vmf.vmf_nmcast != exp_count) {
		test_fail_msg("%s: expected %u installed filters, got %u",
		    label, exp_count, vmf.vmf_nmcast);
	}
	for (uint32_t i = 0; i < exp_count; i++) {
		uint32_t j;

		for (j = 0; j < exp_count; j++) {
			if (memcmp(exp[i], got[j], ETHERADDRL) == 0)
				break;
		}
		if (j == exp_count) {
			test_fail_msg("%s: expected entry %u missing from "
			    "installed table", label, i);
		}
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	vioc_mac_filters_t vmf;
	uint8_t tab[VIONA_MAX_MCAST_FILTERS][ETHERADDRL];

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

	create_link(vfd, ctx, dlid);

	/* A simple pair of valid multicast entries */
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memcpy(tab[0], mcast_a, ETHERADDRL);
	(void) memcpy(tab[1], mcast_b, ETHERADDRL);
	vmf.vmf_nmcast = 2;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_OK, "valid multicast table");
	verify_installed(vfd, 2, tab, "valid multicast table");

	/* Duplicate entries are compacted rather than rejected */
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memcpy(tab[0], mcast_a, ETHERADDRL);
	(void) memcpy(tab[1], mcast_a, ETHERADDRL);
	(void) memcpy(tab[2], mcast_b, ETHERADDRL);
	vmf.vmf_nmcast = 3;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_OK, "duplicate multicast entries");

	/* The installed table holds each address once */
	uint8_t exp_pair[2][ETHERADDRL];
	(void) memcpy(exp_pair[0], mcast_a, ETHERADDRL);
	(void) memcpy(exp_pair[1], mcast_b, ETHERADDRL);
	verify_installed(vfd, 2, exp_pair, "duplicate multicast entries");

	/* Replacement table with a disjoint entry */
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memset(tab, 0, sizeof (tab));
	tab[0][0] = 0x33;
	tab[0][1] = 0x33;
	tab[0][5] = 0x02;
	vmf.vmf_nmcast = 1;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_OK, "replacement multicast table");
	verify_installed(vfd, 1, tab, "replacement multicast table");

	/* Zero counts clear all filters */
	(void) memset(&vmf, 0, sizeof (vmf));
	expect_set_filters(vfd, &vmf, VMF_OK, "clear filters");
	verify_installed(vfd, 0, NULL, "clear filters");

	/* Broadcast entries are accepted but skipped rather than installed */
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memcpy(tab[0], bcast_addr, ETHERADDRL);
	vmf.vmf_nmcast = 1;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_OK, "broadcast in multicast table");
	verify_installed(vfd, 0, NULL, "broadcast in multicast table");

	/* A unicast address is not a valid multicast filter */
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memcpy(tab[0], ucast_other, ETHERADDRL);
	vmf.vmf_nmcast = 1;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_ERR_NOT_MCAST,
	    "unicast in multicast table");
	if (memcmp(vmf.vmf_erraddr, ucast_other, ETHERADDRL) != 0) {
		char expstr[ETHERADDRSTRL], gotstr[ETHERADDRSTRL];

		test_fail_msg("unicast in multicast table: expected "
		    "vmf_erraddr %s, got %s",
		    ether_ntoa_r((const struct ether_addr *)ucast_other,
		    expstr),
		    ether_ntoa_r((const struct ether_addr *)vmf.vmf_erraddr,
		    gotstr));
	}

	/* Counts beyond the device capacity are rejected */
	(void) memset(&vmf, 0, sizeof (vmf));
	vmf.vmf_nmcast = VIONA_MAX_MCAST_FILTERS + 1;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_ERR_COUNT,
	    "oversized multicast count");

	/* An over-capacity failure reports the device capacity in vmf_nmcast */
	if (vmf.vmf_nmcast != VIONA_MAX_MCAST_FILTERS) {
		test_fail_msg("oversized multicast count: expected capacity "
		    "%u in vmf_nmcast, got %u", VIONA_MAX_MCAST_FILTERS,
		    vmf.vmf_nmcast);
	}

	/* A full table of distinct entries installs successfully */
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memset(tab, 0, sizeof (tab));
	for (uint32_t i = 0; i < VIONA_MAX_MCAST_FILTERS; i++) {
		tab[i][0] = 0x33;
		tab[i][1] = 0x33;
		tab[i][5] = (uint8_t)i;
	}
	vmf.vmf_nmcast = VIONA_MAX_MCAST_FILTERS;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_OK, "full multicast table");
	verify_installed(vfd, VIONA_MAX_MCAST_FILTERS, tab,
	    "full multicast table");

	/* A short buffer is truncated while reporting the installed count */
	uint8_t one[1][ETHERADDRL];
	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memset(one, 0, sizeof (one));
	vmf.vmf_nmcast = 1;
	vmf.vmf_addrs = (uintptr_t)one;
	if (ioctl(vfd, VNA_IOC_GET_MAC_FILTERS, &vmf) != 0) {
		test_fail_errno(errno, "get with short buffer");
	}
	if (vmf.vmf_nmcast != VIONA_MAX_MCAST_FILTERS) {
		test_fail_msg("get with short buffer: expected installed "
		    "count %u, got %u", VIONA_MAX_MCAST_FILTERS,
		    vmf.vmf_nmcast);
	}

	/* The truncated copyout still carries an installed entry */
	uint32_t k;
	for (k = 0; k < VIONA_MAX_MCAST_FILTERS; k++) {
		if (memcmp(one[0], tab[k], ETHERADDRL) == 0)
			break;
	}
	if (k == VIONA_MAX_MCAST_FILTERS) {
		test_fail_msg("get with short buffer: copied entry not among "
		    "installed filters");
	}

	/*
	 * Deleting the viona link must remove its installed filters from MAC.
	 * The recreated link below verifies that no filter state carries over.
	 */
	delete_link(vfd);

	/* A fresh link on the same interface starts with a clean slate */
	create_link(vfd, ctx, dlid);
	verify_installed(vfd, 0, NULL, "filters after recreate");

	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memcpy(tab[0], mcast_a, ETHERADDRL);
	vmf.vmf_nmcast = 1;
	vmf.vmf_addrs = (uintptr_t)tab;
	expect_set_filters(vfd, &vmf, VMF_OK, "filters after recreate");

	delete_link(vfd);

	test_pass();
	return (EXIT_SUCCESS);
}
