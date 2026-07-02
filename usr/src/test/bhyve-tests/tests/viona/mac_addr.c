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
 * Tests for VNA_IOC_SET_MAC_ADDR and VNA_IOC_GET_MAC_ADDR, which replace and
 * read back the classified unicast address of the underlying MAC client
 * (vioc_mac_addr_t in sys/viona_io.h, mirroring VIRTIO_NET_CTRL_MAC_ADDR_SET).
 *
 * Both link flavors of interest are exercised: a viona link created directly
 * on the test simnet, where replacement removes the current address from the
 * client before installing the new one, and one created on a VNIC over that
 * simnet, where the single VNIC address is updated in place through
 * mac_unicast_primary_set().  Failed installations are checked on both,
 * requiring the previously active address to remain in effect.  An installed
 * multicast filter table is required to survive replacement, accepted or
 * refused.  This test is confined to ioctl semantics, whereas dataplane
 * consequences are exercised in rx_delivery.c.
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
static const uint8_t mcast_addr[ETHERADDRL] = {
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x01
};
/* Locally administered unicast replacements (default dladm VNIC prefix) */
static const uint8_t ucast_repl[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x10
};
static const uint8_t vnic_repl[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x30
};
/* Fixed address of the test VNIC (passed to create_vnic()) */
static const uint8_t vnic_mac[ETHERADDRL] = {
	0x02, 0x08, 0x20, 0xde, 0xad, 0x20
};
/*
 * Multicast table carried across the replacements: 224.0.0.2 all-routers and
 * ff02::1 all-nodes (mapped per RFC 1112 section 6.4 and RFC 2464 section 7).
 */
#define	MCAST_TAB_COUNT	2
static const uint8_t mcast_tab[MCAST_TAB_COUNT][ETHERADDRL] = {
	{ 0x01, 0x00, 0x5e, 0x00, 0x00, 0x02 },
	{ 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 },
};

/*
 * Issue VNA_IOC_SET_MAC_ADDR for the given address, requiring the ioctl
 * itself to succeed and the semantic error copied out through vma_err to
 * match.
 */
static void
expect_set_mac(int vfd, const uint8_t addr[ETHERADDRL],
    vioc_mac_addr_err_t exp_vma_err, const char *label)
{
	vioc_mac_addr_t vma;

	(void) memset(&vma, 0, sizeof (vma));
	(void) memcpy(vma.vma_addr, addr, ETHERADDRL);
	if (ioctl(vfd, VNA_IOC_SET_MAC_ADDR, &vma) != 0) {
		test_fail_errno(errno, label);
	}
	if (vma.vma_err != (uint32_t)exp_vma_err) {
		test_fail_msg("%s: expected vma_err %s, got %s",
		    label, vma_err_name(exp_vma_err),
		    vma_err_name(vma.vma_err));
	}
	/*
	 * SET copies out vma_present as GET would.  Every state this test
	 * constructs keeps an address installed (see verify_mac()).
	 */
	if (vma.vma_present == 0) {
		test_fail_msg("%s: expected an installed address, "
		    "vma_present reports none", label);
	}
}

/*
 * Read back the active address with VNA_IOC_GET_MAC_ADDR and require an
 * installed one (vma_present) matching what is expected.  Every state this
 * test constructs keeps an address installed.
 *
 * The vma_present == 0 state arises only from a failed restoration, which
 * cannot be provoked deterministically here.  The structure is poisoned
 * beforehand so the presence flag is known to come from the kernel rather than
 * stale stack.
 */
static void
verify_mac(int vfd, const uint8_t exp[ETHERADDRL], const char *label)
{
	vioc_mac_addr_t vma;

	(void) memset(&vma, 0xff, sizeof (vma));
	if (ioctl(vfd, VNA_IOC_GET_MAC_ADDR, &vma) != 0) {
		test_fail_errno(errno, label);
	}
	if (vma.vma_present == 0) {
		test_fail_msg("%s: expected an installed address, "
		    "vma_present reports none", label);
	}
	if (memcmp(vma.vma_addr, exp, ETHERADDRL) != 0) {
		char expstr[ETHERADDRSTRL], gotstr[ETHERADDRSTRL];

		test_fail_msg("%s: expected address %s, got %s", label,
		    ether_ntoa_r((const struct ether_addr *)exp, expstr),
		    ether_ntoa_r((const struct ether_addr *)vma.vma_addr,
		    gotstr));
	}
}

/* Install the carried multicast table with VNA_IOC_SET_MAC_FILTERS. */
static void
set_filters(int vfd, const char *label)
{
	vioc_mac_filters_t vmf;

	(void) memset(&vmf, 0, sizeof (vmf));
	vmf.vmf_nmcast = MCAST_TAB_COUNT;
	vmf.vmf_addrs = (uintptr_t)mcast_tab;
	if (ioctl(vfd, VNA_IOC_SET_MAC_FILTERS, &vmf) != 0) {
		test_fail_errno(errno, label);
	}
	if (vmf.vmf_err != VMF_OK) {
		test_fail_msg("%s: expected vmf_err VMF_OK, got %s", label,
		    vmf_err_name(vmf.vmf_err));
	}
}

/*
 * Read back the installed table with VNA_IOC_GET_MAC_FILTERS and require the
 * carried entries to remain installed.  Installed order is not part of the
 * interface, so with distinct entries, an equal count plus membership amounts
 * to a set comparison.
 */
static void
verify_filters(int vfd, const char *label)
{
	vioc_mac_filters_t vmf;
	uint8_t got[MCAST_TAB_COUNT][ETHERADDRL];

	(void) memset(&vmf, 0, sizeof (vmf));
	(void) memset(got, 0xff, sizeof (got));
	vmf.vmf_nmcast = MCAST_TAB_COUNT;
	vmf.vmf_addrs = (uintptr_t)got;
	if (ioctl(vfd, VNA_IOC_GET_MAC_FILTERS, &vmf) != 0) {
		test_fail_errno(errno, label);
	}
	if (vmf.vmf_nmcast != MCAST_TAB_COUNT) {
		test_fail_msg("%s: expected %u installed filters, got %u",
		    label, MCAST_TAB_COUNT, vmf.vmf_nmcast);
	}
	for (uint32_t i = 0; i < MCAST_TAB_COUNT; i++) {
		uint32_t j;

		for (j = 0; j < MCAST_TAB_COUNT; j++) {
			if (memcmp(mcast_tab[i], got[j], ETHERADDRL) == 0)
				break;
		}
		if (j == MCAST_TAB_COUNT) {
			test_fail_msg("%s: expected filter entry %u missing "
			    "from installed table", label, i);
		}
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	uint8_t primary[ETHERADDRL];

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

	query_mac(VIONA_TEST_IFACE_NAME, primary);

	create_link(vfd, ctx, dlid);

	/* The link begins with the primary address of the simnet */
	verify_mac(vfd, primary, "address at creation");

	/*
	 * Install a multicast table to be carried across every replacement
	 * below: the swap removes the filters ahead of the unicast removal
	 * and reinstalls them afterward, whether the replacement was accepted
	 * or was refused and went through the restoration path.  The degraded
	 * no-unicast state, in which the table is dropped instead, arises
	 * only from a failed restoration, which cannot be provoked
	 * deterministically here.
	 */
	set_filters(vfd, "filter table at creation");
	verify_filters(vfd, "filter table at creation");

	/* Requesting the already-active address succeeds without a swap */
	expect_set_mac(vfd, primary, VMA_OK, "primary re-set");
	verify_mac(vfd, primary, "primary re-set");

	/* A group address is not a valid unicast replacement */
	expect_set_mac(vfd, mcast_addr, VMA_ERR_NOT_UNICAST,
	    "multicast replacement");
	verify_mac(vfd, primary, "multicast replacement");

	/* Replacement with a fresh unicast address */
	expect_set_mac(vfd, ucast_repl, VMA_OK, "unicast replacement");
	verify_mac(vfd, ucast_repl, "unicast replacement");
	verify_filters(vfd, "unicast replacement");

	/* Requesting the active explicit address is likewise a no-op */
	expect_set_mac(vfd, ucast_repl, VMA_OK, "explicit re-set");
	verify_mac(vfd, ucast_repl, "explicit re-set");

	/*
	 * A return to the primary address, which MAC refuses as an explicit
	 * installation, must go through the MAC_UNICAST_PRIMARY path.
	 */
	expect_set_mac(vfd, primary, VMA_OK, "return to primary");
	verify_mac(vfd, primary, "return to primary");
	verify_filters(vfd, "return to primary");

	/*
	 * A VNIC atop the simnet holds its address on the underlying MAC, so
	 * requesting that address is refused as in-use.  The refusal must
	 * leave the previous address in effect whether it was the primary or
	 * an explicit one, exercising both restoration modes.
	 */
	create_vnic(VIONA_TEST_VNIC_NAME, vnic_mac);
	expect_set_mac(vfd, vnic_mac, VMA_ERR_INSTALL,
	    "in-use replacement from primary");
	verify_mac(vfd, primary, "in-use replacement from primary");
	verify_filters(vfd, "in-use replacement from primary");

	expect_set_mac(vfd, ucast_repl, VMA_OK,
	    "unicast replacement with VNIC present");
	expect_set_mac(vfd, vnic_mac, VMA_ERR_INSTALL,
	    "in-use replacement from explicit");
	verify_mac(vfd, ucast_repl, "in-use replacement from explicit");
	verify_filters(vfd, "in-use replacement from explicit");

	expect_set_mac(vfd, primary, VMA_OK, "restore primary");
	delete_link(vfd);

	/*
	 * A viona link on the VNIC itself follows the in-place update path,
	 * with no removal ahead of installation.
	 */
	dls = query_dlid(VIONA_TEST_VNIC_NAME, &dlid);
	if (dls != DLADM_STATUS_OK) {
		char errbuf[DLADM_STRSIZE];

		test_fail_msg("could not query datalink id for %s: %s",
		    VIONA_TEST_VNIC_NAME, dladm_status2str(dls, errbuf));
	}
	create_link(vfd, ctx, dlid);
	verify_mac(vfd, vnic_mac, "VNIC address at creation");

	/* The in-place VNIC path leaves the installed table untouched. */
	set_filters(vfd, "VNIC filter table at creation");

	expect_set_mac(vfd, mcast_addr, VMA_ERR_NOT_UNICAST,
	    "VNIC multicast replacement");
	verify_mac(vfd, vnic_mac, "VNIC multicast replacement");

	/*
	 * MAC refuses to move a VNIC onto the primary address of its
	 * underlying link (mac_vnic_unicast_set()), and the in-place path
	 * leaves the previous address untouched on refusal.
	 */
	expect_set_mac(vfd, primary, VMA_ERR_INSTALL,
	    "VNIC replacement with underlying primary");
	verify_mac(vfd, vnic_mac, "VNIC replacement with underlying primary");

	/*
	 * A successful in-place update changes the address of the VNIC
	 * itself, visible through DLPI as its new physical address.
	 */
	expect_set_mac(vfd, vnic_repl, VMA_OK, "VNIC unicast replacement");
	verify_mac(vfd, vnic_repl, "VNIC unicast replacement");
	verify_filters(vfd, "VNIC unicast replacement");

	uint8_t vnic_cur[ETHERADDRL];
	query_mac(VIONA_TEST_VNIC_NAME, vnic_cur);
	if (memcmp(vnic_cur, vnic_repl, ETHERADDRL) != 0) {
		char expstr[ETHERADDRSTRL], gotstr[ETHERADDRSTRL];

		test_fail_msg("VNIC unicast replacement: expected physical "
		    "address %s, got %s",
		    ether_ntoa_r((const struct ether_addr *)vnic_repl, expstr),
		    ether_ntoa_r((const struct ether_addr *)vnic_cur, gotstr));
	}

	expect_set_mac(vfd, vnic_mac, VMA_OK, "VNIC address restore");
	verify_mac(vfd, vnic_mac, "VNIC address restore");

	delete_link(vfd);
	delete_vnic(VIONA_TEST_VNIC_NAME);

	test_pass();
	return (EXIT_SUCCESS);
}
