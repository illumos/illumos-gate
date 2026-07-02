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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libdladm.h>
#include <libdllink.h>

#include <sys/vmm.h>
#include <sys/viona_io.h>
#include <vmmapi.h>

#include "common.h"
#include "in_guest.h"
#include "viona_suite.h"

const uint8_t bcast_addr[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

int
open_viona(void)
{
	return (open(VIONA_DEV, O_RDWR));
}

/* Convenience helper to get datalink_id_t from an interface name */
dladm_status_t
query_dlid(const char *name, datalink_id_t *dlid)
{
	dladm_handle_t hdl;
	dladm_status_t err;

	err = dladm_open(&hdl);
	if (err != DLADM_STATUS_OK) {
		return (err);
	}

	err = dladm_name2info(hdl, name, dlid, NULL, NULL, NULL);
	dladm_close(hdl);

	return (err);
}

/* Fetch the current primary MAC address of an interface */
static int
query_primary_mac(const char *name, uint8_t *addr, size_t *addrlen)
{
	dlpi_handle_t dh;
	int err;

	err = dlpi_open(name, &dh, 0);
	if (err != DLPI_SUCCESS) {
		return (err);
	}

	err = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, addr, addrlen);
	dlpi_close(dh);

	return (err);
}

/* Fetch the current primary MAC of a link, requiring an Ethernet address */
void
query_mac(const char *name, uint8_t addr[ETHERADDRL])
{
	uint8_t physaddr[DLPI_PHYSADDR_MAX];
	size_t addrlen = sizeof (physaddr);
	int err = query_primary_mac(name, physaddr, &addrlen);

	if (err != DLPI_SUCCESS) {
		test_fail_msg("could not query primary MAC for %s: %s",
		    name, dlpi_strerror(err));
	}
	if (addrlen != ETHERADDRL) {
		test_fail_msg("unexpected physaddr length for %s: "
		    "expected %u, got %zu", name, ETHERADDRL, addrlen);
	}
	(void) memcpy(addr, physaddr, ETHERADDRL);
}

void
create_link(int vfd, struct vmctx *ctx, datalink_id_t dlid)
{
	vioc_create_t create_ioc = {
		.c_linkid = dlid,
		.c_vmfd = vm_get_device_fd(ctx),
	};

	if (ioctl(vfd, VNA_IOC_CREATE, &create_ioc) != 0) {
		test_fail_errno(errno, "failed to create link on viona device");
	}
}

void
delete_link(int vfd)
{
	if (ioctl(vfd, VNA_IOC_DELETE, 0) != 0) {
		test_fail_errno(errno, "failed to delete link on viona device");
	}
}

/*
 * Create a temporary VNIC atop the test simnet.  Should a failure exit leak
 * it, cleanup.ksh sweeps the well-known names (VIONA_TEST_VNIC_NAME and
 * VIONA_TEST_VNIC2_NAME).
 */
void
create_vnic(const char *name, const uint8_t mac[ETHERADDRL])
{
	char macstr[ETHERADDRSTRL];
	char cmd[256];

	(void) snprintf(cmd, sizeof (cmd),
	    "dladm create-vnic -t -l %s -m %s %s", VIONA_TEST_IFACE_NAME,
	    ether_ntoa_r((const struct ether_addr *)mac, macstr), name);
	if (system(cmd) != 0) {
		test_fail_msg("could not create VNIC %s", name);
	}
}

void
delete_vnic(const char *name)
{
	char cmd[256];

	(void) snprintf(cmd, sizeof (cmd), "dladm delete-vnic %s", name);
	if (system(cmd) != 0) {
		test_fail_msg("could not delete VNIC %s", name);
	}
}

/* Names for the semantic error codes of vioc_mac_filters_t */
const char *
vmf_err_name(uint32_t err)
{
	switch ((vioc_mac_filter_err_t)err) {
	case VMF_OK:
		return ("VMF_OK");
	case VMF_ERR_COUNT:
		return ("VMF_ERR_COUNT");
	case VMF_ERR_NOT_MCAST:
		return ("VMF_ERR_NOT_MCAST");
	case VMF_ERR_INSTALL:
		return ("VMF_ERR_INSTALL");
	case VMF_ERR_NO_UNICAST:
		return ("VMF_ERR_NO_UNICAST");
	default:
		return ("<unknown vmf_err>");
	}
}

/* Names for the semantic error codes of vioc_mac_addr_t */
const char *
vma_err_name(uint32_t err)
{
	switch ((vioc_mac_addr_err_t)err) {
	case VMA_OK:
		return ("VMA_OK");
	case VMA_ERR_NOT_UNICAST:
		return ("VMA_ERR_NOT_UNICAST");
	case VMA_ERR_INSTALL:
		return ("VMA_ERR_INSTALL");
	case VMA_ERR_MCAST_RESTORE:
		return ("VMA_ERR_MCAST_RESTORE");
	default:
		return ("<unknown vma_err>");
	}
}
