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

#ifndef _VIONA_SUITE_H
#define	_VIONA_SUITE_H

#include <libdladm.h>
#include <libdlpi.h>
#include <sys/ethernet.h>

struct vmctx;

/*
 * Shared definitions for tests included in viona suite of tests.
 */

/*
 * Name of simnet link create viona instances upon.
 *
 * This is created and destroyed by the setup.ksh/cleanup.ksh scripts, and the
 * name must be kept in sync with them.
 */
#define	VIONA_TEST_IFACE_NAME	"bhyvetest_viona0"

/*
 * Name of a second simnet, peered with VIONA_TEST_IFACE_NAME, from which
 * dataplane tests can inject frames toward the viona link.  Also managed by
 * the setup.ksh/cleanup.ksh scripts.
 */
#define	VIONA_TEST_PEER_NAME	"bhyvetest_viona1"

/*
 * Names of VNICs tests create atop VIONA_TEST_IFACE_NAME for the duration of
 * their runs: mac_addr uses the first, rx_delivery both.  cleanup.ksh sweeps
 * any leftovers, and the names must be kept in sync with it.
 */
#define	VIONA_TEST_VNIC_NAME	"bhyvetest_viona2"
#define	VIONA_TEST_VNIC2_NAME	"bhyvetest_viona3"

/*
 * Name of an iptun with which create_delete verifies that viona rejects
 * non-Ethernet datalinks.  Also managed by the setup.ksh/cleanup.ksh scripts.
 */
#define	VIONA_TEST_IPTUN_NAME	"bhyvetest_viona4"

#define	VIONA_DEV	"/dev/viona"

/*
 * Ethernet broadcast, to which IPv4 limited broadcast maps
 * (RFC 1122 3.3.6, RFC 894)
 */
extern const uint8_t bcast_addr[ETHERADDRL];

int open_viona(void);
dladm_status_t query_dlid(const char *, datalink_id_t *);
void query_mac(const char *, uint8_t [ETHERADDRL]);
void create_link(int, struct vmctx *, datalink_id_t);
void delete_link(int);
void create_vnic(const char *, const uint8_t [ETHERADDRL]);
void delete_vnic(const char *);
const char *vmf_err_name(uint32_t);
const char *vma_err_name(uint32_t);

#endif /* _VIONA_SUITE_H */
