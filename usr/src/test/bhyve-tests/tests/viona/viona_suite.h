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

#ifndef _VIONA_SUITE_H
#define	_VIONA_SUITE_H

#include <libdladm.h>

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

#define	VIONA_DEV	"/dev/viona"

int open_viona(void);
dladm_status_t query_dlid(const char *, datalink_id_t *);

#endif /* _VIONA_SUITE_H */
