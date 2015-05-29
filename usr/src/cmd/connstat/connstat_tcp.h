/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

#ifndef	_CONNSTAT_TCP_H
#define	_CONNSTAT_TCP_H

#include <stddef.h>
#include "connstat.h"

#ifdef	__cplusplus
extern "C" {
#endif

int tcp_str2state(const char *state);
connstat_getfieldsfunc_t tcp_get_fields;
connstat_walkfunc_t tcp_walk_ipv4, tcp_walk_ipv6;

/*
 * Keep the default output to < 80 columns. For most interactive workflows,
 * the user will run the command without arguments to get an idea of what
 * connections exist before narrowing down the investigation to a single
 * connection (with filtering) and specifying additional fields to output
 * depending on what the user is interested in.
 */
#define	TCP_DEFAULT_FIELDS	"laddr,lport,raddr,rport,state"

#define	CONNSTAT_TCP_PROTO \
	{ "tcp", TCP_DEFAULT_FIELDS, MIB2_TCP, MIB2_TCP_CONN, MIB2_TCP6_CONN, \
	tcp_get_fields, tcp_walk_ipv4, tcp_walk_ipv6 }

#ifdef	__cplusplus
}
#endif

#endif	/* _CONNSTAT_TCP_H */
