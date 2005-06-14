/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	DEFAULTS_H
#define	DEFAULTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

/*
 * defaults.[ch] encapsulate the agent's interface to the dhcpagent
 * defaults file.  see defaults.c for documentation on how to use the
 * exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * tunable parameters -- keep in the same order as defaults[] in defaults.c
 */

enum {

	DF_RELEASE_ON_SIGTERM,	/* send RELEASE on each if upon SIGTERM */
	DF_IGNORE_FAILED_ARP,	/* what to do if agent can't ARP */
	DF_OFFER_WAIT,		/* how long to wait to collect offers */
	DF_ARP_WAIT,		/* how long to wait for an ARP reply */
	DF_CLIENT_ID,		/* our client id */
	DF_PARAM_REQUEST_LIST,	/* our parameter request list */
	DF_REQUEST_HOSTNAME	/* request hostname associated with interface */
};

#define	DHCP_AGENT_DEFAULTS	"/etc/default/dhcpagent"

boolean_t	df_get_bool(const char *, unsigned int);
int		df_get_int(const char *, unsigned int);
const char	*df_get_string(const char *, unsigned int);
uchar_t		*df_get_octet(const char *, unsigned int, unsigned int *);

#ifdef	__cplusplus
}
#endif

#endif	/* DEFAULTS_H */
