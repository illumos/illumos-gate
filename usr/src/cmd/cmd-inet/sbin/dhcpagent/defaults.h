/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

#ifndef	DEFAULTS_H
#define	DEFAULTS_H

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
	_UNUSED_DF_IGNORE_FAILED_ARP,
	DF_OFFER_WAIT,		/* how long to wait to collect offers */
	_UNUSED_DF_ARP_WAIT,
	DF_CLIENT_ID,		/* our client id */
	DF_PARAM_REQUEST_LIST,	/* our parameter request list */
	DF_REQUEST_HOSTNAME,	/* request hostname associated with interface */
	DF_DEBUG_LEVEL,		/* set debug level (undocumented) */
	DF_VERBOSE,		/* set verbose mode (undocumented) */
	DF_VERIFIED_LEASE_ONLY,	/* send RELEASE on SIGTERM and need verify */
	DF_PARAM_IGNORE_LIST,	/* our parameter ignore list */
	DF_REQUEST_FQDN,	/* request FQDN associated with interface */
	DF_V4_DEFAULT_IAID_DUID,	/* IAID/DUID if no DF_CLIENT_ID */
	DF_DNS_DOMAINNAME,	/* static domain name if not in --reqhost */
	DF_ADOPT_DOMAINNAME	/* adopt DHCP domain if not in --reqhost */
};

#define	DHCP_AGENT_DEFAULTS	"/etc/default/dhcpagent"

boolean_t	df_get_bool(const char *, boolean_t, uint_t);
int		df_get_int(const char *, boolean_t, uint_t);
const char	*df_get_string(const char *, boolean_t, uint_t);

#ifdef	__cplusplus
}
#endif

#endif	/* DEFAULTS_H */
