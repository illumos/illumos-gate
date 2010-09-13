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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SLP_NET_UTILS_H
#define	_SLP_NET_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* address manipulation */
extern SLPError slp_broadcast_addrs(slp_handle_impl_t *, struct in_addr *,
				int, struct sockaddr_in **, int *);
extern SLPBoolean slp_on_subnet(slp_handle_impl_t *, struct in_addr);
extern SLPBoolean slp_on_localhost(slp_handle_impl_t *, struct in_addr);
extern void slp_free_ifinfo(void *);
extern SLPError slp_surl2sin(SLPSrvURL *, struct sockaddr_in *);
extern char *slp_gethostbyaddr(const char *, int);

#define	SLP_NETDB_BUFSZ	NSS_BUFLEN_HOSTS
#define	INET6_ADDRSTRLEN	46	/* max len of IPv6 addr in ascii */

/* @@@ temporary backport hack */
#ifdef	OSVERS6
typedef int socklen_t;
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SLP_NET_UTILS_H */
