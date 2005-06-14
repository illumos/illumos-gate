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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * IPv4 implementation-specific definitions
 */

#ifndef _IPV4_H
#define	_IPV4_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	RT_UNUSED	1	/* Table entry is unused */
#define	RT_DEFAULT	2	/* Gateway is a default router */
#define	RT_HOST		4	/* Destination is a host */
#define	RT_NET		8	/* Destination is a network */
#define	RT_NG		10	/* Route is No Good */
#define	IPV4_ROUTE_TABLE_SIZE	(5)	/* Number of entries in the table */

#define	IPV4_ADD_ROUTE		0
#define	IPV4_DEL_ROUTE		1
#define	IPV4_BAD_ROUTE		2

extern char		*inet_ntoa(struct in_addr);
extern void		ipv4_setdefaultrouter(struct in_addr *);
extern int		ipv4_setpromiscuous(int);
extern void		ipv4_setipaddr(struct in_addr *);
extern void		ipv4_getipaddr(struct in_addr *);
extern void		ipv4_setnetmask(struct in_addr *);
extern void		ipv4_getnetmask(struct in_addr *);
extern int		ipv4_route(int, uint8_t, struct in_addr *,
			    struct in_addr *);
extern void		ipv4_setmaxttl(uint8_t);
extern in_addr_t	inet_addr(const char *);
extern void		hexdump(char *, int);
extern int		prom_cached_reply(int);
extern void		ipv4_getnetid(struct in_addr *);
#ifdef	__cplusplus
}
#endif

#endif /* _IPV4_H */
