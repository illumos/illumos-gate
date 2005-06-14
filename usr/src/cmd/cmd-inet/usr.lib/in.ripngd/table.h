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
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routing table management daemon.
 */

/*
 * Routing table structure; differs a bit from kernel tables.
 */
struct rthash {
	struct	rt_entry *rt_forw;
	struct	rt_entry *rt_back;
};

struct rt_entry {
	struct	rt_entry *rt_forw;
	struct	rt_entry *rt_back;
	uint_t	rt_hash;		/* for net or host */
	struct	in6_addr rt_dst;	/* match value */
	struct	in6_addr rt_router;	/* who to forward to */
	int	rt_prefix_length;	/* bits in prefix */
	struct	interface *rt_ifp;	/* interface to take */
	uint_t	rt_flags;		/* kernel flags */
	uint_t	rt_state;		/* see below */
	int	rt_timer;		/* for invalidation */
	int	rt_metric;		/* cost of route including the if */
	int	rt_tag;			/* route tag attribute */
};

#define	ROUTEHASHSIZ	32		/* must be a power of 2 */
#define	ROUTEHASHMASK	(ROUTEHASHSIZ - 1)

/*
 * "State" of routing table entry.
 */
#define	RTS_CHANGED	0x1		/* route has been altered recently */
#define	RTS_INTERFACE	0x2		/* route is for network interface */
#define	RTS_PRIVATE	0x4		/* route is private, do not advertise */

/*
 * XXX This is defined in <inet/ip.h> (but should be defined in <netinet/ip6.h>
 * for completeness).
 */
#define	IPV6_ABITS	128		/* Number of bits in an IPv6 address */

extern struct	rthash	*net_hashes[IPV6_ABITS + 1];

extern void	rtadd(struct in6_addr *, struct in6_addr *, int, int, int,
    boolean_t, struct interface *);
extern void	rtchange(struct rt_entry *, struct in6_addr *, short,
    struct interface *);
extern void	rtchangeall(void);
extern void	rtcreate_prefix(struct in6_addr *, struct in6_addr *, int);
extern void	rtdelete(struct rt_entry *);
extern void	rtdown(struct rt_entry *);
extern void	rtdump(void);
extern struct	rt_entry *rtlookup(struct in6_addr *, int);
extern void	rtpurgeif(struct interface *);
