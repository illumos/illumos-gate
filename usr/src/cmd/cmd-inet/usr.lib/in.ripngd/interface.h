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

#ident	"%Z%%M%	%I%	%E% SMI"

struct interface {
	struct	interface *int_next;
	struct	in6_addr int_addr;		/* address on this if */
	struct	in6_addr int_dstaddr;		/* other end of p-to-p link */
	int	int_metric;			/* init's routing entry */
	uint_t	int_flags;			/* see below */
	int	int_prefix_length;		/* prefix length on this if */
	char	*int_name;			/* from kernel if structure */
	char	*int_ifbase;			/* name of physical interface */
	int	int_sock;			/* socket on if to send/recv */
	int	int_ifindex;			/* interface index */
	uint_t	int_mtu;			/* maximum transmission unit */
	struct  ifdebug int_input, int_output;  /* packet tracing stuff */
	int	int_ipackets;			/* input packets received */
	int	int_opackets;			/* output packets sent */
	ushort_t int_transitions;		/* times gone up-down */
};

#define	RIP6_IFF_UP		0x1		/* interface is up */
#define	RIP6_IFF_POINTOPOINT	0x2		/* interface is p-to-p link */
#define	RIP6_IFF_MARKED		0x4		/* to determine removed ifs */
#define	RIP6_IFF_NORTEXCH	0x8		/* don't exchange route info */
#define	RIP6_IFF_PRIVATE	0x10		/* interface is private */

#define	IFMETRIC(ifp)	((ifp != NULL) ? (ifp)->int_metric : 1)

extern void	if_dump(void);
extern struct	interface *if_ifwithname(char *);
extern void	if_purge(struct interface *);
