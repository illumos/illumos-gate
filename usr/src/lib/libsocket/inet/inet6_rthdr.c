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
 * Copyright 2003 Sun Microsystems, Inc.
 * All rights reserved.  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This code is conformant to revision 7 of 2292bis.  Some of these functions
 * were provided (named inet6_rthdr_) in a very similar form in RFC 2292.
 * The RFC 2292 variants are not supported.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <errno.h>

#define	MAX_RTHDR0_SEGMENTS 127

/*
 * Return amount of space needed to hold N segments for the specified
 * routing type. Does NOT include space for cmsghdr.
 */
socklen_t
inet6_rth_space(int type, int segments)
{
	if (type != IPV6_RTHDR_TYPE_0 || segments < 0 ||
	    segments > MAX_RTHDR0_SEGMENTS)
		return (0);

	return (sizeof (struct ip6_rthdr0) +
	    segments * sizeof (struct in6_addr));
}

/*
 * Initializes rthdr structure. Verifies the segments against the length of
 * the buffer.
 * Note that a routing header can only hold 127 segments since the length field
 * in the header is just a byte.
 */
void *
inet6_rth_init(void *bp, socklen_t bp_len, int type, int segments)
{
	struct ip6_rthdr0 *rthdr;

	if (type != IPV6_RTHDR_TYPE_0 || segments < 0 ||
	    segments > MAX_RTHDR0_SEGMENTS)
		return (NULL);

	if (bp_len < sizeof (struct ip6_rthdr0) +
	    segments * sizeof (struct in6_addr))
		return (NULL);

	rthdr = (struct ip6_rthdr0 *)bp;
	rthdr->ip6r0_nxt = 0;
	rthdr->ip6r0_len = (segments * 2);
	rthdr->ip6r0_type = type;
	rthdr->ip6r0_segleft = 0;	/* Incremented by rthdr_add */
	*(uint32_t *)&rthdr->ip6r0_reserved = 0;
	return (bp);
}

/*
 * Add one more address to the routing header. Fails when there is no more
 * room.
 */
int
inet6_rth_add(void *bp, const struct in6_addr *addr)
{
	struct ip6_rthdr0 *rthdr;
	struct in6_addr *addrs;

	rthdr = (struct ip6_rthdr0 *)bp;
	if ((rthdr->ip6r0_segleft + 1) * 2 > rthdr->ip6r0_len) {
		/* Not room for one more */
		return (-1);
	}
	addrs = (struct in6_addr *)((char *)rthdr + sizeof (*rthdr));
	addrs[rthdr->ip6r0_segleft++] = *addr;
	return (0);
}

/*
 * Reverse a source route. Both arguments can point to the same buffer.
 */
int
inet6_rth_reverse(const void *in, void *out)
{
	struct ip6_rthdr0 *rtin, *rtout;
	int i, segments;
	struct in6_addr tmp;
	struct in6_addr *rtout_addrs;
	struct in6_addr *rtin_addrs;

	rtin = (struct ip6_rthdr0 *)in;
	rtout = (struct ip6_rthdr0 *)out;

	if (rtout->ip6r0_type != 0 || rtin->ip6r0_type != 0 ||
	    rtout->ip6r0_len > MAX_RTHDR0_SEGMENTS * 2 ||
	    rtin->ip6r0_len > MAX_RTHDR0_SEGMENTS * 2 ||
	    rtout->ip6r0_len != rtin->ip6r0_len)
		return (-1);

	segments = rtin->ip6r0_len / 2;
	rtout_addrs = (struct in6_addr *)((char *)rtout + sizeof (*rtout));
	rtin_addrs = (struct in6_addr *)((char *)rtin + sizeof (*rtin));
	for (i = 0; i < (segments + 1)/2; i++) {
		tmp = rtin_addrs[i];
		rtout_addrs[i] = rtin_addrs[segments - 1 - i];
		rtout_addrs[segments - 1 - i] = tmp;
	}
	rtout->ip6r0_segleft = segments;
	return (0);
}

/*
 * Return the number of segments in the routing header.
 */
int
inet6_rth_segments(const void *bp)
{
	struct ip6_rthdr0 *rthdr;

	rthdr = (struct ip6_rthdr0 *)bp;
	if (rthdr->ip6r0_type == 0) {
		if (rthdr->ip6r0_len > MAX_RTHDR0_SEGMENTS * 2) {
			return (-1);
		} else {
			return (rthdr->ip6r0_len / 2);
		}
	} else {
		return (-1);
	}
}

/*
 * Return a pointer to an element in the source route.
 * This uses the C convention for index [0, size-1].
 */
struct in6_addr *
inet6_rth_getaddr(const void *bp, int index)
{
	struct ip6_rthdr0 *rthdr;
	struct in6_addr *rv;

	rthdr = (struct ip6_rthdr0 *)bp;
	if (index >= rthdr->ip6r0_len/2 || index < 0)
		return (NULL);

	rv = (struct in6_addr *)((char *)rthdr + sizeof (*rthdr));
	return (&rv[index]);
}
