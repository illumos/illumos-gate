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
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <strings.h>
#include <netinet/in.h>
#include "v4_sum_impl.h"

/*
 * RFC 768 pseudo header. Used in calculating UDP checksums.
 */
struct pseudo_udp {
	struct in_addr	src;
	struct in_addr	dst;
	uint8_t		notused;	/* always zero */
	uint8_t		proto;		/* protocol used */
	uint16_t	len;		/* UDP len */
};

/*
 * One's complement checksum of pseudo header, udp header, and data.
 * Must be MT SAFE.
 */
uint16_t
udp_chksum(struct udphdr *udph, const struct in_addr *src,
    const struct in_addr *dst, uint8_t proto)
{
	struct pseudo_udp	ck;
	uint16_t		*end_pseudo_hdr = (uint16_t *)(&ck + 1);
	uint16_t		*sp = (uint16_t *)&ck;
	uint_t			sum = 0;
	uint16_t		cnt;

	/*
	 * Start on the pseudo header. Note that pseudo_udp already takes
	 * acount for the udphdr...
	 */

	bzero(&ck, sizeof (ck));

	/* struct copies */
	ck.src	 = *src;
	ck.dst	 = *dst;
	ck.len	 = udph->uh_ulen;
	ck.proto = proto;

	/*
	 * If the packet is an odd length, zero the pad byte for checksum
	 * purposes [doesn't hurt data]
	 */

	cnt = ntohs(ck.len) + sizeof (ck);
	if (cnt & 1) {
		((caddr_t)udph)[ntohs(udph->uh_ulen)] = '\0';
		cnt++;	/* make even */
	}

	for (cnt >>= 1; cnt != 0; cnt--) {

		sum += *sp++;
		if (sum >= BIT_WRAP) {
			/* Wrap carries into low bit */
			sum -= BIT_WRAP;
			sum++;
		}

		/*
		 * If we've finished checking the pseudo-header, move
		 * onto the udp header and data.
		 */

		if (sp == end_pseudo_hdr)
			sp = (uint16_t *)udph;
	}

	return (~sum == 0 ? ~0 : ~sum);
}
