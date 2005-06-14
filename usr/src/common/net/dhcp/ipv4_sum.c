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
#include "v4_sum_impl.h"

/*
 * Compute one's complement checksum for IP packet headers.
 */
uint16_t
ipv4cksum(uint16_t *cp, uint16_t count)
{
	uint_t		sum = 0;
	uint_t		oneword = BIT_WRAP;

	if (count == 0)
		return (0);

	count >>= 1;
	while (count--) {
		sum += (uint_t)*cp++;
		if (sum >= oneword) {		/* Wrap carries into low bit */
			sum -= oneword;
			sum++;
		}
	}
	return ((uint16_t)~sum);
}
