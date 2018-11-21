/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */


#include <errno.h>
#include "ktable.h"
#include "hangulcode.h"


/****  _ J O H A P _ T O _ W A N S U N G  ****/

unsigned short _johap_to_wansung(unsigned short ci, unsigned short v,
					unsigned short cf)
{
	register unsigned short	i;
	unsigned short		code, mask, disp;
	long			cfbit;

	if (ci <= 18 && v == CVC_FILL && cf == CVC_FILL)
		return(0xA4A0 + Y19_32[ci + 1]);
	else if (ci == CVC_FILL && v <= 20 && cf == CVC_FILL)
		return(0xA4BF + v);
	else if (ci != CVC_FILL && ci <= 18 && v != CVC_FILL && v <= 20)
	{
		 if (cf == CVC_FILL)
			cf = 1;

		cfbit = cmp_bitmap[ci][v];
		for (disp = 0, i = 0; i < cf; i++)
		{
			if (cfbit & BIT_MASK)
				disp++;
			cfbit >>= 1;
		}
		if (!(cfbit & BIT_MASK))
			return(FAILED);

		code = cmp_srchtbl[ci][v] + disp;
		mask = cmp_srchtbl[ci][v] & 0xFF;

		return(code + (((short)(mask + disp) > 0xFE) ? SKIP : 0));
	}

	return(FAILED);
}  /* end of unsigned short _johap_to_wansung(unsigned short, unsigned short,
    *						unsigned short). */
