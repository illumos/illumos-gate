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


extern kcode_table	euc2utf8_tbl[];


/****  _ W A N S U N G _ T O _ U T F 8  ****/

char _wansung_to_utf8(unsigned long* chosung, unsigned long* joongsung,
				unsigned long* jongsung, unsigned short wcode)
{
	register short	h, i, j, l;
	short		ci, v, cf;
	short		disp;
	long		cfbit;

	if (wcode < 0xb0a1 || wcode > 0xc8fe)
	{  /* Hanja or special symbol */
		for (l = 0, h = MAX_E2U_NUM; l < h; )
		{
			i = (l + h) / 2;
			if (euc2utf8_tbl[i].code == wcode)
				break;
			else if (euc2utf8_tbl[l].code == wcode)
			{
				i = l;
				break;
			}
			else if (euc2utf8_tbl[h].code == wcode)
			{
				i = h;
				break;
			}
			else if (euc2utf8_tbl[i].code < wcode)
				l = i + 1;
			else
				h = i - 1;
		}

		if (euc2utf8_tbl[i].code != wcode)
			return(FAILED);

		*chosung = euc2utf8_tbl[i].utf8;
		return(HANJA_OR_SYMBOL);
	}

	if ((short)(wcode & 0xFF) < 0xA1)
		return(FAILED);

	/* Hangul processing. */
	for (h = CI_CNT, l = 0; ; )
	{
		ci = (l + h) / 2;
		if (l >= h)
			break;
		if (wcode < cmp_srchtbl[ci][0])
			h = ci - 1;
		else if (wcode < cmp_srchtbl[ci + 1][0])
			break;
		else
			l = ci + 1;
	}

	for (v = 1; ; )
	{
		if (wcode < cmp_srchtbl[ci][v])
		{
			while (!cmp_srchtbl[ci][--v])
				;
			break;
		}
		else if (v == V_CNT)
			break;
		v++;
	}

	disp = wcode - cmp_srchtbl[ci][v];
	if (((short)(cmp_srchtbl[ci][v] & BYTE_MASK) + disp) > 0xfe)
		disp -= SKIP;

	for (cfbit = cmp_bitmap[ci][v], i = -1, cf = -1; i < disp; cf++)
	{
		if (cfbit & BIT_MASK)
			i++;
		cfbit >>= 1;
	}

	if (cf == -1)
		return(FAILED);

	*chosung = 0xE18480 + ci;
	*joongsung = 0xE185A1 + v;
	/**** Original meaning is like below.
	*jongsung = (cf < 2) ? 0 <-- FILL character
			     : (cf > 25) ? 0xE18780 + cf - 26
					 : 0xE186A8 + cf - 2;
	****/
	*jongsung = (cf < 2) ? 0 : ((cf > 25) ? 0xE18766 + cf : 0xE186A6 + cf);
	return(HANGUL);
}  /* end of char _wansung_to_utf8(unsigned long*, unsigned long*,
				unsigned long*, unsigned short). */
