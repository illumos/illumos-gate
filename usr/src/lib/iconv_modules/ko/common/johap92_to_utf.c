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


extern kcode_table	johap922utf8_tbl[];


/****  _ J O H A P 9 2 _ T O _ U T F 8  ****/

char _johap92_to_utf8(unsigned long* chosung, unsigned long* joongsung,
				unsigned long* jongsung, unsigned short wcode)
{
	register short	h, i, j, l;
	short		ci, v, cf;
	unsigned char	byte1, byte2;

	if (wcode > 0xD3FE)
	{  /* Hanja or special symbol */
		for (l = 0, h = MAX_J922U_NUM; l < h; )
		{
			i = (l + h) / 2;
			if (johap922utf8_tbl[i].code == wcode)
				break;
			else if (johap922utf8_tbl[l].code == wcode)
			{
				i = l;
				break;
			}
			else if (johap922utf8_tbl[h].code == wcode)
			{
				i = h;
				break;
			}
			else if (johap922utf8_tbl[i].code < wcode)
				l = i + 1;
			else
				h = i - 1;
		}

		if (johap922utf8_tbl[i].code != wcode)
			return(ILLEGAL_SEQ);

		*chosung = johap922utf8_tbl[i].utf8;
		return(HANJA_OR_SYMBOL);
	}

	/* Hangul processing. */
	byte1 = (char)((wcode >> 8) & 0xFF);
	byte2 = (char)(wcode & 0xFF);
	if (byte1 < 0x84 || byte1 > 0xD3 || byte2 < 0x41 || byte2 > 0xFE ||
	    (byte2 > 0x7E && byte2 < 0x81))
		return(ILLEGAL_SEQ);

	ci = CHOSUNG(wcode) - 2;
	v = JOONGSUNG(wcode) -
		((unsigned short)((unsigned short)JOONGSUNG(wcode) - 2) /
			((unsigned short)8) * 2 + 3);
	cf = JONGSUNG(wcode) - (unsigned short)JONGSUNG(wcode) / 18;
	*chosung = (ci < 0) ? 0xE1859F : 0xE18480 + ci;
	*joongsung = (v < 0) ? 0xE185A0 : 0xE185A1 + v;
	*jongsung = (cf < 2) ? 0 : ((cf > 25) ? 0xE18766 + cf : 0xE186A6 + cf);
	return(HANGUL);
}  /* end of char _johap92_to_utf8(unsigned long*, unsigned long*,
				unsigned long*, unsigned short). */
