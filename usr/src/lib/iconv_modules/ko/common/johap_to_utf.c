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


/****  _ J O H A P _ T O _ U T F 8  ****/

char _johap_to_utf8(unsigned long* chosung, unsigned long* joongsung,
				unsigned long* jongsung, unsigned short wcode)
{
	register short	h, i, j, l;
	short		ci, v, cf;

	/* Hangul only conversion. */
	if (wcode < 0xA421 || wcode > 0xF3BC)
		return(FAILED);

	ci = CHOSUNG(wcode) - 0x0A;
	v = JOONGSUNG(wcode) - ((short)JOONGSUNG(wcode) / 4 + 2);
	cf = JONGSUNG(wcode);
	if (ci > 18 || v > 20 || cf > 28)
		return(ILLEGAL_SEQ);

	*chosung = (ci < 0) ? 0xE1859F : 0xE18480 + ci;
	*joongsung = (v < 0) ? 0xE185A0 : 0xE185A1 + v;
	*jongsung = (cf < 2) ? 0 : (cf + ((cf > 25) ? 0xE18766 : 0xE186A6));
	return(HANGUL);
}  /* end of char _johap_to_utf8(unsigned long*, unsigned long*,
				unsigned long*, unsigned short). */
