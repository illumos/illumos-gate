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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 */


#include "common_han.h"
#include "common_utf.h"

/****  _ J O H A P 8 2 _ T O _ U T F 8  ****/

hcode_type _johap82_to_utf8(hcode_type ojh_code)
{
	/* Only for Hangul code */
	hcode_type utf_code;
	hcode_type unicode;
	unsigned int x, y, z;

        /* Hangul only conversion. */
        if (ojh_code.code < 0xA421 || 0xF3BC < ojh_code.code) {
		utf_code.code = 0;	/* Not Hangul */
		return(utf_code);
	}

	x = ojh_code.johap.chosung - 0x0A;  /* 0x0A = 'Kyoug' */
	y = ojh_code.johap.joongsung;
	y = y - (y / 4 + 2);
	z = ojh_code.johap.jongsung - 1;

	if (x > 18 || y > 20 || z > 29) {
		utf_code.code = 0;	/* Not Hangul */
		return(utf_code);
	}

	unicode.code = (unsigned int)(x*588 + y*28 + z)
			+ 0xAC00;
		/* 588 = 21(Joongsung Number) * 28(Jongsung Number) */

	utf_code = _uni_to_utf8(unicode);

	return(utf_code);

}  /* end of hcode_type johap82_to_utf8(hcode_type ojh_code) */
