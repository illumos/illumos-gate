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


#include "common_def.h"
#include "common_han.h"
#include "common_utf.h"

/****  _ U T F 8 _ T O _ J O H A P 8 2 ****/

hcode_type _utf8_to_johap82(hcode_type utfcode)
{
	/* Only for Hangul character */
	hcode_type johap, unicode;

	unicode = _utf8_to_uni(utfcode);

	if ((UNICODE_HANGUL_START <= unicode.code) &&
	    (unicode.code <= UNICODE_HANGUL_END)) {
		/* Hangul Area */
		unsigned int uni, x, y, z;

		uni  = unicode.code - 0xAC00;
		x = uni / 588;
			/* 588 = 21(Joongsung Number) * 28(Jongsung Number) */
		y = (uni % 588) / 28;
		z = (uni % 588) % 28;

		johap.code = 0;
		johap.johap.msb = 1;
		johap.johap.chosung = x + 0x0A;
		johap.johap.joongsung =
			y == 0x14 ? y + 9 :
			y > 0x10 ? y + 8 :
			y > 0x0D ? y + 7 :
			y > 0x0A ? y + 6 :
			y > 0x07 ? y + 5 :
			y > 0x04 ? y + 4 :
			y > 0x01 ? y + 3 : y + 2;
		johap.johap.jongsung = z + 1;

		return(johap);

	} else {
		johap.code = NON_ID_CHAR; /* initial & default set to fail value */

		return(johap);
	}


}  /* end of hcode_type _utf8_to_johap82(hcode_type utfcode) */
