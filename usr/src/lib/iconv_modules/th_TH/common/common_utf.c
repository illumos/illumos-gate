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


#include "common_thai.h"
#include "common_utf.h"

#define UNICODE_UDC_START	0xF700
#define UNICODE_UDC_END		0xF8FF
#define UNICODE_UDC_MAX		(UNICODE_UDC_END - UNICODE_UDC_START)

/****  _ U N I _ T O _ U T F 8  ****/

hcode_type _uni_to_utf8(hcode_type unicode)
{
        hcode_type utf8;

        utf8.utf8.high8bits = 0;
        utf8.utf8.sign1 = 0x0E;                  /* 1110xxxx */
        utf8.utf8.data1 = unicode.unicode.data1;
        utf8.utf8.sign2 = 0x02;                  /* 10xxxxxx */
        utf8.utf8.data2 = unicode.unicode.data2;
        utf8.utf8.sign3 = 0x02;                  /* 10xxxxxx */
        utf8.utf8.data3 = unicode.unicode.data3;

        return(utf8);

}  /* end of hcode_type _uni_to_utf8(hcode_type uni_code) */

/****  _ U T F 8 _ T O _ U N I  ****/

hcode_type _utf8_to_uni(hcode_type utf8)
{
        hcode_type unicode;

        unicode.code = 0;
        unicode.unicode.data1 = utf8.utf8.data1;
        unicode.unicode.data2 = utf8.utf8.data2;
        unicode.unicode.data3 = utf8.utf8.data3;

        return(unicode);

}  /* end of hcode_type _utf8_to_uni(hcode_type utf8) */

/*  Return UTF-8 code from given User Defined Character Index(Serial Number) */
hcode_type _udcidx_to_utf(int udcidx)
{
	hcode_type unicode, utf8;

	if (udcidx < 0 || UNICODE_UDC_MAX < udcidx)
		utf8.code = UTF_UDC_ERROR;	/* over the UDC bound */
	else {
		unicode.code = UNICODE_UDC_START + udcidx;
		utf8 = _uni_to_utf8(unicode);
	}

	return(utf8);
}

/*  Return User Defined Character Index(Serial Number) from given UTF-8 code */
int _utf_to_udcidx(hcode_type utf_code)
{
	hcode_type unicode;

	unicode = _utf8_to_uni(utf_code);

	if (unicode.code < UNICODE_UDC_START || UNICODE_UDC_END < unicode.code)
		return(IDX_UDC_ERROR);
	else
		return((int)(unicode.code - UNICODE_UDC_START));
}
