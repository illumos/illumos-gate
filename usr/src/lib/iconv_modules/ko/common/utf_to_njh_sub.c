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


#include <errno.h>
#include <stdlib.h>
#include "common_han.h"
#include "common_utf.h"
#include "common_njh.h"
#include "utf_njh_table.h"

static int node_compare(const void *node1, const void *node2)
{
	return((int)(((const hcode_table *)node1)->utf8.code) -
	       (int)(((const hcode_table *)node2)->utf8.code));
}


/****  _ U T F 8 _ T O _ J O H A P 9 2 ****/

hcode_type _utf8_to_johap92(hcode_type utfcode)
{
        hcode_table *node_ptr, node;
	hcode_type johap, unicode;
	int udc_index;

	/* User Definable Area Check */
	if ((udc_index = _utf_to_udcidx(utfcode)) != IDX_UDC_ERROR) {

		johap.byte.byte3 = NJH_UDC_SEG;

		if (udc_index < NJH_UDC_OFFSET_GAP)
			johap.byte.byte4 = (unsigned int)(udc_index +
						NJH_UDC_OFFSET1_START);
		else
			johap.byte.byte4 = NJH_UDC_OFFSET2_START +
				(unsigned int)(udc_index - NJH_UDC_OFFSET_GAP);

		return(johap);
	}

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
		z = z > 0x10 ? z + 2 : z + 1;

		johap.code = 0;
		johap.johap.msb = 1;
		johap.johap.jongsung = z;
		johap.johap.joongsung = y > 0x10 ? y + 9 :
			y > 0x0A ? y + 7 :
			y > 0x04 ? y + 5 : y + 3;
		johap.johap.chosung = x + 2;

		return(johap);

	} else {
		/* Notes: if need hangul jamo later, add here */

	        node.utf8 = utfcode;

		node_ptr = bsearch( &node,
			utf2njh_tbl, sizeof(utf2njh_tbl)/sizeof(hcode_table),
			sizeof(hcode_table), node_compare);

		johap.code = NON_ID_CHAR; /* initial & default set to fail value */

		if (node_ptr != NULL)
			johap.word.low = node_ptr->code; /* Success */

		return(johap);
	}


}  /* end of hcode_type _utf8_to_johap92(hcode_type utfcode) */
