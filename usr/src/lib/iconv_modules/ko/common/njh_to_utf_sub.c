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
#include "njh_utf_table.h"

static int node_compare(const void *node1, const void *node2)
{
	return(((int)(((const hcode_table *)node1)->code) -
	        (int)(((const hcode_table *)node2)->code)));
}

/****  _ J O H A P 9 2 _ T O _ U T F 8  ****/

hcode_type _johap92_to_utf8(hcode_type njh_code)
{
        hcode_table *node_ptr, node;
	hcode_type utf_code;
	int	udc_index;

	/* User Definable Area Check */
	if (njh_code.byte.byte3 == NJH_UDC_SEG) {
		if ((njh_code.byte.byte4 < NJH_UDC_OFFSET1_START) ||
		    (NJH_UDC_OFFSET2_END < njh_code.byte.byte4) ||
		    ((NJH_UDC_OFFSET1_END < njh_code.byte.byte4) &&
		     (njh_code.byte.byte4 < NJH_UDC_OFFSET2_START))) {
			/* beyond the UDC area */
			utf_code.code = 0;

			return(utf_code);
		}

		if (njh_code.byte.byte4 >= NJH_UDC_OFFSET2_START)
			udc_index = NJH_UDC_OFFSET_GAP +
				(int)(njh_code.byte.byte4 - NJH_UDC_OFFSET2_START);
		else
			udc_index =
				(int)(njh_code.byte.byte4 - NJH_UDC_OFFSET1_START);

		utf_code = _udcidx_to_utf(udc_index);

		if (utf_code.code == UTF_UDC_ERROR)
			utf_code.code = UTF8_NON_ID_CHAR;	/* Failed */

		return(utf_code);

	} else if (njh_code.code > NJH_HANGUL_END) {
		/* Hanja or special symbol */
		/* Notes: if Hangul Jamo needed, add here to table coversion */

		node.code = njh_code.word.low;

		node_ptr = bsearch( &node,
			njh2utf_tbl, sizeof(njh2utf_tbl)/sizeof(hcode_table),
			sizeof(hcode_table), node_compare);

		if (node_ptr != NULL) /* Success */
			return(node_ptr->utf8);
		else { 			/* Failed */
			utf_code.code = UTF8_NON_ID_CHAR;
			return(utf_code);
		}

	} else {
		/* Hangul code */
		hcode_type unicode;
		register unsigned int x, y, z;

		x = njh_code.johap.chosung - 2;  /* 2 = 'Kyoug' */
		y = njh_code.johap.joongsung;
		y = y < 0x08 ? y - 3 :
			y < 0x10 ? y - 5 :
			y < 0x18 ? y - 7 : y - 9;
		z = njh_code.johap.jongsung;
		z = z < 0x12 ? z - 1 : z - 2;
		unicode.code = (unsigned int)(x*588 + y*28 + z)
				+ 0xAC00;
			/* 588 = 21(Joongsung Number) * 28(Jongsung Number) */

		utf_code = _uni_to_utf8(unicode);

		return(utf_code);

	}

}  /* end of hcode_type johap92_to_utf8(hcode_type njh_code) */
