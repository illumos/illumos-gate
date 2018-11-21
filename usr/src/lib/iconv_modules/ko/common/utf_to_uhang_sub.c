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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 */

#include <errno.h>
#include <stdlib.h>
#include "common_han.h"
#include "common_utf.h"
#include "common_euc.h"
#include "uni_uhang_table.h"
/* #define DEBUG	*/
/* #define DEBUG_C 	*/

static int node_compare2(const void *node1, const void *node2)
{
#ifdef DEBUG_C
	int ret;
	ret = (int)(((const hcode_table *)node1)->utf8.code) -(int)(((const hcode_table *)node2)->utf8.code);
	printf(" %d ",ret);
	return ret;
#else
/*
	return((int)(((const hcode_table *)node1)->utf8.code) -
	       (int)(((const hcode_table *)node2)->utf8.code));
*/
	return((int)(((const hcode_table *)node1)->utf8.code) -
	       (int)(((const hcode_table *)node2)->utf8.code));
#endif
}


/****  _ U T F 8 _ T O _ UNIFIED HANGUL  ****/

hcode_type _utf8_to_unified_hangul(hcode_type utfcode)
{
        hcode_table *node_ptr, node;
	hcode_type uhang;
	int udc_index;

	/* User Definable Area Check */
	if ((udc_index = _utf_to_udcidx(utfcode)) != IDX_UDC_ERROR) {
		if (udc_index < EUC_UDC_SEG_GAP) {
			uhang.byte.byte3 = EUC_UDC_SEG1;
			uhang.byte.byte4 = (unsigned int)(udc_index +
						EUC_UDC_OFFSET_START);
		} else {
			uhang.byte.byte3 = EUC_UDC_SEG2;
			uhang.byte.byte4 = EUC_UDC_OFFSET_START +
				(unsigned int)(udc_index - EUC_UDC_SEG_GAP);
		}

		return(uhang);
	}
/*
        node.utf8 = utfcode;
*/

	if(utfcode.byte.byte1 ==0 && utfcode.byte.byte2 ==0 && utfcode.byte.byte3 ==0)
		return(utfcode);

	node.utf8 = _utf8_to_uni(utfcode);


#ifdef DEBUG
	printf("*-> %2x %2x %2x*",node.utf8.unicode.data1,node.utf8.unicode.data2,node.utf8.unicode.data3);
#endif

        node_ptr = bsearch( &node,
                uni_uhang_tbl, sizeof(uni_uhang_tbl)/sizeof(hcode_table),
                sizeof(hcode_table), node_compare2);

	uhang.code = NON_ID_CHAR; /* initial & default set to fail value */

        if (node_ptr != NULL)
	{
                uhang.word.low = node_ptr->code; /* Success */
	}
#ifdef DEBUG
	else
	{
		printf("Fail in here.");
	}
#endif

        return(uhang);


}  /* end of hcode_type _utf8_to_wansung(hcode_type utfcode) */
