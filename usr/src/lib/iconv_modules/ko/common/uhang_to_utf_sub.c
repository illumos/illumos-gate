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
#include <stdio.h>
#include <stdlib.h>
#include "common_han.h"
#include "common_utf.h"
#include "common_euc.h"
#include "uhang_uni_table.h"
/* #define DEBUG	*/
/* #define DEBUG_OLD	*/
/* #define DEBUG_C	*/

static int node_compare(const void *node1, const void *node2)
{
#ifdef DEBUG_C
	int ret;
	ret = ((int)(((const hcode_table *)node1)->code) -(int)(((const hcode_table *)node2)->code));
	printf("/%d/",ret);
	return ret;
#else
	return(((int)(((const hcode_table *)node1)->code) -
	        (int)(((const hcode_table *)node2)->code)));
#endif
}

/****  UNIFIED KO to UNICODE 2.0 to UTF-8 ****/

hcode_type _unified_hangul_to_utf8(hcode_type euc_code)
{
        hcode_table *node_ptr, node;
	hcode_type utf_code;
	int	udc_index;

        /* User Definable Area Check */
        if ((EUC_UDC_SEG1 == euc_code.byte.byte3) ||
            (EUC_UDC_SEG2 == euc_code.byte.byte3)) {
                if ((euc_code.byte.byte4 < EUC_UDC_OFFSET_START) ||
                    (EUC_UDC_OFFSET_END < euc_code.byte.byte4)) {
                        /* beyond the UDC area */
                        utf_code.code = 0;

                        return(utf_code);
                }

                udc_index = (euc_code.byte.byte3 == EUC_UDC_SEG1) ?
                                0 : EUC_UDC_SEG_GAP;
                udc_index += (int)(euc_code.byte.byte4 - EUC_UDC_OFFSET_START);

                utf_code = _udcidx_to_utf(udc_index);

                if (utf_code.code == UTF_UDC_ERROR)
                        utf_code.code = UTF8_NON_ID_CHAR;       /* Failed */

                return(utf_code);
        }

        node.code = euc_code.word.low;

        node_ptr = bsearch( &node,
                uhang_uni_tbl, sizeof(uhang_uni_tbl)/sizeof(hcode_table),
                sizeof(hcode_table), node_compare);

#ifdef DEBUG
	printf("*->%2x %2x %2x*",node_ptr->utf8.unicode.data1,node_ptr->utf8.unicode.data2,node_ptr->utf8.unicode.data3);
#endif

        if (node_ptr != NULL) 	/* Success 	*/
	{
/*
		return(node_ptr->utf8);
*/

		utf_code = _uni_to_utf8(node_ptr->utf8);
#ifdef DEBUG_OLD
	printf("*->%2x%2x%2x*",utf_code.byte.byte2,utf_code.byte.byte3,utf_code.byte.byte4);
#endif

		return(utf_code);

	}
	else 			/* Failed 	*/
	{
		utf_code.code = UTF8_NON_ID_CHAR;
		return(utf_code);
	}

}  /* end of hcode_type _unified_hangul_to_utf8(hcode_type euc_code) */
