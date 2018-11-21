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
#include "common_thai.h"
#include "ibm_thai_table.h"
#include "common_utf.h"
#include "common_euc.h"

static int node_compare(const void *node1, const void *node2)
{
	return(((int)(((const hcode_table *)node1)->code) -
	        (int)(((const hcode_table *)node2)->code)));
}

/****  IBM Cp838 to IBM Cp 874 ****/

hcode_type _838_to_874(hcode_type euc_code)
{
        hcode_table *node_ptr, node;
	hcode_type utf_code;
	int	udc_index;

	/* User Definable Area Check */
	/* For Thai, this if statement will not be used.*/
	/* I retain them because it's the part of the   */
	/* framework.  To maintain, look down 21 lines. */

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
			utf_code.code = 0;	/* Failed */

		return(utf_code);
	}

	/* For Thai, this function starts here	*/
	/* To change table, just change table	*/
	/* name 5 lines below.			*/

        node.code = euc_code.word.low;

        node_ptr = bsearch( &node,
                ibm838_874_tbl, sizeof(ibm838_874_tbl)/sizeof(hcode_table),
                sizeof(hcode_table), node_compare);

        if (node_ptr != NULL) /* Success */
		return(node_ptr->utf8);
	else { 			/* Failed */
		utf_code.code = 0;
		return(utf_code);
	}

}  /* end of hcode_type _874_to_838(hcode_type euc_code) */
