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
#include "common_thai.h"
#include "common_utf.h"
#include "common_euc.h"
#include "utf_euc_table.h"

static int node_compare(const void *node1, const void *node2)
{
	return((int)(((const hcode_table *)node1)->utf8.code) -
	       (int)(((const hcode_table *)node2)->utf8.code));
}


/****  _ U T F 8 _ T O _ W A N S U N G  ****/

hcode_type _utf8_to_eucTH(hcode_type utfcode)
{
        hcode_table *node_ptr, node;
	hcode_type eucTH;
	int udc_index;

	/* User Definable Area Check */
	if ((udc_index = _utf_to_udcidx(utfcode)) != IDX_UDC_ERROR) {
		if (udc_index < EUC_UDC_SEG_GAP) {
			eucTH.byte.byte3 = EUC_UDC_SEG1;
			eucTH.byte.byte4 = (unsigned int)(udc_index +
						EUC_UDC_OFFSET_START);
		} else {
			eucTH.byte.byte3 = EUC_UDC_SEG2;
			eucTH.byte.byte4 = EUC_UDC_OFFSET_START +
				(unsigned int)(udc_index - EUC_UDC_SEG_GAP);
		}

		return(eucTH);
	}

        node.utf8 = utfcode;

        node_ptr = bsearch( &node,
                utf2euc_tbl, sizeof(utf2euc_tbl)/sizeof(hcode_table),
                sizeof(hcode_table), node_compare);

	eucTH.code = 0; /* initial & default set to fail value */

        if (node_ptr != NULL)
                eucTH.word.low = node_ptr->code; /* Success */

        return(eucTH);


}  /* end of hcode_type _utf8_to_eucTH(hcode_type utfcode) */
