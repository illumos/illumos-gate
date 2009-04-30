/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_lmr_query.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 */

#include "dapl.h"

/*
 * dapl_lmr_query
 *
 * DAPL Requirements Version xxx, 6.6.3.3
 *
 * Provide the LMR arguments.
 *
 * Input:
 * 	lmr_handle
 * 	lmr_param_mask
 *	lmr_param
 *
 * Output:
 * 	lmr_param
 *
 * Returns:
 * 	DAT_SUCCESS
 *      DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_lmr_query(IN DAT_LMR_HANDLE lmr_handle,
	IN DAT_LMR_PARAM_MASK lmr_param_mask,
	IN DAT_LMR_PARAM *lmr_param)
{
	DAPL_LMR *lmr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_lmr_query (%p, 0x%x, %p)\n",
	    lmr_handle, lmr_param_mask, lmr_param);

	if (DAPL_BAD_HANDLE(lmr_handle, DAPL_MAGIC_LMR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_LMR);
		goto bail;
	}
	if (NULL == lmr_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG3);
		goto bail;
	}

	dat_status = DAT_SUCCESS;
	lmr = (DAPL_LMR *) lmr_handle;

	(void) dapl_os_memcpy(lmr_param, &lmr->param, sizeof (DAT_LMR_PARAM));

bail:
	return (dat_status);
}
