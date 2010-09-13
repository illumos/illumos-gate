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
 * MODULE: dapl_rmr_query.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 */

#include "dapl.h"

/*
 * dapl_rmr_query
 *
 * DAPL Requirements Version xxx, 6.6.4.3
 *
 * Provide the RMR arguments.
 *
 * Input:
 * 	rmr_handle
 * 	rmr_args_mask
 *
 * Output:
 * 	rmr_args
 *
 * Returns:
 * 	DAT_SUCCESS
 *      DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_rmr_query(IN DAT_RMR_HANDLE rmr_handle,
	IN DAT_RMR_PARAM_MASK rmr_param_mask,
	IN DAT_RMR_PARAM *rmr_param)
{
	DAPL_RMR *rmr;
	DAT_RETURN dat_status;

	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(rmr_handle, DAPL_MAGIC_RMR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_RMR);
		goto bail;
	}
	if (NULL == rmr_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	rmr = (DAPL_RMR *)rmr_handle;

	/* If the RMR is unbound, there is no LMR triplet associated with   */
	/* this RMR.  If the consumer requests this field, return an error. */
	if ((rmr_param_mask & DAT_RMR_FIELD_LMR_TRIPLET) &&
	    (NULL == rmr->lmr)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG2);
		goto bail;
	}

	(void) dapl_os_memcpy(rmr_param, &rmr->param, sizeof (DAT_RMR_PARAM));

bail:
	return (dat_status);
}
