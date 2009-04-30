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
 * MODULE: dapl_pz_query.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 * $Id: dapl_pz_query.c,v 1.6 2003/07/30 18:13:40 hobie16 Exp $
 */

#include "dapl.h"

/*
 * dapl_pz_query
 *
 * DAPL Requirements Version xxx, 6.6.2.1
 *
 * Return the ia associated with the protection zone pz
 *
 * Input:
 * 	pz_handle
 *      pz_param_mask
 *
 * Output:
 * 	pz_param
 *
 * Returns:
 * 	DAT_SUCCESS
 *      DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_pz_query(
	IN	DAT_PZ_HANDLE		pz_handle,
	IN	DAT_PZ_PARAM_MASK	pz_param_mask,
	OUT	DAT_PZ_PARAM		*pz_param)
{
	DAPL_PZ		*pz;
	DAT_RETURN	dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_pz_query (%p, %x, %p)\n",
	    pz_handle,
	    pz_param_mask,
	    pz_param);

	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(pz_handle, DAPL_MAGIC_PZ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PZ);
		goto bail;
	}
	if (NULL == pz_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}
	if (pz_param_mask & ~DAT_PZ_FIELD_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	pz = (DAPL_PZ *) pz_handle;

	/* Since the DAT_PZ_ARGS values are easily accessible, */
	/* don't bother checking the DAT_PZ_ARGS_MASK value    */
	pz_param->ia_handle = (DAT_IA_HANDLE) pz->header.owner_ia;

bail:
	return (dat_status);
}
