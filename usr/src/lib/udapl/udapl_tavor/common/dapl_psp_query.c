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
 * MODULE: dapl_psp_query.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_psp_query.c,v 1.8 2003/06/23 12:28:05 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_psp_query
 *
 * uDAPL: User Direct Access Program Library Version 1.1, 6.4.1.3
 *
 * Provide arguments of the public service points
 *
 * Input:
 *	psp_handle
 *	psp_args_mask
 *
 * Output:
 * 	psp_args
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_psp_query(
	IN DAT_PSP_HANDLE psp_handle,
	IN DAT_PSP_PARAM_MASK psp_args_mask,
	OUT DAT_PSP_PARAM *psp_param)
{
	DAPL_SP	*sp_ptr;
	DAT_RETURN dat_status;

	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(psp_handle, DAPL_MAGIC_PSP) ||
	    ((DAPL_SP *)psp_handle)->listening != DAT_TRUE) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PSP);
		goto bail;
	}

	if (NULL == psp_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	/* check for invalid psp param mask */
	if (psp_args_mask & ~DAT_PSP_FIELD_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
	}

	sp_ptr = (DAPL_SP *) psp_handle;

	/*
	 * Fill in the PSP params
	 */
	psp_param->ia_handle   = sp_ptr->ia_handle;
	psp_param->conn_qual   = sp_ptr->conn_qual;
	psp_param->evd_handle  = sp_ptr->evd_handle;
	psp_param->psp_flags   = sp_ptr->psp_flags;

bail:
	return (dat_status);
}
