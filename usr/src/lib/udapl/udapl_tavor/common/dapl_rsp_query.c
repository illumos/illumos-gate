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
 * MODULE: dapl_rsp_query.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_rsp_query.c,v 1.6 2003/06/16 17:53:34 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_rsp_query
 *
 * uDAPL: User Direct Access Program Library Version 1.1, 6.4.1.6
 *
 * Provide arguments of the reserved service points
 *
 * Input:
 *	rsp_handle
 *	rsp_args_mask
 *
 * Output:
 *	rsp_args
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_rsp_query(
	IN DAT_RSP_HANDLE rsp_handle,
	IN DAT_RSP_PARAM_MASK rsp_mask,
	OUT DAT_RSP_PARAM *rsp_param)
{
	DAPL_SP *sp_ptr;
	DAT_RETURN dat_status;

	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(rsp_handle, DAPL_MAGIC_RSP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_RSP);
		goto bail;
	}

	if (rsp_mask & ~DAT_RSP_FIELD_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	if (NULL == rsp_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	sp_ptr = (DAPL_SP *)rsp_handle;

	/*
	 * Fill in the RSP params
	 */
	rsp_param->ia_handle   = sp_ptr->ia_handle;
	rsp_param->conn_qual   = sp_ptr->conn_qual;
	rsp_param->evd_handle  = sp_ptr->evd_handle;
	rsp_param->ep_handle   = sp_ptr->ep_handle;

bail:
	return (dat_status);
}
