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
 * MODULE: dapl_cno_query.c
 *
 * PURPOSE: Return the consumer parameters of the CNO
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3.2.5
 *
 * $Id: dapl_cno_query.c,v 1.5 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_cno_query
 *
 * DAPL Requirements Version xxx, 6.3.2.5
 *
 * Return the consumer parameters of the CNO
 *
 * Input:
 *	cno_handle
 *	cno_param_mask
 *	cno_param
 *
 * Output:
 *	cno_param
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_cno_query(
	IN	DAT_CNO_HANDLE		cno_handle,	/* cno_handle */
	IN	DAT_CNO_PARAM_MASK	cno_param_mask,	/* cno_param_mask */
	OUT	DAT_CNO_PARAM 		*cno_param)	/* cno_param */
{
	DAPL_CNO	 *cno_ptr;
	DAT_RETURN   dat_status;

	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(cno_handle, DAPL_MAGIC_CNO)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CNO);
		goto bail;
	}

	/* check for invalid cno param mask */
	if (cno_param_mask & ~DAT_CNO_FIELD_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	if (NULL == cno_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	cno_ptr = (DAPL_CNO *)cno_handle;
	cno_param->ia_handle = cno_ptr->header.owner_ia;
	cno_param->agent = cno_ptr->cno_wait_agent;

bail:
	return (dat_status);
}
