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
 * MODULE: dapl_cr_query.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_cr_query.c,v 1.8 2003/08/20 13:22:05 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_adapter_util.h"

/*
 * dapl_cr_query
 *
 * DAPL Requirements Version xxx, 6.4.2.1
 *
 * Return Connection Request args
 *
 * Input:
 *	cr_handle
 *	cr_param_mask
 *
 * Output:
 *	cr_param
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_HANDLE
 */

DAT_RETURN
dapl_cr_query(
	IN DAT_CR_HANDLE cr_handle,
	IN DAT_CR_PARAM_MASK cr_param_mask,
	OUT DAT_CR_PARAM *cr_param)
{
	DAPL_CR	*cr_ptr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_cr_query (%p, %x, %p)\n",
	    cr_handle, cr_param_mask, cr_param);

	dat_status = DAT_SUCCESS;
	if (DAPL_BAD_HANDLE(cr_handle, DAPL_MAGIC_CR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CR);
		goto bail;
	}

	if (NULL == cr_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG3);
		goto bail;
	}

	cr_ptr = (DAPL_CR *) cr_handle;

	/* since the arguments are easily accessible, ignore the mask */
	(void) dapl_os_memcpy(cr_param, &cr_ptr->param, sizeof (DAT_CR_PARAM));

bail:
	return (dat_status);
}
