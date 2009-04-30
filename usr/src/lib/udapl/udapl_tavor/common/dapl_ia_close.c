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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_ia_close.c
 *
 * PURPOSE: Interface Adapter management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 2
 *
 * $Id: dapl_ia_close.c,v 1.9 2003/07/30 18:13:38 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_ia_util.h"

/*
 * dapl_ia_close
 *
 * DAPL Requirements Version xxx, 6.2.1.2
 *
 * Close a provider, clean up resources, etc.
 *
 * Input:
 *	ia_handle
 *
 * Output:
 *	none
 *
 * Return Values:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_ia_close(
	IN	DAT_IA_HANDLE	ia_handle,
	IN	DAT_CLOSE_FLAGS ia_flags)
{
	DAPL_IA			*ia_ptr;
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_ia_close (%p, %d)\n",
	    ia_handle,
	    ia_flags);

	ia_ptr = (DAPL_IA *)ia_handle;

	if (DAPL_BAD_HANDLE(ia_ptr, DAPL_MAGIC_IA)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_IA);
		goto bail;
	}

	if (DAT_CLOSE_ABRUPT_FLAG == ia_flags) {
		dat_status = dapl_ia_abrupt_close(ia_ptr);
	} else if (DAT_CLOSE_GRACEFUL_FLAG == ia_flags) {
		dat_status = dapl_ia_graceful_close(ia_ptr);
	} else {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG2);
	}

bail:
	return (dat_status);
}
