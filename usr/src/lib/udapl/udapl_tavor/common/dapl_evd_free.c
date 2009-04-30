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
 * MODULE: dapl_evd_free.c
 *
 * PURPOSE: Event management
 * Description: Interfaces in this file are completely described in
 *        the DAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_free.c,v 1.9 2003/07/30 18:13:38 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_evd_util.h"
#include "dapl_ia_util.h"

/*
 * dapl_evd_free
 *
 * DAPL Requirements Version xxx, 6.3.2.2
 *
 * Destroy a specific instance of the Event Dispatcher
 *
 * Input:
 *     evd_handle
 *
 * Output:
 *     None
 *
 * Returns:
 *     DAT_SUCCESS
 *     DAT_INVALID_HANDLE
 *     DAT_INVALID_STATE
 */
DAT_RETURN
dapl_evd_free(
	IN    DAT_EVD_HANDLE    evd_handle)
{
	DAPL_EVD    *evd_ptr;
	DAT_RETURN  dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_evd_free (%p)\n", evd_handle);

	dat_status = DAT_SUCCESS;
	evd_ptr = (DAPL_EVD *)evd_handle;

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}

	if (evd_ptr->evd_ref_count != 0) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_EVD_IN_USE);
		goto bail;
	}

	dapl_ia_unlink_evd(evd_ptr->header.owner_ia, evd_ptr);

	dat_status = dapls_evd_dealloc(evd_ptr);
	if (dat_status != DAT_SUCCESS) {
		dapl_ia_link_evd(evd_ptr->header.owner_ia, evd_ptr);
	}
bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_evd_free () returns 0x%x\n",
	    dat_status);

	return (dat_status);
}
