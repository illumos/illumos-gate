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
 * MODULE: dapl_cno_free.c
 *
 * PURPOSE: Consumer Notification Object destruction
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3.2.2
 *
 * $Id: dapl_cno_free.c,v 1.5 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_ia_util.h"
#include "dapl_cno_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_cno_free
 *
 * DAPL Requirements Version xxx, 6.3.2.2
 *
 * Destroy a consumer notification object instance
 *
 * Input:
 *	cno_handle
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INVALID_STATE
 */
DAT_RETURN
dapl_cno_free(
	IN	DAT_CNO_HANDLE		cno_handle)	/* cno_handle */
{
	DAPL_CNO    *cno_ptr;
	DAT_RETURN  dat_status;

	dat_status = DAT_SUCCESS;
	cno_ptr = (DAPL_CNO *)cno_handle;

	if (DAPL_BAD_HANDLE(cno_handle, DAPL_MAGIC_CNO)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CNO);
		goto bail;
	}

	if (cno_ptr->cno_ref_count != 0 || cno_ptr->cno_waiters != 0) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_CNO_IN_USE);
		goto bail;
	}

	dapl_os_lock(&cno_ptr->header.lock);
	if (!dapl_llist_is_empty(&cno_ptr->evd_list_head)) {
		dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		    "cno_free: evd list not empty!\n");
		dapl_os_unlock(&cno_ptr->header.lock);
		dat_status =  DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_CNO_IN_USE);
		goto bail;
	}
	dapl_os_unlock(&cno_ptr->header.lock);

	dat_status = dapls_ib_cno_free(cno_ptr);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	dapl_ia_unlink_cno(cno_ptr->header.owner_ia, cno_ptr);
	dapl_cno_dealloc(cno_ptr);

bail:
	return (dat_status);
}
