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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_evd_modify_cno.c
 *
 * PURPOSE: Event Management
 *
 * Description: Interfaces in this file are completely described in
 * 		the DAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_modify_cno.c,v 1.10 2003/07/14 17:50:32 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_adapter_util.h"

/*
 * dapl_evd_modify_cno
 *
 * DAPL Requirements Version xxx, 6.3.2.4
 *
 * Modify the CNO associated with the EVD
 *
 * Input:
 * 	evd_handle
 * 	cno_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCSSS
 * 	DAT_INVALID_HANDLE
 */

DAT_RETURN
dapl_evd_modify_cno(
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_CNO_HANDLE		cno_handle)
{
	DAPL_EVD	*evd_ptr;
	DAPL_CNO	*cno_ptr;
	DAPL_CNO	*old_cno_ptr;
	DAT_RETURN	dat_status;

	evd_ptr = (DAPL_EVD *)evd_handle;
	cno_ptr = (DAPL_CNO *)cno_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}

	/* cno_handle of DAT_HANDLE_NULL disassociated the EVD with any CNO */
	if ((cno_handle != DAT_HANDLE_NULL) &&
	    DAPL_BAD_HANDLE(cno_handle, DAPL_MAGIC_CNO)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CNO);
		goto bail;
	}

	/* nothing to change */
	if (cno_ptr == evd_ptr->cno_ptr) {
		dat_status = DAT_SUCCESS;
		goto bail;
	}

	if (dapls_ib_modify_cno(evd_ptr, cno_ptr) != DAT_SUCCESS) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}

	dapl_os_lock(&evd_ptr->header.lock);
	old_cno_ptr = evd_ptr->cno_ptr;
	evd_ptr->cno_ptr = cno_ptr;
	dapl_os_unlock(&evd_ptr->header.lock);

	/*
	 * We need to first remove the evd from the old CNO's list before
	 * adding it to the new CNO's list
	 */
	if (old_cno_ptr) {
		dapl_os_lock(&(old_cno_ptr->header.lock));
		(void) dapl_llist_remove_entry(&old_cno_ptr->evd_list_head,
		    &evd_ptr->cno_list_entry);
		dapl_os_atomic_dec(&(old_cno_ptr->cno_ref_count));
		dapl_os_unlock(&(old_cno_ptr->header.lock));

	}

	if (cno_ptr) {
		dapl_os_lock(&(cno_ptr->header.lock));
		dapl_llist_add_head(&cno_ptr->evd_list_head,
		    &evd_ptr->cno_list_entry, evd_ptr);
		/* Take a reference count on the CNO */
		dapl_os_atomic_inc(&(cno_ptr->cno_ref_count));
		dapl_os_unlock(&cno_ptr->header.lock);
	}

	/*
	 * We need to enable the callback handler if the EVD has a CQ associated
	 * to it and is enabled.
	 */
	if ((evd_ptr->evd_flags & (DAT_EVD_DTO_FLAG | DAT_EVD_RMR_BIND_FLAG)) &&
	    evd_ptr->evd_enabled && cno_handle != DAT_HANDLE_NULL) {
		dat_status = DAPL_NOTIFY(evd_ptr)(
		    evd_ptr->ib_cq_handle, IB_NOTIFY_ON_NEXT_COMP, 0);

		/* FIXME report error */
		dapl_os_assert(dat_status == DAT_SUCCESS);
	}

bail:
	return (dat_status);
}
