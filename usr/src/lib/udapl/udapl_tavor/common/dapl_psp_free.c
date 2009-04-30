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
 * MODULE: dapl_psp_free.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_psp_free.c,v 1.17 2003/07/25 19:24:11 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_sp_util.h"
#include "dapl_ia_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_psp_free
 *
 * uDAPL: User Direct Access Program Library Version 1.1, 6.4.1.2
 *
 * Destroy a specific instance of a Service Point.
 *
 * Input:
 * 	psp_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_psp_free(
	IN DAT_PSP_HANDLE psp_handle)
{
	DAPL_IA *ia_ptr;
	DAPL_SP *sp_ptr;
	DAT_RETURN dat_status;

	sp_ptr = (DAPL_SP *) psp_handle;
	dat_status = DAT_SUCCESS;
	/*
	 * Verify handle
	 */
	dapl_dbg_log(DAPL_DBG_TYPE_CM, ">>> dapl_psp_free %p\n", psp_handle);

	if (DAPL_BAD_HANDLE(sp_ptr, DAPL_MAGIC_PSP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PSP);
		goto bail;
	}

	/* ia_ptr = (DAPL_IA *)sp_ptr->header.owner_ia; */
	ia_ptr = sp_ptr->header.owner_ia;
	/*
	 * Remove the connection listener if it has been established
	 * and there are no current connections in progress.
	 * If we defer removing the sp it becomes something of a zombie
	 * container until the last connection is disconnected, after
	 * which it will be cleaned up.
	 */
	dapl_os_lock(&sp_ptr->header.lock);
	sp_ptr->listening = DAT_FALSE;
	/*
	 * Release reference on EVD.
	 * If an error was encountered in a previous
	 * free the evd_handle will be NULL
	 */
	if (sp_ptr->evd_handle) {
		dapl_os_atomic_dec(&((DAPL_EVD *)sp_ptr->evd_handle)->
		    evd_ref_count);
		sp_ptr->evd_handle = NULL;
	}
	/*
	 * Release the base resource if there are no outstanding
	 * connections; else the last disconnect on this PSP will free it
	 * up. The PSP is used to contain CR records for each connection,
	 * which contain information necessary to disconnect.
	 */
	if ((sp_ptr->state == DAPL_SP_STATE_PSP_LISTENING) &&
	    (sp_ptr->cr_list_count == 0)) {
		sp_ptr->state = DAPL_SP_STATE_FREE;
		dapl_os_unlock(&sp_ptr->header.lock);
		dat_status = dapls_ib_remove_conn_listener(ia_ptr, sp_ptr);
		if (dat_status != DAT_SUCCESS) {
			/* revert to entry state on error */
			sp_ptr->state = DAPL_SP_STATE_PSP_LISTENING;
			goto bail;
		}
		dapls_ia_unlink_sp(ia_ptr, sp_ptr);
		dapls_sp_free_sp(sp_ptr);
	} else {
	/*
	 * The PSP is now in the pending state, where it will sit until
	 * the last connection terminates or the app uses the same
	 * ServiceID again, which will reactivate it.
	 */
		sp_ptr->state = DAPL_SP_STATE_PSP_PENDING;
		dapl_os_unlock(&sp_ptr->header.lock);
	}

bail:
	return (dat_status);
}
