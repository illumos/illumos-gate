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
 * MODULE: dapl_psp_create.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_psp_create_any.c,v 1.4 2003/06/23 12:28:05 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_sp_util.h"
#include "dapl_ia_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_psp_create_any
 *
 * uDAPL: User Direct Access Program Library Version 1.1, 6.4.3.3
 *
 * Create a persistent Public Service Point that can recieve multiple
 * requests for connections and generate multiple connection request
 * instances that wil be delivered to the specified Event Dispatcher
 * in a notification event. Differs from dapl_psp_create() in that
 * the conn_qual is selected by the implementation and returned to
 * the user.
 *
 * Input:
 * 	ia_handle
 * 	evd_handle
 * 	psp_flags
 *
 * Output:
 * 	conn_qual
 * 	psp_handle
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_CONN_QUAL_IN_USE
 * 	DAT_MODEL_NOT_SUPPORTED
 */
DAT_RETURN
dapl_psp_create_any(
	IN DAT_IA_HANDLE ia_handle,
	OUT DAT_CONN_QUAL *conn_qual,
	IN DAT_EVD_HANDLE evd_handle,
	IN DAT_PSP_FLAGS psp_flags,
	OUT DAT_PSP_HANDLE *psp_handle)
{
	DAPL_IA	*ia_ptr;
	DAPL_SP	*sp_ptr;
	DAPL_EVD *evd_ptr;
	DAT_RETURN dat_status;

	ia_ptr = (DAPL_IA *)ia_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(ia_ptr, DAPL_MAGIC_IA)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_IA);
		goto bail;
	}

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EVD_CR);
		goto bail;
	}

	if (psp_handle == NULL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG5);
		goto bail;
	}

	if (conn_qual == NULL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	/* check for invalid psp flags */
	if ((psp_flags != DAT_PSP_CONSUMER_FLAG) &&
	    (psp_flags != DAT_PSP_PROVIDER_FLAG)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4);
		goto bail;
	}

	evd_ptr = (DAPL_EVD *)evd_handle;
	if (!(evd_ptr->evd_flags & DAT_EVD_CR_FLAG)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EVD_CR);
		goto bail;
	}

	/* Allocate PSP */
	sp_ptr = dapls_sp_alloc(ia_ptr, DAT_TRUE);
	if (sp_ptr == NULL) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	/*
	 * Fill out the args for a PSP
	 */
	sp_ptr->ia_handle  = ia_handle;
	sp_ptr->evd_handle = evd_handle;
	sp_ptr->psp_flags  = psp_flags;
	sp_ptr->ep_handle  = NULL;

	/*
	 * Take a reference on the EVD handle
	 */
	dapl_os_atomic_inc(&((DAPL_EVD *)evd_handle)->evd_ref_count);

	/* Link it onto the IA */
	dapl_ia_link_psp(ia_ptr, sp_ptr);

	/*
	 * Set up a listener for a connection. Connections can arrive
	 * even before this call returns!
	 */
	sp_ptr->state = DAPL_SP_STATE_PSP_LISTENING;
	sp_ptr->listening = DAT_TRUE;

	dat_status = dapls_ib_setup_conn_listener(ia_ptr, 0, sp_ptr);

	if (dat_status != DAT_SUCCESS) {
	/*
	 * Have a problem setting up the connection, something wrong!
	 */
		dapl_os_atomic_dec(&((DAPL_EVD *)evd_handle)->evd_ref_count);
		sp_ptr->state = DAPL_SP_STATE_FREE;
		sp_ptr->listening = DAT_FALSE;
		(void) dapl_psp_free((DAT_PSP_HANDLE)sp_ptr);

		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "--> dapl_psp_create cannot set up conn listener: %x\n",
		    dat_status);

		goto bail;
	}

	/*
	 * Return handle to the user
	 */
	*conn_qual  = sp_ptr->conn_qual;
	*psp_handle = (DAT_PSP_HANDLE)sp_ptr;

bail:
	return (dat_status);
}
