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
 * MODULE: dapl_cr_reject.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_cr_reject.c,v 1.10 2003/08/18 12:00:25 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_cr_util.h"
#include "dapl_sp_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_cr_reject
 *
 * DAPL Requirements Version xxx, 6.4.2.2
 *
 * Reject a connection request from the active remote side requesting
 * an Endpoint.
 *
 * Input:
 *	cr_handle
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_cr_reject(
	IN DAT_CR_HANDLE cr_handle)
{
	DAPL_CR *cr_ptr;
	DAPL_EP *ep_ptr;
	DAT_EP_STATE entry_ep_state;
	DAT_EP_HANDLE entry_ep_handle;
	DAPL_SP	*sp_ptr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_cr_reject (%p)\n", cr_handle);

	if (DAPL_BAD_HANDLE(cr_handle, DAPL_MAGIC_CR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CR);
		goto bail;
	}

	cr_ptr = (DAPL_CR *)cr_handle;

	/*
	 * Clean up provider created EP if there is one: only if
	 * DAT_PSP_PROVIDER_FLAG was set on the PSP
	 */
	ep_ptr = (DAPL_EP *)cr_ptr->param.local_ep_handle;
	entry_ep_handle = cr_ptr->param.local_ep_handle;
	entry_ep_state  = 0;
	if (ep_ptr != NULL) {
		entry_ep_state = ep_ptr->param.ep_state;
		ep_ptr->param.ep_state = DAT_EP_STATE_UNCONNECTED;
		cr_ptr->param.local_ep_handle = NULL;
	}

	dat_status =  dapls_ib_reject_connection(cr_ptr->ib_cm_handle,
	    IB_CM_REJ_REASON_CONSUMER_REJ, cr_ptr->sp_ptr);

	if (dat_status != DAT_SUCCESS) {
		if (ep_ptr != NULL) {
			/* Revert our state to the beginning */
			ep_ptr->param.ep_state = entry_ep_state;
			cr_ptr->param.local_ep_handle = entry_ep_handle;
			cr_ptr->param.local_ep_handle = (DAT_EP_HANDLE)ep_ptr;
		}
	} else {
		/*
		 * If this EP has been allocated by the provider, clean it up;
		 * see DAT 1.1 spec, page 100, lines 3-4 (section 6.4.3.1.1.1).
		 * RSP and user-provided EPs are in the control of the user.
		 */
		sp_ptr = cr_ptr->sp_ptr;
		if (ep_ptr != NULL &&
		    sp_ptr->psp_flags == DAT_PSP_PROVIDER_FLAG) {
			(void) dapl_ep_free(ep_ptr);
		}
		/* Remove the CR from the queue, then free it */
		dapl_sp_remove_cr(cr_ptr->sp_ptr, cr_ptr);
		dapls_cr_free(cr_ptr);
	}

bail:
	return (dat_status);
}
