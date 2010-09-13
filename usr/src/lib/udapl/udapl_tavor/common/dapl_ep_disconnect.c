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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_ep_disconnect.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_disconnect.c,v 1.15 2003/07/30 18:13:37 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_ia_util.h"
#include "dapl_ep_util.h"
#include "dapl_evd_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_ep_disconnect
 *
 * DAPL Requirements Version xxx, 6.5.9
 *
 * Terminate a connection.
 *
 * Input:
 *	ep_handle
 *	disconnect_flags
 *
 * Output:
 *	None
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_ep_disconnect(
	IN DAT_EP_HANDLE ep_handle,
	IN DAT_CLOSE_FLAGS disconnect_flags)
{
	DAPL_EP *ep_ptr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API | DAPL_DBG_TYPE_CM,
	    "dapl_ep_disconnect (%p, %x)\n", ep_handle, disconnect_flags);

	ep_ptr = (DAPL_EP *) ep_handle;

	/*
	 * Verify parameter & state
	 */
	if (DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	/*
	 * Do the verification of parameters and the state change
	 * atomically.
	 */
	dapl_os_lock(&ep_ptr->header.lock);

	/*
	 * Check the EP state to ensure we are queiscent. Note that
	 * we may get called in UNCONNECTED state in order to remove
	 * RECV requests from the queue prior to destroying an EP.
	 * See the states in the spec at 6.5.1 Endpont Lifecycle
	 */

	if (ep_ptr->param.ep_state != DAT_EP_STATE_CONNECTED &&
	    ep_ptr->param.ep_state != DAT_EP_STATE_DISCONNECTED &&
	    ep_ptr->param.ep_state != DAT_EP_STATE_ACTIVE_CONNECTION_PENDING &&
	    ep_ptr->param.ep_state != DAT_EP_STATE_COMPLETION_PENDING &&
	    ep_ptr->param.ep_state != DAT_EP_STATE_DISCONNECT_PENDING) {
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_ptr));
		goto bail;
	}

	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED) {
		/*
		 * Calling disconnect when DISCONNECTED is a NOOP, just return
		 * good.
		 */
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_SUCCESS;
		goto bail;
	}

	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECT_PENDING &&
	    disconnect_flags != DAT_CLOSE_ABRUPT_FLAG) {
		/*
		 * If in state DISCONNECT_PENDING then this must be an
		 * ABRUPT disconnect
		 */
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	if (ep_ptr->param.ep_state == DAT_EP_STATE_ACTIVE_CONNECTION_PENDING ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_COMPLETION_PENDING) {
		/*
		 * transition ep_state to DISCONNECT_PENDING
		 */
		ep_ptr->param.ep_state  = DAT_EP_STATE_DISCONNECT_PENDING;
		dapl_os_unlock(&ep_ptr->header.lock);
		dapls_ib_disconnect_clean(ep_ptr, DAT_TRUE,
		    IB_CME_CONNECTION_REQUEST_PENDING);

		/*
		 * we do not have to post an event here.
		 * the CM will generate one.
		 */
		dat_status = DAT_SUCCESS;
		goto bail;
	}

	/*
	 * Transition the EP state to DISCONNECT_PENDING if we are
	 * CONNECTED. Otherwise we do not get a disconnect event and will be
	 * stuck in DISCONNECT_PENDING.
	 *
	 * If the user specifies a graceful disconnect, the underlying
	 * provider should complete all DTOs before disconnecting; in IB
	 * terms, this means setting the QP state to SQD before completing
	 * the disconnect state transitions.
	 */
	if (ep_ptr->param.ep_state == DAT_EP_STATE_CONNECTED) {
		ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECT_PENDING;
	}
	dapl_os_unlock(&ep_ptr->header.lock);
	dat_status = dapls_ib_disconnect(ep_ptr, disconnect_flags);

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN | DAPL_DBG_TYPE_CM,
	    "dapl_ep_disconnect () returns 0x%x\n", dat_status);

	return (dat_status);
}
