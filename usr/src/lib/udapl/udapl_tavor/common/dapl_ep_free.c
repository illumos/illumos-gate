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
 * MODULE: dapl_ep_free.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5.4
 *
 * $Id: dapl_ep_free.c,v 1.21 2003/07/30 18:13:37 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_ia_util.h"
#include "dapl_ep_util.h"
#include "dapl_adapter_util.h"
#include "dapl_ring_buffer_util.h"

/*
 * dapl_ep_free
 *
 * DAPL Requirements Version xxx, 6.5.3
 *
 * Destroy an instance of the Endpoint
 *
 * Input:
 *	ep_handle
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_STATE
 */
DAT_RETURN
dapl_ep_free(
	IN DAT_EP_HANDLE ep_handle)
{
	DAPL_EP	*ep_ptr;
	DAPL_IA	*ia_ptr;
	DAT_EP_PARAM *param;
	DAT_RETURN dat_status = DAT_SUCCESS;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_ep_free (%p)\n", ep_handle);

	ep_ptr = (DAPL_EP *) ep_handle;
	param = &ep_ptr->param;

	/*
	 * Verify parameter & state
	 */
	if (DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP) &&
	    !(ep_ptr->header.magic == DAPL_MAGIC_EP_EXIT &&
	    ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	if (ep_ptr->param.ep_state == DAT_EP_STATE_RESERVED ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_PASSIVE_CONNECTION_PENDING ||
	    ep_ptr->param.ep_state ==
	    DAT_EP_STATE_TENTATIVE_CONNECTION_PENDING) {
		dapl_dbg_log(DAPL_DBG_TYPE_WARN,
		    "--> dapl_ep_free: invalid state: %x, ep %p\n",
		    ep_ptr->param.ep_state, ep_ptr);
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_ptr));
		goto bail;
	}

	ia_ptr = ep_ptr->header.owner_ia;

	/*
	 * If we are connected, issue a disconnect. If we are in the
	 * disconnect_pending state, disconnect with the ABRUPT flag
	 * set.
	 */

	/*
	 * Do verification of parameters and the state change atomically.
	 */
	dapl_os_lock(&ep_ptr->header.lock);

	if (ep_ptr->param.ep_state == DAT_EP_STATE_CONNECTED ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_ACTIVE_CONNECTION_PENDING ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_COMPLETION_PENDING ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECT_PENDING) {
		/*
		 * Issue the disconnect and return. The DISCONNECT callback
		 * will invoke this routine and finish the job
		 */
		ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECT_PENDING;
		dapl_os_unlock(&ep_ptr->header.lock);

		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "--> dapl_ep_free: disconnecting EP: %x, ep %p\n",
		    ep_ptr->param.ep_state, ep_ptr);

		dat_status = dapls_ib_disconnect(ep_ptr, DAT_CLOSE_ABRUPT_FLAG);
		ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECT_PENDING;
		ep_ptr->header.magic = DAPL_MAGIC_EP_EXIT;
	} else {
		dapl_os_unlock(&ep_ptr->header.lock);
	}

	/*
	 * Release all reference counts and unlink this structure. If we
	 * got here from a callback, don't repeat this step
	 */
	if (!(ep_ptr->header.magic == DAPL_MAGIC_EP_EXIT &&
	    ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED)) {
		/* Remove link from the IA */
		dapl_ia_unlink_ep(ia_ptr, ep_ptr);
	}

	/*
	 * If the EP is disconnected tear everything down.  Otherwise,
	 * disconnect the EP but leave the QP and basic EP structure
	 * intact; the callback code will finish the job.
	 */
	dapl_os_lock(&ep_ptr->header.lock);
	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED ||
	    ep_ptr->param.ep_state == DAT_EP_STATE_UNCONNECTED) {
		/*
		 * Update ref counts. Note the user may have used ep_modify
		 * to set handles to NULL.
		 */
		if (param->pz_handle != NULL) {
			dapl_os_atomic_dec(&((DAPL_PZ *)
			    param->pz_handle)->pz_ref_count);
			param->pz_handle = NULL;
		}
		if (param->recv_evd_handle != NULL) {
			dapl_os_atomic_dec(&((DAPL_EVD *)
			    param->recv_evd_handle)->evd_ref_count);
			param->recv_evd_handle = NULL;
		}
		if (param->request_evd_handle != NULL) {
			dapl_os_atomic_dec(&((DAPL_EVD *)
			    param->request_evd_handle)->evd_ref_count);
			param->request_evd_handle = NULL;
		}
		if (param->connect_evd_handle != NULL) {
			dapl_os_atomic_dec(&((DAPL_EVD *)
			    param->connect_evd_handle)->evd_ref_count);
			param->connect_evd_handle = NULL;
		}

		if (param->srq_handle != NULL) {
			dapl_os_atomic_dec(&((DAPL_SRQ *)
			    param->srq_handle)->srq_ref_count);
			param->srq_handle = NULL;
		}

		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "--> dapl_ep_free: Free EP: %x, ep %p\n",
		    ep_ptr->param.ep_state, ep_ptr);
		/*
		 * Free the QP. If the EP has never been used,
		 * the QP is invalid
		 */
		if (ep_ptr->qp_handle != IB_INVALID_HANDLE) {
			dat_status = dapls_ib_qp_free(ia_ptr, ep_ptr);
			/*
			 * This should always succeed, but report to the user if
			 * there is a problem
			 */
			if (dat_status != DAT_SUCCESS) {
				goto bail;
			}
			ep_ptr->qp_handle = IB_INVALID_HANDLE;
		}
		dapl_os_unlock(&ep_ptr->header.lock);
		/* Free the resource */
		dapl_ep_dealloc(ep_ptr);
	} else {
		dapl_os_unlock(&ep_ptr->header.lock);
	}
bail:
	return (dat_status);

}
