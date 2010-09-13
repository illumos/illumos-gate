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
 * MODULE: dapl_ep_connect.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_connect.c,v 1.23 2003/07/31 13:55:18 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_ep_util.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"

/*
 * dapl_ep_connect
 *
 * DAPL Requirements Version xxx, 6.5.7
 *
 * Request a connection be established between the local Endpoint
 * and a remote Endpoint. This operation is used by the active/client
 * side of a connection
 *
 * Input:
 *	ep_handle
 *	remote_ia_address
 *	remote_conn_qual
 *	timeout
 *	private_data_size
 *	privaet_data
 *	qos
 *	connect_flags
 *
 * Output:
 *	None
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOUCRES
 *	DAT_INVALID_PARAMETER
 *	DAT_MODLE_NOT_SUPPORTED
 */
DAT_RETURN
dapl_ep_connect(
	IN DAT_EP_HANDLE ep_handle,
	IN DAT_IA_ADDRESS_PTR remote_ia_address,
	IN DAT_CONN_QUAL remote_conn_qual,
	IN DAT_TIMEOUT timeout,
	IN DAT_COUNT private_data_size,
	IN const DAT_PVOID private_data,
	IN DAT_QOS qos,
	IN DAT_CONNECT_FLAGS connect_flags)
{
	DAPL_EP *ep_ptr;
	DAPL_PRIVATE prd;
	DAPL_EP	alloc_ep;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API | DAPL_DBG_TYPE_CM,
	    "dapl_ep_connect (%p, {%u.%u.%u.%u}, %X, %d, %d, %p, %x, %x)\n",
	    ep_handle,
	    remote_ia_address->sa_data[2],
	    remote_ia_address->sa_data[3],
	    remote_ia_address->sa_data[4],
	    remote_ia_address->sa_data[5],
	    remote_conn_qual,
	    timeout,
	    private_data_size,
	    private_data,
	    qos,
	    connect_flags);

	dat_status = DAT_SUCCESS;
	ep_ptr = (DAPL_EP *) ep_handle;

	/*
	 * Verify parameter & state. The connection handle must be good
	 * at this point.
	 */
	if (DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	if (DAPL_BAD_HANDLE(ep_ptr->param.connect_evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EVD_CONN);
		goto bail;
	}

	/*
	 * If the endpoint needs a QP, associated the QP with it.
	 * This needs to be done carefully, in order to:
	 *	* Avoid allocating under a lock.
	 *  * Not step on data structures being altered by
	 *    routines with which we are racing.
	 * So we:
	 *  * Confirm that a new QP is needed and is not forbidden by the
	 *    current state.
	 *  * Allocate it into a separate EP.
	 *  * Take the EP lock.
	 *  * Reconfirm that the EP is in a state where it needs a QP.
	 *  * Assign the QP and release the lock.
	 */
	if (ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED) {
		if (ep_ptr->param.pz_handle == NULL ||
		    DAPL_BAD_HANDLE(ep_ptr->param.pz_handle, DAPL_MAGIC_PZ)) {
			dat_status = DAT_ERROR(DAT_INVALID_STATE,
			    DAT_INVALID_STATE_EP_NOTREADY);
			goto bail;
		}
		alloc_ep = *ep_ptr;

		dat_status = dapls_ib_qp_alloc(ep_ptr->header.owner_ia,
		    &alloc_ep, ep_ptr);
		if (dat_status != DAT_SUCCESS) {
			dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
			    DAT_RESOURCE_MEMORY);
			goto bail;
		}

		dapl_os_lock(&ep_ptr->header.lock);
		/*
		 * PZ shouldn't have changed since we're only racing with
		 * dapl_cr_accept()
		 */
		if (ep_ptr->qp_state != DAPL_QP_STATE_UNATTACHED) {
			/* Bail, cleaning up.  */
			dapl_os_unlock(&ep_ptr->header.lock);
			dat_status = dapls_ib_qp_free(ep_ptr->header.owner_ia,
			    &alloc_ep);
			if (dat_status != DAT_SUCCESS) {
				dapl_dbg_log(DAPL_DBG_TYPE_WARN,
				    "ep_connect: ib_qp_free failed with %x\n",
				    dat_status);
			}
			dat_status = DAT_ERROR(DAT_INVALID_STATE,
			    dapls_ep_state_subtype(ep_ptr));
			goto bail;
		}
		ep_ptr->qp_handle = alloc_ep.qp_handle;
		ep_ptr->qpn = alloc_ep.qpn;
		ep_ptr->qp_state = alloc_ep.qp_state;

		dapl_os_unlock(&ep_ptr->header.lock);
	}

	/*
	 * We do state checks and transitions under lock.
	 * The only code we're racing against is dapl_cr_accept.
	 */
	dapl_os_lock(&ep_ptr->header.lock);

	/*
	 * Verify the attributes of the EP handle before we connect it. Test
	 * all of the handles to make sure they are currently valid.
	 * Specifically:
	 *   pz_handle		required
	 *   recv_evd_handle	optional, but must be valid
	 *   request_evd_handle	optional, but must be valid
	 *   connect_evd_handle	required
	 */
	if (ep_ptr->param.pz_handle == NULL ||
	    DAPL_BAD_HANDLE(ep_ptr->param.pz_handle, DAPL_MAGIC_PZ) ||
	    ep_ptr->param.connect_evd_handle == NULL ||
	    DAPL_BAD_HANDLE(ep_ptr->param.connect_evd_handle,
	    DAPL_MAGIC_EVD) ||
	    !(((DAPL_EVD *)ep_ptr->param.connect_evd_handle)->evd_flags &
	    DAT_EVD_CONNECTION_FLAG) ||
	    (ep_ptr->param.recv_evd_handle != DAT_HANDLE_NULL &&
	    (DAPL_BAD_HANDLE(ep_ptr->param.recv_evd_handle,
	    DAPL_MAGIC_EVD))) ||
	    (ep_ptr->param.request_evd_handle != DAT_HANDLE_NULL &&
	    (DAPL_BAD_HANDLE(ep_ptr->param.request_evd_handle,
	    DAPL_MAGIC_EVD)))) {
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_EP_NOTREADY);
		goto bail;
	}

	/*
	 * Check both the EP state and the QP state: if we don't have a QP
	 *  we need to attach one now.
	 */
	if (ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED) {
		dat_status = dapls_ib_qp_alloc(ep_ptr->header.owner_ia,
		    ep_ptr, ep_ptr);

		if (dat_status != DAT_SUCCESS) {
			dapl_os_unlock(&ep_ptr->header.lock);
			dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
			    DAT_RESOURCE_TEP);
			goto bail;
		}
	}

	if (ep_ptr->param.ep_state != DAT_EP_STATE_UNCONNECTED) {
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_ptr));
		goto bail;
	}

	if (qos != DAT_QOS_BEST_EFFORT ||
	    connect_flags != DAT_CONNECT_DEFAULT_FLAG) {
		/*
		 * At this point we only support one QOS level
		 */
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_MODEL_NOT_SUPPORTED, 0);
		goto bail;
	}

	/*
	 * Verify the private data size doesn't exceed the max
	 */
	if (private_data_size > DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE) {
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG5);
		goto bail;
	}

	/*
	 * transition the state before requesting a connection to avoid
	 * race conditions
	 */
	ep_ptr->param.ep_state = DAT_EP_STATE_ACTIVE_CONNECTION_PENDING;

	/*
	 * At this point we're committed, and done with the endpoint
	 * except for the connect, so we can drop the lock.
	 */
	dapl_os_unlock(&ep_ptr->header.lock);

	/*
	 * fill in the private data
	 */
	(void) dapl_os_memzero(&prd, sizeof (DAPL_PRIVATE));
	if (private_data_size > 0)
		(void) dapl_os_memcpy(prd.private_data, private_data,
		    private_data_size);

	/* Copy the connection qualifiers */
	(void) dapl_os_memcpy(ep_ptr->param.remote_ia_address_ptr,
	    remote_ia_address, sizeof (DAT_SOCK_ADDR6));
	ep_ptr->param.remote_port_qual = remote_conn_qual;

	dat_status = dapls_ib_connect(ep_handle,
	    remote_ia_address, remote_conn_qual,
	    private_data_size, &prd, timeout);

	if (dat_status != DAT_SUCCESS) {
		DAPL_EVD	*evd_ptr;

		if (dat_status == DAT_ERROR(DAT_INVALID_ADDRESS,
		    DAT_INVALID_ADDRESS_UNREACHABLE)) {
			/* Unreachable IP address */
			evd_ptr = (DAPL_EVD *)ep_ptr->param.connect_evd_handle;
			if (evd_ptr != NULL) {
				(void) dapls_evd_post_connection_event(evd_ptr,
				    DAT_CONNECTION_EVENT_UNREACHABLE,
				    (DAT_HANDLE) ep_ptr, 0, 0);
			}
			ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECTED;
			dat_status = DAT_SUCCESS;
		} else if (dat_status == DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ADDRESS_UNREACHABLE)) {
			/* Non-existant connection qualifier */
			evd_ptr = (DAPL_EVD *)ep_ptr->param.connect_evd_handle;
			if (evd_ptr != NULL) {
				(void) dapls_evd_post_connection_event(evd_ptr,
				    DAT_CONNECTION_EVENT_NON_PEER_REJECTED,
				    (DAT_HANDLE) ep_ptr, 0, 0);
			}
			ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECTED;
			dat_status = DAT_SUCCESS;
		} else {
			ep_ptr->param.ep_state = DAT_EP_STATE_UNCONNECTED;
		}
	}

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN | DAPL_DBG_TYPE_CM,
	    "dapl_ep_connect () returns 0x%x\n", dat_status);

	return (dat_status);
}
