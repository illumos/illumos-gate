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
 * MODULE: dapl_cr_accept.c
 *
 * PURPOSE: Connection management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 4
 *
 * $Id: dapl_cr_accept.c,v 1.21 2003/08/08 19:20:05 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_adapter_util.h"

/*
 * dapl_cr_accept
 *
 * DAPL Requirements Version xxx, 6.4.2.1
 *
 * Establish a connection between active remote side requesting Endpoint
 * and passic side local Endpoint.
 *
 * Input:
 *	cr_handle
 *	ep_handle
 *	private_data_size
 *	private_data
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_ATTRIBUTE
 */
DAT_RETURN
dapl_cr_accept(
	IN	DAT_CR_HANDLE		cr_handle,
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		private_data_size,
	IN	const DAT_PVOID		private_data)
{
	DAPL_EP		*ep_ptr;
	DAT_RETURN	dat_status;
	DAPL_PRIVATE	prd;
	DAPL_CR		*cr_ptr;
	DAT_EP_STATE	entry_ep_state;
	DAT_EP_HANDLE	entry_ep_handle;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_cr_accept(%p, %p, %d, %p)\n",
	    cr_handle, ep_handle, private_data_size, private_data);

	if (DAPL_BAD_HANDLE(cr_handle, DAPL_MAGIC_CR)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_CR);
		goto bail;
	}

	cr_ptr = (DAPL_CR *) cr_handle;

	/*
	 * Return an error if we have an ep_handle and the CR already has an
	 * EP, indicating this is an RSP connection or PSP_PROVIDER_FLAG was
	 * specified.
	 */
	if (ep_handle != NULL &&
	    (DAPL_BAD_HANDLE(ep_handle, DAPL_MAGIC_EP) ||
	    cr_ptr->param.local_ep_handle != NULL)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	if ((0 != private_data_size) && (NULL == private_data)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4);
		goto bail;
	}

	/*
	 * Verify the private data size doesn't exceed the max
	 */
	if (private_data_size > DAPL_CONSUMER_MAX_PRIVATE_DATA_SIZE) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	/*
	 * ep_handle is NULL if the user specified DAT_PSP_PROVIDER_FLAG
	 * OR this is an RSP connection; retrieve it from the cr.
	 */
	if (ep_handle == NULL) {
		ep_handle = cr_ptr->param.local_ep_handle;
		if ((((DAPL_EP *) ep_handle)->param.ep_state !=
		    DAT_EP_STATE_TENTATIVE_CONNECTION_PENDING) &&
		    (((DAPL_EP *)ep_handle)->param.ep_state !=
		    DAT_EP_STATE_PASSIVE_CONNECTION_PENDING)) {
			return (DAT_INVALID_STATE);
		}
	} else {
		/* ensure this EP isn't connected or in use */
		if (((DAPL_EP *)ep_handle)->param.ep_state !=
		    DAT_EP_STATE_UNCONNECTED) {
			return (DAT_INVALID_STATE);
		}
	}

	ep_ptr = (DAPL_EP *) ep_handle;

	/*
	 * Verify the attributes of the EP handle before we connect it. Test
	 * all of the handles to make sure they are currently valid.
	 * Specifically:
	 *   pz_handle		required
	 *   recv_evd_handle	optional, but must be valid
	 *   request_evd_handle	optional, but must be valid
	 *   connect_evd_handle	required
	 * We do all verification and state change under lock, at which
	 * point the EP state should protect us from most races.
	 */
	dapl_os_lock(&ep_ptr->header.lock);
	if ((ep_ptr->param.pz_handle == NULL) ||
	    DAPL_BAD_HANDLE(ep_ptr->param.pz_handle, DAPL_MAGIC_PZ) ||
	    (ep_ptr->param.connect_evd_handle == NULL) ||
	    DAPL_BAD_HANDLE(ep_ptr->param.connect_evd_handle, DAPL_MAGIC_EVD) ||
	    !(((DAPL_EVD *)ep_ptr->param.connect_evd_handle)->evd_flags &
	    DAT_EVD_CONNECTION_FLAG) ||
	    (ep_ptr->param.recv_evd_handle != DAT_HANDLE_NULL &&
	    (DAPL_BAD_HANDLE(ep_ptr->param.recv_evd_handle, DAPL_MAGIC_EVD))) ||
	    (ep_ptr->param.request_evd_handle != DAT_HANDLE_NULL &&
	    (DAPL_BAD_HANDLE(ep_ptr->param.request_evd_handle,
	    DAPL_MAGIC_EVD)))) {
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	if (ep_ptr->qp_state == DAPL_QP_STATE_UNATTACHED) {
		/*
		 * If we are lazy attaching the QP then we may need to
		 * hook it up here. Typically, we run this code only for
		 * DAT_PSP_PROVIDER_FLAG
		 */
		dat_status = dapls_ib_qp_alloc(cr_ptr->header.owner_ia, ep_ptr,
		    ep_ptr);

		if (dat_status != DAT_SUCCESS) {
			/* This is not a great error code, but spec allows */
			dapl_os_unlock(&ep_ptr->header.lock);
			dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
			    DAT_INVALID_HANDLE_EP);
			goto bail;
		}
	}

	entry_ep_state = ep_ptr->param.ep_state;
	entry_ep_handle = cr_ptr->param.local_ep_handle;
	ep_ptr->param.ep_state = DAT_EP_STATE_COMPLETION_PENDING;
	ep_ptr->cm_handle = cr_ptr->ib_cm_handle;
	ep_ptr->cr_ptr = cr_ptr;
	ep_ptr->param.remote_ia_address_ptr = cr_ptr->param.
	    remote_ia_address_ptr;
	cr_ptr->param.local_ep_handle = ep_handle;

	/*
	 * private data
	 */
	(void) dapl_os_memcpy(prd.private_data, private_data,
	    private_data_size);
	(void) dapl_os_memzero(prd.private_data + private_data_size,
	    sizeof (DAPL_PRIVATE) - private_data_size);

	dapl_os_unlock(&ep_ptr->header.lock);

	dat_status = dapls_ib_accept_connection(cr_handle, ep_handle, &prd);

	/*
	 * If the provider failed, unwind the damage so we are back at
	 * the initial state.
	 */
	if (dat_status != DAT_SUCCESS) {
		ep_ptr->param.ep_state = entry_ep_state;
		cr_ptr->param.local_ep_handle = entry_ep_handle;
	} else {
		/*
		 * Make this CR invalid. We need to hang on to it until
		 * the connection terminates, but it's destroyed from
		 * the app point of view.
		 */
		cr_ptr->header.magic = DAPL_MAGIC_CR_DESTROYED;
	}

bail:
	return (dat_status);
}
