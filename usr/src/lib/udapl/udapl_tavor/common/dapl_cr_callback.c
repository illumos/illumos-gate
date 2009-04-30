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
 * MODULE: dapls_cr_callback.c
 *
 * PURPOSE: implements passive side connection callbacks
 *
 * Description: Accepts asynchronous callbacks from the Communications Manager
 *              for EVDs that have been specified as the connection_evd.
 *
 * $Id: dapl_cr_callback.c,v 1.58 2003/08/20 14:55:39 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_ia_util.h"
#include "dapl_sp_util.h"
#include "dapl_ep_util.h"
#include "dapl_adapter_util.h"


/*
 * Prototypes
 */
DAT_RETURN dapli_connection_request(
	IN ib_cm_handle_t ib_cm_handle,
	IN DAPL_SP *sp_ptr,
	IN DAPL_PRIVATE	*prd_ptr,
	IN DAPL_EVD *evd_ptr);

DAPL_EP * dapli_get_sp_ep(
	IN ib_cm_handle_t ib_cm_handle,
	IN DAPL_SP *sp_ptr,
	IN const ib_cm_events_t ib_cm_event);

/*
 * dapls_cr_callback
 *
 * The callback function registered with verbs for passive side of
 * connection requests. The interface is specified by cm_api.h
 *
 *
 * Input:
 * 	ib_cm_handle,		Handle to CM
 * 	ib_cm_event		Specific CM event
 *	instant_data		Private data with DAT ADDRESS header
 * 	context			SP pointer
 *
 * Output:
 * 	None
 *
 */
void
dapls_cr_callback(
	IN ib_cm_handle_t ib_cm_handle,
	IN const ib_cm_events_t ib_cm_event,
	IN const void *private_data_ptr, /* event data */
	IN const void *context)
{
	DAPL_EP		*ep_ptr;
	DAPL_EVD	*evd_ptr;
	DAPL_SP		*sp_ptr;
	DAPL_PRIVATE	*prd_ptr;
	DAT_EVENT_NUMBER	event_type;
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_CM,
	    "--> dapls_cr_callback! context: 0x%p "
	    "event: %d cm_handle 0x%llx magic 0x%x\n",
	    context, ib_cm_event, ib_cm_handle,
	    ((DAPL_HEADER *)context)->magic);

	if (((DAPL_HEADER *)context)->magic == DAPL_MAGIC_INVALID) {
		return;
	}
	/*
	 * Passive side of the connection, context is a SP and
	 * we need to look up the EP.
	 */
	dapl_os_assert(((DAPL_HEADER *)context)->magic == DAPL_MAGIC_PSP ||
	    ((DAPL_HEADER *)context)->magic == DAPL_MAGIC_RSP);
	sp_ptr = (DAPL_SP *) context;

	/*
	 * CONNECT_REQUEST events create an event on the PSP
	 * EVD, which will trigger connection processing. The
	 * sequence is:
	 * CONNECT_REQUEST Event to SP
	 * CONNECTED Event to EP
	 * DISCONNECT Event to EP
	 *
	 * Obtain the EP if required and set an event up on the correct EVD.
	 */
	if (ib_cm_event == IB_CME_CONNECTION_REQUEST_PENDING ||
	    ib_cm_event == IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA) {
		ep_ptr = NULL;
		evd_ptr = sp_ptr->evd_handle;
	} else {
		ep_ptr = dapli_get_sp_ep(ib_cm_handle, sp_ptr, ib_cm_event);
		dapl_os_assert(ep_ptr != NULL);
		evd_ptr = (DAPL_EVD *) ep_ptr->param.connect_evd_handle;
		dapl_dbg_log(DAPL_DBG_TYPE_CM,
		    "    dapls_cr_callback cont: ep 0x%p evd 0x%p\n",
		    ep_ptr, evd_ptr);
	}

	prd_ptr = (DAPL_PRIVATE *)private_data_ptr;
	dat_status = DAT_INTERNAL_ERROR;	/* init to ERR */

	switch (ib_cm_event) {
	case IB_CME_CONNECTION_REQUEST_PENDING:
	case IB_CME_CONNECTION_REQUEST_PENDING_PRIVATE_DATA: {
		/*
		 * Requests arriving on a disabled SP are immediatly rejected
		 */

		dapl_os_lock(&sp_ptr->header.lock);
		if (sp_ptr->listening == DAT_FALSE) {
			dapl_os_unlock(&sp_ptr->header.lock);
			dapl_dbg_log(DAPL_DBG_TYPE_CM,
			"---> dapls_cr_callback: conn event on down SP\n");
			return;
		}

		if (sp_ptr->header.handle_type == DAT_HANDLE_TYPE_RSP) {
		/*
		 * RSP connections only allow a single connection. Close
		 * it down NOW so we reject any further connections.
		 */
			sp_ptr->listening = DAT_FALSE;
		}
		dapl_os_unlock(&sp_ptr->header.lock);

		/*
		 * Only occurs on the passive side of a connection
		 * dapli_connection_request will post the connection
		 * event if appropriate.
		 */
		dat_status = dapli_connection_request(ib_cm_handle,
		    sp_ptr, prd_ptr, evd_ptr);
		break;
	}
	case IB_CME_CONNECTED: {
		/*
		 * This is just a notification the connection is now
		 * established, there isn't any private data to deal with.
		 *
		 * Update the EP state and cache a copy of the cm handle,
		 * then let the user know we are ready to go.
		 */
		dapl_os_lock(&ep_ptr->header.lock);
		if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECT_PENDING) {
		/*
		 * If someone pulled the plug on the connection, just
		 * exit
		 */
			dapl_os_unlock(&ep_ptr->header.lock);
			dat_status = DAT_SUCCESS;
			break;
		}
		dapls_ib_connected(ep_ptr);
		ep_ptr->param.ep_state = DAT_EP_STATE_CONNECTED;
		ep_ptr->cm_handle = ib_cm_handle;
		dapl_os_unlock(&ep_ptr->header.lock);

		dat_status = dapls_evd_post_connection_event(
		    evd_ptr,
		    DAT_CONNECTION_EVENT_ESTABLISHED,
		    (DAT_HANDLE) ep_ptr,
		    ((DAPL_CR *)ep_ptr->cr_ptr)->param.private_data_size,
		    ((DAPL_CR *)ep_ptr->cr_ptr)->param.private_data);
		/*
		 * post them to the recv evd now.
		 * there is a race here - if events arrive after we change
		 * the ep state to connected and before we process premature
		 * events
		 */
		dapls_evd_post_premature_events(ep_ptr);
		break;
	}
	case IB_CME_DISCONNECTED:
	case IB_CME_DISCONNECTED_ON_LINK_DOWN: {
		/*
		 * EP is now fully disconnected; initiate any post processing
		 * to reset the underlying QP and get the EP ready for
		 * another connection
		 */
		dapl_os_lock(&ep_ptr->header.lock);
		if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED) {
			/* DTO error caused this */
			event_type = DAT_CONNECTION_EVENT_BROKEN;
		} else {
			ep_ptr->param.ep_state  = DAT_EP_STATE_DISCONNECTED;
			dapls_ib_disconnect_clean(ep_ptr, DAT_FALSE,
			    ib_cm_event);
			event_type = DAT_CONNECTION_EVENT_DISCONNECTED;
		}
		dapls_evd_post_premature_events(ep_ptr);

		ep_ptr->cr_ptr = NULL;
		dapl_os_unlock(&ep_ptr->header.lock);

		/*
		 * If the user has done an ep_free of the EP, we have been
		 * waiting for the disconnect event; just clean it up now.
		 */
		if (ep_ptr->header.magic == DAPL_MAGIC_EP_EXIT) {
			(void) dapl_ep_free(ep_ptr);
		}

		/* If the EP has been freed, the evd_ptr will be NULL */
		if (evd_ptr != NULL) {
			dat_status = dapls_evd_post_connection_event(
			    evd_ptr, event_type, (DAT_HANDLE) ep_ptr, 0, 0);
		}

		break;
	}
	case IB_CME_DESTINATION_REJECT:
	case IB_CME_DESTINATION_REJECT_PRIVATE_DATA:
	case IB_CME_DESTINATION_UNREACHABLE: {
		/*
		 * After posting an accept the requesting node has
		 * stopped talking.
		 */
		dapl_os_lock(&ep_ptr->header.lock);
		ep_ptr->param.ep_state  = DAT_EP_STATE_DISCONNECTED;
		ep_ptr->cm_handle = IB_INVALID_HANDLE;
		dapls_ib_disconnect_clean(ep_ptr, DAT_FALSE, ib_cm_event);
		dapl_os_unlock(&ep_ptr->header.lock);
		dat_status = dapls_evd_post_connection_event(
		    evd_ptr,
		    DAT_CONNECTION_EVENT_ACCEPT_COMPLETION_ERROR,
		    (DAT_HANDLE) ep_ptr, 0, 0);

		break;
	}
	case IB_CME_TOO_MANY_CONNECTION_REQUESTS: {
		/*
		 * DAPL does not deal with this IB error. There is a
		 * separate OVERFLOW event error if we try to post too many
		 * events, but we don't propagate this provider error.  Not
		 * all providers generate this error.
		 */
		break;
	}
	case IB_CME_LOCAL_FAILURE: {
		ep_ptr->param.ep_state  = DAT_EP_STATE_DISCONNECTED;
		dapls_ib_disconnect_clean(ep_ptr, DAT_FALSE, ib_cm_event);
		dat_status = dapls_evd_post_connection_event(
		    evd_ptr,
		    DAT_CONNECTION_EVENT_BROKEN,
		    (DAT_HANDLE) ep_ptr, 0, 0);

		break;
	}
	case IB_CME_TIMED_OUT: {
		ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECTED;
		dapls_ib_disconnect_clean(ep_ptr, DAT_FALSE, ib_cm_event);
		dat_status = dapls_evd_post_connection_event(
		    evd_ptr,
		    DAT_CONNECTION_EVENT_TIMED_OUT,
		    (DAT_HANDLE) ep_ptr, 0, 0);

		break;
	}
	default:
		dapl_os_assert(0);		/* shouldn't happen */
		break;
	}

	if (dat_status != DAT_SUCCESS) {
		/* The event post failed; take appropriate action.  */
		(void) dapls_ib_reject_connection(ib_cm_handle,
		    IB_CME_LOCAL_FAILURE, sp_ptr);
		return;
	}
}


/*
 * dapli_connection_request
 *
 * Process a connection request on the Passive side of a connection.
 * Create a CR record and link it on to the SP so we can update it
 * and free it later. Create an EP if specified by the PSP flags.
 *
 * Input:
 * 	ib_cm_handle,
 * 	sp_ptr
 * 	event_ptr
 *	prd_ptr
 *
 * Output:
 * 	None
 *
 * Returns
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_SUCCESS
 *
 */
DAT_RETURN
dapli_connection_request(
	IN  ib_cm_handle_t ib_cm_handle,
	IN  DAPL_SP *sp_ptr,
	IN  DAPL_PRIVATE *prd_ptr,
	IN  DAPL_EVD *evd_ptr)
{
	DAT_RETURN	dat_status;
	DAPL_CR		*cr_ptr;
	DAPL_EP		*ep_ptr;
	DAPL_IA		*ia_ptr;
	DAT_SP_HANDLE	sp_handle;
	struct sockaddr_in *sv4;
	struct sockaddr_in6 *sv6;
	uint8_t		*sadata;
	DAT_COUNT	length;

	cr_ptr = dapls_cr_alloc(sp_ptr->header.owner_ia);
	if (cr_ptr == NULL) {
		/* Invoking function will call dapls_ib_cm_reject() */
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	/*
	 * Set up the CR
	 */
	cr_ptr->sp_ptr = sp_ptr; /* maintain sp_ptr in case of reject */
	cr_ptr->ib_cm_handle = ib_cm_handle;
	/*
	 * Copy the remote address and private data out of the private_data
	 * payload and put them in a local structure
	 */
	cr_ptr->param.private_data = cr_ptr->private_data;
	cr_ptr->param.remote_ia_address_ptr =
	    (DAT_IA_ADDRESS_PTR)&cr_ptr->remote_ia_address;
	cr_ptr->param.remote_port_qual =
	    (DAT_PORT_QUAL) prd_ptr->hello_msg.hi_port;
	length = (DAT_COUNT) prd_ptr->hello_msg.hi_clen;
	cr_ptr->param.private_data_size = length;
	(void) dapl_os_memcpy(cr_ptr->private_data,
	    prd_ptr->private_data, length);
	switch (prd_ptr->hello_msg.hi_ipv) {
	case AF_INET:
		sv4 = (struct sockaddr_in *)&cr_ptr->remote_ia_address;
		sv4->sin_family = AF_INET;
		sv4->sin_port = prd_ptr->hello_msg.hi_port;
		sv4->sin_addr = prd_ptr->hello_msg.hi_v4ipaddr;
		break;
	case AF_INET6:
		sv6 = (struct sockaddr_in6 *)&cr_ptr->remote_ia_address;
		sv6->sin6_family = AF_INET6;
		sv6->sin6_port = prd_ptr->hello_msg.hi_port;
		sv6->sin6_addr = prd_ptr->hello_msg.hi_v6ipaddr;
		break;
	default:
		sadata = (uint8_t *)&cr_ptr->remote_ia_address;
		(void) dapl_os_memcpy(sadata, prd_ptr->hello_msg.hi_saaddr,
		    DAPL_ATS_NBYTES);
		break;
	}

	/* EP will be NULL unless RSP service point */
	ep_ptr = (DAPL_EP *) sp_ptr->ep_handle;

	if (sp_ptr->psp_flags == DAT_PSP_PROVIDER_FLAG) {
		/*
		 * Never true for RSP connections
		 *
		 * Create an EP for the user. If we can't allocate an
		 * EP we are out of resources and need to tell the
		 * requestor that we cant help them.
		 */
		ia_ptr = sp_ptr->header.owner_ia;
		ep_ptr = dapl_ep_alloc(ia_ptr, NULL, DAT_FALSE);
		if (ep_ptr == NULL) {
			dapls_cr_free(cr_ptr);
			/* Invoking function will call dapls_ib_cm_reject() */
			return (DAT_INSUFFICIENT_RESOURCES);
		}
		/* Link the EP onto the IA */
		dapl_ia_link_ep(ia_ptr, ep_ptr);
	}

	cr_ptr->param.local_ep_handle = ep_ptr;

	if (ep_ptr != NULL) {
		/* Assign valid EP fields: RSP and PSP_PROVIDER_FLAG only */
		if (sp_ptr->psp_flags == DAT_PSP_PROVIDER_FLAG) {
			ep_ptr->param.ep_state =
			    DAT_EP_STATE_TENTATIVE_CONNECTION_PENDING;
		} else { /* RSP */
			dapl_os_assert(sp_ptr->header.handle_type ==
			    DAT_HANDLE_TYPE_RSP);
			ep_ptr->param.ep_state =
			    DAT_EP_STATE_PASSIVE_CONNECTION_PENDING;
		}
		ep_ptr->cm_handle = ib_cm_handle;
	}

	/* Post the event.  */
	/* assign sp_ptr to union to avoid typecast errors from compilers */
	sp_handle.psp_handle = (DAT_PSP_HANDLE)sp_ptr;
	dat_status = dapls_evd_post_cr_arrival_event(
	    evd_ptr,
	    DAT_CONNECTION_REQUEST_EVENT,
	    sp_handle,
	    (DAT_IA_ADDRESS_PTR)&sp_ptr->header.owner_ia->hca_ptr->hca_address,
	    sp_ptr->conn_qual,
	    (DAT_CR_HANDLE)cr_ptr);
	if (dat_status != DAT_SUCCESS) {
		dapls_cr_free(cr_ptr);
		(void) dapls_ib_reject_connection(ib_cm_handle,
		    IB_CME_LOCAL_FAILURE, sp_ptr);
		return (DAT_INSUFFICIENT_RESOURCES);
	}

	/* link the CR onto the SP so we can pick it up later */
	dapl_sp_link_cr(sp_ptr, cr_ptr);

	return (DAT_SUCCESS);
}


/*
 * dapli_get_sp_ep
 *
 * Passive side of a connection is now fully established. Clean
 * up resources and obtain the EP pointer associated with a CR in
 * the SP
 *
 * Input:
 * 	ib_cm_handle,
 * 	sp_ptr
 *
 * Output:
 *	none
 *
 * Returns
 * 	ep_ptr
 *
 */
DAPL_EP *
dapli_get_sp_ep(
	IN ib_cm_handle_t ib_cm_handle,
	IN DAPL_SP *sp_ptr,
	IN const ib_cm_events_t ib_cm_event)
{
	DAPL_CR		*cr_ptr;
	DAPL_EP		*ep_ptr;

	/*
	 * There are potentially multiple connections in progress. Need to
	 * go through the list and find the one we are interested
	 * in. There is no guarantee of order. dapl_sp_search_cr
	 * leaves the CR on the SP queue.
	 */
	cr_ptr = dapl_sp_search_cr(sp_ptr, ib_cm_handle);
	if (cr_ptr == NULL) {
		dapl_os_assert(0);
		return (NULL);
	}

	ep_ptr = (DAPL_EP *)cr_ptr->param.local_ep_handle;

	dapl_os_assert(!(DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP)) ||
	    ep_ptr->header.magic == DAPL_MAGIC_EP_EXIT);

	if (ib_cm_event == IB_CME_DISCONNECTED ||
	    ib_cm_event == IB_CME_DISCONNECTED_ON_LINK_DOWN) {
		/* Remove the CR from the queue */
		dapl_sp_remove_cr(sp_ptr, cr_ptr);
		/*
		 * Last event, time to clean up and dispose of the resource
		 */
		dapls_cr_free(cr_ptr);

		/*
		 * If this SP has been removed from service, free it
		 * up after the last CR is removed
		 */
		dapl_os_lock(&sp_ptr->header.lock);
		if (sp_ptr->listening != DAT_TRUE &&
		    sp_ptr->cr_list_count == 0 &&
		    sp_ptr->state != DAPL_SP_STATE_FREE) {
			dapl_dbg_log(DAPL_DBG_TYPE_CM,
			    "--> dapli_get_sp_ep! disconnect dump sp: %p \n",
			    sp_ptr);
			sp_ptr->state = DAPL_SP_STATE_FREE;
			dapl_os_unlock(&sp_ptr->header.lock);
			(void) dapls_ib_remove_conn_listener(sp_ptr->
			    header.owner_ia, sp_ptr);
			dapls_ia_unlink_sp((DAPL_IA *)sp_ptr->header.owner_ia,
			    sp_ptr);
			dapls_sp_free_sp(sp_ptr);
		} else {
			dapl_os_unlock(&sp_ptr->header.lock);
		}
	}
	return (ep_ptr);
}
