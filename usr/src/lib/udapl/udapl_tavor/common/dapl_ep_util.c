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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_ep_util.c
 *
 * PURPOSE: Manage EP Info structure
 *
 * $Id: dapl_ep_util.c,v 1.36 2003/08/04 16:50:27 sjs2 Exp $
 */

#include "dapl_ep_util.h"
#include "dapl_ring_buffer_util.h"
#include "dapl_cookie.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_ia_util.h"

/*
 * Local definitions
 */
/*
 * Default number of I/O operations on an end point
 */
#define	IB_IO_DEFAULT	16
/*
 * Default number of scatter/gather entries available to a single
 * post send/recv
 */
#define	IB_IOV_DEFAULT	4

/*
 * Default number of RDMA operations in progress at a time
 */
#define	IB_RDMA_DEFAULT	4

extern void dapli_ep_default_attrs(
    IN DAPL_EP			*ep_ptr);


/*
 * dapl_ep_alloc
 *
 * alloc and initialize an EP INFO struct
 *
 * Input:
 * 	IA INFO struct ptr
 *
 * Output:
 * 	ep_ptr
 *
 * Returns:
 * 	none
 *
 */
DAPL_EP *
dapl_ep_alloc(
	IN DAPL_IA		*ia_ptr,
	IN const DAT_EP_ATTR	*ep_attr,
	IN DAT_BOOLEAN		srq_attached)
{
	DAPL_EP	*ep_ptr;

	/* Allocate EP */
	ep_ptr = (DAPL_EP *)dapl_os_alloc(sizeof (DAPL_EP));
	if (ep_ptr == NULL) {
		goto bail;
	}

	/* zero the structure */
	(void) dapl_os_memzero(ep_ptr, sizeof (DAPL_EP));

	/*
	 * initialize the header
	 */
	ep_ptr->header.provider		= ia_ptr->header.provider;
	ep_ptr->header.magic		= DAPL_MAGIC_EP;
	ep_ptr->header.handle_type	= DAT_HANDLE_TYPE_EP;
	ep_ptr->header.owner_ia			= ia_ptr;
	ep_ptr->header.user_context.as_64	= 0;
	ep_ptr->header.user_context.as_ptr	= NULL;
	dapl_llist_init_entry(&ep_ptr->header.ia_list_entry);
	dapl_os_lock_init(&ep_ptr->header.lock);

	/*
	 * Initialize the body
	 */
	(void) dapl_os_memzero(&ep_ptr->param, sizeof (DAT_EP_PARAM));
	ep_ptr->param.ep_state = DAT_EP_STATE_UNCONNECTED;
	ep_ptr->param.local_ia_address_ptr =
	    (DAT_IA_ADDRESS_PTR)&ia_ptr->hca_ptr->hca_address;

	/* Set the remote address pointer */
	ep_ptr->param.remote_ia_address_ptr =
	    (DAT_IA_ADDRESS_PTR) &ep_ptr->remote_ia_address;

	/*
	 * Set up default parameters if the user passed in a NULL
	 */
	if (ep_attr == NULL) {
		dapli_ep_default_attrs(ep_ptr);
	} else {
		ep_ptr->param.ep_attr = *ep_attr;
	}

	/*
	 * IBM OS API specific fields
	 */
	ep_ptr->qp_handle	= IB_INVALID_HANDLE;
	ep_ptr->qpn		= 0;
	ep_ptr->qp_state	= DAPL_QP_STATE_UNATTACHED;
	ep_ptr->cm_handle	= IB_INVALID_HANDLE;

	ep_ptr->req_count = 0;
	ep_ptr->recv_count = 0;

	ep_ptr->srq_attached = srq_attached;

	if (DAT_SUCCESS != dapls_cb_create(&ep_ptr->req_buffer, ep_ptr,
	    DAPL_COOKIE_QUEUE_EP, ep_ptr->param.ep_attr.max_request_dtos)) {
		dapl_ep_dealloc(ep_ptr);
		ep_ptr = NULL;
		goto bail;
	}

	if (!srq_attached) {
		if (DAT_SUCCESS != dapls_cb_create(&ep_ptr->recv_buffer, ep_ptr,
		    DAPL_COOKIE_QUEUE_EP,
		    ep_ptr->param.ep_attr.max_recv_dtos)) {
			dapl_ep_dealloc(ep_ptr);
			ep_ptr = NULL;
			goto bail;
		}
	}

bail:
	return (ep_ptr);
}


/*
 * dapl_ep_dealloc
 *
 * Free the passed in EP structure.
 *
 * Input:
 * 	entry point pointer
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapl_ep_dealloc(
	IN DAPL_EP		*ep_ptr)
{
	dapl_os_assert(ep_ptr->header.magic == DAPL_MAGIC_EP ||
	    ep_ptr->header.magic == DAPL_MAGIC_EP_EXIT);

	/* reset magic to prevent reuse */
	ep_ptr->header.magic = DAPL_MAGIC_INVALID;

	dapls_cb_free(&ep_ptr->req_buffer);
	dapls_cb_free(&ep_ptr->recv_buffer);

	dapl_os_free(ep_ptr, sizeof (DAPL_EP));
}


/*
 * dapl_ep_default_attrs
 *
 * Set default values in the parameter fields
 *
 * Input:
 * 	entry point pointer
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	none
 *
 */
void
dapli_ep_default_attrs(
	IN DAPL_EP		*ep_ptr)
{
	DAT_EP_ATTR		*ep_attr;

	ep_attr = &ep_ptr->param.ep_attr;
	/* Set up defaults */
	(void) dapl_os_memzero(ep_attr, sizeof (DAT_EP_ATTR));

	/*
	 * mtu and rdma sizes fixed in IB as per IBTA 1.1, 9.4.3, 9.4.4,
	 * 9.7.7.
	 */
	ep_attr->max_mtu_size	= 0x80000000;
	ep_attr->max_rdma_size	= 0x80000000;

	ep_attr->qos		= DAT_QOS_BEST_EFFORT;
	ep_attr->service_type	= DAT_SERVICE_TYPE_RC;
	ep_attr->max_recv_dtos	= IB_IO_DEFAULT;
	ep_attr->max_request_dtos	= IB_IO_DEFAULT;
	ep_attr->max_recv_iov		= IB_IOV_DEFAULT;
	ep_attr->max_request_iov	= IB_IOV_DEFAULT;
	ep_attr->max_rdma_read_in	= IB_RDMA_DEFAULT;
	ep_attr->max_rdma_read_out	= IB_RDMA_DEFAULT;

	ep_attr->request_completion_flags = DAT_COMPLETION_EVD_THRESHOLD_FLAG;
	ep_attr->recv_completion_flags    = DAT_COMPLETION_EVD_THRESHOLD_FLAG;
	/*
	 * Unspecified defaults:
	 *    - ep_privileges: No RDMA capabilities
	 *    - num_transport_specific_params: none
	 *    - transport_specific_params: none
	 *    - num_provider_specific_params: 0
	 *    - provider_specific_params: 0
	 */
}


DAT_RETURN
dapl_ep_check_recv_completion_flags(
	DAT_COMPLETION_FLAGS	flags)
{

	/*
	 * InfiniBand will not allow unsignaled/suppressed RECV completions,
	 * see the 1.0.1 spec section 10.7.3.1, 10.8.6
	 */

	if ((flags & DAT_COMPLETION_UNSIGNALLED_FLAG) ||
	    (flags & DAT_COMPLETION_SUPPRESS_FLAG)) {
		return (DAT_INVALID_PARAMETER);
	}

	return (DAT_SUCCESS);
}

/* ARGSUSED */
DAT_RETURN
dapl_ep_check_request_completion_flags(
	DAT_COMPLETION_FLAGS	flags)
{
	return (DAT_SUCCESS);
}

DAT_RETURN
dapl_ep_check_qos(
	DAT_QOS	qos)
{
	if (qos & ~(DAT_QOS_BEST_EFFORT | DAT_QOS_HIGH_THROUGHPUT |
	    DAT_QOS_LOW_LATENCY | DAT_QOS_ECONOMY | DAT_QOS_PREMIUM)) {
		return (DAT_INVALID_PARAMETER);
	}
	return (DAT_SUCCESS);
}

DAT_RETURN
dapl_ep_post_send_req(
    IN	DAT_EP_HANDLE		ep_handle,
    IN	DAT_COUNT		num_segments,
    IN	DAT_LMR_TRIPLET		*local_iov,
    IN	DAT_DTO_COOKIE		user_cookie,
    IN	const DAT_RMR_TRIPLET	*remote_iov,
    IN	DAT_COMPLETION_FLAGS	completion_flags,
    IN  DAPL_DTO_TYPE 		dto_type,
    IN  ib_send_op_type_t	op_type)
{
	DAPL_EP 		*ep;
	DAPL_COOKIE		*cookie;
	DAT_RETURN		dat_status;

	if (DAPL_BAD_HANDLE(ep_handle, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	ep = (DAPL_EP *)ep_handle;

	/*
	 * Synchronization ok since this buffer is only used for send
	 * requests, which aren't allowed to race with each other.
	 */
	dat_status = dapls_dto_cookie_alloc(&ep->req_buffer,
	    dto_type,
	    user_cookie,
	    &cookie);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	/*
	 * Invoke provider specific routine to post DTO
	 */
	if (num_segments != 1 ||
	    completion_flags != DAT_COMPLETION_DEFAULT_FLAG)
		dat_status = dapls_ib_post_send(ep,
		    op_type,
		    cookie,
		    num_segments,
		    local_iov,
		    remote_iov,
		    completion_flags);
	else
		dat_status = dapls_ib_post_send_one(ep,
		    op_type,
		    cookie,
		    local_iov,
		    remote_iov);

	if (dat_status != DAT_SUCCESS) {
		dapls_cookie_dealloc(&ep->req_buffer, cookie);
	} else {
		dapl_os_atomic_inc(&ep->req_count);
	}

bail:
	return (dat_status);
}


/*
 * dapli_ep_timeout
 *
 * If this routine is invoked before a connection occurs, generate an
 * event
 */
void
dapls_ep_timeout(
	unsigned long			arg)
{
	DAPL_EP		*ep_ptr;

	dapl_dbg_log(DAPL_DBG_TYPE_CM, "--> dapls_ep_timeout! ep %lx\n", arg);

	ep_ptr = (DAPL_EP *)arg;

	/* reset the EP state */
	ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECTED;

	(void) dapls_evd_post_connection_event(
	    (DAPL_EVD *)ep_ptr->param.connect_evd_handle,
	    DAT_CONNECTION_EVENT_TIMED_OUT,
	    (DAT_HANDLE) ep_ptr,
	    0,
	    0);
}


/*
 * dapls_ep_state_subtype
 *
 * Return the INVALID_STATE connection subtype associated with an
 * INVALID_STATE on an EP. Strictly for error reporting.
 */
DAT_RETURN_SUBTYPE
dapls_ep_state_subtype(
    IN  DAPL_EP			*ep_ptr)
{
	DAT_RETURN_SUBTYPE	dat_status;

	switch (ep_ptr->param.ep_state) {
	case DAT_EP_STATE_RESERVED:
	{
		dat_status = DAT_INVALID_STATE_EP_RESERVED;
		break;
	}
	case DAT_EP_STATE_PASSIVE_CONNECTION_PENDING:
	{
		dat_status = DAT_INVALID_STATE_EP_PASSCONNPENDING;
		break;
	}
	case DAT_EP_STATE_ACTIVE_CONNECTION_PENDING:
	{
		dat_status = DAT_INVALID_STATE_EP_ACTCONNPENDING;
		break;
	}
	case DAT_EP_STATE_TENTATIVE_CONNECTION_PENDING:
	{
		dat_status = DAT_INVALID_STATE_EP_TENTCONNPENDING;
		break;
	}
	case DAT_EP_STATE_CONNECTED:
	{
		dat_status = DAT_INVALID_STATE_EP_CONNECTED;
		break;
	}
	case DAT_EP_STATE_DISCONNECT_PENDING:
	{
		dat_status = DAT_INVALID_STATE_EP_DISCPENDING;
		break;
	}
	case DAT_EP_STATE_DISCONNECTED:
	{
		dat_status = DAT_INVALID_STATE_EP_DISCONNECTED;
		break;
	}
	case DAT_EP_STATE_COMPLETION_PENDING:
	{
		dat_status = DAT_INVALID_STATE_EP_COMPLPENDING;
		break;
	}
	default:
	{
		dat_status = 0;
		break;
	}
	}

	return (dat_status);
}


/*
 * dapl_ep_create_common
 *
 * Common code used by dapl_ep_create and dapl_ep_create_srq
 *
 * Input:
 *	ia_handle
 *	pz_handle
 *	recv_evd_handle (recv DTOs)
 *	request_evd_handle (xmit DTOs)
 *	connect_evd_handle
 *	srq_handle
 *	ep_attrs
 *
 * Output:
 *	ep_handle
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_ATTRIBUTE
 *	DAT_MODEL_NOT_SUPPORTED
 */
DAT_RETURN
dapl_ep_create_common(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_PZ_HANDLE		pz_handle,
	IN	DAT_EVD_HANDLE		recv_evd_handle,
	IN	DAT_EVD_HANDLE		request_evd_handle,
	IN	DAT_EVD_HANDLE		connect_evd_handle,
	IN	DAT_SRQ_HANDLE		srq_handle,
	IN	const DAT_EP_ATTR	*ep_attr_arg,
	OUT	DAT_EP_HANDLE		*ep_handle)
{
	DAPL_IA			*ia_ptr;
	DAPL_EP			*ep_ptr;
	DAT_EP_ATTR		ep_attr_limit;
	DAPL_EVD		*evd_ptr;
	DAT_RETURN		dat_status;
	DAT_BOOLEAN		srq_attached;
	DAT_EP_ATTR		*ep_attr, epa;

	if (ep_attr_arg) {
		epa = *ep_attr_arg;
		ep_attr = &epa;
	} else
		ep_attr = NULL;

	ia_ptr = (DAPL_IA *)ia_handle;
	dat_status = DAT_SUCCESS;
	/*
	 * Verify parameters
	 */
	if (DAPL_BAD_HANDLE(ia_ptr, DAPL_MAGIC_IA)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_IA);
		goto bail;
	}

	/*
	 * Verify non-required parameters.
	 * N.B. Assumption: any parameter that can be
	 * modified by dat_ep_modify() is not strictly
	 * required when the EP is created
	 */
	if (pz_handle != NULL &&
	    DAPL_BAD_HANDLE(pz_handle, DAPL_MAGIC_PZ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PZ);
		goto bail;
	}

	/* If connect handle is !NULL verify handle is good  */
	if (connect_evd_handle != DAT_HANDLE_NULL &&
	    (DAPL_BAD_HANDLE(connect_evd_handle, DAPL_MAGIC_EVD) ||
	    !(((DAPL_EVD *)connect_evd_handle)->evd_flags &
	    DAT_EVD_CONNECTION_FLAG))) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EVD_CONN);
		goto bail;
	}
	/* If recv_evd is !NULL, verify handle is good and flags are valid */
	if ((recv_evd_handle != DAT_HANDLE_NULL) &&
	    (DAPL_BAD_HANDLE(recv_evd_handle, DAPL_MAGIC_EVD) ||
	    !(((DAPL_EVD *)recv_evd_handle)->evd_flags & DAT_EVD_DTO_FLAG))) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EVD_RECV);
		goto bail;
	}

	/* If req_evd is !NULL, verify handle is good and flags are valid */
	if ((request_evd_handle != DAT_HANDLE_NULL) &&
	    (DAPL_BAD_HANDLE(request_evd_handle, DAPL_MAGIC_EVD) ||
	    !(((DAPL_EVD *)request_evd_handle)->evd_flags &
	    DAT_EVD_DTO_FLAG))) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EVD_REQUEST);
		goto bail;
	}

	srq_attached = DAT_FALSE;

	/* if srq_handle is not null validate it */
	if (srq_handle != DAT_HANDLE_NULL) {
		if (DAPL_BAD_HANDLE(srq_handle, DAPL_MAGIC_SRQ)) {
			dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
			    DAT_INVALID_HANDLE_SRQ);
			goto bail;
		} else if (pz_handle !=
		    ((DAPL_SRQ *)srq_handle)->param.pz_handle) {
			dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG2);
			goto bail;
		}
		srq_attached = DAT_TRUE;
	}

	if (ep_handle == NULL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    (srq_attached ? DAT_INVALID_ARG8 : DAT_INVALID_ARG7));
		goto bail;
	}

	/* For EPs with SRQ ep_attr is required */
	if ((srq_attached && (ep_attr == NULL)) || (uintptr_t)ep_attr & 3) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    (srq_attached ? DAT_INVALID_ARG7 : DAT_INVALID_ARG6));
		goto bail;
	}

	/*
	 * Qualify EP Attributes are legal and make sense.  Note that if one
	 * or both of the DTO handles are NULL, then the corresponding
	 * max_*_dtos must 0 as the user will not be able to post dto ops on
	 * the respective queue.
	 */
	if (ep_attr != NULL) {
		if (ep_attr->service_type != DAT_SERVICE_TYPE_RC ||
		    (request_evd_handle == DAT_HANDLE_NULL &&
		    ep_attr->max_request_dtos != 0) ||
		    (request_evd_handle != DAT_HANDLE_NULL &&
		    ep_attr->max_request_dtos == 0) ||
		    ep_attr->max_request_iov == 0 ||
		    (DAT_SUCCESS != dapl_ep_check_qos(ep_attr->qos)) ||
		    (DAT_SUCCESS != dapl_ep_check_recv_completion_flags(
		    ep_attr->recv_completion_flags))) {
			dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    (srq_attached ? DAT_INVALID_ARG7 :
			    DAT_INVALID_ARG6));
			goto bail;
		}

		if (srq_attached) {
			if ((ep_attr->max_recv_dtos != DAT_HW_DEFAULT) ||
			    (ep_attr->srq_soft_hw != DAT_HW_DEFAULT)) {
				dat_status = DAT_ERROR(DAT_MODEL_NOT_SUPPORTED,
				    0);
				goto bail;
			}
		} else {
			/* These checks are needed only for EPs without SRQ */
			if ((recv_evd_handle == DAT_HANDLE_NULL &&
			    ep_attr->max_recv_dtos != 0) ||
			    (recv_evd_handle != DAT_HANDLE_NULL &&
			    ep_attr->max_recv_dtos == 0) ||
			    ep_attr->max_recv_iov == 0) {
				dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
				    DAT_INVALID_ARG6);
				goto bail;
			}
		}
	}

	/* Verify the attributes against the transport */
	if (ep_attr != NULL) {
		(void) dapl_os_memzero(&ep_attr_limit, sizeof (DAT_EP_ATTR));
		dat_status = dapls_ib_query_hca(ia_ptr->hca_ptr,
		    NULL, &ep_attr_limit, NULL, NULL);
		if (dat_status != DAT_SUCCESS) {
			goto bail;
		}
		if (ep_attr->max_mtu_size > ep_attr_limit.max_mtu_size ||
		    ep_attr->max_rdma_size > ep_attr_limit.max_rdma_size ||
		    (ep_attr->max_request_dtos >
		    ep_attr_limit.max_request_dtos) ||
		    ep_attr->max_request_iov > ep_attr_limit.max_request_iov) {
			dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    (srq_attached ? DAT_INVALID_ARG7 :
			    DAT_INVALID_ARG6));
			goto bail;
		}
		/* if inlining enabled, recompute max_request_iov */
		if (ia_ptr->hca_ptr->max_inline_send)
			ep_attr->max_request_iov = dapls_ib_max_request_iov(
			    ep_attr->max_request_iov,
			    ep_attr->max_request_dtos,
			    ep_attr_limit.max_request_iov,
			    ia_ptr->hca_ptr->max_inline_send);

		/* Only EPs without SRQ need the following check */
		if ((!srq_attached) &&
		    (ep_attr->max_recv_dtos > ep_attr_limit.max_recv_dtos) ||
		    (ep_attr->max_recv_iov > ep_attr_limit.max_recv_iov)) {
			dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
			    DAT_INVALID_ARG6);
			goto bail;
		}


	}
	/*
	 * Verify the completion flags for the EVD and the EP
	 */

	evd_ptr = (DAPL_EVD *)recv_evd_handle;
	if (evd_ptr->completion_type == DAPL_EVD_STATE_INIT) {
		if (ep_attr != NULL &&
		    (ep_attr->recv_completion_flags ==
		    DAT_COMPLETION_DEFAULT_FLAG)) {
			evd_ptr->completion_type = DAPL_EVD_STATE_THRESHOLD;
		} else {
			/*
			 * Currently we support only thresholds -
			 * eventually it'll depend on
			 * ep_attr->recv_completion_flags;
			 */
			evd_ptr->completion_type = DAPL_EVD_STATE_THRESHOLD;
		}
	}
	evd_ptr = (DAPL_EVD *)request_evd_handle;
	if (evd_ptr->completion_type == DAPL_EVD_STATE_INIT) {
		if (ep_attr != NULL &&
		    (ep_attr->recv_completion_flags ==
		    DAT_COMPLETION_DEFAULT_FLAG)) {
			evd_ptr->completion_type = DAPL_EVD_STATE_THRESHOLD;
		} else {
			/*
			 * Currently we support only thresholds -
			 * eventually it'll depend on
			 * ep_attr->recv_completion_flags;
			 */
			evd_ptr->completion_type = DAPL_EVD_STATE_THRESHOLD;
		}
	}

	/* Allocate EP */
	ep_ptr = dapl_ep_alloc(ia_ptr, ep_attr, srq_attached);
	if (ep_ptr == NULL) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	/*
	 * Fill in the EP
	 */
	ep_ptr->param.ia_handle		= ia_handle;
	ep_ptr->param.pz_handle		= pz_handle;
	ep_ptr->param.recv_evd_handle	= recv_evd_handle;
	ep_ptr->param.request_evd_handle = request_evd_handle;
	ep_ptr->param.connect_evd_handle = connect_evd_handle;
	ep_ptr->param.srq_handle	= srq_handle;

	ep_ptr->srq_attached = srq_attached;

	/*
	 * Make sure we handle the NULL DTO EVDs
	 */
	if (recv_evd_handle == DAT_HANDLE_NULL && ep_attr == NULL) {
		ep_ptr->param.ep_attr.max_recv_dtos = 0;
	}

	if (request_evd_handle == DAT_HANDLE_NULL && ep_attr == NULL) {
		ep_ptr->param.ep_attr.max_request_dtos = 0;
	}

	/*
	 * If the user has specified a PZ handle we allocate a QP for
	 * this EP; else we defer until it is assigned via ep_modify().
	 * As much as possible we try to keep QP creation out of the
	 * connect path to avoid resource errors in strange places.
	 */
	if (pz_handle != DAT_HANDLE_NULL) {
		/* Take a reference on the PZ handle */
		dapl_os_atomic_inc(&((DAPL_PZ *)pz_handle)->pz_ref_count);

		/*
		 * Get a QP from the IB provider
		 */
		dat_status = dapls_ib_qp_alloc(ia_ptr, ep_ptr, ep_ptr);

		if (dat_status != DAT_SUCCESS) {
			dapl_os_atomic_dec(&((DAPL_PZ *)pz_handle)->
			    pz_ref_count);
			dapl_ep_dealloc(ep_ptr);
			goto bail;
		}
	} else {
		ep_ptr->qp_state = DAPL_QP_STATE_UNATTACHED;
	}

	/*
	 * Update ref counts. See the spec where the endpoint marks
	 * a data object as 'in use'
	 *   pz_handle: dat_pz_free, uDAPL Document, 6.6.1.2
	 *   evd_handles:
	 *
	 * N.B. This should really be done by a util routine.
	 */
	dapl_os_atomic_inc(&((DAPL_EVD *)connect_evd_handle)->evd_ref_count);
	/* Optional handles */
	if (recv_evd_handle != NULL) {
		dapl_os_atomic_inc(&((DAPL_EVD *)recv_evd_handle)->
		    evd_ref_count);
	}
	if (request_evd_handle != NULL) {
		dapl_os_atomic_inc(&((DAPL_EVD *)request_evd_handle)->
		    evd_ref_count);
	}
	if (srq_handle != NULL) {
		dapl_os_atomic_inc(&((DAPL_SRQ *)srq_handle)->srq_ref_count);
	}

	/* Link it onto the IA */
	dapl_ia_link_ep(ia_ptr, ep_ptr);

	*ep_handle = ep_ptr;

bail:
	return (dat_status);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
