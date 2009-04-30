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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_srq.c
 *
 * PURPOSE: Shared Receive Queue
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.2 API, Chapter 6, section 5
 *
 */

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_ia_util.h"
#include "dapl_srq_util.h"
#include "dapl_cookie.h"

/*
 * dapl_srq_create
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.5.1
 *
 * creates an instance of a Shared Receive Queue (SRQ) that is provided
 * to the Consumer as srq_handle.
 *
 * Input:
 * 	ia_handle
 * 	pz_handle
 * 	srq_attr
 *
 * Output:
 * 	srq_handle
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_MODEL_NOT_SUPPORTED
 */

DAT_RETURN
dapl_srq_create(
	IN	DAT_IA_HANDLE ia_handle,
	IN	DAT_PZ_HANDLE pz_handle,
	IN	DAT_SRQ_ATTR *srq_attr,
	OUT	DAT_SRQ_HANDLE *srq_handle)
{
	DAPL_IA		*ia_ptr;
	DAPL_SRQ	*srq_ptr;
	DAT_SRQ_ATTR	srq_attr_limit;
	DAT_RETURN	dat_status;

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

	if ((pz_handle == NULL) || DAPL_BAD_HANDLE(pz_handle, DAPL_MAGIC_PZ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_PZ);
		goto bail;
	}

	if ((srq_attr == NULL) || ((uintptr_t)srq_attr & 3)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	if (srq_handle == NULL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4);
		goto bail;
	}

	if (srq_attr->max_recv_dtos == 0 || srq_attr->max_recv_iov == 0 ||
	    srq_attr->low_watermark != DAT_SRQ_LW_DEFAULT) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	/* Verify the attributes against the transport */
	(void) dapl_os_memzero(&srq_attr_limit, sizeof (DAT_SRQ_ATTR));
	dat_status = dapls_ib_query_hca(ia_ptr->hca_ptr, NULL, NULL, NULL,
	    &srq_attr_limit);
	if (dat_status != DAT_SUCCESS) {
			goto bail;
	}
	if (srq_attr->max_recv_dtos > srq_attr_limit.max_recv_dtos ||
	    srq_attr->max_recv_iov > srq_attr_limit.max_recv_iov) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	/* Allocate SRQ */
	srq_ptr = dapl_srq_alloc(ia_ptr, srq_attr);
	if (srq_ptr == NULL) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	/* Take a reference on the PZ handle */
	dapl_os_atomic_inc(&((DAPL_PZ *)pz_handle)->pz_ref_count);

	/*
	 * Fill in the SRQ
	 */
	srq_ptr->param.ia_handle	= ia_handle;
	srq_ptr->param.srq_state	= DAT_SRQ_STATE_OPERATIONAL;
	srq_ptr->param.pz_handle	= pz_handle;
	srq_ptr->param.max_recv_dtos	= srq_attr->max_recv_dtos;
	srq_ptr->param.max_recv_iov	= srq_attr->max_recv_iov;
	srq_ptr->param.low_watermark	= DAT_SRQ_LW_DEFAULT;

	srq_ptr->param.available_dto_count	= DAT_VALUE_UNKNOWN;
	srq_ptr->param.outstanding_dto_count	= 0;

	dat_status = dapls_ib_srq_alloc(ia_ptr, srq_ptr);
	if (dat_status != DAT_SUCCESS) {
		dapl_os_atomic_dec(&((DAPL_PZ *)pz_handle)->pz_ref_count);
		dapl_srq_dealloc(srq_ptr);
		goto bail;
	}
	/* Link it onto the IA */
	dapl_ia_link_srq(ia_ptr, srq_ptr);

	*srq_handle = srq_ptr;
bail:
	return (dat_status);
}

/*
 * dapl_srq_free
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.5.5
 *
 * destroys an instance of the SRQ. The SRQ cannot be destroyed if it is
 * in use by an EP.
 *
 * Input:
 * 	srq_handle
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_STATE
 */

DAT_RETURN
dapl_srq_free(
	IN	DAT_SRQ_HANDLE srq_handle)
{
	DAPL_SRQ	*srq_ptr;
	DAPL_IA		*ia_ptr;
	DAT_SRQ_PARAM	*param;
	DAT_RETURN	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(srq_handle, DAPL_MAGIC_SRQ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_SRQ);
		goto bail;
	}

	srq_ptr = (DAPL_SRQ *)srq_handle;
	param = &srq_ptr->param;
	if (0 != srq_ptr->srq_ref_count) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapl_srq_free: Free SRQ: %p, refcnt %d\n",
		    srq_ptr, srq_ptr->srq_ref_count);
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_STATE_SRQ_IN_USE);
		goto bail;
	}

	ia_ptr = srq_ptr->header.owner_ia;
	param->srq_state = DAT_SRQ_STATE_ERROR;

	dapls_ib_srq_free(ia_ptr, srq_ptr);

	/* Remove link from the IA */
	dapl_ia_unlink_srq(ia_ptr, srq_ptr);

	dapl_os_assert(param->pz_handle != NULL);
	dapl_os_atomic_dec(&((DAPL_PZ *)param->pz_handle)->pz_ref_count);
	param->pz_handle = NULL;

	dapl_srq_dealloc(srq_ptr);

bail:
	return (dat_status);
}

/*
 * dapl_srq_post_recv
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.5.8
 *
 * posts the receive buffer that can be used for the incoming message into
 * the local_iov by any connected EP that uses SRQ.
 *
 * Input:
 * 	srq_handle
 * 	num_segments
 * 	local_iov
 *	user_cookie
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_PARAMETER
 * 	DAT_PROTECTION_VIOLATION
 * 	DAT_PRIVILEGES_VIOLATION
 */

DAT_RETURN
dapl_srq_post_recv(
	IN	DAT_SRQ_HANDLE srq_handle,
	IN	DAT_COUNT num_segments,
	IN	DAT_LMR_TRIPLET *local_iov,
	IN	DAT_DTO_COOKIE user_cookie)
{
	DAPL_SRQ 		*srq_ptr;
	DAPL_COOKIE		*cookie;
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_srq_post_recv (%p, %d, %p, %P)\n",
	    srq_handle,
	    num_segments,
	    local_iov,
	    user_cookie.as_64);

	if (DAPL_BAD_HANDLE(srq_handle, DAPL_MAGIC_SRQ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_SRQ);
		goto bail;
	}

	srq_ptr = (DAPL_SRQ *) srq_handle;

	/*
	 * Synchronization ok since this buffer is only used for receive
	 * requests, which aren't allowed to race with each other.
	 */
	dat_status = dapls_dto_cookie_alloc(&srq_ptr->recv_buffer,
	    DAPL_DTO_TYPE_RECV,
	    user_cookie,
	    &cookie);
	if (DAT_SUCCESS != dat_status) {
		goto bail;
	}

	/*
	 * Invoke provider specific routine to post DTO
	 */
	dat_status = dapls_ib_post_srq(srq_ptr, cookie, num_segments,
	    local_iov);

	if (dat_status != DAT_SUCCESS) {
		dapls_cookie_dealloc(&srq_ptr->recv_buffer, cookie);
	} else {
		dapl_os_atomic_inc(&srq_ptr->recv_count);
	}

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_srq_post_recv () returns 0x%x\n", dat_status);

	return (dat_status);
}


/*
 * dapl_srq_query
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.5.6
 *
 * provides to the Consumer SRQ parameters. The Consumer passes in a pointer
 * to the Consumer-allocated structures for SRQ parameters that the Provider
 * fills.
 *
 * Input:
 * 	srq_handle
 * 	srq_param_mask
 *
 * Output:
 * 	srq_param
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_srq_query(
	IN	DAT_SRQ_HANDLE srq_handle,
	IN	DAT_SRQ_PARAM_MASK srq_param_mask,
	OUT	DAT_SRQ_PARAM *srq_param)
{
	DAPL_SRQ	    *srq_ptr;
	DAT_RETURN	    dat_status;

	dat_status = DAT_SUCCESS;

	if (srq_param_mask & ~DAT_SRQ_FIELD_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	if (NULL == srq_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}


	if (DAPL_BAD_HANDLE(srq_handle, DAPL_MAGIC_SRQ)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}

	srq_ptr = (DAPL_SRQ *)srq_handle;
	/* Do a struct copy */
	*srq_param = srq_ptr->param;
	/* update the outstanding dto count */
	srq_param->outstanding_dto_count  = srq_ptr->recv_count;

bail:
	return (dat_status);
}

/*
 * dapl_srq_set_lw
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.5.4
 *
 * sets the low watermark value for SRQ and arms SRQ for generating an
 * asynchronous event for low watermark. An asynchronous event will be
 * generated when the number of buffers on SRQ is below the low watermark
 * for the first time. This may happen during this call or when an
 * associated EP takes a buffer from the SRQ.
 *
 * Input:
 * 	srq_handle
 * 	low_watermark
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_MODEL_NOT_SUPPORTED
 */

/* ARGSUSED */
DAT_RETURN
dapl_srq_set_lw(
	IN	DAT_SRQ_HANDLE srq_handle,
	IN	DAT_COUNT low_watermark)
{
	return (DAT_MODEL_NOT_SUPPORTED);
}

/*
 * dapl_srq_resize
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.5.7
 *
 * modifies the size of the queue of SRQ. Resizing of SRQ shall not cause
 * any incoming messages on any of the EPs that use the SRQ to be lost.
 *
 * Input:
 * 	srq_handle
 * 	srq_max_recv_dto
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_STATE
 */

/* ARGSUSED */
DAT_RETURN
dapl_srq_resize(
	IN	DAT_SRQ_HANDLE srq_handle,
	IN	DAT_COUNT srq_max_recv_dtos)
{
	DAPL_SRQ		*srq_ptr;
	DAT_SRQ_ATTR		srq_attr_limit;
	DAPL_COOKIE_BUFFER	new_cb;
	DAT_RETURN		dat_status;


	srq_ptr = (DAPL_SRQ *)srq_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(srq_handle, DAPL_MAGIC_SRQ)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_HANDLE_TYPE_SRQ));
	}

	/* can't shrink below the number of outstanding recvs */
	if (srq_max_recv_dtos < srq_ptr->recv_count) {
		return (DAT_ERROR(DAT_INVALID_STATE, 0));
	}

	/*
	 * shrinking SRQs is not supported on tavor return success without
	 * any modification.
	 */
	if (srq_max_recv_dtos <= srq_ptr->param.max_recv_dtos) {
		return (DAT_SUCCESS);
	}

	/* Verify the attributes against the transport */
	(void) dapl_os_memzero(&srq_attr_limit, sizeof (DAT_SRQ_ATTR));
	dat_status = dapls_ib_query_hca(srq_ptr->header.owner_ia->hca_ptr,
	    NULL, NULL, NULL, &srq_attr_limit);
	if (dat_status != DAT_SUCCESS) {
		return (dat_status);
	}

	if (srq_max_recv_dtos > srq_attr_limit.max_recv_dtos) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		return (dat_status);
	}

	dat_status = dapls_cb_resize(&srq_ptr->recv_buffer, srq_max_recv_dtos,
	    &new_cb);
	if (dat_status != DAT_SUCCESS) {
		return (dat_status);
	}

	dat_status = dapls_ib_srq_resize(srq_ptr, srq_max_recv_dtos);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	dapls_cb_free(&srq_ptr->recv_buffer);
	srq_ptr->recv_buffer = new_cb; /* struct copy */
	srq_ptr->param.max_recv_dtos = srq_max_recv_dtos;

	return (DAT_SUCCESS);
bail:
	dapls_cb_free(&new_cb);

	return (dat_status);
}
