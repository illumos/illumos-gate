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
 * MODULE: dapl_rmr_bind.c
 *
 * PURPOSE: Memory management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 6
 *
 * $Id: dapl_rmr_bind.c,v 1.14 2003/07/11 18:23:31 jlentini Exp $
 */

#include "dapl.h"
#include "dapl_rmr_util.h"
#include "dapl_ep_util.h"
#include "dapl_cookie.h"
#include "dapl_adapter_util.h"

/*
 *
 * Function Prototypes
 *
 */

static DAT_RETURN
dapli_rmr_bind_fuse(
    IN  DAPL_RMR		*rmr,
    IN  const DAT_LMR_TRIPLET 	*lmr_triplet,
    IN  DAT_MEM_PRIV_FLAGS 	mem_priv,
    IN  DAPL_EP 		*ep,
    IN  DAT_RMR_COOKIE 		user_cookie,
    IN  DAT_COMPLETION_FLAGS	completion_flags,
    OUT DAT_RMR_CONTEXT 	*rmr_context);

static DAT_RETURN
dapli_rmr_bind_unfuse(
    IN  DAPL_RMR		*rmr,
    IN  const DAT_LMR_TRIPLET 	*lmr_triplet,
    IN  DAPL_EP 		*ep,
    IN  DAT_RMR_COOKIE 		user_cookie,
    IN  DAT_COMPLETION_FLAGS 	completion_flags);


/*
 *
 * Function Definitions
 *
 */

static DAT_RETURN
dapli_rmr_bind_fuse(
    IN  DAPL_RMR		*rmr,
    IN  const DAT_LMR_TRIPLET* 	lmr_triplet,
    IN  DAT_MEM_PRIV_FLAGS 	mem_priv,
    IN  DAPL_EP 		*ep_ptr,
    IN  DAT_RMR_COOKIE 		user_cookie,
    IN  DAT_COMPLETION_FLAGS	completion_flags,
    OUT DAT_RMR_CONTEXT 	*rmr_context)
{
	DAPL_LMR 			*lmr;
	DAPL_COOKIE			*cookie;
	DAT_RETURN 			dat_status;

	dat_status = dapls_hash_search(
	    rmr->header.owner_ia->hca_ptr->lmr_hash_table,
	    lmr_triplet->lmr_context,
	    (DAPL_HASH_DATA *) &lmr);
	if (DAT_SUCCESS != dat_status) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	/*
	 * if the ep in unconnected return an error. IB requires that the
	 * QP be connected to change a memory window binding since:
	 *
	 * - memory window bind operations are WQEs placed on a QP's
	 *   send queue
	 *
	 * - QP's only process WQEs on the send queue when the QP is in
	 *   the RTS state
	 */
	if (DAT_EP_STATE_CONNECTED != ep_ptr->param.ep_state) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_ptr));
		goto bail;
	}

	if (DAT_FALSE == dapl_mr_bounds_check(
	    dapl_mr_get_address(lmr->param.region_desc, lmr->param.mem_type),
	    lmr->param.length,
	    lmr_triplet->virtual_address,
	    lmr_triplet->segment_length)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER,
		    DAT_INVALID_ARG2);
		goto bail;
	}

	/* If the LMR, RMR, and EP are not in the same PZ, there is an error */
	if ((ep_ptr->param.pz_handle != lmr->param.pz_handle) ||
	    (ep_ptr->param.pz_handle != rmr->param.pz_handle)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4);
		goto bail;
	}

	if (!dapl_rmr_validate_completion_flag(DAT_COMPLETION_SUPPRESS_FLAG,
	    ep_ptr->param.ep_attr.request_completion_flags, completion_flags) ||
	    !dapl_rmr_validate_completion_flag(DAT_COMPLETION_UNSIGNALLED_FLAG,
	    ep_ptr->param.ep_attr.request_completion_flags, completion_flags) ||
	    !dapl_rmr_validate_completion_flag(
	    DAT_COMPLETION_BARRIER_FENCE_FLAG,
	    ep_ptr->param.ep_attr.request_completion_flags, completion_flags)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4);
		goto bail;
	}

	dat_status = dapls_rmr_cookie_alloc(&ep_ptr->req_buffer,
	    rmr, user_cookie, &cookie);
	if (DAT_SUCCESS != dat_status) {
		goto bail;
	}

	dat_status = dapls_ib_mw_bind(rmr,
	    lmr_triplet->lmr_context,
	    ep_ptr,
	    cookie,
	    lmr_triplet->virtual_address,
	    lmr_triplet->segment_length,
	    mem_priv,
	    completion_flags);
	if (DAT_SUCCESS != dat_status) {
		dapls_cookie_dealloc(&ep_ptr->req_buffer, cookie);
		goto bail;
	}

	dapl_os_atomic_inc(&lmr->lmr_ref_count);

	/* if the RMR was previously bound */
	if (NULL != rmr->lmr) {
		dapl_os_atomic_dec(&rmr->lmr->lmr_ref_count);
	}

	rmr->param.mem_priv = mem_priv;
	rmr->param.lmr_triplet = *lmr_triplet;
	rmr->ep = ep_ptr;
	rmr->lmr = lmr;

	dapl_os_atomic_inc(&ep_ptr->req_count);

	if (NULL != rmr_context) { *rmr_context = rmr->param.rmr_context; }
bail:
	return (dat_status);
}


static DAT_RETURN
dapli_rmr_bind_unfuse(
    IN  DAPL_RMR		*rmr,
    IN  const DAT_LMR_TRIPLET 	*lmr_triplet,
    IN  DAPL_EP 		*ep_ptr,
    IN  DAT_RMR_COOKIE 		user_cookie,
    IN  DAT_COMPLETION_FLAGS 	completion_flags)
{
	DAPL_COOKIE			*cookie;
	DAT_RETURN 			dat_status;

	dat_status = DAT_SUCCESS;
	/*
	 * if the ep in unconnected return an error. IB requires that the
	 * QP be connected to change a memory window binding since:
	 *
	 * - memory window bind operations are WQEs placed on a QP's
	 *   send queue
	 *
	 * - QP's only process WQEs on the send queue when the QP is in
	 *   the RTS state
	 */
	if (DAT_EP_STATE_CONNECTED != ep_ptr->param.ep_state) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_ptr));
		goto bail1;
	}

	/* If the RMR and EP are not in the same PZ, there is an error */
	if (ep_ptr->param.pz_handle != rmr->param.pz_handle) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail1;
	}

	if (!dapl_rmr_validate_completion_flag(DAT_COMPLETION_SUPPRESS_FLAG,
	    ep_ptr->param.ep_attr.request_completion_flags, completion_flags) ||
	    !dapl_rmr_validate_completion_flag(DAT_COMPLETION_UNSIGNALLED_FLAG,
	    ep_ptr->param.ep_attr.request_completion_flags, completion_flags) ||
	    !dapl_rmr_validate_completion_flag(
	    DAT_COMPLETION_BARRIER_FENCE_FLAG,
	    ep_ptr->param.ep_attr.request_completion_flags, completion_flags)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail1;
	}

	dat_status = dapls_rmr_cookie_alloc(&ep_ptr->req_buffer, rmr,
	    user_cookie, &cookie);
	if (DAT_SUCCESS != dat_status) {
		goto bail1;
	}


	dat_status = dapls_ib_mw_unbind(rmr, lmr_triplet->lmr_context,
	    ep_ptr, cookie, completion_flags);

	if (DAT_SUCCESS != dat_status) {
		dapls_cookie_dealloc(&ep_ptr->req_buffer, cookie);
		goto bail1;
	}

	/* if the RMR was previously bound */
	if (NULL != rmr->lmr) {
		dapl_os_atomic_dec(&rmr->lmr->lmr_ref_count);
	}

	rmr->param.mem_priv = DAT_MEM_PRIV_NONE_FLAG;
	rmr->param.lmr_triplet.lmr_context = 0;
	rmr->param.lmr_triplet.virtual_address = 0;
	rmr->param.lmr_triplet.segment_length = 0;
	rmr->ep = ep_ptr;
	rmr->lmr = NULL;

	dapl_os_atomic_inc(&ep_ptr->req_count);

bail1:
	return (dat_status);
}


/*
 * dapl_rmr_bind
 *
 * DAPL Requirements Version xxx, 6.6.4.4
 *
 * Bind the RMR to the specified memory region within the LMR and
 * provide a new rmr_context value.
 *
 * Input:
 * Output:
 */
DAT_RETURN
dapl_rmr_bind(
	IN	DAT_RMR_HANDLE		rmr_handle,
	IN	const DAT_LMR_TRIPLET	*lmr_triplet,
	IN	DAT_MEM_PRIV_FLAGS	mem_priv,
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_RMR_COOKIE		user_cookie,
	IN	DAT_COMPLETION_FLAGS 	completion_flags,
	OUT	DAT_RMR_CONTEXT		*rmr_context)
{
	DAPL_RMR				*rmr;
	DAPL_EP 				*ep_ptr;

	if (DAPL_BAD_HANDLE(rmr_handle, DAPL_MAGIC_RMR)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_RMR));
	}
	if (DAPL_BAD_HANDLE(ep_handle, DAPL_MAGIC_EP)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}

	rmr = (DAPL_RMR *) rmr_handle;
	ep_ptr = (DAPL_EP *) ep_handle;

	/* if the rmr should be bound */
	if (0 != lmr_triplet->segment_length) {
		return (dapli_rmr_bind_fuse(rmr,
		    lmr_triplet,
		    mem_priv,
		    ep_ptr,
		    user_cookie,
		    completion_flags,
		    rmr_context));
	} else { /* the rmr should be unbound */
		return (dapli_rmr_bind_unfuse(rmr,
		    lmr_triplet,
		    ep_ptr,
		    user_cookie,
		    completion_flags));
	}
}
