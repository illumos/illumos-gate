/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * MODULE: dat_api.c
 *
 * PURPOSE: DAT Provider and Consumer registry functions.
 *
 */

#include "dat_osd.h"
#include <dat/dat_registry.h>


DAT_RETURN dat_set_consumer_context(
	IN	DAT_HANDLE		dat_handle,
	IN	DAT_CONTEXT		context)
{
	if (DAT_BAD_HANDLE(dat_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_SET_CONSUMER_CONTEXT(dat_handle,
				context);
}


DAT_RETURN dat_get_consumer_context(
	IN	DAT_HANDLE		dat_handle,
	OUT	DAT_CONTEXT		*context)
{
	if (DAT_BAD_HANDLE(dat_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_GET_CONSUMER_CONTEXT(dat_handle,
				context);

}


DAT_RETURN dat_get_handle_type(
	IN	DAT_HANDLE		dat_handle,
	OUT	DAT_HANDLE_TYPE		*type)
{
	if (DAT_BAD_HANDLE(dat_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_GET_HANDLE_TYPE(dat_handle,
				type);
}


DAT_RETURN dat_cr_query(
	IN	DAT_CR_HANDLE		cr_handle,
	IN	DAT_CR_PARAM_MASK	cr_param_mask,
	OUT	DAT_CR_PARAM		*cr_param)
{
	if (DAT_BAD_HANDLE(cr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CR));
	}
	return DAT_CR_QUERY(cr_handle,
			    cr_param_mask,
			    cr_param);
}


DAT_RETURN dat_cr_accept(
	IN	DAT_CR_HANDLE		cr_handle,
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		private_data_size,
	IN	const DAT_PVOID		private_data)
{
	if (DAT_BAD_HANDLE(cr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CR));
	}
	return DAT_CR_ACCEPT(cr_handle,
			    ep_handle,
			    private_data_size,
			    private_data);
}


DAT_RETURN dat_cr_reject(
	IN	DAT_CR_HANDLE 		cr_handle)
{
	if (DAT_BAD_HANDLE(cr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_CR));
	}
	return (DAT_CR_REJECT(cr_handle));
}


DAT_RETURN dat_evd_resize(
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_COUNT		evd_min_qlen)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_EVD_RESIZE(evd_handle,
			evd_min_qlen);
}


DAT_RETURN dat_evd_post_se(
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	const DAT_EVENT		*event)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_EVD_POST_SE(evd_handle,
			    event);
}


DAT_RETURN dat_evd_dequeue(
	IN	DAT_EVD_HANDLE		evd_handle,
	OUT	DAT_EVENT		*event)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return DAT_EVD_DEQUEUE(evd_handle,
				event);
}


DAT_RETURN dat_evd_free(
	IN	DAT_EVD_HANDLE 		evd_handle)
{
	if (DAT_BAD_HANDLE(evd_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE1));
	}
	return (DAT_EVD_FREE(evd_handle));
}


DAT_RETURN dat_ep_create(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_PZ_HANDLE		pz_handle,
	IN	DAT_EVD_HANDLE		recv_completion_evd_handle,
	IN	DAT_EVD_HANDLE		request_completion_evd_handle,
	IN	DAT_EVD_HANDLE		connect_evd_handle,
	IN	const DAT_EP_ATTR 	*ep_attributes,
	OUT	DAT_EP_HANDLE		*ep_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_EP_CREATE(ia_handle,
			    pz_handle,
			    recv_completion_evd_handle,
			    request_completion_evd_handle,
			    connect_evd_handle,
			    ep_attributes,
			    ep_handle);
}


DAT_RETURN dat_ep_query(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_EP_PARAM_MASK	ep_param_mask,
	OUT	DAT_EP_PARAM		*ep_param)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_QUERY(ep_handle,
			    ep_param_mask,
			    ep_param);
}


DAT_RETURN dat_ep_modify(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_EP_PARAM_MASK	ep_param_mask,
	IN	const DAT_EP_PARAM 	*ep_param)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_MODIFY(ep_handle,
			    ep_param_mask,
			    ep_param);
}


DAT_RETURN dat_ep_connect(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_IA_ADDRESS_PTR	remote_ia_address,
	IN	DAT_CONN_QUAL		remote_conn_qual,
	IN	DAT_TIMEOUT		timeout,
	IN	DAT_COUNT		private_data_size,
	IN	const DAT_PVOID		private_data,
	IN	DAT_QOS			quality_of_service,
	IN	DAT_CONNECT_FLAGS	connect_flags)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_CONNECT(ep_handle,
			    remote_ia_address,
			    remote_conn_qual,
			    timeout,
			    private_data_size,
			    private_data,
			    quality_of_service,
			    connect_flags);
}


DAT_RETURN dat_ep_dup_connect(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_EP_HANDLE		ep_dup_handle,
	IN	DAT_TIMEOUT		timeout,
	IN	DAT_COUNT		private_data_size,
	IN	const DAT_PVOID		private_data,
	IN	DAT_QOS			quality_of_service)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_DUP_CONNECT(ep_handle,
			    ep_dup_handle,
			    timeout,
			    private_data_size,
			    private_data,
			    quality_of_service);
}


DAT_RETURN dat_ep_disconnect(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_CLOSE_FLAGS		close_flags)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_DISCONNECT(ep_handle,
				close_flags);
}


DAT_RETURN dat_ep_post_send(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	DAT_COMPLETION_FLAGS	completion_flags)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_POST_SEND(ep_handle,
			    num_segments,
			    local_iov,
			    user_cookie,
			    completion_flags);
}


DAT_RETURN dat_ep_post_recv(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	DAT_COMPLETION_FLAGS	completion_flags)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_POST_RECV(ep_handle,
			    num_segments,
			    local_iov,
			    user_cookie,
			    completion_flags);
}


DAT_RETURN dat_ep_post_rdma_read(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	const DAT_RMR_TRIPLET	*remote_iov,
	IN	DAT_COMPLETION_FLAGS	completion_flags)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_POST_RDMA_READ(ep_handle,
				    num_segments,
				    local_iov,
				    user_cookie,
				    remote_iov,
				    completion_flags);
}


DAT_RETURN dat_ep_post_rdma_write(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	const DAT_RMR_TRIPLET	*remote_iov,
	IN	DAT_COMPLETION_FLAGS	completion_flags)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_POST_RDMA_WRITE(ep_handle,
				    num_segments,
				    local_iov,
				    user_cookie,
				    remote_iov,
				    completion_flags);
}


DAT_RETURN dat_ep_get_status(
	IN	DAT_EP_HANDLE		ep_handle,
	OUT	DAT_EP_STATE		*ep_state,
	OUT	DAT_BOOLEAN 		*recv_idle,
	OUT	DAT_BOOLEAN 		*request_idle)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_GET_STATUS(ep_handle,
				ep_state,
				recv_idle,
				request_idle);
}


DAT_RETURN dat_ep_free(
	IN	DAT_EP_HANDLE		ep_handle)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return (DAT_EP_FREE(ep_handle));
}


DAT_RETURN dat_ep_reset(
	IN	DAT_EP_HANDLE		ep_handle)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return (DAT_EP_RESET(ep_handle));
}


DAT_RETURN dat_lmr_free(
	IN	DAT_LMR_HANDLE		lmr_handle)
{
	if (DAT_BAD_HANDLE(lmr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_LMR));
	}
	return (DAT_LMR_FREE(lmr_handle));
}


DAT_RETURN dat_rmr_create(
	IN	DAT_PZ_HANDLE		pz_handle,
	OUT	DAT_RMR_HANDLE		*rmr_handle)
{
	if (DAT_BAD_HANDLE(pz_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_PZ));
	}
	return DAT_RMR_CREATE(pz_handle,
			rmr_handle);
}


DAT_RETURN dat_rmr_query(
	IN	DAT_RMR_HANDLE		rmr_handle,
	IN	DAT_RMR_PARAM_MASK	rmr_param_mask,
	OUT	DAT_RMR_PARAM		*rmr_param)
{
	if (DAT_BAD_HANDLE(rmr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_RMR));
	}
	return DAT_RMR_QUERY(rmr_handle,
			    rmr_param_mask,
			    rmr_param);
}


DAT_RETURN dat_rmr_bind(
	IN	DAT_RMR_HANDLE		rmr_handle,
	IN	const DAT_LMR_TRIPLET	*lmr_triplet,
	IN	DAT_MEM_PRIV_FLAGS	mem_priv,
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_RMR_COOKIE		user_cookie,
	IN	DAT_COMPLETION_FLAGS	completion_flags,
	OUT	DAT_RMR_CONTEXT		*context)
{
	if (DAT_BAD_HANDLE(rmr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_RMR));
	}
	return DAT_RMR_BIND(rmr_handle,
			    lmr_triplet,
			    mem_priv,
			    ep_handle,
			    user_cookie,
			    completion_flags,
			    context);
}


DAT_RETURN dat_rmr_free(
	IN	DAT_RMR_HANDLE		rmr_handle)
{
	if (DAT_BAD_HANDLE(rmr_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_RMR));
	}
	return (DAT_RMR_FREE(rmr_handle));
}


DAT_RETURN dat_psp_create(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_CONN_QUAL		conn_qual,
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_PSP_FLAGS		psp_flags,
	OUT	DAT_PSP_HANDLE		*psp_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_PSP_CREATE(ia_handle,
			    conn_qual,
			    evd_handle,
			    psp_flags,
			    psp_handle);
}


DAT_RETURN dat_psp_query(
	IN	DAT_PSP_HANDLE		psp_handle,
	IN	DAT_PSP_PARAM_MASK	psp_param_mask,
	OUT	DAT_PSP_PARAM 		*psp_param)
{
	if (DAT_BAD_HANDLE(psp_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_PSP));
	}
	return DAT_PSP_QUERY(psp_handle,
			    psp_param_mask,
			    psp_param);
}


DAT_RETURN dat_psp_free(
	IN	DAT_PSP_HANDLE	psp_handle)
{
	if (DAT_BAD_HANDLE(psp_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_PSP));
	}
	return (DAT_PSP_FREE(psp_handle));
}


DAT_RETURN dat_rsp_create(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_CONN_QUAL		conn_qual,
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_EVD_HANDLE		evd_handle,
	OUT	DAT_RSP_HANDLE		*rsp_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_RSP_CREATE(ia_handle,
			    conn_qual,
			    ep_handle,
			    evd_handle,
			    rsp_handle);
}


DAT_RETURN dat_rsp_query(
	IN	DAT_RSP_HANDLE		rsp_handle,
	IN	DAT_RSP_PARAM_MASK	rsp_param_mask,
	OUT	DAT_RSP_PARAM		*rsp_param)
{
	if (DAT_BAD_HANDLE(rsp_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_RSP));
	}
	return DAT_RSP_QUERY(rsp_handle,
			    rsp_param_mask,
			    rsp_param);
}


DAT_RETURN dat_rsp_free(
	IN	DAT_RSP_HANDLE		rsp_handle)
{
	if (DAT_BAD_HANDLE(rsp_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_RSP));
	}
	return (DAT_RSP_FREE(rsp_handle));
}


DAT_RETURN dat_pz_create(
	IN	DAT_IA_HANDLE		ia_handle,
	OUT	DAT_PZ_HANDLE		*pz_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_PZ_CREATE(ia_handle,
			pz_handle);
}


DAT_RETURN dat_pz_query(
	IN	DAT_PZ_HANDLE		pz_handle,
	IN	DAT_PZ_PARAM_MASK	pz_param_mask,
	OUT	DAT_PZ_PARAM		*pz_param)
{
	if (DAT_BAD_HANDLE(pz_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_PZ));
	}
	return DAT_PZ_QUERY(pz_handle,
			pz_param_mask,
			pz_param);
}


DAT_RETURN dat_pz_free(
	IN	DAT_PZ_HANDLE		pz_handle)
{
	if (DAT_BAD_HANDLE(pz_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_PZ));
	}
	return (DAT_PZ_FREE(pz_handle));
}

/* ARGSUSED */
DAT_RETURN dat_lmr_sync_rdma_read(
	IN	DAT_IA_HANDLE	ia_handle,
	IN	const DAT_LMR_TRIPLET *local_segments,
	IN	DAT_VLEN num_segments)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}

#if defined(__x86)
	return (DAT_SUCCESS);
#elif defined(__sparc)
	return (DAT_LMR_SYNC_RDMA_READ(ia_handle, local_segments,
		num_segments));
#else
#error "ISA not supported"
#endif
}

/* ARGSUSED */
DAT_RETURN dat_lmr_sync_rdma_write(
	IN	DAT_IA_HANDLE	ia_handle,
	IN	const DAT_LMR_TRIPLET *local_segments,
	IN	DAT_VLEN num_segments)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}

#if defined(__x86)
	return (DAT_SUCCESS);
#elif defined(__sparc)
	return (DAT_LMR_SYNC_RDMA_WRITE(ia_handle, local_segments,
		num_segments));
#else
#error "ISA not supported"
#endif
}

DAT_RETURN dat_ep_create_with_srq(
	IN	DAT_IA_HANDLE	ia_handle,
	IN	DAT_PZ_HANDLE	pz_handle,
	IN	DAT_EVD_HANDLE	recv_evd_handle,
	IN	DAT_EVD_HANDLE	request_evd_handle,
	IN	DAT_EVD_HANDLE	connect_evd_handle,
	IN	DAT_SRQ_HANDLE	srq_handle,
	IN	const DAT_EP_ATTR *ep_attributes,
	OUT	DAT_EP_HANDLE	*ep_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_EP_CREATE_WITH_SRQ(ia_handle,
				pz_handle,
				recv_evd_handle,
				request_evd_handle,
				connect_evd_handle,
				srq_handle,
				ep_attributes,
				ep_handle);
}

DAT_RETURN dat_ep_recv_query(
	IN	DAT_EP_HANDLE	ep_handle,
	OUT	DAT_COUNT	*nbufs_allocated,
	OUT	DAT_COUNT	*bufs_alloc_span)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_RECV_QUERY(ep_handle,
				nbufs_allocated,
				bufs_alloc_span);
}

DAT_RETURN dat_ep_set_watermark(
	IN	DAT_EP_HANDLE	ep_handle,
	IN	DAT_COUNT	soft_high_watermark,
	IN	DAT_COUNT	hard_high_watermark)
{
	if (DAT_BAD_HANDLE(ep_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_EP));
	}
	return DAT_EP_SET_WATERMARK(ep_handle,
				soft_high_watermark,
				hard_high_watermark);
}

DAT_RETURN dat_srq_create(
	IN	DAT_IA_HANDLE	ia_handle,
	IN	DAT_PZ_HANDLE	pz_handle,
	IN	DAT_SRQ_ATTR	*srq_attr,
	OUT	DAT_SRQ_HANDLE	*srq_handle)
{
	if (DAT_BAD_HANDLE(ia_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_IA));
	}
	return DAT_SRQ_CREATE(ia_handle,
				pz_handle,
				srq_attr,
				srq_handle);
}

DAT_RETURN dat_srq_free(
	IN	DAT_SRQ_HANDLE	srq_handle)
{
	if (DAT_BAD_HANDLE(srq_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_SRQ));
	}
	return (DAT_SRQ_FREE(srq_handle));
}

DAT_RETURN dat_srq_post_recv(
	IN	DAT_SRQ_HANDLE	srq_handle,
	IN	DAT_COUNT	num_segments,
	IN	DAT_LMR_TRIPLET	*local_iov,
	IN	DAT_DTO_COOKIE	user_cookie)
{
	if (DAT_BAD_HANDLE(srq_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_SRQ));
	}
	return DAT_SRQ_POST_RECV(srq_handle,
				num_segments,
				local_iov,
				user_cookie);
}

DAT_RETURN dat_srq_query(
	IN	DAT_SRQ_HANDLE		srq_handle,
	IN	DAT_SRQ_PARAM_MASK	srq_param_mask,
	OUT	DAT_SRQ_PARAM		*srq_param)
{
	if (DAT_BAD_HANDLE(srq_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_SRQ));
	}
	return DAT_SRQ_QUERY(srq_handle,
			srq_param_mask,
			srq_param);
}

DAT_RETURN dat_srq_resize(
	IN	DAT_SRQ_HANDLE	srq_handle,
	IN	DAT_COUNT	srq_max_recv_dto)
{
	if (DAT_BAD_HANDLE(srq_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_SRQ));
	}
	return DAT_SRQ_RESIZE(srq_handle,
			srq_max_recv_dto);
}

DAT_RETURN dat_srq_set_lw(
	IN	DAT_SRQ_HANDLE	srq_handle,
	IN	DAT_COUNT	low_watermark)
{
	if (DAT_BAD_HANDLE(srq_handle)) {
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_SRQ));
	}
	return DAT_SRQ_SET_LW(srq_handle,
			low_watermark);
}
