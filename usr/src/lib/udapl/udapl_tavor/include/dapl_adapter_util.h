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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_adapter_util.h
 *
 * PURPOSE: Utility defs & routines for the adapter data structure
 *
 */

#ifndef _DAPL_ADAPTER_UTIL_H_
#define	_DAPL_ADAPTER_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Max number of cqes that can be polled from the CQ */
#define	MAX_CQES_PER_POLL	8

typedef enum async_handler_type {
	DAPL_ASYNC_UNAFILIATED,
	DAPL_ASYNC_CQ_ERROR,
	DAPL_ASYNC_CQ_COMPLETION,
	DAPL_ASYNC_QP_ERROR
} DAPL_ASYNC_HANDLER_TYPE;


#ifdef	CM_BUSTED
DAT_RETURN dapl_set_remote_lid(IN char *rhost_name);
#endif /* CM_BUSTED */

/* SUNW */
DAT_RETURN dapls_ib_enum_hcas(
	IN   DAPL_HCA	**hca_list,
	OUT  DAT_COUNT	*hca_count);

void dapls_ib_state_init(void);
void dapls_ib_state_fini(void);
/* SUNW */

DAT_RETURN dapls_ib_open_hca(
	IN   DAPL_HCA		*hca_ptr,
	OUT  ib_hca_handle_t	*ib_hca_handle);

DAT_RETURN dapls_ib_close_hca(
	IN  ib_hca_handle_t	ib_hca_handle);

DAT_RETURN dapls_ib_qp_alloc(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EP			*ep_ptr,
	IN  DAPL_EP			*ep_ctx_ptr);

DAT_RETURN dapls_ib_qp_free(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EP			*ep_ptr);

DAT_RETURN dapls_ib_qp_modify(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EP			*ep_ptr,
	IN  DAT_EP_ATTR			*ep_attr);

DAT_RETURN dapls_ib_connect(
	IN  DAT_EP_HANDLE		ep_handle,
	IN  DAT_IA_ADDRESS_PTR		remote_ia_address,
	IN  DAT_CONN_QUAL		remote_conn_qual,
	IN  DAT_COUNT			prd_size,
	IN  DAPL_PRIVATE		*prd_ptr,
	IN  DAT_TIMEOUT			timeout);

DAT_RETURN dapls_ib_disconnect(
	IN	DAPL_EP			*ep_ptr,
	IN	DAT_CLOSE_FLAGS		completion_flags);

DAT_RETURN dapls_ib_setup_conn_listener(
	IN  DAPL_IA			*ia_ptr,
	IN  DAT_UINT64			ServiceID,
	IN  DAPL_SP			*sp_ptr);

DAT_RETURN dapls_ib_remove_conn_listener(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_SP			*sp_ptr);

DAT_RETURN dapls_ib_accept_connection(
	IN  DAT_CR_HANDLE		cr_handle,
	IN  DAT_EP_HANDLE		ep_handle,
	IN  DAPL_PRIVATE		*prd_ptr);

/* SUNW */
DAT_RETURN dapls_ib_reject_connection(
	IN  ib_cm_handle_t		cm_handle,
	IN  int				reject_reason,
	IN  DAPL_SP			*sp_ptr);

DAT_RETURN dapls_ib_handoff_connection(
	IN  DAPL_CR			*cr_ptr,
	IN  DAT_CONN_QUAL		cr_handoff);

void dapls_ib_async_callback(
	IN    DAPL_EVD		  *async_evd,
	IN    ib_hca_handle_t	  hca_handle,
	IN    ib_error_record_t	  *event_ptr,
	IN    void		  *context);
/* SUNW */

DAT_RETURN dapls_ib_setup_async_callback(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_ASYNC_HANDLER_TYPE	handler_type,
	IN  unsigned int		*callback_handle,
	IN  ib_async_handler_t		callback,
	IN  void			*context);

DAT_RETURN dapls_ib_cq_alloc(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EVD			*evd_ptr,
	IN  DAPL_CNO			*cno_ptr,
	IN  DAT_COUNT			*cqlen);

/* SUNW */
DAT_RETURN dapls_ib_cq_resize(
	IN  DAPL_EVD			*evd_ptr,
	IN  DAT_COUNT			cqlen);
/* SUNW */

DAT_RETURN dapls_ib_cq_free(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EVD			*evd_ptr);

DAT_RETURN dapls_set_cq_notify(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EVD			*evd_ptr);

/* SUNW */
DAT_RETURN dapls_set_cqN_notify(
	IN  DAPL_IA			*ia_ptr,
	IN  DAPL_EVD			*evd_ptr,
	IN  uint32_t			events_needed);
/* SUNW */

DAT_RETURN dapls_ib_cqd_create(
	IN  DAPL_HCA			*hca_ptr);

DAT_RETURN dapls_ib_cqd_destroy(
	IN  DAPL_HCA			*hca_ptr);

DAT_RETURN dapls_ib_pd_alloc(
	IN  DAPL_IA 			*ia_ptr,
	IN  DAPL_PZ 			*pz);

DAT_RETURN dapls_ib_pd_free(
	IN  DAPL_PZ			*pz);

DAT_RETURN dapls_ib_mr_register(
	IN  DAPL_IA 			*ia_ptr,
	IN  DAPL_LMR			*lmr,
	IN  DAT_PVOID			virt_addr,
	IN  DAT_VLEN			length,
	IN  DAT_MEM_PRIV_FLAGS		privileges);

DAT_RETURN dapls_ib_mr_register_shared(
	IN  DAPL_IA 			*ia_ptr,
	IN  DAPL_LMR			*lmr,
	IN  DAT_PVOID			virt_addr,
	IN  DAT_VLEN			length,
	IN  DAT_LMR_COOKIE		cookie,
	IN  DAT_MEM_PRIV_FLAGS		privileges);

DAT_RETURN dapls_ib_mr_deregister(
	IN  DAPL_LMR			*lmr);

DAT_RETURN dapls_ib_mr_register_lmr(
	IN  DAPL_IA 			*ia_ptr,
	IN  DAPL_LMR			*lmr,
	IN  DAT_MEM_PRIV_FLAGS		privileges);

DAT_RETURN dapls_ib_mw_alloc(
	IN  DAPL_RMR 			*rmr);

DAT_RETURN dapls_ib_mw_free(
	IN  DAPL_RMR			*rmr);

DAT_RETURN dapls_ib_mw_bind(
	IN  DAPL_RMR			*rmr,
	IN  DAT_LMR_CONTEXT		lmr_context,
	IN  DAPL_EP			*ep,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_VADDR			virtual_address,
	IN  DAT_VLEN			length,
	IN  DAT_MEM_PRIV_FLAGS		mem_priv,
	IN  DAT_COMPLETION_FLAGS	completion_flags);

DAT_RETURN dapls_ib_mw_unbind(
	IN  DAPL_RMR			*rmr,
	IN  DAT_LMR_CONTEXT		lmr_context,
	IN  DAPL_EP			*ep,
	IN  DAPL_COOKIE			*cookie,
	IN  DAT_COMPLETION_FLAGS	completion_flags);

DAT_RETURN dapls_ib_query_hca(
	IN  DAPL_HCA			*hca_ptr,
	OUT DAT_IA_ATTR			*ia_attr,
	OUT DAT_EP_ATTR			*ep_attr,
	OUT DAT_SOCK_ADDR6		*ip_addr,
	OUT DAT_SRQ_ATTR		*srq_attr);

void dapls_ib_reinit_ep(
	IN  DAPL_EP			*ep_ptr);

void dapls_ib_connected(
	IN  DAPL_EP			*ep_ptr);

void dapls_ib_disconnect_clean(
	IN  DAPL_EP			*ep_ptr,
	IN  DAT_BOOLEAN			passive,
	IN  const ib_cm_events_t	ib_cm_event);

DAT_RETURN dapls_ib_get_async_event(
	IN  ib_error_record_t		*cause_ptr,
	OUT DAT_EVENT_NUMBER		*async_event);

DAT_RETURN dapls_ib_cm_remote_addr(
	IN  DAT_HANDLE			dat_handle,
	IN  DAPL_PRIVATE		*prd_ptr,
	OUT DAT_SOCK_ADDR6		*remote_ia_address);

/* SUNW */
void dapls_ib_store_premature_events(
	IN ib_qp_handle_t	qp_ptr,
	IN ib_work_completion_t	*cqe_ptr);

void dapls_ib_poll_premature_events(
	IN  DAPL_EP			*ep_ptr,
	OUT ib_work_completion_t	**cqe_ptr,
	OUT int				*nevents);

void dapls_ib_free_premature_events(
	IN  DAPL_EP	*ep_ptr,
	IN  int		free_index);

DAT_RETURN dapls_ib_event_poll(
	IN DAPL_EVD		*evd_ptr,
	IN uint64_t		timeout,
	IN uint_t		threshold,
	OUT dapl_ib_event_t	*evp_ptr,
	OUT int			*num_events);

DAT_RETURN dapls_ib_event_wakeup(
	IN DAPL_EVD		*evd_ptr);

void dapls_ib_cq_peek(
	IN DAPL_EVD	*evd_ptr,
	OUT int		*num_cqe);

DAT_RETURN dapls_ib_modify_cno(
	IN DAPL_EVD	*evd_ptr,
	IN DAPL_CNO	*cno_ptr);

DAT_RETURN dapls_ib_cno_wait(
	IN DAPL_CNO	*cno_ptr,
	IN DAT_TIMEOUT	timeout,
	IN DAPL_EVD	**evd_ptr_p);

DAT_RETURN dapls_ib_cno_alloc(
	IN DAPL_IA	*ia_ptr,
	IN DAPL_CNO	*cno_ptr);

DAT_RETURN dapls_ib_cno_free(
	IN DAPL_CNO	*cno_ptr);

DAT_RETURN dapls_ib_post_recv(
	IN  DAPL_EP			*ep_ptr,
	IN  DAPL_COOKIE			*dto_cookie,
	IN  DAT_COUNT			num_segments,
	IN  DAT_LMR_TRIPLET		*local_iov,
	IN  DAT_COMPLETION_FLAGS	completion_flags);

DAT_RETURN dapls_ib_post_recv_one(
	IN  DAPL_EP			*ep_ptr,
	IN  DAPL_COOKIE			*dto_cookie,
	IN  DAT_LMR_TRIPLET		*local_iov);

DAT_RETURN dapls_ib_post_srq(
	IN  DAPL_SRQ			*srq_ptr,
	IN  DAPL_COOKIE			*dto_cookie,
	IN  DAT_COUNT			num_segments,
	IN  DAT_LMR_TRIPLET		*local_iov);

DAT_RETURN dapls_ib_post_send(
	IN  DAPL_EP			*ep_ptr,
	IN  ib_send_op_type_t		op_type,
	IN  DAPL_COOKIE			*dto_cookie,
	IN  DAT_COUNT			num_segments,
	IN  DAT_LMR_TRIPLET		*local_iov,
	IN  const DAT_RMR_TRIPLET	*remote_iov,
	IN  DAT_COMPLETION_FLAGS	completion_flags);

DAT_RETURN dapls_ib_post_send_one(
	IN  DAPL_EP			*ep_ptr,
	IN  ib_send_op_type_t		op_type,
	IN  DAPL_COOKIE			*dto_cookie,
	IN  DAT_LMR_TRIPLET		*local_iov,
	IN  const DAT_RMR_TRIPLET	*remote_iov);

DAT_RETURN dapls_ib_lmr_sync_rdma_common(
	IN DAT_IA_HANDLE ia_handle,
	IN const DAT_LMR_TRIPLET *local_segments,
	IN DAT_VLEN num_segments,
	IN uint32_t op_type);

DAT_RETURN dapls_ib_srq_alloc(
	IN DAPL_IA *ia_handle,
	IN DAPL_SRQ *srq_handle);

void dapls_ib_srq_free(
	IN DAPL_IA *ia_handle,
	IN DAPL_SRQ *srq_handle);

DAT_RETURN dapls_ib_srq_resize(
	IN  DAPL_SRQ	*srq_ptr,
	IN  DAT_COUNT	srqlen);

DAPL_EP *dapls_ib_srq_lookup_ep(
	IN DAPL_SRQ *srq_ptr,
	IN ib_work_completion_t *cqe_ptr);

DAT_COUNT dapls_ib_max_request_iov(
	IN DAT_COUNT iovs,
	IN DAT_COUNT wqes,
	IN DAT_COUNT max_iovs,
	IN int max_inline_bytes);

/* SUNW */


#ifdef	IBAPI
#include "dapl_ibapi_dto.h"
#elif VAPI
#include "dapl_vapi_dto.h"
#endif

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_ADAPTER_UTIL_H_ */
