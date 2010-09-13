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
 * Copyright (c) 2002-2004, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _UDAT_REDIRECTION_H_
#define	_UDAT_REDIRECTION_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * HEADER: udat_redirection.h
 *
 * PURPOSE: User DAT macro definitions
 *
 * Description: Macros to invoke DAPL functions from the dat_registry
 *
 * Mapping rules:
 *      All global symbols are prepended with "DAT_" or "dat_"
 *      All DAT objects have an 'api' tag which, such as 'ep' or 'lmr'
 *      The method table is in the provider definition structure.
 *
 *
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	DAT_LMR_CREATE(ia, mem_type, reg_desc, len, pz, priv,\
			lmr, lmr_context, rmr_context, reg_len, reg_addr) \
	(*DAT_HANDLE_TO_PROVIDER(ia)->lmr_create_func)(\
		(ia),\
		(mem_type),\
		(reg_desc),\
		(len),\
		(pz),\
		(priv),\
		(lmr),\
		(lmr_context),\
		(rmr_context),\
		(reg_len),\
		(reg_addr))

#define	DAT_EVD_CREATE(ia, qlen, cno, flags, handle) \
	(*DAT_HANDLE_TO_PROVIDER(ia)->evd_create_func)(\
		(ia),\
		(qlen),\
		(cno),\
		(flags),\
		(handle))

#define	DAT_EVD_ENABLE(evd) \
	(*DAT_HANDLE_TO_PROVIDER(evd)->evd_enable_func)(\
		(evd))

#define	DAT_EVD_WAIT(evd, timeout, threshold, event, nmore) \
	(*DAT_HANDLE_TO_PROVIDER(evd)->evd_wait_func)(\
		(evd),\
		(timeout),\
		(threshold),\
		(event),\
		(nmore))

#define	DAT_EVD_DISABLE(evd) \
	(*DAT_HANDLE_TO_PROVIDER(evd)->evd_disable_func)(\
		(evd))

#define	DAT_EVD_SET_UNWAITABLE(evd) \
	(*DAT_HANDLE_TO_PROVIDER(evd)->evd_set_unwaitable_func)(\
		(evd))

#define	DAT_EVD_CLEAR_UNWAITABLE(evd) \
	(*DAT_HANDLE_TO_PROVIDER(evd)->evd_clear_unwaitable_func)(\
		(evd))

#define	DAT_EVD_MODIFY_CNO(evd, cno) \
	(*DAT_HANDLE_TO_PROVIDER(evd)->evd_modify_cno_func)(\
		(evd),\
		(cno))

#define	DAT_CNO_CREATE(ia, proxy, cno) \
	(*DAT_HANDLE_TO_PROVIDER(ia)->cno_create_func)(\
		(ia),\
		(proxy),\
		(cno))

#define	DAT_CNO_MODIFY_AGENT(cno, proxy) \
	(*DAT_HANDLE_TO_PROVIDER(cno)->cno_modify_agent_func)(\
		(cno),\
		(proxy))

#define	DAT_CNO_QUERY(cno, mask, param) \
	(*DAT_HANDLE_TO_PROVIDER(cno)->cno_query_func)(\
		(cno),\
		(mask),\
		(param))

#define	DAT_CNO_FREE(cno) \
	(*DAT_HANDLE_TO_PROVIDER(cno)->cno_free_func)(\
		(cno))

#define	DAT_CNO_WAIT(cno, timeout, evd) \
	(*DAT_HANDLE_TO_PROVIDER(cno)->cno_wait_func)(\
		(cno),\
		(timeout),\
		(evd))
/*
 * FUNCTION PROTOTYPES
 *
 * User DAT function call definitions
 *
 */

typedef DAT_RETURN (*DAT_LMR_CREATE_FUNC)(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_MEM_TYPE,		/* mem_type		*/
	IN	DAT_REGION_DESCRIPTION,	/* region_description   */
	IN	DAT_VLEN,		/* length		*/
	IN	DAT_PZ_HANDLE,		/* pz_handle		*/
	IN	DAT_MEM_PRIV_FLAGS,	/* privileges		*/
	OUT	DAT_LMR_HANDLE *,	/* lmr_handle		*/
	OUT	DAT_LMR_CONTEXT *,	/* lmr_context		*/
	OUT	DAT_RMR_CONTEXT *,	/* rmr_context		*/
	OUT	DAT_VLEN *,		/* registered_length	*/
	OUT	DAT_VADDR *);		/* registered_address   */

/* Event Functions */

typedef DAT_RETURN (*DAT_EVD_CREATE_FUNC)(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_COUNT,		/* evd_min_qlen		*/
	IN	DAT_CNO_HANDLE,		/* cno_handle		*/
	IN	DAT_EVD_FLAGS,		/* evd_flags		*/
	OUT	DAT_EVD_HANDLE *);	/* evd_handle		*/

typedef DAT_RETURN (*DAT_EVD_MODIFY_CNO_FUNC)(
	IN	DAT_EVD_HANDLE,		/* evd_handle		*/
	IN	DAT_CNO_HANDLE);	/* cno_handle		*/

typedef DAT_RETURN (*DAT_CNO_CREATE_FUNC)(
	IN	DAT_IA_HANDLE,		/* ia_handle		*/
	IN	DAT_OS_WAIT_PROXY_AGENT,	/* agent		*/
	OUT	DAT_CNO_HANDLE *);	/* cno_handle		*/

typedef DAT_RETURN (*DAT_CNO_MODIFY_AGENT_FUNC)(
	IN	DAT_CNO_HANDLE,			/* cno_handle		*/
	IN	DAT_OS_WAIT_PROXY_AGENT);	/* agent		*/

typedef DAT_RETURN (*DAT_CNO_QUERY_FUNC)(
	IN	DAT_CNO_HANDLE,		/* cno_handle		*/
	IN	DAT_CNO_PARAM_MASK,	/* cno_param_mask	*/
	OUT	DAT_CNO_PARAM *);	/* cno_param		*/

typedef DAT_RETURN (*DAT_CNO_FREE_FUNC)(
	IN DAT_CNO_HANDLE);		/* cno_handle		*/

typedef DAT_RETURN(*DAT_CNO_WAIT_FUNC)(
	IN	DAT_CNO_HANDLE,		/* cno_handle		*/
	IN	DAT_TIMEOUT,		/* timeout		*/
	OUT	DAT_EVD_HANDLE *);	/* evd_handle		*/

typedef DAT_RETURN (*DAT_EVD_ENABLE_FUNC)(
	IN	DAT_EVD_HANDLE);	/* evd_handle		*/

typedef DAT_RETURN (*DAT_EVD_WAIT_FUNC)(
	IN	DAT_EVD_HANDLE,		/* evd_handle		*/
	IN	DAT_TIMEOUT,		/* Timeout		*/
	IN	DAT_COUNT,		/* Threshold		*/
	OUT	DAT_EVENT *,		/* event		*/
	OUT	DAT_COUNT *);		/* N more events	*/

typedef DAT_RETURN (*DAT_EVD_DISABLE_FUNC)(
	IN	DAT_EVD_HANDLE);	/* evd_handle		*/

typedef DAT_RETURN (*DAT_EVD_SET_UNWAITABLE_FUNC)(
	IN DAT_EVD_HANDLE);		/* evd_handle */

typedef DAT_RETURN (*DAT_EVD_CLEAR_UNWAITABLE_FUNC)(
	IN DAT_EVD_HANDLE); /* evd_handle */


#include <dat/dat_redirection.h>

struct dat_provider
{
	const char			*device_name;
	DAT_PVOID			extension;

	DAT_IA_OPEN_FUNC		ia_open_func;
	DAT_IA_QUERY_FUNC		ia_query_func;
	DAT_IA_CLOSE_FUNC		ia_close_func;

	DAT_SET_CONSUMER_CONTEXT_FUNC	set_consumer_context_func;
	DAT_GET_CONSUMER_CONTEXT_FUNC	get_consumer_context_func;
	DAT_GET_HANDLE_TYPE_FUNC	get_handle_type_func;

	DAT_CNO_CREATE_FUNC		cno_create_func;	/* udat only */
	DAT_CNO_MODIFY_AGENT_FUNC	cno_modify_agent_func;	/* udat only */
	DAT_CNO_QUERY_FUNC		cno_query_func;		/* udat only */
	DAT_CNO_FREE_FUNC		cno_free_func;		/* udat only */
	DAT_CNO_WAIT_FUNC		cno_wait_func;		/* udat only */

	DAT_CR_QUERY_FUNC		cr_query_func;
	DAT_CR_ACCEPT_FUNC		cr_accept_func;
	DAT_CR_REJECT_FUNC		cr_reject_func;
	DAT_CR_HANDOFF_FUNC		cr_handoff_func;

	DAT_EVD_CREATE_FUNC		evd_create_func;
	DAT_EVD_QUERY_FUNC		evd_query_func;

	DAT_EVD_MODIFY_CNO_FUNC		evd_modify_cno_func;    /* udat only */
	DAT_EVD_ENABLE_FUNC		evd_enable_func;	/* udat only */
	DAT_EVD_DISABLE_FUNC		evd_disable_func;	/* udat only */
	DAT_EVD_WAIT_FUNC		evd_wait_func;		/* udat only */

	DAT_EVD_RESIZE_FUNC		evd_resize_func;
	DAT_EVD_POST_SE_FUNC		evd_post_se_func;
	DAT_EVD_DEQUEUE_FUNC		evd_dequeue_func;
	DAT_EVD_FREE_FUNC		evd_free_func;

	DAT_EP_CREATE_FUNC		ep_create_func;
	DAT_EP_QUERY_FUNC		ep_query_func;
	DAT_EP_MODIFY_FUNC		ep_modify_func;
	DAT_EP_CONNECT_FUNC		ep_connect_func;
	DAT_EP_DUP_CONNECT_FUNC		ep_dup_connect_func;
	DAT_EP_DISCONNECT_FUNC		ep_disconnect_func;
	DAT_EP_POST_SEND_FUNC		ep_post_send_func;
	DAT_EP_POST_RECV_FUNC		ep_post_recv_func;
	DAT_EP_POST_RDMA_READ_FUNC	ep_post_rdma_read_func;
	DAT_EP_POST_RDMA_WRITE_FUNC	ep_post_rdma_write_func;
	DAT_EP_GET_STATUS_FUNC		ep_get_status_func;
	DAT_EP_FREE_FUNC		ep_free_func;

	DAT_LMR_CREATE_FUNC		lmr_create_func;
	DAT_LMR_QUERY_FUNC		lmr_query_func;

	DAT_LMR_FREE_FUNC		lmr_free_func;

	DAT_RMR_CREATE_FUNC		rmr_create_func;
	DAT_RMR_QUERY_FUNC		rmr_query_func;
	DAT_RMR_BIND_FUNC		rmr_bind_func;
	DAT_RMR_FREE_FUNC		rmr_free_func;

	DAT_PSP_CREATE_FUNC		psp_create_func;
	DAT_PSP_QUERY_FUNC		psp_query_func;
	DAT_PSP_FREE_FUNC		psp_free_func;

	DAT_RSP_CREATE_FUNC		rsp_create_func;
	DAT_RSP_QUERY_FUNC		rsp_query_func;
	DAT_RSP_FREE_FUNC		rsp_free_func;

	DAT_PZ_CREATE_FUNC		pz_create_func;
	DAT_PZ_QUERY_FUNC		pz_query_func;
	DAT_PZ_FREE_FUNC		pz_free_func;

	/* dat-1.1 */
	DAT_PSP_CREATE_ANY_FUNC		psp_create_any_func;
	DAT_EP_RESET_FUNC		ep_reset_func;

	/* udat-1.1 */
	DAT_EVD_SET_UNWAITABLE_FUNC	evd_set_unwaitable_func;
	DAT_EVD_CLEAR_UNWAITABLE_FUNC	evd_clear_unwaitable_func;

	/* dat-1.2 */
	DAT_LMR_SYNC_RDMA_READ_FUNC	lmr_sync_rdma_read_func;
	DAT_LMR_SYNC_RDMA_WRITE_FUNC	lmr_sync_rdma_write_func;

	DAT_EP_CREATE_WITH_SRQ_FUNC	ep_create_with_srq_func;
	DAT_EP_RECV_QUERY_FUNC		ep_recv_query_func;
	DAT_EP_SET_WATERMARK_FUNC	ep_set_watermark_func;
	DAT_SRQ_CREATE_FUNC		srq_create_func;
	DAT_SRQ_FREE_FUNC		srq_free_func;
	DAT_SRQ_POST_RECV_FUNC		srq_post_recv_func;
	DAT_SRQ_QUERY_FUNC		srq_query_func;
	DAT_SRQ_RESIZE_FUNC		srq_resize_func;
	DAT_SRQ_SET_LW_FUNC		srq_set_lw_func;
};

#ifdef __cplusplus
}
#endif

#endif /* _UDAT_REDIRECTION_H_ */
