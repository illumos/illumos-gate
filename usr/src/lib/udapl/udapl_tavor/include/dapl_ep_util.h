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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_ep_util.h
 *
 * PURPOSE: Utility defs & routines for the EP data structure
 *
 */

#ifndef _DAPL_EP_UTIL_H_
#define	_DAPL_EP_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"
#include "dapl_adapter_util.h"

/* function prototypes */
extern DAPL_EP *
dapl_ep_alloc(
	IN DAPL_IA		*ia,
	IN const DAT_EP_ATTR	*ep_attr,
	IN DAT_BOOLEAN		srq_attached);

extern void
dapl_ep_dealloc(
	IN DAPL_EP		*ep_ptr);

extern DAT_RETURN
dapl_ep_check_recv_completion_flags(
	DAT_COMPLETION_FLAGS	flags);

extern DAT_RETURN
dapl_ep_check_request_completion_flags(
	DAT_COMPLETION_FLAGS	flags);

extern DAT_RETURN
dapl_ep_check_qos(
	DAT_QOS	qos);

extern DAT_RETURN
dapl_ep_post_send_req(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	const DAT_RMR_TRIPLET	*remote_iov,
	IN	DAT_COMPLETION_FLAGS	completion_flags,
	IN	DAPL_DTO_TYPE		dto_type,
	IN	ib_send_op_type_t	op_type);

void dapls_ep_timeout(unsigned long arg);

DAT_RETURN_SUBTYPE
dapls_ep_state_subtype(
	IN  DAPL_EP	*ep_ptr);

extern DAT_RETURN
dapl_ep_create_common(
	IN	DAT_IA_HANDLE ia_handle,
	IN	DAT_PZ_HANDLE pz_handle,
	IN	DAT_EVD_HANDLE recv_evd_handle,
	IN	DAT_EVD_HANDLE request_evd_handle,
	IN	DAT_EVD_HANDLE connect_evd_handle,
	IN	DAT_SRQ_HANDLE srq_handle,
	IN	const DAT_EP_ATTR *ep_attr,
	OUT	DAT_EP_HANDLE *ep_handle);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_EP_UTIL_H_ */
