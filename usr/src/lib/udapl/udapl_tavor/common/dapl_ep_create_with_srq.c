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
 * MODULE: dapl_ep_create_with_srq.c
 *
 * PURPOSE: EP creates with SRQ
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.2 API, Chapter 6, section 6
 *
 */

#include "dapl.h"
#include "dapl_ep_util.h"

/*
 * dapl_ep_create_with_srq
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.7.4.1
 *
 * creates an instance of an Endpoint that is using SRQ for Recv buffers
 * is provided to the Consumer as ep_handle. Endpoint is created in
 * Unconnected state.
 *
 * Input:
 * 	ia_handle
 * 	pz_handle
 *	recv_evd_handle
 *	request_evd_handle
 *	connect_evd_handle
 *	srq_handle
 * 	ep_attributes
 *
 * Output:
 * 	ep_handle
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 *	DAT_MODEL_NOT_SUPPORTED
 */

/* ARGSUSED */
DAT_RETURN
dapl_ep_create_with_srq(
	IN	DAT_IA_HANDLE ia_handle,
	IN	DAT_PZ_HANDLE pz_handle,
	IN	DAT_EVD_HANDLE recv_evd_handle,
	IN	DAT_EVD_HANDLE request_evd_handle,
	IN	DAT_EVD_HANDLE connect_evd_handle,
	IN	DAT_SRQ_HANDLE srq_handle,
	IN	const DAT_EP_ATTR *ep_attributes,
	OUT	DAT_EP_HANDLE *ep_handle)
{
	return (dapl_ep_create_common(ia_handle, pz_handle, recv_evd_handle,
	    request_evd_handle, connect_evd_handle, srq_handle, ep_attributes,
	    ep_handle));
}

/*
 * dapl_ep_recv_query
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.6.10
 *
 * provides to the Consumer a snapshot for Recv buffers on EP. The values
 * for nbufs_allocated and bufs_alloc_span are not defined when DAT_RETURN
 * is not DAT_SUCCESS.
 *
 * Input:
 * 	ep_handle
 *
 * Output:
 * 	nbufs_allocated
 *	bufs_alloc_span
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 *	DAT_MODEL_NOT_SUPPORTED
 */

/* ARGSUSED */
DAT_RETURN
dapl_ep_recv_query(
	IN	DAT_EP_HANDLE ep_handle,
	OUT	DAT_COUNT *nbufs_allocated,
	OUT	DAT_COUNT *bufs_alloc_span)
{
	return (DAT_MODEL_NOT_SUPPORTED);
}

/*
 * dapl_ep_set_watermark
 *
 * uDAPL: User Direct Access Program Library Version 1.2, 6.6.12
 *
 * sets the soft and hard high watermark values for EP and arms EP
 * for generating asynchronous events for high watermarks. An asynchronous
 * event will be generated for IA async_evd when the number of Recv buffers
 * at EP is above the soft high watermark for the first time. An connection
 * broken event will be generated for EP connect_evd when the number of Recv
 * buffers at EP is above the hard high watermark. These may happen during
 * this call or when EP takes a buffer from the SRQ or EP RQ. The soft and
 * hard high watermark asynchronous event generation and setting are
 * independent from each other.
 *
 * Input:
 * 	ep_handle
 *	soft_high_watermark
 *	hard_high_watermark
 *
 * Output:
 * 	none
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_MODEL_NOT_SUPPORTED
 */

/* ARGSUSED */
DAT_RETURN
dapl_ep_set_watermark(
	IN	DAT_EP_HANDLE ep_handle,
	IN	DAT_COUNT soft_high_watermark,
	IN	DAT_COUNT hard_high_watermark)
{
	return (DAT_MODEL_NOT_SUPPORTED);
}
