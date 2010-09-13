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
 * MODULE: dapl_ep_post_recv.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_post_recv.c,v 1.17 2003/07/30 18:13:37 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_cookie.h"
#include "dapl_adapter_util.h"

/*
 * dapl_ep_post_recv
 *
 * DAPL Requirements Version xxx, 6.5.11
 *
 * Request to receive data over the connection of ep handle into
 * local_iov
 *
 * Input:
 * 	ep_handle
 * 	num_segments
 * 	local_iov
 * 	user_cookie
 * 	completion_flags
 *
 * Output:
 * 	None.
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INSUFFICIENT_RESOURCES
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_STATE
 * 	DAT_PROTECTION_VIOLATION
 * 	DAT_PROVILEGES_VIOLATION
 */
DAT_RETURN
dapl_ep_post_recv(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	DAT_COMPLETION_FLAGS	completion_flags)
{
	DAPL_EP 		*ep_ptr;
	DAPL_COOKIE		*cookie;
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_ep_post_recv (%p, %d, %p, %P, %x)\n",
	    ep_handle,
	    num_segments,
	    local_iov,
	    user_cookie.as_64,
	    completion_flags);

	if (DAPL_BAD_HANDLE(ep_handle, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	ep_ptr = (DAPL_EP *) ep_handle;

	/* dat_ep_post_recv is not supported on EPs with SRQ */
	if (ep_ptr->srq_attached) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE, 0);
		goto bail;
	}

	/*
	 * Synchronization ok since this buffer is only used for receive
	 * requests, which aren't allowed to race with each other.
	 */
	dat_status = dapls_dto_cookie_alloc(&ep_ptr->recv_buffer,
	    DAPL_DTO_TYPE_RECV,
	    user_cookie,
	    &cookie);
	if (DAT_SUCCESS != dat_status) {
		goto bail;
	}

	/*
	 * Invoke provider specific routine to post DTO
	 */
	if (num_segments != 1 ||
	    completion_flags != DAT_COMPLETION_DEFAULT_FLAG)
		dat_status = dapls_ib_post_recv(ep_ptr, cookie, num_segments,
		    local_iov, completion_flags);
	else
		dat_status = dapls_ib_post_recv_one(ep_ptr, cookie, local_iov);

	if (dat_status != DAT_SUCCESS) {
		dapls_cookie_dealloc(&ep_ptr->recv_buffer, cookie);
	} else {
		dapl_os_atomic_inc(&ep_ptr->recv_count);
	}

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_ep_post_recv () returns 0x%x\n", dat_status);

	return (dat_status);
}
