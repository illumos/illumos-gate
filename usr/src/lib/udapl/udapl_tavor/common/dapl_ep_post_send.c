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
 * MODULE: dapl_ep_post_send.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_post_send.c,v 1.7 2003/07/30 18:13:37 hobie16 Exp $
 */

#include "dapl_ep_util.h"

/*
 * dapl_ep_post_send
 *
 * DAPL Requirements Version xxx, 6.5.10
 *
 * Request a transfer of all the data from the local_iov over
 * the connection of the ep handle Endpoint to the remote side.
 *
 * Input:
 *	ep_handle
 *	num_segments
 *	local_iov
 *	user_cookie
 *	completion_flags
 *
 * Output:
 *	None
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_STATE
 *	DAT_PROTECTION_VIOLATION
 *	DAT_PRIVILEGES_VIOLATION
 */
DAT_RETURN
dapl_ep_post_send(
	IN	DAT_EP_HANDLE		ep_handle,
	IN	DAT_COUNT		num_segments,
	IN	DAT_LMR_TRIPLET		*local_iov,
	IN	DAT_DTO_COOKIE		user_cookie,
	IN	DAT_COMPLETION_FLAGS	completion_flags)
{
	DAT_RMR_TRIPLET	remote_iov = {0, 0, 0, 0};
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_ep_post_send(%p, %d, %p, %P, %x)\n",
	    ep_handle,
	    num_segments,
	    local_iov,
	    user_cookie.as_64,
	    completion_flags);

	dat_status = dapl_ep_post_send_req(ep_handle,
	    num_segments,
	    local_iov,
	    user_cookie,
	    &remote_iov,
	    completion_flags,
	    DAPL_DTO_TYPE_SEND,
	    OP_SEND);

	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_ep_post_send () returns 0x%x\n", dat_status);

	return (dat_status);
}
