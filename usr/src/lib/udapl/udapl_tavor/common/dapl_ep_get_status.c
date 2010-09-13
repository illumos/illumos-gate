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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_ep_get_status.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_get_status.c,v 1.9 2003/07/30 18:13:37 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_ring_buffer_util.h"

/*
 * dapl_ep_get_status
 *
 * DAPL Requirements Version xxx, 6.5.4
 *
 * Provide the consumer with a quick snapshot of the Endpoint.
 * The snapshot consists of Endpoint state and DTO information.
 *
 * Input:
 *	ep_handle
 *
 * Output:
 *	ep_state
 *	in_dto_idle
 *	out_dto_idle
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */

DAT_RETURN
dapl_ep_get_status(
	IN DAT_EP_HANDLE ep_handle,
	OUT DAT_EP_STATE *ep_state,
	OUT DAT_BOOLEAN	*in_dto_idle,
	OUT DAT_BOOLEAN	*out_dto_idle)
{
	DAPL_EP *ep_ptr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_ep_get_status (%p, %p, %p, %p)\n",
	    ep_handle, ep_state, in_dto_idle, out_dto_idle);

	ep_ptr = (DAPL_EP *)ep_handle;
	dat_status = DAT_SUCCESS;

	/*
	 * Verify parameter & state
	 */
	if (DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	/*
	 * Gather state info for user
	 */
	if (ep_state != NULL) {
		*ep_state = ep_ptr->param.ep_state;
	}

	if (in_dto_idle != NULL) {
		*in_dto_idle = (ep_ptr->recv_count) ? DAT_FALSE : DAT_TRUE;
	}

	if (out_dto_idle != NULL) {
		*out_dto_idle = (ep_ptr->req_count) ? DAT_FALSE : DAT_TRUE;
	}

bail:
	return (dat_status);
}
