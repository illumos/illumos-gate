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
 * MODULE: dapl_ep_reset.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5.13
 *
 * $Id: dapl_ep_reset.c,v 1.6 2003/07/08 14:23:35 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_ia_util.h"
#include "dapl_ep_util.h"
#include "dapl_adapter_util.h"
#include "dapl_ring_buffer_util.h"

/*
 * dapl_ep_reset
 *
 * DAPL Requirements Version 1.1, 6.5.13
 *
 * Reset the QP attached to this Endpoint, transitioning back to the
 * INIT state
 *
 * Input:
 *	ep_handle
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_STATE
 */
DAT_RETURN
dapl_ep_reset(
	IN DAT_EP_HANDLE ep_handle)
{
	DAPL_EP	*ep_ptr;
	DAT_RETURN dat_status;

	dat_status = DAT_SUCCESS;

	ep_ptr = (DAPL_EP *)ep_handle;

	/*
	 * Verify parameter & state
	 */
	if (DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	if (ep_ptr->param.ep_state != DAT_EP_STATE_UNCONNECTED &&
	    ep_ptr->param.ep_state != DAT_EP_STATE_DISCONNECTED) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_ptr));
		goto bail;
	}

	if (ep_ptr->param.ep_state == DAT_EP_STATE_DISCONNECTED) {
		dapls_ib_reinit_ep(ep_ptr);
		ep_ptr->param.ep_state = DAT_EP_STATE_UNCONNECTED;
	}

bail:
	return (dat_status);
}
