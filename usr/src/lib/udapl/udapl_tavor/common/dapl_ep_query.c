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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_ep_query.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_query.c,v 1.8 2003/08/20 13:22:05 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_adapter_util.h"

/*
 * dapl_ep_query
 *
 * DAPL Requirements Version xxx, 6.5.5
 *
 * Provide the consumer parameters, including attributes and status of
 * the Endpoint.
 *
 * Input:
 *	ep_handle
 *	ep_param_mask
 *
 * Output:
 *	ep_param
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_ep_query(
	IN DAT_EP_HANDLE ep_handle,
	IN DAT_EP_PARAM_MASK ep_param_mask,
	OUT DAT_EP_PARAM *ep_param)
{
	DAPL_EP *ep_ptr;
	DAT_RETURN dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API, "dapl_ep_query (%p, %x, %p)\n",
	    ep_handle, ep_param_mask, ep_param);

	dat_status = DAT_SUCCESS;
	ep_ptr = (DAPL_EP *) ep_handle;

	/*
	 * Verify parameter & state
	 */
	if (DAPL_BAD_HANDLE(ep_ptr, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}

	if (ep_param == NULL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	/*
	 * Fill in according to user request
	 *
	 * N.B. Just slam all values into the user structure, there
	 * is nothing to be gained by checking for each bit.
	 */
	if (ep_param_mask & DAT_EP_FIELD_ALL) {
		if (ep_ptr->param.ep_state == DAT_EP_STATE_CONNECTED) {
			/* obtain the remote IP address */
			dat_status = dapls_ib_cm_remote_addr(
			    (DAT_HANDLE)ep_handle, NULL,
			    &ep_ptr->remote_ia_address);
		}
		*ep_param = ep_ptr->param;
	}

bail:
	return (dat_status);
}
