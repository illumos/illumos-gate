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
 * MODULE: dapl_ep_dup_connect.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_dup_connect.c,v 1.8 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_ep_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_ep_dup_connect
 *
 * DAPL Requirements Version xxx, 6.5.8
 *
 * Requst that a connection be established between the local Endpoint
 * and a remote Endpoint. The remote Endpoint is identified by the
 * dup_ep.
 *
 * Input:
 *	ep_handle
 *	ep_dup_handle
 *	conn_qual
 *	timeout
 *	private_data_size
 *	private_data
 *	qos
 *
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_STATE
 *	DAT_MODEL_NOT_SUPPORTED
 */

DAT_RETURN
dapl_ep_dup_connect(
	IN DAT_EP_HANDLE ep_handle,
	IN DAT_EP_HANDLE ep_dup_handle,
	IN DAT_TIMEOUT timeout,
	IN DAT_COUNT private_data_size,
	IN const DAT_PVOID private_data,
	IN DAT_QOS qos)
{
	DAPL_EP *ep_dup_ptr;
	DAT_RETURN dat_status;
	DAT_IA_ADDRESS_PTR remote_ia_address_ptr;
	DAT_CONN_QUAL remote_conn_qual;

	ep_dup_ptr = (DAPL_EP *)ep_dup_handle;

	/*
	 * Verify the dup handle, which must be connected. All other
	 * parameters will be verified by dapl_ep_connect
	 */
	if (DAPL_BAD_HANDLE(ep_dup_handle, DAPL_MAGIC_EP)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE,
		    DAT_INVALID_HANDLE_EP);
		goto bail;
	}
	/*
	 * Check both the EP state and the QP state: if we don't have a QP
	 *  there is a problem.  Do this under a lock and pull out
	 * the connection parameters for atomicity.
	 */
	dapl_os_lock(&ep_dup_ptr->header.lock);
	if (ep_dup_ptr->param.ep_state != DAT_EP_STATE_CONNECTED) {
		dapl_os_unlock(&ep_dup_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    dapls_ep_state_subtype(ep_dup_ptr));
		goto bail;
	}
	remote_ia_address_ptr = ep_dup_ptr->param.remote_ia_address_ptr;
	remote_conn_qual = ep_dup_ptr->param.remote_port_qual;
	dapl_os_unlock(&ep_dup_ptr->header.lock);

	dat_status = dapl_ep_connect(ep_handle,
	    remote_ia_address_ptr, remote_conn_qual, timeout,
	    private_data_size, private_data, qos,
	    DAT_CONNECT_DEFAULT_FLAG);

bail:
	return (dat_status);
}
