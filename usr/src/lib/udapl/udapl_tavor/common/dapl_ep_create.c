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
 * MODULE: dapl_ep_create.c
 *
 * PURPOSE: Endpoint management
 * Description: Interfaces in this file are completely described in
 *		the kDAPL 1.1 API, Chapter 6, section 5
 *
 * $Id: dapl_ep_create.c,v 1.20 2003/06/30 16:49:36 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_ia_util.h"
#include "dapl_ep_util.h"
#include "dapl_adapter_util.h"


/*
 * dapl_ep_create
 *
 * uDAPL Version 1.1, 6.5.3
 *
 * Create an instance of an Endpoint that is provided to the
 * consumer at ep_handle.
 *
 * Input:
 *	ia_handle
 *	pz_handle
 *	recv_evd_handle (recv DTOs)
 *	request_evd_handle (xmit DTOs)
 *	connect_evd_handle
 *	ep_attrs
 *
 * Output:
 *	ep_handle
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INSUFFICIENT_RESOURCES
 *	DAT_INVALID_PARAMETER
 *	DAT_INVALID_ATTRIBUTE
 *	DAT_MODEL_NOT_SUPPORTED
 */
DAT_RETURN
dapl_ep_create(
	IN	DAT_IA_HANDLE		ia_handle,
	IN	DAT_PZ_HANDLE		pz_handle,
	IN	DAT_EVD_HANDLE		recv_evd_handle,
	IN	DAT_EVD_HANDLE		request_evd_handle,
	IN	DAT_EVD_HANDLE		connect_evd_handle,
	IN	const DAT_EP_ATTR	*ep_attr,
	OUT	DAT_EP_HANDLE		*ep_handle)
{
	return (dapl_ep_create_common(ia_handle, pz_handle, recv_evd_handle,
	    request_evd_handle, connect_evd_handle, DAT_HANDLE_NULL,
	    ep_attr, ep_handle));
}


/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
