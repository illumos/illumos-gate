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
 * MODULE: dapl_evd_cq_async_error_callback.c
 *
 * PURPOSE: implements CQ async_callbacks from verbs
 *
 * $Id: dapl_evd_cq_async_error_callb.c,v 1.8 2003/07/31 13:55:18 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_evd_util.h"

/*
 * dapl_evd_cq_async_error_callback
 *
 * The callback function registered with verbs for cq async errors
 *
 * Input:
 * 	ib_cm_handle,
 * 	ib_cm_event
 * 	cause_ptr
 * 	context (evd)
 *
 * Output:
 * 	None
 *
 */

void
dapl_evd_cq_async_error_callback(
	IN	ib_hca_handle_t		ib_hca_handle,
	IN	ib_cq_handle_t		ib_cq_handle,
	IN	ib_error_record_t	*cause_ptr,
	IN	void			*context)
{
	DAPL_EVD		*async_evd;
	DAPL_EVD		*evd;
	DAT_RETURN		dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK | DAPL_DBG_TYPE_EXCEPTION,
	    "dapl_evd_cq_async_error_callback (%p, %p, %p, %p)\n",
	    ib_hca_handle,
	    ib_cq_handle,
	    cause_ptr,
	    context);

	if (NULL == context) {
		dapl_os_assert(!"NULL == context\n");
		return;
	}

	evd = (DAPL_EVD *) context;
	async_evd = evd->header.owner_ia->async_error_evd;

	dat_status = dapls_evd_post_async_error_event(
	    async_evd,
	    DAT_ASYNC_ERROR_EVD_OVERFLOW,
	    (DAT_IA_HANDLE) async_evd->header.owner_ia);


	if (dat_status != DAT_SUCCESS) {
		dapl_os_assert(!"async EVD overflow\n");
	}

	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK | DAPL_DBG_TYPE_EXCEPTION,
	    "dapl_evd_cq_async_error_callback () returns\n");
}
