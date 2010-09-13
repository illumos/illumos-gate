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
 * MODULE: dapl_evd_query.c
 *
 * PURPOSE: Event management
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_query.c,v 1.8 2003/08/20 13:18:36 sjs2 Exp $
 */

#include "dapl.h"

/*
 * dapl_evd_query
 *
 * DAPL Requirements Version xxx, 6.3.2.3
 *
 * Provides the consumer with arguments of the Event Dispatcher.
 *
 * Input:
 * 	evd_handle
 * 	evd_mask
 *
 * Output:
 * 	evd_param
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_evd_query(
	IN	DAT_EVD_HANDLE		evd_handle,
	IN	DAT_EVD_PARAM_MASK	evd_param_mask,
	OUT	DAT_EVD_PARAM		*evd_param)
{
	DAPL_EVD	    *evd_ptr;
	DAT_RETURN	    dat_status;

	dat_status = DAT_SUCCESS;

	if (evd_param_mask & ~DAT_EVD_FIELD_ALL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	if (NULL == evd_param) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}

	/*
	 * Note: the spec. allows for events to be directed to a NULL EVD
	 * with handle of type DAT_HANDLE_NULL. See 6.3.1
	 */
	if (DAT_HANDLE_NULL == evd_handle) {
		(void) dapl_os_memzero(evd_param, sizeof (DAT_EVD_PARAM));
	} else {
		if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
			dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
			goto bail;
		}

		evd_ptr = (DAPL_EVD *) evd_handle;

		/*
		 * We may be racing against the thread safe modify
		 * calls here (dat_evd_{enable,disable,{set,clear}_unwaitable}).
		 * They are thread safe, so our reads need to be atomic with
		 * regard to those calls.  The below is ok (a single bit
		 * read counts as atomic; if it's in transition you'll get one
		 * of the correct values) but we'll need to be careful
		 * about reading the state variable atomically when we add
		 * in waitable/unwaitable.
		 */
		evd_param->evd_state =
		    (evd_ptr->evd_enabled ? DAT_EVD_STATE_ENABLED :
		    DAT_EVD_STATE_DISABLED);
		evd_param->evd_state |=
		    (evd_ptr->evd_waitable ? DAT_EVD_STATE_WAITABLE :
		    DAT_EVD_STATE_UNWAITABLE);
		evd_param->ia_handle = evd_ptr->header.owner_ia;
		evd_param->evd_qlen = evd_ptr->qlen;
		evd_param->cno_handle = (DAT_CNO_HANDLE) evd_ptr->cno_ptr;
		evd_param->evd_flags  = evd_ptr->evd_flags;
	}

bail:
		return (dat_status);
}
