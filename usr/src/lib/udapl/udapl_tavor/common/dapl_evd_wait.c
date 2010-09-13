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
 * MODULE: dapl_evd_wait.c
 *
 * PURPOSE: EVENT management
 *
 * Description: Interfaces in this file are completely defined in
 *              the uDAPL 1.1 API specification
 *
 * $Id: dapl_evd_wait.c,v 1.22 2003/08/20 13:18:36 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_evd_util.h"
#include "dapl_ring_buffer_util.h"
#include "dapl_adapter_util.h"

/*
 * dapl_evd_wait
 *
 * UDAPL Requirements Version xxx,
 *
 * Wait, up to specified timeout, for notification event on EVD.
 * Then return first available event.
 *
 * Input:
 * 	evd_handle
 * 	timeout
 *
 * Output:
 * 	event
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_STATE
 */
DAT_RETURN dapl_evd_wait(
    IN  DAT_EVD_HANDLE	evd_handle,
    IN  DAT_TIMEOUT	time_out,
    IN  DAT_COUNT	threshold,
    OUT DAT_EVENT	*event,
    OUT DAT_COUNT	*nmore)

{
	DAPL_EVD		*evd_ptr;
	DAT_RETURN		dat_status;
	DAT_EVENT		*local_event;
	DAT_BOOLEAN		waitable;
	DAPL_EVD_STATE		evd_state;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_evd_wait (%p, %d, %d, %p, %p)\n",
	    evd_handle,
	    time_out,
	    threshold,
	    event,
	    nmore);

	evd_ptr = (DAPL_EVD *)evd_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(evd_ptr, DAPL_MAGIC_EVD)) {
		/*
		 * We return directly rather than bailing because
		 * bailing attempts to update the evd, and we don't have
		 * one.
		 */
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}
	if (!event) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG4);
		goto bail;
	}
	if (!nmore) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG5);
		goto bail;
	}
	if (threshold <= 0 ||
	    (threshold > 1 &&
		evd_ptr->completion_type != DAPL_EVD_STATE_THRESHOLD)) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG3);
		goto bail;
	}
	if (evd_ptr->catastrophic_overflow) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE, 0);
		goto bail;
	}

	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
	    "dapl_evd_wait: EVD %p, CQ %p\n",
	    evd_ptr,
	    (void *)evd_ptr->ib_cq_handle);

	/*
	 * Make sure there are no other waiters and the evd is active.
	 * Currently this means only the OPEN state is allowed.
	 * We need to take a lock to synchronize with dapl_evd_dequeue().
	 */

	dapl_os_lock(&evd_ptr->header.lock);
	waitable = evd_ptr->evd_waitable;
	evd_state = evd_ptr->evd_state;
	if (evd_state != DAPL_EVD_STATE_OPEN || !waitable) {
		dapl_os_unlock(&evd_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_STATE, 0);
		goto bail;
	}
	evd_ptr->evd_state = DAPL_EVD_STATE_WAITED;
	dapl_os_unlock(&evd_ptr->header.lock);

	/*
	 * We now own the EVD, we don't have the lock anymore,
	 * because we're in the WAITED state.
	 */

	evd_ptr->threshold = threshold;

	/* return pending events immediately without further polling */
	if (dapls_rbuf_count(&evd_ptr->pending_event_queue) > 0) {
		evd_ptr->evd_state = DAPL_EVD_STATE_OPEN;
		dat_status = DAT_SUCCESS;
	} else {
		dat_status = dapls_evd_copy_events(evd_ptr, time_out);
		evd_ptr->evd_state = DAPL_EVD_STATE_OPEN;
		if (DAT_GET_TYPE(dat_status) == DAT_INTERRUPTED_CALL) {
			goto bail;
		}
		if (!evd_ptr->evd_waitable) {
			/* See if we were awakened by evd_set_unwaitable */
			dat_status = DAT_ERROR(DAT_INVALID_STATE, 0);
			goto bail;
		}
		if (dapls_rbuf_count(&evd_ptr->pending_event_queue) == 0) {
			dat_status = DAT_ERROR(DAT_TIMEOUT_EXPIRED, 0);
		}
	}

	if (dat_status == DAT_SUCCESS) {
		local_event = dapls_rbuf_remove(&evd_ptr->pending_event_queue);
		*event = *local_event;
		dat_status = dapls_rbuf_add(&evd_ptr->free_event_queue,
		    local_event);
		dapl_os_assert(dat_status == DAT_SUCCESS);
	}

	/*
	 * Valid if dat_status == DAT_SUCCESS || dat_status == DAT_TIMEOUT
	 * Undefined otherwise, so ok to set it.
	 */
	*nmore = dapls_rbuf_count(&evd_ptr->pending_event_queue);

bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_evd_wait () returns 0x%x\n",
	    dat_status);

	return (dat_status);
}
