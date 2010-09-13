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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_evd_dequeue.c
 *
 * PURPOSE: Event Management
 *
 * Description:  Interfaces in this file are completely described in
 *               the uDAPL 1.1 API, Chapter 6, section 3
 *
 * $Id: dapl_evd_dequeue.c,v 1.9 2003/07/30 18:13:38 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_ring_buffer_util.h"
#include "dapl_evd_util.h"

/*
 * dapl_evd_dequeue
 *
 * DAPL Requirements Version xxx, 6.3.2.7
 *
 * Remove first element from an event dispatcher
 *
 * Input:
 * 	evd_handle
 *
 * Output:
 * 	event
 *
 * Returns:
 * 	DAT_SUCCESS
 * 	DAT_INVALID_HANDLE
 * 	DAT_INVALID_PARAMETER
 * 	DAT_INVALID_STATE
 * 	DAT_QUEUE_EMPTY
 */

DAT_RETURN dapl_evd_dequeue(
    IN    DAT_EVD_HANDLE	evd_handle,
    OUT   DAT_EVENT		*event)
{
	DAPL_EVD	*evd_ptr;
	DAT_EVENT	*local_event;
	DAT_RETURN	dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_API,
	    "dapl_evd_dequeue (%p, %p)\n",
	    evd_handle,
	    event);

	evd_ptr = (DAPL_EVD *)evd_handle;
	dat_status = DAT_SUCCESS;

	if (DAPL_BAD_HANDLE(evd_handle, DAPL_MAGIC_EVD)) {
		dat_status = DAT_ERROR(DAT_INVALID_HANDLE, 0);
		goto bail;
	}

	if (event == NULL) {
		dat_status = DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG2);
		goto bail;
	}

	/*
	 * We need to dequeue under lock, as the IB OS Access API
	 * restricts us from having multiple threads in CQ poll, and the
	 * DAPL 1.1 API allows multiple threads in dat_evd_dequeue()
	 */
	dapl_os_lock(&evd_ptr->header.lock);

	/*
	 * Make sure there are no other waiters and the evd is active.
	 * Currently this means only the OPEN state is allowed.
	 */
	if (evd_ptr->evd_state != DAPL_EVD_STATE_OPEN ||
	    evd_ptr->catastrophic_overflow) {
		dapl_os_unlock(&evd_ptr->header.lock);
		dat_status = DAT_ERROR(DAT_INVALID_STATE, 0);
		goto bail;
	}

	/*
	 * Try the EVD rbuf first; poll from the CQ only if that's empty.
	 * This keeps events in order if dat_evd_wait() has copied events
	 * from CQ to EVD.
	 */
	if (evd_ptr->pending_event_queue.head !=
	    evd_ptr->pending_event_queue.tail) {
		local_event = (DAT_EVENT *)
		    dapls_rbuf_remove(&evd_ptr->pending_event_queue);
		if (local_event != NULL) {
			*event = *local_event;
			dat_status = dapls_rbuf_add(&evd_ptr->free_event_queue,
			    local_event);
		} else { /* should never happen */
			dat_status = DAT_ERROR(DAT_INTERNAL_ERROR, 0);
		}
	} else if (evd_ptr->ib_cq_handle == IB_INVALID_HANDLE) {
		dat_status =  DAT_ERROR(DAT_QUEUE_EMPTY, 0);
	} else if ((evd_ptr->evd_flags & (DAT_EVD_CONNECTION_FLAG |
	    DAT_EVD_CR_FLAG | DAT_EVD_ASYNC_FLAG)) == 0) {
		/*
		 * No need to drop into kernel, just check the CQ.
		 */
		dat_status = dapls_evd_cq_poll_to_event(evd_ptr, event);
	} else {
		/* poll for events with threshold and timeout both 0 */
		evd_ptr->threshold = 0;

		dapl_os_unlock(&evd_ptr->header.lock);
		dat_status = dapls_evd_copy_events(evd_ptr, 0);
		if (dat_status != DAT_SUCCESS) {
			dat_status = DAT_ERROR(DAT_QUEUE_EMPTY, 0);
			goto bail;
		}

		dapl_os_lock(&evd_ptr->header.lock);

		local_event = (DAT_EVENT *)dapls_rbuf_remove(
		    &evd_ptr->pending_event_queue);
		if (local_event != NULL) {
			*event = *local_event;
			dat_status = dapls_rbuf_add(&evd_ptr->free_event_queue,
			    local_event);
		} else { /* still didn't find anything */
			dat_status =  DAT_ERROR(DAT_QUEUE_EMPTY, 0);
		}
	}

	dapl_os_unlock(&evd_ptr->header.lock);
bail:
	dapl_dbg_log(DAPL_DBG_TYPE_RTN,
	    "dapl_evd_dequeue () returns 0x%x\n",
	    dat_status);

	return (dat_status);
}
