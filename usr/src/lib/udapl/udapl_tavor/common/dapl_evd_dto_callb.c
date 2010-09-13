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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * MODULE: dapl_evd_dto_callback.c
 *
 * PURPOSE: implements DTO callbacks from verbs
 *
 * $Id: dapl_evd_dto_callb.c,v 1.17 2003/07/30 18:13:38 hobie16 Exp $
 */

#include "dapl.h"
#include "dapl_evd_util.h"
#include "dapl_cno_util.h"
#include "dapl_cookie.h"
#include "dapl_adapter_util.h"

/*
 * dapl_evd_dto_callback
 *
 * Input:
 * 	hca_handle_in,
 * 	cq_handle_in,
 *      user_context_cq_p
 *
 * Output:
 *	none
 *
 * This is invoked for both DTO and MW bind completions. Strictly
 * speaking it is an event callback rather than just a DTO callback.
 *
 */

void
dapl_evd_dto_callback(
    IN ib_hca_handle_t 	hca_handle,
    IN ib_cq_handle_t 	cq_handle,
    IN void		*user_context)
{
	DAPL_EVD	*evd_ptr;
	DAT_RETURN	dat_status;
	DAPL_EVD_STATE	state;

	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "dapl_evd_dto_callback(%p, %p, %p)\n",
	    hca_handle,
	    cq_handle,
	    user_context);

	evd_ptr = (DAPL_EVD *) user_context;

	dapl_os_assert(hca_handle ==
	    evd_ptr->header.owner_ia->hca_ptr->ib_hca_handle);
	dapl_os_assert(evd_ptr->ib_cq_handle == cq_handle);
	dapl_os_assert(evd_ptr->header.magic == DAPL_MAGIC_EVD);

	/* Read once.  */
	state = *(volatile DAPL_EVD_STATE *) &evd_ptr->evd_state;

	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
	    "-- dapl_evd_dto_callback: CQ %p, state %x\n",
	    (void *)evd_ptr->ib_cq_handle,
	    state);

	/*
	 * This function does not dequeue from the CQ; only the consumer
	 * can do that. Instead, it wakes up waiters if any exist.
	 * It rearms the completion only if completions should always occur
	 * (specifically if a CNO is associated with the EVD and the
	 * EVD is enabled.
	 */

	if (state == DAPL_EVD_STATE_WAITED) {
		/*
		 * If we could, it would be best to avoid this wakeup
		 * (and the context switch) unless the number of events/CQs
		 * waiting for the waiter was its threshold.  We don't
		 * currently have the ability to determine that without
		 * dequeueing the events, and we can't do that for
		 * synchronization reasons (racing with the waiter waking
		 * up and dequeuing, sparked by other callbacks).
		 */

		/*
		 * We don't need to worry about taking the lock for the
		 * wakeup because wakeups are sticky.
		 */
		(void) dapl_os_wait_object_wakeup(&evd_ptr->wait_object);
	} else if (state == DAPL_EVD_STATE_OPEN) {
		DAPL_CNO *cno = evd_ptr->cno_ptr;
		if (evd_ptr->evd_enabled && (evd_ptr->cno_ptr != NULL)) {
			/*
			 * Re-enable callback, *then* trigger.
			 * This guarantees we won't miss any events.
			 */
			dat_status = DAPL_NOTIFY(evd_ptr)(
			    evd_ptr->ib_cq_handle, IB_NOTIFY_ON_NEXT_COMP, 0);

			if (DAT_SUCCESS != dat_status) {
				(void) dapls_evd_post_async_error_event(
				    evd_ptr->header.owner_ia->async_error_evd,
				    DAT_ASYNC_ERROR_PROVIDER_INTERNAL_ERROR,
				    (DAT_IA_HANDLE)evd_ptr->header.owner_ia);
			}

			dapl_cno_trigger(cno, evd_ptr);
		}
	}
	dapl_dbg_log(DAPL_DBG_TYPE_RTN, "dapl_evd_dto_callback() returns\n");
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
