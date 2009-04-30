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
 * MODULE: dapl_cno_wait.c
 *
 * PURPOSE: Wait for a consumer notification event
 * Description: Interfaces in this file are completely described in
 *		the DAPL 1.1 API, Chapter 6, section 3.2.3
 *
 * $Id: dapl_cno_wait.c,v 1.6 2003/06/16 17:53:32 sjs2 Exp $
 */

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_ring_buffer_util.h"

/*
 * dapl_cno_wait
 *
 * DAPL Requirements Version xxx, 6.3.2.3
 *
 * Wait for a consumer notification event
 *
 * Input:
 *	cno_handle
 *	timeout
 *	evd_handle
 *
 * Output:
 *	evd_handle
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_QUEUE_EMPTY
 *	DAT_INVALID_PARAMETER
 */
DAT_RETURN
dapl_cno_wait(
	IN	DAT_CNO_HANDLE		cno_handle,	/* cno_handle */
	IN	DAT_TIMEOUT		timeout,	/* agent */
	OUT	DAT_EVD_HANDLE		*evd_handle)	/* evd_handle */
{
	DAPL_CNO 	*cno_ptr;
	DAPL_EVD	*evd_ptr, *head_evd_ptr;
	DAT_RETURN 	dat_status;
	int		nevents;

	if (DAPL_BAD_HANDLE(cno_handle, DAPL_MAGIC_CNO)) {
		dat_status = DAT_INVALID_HANDLE | DAT_INVALID_HANDLE_CNO;
		goto bail;
	}

	dat_status = DAT_SUCCESS;
	cno_ptr = (DAPL_CNO *) cno_handle;

	if (cno_ptr->cno_state == DAPL_CNO_STATE_DEAD) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_CNO_DEAD);
		goto bail;
	}

	dapl_os_lock(&cno_ptr->header.lock);
	if (dapl_llist_is_empty(&cno_ptr->evd_list_head)) {
		dapl_os_unlock(&cno_ptr->header.lock);
		return (DAT_ERROR(DAT_QUEUE_EMPTY, 0));
	}

	/* scan evd list */
	evd_ptr = (DAPL_EVD *)
	    dapl_llist_next_entry(&cno_ptr->evd_list_head, NULL);

	for (;;) {
		/*
		 * Check the evd ring buffer for events, if nothing is found
		 * peek into the CQ to see if there are events
		 */
		if (dapls_rbuf_count(&evd_ptr->pending_event_queue) > 0) {
			break;
		}

		nevents = 0;
		dapls_ib_cq_peek(evd_ptr, &nevents);
		if (nevents > 0) {
			break;
		}

		evd_ptr = (DAPL_EVD *)
		    dapl_llist_next_entry(&cno_ptr->evd_list_head,
		    &evd_ptr->cno_list_entry);
		if (evd_ptr == NULL) {
			break;
		}
	}

	/* shift list by one to simulate round-robin */
	head_evd_ptr = (DAPL_EVD *)
	    dapl_llist_remove_head(&cno_ptr->evd_list_head);
	dapl_os_assert(head_evd_ptr != NULL);
	dapl_llist_add_tail(&cno_ptr->evd_list_head,
	    &head_evd_ptr->cno_list_entry, head_evd_ptr);

	if (evd_ptr != NULL) {
		*evd_handle = evd_ptr;
		dapl_os_unlock(&cno_ptr->header.lock);
		return (DAT_SUCCESS);
	}

	cno_ptr->cno_waiters++;
	dapl_os_unlock(&cno_ptr->header.lock);

	dat_status = dapls_ib_cno_wait(cno_ptr, timeout, &evd_ptr);

	dapl_os_lock(&cno_ptr->header.lock);
	cno_ptr->cno_waiters--;

	/* verify that evd_ptr is still in the list */
	head_evd_ptr = dapl_llist_next_entry(&cno_ptr->evd_list_head, NULL);
	for (;;) {
		if (head_evd_ptr == NULL || head_evd_ptr == evd_ptr) {
			break;
		}
		head_evd_ptr = (DAPL_EVD *)
		    dapl_llist_next_entry(&cno_ptr->evd_list_head,
		    &head_evd_ptr->cno_list_entry);
	}

	if (cno_ptr->cno_state == DAPL_CNO_STATE_DEAD) {
		dat_status = DAT_ERROR(DAT_INVALID_STATE,
		    DAT_INVALID_STATE_CNO_DEAD);
	} else if (dat_status == DAT_SUCCESS) {
		/*
		 * After the first triggering, this will be a valid handle.
		 * If we're racing with wakeups of other CNO waiters,
		 * that's ok.
		 */
		if (head_evd_ptr == evd_ptr && evd_ptr != NULL) {
			*evd_handle = evd_ptr;
		} else {
			dat_status = DAT_ERROR(DAT_QUEUE_EMPTY, 0);
		}
	}
	/*
	 * The only other reason we could have made it out of
	 * the loop is a timeout.
	 */
	dapl_os_unlock(&cno_ptr->header.lock);
bail:
	return (dat_status);
}
