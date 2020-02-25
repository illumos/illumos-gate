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
 * MODULE: dapl_evd_util.c
 *
 * PURPOSE: Manage EVD Info structure
 *
 * $Id: dapl_evd_util.c,v 1.41 2003/08/20 13:18:36 sjs2 Exp $
 */

#include <sys/time.h>
#include <strings.h>
#include "dapl_evd_util.h"
#include "dapl_ia_util.h"
#include "dapl_cno_util.h"
#include "dapl_ring_buffer_util.h"
#include "dapl_adapter_util.h"
#include "dapl_tavor_ibtf_impl.h"
#include "dapl_cookie.h"
#include "dapl.h"


#ifdef	DAPL_DBG	/* For debugging.  */
static void
dapli_evd_eh_print_cqe(
	IN  ib_work_completion_t	cqe);
#endif

static DAT_BOOLEAN
dapli_evd_cqe_to_event(
    IN DAPL_EVD			*evd_ptr,
    IN ib_work_completion_t	*cqe_ptr,
    IN DAT_BOOLEAN		process_premature_events,
    OUT DAT_EVENT		*event_ptr);

static DAT_RETURN
dapli_evd_event_alloc(
	IN  DAPL_EVD		*evd_ptr,
	IN  DAPL_CNO		*cno_ptr,
	IN  DAT_COUNT		qlen);


/*
 * dapls_evd_internal_create
 *
 * actually create the evd.  this is called after all parameter checking
 * has been performed in dapl_ep_create.  it is also called from dapl_ia_open
 * to create the default async evd.
 *
 * Input:
 *	ia_ptr
 *	cno_ptr
 *	qlen
 *	evd_flags
 *
 * Output:
 *	evd_ptr_ptr
 *
 * Returns:
 *	none
 *
 */

DAT_RETURN
dapls_evd_internal_create(
    DAPL_IA		*ia_ptr,
    DAPL_CNO		*cno_ptr,
    DAT_COUNT		min_qlen,
    DAT_EVD_FLAGS	evd_flags,
    DAPL_EVD		**evd_ptr_ptr)
{
	DAPL_EVD	*evd_ptr;
	DAT_COUNT	cq_len;
	DAT_RETURN	dat_status;

	dat_status	= DAT_SUCCESS;
	*evd_ptr_ptr	= NULL;
	cq_len		= min_qlen;

	evd_ptr = dapls_evd_alloc(ia_ptr,
	    cno_ptr,
	    evd_flags,
	    min_qlen);
	if (!evd_ptr) {
		dat_status = DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY);
		goto bail;
	}

	/*
	 * If we are dealing with event streams besides a CQ event stream,
	 * be conservative and set producer side locking.  Otherwise, no.
	 */
	evd_ptr->evd_producer_locking_needed =
	    ((evd_flags & ~ (DAT_EVD_DTO_FLAG|DAT_EVD_RMR_BIND_FLAG)) != 0);

	/* Before we setup any callbacks, transition state to OPEN.  */
	evd_ptr->evd_state = DAPL_EVD_STATE_OPEN;

	/*
	 * we need to call cq_alloc even for connection/cr/async evds
	 * since all the allocation happens there.
	 */
	dat_status = dapls_ib_cq_alloc(ia_ptr,
	    evd_ptr, cno_ptr, &cq_len);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

#if 0
	/*
	 * Current implementation of dapls_ib_setup_async_callback() does
	 * nothing and returns DAT_SUCCESS. However, it is declared to expect
	 * function pointers with different signatures. We do leave the code
	 * block out till dapls_ib_setup_async_callback() is implemented.
	 */
	dat_status = dapls_ib_setup_async_callback(
	    ia_ptr,
	    DAPL_ASYNC_CQ_COMPLETION,
	    (unsigned int *) evd_ptr->ib_cq_handle,
	    (ib_async_handler_t)dapl_evd_dto_callback,
	    evd_ptr);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}
#endif
	/*
	 * cq_notify is not required since when evd_wait is called
	 * time we go and poll cq anyways.
	 * dat_status = dapls_set_cq_notify(ia_ptr, evd_ptr);
	 */

	/*
	 * We now have an accurate count of events, so allocate them into
	 * the EVD
	 */
	dat_status = dapli_evd_event_alloc(evd_ptr, cno_ptr, cq_len);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	/* We're assuming success in the following.   */
	dapl_os_assert(dat_status == DAT_SUCCESS);
	dapl_ia_link_evd(ia_ptr, evd_ptr);
	*evd_ptr_ptr = evd_ptr;

bail:
	if (dat_status != DAT_SUCCESS) {
		if (evd_ptr) {
			(void) dapls_evd_dealloc(evd_ptr);
		}
	}

	return (dat_status);
}

/*
 * dapls_evd_alloc
 *
 * alloc and initialize an EVD struct
 *
 * Input:
 *	ia
 *
 * Output:
 *	evd_ptr
 *
 * Returns:
 *	none
 *
 */
DAPL_EVD *
dapls_evd_alloc(
    IN DAPL_IA		*ia_ptr,
    IN DAPL_CNO		*cno_ptr,
    IN DAT_EVD_FLAGS	evd_flags,
    IN DAT_COUNT	qlen) /* ARGSUSED */
{
	DAPL_EVD	*evd_ptr;

	evd_ptr    = NULL;

	/* Allocate EVD */
	evd_ptr = (DAPL_EVD *)dapl_os_alloc(sizeof (DAPL_EVD));
	if (!evd_ptr) {
		goto bail;
	}

	/* zero the structure */
	(void) dapl_os_memzero(evd_ptr, sizeof (DAPL_EVD));

	/*
	 * initialize the header
	 */
	evd_ptr->header.provider		= ia_ptr->header.provider;
	evd_ptr->header.magic			= DAPL_MAGIC_EVD;
	evd_ptr->header.handle_type		= DAT_HANDLE_TYPE_EVD;
	evd_ptr->header.owner_ia		= ia_ptr;
	evd_ptr->header.user_context.as_64	= 0;
	evd_ptr->header.user_context.as_ptr	= NULL;
	dapl_llist_init_entry(&evd_ptr->header.ia_list_entry);
	dapl_os_lock_init(&evd_ptr->header.lock);

	/*
	 * Initialize the body
	 */
	evd_ptr->evd_state	= DAPL_EVD_STATE_INITIAL;
	evd_ptr->evd_flags	= evd_flags;
	evd_ptr->evd_enabled	= DAT_TRUE;
	evd_ptr->evd_waitable	= DAT_TRUE;
	evd_ptr->evd_producer_locking_needed = 1; /* Conservative value.  */
	evd_ptr->ib_cq_handle	= IB_INVALID_HANDLE;
	evd_ptr->evd_ref_count	= 0;
	evd_ptr->catastrophic_overflow = DAT_FALSE;
	evd_ptr->qlen		= qlen;

	dapl_llist_init_entry(&evd_ptr->cno_list_entry);
	evd_ptr->completion_type = DAPL_EVD_STATE_THRESHOLD;
	(void) dapl_os_wait_object_init(&evd_ptr->wait_object);

bail:
	return (evd_ptr);
}


/*
 * dapls_evd_event_alloc
 *
 * alloc events into an EVD.
 *
 * Input:
 *	evd_ptr
 *	qlen
 *
 * Output:
 *	NONE
 *
 * Returns:
 *	DAT_SUCCESS
 *	ERROR
 *
 */
DAT_RETURN
dapli_evd_event_alloc(
    IN DAPL_EVD		*evd_ptr,
    IN  DAPL_CNO	*cno_ptr,
    IN DAT_COUNT	qlen)
{
	DAT_EVENT	*event_ptr;
	DAT_COUNT	i;
	DAT_RETURN	dat_status;

	dat_status = DAT_SUCCESS;
	event_ptr  = NULL;

	/* Allocate EVENTs */
	event_ptr = (DAT_EVENT *) dapl_os_alloc(qlen * sizeof (DAT_EVENT));
	if (!event_ptr) {
		goto bail;
	}
	evd_ptr->events = event_ptr;
	evd_ptr->qlen = qlen;

	/* allocate free event queue */
	dat_status = dapls_rbuf_alloc(&evd_ptr->free_event_queue, qlen);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	/* allocate pending event queue */
	dat_status = dapls_rbuf_alloc(&evd_ptr->pending_event_queue, qlen);
	if (dat_status != DAT_SUCCESS) {
		goto bail;
	}

	/* add events to free event queue */
	for (i = 0; i < qlen; i++) {
		dat_status = dapls_rbuf_add(&evd_ptr->free_event_queue,
		    (void *)event_ptr);
		dapl_os_assert(dat_status == DAT_SUCCESS);
		event_ptr++;
	}
	evd_ptr->cq_notified = DAT_FALSE;
	evd_ptr->cq_notified_when = 0;
	evd_ptr->cno_active_count = 0;
	if (cno_ptr != NULL) {
		dapl_os_lock(&cno_ptr->header.lock);
		dapl_llist_add_head(&cno_ptr->evd_list_head,
		    &evd_ptr->cno_list_entry, evd_ptr);
		/* Take a reference count on the CNO */
		dapl_os_atomic_inc(&cno_ptr->cno_ref_count);
		dapl_os_unlock(&cno_ptr->header.lock);
	}
	evd_ptr->cno_ptr = cno_ptr;
	evd_ptr->threshold = 0;

bail:
	return (dat_status);
}


/*
 * dapls_evd_dealloc
 *
 * Free the passed in EVD structure. If an error occurs, this function
 * will clean up all of the internal data structures and report the
 * error.
 *
 * Input:
 *	evd_ptr
 *
 * Output:
 *	none
 *
 * Returns:
 *	status
 *
 */
DAT_RETURN
dapls_evd_dealloc(
    IN DAPL_EVD		*evd_ptr)
{
	DAT_RETURN	dat_status;
	DAPL_IA	*ia_ptr;

	dat_status = DAT_SUCCESS;

	dapl_os_assert(evd_ptr->header.magic == DAPL_MAGIC_EVD);
	dapl_os_assert(evd_ptr->evd_ref_count == 0);

	/*
	 * Destroy the CQ first, to keep any more callbacks from coming
	 * up from it.
	 */
	if (evd_ptr->ib_cq_handle != IB_INVALID_HANDLE) {
		ia_ptr = evd_ptr->header.owner_ia;

		dat_status = dapls_ib_cq_free(ia_ptr, evd_ptr);
		if (dat_status != DAT_SUCCESS) {
			goto bail;
		}
	}

	/*
	 * We should now be safe to invalidate the EVD; reset the
	 * magic to prevent reuse.
	 */
	evd_ptr->header.magic = DAPL_MAGIC_INVALID;

	/* Release reference on the CNO if it exists */
	if (evd_ptr->cno_ptr != NULL) {
		dapl_os_lock(&evd_ptr->cno_ptr->header.lock);
		(void) dapl_llist_remove_entry(&evd_ptr->cno_ptr->evd_list_head,
		    &evd_ptr->cno_list_entry);
		dapl_os_atomic_dec(&evd_ptr->cno_ptr->cno_ref_count);
		dapl_os_unlock(&evd_ptr->cno_ptr->header.lock);
	}

	/*
	 * If the ring buffer allocation failed, then the dapls_rbuf_destroy
	 * function will detect that the ring buffer's internal data (ex. base
	 * pointer) are invalid and will handle the situation appropriately
	 */
	dapls_rbuf_destroy(&evd_ptr->free_event_queue);
	dapls_rbuf_destroy(&evd_ptr->pending_event_queue);

	if (evd_ptr->events) {
		dapl_os_free(evd_ptr->events,
		    evd_ptr->qlen * sizeof (DAT_EVENT));
	}

	(void) dapl_os_wait_object_destroy(&evd_ptr->wait_object);
	dapl_os_free(evd_ptr, sizeof (DAPL_EVD));

bail:
	return (dat_status);
}


/*
 * dapli_evd_eh_print_cqe
 *
 * Input:
 *	cqe
 *
 * Output:
 *	none
 *
 * Prints out a CQE for debug purposes
 *
 */

#ifdef	DAPL_DBG	/* For debugging.  */
void
dapli_evd_eh_print_cqe(IN ib_work_completion_t cqe)
{
	static char *optable[] = {
		"",
		"OP_SEND",
		"OP_RDMA_READ",
		"OP_RDMA_WRITE",
		"OP_COMP_AND_SWAP",
		"OP_FETCH_AND_ADD",
		"OP_BIND_MW",
		"OP_RECEIVE",
		"OP_RECEIVE_RDMAWI",
		0
	};
	DAPL_COOKIE		*dto_cookie;

	dto_cookie = (DAPL_COOKIE *) (uintptr_t)DAPL_GET_CQE_WRID(&cqe);

	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "\t >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<\n");
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "\t dapl_evd_dto_callback : CQE \n");
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "\t\t work_req_id 0x%llx\n", DAPL_GET_CQE_WRID(&cqe));
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "\t\t op_type: %s\n", optable[DAPL_GET_CQE_OPTYPE(&cqe)]);
	if ((DAPL_GET_CQE_OPTYPE(&cqe) == OP_SEND) ||
	    (DAPL_GET_CQE_OPTYPE(&cqe) == OP_RDMA_WRITE)) {
		dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
		    "\t\t bytes_num %d\n", dto_cookie->val.dto.size);
	} else {
		dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
		    "\t\t bytes_num %d\n", DAPL_GET_CQE_BYTESNUM(&cqe));
	}
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "\t\t status %d\n", DAPL_GET_CQE_STATUS(&cqe));
	dapl_dbg_log(DAPL_DBG_TYPE_CALLBACK,
	    "\t >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<\n");
}
#endif

/*
 * Event posting code follows.
 */

/*
 * These next two functions (dapli_evd_get_event and dapli_evd_post_event)
 * are a pair.  They are always called together, from one of the functions
 * at the end of this file (dapl_evd_post_*_event).
 *
 * Note that if producer side locking is enabled, the first one takes the
 * EVD lock and the second releases it.
 */

/*
 * dapli_evd_get_event
 *
 * Get an event struct from the evd.  The caller should fill in the event
 * and call dapl_evd_post_event.
 *
 * If there are no events available, an overflow event is generated to the
 * async EVD handler.
 *
 * If this EVD required producer locking, a successful return implies
 * that the lock is held.
 *
 * Input:
 *	evd_ptr
 *
 * Output:
 *	event
 *
 */

static DAT_EVENT *
dapli_evd_get_event(
    DAPL_EVD *evd_ptr)
{
	DAT_EVENT	*event;

	if (evd_ptr->evd_producer_locking_needed) {
		dapl_os_lock(&evd_ptr->header.lock);
	}

	event = (DAT_EVENT *)dapls_rbuf_remove(&evd_ptr->free_event_queue);

	/* Release the lock if it was taken and the call failed.  */
	if (!event && evd_ptr->evd_producer_locking_needed) {
		dapl_os_unlock(&evd_ptr->header.lock);
	}

	return (event);
}

/*
 * dapli_evd_post_event
 *
 * Post the <event> to the evd.  If possible, invoke the evd's CNO.
 * Otherwise post the event on the pending queue.
 *
 * If producer side locking is required, the EVD lock must be held upon
 * entry to this function.
 *
 * Input:
 *	evd_ptr
 *	event
 *
 * Output:
 *	none
 *
 */

static void
dapli_evd_post_event(
    IN	DAPL_EVD	*evd_ptr,
    IN	const DAT_EVENT	*event_ptr)
{
	DAT_RETURN	dat_status;
	DAPL_CNO	*cno_to_trigger = NULL;

	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
	    "dapli_evd_post_event: Called with event # %x\n",
	    event_ptr->event_number);

	dat_status = dapls_rbuf_add(&evd_ptr->pending_event_queue,
	    (void *)event_ptr);
	dapl_os_assert(dat_status == DAT_SUCCESS);

	dapl_os_assert(evd_ptr->evd_state == DAPL_EVD_STATE_WAITED ||
	    evd_ptr->evd_state == DAPL_EVD_STATE_OPEN);

	if (evd_ptr->evd_state == DAPL_EVD_STATE_OPEN) {
		/* No waiter.  Arrange to trigger a CNO if it exists.  */

		if (evd_ptr->evd_enabled) {
			cno_to_trigger = evd_ptr->cno_ptr;
		}
		if (evd_ptr->evd_producer_locking_needed) {
			dapl_os_unlock(&evd_ptr->header.lock);
		}
	} else {
		/*
		 * This routine gets called
		 *  - In the context of the waiting thread when CQ, CM or ASYNC
		 *    events need to be put on to the EVD ring buffer.
		 *  - Due to a post of a software event.
		 *
		 * In the first case the waiting thread is pulling the events
		 * from various streams into the evd so there is no need to
		 * wake any thread. In the second case if the evd is in waited
		 * state then we need to wakeup the waiting thread.
		 */
		if (event_ptr->event_number == DAT_SOFTWARE_EVENT) {
			/*
			 * We're in DAPL_EVD_STATE_WAITED.  Take the lock if
			 * we don't have it, recheck, and signal.
			 */

			if (!evd_ptr->evd_producer_locking_needed) {
				dapl_os_lock(&evd_ptr->header.lock);
			}

			if (evd_ptr->evd_state == DAPL_EVD_STATE_WAITED) {
				dapl_os_unlock(&evd_ptr->header.lock);
				(void) dapls_ib_event_wakeup(evd_ptr);
			} else {
				dapl_os_unlock(&evd_ptr->header.lock);
			}
		} else {
			if (evd_ptr->evd_producer_locking_needed) {
				dapl_os_unlock(&evd_ptr->header.lock);
			}
		}
	}

	if (cno_to_trigger != NULL) {
		dapl_cno_trigger(cno_to_trigger, evd_ptr);
	}
}

/*
 * dapli_evd_post_event_nosignal
 *
 * Post the <event> to the evd.  Do not do any wakeup processing.
 * This function should only be called if it is known that there are
 * no waiters that it is appropriate to wakeup on this EVD.  An example
 * of such a situation is during internal dat_evd_wait() processing.
 *
 * If producer side locking is required, the EVD lock must be held upon
 * entry to this function.
 *
 * Input:
 *	evd_ptr
 *	event
 *
 * Output:
 *	none
 *
 */

static void
dapli_evd_post_event_nosignal(
    IN	DAPL_EVD	*evd_ptr,
    IN	const DAT_EVENT	*event_ptr)
{
	DAT_RETURN	dat_status;

	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
	    "dapli_evd_post_event: Called with event # %x\n",
	    event_ptr->event_number);

	dat_status = dapls_rbuf_add(&evd_ptr->pending_event_queue,
	    (void *)event_ptr);
	dapl_os_assert(dat_status == DAT_SUCCESS);

	dapl_os_assert(evd_ptr->evd_state == DAPL_EVD_STATE_WAITED ||
	    evd_ptr->evd_state == DAPL_EVD_STATE_OPEN);

	if (evd_ptr->evd_producer_locking_needed) {
		dapl_os_unlock(&evd_ptr->header.lock);
	}
}

/*
 * dapli_evd_format_overflow_event
 *
 * format an overflow event for posting
 *
 * Input:
 *	evd_ptr
 *	event_ptr
 *
 * Output:
 *	none
 *
 */
static void
dapli_evd_format_overflow_event(
	IN  DAPL_EVD  *evd_ptr,
	OUT DAT_EVENT *event_ptr)
{
	DAPL_IA *ia_ptr;

	ia_ptr = evd_ptr->header.owner_ia;

	event_ptr->evd_handle   = (DAT_EVD_HANDLE)evd_ptr;
	event_ptr->event_number = DAT_ASYNC_ERROR_EVD_OVERFLOW;
	event_ptr->event_data.asynch_error_event_data.dat_handle =
	    (DAT_HANDLE)ia_ptr;
}

/*
 * dapli_evd_post_overflow_event
 *
 * post an overflow event
 *
 * Input:
 *	async_evd_ptr
 *	evd_ptr
 *
 * Output:
 *	none
 *
 */
static void
dapli_evd_post_overflow_event(
    IN  DAPL_EVD  *async_evd_ptr,
    IN  DAPL_EVD  *overflow_evd_ptr)
{
	DAT_EVENT *overflow_event;

	/*
	 * The overflow_evd_ptr mght be the same as evd.
	 * In that case we've got a catastrophic overflow.
	 */
	if (async_evd_ptr == overflow_evd_ptr) {
		async_evd_ptr->catastrophic_overflow = DAT_TRUE;
		async_evd_ptr->evd_state = DAPL_EVD_STATE_DEAD;
		return;
	}

	overflow_event = dapli_evd_get_event(overflow_evd_ptr);
	if (!overflow_event) {
		/* this is not good */
		overflow_evd_ptr->catastrophic_overflow = DAT_TRUE;
		overflow_evd_ptr->evd_state = DAPL_EVD_STATE_DEAD;
		return;
	}
	dapli_evd_format_overflow_event(overflow_evd_ptr, overflow_event);
	dapli_evd_post_event(overflow_evd_ptr, overflow_event);
}

static DAT_EVENT *
dapli_evd_get_and_init_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number)
{
	DAT_EVENT		*event_ptr;

	event_ptr = dapli_evd_get_event(evd_ptr);
	if (NULL == event_ptr) {
		dapli_evd_post_overflow_event(
		    evd_ptr->header.owner_ia->async_error_evd, evd_ptr);
	} else {
		event_ptr->evd_handle = (DAT_EVD_HANDLE) evd_ptr;
		event_ptr->event_number = event_number;
	}

	return (event_ptr);
}

DAT_RETURN
dapls_evd_post_cr_arrival_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_SP_HANDLE			sp_handle,
    DAT_IA_ADDRESS_PTR			ia_address_ptr,
    DAT_CONN_QUAL			conn_qual,
    DAT_CR_HANDLE			cr_handle)
{
	DAT_EVENT		*event_ptr;
	event_ptr = dapli_evd_get_and_init_event(evd_ptr, event_number);
	/*
	 * Note event lock may be held on successful return
	 * to be released by dapli_evd_post_event(), if provider side locking
	 * is needed.
	 */

	if (!event_ptr) {
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}

	event_ptr->event_data.cr_arrival_event_data.sp_handle = sp_handle;
	event_ptr->event_data.cr_arrival_event_data.local_ia_address_ptr
	    = ia_address_ptr;
	event_ptr->event_data.cr_arrival_event_data.conn_qual = conn_qual;
	event_ptr->event_data.cr_arrival_event_data.cr_handle = cr_handle;

	dapli_evd_post_event(evd_ptr, event_ptr);
	return (DAT_SUCCESS);
}


DAT_RETURN
dapls_evd_post_connection_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_EP_HANDLE			ep_handle,
    IN DAT_COUNT			private_data_size,
    IN DAT_PVOID			private_data)
{
	DAT_EVENT		*event_ptr;
	event_ptr = dapli_evd_get_and_init_event(evd_ptr, event_number);
	/*
	 * Note event lock may be held on successful return
	 * to be released by dapli_evd_post_event(), if provider side locking
	 * is needed.
	 */

	if (!event_ptr) {
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}

	event_ptr->event_data.connect_event_data.ep_handle = ep_handle;
	event_ptr->event_data.connect_event_data.private_data_size
	    = private_data_size;
	event_ptr->event_data.connect_event_data.private_data = private_data;

	dapli_evd_post_event(evd_ptr, event_ptr);
	return (DAT_SUCCESS);
}


DAT_RETURN
dapls_evd_post_async_error_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_IA_HANDLE			ia_handle)
{
	DAT_EVENT		*event_ptr;
	event_ptr = dapli_evd_get_and_init_event(evd_ptr, event_number);
	/*
	 * Note event lock may be held on successful return
	 * to be released by dapli_evd_post_event(), if provider side locking
	 * is needed.
	 */

	if (!event_ptr) {
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}

	event_ptr->event_data.asynch_error_event_data.dat_handle = ia_handle;

	dapli_evd_post_event(evd_ptr, event_ptr);
	return (DAT_SUCCESS);
}


DAT_RETURN
dapls_evd_post_software_event(
    IN DAPL_EVD				*evd_ptr,
    IN DAT_EVENT_NUMBER			event_number,
    IN DAT_PVOID			pointer)
{
	DAT_EVENT		*event_ptr;
	event_ptr = dapli_evd_get_and_init_event(evd_ptr, event_number);
	/*
	 * Note event lock may be held on successful return
	 * to be released by dapli_evd_post_event(), if provider side locking
	 * is needed.
	 */

	if (!event_ptr) {
		return (DAT_QUEUE_FULL);
	}

	event_ptr->event_data.software_event_data.pointer = pointer;

	dapli_evd_post_event(evd_ptr, event_ptr);
	return (DAT_SUCCESS);
}

void
dapls_evd_post_premature_events(IN DAPL_EP *ep_ptr)
{
	DAPL_EVD		*evd_ptr;
	DAT_EVENT		*event;
	ib_work_completion_t	*cqe;
	uint32_t		qpn;
	int			prm_idx;
	int			nevents;
	int			i;

	dapls_ib_poll_premature_events(ep_ptr, &cqe, &nevents);
	/* premature events are always recv events */
	evd_ptr = ep_ptr->param.recv_evd_handle;
	qpn = ep_ptr->qpn;

	i = 0;
	prm_idx = 0;
	while (i < nevents) {
		/*
		 * If srq_attached, premature events cannot exceed max_recv_dtos
		 */
		dapl_os_assert(!ep_ptr->srq_attached ||
		    (prm_idx <= ((DAPL_SRQ *)ep_ptr->param.srq_handle)->
		    param.max_recv_dtos));

		/*
		 * The SRQ premature event list could potentially have
		 * holes (ie. free entries in the middle) or premature
		 * events for other QPs. These need to be skipped.
		 */
		if (ep_ptr->srq_attached &&
		    (!DAPL_CQE_IS_VALID(&cqe[prm_idx]) ||
		    (DAPL_GET_CQE_QPN(&cqe[prm_idx]) != qpn))) {
			prm_idx++;
			continue;
		}

		dapl_dbg_log(DAPL_DBG_TYPE_DTO_COMP_ERR,
		    " Premature DTO processing\n");

#ifdef	DAPL_DBG	/* For debugging.  */
		dapli_evd_eh_print_cqe(cqe[i]);
#endif
		/*
		 * Can use DAT_DTO_COMPLETION_EVENT because
		 * dapli_evd_cqe_to_event will overwrite.
		 */
		event = dapli_evd_get_and_init_event(evd_ptr,
		    DAT_DTO_COMPLETION_EVENT);
		if (event == NULL) {
			/* We've already attempted the overflow post, return */
			return;
		}
		(void) dapli_evd_cqe_to_event(evd_ptr, &cqe[i], DAT_TRUE,
		    event);
		dapli_evd_post_event_nosignal(evd_ptr, event);
		/*
		 * For SRQ attached QPs recycle the premature event
		 */
		if (ep_ptr->srq_attached) {
			dapls_ib_free_premature_events(ep_ptr, prm_idx);
			prm_idx++;
		}
		i++;
	}
}

/*
 * dapli_evd_cqe_to_event
 *
 * Convert a CQE into an event structure.
 *
 * Input:
 *	evd_ptr
 *	cqe_ptr
 *
 * Output:
 *	event_ptr
 *
 * Returns:
 *	none
 *
 */
static DAT_BOOLEAN
dapli_evd_cqe_to_event(
    IN DAPL_EVD			*evd_ptr,
    IN ib_work_completion_t	*cqe_ptr,
    IN DAT_BOOLEAN		process_premature_events,
    OUT DAT_EVENT		*event_ptr)
{
	DAPL_EP			*ep_ptr;
	DAPL_SRQ		*srq_ptr;
	DAPL_COOKIE		*cookie;
	DAT_EP_STATE		ep_state;
	ib_qp_handle_t		qp;
	ib_uint32_t		ib_status;
	ib_uint32_t		ibtype;
	int			srq_enabled;
	int			dto_error = 0;


	/*
	 * All that can be relied on if the status is bad is the status
	 * and WRID.
	 */
	ib_status = DAPL_GET_CQE_STATUS(cqe_ptr);

	cookie = (DAPL_COOKIE *)((uintptr_t)DAPL_GET_CQE_WRID(cqe_ptr));
	dapl_os_assert((NULL != cookie));

	if (cookie->queue_type == DAPL_COOKIE_QUEUE_EP) {
		srq_enabled = 0;
		ep_ptr = cookie->queue.ep;
	} else {
		srq_enabled = 1;
		srq_ptr = cookie->queue.srq;
		dapl_os_assert(NULL != srq_ptr);
		dapl_os_assert(srq_ptr->header.magic == DAPL_MAGIC_SRQ);
		ib_status = DAPL_GET_CQE_STATUS(cqe_ptr);
		ep_ptr = dapls_ib_srq_lookup_ep(srq_ptr, cqe_ptr);
	}

	dapl_os_assert((NULL != ep_ptr));
	dapl_os_assert((ep_ptr->header.magic == DAPL_MAGIC_EP) ||
	    (ep_ptr->header.magic == DAPL_MAGIC_EP_EXIT));

	event_ptr->evd_handle = (DAT_EVD_HANDLE) evd_ptr;

	/*
	 * Check if the DTO completion arrived before CONNECTION_ESTABLISHED
	 * event -
	 *
	 * Send DTOs can occur only if ep state is CONNECTED/DISCONNECTED
	 * therefore it cannot occur before connection established event.
	 * Receive DTO can potentially complete before connection established
	 * event has been delivered to the client. In this case if the
	 * ep state is ACTIVE_CONNECTION_PENDING (active side) or
	 * COMPLETION_PENDING (passive side) the event is put in a special
	 * event queue in the qp_handle.
	 *
	 */
	if (!process_premature_events &&
	    (cookie->type == DAPL_COOKIE_TYPE_DTO) &&
	    (ib_status == IB_COMP_ST_SUCCESS)) {
		ep_state = ep_ptr->param.ep_state;
		qp = ep_ptr->qp_handle;
		if ((ep_state == DAT_EP_STATE_ACTIVE_CONNECTION_PENDING) ||
		    (ep_state == DAT_EP_STATE_COMPLETION_PENDING) ||
		    (qp->qp_num_premature_events > 0)) {
			/*
			 * not yet ready to put the event in the evd ring
			 * buffer
			 */
			dapls_ib_store_premature_events(qp, cqe_ptr);
			return (DAT_FALSE);
		}
	}

	switch (cookie->type) {
	case DAPL_COOKIE_TYPE_DTO:
	{
		DAPL_COOKIE_BUFFER	*buffer;

		if (DAPL_DTO_TYPE_RECV == cookie->val.dto.type) {
			if (srq_enabled) {
				dapl_os_atomic_dec(&srq_ptr->recv_count);
				buffer = &srq_ptr->recv_buffer;
			} else {
				dapl_os_atomic_dec(&ep_ptr->recv_count);
				buffer = &ep_ptr->recv_buffer;
			}
		} else {
			dapl_os_atomic_dec(&ep_ptr->req_count);
			buffer = &ep_ptr->req_buffer;
		}

		event_ptr->event_number = DAT_DTO_COMPLETION_EVENT;
		event_ptr->event_data.dto_completion_event_data.ep_handle =
		    ep_ptr;
		event_ptr->event_data.dto_completion_event_data.user_cookie =
		    cookie->val.dto.cookie;

		switch (ib_status) {
		case IB_COMP_ST_SUCCESS:
		{
			ibtype = DAPL_GET_CQE_OPTYPE(cqe_ptr);

			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_SUCCESS;
			dapl_os_assert((ibtype == OP_SEND &&
			    cookie->val.dto.type == DAPL_DTO_TYPE_SEND) ||
			    (ibtype == OP_RECEIVE &&
			    cookie->val.dto.type == DAPL_DTO_TYPE_RECV) ||
			    (ibtype == OP_RDMA_WRITE &&
			    cookie->val.dto.type ==
			    DAPL_DTO_TYPE_RDMA_WRITE) ||
			    (ibtype == OP_RDMA_READ &&
			    cookie->val.dto.type ==
			    DAPL_DTO_TYPE_RDMA_READ));
			break;
		}
		case IB_COMP_ST_LOCAL_LEN_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_LOCAL_LENGTH;
			break;
		}
		case IB_COMP_ST_LOCAL_PROTECT_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_LOCAL_PROTECTION;
			break;
		}
		case IB_COMP_ST_WR_FLUSHED_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_FLUSHED;
			break;
		}
		case IB_COMP_ST_BAD_RESPONSE_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_BAD_RESPONSE;
			break;
		}
		case IB_COMP_ST_REM_REQ_ERR:
		case IB_COMP_ST_REM_OP_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_REMOTE_RESPONDER;
			break;
		}
		case IB_COMP_ST_REM_ACC_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_REMOTE_ACCESS;
			break;
		}
		/*
		 * Unsupported RD errors
		 * case IB_COMP_ST_EE_STATE_ERR:
		 * case IB_COMP_ST_EE_CTX_NO_ERR:
		 */
		case IB_COMP_ST_TRANSP_COUNTER:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_TRANSPORT;
			break;
		}
		case IB_COMP_ST_RNR_COUNTER:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_RECEIVER_NOT_READY;
			break;
		}
		case IB_COMP_ST_MW_BIND_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_RMR_OPERATION_FAILED;
			break;
		}
		case IB_COMP_ST_LOCAL_OP_ERR:
		{
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_ERR_LOCAL_EP;
			break;
		}
		default:
		{
			dapl_dbg_log(DAPL_DBG_TYPE_DTO_COMP_ERR,
			    " DTO completion ERROR: %d: op %#x\n",
			    DAPL_GET_CQE_STATUS(cqe_ptr),
			    DAPL_GET_CQE_OPTYPE(cqe_ptr));
			event_ptr->event_data.dto_completion_event_data.status =
			    DAT_DTO_FAILURE;
			break;
		}
		}

		/* Most error DTO ops result in disconnecting the EP */
		if ((event_ptr->event_data.dto_completion_event_data.status !=
		    DAT_DTO_SUCCESS) &&
		    (event_ptr->event_data.dto_completion_event_data.status !=
		    DAT_RMR_OPERATION_FAILED)) {
			dto_error = 1;
			dapl_dbg_log(DAPL_DBG_TYPE_DTO_COMP_ERR,
			    " DTO completion ERROR: %d: op %#x\n",
			    DAPL_GET_CQE_STATUS(cqe_ptr),
			    DAPL_GET_CQE_OPTYPE(cqe_ptr));
		}

		if (cookie->val.dto.type == DAPL_DTO_TYPE_SEND ||
		    cookie->val.dto.type == DAPL_DTO_TYPE_RDMA_WRITE) {
			/* Get size from DTO; CQE value may be off.  */
			event_ptr->event_data.dto_completion_event_data.
			    transfered_length = cookie->val.dto.size;
		} else {
			event_ptr->event_data.dto_completion_event_data.
			    transfered_length = DAPL_GET_CQE_BYTESNUM(cqe_ptr);
		}

		dapls_cookie_dealloc(buffer, cookie);
		break;
	}

	case DAPL_COOKIE_TYPE_RMR:
	{
		dapl_os_atomic_dec(&ep_ptr->req_count);

		event_ptr->event_number = DAT_RMR_BIND_COMPLETION_EVENT;

		event_ptr->event_data.rmr_completion_event_data.rmr_handle =
		    cookie->val.rmr.rmr;
		event_ptr->event_data.rmr_completion_event_data.user_cookie =
		    cookie->val.rmr.cookie;
		if (ib_status == IB_COMP_ST_SUCCESS) {
			ibtype = DAPL_GET_CQE_OPTYPE(cqe_ptr);

			event_ptr->event_data.rmr_completion_event_data.status =
			    DAT_RMR_BIND_SUCCESS;
			dapl_os_assert(ibtype == OP_BIND_MW);
		} else {
			event_ptr->event_data.rmr_completion_event_data.status =
			    DAT_RMR_BIND_FAILURE;
			dto_error = 1;
		}

		dapls_cookie_dealloc(&ep_ptr->req_buffer, cookie);
		break;
	}
	default:
	{
		dapl_os_assert(!"Invalid Operation type");
		break;
	}
	}

	/*
	 * A DTO failed this will cause the connection to be broken
	 */
	if ((dto_error) && (ep_ptr->param.ep_state == DAT_EP_STATE_CONNECTED)) {
		ep_ptr->param.ep_state = DAT_EP_STATE_DISCONNECTED;
		/*
		 * Disconnect at the IB level.
		 */
		dapls_ib_disconnect_clean(ep_ptr, DAT_TRUE, IB_CME_CONNECTED);
	}
	/* convert premature rec to error flush on disconnect */
	if (process_premature_events && (ep_ptr->param.ep_state ==
	    DAT_EP_STATE_DISCONNECTED) && (ib_status == IB_COMP_ST_SUCCESS)) {
		dapl_os_assert(ibtype == OP_RECEIVE &&
		    cookie->val.dto.type == DAPL_DTO_TYPE_RECV);
		event_ptr->event_data.dto_completion_event_data.status =
		    DAT_DTO_ERR_FLUSHED;
	}
	return (DAT_TRUE);
}

/*
 * dapls_evd_copy_cq
 *
 * Copy all entries on a CQ associated with the EVD onto that EVD
 * Up to caller to handle races, if any.  Note that no EVD waiters will
 * be awoken by this copy.
 *
 * Input:
 *	evd_ptr
 *
 * Output:
 *	nevents
 *
 * Returns:
 *	none
 *
 */
void
dapls_evd_copy_cq(
	DAPL_EVD	*evd_ptr,
	int		*nevents)
{
	ib_work_completion_t	cqe[MAX_CQES_PER_POLL];
	DAT_RETURN		dat_status;
	ib_cq_handle_t		cq_handle;
	DAT_EVENT		*event;
	uint_t			num_cqes_polled = 0;
	int			cqe_events;
	int			i;

	cq_handle = evd_ptr->ib_cq_handle;

	*nevents = 0;

	if (cq_handle == IB_INVALID_HANDLE) {
		/* Nothing to do if no CQ.  */
		return;
	}
	dat_status = DAPL_POLL(evd_ptr)(cq_handle,
	    cqe, MAX_CQES_PER_POLL, &num_cqes_polled);

	if (dat_status == DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_EVD, "dapls_evd_copy_cq: %u\n",
		    num_cqes_polled);
		cqe_events = 0;
		for (i = 0; i < num_cqes_polled; i++) {
#ifdef	DAPL_DBG	/* For debugging.  */
			dapli_evd_eh_print_cqe(cqe[i]);
#endif

			/*
			 * Can use DAT_DTO_COMPLETION_EVENT because
			 * dapli_evd_cqe_to_event will overwrite.
			 */

			event = dapli_evd_get_and_init_event(
			    evd_ptr, DAT_DTO_COMPLETION_EVENT);
			if (event == NULL) {
			/*
			 * We've already attempted the overflow post; return.
			 */
				return;
			}
			if (dapli_evd_cqe_to_event(evd_ptr, &cqe[i], DAT_FALSE,
			    event)) {
				dapli_evd_post_event_nosignal(evd_ptr, event);
				cqe_events++;
			} else {
				dapl_dbg_log(DAPL_DBG_TYPE_EVD,
				    "dapls_evd_copy_cq: premature event\n");
				/*
				 * We've deferred processing the CQE, so add
				 * the event_ptr back to free queue
				 */
				dat_status = dapls_rbuf_add(&evd_ptr->
				    free_event_queue, (void *)event);
				dapl_os_assert(dat_status == DAT_SUCCESS);
				if (evd_ptr->evd_producer_locking_needed) {
					dapl_os_unlock(&evd_ptr->header.lock);
				}
			}
		}
		*nevents = cqe_events;
	} else if (DAT_GET_TYPE(dat_status) != DAT_QUEUE_EMPTY) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_evd_copy_cq: dapls_ib_completion_poll "
		    "returned 0x%x\n", dat_status);
		dapl_os_assert(!"Bad return from dapls_ib_completion_poll");
	}
}

/*
 * dapls_evd_copy_events
 *
 * Copy all events associated with the EVD onto that EVD
 *
 * Input:
 *	evd_ptr
 *	timeout
 *
 * Output:
 *	return status
 *
 * Returns:
 *	none
 *
 */
DAT_RETURN
dapls_evd_copy_events(DAPL_EVD *evd_ptr, DAT_TIMEOUT timeout)
{
	dapl_ib_event_t	evp_arr[NUM_EVENTS_PER_POLL];
	dapl_ib_event_t	*evpp_start;
	dapl_ib_event_t	*evpp;
	DAPL_IA		*ia_ptr;
	DAT_RETURN	dat_status;
	int		waited;
	uint64_t	curr_time;
	uint64_t	final_time;
	uint64_t	time_left;
	int		events_needed = 0;
	int		nevents = 0;
	int		num_cqe = 0;
	int		num_ke = 0; /* kernel events - CM or ASYNC events */
	int		i;

	/* rbuf count is zero on entry */

	if (evd_ptr->evd_flags & (DAT_EVD_CONNECTION_FLAG |
	    DAT_EVD_CR_FLAG | DAT_EVD_ASYNC_FLAG)) {
		if (evd_ptr->threshold <= NUM_EVENTS_PER_POLL) {
			evpp = evp_arr;
		} else {
			/* need to allocate on the heap */
			evpp = (dapl_ib_event_t *)dapl_os_alloc(
			    evd_ptr->threshold * sizeof (dapl_ib_event_t));
			if (evpp == NULL) {
				return (DAT_INSUFFICIENT_RESOURCES);
			}
		}
		evpp_start = evpp;
		/* for evd_dequeue, check for ke before returning Q_EMPTY */
		if (evd_ptr->threshold == 0 && timeout == 0)
			evd_ptr->threshold = 1;
	} else {
		evpp = NULL;
		evpp_start = NULL;
	}
	ia_ptr = evd_ptr->header.owner_ia;
	waited = 0;
	dat_status = DAT_SUCCESS;

	/* calculate various time wait elements */
	if (timeout == 0) {
		final_time = 0;
		time_left = 0;
	} else if (timeout == DAT_TIMEOUT_INFINITE) {
		/*
		 * The real value of DAT_TIMEOUT_INFINITE is fairly small
		 * ~71 mins, to prevent premature timeouts map it to
		 * 1 year.  NOTE: 64-bit integers are needed here
		 * because 32 bits is not enough.  Other types,
		 * such as clock_t are not 64-bit, so are not
		 * sufficient for this.  Similarly, hrtime_t is
		 * defined as a "nanosecond counter", which does not
		 * match our need for time in microseconds, so we
		 * just use the more general uint64_t here.
		 */
#define	DAPL_ONE_YEAR_IN_USEC	((365 * 24 * 3600) * 1000000LL)
		curr_time = gethrtime();
		time_left = DAPL_ONE_YEAR_IN_USEC;
		final_time = curr_time + DAPL_ONE_YEAR_IN_USEC * 1000;
	} else {
		/*
		 * maximum time by which the routine needs to return
		 * DAT_TIMEOUT_INFINITE is defined as ~0 but its of type int
		 * so mask the MSB to avoid overflow
		 */
		curr_time = gethrtime();
		final_time = curr_time + (uint64_t)(timeout&0x7fffffff)*1000;
		time_left = (final_time - curr_time)/1000;
	}

	do {
		/*
		 * If this evd has a CQ event stream check the CQs first
		 */
		if (evd_ptr->evd_flags & (DAT_EVD_DTO_FLAG |
		    DAT_EVD_RMR_BIND_FLAG)) {
			/*
			 * Poll CQ for events, update the total number of CQEs
			 * so far
			 */
			nevents = 0;
			dapls_evd_copy_cq(evd_ptr, &nevents);
			num_cqe += nevents;
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: copy_cq num_cqe(%d)\n",
			    num_cqe);
		}

		/*
		 * We use the dapls_rbuf_count since it includes
		 *  - CQ events pulled by dapls_evd_copy_cq
		 *  - events added by dat_evd_post_se()
		 */
		events_needed = evd_ptr->threshold - num_ke -
		    dapls_rbuf_count(&evd_ptr->pending_event_queue);

		/*
		 * check for pending events
		 * note: threshold=0 implies dapl_evd_dequeue
		 */
		if (events_needed < 0) {
			/* There are more than sufficient events */
			break;
		} else if (events_needed == 0) {
			/* report queue empty on dat_evd_dequeue */
			/* non CQ events are expected to be polled */
			/* by dat_evd_wait */
			if (evd_ptr->threshold == 0)
				dat_status =  DAT_ERROR(DAT_QUEUE_EMPTY, 0);
			/*
			 * when threshold > 0, we have sufficient events
			 */
			break;
		} else {
			/*
			 * when we reach here, this implies dat_evd_wait
			 * return on any dto completion as
			 * threshold > 1 will be taken as hint only
			 */
			if (num_cqe)
				break;
		}

		/* check we've already waited */
		if (waited > 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: waited[%d]\n", waited);
			if (dat_status != DAT_SUCCESS)
				break;
			curr_time = gethrtime();
			/* exit on time expired */
			if (curr_time >= final_time)
				break;
			time_left = (final_time - curr_time)/1000;
		}

		/* check for DTO type evd's */
		if (evd_ptr->evd_flags & (DAT_EVD_DTO_FLAG |
		    DAT_EVD_RMR_BIND_FLAG)) {
			if (events_needed == 1) {
				/*
				 * Need only one event so enable cq
				 * notification
				 */
				/*
				 * XXX: Things need to be modified here to
				 * implement the NOTIFICATION suppression
				 * correctly - relies on THRESHOLD flag
				 * and UNSIGNALLED flag to be stored
				 * in the evd.
				 */
				dat_status = dapls_set_cq_notify(ia_ptr,
				    evd_ptr);
				if (dat_status != DAT_SUCCESS) {
					dapl_dbg_log(DAPL_DBG_TYPE_EVD,
					    "dapls_evd_copy_event:"
					    " set_cq_notify(%d)\n", dat_status);
					return (dat_status);
				}
			} else if (events_needed > 1) {
				/*
				 * We need multiple events so lets enable CQ for
				 * notification on N events.
				 * dat_status = dapls_set_cqN_notify(ia_ptr,
				 * evd_ptr, (uint32_t)events_needed);
				 */
				dat_status = dapls_set_cq_notify(ia_ptr,
				    evd_ptr);
				if (dat_status != DAT_SUCCESS) {
					dapl_dbg_log(DAPL_DBG_TYPE_EVD,
					    "dapls_evd_copy_event:"
					    " set_cqN_notify:%d\n", dat_status);
					return (dat_status);
				}
			}

			/*
			 * Per Tavor PRM if completions occur after polling
			 * the CQ and before arming it, upon arming the CQ
			 * handler will be immediately fired. Hence it
			 * recommends that a re-poll of the CQ can be skipped
			 * as an optimization.
			 */
		}

		nevents = 0;

		/*
		 * non-NULL evpp_start denotes either
		 * DAT_EVD_CONNECTION_FLAG, DAT_EVD_CR_FLAG, DAT_EVD_ASYNC_FLAG
		 * is set and thus needs to check events from kernel
		 */
		if (evpp_start) {
			/*
			 * Even if dat_status is not DAT_SUCCESS, num_events
			 * could be non-zero.
			 */
			dat_status = dapls_ib_event_poll(evd_ptr, time_left,
			    (evd_ptr->threshold - (num_cqe + num_ke)), evpp,
			    &nevents);
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: poll returned 0x%x(%d)\n",
			    dat_status, nevents);

			num_ke += nevents;
			evpp += nevents;
		} else {
			/* perform a timewait */
			dat_status = dapls_ib_event_poll(evd_ptr, time_left,
			    0, NULL, &nevents);
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: poll(cq_notification) "
			    "returned 0x%x\n", dat_status);
			if (DAT_GET_TYPE(dat_status) == DAT_INTERRUPTED_CALL)
				return (dat_status);
		}

		waited++;
	} while (dapls_rbuf_count(&evd_ptr->pending_event_queue) + num_ke <
	    evd_ptr->threshold);

	/* process the cm events now */
	for (i = 0; i < num_ke; i++) {
		switch (evpp_start[i].ibe_ev_family) {
		case DAPL_CR_EVENTS: /* PASSIVE side events */
		case DAPL_PASSIVE_CONNECTION_EVENTS:
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: Passive side Event %d\n",
			    evpp_start[i].ibe_ce.ibce_event);
			dapls_cr_callback((ib_cm_handle_t)
			    evpp_start[i].ibe_ce.ibce_psep_cookie,
			    evpp_start[i].ibe_ce.ibce_event,
			    evpp_start[i].ibe_ce.ibce_priv_data_ptr, (void *)
			    (uintptr_t)evpp_start[i].ibe_ce.ibce_cookie);
			break;
		case DAPL_ACTIVE_CONNECTION_EVENTS: /* ACTIVE side events */
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: Active Conn Event %d\n",
			    evpp_start[i].ibe_ce.ibce_event);
			dapl_evd_connection_callback((ib_cm_handle_t)
			    IB_INVALID_HANDLE,
			    evpp_start[i].ibe_ce.ibce_event,
			    evpp_start[i].ibe_ce.ibce_priv_data_ptr, (void *)
			    (uintptr_t)evpp_start[i].ibe_ce.ibce_cookie);
			break;
		case DAPL_ASYNC_EVENTS:
			dapl_dbg_log(DAPL_DBG_TYPE_EVD,
			    "dapls_evd_copy_event: Async Event %d\n",
			    evpp_start[i].ibe_async.ibae_type);
			dapls_ib_async_callback(evd_ptr,
			    ia_ptr->hca_ptr->ib_hca_handle,
			    &(evpp_start[i].ibe_async), ia_ptr);
			break;
		default:
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapls_evd_copy_event: dapls_ib_event_poll %d "
			    "returned 0x%x\n", i, evpp_start[i].ibe_ev_family);
			dapl_os_assert(!"Bad return from dapls_ib_event_poll");
			break;
		}
	}

	return (dat_status);
}

/*
 * dapls_evd_cq_poll_to_event
 *
 * Attempt to dequeue a single CQE from a CQ and turn it into
 * an event.
 *
 * Input:
 *	evd_ptr
 *
 * Output:
 *	event
 *
 * Returns:
 *	Status of operation
 *
 */
DAT_RETURN
dapls_evd_cq_poll_to_event(IN DAPL_EVD *evd_ptr, OUT DAT_EVENT *event)
{
	DAT_RETURN		dat_status;
	ib_work_completion_t	cur_cqe;

	/* skip one layer of do-nothing function */
	dat_status = DAPL_POLL1(evd_ptr)(evd_ptr->ib_cq_handle, &cur_cqe);

	if (dat_status == DAT_SUCCESS) {
#ifdef	DAPL_DBG	/* For debugging.  */
		dapli_evd_eh_print_cqe(cur_cqe);
#endif
		(void) dapli_evd_cqe_to_event(evd_ptr, &cur_cqe, DAT_FALSE,
		    event);
	}

	return (dat_status);
}

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 8
 * End:
 */
