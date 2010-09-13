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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dapl.h"
#include "dapl_tavor_wr.h"
#include "dapl_hash.h"
#include "dapl_tavor_ibtf_impl.h"

static dapls_tavor_wrid_entry_t *dapli_tavor_wrid_find_match(
	dapls_tavor_workq_hdr_t *, tavor_hw_cqe_t *);
static dapls_tavor_wrid_list_hdr_t *dapli_tavor_wrid_get_list(uint32_t, int);
static void dapli_tavor_wrid_reaplist_add(ib_cq_handle_t,
    dapls_tavor_workq_hdr_t *);
static dapls_tavor_workq_hdr_t *dapli_tavor_wrid_wqhdr_find(ib_cq_handle_t,
    uint_t, uint_t);
static uint32_t dapli_tavor_wrid_get_wqeaddrsz(dapls_tavor_workq_hdr_t *);
static dapls_tavor_workq_hdr_t *dapli_tavor_wrid_list_reap(
	dapls_tavor_wrid_list_hdr_t *);
static dapls_tavor_workq_hdr_t *dapli_tavor_wrid_wqhdr_create(ib_cq_handle_t,
    uint_t, uint_t, uint_t);
static void dapli_tavor_wrid_wqhdr_add(dapls_tavor_workq_hdr_t *,
    dapls_tavor_wrid_list_hdr_t *);
static void dapli_tavor_wrid_wqhdr_remove(dapls_tavor_workq_hdr_t *,
    dapls_tavor_wrid_list_hdr_t *);
static void dapli_tavor_wrid_wqhdr_lock_both(ib_qp_handle_t);
static void dapli_tavor_wrid_wqhdr_unlock_both(ib_qp_handle_t);
static DAT_RETURN dapli_tavor_cq_wqhdr_add(ib_cq_handle_t,
    dapls_tavor_workq_hdr_t *);
static void dapli_tavor_cq_wqhdr_remove(ib_cq_handle_t,
    dapls_tavor_workq_hdr_t *);

/*
 * dapls_tavor_wrid_get_entry()
 */
uint64_t
dapls_tavor_wrid_get_entry(ib_cq_handle_t cq, tavor_hw_cqe_t *cqe,
    uint_t send_or_recv, uint_t error, dapls_tavor_wrid_entry_t *wre)
{
	dapls_tavor_workq_hdr_t	*wq;
	dapls_tavor_wrid_entry_t	*wre_tmp;
	uint64_t		wrid;
	uint_t			qpnum;

	/* Lock the list of work queues associated with this CQ */
	dapl_os_lock(&cq->cq_wrid_wqhdr_lock);

	/* Find the work queue for this QP number (send or receive side) */
	qpnum = TAVOR_CQE_QPNUM_GET(cqe);
	wq = dapli_tavor_wrid_wqhdr_find(cq, qpnum, send_or_recv);

	dapl_os_assert(wq != NULL);

	/*
	 * Regardless of whether the completion is the result of a "success"
	 * or a "failure", we lock the list of "containers" and attempt to
	 * search for the the first matching completion (i.e. the first WR
	 * with a matching WQE addr and size).  Once we find it, we pull out
	 * the "wrid" field and return it (see below).  Note: One possible
	 * future enhancement would be to enable this routine to skip over
	 * any "unsignaled" completions to go directly to the next "signaled"
	 * entry on success. XXX
	 */
	dapl_os_lock(&wq->wq_wrid_lock->wrl_lock);
	wre_tmp = dapli_tavor_wrid_find_match(wq, cqe);

	/*
	 * If this is a "successful" completion, then we assert that this
	 * completion must be a "signaled" completion.
	 */
	dapl_os_assert(error || (wre_tmp->wr_signaled_dbd &
	    TAVOR_WRID_ENTRY_SIGNALED));

	/*
	 * If the completion is a "failed" completion, then we save away the
	 * contents of the entry (into the "wre" field passed in) for use
	 * in later CQE processing. Note: We use the
	 * dapli_tavor_wrid_get_wqeaddrsz() function to grab "wqeaddrsz" from
	 * the next entry in the container.
	 * This is required for error processing (where updating these fields
	 * properly is necessary to correct handling of the "error" CQE)
	 */
	if (error && (wre != NULL)) {
		*wre = *wre_tmp;
		wre->wr_wqeaddrsz = dapli_tavor_wrid_get_wqeaddrsz(wq);
	}

	/* Pull out the WRID and return it */
	wrid = wre_tmp->wr_wrid;

	dapl_os_unlock(&wq->wq_wrid_lock->wrl_lock);
	dapl_os_unlock(&cq->cq_wrid_wqhdr_lock);

	return (wrid);
}


/*
 * dapli_tavor_wrid_find_match()
 */
static dapls_tavor_wrid_entry_t *
dapli_tavor_wrid_find_match(dapls_tavor_workq_hdr_t *wq, tavor_hw_cqe_t *cqe)
{
	dapls_tavor_wrid_entry_t	*curr = NULL;
	dapls_tavor_wrid_list_hdr_t	*container;
	uint32_t		wqeaddr_size;
	uint32_t		head, tail, size;
	int			found = 0, last_container;

	/* dapl_os_assert(MUTEX_HELD(&wq->wq_wrid_lock)); */

	/* Pull the "wqeaddrsz" information from the CQE */
	wqeaddr_size = TAVOR_CQE_WQEADDRSZ_GET(cqe);

	/*
	 * Walk the "containers" list(s), find first WR with a matching WQE
	 * addr.  If the current "container" is not the last one on the list,
	 * i.e. not the current one to which we are posting new WRID entries,
	 * then we do not attempt to update the "q_head", "q_tail", and
	 * "q_full" indicators on the main work queue header.  We do, however,
	 * update the "head" and "full" indicators on the individual containers
	 * as we go.  This is imperative because we need to be able to
	 * determine when the current container has been emptied (so that we
	 * can move on to the next container).
	 */
	container = wq->wq_wrid_poll;
	while (container != NULL) {

		/* Is this the last/only "container" on the list */
		last_container = (container != wq->wq_wrid_post) ? 0 : 1;

		/*
		 * First check if we are on an SRQ.  If so, we grab the entry
		 * and break out.  Since SRQ wridlist's are never added to
		 * reaplist, they can only be the last container.
		 */
		if (container->wl_srq_en) {
			dapl_os_assert(last_container == 1);
			curr = dapli_tavor_wrid_find_match_srq(container, cqe);
			break;
		}

		/*
		 * Grab the current "head", "tail" and "size" fields before
		 * walking the list in the current container. Note: the "size"
		 * field here must always be a power-of-2.  The "full"
		 * parameter is checked (and updated) here to distinguish the
		 * "queue full" condition from "queue empty".
		 */
		head = container->wl_head;
		tail = container->wl_tail;
		size = container->wl_size;
		while ((head != tail) || (container->wl_full)) {
			container->wl_full = 0;
			curr = &container->wl_wre[head];
			head = ((head + 1) & (size - 1));
			/*
			 * If the current entry's "wqeaddrsz" matches the one
			 * we're searching for, then this must correspond to
			 * the work request that caused the completion.  Set
			 * the "found" flag and bail out.
			 */
			if (curr->wr_wqeaddrsz == wqeaddr_size) {
				found = 1;
				break;
			}
		}

		/*
		 * If the current container is empty (having reached here the
		 * "head == tail" condition can only mean that the container
		 * is empty), then NULL out the "wrid_old_tail" field (see
		 * tavor_post_send() and tavor_post_recv() for more details)
		 * and (potentially) remove the current container from future
		 * searches.
		 */
		if (head == tail) {
			container->wl_wre_old_tail = NULL;
			/*
			 * If this wasn't the last "container" on the chain,
			 * i.e. the one to which new WRID entries will be
			 * added, then remove it from the list.
			 * Note: we don't "lose" the memory pointed to by this
			 * because we should have already put this container
			 * on the "reapable" list (from where it will later be
			 * pulled).
			 */
			if (!last_container) {
				wq->wq_wrid_poll = container->wl_next;
			}
		}

		/* Update the head index for the container */
		container->wl_head = head;

		/*
		 * If the entry was found in this container, then continue to
		 * bail out.  Else reset the "curr" pointer and move on to the
		 * next container (if there is one).  Note: the only real
		 * reason for setting "curr = NULL" here is so that the ASSERT
		 * below can catch the case where no matching entry was found
		 * on any of the lists.
		 */
		if (found) {
			break;
		} else {
			curr = NULL;
			container = container->wl_next;
		}
	}

	/*
	 * Update work queue header's "head" and "full" conditions to match
	 * the last entry on the container list.  (Note: Only if we're pulling
	 * entries from the last work queue portion of the list, i.e. not from
	 * the previous portions that may be the "reapable" list.)
	 */
	if (last_container) {
		wq->wq_head = wq->wq_wrid_post->wl_head;
		wq->wq_full = wq->wq_wrid_post->wl_full;
	}

	/* Ensure that we've actually found what we were searching for */
	dapl_os_assert(curr != NULL);

	return (curr);
}

/*
 * tavor_wrid_find_match_srq()
 *    Context: Can be called from interrupt or base context.
 */
dapls_tavor_wrid_entry_t *
dapli_tavor_wrid_find_match_srq(dapls_tavor_wrid_list_hdr_t *wl,
    tavor_hw_cqe_t *cqe)
{
	dapls_tavor_wrid_entry_t	*wre;
	uint32_t		wqe_index;
	uint32_t		wqe_addr;
	uint32_t		qsize_msk;
	uint32_t		tail, next_tail;

	/* Grab the WQE addr out of the CQE */
	wqe_addr = TAVOR_CQE_WQEADDRSZ_GET(cqe) & 0xFFFFFFC0;

	/*
	 * Given the 'wqe_addr' just calculated and the srq buf address, we
	 * find the 'wqe_index'.  The 'wre' returned below contains the WRID
	 * that we are looking for.  This indexes into the wre_list for this
	 * specific WQE.
	 */
	wqe_index = TAVOR_SRQ_WQ_INDEX(wl->wl_srq_desc_addr, wqe_addr,
	    wl->wl_srq_wqesz);

	/* ASSERT on impossible wqe_index values */
	dapl_os_assert(wqe_index < wl->wl_size);

	/* Put this WQE back on the free list */

	qsize_msk = wl->wl_size - 1;
	tail	  = wl->wl_freel_tail;

	next_tail = (tail + 1) & qsize_msk;
	wl->wl_freel_entries++;

	dapl_os_assert(wl->wl_freel_entries <= wl->wl_size);

	/* Get the descriptor (IO Address) of the WQE to be built */
	wl->wl_free_list[tail] = wqe_addr;
	wl->wl_freel_tail = next_tail;
	/* Using the index, return the Work Request ID Entry (wre) */
	wre = &wl->wl_wre[wqe_index];

	return (wre);
}

/*
 * dapls_tavor_wrid_cq_reap()
 */
void
dapls_tavor_wrid_cq_reap(ib_cq_handle_t cq)
{
	dapls_tavor_workq_hdr_t	*consume_wqhdr;
	dapls_tavor_wrid_list_hdr_t	*container, *to_free;


	/* dapl_os_assert(MUTEX_HELD(&cq->cq_lock)); */

	/* Lock the list of work queues associated with this CQ */
	dapl_os_lock(&cq->cq_wrid_wqhdr_lock);

	/* Walk the "reapable" list and free up containers */
	container = cq->cq_wrid_reap_head;
	while (container != NULL) {
		to_free	  = container;
		container = container->wl_reap_next;
		/*
		 * If reaping the WRID list containers pulls the last
		 * container from the given work queue header, then we free
		 * the work queue header as well.
		 */
		consume_wqhdr = dapli_tavor_wrid_list_reap(to_free);
		if (consume_wqhdr != NULL) {
			dapli_tavor_cq_wqhdr_remove(cq, consume_wqhdr);
		}
	}

	/* Once finished reaping, we reset the CQ's reap list */
	cq->cq_wrid_reap_head = cq->cq_wrid_reap_tail = NULL;

	dapl_os_unlock(&cq->cq_wrid_wqhdr_lock);
}


/*
 * dapls_tavor_wrid_cq_force_reap()
 */
void
dapls_tavor_wrid_cq_force_reap(ib_cq_handle_t cq)
{
	DAPL_HASH_DATA		curr;
	DAT_RETURN		retval;
	dapls_tavor_workq_hdr_t		*to_free_wqhdr;
	dapls_tavor_wrid_list_hdr_t	*container, *to_free;

	/* dapl_os_assert(MUTEX_HELD(&cq->cq_lock)); */

	/*
	 * The first step is to walk the "reapable" list and free up those
	 * containers.  This is necessary because the containers on the
	 * reapable list are not otherwise connected to the work queue headers
	 * anymore.
	 */
	dapls_tavor_wrid_cq_reap(cq);

	/* Now lock the list of work queues associated with this CQ */
	dapl_os_lock(&cq->cq_wrid_wqhdr_lock);

	/*
	 * Walk the list of work queue headers and free up all the WRID list
	 * containers chained to it.  Note: We don't need to grab the locks
	 * for each of the individual WRID lists here because the only way
	 * things can be added or removed from the list at this point would be
	 * through post a work request to a QP.  But if we've come this far,
	 * then we can be assured that there are no longer any QP associated
	 * with the CQ that we are trying to free.
	 */
	retval = dapls_hash_iterate(cq->cq_wrid_wqhdr_list,
	    DAPL_HASH_ITERATE_INIT, &curr);
	dapl_os_assert(retval == DAT_SUCCESS);

	while (curr != NULL) {
		to_free_wqhdr = (dapls_tavor_workq_hdr_t *)curr;
		container = ((dapls_tavor_workq_hdr_t *)curr)->wq_wrid_poll;
		retval = dapls_hash_iterate(cq->cq_wrid_wqhdr_list,
		    DAPL_HASH_ITERATE_NEXT, &curr);
		dapl_os_assert(retval == DAT_SUCCESS);
		while (container != NULL) {
			to_free	  = container;
			container = container->wl_next;
			/*
			 * If reaping the WRID list containers pulls the last
			 * container from the given work queue header, then
			 * we free the work queue header as well.  Note: we
			 * ignore the return value because we know that the
			 * work queue header should always be freed once the
			 * list of containers has come to an end.
			 */
			(void) dapli_tavor_wrid_list_reap(to_free);
			if (container == NULL) {
				dapli_tavor_cq_wqhdr_remove(cq, to_free_wqhdr);
			}
		}
	}

	dapl_os_lock(&cq->cq_wrid_wqhdr_lock);
}


/*
 * dapli_tavor_wrid_get_list()
 */
static dapls_tavor_wrid_list_hdr_t *
dapli_tavor_wrid_get_list(uint32_t qsize, int wrid_for_srq)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	dapls_tavor_wrid_entry_t	*wl_wre;
	uint32_t			*wl_freel;
	uint32_t			size;
	uint32_t			wl_wre_size;
	uint32_t			wl_freel_size;

	wridlist = NULL;
	wl_wre = NULL;
	wl_freel = NULL;
	size = wl_wre_size = wl_freel_size = 0;
	/*
	 * The WRID list "container" consists of the dapls_tavor_wrid_list_hdr_t
	 * which holds the pointers necessary for maintaining the "reapable"
	 * list, chaining together multiple "containers" old and new, and
	 * tracking the head, tail, size, etc. for each container.  The
	 * "container" also holds all the tavor_wrid_entry_t's, one for
	 * each entry on the corresponding work queue.
	 */

	/*
	 * For wridlist associated with SRQs the wridlock needs to be
	 * allocated and initialized here.
	 */
	size = sizeof (dapls_tavor_wrid_list_hdr_t);
	if (wrid_for_srq) {
		size = size + sizeof (dapls_tavor_wrid_lock_t);
	}
	wridlist = dapl_os_alloc(size);
	if (wridlist == NULL) {
		goto bail;
	}
	if (wrid_for_srq) {
		wridlist->wl_lock = (dapls_tavor_wrid_lock_t *)(
		    (uintptr_t)wridlist + sizeof (dapls_tavor_wrid_list_hdr_t));
		dapl_os_lock_init(&wridlist->wl_lock->wrl_lock);
		wridlist->wl_lock->wrl_on_srq = wrid_for_srq;
	} else {
		wridlist->wl_lock = NULL;
	}
	wl_wre_size = qsize * sizeof (dapls_tavor_wrid_entry_t);
	wl_wre = dapl_os_alloc(wl_wre_size);
	if (wl_wre == NULL) {
		goto bail;
	}
	if (wrid_for_srq) { /* memory for the SRQ free list */
		wl_freel_size = qsize * sizeof (uint32_t);
		wl_freel = dapl_os_alloc(wl_freel_size);
		if (wl_freel == NULL) {
			goto bail;
		}
	}


	/* Complete the "container" initialization */
	wridlist->wl_size = qsize;
	wridlist->wl_full = 0;
	wridlist->wl_head = 0;
	wridlist->wl_tail = 0;
	wridlist->wl_wre = wl_wre;
	wridlist->wl_wre_old_tail  = NULL;
	wridlist->wl_reap_next = NULL;
	wridlist->wl_next  = NULL;
	wridlist->wl_prev  = NULL;
	if (wrid_for_srq) {
		wridlist->wl_srq_en = 1;
		wridlist->wl_free_list = (uint32_t *)wl_freel;
		wridlist->wl_freel_head = 0;
		wridlist->wl_freel_tail = 0;
		wridlist->wl_freel_entries = qsize;
	} else {
		wridlist->wl_srq_en = 0;
		wridlist->wl_free_list = NULL;
		wridlist->wl_freel_head = 0;
		wridlist->wl_freel_tail = 0;
		wridlist->wl_freel_entries = 0;
		wridlist->wl_srq_wqesz = 0;
		wridlist->wl_srq_desc_addr = 0;
	}
	return (wridlist);
bail:
	if (wridlist) {
		if (wrid_for_srq) {
			dapl_os_lock_destroy(&wridlist->wl_lock->wrl_lock);
		}
		dapl_os_free(wridlist, size);
	}
	if (wl_wre) {
		dapl_os_free(wl_wre, wl_wre_size);
	}
	if (wl_freel) {
		dapl_os_free(wl_freel, wl_freel_size);
	}
	return (NULL);
}


/*
 * dapli_tavor_wrid_reaplist_add()
 */
static void
dapli_tavor_wrid_reaplist_add(ib_cq_handle_t cq, dapls_tavor_workq_hdr_t *wq)
{
	/* dapl_os_assert(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock)); */

	dapl_os_lock(&wq->wq_wrid_lock->wrl_lock);

	/*
	 * Add the "post" container (the last one on the current chain) to
	 * the CQ's "reapable" list
	 */
	if ((cq->cq_wrid_reap_head == NULL) &&
	    (cq->cq_wrid_reap_tail == NULL)) {
		cq->cq_wrid_reap_head = wq->wq_wrid_post;
		cq->cq_wrid_reap_tail = wq->wq_wrid_post;
	} else {
		cq->cq_wrid_reap_tail->wl_reap_next = wq->wq_wrid_post;
		cq->cq_wrid_reap_tail = wq->wq_wrid_post;
	}

	dapl_os_unlock(&wq->wq_wrid_lock->wrl_lock);
}


/*
 * dapli_tavor_wrid_wqhdr_find()
 */
static dapls_tavor_workq_hdr_t *
dapli_tavor_wrid_wqhdr_find(ib_cq_handle_t cq, uint_t qpn, uint_t send_or_recv)
{
	DAPL_HASH_DATA		curr;
	DAPL_HASH_KEY		key;
	DAT_RETURN		status;

	/* dapl_os_assert(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock)); */

	/*
	 * Walk the CQ's work queue list, trying to find a send or recv queue
	 * with the same QP number.  We do this even if we are going to later
	 * create a new entry because it helps us easily find the end of the
	 * list.
	 */
	key = (DAPL_HASH_KEY)(((uint64_t)send_or_recv << 32) | (uint32_t)qpn);

	status = dapls_hash_search(cq->cq_wrid_wqhdr_list, key, &curr);
	if (status == DAT_SUCCESS) {
		return ((dapls_tavor_workq_hdr_t *)curr);
	} else {
		return (NULL);
	}
}




/*
 * dapli_tavor_wrid_get_wqeaddrsz()
 */
static uint32_t
dapli_tavor_wrid_get_wqeaddrsz(dapls_tavor_workq_hdr_t *wq)
{
	dapls_tavor_wrid_entry_t	*wre;
	uint32_t		wqeaddrsz;
	uint32_t		head;

	/*
	 * If the container is empty, then there is no next entry. So just
	 * return zero.  Note: the "head == tail" condition here can only
	 * mean that the container is empty because we have previously pulled
	 * something from the container.
	 *
	 * If the container is not empty, then find the next entry and return
	 * the contents of its "wqeaddrsz" field.
	 */
	if (wq->wq_wrid_poll->wl_head == wq->wq_wrid_poll->wl_tail) {
		wqeaddrsz = 0;
	} else {
		/*
		 * We don't need to calculate the "next" head pointer here
		 * because "head" should already point to the next entry on
		 * the list (since we just pulled something off - in
		 * dapli_tavor_wrid_find_match() - and moved the head index
		 * forward.)
		 */
		head = wq->wq_wrid_poll->wl_head;
		wre = &wq->wq_wrid_poll->wl_wre[head];
		wqeaddrsz = wre->wr_wqeaddrsz;
	}
	return (wqeaddrsz);
}



/*
 * dapli_tavor_wrid_list_reap()
 *    Note: The "wqhdr_list_lock" must be held.
 */
static dapls_tavor_workq_hdr_t *
dapli_tavor_wrid_list_reap(dapls_tavor_wrid_list_hdr_t *wridlist)
{
	dapls_tavor_workq_hdr_t	*wqhdr, *consume_wqhdr = NULL;
	dapls_tavor_wrid_list_hdr_t	*prev, *next;

	/* Get the back pointer to the work queue header (see below) */
	wqhdr = wridlist->wl_wqhdr;
	dapl_os_lock(&wqhdr->wq_wrid_lock->wrl_lock);

	/* Unlink the WRID list "container" from the work queue list */
	prev = wridlist->wl_prev;
	next = wridlist->wl_next;
	if (prev != NULL) {
		prev->wl_next = next;
	}
	if (next != NULL) {
		next->wl_prev = prev;
	}

	/*
	 * If the back pointer to the work queue header shows that it
	 * was pointing to the entry we are about to remove, then the work
	 * queue header is reapable as well.
	 */
	if ((wqhdr->wq_wrid_poll == wridlist) &&
	    (wqhdr->wq_wrid_post == wridlist)) {
		consume_wqhdr = wqhdr;
	}

	/* Be sure to update the "poll" and "post" container pointers */
	if (wqhdr->wq_wrid_poll == wridlist) {
		wqhdr->wq_wrid_poll = next;
	}
	if (wqhdr->wq_wrid_post == wridlist) {
		wqhdr->wq_wrid_post = NULL;
	}

	/*
	 * Calculate the size and free the container, for SRQ wridlist is
	 * freed when srq gets freed
	 */
	if (!wridlist->wl_srq_en) {
		if (wridlist->wl_wre) {
			dapl_os_free(wridlist->wl_wre, wridlist->wl_size *
			    sizeof (dapls_tavor_wrid_entry_t));
		}
		dapl_os_assert(wridlist->wl_free_list == NULL);
		dapl_os_free(wridlist, sizeof (dapls_tavor_wrid_list_hdr_t));
	}

	dapl_os_unlock(&wqhdr->wq_wrid_lock->wrl_lock);

	return (consume_wqhdr);
}

/*
 * dapls_tavor_srq_wrid_init()
 */
DAT_RETURN
dapls_tavor_srq_wrid_init(ib_srq_handle_t srq)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	int i;

	wridlist = dapli_tavor_wrid_get_list(srq->srq_wq_numwqe, 1);


	if (wridlist == NULL) {
		srq->srq_wridlist = NULL;
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}

	/* initialize the free list with the descriptor addresses */
	wridlist->wl_free_list[0] = srq->srq_wq_desc_addr;
	for (i = 1; i < srq->srq_wq_numwqe; i++) {
		wridlist->wl_free_list[i] = wridlist->wl_free_list[i-1] +
		    srq->srq_wq_wqesz;
	}
	wridlist->wl_srq_wqesz = srq->srq_wq_wqesz;
	wridlist->wl_srq_desc_addr = srq->srq_wq_desc_addr;

	srq->srq_wridlist = wridlist;
	return (DAT_SUCCESS);
}

void
dapls_tavor_srq_wrid_free(ib_srq_handle_t srq)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	size_t				size = 0;

	wridlist = srq->srq_wridlist;
	if (wridlist) {
		dapl_os_assert(wridlist->wl_srq_en == 1);
		if (wridlist->wl_wre) {
			dapl_os_free(wridlist->wl_wre, wridlist->wl_size *
			    sizeof (dapls_tavor_wrid_entry_t));
		}
		if (wridlist->wl_free_list) {
			dapl_os_free(wridlist->wl_free_list, wridlist->wl_size *
			    sizeof (uint32_t));
		}
		if (wridlist->wl_lock) {
			dapl_os_assert(wridlist->wl_lock->wrl_on_srq == 1);
			dapl_os_lock_destroy(&wridlist->wl_lock->wrl_lock);
			size = sizeof (dapls_tavor_wrid_lock_t);
		}
		size = size; /* pacify lint */
		dapl_os_free(wridlist, size +
		    sizeof (dapls_tavor_wrid_list_hdr_t));
		srq->srq_wridlist = NULL;
	}
}


/*
 * dapls_tavor_wrid_init()
 */
DAT_RETURN
dapls_tavor_wrid_init(ib_qp_handle_t qp)
{
	dapls_tavor_workq_hdr_t		*swq;
	dapls_tavor_workq_hdr_t		*rwq;
	dapls_tavor_wrid_list_hdr_t	*s_wridlist;
	dapls_tavor_wrid_list_hdr_t	*r_wridlist;
	uint_t		create_new_swq = 0;
	uint_t		create_new_rwq = 0;

	/*
	 * For each of this QP's Work Queues, make sure we have a (properly
	 * initialized) Work Request ID list attached to the relevant
	 * completion queue.  Grab the CQ lock(s) before manipulating the
	 * lists.
	 */
	dapli_tavor_wrid_wqhdr_lock_both(qp);
	swq = dapli_tavor_wrid_wqhdr_find(qp->qp_sq_cqhdl, qp->qp_num,
	    TAVOR_WR_SEND);
	if (swq == NULL) {
		/* Couldn't find matching work queue header, create it */
		create_new_swq = 1;
		swq = dapli_tavor_wrid_wqhdr_create(qp->qp_sq_cqhdl,
		    qp->qp_num, TAVOR_WR_SEND, 1);
		if (swq == NULL) {
			/*
			 * If we couldn't find/allocate space for the workq
			 * header, then drop the lock(s) and return failure.
			 */
			dapli_tavor_wrid_wqhdr_unlock_both(qp);
			return (DAT_INSUFFICIENT_RESOURCES);
		}
	}
	qp->qp_sq_wqhdr = swq;
	swq->wq_size = qp->qp_sq_numwqe;
	swq->wq_head = 0;
	swq->wq_tail = 0;
	swq->wq_full = 0;

	/*
	 * Allocate space for the dapls_tavor_wrid_entry_t container
	 */
	s_wridlist = dapli_tavor_wrid_get_list(swq->wq_size, 0);
	if (s_wridlist == NULL) {
		/*
		 * If we couldn't allocate space for tracking the WRID
		 * entries, then cleanup the workq header from above (if
		 * necessary, i.e. if we created the workq header).  Then
		 * drop the lock(s) and return failure.
		 */
		if (create_new_swq) {
			dapli_tavor_cq_wqhdr_remove(qp->qp_sq_cqhdl, swq);
		}

		dapli_tavor_wrid_wqhdr_unlock_both(qp);
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}
	s_wridlist->wl_wqhdr = swq;
	/* Chain the new WRID list container to the workq hdr list */
	dapl_os_lock(&swq->wq_wrid_lock->wrl_lock);
	dapli_tavor_wrid_wqhdr_add(swq, s_wridlist);
	dapl_os_unlock(&swq->wq_wrid_lock->wrl_lock);


	/*
	 * Now we repeat all the above operations for the receive work queue
	 */
	rwq = dapli_tavor_wrid_wqhdr_find(qp->qp_rq_cqhdl, qp->qp_num,
	    TAVOR_WR_RECV);
	if (rwq == NULL) {
		create_new_rwq = 1;
		/* if qp is attached to an SRQ don't need to alloc wrid_lock */
		rwq = dapli_tavor_wrid_wqhdr_create(qp->qp_rq_cqhdl,
		    qp->qp_num, TAVOR_WR_RECV, qp->qp_srq_enabled ? 0 : 1);
		if (rwq == NULL) {
			/*
			 * If we couldn't find/allocate space for the workq
			 * header, then free all the send queue resources we
			 * just allocated and setup (above), drop the lock(s)
			 * and return failure.
			 */
			dapl_os_lock(&swq->wq_wrid_lock->wrl_lock);
			dapli_tavor_wrid_wqhdr_remove(swq, s_wridlist);
			dapl_os_unlock(&swq->wq_wrid_lock->wrl_lock);
			if (create_new_swq) {
				dapli_tavor_cq_wqhdr_remove(qp->qp_sq_cqhdl,
				    swq);
			}

			dapli_tavor_wrid_wqhdr_unlock_both(qp);
			return (DAT_INSUFFICIENT_RESOURCES |
			    DAT_RESOURCE_MEMORY);
		}
	}
	qp->qp_rq_wqhdr = rwq;
	rwq->wq_size = qp->qp_rq_numwqe;
	rwq->wq_head = 0;
	rwq->wq_tail = 0;
	rwq->wq_full = 0;

	/*
	 * Allocate space for the dapls_tavor_wrid_entry_t container
	 * For qp associated with SRQs the SRQ wridlist is used
	 */
	if (qp->qp_srq_enabled) {
		/* Use existing srq_wridlist pointer */
		r_wridlist = qp->qp_srq->srq_wridlist;
		dapl_os_assert(r_wridlist != NULL);
		/* store the wl_lock in the wqhdr */
		rwq->wq_wrid_lock = r_wridlist->wl_lock;
		dapl_os_assert(rwq->wq_wrid_lock != NULL);
	} else {
		/* Allocate memory for the r_wridlist */
		r_wridlist = dapli_tavor_wrid_get_list(rwq->wq_size, 0);
	}
	if (r_wridlist == NULL) {
		/*
		 * If we couldn't allocate space for tracking the WRID
		 * entries, then cleanup all the stuff from above.  Then
		 * drop the lock(s) and return failure.
		 */
		dapl_os_lock(&swq->wq_wrid_lock->wrl_lock);
		dapli_tavor_wrid_wqhdr_remove(swq, s_wridlist);
		dapl_os_unlock(&swq->wq_wrid_lock->wrl_lock);
		if (create_new_swq) {
			dapli_tavor_cq_wqhdr_remove(qp->qp_sq_cqhdl, swq);
		}
		if (create_new_rwq) {
			dapli_tavor_cq_wqhdr_remove(qp->qp_rq_cqhdl, rwq);
		}

		dapli_tavor_wrid_wqhdr_unlock_both(qp);
		return (DAT_INSUFFICIENT_RESOURCES | DAT_RESOURCE_MEMORY);
	}

	/* For SRQ based QPs r_wridlist does not point to recv wqhdr */
	if (!qp->qp_srq_enabled) {
		r_wridlist->wl_wqhdr = rwq;
	}

	/* Chain the new WRID list "container" to the workq hdr list */
	dapl_os_lock(&rwq->wq_wrid_lock->wrl_lock);
	dapli_tavor_wrid_wqhdr_add(rwq, r_wridlist);
	dapl_os_unlock(&rwq->wq_wrid_lock->wrl_lock);

	dapli_tavor_wrid_wqhdr_unlock_both(qp);

	return (DAT_SUCCESS);
}


/*
 * dapls_tavor_wrid_cleanup()
 */
void
dapls_tavor_wrid_cleanup(DAPL_EP *ep, ib_qp_handle_t qp)
{
	/*
	 * For each of this QP's Work Queues, move the WRID "container" to
	 * the "reapable" list.  Although there may still be unpolled
	 * entries in these containers, it is not a big deal.  We will not
	 * reap the list until either the Poll CQ command detects an empty
	 * condition or the CQ itself is freed.  Grab the CQ lock(s) before
	 * manipulating the lists.
	 */
	dapli_tavor_wrid_wqhdr_lock_both(qp);
	dapli_tavor_wrid_reaplist_add(qp->qp_sq_cqhdl, qp->qp_sq_wqhdr);

	/*
	 * Repeat the above operation for the Recv work queue "container".
	 * However for qps with SRQ we flush the cq entries, remove the
	 * wridlist and wqhdr.
	 * Then drop the CQ lock(s) and return
	 */
	if (qp->qp_srq_enabled) {
		/*
		 * Pull off all (if any) entries for this QP from CQ.  This
		 * only includes entries that have not yet been polled
		 */
		dapl_os_lock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);
		DAPL_FLUSH(ep)(qp);

		/* Remove wridlist from WQHDR */
		dapli_tavor_wrid_wqhdr_remove(qp->qp_rq_wqhdr,
		    qp->qp_rq_wqhdr->wq_wrid_post);

		dapl_os_assert(qp->qp_rq_wqhdr->wq_wrid_post == NULL);

		dapl_os_unlock(&qp->qp_rq_wqhdr->wq_wrid_lock->wrl_lock);

		/* Free the WQHDR */
		dapli_tavor_cq_wqhdr_remove(qp->qp_rq_cqhdl, qp->qp_rq_wqhdr);
	} else {
		dapli_tavor_wrid_reaplist_add(qp->qp_rq_cqhdl, qp->qp_rq_wqhdr);
	}
	dapli_tavor_wrid_wqhdr_unlock_both(qp);
}

/*
 * dapli_tavor_wrid_wqhdr_create()
 */
static dapls_tavor_workq_hdr_t *
dapli_tavor_wrid_wqhdr_create(ib_cq_handle_t cq, uint_t qpn,
    uint_t send_or_recv, uint_t alloc_wrl)
{
	dapls_tavor_workq_hdr_t	*wqhdr_tmp;
	size_t			size, aligned_size;

	/* dapl_os_assert(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock)); */

	/*
	 * Allocate space for a work queue header structure and initialize it.
	 * Each work queue header structure includes a "wq_wrid_lock"
	 * which needs to be initialized.
	 *
	 * Note: the address smashing is needed to ensure wq_wrid_lock is
	 * 8-byte aligned, which is not always the case on 32-bit sparc.
	 */
	size = (sizeof (dapls_tavor_workq_hdr_t) + 0x7) & ~0x7;
	aligned_size = size;
	if (alloc_wrl) {
		/* for non-srq wqhdr the lock is allocated with the wqhdr */
		size = size + sizeof (dapls_tavor_wrid_lock_t);
	}
	wqhdr_tmp = dapl_os_alloc(size);
	if (wqhdr_tmp == NULL) {
		return (NULL);
	}
	if (alloc_wrl) {
		wqhdr_tmp->wq_wrid_lock = (dapls_tavor_wrid_lock_t *)
		    (((uintptr_t)wqhdr_tmp + aligned_size) & ~0x7);
		dapl_os_lock_init(&wqhdr_tmp->wq_wrid_lock->wrl_lock);
		/* wrl allocated with wqhdr don't have srq enabled */
		wqhdr_tmp->wq_wrid_lock->wrl_on_srq = 0;
	}

	wqhdr_tmp->wq_qpn	= qpn;
	wqhdr_tmp->wq_send_or_recv = send_or_recv;

	wqhdr_tmp->wq_wrid_poll = NULL;
	wqhdr_tmp->wq_wrid_post = NULL;

	/* Chain the newly allocated work queue header to the CQ's list */
	if (dapli_tavor_cq_wqhdr_add(cq, wqhdr_tmp) != DAT_SUCCESS) {
		if (alloc_wrl) {
			dapl_os_lock_destroy(&wqhdr_tmp->wq_wrid_lock->
			    wrl_lock);
		}
		dapl_os_free(wqhdr_tmp, size);
		wqhdr_tmp = NULL;
	}

	return (wqhdr_tmp);
}

/*
 * dapli_tavor_wrid_wqhdr_add()
 */
static void
dapli_tavor_wrid_wqhdr_add(dapls_tavor_workq_hdr_t *wqhdr,
    dapls_tavor_wrid_list_hdr_t *wridlist)
{
	/* dapl_os_assert(MUTEX_HELD(&wqhdr->wq_wrid_lock)); */

	/* Chain the new WRID list "container" to the work queue list */
	if ((wqhdr->wq_wrid_post == NULL) &&
	    (wqhdr->wq_wrid_poll == NULL)) {
		wqhdr->wq_wrid_poll = wridlist;
		wqhdr->wq_wrid_post = wridlist;
	} else {
		wqhdr->wq_wrid_post->wl_next = wridlist;
		wridlist->wl_prev = wqhdr->wq_wrid_post;
		wqhdr->wq_wrid_post = wridlist;
	}
}


/*
 * dapli_tavor_wrid_wqhdr_remove()
 *    Note: this is only called to remove the most recently added WRID list
 *    container.
 */
static void
dapli_tavor_wrid_wqhdr_remove(dapls_tavor_workq_hdr_t *wqhdr,
    dapls_tavor_wrid_list_hdr_t *wridlist)
{
	dapls_tavor_wrid_list_hdr_t	*prev, *next;

	/* dapl_os_assert(MUTEX_HELD(&wqhdr->wq_wrid_lock)); */

	/* Unlink the WRID list "container" from the work queue list */
	prev = wridlist->wl_prev;
	next = wridlist->wl_next;
	if (prev != NULL) {
		prev->wl_next = next;
	}
	if (next != NULL) {
		next->wl_prev = prev;
	}

	/*
	 * Update any pointers in the work queue hdr that may point to this
	 * WRID list container
	 */
	if (wqhdr->wq_wrid_post == wridlist) {
		wqhdr->wq_wrid_post = prev;
	}
	if (wqhdr->wq_wrid_poll == wridlist) {
		wqhdr->wq_wrid_poll = NULL;
	}
}


/*
 * dapli_tavor_wrid_wqhdr_lock_both()
 */
static void
dapli_tavor_wrid_wqhdr_lock_both(ib_qp_handle_t qp)
{
	ib_cq_handle_t	sq_cq, rq_cq;

	sq_cq = qp->qp_sq_cqhdl;
	rq_cq = qp->qp_rq_cqhdl;

	/*
	 * If both work queues (send and recv) share a completion queue, then
	 * grab the common lock.  If they use different CQs (hence different
	 * "cq_wrid_wqhdr_list" locks), then grab the send one first, then the
	 * receive.  We do this consistently and correctly in
	 * tavor_wrid_wqhdr_unlock_both() below to avoid introducing any kind
	 * of dead lock condition.
	 */
	if (sq_cq == rq_cq) {
		dapl_os_lock(&sq_cq->cq_wrid_wqhdr_lock);
	} else {
		dapl_os_lock(&sq_cq->cq_wrid_wqhdr_lock);
		dapl_os_lock(&rq_cq->cq_wrid_wqhdr_lock);
	}
}

/*
 * dapli_tavor_wrid_wqhdr_unlock_both()
 */
static void
dapli_tavor_wrid_wqhdr_unlock_both(ib_qp_handle_t qp)
{
	ib_cq_handle_t	sq_cq, rq_cq;

	sq_cq = qp->qp_sq_cqhdl;
	rq_cq = qp->qp_rq_cqhdl;

	/*
	 * See tavor_wrid_wqhdr_lock_both() above for more detail
	 */
	if (sq_cq == rq_cq) {
		dapl_os_unlock(&sq_cq->cq_wrid_wqhdr_lock);
	} else {
		dapl_os_unlock(&rq_cq->cq_wrid_wqhdr_lock);
		dapl_os_unlock(&sq_cq->cq_wrid_wqhdr_lock);
	}
}


/*
 * dapli_tavor_cq_wqhdr_add()
 */
static DAT_RETURN
dapli_tavor_cq_wqhdr_add(ib_cq_handle_t cq, dapls_tavor_workq_hdr_t *wqhdr)
{
	DAPL_HASH_KEY		key;

	/* dapl_os_assert(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock)); */

	/*
	 * If the CQ's work queue list is empty, then just add it.
	 * Otherwise, chain it to the beginning of the list.
	 */
	key = (DAPL_HASH_KEY)(((uint64_t)wqhdr->wq_send_or_recv << 32) |
	    wqhdr->wq_qpn);

	return (dapls_hash_insert(cq->cq_wrid_wqhdr_list, key, wqhdr));
}


/*
 * dapli_tavor_cq_wqhdr_remove
 */
static void
dapli_tavor_cq_wqhdr_remove(ib_cq_handle_t cq, dapls_tavor_workq_hdr_t *wqhdr)
{
	DAPL_HASH_DATA	curr;
	DAPL_HASH_KEY	key;
	size_t		size = 0;

	/* dapl_os_assert(MUTEX_HELD(&cq->cq_wrid_wqhdr_lock)); */

	/* Remove "wqhdr" from the work queue header list on "cq" */

	key = (DAPL_HASH_KEY)(((uint64_t)wqhdr->wq_send_or_recv << 32) |
	    wqhdr->wq_qpn);

	(void) dapls_hash_remove(cq->cq_wrid_wqhdr_list, key,  &curr);

	size = (sizeof (dapls_tavor_workq_hdr_t) + 0x7) & ~0x7;
	if (wqhdr->wq_wrid_lock && (!wqhdr->wq_wrid_lock->wrl_on_srq)) {
		dapl_os_lock_destroy(&wqhdr->wq_wrid_lock->wrl_lock);
		size += sizeof (dapls_tavor_wrid_lock_t);
	}

	/* Free the memory associated with "wqhdr" */
	dapl_os_free(wqhdr, size);
}

/*
 * dapls_tavor_srq_wrid_resize() is called to resize the wridlist
 * associated with SRQS as a result of dat_srq_resize().
 *
 * Returns: DAT_TRUE if successful, otherwise DAT_FALSE
 */
DAT_BOOLEAN
dapls_tavor_srq_wrid_resize(ib_srq_handle_t srq_handle, uint32_t new_size)
{
	dapls_tavor_wrid_list_hdr_t	*wridlist;
	dapls_tavor_wrid_entry_t	*old_wl_wre;
	dapls_tavor_wrid_entry_t	*new_wl_wre;
	uint32_t			*old_wl_freel;
	uint32_t			*new_wl_freel;
	uint32_t			old_size;
	uint32_t			idx;
	uint32_t			prev_idx;
	uint32_t			i;

	wridlist = srq_handle->srq_wridlist;

	if (wridlist == NULL) {
		return (DAT_FALSE);
	}
	dapl_os_assert(wridlist->wl_srq_en);

	dapl_os_lock(&wridlist->wl_lock->wrl_lock);

	old_wl_wre = wridlist->wl_wre;
	old_wl_freel = wridlist->wl_free_list;
	old_size = wridlist->wl_size;

	new_wl_wre = (dapls_tavor_wrid_entry_t *)dapl_os_alloc(new_size *
	    sizeof (dapls_tavor_wrid_entry_t));
	if (new_wl_wre == NULL) {
		goto bail;
	}
	new_wl_freel = dapl_os_alloc(new_size * sizeof (uint32_t));
	if (new_wl_freel == NULL) {
		goto bail;
	}
	/*
	 * we just need to copy the old WREs to the new array. Since the
	 * descriptors are relatively addressed the descriptor to index
	 * mapping doesn't change.
	 */
	(void) dapl_os_memcpy(&new_wl_wre[0], &old_wl_wre[0],
	    old_size * sizeof (dapls_tavor_wrid_entry_t));
	/*
	 * Copy the old free list to the new one
	 */
	idx = wridlist->wl_freel_head;
	for (i = 0; i < wridlist->wl_freel_entries; i++) {
		new_wl_freel[i] = old_wl_freel[idx];
		idx = (idx + 1) % old_size;
	}
	/*
	 * Add the new entries in wl_wre to the new free list
	 */
	idx = wridlist->wl_freel_entries;
	new_wl_freel[idx] = wridlist->wl_srq_desc_addr + old_size *
	    wridlist->wl_srq_wqesz;
	prev_idx = idx;
	idx = (idx + 1) % new_size;
	for (i = 0; i < new_size - old_size - 1; i++) {
		new_wl_freel[idx] = new_wl_freel[prev_idx] +
		    wridlist->wl_srq_wqesz;
		prev_idx = idx;
		idx = (idx + 1) % new_size;
	}
	wridlist->wl_size = new_size;
	wridlist->wl_wre = new_wl_wre;
	wridlist->wl_free_list = new_wl_freel;
	wridlist->wl_freel_head = 0;
	wridlist->wl_freel_tail = idx;
	wridlist->wl_freel_entries = wridlist->wl_freel_entries + new_size -
	    old_size;

	dapl_os_unlock(&wridlist->wl_lock->wrl_lock);

	if (old_wl_wre) {
		dapl_os_free(old_wl_wre, old_size *
		    sizeof (dapls_tavor_wrid_entry_t));
	}
	if (old_wl_freel) {
		dapl_os_free(old_wl_freel, old_size * sizeof (uint32_t));
	}
	return (DAT_TRUE);
bail:
	dapl_os_unlock(&wridlist->wl_lock->wrl_lock);
	if (new_wl_wre) {
		dapl_os_free(new_wl_wre, new_size *
		    sizeof (dapls_tavor_wrid_entry_t));
	}
	return (DAT_FALSE);
}
