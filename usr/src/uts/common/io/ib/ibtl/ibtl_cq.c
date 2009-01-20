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

#include <sys/ib/ibtl/impl/ibtl.h>

/*
 * ibtl_cq.c
 *	These routines implement (most of) the verbs related to
 *	Completion Queues.
 */

/*
 * Globals
 */

static char ibtf_cq[] = "ibtl_cq";

/*
 * This file contains code for the  TI CQ calls
 */

/*
 * ibt_alloc_cq_sched() - Reserve CQ scheduling class resources
 *
 *	chan	    - IBT Channel Handle.
 *	load	    - Expected CQ load in class, 0 = unspecified
 *      sched_hdl_p - Returned scheduling handle.
 */
ibt_status_t
ibt_alloc_cq_sched(ibt_hca_hdl_t hca_hdl, ibt_cq_sched_attr_t *attr,
    ibt_sched_hdl_t *sched_hdl_p)
{
	ibc_cq_handler_attr_t	handler_attrs;
	ibt_cq_priority_t	priority;

	IBTF_DPRINTF_L3(ibtf_cq, "ibt_alloc_cq_sched(%p, %p, %p)",
	    hca_hdl, attr, sched_hdl_p);

	/* Validate and Convert the IBT CQ priority */
	priority = attr->cqs_priority;

	if ((priority < IBT_CQ_DEFAULT) || (priority > IBT_CQ_PRI_16)) {
		return (IBT_CQ_INVALID_PRIORITY);
	}


	/*
	 * Do we need to check for valid range for load ? What's the valid
	 * range?
	 */
	*sched_hdl_p = NULL;	/* Function not implemented fully yet */

	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_cq_sched(
	    IBTL_HCA2CIHCA(hca_hdl), attr->cqs_flags, &handler_attrs));
}


/*
 * ibt_free_cq_sched() - Free CQ scheduling class resources
 *
 *	chan	  - IBT Channel Handle.
 *      sched_hdl - Scheduling handle returned from ibt_alloc_cq_sched.
 *	load	  - CQ load being removed.
 */
ibt_status_t
ibt_free_cq_sched(ibt_hca_hdl_t hca_hdl, ibt_sched_hdl_t sched_hdl,
    uint_t load)
{
	ibt_cq_handler_id_t	handler_id = 0;

	IBTF_DPRINTF_L3(ibtf_cq, "ibt_free_cq_sched(%p, %d, %p)",
	    hca_hdl, sched_hdl, load);

	/*
	 * Function not fully implemented should get handler ID from
	 * sched_hdl.
	 */
	return (IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_free_cq_sched(
	    IBTL_HCA2CIHCA(hca_hdl), handler_id));
}


/*
 *
 * ibt_alloc_cq() - Allocate a completion queue
 */
ibt_status_t
ibt_alloc_cq(ibt_hca_hdl_t hca_hdl, ibt_cq_attr_t *cq_attr,
    ibt_cq_hdl_t *ibt_cq_p, uint32_t *real_size)
{
	ibt_status_t 		status;
	ibt_cq_hdl_t		ibt_cq;

	IBTF_DPRINTF_L3(ibtf_cq, "ibt_alloc_cq(%p, %p)",
	    hca_hdl, cq_attr);


	ibt_cq = kmem_zalloc(sizeof (struct ibtl_cq_s), KM_SLEEP);
	*ibt_cq_p = ibt_cq;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibt_cq->cq_in_thread))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibt_cq->cq_ibc_cq_hdl))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibt_cq->cq_hca))
	/*
	 * Set the following values before creating CI CQ, to avoid race
	 * conditions on async callback.
	 */
	ibt_cq->cq_hca = hca_hdl;

	ibtl_qp_flow_control_enter();
	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_cq(
	    IBTL_HCA2CIHCA(hca_hdl), ibt_cq, cq_attr, &ibt_cq->cq_ibc_cq_hdl,
	    real_size);
	ibtl_qp_flow_control_exit();

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_cq, "ibt_alloc_cq: "
		    "CI CQ handle allocation failed: status = %d", status);
		kmem_free(ibt_cq, sizeof (struct ibtl_cq_s));
		*ibt_cq_p = NULL;
		return (status);
	}

	if (cq_attr->cq_flags & IBT_CQ_HANDLER_IN_THREAD) {
		ibt_cq->cq_in_thread = 1;
		/* We may want additional CQ threads now. */
		ibtl_another_cq_handler_in_thread();
	}
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibt_cq->cq_in_thread))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibt_cq->cq_ibc_cq_hdl))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibt_cq->cq_hca))

	mutex_init(&ibt_cq->cq_mutex, NULL, MUTEX_DEFAULT, NULL);

	/* Update the cq resource count */
	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_cq_cnt++;
	mutex_exit(&hca_hdl->ha_mutex);

	return (IBT_SUCCESS);
}


/*
 * ibt_free_cq() - Free a completion queue
 *
 */
ibt_status_t
ibt_free_cq(ibt_cq_hdl_t ibt_cq)
{
	ibt_status_t	status;
	ibtl_hca_t	*ibt_hca = ibt_cq->cq_hca;

	IBTF_DPRINTF_L3(ibtf_cq, "ibt_free_cq(%p)", ibt_cq);

	ibtl_free_cq_check(ibt_cq);

	status = ((IBTL_CQ2CIHCAOPS_P(ibt_cq))->ibc_free_cq)
	    (IBTL_CQ2CIHCA(ibt_cq), ibt_cq->cq_ibc_cq_hdl);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_cq, "ibt_free_cq: "
		    "CI CQ handle de-allocation failed: status = %d", status);
		return (status);
	}

	/* mutex_destroy(&ibt_cq->cq_mutex); */
	ibtl_free_cq_async_check(ibt_cq);

	/* Update the cq resource count */
	mutex_enter(&ibt_hca->ha_mutex);
	ibt_hca->ha_cq_cnt--;
	mutex_exit(&ibt_hca->ha_mutex);

	return (status);
}


/*
 * ibt_query_cq() - Returns the size of the cq
 */
ibt_status_t
ibt_query_cq(ibt_cq_hdl_t ibt_cq, uint32_t *entries_p, uint_t *count_p,
    uint_t *usec_p, ibt_cq_handler_id_t *hid_p)
{
	IBTF_DPRINTF_L3(ibtf_cq, "ibt_query_cq(%p)", ibt_cq);

	return (IBTL_CQ2CIHCAOPS_P(ibt_cq)->ibc_query_cq(IBTL_CQ2CIHCA(ibt_cq),
	    ibt_cq->cq_ibc_cq_hdl, entries_p, count_p, usec_p, hid_p));
}


/*
 *  ibt_resize_cq() - Change the size of a cq.
 */
ibt_status_t
ibt_resize_cq(ibt_cq_hdl_t ibt_cq, uint32_t new_sz, uint32_t *real_sz)
{
	IBTF_DPRINTF_L3(ibtf_cq, "ibt_resize_cq(%p, %d)", ibt_cq, new_sz);

	return (IBTL_CQ2CIHCAOPS_P(ibt_cq)->ibc_resize_cq(IBTL_CQ2CIHCA(ibt_cq),
	    ibt_cq->cq_ibc_cq_hdl, new_sz, real_sz));
}

ibt_status_t
ibt_modify_cq(ibt_cq_hdl_t ibt_cq, uint_t count, uint_t usec,
    ibt_cq_handler_id_t hid)
{
	IBTF_DPRINTF_L3(ibtf_cq, "ibt_modify_cq(%p, %d, %d, %d)", ibt_cq, count,
	    usec, hid);

	return (IBTL_CQ2CIHCAOPS_P(ibt_cq)->ibc_modify_cq(IBTL_CQ2CIHCA(ibt_cq),
	    ibt_cq->cq_ibc_cq_hdl, count, usec, hid));
}


/*
 * ibt_poll_cq()
 *      Poll the specified CQ for a work request (WR) completion. If a CQ
 *      contains a completed WR, the completed WR at the head of the CQ is
 *      returned.
 *
 *      ibt_cq                  The CQ handle.
 *
 *      work_completions        An array of work completions.
 *
 *      num_wc                  Size of the Work completion array. The
 *                              requested number of completions.
 *
 *      num_polled              The actual number of completions returned.
 *
 */
ibt_status_t
ibt_poll_cq(ibt_cq_hdl_t ibt_cq, ibt_wc_t *work_completions, uint_t num_wc,
    uint_t *num_polled)
{
	IBTF_DPRINTF_L4(ibtf_cq, "ibt_poll_cq(%p)", ibt_cq);

	return (IBTL_CQ2CIHCAOPS_P(ibt_cq)->ibc_poll_cq(IBTL_CQ2CIHCA(ibt_cq),
	    ibt_cq->cq_ibc_cq_hdl, work_completions, num_wc, num_polled));
}

_NOTE(SCHEME_PROTECTS_DATA("client managed", ibtl_cq_s::cq_clnt_private))

/*
 * ibt_set_cq_private - Sets the private data on a given CQ
 *
 *      ibt_cq          The ibt_cq_hdl_t of the allocated CQ.
 *      clnt_private    The client private data.
 */
void
ibt_set_cq_private(ibt_cq_hdl_t ibt_cq, void *clnt_private)
{
	ibt_cq->cq_clnt_private = clnt_private;
}


/*
 * ibt_get_cq_private - Retrieves the private data for a given CQ
 *
 *      ibt_cq          The ibt_cq_hdl_t of the allocated CQ.
 */
void *
ibt_get_cq_private(ibt_cq_hdl_t ibt_cq)
{
	return (ibt_cq->cq_clnt_private);
}
