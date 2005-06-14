/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ib/ibtl/impl/ibtl.h>

/*
 * ibtl_srq.c
 *	These routines implement (most of) the verbs related to
 *	Shared Receive Queues.
 */

/*
 * Globals
 */

static char ibtf_srq[] = "ibtl_srq";

/*
 * This file contains code for the TI SRQ calls
 */

/*
 *
 * ibt_alloc_srq() - Allocate a completion queue
 */
ibt_status_t
ibt_alloc_srq(ibt_hca_hdl_t hca_hdl, ibt_srq_flags_t flags, ibt_pd_hdl_t pd,
    ibt_srq_sizes_t *srq_sizes, ibt_srq_hdl_t *ibt_srq_p,
    ibt_srq_sizes_t *real_sizes_p)
{
	ibt_status_t 		status;
	ibt_srq_hdl_t		ibt_srq;

	IBTF_DPRINTF_L3(ibtf_srq, "ibt_alloc_srq(%p, %p)",
	    hca_hdl, srq_sizes);

	ibt_srq = kmem_zalloc(sizeof (struct ibtl_srq_s), KM_SLEEP);
	*ibt_srq_p = ibt_srq;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibt_srq->srq_ibc_srq_hdl))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(ibt_srq->srq_hca))
	/*
	 * Set the following values before creating CI SRQ, to avoid race
	 * conditions on async callback.
	 */
	ibt_srq->srq_hca = hca_hdl;

	status = IBTL_HCA2CIHCAOPS_P(hca_hdl)->ibc_alloc_srq(
	    IBTL_HCA2CIHCA(hca_hdl), flags, ibt_srq, pd, srq_sizes,
	    &ibt_srq->srq_ibc_srq_hdl, real_sizes_p);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_srq, "ibt_alloc_srq: "
		    "CI SRQ handle allocation failed: status = %d", status);
		kmem_free(ibt_srq, sizeof (struct ibtl_srq_s));
		*ibt_srq_p = NULL;
		return (status);
	}

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibt_srq->srq_ibc_srq_hdl))
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(ibt_srq->srq_hca))

	/* Update the srq resource count */
	mutex_enter(&hca_hdl->ha_mutex);
	hca_hdl->ha_srq_cnt++;
	mutex_exit(&hca_hdl->ha_mutex);

	return (IBT_SUCCESS);
}


/*
 * ibt_free_srq() - Free a shared receive queue
 *
 */
ibt_status_t
ibt_free_srq(ibt_srq_hdl_t ibt_srq)
{
	ibt_status_t	status;
	ibtl_hca_t	*ibt_hca = ibt_srq->srq_hca;

	IBTF_DPRINTF_L3(ibtf_srq, "ibt_free_srq(%p)", ibt_srq);

	status = ((IBTL_SRQ2CIHCAOPS_P(ibt_srq))->ibc_free_srq)
	    (IBTL_SRQ2CIHCA(ibt_srq), ibt_srq->srq_ibc_srq_hdl);

	if (status != IBT_SUCCESS) {
		IBTF_DPRINTF_L2(ibtf_srq, "ibt_free_srq: "
		    "CI SRQ handle de-allocation failed: status = %d", status);
		return (status);
	}

	ibtl_free_srq_async_check(ibt_srq);

	/* Update the srq resource count */
	mutex_enter(&ibt_hca->ha_mutex);
	ibt_hca->ha_srq_cnt--;
	mutex_exit(&ibt_hca->ha_mutex);

	return (status);
}


/*
 * ibt_query_srq() - Returns the size of the srq
 */
ibt_status_t
ibt_query_srq(ibt_srq_hdl_t ibt_srq, ibt_pd_hdl_t *pd_p,
    ibt_srq_sizes_t *sizes_p, uint_t *limit)
{
	IBTF_DPRINTF_L3(ibtf_srq, "ibt_query_srq(%p)", ibt_srq);

	return (IBTL_SRQ2CIHCAOPS_P(ibt_srq)->ibc_query_srq(
	    IBTL_SRQ2CIHCA(ibt_srq), ibt_srq->srq_ibc_srq_hdl, pd_p,
	    sizes_p, limit));
}


/*
 *  ibt_resize_srq() - Change the size of a srq.
 */
ibt_status_t
ibt_modify_srq(ibt_srq_hdl_t ibt_srq, ibt_srq_modify_flags_t flags,
    uint_t size, uint_t limit, uint_t *real_size_p)
{
	IBTF_DPRINTF_L3(ibtf_srq, "ibt_modify_srq(%p, %d, %d, %d)",
	    ibt_srq, flags, size, limit);

	return (IBTL_SRQ2CIHCAOPS_P(ibt_srq)->ibc_modify_srq(
	    IBTL_SRQ2CIHCA(ibt_srq), ibt_srq->srq_ibc_srq_hdl,
	    flags, size, limit, real_size_p));
}


_NOTE(SCHEME_PROTECTS_DATA("client managed", ibtl_srq_s::srq_clnt_private))

/*
 * ibt_set_srq_private - Sets the private data on a given SRQ
 *
 *      ibt_srq          The ibt_srq_hdl_t of the allocated SRQ.
 *      clnt_private    The client private data.
 */
void
ibt_set_srq_private(ibt_srq_hdl_t ibt_srq, void *clnt_private)
{
	ibt_srq->srq_clnt_private = clnt_private;
}


/*
 * ibt_get_srq_private - Retrieves the private data for a given SRQ
 *
 *      ibt_srq          The ibt_srq_hdl_t of the allocated SRQ.
 */
void *
ibt_get_srq_private(ibt_srq_hdl_t ibt_srq)
{
	return (ibt_srq->srq_clnt_private);
}

/*
 * Function:
 *	ibt_post_srq
 * Input:
 *	srq	- SRQ.
 *	wr_list	- Address of array[size] of work requests.
 *	size	- Number of work requests.
 * Output:
 *	posted	- Address to return the number of work requests
 *		  successfully posted.  May be NULL.
 * Description:
 *	Post one or more receive work requests to the SRQ.
 */

ibt_status_t
ibt_post_srq(ibt_srq_hdl_t srq, ibt_recv_wr_t *wr_list, uint_t size,
    uint_t *posted)
{
	IBTF_DPRINTF_L4(ibtf_srq, "ibt_post_srq(%p, %p, %d)",
	    srq, wr_list, size);

	return (IBTL_SRQ2CIHCAOPS_P(srq)->ibc_post_srq(IBTL_SRQ2CIHCA(srq),
	    srq->srq_ibc_srq_hdl, wr_list, size, posted));
}
