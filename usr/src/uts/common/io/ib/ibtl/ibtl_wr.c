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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ib/ibtl/impl/ibtl.h>

/*
 * ibtl_wr.c
 *	These routines simply pass the request to the proper HCA.
 */

/*
 * Globals
 */
static char ibtf_wr[] = "ibtl_wr";

/*
 * Function:
 *	ibt_post_send
 * Input:
 *	chan	- QP.
 *	wr_list	- Address of array[size] of work requests.
 *	size	- Number of work requests.
 * Output:
 *	posted	- Address to return the number of work requests
 *		  successfully posted.  May be NULL.
 * Description:
 *	Post one or more send work requests to the channel.
 */

ibt_status_t
ibt_post_send(ibt_channel_hdl_t chan, ibt_send_wr_t *wr_list, uint_t size,
    uint_t *posted)
{
	IBTF_DPRINTF_L4(ibtf_wr, "ibt_post_send(%p, %p, %d)",
	    chan, wr_list, size);

	return (IBTL_CHAN2CIHCAOPS_P(chan)->ibc_post_send(IBTL_CHAN2CIHCA(chan),
	    chan->ch_qp.qp_ibc_qp_hdl, wr_list, size, posted));
}

/*
 * Function:
 *	ibt_post_recv
 * Input:
 *	chan	- QP.
 *	wr_list	- Address of array[size] of work requests.
 *	size	- Number of work requests.
 * Output:
 *	posted	- Address to return the number of work requests
 *		  successfully posted.  May be NULL.
 * Description:
 *	Post one or more receive work requests to the channel.
 */

ibt_status_t
ibt_post_recv(ibt_channel_hdl_t chan, ibt_recv_wr_t *wr_list, uint_t size,
    uint_t *posted)
{
	IBTF_DPRINTF_L4(ibtf_wr, "ibt_post_recv(%p, %p, %d)",
	    chan, wr_list, size);

	return (IBTL_CHAN2CIHCAOPS_P(chan)->ibc_post_recv(IBTL_CHAN2CIHCA(chan),
	    chan->ch_qp.qp_ibc_qp_hdl, wr_list, size, posted));
}
