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

/*
 * ibtl_mcg.c
 *
 * This file contains Transport API functions that implement the
 * verbs related to Multicast Groups.  These are only applicable
 * for UD channels.
 */

#include <sys/ib/ibtl/impl/ibtl.h>

static char ibtl_mcg[] = "ibtl_mcg";

/*
 * Function:
 *	ibt_attach_mcg
 * Input:
 *	ud_chan		A channel handle returned from ibt_alloc_ud_channel().
 *			This is the UD channel handle, that is to be used to
 *			receive data sent to the multicast group.
 *
 *	mcg_info	A pointer to an ibt_mcg_info_t struct returned from an
 *			ibt_join_mcg() or ibt_query_mcg() call, that identifies
 *			the multicast group to attach this channel to.
 * Output:
 *	none.
 * Returns:
 *	IBT_CHAN_SRV_TYPE_INVALID
 *	Return value as of ibc_attach_mcg() call.
 * Description:
 *	Attaches a UD channel to the specified multicast group.
 */
ibt_status_t
ibt_attach_mcg(ibt_channel_hdl_t ud_chan, ibt_mcg_info_t *mcg_info)
{
	IBTF_DPRINTF_L3(ibtl_mcg, "ibt_attach_mcg(%p, %p)", ud_chan, mcg_info);

	/* re-direct the call to CI's call */
	return (IBTL_CHAN2CIHCAOPS_P(ud_chan)->ibc_attach_mcg(
	    IBTL_CHAN2CIHCA(ud_chan), ud_chan->ch_qp.qp_ibc_qp_hdl,
	    mcg_info->mc_adds_vect.av_dgid, mcg_info->mc_adds_vect.av_dlid));
}


/*
 * Function:
 *	ibt_detach_mcg
 * Input:
 *	ud_chan		A channel handle returned from ibt_alloc_ud_channel().
 *			This is the UD channel handle, that is to be used to
 *			receive data sent to the multicast group.
 *
 *	mcg_info	A pointer to an ibt_mcg_info_t struct returned from an
 *			ibt_join_mcg() or ibt_query_mcg() call, that identifies
 *			the multicast group to detach this channel from.
 * Output:
 *	none.
 * Returns:
 *	IBT_CHAN_SRV_TYPE_INVALID
 *	Return value as of ibc_detach_mcg() call.
 * Description:
 *	Detach the specified UD channel from the specified multicast group.
 */
ibt_status_t
ibt_detach_mcg(ibt_channel_hdl_t ud_chan, ibt_mcg_info_t *mcg_info)
{
	IBTF_DPRINTF_L3(ibtl_mcg, "ibt_detach_mcg(%p, %p", ud_chan, mcg_info);

	/* re-direct the call to CI's call */
	return (IBTL_CHAN2CIHCAOPS_P(ud_chan)->ibc_detach_mcg(
	    IBTL_CHAN2CIHCA(ud_chan), ud_chan->ch_qp.qp_ibc_qp_hdl,
	    mcg_info->mc_adds_vect.av_dgid, mcg_info->mc_adds_vect.av_dlid));
}
