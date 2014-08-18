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

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <ipp/dlcosmk/dlcosmk_impl.h>

/* Module to mark the 802.1d user priority field for a given packet */

/* Debug level */
int dlcosmk_debug = 0;

/*
 * Given a packet, this module marks the mblk with the appropriate b_band or
 * dl_max value so that the VLAN driver marks the outgoing frame with the
 * configured 802.1D user_priority value. For non-VLAN devices or for inbound
 * packets, this module does not do anything (i.e. the packet is processed by
 * the next action in the list, if present).
 * This module does not free any mblks or packets in case or errors.
 */

int
dlcosmk_process(mblk_t **mpp, dlcosmk_data_t *dlcosmk_data, uint32_t ill_index,
    ip_proc_t proc)
{
	ill_t *ill = NULL;
	mblk_t *mp;

	ASSERT((mpp != NULL) && (*mpp != NULL));
	mp = *mpp;

	/*
	 * The action module will receive an M_DATA or an M_CTL followed
	 * by an M_DATA. In the latter case skip the M_CTL.
	 */
	if (mp->b_datap->db_type != M_DATA) {
		if ((mp->b_cont == NULL) ||
		    (mp->b_cont->b_datap->db_type != M_DATA)) {
			atomic_inc_64(&dlcosmk_data->epackets);
			dlcosmk0dbg(("dlcosmk_process: no data\n"));
			return (EINVAL);
		}
	}

	/* Update global stats */
	atomic_inc_64(&dlcosmk_data->npackets);

	/*
	 * This should only be called for outgoing packets. For inbound, just
	 * send it along.
	 */
	if ((proc == IPP_LOCAL_IN) || (proc == IPP_FWD_IN)) {
		dlcosmk2dbg(("dlcosmk_process:cannot mark incoming packets\n"));
		atomic_inc_64(&dlcosmk_data->ipackets);
		return (0);
	}

	if ((ill_index == 0) ||
	    ((ill = ill_lookup_on_ifindex_global_instance(ill_index,
	    B_FALSE)) == NULL)) {
		dlcosmk2dbg(("dlcosmk_process:invalid ill index %u\n",
		    ill_index));
		atomic_inc_64(&dlcosmk_data->ipackets);
		return (0);
	}

	/*
	 * Check if the interface supports CoS marking. If not send it to the
	 * next action in the chain
	 */
	if (!(ill->ill_flags & ILLF_COS_ENABLED)) {
		dlcosmk2dbg(("dlcosmk_process:ill %u does not support CoS\n",
		    ill_index));
		atomic_inc_64(&dlcosmk_data->ipackets);
		ill_refrele(ill);
		return (0);
	}
	ill_refrele(ill);


	/*
	 * Mark the b_band for fastpath messages or dl_priority.dl_max for
	 * DL_UNITDATA_REQ messages. For, others just pass it along.
	 */
	switch (DB_TYPE(mp)) {
		case M_PROTO:
		case M_PCPROTO:
			{ 	/* DL_UNITDATA */
				dl_unitdata_req_t *dlur;
				dlur = (dl_unitdata_req_t *)mp->b_rptr;

				/* DL_UNITDATA message?? */
				if (dlur->dl_primitive == DL_UNITDATA_REQ) {
					dlur->dl_priority.dl_max =
					    dlcosmk_data->dl_max;
				} else {
					atomic_inc_64(&dlcosmk_data->ipackets);
				}
				break;
			}
		case M_DATA:
			/* fastpath message */
			mp->b_band = dlcosmk_data->b_band;
			break;
		default:
			atomic_inc_64(&dlcosmk_data->ipackets);
			break;
	}

	return (0);
}
