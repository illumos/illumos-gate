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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <ipp/meters/meter_impl.h>

/*
 * Module : Time Sliding Window meter - tswtclmtr
 * Description
 * This module implements the metering part of RFC 2859. It accepts the
 * committed rate, peak rate and the window for a flow and determines
 * if the flow is within the committed/peak rate and assigns the appropriate
 * next action.
 * The meter provides an estimate of the running average bandwidth for the
 * flow over the specified window. It uses probability to benefit TCP flows
 * as it reduces the likelihood of dropping multiple packets within a TCP
 * window without adversely effecting UDP flows.
 */

int tswtcl_debug = 0;

/*
 * Given a packet and the tswtcl_data it belongs to, this routine meters the
 * ToS or DSCP for IPv4 and IPv6 resp. with the values configured for
 * the tswtcl_data.
 */
/* ARGSUSED */
int
tswtcl_process(mblk_t **mpp, tswtcl_data_t *tswtcl_data,
    ipp_action_id_t *next_action)
{
	ipha_t *ipha;
	hrtime_t now;
	ip6_t *ip6_hdr;
	uint32_t pkt_len;
	mblk_t *mp = *mpp;
	hrtime_t deltaT;
	uint64_t bitsinwin;
	uint32_t min = 0, additive, rnd;
	tswtcl_cfg_t *cfg_parms = tswtcl_data->cfg_parms;

	if (mp == NULL) {
		tswtcl0dbg(("tswtcl_process: null mp!\n"));
		atomic_inc_64(&tswtcl_data->epackets);
		return (EINVAL);
	}

	if (mp->b_datap->db_type != M_DATA) {
		if ((mp->b_cont != NULL) &&
		    (mp->b_cont->b_datap->db_type == M_DATA)) {
			mp = mp->b_cont;
		} else {
			tswtcl0dbg(("tswtcl_process: no data\n"));
			atomic_inc_64(&tswtcl_data->epackets);
			return (EINVAL);
		}
	}

	/* Figure out the ToS/Traffic Class and length from the message */
	if ((mp->b_wptr - mp->b_rptr) < IP_SIMPLE_HDR_LENGTH) {
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			tswtcl0dbg(("tswtcl_process: pullup error\n"));
			atomic_inc_64(&tswtcl_data->epackets);
			return (EINVAL);
		}
	}
	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		pkt_len = ntohs(ipha->ipha_length);
	} else {
		ip6_hdr = (ip6_t *)mp->b_rptr;
		pkt_len = ntohs(ip6_hdr->ip6_plen) +
		    ip_hdr_length_v6(mp, ip6_hdr);
	}

	/* Convert into bits */
	pkt_len <<= 3;

	/* Get current time */
	now = gethrtime();

	/* Update the avg_rate and win_front tswtcl_data */
	mutex_enter(&tswtcl_data->tswtcl_lock);

	/* avg_rate = bits/sec and window in msec */
	bitsinwin = ((uint64_t)tswtcl_data->avg_rate * cfg_parms->window /
	    1000) + pkt_len;

	deltaT = now - tswtcl_data->win_front + cfg_parms->nsecwindow;

	tswtcl_data->avg_rate = (uint64_t)bitsinwin * METER_SEC_TO_NSEC /
	    deltaT;
	tswtcl_data->win_front = now;

	if (tswtcl_data->avg_rate <= cfg_parms->committed_rate) {
		*next_action = cfg_parms->green_action;
	} else if (tswtcl_data->avg_rate <= cfg_parms->peak_rate) {
		/*
		 * Compute the probability:
		 *
		 * p0 = (avg_rate - committed_rate) / avg_rate
		 *
		 * Yellow with probability p0
		 * Green with probability (1 - p0)
		 *
		 */
		uint32_t aminusc;

		/* Get a random no. betweeen 0 and avg_rate */
		(void) random_get_pseudo_bytes((uint8_t *)&additive,
		    sizeof (additive));
		rnd = min + (additive % (tswtcl_data->avg_rate - min + 1));

		aminusc = tswtcl_data->avg_rate - cfg_parms->committed_rate;
		if (aminusc >= rnd) {
			*next_action = cfg_parms->yellow_action;
		} else {
			*next_action = cfg_parms->green_action;
		}
	} else {
		/*
		 * Compute the probability:
		 *
		 * p1 = (avg_rate - peak_rate) / avg_rate
		 * p2 = (peak_rate - committed_rate) / avg_rate
		 *
		 * Red with probability p1
		 * Yellow with probability p2
		 * Green with probability (1 - (p1 + p2))
		 *
		 */
		uint32_t  aminusp;

		/* Get a random no. betweeen 0 and avg_rate */
		(void) random_get_pseudo_bytes((uint8_t *)&additive,
		    sizeof (additive));
		rnd = min + (additive % (tswtcl_data->avg_rate - min + 1));

		aminusp = tswtcl_data->avg_rate - cfg_parms->peak_rate;

		if (aminusp >= rnd) {
			*next_action = cfg_parms->red_action;
		} else if ((cfg_parms->pminusc + aminusp) >= rnd) {
			*next_action = cfg_parms->yellow_action;
		} else {
			*next_action = cfg_parms->green_action;
		}

	}
	mutex_exit(&tswtcl_data->tswtcl_lock);

	/* Update Stats */
	if (*next_action == cfg_parms->green_action) {
		atomic_inc_64(&tswtcl_data->green_packets);
		atomic_add_64(&tswtcl_data->green_bits, pkt_len);
	} else if (*next_action == cfg_parms->yellow_action) {
		atomic_inc_64(&tswtcl_data->yellow_packets);
		atomic_add_64(&tswtcl_data->yellow_bits, pkt_len);
	} else {
		ASSERT(*next_action == cfg_parms->red_action);
		atomic_inc_64(&tswtcl_data->red_packets);
		atomic_add_64(&tswtcl_data->red_bits, pkt_len);
	}
	return (0);
}
