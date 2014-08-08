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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <ipp/meters/meter_impl.h>

/*
 * Module : Single or Two Rate Metering module - tokenmt
 * Description
 * This module implements the metering part of RFC 2698 & 2697. It accepts the
 * committed rate, peak rate (optional), committed burst and peak burst for a
 * flow and determines if the flow is within the cfgd. rates and assigns
 * next action appropriately..
 * If the peak rate is provided this acts as a two rate meter (RFC 2698), else
 * a single rate meter (RFC 2697). If this is a two rate meter, then
 * the outcome is either green, red or yellow. Else if this a single rate
 * meter and the peak burst size is not provided, the outcome is either
 * green or red.
 * Internally, it maintains 2 token buckets, Tc & Tp, each filled with
 * tokens equal to committed burst & peak burst respectively initially.
 * When a packet arrives, tokens in Tc or Tp are updated at the committed
 * or the peak rate up to a maximum of the committed or peak burst size.
 * If there are enough tokens in Tc, the packet is Green, else if there are
 * enough tokens in Tp, the packet is Yellow, else the packet is Red. In case
 * of Green and Yellow packets, Tc and/or Tp is updated accordingly.
 */

int tokenmt_debug = 0;

/* Updating tokens */
static void tokenmt_update_tokens(tokenmt_data_t *, hrtime_t);

/*
 * Given a packet and the tokenmt_data it belongs to, this routine meters the
 * ToS or DSCP for IPv4 and IPv6 resp. with the values configured for
 * the tokenmt_data.
 */
int
tokenmt_process(mblk_t **mpp, tokenmt_data_t *tokenmt_data,
    ipp_action_id_t *next_action)
{
	uint8_t dscp;
	ipha_t *ipha;
	ip6_t *ip6_hdr;
	uint32_t pkt_len;
	mblk_t *mp = *mpp;
	hrtime_t now;
	enum meter_colour colour;
	tokenmt_cfg_t *cfg_parms = tokenmt_data->cfg_parms;

	if (mp == NULL) {
		tokenmt0dbg(("tokenmt_process: null mp!\n"));
		atomic_inc_64(&tokenmt_data->epackets);
		return (EINVAL);
	}

	if (mp->b_datap->db_type != M_DATA) {
		if ((mp->b_cont != NULL) &&
		    (mp->b_cont->b_datap->db_type == M_DATA)) {
			mp = mp->b_cont;
		} else {
			tokenmt0dbg(("tokenmt_process: no data\n"));
			atomic_inc_64(&tokenmt_data->epackets);
			return (EINVAL);
		}
	}

	/* Figure out the ToS/Traffic Class and length from the message */
	if ((mp->b_wptr - mp->b_rptr) < IP_SIMPLE_HDR_LENGTH) {
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			tokenmt0dbg(("tokenmt_process: pullup error\n"));
			atomic_inc_64(&tokenmt_data->epackets);
			return (EINVAL);
		}
	}
	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) == IPV4_VERSION) {
		/* discard last 2 unused bits */
		dscp = ipha->ipha_type_of_service;
		pkt_len = ntohs(ipha->ipha_length);
	} else {
		ip6_hdr = (ip6_t *)mp->b_rptr;
		/* discard ECN bits */
		dscp = __IPV6_TCLASS_FROM_FLOW(ip6_hdr->ip6_vcf);
		pkt_len = ntohs(ip6_hdr->ip6_plen) +
		    ip_hdr_length_v6(mp, ip6_hdr);
	}

	/* Convert into bits */
	pkt_len <<= 3;

	now = gethrtime();

	mutex_enter(&tokenmt_data->tokenmt_lock);
	/* Update the token counts */
	tokenmt_update_tokens(tokenmt_data, now);

	/*
	 * Figure out the drop preced. for the pkt. Need to be careful here
	 * because if the mode is set to COLOUR_AWARE, then the dscp value
	 * is used regardless of whether it was explicitly set or not.
	 * If the value is defaulted to 000 (drop precd.) then the pkt
	 * will always be coloured RED.
	 */
	if (cfg_parms->tokenmt_type == SRTCL_TOKENMT) {
		if (!cfg_parms->colour_aware) {
			if (pkt_len <= tokenmt_data->committed_tokens) {
				tokenmt_data->committed_tokens -= pkt_len;
				*next_action = cfg_parms->green_action;
			} else if (pkt_len <= tokenmt_data->peak_tokens) {
				/*
				 * Can't do this if yellow_action is not
				 * configured.
				 */
				ASSERT(cfg_parms->yellow_action !=
				    TOKENMT_NO_ACTION);
				tokenmt_data->peak_tokens -= pkt_len;
				*next_action = cfg_parms->yellow_action;
			} else {
				*next_action = cfg_parms->red_action;
			}
		} else {
			colour = cfg_parms->dscp_to_colour[dscp >> 2];
			if ((colour == TOKENMT_GREEN) &&
			    (pkt_len <= tokenmt_data->committed_tokens)) {
				tokenmt_data->committed_tokens -= pkt_len;
				*next_action = cfg_parms->green_action;
			} else if (((colour == TOKENMT_GREEN) ||
			    (colour == TOKENMT_YELLOW)) &&
			    (pkt_len <= tokenmt_data->peak_tokens)) {
				/*
				 * Can't do this if yellow_action is not
				 * configured.
				 */
				ASSERT(cfg_parms->yellow_action !=
				    TOKENMT_NO_ACTION);
				tokenmt_data->peak_tokens -= pkt_len;
				*next_action = cfg_parms->yellow_action;
			} else {
				*next_action = cfg_parms->red_action;
			}
		}
	} else {
		if (!cfg_parms->colour_aware) {
			if (pkt_len > tokenmt_data->peak_tokens) {
				*next_action = cfg_parms->red_action;
			} else if (pkt_len > tokenmt_data->committed_tokens) {
				/*
				 * Can't do this if yellow_action is not
				 * configured.
				 */
				ASSERT(cfg_parms->yellow_action !=
				    TOKENMT_NO_ACTION);
				tokenmt_data->peak_tokens -= pkt_len;
				*next_action = cfg_parms->yellow_action;
			} else {
				tokenmt_data->committed_tokens -= pkt_len;
				tokenmt_data->peak_tokens -= pkt_len;
				*next_action = cfg_parms->green_action;
			}
		} else {
			colour = cfg_parms->dscp_to_colour[dscp >> 2];
			if ((colour == TOKENMT_RED) ||
			    (pkt_len > tokenmt_data->peak_tokens)) {
				*next_action = cfg_parms->red_action;
			} else if ((colour == TOKENMT_YELLOW) ||
			    (pkt_len > tokenmt_data->committed_tokens)) {
				/*
				 * Can't do this if yellow_action is not
				 * configured.
				 */
				ASSERT(cfg_parms->yellow_action !=
				    TOKENMT_NO_ACTION);
				tokenmt_data->peak_tokens -= pkt_len;
				*next_action = cfg_parms->yellow_action;
			} else {
				tokenmt_data->committed_tokens -= pkt_len;
				tokenmt_data->peak_tokens -= pkt_len;
				*next_action = cfg_parms->green_action;
			}
		}
	}
	mutex_exit(&tokenmt_data->tokenmt_lock);

	/* Update Stats */
	if (*next_action == cfg_parms->green_action) {
		atomic_inc_64(&tokenmt_data->green_packets);
		atomic_add_64(&tokenmt_data->green_bits, pkt_len);
	} else if (*next_action == cfg_parms->yellow_action) {
		atomic_inc_64(&tokenmt_data->yellow_packets);
		atomic_add_64(&tokenmt_data->yellow_bits, pkt_len);
	} else {
		ASSERT(*next_action == cfg_parms->red_action);
		atomic_inc_64(&tokenmt_data->red_packets);
		atomic_add_64(&tokenmt_data->red_bits, pkt_len);
	}

	return (0);
}

void
tokenmt_update_tokens(tokenmt_data_t *tokenmt_data, hrtime_t now)
{
	tokenmt_cfg_t *cfg_parms = (tokenmt_cfg_t *)tokenmt_data->cfg_parms;
	hrtime_t diff = now - tokenmt_data->last_seen;
	uint64_t tokens;

	switch (cfg_parms->tokenmt_type) {
		case SRTCL_TOKENMT:
				tokens = (cfg_parms->committed_rate * diff) /
				    METER_SEC_TO_NSEC;

				/*
				 * Add tokens at the committed rate to
				 * committed_tokens. If they are in excess of
				 * the committed burst, add the excess to
				 * peak_tokens, capped to peak_burst.
				 */
				if ((tokenmt_data->committed_tokens + tokens) >
				    cfg_parms->committed_burst) {
					tokens = tokenmt_data->committed_tokens
					    + tokens -
					    cfg_parms->committed_burst;
					tokenmt_data->committed_tokens =
					    cfg_parms->committed_burst;
					tokenmt_data->peak_tokens =
					    MIN(cfg_parms->peak_burst,
					    tokenmt_data->peak_tokens +
					    tokens);
				} else {
					tokenmt_data->committed_tokens +=
					    tokens;
				}
				break;
		case TRTCL_TOKENMT:
				/* Fill at the committed rate */
				tokens = (diff * cfg_parms->committed_rate) /
				    METER_SEC_TO_NSEC;
				tokenmt_data->committed_tokens =
				    MIN(cfg_parms->committed_burst,
				    tokenmt_data->committed_tokens + tokens);

				/* Fill at the peak rate */
				tokens = (diff * cfg_parms->peak_rate) /
				    METER_SEC_TO_NSEC;
				tokenmt_data->peak_tokens =
				    MIN(cfg_parms->peak_burst,
				    tokenmt_data->peak_tokens + tokens);
				break;
	}
	tokenmt_data->last_seen = now;
}
