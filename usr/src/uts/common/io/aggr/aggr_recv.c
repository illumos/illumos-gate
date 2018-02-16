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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 OmniTI Computer Consulting, Inc  All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

/*
 * IEEE 802.3ad Link Aggregation - Receive
 *
 * Implements the collector function.
 * Manages the RX resources exposed by a link aggregation group.
 */

#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/byteorder.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>

static void
aggr_mac_rx(mac_handle_t lg_mh, mac_resource_handle_t mrh, mblk_t *mp)
{
	if (mrh == NULL) {
		mac_rx(lg_mh, mrh, mp);
	} else {
		aggr_pseudo_rx_ring_t	*ring = (aggr_pseudo_rx_ring_t *)mrh;
		mac_rx_ring(lg_mh, ring->arr_rh, mp, ring->arr_gen);
	}
}

void
aggr_recv_lacp(aggr_port_t *port, mac_resource_handle_t mrh, mblk_t *mp)
{
	aggr_grp_t *grp = port->lp_grp;

	/* In promiscuous mode, pass copy of packet up. */
	if (grp->lg_promisc) {
		mblk_t *nmp = copymsg(mp);

		if (nmp != NULL)
			aggr_mac_rx(grp->lg_mh, mrh, nmp);
	}

	aggr_lacp_rx_enqueue(port, mp);
}

/*
 * Callback function invoked by MAC service module when packets are
 * made available by a MAC port, both in promisc_on mode and not.
 */
/* ARGSUSED */
static void
aggr_recv_path_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	aggr_port_t *port = (aggr_port_t *)arg;
	aggr_grp_t *grp = port->lp_grp;

	if (grp->lg_lacp_mode == AGGR_LACP_OFF) {
		aggr_mac_rx(grp->lg_mh, mrh, mp);
	} else {
		mblk_t *cmp, *last, *head;
		struct ether_header *ehp;
		uint16_t sap;

		/* filter out slow protocol packets (LACP & Marker) */
		last = NULL;
		head = cmp = mp;
		while (cmp != NULL) {
			if (MBLKL(cmp) < sizeof (struct ether_header)) {
				/* packet too short */
				if (head == cmp) {
					/* no packets accumulated */
					head = cmp->b_next;
					cmp->b_next = NULL;
					freemsg(cmp);
					cmp = head;
				} else {
					/* send up accumulated packets */
					last->b_next = NULL;
					if (port->lp_collector_enabled) {
						aggr_mac_rx(grp->lg_mh, mrh,
						    head);
					} else {
						freemsgchain(head);
					}
					head = cmp->b_next;
					cmp->b_next = NULL;
					freemsg(cmp);
					cmp = head;
					last = NULL;
				}
				continue;
			}
			ehp = (struct ether_header *)cmp->b_rptr;

			sap = ntohs(ehp->ether_type);
			if (sap == ETHERTYPE_SLOW) {
				/*
				 * LACP or Marker packet. Send up pending
				 * chain, and send LACP/Marker packet
				 * to LACP subsystem.
				 */
				if (head == cmp) {
					/* first packet of chain */
					ASSERT(last == NULL);
					head = cmp->b_next;
					cmp->b_next = NULL;
					aggr_recv_lacp(port, mrh, cmp);
					cmp = head;
				} else {
					/* previously accumulated packets */
					ASSERT(last != NULL);
					/* send up non-LACP packets */
					last->b_next = NULL;
					if (port->lp_collector_enabled) {
						aggr_mac_rx(grp->lg_mh, mrh,
						    head);
					} else {
						freemsgchain(head);
					}
					/* unlink and pass up LACP packets */
					head = cmp->b_next;
					cmp->b_next = NULL;
					aggr_recv_lacp(port, mrh, cmp);
					cmp = head;
					last = NULL;
				}
			} else {
				last = cmp;
				cmp = cmp->b_next;
			}
		}
		if (head != NULL) {
			if (port->lp_collector_enabled)
				aggr_mac_rx(grp->lg_mh, mrh, head);
			else
				freemsgchain(head);
		}
	}
}

void
aggr_recv_cb(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	aggr_recv_path_cb(arg, mrh, mp, loopback);
}
