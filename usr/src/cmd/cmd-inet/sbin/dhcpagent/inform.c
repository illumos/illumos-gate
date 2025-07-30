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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * INFORM_SENT state of the client state machine.
 */

#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <dhcpmsg.h>

#include "agent.h"
#include "states.h"
#include "interface.h"
#include "packet.h"

static boolean_t stop_informing(dhcp_smach_t *, unsigned int);

/*
 * dhcp_inform(): sends an INFORM packet and sets up reception for an ACK
 *
 *   input: dhcp_smach_t *: the state machine to use
 *  output: void
 *    note: the INFORM cannot be sent successfully if the interface
 *	    does not have an IP address (this is mostly an issue for IPv4).
 *	    We switch into INFORM_SENT state before sending the packet so
 *	    that the packet-sending subsystem uses regular sockets and sets
 *	    the source address.  (See set_smach_state.)
 */

void
dhcp_inform(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t		*dpkt;

	if (!set_smach_state(dsmp, INFORM_SENT))
		goto failed;

	if (dsmp->dsm_isv6) {
		dpkt = init_pkt(dsmp, DHCPV6_MSG_INFO_REQ);

		/* Add required Option Request option */
		(void) add_pkt_prl(dpkt, dsmp);
		dsmp->dsm_server = ipv6_all_dhcp_relay_and_servers;
		(void) send_pkt_v6(dsmp, dpkt, dsmp->dsm_server,
		    stop_informing, DHCPV6_INF_TIMEOUT, DHCPV6_INF_MAX_RT);
	} else {
		ipaddr_t server;

		/*
		 * Assemble a DHCPREQUEST packet, without the Server ID option.
		 * Fill in ciaddr, since we know this.  dsm_server will be set
		 * to the server's IP address, which will be the broadcast
		 * address if we don't know it.  The max DHCP message size
		 * option is set to the interface max, minus the size of the
		 * UDP and IP headers.
		 */

		dpkt = init_pkt(dsmp, INFORM);
		IN6_V4MAPPED_TO_INADDR(&dsmp->dsm_lif->lif_v6addr,
		    &dpkt->pkt->ciaddr);

		(void) add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE,
		    htons(dsmp->dsm_lif->lif_pif->pif_mtu -
		    sizeof (struct udpiphdr)));
		if (class_id_len != 0) {
			(void) add_pkt_opt(dpkt, CD_CLASS_ID, class_id,
			    class_id_len);
		}
		(void) add_pkt_prl(dpkt, dsmp);
		(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

		IN6_V4MAPPED_TO_IPADDR(&dsmp->dsm_server, server);
		if (!send_pkt(dsmp, dpkt, server, stop_informing)) {
			dhcpmsg(MSG_ERROR, "dhcp_inform: send_pkt failed");
			goto failed;
		}
	}

	return;

failed:
	dsmp->dsm_dflags |= DHCP_IF_FAILED;
	ipc_action_finish(dsmp, DHCP_IPC_E_INT);
	(void) set_smach_state(dsmp, INIT);
}

/*
 * stop_informing(): decides when to stop retransmitting Information-Requests
 *
 *   input: dhcp_smach_t *: the state machine Info-Reqs are being sent from
 *	    unsigned int: the number of requests sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

/* ARGSUSED */
static boolean_t
stop_informing(dhcp_smach_t *dsmp, unsigned int n_requests)
{
	return (B_FALSE);
}
