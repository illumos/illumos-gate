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
 *
 * INIT_REBOOT state of the DHCP client state machine.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <dhcpmsg.h>
#include <string.h>

#include "agent.h"
#include "packet.h"
#include "states.h"
#include "util.h"
#include "interface.h"
#include "defaults.h"

static stop_func_t	stop_init_reboot;

/*
 * dhcp_init_reboot(): attempts to reuse a cached configuration on an interface
 *
 *   input: struct ifslist *: the interface to reuse the configuration on
 *  output: void
 */

void
dhcp_init_reboot(struct ifslist *ifsp)
{
	dhcp_pkt_t		*dpkt;
	const char		*reqhost;
	char			hostfile[PATH_MAX + 1];

	dhcpmsg(MSG_VERBOSE,  "%s has cached configuration - entering "
	    "INIT_REBOOT", ifsp->if_name);

	ifsp->if_state = INIT_REBOOT;

	if (register_acknak(ifsp) == 0) {

		ifsp->if_state   = INIT;
		ifsp->if_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(ifsp, DHCP_IPC_E_MEMORY);
		async_finish(ifsp);

		dhcpmsg(MSG_ERROR, "dhcp_init_reboot: cannot register to "
		    "collect ACK/NAK packets, reverting to INIT on %s",
		    ifsp->if_name);
		return;
	}

	/*
	 * assemble DHCPREQUEST message.  The max dhcp message size
	 * option is set to the interface max, minus the size of the udp and
	 * ip headers.
	 */

	dpkt = init_pkt(ifsp, REQUEST);
	add_pkt_opt32(dpkt, CD_REQUESTED_IP_ADDR,
	    ifsp->if_ack->pkt->yiaddr.s_addr);

	add_pkt_opt32(dpkt, CD_LEASE_TIME, htonl(DHCP_PERM));
	add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE, htons(ifsp->if_max -
			sizeof (struct udpiphdr)));

	add_pkt_opt(dpkt, CD_CLASS_ID, class_id, class_id_len);
	add_pkt_opt(dpkt, CD_REQUEST_LIST, ifsp->if_prl, ifsp->if_prllen);

	/*
	 * Set CD_HOSTNAME option if REQUEST_HOSTNAME is set and a hostname
	 * is found in /etc/hostname.<ifname>
	 */
	if (df_get_bool(ifsp->if_name, DF_REQUEST_HOSTNAME)) {
		dhcpmsg(MSG_DEBUG, "dhcp_selecting: DF_REQUEST_HOSTNAME");
		(void) snprintf(hostfile, sizeof (hostfile), "/etc/hostname.%s",
		    ifsp->if_name);

		if ((reqhost = iffile_to_hostname(hostfile)) != NULL) {
			dhcpmsg(MSG_DEBUG, "dhcp_selecting: host %s", reqhost);
			if ((ifsp->if_reqhost = strdup(reqhost)) != NULL)
				add_pkt_opt(dpkt, CD_HOSTNAME, ifsp->if_reqhost,
				    strlen(ifsp->if_reqhost));
			else
				dhcpmsg(MSG_WARNING, "dhcp_selecting: cannot"
				    " allocate memory for host name option");
		}
	}

	add_pkt_opt(dpkt, CD_END, NULL, 0);

	(void) send_pkt(ifsp, dpkt, htonl(INADDR_BROADCAST), stop_init_reboot);
}

/*
 * stop_init_reboot(): decides when to stop retransmitting REQUESTs
 *
 *   input: struct ifslist *: the interface REQUESTs are being sent on
 *	    unsigned int: the number of REQUESTs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

static boolean_t
stop_init_reboot(struct ifslist *ifsp, unsigned int n_requests)
{
	if (n_requests >= DHCP_MAX_REQUESTS) {

		(void) unregister_acknak(ifsp);

		dhcpmsg(MSG_INFO, "no ACK/NAK to INIT_REBOOT REQUEST, "
		    "using remainder of existing lease on %s", ifsp->if_name);

		/*
		 * we already stuck our old ack in ifsp->if_ack and
		 * relativized the packet times, so we can just
		 * pretend that the server sent it to us and move to
		 * bound.  if that fails, fall back to selecting.
		 */

		if (dhcp_bound(ifsp, NULL) == 0)
			dhcp_selecting(ifsp);

		return (B_TRUE);
	}

	return (B_FALSE);
}
