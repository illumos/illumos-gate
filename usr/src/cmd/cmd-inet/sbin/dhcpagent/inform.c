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
 * Copyright (c) 1995-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * INFORM_SENT state of the client state machine.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <dhcpmsg.h>

#include "util.h"
#include "packet.h"
#include "interface.h"

/*
 * dhcp_inform(): sends an INFORM packet and sets up reception for an ACK
 *
 *   input: struct ifslist *: the interface to send the inform on, ...
 *  output: void
 *    note: the INFORM cannot be sent successfully if the interface
 *	    does not have an IP address
 */

void
dhcp_inform(struct ifslist *ifsp)
{
	dhcp_pkt_t		*dpkt;
	struct in_addr		*our_addr;
	struct ifreq		ifr;

	ifsp->if_state = INIT;

	/*
	 * fetch our IP address -- since we may not manage the
	 * interface, go fetch it with ioctl()
	 */

	(void) memset(&ifr, 0, sizeof (struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifsp->if_name, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(ifsp->if_sock_fd, SIOCGIFADDR, &ifr) == -1) {
		ifsp->if_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(ifsp, DHCP_IPC_E_INT);
		async_finish(ifsp);
		return;
	}

	/*
	 * the error handling here and in the check for IFF_UP below
	 * are handled different from most since it is the user who is
	 * at fault for the problem, not the machine.
	 */

	/* LINTED [ifr_addr is a sockaddr which will be aligned] */
	our_addr = &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	if (our_addr->s_addr == htonl(INADDR_ANY)) {
		dhcpmsg(MSG_WARNING, "dhcp_inform: INFORM attempted on "
		    "interface with no IP address");
		ipc_action_finish(ifsp, DHCP_IPC_E_NOIPIF);
		async_finish(ifsp);
		remove_ifs(ifsp);
		return;
	}

	if (ioctl(ifsp->if_sock_fd, SIOCGIFFLAGS, &ifr) == -1) {
		ifsp->if_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(ifsp, DHCP_IPC_E_INT);
		async_finish(ifsp);
		return;
	}

	if ((ifr.ifr_flags & IFF_UP) == 0) {
		dhcpmsg(MSG_WARNING, "dhcp_inform: INFORM attempted on downed "
		    "interface");
		ipc_action_finish(ifsp, DHCP_IPC_E_DOWNIF);
		async_finish(ifsp);
		remove_ifs(ifsp);
		return;
	}

	/*
	 * assemble a DHCPREQUEST packet, without the server id
	 * option.  fill in ciaddr, since we know this.  if_server
	 * will be set to the server's IP address, which will be the
	 * broadcast address if we don't know it.  The max dhcp message size
	 * option is set to the interface max, minus the size of the udp and
	 * ip headers.
	 */

	dpkt = init_pkt(ifsp, INFORM);
	dpkt->pkt->ciaddr = *our_addr;

	add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE, htons(ifsp->if_max -
			sizeof (struct udpiphdr)));
	add_pkt_opt(dpkt, CD_CLASS_ID, class_id, class_id_len);
	add_pkt_opt(dpkt, CD_REQUEST_LIST, ifsp->if_prl, ifsp->if_prllen);
	add_pkt_opt(dpkt, CD_END, NULL, 0);

	if (send_pkt(ifsp, dpkt, ifsp->if_server.s_addr, NULL) == 0) {
		ifsp->if_dflags |= DHCP_IF_FAILED;
		dhcpmsg(MSG_ERROR, "dhcp_inform: send_pkt failed");
		ipc_action_finish(ifsp, DHCP_IPC_E_INT);
		async_finish(ifsp);
		return;
	}

	if (register_acknak(ifsp) == 0) {
		ifsp->if_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(ifsp, DHCP_IPC_E_MEMORY);
		async_finish(ifsp);
		return;
	}

	ifsp->if_state = INFORM_SENT;
}
