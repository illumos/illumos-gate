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
 * DECLINE/RELEASE configuration functionality for the DHCP client.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include <dhcpmsg.h>
#include <dhcp_hostconf.h>
#include <unistd.h>

#include "packet.h"
#include "interface.h"
#include "states.h"

/*
 * send_decline(): sends a DECLINE message (broadcasted)
 *
 *   input: struct ifslist *: the interface to send the DECLINE on
 *	    char *: an optional text explanation to send with the message
 *	    struct in_addr *: the IP address being declined
 *  output: void
 */

void
send_decline(struct ifslist *ifsp, char *msg, struct in_addr *declined_ip)
{
	dhcp_pkt_t	*dpkt;

	dpkt = init_pkt(ifsp, DECLINE);
	add_pkt_opt32(dpkt, CD_SERVER_ID, ifsp->if_server.s_addr);

	if (msg != NULL)
		add_pkt_opt(dpkt, CD_MESSAGE, msg, strlen(msg) + 1);

	add_pkt_opt32(dpkt, CD_REQUESTED_IP_ADDR, declined_ip->s_addr);
	add_pkt_opt(dpkt, CD_END, NULL, 0);

	(void) send_pkt(ifsp, dpkt, htonl(INADDR_BROADCAST), NULL);
}

/*
 * dhcp_release(): sends a RELEASE message to a DHCP server and removes
 *		   the interface from DHCP control
 *
 *   input: struct ifslist *: the interface to send the RELEASE on and remove
 *	    const char *: an optional text explanation to send with the message
 *  output: int: 1 on success, 0 on failure
 */

int
dhcp_release(struct ifslist *ifsp, const char *msg)
{
	int		retval = 0;
	int		error = DHCP_IPC_E_INT;
	dhcp_pkt_t	*dpkt;

	if (ifsp->if_dflags & DHCP_IF_BOOTP)
		goto out;

	if (ifsp->if_state != BOUND && ifsp->if_state != RENEWING &&
	    ifsp->if_state != REBINDING)
		goto out;

	dhcpmsg(MSG_INFO, "releasing interface %s", ifsp->if_name);

	dpkt = init_pkt(ifsp, RELEASE);
	dpkt->pkt->ciaddr.s_addr = ifsp->if_addr.s_addr;

	if (msg != NULL)
		add_pkt_opt(dpkt, CD_MESSAGE, msg, strlen(msg) + 1);

	add_pkt_opt32(dpkt, CD_SERVER_ID, ifsp->if_server.s_addr);
	add_pkt_opt(dpkt, CD_END, NULL, 0);

	(void) send_pkt(ifsp, dpkt, ifsp->if_server.s_addr, NULL);

	/*
	 * XXX this totally sucks, but since udp is best-effort,
	 * without this delay, there's a good chance that the packet
	 * that we just enqueued for sending will get pitched
	 * when we canonize the interface below.
	 */

	(void) usleep(500);
	(void) canonize_ifs(ifsp);

	remove_ifs(ifsp);
	error = DHCP_IPC_SUCCESS;
	retval = 1;
out:
	ipc_action_finish(ifsp, error);
	async_finish(ifsp);
	return (retval);
}

/*
 * dhcp_drop(): drops the interface from DHCP control
 *
 *   input: struct ifslist *: the interface to drop
 *	    const char *: unused
 *  output: int: always 1
 */

/* ARGSUSED */
int
dhcp_drop(struct ifslist *ifsp, const char *msg)
{
	PKT_LIST *plp[2];

	dhcpmsg(MSG_INFO, "dropping interface %s", ifsp->if_name);

	if (ifsp->if_state == BOUND || ifsp->if_state == RENEWING ||
	    ifsp->if_state == REBINDING) {

		if ((ifsp->if_dflags & DHCP_IF_BOOTP) == 0) {
			plp[0] = ifsp->if_ack;
			plp[1] = ifsp->if_orig_ack;
			if (write_hostconf(ifsp->if_name, plp, 2,
			    monosec_to_time(ifsp->if_curstart_monosec)) == -1)
				dhcpmsg(MSG_ERR, "cannot write %s (reboot will "
				    "not use cached configuration)",
				    ifname_to_hostconf(ifsp->if_name));
		}
		(void) canonize_ifs(ifsp);
	}
	remove_ifs(ifsp);
	ipc_action_finish(ifsp, DHCP_IPC_SUCCESS);
	async_finish(ifsp);
	return (1);
}
