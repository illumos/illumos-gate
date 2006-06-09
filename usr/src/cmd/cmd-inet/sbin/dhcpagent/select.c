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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * SELECTING state of the client state machine.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <stropts.h>				/* FLUSHR/FLUSHW */
#include <dhcpmsg.h>

#include "states.h"
#include "agent.h"
#include "util.h"
#include "interface.h"
#include "packet.h"
#include "defaults.h"

static iu_eh_callback_t	dhcp_collect_offers;
static stop_func_t	stop_selecting;

/*
 * dhcp_start(): starts DHCP on an interface
 *
 *   input: iu_tq_t *: unused
 *	    void *: the interface to start DHCP on
 *  output: void
 */

/* ARGSUSED */
void
dhcp_start(iu_tq_t *tqp, void *arg)
{
	struct ifslist	*ifsp = (struct ifslist *)arg;

	if (check_ifs(ifsp) == 0) {
		(void) release_ifs(ifsp);
		return;
	}

	dhcpmsg(MSG_VERBOSE, "starting DHCP on %s", ifsp->if_name);
	dhcp_selecting(ifsp);
}

/*
 * dhcp_selecting(): sends a DISCOVER and sets up reception for an OFFER
 *
 *   input: struct ifslist *: the interface to send the DISCOVER on, ...
 *  output: void
 */

void
dhcp_selecting(struct ifslist *ifsp)
{
	dhcp_pkt_t		*dpkt;
	const char		*reqhost;
	char			hostfile[PATH_MAX + 1];

	/*
	 * we first set up to collect OFFER packets as they arrive.
	 * we then send out DISCOVER probes.  then we wait at a
	 * user-tunable number of seconds before seeing if OFFERs have
	 * come in response to our DISCOVER.  if none have come in, we
	 * continue to wait, sending out our DISCOVER probes with
	 * exponential backoff.  if an OFFER is never received, we
	 * will wait forever (note that since we're event-driven
	 * though, we're still able to service other interfaces.)
	 *
	 * note that we do an reset_ifs() here because we may be
	 * landing in dhcp_selecting() as a result of restarting DHCP,
	 * so the ifs may not be fresh.
	 */

	reset_ifs(ifsp);
	ifsp->if_state = SELECTING;

	if ((ifsp->if_offer_id = iu_register_event(eh, ifsp->if_dlpi_fd, POLLIN,
	    dhcp_collect_offers, ifsp)) == -1) {

		dhcpmsg(MSG_ERROR, "dhcp_selecting: cannot register to collect "
		    "OFFER packets, reverting to INIT on %s",
		    ifsp->if_name);

		ifsp->if_state   = INIT;
		ifsp->if_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(ifsp, DHCP_IPC_E_MEMORY);
		async_finish(ifsp);
		return;
	} else
		hold_ifs(ifsp);


	if ((ifsp->if_offer_timer = iu_schedule_timer(tq,
	    ifsp->if_offer_wait, dhcp_requesting, ifsp)) == -1) {

		dhcpmsg(MSG_ERROR, "dhcp_selecting: cannot schedule to read "
		    "OFFER packets");

		if (iu_unregister_event(eh, ifsp->if_offer_id, NULL) != 0) {
			ifsp->if_offer_id = -1;
			(void) release_ifs(ifsp);
		}

		ifsp->if_state   = INIT;
		ifsp->if_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(ifsp, DHCP_IPC_E_MEMORY);
		async_finish(ifsp);
		return;
	} else
		hold_ifs(ifsp);

	/*
	 * Assemble DHCPDISCOVER message.  The max dhcp message size
	 * option is set to the interface max, minus the size of the udp and
	 * ip headers.
	 */

	dpkt = init_pkt(ifsp, DISCOVER);

	add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE, htons(ifsp->if_max -
			sizeof (struct udpiphdr)));
	add_pkt_opt32(dpkt, CD_LEASE_TIME, htonl(DHCP_PERM));

	add_pkt_opt(dpkt, CD_CLASS_ID, class_id, class_id_len);
	add_pkt_opt(dpkt, CD_REQUEST_LIST, ifsp->if_prl, ifsp->if_prllen);

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

	(void) send_pkt(ifsp, dpkt, htonl(INADDR_BROADCAST), stop_selecting);
}

/*
 * dhcp_collect_offers(): collects incoming OFFERs to a DISCOVER
 *
 *   input: iu_eh_t *: unused
 *	    int: the file descriptor the OFFER arrived on
 *	    short: unused
 *	    iu_event_id_t: the id of this event callback with the handler
 *	    void *: the interface that received the OFFER
 *  output: void
 */

/* ARGSUSED */
static void
dhcp_collect_offers(iu_eh_t *eh, int fd, short events, iu_event_id_t id,
    void *arg)
{
	struct ifslist	*ifsp = (struct ifslist *)arg;

	if (verify_ifs(ifsp) == 0) {
		(void) ioctl(fd, I_FLUSH, FLUSHR|FLUSHW);
		return;
	}

	/*
	 * DHCP_PUNTYPED messages are BOOTP server responses.
	 */

	(void) recv_pkt(ifsp, fd, DHCP_POFFER|DHCP_PUNTYPED, B_TRUE);
}

/*
 * stop_selecting(): decides when to stop retransmitting DISCOVERs (never)
 *
 *   input: struct ifslist *: the interface DISCOVERs are being sent on
 *	    unsigned int: the number of DISCOVERs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

/* ARGSUSED */
static boolean_t
stop_selecting(struct ifslist *ifsp, unsigned int n_discovers)
{
	return (B_FALSE);
}
