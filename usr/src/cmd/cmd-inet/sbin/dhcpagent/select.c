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
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 *
 * SELECTING state of the client state machine.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <dhcpmsg.h>
#include <dhcp_hostconf.h>

#include "states.h"
#include "agent.h"
#include "util.h"
#include "interface.h"
#include "packet.h"
#include "defaults.h"

static stop_func_t	stop_selecting;

/*
 * dhcp_start(): starts DHCP on a state machine
 *
 *   input: iu_tq_t *: unused
 *	    void *: the state machine on which to start DHCP
 *  output: void
 */

/* ARGSUSED */
static void
dhcp_start(iu_tq_t *tqp, void *arg)
{
	dhcp_smach_t	*dsmp = arg;

	dsmp->dsm_start_timer = -1;
	(void) set_smach_state(dsmp, INIT);
	if (verify_smach(dsmp)) {
		dhcpmsg(MSG_VERBOSE, "starting DHCP on %s", dsmp->dsm_name);
		dhcp_selecting(dsmp);
	}
}

/*
 * set_start_timer(): sets a random timer to start a DHCP state machine
 *
 *   input: dhcp_smach_t *: the state machine on which to start DHCP
 *  output: boolean_t: B_TRUE if a timer is now running
 */

boolean_t
set_start_timer(dhcp_smach_t *dsmp)
{
	if (dsmp->dsm_start_timer != -1)
		return (B_TRUE);

	dsmp->dsm_start_timer = iu_schedule_timer_ms(tq,
	    lrand48() % DHCP_SELECT_WAIT, dhcp_start, dsmp);
	if (dsmp->dsm_start_timer == -1)
		return (B_FALSE);

	hold_smach(dsmp);
	return (B_TRUE);
}

/*
 * dhcp_selecting(): sends a DISCOVER and sets up reception of OFFERs for
 *		     IPv4, or sends a Solicit and sets up reception of
 *		     Advertisements for DHCPv6.
 *
 *   input: dhcp_smach_t *: the state machine on which to send the DISCOVER
 *  output: void
 */

void
dhcp_selecting(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t		*dpkt;

	/*
	 * We first set up to collect OFFER/Advertise packets as they arrive.
	 * We then send out DISCOVER/Solicit probes.  Then we wait a
	 * user-tunable number of seconds before seeing if OFFERs/
	 * Advertisements have come in response to our DISCOVER/Solicit.  If
	 * none have come in, we continue to wait, sending out our DISCOVER/
	 * Solicit probes with exponential backoff.  If no OFFER/Advertisement
	 * is ever received, we will wait forever (note that since we're
	 * event-driven though, we're still able to service other state
	 * machines).
	 *
	 * Note that we do an reset_smach() here because we may be landing in
	 * dhcp_selecting() as a result of restarting DHCP, so the state
	 * machine may not be fresh.
	 */

	reset_smach(dsmp);
	if (!set_smach_state(dsmp, SELECTING)) {
		dhcpmsg(MSG_ERROR,
		    "dhcp_selecting: cannot switch to SELECTING state; "
		    "reverting to INIT on %s", dsmp->dsm_name);
		goto failed;

	}

	/* Remove the stale hostconf file, if there is any */
	(void) remove_hostconf(dsmp->dsm_name, dsmp->dsm_isv6);

	dsmp->dsm_offer_timer = iu_schedule_timer(tq,
	    dsmp->dsm_offer_wait, dhcp_requesting, dsmp);
	if (dsmp->dsm_offer_timer == -1) {
		dhcpmsg(MSG_ERROR, "dhcp_selecting: cannot schedule to read "
		    "%s packets", dsmp->dsm_isv6 ? "Advertise" : "OFFER");
		goto failed;
	}

	hold_smach(dsmp);

	/*
	 * Assemble and send the DHCPDISCOVER or Solicit message.
	 *
	 * If this fails, we'll wait for the select timer to go off
	 * before trying again.
	 */
	if (dsmp->dsm_isv6) {
		dhcpv6_ia_na_t d6in;

		if ((dpkt = init_pkt(dsmp, DHCPV6_MSG_SOLICIT)) == NULL) {
			dhcpmsg(MSG_ERROR, "dhcp_selecting: unable to set up "
			    "Solicit packet");
			return;
		}

		/* Add an IA_NA option for our controlling LIF */
		d6in.d6in_iaid = htonl(dsmp->dsm_lif->lif_iaid);
		d6in.d6in_t1 = htonl(0);
		d6in.d6in_t2 = htonl(0);
		(void) add_pkt_opt(dpkt, DHCPV6_OPT_IA_NA,
		    (dhcpv6_option_t *)&d6in + 1,
		    sizeof (d6in) - sizeof (dhcpv6_option_t));

		/* Option Request option for desired information */
		(void) add_pkt_prl(dpkt, dsmp);

		/* Enable Rapid-Commit */
		(void) add_pkt_opt(dpkt, DHCPV6_OPT_RAPID_COMMIT, NULL, 0);

		/* xxx add Reconfigure Accept */

		(void) send_pkt_v6(dsmp, dpkt, ipv6_all_dhcp_relay_and_servers,
		    stop_selecting, DHCPV6_SOL_TIMEOUT, DHCPV6_SOL_MAX_RT);
	} else {
		if ((dpkt = init_pkt(dsmp, DISCOVER)) == NULL) {
			dhcpmsg(MSG_ERROR, "dhcp_selecting: unable to set up "
			    "DISCOVER packet");
			return;
		}

		/*
		 * The max DHCP message size option is set to the interface
		 * MTU, minus the size of the UDP and IP headers.
		 */
		(void) add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE,
		    htons(dsmp->dsm_lif->lif_max - sizeof (struct udpiphdr)));
		(void) add_pkt_opt32(dpkt, CD_LEASE_TIME, htonl(DHCP_PERM));

		if (class_id_len != 0) {
			(void) add_pkt_opt(dpkt, CD_CLASS_ID, class_id,
			    class_id_len);
		}
		(void) add_pkt_prl(dpkt, dsmp);

		if (!dhcp_add_fqdn_opt(dpkt, dsmp))
			(void) dhcp_add_hostname_opt(dpkt, dsmp);

		(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

		(void) send_pkt(dsmp, dpkt, htonl(INADDR_BROADCAST),
		    stop_selecting);
	}
	return;

failed:
	(void) set_smach_state(dsmp, INIT);
	dsmp->dsm_dflags |= DHCP_IF_FAILED;
	ipc_action_finish(dsmp, DHCP_IPC_E_MEMORY);
}

/*
 * stop_selecting(): decides when to stop retransmitting DISCOVERs -- only when
 *		     abandoning the state machine.  For DHCPv6, this timer may
 *		     go off before the offer wait timer.  If so, then this is a
 *		     good time to check for valid Advertisements, so cancel the
 *		     timer and go check.
 *
 *   input: dhcp_smach_t *: the state machine DISCOVERs are being sent on
 *	    unsigned int: the number of DISCOVERs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

/* ARGSUSED1 */
static boolean_t
stop_selecting(dhcp_smach_t *dsmp, unsigned int n_discovers)
{
	/*
	 * If we're using v4 and the underlying LIF we're trying to configure
	 * has been touched by the user, then bail out.
	 */
	if (!dsmp->dsm_isv6 && !verify_lif(dsmp->dsm_lif)) {
		finished_smach(dsmp, DHCP_IPC_E_UNKIF);
		return (B_TRUE);
	}

	if (dsmp->dsm_recv_pkt_list != NULL) {
		dhcp_requesting(NULL, dsmp);
		if (dsmp->dsm_state != SELECTING)
			return (B_TRUE);
	}
	return (B_FALSE);
}
