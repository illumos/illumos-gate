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
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 *
 * INIT_REBOOT state of the DHCP client state machine.
 */

#include <sys/types.h>
#include <stdio.h>
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
 * dhcp_init_reboot_v4(): attempts to reuse a cached configuration for a state
 *			  machine.
 *
 *   input: dhcp_smach_t *: the state machine to examine for reuse
 *  output: void
 */

static void
dhcp_init_reboot_v4(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t		*dpkt;

	/*
	 * assemble DHCPREQUEST message.  The max dhcp message size
	 * option is set to the interface max, minus the size of the udp and
	 * ip headers.
	 */

	dpkt = init_pkt(dsmp, REQUEST);
	(void) add_pkt_opt32(dpkt, CD_REQUESTED_IP_ADDR,
	    dsmp->dsm_ack->pkt->yiaddr.s_addr);

	(void) add_pkt_opt32(dpkt, CD_LEASE_TIME, htonl(DHCP_PERM));
	(void) add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE,
	    htons(dsmp->dsm_lif->lif_pif->pif_max - sizeof (struct udpiphdr)));

	if (class_id_len != 0)
		(void) add_pkt_opt(dpkt, CD_CLASS_ID, class_id, class_id_len);
	(void) add_pkt_prl(dpkt, dsmp);

	if (!dhcp_add_fqdn_opt(dpkt, dsmp))
		(void) dhcp_add_hostname_opt(dpkt, dsmp);

	(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

	(void) send_pkt(dsmp, dpkt, htonl(INADDR_BROADCAST), stop_init_reboot);
}


/*
 * dhcp_init_reboot_v6(): attempts to reuse a cached configuration for a state
 *			  machine.  Create a Confirm message and multicast it
 *			  out.
 *
 *   input: dhcp_smach_t *: the state machine to examine for reuse
 *  output: void
 */

static void
dhcp_init_reboot_v6(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t *dpkt;
	dhcpv6_option_t *d6o, *d6so, *popt;
	uint_t olen, solen;
	dhcpv6_ia_na_t d6in;
	dhcpv6_iaaddr_t d6ia;
	char *obase;

	/*
	 * Assemble a Confirm message based on the current ack.
	 */

	dpkt = init_pkt(dsmp, DHCPV6_MSG_CONFIRM);

	/*
	 * Loop over and copy IA_NAs and IAADDRs we have in our last ack.  This
	 * is what we'll be requesting.
	 */
	d6o = NULL;
	while ((d6o = dhcpv6_pkt_option(dsmp->dsm_ack, d6o, DHCPV6_OPT_IA_NA,
	    &olen)) != NULL) {

		/*
		 * Copy in IA_NA option from the ack.  Note that we use zero
		 * for all timers in accordance with RFC 3315.  (It would make
		 * some sense to say what we think the current timers are as
		 * a hint to the server, but the RFC doesn't agree.)
		 */
		if (olen < sizeof (dhcpv6_ia_na_t))
			continue;
		(void) memcpy(&d6in, d6o, sizeof (d6in));
		d6in.d6in_t1 = 0;
		d6in.d6in_t2 = 0;
		popt = add_pkt_opt(dpkt, DHCPV6_OPT_IA_NA,
		    (char *)&d6in + sizeof (*d6o),
		    sizeof (d6in) - sizeof (*d6o));
		if (popt == NULL)
			goto failure;

		/*
		 * Now loop over the IAADDR suboptions and add those.
		 */
		obase = (char *)d6o + sizeof (dhcpv6_ia_na_t);
		olen -= sizeof (dhcpv6_ia_na_t);
		d6so = NULL;
		while ((d6so = dhcpv6_find_option(obase, olen, d6so,
		    DHCPV6_OPT_IAADDR, &solen)) != NULL) {
			if (solen < sizeof (dhcpv6_iaaddr_t))
				continue;
			(void) memcpy(&d6ia, d6so, sizeof (d6ia));
			d6ia.d6ia_preflife = 0;
			d6ia.d6ia_vallife = 0;
			if (add_pkt_subopt(dpkt, popt, DHCPV6_OPT_IAADDR,
			    (char *)&d6ia + sizeof (*d6so),
			    sizeof (d6ia) - sizeof (*d6so)) == NULL)
				goto failure;
		}
	}

	/* Add required Option Request option */
	(void) add_pkt_prl(dpkt, dsmp);

	(void) send_pkt_v6(dsmp, dpkt, ipv6_all_dhcp_relay_and_servers,
	    stop_init_reboot, DHCPV6_CNF_TIMEOUT, DHCPV6_CNF_MAX_RT);

	return;

failure:
	if (!set_start_timer(dsmp))
		dhcp_selecting(dsmp);
}

/*
 * dhcp_init_reboot(): attempts to reuse a cached configuration for a state
 *		       machine.
 *
 *   input: dhcp_smach_t *: the state machine to examine for reuse
 *  output: void
 */

void
dhcp_init_reboot(dhcp_smach_t *dsmp)
{
	dhcpmsg(MSG_VERBOSE,  "%s has cached configuration - entering "
	    "INIT_REBOOT", dsmp->dsm_name);

	if (!set_smach_state(dsmp, INIT_REBOOT)) {
		dhcpmsg(MSG_ERROR, "dhcp_init_reboot: cannot register to "
		    "collect ACK/NAK packets, reverting to INIT on %s",
		    dsmp->dsm_name);

		dsmp->dsm_dflags |= DHCP_IF_FAILED;
		(void) set_smach_state(dsmp, INIT);
		ipc_action_finish(dsmp, DHCP_IPC_E_MEMORY);
		return;
	}

	if (dsmp->dsm_isv6)
		dhcp_init_reboot_v6(dsmp);
	else
		dhcp_init_reboot_v4(dsmp);
}

/*
 * stop_init_reboot(): decides when to stop retransmitting REQUESTs
 *
 *   input: dhcp_smach_t *: the state machine sending the REQUESTs
 *	    unsigned int: the number of REQUESTs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

static boolean_t
stop_init_reboot(dhcp_smach_t *dsmp, unsigned int n_requests)
{
	if (dsmp->dsm_isv6) {
		uint_t nowabs, maxabs;

		nowabs = NSEC2MSEC(gethrtime());
		maxabs = NSEC2MSEC(dsmp->dsm_neg_hrtime) + DHCPV6_CNF_MAX_RD;
		if (nowabs < maxabs) {
			/* Cap the timer based on the maximum */
			if (nowabs + dsmp->dsm_send_timeout > maxabs)
				dsmp->dsm_send_timeout = maxabs - nowabs;
			return (B_FALSE);
		}
	} else {
		if (n_requests < DHCP_MAX_REQUESTS)
			return (B_FALSE);
	}

	if (df_get_bool(dsmp->dsm_name, dsmp->dsm_isv6,
	    DF_VERIFIED_LEASE_ONLY)) {
		dhcpmsg(MSG_INFO,
		    "unable to verify existing lease on %s; restarting",
		    dsmp->dsm_name);
		dhcp_selecting(dsmp);
		return (B_TRUE);
	}

	if (dsmp->dsm_isv6) {
		dhcpmsg(MSG_INFO, "no Reply to Confirm, using remainder of "
		    "existing lease on %s", dsmp->dsm_name);
	} else {
		dhcpmsg(MSG_INFO, "no ACK/NAK to INIT_REBOOT REQUEST, "
		    "using remainder of existing lease on %s", dsmp->dsm_name);
	}

	/*
	 * We already stuck our old ack in dsmp->dsm_ack and relativized the
	 * packet times, so we can just pretend that the server sent it to us
	 * and move to bound.  If that fails, fall back to selecting.
	 */

	if (dhcp_bound(dsmp, NULL)) {
		if (dsmp->dsm_isv6) {
			if (!save_server_id(dsmp, dsmp->dsm_ack))
				goto failure;
			server_unicast_option(dsmp, dsmp->dsm_ack);
		}
	} else {
failure:
		dhcpmsg(MSG_INFO, "unable to use saved lease on %s; restarting",
		    dsmp->dsm_name);
		dhcp_selecting(dsmp);
	}

	return (B_TRUE);
}
