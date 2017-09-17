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
 * REQUESTING state of the client state machine.
 */

#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <arpa/inet.h>
#include <dhcp_hostconf.h>
#include <dhcpagent_util.h>
#include <dhcpmsg.h>

#include "states.h"
#include "util.h"
#include "packet.h"
#include "interface.h"
#include "agent.h"

static PKT_LIST		*select_best(dhcp_smach_t *);
static void		request_failed(dhcp_smach_t *);
static stop_func_t	stop_requesting;

/*
 * send_v6_request(): sends a DHCPv6 Request message and switches to REQUESTING
 *		      state.  This is a separate function because a NoBinding
 *		      response can also cause us to do this.
 *
 *   input: dhcp_smach_t *: the state machine
 *  output: none
 */

void
send_v6_request(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t *dpkt;
	dhcpv6_ia_na_t d6in;

	dpkt = init_pkt(dsmp, DHCPV6_MSG_REQUEST);
	(void) add_pkt_opt(dpkt, DHCPV6_OPT_SERVERID, dsmp->dsm_serverid,
	    dsmp->dsm_serveridlen);

	/* Add an IA_NA option for our controlling LIF */
	d6in.d6in_iaid = htonl(dsmp->dsm_lif->lif_iaid);
	d6in.d6in_t1 = htonl(0);
	d6in.d6in_t2 = htonl(0);
	(void) add_pkt_opt(dpkt, DHCPV6_OPT_IA_NA,
	    (dhcpv6_option_t *)&d6in + 1,
	    sizeof (d6in) - sizeof (dhcpv6_option_t));

	/* Add required Option Request option */
	(void) add_pkt_prl(dpkt, dsmp);

	(void) send_pkt_v6(dsmp, dpkt, dsmp->dsm_server, stop_requesting,
	    DHCPV6_REQ_TIMEOUT, DHCPV6_REQ_MAX_RT);

	/* For DHCPv6, state switch cannot fail */
	(void) set_smach_state(dsmp, REQUESTING);
}

/*
 * server_unicast_option(): determines the server address to use based on the
 *			    DHCPv6 Server Unicast option present in the given
 *			    packet.
 *
 *   input: dhcp_smach_t *: the state machine
 *	    PKT_LIST *: received packet (Advertisement or Reply)
 *  output: none
 */

void
server_unicast_option(dhcp_smach_t *dsmp, PKT_LIST *plp)
{
	const dhcpv6_option_t *d6o;
	uint_t olen;

	d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_UNICAST, &olen);
	olen -= sizeof (*d6o);
	/* LINTED: no consequent */
	if (d6o == NULL) {
		/* No Server Unicast option specified */
	} else if (olen != sizeof (dsmp->dsm_server)) {
		dhcpmsg(MSG_WARNING, "server_unicast_option: %s has Server "
		    "Unicast option with bad length",
		    pkt_type_to_string(pkt_recv_type(plp), B_TRUE));
	} else {
		in6_addr_t addr;

		(void) memcpy(&addr, d6o + 1, olen);
		if (IN6_IS_ADDR_UNSPECIFIED(&addr)) {
			dhcpmsg(MSG_WARNING, "server_unicast_option: unicast "
			    "to unspecified address ignored");
		} else if (IN6_IS_ADDR_MULTICAST(&addr)) {
			dhcpmsg(MSG_WARNING, "server_unicast_option: unicast "
			    "to multicast address ignored");
		} else if (IN6_IS_ADDR_V4COMPAT(&addr) ||
		    IN6_IS_ADDR_V4MAPPED(&addr)) {
			dhcpmsg(MSG_WARNING, "server_unicast_option: unicast "
			    "to invalid address ignored");
		} else {
			dsmp->dsm_server = addr;
		}
	}
}

/*
 * dhcp_requesting(): checks if OFFER packets to come in from DHCP servers.
 *		      if so, chooses the best one, sends a REQUEST to the
 *		      server and registers an event handler to receive
 *		      the ACK/NAK.  This may be called by the offer timer or
 *		      by any function that wants to check for offers after
 *		      canceling that timer.
 *
 *   input: iu_tq_t *: timer queue; non-NULL if this is a timer callback
 *	    void *: the state machine receiving OFFER packets
 *  output: void
 */

void
dhcp_requesting(iu_tq_t *tqp, void *arg)
{
	dhcp_smach_t		*dsmp = arg;
	dhcp_pkt_t		*dpkt;
	PKT_LIST		*offer;
	lease_t			lease;
	boolean_t		isv6 = dsmp->dsm_isv6;

	/*
	 * We assume here that if tqp is set, then this means we're being
	 * called back by the offer wait timer.  If so, then drop our hold
	 * on the state machine.  Otherwise, cancel the timer if it's running.
	 */
	if (tqp != NULL) {
		dhcpmsg(MSG_VERBOSE,
		    "dhcp_requesting: offer wait timer on v%d %s",
		    isv6 ? 6 : 4, dsmp->dsm_name);
		dsmp->dsm_offer_timer = -1;
		if (!verify_smach(dsmp))
			return;
	} else {
		cancel_offer_timer(dsmp);
	}

	/*
	 * select the best OFFER; all others pitched.
	 */

	offer = select_best(dsmp);
	if (offer == NULL) {

		dhcpmsg(MSG_VERBOSE,
		    "no OFFERs/Advertisements on %s, waiting...",
		    dsmp->dsm_name);

		/*
		 * no acceptable OFFERs have come in.  reschedule
		 * ourself for callback.
		 */

		if ((dsmp->dsm_offer_timer = iu_schedule_timer(tq,
		    dsmp->dsm_offer_wait, dhcp_requesting, dsmp)) == -1) {

			/*
			 * ugh.  the best we can do at this point is
			 * revert back to INIT and wait for a user to
			 * restart us.
			 */

			dhcpmsg(MSG_WARNING, "dhcp_requesting: cannot "
			    "reschedule callback, reverting to INIT state on "
			    "%s", dsmp->dsm_name);

			stop_pkt_retransmission(dsmp);
			(void) set_smach_state(dsmp, INIT);
			dsmp->dsm_dflags |= DHCP_IF_FAILED;
			ipc_action_finish(dsmp, DHCP_IPC_E_MEMORY);
		} else {
			hold_smach(dsmp);
		}

		return;
	}

	/*
	 * With IPv4, the DHCPREQUEST packet we're about to transmit implicitly
	 * declines all other offers we've received.  We can no longer use any
	 * cached offers, so we must discard them now.  With DHCPv6, though,
	 * we're permitted to hang onto the advertisements (offers) and try
	 * them if the preferred one doesn't pan out.
	 */
	if (!isv6)
		free_pkt_list(&dsmp->dsm_recv_pkt_list);

	/* stop collecting packets. */

	stop_pkt_retransmission(dsmp);

	/*
	 * For IPv4, check to see whether we got an OFFER or a BOOTP packet.
	 * If we got a BOOTP packet, go to the BOUND state now.
	 */
	if (!isv6 && offer->opts[CD_DHCP_TYPE] == NULL) {
		free_pkt_list(&dsmp->dsm_recv_pkt_list);

		if (!set_smach_state(dsmp, REQUESTING)) {
			dhcp_restart(dsmp);
			return;
		}

		if (!dhcp_bound(dsmp, offer)) {
			dhcpmsg(MSG_WARNING, "dhcp_requesting: dhcp_bound "
			    "failed for %s", dsmp->dsm_name);
			dhcp_restart(dsmp);
			return;
		}

		return;
	}

	save_domainname(dsmp, offer);

	if (isv6) {
		const char *estr, *msg;
		const dhcpv6_option_t *d6o;
		uint_t olen, msglen;

		/* If there's a Status Code option, print the message */
		d6o = dhcpv6_pkt_option(offer, NULL, DHCPV6_OPT_STATUS_CODE,
		    &olen);
		(void) dhcpv6_status_code(d6o, olen, &estr, &msg, &msglen);
		print_server_msg(dsmp, msg, msglen);

		/* Copy in the Server ID (guaranteed to be present now) */
		if (!save_server_id(dsmp, offer))
			goto failure;

		/*
		 * Determine how to send this message.  If the Advertisement
		 * (offer) has the unicast option, then use the address
		 * specified in the option.  Otherwise, send via multicast.
		 */
		server_unicast_option(dsmp, offer);

		send_v6_request(dsmp);
	} else {
		/* if we got a message from the server, display it. */
		if (offer->opts[CD_MESSAGE] != NULL) {
			print_server_msg(dsmp,
			    (char *)offer->opts[CD_MESSAGE]->value,
			    offer->opts[CD_MESSAGE]->len);
		}

		/*
		 * assemble a DHCPREQUEST, with the ciaddr field set to 0,
		 * since we got here from the INIT state.
		 */

		dpkt = init_pkt(dsmp, REQUEST);

		/*
		 * Grab the lease out of the OFFER; we know it's valid because
		 * select_best() already checked.  The max dhcp message size
		 * option is set to the interface max, minus the size of the
		 * udp and ip headers.
		 */

		(void) memcpy(&lease, offer->opts[CD_LEASE_TIME]->value,
		    sizeof (lease_t));

		(void) add_pkt_opt32(dpkt, CD_LEASE_TIME, lease);
		(void) add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE,
		    htons(dsmp->dsm_lif->lif_max - sizeof (struct udpiphdr)));
		(void) add_pkt_opt32(dpkt, CD_REQUESTED_IP_ADDR,
		    offer->pkt->yiaddr.s_addr);
		(void) add_pkt_opt(dpkt, CD_SERVER_ID,
		    offer->opts[CD_SERVER_ID]->value,
		    offer->opts[CD_SERVER_ID]->len);

		if (class_id_len != 0) {
			(void) add_pkt_opt(dpkt, CD_CLASS_ID, class_id,
			    class_id_len);
		}
		(void) add_pkt_prl(dpkt, dsmp);

		/*
		 * dsm_reqhost was set for this state machine in
		 * dhcp_selecting() if the DF_REQUEST_HOSTNAME option set and a
		 * host name was found
		 */
		if (!dhcp_add_fqdn_opt(dpkt, dsmp) &&
		    dsmp->dsm_reqhost != NULL) {
			(void) add_pkt_opt(dpkt, CD_HOSTNAME, dsmp->dsm_reqhost,
			    strlen(dsmp->dsm_reqhost));
		}
		(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

		/*
		 * send out the REQUEST, trying retransmissions.  either a NAK
		 * or too many REQUEST attempts will revert us to SELECTING.
		 */

		if (!set_smach_state(dsmp, REQUESTING)) {
			dhcpmsg(MSG_ERROR, "dhcp_requesting: cannot switch to "
			    "REQUESTING state; reverting to INIT on %s",
			    dsmp->dsm_name);
			goto failure;
		}

		(void) send_pkt(dsmp, dpkt, htonl(INADDR_BROADCAST),
		    stop_requesting);
	}

	/* all done with the offer */
	free_pkt_entry(offer);

	return;

failure:
	dsmp->dsm_dflags |= DHCP_IF_FAILED;
	(void) set_smach_state(dsmp, INIT);
	ipc_action_finish(dsmp, DHCP_IPC_E_MEMORY);
	free_pkt_list(&dsmp->dsm_recv_pkt_list);
}

/*
 * compute_points_v6(): compute the number of "points" for a given v6
 *			advertisement.
 *
 *   input: const PKT_LIST *: packet to inspect
 *	    const dhcp_smach_t *: state machine that received the packet
 *  output: int: -1 to discard, -2 to accept immediately, >=0 for preference.
 */

static int
compute_points_v6(const PKT_LIST *pkt, const dhcp_smach_t *dsmp)
{
	char abuf[INET6_ADDRSTRLEN];
	int points = 0;
	const dhcpv6_option_t *d6o, *d6so;
	uint_t olen, solen;
	int i;
	const char *estr, *msg;
	uint_t msglen;

	/*
	 * Look through the packet contents.  Valid packets must have our
	 * client ID and a server ID, which has already been checked by
	 * dhcp_packet_lif.  Bonus points for each option.
	 */

	/* One point for having a valid message. */
	points++;

	/*
	 * Per RFC 3315, if the Advertise message says, "yes, we have no
	 * bananas today," then ignore the entire message.  (Why it's just
	 * _this_ error and no other is a bit of a mystery, but a standard is a
	 * standard.)
	 */
	d6o = dhcpv6_pkt_option(pkt, NULL, DHCPV6_OPT_STATUS_CODE, &olen);
	if (dhcpv6_status_code(d6o, olen, &estr, &msg, &msglen) ==
	    DHCPV6_STAT_NOADDRS) {
		dhcpmsg(MSG_INFO,
		    "discard advertisement from %s on %s: no address status",
		    inet_ntop(AF_INET6,
		    &((struct sockaddr_in6 *)&pkt->pktfrom)->sin6_addr,
		    abuf, sizeof (abuf)), dsmp->dsm_name);
		return (-1);
	}

	/* Two points for each batch of offered IP addresses */
	d6o = NULL;
	while ((d6o = dhcpv6_pkt_option(pkt, d6o, DHCPV6_OPT_IA_NA,
	    &olen)) != NULL) {

		/*
		 * Note that it's possible to have "no bananas" on an
		 * individual IA.  We must look for that here.
		 *
		 * RFC 3315 section 17.1.3 does not refer to the status code
		 * embedded in the IA itself.  However, the TAHI test suite
		 * checks for this specific case.  Because it's extremely
		 * unlikely that any usable server is going to report that it
		 * has no addresses on a network using DHCP for address
		 * assignment, we allow such messages to be dropped.
		 */
		d6so = dhcpv6_find_option(
		    (const char *)d6o + sizeof (dhcpv6_ia_na_t),
		    olen - sizeof (dhcpv6_ia_na_t), NULL,
		    DHCPV6_OPT_STATUS_CODE, &solen);
		if (dhcpv6_status_code(d6so, solen, &estr, &msg, &msglen) ==
		    DHCPV6_STAT_NOADDRS)
			return (-1);
		points += 2;
	}

	/*
	 * Note that we drive on in the case where there are no addresses.  The
	 * hope here is that we'll at least get some useful configuration
	 * information.
	 */

	/* One point for each requested option */
	for (i = 0; i < dsmp->dsm_prllen; i++) {
		if (dhcpv6_pkt_option(pkt, NULL, dsmp->dsm_prl[i], NULL) !=
		    NULL)
			points++;
	}

	/*
	 * Ten points for each point of "preference."  Note: the value 255 is
	 * special.  It means "stop right now and select this server."
	 */
	d6o = dhcpv6_pkt_option(pkt, NULL, DHCPV6_OPT_PREFERENCE, &olen);
	if (d6o != NULL && olen == sizeof (*d6o) + 1) {
		int pref = *(const uchar_t *)(d6o + 1);

		if (pref == 255)
			return (-2);
		points += 10 * pref;
	}

	return (points);
}

/*
 * compute_points_v4(): compute the number of "points" for a given v4 offer.
 *
 *   input: const PKT_LIST *: packet to inspect
 *	    const dhcp_smach_t *: state machine that received the packet
 *  output: int: -1 to discard, >=0 for preference.
 */

static int
compute_points_v4(const PKT_LIST *pkt)
{
	int points = 0;

	if (pkt->opts[CD_DHCP_TYPE] == NULL) {
		dhcpmsg(MSG_VERBOSE, "compute_points_v4: valid BOOTP reply");
		goto valid_offer;
	}

	if (pkt->opts[CD_LEASE_TIME] == NULL) {
		dhcpmsg(MSG_WARNING, "compute_points_v4: OFFER without lease "
		    "time");
		return (-1);
	}

	if (pkt->opts[CD_LEASE_TIME]->len != sizeof (lease_t)) {
		dhcpmsg(MSG_WARNING, "compute_points_v4: OFFER with garbled "
		    "lease time");
		return (-1);
	}

	if (pkt->opts[CD_SERVER_ID] == NULL) {
		dhcpmsg(MSG_WARNING, "compute_points_v4: OFFER without server "
		    "id");
		return (-1);
	}

	if (pkt->opts[CD_SERVER_ID]->len != sizeof (ipaddr_t)) {
		dhcpmsg(MSG_WARNING, "compute_points_v4: OFFER with garbled "
		    "server id");
		return (-1);
	}

	/* valid DHCP OFFER.  see if we got our parameters. */
	dhcpmsg(MSG_VERBOSE, "compute_points_v4: valid OFFER packet");
	points += 30;

valid_offer:
	if (pkt->rfc1048)
		points += 5;

	/*
	 * also could be faked, though more difficult because the encapsulation
	 * is hard to encode on a BOOTP server; plus there's not as much real
	 * estate in the packet for options, so it's likely this option would
	 * get dropped.
	 */

	if (pkt->opts[CD_VENDOR_SPEC] != NULL)
		points += 80;

	if (pkt->opts[CD_SUBNETMASK] != NULL)
		points++;

	if (pkt->opts[CD_ROUTER] != NULL)
		points++;

	if (pkt->opts[CD_HOSTNAME] != NULL)
		points += 5;

	return (points);
}

/*
 * select_best(): selects the best offer from a list of IPv4 OFFER packets or
 *		  DHCPv6 Advertise packets.
 *
 *   input: dhcp_smach_t *: state machine with enqueued offers
 *  output: PKT_LIST *: the best packet, or NULL if none are acceptable
 */

static PKT_LIST *
select_best(dhcp_smach_t *dsmp)
{
	PKT_LIST	*current = dsmp->dsm_recv_pkt_list;
	PKT_LIST	*next, *best = NULL;
	int		points, best_points = -1;

	/*
	 * pick out the best offer.  point system.
	 * what's important for IPv4?
	 *
	 *	0) DHCP (30 points)
	 *	1) no option overload
	 *	2) encapsulated vendor option (80 points)
	 *	3) non-null sname and siaddr fields
	 *	4) non-null file field
	 *	5) hostname (5 points)
	 *	6) subnetmask (1 point)
	 *	7) router (1 point)
	 */

	for (; current != NULL; current = next) {
		next = current->next;

		points = current->isv6 ?
		    compute_points_v6(current, dsmp) :
		    compute_points_v4(current);

		/*
		 * Just discard any unacceptable entries we encounter.
		 */
		if (points == -1) {
			remque(current);
			free_pkt_entry(current);
			continue;
		}

		dhcpmsg(MSG_DEBUG, "select_best: OFFER had %d points", points);

		/* Special case: stop now and select */
		if (points == -2) {
			best = current;
			break;
		}

		if (points >= best_points) {
			best_points = points;
			best = current;
		}
	}

	if (best != NULL) {
		dhcpmsg(MSG_DEBUG, "select_best: most points: %d", best_points);
		remque(best);
	} else {
		dhcpmsg(MSG_DEBUG, "select_best: no valid OFFER/BOOTP reply");
	}

	return (best);
}

/*
 * accept_v4_acknak(): determine what to do with a DHCPv4 ACK/NAK based on the
 *		       current state.  If we're renewing or rebinding, the ACK
 *		       must be for the same address and must have a new lease
 *		       time.  If it's a NAK, then our cache is garbage, and we
 *		       must restart.  Finally, call dhcp_bound on accepted
 *		       ACKs.
 *
 *   input: dhcp_smach_t *: the state machine to handle the ACK/NAK
 *	    PKT_LIST *: the ACK/NAK message
 *  output: void
 */

static void
accept_v4_acknak(dhcp_smach_t *dsmp, PKT_LIST *plp)
{
	/* Account for received and processed messages */
	dsmp->dsm_received++;

	if (*plp->opts[CD_DHCP_TYPE]->value == ACK) {
		if (dsmp->dsm_state != INFORM_SENT &&
		    dsmp->dsm_state != INFORMATION &&
		    (plp->opts[CD_LEASE_TIME] == NULL ||
		    plp->opts[CD_LEASE_TIME]->len != sizeof (lease_t))) {
			dhcpmsg(MSG_WARNING, "accept_v4_acknak: ACK packet on "
			    "%s missing mandatory lease option, ignored",
			    dsmp->dsm_name);
			dsmp->dsm_bad_offers++;
			free_pkt_entry(plp);
			return;
		}
		if ((dsmp->dsm_state == RENEWING ||
		    dsmp->dsm_state == REBINDING) &&
		    dsmp->dsm_leases->dl_lifs->lif_addr !=
		    plp->pkt->yiaddr.s_addr) {
			dhcpmsg(MSG_WARNING, "accept_v4_acknak: renewal ACK "
			    "packet has a different IP address (%s), ignored",
			    inet_ntoa(plp->pkt->yiaddr));
			dsmp->dsm_bad_offers++;
			free_pkt_entry(plp);
			return;
		}
	}

	/*
	 * looks good; cancel the retransmission timer and unregister
	 * the acknak handler. ACK to BOUND, NAK back to SELECTING.
	 */

	stop_pkt_retransmission(dsmp);

	if (*plp->opts[CD_DHCP_TYPE]->value == NAK) {
		dhcpmsg(MSG_WARNING, "accept_v4_acknak: NAK on interface %s",
		    dsmp->dsm_name);
		dsmp->dsm_bad_offers++;
		free_pkt_entry(plp);
		dhcp_restart(dsmp);

		/*
		 * remove any bogus cached configuration we might have
		 * around (right now would only happen if we got here
		 * from INIT_REBOOT).
		 */

		(void) remove_hostconf(dsmp->dsm_name, dsmp->dsm_isv6);
		return;
	}

	if (plp->opts[CD_SERVER_ID] == NULL ||
	    plp->opts[CD_SERVER_ID]->len != sizeof (ipaddr_t)) {
		dhcpmsg(MSG_ERROR, "accept_v4_acknak: ACK with no valid "
		    "server id on %s", dsmp->dsm_name);
		dsmp->dsm_bad_offers++;
		free_pkt_entry(plp);
		dhcp_restart(dsmp);
		return;
	}

	if (plp->opts[CD_MESSAGE] != NULL) {
		print_server_msg(dsmp, (char *)plp->opts[CD_MESSAGE]->value,
		    plp->opts[CD_MESSAGE]->len);
	}

	dhcpmsg(MSG_VERBOSE, "accept_v4_acknak: ACK on %s", dsmp->dsm_name);
	if (!dhcp_bound(dsmp, plp)) {
		dhcpmsg(MSG_WARNING, "accept_v4_acknak: dhcp_bound failed "
		    "for %s", dsmp->dsm_name);
		dhcp_restart(dsmp);
	}
}

/*
 * accept_v6_message(): determine what to do with a DHCPv6 message based on the
 *			current state.
 *
 *   input: dhcp_smach_t *: the state machine to handle the message
 *	    PKT_LIST *: the DHCPv6 message
 *	    const char *: type of message (for logging)
 *	    uchar_t: type of message (extracted from packet)
 *  output: void
 */

static void
accept_v6_message(dhcp_smach_t *dsmp, PKT_LIST *plp, const char *pname,
    uchar_t recv_type)
{
	const dhcpv6_option_t *d6o;
	uint_t olen;
	const char *estr, *msg;
	uint_t msglen;
	int status;

	/* Account for received and processed messages */
	dsmp->dsm_received++;

	/* We don't yet support Reconfigure at all. */
	if (recv_type == DHCPV6_MSG_RECONFIGURE) {
		dhcpmsg(MSG_VERBOSE, "accept_v6_message: ignored Reconfigure "
		    "on %s", dsmp->dsm_name);
		free_pkt_entry(plp);
		return;
	}

	/*
	 * All valid DHCPv6 messages must have our Client ID specified.
	 */
	d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_CLIENTID, &olen);
	olen -= sizeof (*d6o);
	if (d6o == NULL || olen != dsmp->dsm_cidlen ||
	    memcmp(d6o + 1, dsmp->dsm_cid, olen) != 0) {
		dhcpmsg(MSG_VERBOSE,
		    "accept_v6_message: discarded %s on %s: %s Client ID",
		    pname, dsmp->dsm_name, d6o == NULL ? "no" : "wrong");
		free_pkt_entry(plp);
		return;
	}

	/*
	 * All valid DHCPv6 messages must have a Server ID specified.
	 *
	 * If this is a Reply and it's not in response to Solicit, Confirm,
	 * Rebind, or Information-Request, then it must also match the Server
	 * ID we're expecting.
	 *
	 * For Reply in the Solicit, Confirm, Rebind, and Information-Request
	 * cases, the Server ID needs to be saved.  This is done inside of
	 * dhcp_bound().
	 */
	d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_SERVERID, &olen);
	if (d6o == NULL) {
		dhcpmsg(MSG_DEBUG,
		    "accept_v6_message: discarded %s on %s: no Server ID",
		    pname, dsmp->dsm_name);
		free_pkt_entry(plp);
		return;
	}
	if (recv_type == DHCPV6_MSG_REPLY && dsmp->dsm_state != SELECTING &&
	    dsmp->dsm_state != INIT_REBOOT && dsmp->dsm_state != REBINDING &&
	    dsmp->dsm_state != INFORM_SENT) {
		olen -= sizeof (*d6o);
		if (olen != dsmp->dsm_serveridlen ||
		    memcmp(d6o + 1, dsmp->dsm_serverid, olen) != 0) {
			dhcpmsg(MSG_DEBUG, "accept_v6_message: discarded %s on "
			    "%s: wrong Server ID", pname, dsmp->dsm_name);
			free_pkt_entry(plp);
			return;
		}
	}

	/*
	 * Break out of the switch if the input message needs to be discarded.
	 * Return from the function if the message has been enqueued or
	 * consumed.
	 */
	switch (dsmp->dsm_state) {
	case SELECTING:
		/* A Reply message signifies a Rapid-Commit. */
		if (recv_type == DHCPV6_MSG_REPLY) {
			if (dhcpv6_pkt_option(plp, NULL,
			    DHCPV6_OPT_RAPID_COMMIT, &olen) == NULL) {
				dhcpmsg(MSG_DEBUG, "accept_v6_message: Reply "
				    "on %s lacks Rapid-Commit; ignoring",
				    dsmp->dsm_name);
				break;
			}
			dhcpmsg(MSG_VERBOSE,
			    "accept_v6_message: rapid-commit Reply on %s",
			    dsmp->dsm_name);
			cancel_offer_timer(dsmp);
			goto rapid_commit;
		}

		/* Otherwise, we're looking for Advertisements. */
		if (recv_type != DHCPV6_MSG_ADVERTISE)
			break;

		/*
		 * Special case: if this advertisement has preference 255, then
		 * we must stop right now and select this server.
		 */
		d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_PREFERENCE,
		    &olen);
		if (d6o != NULL && olen == sizeof (*d6o) + 1 &&
		    *(const uchar_t *)(d6o + 1) == 255) {
			pkt_smach_enqueue(dsmp, plp);
			dhcpmsg(MSG_DEBUG, "accept_v6_message: preference 255;"
			    " immediate Request on %s", dsmp->dsm_name);
			dhcp_requesting(NULL, dsmp);
		} else {
			pkt_smach_enqueue(dsmp, plp);
		}
		return;

	case PRE_BOUND:
	case BOUND:
		/*
		 * Not looking for anything in these states.  (If we
		 * implemented reconfigure, that might go here.)
		 */
		break;

	case REQUESTING:
	case INIT_REBOOT:
	case RENEWING:
	case REBINDING:
	case INFORM_SENT:
		/*
		 * We're looking for Reply messages.
		 */
		if (recv_type != DHCPV6_MSG_REPLY)
			break;
		dhcpmsg(MSG_VERBOSE,
		    "accept_v6_message: received Reply message on %s",
		    dsmp->dsm_name);
	rapid_commit:
		/*
		 * Extract the status code option.  If one is present and the
		 * request failed, then try to go to another advertisement in
		 * the list or restart the selection machinery.
		 */
		d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_STATUS_CODE,
		    &olen);
		status = dhcpv6_status_code(d6o, olen, &estr, &msg, &msglen);
		/*
		 * Check for the UseMulticast status code.  If this is present,
		 * and if we were actually using unicast, then drop back and
		 * try again.  If we weren't using unicast, then just pretend
		 * we never saw this message -- the peer is confused.  (TAHI
		 * does this.)
		 */
		if (status == DHCPV6_STAT_USEMCAST) {
			if (IN6_IS_ADDR_MULTICAST(
			    &dsmp->dsm_send_dest.v6.sin6_addr)) {
				break;
			} else {
				free_pkt_entry(plp);
				dsmp->dsm_send_dest.v6.sin6_addr =
				    ipv6_all_dhcp_relay_and_servers;
				retransmit_now(dsmp);
				return;
			}
		}
		print_server_msg(dsmp, msg, msglen);
		/*
		 * We treat NoBinding at the top level as "success."  Granted,
		 * this doesn't make much sense, but the TAHI test suite does
		 * this.  NoBinding really only makes sense in the context of a
		 * specific IA, as it refers to the GUID:IAID binding, so
		 * ignoring it at the top level is safe.
		 */
		if (status == DHCPV6_STAT_SUCCESS ||
		    status == DHCPV6_STAT_NOBINDING) {
			if (dhcp_bound(dsmp, plp)) {
				/*
				 * dhcp_bound will stop retransmission on
				 * success, if that's called for.
				 */
				server_unicast_option(dsmp, plp);
			} else {
				stop_pkt_retransmission(dsmp);
				dhcpmsg(MSG_WARNING, "accept_v6_message: "
				    "dhcp_bound failed for %s", dsmp->dsm_name);
				(void) remove_hostconf(dsmp->dsm_name,
				    dsmp->dsm_isv6);
				dhcp_restart(dsmp);
			}
		} else {
			dhcpmsg(MSG_WARNING, "accept_v6_message: Reply: %s",
			    estr);
			stop_pkt_retransmission(dsmp);
			free_pkt_entry(plp);
			if (dsmp->dsm_state == INFORM_SENT) {
				(void) set_smach_state(dsmp, INIT);
				ipc_action_finish(dsmp, DHCP_IPC_E_SRVFAILED);
			} else {
				(void) remove_hostconf(dsmp->dsm_name,
				    dsmp->dsm_isv6);
				request_failed(dsmp);
			}
		}
		return;

	case DECLINING:
		/*
		 * We're looking for Reply messages.
		 */
		if (recv_type != DHCPV6_MSG_REPLY)
			break;
		stop_pkt_retransmission(dsmp);
		/*
		 * Extract the status code option.  Note that it's not a
		 * failure if the server reports an error.
		 */
		d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_STATUS_CODE,
		    &olen);
		if (dhcpv6_status_code(d6o, olen, &estr, &msg,
		    &msglen) == DHCPV6_STAT_SUCCESS) {
			print_server_msg(dsmp, msg, msglen);
		} else {
			dhcpmsg(MSG_WARNING, "accept_v6_message: Reply: %s",
			    estr);
		}
		free_pkt_entry(plp);
		if (dsmp->dsm_leases == NULL) {
			dhcpmsg(MSG_VERBOSE, "accept_v6_message: %s has no "
			    "leases left", dsmp->dsm_name);
			dhcp_restart(dsmp);
		} else if (dsmp->dsm_lif_wait == 0) {
			(void) set_smach_state(dsmp, BOUND);
		} else {
			(void) set_smach_state(dsmp, PRE_BOUND);
		}
		return;

	case RELEASING:
		/*
		 * We're looking for Reply messages.
		 */
		if (recv_type != DHCPV6_MSG_REPLY)
			break;
		stop_pkt_retransmission(dsmp);
		/*
		 * Extract the status code option.
		 */
		d6o = dhcpv6_pkt_option(plp, NULL, DHCPV6_OPT_STATUS_CODE,
		    &olen);
		if (dhcpv6_status_code(d6o, olen, &estr, &msg,
		    &msglen) == DHCPV6_STAT_SUCCESS) {
			print_server_msg(dsmp, msg, msglen);
		} else {
			dhcpmsg(MSG_WARNING, "accept_v6_message: Reply: %s",
			    estr);
		}
		free_pkt_entry(plp);
		finished_smach(dsmp, DHCP_IPC_SUCCESS);
		return;
	}

	/*
	 * Break from above switch means that the message must be discarded.
	 */
	dhcpmsg(MSG_VERBOSE,
	    "accept_v6_message: discarded v6 %s on %s; state %s",
	    pname, dsmp->dsm_name, dhcp_state_to_string(dsmp->dsm_state));
	free_pkt_entry(plp);
}

/*
 * dhcp_acknak_global(): Processes reception of an ACK or NAK packet on the
 *			 global socket -- broadcast packets for IPv4, all
 *			 packets for DHCPv6.
 *
 *   input: iu_eh_t *: unused
 *	    int: the global file descriptor the ACK/NAK arrived on
 *	    short: unused
 *	    iu_event_id_t: unused
 *	    void *: unused
 *  output: void
 */

/* ARGSUSED */
void
dhcp_acknak_global(iu_eh_t *ehp, int fd, short events, iu_event_id_t id,
    void *arg)
{
	PKT_LIST	*plp;
	dhcp_pif_t	*pif;
	uchar_t		recv_type;
	const char	*pname;
	uint_t		xid;
	dhcp_smach_t	*dsmp;
	boolean_t	isv6 = (fd == v6_sock_fd);
	struct sockaddr_in sin;
	const char	*reason;
	size_t		sinlen = sizeof (sin);
	int		sock;

	plp = recv_pkt(fd, get_max_mtu(isv6), isv6);
	if (plp == NULL)
		return;

	recv_type = pkt_recv_type(plp);
	pname = pkt_type_to_string(recv_type, isv6);

	/*
	 * Find the corresponding state machine and pif.
	 *
	 * Note that DHCPv6 Reconfigure would be special: it's not the reply to
	 * any transaction, and thus we would need to search on transaction ID
	 * zero (all state machines) to find the match.	 However, Reconfigure
	 * is not yet supported.
	 */
	xid = pkt_get_xid(plp->pkt, isv6);

	for (dsmp = lookup_smach_by_xid(xid, NULL, isv6); dsmp != NULL;
	    dsmp = lookup_smach_by_xid(xid, dsmp, isv6)) {
		pif = dsmp->dsm_lif->lif_pif;
		if (pif->pif_index == plp->ifindex ||
		    pif->pif_under_ipmp && pif->pif_grindex == plp->ifindex)
			break;
	}

	if (dsmp == NULL) {
		dhcpmsg(MSG_VERBOSE, "dhcp_acknak_global: ignored v%d %s packet"
		    " on ifindex %d: unknown state machine", isv6 ? 6 : 4,
		    pname, plp->ifindex);
		free_pkt_entry(plp);
		return;
	}

	if (!isv6 && !pkt_v4_match(recv_type, DHCP_PACK|DHCP_PNAK)) {
		reason = "not ACK or NAK";
		goto drop;
	}

	/*
	 * For IPv4, most packets will be handled by dhcp_packet_lif().  The
	 * only exceptions are broadcast packets sent when lif_sock_ip_fd has
	 * bound to something other than INADDR_ANY.
	 */
	if (!isv6) {
		sock = dsmp->dsm_lif->lif_sock_ip_fd;

		if (getsockname(sock, (struct sockaddr *)&sin, &sinlen) != -1 &&
		    sin.sin_addr.s_addr == INADDR_ANY) {
			reason = "handled by lif_sock_ip_fd";
			goto drop;
		}
	}

	/*
	 * We've got a packet; make sure it's acceptable and cancel the REQUEST
	 * retransmissions.
	 */
	if (isv6)
		accept_v6_message(dsmp, plp, pname, recv_type);
	else
		accept_v4_acknak(dsmp, plp);
	return;
drop:
	dhcpmsg(MSG_VERBOSE, "dhcp_acknak_global: ignored v%d %s packet for %s "
	    "received on global socket: %s", isv6 ? 6 : 4, pname, pif->pif_name,
	    reason);
	free_pkt_entry(plp);
}

/*
 * request_failed(): Attempt to request an address has failed.  Take an
 *		     appropriate action.
 *
 *   input: dhcp_smach_t *: state machine that has failed
 *  output: void
 */

static void
request_failed(dhcp_smach_t *dsmp)
{
	PKT_LIST *offer;

	dsmp->dsm_server = ipv6_all_dhcp_relay_and_servers;
	if ((offer = select_best(dsmp)) != NULL) {
		insque(offer, &dsmp->dsm_recv_pkt_list);
		dhcp_requesting(NULL, dsmp);
	} else {
		dhcpmsg(MSG_INFO, "no offers left on %s; restarting",
		    dsmp->dsm_name);
		dhcp_selecting(dsmp);
	}
}

/*
 * dhcp_packet_lif(): Processes reception of an ACK, NAK, or OFFER packet on
 *		      a given logical interface for IPv4 (only).
 *
 *   input: iu_eh_t *: unused
 *	    int: the file descriptor the packet arrived on
 *	    short: unused
 *	    iu_event_id_t: the id of this event callback with the handler
 *	    void *: pointer to logical interface receiving message
 *  output: void
 */

/* ARGSUSED */
void
dhcp_packet_lif(iu_eh_t *ehp, int fd, short events, iu_event_id_t id,
    void *arg)
{
	dhcp_lif_t	*lif = arg;
	PKT_LIST	*plp;
	uchar_t		recv_type;
	const char	*pname;
	uint_t		xid;
	dhcp_smach_t	*dsmp;

	if ((plp = recv_pkt(fd, lif->lif_max, B_FALSE)) == NULL)
		return;

	recv_type = pkt_recv_type(plp);
	pname = pkt_type_to_string(recv_type, B_FALSE);

	if (!pkt_v4_match(recv_type,
	    DHCP_PACK | DHCP_PNAK | DHCP_PUNTYPED | DHCP_POFFER)) {
		dhcpmsg(MSG_VERBOSE, "dhcp_packet_lif: ignored v4 %s packet "
		    "received via LIF %s", pname, lif->lif_name);
		free_pkt_entry(plp);
		return;
	}

	/*
	 * Find the corresponding state machine.
	 */
	xid = pkt_get_xid(plp->pkt, B_FALSE);
	for (dsmp = lookup_smach_by_xid(xid, NULL, B_FALSE); dsmp != NULL;
	    dsmp = lookup_smach_by_xid(xid, dsmp, B_FALSE)) {
		if (dsmp->dsm_lif == lif)
			break;
	}

	if (dsmp == NULL)
		goto drop;

	if (pkt_v4_match(recv_type, DHCP_PACK|DHCP_PNAK)) {
		/*
		 * We've got an ACK/NAK; make sure it's acceptable and cancel
		 * the REQUEST retransmissions.
		 */
		accept_v4_acknak(dsmp, plp);
	} else {
		if (is_bound_state(dsmp->dsm_state))
			goto drop;
		/*
		 * Must be an OFFER or a BOOTP message: enqueue it for later
		 * processing by select_best().
		 */
		pkt_smach_enqueue(dsmp, plp);
	}
	return;
drop:
	dhcpmsg(MSG_VERBOSE, "dhcp_packet_lif: ignored %s packet xid "
	    "%x received via LIF %s; %s", pname, xid, lif->lif_name,
	    dsmp == NULL ? "unknown state machine" : "bound");
	free_pkt_entry(plp);
}

/*
 * dhcp_restart(): restarts DHCP (from INIT) on a given state machine, but only
 *		   if we're leasing addresses.  Doesn't restart for information-
 *		   only interfaces.
 *
 *   input: dhcp_smach_t *: the state machine to restart DHCP on
 *  output: void
 */

void
dhcp_restart(dhcp_smach_t *dsmp)
{
	if (dsmp->dsm_state == INFORM_SENT || dsmp->dsm_state == INFORMATION)
		return;

	/*
	 * As we're returning to INIT state, we need to discard any leases we
	 * may have, and (for v4) canonize the LIF.  There's a bit of tension
	 * between keeping around a possibly still working address, and obeying
	 * the RFCs.  A more elaborate design would be to mark the addresses as
	 * DEPRECATED, and then start a removal timer.  Such a design would
	 * probably compromise testing.
	 */
	deprecate_leases(dsmp);

	if (!set_start_timer(dsmp)) {
		dhcpmsg(MSG_ERROR, "dhcp_restart: cannot schedule dhcp_start, "
		    "reverting to INIT state on %s", dsmp->dsm_name);

		(void) set_smach_state(dsmp, INIT);
		dsmp->dsm_dflags |= DHCP_IF_FAILED;
		ipc_action_finish(dsmp, DHCP_IPC_E_MEMORY);
	} else {
		dhcpmsg(MSG_DEBUG, "dhcp_restart: restarting DHCP on %s",
		    dsmp->dsm_name);
	}
}

/*
 * stop_requesting(): decides when to stop retransmitting REQUESTs
 *
 *   input: dhcp_smach_t *: the state machine REQUESTs are being sent from
 *	    unsigned int: the number of REQUESTs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

static boolean_t
stop_requesting(dhcp_smach_t *dsmp, unsigned int n_requests)
{
	uint_t maxreq;

	maxreq = dsmp->dsm_isv6 ? DHCPV6_REQ_MAX_RC : DHCP_MAX_REQUESTS;
	if (n_requests >= maxreq) {

		dhcpmsg(MSG_INFO, "no ACK/NAK/Reply to REQUEST on %s",
		    dsmp->dsm_name);

		request_failed(dsmp);
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}
