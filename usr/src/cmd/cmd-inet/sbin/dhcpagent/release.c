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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * DECLINE/RELEASE configuration functionality for the DHCP client.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>
#include <dhcpmsg.h>
#include <dhcp_hostconf.h>
#include <dhcpagent_util.h>

#include "agent.h"
#include "packet.h"
#include "interface.h"
#include "states.h"

static boolean_t stop_release_decline(dhcp_smach_t *, unsigned int);

/*
 * send_declines(): sends a DECLINE message (broadcasted for IPv4) to the
 *		    server to indicate a problem with the offered addresses.
 *		    The failing addresses are removed from the leases.
 *
 *   input: dhcp_smach_t *: the state machine sending DECLINE
 *  output: void
 */

void
send_declines(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t	*dpkt;
	dhcp_lease_t	*dlp, *dlpn;
	uint_t		nlifs;
	dhcp_lif_t	*lif, *lifn;
	boolean_t	got_one;

	/*
	 * Create an empty DECLINE message.  We'll stuff the information into
	 * this message as we find it.
	 */
	if (dsmp->dsm_isv6) {
		if ((dpkt = init_pkt(dsmp, DHCPV6_MSG_DECLINE)) == NULL)
			return;
		(void) add_pkt_opt(dpkt, DHCPV6_OPT_SERVERID,
		    dsmp->dsm_serverid, dsmp->dsm_serveridlen);
	} else {
		ipaddr_t serverip;

		/*
		 * If this ack is from BOOTP, then there's no way to send a
		 * decline.  Note that since we haven't bound yet, we can't
		 * just check the BOOTP flag.
		 */
		if (dsmp->dsm_ack->opts[CD_DHCP_TYPE] == NULL)
			return;

		if ((dpkt = init_pkt(dsmp, DECLINE)) == NULL)
			return;
		IN6_V4MAPPED_TO_IPADDR(&dsmp->dsm_server, serverip);
		(void) add_pkt_opt32(dpkt, CD_SERVER_ID, serverip);
	}

	/*
	 * Loop over the leases, looking for ones with now-broken LIFs.  Add
	 * each one found to the DECLINE message, and remove it from the list.
	 * Also remove any completely declined leases.
	 */
	got_one = B_FALSE;
	for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlpn) {
		dlpn = dlp->dl_next;
		lif = dlp->dl_lifs;
		for (nlifs = dlp->dl_nlifs; nlifs > 0; nlifs--, lif = lifn) {
			lifn = lif->lif_next;
			if (lif->lif_declined != NULL) {
				(void) add_pkt_lif(dpkt, lif,
				    DHCPV6_STAT_UNSPECFAIL, lif->lif_declined);
				unplumb_lif(lif);
				got_one = B_TRUE;
			}
		}
		if (dlp->dl_nlifs == 0)
			remove_lease(dlp);
	}

	if (!got_one)
		return;

	(void) set_smach_state(dsmp, DECLINING);

	if (dsmp->dsm_isv6) {
		(void) send_pkt_v6(dsmp, dpkt, dsmp->dsm_server,
		    stop_release_decline, DHCPV6_DEC_TIMEOUT, 0);
	} else {
		(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

		(void) send_pkt(dsmp, dpkt, htonl(INADDR_BROADCAST), NULL);
	}
}

/*
 * dhcp_release(): sends a RELEASE message to a DHCP server and removes
 *		   the all interfaces for the given state machine from DHCP
 *		   control.  Called back by script handler.
 *
 *   input: dhcp_smach_t *: the state machine to send the RELEASE on and remove
 *	    void *: an optional text explanation to send with the message
 *  output: int: 1 on success, 0 on failure
 */

int
dhcp_release(dhcp_smach_t *dsmp, void *arg)
{
	const char	*msg = arg;
	dhcp_pkt_t	*dpkt;
	dhcp_lease_t	*dlp;
	dhcp_lif_t	*lif;
	ipaddr_t	serverip;
	uint_t		nlifs;

	if ((dsmp->dsm_dflags & DHCP_IF_BOOTP) ||
	    !check_cmd_allowed(dsmp->dsm_state, DHCP_RELEASE)) {
		ipc_action_finish(dsmp, DHCP_IPC_E_INT);
		return (0);
	}

	dhcpmsg(MSG_INFO, "releasing leases for state machine %s",
	    dsmp->dsm_name);
	(void) set_smach_state(dsmp, RELEASING);

	if (dsmp->dsm_isv6) {
		dpkt = init_pkt(dsmp, DHCPV6_MSG_RELEASE);
		(void) add_pkt_opt(dpkt, DHCPV6_OPT_SERVERID,
		    dsmp->dsm_serverid, dsmp->dsm_serveridlen);

		for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
			lif = dlp->dl_lifs;
			for (nlifs = dlp->dl_nlifs; nlifs > 0;
			    nlifs--, lif = lif->lif_next) {
				(void) add_pkt_lif(dpkt, lif,
				    DHCPV6_STAT_SUCCESS, NULL);
			}
		}

		/*
		 * Must kill off the leases before attempting to tell the
		 * server.
		 */
		deprecate_leases(dsmp);

		/*
		 * For DHCPv6, this is a transaction, rather than just a
		 * one-shot message.  When this transaction is done, we'll
		 * finish the invoking async operation.
		 */
		(void) send_pkt_v6(dsmp, dpkt, dsmp->dsm_server,
		    stop_release_decline, DHCPV6_REL_TIMEOUT, 0);
	} else {
		if ((dlp = dsmp->dsm_leases) != NULL && dlp->dl_nlifs > 0) {
			dpkt = init_pkt(dsmp, RELEASE);
			if (msg != NULL) {
				(void) add_pkt_opt(dpkt, CD_MESSAGE, msg,
				    strlen(msg) + 1);
			}
			lif = dlp->dl_lifs;
			(void) add_pkt_lif(dpkt, dlp->dl_lifs, 0, NULL);

			IN6_V4MAPPED_TO_IPADDR(&dsmp->dsm_server, serverip);
			(void) add_pkt_opt32(dpkt, CD_SERVER_ID, serverip);
			(void) add_pkt_opt(dpkt, CD_END, NULL, 0);
			(void) send_pkt(dsmp, dpkt, serverip, NULL);
		}

		/*
		 * XXX this totally sucks, but since udp is best-effort,
		 * without this delay, there's a good chance that the packet
		 * that we just enqueued for sending will get pitched
		 * when we canonize the interface through remove_smach.
		 */

		(void) usleep(500);
		deprecate_leases(dsmp);

		finished_smach(dsmp, DHCP_IPC_SUCCESS);
	}
	return (1);
}

/*
 * dhcp_drop(): drops the interface from DHCP control; callback from script
 *		handler
 *
 *   input: dhcp_smach_t *: the state machine dropping leases
 *	    void *: unused
 *  output: int: always 1
 */

/* ARGSUSED1 */
int
dhcp_drop(dhcp_smach_t *dsmp, void *arg)
{
	dhcpmsg(MSG_INFO, "dropping leases for state machine %s",
	    dsmp->dsm_name);

	if (dsmp->dsm_state == PRE_BOUND || dsmp->dsm_state == BOUND ||
	    dsmp->dsm_state == RENEWING || dsmp->dsm_state == REBINDING) {
		if (dsmp->dsm_dflags & DHCP_IF_BOOTP) {
			dhcpmsg(MSG_INFO,
			    "used bootp; not writing lease file for %s",
			    dsmp->dsm_name);
		} else {
			PKT_LIST *plp[2];
			const char *hcfile;

			hcfile = ifname_to_hostconf(dsmp->dsm_name,
			    dsmp->dsm_isv6);
			plp[0] = dsmp->dsm_ack;
			plp[1] = dsmp->dsm_orig_ack;
			if (write_hostconf(dsmp->dsm_name, plp, 2,
			    monosec_to_time(dsmp->dsm_curstart_monosec),
			    dsmp->dsm_isv6) != -1) {
				dhcpmsg(MSG_DEBUG, "wrote lease to %s", hcfile);
			} else if (errno == EROFS) {
				dhcpmsg(MSG_DEBUG, "%s is on a read-only file "
				    "system; not saving lease", hcfile);
			} else {
				dhcpmsg(MSG_ERR, "cannot write %s (reboot will "
				    "not use cached configuration)", hcfile);
			}
		}
	} else {
		dhcpmsg(MSG_DEBUG, "%s in state %s; not saving lease",
		    dsmp->dsm_name, dhcp_state_to_string(dsmp->dsm_state));
	}
	deprecate_leases(dsmp);
	finished_smach(dsmp, DHCP_IPC_SUCCESS);
	return (1);
}

/*
 * stop_release_decline(): decides when to stop retransmitting RELEASE/DECLINE
 *			   messages for DHCPv6.  When we stop, if there are no
 *			   more leases left, then restart the state machine.
 *
 *   input: dhcp_smach_t *: the state machine messages are being sent from
 *	    unsigned int: the number of messages sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

static boolean_t
stop_release_decline(dhcp_smach_t *dsmp, unsigned int n_requests)
{
	if (dsmp->dsm_state == RELEASING) {
		if (n_requests >= DHCPV6_REL_MAX_RC) {
			dhcpmsg(MSG_INFO, "no Reply to Release, finishing "
			    "transaction on %s", dsmp->dsm_name);
			finished_smach(dsmp, DHCP_IPC_SUCCESS);
			return (B_TRUE);
		} else {
			return (B_FALSE);
		}
	} else {
		if (n_requests >= DHCPV6_DEC_MAX_RC) {
			dhcpmsg(MSG_INFO, "no Reply to Decline on %s",
			    dsmp->dsm_name);

			if (dsmp->dsm_leases == NULL) {
				dhcpmsg(MSG_VERBOSE, "stop_release_decline: "
				    "%s has no leases left", dsmp->dsm_name);
				dhcp_restart(dsmp);
			}
			return (B_TRUE);
		} else {
			return (B_FALSE);
		}
	}
}
