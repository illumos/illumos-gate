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
 */

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <libinetutil.h>
#include <dhcpmsg.h>
#include <dhcp_hostconf.h>
#include <string.h>

#include "packet.h"
#include "agent.h"
#include "script_handler.h"
#include "interface.h"
#include "states.h"
#include "util.h"

/*
 * Number of seconds to wait for a retry if the user is interacting with the
 * daemon.
 */
#define	RETRY_DELAY	10

/*
 * If the renew timer fires within this number of seconds of the rebind timer,
 * then skip renew.  This prevents us from sending back-to-back renew and
 * rebind messages -- a pointless activity.
 */
#define	TOO_CLOSE	2

static boolean_t stop_extending(dhcp_smach_t *, unsigned int);

/*
 * dhcp_renew(): attempts to renew a DHCP lease on expiration of the T1 timer.
 *
 *   input: iu_tq_t *: unused
 *	    void *: the lease to renew (dhcp_lease_t)
 *  output: void
 *
 *   notes: The primary expense involved with DHCP (like most UDP protocols) is
 *	    with the generation and handling of packets, not the contents of
 *	    those packets.  Thus, we try to reduce the number of packets that
 *	    are sent.  It would be nice to just renew all leases here (each one
 *	    added has trivial added overhead), but the DHCPv6 RFC doesn't
 *	    explicitly allow that behavior.  Rather than having that argument,
 *	    we settle for ones that are close in expiry to the one that fired.
 *	    For v4, we repeatedly reschedule the T1 timer to do the
 *	    retransmissions.  For v6, we rely on the common timer computation
 *	    in packet.c.
 */

/* ARGSUSED */
void
dhcp_renew(iu_tq_t *tqp, void *arg)
{
	dhcp_lease_t *dlp = arg;
	dhcp_smach_t *dsmp = dlp->dl_smach;
	uint32_t	t2;

	dhcpmsg(MSG_VERBOSE, "dhcp_renew: T1 timer expired on %s",
	    dsmp->dsm_name);

	dlp->dl_t1.dt_id = -1;

	if (dsmp->dsm_state == RENEWING || dsmp->dsm_state == REBINDING) {
		dhcpmsg(MSG_DEBUG, "dhcp_renew: already renewing");
		release_lease(dlp);
		return;
	}

	/*
	 * Sanity check: don't send packets if we're past T2, or if we're
	 * extremely close.
	 */

	t2 = dsmp->dsm_curstart_monosec + dlp->dl_t2.dt_start;
	if (monosec() + TOO_CLOSE >= t2) {
		dhcpmsg(MSG_DEBUG, "dhcp_renew: %spast T2 on %s",
		    monosec() > t2 ? "" : "almost ", dsmp->dsm_name);
		release_lease(dlp);
		return;
	}

	/*
	 * If there isn't an async event pending, or if we can cancel the one
	 * that's there, then try to renew by sending an extension request.  If
	 * that fails, we'll try again when the next timer fires.
	 */
	if (!async_cancel(dsmp) || !async_start(dsmp, DHCP_EXTEND, B_FALSE) ||
	    !dhcp_extending(dsmp)) {
		if (monosec() + RETRY_DELAY < t2) {
			/*
			 * Try again in RETRY_DELAY seconds; user command
			 * should be gone.
			 */
			init_timer(&dlp->dl_t1, RETRY_DELAY);
			(void) set_smach_state(dsmp, BOUND);
			if (!schedule_lease_timer(dlp, &dlp->dl_t1,
			    dhcp_renew)) {
				dhcpmsg(MSG_INFO, "dhcp_renew: unable to "
				    "reschedule renewal around user command "
				    "on %s; will wait for rebind",
				    dsmp->dsm_name);
			}
		} else {
			dhcpmsg(MSG_DEBUG, "dhcp_renew: user busy on %s; will "
			    "wait for rebind", dsmp->dsm_name);
		}
	}
	release_lease(dlp);
}

/*
 * dhcp_rebind(): attempts to renew a DHCP lease from the REBINDING state (T2
 *		  timer expiry).
 *
 *   input: iu_tq_t *: unused
 *	    void *: the lease to renew
 *  output: void
 *   notes: For v4, we repeatedly reschedule the T2 timer to do the
 *	    retransmissions.  For v6, we rely on the common timer computation
 *	    in packet.c.
 */

/* ARGSUSED */
void
dhcp_rebind(iu_tq_t *tqp, void *arg)
{
	dhcp_lease_t	*dlp = arg;
	dhcp_smach_t	*dsmp = dlp->dl_smach;
	int		nlifs;
	dhcp_lif_t	*lif;
	boolean_t	some_valid;
	uint32_t	expiremax;
	DHCPSTATE	oldstate;

	dhcpmsg(MSG_VERBOSE, "dhcp_rebind: T2 timer expired on %s",
	    dsmp->dsm_name);

	dlp->dl_t2.dt_id = -1;

	if ((oldstate = dsmp->dsm_state) == REBINDING) {
		dhcpmsg(MSG_DEBUG, "dhcp_renew: already rebinding");
		release_lease(dlp);
		return;
	}

	/*
	 * Sanity check: don't send packets if we've already expired on all of
	 * the addresses.  We compute the maximum expiration time here, because
	 * it won't matter for v4 (there's only one lease) and for v6 we need
	 * to know when the last lease ages away.
	 */

	some_valid = B_FALSE;
	expiremax = monosec();
	lif = dlp->dl_lifs;
	for (nlifs = dlp->dl_nlifs; nlifs > 0; nlifs--, lif = lif->lif_next) {
		uint32_t expire;

		expire = dsmp->dsm_curstart_monosec + lif->lif_expire.dt_start;
		if (expire > expiremax) {
			expiremax = expire;
			some_valid = B_TRUE;
		}
	}
	if (!some_valid) {
		dhcpmsg(MSG_DEBUG, "dhcp_rebind: all leases expired on %s",
		    dsmp->dsm_name);
		release_lease(dlp);
		return;
	}

	/*
	 * This is our first venture into the REBINDING state, so reset the
	 * server address.  We know the renew timer has already been cancelled
	 * (or we wouldn't be here).
	 */
	if (dsmp->dsm_isv6) {
		dsmp->dsm_server = ipv6_all_dhcp_relay_and_servers;
	} else {
		IN6_IPADDR_TO_V4MAPPED(htonl(INADDR_BROADCAST),
		    &dsmp->dsm_server);
	}

	/* {Bound,Renew}->rebind transitions cannot fail */
	(void) set_smach_state(dsmp, REBINDING);

	/*
	 * If there isn't an async event pending, or if we can cancel the one
	 * that's there, then try to rebind by sending an extension request.
	 * If that fails, we'll clean up when the lease expires.
	 */
	if (!async_cancel(dsmp) || !async_start(dsmp, DHCP_EXTEND, B_FALSE) ||
	    !dhcp_extending(dsmp)) {
		if (monosec() + RETRY_DELAY < expiremax) {
			/*
			 * Try again in RETRY_DELAY seconds; user command
			 * should be gone.
			 */
			init_timer(&dlp->dl_t2, RETRY_DELAY);
			(void) set_smach_state(dsmp, oldstate);
			if (!schedule_lease_timer(dlp, &dlp->dl_t2,
			    dhcp_rebind)) {
				dhcpmsg(MSG_INFO, "dhcp_rebind: unable to "
				    "reschedule rebind around user command on "
				    "%s; lease may expire", dsmp->dsm_name);
			}
		} else {
			dhcpmsg(MSG_WARNING, "dhcp_rebind: user busy on %s; "
			    "will expire", dsmp->dsm_name);
		}
	}
	release_lease(dlp);
}

/*
 * dhcp_finish_expire(): finish expiration of a lease after the user script
 *			 runs.  If this is the last lease, then restart DHCP.
 *			 The caller has a reference to the LIF, which will be
 *			 dropped.
 *
 *   input: dhcp_smach_t *: the state machine to be restarted
 *	    void *: logical interface that has expired
 *  output: int: always 1
 */

static int
dhcp_finish_expire(dhcp_smach_t *dsmp, void *arg)
{
	dhcp_lif_t *lif = arg;
	dhcp_lease_t *dlp;

	dhcpmsg(MSG_DEBUG, "lease expired on %s; removing", lif->lif_name);

	dlp = lif->lif_lease;
	unplumb_lif(lif);
	if (dlp->dl_nlifs == 0)
		remove_lease(dlp);
	release_lif(lif);

	/* If some valid leases remain, then drive on */
	if (dsmp->dsm_leases != NULL) {
		dhcpmsg(MSG_DEBUG,
		    "dhcp_finish_expire: some leases remain on %s",
		    dsmp->dsm_name);
		return (1);
	}

	(void) remove_hostconf(dsmp->dsm_name, dsmp->dsm_isv6);

	dhcpmsg(MSG_INFO, "last lease expired on %s -- restarting DHCP",
	    dsmp->dsm_name);

	/*
	 * in the case where the lease is less than DHCP_REBIND_MIN
	 * seconds, we will never enter dhcp_renew() and thus the packet
	 * counters will not be reset.  in that case, reset them here.
	 */

	if (dsmp->dsm_state == BOUND) {
		dsmp->dsm_bad_offers	= 0;
		dsmp->dsm_sent		= 0;
		dsmp->dsm_received	= 0;
	}

	deprecate_leases(dsmp);

	/* reset_smach() in dhcp_selecting() will clean up any leftover state */
	dhcp_selecting(dsmp);

	return (1);
}

/*
 * dhcp_deprecate(): deprecates an address on a given logical interface when
 *		     the preferred lifetime expires.
 *
 *   input: iu_tq_t *: unused
 *	    void *: the logical interface whose lease is expiring
 *  output: void
 */

/* ARGSUSED */
void
dhcp_deprecate(iu_tq_t *tqp, void *arg)
{
	dhcp_lif_t *lif = arg;

	set_lif_deprecated(lif);
	release_lif(lif);
}

/*
 * dhcp_expire(): expires a lease on a given logical interface and, if there
 *		  are no more leases, restarts DHCP.
 *
 *   input: iu_tq_t *: unused
 *	    void *: the logical interface whose lease has expired
 *  output: void
 */

/* ARGSUSED */
void
dhcp_expire(iu_tq_t *tqp, void *arg)
{
	dhcp_lif_t	*lif = arg;
	dhcp_smach_t	*dsmp;
	const char	*event;

	dhcpmsg(MSG_VERBOSE, "dhcp_expire: lease timer expired on %s",
	    lif->lif_name);

	lif->lif_expire.dt_id = -1;
	if (lif->lif_lease == NULL) {
		release_lif(lif);
		return;
	}

	set_lif_deprecated(lif);

	dsmp = lif->lif_lease->dl_smach;

	if (!async_cancel(dsmp)) {

		dhcpmsg(MSG_WARNING,
		    "dhcp_expire: cannot cancel current asynchronous command "
		    "on %s", dsmp->dsm_name);

		/*
		 * Try to schedule ourselves for callback.  We're really
		 * situation-critical here; there's not much hope for us if
		 * this fails.
		 */
		init_timer(&lif->lif_expire, DHCP_EXPIRE_WAIT);
		if (schedule_lif_timer(lif, &lif->lif_expire, dhcp_expire))
			return;

		dhcpmsg(MSG_CRIT, "dhcp_expire: cannot reschedule dhcp_expire "
		    "to get called back, proceeding...");
	}

	if (!async_start(dsmp, DHCP_START, B_FALSE))
		dhcpmsg(MSG_WARNING, "dhcp_expire: cannot start asynchronous "
		    "transaction on %s, continuing...", dsmp->dsm_name);

	/*
	 * Determine if this state machine has any non-expired LIFs left in it.
	 * If it doesn't, then this is an "expire" event.  Otherwise, if some
	 * valid leases remain, it's a "loss" event.  The SOMEEXP case can
	 * occur only with DHCPv6.
	 */
	if (expired_lif_state(dsmp) == DHCP_EXP_SOMEEXP)
		event = EVENT_LOSS6;
	else if (dsmp->dsm_isv6)
		event = EVENT_EXPIRE6;
	else
		event = EVENT_EXPIRE;

	/*
	 * just march on if this fails; at worst someone will be able
	 * to async_start() while we're actually busy with our own
	 * asynchronous transaction.  better than not having a lease.
	 */

	(void) script_start(dsmp, event, dhcp_finish_expire, lif, NULL);
}

/*
 * dhcp_extending(): sends a REQUEST (IPv4 DHCP) or Rebind/Renew (DHCPv6) to
 *		     extend a lease on a given state machine
 *
 *   input: dhcp_smach_t *: the state machine to send the message from
 *  output: boolean_t: B_TRUE if the extension request was sent
 */

boolean_t
dhcp_extending(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t		*dpkt;

	stop_pkt_retransmission(dsmp);

	/*
	 * We change state here because this function is also called when
	 * adopting a lease and on demand by the user.
	 */
	if (dsmp->dsm_state == BOUND) {
		dsmp->dsm_neg_hrtime	= gethrtime();
		dsmp->dsm_bad_offers	= 0;
		dsmp->dsm_sent		= 0;
		dsmp->dsm_received	= 0;
		/* Bound->renew can't fail */
		(void) set_smach_state(dsmp, RENEWING);
	}

	dhcpmsg(MSG_DEBUG, "dhcp_extending: sending request on %s",
	    dsmp->dsm_name);

	if (dsmp->dsm_isv6) {
		dhcp_lease_t *dlp;
		dhcp_lif_t *lif;
		uint_t nlifs;
		uint_t irt, mrt;

		/*
		 * Start constructing the Renew/Rebind message.  Only Renew has
		 * a server ID, as we still think our server might be
		 * reachable.
		 */
		if (dsmp->dsm_state == RENEWING) {
			dpkt = init_pkt(dsmp, DHCPV6_MSG_RENEW);
			(void) add_pkt_opt(dpkt, DHCPV6_OPT_SERVERID,
			    dsmp->dsm_serverid, dsmp->dsm_serveridlen);
			irt = DHCPV6_REN_TIMEOUT;
			mrt = DHCPV6_REN_MAX_RT;
		} else {
			dpkt = init_pkt(dsmp, DHCPV6_MSG_REBIND);
			irt = DHCPV6_REB_TIMEOUT;
			mrt = DHCPV6_REB_MAX_RT;
		}

		/*
		 * Loop over the leases, and add an IA_NA for each and an
		 * IAADDR for each address.
		 */
		for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
			lif = dlp->dl_lifs;
			for (nlifs = dlp->dl_nlifs; nlifs > 0;
			    nlifs--, lif = lif->lif_next) {
				(void) add_pkt_lif(dpkt, lif,
				    DHCPV6_STAT_SUCCESS, NULL);
			}
		}

		/* Add required Option Request option */
		(void) add_pkt_prl(dpkt, dsmp);

		return (send_pkt_v6(dsmp, dpkt, dsmp->dsm_server,
		    stop_extending, irt, mrt));
	} else {
		dhcp_lif_t *lif = dsmp->dsm_lif;
		ipaddr_t server;

		/* assemble the DHCPREQUEST message. */
		dpkt = init_pkt(dsmp, REQUEST);
		dpkt->pkt->ciaddr.s_addr = lif->lif_addr;

		/*
		 * The max dhcp message size option is set to the interface
		 * max, minus the size of the udp and ip headers.
		 */
		(void) add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE,
		    htons(lif->lif_max - sizeof (struct udpiphdr)));
		(void) add_pkt_opt32(dpkt, CD_LEASE_TIME, htonl(DHCP_PERM));

		if (class_id_len != 0) {
			(void) add_pkt_opt(dpkt, CD_CLASS_ID, class_id,
			    class_id_len);
		}
		(void) add_pkt_prl(dpkt, dsmp);
		/*
		 * dsm_reqhost was set for this state machine in
		 * dhcp_selecting() if the REQUEST_HOSTNAME option was set and
		 * a host name was found.
		 */
		if (!dhcp_add_fqdn_opt(dpkt, dsmp) &&
		    dsmp->dsm_reqhost != NULL) {
			(void) add_pkt_opt(dpkt, CD_HOSTNAME, dsmp->dsm_reqhost,
			    strlen(dsmp->dsm_reqhost));
		}
		(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

		IN6_V4MAPPED_TO_IPADDR(&dsmp->dsm_server, server);
		return (send_pkt(dsmp, dpkt, server, stop_extending));
	}
}

/*
 * stop_extending(): decides when to stop retransmitting v4 REQUEST or v6
 *		     Renew/Rebind messages.  If we're renewing, then stop if
 *		     T2 is soon approaching.
 *
 *   input: dhcp_smach_t *: the state machine REQUESTs are being sent from
 *	    unsigned int: the number of REQUESTs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

/* ARGSUSED */
static boolean_t
stop_extending(dhcp_smach_t *dsmp, unsigned int n_requests)
{
	dhcp_lease_t *dlp;

	/*
	 * If we're renewing and rebind time is soon approaching, then don't
	 * schedule
	 */
	if (dsmp->dsm_state == RENEWING) {
		monosec_t t2;

		t2 = 0;
		for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
			if (dlp->dl_t2.dt_start > t2)
				t2 = dlp->dl_t2.dt_start;
		}
		t2 += dsmp->dsm_curstart_monosec;
		if (monosec() + TOO_CLOSE >= t2) {
			dhcpmsg(MSG_DEBUG, "stop_extending: %spast T2 on %s",
			    monosec() > t2 ? "" : "almost ", dsmp->dsm_name);
			return (B_TRUE);
		}
	}

	/*
	 * Note that returning B_TRUE cancels both this transmission and the
	 * one that would occur at dsm_send_timeout, and that for v4 we cut the
	 * time in half for each retransmission.  Thus we check here against
	 * half of the minimum.
	 */
	if (!dsmp->dsm_isv6 &&
	    dsmp->dsm_send_timeout < DHCP_REBIND_MIN * MILLISEC / 2) {
		dhcpmsg(MSG_DEBUG, "stop_extending: next retry would be in "
		    "%d.%03d; stopping", dsmp->dsm_send_timeout / MILLISEC,
		    dsmp->dsm_send_timeout % MILLISEC);
		return (B_TRUE);
	}

	/* Otherwise, w stop only when the next timer (rebind, expire) fires */
	return (B_FALSE);
}
