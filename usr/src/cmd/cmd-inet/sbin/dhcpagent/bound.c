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
 * Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
 *
 * BOUND state of the DHCP client state machine.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/sockio.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <search.h>
#include <sys/sysmacros.h>
#include <dhcp_hostconf.h>
#include <dhcpagent_util.h>
#include <dhcpmsg.h>

#include "states.h"
#include "packet.h"
#include "util.h"
#include "agent.h"
#include "interface.h"
#include "script_handler.h"

/*
 * Possible outcomes for IPv6 binding attempt.
 */
enum v6_bind_result {
	v6Restart,		/* report failure and restart state machine */
	v6Resent,		/* new Request message has been sent */
	v6Done			/* successful binding */
};

static enum v6_bind_result configure_v6_leases(dhcp_smach_t *);
static boolean_t configure_v4_lease(dhcp_smach_t *);
static boolean_t configure_v4_timers(dhcp_smach_t *);

/*
 * bound_event_cb(): callback for script_start on the event EVENT_BOUND
 *
 *   input: dhcp_smach_t *: the state machine configured
 *	    void *: unused
 *  output: int: always 1
 */

/* ARGSUSED1 */
static int
bound_event_cb(dhcp_smach_t *dsmp, void *arg)
{
	if (dsmp->dsm_ia.ia_fd != -1)
		ipc_action_finish(dsmp, DHCP_IPC_SUCCESS);
	else
		async_finish(dsmp);
	return (1);
}

/*
 * dhcp_bound(): configures an state machine and interfaces using information
 *		 contained in the ACK/Reply packet and sets up lease timers.
 *		 Before starting, the requested address is verified by
 *		 Duplicate Address Detection to make sure it's not in use.
 *
 *   input: dhcp_smach_t *: the state machine to move to bound
 *	    PKT_LIST *: the ACK/Reply packet, or NULL to use dsmp->dsm_ack
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
dhcp_bound(dhcp_smach_t *dsmp, PKT_LIST *ack)
{
	DHCPSTATE	oldstate;
	lease_t		new_lease;
	dhcp_lif_t	*lif;
	dhcp_lease_t	*dlp;
	enum v6_bind_result v6b;

	if (ack != NULL) {
		/* If ack we're replacing is not the original, then free it */
		if (dsmp->dsm_ack != dsmp->dsm_orig_ack)
			free_pkt_entry(dsmp->dsm_ack);
		dsmp->dsm_ack = ack;
		/* Save the first ack as the original */
		if (dsmp->dsm_orig_ack == NULL)
			dsmp->dsm_orig_ack = ack;

		save_domainname(dsmp, ack);
	}

	oldstate = dsmp->dsm_state;
	switch (oldstate) {

	case ADOPTING:
		/* Note that adoption occurs only for IPv4 DHCP. */

		/* Ignore BOOTP */
		if (ack->opts[CD_DHCP_TYPE] == NULL)
			return (B_FALSE);

		/*
		 * if we're adopting a lease, the lease timers
		 * only provide an upper bound since we don't know
		 * from what time they are relative to.  assume we
		 * have a lease time of at most DHCP_ADOPT_LEASE_MAX.
		 */
		(void) memcpy(&new_lease, ack->opts[CD_LEASE_TIME]->value,
		    sizeof (lease_t));

		new_lease = htonl(MIN(ntohl(new_lease), DHCP_ADOPT_LEASE_MAX));

		(void) memcpy(ack->opts[CD_LEASE_TIME]->value, &new_lease,
		    sizeof (lease_t));

		/*
		 * we have no idea when the REQUEST that generated
		 * this ACK was sent, but for diagnostic purposes
		 * we'll assume its close to the current time.
		 */
		dsmp->dsm_newstart_monosec = monosec();

		if (dsmp->dsm_isv6) {
			if ((v6b = configure_v6_leases(dsmp)) != v6Done)
				return (v6b == v6Resent);
		} else {
			if (!configure_v4_lease(dsmp))
				return (B_FALSE);

			if (!configure_v4_timers(dsmp))
				return (B_FALSE);
		}

		dsmp->dsm_curstart_monosec = dsmp->dsm_newstart_monosec;
		write_lease_to_hostconf(dsmp);
		break;

	case SELECTING:
	case REQUESTING:
	case INIT_REBOOT:

		if (dsmp->dsm_isv6) {
			if ((v6b = configure_v6_leases(dsmp)) != v6Done)
				return (v6b == v6Resent);
		} else {
			if (!configure_v4_lease(dsmp))
				return (B_FALSE);

			if (!configure_v4_timers(dsmp))
				return (B_FALSE);

			if (!clear_lif_deprecated(dsmp->dsm_lif))
				return (B_FALSE);
		}

		/* Stop sending requests now */
		stop_pkt_retransmission(dsmp);

		/*
		 * If we didn't end up with any usable leases, then we have a
		 * problem.
		 */
		if (dsmp->dsm_leases == NULL) {
			dhcpmsg(MSG_WARNING,
			    "dhcp_bound: no address lease established");
			return (B_FALSE);
		}

		/*
		 * If this is a Rapid-Commit (selecting state) or if we're
		 * dealing with a reboot (init-reboot), then we will have a new
		 * server ID to save.
		 */
		if (ack != NULL &&
		    (oldstate == SELECTING || oldstate == INIT_REBOOT) &&
		    dsmp->dsm_isv6 && !save_server_id(dsmp, ack)) {
			dhcpmsg(MSG_ERROR,
			    "dhcp_bound: unable to save server ID on %s",
			    dsmp->dsm_name);
			return (B_FALSE);
		}

		/*
		 * We will continue configuring the interfaces via
		 * dhcp_bound_complete, once kernel DAD completes.  If no new
		 * leases were created (which can happen on an init-reboot used
		 * for link-up confirmation), then go straight to bound state.
		 */
		if (!set_smach_state(dsmp, PRE_BOUND))
			return (B_FALSE);
		if (dsmp->dsm_lif_wait == 0)
			dhcp_bound_complete(dsmp);
		break;

	case PRE_BOUND:
	case BOUND:
	case INFORMATION:
		/* This is just a duplicate ack; silently ignore it */
		return (B_TRUE);

	case RENEWING:
	case REBINDING:

		if (dsmp->dsm_isv6) {
			if ((v6b = configure_v6_leases(dsmp)) != v6Done)
				return (v6b == v6Resent);
		} else {
			if (!configure_v4_timers(dsmp))
				return (B_FALSE);
			if (!clear_lif_deprecated(dsmp->dsm_lif))
				return (B_FALSE);
		}

		/*
		 * If some or all of the leases were torn down by the server,
		 * then handle that as an expiry.  When the script is done
		 * running for the LOSS6 event, we'll end up back here.
		 */
		if ((lif = find_expired_lif(dsmp)) != NULL) {
			hold_lif(lif);
			dhcp_expire(NULL, lif);
			while ((lif = find_expired_lif(dsmp)) != NULL) {
				dlp = lif->lif_lease;
				unplumb_lif(lif);
				if (dlp->dl_nlifs == 0)
					remove_lease(dlp);
			}
			if (dsmp->dsm_leases == NULL)
				return (B_FALSE);
		}

		if (oldstate == REBINDING && dsmp->dsm_isv6 &&
		    !save_server_id(dsmp, ack)) {
			return (B_FALSE);
		}

		/*
		 * Handle Renew/Rebind that fails to address one of our leases.
		 * (Should just never happen, but RFC 3315 section 18.1.8
		 * requires it, and TAHI tests for it.)
		 */
		for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
			if (dlp->dl_stale && dlp->dl_nlifs > 0)
				break;
		}
		if (dlp != NULL) {
			dhcpmsg(MSG_DEBUG, "dhcp_bound: lease not updated; "
			    "allow retransmit");
			return (B_TRUE);
		}

		if (!set_smach_state(dsmp, BOUND))
			return (B_FALSE);

		(void) script_start(dsmp, dsmp->dsm_isv6 ? EVENT_EXTEND6 :
		    EVENT_EXTEND, bound_event_cb, NULL, NULL);

		dsmp->dsm_curstart_monosec = dsmp->dsm_newstart_monosec;
		write_lease_to_hostconf(dsmp);

		/* Stop sending requests now */
		stop_pkt_retransmission(dsmp);
		break;

	case INFORM_SENT:

		if (dsmp->dsm_isv6 && !save_server_id(dsmp, ack)) {
			return (B_FALSE);
		}

		(void) bound_event_cb(dsmp, NULL);
		if (!set_smach_state(dsmp, INFORMATION))
			return (B_FALSE);

		/* Stop sending requests now */
		stop_pkt_retransmission(dsmp);
		break;

	default:
		/* something is really bizarre... */
		dhcpmsg(MSG_DEBUG,
		    "dhcp_bound: called in unexpected state: %s",
		    dhcp_state_to_string(dsmp->dsm_state));
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * dhcp_bound_complete(): complete interface configuration after DAD
 *
 *   input: dhcp_smach_t *: the state machine now ready
 *  output: none
 */

void
dhcp_bound_complete(dhcp_smach_t *dsmp)
{
	PKT_LIST	*ack;
	DHCP_OPT	*router_list;
	int		i;
	DHCPSTATE	oldstate;
	dhcp_lif_t	*lif;

	/*
	 * Do bound state entry processing only if running IPv4.  There's no
	 * need for this with DHCPv6 because link-locals are used for I/O and
	 * because DHCPv6 isn't entangled with routing.
	 */
	if (dsmp->dsm_isv6) {
		(void) set_smach_state(dsmp, BOUND);
		dhcpmsg(MSG_DEBUG, "dhcp_bound_complete: bound %s",
		    dsmp->dsm_name);
		(void) script_start(dsmp, EVENT_BOUND6, bound_event_cb, NULL,
		    NULL);
		dsmp->dsm_curstart_monosec = dsmp->dsm_newstart_monosec;
		write_lease_to_hostconf(dsmp);
		return;
	}

	/*
	 * Add each provided router; we'll clean them up when the
	 * state machine goes away or when our lease expires.
	 *
	 * Note that we do not handle default routers on IPv4 logicals;
	 * see README for details.
	 */

	ack = dsmp->dsm_ack;
	router_list = ack->opts[CD_ROUTER];
	for (i = 0; i < dsmp->dsm_pillen; i++) {
		if (dsmp->dsm_pil[i] == CD_ROUTER)
			router_list = NULL;
	}
	lif = dsmp->dsm_lif;
	if (router_list != NULL &&
	    (router_list->len % sizeof (ipaddr_t)) == 0 &&
	    strchr(lif->lif_name, ':') == NULL &&
	    !lif->lif_pif->pif_under_ipmp) {

		dsmp->dsm_nrouters = router_list->len / sizeof (ipaddr_t);
		dsmp->dsm_routers  = malloc(router_list->len);
		if (dsmp->dsm_routers == NULL) {
			dhcpmsg(MSG_ERR, "dhcp_bound_complete: cannot allocate "
			    "default router list, ignoring default routers");
			dsmp->dsm_nrouters = 0;
		}

		for (i = 0; i < dsmp->dsm_nrouters; i++) {

			(void) memcpy(&dsmp->dsm_routers[i].s_addr,
			    router_list->value + (i * sizeof (ipaddr_t)),
			    sizeof (ipaddr_t));

			if (!add_default_route(lif->lif_pif->pif_index,
			    &dsmp->dsm_routers[i])) {
				dhcpmsg(MSG_ERR, "dhcp_bound_complete: cannot "
				    "add default router %s on %s", inet_ntoa(
				    dsmp->dsm_routers[i]), dsmp->dsm_name);
				dsmp->dsm_routers[i].s_addr = htonl(INADDR_ANY);
				continue;
			}

			dhcpmsg(MSG_INFO, "added default router %s on %s",
			    inet_ntoa(dsmp->dsm_routers[i]), dsmp->dsm_name);
		}
	}

	oldstate = dsmp->dsm_state;
	if (!set_smach_state(dsmp, BOUND)) {
		dhcpmsg(MSG_ERR,
		    "dhcp_bound_complete: cannot set bound state on %s",
		    dsmp->dsm_name);
		return;
	}

	dhcpmsg(MSG_DEBUG, "dhcp_bound_complete: bound %s", dsmp->dsm_name);

	/*
	 * We're now committed to this binding, so if it came from BOOTP, set
	 * the flag.
	 */

	if (ack->opts[CD_DHCP_TYPE] == NULL)
		dsmp->dsm_dflags |= DHCP_IF_BOOTP;

	/*
	 * If the previous state was ADOPTING, event loop has not been started
	 * at this time; so don't run the EVENT_BOUND script.
	 */
	if (oldstate != ADOPTING) {
		(void) script_start(dsmp, EVENT_BOUND, bound_event_cb, NULL,
		    NULL);
	}

	dsmp->dsm_curstart_monosec = dsmp->dsm_newstart_monosec;
	write_lease_to_hostconf(dsmp);
}

/*
 * fuzzify(): adds some "fuzz" to a t1/t2 time, in accordance with RFC2131.
 *	      We use up to plus or minus 2% jitter in the time.  This is a
 *	      small value, but the timers involved are typically long.  A
 *	      common T1 value is one day, and the fuzz is up to 28.8 minutes;
 *	      plenty of time to make sure that individual clients don't renew
 *	      all at the same time.
 *
 *   input: uint32_t: the number of seconds until lease expiration
 *	    double: the approximate percentage of that time to return
 *  output: double: a number approximating (sec * pct)
 */

static double
fuzzify(uint32_t sec, double pct)
{
	return (sec * (pct + (drand48() - 0.5) / 25.0));
}

/*
 * get_pkt_times(): pulls the lease times out of a v4 DHCP packet and stores
 *		    them as host byte-order relative times in the passed in
 *		    parameters.
 *
 *   input: PKT_LIST *: the packet to pull the packet times from
 *	    lease_t *: where to store the relative lease time in hbo
 *	    lease_t *: where to store the relative t1 time in hbo
 *	    lease_t *: where to store the relative t2 time in hbo
 *  output: void
 */

static void
get_pkt_times(PKT_LIST *ack, lease_t *lease, lease_t *t1, lease_t *t2)
{
	*lease	= DHCP_PERM;
	*t1	= DHCP_PERM;
	*t2	= DHCP_PERM;

	if (ack->opts[CD_DHCP_TYPE] == NULL) {
		dhcpmsg(MSG_VERBOSE,
		    "get_pkt_times: BOOTP response; infinite lease");
		return;
	}
	if (ack->opts[CD_LEASE_TIME] == NULL) {
		dhcpmsg(MSG_VERBOSE,
		    "get_pkt_times: no lease option provided");
		return;
	}
	if (ack->opts[CD_LEASE_TIME]->len != sizeof (lease_t)) {
		dhcpmsg(MSG_VERBOSE, "get_pkt_times: invalid lease option");
	}

	(void) memcpy(lease, ack->opts[CD_LEASE_TIME]->value, sizeof (lease_t));
	*lease = ntohl(*lease);

	if (*lease == DHCP_PERM) {
		dhcpmsg(MSG_VERBOSE, "get_pkt_times: infinite lease granted");
		return;
	}

	if (ack->opts[CD_T1_TIME] != NULL &&
	    ack->opts[CD_T1_TIME]->len == sizeof (lease_t)) {
		(void) memcpy(t1, ack->opts[CD_T1_TIME]->value, sizeof (*t1));
		*t1 = ntohl(*t1);
	}

	if (ack->opts[CD_T2_TIME] != NULL &&
	    ack->opts[CD_T2_TIME]->len == sizeof (lease_t)) {
		(void) memcpy(t2, ack->opts[CD_T2_TIME]->value, sizeof (*t2));
		*t2 = ntohl(*t2);
	}

	if ((*t1 == DHCP_PERM) || (*t1 >= *lease))
		*t1 = (lease_t)fuzzify(*lease, DHCP_T1_FACT);

	if ((*t2 == DHCP_PERM) || (*t2 > *lease) || (*t2 <= *t1))
		*t2 = (lease_t)fuzzify(*lease, DHCP_T2_FACT);

	dhcpmsg(MSG_VERBOSE, "get_pkt_times: lease %u t1 %u t2 %u",
	    *lease, *t1, *t2);
}

/*
 * configure_v4_timers(): configures the lease timers on a v4 state machine
 *
 *   input: dhcp_smach_t *: the state machine to configure
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

static boolean_t
configure_v4_timers(dhcp_smach_t *dsmp)
{
	PKT_LIST	*ack = dsmp->dsm_ack;
	lease_t		lease, t1, t2;
	dhcp_lease_t	*dlp;
	dhcp_lif_t	*lif;

	/* v4 has just one lease per state machine, and one LIF */
	dlp = dsmp->dsm_leases;
	lif = dlp->dl_lifs;

	/*
	 * If it's DHCP, but there's no valid lease time, then complain,
	 * decline the lease and return error.
	 */
	if (ack->opts[CD_DHCP_TYPE] != NULL &&
	    (ack->opts[CD_LEASE_TIME] == NULL ||
	    ack->opts[CD_LEASE_TIME]->len != sizeof (lease_t))) {
		lif_mark_decline(lif, "Missing or corrupted lease time");
		send_declines(dsmp);
		dhcpmsg(MSG_WARNING, "configure_v4_timers: %s lease time in "
		    "ACK on %s", ack->opts[CD_LEASE_TIME] == NULL ? "missing" :
		    "corrupt", dsmp->dsm_name);
		return (B_FALSE);
	}

	/* Stop the T1 and T2 timers */
	cancel_lease_timers(dlp);

	/* Stop the LEASE timer */
	cancel_lif_timers(lif);

	/*
	 * type has already been verified as ACK.  if type is not set,
	 * then we got a BOOTP packet.  we now fetch the t1, t2, and
	 * lease options out of the packet into variables.  they are
	 * returned as relative host-byte-ordered times.
	 */

	get_pkt_times(ack, &lease, &t1, &t2);

	/*
	 * if the current lease is mysteriously close to the new
	 * lease, warn the user.  unless there's less than a minute
	 * left, round to the closest minute.
	 */

	if (lif->lif_expire.dt_start != 0 &&
	    abs((dsmp->dsm_newstart_monosec + lease) -
	    (dsmp->dsm_curstart_monosec + lif->lif_expire.dt_start)) <
	    DHCP_LEASE_EPS) {
		const char *noext = "configure_v4_timers: lease renewed but "
		    "time not extended";
		int msg_level;
		uint_t minleft;

		if (lif->lif_expire.dt_start < DHCP_LEASE_ERROR_THRESH)
			msg_level = MSG_ERROR;
		else
			msg_level = MSG_VERBOSE;

		minleft = (lif->lif_expire.dt_start + 30) / 60;

		if (lif->lif_expire.dt_start < 60) {
			dhcpmsg(msg_level, "%s; expires in %d seconds",
			    noext, lif->lif_expire.dt_start);
		} else if (minleft == 1) {
			dhcpmsg(msg_level, "%s; expires in 1 minute", noext);
		} else if (minleft > 120) {
			dhcpmsg(msg_level, "%s; expires in %d hours",
			    noext, (minleft + 30) / 60);
		} else {
			dhcpmsg(msg_level, "%s; expires in %d minutes",
			    noext, minleft);
		}
	}

	init_timer(&dlp->dl_t1, t1);
	init_timer(&dlp->dl_t2, t2);
	init_timer(&lif->lif_expire, lease);

	if (lease == DHCP_PERM) {
		dhcpmsg(MSG_INFO,
		    "configure_v4_timers: %s acquired permanent lease",
		    dsmp->dsm_name);
		return (B_TRUE);
	}

	dhcpmsg(MSG_INFO, "configure_v4_timers: %s acquired lease, expires %s",
	    dsmp->dsm_name,
	    monosec_to_string(dsmp->dsm_newstart_monosec + lease));

	dhcpmsg(MSG_INFO, "configure_v4_timers: %s begins renewal at %s",
	    dsmp->dsm_name, monosec_to_string(dsmp->dsm_newstart_monosec +
	    dlp->dl_t1.dt_start));

	dhcpmsg(MSG_INFO, "configure_v4_timers: %s begins rebinding at %s",
	    dsmp->dsm_name, monosec_to_string(dsmp->dsm_newstart_monosec +
	    dlp->dl_t2.dt_start));

	/*
	 * according to RFC2131, there is no minimum lease time, but don't
	 * set up renew/rebind timers if lease is shorter than DHCP_REBIND_MIN.
	 */

	if (!schedule_lif_timer(lif, &lif->lif_expire, dhcp_expire))
		goto failure;

	if (lease < DHCP_REBIND_MIN) {
		dhcpmsg(MSG_WARNING, "configure_v4_timers: lease on %s is for "
		    "less than %d seconds!", dsmp->dsm_name, DHCP_REBIND_MIN);
		return (B_TRUE);
	}

	if (!schedule_lease_timer(dlp, &dlp->dl_t1, dhcp_renew))
		goto failure;

	if (!schedule_lease_timer(dlp, &dlp->dl_t2, dhcp_rebind))
		goto failure;

	return (B_TRUE);

failure:
	cancel_lease_timers(dlp);
	cancel_lif_timers(lif);
	dhcpmsg(MSG_WARNING,
	    "configure_v4_timers: cannot schedule lease timers");
	return (B_FALSE);
}

/*
 * configure_v6_leases(): configures the IPv6 leases on a state machine from
 *			  the current DHCPv6 ACK.  We need to scan the ACK,
 *			  create a lease for each IA_NA, and a new LIF for each
 *			  IAADDR.
 *
 *   input: dhcp_smach_t *: the machine to configure (with a valid dsm_ack)
 *  output: enum v6_bind_result: restart, resend, or done
 */

static enum v6_bind_result
configure_v6_leases(dhcp_smach_t *dsmp)
{
	const dhcpv6_option_t *d6o, *d6so, *d6sso;
	const char *optbase, *estr, *msg;
	uint_t olen, solen, ssolen, msglen;
	dhcpv6_ia_na_t d6in;
	dhcpv6_iaaddr_t d6ia;
	dhcp_lease_t *dlp;
	uint32_t shortest;
	dhcp_lif_t *lif;
	uint_t nlifs;
	boolean_t got_iana = B_FALSE;
	uint_t scode;

	for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next)
		dlp->dl_stale = B_TRUE;

	d6o = NULL;
	while ((d6o = dhcpv6_pkt_option(dsmp->dsm_ack, d6o, DHCPV6_OPT_IA_NA,
	    &olen)) != NULL) {
		if (olen < sizeof (d6in)) {
			dhcpmsg(MSG_WARNING,
			    "configure_v6_leases: garbled IA_NA");
			continue;
		}

		/*
		 * Check the IAID.  It should be for our controlling LIF.  If a
		 * single state machine needs to use multiple IAIDs, then this
		 * will need to change.
		 */
		(void) memcpy(&d6in, d6o, sizeof (d6in));
		d6in.d6in_iaid = ntohl(d6in.d6in_iaid);
		if (d6in.d6in_iaid != dsmp->dsm_lif->lif_iaid) {
			dhcpmsg(MSG_WARNING, "configure_v6_leases: ignored "
			    "IA_NA for IAID %x (not %x)", d6in.d6in_iaid,
			    dsmp->dsm_lif->lif_iaid);
			continue;
		}

		/*
		 * See notes below; there's only one IA_NA and a single IAID
		 * for now.
		 */
		if ((dlp = dsmp->dsm_leases) != NULL)
			dlp->dl_stale = B_FALSE;

		/*
		 * Note that some bug-ridden servers will try to give us
		 * multiple IA_NA options for a single IAID.  We ignore
		 * duplicates.
		 */
		if (got_iana) {
			dhcpmsg(MSG_WARNING, "configure_v6_leases: unexpected "
			    "extra IA_NA ignored");
			continue;
		}

		d6in.d6in_t1 = ntohl(d6in.d6in_t1);
		d6in.d6in_t2 = ntohl(d6in.d6in_t2);

		/* RFC 3315 required check for invalid T1/T2 combinations */
		if (d6in.d6in_t1 > d6in.d6in_t2 && d6in.d6in_t2 != 0) {
			dhcpmsg(MSG_WARNING, "configure_v6_leases: ignored "
			    "IA_NA with invalid T1 %u > T2 %u", d6in.d6in_t1,
			    d6in.d6in_t2);
			continue;
		}

		/*
		 * There may be a status code here.  Process if present.
		 */
		optbase = (const char *)d6o + sizeof (d6in);
		olen -= sizeof (d6in);
		d6so = dhcpv6_find_option(optbase, olen, NULL,
		    DHCPV6_OPT_STATUS_CODE, &solen);
		scode = dhcpv6_status_code(d6so, solen, &estr, &msg, &msglen);
		if (scode != DHCPV6_STAT_SUCCESS) {
			dhcpmsg(MSG_WARNING,
			    "configure_v6_leases: IA_NA: %s: %.*s",
			    estr, msglen, msg);
		}
		print_server_msg(dsmp, msg, msglen);

		/*
		 * Other errors are possible here.  According to RFC 3315
		 * section 18.1.8, we ignore the entire IA if it gives the "no
		 * addresses" status code.  We may try another server if we
		 * like -- we instead opt to allow the addresses to expire and
		 * then try a new server.
		 *
		 * If the status code is "no binding," then we must go back and
		 * redo the Request.  Surprisingly, it doesn't matter if it's
		 * any other code.
		 */
		if (scode == DHCPV6_STAT_NOADDRS) {
			dhcpmsg(MSG_DEBUG, "configure_v6_leases: ignoring "
			    "no-addrs status in IA_NA");
			continue;
		}

		if (scode == DHCPV6_STAT_NOBINDING) {
			send_v6_request(dsmp);
			return (v6Resent);
		}

		/*
		 * Find or create the lease structure.  This part is simple,
		 * because we support only IA_NA and a single IAID.  This means
		 * there's only one lease structure.  The design supports
		 * multiple lease structures so that IA_TA and IA_PD can be
		 * added later.
		 */
		if ((dlp = dsmp->dsm_leases) == NULL &&
		    (dlp = insert_lease(dsmp)) == NULL) {
			dhcpmsg(MSG_ERROR, "configure_v6_leases: unable to "
			    "allocate memory for lease");
			return (v6Restart);
		}

		/*
		 * Iterate over the IAADDR options contained within this IA_NA.
		 */
		shortest = DHCPV6_INFTIME;
		d6so = NULL;
		while ((d6so = dhcpv6_find_option(optbase, olen, d6so,
		    DHCPV6_OPT_IAADDR, &solen)) != NULL) {
			if (solen < sizeof (d6ia)) {
				dhcpmsg(MSG_WARNING,
				    "configure_v6_leases: garbled IAADDR");
				continue;
			}
			(void) memcpy(&d6ia, d6so, sizeof (d6ia));

			d6ia.d6ia_preflife = ntohl(d6ia.d6ia_preflife);
			d6ia.d6ia_vallife = ntohl(d6ia.d6ia_vallife);

			/* RFC 3315 required validity check */
			if (d6ia.d6ia_preflife > d6ia.d6ia_vallife) {
				dhcpmsg(MSG_WARNING,
				    "configure_v6_leases: ignored IAADDR with "
				    "preferred lifetime %u > valid %u",
				    d6ia.d6ia_preflife, d6ia.d6ia_vallife);
				continue;
			}

			/*
			 * RFC 3315 allows a status code to be buried inside
			 * the IAADDR option.  Look for it, and process if
			 * present.  Process in a manner similar to that for
			 * the IA itself; TAHI checks for this.  Real servers
			 * likely won't do this.
			 */
			d6sso = dhcpv6_find_option((const char *)d6so +
			    sizeof (d6ia), solen - sizeof (d6ia), NULL,
			    DHCPV6_OPT_STATUS_CODE, &ssolen);
			scode = dhcpv6_status_code(d6sso, ssolen, &estr, &msg,
			    &msglen);
			print_server_msg(dsmp, msg, msglen);
			if (scode == DHCPV6_STAT_NOADDRS) {
				dhcpmsg(MSG_DEBUG, "configure_v6_leases: "
				    "ignoring no-addrs status in IAADDR");
				continue;
			}
			if (scode == DHCPV6_STAT_NOBINDING) {
				send_v6_request(dsmp);
				return (v6Resent);
			}
			if (scode != DHCPV6_STAT_SUCCESS) {
				dhcpmsg(MSG_WARNING,
				    "configure_v6_leases: IAADDR: %s", estr);
			}

			/*
			 * Locate the existing LIF within the lease associated
			 * with this address, if any.
			 */
			lif = dlp->dl_lifs;
			for (nlifs = dlp->dl_nlifs; nlifs > 0;
			    nlifs--, lif = lif->lif_next) {
				if (IN6_ARE_ADDR_EQUAL(&d6ia.d6ia_addr,
				    &lif->lif_v6addr))
					break;
			}

			/*
			 * If the server has set the lifetime to zero, then
			 * delete the LIF.  Otherwise, set the new LIF expiry
			 * time, adding the LIF if necessary.
			 */
			if (d6ia.d6ia_vallife == 0) {
				/* If it was found, then it's expired */
				if (nlifs != 0) {
					dhcpmsg(MSG_DEBUG,
					    "configure_v6_leases: lif %s has "
					    "expired", lif->lif_name);
					lif->lif_expired = B_TRUE;
				}
				continue;
			}

			/* If it wasn't found, then create it now. */
			if (nlifs == 0) {
				lif = plumb_lif(dsmp->dsm_lif->lif_pif,
				    &d6ia.d6ia_addr);
				if (lif == NULL)
					continue;
				if (++dlp->dl_nlifs == 1) {
					dlp->dl_lifs = lif;
				} else {
					remque(lif);
					insque(lif, dlp->dl_lifs);
				}
				lif->lif_lease = dlp;
				lif->lif_dad_wait = _B_TRUE;
				dsmp->dsm_lif_wait++;
			} else {
				/* If it was found, cancel timer */
				cancel_lif_timers(lif);
				if (d6ia.d6ia_preflife != 0 &&
				    !clear_lif_deprecated(lif)) {
					unplumb_lif(lif);
					continue;
				}
			}

			/* Set the new expiry timers */
			init_timer(&lif->lif_preferred, d6ia.d6ia_preflife);
			init_timer(&lif->lif_expire, d6ia.d6ia_vallife);

			/*
			 * If the preferred lifetime is over now, then the LIF
			 * is deprecated.  If it's the same as the expiry time,
			 * then we don't need a separate timer for it.
			 */
			if (d6ia.d6ia_preflife == 0) {
				set_lif_deprecated(lif);
			} else if (d6ia.d6ia_preflife != DHCPV6_INFTIME &&
			    d6ia.d6ia_preflife != d6ia.d6ia_vallife &&
			    !schedule_lif_timer(lif, &lif->lif_preferred,
			    dhcp_deprecate)) {
				unplumb_lif(lif);
				continue;
			}

			if (d6ia.d6ia_vallife != DHCPV6_INFTIME &&
			    !schedule_lif_timer(lif, &lif->lif_expire,
			    dhcp_expire)) {
				unplumb_lif(lif);
				continue;
			}

			if (d6ia.d6ia_preflife < shortest)
				shortest = d6ia.d6ia_preflife;
		}

		if (dlp->dl_nlifs == 0) {
			dhcpmsg(MSG_WARNING,
			    "configure_v6_leases: no IAADDRs found in IA_NA");
			remove_lease(dlp);
			continue;
		}

		if (d6in.d6in_t1 == 0 && d6in.d6in_t2 == 0) {
			/* Default values from RFC 3315: 0.5 and 0.8 */
			if ((d6in.d6in_t1 = shortest / 2) == 0)
				d6in.d6in_t1 = 1;
			d6in.d6in_t2 = shortest - shortest / 5;
		}

		cancel_lease_timers(dlp);
		init_timer(&dlp->dl_t1, d6in.d6in_t1);
		init_timer(&dlp->dl_t2, d6in.d6in_t2);

		if ((d6in.d6in_t1 != DHCPV6_INFTIME &&
		    !schedule_lease_timer(dlp, &dlp->dl_t1, dhcp_renew)) ||
		    (d6in.d6in_t2 != DHCPV6_INFTIME &&
		    !schedule_lease_timer(dlp, &dlp->dl_t2, dhcp_rebind))) {
			dhcpmsg(MSG_WARNING, "configure_v6_leases: unable to "
			    "set renew/rebind timers");
		} else {
			got_iana = B_TRUE;
		}
	}

	if (!got_iana) {
		dhcpmsg(MSG_WARNING,
		    "configure_v6_leases: no usable IA_NA option found");
	}

	return (v6Done);
}

/*
 * configure_v4_lease(): configures the IPv4 lease on a state machine from
 *			 the current DHCP ACK.  There's only one lease and LIF
 *			 per state machine in IPv4.
 *
 *   input: dhcp_smach_t *: the machine to configure (with a valid dsm_ack)
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

static boolean_t
configure_v4_lease(dhcp_smach_t *dsmp)
{
	struct lifreq		lifr;
	struct sockaddr_in	*sin;
	PKT_LIST		*ack = dsmp->dsm_ack;
	dhcp_lease_t		*dlp;
	dhcp_lif_t		*lif;
	uint32_t		addrhbo;
	struct in_addr		inaddr;

	/*
	 * if we're using DHCP, then we'll have a valid CD_SERVER_ID
	 * (we checked in dhcp_acknak()); set it now so that
	 * dsmp->dsm_server is valid in case we need to send_decline().
	 * note that we use comparisons against opts[CD_DHCP_TYPE]
	 * since we haven't set DHCP_IF_BOOTP yet (we don't do that
	 * until we're sure we want the offered address.)
	 */

	if (ack->opts[CD_DHCP_TYPE] != NULL) {
		(void) memcpy(&inaddr, ack->opts[CD_SERVER_ID]->value,
		    sizeof (inaddr));
		IN6_INADDR_TO_V4MAPPED(&inaddr, &dsmp->dsm_server);
	}

	/*
	 * There needs to be exactly one lease for IPv4, and that lease
	 * controls the main LIF for the state machine.  If it doesn't exist
	 * yet, then create it now.
	 */
	if ((dlp = dsmp->dsm_leases) == NULL &&
	    (dlp = insert_lease(dsmp)) == NULL) {
		dhcpmsg(MSG_ERROR, "configure_v4_lease: unable to allocate "
		    "memory for lease");
		return (B_FALSE);
	}
	if (dlp->dl_nlifs == 0) {
		dlp->dl_lifs = dsmp->dsm_lif;
		dlp->dl_nlifs = 1;

		/* The lease holds a reference on the LIF */
		hold_lif(dlp->dl_lifs);
		dlp->dl_lifs->lif_lease = dlp;
	}

	lif = dlp->dl_lifs;

	IN6_INADDR_TO_V4MAPPED(&ack->pkt->yiaddr, &lif->lif_v6addr);
	addrhbo = ntohl(ack->pkt->yiaddr.s_addr);
	if ((addrhbo & IN_CLASSA_NET) == 0 ||
	    (addrhbo >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    IN_CLASSD(addrhbo)) {
		dhcpmsg(MSG_ERROR,
		    "configure_v4_lease: got invalid IP address %s for %s",
		    inet_ntoa(ack->pkt->yiaddr), lif->lif_name);
		return (B_FALSE);
	}

	(void) memset(&lifr, 0, sizeof (struct lifreq));
	(void) strlcpy(lifr.lifr_name, lif->lif_name, LIFNAMSIZ);

	/*
	 * bring the interface online.  note that there is no optimal
	 * order here: it is considered bad taste (and in > solaris 7,
	 * likely illegal) to bring an interface up before it has an
	 * ip address.  however, due to an apparent bug in sun fddi
	 * 5.0, fddi will not obtain a network routing entry unless
	 * the interface is brought up before it has an ip address.
	 * we take the lesser of the two evils; if fddi customers have
	 * problems, they can get a newer fddi distribution which
	 * fixes the problem.
	 */

	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	sin->sin_family = AF_INET;

	(void) memset(&lif->lif_v6mask, 0xff, sizeof (lif->lif_v6mask));
	if (ack->opts[CD_SUBNETMASK] != NULL &&
	    ack->opts[CD_SUBNETMASK]->len == sizeof (inaddr)) {

		(void) memcpy(&inaddr, ack->opts[CD_SUBNETMASK]->value,
		    sizeof (inaddr));

	} else {

		if (ack->opts[CD_SUBNETMASK] != NULL &&
		    ack->opts[CD_SUBNETMASK]->len != sizeof (inaddr)) {
			dhcpmsg(MSG_WARNING, "configure_v4_lease: specified "
			    "subnet mask length is %d instead of %d, ignoring",
			    ack->opts[CD_SUBNETMASK]->len, sizeof (ipaddr_t));
		} else {
			dhcpmsg(MSG_WARNING, "configure_v4_lease: no IP "
			    "netmask specified for %s, making best guess",
			    lif->lif_name);
		}

		/*
		 * no legitimate IP subnet mask specified..  use best
		 * guess.  recall that lif_addr is in network order, so
		 * imagine it's 0x11223344: then when it is read into
		 * a register on x86, it becomes 0x44332211, so we
		 * must ntohl() it to convert it to 0x11223344 in
		 * order to use the macros in <netinet/in.h>.
		 */

		if (IN_CLASSA(addrhbo))
			inaddr.s_addr = htonl(IN_CLASSA_NET);
		else if (IN_CLASSB(addrhbo))
			inaddr.s_addr = htonl(IN_CLASSB_NET);
		else if (IN_CLASSC(addrhbo))
			inaddr.s_addr = htonl(IN_CLASSC_NET);
		else {
			/*
			 * Cant be Class D as that is multicast
			 * Must be Class E
			 */
			inaddr.s_addr =  htonl(IN_CLASSE_NET);
		}
	}
	lif->lif_v6mask._S6_un._S6_u32[3] = inaddr.s_addr;

	sin->sin_addr = inaddr;
	dhcpmsg(MSG_INFO, "configure_v4_lease: setting IP netmask to %s on %s",
	    inet_ntoa(sin->sin_addr), lif->lif_name);

	if (ioctl(v4_sock_fd, SIOCSLIFNETMASK, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_v4_lease: cannot set IP netmask "
		    "on %s", lif->lif_name);
		return (B_FALSE);
	}

	IN6_V4MAPPED_TO_INADDR(&lif->lif_v6addr, &sin->sin_addr);
	dhcpmsg(MSG_INFO, "configure_v4_lease: setting IP address to %s on %s",
	    inet_ntoa(sin->sin_addr), lif->lif_name);

	if (ioctl(v4_sock_fd, SIOCSLIFADDR, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_v4_lease: cannot set IP address "
		    "on %s", lif->lif_name);
		return (B_FALSE);
	}

	if (!lif->lif_dad_wait) {
		lif->lif_dad_wait = _B_TRUE;
		dsmp->dsm_lif_wait++;
	}

	if (ack->opts[CD_BROADCASTADDR] != NULL &&
	    ack->opts[CD_BROADCASTADDR]->len == sizeof (inaddr)) {

		(void) memcpy(&inaddr, ack->opts[CD_BROADCASTADDR]->value,
		    sizeof (inaddr));

	} else {

		if (ack->opts[CD_BROADCASTADDR] != NULL &&
		    ack->opts[CD_BROADCASTADDR]->len != sizeof (inaddr)) {
			dhcpmsg(MSG_WARNING, "configure_v4_lease: specified "
			    "broadcast address length is %d instead of %d, "
			    "ignoring", ack->opts[CD_BROADCASTADDR]->len,
			    sizeof (inaddr));
		} else {
			dhcpmsg(MSG_WARNING, "configure_v4_lease: no IP "
			    "broadcast specified for %s, making best guess",
			    lif->lif_name);
		}

		/*
		 * no legitimate IP broadcast specified.  compute it
		 * from the IP address and netmask.
		 */

		IN6_V4MAPPED_TO_INADDR(&lif->lif_v6addr, &inaddr);
		inaddr.s_addr |= ~lif->lif_v6mask._S6_un._S6_u32[3];
	}

	/*
	 * the kernel will set the broadcast address for us as part of
	 * bringing the interface up.  since experience has shown that dhcp
	 * servers sometimes provide a bogus broadcast address, we let the
	 * kernel set it so that it's guaranteed to be correct.
	 *
	 * also, note any inconsistencies and save the broadcast address the
	 * kernel set so that we can watch for changes to it.
	 */

	if (ioctl(v4_sock_fd, SIOCGLIFBRDADDR, &lifr) == -1) {
		dhcpmsg(MSG_ERR, "configure_v4_lease: cannot get broadcast "
		    "address for %s", lif->lif_name);
		return (B_FALSE);
	}

	if (inaddr.s_addr != sin->sin_addr.s_addr) {
		dhcpmsg(MSG_WARNING, "configure_v4_lease: incorrect broadcast "
		    "address %s specified for %s; ignoring", inet_ntoa(inaddr),
		    lif->lif_name);
	}

	lif->lif_broadcast = sin->sin_addr.s_addr;
	dhcpmsg(MSG_INFO,
	    "configure_v4_lease: using broadcast address %s on %s",
	    inet_ntoa(inaddr), lif->lif_name);
	return (B_TRUE);
}

/*
 * save_server_id(): save off the new DHCPv6 Server ID
 *
 *   input: dhcp_smach_t *: the state machine to use
 *	    PKT_LIST *: the packet with the Reply message
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
save_server_id(dhcp_smach_t *dsmp, PKT_LIST *msg)
{
	const dhcpv6_option_t *d6o;
	uint_t olen;

	d6o = dhcpv6_pkt_option(msg, NULL, DHCPV6_OPT_SERVERID, &olen);
	if (d6o == NULL)
		return (B_FALSE);
	olen -= sizeof (*d6o);
	free(dsmp->dsm_serverid);
	if ((dsmp->dsm_serverid = malloc(olen)) == NULL) {
		return (B_FALSE);
	} else {
		dsmp->dsm_serveridlen = olen;
		(void) memcpy(dsmp->dsm_serverid, d6o + 1, olen);
		return (B_TRUE);
	}
}
