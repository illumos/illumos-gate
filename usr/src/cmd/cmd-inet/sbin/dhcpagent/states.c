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
 * This module contains core functions for managing DHCP state machine
 * instances.
 */

#include <assert.h>
#include <stdlib.h>
#include <search.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/arp.h>
#include <arpa/inet.h>
#include <dhcpmsg.h>
#include <dhcpagent_util.h>
#include <dhcp_stable.h>
#include <dhcp_inittab.h>

#include "agent.h"
#include "states.h"
#include "interface.h"
#include "defaults.h"
#include "script_handler.h"

static uint_t global_smach_count;

static uchar_t *global_duid;
static size_t global_duidlen;

/*
 * iaid_retry(): attempt to write LIF IAID again
 *
 *   input: iu_tq_t *: ignored
 *	    void *: pointer to LIF
 *  output: none
 */

/* ARGSUSED */
static void
iaid_retry(iu_tq_t *tqp, void *arg)
{
	dhcp_lif_t *lif = arg;

	if (write_stable_iaid(lif->lif_name, lif->lif_iaid) == -1) {
		if (errno != EROFS) {
			dhcpmsg(MSG_ERR,
			    "iaid_retry: unable to write out IAID for %s",
			    lif->lif_name);
			release_lif(lif);
		} else {
			lif->lif_iaid_id = iu_schedule_timer(tq, 60,
			    iaid_retry, lif);
		}
	} else {
		release_lif(lif);
	}
}

/*
 * parse_param_list(): parse a parameter list.
 *
 *   input: const char *: parameter list string with comma-separated entries
 *	    uint_t *: return parameter; number of entries decoded
 *	    const char *: name of parameter list for logging purposes
 *	    dhcp_smach_t *: smach pointer for logging
 *  output: uint16_t *: allocated array of parameters, or NULL if none.
 */

static uint16_t *
parse_param_list(const char *param_list, uint_t *param_cnt,
    const char *param_name, dhcp_smach_t *dsmp)
{
	int i, maxparam;
	char tsym[DSYM_MAX_SYM_LEN + 1];
	uint16_t *params;
	const char *cp;
	dhcp_symbol_t *entry;

	*param_cnt = 0;

	if (param_list == NULL)
		return (NULL);

	for (maxparam = 1, i = 0; param_list[i] != '\0'; i++) {
		if (param_list[i] == ',')
			maxparam++;
	}

	params = malloc(maxparam * sizeof (*params));
	if (params == NULL) {
		dhcpmsg(MSG_WARNING,
		    "cannot allocate parameter %s list for %s (continuing)",
		    param_name, dsmp->dsm_name);
		return (NULL);
	}

	for (i = 0; i < maxparam; ) {

		if (isspace(*param_list))
			param_list++;

		/* extract the next element on the list */
		cp = strchr(param_list, ',');
		if (cp == NULL || cp - param_list >= sizeof (tsym))
			(void) strlcpy(tsym, param_list, sizeof (tsym));
		else
			(void) strlcpy(tsym, param_list, cp - param_list + 1);

		/* LINTED -- do nothing with blanks on purpose */
		if (tsym[0] == '\0') {
			;
		} else if (isalpha(tsym[0])) {
			entry = inittab_getbyname(ITAB_CAT_SITE |
			    ITAB_CAT_STANDARD |
			    (dsmp->dsm_isv6 ? ITAB_CAT_V6 : 0),
			    ITAB_CONS_INFO, tsym);
			if (entry == NULL) {
				dhcpmsg(MSG_INFO, "ignored unknown %s list "
				    "entry '%s' for %s", param_name, tsym,
				    dsmp->dsm_name);
			} else {
				params[i++] = entry->ds_code;
				free(entry);
			}
		} else {
			params[i++] = strtoul(tsym, NULL, 0);
		}
		if (cp == NULL)
			break;
		param_list = cp + 1;
	}

	*param_cnt = i;
	return (params);
}

/*
 * insert_smach(): Create a state machine instance on a given logical
 *		   interface.  The state machine holds the caller's LIF
 *		   reference on success, and frees it on failure.
 *
 *   input: dhcp_lif_t *: logical interface name
 *	    int *: set to DHCP_IPC_E_* if creation fails
 *  output: dhcp_smach_t *: state machine instance
 */

dhcp_smach_t *
insert_smach(dhcp_lif_t *lif, int *error)
{
	dhcp_smach_t *dsmp, *alt_primary;
	boolean_t isv6;
	const char *plist;

	if ((dsmp = calloc(1, sizeof (*dsmp))) == NULL) {
		dhcpmsg(MSG_ERR, "cannot allocate state machine entry for %s",
		    lif->lif_name);
		remove_lif(lif);
		release_lif(lif);
		*error = DHCP_IPC_E_MEMORY;
		return (NULL);
	}
	dsmp->dsm_name = lif->lif_name;
	dsmp->dsm_lif = lif;
	dsmp->dsm_hold_count = 1;
	dsmp->dsm_state = INIT;
	dsmp->dsm_dflags = DHCP_IF_REMOVED;	/* until added to list */
	isv6 = lif->lif_pif->pif_isv6;

	/*
	 * Now that we have a controlling LIF, we need to assign an IAID to
	 * that LIF.
	 */
	if (lif->lif_iaid == 0 &&
	    (lif->lif_iaid = read_stable_iaid(lif->lif_name)) == 0) {
		static uint32_t iaidctr = 0x80000000u;

		/*
		 * If this is a logical interface, then use an arbitrary seed
		 * value.  Otherwise, use the ifIndex.
		 */
		lif->lif_iaid = make_stable_iaid(lif->lif_name,
		    strchr(lif->lif_name, ':') != NULL ? iaidctr++ :
		    lif->lif_pif->pif_index);
		dhcpmsg(MSG_INFO,
		    "insert_smach: manufactured IAID %u for v%d %s",
		    lif->lif_iaid, isv6 ? 6 : 4, lif->lif_name);
		hold_lif(lif);
		iaid_retry(NULL, lif);
	}

	if (isv6) {
		dsmp->dsm_dflags |= DHCP_IF_V6;
		dsmp->dsm_server = ipv6_all_dhcp_relay_and_servers;

		/*
		 * With DHCPv6, we do all of our I/O using the common
		 * v6_sock_fd.  There's no need for per-interface file
		 * descriptors because we have IPV6_PKTINFO.
		 */
	} else {
		IN6_IPADDR_TO_V4MAPPED(htonl(INADDR_BROADCAST),
		    &dsmp->dsm_server);

		/*
		 * With IPv4 DHCP, we use a socket per lif.
		 */
		if (!open_ip_lif(lif, INADDR_ANY, B_TRUE)) {
			dhcpmsg(MSG_ERR, "unable to open socket for %s",
			    lif->lif_name);
			/* This will also dispose of the LIF */
			release_smach(dsmp);
			*error = DHCP_IPC_E_SOCKET;
			return (NULL);
		}
	}

	script_init(dsmp);
	ipc_action_init(&dsmp->dsm_ia);

	dsmp->dsm_neg_hrtime = gethrtime();
	dsmp->dsm_offer_timer = -1;
	dsmp->dsm_start_timer = -1;
	dsmp->dsm_retrans_timer = -1;

	/*
	 * Initialize the parameter request and ignore lists, if any.
	 */
	plist = df_get_string(dsmp->dsm_name, isv6, DF_PARAM_REQUEST_LIST);
	dsmp->dsm_prl = parse_param_list(plist, &dsmp->dsm_prllen, "request",
	    dsmp);
	plist = df_get_string(dsmp->dsm_name, isv6, DF_PARAM_IGNORE_LIST);
	dsmp->dsm_pil = parse_param_list(plist, &dsmp->dsm_pillen, "ignore",
	    dsmp);

	dsmp->dsm_offer_wait = df_get_int(dsmp->dsm_name, isv6,
	    DF_OFFER_WAIT);

	/*
	 * If there is no primary of this type, and there is one of the other,
	 * then make this one primary if it's on the same named PIF.
	 */
	if (primary_smach(isv6) == NULL &&
	    (alt_primary = primary_smach(!isv6)) != NULL) {
		if (strcmp(lif->lif_pif->pif_name,
		    alt_primary->dsm_lif->lif_pif->pif_name) == 0) {
			dhcpmsg(MSG_DEBUG,
			    "insert_smach: making %s primary for v%d",
			    dsmp->dsm_name, isv6 ? 6 : 4);
			dsmp->dsm_dflags |= DHCP_IF_PRIMARY;
		}
	}

	/*
	 * We now have at least one state machine running, so cancel any
	 * running inactivity timer.
	 */
	if (inactivity_id != -1 &&
	    iu_cancel_timer(tq, inactivity_id, NULL) == 1)
		inactivity_id = -1;

	dsmp->dsm_dflags &= ~DHCP_IF_REMOVED;
	insque(dsmp, &lif->lif_smachs);
	global_smach_count++;
	dhcpmsg(MSG_DEBUG2, "insert_smach: inserted %s", dsmp->dsm_name);

	return (dsmp);
}

/*
 * hold_smach(): acquires a hold on a state machine
 *
 *   input: dhcp_smach_t *: the state machine to acquire a hold on
 *  output: void
 */

void
hold_smach(dhcp_smach_t *dsmp)
{
	dsmp->dsm_hold_count++;

	dhcpmsg(MSG_DEBUG2, "hold_smach: hold count on %s: %d",
	    dsmp->dsm_name, dsmp->dsm_hold_count);
}

/*
 * free_smach(): frees the memory occupied by a state machine
 *
 *   input: dhcp_smach_t *: the DHCP state machine to free
 *  output: void
 */

static void
free_smach(dhcp_smach_t *dsmp)
{
	dhcpmsg(MSG_DEBUG, "free_smach: freeing state machine %s",
	    dsmp->dsm_name);

	deprecate_leases(dsmp);
	remove_lif(dsmp->dsm_lif);
	release_lif(dsmp->dsm_lif);
	free_pkt_list(&dsmp->dsm_recv_pkt_list);
	if (dsmp->dsm_ack != dsmp->dsm_orig_ack)
		free_pkt_entry(dsmp->dsm_orig_ack);
	free_pkt_entry(dsmp->dsm_ack);
	free(dsmp->dsm_send_pkt.pkt);
	free(dsmp->dsm_cid);
	free(dsmp->dsm_prl);
	free(dsmp->dsm_pil);
	free(dsmp->dsm_routers);
	free(dsmp->dsm_reqhost);
	free(dsmp->dsm_msg_reqhost);
	free(dsmp->dsm_dhcp_domainname);
	free(dsmp);

	/* no big deal if this fails */
	if (global_smach_count == 0 && inactivity_id == -1) {
		inactivity_id = iu_schedule_timer(tq, DHCP_INACTIVITY_WAIT,
		    inactivity_shutdown, NULL);
	}
}

/*
 * release_smach(): releases a hold previously acquired on a state machine.
 *		    If the hold count reaches 0, the state machine is freed.
 *
 *   input: dhcp_smach_t *: the state machine entry to release the hold on
 *  output: void
 */

void
release_smach(dhcp_smach_t *dsmp)
{
	if (dsmp->dsm_hold_count == 0) {
		dhcpmsg(MSG_CRIT, "release_smach: extraneous release");
		return;
	}

	if (dsmp->dsm_hold_count == 1 &&
	    !(dsmp->dsm_dflags & DHCP_IF_REMOVED)) {
		dhcpmsg(MSG_CRIT, "release_smach: missing removal");
		return;
	}

	if (--dsmp->dsm_hold_count == 0) {
		free_smach(dsmp);
	} else {
		dhcpmsg(MSG_DEBUG2, "release_smach: hold count on %s: %d",
		    dsmp->dsm_name, dsmp->dsm_hold_count);
	}
}

/*
 * next_smach(): state machine iterator function
 *
 *   input: dhcp_smach_t *: current state machine (or NULL for list start)
 *          boolean_t: B_TRUE if DHCPv6, B_FALSE otherwise
 *  output: dhcp_smach_t *: next state machine in list
 */

dhcp_smach_t *
next_smach(dhcp_smach_t *dsmp, boolean_t isv6)
{
	dhcp_lif_t *lif;
	dhcp_pif_t *pif;

	if (dsmp != NULL) {
		if (dsmp->dsm_next != NULL)
			return (dsmp->dsm_next);

		if ((lif = dsmp->dsm_lif) != NULL)
			lif = lif->lif_next;
		for (; lif != NULL; lif = lif->lif_next) {
			if (lif->lif_smachs != NULL)
				return (lif->lif_smachs);
		}

		if ((pif = dsmp->dsm_lif->lif_pif) != NULL)
			pif = pif->pif_next;
	} else {
		pif = isv6 ? v6root : v4root;
	}
	for (; pif != NULL; pif = pif->pif_next) {
		for (lif = pif->pif_lifs; lif != NULL; lif = lif->lif_next) {
			if (lif->lif_smachs != NULL)
				return (lif->lif_smachs);
		}
	}
	return (NULL);
}

/*
 * primary_smach(): loop through all state machines of the given type (v4 or
 *		    v6) in the system, and locate the one that's primary.
 *
 *   input: boolean_t: B_TRUE for IPv6
 *  output: dhcp_smach_t *: the primary state machine
 */

dhcp_smach_t *
primary_smach(boolean_t isv6)
{
	dhcp_smach_t *dsmp;

	for (dsmp = next_smach(NULL, isv6); dsmp != NULL;
	    dsmp = next_smach(dsmp, isv6)) {
		if (dsmp->dsm_dflags & DHCP_IF_PRIMARY)
			break;
	}
	return (dsmp);
}

/*
 * info_primary_smach(): loop through all state machines of the given type (v4
 *			 or v6) in the system, and locate the one that should
 *			 be considered "primary" for dhcpinfo.
 *
 *   input: boolean_t: B_TRUE for IPv6
 *  output: dhcp_smach_t *: the dhcpinfo primary state machine
 */

dhcp_smach_t *
info_primary_smach(boolean_t isv6)
{
	dhcp_smach_t *bestdsm = NULL;
	dhcp_smach_t *dsmp;

	for (dsmp = next_smach(NULL, isv6); dsmp != NULL;
	    dsmp = next_smach(dsmp, isv6)) {
		/*
		 * If there is a primary, then something previously went wrong
		 * with verification, because the caller uses primary_smach()
		 * before calling this routine.  There's nothing else we can do
		 * but return failure, as the designated primary must be bad.
		 */
		if (dsmp->dsm_dflags & DHCP_IF_PRIMARY)
			return (NULL);

		/* If we have no information, then we're not primary. */
		if (dsmp->dsm_ack == NULL)
			continue;

		/*
		 * Among those interfaces that have DHCP information, the
		 * "primary" is the one that sorts lexically first.
		 */
		if (bestdsm == NULL ||
		    strcmp(dsmp->dsm_name, bestdsm->dsm_name) < 0)
			bestdsm = dsmp;
	}
	return (bestdsm);
}

/*
 * make_primary(): designate a given state machine as being the primary
 *		   instance on the primary interface.  Note that the user often
 *		   thinks in terms of a primary "interface" (rather than just
 *		   an instance), so we go to lengths here to keep v4 and v6 in
 *		   sync.
 *
 *   input: dhcp_smach_t *: the primary state machine
 *  output: none
 */

void
make_primary(dhcp_smach_t *dsmp)
{
	dhcp_smach_t *old_primary, *alt_primary;
	dhcp_pif_t *pif;

	if ((old_primary = primary_smach(dsmp->dsm_isv6)) != NULL)
		old_primary->dsm_dflags &= ~DHCP_IF_PRIMARY;
	dsmp->dsm_dflags |= DHCP_IF_PRIMARY;

	/*
	 * Find the primary for the other protocol.
	 */
	alt_primary = primary_smach(!dsmp->dsm_isv6);

	/*
	 * If it's on a different interface, then cancel that.  If it's on the
	 * same interface, then we're done.
	 */
	if (alt_primary != NULL) {
		if (strcmp(alt_primary->dsm_lif->lif_pif->pif_name,
		    dsmp->dsm_lif->lif_pif->pif_name) == 0)
			return;
		alt_primary->dsm_dflags &= ~DHCP_IF_PRIMARY;
	}

	/*
	 * We need a new primary for the other protocol.  If the PIF exists,
	 * there must be at least one state machine.  Just choose the first for
	 * consistency with insert_smach().
	 */
	if ((pif = lookup_pif_by_name(dsmp->dsm_lif->lif_pif->pif_name,
	    !dsmp->dsm_isv6)) != NULL) {
		pif->pif_lifs->lif_smachs->dsm_dflags |= DHCP_IF_PRIMARY;
	}
}

/*
 * lookup_smach(): finds a state machine by name and type; used for dispatching
 *		   user commands.
 *
 *   input: const char *: the name of the state machine
 *          boolean_t: B_TRUE if DHCPv6, B_FALSE otherwise
 *  output: dhcp_smach_t *: the state machine found
 */

dhcp_smach_t *
lookup_smach(const char *smname, boolean_t isv6)
{
	dhcp_smach_t *dsmp;

	for (dsmp = next_smach(NULL, isv6); dsmp != NULL;
	    dsmp = next_smach(dsmp, isv6)) {
		if (strcmp(dsmp->dsm_name, smname) == 0)
			break;
	}
	return (dsmp);
}

/*
 * lookup_smach_by_uindex(): iterate through running state machines by
 *			     truncated interface index.
 *
 *   input: uint16_t: the interface index (truncated)
 *	    dhcp_smach_t *: the previous state machine, or NULL for start
 *	    boolean_t: B_TRUE for DHCPv6, B_FALSE for IPv4 DHCP
 *  output: dhcp_smach_t *: next state machine, or NULL at end of list
 */

dhcp_smach_t *
lookup_smach_by_uindex(uint16_t ifindex, dhcp_smach_t *dsmp, boolean_t isv6)
{
	dhcp_pif_t *pif;
	dhcp_lif_t *lif;

	/*
	 * If the user gives us a state machine, then check that the next one
	 * available is on the same physical interface.  If so, then go ahead
	 * and return that.
	 */
	if (dsmp != NULL) {
		pif = dsmp->dsm_lif->lif_pif;
		if ((dsmp = next_smach(dsmp, isv6)) == NULL)
			return (NULL);
		if (pif == dsmp->dsm_lif->lif_pif)
			return (dsmp);
	} else {
		/* Otherwise, start at the beginning of the list */
		pif = NULL;
	}

	/*
	 * Find the next physical interface with the same truncated interface
	 * index, and return the first state machine on that.  If there are no
	 * more physical interfaces that match, then we're done.
	 */
	do {
		pif = lookup_pif_by_uindex(ifindex, pif, isv6);
		if (pif == NULL)
			return (NULL);
		for (lif = pif->pif_lifs; lif != NULL; lif = lif->lif_next) {
			if ((dsmp = lif->lif_smachs) != NULL)
				break;
		}
	} while (dsmp == NULL);
	return (dsmp);
}

/*
 * lookup_smach_by_xid(): iterate through running state machines by transaction
 *			  id.  Transaction ID zero means "all state machines."
 *
 *   input: uint32_t: the transaction id to look up
 *	    dhcp_smach_t *: the previous state machine, or NULL for start
 *	    boolean_t: B_TRUE if DHCPv6, B_FALSE otherwise
 *  output: dhcp_smach_t *: next state machine, or NULL at end of list
 */

dhcp_smach_t *
lookup_smach_by_xid(uint32_t xid, dhcp_smach_t *dsmp, boolean_t isv6)
{
	for (dsmp = next_smach(dsmp, isv6); dsmp != NULL;
	    dsmp = next_smach(dsmp, isv6)) {
		if (xid == 0 ||
		    pkt_get_xid(dsmp->dsm_send_pkt.pkt, isv6) == xid)
			break;
	}

	return (dsmp);
}

/*
 * lookup_smach_by_event(): find a state machine busy with a particular event
 *			    ID.  This is used only for error handling.
 *
 *   input: iu_event_id_t: the event id to look up
 *  output: dhcp_smach_t *: matching state machine, or NULL if none
 */

dhcp_smach_t *
lookup_smach_by_event(iu_event_id_t eid)
{
	dhcp_smach_t *dsmp;
	boolean_t isv6 = B_FALSE;

	for (;;) {
		for (dsmp = next_smach(NULL, isv6); dsmp != NULL;
		    dsmp = next_smach(dsmp, isv6)) {
			if ((dsmp->dsm_dflags & DHCP_IF_BUSY) &&
			    eid == dsmp->dsm_ia.ia_eid)
				return (dsmp);
		}
		if (isv6)
			break;
		isv6 = B_TRUE;
	}

	return (dsmp);
}

/*
 * cancel_offer_timer(): stop the offer polling timer on a given state machine
 *
 *   input: dhcp_smach_t *: state machine on which to stop polling for offers
 *  output: none
 */

void
cancel_offer_timer(dhcp_smach_t *dsmp)
{
	int retval;

	if (dsmp->dsm_offer_timer != -1) {
		retval = iu_cancel_timer(tq, dsmp->dsm_offer_timer, NULL);
		dsmp->dsm_offer_timer = -1;
		if (retval == 1)
			release_smach(dsmp);
	}
}

/*
 * cancel_smach_timers(): stop all of the timers related to a given state
 *			  machine, including lease and LIF expiry.
 *
 *   input: dhcp_smach_t *: state machine to cancel
 *  output: none
 *    note: this function assumes that the iu timer functions are synchronous
 *	    and thus don't require any protection or ordering on cancellation.
 */

void
cancel_smach_timers(dhcp_smach_t *dsmp)
{
	dhcp_lease_t *dlp;
	dhcp_lif_t *lif;
	uint_t nlifs;

	for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlp->dl_next) {
		cancel_lease_timers(dlp);
		lif = dlp->dl_lifs;
		nlifs = dlp->dl_nlifs;
		for (; nlifs > 0; nlifs--, lif = lif->lif_next)
			cancel_lif_timers(lif);
	}

	cancel_offer_timer(dsmp);
	stop_pkt_retransmission(dsmp);
	if (dsmp->dsm_start_timer != -1) {
		(void) iu_cancel_timer(tq, dsmp->dsm_start_timer, NULL);
		dsmp->dsm_start_timer = -1;
		release_smach(dsmp);
	}
}

/*
 * remove_smach(): removes a given state machine from the system.  marks it
 *		   for being freed (but may not actually free it).
 *
 *   input: dhcp_smach_t *: the state machine to remove
 *  output: void
 */

void
remove_smach(dhcp_smach_t *dsmp)
{
	if (dsmp->dsm_dflags & DHCP_IF_REMOVED)
		return;

	dhcpmsg(MSG_DEBUG2, "remove_smach: removing %s", dsmp->dsm_name);
	dsmp->dsm_dflags |= DHCP_IF_REMOVED;
	remque(dsmp);
	global_smach_count--;

	/*
	 * if we have long term timers, cancel them so that state machine
	 * resources can be reclaimed in a reasonable amount of time.
	 */
	cancel_smach_timers(dsmp);

	/* Drop the hold that the LIF's state machine list had on us */
	release_smach(dsmp);
}

/*
 * finished_smach(): we're finished with a given state machine; remove it from
 *		     the system and tell the user (who may have initiated the
 *		     removal process).  Note that we remove it from the system
 *		     first to allow back-to-back drop and create invocations.
 *
 *   input: dhcp_smach_t *: the state machine to remove
 *	    int: error for IPC
 *  output: void
 */

void
finished_smach(dhcp_smach_t *dsmp, int error)
{
	hold_smach(dsmp);
	remove_smach(dsmp);
	if (dsmp->dsm_ia.ia_fd != -1)
		ipc_action_finish(dsmp, error);
	else
		(void) async_cancel(dsmp);
	release_smach(dsmp);
}

/*
 * is_bound_state(): checks if a state indicates the client is bound
 *
 *   input: DHCPSTATE: the state to check
 *  output: boolean_t: B_TRUE if the state is bound, B_FALSE if not
 */

boolean_t
is_bound_state(DHCPSTATE state)
{
	return (state == BOUND || state == REBINDING || state == INFORMATION ||
	    state == RELEASING || state == INFORM_SENT || state == RENEWING);
}

/*
 * set_smach_state(): changes state and updates I/O
 *
 *   input: dhcp_smach_t *: the state machine to change
 *	    DHCPSTATE: the new state
 *  output: boolean_t: B_TRUE on success, B_FALSE on failure
 */

boolean_t
set_smach_state(dhcp_smach_t *dsmp, DHCPSTATE state)
{
	dhcp_lif_t *lif = dsmp->dsm_lif;

	if (dsmp->dsm_state != state) {
		dhcpmsg(MSG_DEBUG,
		    "set_smach_state: changing from %s to %s on %s",
		    dhcp_state_to_string(dsmp->dsm_state),
		    dhcp_state_to_string(state), dsmp->dsm_name);

		/*
		 * For IPv4, when we're in a bound state our socket must be
		 * bound to our address.  Otherwise, our socket must be bound
		 * to INADDR_ANY.  For IPv6, no such change is necessary.
		 */
		if (!dsmp->dsm_isv6) {
			if (is_bound_state(dsmp->dsm_state)) {
				if (!is_bound_state(state)) {
					close_ip_lif(lif);
					if (!open_ip_lif(lif, INADDR_ANY,
					    B_FALSE))
						return (B_FALSE);
				}
			} else {
				if (is_bound_state(state)) {
					close_ip_lif(lif);
					if (!open_ip_lif(lif,
					    ntohl(lif->lif_addr), B_FALSE))
						return (B_FALSE);
				}
			}
		}

		dsmp->dsm_state = state;
	}
	return (B_TRUE);
}

/*
 * duid_retry(): attempt to write DUID again
 *
 *   input: iu_tq_t *: ignored
 *	    void *: ignored
 *  output: none
 */

/* ARGSUSED */
static void
duid_retry(iu_tq_t *tqp, void *arg)
{
	if (write_stable_duid(global_duid, global_duidlen) == -1) {
		if (errno != EROFS) {
			dhcpmsg(MSG_ERR,
			    "duid_retry: unable to write out DUID");
		} else {
			(void) iu_schedule_timer(tq, 60, duid_retry, NULL);
		}
	}
}

/*
 * get_smach_cid(): gets the client ID for a given state machine.
 *
 *   input: dhcp_smach_t *: the state machine to set up
 *  output: int: DHCP_IPC_SUCCESS or one of DHCP_IPC_E_* on failure.
 */

int
get_smach_cid(dhcp_smach_t *dsmp)
{
	uchar_t *client_id;
	uint_t client_id_len;
	dhcp_lif_t *lif = dsmp->dsm_lif;
	dhcp_pif_t *pif = lif->lif_pif;
	const char *value;
	size_t slen;

	/*
	 * Look in defaults file for the client-id.  If present, this takes
	 * precedence over all other forms of ID.
	 */

	dhcpmsg(MSG_DEBUG, "get_smach_cid: getting default client-id "
	    "property on %s", dsmp->dsm_name);
	value = df_get_string(dsmp->dsm_name, pif->pif_isv6, DF_CLIENT_ID);
	if (value != NULL) {
		/*
		 * The Client ID string can have one of three basic forms:
		 *	<decimal>,<data...>
		 *	0x<hex...>
		 *	<string...>
		 *
		 * The first form is an RFC 3315 DUID.  This is legal for both
		 * IPv4 DHCP and DHCPv6.  For IPv4, an RFC 4361 Client ID is
		 * constructed from this value.
		 *
		 * The second and third forms are legal for IPv4 only.  This is
		 * a raw Client ID, in hex or ASCII string format.
		 */

		if (isdigit(*value) &&
		    value[strspn(value, "0123456789")] == ',') {
			char *cp;
			ulong_t duidtype;
			ulong_t subtype;

			errno = 0;
			duidtype = strtoul(value, &cp, 0);
			if (value == cp || errno != 0 || *cp != ',' ||
			    duidtype > 65535) {
				dhcpmsg(MSG_ERR, "get_smach_cid: cannot parse "
				    "DUID type in %s", value);
				goto no_specified_id;
			}
			value = cp + 1;
			switch (duidtype) {
			case DHCPV6_DUID_LL:
			case DHCPV6_DUID_LLT: {
				int num;
				char chr;

				errno = 0;
				subtype = strtoul(value, &cp, 0);
				if (value == cp || errno != 0 || *cp != ',' ||
				    subtype > 65535) {
					dhcpmsg(MSG_ERR, "get_smach_cid: "
					    "cannot parse MAC type in %s",
					    value);
					goto no_specified_id;
				}
				value = cp + 1;
				client_id_len = pif->pif_isv6 ? 1 : 5;
				for (; *cp != '\0'; cp++) {
					if (*cp == ':')
						client_id_len++;
					else if (!isxdigit(*cp))
						break;
				}
				if (duidtype == DHCPV6_DUID_LL) {
					duid_llt_t *dllt;
					time_t now;

					client_id_len += sizeof (*dllt);
					dllt = malloc(client_id_len);
					if (dllt == NULL)
						goto alloc_failure;
					dsmp->dsm_cid = (uchar_t *)dllt;
					dllt->dllt_dutype = htons(duidtype);
					dllt->dllt_hwtype = htons(subtype);
					now = time(NULL) - DUID_TIME_BASE;
					dllt->dllt_time = htonl(now);
					cp = (char *)(dllt + 1);
				} else {
					duid_ll_t *dll;

					client_id_len += sizeof (*dll);
					dll = malloc(client_id_len);
					if (dll == NULL)
						goto alloc_failure;
					dsmp->dsm_cid = (uchar_t *)dll;
					dll->dll_dutype = htons(duidtype);
					dll->dll_hwtype = htons(subtype);
					cp = (char *)(dll + 1);
				}
				num = 0;
				while ((chr = *value) != '\0') {
					if (isdigit(chr)) {
						num = (num << 4) + chr - '0';
					} else if (isxdigit(chr)) {
						num = (num << 4) + 10 + chr -
						    (isupper(chr) ? 'A' : 'a');
					} else if (chr == ':') {
						*cp++ = num;
						num = 0;
					} else {
						break;
					}
				}
				break;
			}
			case DHCPV6_DUID_EN: {
				duid_en_t *den;

				errno = 0;
				subtype = strtoul(value, &cp, 0);
				if (value == cp || errno != 0 || *cp != ',') {
					dhcpmsg(MSG_ERR, "get_smach_cid: "
					    "cannot parse enterprise in %s",
					    value);
					goto no_specified_id;
				}
				value = cp + 1;
				slen = strlen(value);
				client_id_len = (slen + 1) / 2;
				den = malloc(sizeof (*den) + client_id_len);
				if (den == NULL)
					goto alloc_failure;
				den->den_dutype = htons(duidtype);
				DHCPV6_SET_ENTNUM(den, subtype);
				if (hexascii_to_octet(value, slen, den + 1,
				    &client_id_len) != 0) {
					dhcpmsg(MSG_ERROR, "get_smach_cid: "
					    "cannot parse hex string in %s",
					    value);
					free(den);
					goto no_specified_id;
				}
				dsmp->dsm_cid = (uchar_t *)den;
				break;
			}
			default:
				slen = strlen(value);
				client_id_len = (slen + 1) / 2;
				cp = malloc(client_id_len);
				if (cp == NULL)
					goto alloc_failure;
				if (hexascii_to_octet(value, slen, cp,
				    &client_id_len) != 0) {
					dhcpmsg(MSG_ERROR, "get_smach_cid: "
					    "cannot parse hex string in %s",
					    value);
					free(cp);
					goto no_specified_id;
				}
				dsmp->dsm_cid = (uchar_t *)cp;
				break;
			}
			dsmp->dsm_cidlen = client_id_len;
			if (!pif->pif_isv6) {
				(void) memmove(dsmp->dsm_cid + 5,
				    dsmp->dsm_cid, client_id_len - 5);
				dsmp->dsm_cid[0] = 255;
				dsmp->dsm_cid[1] = lif->lif_iaid >> 24;
				dsmp->dsm_cid[2] = lif->lif_iaid >> 16;
				dsmp->dsm_cid[3] = lif->lif_iaid >> 8;
				dsmp->dsm_cid[4] = lif->lif_iaid;
			}
			return (DHCP_IPC_SUCCESS);
		}

		if (pif->pif_isv6) {
			dhcpmsg(MSG_ERROR,
			    "get_smach_cid: client ID for %s invalid: %s",
			    dsmp->dsm_name, value);
		} else if (strncasecmp("0x", value, 2) == 0 &&
		    value[2] != '\0') {
			/* skip past the 0x and convert the value to binary */
			value += 2;
			slen = strlen(value);
			client_id_len = (slen + 1) / 2;
			dsmp->dsm_cid = malloc(client_id_len);
			if (dsmp->dsm_cid == NULL)
				goto alloc_failure;
			if (hexascii_to_octet(value, slen, dsmp->dsm_cid,
			    &client_id_len) == 0) {
				dsmp->dsm_cidlen = client_id_len;
				return (DHCP_IPC_SUCCESS);
			}
			dhcpmsg(MSG_WARNING, "get_smach_cid: cannot convert "
			    "hex value for Client ID on %s", dsmp->dsm_name);
		} else {
			client_id_len = strlen(value);
			dsmp->dsm_cid = malloc(client_id_len);
			if (dsmp->dsm_cid == NULL)
				goto alloc_failure;
			dsmp->dsm_cidlen = client_id_len;
			(void) memcpy(dsmp->dsm_cid, value, client_id_len);
			return (DHCP_IPC_SUCCESS);
		}
	}
no_specified_id:

	/*
	 * There was either no user-specified Client ID value, or we were
	 * unable to parse it.  We need to determine if a Client ID is required
	 * and, if so, generate one.
	 *
	 * If it's IPv4, not in an IPMP group, not a logical interface,
	 * and a DHCP default for DF_V4_DEFAULT_IAID_DUID is not affirmative,
	 * then we need to preserve backward-compatibility by avoiding
	 * new-fangled DUID/IAID construction.  (Note: even for IPMP test
	 * addresses, we construct a DUID/IAID since we may renew a lease for
	 * an IPMP test address on any functioning IP interface in the group.)
	 */
	if (!pif->pif_isv6 && pif->pif_grifname[0] == '\0' &&
	    strchr(dsmp->dsm_name, ':') == NULL &&
	    !df_get_bool(dsmp->dsm_name, pif->pif_isv6,
	    DF_V4_DEFAULT_IAID_DUID)) {
		if (pif->pif_hwtype == ARPHRD_IB) {
			/*
			 * This comes from the DHCP over IPoIB specification.
			 * In the absence of an user specified client id, IPoIB
			 * automatically uses the required format, with the
			 * unique 4 octet value set to 0 (since IPoIB driver
			 * allows only a single interface on a port with a
			 * specific GID to belong to an IP subnet (PSARC
			 * 2001/289, FWARC 2002/702).
			 *
			 *   Type  Client-Identifier
			 * +-----+-----+-----+-----+-----+----....----+
			 * |  0  |  0 (4 octets)   |   GID (16 octets)|
			 * +-----+-----+-----+-----+-----+----....----+
			 */
			dsmp->dsm_cidlen = 1 + 4 + 16;
			dsmp->dsm_cid = client_id = malloc(dsmp->dsm_cidlen);
			if (dsmp->dsm_cid == NULL)
				goto alloc_failure;

			/*
			 * Pick the GID from the mac address. The format
			 * of the hardware address is:
			 * +-----+-----+-----+-----+----....----+
			 * | QPN (4 octets)  |   GID (16 octets)|
			 * +-----+-----+-----+-----+----....----+
			 */
			(void) memcpy(client_id + 5, pif->pif_hwaddr + 4,
			    pif->pif_hwlen - 4);
			(void) memset(client_id, 0, 5);
		}
		return (DHCP_IPC_SUCCESS);
	}

	/*
	 * Now check for a saved DUID.  If there is one, then use it.  If there
	 * isn't, then generate a new one.  For IPv4, we need to construct the
	 * RFC 4361 Client ID with this value and the LIF's IAID.
	 */
	if (global_duid == NULL &&
	    (global_duid = read_stable_duid(&global_duidlen)) == NULL) {
		global_duid = make_stable_duid(pif->pif_name, &global_duidlen);
		if (global_duid == NULL)
			goto alloc_failure;
		duid_retry(NULL, NULL);
	}

	if (pif->pif_isv6) {
		dsmp->dsm_cid = malloc(global_duidlen);
		if (dsmp->dsm_cid == NULL)
			goto alloc_failure;
		(void) memcpy(dsmp->dsm_cid, global_duid, global_duidlen);
		dsmp->dsm_cidlen = global_duidlen;
	} else {
		dsmp->dsm_cid = malloc(5 + global_duidlen);
		if (dsmp->dsm_cid == NULL)
			goto alloc_failure;
		dsmp->dsm_cid[0] = 255;
		dsmp->dsm_cid[1] = lif->lif_iaid >> 24;
		dsmp->dsm_cid[2] = lif->lif_iaid >> 16;
		dsmp->dsm_cid[3] = lif->lif_iaid >> 8;
		dsmp->dsm_cid[4] = lif->lif_iaid;
		(void) memcpy(dsmp->dsm_cid + 5, global_duid, global_duidlen);
		dsmp->dsm_cidlen = 5 + global_duidlen;
	}

	return (DHCP_IPC_SUCCESS);

alloc_failure:
	dhcpmsg(MSG_ERR, "get_smach_cid: cannot allocate Client Id for %s",
	    dsmp->dsm_name);
	return (DHCP_IPC_E_MEMORY);
}

/*
 * smach_count(): returns the number of state machines running
 *
 *   input: void
 *  output: uint_t: the number of state machines
 */

uint_t
smach_count(void)
{
	return (global_smach_count);
}

/*
 * discard_default_routes(): removes a state machine's default routes alone.
 *
 *   input: dhcp_smach_t *: the state machine whose default routes need to be
 *			    discarded
 *  output: void
 */

void
discard_default_routes(dhcp_smach_t *dsmp)
{
	free(dsmp->dsm_routers);
	dsmp->dsm_routers = NULL;
	dsmp->dsm_nrouters = 0;
}

/*
 * remove_default_routes(): removes a state machine's default routes from the
 *			    kernel and from the state machine.
 *
 *   input: dhcp_smach_t *: the state machine whose default routes need to be
 *			    removed
 *  output: void
 */

void
remove_default_routes(dhcp_smach_t *dsmp)
{
	int idx;
	uint32_t ifindex;

	if (dsmp->dsm_routers != NULL) {
		ifindex = dsmp->dsm_lif->lif_pif->pif_index;
		for (idx = dsmp->dsm_nrouters - 1; idx >= 0; idx--) {
			if (del_default_route(ifindex,
			    &dsmp->dsm_routers[idx])) {
				dhcpmsg(MSG_DEBUG, "remove_default_routes: "
				    "removed %s from %s",
				    inet_ntoa(dsmp->dsm_routers[idx]),
				    dsmp->dsm_name);
			} else {
				dhcpmsg(MSG_INFO, "remove_default_routes: "
				    "unable to remove %s from %s",
				    inet_ntoa(dsmp->dsm_routers[idx]),
				    dsmp->dsm_name);
			}
		}
		discard_default_routes(dsmp);
	}
}

/*
 * reset_smach(): resets a state machine to its initial state
 *
 *   input: dhcp_smach_t *: the state machine to reset
 *  output: void
 */

void
reset_smach(dhcp_smach_t *dsmp)
{
	dsmp->dsm_dflags &= ~DHCP_IF_FAILED;

	remove_default_routes(dsmp);

	free_pkt_list(&dsmp->dsm_recv_pkt_list);
	free_pkt_entry(dsmp->dsm_ack);
	if (dsmp->dsm_orig_ack != dsmp->dsm_ack)
		free_pkt_entry(dsmp->dsm_orig_ack);
	dsmp->dsm_ack = dsmp->dsm_orig_ack = NULL;

	free(dsmp->dsm_reqhost);
	dsmp->dsm_reqhost = NULL;

	/*
	 * Do not reset dsm_msg_reqhost here. Unlike dsm_reqhost coming from
	 * /etc/host.*, dsm_msg_reqhost comes externally, and it survives until
	 * it is reset from another external message.
	 */

	free(dsmp->dsm_dhcp_domainname);
	dsmp->dsm_dhcp_domainname = NULL;

	cancel_smach_timers(dsmp);

	(void) set_smach_state(dsmp, INIT);
	if (dsmp->dsm_isv6) {
		dsmp->dsm_server = ipv6_all_dhcp_relay_and_servers;
	} else {
		IN6_IPADDR_TO_V4MAPPED(htonl(INADDR_BROADCAST),
		    &dsmp->dsm_server);
	}
	dsmp->dsm_neg_hrtime = gethrtime();
	/*
	 * We must never get here with a script running, since it means we're
	 * resetting an smach that is still in the middle of another state
	 * transition with a pending dsm_script_callback.
	 */
	assert(dsmp->dsm_script_pid == -1);
}

/*
 * refresh_smach(): refreshes a given state machine, as though awakened from
 *		    hibernation or by lower layer "link up."
 *
 *   input: dhcp_smach_t *: state machine to refresh
 *  output: void
 */

void
refresh_smach(dhcp_smach_t *dsmp)
{
	if (dsmp->dsm_state == BOUND || dsmp->dsm_state == RENEWING ||
	    dsmp->dsm_state == REBINDING || dsmp->dsm_state == INFORMATION) {
		dhcpmsg(MSG_WARNING, "refreshing state on %s", dsmp->dsm_name);
		cancel_smach_timers(dsmp);
		if (dsmp->dsm_state == INFORMATION)
			dhcp_inform(dsmp);
		else
			dhcp_init_reboot(dsmp);
	}
}

/*
 * refresh_smachs(): refreshes all finite leases under DHCP control
 *
 *   input: iu_eh_t *: unused
 *	    int: unused
 *	    void *: unused
 *  output: void
 */

/* ARGSUSED */
void
refresh_smachs(iu_eh_t *eh, int sig, void *arg)
{
	boolean_t isv6 = B_FALSE;
	dhcp_smach_t *dsmp;

	for (;;) {
		for (dsmp = next_smach(NULL, isv6); dsmp != NULL;
		    dsmp = next_smach(dsmp, isv6)) {
			refresh_smach(dsmp);
		}
		if (isv6)
			break;
		isv6 = B_TRUE;
	}
}

/*
 * nuke_smach_list(): delete the state machine list.  For use when the
 *		      dhcpagent is exiting.
 *
 *   input: none
 *  output: none
 */

void
nuke_smach_list(void)
{
	boolean_t isv6 = B_FALSE;
	dhcp_smach_t *dsmp, *dsmp_next;

	for (;;) {
		for (dsmp = next_smach(NULL, isv6); dsmp != NULL;
		    dsmp = dsmp_next) {
			int	status;

			dsmp_next = next_smach(dsmp, isv6);

			/* If we're already dropping or releasing, skip */
			if (dsmp->dsm_droprelease)
				continue;
			dsmp->dsm_droprelease = B_TRUE;

			cancel_smach_timers(dsmp);

			/*
			 * If the script is started by script_start, dhcp_drop
			 * and dhcp_release should and will only be called
			 * after the script exits.
			 */
			if (df_get_bool(dsmp->dsm_name, isv6,
			    DF_RELEASE_ON_SIGTERM) ||
			    df_get_bool(dsmp->dsm_name, isv6,
			    DF_VERIFIED_LEASE_ONLY)) {
				if (script_start(dsmp, isv6 ? EVENT_RELEASE6 :
				    EVENT_RELEASE, dhcp_release,
				    "DHCP agent is exiting", &status)) {
					continue;
				}
				if (status == 1)
					continue;
			}
			(void) script_start(dsmp, isv6 ? EVENT_DROP6 :
			    EVENT_DROP, dhcp_drop, NULL, NULL);
		}
		if (isv6)
			break;
		isv6 = B_TRUE;
	}
}

/*
 * insert_lease(): Create a lease structure on a given state machine.  The
 *		   lease holds a reference to the state machine.
 *
 *   input: dhcp_smach_t *: state machine
 *  output: dhcp_lease_t *: newly-created lease
 */

dhcp_lease_t *
insert_lease(dhcp_smach_t *dsmp)
{
	dhcp_lease_t *dlp;

	if ((dlp = calloc(1, sizeof (*dlp))) == NULL)
		return (NULL);
	dlp->dl_smach = dsmp;
	dlp->dl_hold_count = 1;
	init_timer(&dlp->dl_t1, 0);
	init_timer(&dlp->dl_t2, 0);
	insque(dlp, &dsmp->dsm_leases);
	dhcpmsg(MSG_DEBUG2, "insert_lease: new lease for %s", dsmp->dsm_name);
	return (dlp);
}

/*
 * hold_lease(): acquires a hold on a lease
 *
 *   input: dhcp_lease_t *: the lease to acquire a hold on
 *  output: void
 */

void
hold_lease(dhcp_lease_t *dlp)
{
	dlp->dl_hold_count++;

	dhcpmsg(MSG_DEBUG2, "hold_lease: hold count on lease for %s: %d",
	    dlp->dl_smach->dsm_name, dlp->dl_hold_count);
}

/*
 * release_lease(): releases a hold previously acquired on a lease.
 *		    If the hold count reaches 0, the lease is freed.
 *
 *   input: dhcp_lease_t *: the lease to release the hold on
 *  output: void
 */

void
release_lease(dhcp_lease_t *dlp)
{
	if (dlp->dl_hold_count == 0) {
		dhcpmsg(MSG_CRIT, "release_lease: extraneous release");
		return;
	}

	if (dlp->dl_hold_count == 1 && !dlp->dl_removed) {
		dhcpmsg(MSG_CRIT, "release_lease: missing removal");
		return;
	}

	if (--dlp->dl_hold_count == 0) {
		dhcpmsg(MSG_DEBUG,
		    "release_lease: freeing lease on state machine %s",
		    dlp->dl_smach->dsm_name);
		free(dlp);
	} else {
		dhcpmsg(MSG_DEBUG2,
		    "release_lease: hold count on lease for %s: %d",
		    dlp->dl_smach->dsm_name, dlp->dl_hold_count);
	}
}

/*
 * remove_lease(): removes a given lease from the state machine and drops the
 *		   state machine's hold on the lease.
 *
 *   input: dhcp_lease_t *: the lease to remove
 *  output: void
 */

void
remove_lease(dhcp_lease_t *dlp)
{
	if (dlp->dl_removed) {
		dhcpmsg(MSG_CRIT, "remove_lease: extraneous removal");
	} else {
		dhcp_lif_t *lif, *lifnext;
		uint_t nlifs;

		dhcpmsg(MSG_DEBUG,
		    "remove_lease: removed lease from state machine %s",
		    dlp->dl_smach->dsm_name);
		dlp->dl_removed = B_TRUE;
		remque(dlp);

		cancel_lease_timers(dlp);

		lif = dlp->dl_lifs;
		nlifs = dlp->dl_nlifs;
		for (; nlifs > 0; nlifs--, lif = lifnext) {
			lifnext = lif->lif_next;
			unplumb_lif(lif);
		}

		release_lease(dlp);
	}
}

/*
 * cancel_lease_timer(): cancels a lease-related timer
 *
 *   input: dhcp_lease_t *: the lease to operate on
 *	    dhcp_timer_t *: the timer to cancel
 *  output: void
 */

static void
cancel_lease_timer(dhcp_lease_t *dlp, dhcp_timer_t *dt)
{
	if (dt->dt_id == -1)
		return;
	if (cancel_timer(dt)) {
		release_lease(dlp);
	} else {
		dhcpmsg(MSG_WARNING,
		    "cancel_lease_timer: cannot cancel timer");
	}
}

/*
 * cancel_lease_timers(): cancels an lease's pending timers
 *
 *   input: dhcp_lease_t *: the lease to operate on
 *  output: void
 */

void
cancel_lease_timers(dhcp_lease_t *dlp)
{
	cancel_lease_timer(dlp, &dlp->dl_t1);
	cancel_lease_timer(dlp, &dlp->dl_t2);
}

/*
 * schedule_lease_timer(): schedules a lease-related timer
 *
 *   input: dhcp_lease_t *: the lease to operate on
 *	    dhcp_timer_t *: the timer to schedule
 *	    iu_tq_callback_t *: the callback to call upon firing
 *  output: boolean_t: B_TRUE if the timer was scheduled successfully
 */

boolean_t
schedule_lease_timer(dhcp_lease_t *dlp, dhcp_timer_t *dt,
    iu_tq_callback_t *expire)
{
	/*
	 * If there's a timer running, cancel it and release its lease
	 * reference.
	 */
	if (dt->dt_id != -1) {
		if (!cancel_timer(dt))
			return (B_FALSE);
		release_lease(dlp);
	}

	if (schedule_timer(dt, expire, dlp)) {
		hold_lease(dlp);
		return (B_TRUE);
	} else {
		dhcpmsg(MSG_WARNING,
		    "schedule_lease_timer: cannot schedule timer");
		return (B_FALSE);
	}
}

/*
 * deprecate_leases(): remove all of the leases from a given state machine
 *
 *   input: dhcp_smach_t *: the state machine
 *  output: none
 */

void
deprecate_leases(dhcp_smach_t *dsmp)
{
	dhcp_lease_t *dlp;

	/*
	 * note that due to infelicities in the routing code, any default
	 * routes must be removed prior to canonizing or deprecating the LIF.
	 */

	remove_default_routes(dsmp);

	while ((dlp = dsmp->dsm_leases) != NULL)
		remove_lease(dlp);
}

/*
 * verify_smach(): if the state machine is in a bound state, then verify the
 *		   standing of the configured interfaces.  Abandon those that
 *		   the user has modified.  If we end up with no valid leases,
 *		   then just terminate the state machine.
 *
 *   input: dhcp_smach_t *: the state machine
 *  output: boolean_t: B_TRUE if the state machine is still valid.
 *    note: assumes caller holds a state machine reference; as with most
 *	    callback functions.
 */

boolean_t
verify_smach(dhcp_smach_t *dsmp)
{
	dhcp_lease_t *dlp, *dlpn;

	if (dsmp->dsm_dflags & DHCP_IF_REMOVED) {
		release_smach(dsmp);
		return (B_FALSE);
	}

	if (!dsmp->dsm_isv6) {
		/*
		 * If this is DHCPv4, then verify the main LIF.
		 */
		if (!verify_lif(dsmp->dsm_lif))
			goto smach_terminate;
	}

	/*
	 * If we're not in one of the bound states, then there are no LIFs to
	 * verify here.
	 */
	if (dsmp->dsm_state != BOUND &&
	    dsmp->dsm_state != RENEWING &&
	    dsmp->dsm_state != REBINDING) {
		release_smach(dsmp);
		return (B_TRUE);
	}

	for (dlp = dsmp->dsm_leases; dlp != NULL; dlp = dlpn) {
		dhcp_lif_t *lif, *lifnext;
		uint_t nlifs;

		dlpn = dlp->dl_next;
		lif = dlp->dl_lifs;
		nlifs = dlp->dl_nlifs;
		for (; nlifs > 0; lif = lifnext, nlifs--) {
			lifnext = lif->lif_next;
			if (!verify_lif(lif)) {
				/*
				 * User has manipulated the interface.  Even
				 * if we plumbed it, we must now disown it.
				 */
				lif->lif_plumbed = B_FALSE;
				remove_lif(lif);
			}
		}
		if (dlp->dl_nlifs == 0)
			remove_lease(dlp);
	}

	/*
	 * If there are leases left, then everything's ok.
	 */
	if (dsmp->dsm_leases != NULL) {
		release_smach(dsmp);
		return (B_TRUE);
	}

smach_terminate:
	finished_smach(dsmp, DHCP_IPC_E_INVIF);
	release_smach(dsmp);

	return (B_FALSE);
}
