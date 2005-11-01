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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.

 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Multi-hop routing module of the WildCat RSM diver.
 * This file manages the programming of WCI route maps based on link
 * up and down events.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/debug.h>

#include <sys/wrsm_common.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_nc_impl.h>
#include <sys/wrsm_lc.h>

#ifdef DEBUG
#define	DBG_MH		0x01
#define	DBG_MH_EXTRA	0x02
#define	DBG_WARN	0x04
#define	DBG_DUMP	0x08

static uint_t wrsm_mh_debug = DBG_WARN;
#define	DPRINTF(a, b) { if (wrsm_mh_debug & a) wrsmdprintf b; }
#define	DUMPWCI(m, w) { if (wrsm_mh_debug & DBG_DUMP) wrsm_mh_dump_wci(m, w); }
#else
#define	DPRINTF(a, b) { }
#define	DUMPWCI(m, w) { }
#endif /* DEBUG */

/*
 * WCI specific definitions used to program the control registers.
 */
#define	ROUTE_MAP_LOCAL 3

enum mh_link_state {
	mh_link_down,
	mh_link_up
};

struct wrsm_mh_reroute_state {
	enum mh_link_state link_state[WRSM_LINKS_PER_WCI];
	wnode_bitmask_t using_link[WRSM_LINKS_PER_WCI];
	wrsm_mh_reachable_t reachable;
};


static void set_route_nostripe(lcwci_handle_t lcwci, wnodeid_t wnode,
    uint32_t linknum);
static void set_route_addstripe(lcwci_handle_t lcwci, wnodeid_t wnode,
    uint32_t linknum);
static void set_route_unstripe(lcwci_handle_t lcwci, wnodeid_t wnode,
    uint32_t linknum);

#ifdef DEBUG
void
wrsm_mh_dump_wci(char *msg, struct wrsm_ncwci *wci)
{
	wnodeid_t wnode;
	linkid_t link;

	cmn_err(CE_WARN, "%s", msg);

	for (wnode = 0; wnode < WRSM_MAX_WNODES; ++wnode) {
		cmn_err(CE_NOTE, "   wnode %d", wnode);
		cmn_err(CE_NOTE, "      first_hop = %d",
		    wci->mh_state->reachable.first_hop[wnode]);
		cmn_err(CE_NOTE, "      stripes = %d",
		    wci->mh_state->reachable.stripes[wnode]);
		link = wrsm_lc_get_route(wci->lcwci, wnode, 0);
		cmn_err(CE_NOTE, "      map0 = %u", link);
		link = wrsm_lc_get_route(wci->lcwci, wnode, 1);
		cmn_err(CE_NOTE, "      map1 = %u", link);
	}
	for (link = 0; link < 3; link++) {
		cmn_err(CE_NOTE, "   link %d", link);
		cmn_err(CE_NOTE, "      state = %d",
		    wci->mh_state->link_state[link]);
	}
}
#endif /* DEBUG */

/*
 * Called from NR when a new wci is brought into use so that the
 * per-wci MH private data structures can be initialized.
 */
void
wrsm_mh_new_wci(wrsm_ncwci_t *wci)
{
	wrsm_mh_reroute_state_t *mh_state;
	wnodeid_t local_wnode;
	int i;

	ASSERT(wci);
	ASSERT(wci->config);
	local_wnode = wci->config->local_wnode;

	DPRINTF(DBG_MH, (CE_CONT, "mh_new_wci wci %d - add loopback route",
	    wci->config->port));

	mh_state = kmem_zalloc(sizeof (wrsm_mh_reroute_state_t),
	    KM_SLEEP);
	ASSERT(mh_state);
	for (i = 0; i < WRSM_LINKS_PER_WCI; ++i) {
		mh_state->link_state[i] = mh_link_down;
		WRSMSET_ZERO(mh_state->using_link[i]);
	}
	for (i = 0; i < WRSM_MAX_WNODES; ++i) {
		mh_state->reachable.nhops[i] = WNODE_UNREACHABLE;
		mh_state->reachable.changed[i] = B_FALSE;
	}
	/* local wnode is for loopback to local node memory */
	mh_state->reachable.nhops[local_wnode] = 0;
	mh_state->reachable.stripes[local_wnode] = 1;
	mh_state->reachable.first_hop[local_wnode] = local_wnode;
	mh_state->reachable.changed[local_wnode] = B_TRUE;
	wci->mh_state = mh_state;

	wrsm_nr_mhdirect(wci, &(mh_state->reachable));
	mh_state->reachable.changed[wci->config->local_wnode] = B_FALSE;
}

/*
 * Called from NR when wci taken away so that resources allocated
 * by wrsm_mh_new_wci() can be freed.
 */
void
wrsm_mh_remove_wci(wrsm_ncwci_t *wci)
{
	ASSERT(wci);
	ASSERT(wci->mh_state);
	ASSERT(wci->config);

	DPRINTF(DBG_MH, (CE_CONT, "mh_remove wci %d", wci->config->port));

	wci->mh_state->reachable.nhops[wci->config->local_wnode] =
		WNODE_UNREACHABLE;
	wci->mh_state->reachable.stripes[wci->config->local_wnode] = 0;
	wci->mh_state->reachable.changed[wci->config->local_wnode] = B_TRUE;

	/* force a full reroute analysis */
	wrsm_nr_mhreroute(wci, &(wci->mh_state->reachable));

	kmem_free(wci->mh_state, sizeof (wrsm_mh_reroute_state_t));
	wci->mh_state = NULL;
}


/*
 * Main entry point of the MH module used to initiate an
 * reevaluation of the multihop subnet.
 */
boolean_t
wrsm_mh_reroute(wrsm_ncwci_t *wci)
{
	ASSERT(wci);
	ASSERT(wci->config);

	DPRINTF(DBG_MH_EXTRA, (CE_CONT, "mh_reroute wci %d",
	    wci->config->port));

	if (wci->reroute_state != wci_need_reroute &&
	    wci->reroute_state != wci_force_reroute) {
		/*
		 * If the wci is in the wrong state, return
		 * without calling wrsm_nr_mhreroute().
		 */
		DPRINTF(DBG_WARN, (CE_WARN, "mh_reroute wci %d - bad "
		    "reroute state!", wci->config->port));
		return (B_FALSE);
	}

	if (wci->mh_state == NULL || wci->lcwci == NULL) {
		/* wci not attached */
		DPRINTF(DBG_MH, (CE_WARN, "mh_reroute wci %d - no "
		    "mh_state or lcwci!", wci->config->port));
		wci->reroute_state = wci_rerouted;
		return (B_FALSE);
	}

	wci->reroute_state = wci_in_reroute;

	/* Do the reroute now */
	wci->reroute_state = wci_rerouted;

	wrsm_nr_mhreroute(wci, &(wci->mh_state->reachable));
	return (B_TRUE);
}



/*
 * Called from the LC when a new link has been successfully
 * brought up.  Programs the WCI's route_map registers to
 * start using that link for direct-connect communication.
 */
void
wrsm_mh_link_is_up(ncwci_handle_t ncwci, uint32_t local_linknum,
    wnodeid_t remote_wnode)
{
	struct wrsm_ncwci *wci = (struct wrsm_ncwci *)ncwci;
	wnodeid_t wnode;
	ASSERT(wci);
	ASSERT(wci->config);
	ASSERT(wci->mh_state);
	ASSERT(wci->lcwci);
	ASSERT(local_linknum >= 0 && local_linknum < WRSM_LINKS_PER_WCI);

	DPRINTF(DBG_MH, (CE_CONT, "mh_link_is_up wci %d link %d wnode %d",
	    wci->config->port, local_linknum, remote_wnode));

	DUMPWCI("Entering wrsm_mh_link_is_up", wci);

#ifdef DEBUG
	if (wci->mh_state->link_state[local_linknum] != mh_link_down) {
		DPRINTF(DBG_MH, (CE_CONT, "mh_link_is_up: wci %d link % "
		    "already up state %d", wci->config->port, local_linknum,
		    wci->mh_state->link_state[local_linknum]));
	}
#endif

	wci->mh_state->link_state[local_linknum] = mh_link_up;

	ASSERT(remote_wnode < WRSM_MAX_WNODES);

	/*
	 * Use the one hop route if the current route uses more hops, or
	 * if a loopback route (0 hops) is currently being used.  The theory
	 * behind this is that there wouldn't be a 1 hop route to the
	 * local node in the configuration unless the configurer wanted
	 * it to be preferred over loopback.
	 */
	if (wci->mh_state->reachable.nhops[remote_wnode] == WNODE_UNREACHABLE ||
	    wci->mh_state->reachable.nhops[remote_wnode] != 1) {
		set_route_nostripe(wci->lcwci, remote_wnode,
		    local_linknum);
		wci->mh_state->reachable.nhops[remote_wnode] = 1;
		wci->mh_state->reachable.stripes[remote_wnode] = 1;
		wci->mh_state->reachable.changed[remote_wnode] = B_TRUE;
		wci->mh_state->reachable.first_hop[remote_wnode] = remote_wnode;
		WRSMSET_ADD(wci->mh_state->using_link[local_linknum],
		    remote_wnode);
	} else if (wci->mh_state->reachable.stripes[remote_wnode] == 1 &&
	    wci->mh_state->reachable.nhops[remote_wnode] == 1) {
		/* Enable route map striping */
		set_route_addstripe(wci->lcwci, remote_wnode, local_linknum);
		wci->mh_state->reachable.stripes[remote_wnode] = 2;
		WRSMSET_ADD(wci->mh_state->using_link[local_linknum],
		    remote_wnode);
		DPRINTF(DBG_MH, (CE_NOTE,
		    "mh_link_is_up: enabling link striping"));
	}

	wrsm_nr_mhdirect(wci, &(wci->mh_state->reachable));

	for (wnode = 0; wnode < WRSM_MAX_WNODES; ++wnode) {
		wci->mh_state->reachable.changed[wnode] = B_FALSE;
	}

	DUMPWCI("Exiting wrsm_mh_link_is_up", wci);
}

/* Sets both routemap entries to route over the given link */
static void
set_route_nostripe(lcwci_handle_t lcwci, wnodeid_t wnode, uint32_t linknum)
{
	/* Write to route_map_0 */
	wrsm_lc_set_route(lcwci, wnode, linknum, 0);

	/* Write same value to route_map_1 */
	wrsm_lc_set_route(lcwci, wnode, linknum, 1);
}

/* Changes route map entry 1 to route over the given link */
static void
set_route_addstripe(lcwci_handle_t lcwci, wnodeid_t wnode, uint32_t linknum)
{
	/* Assume route_map0 contains original stripe, just change map1 */
	wrsm_lc_set_route(lcwci, wnode, linknum, 1);
}

/*
 * Determines which route map entry uses the link, and replaces it with
 * the other route map entry. Returns ENOENT if the wnode was not using
 * this link to stripe.
 */
static void
set_route_unstripe(lcwci_handle_t lcwci, wnodeid_t wnode, uint32_t linknum)
{
	uint32_t link0;
	uint32_t link1;

	link0 = wrsm_lc_get_route(lcwci, wnode, 0);
	link1 = wrsm_lc_get_route(lcwci, wnode, 1);

	DPRINTF(DBG_MH, (CE_CONT, "mh set_route_unstripe link %d wnode %d "
	    "link0 %d link1 %d", linknum, wnode, link0, link1));

	/* Make sure both route map entries are in use, and not the same */
	ASSERT(link0 != ROUTE_MAP_LOCAL);
	ASSERT(link1 != ROUTE_MAP_LOCAL);
	ASSERT(link0 != link1);

	/*
	 * If the caller passed in link0, reprogram routemap to use link1
	 * and vice versa.
	 */
	if (link0 == linknum) {
		set_route_nostripe(lcwci, wnode, link1);
	} else {
		ASSERT(link1 == linknum);
		set_route_nostripe(lcwci, wnode, link0);
	}
}

/*
 * Called from the LC before a link is to be brought down or
 * after it has detected an auto-shutdown of the link.  Turns
 * off routing through the unavailable link.
 */
void
wrsm_mh_link_is_down(ncwci_handle_t ncwci, uint32_t local_linknum,
    wnodeid_t remote_wnode)
{
	struct wrsm_ncwci *wci = (struct wrsm_ncwci *)ncwci;
	wnodeid_t wnode;

	ASSERT(wci);
	ASSERT(wci->config);
	ASSERT(wci->mh_state);
	ASSERT(wci->lcwci);
	ASSERT(local_linknum < WRSM_LINKS_PER_WCI);
	ASSERT(remote_wnode < WRSM_MAX_WNODES);

	DPRINTF(DBG_MH, (CE_CONT, "mh_link_is_down wci %d link %d wnode %d",
	    wci->config->port, local_linknum, remote_wnode));

	if (wci->mh_state->link_state[local_linknum] != mh_link_up)
		return;

	DUMPWCI("Entering wrsm_mh_link_is_down", wci);

	/*
	 * Find all wnodes in the subnet which have routes
	 * using the link which is going down.
	 */
	for (wnode = 0; wnode < WRSM_MAX_WNODES; ++wnode) {
		if (wci->mh_state->reachable.nhops[wnode] !=
		    WNODE_UNREACHABLE &&
		    wci->mh_state->reachable.first_hop[wnode] == remote_wnode) {
			if (wci->mh_state->reachable.stripes[wnode] == 1) {
				set_route_nostripe(wci->lcwci, wnode,
				    ROUTE_MAP_LOCAL);
				wci->mh_state->reachable.changed[wnode] =
				    B_TRUE;
				/*
				 * If this is the local wnode, switching to
				 * ROUTE_MAP_LOCAL means internal loopback
				 * is now being used for this wnode.  In
				 * all other cases, using ROUTE_MAP_LOCAL
				 * will cause failures and is equivalent to
				 * not having a route.
				 */
				if (wnode == wci->config->local_wnode) {
					wci->mh_state->
					    reachable.nhops[wnode] = 0;
					wci->mh_state->
					    reachable.stripes[wnode] = 1;
				} else {
					wci->mh_state->
					    reachable.nhops[wnode] =
					    WNODE_UNREACHABLE;
					wci->mh_state->
					    reachable.stripes[wnode] = 0;
				}
				WRSMSET_DEL(wci->mh_state->
				    using_link[local_linknum], wnode);
			/*
			 * Else, if we were striping, and this wnode was
			 * using this link in its striping, then stop
			 * striping. Checking for stripine level isn't enough;
			 * we have to check for the link being in use because
			 * there could be three links going to same remote
			 * wnode, and the link going down could be the one
			 * not being used.
			 */
			} else if (
			    wci->mh_state->reachable.stripes[wnode] == 2 &&
			    WRSM_IN_SET(wci->mh_state->
				using_link[local_linknum], wnode)) {
				/* Fix route maps to be unstriped */
				set_route_unstripe(wci->lcwci, wnode,
				    local_linknum);
				/* Turn off striping on that link */
				wci->mh_state->reachable.stripes[wnode] = 1;
				WRSMSET_DEL(wci->mh_state->
				    using_link[local_linknum], wnode);
				DPRINTF(DBG_MH, (CE_NOTE, "mh_link_is_down: "
				    "wci %d link %d to wnode %d "
				    "disabling link striping",
				    wci->config->port, local_linknum,
				    wnode));
			}
		}
	}

	if (WRSMSET_ISNULL(wci->mh_state->using_link[local_linknum]))
		wci->mh_state->link_state[local_linknum] = mh_link_down;

	wrsm_nr_mhdirect(wci, &(wci->mh_state->reachable));

	for (wnode = 0; wnode < WRSM_MAX_WNODES; ++wnode) {
		wci->mh_state->reachable.changed[wnode] = B_FALSE;
	}
	DUMPWCI("Exiting wrsm_mh_link_is_down", wci);
}

/*
 * For a given WCI and a remote wnodeid, find the link.
 * This is used to populate the wrsm_route_kstat.
 */
int
wrsm_mh_wnode_to_link(ncwci_handle_t ncwci, int wnodeid)
{
	struct wrsm_ncwci *wci = (struct wrsm_ncwci *)ncwci;
	int i;

	if (wci == NULL || wci->mh_state == NULL) {
		return (-1);
	}

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
	    if (WRSM_IN_SET(wci->mh_state->using_link[i], wnodeid)) {
		return (i);
	    }
	}
	return (-1);
}

/*
 * For a given WCI, determine if the given link leads to given remode wnodeid
 * This is used to populate the wrsm_route_kstat.
 */
boolean_t
wrsm_mh_link_to_wnode(ncwci_handle_t ncwci, int link, int wnodeid)
{
	struct wrsm_ncwci *wci = (struct wrsm_ncwci *)ncwci;

	if (wci == NULL || wci->mh_state == NULL) {
		return (B_FALSE);
	}

	return (boolean_t)
	    (WRSM_IN_SET(wci->mh_state->using_link[link], wnodeid));
}
