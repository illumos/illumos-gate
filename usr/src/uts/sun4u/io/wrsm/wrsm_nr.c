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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Network routing module of the Wildcat RSM driver.  This file manages
 * routes to nodes.  It calculates which links to use to route transactions
 * to each remote node, based on the preferred route list for that node.
 * It handles failing routes between links and wcis.  This includes setting
 * up and tearing down wci striping.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/cpuvar.h>
#include <sys/tnf_probe.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/callb.h>
#include <sys/nvpair.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>


#include <sys/wci_regs.h>
#include <sys/wci_offsets.h>
#include <sys/wci_common.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_nc_impl.h>
#include <sys/wrsm_lc.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_memseg.h>

#ifdef DEBUG
#define	DBG_CONFIG		0x001
#define	DBG_ROUTE		0x002
#define	DBG_HW			0x004
#define	DBG_EVENT		0x008
#define	DBG_CONFIG_EXTRA	0x010
#define	DBG_ROUTE_EXTRA		0x020
#define	DBG_HW_EXTRA		0x040
#define	DBG_EVENT_EXTRA		0x080
#define	DBG_WARN		0x100
#define	DBG_RT_KSTAT		0x200
/*
 * Shouldn't actually call cmn_err while cpus are paused -- this could
 * cause a kmem_alloc to create the string to print, which might require a
 * lock, which if currently taken will never be freed because the owning
 * cpu is now paused...  ask me how I know.  In other words, use these
 * debug flags at your own risk.
 */
#define	DBG_PAUSECPUS		0x1000
#define	DBG_PAUSECPUS_EXTRA	0x2000
#define	DBG_PAUSECPUSWARN	0x4000

/*
 * 0xff0f - DBG_CONFIG_EXTRA DBG_ROUTE_EXTRA DBG_HW_EXTRA DBG_EVENT_EXTRA
 * not turned on
 */
static uint_t wrsm_nr_debug = DBG_WARN;

#define	DPRINTF(a, b) { if (wrsm_nr_debug & a) wrsmdprintf b; }

#else /* DEBUG */
#define	DPRINTF(a, b) { }
#endif /* DEBUG */

static void nr_event_thread(wrsm_network_t *network);
static void nr_wait_for_event_drain(wrsm_network_t *network);
static void nr_wait_for_wcis_rerouted(wrsm_network_t *network);
static void nr_pause_event_thread(wrsm_network_t *network);
static void nr_unpause_event_thread(wrsm_network_t *network);
static void nr_process_event(wrsm_network_t *network,
    wrsm_nr_event_t *event);

static wrsm_ncwci_t *nr_safid_to_wci(wrsm_network_t *network, safari_port_t);
static void nr_wci_routechange(wrsm_ncwci_t *wci,
    wrsm_mh_reachable_t *reachable, wrsm_wci_reroute_t reroute);
static void nr_reroute_wcis(void *arg);
static boolean_t wci_in_use(wrsm_ncwci_t *wci);
static void nr_update_wci(wrsm_ncwci_t *wci);
static void nr_add_extended_routes(wrsm_node_t *local_node,
    wrsm_controller_t *config);
static void nr_free_extended_routes(wrsm_node_t *local_node);

static wrsm_nc_strgrp_t *nr_sgid_to_sg(wrsm_network_t *network,
    uint32_t sgid);
static int nr_sg_install(wrsm_network_t *network);
static int nr_sg_unstripe(wrsm_nc_strgrp_t *sg);
static int nr_sg_stripe(wrsm_nc_strgrp_t *sg);

static boolean_t nr_cnode_route(wrsm_node_t *node);
static void ncslice_build_route(wrsm_node_t *node, ncslice_route_t *routep,
    wrsm_preferred_route_t *proute, boolean_t force);
static int ncslice_one_wci_route(wrsm_routing_policy_t *policy,
    ncslice_route_t *routep, wrsm_preferred_route_t *proute,
    cnode_bitmask_t used_switches, int max_stripes, wrsm_ncwci_t *wci,
    int wcinum);
static void ncslice_build_wci_route(wrsm_routing_policy_t *policy,
    ncslice_route_t *routep, wrsm_preferred_route_t *proute, wrsm_ncwci_t *wci);
static void ncslice_build_sg_route(wrsm_routing_policy_t *policy,
    ncslice_route_t *routep, wrsm_preferred_route_t *proute,
    wrsm_nc_strgrp_t *sg);
static void ncslice_build_sg_nostripe_route(wrsm_routing_policy_t *policy,
    ncslice_route_t *routep, wrsm_preferred_route_t *proute,
    wrsm_nc_strgrp_t *sg);
static boolean_t ncslice_routes_match(ncslice_route_t *route1,
    ncslice_route_t *route2);
static boolean_t ncslice_switch_to_inids(wrsm_ncwci_t *wci, cnodeid_t cnodeid);
static int ncslice_find_inid(wrsm_ncwci_t *wci, wnodeid_t *dnidlist,
    int stripes, cnodeid_t cnodeid);
static void ncslice_add_hw_route(wrsm_node_t *node, ncslice_route_t route);
static void ncslice_remove_hw_route(wrsm_node_t *node, ncslice_route_t route);
static void ncslice_apply_routes(wrsm_network_t *network);

static void nr_reroute_start(wrsm_network_t *network);
static void nr_reroute_finish(wrsm_network_t *network);
static void nr_noroute(wrsm_node_t *node);
static boolean_t nr_haveroute(wrsm_node_t *node);

static void pt_noroute(wrsm_node_t *node);
static boolean_t pt_haveroute(wrsm_node_t *node);
static void pt_newptinfo(wrsm_network_t *network, pt_msgtype_t msgtype,
    wrsm_node_t *node);
static int pt_sendptlist(wrsm_node_t *node, wrsm_message_t *msg);
static boolean_t pt_ptlist_recv_hdlr(wrsm_network_t *network,
    wrsm_message_t *msg);
static void pt_route_update(wrsm_node_t *node, cnode_bitmask_t pt_provided,
    int route_counter);
static void stop_ncslice_traffic(wrsm_network_t *network,
    boolean_t stop_incoming);
static void restart_ncslice_traffic(wrsm_network_t *network,
    boolean_t stop_incoming);
static void nr_rag_freeze(wrsm_ncwci_t *wci, uint_t number_of_nodes);
static void add_wrsm_route_kstat(wrsm_node_t *node);
static void del_wrsm_route_kstat(wrsm_node_t *node);
static int update_wrsm_route_kstat(kstat_t *ksp, int rw);
/*
 * Freezes number_to_freeze of RAG instances starting at 0th bit.
 * Its is required that the CPUs be inactive before calling this function if
 * the number of RAGS to freeze (number_to_freeze) is greater than the number
 * of RAGs currently frozen.
 * We call this function in wrsm_nr_replaceconfig after freezing CPUs
 * in order to freeze additional RAG instances.  We call this function from
 * wrsm_nr_enableconfig without freezing CPUs in order to unfreeze RAG
 * instances.
 */
static void
nr_rag_freeze(wrsm_ncwci_t *wcip, uint_t number_of_nodes)
{
	uint_t number_to_freeze;
	wci_ra_freeze_u wci_ra_freeze;
	int i;

#ifdef DEBUG
	wci_ra_busy_u wci_ra_busy;
#endif

	DPRINTF(DBG_HW, (CE_CONT, "nr_rag_freeze() "));
	number_to_freeze = WRSM_MAX_RAG_INSTANCE -
	    min(WRSM_MAX_RAG_INSTANCE, (WRSM_MAX_CNODES/number_of_nodes));
	while (wcip) {
		if ((wcip->lcwci == NULL) || (wcip->network == NULL)) {
			wcip = wcip->next;
			continue;
		}
#ifdef DEBUG
		wrsm_lc_csr_read(wcip->lcwci, (uint64_t)ADDR_WCI_RA_FREEZE,
		    &(wci_ra_freeze.val));
		wrsm_lc_csr_read(wcip->lcwci, (uint64_t)ADDR_WCI_RA_BUSY,
		    &(wci_ra_busy.val));

		DPRINTF(DBG_HW, (CE_CONT, "nr_rag_freeze: controller %d,"
		    "cnode id %d number of nodes %d, Initial wci_ra_freeze "
		    "0x%lx initial wci_ra_busy 0x%lx",
		    wcip->network->rsm_ctlr_id, wcip->network->cnodeid,
		    number_of_nodes,  wci_ra_freeze.bit.vector,
		    wci_ra_busy.val));
#endif /* DEBUG */

		/*
		 * we don't need to worry about saving Instances frozen due to
		 * error since such an occurence will cause the domain to
		 * go dead.
		 */

		wci_ra_freeze.val = 0;
		DPRINTF(DBG_HW, (CE_CONT, "nr_rag_freeze: number to"
		    "freeze %d", number_to_freeze));
		/* per PRM, bits are to be set starting from 0th bit up */
		for (i = 0; i < number_to_freeze; i ++) {
			wci_ra_freeze.bit.vector |= 1 << i;
		}
		wrsm_lc_csr_write(wcip->lcwci, (uint64_t)ADDR_WCI_RA_FREEZE,
		    wci_ra_freeze.val);
#ifdef DEBUG
		wrsm_lc_csr_read(wcip->lcwci, (uint64_t)ADDR_WCI_RA_FREEZE,
		    &(wci_ra_freeze.val));
		DPRINTF(DBG_HW, (CE_CONT, "nr_rag_freeze: final value 0x%lx",
		    wci_ra_freeze.bit.vector));
#endif /* DEBUG */
		wcip = wcip->next;

	}

}

/*
 * Configuration Functions
 *
 * The configuration functions and wci add/delete function
 * (wrsm_nr_replaceconfig(), wrsm_nr_cleanconfig(), wrsm_nr_installconfig(),
 * wrsm_nr_enableconfig(), wrsm_nr_initialconfig(), wrsm_nr_removeconfig(),
 * wrsm_nr_attachwci(), wrsm_nr_enablecwci() and wrsm_nr_detachwci()) are all
 * guaranteed to be single threaded.  The config layer causes the NC to
 * call these functions.  The config later is the only consumer of these and
 * it will never call a second function in the NC before the first is
 * complete, so none of these functions will be called while another one is
 * still running.
 */


/*
 * verify that the routing configuration meets certain requirements
 */
int
wrsm_nr_verifyconfig(wrsm_network_t *network, wrsm_controller_t *config,
    int attached_cnt, wci_ids_t *attached_wcis)
{
	wrsm_wci_data_t *wciconfig;
	wrsm_nc_strgrp_t *sg;
	wrsm_stripe_group_t *sgconfig;
	int i, j, k, wnid;
	boolean_t found;
	safari_port_t port;
	wrsm_routing_policy_t *policy;
	wrsm_preferred_route_t *proute;
	wrsm_ncwci_t *wci;
	boolean_t have_local;
	int err;

	ASSERT(network);
	ASSERT(config);

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_verifyconfig()\n",
	    network->rsm_ctlr_id));

	if (!config->routing) {
		DPRINTF(DBG_WARN, (CE_WARN,
		    "wrsm_nr_verifyconfig: no routing info\n"));
		return (EINVAL);
	}

	/*
	 * 2 WCIs are not allowed to be part of the same multi-hop network.
	 * Check this by verifying that no wnode/cnode on a wci refers to
	 * the local node.
	 */

	for (i = 0; i < config->routing->nwcis; i++) {
		wciconfig = config->routing->wcis[i];

		for (wnid = 0; wnid < WRSM_MAX_WNODES; wnid++) {
			if (wciconfig->wnode_reachable[wnid]) {
				if (wciconfig->reachable[wnid] ==
				    config->cnodeid) {
					/*
					 * This wnode refers the local node.
					 * This is only ok if this is the local
					 * wnode for this wci (for loopback).
					 */
					if (wnid != wciconfig->local_wnode) {
						DPRINTF(DBG_WARN, (CE_WARN,
						    "wrsm_nr_verifyconfig: "
						    "wci %d: non-local wnode %d"
						    " goes to this node (%d)\n",
						    wciconfig->port,
						    wnid, config->cnodeid));
						return (EINVAL);
					}
				}

				/*
				 * Make sure there is an nmembers structure
				 * for any cnode in the reachable list.
				 */

				for (j = 0; j < config->nmembers; j++) {
					if (wciconfig->reachable[wnid] ==
					    config->members[j]->cnodeid)
						break;
				}
				if (j == config->nmembers) {
					/*
					 * no nmember node for wci
					 * cnodeid
					 */
					DPRINTF(DBG_WARN, (CE_WARN,
					    "wrsm_nr_verifyconfig: "
					    "wci %d wnode %d: cnode %d "
					    "doesn't exist in this "
					    "config\n", wciconfig->port,
					    wnid, wciconfig->
					    reachable[wnid]));
					return (EINVAL);
				}
			}
		}
	}

	/*
	 * verify that the stripe group configuration is allowed on this
	 * platform.  Also verify that each WCI mentioned in the stripe
	 * group is in the config.
	 */
	for (i = 0; i < config->routing->ngroups; i++) {
		if ((err = wrsmplat_stripegroup_verify(
			config->routing->stripe_groups[i])) != 0) {
			DPRINTF(DBG_WARN, (CE_WARN, "wrsm_nr_verifyconfig: "
			    "stripegroup_verify failed %d for group %d",
			    err, i));
			return (err);
		}

		sgconfig = config->routing->stripe_groups[i];
		for (j = 0; j < sgconfig->nwcis; j++) {
			found = B_FALSE;
			port = sgconfig->wcis[j];
			for (k = 0; k < config->routing->nwcis; k++) {
				if (port == config->routing->wcis[k]->port) {
					found = B_TRUE;
				}
			}
			if (!found) {
				DPRINTF(DBG_WARN, (CE_WARN,
				    "wrsm_nr_verifyconfig: "
				    "in stripegroup %d, wci %d "
				    "doesn't exist in this "
				    "config\n", i, port));
				return (EINVAL);
			}
		}
	}

	/*
	 * any node through which forwarding is allowed must be directly
	 * connected to it from this node - not checked here; enforced
	 * in nr_cnode_route().
	 */

	/*
	 * If the node list is not empty, the local node must be in the list.
	 */
	if (config->nmembers > 0) {
		have_local = B_FALSE;
		for (i = 0; i < config->nmembers; i++) {
			if (config->members[i]->cnodeid == network->cnodeid) {
				have_local = B_TRUE;
				break;
			}
		}

		if (!have_local) {
			DPRINTF(DBG_WARN, (CE_WARN, "local node required\n"));
			return (EINVAL);
		}
	}

	/*
	 * Ensure that each hostname is unique
	 */
	for (i = 0; i < config->nmembers; i++) {
		for (j = 0; j < config->nmembers; j++) {
			if (i == j) {
				continue;
			}
			if (strcmp(config->members[i]->hostname,
			    config->members[j]->hostname) == 0) {
				cmn_err(CE_WARN, "hostname %s repeated",
				    config->members[i]->hostname);
				return (EINVAL);
			}
		}
	}

	/*
	 * Make sure there is preferred route info for each cnode in the
	 * config.  (Both the nmember list and routing policy list are
	 * ordered by cnodeid, so the index into each for a particular
	 * cnodeid should be identical.)
	 */

	if (config->nmembers != config->routing->npolicy) {
		DPRINTF(DBG_WARN, (CE_WARN, "unmatching member and routing "
		    "policy information\n"));
		return (EINVAL);
	}
	for (i = 0; i < config->nmembers; i++) {
		if (config->routing->policy[i]->cnodeid !=
		    config->members[i]->cnodeid) {
			DPRINTF(DBG_WARN, (CE_WARN, "no routing policy for "
			    "node %d\n", config->members[i]->cnodeid));
			return (EINVAL);
		}
	}

	/*
	 * make sure each preferred route refers to a valid wci or
	 * stripe group
	 */
	for (i = 0; i < config->routing->npolicy; i++) {
		policy = config->routing->policy[i];
		for (j = 0; j < policy->nroutes; j++) {
			proute = policy->preferred_routes[j];
			if (proute->route_type == route_wci) {
				for (k = 0; k < config->routing->nwcis; k++) {
					if (config->routing->wcis[k]->port ==
					    proute->route.wci_id)
						break;
				}
				if (k == config->routing->nwcis) {
					DPRINTF(DBG_WARN, (CE_WARN, "node %d "
					    "proute %d uses illegal wci %d\n",
					    policy->cnodeid, j,
					    proute->route.wci_id));
					return (EINVAL);
				}
			} else {
				ASSERT(proute->route_type ==
				    route_stripe_group);
				for (k = 0; k < config->routing->ngroups; k++) {
					if (config->routing->
					    stripe_groups[k]->group_id ==
					    proute->route.stripe_group_id)
						break;
				}
				if (k == config->routing->ngroups) {
					DPRINTF(DBG_WARN, (CE_WARN, "node %d "
					    "proute %d uses illegal sg %d\n",
					    policy->cnodeid, j,
					    proute->route.stripe_group_id));
					return (EINVAL);
				}
			}
		}
	}



	/*
	 * make sure each wci is only in one stripe group.
	 */
	for (i = 0; i < config->routing->nwcis; i++) {
		port = config->routing->wcis[i]->port;
		found = B_FALSE;
		for (j = 0; j < config->routing->ngroups; j++) {
			sgconfig = config->routing->stripe_groups[j];
			for (k = 0; k < sgconfig->nwcis; k++) {
				if (sgconfig->wcis[k] == port) {
					if (found) {
						DPRINTF(DBG_WARN, (CE_WARN,
						    "wci %d is in more than "
						    "one stripe group\n",
						    port));
						return (EINVAL);
					} else {
						found = B_TRUE;
					}
				}
			}
		}
	}

	/*
	 * there must be at least one WCI attached
	 */

	if (config->routing->nwcis > 0 && attached_cnt < 1) {
		DPRINTF(DBG_WARN, (CE_WARN, "there must be at least one "
		    "attached wci\n"));
		return (ENODEV);
	}


	/*
	 * checks for conflicts with old config, if there was one
	 */

	if (network->nr == NULL)
		return (WRSM_SUCCESS);

	/*
	 * Verify that any stripe groups in both the old and new config
	 * have matching info (same number of wcis with the same ids) Note:
	 * sgs in network and sgs in config are both ordered by group id.
	 */
	sg = network->nr->sgs;
	for (i = 0; i < config->routing->ngroups; i++) {
		sgconfig = config->routing->stripe_groups[i];

		while (sg && (sg->config->group_id < sgconfig->group_id)) {
			/* sg is not in config; skip it */
			sg = sg->next;
			continue;
		}

		if (!sg) {
			/* rest of sgs in config are new */
			break;
		}

		if (sg->config->group_id > sgconfig->group_id) {
			/* new sg in config */
			continue;
		}

		/* found matching sg */
		ASSERT(sg->config->group_id == sgconfig->group_id);

		if (sg->config->nwcis != sgconfig->nwcis) {
			DPRINTF(DBG_WARN, (CE_WARN,
			    "stripe group %d: old nwcis %d, "
			    "new nwcis %d\n", sg->config->group_id,
			    sg->config->nwcis, sgconfig->nwcis));
			return (EINVAL);
		}

		for (j = 0; j < sg->config->nwcis; j++) {
			if (sg->wcis[j]->config->port != sgconfig->wcis[j]) {
				DPRINTF(DBG_WARN, (CE_WARN, "stripe group "
				    "%d: wci #%d old port is %d, new port "
				    "is %d\n", sg->config->group_id, j,
				    sg->wcis[j]->config->port,
				    sgconfig->wcis[j]));
				return (EINVAL);
			}
		}
	}


	/*
	 * verify that the passed in LC handles match any already saved away
	 * LC handles
	 */
	for (i = 0; i < attached_cnt; i++) {
		wci = nr_safid_to_wci(network, attached_wcis[i].port);
		if (!wci)
			continue;

		if (wci->lcwci != NULL &&
		    wci->lcwci != attached_wcis[i].lcwci) {
			/*
			 * bad LC handle!
			 */
			cmn_err(CE_WARN, "wci %d - old lc handle "
			    "(0x%p) doesn't match new handle (0x%p)\n",
			    wci->config->port, (void *) wci->lcwci,
			    (void *) attached_wcis[i].lcwci);
			return (EINVAL);
		}

	}

	/*
	 * verify that new link config doesn't conflict with old link
	 * config, and that local wnode hasn't changed.
	 */
	for (i = 0; i < config->routing->nwcis; i++) {
		wciconfig = config->routing->wcis[i];
		wci = nr_safid_to_wci(network, wciconfig->port);
		if (!wci)
			continue;

		if (wci->lcwci) {
			if (!wrsm_lc_verifyconfig(wci->lcwci, wciconfig)) {
				DPRINTF(DBG_WARN, (CE_WARN, "nr_verifyconfig: "
				    "lc_verifyconfig failed"));
				return (EINVAL);
			}
		}

		for (wnid = 0; wnid < WRSM_MAX_WNODES; wnid++) {
			if (wci->config->wnode_reachable[wnid] &&
			    wci->config->reachable[wnid] == network->cnodeid &&
			    wci->config->reachable[wnid] !=
			    wciconfig->reachable[wnid]) {
				DPRINTF(DBG_WARN, (CE_WARN, "nr_verifyconfig: "
				    "local wnodeid has changed from %d "
				    "to %d cnodeid %d",
				    wci->config->reachable[wnid],
				    wciconfig->reachable[wnid],
				    network->cnodeid, wnid));
				return (EINVAL);
			}
		}
	}

	return (WRSM_SUCCESS);
}


/*
 * set up initial configuration structures for the NR
 */
boolean_t
wrsm_nr_initialconfig(wrsm_network_t *network,
    int attached_cnt, wci_ids_t *attached_wcis)
{
	ASSERT(network);

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_initialconfig()\n",
	    network->rsm_ctlr_id));

	if (!network->nr) {
		network->nr = (wrsm_nr_t *)kmem_alloc(sizeof (wrsm_nr_t),
		    KM_SLEEP);
		bzero(network->nr, sizeof (wrsm_nr_t));
		cv_init(&(network->nr->event_cv), NULL, CV_DEFAULT, NULL);
		cv_init(&(network->nr->config_cv), NULL, CV_DEFAULT, NULL);
		rw_init(&(network->nr->wcilist_rw), NULL, RW_DEFAULT, NULL);
		mutex_init(&(network->nr->lock), NULL, MUTEX_DRIVER, NULL);
		(void) wrsm_tl_add_handler(network,
		    WRSM_MSG_CONFIG_PASSTHROUGH_LIST, WRSM_TL_NO_HANDLER,
		    pt_ptlist_recv_hdlr);
		wrsm_cmmu_init(network, (unsigned)attached_cnt, attached_wcis);
		/*
		 * Per wci cmmu init is not needed
		 * on an initial config.
		 */
		network->nr->init_cmmu = B_FALSE;
		return (B_TRUE);

	} else {
		network->nr->init_cmmu = B_TRUE;
		return (B_FALSE);
	}

}



/*
 * Allocate data structures for and store routing info for nodes, wcis,
 * stripe groups.  Mark old wcis and stripe groups as disabled.  Call
 * lc_replaceconfig() for each old and new wci.
 */
int
wrsm_nr_replaceconfig(wrsm_network_t *network, wrsm_controller_t *config,
    int attached_cnt, wci_ids_t *attached_wcis)
{
	int i, j;
	cnodeid_t cnodeid;
	wrsm_ncwci_t **wcip, *wci, *newwci;
	wrsm_wci_data_t *wciconfig;
	wrsm_nc_strgrp_t **sgp, *sg, *newsg;
	wrsm_stripe_group_t *sgconfig;
	wrsm_node_t *node;

	ASSERT(network);
	ASSERT(config);

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_replaceconfig()\n",
	    network->rsm_ctlr_id));

	ASSERT(network->availability == wrsm_disabled);

	/* start event thread for this network */
	if (!network->nr->event_thread) {
		network->nr->stop_event_thr = B_FALSE;
		network->nr->event_thread = thread_create(NULL, 0,
		    nr_event_thread, network, 0, &p0, TS_RUN, maxclsyspri);
	}

	/*
	 * cancel any pending timeout to reconfig wcis
	 */
	if (network->nr->wcireroute_timeout_id) {
		/*
		 * cancels timeout or waits until it is finished
		 */
		(void) untimeout(network->nr->wcireroute_timeout_id);
		network->nr->wcireroute_timeout_id = 0;
	}

	/*
	 * Cancel any pending timeout to resend passthrough messages
	 * until the new configuration is installed.
	 */
	if (network->nr->pt_retry_timeout_id) {
		/*
		 * cancels timeout or waits until it is finished
		 */
		(void) untimeout(network->nr->pt_retry_timeout_id);
		network->nr->pt_retry_timeout_id = 0;
	}


	/*
	 * pause the event thread while modifying data structures it
	 * uses
	 */
	nr_pause_event_thread(network);

#ifdef DEBUG
	/*
	 * Both the list of config wcis and the list of network wcis
	 * is ordered by safari port id.
	 */
	for (i = 1; i < config->routing->nwcis; i++) {
		ASSERT(config->routing->wcis[i]->port >
		config->routing->wcis[i-1]->port);
	}

	wci = network->nr->wcis;
	if (wci)
		for (; wci->next != NULL; wci = wci->next) {
			ASSERT(wci->next->config->port > wci->config->port);
		}
#endif

	/*
	 * Update list of wcis to match config wcis -
	 * create wci structs for new wcis; disable old wcis; call
	 * LC for each wci
	 */
	wcip = &(network->nr->wcis);
	wci = *wcip;
	for (i = 0; i < config->routing->nwcis; i++) {
		wciconfig = config->routing->wcis[i];
		while (wci && (wci->config->port < wciconfig->port)) {
			/*
			 * this wci doesn't exist in the new config
			 * mark it as disabled
			 */

			wci->availability = wrsm_disabled;
			WRSMSET_ZERO(wci->nr.cnode_retry);
			if (wci->lcwci) {
				/* notify LC that LC is not in config */
				wrsm_lc_replaceconfig(wci->lcwci, wci, NULL,
				    NULL);
			}
			wcip = &(wci->next);
			wci = *wcip;

		}


		if (wci == NULL || wci->config->port > wciconfig->port) {
			/* wci is new */
			newwci = kmem_alloc(sizeof (wrsm_ncwci_t), KM_SLEEP);
			bzero(newwci, sizeof (wrsm_ncwci_t));
			newwci->network = network;
			newwci->reroute_state = wci_rerouted;
			newwci->availability = wrsm_enabled;
			newwci->nr.using_inids = B_FALSE;
			newwci->nr.reserved_inids = B_FALSE;

			ASSERT(wciconfig->reachable[wciconfig->local_wnode] ==
			    network->cnodeid);

			/* mark all wnodes as unreachable */
			for (j = 0; j < WRSM_MAX_WNODES; j++) {
				newwci->nr.mh_reachable.nhops[j] =
				    WNODE_UNREACHABLE;
			}

			/*
			 * add wci to network's list of wcis
			 * Take rw lock to prevent controller barrier
			 * code (nr_check_all_*()) from getting confused.
			 * (All other accesses of the network->nr_wcis
			 * list are singled threaded config/event thread
			 * accesses.)
			 */
			rw_enter(&network->nr->wcilist_rw, RW_WRITER);
			newwci->next = wci;
			*wcip = newwci;
			wci = *wcip;
			rw_exit(&network->nr->wcilist_rw);
		}

		/*
		 * A wci struct now exists in network struct for this wci;
		 * replace old config info with new info and move to next
		 * wci in network list
		 */
		wci->config = wciconfig;
		wcip = &(wci->next);
		wci = *wcip;
	}

	/*
	 * Any remaining wcis in the network list must no longer
	 * be part of the configuration. Mark them as disabled.
	 */
	while (wci) {
		/*
		 * this wci doesn't exist in the new config
		 * mark it as disabled
		 */

		wci->availability = wrsm_disabled;
		WRSMSET_ZERO(wci->nr.cnode_retry);

		if (wci->lcwci) {
			/* notify LC that LC is not in config */
			wrsm_lc_replaceconfig(wci->lcwci, wci, NULL, NULL);
		}
		wci = wci->next;
	}

	for (i = 0; i < attached_cnt; i++) {
		wci = nr_safid_to_wci(network, attached_wcis[i].port);
#ifdef DEBUG
		if (!wci) {
			DPRINTF(DBG_WARN, (CE_WARN,
			    "wrsm_nr_replaceconfig() "
			    "no wci for attached_wci #%d (id %d)\n", i,
			    attached_wcis[i].port));
			continue;
		}
		if (attached_wcis[i].lcwci == NULL) {
			DPRINTF(DBG_WARN, (CE_WARN,
			    "wrsm_nr_replaceconfig() "
			    "no lcwci for attached_wci #%d (id %d)\n", i,
			    attached_wcis[i].port));
			continue;
		}
#endif
		ASSERT(wci);
		if (wci->lcwci == NULL) {
			/*
			 * new attach - if wrsm_nr_attachwci() fails, the
			 * LC will not be informed of the new WCI,
			 * and it won't come up
			 */
			(void) wrsm_nr_attachwci(network, wci->config->port,
			    attached_wcis[i].lcwci, config,
			    network->nr->init_cmmu, B_FALSE);
		} else {
			/* give LC the replacement configuration */
			wrsm_lc_replaceconfig(wci->lcwci, wci, wci->config,
			    config);
		}

		DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "wrsm_nr_replaceconfig() "
		    "wci %d has lcwci (%p)\n", wci->config->port,
		    (void *)wci->lcwci));
	}


#ifdef DEBUG
	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "wrsm_nr_replaceconfig() "
		    "wci %d: availability %d\n", wci->config->port,
		    wci->availability));
	}
#endif

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "wrsm_nr_replaceconfig() "
		    "number of nodes  %d", network->wrsm_num_nodes));
	if (network->wrsm_num_nodes > WRSM_RAG_FREEZE_NODE_LIMIT) {
		stop_ncslice_traffic(network, B_FALSE);
		/*
		 * Assumption:  All WCI's in a controller will have the
		 * same number of nodes in their multihop group, hence we
		 * apply the same rag freeze algorithm to the entire list
		 * of wcis (network->nr->wcis).
		 */
		nr_rag_freeze(network->nr->wcis, network->wrsm_num_nodes);
		restart_ncslice_traffic(network, B_FALSE);
	}

	/*
	 * mark disabled cnodes as no longer needing a route
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];

		if ((node != NULL) && (node->availability == wrsm_disabled)) {
			node->routeinfo->route_state = ncslice_remove_route;
		}
	}

	/*
	 * Free old extended preferred route list if there is one.
	 */
	nr_free_extended_routes(network->nodes[network->cnodeid]);

	/*
	 * Update the preferred routes for each cnode in the config.
	 */
	for (i = 0; i < config->routing->npolicy; i++) {
		cnodeid = config->routing->policy[i]->cnodeid;

		node = network->nodes[cnodeid];
		ASSERT(node != NULL);

		if (node->routeinfo == NULL) {
			DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "adding routinfo "
			    "for node %d (%d)\n", node->config->cnodeid,
			    cnodeid));
			node->routeinfo = kmem_alloc(
			    sizeof (wrsm_node_routeinfo_t), KM_SLEEP);
			bzero(node->routeinfo, sizeof (wrsm_node_routeinfo_t));

			node->routeinfo->policy = kmem_alloc
			    (sizeof (wrsm_routing_policy_t), KM_SLEEP);

			/* Create the route kstat */
			add_wrsm_route_kstat(node);
		}
		bcopy(config->routing->policy[i], node->routeinfo->policy,
		    sizeof (wrsm_routing_policy_t));
		node->routeinfo->current_route.proute = NULL;
		node->routeinfo->new_route.proute = NULL;
	}

	/*
	 * For local node, extend the preferred route list to include
	 * internal loopback routes through all wcis.  This guarantees
	 * there is a loopback route even if a particular wci is removed.
	 * (It is not permitted to remove the last wci in a controller.)
	 */
	nr_add_extended_routes(network->nodes[network->cnodeid], config);


#ifdef DEBUG
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (node == NULL)
			continue;

		if (node->routeinfo == NULL) {
			panic("missing routinfo (and policy) info for "
			    "node %d\n", node->config->cnodeid);
		}
	}
#endif


	/*
	 * Update list of stripe groups to match config stripe groups -
	 * add sgs, set old sgs to disabled.
	 *
	 * Both the list of config stripe groups and the list of network
	 * stripe groups is ordered by group id.
	 */

#ifdef DEBUG
	for (i = 1; i < config->routing->ngroups; i++) {
		ASSERT(config->routing->stripe_groups[i]->group_id >
		config->routing->stripe_groups[i-1]->group_id);
	}

	sg = network->nr->sgs;
	if (sg)
		for (; sg->next != NULL; sg = sg->next) {
			ASSERT(sg->next->config->group_id >
			    sg->config->group_id);
		}
#endif
	sgp = &(network->nr->sgs);
	sg = *sgp;
	for (i = 0; i < config->routing->ngroups; i++) {
		sgconfig = config->routing->stripe_groups[i];
		while (sg && (sg->config->group_id < sgconfig->group_id)) {
			/*
			 * this stripe group doesn't exist in the new config
			 * mark it as disabled
			 */

			sg->availability = wrsm_disabled;
			sgp = &(sg->next);
			sg = *sgp;
		}


		if (sg == NULL || sg->config->group_id > sgconfig->group_id) {
			/* sg is new */
			newsg = kmem_alloc(sizeof (wrsm_nc_strgrp_t), KM_SLEEP);
			bzero(newsg, sizeof (wrsm_nc_strgrp_t));
			newsg->network = network;
			newsg->availability = wrsm_pending;

			for (j = 0; j < sgconfig->nwcis; j++) {
				DPRINTF(DBG_CONFIG, (CE_CONT, "sg %d includes "
				    "wci #%d (id %d)\n", sgconfig->group_id,
				    j, sgconfig->wcis[j]));

				newsg->wcis[j] = nr_safid_to_wci(network,
					    sgconfig->wcis[j]);
				ASSERT(newsg->wcis[j]);
			}

			newsg->config = sgconfig;

			/*
			 * add sg to network's list of sgs
			 */
			newsg->next = sg;
			*sgp = newsg;
			sg = *sgp;
		}

		/*
		 * An sg now exists in network struct for this stripe
		 * group; if it was there already, it was already checked
		 * (in wrsm_nr_verifyconfig()) to be sure it matches the one
		 * in the new config
		 */
		sgp = &(sg->next);
		sg = *sgp;
	}

	/*
	 * Any remaining sgs in the network list must no longer
	 * be part of the configuration. Mark them as disabled.
	 */
	while (sg) {
		/*
		 * this sg doesn't exist in the new config
		 * mark it as disabled
		 */

		sg->availability = wrsm_disabled;
		WRSMSET_ZERO(sg->cnode_retry);
		sg = sg->next;
	}


#ifdef DEBUG
	for (sg = network->nr->sgs; sg != NULL; sg = sg->next) {
		DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "wrsm_nr_replaceconfig() "
		    "sg %d: availability %d\n", sg->config->group_id,
		    sg->availability));
	}
#endif

	/*
	 * ok to restart event thread
	 */
	nr_unpause_event_thread(network);
	return (WRSM_SUCCESS);

}
uint32_t
wrsm_nr_getcontroller_id(wrsm_ncwci_t *ncwci)
{
	ASSERT(ncwci);
	return (ncwci->network->rsm_ctlr_id);
}

#define	SETLINKBIT(id, bits)	((id) | (1 << (bits)))

/*
 * sets the event name/attribute pair in attr_list for each valid
 * striped wci. attibutes are the safari portid and one bitmask for a links
 * used on all wcis. returns error from nvlist_xxx calls.
 */
int
nr_get_wcieventdata(nvlist_t *attr_list, wrsm_node_t *node)
{
	ncslice_route_t cur_rte;
	char wcistr[5];
	int i, j;
	inidwnode_route_t wroute;
	int err;
	int link;
	int wnodeid;

	/*
	 * linkbitmask is a bitmask of all links for all 4 wci's
	 * such that bits 0-2  represent link 0, 1, 2 for the first
	 * wci. bit 3-5 represent links 0, 1, 2 for the second and so on.
	 */
	uint32_t linkbitmask = 0;

	/*
	 * Copy the current route info into a local data structure
	 */
	ASSERT(node);
	ASSERT(node->routeinfo);

	cur_rte = node->routeinfo->current_route;

	for (i = 0; i < cur_rte.nwcis; i++) {
		ASSERT(i < WRSM_MAX_WCIS_PER_STRIPE);
		/* Get the wroute for this stripe */
		wroute = cur_rte.wroutes[i];
		(void) sprintf(wcistr, "wci%d", i);

		if (wroute.wci == NULL) {
			/* this piece should never happen */
			err = nvlist_add_int32(attr_list,
			    wcistr, -1);
			if (err != DDI_SUCCESS) {
				return (err);
			}
			continue;
		}
		err = nvlist_add_uint32(attr_list,
		    wcistr, (int32_t)wroute.wci->config->port);
		if (err != DDI_SUCCESS) {
			return (err);
		}

		/*
		 * Depending on the route type, the link and
		 * node information are found in different
		 * data structures.
		 */

		if (wroute.route_type == nid_route_inid) {
			DPRINTF(DBG_CONFIG, (CE_CONT,
			    "nid_route_inid, stripe=%d", i));
			DPRINTF(DBG_CONFIG, (CE_CONT,
			    "wroute.id = %d\n", wroute.id));

			for (j = 0; j < WRSM_MAX_DNIDS; j++) {

				/*
				 * Go through the inid2dnid table.
				 * The inid2dnid entry is the wnodeid.
				 */
				wnodeid =
				    wroute.wci->nr.inid2dnid[wroute.id].
				    wnode_list[j];
				DPRINTF(DBG_CONFIG,
				    (CE_CONT, "i=%d, wnodeid=%d", j, wnodeid));
				/*
				 * Since passthrough routes are guaranteed to
				 * not use link striping we only need to
				 * loop up the wnode to link mapping once.
				 */
				link =
				    wrsm_mh_wnode_to_link(wroute.wci, wnodeid);
				if (link != -1) {
					linkbitmask = SETLINKBIT(linkbitmask,
					    (link + (i * WRSM_LINKS_PER_WCI)));
				}
			}

		} else { /* nid_route_wnode */
			/* There will be one or two links from this wci */

			/* The wroute.id is the wnodeid. */
			wnodeid = wroute.id;
			DPRINTF(DBG_CONFIG,
			    (CE_CONT, "nid_route_wnode, wnodeid=%d", wnodeid));

			/* look at links to see which ones lead to wnode */
			for (link = 0; link < WRSM_LINKS_PER_WCI; link++) {
				if (wrsm_mh_link_to_wnode(wroute.wci, link,
				    wnodeid)) {
					linkbitmask = SETLINKBIT(linkbitmask,
					    (link + (i * WRSM_LINKS_PER_WCI)));
				}
			}
		}
	}

	/*
	 * in the event cur_rte.wcis < 4 must set to -1 remaining wci
	 * name-value pairs
	 */
	while (i < 4) {
		(void) sprintf(wcistr, "wci%d", i);
		err = nvlist_add_int32(attr_list,
			    wcistr, -1);
		if (err != DDI_SUCCESS) {
			return (err);
		}
		i++;
	}
	return (nvlist_add_uint32(attr_list, "links", linkbitmask));

}
/*
 * system event logger
 */
void
wrsm_nr_logevent(wrsm_network_t *network, wrsm_node_t *node,
    wrsm_sys_event_t eventtype, char *reason)
{
	nvlist_t *attr_list;
	int err = DDI_SUCCESS;


	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nr_logevent:"));
	ASSERT(network);
	if ((err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
		    KM_SLEEP)) == DDI_SUCCESS) {
		err = nvlist_add_uint32(attr_list, "controller",
		    network->rsm_ctlr_id);
		switch (eventtype) {
		case new_node_route:
			DPRINTF(DBG_CONFIG, (CE_CONT,
			    "wrsm_nr_logevent: new_node_route event"));
			ASSERT(node);
			ASSERT(node->config);
			if (err == DDI_SUCCESS) {
				err = nvlist_add_uint32(attr_list, "nodeid",
				    node->config->fmnodeid);
			}
			ASSERT(node->routeinfo);
			if (err == DDI_SUCCESS) {
				err = nvlist_add_int32(attr_list, "stripes",
				    node->routeinfo->current_route.stripes);
			}
			if (err == DDI_SUCCESS) {
				err = nr_get_wcieventdata(attr_list, node);
			}
			ASSERT(network->dip);
			if (err == DDI_SUCCESS) {
				err = ddi_log_sysevent(network->dip,
				    DDI_VENDOR_SUNW, WRSM_CLASS,
				    WRSM_SUBCLASS_NEW_NODE,
				    attr_list, NULL, DDI_SLEEP);
			}
			break;
		case lost_node_route:
			DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nr_logevent: "
			    "lost_node_route and reason is %s", reason));
			if (err == DDI_SUCCESS) {
				ASSERT(node);
				ASSERT(node->config);
				err = nvlist_add_uint32(attr_list, "nodeid",
				    node->config->fmnodeid);
			}
			if (err == DDI_SUCCESS) {
				err = nvlist_add_string(attr_list, "reason",
				    reason);
			}
			ASSERT(network->dip);

			if (err == DDI_SUCCESS) {
				err = ddi_log_sysevent(network->dip,
				    DDI_VENDOR_SUNW, WRSM_CLASS,
				    WRSM_SUBCLASS_LOST_NODE,
				    attr_list, NULL, DDI_SLEEP);
			}
			break;
		case new_config:

			DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nr_logevent: "
			    "new_config"));
			ASSERT(network->dip);
			if (err == DDI_SUCCESS) {
				err = ddi_log_sysevent(network->dip,
				    DDI_VENDOR_SUNW, WRSM_CLASS,
				    WRSM_SUBCLASS_NEW_CONFIG,
				    attr_list, NULL, DDI_SLEEP);
			}
			break;
		}
		nvlist_free(attr_list);
	}

	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wrsm_nr: error logging system event ");
	}
}

/*
 * Remove ncslice routes and routing data structures for disabled cnodes;
 * reroute cnodes using invalid wnode routes; takedown disabled links.
 * Call lc_cleanconfig() on each old and new wci (takes down old links).
 * Cause an MH reroute on specified wcis.
 */
int
wrsm_nr_cleanconfig(wrsm_network_t *network, int reroute_cnt,
    wci_ids_t *reroute_wcis)
{
	int i, j;
	wrsm_node_t *node;
	wrsm_ncwci_t *wci;
	wrsm_nc_strgrp_t *sg;
	wrsm_nr_event_t *event;
	boolean_t reroute;
	cnode_bitmask_t lost_route;
	wrsm_node_t *local_node;
	struct wrsm_node_routeinfo *routeinfo;

	ASSERT(network);
	ASSERT(network->availability == wrsm_pending);

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_cleanconfig()\n",
	    network->rsm_ctlr_id));

	WRSMSET_ZERO(lost_route);

	/*
	 * temporarily stop processing of wnode route events
	 * while queuing up a bunch of them
	 */
	nr_pause_event_thread(network);

	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		/*
		 * tell the LC to update the link states based on the
		 * configuration; this will cause the LC to (immediately)
		 * notify the MH that certain links are down (any that
		 * are no longer valid in the new config).  This should
		 * cause the MH to (immediately) queue evt_mhdirect events
		 * for the event thread to process.
		 */
		if (wci->lcwci)
			wrsm_lc_cleanconfig(wci->lcwci);

		/*
		 * Modify wnodeinfo array of each wci to match new config
		 * for future route decisions.  Remove references to
		 * disabled cnodes. Request that all cnodes using a no
		 * longer valid wnode have their routes re-evaluated.
		 */

		for (i = 0; i < WRSM_MAX_WNODES; i++) {
			reroute = B_FALSE;
			if (wci->availability == wrsm_disabled) {
				wci->nr.wnodeinfo[i].valid = B_FALSE;
				reroute = B_TRUE;

			} else if (wci->config->wnode_reachable[i]) {
				/* valid wnode in the new config */

				if (wci->nr.wnodeinfo[i].valid &&
				    wci->nr.wnodeinfo[i].cnodeid !=
				    wci->config->reachable[i]) {
					/*
					 * wnodeid to cnodeid mapping changed;
					 * request rerouting for any nodes
					 * using wnode, then treat as a newly
					 * valid wnodeid.
					 */
					wci->nr.wnodeinfo[i].valid = B_FALSE;
					reroute = B_TRUE;
					DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT,
					    "wci %d wnode %d "
					    "old cnode %d new cnode %d\n",
					    wci->config->port, i,
					    wci->nr.wnodeinfo[i].cnodeid,
					    wci->config->reachable[i]));

				}

				/* set new values for wnode */
				if (!wci->nr.wnodeinfo[i].valid) {
					wci->nr.wnodeinfo[i].cnodeid =
					    wci->config->reachable[i];
					wci->nr.wnodeinfo[i].valid = B_TRUE;
					wci->reroute_state = wci_need_reroute;
					DPRINTF(DBG_CONFIG, (CE_CONT,
					    "wci %d add "
					    "wnode %d cnode %d\n",
					    wci->config->port, i,
					    wci->config->reachable[i]));
				}

				WRSMSET_ZERO(wci->nr.wnodeinfo[i].interested);

			} else {
				/* invalid wnode in this config */
				if (wci->nr.wnodeinfo[i].valid) {
					reroute = B_TRUE;
					DPRINTF(DBG_CONFIG, (CE_CONT,
					    "wci %d remove "
					    "wnode %d cnode %d\n",
					    wci->config->port, i,
					    wci->nr.wnodeinfo[i].cnodeid));
				}
				wci->nr.wnodeinfo[i].valid = B_FALSE;
			}

			if (reroute) {
				/*
				 * old wnode is no longer valid, so
				 * figure out which nodes were using this
				 * wnode route (to request a reroute later)
				 */
				wci->reroute_state = wci_need_reroute;
				WRSMSET_OR(wci->nr.cnode_retry,
				    wci->nr.wnodeinfo[i].users);

				if (wci->nr.inids_enabled) {
					for (j = 0; j < WRSM_INID2DNID_ENTRIES;
					    j++) {
						if (WRSM_IN_SET(
						    wci->nr.inid2dnid[j].
						    wnode_bitmask, i)) {
							WRSMSET_OR(lost_route,
							    wci->
							    nr.inid2dnid[j].
							    users);
						}
					}
				} else {
					WRSMSET_OR(lost_route,
					    wci->nr.wnodeinfo[i].users);
				}
			}
		}
	}


	/*
	 * Request an ncslice reroute on any cnodes using invalid wnodes.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if ((node == NULL) || (node->availability == wrsm_disabled))
			continue;

		/*
		 * if node was using now invalid wnode, request
		 * reroute
		 */
		if (WRSM_IN_SET(lost_route, i)) {
			ASSERT(network->nodes[i]);
			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
			    "ctlr %d cleanconfig invalid wnode, "
			    "node %d check_route\n",
			    network->rsm_ctlr_id, i));
			network->nodes[i]->routeinfo->check_route =
			    B_TRUE;
		}
	}

	/*
	 * Request that all nodes using a disabled stripe group have their
	 * ncslice route re-evaluated.
	 */

	for (sg = network->nr->sgs; sg != NULL; sg = sg->next) {
		if (sg->availability == wrsm_disabled) {
			for (i = 0; i < WRSM_MAX_CNODES; i++) {
				if (WRSM_IN_SET(sg->users, i)) {
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d cleanconfig invalid sg, "
					    "node %d check_route\n",
					    network->rsm_ctlr_id, i));
					network->nodes[i]->
					    routeinfo->check_route = B_TRUE;
				}
			}
		}
	}

	/*
	 * force local node loopback route to be calculated
	 */
	DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
	    "ctlr %d cleanconfig re-eval loopback route "
	    "node %d check_route\n",
	    network->rsm_ctlr_id, network->cnodeid));
	network->nodes[network->cnodeid]->routeinfo->check_route = B_TRUE;


	/*
	 * restart network event thread
	 */
	nr_unpause_event_thread(network);

	/*
	 * wait for routes on disabled nodes to be removed
	 */
	nr_wait_for_event_drain(network);


	/*
	 * temporarily stop processing events
	 * while modifying node routinfo pointers
	 */

	nr_pause_event_thread(network);

	/*
	 * At this point, there should be no routes for or references to
	 * disabled cnodes.
	 *
	 * Remove routeinfo for disabled cnodes.  If local node is being
	 * removed (only happens when network/controller is being removed),
	 * also remove its extended preferred route info.
	 */

	local_node = network->nodes[network->cnodeid];
	if (local_node->availability == wrsm_disabled) {
		nr_free_extended_routes(local_node);
	}

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (network->nodes[i] == NULL)
			continue;

		node = network->nodes[i];
		if (node->availability == wrsm_disabled) {
			ASSERT(node->routeinfo->route_state ==
				    ncslice_no_route);
			ASSERT(node->state == wrsm_node_needroute);

			/* Delete the route kstat */
			del_wrsm_route_kstat(node);

			/*
			 * Set routeinfo to NULL after taking lock --
			 * this is to coordinate with passthrough
			 * messages. All other accesses to routeinfo
			 * are by the event thread, which is paused.
			 */
			mutex_enter(&network->nr->lock);
			routeinfo = node->routeinfo;
			node->routeinfo = NULL;
			mutex_exit(&network->nr->lock);

			ASSERT(routeinfo);
			kmem_free(routeinfo->policy,
			    sizeof (wrsm_routing_policy_t));
			kmem_free(routeinfo,
			    sizeof (wrsm_node_routeinfo_t));
		}
	}

	nr_unpause_event_thread(network);
	/*
	 * Cause an MH reroute of specified "reroute" wcis.  The
	 * reroute request will be queued after any wnode down
	 * events for this wci caused by the lc_cleanconfig() call.
	 */

	for (i = 0; i < reroute_cnt; i++) {
		wci = nr_safid_to_wci(network, reroute_wcis[i].port);
		ASSERT(wci);

		if (wci->lcwci) {
			event = kmem_alloc(sizeof (wrsm_nr_event_t),
			    KM_SLEEP);
			event->data.forcereroute.wci = wci;
			event->type = wrsm_evt_force_reroute;
			wrsm_nr_add_event(network, event, B_TRUE);
		}
	}

	nr_wait_for_event_drain(network);

	return (WRSM_SUCCESS);
}


/*
 * Make sure all rerouting around old wcis and stripe groups is complete;
 * Call lc_installconfig() on each old and new wci (brings up new links).
 * Clean up old wci and stripe group data structures.  Make sure ncslice
 * reroute caused by removal of routes is complete.  Recalculate and
 * record which nodes are interested in which wnode/stripe-group/PT routes.
 */
int
wrsm_nr_installconfig(wrsm_network_t *network)
{
	int i, j, k, cindex;
	cnodeid_t cnodeid;
	wrsm_ncwci_t *wci, **wcip;
	wrsm_nr_event_t *event;
	wrsm_nc_strgrp_t *sg;
	wrsm_node_t *node, *pt_node;
	wrsm_routing_policy_t *policy;
	wrsm_preferred_route_t *proute;
	int err;

	ASSERT(network);
	ASSERT(network->availability == wrsm_pending);

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_installconfig()\n",
	    network->rsm_ctlr_id));

	/*
	 * At this point, no old links or wnodes should be in use, and no
	 * old cnodes should be using routes.
	 */


	/*
	 * set up bitmasks describing which cnodes are interested in
	 * various wnode routes and PT routes
	 */

	/*
	 * zero out old passthrough bitmasks
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (node == NULL || node->availability == wrsm_disabled)
			continue;

		ASSERT(node->routeinfo);
		WRSMSET_ZERO(node->routeinfo->pt_interested);
	}

	/*
	 * now mark which nodes are interested in which routes
	 */
	for (cindex = 0; cindex < WRSM_MAX_CNODES; cindex++) {
		node = network->nodes[cindex];
		if (node == NULL || node->availability == wrsm_disabled)
			continue;

		policy = node->routeinfo->policy;

		/*
		 * for each route, mark in the appropriate passthrough
		 * node, wci or stripe group that this cnode is a candidate
		 * user
		 */
		for (i = 0; i < policy->nroutes; i++) {
			proute = policy->preferred_routes[i];
			if (proute->method == routing_passthrough) {
				for (j = 0; j < proute->nswitches; j++) {
					pt_node = network->nodes[
						    proute->switches[j]];
					ASSERT(pt_node);
					WRSMSET_ADD(
					    pt_node->routeinfo->pt_interested,
					    cindex);
				}
			}
			if (proute->route_type == route_wci) {
				wci = nr_safid_to_wci(network,
				    proute->route.wci_id);
				ASSERT(wci);
				for (j = 0; j < WRSM_MAX_WNODES; j++) {
					if (wci->nr.wnodeinfo[j].valid &&
					    wci->nr.wnodeinfo[j].cnodeid ==
					    cindex) {
						WRSMSET_ADD(
						    wci->nr.wnodeinfo[j].
						    interested, cindex);
					}
				}
			} else {
				ASSERT(proute->route_type ==
				    route_stripe_group);
				sg = nr_sgid_to_sg(network,
				    proute->route.stripe_group_id);
				ASSERT(sg);
				for (j = 0; j < sg->config->nwcis; j++) {
					wci = sg->wcis[j];
					ASSERT(wci);
					for (k = 0; k < WRSM_MAX_WNODES; k++) {
						if (wci->
						    nr.wnodeinfo[k].valid &&
						    wci->
						    nr.wnodeinfo[k].cnodeid ==
						    cindex) {
							WRSMSET_ADD(
							    wci->
							    nr.wnodeinfo[k].
							    interested, cindex);
						}
					}
				}
			}
		}

		/*
		 * current.proute was removed during wrsm_nr_replaceconfig,
		 * so need to recreate current.proute.
		 */
		node->routeinfo->check_route = B_TRUE;
	}

	/*
	 * Mark all wcis as needing re-evaluation by all cnodes interested
	 * in any wnode routes on the wci by setting wci's cnode_retry
	 * field.  (Evaluation takes place once check_route is set for
	 * cnode).
	 */

	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		if (wci->availability == wrsm_disabled)
			continue;

		WRSMSET_ZERO(wci->nr.cnode_retry);
		for (i = 0; i < WRSM_MAX_WNODES; i++) {
			if (!wci->nr.wnodeinfo[i].valid)
				continue;

			/*
			 * Add passthrough candidates to list of
			 * nodes interested in a possible wnode route through
			 * a particular cnode.
			 */
			cnodeid = wci->nr.wnodeinfo[i].cnodeid;
			WRSMSET_OR(wci->nr.wnodeinfo[i].interested,
			    network->nodes[cnodeid]->routeinfo->pt_interested);
#ifdef DEBUG
			DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT,
			    "wrsm_nr_installconfig() "
			    "wci %d wnode %d interested:\n",
			    wci->config->port, i));
			if (wrsm_nr_debug & DBG_CONFIG_EXTRA)
				DPRINTNODES(wci->nr.wnodeinfo[i].
				    interested);
#endif
			WRSMSET_OR(wci->nr.cnode_retry,
			    wci->nr.wnodeinfo[i].interested);
		}

#ifdef DEBUG
		DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "wrsm_nr_installconfig() "
		    "wci %d cnode_retry:\n", wci->config->port));
		if (wrsm_nr_debug & DBG_CONFIG_EXTRA)
			DPRINTNODES(wci->nr.cnode_retry);
#endif
	}

	/*
	 * Mark all stripe groups as needing a re-evaluation by all cnodes
	 * that could use stripe groups by setting sg's cnode_retry field.
	 * (Evaluation takes place once check_route is set for cnode).
	 */

	for (sg = network->nr->sgs; sg != NULL; sg = sg->next) {
		if (sg->availability == wrsm_disabled)
			continue;

		WRSMSET_ZERO(sg->cnode_retry);
		for (i = 0; i < sg->config->nwcis; i++) {
			WRSMSET_OR(sg->cnode_retry,
			    sg->wcis[i]->nr.cnode_retry);
		}
#ifdef DEBUG
		DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "wrsm_nr_installconfig() "
		    "sg %d retry:\n", sg->config->group_id));
		if (wrsm_nr_debug & DBG_CONFIG_EXTRA)
			DPRINTNODES(sg->cnode_retry);
#endif
	}

	/*
	 * Force rerouting of any wcis that are marked as needing a
	 * reroute.  This guarantees that invalid wnode routes are no longer
	 * in use.
	 */
	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		if (wci->reroute_state == wci_need_reroute) {
			event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
			event->data.forcereroute.wci = wci;
			event->type = wrsm_evt_force_reroute;
			wrsm_nr_add_event(network, event, B_TRUE);
		}
	}

	/*
	 * Wait until all wci reroutes and ncslice re-routes they cause
	 * are finished.
	 */

	nr_wait_for_event_drain(network);
	nr_wait_for_wcis_rerouted(network);


	/*
	 * At this point, all WCIs are routing only through wnodes valid in
	 * both configurations.  All ncslices are only using routes valid
	 * in both configurations.  All ncslices on wcis that are in old
	 * stripe groups are set to use only a single wci.  All ncslices
	 * using a single wci have the no_stripe bit set in their nc2nid
	 * entry.  This means the stripe group bits can be changed without
	 * affecting any ncslices.
	 */

	/* may call nr_pause_event_thread() */
	if ((err = nr_sg_install(network)) != WRSM_SUCCESS) {
		return (err);
	}

	/*
	 * Tell LC to bringup all links valid to the new configuration on
	 * each wci.  (The LC does not notify the MH of any new up links
	 * until lc_enableconfig() is called.
	 */

	network->nr->waiting_linksup = 0;
	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		if (wci->lcwci) {
			network->nr->waiting_linksup++;
			wrsm_lc_installconfig(wci->lcwci);
			if (wci->availability == wrsm_disabled) {
				wrsm_mh_remove_wci(wci);
			}
		}
	}


	/*
	 * Make sure all cnodes with check_route set due to wci reroutes
	 * have been re-evaluated and ncslices rerouted.
	 */

	nr_wait_for_event_drain(network);

	/*
	 * remove disabled wcis
	 */
	wcip = &(network->nr->wcis);
	wci = *wcip;
	while (wci) {
		if (wci->availability == wrsm_disabled) {
			DPRINTF(DBG_CONFIG, (CE_CONT, "removing wci %d\n",
			    wci->config->port));
			if (wci->lcwci) {
				wrsm_intr_delwci(network, wci->lcwci);
				(void) wrsm_cmmu_delwci(network, wci->lcwci);
				wci->lcwci = NULL;
			}
			/*
			 * remove wci from linked list
			 * Take rw lock to prevent controller barrier
			 * code (nr_check_all_*()) from getting confused.
			 * (All other accesses of the network->nr_wcis
			 * list are singled threaded config/event thread
			 * accesses.)
			 */
			rw_enter(&network->nr->wcilist_rw, RW_WRITER);
			*wcip = wci->next;
			rw_exit(&network->nr->wcilist_rw);
			kmem_free(wci, sizeof (wrsm_ncwci_t));
			wci = *wcip;
		} else {
			wcip = &(wci->next);
			wci = *wcip;
		}
	}

	return (WRSM_SUCCESS);
}


/*
 * Allow ncslice routes to use new wnode routes. Force MH reroute on certain
 * wcis with new direct wnode routes.  Set timeout to ensure MH reroute on
 * all wcis with new wnode routes.
 */
int
wrsm_nr_enableconfig(wrsm_network_t *network, int reroute_cnt,
    wci_ids_t *reroute_wcis)
{
	int i;
	wrsm_node_t *node;
	wrsm_ncwci_t *wci;
	wrsm_nr_event_t *event;
	wrsm_nr_t *nr;
	boolean_t ptnotify = B_FALSE;

	ASSERT(network);
	ASSERT(network->availability == wrsm_installed ||
	    network->availability == wrsm_installed_up);

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_enableconfig()\n",
	    network->rsm_ctlr_id));

	nr = network->nr;

	/*
	 * allow LC to notify the MH of new links that are up
	 */
	nr_pause_event_thread(network);

	for (wci = nr->wcis; wci != NULL; wci = wci->next) {
		if (wci->lcwci) {
			wrsm_lc_enableconfig(wci->lcwci);
		}
	}

	/* wait for link up notificiations to be processed */
	nr_unpause_event_thread(network);
	nr_wait_for_event_drain(network);

	if (reroute_cnt == -1) {
		/* reroute all wcis */
		nr_reroute_wcis((void *)network);

	} else {
		/*
		 * Cause an MH reroute on specified wcis, allowing them
		 * to use any new, up links.  Schedule a timeout to force
		 * MH reroute on remaining wcis in the near future.
		 */

		for (i = 0; i < reroute_cnt; i++) {
			wci = nr_safid_to_wci(network, reroute_wcis[i].port);
			ASSERT(wci);
			event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
			event->data.forcereroute.wci = wci;
			event->type = wrsm_evt_force_reroute;
			wrsm_nr_add_event(network, event, B_TRUE);
		}

		mutex_enter(&network->nr->lock);
		if (network->nr->suspended) {
			nr->need_wcireroute_timeout = B_TRUE;
		} else {
			nr->wcireroute_timeout_id = timeout(nr_reroute_wcis,
			    (void *)network, (clock_t)WRSM_ENABLE_TIMEOUT);
		}
		mutex_exit(&network->nr->lock);
	}



	/*
	 * Turn on passthrough forwarding to appropriate nodes,
	 * and send nodes the latest passthrough list from this
	 * node.
	 */

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if ((network->nodes[i] == NULL) ||
		    (i == network->cnodeid))
			continue;

		node = network->nodes[i];
		ASSERT(node->availability == wrsm_enabled);

		event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
		event->data.addpt.node = node;
		event->type = wrsm_evt_add_passthrough;
		wrsm_nr_add_event(network, event, B_TRUE);
		ptnotify = B_TRUE;
	}

	if (ptnotify) {
		event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);

		WRSMSET_ZERO(event->data.send_ptlist.list);
		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			if ((network->nodes[i] == NULL) ||
			    (i == network->cnodeid))
				continue;
			WRSMSET_ADD(event->data.send_ptlist.list, i);
		}
		event->type = wrsm_evt_send_ptlist;
		wrsm_nr_add_event(network, event, B_TRUE);
	}
	if (network->free_rag_instance) {
		/*
		 * this can be called here with out the security of
		 * stopping all network transactions because we know that
		 * nodes have been removed from the network so that
		 * instances will be either freed or untouched.
		 * The only time we must stop traffic is if we want to
		 * freeze an instance that could potentially be busy.
		 * The call to nr_rag_freeze must come after the call
		 * wrsm_lc_replaceconfig and after wci's have been removed
		 * and or added to the configuation.
		 */
		nr_rag_freeze(network->nr->wcis, network->wrsm_num_nodes);
		network->free_rag_instance = B_FALSE; /* reinit */
	}
	return (WRSM_SUCCESS);
}



/*
 * kill off event thread and remove NR related data structures for this
 * network
 */
void
wrsm_nr_removeconfig(wrsm_network_t *network)
{
	wrsm_nr_t *nr = network->nr;

	DPRINTF(DBG_CONFIG, (CE_CONT, "ctlr %d wrsm_nr_removeconfig()\n",
	    network->rsm_ctlr_id));

	wrsm_cmmu_fini(network);

	mutex_enter(&(nr->lock));
	if (nr->event_thread) {
		nr->stop_event_thr = B_TRUE;
		do {
			cv_broadcast(&(nr->event_cv));
			cv_wait(&(nr->config_cv), &(nr->lock));
		} while (nr->event_thread);
	}
	mutex_exit(&(nr->lock));


	cv_destroy(&(network->nr->event_cv));
	cv_destroy(&(network->nr->config_cv));
	rw_destroy(&(network->nr->wcilist_rw));
	mutex_destroy(&(network->nr->lock));

	kmem_free(network->nr, sizeof (wrsm_nr_t));
	network->nr = NULL;
}


/*
 * Once LC notifies the NR that all links on all wcis are up,
 * notify the NC so it can enable the network (allowing new links
 * to be used).
 */
void
wrsm_nr_all_links_up(wrsm_ncwci_t *wci)
{
	wrsm_network_t *network;

	ASSERT(wci);
	ASSERT(wci->network);
	ASSERT(wci->network->nr);
	network = wci->network;

	mutex_enter(&(network->nr->lock));
	if (!wci->linksup) {
		wci->linksup = B_TRUE;
		network->nr->waiting_linksup--;
	}
	mutex_exit(&(network->nr->lock));

	if (network->nr->waiting_linksup == 0)
		wrsm_nc_config_linksup(network);
}


/*
 * Add a route for each wci in the new configuration to the local node's
 * list of preferred routes.  This guarantees that a loopback route for the
 * local node can always be established.
 *
 * New routes are added by allocating enough space for an array containing
 * all the config-supplied routes plus these new routes.
 */
static void
nr_add_extended_routes(wrsm_node_t *local_node, wrsm_controller_t *config)
{
	int policycount;
	int nwcis;
	int i;
	wrsm_preferred_route_t *proute;

	ASSERT(local_node);
	ASSERT(local_node->config);
	ASSERT(local_node->routeinfo);
	ASSERT(local_node->routeinfo->policy);
	ASSERT(config);
	ASSERT(config->routing);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "add_extended_routes node %d",
	    local_node->config->cnodeid));

	policycount = local_node->routeinfo->policy->nroutes;
	nwcis = config->routing->nwcis;
	local_node->routeinfo->orig_nroutes = policycount;
	local_node->routeinfo->orig_routes =
	    local_node->routeinfo->policy->preferred_routes;
	local_node->routeinfo->policy->nroutes = policycount + nwcis;
	local_node->routeinfo->policy->preferred_routes =
	    kmem_alloc(sizeof (wrsm_preferred_route_t *) *
	    local_node->routeinfo->policy->nroutes, KM_SLEEP);
	local_node->routeinfo->extended_routes =
	    kmem_alloc(sizeof (wrsm_preferred_route_t) * nwcis, KM_SLEEP);
	bcopy(local_node->routeinfo->orig_routes,
	    local_node->routeinfo->policy->preferred_routes,
	    sizeof (wrsm_preferred_route_t *) * policycount);
	for (i = 0; i < nwcis; i++) {
		proute = &(local_node->routeinfo->extended_routes[i]);
		proute->striping_level = 1;
		proute->method = routing_multihop;
		proute->route_type = route_wci;
		proute->route.wci_id = config->routing->wcis[i]->port;
		local_node->routeinfo->policy->preferred_routes[policycount] =
		    proute;
		policycount++;
	}
}


/*
 * Remove extended routes from the local node's prefereed route list, and
 * point back to the original preferred route list provided by the
 * configuration.
 */
static void
nr_free_extended_routes(wrsm_node_t *local_node)
{
	ASSERT(local_node);

	if (local_node->routeinfo && local_node->routeinfo->orig_routes) {
		kmem_free(local_node->routeinfo->extended_routes,
		    sizeof (wrsm_preferred_route_t) *
		    (local_node->routeinfo->policy->nroutes -
		    local_node->routeinfo->orig_nroutes));
		kmem_free(local_node->routeinfo->policy->preferred_routes,
		    local_node->routeinfo->policy->nroutes *
		    sizeof (wrsm_preferred_route_t *));
		local_node->routeinfo->policy->preferred_routes =
		    local_node->routeinfo->orig_routes;
		local_node->routeinfo->policy->nroutes =
		    local_node->routeinfo->orig_nroutes;
		local_node->routeinfo->orig_nroutes = 0;
		local_node->routeinfo->policy->preferred_routes =
		    local_node->routeinfo->orig_routes;
		local_node->routeinfo->orig_routes = NULL;
	}
}


/*
 * Turn off striping on wcis in disabled stripe groups, then remove the
 * stripe groups.
 *
 * turn on striping on new stripe groups
 */
static int
nr_sg_install(wrsm_network_t *network)
{
	int i;
	wrsm_nc_strgrp_t *sg, **sgp;
	int err;

	ASSERT(network);
	ASSERT(network->nr);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "nr_sg_install()\n"));

	/*
	 * first, turn off striping on all wcis in disabled stripe
	 * groups
	 */
	sgp = &(network->nr->sgs);
	sg = *sgp;
	while (sg) {
		if (sg->availability == wrsm_disabled) {
			DPRINTF(DBG_CONFIG, (CE_CONT, "removing sg %d\n",
			    sg->config->group_id));
			if (sg->attached_wcis == sg->config->nwcis) {
				if ((err = nr_sg_unstripe(sg))
				    != WRSM_SUCCESS) {
					return (err);
				}
			}

			for (i = 0; i < sg->config->nwcis; i++) {
				sg->wcis[i]->nr.sg = NULL;
			}

			/* remove sg from linked list */
			*sgp = sg->next;
			kmem_free(sg, sizeof (wrsm_nc_strgrp_t));
			sg = *sgp;
		} else {
			/* this stripe group is ok; skip it */
			sgp = &(sg->next);
			sg = *sgp;
		}
	}

	/*
	 * now turn on striping on wcis in new stripe groups
	 */
	for (sg = network->nr->sgs; sg; sg = sg->next) {
		if (sg->availability == wrsm_pending) {
			for (i = 0; i < sg->config->nwcis; i++) {
				sg->wcis[i]->nr.sg = sg;
				if (sg->wcis[i]->lcwci)
					sg->attached_wcis++;
			}

			/*
			 * if all wcis in this stripe group
			 * are attached, stripe them
			 */
			if (sg->attached_wcis == sg->config->nwcis)
				if ((err = nr_sg_stripe(sg)) != WRSM_SUCCESS) {
					return (err);
				}


			sg->availability = wrsm_enabled;
		}
	}

	return (WRSM_SUCCESS);
}


/*
 * Turn off striping across wcis in the stripe group.
 * Note: all wcis must be attached.
 */
static int
nr_sg_unstripe(wrsm_nc_strgrp_t *sg)
{
	int i;
	lcwci_handle_t lcwci;
	wci_config_u wci_config;
#ifdef DEBUG
	int j;
	uint64_t offset;
	wci_nc2nid_array_u wci_nc2nid;
#endif

	ASSERT(sg);
	ASSERT(sg->config);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "nr_sg_unstripe() sg %d\n",
	    sg->config->group_id));

	nr_pause_event_thread(sg->network);

	sg->striping_on = B_FALSE;

	for (i = 0; i < sg->config->nwcis; i++) {
		lcwci = sg->wcis[i]->lcwci;
		ASSERT(lcwci);
#ifdef DEBUG
		/*
		 * verify that all used nc2nid entries are set to no stripe
		 */
		offset = (uint64_t)ADDR_WCI_NC2NID_ARRAY;
		for (j = 0; j < WRSM_MAX_CNODES; j++) {
			wrsm_lc_csr_read(lcwci, offset, &(wci_nc2nid.val));
			if (wci_nc2nid.bit.launch_remote)
				ASSERT(wci_nc2nid.bit.no_stripe);
			offset += STRIDE_WCI_NC2NID_ARRAY;
		}

#endif
		/* modify register to not do wci striping */
		wrsm_lc_csr_read(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    &(wci_config.val));
		wci_config.bit.stripe_bits = WCI_STRIPE_NONE;
		wrsm_lc_csr_write(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    wci_config.val);
	}
	nr_unpause_event_thread(sg->network);

	return (WRSM_SUCCESS);
}


/*
 * Turn on striping across all wcis in the stripe group.
 * Note: all wcis must be attached.
 */
static int
nr_sg_stripe(wrsm_nc_strgrp_t *sg)
{
	int i;
	int nwcis;
	lcwci_handle_t lcwci;
	int stripe[4];
	wci_config_u wci_config;
#ifdef DEBUG
	int j;
	uint64_t offset;
	wci_nc2nid_array_u wci_nc2nid;
#endif
	ASSERT(sg);
	ASSERT(sg->config);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "nr_sg_stripe() sg %d\n",
	    sg->config->group_id));

	nwcis = sg->config->nwcis;
	ASSERT(nwcis == 1 || nwcis == 2 || nwcis == 4);
	if (nwcis == 1)
		stripe[0] = WCI_STRIPE_NONE;
	if (nwcis == 2) {
		stripe[0] = WCI_STRIPE_2WAY_EVEN;
		stripe[1] = WCI_STRIPE_2WAY_ODD;
	} else if (nwcis == 4) {
		stripe[0] = WCI_STRIPE_4WAY_0;
		stripe[1] = WCI_STRIPE_4WAY_1;
		stripe[2] = WCI_STRIPE_4WAY_2;
		stripe[3] = WCI_STRIPE_4WAY_3;
	}

	nr_pause_event_thread(sg->network);

	for (i = 0; i < nwcis; i++) {
		lcwci = sg->wcis[i]->lcwci;
		ASSERT(lcwci);
#ifdef DEBUG
		/*
		 * verify that all used nc2nid entries are
		 * set to no stripe
		 */
		offset = (uint64_t)ADDR_WCI_NC2NID_ARRAY;
		for (j = 0; j < WRSM_MAX_CNODES; j++) {
			wrsm_lc_csr_read(lcwci, offset, &(wci_nc2nid.val));
			if (wci_nc2nid.bit.launch_remote)
				ASSERT(wci_nc2nid.bit.no_stripe);
			offset += STRIDE_WCI_NC2NID_ARRAY;
		}

#endif
		/* modify register to do wci striping */
		wrsm_lc_csr_read(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    &(wci_config.val));
		wci_config.bit.stripe_bits = stripe[i];
		wrsm_lc_csr_write(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    wci_config.val);
	}

	sg->striping_on = B_TRUE;
	nr_unpause_event_thread(sg->network);

	return (WRSM_SUCCESS);
}



/*
 * Timeout function: causes all WCIs with changed routes to perform
 * an mh reroute.
 */
static void
nr_reroute_wcis(void *arg)
{
	wrsm_network_t *network = (wrsm_network_t *)arg;
	wrsm_ncwci_t *wci;
	wrsm_nr_event_t *event;

	ASSERT(network);
	ASSERT(network->nr);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "nr_reroute_wcis()\n"));

	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		if (wci->reroute_state == wci_need_reroute) {
			event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
			event->data.forcereroute.wci = wci;
			event->type = wrsm_evt_force_reroute;
			wrsm_nr_add_event(network, event, B_TRUE);
		}
	}
}



/*
 * prepare to use new wci - call lc_replaceconfig(), other WCI
 * initialization functions
 */
int
wrsm_nr_attachwci(wrsm_network_t *network, safari_port_t saf_id,
    lcwci_handle_t lcwci, wrsm_controller_t *config, boolean_t init_cmmu,
    boolean_t pause_evt_thread)
{
	wrsm_ncwci_t *wci;
	int err;
	int i;
#ifdef DEBUG
	wci_nc2nid_array_u wci_nc2nid;
	uint64_t offset;
#endif
	ASSERT(network);

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nr_attachwci() wci %d\n",
	    saf_id));

	wci = nr_safid_to_wci(network, saf_id);
	if (wci == NULL)
		return (EINVAL);
	ASSERT(wci->availability == wrsm_enabled);
	ASSERT(wci->reroute_state == wci_rerouted);

#ifdef DEBUG
	/*
	 * verify that all nc2nid entries are turned off
	 */
	offset = (uint64_t)ADDR_WCI_NC2NID_ARRAY;
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		wrsm_lc_csr_read(lcwci, offset, &(wci_nc2nid.val));
		ASSERT(wci_nc2nid.bit.launch_remote == 0);
		offset += STRIDE_WCI_NC2NID_ARRAY;
	}
#endif /* DEBUG */

	for (i = 0; i < WRSM_MAX_WNODES; i++) {
		if (wci->nr.wnodeinfo[i].cnodeid == network->cnodeid) {
			wci->nr.wnodeinfo[i].valid = B_TRUE;
		}
	}

	if (pause_evt_thread)
		nr_pause_event_thread(network);

	wrsm_mh_new_wci(wci);

	wrsm_lc_replaceconfig(lcwci, wci, wci->config, config);

	if (init_cmmu) {
		/*
		 * Cmmu Manager has not yet been notified of this wci
		 */
		if ((err = wrsm_cmmu_newwci(network, lcwci)) != WRSM_SUCCESS) {
			wrsm_lc_replaceconfig(lcwci, wci, NULL, config);
			return (err);
		}
	}

	if ((err = wrsm_intr_newwci(network, lcwci)) != WRSM_SUCCESS) {
		if (init_cmmu)
			(void) wrsm_cmmu_delwci(network, lcwci);
		wrsm_lc_replaceconfig(lcwci, wci, NULL, config);
		return (err);
	}

	/*
	 * wci is now initialized and ready for cluster traffic
	 */
	rw_enter(&network->nr->wcilist_rw, RW_WRITER);
	wci->lcwci = lcwci;
	rw_exit(&network->nr->wcilist_rw);


	if (pause_evt_thread)
		nr_unpause_event_thread(network);

	return (WRSM_SUCCESS);
}


/*
 * start using newly attached wci - call lc_installconfig() and
 * lc_enableconfig() to bring up links.  (For wcis already attached when a
 * new config is installed, this function is not called, and the equivalent
 * work is done in wrsm_nr_installconfig() and wrsm_nr_enableconfig().)
 */
int
wrsm_nr_enablewci(wrsm_network_t *network, safari_port_t saf_id,
    boolean_t dr_attach)
{
	wrsm_ncwci_t *wci;
	wrsm_nc_strgrp_t *sg;
	boolean_t stripe;
	int err;

	ASSERT(network);

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nr_enablewci() wci %d\n",
	    saf_id));
	ASSERT(network->availability == wrsm_enabled);

	wci = nr_safid_to_wci(network, saf_id);
	ASSERT(wci != NULL);
	if (wci->lcwci == NULL)
		return (ENODEV);

	if (wci->nr.sg) {
		sg = wci->nr.sg;
		mutex_enter(&network->nr->lock);
		sg->attached_wcis++;
		/*
		 * If a newly attached wci completes a stripe group,
		 * turn on striping.  (For a new config, do this
		 * during wrsm_nr_installconfig().)
		 */
		if (dr_attach && (sg->attached_wcis == sg->config->nwcis)) {
			stripe = B_TRUE;
		}
		mutex_exit(&network->nr->lock);
		if (stripe)
			if ((err = nr_sg_stripe(sg)) != WRSM_SUCCESS) {
				return (err);
			}
	}

	wrsm_lc_installconfig(wci->lcwci);
	wrsm_lc_enableconfig(wci->lcwci);

	return (WRSM_SUCCESS);
}


/*
 * stop using wci in preparation for it being detached
 */
int
wrsm_nr_detachwci(wrsm_network_t *network, safari_port_t saf_id,
    boolean_t force)
{
	wrsm_ncwci_t *wci, *chkwci;
	lcwci_handle_t lcwci;
	boolean_t unstripe = B_FALSE;
	wrsm_nc_strgrp_t *sg;
	int err;
	int wcicount = 0;
#ifdef DEBUG
	int i;
	wci_nc2nid_array_u wci_nc2nid;
	uint64_t offset;
#endif

	ASSERT(network);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nr_detachwci() wci %d\n",
	    saf_id));
	ASSERT(network->availability == wrsm_enabled);

	wci = nr_safid_to_wci(network, saf_id);
	if (!wci)
		return (ENOENT);

	lcwci = wci->lcwci;

	if (!lcwci)
		return (ENODEV);

	nr_pause_event_thread(network);

	if (!force && wci_in_use(wci)) {
		nr_unpause_event_thread(wci->network);
		return (EBUSY);
	}

	/*
	 * Can't remove wci if it is the last one in the controller,
	 * even if force is requested.
	 */

	for (chkwci = network->nr->wcis; chkwci != NULL;
	    chkwci = chkwci->next) {
		if (chkwci->lcwci)
			wcicount++;
	}
	if (wcicount == 1) {
		nr_unpause_event_thread(wci->network);
		return (EBUSY);
	}

	wrsm_lc_replaceconfig(wci->lcwci, wci, NULL, NULL);
	/*
	 * tell the LC to update the link states based on the new
	 * NULL configuration; this will cause the LC to (immediately)
	 * notify the MH that all links are down (any that
	 * are no longer valid in the new config).  This should
	 * cause the MH to (immediately) queue evt_mhdirect events
	 * for the event thread to process.
	 */
	wrsm_lc_cleanconfig(wci->lcwci);

	nr_unpause_event_thread(wci->network);
	/*
	 * wait for link down events to cause necessary ncslice rerouting
	 */
	nr_wait_for_wcis_rerouted(network);
	nr_wait_for_event_drain(network);

	/*
	 * wait for links to really come down
	 */
	wrsm_lc_installconfig(wci->lcwci);

	/*
	 * turn off striping in the stripe group involving this wci
	 */
	if (wci->nr.sg) {
		sg = wci->nr.sg;
		mutex_enter(&network->nr->lock);
		if (sg->attached_wcis == sg->config->nwcis) {
			unstripe = B_TRUE;
		}
		sg->attached_wcis--;
		mutex_exit(&network->nr->lock);
		if (unstripe) {
			if ((err = nr_sg_unstripe(sg)) != WRSM_SUCCESS) {
				return (err);
			}
		}
	}

	wrsm_mh_remove_wci(wci);

	/*
	 * wait for loopback route to be removed
	 */
	nr_wait_for_event_drain(network);

#ifdef DEBUG
	/*
	 * verify that all nc2nid entries are turned off
	 */
	offset = (uint64_t)ADDR_WCI_NC2NID_ARRAY;
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		wrsm_lc_csr_read(lcwci, offset, &(wci_nc2nid.val));
		ASSERT(wci_nc2nid.bit.launch_remote == 0);
		offset += STRIDE_WCI_NC2NID_ARRAY;
	}
#endif /* DEBUG */

	wrsm_intr_delwci(network, lcwci);
	(void) wrsm_cmmu_delwci(network, lcwci);

	rw_enter(&network->nr->wcilist_rw, RW_WRITER);
	wci->lcwci = NULL;
	rw_exit(&network->nr->wcilist_rw);
	return (WRSM_SUCCESS);
}


/*
 * determine whether this wci is being used by any ncslice routes
 */
static boolean_t
wci_in_use(wrsm_ncwci_t *wci)
{
	cnode_bitmask_t users, nullset;
	boolean_t inuse;
	int i;

	ASSERT(wci);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "wci_in_use() wci %d\n",
	    wci->config->port));

	WRSMSET_ZERO(users);
	WRSMSET_ZERO(nullset);

	for (i = 0; i < WRSM_MAX_WNODES; i++) {
		if (wci->nr.wnodeinfo[i].valid) {
			WRSMSET_OR(users, wci->nr.wnodeinfo[i].users);
#ifdef DEBUG
			if (wrsm_nr_debug & DBG_ROUTE_EXTRA) {
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "wnode %d route users:\n", i));
				DPRINTNODES(wci->nr.wnodeinfo[i].users);
			}
#endif
		}
	}



	if (WRSMSET_ISEQUAL(users, nullset))
		inuse = B_FALSE;
	else
		inuse = B_TRUE;

	return (inuse);
}

/*
 * MH calls when there has been a change in link status on this WCI
 * (causing a change in wnode route status)
 */
void
wrsm_nr_mhdirect(wrsm_ncwci_t *wci, wrsm_mh_reachable_t *reachable)
{
	wrsm_nr_event_t *event;

	ASSERT(wci);
	ASSERT(wci->config);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "wrsm_nr_mhdirect() wci %d\n",
	    wci->config->port));

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_mhdirect;
	event->data.mhevent.wci = wci;
	bcopy(reachable, &(event->data.mhevent.mh_reachable),
	    sizeof (wrsm_mh_reachable_t));
	wrsm_nr_add_event(wci->network, event, B_TRUE);
}


/*
 * MH calls when it has performed an MH subnet coordinated reroute of the
 * wnode routes on this WCI
 */
void
wrsm_nr_mhreroute(wrsm_ncwci_t *wci, wrsm_mh_reachable_t *reachable)
{
	wrsm_nr_event_t *event;

	ASSERT(wci);
	ASSERT(wci->config);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "wrsm_nr_mhreroute() wci %d\n",
	    wci->config->port));

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_mhreroute;
	event->data.mhevent.wci = wci;
	bcopy(reachable, &(event->data.mhevent.mh_reachable),
	    sizeof (wrsm_mh_reachable_t));
	wrsm_nr_add_event(wci->network, event, B_TRUE);
}


/*
 * This is a daemon that processes events for this network.  There are
 * currently 2 generators of events: a change in configuration (
 * initiated by an ioctl), and a change in route state (initiated by
 * the MH after receiving notification of a link up/down or after a
 * network wide MH reroute).
 */
static void
nr_event_thread(wrsm_network_t *network)
{
	int i;
	callb_cpr_t cprinfo;
	wrsm_nr_event_t *event;
	wrsm_node_t *node;
	int wcis_in_reroute;
	wrsm_ncwci_t *wci;
	wrsm_nr_t *nr;
	boolean_t recalc = B_FALSE;

	ASSERT(network);
	ASSERT(network->nr);
	nr = network->nr;

	DPRINTF(DBG_EVENT_EXTRA, (CE_CONT, "nr_event_thread(): "
	    "rsm ctlr id %d\n", network->rsm_ctlr_id));

	CALLB_CPR_INIT(&cprinfo, &(nr->lock), callb_generic_cpr,
	    "wrsm_nr_event_thread");

	/* LINTED: constant in conditional context */
	while (1) {

		/*
		 * The event thread consumes all events on the event queue.
		 * Once the event queue is empty, it looks at each cnode to
		 * see if it needs to be rerouted.  After selecting any new
		 * routes, it then applies them enmasse, thereby avoiding
		 * too many interruptions.
		 */

		mutex_enter(&(nr->lock));
		while (!nr->events) {
			if (nr->stop_event_thr) {
				DPRINTF(DBG_EVENT, (CE_NOTE,
				    "nr_event_thread 0x%p network ctlr %d: "
				    "stopping\n", (void *)curthread,
				    network->rsm_ctlr_id));
				ASSERT(nr->events == NULL);
				nr->event_thread = NULL;
				/* awaken config thread */
				ASSERT(nr->pausing == B_FALSE);
				nr->wait_pause = 0;
				cv_broadcast(&(nr->config_cv));
				/*
				 * CALLB_CPR_EXIT() calles mutex_exit() on lock
				 * passed in above.  Therefore, do not call
				 * mutex_exit() explicitly here.
				 */
				CALLB_CPR_EXIT(&cprinfo);
				thread_exit();
			}
			DPRINTF(DBG_EVENT_EXTRA, (CE_NOTE,
			    "nr_event_thread network ctlr %d: sleeping "
			    "on event_cv\n", network->rsm_ctlr_id));
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&nr->event_cv, &(nr->lock));
			CALLB_CPR_SAFE_END(&cprinfo, &(nr->lock));
			DPRINTF(DBG_EVENT_EXTRA, (CE_NOTE,
			    "nr_event_thread network ctlr %d: awakened\n",
			    network->rsm_ctlr_id));
			/*
			 * Check if we're supposed to stop running.
			 * This shouldn't be called unless the network is
			 * being removed (all activity on this event queue
			 * should have stopped at this point).
			 */
			if (nr->stop_event_thr) {
				DPRINTF(DBG_EVENT, (CE_NOTE,
				    "nr_event_thread 0x%p network ctlr %d: "
				    "stopping\n", (void *)curthread,
				    network->rsm_ctlr_id));
				ASSERT(nr->events == NULL);
				nr->event_thread = NULL;
				/* awaken config thread */
				nr->wait_pause = 0;
				cv_broadcast(&(nr->config_cv));
				/*
				 * CALLB_CPR_EXIT() calles mutex_exit() on lock
				 * passed in above.  Therefore, do not call
				 * mutex_exit() explicitly here.
				 */
				CALLB_CPR_EXIT(&cprinfo);
				thread_exit();
			}
		}
		mutex_exit(&(nr->lock));

		nr->event_thr_loopcnt++;

		/*
		 * process all events
		 */
		mutex_enter(&(nr->lock));
		while ((event = nr->events) != NULL) {
			nr->events = event->next;
			if (nr->last_event == event)
				nr->last_event = NULL;
			mutex_exit(&(nr->lock));
			nr_process_event(network, event);
			kmem_free(event, sizeof (wrsm_nr_event_t));
			mutex_enter(&(nr->lock));
		}
		mutex_exit(&(nr->lock));

		/*
		 * recalculate any cnode's ncslice-routes affected
		 * by events
		 */
recalc:
		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			node = network->nodes[i];
			if (node == NULL || node->routeinfo == NULL)
				continue;

			if (node->routeinfo->check_route) {
				/*
				 * Calculate route for this node.  If
				 * selected route affects other nodes, go
				 * back and restart route evaluation for
				 * previously processed nodes.
				 */
				recalc = nr_cnode_route(node);
				if (recalc)
					goto recalc;
			}
		}

		/*
		 * apply calculated routes
		 */
		ncslice_apply_routes(network);

		/*
		 * call wrsm_mh_reroute() for any WCIs that are being
		 * rerouted (must happen after ncslices have been
		 * routed on any direct connect nodes)
		 */

		wcis_in_reroute = 0;
		for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
			if (wci->reroute_state == wci_in_reroute) {
				wcis_in_reroute++;
			}
			if ((network->availability == wrsm_enabled &&
			    wci->reroute_state == wci_need_reroute) ||
			    wci->reroute_state == wci_force_reroute) {
				if (wrsm_mh_reroute(wci))
					wcis_in_reroute++;
			    }
		}

		/*
		 * See if thread is waiting to be awakened.
		 */

		mutex_enter(&(nr->lock));
		if (nr->wait_eventdrain) {
			nr->wait_eventdrain = B_FALSE;
			cv_broadcast(&nr->config_cv);
		}

		if (nr->wait_wcis_rerouting && wcis_in_reroute == 0) {
			nr->wait_wcis_rerouting = B_FALSE;
			cv_broadcast(&(nr->config_cv));

		}

		if (nr->wait_pause > 0) {
			DPRINTF(DBG_EVENT_EXTRA, (CE_NOTE,
			    "nr_event_thread network ctlr %d: pausing "
			    "on config_cv\n", network->rsm_ctlr_id));
			nr->wait_pause--;
			ASSERT(nr->pausing == B_FALSE);
			nr->pausing = B_TRUE;
			cv_broadcast(&nr->config_cv);
			do {
				cv_wait(&(nr->config_cv), &(nr->lock));
			} while (nr->pausing == B_TRUE);
			DPRINTF(DBG_EVENT_EXTRA, (CE_NOTE,
			    "nr_event_thread network ctlr %d: unpausing\n",
			    network->rsm_ctlr_id));
		}
		mutex_exit(&(nr->lock));
	}
}


/*
 * function to queue an event structure to the network events queue
 */
void
wrsm_nr_add_event(wrsm_network_t *network, wrsm_nr_event_t *event,
    boolean_t release_lock)
{
	wrsm_nr_t *nr;

	ASSERT(network);
	ASSERT(network->nr);
	nr = network->nr;

	event->next = NULL;

	mutex_enter(&(nr->lock));
	if (nr->last_event == NULL) {
		nr->events = event;
	} else {
		nr->last_event->next = event;
	}
	nr->last_event = event;
	cv_signal(&(nr->event_cv));

	if (release_lock)
		mutex_exit(&(nr->lock));
}


/*
 * calling thread sleeps until the event thread consumes all events
 * currently on the queue, re-calculates and applies routes, and
 * initiates wci reroutes based on (at least) these events
 */
static void
nr_wait_for_event_drain(wrsm_network_t *network)
{
	wrsm_nr_t *nr;
	wrsm_nr_event_t *event;

	ASSERT(network);
	ASSERT(network->nr);
	nr = network->nr;

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_wakeup;
	wrsm_nr_add_event(network, event, B_FALSE);
	nr->wait_eventdrain = B_TRUE;
	do {
		DPRINTF(DBG_CONFIG_EXTRA, (CE_NOTE, "waiting for "
		    "event queue to drain\n"));
		cv_wait(&(nr->config_cv), &(nr->lock));
	} while (nr->wait_eventdrain == B_TRUE);
	mutex_exit(&nr->lock);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_NOTE, "events have been drained\n"));
}


/*
 * calling thread sleeps until the event thread determines that no
 * wcis are in the middle of an MH reroute.
 */
static void
nr_wait_for_wcis_rerouted(wrsm_network_t *network)
{
	wrsm_nr_t *nr;
	wrsm_nr_event_t *event;

	ASSERT(network);
	ASSERT(network->nr);
	nr = network->nr;

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_wakeup;
	wrsm_nr_add_event(network, event, B_FALSE);
	nr->wait_wcis_rerouting = B_TRUE;
	do {
		DPRINTF(DBG_CONFIG_EXTRA, (CE_NOTE, "waiting for "
		    "wci reroutes to finish\n"));
		cv_wait(&(nr->config_cv), &(nr->lock));
	} while (nr->wait_wcis_rerouting == B_TRUE);
	mutex_exit(&(nr->lock));

	DPRINTF(DBG_CONFIG_EXTRA, (CE_NOTE, "no wcis are rerouting\n"));
}


/*
 * cause the event thread to pause after it finishes consuming
 * and applying the current set of events on its queue
 */
static void
nr_pause_event_thread(wrsm_network_t *network)
{
	wrsm_nr_t *nr;
	wrsm_nr_event_t *event;
	uint_t pause;

	ASSERT(network);
	ASSERT(network->nr);
	nr = network->nr;

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_wakeup;
	wrsm_nr_add_event(network, event, B_FALSE);
	pause = nr->wait_pause;
	nr->wait_pause++;
	do {
		DPRINTF(DBG_CONFIG_EXTRA, (CE_NOTE, "waiting for "
		    "evt thr to pause with wait_pause %d\n", pause));
		cv_wait(&(nr->config_cv), &(nr->lock));
	} while ((nr->wait_pause != pause) && (nr->wait_pause != 0));
	ASSERT(nr->pausing == B_TRUE);
	mutex_exit(&nr->lock);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_NOTE, "evt thr paused\n"));
}


/*
 * cause the paused event thread to continue consuming events
 */
static void
nr_unpause_event_thread(wrsm_network_t *network)
{
	ASSERT(network);
	ASSERT(network->nr);

	mutex_enter(&(network->nr->lock));
	ASSERT(network->nr->pausing == B_TRUE);
	network->nr->pausing = B_FALSE;
	cv_broadcast(&(network->nr->config_cv));
	mutex_exit(&(network->nr->lock));
}



/*
 * process the event
 * return the event type in case some sort of signalling is needed
 */
static void
nr_process_event(wrsm_network_t *network, wrsm_nr_event_t *event)
{
	wrsm_ncwci_t *wci;
	wrsm_mh_reachable_t *reachable;

	ASSERT(network);
	ASSERT(event);

	DPRINTF(DBG_EVENT, (CE_CONT, "ctlr %d: nr_process_event() "
	    "type %s\n", network->rsm_ctlr_id, WRSM_EVTSTRING(event->type)));

	switch (event->type) {

	case wrsm_evt_mhdirect:
		/*
		 * store away new wci wnode route info
		 */
		wci = event->data.mhevent.wci;
		reachable = &(event->data.mhevent.mh_reachable);
#ifdef DEBUG
		if (!wci) {
			DPRINTF(DBG_WARN, (CE_WARN,
			    "bad event mhdirect: null wci \n"));
			break;
		}
#endif
		if (wci->network->availability == wrsm_enabled) {
			/*
			 * Only check routes for direct connect nodes; the
			 * rest will be re-evaluated after wrsm_mh_reroute() is
			 * performed.  wrsm_mh_reroute() is initiated during
			 * this cycle of the event thread based on the
			 * wci->reroute_state being set to need_reroute.
			 */

			nr_wci_routechange(wci, reachable,
			    wci_reroute_direct);

		} else if (wci->availability == wrsm_disabled) {
			/*
			 * don't change any routes, just record which cnodes
			 * are affected by changes, and tear down invalid
			 * routes
			 */
			nr_wci_routechange(wci, reachable,
			    wci_reroute_disabled);

		} else {
			/*
			 * The network is pending, installed or
			 * installed-up; a complete wrsm_mh_reroute() will not
			 * happen automatically (not until network is moved
			 * to enabled state), and may be delayed for
			 * some time:  force nodes using lost wnode routes
			 * to reroute using the currently available wnode
			 * routes.
			 */

			nr_wci_routechange(wci, reachable, wci_reroute_pending);
		}

		/*
		 * need to call wrsm_mh_reroute() called for this wci
		 */
		wci->reroute_state = wci_need_reroute;

		break;


	case wrsm_evt_mhreroute:
		/*
		 * re-evaluate ncslices routes for any cnode using a wnode
		 * whose route has changed.
		 */
		wci = event->data.mhevent.wci;
		reachable = &(event->data.mhevent.mh_reachable);
#ifdef DEBUG
		if (!wci) {
			DPRINTF(DBG_WARN, (CE_WARN,
			    "bad event mhdirect: null wci \n"));
			break;
		}
#endif
		if (wci->availability == wrsm_disabled) {
			/*
			 * don't change any routes, just record which cnodes
			 * are affected by changes, and tear down invalid
			 * routes
			 */
			nr_wci_routechange(wci, reachable,
			    wci_reroute_disabled);
		} else {
			/*
			 * re-evaluate all cnodes affected by wnode
			 * routes changes
			 */
			nr_wci_routechange(wci, reachable, wci_reroute_all);
		}
		break;


	case wrsm_evt_force_reroute:

		/*
		 * call wrsm_mh_reroute() called for this wci called to cause
		 * controlled mh_rerouting in a pending/installed/installed-up
		 * configuration
		 */

		wci = event->data.forcereroute.wci;
		nr_wci_routechange(wci, NULL, wci_reroute_force);
		wci->reroute_state = wci_force_reroute;
		break;

	case wrsm_evt_add_passthrough:
		/*
		 * turn on passthrough capability for this node if
		 * there is a route to it.
		 */
		(void) pt_haveroute(event->data.addpt.node);
		break;

	case wrsm_evt_send_ptlist: {
		/*
		 * Send PTLIST message with current list of nodes
		 * passthrough is provided for to all specified nodes.
		 */
		int i;
		wrsm_node_t *node;

		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			if (WRSM_IN_SET(event->data.send_ptlist.list, i)) {
				node = network->nodes[i];
				if (node && (i != network->cnodeid) &&
				    WRSM_NODE_HAVE_ROUTE(node)) {
					pt_newptinfo(network, pt_route_counter,
					    node);
				}
			}
		}
		break;
	}

	case wrsm_evt_recv_ptlist: {
		/*
		 * received a PTLIST message from some node: process it
		 */
		wrsm_node_t *node;

		node = network->nodes[event->data.recv_ptlist.cnodeid];
		if (!node) {
			/* ignore requests for non-existant nodes */
			DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: "
			    "evt_recv_ptlist for non-existent node %d\n",
			    event->data.recv_ptlist.cnodeid));
			break;
		}

		pt_route_update(node,
		    event->data.recv_ptlist.pt_provided,
		    event->data.recv_ptlist.pt_route_counter);
		break;
	}

	case wrsm_evt_wakeup:
		/*
		 * an event to get the event thread to run
		 */
		break;

	case wrsm_evt_sessup:
		/*
		 * initiate a session teardown on a node
		 */
		wrsm_sess_establish_immediate(network,
		    event->data.sess.cnodeid);
		break;

	case wrsm_evt_sessdown:
		/*
		 * initiate a session teardown on a node
		 */
		wrsm_sess_teardown_immediate(network,
		    event->data.sess.cnodeid);
		break;
	default:
		DPRINTF(DBG_WARN, (CE_WARN,
			"rsm_ctlr_id %d: unknown event %d",
			network->rsm_ctlr_id, event->type));
		break;
	}
}




/*
 * Any cnodes using ncslice routes which involve invalid wnode routes on
 * this wci must be rerouted.  In some cases, cnode routes should be
 * re-evaluated to take advantage of new routes.  (This depends on the
 * state of the network->availability.)  Cnodes the need to do a route
 * re-evaluation have the check_route field set to true, which causes
 * nr_cnode_route() to be called for this cnode from the event thread.
 * (The event thread does this after processing all events in the queue.)
 *
 * Also, the set of routes each cnode should consider when performing
 * a route evaluation is controlled by the cnode_retry fields: the
 * route evaluation only considers wcis, stripe groups and PT nodes
 * which include this wci in their retry field.  (This prevents
 * continuously re-evaluating routes that haven't changed since they
 * were rejected during the last route evaluation.)
 */

static void
nr_wci_routechange(wrsm_ncwci_t *wci, wrsm_mh_reachable_t *reachable,
    wrsm_wci_reroute_t reroute)
{
	int i, wnid;
	cnode_bitmask_t lost_route;
	cnodeid_t cnodeid;
	wrsm_network_t *network;
	wrsm_node_t *node;
	wrsm_mh_reachable_t old_reachable;
#ifdef DEBUG
	boolean_t changed;
#endif

	ASSERT(wci);
	ASSERT(wci->config);
	network = wci->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "nr_wci_routechange(), wci %d, "
	    "%s\n", wci->config->port, WCI_RTSTRING(reroute)));

	if (reachable) {
		bcopy(&(wci->nr.mh_reachable), &old_reachable,
		    sizeof (wrsm_mh_reachable_t));
		bcopy(reachable, &(wci->nr.mh_reachable),
		    sizeof (wrsm_mh_reachable_t));
	}

	WRSMSET_ZERO(lost_route);

	for (wnid = 0; wnid < WRSM_MAX_WNODES; wnid++) {

		if (!wci->nr.wnodeinfo[wnid].valid)
			continue;

#ifdef DEBUG
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
		    "nr_wci_routechange(), "
		    "wnode %d, valid %d, nhops %d stripes %d "
		    "changed %d cnode %d\n", wnid,
		    wci->nr.wnodeinfo[wnid].valid,
		    wci->nr.mh_reachable.nhops[wnid],
		    wci->nr.mh_reachable.stripes[wnid],
		    wci->nr.mh_reachable.changed[wnid],
		    wci->nr.wnodeinfo[wnid].cnodeid));

		changed = wci->nr.mh_reachable.changed[wnid];
#endif

		/*
		 * If old route change hasn't yet been applied to all
		 * routes, re-evaluate it.
		 */
		if (old_reachable.changed[wnid])
			wci->nr.mh_reachable.changed[wnid] = B_TRUE;

		if (!wci->nr.mh_reachable.changed[wnid] &&
		    reroute != wci_reroute_force)
			continue;


		/*
		 * wnode route has changed
		 *
		 * For the reroute_direct case, we only allow the direct
		 * connect route to be established if it was not available.
		 *
		 * The reroute_direct case never tears down a route, and
		 * only sets up a route for the node accessed by the new
		 * direct route (if needed).  So leave route marked as
		 * changed so it is evaluated again after wrsm_mh_reroute()
		 * has completed multihop rerouting and reports back.
		 *
		 * The reroute_pending is really reroute_direct while
		 * config is not yet enabled.  It only only causes route
		 * evaluations if a route is lost.  This wnode route must
		 * still be re-evaluated for new routes, so leave it marked
		 * as changed.
		 */
		if ((reroute != wci_reroute_direct) &&
		    (reroute != wci_reroute_pending) &&
		    (reroute != wci_reroute_force)) {
			wci->nr.mh_reachable.changed[wnid] = B_FALSE;
		}

		if (wci->nr.mh_reachable.nhops[wnid] > WNODE_UNREACHABLE) {
			/*
			 * a route to this wnode is available
			 */
#ifdef DEBUG
			if (changed) {
				DPRINTF(DBG_ROUTE, (CE_CONT,
				    "ctlr %d: nr route change wci %d wnode %d "
				    "(nhops %d)\n",
				    wci->network->rsm_ctlr_id,
				    wci->config->port, wnid,
				    wci->nr.mh_reachable.nhops[wnid]));
			}
#endif

			cnodeid = wci->nr.wnodeinfo[wnid].cnodeid;
			node = network->nodes[cnodeid];

			ASSERT(node);
			ASSERT(node->routeinfo);

			/*
			 * cnodes currently using this wnode route in their
			 * ncslice_route are ok
			 *
			 * update the wci and stripe group retry lists that
			 * include this wnode route:  the next time cnodes
			 * that could use this wnode route perform a route
			 * re-evaluation, they should reconsider this route
			 */

			WRSMSET_OR(wci->nr.cnode_retry,
			    wci->nr.wnodeinfo[wnid].interested);

			if (wci->nr.sg)
				WRSMSET_OR(wci->nr.sg->cnode_retry,
				    wci->nr.wnodeinfo[wnid].interested);

			if (reroute == wci_reroute_all) {

				/*
				 * cause route re-evaluation on all cnodes
				 * that could use this wnode
				 * (nr_cnode_route() is called for each
				 * cnode).
				 */

				for (i = 0; i < WRSM_MAX_CNODES; i++) {
					if (WRSM_IN_SET(
					    wci->nr.wnodeinfo[wnid].interested,
					    i)) {
						ASSERT(network->nodes[i]);
						network->nodes[i]->
						    routeinfo->check_route =
						    B_TRUE;
						DPRINTF(DBG_ROUTE_EXTRA,
						    (CE_CONT,
						    "re-eval cnode %d on "
						    "avail route  wci %d "
						    "wnode %d\n", i,
						    wci->config->port, wnid));
					}
				}


			} else if (reroute == wci_reroute_direct ||
			    reroute == wci_reroute_force) {

				/*
				 * If this is a direct route and there is
				 * currently no ncslice route for this
				 * node, cause a route re-evaluation for
				 * this node.
				 *
				 * the rest of the re-evaluations will take
				 * place after the next wrsm_evt_mhreroute
				 * event.
				 */

				if (wci->nr.mh_reachable.nhops[wnid] == 1) {
					if (!WRSM_NODE_HAVE_ROUTE(node)) {
						node->routeinfo->check_route =
						    B_TRUE;
						DPRINTF(DBG_ROUTE_EXTRA,
						    (CE_CONT,
						    "re-eval cnode %d on "
						    "avail route  wci %d "
						    "wnode %d\n", cnodeid,
						    wci->config->port, wnid));
					}
				}
			}
			continue;
		} else {

			/*
			 * there is no longer a route to this wnode
			 *
			 * cnode ncslice routes using this wnode route are
			 * no longer valid
			 */

#ifdef DEBUG
			if (changed) {
				DPRINTF(DBG_ROUTE, (CE_CONT,
				    "ctlr %d: nr lost route wci %d "
				    "wnode %d\n",
				    wci->network->rsm_ctlr_id,
				    wci->config->port, wnid));
			}

			if (wrsm_nr_debug & DBG_ROUTE_EXTRA) {
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "route users:\n"));
				DPRINTNODES(wci->nr.wnodeinfo[wnid].users);
			}
#endif

			WRSMSET_OR(wci->nr.cnode_retry,
			    wci->nr.wnodeinfo[wnid].users);


			if (wci->nr.inids_enabled) {
				for (i = 0; i < WRSM_INID2DNID_ENTRIES; i++) {
					if (WRSM_IN_SET(
					    wci->nr.inid2dnid[i].wnode_bitmask,
					    wnid)) {
						WRSMSET_OR(lost_route,
						    wci->nr.inid2dnid[i].users);
					}
				}
			} else {
				WRSMSET_OR(lost_route,
				    wci->nr.wnodeinfo[wnid].users);
			}
		}
	}

	if (reroute == wci_reroute_all || reroute == wci_reroute_pending) {
		/*
		 * if a complete reroute was requested or if configuration
		 * is in pending state, re-evaluate ncslice routes for all
		 * cnodes using invalid wnodes
		 */

		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			if (WRSM_IN_SET(lost_route, i)) {
				ASSERT(network->nodes[i]);
				ASSERT(network->nodes[i]->routeinfo);
				network->nodes[i]->routeinfo->check_route =
				    B_TRUE;
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "re-eval cnode %d on "
				    "lost route wci %d\n", i,
				    wci->config->port, wnid));
			}
		}

	} else if (reroute == wci_reroute_disabled) {
		/*
		 * if configuration is currently disabled, teardown routes
		 * using invalid wnodes (except for the loopback route,
		 * which is always re-evaluated).
		 */

		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			if (WRSM_IN_SET(lost_route, i)) {
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "nr_wci_routechange(), wci %d cnode %d "
				    "lost route\n", wci->config->port,
				    i));

				ASSERT(network->nodes[i]);
				if (i == network->cnodeid) {
					/*
					 * loopback route must always be
					 * valid. Recalculate.
					 */
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d routechange disabled "
					    "reval loopback "
					    "node %d check_route\n",
					    network->rsm_ctlr_id, i));
					network->nodes[i]->routeinfo->
					    check_route = B_TRUE;
				} else {
					if (network->nodes[i]->routeinfo->
					    route_state !=
					    ncslice_remove_route) {
						network->nodes[i]->routeinfo->
						    route_state =
						    ncslice_use_errloopback;
					}
				}
			}
		}
	}
}



/*
 * Find the best ncslice route to this node.
 * Return whether selected route affects other nodes.
 */
static boolean_t
nr_cnode_route(wrsm_node_t *node)
{
	int i;
	ncslice_route_t tryroute, *currentp;
	boolean_t try_all = B_FALSE;
	wrsm_routing_policy_t *policy;
	wrsm_preferred_route_t *proute;
	cnodeid_t cnodeid;
	wrsm_network_t *network;
	wrsm_ncwci_t *wci;
	wrsm_nc_strgrp_t *sg;
	ncslice_route_t *routep;
	inid_t id;
	boolean_t recalc_prev_nodes = B_FALSE;

	ASSERT(node);
	ASSERT(node->config);
	ASSERT(node->network);
	ASSERT(node->routeinfo);
	cnodeid = node->config->cnodeid;
	network = node->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: nr_cnode_route(), "
	    "node %d\n", network->rsm_ctlr_id,
	    node->config->cnodeid));


	if (node->availability == wrsm_pending) {
		/*
		 * Can't set up a route for this node yet.  Leave
		 * check_route set, so that when it is enabled, the next
		 * time the nr event thread runs it will attempt to set up
		 * a route.
		 */
		return (recalc_prev_nodes);
	}

	node->routeinfo->check_route = B_FALSE;

	if ((node->routeinfo->route_state == ncslice_remove_route) ||
	    (node->routeinfo->route_state == ncslice_no_route)) {
		/*
		 * this node is being removed, so don't calculate
		 * a new route for it
		 */
		return (recalc_prev_nodes);
	}

	policy = node->routeinfo->policy;
	ASSERT(policy);
	currentp = &(node->routeinfo->current_route);

	bzero(&(node->routeinfo->new_route), sizeof (ncslice_route_t));
	bzero(&tryroute, sizeof (ncslice_route_t));


	/*
	 * Evaluate the preferred routes to see what is available.  Always
	 * consider the current route.  If current route has changed,
	 * re-evaluate all possible ncslice routes; otherwise, only
	 * re-evaluate ncslice routes where some change has been made to
	 * the wnode or inid routes since last checked.
	 */


	/*
	 * has the current route changed?
	 */
	if (!currentp->proute) {
		try_all = B_TRUE;
	} else if (currentp->proute->method == routing_passthrough) {
		/*
		 * Always re-evaluate passthrough routes, as we don't have
		 * good information about how each preferred route is
		 * affected by changes in passthrough routing availability.
		 */
		try_all = B_TRUE;

	} else if (currentp->proute->route_type == route_wci) {
		wci = nr_safid_to_wci(network, currentp->proute->route.wci_id);
		if (WRSM_IN_SET(wci->nr.cnode_retry, cnodeid))
			try_all = B_TRUE;
	} else {
		ASSERT(currentp->proute->route_type == route_stripe_group);
		sg = nr_sgid_to_sg(network,
		    currentp->proute->route.stripe_group_id);
		if (WRSM_IN_SET(sg->cnode_retry, cnodeid))
			try_all = B_TRUE;
	}


	/*
	 * Compare all routes of interest; for each new route, choose
	 * between it and the current winning route; winning route is
	 * copied into routeinfo->new_route.
	 */
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: node %d has %d routes\n",
	    network->rsm_ctlr_id, cnodeid, policy->nroutes));
	for (i = 0; i < policy->nroutes; i++) {
		proute = policy->preferred_routes[i];
		ncslice_build_route(node, &tryroute, proute, (try_all |
		    (node->routeinfo->current_route.proute == proute)));
		if (tryroute.stripes) {
			/* found a viable route */
			if (node->routeinfo->policy->striping_important) {
				/*
				 * choose best route based on number
				 * of stripes
				 */
				if (tryroute.stripes >
				    node->routeinfo->new_route.stripes) {
					bcopy(&tryroute,
					    &node->routeinfo->new_route,
					    sizeof (ncslice_route_t));
				    }
			} else {
				/*
				 * Order of routes in the preferred routes
				 * is most important, so use this route,
				 * and don't consider any routes after this
				 * one.
				 */
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "use preferred\n"));
				bcopy(&tryroute, &node->routeinfo->new_route,
				    sizeof (ncslice_route_t));
				break;
			}
		}
	}


	/*
	 * Selected route is now saved in node's routeinfo->new_route.
	 *
	 * if no route found, see if we can look at all wcis, stripe groups,
	 * passthrough routes; otherwise, remove current route.
	 */

	if (ncslice_routes_match(currentp, &(node->routeinfo->new_route))) {
		node->routeinfo->route_state = ncslice_use_current;
		/*
		 * If proute nulled to mark update, get value from new_route.
		 */
		if (!currentp->proute)
			currentp->proute = node->routeinfo->new_route.proute;
	} else if (node->routeinfo->new_route.stripes == 0) {
		node->routeinfo->route_state = ncslice_use_errloopback;
		/*
		 * The local node should never end up without a route,
		 * as we're guaranteed to have at least one wci for
		 * the loopback route.
		 */
		ASSERT(cnodeid != network->cnodeid);
	} else {
		/*
		 * apply new route
		 */
		node->routeinfo->route_state = ncslice_use_new_route;
		routep = &node->routeinfo->new_route;
		for (i = 0; i < routep->nwcis; i++) {
			if (routep->wroutes[i].route_type == nid_route_inid) {
				wci = routep->wroutes[i].wci;
				if (!wci->nr.using_inids) {
					/*
					 * In order to use this route, we
					 * need to set up the wci to use
					 * inids for all routes, and force
					 * all users of this wci to use
					 * inids.  If any nodes with a
					 * lower cnodeid are affected,
					 * return a flag to cause routes
					 * for these nodes to be
					 * re-evaluated.
					 */
					recalc_prev_nodes =
						ncslice_switch_to_inids(wci,
						cnodeid);
				} else {
					/*
					 * only update wci's inid2dnid
					 * table if this inid entry has
					 * changed.
					 */
					id = routep->wroutes[i].id;
					if (wci->nr.inid2dnid[id].changed ==
					    B_TRUE)
						wci->nr.need_hw_update = B_TRUE;
				}
			}
		}
	}

	return (recalc_prev_nodes);
}


/*
 * Commit to using inids on this wci.
 * Return whether switching to inids affects other nodes.
 */
static boolean_t
ncslice_switch_to_inids(wrsm_ncwci_t *wci, cnodeid_t cnodeid)
{
	int i;
	cnode_bitmask_t retrynodes;
	wrsm_inid2dnid_entry_t *ientry;
	wrsm_network_t *network;
	boolean_t recalc_prev_nodes = B_FALSE;

	ASSERT(wci);
	ASSERT(wci->config);
	network = wci->network;

	DPRINTF(DBG_ROUTE, (CE_CONT, "switch_to_inids(), wci %d\n",
	    wci->config->port));

	WRSMSET_ZERO(retrynodes);
	wci->nr.need_hw_update = B_TRUE;
	wci->nr.using_inids = B_TRUE;

	for (i = 0; i < WRSM_INID2DNID_ENTRIES; i++) {
		ientry = &(wci->nr.inid2dnid[i]);
		/*
		 * no one should be using inids at this point, as we
		 * haven't yet switched to using inids!
		 */
		/* LINTED: E_NOP_IF_STMT */
		if (!WRSMSET_ISNULL(ientry->users)) {
			DPRINTF(DBG_ROUTE,
			    (CE_NOTE, "ientry->users not "
			    "empty (wci %d, inid2dnid entry %d)\n",
			    wci->config->port, i));
			DPRINTNODES(ientry->users);
		}
		if (!WRSMSET_ISNULL(ientry->reserved)) {
			WRSMSET_OR(wci->nr.cnode_retry, ientry->reserved);
			WRSMSET_OR(retrynodes, ientry->reserved);
			if (wci->nr.sg)
				WRSMSET_OR(wci->nr.sg->cnode_retry,
				    ientry->reserved);
		}
	}

	/*
	 * If any cnodes using or about to use this wci already had their
	 * routes calculated, cause their routes to be recalculated.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (WRSM_IN_SET(retrynodes, i)) {
			ASSERT(network);
			ASSERT(network->nodes[i]);

			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
			    "ctlr %d switch_to_inids "
			    "node %d check_route\n",
			    network->rsm_ctlr_id, i));
			network->nodes[i]->routeinfo->check_route = B_TRUE;
			if (i < cnodeid) {
				recalc_prev_nodes = B_TRUE;
			}
		}
	}

	return (recalc_prev_nodes);
}


/*
 * compare node's current ncslice route and a new ncslice route to see if
 * they match
 */
static boolean_t
ncslice_routes_match(ncslice_route_t *route1, ncslice_route_t *route2)
{
	int i;

	ASSERT(route1);
	ASSERT(route2);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ncslice_routes_match()\n"));

	if (route1->nwcis != route2->nwcis)
		return (B_FALSE);

	for (i = 0; i < route1->nwcis; i++) {
		if (route1->wroutes[i].wci != route2->wroutes[i].wci)
			return (B_FALSE);
		if (route1->wroutes[i].route_type !=
		    route2->wroutes[i].route_type)
			return (B_FALSE);
		if (route1->wroutes[i].id != route2->wroutes[i].id)
			return (B_FALSE);
	}

	if (route1->stripes != route2->stripes)
		return (B_FALSE);

	return (B_TRUE);
}





/*
 * only build an ncslice route using this proute if it has changed or if
 * force is set to true; otherwise, set it to 0 (indicating there is no
 * route using this proute).
 */
static void ncslice_build_route(wrsm_node_t *node, ncslice_route_t *routep,
    wrsm_preferred_route_t *proute, boolean_t force)
{
	int changed = B_FALSE;
	wrsm_ncwci_t *wci = NULL;
	wrsm_nc_strgrp_t *sg = NULL;
	cnodeid_t cnodeid;
	wrsm_network_t *network;

	ASSERT(node);
	ASSERT(node->config);
	ASSERT(proute);
	cnodeid = node->config->cnodeid;
	network = node->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ncslice_build_route() - node %d\n",
	    node->config->cnodeid));

	bzero(routep, sizeof (ncslice_route_t));


	/*
	 * Check to see this node should retry evaluating available routes
	 * on the wci or stripe group for this ncslice route.  (This occurs
	 * if one or more inid2dnid or wnode routes have changed; the wci's
	 * cnode_retry value includes the nodes that should retry).  Remove
	 * this node from the wci or stripe group's retry list.  Note:  if
	 * a wci or stripe group is used in more than one preferred
	 * route in multi-hop mode, only the first preferred route in the
	 * list of preferred routes is considered.
	 */

	if (proute->route_type == route_wci) {
		wci = nr_safid_to_wci(network, proute->route.wci_id);
		ASSERT(wci);
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "route_type wci id %d\n",
		    wci->config->port));
		if (wci->availability == wrsm_disabled) {
			changed = B_TRUE;
		} else if (proute->method == routing_passthrough ||
		    WRSM_IN_SET(wci->nr.cnode_retry, cnodeid)) {
			changed = B_TRUE;
			WRSMSET_DEL(wci->nr.cnode_retry, cnodeid);
		}

	} else {
		sg = nr_sgid_to_sg(network, proute->route.stripe_group_id);
		ASSERT(sg);
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "route_type sg id %d\n",
		    sg->config->group_id));
		if (sg->availability == wrsm_disabled) {
			changed = B_TRUE;
		} else if (proute->method == routing_passthrough ||
		    WRSM_IN_SET(sg->cnode_retry, cnodeid)) {
			changed = B_TRUE;
			WRSMSET_DEL(sg->cnode_retry, cnodeid);
		}
	}

	/*
	 * If this is a passthrough route, always re-evaluate this route.
	 * (It is difficult to keep track of which ncslice routes should be
	 * retried when PT access has changed, so don't bother.)
	 */

	if (proute->method == routing_passthrough)
		changed = B_TRUE;


	if (changed || force) {
		if (wci) {
			ncslice_build_wci_route(node->routeinfo->policy,
			    routep, proute, wci);
#ifdef DEBUG
			if (routep->stripes) {
				DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: node %d "
				    "route on wci %d has %d stripes\n",
				    network->rsm_ctlr_id, cnodeid,
				    wci->config->port, routep->stripes));
			}
#endif
		} else if (sg) {
			ncslice_build_sg_route(node->routeinfo->policy,
			    routep, proute, sg);
#ifdef DEBUG
			if (routep->stripes) {
				DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: node %d "
				    "route on stripe group %d has %d stripes\n",
				    network->rsm_ctlr_id, cnodeid,
				    sg->config->group_id,
				    routep->stripes));
				if ((routep->nwcis == 1) &&
				    (sg->config->nwcis != 1))
					DPRINTF(DBG_ROUTE, (CE_CONT, "route "
					    "uses wci %d no-stripe from stripe "
					    "group\n", routep->
					    wroutes[0].wci->config->port));
			}
#endif
		}
#ifdef DEBUG
		if (routep->stripes) {
			if ((proute->method == routing_passthrough) &&
			    (wrsm_nr_debug & DBG_ROUTE)) {
				DPRINTF(DBG_ROUTE, (CE_CONT,
				    "route uses passthrough nodes:\n"));
				DPRINTNODES(routep->switches);
			}
		}
#endif
	}

}



/*
 * find a route through a particular wci using the preferred route info
 */
static int
ncslice_one_wci_route(wrsm_routing_policy_t *policy, ncslice_route_t *routep,
    wrsm_preferred_route_t *proute, cnode_bitmask_t used_switches,
    int max_stripes, wrsm_ncwci_t *wci, int wcinum)
{
	wrsm_network_t *network;
	wnodeid_t dnidlist[WRSM_MAX_DNIDS];
	cnodeid_t pt_nodeid, dest_cnodeid, inid_nodeid;
	int i, j, wnid, dnids, inid;
	int best_inid, most_stripes;
	int stripes;

	ASSERT(wci);
	ASSERT(wci->config);
	ASSERT(policy);
	ASSERT(proute);
	network = wci->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ncslice_one_wci_route()\n"));

	if (wci->availability != wrsm_enabled) {
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "wci %d not enabled\n",
		    wci->config->port));
		return (0);
	}

	stripes = 0;
	dest_cnodeid = policy->cnodeid;

	if (proute->method == routing_multihop) {

		/* just choose one wnode */
		for (wnid = 0; wnid < WRSM_MAX_WNODES; wnid++) {
			/*
			 * There could be more than one wnode that routes
			 * to this cnode.  (This is not actually allowed in
			 * the configuration currently.) Always use the
			 * first wnode found.
			 */

			if (wci->nr.wnodeinfo[wnid].valid &&
			    wci->config->reachable[wnid] == dest_cnodeid &&
			    wci->nr.mh_reachable.nhops[wnid] >
			    WNODE_UNREACHABLE) {
				stripes = wci->nr.mh_reachable.stripes[wnid];
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "ncslice_one_wci_route() - wnode %d on "
				    "wci %d stripes %d\n", wnid,
				    wci->config->port,
				    wci->nr.mh_reachable.stripes[wnid]));
				break;
			}
		}

		if (wnid == WRSM_MAX_WNODES) {
			/*
			 * no usable wnode on this wci route to the desired
			 * cnode
			 */
			return (0);
		}
		ASSERT(stripes != 0);


		/*
		 * only use inid if we have to
		 */
		if (!wci->nr.using_inids) {
			/* use wnode */
			routep->wroutes[wcinum].wci = wci;
			routep->wroutes[wcinum].route_type = nid_route_wnode;
			routep->wroutes[wcinum].id = (wnodeid_t)wnid;
			WRSMSET_ADD(wci->nr.wnodeinfo[wnid].reserved,
			    dest_cnodeid);
			return (stripes);


		}

		/*
		 * Using inids:  reserve an inid entry with all dnids set
		 * to this wnode.
		 */

		for (i = 0; i < WRSM_MAX_DNIDS; i++) {
			dnidlist[i] = (wnodeid_t)wnid;
		}
		inid = ncslice_find_inid(wci, dnidlist, 1, dest_cnodeid);
		if (inid > -1) {
			/* use inid */
			routep->wroutes[wcinum].wci = wci;
			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
			    "wci %d using_inids "
			    "%c, inid #%d\n", wci->config->port,
			    wci->nr.using_inids ? 'y' : 'n', inid));
			routep->wroutes[wcinum].route_type = nid_route_inid;
			routep->wroutes[wcinum].id = (wnodeid_t)inid;
			return (stripes);
		} else {
			/* no inid2dnid entry available */
			return (0);
		}

	} else {
		ASSERT(proute->method == routing_passthrough);

		/*
		 * Find routes to max_stripes switches, searching in switch
		 * list order (preferred order).  Use only switches that
		 * haven't been used by other wcis in this route (if this
		 * wci is part of a stripe group).
		 *
		 * Routemap striping is not allowed in combination with
		 * passthrough striping, so only use wnode entries with
		 * stripes == 1.
		 */

		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
		    "find passthrough routes\n"));

		dnids = 0;
		for (i = 0; i < proute->nswitches; i++) {
			pt_nodeid = proute->switches[i];
			if (!WRSM_IN_SET(
			    network->nodes[pt_nodeid]->routeinfo->pt_provided,
			    dest_cnodeid)) {
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "passthrough not provided through "
				    "node %d to node %d\n",
				    pt_nodeid, dest_cnodeid));
				/* skip this switch - no passthrough to cnode */
				continue;
			}

			if (WRSM_IN_SET(used_switches, pt_nodeid)) {
				/* skip this switch - used already */
				continue;
			}

			for (wnid = 0; wnid < WRSM_MAX_WNODES; wnid++) {
				if (wci->nr.wnodeinfo[wnid].valid &&
				    (wci->config->reachable[wnid] ==
				    pt_nodeid) &&
				    (wci->nr.mh_reachable.nhops[wnid] == 1) &&
				    (wci->nr.mh_reachable.stripes[wnid] == 1)) {
					dnidlist[dnids] = (wnodeid_t)wnid;
					dnids++;
					if (dnids == max_stripes) {
						/* found enough switches */
						DPRINTF(DBG_ROUTE_EXTRA,
						    (CE_CONT,
						    "found max_stripes (%d) "
						    "switches\n", dnids));
						break;
					}
				}
			}
		}

		if (dnids == 0) {
			/* no route */
			return (0);
		}

		/*
		 * found a route
		 */

		/*
		 * If just one switch through this wci, can use a
		 * wnode rather than inid2dnid entry.
		 */
		if (dnids == 1 && !wci->nr.using_inids) {
			/* use wnode */
			routep->wroutes[wcinum].wci = wci;
			routep->wroutes[wcinum].route_type = nid_route_wnode;
			routep->wroutes[wcinum].id = (wnodeid_t)dnidlist[0];
			WRSMSET_ADD(wci->nr.wnodeinfo[wnid].reserved,
			    dest_cnodeid);
			/* always just one stripe per switch */
			return (1);
		}

		/*
		 * using inids
		 */

		/*
		 * fix up dnid array
		 */
		/* LINTED: logical expression always true */
		ASSERT(WRSM_MAX_DNIDS == 4);
		if (dnids == 1) {
			dnidlist[1] = dnidlist[0];
			dnidlist[2] = dnidlist[0];
			dnidlist[3] = dnidlist[0];
		} else if (dnids == 2) {
			dnidlist[2] = dnidlist[0];
			dnidlist[3] = dnidlist[1];
		} else if (dnids == 3) {
			dnidlist[3] = dnidlist[2];
		}

		/*
		 * Reserve a new inid entry for this dnid array, or find an
		 * existing matching entry if there is one.
		 */

		inid = ncslice_find_inid(wci, dnidlist, dnids, dest_cnodeid);
		if (inid > -1) {
			/* use inid */
			stripes = dnids;
			routep->wroutes[wcinum].wci = wci;
			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE, "wci %d using "
			    "inid %d, inid #%d\n", wci->config->port,
			    wci->nr.using_inids, inid));
			routep->wroutes[wcinum].route_type = nid_route_inid;
			routep->wroutes[wcinum].id = (wnodeid_t)inid;
			return (stripes);
		}


		/*
		 * no inid entry available for the route we created - see
		 * if one of the existing inid entries can be used instead
		 */

		most_stripes = 0;
		best_inid = -1;
		for (inid = 0; inid < WRSM_INID2DNID_ENTRIES; inid++) {
			ASSERT(wci->nr.inid2dnid[inid].stripes != 0);

			/*
			 * make sure each wnode (dnid) in the nr.inid2dnid
			 * entry goes to usable switch
			 */
			dnids = 0;
			for (i = 0; i < WRSM_MAX_DNIDS; i++) {
				wnid = wci->nr.inid2dnid[inid].wnode_list[i];
				inid_nodeid = wci->config->reachable[wnid];

				for (j = 0; j < proute->nswitches; j++) {
					pt_nodeid = proute->switches[j];
					if (inid_nodeid == pt_nodeid) {
						dnids++;
						break;
					}
				}
			}

			if (dnids == WRSM_MAX_DNIDS) {
				/* found a usable entry - all dnids ok */
				if ((wci->nr.inid2dnid[inid].stripes >
				    most_stripes) &&
				    (wci->nr.inid2dnid[inid].stripes <=
				    max_stripes)) {
					/* remember the best usable entry */
					best_inid = inid;
					most_stripes =
					    wci->nr.inid2dnid[inid].stripes;
				}
			}
		}

		if (best_inid != -1) {
			/* found an inid entry */
			stripes = most_stripes;
			routep->wroutes[wcinum].wci = wci;
			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE, "wci %d using "
			    "inid %d, inid #%d\n", wci->config->port,
			    wci->nr.using_inids, best_inid));
			routep->wroutes[wcinum].route_type = nid_route_inid;
			routep->wroutes[wcinum].id = (wnodeid_t)best_inid;
			WRSMSET_ADD(wci->nr.inid2dnid[best_inid].reserved,
			    dest_cnodeid);
			return (stripes);
		}

		/* no inid2dnid entry available */
		return (0);
	}
}


/*
 * build an nclice route using a single wci
 */
static void
ncslice_build_wci_route(wrsm_routing_policy_t *policy, ncslice_route_t *routep,
    wrsm_preferred_route_t *proute, wrsm_ncwci_t *wci)
{
	wnodeid_t id;

	ASSERT(routep);
	ASSERT(proute);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ncslice_build_wci_route()\n"));

	WRSMSET_ZERO(routep->switches);

	routep->stripes = ncslice_one_wci_route(policy, routep, proute,
	    routep->switches, proute->striping_level, wci, 0);

	if (routep->stripes > 0) {
		ASSERT(wci);
		/*
		 * found a route
		 */
		routep->proute = proute;
		routep->nwcis = 1;
		routep->sg = NULL;
		routep->nostripe = B_TRUE;

		id = routep->wroutes[0].id;
		if (routep->wroutes[0].route_type == nid_route_inid) {
			WRSMSET_COPY(wci->nr.inid2dnid[id].cnode_routes,
			    routep->switches);
		} else {
			WRSMSET_ADD(routep->switches,
			    wci->nr.wnodeinfo[id].cnodeid);
		}

	}
}


/*
 * build an nclice route using each wci in stripe group
 */
static void
ncslice_build_sg_route(wrsm_routing_policy_t *policy, ncslice_route_t *routep,
    wrsm_preferred_route_t *proute, wrsm_nc_strgrp_t *sg)
{
	int i;
	int max_stripes, stripes, totalstripes;
	wnodeid_t id;
	wrsm_ncwci_t *wci;

	ASSERT(sg);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ncslice_build_sg_route()\n"));

	if (sg->availability != wrsm_enabled || !sg->striping_on) {
		/*
		 * striping is not enabled -- try just using one
		 * wci from the stripe group
		 */
		ncslice_build_sg_nostripe_route(policy, routep, proute, sg);
		return;
	}

	ASSERT(routep);
	ASSERT(sg->config);

	routep->stripes = 0;
	routep->proute = proute;
	routep->nostripe = B_FALSE;
	routep->sg = sg;
	routep->nwcis = sg->config->nwcis;

	/*
	 * try to get an equal number of stripes per wci
	 */
	ASSERT(sg->config->nwcis > 0);
	max_stripes = proute->striping_level / sg->config->nwcis;
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "max_stripes per wci = %d\n",
	    max_stripes));
	if (max_stripes == 0) {
		/*
		 * Too many wcis, can't get a stripe per wci.
		 * Try using a single wci.
		 */
		ncslice_build_sg_nostripe_route(policy, routep,
		    proute, sg);
			return;
	}



	/*
	 * find a route on each wci in the stripe group
	 */

	WRSMSET_ZERO(routep->switches);
	totalstripes = 0;
retry:
	for (i = 0; i < sg->config->nwcis; i++) {

		wci = sg->wcis[i];
		stripes = ncslice_one_wci_route(policy, routep, proute,
		    routep->switches, max_stripes, wci, i);

		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
		    "found %d stripes on wci #%d "
		    "(id %d)\n", stripes, i, wci->config->port));

		if ((!policy->wcis_balanced && stripes > 0) ||
		    (policy->wcis_balanced && stripes == max_stripes)) {
			/* found a route on this wci */
			totalstripes += stripes;
			id = routep->wroutes[i].id;
			if (routep->wroutes[i].route_type == nid_route_inid) {
				WRSMSET_OR(routep->switches,
				    wci->nr.inid2dnid[id].cnode_routes);
			} else {
				WRSMSET_ADD(routep->switches,
				    wci->nr.wnodeinfo[id].cnodeid);
			}

		} else {
			ASSERT(stripes == 0 || policy->wcis_balanced);

			/*
			 * can't use current set of routes - remove routes on
			 * previous wcis
			 */

			WRSMSET_ZERO(routep->switches);
			totalstripes = 0;

			if (stripes == 0) {
				/*
				 * There is no route on this wci.  Try
				 * using a single wci from the stripe
				 * group.
				 */
				ncslice_build_sg_nostripe_route(policy,
				    routep, proute, sg);
				return;

			} else {
				/*
				 * It is required that the number of
				 * stripes per wci be balanced.  Retry
				 * finding routes on all wcis with only as
				 * many routes as can be found on this wci.
				 * Start over with the first wci.
				 */
				ASSERT(policy->wcis_balanced);
				max_stripes = stripes;
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "retry with "
				    "max_stripes per wci = %d\n", max_stripes));
				goto retry;
			}
		}
	}


	/*
	 * If balanced stripes aren't required, see if we can get
	 * additional stripes on any wcis.
	 */

	if (!policy->wcis_balanced && totalstripes < proute->striping_level) {

		for (i = 0; i < sg->config->nwcis; i++) {
			max_stripes = proute->striping_level - totalstripes;
			if (max_stripes == 0) {
				/* found enough stripes */
				break;
			}

			wci = sg->wcis[i];

			/* remove old route */
			id = routep->wroutes[i].id;
			if (routep->wroutes[i].route_type == nid_route_inid) {
				totalstripes -=
				    wci->nr.inid2dnid[id].stripes;
				max_stripes +=
				    wci->nr.inid2dnid[id].stripes;
				WRSMSET_DIFF(routep->switches,
				    wci->nr.inid2dnid[id].cnode_routes);
			} else {
				ASSERT(routep->wroutes[i].route_type ==
				    nid_route_wnode);
				totalstripes -=
				    wci->nr.mh_reachable.stripes[id];
				max_stripes += wci->nr.mh_reachable.stripes[id];
				WRSMSET_DEL(routep->switches,
				    wci->nr.wnodeinfo[id].cnodeid);
			}

			/* build a new route with more stripes */
			stripes = ncslice_one_wci_route(policy, routep,
			    proute, routep->switches, max_stripes, wci, i);

			/* found a route on this wci */
			totalstripes += stripes;
			id = routep->wroutes[i].id;
			if (routep->wroutes[i].route_type == nid_route_inid) {
				WRSMSET_OR(routep->switches,
				    wci->nr.inid2dnid[id].cnode_routes);
			} else {
				WRSMSET_ADD(routep->switches,
				    wci->nr.wnodeinfo[id].cnodeid);
			}
		}
	}

	routep->stripes = totalstripes;
}



/*
 * build an nclice route using just one wci from a stripe group
 */
static void
ncslice_build_sg_nostripe_route(wrsm_routing_policy_t *policy,
    ncslice_route_t *routep, wrsm_preferred_route_t *proute,
    wrsm_nc_strgrp_t *sg)
{
	int i;
	wnodeid_t id;

	ASSERT(routep);
	ASSERT(sg);
	ASSERT(sg->config);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "ncslice_build_sg_nostripe_route()\n"));

	/*
	 * wci striping is not required: try using a single
	 * wci from this stripe group
	 */
	routep->nostripe = B_TRUE;
	routep->sg = NULL;
	routep->nwcis = 1;
	WRSMSET_ZERO(routep->switches);

	/*
	 * store the single route in routep entry 0
	 */
	for (i = 0; i < sg->config->nwcis; i++) {
		routep->stripes = ncslice_one_wci_route(policy, routep, proute,
		    routep->switches, proute->striping_level, sg->wcis[i], 0);
		if (routep->stripes > 0) {
			/* found a single wci route */
			DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
			    "ncslice_build_sg_nostripe_route() - found route "
			    "on wci %d\n", sg->wcis[i]->config->port));

			id = routep->wroutes[0].id;
			if (routep->wroutes[0].route_type == nid_route_inid) {
				WRSMSET_COPY(
				    sg->wcis[i]->nr.inid2dnid[id].cnode_routes,
				    routep->switches);
			} else {
				WRSMSET_ADD(routep->switches,
				    sg->wcis[i]->nr.wnodeinfo[id].cnodeid);
			}

			return;
		}
	}
}



/*
 * Find a matching inid entry, otherwise find an unused entry and copy
 * dnid info into it.
 */
static int
ncslice_find_inid(wrsm_ncwci_t *wci, wnodeid_t *dnidlist, int stripes,
    cnodeid_t cnodeid)
{
	int i, j, free_inid, unused_inid;
	wnode_bitmask_t wnode_bitmask;
	wrsm_inid2dnid_entry_t *ientry;
	boolean_t switching_to_inids = B_FALSE;

	ASSERT(wci);
	ASSERT(wci->config);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "ncslice_find_inid() wci %d cnode %d "
	    "stripes %d\n", wci->config->port, cnodeid, stripes));
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "dnids (cnodes) %d (%d) %d (%d) %d (%d) %d (%d)\n",
	    dnidlist[0], wci->nr.wnodeinfo[dnidlist[0]].cnodeid,
	    dnidlist[1], wci->nr.wnodeinfo[dnidlist[1]].cnodeid,
	    dnidlist[2], wci->nr.wnodeinfo[dnidlist[2]].cnodeid,
	    dnidlist[3], wci->nr.wnodeinfo[dnidlist[3]].cnodeid));

	free_inid = 0;
	if (!wci->nr.using_inids && !wci->nr.reserved_inids) {
		/*
		 * Need to set up inid2dnid entries for any valid nc2nid
		 * entries already using or planning to use a wnode route
		 * on this WCI prior to looking for free inid entries.
		 */
		switching_to_inids = B_TRUE;

		for (i = 0; i < WRSM_MAX_WNODES; i++) {
			if (!WRSMSET_ISNULL(wci->nr.wnodeinfo[i].users) ||
			    !WRSMSET_ISNULL(wci->nr.wnodeinfo[i].reserved)) {
				/*
				 * This wnode is in use (or about to be).
				 * Use next inid entry to represent this
				 * wnode.  There will always be at least as
				 * many inid2dnid entries as wnodes.
				 */
				ientry = &(wci->nr.inid2dnid[free_inid]);

				ASSERT(free_inid < WRSM_INID2DNID_ENTRIES);
				ASSERT(WRSMSET_ISNULL(ientry->wnode_bitmask));
				ASSERT(WRSMSET_ISNULL(ientry->cnode_routes));
				ASSERT(WRSMSET_ISNULL(ientry->reserved));

				/* LINTED: E_NOP_IF_STMT */
				if (!WRSMSET_ISNULL(ientry->users)) {
					DPRINTF(DBG_ROUTE,
					    (CE_NOTE,
					    "ientry->users not "
					    "empty (wci %d, "
					    "inid2dnid entry %d)\n",
					    wci->config->port,
					    free_inid));
					DPRINTNODES(ientry->users);
				}

				WRSMSET_ADD(ientry->wnode_bitmask, i);
				/* all dnids in entry use this wnode */
				for (j = 0; j < WRSM_MAX_DNIDS; j++) {
					ientry->wnode_list[j] = i;
				}
				ientry->stripes = 1;
				WRSMSET_ADD(ientry->cnode_routes,
				    wci->nr.wnodeinfo[i].cnodeid);
				WRSMSET_OR(ientry->reserved,
				    wci->nr.wnodeinfo[i].users);
				WRSMSET_OR(ientry->reserved,
				    wci->nr.wnodeinfo[i].reserved);
				ientry->changed = B_TRUE;
				DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
				    "reserved inid "
				    "%d for wnode %d stripes %d\n", free_inid,
				    i, ientry->stripes));
				free_inid++;
			}
		}
		wci->nr.reserved_inids = B_TRUE;
	}


	WRSMSET_ZERO(wnode_bitmask);
	for (i = 0; i < WRSM_MAX_DNIDS; i++) {
		WRSMSET_ADD(wnode_bitmask, dnidlist[i]);
	}

	free_inid = -1;
	unused_inid = -1;
	for (i = 0; i < WRSM_INID2DNID_ENTRIES; i++) {
		if (wci->nr.inid2dnid[i].stripes == 0) {
			/* inid not set up; remember */
			free_inid = i;
			DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "inid %d free",
			    free_inid));
			ASSERT(WRSMSET_ISNULL(wci->nr.inid2dnid[i].users));
			ASSERT(WRSMSET_ISNULL(wci->nr.inid2dnid[i].reserved));
			continue;
		}

		/*
		 * inid's wnode_list doesn't need to match exactly, just
		 * need the same number of stripes, and same set of
		 * wnodes
		 */
		if ((wci->nr.inid2dnid[i].stripes == stripes) &&
		    WRSMSET_ISEQUAL(wci->nr.inid2dnid[i].wnode_bitmask,
		    wnode_bitmask)) {
			/* found a matching entry */
			DPRINTF(DBG_ROUTE_EXTRA,
			    (CE_CONT, "inid %d matching entry",
			    i));
			WRSMSET_ADD(wci->nr.inid2dnid[i].reserved, cnodeid);
			return (i);
		}

		if (WRSMSET_ISNULL(wci->nr.inid2dnid[i].users) &&
		    WRSMSET_ISNULL(wci->nr.inid2dnid[i].reserved))
			/* no one is using this entry; remember */
			unused_inid = i;
	}

	/* prefer a free inid over an unused inid */
	if (free_inid != -1) {
		unused_inid = free_inid;
	}

	if (unused_inid != -1) {
		/* copy information into this inid entry */
		ientry = &(wci->nr.inid2dnid[unused_inid]);
		ientry->stripes = stripes;
		WRSMSET_COPY(wnode_bitmask, ientry->wnode_bitmask);
		WRSMSET_ZERO(ientry->cnode_routes);
		for (i = 0; i < WRSM_MAX_DNIDS; i++) {
			ientry->wnode_list[i] = dnidlist[i];
			ASSERT(wci->config->wnode_reachable[dnidlist[i]]);
			WRSMSET_ADD(ientry->cnode_routes,
			    wci->nr.wnodeinfo[dnidlist[i]].cnodeid);
		}
#ifdef DEBUG
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
		    "inid %d stripes %d cnode_routes",
		    unused_inid, ientry->stripes));
		if (wrsm_nr_debug & DBG_ROUTE)
			DPRINTNODES(ientry->cnode_routes);
#endif

		WRSMSET_ADD(ientry->reserved, cnodeid);
		ientry->changed = B_TRUE;
	} else {
		DPRINTF(DBG_ROUTE, (CE_CONT, "no free inid entry\n"));
		if (switching_to_inids) {
			for (i = 0; i < WRSM_INID2DNID_ENTRIES; i++) {
				ientry = &(wci->nr.inid2dnid[i]);
				if (ientry->changed) {
					WRSMSET_ZERO(ientry->wnode_bitmask);
					WRSMSET_ZERO(ientry->cnode_routes);
					WRSMSET_ZERO(ientry->reserved);
					ientry->changed = B_FALSE;
				}
			}
		}
	}

	return (unused_inid);
}


/*
 * Map a wci number, as it appears in the
 * node->routeinfo->current_route list of wcis to the stripe number
 * that it will use.
 */
static int
wci_to_stripe(int i)
{
	ASSERT(i < WRSM_MAX_STRIPEWCIS);
	switch (i) {
	case 0: return (0);
	case 1: return (2);
	case 2: return (1);
	case 3: return (3);
	}
	return (0);
}

/*
 * Calculate the striping for barriers.  The link_stripes field is a bit
 * mask of the offsets to read to collect the CESRs of all wcis and links
 * providing access to this node.
 *
 * Called from event thread.
 */
static void
nr_cnode_stripes(wrsm_node_t *node)
{
	ncslice_route_t *currentp;
	int i;
	int wci_stripe;
	wnodeid_t id;
	ushort_t link_stripes = 0;
	wrsm_ncwci_t *wci;

	ASSERT(node);
	ASSERT(node->routeinfo);

	currentp = &(node->routeinfo->current_route);


	/*
	 * WCI striping is controlled by bits 7 and 8.  This means
	 * that striping occurs at a granularity of 128 bytes.
	 * The striping pattern is as follows:
	 *
	 *			4-way	2-way	1-way
	 *	bit 8:7		WCI	WCI	WCI
	 *	0		A	A	A
	 *	1		B	A	A
	 *	2		C	B	A
	 *	3		D	B	A
	 *
	 * currentp->nwci can be used to turn on the appropriate WCI
	 * stripes:
	 *	1: bit 0; 2: bits 0,1; 4: bits 0-3
	 *
	 *
	 *
	 * for inid2dnid striping, there are always 4 dnids.  The
	 * NR programs the dnids in one of the following patterns:
	 *	1 way: AAAA, 2 way: ABAB, 3 way: ABCC, 4 way: ABCD
	 *
	 * The address bits used for striping are bits 9 and 10.
	 * The striping occurs at a gramularity of 512 bytes.
	 *
	 * The bits are used in reverse from expected order
	 * (see page 5-224 in the PRM, revsion 1.0, Jun 30, 1999).
	 * This means the striping pattern is not quite as expected:
	 *
	 *			INID	4 way	3 way	2 way	1 way
	 *	bit 10:9	entry	INID	INID	INID	INID
	 *	0		0	A	A	A	A
	 *	1		2	C	C	A	A
	 *	2		1	B	B	B	A
	 *	3		3	D	C	B	A
	 *
	 * The inid2dnid.stripe field can be used to turn on the appropriate
	 * stripes:
	 *	1: bit 0; 2: bits 0,2; 3: bits 0-2; 4: bits 0-3
	 *
	 *
	 *
	 * For route map striping, there are alway 2 links. The
	 * possible patterns are:
	 *	1 way: AA, 2 way: AB
	 *
	 * Address bit 9 is used for route map striping.
	 * The striping occurs at a gramularity of 512 bytes.
	 * The striping pattern is as follows:
	 *
	 *			rtmap	2 way	1 way
	 *	bit 9		entry	rtmap	rtmap
	 *	0		0	A	A
	 *	1		1	B	A
	 *
	 * The wnodeinfo.stripes field can be used to turn on the appropriate
	 * stripes:
	 *	1: bit 0, 2: bits 0,1
	 */

	for (i = 0; i < currentp->nwcis; i++) {
		wci = currentp->wroutes[i].wci;
		id = currentp->wroutes[i].id;
		wci_stripe = wci_to_stripe(i);

		if (currentp->wroutes[i].route_type == nid_route_wnode) {

			switch (wci->nr.mh_reachable.stripes[id]) {
				/* fall through in each case */
			case 2:
				link_stripes |= 1 << (BBIT_LINK_STRIDE +
				    wci_stripe);
				/* LINTED: E_CASE_FALLTHRU */
			case 1:
				link_stripes |= 1 << wci_stripe;
			}

		} else {
			ASSERT(currentp->wroutes[i].route_type ==
			    nid_route_inid);
			switch (wci->nr.inid2dnid[id].stripes) {
				/* fall through in each case */
			case 4:
				link_stripes |= 1 << ((3 * BBIT_LINK_STRIDE)
				    + wci_stripe);
				/* LINTED: E_CASE_FALLTHRU */
			case 3:
				link_stripes |= 1 << ((1 * BBIT_LINK_STRIDE)
				    + wci_stripe);
				/* LINTED: E_CASE_FALLTHRU */
			case 2:
				link_stripes |= 1 << ((2 * BBIT_LINK_STRIDE)
				    + wci_stripe);
				/* LINTED: E_CASE_FALLTHRU */
			case 1:
				link_stripes |= 1 << wci_stripe;
			}
		}
	}

	*node->link_stripesp = link_stripes;
}


/*
 * Check whether any ncslice routes are changing, and if changes require
 * traffic to be stopped on the Safari bus.  Stop activity on routes that
 * are being removed.
 *
 * Note:  the current algorithm removes an old route before adding a new
 * route, which means that any time a route changes, traffic must be
 * stopped.  It might be possible to change the algorithm to change the
 * route in one step in the case where the same wci is handling both the
 * old and new routes.  If this were true, traffic would only need to be
 * stopped if the wci handling the route changed (including going from
 * striped to non-striped or vice versa).
 */
static boolean_t
find_changing_routes(wrsm_network_t *network,
    ncslice_route_t *errloopback_route, boolean_t *stop_trafficp)
{
	boolean_t route_changes = B_FALSE;
	boolean_t stop_traffic = B_FALSE;
	wrsm_node_t *node;
	int i;
#ifdef DEBUG
	int x;
	ncslice_route_t *routep;
#endif

	ASSERT(network);

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (node == NULL || node->routeinfo == NULL)
			continue;

#ifdef DEBUG
			routep = &node->routeinfo->current_route;

			for (x = 0; x < routep->nwcis; x++) {
				if (routep->wroutes[x].route_type ==
				    nid_route_inid) {
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d: node %d "
					    "current route wci %d uses "
					    "inid %d\n",
					    network->rsm_ctlr_id,
					    node->config->cnodeid,
					    routep->wroutes[x].wci->
					    config->port,
					    routep->wroutes[x].id));
				    }
			}
#endif

		if (node->routeinfo->route_state == ncslice_use_new_route) {
#ifdef DEBUG
			routep = &node->routeinfo->new_route;

			for (x = 0; x < routep->nwcis; x++) {
				if (routep->wroutes[x].route_type ==
				    nid_route_inid) {
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d: node %d "
					    "new route wci %d uses inid %d\n",
					    network->rsm_ctlr_id,
					    node->config->cnodeid,
					    routep->wroutes[x].wci->
					    config->port,
					    routep->wroutes[x].id));
				    } else {
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d: node %d  new route "
					    "wci %d no inids\n",
					    network->rsm_ctlr_id,
					    node->config->cnodeid,
					    routep->wroutes[x].wci->
					    config->port));
				    }

			}
#endif
			if (stop_traffic) {
				/*
				 * already set any necessary booleans
				 */
				continue;
			}

			ASSERT(node->routeinfo->new_route.stripes != 0);

			route_changes = B_TRUE;

			if (node->routeinfo->current_route.stripes != 0) {
				stop_traffic = B_TRUE;
			}

		} else if (node->routeinfo->route_state ==
		    ncslice_use_errloopback) {
			DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: node %d will "
			    "use err loopback route\n", network->rsm_ctlr_id,
			    node->config->cnodeid));
#ifdef DEBUG
			routep = &node->routeinfo->new_route;

			for (x = 0; x < routep->nwcis; x++) {
				if (routep->wroutes[x].route_type ==
				    nid_route_inid) {
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d: node %d "
					    "err route wci %d uses inid %d\n",
					    network->rsm_ctlr_id,
					    node->config->cnodeid,
					    routep->wroutes[x].wci->
					    config->port,
					    routep->wroutes[x].id));
				    } else {
					DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
					    "ctlr %d: node %d  err route "
					    "wci %d no inids\n",
					    network->rsm_ctlr_id,
					    node->config->cnodeid,
					    routep->wroutes[x].wci->
					    config->port));
				    }

			}
#endif

			/*
			 * Might get here if the error loopback route has
			 * changed, as well as because of newly losing a route.
			 */

			ASSERT(node->routeinfo->current_route.stripes != 0);
			ASSERT(errloopback_route);

			/*
			 * Check whether already using the current
			 * err loopback route
			 */
			if (ncslice_routes_match(
			    &(node->routeinfo->current_route),
			    errloopback_route)) {
				node->routeinfo->route_state =
				    ncslice_use_current;
				continue;
			} else {
				bcopy(errloopback_route,
				    &node->routeinfo->new_route,
				    sizeof (ncslice_route_t));
			}

			if (WRSM_NODE_HAVE_ROUTE(node)) {
				/* previous route was a real one */
				nr_noroute(node);
			}

			if (stop_traffic) {
				continue;
			}


			if (node->routeinfo->route_state !=
			    ncslice_use_current) {
				route_changes = B_TRUE;

				ASSERT(node->routeinfo->new_route.stripes != 0);
				if (node->routeinfo->current_route.stripes
				    != 0) {
					stop_traffic = B_TRUE;
				}
			}

		} else if (node->routeinfo->route_state ==
		    ncslice_remove_route) {
			DPRINTF(DBG_ROUTE, (CE_CONT, "apply_routes: removing "
			    "route for node %d",
			    node->config->cnodeid));
			if (WRSM_NODE_HAVE_ROUTE(node)) {
				nr_noroute(node);
			}

			/*
			 * Route will be completely removed if there is
			 * one.  (There may be no route already, or a real
			 * route or an error route).  It is ok to remove
			 * this route because the only time this happens is
			 * when a node is being removed from a config, and
			 * nodes can only be removed from a config after
			 * the controller unregisters itself (guaranteeing
			 * that there will be no client accesses to this
			 * node).  There is no need to pause cpus or wcis
			 * because they've already stopped using this
			 * route, but we do want to drain wcis of
			 * transactions, because although we've turned off
			 * passthrough, we may need to wait for previous
			 * in-progress transactions to the ncslice.
			 */
			if (node->routeinfo->current_route.stripes != 0) {
				/* there is currently a route to remove */
				DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: "
				    "node %d removing route\n",
				    network->rsm_ctlr_id,
				    node->config->cnodeid));
				route_changes = B_TRUE;
				stop_traffic = B_TRUE;
			} else {
				node->routeinfo->route_state =
				    ncslice_no_route;
			}
		}
	}

	*stop_trafficp = stop_traffic;

	return (route_changes);
}


/*
 * Stop all traffic that could be generating new transactions accessing
 * ncslice addresses, so that we can safely move ncslice ownership from
 * one wci to another.  This function is also used by DDI_SUSPEND, to
 * stop all incoming traffic.
 */
static void stop_ncslice_traffic(wrsm_network_t *network,
    boolean_t stop_incoming)
{
	wci_ca_config_u wci_ca_config;
	wci_ca_busy_u wci_ca_busy;
	wci_ra_busy_u wci_ra_busy;
	wrsm_ncwci_t *wci;

	ASSERT(network);

	/*
	 * Stop local cpus from generating nc2nid traffic.
	 * (pause_cpus does a kpreempt_disable)
	 * The cpu_pause thread on each cpu does a membar sync
	 * when it starts running, flushing the cpu load/store cache.
	 */
	if (!stop_incoming) {
		mutex_enter(&cpu_lock);
		pause_cpus(NULL);
	}

	/*
	 * If wcis are generating passthrough traffic or if all incoming
	 * traffic should be prevented, stop remote
	 * nodes from generating new traffic by turning on the
	 * cluster_disable flag in all wcis.  (All wcis have the
	 * same passthrough configuration.) Note:  the list of
	 * lcwcis can't change in the middle, as all cpus are
	 * stopped.
	 *
	 * Note:  we don't actually know which wcis are being used
	 * by remote nodes for passthrough, so there's no way to
	 * only perform this disabling on some of the wcis.
	 */

	if (network->passthrough_routes || stop_incoming) {
		ASSERT(network->nr);
		for (wci = network->nr->wcis; wci; wci = wci->next) {
			if (!wci->lcwci)
				continue;
			wrsm_lc_csr_read(wci->lcwci,
			    (uint64_t)ADDR_WCI_CA_CONFIG,
			    &(wci_ca_config.val));
			wci_ca_config.bit.cluster_disable = 1;
			wrsm_lc_csr_write(wci->lcwci,
			    (uint64_t)ADDR_WCI_CA_CONFIG,
			    wci_ca_config.val);
		}

		/*
		 * Make sure already arrived passthrough/incoming requests
		 * have been issued onto the bus.
		 *
		 * Look at CAG busy bits; when no CAGs are busy all
		 * requests have completed.
		 */
		for (wci = network->nr->wcis; wci; wci = wci->next) {
			if (!wci->lcwci)
				continue;
			do {
				wrsm_lc_csr_read(wci->lcwci,
				    (uint64_t)ADDR_WCI_CA_BUSY,
				    &(wci_ca_busy.val));
			} while (wci_ca_busy.bit.vector);
		}
	}

	/*
	 * Make sure Request Agents on the wcis having ncslices
	 * removed are finished servicing requests to moving
	 * ncslices.  Given that all cpus have membar-synced and
	 * all CAGS are not busy, RAGS should be pretty much idle
	 * already (some might still be handling a data phase).
	 *
	 * For coding simplicity, check all wcis instead of just
	 * those losing ncslices.
	 *
	 * The hardware team advised that we do this.
	 */

	for (wci = network->nr->wcis; wci; wci = wci->next) {
		if (!wci->lcwci)
			continue;
		do {
			wrsm_lc_csr_read(wci->lcwci,
			    (uint64_t)ADDR_WCI_RA_BUSY,
			    &(wci_ra_busy.val));
		} while (wci_ra_busy.bit.vector);
	}
}


static void
restart_ncslice_traffic(wrsm_network_t *network, boolean_t stop_incoming)
{
	wci_ca_config_u wci_ca_config;
	wrsm_ncwci_t *wci;

	ASSERT(network);

	/*
	 * Allow remote nodes to generate passthrough/incoming nc2nid traffic.
	 * Note:  list of lcwcis can't change in the middle, as all cpus
	 * are stopped.
	 */

	if (network->passthrough_routes || stop_incoming) {
		ASSERT(network->nr);
		for (wci = network->nr->wcis; wci; wci = wci->next) {
			if (!wci->lcwci)
				continue;
			wrsm_lc_csr_read(wci->lcwci,
			    (uint64_t)ADDR_WCI_CA_CONFIG,
			    &(wci_ca_config.val));
			wci_ca_config.bit.cluster_disable = 0;
			wrsm_lc_csr_write(wci->lcwci,
			    (uint64_t)ADDR_WCI_CA_CONFIG,
			    wci_ca_config.val);
		}
	}

	/*
	 * restart local cpus stopped in stop_ncslice_traffic
	 * (does a kpreempt_enable)
	 */
	if (!stop_incoming) {
		start_cpus();
		mutex_exit(&cpu_lock);
	}
}



/*
 * Modify the hardware to reflect the newly calculated inid2dnids for
 * each wci, and the new nc2nid settings described by the ncslice route
 * for each node
 */
static void
ncslice_apply_routes(wrsm_network_t *network)
{
	int i;
	wrsm_node_t *node, *local_node;
	wrsm_ncwci_t *wci;
	cnode_bitmask_t newroute;
	boolean_t route_changes = B_FALSE;
	boolean_t inid_changes = B_FALSE;
	boolean_t stop_traffic = B_FALSE;
	boolean_t ptnotify = B_FALSE;
	ncslice_route_t *errloopback_route = NULL;

	ASSERT(network);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ncslice_apply_routes()\n"));

	/*
	 * If there is no routeinfo for the local node, than it is too
	 * early to set up routes.  Do nothing.
	 */
	local_node = network->nodes[network->cnodeid];
	if (!local_node || !local_node->routeinfo) {
		return;
	}

	/*
	 * The local node is required to have a loopback route, which is
	 * used for any ncslice which has lost its route.  The local
	 * loopback route is set up before any other routes, so it is
	 * guaranteed to be available by the time it is needed.  The only
	 * time it is allowed to go away is when the configuration is being
	 * removed (in which case the controller unregisters, and dangling
	 * accesses to remote nodes are guaranteed to not be a problem).
	 */
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "apply_routes: local route "
	    "state is %s; current stripes %d",
	    ROUTEINFO_MSGSTRING(local_node->routeinfo->route_state),
	    local_node->routeinfo->new_route.stripes));
	if (local_node->routeinfo->route_state == ncslice_use_new_route) {
		errloopback_route = &local_node->routeinfo->new_route;
	} else if (local_node->routeinfo->route_state == ncslice_use_current) {
		errloopback_route = &local_node->routeinfo->current_route;
	} else if (local_node->routeinfo->route_state == ncslice_no_route) {
		/*
		 * If local node is no_route, then must be removing config,
		 * and must have already removed routes for all other nodes.
		 */
#ifdef DEBUG
		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			node = network->nodes[i];
			if (node && node->routeinfo)
				ASSERT(node->routeinfo->route_state ==
				    ncslice_no_route);
		}
#endif
		return;
#ifdef DEBUG
	} else {
		/*
		 * route_state should never be use_errloopback, as this
		 * _is_ the errloopback route!
		 */
		ASSERT(local_node->routeinfo->route_state ==
		    ncslice_remove_route);
		for (i = 0; i < WRSM_MAX_CNODES; i++) {
			node = network->nodes[i];
			if (node && node->routeinfo)
				ASSERT((node->routeinfo->route_state ==
				    ncslice_remove_route) ||
				    (node->routeinfo->route_state ==
				    ncslice_no_route));
		}
#endif
	}

	/*
	 * check whether any inid2dnids are changing
	 */
	for (wci = network->nr->wcis; wci; wci = wci->next) {
		if (wci->nr.need_hw_update) {
			inid_changes = B_TRUE;
		}

		for (i = 0; i < WRSM_MAX_WNODES; i++) {
			WRSMSET_ZERO(wci->nr.wnodeinfo[i].reserved);
		}
		for (i = 0; i < WRSM_INID2DNID_ENTRIES; i++) {
			WRSMSET_ZERO(wci->nr.inid2dnid[i].reserved);
			wci->nr.reserved_inids = B_FALSE;
		}
	}

	/*
	 * Look for changing nc2nid routes.  Check whether there were
	 * existing routes for any of the new routes; replacing an existing
	 * route requires stopping traffic.
	 */
	route_changes = find_changing_routes(network, errloopback_route,
	    &stop_traffic);

	if (!inid_changes && !route_changes)
		return;

	WRSMSET_ZERO(newroute);

	nr_reroute_start(network);

	/*
	 * Enter platform ncslice update critical section.
	 */
	wrsmplat_ncslice_enter();

	if (stop_traffic)
		stop_ncslice_traffic(network, B_FALSE);

	/*
	 * apply changes to inid2dnid registers if necessary
	 */
	for (wci = network->nr->wcis; wci; wci = wci->next) {
		if (wci->nr.need_hw_update)
			nr_update_wci(wci);
	}

	/*
	 * apply changes to nc2nid registers if necessary
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (node == NULL || node->routeinfo == NULL) {
			continue;
		}

		if (node->routeinfo->route_state ==
		    ncslice_remove_route) {
			ncslice_remove_hw_route(node,
			    node->routeinfo->current_route);
			node->routeinfo->current_route.stripes = 0;
			*node->link_stripesp = 0;
		} else if ((node->routeinfo->route_state ==
		    ncslice_use_new_route) ||
		    (node->routeinfo->route_state ==
		    ncslice_use_errloopback)) {

			ASSERT(errloopback_route);


			if (node->routeinfo->current_route.stripes > 0) {
				ncslice_remove_hw_route(node,
				    node->routeinfo->current_route);
			}

			if ((node->routeinfo->route_state ==
			    ncslice_use_new_route) && (node->state ==
			    wrsm_node_needroute)) {
				/* newly able to communicate with this node */
				WRSMSET_ADD(newroute, i);
			}

			ncslice_add_hw_route(node,
			    node->routeinfo->new_route);
		    }
	}

	/*
	 * Notify platform module of any changes in ncslice ownership.
	 * (ncslice_responder array is updated by ncslice_add_hw_route()
	 * and ncslice_remove_hw_route()).
	 */
	wrsmplat_ncslice_setup(network->nr->ncslice_responder);


	if (stop_traffic)
		restart_ncslice_traffic(network, B_FALSE);

	/*
	 * Exit platform ncslice update critical section.
	 */
	wrsmplat_ncslice_exit();

	/*
	 * for nodes that have newly acquired routes, do any necessary
	 * setup and notification
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {

		node = network->nodes[i];
		if (!node || !node->routeinfo)
			continue;
		if (node->routeinfo->route_state ==
		    ncslice_remove_route) {
			wrsm_nr_logevent(network, node, lost_node_route,
			    "unconfigured");
			node->routeinfo->route_state = ncslice_no_route;
		} else if (node->routeinfo->route_state ==
		    ncslice_use_errloopback) {
			wrsm_nr_logevent(network, node, lost_node_route,
			    "no-route");
		} else if (node->routeinfo->route_state ==
			    ncslice_use_new_route) {
			wrsm_nr_logevent(network, node, new_node_route, NULL);
		}
		if ((node->routeinfo->route_state == ncslice_use_new_route) ||
		    (node->routeinfo->route_state ==
		    ncslice_use_errloopback)) {

			/* lock the struct */
			mutex_enter(&network->nr->lock);

			bcopy(&node->routeinfo->new_route,
			    &node->routeinfo->current_route,
			    sizeof (ncslice_route_t));

			/* unlock the struct */
			mutex_exit(&network->nr->lock);

			nr_cnode_stripes(node);
			node->routeinfo->route_state = ncslice_use_current;

			if (WRSM_IN_SET(newroute, i))
				if (nr_haveroute(node) == B_TRUE)
					ptnotify = B_TRUE;
		}
	}

	nr_reroute_finish(network);

	/*
	 * notify other nodes if passthrough access has changed
	 */
	if (ptnotify)
		pt_newptinfo(network, pt_route_counter, NULL);
}


/*
 * Update the wci inid2dnid registers and enable_inid flag in the
 * wci_config registers to match what the data structure says they should
 * be.
 */
static void
nr_update_wci(wrsm_ncwci_t *wci)
{
	int i, j;
	wci_inid2dnid_array_u wci_inid;
	wci_config_u wci_config;
	lcwci_handle_t lcwci;
	uint64_t offset;

	ASSERT(wci);
	lcwci = wci->lcwci;

	DPRINTF(DBG_PAUSECPUS_EXTRA, (CE_CONT, "nr_update_wci()\n"));

	if (wci->nr.using_inids) {
		/* update dnids in inid table */
		wci_inid.val = 0;

		/*
		 * There are 64 entries in the hardware, organized
		 * as inid2dnid[dnid][inid].  Each entry is spaced
		 * at a distance of STRIDE_WCI_INID2DNID_ARRAY bytes
		 * apart, and is 8 bytes (uint64_t) large.
		 */
		for (i = 0; i < WRSM_INID2DNID_ENTRIES; i++) {
			if (!wci->nr.inid2dnid[i].changed) {
				/* skip over this inid's dnids */
				continue;
			}

			for (j = 0; j < WRSM_MAX_DNIDS; j++) {
				wci_inid.bit.dnid =
					wci->nr.inid2dnid[i].wnode_list[j];
				offset = ((uint64_t)ADDR_WCI_INID2DNID_ARRAY) +
				    (STRIDE_WCI_INID2DNID_ARRAY *
				    WRSM_INID2DNID_ENTRIES * j) +
				    (STRIDE_WCI_INID2DNID_ARRAY * i);
				wrsm_lc_csr_write(lcwci, offset, wci_inid.val);
			}
			wci->nr.inid2dnid[i].changed = 0;
		}

		/* modify register to use inid table */
		wrsm_lc_csr_read(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    &(wci_config.val));
		wci_config.bit.enable_inid = 1;
		wrsm_lc_csr_write(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    wci_config.val);

		wci->nr.inids_enabled = B_TRUE;

	} else {
		/* modify register to not use inid table */
		wrsm_lc_csr_read(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    &(wci_config.val));
		wci_config.bit.enable_inid = 0;
		wrsm_lc_csr_write(lcwci, (uint64_t)ADDR_WCI_CONFIG,
		    wci_config.val);
		wci->nr.inids_enabled = B_FALSE;
	}

	wci->nr.need_hw_update = B_FALSE;
}


/*
 * stop using the nc2nid entries on wcis specified by this route
 */
static void
ncslice_remove_hw_route(wrsm_node_t *node, ncslice_route_t route)
{
	int i, j;
	wci_nc2nid_array_u wci_nc2nid;
	uint64_t offset;
	wrsm_ncwci_t *wci;
	wnodeid_t id;	 /* inid is the same */
	wrsm_network_t *network;
	ncslice_t ncslice;

	ASSERT(node);
	network = node->network;

	DPRINTF(DBG_PAUSECPUS, (CE_CONT, "ctlr %d: ncslice_remove_hw_route() - "
	    "node %d\n", node->network->rsm_ctlr_id, node->config->cnodeid));

	/* setting launch remote to 0 means all other fields are ignored */
	wci_nc2nid.bit.launch_remote = 0;
	wci_nc2nid.val = 0; /* just to be sure */

	/*
	 * turn off launch_remote bit for each ncslice on each wci in route
	 */
	for (i = 0; i < WRSM_NODE_NCSLICES; i++) {
		if ((ncslice = node->config->exported_ncslices.id[i]) == 0)
			continue;

		/*
		 * record that there is no wci/stripe group owner - info
		 * for updating AXQ's or SSM WCIs
		 */
		network->nr->ncslice_responder[ncslice].owner_type =
		    WRSM_NCOWNER_NONE;

		offset = (uint64_t)(ADDR_WCI_NC2NID_ARRAY +
		    (ncslice * STRIDE_WCI_NC2NID_ARRAY));
		for (j = 0; j < route.nwcis; j++) {
			wrsm_lc_csr_write(route.wroutes[j].wci->lcwci, offset,
			    wci_nc2nid.val);
#ifdef DEBUG
			wrsm_lc_csr_read(route.wroutes[j].wci->lcwci, offset,
			    &(wci_nc2nid.val));
			ASSERT(wci_nc2nid.bit.launch_remote == 0);
			wci_nc2nid.val = 0;
#endif
		}
	}

	/*
	 * Also need to do this for ncslices forwarded to this cnode.
	 */
	for (i = 0; i < WRSM_MAX_NCSLICES; i++) {
		if (!WRSM_IN_SET(node->routeinfo->policy->forwarding_ncslices,
		    i))
			continue;

		/*
		 * record that there is no wci/stripe group owner - info
		 * for updating AXQ's or SSM WCIs
		 */
		network->nr->ncslice_responder[i].owner_type =
		    WRSM_NCOWNER_NONE;

		offset = (uint64_t)(ADDR_WCI_NC2NID_ARRAY +
		    (i * STRIDE_WCI_NC2NID_ARRAY));
		for (j = 0; j < route.nwcis; j++) {
			wrsm_lc_csr_write(route.wroutes[j].wci->lcwci, offset,
			    wci_nc2nid.val);
#ifdef DEBUG
			wrsm_lc_csr_read(route.wroutes[j].wci->lcwci, offset,
			    &(wci_nc2nid.val));
			ASSERT(wci_nc2nid.bit.launch_remote == 0);
			wci_nc2nid.val = 0;
#endif
		}
	}


	/*
	 * record that this cnode is no longer using these routes
	 */
	for (i = 0; i < route.nwcis; i++) {
		wci = route.wroutes[i].wci;
		id = route.wroutes[i].id;
		ASSERT(id < WRSM_MAX_WNODES); /* same max for inids */
#ifdef DEBUG
		if (wci == NULL) {
			DPRINTF(DBG_PAUSECPUSWARN, (CE_WARN, "wci #%d doesn't "
			    "exist!\n", i));
			continue;
		} else if (wci->config == NULL) {
			DPRINTF(DBG_PAUSECPUSWARN, (CE_WARN, "wci #%d config "
			    "doesn't exist!\n", i));
			continue;
		}
#endif
		if (route.wroutes[i].route_type == nid_route_wnode) {
			DPRINTF(DBG_PAUSECPUS, (CE_CONT, "rmv_hw_route on "
			    "wci %d wnode %d\n", wci->config->port, id));
			WRSMSET_DEL(wci->nr.wnodeinfo[id].users,
			    node->config->cnodeid);
		} else {
			DPRINTF(DBG_PAUSECPUS, (CE_CONT, "rmv_hw_route on "
			    "wci %d inid %d\n", wci->config->port, id));
			WRSMSET_DEL(wci->nr.inid2dnid[id].users,
			    node->config->cnodeid);
		}
	}

	if (route.sg) {
		DPRINTF(DBG_PAUSECPUS, (CE_CONT, "rmv_hw_route for stripe "
		    "group %d\n", route.sg->config->group_id));
		WRSMSET_DEL(route.sg->users, node->config->cnodeid);
	}
}


/*
 * start using the nc2nid entries for ncslices belonging to this node
 * on wcis specified by this route
 */
static void
ncslice_add_hw_route(wrsm_node_t *node, ncslice_route_t route)
{
	int i, j;
	wci_nc2nid_array_u wci_nc2nid;
	uint64_t offset;
	wrsm_ncwci_t *wci;
	wrsm_ncowner_t ncslice_owner_type;
	wrsm_ncowner_id_t ncslice_owner;
	wrsm_network_t *network;
	ncslice_t ncslice;

	ASSERT(node);
	ASSERT(node->config);
	ASSERT(node->network);
	network = node->network;

	DPRINTF(DBG_PAUSECPUS, (CE_CONT, "ctlr %d:  ncslice_add_hw_route() - "
	    "cnode %d\n", node->network->rsm_ctlr_id,
	    node->config->cnodeid));

	wci_nc2nid.val = 0;
	wci_nc2nid.bit.launch_remote = 1;
	wci_nc2nid.bit.encode_cluster_origin_tag = 1;
	if (route.nostripe) {
		wci_nc2nid.bit.no_stripe = 1;
		ncslice_owner_type = WRSM_NCOWNER_WCI;
		ncslice_owner.wci_id = route.wroutes[0].wci->config->port;
	} else {
		wci_nc2nid.bit.no_stripe = 0;
		ncslice_owner_type = WRSM_NCOWNER_STRIPEGROUP;
		ncslice_owner.stripe_group = route.sg->config;
	}

	/*
	 * set the inid/wnode for each ncslice on each wci in route
	 */
	for (i = 0; i < WRSM_NODE_NCSLICES; i++) {
		if ((ncslice = node->config->exported_ncslices.id[i]) == 0)
			continue;

		/*
		 * record new wci/stripe group owner - info for updating
		 * AXQ's or SSM WCIs
		 */
		network->nr->ncslice_responder[ncslice].owner_type =
		    ncslice_owner_type;
		network->nr->ncslice_responder[ncslice].owner = ncslice_owner;

		offset = (uint64_t)(ADDR_WCI_NC2NID_ARRAY +
		    (ncslice * STRIDE_WCI_NC2NID_ARRAY));

		for (j = 0; j < route.nwcis; j++) {
			wci_nc2nid.bit.dest_node_id = route.wroutes[j].id;
			wrsm_lc_csr_write(route.wroutes[j].wci->lcwci, offset,
			    wci_nc2nid.val);
		}
	}

	/*
	 * Also need to do this for ncslices forwarded to this cnode.
	 */
	for (i = 0; i < WRSM_MAX_NCSLICES; i++) {
		if (!WRSM_IN_SET(node->routeinfo->policy->forwarding_ncslices,
		    i))
			continue;

		/*
		 * record new wci/stripe group owner - info for updating
		 * AXQ's or SSM WCIs
		 */
		network->nr->ncslice_responder[i].owner_type =
		    ncslice_owner_type;
		network->nr->ncslice_responder[i].owner = ncslice_owner;

		offset = (uint64_t)(ADDR_WCI_NC2NID_ARRAY +
		    (i * STRIDE_WCI_NC2NID_ARRAY));

		for (j = 0; j < route.nwcis; j++) {
			wci_nc2nid.bit.dest_node_id = route.wroutes[j].id;
			wrsm_lc_csr_write(route.wroutes[j].wci->lcwci, offset,
			    wci_nc2nid.val);
		}
	}

	/*
	 * record that this cnode is now using these routes
	 */
	for (i = 0; i < route.nwcis; i++) {
		wci = route.wroutes[i].wci;
		if (route.wroutes[i].route_type == nid_route_wnode) {
			DPRINTF(DBG_PAUSECPUS, (CE_CONT, "add_hw_route on "
			    "wci %d wnode %d\n", wci->config->port,
			    route.wroutes[i].id));
			WRSMSET_ADD(
			    wci->nr.wnodeinfo[route.wroutes[i].id].users,
			    node->config->cnodeid);
		} else {
			DPRINTF(DBG_PAUSECPUS, (CE_CONT, "add_hw_route on "
			    "wci %d inid %d\n", wci->config->port,
			    route.wroutes[i].id));
			WRSMSET_ADD(
			    wci->nr.inid2dnid[route.wroutes[i].id].users,
			    node->config->cnodeid);
		}
	}
	if (route.sg) {
		DPRINTF(DBG_PAUSECPUS, (CE_CONT, "add_hw_route for stripe "
		    "group %d\n", route.sg->config->group_id));
		WRSMSET_ADD(route.sg->users, node->config->cnodeid);
	}
}



/*
 * A route to this node was established (previously there was no
 * route).  Notify transport layer and passthrough clients.
 *
 * return whether passthrough notification is needed
 */
static boolean_t
nr_haveroute(wrsm_node_t *node)
{
	ASSERT(node);
	ASSERT(node->network);
	ASSERT(node->config);

	DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: nr_haveroute() node %d\n",
	    node->network->rsm_ctlr_id, node->config->cnodeid));

	ASSERT(node->state == wrsm_node_needroute);

	node->state = wrsm_node_haveroute;
	wrsm_tl_reachable(node->network, node->config->cnodeid);
	return (pt_haveroute(node));
}


/*
 * The route to this node was lost:
 * tear down all communication to node; notify passthrough
 * clients
 */
static void
nr_noroute(wrsm_node_t *node)
{
	ASSERT(node);
	ASSERT(node->network);
	ASSERT(node->config);

	DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: nr_noroute() node %d\n",
	    node->network->rsm_ctlr_id, node->config->cnodeid));

	ASSERT(WRSM_NODE_HAVE_ROUTE(node));

	wrsm_tl_unreachable(node->network, node->config->cnodeid);

	/*
	 * notify passthrough clients
	 * etc.etc.
	 */
	pt_noroute(node);

	/*
	 * record new state
	 */
	node->state = wrsm_node_needroute;
}


/*
 * about to change routes in the hardware
 */
static void
nr_reroute_start(wrsm_network_t *network)
{
	ASSERT(network);
	ASSERT(network->reroutingp);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "nr_reroute_start()\n"));

	/*
	 * update local routechange counter
	 */
	mutex_enter(&network->lock);
	(*network->reroutingp)++;
	mutex_exit(&network->lock);

	/*
	 * notify remote nodes using passthrough through this node of
	 * changing routes
	 */
	if (network->passthrough_routes) {
		pt_newptinfo(network, pt_reroute_start, NULL);
	}
}


/*
 * finished changing routes in the hardware
 */
static void
nr_reroute_finish(wrsm_network_t *network)
{
	ASSERT(network);
	ASSERT(network->route_counterp);
	ASSERT(network->reroutingp);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "nr_reroute_finish()\n"));
	mutex_enter(&network->lock);
	(*network->route_counterp)++;
	(*network->reroutingp)--;
	mutex_exit(&network->lock);

	/*
	 * notify remote nodes using passthrough through this node of
	 * changing routes
	 */
	if (network->passthrough_routes) {
		pt_newptinfo(network, pt_reroute_finish, NULL);
	}
}

/*
 * This routine is called from wrsm_lc_check_lockout() when it notices
 * that wci_ra_esr.acc_write_lockout is set.  This means that the
 * remote node that exports 'ncslice' has its write-lockout bit set
 * corresponding to our cnodeid.  We have to clear it by doing a read
 * from page 1 of that slice (for all stripes) and make sure that all
 * currently open barriers fail since this indicates that an
 * undetected write error could have occured.
 */
/* ARGSUSED */
void
wrsm_nr_clear_lockout(wrsm_ncwci_t *wci, ncslice_t ncslice)
{
	int i, j;
	wrsm_network_t *network = wci->network;
	wrsm_node_t *node;
	volatile caddr_t lockout_vaddr;
	wrsm_raw_message_t raw_buf;
	uint64_t *buf = (uint64_t *)&raw_buf;
	uint64_t stripes;

	ASSERT(wci);
	ASSERT(wci->network);
	network = wci->network;

	kpreempt_disable();
	nr_reroute_start(network);
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (!node)
			continue;
		/*
		 * Search the list of ncslices exported by the cnode,
		 * to see if the cnode exports the failed ncslice.
		 */
		for (j = 0; j < WRSM_NODE_NCSLICES; j++) {
			if (ncslice == node->config->exported_ncslices.id[j])
				break;
		}

		/* If this cnode doesn't export the ncslice, continue */
		if (j == WRSM_NODE_NCSLICES)
			continue;

		/* If haven't yet established a route to node, don't bother */
		if (node->state != wrsm_node_haveroute) {
			continue;
		}
		lockout_vaddr = node->lockout_vaddr;

		DPRINTF(DBG_WARN, (CE_CONT,
		    "nr_clear_lockout: clearing node %d vaddr %p stripes=%d",
		    i, (void *)lockout_vaddr, *node->link_stripesp));
		for (stripes = *node->link_stripesp;
		    stripes != 0;
		    stripes = stripes >> 1) {
			if (stripes & 1) {
				/* Do block read from remote page 1 */
				wrsm_blkread(lockout_vaddr, buf, 1);
			}
			/* Advance pointers to next stripe */
			lockout_vaddr += WCI_CLUSTER_STRIPE_STRIDE;
		}
	}
	nr_reroute_finish(network);
	kpreempt_enable();
}

/*
 * Passthrough related route teardown - remove passthrough forwarding
 * to this node, and notify other nodes of this loss of capability.
 */
static void
pt_noroute(wrsm_node_t *node)
{
	int i;
	wrsm_network_t *network;

	ASSERT(node);
	ASSERT(node->config);
	ASSERT(node->routeinfo);
	ASSERT(node->routeinfo->policy);
	ASSERT(node->network);
	network = node->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "pt_noroute() node %d\n",
	    node->config->cnodeid));

	if (!node->routeinfo->policy->forwarding_allowed)
		return;

	/*
	 * stop waiting for this node to finish rerouting
	 */
	mutex_enter(&network->nr->lock);
	if (node->routeinfo->pt_rerouting) {
		node->routeinfo->pt_rerouting = B_FALSE;
		mutex_exit(&network->nr->lock);
		mutex_enter(&network->lock);
		(*network->route_counterp)++;
		(*network->reroutingp)--;
		mutex_exit(&network->lock);
	} else {
		mutex_exit(&network->nr->lock);
	}

	/*
	 * Reroute cnodes that might be using this node as a switch.
	 * (At some point, we might want to keep better track of which
	 * nodes really _are_ using a passthrough route through this node,
	 * to avoid unnecessary route re-evaluations.)
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (WRSM_IN_SET(node->routeinfo->pt_provided, i)) {
			if (!network->nodes[i] || (i == network->cnodeid)) {
				continue;
			}

			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
			    "ctlr %d pt_noroute "
			    "node %d check_route\n",
			    network->rsm_ctlr_id, i));
			network->nodes[i]->routeinfo->check_route = B_TRUE;
		}
	}

	/*
	 * The remote node can't be offering passthrough to anyone if
	 * there's no route!  Zero out pt_provided list, and decrement
	 * pt_route_counter to be sure the next time we communicate with
	 * the remote node, we get an updated passthrough list.
	 */
	node->routeinfo->pt_route_counter--;
	WRSMSET_ZERO(node->routeinfo->pt_provided);

	mutex_enter(&network->nr->lock);
	if (!WRSM_IN_SET(network->nr->pt_provided, node->config->cnodeid)) {
		/*
		 * Don't provide passthrough to this node, so skip rest
		 * of this function.
		 */
		mutex_exit(&network->nr->lock);
		return;
	}

	/*
	 * Update pt_provided list, and immediately notify other nodes of
	 * loss of passthrough access to this node.
	 */

	WRSMSET_DEL(network->nr->pt_provided, node->config->cnodeid);
	network->nr->pt_route_counter++;
	mutex_exit(&network->nr->lock);

	pt_newptinfo(network, pt_route_counter, NULL);


	/*
	 * remove passthrough capability to this node
	 */
	for (i = 0; i < WRSM_MAX_NCSLICES; i++) {
		if (WRSM_IN_SET(node->routeinfo->policy->forwarding_ncslices,
		    i)) {
			/*
			 * Note:  no lock is needed because passthrough
			 * operations are single threaded (handled by nr
			 * event thread, and only passthrough ncslices are
			 * managed by nr event thread.
			 */
			network->wrsm_ncslice_users[i]--;
			if (network->wrsm_ncslice_users[i] == 0) {
				wrsm_ncsliceconfig_set(network, i,
				    ncslice_invalid);
			}
			network->passthrough_routes--;
		}
	}

	/*
	 * It shouldn't be necessary to wait for CAG busy bits to clear on
	 * all wcis to guarantee that they are no longer using this
	 * passthrough route.  Turning off passthrough in the wci should
	 * just cause CAGs to timeout or return errors.
	 */
}


/*
 * Passthrough related route setup after a node becomes newly accessible:
 * turn on passthrough forwarding to this node if it is allowed, and notify
 * other nodes of this capability.
 *
 * Return whether passthrough notification is needed.
 */
static boolean_t
pt_haveroute(wrsm_node_t *node)
{
	int i;
	wrsm_network_t *network;

	ASSERT(node);
	ASSERT(node->config);
	network = node->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "pt_haveroute() node %d\n",
	    node->config->cnodeid));

	if (!WRSM_NODE_HAVE_ROUTE(node))
		return (B_FALSE);

	ASSERT(node->routeinfo);
	ASSERT(node->routeinfo->policy);

	if (!node->routeinfo->policy->forwarding_allowed) {
		ASSERT(network);
		if (node->config->cnodeid != network->cnodeid) {
			/*
			 * let the remote node know about passthrough
			 * routes the local node currently supplies
			 */
			pt_newptinfo(network, pt_route_counter, node);
		}
		return (B_FALSE);
	}

	DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: node %d passthrough allowed\n",
	    network->rsm_ctlr_id, node->config->cnodeid));

	/*
	 * add passthrough capability for this node
	 */
	for (i = 0; i < WRSM_MAX_NCSLICES; i++) {
		if (WRSM_IN_SET(node->routeinfo->policy->forwarding_ncslices,
		    i)) {
			/*
			 * Note:  no lock is needed because passthrough
			 * operations are single threaded (handled by nr
			 * event thread, and only passthrough ncslices are
			 * managed by nr event thread.
			 */
			if (network->wrsm_ncslice_users[i] == 0) {
				wrsm_ncsliceconfig_set(network, i,
				    ncslice_passthrough);
#ifdef DEBUG
			} else {
				ASSERT(wrsm_ncsliceconfig_get(network, i) ==
				    ncslice_passthrough);
#endif
			}
			network->wrsm_ncslice_users[i]++;
			network->passthrough_routes++;
		}
	}


	/*
	 * update pt_provided list
	 */
	mutex_enter(&network->nr->lock);
	WRSMSET_ADD(network->nr->pt_provided, node->config->cnodeid);
	network->nr->pt_route_counter++;
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "pt_provided now = %d\n",
	    network->nr->pt_route_counter));
	mutex_exit(&network->nr->lock);

	/*
	 * request notification of new passthrough routes
	 */
	return (B_TRUE);
}


/*
 * Timeout to send pt_counter to any node that hasn't yet received
 * it.
 */
static void
pt_resend_timeout(void *arg)
{
	wrsm_network_t *network;
	wrsm_nr_t *nr;
	wrsm_nr_event_t *event;

	ASSERT(arg);
	network = (wrsm_network_t *)arg;
	ASSERT(network->nr);
	nr = network->nr;

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);

	mutex_enter(&nr->lock);
	if (network->availability != wrsm_enabled) {
		mutex_exit(&nr->lock);
		kmem_free(event, sizeof (wrsm_nr_event_t));
		return;
	}
	WRSMSET_COPY(nr->pt_retrylist, event->data.send_ptlist.list);
	WRSMSET_ZERO(nr->pt_retrylist);
	nr->pt_retry_timeout_id = 0;
	mutex_exit(&nr->lock);

	event->type = wrsm_evt_send_ptlist;
	wrsm_nr_add_event(network, event, B_TRUE);
}


/*
 * pt_sendptlist to this node failed; schedule a retry
 */
static void
pt_retry(wrsm_node_t *node)
{
	wrsm_network_t *network;
	wrsm_nr_t *nr;

	ASSERT(node);
	ASSERT(node->network);
	ASSERT(node->network->nr);
	network = node->network;
	nr = node->network->nr;

	mutex_enter(&nr->lock);

	if ((node->network->availability != wrsm_enabled) &&
	    (node->network->availability != wrsm_installed)) {
		mutex_exit(&nr->lock);
		return;
	}

	WRSMSET_ADD(nr->pt_retrylist, node->config->cnodeid);
	if (nr->pt_retry_timeout_id == 0) {
		/* set up timeout */
		if (network->nr->suspended) {
			nr->need_pt_retry_timeout = B_TRUE;
		} else {
			nr->pt_retry_timeout_id = timeout(pt_resend_timeout,
			    (void *)network, (clock_t)WRSM_PTRETRY_TIMEOUT);
		}
	}

	mutex_exit(&nr->lock);
}



/*
 * Send current set of nodes this node provides passthrough access to
 * to each other remote node (or to one specified node)
 */
static void
pt_newptinfo(wrsm_network_t *network, pt_msgtype_t msgtype,
    wrsm_node_t *to_node)
{
	int i;
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *msg = (wrsm_message_t *)&msgbuf;
	wrsm_ptlist_msg_t args;
	wrsm_node_t *node;

	ASSERT(network);
	ASSERT(network->nr);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "pt_newptinfo() %s\n",
	    PT_MSGSTRING(msgtype)));

	/*
	 * send message to all remote nodes (or the specified node)
	 * notifying them of available PT route
	 */
	bzero(&args, sizeof (wrsm_ptlist_msg_t));

	/*
	 * set up message
	 */
	msg->header.message_type = WRSM_MSG_CONFIG_PASSTHROUGH_LIST;

	/*
	 * take lock to guarantee local pt_provided and pt_route_counter
	 * match when pt_ptlist_recv_hdlr copies info out
	 */
	mutex_enter(&network->nr->lock);
	WRSMSET_COPY(network->nr->pt_provided, args.pt_provided);
	args.pt_route_counter = network->nr->pt_route_counter;
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "ctlr %d: sending pt msg with pt_route_counter = %d\n",
	    network->rsm_ctlr_id, network->nr->pt_route_counter));
	mutex_exit(&network->nr->lock);
	args.pt_msgtype = msgtype;
	bcopy(&args, &(msg->body), sizeof (args));

	if (to_node) {
		ASSERT(WRSM_NODE_HAVE_ROUTE(to_node));
		if (pt_sendptlist(to_node, msg) == B_FALSE) {
			/*
			 * queue up an event to retry sending this message
			 */
			pt_retry(to_node);
		}
	} else for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (!node || (i == network->cnodeid) ||
		    !WRSM_NODE_HAVE_ROUTE(node)) {
			continue;
		}

		if (pt_sendptlist(node, msg) == B_FALSE) {
			/*
			 * queue up an event retry sending this message
			 */
			pt_retry(node);
		}
	}
}


/*
 * send PTLIST message to specified node; receive and handle reply
 * message
 */
static int
pt_sendptlist(wrsm_node_t *node, wrsm_message_t *msg)
{
	wrsm_raw_message_t recvmsgbuf;
	wrsm_message_t *recvmsg = (wrsm_message_t *)&recvmsgbuf;
	wrsm_network_t *network;
	wrsm_ptlist_msg_t recvargs;
	wrsm_nr_event_t *event;

	ASSERT(node);
	ASSERT(node->config);
	ASSERT(node->network);
	network = node->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: pt_sendptlist() "
	    "node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	ASSERT(WRSM_NODE_HAVE_ROUTE(node));

#ifdef DEBUG
	if (wrsm_nr_debug & DBG_ROUTE_EXTRA)
		wrsm_tl_dump_message("pt_sendptlist sends ", msg);
#endif

	if (wrsm_tl_rpc(network, node->config->cnodeid, msg,
	    recvmsg) != WRSM_SUCCESS) {
		/*
		 * This node is not responding (message not delivered or
		 * response not received).  (Transport Layer tears down the
		 * session if there is a message delivery failure).
		 *
		 * stop waiting for this node to finish rerouting
		 */
		mutex_enter(&network->nr->lock);
		if (node->routeinfo->pt_rerouting) {
			node->routeinfo->pt_rerouting = B_FALSE;
			mutex_exit(&network->nr->lock);
			mutex_enter(&network->lock);
			(*network->route_counterp)++;
			(*network->reroutingp)--;
			mutex_exit(&network->lock);
		} else {
			mutex_exit(&network->nr->lock);
		}
		return (B_FALSE);
	}

#ifdef DEBUG
	if (wrsm_nr_debug & DBG_ROUTE_EXTRA)
		wrsm_tl_dump_message("pt_sendptlist response: ", recvmsg);
#endif
	ASSERT(recvmsg->header.message_type ==
	    WRSM_MSG_CONFIG_PASSTHROUGH_LIST_RESPONSE);

	bcopy(&(recvmsg->body), &recvargs, sizeof (recvargs));

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: pt_sendptlist() "
	    "node %d response message %s route_counter %d\n",
	    network->rsm_ctlr_id, node->config->cnodeid,
	    PT_MSGSTRING(recvargs.pt_msgtype),
	    recvargs.pt_route_counter));
	/*
	 * queue up passthrough event to event handler
	 * to record new passthrough info from this node.
	 */
	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_recv_ptlist;
	event->data.recv_ptlist.cnodeid = node->config->cnodeid;
	WRSMSET_COPY(recvargs.pt_provided,
	    event->data.recv_ptlist.pt_provided);
	event->data.recv_ptlist.pt_route_counter =
	    recvargs.pt_route_counter;
	wrsm_nr_add_event(network, event, B_TRUE);

	return (B_TRUE);
}



/*
 * Handler for the PTLIST message: save new passthrough information
 * from sending node, and reply with passthrough information from this
 * node (what nodes this node provides passthrough access to).
 *
 * The transport layer won't call a handler to deliver a message from
 * a node unless the transport layer knows that node exists.  The transport
 * layer is notified when a node is removed by NC, before it removes the
 * node pointer in network->nodes.  So it's safe to use that pointer in
 * the handler.
 */
static boolean_t
pt_ptlist_recv_hdlr(wrsm_network_t *network, wrsm_message_t *msg)
{
	wrsm_ptlist_msg_t args;
	cnodeid_t cnodeid = msg->header.source_cnode;
	wrsm_node_t *node;
	wrsm_ptlist_msg_t respargs;
	wrsm_raw_message_t msgbuf;
	wrsm_message_t *respmsg = (wrsm_message_t *)&msgbuf;
	wrsm_nr_event_t *event;

	ASSERT(network);

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: pt_recv_hdlr()\n",
	    network->rsm_ctlr_id));

#ifdef DEBUG
	if (wrsm_nr_debug & DBG_ROUTE_EXTRA)
		wrsm_tl_dump_message("pt_ptlist_recv_hdlr: ", msg);
#endif

	if (cnodeid > WRSM_MAX_CNODES) {
		/*
		 * ignore message! can't send a response to a non-existent
		 * node
		 */
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d no node %d\n",
		    network->rsm_ctlr_id, cnodeid));
		return (B_FALSE);
	}
	node = network->nodes[cnodeid];

	bcopy(&(msg->body), &args, sizeof (args));

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: pt_recv_hdlr() "
	    "node %d message %s route_counter %d\n",
	    network->rsm_ctlr_id, cnodeid,
	    PT_MSGSTRING(args.pt_msgtype),
	    args.pt_route_counter));

	/*
	 * handle passthrough reroute start message
	 */
	if (args.pt_msgtype == pt_reroute_start) {
		mutex_enter(&network->nr->lock);
		if (!node->routeinfo) {
			mutex_exit(&network->nr->lock);
		} else if (!node->routeinfo->pt_rerouting) {
			node->routeinfo->pt_rerouting = B_TRUE;
			mutex_exit(&network->nr->lock);
			mutex_enter(&network->lock);
			(*network->reroutingp)++;
			mutex_exit(&network->lock);
		} else {
			mutex_exit(&network->nr->lock);
		}
	}


	/*
	 * handle passthrough reroute finish message
	 */
	if (args.pt_msgtype == pt_reroute_finish) {
		mutex_enter(&network->nr->lock);
		if (!node->routeinfo) {
			mutex_exit(&network->nr->lock);
		} else if (node->routeinfo->pt_rerouting) {
			node->routeinfo->pt_rerouting = B_FALSE;
			mutex_exit(&network->nr->lock);
			mutex_enter(&network->lock);
			(*network->route_counterp)++;
			(*network->reroutingp)--;
			mutex_exit(&network->lock);
		} else {
			mutex_exit(&network->nr->lock);
		}
	}

	/*
	 * queue up passthrough event to event handler with latest
	 * passthrough info from this node
	 */

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_recv_ptlist;
	event->data.recv_ptlist.cnodeid = cnodeid;
	WRSMSET_COPY(args.pt_provided, event->data.recv_ptlist.pt_provided);
	event->data.recv_ptlist.pt_route_counter = args.pt_route_counter;
	wrsm_nr_add_event(network, event, B_TRUE);

	/*
	 * Always send a response message regardless of the pt_msgtype.
	 */
	respmsg->header.message_type =
	    WRSM_MSG_CONFIG_PASSTHROUGH_LIST_RESPONSE;

	/*
	 * take lock to guarantee local pt_provided and pt_route_counter
	 * match
	 */
	bzero(&respargs, sizeof (wrsm_ptlist_msg_t));
	mutex_enter(&network->nr->lock);
	WRSMSET_COPY(network->nr->pt_provided, respargs.pt_provided);
	respargs.pt_route_counter = network->nr->pt_route_counter;
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "ctlr %d: sending pt msg with pt_route_counter = %d\n",
	    network->rsm_ctlr_id, network->nr->pt_route_counter));
	mutex_exit(&network->nr->lock);
	bcopy(&respargs, &(respmsg->body), sizeof (respargs));

#ifdef DEBUG
	if (wrsm_nr_debug & DBG_ROUTE_EXTRA)
		wrsm_tl_dump_message("pt_recv_hdlr responds with", respmsg);
#endif
	if (wrsm_tl_rsp(network, msg, respmsg) != WRSM_SUCCESS) {
		/*
		 * This node is not responding.  (Transport Layer tears
		 * down the session if there is a message delivery
		 * failure).
		 *
		 * stop waiting for this node to finish rerouting
		 */
		mutex_enter(&network->nr->lock);
		if (!node->routeinfo) {
			mutex_exit(&network->nr->lock);
		} else if (node->routeinfo->pt_rerouting) {
			node->routeinfo->pt_rerouting = B_FALSE;
			mutex_exit(&network->nr->lock);
			mutex_enter(&network->lock);
			(*network->route_counterp)++;
			(*network->reroutingp)--;
			mutex_exit(&network->lock);
		} else {
			mutex_exit(&network->nr->lock);
		}
		/* other side will resend, so don't call pt_retry() here. */
	} else {
		mutex_enter(&network->nr->lock);
		WRSMSET_DEL(network->nr->pt_retrylist, cnodeid);
		mutex_exit(&network->nr->lock);
	}

	return (B_TRUE);
}


/*
 * Update the passthrough routing info for the specified node, and
 * cause affected cnodes to re-evaluate their current routes.
 */
static void
pt_route_update(wrsm_node_t *node, cnode_bitmask_t pt_provided,
    int route_counter)
{
	int i;
	wrsm_network_t *network = node->network;

	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: pt_route_update() "
	    "from node %d\n", network->rsm_ctlr_id, node->config->cnodeid));

	if (!node->routeinfo || node->availability == wrsm_disabled) {
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT, "ctlr %d: pt_route_update - "
		    "no routinfo or disabled node %d\n",
		    network->rsm_ctlr_id, node->config->cnodeid));
		/* this node is going away; ignore update message */
		return;
	}


	if (node->routeinfo->pt_route_counter == route_counter) {
		/*
		 * list of passthrough nodes hasn't changed
		 */
		DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
		    "pt_route_counter unchanged\n"));
#ifdef DEBUG
		if (!WRSMSET_ISEQUAL(node->routeinfo->pt_provided,
		    pt_provided))
			DPRINTF(DBG_WARN, (CE_WARN,
			    "pt_provided bitmasks don't match\n"));
#endif

		return;
	}

	/*
	 * Received new list of nodes this node provides passthrough
	 * access to.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		/*
		 * only re-evaluate routes for nodes interested in using
		 * this node as a switch
		 */
		if (!WRSM_IN_SET(node->routeinfo->pt_interested, i))
			continue;

		if (WRSM_IN_SET(node->routeinfo->pt_provided, i) !=
		    WRSM_IN_SET(pt_provided, i)) {
			/*
			 * Passthrough access to this node has changed;
			 * cause route re-evalauation.
			 */
			if (!network->nodes[i])
				continue;

			DPRINTF(DBG_ROUTE_EXTRA, (CE_NOTE,
			    "ctlr %d pt_route_update "
			    "node %d check_route\n",
			    network->rsm_ctlr_id, i));
			network->nodes[i]->routeinfo->check_route = B_TRUE;
#ifdef DEBUG
			if (WRSM_IN_SET(pt_provided, i)) {
				DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: "
				    "gained access "
				    "through node %d to node %d\n",
				    network->rsm_ctlr_id,
				    node->config->cnodeid, i));
			} else {
				DPRINTF(DBG_ROUTE, (CE_CONT, "ctlr %d: "
				    "lost access through node %d to node %d\n",
				    network->rsm_ctlr_id,
				    node->config->cnodeid, i));
			}
#endif
		}
	}

	WRSMSET_COPY(pt_provided, node->routeinfo->pt_provided);
	node->routeinfo->pt_route_counter = route_counter;
#ifdef DEBUG
	DPRINTF(DBG_ROUTE_EXTRA, (CE_CONT,
	    "ctlr %d: node %d pt_provided - \n",
	    network->rsm_ctlr_id, node->config->cnodeid));

	if (wrsm_nr_debug & DBG_ROUTE_EXTRA)
		DPRINTNODES(node->routeinfo->pt_provided);
#endif

}



/*
 * translate from safari port id to wci structure
 */
static wrsm_ncwci_t *
nr_safid_to_wci(wrsm_network_t *network, safari_port_t id)
{
	wrsm_ncwci_t *wci;

	ASSERT(network);
	ASSERT(network->nr);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "nr_safid_to_wci()\n"));

	for (wci = network->nr->wcis; wci != NULL; wci = wci->next) {
		ASSERT(wci->config);
		if (wci->config->port == id)
			return (wci);
	}

	DPRINTF(DBG_WARN, (CE_WARN,
	    "safid_to_wci - no wci with id %d!\n", id));
	return (NULL);
}


/*
 * translate from stripe group id to stripe group structure
 */
static wrsm_nc_strgrp_t *
nr_sgid_to_sg(wrsm_network_t *network, uint32_t sgid)
{
	wrsm_nc_strgrp_t *sg;

	ASSERT(network);
	ASSERT(network->nr);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "nr_sgid_to_sg()\n"));

	for (sg = network->nr->sgs; sg != NULL; sg = sg->next) {
		ASSERT(sg);
		ASSERT(sg->config);
		if (sg->config->group_id == sgid)
			return (sg);
	}

	DPRINTF(DBG_WARN, (CE_WARN,
	    "sgid_to_sg - no sg with id %d!\n", sgid));
	return (NULL);
}


/*
 * add_wrsm_route_kstat
 */
static void
add_wrsm_route_kstat(wrsm_node_t *node)
{
	kstat_t *rte_ksp;
	wrsm_route_kstat_t *rte_named;
	int i, j;
	char tmp_str[30];

	ASSERT(node);
	ASSERT(node->network);
	ASSERT(node->config);

	rte_ksp = kstat_create(WRSM_KSTAT_WRSM_ROUTE,
		node->network->rsm_ctlr_id,
		node->config->hostname,
		"net",
		KSTAT_TYPE_NAMED,
		sizeof (wrsm_route_kstat_t) / sizeof (kstat_named_t),
		0);

	if (rte_ksp == NULL) {
		cmn_err(CE_WARN,
		    "rsm ctlr %d to host %s: routes kstat_create failed",
		    node->network->rsm_ctlr_id, node->config->hostname);
		node->routeinfo->wrsm_route_ksp = NULL;
		return;
	}

	rte_named = (wrsm_route_kstat_t *)(rte_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&rte_named->version,
		WRSMKS_CONFIG_VERSION_NAMED, KSTAT_DATA_UINT64);

	kstat_named_init(&rte_named->type,
		WRSMKS_ROUTE_TYPE_NAMED, KSTAT_DATA_UINT32);

	kstat_named_init(&rte_named->num_wcis,
		WRSMKS_NUM_WCIS, KSTAT_DATA_UINT32);

	kstat_named_init(&rte_named->num_stripes,
		WRSMKS_NUM_STRIPES, KSTAT_DATA_UINT32);

	kstat_named_init(&rte_named->num_changes,
		WRSMKS_NUMCHANGES, KSTAT_DATA_UINT32);

	kstat_named_init(&rte_named->cnodeid,
		WRSMKS_CNODEID, KSTAT_DATA_UINT32);

	kstat_named_init(&rte_named->fmnodeid,
		WRSMKS_FMNODEID, KSTAT_DATA_UINT32);

	for (i = 0; i < WRSM_MAX_WCIS_PER_STRIPE; i++) {
		(void) sprintf(tmp_str, WRSMKS_ROUTE_PORTID, i);

		kstat_named_init(&rte_named->portid[i],
			tmp_str, KSTAT_DATA_UINT32);

		(void) sprintf(tmp_str, WRSMKS_ROUTE_INSTANCE, i);

		kstat_named_init(&rte_named->instance[i],
			tmp_str, KSTAT_DATA_UINT32);

		(void) sprintf(tmp_str, WRSMKS_ROUTE_NUMHOPS, i);
		kstat_named_init(&rte_named->numhops[i],
			tmp_str, KSTAT_DATA_UINT32);

		(void) sprintf(tmp_str, WRSMKS_ROUTE_NUMLINKS, i);
		kstat_named_init(&rte_named->numlinks[i],
			tmp_str, KSTAT_DATA_UINT32);

		for (j = 0; j < WRSM_MAX_DNIDS; j++) {
			(void) sprintf(tmp_str, WRSMKS_ROUTE_LINKID, i, j);
			kstat_named_init(&rte_named->linkid[i][j],
				tmp_str, KSTAT_DATA_UINT32);

			(void) sprintf(tmp_str, WRSMKS_ROUTE_NODEID, i, j);
			kstat_named_init(&rte_named->nodeid[i][j],
				tmp_str, KSTAT_DATA_UINT32);

			(void) sprintf(tmp_str, WRSMKS_ROUTE_GNID, i, j);
			kstat_named_init(&rte_named->gnid[i][j],
				tmp_str, KSTAT_DATA_UINT32);
		}
	}

	/* save the kstat pointer in the routeinfo struct */
	node->routeinfo->wrsm_route_ksp = rte_ksp;

	rte_ksp->ks_update = update_wrsm_route_kstat;
	rte_ksp->ks_private = (void *)node;
	kstat_install(rte_ksp);
}

static void
del_wrsm_route_kstat(wrsm_node_t *node)
{
	ASSERT(node);
	ASSERT(node->routeinfo);
	/*
	 * The kstat framework guarantees that any outstanding
	 * calls to the update function will be completed before
	 * the kstat can be deleted.
	 */
	if (node->routeinfo->wrsm_route_ksp) {
		kstat_delete(node->routeinfo->wrsm_route_ksp);
	}
}

/*
 * update the route kstat
 */
static int
update_wrsm_route_kstat(kstat_t *ksp, int rw)
{
	wrsm_route_kstat_t *rte_named;
	wrsm_node_t *node;
#ifdef DEBUG
	char *fm_node_name;
#endif
	ncslice_route_t cur_rte;
	inidwnode_route_t wroute;
	int wnodeid;
	int link;
	int i, j;

	DPRINTF(DBG_RT_KSTAT, (CE_CONT, "in update_wrsm_route_kstat"));

	/* This is a read=only kstat */
	if (rw == KSTAT_WRITE) {
		/* Writing is not allowed - log the error */
		DPRINTF(DBG_RT_KSTAT, (CE_CONT, "route_kstat is read-only"));
		return (EACCES);
	}

	ASSERT(ksp);

	/* Get the kstat structure */
	rte_named = (wrsm_route_kstat_t *)ksp->ks_data;

	/* Get node structure from private part of kstat */
	node = (wrsm_node_t *)ksp->ks_private;

	/* always initialize to 0 then count number of links for each wci */
	rte_named->num_stripes.value.ui32 = 0;

	/*
	 * Initialize the following values to 0, so that there will not be
	 * bogus values when there is no route
	 */
	rte_named->num_wcis.value.ui32 = 0;
	for (i = 0; i < WRSM_MAX_WCIS_PER_STRIPE; i++) {
		rte_named->portid[i].value.ui32 = 0;
		rte_named->instance[i].value.ui32 = 0;
		rte_named->numhops[i].value.ui32 = 0;
		rte_named->numlinks[i].value.ui32 = 0;
		for (j = 0; j < WRSM_MAX_DNIDS; j++) {
			rte_named->linkid[i][j].value.ui32 = 0;
			rte_named->nodeid[i][j].value.ui32 = 0;
			rte_named->gnid[i][j].value.ui32 = 0;
		}
	}

	if (node == NULL) {
		DPRINTF(DBG_RT_KSTAT, (CE_CONT, "kstat: node is NULL"));
		return (0);
	}

#ifdef DEBUG
	/* Get the FM node name */
	fm_node_name = node->config->hostname;
#endif
	DPRINTF(DBG_RT_KSTAT, (CE_CONT, "node name = %s", fm_node_name));
	DPRINTF(DBG_RT_KSTAT, (CE_CONT, "cnodeid   = %d",
	    node->config->cnodeid));

	if (node->availability != wrsm_enabled) {
		DPRINTF(DBG_WARN,
			(CE_CONT, "kstat: node availability not enabled"));
		return (0);
	}

	if (node->state != wrsm_node_haveroute) {
		DPRINTF(DBG_WARN, (CE_CONT, "kstat: no route for node"));
		return (0);
	}

	if (node->routeinfo->route_state != ncslice_use_current) {
		DPRINTF(DBG_WARN,
			(CE_CONT, "kstat: cannot access current route"));
		return (0);
	}

	/* Lock the network router info */
	mutex_enter(&node->network->nr->lock);

	/* Copy the current route info into a local data structure */
	bcopy(&node->routeinfo->current_route,
		&cur_rte, sizeof (ncslice_route_t));

	rte_named->version.value.ui64 = node->network->version_stamp;
	rte_named->num_changes.value.ui32 =
		(uint32_t)node->routeinfo->num_rte_changes;

	/* Unlock the network router info */
	mutex_exit(&node->network->nr->lock);

	DPRINTF(DBG_RT_KSTAT, (CE_CONT, "after mutex_exit"));

	if (cur_rte.proute == NULL) {
		DPRINTF(DBG_WARN, (CE_CONT, "proute is null"));
		/* do something to indicate this state */
		return (0);
	}

	rte_named->type.value.ui32 =
		(uint32_t)cur_rte.proute->method;
	rte_named->num_wcis.value.ui32 =
		(uint32_t)cur_rte.nwcis;
	rte_named->cnodeid.value.ui32 =
		(uint32_t)node->config->cnodeid;
	rte_named->fmnodeid.value.ui32 =
		(uint32_t)node->config->fmnodeid;

	DPRINTF(DBG_RT_KSTAT,
		(CE_CONT, "kstat: getting per wci/stripe info"));

	/* Get the per stripe information */
	for (i = 0; i < cur_rte.nwcis; i++) {

		/* Get the wroute for this stripe */
		wroute = cur_rte.wroutes[i];

		if (wroute.wci == NULL) {
		    DPRINTF(DBG_WARN,
			(CE_CONT, "kstat: NULL wroute.wci encountered"));
		    rte_named->portid[i].value.ui32 = 0;
		    rte_named->instance[i].value.ui32 = 0;
		    rte_named->numhops[i].value.ui32 = 0;
		    rte_named->numlinks[i].value.ui32 = 0;
		    continue;
		}

		rte_named->portid[i].value.ui32 =
			(uint32_t)wroute.wci->config->port;

		rte_named->instance[i].value.ui32 =
			(uint32_t)wrsm_lc_get_instance(wroute.wci->lcwci);

		rte_named->numhops[i].value.ui32 =
			wroute.wci->nr.mh_reachable.nhops[wroute.id];

		/* If nhops==0, set numlinks=0, and forget about links */
		/* This must be the loopback route */
		if (rte_named->numhops[i].value.ui32 == 0) {
			rte_named->numlinks[i].value.ui32 = 0;
			continue;
		}

		rte_named->numlinks[i].value.ui32 =
			wroute.wci->nr.mh_reachable.stripes[wroute.id];

		/*
		 * Depending on the route type, the link and node
		 * information are found in different data structures.
		 */

		if (wroute.route_type == nid_route_inid) {

		    DPRINTF(DBG_RT_KSTAT, (CE_CONT,
				"nid_route_inid, stripe=%d", i));
		    DPRINTF(DBG_RT_KSTAT, (CE_CONT,
				"wroute.id = %d\n", wroute.id));

		    for (j = 0; j < WRSM_MAX_DNIDS; j++) {

			/*
			 * Go through the inid2dnid table.
			 * The inid2dnid entry is the wnodeid.
			 */
			wnodeid =
			    wroute.wci->nr.inid2dnid[wroute.id].wnode_list[j];

			DPRINTF(DBG_RT_KSTAT, (CE_CONT, "i=%d, wnodeid=%d",
			    j, wnodeid));
			/*
			 * Use wnodeid to look up the link.
			 */
			link = wrsm_mh_wnode_to_link(wroute.wci, wnodeid);

			rte_named->linkid[i][j].value.ui32 = link;

			/*
			 * Use the wnodeid to look up the node id.
			 */
			if (wroute.wci->nr.wnodeinfo[wnodeid].valid) {
				rte_named->nodeid[i][j].value.ui32 =
				    wroute.wci->nr.wnodeinfo[wnodeid].cnodeid;
				rte_named->num_stripes.value.ui32++;
				DPRINTF(DBG_RT_KSTAT, (CE_CONT, "kstat: "
				    "current stripe total for passthrough %d",
				    rte_named->num_stripes.value.ui32));
			} else {
				rte_named->nodeid[i][j].value.ui32 = -1;
			}

			rte_named->gnid[i][j].value.ui32 =
			    wroute.wci->config->links[link].remote_gnid;

		    }

		} else { /* nid_route_wnode */
		    /* There will be one or two links from this wci */

		    /* The wroute.id is the wnodeid. */
		    wnodeid = wroute.id;
		    DPRINTF(DBG_RT_KSTAT,
			    (CE_CONT, "nid_route_wnode, wnodeid=%d", wnodeid));

		    /* look at links to see which ones lead to wnode */
		    j = 0;
		    for (link = 0; link < WRSM_LINKS_PER_WCI; link++) {

			if (wrsm_mh_link_to_wnode(wroute.wci, link,
			    wnodeid)) {

				rte_named->linkid[i][j].value.ui32 =
				    link;
				rte_named->num_stripes.value.ui32++;
				DPRINTF(DBG_RT_KSTAT, (CE_CONT, "kstat: "
				    "current stripe total for multihop %d",
				    rte_named->num_stripes.value.ui32));

				/* Use the wnodeid to look up the node id. */
				rte_named->nodeid[i][j].value.ui32 =
				    wroute.wci->nr.wnodeinfo[wnodeid].cnodeid;

				rte_named->gnid[i][j].value.ui32 =
				    wroute.wci->config->links[link].
				    remote_gnid;
				j++;
			}
		    }
		}
	}
	return (0);
}

void
wrsm_get_wci_num(wrsm_network_t *network, uint_t *num_wcis, uint_t *avail_wcis)
{
	wrsm_ncwci_t *wci;
	*num_wcis = *avail_wcis = 0;

	ASSERT(network);
	ASSERT(network->nr);

	mutex_enter(&network->nr->lock);
	wci = network->nr->wcis;

	/* loop over the wcis and determine which one are available */
	while (wci != NULL) {
		(*num_wcis)++;
		if (wci->lcwci != NULL) (*avail_wcis)++;
		wci = wci->next;
	}
	mutex_exit(&network->nr->lock);

}


/*
 * Pause threads and cancel timeouts in NR.
 * Disable all incoming traffic.
 */
int
wrsm_nr_suspend(wrsm_network_t *network)
{
	timeout_id_t cancel_reroute = 0;
	timeout_id_t cancel_pt_retry = 0;

	if (!network->nr) {
		return (DDI_SUCCESS);
	}

	if (network->nr->suspended) {
		return (DDI_FAILURE);
	}

	/*
	 * Pause event thread first.  This guarantees that it
	 * doesn't re-enable the wcis.
	 */
	nr_pause_event_thread(network);

	mutex_enter(&network->nr->lock);

	if (network->nr->suspended) {
		mutex_exit(&network->nr->lock);
		nr_unpause_event_thread(network);
		return (DDI_FAILURE);

	}

	stop_ncslice_traffic(network, B_TRUE);
	network->nr->suspended = B_TRUE;

	/*
	 * cancel any pending timeout to reconfig wcis
	 */
	if (network->nr->wcireroute_timeout_id) {
		cancel_reroute = network->nr->wcireroute_timeout_id;
		network->nr->wcireroute_timeout_id = 0;
		network->nr->need_wcireroute_timeout = B_TRUE;
	}

	/*
	 * Cancel any pending timeout to resend passthrough messages
	 */
	if (network->nr->pt_retry_timeout_id) {
		/*
		 * cancels timeout or waits until it is finished
		 */
		cancel_pt_retry = network->nr->pt_retry_timeout_id;
		network->nr->pt_retry_timeout_id = 0;
		network->nr->need_pt_retry_timeout = B_TRUE;
	}

	mutex_exit(&network->nr->lock);

	if (cancel_reroute) {
		(void) untimeout(cancel_reroute);
	}

	if (cancel_pt_retry) {
		(void) untimeout(cancel_pt_retry);
	}

	return (DDI_SUCCESS);
}

/*
 * Restart threads and timeouts in NR.
 * Re-enable incoming traffic.
 */
int
wrsm_nr_resume(wrsm_network_t *network)
{
	if (!network->nr) {
		return (DDI_SUCCESS);
	}

	mutex_enter(&network->nr->lock);

	if (!network->nr->suspended) {
		mutex_exit(&network->nr->lock);
		return (DDI_FAILURE);
	}

	restart_ncslice_traffic(network, B_TRUE);
	network->nr->suspended = B_FALSE;

	if (network->nr->need_wcireroute_timeout) {
		/*
		 * restart cancelled timeout to force an MH reroute on wcis
		 */
		network->nr->wcireroute_timeout_id = timeout(nr_reroute_wcis,
		    (void *)network, (clock_t)WRSM_ENABLE_TIMEOUT);
		network->nr->need_wcireroute_timeout = B_FALSE;
	}

	if (network->nr->need_pt_retry_timeout) {
		/*
		 * restart cancelled timeout to retry passthrough message
		 */
		network->nr->pt_retry_timeout_id = timeout(pt_resend_timeout,
		    (void *)network, (clock_t)WRSM_PTRETRY_TIMEOUT);
		network->nr->need_pt_retry_timeout = B_FALSE;
	}

	mutex_exit(&network->nr->lock);

	/*
	 * unpause event thread, and verify that it is running again
	 */
	nr_unpause_event_thread(network);
	nr_wait_for_event_drain(network);

	return (DDI_SUCCESS);
}


int
wrsm_nr_session_up(ncwci_handle_t ncwci, wnodeid_t wnid)
{
	wrsm_sessionid_t session_id;
	wrsm_ncwci_t *wci = (wrsm_ncwci_t *)ncwci;

	session_id = wrsm_sess_get(wci->network,
	    wci->nr.wnodeinfo[wnid].cnodeid);
	return (session_id != SESS_ID_INVALID);
}
