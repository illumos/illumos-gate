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
 * This file manages controllers (networks). It coordinate the network
 * routing, session and transport modules.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/tnf_probe.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/mutex.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/sunddi.h>

#include <sys/wrsm_config.h>
#include <sys/wrsm_cf.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_lc.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_nc_impl.h>
#include <sys/wrsm_plugin.h>

#include <sys/wci_common.h>
#include <sys/rsm/rsmpi_driver.h>
#include <sys/wrsm_rsmpi.h>


#ifdef DEBUG
#define	DBG_CONFIG		0x001
#define	DBG_WARN		0x002
#define	DBG_CONFIG_EXTRA	0x010

uint_t wrsm_nc_debug = DBG_WARN;
#define	DPRINTF(a, b) { if (wrsm_nc_debug & a) wrsmdprintf b; }

#else
#define	DPRINTF(a, b) { }
#endif

static wrsm_network_t *wrsm_networks = NULL;
static kmutex_t wrsm_networks_lock;


static wrsm_network_t *rsmctlr_to_network(uint32_t rsm_ctlr_id);
static int new_network(uint32_t rsm_ctlr_id, wrsm_network_t **networkp);
static void remove_network(wrsm_network_t *network);


static void remove_wrsm_node(wrsm_node_t *node);
static int new_wrsm_node(wrsm_network_t *network, wrsm_net_member_t *member,
    wrsm_node_t **nodep);

static int nc_enableconfig(wrsm_network_t *network, int reroute_cnt,
    wci_ids_t *reconfig_wcis);

static void add_wrsm_ctlr_kstat(wrsm_network_t *network);
static void del_wrsm_ctlr_kstat(wrsm_network_t *network);
static int ctlr_kstat_update(kstat_t *ksp, int rw);


/*
 * The configuration functions (nc_replaceconfig(), nc_cleanconfig(),
 * nc_installconfig(), nc_enableconfig(), nc_initialconfig(),
 * nc_removeconfig()) and the newwci() and removewci() functions are all
 * guaranteed by the config layer to be single threaded.  The config layer
 * is the only consumer of these functions, and it will never call a second
 * function before the first is complete.  The config layer also only
 * calls each function in the apprpropriate order, but the functions
 * still do a quick check to be sure the NC concept of this controller's
 * state is appropriate.
 */

/*
 * set up driver communication path to new node
 */
static int
config_new_node(wrsm_node_t *node)
{
	cnodeid_t cnodeid = node->config->cnodeid;
	wrsm_network_t *network = node->network;
	int i;
	int err;
	ncslice_t id;

	ASSERT(network->nodes[cnodeid] == node);

	/*
	 * allow access to local node's memory through ncslices
	 * used by the remote node.
	 */
	ASSERT(node->config->imported_ncslices.id[0]);
	/*
	 * Note:  no lock is needed because config operations are single
	 * threaded, and only imported ncslices are managed during
	 * configuration.
	 */
	id = node->config->imported_ncslices.id[0];
	if (network->wrsm_ncslice_users[id] == 0) {
		wrsm_ncsliceconfig_set(network, id, ncslice_small_page);
#ifdef DEBUG
	} else {
		ASSERT(wrsm_ncsliceconfig_get(network, id) ==
		    ncslice_small_page);
#endif
	}
	network->wrsm_ncslice_users[id]++;


	for (i = 1; i < WRSM_NODE_NCSLICES; i++) {
		id = node->config->imported_ncslices.id[i];
		if (id != 0) {
			/*
			 * Note:  no lock is needed because config
			 * operations are single threaded, and only
			 * imported ncslices are managed during
			 * configuration.
			 */
			if (network->wrsm_ncslice_users[id] == 0) {
				wrsm_ncsliceconfig_set(network, id,
				    ncslice_large_page);
#ifdef DEBUG
			} else {
				ASSERT(wrsm_ncsliceconfig_get(network, id) ==
				    ncslice_large_page);
#endif
			}
			network->wrsm_ncslice_users[id]++;
		}
	}

	/*
	 * set up mapping to CESR registers for remote node
	 * They are visible through page 0 in the ncslice
	 * exported by the remote note.
	 */

	ASSERT(wrsm_ncslice_dip);
	if ((err = ddi_map_regs(wrsm_ncslice_dip,
	    (uint_t)node->config->comm_ncslice,
	    &(node->cesr_vaddr), 0, PAGESIZE)) != DDI_SUCCESS) {
		/*
		 * can't allow access to this node if this
		 * page can't be mapped
		 */
		DPRINTF(DBG_WARN, (CE_WARN, "wrsm: ddi_map_regs err %d -- "
		    "can't set up mapping to ncslice %d cnode %d CESRs",
		    err, node->config->comm_ncslice, cnodeid));
		return (ENOENT);
	}

	if ((err = ddi_map_regs(wrsm_ncslice_dip,
	    (uint_t)node->config->comm_ncslice,
	    &(node->lockout_vaddr), PAGESIZE, PAGESIZE)) != DDI_SUCCESS) {
		/*
		 * can't allow access to this node if this
		 * page can't be mapped
		 */
		DPRINTF(DBG_WARN, (CE_WARN, "wrsm: ddi_map_regs err %d -- "
		    "can't set up mapping to ncslice %d cnode %d CESRs",
		    err, node->config->comm_ncslice, cnodeid));
		return (ENOENT);
	}

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "mapped cesr page (ncslice %d) for "
	    "node %d into kernel vaddr 0x%p\n", node->config->comm_ncslice,
	    cnodeid, (void *)node->cesr_vaddr));


#ifdef DEBUG
	if (wrsm_nc_debug & DBG_CONFIG) {
		pfn_t pfn; /* page frame number */
		uint64_t pa;  /* Physical address */

		pfn = hat_getpfnum(kas.a_hat, node->lockout_vaddr);
		pa = (pfn << MMU_PAGESHIFT);
		DPRINTF(DBG_CONFIG, (CE_CONT,
		    "mapped lockout page (ncslice %d)"
		    " for node %d into kernel vaddr 0x%p pa=0x%p\n",
		    node->config->comm_ncslice, cnodeid,
		    (void *)node->lockout_vaddr, (void *)pa));
	}
#endif
	/*
	 * configure the transport to this node
	 */
	if ((err = wrsm_tl_newcnode(network, cnodeid)) != WRSM_SUCCESS) {
		DPRINTF(DBG_WARN, (CE_WARN,
		    "wrsm: can't set up transport to cnode %d", cnodeid));

		(void) ddi_unmap_regs(wrsm_ncslice_dip,
		    (uint_t)node->config->comm_ncslice,
		    &(node->cesr_vaddr), 0, PAGESIZE);
		(void) ddi_unmap_regs(wrsm_ncslice_dip,
		    (uint_t)node->config->comm_ncslice,
		    &(node->lockout_vaddr), PAGESIZE, PAGESIZE);
		node->cesr_vaddr = 0;
		node->lockout_vaddr = 0;
		return (err);
	}

	return (WRSM_SUCCESS);
}


/*
 * remove node's transport, CESR mapping, then remove node
 */
static void
remove_old_node(wrsm_node_t *node)
{
	int i;
	wrsm_network_t *network = node->network;
	ncslice_t id;

	if (node->cesr_vaddr) {
		for (i = 0; i < WRSM_NODE_NCSLICES; i++) {
			id = node->config->imported_ncslices.id[i];
			if (id != 0) {
				network->wrsm_ncslice_users[id]--;
				if (network->wrsm_ncslice_users[id] == 0) {
					wrsm_ncsliceconfig_set(network, id,
					    ncslice_invalid);
				}
			}
		}

		(void) wrsm_tl_removecnode(node->network,
		    (cnodeid_t)node->config->cnodeid);
		(void) ddi_unmap_regs(wrsm_ncslice_dip,
		    (uint_t)node->config->comm_ncslice,
		    &(node->cesr_vaddr), 0, PAGESIZE);
		(void) ddi_unmap_regs(wrsm_ncslice_dip,
		    (uint_t)node->config->comm_ncslice,
		    &(node->lockout_vaddr), PAGESIZE, PAGESIZE);
		node->cesr_vaddr = NULL;
		node->lockout_vaddr = NULL;
	}
	remove_wrsm_node(node);
}



/*
 * Save away new configuration information.
 * Notify the NR so it can save the routing configuration and stop rerouting.
 *
 * On failure, restore old configuration.
 */
int
wrsm_nc_replaceconfig(uint_t rsm_ctlr_id, wrsm_controller_t *config,
    dev_info_t *dip, int attached_cnt, wci_ids_t *attached_wcis)
{
	int i, cindex;
	int j;
	int old_availability;
	wrsm_network_t *network;
	wrsm_node_t *node;
	int err = EINVAL;
	cnodeid_t cnodeid;
	wrsm_net_member_t *nmem, *cmem;
	wrsm_net_member_t *oconfig[WRSM_MAX_CNODES];
	wrsm_node_ncslice_array_t o_exported_ncslices;
	boolean_t o_lgpg_ncslice;
	boolean_t initialnr = B_FALSE;
	boolean_t got_localnode_config = B_FALSE;
	wrsm_net_member_t *new_localnode_config;

	TNF_PROBE_0(wrsm_nc_replaceconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_replaceconfig: rsm_ctlr_id %d, "
	    "local cnodeid %d, config_version %ld, attached_cnt %d\n",
	    rsm_ctlr_id, config->cnodeid, config->version_stamp,
	    attached_cnt));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_replaceconfig: bad rsm "
		    "ctlr id\n"));
		return (ENXIO);
	}


	if (config->cnodeid != network->cnodeid) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_replaceconfig: bad cnode\n"));
		return (EINVAL);
	}

	if (config->version_stamp == network->version_stamp) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_replaceconfig: matching "
		    "version stamp\n"));
		return (EEXIST);
	}

	if (network->availability != wrsm_disabled &&
	    network->availability != wrsm_enabled) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_replaceconfig: bad "
		    "availability\n"));
		return (EBUSY);
	}

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_replaceconfig: checking nodes\n"));

	/*
	 * check for invalid changes in node config info
	 */
	for (i = 0; i < config->nmembers; i++) {
		cnodeid = config->members[i]->cnodeid;
		if (cnodeid == network->cnodeid) {
			new_localnode_config = config->members[i];
			got_localnode_config = B_TRUE;
		}

		if (network->nodes[cnodeid] == NULL)
			continue;
		nmem = network->nodes[cnodeid]->config;
		cmem = config->members[i];

		/*
		 * all ncslices in old config must also be in new config
		 */
		for (j = 0; j < WRSM_NODE_NCSLICES; j++) {
			if ((cmem->exported_ncslices.id[j] != 0) &&
			    (nmem->exported_ncslices.id[j] !=
			    cmem->exported_ncslices.id[j])) {
				DPRINTF(DBG_CONFIG, (CE_CONT,
				    "nc_replaceconfig: exported ncslice "
				    "change in new "
				    "config for node cnodeid %d\n", cnodeid));
				return (EINVAL);
			}
		}

		/*
		 * check that other configuration stuff hasn't changed
		 */
		if ((nmem->fmnodeid != cmem->fmnodeid) ||
		    strcmp(nmem->hostname, cmem->hostname) ||
		    (nmem->comm_ncslice != cmem->comm_ncslice) ||
		    (nmem->comm_offset != cmem->comm_offset) ||
		    (nmem->local_offset != cmem->local_offset)) {
			/* these configuration changes not allowed */
			DPRINTF(DBG_WARN, (CE_WARN,
			    "nc_replaceconfig: bad node ncslice info "
			    " cnodeid %d\n", cnodeid));
			return (EINVAL);
		}
	}

	if ((config->nmembers != 0) && !got_localnode_config) {
		DPRINTF(DBG_WARN, (CE_WARN,
		    "nc_replaceconfig: no routing config for local node\n"));
		return (EINVAL);
	}

	/*
	 * check that routing configuration is valid
	 */
	if ((err = wrsm_nr_verifyconfig(network, config, attached_cnt,
	    attached_wcis)) != WRSM_SUCCESS)
		return (err);



	/*
	 * configuration looks reasonable
	 * set new state
	 */
	old_availability = network->availability;
	network->availability = wrsm_disabled;
	network->dip = dip;
	o_exported_ncslices = network->exported_ncslices;
	o_lgpg_ncslice = network->have_lg_page_ncslice;
	if (got_localnode_config) {
		network->exported_ncslices =
		    new_localnode_config->exported_ncslices;
	} else {
		WRSMSET_ZERO(network->exported_ncslices);
	}

	network->have_lg_page_ncslice = B_FALSE;
	for (i = 1; i < WRSM_NODE_NCSLICES; i++) {
		if (network->exported_ncslices.id[i] != 0) {
			network->have_lg_page_ncslice = B_TRUE;
			break;
		}
	}


	/*
	 * add new nodes; disable old nodes
	 */
	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_replaceconfig: adding nodes, "
	    "config->nmembers %d\n", config->nmembers));

#ifdef DEBUG
	for (i = 1; i < config->nmembers; i++) {
		ASSERT(config->members[i]->cnodeid >
		config->members[i-1]->cnodeid);
	}
#endif
	i = 0;
	for (cindex = 0; cindex < WRSM_MAX_CNODES; cindex++) {
		oconfig[cindex] = NULL;
		node = network->nodes[cindex];

		/*
		 * the list of nodes in config->members is ordered by cnodeid
		 */
		if (i < config->nmembers &&
		    config->members[i]->cnodeid == (cnodeid_t)cindex) {
			DPRINTF(DBG_CONFIG, (CE_CONT, "nc_replaceconfig: "
			    "have a config node - cnodeid %d, i %d\n",
			    cindex, i));

			/*
			 * this is a valid node in new config
			 */
			if (node == NULL) {
				/*
				 * new node
				 */
				if ((err = new_wrsm_node(network,
				    config->members[i], &node))
				    != WRSM_SUCCESS)
					goto err_cleanup;
			} else {
				/*
				 * node already existed - update config
				 * info
				 */
				ASSERT(node->availability == wrsm_enabled);
				oconfig[cindex] = node->config;
				node->config = config->members[i];
			}

			i++;

		} else {
			/*
			 * this node is not valid in the new config
			 */
			if (node) {
				node->availability = wrsm_disabled;
				err = wrsm_sess_disable(network, cindex);
				if (err) {
					goto err_cleanup;
				}
			}
		}
	}
	ASSERT(i == config->nmembers);


	/*
	 * configure communication to the new nodes
	 */
	initialnr = wrsm_nr_initialconfig(network, attached_cnt,
	    attached_wcis);

	/*
	 * add routing info
	 */
	if ((err = wrsm_nr_replaceconfig(network, config, attached_cnt,
	    attached_wcis)) != WRSM_SUCCESS) {
		goto err_cleanup;
	}

	network->version_stamp = config->version_stamp;
	wrsm_nr_logevent(network, NULL, new_config, NULL);
	return (WRSM_SUCCESS);


err_cleanup:
	network->exported_ncslices = o_exported_ncslices;
	network->have_lg_page_ncslice = o_lgpg_ncslice;
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (network->nodes[i] == NULL)
			continue;

		node = network->nodes[i];
		if (node->availability == wrsm_pending) {
			node->availability = wrsm_disabled;
			remove_wrsm_node(node);
		} else if (node->availability == wrsm_disabled) {
			node->availability = wrsm_enabled;
		} else if (oconfig[i]) {
			node->config = oconfig[i];
		}
	}

	if (initialnr)
		wrsm_nr_removeconfig(network);

	network->availability = old_availability;

	DPRINTF(DBG_WARN, (CE_WARN, "nc_replaceconfig: failed with "
	    "error %d\n", err));
	return (err);
}



/*
 * Reconfig transport and other layers to stop supporting old nodes.
 * Turn off communication to nodes only in old configuration.
 * Initiate link bringdown on links only in old configuration.
 * Set up loopback route for local node.
 */
int
wrsm_nc_cleanconfig(uint32_t rsm_ctlr_id, int reroute_cnt,
    wci_ids_t *reroute_wcis)
{
	int i;
	wrsm_network_t *network;
	wrsm_node_t *node;
	int err;

	TNF_PROBE_0(wrsm_nc_cleanconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_cleanconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL)
		return (ENXIO);

	if (network->availability != wrsm_disabled)
		return (EBUSY);


	network->availability = wrsm_pending;

	/*
	 * Clean up old routing configuration - use intersection
	 * of old and new configurations.
	 */
	if (err = wrsm_nr_cleanconfig(network, reroute_cnt, reroute_wcis)) {
		return (err);
	}


	/*
	 * remove all nodes that are no longer part of the network
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (network->nodes[i] == NULL)
			continue;

		node = network->nodes[i];

		if (node->availability == wrsm_disabled) {
			/*
			 * tear down communication path to all nodes that
			 * are no longer part of network
			 */
			remove_old_node(node);
		}
	}

	return (WRSM_SUCCESS);
}



/*
 * Wait for all old resources to stop being used.
 * Bring up new links.
 */
int
wrsm_nc_installconfig(uint32_t rsm_ctlr_id)
{
	wrsm_network_t *network;
	wrsm_node_t *node;
	int err = WRSM_SUCCESS;
	int i;

	TNF_PROBE_0(wrsm_nc_installconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_installconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_installconfig: bad "
		    "rsm ctlr id\n"));
		return (ENXIO);
	}

	if (network->availability != wrsm_pending) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_installconfig: bad "
		    "availability\n"));
		return (EBUSY);
	}


	/*
	 * Configure each node for communication and set up error
	 * pages.  Skip local node, which has already been configured.
	 */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (i == network->cnodeid)
			continue;
		node = network->nodes[i];
		if (node && node->availability == wrsm_pending) {
			if ((err = config_new_node(node)) != WRSM_SUCCESS)
				return (err);
		}
	}

	/*
	 * Wait for NR to complete old config clean and to
	 * start new link bringup
	 */
	err = wrsm_nr_installconfig(network);

	network->availability = wrsm_installed;

	return (err);
}


/*
 * check whether all links are up yet
 */
boolean_t
wrsm_nc_is_installed_up(uint_t rsm_ctlr_id)
{
	wrsm_network_t *network;

	TNF_PROBE_0(wrsm_nc_checkconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_checkconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_checkconfig: bad rsm "
		    "ctlr id\n"));
		return (B_FALSE);
	}

	if (network->availability == wrsm_installed_up)
		return (B_TRUE);
	else
		return (B_FALSE);
}



/*
 * start using new routes
 */
int
wrsm_nc_enableconfig(uint_t rsm_ctlr_id, int reroute_cnt,
    wci_ids_t *reconfig_wcis)
{
	wrsm_network_t *network;

	TNF_PROBE_0(wrsm_nc_enableconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_enableconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL) {
		DPRINTF(DBG_WARN, (CE_WARN, "nc_enableconfig: bad rsm "
		    "ctlr id\n"));
		return (ENXIO);
	}

	/* Increment num_reconfigs */
	network->num_reconfigs++;

	/* cancel enable timeout thread (or wait until it is finished) */
	if (network->enable_timeout_id) {
		(void) untimeout(network->enable_timeout_id);
	}

	if (network->availability == wrsm_enabled) {
		/* timeout thread must have enabled network already */
		return (WRSM_SUCCESS);
	}

	return (nc_enableconfig(network, reroute_cnt, reconfig_wcis));
}



/*
 * internal version of nc_enableconfig()  -- may be called from
 * enable timeout thread
 */
static int
nc_enableconfig(wrsm_network_t *network, int reroute_cnt,
    wci_ids_t *reconfig_wcis)
{
	int i;
	int err = WRSM_SUCCESS;

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (network->nodes[i] == NULL)
			continue;
		network->nodes[i]->availability = wrsm_enabled;
	}

	/*
	 * enable local routing
	 */
	err = wrsm_nr_enableconfig(network, reroute_cnt, reconfig_wcis);

	network->availability = wrsm_enabled;

	return (err);
}


int
wrsm_nc_create_errorpage(wrsm_network_t *network,
    wrsm_cmmu_tuple_t **errorpage_tuplep, pfn_t *errorpage_pfnp,
    boolean_t sleep)
{
	caddr_t errorpage_vaddr;
	wrsm_cmmu_t cmmu;
	uint_t num_tuples;
	int err;

	if ((err = wrsm_cmmu_alloc(network, CMMU_PAGE_SIZE_SMALL, 1,
	    errorpage_tuplep, &num_tuples, sleep)) != WRSM_SUCCESS) {
		DPRINTF(DBG_WARN, (CE_WARN, "no cmmu entry for loopback "
		    "error page on controller %d\n", network->rsm_ctlr_id));
		ASSERT(num_tuples == 1);
		return (err);
	}

	/*
	 * set up page to accept transactions, but return user error
	 * on all transactions
	 */
	cmmu.entry_0.bit.count_enable = B_FALSE;
	cmmu.entry_0.bit.large_page = B_FALSE;
	cmmu.entry_0.bit.user_err = B_TRUE;
	cmmu.entry_0.bit.writable = B_TRUE;
	cmmu.entry_0.bit.from_all = B_FALSE;
	cmmu.entry_0.bit.valid = B_TRUE;
	cmmu.entry_0.bit.type = CMMU_TYPE_CACHEABLE;
	cmmu.entry_0.bit.from_node = network->cnodeid;

	wrsm_cmmu_update(network, &cmmu,
	    (*errorpage_tuplep)->index, CMMU_UPDATE_ALL);

	ASSERT(wrsm_ncslice_dip);
	if ((err = ddi_map_regs(wrsm_ncslice_dip,
	    (uint_t)network->nodes[network->cnodeid]->config->comm_ncslice,
	    &errorpage_vaddr, (off_t)(*errorpage_tuplep)->offset,
	    PAGESIZE)) != DDI_SUCCESS) {
		/*
		 * can't allow access to this node if this
		 * page can't be mapped
		 */
		DPRINTF(DBG_WARN, (CE_WARN, "wrsm: ddi_map_regs err %d -- "
		    "can't set up mapping to ncslice %d loopback error "
		    "page on controller %d\n",
		    err,
		    network->nodes[network->cnodeid]->config->comm_ncslice,
		    network->rsm_ctlr_id));
		err = EINVAL;
		return (err);
	}

	*errorpage_pfnp = va_to_pfn(errorpage_vaddr);

	ddi_unmap_regs(wrsm_ncslice_dip,
	    (uint_t)network->nodes[network->cnodeid]->config->comm_ncslice,
	    &errorpage_vaddr, (off_t)(*errorpage_tuplep)->offset,
	    PAGESIZE);

	DPRINTF(DBG_CONFIG_EXTRA, (CE_CONT, "loopback "
	    "error page pfn 0x%lx\n", *errorpage_pfnp));

	return (0);
}



/*
 * install and enable a configuration for a new RSM network
 */
int
wrsm_nc_initialconfig(uint32_t rsm_ctlr_id, wrsm_controller_t *config,
    dev_info_t *dip, int attached_cnt, wci_ids_t *attached_wcis)
{
	wrsm_network_t *network;
	int err;

	TNF_PROBE_0(wrsm_nc_initialconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_initialconfig: rsm_ctlr_id %d, "
	    "local cnodeid %d, attached_cnt %d\n", rsm_ctlr_id,
	    config->cnodeid, attached_cnt));

	if ((err = new_network(rsm_ctlr_id, &network)) != WRSM_SUCCESS)
		return (err);

	network->cnodeid = config->cnodeid;
	network->dip = dip;
	network->version_stamp = config->version_stamp - 1;

	/*
	 * initialize network->attr (rsm_controller_attr_t)  with both the
	 * default driver values and the rsm_addr_t of the controller
	 * Note - it is required the cmmu_init take care of initializing
	 * other fields of the rsm_controller_attr_t structure.
	 */
	wrsm_rsm_setup_controller_attr(network);

	if ((err = wrsm_tl_init(network)) != WRSM_SUCCESS) {
		remove_network(network);
		return (err);
	}

	wrsm_memseg_network_init(network);


	if ((err = wrsm_nc_replaceconfig(rsm_ctlr_id, config,
	    dip, attached_cnt, attached_wcis)) != WRSM_SUCCESS) {
		wrsm_memseg_network_fini(network);
		wrsm_tl_fini(network);
		remove_network(network);
		return (err);
	}

	ASSERT(network->nodes[network->cnodeid]);
	if ((err = config_new_node(network->nodes[network->cnodeid]))
	    != WRSM_SUCCESS) {
		goto err_cleanup;
	}
	network->nodes[network->cnodeid]->availability = wrsm_enabled;

	if ((err = wrsm_nc_cleanconfig(rsm_ctlr_id, attached_cnt,
	    attached_wcis)) != WRSM_SUCCESS) {
		goto err_cleanup;
	}


	/*
	 * make sure the new config allows a loopback route
	 */
	if (!WRSM_NODE_HAVE_ROUTE(network->nodes[network->cnodeid])) {
		DPRINTF(DBG_WARN, (CE_WARN, "no loopback route for "
		    "controller %d\n", network->rsm_ctlr_id));
		err = EIO;
		goto err_cleanup;
	}

	if ((err = wrsm_nc_create_errorpage(network, &network->errorpage_tuple,
	    &network->errorpage_pfn, B_FALSE)) != WRSM_SUCCESS) {
		DPRINTF(DBG_WARN, (CE_WARN, "couldn't create error page "
		    "for controller %d\n", network->rsm_ctlr_id));
		goto err_cleanup;
	}

	if ((err = wrsm_nc_installconfig(rsm_ctlr_id)) != WRSM_SUCCESS) {
		goto err_cleanup;
	}
	/*
	 * notify RSMPI that there is a new network.
	 *
	 * RSMPI clients are kernel modules, and are expected to not mess
	 * up the network data structure.
	 */

	if ((err = rsm_register_controller(WRSM_NAME, rsm_ctlr_id,
	    &network->attr)) != RSM_SUCCESS) {
		cmn_err(CE_WARN, "register_controller failed for wrsm%d "
		    "with error %d\n", rsm_ctlr_id, err);
		goto err_cleanup;
	}
	network->registered = B_TRUE;

	/*
	 * enable local routing - if necessary delay to allow links to come
	 * up before enabling routes
	 */
	mutex_enter(&network->lock);
	if (network->availability == wrsm_installed_up) {
		/* links are all already up - enable now */
		mutex_exit(&network->lock);
		(void) nc_enableconfig(network,
		    attached_cnt, attached_wcis);
	} else {
		/* set a timeout to enable network later */
		DPRINTF(DBG_CONFIG, (CE_CONT, "setting timeout to "
		    "enable network\n"));
		network->auto_enable = B_TRUE;
		mutex_exit(&network->lock);
		network->enable_timeout_id =
		    timeout(wrsm_nc_config_linksup, (void *)network,
		    (clock_t)WRSM_ENABLE_TIMEOUT);
	}

	ASSERT(network->availability == wrsm_enabled ||
	    network->availability == wrsm_installed ||
	    network->availability == wrsm_installed_up);

	return (WRSM_SUCCESS);

err_cleanup:
	if (wrsm_nc_removeconfig(rsm_ctlr_id) != WRSM_SUCCESS) {
		DPRINTF(DBG_WARN, (CE_WARN, "initialconfig: can't remove "
		    "failed controller %d installation",
		    network->rsm_ctlr_id));
		if (network->errorpage_tuple)
			wrsm_cmmu_free(network, 1, network->errorpage_tuple);
		wrsm_memseg_network_fini(network);
		wrsm_tl_fini(network);
		network->availability = wrsm_disabled;
		remove_network(network);
	}
	return (err);
}


/*
 * stop using an RSM controller, then remove it
 */
int
wrsm_nc_removeconfig(uint32_t rsm_ctlr_id)
{
	wrsm_controller_t configd;
	wrsm_routing_data_t routingd;
	wrsm_network_t *network;
	int err;
#ifdef DEBUG
	int i;
#endif

	TNF_PROBE_0(wrsm_nc_removeconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_removeconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL)
		return (ENXIO);
	/*
	 * if plugin has controller open, return EBUSY.
	 * Note, the plugin library (librsmwrsm.so opens the controller
	 * and keeps it open until completely done. this is how
	 * the driver knows that the RSMAPI library applications are not
	 * using the controller.
	 */
	if (network->is_controller_open) {
			DPRINTF(DBG_WARN,
			    (CE_WARN, "nc_removeconfig: FAILED rsm_ctlr_id  %d"
				" EBUSY in use plugin\n", rsm_ctlr_id));
			return (EBUSY);
	}

	if (network->registered) {
		if ((err = rsm_unregister_controller(WRSM_NAME, rsm_ctlr_id))
		    != RSM_SUCCESS) {
			DPRINTF(DBG_WARN,
			    (CE_WARN, "rsm_unregister_controller "
			    "failed with error %d\n", err));
			return (EBUSY);
		}
		network->registered = B_FALSE;
	}

	if (network->enable_timeout_id) {
		(void) untimeout(network->enable_timeout_id);
		network->enable_timeout_id = 0;
	}

	/*
	 * initialize and install a null configuration
	 */
	bzero(&configd, sizeof (wrsm_controller_t));
	bzero(&routingd, sizeof (wrsm_routing_data_t));
	configd.controller_id = rsm_ctlr_id;
	configd.cnodeid = network->cnodeid;
	configd.version_stamp = network->version_stamp + 1;
	configd.routing = &routingd;

	network->availability = wrsm_disabled;
	if ((err = wrsm_nc_replaceconfig(rsm_ctlr_id, &configd, network->dip,
	    0, (wci_ids_t *)NULL)) != WRSM_SUCCESS) {
		return (err);
	}

	/*
	 * Tear down communication to all nodes;
	 * stop using all old wcis, wnodes and links.
	 */
	(void) wrsm_nc_cleanconfig(rsm_ctlr_id, 0, NULL);

#ifdef DEBUG
	for (i = 0; i < WRSM_MAX_NCSLICES; i++) {
		ASSERT(network->wrsm_ncslice_users[i] == 0);
	}
#endif

	/*
	 * tear down loopback error page
	 */
	if (network->errorpage_tuple)
		wrsm_cmmu_free(network, 1, network->errorpage_tuple);

	/*
	 * teardown segments after tearing down sessions
	 * (in replaceconfig) but before removing WCIs
	 * and CMMU entries (in nr_installconfig).
	 */
	wrsm_memseg_network_fini(network);

	/*
	 * Make sure cleanup of old wcis/links is complete,
	 * then remove all data structures associated with
	 * the configuration.
	 */
	(void) wrsm_nr_installconfig(network);
	mutex_enter(&network->lock);
	(void) wrsm_nr_removeconfig(network);
	mutex_exit(&network->lock);

	wrsm_tl_fini(network);
	network->availability = wrsm_disabled;
	remove_network(network);

	return (WRSM_SUCCESS);
}


/*
 * enable sessions on nodes in an RSM controller
 */
int
wrsm_nc_startconfig(uint32_t rsm_ctlr_id)
{
	wrsm_network_t *network;
	int cindex;

	TNF_PROBE_0(wrsm_nc_startconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_startconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL)
		return (ENXIO);

	for (cindex = 0; cindex < WRSM_MAX_CNODES; cindex++) {
		if (network->nodes[cindex]) {
			(void) wrsm_sess_enable(network, cindex);
		}
	}

	return (WRSM_SUCCESS);
}


/*
 * disable sessions on nodes in an RSM controller
 */
int
wrsm_nc_stopconfig(uint32_t rsm_ctlr_id)
{
	wrsm_network_t *network;
	int cindex;

	TNF_PROBE_0(wrsm_nc_stopconfig, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_stopconfig: rsm_ctlr_id %d\n",
	    rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL)
		return (ENXIO);

	for (cindex = 0; cindex < WRSM_MAX_CNODES; cindex++) {
		if (network->nodes[cindex]) {
			(void) wrsm_sess_disable(network, cindex);
		}
	}

	return (WRSM_SUCCESS);
}


/*
 * If auto-enable has been requested, enable all new links and nodes after
 * a timeout, or after all links are up, whichever comes first.
 * (Auto-enable is requested if nc_initialconfig() is called to install a
 * configuration.)
 *
 * If auto-enable has not been requested, simply set the network
 * availability to installed_up so that a higher level entity (the RSM
 * proxy) knows when it is a good time to call nc_enableconfig()).
 */
void
wrsm_nc_config_linksup(void *arg)
{
	boolean_t enable = B_FALSE;
	wrsm_network_t *network = arg;

	TNF_PROBE_0(wrsm_nc_config_linksup, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "nc_config_linksup: rsm_ctlr_id %d\n",
	    network->rsm_ctlr_id));

	if (network->enable_timeout_id) {
		(void) untimeout(network->enable_timeout_id);
	}

	mutex_enter(&network->lock);

	if (network->auto_enable == B_TRUE) {
		/* auto enable of the network has been requested */
		DPRINTF(DBG_CONFIG, (CE_CONT, "nc_config_linksup: "
		    "auto enable\n"));
		network->auto_enable = B_FALSE;
		if (network->availability != wrsm_enabled) {
			DPRINTF(DBG_CONFIG, (CE_CONT, "nc_config_linksup: "
			    "enabling\n"));
			enable = B_TRUE;
		}
	} else {
		/* don't auto enable - just change network availability */
		DPRINTF(DBG_CONFIG, (CE_CONT, "nc_config_linksup: no auto "
		    "enable\n"));
		if (network->availability != wrsm_enabled) {
			DPRINTF(DBG_CONFIG, (CE_CONT, "nc_config_linksup: set "
			    "state "
			    "to installed_up\n"));
			network->availability = wrsm_installed_up;
		}
	}

	mutex_exit(&network->lock);

	if (enable) {
		/*
		 * auto-enable was requested - call nc_enableconfig
		 */
		(void) nc_enableconfig(network, -1, NULL);
		/*
		 * let the controller know we've moved to enabled state
		 */
		wrsm_cf_is_enabled(network->rsm_ctlr_id);
	}
}



/*
 * notify the NC that a WCI in the specified controller is now
 * attached, so the NC can start using it
 */
int wrsm_nc_newwci(uint32_t rsm_ctlr_id, safari_port_t safid,
    lcwci_handle_t lcwci, wrsm_controller_t *config)

{
	wrsm_network_t *network;
	int err;

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL)
		return (ENXIO);

	if (network->availability != wrsm_enabled)
		return (EBUSY);

	if (network->nr == NULL)
		return (EINVAL);

	if ((err = wrsm_nr_attachwci(network, safid, lcwci, config,
	    B_TRUE, B_TRUE)) !=
	    WRSM_SUCCESS)
		return (err);

	return (wrsm_nr_enablewci(network, safid, B_TRUE));
}


/*
 * notify the NC that a WCI in the specified controller is being
 * detached, so the NC stops using it
 */
int
wrsm_nc_removewci(uint32_t rsm_ctlr_id, safari_port_t safid)
{
	wrsm_network_t *network;

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	if (network == NULL)
		return (ENXIO);

	if (network->nr == NULL)
		return (EINVAL);

	if (network->availability != wrsm_enabled)
		return (EBUSY);

	/* force removal even if wci is in use */
	return (wrsm_nr_detachwci(network, safid, B_TRUE));
}

/*
 * functions for managing lists wrsm_node_t structures
 */

/*
 * find node structure from RSM fmnodeid
 */
wrsm_node_t *
wrsm_fmnodeid_to_node(wrsm_network_t *network, fmnodeid_t fmnodeid)
{
	int index;
	wrsm_node_t *node;

	ASSERT(MUTEX_HELD(&network->lock));

	index = WRSM_CNODE_HASH_FUNC(fmnodeid);
	ASSERT(index < WRSM_CNODE_HASH_SIZE);
	node = network->node_hash[index];
	while (node) {
		if (node->config->fmnodeid == fmnodeid)
			return (node);
		node = node->hash;
	}

	return (NULL);
}

/*
 * get cnodeid from fmnodeid
 */
int
wrsm_fmnodeid_to_cnodeid(wrsm_network_t *network,
    fmnodeid_t fmnodeid, cnodeid_t *cnodeidp)
{
	wrsm_node_t *node;

	ASSERT(MUTEX_HELD(&network->lock));

	node = wrsm_fmnodeid_to_node(network, fmnodeid);
	if (node) {
		*cnodeidp = node->config->cnodeid;
		return (WRSM_SUCCESS);
	} else {
		return (EBADF);
	}
}


/*
 * create a new node structure; set default values
 */
static int
new_wrsm_node(wrsm_network_t *network, wrsm_net_member_t *member,
    wrsm_node_t **nodep)
{
	wrsm_node_t *node, **np;
	int index;
	cnodeid_t cnodeid;
	fmnodeid_t fmnodeid;

	TNF_PROBE_0(wrsm_nc_new_wrsm_node, "wrsm", /* CSTYLED */);

	node = kmem_alloc(sizeof (wrsm_node_t), KM_SLEEP);
	bzero(node, sizeof (wrsm_node_t));
	node->network = network;
	node->config = member;
	node->availability = wrsm_pending;
	node->state = wrsm_node_needroute;
	node->cesr_vaddr = NULL;
	node->lockout_vaddr = NULL;

	cnodeid = member->cnodeid;
	fmnodeid = member->fmnodeid;

	mutex_enter(&network->lock);

	if (network->nodes[cnodeid]) {
		mutex_exit(&network->lock);
		kmem_free(node, sizeof (wrsm_node_t));
		return (EADDRINUSE);
	}

	if (wrsm_fmnodeid_to_node(network, fmnodeid) != NULL) {
		mutex_exit(&network->lock);
		kmem_free(node, sizeof (wrsm_node_t));
		return (EADDRINUSE);
	}

	network->wrsm_num_nodes++; /* for each node - remote and local */

	network->nodes[cnodeid] = node;
	/*
	 * route_umem space was allocated previously by ddi_umem_alloc
	 * so that the librsmwrsm.c (plugin library) would be able
	 * to easily mmap in kernel address space. The
	 * network->node[cnodeid].link_stripesp field is also used
	 * by the plugin to determine striping
	 */
	network->nodes[cnodeid]->link_stripesp = (uint32_t *)
	    ((uint64_t)network->route_umem + sizeof (uint64_t));
	wrsm_memseg_node_init(node);

	/*
	 * add to node_hash
	 */
	index = WRSM_CNODE_HASH_FUNC(fmnodeid);
	ASSERT(index < WRSM_CNODE_HASH_SIZE);
	np = &(network->node_hash[index]);
	node->hash = *np;
	*np = node;

	mutex_exit(&network->lock);

	*nodep = node;
	return (WRSM_SUCCESS);
}


/*
 * remove node structure from network, free it
 */
static void
remove_wrsm_node(wrsm_node_t *node)
{
	wrsm_network_t *network;
	wrsm_node_t **np;
	int index;

	TNF_PROBE_0(wrsm_nc_remove_wrsm_node, "wrsm", /* CSTYLED */);

	ASSERT(node != NULL);
	ASSERT(node->config != NULL);
	ASSERT(node->network != NULL);
	ASSERT(node->availability == wrsm_disabled);

	ASSERT(node->routeinfo == NULL);

	network = node->network;

	mutex_enter(&network->lock);
	ASSERT(network->nodes[node->config->cnodeid] != NULL);
	network->nodes[node->config->cnodeid] = NULL;

	/*
	 * remove node from hash table
	 */
	index = WRSM_CNODE_HASH_FUNC(node->config->fmnodeid);
	ASSERT(index < WRSM_CNODE_HASH_SIZE);
	np = &(network->node_hash[index]);

	while (*np != NULL && *np != node) {
		np = &((*np)->hash);
	}

	if (*np == NULL) {
#ifdef DEBUG
		cmn_err(CE_PANIC, "node %p (cnodeid %d) not in hash table",
		    (void *) node, node->config->cnodeid);
#endif
		mutex_exit(&network->lock);
		return;
	}

	*np = node->hash;

	mutex_exit(&network->lock);

	wrsm_memseg_node_fini(node);

	kmem_free(node, sizeof (wrsm_node_t));
	/*
	 * Decrease the number of nodes in the network,
	 * Since it is decreased we set free_rag_instance to TRUE
	 * so that the instances can be freed later in installconfig.
	 */

	network->free_rag_instance = B_TRUE;
	network->wrsm_num_nodes--;
}



/*
 * functions for managing lists of wrsm_network_t structures
 */

wrsm_network_t *
wrsm_nc_cnodeid_to_network(cnodeid_t cnodeid)
{
	wrsm_network_t *network;

	mutex_enter(&wrsm_networks_lock);
	for (network = wrsm_networks; network != NULL;
	    network = network->next) {
		if (network->cnodeid == cnodeid) {
			mutex_exit(&wrsm_networks_lock);
			return (network);
		}
	}

	mutex_exit(&wrsm_networks_lock);
	return (NULL);
}

wrsm_network_t *
wrsm_nc_ctlr_to_network(uint32_t rsm_ctlr_id)
{
	wrsm_network_t *network;

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	mutex_exit(&wrsm_networks_lock);
	return (network);
}

/*
 * find network structure from controller id
 */
static wrsm_network_t *
rsmctlr_to_network(uint32_t rsm_ctlr_id)
{
	wrsm_network_t *network;

	ASSERT(MUTEX_HELD(&wrsm_networks_lock));

	for (network = wrsm_networks; network != NULL;
	    network = network->next) {
		if (network->rsm_ctlr_id == rsm_ctlr_id)
			return (network);
	}
	return (NULL);
}

/*
 * create a new network structure; initialize it
 */
static int
new_network(uint32_t rsm_ctlr_id, wrsm_network_t **networkp)
{
	wrsm_network_t *network;

	TNF_PROBE_0(wrsm_nc_new_network, "wrsm", /* CSTYLED */);

	network = kmem_alloc(sizeof (wrsm_network_t), KM_SLEEP);
	bzero(network, sizeof (wrsm_network_t));
	network->rsm_ctlr_id = rsm_ctlr_id;
	network->availability = wrsm_disabled;
	network->registered = B_FALSE;
	network->errorpage_pfn = 0;
	network->errorpage_mappings = 0;
	network->num_reconfigs = 0;
	/*
	 * wrsm_num_nodes and free_rag_instance are used to determine if we
	 * should freeze and or release RAG instances. When there
	 * are more than 8 nodes on a RSM network we must freeze
	 * RAG instances per hardware requirement (see PRM).
	 * We release instances when nodes have been removed from the
	 * network - that is, when free_rag_instance is set to TRUE
	 */

	network->wrsm_num_nodes = 0;
	network->free_rag_instance = B_FALSE;

	mutex_init(&network->errorpage_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&wrsm_networks_lock);

	if (rsmctlr_to_network(rsm_ctlr_id)) {
		/* network already exists for this controller */
		mutex_exit(&wrsm_networks_lock);
		kmem_free(network, sizeof (wrsm_network_t));
		return (EBUSY);
	}

	/*
	 * allocate kernel space that will also be visible to user
	 * space by a mmap call
	 */
	network->route_umem =  ddi_umem_alloc(WRSM_PAGESIZE, DDI_UMEM_SLEEP,
					&network->route_cookie);
	if (network->route_umem == NULL) {
		mutex_exit(&wrsm_networks_lock);
		kmem_free(network, sizeof (wrsm_network_t));
		return (EAGAIN);

	}
	network->route_counterp =  (uint32_t *)network->route_umem;
	network->reroutingp = (uint32_t *)((uint64_t)network->route_umem +
	    sizeof (uint32_t));
	network->is_controller_open = B_FALSE;
	/*
	 * add to list of wrsm_networks
	 */
	network->next = wrsm_networks;
	wrsm_networks = network;

	/* Add controller (rsmpi) kstat */
	add_wrsm_ctlr_kstat(network);

	mutex_exit(&wrsm_networks_lock);

	DPRINTF(DBG_CONFIG, (CE_CONT, "added network 0x%p (controller id %d)\n",
	    (void *) network, network->rsm_ctlr_id));

	*networkp = network;
	return (WRSM_SUCCESS);
}

/*
 * remove network structure from list of wrsm_networks and free
 */
static void
remove_network(wrsm_network_t *network)
{
#ifdef DEBUG
	int i;
#endif
	wrsm_network_t **np;

	TNF_PROBE_0(wrsm_nc_remove_network, "wrsm", /* CSTYLED */);

	ASSERT(network != NULL);
	ASSERT(network->availability == wrsm_disabled);
	ASSERT(network->transport == NULL);
	ASSERT(network->nr == NULL);
#ifdef DEBUG
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		ASSERT(network->nodes[i] == NULL);
	}
#endif

	/* Remove controller (rsmpi) kstat */
	del_wrsm_ctlr_kstat(network);

	mutex_enter(&wrsm_networks_lock);
	for (np = &wrsm_networks; *np != NULL; np = &((*np)->next)) {
		if (*np == network) {
			*np = network->next;
			mutex_exit(&wrsm_networks_lock);

			DPRINTF(DBG_CONFIG, (CE_CONT, "found and removed "
			    "network 0x%p (controller id %d)\n",
			    (void *) network, network->rsm_ctlr_id));
			ddi_umem_free(network->route_cookie);
			mutex_destroy(&network->errorpage_lock);
			kmem_free(network, sizeof (wrsm_network_t));
			return;
		}
	}
	mutex_exit(&wrsm_networks_lock);

#ifdef DEBUG
	cmn_err(CE_WARN, "network 0x%p (id %d) not in wrsm_networks",
	    (void *) network, network->rsm_ctlr_id);
#endif
}


int
wrsm_get_peers(rsm_controller_handle_t controller, rsm_addr_t *addr_list,
    uint_t count, uint_t *num_addrs)
{
	wrsm_network_t *network = (wrsm_network_t *)controller;
	int i, j;

	*num_addrs = 0;
	j = 0;

	mutex_enter(&network->lock);
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (network->nodes[i]) {
			(*num_addrs)++;
			if (j < count) {
				addr_list[j] = (rsm_addr_t)i;
				j++;
			}
		}
	}
	mutex_exit(&network->lock);

	return (RSM_SUCCESS);
}




/*
 * initialization - returns standard errno errors
 */
void
wrsm_nc_init()
{
	TNF_PROBE_0(wrsm_nc_init, "wrsm", /* CSTYLED */);

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_init()\n"));

	mutex_init(&wrsm_networks_lock, NULL, MUTEX_DRIVER, NULL);
}


/*
 * cleanup
 */
int
wrsm_nc_fini()
{
	TNF_PROBE_0(wrsm_nc_fini, "wrsm", /* CSTYLED */);

	if (wrsm_nc_check() == WRSM_SUCCESS) {
		wrsm_nc_cleanup();
		return (WRSM_SUCCESS);
	}

	return (EBUSY);
}

int
wrsm_nc_check()
{
	mutex_enter(&wrsm_networks_lock);

	if (wrsm_networks) {
		mutex_exit(&wrsm_networks_lock);
		return (EBUSY);
	}

	mutex_exit(&wrsm_networks_lock);

	return (WRSM_SUCCESS);
}

void
wrsm_nc_cleanup()
{
	mutex_destroy(&wrsm_networks_lock);
}

/* Create the controller kstat */
/*
 * add_wrsm_ctlr_kstat
 */
static void
add_wrsm_ctlr_kstat(wrsm_network_t *network)
{
	kstat_t *ctlr_ksp;
	wrsm_rsmpi_stat_t *ctlr_named;

	ctlr_ksp = kstat_create(WRSM_KSTAT_WRSM,
		network->rsm_ctlr_id,
		RSM_KS_NAME,
		"net",
		KSTAT_TYPE_NAMED,
		sizeof (wrsm_rsmpi_stat_t) / sizeof (kstat_named_t),
		0);

	if (ctlr_ksp == NULL) {
		cmn_err(CE_WARN,
			"rsm ctlr %d: controller kstat_create failed",
			network->rsm_ctlr_id);
		return;
	}

	ctlr_named = (wrsm_rsmpi_stat_t *)(ctlr_ksp->ks_data);

	/* initialize the named kstats  (wrsm specific) */

	kstat_named_init(&ctlr_named->free_cmmu_entries,
		WRSMKS_FREE_CMMU_ENTRIES, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->num_reconfigs,
		WRSMKS_NUM_RECONFIGS, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->num_wcis,
		WRSMKS_RSM_NUM_WCIS, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->avail_wcis,
		WRSMKS_RSM_AVAIL_WCIS, KSTAT_DATA_UINT32);

	/* these are defined in rsmpi.h */

	kstat_named_init(&ctlr_named->ctlr_state,
		RSM_KS_CTLR_STATE, KSTAT_DATA_CHAR);

	kstat_named_init(&ctlr_named->addr,
		RSM_KS_ADDR, KSTAT_DATA_UINT64);

	kstat_named_init(&ctlr_named->ex_memsegs,
		RSM_KS_EX_MEMSEGS, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->ex_memsegs_pub,
		RSM_KS_EX_MEMSEGS_PUB, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->ex_memsegs_con,
		RSM_KS_EX_MEMSEGS_CON, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->bytes_bound,
		RSM_KS_BYTES_BOUND, KSTAT_DATA_UINT64);

	kstat_named_init(&ctlr_named->im_memsegs_con,
		RSM_KS_IM_MEMSEGS_CON, KSTAT_DATA_UINT32);

	kstat_named_init(&ctlr_named->sendqs,
		RSM_KS_SENDQS, KSTAT_DATA_UINT64);

	kstat_named_init(&ctlr_named->handlers,
		RSM_KS_HANDLERS, KSTAT_DATA_UINT64);

	ctlr_ksp->ks_update = ctlr_kstat_update;
	ctlr_ksp->ks_private = (void *)network;
	kstat_install(ctlr_ksp);

	network->wrsm_rsmpi_stat_ksp = ctlr_ksp;
}

static void
del_wrsm_ctlr_kstat(wrsm_network_t *network)
{
	kstat_delete(network->wrsm_rsmpi_stat_ksp);
}

static int
ctlr_kstat_update(kstat_t *ksp, int rw)
{
	wrsm_rsmpi_stat_t *ctlr_ksp;
	wrsm_network_t *network;
	wrsm_memseg_stat_data_t data;
	uint_t num_wcis, avail_wcis;

	ctlr_ksp = (wrsm_rsmpi_stat_t *)ksp->ks_data;
	network = (wrsm_network_t *)ksp->ks_private;

	ASSERT(network != NULL);

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	/* Update the named values */
	ctlr_ksp->num_reconfigs.value.ui32 = network->num_reconfigs;

	if (network->registered) {
		(void) strncpy(ctlr_ksp->ctlr_state.value.c, RSM_AE_CTLR_UP,
		    strlen(RSM_AE_CTLR_UP));
	} else {
		(void) strncpy(ctlr_ksp->ctlr_state.value.c, RSM_AE_CTLR_DOWN,
		    strlen(RSM_AE_CTLR_DOWN));
	}
	ctlr_ksp->addr.value.ui64 = network->cnodeid;

	/* access private information form the memseg */
	wrsm_memseg_stat(network, &data);

	ctlr_ksp->ex_memsegs.value.ui32 = data.export_count;
	ctlr_ksp->ex_memsegs_pub.value.ui32 = data.export_published;
	ctlr_ksp->ex_memsegs_con.value.ui32 = data.export_connected;
	ctlr_ksp->bytes_bound.value.ui64 = data.bytes_bound;
	ctlr_ksp->im_memsegs_con.value.ui32 = data.import_count;
	ctlr_ksp->sendqs.value.ui64 = network->sendqs_num;
	ctlr_ksp->handlers.value.ui64 = network->handler_num;

	/* access private information from the cmmu */
	ctlr_ksp->free_cmmu_entries.value.ui32 = wrsm_cmmu_num_free(network);
	/* check the number of wcis */
	wrsm_get_wci_num(network, &num_wcis, &avail_wcis);
	ctlr_ksp->num_wcis.value.ui32 = num_wcis;
	ctlr_ksp->avail_wcis.value.ui32 = avail_wcis;

	return (0);
}




/* Functions provide for Plugin library librsmwrsm.so support for RSMAPI */
int
wrsm_nc_open_controller(uint_t rsm_ctlr_id)
{
	wrsm_network_t *network;

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_open_controller"));

	network = wrsm_nc_ctlr_to_network(rsm_ctlr_id);
	/* if controller isn't part of a configuration, fail */
	if (!network) {
	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_open_controller no network"));
		return (ENXIO);
	}
	if (!network->registered) {
		return (EBUSY);
	}
	if (!network->is_controller_open) {
		/*
		 * Only needs to be set to TRUE the first time. controller
		 * can be opened numerous times, however, it is only closed
		 * once.
		 */
		network->is_controller_open = B_TRUE;
	}
	return (WRSM_SUCCESS);
}

/*
 * network->is_controller_open to FALSE so the remove config will
 * know that the the controller device is not in use by the plugin.
 */
void
wrsm_nc_close_controller(uint_t rsm_ctlr_id)
{
	wrsm_network_t *network;

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_close_controller"
	    " controller %d", rsm_ctlr_id));

	network =  wrsm_nc_ctlr_to_network(rsm_ctlr_id);

	ASSERT(network);
	ASSERT(network->is_controller_open);
	network->is_controller_open = B_FALSE;

}

/*
 * ioctl supplied for plugin library to determine if the export cnode is
 * the local cnode - loopback. Returns WRSM_SUCCESS (0) if match
 */
/* ARGSUSED */
int
wrsm_nc_getlocalnode_ioctl(int minor, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p)
{
	wrsm_network_t *network;
	rsm_addr_t local_cnode;

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_getlocalnode_ioctl"));
	network = wrsm_nc_ctlr_to_network(minor);

	if (network == NULL) {
		DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_getlocalnode_ioctl"
		    " no valid network for controller %d", minor));
		return (ENODEV);
	}

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_getlocalnode_ioctl local cnode "
	    " is %d controller %d", network->cnodeid,  network->rsm_ctlr_id));
	local_cnode = (rsm_addr_t)network->cnodeid;
	if (ddi_copyout(&local_cnode, (void *)arg, sizeof (rsm_addr_t),
	    flag) != 0) {
		*rval_p = EFAULT;
	} else {
		*rval_p = WRSM_SUCCESS;
	}

	return (*rval_p);
}


/*
 * This function translates from nodename to rsm_addr for that node through
 * the specified controller.  (This is for SunCluster, if they want it...)
 */
int
wrsm_nodename_to_rsmaddr(uint_t rsm_ctlr_id, char *nodename, rsm_addr_t *addr)
{
	wrsm_network_t *network;
	wrsm_node_t *node;
	int i;

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	if (network) {
		mutex_enter(&network->lock);
	}
	mutex_exit(&wrsm_networks_lock);

	if (!network) {
		DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nodename_to_rsmaddr "
		    "no network"));
		return (ENODEV);
	}

	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = network->nodes[i];
		if (node == NULL)
			continue;

		if (strcmp(nodename, node->config->hostname) == 0) {
			/* found matching node */
			*addr = (rsm_addr_t)i;
			mutex_exit(&network->lock);
			return (0);
		}
	}

	mutex_exit(&network->lock);
	return (ENXIO);
}


int
wrsm_nc_suspend(uint_t rsm_ctlr_id)
{
	int ret;
	wrsm_network_t *network;

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_suspend ctlr %d", rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	if (network) {
		mutex_enter(&network->lock);
	}
	mutex_exit(&wrsm_networks_lock);

	if (!network) {
		return (DDI_SUCCESS);
	}

	ret = wrsm_nr_suspend(network);

	mutex_exit(&network->lock);
	return (ret);
}


int
wrsm_nc_resume(uint_t rsm_ctlr_id)
{
	int ret;
	wrsm_network_t *network;

	DPRINTF(DBG_CONFIG, (CE_CONT, "wrsm_nc_resume ctlr %d", rsm_ctlr_id));

	mutex_enter(&wrsm_networks_lock);
	network = rsmctlr_to_network(rsm_ctlr_id);
	if (network) {
		mutex_enter(&network->lock);
	}
	mutex_exit(&wrsm_networks_lock);

	if (!network) {
		return (DDI_SUCCESS);
	}

	ret = wrsm_nr_resume(network);

	mutex_exit(&network->lock);
	return (ret);
}
