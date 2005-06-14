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
 * This file manages WCIs for the Wildcat RSM driver.  It orchestrates link
 * bringup and takedown based on configuration changes and changes in
 * remote connectivity, monitors links, and reports status to higher layers
 * (specifically, the multi-hop layer and syseventd).
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/int_fmtio.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/machsystm.h>
#include <sys/async.h>
#include <sys/cheetahregs.h>
#include <sys/nvpair.h>
#include <sys/policy.h>

#include <sys/wci_common.h>
#include <sys/wci_regs.h>
#include <sys/wci_offsets.h>
#include <sys/wci_masks.h>
#include <sys/wrsm_lc.h>
#include <sys/wrsm_driver.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_cf.h>
#include <sys/wrsm_plat.h>


#ifdef DEBUG
#define	LC_DEBUG		0x001
#define	LC_CSR_WRITE_DEBUG	0x002
#define	LC_CSR_READ_DEBUG	0x004
#define	LC_POLL			0x008
#define	LC_CMMU			0x010
#define	LC_CESR			0x020
#define	LC_HWSH			0x040
#define	LC_DEBUG_EXTRA		0x100
#define	LC_WARN			0x200
#define	LC_ECC			0x400
#define	LC_DEBUG_PLAT		0x800
static uint32_t wrsm_lc_debug = LC_WARN;
#define	DPRINTF(a, b) { if (wrsm_lc_debug & a) wrsmdprintf b; }

#else /* DEBUG */

#define	DPRINTF(a, b) { }

#endif /* DEBUG */

#define	LC_MAX_CONT_ERRS	100
#define	ADDR_LAST_CSR		(ADDR_WCI_DNID2GNID) /* Address of last CSR */

/* globals */
/* weight of old average in error average */
uint_t wrsm_avg_weight = 10;
/* minutes in shortterm error interval */
uint_t wrsm_shortterm_interval = 60;
/* number of shortterm intervals per long term interval */
uint_t wrsm_shorts_per_longterm = 24;

/*
 * Artificially limit ourselves to only enough CMMU entries to map 4GB
 * of exported memory.  This is to work around a bug in sun4u/rootnex.c
 * in that it's not 64bit clean.
 *
 * Normal value:     0x200000    2M entries, 16GB
 * Workaround value: 0x80000    .5M entries, 4GB
 */
static uint_t wrsm_cmmu_max_entries = 0x80000;

static clock_t wrsm_poll_hz;
static clock_t wrsm_restart_hz;
static clock_t wrsm_shortterm_hz;
boolean_t wrsm_log_link_errors = B_FALSE;

#define	BIT(id, bits) (((id) & (1 << (bits))) >> (bits))
/* calculate the weight over wrsm_avg_weight intervals */
#define	RUNNING_AVG(value, avg) (value + avg - (avg/wrsm_avg_weight))
#define	MAX(i, j) ((i > j)?i:j)

/* prototypes for local functions */
static void wrsm_lc_link_bringup(wrsm_softstate_t *softsp, uint32_t link_num);
static void wrsm_lc_link_takedown(wrsm_softstate_t *softsp,
    uint32_t local_link_num, boolean_t linkerr, boolean_t user_requested);
static void wrsm_lc_wciinit(wrsm_softstate_t *softsp, cnodeid_t local_cnode,
    wnodeid_t local_wnode);
static void wrsm_lc_platform_wciinit(wrsm_softstate_t *softsp);
static void wrsm_lc_wcifini(wrsm_softstate_t *softsp);
static void wrsm_lc_err_cnt(wrsm_softstate_t *softsp,
    boolean_t do_shortterm);
static void wrsm_lc_poll_timeout(wrsm_softstate_t *softsp);
static void wrsm_lc_check_lockout(wrsm_softstate_t *softsp);
static uint32_t get_index(wrsm_softstate_t *softsp, uint32_t dev_id);
static void wrsm_lc_clear_cmmu(wrsm_softstate_t *softsp);
static void wrsm_lc_ecc_check(wrsm_softstate_t *softsp);
static void wrsm_handle_ce_error(struct wrsm_soft_state *softsp,
    struct async_flt *ecc, int agent_type);
static void wrsm_handle_ue_error(struct wrsm_soft_state *softsp,
    struct async_flt *ecc, int agent_type);

static void wrsm_lc_sram_ecc_check(wrsm_softstate_t *softsp,
    boolean_t do_shortterm);
static void wrsm_lc_restart_downlinks(wrsm_softstate_t *softsp);
static void wrsm_lc_check_paroli_hotplug(wrsm_softstate_t *softsp);
static void wrsm_lc_check_wcx_links(wrsm_softstate_t *softsp);
static void wrsm_lc_logevent(wrsm_softstate_t *softsp,
    wrsm_sys_event_t eventtype, uint32_t local_link_num, char *reason);
#define	NUM_PLATFORMS 7

typedef enum {
	starcat_direct,	   /* starcat in direct connect topology */
	starcat_wcx,	   /* starcat in WCX topology */
	starcat_pt,	   /* starcat compute node in central switch */
	serengeti_direct,  /* serengeti in direct connect topology */
	serengeti_wcx,	   /* serengeti in WCX topology */
	serengeti_pt,	   /* serengeti compute node in central switch */
	starcat_switch	   /* starcat as a central switch */
} wrsm_platform_types_t;


#define	SET_ROUTE(route_map, wnode, linknum) \
	switch (wnode) { \
	case 0: route_map.bit.node0_tlink = linknum; break; \
	case 1: route_map.bit.node1_tlink = linknum; break; \
	case 2: route_map.bit.node2_tlink = linknum; break; \
	case 3: route_map.bit.node3_tlink = linknum; break; \
	case 4: route_map.bit.node4_tlink = linknum; break; \
	case 5: route_map.bit.node5_tlink = linknum; break; \
	case 6: route_map.bit.node6_tlink = linknum; break; \
	case 7: route_map.bit.node7_tlink = linknum; break; \
	case 8: route_map.bit.node8_tlink = linknum; break; \
	case 9: route_map.bit.node9_tlink = linknum; break; \
	case 10: route_map.bit.node10_tlink = linknum; break; \
	case 11: route_map.bit.node11_tlink = linknum; break; \
	case 12: route_map.bit.node12_tlink = linknum; break; \
	case 13: route_map.bit.node13_tlink = linknum; break; \
	case 14: route_map.bit.node14_tlink = linknum; break; \
	case 15: route_map.bit.node15_tlink = linknum; break; \
	default: ASSERT(wnode < 15 && "illegal wnodeid/gnidid"); \
	}

#define	GET_ROUTE(linknum, route_map, wnode) \
	switch (wnode) { \
	case 0: linknum = route_map.bit.node0_tlink; break; \
	case 1: linknum = route_map.bit.node1_tlink; break; \
	case 2: linknum = route_map.bit.node2_tlink; break; \
	case 3: linknum = route_map.bit.node3_tlink; break; \
	case 4: linknum = route_map.bit.node4_tlink; break; \
	case 5: linknum = route_map.bit.node5_tlink; break; \
	case 6: linknum = route_map.bit.node6_tlink; break; \
	case 7: linknum = route_map.bit.node7_tlink; break; \
	case 8: linknum = route_map.bit.node8_tlink; break; \
	case 9: linknum = route_map.bit.node9_tlink; break; \
	case 10: linknum = route_map.bit.node10_tlink; break; \
	case 11: linknum = route_map.bit.node11_tlink; break; \
	case 12: linknum = route_map.bit.node12_tlink; break; \
	case 13: linknum = route_map.bit.node13_tlink; break; \
	case 14: linknum = route_map.bit.node14_tlink; break; \
	case 15: linknum = route_map.bit.node15_tlink; break; \
	default: ASSERT(wnode < 15 && "illegal wnodeid/gnidid"); \
	}

#define	CA_TIMEOUT_CONFIG_VAL_WCI2 0x00001000000100FFULL

static gnid_t
wnode_to_gnid(wrsm_softstate_t *softsp, wnodeid_t wnode)
{
	gnid_t gnid;

	/*
	 * For a WCX, the wnode is always equal to the gnid
	 * so that mapping is not stored in the table.
	 */
	if (WRSM_GNID_IS_WCX(wnode))
		return (wnode);

	for (gnid = 0; gnid < WRSM_MAX_WNODES; gnid++) {
		wnodeid_t wnode_tmp = softsp->gnid_to_wnode[gnid];
		/* Make sure this wnode is in a valid range */
		if (wnode_tmp >= WRSM_MAX_WNODES) {
			continue;
		}
		/* See if gnid yielded the right wnode id */
		if (wnode_tmp == wnode) {
			break;
		}
	}
	return (gnid);
}

linkid_t
wrsm_lc_get_route(wrsm_softstate_t *softsp, wnodeid_t wnode, int map)
{
	wci_route_map0_u route_map;
	linkid_t link;

	if (map == 0) {
		wrsm_lc_csr_read(softsp, ADDR_WCI_ROUTE_MAP0,
		    &(route_map.val));
	} else {
		wrsm_lc_csr_read(softsp, ADDR_WCI_ROUTE_MAP1,
		    &(route_map.val));
	}
	GET_ROUTE(link, route_map, wnode);
	DPRINTF(LC_DEBUG_EXTRA, (CE_NOTE, "wrsm_lc_get_route: "
	    "wnode %d map %d link %u val %lx", wnode, map,
	    link, route_map.val));

	return (link);
}

void
wrsm_lc_set_route(wrsm_softstate_t *softsp, wnodeid_t wnode, linkid_t linknum,
    int map)
{
	gnid_t gnid;
	wci_route_map0_u route_map0;
	wci_route_map1_u route_map1;
	wci_gnid_map0_u gnid_map0;
	wci_gnid_map1_u gnid_map1;

	gnid = wnode_to_gnid(softsp, wnode);
	if (gnid >= WRSM_MAX_WNODES) {
		DPRINTF(LC_WARN, (CE_WARN, "Invalid gnid_to_wnode, wnode %u",
		    wnode));
		return;
	}

	if (map == 0) {
		wrsm_lc_csr_read(softsp, ADDR_WCI_ROUTE_MAP0,
		    &(route_map0.val));
		SET_ROUTE(route_map0, wnode, linknum);
		wrsm_lc_csr_write(softsp, ADDR_WCI_ROUTE_MAP0, route_map0.val);
		DPRINTF(LC_DEBUG_EXTRA, (CE_NOTE, "lc_set_route0 wnode %d "
		    "link %d map %d new val %lx", wnode, linknum, map,
		    route_map0.val));
		if (softsp->wci_rev >= 30) {
			/* also update wci_gnid_map0 for wci 3 */
			wrsm_lc_csr_read(softsp, ADDR_WCI_GNID_MAP0,
			    &(gnid_map0.val));
			SET_ROUTE(gnid_map0, gnid, linknum);
			wrsm_lc_csr_write(softsp, ADDR_WCI_GNID_MAP0,
			    gnid_map0.val);
		}
	} else {
		wrsm_lc_csr_read(softsp, ADDR_WCI_ROUTE_MAP1,
		    &(route_map1.val));
		SET_ROUTE(route_map1, wnode, linknum);
		wrsm_lc_csr_write(softsp, ADDR_WCI_ROUTE_MAP1, route_map1.val);
		DPRINTF(LC_DEBUG_EXTRA, (CE_NOTE, "lc_set_route1 wnode %d "
		    "link %d map %d new val %lx", wnode, linknum, map,
		    route_map0.val));
		if (softsp->wci_rev >= 30) {
			/* also update wci_gnid_map1 for wci 3 */
			wrsm_lc_csr_read(softsp, ADDR_WCI_GNID_MAP1,
			    &(gnid_map1.val));
			SET_ROUTE(gnid_map1, gnid, linknum);
			wrsm_lc_csr_write(softsp, ADDR_WCI_GNID_MAP1,
			    gnid_map1.val);
		}
	}
}

static void
wrsm_lc_link_bringup(wrsm_softstate_t *softsp, uint32_t local_link_num)
{
	wrsm_link_req_state_t link_state;
	ASSERT(softsp != NULL);
	ASSERT(softsp->config != NULL);
	ASSERT(local_link_num < WRSM_LINKS_PER_WCI);
	ASSERT(MUTEX_HELD(&softsp->lc_mutex));

	DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_link_bringup wci %d link %d",
	    softsp->portid, local_link_num));

	softsp->links[local_link_num].user_down_requested = B_FALSE;

	link_state = softsp->links[local_link_num].link_req_state;

	if ((link_state == lc_down) ||
	    (link_state == sc_wait_errdown) ||
	    (link_state == sc_wait_down) ||
	    (link_state == sc_wait_up) ||
	    (link_state == lc_up)) {
		if (link_state != lc_up) {
			/*
			 * lc_up links are config confirmation requests,
			 * hence shouldn't change to sc_wait_up state.
			 */
			softsp->links[local_link_num].link_req_state =
			    sc_wait_up;
		}
		softsp->links[local_link_num].num_requested_bringups++;
		softsp->links[local_link_num].waiting_count = 0;
		(void) wrsmplat_uplink(softsp->portid,
		    (linkid_t)local_link_num,
		    softsp->local_gnid,
		    softsp->ctlr_config->fmnodeid,
		    softsp->ctlr_config->version_stamp,
		    softsp->ctlr_config->controller_id,
		    B_FALSE /* loopback */);
#ifdef DEBUG
	} else {
		DPRINTF(LC_DEBUG, (CE_WARN, "unexpected link state %d for "
		    "for wrsm%d link %d wci %d wci",
		    link_state,
		    softsp->instance,
		    local_link_num, softsp->portid));
#endif /* DEBUG */
	}
}

int
wrsm_lc_loopback_enable(wrsm_softstate_t *softsp, uint32_t local_link_num)
{
	int rc;
	wci_sw_config_u sw_config;

	if (local_link_num >= WRSM_LINKS_PER_WCI)
		return (EINVAL);

	if ((rc = wrsm_cf_claim_wci(WRSM_LOOPBACK_ID, softsp->portid)) != 0)
		return (rc);

	wrsm_lc_csr_read(softsp, ADDR_WCI_SW_CONFIG, &sw_config.val);

	softsp->links[local_link_num].loopback_test_mode = B_TRUE;
	(void) wrsmplat_uplink(softsp->portid, (linkid_t)local_link_num,
	    sw_config.bit.gnid, 0, 0, 0, B_TRUE);

	return (0);
}

int
wrsm_lc_loopback_disable(wrsm_softstate_t *softsp, uint32_t local_link_num)
{
	int i;
	boolean_t release;

	if (local_link_num >= WRSM_LINKS_PER_WCI)
		return (EINVAL);

	if (wrsm_cf_wci_owner(softsp->portid) != WRSM_LOOPBACK_ID)
		return (EACCES);

	(void) wrsmplat_downlink(softsp->portid, (linkid_t)local_link_num,
	    B_TRUE);
	softsp->links[local_link_num].loopback_test_mode = B_FALSE;

	/*
	 * If no other links on this wci are in loopback test mode
	 * then release the wci for general use
	 */
	release = B_TRUE;
	for (i = 0; i < WRSM_LINKS_PER_WCI; ++i) {
		if (softsp->links[i].loopback_test_mode) {
			release = B_FALSE;
			break;
		}
	}
	if (release)
		wrsm_cf_release_wci(softsp->portid);

	return (0);
}

int
wrsm_lc_linktest(wrsm_softstate_t *softsp, wrsm_linktest_arg_t *linktest)
{
	if (wrsm_cf_wci_owner(softsp->portid) != WRSM_LOOPBACK_ID)
		return (EACCES);

	return (wrsmplat_linktest(softsp->portid, linktest));
}

/*
 * Take down link, and record that this is a user-requested takedown.
 */
int
wrsm_lc_user_linkdown(wrsm_softstate_t *softsp, int linkno)
{
	if ((linkno < 0) || (linkno >= WRSM_LINKS_PER_WCI)) {
		return (EINVAL);
	}

	mutex_enter(&softsp->lc_mutex);
	wrsm_lc_link_takedown(softsp, linkno, B_FALSE, B_TRUE);
	mutex_exit(&softsp->lc_mutex);
	return (0);
}

/*
 * Unset user takedown boolean, and attempt to bring it up link.
 */
int
wrsm_lc_user_linkup(wrsm_softstate_t *softsp, int linkno)
{
	if ((linkno < 0) || (linkno >= WRSM_LINKS_PER_WCI)) {
		return (EINVAL);
	}

	mutex_enter(&softsp->lc_mutex);

	if ((softsp->config == NULL) ||
	    !softsp->config->links[linkno].present) {
		mutex_exit(&softsp->lc_mutex);
		return (ENODEV);
	}

	wrsm_lc_link_bringup(softsp, linkno);
	mutex_exit(&softsp->lc_mutex);

	return (0);
}

void
lc_link_takedown_all(wrsm_softstate_t *softsp, uint32_t link)
{
	int i;
	gnid_t remote_gnid;
	wnodeid_t remote_wnode;

	ASSERT(softsp);
	ASSERT(link < WRSM_LINKS_PER_WCI);

	remote_wnode = softsp->links[link].remote_wnode;
	remote_gnid = wnode_to_gnid(softsp, remote_wnode);

	DPRINTF(LC_DEBUG, (CE_CONT, "lc_link_takedown_all: wci %d link %d "
	    "remote_wnode %d remote_gnid %d", softsp->portid, link,
	    remote_wnode, remote_gnid));

	if (WRSM_GNID_IS_WCX(remote_gnid)) {
		int gnids = softsp->links[link].remote_gnids_active;
		for (i = 0; i < WRSM_MAX_WNODES; ++i) {
			if ((gnids & (1 << i)) &&
			    (softsp->gnid_to_wnode[i] <= WRSM_MAX_WNODES)) {
				wrsm_mh_link_is_down(softsp->nc, link,
				    softsp->gnid_to_wnode[i]);
			}
		}
		softsp->links[link].remote_gnids_active = 0;
	} else {
		wrsm_mh_link_is_down(softsp->nc, link, remote_wnode);
	}
}

static void
wrsm_lc_link_takedown(wrsm_softstate_t *softsp, uint32_t local_link_num,
    boolean_t linkerr, boolean_t user_requested)
{
	wrsm_link_req_state_t link_state;

	ASSERT(softsp != NULL);
	ASSERT(local_link_num < WRSM_LINKS_PER_WCI);
	ASSERT(MUTEX_HELD(&softsp->lc_mutex));

	if (user_requested) {
		softsp->links[local_link_num].user_down_requested = B_TRUE;
	}

	link_state = softsp->links[local_link_num].link_req_state;

	DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_link_takedown: wci %d link %d "
	    "linkerr %d user %d remote_wnode %d state %d", softsp->portid,
	    local_link_num, linkerr, user_requested,
	    softsp->links[local_link_num].remote_wnode, link_state));

	if ((link_state != lc_up) && linkerr) {
		/*
		 * ignore any request for link takedown due to linkerr
		 * unless the current link state is up.  (A linkerr
		 * takedown is only generated when the link was up, but
		 * because the lock is dropped, this may not be the state
		 * by the time we get here.)
		 */
		DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_link_takedown: "
		    "link %d not up, state = %d", local_link_num,
		    link_state));
		return;
	}

	if ((link_state == lc_up) || (link_state == sc_wait_up)) {

		DPRINTF(LC_DEBUG, (CE_CONT, "in wrsm_lc_link_takedown"
		    " up/setstate/waitup link %d wci %d",
		    local_link_num, softsp->portid));

		ASSERT(softsp);
		ASSERT(local_link_num < WRSM_LINKS_PER_WCI);

		softsp->links[local_link_num].link_req_state =
		    sc_wait_down;

		if (link_state == lc_up) {
			/* Notify MH that link is going down */
			if (softsp->links[local_link_num].tell_mh_link_is_up) {
				lc_link_takedown_all(softsp, local_link_num);
			}

			/*
			 * check for a linkerr reason for links in lc_up state
			 */
			if (linkerr) {
				/*
				 * Link takedown request is due to link
				 * errors.  Change state to sc_wait_errdown.
				 */
				DPRINTF(LC_DEBUG, (CE_CONT,
				    "in wrsm_lc_link_takedown: linkerr"));

				softsp->links[local_link_num].link_req_state =
				    sc_wait_errdown;

				if (!softsp->links[local_link_num].
				    tell_mh_link_is_up) {
					/*
					 * Link error occured on an up link
					 * after a link_bringup that was
					 * requested by lc_installconfig.
					 * mh_link_is_up has not been
					 * called yet because
					 * tell_mh_link_is_up is still
					 * false.  Increment
					 * newlink_waitup_cnt since we must
					 * now wait for this link to come
					 * back up - again.
					 */
					softsp->newlink_waitup_cnt++;
				}
			} else {
				/*
				 * link_takedown request was intentially
				 * unconfigured. log system event.
				 */
				wrsm_lc_logevent(softsp, link_down,
				    local_link_num, "unconfigured");
			}
		}

		(void) wrsmplat_downlink(softsp->portid,
		    (linkid_t)local_link_num, B_FALSE);

	} else if (link_state == sc_wait_errdown) {
		/*
		 * lc_cleanconfig or user requested link takedown while
		 * link was already coming down due to link error.
		 * Change state so link does not come back up automatically.
		 */
		DPRINTF(LC_DEBUG, (CE_CONT, "in wrsm_lc_link_takedown"
		    " errdown state link %d wci %d linkerr true",
		    local_link_num, softsp->portid));
		softsp->links[local_link_num].link_req_state =
		    sc_wait_down;
		(void) wrsmplat_downlink(softsp->portid,
		    (linkid_t)local_link_num, B_FALSE);

	}
	softsp->links[local_link_num].waiting_count = 0;

	/*
	 * ignore link down request if link is already down
	 */
}

void
wrsm_lc_logevent(wrsm_softstate_t *softsp, wrsm_sys_event_t eventtype,
    uint32_t local_link_num, char *reason)
{
	nvlist_t *attr_list;
	int err = DDI_SUCCESS;
	uint32_t rsm_ctlr_id;

	ASSERT(softsp);

	DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_logevent: link %d  wci %d",
	    local_link_num, softsp->portid));

	rsm_ctlr_id = wrsm_nr_getcontroller_id(softsp->nc);
	if ((err = nvlist_alloc(&attr_list, NV_UNIQUE_NAME_TYPE,
	    KM_SLEEP)) == DDI_SUCCESS) {
		err = nvlist_add_uint32(attr_list, "controller",
		    rsm_ctlr_id);
		if (err == DDI_SUCCESS) {
			err = nvlist_add_uint32(attr_list, "portid",
			    softsp->portid);
		}
		if (err == DDI_SUCCESS) {
			err = nvlist_add_uint32(attr_list, "link",
			    local_link_num);
		}

		switch (eventtype) {
		case link_up:
			cmn_err(CE_NOTE, "wci %d link %d up",
			    softsp->portid, local_link_num);
			if (err == DDI_SUCCESS) {
				err = ddi_log_sysevent(softsp->dip,
				    DDI_VENDOR_SUNW, WRSM_CLASS,
				    WRSM_SUBCLASS_LINKUP,
				    attr_list, NULL, DDI_SLEEP);
			}
			break;
		case link_down:
			cmn_err(CE_NOTE, "wci %d link %d down: %s",
			    softsp->portid, local_link_num, reason);
			if (err == DDI_SUCCESS) {
				err = nvlist_add_string(attr_list, "reason",
				    reason);
			}
			if (err == DDI_SUCCESS) {
				err = ddi_log_sysevent(softsp->dip,
				    DDI_VENDOR_SUNW, WRSM_CLASS,
				    WRSM_SUBCLASS_LINKDOWN,
				    attr_list, NULL, DDI_SLEEP);
			}
			break;
		default:
			break;
		}

		nvlist_free(attr_list);
	}
#ifdef DEBUG
	if (err != DDI_SUCCESS) {
		DPRINTF(LC_WARN, (CE_WARN, "ERROR LOGGING system event"));
	}
#endif /* DEBUG */
}
/*
 * This function is only called by the Mbox message handler function.
 * it is called when the SC has completed discovery.
 * The purpose of this functions is to confirm the remote config data before
 * the hardware knows the link is physically 'connected' that is, the wci
 * register has link_state = in-use. Once lc_phys_link_up confirms that remote
 * data is correct, it will put in a request for the SC to set the link_state
 * to in-use
 */
/* ARGSUSED */
void
wrsm_lc_phys_link_up(safari_port_t local_port, uint32_t local_link_num,
    fmnodeid_t remote_fmnodeid, gnid_t remote_gnid,
    uint32_t remote_link_num, safari_port_t remote_port, uint64_t
    remote_partition_version, uint32_t remote_partition_id)
{
	wrsm_softstate_t *softsp;
	wrsm_linkbadconfig_reasons_t badconfig;
	boolean_t badconfigcaught = B_FALSE;

	badconfig.val = 0;

	softsp = wrsm_cf_lookup_wci(local_port);

	if ((softsp == NULL) || (local_link_num >= WRSM_LINKS_PER_WCI)) {
		/*
		 * since data is invalid, we are not sure
		 * how to send a stop discovery message
		 */
		DPRINTF(LC_WARN, (CE_WARN, "wrsm_lc_phys_link_up: "
		    "Invalid args wrsm%d link %d",
		    softsp?softsp->instance:-1, local_link_num));
		return;
	}

	DPRINTF(LC_DEBUG, (CE_CONT, "in wrsm_lc_phys_link_up link %d "
	    "wci %d", local_link_num, softsp->portid));

	mutex_enter(&softsp->lc_mutex);
	softsp->links[local_link_num].num_completed_bringups++;
	if ((softsp->config == NULL) ||
	    (softsp->ctlr_config == NULL) ||
	    (softsp->suspended) ||
	    (!softsp->config->links[local_link_num].present) ||
	    (softsp->links[local_link_num].link_req_state != sc_wait_up &&
	    softsp->links[local_link_num].link_req_state != lc_up)) {
		mutex_exit(&softsp->lc_mutex);
		return;
	}

	/* verify args */
	if (softsp->ctlr_config->version_stamp !=
	    remote_partition_version) {
		badconfig.reasons.bad_ctlr_version = B_TRUE;
		badconfigcaught = B_TRUE;
		cmn_err(CE_WARN, "wci %d link %d bad remote configuration: "
		    "got controller version %ld expected %ld",
		    softsp->portid, local_link_num,
		    remote_partition_version,
		    softsp->ctlr_config->version_stamp);
	} else {
		if (softsp->ctlr_config->controller_id !=
		    remote_partition_id) {
			badconfig.reasons.bad_ctlr_id = B_TRUE;
			badconfigcaught = B_TRUE;
			cmn_err(CE_WARN,
			    "wci %d link %d bad remote configuration: "
			    "got controller id %d expected %d",
			    softsp->portid, local_link_num,
			    remote_partition_id,
			    softsp->ctlr_config->controller_id);
		}
		if (softsp->config->links[local_link_num].
		    remote_gnid != remote_gnid) {
			badconfig.reasons.bad_gnid = B_TRUE;
			badconfigcaught = B_TRUE;
			cmn_err(CE_WARN,
			    "wci %d link %d bad remote configuration: "
			    "got gnid %d expected %d", softsp->portid,
			    local_link_num, remote_gnid,
			    softsp->config->links[local_link_num].
			    remote_gnid);
		}
		if (softsp->config->links[local_link_num].
		    remote_link_num != remote_link_num) {
			badconfig.reasons.bad_linknum = B_TRUE;
			badconfigcaught = B_TRUE;
			cmn_err(CE_WARN,
			    "wci %d link %d bad remote configuration: "
			    "got link # %d expected %d", softsp->portid,
			    local_link_num, remote_link_num,
			    softsp->config->links[local_link_num].
			    remote_link_num);
		}
		if (softsp->config->links[local_link_num].remote_port
		    != remote_port) {
			badconfig.reasons.bad_safari_port_id = B_TRUE;
			badconfigcaught = B_TRUE;
			cmn_err(CE_WARN,
			    "wci %d link %d bad remote configuration: "
			    "got safari port id %d expected %d",
			    softsp->portid, local_link_num, remote_port,
			    softsp->config->links[local_link_num].remote_port);
		}
	}
	/* Update softstate struct with badconfig reasons */
	softsp->links[local_link_num].badconfig_reasons.val = badconfig.val;

	if (badconfigcaught) {
		softsp->links[local_link_num].num_cfg_takedown++;
		wrsm_lc_link_takedown(softsp, local_link_num,
		    B_FALSE, B_FALSE);
		mutex_exit(&softsp->lc_mutex);
		wrsm_lc_logevent(softsp, link_down, local_link_num,
		    "badconfig");
		return;
	}

	/* If we weren't waiting for the link to come up, just bail */
	if (softsp->links[local_link_num].link_req_state != sc_wait_up) {
		mutex_exit(&softsp->lc_mutex);
		return;
	}

	softsp->links[local_link_num].link_req_state = lc_up;
	if (WRSM_GNID_IS_WCX(remote_gnid))
		softsp->links[local_link_num].remote_wnode = remote_gnid;
	else
		softsp->links[local_link_num].remote_wnode =
		    softsp->gnid_to_wnode[remote_gnid];
	*softsp->links[local_link_num].wrsm_link_err_cnt_addr = 0;

	/* Is it OK to tell MH link is up? */
	if (WRSM_GNID_IS_WCX(remote_gnid)) {
		softsp->links[local_link_num].remote_gnids_active = 0;
		softsp->links[local_link_num].poll_reachable = B_TRUE;
		wrsm_lc_logevent(softsp, link_up, local_link_num,
		    NULL);
		mutex_exit(&softsp->lc_mutex);
		return;
	} else if (softsp->links[local_link_num].tell_mh_link_is_up) {
		wnodeid_t remote_wnode =
		    softsp->links[local_link_num].remote_wnode;
		mutex_exit(&softsp->lc_mutex);
		/* LINTED: E_NOP_IF_STMT */
		if (remote_wnode >= WRSM_MAX_WNODES) {
			DPRINTF(LC_WARN, (CE_WARN,
			    "Bad remote wnode for wci %d link %d: %d",
			    softsp->portid, local_link_num,
			    softsp->links[local_link_num].remote_wnode));
		} else {
			wrsm_mh_link_is_up(softsp->nc, local_link_num,
			    softsp->links[local_link_num].remote_wnode);
			wrsm_lc_logevent(softsp, link_up,
			    local_link_num, NULL);
		}
		return;
	} else {
		/*
		 * newlink_waitup_cnt is how we keep track of
		 * bringup link on a new link requested
		 * initiated by NR via lc_installconfig.
		 * In this case, link is up but the NR has
		 * not as of yet called lc_enableconfig
		 */
		softsp->newlink_waitup_cnt--;
		ASSERT(softsp->newlink_waitup_cnt >= 0);
		wrsm_lc_logevent(softsp, link_up,
			    local_link_num, NULL);
		if (softsp->newlink_waitup_cnt == 0) {
			/*
			 * All new links are up and MH doesn't
			 * know - tell NR so that it will call
			 * lc_enableconfig
			 */
			mutex_exit(&softsp->lc_mutex);
			wrsm_nr_all_links_up(softsp->nc);
			return;
		}
	}
	mutex_exit(&softsp->lc_mutex);
}


/*
 * this function is only called by the mbox message handler function.
 * this function processes responses from the SC (via the SBBC mailbox)
 * that a link is down.
 *
 * This may also be called when we bring down a link in loopback mode.
 * it is harmless, as the lc state is marked as down and the call is ignored
 */
void
wrsm_lc_phys_link_down(safari_port_t local_port, uint32_t local_link_num)
{
	wrsm_softstate_t *softsp;

	softsp = wrsm_cf_lookup_wci(local_port);

	if ((softsp == NULL) || (local_link_num >= WRSM_LINKS_PER_WCI)) {
		/* invalid args */
		DPRINTF(LC_WARN, (CE_WARN, "wrsm_lc_phys_link_down: "
		    "Invalid args wrsm%d link %d",
		    softsp->instance, local_link_num));
		return;
	}

	DPRINTF(LC_DEBUG, (CE_CONT, "in wrsm_lc_phys_link_down link %d "
	    "wci %d", local_link_num, softsp->portid));

	mutex_enter(&softsp->lc_mutex);
	if (softsp->suspended) {
		mutex_exit(&softsp->lc_mutex);
		return;
	}

	softsp->links[local_link_num].poll_reachable = B_FALSE;
	if (softsp->links[local_link_num].link_req_state == sc_wait_down) {

		softsp->links[local_link_num].link_req_state = lc_down;

		if (((softsp->config == NULL) ||
		    !softsp->config->links[local_link_num].present) &&
		    (softsp->oldlink_waitdown_cnt != 0)) {
			/*
			 * If oldlink_waitdown_cnt is set, lc_installconfig
			 * is waiting for all links not in the config to
			 * come down.  Decrement oldlink_waitdown_cnt here
			 * to reflect that another link has come down.
			 */
			ASSERT(softsp->oldlink_waitdown_cnt >= 0 &&
			    softsp->oldlink_waitdown_cnt <=
			    WRSM_LINKS_PER_WCI);
			softsp->oldlink_waitdown_cnt--;
			if (softsp->oldlink_waitdown_cnt == 0) {
				/*
				 * All all requested links are down, so
				 * signal installconfig() to go.
				 */
				DPRINTF(LC_DEBUG, (CE_CONT,
				    "wrsm_lc_phys_link_down signal"
				    " lc_installconfig"));
				cv_signal(&softsp->goinstallconfig);
			}

		} else if (!softsp->links[local_link_num].user_down_requested) {
			/*
			 * Link takedown must have been due to
			 * a config error being caught.  Set timer to
			 * bring up link later if one isn't already set.
			 */
			if (softsp->restart_timeout_id == 0) {
				if (softsp->suspended) {
					softsp->need_restart_timeout = B_TRUE;
				} else {
					softsp->restart_timeout_id =
					    timeout((void (*)(void *))
					    wrsm_lc_restart_downlinks, softsp,
					    wrsm_restart_hz);
					DPRINTF(LC_DEBUG, (CE_CONT,
					    "RESTART LINK "
					    "timeout STARTED wci %d",
					    softsp->portid));
				}
			}
		}

	} else if (softsp->links[local_link_num].link_req_state ==
	    sc_wait_errdown)  {
		/*
		 * If a new config is being installed which doesn't
		 * include this link, don't bring it back up.
		 */
		if ((softsp->config == NULL) ||
		    !softsp->config->links[local_link_num].present) {
			softsp->links[local_link_num].link_req_state = lc_down;
		} else {
			/*
			 * Link take down was due to link error.
			 * Immediately try bringing link back up,
			 * unless this link has had errors on the
			 * last LC_MAX_CONT_ERRS link error checks.
			 */
			if (softsp->links[local_link_num].cont_errs <
			    LC_MAX_CONT_ERRS) {
				wrsm_lc_link_bringup(softsp, local_link_num);
			} else {
				/*
				 * Set timer to bring up link later if one
				 * isn't already set.
				 */
				softsp->links[local_link_num].link_req_state =
				    lc_down;
				softsp->links[local_link_num].cont_errs = 0;
				if (softsp->restart_timeout_id == 0) {
					if (softsp->suspended) {
						softsp->need_restart_timeout =
						    B_TRUE;
					} else {
						softsp->restart_timeout_id =
						    timeout((void (*)(void *))
						    wrsm_lc_restart_downlinks,
						    softsp,
						    wrsm_restart_hz);
						DPRINTF(LC_DEBUG, (CE_CONT,
						    "RESTART LINK "
						    "timeout STARTED wci %d",
						    softsp->portid));
					}
				}
			}
		}
	}

	mutex_exit(&softsp->lc_mutex);
}


/*
 * one time setup for timeout speeds
 */
void
wrsm_lc_setup_timeout_speeds()
{
	wrsm_poll_hz = drv_usectohz(WRSM_POLL_TIMEOUT_USEC);
	wrsm_restart_hz = drv_usectohz(WRSM_RESTART_TIMEOUT_USEC);
	wrsm_shortterm_hz = drv_usectohz(WRSM_SHORTTERM_USEC);
	DPRINTF(LC_POLL, (CE_CONT, "lc_setup_timeout: "
	    "poll = 0x%x restart = 0x%x shortterm = 0x%x",
	    wrsm_poll_hz, wrsm_restart_hz, wrsm_shortterm_hz));
}

static int
wrsm_lc_get_wci_rev(uint64_t jtag_id)
{
	int rev;

	switch (jtag_id) {
	case WCI_ID_WCI1:
		rev = 10;
		break;
	case WCI_ID_WCI2:
		rev = 20;
		break;
	case WCI_ID_WCI3:
		rev = 30;
		break;
	case WCI_ID_WCI31:
		rev = 31;
		break;
	case WCI_ID_WCI4:
		rev = 40;
		break;
	case WCI_ID_WCI41:
		rev = 41;
		break;
	default:
		rev = 99;
		DPRINTF(LC_WARN, (CE_WARN, "unrecognized WCI jtag id 0x%lx"
		    " assuming equivalent to WCI 4.1", jtag_id));
		break;
	}
	return (rev);
}

typedef struct {
	uint32_t offset;
	uint32_t mask_hi;
	uint32_t mask_lo;
	uint32_t shift;
	uint32_t array_entries;
	uint32_t plat_values[NUM_PLATFORMS];
} wrsm_platform_csr_t;

/*
 * Create a wrsm_platform_csr_t entry
 */
#define	TABLE(name, field, v1, v2, v3, v4, v5, v6, v7) \
{ ADDR_ ## name, MASK_ ## name ## _ ## field, 1, v1, v2, v3, v4, v5, v6, v7 }

/*
 * Create a wrsm_platform_csr_t entry for a register array
 */
#define	TABLE_A(name, field, v1, v2, v3, v4, v5, v6, v7) \
{ ADDR_ ## name, MASK_ ## name ## _ ## field, ENTRIES_ ## name, \
v1, v2, v3, v4, v5, v6, v7 }

/*
 * Create a wrsm_platform_csr_t entry using the same value for all
 * platforms.
 */
#define	TABLE_S(name, field, v) \
{ ADDR_ ## name, MASK_ ## name ## _ ## field, 1, v, v, v, v, v, v, v }

/*
 * Platform specific CSRs
 *
 * The following is a list of all the WCI CSRs which may need to have
 * different settings based on the platform type of the local node
 * and/or the network topology.
 *
 * 0x00180 wci_error_pause_timer_hold
 * 0x200e0 wci_ca_timeout_config
 * 0x201a0 wci_ca_timeout_config_2
 * 0x001c0 wci_csra_timeout_config
 * 0x500c0 wci_sa_timeout_config
 * 0x31100 wci_ra_timeout_config
 * 0x400e0 wci_ha_timeout_config
 * 0x201e0 wci_qlim_config_cag
 * 0x34080 wci_qlim_config_piq
 * 0x340a0 wci_qlim_config_niq
 * 0x340c0 wci_qlim_config_ciq
 * 0x00040 wci_config
 * 0x20100 wci_ca_config
 *
 * 0x34040 wci_qlim_3req_priority
 * 0x34060 wci_qlim_2req_priority
 * 0x64160 wci_qlim_sort_ciq
 * 0x64140 wci_qlim_sort_niq
 * 0x64120 wci_qlim_sort_piq
 */

/*
 * These CSR values come from the "Programming the Timeouts", "RSM
 * Sorting and Bandwidth Balancing"  and "Setting the WC{I,X}
 * Network Timeouts: a programmer's guide" sections of the WCI 3 PRM.
 * The seven field values correspond to the the seven platform types
 * as specified by the wrsm_platform_types_t enumeration.
 */
wrsm_platform_csr_t plat_csr_values[] = {

/* Programming the Timeouts */
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, CA_APHASE, 0),
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, CA_DPHASE, 0),
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, CA_REUSE, 1),
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, RA_CLUSTER_PRIMARY, 1),
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, RA_SSM_PRIMARY, 0),
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, HA_PRIMARY, 0),
TABLE_S(WCI_ERROR_PAUSE_TIMER_HOLD, SA_PRIMARY, 0),

TABLE_S(WCI_CA_TIMEOUT_CONFIG, DPHASE_DISABLE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, DPHASE_FREEZE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, DPHASE_DEST_MAG, 3),
TABLE(WCI_CA_TIMEOUT_CONFIG, DPHASE_DEST_VAL, 13, 13, 20, 18, 18, 18, 13),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, DPHASE_PASS_MAG, 3),
TABLE(WCI_CA_TIMEOUT_CONFIG, DPHASE_PASS_VAL, 13, 13, 20, 18, 18, 18, 13),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, APHASE_DISABLE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, APHASE_FREEZE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, APHASE_MAG, 2),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, APHASE_VAL, 32),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, REUSE_DISABLE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, REUSE_FREEZE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, REUSE_MAG, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG, REUSE_VAL, 9),

TABLE_S(WCI_CA_TIMEOUT_CONFIG_2, SFI_TARGID_TIMEOUT_DISABLE, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG_2, SFI_TARGID_TIMEOUT_SEL, 3),
TABLE_S(WCI_CA_TIMEOUT_CONFIG_2, LOC_REUSE_MAG, 0),
TABLE_S(WCI_CA_TIMEOUT_CONFIG_2, LOC_REUSE_VAL, 32),

TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, PULL_TARGID_FAIL_FAST_ENABLE, 0),
TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, PULL_FAIL_FAST_ENABLE, 1),
TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, DISABLE, 0),
TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, FREEZE, 0),
TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, MAGNITUDE, 0),
TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, RD_TIMEOUT, 8),
TABLE_S(WCI_CSRA_TIMEOUT_CONFIG, WR_TIMEOUT, 8),

TABLE_S(WCI_SA_TIMEOUT_CONFIG, SSM_DISABLE, 1),
TABLE_S(WCI_SA_TIMEOUT_CONFIG, SSM_FREEZE, 0),

TABLE_S(WCI_RA_TIMEOUT_CONFIG, CLUS_DISABLE, 0),
TABLE_S(WCI_RA_TIMEOUT_CONFIG, CLUS_FREEZE, 0),
TABLE_S(WCI_RA_TIMEOUT_CONFIG, CLUS_APHASE_MAG, 2),
TABLE(WCI_RA_TIMEOUT_CONFIG, CLUS_APHASE_VAL, 50, 50, 39, 50, 50, 50, 39),
TABLE_S(WCI_RA_TIMEOUT_CONFIG, CLUS_DPHASE_MAG, 0),
TABLE_S(WCI_RA_TIMEOUT_CONFIG, CLUS_DPHASE_VAL, 8),
TABLE_S(WCI_RA_TIMEOUT_CONFIG, SSM_DISABLE, 1),
TABLE_S(WCI_RA_TIMEOUT_CONFIG, SSM_FREEZE, 0),

TABLE_S(WCI_HA_TIMEOUT_CONFIG, SSM_DISABLE, 1),
TABLE_S(WCI_HA_TIMEOUT_CONFIG, SSM_FREEZE, 0),

TABLE_S(WCI_QLIM_CONFIG_CAG, FREEZE, 1),
TABLE_S(WCI_QLIM_CONFIG_CAG, DISABLE, 1),
TABLE(WCI_QLIM_CONFIG_CAG, MAX_DISCARD, 0x1fff, 0x1fff, 0x1fff, 0x1fff,
    0x1fff, 0x1fff, 0x1fff),
TABLE_S(WCI_QLIM_CONFIG_CAG, NUM2DISCARD, 16),
TABLE_S(WCI_QLIM_CONFIG_CAG, TMIN_MAG, 5),
TABLE_S(WCI_QLIM_CONFIG_CAG, HWMARK_EXP, 4),

TABLE_S(WCI_QLIM_CONFIG_PIQ, FREEZE, 1),
TABLE_S(WCI_QLIM_CONFIG_PIQ, DISABLE, 1),
TABLE_S(WCI_QLIM_CONFIG_PIQ, DISCARD_CNT_TIMER_EN, 1),
TABLE(WCI_QLIM_CONFIG_PIQ, DISCARD_CNT_TIMER_MAG, 5, 5, 5, 6, 6, 6, 5),
TABLE_S(WCI_QLIM_CONFIG_PIQ, DISCARD_CNT_TIMER_VAL, 1),
TABLE(WCI_QLIM_CONFIG_PIQ, MAX_DISCARD, 0x1fff, 0x1fff, 0x1fff, 0x1fff,
    0x1fff, 0x1fff, 0x1fff),
TABLE_S(WCI_QLIM_CONFIG_PIQ, NUM2DISCARD, 16),
TABLE_S(WCI_QLIM_CONFIG_PIQ, DECAY, 1),
TABLE(WCI_QLIM_CONFIG_PIQ, TMIN_MAG, 30, 30, 30, 47, 47, 47, 65),
TABLE_S(WCI_QLIM_CONFIG_PIQ, HWMARK_EXP, 4),

TABLE_S(WCI_QLIM_CONFIG_NIQ, FREEZE, 1),
TABLE_S(WCI_QLIM_CONFIG_NIQ, DISABLE, 1),
TABLE_S(WCI_QLIM_CONFIG_NIQ, DISCARD_CNT_TIMER_EN, 1),
TABLE_S(WCI_QLIM_CONFIG_NIQ, DISCARD_CNT_TIMER_MAG, 5),
TABLE(WCI_QLIM_CONFIG_NIQ, DISCARD_CNT_TIMER_VAL, 1, 1, 1, 2, 2, 2, 1),
TABLE(WCI_QLIM_CONFIG_NIQ, MAX_DISCARD, 0x1fff, 0x1fff, 0x1fff, 0x1fff,
    0x1fff, 0x1fff, 0x1fff),
TABLE_S(WCI_QLIM_CONFIG_NIQ, NUM2DISCARD, 16),
TABLE_S(WCI_QLIM_CONFIG_NIQ, DECAY, 1),
TABLE(WCI_QLIM_CONFIG_NIQ, TMIN_MAG, 30, 30, 30, 36, 36, 36, 59),
TABLE_S(WCI_QLIM_CONFIG_NIQ, HWMARK_EXP, 4),

TABLE_S(WCI_QLIM_CONFIG_CIQ, FREEZE, 1),
TABLE_S(WCI_QLIM_CONFIG_CIQ, DISABLE, 1),
TABLE_S(WCI_QLIM_CONFIG_CIQ, DISCARD_CNT_TIMER_EN, 1),
TABLE_S(WCI_QLIM_CONFIG_CIQ, DISCARD_CNT_TIMER_MAG, 6),
TABLE_S(WCI_QLIM_CONFIG_CIQ, DISCARD_CNT_TIMER_VAL, 1),
TABLE(WCI_QLIM_CONFIG_CIQ, MAX_DISCARD, 2048, 2048, 2048, 1024, 1024,
    1024, 2048),
TABLE_S(WCI_QLIM_CONFIG_CIQ, NUM2DISCARD, 16),
TABLE_S(WCI_QLIM_CONFIG_CIQ, DECAY, 1),
TABLE(WCI_QLIM_CONFIG_CIQ, TMIN_MAG, 30, 30, 30, 36, 36, 36, 59),
TABLE_S(WCI_QLIM_CONFIG_CIQ, HWMARK_EXP, 4),

TABLE_S(WCI_CONFIG, SAFARI_COMPLIANT_TARGID, 1),
TABLE_S(WCI_CONFIG, CLUSTER_EARLY_REUSE_EN, 1),

TABLE_S(WCI_CA_CONFIG, REUSE_TIMEOUT_LIMIT, 15),

/* RSM Sorting and Bandwidth Balancing */
TABLE(WCI_QLIM_3REQ_PRIORITY, NUM_SLOTS, 7, 7, 7, 1, 1, 1, 14),
TABLE(WCI_QLIM_3REQ_PRIORITY, ARB_SLOTS, 0xaaa7, 0xaaa7, 0xaaa7, 0xb,
    0xb, 0xb, 0xaaa9aaab),

TABLE(WCI_QLIM_2REQ_PRIORITY, CIQ_NIQ_NUM_SLOTS, 7, 7, 7, 1, 1, 1, 14),
TABLE(WCI_QLIM_2REQ_PRIORITY, PIQ_CIQ_NUM_SLOTS, 0, 0, 0, 0, 0, 0, 1),
TABLE(WCI_QLIM_2REQ_PRIORITY, NIQ_PIQ_NUM_SLOTS, 0, 0, 0, 0, 0, 0, 14),
TABLE(WCI_QLIM_2REQ_PRIORITY, CIQ_NIQ_ARB_SLOTS, 1, 1, 1, 1, 1, 0, 1),
TABLE(WCI_QLIM_2REQ_PRIORITY, PIQ_CIQ_ARB_SLOTS, 0, 0, 0, 0, 0, 0, 1),
TABLE(WCI_QLIM_2REQ_PRIORITY, NIQ_PIQ_ARB_SLOTS, 1, 1, 1, 0, 0, 0, 0x7ffe),

TABLE(WCI_QLIM_SORT_CIQ, DEV_ID_VEC, 0xf000030f, 0xf000030f,
    0xf000030f, 0xffffffff, 0xffffffff, 0xffffffff, 0xf000010f),

TABLE(WCI_QLIM_SORT_NIQ, DEV_ID_VEC, 0xffffcf0, 0xffffcf0, 0xffffcf0,
    0, 0, 0, 0xffffcf0),

TABLE(WCI_QLIM_SORT_PIQ, DEV_ID_VEC, 0xf0000000, 0xf0000000,
    0xf0000000, 0, 0, 0, 0xf0000200),

/* Setting the WC{I,X} Network Timeouts: a programmer's guide */
TABLE_A(WCI_SW_LINK_CONTROL, REXMIT_FREEZE, 0, 0, 0, 0, 0, 0, 0),
TABLE_A(WCI_SW_LINK_CONTROL, REXMIT_MAG, 3, 3, 3, 3, 3, 3, 3),
TABLE_A(WCI_SW_LINK_CONTROL, REXMIT_VAL, 5, 84, 5, 5, 84, 5, 5),
TABLE_A(WCI_SW_LINK_CONTROL, REXMIT_SHUTDOWN_EN, 1, 1, 1, 1, 1, 1, 1),

TABLE_S(WCI_DIF_TIMEOUT_CNTL, TIMEOUT_DISABLE, 0),
TABLE_S(WCI_DIF_TIMEOUT_CNTL, TIMEOUT_FREEZE, 0),
TABLE_S(WCI_DIF_TIMEOUT_CNTL, TIMEOUT_MAG, 3),
TABLE_S(WCI_DIF_TIMEOUT_CNTL, TIMEOUT_VAL, 0),

{ 0 }
};


/*
 * lc_wciinit may ONLY be called from lc_replaceconfig
 * lc_wciinit sets the softstate struct with the local_cnode
 * local_wnode, and initializes several different registers
 * routemap0 and routemap1, wci_brd2cnid_array.
 * enables cluster_disable in wci_ca_config.
 */
static void
wrsm_lc_wciinit(wrsm_softstate_t *softsp, cnodeid_t local_cnode,
    wnodeid_t local_wnode)
{
	int i;
	uint64_t offset;
	uint64_t entry;
	wci_id_u wci_id; /* determine wci partid - wci1, wci2, wci3 */
	wci_cluster_error_status_array_u cesr;
	wci_ca_timeout_config_u ca_timeout_config;
	wci_ra_timeout_config_u ra_timeout_config;
	wci_ra_esr_mask_u ra_mask;
	wci_ca_esr_mask_u ca_mask;
	wci_hli_esr_mask_u hli_mask;
	wci_csra_esr_mask_u csra_mask;
	wci_sfi_esr_mask_u sfi_mask;
	wci_dc_esr_mask_u dc_mask;
	wci_sfq_esr_mask_u sfq_mask;
	wci_link_esr_mask_u link_mask;
	wci_sw_esr_mask_u sw_mask;
	wci_ha_esr_mask_u ha_mask;
	wci_sa_esr_mask_u sa_mask;
	wci_cci_esr_mask_u cci_mask;
	wci_sw_config_u sw_config;
	wci_config_u wci_config_tmp;  /* where w.node_id is defined */
	wci_board2cnid_control_u wci_brd2cnid_control;
	wci_board2cnid_array_u wci_brd2cnid_array_tmp;
	wci_ca_config_u wci_ca_config_tmp; /* where cluster_disable defined */
	wci_sram_config_u sram_config;
	wci_error_inducement_u wci_error_inducement;
	wrsm_cmmu_t cmmu;

	DPRINTF(LC_DEBUG, (CE_CONT, "in wrsm_lc_wciinit wci %d",
	    softsp->portid));
	ASSERT(softsp != NULL);
	ASSERT(local_wnode < 16 && local_wnode >= 0);


	softsp->restart_timeout_id = 0;
	softsp->shortterm_start = ddi_get_lbolt();

	/* set striping bits to no striping */
	wrsm_lc_csr_read(softsp, ADDR_WCI_CONFIG, &wci_config_tmp.val);
	wci_config_tmp.bit.stripe_bits = WCI_STRIPE_NONE;
	wci_config_tmp.bit.enable_inid = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CONFIG, wci_config_tmp.val);

	/*
	 * set up the wci_error_inducement to reset state
	 * this must be done before writing to SRAM (CMMU)
	 */
	wci_error_inducement.val = 0;
	wci_error_inducement.bit.sram_ecc_xor_2_select = 0x3F;
	wci_error_inducement.bit.sram_ecc_xor_1_select = 0x3F;

	wrsm_lc_csr_write(softsp, ADDR_WCI_ERROR_INDUCEMENT,
	    wci_error_inducement.val);

	/* clear all CMMU entries in SRAM */
	wrsm_lc_clear_cmmu(softsp);

	/*
	 * Entry 1 of the CMMU is reserved during cmmu_init() to
	 * be used for clearing cluster write lockout.  Here we
	 * initialized it to a sensible value.
	 */
	cmmu.entry_0.val = 0;
	cmmu.entry_1.val = 0;
	cmmu.entry_0.bit.writable = 0;
	cmmu.entry_0.bit.from_all = 1;
	cmmu.entry_0.bit.from_node = 255;
	cmmu.entry_0.bit.valid = 1;
	cmmu.entry_0.bit.type = CMMU_TYPE_CACHEABLE;
	wrsm_lc_cmmu_update(softsp, &cmmu, 1, CMMU_UPDATE_ALL);


	/* clear wci_nc_slice_config_array */
	for (i = 0; i < ENTRIES_WCI_NC_SLICE_CONFIG_ARRAY; i++) {
		offset = ADDR_WCI_NC_SLICE_CONFIG_ARRAY +
		    i * STRIDE_WCI_NC_SLICE_CONFIG_ARRAY;
		wrsm_lc_csr_write(softsp, offset, 0);
	}

	/* clear wci_cluster_error_count */
	wrsm_lc_csr_write(softsp, ADDR_WCI_CLUSTER_ERROR_COUNT, 0);
	/* clear inid2dnid array */
	for (i = 0; i < ENTRIES_WCI_INID2DNID_ARRAY; i++) {
		offset = ADDR_WCI_INID2DNID_ARRAY +
		    i * STRIDE_WCI_INID2DNID_ARRAY;
		wrsm_lc_csr_write(softsp, offset, 0);
	}
	/* Clear cluster members bits */
	for (i = 0; i < ENTRIES_WCI_CLUSTER_MEMBERS_BITS; i++) {
		offset = ADDR_WCI_CLUSTER_MEMBERS_BITS +
		    i * STRIDE_WCI_CLUSTER_MEMBERS_BITS;
		wrsm_lc_csr_write(softsp, offset, 0);
	}
	/* clear wci_sw_link_error_count */
	for (i = 0; i < ENTRIES_WCI_SW_LINK_ERROR_COUNT; i++)
		*softsp->links[i].wrsm_link_err_cnt_addr = 0;
	/* set wci revisions - to determine if wci  2 or 3 */
	wrsm_lc_csr_read(softsp, ADDR_WCI_ID, &wci_id.val);
	softsp->wci_rev = wrsm_lc_get_wci_rev(wci_id.val);

	cesr.val = 0;
	cesr.bit.disable_fail_fast = 1;
	for (i = 0; i < ENTRIES_WCI_CLUSTER_ERROR_STATUS_ARRAY; i++) {
		offset = ADDR_WCI_CLUSTER_ERROR_STATUS_ARRAY +
		    i * STRIDE_WCI_CLUSTER_ERROR_STATUS_ARRAY;
		wrsm_lc_csr_write(softsp, offset, cesr.val);
	}

	/* Clear the write lockout bits */
	for (i = 0; i < ENTRIES_WCI_CLUSTER_WRITE_LOCKOUT; ++i) {
		offset = ADDR_WCI_CLUSTER_WRITE_LOCKOUT +
		    i * STRIDE_WCI_CLUSTER_WRITE_LOCKOUT;
		wrsm_lc_csr_write(softsp, offset, 0);
	}
	/* clear write lockout status */
	wrsm_lc_csr_write(softsp, ADDR_WCI_RA_WRITE_LOCKOUT_STATUS, 0);

	/*
	 * disable all slave and home agent instances - they are
	 * not used in cluster mode.
	 */
	wrsm_lc_csr_write(softsp, ADDR_WCI_SA_FREEZE, 0xff);
	wrsm_lc_csr_write(softsp, ADDR_WCI_HA_FREEZE, 0xffff);

	/* wci_dco_ce_count must be set before wci_dc_esr register */
	wrsm_lc_csr_write(softsp, ADDR_WCI_DCO_CE_COUNT, CE_CNTMAX);
	wrsm_lc_csr_write(softsp, ADDR_WCI_CA_FREEZE, 0);

	/* Clear any previous freeze bits set in prior configs */
	wrsm_lc_csr_write(softsp, ADDR_WCI_RA_FREEZE, 0);
	/* the following ESR registers require a TOGGLE to reset bit */
	wrsm_lc_csr_read(softsp, ADDR_WCI_CSRA_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_CSRA_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_CCI_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_CCI_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_DC_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_DC_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_HLI_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_HLI_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SFQ_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFQ_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_CA_ESR_0, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_CA_ESR_0, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_CA_ESR_1, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_CA_ESR_1, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_RA_ESR_0, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_RA_ESR_0, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_RA_ESR_1, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_RA_ESR_1, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_HA_ESR_0, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_HA_ESR_0, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_HA_ESR_1, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_HA_ESR_1, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SA_ESR_0, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SA_ESR_0, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SFI_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_LINK_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_LINK_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SW_ESR, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SW_ESR, entry);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SRAM_STATUS, &entry);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SRAM_STATUS, entry);

	/*
	 * mask/unmask ESR registers as outlined in PRM doc
	 * this step should always follow reseting esr
	 */
	ra_mask.val = MASKALL;
	ra_mask.bit.wrong_safari_command = 0;
	ra_mask.bit.unexpected_send_ack = 0;
	ra_mask.bit.unexpected_receive_ack = 0;
	ra_mask.bit.hw_protocol_error = 0;
	ra_mask.bit.hw_fifo_ovfl_unfl = 0;
	ra_mask.bit.cluster_local_timeout = 0;
	ra_mask.bit.mtag_mismatch_between_hcls = 0;
	ra_mask.bit.mtag_mismatch_within_hcl = 0;
	ra_mask.bit.mtag_not_gm = 0;
	ra_mask.bit.uncorrectable_mtag_error = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_RA_ESR_MASK, ra_mask.val);

	ca_mask.val = MASKALL;
	ca_mask.bit.atomic_map_mismatch = 0;
	ca_mask.bit.mtag_mismatch_between_hcls = 0;
	ca_mask.bit.mtag_mismatch_within_hcl = 0;
	ca_mask.bit.dstat_inconsistent = 0;
	ca_mask.bit.uncorrectable_mtag_error = 0;
	ca_mask.bit.internal_error = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CA_ESR_MASK, ca_mask.val);

	hli_mask.val = MASKALL;
	hli_mask.bit.slq_perr = 0;
	hli_mask.bit.hmq_perr = 0;
	hli_mask.bit.strange_pkt = 0;
	hli_mask.bit.bq_unfl = 0;
	hli_mask.bit.hmq_unfl = 0;
	hli_mask.bit.hmq_ovfl = 0;
	hli_mask.bit.slq_ovfl = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_HLI_ESR_MASK, hli_mask.val);

	csra_mask.val = MASKALL;
	csra_mask.bit.timeout = 0;
	csra_mask.bit.pull_targid_timeout = 0;
	csra_mask.bit.pull_timeout = 0;
	csra_mask.bit.mtag_not_gm = 0;
	csra_mask.bit.mtag_mismatch = 0;
	csra_mask.bit.uncorrectable_data_error = 0;
	csra_mask.bit.uncorrectable_mtag_error = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CSRA_ESR_MASK, csra_mask.val);

	sfi_mask.val = MASKALL;
	sfi_mask.bit.targid_timeout = 0;
	sfi_mask.bit.nc2nid_misconfig = 0;
	sfi_mask.bit.addr_pty = 0;
	sfi_mask.bit.incoming_prereq_conflict = 0;
	sfi_mask.bit.modcam_clr_set_conflict = 0;
	sfi_mask.bit.modcam_multi_hit = 0;
	sfi_mask.bit.modcam_set_set = 0;
	sfi_mask.bit.unexpected_incoming = 0;
	sfi_mask.bit.unexpected_targarbgnt = 0;
	sfi_mask.bit.transid_unalloc_released = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_ESR_MASK, sfi_mask.val);

	cci_mask.val = MASKALL;
	cci_mask.bit.sram_ae = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CCI_ESR_MASK, cci_mask.val);

	/*
	 * The PRM recommends unmasking dco_data_parity_error.
	 * However, due to some firmware and/or hardware problems,
	 * these errors happen all the time, so we have to mask it.
	 */
	dc_mask.val = MASKALL;
	dc_mask.bit.dif_timeout = 0;
	dc_mask.bit.dco_map_error = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_DC_ESR_MASK, dc_mask.val);

	sfq_mask.val = MASKALL;
	sfq_mask.bit.sfq_perr = 0;
	sfq_mask.bit.sfq_ovfl = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFQ_ESR_MASK, sfq_mask.val);

	link_mask.val = MASKALL;
	wrsm_lc_csr_write(softsp, ADDR_WCI_LINK_ESR_MASK, link_mask.val);

	sw_mask.val = MASKALL;
	sw_mask.bit.error_pause_broadcast = 0;
	sw_mask.bit.addr_lpbk_fifo_ovf = 0;
	sw_mask.bit.data_lpbk_fifo_ovf = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_SW_ESR_MASK, sw_mask.val);

	/*
	 * although the ha (home agent) and sa (slave agent) are only used
	 * in a SSM configured wci, it was recommended that the mask be
	 * set correctly in the wrsm driver so that illegal ssm transactions
	 * can be caught.
	 */
	ha_mask.val = MASKALL;
	ha_mask.bit.wrong_cmd = 0;
	ha_mask.bit.not_expected_compl = 0;
	ha_mask.bit.address_not_mapped = 0;
	ha_mask.bit.gnr_err = 0;
	ha_mask.bit.timeout = 0;
	ha_mask.bit.unexpected_mtag = 0;
	ha_mask.bit.mtag_mismatch_between_hcls = 0;
	ha_mask.bit.mtag_mismatch_within_hcl = 0;
	ha_mask.bit.dstat_inconsistent = 0;
	ha_mask.bit.mtag_not_gm = 0;
	ha_mask.bit.uncorrectable_mtag_error = 0;
	ha_mask.bit.hw_err = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_HA_ESR_MASK, ha_mask.val);

	sa_mask.val = MASKALL;
	sa_mask.bit.wrong_demand = 0;
	sa_mask.bit.ga2lpa_ecc_error = 0;
	sa_mask.bit.address_not_owned = 0;
	sa_mask.bit.address_not_mapped = 0;
	sa_mask.bit.rip_multi_hit = 0;
	sa_mask.bit.timeout = 0;
	sa_mask.bit.unexpected_mtag = 0;
	sa_mask.bit.mtag_mismatch_between_hcls = 0;
	sa_mask.bit.mtag_mismatch_within_hcl = 0;
	sa_mask.bit.uncorrectable_mtag_error = 0;
	sa_mask.bit.hw_err = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_SA_ESR_MASK, sa_mask.val);

	wrsm_lc_csr_read(softsp, ADDR_WCI_SW_CONFIG, &sw_config.val);
	sw_config.bit.error_pause_shutdown_en = 1;
	sw_config.bit.max_errors = MAXERRORS;
	sw_config.bit.gnid = softsp->local_gnid;
	wrsm_lc_csr_write(softsp, ADDR_WCI_SW_CONFIG, sw_config.val);

	wrsm_lc_csr_write(softsp, ADDR_WCI_ERROR_PAUSE_TIMER_HOLD, 0);

	wrsm_lc_csr_read(softsp, ADDR_WCI_SRAM_CONFIG, &sram_config.val);
	sram_config.bit.ecc_disable = 0;
	sram_config.bit.parity_disable = 1;
	sram_config.bit.ecc_writeback_disable = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_SRAM_CONFIG, sram_config.val);

	/*
	 * On timeout config registers, Hien Nguyen suggests the
	 * following settings.
	 *
	 * Tru(cag) = wci_ca_timeout_config.reuse_timeout
	 * Tdp(rag) = wci_ra_timeout_config.primary_cluster_wr_timeout
	 * T(cpu)   = Cheetah timeout value
	 * T(rag)   = wci_ra_timeout_config.primary_cluster_rd_timeout
	 * T(cag)   = wci_ca_timeout_config.primary_timeout
	 *
	 * T(cag) < T(rag) < Tcpu < Tdp(rag) < Tru(cag)
	 *
	 * Here is a suggestion without much analysis.
	 * Tru(cag) = 256*2^24 cycles (max)
	 * Tdp(rag) = 32*2^24 cycles
	 * T(cpu)   = 16*2^24 cycles (Is 2^28 the default?)
	 * T(rag)   = 2*2^24 cycles
	 * T(cag)   = 1*2^24 cycles
	 *
	 * These numbers are ok for small clusters.  When we have larger
	 * machines, we will have to make some adjustments.
	 */
	ca_timeout_config.val = 0;
	/*
	 * the position of the reuse_mag and reuse_val change between wci2
	 * wci3. Since our driver is compiled to deal with > wci 3 headers
	 * the values for wci 2 fields must be set manually.
	 * reuse_val; wci 2 0-7 th bit, wci 3 0-10 bit
	 * reuse_mag; wci 2 8th and 9th bit, wci 3 11 and 12
	 */

	if (softsp->wci_rev < 30) {
		/* reuse_mag already 0 since config.val = 0 above */
		ca_timeout_config.val = CA_TIMEOUT_CONFIG_VAL_WCI2;
	} else { /* wci 3 or later revision */
		ca_timeout_config.bit.reuse_mag = 0;
		ca_timeout_config.bit.reuse_val = 255;
		ca_timeout_config.bit.dphase_dest_val = 1;
		ca_timeout_config.bit.aphase_val = 1;
	}

	wrsm_lc_csr_write(softsp, ADDR_WCI_CA_TIMEOUT_CONFIG,
	    ca_timeout_config.val);

	ra_timeout_config.val = 0;
	ra_timeout_config.bit.ssm_disable = 1;
	ra_timeout_config.bit.clus_aphase_val = 2;
	ra_timeout_config.bit.clus_dphase_val = 32;
	wrsm_lc_csr_write(softsp, ADDR_WCI_RA_TIMEOUT_CONFIG,
	    ra_timeout_config.val);

	/* set routemap 0 and routemap 1 to local */
	wrsm_lc_csr_write(softsp, ADDR_WCI_ROUTE_MAP0, ROUTEMAPRESET);
	wrsm_lc_csr_write(softsp, ADDR_WCI_ROUTE_MAP1, ROUTEMAPRESET);

	/* Perforance counters settings - expand to bit fields later */
	wrsm_lc_csr_write(softsp, ADDR_WCI_CLUSTER_CTR_CTL, 0xff);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_CTR0_MASK, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_CTR0_MATCH, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_CTR0_MATCH_TRANSACTION, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_CTR1_MASK, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_CTR1_MATCH, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_SFI_CTR1_MATCH_TRANSACTION, 0);
	/* Set wci_misc_ctr_ctl to cluster agent */
	wrsm_lc_csr_write(softsp, ADDR_WCI_MISC_CTR_CTL, 0x440);
	wrsm_lc_csr_write(softsp, ADDR_WCI_MISC_CTR, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_LPBK_CTR_CTL, 0x60001);
	wrsm_lc_csr_write(softsp, ADDR_WCI_LPBK_CTR, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_LINK_CTR_CTL, 0x100006);
	wrsm_lc_csr_write(softsp, ADDR_WCI_LINK_CTR, 0);
	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "routemap0 = 0x%"PRIx64" ",
	    *((uint64_t *)(softsp->wrsm_regs + ADDR_WCI_ROUTE_MAP0))));

	/* set first element in board2cnid */
	wrsm_lc_csr_read(softsp, ADDR_WCI_BOARD2CNID_ARRAY,
	    &wci_brd2cnid_array_tmp.val);
	wci_brd2cnid_array_tmp.bit.data = local_cnode;
	/*
	 * This write to wci_board2dnid_array will be ignored on a Starcat
	 * system if jtag-wr_only bit is set in wci_csr_control.
	 */
	wrsm_lc_csr_write(softsp, ADDR_WCI_BOARD2CNID_ARRAY,
	    wci_brd2cnid_array_tmp.val);

	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "brd2cnid.data = 0x%"PRIx64,
	    *((uint64_t *)(softsp->wrsm_regs + ADDR_WCI_BOARD2CNID_ARRAY))));

	/* Disable board2cnid */
	wrsm_lc_csr_read(softsp, ADDR_WCI_BOARD2CNID_CONTROL,
	    &wci_brd2cnid_control.val);
	wci_brd2cnid_control.bit.board2cnid_enable = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_BOARD2CNID_CONTROL,
	    wci_brd2cnid_control.val);

	/* set wnode in wci_config register */
	wrsm_lc_csr_read(softsp, ADDR_WCI_CONFIG, &wci_config_tmp.val);
	wci_config_tmp.bit.node_id = local_wnode;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CONFIG, wci_config_tmp.val);
	/* turn-off cluster_disable -- that is, allow transactions */
	wrsm_lc_csr_read(softsp, ADDR_WCI_CA_CONFIG, &wci_ca_config_tmp.val);
	wci_ca_config_tmp.bit.cluster_disable = 0;
	wci_ca_config_tmp.bit.reuse_timeout_limit = 0x1F;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CA_CONFIG, wci_ca_config_tmp.val);
	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT,
	    "wciINIT ca_config = 0x%"PRIx64,
	    *((uint64_t *)(softsp->wrsm_regs + ADDR_WCI_CA_CONFIG))));
#ifdef DEBUG
	wrsm_lc_csr_write(softsp, ADDR_WCI_CLUSTER_CTR_CTL, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_LPBK_CTR_CTL, 0);
	wrsm_lc_csr_write(softsp, ADDR_WCI_MISC_CTR_CTL, 0);
#endif

	/* Initialize CSRs new to WCI-3 */
	if (softsp->wci_rev >= 30) {
		wrsm_lc_csr_write(softsp,
		    ADDR_WCI_INT_DEST_BUSY_COUNT, 0);
		wrsm_lc_csr_write(softsp,
		    ADDR_WCI_OS_CLUSTER_DISABLE, 0);
		wrsm_lc_csr_write(softsp,
		    ADDR_WCI_SC_CLUSTER_DISABLE, 0);
		/* Initialize GNID maps for loopback */
		wrsm_lc_csr_write(softsp,
		    ADDR_WCI_GNID_MAP0, (uint64_t)0x6db6db6db6db);
		wrsm_lc_csr_write(softsp,
		    ADDR_WCI_GNID_MAP1, (uint64_t)0x6db6db6db6db);
	}


	softsp->local_cnode = local_cnode;
	softsp->local_wnode = local_wnode;
	softsp->num_sram_ecc_errors = 0;
	softsp->last_sram_ecc_errors = 0;
	softsp->max_sram_ecc_errors = 0;
	softsp->avg_sram_ecc_errors = 0;

	wrsm_lc_platform_wciinit(softsp);

	/* Enable the QDL for WCI-3.1 and later */
	if (softsp->wci_rev >= 31) {
		wci_qlim_config_cag_u cag;
		wci_qlim_config_piq_u piq;
		wci_qlim_config_ciq_u ciq;
		wci_qlim_config_niq_u niq;

		wrsm_lc_csr_read(softsp, ADDR_WCI_QLIM_CONFIG_CAG, &cag.val);
		cag.bit.freeze = 0;
		cag.bit.disable = 0;
		wrsm_lc_csr_write(softsp, ADDR_WCI_QLIM_CONFIG_CAG, cag.val);

		wrsm_lc_csr_read(softsp, ADDR_WCI_QLIM_CONFIG_PIQ, &piq.val);
		piq.bit.freeze = 0;
		piq.bit.disable = 0;
		wrsm_lc_csr_write(softsp, ADDR_WCI_QLIM_CONFIG_PIQ, cag.val);

		wrsm_lc_csr_read(softsp, ADDR_WCI_QLIM_CONFIG_CIQ, &ciq.val);
		ciq.bit.freeze = 0;
		ciq.bit.disable = 0;
		wrsm_lc_csr_write(softsp, ADDR_WCI_QLIM_CONFIG_CIQ, ciq.val);

		wrsm_lc_csr_read(softsp, ADDR_WCI_QLIM_CONFIG_NIQ, &niq.val);
		niq.bit.freeze = 0;
		niq.bit.disable = 0;
		wrsm_lc_csr_write(softsp, ADDR_WCI_QLIM_CONFIG_NIQ, niq.val);
	}

	/*
	 * error polling needs to be started here in order to check
	 * esr registers even if no physical links are up. an error
	 * may appear during initialization or a loopback transaction
	 */

	/* already holding lc_mutex */
	if (softsp->suspended) {
		softsp->need_err_timeout = B_TRUE;
	} else {
		softsp->err_timeout_id = timeout((void (*)(void *))
			    wrsm_lc_poll_timeout, softsp, wrsm_poll_hz);
	}

	DPRINTF(LC_DEBUG, (CE_CONT, "POLLING STARTED"
	    " wci %d", softsp->portid));
}


static void
lc_platform_csr_init(wrsm_softstate_t *softsp, wrsm_platform_csr_t *
    csr, wrsm_platform_types_t type)
{
	uint64_t val;
	uint64_t mask;
	int i;

	mask = (uint64_t)csr->mask_hi << 32 | (uint64_t)csr->mask_lo;
	DPRINTF(LC_DEBUG_PLAT, (CE_CONT, "platform_csr_init: offset %lx "
	    "mask %lx shift %d value %d entries %d type %d", csr->offset,
	    mask, csr->shift, csr->plat_values[type], csr->array_entries,
	    type));

	for (i = 0; i < csr->array_entries; ++i) {
		uint64_t offset = csr->offset + (STRIDE_WCI_SRAM_ARRAY * i);

		wrsm_lc_csr_read(softsp, offset, &val);
		val = (val & ~mask) |
		    (((uint64_t)csr->plat_values[type] << csr->shift) & mask);
		wrsm_lc_csr_write(softsp, offset, val);
	}
}

/*
 * Set up WCI CSRs that depend on the cluster node type and/or the
 * network topology.
 */
static void
wrsm_lc_platform_wciinit(wrsm_softstate_t *softsp)
{
	int i;
	uint_t nentries;
	int *conf_values;
	wrsm_platform_csr_t *conf_plat_array;
	wrsm_platform_types_t plat_type;
	wrsm_node_types_t node_type;
	wrsm_topology_t net_type;

	node_type = wrsmplat_get_node_type();
	ASSERT(softsp->config);
	net_type = softsp->config->topology_type;

	switch (node_type) {
	case wrsm_node_serengeti:
	case wrsm_node_wssm:
		switch (net_type) {
		case topology_distributed_switch:
			plat_type = serengeti_direct;
			break;
		case topology_san_switch:
			plat_type = serengeti_wcx;
			break;
		case topology_central_switch:
			plat_type = serengeti_pt;
			break;
		}
		break;
	case wrsm_node_starcat:
		switch (net_type) {
		case topology_distributed_switch:
			plat_type = starcat_direct;
			break;
		case topology_san_switch:
			plat_type = starcat_wcx;
			break;
		case topology_central_switch:
			plat_type = starcat_pt;
			break;
		}
	}

	if (wrsm_cf_cnode_is_switch(softsp->ctlr_config)) {
		plat_type = starcat_switch;
	}

	if (softsp->wci_rev >= 30) {
		for (i = 0; plat_csr_values[i].offset; ++i)
			lc_platform_csr_init(softsp,
			    &plat_csr_values[i], plat_type);
	}

	/*
	 * Give the wrsmplat module an oportunity to make CSR settings
	 * specific to this platform.
	 */
	wrsmplat_wci_init(softsp->wrsm_regs);

	/*
	 * CSR settings which over-ride the defaults can be encoded in
	 * the driver .conf file using the "wci_csr" property.  This
	 * property is array of integers where each set of 12 ints
	 * represents one wrsm_platform_csr_t struct.  This section
	 * should be performed last in WCI initialization so that
	 * settings in the .conf file take priority to those
	 * hard-coded in the driver.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "wci_csr", &conf_values, &nentries) ==
	    DDI_PROP_SUCCESS) {
		uint32_t num_regs;

		DPRINTF(LC_DEBUG, (CE_CONT, "wciinit: got wci_csr % entries",
		    nentries));
		/*
		 * The number of int in the array must be a multiple
		 * of the size of the wrsm_platform_csr_t struct.
		 */
		num_regs = (nentries * sizeof (int)) /
		    sizeof (wrsm_platform_csr_t);

		if ((num_regs * sizeof (wrsm_platform_csr_t)) ==
		    (nentries * sizeof (int))) {

			conf_plat_array = (wrsm_platform_csr_t *)conf_values;
			for (i = 0; i < num_regs; ++i)
				lc_platform_csr_init(softsp,
				    &conf_plat_array[i], plat_type);
		} else {
			cmn_err(CE_WARN, "wrsm_lc_wciinit: illegal array "
			    "length for wci_csr property: %d",
			    nentries);
		}

		ddi_prop_free(conf_values);
	}
}


/*
 * lc_wcifini can ONLY be called by lc_installconfig.
 * lc_wcifini resets some register values to 'clean' values
 * ie. WCI_ROUTE_MAP= LOOPBACK, wci_ca_config.cluster_disable
 * is disabled - that is set BACK to 1, clears cmmu, etc.
 */
static void
wrsm_lc_wcifini(wrsm_softstate_t *softsp)
{
	wci_ca_config_u wci_ca_config_tmp; /* set cluster_disable */
	wci_config_u wci_config_tmp;  /* where node_id (wnodeid) is defined */
	wci_board2cnid_array_u wci_brd2cnid_array_tmp; /* local cnode */
	timeout_id_t err_timeout_id;	/* timeout handle for link polling */
	ASSERT(softsp != NULL);

	mutex_enter(&softsp->lc_mutex);

	err_timeout_id = softsp->err_timeout_id;
	softsp->err_timeout_id = 0;

	mutex_exit(&softsp->lc_mutex);

	/* LINTED: E_NOP_IF_STMT */
	if (untimeout(err_timeout_id) == -1) {
		DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_wcifini"
		    " err_timeout_id not valid"));
	}

	DPRINTF(LC_DEBUG, (CE_CONT, "in wrsm_lc_wcifini wci %d",
	    softsp->portid));

	/* Clear CMMU to make all entries invalid */
	wrsm_lc_clear_cmmu(softsp);

	/* Reset route maps */
	wrsm_lc_csr_write(softsp, ADDR_WCI_ROUTE_MAP0, ROUTEMAPRESET);
	wrsm_lc_csr_write(softsp, ADDR_WCI_ROUTE_MAP1, ROUTEMAPRESET);

	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "routemap0 = 0x%"PRIx64" ",
	    *((uint64_t *)(softsp->wrsm_regs + ADDR_WCI_ROUTE_MAP0))));

	/* enable cluster_disable */
	wci_ca_config_tmp.val = *((uint64_t *)(softsp->wrsm_regs +
	    ADDR_WCI_CA_CONFIG));
	wci_ca_config_tmp.bit.cluster_disable = 1;
	*((uint64_t *)(softsp->wrsm_regs +
	    ADDR_WCI_CA_CONFIG)) = wci_ca_config_tmp.val;
	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "wcifini ca_config = 0x%"PRIx64"",
	    *((uint64_t *)(softsp->wrsm_regs + ADDR_WCI_CA_CONFIG))));

	/* set wnode in wci_config register  to reset value */
	wrsm_lc_csr_read(softsp, ADDR_WCI_CONFIG, &wci_config_tmp.val);
	wci_config_tmp.bit.node_id = 0;
	wrsm_lc_csr_write(softsp, ADDR_WCI_CONFIG, wci_config_tmp.val);

	/* set first element in board2cnid  to 'cleared' value  */
	wrsm_lc_csr_read(softsp, ADDR_WCI_BOARD2CNID_ARRAY,
	    &wci_brd2cnid_array_tmp.val);
	wci_brd2cnid_array_tmp.bit.data = 0;
	/*
	 * This write to wci_board2dnid_array will be ignored on a Starcat
	 * system if jtag-wr_only bit is set in wci_csr_control.
	 */
	wrsm_lc_csr_write(softsp, ADDR_WCI_BOARD2CNID_ARRAY,
	    wci_brd2cnid_array_tmp.val);
	softsp->nc = NULL;
}

/*
 * lc_verifyconfig must be called before any calls to lc_replaceconfig
 * verifies that a new configuration for existing links is not a mismatch
 * returns TRUE if config is GOOD
 */
boolean_t
wrsm_lc_verifyconfig(wrsm_softstate_t *softsp, wrsm_wci_data_t *config)
{
	int i;
	boolean_t config_ok = B_TRUE; /* init to config is good */
	wnodeid_t locwnode_new; /* local wnode - new configuration */

	ASSERT(softsp != NULL);
	ASSERT(softsp->config != NULL);
	ASSERT(config != NULL);
	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "in wrsm_lc_verifyconfig"));

	/* For WCI2, gnids must equal wnodes */
	if (softsp->wci_rev < 30) {
		for (i = 0; i < WRSM_MAX_WNODES; i++) {
			wnodeid_t wnode = config->gnid_to_wnode[i];
			if (wnode < WRSM_MAX_WNODES &&
			    wnode != i) {
				DPRINTF(LC_WARN, (CE_WARN, "For wci2 "
				    "gnids must equal wnodes"));
				config_ok = B_FALSE;
			}
		}
	}

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
		if (softsp->config->links[i].present &&
		    config->links[i].present) {
			/* a valid link that is part of a config */
			gnid_t rgnid_old;
			gnid_t rgnid_new;
			wnodeid_t rwnid_old;
			wnodeid_t rwnid_new;

			rgnid_old = softsp->config->links[i].remote_gnid;
			rgnid_new = config->links[i].remote_gnid;

			if (rgnid_old != rgnid_new) {
				/*
				 * Remote gnid changes. To support changing
				 * gnids, must bring down links. Not yet
				 * supported.
				 */
				config_ok = B_FALSE;
				cmn_err(CE_WARN, "attempt to change gnid "
				    "for wrsm%d link %d", softsp->instance, i);
				continue;
			}

			if (WRSM_GNID_IS_WCX(rgnid_old)) {
				/*
				 * We already know remote gnid isn't
				 * changing. If remote gnid is a switch,
				 * don't need to check for changes in
				 * cnodeids.
				 */
				continue;
			}

			rwnid_old = softsp->config->gnid_to_wnode[rgnid_old];
			rwnid_new = config->gnid_to_wnode[rgnid_new];

			if (rwnid_new >= WRSM_MAX_WNODES) {
				config_ok = B_FALSE;
				cmn_err(CE_WARN, "wci %d link %d: remote gnid "
				    "%d not in reachable list",
				    softsp->instance, i, rgnid_new);
			} else if (rwnid_old != rwnid_new) {
				/* remote wnodeid mismatch */
				config_ok = B_FALSE;
				cmn_err(CE_WARN, "attempt to change wnodeid "
				    "for wrsm%d link %d", softsp->instance, i);
			} else {
				if (!(config->wnode_reachable[rwnid_new]) ||
				    !(softsp->config->wnode_reachable
					[rwnid_old]) ||
				    ((softsp->config->reachable[rwnid_old])
					!= (config->reachable[rwnid_new]))) {
					config_ok = B_FALSE;
					DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_"
					    "verifyconfig bad remote-cnode"
					    " link %d", i));
					cmn_err(CE_WARN, "Invalid"
					    " remote_cnode for wrsm%d link"
					    " %d", softsp->instance, i);
				}
			}
		}
	}
	locwnode_new = config->local_wnode;
	if (softsp->local_wnode == locwnode_new) {
		if (!(config->wnode_reachable[locwnode_new]) ||
		    !(softsp->config->wnode_reachable[softsp->local_wnode]) ||
		    ((softsp->local_cnode) !=
			(config->reachable[locwnode_new]))) {
			config_ok = B_FALSE;
			cmn_err(CE_WARN, "Invalid local_cnode for wrsm%d link"
			    " %d", softsp->instance, i);
		}
	} else { /* wnode mismatch */
		config_ok = B_FALSE;
		DPRINTF(LC_WARN, (CE_WARN, "wrsm_lc_verify"
		    "bad config local-wnode link %d", i));
		cmn_err(CE_WARN, "Invalid local_wnode"
		    "for wrsm%d link %d", softsp->instance, i);
	}
	return (config_ok);
}



/*
 * lc_replaceconfig must be called before a call to lc_cleanconfig
 * and lc_installconfig. lc_verify_config must be called prior to
 * lc_replaceconfig. responsible for initialization required before link
 * takedown and bringup request can be made.
 */
void
wrsm_lc_replaceconfig(wrsm_softstate_t *softsp, ncwci_handle_t nc,
	wrsm_wci_data_t *config, wrsm_controller_t *ctlr_config)
{
	uint64_t i;
	wnodeid_t local_wnode;
	wrsm_wci_data_t *old_config;

	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "in wrsm_lc_replaceconfig - wci %d",
	    softsp->portid));

	ASSERT(softsp != NULL);
	softsp->nc = nc;
	mutex_enter(&softsp->lc_mutex);

	/*
	 * newlink_waitup_cnt is used to count the number of installconfig
	 * initiated link_bringup requests.  It is decremented when a link
	 * reaches lc_up state.
	 *
	 * old_link_waitdown_cnt is used to count the number of cleanconfig
	 * initiated link_takedown request.  It is decremented when a link
	 * reaches lc_down state.
	 */
	softsp->newlink_waitup_cnt = 0;
	softsp->oldlink_waitdown_cnt = 0;
	softsp->ctlr_config = ctlr_config;
	old_config = softsp->config;
	softsp->config = config;
	if ((old_config == NULL) && (config != NULL)) {
		/* first time only initialize links */
		local_wnode = config->local_wnode;
		ASSERT(config->wnode_reachable[local_wnode]);
		/*
		 * tell_mh_link_is_up is needed so that the LC knows when
		 * it is allowed to call mh_link_is_up. On new request, the
		 * LC must wait until lc_enableconfig is called,
		 * lc_enableconfig sets tell_mh_link_is_up to TRUE, and TRUE
		 * is the value that tell_mh_link_is_up remains until
		 * another 'new' bringup link request is made in
		 * lc_installconfig.
		 */
		for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
			softsp->links[i].tell_mh_link_is_up = B_TRUE;
		}
		wrsm_lc_wciinit(softsp, config->reachable[local_wnode],
		    local_wnode);

	}
	if (config != NULL) {
		/* Save local gnid, gnid_to_wnode map for later */
		softsp->local_gnid = config->local_gnid;
		for (i = 0; i < WRSM_MAX_WNODES; i++) {
			softsp->gnid_to_wnode[i] = config->gnid_to_wnode[i];
		}

		/* Update WCI-3 with local gnid and setup dnid2gnid */
		if (softsp->wci_rev >= 30) {
			wci_dnid2gnid_u dnid2gnid;
			wnodeid_t *gnid2dnid;
			wci_sw_config_u sw_config;

			wrsm_lc_csr_read(softsp, ADDR_WCI_SW_CONFIG,
			    &sw_config.val);
			sw_config.bit.gnid = softsp->local_gnid;
			sw_config.bit.partner_gnid = softsp->local_gnid;
			wrsm_lc_csr_write(softsp, ADDR_WCI_SW_CONFIG,
			    sw_config.val);

			dnid2gnid.val = 0;
			gnid2dnid = softsp->config->gnid_to_wnode;
			for (i = 0; i < WRSM_MAX_WNODES; ++i) {
				if (gnid2dnid[i] < WRSM_MAX_WNODES)
					dnid2gnid.val |= i <<
					    (gnid2dnid[i] * 4);
			}
			wrsm_lc_csr_write(softsp, ADDR_WCI_DNID2GNID,
			    dnid2gnid.val);
		}
	}

	mutex_exit(&softsp->lc_mutex);
}


/*
 * initiates takedown link request for any links where the config pointer
 * in the softstate struct is NULL, or the link is marked as not
 * present in the new configuration.
 */
void
wrsm_lc_cleanconfig(wrsm_softstate_t *softsp)
{
	int i;

	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "in wrsm_lc_cleanconfig - wci %d",
	    softsp->portid));
	ASSERT(softsp->oldlink_waitdown_cnt == 0);

	/*
	 * Take down all links not in the config.
	 */
	mutex_enter(&softsp->lc_mutex);
	for (i =  0; i < WRSM_LINKS_PER_WCI; i++) {
		if ((softsp->config == NULL) ||
		    !softsp->config->links[i].present) {
			DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_cleanconfig - "
			    "takedown link %d wci %d", i, softsp->portid));
			wrsm_lc_link_takedown(softsp, i,
			    B_FALSE, B_FALSE);
			/*
			 * All user link down states are discarded when a
			 * link is removed from a config.
			 */
			softsp->links[i].interval_count = 0;
			softsp->links[i].user_down_requested = B_FALSE;
			softsp->links[i].cont_errs = 0;
			softsp->links[i].num_err_takedown = 0;
			softsp->links[i].last_err_takedown = 0;
			softsp->links[i].max_err_takedown = 0;
			softsp->links[i].avg_err_takedown = 0;
			softsp->links[i].num_disconnected_takedown = 0;
			softsp->links[i].num_cfg_takedown = 0;
			softsp->links[i].num_requested_bringups = 0;
			softsp->links[i].num_completed_bringups = 0;
			softsp->links[i].num_errors = 0;
			softsp->links[i].shortterm_errsum = 0;
			softsp->links[i].shortterm_last_errors = 0;
			softsp->links[i].shortterm_max_errors = 0;
			softsp->links[i].shortterm_avg_errors = 0;
			softsp->links[i].longterm_errsum = 0;
			softsp->links[i].longterm_last_errors = 0;
			softsp->links[i].longterm_max_errors = 0;
			softsp->links[i].longterm_avg_errors = 0;
		}
	}

	/*
	 * Calculate which links not in the config are not down yet, and
	 * need to be waited for.
	 */
	for (i =  0; i < WRSM_LINKS_PER_WCI; i++) {
		if ((softsp->config == NULL) ||
		    !softsp->config->links[i].present) {
			if ((softsp->links[i].link_req_state != lc_down) &&
			    (softsp->links[i].link_req_state != lc_not_there)) {
				softsp->oldlink_waitdown_cnt++;
			}
		}
	}
	mutex_exit(&softsp->lc_mutex);
}

/*
 * lc_installconfig waits for all takedown request to be fully completed.
 * This function will bringup up new links and confirms existing link
 * connections.
 */
void
wrsm_lc_installconfig(wrsm_softstate_t *softsp)
{
	int i;

	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "in wrsm_lc_installconfig - wci %d",
	    softsp->portid));

	/*
	 * wait for old links to come down
	 */
	mutex_enter(&softsp->lc_mutex);
	while (softsp->oldlink_waitdown_cnt != 0) {
		DPRINTF(LC_DEBUG, (CE_CONT, "INSTALL IS WAITING"));
		cv_wait(&softsp->goinstallconfig, &softsp->lc_mutex);
	}

	/*
	 * Cancel timeout initiated link bringup - any links we want to
	 * bring for the new config will be brought up now.
	 */
	if (softsp->restart_timeout_id != 0) {
		timeout_id_t restart_timeout_id;

		restart_timeout_id = softsp->restart_timeout_id;
		softsp->restart_timeout_id = 0;
		mutex_exit(&softsp->lc_mutex);

		/* LINTED: E_NOP_IF_STMT */
		if (untimeout(restart_timeout_id) == -1) {
			DPRINTF(LC_DEBUG, (CE_CONT,
			    "wrsm_lc_link_installconfig"
			    " restart_timeout_id not valid"));
		}
	} else {
		mutex_exit(&softsp->lc_mutex);
	}

	if (softsp->config == NULL) {
		/* no new config; clean up and return */
		wrsm_lc_wcifini(softsp);
		return;
	}

	/*
	 * bring up links in new config
	 */

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {

		mutex_enter(&softsp->lc_mutex);

		if (softsp->config->links[i].present) {
			/*
			 * It is important to attempt to bringup links in
			 * sc_wait_down state to allow for uniform
			 * treatment of down states.  Links in
			 * sc_wait_errdown state will already come back up.
			 */
			if ((softsp->links[i].link_req_state == lc_down) ||
			    (softsp->links[i].link_req_state == sc_wait_down)) {
				/*
				 * For any link that is not currently up,
				 * the LC is not allowed to call
				 * mh_link_is_up for this link until
				 * lc_enableconfig is called.
				 */
				softsp->links[i].tell_mh_link_is_up = B_FALSE;
				softsp->newlink_waitup_cnt++;

				DPRINTF(LC_DEBUG_EXTRA, (CE_CONT,
				    "lc_installconfig: new link %d"
				    " newlink_waitup_cnt = %d", i,
				    softsp->newlink_waitup_cnt));

				wrsm_lc_link_bringup(softsp, i);

			} else if (softsp->links[i].link_req_state == lc_up) {
				/* verify remote config data */
				DPRINTF(LC_DEBUG, (CE_CONT, "confirm"
				    " remote config on old link %d", i));
				wrsm_lc_link_bringup(softsp, i);
			}
		}
		mutex_exit(&softsp->lc_mutex);
	}
}

/*
 * calls mh_link_is_up() for each new link requested up in
 * lc_installconfig
 */
void
wrsm_lc_enableconfig(wrsm_softstate_t *softsp)
{
	int i;
	wrsm_gnid_t remote_gnid;
	wnodeid_t remote_wnode;

	DPRINTF(LC_DEBUG_EXTRA, (CE_CONT, "in wrsm_lc_enableconfig - wci %d",
	    softsp->portid));

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {

		mutex_enter(&softsp->lc_mutex);

		if ((softsp->links[i].link_req_state == lc_up) &&
			(!softsp->links[i].tell_mh_link_is_up)) {
			ASSERT(softsp->config->links[i].present);
			DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_enableconfig:"
			    " enable wci %d link %d", softsp->portid, i));
			softsp->links[i].tell_mh_link_is_up = B_TRUE;
			mutex_exit(&softsp->lc_mutex);
			remote_gnid = softsp->config->links[i].remote_gnid;
			remote_wnode = softsp->links[i].remote_wnode;
			/* LINTED: E_NOP_IF_STMT */
			if (WRSM_GNID_IS_WCX(remote_gnid)) {
				DPRINTF(LC_DEBUG, (CE_CONT, "lc_enableconfig"
				    " enable link %d to wcx %d", i,
				    remote_gnid));
			/* LINTED: E_NOP_IF_STMT */
			} else if (remote_wnode >= WRSM_MAX_WNODES) {
				DPRINTF(LC_WARN, (CE_WARN,
				    "Bad remote wnode for wci %d link %d: %d",
				    softsp->portid, i, remote_wnode));
			} else {
				wrsm_mh_link_is_up(softsp->nc, i,
				    remote_wnode);
			}
		} else {
			softsp->links[i].tell_mh_link_is_up = B_TRUE;
			mutex_exit(&softsp->lc_mutex);
		}
	}

	/*
	 * We no longer care about newlink_waitup_cnt. The purpose of
	 * this count is to determine ahead of time that all the
	 * requested links are up and then call nr_all_links_up which will
	 * force the NR into calling lc_enableconfig earlier
	 */
	softsp->newlink_waitup_cnt = 0;
}

safari_port_t
wrsm_lc_get_safid(wrsm_softstate_t *softsp)
{
	ASSERT(softsp != NULL);
	return (softsp->portid);
}

int
wrsm_lc_get_instance(wrsm_softstate_t *softsp)
{
	ASSERT(softsp != NULL);
	return (softsp->instance);
}

/*
 * given dev_id (and box_id from wci_config) get index into cesr
 */
static uint32_t
get_index(wrsm_softstate_t *softsp, uint32_t dev_id)
{
	wci_config_u wci_config_tmp;
	int box_id;
	int index = 0;

	wrsm_lc_csr_read(softsp, ADDR_WCI_CONFIG, &wci_config_tmp.val);
	box_id = (uint32_t)wci_config_tmp.bit.box_id;
	/*
	 * Hardware defines the index into the CESR as follows:
	 * cesr index bit [0] = dev_id bit [0]
	 * cesr index bit [1] = dev_id bit [1]
	 * cesr index bit [2] = dev_id bit [3] | box_id bit [0]
	 * cesr index bit [3] = dev_id bit [4] | box_id bit [1]
	 * cesr index bit [4] = dev_id bit [2] | box_id bit [2]
	 * cesr index bit [5] = box_id bit [3]
	 * cesr index bit [6] = box_id bit [4]
	 * cesr index bit [7] = box_id bit [5]
	 */
	index = (dev_id & 0x3) | ((box_id & 0x3f) << 2);
	index |= BIT(dev_id, 3) << 2;
	index |= BIT(dev_id, 4) << 3;
	index |= BIT(dev_id, 2) << 4;
	return (index);
}

/*
 * returns entire contents of cesr[index] in entry
 */
void
wrsm_lc_cesr_read(wrsm_softstate_t *softsp,  safari_port_t dev_id,
    uint64_t *entry)
{
	uint32_t index;
	index = get_index(softsp, dev_id);

	ASSERT(index <= ENTRIES_WCI_CLUSTER_ERROR_STATUS_ARRAY);
	*entry = *((uint64_t *)(softsp->wrsm_regs +
	    ADDR_WCI_CLUSTER_ERROR_STATUS_ARRAY + (index
		*  STRIDE_WCI_CLUSTER_ERROR_STATUS_ARRAY)));
	DPRINTF(LC_CESR, (CE_NOTE, "read cesr at index=%d, entry = "
	    "0x%"PRIx64, index, *entry));
}

/*
 * writes entire entry to cesr[index]
 */
void
wrsm_lc_cesr_write(wrsm_softstate_t *softsp, safari_port_t dev_id,
    uint64_t entry)
{
	uint32_t index;
	index = get_index(softsp, dev_id);

	ASSERT(index <= ENTRIES_WCI_CLUSTER_ERROR_STATUS_ARRAY);
	*((uint64_t *)(softsp->wrsm_regs + ADDR_WCI_CLUSTER_ERROR_STATUS_ARRAY
	    + (index *  STRIDE_WCI_CLUSTER_ERROR_STATUS_ARRAY))) = entry;
	DPRINTF(LC_CESR, (CE_NOTE, "write cesr at index=%d, entry is"
	    " 0x%"PRIx64"", index, entry));
}

/*
 * reads from register at reg_offset and returns entire register contents
 * in entry
 */
void
wrsm_lc_csr_read(wrsm_softstate_t *softsp, uint64_t reg_offset,
    uint64_t *entry)
{
	/* check for valid offset */
	ASSERT((reg_offset & REGMASK) == 0);
	ASSERT(softsp);
	ASSERT(softsp->wrsm_regs);
	*entry = *((uint64_t *)(softsp->wrsm_regs + reg_offset));

	DPRINTF(LC_CSR_READ_DEBUG, (CE_NOTE, "read csr at reg_offset="
	    "0x%"PRIx64", entry = 0x%"PRIx64, reg_offset, *entry));
}

/*
 * write entire contents of entry at register at reg_offset
 */
void
wrsm_lc_csr_write(wrsm_softstate_t *softsp, uint64_t reg_offset,
    uint64_t entry)
{
	volatile uint64_t *vaddr = (uint64_t *)
	    (softsp->wrsm_regs + reg_offset);
	/* LINTED: E_FUNC_SET_NOT_USED */
	volatile uint64_t readback;

	/* check for valid offset */
	ASSERT((reg_offset & REGMASK) == 0);

	DPRINTF(LC_CSR_WRITE_DEBUG, (CE_NOTE, "write to csr at reg_offset="
	    "0x%"PRIx64", value of 0x%"PRIx64"", reg_offset, entry));

	/* Write to the CSR */
	*vaddr = entry;

	/* Read back to ensure it's stuck in hardware */
	readback = *vaddr;
}

static void
wrsm_lc_poll_timeout(wrsm_softstate_t *softsp)
{
	int link;
	static uint32_t max_wait_count = WRSM_LINK_MAX_WAIT_COUNT;
	boolean_t do_shortterm = B_FALSE;
	clock_t time_now;

	DPRINTF(LC_POLL, (CE_CONT, "in wrsm_lc_poll_timeout"));

	time_now = ddi_get_lbolt();
	if ((time_now - softsp->shortterm_start) >= wrsm_shortterm_hz) {
		DPRINTF(LC_POLL,
		    (CE_CONT, "lc_poll_timeout: do_shortterm"));
		softsp->shortterm_start = time_now;
		do_shortterm = B_TRUE;
	}

	wrsm_lc_err_cnt(softsp, do_shortterm);
	wrsm_lc_check_lockout(softsp);
	wrsm_lc_check_paroli_hotplug(softsp);
	wrsm_lc_check_wcx_links(softsp);

	wrsm_lc_ecc_check(softsp);
	wrsm_lc_sram_ecc_check(softsp, do_shortterm);

	mutex_enter(&softsp->lc_mutex);

	/* Retry send link bringup request periodically */
	if (softsp->ctlr_config) {
		for (link = 0; link < WRSM_LINKS_PER_WCI; link++) {
			switch (softsp->links[link].link_req_state) {
			case sc_wait_up:
				softsp->links[link].waiting_count++;
				if (softsp->links[link].waiting_count <
				    max_wait_count) {
					break;
				}
				DPRINTF(LC_DEBUG, (CE_CONT,
				    "wrsm_lc_poll_timeout: "
				    "retrying link bringup for "
				    "wci %d link %d\n", softsp->portid, link));
				wrsm_lc_link_bringup(softsp, link);
				break;
			case sc_wait_down:
				softsp->links[link].waiting_count++;
				if (softsp->links[link].waiting_count <
				    max_wait_count) {
					break;
				}
				DPRINTF(LC_DEBUG, (CE_CONT,
				    "wrsm_lc_poll_timeout: "
				    "retrying link takedown for "
				    "wci %d link %d\n", softsp->portid, link));
				wrsm_lc_link_takedown(softsp, link, B_FALSE,
				    B_FALSE);
				break;
			case sc_wait_errdown:
				softsp->links[link].waiting_count++;
				if (softsp->links[link].waiting_count <
				    max_wait_count) {
					break;
				}
				DPRINTF(LC_DEBUG, (CE_CONT,
				    "wrsm_lc_poll_timeout: "
				    "retrying link takedown on errors for "
				    "wci %d link %d\n", softsp->portid, link));
				wrsm_lc_link_takedown(softsp, link, B_TRUE,
				    B_FALSE);
				break;
			}
		}
	}
	if (softsp->err_timeout_id) {
		softsp->err_timeout_id = timeout((void (*)(void *))
		    wrsm_lc_poll_timeout, softsp, wrsm_poll_hz);
	}
	mutex_exit(&softsp->lc_mutex);
}


/*
 * Bring back up any links in the config that have been brought down due to
 * prolonged link errors or bad configs.
 */
static void
wrsm_lc_restart_downlinks(wrsm_softstate_t *softsp)
{
	int i;

	if (softsp->restart_timeout_id == 0) {
		return;
	}
	softsp->restart_timeout_id = 0;

	mutex_enter(&softsp->lc_mutex);
	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
		if ((softsp->links[i].link_req_state == lc_down) &&
		    !softsp->links[i].user_down_requested &&
		    (softsp->config != NULL) &&
		    (softsp->config->links[i].present)) {
			wrsm_lc_link_bringup(softsp, i);
		}
	}
	mutex_exit(&softsp->lc_mutex);
}


/*
 * update error statistics used by status kstat
 */
static void
wrsm_lc_update_errstats(wrsm_softstate_t *softsp, int link,
    uint64_t num_errs, boolean_t do_shortterm)
{
	/* update shortterm error monitor */
	softsp->links[link].num_errors += num_errs;
	softsp->links[link].shortterm_errsum += num_errs;
	if (do_shortterm) {
		softsp->links[link].interval_count++;
		softsp->links[link].last_err_takedown =
		    softsp->links[link].err_takedown_sum;
		softsp->links[link].max_err_takedown =
		    MAX(softsp->links[link].max_err_takedown,
		    softsp->links[link].err_takedown_sum);
		softsp->links[link].avg_err_takedown =
		    RUNNING_AVG(softsp->links[link].err_takedown_sum,
			softsp->links[link].avg_err_takedown);
		softsp->links[link].err_takedown_sum = 0;

		softsp->links[link].shortterm_last_errors =
		    softsp->links[link].shortterm_errsum;
		softsp->links[link].shortterm_max_errors =
		    MAX(softsp->links[link].shortterm_max_errors,
		    softsp->links[link].shortterm_errsum);
		softsp->links[link].shortterm_avg_errors =
		    RUNNING_AVG(softsp->links[link].shortterm_errsum,
			softsp->links[link].shortterm_avg_errors);

		/* update longterm error monitor */
		softsp->links[link].longterm_shortterms++;
		softsp->links[link].longterm_errsum +=
		    softsp->links[link].shortterm_errsum;
		if (softsp->links[link].longterm_shortterms ==
		    wrsm_shorts_per_longterm) {
			softsp->links[link].longterm_last_errors =
			    softsp->links[link].longterm_errsum;
			softsp->links[link].longterm_max_errors =
			    MAX(softsp->links[link].longterm_max_errors,
			    softsp->links[link].longterm_errsum);
			softsp->links[link].longterm_avg_errors =
			    RUNNING_AVG(
				softsp->links[link].longterm_errsum,
				softsp->links[link].longterm_avg_errors);
			softsp->links[link].longterm_errsum = 0;
			softsp->links[link].longterm_shortterms = 0;

		}
		softsp->links[link].shortterm_errsum = 0;
	}
}


/*
 * wrsm_lc_err_cnt checks and clears the link error count register:
 *	wci_sw_link_error_count
 * wrsm_sw_link_error_count is and array of NUM_LINKS =
 * ENTRIES_WCI_SW_LINK_ERROR_COUNT = 3
 * SC controls:
 *    wci_sw_link_control_u.near_end_shutdown_lock (bit 4) should be set
 *    wci_sw_link_control_u.auto_shut_en set to enable hardware to shut
 *    down link. (bit 2) (default is NOT enabled)
 */
static void
wrsm_lc_err_cnt(wrsm_softstate_t *softsp, boolean_t do_shortterm)
{
	wci_sw_link_error_count_u   reg;
	wci_sw_esr_u sw_esr;
	int i;
	wci_sw_link_control_u sw_link_ctrl;
	boolean_t acc_auto_shut[WRSM_LINKS_PER_WCI];
	wci_sw_link_status_u status;
	uint64_t num_errs;
	boolean_t takedown_link;


	/*
	 * We enable auto link shutdown in cluster mode; because of this,
	 * we must check the accumulated auto_shut bits to test for a
	 * hardware shutdown.
	 *
	 * Read registers associated with HW shutdown.
	 */
	wrsm_lc_csr_read(softsp, ADDR_WCI_SW_ESR, &sw_esr.val);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SW_LINK_CONTROL,
	    &sw_link_ctrl.val);
	acc_auto_shut[0] = sw_esr.bit.acc_link_0_auto_shut;
	acc_auto_shut[1] = sw_esr.bit.acc_link_1_auto_shut;
	acc_auto_shut[2] = sw_esr.bit.acc_link_2_auto_shut;


	/*
	 * Because this is a toggle/write register, in order to only set
	 * the bit field in question we must first set all fields to 0 so
	 * that we don't inadvertently toggle write a bit field other than
	 * the one(s) in question.
	 */
	sw_esr.val = 0;

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {

		mutex_enter(&softsp->lc_mutex);
		wrsm_lc_csr_read(softsp, (ADDR_WCI_SW_LINK_STATUS +
		    (i * STRIDE_WCI_SW_LINK_STATUS)), &status.val);
		/* only check on links that are already up */
		if (softsp->links[i].link_req_state != lc_up) {
			wrsm_lc_update_errstats(softsp, i, 0, do_shortterm);
			mutex_exit(&softsp->lc_mutex);
			continue;
		}

		takedown_link = B_FALSE;

		/*
		 * Check if link has been auto-shutdown.  If so, we still
		 * need to turn off lasers, etc, so still must call
		 * wrsm_lc_link_takedown().
		 */
		if (acc_auto_shut[i]) {

			softsp->links[i].cont_errs++;
			if (status.bit.paroli_present != WCI_PAROLI_PRESENT) {
				/* paroli removed while in use */
				cmn_err(CE_NOTE, "wci %d link %d "
				    "removed from service while in use",
				    softsp->portid, i);
				lc_link_takedown_all(softsp, i);
				softsp->links[i].link_req_state = lc_not_there;
			} else {
				takedown_link = B_TRUE;
			}
			/*
			 * If link is configured and session is in
			 * progress, report this link down event.
			 * Otherwise don't; the link_down reason will be
			 * reported as unconfigured.
			 */
			if ((softsp->config != NULL) &&
			    (softsp->config->links[i].present)) {
				if ((softsp->links[i].remote_wnode >=
				    WRSM_MAX_WNODES) ||
				    wrsm_nr_session_up(softsp->nc,
				    softsp->links[i].remote_wnode)) {
					wrsm_lc_logevent(softsp,
					    link_down, i,
					    "hardware-shutdown");
					softsp->links[i].num_err_takedown++;
					softsp->links[i].err_takedown_sum++;
				} else {
					/*
					 * no session, link was probably
					 * shutdown at remote end
					 */
					wrsm_lc_logevent(softsp,
					    link_down, i,
					    "disconnected-shutdown");
					softsp->links[i].
					    num_disconnected_takedown++;
				}
			}

			/*
			 * We clear the acc_auto_shut bit in wci_sw_esr so
			 * that the LC can use it to detect the next
			 * hardware shutdown.  This register is a
			 * toggle/write register, so we must write 1 in
			 * order to clear the bit.
			 *
			 * reset - bit fields are not arrays:
			 * acc_link_0 bit field 20
			 * acc_link_1 bit field 21
			 * acc_link_2 bit field 22
			 */
			sw_esr.val |= ((uint64_t)1 << (20 + i));
		}

		/*
		 * Check the link error counter to see if link
		 * should be shutdown by hand, and to clear
		 * any errors.
		 */

		reg.val = *softsp->links[i].wrsm_link_err_cnt_addr;
		num_errs = reg.bit.error_count;
		softsp->wci_common_softst.
		    wci_sw_link_error_count_sum[i] += num_errs;

		if (!takedown_link && (num_errs >= MAXERRORS) &&
		    (softsp->links[i].link_req_state == lc_up)) {
			DPRINTF(LC_WARN, (CE_WARN,
			    "wrsm%d: err cnt = %"PRIx64" too high"
			    " on link %d", softsp->instance,
			    num_errs, i));
			softsp->links[i].cont_errs++;
			/*
			 * If link is configured, report this link down
			 * event.  Otherwise don't; the link_down reason
			 * will be reported as unconfigured.
			 */
			if ((softsp->config != NULL) &&
			    (softsp->config->links[i].present)) {
				if ((softsp->links[i].remote_wnode >=
				    WRSM_MAX_WNODES) ||
				    wrsm_nr_session_up(softsp->nc,
				    softsp->links[i].remote_wnode)) {
					wrsm_lc_logevent(softsp,
					    link_down, i,
					    "link-errors");
					softsp->links[i].num_err_takedown++;
					softsp->links[i].err_takedown_sum++;
				} else {
					/*
					 * no session, link was probably
					 * shutdown at remote end
					 */
					wrsm_lc_logevent(softsp,
					    link_down, i,
					    "disconnected-shutdown");
					softsp->links[i].
					    num_disconnected_takedown++;
				}
			}
			takedown_link = B_TRUE;
		}

		if (!takedown_link) {
			/*
			 * No link problem during this
			 * round.
			 */
			softsp->links[i].cont_errs = 0;
		}

		/* take down link if needed */
		if (takedown_link) {
			wrsm_lc_link_takedown(softsp, i,
			    B_TRUE, B_FALSE);
		}

		/*
		 * Link error counter and error status registers
		 * must be cleared if any link errors have occured.
		 */
		if (num_errs > 0) {
			reg.bit.error_count = 0;
			*softsp->links[i].wrsm_link_err_cnt_addr = reg.val;

			/* write back to clear error bits */
			wrsm_lc_csr_write(softsp, (ADDR_WCI_SW_LINK_STATUS +
				(i * STRIDE_WCI_SW_LINK_STATUS)), status.val);
			if (wrsm_log_link_errors) {
				cmn_err(CE_NOTE, "wci %u link %d, "
				    "wci_sw_link_error_count = %lu, "
				    "wci_sw_link_error_sum = %lu, "
				    "crc = %ld, framing = %ld, clocking = %ld",
				    softsp->portid, i, num_errs,
				    softsp->wci_common_softst.
				    wci_sw_link_error_count_sum[i],
				    status.bit.crc_error,
				    status.bit.framing_error,
				    status.bit.clocking_error);
			}
		}

		if (takedown_link) {
			/*
			 * Don't count links errors that caused a link
			 * takedown in link_errors counter; they are
			 * counted in the takedown counters.
			 */
			num_errs = 0;
		}
		wrsm_lc_update_errstats(softsp, i, num_errs, do_shortterm);
		mutex_exit(&softsp->lc_mutex);
	}

	/* Toggle auto_shut bits back to reset mode */
	wrsm_lc_csr_write(softsp, ADDR_WCI_SW_ESR, sw_esr.val);
}

static void
wrsm_lc_check_lockout(wrsm_softstate_t *softsp)
{
	wci_ra_esr_1_u ra_esr_1;
	wci_ra_write_lockout_status_u status;

	wrsm_lc_csr_read(softsp, ADDR_WCI_RA_ESR_1, &ra_esr_1.val);
	if (ra_esr_1.bit.acc_write_lockout) {
		DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_check_lockout ra_esr_1"
		    " 0x%"PRIx64, ra_esr_1.val));

		/* First clear the esr bit */
		wrsm_lc_csr_read(softsp, ADDR_WCI_RA_WRITE_LOCKOUT_STATUS,
		    &status.val);
		ra_esr_1.val = 0;
		ra_esr_1.bit.acc_write_lockout = 1;
		wrsm_lc_csr_write(softsp, ADDR_WCI_RA_ESR_1, ra_esr_1.val);

		/* Next do the special read from page 1 */
		wrsm_nr_clear_lockout(softsp->nc,
		    (ncslice_t)status.bit.nc_slice);

		/* clear the esr again, if necessary */
		wrsm_lc_csr_read(softsp, ADDR_WCI_RA_ESR_1, &ra_esr_1.val);
		if (ra_esr_1.bit.acc_write_lockout) {
			ra_esr_1.val = 0;
			ra_esr_1.bit.acc_write_lockout = 1;
			wrsm_lc_csr_write(softsp, ADDR_WCI_RA_ESR_1,
			    ra_esr_1.val);
		}

#ifdef DEBUG
		wrsm_lc_csr_read(softsp, ADDR_WCI_RA_WRITE_LOCKOUT_STATUS,
		    &status.val);
		DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_check_lockout: status"
		    " slice %lu stripe %lu", status.bit.nc_slice,
		    status.bit.link_stripe));
#endif
		/* For good measure, clear the status register too */
		wrsm_lc_csr_write(softsp, ADDR_WCI_RA_WRITE_LOCKOUT_STATUS, 0);
	}
}


/*
 * In the event the SC should crash while messages were between
 * the SC and the mailbox, the SC will have no way of knowing what
 * messages were lost. In this event, the SC sends a 'I am Here"
 * message. When the LC gets this it knows the SC crashed. This function
 * resends all messages in the sc_waitxxx state to the SC, and resends
 * request to set LEDs off or On depending on if the link is lc_down or lc_up
 */
void
wrsm_lc_sc_crash(wrsm_softstate_t *softsp)
{
	int i;

	if (softsp == NULL) {
		/* invalid arg */
		DPRINTF(LC_WARN, (CE_WARN, "wrsm_lc_sc_crash "
		    "invalid softsp"));
		return;
	}
	mutex_enter(&softsp->lc_mutex);
	if (softsp->suspended) {
		mutex_exit(&softsp->lc_mutex);
		return;
	}

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
		if (softsp->links[i].link_req_state == sc_wait_up) {
			DPRINTF(LC_DEBUG, (CE_CONT, "crash UPLINK"));
			softsp->links[i].num_requested_bringups++;
			softsp->links[i].waiting_count = 0;
			(void) wrsmplat_uplink(softsp->portid,
			    (linkid_t)i, softsp->local_gnid,
			    softsp->ctlr_config->fmnodeid,
			    softsp->ctlr_config->version_stamp,
			    softsp->ctlr_config->controller_id,
			    B_FALSE /* loopback */);
		} else if ((softsp->links[i].link_req_state ==
		    sc_wait_down) || (softsp->links[i].link_req_state
			== sc_wait_errdown)) {
			DPRINTF(LC_DEBUG, (CE_CONT, "crash DOWNLINK"));
			softsp->links[i].waiting_count = 0;
			(void) wrsmplat_downlink(softsp->portid,
			    (linkid_t)i, B_FALSE);
		}
	}
	mutex_exit(&softsp->lc_mutex);
}

static void
wrsm_lc_clear_cmmu(wrsm_softstate_t *softsp)
{
	int i;
	wrsm_cmmu_t cmmu;
	const int numcmmu_entries = wrsm_lc_num_cmmu_entries_get(softsp);
#ifdef DEBUG
	const uint32_t debug_flags = wrsm_lc_debug; /* Save original state */
	wrsm_lc_debug &= ~LC_CMMU; /* Turn off the LC_CMMU flag, if it's set */
#endif /* DEBUG */

	cmmu.entry_0.val = 0;
	cmmu.entry_1.val = 0;
	for (i = 0; i < numcmmu_entries; i++) {
		wrsm_lc_cmmu_update(softsp, &cmmu, i,
		    CMMU_UPDATE_WRITEONLY);
	}

#ifdef DEBUG
	wrsm_lc_debug = debug_flags; /* Restore to original settings */
#endif /* DEBUG */
}

void
wrsm_lc_cmmu_update(wrsm_softstate_t *softsp, wrsm_cmmu_t  *entry,
    uint32_t index, wrsm_cmmu_flags_t  flags)
{
	wrsm_cmmu_t tmp_entry;
	uint64_t entry0_addr;
	uint64_t entry1_addr;
	boolean_t prev_valid_bit_value; /* previous value for valid bit */
	volatile uint64_t *cluster_syncp;
	wci_cluster_sync_u cluster_sync;
	/* LINTED: E_FUNC_SET_NOT_USED */
	volatile uint64_t readback;

	ASSERT(softsp != NULL);

	DPRINTF(LC_CMMU, (CE_NOTE,
	    "lc_cmmu_update(wci %d, index=%u, entry0=0x%08lX, "
	    "entry1=0x%08lX, flags=0x%04X)", softsp->portid,
	    index, entry->entry_0.val, entry->entry_1.val, flags));

	/* Don't write off the end of the CMMU sram */
	if (index >= wrsm_lc_num_cmmu_entries_get(softsp)) {
		return;
	}

	/*
	 * Note cmmu_entry0 and cmmu_entry1 are interleaved.
	 * Because of this each Index for an entry is spaced 0x40
	 * apart from the previous one.
	 * The initial physical address starts where cmmu_entry0 begins,
	 * because of the cmmu_entry1 must always be offset by an
	 * additional 20 from the base of softsp->cmmu_addr
	 */
	entry0_addr = (uint64_t)((softsp->wrsm_sram) +
		(index * 2 * STRIDE_WCI_SRAM_ARRAY));
	entry1_addr = entry0_addr + STRIDE_WCI_SRAM_ARRAY;

	/* used to inject SRAM ECC errors into CMMU entries by cmmu injector */
	if (flags & CMMU_UPDATE_WRITEONLY) {
		/* write full values */
		STOREPHYS(entry->entry_1.val, entry1_addr);
		STOREPHYS(entry->entry_0.val, entry0_addr);
		DPRINTF(LC_CMMU, (CE_NOTE, "wrsm_lc_cmmu_update(index=%u) "
		    "clean write to cmmu, no read back", index));
		return;
	}
	if (flags & CMMU_UPDATE_WRITE_0) {
		/* write full value 0 */
		STOREPHYS(entry->entry_0.val, entry0_addr);
		DPRINTF(LC_CMMU, (CE_NOTE, "wrsm_lc_cmmu_update(index=%u) "
		    "clean write to cmmu entry 1, no read back", index));
		return;
	}
	if (flags & CMMU_UPDATE_WRITE_1) {
		/* write full value 1 */
		STOREPHYS(entry->entry_1.val, entry1_addr);
		DPRINTF(LC_CMMU, (CE_NOTE, "wrsm_lc_cmmu_update(index=%u) "
		    "clean write to cmmu entry 0, no read back", index));
		return;
	}

	/* store value for entry 0 in tmp_entry */
	LOADPHYS(tmp_entry.entry_0.val, entry0_addr);


	/*
	 * Set the cmmu entry to invalid so that the separate update of each
	 * half of the entry doesn't end up creating a strange state.
	 *
	 * Only need to clear the valid bit IF both entries need to change
	 * and the valid bit was set and the user error bit wasn't.
	 */
	prev_valid_bit_value = tmp_entry.entry_0.bit.valid; /* needed later */
	if (tmp_entry.entry_0.bit.valid &&
	    !tmp_entry.entry_0.bit.user_err) {
		tmp_entry.entry_0.bit.valid = B_FALSE;
		STOREPHYS(tmp_entry.entry_0.val, entry0_addr);
	}

	LOADPHYS(tmp_entry.entry_1.val, entry1_addr);


	if (flags == CMMU_UPDATE_ALL) {
		/*
		 * Use passed in values for all fields.
		 *
		 * Set entry 1, then entry 0 of the cmmu entry to the
		 * passed in values.  Entry 0 is updated second in order to
		 * leave the valid bit set to false until the update of
		 * both halves is complete.
		 */
		STOREPHYS(entry->entry_1.val, entry1_addr);
		STOREPHYS(entry->entry_0.val, entry0_addr);
		DPRINTF(LC_CMMU, (CE_NOTE, "lc_cmmu_update entry1"
		    " addr 0x%"PRIx64", entry value = 0x%"PRIx64,
		    (uint64_t)(entry1_addr), entry->entry_1.val));
		DPRINTF(LC_CMMU, (CE_NOTE, "lc_cmmu_update entry0"
		    " addr 0x%"PRIx64", entry value = 0x%"PRIx64,
		    (uint64_t)(entry0_addr), entry->entry_0.val));
	} else {
		/*
		 * Update tmp_entry with the appropriate fields, then set
		 * entry 1 followed by entry 0 of the cmmu entry to the
		 * values in tmp_entry.  Entry 0 is updated second in order
		 * to leave the valid bit set to false until the update of
		 * both halves is complete.
		 */
		if (flags & CMMU_UPDATE_MONDO) {
			tmp_entry.entry_1.intr.mondo =
			    entry->entry_1.intr.mondo;
		}
		if (flags & CMMU_UPDATE_FROMNODE) {
			tmp_entry.entry_0.bit.from_node =
			    entry->entry_0.bit.from_node;
		}
		if (flags & CMMU_UPDATE_TYPE) {
			tmp_entry.entry_0.bit.type = entry->entry_0.bit.type;
		}
		if (flags & CMMU_UPDATE_WRITABLE) {
			tmp_entry.entry_0.bit.writable =
			    entry->entry_0.bit.writable;
		}
		if (flags & CMMU_UPDATE_USERERROR) {
			tmp_entry.entry_0.bit.user_err =
			    entry->entry_0.bit.user_err;
		}
		if (flags & CMMU_UPDATE_FROMALL) {
			tmp_entry.entry_0.bit.from_all =
			    entry->entry_0.bit.from_all;
		}
		if (flags & CMMU_UPDATE_LARGEPAGE) {
			tmp_entry.entry_0.bit.large_page =
			    entry->entry_0.bit.large_page;
		}
		if (flags & CMMU_UPDATE_ENABLEPERF) {
			tmp_entry.entry_0.bit.count_enable =
			    entry->entry_0.bit.count_enable;
		}
		if (flags & CMMU_UPDATE_VALID) {
			tmp_entry.entry_0.bit.valid = entry->entry_0.bit.valid;
		} else { /* set back to original value */
			tmp_entry.entry_0.bit.valid = prev_valid_bit_value;
		}

		/*
		 * Only allowed to set either the LPA or the INTRDEST fields,
		 * but not both.  (These fields overlap.)
		 */
		ASSERT(!((flags & CMMU_UPDATE_LPA) &&
		    flags & CMMU_UPDATE_INTRDEST));
		if (flags & CMMU_UPDATE_LPA) {
			tmp_entry.entry_1.addr.lpa_page =
			    entry->entry_1.addr.lpa_page;
		} else if (flags & CMMU_UPDATE_INTRDEST) {
			tmp_entry.entry_1.intr.lpa_page_2 =
			    entry->entry_1.intr.lpa_page_2;
		}
		STOREPHYS(tmp_entry.entry_1.val, entry1_addr);
		STOREPHYS(tmp_entry.entry_0.val, entry0_addr);
		DPRINTF(LC_CMMU, (CE_NOTE, "lc_cmmu_update entry1"
		    "addr  0x%"PRIx64", entry value = 0x%"PRIx64,
		    (uint64_t)(entry1_addr), tmp_entry.entry_1.val));
		DPRINTF(LC_CMMU, (CE_NOTE, "lc_cmmu_update entry0"
		    " addr 0x%"PRIx64", entry value = 0x%"PRIx64,
		    (uint64_t)(entry0_addr), tmp_entry.entry_0.val));
	}

	/* readback to assure the write to hardware occured */
	LOADPHYS(readback, entry0_addr);
	LOADPHYS(readback, entry1_addr);


	if (flags & CMMU_UPDATE_FLUSH) {

		/* grab lock so only one thread at a time has access */
		mutex_enter(&softsp->cmmu_mutex);
		cluster_syncp = (uint64_t *)
		    (softsp->wrsm_regs + ADDR_WCI_CLUSTER_SYNC);
		cluster_sync.val = *cluster_syncp;

		/*
		 * setting sync_in_progress tells the hardware to do
		 * CMMU flush. once the hardware has set sync_in_progress
		 * back to 0 AND there aren't any cag_busy bits set
		 * we can considered the CMMU successfully FLUSHED.
		 */
		cluster_sync.bit.sync_in_progress = 1;
		cluster_sync.bit.cag_busy = 0;
		*cluster_syncp = cluster_sync.val;
		while (cluster_sync.val) {
			DPRINTF(LC_CMMU, (CE_NOTE, "lc_cmmu_update "
			    " CMMU_UPDATE_FLUSH addr %p wci_cluster_sync "
			    "0x%lx has is waiting on hardware to respond",
			    (void *)cluster_syncp, cluster_sync.val));

			cluster_sync.val = *cluster_syncp;
		};
		mutex_exit(&softsp->cmmu_mutex);
	}
}

void
wrsm_lc_cmmu_read(wrsm_softstate_t *softsp, wrsm_cmmu_t *cmmu_entry,
    uint32_t index)
{
	uint64_t entry0_offset;
	uint64_t entry1_offset;

	ASSERT(softsp != NULL);

	/* Don't read beyond the end of the CMMU sram */
	if (index >= wrsm_lc_num_cmmu_entries_get(softsp)) {
		cmmu_entry->entry_0.val = 0;
		cmmu_entry->entry_1.val = 0;
		return;
	}

	/*
	 * Note cmmu_entry0 and cmmu_entry1 are interleaved.
	 * Because of this each Index for an entry is spaced 0x40
	 * apart from the previous one.
	 * The initial physical address starts where cmmu_entry0 begins,
	 * because of the cmmu_entry1 must always be offset by an
	 * additional 20 from the base of softsp->cmmu_addr
	 */
	entry0_offset = index * 2 * STRIDE_WCI_SRAM_ARRAY;
	entry1_offset = STRIDE_WCI_SRAM_ARRAY +
	    (index * 2 * STRIDE_WCI_SRAM_ARRAY);
	LOADPHYS(cmmu_entry->entry_0.val, softsp->wrsm_sram + entry0_offset);
	LOADPHYS(cmmu_entry->entry_1.val, softsp->wrsm_sram + entry1_offset);

	DPRINTF(LC_CMMU, (CE_NOTE, "wrsm_lc_cmmu_read(index=%u) = "
	    "0x%016lX 0x%016lX", index, cmmu_entry->entry_0.val,
	    cmmu_entry->entry_1.val));

	if (cmmu_entry->entry_0.bit.error) {
		cmn_err(CE_WARN, "wci %d sram uncorrectable error "
		    "(0x%016lX) index %u entry 0", softsp->portid,
		    cmmu_entry->entry_0.val, index);
	}
	if (cmmu_entry->entry_1.addr.error) {
		cmn_err(CE_WARN, "wci %d sram uncorrectable error "
		    "(0x%016lX) index %u entry 1", softsp->portid,
		    cmmu_entry->entry_1.val, index);
	}
}

int
wrsm_lc_num_cmmu_entries_get(wrsm_softstate_t *softsp)
{
	int num_entries;
	int max_usable_entries = wrsm_cmmu_max_entries;
	ASSERT(softsp != NULL);

	num_entries = min(max_usable_entries,
	    ((int)softsp->sramsize) / ((int)(2 * STRIDE_WCI_SRAM_ARRAY)));
	return (num_entries);
}


/* The following is for the interrupt trap handler only */
caddr_t
wrsm_lc_get_sram_paddr(wrsm_softstate_t *softsp)
{
	/* phsyical addr used to access wci */
	return ((caddr_t)softsp->wrsm_sram);
}

/*
 * The following function is used to emulate a response from the sc
 */
void
get_remote_config_data(safari_port_t wci_id, uint32_t link_num,
    fmnodeid_t *remote_fmnodeid, gnid_t *remote_gnid, linkid_t *remote_link,
    safari_port_t *remote_port, volatile uchar_t **wrsm_regs)
{
	wrsm_softstate_t *softsp = NULL;
	boolean_t simwci;

	softsp = wrsm_cf_lookup_wci(wci_id);
	if (softsp == NULL) {
		DPRINTF(LC_WARN, (CE_CONT, "get_remote_config_data: "
		    "could not get softsp"));
		return;
	}

	simwci = (boolean_t)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "simwci", 0);

	DPRINTF(LC_DEBUG, (CE_CONT,
	    "get_remote_config_data: wci %d sim %d regs %p",
	    wci_id, simwci, (void *)softsp->wrsm_regs));

	if (softsp->config != NULL && softsp->ctlr_config != NULL) {
		*remote_fmnodeid = softsp->ctlr_config->fmnodeid;
		*remote_gnid = softsp->config->links[link_num].remote_gnid;
		*remote_link = softsp->config->links[link_num].remote_link_num;
		*remote_port = softsp->config->links[link_num].remote_port;
	}
	if (simwci)
		*wrsm_regs = NULL;
	else
		*wrsm_regs = softsp->wrsm_regs;
}

/*
 * lc_check_paroli_hotplug is called from wrsm_lc_poll_timeout to check
 * occasionally if a paroli has been hot pluged.
 */
static void
wrsm_lc_check_paroli_hotplug(wrsm_softstate_t *softsp)
{
	int i;
	wci_sw_link_status_u wci_sw_link_status;

	for (i = 0; i < WRSM_LINKS_PER_WCI; i++) {
		wrsm_lc_csr_read(softsp, (ADDR_WCI_SW_LINK_STATUS +
		    (i * STRIDE_WCI_SW_LINK_STATUS)), &wci_sw_link_status.val);
		/*
		 * if state is both not_there and a paroli has been detected
		 * this is hotpluged link. Check if part of a config
		 * and try to bring up.
		 */
		if ((softsp->links[i].link_req_state ==
		    lc_not_there) && (wci_sw_link_status.bit.paroli_present
			== WCI_PAROLI_PRESENT)) {
			/*
			 * No check for simwci needed since we don't use the
			 * not_there state for simwci's.
			 */
			mutex_enter(&softsp->lc_mutex);
			softsp->links[i].link_req_state = lc_down;

			if ((softsp->config != NULL) &&
			    (softsp->config->links[i].present)) {
				DPRINTF(LC_WARN, (CE_NOTE,
				    "lc_check_paroli_hotplug: paroli detected"
				    ": wrsm%d port id#%u, link#%d",
				    softsp->instance, softsp->portid, i));
				/* link is part of a config - bring it up */
				wrsm_lc_link_bringup(softsp, i);
			}
			mutex_exit(&softsp->lc_mutex);
		}
	}
}

static void
wrsm_lc_check_wcx_links(wrsm_softstate_t *softsp)
{
	int i, gnid;
	wci_sw_link_status_u link_status;
	uint16_t active_diff;
	link_t *link;

	/* If WCI is not part of a controller, abort */
	if (softsp->config == NULL) {
		return;
	}

	for (i = 0; i < WRSM_LINKS_PER_WCI; ++i) {
		link = &softsp->links[i];

		DPRINTF(LC_POLL, (CE_CONT, "check_wcx_links: link %d "
		    "state %d remote wnode %d", i, link->link_req_state,
		    link->remote_wnode));

		/*
		 * Look for links that are up and connected to a WCX
		 */
		if ((link->link_req_state != lc_up) ||
		    (!WRSM_GNID_IS_WCX(softsp->links[i].remote_wnode)))
			continue;

		DPRINTF(LC_POLL, (CE_CONT, "check_wcx_links: link %d "
		    "tell_mh %d", i, link->tell_mh_link_is_up));

		/*
		 * If it's not ok to call mh, just skip this link,
		 * the status bits will still be there later.
		 */
		if (!link->tell_mh_link_is_up)
			continue;

		/*
		 * farend_ustat1 contains a bitmask of other gnids which
		 * are reachable through the WCX at the remote end of this link
		 */
		wrsm_lc_csr_read(softsp, ADDR_WCI_SW_LINK_STATUS +
		    (i * STRIDE_WCI_SW_LINK_STATUS), &link_status.val);
		active_diff = link->remote_gnids_active ^
		    link_status.bit.farend_ustat_1;

		DPRINTF(LC_POLL, (CE_CONT, "check_wcx_links: ustat1 %d",
		    link_status.bit.farend_ustat_1));

		if (active_diff) {

			DPRINTF(LC_DEBUG, (CE_CONT, "check_wcx_links: "
			    "changed reachable 0x%x old 0x%x", active_diff,
			    link->remote_gnids_active));

			for (gnid = 0; gnid < WRSM_MAX_WNODES; ++gnid) {
				uint16_t mask = 1<<gnid;
				wnodeid_t remote_wnode;

				if (gnid == softsp->local_gnid)
					continue;

				if (!(active_diff & mask))
					continue;

				remote_wnode = softsp->gnid_to_wnode[gnid];
				/*
				 * Make sure that the indicated gnid is
				 * actually in the current config.
				 */
				if (remote_wnode >= WRSM_MAX_WNODES) {
					DPRINTF(LC_DEBUG, (CE_CONT,
					    "check_wcx_links: bad active "
					    "gnid from switch %d", gnid));
					continue;
				}

				/* new gnid reachable */
				if (link_status.bit.farend_ustat_1 & mask) {
					wrsm_mh_link_is_up(softsp->nc, i,
					    remote_wnode);
					link->remote_gnids_active |= mask;
					continue;
				}

				/* previously reachable gnid now gone */
				if (link->remote_gnids_active & mask) {
					wrsm_mh_link_is_down(softsp->nc, i,
					    remote_wnode);
					link->remote_gnids_active &= ~mask;
					continue;
				}
			}
		}
	}
}

/*
 * Checks and handles ECC errors noted by the driver
 *
 * correctable errors are noted and if possible corrected
 * uncorrectable errors cause a trap
 *
 */
void
wrsm_lc_ecc_check(wrsm_softstate_t *softsp)
{

	wci_dco_ce_count_u wci_dco_ce_count;
	wci_dc_esr_u wci_dc_esr, wci_dc_esr_clear;
	wci_dco_state_u wci_dco_state;

	wci_ra_esr_1_u wci_ra_esr_1, wci_ra_esr_1_clear;
	wci_ca_esr_0_u wci_ca_esr_0, wci_ca_esr_0_clear;

	wci_ra_ecc_address_u wci_ra_ecc_addr;
	wci_ca_ecc_address_u wci_ca_ecc_addr;

	struct async_flt ecc;

	wci_dco_ce_count.val = *softsp->wci_dco_ce_cnt_vaddr;
	wci_dc_esr.val = *softsp->wci_dc_esr_vaddr;
	wci_dco_state.val = (uint64_t)*softsp->wci_dco_state_vaddr;

	wci_ra_esr_1.val = *softsp->wci_ra_esr_1_vaddr;
	wci_ca_esr_0.val = *softsp->wci_ca_esr_0_vaddr;

	wci_ra_esr_1_clear.val = 0;
	wci_ca_esr_0_clear.val = 0;
	wci_dc_esr_clear.val = 0;

	wci_ra_ecc_addr.val =  *softsp->wci_ra_ecc_addr_vaddr;
	wci_ca_ecc_addr.val =  *softsp->wci_ca_ecc_addr_vaddr;

	/*
	 * Request Agent Mtag UE
	 *
	 * need to check that there is an uncorrectable error,
	 * and the address logged is not data [mtag],
	 * and the address logged is for ue [not ce]
	 */
	if (wci_ra_esr_1.bit.acc_uncorrectable_mtag_error &&
	    !wci_ra_ecc_addr.bit.data && wci_ra_ecc_addr.bit.ue) {

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: RA Mtag UE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.mtag_ecc_error_aid &
		    REQ_CLUSTER_MASK) == REQUEST_AGENT_MASK) &&
		    wci_dco_state.bit.mtag_ecc_ue) {
			ecc.flt_synd = WCI_MTAG_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}

		/*
		 * wci_ra_ecc_addr_tmp.bit.addr <42:4> is over
		 * bit 31 boundary (32/64 bit).
		 */
		ecc.flt_addr = wci_ra_ecc_addr.bit.addr << 4;
		ecc.flt_stat = RA_ECC_MTAG_UE;
		wrsm_handle_ue_error(softsp, &ecc, REQUEST_AGENT);
		/*
		 * clear wci_ra_esr_1  acc_uncorrectable_mtag_error bit
		 * The bit type is RW1TX, i.e.toggle, thus it needs to be
		 * set 1 to be cleared.
		 *
		 */
		wci_ra_esr_1_clear.bit.acc_uncorrectable_mtag_error = 1;
	}

	/* Request Agent Data UE */
	if (wci_ra_esr_1.bit.acc_uncorrectable_data_error &&
	    wci_ra_ecc_addr.bit.data && wci_ra_ecc_addr.bit.ue) {

		DPRINTF(LC_ECC, (CE_NOTE,  "wrsm %d: RA Data UE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.data_ecc_error_aid &
		    REQ_CLUSTER_MASK) == REQUEST_AGENT_MASK) &&
		    wci_dco_state.bit.data_ecc_ue) {
			ecc.flt_synd = WCI_DATA_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}
		/*
		 * Address bits [42:4] of the transaction that caused the
		 * first UE error.
		 */
		ecc.flt_addr = wci_ra_ecc_addr.bit.addr << 4;
		ecc.flt_stat = RA_ECC_DATA_UE;
		wrsm_handle_ue_error(softsp, &ecc, REQUEST_AGENT);
		/* clear wci_ra_esr_1 acc_uncorrectable_data_error bit */
		wci_ra_esr_1_clear.bit.acc_uncorrectable_data_error = 1;

	}

	/* Request Agent Mtag CE */
	if (wci_ra_esr_1.bit.acc_correctable_mtag_error &&
	    !wci_ra_ecc_addr.bit.data && !wci_ra_ecc_addr.bit.ue) {

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: RA Mtag CE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.mtag_ecc_error_aid &
		    REQ_CLUSTER_MASK) == REQUEST_AGENT_MASK) &&
		    !wci_dco_state.bit.mtag_ecc_ue) {
			ecc.flt_synd = WCI_MTAG_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}
		/*
		 * Address bits [42:4] of the transaction that caused the
		 * first CE error.
		 */
		ecc.flt_addr = wci_ra_ecc_addr.bit.addr << 4;
		ecc.flt_stat = RA_ECC_MTAG_CE;
		wrsm_handle_ce_error(softsp, &ecc, REQUEST_AGENT);
		/*
		 * clear wci_ra_esr_1  acc_correctable_mtag_error bit
		 * The bit type is RW1TX (toggle), thus needs to be
		 * set 1 to be cleared.
		 *
		 */
		wci_ra_esr_1_clear.bit.acc_correctable_mtag_error = 1;
	}

	/* Request Agent Data CE */
	if (wci_ra_esr_1.bit.acc_correctable_data_error &&
		wci_ra_ecc_addr.bit.data && !wci_ra_ecc_addr.bit.ue) {

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: RA Data CE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.data_ecc_error_aid &
		    REQ_CLUSTER_MASK) == REQUEST_AGENT_MASK) &&
		    !wci_dco_state.bit.data_ecc_ue) {
			ecc.flt_synd = WCI_DATA_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}

		/*
		 * Address bits [42:4] of the transaction that caused the
		 * first CE error.
		 */
		ecc.flt_addr = wci_ra_ecc_addr.bit.addr << 4;
		ecc.flt_stat = RA_ECC_DATA_CE;
		wrsm_handle_ce_error(softsp, &ecc, REQUEST_AGENT);
		/* clear wci_ra_esr_1 acc_correctable_data_error bit */
		wci_ra_esr_1_clear.bit.acc_correctable_data_error = 1;
	}

	/* Cluster Agent Mtag UE */
	if (wci_ca_esr_0.bit.acc_uncorrectable_mtag_error &&
	    wci_ca_ecc_addr.bit.ue && !wci_ca_ecc_addr.bit.data) {

		DPRINTF(LC_ECC, (CE_NOTE, "wssm %d: CA Mtag UE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.mtag_ecc_error_aid &
		    REQ_CLUSTER_MASK) == CLUSTER_AGENT_MASK) &&
		    wci_dco_state.bit.mtag_ecc_ue) {
			ecc.flt_synd = WCI_MTAG_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}

		/*
		 * Address bits [36:0] of the transaction that caused the
		 * first CE error.
		 */
		ecc.flt_addr = wci_ca_ecc_addr.bit.addr << 6;
		ecc.flt_stat = CA_ECC_MTAG_UE;
		/* mark if it was passthru request */
		if (!wci_ca_ecc_addr.bit.passthru)
		    ecc.flt_stat |= CA_ECC_NOTPASS;
		wrsm_handle_ue_error(softsp, &ecc, CLUSTER_AGENT);
		/* clear wci_ca_esr_0 acc_uncorrectable_mtag_error bit */
		wci_ca_esr_0_clear.bit.acc_uncorrectable_mtag_error = 1;
	}

	/* Cluster Agent Data UE */
	if (wci_ca_esr_0.bit.acc_uncorrectable_data_error &&
	    wci_ca_ecc_addr.bit.ue && wci_ca_ecc_addr.bit.data) {

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: CA Data UE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.data_ecc_error_aid &
		    REQ_CLUSTER_MASK) == CLUSTER_AGENT_MASK) &&
		    wci_dco_state.bit.data_ecc_ue) {
			ecc.flt_synd = WCI_DATA_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}

		/*
		 * Address bits [36:0] of the transaction that caused the
		 * first CE error.
		 */
		ecc.flt_addr = wci_ca_ecc_addr.bit.addr << 6;
		ecc.flt_stat = CA_ECC_DATA_UE;
		/* mark if it was passthru request */
		if (!wci_ca_ecc_addr.bit.passthru)
		    ecc.flt_stat |= CA_ECC_NOTPASS;
		wrsm_handle_ue_error(softsp, &ecc, CLUSTER_AGENT);
		/* clear wci_ca_esr_0 acc_uncorrectable_data_error bit */
		wci_ca_esr_0_clear.bit.acc_uncorrectable_data_error = 1;
	}

	/* Cluster Agent Mtag CE */
	if (wci_ca_esr_0.bit.acc_correctable_mtag_error &&
	    !wci_ca_ecc_addr.bit.data && !wci_ca_ecc_addr.bit.ue) {

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: CA Mtag CE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.mtag_ecc_error_aid &
		    REQ_CLUSTER_MASK) == CLUSTER_AGENT_MASK) &&
		    !wci_dco_state.bit.mtag_ecc_ue) {
			ecc.flt_synd = WCI_MTAG_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}
		/*
		 * Address bits [36:0] of the transaction that caused the
		 * first CE error.
		 */
		ecc.flt_addr = wci_ca_ecc_addr.bit.addr << 6;
		ecc.flt_stat = CA_ECC_MTAG_CE;
		/* mark if it was passthru request */
		if (!wci_ca_ecc_addr.bit.passthru)
		    ecc.flt_stat |= CA_ECC_NOTPASS;
		wrsm_handle_ce_error(softsp, &ecc, CLUSTER_AGENT);
		/* clear wci_ca_esr_0 acc_correctable_mtag_error bit */
		wci_ca_esr_0_clear.bit.acc_correctable_mtag_error = 1;

	}

	/* Cluster Agent Data CE */
	if (wci_ca_esr_0.bit.acc_correctable_data_error &&
	    wci_ca_ecc_addr.bit.data && !wci_ca_ecc_addr.bit.ue) {

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: CA Data CE error caught",
		    softsp->instance));

		if (((wci_dco_state.bit.data_ecc_error_aid &
		    REQ_CLUSTER_MASK) == CLUSTER_AGENT_MASK) &&
		    !wci_dco_state.bit.data_ecc_ue) {
			ecc.flt_synd = WCI_DATA_SYNDROME(wci_dco_state);
		} else {
			ecc.flt_synd = NO_SYNDROME;
		}

		/*
		 * Address bits [36:0] of the transaction that caused the
		 * first CE error.
		 */
		ecc.flt_addr = wci_ca_ecc_addr.bit.addr << 6;
		ecc.flt_stat = CA_ECC_DATA_CE;
		/* mark if it was passthru request */
		if (!wci_ca_ecc_addr.bit.passthru)
		    ecc.flt_stat |= CA_ECC_NOTPASS;
		wrsm_handle_ce_error(softsp, &ecc, CLUSTER_AGENT);
		/* clear wci_ca_esr_0 acc_correctable_data_error bit */
		wci_ca_esr_0_clear.bit.acc_correctable_data_error = 1;
	}

	if (wci_dco_ce_count.bit.ce_count != ECC_MAX_CNT) {
		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: "
		    "ECC error(s) caught and handled "
		    "number of CE errors recorded: %d", softsp->instance,
		    (ECC_MAX_CNT - wci_dco_ce_count.bit.ce_count)));

		/* reset the W1X esr registers */
		*softsp->wci_ra_esr_1_vaddr = wci_ra_esr_1_clear.val;
		*softsp->wci_ca_esr_0_vaddr = wci_ca_esr_0_clear.val;

		/* wci_dco_ce_count counts down from ECC_MAX_CNT */
		wci_dco_ce_count.bit.ce_count = ECC_MAX_CNT;
		*softsp->wci_dco_ce_cnt_vaddr = wci_dco_ce_count.val;

		/* !! bit type is RW1TX toggle */
		wci_dc_esr_clear.bit.acc_dco_ce = wci_dc_esr.bit.acc_dco_ce;
		wci_dc_esr_clear.bit.dco_ce = wci_dc_esr.bit.dco_ce;
		*softsp->wci_dc_esr_vaddr = wci_dc_esr_clear.val;

		/* clear syndrome */
		*softsp->wci_dco_state_vaddr = 0;

		/* reset ca,ra address regs */
		*softsp->wci_ra_ecc_addr_vaddr = 0;
		*softsp->wci_ca_ecc_addr_vaddr = 0;

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm_check_ecc reg CLEARED:"
		    "wci_dco.ce.cnt = %lld,"
		    "wci_dc_esr.bit.acc_dco_ce = %lld,"
		    "wci_dc_esr.bit.dco_ce = %lld,\n"
		    "*softsp->wci_dco_state_vaddr = 0x%llx,\n"
		    "*softsp->wci_ra_ecc_addr_vaddr = 0x%llx,"
		    "*softsp->wci_ca_ecc_addr_vaddr = 0x%llx\n",
		    wci_dco_ce_count.bit.ce_count,
		    wci_dc_esr.bit.acc_dco_ce,
		    wci_dc_esr.bit.dco_ce,
		    *softsp->wci_dco_state_vaddr,
		    *softsp->wci_ra_ecc_addr_vaddr,
		    *softsp->wci_ca_ecc_addr_vaddr));
	}
}

/*
 * WRSM Correctable ecc error trap handler
 *
 */
/* ARGSUSED */
static void
wrsm_handle_ce_error(struct wrsm_soft_state *softsp,
    struct async_flt *ecc, int agent_type)
{
	DPRINTF(LC_ECC, (CE_NOTE, "Enter wrsm_handle_ce_error"));

	ecc->flt_id = gethrtime();
	ecc->flt_pc = 0;
	ecc->flt_func = wci_log_ce_error;
	ecc->flt_inst = softsp->instance;
	ecc->flt_status = ECC_WCI;
	ecc->flt_class = CPU_FAULT;
	ecc->flt_prot = AFLT_PROT_NONE;
	ecc->flt_priv = 0;
	ecc->flt_panic = 0;
	ecc->flt_tl = 0;
	ecc->flt_core = 0;

	ecc->flt_bus_id = softsp->portid;

	DPRINTF(LC_ECC, (CE_NOTE, "ecc->flt_inst = %d agent_type = %d,"
	    " syndrome = %x", ecc->flt_inst, agent_type, ecc->flt_synd));

	/*
	 * We can only scrub if the error comes from CA and it was not
	 * a passthru transaction.  This is already marked in flt_stat
	 */
	if (ecc->flt_stat & CA_ECC_NOTPASS) {
		ecc->flt_stat &= ~CA_ECC_NOTPASS; /* remove the mark */
		ecc->flt_in_memory = 1;
		DPRINTF(LC_ECC, (CE_NOTE, "detected ce error in CA,"
		    "ecc->flt_in_memory = 1"));
	} else {
		/* RA or CA in passthru */
		ecc->flt_in_memory = 0;
		DPRINTF(LC_ECC, (CE_NOTE, "RA or CA in passthru,"
		    "ecc->flt_in_memory = 0"));
	}
	ce_scrub(ecc);
	errorq_dispatch(ce_queue, ecc, sizeof (*ecc), ERRORQ_ASYNC);
}

/*
 * WRSM Uncorrectable ecc error trap handler
 */
/* ARGSUSED */
static void
wrsm_handle_ue_error(struct wrsm_soft_state *softsp,
    struct async_flt *ecc, int agent_type)
{
#ifdef DEBUG
	int level = CE_WARN;
#else
	int level = CE_PANIC;
#endif

	cmn_err(level, "wci %d uncorrectable ECC error "
	    "agent_type %d, fault address 0x%08x.%08x",
	    softsp->portid, agent_type, (uint32_t)(ecc->flt_addr>>32),
	    (uint32_t)ecc->flt_addr);
}

/*
 * Examines the state of wci SRAM in wrsm (CMMU)
 */
static void
wrsm_lc_sram_ecc_check(wrsm_softstate_t *softsp, boolean_t do_shortterm)
{
	wci_cci_esr_u wci_cci_esr;
	wci_sram_ce_count_u wci_sram_ce_count;
	wci_sram_ecc_address_u wci_sram_ecc_address;

	wci_ca_esr_1_u wci_ca_esr_1;
	wci_csra_esr_u wci_csra_esr;
	wci_csra_status_u wci_csra_status;

	wrsm_seprom_data_t seprom;

	uint32_t num_ce_errors;

	wci_cci_esr.val = *softsp->wci_cci_esr_vaddr;

	if (!wci_cci_esr.val) {
		/* no errors found */
		return;
	}

	DPRINTF(LC_ECC, (CE_NOTE, "SRAM ECC ERROR CAUGHT"));

	/* map relevant registers */
	wrsm_lc_csr_read(softsp, ADDR_WCI_SRAM_CE_COUNT,
	    &wci_sram_ce_count.val);
	wrsm_lc_csr_read(softsp, ADDR_WCI_SRAM_ECC_ADDRESS,
	    &wci_sram_ecc_address.val);

	seprom.type = WRSM_WIB_SEPROM_TYPE_ECCERR;
	seprom.data.eccerr.ce = wci_sram_ecc_address.bit.ce;
	seprom.data.eccerr.address = wci_sram_ecc_address.bit.address;
	seprom.data.eccerr.syndrome = wci_sram_ecc_address.bit.syndrome;

	cmn_err(CE_WARN, "wci %d: SRAM ECC error: ce=%u, addr=0x%X, "
	    "syndrome=0x%X",
	    softsp->portid, seprom.data.eccerr.ce,
	    seprom.data.eccerr.address, seprom.data.eccerr.syndrome);

	(void) wrsmplat_set_seprom(softsp->portid, (uchar_t *)&seprom,
	    sizeof (seprom));

	if (wci_cci_esr.bit.acc_sram_ue) { /* uncorrectable SRAM ECC error */
		/*
		 * Note that the CMMU remains disabled after we log the error
		 */

		wrsm_lc_csr_read(softsp, ADDR_WCI_CA_ESR_1, &wci_ca_esr_1.val);
		wrsm_lc_csr_read(softsp, ADDR_WCI_CSRA_ESR, &wci_csra_esr.val);
		wrsm_lc_csr_read(softsp, ADDR_WCI_CSRA_STATUS,
		    &wci_csra_status.val);

		/*
		 * The ecc is calculated from 34 bits of data +
		 * 2 parity bits taken from the address.
		 * We are here knowing that at least one of the address
		 * bits was corrupted
		 */
		if (wci_cci_esr.bit.acc_sram_ae) {
		    cmn_err(CE_WARN, "wci %d uncorrectable sram error: "
			"address", softsp->portid);
		}

		if (wci_ca_esr_1.bit.acc_cmmu_ecc_error) {
			cmn_err(CE_WARN, "wci %d uncorrectable sram error: "
			    " CAG", softsp->portid);
			wci_ca_esr_1.val = 0;
			wci_ca_esr_1.bit.acc_cmmu_ecc_error = 1;
			wrsm_lc_csr_write(softsp, ADDR_WCI_CA_ESR_1,
			    wci_ca_esr_1.val);
		}

		if (wci_csra_esr.bit.acc_sram_error) {
			cmn_err(CE_WARN, "wci %d uncorrectable sram error: "
			    "CSRA, wci_csra_esr_status 0x%08x.%08x",
			    softsp->portid,
			    (uint32_t)(wci_csra_status.val>>32),
			    (uint32_t)wci_csra_status.val);
			wci_csra_esr.val = 0;
			wci_csra_esr.bit.acc_sram_error = 1;
			wrsm_lc_csr_write(softsp, ADDR_WCI_CSRA_ESR,
			    wci_csra_esr.val);
			wrsm_lc_csr_write(softsp, ADDR_WCI_CSRA_STATUS, 0);
		}
		/* note it for kstats */
		softsp->uc_sram_ecc_error = 1;
	}

	if (wci_cci_esr.bit.acc_sram_ce) { /* correctable SRAM ECC error */

		num_ce_errors = 0xFF -  wci_sram_ce_count.val;

		DPRINTF(LC_ECC, (CE_NOTE, "wrsm %d: wci %d SRAM "
		    "correctable error, "
		    "with%s address, total number of CE errors: %d",
		    softsp->instance, softsp->portid,
		    (wci_sram_ecc_address.bit.ce?"":"out"),
		    num_ce_errors));

		/* note count for kstats */
		softsp->num_sram_ecc_errors += num_ce_errors;
		softsp->sram_ecc_errsum += num_ce_errors;
		if (do_shortterm) {
			softsp->last_sram_ecc_errors =
			    softsp->sram_ecc_errsum;
			softsp->max_sram_ecc_errors =
			    MAX(softsp->max_sram_ecc_errors,
			    softsp->sram_ecc_errsum);
			softsp->avg_sram_ecc_errors =
			    RUNNING_AVG(softsp->sram_ecc_errsum,
			    softsp->avg_sram_ecc_errors);
			softsp->sram_ecc_errsum = 0;
		}
	}

	/* clean up */
	wrsm_lc_csr_write(softsp, ADDR_WCI_SRAM_ECC_ADDRESS, 0x0);
	/* reset the count */
	wrsm_lc_csr_write(softsp, ADDR_WCI_SRAM_CE_COUNT, ECC_MAX_CNT);
	/* reset the wci_cci_esr (write 1 to toggle) */
	*softsp->wci_cci_esr_vaddr = wci_cci_esr.val;
}

/* Handles ioctls to read/modify WCI registers */
/* ARGSUSED */
int
wrsm_lc_register_ioctl(wrsm_softstate_t *softsp, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p)
{
	wrsm_cmmu_t cmmu_tmp;
	int retval = 0;
	int num_entries; /* number of cmmu entries */
	uint64_t args[4];

	/* Only allow privileged users to do this */
	if ((retval = secpolicy_sys_config(cred_p, B_FALSE)) != 0)
		return (retval);

	if (ddi_copyin((void *)arg, args, 4 * sizeof (uint64_t), flag) != 0)
		return (EFAULT);
	DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_register_ioctl\n"));

	switch (cmd) {

	case WRSM_LC_READCSR:
		if (((args[0] & REGMASK) != 0) || (args[0] >
		    ADDR_LAST_CSR)) {
			retval = EINVAL;
			break;
		}
		wrsm_lc_csr_read(softsp, args[0], &args[1]);
		if (ddi_copyout(args, (void*)arg, 2 * sizeof (uint64_t),
		    flag) != 0)
			retval = EFAULT;
		break;

	case WRSM_LC_WRITECSR:
		if (((args[0] & REGMASK) != 0) || (args[0] >
		    ADDR_LAST_CSR)) {
			retval = EINVAL;
			break;
		}
		wrsm_lc_csr_write(softsp, args[0], args[1]);
		break;

	case WRSM_LC_READCESR:
		if (args[0] > ENTRIES_WCI_CLUSTER_ERROR_STATUS_ARRAY) {
			retval = EINVAL;
			break;
		}
		wrsm_lc_cesr_read(softsp, (safari_port_t)args[0], &args[1]);
		if (ddi_copyout(args, (void*)arg, 2 * sizeof (uint64_t),
		    flag) != 0)
			retval = EFAULT;
		break;

	case WRSM_LC_WRITECESR:
		if (args[0] > ENTRIES_WCI_CLUSTER_ERROR_STATUS_ARRAY) {
			retval = EINVAL;
			break;
		}
		wrsm_lc_cesr_write(softsp, (safari_port_t)args[0], args[1]);
		break;

	case WRSM_LC_UPDATECMMU:
		num_entries = wrsm_lc_num_cmmu_entries_get(softsp);
		if (args[2] > num_entries) {
			retval = EINVAL;
			break;
		}
		cmmu_tmp.entry_0.val = args[0];
		cmmu_tmp.entry_1.val = args[1];

		wrsm_lc_cmmu_update(softsp, &cmmu_tmp, args[2],
		    (wrsm_cmmu_flags_t)args[3]);
		break;

	case WRSM_LC_READCMMU:
		num_entries = wrsm_lc_num_cmmu_entries_get(softsp);
		if (args[2] > num_entries) {
			retval = EINVAL;
			break;
		}
		wrsm_lc_cmmu_read(softsp, &cmmu_tmp, args[2]);
		args[0] = cmmu_tmp.entry_0.val;
		args[1] = cmmu_tmp.entry_1.val;
		if (ddi_copyout(args, (void*)arg, 2 * sizeof (uint64_t),
		    flag) != 0)
			retval = EFAULT;
		break;

	default:
		return (EINVAL);
	}

	return (retval);
}




/*
 * cancel all timeouts as part of DDI_SUSPEND
 */
void
wrsm_lc_suspend(wrsm_softstate_t *softsp)
{
	timeout_id_t restart_tmoid = 0;
	timeout_id_t err_tmoid = 0;

	ASSERT(softsp);

	DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_suspend wci %d\n",
	    softsp->portid));

	mutex_enter(&softsp->lc_mutex);

	if (softsp->suspended) {
		mutex_exit(&softsp->lc_mutex);
		return;
	}

	softsp->suspended = B_TRUE;

	if (softsp->restart_timeout_id) {
		restart_tmoid = softsp->restart_timeout_id;
		softsp->restart_timeout_id = 0;
		softsp->need_restart_timeout = B_TRUE;
	}


	if (softsp->err_timeout_id) {
		err_tmoid = softsp->err_timeout_id;
		softsp->err_timeout_id = 0;
		softsp->need_err_timeout = B_TRUE;
	}

	mutex_exit(&softsp->lc_mutex);

	if (restart_tmoid)
		(void) untimeout(restart_tmoid);

	if (err_tmoid)
		(void) untimeout(err_tmoid);

	wrsmplat_suspend(softsp->portid);
}



/*
 * restart any timeouts cancelled for a DDI_SUSPEND
 */
void
wrsm_lc_resume(wrsm_softstate_t *softsp)
{
	ASSERT(softsp);

	DPRINTF(LC_DEBUG, (CE_CONT, "wrsm_lc_resume wci %d\n",
	    softsp->portid));

	mutex_enter(&softsp->lc_mutex);

	if (!softsp->suspended) {
		mutex_exit(&softsp->lc_mutex);
		return;
	}

	softsp->suspended = B_FALSE;
	wrsmplat_resume(softsp->portid);

	if (softsp->need_restart_timeout) {
		softsp->need_restart_timeout = B_FALSE;
		softsp->restart_timeout_id = timeout((void (*)(void *))
		    wrsm_lc_restart_downlinks, softsp, wrsm_restart_hz);
	}
	if (softsp->need_err_timeout) {
		softsp->need_err_timeout = B_FALSE;
		softsp->err_timeout_id = timeout((void (*)(void *))
		    wrsm_lc_poll_timeout, softsp, wrsm_poll_hz);
	}

	mutex_exit(&softsp->lc_mutex);
}
