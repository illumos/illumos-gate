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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements RSMPI barriers in the Wildcat RSM driver.
 */

#include <sys/types.h>

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/promif.h>

#include <sys/wrsm_barrier.h>
#include <sys/wrsm_common.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wci_regs.h>

/*
 * The following macros define a DPRINTF macro which can be used to enable
 * or disable various levels of logging for this module.
 */
#ifdef DEBUG

#define	BARDBG		0x1
#define	BARWARN		0x2
#define	BARERR		0x4
#define	BARTRACE	0x8
static uint_t wrsm_bar_debug = BARERR;

#define	DPRINTF(a, b) { if (wrsm_bar_debug & a) wrsmdprintf b; }
#define	PRINT_BAR(a, b) { if (wrsm_bar_debug & a) wrsm_print_barrier(b); }

#else /* DEBUG */

#define	DPRINTF(a, b) { }
#define	PRINT_BAR(a, b) { }

#endif /* DEBUG */

#define	DTRC(s)		DPRINTF(BARTRACE, (CE_CONT, s))
#define	WARN(s)		DPRINTF(BARWARN, (CE_WARN, s))
#define	NOTE(s)		DPRINTF(BARDBG, (CE_NOTE, s))
#define	ERR(s)		DPRINTF(BARERR, (CE_WARN, s))

/*
 * Local types
 */
#define	BARRIER_TIME_REGION		0
#define	BARRIER_TIME_REGIONS		1
#define	BARRIER_TIME_NODE		2
#define	BARRIER_TIME_CONTROLLER		3
#define	BARRIER_THREAD_REGION		4
#define	BARRIER_THREAD_REGIONS		5
#define	BARRIER_THREAD_NODE		6
#define	BARRIER_THREAD_CONTROLLER	7
typedef unsigned char wrsm_barrier_scope_t;

#ifdef DEBUG
/* The following array is used in wrsm_print_barrier, for debug only */
static const char *scope_txt[] = {
	"BARRIER_TIME_REGION",
	"BARRIER_TIME_REGIONS",
	"BARRIER_TIME_NODE",
	"BARRIER_TIME_CONTROLLER",
	"BARRIER_THREAD_REGION",
	"BARRIER_THREAD_REGIONS",
	"BARRIER_THREAD_NODE",
	"BARRIER_THREAD_CONTROLLER"};
#endif /* DEBUG */

/* Define state flags to help ensure that barrier is really initialized */
typedef unsigned char wrsm_barrier_state_t;
#define	BARRIER_CLOSED	((wrsm_barrier_state_t)0xff)
#define	BARRIER_OPENED	((wrsm_barrier_state_t)0xfe)

/* This struct is an overlay for rsm_barrier_t */
typedef struct {
	void *parent;		/* network, importseg or array of importsegs */
	uint64_t init_err_count;
	uint32_t reroute_counter;
	uint32_t transfer_errors;
	int num_regions;	/* if multiple importsegs */
	wrsm_barrier_scope_t scope;
	wrsm_barrier_state_t state;
	cnodeid_t cnodeid;	/* if node barrier */
} wrsm_barrier_t;

/*
 * Local Functions
 */

/*
 * This function sums the wci_cluster_error_count register for all WCIs
 * routing to the given ncslice (i.e., remote node). It does this by
 * reading the wci_cluster_error_count mapped into the stripes of page 0
 * of the nslice.
 */
static uint64_t
sum_errors_node(caddr_t ncslice_base, int link_stripes)
{
	uint64_t total = 0;
	int stripes;
	caddr_t err_addr = ncslice_base + WCI_ERRPAGE_CLUSTER_ERROR_OFFSET;

	for (stripes = link_stripes; stripes; stripes = stripes >> 1) {
		if (stripes & 1) {
			/* Sum in errors for this stripe */
			total += *((uint64_t *)err_addr);
		}
		err_addr += WCI_CLUSTER_STRIPE_STRIDE;
	}
	return (total);
}

/* Sums wci_cluster_error_counts for all nodes in nodes bitmask */
static int
sum_errors_nodes(wrsm_network_t *net, wrsm_cnode_bitmask_t cnodes,
    uint64_t *sum)
{
	wrsm_node_t *node;
	int i;

	/* If we're in the process of rerouting, return MAX INT */
	if (*net->reroutingp) {
		*sum = UINT64_MAX;
		return (RSM_SUCCESS);
	}

	*sum = 0;
	mutex_enter(&net->lock);
	/* Loop for each node in the set. Exit early once set is empty */
	for (i = 0; i < WRSM_MAX_CNODES && !WRSMSET_ISNULL(cnodes); i++) {
		if (WRSM_IN_SET(cnodes, i)) {
			node = net->nodes[i];
			if (node == NULL) {
				mutex_exit(&net->lock);
				return (RSMERR_CONN_ABORTED);
			}
			*sum += sum_errors_node(node->cesr_vaddr,
			    *node->link_stripesp);
		}
		/* Remove this node from the list, hoping for early exit */
		WRSMSET_DEL(cnodes, i);
	}
	mutex_exit(&net->lock);
	return (RSM_SUCCESS);
}

/*
 * RSMPI Functions
 */
/* ARGSUSED */
int
wrsm_open_barrier_ctrl(rsm_controller_handle_t ctrl, rsm_barrier_t *barrier)
{
	DTRC("wrsm_open_barrier_ctrl");
	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT(sizeof (wrsm_barrier_t) <= sizeof (rsm_barrier_t));
	return (RSMERR_UNSUPPORTED_OPERATION);
}

int
wrsm_open_barrier_node(rsm_controller_handle_t ctrl, rsm_addr_t addr,
    rsm_barrier_t *barrier)
{
	wrsm_node_t *node;
	wrsm_network_t *net = (wrsm_network_t *)ctrl;
	wrsm_barrier_t *bar = (wrsm_barrier_t *)barrier;

	DPRINTF(BARTRACE, (CE_CONT, "wrsm_open_barrier_node(addr=%d)", addr));
	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT(sizeof (wrsm_barrier_t) <= sizeof (rsm_barrier_t));

	if (bar == NULL) {
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (net == NULL) {
		return (RSMERR_BAD_CTLR_HNDL);
	}
	if (addr >= WRSM_MAX_CNODES) {
		return (RSMERR_UNKNOWN_RSM_ADDR);
	}
	bar->state = BARRIER_CLOSED; /* Mark as closed until we're done */
	bar->scope = BARRIER_TIME_NODE;

	mutex_enter(&net->lock);
	node = net->nodes[addr];
	if (!node) {
		mutex_exit(&net->lock);
		return (RSMERR_UNKNOWN_RSM_ADDR);
	}
	/* Read route counter */
	bar->reroute_counter = *net->route_counterp;
	bar->init_err_count = sum_errors_node(node->cesr_vaddr,
	    *node->link_stripesp);
	bar->parent = (void *)net;
	bar->cnodeid = (cnodeid_t)addr;
	bar->transfer_errors = node->memseg->transfer_errors;
	bar->state = BARRIER_OPENED;
	mutex_exit(&net->lock);

	/* Make sure a session is established with the remote node */
	(void) wrsm_sess_establish(net, addr);

	PRINT_BAR(BARDBG, barrier);
	return (RSM_SUCCESS);
}

int
wrsm_open_barrier_region(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_t *barrier)
{
	importseg_t *importseg;
	wrsm_barrier_t *bar = (wrsm_barrier_t *)barrier;
	int err;

	DTRC("wrsm_open_barrier_region");
	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT(sizeof (wrsm_barrier_t) <= sizeof (rsm_barrier_t));

	if (im_memseg == NULL) {
		return (RSMERR_BAD_SEG_HNDL);
	}
	if (bar == NULL) {
		return (RSMERR_BAD_BARRIER_PTR);
	}

	/* we assume importseg will not be removed during barrier */
	importseg = (importseg_t *)im_memseg;
	err = wrsm_open_barrier_node(importseg->iseginfo->network,
	    importseg->iseginfo->cnodeid, barrier);
	bar->scope = BARRIER_TIME_REGION;
	bar->parent = (void *)importseg;
	bar->transfer_errors = importseg->iseginfo->transfer_errors;
	bar->cnodeid = importseg->iseginfo->cnodeid;

	PRINT_BAR(BARDBG, barrier);
	return (err);
}

int
wrsm_open_barrier_regions(rsm_memseg_import_handle_t im_memseg[],
    uint_t num_regions, rsm_barrier_t *barrier)
{
	importseg_t **importseg_list;
	wrsm_barrier_t *bar = (wrsm_barrier_t *)barrier;
	wrsm_network_t *net;
	wrsm_cnode_bitmask_t cnodes;
	uint_t i;
	int err;

	DTRC("wrsm_open_barrier_regions");
	/* LINTED: E_TRUE_LOGICAL_EXPR */
	ASSERT(sizeof (wrsm_barrier_t) <= sizeof (rsm_barrier_t));

	if (bar == NULL) {
		return (RSMERR_BAD_BARRIER_PTR);
	}
	bar->state = BARRIER_CLOSED; /* Mark as closed until we're done */

	if (num_regions == 0) {
		return (RSMERR_BAD_SEG_HNDL);
	}

	WRSMSET_ZERO(cnodes);
	for (i = 0; i < num_regions; i++) {
		if (im_memseg[i] == NULL) {
			return (RSMERR_BAD_SEG_HNDL);
		}
		WRSMSET_ADD(cnodes, im_memseg[i]->iseginfo->cnodeid);
	}

	/* we assume importsegs will not be removed during barrier */
	net = ((importseg_t *)im_memseg[0])->iseginfo->network;
	bar->scope = BARRIER_TIME_REGIONS;
	bar->reroute_counter = *net->route_counterp;
	err = sum_errors_nodes(net, cnodes, &bar->init_err_count);
	if (!err) {
		bar->parent = (void *)kmem_alloc(
		    (num_regions * sizeof (importseg_t *)), KM_SLEEP);
		bcopy(im_memseg, bar->parent,
		    (num_regions * sizeof (importseg_t *)));
		bar->num_regions = num_regions;
		importseg_list = (importseg_t **)bar->parent;
		bar->transfer_errors = 0;
		for (i = 0; i < num_regions; i++) {
			bar->transfer_errors +=
			    importseg_list[i]->iseginfo->transfer_errors;
		}
		bar->state = BARRIER_OPENED;
	}

	PRINT_BAR(BARDBG, barrier);
	return (err);
}

int
wrsm_open_barrier_ctrl_thr(rsm_controller_handle_t ctrl,
    rsm_barrier_t *barrier)
{
	DTRC("wrsm_open_barrier_ctrl_thr");
	return (wrsm_open_barrier_ctrl(ctrl, barrier));
}

int
wrsm_open_barrier_node_thr(rsm_controller_handle_t ctrl, rsm_addr_t addr,
    rsm_barrier_t *barrier)
{
	DTRC("wrsm_open_barrier_node_thr");
	return (wrsm_open_barrier_node(ctrl, addr, barrier));
}

int
wrsm_open_barrier_region_thr(rsm_memseg_import_handle_t im_memseg,
    rsm_barrier_t *barrier)
{
	DTRC("wrsm_open_barrier_region_thr");
	return (wrsm_open_barrier_region(im_memseg, barrier));
}

int
wrsm_open_barrier_regions_thr(rsm_memseg_import_handle_t im_memseg[],
    uint_t num_regions, rsm_barrier_t *barrier)
{
	DTRC("wrsm_open_barrier_regions_thr");
	return (wrsm_open_barrier_regions(im_memseg, num_regions, barrier));
}

static int
close_barrier_time_node(wrsm_network_t *net, wrsm_barrier_t *bar)
{
	uint64_t error_sum;
	wrsm_node_t *node;
	DTRC("close_barrier_time_node");

	/* Check to see if there were any errors */
	if (bar->init_err_count == UINT64_MAX) {
		WARN("Barrier failed: error reading wci cluster error count");
		return (RSMERR_BARRIER_FAILURE);
	}
	mutex_enter(&net->lock);
	node = net->nodes[bar->cnodeid];
	error_sum = sum_errors_node(node->cesr_vaddr, *node->link_stripesp);
	mutex_exit(&net->lock);
	if (bar->init_err_count != error_sum) {
		WARN("Barrier failed: wci errors detected");
		return (RSMERR_BARRIER_FAILURE);
	}
	/* Make sure route hasn't changed */
	if (*net->reroutingp || bar->reroute_counter != *net->route_counterp) {
		WARN("Barrier failed: route changed");
		return (RSMERR_BARRIER_FAILURE);
	}

	return (RSM_SUCCESS);
}

static int
close_barrier_time_nodes(wrsm_network_t *net, wrsm_barrier_t *bar,
    wrsm_cnode_bitmask_t cnodes)
{
	uint64_t error_sum;
	int err;
	DTRC("close_barrier_time_nodes");

	/* Check to see if there were any errors */
	if (bar->init_err_count == UINT64_MAX) {
		WARN("Barrier failed: error reading wci cluster error count");
		return (RSMERR_BARRIER_FAILURE);
	}
	/* Sum errors for those remote nodes */
	err = sum_errors_nodes(net, cnodes, &error_sum);
	if (err) {
		return (err);
	}
	if (bar->init_err_count != error_sum) {
		WARN("Barrier failed: wci errors detected");
		return (RSMERR_BARRIER_FAILURE);
	}
	/* Make sure route hasn't changed */
	if (*net->reroutingp || bar->reroute_counter != *net->route_counterp) {
		WARN("Barrier failed: route changed");
		return (RSMERR_BARRIER_FAILURE);
	}

	return (RSM_SUCCESS);
}


int
wrsm_close_barrier(rsm_barrier_t *barrier)
{
	wrsm_barrier_t *bar;
	wrsm_network_t *net;
	wrsm_node_t *node;
	importseg_t *importseg;
	importseg_t **importseg_list;
	uint_t sum_transfer_errors = 0;
	wrsm_cnode_bitmask_t cnodes;
	int i;
	int err = 0;
	int retval = 0;

	DTRC("wrsm_close_barrier");
	PRINT_BAR(BARDBG, barrier);

	bar = (wrsm_barrier_t *)barrier;
	if (bar == NULL) {
		WARN("Barrier failed: barrier pointer is NULL");
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (bar->state != BARRIER_OPENED) {
		WARN("Barrier failed: Barrier not open");
		return (RSMERR_BARRIER_NOT_OPENED);
	}
	bar->state = BARRIER_CLOSED;

	switch (bar->scope) {
	case BARRIER_TIME_REGION:
		importseg = (importseg_t *)bar->parent;
		if (importseg->unpublished) {
			WARN("Barrier failed: importseg was unpublished");
			return (RSMERR_CONN_ABORTED);
		}
		if (bar->transfer_errors !=
		    importseg->iseginfo->transfer_errors) {
			DPRINTF(BARWARN, (CE_WARN,
			    "Barrier failed: transfer errors; last err %d",
			    importseg->iseginfo->last_transfer_error));
			return (importseg->iseginfo->last_transfer_error);
		}
		net = importseg->iseginfo->network;
		mutex_enter(&net->lock);
		node = net->nodes[bar->cnodeid];
		if (node == NULL) {
			WARN("Barrier failed: unknown node");
			retval = RSMERR_CONN_ABORTED;
		} else {
			/* Flush links to remote node */
			retval = wrsm_sess_touch_node(net, bar->cnodeid,
			    *node->link_stripesp);
		}
		mutex_exit(&net->lock);
		if (retval == RSM_SUCCESS) {
			retval = close_barrier_time_node(net, bar);
		}
		break;

	case BARRIER_TIME_REGIONS:
		WRSMSET_ZERO(cnodes);
		importseg_list = (importseg_t **)bar->parent;
		ASSERT(importseg_list);

		/* get net from first importseg */
		net = importseg_list[0]->iseginfo->network;

		mutex_enter(&net->lock);
		for (i = 0; i < bar->num_regions; i++) {
			importseg = importseg_list[i];
			WRSMSET_ADD(cnodes, importseg->iseginfo->cnodeid);
			if (importseg->unpublished) {
				kmem_free(bar->parent, (bar->num_regions *
				    sizeof (importseg_t *)));
				WARN("Barrier failed: importseg unpublished");
				mutex_exit(&net->lock);
				return (RSMERR_CONN_ABORTED);
			}
			sum_transfer_errors +=
			    importseg->iseginfo->transfer_errors;
			/* Remember the first error encountered */
			if (err == 0) {
				err = importseg->iseginfo->last_transfer_error;
			}
			if (retval == RSM_SUCCESS) {
				node = net->nodes[importseg->iseginfo->cnodeid];
				if (node == NULL) {
					WARN("Barrier failed: unknown node");
					retval = RSMERR_CONN_ABORTED;
				} else {
					/* Flush links to remote node */
					retval = wrsm_sess_touch_node(net,
					    importseg->iseginfo->cnodeid,
					    *node->link_stripesp);
				}
			}
		}
		mutex_exit(&net->lock);
		kmem_free(bar->parent,
		    (bar->num_regions * sizeof (importseg_t *)));
		if (bar->transfer_errors != sum_transfer_errors) {
			DPRINTF(BARWARN, (CE_WARN,
			    "Barrier failed: transfer errors, last error %d",
			    err));
			return (err);
		}
		if (retval == RSM_SUCCESS) {
			retval = close_barrier_time_nodes(net, bar, cnodes);
		}
		break;

	case BARRIER_TIME_NODE:
		net = (wrsm_network_t *)bar->parent;
		mutex_enter(&net->lock);
		node = net->nodes[bar->cnodeid];
		if (!node) {
			mutex_exit(&net->lock);
			WARN("Barrier failed: node doesn't exist");
			return (RSMERR_CONN_ABORTED);
		}
		if (node->memseg->removing_session ||
		    (wrsm_sess_get(net, node->config->cnodeid) ==
		    SESS_ID_INVALID)) {
			mutex_exit(&net->lock);
			WARN("Barrier failed: no session to remote node");
			return (RSMERR_CONN_ABORTED);
		}
		if (bar->transfer_errors != node->memseg->transfer_errors) {
			err = node->memseg->last_transfer_error;
			DPRINTF(BARWARN, (CE_WARN,
			    "Barrier failed: transfer error; last err %d",
			    err));
			mutex_exit(&net->lock);
			return (err);
		}
		/* Flush links to remote node */
		retval = wrsm_sess_touch_node(net, bar->cnodeid,
		    *node->link_stripesp);
		mutex_exit(&net->lock);
		if (retval == RSM_SUCCESS) {
			retval = close_barrier_time_node(net, bar);
		}
		break;

	case BARRIER_TIME_CONTROLLER:
		retval = RSMERR_UNSUPPORTED_OPERATION;
		break;

	default:
		ERR("Invalid barrier data");
		retval = RSMERR_BAD_BARRIER_HNDL;
	}

#ifdef DEBUG
	if (retval) {
		DPRINTF(BARWARN, (CE_WARN, "Barrier failed: %d", retval));
	}
#endif
	return (retval);
}

int
wrsm_reopen_barrier(rsm_barrier_t *barrier)
{
	rsm_controller_handle_t ctrl;
	rsm_addr_t addr;
	rsm_memseg_import_handle_t im_memseg;
	rsm_memseg_import_handle_t *im_memsegp;
	uint_t num_regions;
	wrsm_barrier_t *bar = (wrsm_barrier_t *)barrier;
	int retval;

	DTRC("wrsm_reopen_barrier");
	if (barrier == NULL) {
		WARN("Barrier failed: barrier pointer is NULL");
		return (RSMERR_BAD_BARRIER_PTR);
	}
	switch (bar->scope) {
	case BARRIER_TIME_NODE:
		ctrl = bar->parent;
		addr = bar->cnodeid;
		retval = wrsm_close_barrier(barrier);
		(void) wrsm_open_barrier_node(ctrl, addr, barrier);
		break;
	case BARRIER_TIME_REGION:
		im_memseg = bar->parent;
		retval = wrsm_close_barrier(barrier);
		(void) wrsm_open_barrier_region(im_memseg, barrier);
		break;
	case BARRIER_TIME_REGIONS:
		num_regions = bar->num_regions;
		im_memsegp = (rsm_memseg_import_handle_t *)kmem_alloc(
			num_regions *
			sizeof (rsm_memseg_import_handle_t *), KM_SLEEP);
		bcopy(bar->parent, im_memsegp,
		    num_regions * sizeof (rsm_memseg_import_handle_t *));
		retval = wrsm_close_barrier(barrier);
		(void) wrsm_open_barrier_regions(im_memsegp, num_regions,
		    barrier);
		kmem_free(im_memsegp,
		    num_regions * sizeof (rsm_memseg_import_handle_t *));
		break;
	default:
		retval = RSMERR_UNSUPPORTED_OPERATION;
	}
	return (retval);
}

int
wrsm_order_barrier(rsm_barrier_t *barrier)
{
	wrsm_barrier_t *bar;
	int i;
	wrsm_network_t *net;
	wrsm_node_t *node;
	importseg_t *importseg;
	importseg_t **importseg_list;
	int retval = 0;

	DTRC("wrsm_order_barrier");
	PRINT_BAR(BARDBG, barrier);

	bar = (wrsm_barrier_t *)barrier;
	if (bar == NULL) {
		WARN("Barrier failed: barrier pointer is NULL");
		return (RSMERR_BAD_BARRIER_PTR);
	}
	if (bar->state != BARRIER_OPENED) {
		WARN("Barrier failed: Barrier not open");
		return (RSMERR_BARRIER_NOT_OPENED);
	}

	/* Figure out which remote cnode(s) we need to flush */
	switch (bar->scope) {
	case BARRIER_TIME_REGION:
		importseg = (importseg_t *)bar->parent;
		net = importseg->iseginfo->network;
		mutex_enter(&net->lock);
		node = net->nodes[bar->cnodeid];
		if (node) {
			retval = wrsm_sess_touch_node(net, bar->cnodeid,
			    *node->link_stripesp);
		} else {
			retval = RSMERR_CONN_ABORTED;
		}
		mutex_exit(&net->lock);
		break;

	case BARRIER_TIME_REGIONS:
		importseg_list = (importseg_t **)bar->parent;
		ASSERT(importseg_list);

		/* get net from first importseg */
		net = importseg_list[0]->iseginfo->network;

		mutex_enter(&net->lock);
		for (i = 0; i < bar->num_regions; i++) {
			cnodeid_t cnode = importseg_list[i]->iseginfo->cnodeid;
			node = net->nodes[cnode];
			if (node) {
				int err = wrsm_sess_touch_node(net, cnode,
				    *node->link_stripesp);
				retval = retval ? retval : err;
			} else {
				retval = RSMERR_CONN_ABORTED;
			}
		}
		mutex_exit(&net->lock);
		break;

	case BARRIER_TIME_NODE:
		net = (wrsm_network_t *)bar->parent;
		mutex_enter(&net->lock);
		node = net->nodes[bar->cnodeid];
		if (node) {
			retval = wrsm_sess_touch_node(net, bar->cnodeid,
			    *node->link_stripesp);
		} else {
			retval = RSMERR_CONN_ABORTED;
		}
		mutex_exit(&net->lock);
		break;

	case BARRIER_TIME_CONTROLLER:
		retval = RSMERR_UNSUPPORTED_OPERATION;
		break;

	default:
		ERR("Invalid barrier data");
		retval = RSMERR_BAD_BARRIER_HNDL;
	}
	return (retval);
}

int
wrsm_thread_init(rsm_controller_handle_t ctrl)
{
	wrsm_network_t *net;
	DTRC("wrsm_thread_init");

	net = (wrsm_network_t *)ctrl;
	if (net == NULL) {
		return (RSMERR_BAD_CTLR_HNDL);
	}
	/* Thread Barriers not yet implemented, so nothing to do */
	return (RSM_SUCCESS);
}

int
wrsm_thread_fini(rsm_controller_handle_t ctrl)
{
	wrsm_network_t *net;
	DTRC("wrsm_thread_fini");

	net = (wrsm_network_t *)ctrl;
	if (net == NULL) {
		return (RSMERR_BAD_CTLR_HNDL);
	}
	/* Thread Barriers not yet implemented, so nothing to do */
	return (RSM_SUCCESS);
}

int
wrsm_get_barrier_mode(rsm_memseg_import_handle_t mem, rsm_barrier_mode_t *mode)
{
	importseg_t *importseg = (importseg_t *)mem;
	int err;

	DTRC("wrsm_get_barrier_mode");

	if ((err = wrsm_lock_importseg(importseg, RW_READER)) != RSM_SUCCESS) {
		return (err);
	}

	*mode = importseg->barrier_mode;

	rw_exit(&importseg->rw_lock);
	return (RSM_SUCCESS);
}

int
wrsm_set_barrier_mode(rsm_memseg_import_handle_t mem, rsm_barrier_mode_t mode)
{
	importseg_t *importseg = (importseg_t *)mem;
	int err;

	DPRINTF(BARTRACE, (CE_CONT,
	    "wrsm_set_barrier_mode: importseg 0x%p mode %d",
	    (void *)importseg, mode));

	if ((mode != RSM_BARRIER_MODE_EXPLICIT) &&
	    mode != RSM_BARRIER_MODE_IMPLICIT) {
		return (RSMERR_BAD_MODE);
	}

	if ((err = wrsm_lock_importseg(importseg, RW_WRITER)) != RSM_SUCCESS) {
		return (err);
	}

	importseg->barrier_mode = mode;

	rw_exit(&importseg->rw_lock);
	return (RSM_SUCCESS);
}

#ifdef DEBUG
void
wrsm_print_barrier(rsm_barrier_t *barrier)
{
	wrsm_barrier_t *bar = (wrsm_barrier_t *)barrier;

	cmn_err(CE_CONT, "Barrier {");
	cmn_err(CE_CONT, "  scope = %s", scope_txt[bar->scope]);
	cmn_err(CE_CONT, "  state = %s",
	    (bar->state == BARRIER_OPENED) ? "OPENED" : "CLOSED");
	cmn_err(CE_CONT, "  reroute_counter = %u", bar->reroute_counter);
	cmn_err(CE_CONT, "  parent = 0x%p", bar->parent);
	cmn_err(CE_CONT, "  init_err_count = %lu", bar->init_err_count);
	cmn_err(CE_CONT, "  transfer_errors = %u", bar->transfer_errors);
	if ((bar->scope == BARRIER_TIME_REGIONS) ||
	    (bar->scope == BARRIER_THREAD_REGIONS)) {
		cmn_err(CE_CONT, "  num_regions = %u", bar->num_regions);
	}
	if ((bar->scope == BARRIER_TIME_NODE) ||
	    (bar->scope == BARRIER_THREAD_NODE)) {
		cmn_err(CE_CONT, "  cnodeid = %u", bar->cnodeid);
	}
	cmn_err(CE_CONT, "}");
}
#endif /* DEBUG */
