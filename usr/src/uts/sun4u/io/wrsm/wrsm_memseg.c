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
 * This file manages generic RSMPI memory segment management, setup and
 * teardown.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <sys/sunddi.h>
#include <sys/ddimapreq.h>
#include <sys/taskq.h>

#include <sys/rsm/rsmpi.h>

#include <sys/wrsm_common.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>
#include <sys/wrsm_intr.h>


#ifdef DEBUG
#define	DBG_MEMSEG		0x001
#define	DBG_MEMSEG_EXTRA	0x010

static uint_t wrsm_memseg_debug = DBG_MEMSEG;

#define	DPRINTF(a, b) { if (wrsm_memseg_debug & a) wrsmdprintf b; }

#else /* DEBUG */
#define	DPRINTF(a, b) { }
#endif /* DEBUG */


/* Non-pageable kernel memory is allocated from the wrsm_arena. */
static vmem_t *wrsm_arena;

static boolean_t
memseg_sess_teardown(wrsm_node_t *node)
{
	boolean_t teardown_complete = B_TRUE;

	DPRINTF(DBG_MEMSEG, (CE_CONT, "ctlr %d: memseg_sess_teardown node %d\n",
	    node->network->rsm_ctlr_id, node->config->cnodeid));
	/*
	 * it is presumed that at this point the node was removed from the
	 * cluster_members_bits registers in all wcis
	 */

	mutex_enter(&node->memseg->lock);

	/*
	 * clean up exports to the remote node
	 */
	if (!exportseg_sess_teardown(node)) {
		teardown_complete = B_FALSE;
	}

	/*
	 * clean up iseginfos imported from remote node
	 */
	if (!iseginfo_sess_teardown(node)) {
		teardown_complete = B_FALSE;
	}

	mutex_exit(&node->memseg->lock);

	return (teardown_complete);
}



static boolean_t
memseg_sess_notify(wrsm_network_t *network, cnodeid_t cnodeid,
    wrsm_sess_state state)
{
	boolean_t teardown_complete = B_TRUE;

	switch (state) {
		/*
		 * nothing to do on SESSION_UP
		 */
		case SESSION_DOWN:
			teardown_complete = memseg_sess_teardown(
			    network->nodes[cnodeid]);
			break;
	}

	return (teardown_complete);
}

/*
 *
 * driver initialization functions
 *
 */

void
wrsm_memseg_node_init(wrsm_node_t *node)
{
	struct wrsm_node_memseg *memseg;

	DPRINTF(DBG_MEMSEG_EXTRA, (CE_CONT, "wrsm_memseg_node_init(cnode %d)\n",
	    node->config->cnodeid));

	memseg = (struct wrsm_node_memseg *)kmem_zalloc(
	    sizeof (struct wrsm_node_memseg), KM_SLEEP);
	mutex_init(&memseg->lock, NULL, MUTEX_DRIVER, NULL);
	memseg->removing_session = B_FALSE;
	node->memseg = memseg;
}

void
wrsm_memseg_node_fini(wrsm_node_t *node)
{
#ifdef DEBUG
	int i;
#endif
	DPRINTF(DBG_MEMSEG_EXTRA, (CE_CONT, "wrsm_memseg_node_fini(cnode %d)\n",
	    node->config->cnodeid));

#ifdef DEBUG
	/* verify that the segment is really not in use */
	ASSERT(node->memseg->connected == NULL);
	ASSERT(node->memseg->wait_for_unmaps == 0);

	mutex_enter(&node->memseg->lock);
	for (i = 0; i < WRSM_SEGID_HASH_SIZE; i++) {
		ASSERT(node->memseg->iseginfo_hash[i] == NULL);
	}
	mutex_exit(&node->memseg->lock);
#endif
	mutex_destroy(&node->memseg->lock);
	kmem_free(node->memseg, sizeof (wrsm_node_memseg_t));
	node->memseg = NULL;
}

void
wrsm_memseg_network_init(wrsm_network_t *network)
{
	DPRINTF(DBG_MEMSEG_EXTRA, (CE_CONT, "wrsm_memseg_init(ctlr %d)\n",
	    network->rsm_ctlr_id));

	/* this initiates all variables to 0 */
	network->memseg = kmem_zalloc(sizeof (wrsm_memseg_t), KM_SLEEP);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_CONNECT,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);
	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_CONNECT_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_SMALLPUTMAP,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);
	(void) wrsm_tl_add_handler(network,
	    WRSM_MSG_SEGMENT_SMALLPUTMAP_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_BARRIERMAP,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);
	(void) wrsm_tl_add_handler(network,
	    WRSM_MSG_SEGMENT_BARRIERMAP_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_SEGMAP,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);
	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_SEGMAP_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_DISCONNECT,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_UNPUBLISH,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);
	(void) wrsm_tl_add_handler(network,
	    WRSM_MSG_SEGMENT_UNPUBLISH_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_ACCESS,
	    wrsm_tl_txhandler_sessionid, wrsm_memseg_msg_hdlr);

	/*
	 * Register for session teardown calls
	 */
	wrsm_sess_register(network, memseg_sess_notify);
}

void
wrsm_memseg_network_fini(wrsm_network_t *network)
{
	DPRINTF(DBG_MEMSEG_EXTRA, (CE_CONT, "wrsm_memseg_fini(ctlr %d)\n",
	    network->rsm_ctlr_id));


	/*
	 * If there are importsegs or exportsegs left around which a client
	 * did not destroy prior to doing release controller, destroy them
	 * now.
	 */
	wrsm_free_exportsegs(network);
	wrsm_free_importsegs(network);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_CONNECT,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_CONNECT_RESPONSE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_SMALLPUTMAP,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(network,
	    WRSM_MSG_SEGMENT_SMALLPUTMAP_RESPONSE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_BARRIERMAP,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(network,
	    WRSM_MSG_SEGMENT_BARRIERMAP_RESPONSE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_SEGMAP,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_SEGMAP_RESPONSE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_DISCONNECT,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_UNPUBLISH,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(network,
	    WRSM_MSG_SEGMENT_UNPUBLISH_RESPONSE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	(void) wrsm_tl_add_handler(network, WRSM_MSG_SEGMENT_ACCESS,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	wrsm_sess_unregister(network, memseg_sess_notify);

	kmem_free(network->memseg, sizeof (wrsm_memseg_t));
}


void
wrsm_memseg_init(void)
{
	mutex_init(&all_exportsegs_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&all_importsegs_lock, NULL, MUTEX_DRIVER, NULL);
	wrsm_arena = vmem_create("wrsm_arena", NULL, 0,
			    PAGESIZE, vmem_alloc, vmem_free,
			    static_arena, PAGESIZE, VM_SLEEP);
}


void
wrsm_memseg_fini(void)
{
	vmem_destroy(wrsm_arena);
	mutex_destroy(&all_exportsegs_lock);
	mutex_destroy(&all_importsegs_lock);
}

void
wrsm_memseg_stat(wrsm_network_t *network, wrsm_memseg_stat_data_t *data)
{
	mutex_enter(&network->lock);
	data->export_count = network->memseg->export_count;
	data->export_published = network->memseg->export_published;
	data->export_connected = network->memseg->export_connected;
	data->bytes_bound = network->memseg->bytes_bound;
	data->import_count = network->memseg->import_count;
	mutex_exit(&network->lock);
}


/*
 * wrsm alloc routine used in place of kmem_{z}alloc()
 * as it allocates memory from the  non-relocatable heap arena
 */
void *
wrsm_alloc(size_t size, int flags)
{
	return (vmem_alloc(wrsm_arena, size, flags));
}

/*
 * wrsm free routine used in place of kmem_{z}alloc()
 * as it frees memory to the  non-relocatable heap arena
 */
void
wrsm_free(void *addr, size_t size)
{
	vmem_free(wrsm_arena, addr, size);
}
