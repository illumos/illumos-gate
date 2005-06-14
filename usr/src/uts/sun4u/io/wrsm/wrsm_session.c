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
 * Session management module of the Wildcat RSM driver.  This module sets
 * up sessions with remote drivers.  If communication is lost, it notifies
 * interested registered modules so they can invalidate any existing
 * communication paths.
 */

#include <sys/types.h>

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/membar.h>

#include <sys/wrsm_session.h>
#include <sys/wrsm_config.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_sess_impl.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_memseg.h>

/*
 * The following macros define a DPRINTF macro which can be used to enable
 * or disable various levels of logging for this module.
 */
#ifdef DEBUG

#define	SESSDBG		0x1
#define	SESSWARN	0x2
#define	SESSERR		0x4
#define	SESSTRACE	0x8
static uint_t wrsm_sess_debug = SESSERR;

#define	DPRINTF(a, b) { if (wrsm_sess_debug & a) wrsmdprintf b; }

static const char *sess_state_txt[] = {
	"SESS_STATE_UNREACH",
	"SESS_STATE_DOWN",
	"SESS_STATE_ESTAB",
	"SESS_STATE_UP"};

#else /* DEBUG */

#define	DPRINTF(a, b)

#endif /* DEBUG */

#define	DTRC(s)	DPRINTF(SESSTRACE, (CE_CONT, s))
#define	ERR(s)	DPRINTF(SESSERR, (CE_WARN, s))
#define	WARN(s)	DPRINTF(SESSWARN, (CE_WARN, s))
#define	NOTE(s)	DPRINTF(SESSDBG, (CE_NOTE, s))


/*
 * Local function prototypes
 */
static void node_init(wrsm_session_t *, cnodeid_t);
static void node_fini(wrsm_node_session_t *);
static void node_new_state(wrsm_network_t *, cnodeid_t,
    sess_state, wrsm_sessionid_t);
static void msg_init(wrsm_network_t *);
static void msg_fini(wrsm_network_t *);
static boolean_t msg_session_start(wrsm_network_t *, wrsm_message_t *);
static boolean_t msg_session_start_rsp(wrsm_network_t *, wrsm_message_t *);
static boolean_t msg_session_end(wrsm_network_t *, wrsm_message_t *);

/*
 * Local functions
 */


/* Distributes callbacks to all clients */
static int
callback_clients(wrsm_network_t *net, cnodeid_t cnode, wrsm_sess_state state)
{
	uint_t i;
	wrsm_session_t *sess = net->session;
	int dereferences_needed = 0;

	DPRINTF(SESSTRACE, (CE_CONT, "callback clients ctlr %d\n",
	    net->rsm_ctlr_id));

	for (i = 0; i < MAX_CLIENTS; i++) {
		wrsm_sess_func_t fn = sess->cb[i];
		if (fn) {
			if (!(*fn)(net, cnode, state)) {
				dereferences_needed++;
			}
		}
	}

	return (dereferences_needed);
}


/*
 * Node related functions
 */

/* Initializes node structure */
static void
node_init(wrsm_session_t *sess, cnodeid_t cnodeid)
{
	wrsm_node_session_t *node = &sess->node[cnodeid];
	node->cnodeid = cnodeid;
	mutex_init(&node->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&node->cv_session_up, NULL, CV_DRIVER, NULL);
	cv_init(&node->cv_state_changing, NULL, CV_DRIVER, NULL);
	cv_init(&node->cv_await_dereferences, NULL, CV_DRIVER, NULL);
	node->enabled = B_TRUE;
	node->state = SESS_STATE_UNREACH;
	node->session_id = SESS_ID_INVALID;
	node->last_session_id = 0;
	node->barrier_mem = NULL;
}

/* Cleans up node structure */
static void
node_fini(wrsm_node_session_t *node)
{
	mutex_destroy(&node->mutex);
	cv_destroy(&node->cv_session_up);
	cv_destroy(&node->cv_state_changing);
	cv_destroy(&node->cv_await_dereferences);
}

/*
 * Changes state of node, performing callback if required.
 * NOTE: Releases the node->mutex lock during callbacks.
 */
static void
node_new_state(wrsm_network_t *net, cnodeid_t cnodeid,
    sess_state new_state, wrsm_sessionid_t new_session_id)
{
	wrsm_session_t *sess = net->session;
	wrsm_node_session_t *node = &sess->node[cnodeid];
	sess_state old_state;
	int err;

	DPRINTF(SESSTRACE, (CE_CONT,
	    "node_new_state(ctrl=%u, cnode=%u, state=%s, sess_id=%u)",
	    net->rsm_ctlr_id, cnodeid, sess_state_txt[new_state],
	    new_session_id));
	ASSERT(mutex_owned(&node->mutex));
	while (node->state_changing) {
		cv_wait(&node->cv_state_changing, &node->mutex);
	}
	old_state = node->state;
	node->state = new_state;
	node->session_id = new_session_id;
	node->state_changing = B_TRUE;
	if (node->state == SESS_STATE_UP) {
		cv_broadcast(&node->cv_session_up);
	}
	mutex_exit(&node->mutex);

	if (old_state == SESS_STATE_UP && new_state != SESS_STATE_UP) {
		node->dereferences_needed = callback_clients(net, cnodeid,
		    SESSION_DOWN);
		DPRINTF(SESSDBG, (CE_CONT, "callback clients ctlr %d "
		    "node %d dereferences_needed %d\n",
		    net->rsm_ctlr_id, cnodeid, node->dereferences_needed));
		wrsm_clustermember_delete(net, cnodeid);
		/* Unmap remote barrier page */
		ddi_unmap_regs(wrsm_ncslice_dip,
		    node->remote_tuple.ncslice,
		    &node->barrier_page,
		    (off_t)node->remote_tuple.offset,
		    MMU_PAGESIZE);
		node->barrier_page = NULL;
	} else if (old_state != SESS_STATE_UP && new_state == SESS_STATE_UP) {
		/* Map remote barrier page */
		if (node->remote_tuple.ncslice !=
		    net->nodes[cnodeid]->config->exported_ncslices.id[0]) {
			/*
			 * Node is claiming it exports an ncslice it doesn't!
			 * Something must be wrong with connection.
			 */
			DPRINTF(SESSWARN, (CE_WARN, "sess node_new_state: "
			    "bad ncslice %d from node %d\n",
			    node->remote_tuple.ncslice, cnodeid));
			node->state = old_state;
		} else {
			err = ddi_map_regs(wrsm_ncslice_dip,
			    node->remote_tuple.ncslice,
			    &node->barrier_page,
			    (off_t)node->remote_tuple.offset,
			    MMU_PAGESIZE);
			if (err) {
				node->state = old_state;
			} else {
				wrsm_clustermember_add(net, cnodeid);
				(void) callback_clients(net, cnodeid,
				    SESSION_UP);
			}
		}
	}

	/* Re-enter the node->mutex lock */
	mutex_enter(&node->mutex);
	node->state_changing = B_FALSE;
	cv_signal(&node->cv_state_changing);
}

/*
 * Message related functions
 */

/* Regiseters message handling functions */
static void
msg_init(wrsm_network_t *net)
{
	(void) wrsm_tl_add_handler(net, WRSM_MSG_SESSION_START,
			WRSM_TL_NO_HANDLER, msg_session_start);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_SESSION_START_RESPONSE,
			WRSM_TL_NO_HANDLER, msg_session_start_rsp);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_SESSION_END,
			WRSM_TL_NO_HANDLER, msg_session_end);
}

/* Removes message handling functions */
static void
msg_fini(wrsm_network_t *net)
{
	(void) wrsm_tl_add_handler(net, WRSM_MSG_SESSION_START,
			WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_SESSION_END,
			WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_SESSION_START_RESPONSE,
			WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
}

/* Handles session start message */
static boolean_t
msg_session_start(wrsm_network_t *net, wrsm_message_t *message)
{
	msg_session_start_t *msg = (msg_session_start_t *)message;
	wrsm_node_session_t *node;
	wrsm_raw_message_t raw_response;
	msg_session_start_rsp_t *response = (msg_session_start_rsp_t *)
		&raw_response;
	DTRC("msg_session_start");

	ASSERT(net);
	ASSERT(msg);
	ASSERT(response);

	node = &net->session->node[msg->header.source_cnode];
	response->header.message_type = WRSM_MSG_SESSION_START_RESPONSE;
	response->session_id = msg->session_id;
	response->barrier_ncslice = node->barrier_tuple->ncslice;
	response->barrier_offset = (off_t)node->barrier_tuple->offset;
	response->result = SESS_SUCCESS; /* Assume success */
	mutex_enter(&node->mutex);

	switch (node->state) {
	case SESS_STATE_UNREACH:
		response->result = (node->enabled) ? ENXIO : EPERM;
		break;

	case SESS_STATE_DOWN:
		if (node->enabled) {
			node->remote_tuple.ncslice = msg->barrier_ncslice;
			node->remote_tuple.offset = msg->barrier_offset;
			node_new_state(net, node->cnodeid,
			    SESS_STATE_UP, msg->session_id);
		} else {
			response->result = EPERM;
		}
		break;

	case SESS_STATE_ESTAB:
		if (msg->header.source_cnode > net->cnodeid) {
			/* If we have lower cnodeid, ignore them */
			response->result = EBUSY;
		} else {
			/* If they have lower cnodeid, then they win */
			node->remote_tuple.ncslice = msg->barrier_ncslice;
			node->remote_tuple.offset = msg->barrier_offset;
			node_new_state(net, node->cnodeid,
			    SESS_STATE_UP, msg->session_id);
		}
		break;

	case SESS_STATE_UP:
		/* New session request. Go down then back up */
		node_new_state(net, node->cnodeid,
		    SESS_STATE_DOWN, SESS_ID_INVALID);
		node->remote_tuple.ncslice = msg->barrier_ncslice;
		node->remote_tuple.offset = msg->barrier_offset;
		node_new_state(net, node->cnodeid,
		    SESS_STATE_UP, msg->session_id);
		break;
	}

	/* Only send response if this is not loopback */
	if (net->cnodeid != msg->header.source_cnode) {
		(void) wrsm_tl_dg(net, msg->header.source_cnode,
		    (wrsm_message_t *)response);
	}
	mutex_exit(&node->mutex);
	return (B_TRUE);
}

static boolean_t
msg_session_start_rsp(wrsm_network_t *net, wrsm_message_t *message)
{
	msg_session_start_rsp_t *msg = (msg_session_start_rsp_t *)message;
	wrsm_node_session_t *node;
	cnodeid_t source;
	DTRC("msg_session_start_rsp");

	ASSERT(net);
	ASSERT(msg);

	source = msg->header.source_cnode;
	node = &net->session->node[source];
	mutex_enter(&node->mutex);

	if (node->state == SESS_STATE_ESTAB &&
	    node->session_id == msg->session_id) {
		if (msg->result) {
			DPRINTF(SESSERR, (CE_WARN,
			    "sess_start_rsp from cnode %u to ctlr %u:"
			    "bad result = %d",
			    source, net->rsm_ctlr_id, msg->result));
			node_new_state(net, source, SESS_STATE_DOWN,
			    SESS_ID_INVALID);
		} else {
			node->remote_tuple.ncslice = msg->barrier_ncslice;
			node->remote_tuple.offset =
				(caddr_t)msg->barrier_offset;
			node_new_state(net, source, SESS_STATE_UP,
			    node->session_id);
		}
	/* LINTED: E_NOP_ELSE_STMT */
	} else {
		DPRINTF(SESSERR, (CE_WARN,
		    "unexpected sess_start_rsp from cnode %u to ctlr %u: "
		    "result %d, wrong state %s",
		    source, net->rsm_ctlr_id, msg->result,
		    sess_state_txt[node->state]));
	}
	mutex_exit(&node->mutex);
	return (B_TRUE);
}

static boolean_t
msg_session_end(wrsm_network_t *net, wrsm_message_t *message)
{
	msg_session_end_t *msg = (msg_session_end_t *)message;
	wrsm_node_session_t *node;
	DTRC("msg_session_end");

	ASSERT(net);
	ASSERT(msg);

	node = &net->session->node[msg->header.source_cnode];
	mutex_enter(&node->mutex);

	switch (node->state) {
	case SESS_STATE_ESTAB:
	case SESS_STATE_UP:
		node_new_state(net, node->cnodeid, SESS_STATE_DOWN,
		    SESS_ID_INVALID);
		break;
	}

	mutex_exit(&node->mutex);
	return (B_TRUE);
}

/*
 * Interface Functions
 */

/* Init function. */
void
wrsm_sess_init(wrsm_network_t *net)
{
	uint_t i;
	wrsm_session_t *sess;
	DTRC("wrsm_sess_init");

	/* Add session structure to the net structure. */
	ASSERT(net);
	sess = kmem_zalloc(sizeof (wrsm_session_t), KM_SLEEP);
	ASSERT(sess);

	/* Initialize client callback structure to all NULL */
	for (i = 0; i < MAX_CLIENTS; i++) {
		sess->cb[i] = NULL;
	}

	/* Initialize cnode-specific structures */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node_init(sess, i);
	}

	/* Tell transport about our message handlers */
	msg_init(net);

	/* Publish! */
	net->session = sess;
}

/* Fini function. */
void
wrsm_sess_fini(wrsm_network_t *net)
{
	uint_t i;
	wrsm_node_session_t *node;

	DTRC("wrsm_sess_fini");

	/* Remove our transport message handlers */
	msg_fini(net);

	/* Clean-up per node session structures */
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		node = &net->session->node[i];
		ASSERT((node->state == SESS_STATE_DOWN) ||
		    (node->state == SESS_STATE_UNREACH));
		ASSERT(node->dereferences_needed == 0);
		node_fini(node);
	}

	kmem_free(net->session, sizeof (wrsm_session_t));
	net->session = NULL;

}

/* Informs session that a new cnode is reachable */
void
wrsm_sess_reachable(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_node_session_t *node;
	unsigned num_tuples;
	caddr_t aligned_vaddr;
	wrsm_cmmu_t cmmu;
	int err;

	ASSERT(net);
	ASSERT(net->session);
	node = &net->session->node[cnodeid];
	ASSERT(node->state == SESS_STATE_UNREACH);

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_reachable: cnodeid = %u",
	    cnodeid));
	mutex_enter(&node->mutex);

	/* First, allocate a cmmu entry */
	err = wrsm_cmmu_alloc(net, CMMU_PAGE_SIZE_SMALL, 1,
	    &node->barrier_tuple, &num_tuples, 0);
	if (err != WRSM_SUCCESS) {
		mutex_exit(&node->mutex);
		return;
	}
	/*
	 * Fix up the ncslice in the tuple to use the ncslice the
	 * remote node imports.
	 */
	ASSERT(net->exported_ncslices.id[0] == node->barrier_tuple->ncslice);
	node->barrier_tuple->ncslice =
	    net->nodes[cnodeid]->config->imported_ncslices.id[0];

	/* Allocate enough memory to create an aligned page */
	node->barrier_mem = wrsm_alloc((MMU_PAGESIZE * 2), VM_SLEEP);
	bzero(node->barrier_mem, (MMU_PAGESIZE * 2));

	/* Find page-aligned address */
	aligned_vaddr = (caddr_t)
	    ((uint64_t)((caddr_t)node->barrier_mem + MMU_PAGEOFFSET) &
		(uint64_t)MMU_PAGEMASK);

	/* Write CMMU entry */
	cmmu.entry_0.val = 0;
	cmmu.entry_0.bit.count_enable = B_FALSE;
	cmmu.entry_0.bit.large_page = B_FALSE;
	cmmu.entry_0.bit.user_err = B_FALSE;
	cmmu.entry_0.bit.writable = B_TRUE;
	cmmu.entry_0.bit.from_all = B_FALSE;
	cmmu.entry_0.bit.valid = B_TRUE;
	cmmu.entry_0.bit.type = CMMU_TYPE_CACHEABLE;
	cmmu.entry_0.bit.from_node = cnodeid;

	cmmu.entry_1.val = 0;
	cmmu.entry_1.addr.lpa_page = hat_getpfnum(kas.a_hat, aligned_vaddr);

	/* Update the CMMU */
	wrsm_cmmu_update(net, &cmmu, node->barrier_tuple->index,
	    CMMU_UPDATE_ALL);

	node_new_state(net, cnodeid, SESS_STATE_DOWN, SESS_ID_INVALID);
	mutex_exit(&node->mutex);

	/* Start the process of establishing a new session */
	wrsm_sess_establish(net, cnodeid);
}

/* Informs session that a cnode is no longer reachable */
void
wrsm_sess_unreachable(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_cmmu_t cmmu;
	wrsm_node_session_t *node;

	ASSERT(net);
	ASSERT(net->session);
	node = &net->session->node[cnodeid];
	ASSERT(node->state != SESS_STATE_UNREACH);

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_unreachable: cnodeid = %u",
	    cnodeid));

	mutex_enter(&node->mutex);
	node_new_state(net, cnodeid, SESS_STATE_UNREACH, SESS_ID_INVALID);

	/* Set CMMU to invalid */
	cmmu.entry_0.val = 0;
	cmmu.entry_1.val = 0;
	wrsm_cmmu_update(net, &cmmu, node->barrier_tuple->index,
	    CMMU_UPDATE_ALL);
	wrsm_cmmu_free(net, 1, node->barrier_tuple);

	/* Free barrier page memory */
	wrsm_free(node->barrier_mem, MMU_PAGESIZE * 2);
	node->barrier_mem = NULL;

	mutex_exit(&node->mutex);
}

/*
 * Functions for client use.
 */

/* Establishes a session with a remote cnode, if enabled. */
wrsm_sessionid_t
wrsm_sess_establish(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_sessionid_t session_id = SESS_ID_INVALID;

	wrsm_node_session_t *node;

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_establish: cnodeid = %u",
	    cnodeid));

	ASSERT(net);
	node = &net->session->node[cnodeid];
	if (!node->enabled) {
		return (SESS_ID_INVALID);
	}

	mutex_enter(&node->mutex);

	/* If the session is currently down or being established... */
	if (node->state == SESS_STATE_DOWN ||
	    node->state == SESS_STATE_ESTAB) {
		clock_t timeout;

		/* Queue an event to the event thread, if necessary */
		if (!node->event_queued) {
			wrsm_nr_event_t *event;

			node->event_queued = B_TRUE;
			event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
			event->type = wrsm_evt_sessup;
			event->data.sess.cnodeid = cnodeid;
			wrsm_nr_add_event(net, event, B_TRUE);
		}
		/* Wait for session to be established, or timeout */
		timeout = ddi_get_lbolt() + drv_usectohz(SESS_TIMEOUT);
		(void) cv_timedwait(&node->cv_session_up, &node->mutex,
		    timeout);
	}

	/* If the session came up, return the session id */
	if (node->state == SESS_STATE_UP) {
		session_id = node->session_id;
	}
	mutex_exit(&node->mutex);
	return (session_id);
}

/* Establishes a session with a remote cnode, if enabled. */
void
wrsm_sess_establish_immediate(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_node_session_t *node;
	wrsm_raw_message_t raw_msg;
	msg_session_start_t *msg = (msg_session_start_t *)&raw_msg;
	clock_t timeout;
	wrsm_sessionid_t session_id;

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_establish_immediate: "
	    "cnodeid = %u", cnodeid));

	ASSERT(net);
	ASSERT(msg);

	node = &net->session->node[cnodeid];
	mutex_enter(&node->mutex);

	/* Deal with disabled nodes */
	if (!node->enabled) {
		node->event_queued = B_FALSE;
		mutex_exit(&node->mutex);
		return;
	}

	if (node->state == SESS_STATE_DOWN) {
		/* Get a new session id and set state to establishing */
		node->last_session_id++;
		if (node->last_session_id == SESS_ID_INVALID) {
			node->last_session_id++;
		}
		session_id = node->last_session_id;
		node_new_state(net, cnodeid, SESS_STATE_ESTAB,
		    session_id);

		/* Create and send session start message */
		msg->session_id = node->session_id;
		msg->barrier_ncslice = node->barrier_tuple->ncslice;
		msg->barrier_offset = node->barrier_tuple->offset;
		msg->header.message_type = WRSM_MSG_SESSION_START;
		(void) wrsm_tl_dg(net, cnodeid, (wrsm_message_t *)msg);

		/* Wait for msg_session_start_rsp */
		timeout = ddi_get_lbolt() + drv_usectohz(SESS_TIMEOUT);
		(void) cv_timedwait_sig(&node->cv_session_up, &node->mutex,
		    timeout);
		/* Don't care why cv was signaled, just check state... */
		if (node->state != SESS_STATE_UP) {
			node_new_state(net, cnodeid,
			    SESS_STATE_DOWN, SESS_ID_INVALID);
		}
	}
	node->event_queued = B_FALSE;
	mutex_exit(&node->mutex);
}

void
wrsm_sess_teardown_immediate(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_node_session_t *node;
	wrsm_raw_message_t raw_msg;
	msg_session_end_t *msg = (msg_session_end_t *)&raw_msg;

	ASSERT(net);
	ASSERT(net->session);

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_teardown_immediate: "
	    "ctlr %d cnodeid = %u", net->rsm_ctlr_id, cnodeid));

	node = &net->session->node[cnodeid];

	mutex_enter(&node->mutex);
	switch (node->state) {
	case SESS_STATE_UNREACH:
	case SESS_STATE_DOWN:
		break;

	case SESS_STATE_ESTAB:
	case SESS_STATE_UP:
		msg->header.message_type = WRSM_MSG_SESSION_END;
		msg->session_id = node->session_id;
		(void) wrsm_tl_dg(net, cnodeid, (wrsm_message_t *)msg);
		node_new_state(net, cnodeid, SESS_STATE_DOWN, SESS_ID_INVALID);
	}
	mutex_exit(&node->mutex);
}


/* Asynchronously tears down a session to a cnode. */
void
wrsm_sess_teardown(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_nr_event_t *event;

	DTRC("wrsm_sess_teardown");

	event = kmem_alloc(sizeof (wrsm_nr_event_t), KM_SLEEP);
	event->type = wrsm_evt_sessdown;
	event->data.sess.cnodeid = cnodeid;
	wrsm_nr_add_event(net, event, B_TRUE);
}


/* Returns the current session. */
wrsm_sessionid_t
wrsm_sess_get(wrsm_network_t *net, cnodeid_t cnodeid)
{
	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_get: cnodeid = %u", cnodeid));

	ASSERT(net);
	ASSERT(net->session);

	/*
	 * We don't need node->mutex here, because reading one int
	 * is atomic.  Also, since the session_is is set to INVALID
	 * any time the session is not in the UP state, we don't need
	 * to check which state we're in now.
	 */
	return (net->session->node[cnodeid].session_id);
}

/* Allows user to register for callbacks. */
void
wrsm_sess_register(wrsm_network_t *net, wrsm_sess_func_t fn)
{
	uint_t i;
	DTRC("wrsm_sess_register");

	ASSERT(net);
	ASSERT(net->session);
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (net->session->cb[i] == NULL) {
			net->session->cb[i] = fn;
			break;
		}
	}
	ASSERT(i < MAX_CLIENTS);
}

/* Removes a user callback registration. */
void
wrsm_sess_unregister(wrsm_network_t *net, wrsm_sess_func_t fn)
{
	uint_t i;
	DTRC("wrsm_sess_unregister");

	ASSERT(net);
	ASSERT(net->session);
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (net->session->cb[i] == fn) {
			net->session->cb[i] = NULL;
			return;
		}
	}
	ASSERT(0);
}

/*
 * Functions for use by some session control software entitiy.
 */

/* Enables communication with a cnode. */
void
wrsm_sess_enable(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_node_session_t *node = &(net->session->node[cnodeid]);
	clock_t timeout;

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_enable: cnodeid = %u",
	    cnodeid));

	ASSERT(net);

	mutex_enter(&node->mutex);
	if ((node->enabled == B_FALSE) && node->dereferences_needed) {
		/*
		 * A sess disable is in progress.  Wait for it to complete
		 * or fail before enabling.
		 */
		timeout = ddi_get_lbolt() + drv_usectohz(SESS_TIMEOUT);
		(void) cv_timedwait(&node->cv_await_dereferences, &node->mutex,
		    timeout);
	}
	node->enabled = B_TRUE;
	mutex_exit(&node->mutex);
	wrsm_sess_establish(net, cnodeid);
}


/* Disables communication with a cnode. May cause a teardown. */
int
wrsm_sess_disable(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_raw_message_t raw_msg;
	msg_session_start_t *msg = (msg_session_start_t *)&raw_msg;
	wrsm_node_session_t *node = &(net->session->node[cnodeid]);
	clock_t timeout;

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_disable: cnodeid = %u",
	    cnodeid));

	ASSERT(net);

	mutex_enter(&node->mutex);
	node->enabled = B_FALSE;
	if (node->state == SESS_STATE_ESTAB || node->state == SESS_STATE_UP) {
		msg->header.message_type = WRSM_MSG_SESSION_END;
		msg->session_id = node->session_id;
		(void) wrsm_tl_dg(net, cnodeid, (wrsm_message_t *)msg);
		node_new_state(net, cnodeid, SESS_STATE_DOWN, SESS_ID_INVALID);
	}
	if (node->dereferences_needed) {
		timeout = ddi_get_lbolt() + drv_usectohz(SESS_TIMEOUT);
		if (cv_timedwait(&node->cv_await_dereferences, &node->mutex,
		    timeout) == -1) {
			/* timed out waiting for dereferences - fail */
			mutex_exit(&node->mutex);
			return (EBUSY);
		}
	}
	mutex_exit(&node->mutex);
	return (WRSM_SUCCESS);
}


/* Returns a cnode bitmask indicating which cnodes have valid sessions */
void
wrsm_sess_get_cnodes(wrsm_network_t *net, cnode_bitmask_t *cnodes)
{
	uint_t i;
	DTRC("wrsm_sess_get_cnodes");

	ASSERT(net);

	WRSMSET_ZERO(*cnodes);
	for (i = 0; i < WRSM_MAX_CNODES; i++) {
		if (net->session->node[i].state == SESS_STATE_UP) {
			WRSMSET_ADD(*cnodes, i);
		}
	}
}

/*
 * Clients call this when all references to node with invalid session
 * are truly freed
 */
void
wrsm_sess_unreferenced(wrsm_network_t *net, cnodeid_t cnode)
{
	wrsm_session_t *sess = net->session;
	wrsm_node_session_t *node = &sess->node[cnode];

	DPRINTF(SESSTRACE, (CE_CONT, "wrsm_sess_unreferenced ctlr %d node %d\n",
	    net->rsm_ctlr_id, cnode));

	mutex_enter(&node->mutex);

	if (node->dereferences_needed) {
		node->dereferences_needed--;
		DPRINTF(SESSDBG, (CE_CONT,
		    "wrsm_sess_unreferenced dereferences needed now %d\n",
		    node->dereferences_needed));
		if (node->dereferences_needed == 0) {
			cv_broadcast(&node->cv_await_dereferences);
		}
	}

	mutex_exit(&node->mutex);
}

int
wrsm_sess_touch_node(wrsm_network_t *net, cnodeid_t cnodeid, uint32_t stripes)
{
	int str;
	caddr_t vaddr;
	wrsm_raw_message_t raw_buf;
	uint64_t *buf = (uint64_t *)&raw_buf;
	wrsm_node_session_t *node = &net->session->node[cnodeid];
	const uint64_t pattern = 0x0123456789abcdef; /* Arbitrary, non-zero */

	DPRINTF(SESSTRACE, (CE_CONT,
	    "wrsm_sess_touch_node(cnode=%d,stripes=0x%X)",
	    cnodeid, stripes));

	membar_sync();
	mutex_enter(&node->mutex);

	if (node->state != SESS_STATE_UP) {
		WARN("wrsm_sess_touch_node: session not up");
		mutex_exit(&node->mutex);
		return (RSMERR_CONN_ABORTED);
	}
	if (node->barrier_page == NULL) {
		WARN("wrsm_sess_touch_node: NULL barrier_page pointer");
		mutex_exit(&node->mutex);
		return (RSMERR_CONN_ABORTED);
	}
	buf[0] = pattern;  /* Seed first part of buffer with pattern */
	buf[4] = ~pattern; /* Seed second half of buffer */

	/* If multiple stripes, get all the writes going in parallel... */
	vaddr = node->barrier_page;
	for (str = stripes; str; str = str >> 1) {
		if (str & 1) {
			wrsm_blkwrite(buf, vaddr, 1);
		}
		vaddr += WCI_CLUSTER_STRIPE_STRIDE;
	}
	membar_sync();

	/* Now read back. If we get an error, data will be 0. */
	vaddr = node->barrier_page;
	for (str = stripes; str; str = str >> 1) {
		if (str & 1) {
			wrsm_blkread(vaddr, buf, 1);
			if (buf[0] != pattern ||
			    buf[4] != ~pattern) {
				WARN("wrsm_sess_touch_node: pattern mismatch");
				mutex_exit(&node->mutex);
				return (RSMERR_BARRIER_FAILURE);
			}
		}
		vaddr += WCI_CLUSTER_STRIPE_STRIDE;
	}

	mutex_exit(&node->mutex);
	return (RSM_SUCCESS);
}
