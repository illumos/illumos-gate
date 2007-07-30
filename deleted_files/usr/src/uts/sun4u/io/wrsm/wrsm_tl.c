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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Transport Layer of the Wildcat RSM driver.  This module provides an rpc
 * and datagram service by sending/receiving interrupts to/from remote
 * drivers.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <vm/hat.h>
#include <sys/promif.h>
#include <sys/disp.h>
#include <sys/callb.h>
#include <sys/taskq.h>

#include <sys/wci_common.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_memseg.h>
#include <sys/wrsm_memseg_impl.h>
/*
 * Manifest Constants and Macros
 */

#ifdef DEBUG

#define	TLDBG		0x1
#define	TLWARN		0x2
#define	TLERR		0x4
#define	TLTRACE		0x8
#define	TLDUMP		0x10
static uint_t tl_debug = TLERR;

#define	DPRINTF(a, b) { if (tl_debug & a) wrsmdprintf b; }

#else /* DEBUG */

#define	DPRINTF(a, b) { }

#endif /* DEBUG */

#define	WARN(s) DPRINTF(TLWARN, (CE_WARN, s))
#define	NOTE(s) DPRINTF(TLDBG, (CE_NOTE, s))

#define	WRSM_TL_PACKETRING_SIZE	118	/* Fill up 1 page */
/*
 * Set RPC message highwater mark to 44%, lowwater to 20% of packetring
 * size.  44% allows reply messages and other messages that don't go through
 * the flow control to have some space.
 */
#define	WRSM_TL_RPC_HIGHWATER_PERCENT (88)
#define	WRSM_TL_RPC_LOWWATER_PERCENT  (20)
#define	WRSM_TL_RPC_HIGHWATER (((((WRSM_TL_PACKETRING_SIZE) / 2) * \
				(WRSM_TL_RPC_HIGHWATER_PERCENT)) / 100) + 1)
#define	WRSM_TL_RPC_LOWWATER  (((WRSM_TL_PACKETRING_SIZE) * \
				(WRSM_TL_RPC_LOWWATER_PERCENT)) / 100)
int wrsm_tl_rpc_highwater = WRSM_TL_RPC_HIGHWATER;
int wrsm_tl_rpc_lowwater  = WRSM_TL_RPC_LOWWATER;

#define	WRSM_TL_DEVLOAD_ATTRS	(PROT_READ | PROT_WRITE | HAT_NEVERSWAP | \
				HAT_STRICTORDER)

/*
 * Message IDs go from 1 through 0x7fffffff. ID 0 is reserved as a null id.
 * The MSB of the message ID is reserved as an RPC response flag. If this
 * bit is set, the message is a response to the message whose ID is stored
 * in the lower 31 bits.
 */
#define	MESSAGE_ID_INVALID	0
#define	MESSAGE_ID_FIRST	1
#define	MESSAGE_ID_MAX		0x7fffffff
#define	MESSAGE_ID_RPCRESP	0x80000000

#define	MAKERESPID(msgid)	((msgid) | MESSAGE_ID_RPCRESP)
#define	MAKEORIGID(respid)	((respid) & MESSAGE_ID_MAX)
#define	ISRESPONSEID(msgid)	(((msgid) & MESSAGE_ID_RPCRESP) != 0)
#define	ISDATAGRAMID(msgid)	(!ISRESPONSEID(msgid))

#define	MASK_ALIGN		(~0x3f)
#define	IS_ALIGNED(ptr)		(((uint64_t)(ptr) & 0x3f) == 0)

/*
 * RPC timeout:
 * The nr_event_thread that awakens to process response events may actually
 * be delayed by up to 1.5 seconds if the processor it is scheduled to run on
 * is in the middle of running wrsm_lc_clear_cmmu() for another controller.
 * This function calls wrsm_lc_cmmu_update() 2,097,152 times, resulting in the
 * observed delay.  Therefore, we set the RPC timeout to 5 seconds to be safe.
 */
static uint_t wrsm_tl_rpc_timeout = (5*1000*1000); /* 5 secs */

/*
 * This tunable controls the number of worker threads available per taskq.
 * There is one taskq for each of the 7 categories of messages, so multiply
 * this value by 7 to get the total number of worker threads created.
 */
static uint_t wrsm_tl_tqthreads = 1;

/* #define msgcpy(dest, src) bcopy((dest), (src), sizeof (wrsm_message_t)) */
void
msgcpy(wrsm_message_t *dest, wrsm_message_t *src)
{
	unsigned i;

	dest->header.reserved1 = src->header.reserved1;
	dest->header.version = src->header.version;
	dest->header.session_id = src->header.session_id;
	dest->header.source_cnode = src->header.source_cnode;
	dest->header.message_type = src->header.message_type;
	dest->header.message_id = src->header.message_id;
	dest->header.reserved2 = src->header.reserved2;
	for (i = 0; i < WRSM_MESSAGE_BODY_SIZE; i++) {
		dest->body[i] = src->body[i];
	}
}

/*
 * Local Typedefs
 */

/*
 * The following is an element in a linked list of RPC's waiting for a
 * response. The message_id is used to match response with original
 * message, and *response is where the user wants the response placed.
 */
typedef struct pending_rpc {
	wrsm_messageid_t message_id;
	struct pending_rpc *next;
	struct pending_rpc *prev;
	kcondvar_t cv;
	kmutex_t mutex;
	boolean_t resp_recvd;
	wrsm_message_t *response;
} pending_rpc_t;

/*
 * The wrsm_transport holds the state of a given instance of
 * the transport.
 */
typedef struct tl_cnode {
	wrsm_intr_recvq_t *recvq;
	wrsm_cmmu_tuple_t tuple;
	caddr_t addr;
	uint_t  offset;
	boolean_t reachable;
} tl_cnode_t;

typedef struct tl_event {
	wrsm_network_t *net;
	wrsm_message_t msg;
	wrsm_message_rxhandler_t handler;
	struct tl_event *next;
} tl_event_t;

struct wrsm_transport {
	kmutex_t mutex;
	wrsm_message_txhandler_t tx_handlers[WRSM_MSG_TYPES_MAX];
	wrsm_message_rxhandler_t rx_handlers[WRSM_MSG_TYPES_MAX];
	pending_rpc_t *rpc_list;
	kcondvar_t rpc_cv;
	uint_t rpc_count;
	wrsm_messageid_t last_message_id;
	tl_cnode_t cnode[WRSM_MAX_CNODES];

	/* event thread handling */
	kmutex_t event_mutex;
	kcondvar_t event_cv;
	kthread_t *event_thread;
	tl_event_t *events;
	boolean_t stop_events;
	kcondvar_t event_exit_cv;

	/* taskqs for WRSM_MSG_SEGMENT_* messages */
	kmutex_t taskq_mutex;
	boolean_t stop_taskqs;
	taskq_t *connect_taskq;
	taskq_t *smallputmap_taskq;
	taskq_t *barriermap_taskq;
	taskq_t *segmap_taskq;
	taskq_t *disconnect_taskq;
	taskq_t *unpublish_taskq;
	taskq_t *access_taskq;
};

/*
 * Event Handling
 */

/* Processes events for the event thread. */
static void
tl_process_events(wrsm_transport_t *tl)
{
	tl_event_t *event;

	ASSERT(mutex_owned(&tl->event_mutex));

	while (tl->events) {
		event = tl->events;
		tl->events = event->next;
		mutex_exit(&tl->event_mutex);

		(void) (*event->handler)(event->net, &event->msg);

		kmem_free(event, sizeof (tl_event_t));

		mutex_enter(&tl->event_mutex);
	}

}

/*
 * Event thread.  Handles TL message processing so we don't have to
 * process in the interrupt thread
 */
static void
tl_event_thread(void *arg)
{
	wrsm_transport_t *tl = (wrsm_transport_t *)arg;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &tl->event_mutex,
		callb_generic_cpr, "tl_event_thread");

	mutex_enter(&tl->event_mutex);

	while (!tl->stop_events) {
		tl_process_events(tl);

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&tl->event_cv, &tl->event_mutex);
		CALLB_CPR_SAFE_END(&cprinfo, &tl->event_mutex);
	}

	tl_process_events(tl);
	cv_broadcast(&tl->event_exit_cv);

	/*
	 * CALLB_CPR_EXIT() calls mutex_exit() on the
	 * lock passed into CALLB_CPR_INIT() above, therefore
	 * we don't want to call mutex_exit() here. See
	 * common/sys/callb.h and common/sys/cpr.h.
	 */
	CALLB_CPR_EXIT(&cprinfo);

	thread_exit();
}

/* Adds an event to the event queue and wakes up the event thread */
static void
tl_add_event(wrsm_transport_t *tl, tl_event_t *event)
{
	tl_event_t *evt;

	mutex_enter(&tl->event_mutex);

	if (tl->stop_events) {
		mutex_exit(&tl->event_mutex);
		return;
	}

	evt = tl->events;
	if (evt) {
		while (evt->next)
			evt = evt->next;
		evt->next = event;
	} else {
		tl->events = event;
	}

	cv_broadcast(&tl->event_cv);
	mutex_exit(&tl->event_mutex);
}


/*
 * Utility functions
 */

/* Implements a ping service */
static boolean_t
ping_message_rxhandler(wrsm_network_t *net, wrsm_message_t *msg)
{
	wrsm_raw_message_t raw_resp;
	wrsm_message_t *resp = (wrsm_message_t *)&raw_resp;

	ASSERT(msg->header.message_type == WRSM_MSG_PING);
	DPRINTF(TLDBG, (CE_NOTE, "Cnode %d is being pinged by %d",
		net->cnodeid,
		msg->header.source_cnode));
	resp->header.message_type = WRSM_MSG_PING_RESPONSE;
	(void) wrsm_tl_rsp(net, msg, resp);

	return (B_TRUE);
}

#ifdef DEBUG
/* Debug function to print pending RPC list info */
static void
list_print(wrsm_transport_t *tl)
{
	pending_rpc_t *p;

	ASSERT(mutex_owned(&tl->mutex));

	for (p = tl->rpc_list; p; p = p->next) {
		DPRINTF(TLWARN, (CE_NOTE, "addr=%p, id=0x%08X, next=%p, "
		    "prev=%p", (void *)p, p->message_id, (void *)p->next,
		    (void *)p->prev));
	}
}
#endif /* DEBUG */

/* Adds a pending_rpc entry to the linked list */
static int
add_to_list(wrsm_transport_t *tl, pending_rpc_t *entry)
{
	int retval;

	mutex_enter(&tl->mutex);

	/* Check to see if pending rpc is above highwater mark */
	while (tl->rpc_count >= wrsm_tl_rpc_highwater) {
		retval = cv_wait_sig(&tl->rpc_cv, &tl->mutex);
		/* retval of 0 indicates a signal was received */
		if (retval <= 0 && tl->rpc_count >= wrsm_tl_rpc_highwater) {
			mutex_exit(&tl->mutex);
			return (EAGAIN);
		}
	}
	/* We got in! */
	tl->rpc_count++;

	/* Point to who used to be first */
	entry->next = tl->rpc_list;
	/* If someone else used to be first on list... */
	if (entry->next) {
		/* Make them point back at me */
		entry->next->prev = entry;
	}
	/* Change list to point to me */
	tl->rpc_list = entry;
	mutex_exit(&tl->mutex);
	return (0);
}

/* Removes a pending_rpc entry to the linked list */
static void
remove_from_list(wrsm_transport_t *tl, pending_rpc_t *entry)
{
	mutex_enter(&tl->mutex);
	/*
	 * If there's a previous node, make them point to our next
	 * node. If not, we  were first, so update head pointer.
	 */
	if (entry->prev) {
		(entry->prev)->next = entry->next;
	} else {
		tl->rpc_list = entry->next;
	}
	/*
	 * If there's a next node, have them point
	 * back to whomever we pointed back to.
	 */
	if (entry->next) {
		(entry->next)->prev = entry->prev;
	}
	/* If rpc count is falling below lowwater, wake up waiting threads */
	if (tl->rpc_count == wrsm_tl_rpc_lowwater) {
		cv_broadcast(&tl->rpc_cv);
	}
	tl->rpc_count--;
	mutex_exit(&tl->mutex);
}

/* Constructs and initializes a wrsm_transport structure */
static wrsm_transport_t *
alloc_state(void)
{
	int i;
	wrsm_transport_t *tl =
		kmem_zalloc(sizeof (wrsm_transport_t), KM_SLEEP);

	ASSERT(tl);
	mutex_init(&tl->mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&tl->event_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&tl->taskq_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tl->event_cv, NULL, CV_DRIVER, NULL);
	cv_init(&tl->event_exit_cv, NULL, CV_DRIVER, NULL);
	cv_init(&tl->rpc_cv, NULL, CV_DRIVER, NULL);
	for (i = 0; i < WRSM_MSG_TYPES_MAX; i++) {
		tl->tx_handlers[i] = NULL;
		tl->rx_handlers[i] = NULL;
	}
	tl->last_message_id = 0;
	tl->rpc_list = NULL;
	tl->rpc_count = 0;

	return (tl);
}

/* Cleans-up and destroys a wrsm_transport structure */
static void
free_state(wrsm_transport_t *tl)
{
	while (tl->rpc_list) {
		remove_from_list(tl, tl->rpc_list);
	}
	mutex_destroy(&tl->mutex);
	mutex_destroy(&tl->event_mutex);
	mutex_destroy(&tl->taskq_mutex);
	cv_destroy(&tl->event_cv);
	cv_destroy(&tl->event_exit_cv);
	cv_destroy(&tl->rpc_cv);
	kmem_free(tl, sizeof (wrsm_transport_t));
}

/* Handles incoming messages */
/* ARGSUSED */
static rsm_intr_hand_ret_t
intr_handler(
	rsm_controller_object_t *controller,
	rsm_intr_q_op_t operation,
	rsm_addr_t sender,
	void *data,
	size_t size,
	rsm_intr_hand_arg_t arg)
{
	wrsm_network_t *net = (wrsm_network_t *)arg;
	wrsm_message_t *msg = (wrsm_message_t *)data;
	wrsm_transport_t *tl = net->transport;
	wrsm_message_rxhandler_t handler;
	tl_event_t *event;
	boolean_t handler_retval = B_TRUE;
	cnodeid_t from_cnode = (cnodeid_t)sender;

	NOTE("wrsm_tl::intr_handler");
#ifdef DEBUG
	if (TLDUMP & tl_debug) {
		WRSM_TL_DUMP_MESSAGE("tl intr_handler:", msg);
	}
#endif /* DEBUG */

	if (msg->header.version != WRSM_TL_VERSION) {
		cmn_err(CE_WARN, "Remote driver version mismatch: "
		    "local version %u, remote version %u",
		    WRSM_TL_VERSION, msg->header.version);
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}
	/*
	 * Verify that the msg->source_cnode matches where the
	 * interrupt came from.
	 */
	if (msg->header.source_cnode != from_cnode) {
		DPRINTF(TLERR, (CE_WARN,
		    "msg->header.source_cnode %d != from_cnode %d",
		    msg->header.source_cnode, from_cnode));
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}

	if (tl->cnode[from_cnode].addr == NULL) {
		DPRINTF(TLERR, (CE_WARN,
		    "sender %d is not reachable; dropping message",
		    from_cnode));
		return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
	}

	if (tl->rx_handlers[msg->header.message_type]) {
		/*
		 * All messages with an identifier in the _SESSION_ or _RECVQ_
		 * range could possibly either block, or take locks from other
		 * threads that could block.  Therefore, handle them on the
		 * event thread.
		 */
		if (ISDATAGRAMID(msg->header.message_id) &&
			((msg->header.message_type >=
				WRSM_MSG_SESSION_START &&
			    msg->header.message_type <=
				WRSM_MSG_SESSION_END) ||
			(msg->header.message_type >=
				WRSM_MSG_INTR_RECVQ_CREATE &&
			    msg->header.message_type <=
				WRSM_MSG_INTR_RECVQ_DESTROY))) {
			event = kmem_alloc(sizeof (tl_event_t),
					KM_NOSLEEP);
			event->net = net;
			event->handler =
				tl->rx_handlers[msg->header.message_type];
			msgcpy(&event->msg, msg);
			event->next = (tl_event_t *)NULL;

			tl_add_event(tl, event);

		} else {
			handler = tl->rx_handlers[msg->header.message_type];
			handler_retval = (*handler)(net, msg);
		}
	}

	if (ISRESPONSEID(msg->header.message_id) && handler_retval) {
		/*
		 * This is an RPC response and handler was successful
		 */
		wrsm_messageid_t orig_id = MAKEORIGID(msg->header.message_id);
		pending_rpc_t *p;
		mutex_enter(&tl->mutex);
		/* Walk the linked list, looking for matching message id */
		for (p = tl->rpc_list; p; p = p->next) {
			if (p->message_id == orig_id) {
				mutex_enter(&p->mutex);

				/* Clear message id, so we don't reenter. */
				p->message_id = MESSAGE_ID_INVALID;

				/* Copy response to holding area */
				msgcpy(p->response, msg);

				/* Set flag indicating response was received */
				p->resp_recvd = B_TRUE;

				/* Wake up the waiting thread */
				cv_signal(&p->cv);

				mutex_exit(&p->mutex);

				break;
			}
		}
		if (!p) {
			DPRINTF(TLERR, (CE_WARN, "intr_handler: "
				"rpc resp but no one waiting: 0x%08X 0x%08X",
				msg->header.message_id, orig_id));
#ifdef DEBUG
			list_print(tl);
			WRSM_TL_DUMP_MESSAGE("intr_handler:", msg);
#endif
		}
		mutex_exit(&tl->mutex);
	/* LINTED: E_NOP_IF_STMT */
	} else if (ISDATAGRAMID(msg->header.message_id) && (handler == NULL)) {
		/*
		 * This is a datagram and we don't have a handler
		 */
		DPRINTF(TLERR, (CE_WARN, "intr_handler: "
			"no handler for message_type %u",
			msg->header.message_type));
	}
	return (RSM_INTR_HAND_CLAIMED_EXCLUSIVE);
}

/* Formats and sends a message, used by dg, rpc and resp */
static int
send_message(wrsm_network_t *net,
		cnodeid_t destination,
		wrsm_message_t *msg,
		wrsm_messageid_t msg_id)
{
	wrsm_message_txhandler_t h;
	wrsm_transport_t *tl;
	caddr_t node_addr;
	caddr_t rem_addr;
	int retry;
	const int max_retries = 8; /* At most, retry on each wci/link */
	int retval;
	boolean_t handler_rc;

	ASSERT(net);
	ASSERT(net->transport);
	tl = net->transport;

	/* Validate the message. */
	ASSERT(msg);

	mutex_enter(&tl->mutex);
	/* Validate that we know how to get to destination */
	node_addr = tl->cnode[destination].addr;
	if (node_addr == NULL) {
		DPRINTF(TLERR, (CE_WARN, "send_message: unknown dest %d",
		    destination));
		mutex_exit(&tl->mutex);
		return (EPIPE);
	}
	if (tl->cnode[destination].reachable == B_FALSE) {
		DPRINTF(TLERR, (CE_WARN, "send_message: dest %d unreachable",
		    destination));
		mutex_exit(&tl->mutex);
		return (EPIPE);
	}
	mutex_exit(&tl->mutex);
	msg->header.reserved1 = 0;
	msg->header.reserved2 = 0;
	msg->header.message_id = msg_id;
	msg->header.version = WRSM_TL_VERSION;
	msg->header.session_id = 0;
	msg->header.source_cnode = net->cnodeid;

	/* Call send function handler before sending message. */
	h = tl->tx_handlers[msg->header.message_type];
	if (h) {
		handler_rc = (*h)(net, destination, msg);
		if (handler_rc == B_FALSE) {
			DPRINTF(TLERR, (CE_WARN, "send_message: tx_handler "
			    "failed rc=%d handler=%p", handler_rc, (void *)h));
			return (EAGAIN);
		}
	}

	for (retry = 0; retry < max_retries; retry++) {

		/* Calculate remote address, taking into account striping */
		rem_addr = node_addr + tl->cnode[destination].offset;

		/*
		 * Advance the offset by the link stripe stride, so we tend to
		 * distribute interrupts across link and WCI stripes, but make
		 * sure not to exceed the page size!
		 *
		 * Note that this should be atomic, but the worst thing that
		 * can happen is we send two interrupts in a row on the same
		 * link which is probably less of a performance impact than
		 * grabbing a mutex for every single interrupt.
		 */
		tl->cnode[destination].offset =
			(tl->cnode[destination].offset +
			WCI_CLUSTER_STRIPE_STRIDE) & WCI_CLUSTER_STRIPE_MASK;

		/* Send the message */
#ifdef DEBUG
		if (TLDUMP & tl_debug) {
			WRSM_TL_DUMP_MESSAGE("wrsm_intr_send:", msg);
		}
#endif /* DEBUG */
		retval = wrsm_intr_send(net, rem_addr, destination, msg, 0,
		    WRSM_INTR_WAIT_DEFAULT, 0);

		/* Stop retrying on success */
		if (retval == 0) {
			break;
		}
	}
	return (retval);
}

/* Atomically allocates a unique message id */
static wrsm_messageid_t
allocate_message_id(wrsm_transport_t *tl)
{
	wrsm_messageid_t msg_id;

	mutex_enter(&tl->mutex);
	tl->last_message_id++;
	if (tl->last_message_id > MESSAGE_ID_MAX) {
		tl->last_message_id = MESSAGE_ID_FIRST;
	}
	msg_id = tl->last_message_id;
	mutex_exit(&tl->mutex);

	return (msg_id);
}

/*
 * Transport API functions
 */
int
wrsm_tl_init(wrsm_network_t *net)
{
	int retval;
	wrsm_transport_t *tl;
	ASSERT(net);

	/* First, initialize interrupt component */
	retval = wrsm_intr_init(net);
	if (retval) {
		return (retval);
	}
	wrsm_intr_print(net);

	/* Allocate structure to store transport state */
	tl = alloc_state();
	ASSERT(tl);

	/* Spin up the event thread for this transport */
	tl->stop_events = B_FALSE;
	tl->events = (tl_event_t *)NULL;
	tl->event_thread = thread_create(NULL, 0, tl_event_thread,
	    (void *)tl, 0, &p0, TS_RUN, maxclsyspri);

	/*
	 * Allocate all the taskq's for MSG_SEGMENT handlers. You need to
	 * allocate one for each message type we handle in this way in order
	 * to guarantee that one message type blocking doesn't interfere with
	 * any other message types.
	 *
	 * The gloabl variable wrsm_tl_tqthreads controls the number of
	 * threads servicing -each- taskq.
	 */
	tl->stop_taskqs = B_FALSE;
	tl->connect_taskq = taskq_create("wrsm_connect_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);
	tl->smallputmap_taskq = taskq_create("wrsm_smallputmap_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);
	tl->barriermap_taskq = taskq_create("wrsm_barriermap_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);
	tl->segmap_taskq = taskq_create("wrsm_segmap_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);
	tl->disconnect_taskq = taskq_create("wrsm_disconnect_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);
	tl->unpublish_taskq = taskq_create("wrsm_unpublish_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);
	tl->access_taskq = taskq_create("wrsm_access_taskq",
			wrsm_tl_tqthreads, maxclsyspri, 1, 8,
			TASKQ_PREPOPULATE);

	/* Hook structure into network */
	net->transport = tl;

	/* Register with the interrupt component for driver messages */
	(void) wrsm_register_handler(net, NULL, WRSM_TL_INTR_TYPE,
	    intr_handler, (rsm_intr_hand_arg_t)net, NULL, 0);

	/* Register ping message handler with ourselves */
	(void) wrsm_tl_add_handler(net, WRSM_MSG_PING,
	    WRSM_TL_NO_HANDLER, ping_message_rxhandler);

	wrsm_sess_init(net);
	wrsm_intr_rsminit(net);

	return (0);
}

void
wrsm_tl_fini(wrsm_network_t *net)
{
	wrsm_transport_t *tl = (wrsm_transport_t *)net->transport;

	/* First, validate pointers */
	ASSERT(net);
	ASSERT(net->transport);

	wrsm_intr_rsmfini(net);

	/* Unregister from interrupt component */
	(void) wrsm_unregister_handler(net, WRSM_TL_INTR_TYPE,
	    intr_handler, (rsm_intr_hand_arg_t)net);

	/* stop the taskq's and wait for them to drain */
	mutex_enter(&tl->taskq_mutex);
	tl->stop_taskqs = B_TRUE;

	taskq_destroy(tl->connect_taskq);
	taskq_destroy(tl->smallputmap_taskq);
	taskq_destroy(tl->barriermap_taskq);
	taskq_destroy(tl->segmap_taskq);
	taskq_destroy(tl->disconnect_taskq);
	taskq_destroy(tl->unpublish_taskq);
	taskq_destroy(tl->access_taskq);
	mutex_exit(&tl->taskq_mutex);

	/* Stop and exit the event thread */
	mutex_enter(&tl->event_mutex);
	tl->stop_events = B_TRUE;
	cv_broadcast(&tl->event_cv);
	cv_wait(&tl->event_exit_cv, &tl->event_mutex);
	mutex_exit(&tl->event_mutex);

	wrsm_sess_fini(net);
	free_state(net->transport);
	net->transport = NULL;

	/* Last, fini interrupt component */
	wrsm_intr_fini(net);
}

int
wrsm_tl_newcnode(wrsm_network_t *net, cnodeid_t cnodeid)
{
	int retval = RSM_SUCCESS;
	wrsm_transport_t *tl;

	DPRINTF(TLDBG, (CE_NOTE, "wrsm_tl_newcnode: %d", cnodeid));
	ASSERT(net);
	tl = net->transport;
	ASSERT(tl);

	mutex_enter(&tl->mutex);

	retval = wrsm_cmmu_comm_alloc(net,
	    (uint_t)net->nodes[net->cnodeid]->config->comm_ncslice,
	    (wrsm_cmmu_offset_t)net->nodes[cnodeid]->config->local_offset,
	    &(tl->cnode[cnodeid].tuple));
	if (retval) {
		mutex_exit(&tl->mutex);
		return (retval);
	}

	DPRINTF(TLDBG, (CE_NOTE, "wrsm_tl_newcnode: cnode %d got cmmu %d",
	    cnodeid, tl->cnode[cnodeid].tuple.index));

	retval = wrsm_intr_create_recvq(net,
	    WRSM_TL_INTR_TYPE,
	    WRSM_TL_PACKETRING_SIZE,
	    tl->cnode[cnodeid].tuple.index,
	    &(tl->cnode[cnodeid].recvq),
	    cnodeid,
	    NULL,
	    WRSM_CREATE_RECVQ_NOFLAGS);
	if (retval) {
		wrsm_cmmu_comm_free(net, &tl->cnode[cnodeid].tuple);
		mutex_exit(&tl->mutex);
		return (retval);
	}

	mutex_exit(&tl->mutex);

	return (RSM_SUCCESS);
}

int
wrsm_tl_removecnode(wrsm_network_t *net, cnodeid_t cnodeid)
{
	int rc = RSM_SUCCESS;
	wrsm_transport_t *tl;

	DPRINTF(TLDBG, (CE_NOTE, "wrsm_tl_removecnode: %d", cnodeid));
	ASSERT(net);
	tl = net->transport;
	ASSERT(tl);

	mutex_enter(&tl->mutex);

	if (tl->cnode[cnodeid].reachable) {
		wrsm_tl_unreachable(net, cnodeid);
	}

	if (tl->cnode[cnodeid].recvq == NULL) {
		DPRINTF(TLDBG, (CE_CONT, "wrsm_tl_removecnode: %d "
		"no recvq - tl_newcnode never called\n", cnodeid));
		mutex_exit(&tl->mutex);
		return (ENOENT);
	}

	/* Unmap remote address if it had been mapped */
	if (tl->cnode[cnodeid].addr) {
		ddi_unmap_regs(wrsm_ncslice_dip,
		    (uint_t)net->nodes[cnodeid]->config->comm_ncslice,
		    &(tl->cnode[cnodeid].addr),
		    (off_t)net->nodes[cnodeid]->config->comm_offset,
		    PAGESIZE);
		tl->cnode[cnodeid].addr = NULL;
	}

	wrsm_intr_destroy_recvq(net, tl->cnode[cnodeid].recvq);
	tl->cnode[cnodeid].recvq = NULL;

	wrsm_cmmu_comm_free(net, &(tl->cnode[cnodeid].tuple));

	mutex_exit(&tl->mutex);

	return (rc);
}

void
wrsm_tl_reachable(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_transport_t *tl;
	int retval;

	DPRINTF(TLDBG, (CE_NOTE, "wrsm_tl_reachable: %d", cnodeid));
	ASSERT(net);
	tl = net->transport;
	ASSERT(tl);

	mutex_enter(&tl->mutex);
	if (tl->cnode[cnodeid].addr == NULL) {
		/* We've never been able to reach this node before... */
		retval = ddi_map_regs(wrsm_ncslice_dip,
		    (uint_t)net->nodes[cnodeid]->config->comm_ncslice,
		    &(tl->cnode[cnodeid].addr),
		    (off_t)net->nodes[cnodeid]->config->comm_offset,
		    PAGESIZE);

		if (retval != DDI_SUCCESS) {
			cmn_err(CE_WARN, "ddi_map_regs returned error: %d",
			    retval);
		}
	}
	tl->cnode[cnodeid].reachable = B_TRUE;
	mutex_exit(&tl->mutex);

#ifdef DEBUG
	if (tl_debug & TLDBG) {
		uint64_t kpf; /* Kernel Page Frame */
		uint64_t pa;  /* Physical address */
		uint_t ncslice;

		kpf = hat_getpfnum(kas.a_hat, tl->cnode[cnodeid].addr);
		pa = (kpf << 13);
		ncslice = (uint_t)((pa >> 34) & 0xff);

		DPRINTF(TLDBG, (CE_WARN,
		    "ncslice %u off 0x%p mapped to va=0x%p, pa=0x%p, nc=%u",
		    (uint_t)net->nodes[cnodeid]->config->comm_ncslice,
		    (void *)net->nodes[cnodeid]->config->comm_offset,
		    (void *)tl->cnode[cnodeid].addr,
		    (void *)pa,
		    ncslice));
	}
#endif /* DEBUG */
	wrsm_sess_reachable(net, cnodeid);
}

void
wrsm_tl_unreachable(wrsm_network_t *net, cnodeid_t cnodeid)
{
	wrsm_transport_t *tl;

	DPRINTF(TLDBG, (CE_NOTE, "wrsm_tl_unreachable: %d", cnodeid));
	ASSERT(net);
	tl = net->transport;
	ASSERT(tl);

	tl->cnode[cnodeid].reachable = B_FALSE;
	if (tl->cnode[cnodeid].addr == NULL) {
		/* Node was never reachable */
		return;
	}
	wrsm_sess_unreachable(net, cnodeid);
}

int
wrsm_tl_add_handler(wrsm_network_t *net,
		    wrsm_message_type_t msg_type,
		    wrsm_message_txhandler_t send_fn,
		    wrsm_message_rxhandler_t rcv_fn)
{
	int rc = RSM_SUCCESS;
	wrsm_transport_t *tl = net->transport;

	mutex_enter(&tl->mutex);

	if (rcv_fn && tl->rx_handlers[msg_type]) {
		DPRINTF(TLERR, (CE_WARN, "wrsm_tl_add_handler: "
			"receive handler already exists for msg type %u",
			msg_type));
		rc = EEXIST;
	}

	if (send_fn && tl->tx_handlers[msg_type]) {
		DPRINTF(TLERR, (CE_WARN, "wrsm_tl_add_handler: "
			"send handler already exists for msg type %u",
			msg_type));
		rc = EEXIST;
	}

	if (!rc) {
		tl->rx_handlers[msg_type] = rcv_fn;
		tl->tx_handlers[msg_type] = send_fn;
	}
	mutex_exit(&tl->mutex);

	return (rc);
}

int
wrsm_tl_dg(wrsm_network_t *net,
		cnodeid_t destination,
		wrsm_message_t *msg)
{
	int rc;
	ASSERT(net);
	ASSERT(net->transport);

	rc = send_message(net, destination, msg,
			allocate_message_id(net->transport));
	return (rc);
}

int
wrsm_tl_rpc(wrsm_network_t *net,
	    cnodeid_t destination,
	    wrsm_message_t *msg,
	    wrsm_message_t *resp)
{
	int rc = RSM_SUCCESS;
	clock_t timeout_ticks;
	wrsm_messageid_t message_id;
	pending_rpc_t me;
	wrsm_transport_t *tl = net->transport;

	/* Allocate ourselves a message id now, before it's too late */
	message_id = allocate_message_id(tl);

	/* Create and initialize a pending rpc item in linked list */
	/* Don't need to use mutex, cause we're still not listed */

	me.message_id = message_id;
	me.next = NULL;
	me.prev = NULL;
	me.response = resp;
	me.resp_recvd = B_FALSE;
	cv_init(&me.cv, NULL, CV_DRIVER, NULL);
	mutex_init(&me.mutex, NULL, MUTEX_DRIVER, NULL);

	/* Add me to the front of the waiting rpc list */
	if (add_to_list(tl, &me) != 0) {
		/* Failed to add to list, return error */
		mutex_destroy(&me.mutex);
		wrsm_sess_teardown(net, destination);
		return (EAGAIN);
	}

	/* Grab our mutex -- response could come before we get to wait */
	mutex_enter(&me.mutex);

	/* Send the message */
	rc = send_message(net, destination, msg, message_id);

	if (rc == RSM_SUCCESS) {
		/* Wait for rpc response */
		timeout_ticks = ddi_get_lbolt() +
				drv_usectohz(wrsm_tl_rpc_timeout);
		/*
		 * If cv_timedwait returns -1, condition was "not necessarily"
		 * signaled. To see if response was actually received, we
		 * really need to check resp_recvd flag.
		 */
		(void) cv_timedwait(&me.cv, &me.mutex, timeout_ticks);
		if (!me.resp_recvd) {
			DPRINTF(TLWARN, (CE_WARN, "rpc: timed out waiting for "
			    "response, msg id = 0x%08X", me.message_id));
			rc = ETIME;
		}
	/* LINTED: E_NOP_ELSE_STMT */
	} else {
		DPRINTF(TLWARN, (CE_WARN, "send_message failed: %d", rc));
	}

	me.message_id = MESSAGE_ID_INVALID;

	if (rc != RSM_SUCCESS) {
		wrsm_sess_teardown(net, destination);
	}

	mutex_exit(&me.mutex);

#ifdef DEBUG
	/*
	 * can't take tl->mutex while holding me.mutex, so do debug stuff here
	 */
	if (!me.resp_recvd) {
		mutex_enter(&tl->mutex);
		list_print(tl);
		mutex_exit(&tl->mutex);
	}
#endif
	remove_from_list(tl, &me);
	mutex_destroy(&me.mutex);

	return (rc);
}

int
wrsm_tl_rsp(wrsm_network_t *net,
		wrsm_message_t *orig,
		wrsm_message_t *resp)
{
	wrsm_messageid_t resp_id = MAKERESPID(orig->header.message_id);
	int rc = send_message(net, orig->header.source_cnode,
				resp, resp_id);
	return (rc);
}

boolean_t
wrsm_tl_txhandler_sessionid(wrsm_network_t *net, cnodeid_t cnodeid,
				wrsm_message_t *msg)
{
	if (ISRESPONSEID(msg->header.message_id)) {
		/*
		 * If this message is a response, don't try to establish
		 * a new session, just get the current session id or
		 * SESS_ID_INVALID if the session has ended.
		 */
		msg->header.session_id = wrsm_sess_get(net, cnodeid);
	} else {
		/*
		 * If this message is not a response, try to establish
		 * a new session if one doesn't already exist.
		 */
		msg->header.session_id = wrsm_sess_establish(net, cnodeid);
	}
	return (msg->header.session_id != SESS_ID_INVALID);
}

boolean_t
wrsm_tl_rxhandler_sessionid(wrsm_network_t *net, wrsm_message_t *msg)
{
	wrsm_sessionid_t session_id;

	session_id = wrsm_sess_get(net, msg->header.source_cnode);

	return ((session_id != SESS_ID_INVALID) &&
			(msg->header.session_id == session_id));
}

/*
 * Generic memseg message handler for the following message types:
 * CONNECT SMALLPUTMAP BARRIERMAP SEGMAP DISCONNECT UNPUBLISH ACCESS
 *
 * Note: This must reside in wrsm_tl.c because it needs to know about
 * the innards of the wrsm_transport structure.
 */
boolean_t
wrsm_memseg_msg_hdlr(wrsm_network_t *network, wrsm_message_t *msg)
{
	wrsm_node_t *node = network->nodes[msg->header.source_cnode];
	wrsm_transport_t *tl = network->transport;
	wrsm_memseg_evt_args_t *args;

	if (node == NULL) {
		/* non-existent node */
		return (B_FALSE);
	}

	/* Verify that this is a message type we support */
	ASSERT(msg->header.message_type >= WRSM_MSG_SEGMENT_CONNECT);
	ASSERT(msg->header.message_type <= WRSM_MSG_SEGMENT_ACCESS);

	if (wrsm_tl_rxhandler_sessionid(network, msg) == B_FALSE) {
		/* session must not be valid */
		return (B_FALSE);
	}

	/*
	 * Allocate the args structure, to be passed to the event handlers.
	 * NEEDS TO BE DEALLOCATED IN THE HANDLERS!
	 */
	args = kmem_alloc(sizeof (wrsm_memseg_evt_args_t), KM_SLEEP);
	args->network = network;
	msgcpy(&args->msg, msg);

	/* grab the taskq's lock so they don't disappear out from under us */
	mutex_enter(&tl->taskq_mutex);

	if (tl->stop_taskqs) {
		mutex_exit(&tl->taskq_mutex);
		return (B_FALSE);
	}

	switch (msg->header.message_type) {

		/* export segment events */
		case WRSM_MSG_SEGMENT_CONNECT:
			taskq_dispatch(tl->connect_taskq,
					wrsm_connect_msg_evt,
					(void *)args, TQ_SLEEP);
			break;
		case WRSM_MSG_SEGMENT_SMALLPUTMAP:
			taskq_dispatch(tl->smallputmap_taskq,
					wrsm_smallputmap_msg_evt,
					(void *)args, TQ_SLEEP);
			break;
		case WRSM_MSG_SEGMENT_BARRIERMAP:
			taskq_dispatch(tl->barriermap_taskq,
					wrsm_barriermap_msg_evt,
					(void *)args, TQ_SLEEP);
			break;
		case WRSM_MSG_SEGMENT_SEGMAP:
			taskq_dispatch(tl->segmap_taskq,
					wrsm_segmap_msg_evt,
					(void *)args, TQ_SLEEP);
			break;
		case WRSM_MSG_SEGMENT_DISCONNECT:
			taskq_dispatch(tl->disconnect_taskq,
					wrsm_disconnect_msg_evt,
					(void *)args, TQ_SLEEP);
			break;

		/* import segment events */
		case WRSM_MSG_SEGMENT_UNPUBLISH:
			taskq_dispatch(tl->unpublish_taskq,
					wrsm_unpublish_msg_evt,
					(void *)args, TQ_SLEEP);
			break;
		case WRSM_MSG_SEGMENT_ACCESS:
			taskq_dispatch(tl->access_taskq,
					wrsm_access_msg_evt,
					(void *)args, TQ_SLEEP);
			break;
	}

	mutex_exit(&tl->taskq_mutex);

	return (B_TRUE);
}


#ifdef DEBUG
static char *
messagetype2string(wrsm_message_type_t type)
{
	switch (type) {
	case WRSM_MSG_ACK:
		return ("ACK");
	case WRSM_MSG_NACK:
		return ("NACK");
	case WRSM_MSG_PING:
		return ("PING");
	case WRSM_MSG_PING_RESPONSE:
		return ("PING_RESPONSE");
	case WRSM_MSG_CONFIG_COOKIE:
		return ("CONFIG_COOKIE");
	case WRSM_MSG_CONFIG_PASSTHROUGH_LIST:
		return ("CONFIG_PASSTHROUGH_LIST");
	case WRSM_MSG_CONFIG_PASSTHROUGH_LIST_RESPONSE:
		return ("CONFIG_PASSTHROUGH_LIST_RESPONSE");
	case WRSM_MSG_CONFIG_CNODE_ACCESS:
		return ("CONFIG_CNODE_ACCESS");
	case WRSM_MSG_SESSION_START:
		return ("SESSION_START");
	case WRSM_MSG_SESSION_START_RESPONSE:
		return ("SESSION_START_RESPONSE");
	case WRSM_MSG_SESSION_END:
		return ("SESSION_END");
	case WRSM_MSG_SEGMENT_CONNECT:
		return ("SEGMENT_CONNECT");
	case WRSM_MSG_SEGMENT_CONNECT_RESPONSE:
		return ("SEGMENT_CONNECT_RESPONSE");
	case WRSM_MSG_SEGMENT_SMALLPUTMAP:
		return ("SEGMENT_SMALLPUTMAP");
	case WRSM_MSG_SEGMENT_SMALLPUTMAP_RESPONSE:
		return ("SEGMENT_SMALLPUTMAP_RESPONSE");
	case WRSM_MSG_SEGMENT_BARRIERMAP:
		return ("SEGMENT_BARRIERMAP");
	case WRSM_MSG_SEGMENT_BARRIERMAP_RESPONSE:
		return ("SEGMENT_BARRIERMAP_RESPONSE");
	case WRSM_MSG_SEGMENT_SEGMAP:
		return ("SEGMENT_SEGMAP");
	case WRSM_MSG_SEGMENT_SEGMAP_RESPONSE:
		return ("SEGMENT_SEGMAP_RESPONSE");
	case WRSM_MSG_SEGMENT_DISCONNECT:
		return ("SEGMENT_DISCONNECT");
	case WRSM_MSG_SEGMENT_UNPUBLISH:
		return ("SEGMENT_UNPUBLISH");
	case WRSM_MSG_SEGMENT_UNPUBLISH_RESPONSE:
		return ("SEGMENT_UNPUBLISH_RESPONSE");
	case WRSM_MSG_SEGMENT_ACCESS:
		return ("SEGMENT_ACCESS");
	case WRSM_MSG_SEGMENT_ACCESS_RESPONSE:
		return ("SEGMENT_ACCESS_RESPONSE");
	case WRSM_MSG_INTR_RECVQ_CREATE:
		return ("INTR_RECVQ_CREATE");
	case WRSM_MSG_INTR_RECVQ_CREATE_RESPONSE:
		return ("INTR_RECVQ_CREATE_RESPONSE");
	case WRSM_MSG_INTR_RECVQ_DESTROY:
		return ("INTR_RECVQ_DESTROY");
	default:
		return ("Unknown");
	}
}

void
wrsm_tl_dump_message(char *txt, wrsm_message_t *msg)
{
	unsigned i;

	cmn_err(CE_CONT, "%s", txt);
	cmn_err(CE_CONT, "---- Message ----\n");
	cmn_err(CE_CONT, "Reserved1:    0x%08X\n", msg->header.reserved1);
	cmn_err(CE_CONT, "Message Id:   0x%08X\n", msg->header.message_id);
	cmn_err(CE_CONT, "Version:      %u\n", msg->header.version);
	cmn_err(CE_CONT, "Session:      %u\n", msg->header.session_id);
	cmn_err(CE_CONT, "Source cnode: %u\n", msg->header.source_cnode);
	cmn_err(CE_CONT, "Message type: %s (%u)\n",
	    messagetype2string(msg->header.message_type),
	    msg->header.message_type);
	cmn_err(CE_CONT, "Reserved2:    0x%08X\n", msg->header.reserved2);
	cmn_err(CE_CONT, "Body:\n");
	for (i = 0; i < WRSM_MESSAGE_BODY_SIZE; i += 8) {
		cmn_err(CE_CONT, "              "
			"%02X %02X %02X %02X %02X %02X %02X %02X\n",
			msg->body[i+0],
			msg->body[i+1],
			msg->body[i+2],
			msg->body[i+3],
			msg->body[i+4],
			msg->body[i+5],
			msg->body[i+6],
			msg->body[i+7]);
	}

	cmn_err(CE_CONT, "-----------------\n");
}
#endif /* DEBUG */
