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
 * This file implements the RSMPI sendq functions in the Wildcat RSM
 * driver.  In addition, the driver uses Wildcat interrupts to communicate;
 * this file also implements the driver internal interrupt generation and
 * receiving functions.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/processor.h>
#include <sys/dmv.h>
#include <sys/cpuvar.h>
#include <sys/param.h>
#include <sys/sysconf.h>
#include <sys/machsystm.h>
#include <sys/errno.h>
#include <sys/ivintr.h>
#include <sys/promif.h>
#include <sys/cpu_module.h>
#include <sys/atomic.h> /* For cas atomics */

#include <sys/wrsm_intr.h>
#include <sys/wrsm_intr_impl.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_plat.h>
#include <sys/sysmacros.h>
#include <sys/wrsm_nc.h>
#include <sys/wrsm_lc.h>
#include <sys/wci_regs.h>
#include <sys/wci_common.h>
#include <sys/wrsm_session.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_memseg_impl.h>

#ifdef DEBUG
extern char platform[];

static wrsm_network_t *networks[WRSM_MAX_CNODES] = {0};
#endif /* DEBUG */

/*
 * Manifest Constants and Macros
 */
#define	WRSM_INTR_MAX_DRAINERS	8
#define	WRSM_INTR_MAX_TARGETS	8

#define	RECVQ_HIGHWATER_MARGIN	10

#define	BIT31SET	(((uint_t)1) << 31)
#define	MAKE_INTR_DIST_MONDO(safari_id, index) \
	(int)(BIT31SET | ((safari_id) << 16) | (index))
#define	NULL_INTR_DIST_MONDO 0 /* Valid mondo has bit 31 set */
#define	CPUID_TO_DESTNODE(cpu)	((cpu >> 5) & 0xf)
#define	CPUID_TO_DESTDEV(cpu)	(cpu & 0x1f)

#define	INVALID_SAFARI_ID	-1

#define	INFINITY	LONG_MAX

extern kmutex_t intr_dist_lock;
extern int servicing_interrupt(void);

/*
 * The following macros define a DPRINTF macro which can be used to enable
 * or disable various levels of logging for this module.
 */
#ifdef DEBUG

#define	INTRDBG		0x1
#define	INTRWARN	0x2
#define	INTRERR		0x4
#define	INTRTRACE	0x8
#define	INTRCESR	0x10
static uint_t wrsm_intr_debug = INTRERR;

#define	DPRINTF(a, b) { if (wrsm_intr_debug & a) wrsmdprintf b; }

#else /* DEBUG */

#define	DPRINTF(a, b)

#endif /* DEBUG */

#define	DTRC(s) DPRINTF(INTRTRACE, (CE_CONT, s))
#define	WARN(s) DPRINTF(INTRWARN, (CE_WARN, s))
#define	NOTE(s) DPRINTF(INTRDBG, (CE_CONT, s))

/*
 * The recvq_table entries can contain recvq pointers, or when not in use,
 * contain an overlaid free list. As a result, you can't just compare
 * the recvq pointer to NULL, since it may in fact be a free list index.
 * To differentiate, we purposely set the LSB of the entry while it's
 * free (and store the free list info in the upper bits).
 * Macro MONDO2RECVQ does the shifting/oring to put a free list mondo
 * in the aforementioned format.
 * Macro RECVQ2MONDO extracts the mondo value from the aforementioned format.
 * Macro RECVQ_VALID tests to see if the item is indeed a valid recvq pointer.
 */
#define	CAST_MONDO2RECVQ(mondo)	(wrsm_intr_recvq_t *)(((mondo) << 16) | 0x1)
#define	CAST_RECVQ2MONDO(recvq)	(((uint_t)(recvq)) >> 16)
#define	RECVQ_VALID(recvq)	((recvq) && (((uint64_t)(recvq)) & 0x1) == 0)

/*
 * Message Structures
 */

/* Format of message for WRSM_MSG_INTR_RECVQ_CREATE request */
typedef struct recvq_create_req {
	wrsm_message_header_t header;
	rsm_intr_t service;
	rsm_intr_pri_t prio;
	size_t qdepth;
} recvq_create_req_t;

/* Format of message for WRSM_MSG_INTR_RECVQ_CREATE_RESPONSE */
typedef struct recvq_create_rsp {
	wrsm_message_header_t header;
	int retval;	/* RSM_SUCCESS or errno */
	off_t nc_off;	/* Offset into comm ncslice page */
	uint64_t qid;	/* ID of remote recvq */
	uint_t mondo;	/* CMMU mondo of remote recvq */
} recvq_create_rsp_t;

/* Format of message for WRSM_MSG_INTR_RECVQ_CONFIG request */
typedef struct recvq_config_req {
	wrsm_message_header_t header;
	uint64_t qid;
	uint_t mondo;
	size_t new_qdepth;
} recvq_config_req_t;

/* Format of message for WRSM_MSG_INTR_RECVQ_CONFIG_RESPONSE */
typedef struct recvq_config_rsp {
	wrsm_message_header_t header;
	int retval;	/* RSM_SUCCESS or errno */
} recvq_config_rsp_t;

/* Format of message for WRSM_MSG_INTR_RECVQ_DESTROY request */
typedef struct recvq_destroy {
	wrsm_message_header_t header;
	uint64_t qid;
	uint_t mondo;
	rsm_intr_t service;
} recvq_destroy_t;

/*
 * Local functions
 */

/* Handler functions */
static void
handler_init(wrsm_intr_handler_t *handler, rsm_intr_hand_t func,
    rsm_intr_hand_arg_t arg, cnode_bitmask_t cnodes,
    rsm_controller_object_t *controller_obj)
{
	DTRC("handler_init");
	handler->func = func;
	handler->arg = arg;
	handler->controller_obj = controller_obj;
	WRSMSET_COPY(cnodes, handler->cnodes);
}

/* ARGSUSED */
static void
handler_fini(wrsm_intr_handler_t *handler)
{
	DTRC("handler_fini");
	/* Nothing to do */
}

/* ARGSUSED */
static void
handler_print(wrsm_intr_handler_t *handler)
{
	DPRINTF(INTRDBG, (CE_CONT,
	    "    handler 0x%p func 0x%p arg 0x%p ctlr-obj 0x%p next 0x%p",
	    (void *)handler,
	    (void *)handler->func,
	    (void *)handler->arg,
	    (void *)handler->controller_obj,
	    (void *)handler->next));
}

/* Calls back the client with an interrupt event */
static rsm_intr_hand_ret_t
handler_callback(wrsm_intr_handler_t *handler, rsm_intr_q_op_t q_op,
	cnodeid_t from_cnode, void *is_data, size_t is_size)
{
	rsm_intr_hand_ret_t retval = RSM_INTR_HAND_UNCLAIMED;
	DTRC("handler_callback");

	handler_print(handler);

	/* If source is allowed to send to this handler, do callback */
	if (WRSM_IN_SET(handler->cnodes, from_cnode)) {
		retval = (*handler->func)(handler->controller_obj,
		    q_op,
		    (rsm_addr_t)from_cnode,
		    is_data,
		    is_size,
		    handler->arg);
	}
	return (retval);
}

/* Service functions */

/* Initializes a service */
static void
service_init(wrsm_intr_service_t *service, wrsm_network_t *net, rsm_intr_t t)
{
	DTRC("service_init");
	bzero(service, sizeof (wrsm_intr_service_t));
	service->net = net;
	service->type = t;
	mutex_init(&service->handler_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&service->recvq_mutex, NULL, MUTEX_DRIVER, NULL);
}

static void
service_fini(wrsm_intr_service_t *service)
{
	/* Destroy the handler list */
	wrsm_intr_handler_t *p = service->handler_list;
	DTRC("service_fini");

	while (p) {
		wrsm_intr_handler_t *next = p->next;
		handler_fini(p);
		kmem_free(p, sizeof (wrsm_intr_handler_t));
		p = next;
	}
	mutex_destroy(&service->handler_mutex);
	mutex_destroy(&service->recvq_mutex);
}

static void
service_print(wrsm_intr_service_t *service)
{
	wrsm_intr_handler_t *h;

	DPRINTF(INTRDBG, (CE_CONT, "    service 0x%p id=%d ctlr=%d\n",
	    (void *)service,
	    service->type,
	    service->net->rsm_ctlr_id));

	DPRINTF(INTRDBG, (CE_CONT, "	service handler list:\n"));
	for (h = service->handler_list; h; h = h->next) {
		handler_print(h);
	}
}

/* Adds a recvq to the service's linked list of recvqs */
static void
service_add_recvq(wrsm_intr_service_t *service, wrsm_intr_recvq_t *recvq)
{
	DTRC("service_add_recvq");

	mutex_enter(&service->recvq_mutex);
	recvq->service_next = service->recvq_list;
	service->recvq_list = recvq;
	service_print(service);
	mutex_exit(&service->recvq_mutex);
}

/* Finds and removes a recvq from the service's linked list of recvqs */
static void
service_rem_recvq(wrsm_intr_service_t *service, wrsm_intr_recvq_t *recvq)
{
	wrsm_intr_recvq_t *p;
	DTRC("service_rem_recvq");

	mutex_enter(&service->recvq_mutex);
	/* If recvq is first on list, handle special */
	if (service->recvq_list == recvq) {
		service->recvq_list = recvq->service_next;
	} else {
		for (p = service->recvq_list; p; p = p->service_next) {
			if (p->service_next == recvq) {
				p->service_next = recvq->service_next;
				break;
			}
		}
	}
	mutex_exit(&service->recvq_mutex);
}

/* Adds a handler to the linked list of handlers for this service */
static void
service_add_handler(wrsm_intr_service_t *service, wrsm_intr_handler_t *handler)
{
	wrsm_intr_handler_t *p;
	DTRC("service_add_handler");
	mutex_enter(&service->handler_mutex);
	handler->next = NULL;

	/* Add to end of list */
	if (service->handler_list == NULL) {
		service->handler_list = handler;
	} else {
		/* Advance to last node in list */
		for (p = service->handler_list; p->next; p = p->next)
			;
		p->next = handler;
	}

	service_print(service);

	mutex_exit(&service->handler_mutex);
}

/* Removes and returns a handler from the service's handler list */
static wrsm_intr_handler_t *
service_rem_handler(wrsm_intr_service_t *service,
    rsm_intr_hand_t func, rsm_intr_hand_arg_t arg)
{
	wrsm_intr_handler_t *handler = NULL;
	DTRC("service_rem_handler");

	mutex_enter(&service->handler_mutex);
	if (service->handler_list == NULL) {
		handler = NULL;
	} else if (service->handler_list->func == func &&
	    service->handler_list->arg == arg) {
		/* If this is the first handler in the list, handle special */
		handler = service->handler_list;
		service->handler_list = handler->next;
		handler->next = NULL;
	} else {
		wrsm_intr_handler_t *p;
		for (p = service->handler_list; p->next; p = p->next) {
			if (p->next->func == func && p->next->arg == arg) {
				handler = p->next;
				p->next = handler->next;
				handler->next = NULL;
				break;
			}
		}
	}
	mutex_exit(&service->handler_mutex);
	return (handler);
}

/* Distributes a packet to all handlers registered for this service. */
static void
service_callback(wrsm_intr_service_t *service, void *buffer, size_t size,
    cnodeid_t from_cnode)
{
	wrsm_intr_handler_t *h;

	DTRC("service_callback");

	mutex_enter(&service->handler_mutex); /* Lock the handler list */
	for (h = service->handler_list; h; h = h->next) {
		if (handler_callback(h, RSM_INTR_Q_OP_RECEIVE, from_cnode,
		    buffer, size) == RSM_INTR_HAND_CLAIMED_EXCLUSIVE) {
			break;
		}
	}
	mutex_exit(&service->handler_mutex);
}


/* Initializes the service list */
static void
service_list_init(wrsm_interrupt_t *intr, wrsm_network_t *net)
{
	uint_t i;
	DTRC("service_list_init");

	for (i = 0; i < WRSM_INTR_TYPE_MAX; i++) {
		service_init(&intr->services[i], net, i);
	}
}

/* Destroys the service list */
static void
service_list_fini(wrsm_interrupt_t *intr)
{
	uint_t i;
	DTRC("service_list_fini");

	for (i = 0; i < WRSM_INTR_TYPE_MAX; i++) {
		service_fini(&intr->services[i]);
	}
}


/* Recvq Functions */

/* Initializes/Refreshes the recvq CMMU entry */
static void
recvq_cmmu_update(wrsm_intr_recvq_t *recvq, boolean_t set_invalid,
    boolean_t set_user_error)
{
	wrsm_cmmu_t cmmu;
	uint_t cpu_id = recvq->target->cpu_id;
	boolean_t user_err;

	ASSERT(recvq);
	ASSERT(recvq->net);

	/*
	 * If the high water mark is 0, then the user must have created
	 * a queue of length 0. Force the user error to be set right
	 * from the start. This would probably only be done in testing,
	 * but the spec doesn't say it's not allowed.
	 */
	user_err = (set_user_error || recvq->high_water_mark == 0) ?
		B_TRUE : B_FALSE;

	cmmu.entry_0.val = 0;
	cmmu.entry_1.val = 0;
	cmmu.entry_0.bit.count_enable = B_FALSE;
	cmmu.entry_0.bit.large_page = B_FALSE;
	cmmu.entry_0.bit.user_err = user_err;
	cmmu.entry_0.bit.writable = B_TRUE;
	cmmu.entry_0.bit.from_all = (recvq->exportseg ? B_TRUE : B_FALSE);
	cmmu.entry_0.bit.valid = (set_invalid ? B_FALSE : B_TRUE);
	cmmu.entry_0.bit.type = CMMU_TYPE_INTERRUPT;
	cmmu.entry_0.bit.from_node = recvq->from_cnode;
	cmmu.entry_1.intr.mondo = recvq->cmmu_mondo;
	cmmu.entry_1.intr.lpa_page_2 = (cpu_id<<1);

	wrsm_cmmu_update(recvq->net, &cmmu, recvq->cmmu_index,
	    CMMU_UPDATE_ALL | CMMU_UPDATE_FLUSH);
}

/* Destroys the receive queue contents */
static void
recvq_fini(wrsm_network_t *net, wrsm_intr_recvq_t *recvq)
{
	wrsm_cmmu_tuple_t *tuples;

	wrsm_interrupt_t *intr;
	DTRC("recvq_fini");

	intr = net->interrupt;
	ASSERT(mutex_owned(&intr->mutex));

	/* Set the CMMU entry to invalid */
	recvq_cmmu_update(recvq, B_TRUE, B_FALSE);

	/* Cross trap to make sure trap handler isn't running */
	wrsmplat_xt_sync(recvq->target->cpu_id);

	/* Take recvq mutex to ensure drainer isn't using it */
	mutex_enter(&recvq->mutex);

	tuples = recvq->tuples;

	/* Use cmmu_mondo to free recvq table entry */
	recvq_table_free_entry(intr, recvq->cmmu_mondo);
	cv_broadcast(&intr->resource_cv);

	/* Remove from target and service lists */
	target_rem_recvq(recvq->target, recvq);
	service_rem_recvq(recvq->service, recvq);

	/* Delete packet ring */
	if (recvq->packet_ring) {
		kmem_free(recvq->packet_ring,
		    recvq->packet_ring_info.info.size *
		    sizeof (wrsm_intr_packet_t));
	}

	/* If it's on a drainer list, can't free yet, let drainer do it */
	if ((recvq->packet_ring_info.info.head !=
	    recvq->packet_ring_info.info.tail) ||
	    (recvq->drainer_next != NULL) ||
	    recvq->in_use) {
		recvq->delete_me = B_TRUE;
		mutex_exit(&recvq->mutex);
	} else {
		DPRINTF(INTRTRACE, (CE_CONT,
		    "freeing recvq 0x%p\n", (void *)recvq));
		mutex_exit(&recvq->mutex);
		mutex_destroy(&recvq->mutex);
		/* else, free the receive queue now */
		kmem_free(recvq, sizeof (wrsm_intr_recvq_t));
	}

	/* Free the CMMU tuples */
	wrsm_cmmu_free(net, 1, tuples);
}

/* Retrieves a packet from the recvq. Returns size of packet */
static size_t
recvq_get_packet(wrsm_intr_recvq_t *recvq, wrsm_intr_packet_t buffer,
    uint32_t *num_packets)
{
	wrsm_intr_packet_ring_union_t new;
	wrsm_intr_packet_ring_union_t old;
	volatile uint64_t *p = &(recvq->packet_ring_info.val);
	int tail = recvq->packet_ring_info.info.tail;
	uint64_t *data = (uint64_t *)&recvq->packet_ring[tail];
	size_t size = sizeof (wrsm_intr_packet_t);

	*num_packets = 0;

	/* If packet ring is empty, return 0 */
	if (recvq->packet_ring_info.info.tail ==
	    recvq->packet_ring_info.info.head) {
		return (0);
	}
	/*
	 * For user interrupts, first word contains size in
	 * lower 6 bits, garbage in rest of word. Advance
	 * start of data by 1 64-bit word so user sees only
	 * the user data portion of the interrupt.
	 */
	if (recvq->user_interrupt) {
		size = (uint_t)(data[0] & 0x3f);
		data++;
	}

	/* Copy data from recvq to a caller's buffer */
	bcopy(data, buffer, size);

	/* Atomically increment the tail */
	do {
		/* Keep reading info until lock bit not set */
		old.val = *p;
		if (old.info.lock) {
			continue;
		}
		*num_packets = (old.info.tail <= old.info.head) ?
		    (old.info.head - old.info.tail) :
		    (old.info.size - (old.info.tail - old.info.head));
		new.val = old.val;
		new.info.tail = (new.info.tail + 1) % new.info.size;
		if (cas64((uint64_t *)p, old.val, new.val) == old.val)
			break;
	/* LINTED: E_CONST_EXPR */
	} while (1);

	return (size);
}

static void
recvq_callback(wrsm_intr_recvq_t *recvq)
{
	wrsm_intr_service_t *service;
	wrsm_intr_packet_t buf;
	size_t size;
	uint32_t num_packets;
	cnodeid_t from_cnode;

	mutex_enter(&recvq->mutex);

	ASSERT(recvq->in_use == B_FALSE);
	ASSERT(recvq->drainer_next != NULL);

	if (recvq->delete_me) {
		/* recvq_was deleted while on the pending service list */
		DPRINTF(INTRTRACE, (CE_CONT,
		    "freeing recvq in recvq_callback 0x%p\n",
		    (void *)recvq));
		mutex_exit(&recvq->mutex);
		mutex_destroy(&recvq->mutex);
		kmem_free(recvq, sizeof (wrsm_intr_recvq_t));
		return;
	}

	/*
	 * in_use prevents recvq_fini from removing recvq even after the
	 * last packet is removed from the packet ring and drainer_next is
	 * NULL.
	 */
	recvq->in_use = B_TRUE;

	/*
	 * Allow recvq to be queued to pending service queue again by
	 * setting drainer_next to NULL.  This must be allowed prior to
	 * emptying the packet ring.  If drainer_next were NULLed after
	 * processing the packet ring, we could have a race, where
	 * recvq_callback thinks it has processed all packets, then a trap
	 * comes in and queues a packet, then recvq_callback sets
	 * drainer_next to NULL.  This would leave the new packet
	 * unprocessed, with recvq not in the pending service queue.
	 */
	recvq->drainer_next = NULL;

	NOTE("Servicing recvq: ");
	recvq_print(recvq);

	service = recvq->service;
	from_cnode = recvq->from_cnode;

	for (size = recvq_get_packet(recvq, buf, &num_packets);
	    num_packets > 0;
	    size = recvq_get_packet(recvq, buf, &num_packets)) {

		mutex_exit(&recvq->mutex);
		/* Callback handlers for this service */
		service_callback(service, buf, size, from_cnode);
		mutex_enter(&recvq->mutex);
		/*
		 * At the point where recvq->delete_me is set, it is
		 * guaranteed that no further traps for this recvq will
		 * arrive, as the cmmu entry was invalidated and traps were
		 * flushed.  This means the recvq won't be added to the
		 * pending service queue, and the state of drainer_next
		 * will not change to non-NULL after revq->delete_me is
		 * set.  This means we can check the value of drainer_next
		 * here.
		 *
		 * If drainer_next is not NULL, this means this recvq was
		 * added back onto the pending service queue since this
		 * function set drainer_next to NULL.  In this case, the
		 * recvq will be deleted during the servicing of this recvq
		 * the next time it is taken off the pending service queue.
		 */
		if (recvq->delete_me) {
			/* recvq was deleted during the callback */
			if (recvq->drainer_next == NULL) {
				DPRINTF(INTRTRACE, (CE_CONT,
				    "freeing recvq post service_callback "
				    "in recvq_callback 0x%p\n",
				    (void *)recvq));
				mutex_exit(&recvq->mutex);
				mutex_destroy(&recvq->mutex);
				kmem_free(recvq, sizeof (wrsm_intr_recvq_t));
				return;
			} else {
				/* don't process any more packets */
				break;
			}

		} else if (num_packets >= recvq->high_water_mark) {
			recvq_cmmu_update(recvq, B_FALSE, B_FALSE);
		}
	}

	recvq->in_use = B_FALSE;
	mutex_exit(&recvq->mutex);
}

/* ARGSUSED */
static void
recvq_print(wrsm_intr_recvq_t *recvq)
{
	DPRINTF(INTRDBG, (CE_CONT,
	    "    recvq 0x%X from=%d head=%d tail=%d target=%d drainer=0x%X "
	    "drainer_next=%p",
	    recvq->cmmu_mondo,
	    recvq->from_cnode,
	    recvq->packet_ring_info.info.head,
	    recvq->packet_ring_info.info.tail,
	    recvq->target->index,
	    recvq->drainer->drainer_inum,
	    (void *)recvq->drainer_next));
}

/* Recvq Table Functions */

/* Initialized the recvq tables */
/* ARGSUSED */
static void
recvq_table_init(wrsm_interrupt_t *intr)
{
	DTRC("recvq_table_init");
	/* Allocate first table, since we'll eventually need it */
	recvq_table_alloc_table(intr, 0);
}

/* Deletes the recvq table and all the recvqs */
static void
recvq_table_fini(wrsm_interrupt_t *intr, wrsm_network_t *net)
{
	uint_t i;
	uint_t j;
	DTRC("recvq_table_fini");

	for (i = 0; i < WRSM_INTR_RECVQ_TABLES; i++) {
		/* Once we hit a null table, we can break */
		if (intr->recvq_tables[i] == NULL) {
			break;
		}
		/* For each pointer in table, kill it */
		for (j = 0; j < WRSM_INTR_RECVQ_TABLE_SIZE; j++) {
			wrsm_intr_recvq_t *recvq = (*intr->recvq_tables[i])[j];
			if (RECVQ_VALID(recvq)) {
				wrsm_intr_destroy_recvq(net, recvq);
			}
		}
		kmem_free(intr->recvq_tables[i],
		    WRSM_INTR_RECVQ_TABLES_ARRAY_SIZE);
	}
}

/* Prints all recvqs */
static void
recvq_table_print(wrsm_interrupt_t *intr)
{
	uint_t i;
	uint_t j;

	mutex_enter(&intr->mutex);
	for (i = 0; i < WRSM_INTR_RECVQ_TABLES; i++) {
		/* Once we hit a null table, we can break */
		if (intr->recvq_tables[i] == NULL) {
			break;
		}
		/* For each pointer in table, kill it */
		for (j = 0; j < WRSM_INTR_RECVQ_TABLE_SIZE; j++) {
			wrsm_intr_recvq_t *recvq = (*intr->recvq_tables[i])[j];
			if (RECVQ_VALID(recvq)) {
				recvq_print(recvq);
			}
		}
	}
	mutex_exit(&intr->mutex);
}

/* Allocates and initializes a recvq_table array */
static void
recvq_table_alloc_table(wrsm_interrupt_t *intr, unsigned table)
{
	unsigned i;
	int mondo;

	DPRINTF(INTRTRACE, (CE_NOTE, "recvq_table_alloc_table(%d)", table));

	ASSERT(intr->recvq_tables[table] == NULL);
	/*
	 * In order to provide fast identification of the next freerecvq_table
	 * entry, the unused entries in the recvq_table contain the cmmu_mondo
	 * of the next free entry in a linked free list sort of fashion. In
	 * other words, at initialization, entry 0 contains the number 1,
	 * entry 1 contains the number 2, etc. When entry 1 is allocated,
	 * for example, entry 0 is updated to contain a 2 since 2 is now the
	 * first free entry. Since it is not allowed to use
	 * cmmu_mondo == 0, entry 0 is used as the implicit head of the linked
	 * list. When someone wants to allocate a cmmu entry, we look at the
	 * value in entry 0, which is the mondo of the first free entry. We
	 * then allocate that entry, and whatever value was in that location
	 * goes into entry 0 to maintain the free list.
	 */

	/* Calculate mondo of first entry in this table */
	mondo = WRSM_INTR_RECVQ_TABLE_SIZE * table;
	intr->recvq_tables[table] =
		kmem_zalloc(WRSM_INTR_RECVQ_TABLES_ARRAY_SIZE, KM_SLEEP);
	for (i = 0; i < WRSM_INTR_RECVQ_TABLE_SIZE; i++) {
		mondo++; /* Point to next (free) entry for free list */
		(*intr->recvq_tables[table])[i] = CAST_MONDO2RECVQ(mondo);
	}
}

/* Allocates a recvq table entry. Returns cmmu_mondo, or 0 if out of space. */
static int
recvq_table_alloc_entry(wrsm_interrupt_t *intr)
{
	int free_mondo;
	unsigned table;
	unsigned index;

	DTRC("recvq_table_alloc_entry");

	ASSERT(mutex_owned(&intr->mutex));

	/*
	 * The recvq table entries are overlaid with a linked list. Entry
	 * (0,0) contains the mondo of the next free entry. That
	 * entry contains the mondo of the second free entry, and so forth.
	 * If the next free mondo points beyond the last table, then we're
	 * out of entries.
	 */
	free_mondo = CAST_RECVQ2MONDO((*intr->recvq_tables[0])[0]);
	table = WRSM_MONDO2TABLE(free_mondo);
	index = WRSM_MONDO2INDEX(free_mondo);

	/* Check for empty */
	if (table >= WRSM_INTR_RECVQ_TABLES) {
		WARN("recvq_table_alloc_entry: out of memory");
		return (NULL);
	}

	/*
	 * We only allocate tables when needed, so it's possible the table
	 * doesn't exist yet. If it doesn't, allocate it.
	 */
	if (intr->recvq_tables[table] == NULL) {
#ifdef DEBUG
		if (index != 0) {
			DPRINTF(INTRERR, (CE_WARN,
			    "alloc_entry table %d: index = %d != 0",
			    table, index));
		}
#endif /* DEBUG */
		recvq_table_alloc_table(intr, table);
	}

	/* Make head of list point at "next" free entry */
	(*intr->recvq_tables[0])[0] = (*intr->recvq_tables[table])[index];

	/* Be nice and null the new entry */
	(*intr->recvq_tables[table])[index] = NULL;

	return (free_mondo);
}

/* Places a recvq_table_entry back on the free list */
static void
recvq_table_free_entry(wrsm_interrupt_t *intr, int cmmu_mondo)
{
	unsigned table = WRSM_MONDO2TABLE(cmmu_mondo);
	unsigned index = WRSM_MONDO2INDEX(cmmu_mondo);

	ASSERT(mutex_owned(&intr->mutex));
#ifdef DEBUG
	if (!RECVQ_VALID((*intr->recvq_tables[table])[index])) {
		DPRINTF(INTRERR, (CE_WARN, "recvq_table_free_entry: "
		    "attempt to free an unused recvq entry: %d",
		    cmmu_mondo));
		return;
	}
#endif /* DEBUG */

	/* Places this entry at head of free list */
	(*intr->recvq_tables[table])[index] =  (*intr->recvq_tables[0])[0];
	(*intr->recvq_tables[0])[0] = CAST_MONDO2RECVQ(cmmu_mondo);
}

/* Sets the recvq table entry based on the cmmu_mondo */
static void
recvq_table_set(wrsm_interrupt_t *intr, int cmmu_mondo,
    wrsm_intr_recvq_t *recvq)
{
	unsigned table = WRSM_MONDO2TABLE(cmmu_mondo);
	unsigned index = WRSM_MONDO2INDEX(cmmu_mondo);
	wrsm_intr_recvq_table_t *ptable = intr->recvq_tables[table];
	DTRC("recvq_table_set");

	ASSERT(ptable);
#ifdef DEBUG
	if ((*ptable)[index]) {
		DPRINTF(INTRERR, (CE_WARN, "recvq_table_set: "
		    "attempt to set in-use entry %d", cmmu_mondo));
	}
#endif /* DEBUG */
	(*ptable)[index] = recvq;
}

/* Target functions */

/* Initializes a target structure */
static void
target_init(wrsm_intr_target_t *target, wrsm_intr_drainer_t *drainer,
    uint32_t target_index)
{
	DPRINTF(INTRTRACE, (CE_CONT, "target_init: %d", target_index));
	DPRINTF(INTRDBG, (CE_CONT, "  Got drainer 0x%X",
	    drainer->drainer_inum));

	bzero(target, sizeof (wrsm_intr_target_t));
	target->index = target_index;
	target->intr_dist_mondo = NULL_INTR_DIST_MONDO;
	target->drainer = drainer;
	target->cpu_id = INVALID_SAFARI_ID;
}

/* Destroys a target struct */
static void
target_fini(wrsm_intr_target_t *target)
{
	DPRINTF(INTRTRACE, (CE_CONT, "target_fini %d", target->index));
}

/*
 * Repeats the intr_dist_cpu process if the safari port id of the WCI
 * changes, thus changing the interrupt distribution mondo. This
 * may happen if the WCI is removed from the controller.  If we didn't
 * repeat the intr_dist_cpu with a new intr_dist_mondo, and the WCI
 * is moved to a new controller, that new controller would have
 * conflicting intr_dist_mondos. Also, we must use a valid WCI
 * id, since other devices/drivers may also use the interrupt
 * distribution mechanism.
 */
static void
target_readd_cpu(wrsm_network_t *net, wrsm_intr_target_t *target)
{
	safari_port_t safid = net->interrupt->wci_safari_port;

	if (safid == INVALID_SAFARI_ID) {
		target->intr_dist_mondo = NULL_INTR_DIST_MONDO;
	} else {
		target->intr_dist_mondo =
			MAKE_INTR_DIST_MONDO(safid, target->index);
		target->cpu_id = intr_dist_cpuid();
	}

	/* Retarget all the CMMU entries for this target */
	target_retarget(net, target);
}

/*
 * This function is called by OS when a CPU we're targeted at is removed.
 */
void
wrsm_redist(void *dip)
{
	wrsm_intr_target_t *start;
	wrsm_intr_target_t *target;
	wrsm_network_t *net;
	wrsm_interrupt_t *intr;

	/* Use dip to get wrsm_network_t, then interrupt structure */
	net = wrsm_dip_to_network(dip);
	if (net == NULL) {
		return;
	}

	if (net->cmmu == NULL) {
		return;
	}

	intr = net->interrupt;
	if (intr == NULL) {
		return;
	}

	mutex_enter(&intr->mutex);

	if (intr->targets == NULL) {
		mutex_exit(&intr->mutex);
		return;
	}

	start = target = intr->targets;

	do {
		/* Save new cpu id */
		target->cpu_id = intr_dist_cpuid();

		DPRINTF(INTRDBG, (CE_CONT, "wrsm_redist cpu: 0x%04X",
			target->cpu_id));

		/* Retarget all the CMMU entries for this target */
		target_retarget(net, target);

		target = target->next;

	} while (target != start);

	mutex_exit(&intr->mutex);
}

/*
 * Updates the CMMU entries for a given target, presumable because the
 * target->cpu_id has changed.
 */
static void
target_retarget(wrsm_network_t *net, wrsm_intr_target_t *target)
{
	wrsm_intr_recvq_t *p;
	wrsm_cmmu_t cmmu;
	processorid_t cpu_id = target->cpu_id;
	uint64_t lpa_page_2 = (cpu_id<<1);

	/*
	 * Walk list of recvq's pointed at this target, and change cmmu
	 * entries to point to new cpu
	 */
	for (p = target->recvq_list; p; p = p->target_next) {
		DPRINTF(INTRDBG, (CE_CONT, "  Update cmmu entry %u",
		    p->cmmu_index));

		/* Read the current cmmu entry */
		wrsm_cmmu_read(net, &cmmu, p->cmmu_index);

		/* Set user error bit */
		cmmu.entry_0.bit.user_err = B_TRUE;
		wrsm_cmmu_update(net, &cmmu, p->cmmu_index,
		    CMMU_UPDATE_USERERROR | CMMU_UPDATE_FLUSH);

		/*
		 * Do a cross trap to the target CPU to make sure that any
		 * in-process interrupts are complete.
		 */
		wrsmplat_xt_sync(target->cpu_id);

		/* Update CMMU to the new target cpu and clear user err bit */
		cmmu.entry_1.intr.lpa_page_2 = lpa_page_2;
		cmmu.entry_0.bit.user_err = B_FALSE;
		wrsm_cmmu_update(net, &cmmu, p->cmmu_index,
		    CMMU_UPDATE_INTRDEST |
		    CMMU_UPDATE_USERERROR |
		    CMMU_UPDATE_FLUSH);
	}
}

/* Adds a recvq to the target's linked list of recvqs. Must own intr->mutex */
static void
target_add_recvq(wrsm_intr_target_t *target, wrsm_intr_recvq_t *recvq)
{
	DTRC("target_add_recvq");

	recvq->target_next = target->recvq_list;
	target->recvq_list = recvq;
}

/* Finds and removes a recvq from linked list. Must own intr->mutex */
static void
target_rem_recvq(wrsm_intr_target_t *target, wrsm_intr_recvq_t *recvq)
{
	wrsm_intr_recvq_t *p;
	DTRC("target_rem_recvq");

	/* If recvq is first on list, handle special */
	if (target->recvq_list == recvq) {
		target->recvq_list = recvq->target_next;
	} else {
		for (p = target->recvq_list; p; p = p->target_next) {
			if (p->target_next == recvq) {
				p->target_next = recvq->target_next;
				break;
			}
		}
	}
}

/* Prints interesting info about the target, mostly for debug */
/* ARGSUSED */
static void
target_print(wrsm_intr_target_t *target)
{
	DPRINTF(INTRDBG, (CE_CONT,
	    "    target %d cpuid=%d mondo=0x%X drainer=0x%X",
	    target->index,
	    target->cpu_id,
	    target->intr_dist_mondo,
	    target->drainer->drainer_inum));
}

/* Builds the list of targets and places it in the interrupt structure */
static void
target_list_init(wrsm_interrupt_t *intr)
{
	int num_targets = MIN(ncpus, WRSM_INTR_MAX_TARGETS);
	int i;
	DTRC("target_list_init");

	for (i = 0; i < num_targets; i++) {
		/* Allocate space for each target */
		wrsm_intr_target_t *target =
			kmem_alloc(sizeof (wrsm_intr_target_t), KM_SLEEP);
		/* Pick a drainer */
		wrsm_intr_drainer_t *drainer = drainer_list_get_next(intr);
		/* Init the target structure */
		target_init(target, drainer, i);


		if (intr->targets == NULL) {
			/* If list is empty, point at this item */
			(intr->targets) = target;
		} else {
			/* Otherwise, point at whoever was next */
			target->next = (intr->targets)->next;
		}
		/* Point head of list at this new item */
		(intr->targets)->next = target;
	}
}

/* Deletes the entire target list */
static void
target_list_fini(wrsm_interrupt_t *intr)
{
	wrsm_intr_target_t *first = intr->targets;
	wrsm_intr_target_t *target = first;
	DTRC("target_list_fini");

	ASSERT(first); /* Target list should never be empty */

	/* Repeat until we loop around to first again */
	do {
		/* Remember which comes next */
		wrsm_intr_target_t *next = target->next;

		/* Now it's safe to kill it */
		target_fini(target);
		kmem_free(target, sizeof (wrsm_intr_target_t));

		/* We're done when next points back to original target */
		target = next;
	} while (target != first);

	intr->targets = NULL;
}

/* Repeats the intr_dist_cpu process for all targets with new wci */
static void
target_list_readd_cpu(wrsm_network_t *net)
{
	wrsm_intr_target_t *first = net->interrupt->targets;
	wrsm_intr_target_t *target = first;
	DTRC("target_list_readd");

	ASSERT(first); /* Target list should never be empty */

	/* Repeat until we loop around to first again */
	do {
		target_readd_cpu(net, target);
		target = target->next;
	} while (target != first);
}

static wrsm_intr_target_t *
target_list_get_next(wrsm_interrupt_t *intr)
{
	wrsm_intr_target_t *target;
	DTRC("target_list_get_next");

	ASSERT(mutex_owned(&intr->mutex));
	ASSERT(intr->targets != NULL);

	target = intr->targets;
	intr->targets = (intr->targets)->next;
	return (target);
}

/* Prints the entire target list */
static void
target_list_print(wrsm_interrupt_t *intr)
{
	wrsm_intr_target_t *start = intr->targets;
	wrsm_intr_target_t *target = start;

	DPRINTF(INTRDBG, (CE_CONT, "  target_list:"));
	mutex_enter(&intr->mutex);
	do {
		target_print(target);
		target = target->next;
	} while (target != start);
	mutex_exit(&intr->mutex);
}

/* Drainer functions */

static int
drainer_init(wrsm_intr_drainer_t *drainer)
{
	DTRC("drainer_init");

	bzero(drainer, sizeof (wrsm_intr_drainer_t));

	drainer->drainer_inum =
		add_softintr(PIL_6, (softintrfunc)drainer_handler,
		    (caddr_t)drainer);
	if (drainer->drainer_inum == 0) {
		DPRINTF(INTRERR, (CE_WARN, "add_softintr() failed"));
		return (EAGAIN);
	}
	DPRINTF(INTRDBG, (CE_CONT, "soft_vec: 0x%X\n", drainer->drainer_inum));
	drainer->drainer_psl = (wrsm_intr_recvq_t *)WRSM_INTR_PSL_IDLE;

	return (0);
}

/* Prints interesting info about a drainer */
/* ARGSUSED */
static void
drainer_print(wrsm_intr_drainer_t *drainer)
{
	DPRINTF(INTRDBG, (CE_CONT, "    drainer 0x%X", drainer->drainer_inum));
}

/* Destroys a drainer */
static void
drainer_fini(wrsm_intr_drainer_t *drainer)
{
	DTRC("drainer_fini");
	rem_softintr(drainer->drainer_inum);
}

/* Returns the old psl pointer, atomically setting new psl to empty */
static wrsm_intr_recvq_t *
drainer_get_psl(wrsm_intr_drainer_t *drainer)
{
	wrsm_intr_recvq_t *sl;
	wrsm_intr_recvq_t *oldval;
	do {
		/* Copy psl to sl */
		sl = drainer->drainer_psl;
		/* If psl hasn't changed, oldval will be sl, psl will be 0 */
		oldval = (wrsm_intr_recvq_t *)casptr(
		    &drainer->drainer_psl,
		    sl,
		    WRSM_INTR_PSL_EMPTY);
	} while (oldval != sl);
	/* The following shouldn't happen, but just to be sure... */
	if (sl == (wrsm_intr_recvq_t *)WRSM_INTR_PSL_IDLE) {
		WARN("drainer_get_psl: psl was IDLE");
		sl = WRSM_INTR_PSL_EMPTY;
	}
	return (sl);
}

/* If psl is empty, set it to idle and return true; else return false */
static boolean_t
drainer_psl_empty(wrsm_intr_drainer_t *drainer)
{
	return (WRSM_INTR_PSL_EMPTY ==
	    casptr(&drainer->drainer_psl,
		WRSM_INTR_PSL_EMPTY,
		(void *)WRSM_INTR_PSL_IDLE));
}

/* Drainer soft interrupt handler */
static uint_t
drainer_handler(caddr_t arg)
{
	wrsm_intr_recvq_t *sl;
	wrsm_intr_drainer_t *drainer = (wrsm_intr_drainer_t *)arg;
	wrsm_intr_recvq_t *recvq;

	DTRC("drainer_handler");
	ASSERT(drainer);

	drainer_print(drainer);

	/* Swap service list with pending service list */
	do {
		sl = drainer_get_psl(drainer);

		/* While there's something on the service list */
		while (sl != WRSM_INTR_PSL_EMPTY) {
			/* Get head of service list */
			recvq = sl;

			/* Update service list to point to next recvq */
			sl = recvq->drainer_next;
			ASSERT(recvq != sl);

			/* If we've reached the end, set to empty */
			if (sl == (wrsm_intr_recvq_t *)WRSM_INTR_PSL_IDLE) {
				sl = WRSM_INTR_PSL_EMPTY;
			}
			/*
			 * Process the recvq - this also sets drainer_next
			 * to NULL
			 */
			recvq_callback(recvq);
		}
	} while (!drainer_psl_empty(drainer));
	return (DDI_INTR_CLAIMED);
}

/* Drainer List functions */

/* Builds the list of drainers and places it in the interrupt structure */
static int
drainer_list_init(wrsm_interrupt_t *intr)
{
	int retval = 0;
	int i;
	int num_drainers = MIN(ncpus, WRSM_INTR_MAX_DRAINERS);
	DTRC("drainer_list_init");

	intr->drainers = NULL;
	for (i = 0; i < num_drainers; i++) {
		wrsm_intr_drainer_t *drainer =
		    kmem_alloc(sizeof (wrsm_intr_drainer_t), KM_SLEEP);
		int retval = drainer_init(drainer);

		if (retval) {
			kmem_free(drainer, sizeof (wrsm_intr_drainer_t));
			break;
		}

		if (intr->drainers == NULL) {
			/* If list is empty, point at this item */
			(intr->drainers) = drainer;
		} else {
			/* Otherwise, point at whoever was next */
			drainer->next = (intr->drainers)->next;
		}
		/* Point head of list at this new item */
		(intr->drainers)->next = drainer;
	}
	/* If we weren't able to allocate ANY soft interrupts... */
	if (i == 0) {
		cmn_err(CE_WARN, "Unable to allocate any soft interrupts");
	}
	return (retval);
}

/* Deletes the entire drainer list */
static void
drainer_list_fini(wrsm_interrupt_t *intr)
{
	wrsm_intr_drainer_t *first = intr->drainers;
	wrsm_intr_drainer_t *drainer = first;
	DTRC("drainer_list_fini");

	ASSERT(first); /* Drainer list should never be empty */

	/* Repeat until we loop around to first again */
	do {
		/* Remember which comes next */
		wrsm_intr_drainer_t *next = drainer->next;

		/* Now it's safe to kill it */
		drainer_fini(drainer);
		kmem_free(drainer, sizeof (wrsm_intr_drainer_t));

		/* We're done when next points back to original drainer */
		drainer = next;
	} while (drainer != first);

	intr->drainers = NULL;
}

static wrsm_intr_drainer_t *
drainer_list_get_next(wrsm_interrupt_t *intr)
{
	wrsm_intr_drainer_t *drainer;
	DTRC("drainer_list_get_next");

	/* Don't need lock since this is only called building target list */
	ASSERT(intr->drainers != NULL);

	drainer = intr->drainers;
	intr->drainers = (intr->drainers)->next;
	return (drainer);
}

/* Prints the entire drainer list */
static void
drainer_list_print(wrsm_interrupt_t *intr)
{
	wrsm_intr_drainer_t *start = intr->drainers;
	wrsm_intr_drainer_t *drainer = start;

	DPRINTF(INTRDBG, (CE_CONT, "  drainer_list:"));
	mutex_enter(&intr->mutex);
	do {
		drainer_print(drainer);
		drainer = drainer->next;
	} while (drainer != start);
	mutex_exit(&intr->mutex);
}

/* Prints all members of the interrupt component */
void
wrsm_intr_print(wrsm_network_t *net)
{
	DPRINTF(INTRDBG, (CE_CONT, "interrupt_print"));
	ASSERT(net);
	ASSERT(net->interrupt);

	drainer_list_print(net->interrupt);
	target_list_print(net->interrupt);
	recvq_table_print(net->interrupt);
}

/*
 * Message Handlers
 */
/* Handler for the recvq create request from a remote node */
static boolean_t
msg_recvq_create(wrsm_network_t *net, wrsm_message_t *msg)
{
	int retval;
	cnodeid_t from_cnode;
	unsigned ntuples;
	wrsm_interrupt_t *intr;
	wrsm_cmmu_tuple_t *tuples;
	wrsm_intr_recvq_t *recvq;
	wrsm_intr_service_t *service;
	wrsm_intr_handler_t *hdlr;
	wrsm_raw_message_t raw_resp;
	recvq_create_req_t *req = (recvq_create_req_t *)msg;
	recvq_create_rsp_t *rsp = (recvq_create_rsp_t *)&raw_resp;

	DPRINTF(INTRDBG, (CE_NOTE, "Cnode %d is requesting a recvq to %d",
		msg->header.source_cnode,
		net->cnodeid));
	intr = net->interrupt;
	from_cnode = req->header.source_cnode;
	rsp->header.message_type = WRSM_MSG_INTR_RECVQ_CREATE_RESPONSE;
	rsp->qid = 0;
	rsp->mondo = 0;
	rsp->nc_off = 0;
	rsp->retval = RSMERR_NO_HANDLER;

	/* Find the service */
	service = &intr->services[req->service];

	mutex_enter(&service->handler_mutex);
	/* Search for a handler willing to accept messages from this node */
	for (hdlr = service->handler_list; hdlr; hdlr = hdlr->next) {
		if (WRSM_IN_SET(hdlr->cnodes, req->header.source_cnode)) {
			rsp->retval = 0;
			break;
		}
	}
	mutex_exit(&service->handler_mutex);

	/* No handler -- send an error response */
	if (rsp->retval) {
		WARN("msg_recvq_create: no message handler");
		(void) wrsm_tl_rsp(net, msg, (wrsm_message_t *)rsp);
		return (B_TRUE);
	}

	/* Allocate a CMMU entry for this recvq */
	retval = wrsm_cmmu_alloc(net,
	    CMMU_PAGE_SIZE_SMALL,
	    1, /* nentries */
	    &tuples,
	    &ntuples,
	    B_FALSE);
	if (retval) {
		WARN("msg_recvq_create: unable to allocate cmmu entry");
		rsp->retval = RSMERR_INSUFFICIENT_RESOURCES;
		(void) wrsm_tl_rsp(net, msg, (wrsm_message_t *)rsp);
		return (B_TRUE);
	}

	/* Create the recvq */
	retval = wrsm_intr_create_recvq(net,
	    req->service,
	    req->qdepth,
	    tuples->index,
	    &recvq,
	    req->header.source_cnode,
	    NULL,
	    WRSM_CREATE_RECVQ_USER);
	if (retval) {
		WARN("msg_recvq_create: unable to create recvq");
		rsp->retval = RSMERR_INSUFFICIENT_RESOURCES;
		wrsm_cmmu_free(net, ntuples, tuples);
		(void) wrsm_tl_rsp(net, msg, (wrsm_message_t *)rsp);
		return (B_TRUE);
	}

	/* Link this new recvq into recvq_list for from_cnode */
	mutex_enter(&net->interrupt->mutex);
	recvq->recvq_next = intr->recvq_list[from_cnode];
	intr->recvq_list[from_cnode] = recvq;
	mutex_exit(&net->interrupt->mutex);

	/* Since creator is remote, store tuple pointer in recvq */
	recvq->tuples = tuples;

	/* Tell the handlers that a new recvq exists */
	for (hdlr = service->handler_list; hdlr; hdlr = hdlr->next) {
		(void) handler_callback(hdlr, RSM_INTR_Q_OP_CREATE,
		    req->header.source_cnode, NULL, 0);
	}

	/* Recvq has been created. Notify requestor */
	rsp->nc_off = (off_t)((tuples->index) * CMMU_SMALL_PAGE_SIZE);
	rsp->qid = (uint64_t)recvq;
	rsp->mondo = recvq->cmmu_mondo;

	/* If response fails, destroy the recvq */
	/* LINTED */
	if (wrsm_tl_rsp(net, msg, (wrsm_message_t *)rsp) != RSM_SUCCESS) {
		/*
		 * Don't need to destroy the recvq since, if rsp fails,
		 * TL tears down the session and the recvq gets
		 * destroyed anyway.
		 */
		WARN("msg_recvq_create: Unable to send response");
	}
	return (B_TRUE);
}

/* Handler for the recvq config request from a remote node */
static boolean_t
msg_recvq_config(wrsm_network_t *net, wrsm_message_t *msg)
{
	wrsm_interrupt_t *intr = net->interrupt;
	recvq_config_req_t *req = (recvq_config_req_t *)msg;
	wrsm_raw_message_t raw_resp;
	recvq_config_rsp_t *rsp = (recvq_config_rsp_t *)&raw_resp;
	unsigned table;
	unsigned index;
	wrsm_intr_recvq_table_t *ptable;
	wrsm_intr_recvq_t *recvq = (wrsm_intr_recvq_t *)(req->qid);
	wrsm_intr_packet_t *new_ring = NULL;
	size_t new_size;
	cnodeid_t source_cnode = msg->header.source_cnode;

	DTRC("msg_recvq_config");
	mutex_enter(&intr->mutex);

	/* Validate that the CMMU mondo and recvq pointer match */
	table = WRSM_MONDO2TABLE(req->mondo);
	index = WRSM_MONDO2INDEX(req->mondo);
	ptable = intr->recvq_tables[table];
	if ((ptable == NULL) ||
	    ((*ptable)[index] != recvq) ||
	    (recvq->from_cnode != source_cnode)) {
		/* The recvq doesn't exist or is invalid */
		WARN("msg_recvq_config: Recvq doesn't exist or is invalid");
		rsp->retval = RSMERR_NO_HANDLER;
	} else {
		rsp->retval = RSM_SUCCESS;
	}

	if (rsp->retval == RSM_SUCCESS) {
		/*
		 * Since the sender will take a lock before sending the
		 * recvq_config request, there should be no more interrupts
		 * arriving; however, set user_error bit in cmmu just to
		 * play it safe.
		 */
		recvq_cmmu_update(recvq, B_FALSE, B_TRUE);

		/*
		 * Now all we have to do is wait for the trap handler to
		 * finish any outstanding interrupts. This can be done with
		 * a cross-trap sync (xt_sync).
		 */
		wrsmplat_xt_sync(recvq->target->cpu_id);

		/* Lock servicing of recvq */
		mutex_enter(&recvq->mutex);

		/* Calculate size of new packet ring */
		new_size = req->new_qdepth + RECVQ_HIGHWATER_MARGIN;

		/* Alloc new packet ring if required */
		if (new_size > recvq->packet_ring_info.info.size) {
			new_ring = kmem_zalloc(
				new_size * sizeof (wrsm_intr_packet_t),
				KM_SLEEP);
		}

		/* If we've allocated a new ring, and we have an old ring... */
		if (new_ring && recvq->packet_ring) {
			/* Copy old ring contents to new ring */
			bcopy(recvq->packet_ring, new_ring,
			    recvq->packet_ring_info.info.size *
			    sizeof (wrsm_intr_packet_t));
			/* And free the old ring */
			kmem_free(recvq->packet_ring,
			    recvq->packet_ring_info.info.size *
			    sizeof (wrsm_intr_packet_t));
		}

		/* If we've allocated a new ring, update recvq */
		if (new_ring) {
			recvq->packet_ring = new_ring;
			recvq->packet_ring_info.info.size = new_size;
		}

		recvq->high_water_mark = req->new_qdepth;

		recvq_cmmu_update(recvq, B_FALSE, B_FALSE);

		mutex_exit(&recvq->mutex);
	}

	mutex_exit(&intr->mutex);

	rsp->header.message_type = WRSM_MSG_INTR_RECVQ_CONFIG_RESPONSE;
	/* LINTED */
	if (wrsm_tl_rsp(net, msg, (wrsm_message_t *)rsp) != RSM_SUCCESS) {
		/* Nothing to do - a failed rsp will cause seesion to end */
		WARN("msg_recvq_config: Unable to send response");
	}
	return (B_TRUE);
}

/* Handler for the recvq destroy request from a remote node */
static boolean_t
msg_recvq_destroy(wrsm_network_t *net, wrsm_message_t *msg)
{
	wrsm_interrupt_t *intr = net->interrupt;
	recvq_destroy_t *req = (recvq_destroy_t *)msg;
	unsigned table;
	unsigned index;
	wrsm_intr_recvq_table_t *ptable;
	wrsm_intr_recvq_t *recvq = (wrsm_intr_recvq_t *)(req->qid);
	wrsm_intr_recvq_t *rq;
	wrsm_intr_handler_t *hdlr;
	cnodeid_t source_cnode = msg->header.source_cnode;

	mutex_enter(&intr->mutex);
	/* Validate that the CMMU mondo and recvq pointer match */
	table = WRSM_MONDO2TABLE(req->mondo);
	index = WRSM_MONDO2INDEX(req->mondo);
	ptable = intr->recvq_tables[table];
	if (ptable == NULL) {
		mutex_exit(&intr->mutex);
		return (B_TRUE);
	}
	if ((*ptable)[index] != recvq) {
		mutex_exit(&intr->mutex);
		return (B_TRUE);
	}

	/* Validate that this is the right source cnode */
	if (recvq->from_cnode != source_cnode) {
		mutex_exit(&intr->mutex);
		return (B_TRUE);
	}

	/* Tell the handlers that the recvq is destroyed */
	for (hdlr = recvq->service->handler_list; hdlr; hdlr = hdlr->next) {
		(void) handler_callback(hdlr, RSM_INTR_Q_OP_DESTROY,
		    req->header.source_cnode, NULL, 0);
	}

	/* Unlink this recvq from that node's recvq_list */
	rq = intr->recvq_list[source_cnode];
	if (rq == recvq) {
		intr->recvq_list[source_cnode] = recvq->recvq_next;
	} else while (rq->recvq_next) {
		if (rq->recvq_next == recvq) {
			rq->recvq_next = recvq->recvq_next;
			recvq->recvq_next = NULL;
			break;
		}
		rq = rq->recvq_next;
	}

	/* Destroy the recvq */
	recvq_fini(net, recvq);

	mutex_exit(&intr->mutex);

	return (B_TRUE);
}

/*
 * Client functions
 */

static safari_port_t
find_a_wci(wrsm_interrupt_t *intr)
{
	int i;
	for (i = 0; i < WRSM_MAX_WCIS; i++) {
		if (intr->wci_ids[i] != INVALID_SAFARI_ID) {
			return (intr->wci_ids[i]);
		}
	}
	return (INVALID_SAFARI_ID);
}

/* Initialize the interrupt component for this network */
int
wrsm_intr_init(wrsm_network_t *net)
{
	wrsm_interrupt_t *intr;
	int i;
	int retval = 0;
	DTRC("wrsm_intr_init");

	ASSERT(net);
	ASSERT(net->interrupt == NULL);

	intr = kmem_zalloc(sizeof (wrsm_interrupt_t), KM_SLEEP);
	ASSERT(intr);

	mutex_init(&intr->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&intr->resource_cv, NULL, CV_DEFAULT, NULL);

	retval = drainer_list_init(intr);
	ASSERT(retval == 0);
	if (retval) {
		mutex_destroy(&intr->mutex);
		kmem_free(intr, sizeof (wrsm_interrupt_t));
		return (retval);
	}

	/* We don't yet know the safari ids of any of our wcis... */
	for (i = 0; i < WRSM_MAX_WCIS; i++) {
		intr->wci_ids[i] = INVALID_SAFARI_ID;
	}
	intr->wci_safari_port = INVALID_SAFARI_ID;

	/* Initialize the other interrupt components */
	recvq_table_init(intr);
	service_list_init(intr, net);
	target_list_init(intr);

	net->interrupt = intr; /* Publish it! */

#ifdef DEBUG
	networks[net->cnodeid] = net;
#endif /* DEBUG */

	return (retval);
}

/* Destroy the interrupt component for this network */
void
wrsm_intr_fini(wrsm_network_t *net)
{
	wrsm_interrupt_t *intr;
	DTRC("wrsm_intr_fini");

	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;

	/* Fini all our children */
	recvq_table_fini(intr, net);

	drainer_list_fini(intr);
	target_list_fini(intr);
	service_list_fini(intr);
	cv_destroy(&intr->resource_cv);
	mutex_destroy(&intr->mutex);

	/* Remove us from the network structure */
	net->interrupt = NULL;

	/* Free the memory */
	kmem_free(intr, sizeof (wrsm_interrupt_t));

#ifdef DEBUG
	networks[net->cnodeid] = NULL;
#endif /* DEBUG */
}

/*
 * WCI Functions - Can/should these be moved to LC?
 */

/* Inform the interrupt component of a new WCI */
int
wrsm_intr_newwci(wrsm_network_t *net, lcwci_handle_t lc)
{
	int retval;
	wrsm_interrupt_t *intr;
	safari_port_t safid;
	void *arg;
	int i;
	caddr_t sram_paddr;

	DTRC("wrsm_intr_newwci");
	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;

	sram_paddr = wrsm_lc_get_sram_paddr(lc);
	safid = wrsm_lc_get_safid(lc);

	arg = (void *)&(intr->recvq_tables[0]);
	DPRINTF(INTRDBG, (CE_CONT, "dmv_add_intr(0x%08X)", safid));
	retval = dmv_add_intr(safid, wrsm_tl1_handler, arg);

	if (retval) {
		cmn_err(CE_WARN,
		    "dmv_add_intr() failed for device %d: %d",
		    safid, retval);
	}
	/* Store phys addr of cmmu sram for trap handler, and safari port id */
	mutex_enter(&intr->mutex);
	for (i = 0; i < WRSM_MAX_WCIS; i++) {
		if (intr->sram_paddr[i] == NULL) {
			intr->sram_paddr[i] = sram_paddr;
			intr->wci_ids[i] = safid;
			break;
		}
	}
	ASSERT(i < WRSM_MAX_WCIS);
	/*
	 * If we don't have a valid wci_safari_port, this must be the first
	 * WCI, so notify the targets.
	 */
	if (intr->wci_safari_port == INVALID_SAFARI_ID) {
		DPRINTF(INTRWARN, (CE_CONT, "wrsm_intr_newwci: First wci %d",
		    safid));
		intr->wci_safari_port = safid;
		target_list_readd_cpu(net);
	}

	mutex_exit(&intr->mutex);

	return (retval);
}

/* Inform the interrupt component that a WCI is going away */
void
wrsm_intr_delwci(wrsm_network_t *net, lcwci_handle_t lc)
{
	safari_port_t safid;
	caddr_t sram_paddr;
	int i;
	wrsm_interrupt_t *intr;

	DTRC("wrsm_intr_delwci");
	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;

	mutex_enter(&intr->mutex);

	/* Remove the dmv interrupt registration */
	safid = wrsm_lc_get_safid(lc);
	(void) dmv_rem_intr(safid);

	/* Clear phys addr of cmmu sram */
	sram_paddr = wrsm_lc_get_sram_paddr(lc);
	for (i = 0; i < WRSM_MAX_WCIS; i++) {
		if (intr->sram_paddr[i] == sram_paddr) {
			intr->sram_paddr[i] = NULL;
			intr->wci_ids[i] = INVALID_SAFARI_ID;
			break;
		}
	}
	/*
	 * If this was the WCI we were using for interrupt target
	 * redistribution, we need to repeat the intr_dist_cpu process
	 * for all the targets with a different WCI, if one exists.
	 */
	if (safid == intr->wci_safari_port) {
		safari_port_t new_wci = find_a_wci(intr);
		if (new_wci != INVALID_SAFARI_ID) {
			DPRINTF(INTRWARN, (CE_CONT, "wrsm_intr_delwci: "
			    "Changing golden wci from %d to %d",
			    safid, new_wci));
			intr->wci_safari_port = new_wci;
			target_list_readd_cpu(net);
		}
	}

	mutex_exit(&intr->mutex);
}

/*
 * Handler Management Functions
 */

/* Registers a handler for a specific interrupt type - rsmpi interface */
int
wrsmrsm_register_handler(
    rsm_controller_handle_t controller,
    rsm_controller_object_t *controller_obj,
    rsm_intr_t type,
    rsm_intr_hand_t func,
    rsm_intr_hand_arg_t arg,
    rsm_addr_t senders_list[],
    uint_t senders_list_length)
{
	wrsm_network_t *net = (wrsm_network_t *)controller;
	int retval;
	if (type < RSM_INTR_T_SUN_BASE) {
		retval = RSMERR_PERM_DENIED;
	} else if (net == NULL || net->interrupt == NULL) {
		retval = RSMERR_BAD_CTLR_HNDL;
	} else {
		retval = wrsm_register_handler(controller, controller_obj,
		    type, func, arg, senders_list, senders_list_length);
	}
	return (retval);
}

/* Registers a handler for a specific interrupt type - driver interface */
int
wrsm_register_handler(
    wrsm_network_t *net,
    rsm_controller_object_t *controller_obj,
    rsm_intr_t type,
    rsm_intr_hand_t func,
    rsm_intr_hand_arg_t arg,
    rsm_addr_t senders_list[],
    uint_t senders_list_length)
{
	wrsm_intr_handler_t *handler;
	wrsm_interrupt_t *intr;
	uint_t i;

	/* Assume all senders, unless a senders_list is provided */
	cnode_bitmask_t cnode_list = {
		0xffffffff, 0xffffffff,
		0xffffffff, 0xffffffff,
		0xffffffff, 0xffffffff,
		0xffffffff, 0xffffffff};
	DPRINTF(INTRTRACE, (CE_CONT, "wrsm_register_handler - ctlr %d "
	    "service id %d func 0x%p arg 0x%p", net->rsm_ctlr_id, type,
	    (void *)func, (void *)arg));

	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;

	if (type > RSM_INTR_T_USR_END) {
		return (RSMERR_PERM_DENIED);
	}
	/* If a sender's list is provided, record it */
	if (senders_list_length != 0) {
		WRSMSET_ZERO(cnode_list);
		for (i = 0; i < senders_list_length; i++) {
			if (senders_list[i] >= WRSM_MAX_CNODES) {
				return (RSMERR_UNKNOWN_RSM_ADDR);
			}
			WRSMSET_ADD(cnode_list, senders_list[i]);
		}
	}

	/* Allocate and initialize handler structure */
	handler = kmem_alloc(sizeof (wrsm_intr_handler_t), KM_SLEEP);
	handler_init(handler, func, arg, cnode_list, controller_obj);

	/* Add this handler to the list of handlers for this service */
	service_add_handler(&intr->services[type], handler);

	/* Count non-driver handlers */
	if (type > RSM_INTR_T_DRV_END) {
		mutex_enter(&intr->mutex);
		net->handler_num++;
		mutex_exit(&intr->mutex);
	}

	return (RSM_SUCCESS);
}

/* Unregisters a handler - rsmpi interface */
int
wrsmrsm_unregister_handler(
    rsm_controller_handle_t controller,
    rsm_intr_t type,
    rsm_intr_hand_t func,
    rsm_intr_hand_arg_t arg)
{
	wrsm_network_t *net = (wrsm_network_t *)controller;
	int retval;
	if (type < RSM_INTR_T_SUN_BASE) {
		retval = RSMERR_PERM_DENIED;
	} else if (net == NULL || net->interrupt == NULL) {
		retval = RSMERR_BAD_CTLR_HNDL;
	} else {
		retval = wrsm_unregister_handler(controller, type, func, arg);
	}
	return (retval);
}

/* Unregisters a handler - driver interface */
int
wrsm_unregister_handler(
    wrsm_network_t *net,
    rsm_intr_t type,
    rsm_intr_hand_t func,
    rsm_intr_hand_arg_t arg)
{
	wrsm_interrupt_t *intr;
	wrsm_intr_service_t *service;
	wrsm_intr_handler_t *handler;
	int num_unregistered_client_handlers = 0;
	int retval = RSM_SUCCESS;
	DTRC("wrsm_unregister_handler");

	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;
	service = &intr->services[type];

	if (func == NULL) {
		DPRINTF(INTRWARN, (CE_CONT, "wrsm_unregister_handler: "
		    "Unregister all handlers for service %d", type));
		/* If handler func is null, remove all handlers of that type */
		mutex_enter(&service->handler_mutex);
		handler = service->handler_list;
		while (handler) {
			wrsm_intr_handler_t *next = handler->next;
			handler_fini(handler);
			kmem_free(handler, sizeof (wrsm_intr_handler_t));
			handler = next;
			/* Update count of user handlers */
			if (type > RSM_INTR_T_DRV_END) {
				num_unregistered_client_handlers++;
			}
		}
		service->handler_list = NULL;
		mutex_exit(&service->handler_mutex);
	} else {
		handler = service_rem_handler(service, func, arg);
		if (handler) {
			handler_fini(handler);
			kmem_free(handler, sizeof (wrsm_intr_handler_t));
			/* Update count of user handlers */
			if (type > RSM_INTR_T_DRV_END) {
				num_unregistered_client_handlers = 1;
			}
		} else {
			DPRINTF(INTRERR, (CE_WARN, "wrsm_unregister_handler: "
			    "Handler not found"));
			retval = RSMERR_HANDLER_NOT_REGISTERED;
		}
	}
	mutex_enter(&intr->mutex);
	net->handler_num -= num_unregistered_client_handlers;
	mutex_exit(&intr->mutex);

	return (retval);
}

/*
 * Receive Queue Functions
 */

/* Creates a receive queue of a given type */
int
wrsm_intr_create_recvq(
    wrsm_network_t *net,
    rsm_intr_t type,
    size_t qdepth,
    wrsm_cmmu_index_t cmmu_index,
    wrsm_intr_recvq_t **recvq,
    cnodeid_t from_cnode,
    void *exportseg,
    int flags)
{
	wrsm_interrupt_t *intr;
	unsigned cmmu_mondo;
	int retval;
	int ring_size;

	DTRC("wrsm_intr_create_recvq");

	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;

	/* First, find if there's space to allocate a new recvq */
	mutex_enter(&intr->mutex);
retry:
	cmmu_mondo = recvq_table_alloc_entry(intr);
	DPRINTF(INTRDBG, (CE_CONT, "Recvq from cnode %d got cmmu_mondo = %d",
	    exportseg ? -1 : from_cnode, cmmu_mondo));
	if (cmmu_mondo <= 0) {
		WARN("wrsm_intr_create_recvq: Unable to allocate a mondo");
		if (flags & WRSM_CREATE_RECVQ_SLEEP) {
			WARN("wrsm_intr_create_recvq: waiting for resources");
			retval = cv_wait_sig(&intr->resource_cv, &intr->mutex);
			if (retval > 0) {
				goto retry;
			} else {
				/* got a signal */
				mutex_exit(&intr->mutex);
				return (EINTR);
			}
		} else {
			mutex_exit(&intr->mutex);
			return (EAGAIN);
		}
	}

	/* Create and initialize recvq structure */
	*recvq = kmem_zalloc(sizeof (wrsm_intr_recvq_t), KM_SLEEP);
	DPRINTF(INTRTRACE, (CE_CONT,
	    "created recvq 0x%p\n", (void *)*recvq));
	mutex_init(&(*recvq)->mutex, NULL, MUTEX_DRIVER, NULL);
	if (qdepth > 0) {
		/* Alloc extra space to give margin for flow ctrl */
		ring_size = qdepth  + RECVQ_HIGHWATER_MARGIN;
		(*recvq)->packet_ring_info.info.size = ring_size;
		(*recvq)->packet_ring =
			kmem_zalloc(ring_size * sizeof (wrsm_intr_packet_t),
			    KM_SLEEP);
		(*recvq)->high_water_mark = qdepth;
	}
	(*recvq)->net = net;
	(*recvq)->low_water_mark = 0; /* Force them to drain it */
	(*recvq)->sram_paddr = intr->sram_paddr;
	(*recvq)->service = &(intr->services[type]);
	(*recvq)->cmmu_mondo = cmmu_mondo;
	(*recvq)->cmmu_index = cmmu_index;
	(*recvq)->from_cnode = from_cnode;
	(*recvq)->user_interrupt = (flags & WRSM_CREATE_RECVQ_USER);
	(*recvq)->exportseg = exportseg;

	/* Get next target */
	(*recvq)->target = target_list_get_next(intr);
	/* Remember it's drainer */
	(*recvq)->drainer = (*recvq)->target->drainer;

	/* Add this recvq to target and service lists */
	target_add_recvq((*recvq)->target, *recvq);
	service_add_recvq((*recvq)->service, *recvq);

	/* Use cmmu_mondo to store recvq */
	recvq_table_set(intr, cmmu_mondo, *recvq);

	mutex_exit(&intr->mutex);

	/* Update CMMU entry to enable the interrupt. */
	recvq_cmmu_update(*recvq,
	    (flags & WRSM_CREATE_RECVQ_INVALID) ? B_TRUE : B_FALSE, B_FALSE);

	return (RSM_SUCCESS);
}

/* Destroys the receive queue */
void
wrsm_intr_destroy_recvq(wrsm_network_t *net, wrsm_intr_recvq_t *recvq)
{
	DTRC("wrsm_destroy_recvq");

	ASSERT(net);
	ASSERT(net->interrupt);
	ASSERT(recvq);

	mutex_enter(&net->interrupt->mutex);
	recvq_fini(net, recvq);
	mutex_exit(&net->interrupt->mutex);
}

/* Flushes the receive queue */
void
wrsm_intr_flush_recvq(wrsm_intr_recvq_t *recvq)
{
	DTRC("wrsm_flush_recvq");
	ASSERT(recvq);

	/*
	 * Do a cross trap to the target CPU to make sure that any
	 * in-process interrupts are complete.
	 */
	wrsmplat_xt_sync(recvq->target->cpu_id);
}

/*
 * Send Functions
 */

/*
 * Reads the CESR pointed to by p, until the not_valid flag is clear, then
 * sets the CESR to the new value. Returns EIO if the not_valid flag never
 * clears (implies the WCI is hung).
 */
#define	CESR_READ_DELAY		10 /* 10 usec */
#define	CESR_READ_RETRY_LIMIT	(1500000 / CESR_READ_DELAY) /* 1.5 sec */
#define	CESR_FAILFAST_DISABLED	0x20

#define	UINT64S_PER_BLOCK	(WRSM_CACHELINE_SIZE / sizeof (uint64_t))

static int
cesr_swap(volatile uint64_t *p, uint64_t new, uint64_t *old)
{
	uint64_t block[UINT64S_PER_BLOCK];
	wci_cluster_error_status_array_u cesr;
	uint_t i = 0;

	do {
		wrsm_blkread((void*)p, (void *)block, 1);
		cesr.val = block[0];
		if (i++ > CESR_READ_RETRY_LIMIT) {
			return (EIO);
		}
		if (cesr.bit.not_valid) {
			drv_usecwait(CESR_READ_DELAY);
		}
	} while (cesr.bit.not_valid);

	DPRINTF(INTRCESR, (CE_WARN, "cesr_swap: changing cesr from "
	    "0x%lx to 0x%lx", cesr.val, new));
	*old = cesr.val;
	/*
	 * Put new value in both half cachelines -- don't know
	 * which one will actually get stored into wci.
	 */
	block[0] = new;
	block[UINT64S_PER_BLOCK / 2] = new;
	wrsm_blkwrite((void *)block, (void *)p, 1);
	/* Read back to force flush to physical memory */
	wrsm_blkread((void *)p, (void *)block, 1);
	DPRINTF(INTRCESR, (CE_WARN, "cesr_swap: read back cesr as 0x%lx",
	    block[0]));

	return (0);
}

/* Does the send, with CESR swapping and kpreemt disabling */
static int
send(void *remote_addr, void *aligned_buf, caddr_t p_cesr)
{
	uint64_t offset;
	wci_cluster_error_status_array_u cesr_before;
	wci_cluster_error_status_array_u cesr_after;

	/*
	 * With preemption disabled, we want to clear the CESR to
	 * disable fail-fast, send the interrupt, then restore the
	 * CESR. If the CESR was set during the transaction, the
	 * interupt failed. If the error was destination CPU busy,
	 * then we should retry.
	 */
	kpreempt_disable();
	offset = ((uint64_t)remote_addr) & (PAGESIZE - 1);

	/* Read CESR and replace with a value of 0 and failfast disabled */

	wrsmplat_set_asi_cesr_id();

	if (cesr_swap((uint64_t *)(p_cesr + offset), CESR_FAILFAST_DISABLED,
	    &cesr_before.val)) {
		wrsmplat_clr_asi_cesr_id();
		kpreempt_enable();
		return (WCI_CESR_BUSY_TOO_LONG);
	}

	/* Send interrupt */
	wrsm_blkwrite(aligned_buf, remote_addr, 1);

	/* Read CESR and restore original value */
	if (cesr_swap((uint64_t *)(p_cesr + offset), cesr_before.val,
	    &cesr_after.val)) {
		wrsmplat_clr_asi_cesr_id();
		kpreempt_enable();
		return (WCI_CESR_BUSY_TOO_LONG);
	}


	wrsmplat_clr_asi_cesr_id();
	kpreempt_enable();

	return ((int)cesr_after.bit.value);
}

/*
 * wrsm_intr_send -- The parameters is_flags, is_wait and sendq_flags are
 * normally provided by wrsm_send from the sendq or is data structures.
 * To allow this function to be called from the driver, make sure that:
 *   is_flags of 0 => don't sleep
 *   sendq_flags of 0 => don't fail on full
 * Since is_wait of 0 is a valid input, the caller must provide a valid
 * value for is_wait, or WRSM_INTR_WAIT_DEFAULT to use a default driver
 * timeout.
 */
int
wrsm_intr_send(wrsm_network_t *net,
    void *remote_addr,
    cnodeid_t remote_cnode,
    void *aligned_buf,
    int is_flags,
    clock_t is_wait,
    int sendq_flags)
{
	const clock_t spin_time = 10; /* microseconds */
	const clock_t sleep_time = 20000; /* microseconds */
	const clock_t sleep_ticks = drv_usectohz(sleep_time);
	clock_t time_limit;
	int cesr;
	int retval = RSM_SUCCESS;
	const clock_t def_wait_time = drv_usectohz(90000);
	const int min_retries = 10;
	int retries = 0;

	int was_busy = 0;

	ASSERT(net);
	ASSERT(net->interrupt);

	if (is_wait == WRSM_INTR_WAIT_DEFAULT) {
		is_wait = def_wait_time;
	}

	/* Calculate time to wait when trying to send */
	time_limit = ddi_get_lbolt() + is_wait;

	DPRINTF(INTRDBG, (CE_NOTE,
	    "wrsm_blkwrite(src=0x%p, dst=0x%p) from cpu %d",
	    (void *)aligned_buf, (void *)remote_addr, CPU->cpu_id));

	/*
	 * Keep retrying until we exceed the time limit. However, even
	 * if we run out of time, we should at least make min_retries
	 * attempts before giving up.
	 */
	while ((ddi_get_lbolt() < time_limit) || (retries++ < min_retries)) {
		cesr = send(remote_addr, aligned_buf,
		    net->nodes[remote_cnode]->cesr_vaddr);

		if (cesr == WCI_CESR_INTR_DEST_BUSY) {
			was_busy++;
			/* If "inter dest busy", retry */
			retval = RSMERR_TIMEOUT;
		} else if (cesr == WCI_CESR_USER_ERROR_BIT_SET) {
			/*
			 * User error means overflow, retry unless sendq
			 * was created with full-fail flag set or no
			 * wait time was specified.
			 */
			if ((sendq_flags & RSM_INTR_SEND_Q_FULL_FAIL) ||
			    (is_wait == 0)) {
				retval = RSMERR_QUEUE_FULL;
				break;
			} else {
				/* Assume we might timeout */
				retval = RSMERR_TIMEOUT;
			}
		} else if (cesr != 0) {
			DPRINTF(INTRERR, (CE_CONT, "wrsm_intr_send: cesr=%d",
			    cesr));
			/* All other comm errors, break from retrying */
			retval = RSMERR_COMM_ERR_NOT_DELIVERED;
			break;
		} else {
			/* Success! */
			retval = RSM_SUCCESS;
			break;
		}

		/* If we got here, we've failed and may retry */
		if ((is_flags & RSM_INTR_SEND_SLEEP) &&
		    !servicing_interrupt()) {
			delay(sleep_ticks);
		} else {
			drv_usecwait(spin_time);
		}
	}

	if ((retval != RSM_SUCCESS) && was_busy)
			DPRINTF(INTRWARN, (CE_WARN,
			"wrsm_intr_send: intr dest busy %d times", was_busy));
	return (retval);
}

/* Callback from session, sets net_reset flag when session goes away */
boolean_t
wrsm_intr_sess_callback(wrsm_network_t *net, cnodeid_t cnode,
    wrsm_sess_state state)
{
	wrsm_interrupt_t *intr;
	wrsm_sendq_t *sq;
	wrsm_sendq_t *sq_next;
	wrsm_intr_recvq_t *rq;
	wrsm_intr_recvq_t *rq_next;
	DPRINTF(INTRTRACE, (CE_CONT, "wrsm_intr_sess_callback("
	    "cnode=%d, state=%d)", cnode, state));

	ASSERT(net);
	ASSERT(net->interrupt);
	intr = net->interrupt;

	if (state == SESSION_DOWN) {
		mutex_enter(&net->interrupt->mutex);
		/*
		 * Mark "net reset" on all sendq's to remote node, then
		 * unlink from sendq_list and forget about them. Could move
		 * them to a "zombie" list and free in wrsm_intr_fini.
		 */
		for (sq = intr->sendq_list[cnode]; sq; sq = sq_next) {
			sq_next = sq->next;
			sq->net_reset = B_TRUE;
			sq->next = NULL;
		}
		intr->sendq_list[cnode] = NULL;

		/* Delete all recvq's from remote node */
		for (rq = intr->recvq_list[cnode]; rq; rq = rq_next) {
			wrsm_intr_handler_t *h;
			rq_next = rq->recvq_next;
			/* Tell the handlers that the recvq is destroyed */
			for (h = rq->service->handler_list; h; h = h->next) {
				(void) handler_callback(h,
				    RSM_INTR_Q_OP_DESTROY,
				    rq->from_cnode, NULL, 0);
			}
			recvq_fini(net, rq);
		}
		intr->recvq_list[cnode] = NULL;
		mutex_exit(&net->interrupt->mutex);
	}

	return (B_TRUE);
}

/* Initializes the rsmpi portion of interrupts */
void
wrsm_intr_rsminit(wrsm_network_t *net)
{
	DTRC("wrsm_intr_rsminit");

	/* Register sendq create message handler */
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_CREATE,
	    wrsm_tl_txhandler_sessionid, msg_recvq_create);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_CREATE_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	/* Register sendq config message handler */
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_CONFIG,
	    wrsm_tl_txhandler_sessionid, msg_recvq_config);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_CONFIG_RESPONSE,
	    wrsm_tl_txhandler_sessionid, wrsm_tl_rxhandler_sessionid);

	/* Register sendq destroy message handler */
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_DESTROY,
	    wrsm_tl_txhandler_sessionid, msg_recvq_destroy);

	/* Register with Session for callbacks */
	wrsm_sess_register(net, wrsm_intr_sess_callback);
}

/* Cleans-up the rsmpi portion of interrupts */
void
wrsm_intr_rsmfini(wrsm_network_t *net)
{
	uint_t cnode;
	DTRC("wrsm_intr_rsmfini");

	ASSERT(net);
	ASSERT(net->interrupt);

	/* Unregister with session */
	wrsm_sess_unregister(net, wrsm_intr_sess_callback);

	/* Make sure everything's been cleaned up */
	for (cnode = 0; cnode < WRSM_MAX_CNODES; cnode++) {
		(void) wrsm_intr_sess_callback(net, cnode, SESSION_DOWN);
	}
	mutex_enter(&net->interrupt->mutex);

#ifdef DEBUG
	for (cnode = 0; cnode < WRSM_MAX_CNODES; cnode++) {
		/* Check sendq's are marked invalid */
		if (net->interrupt->sendq_list[cnode]) {
			DPRINTF(INTRWARN, (CE_WARN,
			    "sendq_list[%d] not empty!", cnode));
		}
		/* Make sure all recvq's have been deleted */
		if (net->interrupt->recvq_list[cnode]) {
			DPRINTF(INTRWARN, (CE_WARN,
			    "revq_list[%d] not empty!", cnode));
		}
	}
#endif /* DEBUG */

	/* Unregister sendq create message handler */
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_CREATE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_CREATE_RESPONSE,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	/* Unregister sendq destroy message handler */
	(void) wrsm_tl_add_handler(net, WRSM_MSG_INTR_RECVQ_DESTROY,
	    WRSM_TL_NO_HANDLER, WRSM_TL_NO_HANDLER);

	mutex_exit(&net->interrupt->mutex);
}

/*
 * RSMPI public functions
 */

/* Creates a send queue */
/* ARGSUSED */
int
wrsm_sendq_create(
    rsm_controller_handle_t controller,
    rsm_addr_t addr,
    rsm_intr_t service,
    rsm_intr_pri_t prio,
    size_t qdepth,
    uint_t flags,
    rsm_resource_callback_t fn,
    rsm_resource_callback_arg_t arg,
    rsm_send_q_handle_t *send_q)
{
	wrsm_network_t *net = (wrsm_network_t *)controller;
	wrsm_sendq_t *sendq;
	wrsm_raw_message_t raw_req;
	wrsm_raw_message_t raw_rsp;
	recvq_create_req_t *req = (recvq_create_req_t *)&raw_req;
	recvq_create_rsp_t *rsp = (recvq_create_rsp_t *)&raw_rsp;
	cnodeid_t dest_cnode = (cnodeid_t)addr;
	caddr_t vaddr;

	DPRINTF(INTRTRACE, (CE_CONT, "wrsm_sendq_create(addr = %d)",
	    dest_cnode));

	*send_q = NULL; /* Make sure to return NULL on error */
	ASSERT(net);
	ASSERT(net->interrupt);

	if (fn != RSM_RESOURCE_SLEEP && fn != RSM_RESOURCE_DONTWAIT) {
		DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_create: "
		    "invalid callback 0x%p", (void *)fn));
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if (addr >= WRSM_MAX_CNODES) {
		DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_create: "
		    "invalid cnode"));
		return (RSMERR_RSM_ADDR_UNREACHABLE);
	}
	req->header.message_type = WRSM_MSG_INTR_RECVQ_CREATE;
	req->service = service;
	req->prio = prio;
	req->qdepth = qdepth;

	/* Send request to remote node to create a receive queue */
	do {
		if (wrsm_tl_rpc(net, dest_cnode, (wrsm_message_t *)req,
		    (wrsm_message_t *)rsp)) {
			DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_create: "
			    "rpc failed"));
			return (RSMERR_RSM_ADDR_UNREACHABLE);
		}
		if (rsp->retval && rsp->retval !=
		    RSMERR_INSUFFICIENT_RESOURCES) {
			DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_create: "
			    "remote reject: %d", rsp->retval));
			return (RSMERR_NO_HANDLER);
		}
		if (rsp->retval == RSMERR_INSUFFICIENT_RESOURCES &&
		    fn != RSM_RESOURCE_SLEEP) {
			/* Temporary failure, but user said don't sleep */
			DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_create: "
			    "remote reject: EAGAIN"));
			return (RSMERR_INSUFFICIENT_RESOURCES);
		}
	} while (rsp->retval);

	/* Map-in interrupt page */
	if (ddi_map_regs(wrsm_ncslice_dip,
	    (uint_t)net->nodes[dest_cnode]->config->comm_ncslice,
	    &vaddr,
	    (off_t)rsp->nc_off,
	    PAGESIZE) != DDI_SUCCESS) {
		/* Send recvq_destroy message */
		wrsm_raw_message_t raw_msg;
		recvq_destroy_t *msg = (recvq_destroy_t *)&raw_msg;
		DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_create: "
		    "ddi_map_regs failed"));

		msg->header.message_type = WRSM_MSG_INTR_RECVQ_DESTROY;
		msg->qid = rsp->qid;
		msg->mondo = rsp->mondo;
		msg->service = service;
		(void) wrsm_tl_dg(net, dest_cnode, (wrsm_message_t *)msg);
		return (RSMERR_INSUFFICIENT_RESOURCES);
	}

	/* Create sendq structure and pass back result */
	sendq = kmem_zalloc(sizeof (wrsm_sendq_t), KM_SLEEP);
	mutex_init(&sendq->mutex, NULL, MUTEX_DRIVER, NULL);
	sendq->net = net;
	sendq->vaddr = vaddr;
	sendq->nc_off = rsp->nc_off;
	sendq->nc_slice = net->nodes[dest_cnode]->config->comm_ncslice;
	sendq->offset = NULL;
	sendq->qid = rsp->qid;
	sendq->mondo = rsp->mondo;
	sendq->dest_cnode = dest_cnode;
	sendq->qdepth = qdepth;
	sendq->service = service;
	sendq->flags = flags;

	/* Add sendq to linked list of sendqs */
	mutex_enter(&net->interrupt->mutex);
	sendq->next = net->interrupt->sendq_list[dest_cnode];
	net->interrupt->sendq_list[dest_cnode] = sendq;
	net->sendqs_num++;
	mutex_exit(&net->interrupt->mutex);

	*send_q = (rsm_send_q_handle_t)sendq;
	return (RSM_SUCCESS);
}

/* Reconfigure some of the attributes of an interrupt queue */
/* ARGSUSED */
int
wrsm_sendq_config(
	rsm_send_q_handle_t send_q,
	rsm_intr_pri_t prio,
	size_t qdepth,
	uint_t flags,
	rsm_resource_callback_t fn,
	rsm_resource_callback_arg_t arg)
{
	wrsm_sendq_t *sendq = (wrsm_sendq_t *)send_q;
	wrsm_network_t *net = sendq->net;
	wrsm_raw_message_t raw_req;
	wrsm_raw_message_t raw_rsp;
	recvq_config_req_t *req = (recvq_config_req_t *)&raw_req;
	recvq_config_rsp_t *rsp = (recvq_config_rsp_t *)&raw_rsp;
	cnodeid_t dest_cnode;
	int retval = RSM_SUCCESS;

	DTRC("wrsm_sendq_config");

	if (fn != RSM_RESOURCE_SLEEP && fn != RSM_RESOURCE_DONTWAIT) {
		DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_config: "
		    "invalid callback 0x%p", (void *)fn));
		return (RSMERR_CALLBACKS_NOT_SUPPORTED);
	}

	if (sendq->net_reset) {
		WARN("Attempt to sendq_config after net reset");
		return (RSMERR_CONN_ABORTED);
	}

	mutex_enter(&sendq->mutex);

	sendq->flags = flags;
	/* If fence was up, and we're getting rid of fence, then lower it */
	if (sendq->flags & RSM_INTR_SEND_Q_NO_FENCE) {
		sendq->fence_up = B_FALSE;
	}

	/* Request remote node reconfigure the receive queue */
	if (sendq->qdepth != qdepth) {
		req->header.message_type = WRSM_MSG_INTR_RECVQ_CONFIG;
		req->qid = sendq->qid;
		req->mondo = sendq->mondo;
		req->new_qdepth = qdepth;
		dest_cnode = sendq->dest_cnode;
		NOTE("   Sending recvq_config rpc to remote node");
		if (wrsm_tl_rpc(net, dest_cnode, (wrsm_message_t *)req,
		    (wrsm_message_t *)rsp)) {
			DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_config: "
			    "rpc failed"));
			retval = RSMERR_CONN_ABORTED;
		} else if (rsp->retval) {
			DPRINTF(INTRERR, (CE_WARN, "wrsm_sendq_config: "
			    "remote reject: %d", rsp->retval));
			retval = rsp->retval;
		} else {
			/* Update the qdepth */
			sendq->qdepth = qdepth;
		}
	}
	mutex_exit(&sendq->mutex);

	return (retval);
}

/* Destroys an interrupt queue, freeing all resources allocated */
/* ARGSUSED */
int
wrsm_sendq_destroy(rsm_send_q_handle_t send_q)
{
	wrsm_sendq_t *sendq = (wrsm_sendq_t *)send_q;
	wrsm_interrupt_t *intr;
	DTRC("wrsm_sendq_destroy");

	ASSERT(sendq);

	intr = sendq->net->interrupt;
	ASSERT(intr);

	mutex_enter(&intr->mutex);
	mutex_enter(&sendq->mutex);

	if (!sendq->net_reset) {
		cnodeid_t dest_cnode = sendq->dest_cnode;
		wrsm_sendq_t *sq;
		wrsm_raw_message_t raw_msg;
		recvq_destroy_t *msg = (recvq_destroy_t *)&raw_msg;

		/* Remove from sendq_list */
		sq = intr->sendq_list[dest_cnode];
		if (sq == sendq) {
			intr->sendq_list[dest_cnode] = sendq->next;
			sendq->next = NULL;
		} else while (sq && sq->next) {
			if (sq->next == sendq) {
				sq->next = sendq->next;
				sendq->next = NULL;
				break;
			}
			sq = sq->next;
		}

		/* Send message to remove node */
		msg->header.message_type = WRSM_MSG_INTR_RECVQ_DESTROY;
		msg->qid = sendq->qid;
		msg->mondo = sendq->mondo;
		msg->service = sendq->service;
		(void) wrsm_tl_dg(sendq->net, sendq->dest_cnode,
		    (wrsm_message_t *)msg);
	}
	mutex_exit(&sendq->mutex);
	sendq->net->sendqs_num--;
	mutex_exit(&intr->mutex);

	mutex_destroy(&sendq->mutex);

	ddi_unmap_regs(wrsm_ncslice_dip,
	    (uint_t)sendq->nc_slice,
	    &sendq->vaddr,
	    (off_t)sendq->nc_off,
	    PAGESIZE);
	kmem_free(sendq, sizeof (wrsm_sendq_t));

	return (RSM_SUCCESS);
}

/* Enqueues a datagram on an interrupt queue */
/* ARGSUSED */
int
wrsm_send(
	rsm_send_q_handle_t send_q,
	rsm_send_t *is,
	rsm_barrier_t *barrier)
{
	int retval;
	wrsm_sendq_t *sendq = (wrsm_sendq_t *)send_q;
	wrsm_raw_message_t raw_buf;
	uint64_t *buf = (uint64_t *)&raw_buf;
	clock_t wait_time;
	cnodeid_t dest_cnode;
	caddr_t vaddr;
	int sendq_flags;

	mutex_enter(&sendq->mutex);
	if (barrier) {
		mutex_exit(&sendq->mutex);
		return (RSMERR_BAD_BARRIER_HNDL);
	}
	if (sendq->net_reset) {
		mutex_exit(&sendq->mutex);
		return (RSMERR_CONN_ABORTED);
	}
	if (is->is_flags & RSM_INTR_SEND_LOWER_FENCE) {
		sendq->fence_up = B_FALSE;
	}
	if (sendq->fence_up) {
		mutex_exit(&sendq->mutex);
		return (RSMERR_QUEUE_FENCE_UP);
	}
	ASSERT(sendq->net->attr.attr_intr_data_size_max <=
	    (WRSM_TL_MSG_SIZE - sizeof (uint64_t)));

	if (is->is_size > sendq->net->attr.attr_intr_data_size_max) {
		mutex_exit(&sendq->mutex);
		return (RSMERR_BAD_BARRIER_HNDL);
	}

	/* Copy data to an aligned buffer */
	bcopy(is->is_data, &buf[1], is->is_size);
	buf[0] = is->is_size;

#ifdef DEBUG
	((caddr_t)(buf))[6] = sendq->net->cnodeid;
#endif /* DEBUG */

	/* Increment the offset, to take advantage of striping */
	sendq->offset = (sendq->offset + WCI_CLUSTER_STRIPE_STRIDE) &
		WCI_CLUSTER_STRIPE_MASK;

	/* If method-of-wait is SLEEP, is_wait of 0 means "wait forever" */
	wait_time = is->is_wait;
	if (wait_time == 0 && (is->is_flags & RSM_INTR_SEND_SLEEP)) {
		wait_time = INFINITY;
	}

	vaddr = sendq->vaddr + sendq->offset;
	dest_cnode = sendq->dest_cnode;
	sendq_flags = sendq->flags;

	mutex_exit(&sendq->mutex);

	/* Send the packet */
	retval = wrsm_intr_send(sendq->net,
	    vaddr,
	    dest_cnode,
	    buf,
	    is->is_flags,
	    wait_time,
	    sendq_flags);

	if (retval && !(sendq_flags & RSM_INTR_SEND_Q_NO_FENCE)) {
		sendq->fence_up = B_TRUE;
	}

	return (retval);
}
