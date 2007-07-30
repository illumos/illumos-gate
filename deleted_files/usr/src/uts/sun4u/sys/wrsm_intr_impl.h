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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_WRSM_INTR_IMPL_H
#define	_WRSM_INTR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Setting up recvq overflow */
#define	WRSM_CMMU_0_ERROR_BIT	0x2
#define	WRSM_CMMU_0_VALID	0x4000000
#define	WRSM_CMMU_0_TYPE	(2 << 24)
#define	WRSM_CMMU_0_FROMALL	(1 << 27)
#define	WRSM_CMMU_0_WRITABLE	(1 << 28)
#define	WRSM_CMMU_0_DISABLE	(WRSM_CMMU_0_ERROR_BIT | WRSM_CMMU_0_VALID | \
				WRSM_CMMU_0_TYPE | WRSM_CMMU_0_FROMALL | \
				WRSM_CMMU_0_WRITABLE)

/*
 * Recvq pointers are stored in a 2-level tree, implemented as an array of
 * pointers to an array of recvq pointers. The recvq_tables array gives access
 * to a table of 256 pointers. Each entry in recvq_tables will remain NULL
 * until all the entries in all the existing tables are used, and a new
 * table needs to be allocated. Tables will never be deleted to eliminate the
 * need to lock a table from a TL1 interrupt. Given a 16-bit mondo vector
 * argument, the macro MONDOARG2TABLE generates the index into recvq_tables,
 * while the macro MONDOARG2TABLEINDEX generates the index into the selected
 * table, which provides the recvq pointer.
 *
 *
 *       recvq_tables[256]
 *        _____________________________..__________
 *       |0  |1  |2  |3  |4  |5  |6  |     |254|255|
 *       | * |nul|nul|nul|nul|nul|nul|     |nul|nul|
 *       |_|_|___|___|___|___|___|___|_..__|___|___|
 *         |
 *         | table[256]
 *        _V_
 *       |0  |
 *       | *-+--> recvq with mondo arg 0
 *       |___|
 *       |1  |
 *       | *-+--> recvq with mondo arg 1
 *       |___|
 *       |2  |
 *       |nul|
 *       |___|
 *       |   |
 *       ~   ~
 *       |   |
 *       |___|
 *       |255|
 *       |nul|
 *       |___|
 *
 */
#define	WRSM_INTR_RECVQ_TABLE_SIZE	256
#define	WRSM_INTR_RECVQ_TABLES		256
#define	WRSM_INTR_TABLE_MASK		0xff
#define	WRSM_INTR_TABLE_SHIFT		8
#define	WRSM_INTR_INDEX_MASK		0xff
#define	WRSM_INTR_INDEX_SHIFT		0

/* Values for the PSL when it is empty */

/* Empty, but softint is active */
#define	WRSM_INTR_PSL_EMPTY		(wrsm_intr_recvq_t *)2
/* Empty and no softint running; can't cast, as used in wrsm_trap.s */
#define	WRSM_INTR_PSL_IDLE		1


#define	WRSM_MONDO2TABLE(m) \
	(((m) >> WRSM_INTR_TABLE_SHIFT) & WRSM_INTR_TABLE_MASK)
#define	WRSM_MONDO2INDEX(m) \
	(((m) >> WRSM_INTR_INDEX_SHIFT) & WRSM_INTR_INDEX_MASK)

/* Each table array contains pointers to WRSM_INTR_RECVQ_TABLES tables */
#define	WRSM_INTR_RECVQ_TABLES_ARRAY_SIZE \
	(WRSM_INTR_RECVQ_TABLES * sizeof (void *))

#define	WRSM_INTR_PACKET_SIZE	64

#ifndef _ASM

/*
 * Receive Queue structures
 */
typedef struct __rsm_send_q_handle wrsm_sendq_t;

typedef uint64_t wrsm_intr_packet_t[WRSM_INTR_PACKET_SIZE/sizeof (uint64_t)];

/* Describes an interrupt drainer (software interrupt thread) */
typedef struct wrsm_intr_drainer {
	uint64_t drainer_inum;	/* Softint vector for drainer */
	struct wrsm_intr_recvq *drainer_psl;
	struct wrsm_intr_drainer *next; /* Next in circular list */
} wrsm_intr_drainer_t;

/* Describes an interrupt target CPU */
typedef struct wrsm_intr_target {
	processorid_t cpu_id;
	struct wrsm_intr_recvq *recvq_list;
	wrsm_intr_drainer_t *drainer;
	uint32_t index;
	int intr_dist_mondo;
	struct wrsm_intr_target *next; /* Next in circular list */
} wrsm_intr_target_t;

/* An element in a linked-list of intr handlers, part of wrsm_intr_service */
typedef struct wrsm_intr_handler {
	rsm_intr_hand_t func;
	rsm_intr_hand_arg_t arg;
	rsm_controller_object_t *controller_obj;
	cnode_bitmask_t cnodes;
	struct wrsm_intr_handler *next;
} wrsm_intr_handler_t;

/* Describes an interrupt service, including list of handlers and a recvq */
typedef struct wrsm_intr_service {
	wrsm_network_t *net;
	rsm_intr_t type;
	wrsm_intr_handler_t *handler_list;
	kmutex_t handler_mutex; /* Protects access to handler_list */
	struct wrsm_intr_recvq *recvq_list;
	kmutex_t recvq_mutex;   /* Protects access to recvq_list */
} wrsm_intr_service_t;

/* State of packet ring. Must be 64-bits for casx */
typedef struct {
	uint16_t lock;	/* If non-zero, trap is running */
	uint16_t head;	/* Next available packet */
	uint16_t tail;	/* Last consumed packet */
	uint16_t size;	/* Size, in packets */
} wrsm_intr_packet_ring_info_t;

typedef union {
	wrsm_intr_packet_ring_info_t info;
	uint64_t val;
} wrsm_intr_packet_ring_union_t;

/* The receive queue structure */
struct wrsm_intr_recvq {
	wrsm_intr_packet_t *packet_ring; /* Pointer to packet ring */
	wrsm_intr_packet_ring_union_t packet_ring_info;
	uint32_t high_water_mark;    	/* If head-tail>hwm, set user_err */
	uint32_t low_water_mark;	/* If head-tail<lwm, clear user_err */
	caddr_t *sram_paddr;		/* Points to array of WCI sram addr */

	boolean_t in_use;
	boolean_t delete_me;

	uint_t cmmu_mondo;
	wrsm_cmmu_index_t cmmu_index;
	cnodeid_t from_cnode;

	wrsm_intr_drainer_t *drainer;	/* Drainer of this recvq */
	wrsm_intr_target_t *target;	/* Target CPU of this recvq */
	wrsm_intr_service_t *service;	/* Service for this recvq */

	/* Pointers for various linked lists */
	struct wrsm_intr_recvq *service_next;
	struct wrsm_intr_recvq *target_next;
	struct wrsm_intr_recvq *drainer_next;
	struct wrsm_intr_recvq *recvq_next;

	boolean_t user_interrupt;
	void *exportseg;		/* info for small puts */
	wrsm_cmmu_tuple_t *tuples;	/* used for remote recvq destroys */
	kmutex_t mutex;

	wrsm_network_t *net;
	/* count of how often high-water mark has been reached */
	uint64_t high_water_count;
};

/*
 * Used to map a DMV argument (16-bits) to a recvq struct pointer. The
 * The wrsm_interrupt_t structure contains an array of 256 pointers to
 * recvq_table, which contains 256 recvq pointers. Use the macros
 * MONDOARG2TABLE to get the table pointer from the wrsm_interrupt structure,
 * the the macro MONDOARG2TABLEINDEX to index into the wrsm_intr_recvq_table
 * to select the correct recvq pointer.
 */
typedef wrsm_intr_recvq_t *wrsm_intr_recvq_table_t[WRSM_INTR_RECVQ_TABLE_SIZE];

/* The sendq structure */
struct __rsm_send_q_handle {
	wrsm_network_t *net;
	caddr_t vaddr;
	uint_t nc_slice;
	off_t nc_off;
	uint_t offset;
	uint64_t qid;
	uint_t mondo;
	kmutex_t mutex;
	cnodeid_t dest_cnode;
	size_t qdepth;
	rsm_intr_t service;
	int flags;
	boolean_t net_reset;
	boolean_t fence_up;
	wrsm_sendq_t *next;
};

/*
 * Interrupt Structure part of wrsm_network_t
 */
struct wrsm_interrupt {
	wrsm_intr_recvq_table_t *recvq_tables[WRSM_INTR_RECVQ_TABLES];
	wrsm_intr_service_t services[WRSM_INTR_TYPE_MAX];
	wrsm_intr_drainer_t *drainers;		/* Circular list of drainers */
	wrsm_intr_target_t *targets;		/* Circular list of targets */
	wrsm_intr_recvq_t *recvq_list[WRSM_MAX_CNODES];	/* List of recvqs */
	wrsm_sendq_t *sendq_list[WRSM_MAX_CNODES]; /* List of sendq's */
	kmutex_t mutex; /* Take before any other interrupt locks */
	kcondvar_t resource_cv;
	safari_port_t wci_safari_port; /* Sample WCI used for DMV inums */
	/*
	 * The following arrays is used for flow control. If the trap
	 * handler detects a high water condition on a recvq, it must
	 * set the user_error flag in that recvq's cmmu for all WCIs
	 * (actually, it's sufficient to set the cmmu entry to valid
	 * and user_error). To do that, it must know the address of
	 * the sram. The array cmmu_paddr contains the physical address
	 * of the CMMU entry in sram (or NULL) for every WCI in this
	 * controller.
	 */
	caddr_t sram_paddr[WRSM_MAX_WCIS];
	safari_port_t wci_ids[WRSM_MAX_WCIS];
};

/*
 * Local Function Prototypes
 */
static void handler_init(wrsm_intr_handler_t *, rsm_intr_hand_t,
    rsm_intr_hand_arg_t, cnode_bitmask_t, rsm_controller_object_t *);
static void handler_fini(wrsm_intr_handler_t *);
static rsm_intr_hand_ret_t handler_callback(wrsm_intr_handler_t *,
    rsm_intr_q_op_t q_op, cnodeid_t, void *, size_t);

static void service_init(wrsm_intr_service_t *, wrsm_network_t *, rsm_intr_t);
static void service_fini(wrsm_intr_service_t *);
static void service_add_recvq(wrsm_intr_service_t *, wrsm_intr_recvq_t *);
static void service_rem_recvq(wrsm_intr_service_t *, wrsm_intr_recvq_t *);
static void service_add_handler(wrsm_intr_service_t *, wrsm_intr_handler_t *);
static wrsm_intr_handler_t *service_rem_handler(wrsm_intr_service_t *,
    rsm_intr_hand_t, rsm_intr_hand_arg_t);
static void service_callback(wrsm_intr_service_t *, void *, size_t, cnodeid_t);

static void service_list_init(wrsm_interrupt_t *, wrsm_network_t *);
static void service_list_fini(wrsm_interrupt_t *);

static void target_init(wrsm_intr_target_t *, wrsm_intr_drainer_t *, uint32_t);
static void target_fini(wrsm_intr_target_t *);
static void target_readd_cpu(wrsm_network_t *, wrsm_intr_target_t *);
static void target_retarget(wrsm_network_t *, wrsm_intr_target_t *);
static void target_add_recvq(wrsm_intr_target_t *, wrsm_intr_recvq_t *);
static void target_rem_recvq(wrsm_intr_target_t *, wrsm_intr_recvq_t *);
static void target_print(wrsm_intr_target_t *);

static void target_list_init(wrsm_interrupt_t *);
static void target_list_fini(wrsm_interrupt_t *);
static void target_list_readd_cpu(wrsm_network_t *net);
static wrsm_intr_target_t *target_list_get_next(wrsm_interrupt_t *);
static void target_list_print(wrsm_interrupt_t *);

static int  drainer_init(wrsm_intr_drainer_t *);
static void drainer_fini(wrsm_intr_drainer_t *);
static uint_t drainer_handler(caddr_t arg);
static void drainer_print(wrsm_intr_drainer_t *);

static int  drainer_list_init(wrsm_interrupt_t *);
static void drainer_list_fini(wrsm_interrupt_t *);
static wrsm_intr_drainer_t *drainer_list_get_next(wrsm_interrupt_t *);
static void drainer_list_print(wrsm_interrupt_t *);

static void recvq_fini(wrsm_network_t *, wrsm_intr_recvq_t *);
static size_t recvq_get_packet(wrsm_intr_recvq_t *, wrsm_intr_packet_t,
    uint32_t *num_packets);
static void recvq_callback(wrsm_intr_recvq_t *);
static void recvq_print(wrsm_intr_recvq_t *);

static void recvq_table_init(wrsm_interrupt_t *);
static void recvq_table_fini(wrsm_interrupt_t *, wrsm_network_t *);
static void recvq_table_alloc_table(wrsm_interrupt_t *, unsigned table);
static int  recvq_table_alloc_entry(wrsm_interrupt_t *);
static void recvq_table_free_entry(wrsm_interrupt_t *, int cmmu_mondo);
static void recvq_table_set(wrsm_interrupt_t *, int pos, wrsm_intr_recvq_t *);
static void recvq_table_print(wrsm_interrupt_t *);

extern void wrsm_tl1_handler();


#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_INTR_IMPL_H */
