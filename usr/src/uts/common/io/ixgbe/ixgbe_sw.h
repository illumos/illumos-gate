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
 * Copyright(c) 2007-2010 Intel Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013 Saso Kiselkov. All rights reserved.
 */

#ifndef	_IXGBE_SW_H
#define	_IXGBE_SW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/sdt.h>
#include <sys/ethernet.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/netlb.h>
#include <sys/random.h>
#include <inet/common.h>
#include <inet/tcp.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/bitmap.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/disp.h>
#include <sys/fm/io/ddi.h>
#include "ixgbe_api.h"

#define	MODULE_NAME			"ixgbe"	/* module name */

#define	IXGBE_FAILURE			DDI_FAILURE

#define	IXGBE_UNKNOWN			0x00
#define	IXGBE_INITIALIZED		0x01
#define	IXGBE_STARTED			0x02
#define	IXGBE_SUSPENDED			0x04
#define	IXGBE_STALL			0x08
#define	IXGBE_OVERTEMP			0x20
#define	IXGBE_INTR_ADJUST		0x40
#define	IXGBE_ERROR			0x80

#define	MAX_NUM_UNICAST_ADDRESSES 	0x80
#define	MAX_NUM_MULTICAST_ADDRESSES 	0x1000
#define	IXGBE_INTR_NONE			0
#define	IXGBE_INTR_MSIX			1
#define	IXGBE_INTR_MSI			2
#define	IXGBE_INTR_LEGACY		3

#define	IXGBE_POLL_NULL			-1

#define	MAX_COOKIE			18
#define	MIN_NUM_TX_DESC			2

#define	IXGBE_TX_DESC_LIMIT		32	/* tx desc limitation	*/

#define	IXGBE_ADAPTER_REGSET		1	/* map adapter registers */

#define	IXGBE_RX_STOPPED		0x1

#define	IXGBE_PKG_BUF_16k		16384

/*
 * MAX_xx_QUEUE_NUM and MAX_INTR_VECTOR values need to be the maximum of all
 * supported silicon types.
 */
#define	MAX_TX_QUEUE_NUM		128
#define	MAX_RX_QUEUE_NUM		128
#define	MAX_INTR_VECTOR			64

/*
 * Maximum values for user configurable parameters
 */
#define	MAX_TX_RING_SIZE		4096
#define	MAX_RX_RING_SIZE		4096

#define	MAX_RX_LIMIT_PER_INTR		4096

#define	MAX_RX_COPY_THRESHOLD		9216
#define	MAX_TX_COPY_THRESHOLD		9216
#define	MAX_TX_RECYCLE_THRESHOLD	DEFAULT_TX_RING_SIZE
#define	MAX_TX_OVERLOAD_THRESHOLD	DEFAULT_TX_RING_SIZE
#define	MAX_TX_RESCHED_THRESHOLD	DEFAULT_TX_RING_SIZE

/*
 * Minimum values for user configurable parameters
 */
#define	MIN_TX_RING_SIZE		64
#define	MIN_RX_RING_SIZE		64

#define	MIN_MTU				ETHERMIN
#define	MIN_RX_LIMIT_PER_INTR		16
#define	MIN_TX_COPY_THRESHOLD		0
#define	MIN_RX_COPY_THRESHOLD		0
#define	MIN_TX_RECYCLE_THRESHOLD	MIN_NUM_TX_DESC
#define	MIN_TX_OVERLOAD_THRESHOLD	MIN_NUM_TX_DESC
#define	MIN_TX_RESCHED_THRESHOLD	MIN_NUM_TX_DESC

/*
 * Default values for user configurable parameters
 */
#define	DEFAULT_TX_RING_SIZE		1024
#define	DEFAULT_RX_RING_SIZE		1024

#define	DEFAULT_MTU			ETHERMTU
#define	DEFAULT_RX_LIMIT_PER_INTR	256
#define	DEFAULT_RX_COPY_THRESHOLD	128
#define	DEFAULT_TX_COPY_THRESHOLD	512
#define	DEFAULT_TX_RECYCLE_THRESHOLD	(MAX_COOKIE + 1)
#define	DEFAULT_TX_OVERLOAD_THRESHOLD	MIN_NUM_TX_DESC
#define	DEFAULT_TX_RESCHED_THRESHOLD	128
#define	DEFAULT_FCRTH			0x20000
#define	DEFAULT_FCRTL			0x10000
#define	DEFAULT_FCPAUSE			0xFFFF

#define	DEFAULT_TX_HCKSUM_ENABLE	B_TRUE
#define	DEFAULT_RX_HCKSUM_ENABLE	B_TRUE
#define	DEFAULT_LSO_ENABLE		B_TRUE
#define	DEFAULT_LRO_ENABLE		B_FALSE
#define	DEFAULT_MR_ENABLE		B_TRUE
#define	DEFAULT_TX_HEAD_WB_ENABLE	B_TRUE
#define	DEFAULT_RELAX_ORDER_ENABLE	B_TRUE
#define	DEFAULT_ALLOW_UNSUPPORTED_SFP	B_FALSE

#define	IXGBE_LSO_MAXLEN		65535

#define	TX_DRAIN_TIME			200
#define	RX_DRAIN_TIME			200

#define	STALL_WATCHDOG_TIMEOUT		8	/* 8 seconds */
#define	MAX_LINK_DOWN_TIMEOUT		8	/* 8 seconds */

#define	IXGBE_CYCLIC_PERIOD		(1000000000)	/* 1s */

/*
 * Extra register bit masks for 82598
 */
#define	IXGBE_PCS1GANA_FDC	0x20
#define	IXGBE_PCS1GANLP_LPFD	0x20
#define	IXGBE_PCS1GANLP_LPHD	0x40

/*
 * Defined for IP header alignment.
 */
#define	IPHDR_ALIGN_ROOM		2

/*
 * Bit flags for attach_progress
 */
#define	ATTACH_PROGRESS_PCI_CONFIG	0x0001	/* PCI config setup */
#define	ATTACH_PROGRESS_REGS_MAP	0x0002	/* Registers mapped */
#define	ATTACH_PROGRESS_PROPS		0x0004	/* Properties initialized */
#define	ATTACH_PROGRESS_ALLOC_INTR	0x0008	/* Interrupts allocated */
#define	ATTACH_PROGRESS_ALLOC_RINGS	0x0010	/* Rings allocated */
#define	ATTACH_PROGRESS_ADD_INTR	0x0020	/* Intr handlers added */
#define	ATTACH_PROGRESS_LOCKS		0x0040	/* Locks initialized */
#define	ATTACH_PROGRESS_INIT		0x0080	/* Device initialized */
#define	ATTACH_PROGRESS_STATS		0x0200	/* Kstats created */
#define	ATTACH_PROGRESS_MAC		0x0800	/* MAC registered */
#define	ATTACH_PROGRESS_ENABLE_INTR	0x1000	/* DDI interrupts enabled */
#define	ATTACH_PROGRESS_FM_INIT		0x2000	/* FMA initialized */
#define	ATTACH_PROGRESS_SFP_TASKQ	0x4000	/* SFP taskq created */
#define	ATTACH_PROGRESS_LINK_TIMER	0x8000	/* link check timer */
#define	ATTACH_PROGRESS_OVERTEMP_TASKQ	0x10000 /* Over-temp taskq created */

#define	PROP_DEFAULT_MTU		"default_mtu"
#define	PROP_FLOW_CONTROL		"flow_control"
#define	PROP_TX_QUEUE_NUM		"tx_queue_number"
#define	PROP_TX_RING_SIZE		"tx_ring_size"
#define	PROP_RX_QUEUE_NUM		"rx_queue_number"
#define	PROP_RX_RING_SIZE		"rx_ring_size"
#define	PROP_RX_GROUP_NUM		"rx_group_number"

#define	PROP_INTR_FORCE			"intr_force"
#define	PROP_TX_HCKSUM_ENABLE		"tx_hcksum_enable"
#define	PROP_RX_HCKSUM_ENABLE		"rx_hcksum_enable"
#define	PROP_LSO_ENABLE			"lso_enable"
#define	PROP_LRO_ENABLE			"lro_enable"
#define	PROP_MR_ENABLE			"mr_enable"
#define	PROP_RELAX_ORDER_ENABLE		"relax_order_enable"
#define	PROP_TX_HEAD_WB_ENABLE		"tx_head_wb_enable"
#define	PROP_TX_COPY_THRESHOLD		"tx_copy_threshold"
#define	PROP_TX_RECYCLE_THRESHOLD	"tx_recycle_threshold"
#define	PROP_TX_OVERLOAD_THRESHOLD	"tx_overload_threshold"
#define	PROP_TX_RESCHED_THRESHOLD	"tx_resched_threshold"
#define	PROP_RX_COPY_THRESHOLD		"rx_copy_threshold"
#define	PROP_RX_LIMIT_PER_INTR		"rx_limit_per_intr"
#define	PROP_INTR_THROTTLING		"intr_throttling"
#define	PROP_FM_CAPABLE			"fm_capable"
#define	PROP_ALLOW_UNSUPPORTED_SFP	"allow_unsupported_sfp"

#define	IXGBE_LB_NONE			0
#define	IXGBE_LB_EXTERNAL		1
#define	IXGBE_LB_INTERNAL_MAC		2
#define	IXGBE_LB_INTERNAL_PHY		3
#define	IXGBE_LB_INTERNAL_SERDES	4

/*
 * capability/feature flags
 * Flags named _CAPABLE are set when the NIC hardware is capable of the feature.
 * Separately, the flag named _ENABLED is set when the feature is enabled.
 */
#define	IXGBE_FLAG_DCA_ENABLED		(u32)(1)
#define	IXGBE_FLAG_DCA_CAPABLE		(u32)(1 << 1)
#define	IXGBE_FLAG_DCB_ENABLED		(u32)(1 << 2)
#define	IXGBE_FLAG_DCB_CAPABLE		(u32)(1 << 4)
#define	IXGBE_FLAG_RSS_ENABLED		(u32)(1 << 4)
#define	IXGBE_FLAG_RSS_CAPABLE		(u32)(1 << 5)
#define	IXGBE_FLAG_VMDQ_CAPABLE		(u32)(1 << 6)
#define	IXGBE_FLAG_VMDQ_ENABLED		(u32)(1 << 7)
#define	IXGBE_FLAG_FAN_FAIL_CAPABLE	(u32)(1 << 8)
#define	IXGBE_FLAG_RSC_CAPABLE		(u32)(1 << 9)
#define	IXGBE_FLAG_SFP_PLUG_CAPABLE	(u32)(1 << 10)
#define	IXGBE_FLAG_TEMP_SENSOR_CAPABLE	(u32)(1 << 11)

/*
 * Classification mode
 */
#define	IXGBE_CLASSIFY_NONE		0
#define	IXGBE_CLASSIFY_RSS		1
#define	IXGBE_CLASSIFY_VMDQ		2
#define	IXGBE_CLASSIFY_VMDQ_RSS		3

/* adapter-specific info for each supported device type */
typedef struct adapter_info {
	uint32_t	max_rx_que_num; /* maximum number of rx queues */
	uint32_t	min_rx_que_num; /* minimum number of rx queues */
	uint32_t	def_rx_que_num; /* default number of rx queues */
	uint32_t	max_rx_grp_num; /* maximum number of rx groups */
	uint32_t	min_rx_grp_num; /* minimum number of rx groups */
	uint32_t	def_rx_grp_num; /* default number of rx groups */
	uint32_t	max_tx_que_num;	/* maximum number of tx queues */
	uint32_t	min_tx_que_num;	/* minimum number of tx queues */
	uint32_t	def_tx_que_num;	/* default number of tx queues */
	uint32_t	max_mtu;	/* maximum MTU size */
	/*
	 * Interrupt throttling is in unit of 256 nsec
	 */
	uint32_t	max_intr_throttle; /* maximum interrupt throttle */
	uint32_t	min_intr_throttle; /* minimum interrupt throttle */
	uint32_t	def_intr_throttle; /* default interrupt throttle */

	uint32_t	max_msix_vect;	/* maximum total msix vectors */
	uint32_t	max_ring_vect;	/* maximum number of ring vectors */
	uint32_t	max_other_vect;	/* maximum number of other vectors */
	uint32_t	other_intr;	/* "other" interrupt types handled */
	uint32_t	other_gpie;	/* "other" interrupt types enabling */
	uint32_t	flags;		/* capability flags */
} adapter_info_t;

/* bits representing all interrupt types other than tx & rx */
#define	IXGBE_OTHER_INTR	0x3ff00000
#define	IXGBE_82599_OTHER_INTR	0x86100000

enum ioc_reply {
	IOC_INVAL = -1,	/* bad, NAK with EINVAL */
	IOC_DONE, 	/* OK, reply sent */
	IOC_ACK,	/* OK, just send ACK */
	IOC_REPLY	/* OK, just send reply */
};

#define	DMA_SYNC(area, flag)	((void) ddi_dma_sync((area)->dma_handle, \
				    0, 0, (flag)))

/*
 * Defined for ring index operations
 * ASSERT(index < limit)
 * ASSERT(step < limit)
 * ASSERT(index1 < limit)
 * ASSERT(index2 < limit)
 */
#define	NEXT_INDEX(index, step, limit)	(((index) + (step)) < (limit) ? \
	(index) + (step) : (index) + (step) - (limit))
#define	PREV_INDEX(index, step, limit)	((index) >= (step) ? \
	(index) - (step) : (index) + (limit) - (step))
#define	OFFSET(index1, index2, limit)	((index1) <= (index2) ? \
	(index2) - (index1) : (index2) + (limit) - (index1))

#define	LINK_LIST_INIT(_LH)	\
	(_LH)->head = (_LH)->tail = NULL

#define	LIST_GET_HEAD(_LH)	((single_link_t *)((_LH)->head))

#define	LIST_POP_HEAD(_LH)	\
	(single_link_t *)(_LH)->head; \
	{ \
		if ((_LH)->head != NULL) { \
			(_LH)->head = (_LH)->head->link; \
			if ((_LH)->head == NULL) \
				(_LH)->tail = NULL; \
		} \
	}

#define	LIST_GET_TAIL(_LH)	((single_link_t *)((_LH)->tail))

#define	LIST_PUSH_TAIL(_LH, _E)	\
	if ((_LH)->tail != NULL) { \
		(_LH)->tail->link = (single_link_t *)(_E); \
		(_LH)->tail = (single_link_t *)(_E); \
	} else { \
		(_LH)->head = (_LH)->tail = (single_link_t *)(_E); \
	} \
	(_E)->link = NULL;

#define	LIST_GET_NEXT(_LH, _E)		\
	(((_LH)->tail == (single_link_t *)(_E)) ? \
	NULL : ((single_link_t *)(_E))->link)


typedef struct single_link {
	struct single_link	*link;
} single_link_t;

typedef struct link_list {
	single_link_t		*head;
	single_link_t		*tail;
} link_list_t;

/*
 * Property lookups
 */
#define	IXGBE_PROP_EXISTS(d, n)	ddi_prop_exists(DDI_DEV_T_ANY, (d), \
				    DDI_PROP_DONTPASS, (n))
#define	IXGBE_PROP_GET_INT(d, n)	ddi_prop_get_int(DDI_DEV_T_ANY, (d), \
				    DDI_PROP_DONTPASS, (n), -1)


typedef union ixgbe_ether_addr {
	struct {
		uint32_t	high;
		uint32_t	low;
	} reg;
	struct {
		uint8_t		set;
		uint8_t		group_index;
		uint8_t		addr[ETHERADDRL];
	} mac;
} ixgbe_ether_addr_t;

typedef enum {
	USE_NONE,
	USE_COPY,
	USE_DMA
} tx_type_t;

typedef struct ixgbe_tx_context {
	uint32_t		hcksum_flags;
	uint32_t		ip_hdr_len;
	uint32_t		mac_hdr_len;
	uint32_t		l4_proto;
	uint32_t		mss;
	uint32_t		l4_hdr_len;
	boolean_t		lso_flag;
} ixgbe_tx_context_t;

/*
 * Hold address/length of each DMA segment
 */
typedef struct sw_desc {
	uint64_t		address;
	size_t			length;
} sw_desc_t;

/*
 * Handles and addresses of DMA buffer
 */
typedef struct dma_buffer {
	caddr_t			address;	/* Virtual address */
	uint64_t		dma_address;	/* DMA (Hardware) address */
	ddi_acc_handle_t	acc_handle;	/* Data access handle */
	ddi_dma_handle_t	dma_handle;	/* DMA handle */
	size_t			size;		/* Buffer size */
	size_t			len;		/* Data length in the buffer */
} dma_buffer_t;

/*
 * Tx Control Block
 */
typedef struct tx_control_block {
	single_link_t		link;
	uint32_t		last_index; /* last descriptor of the pkt */
	uint32_t		frag_num;
	uint32_t		desc_num;
	mblk_t			*mp;
	tx_type_t		tx_type;
	ddi_dma_handle_t	tx_dma_handle;
	dma_buffer_t		tx_buf;
	sw_desc_t		desc[MAX_COOKIE];
} tx_control_block_t;

/*
 * RX Control Block
 */
typedef struct rx_control_block {
	mblk_t			*mp;
	uint32_t		ref_cnt;
	dma_buffer_t		rx_buf;
	frtn_t			free_rtn;
	struct ixgbe_rx_data	*rx_data;
	int			lro_next;	/* Index of next rcb */
	int			lro_prev;	/* Index of previous rcb */
	boolean_t		lro_pkt;	/* Flag for LRO rcb */
} rx_control_block_t;

/*
 * Software Data Structure for Tx Ring
 */
typedef struct ixgbe_tx_ring {
	uint32_t		index;	/* Ring index */
	uint32_t		intr_vector;	/* Interrupt vector index */
	uint32_t		vect_bit;	/* vector's bit in register */

	/*
	 * Mutexes
	 */
	kmutex_t		tx_lock;
	kmutex_t		recycle_lock;
	kmutex_t		tcb_head_lock;
	kmutex_t		tcb_tail_lock;

	/*
	 * Tx descriptor ring definitions
	 */
	dma_buffer_t		tbd_area;
	union ixgbe_adv_tx_desc	*tbd_ring;
	uint32_t		tbd_head; /* Index of next tbd to recycle */
	uint32_t		tbd_tail; /* Index of next tbd to transmit */
	uint32_t		tbd_free; /* Number of free tbd */

	/*
	 * Tx control block list definitions
	 */
	tx_control_block_t	*tcb_area;
	tx_control_block_t	**work_list;
	tx_control_block_t	**free_list;
	uint32_t		tcb_head; /* Head index of free list */
	uint32_t		tcb_tail; /* Tail index of free list */
	uint32_t		tcb_free; /* Number of free tcb in free list */

	uint32_t		*tbd_head_wb; /* Head write-back */
	uint32_t		(*tx_recycle)(struct ixgbe_tx_ring *);

	/*
	 * s/w context structure for TCP/UDP checksum offload
	 * and LSO.
	 */
	ixgbe_tx_context_t	tx_context;

	/*
	 * Tx ring settings and status
	 */
	uint32_t		ring_size; /* Tx descriptor ring size */
	uint32_t		free_list_size;	/* Tx free list size */

	boolean_t		reschedule;
	uint32_t		recycle_fail;
	uint32_t		stall_watchdog;

#ifdef IXGBE_DEBUG
	/*
	 * Debug statistics
	 */
	uint32_t		stat_overload;
	uint32_t		stat_fail_no_tbd;
	uint32_t		stat_fail_no_tcb;
	uint32_t		stat_fail_dma_bind;
	uint32_t		stat_reschedule;
	uint32_t		stat_break_tbd_limit;
	uint32_t		stat_lso_header_fail;
#endif
	uint64_t		stat_obytes;
	uint64_t		stat_opackets;

	mac_ring_handle_t	ring_handle;

	/*
	 * Pointer to the ixgbe struct
	 */
	struct ixgbe		*ixgbe;
} ixgbe_tx_ring_t;

/*
 * Software Receive Ring
 */
typedef struct ixgbe_rx_data {
	kmutex_t		recycle_lock;	/* Recycle lock, for rcb_tail */

	/*
	 * Rx descriptor ring definitions
	 */
	dma_buffer_t		rbd_area;	/* DMA buffer of rx desc ring */
	union ixgbe_adv_rx_desc	*rbd_ring;	/* Rx desc ring */
	uint32_t		rbd_next;	/* Index of next rx desc */

	/*
	 * Rx control block list definitions
	 */
	rx_control_block_t	*rcb_area;
	rx_control_block_t	**work_list;	/* Work list of rcbs */
	rx_control_block_t	**free_list;	/* Free list of rcbs */
	uint32_t		rcb_head;	/* Index of next free rcb */
	uint32_t		rcb_tail;	/* Index to put recycled rcb */
	uint32_t		rcb_free;	/* Number of free rcbs */

	/*
	 * Rx sw ring settings and status
	 */
	uint32_t		ring_size;	/* Rx descriptor ring size */
	uint32_t		free_list_size;	/* Rx free list size */

	uint32_t		rcb_pending;
	uint32_t		flag;

	uint32_t		lro_num;	/* Number of rcbs of one LRO */
	uint32_t		lro_first;	/* Index of first LRO rcb */

	struct ixgbe_rx_ring	*rx_ring;	/* Pointer to rx ring */
} ixgbe_rx_data_t;

/*
 * Software Data Structure for Rx Ring
 */
typedef struct ixgbe_rx_ring {
	uint32_t		index;		/* Ring index */
	uint32_t		group_index;	/* Group index */
	uint32_t		hw_index;	/* h/w ring index */
	uint32_t		intr_vector;	/* Interrupt vector index */
	uint32_t		vect_bit;	/* vector's bit in register */

	ixgbe_rx_data_t		*rx_data;	/* Rx software ring */

	kmutex_t		rx_lock;	/* Rx access lock */

#ifdef IXGBE_DEBUG
	/*
	 * Debug statistics
	 */
	uint32_t		stat_frame_error;
	uint32_t		stat_cksum_error;
	uint32_t		stat_exceed_pkt;
#endif
	uint64_t		stat_rbytes;
	uint64_t		stat_ipackets;

	mac_ring_handle_t	ring_handle;
	uint64_t		ring_gen_num;

	struct ixgbe		*ixgbe;		/* Pointer to ixgbe struct */
} ixgbe_rx_ring_t;
/*
 * Software Receive Ring Group
 */
typedef struct ixgbe_rx_group {
	uint32_t		index;		/* Group index */
	mac_group_handle_t	group_handle;   /* call back group handle */
	struct ixgbe		*ixgbe;		/* Pointer to ixgbe struct */
} ixgbe_rx_group_t;

/*
 * structure to map interrupt cleanup to msi-x vector
 */
typedef struct ixgbe_intr_vector {
	struct ixgbe *ixgbe;	/* point to my adapter */
	ulong_t rx_map[BT_BITOUL(MAX_RX_QUEUE_NUM)];	/* bitmap of rx rings */
	int	rxr_cnt;	/* count rx rings */
	ulong_t tx_map[BT_BITOUL(MAX_TX_QUEUE_NUM)];	/* bitmap of tx rings */
	int	txr_cnt;	/* count tx rings */
	ulong_t other_map[BT_BITOUL(2)];		/* bitmap of other */
	int	other_cnt;	/* count other interrupt */
} ixgbe_intr_vector_t;

/*
 * Software adapter state
 */
typedef struct ixgbe {
	int 			instance;
	mac_handle_t		mac_hdl;
	dev_info_t		*dip;
	struct ixgbe_hw		hw;
	struct ixgbe_osdep	osdep;

	adapter_info_t		*capab;	/* adapter hardware capabilities */
	ddi_taskq_t		*sfp_taskq;	/* sfp-change taskq */
	ddi_taskq_t		*overtemp_taskq; /* overtemp taskq */
	uint32_t		eims;		/* interrupt mask setting */
	uint32_t		eimc;		/* interrupt mask clear */
	uint32_t		eicr;		/* interrupt cause reg */

	uint32_t		ixgbe_state;
	link_state_t		link_state;
	uint32_t		link_speed;
	uint32_t		link_duplex;

	uint32_t		reset_count;
	uint32_t		attach_progress;
	uint32_t		loopback_mode;
	uint32_t		default_mtu;
	uint32_t		max_frame_size;

	uint32_t		rcb_pending;

	/*
	 * Each msi-x vector: map vector to interrupt cleanup
	 */
	ixgbe_intr_vector_t	vect_map[MAX_INTR_VECTOR];

	/*
	 * Receive Rings
	 */
	ixgbe_rx_ring_t		*rx_rings;	/* Array of rx rings */
	uint32_t		num_rx_rings;	/* Number of rx rings in use */
	uint32_t		rx_ring_size;	/* Rx descriptor ring size */
	uint32_t		rx_buf_size;	/* Rx buffer size */
	boolean_t		lro_enable;	/* Large Receive Offload */
	uint64_t		lro_pkt_count;	/* LRO packet count */
	/*
	 * Receive Groups
	 */
	ixgbe_rx_group_t	*rx_groups;	/* Array of rx groups */
	uint32_t		num_rx_groups;	/* Number of rx groups in use */

	/*
	 * Transmit Rings
	 */
	ixgbe_tx_ring_t		*tx_rings;	/* Array of tx rings */
	uint32_t		num_tx_rings;	/* Number of tx rings in use */
	uint32_t		tx_ring_size;	/* Tx descriptor ring size */
	uint32_t		tx_buf_size;	/* Tx buffer size */

	boolean_t		tx_ring_init;
	boolean_t		tx_head_wb_enable; /* Tx head wrtie-back */
	boolean_t		tx_hcksum_enable; /* Tx h/w cksum offload */
	boolean_t 		lso_enable; 	/* Large Segment Offload */
	boolean_t 		mr_enable; 	/* Multiple Tx and Rx Ring */
	boolean_t		relax_order_enable; /* Relax Order */
	uint32_t		classify_mode;	/* Classification mode */
	uint32_t		tx_copy_thresh;	/* Tx copy threshold */
	uint32_t		tx_recycle_thresh; /* Tx recycle threshold */
	uint32_t		tx_overload_thresh; /* Tx overload threshold */
	uint32_t		tx_resched_thresh; /* Tx reschedule threshold */
	boolean_t		rx_hcksum_enable; /* Rx h/w cksum offload */
	uint32_t		rx_copy_thresh; /* Rx copy threshold */
	uint32_t		rx_limit_per_intr; /* Rx pkts per interrupt */
	uint32_t		intr_throttling[MAX_INTR_VECTOR];
	uint32_t		intr_force;
	int			fm_capabilities; /* FMA capabilities */

	int			intr_type;
	int			intr_cnt;
	uint32_t		intr_cnt_max;
	uint32_t		intr_cnt_min;
	int			intr_cap;
	size_t			intr_size;
	uint_t			intr_pri;
	ddi_intr_handle_t	*htable;
	uint32_t		eims_mask;
	ddi_cb_handle_t		cb_hdl;		/* Interrupt callback handle */

	kmutex_t		gen_lock; /* General lock for device access */
	kmutex_t		watchdog_lock;
	kmutex_t		rx_pending_lock;

	boolean_t		watchdog_enable;
	boolean_t		watchdog_start;
	timeout_id_t		watchdog_tid;

	boolean_t		unicst_init;
	uint32_t		unicst_avail;
	uint32_t		unicst_total;
	ixgbe_ether_addr_t	unicst_addr[MAX_NUM_UNICAST_ADDRESSES];
	uint32_t		mcast_count;
	struct ether_addr	mcast_table[MAX_NUM_MULTICAST_ADDRESSES];

	ulong_t			sys_page_size;

	boolean_t		link_check_complete;
	hrtime_t		link_check_hrtime;
	ddi_periodic_t		periodic_id; /* for link check timer func */

	/*
	 * Kstat definitions
	 */
	kstat_t			*ixgbe_ks;

	uint32_t		param_en_10000fdx_cap:1,
				param_en_1000fdx_cap:1,
				param_en_100fdx_cap:1,
				param_adv_10000fdx_cap:1,
				param_adv_1000fdx_cap:1,
				param_adv_100fdx_cap:1,
				param_pause_cap:1,
				param_asym_pause_cap:1,
				param_rem_fault:1,
				param_adv_autoneg_cap:1,
				param_adv_pause_cap:1,
				param_adv_asym_pause_cap:1,
				param_adv_rem_fault:1,
				param_lp_10000fdx_cap:1,
				param_lp_1000fdx_cap:1,
				param_lp_100fdx_cap:1,
				param_lp_autoneg_cap:1,
				param_lp_pause_cap:1,
				param_lp_asym_pause_cap:1,
				param_lp_rem_fault:1,
				param_pad_to_32:12;
} ixgbe_t;

typedef struct ixgbe_stat {
	kstat_named_t link_speed;	/* Link Speed */

	kstat_named_t reset_count;	/* Reset Count */

	kstat_named_t rx_frame_error;	/* Rx Error in Packet */
	kstat_named_t rx_cksum_error;	/* Rx Checksum Error */
	kstat_named_t rx_exceed_pkt;	/* Rx Exceed Max Pkt Count */

	kstat_named_t tx_overload;	/* Tx Desc Ring Overload */
	kstat_named_t tx_fail_no_tcb;	/* Tx Fail Freelist Empty */
	kstat_named_t tx_fail_no_tbd;	/* Tx Fail Desc Ring Empty */
	kstat_named_t tx_fail_dma_bind;	/* Tx Fail DMA bind */
	kstat_named_t tx_reschedule;	/* Tx Reschedule */

	kstat_named_t gprc;	/* Good Packets Received Count */
	kstat_named_t gptc;	/* Good Packets Xmitted Count */
	kstat_named_t gor;	/* Good Octets Received Count */
	kstat_named_t got;	/* Good Octets Xmitd Count */
	kstat_named_t prc64;	/* Packets Received - 64b */
	kstat_named_t prc127;	/* Packets Received - 65-127b */
	kstat_named_t prc255;	/* Packets Received - 127-255b */
	kstat_named_t prc511;	/* Packets Received - 256-511b */
	kstat_named_t prc1023;	/* Packets Received - 511-1023b */
	kstat_named_t prc1522;	/* Packets Received - 1024-1522b */
	kstat_named_t ptc64;	/* Packets Xmitted (64b) */
	kstat_named_t ptc127;	/* Packets Xmitted (64-127b) */
	kstat_named_t ptc255;	/* Packets Xmitted (128-255b) */
	kstat_named_t ptc511;	/* Packets Xmitted (255-511b) */
	kstat_named_t ptc1023;	/* Packets Xmitted (512-1023b) */
	kstat_named_t ptc1522;	/* Packets Xmitted (1024-1522b */
	kstat_named_t qprc[16];	/* Queue Packets Received Count */
	kstat_named_t qptc[16];	/* Queue Packets Transmitted Count */
	kstat_named_t qbrc[16];	/* Queue Bytes Received Count */
	kstat_named_t qbtc[16];	/* Queue Bytes Transmitted Count */

	kstat_named_t crcerrs;	/* CRC Error Count */
	kstat_named_t illerrc;	/* Illegal Byte Error Count */
	kstat_named_t errbc;	/* Error Byte Count */
	kstat_named_t mspdc;	/* MAC Short Packet Discard Count */
	kstat_named_t mpc;	/* Missed Packets Count */
	kstat_named_t mlfc;	/* MAC Local Fault Count */
	kstat_named_t mrfc;	/* MAC Remote Fault Count */
	kstat_named_t rlec;	/* Receive Length Error Count */
	kstat_named_t lxontxc;	/* Link XON Transmitted Count */
	kstat_named_t lxonrxc;	/* Link XON Received Count */
	kstat_named_t lxofftxc;	/* Link XOFF Transmitted Count */
	kstat_named_t lxoffrxc;	/* Link XOFF Received Count */
	kstat_named_t bprc;	/* Broadcasts Pkts Received Count */
	kstat_named_t mprc;	/* Multicast Pkts Received Count */
	kstat_named_t rnbc;	/* Receive No Buffers Count */
	kstat_named_t ruc;	/* Receive Undersize Count */
	kstat_named_t rfc;	/* Receive Frag Count */
	kstat_named_t roc;	/* Receive Oversize Count */
	kstat_named_t rjc;	/* Receive Jabber Count */
	kstat_named_t tor;	/* Total Octets Recvd Count */
	kstat_named_t tot;	/* Total Octets Xmitted Count */
	kstat_named_t tpr;	/* Total Packets Received */
	kstat_named_t tpt;	/* Total Packets Xmitted */
	kstat_named_t mptc;	/* Multicast Packets Xmited Count */
	kstat_named_t bptc;	/* Broadcast Packets Xmited Count */
	kstat_named_t lroc;	/* LRO Packets Received Count */
} ixgbe_stat_t;

/*
 * Function prototypes in ixgbe_buf.c
 */
int ixgbe_alloc_dma(ixgbe_t *);
void ixgbe_free_dma(ixgbe_t *);
void ixgbe_set_fma_flags(int);
void ixgbe_free_dma_buffer(dma_buffer_t *);
int ixgbe_alloc_rx_ring_data(ixgbe_rx_ring_t *rx_ring);
void ixgbe_free_rx_ring_data(ixgbe_rx_data_t *rx_data);

/*
 * Function prototypes in ixgbe_main.c
 */
int ixgbe_start(ixgbe_t *, boolean_t);
void ixgbe_stop(ixgbe_t *, boolean_t);
int ixgbe_driver_setup_link(ixgbe_t *, boolean_t);
int ixgbe_multicst_add(ixgbe_t *, const uint8_t *);
int ixgbe_multicst_remove(ixgbe_t *, const uint8_t *);
enum ioc_reply ixgbe_loopback_ioctl(ixgbe_t *, struct iocblk *, mblk_t *);

void ixgbe_enable_watchdog_timer(ixgbe_t *);
void ixgbe_disable_watchdog_timer(ixgbe_t *);
int ixgbe_atomic_reserve(uint32_t *, uint32_t);

int ixgbe_check_acc_handle(ddi_acc_handle_t handle);
int ixgbe_check_dma_handle(ddi_dma_handle_t handle);
void ixgbe_fm_ereport(ixgbe_t *, char *);

void ixgbe_fill_ring(void *, mac_ring_type_t, const int, const int,
    mac_ring_info_t *, mac_ring_handle_t);
void ixgbe_fill_group(void *arg, mac_ring_type_t, const int,
    mac_group_info_t *, mac_group_handle_t);
int ixgbe_rx_ring_intr_enable(mac_intr_handle_t);
int ixgbe_rx_ring_intr_disable(mac_intr_handle_t);

/*
 * Function prototypes in ixgbe_gld.c
 */
int ixgbe_m_start(void *);
void ixgbe_m_stop(void *);
int ixgbe_m_promisc(void *, boolean_t);
int ixgbe_m_multicst(void *, boolean_t, const uint8_t *);
void ixgbe_m_resources(void *);
void ixgbe_m_ioctl(void *, queue_t *, mblk_t *);
boolean_t ixgbe_m_getcapab(void *, mac_capab_t, void *);
int ixgbe_m_setprop(void *, const char *, mac_prop_id_t, uint_t, const void *);
int ixgbe_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
void ixgbe_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
int ixgbe_set_priv_prop(ixgbe_t *, const char *, uint_t, const void *);
int ixgbe_get_priv_prop(ixgbe_t *, const char *, uint_t, void *);
boolean_t ixgbe_param_locked(mac_prop_id_t);

/*
 * Function prototypes in ixgbe_rx.c
 */
mblk_t *ixgbe_ring_rx(ixgbe_rx_ring_t *, int);
void ixgbe_rx_recycle(caddr_t arg);
mblk_t *ixgbe_ring_rx_poll(void *, int);

/*
 * Function prototypes in ixgbe_tx.c
 */
mblk_t *ixgbe_ring_tx(void *, mblk_t *);
void ixgbe_free_tcb(tx_control_block_t *);
void ixgbe_put_free_list(ixgbe_tx_ring_t *, link_list_t *);
uint32_t ixgbe_tx_recycle_legacy(ixgbe_tx_ring_t *);
uint32_t ixgbe_tx_recycle_head_wb(ixgbe_tx_ring_t *);

/*
 * Function prototypes in ixgbe_log.c
 */
void ixgbe_notice(void *, const char *, ...);
void ixgbe_log(void *, const char *, ...);
void ixgbe_error(void *, const char *, ...);

/*
 * Function prototypes in ixgbe_stat.c
 */
int ixgbe_init_stats(ixgbe_t *);
int ixgbe_m_stat(void *, uint_t, uint64_t *);
int ixgbe_rx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);
int ixgbe_tx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);

#ifdef __cplusplus
}
#endif

#endif /* _IXGBE_SW_H */
