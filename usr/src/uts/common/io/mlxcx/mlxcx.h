/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020, The University of Queensland
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Mellanox Connect-X 4/5/6 driver.
 *
 * More details in mlxcx.c
 */

#ifndef _MLXCX_H
#define	_MLXCX_H

/*
 * mlxcx(7D) defintions
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/id_space.h>
#include <sys/list.h>
#include <sys/stddef.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/cpuvar.h>
#include <sys/ethernet.h>

#include <inet/ip.h>
#include <inet/ip6.h>

#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#include <mlxcx_reg.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Get access to the first PCI BAR.
 */
#define	MLXCX_REG_NUMBER		1

/*
 * The command queue is supposed to be a page, which is 4k.
 */
#define	MLXCX_CMD_DMA_PAGE_SIZE		4096

/*
 * Queues can allocate in units of this much memory.
 */
#define	MLXCX_QUEUE_DMA_PAGE_SIZE	4096

/*
 * We advertise two sizes of groups to MAC -- a certain number of "large"
 * groups (including the default group, which is sized to at least ncpus)
 * followed by a certain number of "small" groups.
 *
 * This allows us to have a larger amount of classification resources available
 * for zones/VMs without resorting to software classification.
 */
#define	MLXCX_RX_NGROUPS_LARGE_DFLT		2
#define	MLXCX_RX_NRINGS_PER_LARGE_GROUP_DFLT	16
#define	MLXCX_RX_NGROUPS_SMALL_DFLT		256
#define	MLXCX_RX_NRINGS_PER_SMALL_GROUP_DFLT	4

#define	MLXCX_TX_NGROUPS_DFLT		1
#define	MLXCX_TX_NRINGS_PER_GROUP_DFLT	64

/*
 * Queues will be sized to (1 << *Q_SIZE_SHIFT) entries long.
 */
#define	MLXCX_EQ_SIZE_SHIFT_DFLT	9
#define	MLXCX_CQ_SIZE_SHIFT_DFLT	10

/*
 * Default to making SQs bigger than RQs for 9k MTU, since most packets will
 * spill over into more than one slot. RQ WQEs are always 1 slot.
 */
#define	MLXCX_SQ_SIZE_SHIFT_DFLT	11
#define	MLXCX_RQ_SIZE_SHIFT_DFLT	10

#define	MLXCX_CQ_HWM_GAP		16
#define	MLXCX_CQ_LWM_GAP		24

#define	MLXCX_RQ_REFILL_STEP		64

/*
 * CQ event moderation
 */
#define	MLXCX_CQEMOD_PERIOD_USEC_DFLT	50
#define	MLXCX_CQEMOD_COUNT_DFLT		\
	(8 * ((1 << MLXCX_CQ_SIZE_SHIFT_DFLT) / 10))

/*
 * EQ interrupt moderation
 */
#define	MLXCX_INTRMOD_PERIOD_USEC_DFLT	10

/* Size of root flow tables */
#define	MLXCX_FTBL_ROOT_SIZE_SHIFT_DFLT		12

/* Size of 2nd level flow tables for VLAN filtering */
#define	MLXCX_FTBL_VLAN_SIZE_SHIFT_DFLT		4

/*
 * How big does an mblk have to be before we dma_bind() it instead of
 * bcopying?
 */
#define	MLXCX_TX_BIND_THRESHOLD_DFLT	2048

/*
 * How often to check the status of completion queues for overflow and
 * other problems.
 */
#define	MLXCX_WQ_CHECK_INTERVAL_SEC_DFLT		300
#define	MLXCX_CQ_CHECK_INTERVAL_SEC_DFLT		300
#define	MLXCX_EQ_CHECK_INTERVAL_SEC_DFLT		30

#define	MLXCX_DOORBELL_TRIES_DFLT		3
extern uint_t mlxcx_doorbell_tries;

#define	MLXCX_STUCK_INTR_COUNT_DFLT		128
extern uint_t mlxcx_stuck_intr_count;

#define	MLXCX_BUF_BIND_MAX_ATTEMTPS		50

#define	MLXCX_MTU_OFFSET	\
	(sizeof (struct ether_vlan_header) + ETHERFCSL)

/*
 * This is the current version of the command structure that the driver expects
 * to be found in the ISS.
 */
#define	MLXCX_CMD_REVISION	5

#ifdef	DEBUG
#define	MLXCX_DMA_SYNC(dma, flag)	VERIFY0(ddi_dma_sync( \
					    (dma).mxdb_dma_handle, 0, 0, \
					    (flag)))
#else
#define	MLXCX_DMA_SYNC(dma, flag)	(void) ddi_dma_sync( \
					    (dma).mxdb_dma_handle, 0, 0, \
					    (flag))
#endif

#define	MLXCX_FM_SERVICE_MLXCX	"mlxcx"

/*
 * This macro defines the expected value of the 'Interface Step Sequence ID'
 * (issi) which represents the version of the start up and tear down sequence.
 * We must check that hardware supports this and tell it which version we're
 * using as well.
 */
#define	MLXCX_CURRENT_ISSI	1

/*
 * This is the size of a page that the hardware expects from us when
 * manipulating pages.
 */
#define	MLXCX_HW_PAGE_SIZE	4096

/*
 * This is a special lkey value used to terminate a list of scatter pointers.
 */
#define	MLXCX_NULL_LKEY		0x100

/*
 * Forwards
 */
struct mlxcx;
typedef struct mlxcx mlxcx_t;

typedef enum {
	MLXCX_DMABUF_HDL_ALLOC		= 1 << 0,
	MLXCX_DMABUF_MEM_ALLOC		= 1 << 1,
	MLXCX_DMABUF_BOUND		= 1 << 2,
	MLXCX_DMABUF_FOREIGN		= 1 << 3,
} mlxcx_dma_buffer_flags_t;

typedef struct mlxcx_dma_buffer {
	mlxcx_dma_buffer_flags_t	mxdb_flags;
	caddr_t				mxdb_va;	/* Buffer VA */
	size_t				mxdb_len;	/* Buffer logical len */
	ddi_acc_handle_t		mxdb_acc_handle;
	ddi_dma_handle_t		mxdb_dma_handle;
	uint_t				mxdb_ncookies;
} mlxcx_dma_buffer_t;

typedef struct mlxcx_dev_page {
	list_node_t		mxdp_list;
	avl_node_t		mxdp_tree;
	uintptr_t		mxdp_pa;
	mlxcx_dma_buffer_t	mxdp_dma;
} mlxcx_dev_page_t;

/*
 * Data structure to keep track of all information related to the command queue.
 */
typedef enum {
	MLXCX_CMD_QUEUE_S_IDLE = 1,
	MLXCX_CMD_QUEUE_S_BUSY,
	MLXCX_CMD_QUEUE_S_BROKEN
} mlxcx_cmd_queue_status_t;

typedef struct mlxcx_cmd_queue {
	kmutex_t		mcmd_lock;
	kcondvar_t		mcmd_cv;
	mlxcx_dma_buffer_t	mcmd_dma;
	mlxcx_cmd_ent_t		*mcmd_ent;

	uint8_t			mcmd_size_l2;
	uint8_t			mcmd_stride_l2;

	mlxcx_cmd_queue_status_t	mcmd_status;

	ddi_taskq_t		*mcmd_taskq;
	id_space_t		*mcmd_tokens;
} mlxcx_cmd_queue_t;

typedef struct mlxcd_cmd_mbox {
	list_node_t		mlbox_node;
	mlxcx_dma_buffer_t	mlbox_dma;
	mlxcx_cmd_mailbox_t	*mlbox_data;
} mlxcx_cmd_mbox_t;

typedef enum {
	MLXCX_EQ_ALLOC		= 1 << 0,	/* dma mem alloc'd, size set */
	MLXCX_EQ_CREATED	= 1 << 1,	/* CREATE_EQ sent to hw */
	MLXCX_EQ_DESTROYED	= 1 << 2,	/* DESTROY_EQ sent to hw */
	MLXCX_EQ_ARMED		= 1 << 3,	/* Armed through the UAR */
	MLXCX_EQ_POLLING	= 1 << 4,	/* Currently being polled */
} mlxcx_eventq_state_t;

typedef struct mlxcx_bf {
	kmutex_t		mbf_mtx;
	uint_t			mbf_cnt;
	uint_t			mbf_even;
	uint_t			mbf_odd;
} mlxcx_bf_t;

typedef struct mlxcx_uar {
	boolean_t		mlu_allocated;
	uint_t			mlu_num;
	uint_t			mlu_base;

	volatile uint_t		mlu_bfcnt;
	mlxcx_bf_t		mlu_bf[MLXCX_BF_PER_UAR];
} mlxcx_uar_t;

typedef struct mlxcx_pd {
	boolean_t		mlpd_allocated;
	uint32_t		mlpd_num;
} mlxcx_pd_t;

typedef struct mlxcx_tdom {
	boolean_t		mltd_allocated;
	uint32_t		mltd_num;
} mlxcx_tdom_t;

typedef enum {
	MLXCX_PORT_VPORT_PROMISC	= 1 << 0,
} mlxcx_port_flags_t;

typedef struct mlxcx_flow_table mlxcx_flow_table_t;
typedef struct mlxcx_flow_group mlxcx_flow_group_t;

typedef struct {
	uint64_t		mlps_rx_drops;
} mlxcx_port_stats_t;

typedef enum {
	MLXCX_PORT_INIT		= 1 << 0
} mlxcx_port_init_t;

typedef struct mlxcx_port {
	kmutex_t		mlp_mtx;
	mlxcx_port_init_t	mlp_init;
	mlxcx_t			*mlp_mlx;
	/*
	 * The mlp_num we have here starts at zero (it's an index), but the
	 * numbering we have to use for register access starts at 1. We
	 * currently write mlp_num into the other_vport fields in mlxcx_cmd.c
	 * (where 0 is a magic number meaning "my vport") so if we ever add
	 * support for virtualisation features and deal with more than one
	 * vport, we will probably have to change this.
	 */
	uint_t			mlp_num;
	mlxcx_port_flags_t	mlp_flags;
	uint64_t		mlp_guid;
	uint8_t			mlp_mac_address[ETHERADDRL];

	uint_t			mlp_mtu;
	uint_t			mlp_max_mtu;

	mlxcx_port_status_t	mlp_admin_status;
	mlxcx_port_status_t	mlp_oper_status;

	boolean_t		mlp_autoneg;
	mlxcx_eth_proto_t	mlp_max_proto;
	mlxcx_eth_proto_t	mlp_admin_proto;
	mlxcx_eth_proto_t	mlp_oper_proto;

	mlxcx_eth_inline_mode_t	mlp_wqe_min_inline;

	/* Root flow tables */
	mlxcx_flow_table_t	*mlp_rx_flow;
	mlxcx_flow_table_t	*mlp_tx_flow;

	mlxcx_flow_group_t	*mlp_promisc;
	mlxcx_flow_group_t	*mlp_bcast;
	mlxcx_flow_group_t	*mlp_umcast;

	avl_tree_t		mlp_dmac_fe;

	mlxcx_port_stats_t	mlp_stats;

	mlxcx_module_status_t	mlp_last_modstate;
	mlxcx_module_error_type_t	mlp_last_moderr;
} mlxcx_port_t;

typedef enum {
	MLXCX_EQ_TYPE_ANY,
	MLXCX_EQ_TYPE_RX,
	MLXCX_EQ_TYPE_TX
} mlxcx_eventq_type_t;

typedef struct mlxcx_event_queue {
	kmutex_t		mleq_mtx;
	mlxcx_t			*mleq_mlx;
	mlxcx_eventq_state_t	mleq_state;
	mlxcx_eventq_type_t	mleq_type;

	mlxcx_dma_buffer_t	mleq_dma;

	size_t			mleq_entshift;
	size_t			mleq_nents;
	mlxcx_eventq_ent_t	*mleq_ent;
	uint32_t		mleq_cc;	/* consumer counter */
	uint32_t		mleq_cc_armed;

	uint32_t		mleq_events;

	uint32_t		mleq_badintrs;

	/* Hardware eq number */
	uint_t			mleq_num;
	/* Index into the mlxcx_t's interrupts array */
	uint_t			mleq_intr_index;

	/* UAR region that has this EQ's doorbell in it */
	mlxcx_uar_t		*mleq_uar;

	/* Tree of CQn => mlxcx_completion_queue_t */
	avl_tree_t		mleq_cqs;

	uint32_t		mleq_check_disarm_cc;
	uint_t			mleq_check_disarm_cnt;
} mlxcx_event_queue_t;

typedef enum {
	MLXCX_TIS_CREATED		= 1 << 0,
	MLXCX_TIS_DESTROYED		= 1 << 1,
} mlxcx_tis_state_t;

typedef struct mlxcx_tis {
	mlxcx_tis_state_t		mltis_state;
	list_node_t			mltis_entry;
	uint_t				mltis_num;
	mlxcx_tdom_t			*mltis_tdom;
} mlxcx_tis_t;

typedef enum {
	MLXCX_BUFFER_INIT,
	MLXCX_BUFFER_FREE,
	MLXCX_BUFFER_ON_WQ,
	MLXCX_BUFFER_ON_LOAN,
	MLXCX_BUFFER_ON_CHAIN,
} mlxcx_buffer_state_t;

typedef struct mlxcx_buf_shard {
	list_node_t		mlbs_entry;
	kmutex_t		mlbs_mtx;
	list_t			mlbs_busy;
	list_t			mlbs_free;
	kcondvar_t		mlbs_free_nonempty;
} mlxcx_buf_shard_t;

typedef struct mlxcx_buffer {
	mlxcx_buf_shard_t	*mlb_shard;
	list_node_t		mlb_entry;
	list_node_t		mlb_cq_entry;

	struct mlxcx_buffer	*mlb_tx_head;	/* head of tx chain */
	list_t			mlb_tx_chain;
	list_node_t		mlb_tx_chain_entry;

	boolean_t		mlb_foreign;
	size_t			mlb_used;
	mblk_t			*mlb_tx_mp;

	mlxcx_t			*mlb_mlx;
	mlxcx_buffer_state_t	mlb_state;
	uint_t			mlb_wqe_index;
	mlxcx_dma_buffer_t	mlb_dma;
	mblk_t			*mlb_mp;
	frtn_t			mlb_frtn;
} mlxcx_buffer_t;

typedef enum {
	MLXCX_CQ_ALLOC		= 1 << 0,
	MLXCX_CQ_CREATED	= 1 << 1,
	MLXCX_CQ_DESTROYED	= 1 << 2,
	MLXCX_CQ_EQAVL		= 1 << 3,
	MLXCX_CQ_BLOCKED_MAC	= 1 << 4,
	MLXCX_CQ_TEARDOWN	= 1 << 5,
	MLXCX_CQ_POLLING	= 1 << 6,
	MLXCX_CQ_ARMED		= 1 << 7,
} mlxcx_completionq_state_t;

typedef struct mlxcx_work_queue mlxcx_work_queue_t;

typedef struct mlxcx_completion_queue {
	kmutex_t			mlcq_mtx;
	mlxcx_t				*mlcq_mlx;
	mlxcx_completionq_state_t	mlcq_state;

	mlxcx_port_stats_t		*mlcq_stats;

	list_node_t			mlcq_entry;
	avl_node_t			mlcq_eq_entry;

	uint_t				mlcq_num;

	mlxcx_work_queue_t		*mlcq_wq;
	mlxcx_event_queue_t		*mlcq_eq;

	/* UAR region that has this CQ's UAR doorbell in it */
	mlxcx_uar_t			*mlcq_uar;

	mlxcx_dma_buffer_t		mlcq_dma;

	size_t				mlcq_entshift;
	size_t				mlcq_nents;
	mlxcx_completionq_ent_t		*mlcq_ent;
	uint32_t			mlcq_cc;	/* consumer counter */
	uint32_t			mlcq_cc_armed;	/* cc at last arm */
	uint32_t			mlcq_ec;	/* event counter */
	uint32_t			mlcq_ec_armed;	/* ec at last arm */

	mlxcx_dma_buffer_t		mlcq_doorbell_dma;
	mlxcx_completionq_doorbell_t	*mlcq_doorbell;

	uint64_t			mlcq_bufcnt;
	size_t				mlcq_bufhwm;
	size_t				mlcq_buflwm;
	list_t				mlcq_buffers;
	kmutex_t			mlcq_bufbmtx;
	list_t				mlcq_buffers_b;

	uint_t				mlcq_check_disarm_cnt;
	uint64_t			mlcq_check_disarm_cc;

	uint_t				mlcq_cqemod_period_usec;
	uint_t				mlcq_cqemod_count;

	mac_ring_handle_t		mlcq_mac_hdl;
	uint64_t			mlcq_mac_gen;

	boolean_t			mlcq_fm_repd_qstate;
} mlxcx_completion_queue_t;

typedef enum {
	MLXCX_WQ_ALLOC		= 1 << 0,
	MLXCX_WQ_CREATED	= 1 << 1,
	MLXCX_WQ_STARTED	= 1 << 2,
	MLXCX_WQ_DESTROYED	= 1 << 3,
	MLXCX_WQ_TEARDOWN	= 1 << 4,
	MLXCX_WQ_BUFFERS	= 1 << 5,
} mlxcx_workq_state_t;

typedef enum {
	MLXCX_WQ_TYPE_SENDQ = 1,
	MLXCX_WQ_TYPE_RECVQ
} mlxcx_workq_type_t;

typedef struct mlxcx_ring_group mlxcx_ring_group_t;

struct mlxcx_work_queue {
	kmutex_t			mlwq_mtx;
	mlxcx_t				*mlwq_mlx;
	mlxcx_workq_type_t		mlwq_type;
	mlxcx_workq_state_t		mlwq_state;

	list_node_t			mlwq_entry;
	list_node_t			mlwq_group_entry;

	mlxcx_ring_group_t		*mlwq_group;

	uint_t				mlwq_num;

	mlxcx_completion_queue_t	*mlwq_cq;
	mlxcx_pd_t			*mlwq_pd;

	/* Required for send queues */
	mlxcx_tis_t			*mlwq_tis;

	/* UAR region that has this WQ's blueflame buffers in it */
	mlxcx_uar_t			*mlwq_uar;

	mlxcx_dma_buffer_t		mlwq_dma;

	mlxcx_eth_inline_mode_t		mlwq_inline_mode;
	size_t				mlwq_entshift;
	size_t				mlwq_nents;
	/* Discriminate based on mwq_type */
	union {
		mlxcx_sendq_ent_t	*mlwq_send_ent;
		mlxcx_sendq_extra_ent_t	*mlwq_send_extra_ent;
		mlxcx_recvq_ent_t	*mlwq_recv_ent;
		mlxcx_sendq_bf_t	*mlwq_bf_ent;
	};
	uint64_t			mlwq_pc;	/* producer counter */

	mlxcx_dma_buffer_t		mlwq_doorbell_dma;
	mlxcx_workq_doorbell_t		*mlwq_doorbell;

	mlxcx_buf_shard_t		*mlwq_bufs;
	mlxcx_buf_shard_t		*mlwq_foreign_bufs;

	boolean_t			mlwq_fm_repd_qstate;
};

#define	MLXCX_RQT_MAX_SIZE		64

typedef enum {
	MLXCX_RQT_CREATED		= 1 << 0,
	MLXCX_RQT_DESTROYED		= 1 << 1,
	MLXCX_RQT_DIRTY			= 1 << 2,
} mlxcx_rqtable_state_t;

typedef struct mlxcx_rqtable {
	mlxcx_rqtable_state_t		mlrqt_state;
	list_node_t			mlrqt_entry;
	uint_t				mlrqt_num;

	size_t				mlrqt_max;
	size_t				mlrqt_used;

	size_t				mlrqt_rq_size;
	mlxcx_work_queue_t		**mlrqt_rq;
} mlxcx_rqtable_t;

typedef enum {
	MLXCX_TIR_CREATED		= 1 << 0,
	MLXCX_TIR_DESTROYED		= 1 << 1,
} mlxcx_tir_state_t;

typedef struct mlxcx_tir {
	mlxcx_tir_state_t		mltir_state;
	list_node_t			mltir_entry;
	uint_t				mltir_num;
	mlxcx_tdom_t			*mltir_tdom;
	mlxcx_tir_type_t		mltir_type;
	union {
		mlxcx_rqtable_t			*mltir_rqtable;
		mlxcx_work_queue_t		*mltir_rq;
	};
	mlxcx_tir_hash_fn_t		mltir_hash_fn;
	uint8_t				mltir_toeplitz_key[40];
	mlxcx_tir_rx_hash_l3_type_t	mltir_l3_type;
	mlxcx_tir_rx_hash_l4_type_t	mltir_l4_type;
	mlxcx_tir_rx_hash_fields_t	mltir_hash_fields;
} mlxcx_tir_t;

typedef enum {
	MLXCX_FLOW_GROUP_CREATED	= 1 << 0,
	MLXCX_FLOW_GROUP_BUSY		= 1 << 1,
	MLXCX_FLOW_GROUP_DESTROYED	= 1 << 2,
} mlxcx_flow_group_state_t;

typedef enum {
	MLXCX_FLOW_MATCH_SMAC		= 1 << 0,
	MLXCX_FLOW_MATCH_DMAC		= 1 << 1,
	MLXCX_FLOW_MATCH_VLAN		= 1 << 2,
	MLXCX_FLOW_MATCH_VID		= 1 << 3,
	MLXCX_FLOW_MATCH_IP_VER		= 1 << 4,
	MLXCX_FLOW_MATCH_SRCIP		= 1 << 5,
	MLXCX_FLOW_MATCH_DSTIP		= 1 << 6,
	MLXCX_FLOW_MATCH_IP_PROTO	= 1 << 7,
	MLXCX_FLOW_MATCH_SQN		= 1 << 8,
	MLXCX_FLOW_MATCH_VXLAN		= 1 << 9,
} mlxcx_flow_mask_t;

struct mlxcx_flow_group {
	list_node_t			mlfg_entry;
	list_node_t			mlfg_role_entry;
	mlxcx_flow_group_state_t	mlfg_state;
	mlxcx_flow_table_t		*mlfg_table;
	uint_t				mlfg_num;
	size_t				mlfg_start_idx;
	size_t				mlfg_size;
	size_t				mlfg_avail;
	list_t				mlfg_entries;
	mlxcx_flow_mask_t		mlfg_mask;
};

typedef enum {
	MLXCX_FLOW_ENTRY_RESERVED	= 1 << 0,
	MLXCX_FLOW_ENTRY_CREATED	= 1 << 1,
	MLXCX_FLOW_ENTRY_DELETED	= 1 << 2,
	MLXCX_FLOW_ENTRY_DIRTY		= 1 << 3,
} mlxcx_flow_entry_state_t;

typedef struct {
	mlxcx_tir_t			*mlfed_tir;
	mlxcx_flow_table_t		*mlfed_flow;
} mlxcx_flow_entry_dest_t;

typedef struct mlxcx_flow_entry {
	list_node_t			mlfe_group_entry;
	avl_node_t			mlfe_dmac_entry;
	mlxcx_flow_entry_state_t	mlfe_state;
	mlxcx_flow_table_t		*mlfe_table;
	mlxcx_flow_group_t		*mlfe_group;
	uint_t				mlfe_index;

	mlxcx_flow_action_t		mlfe_action;

	/* Criteria for match */
	uint8_t				mlfe_smac[ETHERADDRL];
	uint8_t				mlfe_dmac[ETHERADDRL];

	mlxcx_vlan_type_t		mlfe_vlan_type;
	uint16_t			mlfe_vid;

	uint_t				mlfe_ip_version;
	uint8_t				mlfe_srcip[IPV6_ADDR_LEN];
	uint8_t				mlfe_dstip[IPV6_ADDR_LEN];

	uint_t				mlfe_ip_proto;
	uint16_t			mlfe_sport;
	uint16_t			mlfe_dport;

	uint32_t			mlfe_sqn;
	uint32_t			mlfe_vxlan_vni;

	/* Destinations */
	size_t				mlfe_ndest;
	mlxcx_flow_entry_dest_t		mlfe_dest[MLXCX_FLOW_MAX_DESTINATIONS];

	/*
	 * mlxcx_group_mac_ts joining this entry to N ring groups
	 * only used by FEs on the root rx flow table
	 */
	list_t				mlfe_ring_groups;
} mlxcx_flow_entry_t;

typedef enum {
	MLXCX_FLOW_TABLE_CREATED	= 1 << 0,
	MLXCX_FLOW_TABLE_DESTROYED	= 1 << 1,
	MLXCX_FLOW_TABLE_ROOT		= 1 << 2
} mlxcx_flow_table_state_t;

struct mlxcx_flow_table {
	kmutex_t			mlft_mtx;
	mlxcx_flow_table_state_t	mlft_state;
	uint_t				mlft_level;
	uint_t				mlft_num;
	mlxcx_flow_table_type_t		mlft_type;

	mlxcx_port_t			*mlft_port;

	size_t				mlft_entshift;
	size_t				mlft_nents;

	size_t				mlft_entsize;
	mlxcx_flow_entry_t		*mlft_ent;

	/* First entry not yet claimed by a group */
	size_t				mlft_next_ent;

	list_t				mlft_groups;
};

typedef enum {
	MLXCX_GROUP_RX,
	MLXCX_GROUP_TX
} mlxcx_group_type_t;

typedef enum {
	MLXCX_GROUP_INIT		= 1 << 0,
	MLXCX_GROUP_WQS			= 1 << 1,
	MLXCX_GROUP_TIRTIS		= 1 << 2,
	MLXCX_GROUP_FLOWS		= 1 << 3,
	MLXCX_GROUP_RUNNING		= 1 << 4,
	MLXCX_GROUP_RQT			= 1 << 5,
} mlxcx_group_state_t;

#define	MLXCX_RX_HASH_FT_SIZE_SHIFT	4

typedef enum {
	MLXCX_TIR_ROLE_IPv4 = 0,
	MLXCX_TIR_ROLE_IPv6,
	MLXCX_TIR_ROLE_TCPv4,
	MLXCX_TIR_ROLE_TCPv6,
	MLXCX_TIR_ROLE_UDPv4,
	MLXCX_TIR_ROLE_UDPv6,
	MLXCX_TIR_ROLE_OTHER,

	MLXCX_TIRS_PER_GROUP
} mlxcx_tir_role_t;

typedef struct {
	avl_node_t		mlgm_group_entry;
	list_node_t		mlgm_fe_entry;
	mlxcx_ring_group_t	*mlgm_group;
	uint8_t			mlgm_mac[6];
	mlxcx_flow_entry_t	*mlgm_fe;
} mlxcx_group_mac_t;

typedef struct {
	list_node_t		mlgv_entry;
	boolean_t		mlgv_tagged;
	uint16_t		mlgv_vid;
	mlxcx_flow_entry_t	*mlgv_fe;
} mlxcx_group_vlan_t;

struct mlxcx_ring_group {
	kmutex_t			mlg_mtx;
	mlxcx_t				*mlg_mlx;
	mlxcx_group_state_t		mlg_state;
	mlxcx_group_type_t		mlg_type;

	mac_group_handle_t		mlg_mac_hdl;

	union {
		mlxcx_tis_t		mlg_tis;
		mlxcx_tir_t		mlg_tir[MLXCX_TIRS_PER_GROUP];
	};
	mlxcx_port_t			*mlg_port;

	size_t				mlg_nwqs;
	size_t				mlg_wqs_size;
	mlxcx_work_queue_t		*mlg_wqs;

	mlxcx_rqtable_t			*mlg_rqt;

	/*
	 * Flow table for matching VLAN IDs
	 */
	mlxcx_flow_table_t		*mlg_rx_vlan_ft;
	mlxcx_flow_group_t		*mlg_rx_vlan_fg;
	mlxcx_flow_group_t		*mlg_rx_vlan_def_fg;
	mlxcx_flow_group_t		*mlg_rx_vlan_promisc_fg;
	list_t				mlg_rx_vlans;

	/*
	 * Flow table for separating out by protocol before hashing
	 */
	mlxcx_flow_table_t		*mlg_rx_hash_ft;

	/*
	 * Links to flow entries on the root flow table which are pointing to
	 * our rx_vlan_ft.
	 */
	avl_tree_t			mlg_rx_macs;
};

typedef enum mlxcx_cmd_state {
	MLXCX_CMD_S_DONE	= 1 << 0,
	MLXCX_CMD_S_ERROR	= 1 << 1
} mlxcx_cmd_state_t;

typedef struct mlxcx_cmd {
	struct mlxcx		*mlcmd_mlxp;
	kmutex_t		mlcmd_lock;
	kcondvar_t		mlcmd_cv;

	uint8_t			mlcmd_token;
	mlxcx_cmd_op_t		mlcmd_op;

	/*
	 * Command data and extended mailboxes for responses.
	 */
	const void		*mlcmd_in;
	uint32_t		mlcmd_inlen;
	void			*mlcmd_out;
	uint32_t		mlcmd_outlen;
	list_t			mlcmd_mbox_in;
	uint8_t			mlcmd_nboxes_in;
	list_t			mlcmd_mbox_out;
	uint8_t			mlcmd_nboxes_out;
	/*
	 * Status information.
	 */
	mlxcx_cmd_state_t	mlcmd_state;
	uint8_t			mlcmd_status;
} mlxcx_cmd_t;

/*
 * Our view of capabilities.
 */
typedef struct mlxcx_hca_cap {
	mlxcx_hca_cap_mode_t	mhc_mode;
	mlxcx_hca_cap_type_t	mhc_type;
	union {
		uint8_t				mhc_bulk[MLXCX_HCA_CAP_SIZE];
		mlxcx_hca_cap_general_caps_t	mhc_general;
		mlxcx_hca_cap_eth_caps_t	mhc_eth;
		mlxcx_hca_cap_flow_caps_t	mhc_flow;
	};
} mlxcx_hca_cap_t;

typedef struct {
	/* Cooked values */
	boolean_t		mlc_checksum;
	boolean_t		mlc_lso;
	boolean_t		mlc_vxlan;
	size_t			mlc_max_lso_size;
	size_t			mlc_max_rqt_size;

	size_t			mlc_max_rx_ft_shift;
	size_t			mlc_max_rx_fe_dest;
	size_t			mlc_max_rx_flows;

	size_t			mlc_max_tir;

	/* Raw caps data */
	mlxcx_hca_cap_t		mlc_hca_cur;
	mlxcx_hca_cap_t		mlc_hca_max;
	mlxcx_hca_cap_t		mlc_ether_cur;
	mlxcx_hca_cap_t		mlc_ether_max;
	mlxcx_hca_cap_t		mlc_nic_flow_cur;
	mlxcx_hca_cap_t		mlc_nic_flow_max;
} mlxcx_caps_t;

typedef struct {
	uint_t			mldp_eq_size_shift;
	uint_t			mldp_cq_size_shift;
	uint_t			mldp_rq_size_shift;
	uint_t			mldp_sq_size_shift;
	uint_t			mldp_cqemod_period_usec;
	uint_t			mldp_cqemod_count;
	uint_t			mldp_intrmod_period_usec;
	uint_t			mldp_rx_ngroups_large;
	uint_t			mldp_rx_ngroups_small;
	uint_t			mldp_rx_nrings_per_large_group;
	uint_t			mldp_rx_nrings_per_small_group;
	uint_t			mldp_tx_ngroups;
	uint_t			mldp_tx_nrings_per_group;
	uint_t			mldp_ftbl_root_size_shift;
	size_t			mldp_tx_bind_threshold;
	uint_t			mldp_ftbl_vlan_size_shift;
	uint64_t		mldp_eq_check_interval_sec;
	uint64_t		mldp_cq_check_interval_sec;
	uint64_t		mldp_wq_check_interval_sec;
} mlxcx_drv_props_t;

typedef enum {
	MLXCX_ATTACH_FM		= 1 << 0,
	MLXCX_ATTACH_PCI_CONFIG	= 1 << 1,
	MLXCX_ATTACH_REGS	= 1 << 2,
	MLXCX_ATTACH_CMD	= 1 << 3,
	MLXCX_ATTACH_ENABLE_HCA	= 1 << 4,
	MLXCX_ATTACH_PAGE_LIST	= 1 << 5,
	MLXCX_ATTACH_INIT_HCA	= 1 << 6,
	MLXCX_ATTACH_UAR_PD_TD	= 1 << 7,
	MLXCX_ATTACH_INTRS	= 1 << 8,
	MLXCX_ATTACH_PORTS	= 1 << 9,
	MLXCX_ATTACH_MAC_HDL	= 1 << 10,
	MLXCX_ATTACH_CQS	= 1 << 11,
	MLXCX_ATTACH_WQS	= 1 << 12,
	MLXCX_ATTACH_GROUPS	= 1 << 13,
	MLXCX_ATTACH_BUFS	= 1 << 14,
	MLXCX_ATTACH_CAPS	= 1 << 15,
	MLXCX_ATTACH_CHKTIMERS	= 1 << 16,
} mlxcx_attach_progress_t;

struct mlxcx {
	/* entry on the mlxcx_glist */
	list_node_t		mlx_gentry;

	dev_info_t		*mlx_dip;
	int			mlx_inst;
	mlxcx_attach_progress_t	mlx_attach;

	mlxcx_drv_props_t	mlx_props;

	/*
	 * Misc. data
	 */
	uint16_t		mlx_fw_maj;
	uint16_t		mlx_fw_min;
	uint16_t		mlx_fw_rev;
	uint16_t		mlx_cmd_rev;

	/*
	 * Various capabilities of hardware.
	 */
	mlxcx_caps_t		*mlx_caps;

	uint_t			mlx_max_sdu;
	uint_t			mlx_sdu;

	/*
	 * FM State
	 */
	int			mlx_fm_caps;

	/*
	 * PCI Data
	 */
	ddi_acc_handle_t	mlx_cfg_handle;
	ddi_acc_handle_t	mlx_regs_handle;
	caddr_t			mlx_regs_base;

	/*
	 * MAC handle
	 */
	mac_handle_t		mlx_mac_hdl;

	/*
	 * Main command queue for issuing general FW control commands.
	 */
	mlxcx_cmd_queue_t	mlx_cmd;

	/*
	 * Interrupts
	 */
	uint_t			mlx_intr_pri;
	uint_t			mlx_intr_type;		/* always MSI-X */
	int			mlx_intr_count;
	size_t			mlx_intr_size;		/* allocation size */
	ddi_intr_handle_t	*mlx_intr_handles;

	/*
	 * Basic firmware resources which we use for a variety of things.
	 * The UAR is a reference to a page where CQ and EQ doorbells are
	 * located. It also holds all the BlueFlame stuff (which we don't
	 * use).
	 */
	mlxcx_uar_t		mlx_uar;
	/*
	 * The PD (Protection Domain) and TDOM (Transport Domain) are opaque
	 * entities to us (they're Infiniband constructs we don't actually care
	 * about) -- we just allocate them and shove their ID numbers in
	 * whenever we're asked for one.
	 *
	 * The "reserved" LKEY is what we should put in queue entries that
	 * have references to memory to indicate that they're using linear
	 * addresses (comes from the QUERY_SPECIAL_CONTEXTS cmd).
	 */
	mlxcx_pd_t		mlx_pd;
	mlxcx_tdom_t		mlx_tdom;
	uint_t			mlx_rsvd_lkey;

	/*
	 * Our event queues. These are 1:1 with interrupts.
	 */
	size_t			mlx_eqs_size;		/* allocation size */
	mlxcx_event_queue_t	*mlx_eqs;

	/*
	 * Page list. These represent the set of 4k pages we've given to
	 * hardware.
	 *
	 * We can add to this list at the request of hardware from interrupt
	 * context (the PAGE_REQUEST event), so it's protected by pagemtx.
	 */
	kmutex_t		mlx_pagemtx;
	uint_t			mlx_npages;
	avl_tree_t		mlx_pages;

	/*
	 * Port state
	 */
	uint_t			mlx_nports;
	size_t			mlx_ports_size;
	mlxcx_port_t		*mlx_ports;

	/*
	 * Completion queues (CQs). These are also indexed off the
	 * event_queue_ts that they each report to.
	 */
	list_t			mlx_cqs;

	uint_t			mlx_next_eq;

	/*
	 * Work queues (WQs).
	 */
	list_t			mlx_wqs;

	/*
	 * Ring groups
	 */
	size_t			mlx_rx_ngroups;
	size_t			mlx_rx_groups_size;
	mlxcx_ring_group_t	*mlx_rx_groups;

	size_t			mlx_tx_ngroups;
	size_t			mlx_tx_groups_size;
	mlxcx_ring_group_t	*mlx_tx_groups;

	kmem_cache_t		*mlx_bufs_cache;
	list_t			mlx_buf_shards;

	ddi_periodic_t		mlx_eq_checktimer;
	ddi_periodic_t		mlx_cq_checktimer;
	ddi_periodic_t		mlx_wq_checktimer;
};

/*
 * Register access
 */
extern uint16_t mlxcx_get16(mlxcx_t *, uintptr_t);
extern uint32_t mlxcx_get32(mlxcx_t *, uintptr_t);
extern uint64_t mlxcx_get64(mlxcx_t *, uintptr_t);

extern void mlxcx_put32(mlxcx_t *, uintptr_t, uint32_t);
extern void mlxcx_put64(mlxcx_t *, uintptr_t, uint64_t);

extern void mlxcx_uar_put32(mlxcx_t *, mlxcx_uar_t *, uintptr_t, uint32_t);
extern void mlxcx_uar_put64(mlxcx_t *, mlxcx_uar_t *, uintptr_t, uint64_t);

/*
 * Logging functions.
 */
extern void mlxcx_warn(mlxcx_t *, const char *, ...);
extern void mlxcx_note(mlxcx_t *, const char *, ...);
extern void mlxcx_panic(mlxcx_t *, const char *, ...);

extern void mlxcx_fm_ereport(mlxcx_t *, const char *);

extern void mlxcx_check_sq(mlxcx_t *, mlxcx_work_queue_t *);
extern void mlxcx_check_rq(mlxcx_t *, mlxcx_work_queue_t *);

/*
 * DMA Functions
 */
extern void mlxcx_dma_free(mlxcx_dma_buffer_t *);
extern boolean_t mlxcx_dma_alloc(mlxcx_t *, mlxcx_dma_buffer_t *,
    ddi_dma_attr_t *, ddi_device_acc_attr_t *, boolean_t, size_t, boolean_t);
extern boolean_t mlxcx_dma_init(mlxcx_t *, mlxcx_dma_buffer_t *,
    ddi_dma_attr_t *, boolean_t);
extern boolean_t mlxcx_dma_bind_mblk(mlxcx_t *, mlxcx_dma_buffer_t *,
    const mblk_t *, size_t, boolean_t);
extern boolean_t mlxcx_dma_alloc_offset(mlxcx_t *, mlxcx_dma_buffer_t *,
    ddi_dma_attr_t *, ddi_device_acc_attr_t *, boolean_t,
    size_t, size_t, boolean_t);
extern void mlxcx_dma_unbind(mlxcx_t *, mlxcx_dma_buffer_t *);
extern void mlxcx_dma_acc_attr(mlxcx_t *, ddi_device_acc_attr_t *);
extern void mlxcx_dma_page_attr(mlxcx_t *, ddi_dma_attr_t *);
extern void mlxcx_dma_queue_attr(mlxcx_t *, ddi_dma_attr_t *);
extern void mlxcx_dma_qdbell_attr(mlxcx_t *, ddi_dma_attr_t *);
extern void mlxcx_dma_buf_attr(mlxcx_t *, ddi_dma_attr_t *);

extern boolean_t mlxcx_give_pages(mlxcx_t *, int32_t);

static inline const ddi_dma_cookie_t *
mlxcx_dma_cookie_iter(const mlxcx_dma_buffer_t *db,
    const ddi_dma_cookie_t *prev)
{
	ASSERT(db->mxdb_flags & MLXCX_DMABUF_BOUND);
	return (ddi_dma_cookie_iter(db->mxdb_dma_handle, prev));
}

static inline const ddi_dma_cookie_t *
mlxcx_dma_cookie_one(const mlxcx_dma_buffer_t *db)
{
	ASSERT(db->mxdb_flags & MLXCX_DMABUF_BOUND);
	return (ddi_dma_cookie_one(db->mxdb_dma_handle));
}

/*
 * From mlxcx_intr.c
 */
extern boolean_t mlxcx_intr_setup(mlxcx_t *);
extern void mlxcx_intr_teardown(mlxcx_t *);
extern void mlxcx_arm_eq(mlxcx_t *, mlxcx_event_queue_t *);
extern void mlxcx_arm_cq(mlxcx_t *, mlxcx_completion_queue_t *);

extern mblk_t *mlxcx_rx_poll(mlxcx_t *, mlxcx_completion_queue_t *, size_t);

/*
 * From mlxcx_gld.c
 */
extern boolean_t mlxcx_register_mac(mlxcx_t *);

/*
 * From mlxcx_ring.c
 */
extern boolean_t mlxcx_cq_alloc_dma(mlxcx_t *, mlxcx_completion_queue_t *);
extern void mlxcx_cq_rele_dma(mlxcx_t *, mlxcx_completion_queue_t *);
extern boolean_t mlxcx_wq_alloc_dma(mlxcx_t *, mlxcx_work_queue_t *);
extern void mlxcx_wq_rele_dma(mlxcx_t *, mlxcx_work_queue_t *);

extern boolean_t mlxcx_buf_create(mlxcx_t *, mlxcx_buf_shard_t *,
    mlxcx_buffer_t **);
extern boolean_t mlxcx_buf_create_foreign(mlxcx_t *, mlxcx_buf_shard_t *,
    mlxcx_buffer_t **);
extern void mlxcx_buf_take(mlxcx_t *, mlxcx_work_queue_t *, mlxcx_buffer_t **);
extern size_t mlxcx_buf_take_n(mlxcx_t *, mlxcx_work_queue_t *,
    mlxcx_buffer_t **, size_t);
extern boolean_t mlxcx_buf_loan(mlxcx_t *, mlxcx_buffer_t *);
extern void mlxcx_buf_return(mlxcx_t *, mlxcx_buffer_t *);
extern void mlxcx_buf_return_chain(mlxcx_t *, mlxcx_buffer_t *, boolean_t);
extern void mlxcx_buf_destroy(mlxcx_t *, mlxcx_buffer_t *);

extern boolean_t mlxcx_buf_bind_or_copy(mlxcx_t *, mlxcx_work_queue_t *,
    mblk_t *, size_t, mlxcx_buffer_t **);

extern boolean_t mlxcx_rx_group_setup(mlxcx_t *, mlxcx_ring_group_t *);
extern boolean_t mlxcx_tx_group_setup(mlxcx_t *, mlxcx_ring_group_t *);

extern boolean_t mlxcx_rx_group_start(mlxcx_t *, mlxcx_ring_group_t *);
extern boolean_t mlxcx_tx_ring_start(mlxcx_t *, mlxcx_ring_group_t *,
    mlxcx_work_queue_t *);
extern boolean_t mlxcx_rx_ring_start(mlxcx_t *, mlxcx_ring_group_t *,
    mlxcx_work_queue_t *);

extern boolean_t mlxcx_rq_add_buffer(mlxcx_t *, mlxcx_work_queue_t *,
    mlxcx_buffer_t *);
extern boolean_t mlxcx_rq_add_buffers(mlxcx_t *, mlxcx_work_queue_t *,
    mlxcx_buffer_t **, size_t);
extern boolean_t mlxcx_sq_add_buffer(mlxcx_t *, mlxcx_work_queue_t *,
    uint8_t *, size_t, uint32_t, mlxcx_buffer_t *);
extern boolean_t mlxcx_sq_add_nop(mlxcx_t *, mlxcx_work_queue_t *);
extern void mlxcx_rq_refill(mlxcx_t *, mlxcx_work_queue_t *);

extern void mlxcx_teardown_groups(mlxcx_t *);
extern void mlxcx_wq_teardown(mlxcx_t *, mlxcx_work_queue_t *);
extern void mlxcx_cq_teardown(mlxcx_t *, mlxcx_completion_queue_t *);
extern void mlxcx_teardown_rx_group(mlxcx_t *, mlxcx_ring_group_t *);
extern void mlxcx_teardown_tx_group(mlxcx_t *, mlxcx_ring_group_t *);

extern void mlxcx_tx_completion(mlxcx_t *, mlxcx_completion_queue_t *,
    mlxcx_completionq_ent_t *, mlxcx_buffer_t *);
extern mblk_t *mlxcx_rx_completion(mlxcx_t *, mlxcx_completion_queue_t *,
    mlxcx_completionq_ent_t *, mlxcx_buffer_t *);

extern mlxcx_buf_shard_t *mlxcx_mlbs_create(mlxcx_t *);

/*
 * Flow mgmt
 */
extern boolean_t mlxcx_add_umcast_entry(mlxcx_t *, mlxcx_port_t *,
    mlxcx_ring_group_t *, const uint8_t *);
extern boolean_t mlxcx_remove_umcast_entry(mlxcx_t *, mlxcx_port_t *,
    mlxcx_ring_group_t *, const uint8_t *);
extern void mlxcx_remove_all_umcast_entries(mlxcx_t *, mlxcx_port_t *,
    mlxcx_ring_group_t *);
extern boolean_t mlxcx_setup_flow_group(mlxcx_t *, mlxcx_flow_table_t *,
    mlxcx_flow_group_t *);
extern void mlxcx_teardown_flow_table(mlxcx_t *, mlxcx_flow_table_t *);

extern void mlxcx_remove_all_vlan_entries(mlxcx_t *, mlxcx_ring_group_t *);
extern boolean_t mlxcx_remove_vlan_entry(mlxcx_t *, mlxcx_ring_group_t *,
    boolean_t, uint16_t);
extern boolean_t mlxcx_add_vlan_entry(mlxcx_t *, mlxcx_ring_group_t *,
    boolean_t, uint16_t);

/*
 * Command functions
 */
extern boolean_t mlxcx_cmd_queue_init(mlxcx_t *);
extern void mlxcx_cmd_queue_fini(mlxcx_t *);

extern boolean_t mlxcx_cmd_enable_hca(mlxcx_t *);
extern boolean_t mlxcx_cmd_disable_hca(mlxcx_t *);

extern boolean_t mlxcx_cmd_query_issi(mlxcx_t *, uint_t *);
extern boolean_t mlxcx_cmd_set_issi(mlxcx_t *, uint16_t);

extern boolean_t mlxcx_cmd_query_pages(mlxcx_t *, uint_t, int32_t *);
extern boolean_t mlxcx_cmd_give_pages(mlxcx_t *, uint_t, int32_t,
    mlxcx_dev_page_t **);
extern boolean_t mlxcx_cmd_return_pages(mlxcx_t *, int32_t, uint64_t *,
    int32_t *);

extern boolean_t mlxcx_cmd_query_hca_cap(mlxcx_t *, mlxcx_hca_cap_type_t,
    mlxcx_hca_cap_mode_t, mlxcx_hca_cap_t *);

extern boolean_t mlxcx_cmd_set_driver_version(mlxcx_t *, const char *);

extern boolean_t mlxcx_cmd_init_hca(mlxcx_t *);
extern boolean_t mlxcx_cmd_teardown_hca(mlxcx_t *);

extern boolean_t mlxcx_cmd_alloc_uar(mlxcx_t *, mlxcx_uar_t *);
extern boolean_t mlxcx_cmd_dealloc_uar(mlxcx_t *, mlxcx_uar_t *);

extern boolean_t mlxcx_cmd_alloc_pd(mlxcx_t *, mlxcx_pd_t *);
extern boolean_t mlxcx_cmd_dealloc_pd(mlxcx_t *, mlxcx_pd_t *);

extern boolean_t mlxcx_cmd_alloc_tdom(mlxcx_t *, mlxcx_tdom_t *);
extern boolean_t mlxcx_cmd_dealloc_tdom(mlxcx_t *, mlxcx_tdom_t *);

extern boolean_t mlxcx_cmd_create_eq(mlxcx_t *, mlxcx_event_queue_t *);
extern boolean_t mlxcx_cmd_destroy_eq(mlxcx_t *, mlxcx_event_queue_t *);
extern boolean_t mlxcx_cmd_query_eq(mlxcx_t *, mlxcx_event_queue_t *,
    mlxcx_eventq_ctx_t *);

extern boolean_t mlxcx_cmd_create_cq(mlxcx_t *, mlxcx_completion_queue_t *);
extern boolean_t mlxcx_cmd_destroy_cq(mlxcx_t *, mlxcx_completion_queue_t *);
extern boolean_t mlxcx_cmd_query_cq(mlxcx_t *, mlxcx_completion_queue_t *,
    mlxcx_completionq_ctx_t *);

extern boolean_t mlxcx_cmd_create_rq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_start_rq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_stop_rq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_destroy_rq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_query_rq(mlxcx_t *, mlxcx_work_queue_t *,
    mlxcx_rq_ctx_t *);

extern boolean_t mlxcx_cmd_create_tir(mlxcx_t *, mlxcx_tir_t *);
extern boolean_t mlxcx_cmd_destroy_tir(mlxcx_t *, mlxcx_tir_t *);

extern boolean_t mlxcx_cmd_create_sq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_start_sq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_stop_sq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_destroy_sq(mlxcx_t *, mlxcx_work_queue_t *);
extern boolean_t mlxcx_cmd_query_sq(mlxcx_t *, mlxcx_work_queue_t *,
    mlxcx_sq_ctx_t *);

extern boolean_t mlxcx_cmd_create_tis(mlxcx_t *, mlxcx_tis_t *);
extern boolean_t mlxcx_cmd_destroy_tis(mlxcx_t *, mlxcx_tis_t *);

extern boolean_t mlxcx_cmd_query_nic_vport_ctx(mlxcx_t *, mlxcx_port_t *);
extern boolean_t mlxcx_cmd_query_special_ctxs(mlxcx_t *);

extern boolean_t mlxcx_cmd_modify_nic_vport_ctx(mlxcx_t *, mlxcx_port_t *,
    mlxcx_modify_nic_vport_ctx_fields_t);

extern boolean_t mlxcx_cmd_create_flow_table(mlxcx_t *, mlxcx_flow_table_t *);
extern boolean_t mlxcx_cmd_destroy_flow_table(mlxcx_t *, mlxcx_flow_table_t *);
extern boolean_t mlxcx_cmd_set_flow_table_root(mlxcx_t *, mlxcx_flow_table_t *);

extern boolean_t mlxcx_cmd_create_flow_group(mlxcx_t *, mlxcx_flow_group_t *);
extern boolean_t mlxcx_cmd_set_flow_table_entry(mlxcx_t *,
    mlxcx_flow_entry_t *);
extern boolean_t mlxcx_cmd_delete_flow_table_entry(mlxcx_t *,
    mlxcx_flow_entry_t *);
extern boolean_t mlxcx_cmd_destroy_flow_group(mlxcx_t *, mlxcx_flow_group_t *);

extern boolean_t mlxcx_cmd_access_register(mlxcx_t *, mlxcx_cmd_reg_opmod_t,
    mlxcx_register_id_t, mlxcx_register_data_t *);
extern boolean_t mlxcx_cmd_query_port_mtu(mlxcx_t *, mlxcx_port_t *);
extern boolean_t mlxcx_cmd_query_port_status(mlxcx_t *, mlxcx_port_t *);
extern boolean_t mlxcx_cmd_query_port_speed(mlxcx_t *, mlxcx_port_t *);

extern boolean_t mlxcx_cmd_set_port_mtu(mlxcx_t *, mlxcx_port_t *);

extern boolean_t mlxcx_cmd_create_rqt(mlxcx_t *, mlxcx_rqtable_t *);
extern boolean_t mlxcx_cmd_destroy_rqt(mlxcx_t *, mlxcx_rqtable_t *);

extern boolean_t mlxcx_cmd_set_int_mod(mlxcx_t *, uint_t, uint_t);

extern boolean_t mlxcx_cmd_query_module_status(mlxcx_t *, uint_t,
    mlxcx_module_status_t *, mlxcx_module_error_type_t *);
extern boolean_t mlxcx_cmd_set_port_led(mlxcx_t *, mlxcx_port_t *, uint16_t);

/* Comparator for avl_ts */
extern int mlxcx_cq_compare(const void *, const void *);
extern int mlxcx_dmac_fe_compare(const void *, const void *);
extern int mlxcx_grmac_compare(const void *, const void *);
extern int mlxcx_page_compare(const void *, const void *);

extern void mlxcx_update_link_state(mlxcx_t *, mlxcx_port_t *);

extern void mlxcx_eth_proto_to_string(mlxcx_eth_proto_t, char *, size_t);
extern const char *mlxcx_port_status_string(mlxcx_port_status_t);

extern const char *mlxcx_event_name(mlxcx_event_t);

#ifdef __cplusplus
}
#endif

#endif /* _MLXCX_H */
