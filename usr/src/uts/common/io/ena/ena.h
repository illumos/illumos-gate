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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef	_ENA_H
#define	_ENA_H

#include <sys/stdbool.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/list.h>
#include <sys/time.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/pattr.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/utsname.h>
#include "ena_hw.h"

/*
 * AWS ENA Ethernet Driver
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ENA_MODULE_NAME	"ena"

/*
 * The minimum supported ENA device controller version.
 */
#define	ENA_CTRL_MAJOR_VSN_MIN		0
#define	ENA_CTRL_MINOR_VSN_MIN		0
#define	ENA_CTRL_SUBMINOR_VSN_MIN	1

#define	ENA_MODULE_VER_MAJOR	1
#define	ENA_MODULE_VER_MINOR	0
#define	ENA_MODULE_VER_SUBMINOR	0

/*
 * The Linux driver doesn't document what the specification version
 * number controls or the contract around version changes. The best we
 * can do is use the same version that they use and port version
 * changes as they come (the last one was in 2018).
 *
 * common: ENA_COMMON_SPEC_VERSION_{MAJOR,MINOR}
 */
#define	ENA_SPEC_VERSION_MAJOR	2
#define	ENA_SPEC_VERSION_MINOR	0


/* This represents BAR 0. */
#define	ENA_REG_NUMBER	1

/*
 * A sentinel value passed as argument to ena_ring_rx() to indicate
 * the Rx ring is being read in interrupt mode, not polling mode.
 */
#define	ENA_INTERRUPT_MODE	-1

#define	ENA_RX_BUF_IPHDR_ALIGNMENT	2
#define	ENA_ADMINQ_DEPTH		32
#define	ENA_AENQ_NUM_DESCS		32

/* Convert milliseconds to nanoseconds. */
#define	ENA_MS_TO_NS(ms)	((ms) * 1000000ul)

/*
 * The default amount of time we will wait for an admin command to complete,
 * specified in nanoseconds. This can be overridden by hints received from the
 * device. We default to half a second.
 */
#define	ENA_ADMIN_CMD_DEF_TIMEOUT_NS	MSEC2NSEC(500)

/*
 * The interval of the watchdog timer, in nanoseconds.
 */
#define	ENA_WATCHDOG_INTERVAL_NS	MSEC2NSEC(1000)

/*
 * The device sends a keepalive message every second. If we don't see any for
 * a while we will trigger a device reset. Other open source drivers use
 * 6 seconds for this value, so do we.
 */
#define	ENA_DEVICE_KEEPALIVE_TIMEOUT_NS	MSEC2NSEC(6000)

/*
 * The number of consecutive times a TX queue needs to be seen as blocked by
 * the watchdog timer before a reset is invoked. Since the watchdog interval
 * is one second, this is approximately in seconds.
 */
#define	ENA_TX_STALL_TIMEOUT		8

/*
 * In order to avoid rapidly sending basic stats requests to the controller, we
 * impose a limit of one request every 10ms.
 */
#define	ENA_BASIC_STATS_MINIMUM_INTERVAL_NS	MSEC2NSEC(10);

/*
 * Property macros.
 */
#define	ENA_PROP_RXQ_NUM_DESCS	"rx_queue_num_descs"
#define	ENA_PROP_RXQ_NUM_DESCS_MIN	64

#define	ENA_PROP_TXQ_NUM_DESCS	"tx_queue_num_descs"
#define	ENA_PROP_TXQ_NUM_DESCS_MIN	64

#define	ENA_PROP_RXQ_INTR_LIMIT	"rx_queue_intr_limit"
#define	ENA_PROP_RXQ_INTR_LIMIT_MIN	16
#define	ENA_PROP_RXQ_INTR_LIMIT_MAX	4096
#define	ENA_PROP_RXQ_INTR_LIMIT_DEF	256

#define	ENA_DMA_BIT_MASK(x)	((1ULL << (x)) - 1ULL)
#define	ENA_DMA_VERIFY_ADDR(ena, phys_addr)				\
	VERIFY3U(ENA_DMA_BIT_MASK((ena)->ena_dma_width) & (phys_addr), \
	    ==, (phys_addr))

typedef struct ena_dma_conf {
	size_t		edc_size;
	uint64_t	edc_align;
	int		edc_sgl;
	uchar_t		edc_endian;
	bool		edc_stream;
} ena_dma_conf_t;

typedef struct ena_dma_buf {
	caddr_t			edb_va;
	size_t			edb_len;
	/*
	 * The length given by DMA engine, kept around for debugging
	 * purposes.
	 */
	size_t			edb_real_len;
	size_t			edb_used_len;
	ddi_acc_handle_t	edb_acc_hdl;
	ddi_dma_handle_t	edb_dma_hdl;
	const ddi_dma_cookie_t	*edb_cookie;
} ena_dma_buf_t;

/*
 * We always sync the entire range, and therefore expect success.
 */
#ifdef DEBUG
#define	ENA_DMA_SYNC(buf, flag)					\
	ASSERT0(ddi_dma_sync((buf).edb_dma_hdl, 0, 0, (flag)))
#else  /* DEBUG */
#define	ENA_DMA_SYNC(buf, flag)					\
	((void)ddi_dma_sync((buf).edb_dma_hdl, 0, 0, (flag)))
#endif

typedef void (*ena_aenq_hdlr_t)(void *data, enahw_aenq_desc_t *desc);

typedef struct ena_aenq {
	enahw_aenq_desc_t	*eaenq_descs;
	ena_dma_buf_t		eaenq_dma;
	ena_aenq_hdlr_t		eaenq_hdlrs[ENAHW_AENQ_GROUPS_ARR_NUM];
	uint16_t		eaenq_num_descs;
	uint16_t		eaenq_head;
	uint8_t			eaenq_phase;
} ena_aenq_t;

typedef struct ena_admin_sq {
	enahw_cmd_desc_t	*eas_entries;
	ena_dma_buf_t		eas_dma;
	uint32_t		*eas_dbaddr;
	uint16_t		eas_tail;
	uint8_t			eas_phase;
} ena_admin_sq_t;

typedef struct ena_admin_cq {
	enahw_resp_desc_t	*eac_entries;
	ena_dma_buf_t		eac_dma;
	uint16_t		eac_head;
	uint8_t			eac_phase;
} ena_admin_cq_t;

/*
 * The command context is used to track outstanding requests and match
 * them to device responses.
 */
typedef struct ena_cmd_ctx {
	list_node_t		ectx_node;

	/*
	 * The index into ea_cmd_ctxs where this ctx lives. Used as
	 * the command ID value in the command descriptor. This allows
	 * us to match a response to its associated context.
	 */
	uint16_t		ectx_id;

	/* Is the command pending? */
	bool			ectx_pending;

	/* The type of command associated with this context. */
	enahw_cmd_opcode_t	ectx_cmd_opcode;

	/*
	 * The location to copy the full response to. This is
	 * specified by the caller of the command during
	 * submission.
	 */
	enahw_resp_desc_t	*ectx_resp;
} ena_cmd_ctx_t;

/*
 * The admin queue, the queue through which commands are sent to the
 * device.
 *
 * WO: Write Once (at initialization)
 *
 * In general, only a single lock needs to be held in order to access
 * the different parts of the admin queue:
 *
 *  sq_lock: Any data dealing with submitting admin commands, which
 *  includes acquiring a command context.
 *
 *  cq_lock: Any data dealing with reading command responses.
 *
 *  stat_lock: For accessing statistics.
 *
 * In some cases, the ectx_lock/stat_lock may be held in tandem with
 * either the SQ or CQ lock. In that case, the SQ/CQ lock is always
 * entered first.
 */
typedef struct ena_adminq {
	kmutex_t		ea_sq_lock;	/* WO */
	kmutex_t		ea_cq_lock;	/* WO */
	kmutex_t		ea_stat_lock;	/* WO */

	hrtime_t		ea_cmd_timeout_ns; /* WO */

	uint16_t		ea_qlen;	/* WO */
	bool			ea_poll_mode;	/* WO */

	ena_cmd_ctx_t		*ea_cmd_ctxs;	  /* WO */
	list_t			ea_cmd_ctxs_free; /* ea_sq_lock */
	list_t			ea_cmd_ctxs_used; /* ea_sq_lock */
	uint16_t		ea_pending_cmds; /* ea_sq_lock */
	ena_admin_sq_t		ea_sq; /* eq_sq_lock */
	ena_admin_cq_t		ea_cq; /* eq_cq_lock */

	/* ea_stat_lock */
	struct ena_adminq_stats {
		uint64_t cmds_fail;
		uint64_t cmds_submitted;
		uint64_t cmds_success;
		uint64_t queue_full;
	} ea_stats;
} ena_adminq_t;

/*
 * Cache of the last set of value hints received from the device. See the
 * definition of ehahw_device_hints_t in ena_hw.h for more detail on the
 * purpose of each.
 */
typedef struct ena_hints {
	uint16_t		eh_mmio_read_timeout;
	uint16_t		eh_keep_alive_timeout;
	uint16_t		eh_tx_comp_timeout;
	uint16_t		eh_missed_tx_reset_threshold;
	uint16_t		eh_admin_comp_timeout;
	uint16_t		eh_max_tx_sgl;
	uint16_t		eh_max_rx_sgl;
} ena_hints_t;

typedef enum ena_attach_seq {
	ENA_ATTACH_PCI = 1,	 /* PCI config space */
	ENA_ATTACH_REGS,	 /* BAR mapping */
	ENA_ATTACH_DEV_INIT,	 /* ENA device initialization */
	ENA_ATTACH_READ_CONF,	 /* Read driver conf file */
	ENA_ATTACH_DEV_CFG,	 /* Set any needed device config */
	ENA_ATTACH_INTR_ALLOC,	 /* interrupt handles allocated */
	ENA_ATTACH_INTR_HDLRS,	 /* intr handlers set */
	ENA_ATTACH_TXQS_ALLOC,	 /* Tx Queues allocated */
	ENA_ATTACH_RXQS_ALLOC,	 /* Tx Queues allocated */
	ENA_ATTACH_MAC_REGISTER, /* registered with mac */
	ENA_ATTACH_INTRS_ENABLE, /* interrupts are enabled */
	ENA_ATTACH_END
} ena_attach_seq_t;

#define	ENA_ATTACH_SEQ_FIRST	(ENA_ATTACH_PCI)
#define	ENA_ATTACH_NUM_ENTRIES	(ENA_ATTACH_END - 1)

struct ena;
typedef bool (*ena_attach_fn_t)(struct ena *);
typedef void (*ena_cleanup_fn_t)(struct ena *, bool);

typedef struct ena_attach_desc {
	ena_attach_seq_t ead_seq;
	const char *ead_name;
	ena_attach_fn_t ead_attach_fn;
	bool ead_attach_hard_fail;
	ena_cleanup_fn_t ead_cleanup_fn;
} ena_attach_desc_t;

typedef enum {
	ENA_TCB_NONE,
	ENA_TCB_COPY
} ena_tcb_type_t;

/*
 * The TCB is used to track information relating to the Tx of a
 * packet. At the moment we support copy only.
 */
typedef struct ena_tx_control_block {
	/*
	 * The index into et_tcbs where this tcb lives. Used as the request ID
	 * value in the Tx descriptor. This allows us to match a response to
	 * its associated TCB.
	 */
	uint16_t	etcb_id;
	mblk_t		*etcb_mp;
	ena_tcb_type_t	etcb_type;
	ena_dma_buf_t	etcb_dma;
} ena_tx_control_block_t;

typedef enum ena_txq_state {
	ENA_TXQ_STATE_NONE		= 0,
	ENA_TXQ_STATE_HOST_ALLOC	= 1 << 0,
	ENA_TXQ_STATE_CQ_CREATED	= 1 << 1,
	ENA_TXQ_STATE_SQ_CREATED	= 1 << 2,
	ENA_TXQ_STATE_READY		= 1 << 3, /* TxQ ready and waiting */
	ENA_TXQ_STATE_RUNNING		= 1 << 4, /* intrs enabled */
} ena_txq_state_t;

typedef struct ena_txq_stat {
	/* Number of times mac_ether_offload_info() has failed. */
	kstat_named_t	ets_hck_meoifail;

	/*
	 * Total number of times the ring was blocked due to
	 * insufficient descriptors, or unblocked due to recycling
	 * descriptors.
	 */
	kstat_named_t	ets_blocked;
	kstat_named_t	ets_unblocked;

	/* The total number descriptors that have been recycled. */
	kstat_named_t	ets_recycled;

	/*
	 * Number of bytes and packets that have been _submitted_ to
	 * the device.
	 */
	kstat_named_t	ets_bytes;
	kstat_named_t	ets_packets;
} ena_txq_stat_t;

/*
 * A transmit queue, made up of a Submission Queue (SQ) and Completion
 * Queue (CQ) to form a logical descriptor ring for sending packets.
 *
 * Write Once (WO)
 *
 *   This value is written once, before the datapath is activated, in
 *   a function which is controlled by mac(9E). Some values may be
 *   written earlier, during ena attach, like et_ena and
 *   et_sq_num_descs.
 *
 * Tx Mutex (TM) -- et_lock
 *
 *   This value is protected by the Tx queue's mutex. Some values may
 *   be initialized in a WO path, but also continually updated as part
 *   of normal datapath operation, such as et_sq_avail_descs. These
 *   values need mutex protection.
 */
typedef struct ena_txq {
	kmutex_t		et_lock; /* WO */

	struct ena		*et_ena; /* WO */
	uint_t			et_txqs_idx; /* WO */
	mac_ring_handle_t	et_mrh;	 /* WO */
	uint64_t		et_m_gen_num; /* TM */
	ena_txq_state_t		et_state; /* WO */
	uint16_t		et_intr_vector; /* WO */

	enahw_tx_desc_t		*et_sq_descs; /* TM */
	ena_dma_buf_t		et_sq_dma;    /* WO */

	/* Is the Tx queue currently in a blocked state? */
	bool			et_blocked; /* TM */

	/*
	 * The number of descriptors owned by this ring. This value
	 * never changes after initialization.
	 */
	uint16_t		et_sq_num_descs;   /* WO */

	/*
	 * The number of descriptors currently available for Tx
	 * submission. When this value reaches zero the ring must
	 * block until device notifies us of freed descriptors.
	 */
	uint16_t		et_sq_avail_descs; /* TM */

	/*
	 * The current tail index of the queue (the first free
	 * descriptor for host Tx submission). After initialization,
	 * this value only increments, relying on unsigned wrap
	 * around. The ENA device seems to expect this behavior,
	 * performing its own modulo on the value for the purposes of
	 * indexing, much like the driver code needs to do in order to
	 * access the proper TCB entry.
	 */
	uint16_t		et_sq_tail_idx;  /* TM */

	/*
	 * The phase is used to know which CQ descriptors may be
	 * reclaimed. This is explained further in ena.c.
	 */
	uint16_t		et_sq_phase; /* TM */
	uint16_t		et_sq_hw_idx; /* WO */

	/*
	 * The "doorbell" address is how the host indicates to the
	 * device which descriptors are ready for Tx processing.
	 */
	uint32_t		*et_sq_db_addr; /* WO */

	/*
	 * The TCBs track host Tx information, like a pointer to the
	 * mblk being submitted. The TCBs currently available for use are
	 * maintained in a free list.
	 */
	ena_tx_control_block_t	*et_tcbs;    /* TM */
	ena_tx_control_block_t	**et_tcbs_freelist; /* TM */
	uint16_t		et_tcbs_freelist_size; /* TM */

	enahw_tx_cdesc_t	*et_cq_descs; /* TM */
	ena_dma_buf_t		et_cq_dma;    /* WO */
	uint16_t		et_cq_num_descs; /* WO */
	uint16_t		et_cq_head_idx; /* TM */
	uint16_t		et_cq_phase;	/* TM */
	uint16_t		et_cq_hw_idx;	/* WO */

	/*
	 * This address is used to control the CQ interrupts.
	 */
	uint32_t		*et_cq_unmask_addr; /* WO */
	uint32_t		*et_cq_numa_addr;   /* WO (currently unused) */

	/*
	 * This is used to detect transmit stalls and invoke a reset. The
	 * watchdog increments this counter when it sees that the TX
	 * ring is still blocked, and if it exceeds the threshold then the
	 * device is assumed to have stalled and needs to be reset.
	 */
	uint32_t		et_stall_watchdog; /* TM */

	/*
	 * This mutex protects the Tx queue stats. This mutex may be
	 * entered while et_lock is held, but et_lock is not required
	 * to access/modify the stats. However, if both locks are
	 * held, then et_lock must be entered first.
	 */
	kmutex_t		et_stat_lock;
	ena_txq_stat_t		et_stat;
	kstat_t			*et_kstat;
} ena_txq_t;

typedef enum ena_rxq_state {
	ENA_RXQ_STATE_NONE		= 0,
	ENA_RXQ_STATE_HOST_ALLOC	= 1 << 0,
	ENA_RXQ_STATE_CQ_CREATED	= 1 << 1,
	ENA_RXQ_STATE_SQ_CREATED	= 1 << 2,
	ENA_RXQ_STATE_SQ_FILLED		= 1 << 3,
	ENA_RXQ_STATE_READY		= 1 << 4, /* RxQ ready and waiting */
	ENA_RXQ_STATE_RUNNING		= 1 << 5, /* intrs enabled */
} ena_rxq_state_t;

typedef struct ena_rx_ctrl_block {
	ena_dma_buf_t	ercb_dma;
	uint8_t		ercb_offset;
	uint16_t	ercb_length;
} ena_rx_ctrl_block_t;

typedef enum {
	ENA_RXQ_MODE_POLLING	= 1,
	ENA_RXQ_MODE_INTR	= 2,
} ena_rxq_mode_t;

typedef struct ena_rxq_stat_t {
	/* The total number of packets/bytes received on this queue. */
	kstat_named_t	ers_packets;
	kstat_named_t	ers_bytes;

	/*
	 * At this time we expect all incoming frames to fit in a
	 * single buffer/descriptor. In some rare event that the
	 * device doesn't cooperate this stat is incremented.
	 */
	kstat_named_t	ers_multi_desc;

	/*
	 * The total number of times we failed to allocate a new mblk
	 * for an incoming frame.
	 */
	kstat_named_t	ers_allocb_fail;

	/*
	 * The total number of times the Rx interrupt handler reached
	 * its maximum limit for number of packets to process in a
	 * single interrupt. If you see this number increase
	 * continuously at a steady rate, then it may be an indication
	 * the driver is not entering polling mode.
	 */
	kstat_named_t	ers_intr_limit;

	/*
	 * The total number of times the device detected an incorrect
	 * IPv4 header checksum.
	 */
	kstat_named_t	ers_hck_ipv4_err;

	/*
	 * The total number of times the device detected an incorrect
	 * L4/ULP checksum.
	 */
	kstat_named_t	ers_hck_l4_err;
} ena_rxq_stat_t;

/*
 * A receive queue, made up of a Submission Queue (SQ) and Completion
 * Queue (CQ) to form a logical descriptor ring for receiving packets.
 *
 * Write Once (WO)
 *
 *   This value is written once, before the datapath is activated, in
 *   a function which is controlled by mac(9E).
 *
 * Rx Mutex (RM) -- er_lock
 *
 *   This value is protected by the Rx queue's mutex. Some values may
 *   be initialized in a WO path, but also continually updated as part
 *   of normal datapath operation, such as er_sq_avail_descs. These
 *   values need mutex protection.
 */
typedef struct ena_rxq {
	kmutex_t		er_lock;

	struct ena		*er_ena; /* WO */
	uint_t			er_rxqs_idx; /* WO */
	mac_ring_handle_t	er_mrh;	 /* WO */
	uint64_t		er_m_gen_num; /* WO */
	ena_rxq_state_t		er_state; /* WO */
	uint16_t		er_intr_vector; /* WO */
	ena_rxq_mode_t		er_mode;	/* RM */
	uint16_t		er_intr_limit;	/* RM */

	enahw_rx_desc_t		*er_sq_descs; /* RM */
	ena_dma_buf_t		er_sq_dma;    /* WO */
	uint16_t		er_sq_num_descs;   /* WO */
	uint16_t		er_sq_avail_descs; /* RM */
	uint16_t		er_sq_tail_idx;  /* RM */
	uint16_t		er_sq_phase; /* RM */
	uint16_t		er_sq_hw_idx;	/* WO */
	uint32_t		*er_sq_db_addr; /* WO */

	enahw_rx_cdesc_t	*er_cq_descs; /* RM */
	ena_dma_buf_t		er_cq_dma;    /* WO */
	uint16_t		er_cq_num_descs; /* WO */
	uint16_t		er_cq_head_idx;	 /* RM */
	uint16_t		er_cq_phase;	 /* RM */
	uint16_t		er_cq_hw_idx;	 /* WO */
	uint32_t		*er_cq_unmask_addr; /* WO */
	uint32_t		*er_cq_numa_addr;    /* WO (currently unused) */

	ena_rx_ctrl_block_t	*er_rcbs; /* RM */

	kmutex_t		er_stat_lock;
	ena_rxq_stat_t		er_stat;
	kstat_t			*er_kstat;
} ena_rxq_t;

typedef struct ena_device_stat {
	kstat_named_t	eds_reset_forced;
	kstat_named_t	eds_reset_error;
	kstat_named_t	eds_reset_fatal;
	kstat_named_t	eds_reset_keepalive;
	kstat_named_t	eds_reset_txstall;
} ena_device_stat_t;

/*
 * These are stats based on enahw_resp_basic_stats_t and data that accompanies
 * the asynchronous keepalive event.
 */
typedef struct ena_basic_stat {
	kstat_named_t	ebs_tx_bytes;
	kstat_named_t	ebs_tx_pkts;
	kstat_named_t	ebs_tx_drops;

	kstat_named_t	ebs_rx_bytes;
	kstat_named_t	ebs_rx_pkts;
	kstat_named_t	ebs_rx_drops;
	kstat_named_t	ebs_rx_overruns;
} ena_basic_stat_t;

/* These are stats based on enahw_resp_eni_stats_t. */
typedef struct ena_extended_stat {
	kstat_named_t	ees_bw_in_exceeded;
	kstat_named_t	ees_bw_out_exceeded;
	kstat_named_t	ees_pps_exceeded;
	kstat_named_t	ees_conns_exceeded;
	kstat_named_t	ees_linklocal_exceeded;
} ena_extended_stat_t;

/* These stats monitor which AENQ handlers have been called. */
typedef struct ena_aenq_stat {
	kstat_named_t	eaes_default;
	kstat_named_t	eaes_link_change;
	kstat_named_t	eaes_notification;
	kstat_named_t	eaes_keep_alive;
	kstat_named_t	eaes_request_reset;
	kstat_named_t	eaes_fatal_error;
	kstat_named_t	eaes_warning;
} ena_aenq_stat_t;

#ifdef DEBUG
typedef struct ena_reg {
	const char	*er_name;
	const uint16_t	er_offset;
	uint32_t	er_value;
} ena_reg_t;
#endif

#define	ENA_STATE_UNKNOWN	0x00u
#define	ENA_STATE_INITIALIZED	0x01u
#define	ENA_STATE_STARTED	0x02u
#define	ENA_STATE_ERROR		0x04u
#define	ENA_STATE_RESETTING	0x08u

/*
 * This structure contains the per-instance (PF of VF) state of the
 * device.
 */
typedef struct ena {
	dev_info_t		*ena_dip;
	int			ena_instance;

#ifdef DEBUG
	/*
	 * In debug kernels, the registers are cached here at various points
	 * for easy inspection via mdb(1).
	 */
	ena_reg_t		ena_reg[ENAHW_NUM_REGS];
#endif

	/*
	 * Global lock, used to synchronize administration changes to
	 * the ena_t. This lock should not be held in the datapath.
	 */
	kmutex_t		ena_lock;
	ena_attach_seq_t	ena_attach_seq;

	/*
	 * We use atomic ops for ena_state so that datapath consumers
	 * do not need to enter ena_lock.
	 */
	uint32_t		ena_state;

	/*
	 * The reason for the last device reset.
	 */
	enahw_reset_reason_t	ena_reset_reason;

	/*
	 * Watchdog
	 */
	kmutex_t		ena_watchdog_lock;
	ddi_periodic_t		ena_watchdog_periodic;
	uint64_t		ena_watchdog_last_keepalive;

	/*
	 * PCI config space and BAR handle.
	 */
	ddi_acc_handle_t	ena_pci_hdl;
	off_t			ena_reg_size;
	caddr_t			ena_reg_base;
	ddi_device_acc_attr_t	ena_reg_attr;
	ddi_acc_handle_t	ena_reg_hdl;

	/*
	 * Vendor information.
	 */
	uint16_t		ena_pci_vid;
	uint16_t		ena_pci_did;
	uint8_t			ena_pci_rev;
	uint16_t		ena_pci_svid;
	uint16_t		ena_pci_sdid;

	/*
	 * Device and controller versions.
	 */
	uint32_t		ena_dev_major_vsn;
	uint32_t		ena_dev_minor_vsn;
	uint32_t		ena_ctrl_major_vsn;
	uint32_t		ena_ctrl_minor_vsn;
	uint32_t		ena_ctrl_subminor_vsn;
	uint32_t		ena_ctrl_impl_id;

	/*
	 * Interrupts
	 */
	int			ena_num_intrs;
	ddi_intr_handle_t	*ena_intr_handles;
	size_t			ena_intr_handles_sz;
	int			ena_intr_caps;
	uint_t			ena_intr_pri;

	mac_handle_t		ena_mh;

	size_t			ena_page_sz;

	/*
	 * The MTU and data layer frame sizes.
	 */
	uint32_t		ena_mtu;
	uint32_t		ena_max_frame_hdr;
	uint32_t		ena_max_frame_total;

	/* The size (in bytes) of the Rx/Tx data buffers. */
	uint32_t		ena_tx_buf_sz;
	uint32_t		ena_rx_buf_sz;

	/*
	 * The maximum number of Scatter Gather List segments the
	 * device can address.
	 */
	uint8_t			ena_tx_sgl_max_sz;
	uint8_t			ena_rx_sgl_max_sz;

	/* The number of descriptors per Rx/Tx queue. */
	uint16_t		ena_rxq_num_descs;
	uint16_t		ena_txq_num_descs;

	/*
	 * The maximum number of frames which may be read per Rx
	 * interrupt.
	 */
	uint16_t		ena_rxq_intr_limit;

	/* The Rx/Tx data queues (rings). */
	ena_rxq_t		*ena_rxqs;
	uint16_t		ena_num_rxqs;
	ena_txq_t		*ena_txqs;
	uint16_t		ena_num_txqs;

	/* These statistics are device-wide. */
	kstat_t			*ena_device_kstat;
	ena_device_stat_t	ena_device_stat;
	hrtime_t		ena_device_basic_stat_last_update;
	kmutex_t		ena_device_basic_stat_lock;
	kstat_t			*ena_device_basic_kstat;
	kstat_t			*ena_device_extended_kstat;

	/*
	 * This tracks AENQ-related stats, it is implicitly
	 * device-wide.
	 */
	ena_aenq_stat_t		ena_aenq_stat;
	kstat_t			*ena_aenq_kstat;

	/*
	 * The Admin Queue, through which call device commands are
	 * sent.
	 */
	ena_adminq_t		ena_aq;

	ena_aenq_t		ena_aenq;
	ena_dma_buf_t		ena_host_info;

	/*
	 * Hardware info
	 */
	ena_hints_t		ena_device_hints;
	uint32_t		ena_supported_features;
	uint32_t		ena_capabilities;
	uint8_t			ena_dma_width;
	bool			ena_link_autoneg;
	link_duplex_t		ena_link_duplex;
	uint64_t		ena_link_speed_mbits;
	enahw_link_speeds_t	ena_link_speeds;
	link_state_t		ena_link_state;
	uint32_t		ena_aenq_supported_groups;
	uint32_t		ena_aenq_enabled_groups;

	uint32_t		ena_tx_max_sq_num;
	uint32_t		ena_tx_max_sq_num_descs;
	uint32_t		ena_tx_max_cq_num;
	uint32_t		ena_tx_max_cq_num_descs;
	uint16_t		ena_tx_max_desc_per_pkt;
	uint32_t		ena_tx_max_hdr_len;

	uint32_t		ena_rx_max_sq_num;
	uint32_t		ena_rx_max_sq_num_descs;
	uint32_t		ena_rx_max_cq_num;
	uint32_t		ena_rx_max_cq_num_descs;
	uint16_t		ena_rx_max_desc_per_pkt;

	/* This is calculated from the Rx/Tx queue nums. */
	uint16_t		ena_max_io_queues;

	/* Hardware Offloads */
	bool			ena_tx_l3_ipv4_csum;

	bool			ena_tx_l4_ipv4_part_csum;
	bool			ena_tx_l4_ipv4_full_csum;
	bool			ena_tx_l4_ipv4_lso;

	bool			ena_tx_l4_ipv6_part_csum;
	bool			ena_tx_l4_ipv6_full_csum;
	bool			ena_tx_l4_ipv6_lso;

	bool			ena_rx_l3_ipv4_csum;
	bool			ena_rx_l4_ipv4_csum;
	bool			ena_rx_l4_ipv6_csum;
	bool			ena_rx_hash;

	uint32_t		ena_max_mtu;
	uint8_t			ena_mac_addr[ETHERADDRL];
} ena_t;

/*
 * Misc
 */
extern bool ena_reset(ena_t *, const enahw_reset_reason_t);
extern bool ena_is_feat_avail(ena_t *, const enahw_feature_id_t);
extern bool ena_is_cap_avail(ena_t *, const enahw_capability_id_t);
extern void ena_update_hints(ena_t *, enahw_device_hints_t *);

/*
 * Logging functions.
 */
extern bool ena_debug;
extern void ena_err(const ena_t *, const char *, ...) __KPRINTFLIKE(2);
extern void ena_dbg(const ena_t *, const char *, ...) __KPRINTFLIKE(2);
extern void ena_panic(const ena_t *, const char *, ...) __KPRINTFLIKE(2);
extern void ena_trigger_reset(ena_t *, enahw_reset_reason_t);

/*
 * Hardware access.
 */
extern uint32_t ena_hw_bar_read32(const ena_t *, const uint16_t);
extern uint32_t ena_hw_abs_read32(const ena_t *, uint32_t *);
extern void ena_hw_bar_write32(const ena_t *, const uint16_t, const uint32_t);
extern void ena_hw_abs_write32(const ena_t *, uint32_t *, const uint32_t);
extern const char *enahw_reset_reason(enahw_reset_reason_t);
#ifdef DEBUG
extern void ena_init_regcache(ena_t *);
extern void ena_update_regcache(ena_t *);
#else
#define	ena_init_regcache(x)
#define	ena_update_regcache(x)
#endif

/*
 * Watchdog
 */
extern void ena_enable_watchdog(ena_t *);
extern void ena_disable_watchdog(ena_t *);

/*
 * Stats
 */
extern void ena_stat_device_cleanup(ena_t *);
extern bool ena_stat_device_init(ena_t *);

extern void ena_stat_device_basic_cleanup(ena_t *);
extern bool ena_stat_device_basic_init(ena_t *);

extern void ena_stat_device_extended_cleanup(ena_t *);
extern bool ena_stat_device_extended_init(ena_t *);

extern void ena_stat_aenq_cleanup(ena_t *);
extern bool ena_stat_aenq_init(ena_t *);

extern void ena_stat_rxq_cleanup(ena_rxq_t *);
extern bool ena_stat_rxq_init(ena_rxq_t *);
extern void ena_stat_txq_cleanup(ena_txq_t *);
extern bool ena_stat_txq_init(ena_txq_t *);

/*
 * DMA
 */
extern bool ena_dma_alloc(ena_t *, ena_dma_buf_t *, ena_dma_conf_t *,
    size_t);
extern void ena_dma_free(ena_dma_buf_t *);
extern void ena_dma_bzero(ena_dma_buf_t *);
extern void ena_set_dma_addr(const ena_t *, const uint64_t, enahw_addr_t *);
extern void ena_set_dma_addr_values(const ena_t *, const uint64_t, uint32_t *,
    uint16_t *);

/*
 * Interrupts
 */
extern bool ena_intr_add_handlers(ena_t *);
extern void ena_intr_remove_handlers(ena_t *, bool);
extern void ena_tx_intr_work(ena_txq_t *);
extern void ena_rx_intr_work(ena_rxq_t *);
extern bool ena_intrs_disable(ena_t *);
extern bool ena_intrs_enable(ena_t *);

/*
 * MAC
 */
extern bool ena_mac_register(ena_t *);
extern int ena_mac_unregister(ena_t *);
extern void ena_ring_tx_stop(mac_ring_driver_t);
extern int ena_ring_tx_start(mac_ring_driver_t, uint64_t);
extern mblk_t *ena_ring_tx(void *, mblk_t *);
extern void ena_ring_rx_stop(mac_ring_driver_t);
extern int ena_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num);
extern int ena_m_stat(void *, uint_t, uint64_t *);
extern mblk_t *ena_ring_rx_poll(void *, int);
extern int ena_ring_rx_stat(mac_ring_driver_t, uint_t, uint64_t *);
extern int ena_ring_tx_stat(mac_ring_driver_t, uint_t, uint64_t *);

/*
 * Admin API
 */
extern int ena_admin_submit_cmd(ena_t *, enahw_cmd_desc_t *,
    enahw_resp_desc_t *, ena_cmd_ctx_t **);
extern int ena_admin_poll_for_resp(ena_t *, ena_cmd_ctx_t *);
extern void ena_free_host_info(ena_t *);
extern bool ena_init_host_info(ena_t *);
extern void ena_create_cmd_ctx(ena_t *);
extern void ena_release_all_cmd_ctx(ena_t *);
extern int ena_create_cq(ena_t *, uint16_t, uint64_t, bool, uint32_t,
    uint16_t *, uint32_t **, uint32_t **);
extern int ena_destroy_cq(ena_t *, uint16_t);
extern int ena_create_sq(ena_t *, uint16_t, uint64_t, bool, uint16_t,
    uint16_t *, uint32_t **);
extern int ena_destroy_sq(ena_t *, uint16_t, bool);
extern int ena_set_feature(ena_t *, enahw_cmd_desc_t *,
    enahw_resp_desc_t *, const enahw_feature_id_t, const uint8_t);
extern int ena_get_feature(ena_t *, enahw_resp_desc_t *,
    const enahw_feature_id_t, const uint8_t);
extern int ena_admin_get_basic_stats(ena_t *, enahw_resp_desc_t *);
extern int ena_admin_get_eni_stats(ena_t *, enahw_resp_desc_t *);
extern int enahw_resp_status_to_errno(ena_t *, enahw_resp_status_t);

/*
 * Async event queue
 */
extern bool ena_aenq_init(ena_t *);
extern bool ena_aenq_configure(ena_t *);
extern void ena_aenq_enable(ena_t *);
extern void ena_aenq_work(ena_t *);
extern void ena_aenq_free(ena_t *);

/*
 * Rx/Tx allocations
 */
extern bool ena_alloc_rxq(ena_rxq_t *);
extern void ena_cleanup_rxq(ena_rxq_t *, bool);
extern bool ena_alloc_txq(ena_txq_t *);
extern void ena_cleanup_txq(ena_txq_t *, bool);

#ifdef __cplusplus
}
#endif

#endif	/* _ENA_H */
