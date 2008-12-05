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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *  Copyright (c) 2002-2005 Neterion, Inc.
 *  All right Reserved.
 *
 *  FileName :    xgell.h
 *
 *  Description:  Link Layer driver declaration
 *
 */

#ifndef _SYS_XGELL_H
#define	_SYS_XGELL_H

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/dlpi.h>
#include <sys/taskq.h>
#include <sys/cyclic.h>

#include <sys/pattr.h>
#include <sys/strsun.h>

#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	XGELL_DESC		"Xframe I/II 10Gb Ethernet"
#define	XGELL_IFNAME		"xge"

#include <xgehal.h>

/*
 * The definition of XGELL_RX_BUFFER_RECYCLE_CACHE is an experimental value.
 * With this value, the lock contention between xgell_rx_buffer_recycle()
 * and xgell_rx_1b_compl() is reduced to great extent. And multiple rx rings
 * alleviate the lock contention further since each rx ring has its own mutex.
 */
#define	XGELL_RX_BUFFER_RECYCLE_CACHE	XGE_HAL_RING_RXDS_PER_BLOCK(1) * 2
#define	MSG_SIZE	64

/*
 * These default values can be overridden by vaules in xge.conf.
 * In xge.conf user has to specify actual (not percentages) values.
 */
#define	XGELL_RX_BUFFER_TOTAL		XGE_HAL_RING_RXDS_PER_BLOCK(1) * 6
#define	XGELL_RX_BUFFER_POST_HIWAT	XGE_HAL_RING_RXDS_PER_BLOCK(1) * 5

/*
 * Multiple rings configuration
 */
#define	XGELL_RX_RING_MAIN			0
#define	XGELL_TX_RING_MAIN			0

#define	XGELL_RX_RING_NUM_MIN			1
#define	XGELL_TX_RING_NUM_MIN			1
#define	XGELL_RX_RING_NUM_MAX			8
#define	XGELL_TX_RING_NUM_MAX			1 /* TODO */
#define	XGELL_RX_RING_NUM_DEFAULT		XGELL_RX_RING_NUM_MAX
#define	XGELL_TX_RING_NUM_DEFAULT		XGELL_TX_RING_NUM_MAX

#define	XGELL_MINTR_NUM_MIN			1
#define	XGELL_MINTR_NUM_MAX			\
	(XGELL_RX_RING_NUM_MAX + XGELL_TX_RING_NUM_MAX + 1)
#define	XGELL_MINTR_NUM_DEFAULT			XGELL_MINTR_NUM_MAX

#define	XGELL_CONF_GROUP_POLICY_BASIC		0
#define	XGELL_CONF_GROUP_POLICY_VIRT		1
#define	XGELL_CONF_GROUP_POLICY_PERF		2
#if 0
#if defined(__sparc)
#define	XGELL_CONF_GROUP_POLICY_DEFAULT		XGELL_CONF_GROUP_POLICY_PERF
#else
#define	XGELL_CONF_GROUP_POLICY_DEFAULT		XGELL_CONF_GROUP_POLICY_VIRT
#endif
#else
/*
 * The _PERF configuration enable a fat group of all rx rings, as approachs
 * better fanout performance of the primary interface.
 */
#define	XGELL_CONF_GROUP_POLICY_DEFAULT		XGELL_CONF_GROUP_POLICY_PERF
#endif

#define	XGELL_TX_LEVEL_LOW	8
#define	XGELL_TX_LEVEL_HIGH	32
#define	XGELL_TX_LEVEL_CHECK	3
#define	XGELL_MAX_RING_DEFAULT	8
#define	XGELL_MAX_FIFO_DEFAULT	1

/* Control driver to copy or DMA inbound/outbound packets */
#if defined(__sparc)
#define	XGELL_RX_DMA_LOWAT			256
#define	XGELL_TX_DMA_LOWAT			512
#else
#define	XGELL_RX_DMA_LOWAT			256
#define	XGELL_TX_DMA_LOWAT			128
#endif

/*
 * Try to collapse up to XGELL_RX_PKT_BURST packets into single mblk
 * sequence before mac_rx() is called.
 */
#define	XGELL_RX_PKT_BURST			32

/* About 1s */
#define	XGE_DEV_POLL_TICKS			drv_usectohz(1000000)

#define	XGELL_LSO_MAXLEN			65535
#define	XGELL_CONF_ENABLE_BY_DEFAULT		1
#define	XGELL_CONF_DISABLE_BY_DEFAULT		0

/* LRO configuration */
#define	XGE_HAL_DEFAULT_LRO_SG_SIZE		2 /* <=2 LRO fix not required */
#define	XGE_HAL_DEFAULT_LRO_FRM_LEN		65535

/*
 * Default values for tunables used in HAL. Please refer to xgehal-config.h
 * for more details.
 */
#define	XGE_HAL_DEFAULT_USE_HARDCODE		-1

/* Bimodal adaptive schema defaults - ENABLED */
#define	XGE_HAL_DEFAULT_BIMODAL_INTERRUPTS	-1
#define	XGE_HAL_DEFAULT_BIMODAL_TIMER_LO_US	24
#define	XGE_HAL_DEFAULT_BIMODAL_TIMER_HI_US	256

/* Interrupt moderation/utilization defaults */
#define	XGE_HAL_DEFAULT_TX_URANGE_A		5
#define	XGE_HAL_DEFAULT_TX_URANGE_B		15
#define	XGE_HAL_DEFAULT_TX_URANGE_C		30
#define	XGE_HAL_DEFAULT_TX_UFC_A		15
#define	XGE_HAL_DEFAULT_TX_UFC_B		30
#define	XGE_HAL_DEFAULT_TX_UFC_C		45
#define	XGE_HAL_DEFAULT_TX_UFC_D		60
#define	XGE_HAL_DEFAULT_TX_TIMER_CI_EN		1
#define	XGE_HAL_DEFAULT_TX_TIMER_AC_EN		1
#define	XGE_HAL_DEFAULT_TX_TIMER_VAL		10000
#define	XGE_HAL_DEFAULT_INDICATE_MAX_PKTS_B	512 /* bimodal */
#define	XGE_HAL_DEFAULT_INDICATE_MAX_PKTS_N	256 /* normal UFC */
#define	XGE_HAL_DEFAULT_RX_URANGE_A		10
#define	XGE_HAL_DEFAULT_RX_URANGE_B		30
#define	XGE_HAL_DEFAULT_RX_URANGE_C		50
#define	XGE_HAL_DEFAULT_RX_UFC_A		1
#define	XGE_HAL_DEFAULT_RX_UFC_B_J		2
#define	XGE_HAL_DEFAULT_RX_UFC_B_N		8
#define	XGE_HAL_DEFAULT_RX_UFC_C_J		4
#define	XGE_HAL_DEFAULT_RX_UFC_C_N		16
#define	XGE_HAL_DEFAULT_RX_UFC_D		32
#define	XGE_HAL_DEFAULT_RX_TIMER_AC_EN		1
#define	XGE_HAL_DEFAULT_RX_TIMER_VAL		384

#define	XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_A	1024
#define	XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_J	2048
#define	XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_N	4096
#define	XGE_HAL_DEFAULT_FIFO_QUEUE_INTR		0
#define	XGE_HAL_DEFAULT_FIFO_RESERVE_THRESHOLD	0
#define	XGE_HAL_DEFAULT_FIFO_MEMBLOCK_SIZE	PAGESIZE

/*
 * This will force HAL to allocate extra copied buffer per TXDL which
 * size calculated by formula:
 *
 *      (ALIGNMENT_SIZE * ALIGNED_FRAGS)
 */
#define	XGE_HAL_DEFAULT_FIFO_ALIGNMENT_SIZE	4096
#define	XGE_HAL_DEFAULT_FIFO_MAX_ALIGNED_FRAGS	1
#if defined(__sparc)
#define	XGE_HAL_DEFAULT_FIFO_FRAGS		64
#else
#define	XGE_HAL_DEFAULT_FIFO_FRAGS		128
#endif
#define	XGE_HAL_DEFAULT_FIFO_FRAGS_THRESHOLD	18

#define	XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS	2
#define	XGE_HAL_RING_QUEUE_BUFFER_MODE_DEFAULT	1
#define	XGE_HAL_DEFAULT_BACKOFF_INTERVAL_US	64
#define	XGE_HAL_DEFAULT_RING_PRIORITY		0
#define	XGE_HAL_DEFAULT_RING_MEMBLOCK_SIZE	PAGESIZE

#define	XGE_HAL_DEFAULT_RING_NUM		8
#define	XGE_HAL_DEFAULT_TMAC_UTIL_PERIOD	5
#define	XGE_HAL_DEFAULT_RMAC_UTIL_PERIOD	5
#define	XGE_HAL_DEFAULT_RMAC_HIGH_PTIME		65535
#define	XGE_HAL_DEFAULT_MC_PAUSE_THRESHOLD_Q0Q3	187
#define	XGE_HAL_DEFAULT_MC_PAUSE_THRESHOLD_Q4Q7	187
#define	XGE_HAL_DEFAULT_RMAC_PAUSE_GEN_EN	1
#define	XGE_HAL_DEFAULT_RMAC_PAUSE_GEN_DIS	0
#define	XGE_HAL_DEFAULT_RMAC_PAUSE_RCV_EN	1
#define	XGE_HAL_DEFAULT_RMAC_PAUSE_RCV_DIS	0
#define	XGE_HAL_DEFAULT_INITIAL_MTU		XGE_HAL_DEFAULT_MTU /* 1500 */
#define	XGE_HAL_DEFAULT_ISR_POLLING_CNT		0
#define	XGE_HAL_DEFAULT_LATENCY_TIMER		255
#define	XGE_HAL_DEFAULT_SHARED_SPLITS		0
#define	XGE_HAL_DEFAULT_STATS_REFRESH_TIME	1

#if defined(__sparc)
#define	XGE_HAL_DEFAULT_MMRB_COUNT		XGE_HAL_MAX_MMRB_COUNT
#define	XGE_HAL_DEFAULT_SPLIT_TRANSACTION	XGE_HAL_EIGHT_SPLIT_TRANSACTION
#else
#define	XGE_HAL_DEFAULT_MMRB_COUNT		1 /* 1k */
#define	XGE_HAL_DEFAULT_SPLIT_TRANSACTION	XGE_HAL_TWO_SPLIT_TRANSACTION
#endif

/*
 * Default the size of buffers allocated for ndd interface functions
 */
#define	XGELL_STATS_BUFSIZE			8192
#define	XGELL_PCICONF_BUFSIZE			2048
#define	XGELL_ABOUT_BUFSIZE			512
#define	XGELL_IOCTL_BUFSIZE			64
#define	XGELL_DEVCONF_BUFSIZE			8192

/*
 * Multiple mac address definitions
 *
 * We'll use whole MAC Addresses Configuration Memory for unicast addresses,
 * since current multicast implementation in HAL is by enabling promise mode.
 */
#define	XGE_RX_MULTI_MAC_ADDRESSES_MAX		8 /* per ring group */

typedef struct {
	int rx_pkt_burst;
	int rx_buffer_total;
	int rx_buffer_post_hiwat;
	int rx_dma_lowat;
	int tx_dma_lowat;
	int lso_enable;
	int msix_enable;
	int grouping;
} xgell_config_t;

typedef struct xgell_multi_mac xgell_multi_mac_t;
typedef struct xgell_rx_ring xgell_rx_ring_t;
typedef struct xgell_tx_ring xgell_tx_ring_t;
typedef struct xgelldev xgelldev_t;

typedef struct xgell_rx_buffer_t {
	struct xgell_rx_buffer_t *next;
	void			*vaddr;
	dma_addr_t		dma_addr;
	ddi_dma_handle_t	dma_handle;
	ddi_acc_handle_t	dma_acch;
	xgell_rx_ring_t		*ring;
	frtn_t			frtn;
} xgell_rx_buffer_t;

/* Buffer pool for one rx ring */
typedef struct xgell_rx_buffer_pool_t {
	uint_t			total;		/* total buffers */
	uint_t			size;		/* buffer size */
	xgell_rx_buffer_t	*head;		/* header pointer */
	uint_t			free;		/* free buffers */
	uint_t			post;		/* posted buffers */
	uint_t			post_hiwat;	/* hiwat to stop post */
	spinlock_t		pool_lock;	/* buffer pool lock */
	boolean_t		live;		/* pool status */
	xgell_rx_buffer_t	*recycle_head;	/* recycle list's head */
	xgell_rx_buffer_t	*recycle_tail;	/* recycle list's tail */
	uint_t			recycle;	/* # of rx buffers recycled */
	spinlock_t		recycle_lock;	/* buffer recycle lock */
} xgell_rx_buffer_pool_t;

struct xgell_multi_mac {
	int			naddr;		/* total supported addresses */
	int			naddrfree;	/* free addresses slots */
	ether_addr_t		mac_addr[XGE_RX_MULTI_MAC_ADDRESSES_MAX];
	boolean_t		mac_addr_set[XGE_RX_MULTI_MAC_ADDRESSES_MAX];
};

typedef uint_t (*intr_func_t)(caddr_t, caddr_t);

typedef struct xgell_intr {
	uint_t			index;
	ddi_intr_handle_t	*handle;	/* DDI interrupt handle */
	intr_func_t		*function;	/* interrupt function */
	caddr_t			arg;		/* interrupt source */
} xgell_intr_t;

struct xgell_rx_ring {
	int			index;
	boolean_t		live;		/* ring active status */
	xge_hal_channel_h	channelh;	/* hardware channel */
	xgelldev_t		*lldev;		/* driver device */
	mac_ring_handle_t	ring_handle;	/* call back ring handle */
	mac_group_handle_t	group_handle;	/* call back group handle */
	uint64_t		ring_gen_num;

	xgell_multi_mac_t	mmac;		/* per group multiple addrs */
	xgell_rx_buffer_pool_t	bf_pool;	/* per ring buffer pool */
	int			received_bytes;	/* total received bytes */
	int			intr_bytes;	/* interrupt received bytes */
	int			poll_bytes;	/* bytes to be polled up */
	int			polled_bytes;	/* total polled bytes */
	mblk_t			*poll_mp;	/* polled messages */

	spinlock_t		ring_lock;	/* per ring lock */
};

struct xgell_tx_ring {
	int			index;
	boolean_t		live;		/* ring active status */
	xge_hal_channel_h	channelh;	/* hardware channel */
	xgelldev_t		*lldev;		/* driver device */
	mac_ring_handle_t	ring_handle;	/* call back ring handle */
	int			sent_bytes;	/* bytes sent though the ring */

	boolean_t		need_resched;
};

struct xgelldev {
	volatile int		is_initialized;
	volatile int		in_reset;
	kmutex_t		genlock;
	mac_handle_t		mh;
	int			instance;
	dev_info_t		*dev_info;
	xge_hal_device_h	devh;
	caddr_t			ndp;
	timeout_id_t		timeout_id;

	int			init_rx_rings;
	int			init_tx_rings;
	int			init_rx_groups;

	int			live_rx_rings;
	int			live_tx_rings;
	xgell_rx_ring_t		rx_ring[XGELL_RX_RING_NUM_DEFAULT];
	xgell_tx_ring_t		tx_ring[XGELL_TX_RING_NUM_DEFAULT];

	int			tx_copied_max;

	xgell_intr_t		intrs[XGELL_MINTR_NUM_DEFAULT];

	ddi_intr_handle_t	*intr_table;
	uint_t			intr_table_size;
	int			intr_type;
	int			intr_cnt;
	uint_t			intr_pri;
	int			intr_cap;

	xgell_config_t		config;
};

typedef struct {
	mblk_t			*mblk;
	ddi_dma_handle_t	dma_handles[XGE_HAL_DEFAULT_FIFO_FRAGS];
	int			handle_cnt;
} xgell_txd_priv_t;

typedef struct {
	xgell_rx_buffer_t	*rx_buffer;
} xgell_rxd_priv_t;

int xgell_device_alloc(xge_hal_device_h devh, dev_info_t *dev_info,
    xgelldev_t **lldev_out);

void xgell_device_free(xgelldev_t *lldev);

int xgell_device_register(xgelldev_t *lldev, xgell_config_t *config);

int xgell_device_unregister(xgelldev_t *lldev);

void xgell_callback_link_up(void *userdata);

void xgell_callback_link_down(void *userdata);

int xgell_onerr_reset(xgelldev_t *lldev);

void xge_device_poll_now(void *data);

int xge_add_intrs(xgelldev_t *lldev);

int xge_enable_intrs(xgelldev_t *lldev);

void xge_disable_intrs(xgelldev_t *lldev);

void xge_rem_intrs(xgelldev_t *lldev);




#ifdef __cplusplus
}
#endif

#endif /* _SYS_XGELL_H */
