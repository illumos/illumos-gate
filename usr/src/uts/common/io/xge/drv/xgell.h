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

#include <sys/mac.h>
#include <sys/mac_ether.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	XGELL_DESC		"Xframe I/II 10Gb Ethernet"
#define	XGELL_IFNAME		"xge"
#define	XGELL_TX_LEVEL_LOW	8
#define	XGELL_TX_LEVEL_HIGH	32
#define	XGELL_TX_LEVEL_CHECK	3
#define	XGELL_MAX_RING_DEFAULT	8
#define	XGELL_MAX_FIFO_DEFAULT	1

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

/* Control driver to copy or DMA received packets */
#define	XGELL_RX_DMA_LOWAT		256

#define	XGELL_RING_MAIN_QID		0

#if defined(__x86)
#define	XGELL_TX_DMA_LOWAT		128
#else
#define	XGELL_TX_DMA_LOWAT		512
#endif

/*
 * Try to collapse up to XGELL_RX_PKT_BURST packets into single mblk
 * sequence before mac_rx() is called.
 */
#define	XGELL_RX_PKT_BURST		32

/* About 1s */
#define	XGE_DEV_POLL_TICKS drv_usectohz(1000000)

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
#if defined(__x86)
#define	XGE_HAL_DEFAULT_FIFO_FRAGS		128
#else
#define	XGE_HAL_DEFAULT_FIFO_FRAGS		64
#endif
#define	XGE_HAL_DEFAULT_FIFO_FRAGS_THRESHOLD	18

#define	XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS_J	2
#define	XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS_N	2
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
#define	XGE_HAL_DEFAULT_MMRB_COUNT		\
		XGE_HAL_MAX_MMRB_COUNT
#define	XGE_HAL_DEFAULT_SPLIT_TRANSACTION	\
		XGE_HAL_EIGHT_SPLIT_TRANSACTION
#else
#define	XGE_HAL_DEFAULT_MMRB_COUNT		1 /* 1k */
#define	XGE_HAL_DEFAULT_SPLIT_TRANSACTION	\
		XGE_HAL_TWO_SPLIT_TRANSACTION
#endif

/*
 * default the size of buffers allocated for ndd interface functions
 */
#define	XGELL_STATS_BUFSIZE			8192
#define	XGELL_PCICONF_BUFSIZE			2048
#define	XGELL_ABOUT_BUFSIZE			512
#define	XGELL_IOCTL_BUFSIZE			64
#define	XGELL_DEVCONF_BUFSIZE			8192

/*
 * xgell_event_e
 *
 * This enumeration derived from xgehal_event_e. It extends it
 * for the reason to get serialized context.
 */
/* Renamb the macro from HAL */
#define	XGELL_EVENT_BASE	XGE_LL_EVENT_BASE
typedef enum xgell_event_e {
	/* LL events */
	XGELL_EVENT_RESCHED_NEEDED	= XGELL_EVENT_BASE + 1,
} xgell_event_e;

typedef struct {
	int rx_pkt_burst;
	int rx_buffer_total;
	int rx_buffer_post_hiwat;
	int rx_dma_lowat;
	int tx_dma_lowat;
	int msix_enable;
	int lso_enable;
} xgell_config_t;

typedef struct xgell_ring xgell_ring_t;
typedef struct xgell_fifo xgell_fifo_t;

typedef struct xgell_rx_buffer_t {
	struct xgell_rx_buffer_t	*next;
	void				*vaddr;
	dma_addr_t			dma_addr;
	ddi_dma_handle_t		dma_handle;
	ddi_acc_handle_t		dma_acch;
	xgell_ring_t			*ring;
	frtn_t				frtn;
} xgell_rx_buffer_t;

/* Buffer pool for all rings */
typedef struct xgell_rx_buffer_pool_t {
	uint_t			total;		/* total buffers */
	uint_t			size;		/* buffer size */
	xgell_rx_buffer_t	*head;		/* header pointer */
	uint_t			free;		/* free buffers */
	uint_t			post;		/* posted buffers */
	uint_t			post_hiwat;	/* hiwat to stop post */
	spinlock_t		pool_lock;	/* buffer pool lock */
	xgell_rx_buffer_t	*recycle_head;	/* recycle list's head */
	xgell_rx_buffer_t	*recycle_tail;	/* recycle list's tail */
	uint_t			recycle;	/* # of rx buffers recycled */
	spinlock_t		recycle_lock;	/* buffer recycle lock */
} xgell_rx_buffer_pool_t;

typedef struct xgelldev xgelldev_t;

struct xgell_ring {
	xge_hal_channel_h	channelh;
	xgelldev_t		*lldev;
	mac_resource_handle_t	handle;		/* per ring cookie */
	xgell_rx_buffer_pool_t	bf_pool;
};

struct xgell_fifo {
	xge_hal_channel_h	channelh;
	xgelldev_t		*lldev;
	int			level_low;
};

struct xgelldev {
	caddr_t			ndp;
	mac_handle_t		mh;
	int			instance;
	dev_info_t		*dev_info;
	xge_hal_device_h	devh;
	xgell_ring_t		rings[XGE_HAL_MAX_RING_NUM];
	xgell_fifo_t		fifos[XGE_HAL_MAX_FIFO_NUM];
	int			resched_avail;
	int			resched_send;
	int			resched_retry;
	int			tx_copied_max;
	volatile int		is_initialized;
	xgell_config_t		config;
	volatile int		in_reset;
	timeout_id_t		timeout_id;
	kmutex_t		genlock;
	ddi_intr_handle_t	*intr_table;
	uint_t			intr_table_size;
	int			intr_type;
	int			intr_cnt;
	uint_t			intr_pri;
	int			intr_cap;
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
