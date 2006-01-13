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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#ifdef __cplusplus
extern "C" {
#endif

#define	XGELL_DESC		"Xframe I/II 10Gb Ethernet %I%"
#define	XGELL_IFNAME		"xge"
#define	XGELL_TX_LEVEL_LOW	8
#define	XGELL_TX_LEVEL_HIGH	32

#include <xgehal.h>

#if defined(__sparc) || defined(__amd64)
#define	XGELL_L3_ALIGNED		1
#endif

/* Control driver to copy or DMA received packets */
#define	XGELL_DMA_BUFFER_SIZE_LOWAT		256

/* There default values can be overrided by vaules in xge.conf */
#define	XGELL_RX_BUFFER_TOTAL		(1024 * 6)	/* 6K */
#define	XGELL_RX_BUFFER_POST_HIWAT	(1024 * 3)	/* 3K */
#define	XGELL_RX_BUFFER_RECYCLE_HIWAT	64

#define	XGELL_RING_MAIN_QID		0

/* About 1s */
#define	XGE_DEV_POLL_TICKS drv_usectohz(1000000)

/*
 * If HAL could provide defualt values to all tunables, we'll remove following
 * macros.
 * Before removing, please refer to xgehal-config.h for more details.
 */
#define	XGE_HAL_DEFAULT_USE_HARDCODE		-1

/*
 * The reason to define different values for Link Utilization interrupts is
 * different performance numbers between SPARC and x86 platforms.
 */
#if defined(__sparc)
#define	XGE_HAL_DEFAULT_TX_URANGE_A		2
#define	XGE_HAL_DEFAULT_TX_UFC_A		1
#define	XGE_HAL_DEFAULT_TX_URANGE_B		5
#define	XGE_HAL_DEFAULT_TX_UFC_B		10
#define	XGE_HAL_DEFAULT_TX_URANGE_C		10
#define	XGE_HAL_DEFAULT_TX_UFC_C		40
#define	XGE_HAL_DEFAULT_TX_UFC_D		80
#define	XGE_HAL_DEFAULT_TX_TIMER_CI_EN		1
#define	XGE_HAL_DEFAULT_TX_TIMER_AC_EN		1
#define	XGE_HAL_DEFAULT_TX_TIMER_VAL		4000
#define	XGE_HAL_DEFAULT_INDICATE_MAX_PKTS	128
#define	XGE_HAL_DEFAULT_RX_URANGE_A		2
#define	XGE_HAL_DEFAULT_RX_UFC_A		1
#define	XGE_HAL_DEFAULT_RX_URANGE_B		5
#define	XGE_HAL_DEFAULT_RX_UFC_B		10
#define	XGE_HAL_DEFAULT_RX_URANGE_C		10
#define	XGE_HAL_DEFAULT_RX_UFC_C		40
#define	XGE_HAL_DEFAULT_RX_UFC_D		80
#define	XGE_HAL_DEFAULT_RX_TIMER_AC_EN		1
#define	XGE_HAL_DEFAULT_RX_TIMER_VAL		24
#else
#define	XGE_HAL_DEFAULT_TX_URANGE_A		10
#define	XGE_HAL_DEFAULT_TX_UFC_A		1
#define	XGE_HAL_DEFAULT_TX_URANGE_B		20
#define	XGE_HAL_DEFAULT_TX_UFC_B		10
#define	XGE_HAL_DEFAULT_TX_URANGE_C		50
#define	XGE_HAL_DEFAULT_TX_UFC_C		40
#define	XGE_HAL_DEFAULT_TX_UFC_D		80
#define	XGE_HAL_DEFAULT_TX_TIMER_CI_EN		1
#define	XGE_HAL_DEFAULT_TX_TIMER_AC_EN		1
#define	XGE_HAL_DEFAULT_TX_TIMER_VAL		4000
#define	XGE_HAL_DEFAULT_INDICATE_MAX_PKTS	128
#define	XGE_HAL_DEFAULT_RX_URANGE_A		10
#define	XGE_HAL_DEFAULT_RX_UFC_A		1
#define	XGE_HAL_DEFAULT_RX_URANGE_B		20
#define	XGE_HAL_DEFAULT_RX_UFC_B		10
#define	XGE_HAL_DEFAULT_RX_URANGE_C		50
#define	XGE_HAL_DEFAULT_RX_UFC_C		40
#define	XGE_HAL_DEFAULT_RX_UFC_D		80
#define	XGE_HAL_DEFAULT_RX_TIMER_AC_EN		1
#define	XGE_HAL_DEFAULT_RX_TIMER_VAL		24
#endif

#define	XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_J	2048
#define	XGE_HAL_DEFAULT_FIFO_QUEUE_LENGTH_N	4096
#define	XGE_HAL_DEFAULT_FIFO_QUEUE_INTR		0
#define	XGE_HAL_DEFAULT_FIFO_RESERVE_THRESHOLD	0
#define	XGE_HAL_DEFAULT_FIFO_MEMBLOCK_SIZE	PAGESIZE

#ifdef XGELL_TX_NOMAP_COPY

#define	XGE_HAL_DEFAULT_FIFO_FRAGS		1
#define	XGE_HAL_DEFAULT_FIFO_FRAGS_THRESHOLD	0
#define	XGE_HAL_DEFAULT_FIFO_ALIGNMENT_SIZE	(XGE_HAL_MAC_HEADER_MAX_SIZE + \
						XGE_HAL_DEFAULT_MTU)
#define	XGE_HAL_DEFAULT_FIFO_MAX_ALIGNED_FRAGS	1
#else

#if defined(__x86)
#define	XGE_HAL_DEFAULT_FIFO_FRAGS		32
#else
#define	XGE_HAL_DEFAULT_FIFO_FRAGS		16
#endif
#define	XGE_HAL_DEFAULT_FIFO_FRAGS_THRESHOLD	4
#define	XGE_HAL_DEFAULT_FIFO_ALIGNMENT_SIZE	sizeof (uint64_t)
#define	XGE_HAL_DEFAULT_FIFO_MAX_ALIGNED_FRAGS	6

#endif /* XGELL_TX_NOMAP_COPY */

#define	XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS_J	16
#define	XGE_HAL_DEFAULT_RING_QUEUE_BLOCKS_N	32
#define	XGE_HAL_RING_QUEUE_BUFFER_MODE_DEFAULT	1
#define	XGE_HAL_DEFAULT_RING_QUEUE_SIZE		64
#define	XGE_HAL_DEFAULT_BACKOFF_INTERVAL_US	35
#define	XGE_HAL_DEFAULT_RING_PRIORITY		0
#define	XGE_HAL_DEFAULT_RING_MEMBLOCK_SIZE	PAGESIZE

#define	XGE_HAL_DEFAULT_RING_NUM		8
#define	XGE_HAL_DEFAULT_TMAC_UTIL_PERIOD	5
#define	XGE_HAL_DEFAULT_RMAC_UTIL_PERIOD	5
#define	XGE_HAL_DEFAULT_RMAC_HIGH_PTIME		65535
#define	XGE_HAL_DEFAULT_MC_PAUSE_THRESHOLD_Q0Q3	187
#define	XGE_HAL_DEFAULT_MC_PAUSE_THRESHOLD_Q4Q7	187
#define	XGE_HAL_DEFAULT_INITIAL_MTU		XGE_HAL_DEFAULT_MTU /* 1500 */
#define	XGE_HAL_DEFAULT_ISR_POLLING_CNT		4
#define	XGE_HAL_DEFAULT_LATENCY_TIMER		255
#define	XGE_HAL_DEFAULT_SPLIT_TRANSACTION	1 /* 2 splits */
#define	XGE_HAL_DEFAULT_BIOS_MMRB_COUNT		-1
#define	XGE_HAL_DEFAULT_MMRB_COUNT		1 /* 1k */
#define	XGE_HAL_DEFAULT_SHARED_SPLITS		0
#define	XGE_HAL_DEFAULT_STATS_REFRESH_TIME	1
#define	XGE_HAL_PCI_FREQ_MHERZ_DEFAULT		133

/*
 * default the size of buffers allocated for ndd interface functions
 */
#define	XGELL_STATS_BUFSIZE			4096
#define	XGELL_PCICONF_BUFSIZE			2048
#define	XGELL_ABOUT_BUFSIZE			512
#define	XGELL_IOCTL_BUFSIZE			64
#define	XGELL_DEVCONF_BUFSIZE			4096

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
	int rx_buffer_total;
	int rx_buffer_post_hiwat;
	int rx_buffer_recycle_hiwat;
} xgell_config_t;

typedef struct xgell_rx_buffer_t {
	struct xgell_rx_buffer_t	*next;
	void				*vaddr;
	dma_addr_t			dma_addr;
	ddi_dma_handle_t		dma_handle;
	ddi_acc_handle_t		dma_acch;
	void				*lldev;
	frtn_t				frtn;
#ifdef XGELL_L3_ALIGNED
	unsigned char			header[XGE_HAL_TCPIP_HEADER_MAX_SIZE * 2
					+ 8];
#endif
} xgell_rx_buffer_t;

/* Buffer pool for all rings */
typedef struct xgell_rx_buffer_pool_t {
	uint_t			total;		/* total buffers */
	uint_t			size;		/* buffer size */
	xgell_rx_buffer_t	*head;		/* header pointer */
	uint_t			recycle_hiwat;	/* hiwat to recycle */
	uint_t			free;		/* free buffers */
	uint_t			post;		/* posted buffers */
	uint_t			post_hiwat;	/* hiwat to stop post */
	spinlock_t		pool_lock;	/* buffer pool lock */
} xgell_rx_buffer_pool_t;

typedef struct xgell_ring_t {
	xge_hal_channel_h	channelh;
	mac_t			*macp;
	mac_resource_handle_t	handle;		/* per ring cookie */
} xgell_ring_t;

typedef struct {
	caddr_t			ndp;
	mac_t			*macp;
	int			instance;
	dev_info_t		*dev_info;
	xge_hal_device_h	devh;
	xgell_ring_t		ring_main;
	xgell_rx_buffer_pool_t	bf_pool;
	int			resched_avail;
	int			resched_send;
	int			resched_retry;
	xge_hal_channel_h	fifo_channel;
	volatile int		is_initialized;
	xgell_config_t		config;
	volatile int		in_reset;
	timeout_id_t		timeout_id;
	kmutex_t		genlock;
} xgelldev_t;

typedef struct {
	mblk_t			*mblk;
#if !defined(XGELL_TX_NOMAP_COPY)
	ddi_dma_handle_t	dma_handles[XGE_HAL_DEFAULT_FIFO_FRAGS];
	int			handle_cnt;
#endif
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

#ifdef __cplusplus
}
#endif

#endif /* _SYS_XGELL_H */
