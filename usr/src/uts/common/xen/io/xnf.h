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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_XNF_H
#define	_SYS_XNF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	NET_TX_RING_SIZE  __RING_SIZE((netif_tx_sring_t *)0, PAGESIZE)
#define	NET_RX_RING_SIZE  __RING_SIZE((netif_rx_sring_t *)0, PAGESIZE)

#define	XNF_MAXPKT	1500		/* MTU size */
#define	XNF_FRAMESIZE	1514		/* frame size including MAC header */

#define	XNF_MAX_RXDESCS	256

/* Watermark for causing "interrupt on completion" for outgoing packets */
#define	XNF_TX_FREE_THRESH	(NET_TX_RING_SIZE / 10)

#define	MCAST_HASHBITS		256

extern int	xnf_diagnose;	/* Available for use any time. */

/* Flags to set in the global xnf_diagnose */
#define	XNF_DIAG_RX		0x01
#define	XNF_DIAG_TX		0x02
#define	XNF_DIAG_STATS		0x04
#define	XNF_DIAG_RX_BUFS	0x08

/* DEBUG flags */
#define	XNF_DEBUG_DDI		0x01
#define	XNF_DEBUG_TRACE		0x02
#define	XNF_DEBUG_SEND		0x04
#define	XNF_DEBUG_INT		0x08

#define	XNF_DESC_ALIGN		8


/* Info pertaining to each xmit/receive buffer */
struct xnf_buffer_desc {
	frtn_t			free_rtn;	/* desballoc() structure */
	struct xnf		*xnfp;
	ddi_dma_handle_t	dma_handle;
	caddr_t			buf;		/* DMA-able data buffer */
	paddr_t			buf_phys;
	struct xnf_buffer_desc	*next;	/* For linking into free list */
	ddi_acc_handle_t	acc_handle;
	grant_ref_t		grant_ref;	/* grant table reference */
	uint16_t		id;		/* buffer id */
};

/* Various information about each transmit packet */
struct tx_pktinfo {
	mblk_t			*mp;	/* mblk associated with packet */
	ddi_dma_handle_t	dma_handle;
	struct xnf_buffer_desc	*bdesc; /* pointer to buffer descriptor */
	grant_ref_t		grant_ref;	/* grant table reference */
	uint16_t		id;	/* tx pkt id/free list next pointer */
};

/* Per network-interface-controller driver private structure */
typedef struct xnf {
	/* most interesting stuff first to assist debugging */
	dev_info_t		*xnf_devinfo;	/* System per-device info. */
	mac_handle_t		xnf_mh;		/* Nemo per-device info. */
	int			xnf_rx_bufs_outstanding;
	int			xnf_tx_descs_free;
	int			xnf_rx_descs_free; /* count of free rx bufs */
	int			xnf_n_tx;	/* No. xmit descriptors */
	int			xnf_n_rx;	/* No. recv descriptors */
	int			xnf_n_rx_bufs;	/* No. recv DMA buffers */
	int			xnf_tx_start_thresh_regval;
	unsigned char		xnf_mac_addr[ETHERADDRL];
	int			xnf_max_rx_bufs;
	int			xnf_rx_buffer_count;
	int			xnf_tx_buffer_count;

	boolean_t		xnf_connected;
	boolean_t		xnf_running;

	boolean_t		xnf_cksum_offload;

	uint64_t		xnf_stat_interrupts;
	uint64_t		xnf_stat_unclaimed_interrupts;
	uint64_t		xnf_stat_norxbuf;
	uint64_t		xnf_stat_errrx;

	uint64_t		xnf_stat_tx_attempt;
	uint64_t		xnf_stat_tx_pullup;
	uint64_t		xnf_stat_tx_pagebndry;
	uint64_t		xnf_stat_tx_defer;
	uint64_t		xnf_stat_rx_no_ringbuf;
	uint64_t		xnf_stat_mac_rcv_error;
	uint64_t		xnf_stat_runt;

	uint64_t		xnf_stat_ipackets;
	uint64_t		xnf_stat_opackets;
	uint64_t		xnf_stat_rbytes;
	uint64_t		xnf_stat_obytes;

	uint64_t		xnf_stat_tx_cksum_deferred;
	uint64_t		xnf_stat_rx_cksum_no_need;
	uint64_t		xnf_stat_hvcopy_enabled; /* on/off */
	uint64_t		xnf_stat_hvcopy_packet_processed;

	kstat_t			*xnf_kstat_aux;

	struct xnf_buffer_desc	*xnf_free_list;
	struct xnf_buffer_desc	*xnf_tx_free_list;
	int			xnf_tx_pkt_id_list;
				/* free list of avail pkt ids */
	struct tx_pktinfo	xnf_tx_pkt_info[NET_TX_RING_SIZE];
	struct xnf_buffer_desc	*xnf_rxpkt_bufptr[XNF_MAX_RXDESCS];

	mac_resource_handle_t	xnf_rx_handle;
	ddi_iblock_cookie_t	xnf_icookie;
	kmutex_t		xnf_tx_buf_mutex;
	kmutex_t		xnf_rx_buf_mutex;
	kmutex_t		xnf_txlock;
	kmutex_t		xnf_intrlock;
	boolean_t		xnf_tx_pages_readonly;

	netif_tx_front_ring_t	xnf_tx_ring;	/* tx interface struct ptr */
	ddi_dma_handle_t	xnf_tx_ring_dma_handle;
	ddi_acc_handle_t	xnf_tx_ring_dma_acchandle;
	paddr_t			xnf_tx_ring_phys_addr;
	grant_ref_t		xnf_tx_ring_ref;

	netif_rx_front_ring_t	xnf_rx_ring;	/* rx interface struct ptr */
	ddi_dma_handle_t	xnf_rx_ring_dma_handle;
	ddi_acc_handle_t	xnf_rx_ring_dma_acchandle;
	paddr_t			xnf_rx_ring_phys_addr;
	grant_ref_t		xnf_rx_ring_ref;

	uint16_t		xnf_evtchn;	/* channel to back end ctlr */
	grant_ref_t		xnf_gref_tx_head;	/* tx grant free list */
	grant_ref_t		xnf_gref_rx_head;	/* rx grant free list */
	kcondvar_t		xnf_cv;

	boolean_t		xnf_rx_hvcopy;	/* do we do HV copy? */
} xnf_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XNF_H */
