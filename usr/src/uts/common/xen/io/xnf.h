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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_XNF_H
#define	_SYS_XNF_H

#ifdef __cplusplus
extern "C" {
#endif

#define	NET_TX_RING_SIZE  __CONST_RING_SIZE(netif_tx, PAGESIZE)
#define	NET_RX_RING_SIZE  __CONST_RING_SIZE(netif_rx, PAGESIZE)

#define	XNF_MAXPKT	1500		/* MTU size */
#define	XNF_FRAMESIZE	1514		/* frame size including MAC header */

/* DEBUG flags */
#define	XNF_DEBUG_DDI		0x01
#define	XNF_DEBUG_TRACE		0x02

/*
 * Information about each receive buffer and any transmit look-aside
 * buffers.
 */
typedef struct xnf_buf {
	frtn_t			free_rtn;
	struct xnf		*xnfp;
	ddi_dma_handle_t	dma_handle;
	caddr_t			buf;		/* DMA-able data buffer */
	paddr_t			buf_phys;
	mfn_t			buf_mfn;
	size_t			len;
	struct xnf_buf		*next;	/* For linking into free list */
	ddi_acc_handle_t	acc_handle;
	grant_ref_t		grant_ref;	/* grant table reference */
	uint16_t		id;		/* buffer id */
	unsigned int		gen;
} xnf_buf_t;

/*
 * Information about each transmit buffer.
 */
typedef struct xnf_txbuf {
	struct xnf_txbuf	*tx_next;
	mblk_t			*tx_mp;	/* mblk associated with packet */
	netif_tx_request_t	tx_txreq;
	caddr_t			tx_bufp;
	ddi_dma_handle_t	tx_dma_handle;
	mfn_t			tx_mfn;
	xnf_buf_t		*tx_bdesc; /* Look-aside buffer, if used. */
	unsigned char		tx_type;
	int16_t			tx_status;
	RING_IDX		tx_slot;

#define	TX_DATA		1
#define	TX_MCAST_REQ	2
#define	TX_MCAST_RSP	3
} xnf_txbuf_t;

/*
 * Information about each outstanding transmit operation.
 */
typedef struct xnf_txid {
	uint16_t	id;	/* Id of this transmit buffer. */
	uint16_t	next;	/* Freelist of ids. */
	xnf_txbuf_t	*txbuf;	/* Buffer details. */
} xnf_txid_t;

/*
 * Per-instance data.
 */
typedef struct xnf {
	/* most interesting stuff first to assist debugging */
	dev_info_t		*xnf_devinfo;
	mac_handle_t		xnf_mh;
	unsigned char		xnf_mac_addr[ETHERADDRL];

	unsigned int		xnf_gen;	/* Increments on resume. */

	boolean_t		xnf_connected;
	boolean_t		xnf_running;

	boolean_t		xnf_be_rx_copy;
	boolean_t		xnf_be_mcast_control;

	uint64_t		xnf_stat_interrupts;
	uint64_t		xnf_stat_unclaimed_interrupts;
	uint64_t		xnf_stat_norxbuf;
	uint64_t		xnf_stat_drop;
	uint64_t		xnf_stat_errrx;

	uint64_t		xnf_stat_tx_attempt;
	uint64_t		xnf_stat_tx_pullup;
	uint64_t		xnf_stat_tx_pagebndry;
	uint64_t		xnf_stat_tx_defer;
	uint64_t		xnf_stat_mac_rcv_error;
	uint64_t		xnf_stat_runt;

	uint64_t		xnf_stat_ipackets;
	uint64_t		xnf_stat_opackets;
	uint64_t		xnf_stat_rbytes;
	uint64_t		xnf_stat_obytes;

	uint64_t		xnf_stat_tx_cksum_deferred;
	uint64_t		xnf_stat_rx_cksum_no_need;

	uint64_t		xnf_stat_buf_allocated;
	uint64_t		xnf_stat_buf_outstanding;
	uint64_t		xnf_stat_gref_outstanding;
	uint64_t		xnf_stat_gref_failure;
	uint64_t		xnf_stat_gref_peak;
	uint64_t		xnf_stat_rx_allocb_fail;
	uint64_t		xnf_stat_rx_desballoc_fail;

	kstat_t			*xnf_kstat_aux;

	ddi_iblock_cookie_t	xnf_icookie;

	netif_tx_front_ring_t	xnf_tx_ring;
	ddi_dma_handle_t	xnf_tx_ring_dma_handle;
	ddi_acc_handle_t	xnf_tx_ring_dma_acchandle;
	paddr_t			xnf_tx_ring_phys_addr;
	grant_ref_t		xnf_tx_ring_ref;

	xnf_txid_t		xnf_tx_pkt_id[NET_TX_RING_SIZE];
	uint16_t		xnf_tx_pkt_id_head;
	kmutex_t		xnf_txlock;
	kmutex_t		xnf_schedlock;
	boolean_t		xnf_need_sched;
	kcondvar_t		xnf_cv_tx_slots;
	kmem_cache_t		*xnf_tx_buf_cache;

	netif_rx_front_ring_t	xnf_rx_ring;
	ddi_dma_handle_t	xnf_rx_ring_dma_handle;
	ddi_acc_handle_t	xnf_rx_ring_dma_acchandle;
	paddr_t			xnf_rx_ring_phys_addr;
	grant_ref_t		xnf_rx_ring_ref;

	xnf_buf_t		*xnf_rx_pkt_info[NET_RX_RING_SIZE];
	kmutex_t		xnf_rxlock;
	mblk_t			*xnf_rx_head;
	mblk_t			*xnf_rx_tail;
	boolean_t		xnf_rx_new_buffers_posted;
	kmem_cache_t		*xnf_buf_cache;

	uint16_t		xnf_evtchn;

	kmutex_t		xnf_gref_lock;
	grant_ref_t		xnf_gref_head;

	kcondvar_t		xnf_cv_state;
	kcondvar_t		xnf_cv_multicast;
	uint_t			xnf_pending_multicast;
} xnf_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XNF_H */
