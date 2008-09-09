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
 *
 * xnb.h - definitions for Xen dom0 network driver
 */

#ifndef _SYS_XNB_H
#define	_SYS_XNB_H

#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/stream.h>
#include <sys/ethernet.h>
#include <sys/hypervisor.h>
#include <xen/public/io/netif.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	NET_TX_RING_SIZE  __RING_SIZE((netif_tx_sring_t *)0, PAGESIZE)
#define	NET_RX_RING_SIZE  __RING_SIZE((netif_rx_sring_t *)0, PAGESIZE)

#define	XNBMAXPKT	1500		/* MTU size */

/* DEBUG flags */
#define	XNBDDI		0x01
#define	XNBTRACE	0x02
#define	XNBSEND		0x04
#define	XNBRECV		0x08
#define	XNBINTR		0x10
#define	XNBRING		0x20
#define	XNBCKSUM	0x40

typedef struct xnb xnb_t;

/*
 * The xnb module provides core inter-domain network protocol functionality.
 * It is connected to the rest of Solaris in two ways:
 * - as a GLDv3 driver (with xnbu),
 * - as a GLDv3 consumer (with xnbo).
 *
 * The different modes of operation are termed "flavours" and each
 * instance of an xnb based driver operates in one and only one mode.
 * The common xnb driver exports a set of functions to these drivers
 * (declarations at the foot of this file) and calls back into the
 * drivers via the xnb_flavour_t structure.
 */
typedef struct xnb_flavour {
	void		(*xf_recv)(xnb_t *, mblk_t *);
	void		(*xf_peer_connected)(xnb_t *);
	void		(*xf_peer_disconnected)(xnb_t *);
	boolean_t	(*xf_hotplug_connected)(xnb_t *);
	mblk_t		*(*xf_cksum_from_peer)(xnb_t *, mblk_t *, uint16_t);
	uint16_t	(*xf_cksum_to_peer)(xnb_t *, mblk_t *);
} xnb_flavour_t;

typedef struct xnb_rxbuf {
	frtn_t			xr_free_rtn;
	xnb_t			*xr_xnbp;
	gnttab_map_grant_ref_t	xr_mop;
	RING_IDX		xr_id;
	uint16_t		xr_status;
	unsigned int		xr_flags;

#define	XNB_RXBUF_INUSE	0x01

} xnb_rxbuf_t;

/* Per network-interface-controller driver private structure */
struct xnb {
	/* most interesting stuff first to assist debugging */
	dev_info_t		*xnb_devinfo;	/* System per-device info. */

	xnb_flavour_t		*xnb_flavour;
	void			*xnb_flavour_data;

	boolean_t		xnb_irq;
	unsigned char		xnb_mac_addr[ETHERADDRL];

	uint64_t		xnb_stat_ipackets;
	uint64_t		xnb_stat_opackets;
	uint64_t		xnb_stat_rbytes;
	uint64_t		xnb_stat_obytes;

	uint64_t		xnb_stat_intr;
	uint64_t		xnb_stat_xmit_defer;

	uint64_t		xnb_stat_tx_cksum_deferred;
	uint64_t		xnb_stat_rx_cksum_no_need;

	uint64_t		xnb_stat_tx_rsp_notok;

	uint64_t		xnb_stat_tx_notify_sent;
	uint64_t		xnb_stat_tx_notify_deferred;

	uint64_t		xnb_stat_rx_notify_sent;
	uint64_t		xnb_stat_rx_notify_deferred;

	uint64_t		xnb_stat_tx_too_early;
	uint64_t		xnb_stat_rx_too_early;
	uint64_t		xnb_stat_rx_allocb_failed;
	uint64_t		xnb_stat_tx_allocb_failed;
	uint64_t		xnb_stat_tx_foreign_page;
	uint64_t		xnb_stat_mac_full;
	uint64_t		xnb_stat_spurious_intr;
	uint64_t		xnb_stat_allocation_success;
	uint64_t		xnb_stat_allocation_failure;
	uint64_t		xnb_stat_small_allocation_success;
	uint64_t		xnb_stat_small_allocation_failure;
	uint64_t		xnb_stat_other_allocation_failure;

	uint64_t		xnb_stat_tx_pagebndry_crossed;
	uint64_t		xnb_stat_tx_cpoparea_grown;

	uint64_t		xnb_stat_csum_hardware;
	uint64_t		xnb_stat_csum_software;

	kstat_t			*xnb_kstat_aux;

	boolean_t		xnb_cksum_offload;

	ddi_iblock_cookie_t	xnb_icookie;

	kmutex_t		xnb_rx_lock;
	kmutex_t		xnb_tx_lock;

	int			xnb_rx_unmop_count;
	int			xnb_rx_buf_count;
	boolean_t		xnb_rx_pages_writable;
	boolean_t		xnb_rx_always_copy;

	netif_rx_back_ring_t	xnb_rx_ring;	/* rx interface struct ptr */
	void			*xnb_rx_ring_addr;
	grant_ref_t		xnb_rx_ring_ref;
	grant_handle_t		xnb_rx_ring_handle;

	netif_tx_back_ring_t	xnb_tx_ring;	/* tx interface struct ptr */
	void			*xnb_tx_ring_addr;
	grant_ref_t		xnb_tx_ring_ref;
	grant_handle_t		xnb_tx_ring_handle;

	boolean_t		xnb_connected;
	boolean_t		xnb_hotplugged;
	boolean_t		xnb_detachable;
	int			xnb_evtchn;	/* channel to front end */
	domid_t			xnb_peer;

	xnb_rxbuf_t			*xnb_rx_bufp[NET_TX_RING_SIZE];
	gnttab_map_grant_ref_t		xnb_rx_mop[NET_TX_RING_SIZE];
	gnttab_unmap_grant_ref_t	xnb_rx_unmop[NET_TX_RING_SIZE];

	/* store information for unmop */
	xnb_rxbuf_t		*xnb_rx_unmop_rxp[NET_TX_RING_SIZE];

	caddr_t			xnb_tx_va;
	gnttab_transfer_t	xnb_tx_top[NET_RX_RING_SIZE];

	boolean_t		xnb_hv_copy;	/* do we do hypervisor copy? */
	gnttab_copy_t		*xnb_tx_cpop;
#define	CPOP_DEFCNT 	8
	size_t			xnb_cpop_sz; 	/* in elements, not bytes */
};

extern int xnb_attach(dev_info_t *, xnb_flavour_t *, void *);
extern void xnb_detach(dev_info_t *);
extern mblk_t *xnb_copy_to_peer(xnb_t *, mblk_t *);
extern mblk_t *xnb_process_cksum_flags(xnb_t *, mblk_t *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_XNB_H */
