/*
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

#ifndef _IF_HNVAR_H_
#define	_IF_HNVAR_H_

#include <sys/ethernet.h>
#include <sys/mac.h>
#include <sys/mutex.h>
#include <sys/debug.h>

#include <sys/vmbus.h>
#include <sys/hyperv_busdma.h>

#include "ndis.h"

#define	HN_CHIM_SIZE			(15 * 1024 * 1024)

#define	HN_RXBUF_SIZE			(16 * 1024 * 1024)
#define	HN_RXBUF_SIZE_COMPAT		(15 * 1024 * 1024)

/* Claimed to be 12232B */
#define	HN_MTU_MAX			(9 * 1024)
#define	HN_MTU_MIN			60

#define	HN_TXBR_SIZE			(128 * PAGESIZE)
#define	HN_RXBR_SIZE			(128 * PAGESIZE)

#define	HN_XACT_REQ_PGCNT		2
#define	HN_XACT_RESP_PGCNT		2
#define	HN_XACT_REQ_SIZE		(HN_XACT_REQ_PGCNT * PAGESIZE)
#define	HN_XACT_RESP_SIZE		(HN_XACT_RESP_PGCNT * PAGESIZE)

#define	HN_GPACNT_MAX			32

#define	HN_RING_CNT_DEF_MAX		8

#define	HN_DEFAULT_TRUST_HOST_CKSUM	B_FALSE

struct hn_txdesc;
struct buf_ring;
struct hn_tx_ring;

typedef struct hn_rx_stats {
	uint64_t	pkts;
	uint64_t	mcast_pkts;
	uint64_t	bcast_pkts;
	uint64_t	bytes;
	uint64_t	norxbufs;
	uint64_t	ierrors;
	uint64_t	csum_ip;
	uint64_t	csum_tcp;
	uint64_t	csum_udp;
	uint64_t	csum_trusted;
} hn_rx_stats_t;

struct hn_rx_ring {
	struct hn_softc	*hn_sc;
	struct hn_tx_ring *hn_txr;
	void		*hn_pktbuf;
	int		hn_pktbuf_len;
	uint8_t		*hn_rxbuf;	/* shadow sc->hn_rxbuf */
	int		hn_rx_idx;
	kmutex_t	hn_rx_lock;
	mblk_t		*hn_mps;
	mblk_t		*hn_mp_tail;

	/* Trust csum verification on host side */
	int		hn_trust_hcsum;	/* HN_TRUST_HCSUM_ */

	hn_rx_stats_t	hn_rx_stats;	/* protected by hn_rx_lock */

	/* GLD related */
	mac_ring_handle_t hn_ring_handle;
	uint64_t	hn_ring_gen_num;
	ulong_t		hn_ack_failed;

	/* Rarely used stuffs */
	int		hn_rx_flags;

	void		*hn_br;		/* TX/RX bufring */
	struct hyperv_dma hn_br_dma;
} __aligned(CACHE_LINE_SIZE);

#define	HN_TRUST_HCSUM_IP	0x0001
#define	HN_TRUST_HCSUM_TCP	0x0002
#define	HN_TRUST_HCSUM_UDP	0x0004
#define	HN_TRUST_HCSUM_ALL	(HN_TRUST_HCSUM_IP | HN_TRUST_HCSUM_TCP | \
    HN_TRUST_HCSUM_UDP)

#define	HN_RX_FLAG_ATTACHED	0x0001
#define	HN_RX_FLAG_BR_REF	0x0002

typedef struct hn_tx_stats {
	uint64_t	pkts;
	uint64_t	mcast_pkts;
	uint64_t	bcast_pkts;
	uint64_t	bytes;
	uint64_t	no_txdescs;
	uint64_t	send_failed;
	uint64_t	pulledup;
	uint64_t	chimney_tried;
	uint64_t	chimney_sent;
	uint64_t	dma_failed;
} hn_tx_stats_t;

typedef enum hn_pkt_type {
	HN_UNICAST,
	HN_MULTICAST,
	HN_BROADCAST
} hn_pkt_type_t;

struct hn_tx_ring {
	struct hn_softc	*hn_sc;
	struct buf_ring	*hn_txdesc_br;
	int		hn_txdesc_cnt;
	int		hn_txdesc_avail;
	int		hn_tx_idx;
	int		hn_tx_flags;
	kmutex_t	hn_tx_lock;
	struct vmbus_channel *hn_chan;
	int		hn_chim_size;

	/* info about next packet to send */
	int		(*hn_sendpkt)(struct hn_tx_ring *, struct hn_txdesc *);
	hn_pkt_type_t	hn_pkt_type;
	int		hn_pkt_length;

	ddi_dma_handle_t hn_data_dmah;
	boolean_t	hn_suspended;
	int		hn_gpa_cnt;
	struct vmbus_gpa hn_gpa[HN_GPACNT_MAX];
	hn_tx_stats_t	hn_tx_stats;	/* protected by hn_tx_lock */
	boolean_t	hn_reschedule;	/* flow control (br empty, etc.) */
	mac_ring_handle_t hn_ring_handle;
	struct hn_txdesc *hn_txdesc;
} __aligned(CACHE_LINE_SIZE);

#define	HN_TX_FLAG_ATTACHED	0x0001
#define	HN_TX_FLAG_HASHVAL	0x0002	/* support HASHVAL pktinfo */

typedef struct hn_rx_group {
	uint32_t		index;		/* Group index */
	mac_group_handle_t	group_handle;   /* call back group handle */
	struct hn_softc		*sc;		/* Pointer to the driver */
} hn_rx_group_t;

typedef struct hn_kstats {
	kstat_named_t	tx_ring_cnt;
	kstat_named_t	tx_ring_inuse;
	kstat_named_t	rx_ring_cnt;
	kstat_named_t	rx_ring_inuse;

	kstat_named_t	tx_send_failed;
	kstat_named_t	tx_no_descs;
	kstat_named_t	tx_mblk_pulledup;
	kstat_named_t	tx_chimney_tried;
	kstat_named_t	tx_chimney_sent;
	kstat_named_t	tx_dma_failed;
	kstat_named_t	tx_descs_used;

	kstat_named_t	rx_no_bufs;
	kstat_named_t	rx_csum_ip;
	kstat_named_t	rx_csum_tcp;
	kstat_named_t	rx_csum_udp;
	kstat_named_t	rx_csum_trusted;
} hn_kstats_t;

/*
 * Device-specific softc structure
 */
struct hn_softc {
	dev_info_t		*hn_dev;
	int			hn_instance;
	boolean_t		hn_running;
	mac_handle_t		hn_mac_hdl;
	boolean_t		hn_promiscuous;
	uint8_t			hn_macaddr[ETHERADDRL];
	boolean_t		hn_mac_addr_set;
	int			hn_mtu;
	boolean_t		hn_tx_hcksum_enable;
	uint32_t		hn_hcksum_flags;
	boolean_t		hn_lso_enable;
	uint32_t		hn_lso_flags;
	int			hn_txdesc_cnt;
	kmutex_t		hn_lock;
	struct vmbus_channel	*hn_prichan;
	kstat_t			*hn_kstats;

	int			hn_rx_ring_cnt;
	int			hn_rx_ring_inuse;
	struct hn_rx_ring	*hn_rx_ring;
	hn_rx_group_t		hn_rx_group;

	int			hn_tx_ring_cnt;
	int			hn_tx_ring_inuse;
	struct hn_tx_ring	*hn_tx_ring;

	caddr_t			hn_chim;
	ulong_t			*hn_chim_bmap;
	int			hn_chim_bmap_cnt;
	int			hn_chim_cnt;
	int			hn_chim_szmax;

	int			hn_cpu;
	struct vmbus_xact_ctx	*hn_xact;
	uint32_t		hn_nvs_ver;
	uint32_t		hn_rx_filter;

	kmutex_t		hn_mgmt_lock;	/* protect hn_mgmt_taskq */
	ddi_taskq_t		*hn_mgmt_taskq;
	ddi_taskq_t		*hn_mgmt_taskq0;
	uint32_t		hn_link_flags;	/* HN_LINK_FLAG_ */

	uint32_t		hn_caps;	/* HN_CAP_ */
	uint32_t		hn_flags;	/* HN_FLAG_ */
	void			*hn_rxbuf;
	uint32_t		hn_rxbuf_gpadl;
	struct hyperv_dma	hn_rxbuf_dma;

	uint32_t		hn_chim_gpadl;
	struct hyperv_dma	hn_chim_dma;

	uint32_t		hn_rndis_rid;
	uint32_t		hn_ndis_ver;
	int			hn_ndis_tso_szmax;
	int			hn_ndis_tso_sgmin;

	int			hn_rss_ind_size;
	uint32_t		hn_rss_hash;	/* NDIS_HASH_ */
	struct ndis_rssprm_toeplitz hn_rss;
};

#define	HN_FLAG_RXBUF_CONNECTED		0x0001
#define	HN_FLAG_CHIM_CONNECTED		0x0002
#define	HN_FLAG_HAS_RSSKEY		0x0004
#define	HN_FLAG_HAS_RSSIND		0x0008
#define	HN_FLAG_SYNTH_ATTACHED		0x0010
#define	HN_FLAG_RXBUF_REF		0x0040
#define	HN_FLAG_CHIM_REF		0x0080

#define	HN_FLAG_ERRORS			(HN_FLAG_RXBUF_REF | HN_FLAG_CHIM_REF)

#define	HN_CAP_VLAN			0x0001
#define	HN_CAP_MTU			0x0002
#define	HN_CAP_IPCS			0x0004
#define	HN_CAP_TCP4CS			0x0008
#define	HN_CAP_TCP6CS			0x0010
#define	HN_CAP_UDP4CS			0x0020
#define	HN_CAP_UDP6CS			0x0040
#define	HN_CAP_TSO4			0x0080
#define	HN_CAP_TSO6			0x0100
#define	HN_CAP_HASHVAL			0x0200

#define	HN_CAP_L4CS	(HN_CAP_TCP4CS | HN_CAP_TCP6CS | \
			HN_CAP_UDP4CS | HN_CAP_UDP6CS)

#define	HN_WARN(dev, fmt...)	dev_err((dev)->hn_dev, CE_WARN, fmt)
#define	HN_NOTE(dev, fmt...)	dev_err((dev)->hn_dev, CE_NOTE, fmt)

extern int hn_debug;

#define	HN_DEBUG(dev, level, fmt...) {	\
	if (level <= hn_debug) {	\
		dev_err((dev)->hn_dev, CE_NOTE, fmt);	\
	}	\
}

#define	HN_LOCK_INIT(sc)		\
	mutex_init(&(sc)->hn_lock, NULL, MUTEX_DEFAULT, NULL)
#define	HN_LOCK_ASSERT(sc)		ASSERT(MUTEX_HELD(&(sc)->hn_lock))
#define	HN_LOCKED(sc)			MUTEX_HELD(&(sc)->hn_lock)
#define	HN_LOCK_DESTROY(sc)		mutex_destroy(&(sc)->hn_lock)
#define	HN_LOCK(sc)			mutex_enter(&(sc)->hn_lock)
#define	HN_UNLOCK(sc)			mutex_exit(&(sc)->hn_lock)

#define	MACADDR_FMT "%02x%02x%02x%02x%02x%02x"
#define	MACADDR_FMT_PRETTY "%02x:%02x:%02x:%02x:%02x:%02x"
#define	MACADDR_FMT_ARGS(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

#define	HN_LINK_FLAG_LINKUP		0x0001
#define	HN_LINK_FLAG_NETCHG		0x0002

void	hn_init(void *);
void	hn_stop(struct hn_softc *);
int	hn_register_mac(struct hn_softc *);
int	hn_change_mtu(struct hn_softc *, uint32_t);
mblk_t	*hn_xmit(struct hn_tx_ring *, mblk_t *);
int	hn_set_rxfilter(struct hn_softc *);
void	hn_set_chim_size(struct hn_softc *, int);

#endif	/* !_IF_HNVAR_H_ */
