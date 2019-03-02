/*
 * Copyright (c) 2010-2012 Citrix Inc.
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
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
 */

/*
 * Copyright (c) 2004-2006 Kip Macy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <sys/dlpi.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <sys/mutex.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include <sys/conf.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/pattr.h>
#include <sys/strsun.h>
#include <sys/stream.h>
#include <sys/debug.h>

#include <sys/hyperv.h>
#include <sys/hyperv_busdma.h>
#include <sys/vmbus_xact.h>
#include <sys/vmbus.h>

#include "if_hnreg.h"
#include "if_hnvar.h"
#include "hn_rndis.h"
#include "hn_nvs.h"
#include "ndis.h"
#include "buf_ring.h"

#include <sys/hyperv_illumos.h>

#define	NETVSC_DEVNAME "hv_netvsc"

static uchar_t hn_broadcast[ETHERADDRL] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

#define	HN_RNDIS_PKT_LEN					\
	(sizeof (struct rndis_packet_msg) +			\
	HN_RNDIS_PKTINFO_SIZE(HN_NDIS_HASH_VALUE_SIZE) +	\
	HN_RNDIS_PKTINFO_SIZE(NDIS_VLAN_INFO_SIZE) +		\
	HN_RNDIS_PKTINFO_SIZE(NDIS_LSO2_INFO_SIZE) +		\
	HN_RNDIS_PKTINFO_SIZE(NDIS_TXCSUM_INFO_SIZE))
#define	HN_RNDIS_PKT_BOUNDARY		0x1000
#define	HN_RNDIS_PKT_ALIGN		CACHE_LINE_SIZE

#define	HN_TX_DATA_BOUNDARY		0x1000
#define	HN_TX_DATA_MAXSIZE		IP_MAXPACKET
#define	HN_TX_DATA_SEGSIZE		0x1000
/* -1 for RNDIS packet message */
#define	HN_TX_DATA_SEGCNT_MAX		(HN_GPACNT_MAX - 1)

#define	HN_PKTBUF_LEN_DEF		(16 * 1024)

struct hn_txdesc {
	mblk_t			*m;
	struct hn_tx_ring	*txr;
	uint32_t		flags;		/* HN_TXD_FLAG_ */
	struct hn_nvs_sendctx	send_ctx;
	uint32_t		chim_index;
	int			chim_size;
	uint64_t		rndis_pkt_paddr;
	struct rndis_packet_msg *rndis_pkt;
	ddi_dma_handle_t	rndis_pkt_dmah;
	ddi_acc_handle_t	rndis_pkt_datah;
	size_t			rndis_pkt_buflen;
};

#define	HN_TXD_FLAG_ONLIST		0x0001
#define	HN_TXD_FLAG_DMAMAP		0x0002

struct hn_rxinfo {
	uint32_t			vlan_info;
	uint32_t			csum_info;
	uint32_t			hash_info;
	uint32_t			hash_value;
};

#define	HN_RXINFO_VLAN			0x0001
#define	HN_RXINFO_CSUM			0x0002
#define	HN_RXINFO_HASHINF		0x0004
#define	HN_RXINFO_HASHVAL		0x0008
#define	HN_RXINFO_ALL			\
	(HN_RXINFO_VLAN |		\
	HN_RXINFO_CSUM |		\
	HN_RXINFO_HASHINF |		\
	HN_RXINFO_HASHVAL)

#define	HN_NDIS_VLAN_INFO_INVALID	0xffffffff
#define	HN_NDIS_RXCSUM_INFO_INVALID	0
#define	HN_NDIS_HASH_INFO_INVALID	0


static void			hn_chan_callback(struct vmbus_channel *,
				    void *);

static int			hn_rndis_rxinfo(const void *, int,
				    struct hn_rxinfo *);
static void			hn_rndis_rx_data(struct hn_rx_ring *,
				    const void *, int);
static void			hn_rndis_rx_status(struct hn_softc *,
				    const void *, int);

static void			hn_nvs_handle_notify(struct hn_softc *,
				    const struct vmbus_chanpkt_hdr *);
static void			hn_nvs_handle_comp(struct hn_softc *,
				    struct vmbus_channel *,
				    const struct vmbus_chanpkt_hdr *);
static void			hn_nvs_handle_rxbuf(struct hn_rx_ring *,
				    struct vmbus_channel *,
				    const struct vmbus_chanpkt_hdr *);
static void			hn_nvs_ack_rxbuf(struct hn_rx_ring *,
				    struct vmbus_channel *, uint64_t);

static int			hn_chan_attach(struct hn_softc *,
				    struct vmbus_channel *);
static void			hn_chan_detach(struct hn_softc *,
				    struct vmbus_channel *);
static int			hn_attach_subchans(struct hn_softc *);
static void			hn_detach_allchans(struct hn_softc *);
static void			hn_detach_impl(struct hn_softc *);

static void			hn_update_ring_inuse(struct hn_softc *, int);
static int			hn_synth_attach(struct hn_softc *, int);
static void			hn_synth_detach(struct hn_softc *);
static int			hn_synth_alloc_subchans(struct hn_softc *,
				    int *);
static boolean_t		hn_synth_attachable(const struct hn_softc *);
static void			hn_suspend(struct hn_softc *);
static void			hn_suspend_data(struct hn_softc *);
static void			hn_suspend_mgmt(struct hn_softc *);
static void			hn_resume(struct hn_softc *);
static void			hn_resume_data(struct hn_softc *);
static void			hn_resume_mgmt(struct hn_softc *);
static void			hn_chan_drain(struct hn_softc *,
				    struct vmbus_channel *);

static void			hn_update_link_status(struct hn_softc *);
static void			hn_change_network(struct hn_softc *);
static void			hn_link_taskfunc(void *);
static void			hn_netchg_taskfunc(void *);
static void			hn_link_status(struct hn_softc *);

static int			hn_create_rx_data(struct hn_softc *);
static void			hn_destroy_rx_data(struct hn_softc *);
static void			hn_rss_ind_fixup(struct hn_softc *);
static int			hn_rxpkt(struct hn_rx_ring *, const void *,
				    int, const struct hn_rxinfo *);
static uint32_t			hn_get_implied_hcksum(struct hn_rx_ring *,
				    const mblk_t *);

static int			hn_tx_ring_create(struct hn_softc *, int);
static void			hn_tx_ring_destroy(struct hn_tx_ring *);
static int			hn_create_tx_data(struct hn_softc *);
static void			hn_fixup_tx_data(struct hn_softc *);
static void			hn_destroy_tx_data(struct hn_softc *);
static void			hn_txdesc_dmamap_destroy(struct hn_txdesc *);
#ifdef txagg
static void			hn_txdesc_gc(struct hn_tx_ring *,
				    struct hn_txdesc *);
#endif
static int			hn_encap(struct hn_tx_ring *,
				    struct hn_txdesc *, mblk_t *);
static int			hn_txpkt(struct hn_tx_ring *,
				    struct hn_txdesc *);
static boolean_t		hn_tx_ring_pending(struct hn_tx_ring *);
static void			hn_resume_tx(struct hn_softc *, int);

static void			hn_txpkt_done(struct hn_nvs_sendctx *,
				    struct hn_softc *, struct vmbus_channel *,
				    const void *, int);
static int			hn_txpkt_sglist(struct hn_tx_ring *,
				    struct hn_txdesc *);
static int			hn_txpkt_chim(struct hn_tx_ring *,
				    struct hn_txdesc *);

/*
 * Global Tunables
 */

/*
 * HN_DEBUG() level.
 * 0 - disabled
 * 1 - attach, config, milestones
 * 2 - stats, props, more verbose
 * 3 - more verbose
 * 4 - most verbose: each tx/rx pkt
 */
int hn_debug = 0;

/*
 * Trust tcp/udp/ip checksum verification on host side.
 */
boolean_t hn_trust_host_cksum = HN_DEFAULT_TRUST_HOST_CKSUM;
/*
 * Limit TSO burst size
 */
int hn_tso_maxlen = IP_MAXPACKET;
/*
 * Limit chimney send size
 * (chimney is used to send small packets more efficiently. 0 = use default)
 */
int hn_tx_chimney_size = 0;
/*
 * Enable hardware offloading of tx checksumming.
 * Can be overriden in driver.conf.
 */
boolean_t hn_tx_hcksum_enable_default = B_TRUE;
/*
 * Enable Large Send Offload.
 * Can be overriden in driver.conf.
 */
boolean_t hn_lso_enable_default = B_TRUE;
/*
 * default number of tx descriptors per ring.
 * Can be overriden in driver.conf.
 */
#define	HN_TX_DESC_CNT_DEFAULT	512
#define	HN_TX_DESC_CNT_MIN	512
#define	HN_TX_DESC_CNT_MAX	8192
int hn_txdesc_cnt_default = HN_TX_DESC_CNT_DEFAULT;

/*
 * Globals
 */

/*
 * Assign each channel to a different cpu.
 */
uint32_t hn_cpu_index = 0;

static const uint8_t
hn_rss_key_default[NDIS_HASH_KEYSIZE_TOEPLITZ] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa
};

/*
 * Get the numeric value of the property "name" in netvsc.conf for
 * the corresponding device instance.
 * If the property isn't found or if it doesn't satisfy the conditions,
 * "def" is returned.
 */
static int
hn_getprop(struct hn_softc *sc, char *name, int min, int max, int def)
{
	int ret = def;
	int *props;
	uint_t nprops;

	ASSERT(def >= min && def <= max);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sc->hn_dev,
	    DDI_PROP_DONTPASS, name, &props, &nprops) == DDI_PROP_SUCCESS) {
		if (sc->hn_instance < nprops) {
			ret = props[sc->hn_instance];
			HN_NOTE(sc, "property %s configured to %d", name, ret);
		} else {
			HN_WARN(sc, "property %s not available for this "
			    "device", name);
		}
		ddi_prop_free(props);
	}

	if (ret < min || ret > max) {
		HN_WARN(sc, "property %s out of range (%d <= %d <= %d), "
		    "setting to default (%d)", name, min, ret, max, def);
		ret = def;
	}

	HN_DEBUG(sc, 2, "hn_getprop(%s) -> %d", name, ret);

	return (ret);
}

static void
hn_init_properties(struct hn_softc *sc)
{
	/*
	 * NOTE:
	 * The # of RX rings to use is same as the # of channels to use.
	 */
	sc->hn_rx_ring_cnt = hn_getprop(sc, "rx_rings", 1, HN_RING_CNT_DEF_MAX,
	    min(ncpus, HN_RING_CNT_DEF_MAX));

	/*
	 * # of TX rings is limited by the number of channels (i.e RX rings)
	 */
	sc->hn_tx_ring_cnt = hn_getprop(sc, "tx_rings", 1, sc->hn_rx_ring_cnt,
	    sc->hn_rx_ring_cnt);

	sc->hn_lso_enable = hn_getprop(sc, "lso", B_FALSE, B_TRUE,
	    hn_lso_enable_default);

	sc->hn_tx_hcksum_enable = hn_getprop(sc, "tx_cksum_offload", B_FALSE,
	    B_TRUE, hn_tx_hcksum_enable_default);

	/* TODO: find txdesc_cnt hard limit, or get it from host */
	sc->hn_txdesc_cnt = hn_getprop(sc, "tx_desc_cnt", HN_TX_DESC_CNT_MIN,
	    HN_TX_DESC_CNT_MAX, hn_txdesc_cnt_default);
	if (!ISP2(sc->hn_txdesc_cnt)) {
		HN_WARN(sc, "number of tx descriptors (%d) must be a power "
		    "of 2, defaulting to %d", sc->hn_txdesc_cnt,
		    HN_TX_DESC_CNT_DEFAULT);
		sc->hn_txdesc_cnt = HN_TX_DESC_CNT_DEFAULT;
	}

	/*
	 * Set the leader CPU for channels.
	 */
	sc->hn_cpu = (atomic_add_32_nv(&hn_cpu_index, sc->hn_rx_ring_cnt) -
	    sc->hn_rx_ring_cnt) % ncpus;
}

int
hn_change_mtu(struct hn_softc *sc, uint32_t new_mtu)
{
	int error = 0;

	if (new_mtu > HN_MTU_MAX || new_mtu < HN_MTU_MIN)
		return (EINVAL);

	HN_LOCK(sc);
	ASSERT(sc->hn_flags & HN_FLAG_SYNTH_ATTACHED);

	if ((sc->hn_caps & HN_CAP_MTU) == 0) {
		/* changing mtu is not supported */
		HN_UNLOCK(sc);
		return (ENOTSUP);
	}

	if (new_mtu == sc->hn_mtu) {
		HN_UNLOCK(sc);
		return (0);
	}

	HN_DEBUG(sc, 2, "hn_change_mtu: %d --> %d", sc->hn_mtu, new_mtu);

	if (sc->hn_running)
		hn_suspend(sc);

	sc->hn_mtu = new_mtu;

	/*
	 * Detach the synthetics parts, i.e. NVS, RNDIS and channels.
	 * Essentially we need to disconnect & reconnect the back end of the
	 * interface in order to change the MTU.
	 */
	hn_synth_detach(sc);

	/*
	 * Reattach the synthetic parts, i.e. NVS and RNDIS,
	 * with the new MTU setting.
	 */
	error = hn_synth_attach(sc, sc->hn_mtu);
	if (error != 0) {
		HN_WARN(sc, "hn_change_mtu: hn_synth_attach failed, %d",
		    error);
		HN_UNLOCK(sc);
		return (EIO);
	}

	if (sc->hn_tx_ring[0].hn_chim_size > sc->hn_chim_szmax)
		hn_set_chim_size(sc, sc->hn_chim_szmax);

	error = mac_maxsdu_update(sc->hn_mac_hdl, new_mtu);
	if (error != 0) {
		HN_WARN(sc, "Unable to update mac with %d mtu: %d",
		    new_mtu, error);
		HN_UNLOCK(sc);
		return (EIO);
	}

	/* All done!  Resume now. */
	hn_resume(sc);

	HN_UNLOCK(sc);

	return (0);
}


static int
hn_kstat_update(kstat_t *ksp, int rw)
{
	struct hn_softc *sc = ksp->ks_private;
	hn_kstats_t *sp = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	sp->tx_ring_cnt.value.ui32 = sc->hn_tx_ring_cnt;
	sp->tx_ring_inuse.value.ui32 = sc->hn_tx_ring_inuse;
	sp->rx_ring_cnt.value.ui32 = sc->hn_rx_ring_cnt;
	sp->rx_ring_inuse.value.ui32 = sc->hn_rx_ring_inuse;

	sp->tx_send_failed.value.ui64 = 0;
	sp->tx_no_descs.value.ui64 = 0;
	sp->tx_mblk_pulledup.value.ui64 = 0;
	sp->tx_chimney_tried.value.ui64 = 0;
	sp->tx_chimney_sent.value.ui64 = 0;
	sp->tx_dma_failed.value.ui64 = 0;
#ifdef DEBUG
	sp->tx_descs_used.value.ui64 = 0;
#endif

	for (int i = 0; i < sc->hn_tx_ring_inuse; i++) {
		struct hn_tx_ring *txr = &sc->hn_tx_ring[i];
		hn_tx_stats_t *txs = &txr->hn_tx_stats;
		mutex_enter(&txr->hn_tx_lock);
		sp->tx_send_failed.value.ui64 += txs->send_failed;
		sp->tx_no_descs.value.ui64 += txs->no_txdescs;
		sp->tx_mblk_pulledup.value.ui64 += txs->pulledup;
		sp->tx_chimney_tried.value.ui64 += txs->chimney_tried;
		sp->tx_chimney_sent.value.ui64 += txs->chimney_sent;
		sp->tx_dma_failed.value.ui64 += txs->dma_failed;
#ifdef DEBUG
		sp->tx_descs_used.value.ui64 +=
		    (txr->hn_txdesc_cnt - txr->hn_txdesc_avail);
#endif
		mutex_exit(&txr->hn_tx_lock);
	}

	sp->rx_no_bufs.value.ui64 = 0;
	sp->rx_csum_ip.value.ui64 = 0;
	sp->rx_csum_tcp.value.ui64 = 0;
	sp->rx_csum_udp.value.ui64 = 0;
	sp->rx_csum_trusted.value.ui64 = 0;

	for (int i = 0; i < sc->hn_rx_ring_inuse; i++) {
		struct hn_rx_ring *rxr = &sc->hn_rx_ring[i];
		hn_rx_stats_t *rxs = &rxr->hn_rx_stats;
		mutex_enter(&rxr->hn_rx_lock);
		sp->rx_no_bufs.value.ui64 += rxs->norxbufs;
		sp->rx_csum_ip.value.ui64 += rxs->csum_ip;
		sp->rx_csum_tcp.value.ui64 += rxs->csum_tcp;
		sp->rx_csum_udp.value.ui64 += rxs->csum_udp;
		sp->rx_csum_trusted.value.ui64 += rxs->csum_trusted;
		mutex_exit(&rxr->hn_rx_lock);
	}

	return (0);
}


static int
hn_kstat_init(struct hn_softc *sc)
{
	hn_kstats_t *sp;

	sc->hn_kstats = kstat_create(NETVSC_DEVNAME, sc->hn_instance,
	    "statistics", "dev",  KSTAT_TYPE_NAMED,
	    sizeof (hn_kstats_t) / sizeof (kstat_named_t), 0);
	if (sc->hn_kstats == NULL) {
		HN_WARN(sc, "Failed to allocate kstats");
		return (EINVAL);
	}

	sc->hn_kstats->ks_update = hn_kstat_update;
	sc->hn_kstats->ks_private = sc;

	sp = sc->hn_kstats->ks_data;

	kstat_named_init(&sp->tx_ring_cnt, "tx_ring_cnt",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&sp->tx_ring_inuse, "tx_ring_inuse",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&sp->rx_ring_cnt, "rx_ring_cnt",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&sp->rx_ring_inuse, "rx_ring_inuse",
	    KSTAT_DATA_UINT32);

	kstat_named_init(&sp->tx_send_failed, "tx_send_failed",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->tx_no_descs, "tx_no_descs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->tx_mblk_pulledup, "tx_mblk_pulledup",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->tx_chimney_tried, "tx_chimney_tried",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->tx_chimney_sent, "tx_chimney_sent",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->tx_dma_failed, "tx_dma_failed",
	    KSTAT_DATA_ULONG);
#ifdef DEBUG
	kstat_named_init(&sp->tx_descs_used, "tx_descs_used",
	    KSTAT_DATA_ULONG);
#endif

	kstat_named_init(&sp->rx_no_bufs, "rx_no_bufs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->rx_csum_ip, "rx_csum_ip",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->rx_csum_tcp, "rx_csum_tcp",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->rx_csum_udp, "rx_csum_udp",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->rx_csum_trusted, "rx_csum_trusted",
	    KSTAT_DATA_ULONG);

	kstat_install(sc->hn_kstats);

	return (0);
}

static int
hn_txpkt_sglist(struct hn_tx_ring *txr, struct hn_txdesc *txd)
{

	ASSERT3U(txd->chim_index, ==, HN_NVS_CHIM_IDX_INVALID);
	ASSERT3S(txd->chim_size, ==, 0);

	return (hn_nvs_send_rndis_sglist(txr->hn_chan, HN_NVS_RNDIS_MTYPE_DATA,
	    &txd->send_ctx, txr->hn_gpa, txr->hn_gpa_cnt));
}

static int
hn_txpkt_chim(struct hn_tx_ring *txr, struct hn_txdesc *txd)
{
	struct hn_nvs_rndis rndis;

	ASSERT(txd->chim_index != HN_NVS_CHIM_IDX_INVALID);
	ASSERT3S(txd->chim_size, >, 0);

	rndis.nvs_type = HN_NVS_TYPE_RNDIS;
	rndis.nvs_rndis_mtype = HN_NVS_RNDIS_MTYPE_DATA;
	rndis.nvs_chim_idx = txd->chim_index;
	rndis.nvs_chim_sz = txd->chim_size;

	return (hn_nvs_send(txr->hn_chan, VMBUS_CHANPKT_FLAG_RC,
	    &rndis, sizeof (rndis), &txd->send_ctx));
}

uint32_t
hn_chim_alloc(struct hn_softc *sc)
{
	int i, bmap_cnt = sc->hn_chim_bmap_cnt;
	ulong_t *bmap = sc->hn_chim_bmap;

	for (i = 0; i < bmap_cnt; ++i) {
		int result, idx;
		uint32_t chim_idx;

		idx = lowbit(~bmap[i]);
		if (idx == 0)
			continue;

		--idx; /* lowbit is 1-based */

		chim_idx = (i << BT_ULSHIFT) + idx;
		ASSERT3U(chim_idx, <, sc->hn_chim_cnt);

		BT_ATOMIC_SET_EXCL(bmap, chim_idx, result);
		if (result == 0)
			return (chim_idx);
	}
	return (HN_NVS_CHIM_IDX_INVALID);
}

void
hn_chim_free(struct hn_softc *sc, uint32_t chim_idx)
{
	ASSERT3U(chim_idx >> BT_ULSHIFT, <, sc->hn_chim_bmap_cnt);
	ASSERT(BT_TEST(sc->hn_chim_bmap, chim_idx));

	BT_ATOMIC_CLEAR(sc->hn_chim_bmap, chim_idx);
}

int
hn_set_rxfilter(struct hn_softc *sc)
{
	uint32_t filter;
	int error = 0;

	HN_LOCK_ASSERT(sc);

	/*
	 * We currently support only two modes (based on Linux implementation):
	 *  - non-promiscuous mode, accepting all multicast packets
	 *  - promiscuous mode
	 */
	if (sc->hn_promiscuous) {
		filter = NDIS_PACKET_TYPE_PROMISCUOUS;
	} else {
		filter = NDIS_PACKET_TYPE_DIRECTED |
		    NDIS_PACKET_TYPE_BROADCAST |
		    NDIS_PACKET_TYPE_ALL_MULTICAST;
	}

	if (sc->hn_rx_filter != filter) {
		error = hn_rndis_set_rxfilter(sc, filter);
		if (!error)
			sc->hn_rx_filter = filter;
	}
	return (error);
}

static void
hn_rss_ind_fixup(struct hn_softc *sc)
{
	struct ndis_rssprm_toeplitz *rss = &sc->hn_rss;
	int i, nchan;

	nchan = sc->hn_rx_ring_inuse;
	/*
	 * RSS requires more than one channel to be configured
	 */
	ASSERT(nchan > 1);

	/*
	 * Check indirect table to make sure that all channels in it
	 * can be used.
	 */
	for (i = 0; i < NDIS_HASH_INDCNT; ++i) {
		if (rss->rss_ind[i] >= nchan) {
			/*
			 * TODO: this looks like a terrible way to "fix"
			 * RSS index mapping.
			 */
			HN_WARN(sc, "RSS indirect table %d fixup: %u -> %d",
			    i, rss->rss_ind[i], nchan - 1);
			rss->rss_ind[i] = nchan - 1;
		}
	}
}

static int
hn_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct hn_softc *sc;
	int error;

	/*
	 * We do not currently support DDI_RESUME
	 */
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	sc = kmem_zalloc(sizeof (struct hn_softc), KM_SLEEP);
	HN_LOCK_INIT(sc);
	mutex_init(&sc->hn_mgmt_lock, NULL, MUTEX_DEFAULT, NULL);

	sc->hn_dev = dip;
	sc->hn_instance = ddi_get_instance(dip);

	/*
	 * Get the primary channel for the netvsc device
	 */
	sc->hn_prichan = vmbus_get_channel(dip);

	ddi_set_driver_private(dip, sc);

	hn_init_properties(sc);

	/*
	 * Setup taskqueue for management tasks, e.g. link status.
	 */
	sc->hn_mgmt_taskq0 = ddi_taskq_create(dip, "hn_mgmt", 1,
	    TASKQ_DEFAULTPRI, 0);

	/*
	 * Create enough TX/RX rings, even if only limited number of
	 * channels can be allocated.
	 */
	error = hn_create_tx_data(sc);
	if (error != 0)
		goto failed;
	error = hn_create_rx_data(sc);
	if (error != 0)
		goto failed;

	/*
	 * Create transaction context for NVS and RNDIS transactions.
	 */
	sc->hn_xact = vmbus_xact_ctx_create(dip,
	    HN_XACT_REQ_SIZE, HN_XACT_RESP_SIZE, 0);
	if (sc->hn_xact == NULL) {
		error = ENXIO;
		goto failed;
	}

	/*
	 * Install orphan handler for the revocation of this device's
	 * primary channel.
	 *
	 * NOTE:
	 * The processing order is critical here:
	 * Install the orphan handler, _before_ testing whether this
	 * device's primary channel has been revoked or not.
	 */
	vmbus_chan_set_orphan(sc->hn_prichan, sc->hn_xact);
	if (vmbus_chan_is_revoked(sc->hn_prichan)) {
		error = ENXIO;
		goto failed;
	}

	sc->hn_mtu = ETHERMTU;
	/*
	 * Attach the synthetic parts, i.e. NVS and RNDIS.
	 */
	error = hn_synth_attach(sc, sc->hn_mtu);
	if (error != 0)
		goto failed;

	/*
	 * Fixup TX stuffs after synthetic parts are attached.
	 */
	hn_fixup_tx_data(sc);

	error = hn_kstat_init(sc);
	if (error != 0)
		goto failed;

	/*
	 * Register device with the MAC framework.
	 * We need to do this after the synthetic parts are attached as we
	 * have to query for the MAC address.
	 */
	error = hn_register_mac(sc);
	if (error != 0)
		goto failed;

	/*
	 * Kick off link status check.
	 */
	sc->hn_mgmt_taskq = sc->hn_mgmt_taskq0;
	hn_update_link_status(sc);

	return (DDI_SUCCESS);

failed:
	if (sc->hn_flags & HN_FLAG_SYNTH_ATTACHED)
		hn_synth_detach(sc);

	hn_detach_impl(sc);

	return (DDI_FAILURE);
}

static void
hn_detach_impl(struct hn_softc *sc)
{
	if (sc->hn_xact != NULL && vmbus_chan_is_revoked(sc->hn_prichan)) {
		/*
		 * In case that the vmbus missed the orphan handler
		 * installation.
		 */
		(void) vmbus_xact_ctx_orphan(sc->hn_xact);
	}

	HN_LOCK(sc);
	if (sc->hn_flags & HN_FLAG_SYNTH_ATTACHED) {
		ASSERT(!sc->hn_running);
		hn_suspend_mgmt(sc);
		hn_synth_detach(sc);
	}
	HN_UNLOCK(sc);

	if (sc->hn_mac_hdl != NULL)
		VERIFY0(mac_unregister(sc->hn_mac_hdl));

	if (sc->hn_kstats != NULL)
		kstat_delete(sc->hn_kstats);

	hn_destroy_rx_data(sc);
	hn_destroy_tx_data(sc);

	ddi_taskq_destroy(sc->hn_mgmt_taskq0);

	if (sc->hn_xact != NULL) {
		/*
		 * Uninstall the orphan handler _before_ the xact is
		 * destructed.
		 */
		vmbus_chan_unset_orphan(sc->hn_prichan);
		vmbus_xact_ctx_destroy(sc->hn_xact);
	}

	mutex_destroy(&sc->hn_mgmt_lock);
	HN_LOCK_DESTROY(sc);

	kmem_free(sc, sizeof (*sc));
}

static int
hn_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct hn_softc *sc = ddi_get_driver_private(dip);

	HN_DEBUG(sc, 1, "detach()");

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	hn_detach_impl(sc);

	return (DDI_SUCCESS);
}

static void
hn_link_status(struct hn_softc *sc)
{
	uint32_t link_status;
	int error;

	error = hn_rndis_get_linkstatus(sc, &link_status);
	if (error) {
		/* XXX what to do? */
		HN_WARN(sc, "Failed to get link status, %d", error);
		return;
	}

	if (link_status == NDIS_MEDIA_STATE_CONNECTED)
		sc->hn_link_flags |= HN_LINK_FLAG_LINKUP;
	else
		sc->hn_link_flags &= ~HN_LINK_FLAG_LINKUP;

	mac_link_update(sc->hn_mac_hdl,
	    (sc->hn_link_flags & HN_LINK_FLAG_LINKUP) ?
	    LINK_STATE_UP : LINK_STATE_DOWN);
}

static void
hn_link_taskfunc(void *xsc)
{
	struct hn_softc *sc = xsc;

	if (sc->hn_link_flags & HN_LINK_FLAG_NETCHG)
		return;
	hn_link_status(sc);
}

/*
 * TODO: test this function.
 */
static void
hn_netchg_taskfunc(void *xsc)
{
	struct hn_softc *sc = xsc;

	/* Prevent any link status checks from running. */
	sc->hn_link_flags |= HN_LINK_FLAG_NETCHG;

	/*
	 * FreeBSD comment:
	 * Fake up a [link down --> link up] state change; 5 seconds
	 * delay is used, which closely simulates miibus reaction
	 * upon link down event.
	 */

	sc->hn_link_flags &= ~HN_LINK_FLAG_LINKUP;
	mac_link_update(sc->hn_mac_hdl, LINK_STATE_DOWN);

	delay(SEC_TO_TICK(5));

	/* Re-allow link status checks. */
	sc->hn_link_flags &= ~HN_LINK_FLAG_NETCHG;
	hn_link_status(sc);
}

static void
hn_update_link_status(struct hn_softc *sc)
{
	mutex_enter(&sc->hn_mgmt_lock);
	if (sc->hn_mgmt_taskq != NULL) {
		(void) ddi_taskq_dispatch(sc->hn_mgmt_taskq, hn_link_taskfunc,
		    sc, TQ_SLEEP);
	}
	mutex_exit(&sc->hn_mgmt_lock);
}

static void
hn_change_network(struct hn_softc *sc)
{
	mutex_enter(&sc->hn_mgmt_lock);
	if (sc->hn_mgmt_taskq != NULL) {
		(void) ddi_taskq_dispatch(sc->hn_mgmt_taskq, hn_netchg_taskfunc,
		    sc, TQ_SLEEP);
	}
	mutex_exit(&sc->hn_mgmt_lock);
}

static int
hn_txdesc_dmamap_load(struct hn_tx_ring *txr, struct hn_txdesc *txd,
    mblk_t *mp, int pktlen)
{
	ASSERT3U(txd->chim_index, ==, HN_NVS_CHIM_IDX_INVALID);

	txr->hn_gpa[0].gpa_page = btop(txd->rndis_pkt_paddr);
	txr->hn_gpa[0].gpa_ofs = txd->rndis_pkt_paddr & PAGEOFFSET;
	txr->hn_gpa[0].gpa_len = pktlen;

	int nsegs = 1; /* First seg is used by RNDIS packet */
	for (; mp != NULL; mp = mp->b_cont) {
		ddi_dma_cookie_t cookie;
		uint_t cookie_count;

		if (MBLKL(mp) == 0)
			continue;

		int ret = ddi_dma_addr_bind_handle(txr->hn_data_dmah, NULL,
		    (caddr_t)mp->b_rptr, MBLKL(mp),
		    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
		    &cookie, &cookie_count);
		if (ret != DDI_DMA_MAPPED) {
			HN_WARN(txr->hn_sc, "ddi_dma_addr_bind_handle() "
			    "failed, [error=%d]", ret);
			return (ENOMEM);
		}
		ASSERT(cookie_count > 0);
		for (int i = 0; i < cookie_count; i++) {
			if (nsegs == HN_GPACNT_MAX) {
				(void) ddi_dma_unbind_handle(txr->hn_data_dmah);
				return (EAGAIN);
			}
			struct vmbus_gpa *gpa = &txr->hn_gpa[nsegs];
			gpa->gpa_page = btop(cookie.dmac_laddress);
			gpa->gpa_ofs = cookie.dmac_laddress & PAGEOFFSET;
			gpa->gpa_len = cookie.dmac_size;
			ddi_dma_nextcookie(txr->hn_data_dmah, &cookie);
			nsegs++;
		}
		/*
		 * XXX: HACK
		 * We do a hack here by unbinding the handle before the data
		 * has been sent in order to be able to re-use the same handle.
		 * The assumption here is that data copying is not necessary
		 * as the DMA constraints are relaxed enough.
		 * Alternatively, we could try to access the HAT directly to
		 * retrieve the physical addresses by calling hat_getpfnum().
		 */
		(void) ddi_dma_unbind_handle(txr->hn_data_dmah);
	}
	txr->hn_gpa_cnt = nsegs;

	DTRACE_PROBE2(segs, int, nsegs, int, txr->hn_pkt_length);

	txd->flags |= HN_TXD_FLAG_DMAMAP;

	return (0);
}

static void
hn_txdesc_put(struct hn_tx_ring *txr, struct hn_txdesc *txd)
{
	ASSERT0(txd->flags & HN_TXD_FLAG_ONLIST);

	if (txd->chim_index != HN_NVS_CHIM_IDX_INVALID) {
		ASSERT0(txd->flags & HN_TXD_FLAG_DMAMAP);
		hn_chim_free(txr->hn_sc, txd->chim_index);
		txd->chim_index = HN_NVS_CHIM_IDX_INVALID;
	} else if (txd->flags & HN_TXD_FLAG_DMAMAP) {
		txd->flags &= ~HN_TXD_FLAG_DMAMAP;
	}

	if (txd->m != NULL) {
		freemsg(txd->m);
		txd->m = NULL;
	}

	txd->flags |= HN_TXD_FLAG_ONLIST;
#ifdef DEBUG
	atomic_inc_32((uint32_t *)&txr->hn_txdesc_avail);
#endif
	(void) buf_ring_enqueue(txr->hn_txdesc_br, txd);
}

static struct hn_txdesc *
hn_txdesc_get(struct hn_tx_ring *txr)
{
	struct hn_txdesc *txd;

	txd = buf_ring_dequeue_sc(txr->hn_txdesc_br);

	if (txd != NULL) {
#ifdef DEBUG
		atomic_dec_32((uint32_t *)&txr->hn_txdesc_avail);
#endif
		ASSERT3P(txd->m, ==, NULL);
		ASSERT3U(txd->chim_index, ==, HN_NVS_CHIM_IDX_INVALID);
		ASSERT(txd->flags & HN_TXD_FLAG_ONLIST);
		ASSERT0(txd->flags & HN_TXD_FLAG_DMAMAP);
		txd->flags &= ~HN_TXD_FLAG_ONLIST;
	}
	return (txd);
}

static boolean_t
hn_tx_ring_pending(struct hn_tx_ring *txr)
{
	return (!buf_ring_full(txr->hn_txdesc_br));
}

/* ARGSUSED */
static void
hn_txpkt_done(struct hn_nvs_sendctx *sndc, struct hn_softc *sc,
    struct vmbus_channel *chan, const void *data, int dlen)
{
	struct hn_txdesc *txd = sndc->hn_cbarg;
	struct hn_tx_ring *txr;

	txr = txd->txr;
	ASSERT3P(txr->hn_chan, ==, chan);

	hn_txdesc_put(txr, txd);

	/*
	 * We have freed some buffers so we can now resume transmission of
	 * packets.
	 */
	if (txr->hn_reschedule) {
		txr->hn_reschedule = B_FALSE;
		mac_tx_ring_update(txr->hn_sc->hn_mac_hdl, txr->hn_ring_handle);
	}
}

static inline uint32_t
hn_rndis_pktmsg_offset(uint32_t ofs)
{
	ASSERT3U(ofs, >=, sizeof (struct rndis_packet_msg));
	return (ofs - offsetof(struct rndis_packet_msg, rm_dataoffset));
}

static inline void *
hn_rndis_pktinfo_append(struct rndis_packet_msg *pkt, size_t pktsize,
    size_t pi_dlen, uint32_t pi_type)
{
	const size_t pi_size = HN_RNDIS_PKTINFO_SIZE(pi_dlen);
	struct rndis_pktinfo *pi;

	ASSERT0(pi_size & RNDIS_PACKET_MSG_OFFSET_ALIGNMASK);

	/*
	 * Per-packet-info does not move; it only grows.
	 *
	 * NOTE:
	 * rm_pktinfooffset in this phase counts from the beginning
	 * of rndis_packet_msg.
	 */
	ASSERT3U(pkt->rm_pktinfooffset + pkt->rm_pktinfolen + pi_size, <=,
	    pktsize);
	pi = (struct rndis_pktinfo *)((uint8_t *)pkt + pkt->rm_pktinfooffset +
	    pkt->rm_pktinfolen);
	pkt->rm_pktinfolen += pi_size;

	pi->rm_size = pi_size;
	pi->rm_type = pi_type;
	pi->rm_pktinfooffset = RNDIS_PKTINFO_OFFSET;

	/* Data immediately follow per-packet-info. */
	pkt->rm_dataoffset += pi_size;

	/* Update RNDIS packet msg length */
	pkt->rm_len += pi_size;

	return (pi->rm_data);
}

/*
 * Prepare the RNDIS packet (it prepends the data).
 * Return the length of the RNDIS packet.
 *
 * For reference:
 *     [MS-RNDIS] - v20140501
 *     chapter 2.2.14 - REMOTE_NDIS_PACKET_MSG
 */
static int
hn_tx_prepare_rndis_pkt(struct hn_softc *sc, struct rndis_packet_msg *pkt,
    mblk_t *mp, int dlen, int txr_idx)
{
	uint32_t hck_flags, lso_flag, mss;
	uint32_t hck_start = 0;
	uint32_t *pi_data;
	int pktlen;

	pkt->rm_type = REMOTE_NDIS_PACKET_MSG;
	pkt->rm_len = sizeof (*pkt) + dlen;
	pkt->rm_dataoffset = sizeof (*pkt);
	pkt->rm_datalen = dlen;
	pkt->rm_oobdataoffset = 0;
	pkt->rm_oobdatalen = 0;
	pkt->rm_oobdataelements = 0;
	pkt->rm_pktinfooffset = sizeof (*pkt);
	pkt->rm_pktinfolen = 0;
	pkt->rm_vchandle = 0;
	pkt->rm_reserved = 0;

	/*
	 * Set the hash value for this packet, so that the host could
	 * dispatch the TX done event for this packet back to this TX
	 * ring's channel.
	 */
	pi_data = hn_rndis_pktinfo_append(pkt, HN_RNDIS_PKT_LEN,
	    HN_NDIS_HASH_VALUE_SIZE, HN_NDIS_PKTINFO_TYPE_HASHVAL);
	*pi_data = txr_idx;

	/*
	 * Get hardware checksum and lso info for mblk
	 */
	hcksum_retrieve(mp, NULL, NULL, &hck_start, NULL, NULL, NULL,
	    &hck_flags);
	mac_lso_get(mp, &mss, &lso_flag);

	unsigned char *ptr = mp->b_rptr;
	uint32_t sap = ntohs(((struct ether_header *)ptr)->ether_type);

	/*
	 * If applicable, append vlan info to packet info
	 */
	if (sap == ETHERTYPE_VLAN) {
		struct ether_vlan_header *eth = (void *)ptr;
		sap = ntohs(eth->ether_type);

		pi_data = hn_rndis_pktinfo_append(pkt, HN_RNDIS_PKT_LEN,
		    NDIS_VLAN_INFO_SIZE, NDIS_PKTINFO_TYPE_VLAN);
		*pi_data = NDIS_VLAN_INFO_MAKE(
		    VLAN_ID(eth->ether_tci),
		    VLAN_PRI(eth->ether_tci),
		    VLAN_CFI(eth->ether_tci));

		ptr += sizeof (struct ether_vlan_header);
	} else {
		ptr += sizeof (struct ether_header);
	}

	/*
	 * Ethernet and IP headers may be in different mblk segments.
	 */
	ASSERT3P(ptr, <=, mp->b_wptr);
	if (ptr == mp->b_wptr) {
		mp = mp->b_cont;
		ptr = mp->b_rptr;
	}

	HN_DEBUG(sc, 4, "size %u, hck_flags=0x%x, lso_flag=0x%x, hck_start=%d, "
	    "ether_type=0x%x", dlen, hck_flags, lso_flag, hck_start, sap);

	if (lso_flag & HW_LSO) {
		/*
		 * The only type of LSO that we support is for IPv4.
		 * We advertise LSO_TX_BASIC_TCP_IPV4 for MAC_CAPAB_LSO.
		 * IPv6 is not yet supported in the framework.
		 */
		ASSERT3U(sap, ==, ETHERTYPE_IP);

		pi_data = hn_rndis_pktinfo_append(pkt, HN_RNDIS_PKT_LEN,
		    NDIS_LSO2_INFO_SIZE, NDIS_PKTINFO_TYPE_LSO);

		/*
		 * Some hardware requires this to be 0, otherwise it generates
		 * improper ip header checksums.
		 */
		ipha_t *ipha = (ipha_t *)ptr;
		ipha->ipha_hdr_checksum = 0;

		/*
		 * TODO: figure out why it is ok to put 0 for the tcp checksum
		 * offset.
		 */
		*pi_data = NDIS_LSO2_INFO_MAKEIPV4(0, mss);
	} else if (hck_flags != 0) {
		/*
		 * The only checksum offload that we support is
		 * HCKSUM_INET_PARTIAL as advertised for MAC_CAPAB_HCKSUM.
		 */
		ASSERT3U(hck_flags, ==, HCK_PARTIALCKSUM);

		pi_data = hn_rndis_pktinfo_append(pkt, HN_RNDIS_PKT_LEN,
		    NDIS_TXCSUM_INFO_SIZE, NDIS_PKTINFO_TYPE_CSUM);

		uint8_t l4proto;

		if (sap == ETHERTYPE_IP) {
			ipha_t *ipha = (ipha_t *)ptr;
			l4proto = ipha->ipha_protocol;
			*pi_data = NDIS_TXCSUM_INFO_IPV4;
		} else if (sap == ETHERTYPE_IPV6) {
			ip6_t *ip6 = (ip6_t *)ptr;
			l4proto = ip6->ip6_nxt;
			*pi_data = NDIS_TXCSUM_INFO_IPV6;
		} else {
			HN_WARN(sc, "hn_tx_prepare_rndis_pkt: unexpected L3 "
			    "protocol: 0x%04x", sap);
			*pi_data = 0;
			goto skip_cksum;
		}

		switch (l4proto) {
		case IPPROTO_TCP:
			*pi_data |= NDIS_TXCSUM_INFO_TCPCS;

			/*
			 * TODO: figure out why it is ok to put 0 for
			 * the tcp checksum offset.
			 * Normally we'd need to specify what's the
			 * offset of the TCP checksum field using
			 * NDIS_TXCSUM_INFO_THOFF() but in practice it
			 * seems to be fine to leave this field as 0.
			 */
			break;
		case IPPROTO_UDP:
			/*
			 * TODO: Investigate / test?
			 * There seemed to be issues with UDP checksum
			 * calculation on W2008 hosts and in some cases
			 * in W2012 hosts. In Linux, they disable UDP
			 * checksum offload in those case:
			 * http://lxr.free-electrons.com/source/
			 *   drivers/net/hyperv/netvsc_drv.c#L486
			 * It seems like in FreeBSD, they were also
			 * doing this until commit on 09/20/2016,
			 * 9dd94538df4fa56fb715d19b93802fe67f5bbf4c
			 * (https://reviews.freebsd.org/D7948)
			 * which removed that restriction.
			 */
			*pi_data |= NDIS_TXCSUM_INFO_UDPCS;
			break;
		default:
			/*
			 * FIXME: we can end up here if we have a TCP or UDP
			 * IPv6 packet with extension headers. As a result,
			 * proper checksum offload flags will not be set for
			 * this packet and it has a high chance to be dropped
			 * by the receiver.
			 */
			HN_WARN(sc, "hn_tx_prepare_rndis_pkt: unexpected "
			    "transport protocol: 0x%04x", l4proto);
		}
	}

skip_cksum:
	pktlen = pkt->rm_pktinfooffset + pkt->rm_pktinfolen;
	/* Convert RNDIS packet message offsets as per 2.2.14 */
	pkt->rm_dataoffset = hn_rndis_pktmsg_offset(pkt->rm_dataoffset);
	pkt->rm_pktinfooffset = hn_rndis_pktmsg_offset(pkt->rm_pktinfooffset);

	return (pktlen);
}

/*
 * NOTE:
 * If this function fails, then both txd and mp will be freed.
 */
static int
hn_encap(struct hn_tx_ring *txr, struct hn_txdesc *txd, mblk_t *mp)
{
	struct hn_softc *sc = txr->hn_sc;
	hn_tx_stats_t *stats = &txr->hn_tx_stats;
	int error;
	int pktlen; /* length of rndis packet header */

	ASSERT3P(mp->b_next, ==, NULL);

	int dlen = 0;
	for (mblk_t *m = mp; m != NULL; m = m->b_cont) {
		dlen += MBLKL(m);
	}
	txr->hn_pkt_length = dlen;

	/*
	 * Look at the ethernet header to figure out if the packet is unicast,
	 * multicast or broadcast.
	 * We do this here while the mblk is still available.
	 */
	if (mp->b_rptr[0] & 0x1) {
		if (bcmp(mp->b_rptr, hn_broadcast, ETHERADDRL) != 0)
			txr->hn_pkt_type = HN_MULTICAST;
		else
			txr->hn_pkt_type = HN_BROADCAST;
	} else {
		txr->hn_pkt_type = HN_UNICAST;
	}

	if (dlen + HN_RNDIS_PKT_LEN < txr->hn_chim_size) {
		/*
		 * Fast path: Chimney sending.
		 * This packet is small enough to fit into a chimney sending
		 * buffer.  Try allocating one chimney sending buffer now.
		 */
		stats->chimney_tried++;
		txd->chim_index = hn_chim_alloc(sc);
		if (txd->chim_index != HN_NVS_CHIM_IDX_INVALID) {
			caddr_t chim = sc->hn_chim +
			    (txd->chim_index * sc->hn_chim_szmax);
			/*
			 * Directly fill the chimney sending buffer w/ the
			 * RNDIS packet message.
			 */
			struct rndis_packet_msg *pkt = (void *)chim;
			pktlen = hn_tx_prepare_rndis_pkt(sc, pkt, mp, dlen,
			    txr->hn_tx_idx);

			/* Copy message into chimney (mblk is freed) */
			mcopymsg(mp, chim + pktlen);
			txd->m = NULL;

			txd->chim_size = pkt->rm_len;
			txr->hn_gpa_cnt = 0;
			stats->chimney_sent++;
			txr->hn_sendpkt = hn_txpkt_chim;
			goto done;
		}
	}

	pktlen = hn_tx_prepare_rndis_pkt(sc, txd->rndis_pkt, mp, dlen,
	    txr->hn_tx_idx);

	/* send packet with page buffer */
	error = hn_txdesc_dmamap_load(txr, txd, mp, pktlen);
	/* check if we have too many segments */
	if (error == EAGAIN) {
		mblk_t *nmp = msgpullup(mp, -1);
		freemsg(mp);
		mp = nmp;
		stats->pulledup++;
		error = hn_txdesc_dmamap_load(txr, txd, mp, pktlen);
	}
	if (error != 0) {
		/*
		 * This mblk is not linked w/ the txd yet, so free it now.
		 */
		freemsg(mp);
		hn_txdesc_put(txr, txd);
		stats->dma_failed++;
		return (error);
	}

	txd->m = mp;
	txd->chim_index = HN_NVS_CHIM_IDX_INVALID;
	txd->chim_size = 0;
	txr->hn_sendpkt = hn_txpkt_sglist;
done:
	/* Set the completion routine */
	hn_nvs_sendctx_init(&txd->send_ctx, hn_txpkt_done, txd);

	return (0);
}

/*
 * NOTE:
 * If this function fails, then both the txd and mblk will be freed.
 */
static int
hn_txpkt(struct hn_tx_ring *txr, struct hn_txdesc *txd)
{
	int error;
	hn_tx_stats_t *stats = &txr->hn_tx_stats;

	error = txr->hn_sendpkt(txr, txd);

	if (error == 0) {
		if (txr->hn_pkt_type == HN_MULTICAST)
			stats->mcast_pkts++;
		else if (txr->hn_pkt_type == HN_BROADCAST)
			stats->bcast_pkts++;
		stats->pkts++;
		stats->bytes += txr->hn_pkt_length;
	} else {
		/*
		 * This should "really rarely" happen.
		 *
		 * XXX Too many RX to be acked or too many sideband
		 * commands to run?
		 */
		stats->send_failed++;
		HN_WARN(txr->hn_sc, "send failed, err=%d", error);

		/* discard packet */
		hn_txdesc_put(txr, txd);
	}
	return (error);
}

int
hn_rxpkt(struct hn_rx_ring *rxr, const void *data, int dlen,
    const struct hn_rxinfo *info)
{
	struct hn_softc *sc = rxr->hn_sc;
	hn_rx_stats_t *stats = &rxr->hn_rx_stats;

	ASSERT(MUTEX_HELD(&rxr->hn_rx_lock));

	if (!sc->hn_running)
		return (0);

	/*
	 * Bail out if packet contains more data than configured MTU.
	 */
	if (dlen > (sc->hn_mtu + sizeof (struct ether_vlan_header))) {
		HN_DEBUG(sc, 3, "discarding oversized packet");
		return (0);
	}

	mblk_t *mp = allocb(dlen, 0);
	if (mp == NULL) {
		stats->norxbufs++;
		stats->ierrors++;
		return (0);
	}
	/*
	 * We cannot bind the buffer provided by vsc, so we must always
	 * copy it.
	 */
	bcopy(data, mp->b_rptr, dlen);
	mp->b_wptr = mp->b_rptr + dlen;

	/* receive side checksum offload */
	uint32_t hcksum_flags = 0;
	if (info->csum_info != HN_NDIS_RXCSUM_INFO_INVALID) {
		if (info->csum_info & NDIS_RXCSUM_INFO_IPCS_OK) {
			hcksum_flags |= HCK_IPV4_HDRCKSUM_OK;
			stats->csum_ip++;
		}

		if (info->csum_info & NDIS_RXCSUM_INFO_UDPCS_OK) {
			hcksum_flags |= HCK_FULLCKSUM_OK;
			stats->csum_udp++;
		}

		if (info->csum_info & NDIS_RXCSUM_INFO_TCPCS_OK) {
			hcksum_flags |= HCK_FULLCKSUM_OK;
			stats->csum_tcp++;
		}
	} else {
		/*
		 * FreeBSD's implementation seems to suggest that the host
		 * might omit filling up csum_info even though the checksums
		 * have actually been checked.
		 */
		hcksum_flags = hn_get_implied_hcksum(rxr, mp);
	}

	if (hcksum_flags != 0)
		mac_hcksum_set(mp, 0, 0, 0, 0, hcksum_flags);

	/*
	 * Look at the ethernet header to figure out if the packet is unicast,
	 * multicast or broadcast.
	 */
	if (mp->b_rptr[0] & 0x1) {
		if (bcmp(mp->b_rptr, hn_broadcast, ETHERADDRL) != 0)
			stats->mcast_pkts++;
		else
			stats->bcast_pkts++;
	}
	stats->pkts++;
	stats->bytes += dlen;

	/*
	 * Enqueue pending received packets so that we can send them all
	 * at once to the MAC framework in hn_nvs_handle_rxbuf().
	 */
	if (rxr->hn_mps != NULL) {
		ASSERT(rxr->hn_mp_tail != NULL);
		rxr->hn_mp_tail->b_next = mp;
		rxr->hn_mp_tail = mp;
	} else {
		rxr->hn_mps = mp;
		rxr->hn_mp_tail = mp;
	}

	return (0);
}

void
hn_stop(struct hn_softc *sc)
{
	HN_LOCK_ASSERT(sc);
	if (!sc->hn_running)
		return;

	ASSERT(sc->hn_flags & HN_FLAG_SYNTH_ATTACHED);

	/* Clear RUNNING _before_ hn_suspend_data() */
	sc->hn_running = B_FALSE;
	hn_suspend_data(sc);
}
static void
hn_init_locked(struct hn_softc *sc)
{
	HN_LOCK_ASSERT(sc);

	if (!(sc->hn_flags & HN_FLAG_SYNTH_ATTACHED))
		return;

	if (sc->hn_running)
		return;

	/* Configure RX filter */
	(void) hn_set_rxfilter(sc);

	/* Clear TX 'suspended' bit. */
	hn_resume_tx(sc, sc->hn_tx_ring_inuse);

	/* Everything is ready; unleash! */
	sc->hn_running = B_TRUE;
}

void
hn_init(void *xsc)
{
	struct hn_softc *sc = xsc;

	HN_LOCK(sc);
	hn_init_locked(sc);
	HN_UNLOCK(sc);
}

/*
 * Do a sanity check of the received packet.
 * Return the relevant hardware checksum flags depending on the protocol
 * of the packet.
 *
 * Returns flags to be passed to mac_hcksum_set().
 */
static uint32_t
hn_get_implied_hcksum(struct hn_rx_ring *rxr, const mblk_t *mp)
{
	unsigned char *ptr = mp->b_rptr;
	int dlen = MBLKL(mp);
	uint32_t sap;

	ASSERT3P(mp->b_cont, ==, NULL);

	/*
	 * sanity check that we do not read past the buffer size
	 */
	if (dlen < sizeof (struct ether_vlan_header))
		return (0);

	sap = ntohs(((struct ether_header *)ptr)->ether_type);
	if (sap == ETHERTYPE_VLAN) {
		sap = ntohs(((struct ether_vlan_header *)ptr)->ether_type);
		ptr += sizeof (struct ether_vlan_header);
		dlen -= sizeof (struct ether_vlan_header);
	} else {
		ptr += sizeof (struct ether_header);
		dlen -= sizeof (struct ether_header);
	}

	/*
	 * check that the packet has an IPv4 header
	 */
	if (sap != ETHERTYPE_IP)
		return (0);

	if (dlen < sizeof (ipha_t))
		return (0);

	ipha_t *ipha = (ipha_t *)ptr;
	int iphlen = IPH_HDR_LENGTH(ipha);

	if (iphlen < sizeof (ipha_t))
		return (0);

	/*
	 * Ignore IP fragments.
	 */
	if (IS_V4_FRAGMENT(ipha->ipha_fragment_offset_and_flags))
		return (0);

	int iplen = ntohs(ipha->ipha_length);
	if (dlen < iplen)
		return (0);

	ptr += iphlen;
	dlen -= iphlen;

	switch (ipha->ipha_protocol) {
	case IPPROTO_TCP:
		/*
		 * TODO: not sure if we need those checks in Illumos
		 */
		if (iplen < iphlen + sizeof (tcph_t))
			return (0);
		int tcphlen = TCP_HDR_LENGTH(ptr);
		if (tcphlen < sizeof (tcph_t) || tcphlen + iphlen > iplen)
			return (0);

		if (rxr->hn_trust_hcsum & HN_TRUST_HCSUM_TCP) {
			rxr->hn_rx_stats.csum_trusted++;
			return (HCK_FULLCKSUM_OK | HCK_IPV4_HDRCKSUM_OK);
		}
		break;
	case IPPROTO_UDP:
		/*
		 * TODO: not sure if we need this check in Illumos
		 */
		if (iplen < iphlen + sizeof (struct udphdr))
			return (0);

		if (rxr->hn_trust_hcsum & HN_TRUST_HCSUM_UDP) {
			rxr->hn_rx_stats.csum_trusted++;
			return (HCK_FULLCKSUM_OK | HCK_IPV4_HDRCKSUM_OK);
		}
		break;
	default:
		if (iplen < iphlen)
			return (0);

		if (rxr->hn_trust_hcsum & HN_TRUST_HCSUM_IP) {
			rxr->hn_rx_stats.csum_trusted++;
			return (HCK_IPV4_HDRCKSUM_OK);
		}
	}

	return (0);
}

static int
hn_create_rx_data(struct hn_softc *sc)
{
	/*
	 * Create RXBUF for reception.
	 *
	 * NOTE:
	 * - It is shared by all channels.
	 * - A large enough buffer is allocated, certain version of NVSes
	 *   may further limit the usable space.
	 */
	sc->hn_rxbuf = hyperv_dmamem_alloc(sc->hn_dev,
	    PAGESIZE, 0, HN_RXBUF_SIZE, &sc->hn_rxbuf_dma,
	    DDI_DMA_RDWR);
	if (sc->hn_rxbuf == NULL) {
		HN_WARN(sc, "allocate rxbuf failed");
		return (ENOMEM);
	}

	sc->hn_rx_ring_inuse = sc->hn_rx_ring_cnt;

	sc->hn_rx_ring = kmem_zalloc(sizeof (struct hn_rx_ring) *
	    sc->hn_rx_ring_cnt, KM_SLEEP);

	for (int i = 0; i < sc->hn_rx_ring_cnt; i++) {
		struct hn_rx_ring *rxr = &sc->hn_rx_ring[i];
		rxr->hn_sc = sc;

		rxr->hn_br = hyperv_dmamem_alloc(sc->hn_dev, PAGESIZE, 0,
		    HN_TXBR_SIZE + HN_RXBR_SIZE,
		    &rxr->hn_br_dma, DDI_DMA_RDWR);
		if (rxr->hn_br == NULL) {
			HN_WARN(sc, "allocate bufring failed");
			return (ENOMEM);
		}

		if (hn_trust_host_cksum)
			rxr->hn_trust_hcsum = HN_TRUST_HCSUM_ALL;

		if (i < sc->hn_tx_ring_cnt)
			rxr->hn_txr = &sc->hn_tx_ring[i];
		rxr->hn_pktbuf_len = HN_PKTBUF_LEN_DEF;
		rxr->hn_pktbuf = kmem_zalloc(rxr->hn_pktbuf_len, KM_SLEEP);
		rxr->hn_rx_idx = i;
		rxr->hn_rxbuf = sc->hn_rxbuf;
	}

	return (0);
}

static void
hn_destroy_rx_data(struct hn_softc *sc)
{
	if (sc->hn_rxbuf != NULL) {
		if ((sc->hn_flags & HN_FLAG_RXBUF_REF) == 0)
			hyperv_dmamem_free(&sc->hn_rxbuf_dma);
		else
			HN_WARN(sc, "RXBUF is referenced");
		sc->hn_rxbuf = NULL;
	}

	if (sc->hn_rx_ring_cnt == 0)
		return;

	for (int i = 0; i < sc->hn_rx_ring_cnt; i++) {
		struct hn_rx_ring *rxr = &sc->hn_rx_ring[i];

		if (rxr->hn_br != NULL) {
			if ((rxr->hn_rx_flags & HN_RX_FLAG_BR_REF) == 0) {
				hyperv_dmamem_free(&rxr->hn_br_dma);
			} else {
				HN_WARN(sc,
				    "%dth channel bufring is referenced", i);
			}
			rxr->hn_br = NULL;
		}

		if (rxr->hn_pktbuf != NULL) {
			kmem_free(rxr->hn_pktbuf, rxr->hn_pktbuf_len);
			rxr->hn_pktbuf = NULL;
		}
	}
	if (sc->hn_rx_ring != NULL) {
		kmem_free(sc->hn_rx_ring, sizeof (struct hn_rx_ring) *
		    sc->hn_rx_ring_cnt);
	}
	sc->hn_rx_ring = NULL;

	sc->hn_rx_ring_cnt = 0;
	sc->hn_rx_ring_inuse = 0;
}

/*
 * DMA alignment and boundary constraints for RNDIS packet
 */
CTASSERT(ISP2(HN_RNDIS_PKT_BOUNDARY));
static ddi_dma_attr_t hn_tx_rndis_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_align =	HN_RNDIS_PKT_ALIGN,
	.dma_attr_burstsizes =	0x0000000000001FFFull,
	.dma_attr_minxfer =	0x00000001,
	.dma_attr_maxxfer =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_seg =		HN_RNDIS_PKT_BOUNDARY - 1,
	.dma_attr_sgllen =	1,
	.dma_attr_granular =	0x00000001,
	.dma_attr_flags =	0
};

/*
 * DMA alignment and boundary constraints for TX data
 */
CTASSERT(ISP2(HN_TX_DATA_BOUNDARY));
static ddi_dma_attr_t hn_tx_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000ull,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_count_max =	0xFFFFFFFFFFFFFFFFull,
	.dma_attr_align =	1,
	.dma_attr_burstsizes =	0x0000000000001FFFull,
	.dma_attr_minxfer =	0x00000001,
	.dma_attr_maxxfer =	HN_TX_DATA_MAXSIZE,
	.dma_attr_seg =		HN_TX_DATA_BOUNDARY - 1,
	.dma_attr_sgllen =	HN_TX_DATA_SEGCNT_MAX,
	.dma_attr_granular =	0x00000001,
	.dma_attr_flags =	0
};

static ddi_device_acc_attr_t hn_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC,
};

static int
hn_tx_ring_create(struct hn_softc *sc, int id)
{
	struct hn_tx_ring *txr = &sc->hn_tx_ring[id];
	int error;

	txr->hn_sc = sc;
	txr->hn_tx_idx = id;

	mutex_init(&txr->hn_tx_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * A bufring can hold one buffer less than its size
	 */
	txr->hn_txdesc_cnt = sc->hn_txdesc_cnt - 1;
	txr->hn_txdesc = kmem_zalloc(sizeof (struct hn_txdesc) *
	    txr->hn_txdesc_cnt, KM_SLEEP);
	txr->hn_txdesc_br = buf_ring_alloc(txr->hn_txdesc_cnt + 1, KM_SLEEP,
	    &txr->hn_tx_lock);
	/*
	 * XXX: HACK
	 * Allocate a DMA handle for the TX data. Note that we only use it to
	 * get the physical address for the memory and unbind it right after,
	 * thus we require only one per ring.
	 */
	error = ddi_dma_alloc_handle(sc->hn_dev, &hn_tx_dma_attr,
	    DDI_DMA_SLEEP, NULL, &txr->hn_data_dmah);
	if (error != DDI_SUCCESS) {
		HN_WARN(sc, "failed to allocate data_dmah, "
		    "error %d", error);
		return (EINVAL);
	}

	for (int i = 0; i < txr->hn_txdesc_cnt; i++) {
		struct hn_txdesc *txd = &txr->hn_txdesc[i];
		ddi_dma_cookie_t cookie;
		uint_t segcount;

		txd->txr = txr;
		txd->chim_index = HN_NVS_CHIM_IDX_INVALID;

		/*
		 * Allocate a DMA handle for the RNDIS packet
		 */
		error = ddi_dma_alloc_handle(sc->hn_dev, &hn_tx_rndis_dma_attr,
		    DDI_DMA_SLEEP, NULL, &txd->rndis_pkt_dmah);
		if (error != DDI_SUCCESS) {
			HN_WARN(sc, "failed to allocate rndis_packet_dmah[%d], "
			    "error %d", i, error);
			return (EINVAL);
		}

		/*
		 * Allocate memory for the RNDIS packet
		 */
		error = ddi_dma_mem_alloc(txd->rndis_pkt_dmah, HN_RNDIS_PKT_LEN,
		    &hn_dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		    (caddr_t *)&txd->rndis_pkt, &txd->rndis_pkt_buflen,
		    &txd->rndis_pkt_datah);
		if (error != DDI_SUCCESS) {
			HN_WARN(sc, "failed to allocate memory for "
			    "rndis_pkt[%d], error %d", i, error);
			ddi_dma_free_handle(&txd->rndis_pkt_dmah);
			return (EINVAL);
		}

		/*
		 * Map the memory of the RNDIS packet
		 */
		error = ddi_dma_addr_bind_handle(txd->rndis_pkt_dmah, NULL,
		    (caddr_t)txd->rndis_pkt, txd->rndis_pkt_buflen,
		    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    &cookie, &segcount);
		if (error != DDI_DMA_MAPPED) {
			HN_WARN(sc, "failed to bind rndis_packet_dmah[%d], "
			    "error %d", i, error);
			ddi_dma_mem_free(&txd->rndis_pkt_datah);
			ddi_dma_free_handle(&txd->rndis_pkt_dmah);
			return (EINVAL);
		}

		ASSERT3U(segcount, ==, 1);
		txd->rndis_pkt_paddr = cookie.dmac_laddress;

		/* All set, put it to list */
		txd->flags |= HN_TXD_FLAG_ONLIST;
		error = buf_ring_enqueue(txr->hn_txdesc_br, txd);
		ASSERT0(error);
	}
	txr->hn_txdesc_avail = txr->hn_txdesc_cnt;

	return (0);
}

static void
hn_txdesc_dmamap_destroy(struct hn_txdesc *txd)
{
	ASSERT3P(txd->m, ==, NULL);
	ASSERT0(txd->flags & HN_TXD_FLAG_DMAMAP);

	(void) ddi_dma_unbind_handle(txd->rndis_pkt_dmah);
	ddi_dma_mem_free(&txd->rndis_pkt_datah);
	ddi_dma_free_handle(&txd->rndis_pkt_dmah);
}

#ifdef txagg
static void
hn_txdesc_gc(struct hn_tx_ring *txr, struct hn_txdesc *txd)
{
	KASSERT(txd->refs == 0 || txd->refs == 1,
	    ("invalid txd refs %d", txd->refs));

	/* Aggregated txds will be freed by their aggregating txd. */
	if (txd->refs > 0 && (txd->flags & HN_TXD_FLAG_ONAGG) == 0) {
		int freed;

		freed = hn_txdesc_put(txr, txd);
		KASSERT(freed, ("can't free txdesc"));
	}
}
#endif

static void
hn_tx_ring_destroy(struct hn_tx_ring *txr)
{
	struct hn_softc *sc = txr->hn_sc;
	struct hn_txdesc *txd;

	if (txr->hn_txdesc == NULL)
		return;

	if (txr->hn_data_dmah != NULL)
		ddi_dma_free_handle(&txr->hn_data_dmah);

#ifdef txagg
	/*
	 * NOTE:
	 * Because the freeing of aggregated txds will be deferred
	 * to the aggregating txd, two passes are used here:
	 * - The first pass GCes any pending txds.  This GC is necessary,
	 *   since if the channels are revoked, hypervisor will not
	 *   deliver send-done for all pending txds.
	 * - The second pass frees the busdma stuffs, i.e. after all txds
	 *   were freed.
	 */
	for (int i = 0; i < txr->hn_txdesc_cnt; ++i)
		hn_txdesc_gc(txr, &txr->hn_txdesc[i]);
	for (int i = 0; i < txr->hn_txdesc_cnt; ++i)
		hn_txdesc_dmamap_destroy(&txr->hn_txdesc[i]);
#else
	mutex_enter(&txr->hn_tx_lock);
	if (i_ddi_devi_attached(sc->hn_dev) && hn_tx_ring_pending(txr)) {
		HN_WARN(sc, "leaking %d descriptors from tx ring %d",
		    buf_ring_count(txr->hn_txdesc_br), txr->hn_tx_idx);
	}
	while ((txd = buf_ring_dequeue_sc(txr->hn_txdesc_br)) != NULL)
		hn_txdesc_dmamap_destroy(txd);
	mutex_exit(&txr->hn_tx_lock);
#endif

	kmem_free(txr->hn_txdesc, sizeof (struct hn_txdesc) *
	    txr->hn_txdesc_cnt);
	txr->hn_txdesc = NULL;
	buf_ring_free(txr->hn_txdesc_br);

	mutex_destroy(&txr->hn_tx_lock);
}

static int
hn_create_tx_data(struct hn_softc *sc)
{
	/*
	 * Create TXBUF for chimney sending.
	 *
	 * NOTE: It is shared by all channels.
	 */
	sc->hn_chim = hyperv_dmamem_alloc(sc->hn_dev,
	    PAGESIZE, 0, HN_CHIM_SIZE, &sc->hn_chim_dma,
	    DDI_DMA_RDWR);
	if (sc->hn_chim == NULL) {
		HN_WARN(sc, "allocate tx chimney buf failed");
		return (ENOMEM);
	}

	sc->hn_tx_ring_inuse = sc->hn_tx_ring_cnt;

	sc->hn_tx_ring = kmem_zalloc(sizeof (struct hn_tx_ring) *
	    sc->hn_tx_ring_cnt, KM_SLEEP);

	for (int i = 0; i < sc->hn_tx_ring_cnt; i++) {
		int error;

		error = hn_tx_ring_create(sc, i);
		if (error)
			return (error);
	}

	return (0);
}

void
hn_set_chim_size(struct hn_softc *sc, int chim_size)
{
	int i;

	for (i = 0; i < sc->hn_tx_ring_cnt; ++i)
		sc->hn_tx_ring[i].hn_chim_size = chim_size;
}

static void
hn_fixup_tx_data(struct hn_softc *sc)
{
	/*
	 * TX chimney is used as a fast path to send small packets.
	 */
	hn_set_chim_size(sc, sc->hn_chim_szmax);
	if (hn_tx_chimney_size > 0 &&
	    hn_tx_chimney_size < sc->hn_chim_szmax)
		hn_set_chim_size(sc, hn_tx_chimney_size);

	/*
	 * Determine which hardware checksum offloading features
	 * are enabled.
	 */
	sc->hn_hcksum_flags = 0;
	if (sc->hn_tx_hcksum_enable) {
		if ((sc->hn_caps & HN_CAP_L4CS) == HN_CAP_L4CS)
			sc->hn_hcksum_flags |= HCKSUM_INET_PARTIAL;
	}

	/*
	 * Determine if Large Send Offload is enabled.
	 */
	sc->hn_lso_flags = 0;
	if (sc->hn_lso_enable && (sc->hn_caps & HN_CAP_TSO4))
		sc->hn_lso_flags = LSO_TX_BASIC_TCP_IPV4;
}
static void
hn_destroy_tx_data(struct hn_softc *sc)
{
	int i;

	if (sc->hn_chim != NULL) {
		if ((sc->hn_flags & HN_FLAG_CHIM_REF) == 0) {
			hyperv_dmamem_free(&sc->hn_chim_dma);
		} else {
			HN_WARN(sc,
			    "chimney sending buffer is referenced");
		}
		sc->hn_chim = NULL;
	}

	if (sc->hn_tx_ring_cnt == 0)
		return;

	for (i = 0; i < sc->hn_tx_ring_cnt; ++i)
		hn_tx_ring_destroy(&sc->hn_tx_ring[i]);

	kmem_free(sc->hn_tx_ring, sizeof (struct hn_tx_ring) *
	    sc->hn_tx_ring_cnt);
	sc->hn_tx_ring = NULL;

	sc->hn_tx_ring_cnt = 0;
	sc->hn_tx_ring_inuse = 0;
}

mblk_t *
hn_xmit(struct hn_tx_ring *txr, mblk_t *mp)
{
	struct hn_txdesc *txd;
	int error;

	/*
	 * If the tx is suspended (e.g. we are doing an MTU change), return
	 * we will reschedule the packets once interface is resumed.
	 */
	if (__predict_false(txr->hn_suspended))
		return (mp);

	ASSERT3P(mp, !=, NULL);
	ASSERT3P(mp->b_next, ==, NULL);

	txd = hn_txdesc_get(txr);
	if (txd == NULL) {
		/*
		 * We set hn_reschedule and check for descriptors again. If we
		 * still get no descriptors, this guarantees that
		 * hn_txpkt_done() will be called some time in the future and
		 * will call mac_tx_ring_update().
		 */
		txr->hn_reschedule = B_TRUE;
		txd = hn_txdesc_get(txr);
		if (txd == NULL) {
			/*
			 * No descriptors available for now, return the packet
			 * back to the MAC framework so it can reschedule a send
			 * later.
			 */
			txr->hn_tx_stats.no_txdescs++;
			return (mp);
		} else {
			txr->hn_reschedule = B_FALSE;
		}
	}

	/*
	 * Note: on error, both txd and mp are freed; discard packet
	 */
	error = hn_encap(txr, txd, mp);
	if (error == 0)
		error = hn_txpkt(txr, txd);

	return (NULL);
}

/*
 * Like any other enlightened driver, netvsc uses channels in order to
 * communicate with the primary partition (i.e. netvsp in this case). Each
 * channel is bi-directional and can be tied to a given CPU. In the case of
 * netvsc, we need one channel for each rx/tx ring pair. Each device receives
 * exactly one primary channel from vmbus, but can request additional
 * sub-channels. The primary channel must be used for all management
 * communications with the primary partition, but other than that it is
 * almost identical to sub-channels.
 */
static int
hn_chan_attach(struct hn_softc *sc, struct vmbus_channel *chan)
{
	struct vmbus_chan_br cbr;
	struct hn_rx_ring *rxr;
	struct hn_tx_ring *txr = NULL;
	int idx, error;

	idx = vmbus_chan_subidx(chan);

	/*
	 * Link this channel to RX/TX ring.
	 */
	ASSERT3S(idx, >=, 0);
	ASSERT3S(idx, <, sc->hn_rx_ring_inuse);

	rxr = &sc->hn_rx_ring[idx];
	ASSERT0(rxr->hn_rx_flags & HN_RX_FLAG_ATTACHED);
	rxr->hn_rx_flags |= HN_RX_FLAG_ATTACHED;

	HN_DEBUG(sc, 1, "link RX ring %d to chan%u", idx,
	    vmbus_chan_id(chan));

	if (idx < sc->hn_tx_ring_inuse) {
		txr = &sc->hn_tx_ring[idx];
		ASSERT0(txr->hn_tx_flags & HN_TX_FLAG_ATTACHED);

		txr->hn_tx_flags |= HN_TX_FLAG_ATTACHED;

		txr->hn_chan = chan;
		HN_DEBUG(sc, 1, "link TX ring %d to chan%u", idx,
		    vmbus_chan_id(chan));
	}

	/* Bind this channel to a proper CPU. */
	vmbus_chan_cpu_set(chan, (sc->hn_cpu + idx) % ncpus);

	/*
	 * Open this channel
	 */
	cbr.cbr = rxr->hn_br;
	cbr.cbr_paddr = rxr->hn_br_dma.hv_paddr;
	cbr.cbr_txsz = HN_TXBR_SIZE;
	cbr.cbr_rxsz = HN_RXBR_SIZE;
	error = vmbus_chan_open_br(chan, &cbr, NULL, 0, hn_chan_callback, rxr);
	if (error != 0) {
		if (error == EISCONN) {
			HN_WARN(sc, "bufring is connected after "
			    "chan%u open failure", vmbus_chan_id(chan));
			rxr->hn_rx_flags |= HN_RX_FLAG_BR_REF;
		} else {
			HN_WARN(sc, "open chan%u failed: %d",
			    vmbus_chan_id(chan), error);
		}
	}
	return (error);
}

static void
hn_chan_detach(struct hn_softc *sc, struct vmbus_channel *chan)
{
	struct hn_rx_ring *rxr;
	int idx, error;

	idx = vmbus_chan_subidx(chan);

	/*
	 * Link this channel to RX/TX ring.
	 */
	ASSERT3S(idx, >=, 0);
	ASSERT3S(idx, <, sc->hn_rx_ring_inuse);
	rxr = &sc->hn_rx_ring[idx];

	ASSERT(rxr->hn_rx_flags & HN_RX_FLAG_ATTACHED);
	rxr->hn_rx_flags &= ~HN_RX_FLAG_ATTACHED;

	if (idx < sc->hn_tx_ring_inuse) {
		struct hn_tx_ring *txr = &sc->hn_tx_ring[idx];

		ASSERT(txr->hn_tx_flags & HN_TX_FLAG_ATTACHED);
		txr->hn_tx_flags &= ~HN_TX_FLAG_ATTACHED;
	}

	/*
	 * Close this channel.
	 *
	 * NOTE:
	 * Channel closing does _not_ destroy the target channel.
	 */
	error = vmbus_chan_close_direct(chan);
	if (error == EISCONN) {
		HN_WARN(sc, "chan%u bufring is connected "
		    "after being closed", vmbus_chan_id(chan));
		rxr->hn_rx_flags |= HN_RX_FLAG_BR_REF;
	} else if (error) {
		HN_WARN(sc, "chan%u close failed: %d",
		    vmbus_chan_id(chan), error);
	}
}

static int
hn_attach_subchans(struct hn_softc *sc)
{
	struct vmbus_channel **subchans;
	int subchan_cnt = sc->hn_rx_ring_inuse - 1;
	int i, error = 0;

	ASSERT(subchan_cnt > 0);

	/* Attach the sub-channels. */
	subchans = vmbus_subchan_get(sc->hn_prichan, subchan_cnt);
	for (i = 0; i < subchan_cnt; ++i) {
		int error1;

		error1 = hn_chan_attach(sc, subchans[i]);
		if (error1) {
			error = error1;
			/* Move on; all channels will be detached later. */
		}
	}
	vmbus_subchan_rel(subchans, subchan_cnt);

	if (error) {
		HN_WARN(sc, "sub-channels attach failed: %d", error);
	} else {
		HN_DEBUG(sc, 1, "%d sub-channels attached", subchan_cnt);
	}
	return (error);
}

static void
hn_detach_allchans(struct hn_softc *sc)
{
	struct vmbus_channel **subchans;
	int subchan_cnt = sc->hn_rx_ring_inuse - 1;
	int i;

	if (subchan_cnt == 0)
		goto back;

	/* Detach the sub-channels. */
	subchans = vmbus_subchan_get(sc->hn_prichan, subchan_cnt);
	for (i = 0; i < subchan_cnt; ++i)
		hn_chan_detach(sc, subchans[i]);
	vmbus_subchan_rel(subchans, subchan_cnt);

back:
	/*
	 * Detach the primary channel, _after_ all sub-channels
	 * are detached.
	 */
	hn_chan_detach(sc, sc->hn_prichan);

	/* Wait for sub-channels to be destroyed, if any. */
	vmbus_subchan_drain(sc->hn_prichan);

	for (i = 0; i < sc->hn_rx_ring_cnt; ++i)
		VERIFY0(sc->hn_rx_ring[i].hn_rx_flags & HN_RX_FLAG_ATTACHED);

	for (i = 0; i < sc->hn_tx_ring_cnt; ++i)
		VERIFY0(sc->hn_tx_ring[i].hn_tx_flags & HN_TX_FLAG_ATTACHED);
}

static int
hn_synth_alloc_subchans(struct hn_softc *sc, int *nsubch)
{
	struct vmbus_channel **subchans;
	int nchan, rxr_cnt, error;

	nchan = *nsubch + 1;
	if (nchan == 1) {
		/*
		 * Multiple RX/TX rings are not requested.
		 */
		*nsubch = 0;
		return (0);
	}

	/*
	 * Query RSS capabilities, e.g. # of RX rings, and # of indirect
	 * table entries.
	 */
	error = hn_rndis_query_rsscaps(sc, &rxr_cnt);
	if (error) {
		/* No RSS; this is benign. */
		*nsubch = 0;
		return (0);
	}
	HN_DEBUG(sc, 1, "RX rings offered %u, requested %d", rxr_cnt, nchan);

	if (nchan > rxr_cnt)
		nchan = rxr_cnt;
	if (nchan == 1) {
		HN_WARN(sc, "only 1 channel is supported, no vRSS");
		*nsubch = 0;
		return (0);
	}

	/*
	 * Allocate sub-channels from NVS.
	 */
	*nsubch = nchan - 1;
	error = hn_nvs_alloc_subchans(sc, nsubch);
	if (error || *nsubch == 0) {
		/* Failed to allocate sub-channels. */
		*nsubch = 0;
		return (0);
	}

	/*
	 * Wait for all sub-channels to become ready before moving on.
	 */
	subchans = vmbus_subchan_get(sc->hn_prichan, *nsubch);
	vmbus_subchan_rel(subchans, *nsubch);
	return (0);
}

static boolean_t
hn_synth_attachable(const struct hn_softc *sc)
{
	int i;

	if (sc->hn_flags & HN_FLAG_ERRORS)
		return (B_FALSE);

	for (i = 0; i < sc->hn_rx_ring_cnt; ++i) {
		const struct hn_rx_ring *rxr = &sc->hn_rx_ring[i];

		if (rxr->hn_rx_flags & HN_RX_FLAG_BR_REF)
			return (B_FALSE);
	}
	return (B_TRUE);
}

static int
hn_synth_attach(struct hn_softc *sc, int mtu)
{
	struct ndis_rssprm_toeplitz *rss = &sc->hn_rss;
	int error, nsubch, nchan, i;
	uint32_t old_caps;
	boolean_t attached_nvs = B_FALSE, attached_rndis = B_FALSE;

	ASSERT0(sc->hn_flags & HN_FLAG_SYNTH_ATTACHED);

	if (!hn_synth_attachable(sc))
		return (ENXIO);

	/* Save capabilities for later verification. */
	old_caps = sc->hn_caps;
	sc->hn_caps = 0;

	/* Clear RSS stuffs. */
	sc->hn_rss_ind_size = 0;
	sc->hn_rss_hash = 0;

	/*
	 * Attach the primary channel _before_ attaching NVS and RNDIS.
	 */
	error = hn_chan_attach(sc, sc->hn_prichan);
	if (error != 0)
		goto failed;

	/*
	 * Attach NVS.
	 */
	error = hn_nvs_attach(sc, mtu);
	if (error != 0)
		goto failed;
	attached_nvs = B_TRUE;

	/*
	 * Attach RNDIS _after_ NVS is attached.
	 */
	error = hn_rndis_attach(sc, mtu);
	if (error != 0)
		goto failed;
	attached_rndis = B_TRUE;

	/*
	 * Make sure capabilities are not changed.
	 */
	if (i_ddi_devi_attached(sc->hn_dev) && old_caps != sc->hn_caps) {
		HN_WARN(sc, "caps mismatch old 0x%08x, new 0x%08x",
		    old_caps, sc->hn_caps);
		error = ENXIO;
		goto failed;
	}

	/*
	 * Allocate sub-channels for multi-TX/RX rings.
	 *
	 * NOTE:
	 * The # of RX rings that can be used is equivalent to the # of
	 * channels to be requested.
	 */
	nsubch = sc->hn_rx_ring_inuse - 1;
	error = hn_synth_alloc_subchans(sc, &nsubch);
	if (error != 0)
		goto failed;
	/* NOTE: _Full_ synthetic parts detach is required now. */
	sc->hn_flags |= HN_FLAG_SYNTH_ATTACHED;

	/*
	 * Set the # of TX/RX rings that could be used according to
	 * the # of channels that NVS offered.
	 */
	nchan = nsubch + 1;
	hn_update_ring_inuse(sc, nchan);
	if (nchan == 1) {
		/* Only the primary channel can be used; done */
		goto back;
	}

	/*
	 * Attach the sub-channels.
	 *
	 * NOTE: hn_update_ring_inuse() _must_ have been called.
	 */
	error = hn_attach_subchans(sc);
	if (error != 0)
		goto failed;

	/*
	 * Configure RSS key and indirect table _after_ all sub-channels
	 * are attached.
	 */
	if ((sc->hn_flags & HN_FLAG_HAS_RSSKEY) == 0) {
		/*
		 * RSS key is not set yet; set it to the default RSS key.
		 */
		HN_DEBUG(sc, 1, "setup default RSS key");
		(void) memcpy(rss->rss_key, hn_rss_key_default,
		    sizeof (rss->rss_key));
		sc->hn_flags |= HN_FLAG_HAS_RSSKEY;
	}

	if ((sc->hn_flags & HN_FLAG_HAS_RSSIND) == 0) {
		/*
		 * RSS indirect table is not set yet; set it up in round-
		 * robin fashion.
		 */
		HN_DEBUG(sc, 1, "setup default RSS indirect table");
		for (i = 0; i < NDIS_HASH_INDCNT; ++i)
			rss->rss_ind[i] = i % nchan;
		sc->hn_flags |= HN_FLAG_HAS_RSSIND;
	} else {
		/*
		 * # of usable channels may be changed, so we have to
		 * make sure that all entries in RSS indirect table
		 * are valid.
		 *
		 * NOTE: hn_update_ring_inuse() _must_ have been called.
		 */
		hn_rss_ind_fixup(sc);
	}

	error = hn_rndis_conf_rss(sc, NDIS_RSS_FLAG_NONE);
	if (error != 0)
		goto failed;
back:
	return (0);

failed:
	if (sc->hn_flags & HN_FLAG_SYNTH_ATTACHED) {
		hn_synth_detach(sc);
	} else {
		if (attached_rndis)
			hn_rndis_detach(sc);
		if (attached_nvs)
			hn_nvs_detach(sc);
		hn_chan_detach(sc, sc->hn_prichan);
		/* Restore old capabilities. */
		sc->hn_caps = old_caps;
	}
	return (error);
}

/*
 * NOTE:
 * The interface must have been suspended though hn_suspend(), before
 * this function get called.
 */
static void
hn_synth_detach(struct hn_softc *sc)
{

	ASSERT(sc->hn_flags & HN_FLAG_SYNTH_ATTACHED);

	/* Detach the RNDIS first. */
	hn_rndis_detach(sc);

	/* Detach NVS. */
	hn_nvs_detach(sc);

	/* Detach all of the channels. */
	hn_detach_allchans(sc);

	sc->hn_flags &= ~HN_FLAG_SYNTH_ATTACHED;
}

static void
hn_update_ring_inuse(struct hn_softc *sc, int ring_cnt)
{
	ASSERT(ring_cnt > 0);
	VERIFY3U(ring_cnt, <=, sc->hn_rx_ring_inuse);

	/*
	 * Changing the amount of rings is not supported after
	 * mac_register() has been called.
	 */
	if (i_ddi_devi_attached(sc->hn_dev)) {
		VERIFY3U(ring_cnt, ==, sc->hn_rx_ring_inuse);
		VERIFY3U(ring_cnt, >=, sc->hn_tx_ring_inuse);
		return;
	}

	/*
	 * Rings in use must be initialized to the same number as
	 * rings count.
	 */
	VERIFY3U(sc->hn_rx_ring_cnt, ==, sc->hn_rx_ring_inuse);
	VERIFY3U(sc->hn_tx_ring_cnt, ==, sc->hn_tx_ring_inuse);

	if (ring_cnt < sc->hn_rx_ring_cnt) {
		HN_WARN(sc, "Rings in use (%d) < configured rings (%d) ",
		    ring_cnt, sc->hn_rx_ring_cnt);
	}

	/*
	 * The number of tx rings is limited by the number of channels, which
	 * is identical to the number of rx rings.
	 */
	if (sc->hn_tx_ring_inuse > ring_cnt)
		sc->hn_tx_ring_inuse = ring_cnt;

	sc->hn_rx_ring_inuse = ring_cnt;

	HN_DEBUG(sc, 1, "using %d TX rings, %d RX rings",
	    sc->hn_tx_ring_inuse, sc->hn_rx_ring_inuse);
}

static void
hn_chan_drain(struct hn_softc *sc, struct vmbus_channel *chan)
{

	/*
	 * NOTE:
	 * The TX bufring will not be drained by the hypervisor,
	 * if the primary channel is revoked.
	 */
	while (!vmbus_chan_rx_empty(chan) ||
	    (!vmbus_chan_is_revoked(sc->hn_prichan) &&
	    !vmbus_chan_tx_empty(chan)))
		delay(1);
	vmbus_chan_intr_drain(chan);
}

static void
hn_suspend_data(struct hn_softc *sc)
{
	struct vmbus_channel **subch = NULL;
	struct hn_tx_ring *txr;
	int i, nsubch;

	HN_LOCK_ASSERT(sc);

	/*
	 * Suspend TX.
	 */
	for (i = 0; i < sc->hn_tx_ring_inuse; ++i) {
		txr = &sc->hn_tx_ring[i];

		mutex_enter(&txr->hn_tx_lock);
		txr->hn_suspended = B_TRUE;
		mutex_exit(&txr->hn_tx_lock);
		/* No one is able to send more packets now. */

		/*
		 * Wait for all pending sends to finish.
		 *
		 * NOTE:
		 * We will _not_ receive all pending send-done, if the
		 * primary channel is revoked.
		 */
		while (hn_tx_ring_pending(txr) &&
		    !vmbus_chan_is_revoked(sc->hn_prichan))
			delay(1); /* 1 tick */
		/* TODO: timeout ? */
		if (hn_tx_ring_pending(txr)) {
			HN_WARN(sc, "tx ring %d suspended while %d "
			    "descriptors are still inflight", i,
			    buf_ring_count(txr->hn_txdesc_br));
		}
	}

	/*
	 * Disable RX by clearing RX filter.
	 */
	sc->hn_rx_filter = NDIS_PACKET_TYPE_NONE;
	(void) hn_rndis_set_rxfilter(sc, sc->hn_rx_filter);

	/*
	 * Give RNDIS enough time to flush all pending data packets.
	 */
	delay(MSEC_TO_TICK(200));

	/*
	 * Drain RX/TX bufrings and interrupts.
	 */
	nsubch = sc->hn_rx_ring_inuse - 1;
	if (nsubch > 0)
		subch = vmbus_subchan_get(sc->hn_prichan, nsubch);

	if (subch != NULL) {
		for (i = 0; i < nsubch; ++i)
			hn_chan_drain(sc, subch[i]);
	}
	hn_chan_drain(sc, sc->hn_prichan);

	if (subch != NULL)
		vmbus_subchan_rel(subch, nsubch);
}

static void
hn_suspend_mgmt(struct hn_softc *sc)
{
	/*
	 * Make sure that hn_mgmt_taskq0 can no longer be accessed
	 * through hn_mgmt_taskq.
	 */
	mutex_enter(&sc->hn_mgmt_lock);
	sc->hn_mgmt_taskq = NULL;
	mutex_exit(&sc->hn_mgmt_lock);

	/*
	 * Make sure that all pending management tasks are completed.
	 */
	ddi_taskq_wait(sc->hn_mgmt_taskq0);
}

static void
hn_suspend(struct hn_softc *sc)
{

	if (sc->hn_running)
		hn_suspend_data(sc);
	hn_suspend_mgmt(sc);
}

static void
hn_resume_tx(struct hn_softc *sc, int tx_ring_cnt)
{
	int i;

	ASSERT3U(tx_ring_cnt, <=, sc->hn_tx_ring_cnt);

	for (i = 0; i < tx_ring_cnt; ++i) {
		struct hn_tx_ring *txr = &sc->hn_tx_ring[i];

		mutex_enter(&txr->hn_tx_lock);
		txr->hn_suspended = B_FALSE;
		mutex_exit(&txr->hn_tx_lock);

		/*
		 * Notify MAC that we can resume sending packets
		 */
		mac_tx_ring_update(txr->hn_sc->hn_mac_hdl, txr->hn_ring_handle);
	}
}

static void
hn_resume_data(struct hn_softc *sc)
{
	/*
	 * Re-enable RX.
	 */
	(void) hn_set_rxfilter(sc);

	/*
	 * Make sure to clear suspend status on "all" TX rings,
	 * since hn_tx_ring_inuse can be changed after
	 * hn_suspend_data().
	 */
	hn_resume_tx(sc, sc->hn_tx_ring_cnt);
}

static void
hn_resume_mgmt(struct hn_softc *sc)
{
	mutex_enter(&sc->hn_mgmt_lock);
	sc->hn_mgmt_taskq = sc->hn_mgmt_taskq0;
	mutex_exit(&sc->hn_mgmt_lock);

	/*
	 * Kick off network change detection, if it was pending.
	 * If no network change was pending, start link status
	 * checks, which is more lightweight than network change
	 * detection.
	 */
	if (sc->hn_link_flags & HN_LINK_FLAG_NETCHG)
		hn_change_network(sc);
	else
		hn_update_link_status(sc);
}

static void
hn_resume(struct hn_softc *sc)
{

	if (sc->hn_running)
		hn_resume_data(sc);
	hn_resume_mgmt(sc);
}

static void
hn_rndis_rx_status(struct hn_softc *sc, const void *data, int dlen)
{
	const struct rndis_status_msg *msg;
	int ofs;

	if (dlen < sizeof (*msg)) {
		HN_WARN(sc, "invalid RNDIS status");
		return;
	}
	msg = data;

	switch (msg->rm_status) {
	case RNDIS_STATUS_MEDIA_CONNECT:
	case RNDIS_STATUS_MEDIA_DISCONNECT:
		hn_update_link_status(sc);
		break;

	case RNDIS_STATUS_TASK_OFFLOAD_CURRENT_CONFIG:
		/* Not really useful; ignore. */
		break;

	case RNDIS_STATUS_NETWORK_CHANGE:
		ofs = RNDIS_STBUFOFFSET_ABS(msg->rm_stbufoffset);
		if (dlen < ofs + msg->rm_stbuflen ||
		    msg->rm_stbuflen < sizeof (uint32_t)) {
			HN_WARN(sc, "network changed");
		} else {
			uint32_t change;

			(void) memcpy(&change, ((const uint8_t *)msg) + ofs,
			    sizeof (change));
			HN_WARN(sc, "network changed, change %u", change);
		}
		hn_change_network(sc);
		break;

	default:
		HN_WARN(sc, "unknown RNDIS status 0x%08x", msg->rm_status);
		break;
	}
}

static int
hn_rndis_rxinfo(const void *info_data, int info_dlen, struct hn_rxinfo *info)
{
	const struct rndis_pktinfo *pi = info_data;
	uint32_t mask = 0;

	while (info_dlen != 0) {
		const void *data;
		uint32_t dlen;

		if (__predict_false(info_dlen < sizeof (*pi)))
			return (EINVAL);
		if (__predict_false(info_dlen < pi->rm_size))
			return (EINVAL);
		info_dlen -= pi->rm_size;

		if (__predict_false(pi->rm_size & RNDIS_PKTINFO_SIZE_ALIGNMASK))
			return (EINVAL);
		if (__predict_false(pi->rm_size < pi->rm_pktinfooffset))
			return (EINVAL);
		dlen = pi->rm_size - pi->rm_pktinfooffset;
		data = pi->rm_data;

		switch (pi->rm_type) {
		case NDIS_PKTINFO_TYPE_VLAN:
			if (__predict_false(dlen < NDIS_VLAN_INFO_SIZE))
				return (EINVAL);
			info->vlan_info = *((const uint32_t *)data);
			mask |= HN_RXINFO_VLAN;
			break;

		case NDIS_PKTINFO_TYPE_CSUM:
			if (__predict_false(dlen < NDIS_RXCSUM_INFO_SIZE))
				return (EINVAL);
			info->csum_info = *((const uint32_t *)data);
			mask |= HN_RXINFO_CSUM;
			break;

		case HN_NDIS_PKTINFO_TYPE_HASHVAL:
			if (__predict_false(dlen < HN_NDIS_HASH_VALUE_SIZE))
				return (EINVAL);
			info->hash_value = *((const uint32_t *)data);
			mask |= HN_RXINFO_HASHVAL;
			break;

		case HN_NDIS_PKTINFO_TYPE_HASHINF:
			if (__predict_false(dlen < HN_NDIS_HASH_INFO_SIZE))
				return (EINVAL);
			info->hash_info = *((const uint32_t *)data);
			mask |= HN_RXINFO_HASHINF;
			break;

		default:
			goto next;
		}

		if (mask == HN_RXINFO_ALL) {
			/* All found; done */
			break;
		}
next:
		pi = (const struct rndis_pktinfo *)
		    ((const uint8_t *)pi + pi->rm_size);
	}

	/*
	 * Final fixup.
	 * - If there is no hash value, invalidate the hash info.
	 */
	if ((mask & HN_RXINFO_HASHVAL) == 0)
		info->hash_info = HN_NDIS_HASH_INFO_INVALID;
	return (0);
}

static inline boolean_t
hn_rndis_check_overlap(int off, int len, int check_off, int check_len)
{

	if (off < check_off) {
		if (__predict_true(off + len <= check_off))
			return (B_FALSE);
	} else if (off > check_off) {
		if (__predict_true(check_off + check_len <= off))
			return (B_FALSE);
	}
	return (B_TRUE);
}

static void
hn_rndis_rx_data(struct hn_rx_ring *rxr, const void *data, int dlen)
{
	struct hn_softc *sc = rxr->hn_sc;
	const struct rndis_packet_msg *pkt;
	struct hn_rxinfo info;
	int data_off, pktinfo_off, data_len, pktinfo_len;

	/*
	 * Check length.
	 */
	if (__predict_false(dlen < sizeof (*pkt))) {
		HN_WARN(sc, "invalid RNDIS packet msg");
		return;
	}
	pkt = data;

	if (__predict_false(dlen < pkt->rm_len)) {
		HN_WARN(sc, "truncated RNDIS packet msg, "
		    "dlen %d, msglen %u", dlen, pkt->rm_len);
		return;
	}
	if (__predict_false(pkt->rm_len <
	    pkt->rm_datalen + pkt->rm_oobdatalen + pkt->rm_pktinfolen)) {
		HN_WARN(sc, "invalid RNDIS packet msglen, "
		    "msglen %u, data %u, oob %u, pktinfo %u",
		    pkt->rm_len, pkt->rm_datalen, pkt->rm_oobdatalen,
		    pkt->rm_pktinfolen);
		return;
	}
	if (__predict_false(pkt->rm_datalen == 0)) {
		HN_WARN(sc, "invalid RNDIS packet msg, no data");
		return;
	}

	/*
	 * Check offests.
	 */
#define	IS_OFFSET_INVALID(ofs)			\
	((ofs) < RNDIS_PACKET_MSG_OFFSET_MIN ||	\
	((ofs) & RNDIS_PACKET_MSG_OFFSET_ALIGNMASK))

	/* XXX Hyper-V does not meet data offset alignment requirement */
	if (__predict_false(pkt->rm_dataoffset < RNDIS_PACKET_MSG_OFFSET_MIN)) {
		HN_WARN(sc, "invalid RNDIS packet msg, data offset %u",
		    pkt->rm_dataoffset);
		return;
	}
	if (__predict_false(pkt->rm_oobdataoffset > 0 &&
	    IS_OFFSET_INVALID(pkt->rm_oobdataoffset))) {
		HN_WARN(sc, "invalid RNDIS packet msg, oob offset %u",
		    pkt->rm_oobdataoffset);
		return;
	}
	if (__predict_true(pkt->rm_pktinfooffset > 0) &&
	    __predict_false(IS_OFFSET_INVALID(pkt->rm_pktinfooffset))) {
		HN_WARN(sc, "invalid RNDIS packet msg, pktinfo offset %u",
		    pkt->rm_pktinfooffset);
		return;
	}

#undef IS_OFFSET_INVALID

	data_off = RNDIS_PACKET_MSG_OFFSET_ABS(pkt->rm_dataoffset);
	data_len = pkt->rm_datalen;
	pktinfo_off = RNDIS_PACKET_MSG_OFFSET_ABS(pkt->rm_pktinfooffset);
	pktinfo_len = pkt->rm_pktinfolen;

	/*
	 * Check OOB coverage.
	 */
	if (__predict_false(pkt->rm_oobdatalen != 0)) {
		int oob_off, oob_len;

		HN_WARN(sc, "got oobdata");
		oob_off = RNDIS_PACKET_MSG_OFFSET_ABS(pkt->rm_oobdataoffset);
		oob_len = pkt->rm_oobdatalen;

		if (__predict_false(oob_off + oob_len > pkt->rm_len)) {
			HN_WARN(sc, "invalid RNDIS packet msg, "
			    "oob overflow, msglen %u, oob abs %d len %d",
			    pkt->rm_len, oob_off, oob_len);
			return;
		}

		/*
		 * Check against data.
		 */
		if (hn_rndis_check_overlap(oob_off, oob_len,
		    data_off, data_len)) {
			HN_WARN(sc, "invalid RNDIS packet msg, "
			    "oob overlaps data, oob abs %d len %d, "
			    "data abs %d len %d",
			    oob_off, oob_len, data_off, data_len);
			return;
		}

		/*
		 * Check against pktinfo.
		 */
		if (pktinfo_len != 0 &&
		    hn_rndis_check_overlap(oob_off, oob_len,
		    pktinfo_off, pktinfo_len)) {
			HN_WARN(sc, "invalid RNDIS packet msg, "
			    "oob overlaps pktinfo, oob abs %d len %d, "
			    "pktinfo abs %d len %d",
			    oob_off, oob_len, pktinfo_off, pktinfo_len);
			return;
		}
	}

	/*
	 * Check per-packet-info coverage and find useful per-packet-info.
	 */
	info.vlan_info = HN_NDIS_VLAN_INFO_INVALID;
	info.csum_info = HN_NDIS_RXCSUM_INFO_INVALID;
	info.hash_info = HN_NDIS_HASH_INFO_INVALID;
	if (__predict_true(pktinfo_len != 0)) {
		boolean_t overlap;
		int error;

		if (__predict_false(pktinfo_off + pktinfo_len > pkt->rm_len)) {
			HN_WARN(sc, "invalid RNDIS packet msg, "
			    "pktinfo overflow, msglen %u, "
			    "pktinfo abs %d len %d",
			    pkt->rm_len, pktinfo_off, pktinfo_len);
			return;
		}

		/*
		 * Check packet info coverage.
		 */
		overlap = hn_rndis_check_overlap(pktinfo_off, pktinfo_len,
		    data_off, data_len);
		if (__predict_false(overlap)) {
			HN_WARN(sc, "invalid RNDIS packet msg, "
			    "pktinfo overlap data, pktinfo abs %d len %d, "
			    "data abs %d len %d",
			    pktinfo_off, pktinfo_len, data_off, data_len);
			return;
		}

		/*
		 * Find useful per-packet-info.
		 */
		error = hn_rndis_rxinfo(((const uint8_t *)pkt) + pktinfo_off,
		    pktinfo_len, &info);
		if (__predict_false(error)) {
			HN_WARN(sc, "invalid RNDIS packet msg pktinfo");
			return;
		}
	}

	if (__predict_false(data_off + data_len > pkt->rm_len)) {
		HN_WARN(sc, "invalid RNDIS packet msg, "
		    "data overflow, msglen %u, data abs %d len %d",
		    pkt->rm_len, data_off, data_len);
		return;
	}
	mutex_enter(&rxr->hn_rx_lock);
	(void) hn_rxpkt(rxr, ((const uint8_t *)pkt) + data_off,
	    data_len, &info);
	mutex_exit(&rxr->hn_rx_lock);
}

static void
hn_rndis_rxpkt(struct hn_rx_ring *rxr, const void *data, int dlen)
{
	struct hn_softc *sc = rxr->hn_sc;
	const struct rndis_msghdr *hdr;

	if (__predict_false(dlen < sizeof (*hdr))) {
		HN_WARN(sc, "invalid RNDIS msg");
		return;
	}
	hdr = data;

	if (__predict_true(hdr->rm_type == REMOTE_NDIS_PACKET_MSG)) {
		/* Hot data path. */
		hn_rndis_rx_data(rxr, data, dlen);
		/* Done! */
		return;
	}

	if (hdr->rm_type == REMOTE_NDIS_INDICATE_STATUS_MSG)
		hn_rndis_rx_status(sc, data, dlen);
	else
		hn_rndis_rx_ctrl(sc, data, dlen);
}

static void
hn_nvs_handle_notify(struct hn_softc *sc, const struct vmbus_chanpkt_hdr *pkt)
{
	const struct hn_nvs_hdr *hdr;

	if (VMBUS_CHANPKT_DATALEN(pkt) < sizeof (*hdr)) {
		HN_WARN(sc, "invalid nvs notify");
		return;
	}
	hdr = VMBUS_CHANPKT_CONST_DATA(pkt);

	if (hdr->nvs_type == HN_NVS_TYPE_TXTBL_NOTE) {
		/* Useless; ignore */
		return;
	}
	HN_WARN(sc, "got notify, nvs type %u", hdr->nvs_type);
}

static void
hn_nvs_handle_comp(struct hn_softc *sc, struct vmbus_channel *chan,
    const struct vmbus_chanpkt_hdr *pkt)
{
	struct hn_nvs_sendctx *sndc;

	sndc = (struct hn_nvs_sendctx *)(uintptr_t)pkt->cph_xactid;
	sndc->hn_cb(sndc, sc, chan, VMBUS_CHANPKT_CONST_DATA(pkt),
	    VMBUS_CHANPKT_DATALEN(pkt));
	/*
	 * NOTE:
	 * 'sndc' CAN NOT be accessed anymore, since it can be freed by
	 * its callback.
	 */
}

static void
hn_nvs_handle_rxbuf(struct hn_rx_ring *rxr, struct vmbus_channel *chan,
    const struct vmbus_chanpkt_hdr *pkthdr)
{
	struct hn_softc *sc = rxr->hn_sc;
	const struct vmbus_chanpkt_rxbuf *pkt;
	const struct hn_nvs_hdr *nvs_hdr;
	int count, i, hlen;

	if (__predict_false(VMBUS_CHANPKT_DATALEN(pkthdr) <
	    sizeof (*nvs_hdr))) {
		HN_WARN(sc, "invalid nvs RNDIS");
		return;
	}
	nvs_hdr = VMBUS_CHANPKT_CONST_DATA(pkthdr);

	/* Make sure that this is a RNDIS message. */
	if (__predict_false(nvs_hdr->nvs_type != HN_NVS_TYPE_RNDIS)) {
		HN_WARN(sc, "nvs type %u, not RNDIS", nvs_hdr->nvs_type);
		return;
	}

	hlen = VMBUS_CHANPKT_GETLEN(pkthdr->cph_hlen);
	if (__predict_false(hlen < sizeof (*pkt))) {
		HN_WARN(sc, "invalid rxbuf chanpkt");
		return;
	}
	pkt = (const struct vmbus_chanpkt_rxbuf *)pkthdr;

	if (__predict_false(pkt->cp_rxbuf_id != HN_NVS_RXBUF_SIG)) {
		HN_WARN(sc, "invalid rxbuf_id 0x%08x", pkt->cp_rxbuf_id);
		return;
	}

	count = pkt->cp_rxbuf_cnt;
	if (__predict_false(hlen <
	    offsetof(struct vmbus_chanpkt_rxbuf, cp_rxbuf[count]))) {
		HN_WARN(sc, "invalid rxbuf_cnt %d", count);
		return;
	}

	/* Each range represents 1 RNDIS pkt that contains 1 Ethernet frame */
	for (i = 0; i < count; ++i) {
		int ofs, len;

		ofs = pkt->cp_rxbuf[i].rb_ofs;
		len = pkt->cp_rxbuf[i].rb_len;
		if (__predict_false(ofs + len > HN_RXBUF_SIZE)) {
			HN_WARN(sc, "%dth RNDIS msg overflow rxbuf, "
			    "ofs %d, len %d", i, ofs, len);
			continue;
		}
		hn_rndis_rxpkt(rxr, rxr->hn_rxbuf + ofs, len);
	}

	/*
	 * Send all the pending mblks to the MAC framework
	 */
	if (rxr->hn_mps) {
		mac_rx_ring(sc->hn_mac_hdl, rxr->hn_ring_handle, rxr->hn_mps,
		    rxr->hn_ring_gen_num);
		rxr->hn_mps = NULL;
		rxr->hn_mp_tail = NULL;
	}
	ASSERT3P(rxr->hn_mp_tail, ==, NULL);

	/*
	 * Ack the consumed RXBUF associated w/ this channel packet,
	 * so that this RXBUF can be recycled by the hypervisor.
	 */
	hn_nvs_ack_rxbuf(rxr, chan, pkt->cp_hdr.cph_xactid);
}

static void
hn_nvs_ack_rxbuf(struct hn_rx_ring *rxr, struct vmbus_channel *chan,
    uint64_t tid)
{
	struct hn_nvs_rndis_ack ack;
	struct hn_softc *sc = rxr->hn_sc;
	int retries, error;

	ack.nvs_type = HN_NVS_TYPE_RNDIS_ACK;
	ack.nvs_status = HN_NVS_STATUS_OK;

	retries = 0;
again:
	error = vmbus_chan_send(chan, VMBUS_CHANPKT_TYPE_COMP,
	    VMBUS_CHANPKT_FLAG_NONE, &ack, sizeof (ack), tid);
	if (__predict_false(error == EAGAIN)) {
		/*
		 * NOTE:
		 * This should _not_ happen in real world, since the
		 * consumption of the TX bufring from the TX path is
		 * controlled.
		 */
		if (rxr->hn_ack_failed == 0)
			HN_WARN(sc, "RXBUF ack retry");
		rxr->hn_ack_failed++;
		retries++;
		if (retries < 10) {
			DELAY(100);
			goto again;
		}
		/* RXBUF leaks! */
		HN_WARN(sc, "RXBUF ack failed");
	}
}

static void
hn_chan_callback(struct vmbus_channel *chan, void *xrxr)
{
	struct hn_rx_ring *rxr = xrxr;
	struct hn_softc *sc = rxr->hn_sc;

	for (;;) {
		struct vmbus_chanpkt_hdr *pkt = rxr->hn_pktbuf;
		int error, pktlen;

		pktlen = rxr->hn_pktbuf_len;
		error = vmbus_chan_recv_pkt(chan, pkt, &pktlen);
		if (__predict_false(error == ENOBUFS)) {
			void *nbuf;
			int nlen;

			/*
			 * Expand channel packet buffer.
			 *
			 * XXX
			 * Use KM_SLEEP here, since allocation failure
			 * is fatal.
			 */
			nlen = rxr->hn_pktbuf_len * 2;
			while (nlen < pktlen)
				nlen *= 2;
			nbuf = kmem_zalloc(nlen, KM_SLEEP);

			HN_DEBUG(sc, 1, "expand pktbuf %d -> %d",
			    rxr->hn_pktbuf_len, nlen);

			kmem_free(rxr->hn_pktbuf, rxr->hn_pktbuf_len);
			rxr->hn_pktbuf = nbuf;
			rxr->hn_pktbuf_len = nlen;
			/* Retry! */
			continue;
		} else if (__predict_false(error == EAGAIN)) {
			/* No more channel packets; done! */
			break;
		}
		/*
		 * We do not expect any other type of error.
		 */
		ASSERT3S(error, ==, 0);

		switch (pkt->cph_type) {
		case VMBUS_CHANPKT_TYPE_COMP:
			hn_nvs_handle_comp(sc, chan, pkt);
			break;

		case VMBUS_CHANPKT_TYPE_RXBUF:
			hn_nvs_handle_rxbuf(rxr, chan, pkt);
			break;

		case VMBUS_CHANPKT_TYPE_INBAND:
			hn_nvs_handle_notify(sc, pkt);
			break;

		default:
			HN_WARN(sc, "unknown chan pkt %u", pkt->cph_type);
			break;
		}
	}
}

/*
 * Structures used by the module loader
 */

#define	HN_DRIVER_VERSION_STRING "1.0"
#define	HN_IDENT "Hyper-V Network Interface " HN_DRIVER_VERSION_STRING

DDI_DEFINE_STREAM_OPS(
	netvsc_dev_ops,
	nulldev,
	nulldev,
	hn_attach,
	hn_detach,
	nodev,
	NULL,
	D_NEW | D_MP,
	NULL,
	ddi_quiesce_not_supported);

static struct modldrv netvsc_modldrv = {
	&mod_driverops,		/* drv_modops */
	HN_IDENT,		/* drv_linkinfo */
	&netvsc_dev_ops		/* drv_dev_ops */
};

static struct modlinkage netvsc_modlinkage = {
	MODREV_1,			/* ml_rev */
	{ &netvsc_modldrv, NULL }	/* ml_linkage */
};

/* Module load entry point */
int
_init(void)
{
	int ret;

	mac_init_ops(&netvsc_dev_ops, NETVSC_DEVNAME);
	ret = mod_install(&netvsc_modlinkage);
	if (ret != DDI_SUCCESS) {
		mac_fini_ops(&netvsc_dev_ops);
	}

	return (ret);
}

/* Module unload entry point */
int
_fini(void)
{
	int ret;

	ret = mod_remove(&netvsc_modlinkage);
	if (ret == DDI_SUCCESS) {
		mac_fini_ops(&netvsc_dev_ops);
	}

	return (ret);
}

/* Module info entry point */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&netvsc_modlinkage, modinfop));
}
