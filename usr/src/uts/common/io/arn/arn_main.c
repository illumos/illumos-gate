/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/errno.h>
#include <sys/mac_provider.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/list.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/net80211_proto.h>
#include <sys/net80211_ht.h>


#include "arn_ath9k.h"
#include "arn_core.h"
#include "arn_reg.h"
#include "arn_hw.h"

#define	ARN_MAX_RSSI	45	/* max rssi */

/*
 * Default 11n reates supported by this station.
 */
extern struct ieee80211_htrateset ieee80211_rateset_11n;

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t arn_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptors: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t arn_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t arn_dma_attr = {
	DMA_ATTR_V0,	/* version number */
	0,				/* low address */
	0xffffffffU,	/* high address */
	0x3ffffU,		/* counter register max */
	1,				/* alignment */
	0xFFF,			/* burst sizes */
	1,				/* minimum transfer size */
	0x3ffffU,		/* max transfer size */
	0xffffffffU,	/* address register max */
	1,				/* no scatter-gather */
	1,				/* granularity of device */
	0,				/* DMA flags */
};

static ddi_dma_attr_t arn_desc_dma_attr = {
	DMA_ATTR_V0,	/* version number */
	0,				/* low address */
	0xffffffffU,	/* high address */
	0xffffffffU,	/* counter register max */
	0x1000,			/* alignment */
	0xFFF,			/* burst sizes */
	1,				/* minimum transfer size */
	0xffffffffU,	/* max transfer size */
	0xffffffffU,	/* address register max */
	1,				/* no scatter-gather */
	1,				/* granularity of device */
	0,				/* DMA flags */
};

#define	ATH_DEF_CACHE_BYTES	32 /* default cache line size */

static kmutex_t arn_loglock;
static void *arn_soft_state_p = NULL;
static int arn_dwelltime = 200; /* scan interval */

static int	arn_m_stat(void *,  uint_t, uint64_t *);
static int	arn_m_start(void *);
static void	arn_m_stop(void *);
static int	arn_m_promisc(void *, boolean_t);
static int	arn_m_multicst(void *, boolean_t, const uint8_t *);
static int	arn_m_unicst(void *, const uint8_t *);
static mblk_t	*arn_m_tx(void *, mblk_t *);
static void	arn_m_ioctl(void *, queue_t *, mblk_t *);
static int	arn_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int	arn_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void	arn_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

/* MAC Callcack Functions */
static mac_callbacks_t arn_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	arn_m_stat,
	arn_m_start,
	arn_m_stop,
	arn_m_promisc,
	arn_m_multicst,
	arn_m_unicst,
	arn_m_tx,
	NULL,
	arn_m_ioctl,
	NULL,
	NULL,
	NULL,
	arn_m_setprop,
	arn_m_getprop,
	arn_m_propinfo
};

/*
 * ARN_DBG_HW
 * ARN_DBG_REG_IO
 * ARN_DBG_QUEUE
 * ARN_DBG_EEPROM
 * ARN_DBG_XMIT
 * ARN_DBG_RECV
 * ARN_DBG_CALIBRATE
 * ARN_DBG_CHANNEL
 * ARN_DBG_INTERRUPT
 * ARN_DBG_REGULATORY
 * ARN_DBG_ANI
 * ARN_DBG_POWER_MGMT
 * ARN_DBG_KEYCACHE
 * ARN_DBG_BEACON
 * ARN_DBG_RATE
 * ARN_DBG_INIT
 * ARN_DBG_ATTACH
 * ARN_DBG_DEATCH
 * ARN_DBG_AGGR
 * ARN_DBG_RESET
 * ARN_DBG_FATAL
 * ARN_DBG_ANY
 * ARN_DBG_ALL
 */
uint32_t arn_dbg_mask = 0;

/*
 * Exception/warning cases not leading to panic.
 */
void
arn_problem(const int8_t *fmt, ...)
{
	va_list args;

	mutex_enter(&arn_loglock);

	va_start(args, fmt);
	vcmn_err(CE_WARN, fmt, args);
	va_end(args);

	mutex_exit(&arn_loglock);
}

/*
 * Normal log information independent of debug.
 */
void
arn_log(const int8_t *fmt, ...)
{
	va_list args;

	mutex_enter(&arn_loglock);

	va_start(args, fmt);
	vcmn_err(CE_CONT, fmt, args);
	va_end(args);

	mutex_exit(&arn_loglock);
}

void
arn_dbg(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & arn_dbg_mask) {
		mutex_enter(&arn_loglock);
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
		mutex_exit(&arn_loglock);
	}
}

/*
 * Read and write, they both share the same lock. We do this to serialize
 * reads and writes on Atheros 802.11n PCI devices only. This is required
 * as the FIFO on these devices can only accept sanely 2 requests. After
 * that the device goes bananas. Serializing the reads/writes prevents this
 * from happening.
 */
void
arn_iowrite32(struct ath_hal *ah, uint32_t reg_offset, uint32_t val)
{
	struct arn_softc *sc = ah->ah_sc;
	if (ah->ah_config.serialize_regmode == SER_REG_MODE_ON) {
		mutex_enter(&sc->sc_serial_rw);
		ddi_put32(sc->sc_io_handle,
		    (uint32_t *)((uintptr_t)(sc->mem) + (reg_offset)), val);
		mutex_exit(&sc->sc_serial_rw);
	} else {
		ddi_put32(sc->sc_io_handle,
		    (uint32_t *)((uintptr_t)(sc->mem) + (reg_offset)), val);
	}
}

unsigned int
arn_ioread32(struct ath_hal *ah, uint32_t reg_offset)
{
	uint32_t val;
	struct arn_softc *sc = ah->ah_sc;
	if (ah->ah_config.serialize_regmode == SER_REG_MODE_ON) {
		mutex_enter(&sc->sc_serial_rw);
		val = ddi_get32(sc->sc_io_handle,
		    (uint32_t *)((uintptr_t)(sc->mem) + (reg_offset)));
		mutex_exit(&sc->sc_serial_rw);
	} else {
		val = ddi_get32(sc->sc_io_handle,
		    (uint32_t *)((uintptr_t)(sc->mem) + (reg_offset)));
	}

	return (val);
}

/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
arn_alloc_dma_mem(dev_info_t *devinfo, ddi_dma_attr_t *dma_attr, size_t memsize,
    ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
    uint_t bind_flags, dma_area_t *dma_p)
{
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    alloc_flags, DDI_DMA_SLEEP, NULL, &dma_p->mem_va,
	    &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Bind the two together
	 */
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    dma_p->mem_va, dma_p->alength, bind_flags,
	    DDI_DMA_SLEEP, NULL, &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED)
		return (DDI_FAILURE);

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;
	return (DDI_SUCCESS);
}

/*
 * Free one allocated area of DMAable memory
 */
static void
arn_free_dma_mem(dma_area_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
		if (dma_p->acc_hdl != NULL) {
			ddi_dma_mem_free(&dma_p->acc_hdl);
			dma_p->acc_hdl = NULL;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->ncookies = 0;
		dma_p->dma_hdl = NULL;
	}
}

/*
 * Initialize tx, rx. or beacon buffer list. Allocate DMA memory for
 * each buffer.
 */
static int
arn_buflist_setup(dev_info_t *devinfo,
    struct arn_softc *sc,
    list_t *bflist,
    struct ath_buf **pbf,
    struct ath_desc **pds,
    int nbuf,
    uint_t dmabflags,
    uint32_t buflen)
{
	int i, err;
	struct ath_buf *bf = *pbf;
	struct ath_desc *ds = *pds;

	list_create(bflist, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));
	for (i = 0; i < nbuf; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = sc->sc_desc_dma.cookie.dmac_address +
		    ((uintptr_t)ds - (uintptr_t)sc->sc_desc);
		list_insert_tail(bflist, bf);

		/* alloc DMA memory */
		err = arn_alloc_dma_mem(devinfo, &arn_dma_attr,
		    buflen, &arn_desc_accattr, DDI_DMA_STREAMING,
		    dmabflags, &bf->bf_dma);
		if (err != DDI_SUCCESS)
			return (err);
	}
	*pbf = bf;
	*pds = ds;

	return (DDI_SUCCESS);
}

/*
 * Destroy tx, rx or beacon buffer list. Free DMA memory.
 */
static void
arn_buflist_cleanup(list_t *buflist)
{
	struct ath_buf *bf;

	if (!buflist)
		return;

	bf = list_head(buflist);
	while (bf != NULL) {
		if (bf->bf_m != NULL) {
			freemsg(bf->bf_m);
			bf->bf_m = NULL;
		}
		/* Free DMA buffer */
		arn_free_dma_mem(&bf->bf_dma);
		if (bf->bf_in != NULL) {
			ieee80211_free_node(bf->bf_in);
			bf->bf_in = NULL;
		}
		list_remove(buflist, bf);
		bf = list_head(buflist);
	}
	list_destroy(buflist);
}

static void
arn_desc_free(struct arn_softc *sc)
{
	arn_buflist_cleanup(&sc->sc_txbuf_list);
	arn_buflist_cleanup(&sc->sc_rxbuf_list);
#ifdef ARN_IBSS
	arn_buflist_cleanup(&sc->sc_bcbuf_list);
#endif

	/* Free descriptor DMA buffer */
	arn_free_dma_mem(&sc->sc_desc_dma);

	kmem_free((void *)sc->sc_vbufptr, sc->sc_vbuflen);
	sc->sc_vbufptr = NULL;
}

static int
arn_desc_alloc(dev_info_t *devinfo, struct arn_softc *sc)
{
	int err;
	size_t size;
	struct ath_desc *ds;
	struct ath_buf *bf;

#ifdef ARN_IBSS
	size = sizeof (struct ath_desc) * (ATH_TXBUF + ATH_RXBUF + ATH_BCBUF);
#else
	size = sizeof (struct ath_desc) * (ATH_TXBUF + ATH_RXBUF);
#endif

	err = arn_alloc_dma_mem(devinfo, &arn_desc_dma_attr, size,
	    &arn_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &sc->sc_desc_dma);

	/* virtual address of the first descriptor */
	sc->sc_desc = (struct ath_desc *)sc->sc_desc_dma.mem_va;

	ds = sc->sc_desc;
	ARN_DBG((ARN_DBG_INIT, "arn: arn_desc_alloc(): DMA map: "
	    "%p (%d) -> %p\n",
	    sc->sc_desc, sc->sc_desc_dma.alength,
	    sc->sc_desc_dma.cookie.dmac_address));

	/* allocate data structures to describe TX/RX DMA buffers */
#ifdef ARN_IBSS
	sc->sc_vbuflen = sizeof (struct ath_buf) * (ATH_TXBUF + ATH_RXBUF +
	    ATH_BCBUF);
#else
	sc->sc_vbuflen = sizeof (struct ath_buf) * (ATH_TXBUF + ATH_RXBUF);
#endif
	bf = (struct ath_buf *)kmem_zalloc(sc->sc_vbuflen, KM_SLEEP);
	sc->sc_vbufptr = bf;

	/* DMA buffer size for each TX/RX packet */
#ifdef ARN_TX_AGGREGRATION
	sc->tx_dmabuf_size =
	    roundup((IEEE80211_MAX_MPDU_LEN + 3840 * 2),
	    min(sc->sc_cachelsz, (uint16_t)64));
#else
	sc->tx_dmabuf_size =
	    roundup(IEEE80211_MAX_MPDU_LEN, min(sc->sc_cachelsz, (uint16_t)64));
#endif
	sc->rx_dmabuf_size =
	    roundup(IEEE80211_MAX_MPDU_LEN, min(sc->sc_cachelsz, (uint16_t)64));

	/* create RX buffer list */
	err = arn_buflist_setup(devinfo, sc, &sc->sc_rxbuf_list, &bf, &ds,
	    ATH_RXBUF, DDI_DMA_READ | DDI_DMA_STREAMING, sc->rx_dmabuf_size);
	if (err != DDI_SUCCESS) {
		arn_desc_free(sc);
		return (err);
	}

	/* create TX buffer list */
	err = arn_buflist_setup(devinfo, sc, &sc->sc_txbuf_list, &bf, &ds,
	    ATH_TXBUF, DDI_DMA_STREAMING, sc->tx_dmabuf_size);
	if (err != DDI_SUCCESS) {
		arn_desc_free(sc);
		return (err);
	}

	/* create beacon buffer list */
#ifdef ARN_IBSS
	err = arn_buflist_setup(devinfo, sc, &sc->sc_bcbuf_list, &bf, &ds,
	    ATH_BCBUF, DDI_DMA_STREAMING);
	if (err != DDI_SUCCESS) {
		arn_desc_free(sc);
		return (err);
	}
#endif

	return (DDI_SUCCESS);
}

static void
arn_setcurmode(struct arn_softc *sc, enum wireless_mode mode)
{
	struct ath_rate_table *rt;
	int i;

	for (i = 0; i < sizeof (sc->asc_rixmap); i++)
		sc->asc_rixmap[i] = 0xff;

	rt = sc->hw_rate_table[mode];
	ASSERT(rt != NULL);

	for (i = 0; i < rt->rate_cnt; i++)
		sc->asc_rixmap[rt->info[i].dot11rate &
		    IEEE80211_RATE_VAL] = (uint8_t)i; /* LINT */

	sc->sc_currates = rt;
	sc->sc_curmode = mode;

	/*
	 * All protection frames are transmited at 2Mb/s for
	 * 11g, otherwise at 1Mb/s.
	 * XXX select protection rate index from rate table.
	 */
	sc->sc_protrix = (mode == ATH9K_MODE_11G ? 1 : 0);
}

static enum wireless_mode
arn_chan2mode(struct ath9k_channel *chan)
{
	if (chan->chanmode == CHANNEL_A)
		return (ATH9K_MODE_11A);
	else if (chan->chanmode == CHANNEL_G)
		return (ATH9K_MODE_11G);
	else if (chan->chanmode == CHANNEL_B)
		return (ATH9K_MODE_11B);
	else if (chan->chanmode == CHANNEL_A_HT20)
		return (ATH9K_MODE_11NA_HT20);
	else if (chan->chanmode == CHANNEL_G_HT20)
		return (ATH9K_MODE_11NG_HT20);
	else if (chan->chanmode == CHANNEL_A_HT40PLUS)
		return (ATH9K_MODE_11NA_HT40PLUS);
	else if (chan->chanmode == CHANNEL_A_HT40MINUS)
		return (ATH9K_MODE_11NA_HT40MINUS);
	else if (chan->chanmode == CHANNEL_G_HT40PLUS)
		return (ATH9K_MODE_11NG_HT40PLUS);
	else if (chan->chanmode == CHANNEL_G_HT40MINUS)
		return (ATH9K_MODE_11NG_HT40MINUS);

	return (ATH9K_MODE_11B);
}

static void
arn_update_txpow(struct arn_softc *sc)
{
	struct ath_hal 	*ah = sc->sc_ah;
	uint32_t txpow;

	if (sc->sc_curtxpow != sc->sc_config.txpowlimit) {
		(void) ath9k_hw_set_txpowerlimit(ah, sc->sc_config.txpowlimit);
		/* read back in case value is clamped */
		(void) ath9k_hw_getcapability(ah, ATH9K_CAP_TXPOW, 1, &txpow);
		sc->sc_curtxpow = (uint32_t)txpow;
	}
}

uint8_t
parse_mpdudensity(uint8_t mpdudensity)
{
	/*
	 * 802.11n D2.0 defined values for "Minimum MPDU Start Spacing":
	 *   0 for no restriction
	 *   1 for 1/4 us
	 *   2 for 1/2 us
	 *   3 for 1 us
	 *   4 for 2 us
	 *   5 for 4 us
	 *   6 for 8 us
	 *   7 for 16 us
	 */
	switch (mpdudensity) {
	case 0:
		return (0);
	case 1:
	case 2:
	case 3:
		/*
		 * Our lower layer calculations limit our
		 * precision to 1 microsecond
		 */
		return (1);
	case 4:
		return (2);
	case 5:
		return (4);
	case 6:
		return (8);
	case 7:
		return (16);
	default:
		return (0);
	}
}

static void
arn_setup_rates(struct arn_softc *sc, uint32_t mode)
{
	int i, maxrates;
	struct ath_rate_table *rate_table = NULL;
	struct ieee80211_rateset *rateset;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	/* rate_table = arn_get_ratetable(sc, mode); */
	switch (mode) {
	case IEEE80211_MODE_11A:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11A];
		break;
	case IEEE80211_MODE_11B:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11B];
		break;
	case IEEE80211_MODE_11G:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11G];
		break;
#ifdef ARN_11N
	case IEEE80211_MODE_11NA_HT20:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11NA_HT20];
		break;
	case IEEE80211_MODE_11NG_HT20:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11NG_HT20];
		break;
	case IEEE80211_MODE_11NA_HT40PLUS:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11NA_HT40PLUS];
		break;
	case IEEE80211_MODE_11NA_HT40MINUS:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11NA_HT40MINUS];
		break;
	case IEEE80211_MODE_11NG_HT40PLUS:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11NG_HT40PLUS];
		break;
	case IEEE80211_MODE_11NG_HT40MINUS:
		rate_table = sc->hw_rate_table[ATH9K_MODE_11NG_HT40MINUS];
		break;
#endif
	default:
		ARN_DBG((ARN_DBG_RATE, "arn: arn_get_ratetable(): "
		    "invalid mode %u\n", mode));
		break;
	}
	if (rate_table == NULL)
		return;
	if (rate_table->rate_cnt > ATH_RATE_MAX) {
		ARN_DBG((ARN_DBG_RATE, "arn: arn_rate_setup(): "
		    "rate table too small (%u > %u)\n",
		    rate_table->rate_cnt, IEEE80211_RATE_MAXSIZE));
		maxrates = ATH_RATE_MAX;
	} else
		maxrates = rate_table->rate_cnt;

	ARN_DBG((ARN_DBG_RATE, "arn: arn_rate_setup(): "
	    "maxrates is %d\n", maxrates));

	rateset = &ic->ic_sup_rates[mode];
	for (i = 0; i < maxrates; i++) {
		rateset->ir_rates[i] = rate_table->info[i].dot11rate;
		ARN_DBG((ARN_DBG_RATE, "arn: arn_rate_setup(): "
		    "%d\n", rate_table->info[i].dot11rate));
	}
	rateset->ir_nrates = (uint8_t)maxrates; /* ??? */
}

static int
arn_setup_channels(struct arn_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	int nchan, i, index;
	uint8_t regclassids[ATH_REGCLASSIDS_MAX];
	uint32_t nregclass = 0;
	struct ath9k_channel *c;

	/* Fill in ah->ah_channels */
	if (!ath9k_regd_init_channels(ah, ATH_CHAN_MAX, (uint32_t *)&nchan,
	    regclassids, ATH_REGCLASSIDS_MAX, &nregclass, CTRY_DEFAULT,
	    B_FALSE, 1)) {
		uint32_t rd = ah->ah_currentRD;
		ARN_DBG((ARN_DBG_CHANNEL, "arn: arn_setup_channels(): "
		    "unable to collect channel list; "
		    "regdomain likely %u country code %u\n",
		    rd, CTRY_DEFAULT));
		return (EINVAL);
	}

	ARN_DBG((ARN_DBG_CHANNEL, "arn: arn_setup_channels(): "
	    "number of channel is %d\n", nchan));

	for (i = 0; i < nchan; i++) {
		c = &ah->ah_channels[i];
		uint32_t flags;
		index = ath9k_hw_mhz2ieee(ah, c->channel, c->channelFlags);

		if (index > IEEE80211_CHAN_MAX) {
			ARN_DBG((ARN_DBG_CHANNEL,
			    "arn: arn_setup_channels(): "
			    "bad hal channel %d (%u/%x) ignored\n",
			    index, c->channel, c->channelFlags));
			continue;
		}
		/* NB: flags are known to be compatible */
		if (index < 0) {
			/*
			 * can't handle frequency <2400MHz (negative
			 * channels) right now
			 */
			ARN_DBG((ARN_DBG_CHANNEL,
			    "arn: arn_setup_channels(): "
			    "hal channel %d (%u/%x) "
			    "cannot be handled, ignored\n",
			    index, c->channel, c->channelFlags));
			continue;
		}

		/*
		 * Calculate net80211 flags; most are compatible
		 * but some need massaging.  Note the static turbo
		 * conversion can be removed once net80211 is updated
		 * to understand static vs. dynamic turbo.
		 */

		flags = c->channelFlags & (CHANNEL_ALL | CHANNEL_PASSIVE);

		if (ic->ic_sup_channels[index].ich_freq == 0) {
			ic->ic_sup_channels[index].ich_freq = c->channel;
			ic->ic_sup_channels[index].ich_flags = flags;
		} else {
			/* channels overlap; e.g. 11g and 11b */
			ic->ic_sup_channels[index].ich_flags |= flags;
		}
		if ((c->channelFlags & CHANNEL_G) == CHANNEL_G) {
			sc->sc_have11g = 1;
			ic->ic_caps |= IEEE80211_C_SHPREAMBLE |
			    IEEE80211_C_SHSLOT;	/* short slot time */
		}
	}

	return (0);
}

uint32_t
arn_chan2flags(ieee80211com_t *isc, struct ieee80211_channel *chan)
{
	uint32_t channel_mode;
	switch (ieee80211_chan2mode(isc, chan)) {
	case IEEE80211_MODE_11NA:
		if (chan->ich_flags & IEEE80211_CHAN_HT40U)
			channel_mode = CHANNEL_A_HT40PLUS;
		else if (chan->ich_flags & IEEE80211_CHAN_HT40D)
			channel_mode = CHANNEL_A_HT40MINUS;
		else
			channel_mode = CHANNEL_A_HT20;
		break;
	case IEEE80211_MODE_11NG:
		if (chan->ich_flags & IEEE80211_CHAN_HT40U)
			channel_mode = CHANNEL_G_HT40PLUS;
		else if (chan->ich_flags & IEEE80211_CHAN_HT40D)
			channel_mode = CHANNEL_G_HT40MINUS;
		else
			channel_mode = CHANNEL_G_HT20;
		break;
	case IEEE80211_MODE_TURBO_G:
	case IEEE80211_MODE_STURBO_A:
	case IEEE80211_MODE_TURBO_A:
		channel_mode = 0;
		break;
	case IEEE80211_MODE_11A:
		channel_mode = CHANNEL_A;
		break;
	case IEEE80211_MODE_11G:
		channel_mode = CHANNEL_B;
		break;
	case IEEE80211_MODE_11B:
		channel_mode = CHANNEL_G;
		break;
	case IEEE80211_MODE_FH:
		channel_mode = 0;
		break;
	default:
		break;
	}

	return (channel_mode);
}

/*
 * Update internal state after a channel change.
 */
void
arn_chan_change(struct arn_softc *sc, struct ieee80211_channel *chan)
{
	struct ieee80211com *ic = &sc->sc_isc;
	enum ieee80211_phymode mode;
	enum wireless_mode wlmode;

	/*
	 * Change channels and update the h/w rate map
	 * if we're switching; e.g. 11a to 11b/g.
	 */
	mode = ieee80211_chan2mode(ic, chan);
	switch (mode) {
	case IEEE80211_MODE_11A:
		wlmode = ATH9K_MODE_11A;
		break;
	case IEEE80211_MODE_11B:
		wlmode = ATH9K_MODE_11B;
		break;
	case IEEE80211_MODE_11G:
		wlmode = ATH9K_MODE_11B;
		break;
	default:
		break;
	}
	if (wlmode != sc->sc_curmode)
		arn_setcurmode(sc, wlmode);

}

/*
 * Set/change channels.  If the channel is really being changed, it's done
 * by reseting the chip.  To accomplish this we must first cleanup any pending
 * DMA, then restart stuff.
 */
static int
arn_set_channel(struct arn_softc *sc, struct ath9k_channel *hchan)
{
	struct ath_hal *ah = sc->sc_ah;
	ieee80211com_t *ic = &sc->sc_isc;
	boolean_t fastcc = B_TRUE;
	boolean_t  stopped;
	struct ieee80211_channel chan;
	enum wireless_mode curmode;

	if (sc->sc_flags & SC_OP_INVALID)
		return (EIO);

	if (hchan->channel != sc->sc_ah->ah_curchan->channel ||
	    hchan->channelFlags != sc->sc_ah->ah_curchan->channelFlags ||
	    (sc->sc_flags & SC_OP_CHAINMASK_UPDATE) ||
	    (sc->sc_flags & SC_OP_FULL_RESET)) {
		int status;

		/*
		 * This is only performed if the channel settings have
		 * actually changed.
		 *
		 * To switch channels clear any pending DMA operations;
		 * wait long enough for the RX fifo to drain, reset the
		 * hardware at the new frequency, and then re-enable
		 * the relevant bits of the h/w.
		 */
		(void) ath9k_hw_set_interrupts(ah, 0);	/* disable interrupts */
		arn_draintxq(sc, B_FALSE);	/* clear pending tx frames */
		stopped = arn_stoprecv(sc);	/* turn off frame recv */

		/*
		 * XXX: do not flush receive queue here. We don't want
		 * to flush data frames already in queue because of
		 * changing channel.
		 */

		if (!stopped || (sc->sc_flags & SC_OP_FULL_RESET))
			fastcc = B_FALSE;

		ARN_DBG((ARN_DBG_CHANNEL, "arn: arn_set_channel(): "
		    "(%u MHz) -> (%u MHz), cflags:%x, chanwidth: %d\n",
		    sc->sc_ah->ah_curchan->channel,
		    hchan->channel, hchan->channelFlags, sc->tx_chan_width));

		if (!ath9k_hw_reset(ah, hchan, sc->tx_chan_width,
		    sc->sc_tx_chainmask, sc->sc_rx_chainmask,
		    sc->sc_ht_extprotspacing, fastcc, &status)) {
			ARN_DBG((ARN_DBG_FATAL, "arn: arn_set_channel(): "
			    "unable to reset channel %u (%uMhz) "
			    "flags 0x%x hal status %u\n",
			    ath9k_hw_mhz2ieee(ah, hchan->channel,
			    hchan->channelFlags),
			    hchan->channel, hchan->channelFlags, status));
			return (EIO);
		}

		sc->sc_curchan = *hchan;

		sc->sc_flags &= ~SC_OP_CHAINMASK_UPDATE;
		sc->sc_flags &= ~SC_OP_FULL_RESET;

		if (arn_startrecv(sc) != 0) {
			arn_problem("arn: arn_set_channel(): "
			    "unable to restart recv logic\n");
			return (EIO);
		}

		chan.ich_freq = hchan->channel;
		chan.ich_flags = hchan->channelFlags;
		ic->ic_ibss_chan = &chan;

		/*
		 * Change channels and update the h/w rate map
		 * if we're switching; e.g. 11a to 11b/g.
		 */
		curmode = arn_chan2mode(hchan);
		if (curmode != sc->sc_curmode)
			arn_setcurmode(sc, arn_chan2mode(hchan));

		arn_update_txpow(sc);

		(void) ath9k_hw_set_interrupts(ah, sc->sc_imask);
	}

	return (0);
}

/*
 *  This routine performs the periodic noise floor calibration function
 *  that is used to adjust and optimize the chip performance.  This
 *  takes environmental changes (location, temperature) into account.
 *  When the task is complete, it reschedules itself depending on the
 *  appropriate interval that was calculated.
 */
static void
arn_ani_calibrate(void *arg)
{
	ieee80211com_t *ic = (ieee80211com_t *)arg;
	struct arn_softc *sc = (struct arn_softc *)ic;
	struct ath_hal *ah = sc->sc_ah;
	boolean_t longcal = B_FALSE;
	boolean_t shortcal = B_FALSE;
	boolean_t aniflag = B_FALSE;
	unsigned int timestamp = drv_hztousec(ddi_get_lbolt())/1000;
	uint32_t cal_interval;

	/*
	 * don't calibrate when we're scanning.
	 * we are most likely not on our home channel.
	 */
	if (ic->ic_state != IEEE80211_S_RUN)
		goto settimer;

	/* Long calibration runs independently of short calibration. */
	if ((timestamp - sc->sc_ani.sc_longcal_timer) >= ATH_LONG_CALINTERVAL) {
		longcal = B_TRUE;
		ARN_DBG((ARN_DBG_CALIBRATE, "arn: "
		    "%s: longcal @%lu\n", __func__, drv_hztousec));
		sc->sc_ani.sc_longcal_timer = timestamp;
	}

	/* Short calibration applies only while sc_caldone is FALSE */
	if (!sc->sc_ani.sc_caldone) {
		if ((timestamp - sc->sc_ani.sc_shortcal_timer) >=
		    ATH_SHORT_CALINTERVAL) {
			shortcal = B_TRUE;
			ARN_DBG((ARN_DBG_CALIBRATE, "arn: "
			    "%s: shortcal @%lu\n",
			    __func__, drv_hztousec));
			sc->sc_ani.sc_shortcal_timer = timestamp;
			sc->sc_ani.sc_resetcal_timer = timestamp;
		}
	} else {
		if ((timestamp - sc->sc_ani.sc_resetcal_timer) >=
		    ATH_RESTART_CALINTERVAL) {
			ath9k_hw_reset_calvalid(ah, ah->ah_curchan,
			    &sc->sc_ani.sc_caldone);
			if (sc->sc_ani.sc_caldone)
				sc->sc_ani.sc_resetcal_timer = timestamp;
		}
	}

	/* Verify whether we must check ANI */
	if ((timestamp - sc->sc_ani.sc_checkani_timer) >=
	    ATH_ANI_POLLINTERVAL) {
		aniflag = B_TRUE;
		sc->sc_ani.sc_checkani_timer = timestamp;
	}

	/* Skip all processing if there's nothing to do. */
	if (longcal || shortcal || aniflag) {
		/* Call ANI routine if necessary */
		if (aniflag)
			ath9k_hw_ani_monitor(ah, &sc->sc_halstats,
			    ah->ah_curchan);

		/* Perform calibration if necessary */
		if (longcal || shortcal) {
			boolean_t iscaldone = B_FALSE;

			if (ath9k_hw_calibrate(ah, ah->ah_curchan,
			    sc->sc_rx_chainmask, longcal, &iscaldone)) {
				if (longcal)
					sc->sc_ani.sc_noise_floor =
					    ath9k_hw_getchan_noise(ah,
					    ah->ah_curchan);

				ARN_DBG((ARN_DBG_CALIBRATE, "arn: "
				    "%s: calibrate chan %u/%x nf: %d\n",
				    __func__,
				    ah->ah_curchan->channel,
				    ah->ah_curchan->channelFlags,
				    sc->sc_ani.sc_noise_floor));
			} else {
				ARN_DBG((ARN_DBG_CALIBRATE, "arn: "
				    "%s: calibrate chan %u/%x failed\n",
				    __func__,
				    ah->ah_curchan->channel,
				    ah->ah_curchan->channelFlags));
			}
			sc->sc_ani.sc_caldone = iscaldone;
		}
	}

settimer:
	/*
	 * Set timer interval based on previous results.
	 * The interval must be the shortest necessary to satisfy ANI,
	 * short calibration and long calibration.
	 */
	cal_interval = ATH_LONG_CALINTERVAL;
	if (sc->sc_ah->ah_config.enable_ani)
		cal_interval =
		    min(cal_interval, (uint32_t)ATH_ANI_POLLINTERVAL);

	if (!sc->sc_ani.sc_caldone)
		cal_interval = min(cal_interval,
		    (uint32_t)ATH_SHORT_CALINTERVAL);

	sc->sc_scan_timer = 0;
	sc->sc_scan_timer = timeout(arn_ani_calibrate, (void *)sc,
	    drv_usectohz(cal_interval * 1000));
}

static void
arn_stop_caltimer(struct arn_softc *sc)
{
	timeout_id_t tmp_id = 0;

	while ((sc->sc_cal_timer != 0) && (tmp_id != sc->sc_cal_timer)) {
		tmp_id = sc->sc_cal_timer;
		(void) untimeout(tmp_id);
	}
	sc->sc_cal_timer = 0;
}

static uint_t
arn_isr(caddr_t arg)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct arn_softc *sc = (struct arn_softc *)arg;
	struct ath_hal *ah = sc->sc_ah;
	enum ath9k_int status;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	ARN_LOCK(sc);

	if (sc->sc_flags & SC_OP_INVALID) {
		/*
		 * The hardware is not ready/present, don't
		 * touch anything. Note this can happen early
		 * on if the IRQ is shared.
		 */
		ARN_UNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}
	if (!ath9k_hw_intrpend(ah)) {	/* shared irq, not for us */
		ARN_UNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Figure out the reason(s) for the interrupt. Note
	 * that the hal returns a pseudo-ISR that may include
	 * bits we haven't explicitly enabled so we mask the
	 * value to insure we only process bits we requested.
	 */
	(void) ath9k_hw_getisr(ah, &status); /* NB: clears ISR too */

	status &= sc->sc_imask; /* discard unasked-for bits */

	/*
	 * If there are no status bits set, then this interrupt was not
	 * for me (should have been caught above).
	 */
	if (!status) {
		ARN_UNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	sc->sc_intrstatus = status;

	if (status & ATH9K_INT_FATAL) {
		/* need a chip reset */
		ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
		    "ATH9K_INT_FATAL\n"));
		goto reset;
	} else if (status & ATH9K_INT_RXORN) {
		/* need a chip reset */
		ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
		    "ATH9K_INT_RXORN\n"));
		goto reset;
	} else {
		if (status & ATH9K_INT_RXEOL) {
			/*
			 * NB: the hardware should re-read the link when
			 * RXE bit is written, but it doesn't work
			 * at least on older hardware revs.
			 */
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_RXEOL\n"));
			sc->sc_rxlink = NULL;
		}
		if (status & ATH9K_INT_TXURN) {
			/* bump tx trigger level */
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_TXURN\n"));
			(void) ath9k_hw_updatetxtriglevel(ah, B_TRUE);
		}
		/* XXX: optimize this */
		if (status & ATH9K_INT_RX) {
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_RX\n"));
			sc->sc_rx_pend = 1;
			ddi_trigger_softintr(sc->sc_softint_id);
		}
		if (status & ATH9K_INT_TX) {
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_TX\n"));
			if (ddi_taskq_dispatch(sc->sc_tq,
			    arn_tx_int_proc, sc, DDI_NOSLEEP) !=
			    DDI_SUCCESS) {
				arn_problem("arn: arn_isr(): "
				    "No memory for tx taskq\n");
				}
			}
#ifdef ARN_ATH9K_INT_MIB
		if (status & ATH9K_INT_MIB) {
			/*
			 * Disable interrupts until we service the MIB
			 * interrupt; otherwise it will continue to
			 * fire.
			 */
			(void) ath9k_hw_set_interrupts(ah, 0);
			/*
			 * Let the hal handle the event. We assume
			 * it will clear whatever condition caused
			 * the interrupt.
			 */
			ath9k_hw_procmibevent(ah, &sc->sc_halstats);
			(void) ath9k_hw_set_interrupts(ah, sc->sc_imask);
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_MIB\n"));
		}
#endif

#ifdef ARN_ATH9K_INT_TIM_TIMER
		if (status & ATH9K_INT_TIM_TIMER) {
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_TIM_TIMER\n"));
			if (!(ah->ah_caps.hw_caps &
			    ATH9K_HW_CAP_AUTOSLEEP)) {
				/*
				 * Clear RxAbort bit so that we can
				 * receive frames
				 */
				ath9k_hw_setrxabort(ah, 0);
				goto reset;
			}
		}
#endif

		if (status & ATH9K_INT_BMISS) {
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_BMISS\n"));
#ifdef ARN_HW_BEACON_MISS_HANDLE
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "handle beacon mmiss by H/W mechanism\n"));
			if (ddi_taskq_dispatch(sc->sc_tq, arn_bmiss_proc,
			    sc, DDI_NOSLEEP) != DDI_SUCCESS) {
				arn_problem("arn: arn_isr(): "
				    "No memory available for bmiss taskq\n");
			}
#else
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "handle beacon mmiss by S/W mechanism\n"));
#endif /* ARN_HW_BEACON_MISS_HANDLE */
		}

		ARN_UNLOCK(sc);

#ifdef ARN_ATH9K_INT_CST
		/* carrier sense timeout */
		if (status & ATH9K_INT_CST) {
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_CST\n"));
			return (DDI_INTR_CLAIMED);
		}
#endif

		if (status & ATH9K_INT_SWBA) {
			ARN_DBG((ARN_DBG_INTERRUPT, "arn: arn_isr(): "
			    "ATH9K_INT_SWBA\n"));
			/* This will occur only in Host-AP or Ad-Hoc mode */
			return (DDI_INTR_CLAIMED);
		}
	}

	return (DDI_INTR_CLAIMED);
reset:
	ARN_DBG((ARN_DBG_INTERRUPT, "Rset for fatal err\n"));
	(void) arn_reset(ic);
	ARN_UNLOCK(sc);
	return (DDI_INTR_CLAIMED);
}

static int
arn_get_channel(struct arn_softc *sc, struct ieee80211_channel *chan)
{
	int i;

	for (i = 0; i < sc->sc_ah->ah_nchan; i++) {
		if (sc->sc_ah->ah_channels[i].channel == chan->ich_freq)
			return (i);
	}

	return (-1);
}

int
arn_reset(ieee80211com_t *ic)
{
	struct arn_softc *sc = (struct arn_softc *)ic;
	struct ath_hal *ah = sc->sc_ah;
	int status;
	int error = 0;

	(void) ath9k_hw_set_interrupts(ah, 0);
	arn_draintxq(sc, 0);
	(void) arn_stoprecv(sc);

	if (!ath9k_hw_reset(ah, sc->sc_ah->ah_curchan, sc->tx_chan_width,
	    sc->sc_tx_chainmask, sc->sc_rx_chainmask,
	    sc->sc_ht_extprotspacing, B_FALSE, &status)) {
		ARN_DBG((ARN_DBG_RESET, "arn: arn_reset(): "
		    "unable to reset hardware; hal status %u\n", status));
		error = EIO;
	}

	if (arn_startrecv(sc) != 0)
		ARN_DBG((ARN_DBG_RESET, "arn: arn_reset(): "
		    "unable to start recv logic\n"));

	/*
	 * We may be doing a reset in response to a request
	 * that changes the channel so update any state that
	 * might change as a result.
	 */
	arn_setcurmode(sc, arn_chan2mode(sc->sc_ah->ah_curchan));

	arn_update_txpow(sc);

	if (sc->sc_flags & SC_OP_BEACONS)
		arn_beacon_config(sc);	/* restart beacons */

	(void) ath9k_hw_set_interrupts(ah, sc->sc_imask);

	return (error);
}

int
arn_get_hal_qnum(uint16_t queue, struct arn_softc *sc)
{
	int qnum;

	switch (queue) {
	case WME_AC_VO:
		qnum = sc->sc_haltype2q[ATH9K_WME_AC_VO];
		break;
	case WME_AC_VI:
		qnum = sc->sc_haltype2q[ATH9K_WME_AC_VI];
		break;
	case WME_AC_BE:
		qnum = sc->sc_haltype2q[ATH9K_WME_AC_BE];
		break;
	case WME_AC_BK:
		qnum = sc->sc_haltype2q[ATH9K_WME_AC_BK];
		break;
	default:
		qnum = sc->sc_haltype2q[ATH9K_WME_AC_BE];
		break;
	}

	return (qnum);
}

static struct {
	uint32_t version;
	const char *name;
} ath_mac_bb_names[] = {
	{ AR_SREV_VERSION_5416_PCI,	"5416" },
	{ AR_SREV_VERSION_5416_PCIE,	"5418" },
	{ AR_SREV_VERSION_9100,		"9100" },
	{ AR_SREV_VERSION_9160,		"9160" },
	{ AR_SREV_VERSION_9280,		"9280" },
	{ AR_SREV_VERSION_9285,		"9285" }
};

static struct {
	uint16_t version;
	const char *name;
} ath_rf_names[] = {
	{ 0,				"5133" },
	{ AR_RAD5133_SREV_MAJOR,	"5133" },
	{ AR_RAD5122_SREV_MAJOR,	"5122" },
	{ AR_RAD2133_SREV_MAJOR,	"2133" },
	{ AR_RAD2122_SREV_MAJOR,	"2122" }
};

/*
 * Return the MAC/BB name. "????" is returned if the MAC/BB is unknown.
 */

static const char *
arn_mac_bb_name(uint32_t mac_bb_version)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ath_mac_bb_names); i++) {
		if (ath_mac_bb_names[i].version == mac_bb_version) {
			return (ath_mac_bb_names[i].name);
		}
	}

	return ("????");
}

/*
 * Return the RF name. "????" is returned if the RF is unknown.
 */

static const char *
arn_rf_name(uint16_t rf_version)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ath_rf_names); i++) {
		if (ath_rf_names[i].version == rf_version) {
			return (ath_rf_names[i].name);
		}
	}

	return ("????");
}

static void
arn_next_scan(void *arg)
{
	ieee80211com_t *ic = arg;
	struct arn_softc *sc = (struct arn_softc *)ic;

	sc->sc_scan_timer = 0;
	if (ic->ic_state == IEEE80211_S_SCAN) {
		sc->sc_scan_timer = timeout(arn_next_scan, (void *)sc,
		    drv_usectohz(arn_dwelltime * 1000));
		ieee80211_next_scan(ic);
	}
}

static void
arn_stop_scantimer(struct arn_softc *sc)
{
	timeout_id_t tmp_id = 0;

	while ((sc->sc_scan_timer != 0) && (tmp_id != sc->sc_scan_timer)) {
		tmp_id = sc->sc_scan_timer;
		(void) untimeout(tmp_id);
	}
	sc->sc_scan_timer = 0;
}

static int32_t
arn_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	struct arn_softc *sc = (struct arn_softc *)ic;
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211_node *in;
	int32_t i, error;
	uint8_t *bssid;
	uint32_t rfilt;
	enum ieee80211_state ostate;
	struct ath9k_channel *channel;
	int pos;

	/* Should set up & init LED here */

	if (sc->sc_flags & SC_OP_INVALID)
		return (0);

	ostate = ic->ic_state;
	ARN_DBG((ARN_DBG_INIT, "arn: arn_newstate(): "
	    "%x -> %x!\n", ostate, nstate));

	ARN_LOCK(sc);

	if (nstate != IEEE80211_S_SCAN)
		arn_stop_scantimer(sc);
	if (nstate != IEEE80211_S_RUN)
		arn_stop_caltimer(sc);

	/* Should set LED here */

	if (nstate == IEEE80211_S_INIT) {
		sc->sc_imask &= ~(ATH9K_INT_SWBA | ATH9K_INT_BMISS);
		/*
		 * Disable interrupts.
		 */
		(void) ath9k_hw_set_interrupts
		    (ah, sc->sc_imask &~ ATH9K_INT_GLOBAL);

#ifdef ARN_IBSS
		if (ic->ic_opmode == IEEE80211_M_IBSS) {
			(void) ath9k_hw_stoptxdma(ah, sc->sc_beaconq);
			arn_beacon_return(sc);
		}
#endif
		ARN_UNLOCK(sc);
		ieee80211_stop_watchdog(ic);
		goto done;
	}
	in = ic->ic_bss;

	pos = arn_get_channel(sc, ic->ic_curchan);

	if (pos == -1) {
		ARN_DBG((ARN_DBG_FATAL, "arn: "
		    "%s: Invalid channel\n", __func__));
		error = EINVAL;
		ARN_UNLOCK(sc);
		goto bad;
	}

	if (in->in_htcap & IEEE80211_HTCAP_CHWIDTH40) {
		arn_update_chainmask(sc);
		sc->tx_chan_width = ATH9K_HT_MACMODE_2040;
	} else
		sc->tx_chan_width = ATH9K_HT_MACMODE_20;

	sc->sc_ah->ah_channels[pos].chanmode =
	    arn_chan2flags(ic, ic->ic_curchan);
	channel = &sc->sc_ah->ah_channels[pos];
	if (channel == NULL) {
		arn_problem("arn_newstate(): channel == NULL");
		ARN_UNLOCK(sc);
		goto bad;
	}
	error = arn_set_channel(sc, channel);
	if (error != 0) {
		if (nstate != IEEE80211_S_SCAN) {
			ARN_UNLOCK(sc);
			ieee80211_reset_chan(ic);
			goto bad;
		}
	}

	/*
	 * Get the receive filter according to the
	 * operating mode and state
	 */
	rfilt = arn_calcrxfilter(sc);

	if (nstate == IEEE80211_S_SCAN)
		bssid = ic->ic_macaddr;
	else
		bssid = in->in_bssid;

	ath9k_hw_setrxfilter(ah, rfilt);

	if (nstate == IEEE80211_S_RUN && ic->ic_opmode != IEEE80211_M_IBSS)
		ath9k_hw_write_associd(ah, bssid, in->in_associd);
	else
		ath9k_hw_write_associd(ah, bssid, 0);

	/* Check for WLAN_CAPABILITY_PRIVACY ? */
	if (ic->ic_flags & IEEE80211_F_PRIVACY) {
		for (i = 0; i < IEEE80211_WEP_NKID; i++) {
			if (ath9k_hw_keyisvalid(ah, (uint16_t)i))
				(void) ath9k_hw_keysetmac(ah, (uint16_t)i,
				    bssid);
		}
	}

	if (nstate == IEEE80211_S_RUN) {
		switch (ic->ic_opmode) {
#ifdef ARN_IBSS
		case IEEE80211_M_IBSS:
			/*
			 * Allocate and setup the beacon frame.
			 * Stop any previous beacon DMA.
			 */
			(void) ath9k_hw_stoptxdma(ah, sc->sc_beaconq);
			arn_beacon_return(sc);
			error = arn_beacon_alloc(sc, in);
			if (error != 0) {
				ARN_UNLOCK(sc);
				goto bad;
			}
			/*
			 * If joining an adhoc network defer beacon timer
			 * configuration to the next beacon frame so we
			 * have a current TSF to use.  Otherwise we're
			 * starting an ibss/bss so there's no need to delay.
			 */
			if (ic->ic_opmode == IEEE80211_M_IBSS &&
			    ic->ic_bss->in_tstamp.tsf != 0) {
				sc->sc_bsync = 1;
			} else {
				arn_beacon_config(sc);
			}
			break;
#endif /* ARN_IBSS */
		case IEEE80211_M_STA:
			if (ostate != IEEE80211_S_RUN) {
				/*
				 * Defer beacon timer configuration to the next
				 * beacon frame so we have a current TSF to use.
				 * Any TSF collected when scanning is likely old
				 */
#ifdef ARN_IBSS
				sc->sc_bsync = 1;
#else
				/* Configure the beacon and sleep timers. */
				arn_beacon_config(sc);
				/* Reset rssi stats */
				sc->sc_halstats.ns_avgbrssi =
				    ATH_RSSI_DUMMY_MARKER;
				sc->sc_halstats.ns_avgrssi =
				    ATH_RSSI_DUMMY_MARKER;
				sc->sc_halstats.ns_avgtxrssi =
				    ATH_RSSI_DUMMY_MARKER;
				sc->sc_halstats.ns_avgtxrate =
				    ATH_RATE_DUMMY_MARKER;
/* end */

#endif /* ARN_IBSS */
			}
			break;
		default:
			break;
		}
	} else {
		sc->sc_imask &= ~(ATH9K_INT_SWBA | ATH9K_INT_BMISS);
		(void) ath9k_hw_set_interrupts(ah, sc->sc_imask);
	}

	/*
	 * Reset the rate control state.
	 */
	arn_rate_ctl_reset(sc, nstate);

	ARN_UNLOCK(sc);
done:
	/*
	 * Invoke the parent method to complete the work.
	 */
	error = sc->sc_newstate(ic, nstate, arg);

	/*
	 * Finally, start any timers.
	 */
	if (nstate == IEEE80211_S_RUN) {
		ieee80211_start_watchdog(ic, 1);
		ASSERT(sc->sc_cal_timer == 0);
		sc->sc_cal_timer = timeout(arn_ani_calibrate, (void *)sc,
		    drv_usectohz(100 * 1000));
	} else if ((nstate == IEEE80211_S_SCAN) && (ostate != nstate)) {
		/* start ap/neighbor scan timer */
		/* ASSERT(sc->sc_scan_timer == 0); */
		if (sc->sc_scan_timer != 0) {
			(void) untimeout(sc->sc_scan_timer);
			sc->sc_scan_timer = 0;
		}
		sc->sc_scan_timer = timeout(arn_next_scan, (void *)sc,
		    drv_usectohz(arn_dwelltime * 1000));
	}

bad:
	return (error);
}

static void
arn_watchdog(void *arg)
{
	struct arn_softc *sc = arg;
	ieee80211com_t *ic = &sc->sc_isc;
	int ntimer = 0;

	ARN_LOCK(sc);
	ic->ic_watchdog_timer = 0;
	if (sc->sc_flags & SC_OP_INVALID) {
		ARN_UNLOCK(sc);
		return;
	}

	if (ic->ic_state == IEEE80211_S_RUN) {
		/*
		 * Start the background rate control thread if we
		 * are not configured to use a fixed xmit rate.
		 */
#ifdef ARN_LEGACY_RC
		if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
			sc->sc_stats.ast_rate_calls ++;
			if (ic->ic_opmode == IEEE80211_M_STA)
				arn_rate_ctl(ic, ic->ic_bss);
			else
				ieee80211_iterate_nodes(&ic->ic_sta,
				    arn_rate_ctl, sc);
		}
#endif /* ARN_LEGACY_RC */

#ifdef ARN_HW_BEACON_MISS_HANDLE
	/* nothing to do here */
#else
	/* currently set 10 seconds as beacon miss threshold */
	if (ic->ic_beaconmiss++ > 100) {
		ARN_DBG((ARN_DBG_BEACON, "arn_watchdog():"
		    "Beacon missed for 10 seconds, run"
		    "ieee80211_new_state(ic, IEEE80211_S_INIT, -1)\n"));
		ARN_UNLOCK(sc);
		(void) ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
		return;
	}
#endif /* ARN_HW_BEACON_MISS_HANDLE */

		ntimer = 1;
	}
	ARN_UNLOCK(sc);

	ieee80211_watchdog(ic);
	if (ntimer != 0)
		ieee80211_start_watchdog(ic, ntimer);
}

/* ARGSUSED */
static struct ieee80211_node *
arn_node_alloc(ieee80211com_t *ic)
{
	struct ath_node *an;
#ifdef ARN_TX_AGGREGATION
	struct arn_softc *sc = (struct arn_softc *)ic;
#endif

	an = kmem_zalloc(sizeof (struct ath_node), KM_SLEEP);

	/* legacy rate control */
#ifdef ARN_LEGACY_RC
	arn_rate_update(sc, &an->an_node, 0);
#endif

#ifdef ARN_TX_AGGREGATION
	if (sc->sc_flags & SC_OP_TXAGGR) {
		arn_tx_node_init(sc, an);
	}
#endif /* ARN_TX_AGGREGATION */

	an->last_rssi = ATH_RSSI_DUMMY_MARKER;

	return ((an != NULL) ? &an->an_node : NULL);
}

static void
arn_node_free(struct ieee80211_node *in)
{
	ieee80211com_t *ic = in->in_ic;
	struct arn_softc *sc = (struct arn_softc *)ic;
	struct ath_buf *bf;
	struct ath_txq *txq;
	int32_t i;

#ifdef ARN_TX_AGGREGATION
	if (sc->sc_flags & SC_OP_TXAGGR)
		arn_tx_node_cleanup(sc, in);
#endif /* TX_AGGREGATION */

	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i)) {
			txq = &sc->sc_txq[i];
			mutex_enter(&txq->axq_lock);
			bf = list_head(&txq->axq_list);
			while (bf != NULL) {
				if (bf->bf_in == in) {
					bf->bf_in = NULL;
				}
				bf = list_next(&txq->axq_list, bf);
			}
			mutex_exit(&txq->axq_lock);
		}
	}

	ic->ic_node_cleanup(in);

	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);

	if (in->in_wme_ie != NULL)
		ieee80211_free(in->in_wme_ie);

	if (in->in_htcap_ie != NULL)
		ieee80211_free(in->in_htcap_ie);

	kmem_free(in, sizeof (struct ath_node));
}

/*
 * Allocate tx/rx key slots for TKIP.  We allocate one slot for
 * each key. MIC is right after the decrypt/encrypt key.
 */
static uint16_t
arn_key_alloc_pair(struct arn_softc *sc, ieee80211_keyix *txkeyix,
    ieee80211_keyix *rxkeyix)
{
	uint16_t i, keyix;

	ASSERT(!sc->sc_splitmic);
	for (i = 0; i < ARRAY_SIZE(sc->sc_keymap)/4; i++) {
		uint8_t b = sc->sc_keymap[i];
		if (b == 0xff)
			continue;
		for (keyix = i * NBBY; keyix < (i + 1) * NBBY;
		    keyix++, b >>= 1) {
			if ((b & 1) || is_set(keyix+64, sc->sc_keymap)) {
				/* full pair unavailable */
				continue;
			}
			set_bit(keyix, sc->sc_keymap);
			set_bit(keyix+64, sc->sc_keymap);
			ARN_DBG((ARN_DBG_KEYCACHE,
			    "arn_key_alloc_pair(): key pair %u,%u\n",
			    keyix, keyix+64));
			*txkeyix = *rxkeyix = keyix;
			return (1);
		}
	}
	ARN_DBG((ARN_DBG_KEYCACHE, "arn_key_alloc_pair():"
	    " out of pair space\n"));

	return (0);
}

/*
 * Allocate tx/rx key slots for TKIP.  We allocate two slots for
 * each key, one for decrypt/encrypt and the other for the MIC.
 */
static int
arn_key_alloc_2pair(struct arn_softc *sc, ieee80211_keyix *txkeyix,
    ieee80211_keyix *rxkeyix)
{
	uint16_t i, keyix;

	ASSERT(sc->sc_splitmic);
	for (i = 0; i < ARRAY_SIZE(sc->sc_keymap)/4; i++) {
		uint8_t b = sc->sc_keymap[i];
		if (b != 0xff) {
			/*
			 * One or more slots in this byte are free.
			 */
			keyix = i*NBBY;
			while (b & 1) {
		again:
				keyix++;
				b >>= 1;
			}
			/* XXX IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV */
			if (is_set(keyix+32, sc->sc_keymap) ||
			    is_set(keyix+64, sc->sc_keymap) ||
			    is_set(keyix+32+64, sc->sc_keymap)) {
				/* full pair unavailable */
				if (keyix == (i+1)*NBBY) {
					/* no slots were appropriate, advance */
					continue;
				}
				goto again;
			}
			set_bit(keyix, sc->sc_keymap);
			set_bit(keyix+64, sc->sc_keymap);
			set_bit(keyix+32, sc->sc_keymap);
			set_bit(keyix+32+64, sc->sc_keymap);
			ARN_DBG((ARN_DBG_KEYCACHE,
			    "arn_key_alloc_2pair(): key pair %u,%u %u,%u\n",
			    keyix, keyix+64,
			    keyix+32, keyix+32+64));
			*txkeyix = *rxkeyix = keyix;
			return (1);
		}
	}
	ARN_DBG((ARN_DBG_KEYCACHE, "arn_key_alloc_2pair(): "
	    " out of pair space\n"));

	return (0);
}
/*
 * Allocate a single key cache slot.
 */
static int
arn_key_alloc_single(struct arn_softc *sc, ieee80211_keyix *txkeyix,
    ieee80211_keyix *rxkeyix)
{
	uint16_t i, keyix;

	/* try i,i+32,i+64,i+32+64 to minimize key pair conflicts */
	for (i = 0; i < ARRAY_SIZE(sc->sc_keymap); i++) {
		uint8_t b = sc->sc_keymap[i];

		if (b != 0xff) {
			/*
			 * One or more slots are free.
			 */
			keyix = i*NBBY;
			while (b & 1)
				keyix++, b >>= 1;
			set_bit(keyix, sc->sc_keymap);
			ARN_DBG((ARN_DBG_KEYCACHE, "arn_key_alloc_single(): "
			    "key %u\n", keyix));
			*txkeyix = *rxkeyix = keyix;
			return (1);
		}
	}
	return (0);
}

/*
 * Allocate one or more key cache slots for a unicast key.  The
 * key itself is needed only to identify the cipher.  For hardware
 * TKIP with split cipher+MIC keys we allocate two key cache slot
 * pairs so that we can setup separate TX and RX MIC keys.  Note
 * that the MIC key for a TKIP key at slot i is assumed by the
 * hardware to be at slot i+64.  This limits TKIP keys to the first
 * 64 entries.
 */
/* ARGSUSED */
int
arn_key_alloc(ieee80211com_t *ic, const struct ieee80211_key *k,
    ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
	struct arn_softc *sc = (struct arn_softc *)ic;

	/*
	 * We allocate two pair for TKIP when using the h/w to do
	 * the MIC.  For everything else, including software crypto,
	 * we allocate a single entry.  Note that s/w crypto requires
	 * a pass-through slot on the 5211 and 5212.  The 5210 does
	 * not support pass-through cache entries and we map all
	 * those requests to slot 0.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
		return (arn_key_alloc_single(sc, keyix, rxkeyix));
	} else if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
		if (sc->sc_splitmic)
			return (arn_key_alloc_2pair(sc, keyix, rxkeyix));
		else
			return (arn_key_alloc_pair(sc, keyix, rxkeyix));
	} else {
		return (arn_key_alloc_single(sc, keyix, rxkeyix));
	}
}

/*
 * Delete an entry in the key cache allocated by ath_key_alloc.
 */
int
arn_key_delete(ieee80211com_t *ic, const struct ieee80211_key *k)
{
	struct arn_softc *sc = (struct arn_softc *)ic;
	struct ath_hal *ah = sc->sc_ah;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	ieee80211_keyix keyix = k->wk_keyix;

	ARN_DBG((ARN_DBG_KEYCACHE, "arn_key_delete():"
	    " delete key %u ic_cipher=0x%x\n", keyix, cip->ic_cipher));

	(void) ath9k_hw_keyreset(ah, keyix);
	/*
	 * Handle split tx/rx keying required for TKIP with h/w MIC.
	 */
	if (cip->ic_cipher == IEEE80211_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0 && sc->sc_splitmic)
		(void) ath9k_hw_keyreset(ah, keyix+32);		/* RX key */

	if (keyix >= IEEE80211_WEP_NKID) {
		/*
		 * Don't touch keymap entries for global keys so
		 * they are never considered for dynamic allocation.
		 */
		clr_bit(keyix, sc->sc_keymap);
		if (cip->ic_cipher == IEEE80211_CIPHER_TKIP &&
		    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
			/*
			 * If splitmic is true +64 is TX key MIC,
			 * else +64 is RX key + RX key MIC.
			 */
			clr_bit(keyix+64, sc->sc_keymap);
			if (sc->sc_splitmic) {
				/* Rx key */
				clr_bit(keyix+32, sc->sc_keymap);
				/* RX key MIC */
				clr_bit(keyix+32+64, sc->sc_keymap);
			}
		}
	}
	return (1);
}

/*
 * Set a TKIP key into the hardware.  This handles the
 * potential distribution of key state to multiple key
 * cache slots for TKIP.
 */
static int
arn_keyset_tkip(struct arn_softc *sc, const struct ieee80211_key *k,
    struct ath9k_keyval *hk, const uint8_t mac[IEEE80211_ADDR_LEN])
{
	uint8_t *key_rxmic = NULL;
	uint8_t *key_txmic = NULL;
	uint8_t  *key = (uint8_t *)&(k->wk_key[0]);
	struct ath_hal *ah = sc->sc_ah;

	key_txmic = key + 16;
	key_rxmic = key + 24;

	if (mac == NULL) {
		/* Group key installation */
		(void) memcpy(hk->kv_mic,  key_rxmic, sizeof (hk->kv_mic));
		return (ath9k_hw_set_keycache_entry(ah, k->wk_keyix, hk,
		    mac, B_FALSE));
	}
	if (!sc->sc_splitmic) {
		/*
		 * data key goes at first index,
		 * the hal handles the MIC keys at index+64.
		 */
		(void) memcpy(hk->kv_mic, key_rxmic, sizeof (hk->kv_mic));
		(void) memcpy(hk->kv_txmic, key_txmic, sizeof (hk->kv_txmic));
		return (ath9k_hw_set_keycache_entry(ah, k->wk_keyix, hk,
		    mac, B_FALSE));
	}
	/*
	 * TX key goes at first index, RX key at +32.
	 * The hal handles the MIC keys at index+64.
	 */
	(void) memcpy(hk->kv_mic, key_txmic, sizeof (hk->kv_mic));
	if (!(ath9k_hw_set_keycache_entry(ah, k->wk_keyix, hk, NULL,
	    B_FALSE))) {
		/* Txmic entry failed. No need to proceed further */
		ARN_DBG((ARN_DBG_KEYCACHE,
		    "%s Setting TX MIC Key Failed\n", __func__));
		return (0);
	}

	(void) memcpy(hk->kv_mic, key_rxmic, sizeof (hk->kv_mic));

	/* XXX delete tx key on failure? */
	return (ath9k_hw_set_keycache_entry(ah, k->wk_keyix, hk, mac, B_FALSE));

}

int
arn_key_set(ieee80211com_t *ic, const struct ieee80211_key *k,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct arn_softc *sc = (struct arn_softc *)ic;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	struct ath9k_keyval hk;

	/* cipher table */
	static const uint8_t ciphermap[] = {
		ATH9K_CIPHER_WEP,		/* IEEE80211_CIPHER_WEP */
		ATH9K_CIPHER_TKIP,		/* IEEE80211_CIPHER_TKIP */
		ATH9K_CIPHER_AES_OCB,	/* IEEE80211_CIPHER_AES_OCB */
		ATH9K_CIPHER_AES_CCM,	/* IEEE80211_CIPHER_AES_CCM */
		ATH9K_CIPHER_CKIP,		/* IEEE80211_CIPHER_CKIP */
		ATH9K_CIPHER_CLR,		/* IEEE80211_CIPHER_NONE */
	};

	bzero(&hk, sizeof (hk));

	/*
	 * Software crypto uses a "clear key" so non-crypto
	 * state kept in the key cache are maintainedd so that
	 * rx frames have an entry to match.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) == 0) {
		ASSERT(cip->ic_cipher < 6);
		hk.kv_type = ciphermap[cip->ic_cipher];
		hk.kv_len = k->wk_keylen;
		bcopy(k->wk_key, hk.kv_val, k->wk_keylen);
	} else {
		hk.kv_type = ATH9K_CIPHER_CLR;
	}

	if (hk.kv_type == ATH9K_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0) {
		return (arn_keyset_tkip(sc, k, &hk, mac));
	} else {
		return (ath9k_hw_set_keycache_entry(sc->sc_ah,
		    k->wk_keyix, &hk, mac, B_FALSE));
	}
}

/*
 * Enable/Disable short slot timing
 */
void
arn_set_shortslot(ieee80211com_t *ic, int onoff)
{
	struct ath_hal *ah = ((struct arn_softc *)ic)->sc_ah;

	if (onoff)
		(void) ath9k_hw_setslottime(ah, ATH9K_SLOT_TIME_9);
	else
		(void) ath9k_hw_setslottime(ah, ATH9K_SLOT_TIME_20);
}

static int
arn_open(struct arn_softc *sc)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ieee80211_channel *curchan = ic->ic_curchan;
	struct ath9k_channel *init_channel;
	int error = 0, pos, status;

	ARN_LOCK_ASSERT(sc);

	pos = arn_get_channel(sc, curchan);
	if (pos == -1) {
		ARN_DBG((ARN_DBG_FATAL, "arn: "
		    "%s: Invalid channel\n", __func__));
		error = EINVAL;
		goto error;
	}

	sc->tx_chan_width = ATH9K_HT_MACMODE_20;

	if (sc->sc_curmode == ATH9K_MODE_11A) {
		sc->sc_ah->ah_channels[pos].chanmode = CHANNEL_A;
	} else {
		sc->sc_ah->ah_channels[pos].chanmode = CHANNEL_G;
	}

	init_channel = &sc->sc_ah->ah_channels[pos];

	/* Reset SERDES registers */
	ath9k_hw_configpcipowersave(sc->sc_ah, 0);

	/*
	 * The basic interface to setting the hardware in a good
	 * state is ``reset''.	On return the hardware is known to
	 * be powered up and with interrupts disabled.	This must
	 * be followed by initialization of the appropriate bits
	 * and then setup of the interrupt mask.
	 */
	if (!ath9k_hw_reset(sc->sc_ah, init_channel,
	    sc->tx_chan_width, sc->sc_tx_chainmask,
	    sc->sc_rx_chainmask, sc->sc_ht_extprotspacing,
	    B_FALSE, &status)) {
		ARN_DBG((ARN_DBG_FATAL, "arn: "
		    "%s: unable to reset hardware; hal status %u "
		    "(freq %u flags 0x%x)\n", __func__, status,
		    init_channel->channel, init_channel->channelFlags));

		error = EIO;
		goto error;
	}

	/*
	 * This is needed only to setup initial state
	 * but it's best done after a reset.
	 */
	arn_update_txpow(sc);

	/*
	 * Setup the hardware after reset:
	 * The receive engine is set going.
	 * Frame transmit is handled entirely
	 * in the frame output path; there's nothing to do
	 * here except setup the interrupt mask.
	 */
	if (arn_startrecv(sc) != 0) {
		ARN_DBG((ARN_DBG_INIT, "arn: "
		    "%s: unable to start recv logic\n", __func__));
		error = EIO;
		goto error;
	}

	/* Setup our intr mask. */
	sc->sc_imask = ATH9K_INT_RX | ATH9K_INT_TX |
	    ATH9K_INT_RXEOL | ATH9K_INT_RXORN |
	    ATH9K_INT_FATAL | ATH9K_INT_GLOBAL;
#ifdef ARN_ATH9K_HW_CAP_GTT
	if (sc->sc_ah->ah_caps.hw_caps & ATH9K_HW_CAP_GTT)
		sc->sc_imask |= ATH9K_INT_GTT;
#endif

#ifdef ARN_ATH9K_HW_CAP_GTT
	if (sc->sc_ah->ah_caps.hw_caps & ATH9K_HW_CAP_HT)
		sc->sc_imask |= ATH9K_INT_CST;
#endif

	/*
	 * Enable MIB interrupts when there are hardware phy counters.
	 * Note we only do this (at the moment) for station mode.
	 */
#ifdef ARN_ATH9K_INT_MIB
	if (ath9k_hw_phycounters(sc->sc_ah) &&
	    ((sc->sc_ah->ah_opmode == ATH9K_M_STA) ||
	    (sc->sc_ah->ah_opmode == ATH9K_M_IBSS)))
		sc->sc_imask |= ATH9K_INT_MIB;
#endif
	/*
	 * Some hardware processes the TIM IE and fires an
	 * interrupt when the TIM bit is set.  For hardware
	 * that does, if not overridden by configuration,
	 * enable the TIM interrupt when operating as station.
	 */
#ifdef ARN_ATH9K_INT_TIM
	if ((sc->sc_ah->ah_caps.hw_caps & ATH9K_HW_CAP_ENHANCEDPM) &&
	    (sc->sc_ah->ah_opmode == ATH9K_M_STA) &&
	    !sc->sc_config.swBeaconProcess)
		sc->sc_imask |= ATH9K_INT_TIM;
#endif
	if (arn_chan2mode(init_channel) != sc->sc_curmode)
		arn_setcurmode(sc, arn_chan2mode(init_channel));
	ARN_DBG((ARN_DBG_INIT, "arn: "
	    "%s: current mode after arn_setcurmode is %d\n",
	    __func__, sc->sc_curmode));

	sc->sc_isrunning = 1;

	/* Disable BMISS interrupt when we're not associated */
	sc->sc_imask &= ~(ATH9K_INT_SWBA | ATH9K_INT_BMISS);
	(void) ath9k_hw_set_interrupts(sc->sc_ah, sc->sc_imask);

	return (0);

error:
	return (error);
}

static void
arn_close(struct arn_softc *sc)
{
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ath_hal *ah = sc->sc_ah;

	ARN_LOCK_ASSERT(sc);

	if (!sc->sc_isrunning)
		return;

	/*
	 * Shutdown the hardware and driver
	 * Note that some of this work is not possible if the
	 * hardware is gone (invalid).
	 */
	ARN_UNLOCK(sc);
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);
	ARN_LOCK(sc);

	/*
	 * make sure h/w will not generate any interrupt
	 * before setting the invalid flag.
	 */
	(void) ath9k_hw_set_interrupts(ah, 0);

	if (!(sc->sc_flags & SC_OP_INVALID)) {
		arn_draintxq(sc, 0);
		(void) arn_stoprecv(sc);
		(void) ath9k_hw_phy_disable(ah);
	} else {
		sc->sc_rxlink = NULL;
	}

	sc->sc_isrunning = 0;
}

/*
 * MAC callback functions
 */
static int
arn_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct arn_softc *sc = arg;
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ieee80211_node *in;
	struct ieee80211_rateset *rs;

	ARN_LOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		in = ic->ic_bss;
		rs = &in->in_rates;
		*val = (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL) / 2 *
		    1000000ull;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = sc->sc_stats.ast_tx_nobuf +
		    sc->sc_stats.ast_tx_nobufmgt;
		break;
	case MAC_STAT_IERRORS:
		*val = sc->sc_stats.ast_rx_tooshort;
		break;
	case MAC_STAT_RBYTES:
		*val = ic->ic_stats.is_rx_bytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = ic->ic_stats.is_rx_frags;
		break;
	case MAC_STAT_OBYTES:
		*val = ic->ic_stats.is_tx_bytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = ic->ic_stats.is_tx_frags;
		break;
	case MAC_STAT_OERRORS:
	case WIFI_STAT_TX_FAILED:
		*val = sc->sc_stats.ast_tx_fifoerr +
		    sc->sc_stats.ast_tx_xretries +
		    sc->sc_stats.ast_tx_discard;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = sc->sc_stats.ast_tx_xretries;
		break;
	case WIFI_STAT_FCS_ERRORS:
		*val = sc->sc_stats.ast_rx_crcerr;
		break;
	case WIFI_STAT_WEP_ERRORS:
		*val = sc->sc_stats.ast_rx_badcrypt;
		break;
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		ARN_UNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		ARN_UNLOCK(sc);
		return (ENOTSUP);
	}
	ARN_UNLOCK(sc);

	return (0);
}

int
arn_m_start(void *arg)
{
	struct arn_softc *sc = arg;
	int err = 0;

	ARN_LOCK(sc);

	/*
	 * Stop anything previously setup.  This is safe
	 * whether this is the first time through or not.
	 */

	arn_close(sc);

	if ((err = arn_open(sc)) != 0) {
		ARN_UNLOCK(sc);
		return (err);
	}

	/* H/W is reday now */
	sc->sc_flags &= ~SC_OP_INVALID;

	ARN_UNLOCK(sc);

	return (0);
}

static void
arn_m_stop(void *arg)
{
	struct arn_softc *sc = arg;

	ARN_LOCK(sc);
	arn_close(sc);

	/* disable HAL and put h/w to sleep */
	(void) ath9k_hw_disable(sc->sc_ah);
	ath9k_hw_configpcipowersave(sc->sc_ah, 1);

	/* XXX: hardware will not be ready in suspend state */
	sc->sc_flags |= SC_OP_INVALID;
	ARN_UNLOCK(sc);
}

static int
arn_m_promisc(void *arg, boolean_t on)
{
	struct arn_softc *sc = arg;
	struct ath_hal *ah = sc->sc_ah;
	uint32_t rfilt;

	ARN_LOCK(sc);

	rfilt = ath9k_hw_getrxfilter(ah);
	if (on)
		rfilt |= ATH9K_RX_FILTER_PROM;
	else
		rfilt &= ~ATH9K_RX_FILTER_PROM;
	sc->sc_promisc = on;
	ath9k_hw_setrxfilter(ah, rfilt);

	ARN_UNLOCK(sc);

	return (0);
}

static int
arn_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	struct arn_softc *sc = arg;
	struct ath_hal *ah = sc->sc_ah;
	uint32_t val, index, bit;
	uint8_t pos;
	uint32_t *mfilt = sc->sc_mcast_hash;

	ARN_LOCK(sc);

	/* calculate XOR of eight 6bit values */
	val = ARN_LE_READ_32(mca + 0);
	pos = (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
	val = ARN_LE_READ_32(mca + 3);
	pos ^= (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
	pos &= 0x3f;
	index = pos / 32;
	bit = 1 << (pos % 32);

	if (add) {	/* enable multicast */
		sc->sc_mcast_refs[pos]++;
		mfilt[index] |= bit;
	} else {	/* disable multicast */
		if (--sc->sc_mcast_refs[pos] == 0)
			mfilt[index] &= ~bit;
	}
	ath9k_hw_setmcastfilter(ah, mfilt[0], mfilt[1]);

	ARN_UNLOCK(sc);
	return (0);
}

static int
arn_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct arn_softc *sc = arg;
	struct ath_hal *ah = sc->sc_ah;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	ARN_DBG((ARN_DBG_XMIT, "ath: ath_gld_saddr(): "
	    "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	    macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]));

	ARN_LOCK(sc);
	IEEE80211_ADDR_COPY(sc->sc_isc.ic_macaddr, macaddr);
	(void) ath9k_hw_setmac(ah, sc->sc_isc.ic_macaddr);
	(void) arn_reset(ic);
	ARN_UNLOCK(sc);
	return (0);
}

static mblk_t *
arn_m_tx(void *arg, mblk_t *mp)
{
	struct arn_softc *sc = arg;
	int error = 0;
	mblk_t *next;
	ieee80211com_t *ic = (ieee80211com_t *)sc;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		ARN_DBG((ARN_DBG_XMIT, "arn: arn_m_tx(): "
		    "discard, state %u\n", ic->ic_state));
		sc->sc_stats.ast_tx_discard++;
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		error = arn_tx(ic, mp, IEEE80211_FC0_TYPE_DATA);
		if (error != 0) {
			mp->b_next = next;
			if (error == ENOMEM) {
				break;
			} else {
				freemsgchain(mp);
				return (NULL);
			}
		}
		mp = next;
	}

	return (mp);
}

static void
arn_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct arn_softc *sc = arg;
	int32_t err;

	err = ieee80211_ioctl(&sc->sc_isc, wq, mp);

	ARN_LOCK(sc);
	if (err == ENETRESET) {
		if (!(sc->sc_flags & SC_OP_INVALID)) {
			ARN_UNLOCK(sc);

			(void) arn_m_start(sc);

			(void) ieee80211_new_state(&sc->sc_isc,
			    IEEE80211_S_SCAN, -1);
			ARN_LOCK(sc);
		}
	}
	ARN_UNLOCK(sc);
}

static int
arn_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct arn_softc *sc = arg;
	int	err;

	err = ieee80211_setprop(&sc->sc_isc, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	ARN_LOCK(sc);

	if (err == ENETRESET) {
		if (!(sc->sc_flags & SC_OP_INVALID)) {
			ARN_UNLOCK(sc);
			(void) arn_m_start(sc);
			(void) ieee80211_new_state(&sc->sc_isc,
			    IEEE80211_S_SCAN, -1);
			ARN_LOCK(sc);
		}
		err = 0;
	}

	ARN_UNLOCK(sc);

	return (err);
}

/* ARGSUSED */
static int
arn_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct arn_softc *sc = arg;
	int	err = 0;

	err = ieee80211_getprop(&sc->sc_isc, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
arn_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct arn_softc *sc = arg;

	ieee80211_propinfo(&sc->sc_isc, pr_name, wldp_pr_num, prh);
}

/* return bus cachesize in 4B word units */
static void
arn_pci_config_cachesize(struct arn_softc *sc)
{
	uint8_t csz;

	/*
	 * Cache line size is used to size and align various
	 * structures used to communicate with the hardware.
	 */
	csz = pci_config_get8(sc->sc_cfg_handle, PCI_CONF_CACHE_LINESZ);
	if (csz == 0) {
		/*
		 * We must have this setup properly for rx buffer
		 * DMA to work so force a reasonable value here if it
		 * comes up zero.
		 */
		csz = ATH_DEF_CACHE_BYTES / sizeof (uint32_t);
		pci_config_put8(sc->sc_cfg_handle, PCI_CONF_CACHE_LINESZ,
		    csz);
	}
	sc->sc_cachelsz = csz << 2;
}

static int
arn_pci_setup(struct arn_softc *sc)
{
	uint16_t command;

	/*
	 * Enable memory mapping and bus mastering
	 */
	ASSERT(sc != NULL);
	command = pci_config_get16(sc->sc_cfg_handle, PCI_CONF_COMM);
	command	|= PCI_COMM_MAE | PCI_COMM_ME;
	pci_config_put16(sc->sc_cfg_handle, PCI_CONF_COMM, command);
	command = pci_config_get16(sc->sc_cfg_handle, PCI_CONF_COMM);
	if ((command & PCI_COMM_MAE) == 0) {
		arn_problem("arn: arn_pci_setup(): "
		    "failed to enable memory mapping\n");
		return (EIO);
	}
	if ((command & PCI_COMM_ME) == 0) {
		arn_problem("arn: arn_pci_setup(): "
		    "failed to enable bus mastering\n");
		return (EIO);
	}
	ARN_DBG((ARN_DBG_INIT, "arn: arn_pci_setup(): "
	    "set command reg to 0x%x \n", command));

	return (0);
}

static void
arn_get_hw_encap(struct arn_softc *sc)
{
	ieee80211com_t *ic;
	struct ath_hal *ah;

	ic = (ieee80211com_t *)sc;
	ah = sc->sc_ah;

	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_AES_CCM, NULL))
		ic->ic_caps |= IEEE80211_C_AES_CCM;
	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_AES_OCB, NULL))
		ic->ic_caps |= IEEE80211_C_AES;
	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_TKIP, NULL))
		ic->ic_caps |= IEEE80211_C_TKIP;
	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_WEP, NULL))
		ic->ic_caps |= IEEE80211_C_WEP;
	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_MIC, NULL))
		ic->ic_caps |= IEEE80211_C_TKIPMIC;
}

static void
arn_setup_ht_cap(struct arn_softc *sc)
{
#define	ATH9K_HT_CAP_MAXRXAMPDU_65536 0x3	/* 2 ^ 16 */
#define	ATH9K_HT_CAP_MPDUDENSITY_8 0x6		/* 8 usec */

	uint8_t rx_streams;

	arn_ht_conf *ht_info = &sc->sc_ht_conf;

	ht_info->ht_supported = B_TRUE;

	/* Todo: IEEE80211_HTCAP_SMPS */
	ht_info->cap = IEEE80211_HTCAP_CHWIDTH40|
	    IEEE80211_HTCAP_SHORTGI40 |
	    IEEE80211_HTCAP_DSSSCCK40;

	ht_info->ampdu_factor = ATH9K_HT_CAP_MAXRXAMPDU_65536;
	ht_info->ampdu_density = ATH9K_HT_CAP_MPDUDENSITY_8;

	/* set up supported mcs set */
	(void) memset(&ht_info->rx_mcs_mask, 0, sizeof (ht_info->rx_mcs_mask));
	rx_streams = ISP2(sc->sc_ah->ah_caps.rx_chainmask) ? 1 : 2;

	ht_info->rx_mcs_mask[0] = 0xff;
	if (rx_streams >= 2)
		ht_info->rx_mcs_mask[1] = 0xff;
}

/* xxx should be used for ht rate set negotiating ? */
static void
arn_overwrite_11n_rateset(struct arn_softc *sc)
{
	uint8_t *ht_rs = sc->sc_ht_conf.rx_mcs_mask;
	int mcs_idx, mcs_count = 0;
	int i, j;

	(void) memset(&ieee80211_rateset_11n, 0,
	    sizeof (ieee80211_rateset_11n));
	for (i = 0; i < 10; i++) {
		for (j = 0; j < 8; j++) {
			if (ht_rs[i] & (1 << j)) {
				mcs_idx = i * 8 + j;
				if (mcs_idx >= IEEE80211_HTRATE_MAXSIZE) {
					break;
				}

				ieee80211_rateset_11n.rs_rates[mcs_idx] =
				    (uint8_t)mcs_idx;
				mcs_count++;
			}
		}
	}

	ieee80211_rateset_11n.rs_nrates = (uint8_t)mcs_count;

	ARN_DBG((ARN_DBG_RATE, "arn_overwrite_11n_rateset(): "
	    "MCS rate set supported by this station is as follows:\n"));

	for (i = 0; i < ieee80211_rateset_11n.rs_nrates; i++) {
		ARN_DBG((ARN_DBG_RATE, "MCS rate %d is %d\n",
		    i, ieee80211_rateset_11n.rs_rates[i]));
	}

}

/*
 * Update WME parameters for a transmit queue.
 */
static int
arn_tx_queue_update(struct arn_softc *sc, int ac)
{
#define	ATH_EXPONENT_TO_VALUE(v)	((1<<v)-1)
#define	ATH_TXOP_TO_US(v)		(v<<5)
	ieee80211com_t *ic = (ieee80211com_t *)sc;
	struct ath_txq *txq;
	struct wmeParams *wmep = &ic->ic_wme.wme_chanParams.cap_wmeParams[ac];
	struct ath_hal *ah = sc->sc_ah;
	struct ath9k_tx_queue_info qi;

	txq = &sc->sc_txq[arn_get_hal_qnum(ac, sc)];
	(void) ath9k_hw_get_txq_props(ah, txq->axq_qnum, &qi);

	/*
	 * TXQ_FLAG_TXOKINT_ENABLE = 0x0001
	 * TXQ_FLAG_TXERRINT_ENABLE = 0x0001
	 * TXQ_FLAG_TXDESCINT_ENABLE = 0x0002
	 * TXQ_FLAG_TXEOLINT_ENABLE = 0x0004
	 * TXQ_FLAG_TXURNINT_ENABLE = 0x0008
	 * TXQ_FLAG_BACKOFF_DISABLE = 0x0010
	 * TXQ_FLAG_COMPRESSION_ENABLE = 0x0020
	 * TXQ_FLAG_RDYTIME_EXP_POLICY_ENABLE = 0x0040
	 * TXQ_FLAG_FRAG_BURST_BACKOFF_ENABLE = 0x0080
	 */

	/* xxx should update these flags here? */
#if 0
	qi.tqi_qflags = TXQ_FLAG_TXOKINT_ENABLE |
	    TXQ_FLAG_TXERRINT_ENABLE |
	    TXQ_FLAG_TXDESCINT_ENABLE |
	    TXQ_FLAG_TXURNINT_ENABLE;
#endif

	qi.tqi_aifs = wmep->wmep_aifsn;
	qi.tqi_cwmin = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmin);
	qi.tqi_cwmax = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmax);
	qi.tqi_readyTime = 0;
	qi.tqi_burstTime = ATH_TXOP_TO_US(wmep->wmep_txopLimit);

	ARN_DBG((ARN_DBG_INIT,
	    "%s:"
	    "Q%u"
	    "qflags 0x%x"
	    "aifs %u"
	    "cwmin %u"
	    "cwmax %u"
	    "burstTime %u\n",
	    __func__,
	    txq->axq_qnum,
	    qi.tqi_qflags,
	    qi.tqi_aifs,
	    qi.tqi_cwmin,
	    qi.tqi_cwmax,
	    qi.tqi_burstTime));

	if (!ath9k_hw_set_txq_props(ah, txq->axq_qnum, &qi)) {
		arn_problem("unable to update hardware queue "
		    "parameters for %s traffic!\n",
		    ieee80211_wme_acnames[ac]);
		return (0);
	} else {
		/* push to H/W */
		(void) ath9k_hw_resettxqueue(ah, txq->axq_qnum);
		return (1);
	}

#undef ATH_TXOP_TO_US
#undef ATH_EXPONENT_TO_VALUE
}

/* Update WME parameters */
static int
arn_wme_update(ieee80211com_t *ic)
{
	struct arn_softc *sc = (struct arn_softc *)ic;

	/* updateing */
	return (!arn_tx_queue_update(sc, WME_AC_BE) ||
	    !arn_tx_queue_update(sc, WME_AC_BK) ||
	    !arn_tx_queue_update(sc, WME_AC_VI) ||
	    !arn_tx_queue_update(sc, WME_AC_VO) ? EIO : 0);
}

/*
 * Update tx/rx chainmask. For legacy association,
 * hard code chainmask to 1x1, for 11n association, use
 * the chainmask configuration.
 */
void
arn_update_chainmask(struct arn_softc *sc)
{
	boolean_t is_ht = B_FALSE;
	sc->sc_flags |= SC_OP_CHAINMASK_UPDATE;

	is_ht = sc->sc_ht_conf.ht_supported;
	if (is_ht) {
		sc->sc_tx_chainmask = sc->sc_ah->ah_caps.tx_chainmask;
		sc->sc_rx_chainmask = sc->sc_ah->ah_caps.rx_chainmask;
	} else {
		sc->sc_tx_chainmask = 1;
		sc->sc_rx_chainmask = 1;
	}

	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
	    "tx_chainmask = %d, rx_chainmask = %d\n",
	    sc->sc_tx_chainmask, sc->sc_rx_chainmask));
}

static int
arn_resume(dev_info_t *devinfo)
{
	struct arn_softc *sc;
	int ret = DDI_SUCCESS;

	sc = ddi_get_soft_state(arn_soft_state_p, ddi_get_instance(devinfo));
	if (sc == NULL) {
		ARN_DBG((ARN_DBG_INIT, "ath: ath_resume(): "
		    "failed to get soft state\n"));
		return (DDI_FAILURE);
	}

	ARN_LOCK(sc);
	/*
	 * Set up config space command register(s). Refuse
	 * to resume on failure.
	 */
	if (arn_pci_setup(sc) != 0) {
		ARN_DBG((ARN_DBG_INIT, "ath: ath_resume(): "
		    "ath_pci_setup() failed\n"));
		ARN_UNLOCK(sc);
		return (DDI_FAILURE);
	}

	if (!(sc->sc_flags & SC_OP_INVALID))
		ret = arn_open(sc);
	ARN_UNLOCK(sc);

	return (ret);
}

static int
arn_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct arn_softc *sc;
	int		instance;
	int		status;
	int32_t		err;
	uint16_t	vendor_id;
	uint16_t	device_id;
	uint32_t	i;
	uint32_t	val;
	char		strbuf[32];
	ieee80211com_t *ic;
	struct ath_hal *ah;
	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (arn_resume(devinfo));
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);
	if (ddi_soft_state_zalloc(arn_soft_state_p, instance) != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: "
		    "%s: Unable to alloc softstate\n", __func__));
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(arn_soft_state_p, ddi_get_instance(devinfo));
	ic = (ieee80211com_t *)sc;
	sc->sc_dev = devinfo;

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_serial_rw, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txbuflock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxbuflock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_resched_lock, NULL, MUTEX_DRIVER, NULL);
#ifdef ARN_IBSS
	mutex_init(&sc->sc_bcbuflock, NULL, MUTEX_DRIVER, NULL);
#endif

	sc->sc_flags |= SC_OP_INVALID;

	err = pci_config_setup(devinfo, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "pci_config_setup() failed"));
		goto attach_fail0;
	}

	if (arn_pci_setup(sc) != 0)
		goto attach_fail1;

	/* Cache line size set up */
	arn_pci_config_cachesize(sc);

	vendor_id = pci_config_get16(sc->sc_cfg_handle, PCI_CONF_VENID);
	device_id = pci_config_get16(sc->sc_cfg_handle, PCI_CONF_DEVID);
	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): vendor 0x%x, "
	    "device id 0x%x, cache size %d\n",
	    vendor_id, device_id,
	    pci_config_get8(sc->sc_cfg_handle, PCI_CONF_CACHE_LINESZ)));

	pci_config_put8(sc->sc_cfg_handle, PCI_CONF_LATENCY_TIMER, 0xa8);
	val = pci_config_get32(sc->sc_cfg_handle, 0x40);
	if ((val & 0x0000ff00) != 0)
		pci_config_put32(sc->sc_cfg_handle, 0x40, val & 0xffff00ff);

	err = ddi_regs_map_setup(devinfo, 1,
	    &sc->mem, 0, 0, &arn_reg_accattr, &sc->sc_io_handle);
	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
	    "regs map1 = %x err=%d\n", sc->mem, err));
	if (err != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "ddi_regs_map_setup() failed"));
		goto attach_fail1;
	}

	ah = ath9k_hw_attach(device_id, sc, sc->mem, &status);
	if (ah == NULL) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to attach hw: H/W status %u\n",
		    status));
		goto attach_fail2;
	}
	sc->sc_ah = ah;

	ath9k_hw_getmac(ah, ic->ic_macaddr);

	/* Get the hardware key cache size. */
	sc->sc_keymax = ah->ah_caps.keycache_size;
	if (sc->sc_keymax > ATH_KEYMAX) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "Warning, using only %u entries in %u key cache\n",
		    ATH_KEYMAX, sc->sc_keymax));
		sc->sc_keymax = ATH_KEYMAX;
	}

	/*
	 * Reset the key cache since some parts do not
	 * reset the contents on initial power up.
	 */
	for (i = 0; i < sc->sc_keymax; i++)
		(void) ath9k_hw_keyreset(ah, (uint16_t)i);
	/*
	 * Mark key cache slots associated with global keys
	 * as in use.  If we knew TKIP was not to be used we
	 * could leave the +32, +64, and +32+64 slots free.
	 * XXX only for splitmic.
	 */
	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		set_bit(i, sc->sc_keymap);
		set_bit(i + 32, sc->sc_keymap);
		set_bit(i + 64, sc->sc_keymap);
		set_bit(i + 32 + 64, sc->sc_keymap);
	}

	/* Collect the channel list using the default country code */
	err = arn_setup_channels(sc);
	if (err == EINVAL) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "ERR:arn_setup_channels\n"));
		goto attach_fail3;
	}

	/* default to STA mode */
	sc->sc_ah->ah_opmode = ATH9K_M_STA;

	/* Setup rate tables */
	arn_rate_attach(sc);
	arn_setup_rates(sc, IEEE80211_MODE_11A);
	arn_setup_rates(sc, IEEE80211_MODE_11B);
	arn_setup_rates(sc, IEEE80211_MODE_11G);

	/* Setup current mode here */
	arn_setcurmode(sc, ATH9K_MODE_11G);

	/* 802.11g features */
	if (sc->sc_have11g)
		ic->ic_caps |= IEEE80211_C_SHPREAMBLE |
		    IEEE80211_C_SHSLOT;		/* short slot time */

	/* Temp workaround */
	sc->sc_mrretry = 1;
	sc->sc_config.ath_aggr_prot = 0;

	/* Setup tx/rx descriptors */
	err = arn_desc_alloc(devinfo, sc);
	if (err != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "failed to allocate descriptors: %d\n", err));
		goto attach_fail3;
	}

	if ((sc->sc_tq = ddi_taskq_create(devinfo, "ath_taskq", 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "ERR:ddi_taskq_create\n"));
		goto attach_fail4;
	}

	/*
	 * Allocate hardware transmit queues: one queue for
	 * beacon frames and one data queue for each QoS
	 * priority.  Note that the hal handles reseting
	 * these queues at the needed time.
	 */
#ifdef ARN_IBSS
	sc->sc_beaconq = arn_beaconq_setup(ah);
	if (sc->sc_beaconq == (-1)) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to setup a beacon xmit queue\n"));
		goto attach_fail4;
	}
#endif
#ifdef ARN_HOSTAP
	sc->sc_cabq = arn_txq_setup(sc, ATH9K_TX_QUEUE_CAB, 0);
	if (sc->sc_cabq == NULL) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to setup CAB xmit queue\n"));
		goto attach_fail4;
	}

	sc->sc_config.cabqReadytime = ATH_CABQ_READY_TIME;
	ath_cabq_update(sc);
#endif

	for (i = 0; i < ARRAY_SIZE(sc->sc_haltype2q); i++)
		sc->sc_haltype2q[i] = -1;

	/* Setup data queues */
	/* NB: ensure BK queue is the lowest priority h/w queue */
	if (!arn_tx_setup(sc, ATH9K_WME_AC_BK)) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to setup xmit queue for BK traffic\n"));
		goto attach_fail4;
	}
	if (!arn_tx_setup(sc, ATH9K_WME_AC_BE)) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to setup xmit queue for BE traffic\n"));
		goto attach_fail4;
	}
	if (!arn_tx_setup(sc, ATH9K_WME_AC_VI)) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to setup xmit queue for VI traffic\n"));
		goto attach_fail4;
	}
	if (!arn_tx_setup(sc, ATH9K_WME_AC_VO)) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "unable to setup xmit queue for VO traffic\n"));
		goto attach_fail4;
	}

	/*
	 * Initializes the noise floor to a reasonable default value.
	 * Later on this will be updated during ANI processing.
	 */

	sc->sc_ani.sc_noise_floor = ATH_DEFAULT_NOISE_FLOOR;


	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_TKIP, NULL)) {
		/*
		 * Whether we should enable h/w TKIP MIC.
		 * XXX: if we don't support WME TKIP MIC, then we wouldn't
		 * report WMM capable, so it's always safe to turn on
		 * TKIP MIC in this case.
		 */
		(void) ath9k_hw_setcapability(sc->sc_ah, ATH9K_CAP_TKIP_MIC,
		    0, 1, NULL);
	}

	/* Get cipher releated capability information */
	arn_get_hw_encap(sc);

	/*
	 * Check whether the separate key cache entries
	 * are required to handle both tx+rx MIC keys.
	 * With split mic keys the number of stations is limited
	 * to 27 otherwise 59.
	 */
	if (ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_TKIP, NULL) &&
	    ath9k_hw_getcapability(ah, ATH9K_CAP_CIPHER,
	    ATH9K_CIPHER_MIC, NULL) &&
	    ath9k_hw_getcapability(ah, ATH9K_CAP_TKIP_SPLIT,
	    0, NULL))
		sc->sc_splitmic = 1;

	/* turn on mcast key search if possible */
	if (!ath9k_hw_getcapability(ah, ATH9K_CAP_MCAST_KEYSRCH, 0, NULL))
		(void) ath9k_hw_setcapability(ah, ATH9K_CAP_MCAST_KEYSRCH, 1,
		    1, NULL);

	sc->sc_config.txpowlimit = ATH_TXPOWER_MAX;
	sc->sc_config.txpowlimit_override = 0;

	/* 11n Capabilities */
	if (ah->ah_caps.hw_caps & ATH9K_HW_CAP_HT) {
		sc->sc_flags |= SC_OP_TXAGGR;
		sc->sc_flags |= SC_OP_RXAGGR;
		arn_setup_ht_cap(sc);
		arn_overwrite_11n_rateset(sc);
	}

	sc->sc_tx_chainmask = 1;
	sc->sc_rx_chainmask = 1;
	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
	    "tx_chainmask = %d, rx_chainmask = %d\n",
	    sc->sc_tx_chainmask, sc->sc_rx_chainmask));

	/* arn_update_chainmask(sc); */

	(void) ath9k_hw_setcapability(ah, ATH9K_CAP_DIVERSITY, 1, B_TRUE, NULL);
	sc->sc_defant = ath9k_hw_getdefantenna(ah);

	ath9k_hw_getmac(ah, sc->sc_myaddr);
	if (ah->ah_caps.hw_caps & ATH9K_HW_CAP_BSSIDMASK) {
		ath9k_hw_getbssidmask(ah, sc->sc_bssidmask);
		ATH_SET_VAP_BSSID_MASK(sc->sc_bssidmask);
		(void) ath9k_hw_setbssidmask(ah, sc->sc_bssidmask);
	}

	/* set default value to short slot time */
	sc->sc_slottime = ATH9K_SLOT_TIME_9;
	(void) ath9k_hw_setslottime(ah, ATH9K_SLOT_TIME_9);

	/* initialize beacon slots */
	for (i = 0; i < ARRAY_SIZE(sc->sc_bslot); i++)
		sc->sc_bslot[i] = ATH_IF_ID_ANY;

	/* Save MISC configurations */
	sc->sc_config.swBeaconProcess = 1;

	/* Support QoS/WME */
	ic->ic_caps |= IEEE80211_C_WME;
	ic->ic_wme.wme_update = arn_wme_update;

	/* Support 802.11n/HT */
	if (sc->sc_ht_conf.ht_supported) {
		ic->ic_htcaps =
		    IEEE80211_HTCAP_CHWIDTH40 |
		    IEEE80211_HTCAP_SHORTGI40 |
		    IEEE80211_HTCAP_DSSSCCK40 |
		    IEEE80211_HTCAP_MAXAMSDU_7935 |
		    IEEE80211_HTC_HT |
		    IEEE80211_HTC_AMSDU |
		    IEEE80211_HTCAP_RXSTBC_2STREAM;

#ifdef ARN_TX_AGGREGATION
	ic->ic_htcaps |= IEEE80211_HTC_AMPDU;
#endif
	}

	/* Header padding requested by driver */
	ic->ic_flags |= IEEE80211_F_DATAPAD;
	/* Support WPA/WPA2 */
	ic->ic_caps |= IEEE80211_C_WPA;
#if 0
	ic->ic_caps |= IEEE80211_C_TXFRAG; /* handle tx frags */
	ic->ic_caps |= IEEE80211_C_BGSCAN; /* capable of bg scanning */
#endif
	ic->ic_phytype = IEEE80211_T_HT;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_state = IEEE80211_S_INIT;
	ic->ic_maxrssi = ARN_MAX_RSSI;
	ic->ic_set_shortslot = arn_set_shortslot;
	ic->ic_xmit = arn_tx;
	ieee80211_attach(ic);

	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
	    "ic->ic_curchan->ich_freq: %d\n", ic->ic_curchan->ich_freq));

	/* different instance has different WPA door */
	(void) snprintf(ic->ic_wpadoor, MAX_IEEE80211STR, "%s_%s%d", WPA_DOOR,
	    ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	if (sc->sc_ht_conf.ht_supported) {
		sc->sc_recv_action = ic->ic_recv_action;
		ic->ic_recv_action = arn_ampdu_recv_action;
		// sc->sc_send_action = ic->ic_send_action;
		// ic->ic_send_action = arn_ampdu_send_action;

		ic->ic_ampdu_rxmax = sc->sc_ht_conf.ampdu_factor;
		ic->ic_ampdu_density = sc->sc_ht_conf.ampdu_density;
		ic->ic_ampdu_limit = ic->ic_ampdu_rxmax;
	}

	/* Override 80211 default routines */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = arn_newstate;
#ifdef ARN_IBSS
	sc->sc_recv_mgmt = ic->ic_recv_mgmt;
	ic->ic_recv_mgmt = arn_recv_mgmt;
#endif
	ic->ic_watchdog = arn_watchdog;
	ic->ic_node_alloc = arn_node_alloc;
	ic->ic_node_free = arn_node_free;
	ic->ic_crypto.cs_key_alloc = arn_key_alloc;
	ic->ic_crypto.cs_key_delete = arn_key_delete;
	ic->ic_crypto.cs_key_set = arn_key_set;

	ieee80211_media_init(ic);

	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	sc->sc_rx_pend = 0;
	(void) ath9k_hw_set_interrupts(sc->sc_ah, 0);
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW,
	    &sc->sc_softint_id, NULL, 0, arn_softint_handler, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "ddi_add_softintr() failed....\n"));
		goto attach_fail5;
	}

	if (ddi_get_iblock_cookie(devinfo, 0, &sc->sc_iblock)
	    != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "Can not get iblock cookie for INT\n"));
		goto attach_fail6;
	}

	if (ddi_add_intr(devinfo, 0, NULL, NULL, arn_isr,
	    (caddr_t)sc) != DDI_SUCCESS) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "Can not set intr for ARN driver\n"));
		goto attach_fail6;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
	    "IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid)"
	    "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	    wd.wd_bssid[0], wd.wd_bssid[1], wd.wd_bssid[2],
	    wd.wd_bssid[3], wd.wd_bssid[4], wd.wd_bssid[5]));

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "MAC version mismatch\n"));
		goto attach_fail7;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &arn_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
		    "mac_register err %x\n", err));
		goto attach_fail7;
	}

	/* Create minor node of type DDI_NT_NET_WIFI */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    ARN_NODENAME, instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		ARN_DBG((ARN_DBG_ATTACH, "WARN: arn: arn_attach(): "
		    "Create minor node failed - %d\n", err));

	/* Notify link is down now */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	sc->sc_promisc = B_FALSE;
	bzero(sc->sc_mcast_refs, sizeof (sc->sc_mcast_refs));
	bzero(sc->sc_mcast_hash, sizeof (sc->sc_mcast_hash));

	ARN_DBG((ARN_DBG_ATTACH, "arn: arn_attach(): "
	    "Atheros AR%s MAC/BB Rev:%x "
	    "AR%s RF Rev:%x: mem=0x%lx\n",
	    arn_mac_bb_name(ah->ah_macVersion),
	    ah->ah_macRev,
	    arn_rf_name((ah->ah_analog5GhzRev & AR_RADIO_SREV_MAJOR)),
	    ah->ah_phyRev,
	    (unsigned long)sc->mem));

	/* XXX: hardware will not be ready until arn_open() being called */
	sc->sc_flags |= SC_OP_INVALID;
	sc->sc_isrunning = 0;

	return (DDI_SUCCESS);

attach_fail7:
	ddi_remove_intr(devinfo, 0, sc->sc_iblock);
attach_fail6:
	ddi_remove_softintr(sc->sc_softint_id);
attach_fail5:
	(void) ieee80211_detach(ic);
attach_fail4:
	arn_desc_free(sc);
	if (sc->sc_tq)
		ddi_taskq_destroy(sc->sc_tq);
attach_fail3:
	ath9k_hw_detach(ah);
attach_fail2:
	ddi_regs_map_free(&sc->sc_io_handle);
attach_fail1:
	pci_config_teardown(&sc->sc_cfg_handle);
attach_fail0:
	sc->sc_flags |= SC_OP_INVALID;
	/* cleanup tx queues */
	mutex_destroy(&sc->sc_txbuflock);
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i)) {
			/* arn_tx_cleanupq(asc, &asc->sc_txq[i]); */
			mutex_destroy(&((&sc->sc_txq[i])->axq_lock));
		}
	}
	mutex_destroy(&sc->sc_rxbuflock);
	mutex_destroy(&sc->sc_serial_rw);
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_resched_lock);
#ifdef ARN_IBSS
	mutex_destroy(&sc->sc_bcbuflock);
#endif

	ddi_soft_state_free(arn_soft_state_p, instance);

	return (DDI_FAILURE);

}

/*
 * Suspend transmit/receive for powerdown
 */
static int
arn_suspend(struct arn_softc *sc)
{
	ARN_LOCK(sc);
	arn_close(sc);
	ARN_UNLOCK(sc);

	return (DDI_SUCCESS);
}

static int32_t
arn_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct arn_softc *sc;
	int i;

	sc = ddi_get_soft_state(arn_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (arn_suspend(sc));

	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_isc.ic_mach) != 0)
		return (DDI_FAILURE);

	arn_stop_scantimer(sc);
	arn_stop_caltimer(sc);

	/* disable interrupts */
	(void) ath9k_hw_set_interrupts(sc->sc_ah, 0);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_isc.ic_mach);

	/* free intterrupt resources */
	ddi_remove_intr(devinfo, 0, sc->sc_iblock);
	ddi_remove_softintr(sc->sc_softint_id);

	/*
	 * NB: the order of these is important:
	 * o call the 802.11 layer before detaching the hal to
	 *   insure callbacks into the driver to delete global
	 *   key cache entries can be handled
	 * o reclaim the tx queue data structures after calling
	 *   the 802.11 layer as we'll get called back to reclaim
	 *   node state and potentially want to use them
	 * o to cleanup the tx queues the hal is called, so detach
	 *   it last
	 */
	ieee80211_detach(&sc->sc_isc);

	arn_desc_free(sc);

	ddi_taskq_destroy(sc->sc_tq);

	if (!(sc->sc_flags & SC_OP_INVALID))
		(void) ath9k_hw_setpower(sc->sc_ah, ATH9K_PM_AWAKE);

	/* cleanup tx queues */
	mutex_destroy(&sc->sc_txbuflock);
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i)) {
			arn_tx_cleanupq(sc, &sc->sc_txq[i]);
			mutex_destroy(&((&sc->sc_txq[i])->axq_lock));
		}
	}

	ath9k_hw_detach(sc->sc_ah);

	/* free io handle */
	ddi_regs_map_free(&sc->sc_io_handle);
	pci_config_teardown(&sc->sc_cfg_handle);

	/* destroy locks */
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_serial_rw);
	mutex_destroy(&sc->sc_rxbuflock);
	mutex_destroy(&sc->sc_resched_lock);
#ifdef ARN_IBSS
	mutex_destroy(&sc->sc_bcbuflock);
#endif

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(arn_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int32_t
arn_quiesce(dev_info_t *devinfo)
{
	struct arn_softc *sc;
	int i;
	struct ath_hal *ah;

	sc = ddi_get_soft_state(arn_soft_state_p, ddi_get_instance(devinfo));

	if (sc == NULL || (ah = sc->sc_ah) == NULL)
		return (DDI_FAILURE);

	/*
	 * Disable interrupts
	 */
	(void) ath9k_hw_set_interrupts(ah, 0);

	/*
	 * Disable TX HW
	 */
	for (i = 0; i < ATH9K_NUM_TX_QUEUES; i++) {
		if (ARN_TXQ_SETUP(sc, i))
			(void) ath9k_hw_stoptxdma(ah, sc->sc_txq[i].axq_qnum);
	}

	/*
	 * Disable RX HW
	 */
	ath9k_hw_stoppcurecv(ah);
	ath9k_hw_setrxfilter(ah, 0);
	(void) ath9k_hw_stopdmarecv(ah);
	drv_usecwait(3000);

	/*
	 * Power down HW
	 */
	(void) ath9k_hw_phy_disable(ah);

	return (DDI_SUCCESS);
}

DDI_DEFINE_STREAM_OPS(arn_dev_ops, nulldev, nulldev, arn_attach, arn_detach,
    nodev, NULL, D_MP, NULL, arn_quiesce);

static struct modldrv arn_modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"Atheros 9000 series driver", /* short description */
	&arn_dev_ops /* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&arn_modldrv, NULL
};

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init
	    (&arn_soft_state_p, sizeof (struct arn_softc), 1);
	if (status != 0)
		return (status);

	mutex_init(&arn_loglock, NULL, MUTEX_DRIVER, NULL);
	mac_init_ops(&arn_dev_ops, "arn");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&arn_dev_ops);
		mutex_destroy(&arn_loglock);
		ddi_soft_state_fini(&arn_soft_state_p);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&arn_dev_ops);
		mutex_destroy(&arn_loglock);
		ddi_soft_state_fini(&arn_soft_state_p);
	}
	return (status);
}
