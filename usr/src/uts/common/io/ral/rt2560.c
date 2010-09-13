/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2005, 2006
 *	Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

/*
 * Ralink Technology RT2560 chipset driver
 * http://www.ralinktech.com/
 */

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <inet/common.h>
#include <sys/note.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>

#include "ral_rate.h"
#include "rt2560_reg.h"
#include "rt2560_var.h"

static void *ral_soft_state_p = NULL;

#define	RAL_TXBUF_SIZE  	(IEEE80211_MAX_LEN)
#define	RAL_RXBUF_SIZE  	(IEEE80211_MAX_LEN)

/* quickly determine if a given rate is CCK or OFDM */
#define	RAL_RATE_IS_OFDM(rate)	((rate) >= 12 && (rate) != 22)
#define	RAL_ACK_SIZE		14	/* 10 + 4(FCS) */
#define	RAL_CTS_SIZE		14	/* 10 + 4(FCS) */
#define	RAL_SIFS		10	/* us */
#define	RT2560_TXRX_TURNAROUND	10	/* us */

/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset rt2560_rateset_11a =
	{ 8, { 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct ieee80211_rateset rt2560_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset rt2560_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct {
	uint32_t	reg;
	uint32_t	val;
} rt2560_def_mac[] = {
	RT2560_DEF_MAC
};

static const struct {
	uint8_t	reg;
	uint8_t	val;
} rt2560_def_bbp[] = {
	RT2560_DEF_BBP
};

static const uint32_t rt2560_rf2522_r2[]    = RT2560_RF2522_R2;
static const uint32_t rt2560_rf2523_r2[]    = RT2560_RF2523_R2;
static const uint32_t rt2560_rf2524_r2[]    = RT2560_RF2524_R2;
static const uint32_t rt2560_rf2525_r2[]    = RT2560_RF2525_R2;
static const uint32_t rt2560_rf2525_hi_r2[] = RT2560_RF2525_HI_R2;
static const uint32_t rt2560_rf2525e_r2[]   = RT2560_RF2525E_R2;
static const uint32_t rt2560_rf2526_r2[]    = RT2560_RF2526_R2;
static const uint32_t rt2560_rf2526_hi_r2[] = RT2560_RF2526_HI_R2;

static const struct {
	uint8_t		chan;
	uint32_t	r1, r2, r4;
} rt2560_rf5222[] = {
	RT2560_RF5222
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t ral_csr_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for descriptors: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t ral_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t ral_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xFFFFFFFF,			/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,		/* dma_attr_count_max */
	0x0000000000000001ull,		/* dma_attr_align */
	0x00000FFF,			/* dma_attr_burstsizes */
	0x00000001,			/* dma_attr_minxfer */
	0x000000000000FFFFull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	0x00000001,			/* dma_attr_granular */
	0				/* dma_attr_flags */
};

/*
 * device operations
 */
static int rt2560_attach(dev_info_t *, ddi_attach_cmd_t);
static int rt2560_detach(dev_info_t *, ddi_detach_cmd_t);
static int32_t rt2560_quiesce(dev_info_t *);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(ral_dev_ops, nulldev, nulldev, rt2560_attach,
    rt2560_detach, nodev, NULL, D_MP, NULL, rt2560_quiesce);

static struct modldrv ral_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Ralink RT2500 driver v1.6",	/* short description */
	&ral_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&ral_modldrv,
	NULL
};

static int	rt2560_m_stat(void *,  uint_t, uint64_t *);
static int	rt2560_m_start(void *);
static void	rt2560_m_stop(void *);
static int	rt2560_m_promisc(void *, boolean_t);
static int	rt2560_m_multicst(void *, boolean_t, const uint8_t *);
static int	rt2560_m_unicst(void *, const uint8_t *);
static mblk_t	*rt2560_m_tx(void *, mblk_t *);
static void	rt2560_m_ioctl(void *, queue_t *, mblk_t *);
static int	rt2560_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int	rt2560_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void	rt2560_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static mac_callbacks_t rt2560_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	rt2560_m_stat,
	rt2560_m_start,
	rt2560_m_stop,
	rt2560_m_promisc,
	rt2560_m_multicst,
	rt2560_m_unicst,
	rt2560_m_tx,
	NULL,
	rt2560_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,
	NULL,
	rt2560_m_setprop,
	rt2560_m_getprop,
	rt2560_m_propinfo
};

uint32_t ral_dbg_flags = 0;

void
ral_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & ral_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}

static void
rt2560_set_basicrates(struct rt2560_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	/* update basic rate set */
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		/* 11b basic rates: 1, 2Mbps */
		RAL_WRITE(sc, RT2560_ARSP_PLCP_1, 0x3);
	} else if (IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan)) {
		/* 11a basic rates: 6, 12, 24Mbps */
		RAL_WRITE(sc, RT2560_ARSP_PLCP_1, 0x150);
	} else {
		/* 11g basic rates: 1, 2, 5.5, 11, 6, 12, 24Mbps */
		RAL_WRITE(sc, RT2560_ARSP_PLCP_1, 0x15f);
	}
}

static void
rt2560_update_led(struct rt2560_softc *sc, int led1, int led2)
{
	uint32_t tmp;

	/* set ON period to 70ms and OFF period to 30ms */
	tmp = led1 << 16 | led2 << 17 | 70 << 8 | 30;
	RAL_WRITE(sc, RT2560_LEDCSR, tmp);
}

static void
rt2560_set_bssid(struct rt2560_softc *sc, uint8_t *bssid)
{
	uint32_t tmp;

	tmp = bssid[0] | bssid[1] << 8 | bssid[2] << 16 | bssid[3] << 24;
	RAL_WRITE(sc, RT2560_CSR5, tmp);

	tmp = bssid[4] | bssid[5] << 8;
	RAL_WRITE(sc, RT2560_CSR6, tmp);

	ral_debug(RAL_DBG_HW, "setting BSSID to " MACSTR "\n", MAC2STR(bssid));
}


static void
rt2560_bbp_write(struct rt2560_softc *sc, uint8_t reg, uint8_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RAL_READ(sc, RT2560_BBPCSR) & RT2560_BBP_BUSY))
			break;
		drv_usecwait(1);
	}
	if (ntries == 100) {
		ral_debug(RAL_DBG_HW, "could not write to BBP\n");
		return;
	}

	tmp = RT2560_BBP_WRITE | RT2560_BBP_BUSY | reg << 8 | val;
	RAL_WRITE(sc, RT2560_BBPCSR, tmp);

	ral_debug(RAL_DBG_HW, "BBP R%u <- 0x%02x\n", reg, val);
}

static uint8_t
rt2560_bbp_read(struct rt2560_softc *sc, uint8_t reg)
{
	uint32_t val;
	int ntries;

	val = RT2560_BBP_BUSY | reg << 8;
	RAL_WRITE(sc, RT2560_BBPCSR, val);

	for (ntries = 0; ntries < 100; ntries++) {
		val = RAL_READ(sc, RT2560_BBPCSR);
		if (!(val & RT2560_BBP_BUSY))
			return (val & 0xff);
		drv_usecwait(1);
	}

	ral_debug(RAL_DBG_HW, "could not read from BBP\n");
	return (0);
}

static void
rt2560_rf_write(struct rt2560_softc *sc, uint8_t reg, uint32_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RAL_READ(sc, RT2560_RFCSR) & RT2560_RF_BUSY))
			break;
		drv_usecwait(1);
	}
	if (ntries == 100) {
		ral_debug(RAL_DBG_HW, "could not write to RF\n");
		return;
	}

	tmp = RT2560_RF_BUSY | RT2560_RF_20BIT | (val & 0xfffff) << 2 |
	    (reg & 0x3);
	RAL_WRITE(sc, RT2560_RFCSR, tmp);

	/* remember last written value in sc */
	sc->rf_regs[reg] = val;

	ral_debug(RAL_DBG_HW, "RF R[%u] <- 0x%05x\n", reg & 0x3, val & 0xfffff);
}

static void
rt2560_set_chan(struct rt2560_softc *sc, struct ieee80211_channel *c)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t power, tmp;
	uint_t i, chan;

	chan = ieee80211_chan2ieee(ic, c);
	if (chan == 0 || chan == IEEE80211_CHAN_ANY)
		return;

	if (IEEE80211_IS_CHAN_2GHZ(c))
		power = min(sc->txpow[chan - 1], 31);
	else
		power = 31;

	/* adjust txpower using ifconfig settings */
	power -= (100 - ic->ic_txpowlimit) / 8;

	ral_debug(RAL_DBG_CHAN, "setting channel to %u, txpower to %u\n",
	    chan, power);

	switch (sc->rf_rev) {
	case RT2560_RF_2522:
		rt2560_rf_write(sc, RAL_RF1, 0x00814);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2522_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x00040);
		break;

	case RT2560_RF_2523:
		rt2560_rf_write(sc, RAL_RF1, 0x08804);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2523_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x38044);
		rt2560_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);
		break;

	case RT2560_RF_2524:
		rt2560_rf_write(sc, RAL_RF1, 0x0c808);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2524_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x00040);
		rt2560_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);
		break;

	case RT2560_RF_2525:
		rt2560_rf_write(sc, RAL_RF1, 0x08808);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2525_hi_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		rt2560_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);

		rt2560_rf_write(sc, RAL_RF1, 0x08808);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2525_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		rt2560_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);
		break;

	case RT2560_RF_2525E:
		rt2560_rf_write(sc, RAL_RF1, 0x08808);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2525e_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		rt2560_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00286 : 0x00282);
		break;

	case RT2560_RF_2526:
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2526_hi_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF4, (chan & 1) ? 0x00386 : 0x00381);
		rt2560_rf_write(sc, RAL_RF1, 0x08804);

		rt2560_rf_write(sc, RAL_RF2, rt2560_rf2526_r2[chan - 1]);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		rt2560_rf_write(sc, RAL_RF4, (chan & 1) ? 0x00386 : 0x00381);
		break;

	/* dual-band RF */
	case RT2560_RF_5222:
		for (i = 0; rt2560_rf5222[i].chan != chan; i++) {
		}

		rt2560_rf_write(sc, RAL_RF1, rt2560_rf5222[i].r1);
		rt2560_rf_write(sc, RAL_RF2, rt2560_rf5222[i].r2);
		rt2560_rf_write(sc, RAL_RF3, power << 7 | 0x00040);
		rt2560_rf_write(sc, RAL_RF4, rt2560_rf5222[i].r4);
		break;
	}

	if (ic->ic_state != IEEE80211_S_SCAN) {
		/* set Japan filter bit for channel 14 */
		tmp = rt2560_bbp_read(sc, 70);

		tmp &= ~RT2560_JAPAN_FILTER;
		if (chan == 14)
			tmp |= RT2560_JAPAN_FILTER;

		rt2560_bbp_write(sc, 70, tmp);

		/* clear CRC errors */
		(void) RAL_READ(sc, RT2560_CNT0);
	}
}

/*
 * Refer to IEEE Std 802.11-1999 pp. 123 for more information on TSF
 * synchronization.
 */
static void
rt2560_enable_tsf_sync(struct rt2560_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t logcwmin, preload;
	uint32_t tmp;

	/* first, disable TSF synchronization */
	RAL_WRITE(sc, RT2560_CSR14, 0);

	tmp = 16 * ic->ic_bss->in_intval;
	RAL_WRITE(sc, RT2560_CSR12, tmp);

	RAL_WRITE(sc, RT2560_CSR13, 0);

	logcwmin = 5;
	preload = (ic->ic_opmode == IEEE80211_M_STA) ? 384 : 1024;
	tmp = logcwmin << 16 | preload;
	RAL_WRITE(sc, RT2560_BCNOCSR, tmp);

	/* finally, enable TSF synchronization */
	tmp = RT2560_ENABLE_TSF | RT2560_ENABLE_TBCN;
	if (ic->ic_opmode == IEEE80211_M_STA)
		tmp |= RT2560_ENABLE_TSF_SYNC(1);
	else
		tmp |= RT2560_ENABLE_TSF_SYNC(2) |
		    RT2560_ENABLE_BEACON_GENERATOR;
	RAL_WRITE(sc, RT2560_CSR14, tmp);

	ral_debug(RAL_DBG_HW, "enabling TSF synchronization\n");
}

static void
rt2560_update_plcp(struct rt2560_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	/* no short preamble for 1Mbps */
	RAL_WRITE(sc, RT2560_PLCP1MCSR, 0x00700400);

	if (!(ic->ic_flags & IEEE80211_F_SHPREAMBLE)) {
		/* values taken from the reference driver */
		RAL_WRITE(sc, RT2560_PLCP2MCSR,   0x00380401);
		RAL_WRITE(sc, RT2560_PLCP5p5MCSR, 0x00150402);
		RAL_WRITE(sc, RT2560_PLCP11MCSR,  0x000b8403);
	} else {
		/* same values as above or'ed 0x8 */
		RAL_WRITE(sc, RT2560_PLCP2MCSR,   0x00380409);
		RAL_WRITE(sc, RT2560_PLCP5p5MCSR, 0x0015040a);
		RAL_WRITE(sc, RT2560_PLCP11MCSR,  0x000b840b);
	}

	ral_debug(RAL_DBG_HW, "updating PLCP for %s preamble\n",
	    (ic->ic_flags & IEEE80211_F_SHPREAMBLE) ? "short" : "long");
}

/*
 * This function can be called by ieee80211_set_shortslottime(). Refer to
 * IEEE Std 802.11-1999 pp. 85 to know how these values are computed.
 */
void
rt2560_update_slot(struct ieee80211com *ic, int onoff)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)ic;
	uint8_t slottime;
	uint16_t tx_sifs, tx_pifs, tx_difs, eifs;
	uint32_t tmp;

	/* slottime = (ic->ic_flags & IEEE80211_F_SHSLOT) ? 9 : 20; */
	slottime = (onoff ? 9 : 20);

	/* update the MAC slot boundaries */
	tx_sifs = RAL_SIFS - RT2560_TXRX_TURNAROUND;
	tx_pifs = tx_sifs + slottime;
	tx_difs = tx_sifs + 2 * slottime;
	eifs = (ic->ic_curmode == IEEE80211_MODE_11B) ? 364 : 60;

	tmp = RAL_READ(sc, RT2560_CSR11);
	tmp = (tmp & ~0x1f00) | slottime << 8;
	RAL_WRITE(sc, RT2560_CSR11, tmp);

	tmp = tx_pifs << 16 | tx_sifs;
	RAL_WRITE(sc, RT2560_CSR18, tmp);

	tmp = eifs << 16 | tx_difs;
	RAL_WRITE(sc, RT2560_CSR19, tmp);

	ral_debug(RAL_DBG_HW, "setting slottime to %uus\n", slottime);
}

int
ral_dma_region_alloc(struct rt2560_softc *sc, struct dma_region *dr,
    size_t size, uint_t alloc_flags, uint_t bind_flags)
{
	dev_info_t *dip = sc->sc_dev;
	int err;

	err = ddi_dma_alloc_handle(dip, &ral_dma_attr, DDI_DMA_SLEEP, NULL,
	    &dr->dr_hnd);
	if (err != DDI_SUCCESS)
		goto fail1;

	err = ddi_dma_mem_alloc(dr->dr_hnd, size, &ral_desc_accattr,
	    alloc_flags, DDI_DMA_SLEEP, NULL,
	    &dr->dr_base, &dr->dr_size, &dr->dr_acc);
	if (err != DDI_SUCCESS)
		goto fail2;

	err = ddi_dma_addr_bind_handle(dr->dr_hnd, NULL,
	    dr->dr_base, dr->dr_size,
	    bind_flags, DDI_DMA_SLEEP, NULL, &dr->dr_cookie, &dr->dr_ccnt);
	if (err != DDI_SUCCESS)
		goto fail3;

	if (dr->dr_ccnt != 1) {
		err = DDI_FAILURE;
		goto fail4;
	}

	dr->dr_pbase = dr->dr_cookie.dmac_address;
	ral_debug(RAL_DBG_DMA, "get physical-base=0x%08x\n", dr->dr_pbase);

	return (DDI_SUCCESS);

fail4:
	(void) ddi_dma_unbind_handle(dr->dr_hnd);
fail3:
	ddi_dma_mem_free(&dr->dr_acc);
fail2:
	ddi_dma_free_handle(&dr->dr_hnd);
fail1:
	return (err);
}

/* ARGSUSED */
void
ral_dma_region_free(struct rt2560_softc *sc, struct dma_region *dr)
{
	(void) ddi_dma_unbind_handle(dr->dr_hnd);
	ddi_dma_mem_free(&dr->dr_acc);
	ddi_dma_free_handle(&dr->dr_hnd);
}

int
rt2560_alloc_tx_ring(struct rt2560_softc *sc, struct rt2560_tx_ring *ring,
	int count)
{
	int i, err;
	int size;

	ring->count = count;
	ring->queued = 0;
	ring->cur = ring->next = 0;
	ring->cur_encrypt = ring->next_encrypt = 0;

	ring->data = kmem_zalloc(count * (sizeof (struct rt2560_tx_data)),
	    KM_SLEEP);
	ring->dr_txbuf = kmem_zalloc(count * (sizeof (struct dma_region)),
	    KM_SLEEP);

	err = ral_dma_region_alloc(sc, &ring->dr_desc,
	    count * (sizeof (struct rt2560_tx_desc)),
	    DDI_DMA_CONSISTENT, DDI_DMA_RDWR | DDI_DMA_CONSISTENT);

	if (err != DDI_SUCCESS)
		goto fail1;

	size = roundup(RAL_TXBUF_SIZE, sc->sc_cachelsz);
	for (i = 0; i < count; i++) {
		err = ral_dma_region_alloc(sc, &ring->dr_txbuf[i], size,
		    DDI_DMA_STREAMING, DDI_DMA_WRITE | DDI_DMA_STREAMING);
		if (err != DDI_SUCCESS) {
			while (i >= 0) {
				ral_dma_region_free(sc, &ring->dr_txbuf[i]);
				i--;
			}
			goto fail2;
		}
	}

	ring->physaddr = LE_32(ring->dr_desc.dr_pbase);
	ring->desc = (struct rt2560_tx_desc *)ring->dr_desc.dr_base;

	for (i = 0; i < count; i++) {
		ring->desc[i].physaddr = LE_32(ring->dr_txbuf[i].dr_pbase);
		ring->data[i].buf = ring->dr_txbuf[i].dr_base;
	}

	return (DDI_SUCCESS);
fail2:
	ral_dma_region_free(sc, &ring->dr_desc);
fail1:
	return (err);
}

/* ARGSUSED */
void
rt2560_reset_tx_ring(struct rt2560_softc *sc, struct rt2560_tx_ring *ring)
{
	struct rt2560_tx_desc *desc;
	struct rt2560_tx_data *data;
	int i;

	for (i = 0; i < ring->count; i++) {
		desc = &ring->desc[i];
		data = &ring->data[i];

		if (data->ni != NULL) {
			ieee80211_free_node(data->ni);
			data->ni = NULL;
		}

		desc->flags = 0;
	}

	(void) ddi_dma_sync(ring->dr_desc.dr_hnd, 0,
	    ring->count * sizeof (struct rt2560_tx_desc), DDI_DMA_SYNC_FORDEV);

	ring->queued = 0;
	ring->cur = ring->next = 0;
	ring->cur_encrypt = ring->next_encrypt = 0;
}

void
rt2560_free_tx_ring(struct rt2560_softc *sc, struct rt2560_tx_ring *ring)
{
	struct rt2560_tx_data *data;
	int i;

	ral_dma_region_free(sc, &ring->dr_desc);
	/* tx buf */
	for (i = 0; i < ring->count; i++) {
		data = &ring->data[i];
		if (data->ni != NULL) {
			ieee80211_free_node(data->ni);
			data->ni = NULL;
		}

		ral_dma_region_free(sc, &ring->dr_txbuf[i]);
	}

	kmem_free(ring->data, ring->count * (sizeof (struct rt2560_tx_data)));
	kmem_free(ring->dr_txbuf, ring->count * (sizeof (struct dma_region)));
}

void
rt2560_ring_hwsetup(struct rt2560_softc *sc)
{
	uint32_t tmp;

	/* setup tx rings */
	tmp = ((uint32_t)RT2560_PRIO_RING_COUNT << 24) |
	    RT2560_ATIM_RING_COUNT << 16 |
	    RT2560_TX_RING_COUNT   <<  8 |
	    RT2560_TX_DESC_SIZE;

	/* rings must be initialized in this exact order */
	RAL_WRITE(sc, RT2560_TXCSR2, tmp);
	RAL_WRITE(sc, RT2560_TXCSR3, sc->txq.physaddr);
	RAL_WRITE(sc, RT2560_TXCSR5, sc->prioq.physaddr);

	/* setup rx ring */
	tmp = RT2560_RX_RING_COUNT << 8 | RT2560_RX_DESC_SIZE;

	RAL_WRITE(sc, RT2560_RXCSR1, tmp);
	RAL_WRITE(sc, RT2560_RXCSR2, sc->rxq.physaddr);
}

int
rt2560_alloc_rx_ring(struct rt2560_softc *sc, struct rt2560_rx_ring *ring,
	int count)
{
	struct rt2560_rx_desc *desc;
	struct rt2560_rx_data *data;
	int i, err;
	int size;

	ring->count = count;
	ring->cur = ring->next = 0;
	ring->cur_decrypt = 0;

	ring->data = kmem_zalloc(count * (sizeof (struct rt2560_rx_data)),
	    KM_SLEEP);
	ring->dr_rxbuf = kmem_zalloc(count * (sizeof (struct dma_region)),
	    KM_SLEEP);

	err = ral_dma_region_alloc(sc, &ring->dr_desc,
	    count * (sizeof (struct rt2560_rx_desc)),
	    DDI_DMA_CONSISTENT, DDI_DMA_RDWR | DDI_DMA_CONSISTENT);

	if (err != DDI_SUCCESS)
		goto fail1;

	size = roundup(RAL_RXBUF_SIZE, sc->sc_cachelsz);
	for (i = 0; i < count; i++) {
		err = ral_dma_region_alloc(sc, &ring->dr_rxbuf[i], size,
		    DDI_DMA_STREAMING, DDI_DMA_READ | DDI_DMA_STREAMING);
		if (err != DDI_SUCCESS) {
			while (i >= 0) {
				ral_dma_region_free(sc, &ring->dr_rxbuf[i]);
				i--;
			}
			goto fail2;
		}
	}

	ring->physaddr = ring->dr_desc.dr_pbase;
	ring->desc = (struct rt2560_rx_desc *)ring->dr_desc.dr_base;

	for (i = 0; i < count; i++) {
		desc = &ring->desc[i];
		data = &ring->data[i];

		desc->physaddr = LE_32(ring->dr_rxbuf[i].dr_pbase);
		desc->flags = LE_32(RT2560_RX_BUSY);

		data->buf = ring->dr_rxbuf[i].dr_base;
	}

	return (DDI_SUCCESS);
fail2:
	ral_dma_region_free(sc, &ring->dr_desc);
fail1:
	return (err);
}

/* ARGSUSED */
static void
rt2560_reset_rx_ring(struct rt2560_softc *sc, struct rt2560_rx_ring *ring)
{
	int i;

	for (i = 0; i < ring->count; i++) {
		ring->desc[i].flags = LE_32(RT2560_RX_BUSY);
		ring->data[i].drop = 0;
	}

	(void) ddi_dma_sync(ring->dr_desc.dr_hnd, 0,
	    ring->count * sizeof (struct rt2560_rx_desc),
	    DDI_DMA_SYNC_FORKERNEL);

	ring->cur = ring->next = 0;
	ring->cur_decrypt = 0;
}

static void
rt2560_free_rx_ring(struct rt2560_softc *sc, struct rt2560_rx_ring *ring)
{
	int i;

	ral_dma_region_free(sc, &ring->dr_desc);
	/* rx buf */
	for (i = 0; i < ring->count; i++)
		ral_dma_region_free(sc, &ring->dr_rxbuf[i]);

	kmem_free(ring->data, ring->count * (sizeof (struct rt2560_rx_data)));
	kmem_free(ring->dr_rxbuf, ring->count * (sizeof (struct dma_region)));
}

/* ARGSUSED */
static struct ieee80211_node *
rt2560_node_alloc(ieee80211com_t *ic)
{
	struct rt2560_node *rn;

	rn = kmem_zalloc(sizeof (struct rt2560_node), KM_SLEEP);
	return ((rn != NULL) ? &rn->ni : NULL);
}

static void
rt2560_node_free(struct ieee80211_node *in)
{
	ieee80211com_t *ic = in->in_ic;

	ic->ic_node_cleanup(in);
	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);
	kmem_free(in, sizeof (struct rt2560_node));
}

/*
 * This function is called periodically (every 200ms) during scanning to
 * switch from one channel to another.
 */
static void
rt2560_next_scan(void *arg)
{
	struct rt2560_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		(void) ieee80211_next_scan(ic);
}

/*
 * This function is called for each node present in the node station table.
 */
/* ARGSUSED */
static void
rt2560_iter_func(void *arg, struct ieee80211_node *ni)
{
	struct rt2560_node *rn = (struct rt2560_node *)ni;

	ral_rssadapt_updatestats(&rn->rssadapt);
}

/*
 * This function is called periodically (every 100ms) in RUN state to update
 * the rate adaptation statistics.
 */
static void
rt2560_update_rssadapt(void *arg)
{
	struct rt2560_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_iterate_nodes(&ic->ic_sta, rt2560_iter_func, arg);
	sc->sc_rssadapt_id = timeout(rt2560_update_rssadapt, (void *)sc,
	    drv_usectohz(100 * 1000));
}

static void
rt2560_statedog(void *arg)
{
	struct rt2560_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	enum ieee80211_state state;

	RAL_LOCK(sc);

	sc->sc_state_id = 0;
	state = ic->ic_state;
	ic->ic_state = sc->sc_ostate;

	RAL_UNLOCK(sc);

	ieee80211_new_state(ic, state, -1);

}

static int
rt2560_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)ic;
	enum ieee80211_state ostate;
	struct ieee80211_node *ni;
	int err;

	RAL_LOCK(sc);

	ostate = ic->ic_state;
	sc->sc_ostate = ostate;

	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}

	if (sc->sc_rssadapt_id != 0) {
		(void) untimeout(sc->sc_rssadapt_id);
		sc->sc_rssadapt_id = 0;
	}

	if (sc->sc_state_id != 0) {
		(void) untimeout(sc->sc_state_id);
		sc->sc_state_id = 0;
	}

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_RUN) {
			/* abort TSF synchronization */
			RAL_WRITE(sc, RT2560_CSR14, 0);
			/* turn association led off */
			rt2560_update_led(sc, 0, 0);
		}
		break;

	case IEEE80211_S_SCAN:
		rt2560_set_chan(sc, ic->ic_curchan);
		sc->sc_scan_id = timeout(rt2560_next_scan, (void *)sc,
		    drv_usectohz(sc->dwelltime * 1000));
		break;

	case IEEE80211_S_AUTH:
		rt2560_set_chan(sc, ic->ic_curchan);
		break;

	case IEEE80211_S_ASSOC:
		rt2560_set_chan(sc, ic->ic_curchan);

		drv_usecwait(10 * 1000);	/* dlink */
		sc->sc_state_id = timeout(rt2560_statedog, (void *)sc,
		    drv_usectohz(300 * 1000));	/* ap7-3 */
		break;

	case IEEE80211_S_RUN:
		rt2560_set_chan(sc, ic->ic_curchan);

		ni = ic->ic_bss;

		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			rt2560_update_plcp(sc);
			rt2560_set_basicrates(sc);
			rt2560_set_bssid(sc, ni->in_bssid);
		}

		/* turn assocation led on */
		rt2560_update_led(sc, 1, 0);
		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			sc->sc_rssadapt_id = timeout(rt2560_update_rssadapt,
			    (void *)sc, drv_usectohz(100 * 1000));
			rt2560_enable_tsf_sync(sc);
		}
		break;
	}

	RAL_UNLOCK(sc);

	err = sc->sc_newstate(ic, nstate, arg);
	/*
	 * Finally, start any timers.
	 */
	if (nstate == IEEE80211_S_RUN)
		ieee80211_start_watchdog(ic, 1);

	return (err);
}

/*
 * Read 16 bits at address 'addr' from the serial EEPROM (either 93C46 or
 * 93C66).
 */
static uint16_t
rt2560_eeprom_read(struct rt2560_softc *sc, uint8_t addr)
{
	uint32_t tmp;
	uint16_t val;
	int n;

	/* clock C once before the first command */
	RT2560_EEPROM_CTL(sc, 0);

	RT2560_EEPROM_CTL(sc, RT2560_S);
	RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_C);
	RT2560_EEPROM_CTL(sc, RT2560_S);

	/* write start bit (1) */
	RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_D);
	RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_D | RT2560_C);

	/* write READ opcode (10) */
	RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_D);
	RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_D | RT2560_C);
	RT2560_EEPROM_CTL(sc, RT2560_S);
	RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_C);

	/* write address (A5-A0 or A7-A0) */
	n = (RAL_READ(sc, RT2560_CSR21) & RT2560_93C46) ? 5 : 7;
	for (; n >= 0; n--) {
		RT2560_EEPROM_CTL(sc, RT2560_S |
		    (((addr >> n) & 1) << RT2560_SHIFT_D));
		RT2560_EEPROM_CTL(sc, RT2560_S |
		    (((addr >> n) & 1) << RT2560_SHIFT_D) | RT2560_C);
	}

	RT2560_EEPROM_CTL(sc, RT2560_S);

	/* read data Q15-Q0 */
	val = 0;
	for (n = 15; n >= 0; n--) {
		RT2560_EEPROM_CTL(sc, RT2560_S | RT2560_C);
		tmp = RAL_READ(sc, RT2560_CSR21);
		val |= ((tmp & RT2560_Q) >> RT2560_SHIFT_Q) << n;
		RT2560_EEPROM_CTL(sc, RT2560_S);
	}

	RT2560_EEPROM_CTL(sc, 0);

	/* clear Chip Select and clock C */
	RT2560_EEPROM_CTL(sc, RT2560_S);
	RT2560_EEPROM_CTL(sc, 0);
	RT2560_EEPROM_CTL(sc, RT2560_C);

	return (val);
}

static void
rt2560_tx_intr(struct rt2560_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct rt2560_tx_desc *desc;
	struct rt2560_tx_data *data;
	struct rt2560_node *rn;

	struct dma_region *dr;
	int count;

	dr = &sc->txq.dr_desc;
	count = sc->txq.count;

	(void) ddi_dma_sync(dr->dr_hnd, 0, count * RT2560_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

	mutex_enter(&sc->txq.tx_lock);

	for (;;) {
		desc = &sc->txq.desc[sc->txq.next];
		data = &sc->txq.data[sc->txq.next];

		if ((LE_32(desc->flags) & RT2560_TX_BUSY) ||
		    (LE_32(desc->flags) & RT2560_TX_CIPHER_BUSY) ||
		    !(LE_32(desc->flags) & RT2560_TX_VALID))
			break;

		rn = (struct rt2560_node *)data->ni;

		switch (LE_32(desc->flags) & RT2560_TX_RESULT_MASK) {
		case RT2560_TX_SUCCESS:
			ral_debug(RAL_DBG_INTR, "data frame sent success\n");
			if (data->id.id_node != NULL) {
				ral_rssadapt_raise_rate(ic, &rn->rssadapt,
				    &data->id);
			}
			break;

		case RT2560_TX_SUCCESS_RETRY:
			ral_debug(RAL_DBG_INTR,
			    "data frame sent after %u retries\n",
			    (LE_32(desc->flags) >> 5) & 0x7);
			sc->sc_tx_retries++;
			break;

		case RT2560_TX_FAIL_RETRY:
			ral_debug(RAL_DBG_INTR,
			    "sending data frame failed (too much retries)\n");
			if (data->id.id_node != NULL) {
				ral_rssadapt_lower_rate(ic, data->ni,
				    &rn->rssadapt, &data->id);
			}
			break;

		case RT2560_TX_FAIL_INVALID:
		case RT2560_TX_FAIL_OTHER:
		default:
			ral_debug(RAL_DBG_INTR, "sending data frame failed "
			    "0x%08x\n", LE_32(desc->flags));
			break;
		}

		ieee80211_free_node(data->ni);
		data->ni = NULL;

		/* descriptor is no longer valid */
		desc->flags &= ~LE_32(RT2560_TX_VALID);

		ral_debug(RAL_DBG_INTR, "tx done idx=%u\n", sc->txq.next);

		sc->txq.queued--;
		sc->txq.next = (sc->txq.next + 1) % RT2560_TX_RING_COUNT;

		if (sc->sc_need_sched &&
		    sc->txq.queued < (RT2560_TX_RING_COUNT - 32)) {
			sc->sc_need_sched = 0;
			mac_tx_update(ic->ic_mach);
		}
	}

	(void) ddi_dma_sync(dr->dr_hnd, 0, count * RT2560_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	sc->sc_tx_timer = 0;
	mutex_exit(&sc->txq.tx_lock);
}

static void
rt2560_prio_intr(struct rt2560_softc *sc)
{
	struct rt2560_tx_desc *desc;
	struct rt2560_tx_data *data;

	struct dma_region *dr;
	int count;

	dr = &sc->prioq.dr_desc;
	count = sc->prioq.count;

	(void) ddi_dma_sync(dr->dr_hnd, 0, count * RT2560_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

	mutex_enter(&sc->prioq.tx_lock);

	for (;;) {
		desc = &sc->prioq.desc[sc->prioq.next];
		data = &sc->prioq.data[sc->prioq.next];

		if ((LE_32(desc->flags) & RT2560_TX_BUSY) ||
		    !(LE_32(desc->flags) & RT2560_TX_VALID))
			break;

		switch (LE_32(desc->flags) & RT2560_TX_RESULT_MASK) {
		case RT2560_TX_SUCCESS:
			ral_debug(RAL_DBG_INTR, "mgt frame sent success\n");
			break;

		case RT2560_TX_SUCCESS_RETRY:
			ral_debug(RAL_DBG_INTR,
			    "mgt frame sent after %u retries\n",
			    (LE_32(desc->flags) >> 5) & 0x7);
			break;

		case RT2560_TX_FAIL_RETRY:
			ral_debug(RAL_DBG_INTR,
			    "sending mgt frame failed (too much " "retries)\n");
			break;

		case RT2560_TX_FAIL_INVALID:
		case RT2560_TX_FAIL_OTHER:
		default:
			ral_debug(RAL_DBG_INTR, "sending mgt frame failed "
			    "0x%08x\n", LE_32(desc->flags));
		}

		ieee80211_free_node(data->ni);
		data->ni = NULL;

		/* descriptor is no longer valid */
		desc->flags &= ~LE_32(RT2560_TX_VALID);

		ral_debug(RAL_DBG_INTR, "prio done idx=%u\n", sc->prioq.next);

		sc->prioq.queued--;
		sc->prioq.next = (sc->prioq.next + 1) % RT2560_PRIO_RING_COUNT;
	}

	(void) ddi_dma_sync(dr->dr_hnd, 0, count * RT2560_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	sc->sc_tx_timer = 0;
	mutex_exit(&sc->prioq.tx_lock);
}

/*
 * Some frames were received. Pass them to the hardware cipher engine before
 * sending them to the 802.11 layer.
 */
void
rt2560_rx_intr(struct rt2560_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct rt2560_rx_desc *desc;
	struct rt2560_rx_data *data;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct rt2560_node *rn;

	mblk_t *m;
	uint32_t len;
	char *rxbuf;

	struct dma_region *dr, *dr_bf;
	int count;

	dr = &sc->rxq.dr_desc;
	count = sc->rxq.count;

	mutex_enter(&sc->rxq.rx_lock);

	(void) ddi_dma_sync(dr->dr_hnd, 0, count * RT2560_RX_DESC_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

	for (;;) {
		desc = &sc->rxq.desc[sc->rxq.cur];
		data = &sc->rxq.data[sc->rxq.cur];

		if ((LE_32(desc->flags) & RT2560_RX_BUSY) ||
		    (LE_32(desc->flags) & RT2560_RX_CIPHER_BUSY))
			break;

		data->drop = 0;

		if ((LE_32(desc->flags) & RT2560_RX_PHY_ERROR) ||
		    (LE_32(desc->flags) & RT2560_RX_CRC_ERROR)) {
			/*
			 * This should not happen since we did not request
			 * to receive those frames when we filled RXCSR0.
			 */
			ral_debug(RAL_DBG_RX, "PHY or CRC error flags 0x%08x\n",
			    LE_32(desc->flags));
			data->drop = 1;
		}

		if (((LE_32(desc->flags) >> 16) & 0xfff) > RAL_RXBUF_SIZE) {
			ral_debug(RAL_DBG_RX, "bad length\n");
			data->drop = 1;
		}

		if (data->drop) {
			sc->sc_rx_err++;
			goto skip;
		}

		rxbuf = data->buf;
		len = (LE_32(desc->flags) >> 16) & 0xfff;

		if ((len < sizeof (struct ieee80211_frame_min)) ||
		    (len > RAL_RXBUF_SIZE)) {
			ral_debug(RAL_DBG_RX, "bad frame length=%u\n", len);
			sc->sc_rx_err++;
			goto skip;
		}

		if ((m = allocb(len, BPRI_MED)) == NULL) {
			ral_debug(RAL_DBG_RX, "rt2560_rx_intr():"
			    " allocate mblk failed.\n");
			sc->sc_rx_nobuf++;
			goto skip;
		}

		dr_bf = &sc->rxq.dr_rxbuf[sc->rxq.cur];
		(void) ddi_dma_sync(dr_bf->dr_hnd, 0, dr_bf->dr_size,
		    DDI_DMA_SYNC_FORCPU);

		bcopy(rxbuf, m->b_rptr, len);
		m->b_wptr += len;

		wh = (struct ieee80211_frame *)m->b_rptr;
		ni = ieee80211_find_rxnode(ic, wh);

		/* give rssi to the rate adatation algorithm */
		rn = (struct rt2560_node *)ni;
		ral_rssadapt_input(ic, ni, &rn->rssadapt, desc->rssi);

		/* send the frame to the 802.11 layer */
		(void) ieee80211_input(ic, m, ni, desc->rssi, 0);

		/* node is no longer needed */
		ieee80211_free_node(ni);

skip:		desc->flags = LE_32(RT2560_RX_BUSY);
		ral_debug(RAL_DBG_RX, "rx done idx=%u\n", sc->rxq.cur);

		sc->rxq.cur = (sc->rxq.cur + 1) % RT2560_RX_RING_COUNT;
	}
	mutex_exit(&sc->rxq.rx_lock);

	(void) ddi_dma_sync(dr->dr_hnd, 0, count * RT2560_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORDEV);
}

uint_t
ral_softint_handler(caddr_t data)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct rt2560_softc *sc = (struct rt2560_softc *)data;

	/*
	 * Check if the soft interrupt is triggered by another
	 * driver at the same level.
	 */
	RAL_LOCK(sc);
	if (sc->sc_rx_pend) {
		sc->sc_rx_pend = 0;
		RAL_UNLOCK(sc);
		rt2560_rx_intr(sc);
		return (DDI_INTR_CLAIMED);
	}
	RAL_UNLOCK(sc);
	return (DDI_INTR_UNCLAIMED);
}

/*
 * Return the expected ack rate for a frame transmitted at rate `rate'.
 * XXX: this should depend on the destination node basic rate set.
 */
static int
rt2560_ack_rate(struct ieee80211com *ic, int rate)
{
	switch (rate) {
	/* CCK rates */
	case 2:
		return (2);
	case 4:
	case 11:
	case 22:
		return ((ic->ic_curmode == IEEE80211_MODE_11B) ? 4 : rate);

	/* OFDM rates */
	case 12:
	case 18:
		return (12);
	case 24:
	case 36:
		return (24);
	case 48:
	case 72:
	case 96:
	case 108:
		return (48);
	}

	/* default to 1Mbps */
	return (2);
}

/*
 * Compute the duration (in us) needed to transmit `len' bytes at rate `rate'.
 * The function automatically determines the operating mode depending on the
 * given rate. `flags' indicates whether short preamble is in use or not.
 */
static uint16_t
rt2560_txtime(int len, int rate, uint32_t flags)
{
	uint16_t txtime;

	if (RAL_RATE_IS_OFDM(rate)) {
		/* IEEE Std 802.11a-1999, pp. 37 */
		txtime = (8 + 4 * len + 3 + rate - 1) / rate;
		txtime = 16 + 4 + 4 * txtime + 6;
	} else {
		/* IEEE Std 802.11b-1999, pp. 28 */
		txtime = (16 * len + rate - 1) / rate;
		if (rate != 2 && (flags & IEEE80211_F_SHPREAMBLE))
			txtime +=  72 + 24;
		else
			txtime += 144 + 48;
	}

	return (txtime);
}

static uint8_t
rt2560_plcp_signal(int rate)
{
	switch (rate) {
	/* CCK rates (returned values are device-dependent) */
	case 2:		return (0x0);
	case 4:		return (0x1);
	case 11:	return (0x2);
	case 22:	return (0x3);

	/* OFDM rates (cf IEEE Std 802.11a-1999, pp. 14 Table 80) */
	case 12:	return (0xb);
	case 18:	return (0xf);
	case 24:	return (0xa);
	case 36:	return (0xe);
	case 48:	return (0x9);
	case 72:	return (0xd);
	case 96:	return (0x8);
	case 108:	return (0xc);

	/* unsupported rates (should not get there) */
	default:	return (0xff);
	}
}

void
rt2560_setup_tx_desc(struct rt2560_softc *sc, struct rt2560_tx_desc *desc,
    uint32_t flags, int len, int rate, int encrypt)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t plcp_length;
	int remainder;

	desc->flags = LE_32(flags);
	desc->flags |= LE_32(len << 16);
	desc->flags |= encrypt ? LE_32(RT2560_TX_CIPHER_BUSY) :
	    LE_32(RT2560_TX_BUSY | RT2560_TX_VALID);

	desc->wme = LE_16(
	    RT2560_AIFSN(2) |
	    RT2560_LOGCWMIN(3) |
	    RT2560_LOGCWMAX(8));

	/* setup PLCP fields */
	desc->plcp_signal  = rt2560_plcp_signal(rate);
	desc->plcp_service = 4;

	len += IEEE80211_CRC_LEN;
	if (RAL_RATE_IS_OFDM(rate)) {
		desc->flags |= LE_32(RT2560_TX_OFDM);

		plcp_length = len & 0xfff;
		desc->plcp_length_hi = plcp_length >> 6;
		desc->plcp_length_lo = plcp_length & 0x3f;
	} else {
		plcp_length = (16 * len + rate - 1) / rate;
		if (rate == 22) {
			remainder = (16 * len) % 22;
			if (remainder != 0 && remainder < 7)
				desc->plcp_service |= RT2560_PLCP_LENGEXT;
		}
		desc->plcp_length_hi = plcp_length >> 8;
		desc->plcp_length_lo = plcp_length & 0xff;

		if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
			desc->plcp_signal |= 0x08;
	}
}

/* ARGSUSED */
int
rt2560_mgmt_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)ic;
	struct rt2560_tx_desc *desc;
	struct rt2560_tx_data *data;
	struct ieee80211_frame *wh;
	uint16_t dur;
	uint32_t flags = 0;
	int rate, err = DDI_SUCCESS;

	int off, pktlen, mblen;
	caddr_t dest;
	mblk_t *m, *m0;

	struct dma_region *dr;
	uint32_t idx;
	struct ieee80211_node *ni;
	struct ieee80211_key *k;

	mutex_enter(&sc->prioq.tx_lock);

	if (!RAL_IS_RUNNING(sc)) {
		err = ENXIO;
		goto fail1;
	}

	if (sc->prioq.queued >= RT2560_PRIO_RING_COUNT) {
		err = ENOMEM;
		sc->sc_tx_nobuf++;
		goto fail1;
	}

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) {
		ral_debug(RAL_DBG_TX, "rt2560_mgmt_send: can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail1;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) memcpy(m->b_rptr + off, m0->b_rptr, mblen);
		off += mblen;
	}
	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;
	ni = ieee80211_find_txnode(ic, wh->i_addr1);

	if (ni == NULL) {
		err = DDI_FAILURE;
		sc->sc_tx_err++;
		goto fail2;
	}

	/* to support shared_key auth mode */
	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			err = DDI_FAILURE;
			sc->sc_tx_err++;
			goto fail3;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	desc = &sc->prioq.desc[sc->prioq.cur];
	data = &sc->prioq.data[sc->prioq.cur];

	rate = IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) ? 12 : 2;
	data->ni = ieee80211_ref_node(ni);

	pktlen = msgdsize(m);
	dest = data->buf;
	bcopy(m->b_rptr, dest, pktlen);

	wh = (struct ieee80211_frame *)m->b_rptr;
	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= RT2560_TX_ACK;

		dur = rt2560_txtime(RAL_ACK_SIZE, rate, ic->ic_flags) +
		    RAL_SIFS;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		*(uint16_t *)wh->i_dur = LE_16(dur);

		/* tell hardware to add timestamp for probe responses */
		if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_MGT &&
		    (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			flags |= RT2560_TX_TIMESTAMP;
	}

	rt2560_setup_tx_desc(sc, desc, flags, pktlen, rate, 0);

	idx = sc->prioq.cur;

	dr = &sc->prioq.dr_txbuf[idx];
	(void) ddi_dma_sync(dr->dr_hnd, 0, RAL_TXBUF_SIZE, DDI_DMA_SYNC_FORDEV);

	dr = &sc->prioq.dr_desc;
	(void) ddi_dma_sync(dr->dr_hnd, idx * RT2560_TX_DESC_SIZE,
	    RT2560_TX_DESC_SIZE, DDI_DMA_SYNC_FORDEV);

	ral_debug(RAL_DBG_MGMT, "sending mgt frame len=%u idx=%u rate=%u\n",
	    pktlen, sc->prioq.cur, rate);

	/* kick prio */
	sc->prioq.queued++; /* IF > RT2560_PRIO_RING_COUNT? FULL */
	sc->prioq.cur = (sc->prioq.cur + 1) % RT2560_PRIO_RING_COUNT;
	RAL_WRITE(sc, RT2560_TXCSR0, RT2560_KICK_PRIO);

	sc->sc_tx_timer = 5;

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

fail3:
	ieee80211_free_node(ni);
fail2:
	freemsg(m);
fail1:
	freemsg(mp);
	mutex_exit(&sc->prioq.tx_lock);

	return (err);
}

static int
rt2560_send(ieee80211com_t *ic, mblk_t *mp)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)ic;
	struct rt2560_tx_desc *desc;
	struct rt2560_tx_data *data;
	struct rt2560_node *rn;
	struct ieee80211_rateset *rs;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k;
	uint16_t dur;
	uint32_t flags = 0;
	int rate, err = DDI_SUCCESS;

	struct ieee80211_node *ni;
	mblk_t *m, *m0;
	int off, mblen, pktlen;
	caddr_t dest;

	struct dma_region *dr;
	uint32_t idx;

	mutex_enter(&sc->txq.tx_lock);

	if (sc->txq.queued >= RT2560_TX_RING_COUNT - 1) {
		ral_debug(RAL_DBG_TX, "ral: rt2560_tx_data(): "
		    "no TX DMA buffer available!\n");
		sc->sc_need_sched = 1;
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail1;
	}

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) {
		ral_debug(RAL_DBG_TX, "rt2560_xmit(): can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail1;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) memcpy(m->b_rptr + off, m0->b_rptr, mblen);
		off += mblen;
	}
	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;
	ni = ieee80211_find_txnode(ic, wh->i_addr1);

	if (ni == NULL) {
		err = DDI_FAILURE;
		sc->sc_tx_err++;
		goto fail2;
	}

	(void) ieee80211_encap(ic, m, ni);

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			sc->sc_tx_err++;
			err = DDI_FAILURE;
			goto fail3;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	/*
	 * RTS/CTS exchange ignore, since the max packet will less than
	 * the rtsthreshold (2346)
	 * Unnecessary codes deleted.
	 */

	data = &sc->txq.data[sc->txq.cur];
	desc = &sc->txq.desc[sc->txq.cur];

	data->ni = ieee80211_ref_node(ni);

	pktlen = msgdsize(m);
	dest = data->buf;
	bcopy(m->b_rptr, dest, pktlen);

	if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
		rs = &ic->ic_sup_rates[ic->ic_curmode];
		rate = rs->ir_rates[ic->ic_fixed_rate];
	} else {
		rs = &ni->in_rates;
		rn = (struct rt2560_node *)ni;
		ni->in_txrate = ral_rssadapt_choose(&rn->rssadapt, rs, wh,
		    pktlen, NULL, 0);
		rate = rs->ir_rates[ni->in_txrate];
	}

	rate &= IEEE80211_RATE_VAL;
	if (rate <= 0) {
		rate = 2;	/* basic rate */
	}

	/* remember link conditions for rate adaptation algorithm */
	if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
		data->id.id_len = pktlen;
		data->id.id_rateidx = ni->in_txrate;
		data->id.id_node = ni;
		data->id.id_rssi = ni->in_rssi;
	} else
		data->id.id_node = NULL;

	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= RT2560_TX_ACK;

		dur = rt2560_txtime(RAL_ACK_SIZE, rt2560_ack_rate(ic, rate),
		    ic->ic_flags) + RAL_SIFS;
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		*(uint16_t *)wh->i_dur = LE_16(dur);
	}

	/* flags |= RT2560_TX_CIPHER_NONE; */
	rt2560_setup_tx_desc(sc, desc, flags, pktlen, rate, 0);

	idx = sc->txq.cur;

	dr = &sc->txq.dr_txbuf[idx];
	(void) ddi_dma_sync(dr->dr_hnd, 0, RAL_TXBUF_SIZE, DDI_DMA_SYNC_FORDEV);

	dr = &sc->txq.dr_desc;
	(void) ddi_dma_sync(dr->dr_hnd, idx * RT2560_TX_DESC_SIZE,
	    RT2560_TX_DESC_SIZE, DDI_DMA_SYNC_FORDEV);

	ral_debug(RAL_DBG_TX, "sending data frame len=%u idx=%u rate=%u\n",
	    pktlen, sc->txq.cur, rate);

	/* kick tx */
	sc->txq.queued++;
	sc->txq.cur = (sc->txq.cur + 1) % RT2560_TX_RING_COUNT;
	RAL_WRITE(sc, RT2560_TXCSR0, RT2560_KICK_TX);

	sc->sc_tx_timer = 5;

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

	freemsg(mp);
fail3:
	ieee80211_free_node(ni);
fail2:
	freemsg(m);
fail1:
	mutex_exit(&sc->txq.tx_lock);
	return (err);
}

static mblk_t *
rt2560_m_tx(void *arg, mblk_t *mp)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	if (!RAL_IS_RUNNING(sc)) {
		freemsgchain(mp);
		return (NULL);
	}
	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		ral_debug(RAL_DBG_TX, "ral: rt2560_m_tx(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (rt2560_send(ic, mp) != DDI_SUCCESS) {
			mp->b_next = next;
			freemsgchain(mp);
			return (NULL);
		}
		mp = next;
	}
	return (mp);
}

static void
rt2560_set_macaddr(struct rt2560_softc *sc, uint8_t *addr)
{
	uint32_t tmp;

	tmp = addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24;
	RAL_WRITE(sc, RT2560_CSR3, tmp);

	tmp = addr[4] | addr[5] << 8;
	RAL_WRITE(sc, RT2560_CSR4, tmp);

	ral_debug(RAL_DBG_HW,
	    "setting MAC address to " MACSTR "\n", MAC2STR(addr));
}

static void
rt2560_get_macaddr(struct rt2560_softc *sc, uint8_t *addr)
{
	uint32_t tmp;

	tmp = RAL_READ(sc, RT2560_CSR3);
	addr[0] = tmp & 0xff;
	addr[1] = (tmp >>  8) & 0xff;
	addr[2] = (tmp >> 16) & 0xff;
	addr[3] = (tmp >> 24);

	tmp = RAL_READ(sc, RT2560_CSR4);
	addr[4] = tmp & 0xff;
	addr[5] = (tmp >> 8) & 0xff;
}

static void
rt2560_update_promisc(struct rt2560_softc *sc)
{
	uint32_t tmp;

	tmp = RAL_READ(sc, RT2560_RXCSR0);
	tmp &= ~RT2560_DROP_NOT_TO_ME;
	if (!(sc->sc_rcr & RAL_RCR_PROMISC))
		tmp |= RT2560_DROP_NOT_TO_ME;

	RAL_WRITE(sc, RT2560_RXCSR0, tmp);
	ral_debug(RAL_DBG_HW, "%s promiscuous mode\n",
	    (sc->sc_rcr & RAL_RCR_PROMISC) ?  "entering" : "leaving");
}

static const char *
rt2560_get_rf(int rev)
{
	switch (rev) {
	case RT2560_RF_2522:	return ("RT2522");
	case RT2560_RF_2523:	return ("RT2523");
	case RT2560_RF_2524:	return ("RT2524");
	case RT2560_RF_2525:	return ("RT2525");
	case RT2560_RF_2525E:	return ("RT2525e");
	case RT2560_RF_2526:	return ("RT2526");
	case RT2560_RF_5222:	return ("RT5222");
	default:		return ("unknown");
	}
}

static void
rt2560_read_eeprom(struct rt2560_softc *sc)
{
	uint16_t val;
	int i;

	val = rt2560_eeprom_read(sc, RT2560_EEPROM_CONFIG0);
	sc->rf_rev =   (val >> 11) & 0x7;
	sc->hw_radio = (val >> 10) & 0x1;
	sc->led_mode = (val >> 6)  & 0x7;
	sc->rx_ant =   (val >> 4)  & 0x3;
	sc->tx_ant =   (val >> 2)  & 0x3;
	sc->nb_ant =   val & 0x3;

	/* read default values for BBP registers */
	for (i = 0; i < 16; i++) {
		val = rt2560_eeprom_read(sc, RT2560_EEPROM_BBP_BASE + i);
		sc->bbp_prom[i].reg = val >> 8;
		sc->bbp_prom[i].val = val & 0xff;
	}

	/* read Tx power for all b/g channels */
	for (i = 0; i < 14 / 2; i++) {
		val = rt2560_eeprom_read(sc, RT2560_EEPROM_TXPOWER + i);
		sc->txpow[i * 2] = val >> 8;
		sc->txpow[i * 2 + 1] = val & 0xff;
	}
}

static int
rt2560_bbp_init(struct rt2560_softc *sc)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))
	int i, ntries;

	/* wait for BBP to be ready */
	for (ntries = 0; ntries < 100; ntries++) {
		if (rt2560_bbp_read(sc, RT2560_BBP_VERSION) != 0)
			break;
		drv_usecwait(1);
	}
	if (ntries == 100) {
		ral_debug(RAL_DBG_HW, "timeout waiting for BBP\n");
		return (EIO);
	}
	/* initialize BBP registers to default values */
	for (i = 0; i < N(rt2560_def_bbp); i++) {
		rt2560_bbp_write(sc, rt2560_def_bbp[i].reg,
		    rt2560_def_bbp[i].val);
	}

	return (0);
#undef N
}

static void
rt2560_set_txantenna(struct rt2560_softc *sc, int antenna)
{
	uint32_t tmp;
	uint8_t tx;

	tx = rt2560_bbp_read(sc, RT2560_BBP_TX) & ~RT2560_BBP_ANTMASK;
	if (antenna == 1)
		tx |= RT2560_BBP_ANTA;
	else if (antenna == 2)
		tx |= RT2560_BBP_ANTB;
	else
		tx |= RT2560_BBP_DIVERSITY;

	/* need to force I/Q flip for RF 2525e, 2526 and 5222 */
	if (sc->rf_rev == RT2560_RF_2525E || sc->rf_rev == RT2560_RF_2526 ||
	    sc->rf_rev == RT2560_RF_5222)
		tx |= RT2560_BBP_FLIPIQ;

	rt2560_bbp_write(sc, RT2560_BBP_TX, tx);

	/* update values for CCK and OFDM in BBPCSR1 */
	tmp = RAL_READ(sc, RT2560_BBPCSR1) & ~0x00070007;
	tmp |= (tx & 0x7) << 16 | (tx & 0x7);
	RAL_WRITE(sc, RT2560_BBPCSR1, tmp);
}

static void
rt2560_set_rxantenna(struct rt2560_softc *sc, int antenna)
{
	uint8_t rx;

	rx = rt2560_bbp_read(sc, RT2560_BBP_RX) & ~RT2560_BBP_ANTMASK;
	if (antenna == 1)
		rx |= RT2560_BBP_ANTA;
	else if (antenna == 2)
		rx |= RT2560_BBP_ANTB;
	else
		rx |= RT2560_BBP_DIVERSITY;

	/* need to force no I/Q flip for RF 2525e and 2526 */
	if (sc->rf_rev == RT2560_RF_2525E || sc->rf_rev == RT2560_RF_2526)
		rx &= ~RT2560_BBP_FLIPIQ;

	rt2560_bbp_write(sc, RT2560_BBP_RX, rx);
}

static void
rt2560_stop(struct rt2560_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);	/* stop the watchdog */

	RAL_LOCK(sc);
	sc->sc_tx_timer = 0;

	/* abort Tx */
	RAL_WRITE(sc, RT2560_TXCSR0, RT2560_ABORT_TX);

	/* disable Rx */
	RAL_WRITE(sc, RT2560_RXCSR0, RT2560_DISABLE_RX);

	/* reset ASIC (imply reset BBP) */
	RAL_WRITE(sc, RT2560_CSR1, RT2560_RESET_ASIC);
	RAL_WRITE(sc, RT2560_CSR1, 0);

	/* disable interrupts */
	RAL_WRITE(sc, RT2560_CSR8, 0xffffffff);

	/* reset Tx and Rx rings */
	rt2560_reset_tx_ring(sc, &sc->txq);
	rt2560_reset_tx_ring(sc, &sc->prioq);
	rt2560_reset_rx_ring(sc, &sc->rxq);
	RAL_UNLOCK(sc);
}

static int
rt2560_init(struct rt2560_softc *sc)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))
	/* struct rt2560_softc *sc = priv; */
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;
	int i;

	rt2560_stop(sc);

	RAL_LOCK(sc);
	/* setup tx/rx ring */
	rt2560_ring_hwsetup(sc);

	/* initialize MAC registers to default values */
	for (i = 0; i < N(rt2560_def_mac); i++)
		RAL_WRITE(sc, rt2560_def_mac[i].reg, rt2560_def_mac[i].val);

	rt2560_set_macaddr(sc, ic->ic_macaddr);

	/* set basic rate set (will be updated later) */
	RAL_WRITE(sc, RT2560_ARSP_PLCP_1, 0x153);

	rt2560_set_txantenna(sc, sc->tx_ant);
	rt2560_set_rxantenna(sc, sc->rx_ant);
	rt2560_update_slot(ic, 1);
	rt2560_update_plcp(sc);
	rt2560_update_led(sc, 0, 0);

	RAL_WRITE(sc, RT2560_CSR1, RT2560_RESET_ASIC);
	RAL_WRITE(sc, RT2560_CSR1, RT2560_HOST_READY);

	if (rt2560_bbp_init(sc) != 0) {
		RAL_UNLOCK(sc);
		rt2560_stop(sc);
		return (DDI_FAILURE);
	}

	/* set default BSS channel */
	rt2560_set_chan(sc, ic->ic_curchan);

	/* kick Rx */
	tmp = RT2560_DROP_PHY_ERROR | RT2560_DROP_CRC_ERROR;
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		tmp |= RT2560_DROP_CTL | RT2560_DROP_VERSION_ERROR;
		if (ic->ic_opmode != IEEE80211_M_HOSTAP)
			tmp |= RT2560_DROP_TODS;
		if (!(sc->sc_rcr & RAL_RCR_PROMISC))
			tmp |= RT2560_DROP_NOT_TO_ME;

	}
	RAL_WRITE(sc, RT2560_RXCSR0, tmp);

	/* clear old FCS and Rx FIFO errors */
	(void) RAL_READ(sc, RT2560_CNT0);
	(void) RAL_READ(sc, RT2560_CNT4);

	/* clear any pending interrupts */
	RAL_WRITE(sc, RT2560_CSR7, 0xffffffff);
	/* enable interrupts */
	RAL_WRITE(sc, RT2560_CSR8, RT2560_INTR_MASK);

	RAL_UNLOCK(sc);
#undef N
	return (DDI_SUCCESS);
}

void
rt2560_watchdog(void *arg)
{
	struct rt2560_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int ntimer = 0;

	RAL_LOCK(sc);
	ic->ic_watchdog_timer = 0;

	if (!RAL_IS_RUNNING(sc)) {
		RAL_UNLOCK(sc);
		return;
	}

	if (sc->sc_tx_timer > 0) {
		if (--sc->sc_tx_timer == 0) {
			ral_debug(RAL_DBG_MSG, "tx timer timeout\n");
			RAL_UNLOCK(sc);
			(void) rt2560_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			return;
		}
	}

	if (ic->ic_state == IEEE80211_S_RUN)
		ntimer = 1;

	RAL_UNLOCK(sc);

	ieee80211_watchdog(ic);

	if (ntimer)
		ieee80211_start_watchdog(ic, ntimer);
}

static int
rt2560_m_start(void *arg)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;
	int err;

	/*
	 * initialize rt2560 hardware
	 */
	err = rt2560_init(sc);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "device configuration failed\n");
		goto fail;
	}
	sc->sc_flags |= RAL_FLAG_RUNNING;	/* RUNNING */
	return (err);

fail:
	rt2560_stop(sc);
	return (err);
}

static void
rt2560_m_stop(void *arg)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;

	(void) rt2560_stop(sc);
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */
}

static int
rt2560_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ral_debug(RAL_DBG_GLD, "rt2560_m_unicst(): " MACSTR "\n",
	    MAC2STR(macaddr));

	IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
	(void) rt2560_set_macaddr(sc, (uint8_t *)macaddr);
	(void) rt2560_init(sc);

	return (0);
}

/*ARGSUSED*/
static int
rt2560_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (0);
}

static int
rt2560_m_promisc(void *arg, boolean_t on)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;

	if (on) {
		sc->sc_rcr |= RAL_RCR_PROMISC;
		sc->sc_rcr |= RAL_RCR_MULTI;
	} else {
		sc->sc_rcr &= ~RAL_RCR_PROMISC;
		sc->sc_rcr &= ~RAL_RCR_PROMISC;
	}

	rt2560_update_promisc(sc);
	return (0);
}

/*
 * callback functions for /get/set properties
 */
static int
rt2560_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct rt2560_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	RAL_LOCK(sc);
	if (err == ENETRESET) {
		if (RAL_IS_RUNNING(sc)) {
			RAL_UNLOCK(sc);
			(void) rt2560_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			RAL_LOCK(sc);
		}
		err = 0;
	}
	RAL_UNLOCK(sc);

	return (err);
}

static int
rt2560_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct rt2560_softc *sc = arg;
	int err;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
rt2560_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct rt2560_softc *sc = arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static void
rt2560_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	RAL_LOCK(sc);
	if (err == ENETRESET) {
		if (RAL_IS_RUNNING(sc)) {
			RAL_UNLOCK(sc);
			(void) rt2560_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			RAL_LOCK(sc);
		}
	}
	RAL_UNLOCK(sc);
}

static int
rt2560_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct rt2560_softc *sc  = (struct rt2560_softc *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	ieee80211_node_t *ni = ic->ic_bss;
	struct ieee80211_rateset *rs = &ni->in_rates;

	RAL_LOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[ni->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) / 2 * 1000000;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = sc->sc_tx_nobuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = sc->sc_rx_nobuf;
		break;
	case MAC_STAT_IERRORS:
		*val = sc->sc_rx_err;
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
		*val = sc->sc_tx_err;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = sc->sc_tx_retries;
		break;
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		RAL_UNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		RAL_UNLOCK(sc);
		return (ENOTSUP);
	}
	RAL_UNLOCK(sc);

	return (0);
}

static uint_t
rt2560_intr(caddr_t arg)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	struct rt2560_softc *sc = (struct rt2560_softc *)arg;
	uint32_t r;

	RAL_LOCK(sc);

	if (!RAL_IS_RUNNING(sc)) {
		/*
		 * The hardware is not ready/present, don't touch anything.
		 * Note this can happen early on if the IRQ is shared.
		 */
		RAL_UNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	r = RAL_READ(sc, RT2560_CSR7);
	RAL_WRITE(sc, RT2560_CSR7, r);

	if (r == 0xffffffff) {
		RAL_UNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	if (!(r & RT2560_INTR_ALL)) {
		RAL_UNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	/* disable interrupts */
	RAL_WRITE(sc, RT2560_CSR8, 0xffffffff);

	if (r & RT2560_TX_DONE) {
		RAL_UNLOCK(sc);
		rt2560_tx_intr(sc);
		RAL_LOCK(sc);
	}

	if (r & RT2560_PRIO_DONE) {
		RAL_UNLOCK(sc);
		rt2560_prio_intr(sc);
		RAL_LOCK(sc);
	}

	if (r & RT2560_RX_DONE) {
		sc->sc_rx_pend = 1;
		ddi_trigger_softintr(sc->sc_softint_id);
	}

	/* re-enable interrupts */
	RAL_WRITE(sc, RT2560_CSR8, RT2560_INTR_MASK);
	RAL_UNLOCK(sc);

	return (DDI_INTR_CLAIMED);
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
rt2560_quiesce(dev_info_t *devinfo)
{
	struct rt2560_softc *sc;

	sc = ddi_get_soft_state(ral_soft_state_p, ddi_get_instance(devinfo));
	if (sc == NULL)
		return (DDI_FAILURE);

	/* abort Tx */
	RAL_WRITE(sc, RT2560_TXCSR0, RT2560_ABORT_TX);

	/* disable Rx */
	RAL_WRITE(sc, RT2560_RXCSR0, RT2560_DISABLE_RX);

	/* reset ASIC (imply reset BBP) */
	RAL_WRITE(sc, RT2560_CSR1, RT2560_RESET_ASIC);
	RAL_WRITE(sc, RT2560_CSR1, 0);

	/* disable interrupts */
	RAL_WRITE(sc, RT2560_CSR8, 0xffffffff);

	return (DDI_SUCCESS);
}

static int
rt2560_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct rt2560_softc *sc;
	struct ieee80211com *ic;
	int err, i;
	int instance;

	ddi_acc_handle_t ioh;
	caddr_t regs;
	uint16_t vendor_id, device_id, command;
	uint8_t cachelsz;
	char strbuf[32];

	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(ral_soft_state_p,
		    ddi_get_instance(devinfo));
		sc->sc_flags &= ~RAL_FLAG_SUSPENDING;
		if (RAL_IS_INITED(sc))
			(void) rt2560_init(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);

	if (ddi_soft_state_zalloc(ral_soft_state_p, instance) != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "unable to alloc soft_state_p\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(ral_soft_state_p, instance);
	ic = (ieee80211com_t *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	/* pci configuration */
	err = ddi_regs_map_setup(devinfo, 0, &regs, 0, 0, &ral_csr_accattr,
	    &ioh);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "ddi_regs_map_setup() failed");
		goto fail1;
	}

	cachelsz = ddi_get8(ioh, (uint8_t *)(regs + PCI_CONF_CACHE_LINESZ));
	if (cachelsz == 0)
		cachelsz = 0x10;
	sc->sc_cachelsz = cachelsz << 2;

	vendor_id = ddi_get16(ioh,
	    (uint16_t *)((uintptr_t)regs + PCI_CONF_VENID));
	device_id = ddi_get16(ioh,
	    (uint16_t *)((uintptr_t)regs + PCI_CONF_DEVID));

	ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): vendor 0x%x, "
	    "device id 0x%x, cache size %d\n", vendor_id, device_id, cachelsz);

	/*
	 * Enable response to memory space accesses,
	 * and enabe bus master.
	 */
	command = PCI_COMM_MAE | PCI_COMM_ME;
	ddi_put16(ioh, (uint16_t *)((uintptr_t)regs + PCI_CONF_COMM), command);
	ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
	    "set command reg to 0x%x \n", command);

	ddi_put8(ioh, (uint8_t *)(regs + PCI_CONF_LATENCY_TIMER), 0xa8);
	ddi_put8(ioh, (uint8_t *)(regs + PCI_CONF_ILINE), 0x10);
	ddi_regs_map_free(&ioh);

	/* pci i/o space */
	err = ddi_regs_map_setup(devinfo, 1,
	    &sc->sc_rbase, 0, 0, &ral_csr_accattr, &sc->sc_ioh);
	ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
	    "regs map1 = %x err=%d\n", regs, err);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "ddi_regs_map_setup() failed");
		goto fail1;
	}

	/* initialize the ral rate */
	ral_rate_init();

	/* retrieve RT2560 rev. no */
	sc->asic_rev = RAL_READ(sc, RT2560_CSR0);

	/* retrieve MAC address */
	rt2560_get_macaddr(sc, ic->ic_macaddr);

	/* retrieve RF rev. no and various other things from EEPROM */
	rt2560_read_eeprom(sc);

	ral_debug(RAL_DBG_GLD, "MAC/BBP RT2560 (rev 0x%02x), RF %s\n",
	    sc->asic_rev, rt2560_get_rf(sc->rf_rev));

	/*
	 * Allocate Tx and Rx rings.
	 */
	err = rt2560_alloc_tx_ring(sc, &sc->txq, RT2560_TX_RING_COUNT);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "could not allocate Tx ring\n");
		goto fail2;
	}
	err = rt2560_alloc_tx_ring(sc, &sc->prioq, RT2560_PRIO_RING_COUNT);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "could not allocate Prio ring\n");
		goto fail3;
	}
	err = rt2560_alloc_rx_ring(sc, &sc->rxq, RT2560_RX_RING_COUNT);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "could not allocate Rx ring\n");
		goto fail4;
	}

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->txq.tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->prioq.tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->rxq.rx_lock, NULL, MUTEX_DRIVER, NULL);


	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	ic->ic_maxrssi = 63;
	ic->ic_set_shortslot = rt2560_update_slot;
	ic->ic_xmit = rt2560_mgmt_send;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;		/* short slot time supported */

	ic->ic_caps |= IEEE80211_C_WPA; /* Support WPA/WPA2 */

#define	IEEE80211_CHAN_A	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)

	if (sc->rf_rev == RT2560_RF_5222) {
		/* set supported .11a rates */
		ic->ic_sup_rates[IEEE80211_MODE_11A] = rt2560_rateset_11a;

		/* set supported .11a channels */
		for (i = 36; i <= 64; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
		for (i = 100; i <= 140; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
		for (i = 149; i <= 161; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
	}

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = rt2560_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = rt2560_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	ic->ic_node_alloc = rt2560_node_alloc;
	ic->ic_node_free = rt2560_node_free;

	/* override state transition machine */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = rt2560_newstate;
	ic->ic_watchdog = rt2560_watchdog;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	sc->sc_rcr = 0;
	sc->sc_rx_pend = 0;
	sc->dwelltime = 300;
	sc->sc_flags &= ~RAL_FLAG_RUNNING;

	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW,
	    &sc->sc_softint_id, NULL, 0, ral_softint_handler, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "ddi_add_softintr() failed");
		goto fail5;
	}

	err = ddi_get_iblock_cookie(devinfo, 0, &sc->sc_iblock);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "Can not get iblock cookie for INT\n");
		goto fail6;
	}

	err = ddi_add_intr(devinfo, 0, NULL, NULL, rt2560_intr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_GLD,
		    "unable to add device interrupt handler\n");
		goto fail6;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "MAC version mismatch\n");
		goto fail7;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &rt2560_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		ral_debug(RAL_DBG_GLD, "ral: rt2560_attach(): "
		    "mac_register err %x\n", err);
		goto fail7;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "ral", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);

	if (err != DDI_SUCCESS)
		ral_debug(RAL_DBG_GLD, "ddi_create_minor_node() failed\n");

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	return (DDI_SUCCESS);
fail7:
	ddi_remove_intr(devinfo, 0, sc->sc_iblock);
fail6:
	ddi_remove_softintr(sc->sc_softint_id);
fail5:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->txq.tx_lock);
	mutex_destroy(&sc->prioq.tx_lock);
	mutex_destroy(&sc->rxq.rx_lock);

	rt2560_free_rx_ring(sc, &sc->rxq);
fail4:
	rt2560_free_tx_ring(sc, &sc->prioq);
fail3:
	rt2560_free_tx_ring(sc, &sc->txq);
fail2:
	ddi_regs_map_free(&sc->sc_ioh);
fail1:
	ddi_soft_state_free(ral_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_FAILURE);
}

static int
rt2560_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct rt2560_softc *sc;

	sc = ddi_get_soft_state(ral_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (RAL_IS_INITED(sc))
			(void) rt2560_stop(sc);
		sc->sc_flags |= RAL_FLAG_SUSPENDING;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	rt2560_stop(sc);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	ddi_remove_intr(devinfo, 0, sc->sc_iblock);
	ddi_remove_softintr(sc->sc_softint_id);

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);

	rt2560_free_tx_ring(sc, &sc->txq);
	rt2560_free_tx_ring(sc, &sc->prioq);
	rt2560_free_rx_ring(sc, &sc->rxq);

	ddi_regs_map_free(&sc->sc_ioh);

	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->txq.tx_lock);
	mutex_destroy(&sc->prioq.tx_lock);
	mutex_destroy(&sc->rxq.rx_lock);

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(ral_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&ral_soft_state_p,
	    sizeof (struct rt2560_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&ral_dev_ops, "ral");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&ral_dev_ops);
		ddi_soft_state_fini(&ral_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&ral_dev_ops);
		ddi_soft_state_fini(&ral_soft_state_p);
	}
	return (status);
}
