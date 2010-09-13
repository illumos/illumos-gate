/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, 2008
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
 * Ralink Technology RT2860 chipset driver
 * http://www.ralinktech.com/
 */

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <inet/common.h>
#include <sys/note.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/net80211_proto.h>
#include <sys/varargs.h>
#include <sys/pci.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <inet/wifi_ioctl.h>

#include "rt2860_reg.h"
#include "rt2860_var.h"

#define	RT2860_DBG_80211	(1 << 0)
#define	RT2860_DBG_DMA		(1 << 1)
#define	RT2860_DBG_EEPROM	(1 << 2)
#define	RT2860_DBG_FW		(1 << 3)
#define	RT2860_DBG_HW		(1 << 4)
#define	RT2860_DBG_INTR		(1 << 5)
#define	RT2860_DBG_RX		(1 << 6)
#define	RT2860_DBG_SCAN		(1 << 7)
#define	RT2860_DBG_TX		(1 << 8)
#define	RT2860_DBG_RADIO	(1 << 9)
#define	RT2860_DBG_RESUME	(1 << 10)
#define	RT2860_DBG_MSG		(1 << 11)

uint32_t rt2860_dbg_flags = 0x0;

#ifdef DEBUG
#define	RWN_DEBUG \
	rt2860_debug
#else
#define	RWN_DEBUG
#endif

static void *rt2860_soft_state_p = NULL;
static uint8_t rt2860_fw_bin [] = {
#include "fw-rt2860/rt2860.ucode"
};

static const struct ieee80211_rateset rt2860_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset rt2860_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct {
	uint32_t	reg;
	uint32_t	val;
} rt2860_def_mac[] = {
	RT2860_DEF_MAC
};

static const struct {
	uint8_t	reg;
	uint8_t	val;
} rt2860_def_bbp[] = {
	RT2860_DEF_BBP
};

static const struct rfprog {
	uint8_t		chan;
	uint32_t	r1, r2, r3, r4;
} rt2860_rf2850[] = {
	RT2860_RF2850
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t rwn_csr_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for descriptors: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t rt2860_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t rt2860_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t rt2860_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0,				/* dma_attr_addr_lo */
	0xffffffffU,			/* dma_attr_addr_hi */
	0xffffffffU,			/* dma_attr_count_max */
	16,				/* dma_attr_align */
	0x00000fff,			/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	0xffffffffU,			/* dma_attr_maxxfer */
	0xffffffffU,			/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

static uint16_t	rt2860_eeprom_read(struct rt2860_softc *, uint8_t);
static int 	rt2860_read_eeprom(struct rt2860_softc *);
const char	*rt2860_get_rf(uint8_t);
static int	rt2860_alloc_dma_mem(dev_info_t *, ddi_dma_attr_t *, size_t,
		    ddi_device_acc_attr_t *, uint_t, uint_t, struct dma_area *);
static void	rt2860_free_dma_mem(struct dma_area *);
static int	rt2860_alloc_tx_ring(struct rt2860_softc *,
		    struct rt2860_tx_ring *);
static void	rt2860_free_tx_ring(struct rt2860_softc *,
		    struct rt2860_tx_ring *);
static int	rt2860_alloc_rx_ring(struct rt2860_softc *,
		    struct rt2860_rx_ring *);
static void	rt2860_free_rx_ring(struct rt2860_softc *,
		    struct rt2860_rx_ring *);
static int	rt2860_alloc_tx_pool(struct rt2860_softc *);
static void	rt2860_free_tx_pool(struct rt2860_softc *);
static uint16_t	rt2860_txtime(int, int, uint32_t);
static int	rt2860_ack_rate(struct ieee80211com *, int);
static int	rt2860_send(ieee80211com_t *, mblk_t *, uint8_t);
static uint8_t	rt2860_maxrssi_chain(struct rt2860_softc *,
		    const struct rt2860_rxwi *);
static void	rt2860_drain_stats_fifo(struct rt2860_softc *);
static void	rt2860_tx_intr(struct rt2860_softc *, int);
static void	rt2860_rx_intr(struct rt2860_softc *);
static uint_t	rt2860_softintr(caddr_t);
static uint_t	rt2860_intr(caddr_t);
static void	rt2860_set_region_4(struct rt2860_softc *,
		    uint32_t, uint32_t, int);
static int	rt2860_load_microcode(struct rt2860_softc *);
static void	rt2860_set_macaddr(struct rt2860_softc *, const uint8_t *);
static int	rt2860_bbp_init(struct rt2860_softc *);
static uint8_t	rt2860_mcu_bbp_read(struct rt2860_softc *, uint8_t);
static void	rt2860_mcu_bbp_write(struct rt2860_softc *, uint8_t, uint8_t);
static int	rt2860_mcu_cmd(struct rt2860_softc *, uint8_t, uint16_t);
static void	rt2860_rf_write(struct rt2860_softc *, uint8_t, uint32_t);
static void	rt2860_select_chan_group(struct rt2860_softc *, int);
static void	rt2860_set_chan(struct rt2860_softc *,
		    struct ieee80211_channel *);
static void	rt2860_updateprot(struct ieee80211com *);
static void	rt2860_set_leds(struct rt2860_softc *, uint16_t);
static void	rt2860_next_scan(void *);
static void	rt2860_iter_func(void *, struct ieee80211_node *);
static void	rt2860_updateslot(struct rt2860_softc *);
static uint8_t	rt2860_rate2mcs(uint8_t);
static void	rt2860_enable_mrr(struct rt2860_softc *);
static void	rt2860_set_txpreamble(struct rt2860_softc *);
static void	rt2860_set_basicrates(struct rt2860_softc *);
static void	rt2860_set_bssid(struct rt2860_softc *, const uint8_t *);
static void	rt2860_amrr_node_init(const struct rt2860_amrr *,
		    struct rt2860_amrr_node *);
static void	rt2860_amrr_choose(struct rt2860_amrr *,
		    struct ieee80211_node *, struct rt2860_amrr_node *);
static void	rt2860_newassoc(struct ieee80211com *, struct ieee80211_node *,
		    int);
static void	rt2860_enable_tsf_sync(struct rt2860_softc *);
static int	rt2860_newstate(struct ieee80211com *,
		    enum ieee80211_state, int);
static int	rt2860_init(struct rt2860_softc *);
static void	rt2860_stop(struct rt2860_softc *);
static int	rt2860_quiesce(dev_info_t *t);

/*
 * device operations
 */
static int rt2860_attach(dev_info_t *, ddi_attach_cmd_t);
static int rt2860_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(rwn_dev_ops, nulldev, nulldev, rt2860_attach,
    rt2860_detach, nodev, NULL, D_MP, NULL, rt2860_quiesce);

static struct modldrv rwn_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Ralink RT2700/2800 driver v1.2",	/* short description */
	&rwn_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&rwn_modldrv,
	NULL
};

static int	rt2860_m_stat(void *,  uint_t, uint64_t *);
static int	rt2860_m_start(void *);
static void	rt2860_m_stop(void *);
static int	rt2860_m_promisc(void *, boolean_t);
static int	rt2860_m_multicst(void *, boolean_t, const uint8_t *);
static int	rt2860_m_unicst(void *, const uint8_t *);
static mblk_t	*rt2860_m_tx(void *, mblk_t *);
static void	rt2860_m_ioctl(void *, queue_t *, mblk_t *);
static int	rt2860_m_setprop(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num,
		    uint_t wldp_length, const void *wldp_buf);
static void	rt2860_m_propinfo(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num, mac_prop_info_handle_t prh);
static int	rt2860_m_getprop(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num, uint_t wldp_length,
		    void *wldp_buf);

static mac_callbacks_t rt2860_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	rt2860_m_stat,
	rt2860_m_start,
	rt2860_m_stop,
	rt2860_m_promisc,
	rt2860_m_multicst,
	rt2860_m_unicst,
	rt2860_m_tx,
	NULL,
	rt2860_m_ioctl,
	NULL,
	NULL,
	NULL,
	rt2860_m_setprop,
	rt2860_m_getprop,
	rt2860_m_propinfo
};

#ifdef DEBUG
void
rt2860_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & rt2860_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}
#endif

const char *
rt2860_get_rf(uint8_t rev)
{
	switch (rev) {
	case RT2860_RF_2820:	return "RT2820";
	case RT2860_RF_2850:	return "RT2850";
	case RT2860_RF_2720:	return "RT2720";
	case RT2860_RF_2750:	return "RT2750";
	default:		return "unknown";
	}
}

/*
 * Read 16 bits at address 'addr' from the serial EEPROM (either 93C46,
 * 93C66 or 93C86).
 */
static uint16_t
rt2860_eeprom_read(struct rt2860_softc *sc, uint8_t addr)
{
	int		n;
	uint16_t	val;
	uint32_t	tmp;

	/* clock C once before the first command */
	RT2860_EEPROM_CTL(sc, 0);

	RT2860_EEPROM_CTL(sc, RT2860_S);
	RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_C);
	RT2860_EEPROM_CTL(sc, RT2860_S);

	/* write start bit (1) */
	RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_D);
	RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_D | RT2860_C);

	/* write READ opcode (10) */
	RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_D);
	RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_D | RT2860_C);
	RT2860_EEPROM_CTL(sc, RT2860_S);
	RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_C);

	/* write address (A5-A0 or A7-A0) */
	n = ((RT2860_READ(sc, RT2860_PCI_EECTRL) & 0x30) == 0) ? 5 : 7;
	for (; n >= 0; n--) {
		RT2860_EEPROM_CTL(sc, RT2860_S |
		    (((addr >> n) & 1) << RT2860_SHIFT_D));
		RT2860_EEPROM_CTL(sc, RT2860_S |
		    (((addr >> n) & 1) << RT2860_SHIFT_D) | RT2860_C);
	}

	RT2860_EEPROM_CTL(sc, RT2860_S);

	/* read data Q15-Q0 */
	val = 0;
	for (n = 15; n >= 0; n--) {
		RT2860_EEPROM_CTL(sc, RT2860_S | RT2860_C);
		tmp = RT2860_READ(sc, RT2860_PCI_EECTRL);
		val |= ((tmp & RT2860_Q) >> RT2860_SHIFT_Q) << n;
		RT2860_EEPROM_CTL(sc, RT2860_S);
	}

	RT2860_EEPROM_CTL(sc, 0);

	/* clear Chip Select and clock C */
	RT2860_EEPROM_CTL(sc, RT2860_S);
	RT2860_EEPROM_CTL(sc, 0);
	RT2860_EEPROM_CTL(sc, RT2860_C);

	return (val);
}

/*
 * Add `delta' (signed) to each 4-bit sub-word of a 32-bit word.
 * Used to adjust per-rate Tx power registers.
 */
static inline uint32_t
b4inc(uint32_t b32, int8_t delta)
{
	int8_t i, b4;

	for (i = 0; i < 8; i++) {
		b4 = b32 & 0xf;
		b4 += delta;
		if (b4 < 0)
			b4 = 0;
		else if (b4 > 0xf)
			b4 = 0xf;
		b32 = b32 >> 4 | b4 << 28;
	}
	return (b32);
}

static int
rt2860_read_eeprom(struct rt2860_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	int			ridx, ant, i;
	int8_t			delta_2ghz, delta_5ghz;
	uint16_t		val;

	/* read EEPROM version */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_VERSION);
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "EEPROM rev=%d, FAE=%d\n",
	    val & 0xff, val >> 8);

	/* read MAC address */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_MAC01);
	ic->ic_macaddr[0] = val & 0xff;
	ic->ic_macaddr[1] = val >> 8;
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_MAC23);
	ic->ic_macaddr[2] = val & 0xff;
	ic->ic_macaddr[3] = val >> 8;
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_MAC45);
	ic->ic_macaddr[4] = val & 0xff;
	ic->ic_macaddr[5] = val >> 8;
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "MAC address is: %x:%x:%x:%x:%x:%x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1],
	    ic->ic_macaddr[2], ic->ic_macaddr[3],
	    ic->ic_macaddr[4], ic->ic_macaddr[5]);

	/* read country code */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_COUNTRY);
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "EEPROM region code=0x%04x\n", val);

	/* read default BBP settings */
	for (i = 0; i < 8; i++) {
		val = rt2860_eeprom_read(sc, RT2860_EEPROM_BBP_BASE + i);
		sc->bbp[i].val = val & 0xff;
		sc->bbp[i].reg = val >> 8;
		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "BBP%d=0x%02x\n",
		    sc->bbp[i].reg, sc->bbp[i].val);
	}

	/* read RF frequency offset from EEPROM */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_FREQ_LEDS);
	sc->freq = ((val & 0xff) != 0xff) ? val & 0xff : 0;
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "EEPROM freq offset %d\n", sc->freq & 0xff);

	if ((sc->leds = val >> 8) != 0xff) {
		/* read LEDs operating mode */
		sc->led[0] = rt2860_eeprom_read(sc, RT2860_EEPROM_LED1);
		sc->led[1] = rt2860_eeprom_read(sc, RT2860_EEPROM_LED2);
		sc->led[2] = rt2860_eeprom_read(sc, RT2860_EEPROM_LED3);
	} else {
		/* broken EEPROM, use default settings */
		sc->leds = 0x01;
		sc->led[0] = 0x5555;
		sc->led[1] = 0x2221;
		sc->led[2] = 0xa9f8;
	}
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "EEPROM LED mode=0x%02x, LEDs=0x%04x/0x%04x/0x%04x\n",
	    sc->leds, sc->led[0], sc->led[1], sc->led[2]);

	/* read RF information */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_ANTENNA);
	if (val == 0xffff) {
		/* broken EEPROM, default to RF2820 1T2R */
		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "invalid EEPROM antenna info, using default\n");
		sc->rf_rev = RT2860_RF_2820;
		sc->ntxchains = 1;
		sc->nrxchains = 2;
	} else {
		sc->rf_rev = (val >> 8) & 0xf;
		sc->ntxchains = (val >> 4) & 0xf;
		sc->nrxchains = val & 0xf;
	}
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "EEPROM RF rev=0x%02x chains=%dT%dR\n",
	    sc->rf_rev, sc->ntxchains, sc->nrxchains);

	/* check if RF supports automatic Tx access gain control */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_CONFIG);
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "EEPROM CFG 0x%04x\n", val);
	if ((val & 0xff) != 0xff)
		sc->calib_2ghz = sc->calib_5ghz = 0; /* XXX (val >> 1) & 1 */;

	if (sc->sc_flags & RT2860_ADVANCED_PS) {
		/* read PCIe power save level */
		val = rt2860_eeprom_read(sc, RT2860_EEPROM_PCIE_PSLEVEL);
		if ((val & 0xff) != 0xff) {
			sc->pslevel = val & 0x3;
			val = rt2860_eeprom_read(sc, RT2860_EEPROM_REV);
			if (val >> 8 != 0x92 || !(val & 0x80))
				sc->pslevel = MIN(sc->pslevel, 1);
			RWN_DEBUG(RT2860_DBG_EEPROM,
			    "rwn: rt2860_read_eeprom(): "
			    "EEPROM PCIe PS Level=%d\n",
			    sc->pslevel);
		}
	}
	/* read power settings for 2GHz channels */
	for (i = 0; i < 14; i += 2) {
		val = rt2860_eeprom_read(sc,
		    RT2860_EEPROM_PWR2GHZ_BASE1 + i / 2);
		sc->txpow1[i + 0] = (int8_t)(val & 0xff);
		sc->txpow1[i + 1] = (int8_t)(val >> 8);

		val = rt2860_eeprom_read(sc,
		    RT2860_EEPROM_PWR2GHZ_BASE2 + i / 2);
		sc->txpow2[i + 0] = (int8_t)(val & 0xff);
		sc->txpow2[i + 1] = (int8_t)(val >> 8);
	}
	/* fix broken Tx power entries */
	for (i = 0; i < 14; i++) {
		if (sc->txpow1[i] < 0 || sc->txpow1[i] > 31)
			sc->txpow1[i] = 5;
		if (sc->txpow2[i] < 0 || sc->txpow2[i] > 31)
			sc->txpow2[i] = 5;
		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "chan %d: power1=%d, power2=%d\n",
		    rt2860_rf2850[i].chan, sc->txpow1[i], sc->txpow2[i]);
	}
	/* read power settings for 5GHz channels */
	for (i = 0; i < 36; i += 2) {
		val = rt2860_eeprom_read(sc,
		    RT2860_EEPROM_PWR5GHZ_BASE1 + i / 2);
		sc->txpow1[i + 14] = (int8_t)(val & 0xff);
		sc->txpow1[i + 15] = (int8_t)(val >> 8);

		val = rt2860_eeprom_read(sc,
		    RT2860_EEPROM_PWR5GHZ_BASE2 + i / 2);
		sc->txpow2[i + 14] = (int8_t)(val & 0xff);
		sc->txpow2[i + 15] = (int8_t)(val >> 8);
	}
	/* fix broken Tx power entries */
	for (i = 0; i < 36; i++) {
		if (sc->txpow1[14 + i] < -7 || sc->txpow1[14 + i] > 15)
			sc->txpow1[14 + i] = 5;
		if (sc->txpow2[14 + i] < -7 || sc->txpow2[14 + i] > 15)
			sc->txpow2[14 + i] = 5;
		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "chan %d: power1=%d, power2=%d\n",
		    rt2860_rf2850[14 + i].chan, sc->txpow1[14 + i],
		    sc->txpow2[14 + i]);
	}

	/* read Tx power compensation for each Tx rate */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_DELTAPWR);
	delta_2ghz = delta_5ghz = 0;
	if ((val & 0xff) != 0xff && (val & 0x80)) {
		delta_2ghz = val & 0xf;
		if (!(val & 0x40))	/* negative number */
			delta_2ghz = -delta_2ghz;
	}
	val >>= 8;
	if ((val & 0xff) != 0xff && (val & 0x80)) {
		delta_5ghz = val & 0xf;
		if (!(val & 0x40))	/* negative number */
			delta_5ghz = -delta_5ghz;
	}
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "power compensation=%d (2GHz), %d (5GHz) \n",
	    delta_2ghz, delta_5ghz);

	for (ridx = 0; ridx < 5; ridx++) {
		uint32_t	reg;

		val = rt2860_eeprom_read(sc, RT2860_EEPROM_RPWR + ridx);
		reg = (uint32_t)val << 16;
		val = rt2860_eeprom_read(sc, RT2860_EEPROM_RPWR + ridx + 1);
		reg |= val;

		sc->txpow20mhz[ridx] = reg;
		sc->txpow40mhz_2ghz[ridx] = b4inc(reg, delta_2ghz);
		sc->txpow40mhz_5ghz[ridx] = b4inc(reg, delta_5ghz);

		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "ridx %d: power 20MHz=0x%08x, 40MHz/2GHz=0x%08x, "
		    "40MHz/5GHz=0x%08x\n", ridx, sc->txpow20mhz[ridx],
		    sc->txpow40mhz_2ghz[ridx], sc->txpow40mhz_5ghz[ridx]);
	}

	/* read factory-calibrated samples for temperature compensation */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI1_2GHZ);
	sc->tssi_2ghz[0] = val & 0xff;	/* [-4] */
	sc->tssi_2ghz[1] = val >> 8;	/* [-3] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI2_2GHZ);
	sc->tssi_2ghz[2] = val & 0xff;	/* [-2] */
	sc->tssi_2ghz[3] = val >> 8;	/* [-1] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI3_2GHZ);
	sc->tssi_2ghz[4] = val & 0xff;	/* [+0] */
	sc->tssi_2ghz[5] = val >> 8;	/* [+1] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI4_2GHZ);
	sc->tssi_2ghz[6] = val & 0xff;	/* [+2] */
	sc->tssi_2ghz[7] = val >> 8;	/* [+3] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI5_2GHZ);
	sc->tssi_2ghz[8] = val & 0xff;	/* [+4] */
	sc->step_2ghz = val >> 8;
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "TSSI 2GHz: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
	    "0x%02x 0x%02x step=%d\n", sc->tssi_2ghz[0], sc->tssi_2ghz[1],
	    sc->tssi_2ghz[2], sc->tssi_2ghz[3], sc->tssi_2ghz[4],
	    sc->tssi_2ghz[5], sc->tssi_2ghz[6], sc->tssi_2ghz[7],
	    sc->tssi_2ghz[8], sc->step_2ghz);
	/* check that ref value is correct, otherwise disable calibration */
	if (sc->tssi_2ghz[4] == 0xff)
		sc->calib_2ghz = 0;

	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI1_5GHZ);
	sc->tssi_5ghz[0] = val & 0xff;	/* [-4] */
	sc->tssi_5ghz[1] = val >> 8;	/* [-3] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI2_5GHZ);
	sc->tssi_5ghz[2] = val & 0xff;	/* [-2] */
	sc->tssi_5ghz[3] = val >> 8;	/* [-1] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI3_5GHZ);
	sc->tssi_5ghz[4] = val & 0xff;	/* [+0] */
	sc->tssi_5ghz[5] = val >> 8;	/* [+1] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI4_5GHZ);
	sc->tssi_5ghz[6] = val & 0xff;	/* [+2] */
	sc->tssi_5ghz[7] = val >> 8;	/* [+3] */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_TSSI5_5GHZ);
	sc->tssi_5ghz[8] = val & 0xff;	/* [+4] */
	sc->step_5ghz = val >> 8;
	RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
	    "TSSI 5GHz: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
	    "0x%02x 0x%02x step=%d\n", sc->tssi_5ghz[0], sc->tssi_5ghz[1],
	    sc->tssi_5ghz[2], sc->tssi_5ghz[3], sc->tssi_5ghz[4],
	    sc->tssi_5ghz[5], sc->tssi_5ghz[6], sc->tssi_5ghz[7],
	    sc->tssi_5ghz[8], sc->step_5ghz);
	/* check that ref value is correct, otherwise disable calibration */
	if (sc->tssi_5ghz[4] == 0xff)
		sc->calib_5ghz = 0;

	/* read RSSI offsets and LNA gains from EEPROM */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_RSSI1_2GHZ);
	sc->rssi_2ghz[0] = val & 0xff;	/* Ant A */
	sc->rssi_2ghz[1] = val >> 8;	/* Ant B */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_RSSI2_2GHZ);
	sc->rssi_2ghz[2] = val & 0xff;	/* Ant C */
	sc->lna[2] = val >> 8;		/* channel group 2 */

	val = rt2860_eeprom_read(sc, RT2860_EEPROM_RSSI1_5GHZ);
	sc->rssi_5ghz[0] = val & 0xff;	/* Ant A */
	sc->rssi_5ghz[1] = val >> 8;	/* Ant B */
	val = rt2860_eeprom_read(sc, RT2860_EEPROM_RSSI2_5GHZ);
	sc->rssi_5ghz[2] = val & 0xff;	/* Ant C */
	sc->lna[3] = val >> 8;		/* channel group 3 */

	val = rt2860_eeprom_read(sc, RT2860_EEPROM_LNA);
	sc->lna[0] = val & 0xff;	/* channel group 0 */
	sc->lna[1] = val >> 8;		/* channel group 1 */

	/* fix broken 5GHz LNA entries */
	if (sc->lna[2] == 0 || sc->lna[2] == 0xff) {
		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "invalid LNA for channel group %d\n", 2);
		sc->lna[2] = sc->lna[1];
	}
	if (sc->lna[3] == 0 || sc->lna[3] == 0xff) {
		RWN_DEBUG(RT2860_DBG_EEPROM, "rwn: rt2860_read_eeprom(): "
		    "invalid LNA for channel group %d\n", 3);
		sc->lna[3] = sc->lna[1];
	}

	/* fix broken RSSI offset entries */
	for (ant = 0; ant < 3; ant++) {
		if (sc->rssi_2ghz[ant] < -10 || sc->rssi_2ghz[ant] > 10) {
			RWN_DEBUG(RT2860_DBG_EEPROM,
			    "rwn: rt2860_read_eeprom(): "
			    "invalid RSSI%d offset: %d (2GHz)\n",
			    ant + 1, sc->rssi_2ghz[ant]);
			sc->rssi_2ghz[ant] = 0;
		}
		if (sc->rssi_5ghz[ant] < -10 || sc->rssi_5ghz[ant] > 10) {
			RWN_DEBUG(RT2860_DBG_EEPROM,
			    "rwn: rt2860_read_eeprom(): "
			    "invalid RSSI%d offset: %d (2GHz)\n",
			    ant + 1, sc->rssi_5ghz[ant]);
			sc->rssi_5ghz[ant] = 0;
		}
	}

	return (RT2860_SUCCESS);
}

/*
 * Allocate an DMA memory and a DMA handle for accessing it
 */
static int
rt2860_alloc_dma_mem(dev_info_t *devinfo, ddi_dma_attr_t *dma_attr,
	size_t memsize, ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
	uint_t bind_flags, struct dma_area *dma_p)
{
	int	err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rwn_allo_dma_mem(): "
		    "failed to alloc handle\n");
		goto fail1;
	}

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    alloc_flags, DDI_DMA_SLEEP, NULL, &dma_p->mem_va,
	    &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rwn_alloc_dma_mem(): "
		    "failed to alloc mem\n");
		goto fail2;
	}

	/*
	 * Bind the two together
	 */
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    dma_p->mem_va, dma_p->alength, bind_flags,
	    DDI_DMA_SLEEP, NULL, &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rwn_alloc_dma_mem(): "
		    "failed to bind handle\n");
		goto fail3;
	}

	if (dma_p->ncookies != 1) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rwn_alloc_dma_mem(): "
		    "failed to alloc cookies\n");
		goto fail4;
	}

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;
	return (DDI_SUCCESS);

fail4:
	(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
fail3:
	ddi_dma_mem_free(&dma_p->acc_hdl);
fail2:
	ddi_dma_free_handle(&dma_p->dma_hdl);
fail1:
	return (err);
}

static void
rt2860_free_dma_mem(struct dma_area *dma_p)
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

/*ARGSUSED*/
static int
rt2860_alloc_tx_ring(struct rt2860_softc *sc, struct rt2860_tx_ring *ring)
{
	int	size, err;

	size = RT2860_TX_RING_COUNT * sizeof (struct rt2860_txd);

	err = rt2860_alloc_dma_mem(sc->sc_dev, &rt2860_dma_attr, size,
	    &rt2860_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->txdesc_dma);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rt2860_alloc_tx_ring(): "
		    "failed to alloc dma mem\n");
		goto fail1;
	}

	ring->txd = (struct rt2860_txd *)ring->txdesc_dma.mem_va;
	ring->paddr = ring->txdesc_dma.cookie.dmac_address;

	ring->cur = 0;
	ring->next = 0;
	ring->queued = 0;

	(void) bzero(ring->txd, size);
	RT2860_DMA_SYNC(ring->txdesc_dma, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
fail1:
	return (err);
}

void
rt2860_reset_tx_ring(struct rt2860_softc *sc, struct rt2860_tx_ring *ring)
{
	struct rt2860_tx_data *data;
	int i;

	for (i = 0; i < RT2860_TX_RING_COUNT; i++) {
		ring->txd[i].sdl0 &= ~LE_16(RT2860_TX_DDONE);

		if ((data = ring->data[i]) == NULL)
			continue;	/* nothing mapped in this slot */

		/* by pass if it's quiesced */
		if (!(sc->sc_flags & RT2860_F_QUIESCE))
			RT2860_DMA_SYNC(data->txbuf_dma, DDI_DMA_SYNC_FORDEV);

		if (data->ni != NULL) {
			ieee80211_free_node(data->ni);
			data->ni = NULL;	/* node already freed */
		}

		SLIST_INSERT_HEAD(&sc->data_pool, data, next);
		ring->data[i] = NULL;
	}

	/* by pass if it's quiesced */
	if (!(sc->sc_flags & RT2860_F_QUIESCE))
		RT2860_DMA_SYNC(ring->txdesc_dma, DDI_DMA_SYNC_FORDEV);

	ring->queued = 0;
	ring->cur = ring->next = 0;
}

/*ARGSUSED*/
static void
rt2860_free_tx_ring(struct rt2860_softc *sc, struct rt2860_tx_ring *ring)
{
	if (ring->txd != NULL) {
		rt2860_free_dma_mem(&ring->txdesc_dma);
	}
}

static int
rt2860_alloc_rx_ring(struct rt2860_softc *sc, struct rt2860_rx_ring *ring)
{
	struct rt2860_rx_data	*data;
	struct rt2860_rxd	*rxd;
	int			i, err, size, datalen;

	size = RT2860_RX_RING_COUNT * sizeof (struct rt2860_rxd);

	err = rt2860_alloc_dma_mem(sc->sc_dev, &rt2860_dma_attr, size,
	    &rt2860_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->rxdesc_dma);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rt2860_alloc_rx_ring(): "
		    "failed to alloc dma mem\n");
		goto fail1;
	}

	ring->rxd = (struct rt2860_rxd *)ring->rxdesc_dma.mem_va;
	ring->paddr = ring->rxdesc_dma.cookie.dmac_address;
	bzero(ring->rxd, size);

	/*
	 * Pre-allocate Rx buffers and populate Rx ring.
	 */
	datalen = RT2860_RX_RING_COUNT * sizeof (struct rt2860_rx_data);
	bzero(ring->data, datalen);
	for (i = 0; i < RT2860_RX_RING_COUNT; i++) {
		rxd = &ring->rxd[i];
		data = &ring->data[i];
		/* alloc DMA memory */
		(void) rt2860_alloc_dma_mem(sc->sc_dev, &rt2860_dma_attr,
		    sc->sc_dmabuf_size,
		    &rt2860_buf_accattr,
		    DDI_DMA_STREAMING,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &data->rxbuf_dma);
		rxd->sdp0 = LE_32(data->rxbuf_dma.cookie.dmac_address);
		rxd->sdl0 = LE_16(sc->sc_dmabuf_size);
	}

	ring->cur = 0;

	RT2860_DMA_SYNC(ring->rxdesc_dma, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
fail2:
	rt2860_free_dma_mem(&ring->rxdesc_dma);
fail1:
	return (err);
}

/*ARGSUSED*/
void
rt2860_reset_rx_ring(struct rt2860_softc *sc, struct rt2860_rx_ring *ring)
{
	int i;

	for (i = 0; i < RT2860_RX_RING_COUNT; i++)
		ring->rxd[i].sdl0 &= ~LE_16(RT2860_RX_DDONE);

	RT2860_DMA_SYNC(ring->rxdesc_dma, DDI_DMA_SYNC_FORDEV);

	ring->cur = 0;
}

/*ARGSUSED*/
static void
rt2860_free_rx_ring(struct rt2860_softc *sc, struct rt2860_rx_ring *ring)
{
	struct rt2860_rx_data	*data;
	int			i, count;

	if (ring->rxd != NULL)
		rt2860_free_dma_mem(&ring->rxdesc_dma);

	count = RT2860_RX_RING_COUNT;
	if (ring->data != NULL) {
		for (i = 0; i < count; i++) {
			data = &ring->data[i];
			rt2860_free_dma_mem(&data->rxbuf_dma);
		}
	}
}

static int
rt2860_alloc_tx_pool(struct rt2860_softc *sc)
{
	struct rt2860_tx_data	*data;
	int			i, err, size;

	size = RT2860_TX_POOL_COUNT * sizeof (struct rt2860_txwi);

	/* init data_pool early in case of failure.. */
	SLIST_INIT(&sc->data_pool);

	err = rt2860_alloc_dma_mem(sc->sc_dev, &rt2860_dma_attr, size,
	    &rt2860_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->txpool_dma);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rt2860_alloc_tx_pool(): "
		    "failed to alloc dma mem\n");
		goto fail1;
	}

	sc->txwi = (struct rt2860_txwi *)sc->txpool_dma.mem_va;
	(void) bzero(sc->txwi, size);
	RT2860_DMA_SYNC(sc->txpool_dma, DDI_DMA_SYNC_FORDEV);

	for (i = 0; i < RT2860_TX_POOL_COUNT; i++) {
		data = &sc->data[i];

		err = rt2860_alloc_dma_mem(sc->sc_dev, &rt2860_dma_attr,
		    sc->sc_dmabuf_size,
		    &rt2860_buf_accattr, DDI_DMA_CONSISTENT,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    &data->txbuf_dma);
		if (err != DDI_SUCCESS) {
			RWN_DEBUG(RT2860_DBG_DMA,
			    "rwn: rt2860_alloc_tx_pool(): "
			    "failed to alloc dma mem\n");
			goto fail2;
		}
		data->txwi = &sc->txwi[i];
		data->paddr = sc->txpool_dma.cookie.dmac_address +
		    i * sizeof (struct rt2860_txwi);

		SLIST_INSERT_HEAD(&sc->data_pool, data, next);
	}
	return (DDI_SUCCESS);
fail2:
	rt2860_free_dma_mem(&sc->txpool_dma);
fail1:
	return (err);
}

static void
rt2860_free_tx_pool(struct rt2860_softc *sc)
{
	struct rt2860_tx_data	*data;
	int	i;

	if (sc->txwi != NULL) {
		rt2860_free_dma_mem(&sc->txpool_dma);
	}

	for (i = 0; i < RT2860_TX_POOL_COUNT; i++) {
		data = &sc->data[i];
		rt2860_free_dma_mem(&data->txbuf_dma);
	}
}

/* quickly determine if a given rate is CCK or OFDM */
#define	RT2860_RATE_IS_OFDM(rate) ((rate) >= 12 && (rate) != 22)

#define	RT2860_ACK_SIZE		14	/* 10 + 4(FCS) */
#define	RT2860_SIFS_TIME	10

static uint8_t
rt2860_rate2mcs(uint8_t rate)
{
	switch (rate) {
	/* CCK rates */
	case 2:
		return (0);
	case 4:
		return (1);
	case 11:
		return (2);
	case 22:
		return (3);
	/* OFDM rates */
	case 12:
		return (0);
	case 18:
		return (1);
	case 24:
		return (2);
	case 36:
		return (3);
	case 48:
		return (4);
	case 72:
		return (5);
	case 96:
		return (6);
	case 108:
		return (7);
	}

	return (0);	/* shouldn't get there */
}

/*
 * Return the expected ack rate for a frame transmitted at rate `rate'.
 */
static int
rt2860_ack_rate(struct ieee80211com *ic, int rate)
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
rt2860_txtime(int len, int rate, uint32_t flags)
{
	uint16_t	txtime;

	if (RT2860_RATE_IS_OFDM(rate)) {
		/* IEEE Std 802.11g-2003, pp. 44 */
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

static int
rt2860_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)ic;
	struct rt2860_tx_ring	*ring;
	struct rt2860_tx_data	*data;
	struct rt2860_txd	*txd;
	struct rt2860_txwi	*txwi;
	struct ieee80211_frame	*wh;
	struct ieee80211_node	*ni;
	int			qid, off, rate, err;
	int			mblen, pktlen;
	uint_t			hdrlen;
	uint8_t			mcs, pid, qsel;
	uint16_t		dur;
	mblk_t			*m, *m0;

	err = DDI_SUCCESS;

	mutex_enter(&sc->sc_txlock);
	if (RT2860_IS_SUSPEND(sc)) {
		err = ENXIO;
		goto fail1;
	}

	if ((type & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_DATA)
		qid = sc->mgtqid;
	else
		qid = EDCA_AC_BE;
	ring = &sc->txq[qid];

	if (SLIST_EMPTY(&sc->data_pool) || (ring->queued > 15)) {
		sc->sc_need_sched = 1;
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail1;
	}

	/* the data pool contains at least one element, pick the first */
	data = SLIST_FIRST(&sc->data_pool);

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) {
		RWN_DEBUG(RT2860_DBG_TX, "rwn: rt2860_send():"
		    "rt2860_mgmt_send: can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail1;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) bcopy(m0->b_rptr, m->b_rptr + off, mblen);
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

	if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA)
		(void) ieee80211_encap(ic, m, ni);

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		struct ieee80211_key *k;
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			sc->sc_tx_err++;
			err = DDI_FAILURE;
			goto fail3;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}
	pktlen = msgdsize(m);
	hdrlen = sizeof (*wh);

	/* pickup a rate */
	if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
	    ((type & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_DATA))
		rate = ni->in_rates.ir_rates[0];
	else {
		if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE)
			rate = ic->ic_fixed_rate;
		else
			rate = ni->in_rates.ir_rates[ni->in_txrate];
	}
	rate &= IEEE80211_RATE_VAL;

	/* get MCS code from rate */
	mcs = rt2860_rate2mcs(rate);

	/* setup TX Wireless Information */
	txwi = data->txwi;
	(void) bzero(txwi, sizeof (struct rt2860_txwi));
	txwi->wcid = (type == IEEE80211_FC0_TYPE_DATA) ?
	    RT2860_AID2WCID(ni->in_associd) : 0xff;
	txwi->len = LE_16(pktlen);
	if (!RT2860_RATE_IS_OFDM(rate)) {
		txwi->phy = LE_16(RT2860_PHY_CCK);
		if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
			mcs |= RT2860_PHY_SHPRE;
	} else
		txwi->phy = LE_16(RT2860_PHY_OFDM);
	txwi->phy |= LE_16(mcs);

	/*
	 * We store the MCS code into the driver-private PacketID field.
	 * The PacketID is latched into TX_STAT_FIFO when Tx completes so
	 * that we know at which initial rate the frame was transmitted.
	 * We add 1 to the MCS code because setting the PacketID field to
	 * 0 means that we don't want feedback in TX_STAT_FIFO.
	 */
	pid = (mcs + 1) & 0xf;
	txwi->len |= LE_16(pid << RT2860_TX_PID_SHIFT);

	/* check if RTS/CTS or CTS-to-self protection is required */
	if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
	    (pktlen + IEEE80211_CRC_LEN > ic->ic_rtsthreshold ||
	    ((ic->ic_flags &
	    IEEE80211_F_USEPROT) && RT2860_RATE_IS_OFDM(rate))))
		txwi->txop = RT2860_TX_TXOP_HT;
	else
		txwi->txop = RT2860_TX_TXOP_BACKOFF;

	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		txwi->xflags |= RT2860_TX_ACK;

		dur = rt2860_txtime(RT2860_ACK_SIZE, rt2860_ack_rate(ic, rate),
		    ic->ic_flags) + sc->sifs;
		*(uint16_t *)wh->i_dur = LE_16(dur);
	}

	/* copy and trim 802.11 header */
	bcopy(wh, &txwi->wh, hdrlen);
	m->b_rptr += hdrlen;
	bcopy(m->b_rptr, data->txbuf_dma.mem_va, pktlen - hdrlen);

	qsel = (qid < EDCA_NUM_AC) ? RT2860_TX_QSEL_EDCA : RT2860_TX_QSEL_MGMT;

	/* first segment is TXWI + 802.11 header */
	txd = &ring->txd[ring->cur];
	txd->sdp0 = LE_32(data->paddr);
	txd->sdl0 = LE_16(16 + hdrlen);
	txd->flags = qsel;

	/* finalize last segment */
	txd->sdp1 = LE_32(data->txbuf_dma.cookie.dmac_address);
	txd->sdl1 = LE_16(pktlen - hdrlen | RT2860_TX_LS1);

	/* remove from the free pool and link it into the SW Tx slot */
	SLIST_REMOVE_HEAD(&sc->data_pool, next);
	data->ni = ieee80211_ref_node(ni);
	ring->data[ring->cur] = data;

	(void) ddi_dma_sync(sc->txpool_dma.dma_hdl,
	    _PTRDIFF(txwi, sc->txwi),
	    (hdrlen + 16 + 2),
	    DDI_DMA_SYNC_FORDEV);
	RT2860_DMA_SYNC(data->txbuf_dma, DDI_DMA_SYNC_FORDEV);
	RT2860_DMA_SYNC(ring->txdesc_dma, DDI_DMA_SYNC_FORDEV);

	RWN_DEBUG(RT2860_DBG_TX, "rwn: rt2860_send():"
	    "sending frame qid=%d wcid=%d rate=%d cur = %x\n",
	    qid, txwi->wcid, rate, ring->cur);

	ring->queued++;
	ring->cur = (ring->cur + 1) % RT2860_TX_RING_COUNT;

	/* kick Tx */
	RT2860_WRITE(sc, RT2860_TX_CTX_IDX(qid), ring->cur);

	sc->sc_tx_timer = 5;

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

fail3:
	ieee80211_free_node(ni);
fail2:
	freemsg(m);
fail1:
	if ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    err == DDI_SUCCESS)
		freemsg(mp);
	mutex_exit(&sc->sc_txlock);
	return (err);
}

/*
 * This function is called periodically (every 200ms) during scanning to
 * switch from one channel to another.
 */
static void
rt2860_next_scan(void *arg)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		(void) ieee80211_next_scan(ic);
}

static void
rt2860_updateslot(struct rt2860_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	tmp = RT2860_READ(sc, RT2860_BKOFF_SLOT_CFG);
	tmp &= ~0xff;
	tmp |= (ic->ic_flags & IEEE80211_F_SHSLOT) ? 9 : 20;
	RT2860_WRITE(sc, RT2860_BKOFF_SLOT_CFG, tmp);
}

static void
rt2860_iter_func(void *arg, struct ieee80211_node *ni)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)arg;
	uint8_t wcid;

	wcid = RT2860_AID2WCID(ni->in_associd);
	rt2860_amrr_choose(&sc->amrr, ni, &sc->amn[wcid]);
}

static void
rt2860_updatestats(void *arg)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_opmode == IEEE80211_M_STA)
		rt2860_iter_func(sc, ic->ic_bss);
	else
		ieee80211_iterate_nodes(&ic->ic_sta, rt2860_iter_func, arg);

	sc->sc_rssadapt_id = timeout(rt2860_updatestats, (void *)sc,
	    drv_usectohz(500 * 1000));
}

static void
rt2860_enable_mrr(struct rt2860_softc *sc)
{
#define	CCK(mcs)	(mcs)
#define	OFDM(mcs)	((uint32_t)1 << 3 | (mcs))
	RT2860_WRITE(sc, RT2860_LG_FBK_CFG0,
	    OFDM(6) << 28 |	/* 54->48 */
	    OFDM(5) << 24 |	/* 48->36 */
	    OFDM(4) << 20 |	/* 36->24 */
	    OFDM(3) << 16 |	/* 24->18 */
	    OFDM(2) << 12 |	/* 18->12 */
	    OFDM(1) <<  8 |	/* 12-> 9 */
	    OFDM(0) <<  4 |	/*  9-> 6 */
	    OFDM(0));		/*  6-> 6 */

	RT2860_WRITE(sc, RT2860_LG_FBK_CFG1,
	    CCK(2) << 12 |	/* 11->5.5 */
	    CCK(1) <<  8 |	/* 5.5-> 2 */
	    CCK(0) <<  4 |	/*   2-> 1 */
	    CCK(0));		/*   1-> 1 */
#undef OFDM
#undef CCK
}

static void
rt2860_set_txpreamble(struct rt2860_softc *sc)
{
	uint32_t tmp;

	tmp = RT2860_READ(sc, RT2860_AUTO_RSP_CFG);
	tmp &= ~RT2860_CCK_SHORT_EN;
	if (sc->sc_ic.ic_flags & IEEE80211_F_SHPREAMBLE)
		tmp |= RT2860_CCK_SHORT_EN;
	RT2860_WRITE(sc, RT2860_AUTO_RSP_CFG, tmp);
}

static void
rt2860_set_bssid(struct rt2860_softc *sc, const uint8_t *bssid)
{
	RT2860_WRITE(sc, RT2860_MAC_BSSID_DW0,
	    bssid[0] | bssid[1] << 8 | bssid[2] << 16 | bssid[3] << 24);
	RT2860_WRITE(sc, RT2860_MAC_BSSID_DW1,
	    bssid[4] | bssid[5] << 8);
}

static void
rt2860_set_basicrates(struct rt2860_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	/* set basic rates mask */
	if (ic->ic_curmode == IEEE80211_MODE_11B)
		RT2860_WRITE(sc, RT2860_LEGACY_BASIC_RATE, 0x003);
	else if (ic->ic_curmode == IEEE80211_MODE_11A)
		RT2860_WRITE(sc, RT2860_LEGACY_BASIC_RATE, 0x150);
	else	/* 11g */
		RT2860_WRITE(sc, RT2860_LEGACY_BASIC_RATE, 0x15f);
}

static void
rt2860_amrr_node_init(const struct rt2860_amrr *amrr,
    struct rt2860_amrr_node *amn)
{
	amn->amn_success = 0;
	amn->amn_recovery = 0;
	amn->amn_txcnt = amn->amn_retrycnt = 0;
	amn->amn_success_threshold = amrr->amrr_min_success_threshold;
}

static void
rt2860_amrr_choose(struct rt2860_amrr *amrr, struct ieee80211_node *ni,
    struct rt2860_amrr_node *amn)
{
#define	RV(rate)	((rate) & IEEE80211_RATE_VAL)
#define	is_success(amn)	\
	((amn)->amn_retrycnt < (amn)->amn_txcnt / 10)
#define	is_failure(amn)	\
	((amn)->amn_retrycnt > (amn)->amn_txcnt / 3)
#define	is_enough(amn)		\
	((amn)->amn_txcnt > 10)
#define	is_min_rate(ni)		\
	((ni)->in_txrate == 0)
#define	is_max_rate(ni)		\
	((ni)->in_txrate == (ni)->in_rates.ir_nrates - 1)
#define	increase_rate(ni)	\
	((ni)->in_txrate++)
#define	decrease_rate(ni)	\
	((ni)->in_txrate--)
#define	reset_cnt(amn)		\
	{ (amn)->amn_txcnt = (amn)->amn_retrycnt = 0; }

	int need_change = 0;

	if (is_success(amn) && is_enough(amn)) {
		amn->amn_success++;
		if (amn->amn_success >= amn->amn_success_threshold &&
		    !is_max_rate(ni)) {
			amn->amn_recovery = 1;
			amn->amn_success = 0;
			increase_rate(ni);
			RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_amrr_choose(): "
			    "increase rate = %d, #tx = %d, #retries = %d\n",
			    RV(ni->in_rates.ir_rates[ni->in_txrate]),
			    amn->amn_txcnt, amn->amn_retrycnt);
			need_change = 1;
		} else {
			amn->amn_recovery = 0;
		}
	} else if (is_failure(amn)) {
		amn->amn_success = 0;
		if (!is_min_rate(ni)) {
			if (amn->amn_recovery) {
				amn->amn_success_threshold *= 2;
				if (amn->amn_success_threshold >
				    amrr->amrr_max_success_threshold)
					amn->amn_success_threshold =
					    amrr->amrr_max_success_threshold;
			} else {
				amn->amn_success_threshold =
				    amrr->amrr_min_success_threshold;
			}
			decrease_rate(ni);
			RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_amrr_choose(): "
			    "decrease rate = %d, #tx = %d, #retries = %d\n",
			    RV(ni->in_rates.ir_rates[ni->in_txrate]),
			    amn->amn_txcnt, amn->amn_retrycnt);
			need_change = 1;
		}
		amn->amn_recovery = 0;
	}

	if (is_enough(amn) || need_change)
		reset_cnt(amn);
#undef RV
}

static void
rt2860_newassoc(struct ieee80211com *ic, struct ieee80211_node *in, int isnew)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)ic;
	uint32_t off;
	uint8_t *fptr, wcid = 0;
	int i;

	if (isnew && in->in_associd != 0) {
		/* only interested in true associations */
		wcid = RT2860_AID2WCID(in->in_associd);

		/* init WCID table entry */
		off = RT2860_WCID_ENTRY(wcid);
		fptr = in->in_macaddr;
		for (i = 0; i < IEEE80211_ADDR_LEN; i++)
			rt2860_mem_write1(sc, off++, *fptr++);
	}
	rt2860_amrr_node_init(&sc->amrr, &sc->amn[wcid]);

	/* set rate to some reasonable initial value */
	i = in->in_rates.ir_nrates - 1;
	for (; i > 0 && (in->in_rates.ir_rates[i] & IEEE80211_RATE_VAL) > 72; )
		i--;
	in->in_txrate = i;

	RWN_DEBUG(RT2860_DBG_80211, "rwn: rt2860_newassoc(): "
	    "new assoc isnew=%d WCID=%d, initial rate=%d\n",
	    isnew, wcid,
	    in->in_rates.ir_rates[i] & IEEE80211_RATE_VAL);
	RWN_DEBUG(RT2860_DBG_80211, "rwn: rt2860_newassoc(): "
	    "addr=%x:%x:%x:%x:%x:%x\n",
	    in->in_macaddr[0], in->in_macaddr[1], in->in_macaddr[2],
	    in->in_macaddr[3], in->in_macaddr[4], in->in_macaddr[5]);
}

void
rt2860_enable_tsf_sync(struct rt2860_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	tmp = RT2860_READ(sc, RT2860_BCN_TIME_CFG);

	tmp &= ~0x1fffff;
	tmp |= ic->ic_bss->in_intval * 16;
	tmp |= RT2860_TSF_TIMER_EN | RT2860_TBTT_TIMER_EN;
	if (ic->ic_opmode == IEEE80211_M_STA) {
		/*
		 * Local TSF is always updated with remote TSF on beacon
		 * reception.
		 */
		tmp |= 1 << RT2860_TSF_SYNC_MODE_SHIFT;
	}

	RT2860_WRITE(sc, RT2860_BCN_TIME_CFG, tmp);
}

static int
rt2860_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)ic;
	enum ieee80211_state	ostate;
	int			err;
	uint32_t		tmp;

	ostate = ic->ic_state;
	RWN_DEBUG(RT2860_DBG_80211, "rwn: rt2860_newstate(): "
	    "%x -> %x!\n", ostate, nstate);

	RT2860_GLOCK(sc);
	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}
	if (sc->sc_rssadapt_id != 0) {
		(void) untimeout(sc->sc_rssadapt_id);
		sc->sc_rssadapt_id = 0;
	}
	if (ostate == IEEE80211_S_RUN) {
		/* turn link LED off */
		rt2860_set_leds(sc, RT2860_LED_RADIO);
	}

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_RUN) {
			/* abort TSF synchronization */
			tmp = RT2860_READ(sc, RT2860_BCN_TIME_CFG);
			RT2860_WRITE(sc, RT2860_BCN_TIME_CFG,
			    tmp & ~(RT2860_BCN_TX_EN | RT2860_TSF_TIMER_EN |
			    RT2860_TBTT_TIMER_EN));
		}
		break;

	case IEEE80211_S_SCAN:
		rt2860_set_chan(sc, ic->ic_curchan);
		sc->sc_scan_id = timeout(rt2860_next_scan, (void *)sc,
		    drv_usectohz(200000));
		break;

	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC:
		rt2860_set_chan(sc, ic->ic_curchan);
		break;

	case IEEE80211_S_RUN:
		rt2860_set_chan(sc, ic->ic_curchan);

		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			rt2860_updateslot(sc);
			rt2860_enable_mrr(sc);
			rt2860_set_txpreamble(sc);
			rt2860_set_basicrates(sc);
			rt2860_set_bssid(sc, ic->ic_bss->in_bssid);
		}
		if (ic->ic_opmode == IEEE80211_M_STA) {
			/* fake a join to init the tx rate */
			rt2860_newassoc(ic, ic->ic_bss, 1);
		}

		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			rt2860_enable_tsf_sync(sc);
			sc->sc_rssadapt_id = timeout(rt2860_updatestats,
			    (void *)sc, drv_usectohz(500 * 1000));
		}

		/* turn link LED on */
		rt2860_set_leds(sc, RT2860_LED_RADIO |
		    (IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan) ?
		    RT2860_LED_LINK_2GHZ : RT2860_LED_LINK_5GHZ));
		break;
	}

	RT2860_GUNLOCK(sc);

	err = sc->sc_newstate(ic, nstate, arg);

	return (err);
}

/*
 * Return the Rx chain with the highest RSSI for a given frame.
 */
static uint8_t
rt2860_maxrssi_chain(struct rt2860_softc *sc, const struct rt2860_rxwi *rxwi)
{
	uint8_t rxchain = 0;

	if (sc->nrxchains > 1)
		if (rxwi->rssi[1] > rxwi->rssi[rxchain])
			rxchain = 1;
	if (sc->nrxchains > 2)
		if (rxwi->rssi[2] > rxwi->rssi[rxchain])
			rxchain = 2;

	return (rxchain);
}

static void
rt2860_drain_stats_fifo(struct rt2860_softc *sc)
{
	struct rt2860_amrr_node *amn;
	uint32_t stat;
	uint8_t wcid, mcs, pid;

	/* drain Tx status FIFO (maxsize = 16) */
	while ((stat = RT2860_READ(sc, RT2860_TX_STAT_FIFO)) & RT2860_TXQ_VLD) {
		RWN_DEBUG(RT2860_DBG_TX, "rwn: rt2860_drain_stats_fifo(): "
		    "tx stat 0x%08\n", stat);

		wcid = (stat >> 8) & 0xff;

		/* if no ACK was requested, no feedback is available */
		if (!(stat & RT2860_TXQ_ACKREQ) || wcid == 0xff)
			continue;
		/* update per-STA AMRR stats */
		amn = &sc->amn[wcid];
		amn->amn_txcnt++;
		if (stat & RT2860_TXQ_OK) {
			/*
			 * Check if there were retries, ie if the Tx success
			 * rate is different from the requested rate.  Note
			 * that it works only because we do not allow rate
			 * fallback from OFDM to CCK.
			 */
			mcs = (stat >> RT2860_TXQ_MCS_SHIFT) & 0x7f;
			pid = (stat >> RT2860_TXQ_PID_SHIFT) & 0xf;
			if (mcs + 1 != pid)
				amn->amn_retrycnt++;
		} else
			amn->amn_retrycnt++;
	}
}

/*ARGSUSED*/
static void
rt2860_tx_intr(struct rt2860_softc *sc, int qid)
{
	struct rt2860_tx_ring	*ring = &sc->txq[qid];
	struct ieee80211com	*ic = &sc->sc_ic;
	uint32_t hw;

	rt2860_drain_stats_fifo(sc);

	mutex_enter(&sc->sc_txlock);
	hw = RT2860_READ(sc, RT2860_TX_DTX_IDX(qid));
	RWN_DEBUG(RT2860_DBG_TX, "rwn: rwn_tx_intr():"
	    "hw = %x, ring->next = %x, queued = %d\n",
	    hw, ring->next, ring->queued);
	while (ring->next != hw) {
		struct rt2860_txd *txd = &ring->txd[ring->next];
		struct rt2860_tx_data *data = ring->data[ring->next];

		if (data != NULL) {
			RT2860_DMA_SYNC(data->txbuf_dma, DDI_DMA_SYNC_FORDEV);
			if (data->ni != NULL) {
				ieee80211_free_node(data->ni);
				data->ni = NULL;
			}
			SLIST_INSERT_HEAD(&sc->data_pool, data, next);
			ring->data[ring->next] = NULL;
		}

		txd->sdl0 &= ~LE_16(RT2860_TX_DDONE);

		(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
		    ring->next * sizeof (struct rt2860_txd),
		    sizeof (struct rt2860_txd),
		    DDI_DMA_SYNC_FORDEV);

		ring->queued--;
		ring->next = (ring->next + 1) % RT2860_TX_RING_COUNT;

		if (sc->sc_need_sched &&
		    (ring->queued < RT2860_TX_RING_COUNT)) {
			sc->sc_need_sched = 0;
			mac_tx_update(ic->ic_mach);
		}
	}
	sc->sc_tx_timer = 0;
	mutex_exit(&sc->sc_txlock);
}

static void
rt2860_rx_intr(struct rt2860_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	struct ieee80211_node	*ni;
	struct ieee80211_frame	*wh;
	int	pktlen;
	uint8_t ant, rssi, *rxbuf;
	mblk_t	*mp0;

	mutex_enter(&sc->sc_rxlock);
	for (;;) {
		struct rt2860_rx_data *data = &sc->rxq.data[sc->rxq.cur];
		struct rt2860_rxd *rxd = &sc->rxq.rxd[sc->rxq.cur];
		struct rt2860_rxwi *rxwi;

		(void) ddi_dma_sync(sc->rxq.rxdesc_dma.dma_hdl,
		    sc->rxq.cur * sizeof (struct rt2860_rxd),
		    sizeof (struct rt2860_rxd),
		    DDI_DMA_SYNC_FORKERNEL);

		if (!(rxd->sdl0 & LE_16(RT2860_RX_DDONE))) {
			RWN_DEBUG(RT2860_DBG_RX, "rwn: rt2860_rx_intr(): "
			    "rx done!\n");
			break;
		}

		if (rxd->flags &
		    LE_32(RT2860_RX_CRCERR | RT2860_RX_ICVERR)) {
			RWN_DEBUG(RT2860_DBG_RX, "rwn: rt2860_rx_intr(): "
			    "rx crc error & rx icv error!\n");
			sc->sc_rx_err++;
			goto skip;
		}

		if (rxd->flags & LE_32(RT2860_RX_MICERR)) {
			RWN_DEBUG(RT2860_DBG_RX, "rwn: rt2860_rx_intr(): "
			    "rx mic error!\n");
			sc->sc_rx_err++;
			goto skip;
		}

		(void) ddi_dma_sync(data->rxbuf_dma.dma_hdl,
		    data->rxbuf_dma.offset,
		    data->rxbuf_dma.alength,
		    DDI_DMA_SYNC_FORCPU);

		rxbuf = (uint8_t *)data->rxbuf_dma.mem_va;
		rxd->sdp0 = LE_32(data->rxbuf_dma.cookie.dmac_address);
		rxwi = (struct rt2860_rxwi *)rxbuf;
		rxbuf = (uint8_t *)(rxwi + 1);
		pktlen = LE_16(rxwi->len) & 0xfff;

		mp0 = allocb(sc->sc_dmabuf_size, BPRI_MED);
		if (mp0 == NULL) {
			RWN_DEBUG(RT2860_DBG_RX, "rwn: rt2860_rx_intr():"
			    "alloc mblk error\n");
			sc->sc_rx_nobuf++;
			goto skip;
		}
		bcopy(rxbuf, mp0->b_rptr, pktlen);
		mp0->b_wptr += pktlen;

		wh = (struct ieee80211_frame *)mp0->b_rptr;

		/* HW may insert 2 padding bytes after 802.11 header */
		if (rxd->flags & LE_32(RT2860_RX_L2PAD)) {
			RWN_DEBUG(RT2860_DBG_RX, "rwn: rt2860_rx_intr():"
			    "2 padding bytes after 80211 header!\n");
		}

		ant = rt2860_maxrssi_chain(sc, rxwi);
		rssi = RT2860_RSSI_OFFSET - rxwi->rssi[ant];
		/* grab a reference to the source node */
		ni = ieee80211_find_rxnode(ic, wh);

		(void) ieee80211_input(ic, mp0, ni, rssi, 0);

		/* node is no longer needed */
		ieee80211_free_node(ni);
skip:
		rxd->sdl0 &= ~LE_16(RT2860_RX_DDONE);

		(void) ddi_dma_sync(sc->rxq.rxdesc_dma.dma_hdl,
		    sc->rxq.cur * sizeof (struct rt2860_rxd),
		    sizeof (struct rt2860_rxd),
		    DDI_DMA_SYNC_FORDEV);

		sc->rxq.cur = (sc->rxq.cur + 1) % RT2860_RX_RING_COUNT;
	}
	mutex_exit(&sc->sc_rxlock);

	/* tell HW what we have processed */
	RT2860_WRITE(sc, RT2860_RX_CALC_IDX,
	    (sc->rxq.cur - 1) % RT2860_RX_RING_COUNT);
}

static uint_t
rt2860_softintr(caddr_t data)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)data;

	/*
	 * Check if the soft interrupt is triggered by another
	 * driver at the same level.
	 */
	RT2860_GLOCK(sc);
	if (sc->sc_rx_pend) {
		sc->sc_rx_pend = 0;
		RT2860_GUNLOCK(sc);
		rt2860_rx_intr(sc);
		return (DDI_INTR_CLAIMED);
	}
	RT2860_GUNLOCK(sc);

	return (DDI_INTR_UNCLAIMED);
}

static uint_t
rt2860_intr(caddr_t arg)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;
	uint32_t		r;

	RT2860_GLOCK(sc);

	if ((!RT2860_IS_RUNNING(sc)) || RT2860_IS_SUSPEND(sc)) {
		/*
		 * The hardware is not ready/present, don't touch anything.
		 * Note this can happen early on if the IRQ is shared.
		 */
		RT2860_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	r = RT2860_READ(sc, RT2860_INT_STATUS);
	if (r == 0xffffffff) {
		RT2860_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}
	if (r == 0) {
		RT2860_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	/* acknowledge interrupts */
	RT2860_WRITE(sc, RT2860_INT_STATUS, r);

	if (r & RT2860_TX_COHERENT)
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr()"
		    "RT2860_TX_COHERENT\n");

	if (r & RT2860_RX_COHERENT)
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr()"
		    "RT2860_RX_COHERENT\n");

	if (r & RT2860_MAC_INT_2) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_MAC_INT_2\n");
		rt2860_drain_stats_fifo(sc);
	}

	if (r & RT2860_TX_DONE_INT5) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_TX_DONE_INT5\n");
		rt2860_tx_intr(sc, 5);
	}

	if (r & RT2860_RX_DONE_INT) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr()"
		    "RT2860_RX_INT\n");
		sc->sc_rx_pend = 1;
		ddi_trigger_softintr(sc->sc_softintr_hdl);
	}

	if (r & RT2860_TX_DONE_INT4) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_TX_DONE_INT4\n");
		rt2860_tx_intr(sc, 4);
	}

	if (r & RT2860_TX_DONE_INT3) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_TX_DONE_INT3\n");
		rt2860_tx_intr(sc, 3);
	}

	if (r & RT2860_TX_DONE_INT2) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_TX_DONE_INT2\n");
		rt2860_tx_intr(sc, 2);
	}

	if (r & RT2860_TX_DONE_INT1) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_TX_DONE_INT1\n");
		rt2860_tx_intr(sc, 1);
	}

	if (r & RT2860_TX_DONE_INT0) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_TX_DONE_INT0\n");
		rt2860_tx_intr(sc, 0);
	}

	if (r & RT2860_MAC_INT_0) {
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_MAC_INT_0\n");
		struct ieee80211com *ic = &sc->sc_ic;
		/* check if protection mode has changed */
		if ((sc->sc_ic_flags ^ ic->ic_flags) & IEEE80211_F_USEPROT) {
			rt2860_updateprot(ic);
			sc->sc_ic_flags = ic->ic_flags;
		}
	}

	if (r & RT2860_MAC_INT_3)
		RWN_DEBUG(RT2860_DBG_INTR, "rwn: rt2860_intr(): "
		    "RT2860_MAC_INT_3\n");

	RT2860_GUNLOCK(sc);

	return (DDI_INTR_CLAIMED);
}

static void
rt2860_set_region_4(struct rt2860_softc *sc,
    uint32_t addr, uint32_t data, int size)
{
	for (; size > 0; size--, data++, addr += 4)
		ddi_put32((sc)->sc_io_handle,
		    (uint32_t *)((uintptr_t)(sc)->sc_io_base + addr), data);
}

static int
rt2860_load_microcode(struct rt2860_softc *sc)
{
	int		ntries;
	size_t		size;
	uint8_t		*ucode, *fptr;
	uint32_t	off, i;

	ucode = rt2860_fw_bin;
	size = sizeof (rt2860_fw_bin);
	RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_load_microcode(): "
	    "The size of ucode is: %x\n", size);

	/* set "host program ram write selection" bit */
	RT2860_WRITE(sc, RT2860_SYS_CTRL, RT2860_HST_PM_SEL);
	/* write microcode image */
	fptr = ucode;
	off = RT2860_FW_BASE;
	for (i = 0; i < size; i++) {
		rt2860_mem_write1(sc, off++, *fptr++);
	}
	/* kick microcontroller unit */
	RT2860_WRITE(sc, RT2860_SYS_CTRL, 0);
	RT2860_WRITE(sc, RT2860_SYS_CTRL, RT2860_MCU_RESET);

	RT2860_WRITE(sc, RT2860_H2M_BBPAGENT, 0);
	RT2860_WRITE(sc, RT2860_H2M_MAILBOX, 0);

	/* wait until microcontroller is ready */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (RT2860_READ(sc, RT2860_SYS_CTRL) & RT2860_MCU_READY)
			break;
		DELAY(1000);
	}
	if (ntries == 1000) {
		RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_load_microcode(): "
		    "timeout waiting for MCU to initialie\n");
		return (ETIMEDOUT);
	}

	return (0);
}

static void
rt2860_set_macaddr(struct rt2860_softc *sc, const uint8_t *addr)
{
	RT2860_WRITE(sc, RT2860_MAC_ADDR_DW0,
	    addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24);
	RT2860_WRITE(sc, RT2860_MAC_ADDR_DW1,
	    addr[4] | addr[5] << 8);
}

/*
 * Send a command to the 8051 microcontroller unit.
 */
static int
rt2860_mcu_cmd(struct rt2860_softc *sc, uint8_t cmd, uint16_t arg)
{
	int	ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2860_READ(sc, RT2860_H2M_MAILBOX) & RT2860_H2M_BUSY))
			break;
		DELAY(2);
	}
	if (ntries == 100)
		return (EIO);

	RT2860_WRITE(sc, RT2860_H2M_MAILBOX,
	    RT2860_H2M_BUSY | RT2860_TOKEN_NO_INTR << 16 | arg);
	RT2860_WRITE(sc, RT2860_HOST_CMD, cmd);

	return (RT2860_SUCCESS);
}

/*
 * Reading and writing from/to the BBP is different from RT2560 and RT2661.
 * We access the BBP through the 8051 microcontroller unit which means that
 * the microcode must be loaded first.
 */
static uint8_t
rt2860_mcu_bbp_read(struct rt2860_softc *sc, uint8_t reg)
{
	uint32_t val;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2860_READ(sc,
		    RT2860_H2M_BBPAGENT) & RT2860_BBP_CSR_KICK))
			break;
		DELAY(1);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_mcu_bbp_read():"
		    "could not read from BBP through MCU\n");
		return (0);
	}

	RT2860_WRITE(sc, RT2860_H2M_BBPAGENT, RT2860_BBP_RW_PARALLEL |
	    RT2860_BBP_CSR_KICK | RT2860_BBP_CSR_READ | reg << 8);

	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_BBP, 0);
	DELAY(1000);

	for (ntries = 0; ntries < 100; ntries++) {
		val = RT2860_READ(sc, RT2860_H2M_BBPAGENT);
		if (!(val & RT2860_BBP_CSR_KICK))
			return (val & 0xff);
		DELAY(1);
	}
	RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_mcu_bbp_read():"
	    "could not read from BBP through MCU\n");

	return (0);
}

static void
rt2860_mcu_bbp_write(struct rt2860_softc *sc, uint8_t reg, uint8_t val)
{
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2860_READ(sc,
		    RT2860_H2M_BBPAGENT) & RT2860_BBP_CSR_KICK))
			break;
		DELAY(1);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_mcu_bbp_write():"
		    "could not write to BBP through MCU\n");
		return;
	}

	RT2860_WRITE(sc, RT2860_H2M_BBPAGENT, RT2860_BBP_RW_PARALLEL |
	    RT2860_BBP_CSR_KICK | reg << 8 | val);

	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_BBP, 0);
	DELAY(1000);
}

static int
rt2860_bbp_init(struct rt2860_softc *sc)
{
	int i, ntries;

	/* wait for BBP to wake up */
	for (ntries = 0; ntries < 20; ntries++) {
		uint8_t bbp0 = rt2860_mcu_bbp_read(sc, 0);
		if (bbp0 != 0 && bbp0 != 0xff)
			break;
	}
	if (ntries == 20) {
		RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_bbp_init():"
		    "timeout waiting for BBP to wake up\n");
		return (ETIMEDOUT);
	}

	/* initialize BBP registers to default values */
	for (i = 0; i < 12; i++) {
		rt2860_mcu_bbp_write(sc, rt2860_def_bbp[i].reg,
		    rt2860_def_bbp[i].val);
	}

	/* fix BBP69 and BBP73 for RT2860C */
	if (sc->mac_rev == 0x28600100) {
		rt2860_mcu_bbp_write(sc, 69, 0x16);
		rt2860_mcu_bbp_write(sc, 73, 0x12);
	}

	return (0);
}

static void
rt2860_rf_write(struct rt2860_softc *sc, uint8_t reg, uint32_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2860_READ(sc, RT2860_RF_CSR_CFG0) & RT2860_RF_REG_CTRL))
			break;
		DELAY(1);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_FW, "rwn: rwn_init()"
		    "could not write to RF\n");
		return;
	}

	/* RF registers are 24-bit on the RT2860 */
	tmp = RT2860_RF_REG_CTRL | 24 << RT2860_RF_REG_WIDTH_SHIFT |
	    (val & 0x3fffff) << 2 | (reg & 3);
	RT2860_WRITE(sc, RT2860_RF_CSR_CFG0, tmp);
}

static void
rt2860_select_chan_group(struct rt2860_softc *sc, int group)
{
	uint32_t tmp;

	rt2860_mcu_bbp_write(sc, 62, 0x37 - sc->lna[group]);
	rt2860_mcu_bbp_write(sc, 63, 0x37 - sc->lna[group]);
	rt2860_mcu_bbp_write(sc, 64, 0x37 - sc->lna[group]);
	rt2860_mcu_bbp_write(sc, 82, (group == 0) ? 0x62 : 0xf2);

	tmp = RT2860_READ(sc, RT2860_TX_BAND_CFG);
	tmp &= ~(RT2860_5G_BAND_SEL_N | RT2860_5G_BAND_SEL_P);
	tmp |= (group == 0) ? RT2860_5G_BAND_SEL_N : RT2860_5G_BAND_SEL_P;
	RT2860_WRITE(sc, RT2860_TX_BAND_CFG, tmp);

	/* enable appropriate Power Amplifiers and Low Noise Amplifiers */
	tmp = RT2860_RFTR_EN | RT2860_TRSW_EN;
	if (group == 0) {	/* 2GHz */
		tmp |= RT2860_PA_PE_G0_EN | RT2860_LNA_PE_G0_EN;
		if (sc->ntxchains > 1)
			tmp |= RT2860_PA_PE_G1_EN;
		if (sc->nrxchains > 1)
			tmp |= RT2860_LNA_PE_G1_EN;
	} else {		/* 5GHz */
		tmp |= RT2860_PA_PE_A0_EN | RT2860_LNA_PE_A0_EN;
		if (sc->ntxchains > 1)
			tmp |= RT2860_PA_PE_A1_EN;
		if (sc->nrxchains > 1)
			tmp |= RT2860_LNA_PE_A1_EN;
	}
	RT2860_WRITE(sc, RT2860_TX_PIN_CFG, tmp);

	rt2860_mcu_bbp_write(sc, 66, 0x2e + sc->lna[group]);
}
static void
rt2860_set_chan(struct rt2860_softc *sc, struct ieee80211_channel *c)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	const struct rfprog	*rfprog = rt2860_rf2850;
	uint_t			i, chan, group;
	uint8_t			txpow1, txpow2;
	uint32_t		r2, r3, r4;

	chan = ieee80211_chan2ieee(ic, c);
	if (chan == 0 || chan == IEEE80211_CHAN_ANY) {
		RWN_DEBUG(RT2860_DBG_FW, "Unkonwn channel!\n");
		return;
	}

	/* find the settings for this channel (we know it exists) */
	for (i = 0; rfprog[i].chan != chan; )
		i++;

	r2 = rfprog[i].r2;
	if (sc->ntxchains == 1)
		r2 |= 1 << 12;		/* 1T: disable Tx chain 2 */
	if (sc->nrxchains == 1)
		r2 |= 1 << 15 | 1 << 4;	/* 1R: disable Rx chains 2 & 3 */
	else if (sc->nrxchains == 2)
		r2 |= 1 << 4;		/* 2R: disable Rx chain 3 */

	/* use Tx power values from EEPROM */
	txpow1 = sc->txpow1[i];
	txpow2 = sc->txpow2[i];
	if (IEEE80211_IS_CHAN_5GHZ(c)) {
		txpow1 = txpow1 << 1 | 1;
		txpow2 = txpow2 << 1 | 1;
	}
	r3 = rfprog[i].r3 | txpow1 << 7;
	r4 = rfprog[i].r4 | sc->freq << 13 | txpow2 << 4;

	rt2860_rf_write(sc, RAL_RF1, rfprog[i].r1);
	rt2860_rf_write(sc, RAL_RF2, r2);
	rt2860_rf_write(sc, RAL_RF3, r3);
	rt2860_rf_write(sc, RAL_RF4, r4);

	DELAY(200);

	rt2860_rf_write(sc, RAL_RF1, rfprog[i].r1);
	rt2860_rf_write(sc, RAL_RF2, r2);
	rt2860_rf_write(sc, RAL_RF3, r3 | 1);
	rt2860_rf_write(sc, RAL_RF4, r4);

	DELAY(200);

	rt2860_rf_write(sc, RAL_RF1, rfprog[i].r1);
	rt2860_rf_write(sc, RAL_RF2, r2);
	rt2860_rf_write(sc, RAL_RF3, r3);
	rt2860_rf_write(sc, RAL_RF4, r4);

	/* 802.11a uses a 16 microseconds short interframe space */
	sc->sifs = IEEE80211_IS_CHAN_5GHZ(c) ? 16 : 10;

	/* determine channel group */
	if (chan <= 14)
		group = 0;
	else if (chan <= 64)
		group = 1;
	else if (chan <= 128)
		group = 2;
	else
		group = 3;

	/* XXX necessary only when group has changed! */
	rt2860_select_chan_group(sc, group);

	DELAY(1000);
}

static void
rt2860_updateprot(struct ieee80211com *ic)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)ic;
	uint32_t tmp;

	tmp = RT2860_RTSTH_EN | RT2860_PROT_NAV_SHORT | RT2860_TXOP_ALLOW_ALL;
	/* setup protection frame rate (MCS code) */
	tmp |= (ic->ic_curmode == IEEE80211_MODE_11A) ? 0 : 3;

	/* CCK frames don't require protection */
	RT2860_WRITE(sc, RT2860_CCK_PROT_CFG, tmp);

	if (ic->ic_flags & IEEE80211_F_USEPROT) {
		if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
			tmp |= RT2860_PROT_CTRL_RTS_CTS;
		else if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
			tmp |= RT2860_PROT_CTRL_CTS;
	}
	RT2860_WRITE(sc, RT2860_OFDM_PROT_CFG, tmp);
}

static void
rt2860_set_leds(struct rt2860_softc *sc, uint16_t which)
{
	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_LEDS,
	    which | (sc->leds & 0x7f));
}

static int
rt2860_init(struct rt2860_softc *sc)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))
	struct ieee80211com	*ic;
	int			i, err, qid, ridx, ntries;
	uint8_t			bbp1, bbp3;
	uint32_t		tmp;

	ic = &sc->sc_ic;

	rt2860_stop(sc);
	tmp = RT2860_READ(sc, RT2860_WPDMA_GLO_CFG);
	tmp &= 0xff0;
	RT2860_WRITE(sc, RT2860_WPDMA_GLO_CFG, tmp | RT2860_TX_WB_DDONE);

	RT2860_WRITE(sc, RT2860_WPDMA_RST_IDX, 0xffffffff);

	/* PBF hardware reset */
	RT2860_WRITE(sc, RT2860_SYS_CTRL, 0xe1f);
	RT2860_WRITE(sc, RT2860_SYS_CTRL, 0xe00);

	if (!(sc->sc_flags & RT2860_FWLOADED)) {
		if ((err = rt2860_load_microcode(sc)) != 0) {
			RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_init(): "
			    "could not load 8051 microcode\n");
			rt2860_stop(sc);
			return (err);
		}
		RT2860_GLOCK(sc);
		sc->sc_flags |= RT2860_FWLOADED;
		RT2860_GUNLOCK(sc);
	}

	rt2860_set_macaddr(sc, ic->ic_macaddr);

	/* init Tx power for all Tx rates (from EEPROM) */
	for (ridx = 0; ridx < 5; ridx++) {
		if (sc->txpow20mhz[ridx] == 0xffffffff)
			continue;
		RT2860_WRITE(sc, RT2860_TX_PWR_CFG(ridx), sc->txpow20mhz[ridx]);
	}

	for (ntries = 0; ntries < 100; ntries++) {
		tmp = RT2860_READ(sc, RT2860_WPDMA_GLO_CFG);
		if ((tmp & (RT2860_TX_DMA_BUSY | RT2860_RX_DMA_BUSY)) == 0)
			break;
		DELAY(1000);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rt2860_init():"
		    "timeout waiting for DMA engine\n");
		rt2860_stop(sc);
		return (ETIMEDOUT);
	}
	tmp &= 0xff0;
	RT2860_WRITE(sc, RT2860_WPDMA_GLO_CFG, tmp | RT2860_TX_WB_DDONE);

	/* reset Rx ring and all 6 Tx rings */
	RT2860_WRITE(sc, RT2860_WPDMA_RST_IDX, 0x1003f);

	/* PBF hardware reset */
	RT2860_WRITE(sc, RT2860_SYS_CTRL, 0xe1f);
	RT2860_WRITE(sc, RT2860_SYS_CTRL, 0xe00);

	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL,
	    RT2860_BBP_HRST | RT2860_MAC_SRST);
	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL, 0);

	for (i = 0; i < N(rt2860_def_mac); i++)
		RT2860_WRITE(sc, rt2860_def_mac[i].reg, rt2860_def_mac[i].val);

	/* wait while MAC is busy */
	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2860_READ(sc, RT2860_MAC_STATUS_REG) &
		    (RT2860_RX_STATUS_BUSY | RT2860_TX_STATUS_BUSY)))
			break;
		DELAY(1000);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_FW, "rwn: rt2860_init():"
		    "timeout waiting for MAC\n");
		rt2860_stop(sc);
		return (ETIMEDOUT);
	}

	/* clear Host to MCU mailbox */
	RT2860_WRITE(sc, RT2860_H2M_BBPAGENT, 0);
	RT2860_WRITE(sc, RT2860_H2M_MAILBOX, 0);

	if ((err = rt2860_bbp_init(sc)) != 0) {
		rt2860_stop(sc);
		return (err);
	}

	/* init Tx rings (4 EDCAs + HCCA + Mgt) */
	for (qid = 0; qid < 6; qid++) {
		RT2860_WRITE(sc, RT2860_TX_BASE_PTR(qid), sc->txq[qid].paddr);
		RT2860_WRITE(sc, RT2860_TX_MAX_CNT(qid), RT2860_TX_RING_COUNT);
		RT2860_WRITE(sc, RT2860_TX_CTX_IDX(qid), 0);
	}

	/* init Rx ring */
	RT2860_WRITE(sc, RT2860_RX_BASE_PTR, sc->rxq.paddr);
	RT2860_WRITE(sc, RT2860_RX_MAX_CNT, RT2860_RX_RING_COUNT);
	RT2860_WRITE(sc, RT2860_RX_CALC_IDX, RT2860_RX_RING_COUNT - 1);

	/* setup maximum buffer sizes */
	RT2860_WRITE(sc, RT2860_MAX_LEN_CFG, 1 << 12 |
	    (sc->sc_dmabuf_size - sizeof (struct rt2860_rxwi) - 2));

	for (ntries = 0; ntries < 100; ntries++) {
		tmp = RT2860_READ(sc, RT2860_WPDMA_GLO_CFG);
		if ((tmp & (RT2860_TX_DMA_BUSY | RT2860_RX_DMA_BUSY)) == 0)
			break;
		DELAY(1000);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rt2860_init():"
		    "timeout waiting for DMA engine\n");
		rt2860_stop(sc);
		return (ETIMEDOUT);
	}
	tmp &= 0xff0;
	RT2860_WRITE(sc, RT2860_WPDMA_GLO_CFG, tmp | RT2860_TX_WB_DDONE);

	/* disable interrupts mitigation */
	RT2860_WRITE(sc, RT2860_DELAY_INT_CFG, 0);

	/* write vendor-specific BBP values (from EEPROM) */
	for (i = 0; i < 8; i++) {
		if (sc->bbp[i].reg == 0 || sc->bbp[i].reg == 0xff)
			continue;
		rt2860_mcu_bbp_write(sc, sc->bbp[i].reg, sc->bbp[i].val);
	}

	/* send LEDs operating mode to microcontroller */
	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_LED1, sc->led[0]);
	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_LED2, sc->led[1]);
	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_LED3, sc->led[2]);

	/* disable non-existing Rx chains */
	bbp3 = rt2860_mcu_bbp_read(sc, 3);
	bbp3 &= ~(1 << 3 | 1 << 4);
	if (sc->nrxchains == 2)
		bbp3 |= 1 << 3;
	else if (sc->nrxchains == 3)
		bbp3 |= 1 << 4;
	rt2860_mcu_bbp_write(sc, 3, bbp3);

	/* disable non-existing Tx chains */
	bbp1 = rt2860_mcu_bbp_read(sc, 1);
	if (sc->ntxchains == 1)
		bbp1 &= ~(1 << 3 | 1 << 4);
	rt2860_mcu_bbp_write(sc, 1, bbp1);

	/* select default channel */
	rt2860_set_chan(sc, ic->ic_curchan);

	/* XXX not clear what the following 8051 command does.. */
	(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_BOOT, 0);

	/* set RTS threshold */
	tmp = RT2860_READ(sc, RT2860_TX_RTS_CFG);
	tmp &= ~0xffff00;
	tmp |= ic->ic_rtsthreshold << 8;

	/* setup initial protection mode */
	sc->sc_ic_flags = ic->ic_flags;
	rt2860_updateprot(ic);

	/* enable Tx/Rx DMA engine */
	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL, RT2860_MAC_TX_EN);
	for (ntries = 0; ntries < 200; ntries++) {
		tmp = RT2860_READ(sc, RT2860_WPDMA_GLO_CFG);
		if ((tmp & (RT2860_TX_DMA_BUSY | RT2860_RX_DMA_BUSY)) == 0)
			break;
		DELAY(1000);
	}
	if (ntries == 200) {
		RWN_DEBUG(RT2860_DBG_DMA, "rwn: rt2860_int():"
		    "timeout waiting for DMA engine\n");
		rt2860_stop(sc);
		return (ETIMEDOUT);
	}

	DELAY(50);

	tmp |= RT2860_TX_WB_DDONE | RT2860_RX_DMA_EN | RT2860_TX_DMA_EN |
	    RT2860_WPDMA_BT_SIZE64 << RT2860_WPDMA_BT_SIZE_SHIFT;
	RT2860_WRITE(sc, RT2860_WPDMA_GLO_CFG, tmp);

	/* turn radio LED on */
	rt2860_set_leds(sc, RT2860_LED_RADIO);

	/* set Rx filter */
	tmp = RT2860_DROP_CRC_ERR | RT2860_DROP_PHY_ERR;
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		tmp |= RT2860_DROP_UC_NOME | RT2860_DROP_DUPL |
		    RT2860_DROP_CTS | RT2860_DROP_BA | RT2860_DROP_ACK |
		    RT2860_DROP_VER_ERR | RT2860_DROP_CTRL_RSV |
		    RT2860_DROP_CFACK | RT2860_DROP_CFEND;
		if (ic->ic_opmode == IEEE80211_M_STA)
			tmp |= RT2860_DROP_RTS | RT2860_DROP_PSPOLL;
	}
	RT2860_WRITE(sc, RT2860_RX_FILTR_CFG, tmp);

	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL,
	    RT2860_MAC_RX_EN | RT2860_MAC_TX_EN);

	/* clear pending interrupts */
	RT2860_WRITE(sc, RT2860_INT_STATUS, 0xffffffff);
	/* enable interrupts */
	RT2860_WRITE(sc, RT2860_INT_MASK, 0x3fffc);

	if (sc->sc_flags & RT2860_ADVANCED_PS)
		(void) rt2860_mcu_cmd(sc, RT2860_MCU_CMD_PSLEVEL, sc->pslevel);

	return (DDI_SUCCESS);
}

static int
rt2860_quiesce(dev_info_t *dip)
{
	struct rt2860_softc	*sc;

	sc = ddi_get_soft_state(rt2860_soft_state_p, ddi_get_instance(dip));
	if (sc == NULL)
		return (DDI_FAILURE);

#ifdef DEBUG
	rt2860_dbg_flags = 0;
#endif

	/*
	 * No more blocking is allowed while we are in quiesce(9E) entry point
	 */
	sc->sc_flags |= RT2860_F_QUIESCE;

	/*
	 * Disable and mask all interrupts
	 */
	rt2860_stop(sc);
	return (DDI_SUCCESS);
}

static void
rt2860_stop(struct rt2860_softc *sc)
{
	int		qid;
	uint32_t	tmp;

	/* by pass if it's quiesced */
	if (!(sc->sc_flags & RT2860_F_QUIESCE))
		RT2860_GLOCK(sc);
	if (sc->sc_flags == RT2860_F_RUNNING)
		rt2860_set_leds(sc, 0);	/* turn all LEDs off */
	sc->sc_tx_timer = 0;
	/* by pass if it's quiesced */
	if (!(sc->sc_flags & RT2860_F_QUIESCE))
		RT2860_GUNLOCK(sc);

	/* clear RX WCID search table */
	rt2860_set_region_4(sc, RT2860_WCID_ENTRY(0), 0, 512);
	/* clear pairwise key table */
	rt2860_set_region_4(sc, RT2860_PKEY(0), 0, 2048);
	/* clear IV/EIV table */
	rt2860_set_region_4(sc, RT2860_IVEIV(0), 0, 512);
	/* clear WCID attribute table */
	rt2860_set_region_4(sc, RT2860_WCID_ATTR(0), 0, 256);
	/* clear shared key table */
	rt2860_set_region_4(sc, RT2860_SKEY(0, 0), 0, 8 * 32);
	/* clear shared key mode */
	rt2860_set_region_4(sc, RT2860_SKEY_MODE_0_7, 0, 4);

	/* disable interrupts */
	RT2860_WRITE(sc, RT2860_INT_MASK, 0);

	/* disable Rx */
	tmp = RT2860_READ(sc, RT2860_MAC_SYS_CTRL);
	tmp &= ~(RT2860_MAC_RX_EN | RT2860_MAC_TX_EN);
	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL, tmp);

	/* reset adapter */
	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL,
	    RT2860_BBP_HRST | RT2860_MAC_SRST);
	RT2860_WRITE(sc, RT2860_MAC_SYS_CTRL, 0);

	/* reset Tx and Rx rings (and reclaim TXWIs) */
	for (qid = 0; qid < 6; qid++)
		rt2860_reset_tx_ring(sc, &sc->txq[qid]);
	rt2860_reset_rx_ring(sc, &sc->rxq);

	/* by pass if it's quiesced */
	if (!(sc->sc_flags & RT2860_F_QUIESCE))
		RT2860_GLOCK(sc);
	sc->sc_flags &= ~RT2860_UPD_BEACON;
	/* by pass if it's quiesced */
	if (!(sc->sc_flags & RT2860_F_QUIESCE))
		RT2860_GUNLOCK(sc);
}

static int
rt2860_m_start(void *arg)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	int			err;

	err = rt2860_init(sc);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_m_start():"
		    "Hardware initialization failed\n");
		goto fail1;
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	RT2860_GLOCK(sc);
	sc->sc_flags |= RT2860_F_RUNNING;
	RT2860_GUNLOCK(sc);

	return (err);
fail1:
	rt2860_stop(sc);
	return (err);
}

static void
rt2860_m_stop(void *arg)
{
	struct rt2860_softc *sc = (struct rt2860_softc *)arg;

	(void) rt2860_stop(sc);

	ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);

	RT2860_GLOCK(sc);
	sc->sc_flags &= ~RT2860_F_RUNNING;
	RT2860_GUNLOCK(sc);
}

static void
rt2860_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	int			err;

	err = ieee80211_ioctl(ic, wq, mp);
	RT2860_GLOCK(sc);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (RT2860_IS_RUNNING(sc)) {
				RT2860_GUNLOCK(sc);
				(void) rt2860_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
				RT2860_GLOCK(sc);
			}
		}
	}
	RT2860_GUNLOCK(sc);
}

/*
 * Call back function for get/set proporty
 */
static int
rt2860_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;
	int			err = 0;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
rt2860_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static int
rt2860_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;
	ieee80211com_t		*ic = &sc->sc_ic;
	int			err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);
	RT2860_GLOCK(sc);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (RT2860_IS_RUNNING(sc)) {
				RT2860_GUNLOCK(sc);
				(void) rt2860_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
				RT2860_GLOCK(sc);
			}
		}
		err = 0;
	}
	RT2860_GUNLOCK(sc);
	return (err);
}

static mblk_t *
rt2860_m_tx(void *arg, mblk_t *mp)
{
	struct rt2860_softc	*sc = (struct rt2860_softc *)arg;
	struct ieee80211com	*ic = &sc->sc_ic;
	mblk_t			*next;

	if (RT2860_IS_SUSPEND(sc)) {
		freemsgchain(mp);
		return (NULL);
	}

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		RWN_DEBUG(RT2860_DBG_TX, "rwn: rt2860_tx_data(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (rt2860_send(ic, mp, IEEE80211_FC0_TYPE_DATA) !=
		    DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/*ARGSUSED*/
static int
rt2860_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
rt2860_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
rt2860_m_promisc(void *arg, boolean_t on)
{
	return (0);
}

static int
rt2860_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct rt2860_softc	*sc  = (struct rt2860_softc *)arg;
	ieee80211com_t		*ic = &sc->sc_ic;
	ieee80211_node_t	*ni = ic->ic_bss;
	struct ieee80211_rateset *rs = &ni->in_rates;

	RT2860_GLOCK(sc);
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
		RT2860_GUNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		RT2860_GUNLOCK(sc);
		return (ENOTSUP);
	}
	RT2860_GUNLOCK(sc);

	return (0);
}

static int
rt2860_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct rt2860_softc	*sc;
	struct ieee80211com	*ic;
	int			i, err, qid, ntries, instance;
	uint8_t			cachelsz;
	uint16_t		command, vendor_id, device_id;
	char			strbuf[32];
	wifi_data_t		wd = { 0 };
	mac_register_t		*macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(rt2860_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		RT2860_GLOCK(sc);
		sc->sc_flags &= ~RT2860_F_SUSPEND;
		RT2860_GUNLOCK(sc);
		if (RT2860_IS_RUNNING(sc))
			(void) rt2860_init(sc);
		RWN_DEBUG(RT2860_DBG_RESUME, "rwn: rt2860_attach(): "
		    "resume now\n");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);

	err = ddi_soft_state_zalloc(rt2860_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "unable to alloc soft_state_p\n");
		return (err);
	}

	sc = ddi_get_soft_state(rt2860_soft_state_p, instance);
	ic = (ieee80211com_t *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	/* pci configuration */
	err = ddi_regs_map_setup(devinfo, 0, &sc->sc_cfg_base, 0, 0,
	    &rwn_csr_accattr, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "ddi_regs_map_setup() failed");
		goto fail1;
	}

	cachelsz = ddi_get8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_CACHE_LINESZ));
	if (cachelsz == 0)
		cachelsz = 0x10;
	sc->sc_cachelsz = cachelsz << 2;
	sc->sc_dmabuf_size = roundup(IEEE80211_MAX_LEN, sc->sc_cachelsz);

	vendor_id = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)(sc->sc_cfg_base) + PCI_CONF_VENID));
	device_id = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)(sc->sc_cfg_base) + PCI_CONF_DEVID));
	RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
	    "vendor 0x%x, device id 0x%x, cache size %d\n",
	    vendor_id, device_id, cachelsz);

	/*
	 * Enable response to memory space accesses,
	 * and enabe bus master.
	 */
	command = PCI_COMM_MAE | PCI_COMM_ME;
	ddi_put16(sc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)(sc->sc_cfg_base) + PCI_CONF_COMM),
	    command);
	ddi_put8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_LATENCY_TIMER), 0xa8);
	ddi_put8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_ILINE), 0x10);

	/* pci i/o space */
	err = ddi_regs_map_setup(devinfo, 1,
	    &sc->sc_io_base, 0, 0, &rwn_csr_accattr, &sc->sc_io_handle);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "ddi_regs_map_setup() failed");
		goto fail2;
	}
	RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
	    "PCI configuration is done successfully\n");

	sc->amrr.amrr_min_success_threshold =  1;
	sc->amrr.amrr_max_success_threshold = 15;

	/* wait for NIC to initialize */
	for (ntries = 0; ntries < 100; ntries++) {
		sc->mac_rev = RT2860_READ(sc, RT2860_ASIC_VER_ID);
		if (sc->mac_rev != 0 && sc->mac_rev != 0xffffffff)
			break;
		DELAY(10);
	}
	if (ntries == 100) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "timeout waiting for NIC initialize\n");
		return (DDI_FAILURE);
	}

	if ((sc->mac_rev >> 16) != 0x2860 &&
	    (device_id == PRODUCT_RALINK_RT2890 ||
	    device_id == PRODUCT_RALINK_RT2790 ||
	    device_id == PRODUCT_AWT_RT2890))
		sc->sc_flags |= RT2860_ADVANCED_PS;

	/* retrieve RF rev. no and various other things from EEPROM */
	(void) rt2860_read_eeprom(sc);
	RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
	    "MAC/BBP RT%X (rev 0x%04X), RF %s (%dT%dR)\n",
	    sc->mac_rev >> 16, sc->mac_rev & 0xffff,
	    rt2860_get_rf(sc->rf_rev), sc->ntxchains, sc->nrxchains);

	/*
	 * Allocate Tx (4 EDCAs + HCCA + Mgt) and Rx rings.
	 */
	for (qid = 0; qid < 6; qid++) {
		if ((err = rt2860_alloc_tx_ring(sc, &sc->txq[qid])) != 0) {
			RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
			    "could not allocate Tx ring %d\n", qid);
			goto fail3;
		}
	}

	if ((err = rt2860_alloc_rx_ring(sc, &sc->rxq)) != 0) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "could not allocte Rx ring\n");
		goto fail4;
	}

	if ((err = rt2860_alloc_tx_pool(sc)) != 0) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "could not allocte Tx pool\n");
		goto fail5;
	}

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxlock, NULL, MUTEX_DRIVER, NULL);

	/* mgmt ring is broken on RT2860C, use EDCA AC VO ring instead */
	sc->mgtqid = (sc->mac_rev == 0x28600100) ? EDCA_AC_VO : 5;
	RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach():"
	    "mgtqid = %x\n", sc->mgtqid);

	ic->ic_phytype = IEEE80211_T_OFDM; /* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA; /* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;		/* short slot time supported */

	/* WPA/WPA2 support */
	ic->ic_caps |= IEEE80211_C_WPA; /* Support WPA/WPA2 */

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = rt2860_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = rt2860_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	ic->ic_maxrssi = 63;
	ic->ic_xmit = rt2860_send;

	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	/* override state transition machine */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = rt2860_newstate;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW,
	    &sc->sc_softintr_hdl, NULL, 0, rt2860_softintr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "ddi_add_softintr() failed");
		goto fail8;
	}

	err = ddi_get_iblock_cookie(devinfo, 0, &sc->sc_iblock);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "Can not get iblock cookie for INT\n");
		goto fail7;
	}

	err = ddi_add_intr(devinfo, 0, NULL, NULL, rt2860_intr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "unable to add device interrupt handler\n");
		goto fail7;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "MAC version mismatch\n");
		goto fail9;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &rt2860_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach(): "
		    "mac_register err %x\n", err);
		goto fail9;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "rwn", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	sc->sc_flags &= ~RT2860_F_RUNNING;

	RWN_DEBUG(RT2860_DBG_MSG, "rwn: rt2860_attach() successfully.\n");
	return (DDI_SUCCESS);
fail9:
	ddi_remove_softintr(sc->sc_softintr_hdl);
fail8:
	ddi_remove_intr(devinfo, 0, sc->sc_iblock);
fail7:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_txlock);
	mutex_destroy(&sc->sc_rxlock);
fail6:
	rt2860_free_tx_pool(sc);
fail5:
	rt2860_free_rx_ring(sc, &sc->rxq);
fail4:
	while (--qid >= 0)
		rt2860_free_tx_ring(sc, &sc->txq[qid]);
fail3:
	ddi_regs_map_free(&sc->sc_io_handle);
fail2:
	ddi_regs_map_free(&sc->sc_cfg_handle);
fail1:
	return (err);
}

static int
rt2860_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct rt2860_softc	*sc;
	int			qid;

	sc = ddi_get_soft_state(rt2860_soft_state_p, ddi_get_instance(devinfo));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (RT2860_IS_RUNNING(sc))
			rt2860_stop(sc);
		RT2860_GLOCK(sc);
		sc->sc_flags &= ~RT2860_FWLOADED;
		sc->sc_flags |= RT2860_F_SUSPEND;
		RT2860_GUNLOCK(sc);
		RWN_DEBUG(RT2860_DBG_RESUME, "rwn: rt2860_detach(): "
		    "suspend now\n");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	rt2860_stop(sc);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	ddi_remove_intr(devinfo, 0, sc->sc_iblock);
	ddi_remove_softintr(sc->sc_softintr_hdl);

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);

	rt2860_free_tx_pool(sc);
	rt2860_free_rx_ring(sc, &sc->rxq);
	for (qid = 0; qid < 6; qid++)
		rt2860_free_tx_ring(sc, &sc->txq[qid]);

	ddi_regs_map_free(&sc->sc_io_handle);

	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_txlock);
	mutex_destroy(&sc->sc_rxlock);

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(rt2860_soft_state_p, ddi_get_instance(devinfo));

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

	status = ddi_soft_state_init(&rt2860_soft_state_p,
	    sizeof (struct rt2860_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&rwn_dev_ops, "rwn");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&rwn_dev_ops);
		ddi_soft_state_fini(&rt2860_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&rwn_dev_ops);
		ddi_soft_state_fini(&rt2860_soft_state_p);
	}
	return (status);
}
