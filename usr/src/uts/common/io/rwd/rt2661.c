/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2006
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
 * Ralink Technology RT2561, RT2561S and RT2661  chipset driver
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
#include <sys/ethernet.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <sys/note.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/net80211_proto.h>
#include <sys/varargs.h>
#include <sys/policy.h>
#include <sys/pci.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <inet/wifi_ioctl.h>

#include "rt2661_reg.h"
#include "rt2661_var.h"
#include "rt2661_ucode.h"

#define	RT2661_DBG_80211	(1 << 0)
#define	RT2661_DBG_DMA		(1 << 1)
#define	RT2661_DBG_EEPROM	(1 << 2)
#define	RT2661_DBG_FW		(1 << 3)
#define	RT2661_DBG_HW		(1 << 4)
#define	RT2661_DBG_INTR		(1 << 5)
#define	RT2661_DBG_RX		(1 << 6)
#define	RT2661_DBG_SCAN		(1 << 7)
#define	RT2661_DBG_TX		(1 << 8)
#define	RT2661_DBG_RADIO	(1 << 9)
#define	RT2661_DBG_RESUME	(1 << 10)
#define	RT2661_DBG_MSG		(1 << 11)

uint32_t rt2661_dbg_flags = 0;

#ifdef DEBUG
#define	RWD_DEBUG \
	rt2661_debug
#else
#define	RWD_DEBUG
#endif

static void *rt2661_soft_state_p = NULL;

static const uint8_t *ucode = NULL;
int usize;

static const struct {
	uint32_t	reg;
	uint32_t	val;
} rt2661_def_mac[] = {
	RT2661_DEF_MAC
};

static const struct {
	uint8_t	reg;
	uint8_t	val;
} rt2661_def_bbp[] = {
	RT2661_DEF_BBP
};

static const struct rfprog {
	uint8_t		chan;
	uint32_t	r1, r2, r3, r4;
}  rt2661_rf5225_1[] = {
	RT2661_RF5225_1
}, rt2661_rf5225_2[] = {
	RT2661_RF5225_2
};

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t rt2661_csr_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for descriptors: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t rt2661_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

static ddi_device_acc_attr_t rt2661_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t rt2661_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0,				/* dma_attr_addr_lo */
	0xffffffffU,			/* dma_attr_addr_hi */
	0xffffffffU,			/* dma_attr_count_max */
	1,				/* dma_attr_align */
	0x00000fff,			/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	0xffffffffU,			/* dma_attr_maxxfer */
	0xffffffffU,			/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0				/* dma_attr_flags */
};

static const struct ieee80211_rateset rt2661_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset rt2661_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };


static const char *rt2661_get_rf(int);

static void	rt2661_read_eeprom(struct rt2661_softc *);
static uint16_t	rt2661_eeprom_read(struct rt2661_softc *, uint8_t);
static int	rt2661_load_microcode(struct rt2661_softc *,
		    const uint8_t *, int);

static int	rt2661_alloc_dma_mem(dev_info_t *, ddi_dma_attr_t *, size_t,
		    ddi_device_acc_attr_t *, uint_t, uint_t, struct dma_area *);
static void	rt2661_free_dma_mem(struct dma_area *);
static int	rt2661_alloc_tx_ring(struct rt2661_softc *,
		    struct rt2661_tx_ring *, int);
static void	rt2661_reset_tx_ring(struct rt2661_softc *,
		    struct rt2661_tx_ring *);
static void	rt2661_free_tx_ring(struct rt2661_softc *,
		    struct rt2661_tx_ring *);
static int	rt2661_alloc_rx_ring(struct rt2661_softc *,
		    struct rt2661_rx_ring *, int);
static void	rt2661_reset_rx_ring(struct rt2661_softc *,
		    struct rt2661_rx_ring *);
static void	rt2661_free_rx_ring(struct rt2661_softc *,
		    struct rt2661_rx_ring *);
static void	rt2661_tx_dma_intr(struct rt2661_softc *,
		    struct rt2661_tx_ring *);
static void	rt2661_tx_intr(struct rt2661_softc *);
static void	rt2661_rx_intr(struct rt2661_softc *);
static uint_t	rt2661_softintr(caddr_t, caddr_t);
static void	rt2661_mcu_wakeup(struct rt2661_softc *);
static void	rt2661_mcu_cmd_intr(struct rt2661_softc *);
static uint_t	rt2661_intr(caddr_t, caddr_t);

static uint16_t	rt2661_txtime(int, int, uint32_t);
static int	rt2661_ack_rate(struct ieee80211com *, int);
static uint8_t	rt2661_plcp_signal(int);
static void	rt2661_setup_tx_desc(struct rt2661_softc *,
		    struct rt2661_tx_desc *, uint32_t, uint16_t, int,
		    int, int);

static int	rt2661_get_rssi(struct rt2661_softc *, uint8_t);

static int	rt2661_send(ieee80211com_t *, mblk_t *);
static int	rt2661_mgmt_send(ieee80211com_t *, mblk_t *, uint8_t);

static void	rt2661_amrr_node_init(const struct rt2661_amrr *,
		    struct rt2661_amrr_node *);
static void	rt2661_amrr_choose(struct rt2661_amrr *,
		    struct ieee80211_node *, struct rt2661_amrr_node *);

static void	rt2661_update_promisc(struct rt2661_softc *);
static void	rt2661_updateslot(struct ieee80211com *, int);
static void	rt2661_set_slottime(struct rt2661_softc *);
static void	rt2661_enable_mrr(struct rt2661_softc *);
static void	rt2661_set_txpreamble(struct rt2661_softc *);
static void	rt2661_set_basicrates(struct rt2661_softc *);
static void	rt2661_set_bssid(struct rt2661_softc *, const uint8_t *);
static void	rt2661_newassoc(struct ieee80211com *, struct ieee80211_node *);
static void	rt2661_updatestats(void *);
static void	rt2661_rx_tune(struct rt2661_softc *);
static void	rt2661_enable_tsf_sync(struct rt2661_softc *);
static int	rt2661_newstate(struct ieee80211com *,
		    enum ieee80211_state, int);

static void	rt2661_set_macaddr(struct rt2661_softc *, const uint8_t *);
static int	rt2661_bbp_init(struct rt2661_softc *);
static uint8_t	rt2661_bbp_read(struct rt2661_softc *, uint8_t);
static void	rt2661_bbp_write(struct rt2661_softc *, uint8_t, uint8_t);
static void	rt2661_select_band(struct rt2661_softc *,
		    struct ieee80211_channel *);
static void	rt2661_select_antenna(struct rt2661_softc *);
static void	rt2661_rf_write(struct rt2661_softc *, uint8_t, uint32_t);
static void	rt2661_set_chan(struct rt2661_softc *,
		    struct ieee80211_channel *);

static void	rt2661_stop_locked(struct rt2661_softc *);
static int	rt2661_init(struct rt2661_softc *);
static void	rt2661_stop(struct rt2661_softc *);
/*
 * device operations
 */
static int rt2661_attach(dev_info_t *, ddi_attach_cmd_t);
static int rt2661_detach(dev_info_t *, ddi_detach_cmd_t);
static int rt2661_quiesce(dev_info_t *);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(rwd_dev_ops, nulldev, nulldev, rt2661_attach,
    rt2661_detach, nodev, NULL, D_MP, NULL, rt2661_quiesce);

static struct modldrv rwd_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Ralink RT2661 driver v1.1",	/* short description */
	&rwd_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&rwd_modldrv,
	NULL
};

static int	rt2661_m_stat(void *,  uint_t, uint64_t *);
static int	rt2661_m_start(void *);
static void	rt2661_m_stop(void *);
static int	rt2661_m_promisc(void *, boolean_t);
static int	rt2661_m_multicst(void *, boolean_t, const uint8_t *);
static int	rt2661_m_unicst(void *, const uint8_t *);
static mblk_t	*rt2661_m_tx(void *, mblk_t *);
static void	rt2661_m_ioctl(void *, queue_t *, mblk_t *);
static int	rt2661_m_setprop(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num,
		    uint_t wldp_length, const void *wldp_buf);
static int	rt2661_m_getprop(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num, uint_t wldp_length,
		    void *wldp_buf);
static void	rt2661_m_propinfo(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num, mac_prop_info_handle_t mph);

static mac_callbacks_t rt2661_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	rt2661_m_stat,
	rt2661_m_start,
	rt2661_m_stop,
	rt2661_m_promisc,
	rt2661_m_multicst,
	rt2661_m_unicst,
	rt2661_m_tx,
	NULL,
	rt2661_m_ioctl,
	NULL,
	NULL,
	NULL,
	rt2661_m_setprop,
	rt2661_m_getprop,
	rt2661_m_propinfo
};

#ifdef DEBUG
void
rt2661_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & rt2661_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}
#endif

/*
 * Read 16 bits at address 'addr' from the serial EEPROM (either 93C46 or
 * 93C66).
 */
static uint16_t
rt2661_eeprom_read(struct rt2661_softc *sc, uint8_t addr)
{
	uint32_t tmp;
	uint16_t val;
	int n;

	/* clock C once before the first command */
	RT2661_EEPROM_CTL(sc, 0);

	RT2661_EEPROM_CTL(sc, RT2661_S);
	RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_C);
	RT2661_EEPROM_CTL(sc, RT2661_S);

	/* write start bit (1) */
	RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_D);
	RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_D | RT2661_C);

	/* write READ opcode (10) */
	RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_D);
	RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_D | RT2661_C);
	RT2661_EEPROM_CTL(sc, RT2661_S);
	RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_C);

	/* write address (A5-A0 or A7-A0) */
	n = (RT2661_READ(sc, RT2661_E2PROM_CSR) & RT2661_93C46) ? 5 : 7;
	for (; n >= 0; n--) {
		RT2661_EEPROM_CTL(sc, RT2661_S |
		    (((addr >> n) & 1) << RT2661_SHIFT_D));
		RT2661_EEPROM_CTL(sc, RT2661_S |
		    (((addr >> n) & 1) << RT2661_SHIFT_D) | RT2661_C);
	}

	RT2661_EEPROM_CTL(sc, RT2661_S);

	/* read data Q15-Q0 */
	val = 0;
	for (n = 15; n >= 0; n--) {
		RT2661_EEPROM_CTL(sc, RT2661_S | RT2661_C);
		tmp = RT2661_READ(sc, RT2661_E2PROM_CSR);
		val |= ((tmp & RT2661_Q) >> RT2661_SHIFT_Q) << n;
		RT2661_EEPROM_CTL(sc, RT2661_S);
	}

	RT2661_EEPROM_CTL(sc, 0);

	/* clear Chip Select and clock C */
	RT2661_EEPROM_CTL(sc, RT2661_S);
	RT2661_EEPROM_CTL(sc, 0);
	RT2661_EEPROM_CTL(sc, RT2661_C);

	return (val);
}


static void
rt2661_read_eeprom(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t val;
	int i;

	/* read MAC address */
	val = rt2661_eeprom_read(sc, RT2661_EEPROM_MAC01);
	ic->ic_macaddr[0] = val & 0xff;
	ic->ic_macaddr[1] = val >> 8;

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_MAC23);
	ic->ic_macaddr[2] = val & 0xff;
	ic->ic_macaddr[3] = val >> 8;

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_MAC45);
	ic->ic_macaddr[4] = val & 0xff;
	ic->ic_macaddr[5] = val >> 8;

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_ANTENNA);
	/* XXX: test if different from 0xffff? */
	sc->rf_rev   = (val >> 11) & 0x1f;
	sc->hw_radio = (val >> 10) & 0x1;
	sc->rx_ant   = (val >> 4)  & 0x3;
	sc->tx_ant   = (val >> 2)  & 0x3;
	sc->nb_ant   = val & 0x3;

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
	    "RF revision=%d\n", sc->rf_rev);

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_CONFIG2);
	sc->ext_5ghz_lna = (val >> 6) & 0x1;
	sc->ext_2ghz_lna = (val >> 4) & 0x1;

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
	    "External 2GHz LNA=%d\nExternal 5GHz LNA=%d\n",
	    sc->ext_2ghz_lna, sc->ext_5ghz_lna);

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_RSSI_2GHZ_OFFSET);
	if ((val & 0xff) != 0xff)
		sc->rssi_2ghz_corr = (int8_t)(val & 0xff);

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_RSSI_5GHZ_OFFSET);
	if ((val & 0xff) != 0xff)
		sc->rssi_5ghz_corr = (int8_t)(val & 0xff);

	/* adjust RSSI correction for external low-noise amplifier */
	if (sc->ext_2ghz_lna)
		sc->rssi_2ghz_corr -= 14;
	if (sc->ext_5ghz_lna)
		sc->rssi_5ghz_corr -= 14;

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
	    "RSSI 2GHz corr=%d\nRSSI 5GHz corr=%d\n",
	    sc->rssi_2ghz_corr, sc->rssi_5ghz_corr);

	val = rt2661_eeprom_read(sc, RT2661_EEPROM_FREQ_OFFSET);
	if ((val >> 8) != 0xff)
		sc->rfprog = (val >> 8) & 0x3;
	if ((val & 0xff) != 0xff)
		sc->rffreq = val & 0xff;

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
	    "RF prog=%d\nRF freq=%d\n", sc->rfprog, sc->rffreq);

	/* read Tx power for all a/b/g channels */
	for (i = 0; i < 19; i++) {
		val = rt2661_eeprom_read(sc, RT2661_EEPROM_TXPOWER + i);
		sc->txpow[i * 2] = (int8_t)(val >> 8);
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
		    "Channel=%d Tx power=%d\n",
		    rt2661_rf5225_1[i * 2].chan, sc->txpow[i * 2]);
		sc->txpow[i * 2 + 1] = (int8_t)(val & 0xff);
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
		    "Channel=%d Tx power=%d\n",
		    rt2661_rf5225_1[i * 2 + 1].chan, sc->txpow[i * 2 + 1]);
	}

	/* read vendor-specific BBP values */
	for (i = 0; i < 16; i++) {
		val = rt2661_eeprom_read(sc, RT2661_EEPROM_BBP_BASE + i);
		if (val == 0 || val == 0xffff)
			continue;
		sc->bbp_prom[i].reg = val >> 8;
		sc->bbp_prom[i].val = val & 0xff;
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_read_eeprom(): "
		    "BBP R%d=%02x\n", sc->bbp_prom[i].reg,
		    sc->bbp_prom[i].val);
	}
}

static const char *
rt2661_get_rf(int rev)
{
	switch (rev) {
	case RT2661_RF_5225:	return "RT5225";
	case RT2661_RF_5325:	return "RT5325 (MIMO XR)";
	case RT2661_RF_2527:	return "RT2527";
	case RT2661_RF_2529:	return "RT2529 (MIMO XR)";
	default:		return "unknown";
	}
}

static int
rt2661_load_microcode(struct rt2661_softc *sc, const uint8_t *ucode_p, int size)
{
	int ntries;
	uint32_t off, i;
	const uint8_t *fptr;

	fptr = ucode_p;
	off = RT2661_MCU_CODE_BASE;

	/* reset 8051 */
	RT2661_WRITE(sc, RT2661_MCU_CNTL_CSR, RT2661_MCU_RESET);

	/* cancel any pending Host to MCU command */
	RT2661_WRITE(sc, RT2661_H2M_MAILBOX_CSR, 0);
	RT2661_WRITE(sc, RT2661_M2H_CMD_DONE_CSR, 0xffffffff);
	RT2661_WRITE(sc, RT2661_HOST_CMD_CSR, 0);

	/* write 8051's microcode */
	RT2661_WRITE(sc, RT2661_MCU_CNTL_CSR,
	    RT2661_MCU_RESET | RT2661_MCU_SEL);
	/* RT2661_WRITE_REGION_1(sc, RT2661_MCU_CODE_BASE, ucode, size); */

	for (i = 0; i < size; i++) {
		RT2661_MEM_WRITE1(sc, off++, *fptr++);
	}

	RT2661_WRITE(sc, RT2661_MCU_CNTL_CSR, RT2661_MCU_RESET);

	/* kick 8051's ass */
	RT2661_WRITE(sc, RT2661_MCU_CNTL_CSR, 0);

	/* wait for 8051 to initialize */
	for (ntries = 0; ntries < 500; ntries++) {
		if (RT2661_READ(sc, RT2661_MCU_CNTL_CSR) & RT2661_MCU_READY)
			break;
		DELAY(100);
	}
	if (ntries == 500) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_load_microcode(): "
		    "timeout waiting for MCU to initialize\n");
		return (RT2661_FAILURE);
	}

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_load_microcode(): "
	    "MCU initialized successfully\n");
	return (RT2661_SUCCESS);
}

/*
 * Allocate an DMA memory and a DMA handle for accessing it
 */
static int
rt2661_alloc_dma_mem(dev_info_t *devinfo, ddi_dma_attr_t *dma_attr,
	size_t memsize, ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
	uint_t bind_flags, struct dma_area *dma_p)
{
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rwd_allo_dma_mem(): "
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
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rwd_alloc_dma_mem(): "
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
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rwd_alloc_dma_mem(): "
		    "failed to bind handle\n");
		goto fail3;
	}

	if (dma_p->ncookies != 1) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rwd_alloc_dma_mem(): "
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
rt2661_free_dma_mem(struct dma_area *dma_p)
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
rt2661_alloc_tx_ring(struct rt2661_softc *sc,
    struct rt2661_tx_ring *ring, int count)
{
	struct rt2661_tx_desc *desc;
	struct rt2661_tx_data *data;
	int i, err, size, len;

	size = count * RT2661_TX_DESC_SIZE;
	len = count * sizeof (struct rt2661_tx_data);

	ring->count = count;
	ring->queued = 0;
	ring->cur = 0;
	ring->next = 0;
	ring->stat = 0;

	err = rt2661_alloc_dma_mem(sc->sc_dev, &rt2661_dma_attr, size,
	    &rt2661_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->txdesc_dma);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_DMA, "rwd: rt2661_alloc_tx_ring(): "
		    "failed to alloc dma mem\n");
		goto fail1;
	}

	ring->desc = (struct rt2661_tx_desc *)ring->txdesc_dma.mem_va;
	(void) bzero(ring->desc, size);
	ring->paddr = ring->txdesc_dma.cookie.dmac_address;

	ring->data = kmem_zalloc(len, KM_NOSLEEP);
	if (ring->data == NULL) {
		RWD_DEBUG(RT2661_DBG_DMA, "rwd: rt2661_alloc_tx_ring(): "
		    "failed to alloc tx buffer\n");
		goto fail2;
	}

	for (i = 0; i < count; i++) {
		desc = &ring->desc[i];
		data = &ring->data[i];
		err = rt2661_alloc_dma_mem(sc->sc_dev,
		    &rt2661_dma_attr, sc->sc_dmabuf_size,
		    &rt2661_buf_accattr, DDI_DMA_CONSISTENT,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    &data->txdata_dma);
		if (err != DDI_SUCCESS) {
			RWD_DEBUG(RT2661_DBG_DMA,
			    "rwd: rt2661_alloc_tx_ring(): "
			    "failed to alloc tx buffer dma\n");
			while (i >= 0) {
				rt2661_free_dma_mem(&ring->data[i].txdata_dma);
				i--;
			}
			goto fail3;
		}
		desc->addr[0] = data->txdata_dma.cookie.dmac_address;
		data->buf = data->txdata_dma.mem_va;
		data->paddr = data->txdata_dma.cookie.dmac_address;
	}

	(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
	    0, size, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
fail3:
	if (ring->data)
		kmem_free(ring->data,
		    count * sizeof (struct rt2661_tx_data));
fail2:
	rt2661_free_dma_mem(&ring->txdesc_dma);
fail1:
	return (err);
}

static void
rt2661_reset_tx_ring(struct rt2661_softc *sc, struct rt2661_tx_ring *ring)
{
	struct rt2661_tx_desc *desc;
	struct rt2661_tx_data *data;
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

	if (!RT2661_IS_FASTREBOOT(sc))
		(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl, 0,
		    ring->count * sizeof (struct rt2661_tx_desc),
		    DDI_DMA_SYNC_FORDEV);

	ring->queued = 0;
	ring->cur = ring->next = ring->stat = 0;
}


/*ARGSUSED*/
static void
rt2661_free_tx_ring(struct rt2661_softc *sc, struct rt2661_tx_ring *ring)
{
	struct rt2661_tx_data *data;
	int i;

	if (ring->desc != NULL) {
		rt2661_free_dma_mem(&ring->txdesc_dma);
	}

	if (ring->data != NULL) {
		for (i = 0; i < ring->count; i++) {
			data = &ring->data[i];
			rt2661_free_dma_mem(&data->txdata_dma);
			if (data->ni != NULL) {
				ieee80211_free_node(data->ni);
				data->ni = NULL;
			}
		}
		kmem_free(ring->data,
		    ring->count * sizeof (struct rt2661_tx_data));
	}
}

/*ARGSUSED*/
static int
rt2661_alloc_rx_ring(struct rt2661_softc *sc,
    struct rt2661_rx_ring *ring, int count)
{
	struct rt2661_rx_desc *desc;
	struct rt2661_rx_data *data;
	int i, err, len, size;

	size = count * RT2661_RX_DESC_SIZE;
	len = count * sizeof (struct rt2661_rx_data);

	ring->count = count;
	ring->cur = 0;
	ring->next = 0;

	err = rt2661_alloc_dma_mem(sc->sc_dev, &rt2661_dma_attr, size,
	    &rt2661_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->rxdesc_dma);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_DMA, "rwd: rt2661_alloc_rx_ring(): "
		    "failed to alloc dma mem\n");
		goto fail1;
	}

	ring->desc = (struct rt2661_rx_desc *)ring->rxdesc_dma.mem_va;
	(void) bzero(ring->desc, size);
	ring->paddr = ring->rxdesc_dma.cookie.dmac_address;

	ring->data = kmem_zalloc(len, KM_NOSLEEP);
	if (ring->data == NULL) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_alloc_rx_ring(): "
		    "failed to alloc rx buffer\n");
		goto fail2;
	}

	for (i = 0; i < count; i++) {
		desc = &ring->desc[i];
		data = &ring->data[i];
		err = rt2661_alloc_dma_mem(sc->sc_dev,
		    &rt2661_dma_attr, sc->sc_dmabuf_size,
		    &rt2661_buf_accattr, DDI_DMA_CONSISTENT,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    &data->rxdata_dma);
		if (err != DDI_SUCCESS) {
			RWD_DEBUG(RT2661_DBG_DMA,
			    "rwd: rt2661_alloc_rx_ring(): "
			    "failed to alloc rx buffer dma\n");
			while (i >= 0) {
				rt2661_free_dma_mem(&ring->data[i].rxdata_dma);
				i--;
			}
			goto fail3;
		}
		data->buf = data->rxdata_dma.mem_va;
		data->paddr = data->rxdata_dma.cookie.dmac_address;
		desc->flags = LE_32(RT2661_RX_BUSY);
		desc->physaddr = LE_32(data->paddr);
	}

	(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
	    0, size, DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
fail3:
	if (ring->data)
		kmem_free(ring->data,
		    count * sizeof (struct rt2661_rx_data));
fail2:
	rt2661_free_dma_mem(&ring->rxdesc_dma);
fail1:
	return (err);
}

static void
rt2661_reset_rx_ring(struct rt2661_softc *sc, struct rt2661_rx_ring *ring)
{
	int i;

	for (i = 0; i < ring->count; i++)
		ring->desc[i].flags = LE_32(RT2661_RX_BUSY);

	if (!RT2661_IS_FASTREBOOT(sc))
		(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl, 0,
		    ring->count * sizeof (struct rt2661_rx_ring),
		    DDI_DMA_SYNC_FORKERNEL);

	ring->cur = ring->next = 0;
}

/*ARGSUSED*/
static void
rt2661_free_rx_ring(struct rt2661_softc *sc, struct rt2661_rx_ring *ring)
{
	struct rt2661_rx_data *data;
	int i;

	if (ring->desc != NULL) {
		rt2661_free_dma_mem(&ring->rxdesc_dma);
	}

	if (ring->data != NULL) {
		for (i = 0; i < ring->count; i++) {
			data = &ring->data[i];
			rt2661_free_dma_mem(&data->rxdata_dma);
		}
		kmem_free(ring->data,
		    ring->count * sizeof (struct rt2661_rx_data));
	}
}

static void
rt2661_tx_dma_intr(struct rt2661_softc *sc, struct rt2661_tx_ring *ring)
{
	struct rt2661_tx_desc *desc;
	struct rt2661_tx_data *data;

	for (;;) {
		desc = &ring->desc[ring->next];
		data = &ring->data[ring->next];

		(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
		    ring->next * RT2661_TX_DESC_SIZE,
		    RT2661_TX_DESC_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);

		if ((LE_32(desc->flags) & RT2661_TX_BUSY) ||
		    !(LE_32(desc->flags) & RT2661_TX_VALID))
			break;

		(void) ddi_dma_sync(data->txdata_dma.dma_hdl,
		    0, sc->sc_dmabuf_size,
		    DDI_DMA_SYNC_FORDEV);

		/* descriptor is no longer valid */
		desc->flags &= ~LE_32(RT2661_TX_VALID);

		(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
		    ring->next * RT2661_TX_DESC_SIZE,
		    RT2661_TX_DESC_SIZE,
		    DDI_DMA_SYNC_FORDEV);

		RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_dma_intr(): "
		    "tx dma done q=%p idx=%u\n", ring, ring->next);

		if (++ring->next >= ring->count) /* faster than % count */
			ring->next = 0;
	}
}

static void
rt2661_tx_intr(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct rt2661_tx_ring *ring;
	struct rt2661_tx_data *data;
	struct rt2661_node *rn;

	uint32_t val;
	int qid, retrycnt;

	for (;;) {
		val = RT2661_READ(sc, RT2661_STA_CSR4);
		if (!(val & RT2661_TX_STAT_VALID))
			break;

		/* retrieve the queue in which this frame was send */
		qid = RT2661_TX_QID(val);
		ring = (qid <= 3) ? &sc->txq[qid] : &sc->mgtq;

		/* retrieve rate control algorithm context */
		data = &ring->data[ring->stat];
		rn = (struct rt2661_node *)data->ni;

		/* if no frame has been sent, ignore */
		if (rn == NULL) {
			RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_intr(): "
			    "no frame has been send, ignore\n");
			continue;
		}

		switch (RT2661_TX_RESULT(val)) {
		case RT2661_TX_SUCCESS:
			retrycnt = RT2661_TX_RETRYCNT(val);

			RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_intr(): "
			    "data frame sent successfully after "
			    "%d retries\n", retrycnt);
			rn->amn.amn_txcnt++;
			if (retrycnt > 0) {
				rn->amn.amn_retrycnt++;
				sc->sc_tx_retries++;
			}
			break;
		case RT2661_TX_RETRY_FAIL:
			RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_intr(): "
			    "sending data frame failed (too much retries)\n");
			rn->amn.amn_txcnt++;
			rn->amn.amn_retrycnt++;
			break;
		default:
			/* other failure */
			RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_intr():"
			    "sending data frame failed 0x%08x\n", val);
		}

		RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_intr(): "
		    "tx done q=%d idx=%u\n", qid, ring->stat);

		ieee80211_free_node(data->ni);
		data->ni = NULL;

		ring->queued--;

		/* faster than % count */
		if (++ring->stat >= ring->count)
			ring->stat = 0;

		if (sc->sc_need_sched) {
			sc->sc_need_sched = 0;
			mac_tx_update(ic->ic_mach);
		}
	}
	sc->sc_tx_timer = 0;
}

static void
rt2661_rx_intr(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct rt2661_rx_ring *ring;
	struct rt2661_rx_desc *desc;
	struct rt2661_rx_data *data;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	mblk_t *m;
	uint8_t *rxbuf;
	uint32_t pktlen;

	mutex_enter(&sc->sc_rxlock);
	ring = &sc->rxq;

	for (;;) {
		int rssi;

		desc = &ring->desc[ring->cur];
		data = &ring->data[ring->cur];

		(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
		    ring->cur * RT2661_RX_DESC_SIZE,
		    RT2661_RX_DESC_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);


		if (LE_32(desc->flags) & RT2661_RX_BUSY)
			break;

		if ((LE_32(desc->flags) & RT2661_RX_PHY_ERROR) ||
		    (LE_32(desc->flags) & RT2661_RX_CRC_ERROR)) {
			/*
			 * This should not happen since we did not request
			 * to receive those frames when we filled TXRX_CSR0.
			 */
			RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_rx_intr(): "
			    "PHY or CRC error flags 0x%08x\n",
			    LE_32(desc->flags));
			sc->sc_rx_err++;
			goto skip;
		}

		if ((LE_32(desc->flags) & RT2661_RX_CIPHER_MASK) != 0) {
			sc->sc_rx_err++;
			goto skip;
		}

		(void) ddi_dma_sync(data->rxdata_dma.dma_hdl,
		    0, sc->sc_dmabuf_size,
		    DDI_DMA_SYNC_FORCPU);

		rxbuf = (uint8_t *)data->rxdata_dma.mem_va;
		desc->physaddr = LE_32(data->rxdata_dma.cookie.dmac_address);
		pktlen = (LE_32(desc->flags) >> 16) & 0xfff;
		if ((pktlen < sizeof (struct ieee80211_frame_min)) ||
		    (pktlen > sc->sc_dmabuf_size)) {
			RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_rx_intr(): "
			    "bad fram length=%u\n", pktlen);
			sc->sc_rx_err++;
			goto skip;
		}

		if ((m = allocb(pktlen, BPRI_MED)) == NULL) {
			RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_rx_intr(): "
			    "allocate mblk failed.\n");
			sc->sc_rx_nobuf++;
			goto skip;
		}

		bcopy(rxbuf, m->b_rptr, pktlen);
		m->b_wptr += pktlen;

		wh = (struct ieee80211_frame *)m->b_rptr;
		ni = ieee80211_find_rxnode(ic, wh);

		rssi = rt2661_get_rssi(sc, desc->rssi);
		/* send the frame to the 802.11 layer */
		(void) ieee80211_input(ic, m, ni, rssi + 95, 0);

		sc->avg_rssi = (rssi + 7 * sc->avg_rssi) / 8;

		/* node is no longer needed */
		ieee80211_free_node(ni);
skip:
		desc->flags |= LE_32(RT2661_RX_BUSY);

		(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
		    ring->cur * RT2661_RX_DESC_SIZE,
		    RT2661_RX_DESC_SIZE,
		    DDI_DMA_SYNC_FORDEV);

		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_rx_intr(): "
		    "rx intr idx=%u\n", sc->rxq.cur);
		ring->cur = (ring->cur + 1) % RT2661_RX_RING_COUNT;
	}
	mutex_exit(&sc->sc_rxlock);
}

/*ARGSUSED*/
static uint_t
rt2661_softintr(caddr_t data, caddr_t unused)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)data;

	if (sc->sc_rx_pend) {
		sc->sc_rx_pend = 0;
		rt2661_rx_intr(sc);
		return (DDI_INTR_CLAIMED);
	}
	return (DDI_INTR_UNCLAIMED);
}

static int
rt2661_tx_cmd(struct rt2661_softc *sc, uint8_t cmd, uint16_t arg)
{
	if (RT2661_READ(sc, RT2661_H2M_MAILBOX_CSR) & RT2661_H2M_BUSY)
		return (EIO);	/* there is already a command pending */

	RT2661_WRITE(sc, RT2661_H2M_MAILBOX_CSR,
	    RT2661_H2M_BUSY | RT2661_TOKEN_NO_INTR << 16 | arg);

	RT2661_WRITE(sc, RT2661_HOST_CMD_CSR, RT2661_KICK_CMD | cmd);

	return (0);
}

static void
rt2661_mcu_wakeup(struct rt2661_softc *sc)
{
	RT2661_WRITE(sc, RT2661_MAC_CSR11, 5 << 16);

	RT2661_WRITE(sc, RT2661_SOFT_RESET_CSR, 0x7);
	RT2661_WRITE(sc, RT2661_IO_CNTL_CSR, 0x18);
	RT2661_WRITE(sc, RT2661_PCI_USEC_CSR, 0x20);

	/* send wakeup command to MCU */
	(void) rt2661_tx_cmd(sc, RT2661_MCU_CMD_WAKEUP, 0);
}

static void
rt2661_mcu_cmd_intr(struct rt2661_softc *sc)
{
	(void) RT2661_READ(sc, RT2661_M2H_CMD_DONE_CSR);
	RT2661_WRITE(sc, RT2661_M2H_CMD_DONE_CSR, 0xffffffff);
}

/*ARGSUSED*/
static uint_t
rt2661_intr(caddr_t arg, caddr_t unused)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;
	uint32_t r1, r2;

	RT2661_GLOCK(sc);

	if (!RT2661_IS_RUNNING(sc) || RT2661_IS_SUSPEND(sc)) {
		RT2661_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	r1 = RT2661_READ(sc, RT2661_INT_SOURCE_CSR);
	r2 = RT2661_READ(sc, RT2661_MCU_INT_SOURCE_CSR);
	if (r1 == 0 && r2 == 0) {
		RT2661_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);	/* not for us */
	}

	/* disable MAC and MCU interrupts */
	RT2661_WRITE(sc, RT2661_INT_MASK_CSR, 0xffffff7f);
	RT2661_WRITE(sc, RT2661_MCU_INT_MASK_CSR, 0xffffffff);

	/* acknowledge interrupts */
	RT2661_WRITE(sc, RT2661_INT_SOURCE_CSR, r1);
	RT2661_WRITE(sc, RT2661_MCU_INT_SOURCE_CSR, r2);

	if (r1 & RT2661_MGT_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_MGT_DONE\n");
		rt2661_tx_dma_intr(sc, &sc->mgtq);
	}

	if (r1 & RT2661_RX_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_RX_DONE\n");
		sc->sc_rx_pend = 1;
		(void) ddi_intr_trigger_softint(sc->sc_softintr_hdl, NULL);
	}

	if (r1 & RT2661_TX0_DMA_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_TX0_DMA_DONE\n");
		rt2661_tx_dma_intr(sc, &sc->txq[0]);
	}

	if (r1 & RT2661_TX1_DMA_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_TX1_DMA_DONE\n");
		rt2661_tx_dma_intr(sc, &sc->txq[1]);
	}

	if (r1 & RT2661_TX2_DMA_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_TX2_DMA_DONE\n");
		rt2661_tx_dma_intr(sc, &sc->txq[2]);
	}

	if (r1 & RT2661_TX3_DMA_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_TX3_DMA_DONE\n");
		rt2661_tx_dma_intr(sc, &sc->txq[3]);
	}

	if (r1 & RT2661_TX_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_TX_DONE\n");
		rt2661_tx_intr(sc);
	}

	if (r2 & RT2661_MCU_CMD_DONE) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_MCU_CMD_DONE\n");
		rt2661_mcu_cmd_intr(sc);
	}

	if (r2 & RT2661_MCU_WAKEUP) {
		RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_intr(): "
		    "RT2661_MCU_WAKEUP\n");
		rt2661_mcu_wakeup(sc);
	}

	/* re-enable MAC and MCU interrupts */
	RT2661_WRITE(sc, RT2661_INT_MASK_CSR, 0x0000ff10);
	RT2661_WRITE(sc, RT2661_MCU_INT_MASK_CSR, 0);

	RT2661_GUNLOCK(sc);
	return (RT2661_SUCCESS);
}

/*
 * Retrieve the "Received Signal Strength Indicator" from the raw values
 * contained in Rx descriptors.  The computation depends on which band the
 * frame was received.  Correction values taken from the reference driver.
 */
static int
rt2661_get_rssi(struct rt2661_softc *sc, uint8_t raw)
{
	int lna, agc, rssi;

	lna = (raw >> 5) & 0x3;
	agc = raw & 0x1f;

	rssi = 2 * agc;

	if (IEEE80211_IS_CHAN_2GHZ(sc->sc_curchan)) {
		rssi += sc->rssi_2ghz_corr;

		if (lna == 1)
			rssi -= 64;
		else if (lna == 2)
			rssi -= 74;
		else if (lna == 3)
			rssi -= 90;
	} else {
		rssi += sc->rssi_5ghz_corr;

		if (lna == 1)
			rssi -= 64;
		else if (lna == 2)
			rssi -= 86;
		else if (lna == 3)
			rssi -= 100;
	}
	return (rssi);
}

/* quickly determine if a given rate is CCK or OFDM */
#define	RT2661_RATE_IS_OFDM(rate) ((rate) >= 12 && (rate) != 22)

#define	RT2661_ACK_SIZE	14	/* 10 + 4(FCS) */
#define	RT2661_CTS_SIZE	14	/* 10 + 4(FCS) */

#define	RT2661_SIFS	10	/* us */

/*
 * Return the expected ack rate for a frame transmitted at rate `rate'.
 * XXX: this should depend on the destination node basic rate set.
 */
static int
rt2661_ack_rate(struct ieee80211com *ic, int rate)
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
rt2661_txtime(int len, int rate, uint32_t flags)
{
	uint16_t txtime;

	if (RT2661_RATE_IS_OFDM(rate)) {
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
rt2661_plcp_signal(int rate)
{
	switch (rate) {
	/* CCK rates (returned values are device-dependent) */
	case 2:
		return (0x0);
	case 4:
		return (0x1);
	case 11:
		return (0x2);
	case 22:
		return (0x3);

	/* OFDM rates (cf IEEE Std 802.11a-1999, pp. 14 Table 80) */
	case 12:
		return (0xb);
	case 18:
		return (0xf);
	case 24:
		return (0xa);
	case 36:
		return (0xe);
	case 48:
		return (0x9);
	case 72:
		return (0xd);
	case 96:
		return (0x8);
	case 108:
		return (0xc);

	/* unsupported rates (should not get there) */
	default:
		return (0xff);
	}
}

static void
rt2661_setup_tx_desc(struct rt2661_softc *sc, struct rt2661_tx_desc *desc,
    uint32_t flags, uint16_t xflags, int len, int rate, int ac)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t plcp_length;
	int remainder;

	desc->flags = LE_32(flags);
	desc->flags |= LE_32(len << 16);
	desc->flags |= LE_32(RT2661_TX_BUSY | RT2661_TX_VALID);

	desc->xflags = LE_16(xflags);
	desc->xflags |= LE_16(1 << 13);

	desc->wme = LE_16(
	    RT2661_QID(ac) |
	    RT2661_AIFSN(2) |
	    RT2661_LOGCWMIN(4) |
	    RT2661_LOGCWMAX(10));

	/*
	 * Remember in which queue this frame was sent. This field is driver
	 * private data only. It will be made available by the NIC in STA_CSR4
	 * on Tx interrupts.
	 */
	desc->qid = (uint8_t)ac;

	/* setup PLCP fields */
	desc->plcp_signal  = rt2661_plcp_signal(rate);
	desc->plcp_service = 4;

	len += IEEE80211_CRC_LEN;

	if (RT2661_RATE_IS_OFDM(rate)) {
		desc->flags |= LE_32(RT2661_TX_OFDM);

		plcp_length = len & 0xfff;
		desc->plcp_length_hi = plcp_length >> 6;
		desc->plcp_length_lo = plcp_length & 0x3f;
	} else {
		plcp_length = (16 * len + rate - 1) / rate;
		if (rate == 22) {
			remainder = (16 * len) % 22;
			if (remainder != 0 && remainder < 7)
				desc->plcp_service |= RT2661_PLCP_LENGEXT;
		}
		desc->plcp_length_hi = plcp_length >> 8;
		desc->plcp_length_lo = plcp_length & 0xff;

		if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
			desc->plcp_signal |= 0x08;
	}

	/* RT2x61 supports scatter with up to 5 segments */
	desc->len [0] = LE_16(len);
}

static int
rt2661_send(ieee80211com_t *ic, mblk_t *mp)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)ic;
	struct rt2661_tx_ring *ring;
	struct rt2661_tx_desc *desc;
	struct rt2661_tx_data *data;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	int err, off, rate;
	int mblen, pktlen;
	mblk_t *m, *m0;
	uint16_t dur;
	uint32_t flags = 0;

	mutex_enter(&sc->sc_txlock);
	ring = &sc->txq[0];
	err = DDI_SUCCESS;

	if (ring->queued > RT2661_TX_RING_COUNT - 8) {
		sc->sc_need_sched = 1;
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail1;
	}

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) {
		RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_send():"
		    "can't alloc mblk.\n");
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

	desc = &ring->desc[ring->cur];
	data = &ring->data[ring->cur];
	data->ni = ieee80211_ref_node(ni);

	/* pickup a rate */
	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		/* multicast frames are sent at the lowest avail. rate */
		rate = ni->in_rates.ir_rates[0];
	} else if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
		rate = ic->ic_sup_rates[ic->ic_curmode].
		    ir_rates[ic->ic_fixed_rate];
	} else
		rate = ni->in_rates.ir_rates[ni->in_txrate];
	if (rate == 0)
		rate = 2;	/* XXX should not happen */
	rate &= IEEE80211_RATE_VAL;

	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= RT2661_TX_NEED_ACK;

		dur = rt2661_txtime(RT2661_ACK_SIZE,
		    rt2661_ack_rate(ic, rate), ic->ic_flags) + sc->sifs;
		*(uint16_t *)wh->i_dur = LE_16(dur);
	}

	bcopy(m->b_rptr, data->buf, pktlen);
	rt2661_setup_tx_desc(sc, desc, flags, 0, pktlen, rate, 0);

	(void) ddi_dma_sync(data->txdata_dma.dma_hdl,
	    0, pktlen,
	    DDI_DMA_SYNC_FORDEV);

	(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
	    ring->cur * RT2661_TX_DESC_SIZE,
	    RT2661_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_send(): "
	    "sending data frame len=%u idx=%u rate=%u\n",
	    pktlen, ring->cur, rate);

	/* kick Tx */
	ring->queued++;
	ring->cur = (ring->cur + 1) % RT2661_TX_RING_COUNT;
	RT2661_WRITE(sc, RT2661_TX_CNTL_CSR, 1 << 0);

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;
fail3:
	ieee80211_free_node(ni);
fail2:
	freemsg(m);
fail1:
	if (err == DDI_SUCCESS)
		freemsg(mp);
	mutex_exit(&sc->sc_txlock);
	return (err);
}

/*ARGSUSED*/
static int
rt2661_mgmt_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)ic;
	struct rt2661_tx_ring *ring;
	struct rt2661_tx_desc *desc;
	struct rt2661_tx_data *data;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	int err, off, rate;
	int mblen, pktlen;
	mblk_t *m, *m0;
	uint16_t dur;
	uint32_t flags = 0;

	if ((!RT2661_IS_RUNNING(sc)) || RT2661_IS_SUSPEND(sc)) {
		err = ENXIO;
		goto fail1;
	}

	ring = &sc->mgtq;
	err = DDI_SUCCESS;

	if (ring->queued >= RT2661_MGT_RING_COUNT) {
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail1;
	}

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) {
		RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_mgmt_send():"
		    "can't alloc mblk.\n");
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

	desc = &ring->desc[ring->cur];
	data = &ring->data[ring->cur];
	data->ni = ieee80211_ref_node(ni);

	/* send mgt frames at the lowest available rate */
	rate = IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) ? 12 : 2;

	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= RT2661_TX_NEED_ACK;

		dur = rt2661_txtime(RT2661_ACK_SIZE,
		    rate, ic->ic_flags) + sc->sifs;
		*(uint16_t *)wh->i_dur = LE_16(dur);

		/* tell hardware to add timestamp in probe responses */
		if ((wh->i_fc[0] &
		    (IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_MASK)) ==
		    (IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP))
			flags |= RT2661_TX_TIMESTAMP;
	}

	bcopy(m->b_rptr, data->buf, pktlen);
	rt2661_setup_tx_desc(sc, desc, flags, 0, pktlen, rate, RT2661_QID_MGT);

	(void) ddi_dma_sync(data->txdata_dma.dma_hdl,
	    0, pktlen,
	    DDI_DMA_SYNC_FORDEV);

	(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
	    ring->cur * RT2661_TX_DESC_SIZE,
	    RT2661_TX_DESC_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_mgmt_send(): "
	    "sending mgmt frame len=%u idx=%u rate=%u\n",
	    pktlen, ring->cur, rate);

	/* kick Tx */
	ring->queued++;
	ring->cur = (ring->cur + 1) % RT2661_MGT_RING_COUNT;
	RT2661_WRITE(sc, RT2661_TX_CNTL_CSR, RT2661_KICK_MGT);

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

fail3:
	ieee80211_free_node(ni);
fail2:
	freemsg(m);
fail1:
	freemsg(mp);
	return (err);
}

static void
rt2661_amrr_node_init(const struct rt2661_amrr *amrr,
    struct rt2661_amrr_node *amn)
{
	amn->amn_success = 0;
	amn->amn_recovery = 0;
	amn->amn_txcnt = amn->amn_retrycnt = 0;
	amn->amn_success_threshold = amrr->amrr_min_success_threshold;
}

static void
rt2661_amrr_choose(struct rt2661_amrr *amrr, struct ieee80211_node *ni,
    struct rt2661_amrr_node *amn)
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
			RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_amrr_choose(): "
			    "increase rate = %d, #tx = %d, #retries = %d\n",
			    RV(ni->in_rates.ir_rates[ni->in_txrate]),
			    amn->amn_txcnt, amn->amn_retrycnt);
			need_change = 1;
		} else
			amn->amn_recovery = 0;
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
			RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_amrr_choose(): "
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
rt2661_update_promisc(struct rt2661_softc *sc)
{
	uint32_t tmp;

	tmp = RT2661_READ(sc, RT2661_TXRX_CSR0);

	tmp &= ~RT2661_DROP_NOT_TO_ME;
	if (!(sc->sc_rcr & RT2661_RCR_PROMISC))
		tmp |= RT2661_DROP_NOT_TO_ME;

	RT2661_WRITE(sc, RT2661_TXRX_CSR0, tmp);
	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_update_promisc(): "
	    "%s promiscuous mode\n",
	    (sc->sc_rcr & RT2661_RCR_PROMISC) ? "entering" : "leaving");
}

static void
rt2661_updateslot(struct ieee80211com *ic, int onoff)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)ic;
	uint8_t slottime;
	uint32_t tmp;

	slottime = (onoff ? 9 : 20);

	tmp = RT2661_READ(sc, RT2661_MAC_CSR9);
	tmp = (tmp & ~0xff) | slottime;
	RT2661_WRITE(sc, RT2661_MAC_CSR9, tmp);

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_updateslot(): "
	    "setting slot time to %uus\n", slottime);
}

static void
rt2661_set_slottime(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t slottime;
	uint32_t tmp;

	slottime = (ic->ic_flags & IEEE80211_F_SHSLOT) ? 9 : 20;

	tmp = RT2661_READ(sc, RT2661_MAC_CSR9);
	tmp = (tmp & ~0xff) | slottime;
	RT2661_WRITE(sc, RT2661_MAC_CSR9, tmp);

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_set_slottime(): "
	    "setting slot time to %uus\n", slottime);
}


/*
 * Enable multi-rate retries for frames sent at OFDM rates.
 * In 802.11b/g mode, allow fallback to CCK rates.
 */
static void
rt2661_enable_mrr(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	tmp = RT2661_READ(sc, RT2661_TXRX_CSR4);

	tmp &= ~RT2661_MRR_CCK_FALLBACK;
	if (!IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
		tmp |= RT2661_MRR_CCK_FALLBACK;
	tmp |= RT2661_MRR_ENABLED;

	RT2661_WRITE(sc, RT2661_TXRX_CSR4, tmp);
}

static void
rt2661_set_txpreamble(struct rt2661_softc *sc)
{
	uint32_t tmp;

	tmp = RT2661_READ(sc, RT2661_TXRX_CSR4);

	tmp &= ~RT2661_SHORT_PREAMBLE;
	if (sc->sc_ic.ic_flags & IEEE80211_F_SHPREAMBLE)
		tmp |= RT2661_SHORT_PREAMBLE;

	RT2661_WRITE(sc, RT2661_TXRX_CSR4, tmp);
}

static void
rt2661_set_basicrates(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	/* update basic rate set */
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		/* 11b basic rates: 1, 2Mbps */
		RT2661_WRITE(sc, RT2661_TXRX_CSR5, 0x3);
	} else if (ic->ic_curmode == IEEE80211_MODE_11A) {
		/* 11a basic rates: 6, 12, 24Mbps */
		RT2661_WRITE(sc, RT2661_TXRX_CSR5, 0x150);
	} else {
		/* 11b/g basic rates: 1, 2, 5.5, 11Mbps */
		RT2661_WRITE(sc, RT2661_TXRX_CSR5, 0xf);
	}
}

static void
rt2661_set_bssid(struct rt2661_softc *sc, const uint8_t *bssid)
{
	uint32_t tmp;

	tmp = bssid[0] | bssid[1] << 8 | bssid[2] << 16 | bssid[3] << 24;
	RT2661_WRITE(sc, RT2661_MAC_CSR4, tmp);

	tmp = bssid[4] | bssid[5] << 8 | RT2661_ONE_BSSID << 16;
	RT2661_WRITE(sc, RT2661_MAC_CSR5, tmp);
}

/*
 * Enable TSF synchronization and tell h/w to start sending beacons for IBSS
 * and HostAP operating modes.
 */
static void
rt2661_enable_tsf_sync(struct rt2661_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	tmp = RT2661_READ(sc, RT2661_TXRX_CSR9) & 0xff000000;

	/* set beacon interval (in 1/16ms unit) */
	tmp |= ic->ic_bss->in_intval * 16;

	tmp |= RT2661_TSF_TICKING | RT2661_ENABLE_TBTT;
	if (ic->ic_opmode == IEEE80211_M_STA)
		tmp |= RT2661_TSF_MODE(1);

	RT2661_WRITE(sc, RT2661_TXRX_CSR9, tmp);
}


static void
rt2661_next_scan(void *arg)
{
	struct rt2661_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		(void) ieee80211_next_scan(ic);
}

static void
rt2661_newassoc(struct ieee80211com *ic, struct ieee80211_node *ni)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)ic;
	int i;

	rt2661_amrr_node_init(&sc->amrr, &((struct rt2661_node *)ni)->amn);

	/* set rate to some reasonable initial value */
	i = ni->in_rates.ir_nrates - 1;
	while (i > 0 && ((ni->in_rates.ir_rates[i] & IEEE80211_RATE_VAL) > 72))
		i--;

	ni->in_txrate = i;
}

static void
rt2661_iter_func(void *arg, struct ieee80211_node *ni)
{
	struct rt2661_softc *sc = arg;
	struct rt2661_node *rn = (struct rt2661_node *)ni;

	rt2661_amrr_choose(&sc->amrr, ni, &rn->amn);

}

/*
 * Dynamically tune Rx sensitivity (BBP register 17) based on average RSSI and
 * false CCA count.  This function is called periodically (every seconds) when
 * in the RUN state.  Values taken from the reference driver.
 */
static void
rt2661_rx_tune(struct rt2661_softc *sc)
{
	uint8_t	bbp17;
	uint16_t cca;
	int lo, hi, dbm;

	/*
	 * Tuning range depends on operating band and on the presence of an
	 * external low-noise amplifier.
	 */
	lo = 0x20;
	if (IEEE80211_IS_CHAN_5GHZ(sc->sc_curchan))
		lo += 0x08;
	if ((IEEE80211_IS_CHAN_2GHZ(sc->sc_curchan) && sc->ext_2ghz_lna) ||
	    (IEEE80211_IS_CHAN_5GHZ(sc->sc_curchan) && sc->ext_5ghz_lna))
		lo += 0x10;
	hi = lo + 0x20;

	dbm = sc->avg_rssi;
	/* retrieve false CCA count since last call (clear on read) */
	cca = RT2661_READ(sc, RT2661_STA_CSR1) & 0xffff;

	RWD_DEBUG(RT2661_DBG_INTR, "rwd: rt2661_rx_tune(): "
	    "RSSI=%ddBm false CCA=%d\n", dbm, cca);

	if (dbm < -74) {
		/* very bad RSSI, tune using false CCA count */
		bbp17 = sc->bbp17; /* current value */

		hi -= 2 * (-74 - dbm);
		if (hi < lo)
			hi = lo;

		if (bbp17 > hi)
			bbp17 = (uint8_t)hi;
		else if (cca > 512)
			bbp17 = (uint8_t)min(bbp17 + 1, hi);
		else if (cca < 100)
			bbp17 = (uint8_t)max(bbp17 - 1, lo);

	} else if (dbm < -66) {
		bbp17 = lo + 0x08;
	} else if (dbm < -58) {
		bbp17 = lo + 0x10;
	} else if (dbm < -35) {
		bbp17 = (uint8_t)hi;
	} else {	/* very good RSSI >= -35dBm */
		bbp17 = 0x60;	/* very low sensitivity */
	}

	if (bbp17 != sc->bbp17) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_rx_tune(): "
		    "BBP17 %x->%x\n", sc->bbp17, bbp17);
		rt2661_bbp_write(sc, 17, bbp17);
		sc->bbp17 = bbp17;
	}
}

/*
 * This function is called periodically (every 500ms) in RUN state to update
 * various settings like rate control statistics or Rx sensitivity.
 */
static void
rt2661_updatestats(void *arg)
{
	struct rt2661_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_opmode == IEEE80211_M_STA)
		rt2661_iter_func(sc, ic->ic_bss);
	else
		ieee80211_iterate_nodes(&ic->ic_sta, rt2661_iter_func, arg);

	/* update rx sensitivity every 1 sec */
	if (++sc->ncalls & 1)
		rt2661_rx_tune(sc);

	sc->sc_rssadapt_id = timeout(rt2661_updatestats, (void *)sc,
	    drv_usectohz(200 * 1000));
}

static int
rt2661_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)ic;
	enum ieee80211_state ostate;
	struct ieee80211_node *ni;
	uint32_t tmp;
	int err;

	RT2661_GLOCK(sc);

	ostate = ic->ic_state;
	sc->sc_ostate = ostate;

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt26661_newstate(): "
	    "%x -> %x\n", ostate, nstate);

	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}

	if (sc->sc_rssadapt_id) {
		(void) untimeout(sc->sc_rssadapt_id);
		sc->sc_rssadapt_id = 0;
	}

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_RUN) {
			/* abort TSF synchronization */
			tmp = RT2661_READ(sc, RT2661_TXRX_CSR9);
			RT2661_WRITE(sc, RT2661_TXRX_CSR9, tmp & ~0x00ffffff);
		}
		break;
	case IEEE80211_S_SCAN:
		rt2661_set_chan(sc, ic->ic_curchan);
		sc->sc_scan_id = timeout(rt2661_next_scan, (void *)sc,
		    drv_usectohz(200000));
		break;
	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC:
		rt2661_set_chan(sc, ic->ic_curchan);
		break;
	case IEEE80211_S_RUN:
		rt2661_set_chan(sc, ic->ic_curchan);

		ni = ic->ic_bss;
		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			rt2661_set_slottime(sc);
			rt2661_enable_mrr(sc);
			rt2661_set_txpreamble(sc);
			rt2661_set_basicrates(sc);
			rt2661_set_bssid(sc, ni->in_bssid);
		}

		if (ic->ic_opmode == IEEE80211_M_STA) {
			/* fake a join to init the tx rate */
			rt2661_newassoc(ic, ni);
		}

		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			sc->ncalls = 0;
			sc->avg_rssi = -95;	/* reset EMA */
			sc->sc_rssadapt_id = timeout(rt2661_updatestats,
			    (void *)sc, drv_usectohz(200 * 1000));
			rt2661_enable_tsf_sync(sc);
		}
		break;
	default:
		break;
	}

	RT2661_GUNLOCK(sc);

	err = sc->sc_newstate(ic, nstate, arg);
	return (err);
}

/*ARGSUSED*/
static struct ieee80211_node *
rt2661_node_alloc(ieee80211com_t *ic)
{
	struct rt2661_node *rn;

	rn = kmem_zalloc(sizeof (struct rt2661_node), KM_SLEEP);
	return ((rn != NULL) ? &rn->ni : NULL);
}

static void
rt2661_node_free(struct ieee80211_node *in)
{
	struct ieee80211com *ic = in->in_ic;

	ic->ic_node_cleanup(in);
	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);
	kmem_free(in, sizeof (struct rt2661_node));
}

static void
rt2661_stop_locked(struct rt2661_softc *sc)
{
	uint32_t tmp;

	if (RT2661_IS_RUNNING(sc)) {
		sc->sc_tx_timer = 0;

		/* abort Tx (for all 5 Tx rings) */
		RT2661_WRITE(sc, RT2661_TX_CNTL_CSR, 0x1f << 16);

		/* disable Rx (value remains after reset!) */
		tmp = RT2661_READ(sc, RT2661_TXRX_CSR0);
		RT2661_WRITE(sc, RT2661_TXRX_CSR0, tmp | RT2661_DISABLE_RX);

		/* reset ASIC */
		RT2661_WRITE(sc, RT2661_MAC_CSR1, 3);
		RT2661_WRITE(sc, RT2661_MAC_CSR1, 0);

		/* disable interrupts */
		RT2661_WRITE(sc, RT2661_INT_MASK_CSR, 0xffffff7f);
		RT2661_WRITE(sc, RT2661_MCU_INT_MASK_CSR, 0xffffffff);

		/* clear any pending interrupt */
		RT2661_WRITE(sc, RT2661_INT_SOURCE_CSR, 0xffffffff);
		RT2661_WRITE(sc, RT2661_MCU_INT_SOURCE_CSR, 0xffffffff);

		/* reset Tx and Rx rings */
		rt2661_reset_tx_ring(sc, &sc->txq[0]);
		rt2661_reset_tx_ring(sc, &sc->txq[1]);
		rt2661_reset_tx_ring(sc, &sc->txq[2]);
		rt2661_reset_tx_ring(sc, &sc->txq[3]);
		rt2661_reset_tx_ring(sc, &sc->mgtq);
		rt2661_reset_rx_ring(sc, &sc->rxq);
	}
}

static void
rt2661_set_macaddr(struct rt2661_softc *sc, const uint8_t *addr)
{
	uint32_t tmp;

	tmp = addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24;
	RT2661_WRITE(sc, RT2661_MAC_CSR2, tmp);

	tmp = addr[4] | addr[5] << 8 | 0xff << 16;
	RT2661_WRITE(sc, RT2661_MAC_CSR3, tmp);
}

static uint8_t
rt2661_bbp_read(struct rt2661_softc *sc, uint8_t reg)
{
	uint32_t val;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2661_READ(sc, RT2661_PHY_CSR3) & RT2661_BBP_BUSY))
			break;
		DELAY(1);
	}
	if (ntries == 100) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_bbp_read(): "
		    "could not read from BBP\n");
		return (0);
	}

	val = RT2661_BBP_BUSY | RT2661_BBP_READ | reg << 8;
	RT2661_WRITE(sc, RT2661_PHY_CSR3, val);

	for (ntries = 0; ntries < 100; ntries++) {
		val = RT2661_READ(sc, RT2661_PHY_CSR3);
		if (!(val & RT2661_BBP_BUSY))
			return (val & 0xff);
		DELAY(1);
	}

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_bbp_read(): "
	    "could not read from BBP\n");
	return (0);
}

static int
rt2661_bbp_init(struct rt2661_softc *sc)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))

	int i, ntries;
	uint8_t	val;

	/* wait for BBP to be ready */
	for (ntries = 0; ntries < 100; ntries++) {
		val = rt2661_bbp_read(sc, 0);
		if (val != 0 && val != 0xff)
			break;
		DELAY(100);
	}
	if (ntries == 100) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_bbp_init(): "
		    "timeout waiting for BBP\n");
		return (RT2661_FAILURE);
	}

	/* initialize BBP registers to default values */
	for (i = 0; i < N(rt2661_def_bbp); i++) {
		rt2661_bbp_write(sc, rt2661_def_bbp[i].reg,
		    rt2661_def_bbp[i].val);
	}

	/* write vendor-specific BBP values (from EEPROM) */
	for (i = 0; i < 16; i++) {
		if (sc->bbp_prom[i].reg == 0)
			continue;
		rt2661_bbp_write(sc, sc->bbp_prom[i].reg, sc->bbp_prom[i].val);
	}

	return (RT2661_SUCCESS);
#undef N
}

static void
rt2661_bbp_write(struct rt2661_softc *sc, uint8_t reg, uint8_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2661_READ(sc, RT2661_PHY_CSR3) & RT2661_BBP_BUSY))
			break;
		DELAY(1);
	}
	if (ntries == 100) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_bbp_write(): "
		    "could not write to BBP\n");
		return;
	}

	tmp = RT2661_BBP_BUSY | (reg & 0x7f) << 8 | val;
	RT2661_WRITE(sc, RT2661_PHY_CSR3, tmp);

	RWD_DEBUG(RT2661_DBG_HW, "rwd: rt2661_bbp_write(): "
	    "BBP R%u <- 0x%02x\n", reg, val);
}

/*
 * Reprogram MAC/BBP to switch to a new band.  Values taken from the reference
 * driver.
 */
static void
rt2661_select_band(struct rt2661_softc *sc, struct ieee80211_channel *c)
{
	uint8_t bbp17, bbp35, bbp96, bbp97, bbp98, bbp104;
	uint32_t tmp;

	/* update all BBP registers that depend on the band */
	bbp17 = 0x20; bbp96 = 0x48; bbp104 = 0x2c;
	bbp35 = 0x50; bbp97 = 0x48; bbp98  = 0x48;
	if (IEEE80211_IS_CHAN_5GHZ(c)) {
		bbp17 += 0x08; bbp96 += 0x10; bbp104 += 0x0c;
		bbp35 += 0x10; bbp97 += 0x10; bbp98  += 0x10;
	}
	if ((IEEE80211_IS_CHAN_2GHZ(c) && sc->ext_2ghz_lna) ||
	    (IEEE80211_IS_CHAN_5GHZ(c) && sc->ext_5ghz_lna)) {
		bbp17 += 0x10; bbp96 += 0x10; bbp104 += 0x10;
	}

	sc->bbp17 = bbp17;
	rt2661_bbp_write(sc,  17, bbp17);
	rt2661_bbp_write(sc,  96, bbp96);
	rt2661_bbp_write(sc, 104, bbp104);

	if ((IEEE80211_IS_CHAN_2GHZ(c) && sc->ext_2ghz_lna) ||
	    (IEEE80211_IS_CHAN_5GHZ(c) && sc->ext_5ghz_lna)) {
		rt2661_bbp_write(sc, 75, 0x80);
		rt2661_bbp_write(sc, 86, 0x80);
		rt2661_bbp_write(sc, 88, 0x80);
	}

	rt2661_bbp_write(sc, 35, bbp35);
	rt2661_bbp_write(sc, 97, bbp97);
	rt2661_bbp_write(sc, 98, bbp98);

	tmp = RT2661_READ(sc, RT2661_PHY_CSR0);
	tmp &= ~(RT2661_PA_PE_2GHZ | RT2661_PA_PE_5GHZ);
	if (IEEE80211_IS_CHAN_2GHZ(c))
		tmp |= RT2661_PA_PE_2GHZ;
	else
		tmp |= RT2661_PA_PE_5GHZ;
	RT2661_WRITE(sc, RT2661_PHY_CSR0, tmp);

	/* 802.11a uses a 16 microseconds short interframe space */
	sc->sifs = IEEE80211_IS_CHAN_5GHZ(c) ? 16 : 10;
}

static void
rt2661_select_antenna(struct rt2661_softc *sc)
{
	uint8_t bbp4, bbp77;
	uint32_t tmp;

	bbp4  = rt2661_bbp_read(sc,  4);
	bbp77 = rt2661_bbp_read(sc, 77);

	/* TBD */

	/* make sure Rx is disabled before switching antenna */
	tmp = RT2661_READ(sc, RT2661_TXRX_CSR0);
	RT2661_WRITE(sc, RT2661_TXRX_CSR0, tmp | RT2661_DISABLE_RX);

	rt2661_bbp_write(sc,  4, bbp4);
	rt2661_bbp_write(sc, 77, bbp77);

	/* restore Rx filter */
	RT2661_WRITE(sc, RT2661_TXRX_CSR0, tmp);
}

static void
rt2661_rf_write(struct rt2661_softc *sc, uint8_t reg, uint32_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 100; ntries++) {
		if (!(RT2661_READ(sc, RT2661_PHY_CSR4) & RT2661_RF_BUSY))
			break;
		DELAY(1);
	}
	if (ntries == 100) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_rf_write(): "
		    "could not write to RF\n");
		return;
	}

	tmp = RT2661_RF_BUSY | RT2661_RF_21BIT | (val & 0x1fffff) << 2 |
	    (reg & 3);
	RT2661_WRITE(sc, RT2661_PHY_CSR4, tmp);

	/* remember last written value in sc */
	sc->rf_regs[reg] = val;

	RWD_DEBUG(RT2661_DBG_FW, "rwd: rt2661_rf_write(): "
	    "RF R[%u] <- 0x%05x\n", reg & 3, val & 0x1fffff);
}

static void
rt2661_set_chan(struct rt2661_softc *sc, struct ieee80211_channel *c)
{
	struct ieee80211com *ic = &sc->sc_ic;
	const struct rfprog *rfprog;
	uint8_t bbp3, bbp94 = RT2661_BBPR94_DEFAULT;
	int8_t power;
	uint_t i, chan;

	chan = ieee80211_chan2ieee(ic, c);
	if (chan == 0 || chan == IEEE80211_CHAN_ANY)
		return;

	/* select the appropriate RF settings based on what EEPROM says */
	rfprog = (sc->rfprog == 0) ? rt2661_rf5225_1 : rt2661_rf5225_2;

	/* find the settings for this channel (we know it exists) */
	i = 0;
	while (rfprog[i].chan != chan)
		i++;

	power = sc->txpow[i];
	if (power < 0) {
		bbp94 += power;
		power = 0;
	} else if (power > 31) {
		bbp94 += power - 31;
		power = 31;
	}

	/*
	 * If we are switching from the 2GHz band to the 5GHz band or
	 * vice-versa, BBP registers need to be reprogrammed.
	 */
	if (ic->ic_flags != sc->sc_curchan->ich_flags) {
		rt2661_select_band(sc, c);
		rt2661_select_antenna(sc);
	}
	sc->sc_curchan = c;

	rt2661_rf_write(sc, RT2661_RF1, rfprog[i].r1);
	rt2661_rf_write(sc, RT2661_RF2, rfprog[i].r2);
	rt2661_rf_write(sc, RT2661_RF3, rfprog[i].r3 | power << 7);
	rt2661_rf_write(sc, RT2661_RF4, rfprog[i].r4 | sc->rffreq << 10);

	DELAY(200);

	rt2661_rf_write(sc, RT2661_RF1, rfprog[i].r1);
	rt2661_rf_write(sc, RT2661_RF2, rfprog[i].r2);
	rt2661_rf_write(sc, RT2661_RF3, rfprog[i].r3 | power << 7 | 1);
	rt2661_rf_write(sc, RT2661_RF4, rfprog[i].r4 | sc->rffreq << 10);

	DELAY(200);

	rt2661_rf_write(sc, RT2661_RF1, rfprog[i].r1);
	rt2661_rf_write(sc, RT2661_RF2, rfprog[i].r2);
	rt2661_rf_write(sc, RT2661_RF3, rfprog[i].r3 | power << 7);
	rt2661_rf_write(sc, RT2661_RF4, rfprog[i].r4 | sc->rffreq << 10);

	/* enable smart mode for MIMO-capable RFs */
	bbp3 = rt2661_bbp_read(sc, 3);

	bbp3 &= ~RT2661_SMART_MODE;
	if (sc->rf_rev == RT2661_RF_5325 || sc->rf_rev == RT2661_RF_2529)
		bbp3 |= RT2661_SMART_MODE;

	rt2661_bbp_write(sc, 3, bbp3);

	if (bbp94 != RT2661_BBPR94_DEFAULT)
		rt2661_bbp_write(sc, 94, bbp94);

	/* 5GHz radio needs a 1ms delay here */
	if (IEEE80211_IS_CHAN_5GHZ(c))
		DELAY(1000);
}

static int
rt2661_init(struct rt2661_softc *sc)
{
#define	N(a)	(sizeof (a) / sizeof ((a)[0]))

	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp, sta[3], *fptr;
	int i, err, off, ntries;

	RT2661_GLOCK(sc);

	rt2661_stop_locked(sc);

	if (!RT2661_IS_FWLOADED(sc)) {
		err = rt2661_load_microcode(sc, ucode, usize);
		if (err != RT2661_SUCCESS) {
			RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
			    "could not load 8051 microcode\n");
			return (DDI_FAILURE);
		}
		sc->sc_flags |= RT2661_F_FWLOADED;
	}

	/* initialize Tx rings */
	RT2661_WRITE(sc, RT2661_AC1_BASE_CSR, sc->txq[1].paddr);
	RT2661_WRITE(sc, RT2661_AC0_BASE_CSR, sc->txq[0].paddr);
	RT2661_WRITE(sc, RT2661_AC2_BASE_CSR, sc->txq[2].paddr);
	RT2661_WRITE(sc, RT2661_AC3_BASE_CSR, sc->txq[3].paddr);

	/* initialize Mgt ring */
	RT2661_WRITE(sc, RT2661_MGT_BASE_CSR, sc->mgtq.paddr);

	/* initialize Rx ring */
	RT2661_WRITE(sc, RT2661_RX_BASE_CSR, sc->rxq.paddr);

	/* initialize Tx rings sizes */
	RT2661_WRITE(sc, RT2661_TX_RING_CSR0,
	    RT2661_TX_RING_COUNT << 24 |
	    RT2661_TX_RING_COUNT << 16 |
	    RT2661_TX_RING_COUNT <<  8 |
	    RT2661_TX_RING_COUNT);

	RT2661_WRITE(sc, RT2661_TX_RING_CSR1,
	    RT2661_TX_DESC_WSIZE << 16 |
	    RT2661_TX_RING_COUNT <<  8 |
	    RT2661_MGT_RING_COUNT);

	/* initialize Rx rings */
	RT2661_WRITE(sc, RT2661_RX_RING_CSR,
	    RT2661_RX_DESC_BACK  << 16 |
	    RT2661_RX_DESC_WSIZE <<  8 |
	    RT2661_RX_RING_COUNT);

	/* XXX: some magic here */
	RT2661_WRITE(sc, RT2661_TX_DMA_DST_CSR, 0xaa);

	/* load base addresses of all 5 Tx rings (4 data + 1 mgt) */
	RT2661_WRITE(sc, RT2661_LOAD_TX_RING_CSR, 0x1f);

	/* load base address of Rx ring */
	RT2661_WRITE(sc, RT2661_RX_CNTL_CSR, 2);

	/* initialize MAC registers to default values */
	for (i = 0; i < N(rt2661_def_mac); i++)
		RT2661_WRITE(sc, rt2661_def_mac[i].reg, rt2661_def_mac[i].val);

	rt2661_set_macaddr(sc, ic->ic_macaddr);

	/* set host ready */
	RT2661_WRITE(sc, RT2661_MAC_CSR1, 3);
	RT2661_WRITE(sc, RT2661_MAC_CSR1, 0);

	/* wait for BBP/RF to wakeup */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (RT2661_READ(sc, RT2661_MAC_CSR12) & 8)
			break;
		DELAY(1000);
	}
	if (ntries == 1000) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "timeout waiting for BBP/RF to wakeup\n");
		rt2661_stop_locked(sc);
		RT2661_GUNLOCK(sc);
		return (DDI_FAILURE);
	}

	if (rt2661_bbp_init(sc) != RT2661_SUCCESS) {
		rt2661_stop_locked(sc);
		RT2661_GUNLOCK(sc);
		return (DDI_FAILURE);
	}

	/* select default channel */
	sc->sc_curchan = ic->ic_bss->in_chan = ic->ic_curchan;
	rt2661_select_band(sc, sc->sc_curchan);
	rt2661_select_antenna(sc);
	rt2661_set_chan(sc, sc->sc_curchan);

	/* update Rx filter */
	tmp = RT2661_READ(sc, RT2661_TXRX_CSR0) & 0xffff;

	tmp |= RT2661_DROP_PHY_ERROR | RT2661_DROP_CRC_ERROR;
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		tmp |= RT2661_DROP_CTL | RT2661_DROP_VER_ERROR |
		    RT2661_DROP_ACKCTS;
		if (ic->ic_opmode != IEEE80211_M_HOSTAP)
			tmp |= RT2661_DROP_TODS;
		if (!(sc->sc_rcr & RT2661_RCR_PROMISC))
			tmp |= RT2661_DROP_NOT_TO_ME;
	}

	RT2661_WRITE(sc, RT2661_TXRX_CSR0, tmp);

	/* clear STA registers */
	off = RT2661_STA_CSR0;
	fptr = sta;
	for (i = 0; i < N(sta); i++) {
		*fptr = RT2661_MEM_READ1(sc, off++);
	}

	/* initialize ASIC */
	RT2661_WRITE(sc, RT2661_MAC_CSR1, 4);

	/* clear any pending interrupt */
	RT2661_WRITE(sc, RT2661_INT_SOURCE_CSR, 0xffffffff);

	/* enable interrupts */
	RT2661_WRITE(sc, RT2661_INT_MASK_CSR, 0x0000ff10);
	RT2661_WRITE(sc, RT2661_MCU_INT_MASK_CSR, 0);

	/* kick Rx */
	RT2661_WRITE(sc, RT2661_RX_CNTL_CSR, 1);
	RT2661_GUNLOCK(sc);

#undef N
	return (DDI_SUCCESS);
}

static void
rt2661_stop(struct rt2661_softc *sc)
{
	if (!RT2661_IS_FASTREBOOT(sc))
		RT2661_GLOCK(sc);
	rt2661_stop_locked(sc);
	if (!RT2661_IS_FASTREBOOT(sc))
		RT2661_GUNLOCK(sc);
}

static int
rt2661_m_start(void *arg)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = rt2661_init(sc);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_m_start():"
		    "Hardware initialization failed\n");
		goto fail1;
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	RT2661_GLOCK(sc);
	sc->sc_flags |= RT2661_F_RUNNING;
	RT2661_GUNLOCK(sc);

	return (DDI_SUCCESS);
fail1:
	rt2661_stop(sc);
	return (err);
}

static void
rt2661_m_stop(void *arg)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;

	(void) rt2661_stop(sc);

	ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);

	RT2661_GLOCK(sc);
	sc->sc_flags &= ~RT2661_F_RUNNING;
	RT2661_GUNLOCK(sc);
}

static void
rt2661_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	RT2661_GLOCK(sc);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (RT2661_IS_RUNNING(sc)) {
				RT2661_GUNLOCK(sc);
				(void) rt2661_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
				RT2661_GLOCK(sc);
			}
		}
	}
	RT2661_GUNLOCK(sc);
}

/*
 * Call back function for get/set proporty
 */
static int
rt2661_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;
	int err = 0;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
rt2661_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t mph)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, mph);
}

static int
rt2661_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;
	ieee80211com_t *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);
	RT2661_GLOCK(sc);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (RT2661_IS_RUNNING(sc)) {
				RT2661_GUNLOCK(sc);
				(void) rt2661_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
				RT2661_GLOCK(sc);
			}
		}
		err = 0;
	}
	RT2661_GUNLOCK(sc);
	return (err);
}

static mblk_t *
rt2661_m_tx(void *arg, mblk_t *mp)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	if (RT2661_IS_SUSPEND(sc)) {
		freemsgchain(mp);
		return (NULL);
	}

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		RWD_DEBUG(RT2661_DBG_TX, "rwd: rt2661_tx_data(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (rt2661_send(ic, mp) !=
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
rt2661_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
rt2661_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
rt2661_m_promisc(void *arg, boolean_t on)
{
	struct rt2661_softc *sc = (struct rt2661_softc *)arg;

	if (on) {
		sc->sc_rcr |= RT2661_RCR_PROMISC;
		sc->sc_rcr |= RT2661_RCR_MULTI;
	} else {
		sc->sc_rcr &= ~RT2661_RCR_PROMISC;
		sc->sc_rcr &= ~RT2661_RCR_MULTI;
	}

	rt2661_update_promisc(sc);
	return (0);
}

static int
rt2661_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct rt2661_softc *sc  = (struct rt2661_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct ieee80211_rateset *rs = &ni->in_rates;

	RT2661_GLOCK(sc);
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
		RT2661_GUNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		RT2661_GUNLOCK(sc);
		return (ENOTSUP);
	}
	RT2661_GUNLOCK(sc);

	return (0);
}

static int
rt2661_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct rt2661_softc *sc;
	struct ieee80211com *ic;

	int i, ac, err, ntries, instance;
	int intr_type, intr_count, intr_actual;
	char strbuf[32];
	uint8_t cachelsz;
	uint16_t command, vendor_id, device_id;
	uint32_t val;

	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(rt2661_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		RT2661_GLOCK(sc);
		sc->sc_flags &= ~RT2661_F_SUSPEND;
		RT2661_GUNLOCK(sc);
		if (RT2661_IS_RUNNING(sc))
			(void) rt2661_init(sc);
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "resume now\n");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);

	err = ddi_soft_state_zalloc(rt2661_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "unable to alloc soft_state_p\n");
		return (err);
	}

	sc = ddi_get_soft_state(rt2661_soft_state_p, instance);
	ic = (struct ieee80211com *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	/* PCI configuration */
	err = ddi_regs_map_setup(devinfo, 0, &sc->sc_cfg_base, 0, 0,
	    &rt2661_csr_accattr, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
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
	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
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
	    &sc->sc_io_base, 0, 0, &rt2661_csr_accattr, &sc->sc_io_handle);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "ddi_regs_map_setup() failed");
		goto fail2;
	}
	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
	    "PCI configuration is done successfully\n");

	err = ddi_intr_get_supported_types(devinfo, &intr_type);
	if ((err != DDI_SUCCESS) || (!(intr_type & DDI_INTR_TYPE_FIXED))) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "fixed type interrupt is not supported\n");
		goto fail3;
	}

	err = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_FIXED, &intr_count);
	if ((err != DDI_SUCCESS) || (intr_count != 1)) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "no fixed interrupts\n");
		goto fail3;
	}

	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);

	err = ddi_intr_alloc(devinfo, sc->sc_intr_htable,
	    DDI_INTR_TYPE_FIXED, 0, intr_count, &intr_actual, 0);
	if ((err != DDI_SUCCESS) || (intr_actual != 1)) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "ddi_intr_alloc() failed 0x%x\n", err);
		goto faili4;
	}

	err = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_pri);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "ddi_intr_get_pri() failed 0x%x\n", err);
		goto faili5;
	}

	sc->amrr.amrr_min_success_threshold =  1;
	sc->amrr.amrr_max_success_threshold = 15;

	/* wait for NIC to initialize */
	for (ntries = 0; ntries < 1000; ntries++) {
		if ((val = RT2661_READ(sc, RT2661_MAC_CSR0)) != 0)
			break;
		DELAY(1000);
	}
	if (ntries == 1000) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "timeout waiting for NIC to initialize\n");
		goto faili5;
	}

	/* retrieve RF rev. no and various other things from EEPROM */
	rt2661_read_eeprom(sc);

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
	    "MAC/BBP RT%X, RF %s\n"
	    "MAC address is: %x:%x:%x:%x:%x:%x\n", val,
	    rt2661_get_rf(sc->rf_rev),
	    ic->ic_macaddr[0], ic->ic_macaddr[1], ic->ic_macaddr[2],
	    ic->ic_macaddr[3], ic->ic_macaddr[4], ic->ic_macaddr[5]);

	/*
	 * Load 8051 microcode into NIC.
	 */
	switch (device_id) {
	case 0x0301:
		ucode = rt2561s_ucode;
		usize = sizeof (rt2561s_ucode);
		break;
	case 0x0302:
		ucode = rt2561_ucode;
		usize = sizeof (rt2561_ucode);
		break;
	case 0x0401:
		ucode = rt2661_ucode;
		usize = sizeof (rt2661_ucode);
		break;
	}

	err = rt2661_load_microcode(sc, ucode, usize);
	if (err != RT2661_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "could not load 8051 microcode\n");
		goto faili5;
	}

	sc->sc_flags = 0;
	sc->sc_flags |= RT2661_F_FWLOADED;

	/*
	 * Allocate Tx and Rx rings.
	 */
	for (ac = 0; ac < 4; ac++) {
		err = rt2661_alloc_tx_ring(sc, &sc->txq[ac],
		    RT2661_TX_RING_COUNT);
		if (err != RT2661_SUCCESS) {
			RWD_DEBUG(RT2661_DBG_DMA, "rwd: rt2661_attach(): "
			    "could not allocate Tx ring %d\n", ac);
			goto fail4;
		}
	}

	err = rt2661_alloc_tx_ring(sc, &sc->mgtq, RT2661_MGT_RING_COUNT);
	if (err != RT2661_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_DMA, "rwd: rt2661_attach(): "
		    "could not allocate Mgt ring\n");
		goto fail5;
	}

	err = rt2661_alloc_rx_ring(sc, &sc->rxq, RT2661_RX_RING_COUNT);
	if (err != RT2661_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_DMA, "rwd: rt2661_attach(): "
		    "could not allocate Rx ring\n");
		goto fail6;
	}

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxlock, NULL, MUTEX_DRIVER, NULL);

	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_state = IEEE80211_S_INIT;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |
	    IEEE80211_C_SHPREAMBLE |
	    IEEE80211_C_SHSLOT;

	/* WPA/WPA2 support */
	ic->ic_caps |= IEEE80211_C_WPA;

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = rt2661_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = rt2661_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	ic->ic_maxrssi = 63;
	ic->ic_xmit = rt2661_mgmt_send;

	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	ic->ic_node_alloc = rt2661_node_alloc;
	ic->ic_node_free = rt2661_node_free;
	ic->ic_set_shortslot = rt2661_updateslot;

	/* override state transition machine */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = rt2661_newstate;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	err = ddi_intr_add_softint(devinfo, &sc->sc_softintr_hdl,
	    DDI_INTR_SOFTPRI_MAX, rt2661_softintr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "ddi_add_softintr() failed");
		goto fail7;
	}

	err = ddi_intr_add_handler(sc->sc_intr_htable[0], rt2661_intr,
	    (caddr_t)sc, NULL);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "ddi_intr_addr_handle() failed\n");
		goto fail8;
	}

	err = ddi_intr_enable(sc->sc_intr_htable[0]);
	if (err != DDI_SUCCESS) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd; rt2661_attach(): "
		    "ddi_intr_enable() failed\n");
		goto fail9;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "MAC version mismatch\n");
		goto fail10;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &rt2661_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
		    "mac_register err %x\n", err);
		goto fail10;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "rwd", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_attach(): "
	    "attach successfully\n");
	return (DDI_SUCCESS);

fail10:
	(void) ddi_intr_disable(sc->sc_intr_htable[0]);
fail9:
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
fail8:
	(void) ddi_intr_remove_softint(sc->sc_softintr_hdl);
	sc->sc_softintr_hdl = NULL;
fail7:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_txlock);
	mutex_destroy(&sc->sc_rxlock);
fail6:
	rt2661_free_rx_ring(sc, &sc->rxq);
fail5:
	rt2661_free_tx_ring(sc, &sc->mgtq);
fail4:
	while (--ac >= 0)
		rt2661_free_tx_ring(sc, &sc->txq[ac]);
faili5:
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
faili4:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));
fail3:
	ddi_regs_map_free(&sc->sc_io_handle);
fail2:
	ddi_regs_map_free(&sc->sc_cfg_handle);
fail1:
	return (DDI_FAILURE);
}

static int
rt2661_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{

	struct rt2661_softc *sc;

	sc = ddi_get_soft_state(rt2661_soft_state_p, ddi_get_instance(devinfo));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (RT2661_IS_RUNNING(sc))
			rt2661_stop(sc);
		RT2661_GLOCK(sc);
		sc->sc_flags |= RT2661_F_SUSPEND;
		sc->sc_flags &= ~RT2661_F_FWLOADED;
		RT2661_GUNLOCK(sc);
		RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_detach(): "
		    "suspend now\n");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	(void) ddi_intr_remove_softint(sc->sc_softintr_hdl);
	sc->sc_softintr_hdl = NULL;
	(void) ddi_intr_disable(sc->sc_intr_htable[0]);
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);

	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_txlock);
	mutex_destroy(&sc->sc_rxlock);

	rt2661_free_tx_ring(sc, &sc->txq[0]);
	rt2661_free_tx_ring(sc, &sc->txq[1]);
	rt2661_free_tx_ring(sc, &sc->txq[2]);
	rt2661_free_tx_ring(sc, &sc->txq[3]);
	rt2661_free_tx_ring(sc, &sc->mgtq);
	rt2661_free_rx_ring(sc, &sc->rxq);

	ddi_regs_map_free(&sc->sc_io_handle);
	ddi_regs_map_free(&sc->sc_cfg_handle);

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(rt2661_soft_state_p, ddi_get_instance(devinfo));

	RWD_DEBUG(RT2661_DBG_MSG, "rwd: rt2661_detach(): "
	    "detach successfully\n");
	return (DDI_SUCCESS);
}

static int
rt2661_quiesce(dev_info_t *dip)
{
	struct rt2661_softc *sc;

	sc = ddi_get_soft_state(rt2661_soft_state_p, ddi_get_instance(dip));
	if (sc == NULL)
		return (DDI_FAILURE);

#ifdef DEBUG
	rt2661_dbg_flags = 0;
#endif

	/*
	 * No more blocking is allowed while we are in quiesce(9E) entry point
	 */
	sc->sc_flags |= RT2661_F_QUIESCE;

	/*
	 * Disable all interrupts
	 */
	rt2661_stop(sc);
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

	status = ddi_soft_state_init(&rt2661_soft_state_p,
	    sizeof (struct rt2661_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&rwd_dev_ops, "rwd");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&rwd_dev_ops);
		ddi_soft_state_fini(&rt2661_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&rwd_dev_ops);
		ddi_soft_state_fini(&rt2661_soft_state_p);
	}
	return (status);
}
