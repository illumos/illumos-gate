/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
 * Driver for Intel PRO/Wireless 3945ABG 802.11 network adapters.
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

#include "wpireg.h"
#include "wpivar.h"
#include <inet/wifi_ioctl.h>

#ifdef DEBUG
#define	WPI_DEBUG_80211		(1 << 0)
#define	WPI_DEBUG_CMD		(1 << 1)
#define	WPI_DEBUG_DMA		(1 << 2)
#define	WPI_DEBUG_EEPROM	(1 << 3)
#define	WPI_DEBUG_FW		(1 << 4)
#define	WPI_DEBUG_HW		(1 << 5)
#define	WPI_DEBUG_INTR		(1 << 6)
#define	WPI_DEBUG_MRR		(1 << 7)
#define	WPI_DEBUG_PIO		(1 << 8)
#define	WPI_DEBUG_RX		(1 << 9)
#define	WPI_DEBUG_SCAN		(1 << 10)
#define	WPI_DEBUG_TX		(1 << 11)
#define	WPI_DEBUG_RATECTL	(1 << 12)
#define	WPI_DEBUG_RADIO		(1 << 13)
#define	WPI_DEBUG_RESUME	(1 << 14)
uint32_t wpi_dbg_flags = 0;
#define	WPI_DBG(x) \
	wpi_dbg x
#else
#define	WPI_DBG(x)
#endif

static void	*wpi_soft_state_p = NULL;
static uint8_t wpi_fw_bin [] = {
#include "fw-wpi/ipw3945.ucode.hex"
};

/* DMA attributes for a shared page */
static ddi_dma_attr_t sh_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0xffffffffU,	/* maximum DMAable byte count */
	0x1000,		/* alignment in bytes */
	0x1000,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};

/* DMA attributes for a ring descriptor */
static ddi_dma_attr_t ring_desc_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0xffffffffU,	/* maximum DMAable byte count */
	0x4000,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};


/* DMA attributes for a tx cmd */
static ddi_dma_attr_t tx_cmd_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0xffffffffU,	/* maximum DMAable byte count */
	4,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};

/* DMA attributes for a rx buffer */
static ddi_dma_attr_t rx_buffer_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0xffffffffU,	/* maximum DMAable byte count */
	1,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};

/*
 * DMA attributes for a tx buffer.
 * the maximum number of segments is 4 for the hardware.
 * now all the wifi drivers put the whole frame in a single
 * descriptor, so we define the maximum  number of segments 4,
 * just the same as the rx_buffer. we consider leverage the HW
 * ability in the future, that is why we don't define rx and tx
 * buffer_dma_attr as the same.
 */
static ddi_dma_attr_t tx_buffer_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0xffffffffU,	/* maximum DMAable byte count */
	1,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};

/* DMA attributes for a load firmware */
static ddi_dma_attr_t fw_buffer_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0x7fffffff,	/* maximum DMAable byte count */
	4,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	4,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};

/* regs access attributes */
static ddi_device_acc_attr_t wpi_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/* DMA access attributes */
static ddi_device_acc_attr_t wpi_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static int	wpi_ring_init(wpi_sc_t *);
static void	wpi_ring_free(wpi_sc_t *);
static int	wpi_alloc_shared(wpi_sc_t *);
static void	wpi_free_shared(wpi_sc_t *);
static int	wpi_alloc_fw_dma(wpi_sc_t *);
static void	wpi_free_fw_dma(wpi_sc_t *);
static int	wpi_alloc_rx_ring(wpi_sc_t *);
static void	wpi_reset_rx_ring(wpi_sc_t *);
static void	wpi_free_rx_ring(wpi_sc_t *);
static int	wpi_alloc_tx_ring(wpi_sc_t *, wpi_tx_ring_t *, int, int);
static void	wpi_reset_tx_ring(wpi_sc_t *, wpi_tx_ring_t *);
static void	wpi_free_tx_ring(wpi_sc_t *, wpi_tx_ring_t *);

static ieee80211_node_t *wpi_node_alloc(ieee80211com_t *);
static void	wpi_node_free(ieee80211_node_t *);
static int	wpi_newstate(ieee80211com_t *, enum ieee80211_state, int);
static int	wpi_key_set(ieee80211com_t *, const struct ieee80211_key *,
    const uint8_t mac[IEEE80211_ADDR_LEN]);
static void	wpi_mem_lock(wpi_sc_t *);
static void	wpi_mem_unlock(wpi_sc_t *);
static uint32_t	wpi_mem_read(wpi_sc_t *, uint16_t);
static void	wpi_mem_write(wpi_sc_t *, uint16_t, uint32_t);
static void	wpi_mem_write_region_4(wpi_sc_t *, uint16_t,
		    const uint32_t *, int);
static uint16_t	wpi_read_prom_word(wpi_sc_t *, uint32_t);
static int	wpi_load_microcode(wpi_sc_t *);
static int	wpi_load_firmware(wpi_sc_t *, uint32_t);
static void	wpi_rx_intr(wpi_sc_t *, wpi_rx_desc_t *,
		    wpi_rx_data_t *);
static void	wpi_tx_intr(wpi_sc_t *, wpi_rx_desc_t *,
		    wpi_rx_data_t *);
static void	wpi_cmd_intr(wpi_sc_t *, wpi_rx_desc_t *);
static uint_t	wpi_intr(caddr_t);
static uint_t	wpi_notif_softintr(caddr_t);
static uint8_t	wpi_plcp_signal(int);
static void	wpi_read_eeprom(wpi_sc_t *);
static int	wpi_cmd(wpi_sc_t *, int, const void *, int, int);
static int	wpi_mrr_setup(wpi_sc_t *);
static void	wpi_set_led(wpi_sc_t *, uint8_t, uint8_t, uint8_t);
static int	wpi_auth(wpi_sc_t *);
static int	wpi_scan(wpi_sc_t *);
static int	wpi_config(wpi_sc_t *);
static void	wpi_stop_master(wpi_sc_t *);
static int	wpi_power_up(wpi_sc_t *);
static int	wpi_reset(wpi_sc_t *);
static void	wpi_hw_config(wpi_sc_t *);
static int	wpi_init(wpi_sc_t *);
static void	wpi_stop(wpi_sc_t *);
static int	wpi_quiesce(dev_info_t *dip);
static void	wpi_amrr_init(wpi_amrr_t *);
static void	wpi_amrr_timeout(wpi_sc_t *);
static void	wpi_amrr_ratectl(void *, ieee80211_node_t *);

static int wpi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int wpi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * GLD specific operations
 */
static int	wpi_m_stat(void *arg, uint_t stat, uint64_t *val);
static int	wpi_m_start(void *arg);
static void	wpi_m_stop(void *arg);
static int	wpi_m_unicst(void *arg, const uint8_t *macaddr);
static int	wpi_m_multicst(void *arg, boolean_t add, const uint8_t *m);
static int	wpi_m_promisc(void *arg, boolean_t on);
static mblk_t  *wpi_m_tx(void *arg, mblk_t *mp);
static void	wpi_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);
static int	wpi_m_setprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, const void *wldp_buf);
static int	wpi_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t pr_flags, uint_t wldp_lenth,
    void *wldp_buf, uint_t *);
static void	wpi_destroy_locks(wpi_sc_t *sc);
static int	wpi_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type);
static void	wpi_thread(wpi_sc_t *sc);

/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset wpi_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset wpi_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

static const uint8_t wpi_ridx_to_signal[] = {
	/* OFDM: IEEE Std 802.11a-1999, pp. 14 Table 80 */
	/* R1-R4 (ral/ural is R4-R1) */
	0xd, 0xf, 0x5, 0x7, 0x9, 0xb, 0x1, 0x3,
	/* CCK: device-dependent */
	10, 20, 55, 110
};

/*
 * For mfthread only
 */
extern pri_t minclsyspri;

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(wpi_devops, nulldev, nulldev, wpi_attach,
    wpi_detach, nodev, NULL, D_MP, NULL, wpi_quiesce);

static struct modldrv wpi_modldrv = {
	&mod_driverops,
	"Intel(R) PRO/Wireless 3945ABG driver",
	&wpi_devops
};

static struct modlinkage wpi_modlinkage = {
	MODREV_1,
	&wpi_modldrv,
	NULL
};

int
_init(void)
{
	int	status;

	status = ddi_soft_state_init(&wpi_soft_state_p,
	    sizeof (wpi_sc_t), 1);
	if (status != DDI_SUCCESS)
		return (status);

	mac_init_ops(&wpi_devops, "wpi");
	status = mod_install(&wpi_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&wpi_devops);
		ddi_soft_state_fini(&wpi_soft_state_p);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&wpi_modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&wpi_devops);
		ddi_soft_state_fini(&wpi_soft_state_p);
	}

	return (status);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&wpi_modlinkage, mip));
}

/*
 * Mac Call Back entries
 */
mac_callbacks_t	wpi_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP,
	wpi_m_stat,
	wpi_m_start,
	wpi_m_stop,
	wpi_m_promisc,
	wpi_m_multicst,
	wpi_m_unicst,
	wpi_m_tx,
	wpi_m_ioctl,
	NULL,
	NULL,
	NULL,
	wpi_m_setprop,
	wpi_m_getprop
};

#ifdef DEBUG
void
wpi_dbg(uint32_t flags, const char *fmt, ...)
{
	va_list	ap;

	if (flags & wpi_dbg_flags) {
		va_start(ap, fmt);
		vcmn_err(CE_NOTE, fmt, ap);
		va_end(ap);
	}
}
#endif
/*
 * device operations
 */
int
wpi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	wpi_sc_t		*sc;
	ddi_acc_handle_t	cfg_handle;
	caddr_t			cfg_base;
	ieee80211com_t	*ic;
	int			instance, err, i;
	char			strbuf[32];
	wifi_data_t		wd = { 0 };
	mac_register_t		*macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(wpi_soft_state_p,
		    ddi_get_instance(dip));
		ASSERT(sc != NULL);
		mutex_enter(&sc->sc_glock);
		sc->sc_flags &= ~WPI_F_SUSPEND;
		mutex_exit(&sc->sc_glock);
		if (sc->sc_flags & WPI_F_RUNNING) {
			(void) wpi_init(sc);
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		}
		WPI_DBG((WPI_DEBUG_RESUME, "wpi: resume \n"));
		return (DDI_SUCCESS);
	default:
		err = DDI_FAILURE;
		goto attach_fail1;
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(wpi_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to allocate soft state\n");
		goto attach_fail1;
	}
	sc = ddi_get_soft_state(wpi_soft_state_p, instance);
	sc->sc_dip = dip;

	err = ddi_regs_map_setup(dip, 0, &cfg_base, 0, 0,
	    &wpi_reg_accattr, &cfg_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to map config spaces regs\n");
		goto attach_fail2;
	}
	sc->sc_rev = ddi_get8(cfg_handle,
	    (uint8_t *)(cfg_base + PCI_CONF_REVID));
	ddi_put8(cfg_handle, (uint8_t *)(cfg_base + 0x41), 0);
	sc->sc_clsz = ddi_get16(cfg_handle,
	    (uint16_t *)(cfg_base + PCI_CONF_CACHE_LINESZ));
	ddi_regs_map_free(&cfg_handle);
	if (!sc->sc_clsz)
		sc->sc_clsz = 16;
	sc->sc_clsz = (sc->sc_clsz << 2);
	sc->sc_dmabuf_sz = roundup(0x1000 + sizeof (struct ieee80211_frame) +
	    IEEE80211_MTU + IEEE80211_CRC_LEN +
	    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_CRCLEN), sc->sc_clsz);
	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(dip, 1, &sc->sc_base,
	    0, 0, &wpi_reg_accattr, &sc->sc_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to map device regs\n");
		goto attach_fail2;
	}

	/*
	 * Allocate shared page.
	 */
	err = wpi_alloc_shared(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to allocate shared page\n");
		goto attach_fail3;
	}

	/*
	 * Get the hw conf, including MAC address, then init all rings.
	 */
	wpi_read_eeprom(sc);
	err = wpi_ring_init(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_attach(): "
		    "failed to allocate and initialize ring\n");
		goto attach_fail4;
	}

	sc->sc_hdr = (const wpi_firmware_hdr_t *)wpi_fw_bin;

	/* firmware image layout: |HDR|<--TEXT-->|<--DATA-->|<--BOOT-->| */
	sc->sc_text = (const char *)(sc->sc_hdr + 1);
	sc->sc_data = sc->sc_text + LE_32(sc->sc_hdr->textsz);
	sc->sc_boot = sc->sc_data + LE_32(sc->sc_hdr->datasz);
	err = wpi_alloc_fw_dma(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_attach(): "
		    "failed to allocate firmware dma\n");
		goto attach_fail5;
	}

	/*
	 * Initialize mutexs and condvars
	 */
	err = ddi_get_iblock_cookie(dip, 0, &sc->sc_iblk);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to do ddi_get_iblock_cookie()\n");
		goto attach_fail6;
	}
	mutex_init(&sc->sc_glock, NULL, MUTEX_DRIVER, sc->sc_iblk);
	mutex_init(&sc->sc_tx_lock, NULL, MUTEX_DRIVER, sc->sc_iblk);
	cv_init(&sc->sc_fw_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_cmd_cv, NULL, CV_DRIVER, NULL);

	/*
	 * initialize the mfthread
	 */
	mutex_init(&sc->sc_mt_lock, NULL, MUTEX_DRIVER,
	    (void *) sc->sc_iblk);
	cv_init(&sc->sc_mt_cv, NULL, CV_DRIVER, NULL);
	sc->sc_mf_thread = NULL;
	sc->sc_mf_thread_switch = 0;
	/*
	 * Initialize the wifi part, which will be used by
	 * generic layer
	 */
	ic = &sc->sc_ic;
	ic->ic_phytype  = IEEE80211_T_OFDM;
	ic->ic_opmode   = IEEE80211_M_STA; /* default to BSS mode */
	ic->ic_state    = IEEE80211_S_INIT;
	ic->ic_maxrssi  = 70; /* experimental number */
	ic->ic_caps = IEEE80211_C_SHPREAMBLE | IEEE80211_C_TXPMGT |
	    IEEE80211_C_PMGT | IEEE80211_C_SHSLOT;

	/*
	 * use software WEP and TKIP, hardware CCMP;
	 */
	ic->ic_caps |= IEEE80211_C_AES_CCM;
	ic->ic_caps |= IEEE80211_C_WPA; /* Support WPA/WPA2 */

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = wpi_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = wpi_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ |
		    IEEE80211_CHAN_PASSIVE;
	}
	ic->ic_ibss_chan = &ic->ic_sup_channels[0];
	ic->ic_xmit = wpi_send;
	/*
	 * init Wifi layer
	 */
	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(dip),
	    ddi_get_instance(dip));

	/*
	 * Override 80211 default routines
	 */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = wpi_newstate;
	ic->ic_node_alloc = wpi_node_alloc;
	ic->ic_node_free = wpi_node_free;
	ic->ic_crypto.cs_key_set = wpi_key_set;
	ieee80211_media_init(ic);
	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	err = ddi_add_softintr(dip, DDI_SOFTINT_LOW,
	    &sc->sc_notif_softint_id, &sc->sc_iblk, NULL, wpi_notif_softintr,
	    (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to do ddi_add_softintr()\n");
		goto attach_fail7;
	}

	/*
	 * Add the interrupt handler
	 */
	err = ddi_add_intr(dip, 0, &sc->sc_iblk, NULL,
	    wpi_intr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to do ddi_add_intr()\n");
		goto attach_fail8;
	}

	/*
	 * Initialize pointer to device specific functions
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = ic->ic_opmode;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_macaddr);

	macp = mac_alloc(MAC_VERSION);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to do mac_alloc()\n");
		goto attach_fail9;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &wpi_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	/*
	 * Register the macp to mac
	 */
	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to do mac_register()\n");
		goto attach_fail9;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "wpi%d", instance);
	err = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		cmn_err(CE_WARN,
		    "wpi_attach(): failed to do ddi_create_minor_node()\n");

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	/*
	 * create the mf thread to handle the link status,
	 * recovery fatal error, etc.
	 */

	sc->sc_mf_thread_switch = 1;
	if (sc->sc_mf_thread == NULL)
		sc->sc_mf_thread = thread_create((caddr_t)NULL, 0,
		    wpi_thread, sc, 0, &p0, TS_RUN, minclsyspri);

	sc->sc_flags |= WPI_F_ATTACHED;

	return (DDI_SUCCESS);
attach_fail9:
	ddi_remove_intr(dip, 0, sc->sc_iblk);
attach_fail8:
	ddi_remove_softintr(sc->sc_notif_softint_id);
	sc->sc_notif_softint_id = NULL;
attach_fail7:
	ieee80211_detach(ic);
	wpi_destroy_locks(sc);
attach_fail6:
	wpi_free_fw_dma(sc);
attach_fail5:
	wpi_ring_free(sc);
attach_fail4:
	wpi_free_shared(sc);
attach_fail3:
	ddi_regs_map_free(&sc->sc_handle);
attach_fail2:
	ddi_soft_state_free(wpi_soft_state_p, instance);
attach_fail1:
	return (err);
}

int
wpi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	wpi_sc_t	*sc;
	int err;

	sc = ddi_get_soft_state(wpi_soft_state_p, ddi_get_instance(dip));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (sc->sc_flags & WPI_F_RUNNING) {
			wpi_stop(sc);
		}
		mutex_enter(&sc->sc_glock);
		sc->sc_flags |= WPI_F_SUSPEND;
		mutex_exit(&sc->sc_glock);
		WPI_DBG((WPI_DEBUG_RESUME, "wpi: suspend \n"));
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
	if (!(sc->sc_flags & WPI_F_ATTACHED))
		return (DDI_FAILURE);

	err = mac_disable(sc->sc_ic.ic_mach);
	if (err != DDI_SUCCESS)
		return (err);

	/*
	 * Destroy the mf_thread
	 */
	mutex_enter(&sc->sc_mt_lock);
	sc->sc_mf_thread_switch = 0;
	while (sc->sc_mf_thread != NULL) {
		if (cv_wait_sig(&sc->sc_mt_cv, &sc->sc_mt_lock) == 0)
			break;
	}
	mutex_exit(&sc->sc_mt_lock);

	wpi_stop(sc);

	/*
	 * Unregiste from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	mutex_enter(&sc->sc_glock);
	wpi_free_fw_dma(sc);
	wpi_ring_free(sc);
	wpi_free_shared(sc);
	mutex_exit(&sc->sc_glock);

	ddi_remove_intr(dip, 0, sc->sc_iblk);
	ddi_remove_softintr(sc->sc_notif_softint_id);
	sc->sc_notif_softint_id = NULL;

	/*
	 * detach ieee80211
	 */
	ieee80211_detach(&sc->sc_ic);

	wpi_destroy_locks(sc);

	ddi_regs_map_free(&sc->sc_handle);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(wpi_soft_state_p, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

static void
wpi_destroy_locks(wpi_sc_t *sc)
{
	cv_destroy(&sc->sc_mt_cv);
	mutex_destroy(&sc->sc_mt_lock);
	cv_destroy(&sc->sc_cmd_cv);
	cv_destroy(&sc->sc_fw_cv);
	mutex_destroy(&sc->sc_tx_lock);
	mutex_destroy(&sc->sc_glock);
}

/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
wpi_alloc_dma_mem(wpi_sc_t *sc, size_t memsize, ddi_dma_attr_t *dma_attr_p,
	ddi_device_acc_attr_t *acc_attr_p, uint_t dma_flags, wpi_dma_t *dma_p)
{
	caddr_t vaddr;
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(sc->sc_dip, dma_attr_p,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS) {
		dma_p->dma_hdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, acc_attr_p,
	    dma_flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING),
	    DDI_DMA_SLEEP, NULL, &vaddr, &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS) {
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
		dma_p->acc_hdl = NULL;
		return (DDI_FAILURE);
	}

	/*
	 * Bind the two together
	 */
	dma_p->mem_va = vaddr;
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    vaddr, dma_p->alength, dma_flags, DDI_DMA_SLEEP, NULL,
	    &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->acc_hdl = NULL;
		dma_p->dma_hdl = NULL;
		return (DDI_FAILURE);
	}

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
wpi_free_dma_mem(wpi_dma_t *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		if (dma_p->ncookies) {
			(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
			dma_p->ncookies = 0;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->dma_hdl = NULL;
	}

	if (dma_p->acc_hdl != NULL) {
		ddi_dma_mem_free(&dma_p->acc_hdl);
		dma_p->acc_hdl = NULL;
	}
}

/*
 * Allocate an area of dma memory for firmware load.
 * Idealy, this allocation should be a one time action, that is,
 * the memory will be freed after the firmware is uploaded to the
 * card. but since a recovery mechanism for the fatal firmware need
 * reload the firmware, and re-allocate dma at run time may be failed,
 * so we allocate it at attach and keep it in the whole lifecycle of
 * the driver.
 */
static int
wpi_alloc_fw_dma(wpi_sc_t *sc)
{
	int i, err = DDI_SUCCESS;
	wpi_dma_t *dma_p;

	err = wpi_alloc_dma_mem(sc, LE_32(sc->sc_hdr->textsz),
	    &fw_buffer_dma_attr, &wpi_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_text);
	dma_p = &sc->sc_dma_fw_text;
	WPI_DBG((WPI_DEBUG_DMA, "ncookies:%d addr1:%x size1:%x\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_alloc_fw_dma(): failed to alloc"
		    "text dma memory");
		goto fail;
	}
	for (i = 0; i < dma_p->ncookies; i++) {
		sc->sc_fw_text_cookie[i] = dma_p->cookie;
		ddi_dma_nextcookie(dma_p->dma_hdl, &dma_p->cookie);
	}
	err = wpi_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_buffer_dma_attr, &wpi_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data);
	dma_p = &sc->sc_dma_fw_data;
	WPI_DBG((WPI_DEBUG_DMA, "ncookies:%d addr1:%x size1:%x\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_alloc_fw_dma(): failed to alloc"
		    "data dma memory");
		goto fail;
	}
	for (i = 0; i < dma_p->ncookies; i++) {
		sc->sc_fw_data_cookie[i] = dma_p->cookie;
		ddi_dma_nextcookie(dma_p->dma_hdl, &dma_p->cookie);
	}
fail:
	return (err);
}

static void
wpi_free_fw_dma(wpi_sc_t *sc)
{
	wpi_free_dma_mem(&sc->sc_dma_fw_text);
	wpi_free_dma_mem(&sc->sc_dma_fw_data);
}

/*
 * Allocate a shared page between host and NIC.
 */
static int
wpi_alloc_shared(wpi_sc_t *sc)
{
	int err = DDI_SUCCESS;

	/* must be aligned on a 4K-page boundary */
	err = wpi_alloc_dma_mem(sc, sizeof (wpi_shared_t),
	    &sh_dma_attr, &wpi_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_sh);
	if (err != DDI_SUCCESS)
		goto fail;
	sc->sc_shared = (wpi_shared_t *)sc->sc_dma_sh.mem_va;
	return (err);

fail:
	wpi_free_shared(sc);
	return (err);
}

static void
wpi_free_shared(wpi_sc_t *sc)
{
	wpi_free_dma_mem(&sc->sc_dma_sh);
}

static int
wpi_alloc_rx_ring(wpi_sc_t *sc)
{
	wpi_rx_ring_t *ring;
	wpi_rx_data_t *data;
	int i, err = DDI_SUCCESS;

	ring = &sc->sc_rxq;
	ring->cur = 0;

	err = wpi_alloc_dma_mem(sc, WPI_RX_RING_COUNT * sizeof (uint32_t),
	    &ring_desc_dma_attr, &wpi_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		WPI_DBG((WPI_DEBUG_DMA, "dma alloc rx ring desc failed\n"));
		goto fail;
	}
	ring->desc = (uint32_t *)ring->dma_desc.mem_va;

	/*
	 * Allocate Rx buffers.
	 */
	for (i = 0; i < WPI_RX_RING_COUNT; i++) {
		data = &ring->data[i];
		err = wpi_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &rx_buffer_dma_attr, &wpi_dma_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			WPI_DBG((WPI_DEBUG_DMA, "dma alloc rx ring buf[%d] "
			    "failed\n", i));
			goto fail;
		}

		ring->desc[i] = LE_32(data->dma_data.cookie.dmac_address);
	}

	WPI_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	return (err);

fail:
	wpi_free_rx_ring(sc);
	return (err);
}

static void
wpi_reset_rx_ring(wpi_sc_t *sc)
{
	int ntries;

	wpi_mem_lock(sc);

	WPI_WRITE(sc, WPI_RX_CONFIG, 0);
	for (ntries = 0; ntries < 2000; ntries++) {
		if (WPI_READ(sc, WPI_RX_STATUS) & WPI_RX_IDLE)
			break;
		DELAY(1000);
	}
	if (ntries == 2000)
		WPI_DBG((WPI_DEBUG_DMA, "timeout resetting Rx ring\n"));

	wpi_mem_unlock(sc);

	sc->sc_rxq.cur = 0;
}

static void
wpi_free_rx_ring(wpi_sc_t *sc)
{
	int i;

	for (i = 0; i < WPI_RX_RING_COUNT; i++) {
		if (sc->sc_rxq.data[i].dma_data.dma_hdl)
			WPI_DMA_SYNC(sc->sc_rxq.data[i].dma_data,
			    DDI_DMA_SYNC_FORCPU);
		wpi_free_dma_mem(&sc->sc_rxq.data[i].dma_data);
	}

	if (sc->sc_rxq.dma_desc.dma_hdl)
		WPI_DMA_SYNC(sc->sc_rxq.dma_desc, DDI_DMA_SYNC_FORDEV);
	wpi_free_dma_mem(&sc->sc_rxq.dma_desc);
}

static int
wpi_alloc_tx_ring(wpi_sc_t *sc, wpi_tx_ring_t *ring, int count, int qid)
{
	wpi_tx_data_t *data;
	wpi_tx_desc_t *desc_h;
	uint32_t paddr_desc_h;
	wpi_tx_cmd_t *cmd_h;
	uint32_t paddr_cmd_h;
	int i, err = DDI_SUCCESS;

	ring->qid = qid;
	ring->count = count;
	ring->queued = 0;
	ring->cur = 0;

	err = wpi_alloc_dma_mem(sc, count * sizeof (wpi_tx_desc_t),
	    &ring_desc_dma_attr, &wpi_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		WPI_DBG((WPI_DEBUG_DMA, "dma alloc tx ring desc[%d] failed\n",
		    qid));
		goto fail;
	}

	/* update shared page with ring's base address */
	sc->sc_shared->txbase[qid] = ring->dma_desc.cookie.dmac_address;

	desc_h = (wpi_tx_desc_t *)ring->dma_desc.mem_va;
	paddr_desc_h = ring->dma_desc.cookie.dmac_address;

	err = wpi_alloc_dma_mem(sc, count * sizeof (wpi_tx_cmd_t),
	    &tx_cmd_dma_attr, &wpi_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_cmd);
	if (err != DDI_SUCCESS) {
		WPI_DBG((WPI_DEBUG_DMA, "dma alloc tx ring cmd[%d] failed\n",
		    qid));
		goto fail;
	}

	cmd_h = (wpi_tx_cmd_t *)ring->dma_cmd.mem_va;
	paddr_cmd_h = ring->dma_cmd.cookie.dmac_address;

	/*
	 * Allocate Tx buffers.
	 */
	ring->data = kmem_zalloc(sizeof (wpi_tx_data_t) * count, KM_NOSLEEP);
	if (ring->data == NULL) {
		WPI_DBG((WPI_DEBUG_DMA, "could not allocate tx data slots\n"));
		goto fail;
	}

	for (i = 0; i < count; i++) {
		data = &ring->data[i];
		err = wpi_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &tx_buffer_dma_attr, &wpi_dma_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			WPI_DBG((WPI_DEBUG_DMA, "dma alloc tx ring buf[%d] "
			    "failed\n", i));
			goto fail;
		}

		data->desc = desc_h + i;
		data->paddr_desc = paddr_desc_h +
		    ((uintptr_t)data->desc - (uintptr_t)desc_h);
		data->cmd = cmd_h + i;
		data->paddr_cmd = paddr_cmd_h +
		    ((uintptr_t)data->cmd - (uintptr_t)cmd_h);
	}

	return (err);

fail:
	wpi_free_tx_ring(sc, ring);
	return (err);
}

static void
wpi_reset_tx_ring(wpi_sc_t *sc, wpi_tx_ring_t *ring)
{
	wpi_tx_data_t *data;
	int i, ntries;

	wpi_mem_lock(sc);

	WPI_WRITE(sc, WPI_TX_CONFIG(ring->qid), 0);
	for (ntries = 0; ntries < 100; ntries++) {
		if (WPI_READ(sc, WPI_TX_STATUS) & WPI_TX_IDLE(ring->qid))
			break;
		DELAY(10);
	}
#ifdef DEBUG
	if (ntries == 100 && wpi_dbg_flags > 0) {
		WPI_DBG((WPI_DEBUG_DMA, "timeout resetting Tx ring %d\n",
		    ring->qid));
	}
#endif
	wpi_mem_unlock(sc);

	if (!(sc->sc_flags & WPI_F_QUIESCED)) {
		for (i = 0; i < ring->count; i++) {
			data = &ring->data[i];
			WPI_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
		}
	}

	ring->queued = 0;
	ring->cur = 0;
}

/*ARGSUSED*/
static void
wpi_free_tx_ring(wpi_sc_t *sc, wpi_tx_ring_t *ring)
{
	int i;

	if (ring->dma_desc.dma_hdl != NULL)
		WPI_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);
	wpi_free_dma_mem(&ring->dma_desc);

	if (ring->dma_cmd.dma_hdl != NULL)
		WPI_DMA_SYNC(ring->dma_cmd, DDI_DMA_SYNC_FORDEV);
	wpi_free_dma_mem(&ring->dma_cmd);

	if (ring->data != NULL) {
		for (i = 0; i < ring->count; i++) {
			if (ring->data[i].dma_data.dma_hdl)
				WPI_DMA_SYNC(ring->data[i].dma_data,
				    DDI_DMA_SYNC_FORDEV);
			wpi_free_dma_mem(&ring->data[i].dma_data);
		}
		kmem_free(ring->data, ring->count * sizeof (wpi_tx_data_t));
		ring->data = NULL;
	}
}

static int
wpi_ring_init(wpi_sc_t *sc)
{
	int i, err = DDI_SUCCESS;

	for (i = 0; i < 4; i++) {
		err = wpi_alloc_tx_ring(sc, &sc->sc_txq[i], WPI_TX_RING_COUNT,
		    i);
		if (err != DDI_SUCCESS)
			goto fail;
	}
	err = wpi_alloc_tx_ring(sc, &sc->sc_cmdq, WPI_CMD_RING_COUNT, 4);
	if (err != DDI_SUCCESS)
		goto fail;
	err = wpi_alloc_tx_ring(sc, &sc->sc_svcq, WPI_SVC_RING_COUNT, 5);
	if (err != DDI_SUCCESS)
		goto fail;
	err = wpi_alloc_rx_ring(sc);
	if (err != DDI_SUCCESS)
		goto fail;
	return (err);

fail:
	return (err);
}

static void
wpi_ring_free(wpi_sc_t *sc)
{
	int i = 4;

	wpi_free_rx_ring(sc);
	wpi_free_tx_ring(sc, &sc->sc_svcq);
	wpi_free_tx_ring(sc, &sc->sc_cmdq);
	while (--i >= 0) {
		wpi_free_tx_ring(sc, &sc->sc_txq[i]);
	}
}

/* ARGSUSED */
static ieee80211_node_t *
wpi_node_alloc(ieee80211com_t *ic)
{
	wpi_amrr_t *amrr;

	amrr = kmem_zalloc(sizeof (wpi_amrr_t), KM_SLEEP);
	if (amrr != NULL)
		wpi_amrr_init(amrr);
	return (&amrr->in);
}

static void
wpi_node_free(ieee80211_node_t *in)
{
	ieee80211com_t *ic = in->in_ic;

	ic->ic_node_cleanup(in);
	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);
	kmem_free(in, sizeof (wpi_amrr_t));
}

/*ARGSUSED*/
static int
wpi_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	wpi_sc_t *sc = (wpi_sc_t *)ic;
	ieee80211_node_t *in = ic->ic_bss;
	enum ieee80211_state ostate;
	int i, err = WPI_SUCCESS;

	mutex_enter(&sc->sc_glock);
	ostate = ic->ic_state;
	switch (nstate) {
	case IEEE80211_S_SCAN:
		switch (ostate) {
		case IEEE80211_S_INIT:
		{
			wpi_node_t node;

			sc->sc_flags |= WPI_F_SCANNING;
			sc->sc_scan_next = 0;

			/* make the link LED blink while we're scanning */
			wpi_set_led(sc, WPI_LED_LINK, 20, 2);

			/*
			 * clear association to receive beacons from all
			 * BSS'es
			 */
			sc->sc_config.state = 0;
			sc->sc_config.filter &= ~LE_32(WPI_FILTER_BSS);

			WPI_DBG((WPI_DEBUG_80211, "config chan %d flags %x "
			    "filter %x\n",
			    sc->sc_config.chan, sc->sc_config.flags,
			    sc->sc_config.filter));

			err = wpi_cmd(sc, WPI_CMD_CONFIGURE, &sc->sc_config,
			    sizeof (wpi_config_t), 1);
			if (err != WPI_SUCCESS) {
				cmn_err(CE_WARN,
				    "could not clear association\n");
				sc->sc_flags &= ~WPI_F_SCANNING;
				mutex_exit(&sc->sc_glock);
				return (err);
			}

			/* add broadcast node to send probe request */
			(void) memset(&node, 0, sizeof (node));
			(void) memset(&node.bssid, 0xff, IEEE80211_ADDR_LEN);
			node.id = WPI_ID_BROADCAST;

			err = wpi_cmd(sc, WPI_CMD_ADD_NODE, &node,
			    sizeof (node), 1);
			if (err != WPI_SUCCESS) {
				cmn_err(CE_WARN,
				    "could not add broadcast node\n");
				sc->sc_flags &= ~WPI_F_SCANNING;
				mutex_exit(&sc->sc_glock);
				return (err);
			}
			break;
		}
		case IEEE80211_S_SCAN:
			mutex_exit(&sc->sc_glock);
			/* step to next channel before actual FW scan */
			err = sc->sc_newstate(ic, nstate, arg);
			mutex_enter(&sc->sc_glock);
			if ((err != 0) || ((err = wpi_scan(sc)) != 0)) {
				cmn_err(CE_WARN,
				    "could not initiate scan\n");
				sc->sc_flags &= ~WPI_F_SCANNING;
				ieee80211_cancel_scan(ic);
			}
			mutex_exit(&sc->sc_glock);
			return (err);
		default:
			break;
		}
		sc->sc_clk = 0;
		break;

	case IEEE80211_S_AUTH:
		if (ostate == IEEE80211_S_SCAN) {
			sc->sc_flags &= ~WPI_F_SCANNING;
		}

		/* reset state to handle reassociations correctly */
		sc->sc_config.state = 0;
		sc->sc_config.filter &= ~LE_32(WPI_FILTER_BSS);

		if ((err = wpi_auth(sc)) != 0) {
			WPI_DBG((WPI_DEBUG_80211,
			    "could not send authentication request\n"));
			mutex_exit(&sc->sc_glock);
			return (err);
		}
		break;

	case IEEE80211_S_RUN:
		if (ostate == IEEE80211_S_SCAN) {
			sc->sc_flags &= ~WPI_F_SCANNING;
		}

		if (ic->ic_opmode == IEEE80211_M_MONITOR) {
			/* link LED blinks while monitoring */
			wpi_set_led(sc, WPI_LED_LINK, 5, 5);
			break;
		}

		if (ic->ic_opmode != IEEE80211_M_STA) {
			(void) wpi_auth(sc);
			/* need setup beacon here */
		}
		WPI_DBG((WPI_DEBUG_80211, "wpi: associated."));

		/* update adapter's configuration */
		sc->sc_config.state = LE_16(WPI_CONFIG_ASSOCIATED);
		/* short preamble/slot time are negotiated when associating */
		sc->sc_config.flags &= ~LE_32(WPI_CONFIG_SHPREAMBLE |
		    WPI_CONFIG_SHSLOT);
		if (ic->ic_flags & IEEE80211_F_SHSLOT)
			sc->sc_config.flags |= LE_32(WPI_CONFIG_SHSLOT);
		if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
			sc->sc_config.flags |= LE_32(WPI_CONFIG_SHPREAMBLE);
		sc->sc_config.filter |= LE_32(WPI_FILTER_BSS);
		if (ic->ic_opmode != IEEE80211_M_STA)
			sc->sc_config.filter |= LE_32(WPI_FILTER_BEACON);

		WPI_DBG((WPI_DEBUG_80211, "config chan %d flags %x\n",
		    sc->sc_config.chan, sc->sc_config.flags));
		err = wpi_cmd(sc, WPI_CMD_CONFIGURE, &sc->sc_config,
		    sizeof (wpi_config_t), 1);
		if (err != WPI_SUCCESS) {
			WPI_DBG((WPI_DEBUG_80211,
			    "could not update configuration\n"));
			mutex_exit(&sc->sc_glock);
			return (err);
		}

		/* start automatic rate control */
		mutex_enter(&sc->sc_mt_lock);
		if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
			sc->sc_flags |= WPI_F_RATE_AUTO_CTL;
			/* set rate to some reasonable initial value */
			i = in->in_rates.ir_nrates - 1;
			while (i > 0 && IEEE80211_RATE(i) > 72)
				i--;
			in->in_txrate = i;
		} else {
			sc->sc_flags &= ~WPI_F_RATE_AUTO_CTL;
		}
		mutex_exit(&sc->sc_mt_lock);

		/* link LED always on while associated */
		wpi_set_led(sc, WPI_LED_LINK, 0, 1);
		break;

	case IEEE80211_S_INIT:
		sc->sc_flags &= ~WPI_F_SCANNING;
		break;

	case IEEE80211_S_ASSOC:
		sc->sc_flags &= ~WPI_F_SCANNING;
		break;
	}

	mutex_exit(&sc->sc_glock);
	return (sc->sc_newstate(ic, nstate, arg));
}

/*ARGSUSED*/
static int wpi_key_set(ieee80211com_t *ic, const struct ieee80211_key *k,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	wpi_sc_t *sc = (wpi_sc_t *)ic;
	wpi_node_t node;
	int err;

	switch (k->wk_cipher->ic_cipher) {
	case IEEE80211_CIPHER_WEP:
	case IEEE80211_CIPHER_TKIP:
		return (1); /* sofeware do it. */
	case IEEE80211_CIPHER_AES_CCM:
		break;
	default:
		return (0);
	}
	sc->sc_config.filter &= ~(WPI_FILTER_NODECRYPTUNI |
	    WPI_FILTER_NODECRYPTMUL);

	mutex_enter(&sc->sc_glock);

	/* update ap/multicast node */
	(void) memset(&node, 0, sizeof (node));
	if (IEEE80211_IS_MULTICAST(mac)) {
		(void) memset(node.bssid, 0xff, 6);
		node.id = WPI_ID_BROADCAST;
	} else {
		IEEE80211_ADDR_COPY(node.bssid, ic->ic_bss->in_bssid);
		node.id = WPI_ID_BSS;
	}
	if (k->wk_flags & IEEE80211_KEY_XMIT) {
		node.key_flags = 0;
		node.keyp = k->wk_keyix;
	} else {
		node.key_flags = (1 << 14);
		node.keyp = k->wk_keyix + 4;
	}
	(void) memcpy(node.key, k->wk_key, k->wk_keylen);
	node.key_flags |= (2 | (1 << 3) | (k->wk_keyix << 8));
	node.sta_mask = 1;
	node.control = 1;
	err = wpi_cmd(sc, WPI_CMD_ADD_NODE, &node, sizeof (node), 1);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_key_set():"
		    "failed to update ap node\n");
		mutex_exit(&sc->sc_glock);
		return (0);
	}
	mutex_exit(&sc->sc_glock);
	return (1);
}

/*
 * Grab exclusive access to NIC memory.
 */
static void
wpi_mem_lock(wpi_sc_t *sc)
{
	uint32_t tmp;
	int ntries;

	tmp = WPI_READ(sc, WPI_GPIO_CTL);
	WPI_WRITE(sc, WPI_GPIO_CTL, tmp | WPI_GPIO_MAC);

	/* spin until we actually get the lock */
	for (ntries = 0; ntries < 1000; ntries++) {
		if ((WPI_READ(sc, WPI_GPIO_CTL) &
		    (WPI_GPIO_CLOCK | WPI_GPIO_SLEEP)) == WPI_GPIO_CLOCK)
			break;
		DELAY(10);
	}
	if (ntries == 1000)
		WPI_DBG((WPI_DEBUG_PIO, "could not lock memory\n"));
}

/*
 * Release lock on NIC memory.
 */
static void
wpi_mem_unlock(wpi_sc_t *sc)
{
	uint32_t tmp = WPI_READ(sc, WPI_GPIO_CTL);
	WPI_WRITE(sc, WPI_GPIO_CTL, tmp & ~WPI_GPIO_MAC);
}

static uint32_t
wpi_mem_read(wpi_sc_t *sc, uint16_t addr)
{
	WPI_WRITE(sc, WPI_READ_MEM_ADDR, WPI_MEM_4 | addr);
	return (WPI_READ(sc, WPI_READ_MEM_DATA));
}

static void
wpi_mem_write(wpi_sc_t *sc, uint16_t addr, uint32_t data)
{
	WPI_WRITE(sc, WPI_WRITE_MEM_ADDR, WPI_MEM_4 | addr);
	WPI_WRITE(sc, WPI_WRITE_MEM_DATA, data);
}

static void
wpi_mem_write_region_4(wpi_sc_t *sc, uint16_t addr,
    const uint32_t *data, int wlen)
{
	for (; wlen > 0; wlen--, data++, addr += 4)
		wpi_mem_write(sc, addr, *data);
}

/*
 * Read 16 bits from the EEPROM.  We access EEPROM through the MAC instead of
 * using the traditional bit-bang method.
 */
static uint16_t
wpi_read_prom_word(wpi_sc_t *sc, uint32_t addr)
{
	uint32_t val;
	int ntries;

	WPI_WRITE(sc, WPI_EEPROM_CTL, addr << 2);

	wpi_mem_lock(sc);
	for (ntries = 0; ntries < 10; ntries++) {
		if ((val = WPI_READ(sc, WPI_EEPROM_CTL)) & WPI_EEPROM_READY)
			break;
		DELAY(10);
	}
	wpi_mem_unlock(sc);

	if (ntries == 10) {
		WPI_DBG((WPI_DEBUG_PIO, "could not read EEPROM\n"));
		return (0xdead);
	}
	return (val >> 16);
}

/*
 * The firmware boot code is small and is intended to be copied directly into
 * the NIC internal memory.
 */
static int
wpi_load_microcode(wpi_sc_t *sc)
{
	const char *ucode;
	int size;

	ucode = sc->sc_boot;
	size = LE_32(sc->sc_hdr->bootsz);
	/* check that microcode size is a multiple of 4 */
	if (size & 3)
		return (EINVAL);

	size /= sizeof (uint32_t);

	wpi_mem_lock(sc);

	/* copy microcode image into NIC memory */
	wpi_mem_write_region_4(sc, WPI_MEM_UCODE_BASE, (const uint32_t *)ucode,
	    size);

	wpi_mem_write(sc, WPI_MEM_UCODE_SRC, 0);
	wpi_mem_write(sc, WPI_MEM_UCODE_DST, WPI_FW_TEXT);
	wpi_mem_write(sc, WPI_MEM_UCODE_SIZE, size);

	/* run microcode */
	wpi_mem_write(sc, WPI_MEM_UCODE_CTL, WPI_UC_RUN);

	wpi_mem_unlock(sc);

	return (WPI_SUCCESS);
}

/*
 * The firmware text and data segments are transferred to the NIC using DMA.
 * The driver just copies the firmware into DMA-safe memory and tells the NIC
 * where to find it.  Once the NIC has copied the firmware into its internal
 * memory, we can free our local copy in the driver.
 */
static int
wpi_load_firmware(wpi_sc_t *sc, uint32_t target)
{
	const char *fw;
	int size;
	wpi_dma_t *dma_p;
	ddi_dma_cookie_t *cookie;
	wpi_tx_desc_t desc;
	int i, ntries, err = WPI_SUCCESS;

	/* only text and data here */
	if (target == WPI_FW_TEXT) {
		fw = sc->sc_text;
		size = LE_32(sc->sc_hdr->textsz);
		dma_p = &sc->sc_dma_fw_text;
		cookie = sc->sc_fw_text_cookie;
	} else {
		fw = sc->sc_data;
		size = LE_32(sc->sc_hdr->datasz);
		dma_p = &sc->sc_dma_fw_data;
		cookie = sc->sc_fw_data_cookie;
	}

	/* copy firmware image to DMA-safe memory */
	(void) memcpy(dma_p->mem_va, fw, size);

	/* make sure the adapter will get up-to-date values */
	(void) ddi_dma_sync(dma_p->dma_hdl, 0, size, DDI_DMA_SYNC_FORDEV);

	(void) memset(&desc, 0, sizeof (desc));
	desc.flags = LE_32(WPI_PAD32(size) << 28 | dma_p->ncookies << 24);
	for (i = 0; i < dma_p->ncookies; i++) {
		WPI_DBG((WPI_DEBUG_DMA, "cookie%d addr:%x size:%x\n",
		    i, cookie[i].dmac_address, cookie[i].dmac_size));
		desc.segs[i].addr = cookie[i].dmac_address;
		desc.segs[i].len = (uint32_t)cookie[i].dmac_size;
	}

	wpi_mem_lock(sc);

	/* tell adapter where to copy image in its internal memory */
	WPI_WRITE(sc, WPI_FW_TARGET, target);

	WPI_WRITE(sc, WPI_TX_CONFIG(6), 0);

	/* copy firmware descriptor into NIC memory */
	WPI_WRITE_REGION_4(sc, WPI_TX_DESC(6), (uint32_t *)&desc,
	    sizeof desc / sizeof (uint32_t));

	WPI_WRITE(sc, WPI_TX_CREDIT(6), 0xfffff);
	WPI_WRITE(sc, WPI_TX_STATE(6), 0x4001);
	WPI_WRITE(sc, WPI_TX_CONFIG(6), 0x80000001);

	/* wait while the adapter is busy copying the firmware */
	for (ntries = 0; ntries < 100; ntries++) {
		if (WPI_READ(sc, WPI_TX_STATUS) & WPI_TX_IDLE(6))
			break;
		DELAY(1000);
	}
	if (ntries == 100) {
		WPI_DBG((WPI_DEBUG_FW, "timeout transferring firmware\n"));
		err = ETIMEDOUT;
	}

	WPI_WRITE(sc, WPI_TX_CREDIT(6), 0);

	wpi_mem_unlock(sc);

	return (err);
}

/*ARGSUSED*/
static void
wpi_rx_intr(wpi_sc_t *sc, wpi_rx_desc_t *desc, wpi_rx_data_t *data)
{
	ieee80211com_t *ic = &sc->sc_ic;
	wpi_rx_ring_t *ring = &sc->sc_rxq;
	wpi_rx_stat_t *stat;
	wpi_rx_head_t *head;
	wpi_rx_tail_t *tail;
	ieee80211_node_t *in;
	struct ieee80211_frame *wh;
	mblk_t *mp;
	uint16_t len;

	stat = (wpi_rx_stat_t *)(desc + 1);

	if (stat->len > WPI_STAT_MAXLEN) {
		WPI_DBG((WPI_DEBUG_RX, "invalid rx statistic header\n"));
		return;
	}

	head = (wpi_rx_head_t *)((caddr_t)(stat + 1) + stat->len);
	tail = (wpi_rx_tail_t *)((caddr_t)(head + 1) + LE_16(head->len));

	len = LE_16(head->len);

	WPI_DBG((WPI_DEBUG_RX, "rx intr: idx=%d len=%d stat len=%d rssi=%d "
	    "rate=%x chan=%d tstamp=%llu", ring->cur, LE_32(desc->len),
	    len, (int8_t)stat->rssi, head->rate, head->chan,
	    LE_64(tail->tstamp)));

	if ((len < 20) || (len > sc->sc_dmabuf_sz)) {
		sc->sc_rx_err++;
		return;
	}

	/*
	 * Discard Rx frames with bad CRC early
	 */
	if ((LE_32(tail->flags) & WPI_RX_NOERROR) != WPI_RX_NOERROR) {
		WPI_DBG((WPI_DEBUG_RX, "rx tail flags error %x\n",
		    LE_32(tail->flags)));
		sc->sc_rx_err++;
		return;
	}

	/* update Rx descriptor */
	/* ring->desc[ring->cur] = LE_32(data->dma_data.cookie.dmac_address); */

#ifdef WPI_BPF
#ifndef WPI_CURRENT
	if (sc->sc_drvbpf != NULL) {
#else
	if (bpf_peers_present(sc->sc_drvbpf)) {
#endif
		struct wpi_rx_radiotap_header *tap = &sc->sc_rxtap;

		tap->wr_flags = 0;
		tap->wr_rate = head->rate;
		tap->wr_chan_freq =
		    LE_16(ic->ic_channels[head->chan].ic_freq);
		tap->wr_chan_flags =
		    LE_16(ic->ic_channels[head->chan].ic_flags);
		tap->wr_dbm_antsignal = (int8_t)(stat->rssi - WPI_RSSI_OFFSET);
		tap->wr_dbm_antnoise = (int8_t)LE_16(stat->noise);
		tap->wr_tsft = tail->tstamp;
		tap->wr_antenna = (LE_16(head->flags) >> 4) & 0xf;
		switch (head->rate) {
		/* CCK rates */
		case  10: tap->wr_rate =   2; break;
		case  20: tap->wr_rate =   4; break;
		case  55: tap->wr_rate =  11; break;
		case 110: tap->wr_rate =  22; break;
		/* OFDM rates */
		case 0xd: tap->wr_rate =  12; break;
		case 0xf: tap->wr_rate =  18; break;
		case 0x5: tap->wr_rate =  24; break;
		case 0x7: tap->wr_rate =  36; break;
		case 0x9: tap->wr_rate =  48; break;
		case 0xb: tap->wr_rate =  72; break;
		case 0x1: tap->wr_rate =  96; break;
		case 0x3: tap->wr_rate = 108; break;
		/* unknown rate: should not happen */
		default:  tap->wr_rate =   0;
		}
		if (LE_16(head->flags) & 0x4)
			tap->wr_flags |= IEEE80211_RADIOTAP_F_SHORTPRE;

		bpf_mtap2(sc->sc_drvbpf, tap, sc->sc_rxtap_len, m);
	}
#endif
	/* grab a reference to the source node */
	wh = (struct ieee80211_frame *)(head + 1);

#ifdef DEBUG
	if (wpi_dbg_flags & WPI_DEBUG_RX)
		ieee80211_dump_pkt((uint8_t *)wh, len, 0, 0);
#endif

	in = ieee80211_find_rxnode(ic, wh);
	mp = allocb(len, BPRI_MED);
	if (mp) {
		(void) memcpy(mp->b_wptr, wh, len);
		mp->b_wptr += len;

		/* send the frame to the 802.11 layer */
		(void) ieee80211_input(ic, mp, in, stat->rssi, 0);
	} else {
		sc->sc_rx_nobuf++;
		WPI_DBG((WPI_DEBUG_RX,
		    "wpi_rx_intr(): alloc rx buf failed\n"));
	}
	/* release node reference */
	ieee80211_free_node(in);
}

/*ARGSUSED*/
static void
wpi_tx_intr(wpi_sc_t *sc, wpi_rx_desc_t *desc, wpi_rx_data_t *data)
{
	ieee80211com_t *ic = &sc->sc_ic;
	wpi_tx_ring_t *ring = &sc->sc_txq[desc->qid & 0x3];
	/* wpi_tx_data_t *txdata = &ring->data[desc->idx]; */
	wpi_tx_stat_t *stat = (wpi_tx_stat_t *)(desc + 1);
	wpi_amrr_t *amrr = (wpi_amrr_t *)ic->ic_bss;

	WPI_DBG((WPI_DEBUG_TX, "tx done: qid=%d idx=%d retries=%d nkill=%d "
	    "rate=%x duration=%d status=%x\n",
	    desc->qid, desc->idx, stat->ntries, stat->nkill, stat->rate,
	    LE_32(stat->duration), LE_32(stat->status)));

	amrr->txcnt++;
	WPI_DBG((WPI_DEBUG_RATECTL, "tx: %d cnt\n", amrr->txcnt));
	if (stat->ntries > 0) {
		amrr->retrycnt++;
		sc->sc_tx_retries++;
		WPI_DBG((WPI_DEBUG_RATECTL, "tx: %d retries\n",
		    amrr->retrycnt));
	}

	sc->sc_tx_timer = 0;

	mutex_enter(&sc->sc_tx_lock);
	ring->queued--;
	if (ring->queued < 0)
		ring->queued = 0;
	if ((sc->sc_need_reschedule) && (ring->queued <= (ring->count << 3))) {
		sc->sc_need_reschedule = 0;
		mutex_exit(&sc->sc_tx_lock);
		mac_tx_update(ic->ic_mach);
		mutex_enter(&sc->sc_tx_lock);
	}
	mutex_exit(&sc->sc_tx_lock);
}

static void
wpi_cmd_intr(wpi_sc_t *sc, wpi_rx_desc_t *desc)
{
	if ((desc->qid & 7) != 4) {
		return;	/* not a command ack */
	}
	mutex_enter(&sc->sc_glock);
	sc->sc_flags |= WPI_F_CMD_DONE;
	cv_signal(&sc->sc_cmd_cv);
	mutex_exit(&sc->sc_glock);
}

static uint_t
wpi_notif_softintr(caddr_t arg)
{
	wpi_sc_t *sc = (wpi_sc_t *)arg;
	wpi_rx_desc_t *desc;
	wpi_rx_data_t *data;
	uint32_t hw;

	mutex_enter(&sc->sc_glock);
	if (sc->sc_notif_softint_pending != 1) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	mutex_exit(&sc->sc_glock);

	hw = LE_32(sc->sc_shared->next);

	while (sc->sc_rxq.cur != hw) {
		data = &sc->sc_rxq.data[sc->sc_rxq.cur];
		desc = (wpi_rx_desc_t *)data->dma_data.mem_va;

		WPI_DBG((WPI_DEBUG_INTR, "rx notification hw = %d cur = %d "
		    "qid=%x idx=%d flags=%x type=%d len=%d\n",
		    hw, sc->sc_rxq.cur, desc->qid, desc->idx, desc->flags,
		    desc->type, LE_32(desc->len)));

		if (!(desc->qid & 0x80))	/* reply to a command */
			wpi_cmd_intr(sc, desc);

		switch (desc->type) {
		case WPI_RX_DONE:
			/* a 802.11 frame was received */
			wpi_rx_intr(sc, desc, data);
			break;

		case WPI_TX_DONE:
			/* a 802.11 frame has been transmitted */
			wpi_tx_intr(sc, desc, data);
			break;

		case WPI_UC_READY:
		{
			wpi_ucode_info_t *uc =
			    (wpi_ucode_info_t *)(desc + 1);

			/* the microcontroller is ready */
			WPI_DBG((WPI_DEBUG_FW,
			    "microcode alive notification version %x "
			    "alive %x\n", LE_32(uc->version),
			    LE_32(uc->valid)));

			if (LE_32(uc->valid) != 1) {
				WPI_DBG((WPI_DEBUG_FW,
				    "microcontroller initialization failed\n"));
			}
			break;
		}
		case WPI_STATE_CHANGED:
		{
			uint32_t *status = (uint32_t *)(desc + 1);

			/* enabled/disabled notification */
			WPI_DBG((WPI_DEBUG_RADIO, "state changed to %x\n",
			    LE_32(*status)));

			if (LE_32(*status) & 1) {
				/*
				 * the radio button has to be pushed(OFF). It
				 * is considered as a hw error, the
				 * wpi_thread() tries to recover it after the
				 * button is pushed again(ON)
				 */
				cmn_err(CE_NOTE,
				    "wpi: Radio transmitter is off\n");
				sc->sc_ostate = sc->sc_ic.ic_state;
				ieee80211_new_state(&sc->sc_ic,
				    IEEE80211_S_INIT, -1);
				sc->sc_flags |=
				    (WPI_F_HW_ERR_RECOVER | WPI_F_RADIO_OFF);
			}
			break;
		}
		case WPI_START_SCAN:
		{
			wpi_start_scan_t *scan =
			    (wpi_start_scan_t *)(desc + 1);

			WPI_DBG((WPI_DEBUG_SCAN,
			    "scanning channel %d status %x\n",
			    scan->chan, LE_32(scan->status)));

			break;
		}
		case WPI_STOP_SCAN:
		{
			wpi_stop_scan_t *scan =
			    (wpi_stop_scan_t *)(desc + 1);

			WPI_DBG((WPI_DEBUG_SCAN,
			    "completed channel %d (burst of %d) status %02x\n",
			    scan->chan, scan->nchan, scan->status));

			sc->sc_scan_pending = 0;
			sc->sc_scan_next++;
			break;
		}
		default:
			break;
		}

		sc->sc_rxq.cur = (sc->sc_rxq.cur + 1) % WPI_RX_RING_COUNT;
	}

	/* tell the firmware what we have processed */
	hw = (hw == 0) ? WPI_RX_RING_COUNT - 1 : hw - 1;
	WPI_WRITE(sc, WPI_RX_WIDX, hw & (~7));
	mutex_enter(&sc->sc_glock);
	sc->sc_notif_softint_pending = 0;
	mutex_exit(&sc->sc_glock);

	return (DDI_INTR_CLAIMED);
}

static uint_t
wpi_intr(caddr_t arg)
{
	wpi_sc_t *sc = (wpi_sc_t *)arg;
	uint32_t r, rfh;

	mutex_enter(&sc->sc_glock);
	if (sc->sc_flags & WPI_F_SUSPEND) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	r = WPI_READ(sc, WPI_INTR);
	if (r == 0 || r == 0xffffffff) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	WPI_DBG((WPI_DEBUG_INTR, "interrupt reg %x\n", r));

	rfh = WPI_READ(sc, WPI_INTR_STATUS);
	/* disable interrupts */
	WPI_WRITE(sc, WPI_MASK, 0);
	/* ack interrupts */
	WPI_WRITE(sc, WPI_INTR, r);
	WPI_WRITE(sc, WPI_INTR_STATUS, rfh);

	if (sc->sc_notif_softint_id == NULL) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_CLAIMED);
	}

	if (r & (WPI_SW_ERROR | WPI_HW_ERROR)) {
		WPI_DBG((WPI_DEBUG_FW, "fatal firmware error\n"));
		mutex_exit(&sc->sc_glock);
		wpi_stop(sc);
		if (!(sc->sc_flags & WPI_F_HW_ERR_RECOVER)) {
			sc->sc_ostate = sc->sc_ic.ic_state;
		}
		ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		sc->sc_flags |= WPI_F_HW_ERR_RECOVER;
		return (DDI_INTR_CLAIMED);
	}

	if ((r & (WPI_RX_INTR | WPI_RX_SWINT)) ||
	    (rfh & 0x40070000)) {
		sc->sc_notif_softint_pending = 1;
		ddi_trigger_softintr(sc->sc_notif_softint_id);
	}

	if (r & WPI_ALIVE_INTR)	{ /* firmware initialized */
		sc->sc_flags |= WPI_F_FW_INIT;
		cv_signal(&sc->sc_fw_cv);
	}

	/* re-enable interrupts */
	WPI_WRITE(sc, WPI_MASK, WPI_INTR_MASK);
	mutex_exit(&sc->sc_glock);

	return (DDI_INTR_CLAIMED);
}

static uint8_t
wpi_plcp_signal(int rate)
{
	switch (rate) {
	/* CCK rates (returned values are device-dependent) */
	case 2:		return (10);
	case 4:		return (20);
	case 11:	return (55);
	case 22:	return (110);

	/* OFDM rates (cf IEEE Std 802.11a-1999, pp. 14 Table 80) */
	/* R1-R4 (ral/ural is R4-R1) */
	case 12:	return (0xd);
	case 18:	return (0xf);
	case 24:	return (0x5);
	case 36:	return (0x7);
	case 48:	return (0x9);
	case 72:	return (0xb);
	case 96:	return (0x1);
	case 108:	return (0x3);

	/* unsupported rates (should not get there) */
	default:	return (0);
	}
}

static mblk_t *
wpi_m_tx(void *arg, mblk_t *mp)
{
	wpi_sc_t	*sc = (wpi_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	mblk_t			*next;

	if (sc->sc_flags & WPI_F_SUSPEND) {
		freemsgchain(mp);
		return (NULL);
	}

	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (wpi_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != 0) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/* ARGSUSED */
static int
wpi_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	wpi_sc_t *sc = (wpi_sc_t *)ic;
	wpi_tx_ring_t *ring;
	wpi_tx_desc_t *desc;
	wpi_tx_data_t *data;
	wpi_tx_cmd_t *cmd;
	wpi_cmd_data_t *tx;
	ieee80211_node_t *in;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k;
	mblk_t *m, *m0;
	int rate, hdrlen, len, mblen, off, err = WPI_SUCCESS;

	ring = ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA) ?
	    (&sc->sc_txq[0]) : (&sc->sc_txq[1]);
	data = &ring->data[ring->cur];
	desc = data->desc;
	cmd = data->cmd;
	bzero(desc, sizeof (*desc));
	bzero(cmd, sizeof (*cmd));

	mutex_enter(&sc->sc_tx_lock);
	if (sc->sc_flags & WPI_F_SUSPEND) {
		mutex_exit(&sc->sc_tx_lock);
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		err = ENXIO;
		goto exit;
	}

	if (ring->queued > ring->count - 64) {
		WPI_DBG((WPI_DEBUG_TX, "wpi_send(): no txbuf\n"));
		sc->sc_need_reschedule = 1;
		mutex_exit(&sc->sc_tx_lock);
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto exit;
	}
	mutex_exit(&sc->sc_tx_lock);

	hdrlen = sizeof (struct ieee80211_frame);

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) { /* can not alloc buf, drop this package */
		cmn_err(CE_WARN,
		    "wpi_send(): failed to allocate msgbuf\n");
		freemsg(mp);
		err = WPI_SUCCESS;
		goto exit;
	}
	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) memcpy(m->b_rptr + off, m0->b_rptr, mblen);
		off += mblen;
	}
	m->b_wptr += off;
	freemsg(mp);

	wh = (struct ieee80211_frame *)m->b_rptr;

	in = ieee80211_find_txnode(ic, wh->i_addr1);
	if (in == NULL) {
		cmn_err(CE_WARN, "wpi_send(): failed to find tx node\n");
		freemsg(m);
		sc->sc_tx_err++;
		err = WPI_SUCCESS;
		goto exit;
	}

	(void) ieee80211_encap(ic, m, in);

	cmd->code = WPI_CMD_TX_DATA;
	cmd->flags = 0;
	cmd->qid = ring->qid;
	cmd->idx = ring->cur;

	tx = (wpi_cmd_data_t *)cmd->data;
	tx->flags = 0;
	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		tx->flags |= LE_32(WPI_TX_NEED_ACK);
	} else {
		tx->flags &= ~(LE_32(WPI_TX_NEED_ACK));
	}

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			freemsg(m);
			sc->sc_tx_err++;
			err = WPI_SUCCESS;
			goto exit;
		}

		if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_CCM) {
			tx->security = 2; /* for CCMP */
			tx->flags |= LE_32(WPI_TX_NEED_ACK);
			(void) memcpy(&tx->key, k->wk_key, k->wk_keylen);
		}

		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	len = msgdsize(m);

#ifdef DEBUG
	if (wpi_dbg_flags & WPI_DEBUG_TX)
		ieee80211_dump_pkt((uint8_t *)wh, hdrlen, 0, 0);
#endif

	/* pickup a rate */
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
		/* mgmt frames are sent at the lowest available bit-rate */
		rate = 2;
	} else {
		if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
			rate = ic->ic_fixed_rate;
		} else
			rate = in->in_rates.ir_rates[in->in_txrate];
	}
	rate &= IEEE80211_RATE_VAL;
	WPI_DBG((WPI_DEBUG_RATECTL, "tx rate[%d of %d] = %x",
	    in->in_txrate, in->in_rates.ir_nrates, rate));
#ifdef WPI_BPF
#ifndef WPI_CURRENT
	if (sc->sc_drvbpf != NULL) {
#else
	if (bpf_peers_present(sc->sc_drvbpf)) {
#endif
		struct wpi_tx_radiotap_header *tap = &sc->sc_txtap;

		tap->wt_flags = 0;
		tap->wt_chan_freq = LE_16(ic->ic_curchan->ic_freq);
		tap->wt_chan_flags = LE_16(ic->ic_curchan->ic_flags);
		tap->wt_rate = rate;
		if (wh->i_fc[1] & IEEE80211_FC1_WEP)
			tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;

		bpf_mtap2(sc->sc_drvbpf, tap, sc->sc_txtap_len, m0);
	}
#endif

	tx->flags |= (LE_32(WPI_TX_AUTO_SEQ));
	tx->flags |= LE_32(WPI_TX_BT_DISABLE | WPI_TX_CALIBRATION);

	/* retrieve destination node's id */
	tx->id = IEEE80211_IS_MULTICAST(wh->i_addr1) ? WPI_ID_BROADCAST :
	    WPI_ID_BSS;

	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
		/* tell h/w to set timestamp in probe responses */
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			tx->flags |= LE_32(WPI_TX_INSERT_TSTAMP);

		if (((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
		    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_REASSOC_REQ))
			tx->timeout = 3;
		else
			tx->timeout = 2;
	} else
		tx->timeout = 0;

	tx->rate = wpi_plcp_signal(rate);

	/* be very persistant at sending frames out */
	tx->rts_ntries = 7;
	tx->data_ntries = 15;

	tx->cck_mask  = 0x0f;
	tx->ofdm_mask = 0xff;
	tx->lifetime  = LE_32(0xffffffff);

	tx->len = LE_16(len);

	/* save and trim IEEE802.11 header */
	(void) memcpy(tx + 1, m->b_rptr, hdrlen);
	m->b_rptr += hdrlen;
	(void) memcpy(data->dma_data.mem_va, m->b_rptr, len - hdrlen);

	WPI_DBG((WPI_DEBUG_TX, "sending data: qid=%d idx=%d len=%d", ring->qid,
	    ring->cur, len));

	/* first scatter/gather segment is used by the tx data command */
	desc->flags = LE_32(WPI_PAD32(len) << 28 | (2) << 24);
	desc->segs[0].addr = LE_32(data->paddr_cmd);
	desc->segs[0].len  = LE_32(
	    roundup(4 + sizeof (wpi_cmd_data_t) + hdrlen, 4));
	desc->segs[1].addr = LE_32(data->dma_data.cookie.dmac_address);
	desc->segs[1].len  = LE_32(len - hdrlen);

	WPI_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
	WPI_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	mutex_enter(&sc->sc_tx_lock);
	ring->queued++;
	mutex_exit(&sc->sc_tx_lock);

	/* kick ring */
	ring->cur = (ring->cur + 1) % WPI_TX_RING_COUNT;
	WPI_WRITE(sc, WPI_TX_WIDX, ring->qid << 8 | ring->cur);
	freemsg(m);
	/* release node reference */
	ieee80211_free_node(in);

	ic->ic_stats.is_tx_bytes += len;
	ic->ic_stats.is_tx_frags++;

	if (sc->sc_tx_timer == 0)
		sc->sc_tx_timer = 5;
exit:
	return (err);
}

static void
wpi_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	wpi_sc_t	*sc  = (wpi_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	int		err;

	err = ieee80211_ioctl(ic, wq, mp);
	if (err == ENETRESET) {
		/*
		 * This is special for the hidden AP connection.
		 * In any case, we should make sure only one 'scan'
		 * in the driver for a 'connect' CLI command. So
		 * when connecting to a hidden AP, the scan is just
		 * sent out to the air when we know the desired
		 * essid of the AP we want to connect.
		 */
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & WPI_F_RUNNING) {
				wpi_m_stop(sc);
				(void) wpi_m_start(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
	}
}

/*
 * Callback functions for get/set properties
 */
/* ARGSUSED */
static int
wpi_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_name,
    uint_t pr_flags, uint_t wldp_length, void *wldp_buf, uint_t *perm)
{
	int		err = 0;
	wpi_sc_t	*sc = (wpi_sc_t *)arg;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_name,
	    pr_flags, wldp_length, wldp_buf, perm);

	return (err);
}
static int
wpi_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_name,
    uint_t wldp_length, const void *wldp_buf)
{
	int		err;
	wpi_sc_t	*sc = (wpi_sc_t *)arg;
	ieee80211com_t  *ic = &sc->sc_ic;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_name,
	    wldp_length, wldp_buf);

	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & WPI_F_RUNNING) {
				wpi_m_stop(sc);
				(void) wpi_m_start(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}

		err = 0;
	}

	return (err);
}

/*ARGSUSED*/
static int
wpi_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	wpi_sc_t	*sc  = (wpi_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	ieee80211_node_t *in;

	mutex_enter(&sc->sc_glock);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		in = ic->ic_bss;
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    IEEE80211_RATE(in->in_txrate) :
		    ic->ic_fixed_rate) / 2 * 1000000;
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
		mutex_exit(&sc->sc_glock);
		return (ieee80211_stat(ic, stat, val));
	default:
		mutex_exit(&sc->sc_glock);
		return (ENOTSUP);
	}
	mutex_exit(&sc->sc_glock);

	return (WPI_SUCCESS);

}

static int
wpi_m_start(void *arg)
{
	wpi_sc_t *sc = (wpi_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	int err;

	err = wpi_init(sc);
	if (err != WPI_SUCCESS) {
		wpi_stop(sc);
		DELAY(1000000);
		err = wpi_init(sc);
	}

	if (err) {
		/*
		 * The hw init err(eg. RF is OFF). Return Success to make
		 * the 'plumb' succeed. The wpi_thread() tries to re-init
		 * background.
		 */
		mutex_enter(&sc->sc_glock);
		sc->sc_flags |= WPI_F_HW_ERR_RECOVER;
		mutex_exit(&sc->sc_glock);
		return (WPI_SUCCESS);
	}
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	mutex_enter(&sc->sc_glock);
	sc->sc_flags |= WPI_F_RUNNING;
	mutex_exit(&sc->sc_glock);

	return (WPI_SUCCESS);
}

static void
wpi_m_stop(void *arg)
{
	wpi_sc_t *sc = (wpi_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;

	wpi_stop(sc);
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	mutex_enter(&sc->sc_mt_lock);
	sc->sc_flags &= ~WPI_F_HW_ERR_RECOVER;
	sc->sc_flags &= ~WPI_F_RATE_AUTO_CTL;
	mutex_exit(&sc->sc_mt_lock);
	mutex_enter(&sc->sc_glock);
	sc->sc_flags &= ~WPI_F_RUNNING;
	mutex_exit(&sc->sc_glock);
}

/*ARGSUSED*/
static int
wpi_m_unicst(void *arg, const uint8_t *macaddr)
{
	wpi_sc_t *sc = (wpi_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	int err;

	if (!IEEE80211_ADDR_EQ(ic->ic_macaddr, macaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
		mutex_enter(&sc->sc_glock);
		err = wpi_config(sc);
		mutex_exit(&sc->sc_glock);
		if (err != WPI_SUCCESS) {
			cmn_err(CE_WARN,
			    "wpi_m_unicst(): "
			    "failed to configure device\n");
			goto fail;
		}
	}
	return (WPI_SUCCESS);
fail:
	return (err);
}

/*ARGSUSED*/
static int
wpi_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	return (WPI_SUCCESS);
}

/*ARGSUSED*/
static int
wpi_m_promisc(void *arg, boolean_t on)
{
	return (WPI_SUCCESS);
}

static void
wpi_thread(wpi_sc_t *sc)
{
	ieee80211com_t	*ic = &sc->sc_ic;
	clock_t clk;
	int times = 0, err, n = 0, timeout = 0;
	uint32_t tmp;

	mutex_enter(&sc->sc_mt_lock);
	while (sc->sc_mf_thread_switch) {
		tmp = WPI_READ(sc, WPI_GPIO_CTL);
		if (tmp & WPI_GPIO_HW_RF_KILL) {
			sc->sc_flags &= ~WPI_F_RADIO_OFF;
		} else {
			sc->sc_flags |= WPI_F_RADIO_OFF;
		}
		/*
		 * If in SUSPEND or the RF is OFF, do nothing
		 */
		if ((sc->sc_flags & WPI_F_SUSPEND) ||
		    (sc->sc_flags & WPI_F_RADIO_OFF)) {
			mutex_exit(&sc->sc_mt_lock);
			delay(drv_usectohz(100000));
			mutex_enter(&sc->sc_mt_lock);
			continue;
		}

		/*
		 * recovery fatal error
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & WPI_F_HW_ERR_RECOVER)) {

			WPI_DBG((WPI_DEBUG_FW,
			    "wpi_thread(): "
			    "try to recover fatal hw error: %d\n", times++));

			wpi_stop(sc);
			mutex_exit(&sc->sc_mt_lock);

			ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
			delay(drv_usectohz(2000000));

			mutex_enter(&sc->sc_mt_lock);
			err = wpi_init(sc);
			if (err != WPI_SUCCESS) {
				n++;
				if (n < 3)
					continue;
			}
			n = 0;
			if (!err)
				sc->sc_flags |= WPI_F_RUNNING;
			sc->sc_flags &= ~WPI_F_HW_ERR_RECOVER;
			mutex_exit(&sc->sc_mt_lock);
			delay(drv_usectohz(2000000));
			if (sc->sc_ostate != IEEE80211_S_INIT)
				ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
			mutex_enter(&sc->sc_mt_lock);
		}

		/*
		 * scan next channel
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & WPI_F_SCANNING) && sc->sc_scan_next) {

			WPI_DBG((WPI_DEBUG_SCAN,
			    "wpi_thread(): "
			    "wait for probe response\n"));

			sc->sc_scan_next--;
			mutex_exit(&sc->sc_mt_lock);
			delay(drv_usectohz(200000));
			ieee80211_next_scan(ic);
			mutex_enter(&sc->sc_mt_lock);
		}

		/*
		 * rate ctl
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & WPI_F_RATE_AUTO_CTL)) {
			clk = ddi_get_lbolt();
			if (clk > sc->sc_clk + drv_usectohz(500000)) {
				wpi_amrr_timeout(sc);
			}
		}
		mutex_exit(&sc->sc_mt_lock);
		delay(drv_usectohz(100000));
		mutex_enter(&sc->sc_mt_lock);
		if (sc->sc_tx_timer) {
			timeout++;
			if (timeout == 10) {
				sc->sc_tx_timer--;
				if (sc->sc_tx_timer == 0) {
					sc->sc_flags |= WPI_F_HW_ERR_RECOVER;
					sc->sc_ostate = IEEE80211_S_RUN;
					WPI_DBG((WPI_DEBUG_FW,
					    "wpi_thread(): send fail\n"));
				}
				timeout = 0;
			}
		}
	}
	sc->sc_mf_thread = NULL;
	cv_signal(&sc->sc_mt_cv);
	mutex_exit(&sc->sc_mt_lock);
}

/*
 * Extract various information from EEPROM.
 */
static void
wpi_read_eeprom(wpi_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	uint16_t val;
	int i;

	/* read MAC address */
	val = wpi_read_prom_word(sc, WPI_EEPROM_MAC + 0);
	ic->ic_macaddr[0] = val & 0xff;
	ic->ic_macaddr[1] = val >> 8;
	val = wpi_read_prom_word(sc, WPI_EEPROM_MAC + 1);
	ic->ic_macaddr[2] = val & 0xff;
	ic->ic_macaddr[3] = val >> 8;
	val = wpi_read_prom_word(sc, WPI_EEPROM_MAC + 2);
	ic->ic_macaddr[4] = val & 0xff;
	ic->ic_macaddr[5] = val >> 8;

	WPI_DBG((WPI_DEBUG_EEPROM,
	    "mac:%2x:%2x:%2x:%2x:%2x:%2x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1],
	    ic->ic_macaddr[2], ic->ic_macaddr[3],
	    ic->ic_macaddr[4], ic->ic_macaddr[5]));
	/* read power settings for 2.4GHz channels */
	for (i = 0; i < 14; i++) {
		sc->sc_pwr1[i] = wpi_read_prom_word(sc, WPI_EEPROM_PWR1 + i);
		sc->sc_pwr2[i] = wpi_read_prom_word(sc, WPI_EEPROM_PWR2 + i);
		WPI_DBG((WPI_DEBUG_EEPROM,
		    "channel %d pwr1 0x%04x pwr2 0x%04x\n", i + 1,
		    sc->sc_pwr1[i], sc->sc_pwr2[i]));
	}
}

/*
 * Send a command to the firmware.
 */
static int
wpi_cmd(wpi_sc_t *sc, int code, const void *buf, int size, int async)
{
	wpi_tx_ring_t *ring = &sc->sc_cmdq;
	wpi_tx_desc_t *desc;
	wpi_tx_cmd_t *cmd;

	ASSERT(size <= sizeof (cmd->data));
	ASSERT(mutex_owned(&sc->sc_glock));

	WPI_DBG((WPI_DEBUG_CMD, "wpi_cmd() # code[%d]", code));
	desc = ring->data[ring->cur].desc;
	cmd = ring->data[ring->cur].cmd;

	cmd->code = (uint8_t)code;
	cmd->flags = 0;
	cmd->qid = ring->qid;
	cmd->idx = ring->cur;
	(void) memcpy(cmd->data, buf, size);

	desc->flags = LE_32(WPI_PAD32(size) << 28 | 1 << 24);
	desc->segs[0].addr = ring->data[ring->cur].paddr_cmd;
	desc->segs[0].len  = 4 + size;

	/* kick cmd ring */
	ring->cur = (ring->cur + 1) % WPI_CMD_RING_COUNT;
	WPI_WRITE(sc, WPI_TX_WIDX, ring->qid << 8 | ring->cur);

	if (async)
		return (WPI_SUCCESS);
	else {
		clock_t clk;
		sc->sc_flags &= ~WPI_F_CMD_DONE;
		clk = ddi_get_lbolt() + drv_usectohz(2000000);
		while (!(sc->sc_flags & WPI_F_CMD_DONE)) {
			if (cv_timedwait(&sc->sc_cmd_cv, &sc->sc_glock, clk)
			    < 0)
				break;
		}
		if (sc->sc_flags & WPI_F_CMD_DONE)
			return (WPI_SUCCESS);
		else
			return (WPI_FAIL);
	}
}

/*
 * Configure h/w multi-rate retries.
 */
static int
wpi_mrr_setup(wpi_sc_t *sc)
{
	wpi_mrr_setup_t mrr;
	int i, err;

	/* CCK rates (not used with 802.11a) */
	for (i = WPI_CCK1; i <= WPI_CCK11; i++) {
		mrr.rates[i].flags = 0;
		mrr.rates[i].signal = wpi_ridx_to_signal[i];
		/* fallback to the immediate lower CCK rate (if any) */
		mrr.rates[i].next = (i == WPI_CCK1) ? WPI_CCK1 : i - 1;
		/* try one time at this rate before falling back to "next" */
		mrr.rates[i].ntries = 1;
	}

	/* OFDM rates (not used with 802.11b) */
	for (i = WPI_OFDM6; i <= WPI_OFDM54; i++) {
		mrr.rates[i].flags = 0;
		mrr.rates[i].signal = wpi_ridx_to_signal[i];
		/* fallback to the immediate lower OFDM rate (if any) */
		mrr.rates[i].next = (i == WPI_OFDM6) ? WPI_OFDM6 : i - 1;
		/* try one time at this rate before falling back to "next" */
		mrr.rates[i].ntries = 1;
	}

	/* setup MRR for control frames */
	mrr.which = LE_32(WPI_MRR_CTL);
	err = wpi_cmd(sc, WPI_CMD_MRR_SETUP, &mrr, sizeof (mrr), 1);
	if (err != WPI_SUCCESS) {
		WPI_DBG((WPI_DEBUG_MRR,
		    "could not setup MRR for control frames\n"));
		return (err);
	}

	/* setup MRR for data frames */
	mrr.which = LE_32(WPI_MRR_DATA);
	err = wpi_cmd(sc, WPI_CMD_MRR_SETUP, &mrr, sizeof (mrr), 1);
	if (err != WPI_SUCCESS) {
		WPI_DBG((WPI_DEBUG_MRR,
		    "could not setup MRR for data frames\n"));
		return (err);
	}

	return (WPI_SUCCESS);
}

static void
wpi_set_led(wpi_sc_t *sc, uint8_t which, uint8_t off, uint8_t on)
{
	wpi_cmd_led_t led;

	led.which = which;
	led.unit = LE_32(100000);	/* on/off in unit of 100ms */
	led.off = off;
	led.on = on;

	(void) wpi_cmd(sc, WPI_CMD_SET_LED, &led, sizeof (led), 1);
}

static int
wpi_auth(wpi_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	wpi_node_t node;
	int err;

	/* update adapter's configuration */
	IEEE80211_ADDR_COPY(sc->sc_config.bssid, in->in_bssid);
	sc->sc_config.chan = ieee80211_chan2ieee(ic, in->in_chan);
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		sc->sc_config.cck_mask  = 0x03;
		sc->sc_config.ofdm_mask = 0;
	} else if ((in->in_chan != IEEE80211_CHAN_ANYC) &&
	    (IEEE80211_IS_CHAN_5GHZ(in->in_chan))) {
		sc->sc_config.cck_mask  = 0;
		sc->sc_config.ofdm_mask = 0x15;
	} else {	/* assume 802.11b/g */
		sc->sc_config.cck_mask  = 0x0f;
		sc->sc_config.ofdm_mask = 0xff;
	}

	WPI_DBG((WPI_DEBUG_80211, "config chan %d flags %x cck %x ofdm %x"
	    " bssid:%02x:%02x:%02x:%02x:%02x:%2x\n",
	    sc->sc_config.chan, sc->sc_config.flags,
	    sc->sc_config.cck_mask, sc->sc_config.ofdm_mask,
	    sc->sc_config.bssid[0], sc->sc_config.bssid[1],
	    sc->sc_config.bssid[2], sc->sc_config.bssid[3],
	    sc->sc_config.bssid[4], sc->sc_config.bssid[5]));
	err = wpi_cmd(sc, WPI_CMD_CONFIGURE, &sc->sc_config,
	    sizeof (wpi_config_t), 1);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_auth(): failed to configurate chan%d\n",
		    sc->sc_config.chan);
		return (err);
	}

	/* add default node */
	(void) memset(&node, 0, sizeof (node));
	IEEE80211_ADDR_COPY(node.bssid, in->in_bssid);
	node.id = WPI_ID_BSS;
	node.rate = wpi_plcp_signal(2);
	err = wpi_cmd(sc, WPI_CMD_ADD_NODE, &node, sizeof (node), 1);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_auth(): failed to add BSS node\n");
		return (err);
	}

	err = wpi_mrr_setup(sc);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_auth(): failed to setup MRR\n");
		return (err);
	}

	return (WPI_SUCCESS);
}

/*
 * Send a scan request to the firmware.
 */
static int
wpi_scan(wpi_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	wpi_tx_ring_t *ring = &sc->sc_cmdq;
	wpi_tx_desc_t *desc;
	wpi_tx_data_t *data;
	wpi_tx_cmd_t *cmd;
	wpi_scan_hdr_t *hdr;
	wpi_scan_chan_t *chan;
	struct ieee80211_frame *wh;
	ieee80211_node_t *in = ic->ic_bss;
	uint8_t essid[IEEE80211_NWID_LEN+1];
	struct ieee80211_rateset *rs;
	enum ieee80211_phymode mode;
	uint8_t *frm;
	int i, pktlen, nrates;

	/* previous scan not completed */
	if (sc->sc_scan_pending) {
		WPI_DBG((WPI_DEBUG_SCAN, "previous scan not completed\n"));
		return (WPI_SUCCESS);
	}

	data = &ring->data[ring->cur];
	desc = data->desc;
	cmd = (wpi_tx_cmd_t *)data->dma_data.mem_va;

	cmd->code = WPI_CMD_SCAN;
	cmd->flags = 0;
	cmd->qid = ring->qid;
	cmd->idx = ring->cur;

	hdr = (wpi_scan_hdr_t *)cmd->data;
	(void) memset(hdr, 0, sizeof (wpi_scan_hdr_t));
	hdr->first = 1;
	hdr->nchan = 1;
	hdr->len = hdr->nchan * sizeof (wpi_scan_chan_t);
	hdr->quiet = LE_16(50);
	hdr->threshold = LE_16(1);
	hdr->filter = LE_32(5);
	hdr->rate = wpi_plcp_signal(2);
	hdr->id = WPI_ID_BROADCAST;
	hdr->mask = LE_32(0xffffffff);
	hdr->esslen = ic->ic_des_esslen;

	if (ic->ic_des_esslen) {
		bcopy(ic->ic_des_essid, essid, ic->ic_des_esslen);
		essid[ic->ic_des_esslen] = '\0';
		WPI_DBG((WPI_DEBUG_SCAN, "directed scan %s\n", essid));

		bcopy(ic->ic_des_essid, hdr->essid, ic->ic_des_esslen);
	} else {
		bzero(hdr->essid, sizeof (hdr->essid));
	}

	/*
	 * Build a probe request frame.  Most of the following code is a
	 * copy & paste of what is done in net80211.  Unfortunately, the
	 * functions to add IEs are static and thus can't be reused here.
	 */
	wh = (struct ieee80211_frame *)(hdr + 1);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    IEEE80211_FC0_SUBTYPE_PROBE_REQ;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	(void) memset(wh->i_addr1, 0xff, 6);
	IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_macaddr);
	(void) memset(wh->i_addr3, 0xff, 6);
	*(uint16_t *)&wh->i_dur[0] = 0;	/* filled by h/w */
	*(uint16_t *)&wh->i_seq[0] = 0;	/* filled by h/w */

	frm = (uint8_t *)(wh + 1);

	/* add essid IE */
	if (in->in_esslen) {
		bcopy(in->in_essid, essid, in->in_esslen);
		essid[in->in_esslen] = '\0';
		WPI_DBG((WPI_DEBUG_SCAN, "probe with ESSID %s\n",
		    essid));
	}
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = in->in_esslen;
	(void) memcpy(frm, in->in_essid, in->in_esslen);
	frm += in->in_esslen;

	mode = ieee80211_chan2mode(ic, ic->ic_curchan);
	rs = &ic->ic_sup_rates[mode];

	/* add supported rates IE */
	*frm++ = IEEE80211_ELEMID_RATES;
	nrates = rs->ir_nrates;
	if (nrates > IEEE80211_RATE_SIZE)
		nrates = IEEE80211_RATE_SIZE;
	*frm++ = (uint8_t)nrates;
	(void) memcpy(frm, rs->ir_rates, nrates);
	frm += nrates;

	/* add supported xrates IE */
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;
		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = (uint8_t)nrates;
		(void) memcpy(frm, rs->ir_rates + IEEE80211_RATE_SIZE, nrates);
		frm += nrates;
	}

	/* add optionnal IE (usually an RSN IE) */
	if (ic->ic_opt_ie != NULL) {
		(void) memcpy(frm, ic->ic_opt_ie, ic->ic_opt_ie_len);
		frm += ic->ic_opt_ie_len;
	}

	/* setup length of probe request */
	hdr->pbrlen = LE_16((uintptr_t)frm - (uintptr_t)wh);

	/* align on a 4-byte boundary */
	chan = (wpi_scan_chan_t *)frm;
	for (i = 1; i <= hdr->nchan; i++, chan++) {
		if (ic->ic_des_esslen) {
			chan->flags = 0x3;
		} else {
			chan->flags = 0x1;
		}
		chan->chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
		chan->magic = LE_16(0x62ab);
		chan->active = LE_16(50);
		chan->passive = LE_16(120);

		frm += sizeof (wpi_scan_chan_t);
	}

	pktlen = (uintptr_t)frm - (uintptr_t)cmd;

	desc->flags = LE_32(WPI_PAD32(pktlen) << 28 | 1 << 24);
	desc->segs[0].addr = LE_32(data->dma_data.cookie.dmac_address);
	desc->segs[0].len  = LE_32(pktlen);

	WPI_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
	WPI_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	/* kick cmd ring */
	ring->cur = (ring->cur + 1) % WPI_CMD_RING_COUNT;
	WPI_WRITE(sc, WPI_TX_WIDX, ring->qid << 8 | ring->cur);

	sc->sc_scan_pending = 1;

	return (WPI_SUCCESS);	/* will be notified async. of failure/success */
}

static int
wpi_config(wpi_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	wpi_txpower_t txpower;
	wpi_power_t power;
#ifdef WPI_BLUE_COEXISTENCE
	wpi_bluetooth_t bluetooth;
#endif
	wpi_node_t node;
	int err;

	/* Intel's binary only daemon is a joke.. */

	/* set Tx power for 2.4GHz channels (values read from EEPROM) */
	(void) memset(&txpower, 0, sizeof (txpower));
	(void) memcpy(txpower.pwr1, sc->sc_pwr1, 14 * sizeof (uint16_t));
	(void) memcpy(txpower.pwr2, sc->sc_pwr2, 14 * sizeof (uint16_t));
	err = wpi_cmd(sc, WPI_CMD_TXPOWER, &txpower, sizeof (txpower), 0);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_config(): failed to set txpower\n");
		return (err);
	}

	/* set power mode */
	(void) memset(&power, 0, sizeof (power));
	power.flags = LE_32(0x8);
	err = wpi_cmd(sc, WPI_CMD_SET_POWER_MODE, &power, sizeof (power), 0);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_config(): failed to set power mode\n");
		return (err);
	}
#ifdef WPI_BLUE_COEXISTENCE
	/* configure bluetooth coexistence */
	(void) memset(&bluetooth, 0, sizeof (bluetooth));
	bluetooth.flags = 3;
	bluetooth.lead = 0xaa;
	bluetooth.kill = 1;
	err = wpi_cmd(sc, WPI_CMD_BLUETOOTH, &bluetooth,
	    sizeof (bluetooth), 0);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN,
		    "wpi_config(): "
		    "failed to configurate bluetooth coexistence\n");
		return (err);
	}
#endif
	/* configure adapter */
	(void) memset(&sc->sc_config, 0, sizeof (wpi_config_t));
	IEEE80211_ADDR_COPY(sc->sc_config.myaddr, ic->ic_macaddr);
	sc->sc_config.chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
	sc->sc_config.flags = LE_32(WPI_CONFIG_TSF | WPI_CONFIG_AUTO |
	    WPI_CONFIG_24GHZ);
	sc->sc_config.filter = 0;
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		sc->sc_config.mode = WPI_MODE_STA;
		sc->sc_config.filter |= LE_32(WPI_FILTER_MULTICAST);
		break;
	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		sc->sc_config.mode = WPI_MODE_IBSS;
		break;
	case IEEE80211_M_HOSTAP:
		sc->sc_config.mode = WPI_MODE_HOSTAP;
		break;
	case IEEE80211_M_MONITOR:
		sc->sc_config.mode = WPI_MODE_MONITOR;
		sc->sc_config.filter |= LE_32(WPI_FILTER_MULTICAST |
		    WPI_FILTER_CTL | WPI_FILTER_PROMISC);
		break;
	}
	sc->sc_config.cck_mask  = 0x0f;	/* not yet negotiated */
	sc->sc_config.ofdm_mask = 0xff;	/* not yet negotiated */
	err = wpi_cmd(sc, WPI_CMD_CONFIGURE, &sc->sc_config,
	    sizeof (wpi_config_t), 0);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_config(): "
		    "failed to set configure command\n");
		return (err);
	}

	/* add broadcast node */
	(void) memset(&node, 0, sizeof (node));
	(void) memset(node.bssid, 0xff, 6);
	node.id = WPI_ID_BROADCAST;
	node.rate = wpi_plcp_signal(2);
	err = wpi_cmd(sc, WPI_CMD_ADD_NODE, &node, sizeof (node), 0);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_config(): "
		    "failed to add broadcast node\n");
		return (err);
	}

	return (WPI_SUCCESS);
}

static void
wpi_stop_master(wpi_sc_t *sc)
{
	uint32_t tmp;
	int ntries;

	tmp = WPI_READ(sc, WPI_RESET);
	WPI_WRITE(sc, WPI_RESET, tmp | WPI_STOP_MASTER);

	tmp = WPI_READ(sc, WPI_GPIO_CTL);
	if ((tmp & WPI_GPIO_PWR_STATUS) == WPI_GPIO_PWR_SLEEP)
		return;	/* already asleep */

	for (ntries = 0; ntries < 2000; ntries++) {
		if (WPI_READ(sc, WPI_RESET) & WPI_MASTER_DISABLED)
			break;
		DELAY(1000);
	}
	if (ntries == 2000)
		WPI_DBG((WPI_DEBUG_HW, "timeout waiting for master\n"));
}

static int
wpi_power_up(wpi_sc_t *sc)
{
	uint32_t tmp;
	int ntries;

	wpi_mem_lock(sc);
	tmp = wpi_mem_read(sc, WPI_MEM_POWER);
	wpi_mem_write(sc, WPI_MEM_POWER, tmp & ~0x03000000);
	wpi_mem_unlock(sc);

	for (ntries = 0; ntries < 5000; ntries++) {
		if (WPI_READ(sc, WPI_GPIO_STATUS) & WPI_POWERED)
			break;
		DELAY(10);
	}
	if (ntries == 5000) {
		cmn_err(CE_WARN,
		    "wpi_power_up(): timeout waiting for NIC to power up\n");
		return (ETIMEDOUT);
	}
	return (WPI_SUCCESS);
}

static int
wpi_reset(wpi_sc_t *sc)
{
	uint32_t tmp;
	int ntries;

	/* clear any pending interrupts */
	WPI_WRITE(sc, WPI_INTR, 0xffffffff);

	tmp = WPI_READ(sc, WPI_PLL_CTL);
	WPI_WRITE(sc, WPI_PLL_CTL, tmp | WPI_PLL_INIT);

	tmp = WPI_READ(sc, WPI_CHICKEN);
	WPI_WRITE(sc, WPI_CHICKEN, tmp | WPI_CHICKEN_RXNOLOS);

	tmp = WPI_READ(sc, WPI_GPIO_CTL);
	WPI_WRITE(sc, WPI_GPIO_CTL, tmp | WPI_GPIO_INIT);

	/* wait for clock stabilization */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (WPI_READ(sc, WPI_GPIO_CTL) & WPI_GPIO_CLOCK)
			break;
		DELAY(10);
	}
	if (ntries == 1000) {
		cmn_err(CE_WARN,
		    "wpi_reset(): timeout waiting for clock stabilization\n");
		return (ETIMEDOUT);
	}

	/* initialize EEPROM */
	tmp = WPI_READ(sc, WPI_EEPROM_STATUS);
	if ((tmp & WPI_EEPROM_VERSION) == 0) {
		cmn_err(CE_WARN, "wpi_reset(): EEPROM not found\n");
		return (EIO);
	}
	WPI_WRITE(sc, WPI_EEPROM_STATUS, tmp & ~WPI_EEPROM_LOCKED);

	return (WPI_SUCCESS);
}

static void
wpi_hw_config(wpi_sc_t *sc)
{
	uint16_t val;
	uint32_t hw;

	/* voodoo from the Linux "driver".. */
	hw = WPI_READ(sc, WPI_HWCONFIG);

	if ((sc->sc_rev & 0xc0) == 0x40)
		hw |= WPI_HW_ALM_MB;
	else if (!(sc->sc_rev & 0x80))
		hw |= WPI_HW_ALM_MM;

	val = wpi_read_prom_word(sc, WPI_EEPROM_CAPABILITIES);
	if ((val & 0xff) == 0x80)
		hw |= WPI_HW_SKU_MRC;

	val = wpi_read_prom_word(sc, WPI_EEPROM_REVISION);
	hw &= ~WPI_HW_REV_D;
	if ((val & 0xf0) == 0xd0)
		hw |= WPI_HW_REV_D;

	val = wpi_read_prom_word(sc, WPI_EEPROM_TYPE);
	if ((val & 0xff) > 1)
		hw |= WPI_HW_TYPE_B;

	WPI_DBG((WPI_DEBUG_HW, "setting h/w config %x\n", hw));
	WPI_WRITE(sc, WPI_HWCONFIG, hw);
}

static int
wpi_init(wpi_sc_t *sc)
{
	uint32_t tmp;
	int qid, ntries, err;
	clock_t clk;

	mutex_enter(&sc->sc_glock);
	sc->sc_flags &= ~WPI_F_FW_INIT;

	(void) wpi_reset(sc);

	wpi_mem_lock(sc);
	wpi_mem_write(sc, WPI_MEM_CLOCK1, 0xa00);
	DELAY(20);
	tmp = wpi_mem_read(sc, WPI_MEM_PCIDEV);
	wpi_mem_write(sc, WPI_MEM_PCIDEV, tmp | 0x800);
	wpi_mem_unlock(sc);

	(void) wpi_power_up(sc);
	wpi_hw_config(sc);

	tmp = WPI_READ(sc, WPI_GPIO_CTL);
	if (!(tmp & WPI_GPIO_HW_RF_KILL)) {
		cmn_err(CE_WARN, "wpi_init(): Radio transmitter is off\n");
		goto fail1;
	}

	/* init Rx ring */
	wpi_mem_lock(sc);
	WPI_WRITE(sc, WPI_RX_BASE, sc->sc_rxq.dma_desc.cookie.dmac_address);
	WPI_WRITE(sc, WPI_RX_RIDX_PTR,
	    (uint32_t)(sc->sc_dma_sh.cookie.dmac_address +
	    offsetof(wpi_shared_t, next)));
	WPI_WRITE(sc, WPI_RX_WIDX, (WPI_RX_RING_COUNT - 1) & (~7));
	WPI_WRITE(sc, WPI_RX_CONFIG, 0xa9601010);
	wpi_mem_unlock(sc);

	/* init Tx rings */
	wpi_mem_lock(sc);
	wpi_mem_write(sc, WPI_MEM_MODE, 2);	/* bypass mode */
	wpi_mem_write(sc, WPI_MEM_RA, 1);	/* enable RA0 */
	wpi_mem_write(sc, WPI_MEM_TXCFG, 0x3f);	/* enable all 6 Tx rings */
	wpi_mem_write(sc, WPI_MEM_BYPASS1, 0x10000);
	wpi_mem_write(sc, WPI_MEM_BYPASS2, 0x30002);
	wpi_mem_write(sc, WPI_MEM_MAGIC4, 4);
	wpi_mem_write(sc, WPI_MEM_MAGIC5, 5);

	WPI_WRITE(sc, WPI_TX_BASE_PTR, sc->sc_dma_sh.cookie.dmac_address);
	WPI_WRITE(sc, WPI_MSG_CONFIG, 0xffff05a5);

	for (qid = 0; qid < 6; qid++) {
		WPI_WRITE(sc, WPI_TX_CTL(qid), 0);
		WPI_WRITE(sc, WPI_TX_BASE(qid), 0);
		WPI_WRITE(sc, WPI_TX_CONFIG(qid), 0x80200008);
	}
	wpi_mem_unlock(sc);

	/* clear "radio off" and "disable command" bits (reversed logic) */
	WPI_WRITE(sc, WPI_UCODE_CLR, WPI_RADIO_OFF);
	WPI_WRITE(sc, WPI_UCODE_CLR, WPI_DISABLE_CMD);

	/* clear any pending interrupts */
	WPI_WRITE(sc, WPI_INTR, 0xffffffff);

	/* enable interrupts */
	WPI_WRITE(sc, WPI_MASK, WPI_INTR_MASK);

	/* load firmware boot code into NIC */
	err = wpi_load_microcode(sc);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_init(): failed to load microcode\n");
		goto fail1;
	}

	/* load firmware .text segment into NIC */
	err = wpi_load_firmware(sc, WPI_FW_TEXT);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_init(): "
		    "failed to load firmware(text)\n");
		goto fail1;
	}

	/* load firmware .data segment into NIC */
	err = wpi_load_firmware(sc, WPI_FW_DATA);
	if (err != WPI_SUCCESS) {
		cmn_err(CE_WARN, "wpi_init(): "
		    "failed to load firmware(data)\n");
		goto fail1;
	}

	/* now press "execute" ;-) */
	tmp = WPI_READ(sc, WPI_RESET);
	tmp &= ~(WPI_MASTER_DISABLED | WPI_STOP_MASTER | WPI_NEVO_RESET);
	WPI_WRITE(sc, WPI_RESET, tmp);

	/* ..and wait at most one second for adapter to initialize */
	clk = ddi_get_lbolt() + drv_usectohz(2000000);
	while (!(sc->sc_flags & WPI_F_FW_INIT)) {
		if (cv_timedwait(&sc->sc_fw_cv, &sc->sc_glock, clk) < 0)
			break;
	}
	if (!(sc->sc_flags & WPI_F_FW_INIT)) {
		cmn_err(CE_WARN,
		    "wpi_init(): timeout waiting for firmware init\n");
		goto fail1;
	}

	/* wait for thermal sensors to calibrate */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (WPI_READ(sc, WPI_TEMPERATURE) != 0)
			break;
		DELAY(10);
	}

	if (ntries == 1000) {
		WPI_DBG((WPI_DEBUG_HW,
		    "wpi_init(): timeout waiting for thermal sensors "
		    "calibration\n"));
	}

	WPI_DBG((WPI_DEBUG_HW, "temperature %d\n",
	    (int)WPI_READ(sc, WPI_TEMPERATURE)));

	err = wpi_config(sc);
	if (err) {
		cmn_err(CE_WARN, "wpi_init(): failed to configure device\n");
		goto fail1;
	}

	mutex_exit(&sc->sc_glock);
	return (WPI_SUCCESS);

fail1:
	err = WPI_FAIL;
	mutex_exit(&sc->sc_glock);
	return (err);
}

/*
 * quiesce(9E) entry point.
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
wpi_quiesce(dev_info_t *dip)
{
	wpi_sc_t *sc;

	sc = ddi_get_soft_state(wpi_soft_state_p, ddi_get_instance(dip));
	if (sc == NULL)
		return (DDI_FAILURE);

#ifdef DEBUG
	/* by pass any messages, if it's quiesce */
	wpi_dbg_flags = 0;
#endif

	/*
	 * No more blocking is allowed while we are in the
	 * quiesce(9E) entry point.
	 */
	sc->sc_flags |= WPI_F_QUIESCED;

	/*
	 * Disable and mask all interrupts.
	 */
	wpi_stop(sc);
	return (DDI_SUCCESS);
}

static void
wpi_stop(wpi_sc_t *sc)
{
	uint32_t tmp;
	int ac;

	/* no mutex operation, if it's quiesced */
	if (!(sc->sc_flags & WPI_F_QUIESCED))
		mutex_enter(&sc->sc_glock);

	/* disable interrupts */
	WPI_WRITE(sc, WPI_MASK, 0);
	WPI_WRITE(sc, WPI_INTR, WPI_INTR_MASK);
	WPI_WRITE(sc, WPI_INTR_STATUS, 0xff);
	WPI_WRITE(sc, WPI_INTR_STATUS, 0x00070000);

	wpi_mem_lock(sc);
	wpi_mem_write(sc, WPI_MEM_MODE, 0);
	wpi_mem_unlock(sc);

	/* reset all Tx rings */
	for (ac = 0; ac < 4; ac++)
		wpi_reset_tx_ring(sc, &sc->sc_txq[ac]);
	wpi_reset_tx_ring(sc, &sc->sc_cmdq);
	wpi_reset_tx_ring(sc, &sc->sc_svcq);

	/* reset Rx ring */
	wpi_reset_rx_ring(sc);

	wpi_mem_lock(sc);
	wpi_mem_write(sc, WPI_MEM_CLOCK2, 0x200);
	wpi_mem_unlock(sc);

	DELAY(5);

	wpi_stop_master(sc);

	sc->sc_tx_timer = 0;
	sc->sc_flags &= ~WPI_F_SCANNING;
	sc->sc_scan_pending = 0;
	sc->sc_scan_next = 0;

	tmp = WPI_READ(sc, WPI_RESET);
	WPI_WRITE(sc, WPI_RESET, tmp | WPI_SW_RESET);

	/* no mutex operation, if it's quiesced */
	if (!(sc->sc_flags & WPI_F_QUIESCED))
		mutex_exit(&sc->sc_glock);
}

/*
 * Naive implementation of the Adaptive Multi Rate Retry algorithm:
 * "IEEE 802.11 Rate Adaptation: A Practical Approach"
 * Mathieu Lacage, Hossein Manshaei, Thierry Turletti
 * INRIA Sophia - Projet Planete
 * http://www-sop.inria.fr/rapports/sophia/RR-5208.html
 */
#define	is_success(amrr)	\
	((amrr)->retrycnt < (amrr)->txcnt / 10)
#define	is_failure(amrr)	\
	((amrr)->retrycnt > (amrr)->txcnt / 3)
#define	is_enough(amrr)		\
	((amrr)->txcnt > 100)
#define	is_min_rate(in)		\
	((in)->in_txrate == 0)
#define	is_max_rate(in)		\
	((in)->in_txrate == (in)->in_rates.ir_nrates - 1)
#define	increase_rate(in)	\
	((in)->in_txrate++)
#define	decrease_rate(in)	\
	((in)->in_txrate--)
#define	reset_cnt(amrr)		\
	{ (amrr)->txcnt = (amrr)->retrycnt = 0; }

#define	WPI_AMRR_MIN_SUCCESS_THRESHOLD	 1
#define	WPI_AMRR_MAX_SUCCESS_THRESHOLD	15

static void
wpi_amrr_init(wpi_amrr_t *amrr)
{
	amrr->success = 0;
	amrr->recovery = 0;
	amrr->txcnt = amrr->retrycnt = 0;
	amrr->success_threshold = WPI_AMRR_MIN_SUCCESS_THRESHOLD;
}

static void
wpi_amrr_timeout(wpi_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	WPI_DBG((WPI_DEBUG_RATECTL, "wpi_amrr_timeout() enter\n"));
	if (ic->ic_opmode == IEEE80211_M_STA)
		wpi_amrr_ratectl(NULL, ic->ic_bss);
	else
		ieee80211_iterate_nodes(&ic->ic_sta, wpi_amrr_ratectl, NULL);
	sc->sc_clk = ddi_get_lbolt();
}

/* ARGSUSED */
static void
wpi_amrr_ratectl(void *arg, ieee80211_node_t *in)
{
	wpi_amrr_t *amrr = (wpi_amrr_t *)in;
	int need_change = 0;

	if (is_success(amrr) && is_enough(amrr)) {
		amrr->success++;
		if (amrr->success >= amrr->success_threshold &&
		    !is_max_rate(in)) {
			amrr->recovery = 1;
			amrr->success = 0;
			increase_rate(in);
			WPI_DBG((WPI_DEBUG_RATECTL,
			    "AMRR increasing rate %d (txcnt=%d retrycnt=%d)\n",
			    in->in_txrate, amrr->txcnt, amrr->retrycnt));
			need_change = 1;
		} else {
			amrr->recovery = 0;
		}
	} else if (is_failure(amrr)) {
		amrr->success = 0;
		if (!is_min_rate(in)) {
			if (amrr->recovery) {
				amrr->success_threshold++;
				if (amrr->success_threshold >
				    WPI_AMRR_MAX_SUCCESS_THRESHOLD)
					amrr->success_threshold =
					    WPI_AMRR_MAX_SUCCESS_THRESHOLD;
			} else {
				amrr->success_threshold =
				    WPI_AMRR_MIN_SUCCESS_THRESHOLD;
			}
			decrease_rate(in);
			WPI_DBG((WPI_DEBUG_RATECTL,
			    "AMRR decreasing rate %d (txcnt=%d retrycnt=%d)\n",
			    in->in_txrate, amrr->txcnt, amrr->retrycnt));
			need_change = 1;
		}
		amrr->recovery = 0;	/* paper is incorrect */
	}

	if (is_enough(amrr) || need_change)
		reset_cnt(amrr);
}
