/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, Intel Corporation
 * All rights reserved.
 */

/*
 * Copyright (c) 2006
 * Copyright (c) 2007
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Driver for Intel PRO/Wireless 4965AGN(kedron) 802.11 network adapters.
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
#include <sys/mac.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/net80211_proto.h>
#include <sys/varargs.h>
#include <sys/policy.h>
#include <sys/pci.h>

#include "iwk_hw.h"
#include "iwk_eeprom.h"
#include "iwk2_var.h"
#include <inet/wifi_ioctl.h>

#ifdef DEBUG
#define	IWK_DEBUG_80211		(1 << 0)
#define	IWK_DEBUG_CMD		(1 << 1)
#define	IWK_DEBUG_DMA		(1 << 2)
#define	IWK_DEBUG_EEPROM	(1 << 3)
#define	IWK_DEBUG_FW		(1 << 4)
#define	IWK_DEBUG_HW		(1 << 5)
#define	IWK_DEBUG_INTR		(1 << 6)
#define	IWK_DEBUG_MRR		(1 << 7)
#define	IWK_DEBUG_PIO		(1 << 8)
#define	IWK_DEBUG_RX		(1 << 9)
#define	IWK_DEBUG_SCAN		(1 << 10)
#define	IWK_DEBUG_TX		(1 << 11)
#define	IWK_DEBUG_RATECTL	(1 << 12)
#define	IWK_DEBUG_RADIO		(1 << 13)
#define	IWK_DEBUG_RESUME	(1 << 14)
uint32_t iwk_dbg_flags = 0;
#define	IWK_DBG(x) \
	iwk_dbg x
#else
#define	IWK_DBG(x)
#endif

static void	*iwk_soft_state_p = NULL;
static uint8_t iwk_fw_bin [] = {
#include "fw-iw/iw4965.ucode.hex"
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

/* DMA attributes for a keep warm DRAM descriptor */
static ddi_dma_attr_t kw_dma_attr = {
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
	0x100,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};

/* DMA attributes for a cmd */
static ddi_dma_attr_t cmd_dma_attr = {
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
	0x100,		/* alignment in bytes */
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
 * descriptor, so we define the maximum  number of segments 1,
 * just the same as the rx_buffer. we consider leverage the HW
 * ability in the future, that is why we don't define rx and tx
 * buffer_dma_attr as the same.
 */
static ddi_dma_attr_t tx_buffer_dma_attr = {
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

/* DMA attributes for text and data part in the firmware */
static ddi_dma_attr_t fw_dma_attr = {
	DMA_ATTR_V0,	/* version of this structure */
	0,		/* lowest usable address */
	0xffffffffU,	/* highest usable address */
	0x7fffffff,	/* maximum DMAable byte count */
	0x10,		/* alignment in bytes */
	0x100,		/* burst sizes (any?) */
	1,		/* minimum transfer */
	0xffffffffU,	/* maximum transfer */
	0xffffffffU,	/* maximum segment length */
	1,		/* maximum number of segments */
	1,		/* granularity */
	0,		/* flags (reserved) */
};


/* regs access attributes */
static ddi_device_acc_attr_t iwk_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/* DMA access attributes */
static ddi_device_acc_attr_t iwk_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static int	iwk_ring_init(iwk_sc_t *);
static void	iwk_ring_free(iwk_sc_t *);
static int	iwk_alloc_shared(iwk_sc_t *);
static void	iwk_free_shared(iwk_sc_t *);
static int	iwk_alloc_kw(iwk_sc_t *);
static void	iwk_free_kw(iwk_sc_t *);
static int	iwk_alloc_fw_dma(iwk_sc_t *);
static void	iwk_free_fw_dma(iwk_sc_t *);
static int	iwk_alloc_rx_ring(iwk_sc_t *);
static void	iwk_reset_rx_ring(iwk_sc_t *);
static void	iwk_free_rx_ring(iwk_sc_t *);
static int	iwk_alloc_tx_ring(iwk_sc_t *, iwk_tx_ring_t *,
    int, int);
static void	iwk_reset_tx_ring(iwk_sc_t *, iwk_tx_ring_t *);
static void	iwk_free_tx_ring(iwk_sc_t *, iwk_tx_ring_t *);

static ieee80211_node_t *iwk_node_alloc(ieee80211com_t *);
static void	iwk_node_free(ieee80211_node_t *);
static int	iwk_newstate(ieee80211com_t *, enum ieee80211_state, int);
static int	iwk_key_set(ieee80211com_t *, const struct ieee80211_key *,
    const uint8_t mac[IEEE80211_ADDR_LEN]);
static void	iwk_mac_access_enter(iwk_sc_t *);
static void	iwk_mac_access_exit(iwk_sc_t *);
static uint32_t	iwk_reg_read(iwk_sc_t *, uint32_t);
static void	iwk_reg_write(iwk_sc_t *, uint32_t, uint32_t);
static void	iwk_reg_write_region_4(iwk_sc_t *, uint32_t,
		    uint32_t *, int);
static int	iwk_load_firmware(iwk_sc_t *);
static void	iwk_rx_intr(iwk_sc_t *, iwk_rx_desc_t *,
		    iwk_rx_data_t *);
static void	iwk_tx_intr(iwk_sc_t *, iwk_rx_desc_t *,
		    iwk_rx_data_t *);
static void	iwk_cmd_intr(iwk_sc_t *, iwk_rx_desc_t *);
static uint_t	iwk_intr(caddr_t);
static int	iwk_eep_load(iwk_sc_t *sc);
static void	iwk_get_mac_from_eep(iwk_sc_t *sc);
static int	iwk_eep_sem_down(iwk_sc_t *sc);
static void	iwk_eep_sem_up(iwk_sc_t *sc);
static uint_t	iwk_rx_softintr(caddr_t);
static uint8_t	iwk_rate_to_plcp(int);
static int	iwk_cmd(iwk_sc_t *, int, const void *, int, int);
static void	iwk_set_led(iwk_sc_t *, uint8_t, uint8_t, uint8_t);
static int	iwk_hw_set_before_auth(iwk_sc_t *);
static int	iwk_scan(iwk_sc_t *);
static int	iwk_config(iwk_sc_t *);
static void	iwk_stop_master(iwk_sc_t *);
static int	iwk_power_up(iwk_sc_t *);
static int	iwk_preinit(iwk_sc_t *);
static int	iwk_init(iwk_sc_t *);
static void	iwk_stop(iwk_sc_t *);
static void	iwk_amrr_init(iwk_amrr_t *);
static void	iwk_amrr_timeout(iwk_sc_t *);
static void	iwk_amrr_ratectl(void *, ieee80211_node_t *);

static int iwk_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int iwk_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * GLD specific operations
 */
static int	iwk_m_stat(void *arg, uint_t stat, uint64_t *val);
static int	iwk_m_start(void *arg);
static void	iwk_m_stop(void *arg);
static int	iwk_m_unicst(void *arg, const uint8_t *macaddr);
static int	iwk_m_multicst(void *arg, boolean_t add, const uint8_t *m);
static int	iwk_m_promisc(void *arg, boolean_t on);
static mblk_t  *iwk_m_tx(void *arg, mblk_t *mp);
static void	iwk_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);

static void	iwk_destroy_locks(iwk_sc_t *sc);
static int	iwk_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type);
static void	iwk_thread(iwk_sc_t *sc);

/*
 * Supported rates for 802.11b/g modes (in 500Kbps unit).
 * 11a and 11n support will be added later.
 */
static const struct ieee80211_rateset iwk_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset iwk_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

/*
 * For mfthread only
 */
extern pri_t minclsyspri;

#define	DRV_NAME_4965	"iwk"

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(iwk_devops, nulldev, nulldev, iwk_attach,
    iwk_detach, nodev, NULL, D_MP, NULL);

static struct modldrv iwk_modldrv = {
	&mod_driverops,
	"Intel(R) 4965AGN driver(N)",
	&iwk_devops
};

static struct modlinkage iwk_modlinkage = {
	MODREV_1,
	&iwk_modldrv,
	NULL
};

int
_init(void)
{
	int	status;

	status = ddi_soft_state_init(&iwk_soft_state_p,
	    sizeof (iwk_sc_t), 1);
	if (status != DDI_SUCCESS)
		return (status);

	mac_init_ops(&iwk_devops, DRV_NAME_4965);
	status = mod_install(&iwk_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&iwk_devops);
		ddi_soft_state_fini(&iwk_soft_state_p);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&iwk_modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&iwk_devops);
		ddi_soft_state_fini(&iwk_soft_state_p);
	}

	return (status);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&iwk_modlinkage, mip));
}

/*
 * Mac Call Back entries
 */
mac_callbacks_t	iwk_m_callbacks = {
	MC_IOCTL,
	iwk_m_stat,
	iwk_m_start,
	iwk_m_stop,
	iwk_m_promisc,
	iwk_m_multicst,
	iwk_m_unicst,
	iwk_m_tx,
	NULL,
	iwk_m_ioctl
};

#ifdef DEBUG
void
iwk_dbg(uint32_t flags, const char *fmt, ...)
{
	va_list	ap;

	if (flags & iwk_dbg_flags) {
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
iwk_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	iwk_sc_t		*sc;
	ieee80211com_t	*ic;
	int			instance, err, i;
	char			strbuf[32];
	wifi_data_t		wd = { 0 };
	mac_register_t		*macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(iwk_soft_state_p,
		    ddi_get_instance(dip));
		ASSERT(sc != NULL);
		mutex_enter(&sc->sc_glock);
		sc->sc_flags &= ~IWK_F_SUSPEND;
		mutex_exit(&sc->sc_glock);
		if (sc->sc_flags & IWK_F_RUNNING) {
			(void) iwk_init(sc);
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		}
		IWK_DBG((IWK_DEBUG_RESUME, "iwk: resume\n"));
		return (DDI_SUCCESS);
	default:
		err = DDI_FAILURE;
		goto attach_fail1;
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(iwk_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to allocate soft state\n");
		goto attach_fail1;
	}
	sc = ddi_get_soft_state(iwk_soft_state_p, instance);
	sc->sc_dip = dip;

	err = ddi_regs_map_setup(dip, 0, &sc->sc_cfg_base, 0, 0,
	    &iwk_reg_accattr, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to map config spaces regs\n");
		goto attach_fail2;
	}
	sc->sc_rev = ddi_get8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_REVID));
	ddi_put8(sc->sc_cfg_handle, (uint8_t *)(sc->sc_cfg_base + 0x41), 0);
	sc->sc_clsz = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)(sc->sc_cfg_base + PCI_CONF_CACHE_LINESZ));
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
	    0, 0, &iwk_reg_accattr, &sc->sc_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to map device regs\n");
		goto attach_fail2a;
	}

	/*
	 * Initialize mutexs and condvars
	 */
	err = ddi_get_iblock_cookie(dip, 0, &sc->sc_iblk);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to do ddi_get_iblock_cookie()\n");
		goto attach_fail2b;
	}
	mutex_init(&sc->sc_glock, NULL, MUTEX_DRIVER, sc->sc_iblk);
	mutex_init(&sc->sc_tx_lock, NULL, MUTEX_DRIVER, sc->sc_iblk);
	cv_init(&sc->sc_fw_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_cmd_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_tx_cv, "tx-ring", CV_DRIVER, NULL);
	/*
	 * initialize the mfthread
	 */
	mutex_init(&sc->sc_mt_lock, NULL, MUTEX_DRIVER,
	    (void *) sc->sc_iblk);
	cv_init(&sc->sc_mt_cv, NULL, CV_DRIVER, NULL);
	sc->sc_mf_thread = NULL;
	sc->sc_mf_thread_switch = 0;

	/*
	 * Allocate shared page.
	 */
	err = iwk_alloc_shared(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to allocate shared page\n");
		goto attach_fail3;
	}

	/*
	 * Allocate keep warm page.
	 */
	err = iwk_alloc_kw(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to allocate keep warm page\n");
		goto attach_fail3a;
	}

	/*
	 * Do some necessary hardware initializations.
	 */
	err = iwk_preinit(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to init hardware\n");
		goto attach_fail4;
	}

	/* initialize EEPROM */
	err = iwk_eep_load(sc);  /* get hardware configurations from eeprom */
	if (err != 0) {
		cmn_err(CE_WARN, "iwk_attach(): failed to load eeprom\n");
		goto attach_fail4;
	}

	if (sc->sc_eep_map.calib_version < EEP_TX_POWER_VERSION_NEW) {
		IWK_DBG((IWK_DEBUG_EEPROM, "older EEPROM detected"));
		goto attach_fail4;
	}

	iwk_get_mac_from_eep(sc);

	err = iwk_ring_init(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_attach(): "
		    "failed to allocate and initialize ring\n");
		goto attach_fail4;
	}

	sc->sc_hdr = (iwk_firmware_hdr_t *)iwk_fw_bin;

	err = iwk_alloc_fw_dma(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_attach(): "
		    "failed to allocate firmware dma\n");
		goto attach_fail5;
	}

	/*
	 * Initialize the wifi part, which will be used by
	 * generic layer
	 */
	ic = &sc->sc_ic;
	ic->ic_phytype  = IEEE80211_T_OFDM;
	ic->ic_opmode   = IEEE80211_M_STA; /* default to BSS mode */
	ic->ic_state    = IEEE80211_S_INIT;
	ic->ic_maxrssi  = 100; /* experimental number */
	ic->ic_caps = IEEE80211_C_SHPREAMBLE | IEEE80211_C_TXPMGT |
	    IEEE80211_C_PMGT | IEEE80211_C_SHSLOT;
	/*
	 * use software WEP and TKIP, hardware CCMP;
	 */
	ic->ic_caps |= IEEE80211_C_AES_CCM;
	/*
	 * Support WPA/WPA2
	 */
	ic->ic_caps |= IEEE80211_C_WPA;
	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = iwk_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = iwk_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}
	ic->ic_ibss_chan = &ic->ic_sup_channels[0];
	ic->ic_xmit = iwk_send;
	/*
	 * init Wifi layer
	 */
	ieee80211_attach(ic);

	/*
	 * different instance has different WPA door
	 */
	(void) snprintf(ic->ic_wpadoor, MAX_IEEE80211STR, "%s_%s%d", WPA_DOOR,
	    ddi_driver_name(dip),
	    ddi_get_instance(dip));

	/*
	 * Override 80211 default routines
	 */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = iwk_newstate;
	ic->ic_node_alloc = iwk_node_alloc;
	ic->ic_node_free = iwk_node_free;
	ic->ic_crypto.cs_key_set = iwk_key_set;
	ieee80211_media_init(ic);
	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	err = ddi_add_softintr(dip, DDI_SOFTINT_LOW,
	    &sc->sc_rx_softint_id, &sc->sc_iblk, NULL, iwk_rx_softintr,
	    (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to do ddi_add_softintr()\n");
		goto attach_fail7;
	}

	/*
	 * Add the interrupt handler
	 */
	err = ddi_add_intr(dip, 0, &sc->sc_iblk, NULL,
	    iwk_intr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to do ddi_add_intr()\n");
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
		    "iwk_attach(): failed to do mac_alloc()\n");
		goto attach_fail9;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &iwk_m_callbacks;
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
		    "iwk_attach(): failed to do mac_register()\n");
		goto attach_fail9;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), DRV_NAME_4965"%d", instance);
	err = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		cmn_err(CE_WARN,
		    "iwk_attach(): failed to do ddi_create_minor_node()\n");

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
		    iwk_thread, sc, 0, &p0, TS_RUN, minclsyspri);

	sc->sc_flags |= IWK_F_ATTACHED;

	return (DDI_SUCCESS);
attach_fail9:
	ddi_remove_intr(dip, 0, sc->sc_iblk);
attach_fail8:
	ddi_remove_softintr(sc->sc_rx_softint_id);
	sc->sc_rx_softint_id = NULL;
attach_fail7:
	ieee80211_detach(ic);
attach_fail6:
	iwk_free_fw_dma(sc);
attach_fail5:
	iwk_ring_free(sc);
attach_fail4:
	iwk_free_kw(sc);
attach_fail3a:
	iwk_free_shared(sc);
attach_fail3:
	iwk_destroy_locks(sc);
attach_fail2b:
	ddi_regs_map_free(&sc->sc_handle);
attach_fail2a:
	ddi_regs_map_free(&sc->sc_cfg_handle);
attach_fail2:
	ddi_soft_state_free(iwk_soft_state_p, instance);
attach_fail1:
	return (err);
}

int
iwk_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	iwk_sc_t	*sc;
	int err;

	sc = ddi_get_soft_state(iwk_soft_state_p, ddi_get_instance(dip));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (sc->sc_flags & IWK_F_RUNNING) {
			iwk_stop(sc);
		}
		mutex_enter(&sc->sc_glock);
		sc->sc_flags |= IWK_F_SUSPEND;
		mutex_exit(&sc->sc_glock);
		IWK_DBG((IWK_DEBUG_RESUME, "iwk: suspend\n"));
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (!(sc->sc_flags & IWK_F_ATTACHED))
		return (DDI_FAILURE);

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

	iwk_stop(sc);
	DELAY(500000);

	/*
	 * Unregiste from the MAC layer subsystem
	 */
	err = mac_unregister(sc->sc_ic.ic_mach);
	if (err != DDI_SUCCESS)
		return (err);

	mutex_enter(&sc->sc_glock);
	iwk_free_fw_dma(sc);
	iwk_ring_free(sc);
	iwk_free_kw(sc);
	iwk_free_shared(sc);
	mutex_exit(&sc->sc_glock);

	ddi_remove_intr(dip, 0, sc->sc_iblk);
	ddi_remove_softintr(sc->sc_rx_softint_id);
	sc->sc_rx_softint_id = NULL;

	/*
	 * detach ieee80211
	 */
	ieee80211_detach(&sc->sc_ic);

	iwk_destroy_locks(sc);

	ddi_regs_map_free(&sc->sc_handle);
	ddi_regs_map_free(&sc->sc_cfg_handle);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(iwk_soft_state_p, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

static void
iwk_destroy_locks(iwk_sc_t *sc)
{
	cv_destroy(&sc->sc_mt_cv);
	mutex_destroy(&sc->sc_mt_lock);
	cv_destroy(&sc->sc_tx_cv);
	cv_destroy(&sc->sc_cmd_cv);
	cv_destroy(&sc->sc_fw_cv);
	mutex_destroy(&sc->sc_tx_lock);
	mutex_destroy(&sc->sc_glock);
}

/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
iwk_alloc_dma_mem(iwk_sc_t *sc, size_t memsize,
    ddi_dma_attr_t *dma_attr_p, ddi_device_acc_attr_t *acc_attr_p,
    uint_t dma_flags, iwk_dma_t *dma_p)
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
iwk_free_dma_mem(iwk_dma_t *dma_p)
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
 *
 */
static int
iwk_alloc_fw_dma(iwk_sc_t *sc)
{
	int err = DDI_SUCCESS;
	iwk_dma_t *dma_p;
	char *t;

	/*
	 * firmware image layout:
	 * |HDR|<-TEXT->|<-DATA->|<-INIT_TEXT->|<-INIT_DATA->|<-BOOT->|
	 */
	t = (char *)(sc->sc_hdr + 1);
	err = iwk_alloc_dma_mem(sc, LE_32(sc->sc_hdr->textsz),
	    &fw_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_text);
	dma_p = &sc->sc_dma_fw_text;
	IWK_DBG((IWK_DEBUG_DMA, "text[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_alloc_fw_dma(): failed to alloc"
		    " text dma memory");
		goto fail;
	}
	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->textsz));

	t += LE_32(sc->sc_hdr->textsz);
	err = iwk_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data);
	dma_p = &sc->sc_dma_fw_data;
	IWK_DBG((IWK_DEBUG_DMA, "data[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_alloc_fw_dma(): failed to alloc"
		    " data dma memory");
		goto fail;
	}
	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->datasz));

	err = iwk_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data_bak);
	dma_p = &sc->sc_dma_fw_data_bak;
	IWK_DBG((IWK_DEBUG_DMA, "data_bak[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_alloc_fw_dma(): failed to alloc"
		    " data bakeup dma memory");
		goto fail;
	}
	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->datasz));

	t += LE_32(sc->sc_hdr->datasz);
	err = iwk_alloc_dma_mem(sc, LE_32(sc->sc_hdr->init_textsz),
	    &fw_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_init_text);
	dma_p = &sc->sc_dma_fw_init_text;
	IWK_DBG((IWK_DEBUG_DMA, "init_text[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_alloc_fw_dma(): failed to alloc"
		    "init text dma memory");
		goto fail;
	}
	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->init_textsz));

	t += LE_32(sc->sc_hdr->init_textsz);
	err = iwk_alloc_dma_mem(sc, LE_32(sc->sc_hdr->init_datasz),
	    &fw_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_init_data);
	dma_p = &sc->sc_dma_fw_init_data;
	IWK_DBG((IWK_DEBUG_DMA, "init_data[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwk_alloc_fw_dma(): failed to alloc"
		    "init data dma memory");
		goto fail;
	}
	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->init_datasz));

	sc->sc_boot = t + LE_32(sc->sc_hdr->init_datasz);
fail:
	return (err);
}

static void
iwk_free_fw_dma(iwk_sc_t *sc)
{
	iwk_free_dma_mem(&sc->sc_dma_fw_text);
	iwk_free_dma_mem(&sc->sc_dma_fw_data);
	iwk_free_dma_mem(&sc->sc_dma_fw_data_bak);
	iwk_free_dma_mem(&sc->sc_dma_fw_init_text);
	iwk_free_dma_mem(&sc->sc_dma_fw_init_data);
}

/*
 * Allocate a shared page between host and NIC.
 */
static int
iwk_alloc_shared(iwk_sc_t *sc)
{
	iwk_dma_t *dma_p;
	int err = DDI_SUCCESS;

	/* must be aligned on a 4K-page boundary */
	err = iwk_alloc_dma_mem(sc, sizeof (iwk_shared_t),
	    &sh_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_sh);
	if (err != DDI_SUCCESS)
		goto fail;
	sc->sc_shared = (iwk_shared_t *)sc->sc_dma_sh.mem_va;

	dma_p = &sc->sc_dma_sh;
	IWK_DBG((IWK_DEBUG_DMA, "sh[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);
fail:
	iwk_free_shared(sc);
	return (err);
}

static void
iwk_free_shared(iwk_sc_t *sc)
{
	iwk_free_dma_mem(&sc->sc_dma_sh);
}

/*
 * Allocate a keep warm page.
 */
static int
iwk_alloc_kw(iwk_sc_t *sc)
{
	iwk_dma_t *dma_p;
	int err = DDI_SUCCESS;

	/* must be aligned on a 4K-page boundary */
	err = iwk_alloc_dma_mem(sc, IWK_KW_SIZE,
	    &kw_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_kw);
	if (err != DDI_SUCCESS)
		goto fail;

	dma_p = &sc->sc_dma_kw;
	IWK_DBG((IWK_DEBUG_DMA, "kw[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);
fail:
	iwk_free_kw(sc);
	return (err);
}

static void
iwk_free_kw(iwk_sc_t *sc)
{
	iwk_free_dma_mem(&sc->sc_dma_kw);
}

static int
iwk_alloc_rx_ring(iwk_sc_t *sc)
{
	iwk_rx_ring_t *ring;
	iwk_rx_data_t *data;
	iwk_dma_t *dma_p;
	int i, err = DDI_SUCCESS;

	ring = &sc->sc_rxq;
	ring->cur = 0;

	err = iwk_alloc_dma_mem(sc, RX_QUEUE_SIZE * sizeof (uint32_t),
	    &ring_desc_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		IWK_DBG((IWK_DEBUG_DMA, "dma alloc rx ring desc "
		    "failed\n"));
		goto fail;
	}
	ring->desc = (uint32_t *)ring->dma_desc.mem_va;
	dma_p = &ring->dma_desc;
	IWK_DBG((IWK_DEBUG_DMA, "rx bd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	/*
	 * Allocate Rx buffers.
	 */
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		data = &ring->data[i];
		err = iwk_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &rx_buffer_dma_attr, &iwk_dma_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			IWK_DBG((IWK_DEBUG_DMA, "dma alloc rx ring "
			    "buf[%d] failed\n", i));
			goto fail;
		}
		/*
		 * the physical address bit [8-36] are used,
		 * instead of bit [0-31] in 3945.
		 */
		ring->desc[i] = LE_32((uint32_t)
		    (data->dma_data.cookie.dmac_address >> 8));
	}
	dma_p = &ring->data[0].dma_data;
	IWK_DBG((IWK_DEBUG_DMA, "rx buffer[0][ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	IWK_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	return (err);

fail:
	iwk_free_rx_ring(sc);
	return (err);
}

static void
iwk_reset_rx_ring(iwk_sc_t *sc)
{
	int n;

	iwk_mac_access_enter(sc);
	IWK_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
	for (n = 0; n < 2000; n++) {
		if (IWK_READ(sc, FH_MEM_RSSR_RX_STATUS_REG) & (1 << 24))
			break;
		DELAY(1000);
	}
#ifdef DEBUG
	if (n == 2000)
		IWK_DBG((IWK_DEBUG_DMA, "timeout resetting Rx ring\n"));
#endif
	iwk_mac_access_exit(sc);

	sc->sc_rxq.cur = 0;
}

static void
iwk_free_rx_ring(iwk_sc_t *sc)
{
	int i;

	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		if (sc->sc_rxq.data[i].dma_data.dma_hdl)
			IWK_DMA_SYNC(sc->sc_rxq.data[i].dma_data,
			    DDI_DMA_SYNC_FORCPU);
		iwk_free_dma_mem(&sc->sc_rxq.data[i].dma_data);
	}

	if (sc->sc_rxq.dma_desc.dma_hdl)
		IWK_DMA_SYNC(sc->sc_rxq.dma_desc, DDI_DMA_SYNC_FORDEV);
	iwk_free_dma_mem(&sc->sc_rxq.dma_desc);
}

static int
iwk_alloc_tx_ring(iwk_sc_t *sc, iwk_tx_ring_t *ring,
    int slots, int qid)
{
	iwk_tx_data_t *data;
	iwk_tx_desc_t *desc_h;
	uint32_t paddr_desc_h;
	iwk_cmd_t *cmd_h;
	uint32_t paddr_cmd_h;
	iwk_dma_t *dma_p;
	int i, err = DDI_SUCCESS;

	ring->qid = qid;
	ring->count = TFD_QUEUE_SIZE_MAX;
	ring->window = slots;
	ring->queued = 0;
	ring->cur = 0;

	err = iwk_alloc_dma_mem(sc,
	    TFD_QUEUE_SIZE_MAX * sizeof (iwk_tx_desc_t),
	    &ring_desc_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		IWK_DBG((IWK_DEBUG_DMA, "dma alloc tx ring desc[%d]"
		    " failed\n", qid));
		goto fail;
	}
	dma_p = &ring->dma_desc;
	IWK_DBG((IWK_DEBUG_DMA, "tx bd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	desc_h = (iwk_tx_desc_t *)ring->dma_desc.mem_va;
	paddr_desc_h = ring->dma_desc.cookie.dmac_address;

	err = iwk_alloc_dma_mem(sc,
	    TFD_QUEUE_SIZE_MAX * sizeof (iwk_cmd_t),
	    &cmd_dma_attr, &iwk_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_cmd);
	if (err != DDI_SUCCESS) {
		IWK_DBG((IWK_DEBUG_DMA, "dma alloc tx ring cmd[%d]"
		    " failed\n", qid));
		goto fail;
	}
	dma_p = &ring->dma_cmd;
	IWK_DBG((IWK_DEBUG_DMA, "tx cmd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	cmd_h = (iwk_cmd_t *)ring->dma_cmd.mem_va;
	paddr_cmd_h = ring->dma_cmd.cookie.dmac_address;

	/*
	 * Allocate Tx buffers.
	 */
	ring->data = kmem_zalloc(sizeof (iwk_tx_data_t) * TFD_QUEUE_SIZE_MAX,
	    KM_NOSLEEP);
	if (ring->data == NULL) {
		IWK_DBG((IWK_DEBUG_DMA, "could not allocate "
		    "tx data slots\n"));
		goto fail;
	}

	for (i = 0; i < TFD_QUEUE_SIZE_MAX; i++) {
		data = &ring->data[i];
		err = iwk_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &tx_buffer_dma_attr, &iwk_dma_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			IWK_DBG((IWK_DEBUG_DMA, "dma alloc tx "
			    "ring buf[%d] failed\n", i));
			goto fail;
		}

		data->desc = desc_h + i;
		data->paddr_desc = paddr_desc_h +
		    _PTRDIFF(data->desc, desc_h);
		data->cmd = cmd_h +  i; /* (i % slots); */
		data->paddr_cmd = paddr_cmd_h +
		    _PTRDIFF(data->cmd, cmd_h);
		    /* ((i % slots) * sizeof (iwk_cmd_t)); */
	}
	dma_p = &ring->data[0].dma_data;
	IWK_DBG((IWK_DEBUG_DMA, "tx buffer[0][ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);

fail:
	if (ring->data)
		kmem_free(ring->data,
		    sizeof (iwk_tx_data_t) * TFD_QUEUE_SIZE_MAX);
	iwk_free_tx_ring(sc, ring);
	return (err);
}

static void
iwk_reset_tx_ring(iwk_sc_t *sc, iwk_tx_ring_t *ring)
{
	iwk_tx_data_t *data;
	int i, n;

	iwk_mac_access_enter(sc);

	IWK_WRITE(sc, IWK_FH_TCSR_CHNL_TX_CONFIG_REG(ring->qid), 0);
	for (n = 0; n < 200; n++) {
		if (IWK_READ(sc, IWK_FH_TSSR_TX_STATUS_REG) &
		    IWK_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(ring->qid))
			break;
		DELAY(10);
	}
#ifdef DEBUG
	if (n == 200 && iwk_dbg_flags > 0) {
		IWK_DBG((IWK_DEBUG_DMA, "timeout reset tx ring %d\n",
		    ring->qid));
	}
#endif
	iwk_mac_access_exit(sc);

	for (i = 0; i < ring->count; i++) {
		data = &ring->data[i];
		IWK_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
	}

	ring->queued = 0;
	ring->cur = 0;
}

/*ARGSUSED*/
static void
iwk_free_tx_ring(iwk_sc_t *sc, iwk_tx_ring_t *ring)
{
	int i;

	if (ring->dma_desc.dma_hdl != NULL)
		IWK_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);
	iwk_free_dma_mem(&ring->dma_desc);

	if (ring->dma_cmd.dma_hdl != NULL)
		IWK_DMA_SYNC(ring->dma_cmd, DDI_DMA_SYNC_FORDEV);
	iwk_free_dma_mem(&ring->dma_cmd);

	if (ring->data != NULL) {
		for (i = 0; i < ring->count; i++) {
			if (ring->data[i].dma_data.dma_hdl)
				IWK_DMA_SYNC(ring->data[i].dma_data,
				    DDI_DMA_SYNC_FORDEV);
			iwk_free_dma_mem(&ring->data[i].dma_data);
		}
		kmem_free(ring->data, ring->count * sizeof (iwk_tx_data_t));
	}
}

static int
iwk_ring_init(iwk_sc_t *sc)
{
	int i, err = DDI_SUCCESS;

	for (i = 0; i < IWK_NUM_QUEUES; i++) {
		if (i == IWK_CMD_QUEUE_NUM)
			continue;
		err = iwk_alloc_tx_ring(sc, &sc->sc_txq[i], TFD_TX_CMD_SLOTS,
		    i);
		if (err != DDI_SUCCESS)
			goto fail;
	}
	err = iwk_alloc_tx_ring(sc, &sc->sc_txq[IWK_CMD_QUEUE_NUM],
	    TFD_CMD_SLOTS, IWK_CMD_QUEUE_NUM);
	if (err != DDI_SUCCESS)
		goto fail;
	err = iwk_alloc_rx_ring(sc);
	if (err != DDI_SUCCESS)
		goto fail;
	return (err);

fail:
	return (err);
}

static void
iwk_ring_free(iwk_sc_t *sc)
{
	int i = IWK_NUM_QUEUES;

	iwk_free_rx_ring(sc);
	while (--i >= 0) {
		iwk_free_tx_ring(sc, &sc->sc_txq[i]);
	}
}

/* ARGSUSED */
static ieee80211_node_t *
iwk_node_alloc(ieee80211com_t *ic)
{
	iwk_amrr_t *amrr;

	amrr = kmem_zalloc(sizeof (iwk_amrr_t), KM_SLEEP);
	if (amrr != NULL)
		iwk_amrr_init(amrr);
	return (&amrr->in);
}

static void
iwk_node_free(ieee80211_node_t *in)
{
	ieee80211com_t *ic = in->in_ic;

	ic->ic_node_cleanup(in);
	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);
	kmem_free(in, sizeof (iwk_amrr_t));
}

/*ARGSUSED*/
static int
iwk_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	iwk_sc_t *sc = (iwk_sc_t *)ic;
	ieee80211_node_t *in = ic->ic_bss;
	iwk_tx_power_table_cmd_t txpower;
	enum ieee80211_state ostate = ic->ic_state;
	int i, err = IWK_SUCCESS;

	mutex_enter(&sc->sc_glock);
	switch (nstate) {
	case IEEE80211_S_SCAN:
		if (ostate == IEEE80211_S_INIT) {
			ic->ic_flags |= IEEE80211_F_SCAN | IEEE80211_F_ASCAN;
			/* let LED blink when scanning */
			iwk_set_led(sc, 2, 10, 2);

			if ((err = iwk_scan(sc)) != 0) {
				IWK_DBG((IWK_DEBUG_80211,
				    "could not initiate scan\n"));
				ic->ic_flags &= ~(IEEE80211_F_SCAN |
				    IEEE80211_F_ASCAN);
				mutex_exit(&sc->sc_glock);
				return (err);
			}
		}
		ic->ic_state = nstate;
		sc->sc_clk = 0;
		mutex_exit(&sc->sc_glock);
		return (IWK_SUCCESS);

	case IEEE80211_S_AUTH:
		/* reset state to handle reassociations correctly */
		sc->sc_config.assoc_id = 0;
		sc->sc_config.filter_flags &= ~LE_32(RXON_FILTER_ASSOC_MSK);

		/*
		 * before sending authentication and association request frame,
		 * we need do something in the hardware, such as setting the
		 * channel same to the target AP...
		 */
		if ((err = iwk_hw_set_before_auth(sc)) != 0) {
			IWK_DBG((IWK_DEBUG_80211,
			    "could not send authentication request\n"));
			mutex_exit(&sc->sc_glock);
			return (err);
		}
		break;

	case IEEE80211_S_RUN:
		if (ic->ic_opmode == IEEE80211_M_MONITOR) {
			/* let LED blink when monitoring */
			iwk_set_led(sc, 2, 10, 10);
			break;
		}

		if (ic->ic_opmode != IEEE80211_M_STA) {
			(void) iwk_hw_set_before_auth(sc);
			/* need setup beacon here */
		}
		IWK_DBG((IWK_DEBUG_80211, "iwk: associated."));

		/* update adapter's configuration */
		sc->sc_config.assoc_id = sc->sc_assoc_id & 0x3fff;
		/* short preamble/slot time are negotiated when associating */
		sc->sc_config.flags &= ~LE_32(RXON_FLG_SHORT_PREAMBLE_MSK |
		    RXON_FLG_SHORT_SLOT_MSK);

		if (ic->ic_flags & IEEE80211_F_SHSLOT)
			sc->sc_config.flags |= LE_32(RXON_FLG_SHORT_SLOT_MSK);

		if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
			sc->sc_config.flags |=
			    LE_32(RXON_FLG_SHORT_PREAMBLE_MSK);

		sc->sc_config.filter_flags |= LE_32(RXON_FILTER_ASSOC_MSK);

		if (ic->ic_opmode != IEEE80211_M_STA)
			sc->sc_config.filter_flags |=
			    LE_32(RXON_FILTER_BCON_AWARE_MSK);

		IWK_DBG((IWK_DEBUG_80211, "config chan %d flags %x"
		    " filter_flags %x\n",
		    sc->sc_config.chan, sc->sc_config.flags,
		    sc->sc_config.filter_flags));
		err = iwk_cmd(sc, REPLY_RXON, &sc->sc_config,
		    sizeof (iwk_rxon_cmd_t), 1);
		if (err != IWK_SUCCESS) {
			IWK_DBG((IWK_DEBUG_80211,
			    "could not update configuration\n"));
			mutex_exit(&sc->sc_glock);
			return (err);
		}

		/*
		 * set Tx power for 2.4GHz channels
		 * (need further investigation. fix tx power at present)
		 * This cmd should be issued each time the reply_rxon cmd is
		 * invoked.
		 */
		(void) memset(&txpower, 0, sizeof (txpower));
		txpower.band = 1; /* for 2.4G */
		txpower.channel = sc->sc_config.chan;
		txpower.channel_normal_width = 0;
		for (i = 0; i < POWER_TABLE_NUM_HT_OFDM_ENTRIES; i++) {
			txpower.tx_power.ht_ofdm_power[i].s.ramon_tx_gain =
			    0x3f3f;
			txpower.tx_power.ht_ofdm_power[i].s.dsp_predis_atten =
			    110 | (110 << 8);
		}
		txpower.tx_power.ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES]
		    .s.ramon_tx_gain = 0x3f3f;
		txpower.tx_power.ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES]
		    .s.dsp_predis_atten = 110 | (110 << 8);
		err = iwk_cmd(sc, REPLY_TX_PWR_TABLE_CMD, &txpower,
		    sizeof (txpower), 1);
		if (err != IWK_SUCCESS) {
			cmn_err(CE_WARN, "iwk_newstate(): failed to "
			    "set txpower\n");
			return (err);
		}

		/* start automatic rate control */
		mutex_enter(&sc->sc_mt_lock);
		if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
			sc->sc_flags |= IWK_F_RATE_AUTO_CTL;
			/* set rate to some reasonable initial value */
			i = in->in_rates.ir_nrates - 1;
			while (i > 0 && IEEE80211_RATE(i) > 72)
				i--;
			in->in_txrate = i;
		} else {
			sc->sc_flags &= ~IWK_F_RATE_AUTO_CTL;
		}
		mutex_exit(&sc->sc_mt_lock);

		/* set LED on after associated */
		iwk_set_led(sc, 2, 0, 1);
		break;

	case IEEE80211_S_INIT:
		/* set LED off after init */
		iwk_set_led(sc, 2, 1, 0);
		break;
	case IEEE80211_S_ASSOC:
		break;
	}

	mutex_exit(&sc->sc_glock);
	return (sc->sc_newstate(ic, nstate, arg));
}

/*ARGSUSED*/
static int iwk_key_set(ieee80211com_t *ic, const struct ieee80211_key *k,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	iwk_sc_t *sc = (iwk_sc_t *)ic;
	iwk_add_sta_t node;
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
	sc->sc_config.filter_flags &= ~(RXON_FILTER_DIS_DECRYPT_MSK
	    | RXON_FILTER_DIS_GRP_DECRYPT_MSK);

	mutex_enter(&sc->sc_glock);

	/* update ap/multicast node */
	(void) memset(&node, 0, sizeof (node));
	if (IEEE80211_IS_MULTICAST(mac)) {
		(void) memset(node.bssid, 0xff, 6);
		node.id = IWK_BROADCAST_ID;
	} else {
		IEEE80211_ADDR_COPY(node.bssid, ic->ic_bss->in_bssid);
		node.id = IWK_AP_ID;
	}
	if (k->wk_flags & IEEE80211_KEY_XMIT) {
		node.key_flags = 0;
		node.keyp = k->wk_keyix;
	} else {
		node.key_flags = (1 << 14);
		node.keyp = k->wk_keyix + 4;
	}
	(void) memcpy(node.key, k->wk_key, k->wk_keylen);
	node.key_flags |= (STA_KEY_FLG_CCMP | (1 << 3) | (k->wk_keyix << 8));
	node.sta_mask = STA_MODIFY_KEY_MASK;
	node.control = 1;
	err = iwk_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_key_set():"
		    "failed to update ap node\n");
		mutex_exit(&sc->sc_glock);
		return (0);
	}
	mutex_exit(&sc->sc_glock);
	return (1);
}

/*
 * exclusive access to mac begin.
 */
static void
iwk_mac_access_enter(iwk_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWK_READ(sc, CSR_GP_CNTRL);
	IWK_WRITE(sc, CSR_GP_CNTRL,
	    tmp | CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

	/* wait until we succeed */
	for (n = 0; n < 1000; n++) {
		if ((IWK_READ(sc, CSR_GP_CNTRL) &
		    (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
		    CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP)) ==
		    CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN)
			break;
		DELAY(10);
	}
	if (n == 1000)
		IWK_DBG((IWK_DEBUG_PIO, "could not lock memory\n"));
}

/*
 * exclusive access to mac end.
 */
static void
iwk_mac_access_exit(iwk_sc_t *sc)
{
	uint32_t tmp = IWK_READ(sc, CSR_GP_CNTRL);
	IWK_WRITE(sc, CSR_GP_CNTRL,
	    tmp & ~CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
}

/*
 * this function defined here for future use.
 * static uint32_t
 * iwk_mem_read(iwk_sc_t *sc, uint32_t addr)
 * {
 * 	IWK_WRITE(sc, HBUS_TARG_MEM_RADDR, addr);
 * 	return (IWK_READ(sc, HBUS_TARG_MEM_RDAT));
 * }
 */

static void
iwk_mem_write(iwk_sc_t *sc, uint32_t addr, uint32_t data)
{
	IWK_WRITE(sc, HBUS_TARG_MEM_WADDR, addr);
	IWK_WRITE(sc, HBUS_TARG_MEM_WDAT, data);
}

static uint32_t
iwk_reg_read(iwk_sc_t *sc, uint32_t addr)
{
	IWK_WRITE(sc, HBUS_TARG_PRPH_RADDR, addr | (3 << 24));
	return (IWK_READ(sc, HBUS_TARG_PRPH_RDAT));
}

static void
iwk_reg_write(iwk_sc_t *sc, uint32_t addr, uint32_t data)
{
	IWK_WRITE(sc, HBUS_TARG_PRPH_WADDR, addr | (3 << 24));
	IWK_WRITE(sc, HBUS_TARG_PRPH_WDAT, data);
}

static void
iwk_reg_write_region_4(iwk_sc_t *sc, uint32_t addr,
    uint32_t *data, int wlen)
{
	for (; wlen > 0; wlen--, data++, addr += 4)
		iwk_reg_write(sc, addr, *data);
}


/*
 * ucode load/initialization steps:
 * 1)  load Bootstrap State Machine (BSM) with "bootstrap" uCode image.
 * BSM contains a small memory that *always* stays powered up, so it can
 * retain the bootstrap program even when the card is in a power-saving
 * power-down state.  The BSM loads the small program into ARC processor's
 * instruction memory when triggered by power-up.
 * 2)  load Initialize image via bootstrap program.
 * The Initialize image sets up regulatory and calibration data for the
 * Runtime/Protocol uCode. This sends a REPLY_ALIVE notification when completed.
 * The 4965 reply contains calibration data for temperature, voltage and tx gain
 * correction.
 */
static int
iwk_load_firmware(iwk_sc_t *sc)
{
	uint32_t *boot_fw = (uint32_t *)sc->sc_boot;
	uint32_t size = sc->sc_hdr->bootsz;
	int n, err = IWK_SUCCESS;

	/*
	 * The physical address bit [4-35] of the initialize uCode.
	 * In the initialize alive notify interrupt the physical address of
	 * the runtime ucode will be set for loading.
	 */
	iwk_mac_access_enter(sc);

	iwk_reg_write(sc, BSM_DRAM_INST_PTR_REG,
	    sc->sc_dma_fw_init_text.cookie.dmac_address >> 4);
	iwk_reg_write(sc, BSM_DRAM_DATA_PTR_REG,
	    sc->sc_dma_fw_init_data.cookie.dmac_address >> 4);
	iwk_reg_write(sc, BSM_DRAM_INST_BYTECOUNT_REG,
	    sc->sc_dma_fw_init_text.cookie.dmac_size);
	iwk_reg_write(sc, BSM_DRAM_DATA_BYTECOUNT_REG,
	    sc->sc_dma_fw_init_data.cookie.dmac_size);

	/* load bootstrap code into BSM memory */
	iwk_reg_write_region_4(sc, BSM_SRAM_LOWER_BOUND, boot_fw,
	    size / sizeof (uint32_t));

	iwk_reg_write(sc, BSM_WR_MEM_SRC_REG, 0);
	iwk_reg_write(sc, BSM_WR_MEM_DST_REG, RTC_INST_LOWER_BOUND);
	iwk_reg_write(sc, BSM_WR_DWCOUNT_REG, size / sizeof (uint32_t));

	/*
	 * prepare to load initialize uCode
	 */
	iwk_reg_write(sc, BSM_WR_CTRL_REG, BSM_WR_CTRL_REG_BIT_START);

	/* wait while the adapter is busy loading the firmware */
	for (n = 0; n < 1000; n++) {
		if (!(iwk_reg_read(sc, BSM_WR_CTRL_REG) &
		    BSM_WR_CTRL_REG_BIT_START))
			break;
		DELAY(10);
	}
	if (n == 1000) {
		IWK_DBG((IWK_DEBUG_FW,
		    "timeout transferring firmware\n"));
		err = ETIMEDOUT;
		return (err);
	}

	/* for future power-save mode use */
	iwk_reg_write(sc, BSM_WR_CTRL_REG, BSM_WR_CTRL_REG_BIT_START_EN);

	iwk_mac_access_exit(sc);

	return (err);
}

/*ARGSUSED*/
static void
iwk_rx_intr(iwk_sc_t *sc, iwk_rx_desc_t *desc, iwk_rx_data_t *data)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwk_rx_ring_t *ring = &sc->sc_rxq;
	iwk_rx_phy_res_t *stat;
	ieee80211_node_t *in;
	uint32_t *tail;
	struct ieee80211_frame *wh;
	mblk_t *mp;
	uint16_t len, rssi, mrssi, agc;
	int16_t t;
	uint32_t ants, i;
	struct iwk_rx_non_cfg_phy *phyinfo;

	/* assuming not 11n here. cope with 11n in phase-II */
	stat = (iwk_rx_phy_res_t *)(desc + 1);
	if (stat->cfg_phy_cnt > 20) {
		return;
	}

	phyinfo = (struct iwk_rx_non_cfg_phy *)stat->non_cfg_phy;
	agc = (phyinfo->agc_info & IWK_AGC_DB_MASK) >> IWK_AGC_DB_POS;
	mrssi = 0;
	ants = (stat->phy_flags & RX_PHY_FLAGS_ANTENNAE_MASK)
	    >> RX_PHY_FLAGS_ANTENNAE_OFFSET;
	for (i = 0; i < 3; i++) {
		if (ants & (1 << i))
			mrssi = MAX(mrssi, phyinfo->rssi_info[i << 1]);
	}
	t = mrssi - agc - 44; /* t is the dBM value */
	/*
	 * convert dBm to percentage ???
	 */
	rssi = (100 * 75 * 75 - (-20 - t) * (15 * 75 + 62 * (-20 - t)))
	    / (75 * 75);
	if (rssi > 100)
		rssi = 100;
	if (rssi < 1)
		rssi = 1;
	len = stat->byte_count;
	tail = (uint32_t *)((uint8_t *)(stat + 1) + stat->cfg_phy_cnt + len);

	IWK_DBG((IWK_DEBUG_RX, "rx intr: idx=%d phy_len=%x len=%d "
	    "rate=%x chan=%d tstamp=%x non_cfg_phy_count=%x "
	    "cfg_phy_count=%x tail=%x", ring->cur, sizeof (*stat),
	    len, stat->rate.r.s.rate, stat->channel,
	    LE_32(stat->timestampl), stat->non_cfg_phy_cnt,
	    stat->cfg_phy_cnt, LE_32(*tail)));

	if ((len < 16) || (len > sc->sc_dmabuf_sz)) {
		IWK_DBG((IWK_DEBUG_RX, "rx frame oversize\n"));
		return;
	}

	/*
	 * discard Rx frames with bad CRC
	 */
	if ((LE_32(*tail) &
	    (RX_RES_STATUS_NO_CRC32_ERROR | RX_RES_STATUS_NO_RXE_OVERFLOW)) !=
	    (RX_RES_STATUS_NO_CRC32_ERROR | RX_RES_STATUS_NO_RXE_OVERFLOW)) {
		IWK_DBG((IWK_DEBUG_RX, "rx crc error tail: %x\n",
		    LE_32(*tail)));
		sc->sc_rx_err++;
		return;
	}

	wh = (struct ieee80211_frame *)
	    ((uint8_t *)(stat + 1)+ stat->cfg_phy_cnt);
	if (*(uint8_t *)wh == IEEE80211_FC0_SUBTYPE_ASSOC_RESP) {
		sc->sc_assoc_id = *((uint16_t *)(wh + 1) + 2);
		IWK_DBG((IWK_DEBUG_RX, "rx : association id = %x\n",
		    sc->sc_assoc_id));
	}
#ifdef DEBUG
	if (iwk_dbg_flags & IWK_DEBUG_RX)
		ieee80211_dump_pkt((uint8_t *)wh, len, 0, 0);
#endif
	in = ieee80211_find_rxnode(ic, wh);
	mp = allocb(len, BPRI_MED);
	if (mp) {
		(void) memcpy(mp->b_wptr, wh, len);
		mp->b_wptr += len;

		/* send the frame to the 802.11 layer */
		(void) ieee80211_input(ic, mp, in, rssi, 0);
	} else {
		sc->sc_rx_nobuf++;
		IWK_DBG((IWK_DEBUG_RX,
		    "iwk_rx_intr(): alloc rx buf failed\n"));
	}
	/* release node reference */
	ieee80211_free_node(in);
}

/*ARGSUSED*/
static void
iwk_tx_intr(iwk_sc_t *sc, iwk_rx_desc_t *desc, iwk_rx_data_t *data)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwk_tx_ring_t *ring = &sc->sc_txq[desc->hdr.qid & 0x3];
	iwk_tx_stat_t *stat = (iwk_tx_stat_t *)(desc + 1);
	iwk_amrr_t *amrr = (iwk_amrr_t *)ic->ic_bss;

	IWK_DBG((IWK_DEBUG_TX, "tx done: qid=%d idx=%d"
	    " retries=%d frame_count=%x nkill=%d "
	    "rate=%x duration=%d status=%x\n",
	    desc->hdr.qid, desc->hdr.idx, stat->ntries, stat->frame_count,
	    stat->bt_kill_count, stat->rate.r.s.rate,
	    LE_32(stat->duration), LE_32(stat->status)));

	amrr->txcnt++;
	IWK_DBG((IWK_DEBUG_RATECTL, "tx: %d cnt\n", amrr->txcnt));
	if (stat->ntries > 0) {
		amrr->retrycnt++;
		sc->sc_tx_retries++;
		IWK_DBG((IWK_DEBUG_TX, "tx: %d retries\n",
		    sc->sc_tx_retries));
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
iwk_cmd_intr(iwk_sc_t *sc, iwk_rx_desc_t *desc)
{
	if ((desc->hdr.qid & 7) != 4) {
		return;
	}
	mutex_enter(&sc->sc_glock);
	sc->sc_flags |= IWK_F_CMD_DONE;
	cv_signal(&sc->sc_cmd_cv);
	mutex_exit(&sc->sc_glock);
	IWK_DBG((IWK_DEBUG_CMD, "rx cmd: "
	    "qid=%x idx=%d flags=%x type=0x%x\n",
	    desc->hdr.qid, desc->hdr.idx, desc->hdr.flags,
	    desc->hdr.type));
}

static void
iwk_ucode_alive(iwk_sc_t *sc, iwk_rx_desc_t *desc)
{
	uint32_t base, i;
	struct iwk_alive_resp *ar =
	    (struct iwk_alive_resp *)(desc + 1);

	/* the microcontroller is ready */
	IWK_DBG((IWK_DEBUG_FW,
	    "microcode alive notification minor: %x major: %x type:"
	    " %x subtype: %x\n",
	    ar->ucode_minor, ar->ucode_minor, ar->ver_type, ar->ver_subtype));

	if (LE_32(ar->is_valid) != UCODE_VALID_OK) {
		IWK_DBG((IWK_DEBUG_FW,
		    "microcontroller initialization failed\n"));
	}
	if (ar->ver_subtype == INITIALIZE_SUBTYPE) {
		IWK_DBG((IWK_DEBUG_FW,
		    "initialization alive received.\n"));
		(void) memcpy(&sc->sc_card_alive_init, ar,
		    sizeof (struct iwk_init_alive_resp));
		/* XXX get temperature */
		iwk_mac_access_enter(sc);
		iwk_reg_write(sc, BSM_DRAM_INST_PTR_REG,
		    sc->sc_dma_fw_text.cookie.dmac_address >> 4);
		iwk_reg_write(sc, BSM_DRAM_DATA_PTR_REG,
		    sc->sc_dma_fw_data_bak.cookie.dmac_address >> 4);
		iwk_reg_write(sc, BSM_DRAM_DATA_BYTECOUNT_REG,
		    sc->sc_dma_fw_data.cookie.dmac_size);
		iwk_reg_write(sc, BSM_DRAM_INST_BYTECOUNT_REG,
		    sc->sc_dma_fw_text.cookie.dmac_size | 0x80000000);
		iwk_mac_access_exit(sc);
	} else {
		IWK_DBG((IWK_DEBUG_FW, "runtime alive received.\n"));
		(void) memcpy(&sc->sc_card_alive_run, ar,
		    sizeof (struct iwk_alive_resp));

		/*
		 * Init SCD related registers to make Tx work. XXX
		 */
		iwk_mac_access_enter(sc);

		/* read sram address of data base */
		sc->sc_scd_base = iwk_reg_read(sc, SCD_SRAM_BASE_ADDR);

		/* clear and init SCD_CONTEXT_DATA_OFFSET area. 128 bytes */
		for (base = sc->sc_scd_base + SCD_CONTEXT_DATA_OFFSET, i = 0;
		    i < 128; i += 4)
			iwk_mem_write(sc, base + i, 0);

		/* clear and init SCD_TX_STTS_BITMAP_OFFSET area. 256 bytes */
		for (base = sc->sc_scd_base + SCD_TX_STTS_BITMAP_OFFSET;
		    i < 256; i += 4)
			iwk_mem_write(sc, base + i, 0);

		/* clear and init SCD_TRANSLATE_TBL_OFFSET area. 32 bytes */
		for (base = sc->sc_scd_base + SCD_TRANSLATE_TBL_OFFSET;
		    i < sizeof (uint16_t) * IWK_NUM_QUEUES; i += 4)
			iwk_mem_write(sc, base + i, 0);

		iwk_reg_write(sc, SCD_DRAM_BASE_ADDR,
		    sc->sc_dma_sh.cookie.dmac_address >> 10);
		iwk_reg_write(sc, SCD_QUEUECHAIN_SEL, 0);

		/* initiate the tx queues */
		for (i = 0; i < IWK_NUM_QUEUES; i++) {
			iwk_reg_write(sc, SCD_QUEUE_RDPTR(i), 0);
			IWK_WRITE(sc, HBUS_TARG_WRPTR, (i << 8));
			iwk_mem_write(sc, sc->sc_scd_base +
			    SCD_CONTEXT_QUEUE_OFFSET(i),
			    (SCD_WIN_SIZE & 0x7f));
			iwk_mem_write(sc, sc->sc_scd_base +
			    SCD_CONTEXT_QUEUE_OFFSET(i) + sizeof (uint32_t),
			    (SCD_FRAME_LIMIT & 0x7f) << 16);
		}
		/* interrupt enable on each queue0-7 */
		iwk_reg_write(sc, SCD_INTERRUPT_MASK,
		    (1 << IWK_NUM_QUEUES) - 1);
		/* enable  each channel 0-7 */
		iwk_reg_write(sc, SCD_TXFACT,
		    SCD_TXFACT_REG_TXFIFO_MASK(0, 7));
		/*
		 * queue 0-7 maps to FIFO 0-7 and
		 * all queues work under FIFO mode (none-scheduler-ack)
		 */
		for (i = 0; i < 7; i++) {
			iwk_reg_write(sc,
			    SCD_QUEUE_STATUS_BITS(i),
			    (1 << SCD_QUEUE_STTS_REG_POS_ACTIVE)|
			    (i << SCD_QUEUE_STTS_REG_POS_TXF)|
			    SCD_QUEUE_STTS_REG_MSK);
		}
		iwk_mac_access_exit(sc);

		sc->sc_flags |= IWK_F_FW_INIT;
		cv_signal(&sc->sc_fw_cv);
	}

}

static uint_t
iwk_rx_softintr(caddr_t arg)
{
	iwk_sc_t *sc = (iwk_sc_t *)arg;
	ieee80211com_t *ic = &sc->sc_ic;
	iwk_rx_desc_t *desc;
	iwk_rx_data_t *data;
	uint32_t index;

	mutex_enter(&sc->sc_glock);
	if (sc->sc_rx_softint_pending != 1) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_UNCLAIMED);
	}
	/* disable interrupts */
	IWK_WRITE(sc, CSR_INT_MASK, 0);
	mutex_exit(&sc->sc_glock);

	/*
	 * firmware has moved the index of the rx queue, driver get it,
	 * and deal with it.
	 */
	index = LE_32(sc->sc_shared->val0) & 0xfff;

	while (sc->sc_rxq.cur != index) {
		data = &sc->sc_rxq.data[sc->sc_rxq.cur];
		desc = (iwk_rx_desc_t *)data->dma_data.mem_va;

		IWK_DBG((IWK_DEBUG_INTR, "rx notification index = %d"
		    " cur = %d qid=%x idx=%d flags=%x type=%x len=%d\n",
		    index, sc->sc_rxq.cur, desc->hdr.qid, desc->hdr.idx,
		    desc->hdr.flags, desc->hdr.type, LE_32(desc->len)));

		/* a command other than a tx need to be replied */
		if (!(desc->hdr.qid & 0x80) &&
		    (desc->hdr.type != REPLY_RX_PHY_CMD) &&
		    (desc->hdr.type != REPLY_TX))
			iwk_cmd_intr(sc, desc);

		switch (desc->hdr.type) {
		case REPLY_4965_RX:
			iwk_rx_intr(sc, desc, data);
			break;

		case REPLY_TX:
			iwk_tx_intr(sc, desc, data);
			break;

		case REPLY_ALIVE:
			iwk_ucode_alive(sc, desc);
			break;

		case CARD_STATE_NOTIFICATION:
		{
			uint32_t *status = (uint32_t *)(desc + 1);

			IWK_DBG((IWK_DEBUG_RADIO, "state changed to %x\n",
			    LE_32(*status)));

			if (LE_32(*status) & 1) {
				/*
				 * the radio button has to be pushed(OFF). It
				 * is considered as a hw error, the
				 * iwk_thread() tries to recover it after the
				 * button is pushed again(ON)
				 */
				cmn_err(CE_NOTE,
				    "iwk: Radio transmitter is off\n");
				sc->sc_ostate = sc->sc_ic.ic_state;
				ieee80211_new_state(&sc->sc_ic,
				    IEEE80211_S_INIT, -1);
				sc->sc_flags |=
				    (IWK_F_HW_ERR_RECOVER | IWK_F_RADIO_OFF);
			}
			break;
		}
		case SCAN_START_NOTIFICATION:
		{
			iwk_start_scan_t *scan =
			    (iwk_start_scan_t *)(desc + 1);

			IWK_DBG((IWK_DEBUG_SCAN,
			    "scanning channel %d status %x\n",
			    scan->chan, LE_32(scan->status)));

			ic->ic_curchan = &ic->ic_sup_channels[scan->chan];
			break;
		}
		case SCAN_COMPLETE_NOTIFICATION:
			IWK_DBG((IWK_DEBUG_SCAN, "scan finished\n"));
			ieee80211_end_scan(ic);
			break;
		}

		sc->sc_rxq.cur = (sc->sc_rxq.cur + 1) % RX_QUEUE_SIZE;
	}

	/*
	 * driver dealt with what reveived in rx queue and tell the information
	 * to the firmware.
	 */
	index = (index == 0) ? RX_QUEUE_SIZE - 1 : index - 1;
	IWK_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, index & (~7));

	mutex_enter(&sc->sc_glock);
	/* re-enable interrupts */
	IWK_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);
	sc->sc_rx_softint_pending = 0;
	mutex_exit(&sc->sc_glock);

	return (DDI_INTR_CLAIMED);
}

static uint_t
iwk_intr(caddr_t arg)
{
	iwk_sc_t *sc = (iwk_sc_t *)arg;
	uint32_t r, rfh;

	mutex_enter(&sc->sc_glock);

	if (sc->sc_flags & IWK_F_SUSPEND) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	r = IWK_READ(sc, CSR_INT);
	if (r == 0 || r == 0xffffffff) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_UNCLAIMED);
	}

	IWK_DBG((IWK_DEBUG_INTR, "interrupt reg %x\n", r));

	rfh = IWK_READ(sc, CSR_FH_INT_STATUS);
	IWK_DBG((IWK_DEBUG_INTR, "FH interrupt reg %x\n", rfh));
	/* disable interrupts */
	IWK_WRITE(sc, CSR_INT_MASK, 0);
	/* ack interrupts */
	IWK_WRITE(sc, CSR_INT, r);
	IWK_WRITE(sc, CSR_FH_INT_STATUS, rfh);

	if (sc->sc_rx_softint_id == NULL) {
		mutex_exit(&sc->sc_glock);
		return (DDI_INTR_CLAIMED);
	}

	if (r & (BIT_INT_SWERROR | BIT_INT_ERR)) {
		IWK_DBG((IWK_DEBUG_FW, "fatal firmware error\n"));
		mutex_exit(&sc->sc_glock);
		iwk_stop(sc);
		sc->sc_ostate = sc->sc_ic.ic_state;
		ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		sc->sc_flags |= IWK_F_HW_ERR_RECOVER;
		return (DDI_INTR_CLAIMED);
	}

	if (r & BIT_INT_RF_KILL) {
		IWK_DBG((IWK_DEBUG_RADIO, "RF kill\n"));
	}

	if ((r & (BIT_INT_FH_RX | BIT_INT_SW_RX)) ||
	    (rfh & FH_INT_RX_MASK)) {
		sc->sc_rx_softint_pending = 1;
		ddi_trigger_softintr(sc->sc_rx_softint_id);
	}

	if (r & BIT_INT_ALIVE)	{
		IWK_DBG((IWK_DEBUG_FW, "firmware initialized.\n"));
	}

	/* re-enable interrupts */
	IWK_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);
	mutex_exit(&sc->sc_glock);

	return (DDI_INTR_CLAIMED);
}

static uint8_t
iwk_rate_to_plcp(int rate)
{
	uint8_t ret;

	switch (rate) {
	/* CCK rates */
	case 2:
		ret = 0xa;
		break;
	case 4:
		ret = 0x14;
		break;
	case 11:
		ret = 0x37;
		break;
	case 22:
		ret = 0x6e;
		break;
	/* OFDM rates */
	case 12:
		ret = 0xd;
		break;
	case 18:
		ret = 0xf;
		break;
	case 24:
		ret = 0x5;
		break;
	case 36:
		ret = 0x7;
		break;
	case 48:
		ret = 0x9;
		break;
	case 72:
		ret = 0xb;
		break;
	case 96:
		ret = 0x1;
		break;
	case 108:
		ret = 0x3;
		break;
	default:
		ret = 0;
		break;
	}
	return (ret);
}

static mblk_t *
iwk_m_tx(void *arg, mblk_t *mp)
{
	iwk_sc_t	*sc = (iwk_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	mblk_t			*next;

	if (sc->sc_flags & IWK_F_SUSPEND) {
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
		if (iwk_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != 0) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

/* ARGSUSED */
static int
iwk_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	iwk_sc_t *sc = (iwk_sc_t *)ic;
	iwk_tx_ring_t *ring;
	iwk_tx_desc_t *desc;
	iwk_tx_data_t *data;
	iwk_cmd_t *cmd;
	iwk_tx_cmd_t *tx;
	ieee80211_node_t *in;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k = NULL;
	mblk_t *m, *m0;
	int rate, hdrlen, len, len0, mblen, off, err = IWK_SUCCESS;
	uint16_t masks = 0;

	ring = &sc->sc_txq[0];
	data = &ring->data[ring->cur];
	desc = data->desc;
	cmd = data->cmd;
	bzero(desc, sizeof (*desc));
	bzero(cmd, sizeof (*cmd));

	mutex_enter(&sc->sc_tx_lock);
	if (sc->sc_flags & IWK_F_SUSPEND) {
		mutex_exit(&sc->sc_tx_lock);
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		err = IWK_FAIL;
		goto exit;
	}

	if (ring->queued > ring->count - 64) {
		IWK_DBG((IWK_DEBUG_TX, "iwk_send(): no txbuf\n"));
		sc->sc_need_reschedule = 1;
		mutex_exit(&sc->sc_tx_lock);
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		sc->sc_tx_nobuf++;
		err = IWK_FAIL;
		goto exit;
	}
	mutex_exit(&sc->sc_tx_lock);

	hdrlen = sizeof (struct ieee80211_frame);

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) { /* can not alloc buf, drop this package */
		cmn_err(CE_WARN,
		    "iwk_send(): failed to allocate msgbuf\n");
		freemsg(mp);
		err = IWK_SUCCESS;
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
		cmn_err(CE_WARN, "iwk_send(): failed to find tx node\n");
		freemsg(m);
		sc->sc_tx_err++;
		err = IWK_SUCCESS;
		goto exit;
	}
	(void) ieee80211_encap(ic, m, in);

	cmd->hdr.type = REPLY_TX;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur;

	tx = (iwk_tx_cmd_t *)cmd->data;
	tx->tx_flags = 0;

	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		tx->tx_flags &= ~(LE_32(TX_CMD_FLG_ACK_MSK));
	} else {
		tx->tx_flags |= LE_32(TX_CMD_FLG_ACK_MSK);
	}

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			freemsg(m);
			sc->sc_tx_err++;
			err = IWK_SUCCESS;
			goto exit;
		}

		if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_AES_CCM) {
			tx->sec_ctl = 2; /* for CCMP */
			tx->tx_flags |= LE_32(TX_CMD_FLG_ACK_MSK);
			(void) memcpy(&tx->key, k->wk_key, k->wk_keylen);
		}

		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	len = msgdsize(m);

#ifdef DEBUG
	if (iwk_dbg_flags & IWK_DEBUG_TX)
		ieee80211_dump_pkt((uint8_t *)wh, hdrlen, 0, 0);
#endif

	/* pickup a rate */
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
		/* mgmt frames are sent at 1M */
		rate = in->in_rates.ir_rates[0];
	} else {
		/*
		 * do it here for the software way rate control.
		 * later for rate scaling in hardware.
		 * maybe like the following, for management frame:
		 * tx->initial_rate_index = LINK_QUAL_MAX_RETRY_NUM - 1;
		 * for data frame:
		 * tx->tx_flags |= (LE_32(TX_CMD_FLG_STA_RATE_MSK));
		 * rate = in->in_rates.ir_rates[in->in_txrate];
		 * tx->initial_rate_index = 1;
		 *
		 * now the txrate is determined in tx cmd flags, set to the
		 * max value 54M for 11g and 11M for 11b.
		 */

		if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
			rate = ic->ic_fixed_rate;
		} else {
			rate = in->in_rates.ir_rates[in->in_txrate];
		}
	}
	rate &= IEEE80211_RATE_VAL;
	IWK_DBG((IWK_DEBUG_TX, "tx rate[%d of %d] = %x",
	    in->in_txrate, in->in_rates.ir_nrates, rate));

	tx->tx_flags |= (LE_32(TX_CMD_FLG_SEQ_CTL_MSK));

	len0 = roundup(4 + sizeof (iwk_tx_cmd_t) + hdrlen, 4);
	if (len0 != (4 + sizeof (iwk_tx_cmd_t) + hdrlen))
		tx->tx_flags |= TX_CMD_FLG_MH_PAD_MSK;

	/* retrieve destination node's id */
	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		tx->sta_id = IWK_BROADCAST_ID;
	} else {
		tx->sta_id = IWK_AP_ID;
	}

	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
		/* tell h/w to set timestamp in probe responses */
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			tx->tx_flags |= LE_32(TX_CMD_FLG_TSF_MSK);

		if (((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
		    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_REASSOC_REQ))
			tx->timeout.pm_frame_timeout = 3;
		else
			tx->timeout.pm_frame_timeout = 2;
	} else
		tx->timeout.pm_frame_timeout = 0;
	if (rate == 2 || rate == 4 || rate == 11 || rate == 22)
		masks |= RATE_MCS_CCK_MSK;

	masks |= RATE_MCS_ANT_B_MSK;
	tx->rate.r.rate_n_flags = (iwk_rate_to_plcp(rate) | masks);

	IWK_DBG((IWK_DEBUG_TX, "tx flag = %x",
	    tx->tx_flags));

	tx->rts_retry_limit = 60;
	tx->data_retry_limit = 15;

	tx->stop_time.life_time  = LE_32(0xffffffff);

	tx->len = LE_16(len);

	tx->dram_lsb_ptr =
	    data->paddr_cmd + 4 + offsetof(iwk_tx_cmd_t, scratch);
	tx->dram_msb_ptr = 0;
	tx->driver_txop = 0;
	tx->next_frame_len = 0;

	(void) memcpy(tx + 1, m->b_rptr, hdrlen);
	m->b_rptr += hdrlen;
	(void) memcpy(data->dma_data.mem_va, m->b_rptr, len - hdrlen);

	IWK_DBG((IWK_DEBUG_TX, "sending data: qid=%d idx=%d len=%d",
	    ring->qid, ring->cur, len));

	/*
	 * first segment includes the tx cmd plus the 802.11 header,
	 * the second includes the remaining of the 802.11 frame.
	 */
	desc->val0 = LE_32(2 << 24);
	desc->pa[0].tb1_addr = LE_32(data->paddr_cmd);
	desc->pa[0].val1 = ((len0 << 4) & 0xfff0) |
	    ((data->dma_data.cookie.dmac_address & 0xffff) << 16);
	desc->pa[0].val2 =
	    ((data->dma_data.cookie.dmac_address & 0xffff0000) >> 16) |
	    ((len - hdrlen) << 20);
	IWK_DBG((IWK_DEBUG_TX, "phy addr1 = 0x%x phy addr2 = 0x%x "
	    "len1 = 0x%x, len2 = 0x%x val1 = 0x%x val2 = 0x%x",
	    data->paddr_cmd, data->dma_data.cookie.dmac_address,
	    len0, len - hdrlen, desc->pa[0].val1, desc->pa[0].val2));

	mutex_enter(&sc->sc_tx_lock);
	ring->queued++;
	mutex_exit(&sc->sc_tx_lock);

	/* kick ring */
	sc->sc_shared->queues_byte_cnt_tbls[ring->qid].tfd_offset[ring->cur].val
	    = 8 + len;
	if (ring->cur < IWK_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWK_QUEUE_SIZE + ring->cur].val = 8 + len;
	}

	IWK_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
	IWK_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	ring->cur = (ring->cur + 1) % ring->count;
	IWK_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);
	freemsg(m);
	/* release node reference */
	ieee80211_free_node(in);

	ic->ic_stats.is_tx_bytes += len;
	ic->ic_stats.is_tx_frags++;

	if (sc->sc_tx_timer == 0)
		sc->sc_tx_timer = 10;
exit:
	return (err);
}

static void
iwk_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	iwk_sc_t	*sc  = (iwk_sc_t *)arg;
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
			(void) ieee80211_new_state(ic,
			    IEEE80211_S_SCAN, -1);
		}
	}
}

/*ARGSUSED*/
static int
iwk_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	iwk_sc_t	*sc  = (iwk_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	struct ieee80211_rateset *rs = &in->in_rates;

	mutex_enter(&sc->sc_glock);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) /2 * 1000000;
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

	return (IWK_SUCCESS);

}

static int
iwk_m_start(void *arg)
{
	iwk_sc_t *sc = (iwk_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	int err;

	err = iwk_init(sc);

	if (err != IWK_SUCCESS) {
		/*
		 * The hw init err(eg. RF is OFF). Return Success to make
		 * the 'plumb' succeed. The iwk_thread() tries to re-init
		 * background.
		 */
		mutex_enter(&sc->sc_glock);
		sc->sc_flags |= IWK_F_HW_ERR_RECOVER;
		mutex_exit(&sc->sc_glock);
		return (IWK_SUCCESS);
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	mutex_enter(&sc->sc_glock);
	sc->sc_flags |= IWK_F_RUNNING;
	mutex_exit(&sc->sc_glock);

	return (IWK_SUCCESS);
}

static void
iwk_m_stop(void *arg)
{
	iwk_sc_t *sc = (iwk_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;

	iwk_stop(sc);
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	mutex_enter(&sc->sc_mt_lock);
	sc->sc_flags &= ~IWK_F_HW_ERR_RECOVER;
	sc->sc_flags &= ~IWK_F_RATE_AUTO_CTL;
	mutex_exit(&sc->sc_mt_lock);
	mutex_enter(&sc->sc_glock);
	sc->sc_flags &= ~IWK_F_RUNNING;
	mutex_exit(&sc->sc_glock);
}

/*ARGSUSED*/
static int
iwk_m_unicst(void *arg, const uint8_t *macaddr)
{
	iwk_sc_t *sc = (iwk_sc_t *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	int err;

	if (!IEEE80211_ADDR_EQ(ic->ic_macaddr, macaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
		mutex_enter(&sc->sc_glock);
		err = iwk_config(sc);
		mutex_exit(&sc->sc_glock);
		if (err != IWK_SUCCESS) {
			cmn_err(CE_WARN,
			    "iwk_m_unicst(): "
			    "failed to configure device\n");
			goto fail;
		}
	}
	return (IWK_SUCCESS);
fail:
	return (err);
}

/*ARGSUSED*/
static int
iwk_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	return (IWK_SUCCESS);
}

/*ARGSUSED*/
static int
iwk_m_promisc(void *arg, boolean_t on)
{
	return (IWK_SUCCESS);
}

static void
iwk_thread(iwk_sc_t *sc)
{
	ieee80211com_t	*ic = &sc->sc_ic;
	clock_t clk;
	int times = 0, err, n = 0, timeout = 0;
	uint32_t tmp;

	mutex_enter(&sc->sc_mt_lock);
	while (sc->sc_mf_thread_switch) {
		tmp = IWK_READ(sc, CSR_GP_CNTRL);
		if (tmp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) {
			sc->sc_flags &= ~IWK_F_RADIO_OFF;
		} else {
			sc->sc_flags |= IWK_F_RADIO_OFF;
		}
		/*
		 * If in SUSPEND or the RF is OFF, do nothing
		 */
		if ((sc->sc_flags & IWK_F_SUSPEND) ||
		    (sc->sc_flags & IWK_F_RADIO_OFF)) {
			mutex_exit(&sc->sc_mt_lock);
			delay(drv_usectohz(100000));
			mutex_enter(&sc->sc_mt_lock);
			continue;
		}

		/*
		 * recovery fatal error
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IWK_F_HW_ERR_RECOVER)) {

			IWK_DBG((IWK_DEBUG_FW,
			    "iwk_thread(): "
			    "try to recover fatal hw error: %d\n", times++));

			iwk_stop(sc);
			ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

			mutex_exit(&sc->sc_mt_lock);
			delay(drv_usectohz(2000000 + n*500000));
			mutex_enter(&sc->sc_mt_lock);
			err = iwk_init(sc);
			if (err != IWK_SUCCESS) {
				n++;
				if (n < 20)
					continue;
			}
			n = 0;
			if (!err)
				sc->sc_flags |= IWK_F_RUNNING;
			sc->sc_flags &= ~IWK_F_HW_ERR_RECOVER;
			mutex_exit(&sc->sc_mt_lock);
			delay(drv_usectohz(2000000));
			if (sc->sc_ostate != IEEE80211_S_INIT)
				ieee80211_new_state(ic, IEEE80211_S_SCAN, 0);
			mutex_enter(&sc->sc_mt_lock);
		}

		/*
		 * rate ctl
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IWK_F_RATE_AUTO_CTL)) {
			clk = ddi_get_lbolt();
			if (clk > sc->sc_clk + drv_usectohz(500000)) {
				iwk_amrr_timeout(sc);
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
					sc->sc_flags |= IWK_F_HW_ERR_RECOVER;
					sc->sc_ostate = IEEE80211_S_RUN;
					IWK_DBG((IWK_DEBUG_FW,
					    "iwk_thread(): try to recover from"
					    " 'send fail\n"));
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
 * Send a command to the firmware.
 */
static int
iwk_cmd(iwk_sc_t *sc, int code, const void *buf, int size, int async)
{
	iwk_tx_ring_t *ring = &sc->sc_txq[IWK_CMD_QUEUE_NUM];
	iwk_tx_desc_t *desc;
	iwk_cmd_t *cmd;

	ASSERT(size <= sizeof (cmd->data));
	ASSERT(mutex_owned(&sc->sc_glock));

	IWK_DBG((IWK_DEBUG_CMD, "iwk_cmd() code[%d]", code));
	desc = ring->data[ring->cur].desc;
	cmd = ring->data[ring->cur].cmd;

	cmd->hdr.type = (uint8_t)code;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur;
	(void) memcpy(cmd->data, buf, size);
	(void) memset(desc, 0, sizeof (*desc));

	desc->val0 = LE_32(1 << 24);
	desc->pa[0].tb1_addr =
	    (uint32_t)(ring->data[ring->cur].paddr_cmd & 0xffffffff);
	desc->pa[0].val1 = ((4 + size) << 4) & 0xfff0;

	/* kick cmd ring XXX */
	sc->sc_shared->queues_byte_cnt_tbls[ring->qid]
	    .tfd_offset[ring->cur].val = 8;
	if (ring->cur < IWK_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid]
		    .tfd_offset[IWK_QUEUE_SIZE + ring->cur].val = 8;
	}
	ring->cur = (ring->cur + 1) % ring->count;
	IWK_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	if (async)
		return (IWK_SUCCESS);
	else {
		clock_t clk;
		sc->sc_flags &= ~IWK_F_CMD_DONE;
		clk = ddi_get_lbolt() + drv_usectohz(2000000);
		while (!(sc->sc_flags & IWK_F_CMD_DONE)) {
			if (cv_timedwait(&sc->sc_cmd_cv, &sc->sc_glock, clk)
			    < 0)
				break;
		}
		if (sc->sc_flags & IWK_F_CMD_DONE)
			return (IWK_SUCCESS);
		else
			return (IWK_FAIL);
	}
}

static void
iwk_set_led(iwk_sc_t *sc, uint8_t id, uint8_t off, uint8_t on)
{
	iwk_led_cmd_t led;

	led.interval = LE_32(100000);	/* unit: 100ms */
	led.id = id;
	led.off = off;
	led.on = on;

	(void) iwk_cmd(sc, REPLY_LEDS_CMD, &led, sizeof (led), 1);
}

static int
iwk_hw_set_before_auth(iwk_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	iwk_tx_power_table_cmd_t txpower;
	iwk_add_sta_t node;
	iwk_link_quality_cmd_t link_quality;
	struct ieee80211_rateset rs;
	uint16_t masks = 0, rate;
	int i, err;

	/* update adapter's configuration according the info of target AP */
	IEEE80211_ADDR_COPY(sc->sc_config.bssid, in->in_bssid);
	sc->sc_config.chan = ieee80211_chan2ieee(ic, in->in_chan);
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		sc->sc_config.cck_basic_rates  = 0x03;
		sc->sc_config.ofdm_basic_rates = 0;
	} else if ((in->in_chan != IEEE80211_CHAN_ANYC) &&
	    (IEEE80211_IS_CHAN_5GHZ(in->in_chan))) {
		sc->sc_config.cck_basic_rates  = 0;
		sc->sc_config.ofdm_basic_rates = 0x15;
	} else { /* assume 802.11b/g */
		sc->sc_config.cck_basic_rates  = 0x0f;
		sc->sc_config.ofdm_basic_rates = 0xff;
	}

	sc->sc_config.flags &= ~LE_32(RXON_FLG_SHORT_PREAMBLE_MSK |
	    RXON_FLG_SHORT_SLOT_MSK);

	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		sc->sc_config.flags |= LE_32(RXON_FLG_SHORT_SLOT_MSK);
	else
		sc->sc_config.flags &= LE_32(~RXON_FLG_SHORT_SLOT_MSK);

	if (ic->ic_flags & IEEE80211_F_SHPREAMBLE)
		sc->sc_config.flags |= LE_32(RXON_FLG_SHORT_PREAMBLE_MSK);
	else
		sc->sc_config.flags &= LE_32(~RXON_FLG_SHORT_PREAMBLE_MSK);

	IWK_DBG((IWK_DEBUG_80211, "config chan %d flags %x "
	    "filter_flags %x  cck %x ofdm %x"
	    " bssid:%02x:%02x:%02x:%02x:%02x:%2x\n",
	    sc->sc_config.chan, sc->sc_config.flags,
	    sc->sc_config.filter_flags,
	    sc->sc_config.cck_basic_rates, sc->sc_config.ofdm_basic_rates,
	    sc->sc_config.bssid[0], sc->sc_config.bssid[1],
	    sc->sc_config.bssid[2], sc->sc_config.bssid[3],
	    sc->sc_config.bssid[4], sc->sc_config.bssid[5]));
	err = iwk_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwk_rxon_cmd_t), 1);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_hw_set_before_auth():"
		    " failed to config chan%d\n",
		    sc->sc_config.chan);
		return (err);
	}

	/*
	 * set Tx power for 2.4GHz channels
	 * (need further investigation. fix tx power at present)
	 */
	(void) memset(&txpower, 0, sizeof (txpower));
	txpower.band = 1; /* for 2.4G */
	txpower.channel = sc->sc_config.chan;
	txpower.channel_normal_width = 0;
	for (i = 0; i < POWER_TABLE_NUM_HT_OFDM_ENTRIES; i++) {
		txpower.tx_power.ht_ofdm_power[i].s
		    .ramon_tx_gain = 0x3f3f;
		txpower.tx_power.ht_ofdm_power[i].s
		    .dsp_predis_atten = 110 | (110 << 8);
	}
	txpower.tx_power.ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES].
	    s.ramon_tx_gain = 0x3f3f;
	txpower.tx_power.ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES].
	    s.dsp_predis_atten = 110 | (110 << 8);
	err = iwk_cmd(sc, REPLY_TX_PWR_TABLE_CMD, &txpower,
	    sizeof (txpower), 1);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_hw_set_before_auth():"
		    " failed to set txpower\n");
		return (err);
	}

	/* add default AP node */
	(void) memset(&node, 0, sizeof (node));
	IEEE80211_ADDR_COPY(node.bssid, in->in_bssid);
	node.id = IWK_AP_ID;
	err = iwk_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_hw_set_before_auth():"
		    " failed to add BSS node\n");
		return (err);
	}

	/* TX_LINK_QUALITY cmd ? */
	(void) memset(&link_quality, 0, sizeof (link_quality));
	rs = ic->ic_sup_rates[ieee80211_chan2mode(ic, ic->ic_curchan)];
	for (i = 0; i < LINK_QUAL_MAX_RETRY_NUM; i++) {
		if (i < rs.ir_nrates)
			rate = rs.ir_rates[rs.ir_nrates - i];
		else
			rate = 2;
		if (rate == 2 || rate == 4 || rate == 11 || rate == 22)
			masks |= RATE_MCS_CCK_MSK;
		masks |= RATE_MCS_ANT_B_MSK;
		masks &= ~RATE_MCS_ANT_A_MSK;
		link_quality.rate_n_flags[i] =
		    iwk_rate_to_plcp(rate) | masks;
	}

	link_quality.general_params.single_stream_ant_msk = 2;
	link_quality.general_params.dual_stream_ant_msk = 3;
	link_quality.agg_params.agg_dis_start_th = 3;
	link_quality.agg_params.agg_time_limit = LE_16(4000);
	link_quality.sta_id = IWK_AP_ID;
	err = iwk_cmd(sc, REPLY_TX_LINK_QUALITY_CMD, &link_quality,
	    sizeof (link_quality), 1);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_hw_set_before_auth(): "
		    "failed to config link quality table\n");
		return (err);
	}

	return (IWK_SUCCESS);
}

/*
 * Send a scan request(assembly scan cmd) to the firmware.
 */
static int
iwk_scan(iwk_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwk_tx_ring_t *ring = &sc->sc_txq[IWK_CMD_QUEUE_NUM];
	iwk_tx_desc_t *desc;
	iwk_tx_data_t *data;
	iwk_cmd_t *cmd;
	iwk_scan_hdr_t *hdr;
	iwk_scan_chan_t *chan;
	struct ieee80211_frame *wh;
	ieee80211_node_t *in = ic->ic_bss;
	struct ieee80211_rateset *rs;
	enum ieee80211_phymode mode;
	uint8_t *frm;
	int i, pktlen, nrates;

	data = &ring->data[ring->cur];
	desc = data->desc;
	cmd = (iwk_cmd_t *)data->dma_data.mem_va;

	cmd->hdr.type = REPLY_SCAN_CMD;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur | 0x40;

	hdr = (iwk_scan_hdr_t *)cmd->data;
	(void) memset(hdr, 0, sizeof (iwk_scan_hdr_t));
	hdr->nchan = 11;
	hdr->quiet_time = LE_16(5);
	hdr->quiet_plcp_th = LE_16(1);

	hdr->flags = RXON_FLG_BAND_24G_MSK | RXON_FLG_AUTO_DETECT_MSK;
	hdr->rx_chain = RXON_RX_CHAIN_DRIVER_FORCE_MSK |
	    LE_16((0x7 << RXON_RX_CHAIN_VALID_POS) |
	    (0x6 << RXON_RX_CHAIN_FORCE_SEL_POS) |
	    (0x7 << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS));

	hdr->tx_cmd.tx_flags = TX_CMD_FLG_SEQ_CTL_MSK;
	hdr->tx_cmd.sta_id = IWK_BROADCAST_ID;
	hdr->tx_cmd.stop_time.life_time = 0xffffffff;
	hdr->tx_cmd.tx_flags |= (0x200);
	hdr->tx_cmd.rate.r.rate_n_flags = iwk_rate_to_plcp(2);
	hdr->tx_cmd.rate.r.rate_n_flags |=
	    (RATE_MCS_ANT_B_MSK|RATE_MCS_CCK_MSK);
	hdr->direct_scan[0].len = ic->ic_des_esslen;
	hdr->direct_scan[0].id  = IEEE80211_ELEMID_SSID;

	if (ic->ic_des_esslen)
		bcopy(ic->ic_des_essid, hdr->direct_scan[0].ssid,
		    ic->ic_des_esslen);
	else
		bzero(hdr->direct_scan[0].ssid,
		    sizeof (hdr->direct_scan[0].ssid));
	/*
	 * a probe request frame is required after the REPLY_SCAN_CMD
	 */
	wh = (struct ieee80211_frame *)(hdr + 1);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
	    IEEE80211_FC0_SUBTYPE_PROBE_REQ;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	(void) memset(wh->i_addr1, 0xff, 6);
	IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_macaddr);
	(void) memset(wh->i_addr3, 0xff, 6);
	*(uint16_t *)&wh->i_dur[0] = 0;
	*(uint16_t *)&wh->i_seq[0] = 0;

	frm = (uint8_t *)(wh + 1);

	/* essid IE */
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = in->in_esslen;
	(void) memcpy(frm, in->in_essid, in->in_esslen);
	frm += in->in_esslen;

	mode = ieee80211_chan2mode(ic, ic->ic_curchan);
	rs = &ic->ic_sup_rates[mode];

	/* supported rates IE */
	*frm++ = IEEE80211_ELEMID_RATES;
	nrates = rs->ir_nrates;
	if (nrates > IEEE80211_RATE_SIZE)
		nrates = IEEE80211_RATE_SIZE;
	*frm++ = (uint8_t)nrates;
	(void) memcpy(frm, rs->ir_rates, nrates);
	frm += nrates;

	/* supported xrates IE */
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;
		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = (uint8_t)nrates;
		(void) memcpy(frm, rs->ir_rates + IEEE80211_RATE_SIZE, nrates);
		frm += nrates;
	}

	/* optionnal IE (usually for wpa) */
	if (ic->ic_opt_ie != NULL) {
		(void) memcpy(frm, ic->ic_opt_ie, ic->ic_opt_ie_len);
		frm += ic->ic_opt_ie_len;
	}

	/* setup length of probe request */
	hdr->tx_cmd.len = LE_16(_PTRDIFF(frm, wh));
	hdr->len = hdr->nchan * sizeof (iwk_scan_chan_t) +
	    hdr->tx_cmd.len + sizeof (iwk_scan_hdr_t);

	/*
	 * the attribute of the scan channels are required after the probe
	 * request frame.
	 */
	chan = (iwk_scan_chan_t *)frm;
	for (i = 1; i <= hdr->nchan; i++, chan++) {
		chan->type = 3;
		chan->chan = (uint8_t)i;
		chan->tpc.tx_gain = 0x3f;
		chan->tpc.dsp_atten = 110;
		chan->active_dwell = LE_16(20);
		chan->passive_dwell = LE_16(120);

		frm += sizeof (iwk_scan_chan_t);
	}

	pktlen = _PTRDIFF(frm, cmd);

	(void) memset(desc, 0, sizeof (*desc));
	desc->val0 = LE_32(1 << 24);
	desc->pa[0].tb1_addr =
	    (uint32_t)(data->dma_data.cookie.dmac_address & 0xffffffff);
	desc->pa[0].val1 = (pktlen << 4) & 0xfff0;

	/*
	 * maybe for cmd, filling the byte cnt table is not necessary.
	 * anyway, we fill it here.
	 */
	sc->sc_shared->queues_byte_cnt_tbls[ring->qid]
	    .tfd_offset[ring->cur].val = 8;
	if (ring->cur < IWK_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid]
		    .tfd_offset[IWK_QUEUE_SIZE + ring->cur].val = 8;
	}

	/* kick cmd ring */
	ring->cur = (ring->cur + 1) % ring->count;
	IWK_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	return (IWK_SUCCESS);
}

static int
iwk_config(iwk_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwk_tx_power_table_cmd_t txpower;
	iwk_powertable_cmd_t powertable;
	iwk_bt_cmd_t bt;
	iwk_add_sta_t node;
	iwk_link_quality_cmd_t link_quality;
	int i, err;
	uint16_t masks = 0;

	/*
	 * set power mode. Disable power management at present, do it later
	 */
	(void) memset(&powertable, 0, sizeof (powertable));
	powertable.flags = LE_16(0x8);
	err = iwk_cmd(sc, POWER_TABLE_CMD, &powertable,
	    sizeof (powertable), 0);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_config(): failed to set power mode\n");
		return (err);
	}

	/* configure bt coexistence */
	(void) memset(&bt, 0, sizeof (bt));
	bt.flags = 3;
	bt.lead_time = 0xaa;
	bt.max_kill = 1;
	err = iwk_cmd(sc, REPLY_BT_CONFIG, &bt,
	    sizeof (bt), 0);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN,
		    "iwk_config(): "
		    "failed to configurate bt coexistence\n");
		return (err);
	}

	/* configure rxon */
	(void) memset(&sc->sc_config, 0, sizeof (iwk_rxon_cmd_t));
	IEEE80211_ADDR_COPY(sc->sc_config.node_addr, ic->ic_macaddr);
	IEEE80211_ADDR_COPY(sc->sc_config.wlap_bssid, ic->ic_macaddr);
	sc->sc_config.chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
	sc->sc_config.flags = (RXON_FLG_TSF2HOST_MSK | RXON_FLG_AUTO_DETECT_MSK
	    | RXON_FLG_BAND_24G_MSK);
	sc->sc_config.flags &= (~RXON_FLG_CCK_MSK);
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		sc->sc_config.dev_type = RXON_DEV_TYPE_ESS;
		sc->sc_config.filter_flags |= LE_32(RXON_FILTER_ACCEPT_GRP_MSK |
		    RXON_FILTER_DIS_DECRYPT_MSK |
		    RXON_FILTER_DIS_GRP_DECRYPT_MSK);
		break;
	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		sc->sc_config.dev_type = RXON_DEV_TYPE_IBSS;
		break;
	case IEEE80211_M_HOSTAP:
		sc->sc_config.dev_type = RXON_DEV_TYPE_AP;
		break;
	case IEEE80211_M_MONITOR:
		sc->sc_config.dev_type = RXON_DEV_TYPE_SNIFFER;
		sc->sc_config.filter_flags |= LE_32(RXON_FILTER_ACCEPT_GRP_MSK |
		    RXON_FILTER_CTL2HOST_MSK | RXON_FILTER_PROMISC_MSK);
		break;
	}
	sc->sc_config.cck_basic_rates  = 0x0f;
	sc->sc_config.ofdm_basic_rates = 0xff;

	sc->sc_config.ofdm_ht_single_stream_basic_rates = 0xff;
	sc->sc_config.ofdm_ht_dual_stream_basic_rates = 0xff;

	/* set antenna */

	sc->sc_config.rx_chain = RXON_RX_CHAIN_DRIVER_FORCE_MSK |
	    LE_16((0x7 << RXON_RX_CHAIN_VALID_POS) |
	    (0x6 << RXON_RX_CHAIN_FORCE_SEL_POS) |
	    (0x7 << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS));

	err = iwk_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwk_rxon_cmd_t), 0);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_config(): "
		    "failed to set configure command\n");
		return (err);
	}

	/*
	 * set Tx power for 2.4GHz channels
	 * (need further investigation. fix tx power at present)
	 */
	(void) memset(&txpower, 0, sizeof (txpower));
	txpower.band = 1; /* for 2.4G */
	txpower.channel = sc->sc_config.chan;
	txpower.channel_normal_width = 0;
	for (i = 0; i < POWER_TABLE_NUM_HT_OFDM_ENTRIES; i++) {
		txpower.tx_power.ht_ofdm_power[i]
		    .s.ramon_tx_gain = 0x3f3f;
		txpower.tx_power.ht_ofdm_power[i]
		    .s.dsp_predis_atten = 110 | (110 << 8);
	}
	txpower.tx_power.ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES]
	    .s.ramon_tx_gain = 0x3f3f;
	txpower.tx_power.ht_ofdm_power[POWER_TABLE_NUM_HT_OFDM_ENTRIES]
	    .s.dsp_predis_atten = 110 | (110 << 8);
	err = iwk_cmd(sc, REPLY_TX_PWR_TABLE_CMD, &txpower,
	    sizeof (txpower), 0);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_config(): failed to set txpower\n");
		return (err);
	}

	/* add broadcast node so that we can send broadcast frame */
	(void) memset(&node, 0, sizeof (node));
	(void) memset(node.bssid, 0xff, 6);
	node.id = IWK_BROADCAST_ID;
	err = iwk_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 0);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_config(): "
		    "failed to add broadcast node\n");
		return (err);
	}

	/* TX_LINK_QUALITY cmd ? */
	(void) memset(&link_quality, 0, sizeof (link_quality));
	for (i = 0; i < LINK_QUAL_MAX_RETRY_NUM; i++) {
		masks |= RATE_MCS_CCK_MSK;
		masks |= RATE_MCS_ANT_B_MSK;
		masks &= ~RATE_MCS_ANT_A_MSK;
		link_quality.rate_n_flags[i] = iwk_rate_to_plcp(2) | masks;
	}

	link_quality.general_params.single_stream_ant_msk = 2;
	link_quality.general_params.dual_stream_ant_msk = 3;
	link_quality.agg_params.agg_dis_start_th = 3;
	link_quality.agg_params.agg_time_limit = LE_16(4000);
	link_quality.sta_id = IWK_BROADCAST_ID;
	err = iwk_cmd(sc, REPLY_TX_LINK_QUALITY_CMD, &link_quality,
	    sizeof (link_quality), 0);
	if (err != IWK_SUCCESS) {
		cmn_err(CE_WARN, "iwk_config(): "
		    "failed to config link quality table\n");
		return (err);
	}

	return (IWK_SUCCESS);
}

static void
iwk_stop_master(iwk_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWK_READ(sc, CSR_RESET);
	IWK_WRITE(sc, CSR_RESET, tmp | CSR_RESET_REG_FLAG_STOP_MASTER);

	tmp = IWK_READ(sc, CSR_GP_CNTRL);
	if ((tmp & CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE) ==
	    CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE)
		return;

	for (n = 0; n < 2000; n++) {
		if (IWK_READ(sc, CSR_RESET) &
		    CSR_RESET_REG_FLAG_MASTER_DISABLED)
			break;
		DELAY(1000);
	}
	if (n == 2000)
		IWK_DBG((IWK_DEBUG_HW,
		    "timeout waiting for master stop\n"));
}

static int
iwk_power_up(iwk_sc_t *sc)
{
	uint32_t tmp;

	iwk_mac_access_enter(sc);
	tmp = iwk_reg_read(sc, ALM_APMG_PS_CTL);
	tmp &= ~APMG_PS_CTRL_REG_MSK_POWER_SRC;
	tmp |= APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN;
	iwk_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	iwk_mac_access_exit(sc);

	DELAY(5000);
	return (IWK_SUCCESS);
}

static int
iwk_preinit(iwk_sc_t *sc)
{
	uint32_t tmp;
	int n;
	uint8_t vlink;

	/* clear any pending interrupts */
	IWK_WRITE(sc, CSR_INT, 0xffffffff);

	tmp = IWK_READ(sc, CSR_GIO_CHICKEN_BITS);
	IWK_WRITE(sc, CSR_GIO_CHICKEN_BITS,
	    tmp | CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER);

	tmp = IWK_READ(sc, CSR_GP_CNTRL);
	IWK_WRITE(sc, CSR_GP_CNTRL, tmp | CSR_GP_CNTRL_REG_FLAG_INIT_DONE);

	/* wait for clock ready */
	for (n = 0; n < 1000; n++) {
		if (IWK_READ(sc, CSR_GP_CNTRL) &
		    CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY)
			break;
		DELAY(10);
	}
	if (n == 1000) {
		return (ETIMEDOUT);
	}
	iwk_mac_access_enter(sc);
	tmp = iwk_reg_read(sc, APMG_CLK_CTRL_REG);
	iwk_reg_write(sc, APMG_CLK_CTRL_REG, tmp |
	    APMG_CLK_REG_VAL_DMA_CLK_RQT | APMG_CLK_REG_VAL_BSM_CLK_RQT);

	DELAY(20);
	tmp = iwk_reg_read(sc, ALM_APMG_PCIDEV_STT);
	iwk_reg_write(sc, ALM_APMG_PCIDEV_STT, tmp |
	    APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE);
	iwk_mac_access_exit(sc);

	IWK_WRITE(sc, CSR_INT_COALESCING, 512 / 32); /* ??? */

	(void) iwk_power_up(sc);

	if ((sc->sc_rev & 0x80) == 0x80 && (sc->sc_rev & 0x7f) < 8) {
		tmp = ddi_get32(sc->sc_cfg_handle,
		    (uint32_t *)(sc->sc_cfg_base + 0xe8));
		ddi_put32(sc->sc_cfg_handle,
		    (uint32_t *)(sc->sc_cfg_base + 0xe8),
		    tmp & ~(1 << 11));
	}


	vlink = ddi_get8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + 0xf0));
	ddi_put8(sc->sc_cfg_handle, (uint8_t *)(sc->sc_cfg_base + 0xf0),
	    vlink & ~2);

	tmp = IWK_READ(sc, CSR_SW_VER);
	tmp |= CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
	    CSR_HW_IF_CONFIG_REG_BIT_MAC_SI | CSR_HW_IF_CONFIG_REG_BIT_KEDRON_R;
	IWK_WRITE(sc, CSR_SW_VER, tmp);

	/* make sure power supply on each part of the hardware */
	iwk_mac_access_enter(sc);
	tmp = iwk_reg_read(sc, ALM_APMG_PS_CTL);
	tmp |= APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ;
	iwk_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	DELAY(5);
	tmp = iwk_reg_read(sc, ALM_APMG_PS_CTL);
	tmp &= ~APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ;
	iwk_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	iwk_mac_access_exit(sc);
	return (IWK_SUCCESS);
}

/*
 * set up semphore flag to own EEPROM
 */
static int iwk_eep_sem_down(iwk_sc_t *sc)
{
	int count1, count2;
	uint32_t tmp;

	for (count1 = 0; count1 < 1000; count1++) {
		tmp = IWK_READ(sc, CSR_HW_IF_CONFIG_REG);
		IWK_WRITE(sc, CSR_HW_IF_CONFIG_REG,
		    tmp | CSR_HW_IF_CONFIG_REG_EEP_SEM);

		for (count2 = 0; count2 < 2; count2++) {
			if (IWK_READ(sc, CSR_HW_IF_CONFIG_REG) &
			    CSR_HW_IF_CONFIG_REG_EEP_SEM)
				return (IWK_SUCCESS);
			DELAY(10000);
		}
	}
	return (IWK_FAIL);
}

/*
 * reset semphore flag to release EEPROM
 */
static void iwk_eep_sem_up(iwk_sc_t *sc)
{
	uint32_t tmp;

	tmp = IWK_READ(sc, CSR_HW_IF_CONFIG_REG);
	IWK_WRITE(sc, CSR_HW_IF_CONFIG_REG,
	    tmp & (~CSR_HW_IF_CONFIG_REG_EEP_SEM));
}

/*
 * This function load all infomation in eeprom into iwk_eep
 * structure in iwk_sc_t structure
 */
static int iwk_eep_load(iwk_sc_t *sc)
{
	int i, rr;
	uint32_t rv, tmp, eep_gp;
	uint16_t addr, eep_sz = sizeof (sc->sc_eep_map);
	uint16_t *eep_p = (uint16_t *)&sc->sc_eep_map;

	/* read eeprom gp register in CSR */
	eep_gp = IWK_READ(sc, CSR_EEPROM_GP);
	if ((eep_gp & CSR_EEPROM_GP_VALID_MSK) ==
	    CSR_EEPROM_GP_BAD_SIGNATURE) {
		IWK_DBG((IWK_DEBUG_EEPROM, "not find eeprom\n"));
		return (IWK_FAIL);
	}

	rr = iwk_eep_sem_down(sc);
	if (rr != 0) {
		IWK_DBG((IWK_DEBUG_EEPROM, "driver failed to own EEPROM\n"));
		return (IWK_FAIL);
	}

	for (addr = 0; addr < eep_sz; addr += 2) {
		IWK_WRITE(sc, CSR_EEPROM_REG, addr<<1);
		tmp = IWK_READ(sc, CSR_EEPROM_REG);
		IWK_WRITE(sc, CSR_EEPROM_REG, tmp & ~(0x2));

		for (i = 0; i < 10; i++) {
			rv = IWK_READ(sc, CSR_EEPROM_REG);
			if (rv & 1)
				break;
			DELAY(10);
		}

		if (!(rv & 1)) {
			IWK_DBG((IWK_DEBUG_EEPROM,
			    "time out when read eeprome\n"));
			iwk_eep_sem_up(sc);
			return (IWK_FAIL);
		}

		eep_p[addr/2] = rv >> 16;
	}

	iwk_eep_sem_up(sc);
	return (IWK_SUCCESS);
}

/*
 * init mac address in ieee80211com_t struct
 */
static void iwk_get_mac_from_eep(iwk_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	struct iwk_eep *ep = &sc->sc_eep_map;

	IEEE80211_ADDR_COPY(ic->ic_macaddr, ep->mac_address);

	IWK_DBG((IWK_DEBUG_EEPROM, "mac:%2x:%2x:%2x:%2x:%2x:%2x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1], ic->ic_macaddr[2],
	    ic->ic_macaddr[3], ic->ic_macaddr[4], ic->ic_macaddr[5]));
}

static int
iwk_init(iwk_sc_t *sc)
{
	int qid, n, err;
	clock_t clk;
	uint32_t tmp;

	mutex_enter(&sc->sc_glock);
	sc->sc_flags &= ~IWK_F_FW_INIT;

	(void) iwk_preinit(sc);

	tmp = IWK_READ(sc, CSR_GP_CNTRL);
	if (!(tmp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)) {
		cmn_err(CE_WARN, "iwk_init(): Radio transmitter is off\n");
		goto fail1;
	}

	/* init Rx ring */
	iwk_mac_access_enter(sc);
	IWK_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);

	IWK_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, 0);
	IWK_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_BASE_REG,
	    sc->sc_rxq.dma_desc.cookie.dmac_address >> 8);

	IWK_WRITE(sc, FH_RSCSR_CHNL0_STTS_WPTR_REG,
	    ((uint32_t)(sc->sc_dma_sh.cookie.dmac_address +
	    offsetof(struct iwk_shared, val0)) >> 4));

	IWK_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG,
	    FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL |
	    FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL |
	    IWK_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K |
	    (RX_QUEUE_SIZE_LOG <<
	    FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT));
	iwk_mac_access_exit(sc);
	IWK_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG,
	    (RX_QUEUE_SIZE - 1) & ~0x7);

	/* init Tx rings */
	iwk_mac_access_enter(sc);
	iwk_reg_write(sc, SCD_TXFACT, 0);

	/* keep warm page */
	iwk_reg_write(sc, IWK_FH_KW_MEM_ADDR_REG,
	    sc->sc_dma_kw.cookie.dmac_address >> 4);

	for (qid = 0; qid < IWK_NUM_QUEUES; qid++) {
		IWK_WRITE(sc, FH_MEM_CBBC_QUEUE(qid),
		    sc->sc_txq[qid].dma_desc.cookie.dmac_address >> 8);
		IWK_WRITE(sc, IWK_FH_TCSR_CHNL_TX_CONFIG_REG(qid),
		    IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
		    IWK_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL);
	}
	iwk_mac_access_exit(sc);

	/* clear "radio off" and "disable command" bits */
	IWK_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	IWK_WRITE(sc, CSR_UCODE_DRV_GP1_CLR,
	    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);

	/* clear any pending interrupts */
	IWK_WRITE(sc, CSR_INT, 0xffffffff);

	/* enable interrupts */
	IWK_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	IWK_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	IWK_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	/*
	 * backup ucode data part for future use.
	 */
	(void) memcpy(sc->sc_dma_fw_data_bak.mem_va,
	    sc->sc_dma_fw_data.mem_va,
	    sc->sc_dma_fw_data.alength);

	for (n = 0; n < 2; n++) {
		/* load firmware init segment into NIC */
		err = iwk_load_firmware(sc);
		if (err != IWK_SUCCESS) {
			cmn_err(CE_WARN, "iwk_init(): "
			    "failed to setup boot firmware\n");
			continue;
		}

		/* now press "execute" start running */
		IWK_WRITE(sc, CSR_RESET, 0);
		break;
	}
	if (n == 2) {
		cmn_err(CE_WARN, "iwk_init(): " "failed to load firmware\n");
		goto fail1;
	}
	/* ..and wait at most one second for adapter to initialize */
	clk = ddi_get_lbolt() + drv_usectohz(2000000);
	while (!(sc->sc_flags & IWK_F_FW_INIT)) {
		if (cv_timedwait(&sc->sc_fw_cv, &sc->sc_glock, clk) < 0)
			break;
	}
	if (!(sc->sc_flags & IWK_F_FW_INIT)) {
		cmn_err(CE_WARN,
		    "iwk_init(): timeout waiting for firmware init\n");
		goto fail1;
	}

	/*
	 * at this point, the firmware is loaded OK, then config the hardware
	 * with the ucode API, including rxon, txpower, etc.
	 */
	err = iwk_config(sc);
	if (err) {
		cmn_err(CE_WARN, "iwk_init(): failed to configure device\n");
		goto fail1;
	}

	/* at this point, hardware may receive beacons :) */
	mutex_exit(&sc->sc_glock);
	return (IWK_SUCCESS);

fail1:
	err = IWK_FAIL;
	mutex_exit(&sc->sc_glock);
	return (err);
}

static void
iwk_stop(iwk_sc_t *sc)
{
	uint32_t tmp;
	int i;


	mutex_enter(&sc->sc_glock);

	IWK_WRITE(sc, CSR_RESET, CSR_RESET_REG_FLAG_NEVO_RESET);
	/* disable interrupts */
	IWK_WRITE(sc, CSR_INT_MASK, 0);
	IWK_WRITE(sc, CSR_INT, CSR_INI_SET_MASK);
	IWK_WRITE(sc, CSR_FH_INT_STATUS, 0xffffffff);

	/* reset all Tx rings */
	for (i = 0; i < IWK_NUM_QUEUES; i++)
		iwk_reset_tx_ring(sc, &sc->sc_txq[i]);

	/* reset Rx ring */
	iwk_reset_rx_ring(sc);

	iwk_mac_access_enter(sc);
	iwk_reg_write(sc, ALM_APMG_CLK_DIS, APMG_CLK_REG_VAL_DMA_CLK_RQT);
	iwk_mac_access_exit(sc);

	DELAY(5);

	iwk_stop_master(sc);

	sc->sc_tx_timer = 0;
	tmp = IWK_READ(sc, CSR_RESET);
	IWK_WRITE(sc, CSR_RESET, tmp | CSR_RESET_REG_FLAG_SW_RESET);
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

#define	IWK_AMRR_MIN_SUCCESS_THRESHOLD	 1
#define	IWK_AMRR_MAX_SUCCESS_THRESHOLD	15

static void
iwk_amrr_init(iwk_amrr_t *amrr)
{
	amrr->success = 0;
	amrr->recovery = 0;
	amrr->txcnt = amrr->retrycnt = 0;
	amrr->success_threshold = IWK_AMRR_MIN_SUCCESS_THRESHOLD;
}

static void
iwk_amrr_timeout(iwk_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	IWK_DBG((IWK_DEBUG_RATECTL, "iwk_amrr_timeout() enter\n"));
	if (ic->ic_opmode == IEEE80211_M_STA)
		iwk_amrr_ratectl(NULL, ic->ic_bss);
	else
		ieee80211_iterate_nodes(&ic->ic_sta, iwk_amrr_ratectl, NULL);
	sc->sc_clk = ddi_get_lbolt();
}

/* ARGSUSED */
static void
iwk_amrr_ratectl(void *arg, ieee80211_node_t *in)
{
	iwk_amrr_t *amrr = (iwk_amrr_t *)in;
	int need_change = 0;

	if (is_success(amrr) && is_enough(amrr)) {
		amrr->success++;
		if (amrr->success >= amrr->success_threshold &&
		    !is_max_rate(in)) {
			amrr->recovery = 1;
			amrr->success = 0;
			increase_rate(in);
			IWK_DBG((IWK_DEBUG_RATECTL,
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
				    IWK_AMRR_MAX_SUCCESS_THRESHOLD)
					amrr->success_threshold =
					    IWK_AMRR_MAX_SUCCESS_THRESHOLD;
			} else {
				amrr->success_threshold =
				    IWK_AMRR_MIN_SUCCESS_THRESHOLD;
			}
			decrease_rate(in);
			IWK_DBG((IWK_DEBUG_RATECTL,
			    "AMRR decreasing rate %d (txcnt=%d retrycnt=%d)\n",
			    in->in_txrate, amrr->txcnt, amrr->retrycnt));
			need_change = 1;
		}
		amrr->recovery = 0;	/* paper is incorrect */
	}

	if (is_enough(amrr) || need_change)
		reset_cnt(amrr);
}
