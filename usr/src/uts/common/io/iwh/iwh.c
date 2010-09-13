/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, Intel Corporation
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

/*
 * Intel(R) WiFi Link 5100/5300 Driver
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
#include <sys/net80211_ht.h>
#include <sys/varargs.h>
#include <sys/policy.h>
#include <sys/pci.h>

#include "iwh_calibration.h"
#include "iwh_hw.h"
#include "iwh_eeprom.h"
#include "iwh_var.h"
#include <inet/wifi_ioctl.h>

#ifdef DEBUG
#define	IWH_DEBUG_80211		(1 << 0)
#define	IWH_DEBUG_CMD		(1 << 1)
#define	IWH_DEBUG_DMA		(1 << 2)
#define	IWH_DEBUG_EEPROM	(1 << 3)
#define	IWH_DEBUG_FW		(1 << 4)
#define	IWH_DEBUG_HW		(1 << 5)
#define	IWH_DEBUG_INTR		(1 << 6)
#define	IWH_DEBUG_MRR		(1 << 7)
#define	IWH_DEBUG_PIO		(1 << 8)
#define	IWH_DEBUG_RX		(1 << 9)
#define	IWH_DEBUG_SCAN		(1 << 10)
#define	IWH_DEBUG_TX		(1 << 11)
#define	IWH_DEBUG_RATECTL	(1 << 12)
#define	IWH_DEBUG_RADIO		(1 << 13)
#define	IWH_DEBUG_RESUME	(1 << 14)
#define	IWH_DEBUG_CALIBRATION	(1 << 15)
#define	IWH_DEBUG_BA		(1 << 16)
#define	IWH_DEBUG_RXON		(1 << 17)
#define	IWH_DEBUG_HWRATE	(1 << 18)
#define	IWH_DEBUG_HTRATE	(1 << 19)
#define	IWH_DEBUG_QOS		(1 << 20)
/*
 * if want to see debug message of a given section,
 * please set this flag to one of above values
 */
uint32_t iwh_dbg_flags = 0;
#define	IWH_DBG(x) \
	iwh_dbg x
#else
#define	IWH_DBG(x)
#endif

#define	MS(v, f)    (((v) & f) >> f##_S)

static void	*iwh_soft_state_p = NULL;

/*
 * ucode will be compiled into driver image
 */
static uint8_t iwh_fw_5000_bin[] = {
#include "fw-iw/fw_5000/iwh_5000.ucode"
};

static uint8_t iwh_fw_5150_bin[] = {
#include "fw-iw/fw_5150/iwh_5150.ucode"
};

/*
 * DMA attributes for a shared page
 */
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

/*
 * DMA attributes for a keep warm DRAM descriptor
 */
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

/*
 * DMA attributes for a ring descriptor
 */
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

/*
 * DMA attributes for a cmd
 */
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

/*
 * DMA attributes for a rx buffer
 */
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

/*
 * DMA attributes for text and data part in the firmware
 */
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

/*
 * regs access attributes
 */
static ddi_device_acc_attr_t iwh_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptor
 */
static ddi_device_acc_attr_t iwh_dma_descattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes
 */
static ddi_device_acc_attr_t iwh_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static int	iwh_ring_init(iwh_sc_t *);
static void	iwh_ring_free(iwh_sc_t *);
static int	iwh_alloc_shared(iwh_sc_t *);
static void	iwh_free_shared(iwh_sc_t *);
static int	iwh_alloc_kw(iwh_sc_t *);
static void	iwh_free_kw(iwh_sc_t *);
static int	iwh_alloc_fw_dma(iwh_sc_t *);
static void	iwh_free_fw_dma(iwh_sc_t *);
static int	iwh_alloc_rx_ring(iwh_sc_t *);
static void	iwh_reset_rx_ring(iwh_sc_t *);
static void	iwh_free_rx_ring(iwh_sc_t *);
static int	iwh_alloc_tx_ring(iwh_sc_t *, iwh_tx_ring_t *,
    int, int);
static void	iwh_reset_tx_ring(iwh_sc_t *, iwh_tx_ring_t *);
static void	iwh_free_tx_ring(iwh_tx_ring_t *);
static ieee80211_node_t *iwh_node_alloc(ieee80211com_t *);
static void	iwh_node_free(ieee80211_node_t *);
static int	iwh_newstate(ieee80211com_t *, enum ieee80211_state, int);
static void	iwh_mac_access_enter(iwh_sc_t *);
static void	iwh_mac_access_exit(iwh_sc_t *);
static uint32_t	iwh_reg_read(iwh_sc_t *, uint32_t);
static void	iwh_reg_write(iwh_sc_t *, uint32_t, uint32_t);
static int	iwh_load_init_firmware(iwh_sc_t *);
static int	iwh_load_run_firmware(iwh_sc_t *);
static void	iwh_tx_intr(iwh_sc_t *, iwh_rx_desc_t *);
static void	iwh_cmd_intr(iwh_sc_t *, iwh_rx_desc_t *);
static uint_t   iwh_intr(caddr_t, caddr_t);
static int	iwh_eep_load(iwh_sc_t *);
static void	iwh_get_mac_from_eep(iwh_sc_t *);
static int	iwh_eep_sem_down(iwh_sc_t *);
static void	iwh_eep_sem_up(iwh_sc_t *);
static uint_t   iwh_rx_softintr(caddr_t, caddr_t);
static uint8_t	iwh_rate_to_plcp(int);
static int	iwh_cmd(iwh_sc_t *, int, const void *, int, int);
static void	iwh_set_led(iwh_sc_t *, uint8_t, uint8_t, uint8_t);
static int	iwh_hw_set_before_auth(iwh_sc_t *);
static int	iwh_scan(iwh_sc_t *);
static int	iwh_config(iwh_sc_t *);
static void	iwh_stop_master(iwh_sc_t *);
static int	iwh_power_up(iwh_sc_t *);
static int	iwh_preinit(iwh_sc_t *);
static int	iwh_init(iwh_sc_t *);
static void	iwh_stop(iwh_sc_t *);
static int	iwh_quiesce(dev_info_t *t);
static void	iwh_amrr_init(iwh_amrr_t *);
static void	iwh_amrr_timeout(iwh_sc_t *);
static void	iwh_amrr_ratectl(void *, ieee80211_node_t *);
static void	iwh_ucode_alive(iwh_sc_t *, iwh_rx_desc_t *);
static void	iwh_rx_phy_intr(iwh_sc_t *, iwh_rx_desc_t *);
static void	iwh_rx_mpdu_intr(iwh_sc_t *, iwh_rx_desc_t *);
static void	iwh_release_calib_buffer(iwh_sc_t *);
static int	iwh_init_common(iwh_sc_t *);
static uint8_t	*iwh_eep_addr_trans(iwh_sc_t *, uint32_t);
static int	iwh_put_seg_fw(iwh_sc_t *, uint32_t, uint32_t, uint32_t);
static	int	iwh_alive_common(iwh_sc_t *);
static void	iwh_save_calib_result(iwh_sc_t *, iwh_rx_desc_t *);
static int	iwh_tx_power_table(iwh_sc_t *, int);
static int	iwh_attach(dev_info_t *, ddi_attach_cmd_t);
static int	iwh_detach(dev_info_t *, ddi_detach_cmd_t);
static void	iwh_destroy_locks(iwh_sc_t *);
static int	iwh_send(ieee80211com_t *, mblk_t *, uint8_t);
static void	iwh_thread(iwh_sc_t *);
static int	iwh_run_state_config(iwh_sc_t *);
static int	iwh_fast_recover(iwh_sc_t *);
static int	iwh_wme_update(ieee80211com_t *);
static int	iwh_qosparam_to_hw(iwh_sc_t *, int);
static int	iwh_wme_to_qos_ac(int);
static uint16_t	iwh_cw_e_to_cw(uint8_t);
static int	iwh_wmeparam_check(struct wmeParams *);
static inline int	iwh_wme_tid_qos_ac(int);
static inline int	iwh_qos_ac_to_txq(int);
static int	iwh_wme_tid_to_txq(int);
static void	iwh_init_ht_conf(iwh_sc_t *);
static void	iwh_overwrite_11n_rateset(iwh_sc_t *);
static void	iwh_overwrite_ic_default(iwh_sc_t *);
static void	iwh_config_rxon_chain(iwh_sc_t *);
static int	iwh_add_ap_sta(iwh_sc_t *);
static int	iwh_ap_lq(iwh_sc_t *);
static void	iwh_recv_action(struct ieee80211_node *,
    const uint8_t *, const uint8_t *);
static int	iwh_send_action(struct ieee80211_node *,
    int, int, uint16_t[4]);
static int	iwh_is_max_rate(ieee80211_node_t *);
static int	iwh_is_min_rate(ieee80211_node_t *);
static void	iwh_increase_rate(ieee80211_node_t *);
static void	iwh_decrease_rate(ieee80211_node_t *);
static int	iwh_alloc_dma_mem(iwh_sc_t *, size_t,
    ddi_dma_attr_t *, ddi_device_acc_attr_t *,
    uint_t, iwh_dma_t *);
static void	iwh_free_dma_mem(iwh_dma_t *);
static int	iwh_reset_hw(iwh_sc_t *);

/*
 * GLD specific operations
 */
static int	iwh_m_stat(void *, uint_t, uint64_t *);
static int	iwh_m_start(void *);
static void	iwh_m_stop(void *);
static int	iwh_m_unicst(void *, const uint8_t *);
static int	iwh_m_multicst(void *, boolean_t, const uint8_t *);
static int	iwh_m_promisc(void *, boolean_t);
static mblk_t	*iwh_m_tx(void *, mblk_t *);
static void	iwh_m_ioctl(void *, queue_t *, mblk_t *);
static int	iwh_m_setprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, const void *wldp_buf);
static int	iwh_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length,
    void *wldp_buf);
static void	iwh_m_propinfo(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, mac_prop_info_handle_t mph);

/*
 * Supported rates for 802.11b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset iwh_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset iwh_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

/*
 * Default 11n reates supported by this station.
 */
extern struct ieee80211_htrateset ieee80211_rateset_11n;

/*
 * For mfthread only
 */
extern pri_t minclsyspri;

#define	DRV_NAME_SP	"iwh"

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(iwh_devops, nulldev, nulldev, iwh_attach,
    iwh_detach, nodev, NULL, D_MP, NULL, iwh_quiesce);

static struct modldrv iwh_modldrv = {
	&mod_driverops,
	"Intel(R) ShirleyPeak/EchoPeak driver(N)",
	&iwh_devops
};

static struct modlinkage iwh_modlinkage = {
	MODREV_1,
	&iwh_modldrv,
	NULL
};

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&iwh_soft_state_p,
	    sizeof (iwh_sc_t), 1);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	mac_init_ops(&iwh_devops, DRV_NAME_SP);
	status = mod_install(&iwh_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&iwh_devops);
		ddi_soft_state_fini(&iwh_soft_state_p);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&iwh_modlinkage);
	if (DDI_SUCCESS == status) {
		mac_fini_ops(&iwh_devops);
		ddi_soft_state_fini(&iwh_soft_state_p);
	}

	return (status);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&iwh_modlinkage, mip));
}

/*
 * Mac Call Back entries
 */
mac_callbacks_t	iwh_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	iwh_m_stat,
	iwh_m_start,
	iwh_m_stop,
	iwh_m_promisc,
	iwh_m_multicst,
	iwh_m_unicst,
	iwh_m_tx,
	NULL,
	iwh_m_ioctl,
	NULL,
	NULL,
	NULL,
	iwh_m_setprop,
	iwh_m_getprop,
	iwh_m_propinfo
};

#ifdef DEBUG
void
iwh_dbg(uint32_t flags, const char *fmt, ...)
{
	va_list	ap;

	if (flags & iwh_dbg_flags) {
		va_start(ap, fmt);
		vcmn_err(CE_NOTE, fmt, ap);
		va_end(ap);
	}
}
#endif	/* DEBUG */

/*
 * device operations
 */
int
iwh_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	int instance, i;
	char strbuf[32];
	wifi_data_t wd = { 0 };
	mac_register_t *macp;
	int intr_type;
	int intr_count;
	int intr_actual;
	int err = DDI_FAILURE;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		instance = ddi_get_instance(dip);
		sc = ddi_get_soft_state(iwh_soft_state_p,
		    instance);
		ASSERT(sc != NULL);

		if (sc->sc_flags & IWH_F_RUNNING) {
			(void) iwh_init(sc);
		}

		atomic_and_32(&sc->sc_flags, ~IWH_F_SUSPEND);

		IWH_DBG((IWH_DEBUG_RESUME, "iwh_attach(): "
		    "resume\n"));
		return (DDI_SUCCESS);

	default:
		goto attach_fail1;
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(iwh_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to allocate soft state\n");
		goto attach_fail1;
	}

	sc = ddi_get_soft_state(iwh_soft_state_p, instance);
	ASSERT(sc != NULL);

	sc->sc_dip = dip;

	/*
	 * map configure space
	 */
	err = ddi_regs_map_setup(dip, 0, &sc->sc_cfg_base, 0, 0,
	    &iwh_reg_accattr, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to map config spaces regs\n");
		goto attach_fail2;
	}

	sc->sc_dev_id = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)(sc->sc_cfg_base + PCI_CONF_DEVID));
	if ((sc->sc_dev_id != 0x4232) &&
	    (sc->sc_dev_id != 0x4235) &&
	    (sc->sc_dev_id != 0x4236) &&
	    (sc->sc_dev_id != 0x4237) &&
	    (sc->sc_dev_id != 0x423a) &&
	    (sc->sc_dev_id != 0x423b) &&
	    (sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "Do not support this device\n");
		goto attach_fail3;
	}

	iwh_init_ht_conf(sc);
	iwh_overwrite_11n_rateset(sc);

	sc->sc_rev = ddi_get8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_REVID));

	/*
	 * keep from disturbing C3 state of CPU
	 */
	ddi_put8(sc->sc_cfg_handle, (uint8_t *)(sc->sc_cfg_base +
	    PCI_CFG_RETRY_TIMEOUT), 0);

	/*
	 * determine the size of buffer for frame and command to ucode
	 */
	sc->sc_clsz = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)(sc->sc_cfg_base + PCI_CONF_CACHE_LINESZ));
	if (!sc->sc_clsz) {
		sc->sc_clsz = 16;
	}
	sc->sc_clsz = (sc->sc_clsz << 2);

	sc->sc_dmabuf_sz = roundup(0x2000 + sizeof (struct ieee80211_frame) +
	    IEEE80211_MTU + IEEE80211_CRC_LEN +
	    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_CRCLEN), sc->sc_clsz);

	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(dip, 1, &sc->sc_base,
	    0, 0, &iwh_reg_accattr, &sc->sc_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to map device regs\n");
		goto attach_fail3;
	}

	/*
	 * this is used to differentiate type of hardware
	 */
	sc->sc_hw_rev = IWH_READ(sc, CSR_HW_REV);

	err = ddi_intr_get_supported_types(dip, &intr_type);
	if ((err != DDI_SUCCESS) || (!(intr_type & DDI_INTR_TYPE_FIXED))) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "fixed type interrupt is not supported\n");
		goto attach_fail4;
	}

	err = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &intr_count);
	if ((err != DDI_SUCCESS) || (intr_count != 1)) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "no fixed interrupts\n");
		goto attach_fail4;
	}

	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);

	err = ddi_intr_alloc(dip, sc->sc_intr_htable, DDI_INTR_TYPE_FIXED, 0,
	    intr_count, &intr_actual, 0);
	if ((err != DDI_SUCCESS) || (intr_actual != 1)) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "ddi_intr_alloc() failed 0x%x\n", err);
		goto attach_fail5;
	}

	err = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_pri);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "ddi_intr_get_pri() failed 0x%x\n", err);
		goto attach_fail6;
	}

	mutex_init(&sc->sc_glock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_pri));
	mutex_init(&sc->sc_tx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_pri));
	mutex_init(&sc->sc_mt_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sc->sc_intr_pri));

	cv_init(&sc->sc_cmd_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_put_seg_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sc->sc_ucode_cv, NULL, CV_DRIVER, NULL);

	/*
	 * initialize the mfthread
	 */
	cv_init(&sc->sc_mt_cv, NULL, CV_DRIVER, NULL);
	sc->sc_mf_thread = NULL;
	sc->sc_mf_thread_switch = 0;

	/*
	 * Allocate shared buffer for communication between driver and ucode.
	 */
	err = iwh_alloc_shared(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to allocate shared page\n");
		goto attach_fail7;
	}

	(void) memset(sc->sc_shared, 0, sizeof (iwh_shared_t));

	/*
	 * Allocate keep warm page.
	 */
	err = iwh_alloc_kw(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to allocate keep warm page\n");
		goto attach_fail8;
	}

	err = iwh_reset_hw(sc);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to reset hardware\n");
		goto attach_fail9;
	}

	/*
	 * Do some necessary hardware initializations.
	 */
	err = iwh_preinit(sc);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to initialize hardware\n");
		goto attach_fail9;
	}

	/*
	 * get hardware configurations from eeprom
	 */
	err = iwh_eep_load(sc);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to load eeprom\n");
		goto attach_fail9;
	}

	if (IWH_READ_EEP_SHORT(sc, EEP_VERSION) < 0x011a) {
		IWH_DBG((IWH_DEBUG_EEPROM, "iwh_attach(): "
		    "unsupported eeprom detected\n"));
		goto attach_fail9;
	}

	/*
	 * get MAC address of this chipset
	 */
	iwh_get_mac_from_eep(sc);

	/*
	 * calibration information from EEPROM
	 */
	sc->sc_eep_calib = (struct iwh_eep_calibration *)
	    iwh_eep_addr_trans(sc, EEP_CALIBRATION);

	/*
	 * initialize TX and RX ring buffers
	 */
	err = iwh_ring_init(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to allocate and initialize ring\n");
		goto attach_fail9;
	}

	if ((0x423c == sc->sc_dev_id) || (0x423d == sc->sc_dev_id)) {
		sc->sc_hdr = (iwh_firmware_hdr_t *)iwh_fw_5150_bin;
	} else {
		sc->sc_hdr = (iwh_firmware_hdr_t *)iwh_fw_5000_bin;
	}

	/*
	 * copy ucode to dma buffer
	 */
	err = iwh_alloc_fw_dma(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to allocate firmware dma\n");
		goto attach_fail10;
	}

	/*
	 * Initialize the wifi part, which will be used by
	 * 802.11 module
	 */
	ic = &sc->sc_ic;
	ic->ic_phytype  = IEEE80211_T_HT;
	ic->ic_opmode   = IEEE80211_M_STA; /* default to BSS mode */
	ic->ic_state    = IEEE80211_S_INIT;
	ic->ic_maxrssi  = 100; /* experimental number */
	ic->ic_caps = IEEE80211_C_SHPREAMBLE | IEEE80211_C_TXPMGT |
	    IEEE80211_C_PMGT | IEEE80211_C_SHSLOT;

	/*
	 * Support WPA/WPA2
	 */
	ic->ic_caps |= IEEE80211_C_WPA;

	/*
	 * Support QoS/WME
	 */
	ic->ic_caps |= IEEE80211_C_WME;
	ic->ic_wme.wme_update = iwh_wme_update;

	/*
	 * Support 802.11n/HT
	 */
	if (sc->sc_ht_conf.ht_support) {
		ic->ic_htcaps = IEEE80211_HTC_HT |
		    IEEE80211_HTC_AMSDU;
		ic->ic_htcaps |= IEEE80211_HTCAP_MAXAMSDU_7935;
	}

	/*
	 * set supported .11b and .11g rates
	 */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = iwh_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = iwh_rateset_11g;

	/*
	 * set supported .11b and .11g channels (1 through 11)
	 */
	for (i = 1; i <= 11; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ |
		    IEEE80211_CHAN_PASSIVE;

		if (sc->sc_ht_conf.cap & HT_CAP_SUP_WIDTH) {
			ic->ic_sup_channels[i].ich_flags |=
			    IEEE80211_CHAN_HT40;
		} else {
			ic->ic_sup_channels[i].ich_flags |=
			    IEEE80211_CHAN_HT20;
		}
	}

	ic->ic_ibss_chan = &ic->ic_sup_channels[0];
	ic->ic_xmit = iwh_send;

	/*
	 * attach to 802.11 module
	 */
	ieee80211_attach(ic);

	/*
	 * different instance has different WPA door
	 */
	(void) snprintf(ic->ic_wpadoor, MAX_IEEE80211STR, "%s_%s%d", WPA_DOOR,
	    ddi_driver_name(dip),
	    ddi_get_instance(dip));

	/*
	 * Overwrite 80211 default configurations.
	 */
	iwh_overwrite_ic_default(sc);

	/*
	 * initialize 802.11 module
	 */
	ieee80211_media_init(ic);

	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	err = ddi_intr_add_softint(dip, &sc->sc_soft_hdl, DDI_INTR_SOFTPRI_MAX,
	    iwh_rx_softintr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "add soft interrupt failed\n");
		goto attach_fail12;
	}

	err = ddi_intr_add_handler(sc->sc_intr_htable[0], iwh_intr,
	    (caddr_t)sc, NULL);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "ddi_intr_add_handle() failed\n");
		goto attach_fail13;
	}

	err = ddi_intr_enable(sc->sc_intr_htable[0]);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "ddi_intr_enable() failed\n");
		goto attach_fail14;
	}

	/*
	 * Initialize pointer to device specific functions
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = ic->ic_opmode;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_macaddr);

	/*
	 * create relation to GLD
	 */
	macp = mac_alloc(MAC_VERSION);
	if (NULL == macp) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to do mac_alloc()\n");
		goto attach_fail15;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &iwh_m_callbacks;
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
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to do mac_register()\n");
		goto attach_fail15;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), DRV_NAME_SP"%d", instance);
	err = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_attach(): "
		    "failed to do ddi_create_minor_node()\n");
	}

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	/*
	 * create the mf thread to handle the link status,
	 * recovery fatal error, etc.
	 */
	sc->sc_mf_thread_switch = 1;
	if (NULL == sc->sc_mf_thread) {
		sc->sc_mf_thread = thread_create((caddr_t)NULL, 0,
		    iwh_thread, sc, 0, &p0, TS_RUN, minclsyspri);
	}

	atomic_or_32(&sc->sc_flags, IWH_F_ATTACHED);

	return (DDI_SUCCESS);

attach_fail15:
	(void) ddi_intr_disable(sc->sc_intr_htable[0]);

attach_fail14:
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);

attach_fail13:
	(void) ddi_intr_remove_softint(sc->sc_soft_hdl);
	sc->sc_soft_hdl = NULL;

attach_fail12:
	ieee80211_detach(ic);

attach_fail11:
	iwh_free_fw_dma(sc);

attach_fail10:
	iwh_ring_free(sc);

attach_fail9:
	iwh_free_kw(sc);

attach_fail8:
	iwh_free_shared(sc);

attach_fail7:
	iwh_destroy_locks(sc);

attach_fail6:
	(void) ddi_intr_free(sc->sc_intr_htable[0]);

attach_fail5:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));

attach_fail4:
	ddi_regs_map_free(&sc->sc_handle);

attach_fail3:
	ddi_regs_map_free(&sc->sc_cfg_handle);

attach_fail2:
	ddi_soft_state_free(iwh_soft_state_p, instance);

attach_fail1:
	return (DDI_FAILURE);
}

int
iwh_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	int err;

	sc = ddi_get_soft_state(iwh_soft_state_p, ddi_get_instance(dip));
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		atomic_and_32(&sc->sc_flags, ~IWH_F_HW_ERR_RECOVER);
		atomic_and_32(&sc->sc_flags, ~IWH_F_RATE_AUTO_CTL);

		atomic_or_32(&sc->sc_flags, IWH_F_SUSPEND);

		if (sc->sc_flags & IWH_F_RUNNING) {
			ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
			iwh_stop(sc);
		}

		IWH_DBG((IWH_DEBUG_RESUME, "iwh_detach(): "
		    "suspend\n"));
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (!(sc->sc_flags & IWH_F_ATTACHED)) {
		return (DDI_FAILURE);
	}

	/*
	 * Destroy the mf_thread
	 */
	sc->sc_mf_thread_switch = 0;

	mutex_enter(&sc->sc_mt_lock);
	while (sc->sc_mf_thread != NULL) {
		if (cv_wait_sig(&sc->sc_mt_cv, &sc->sc_mt_lock) == 0) {
			break;
		}
	}
	mutex_exit(&sc->sc_mt_lock);

	err = mac_disable(sc->sc_ic.ic_mach);
	if (err != DDI_SUCCESS) {
		return (err);
	}

	/*
	 * stop chipset
	 */
	iwh_stop(sc);

	DELAY(500000);

	/*
	 * release buffer for calibration
	 */
	iwh_release_calib_buffer(sc);

	/*
	 * Unregiste from GLD
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	mutex_enter(&sc->sc_glock);
	iwh_free_fw_dma(sc);
	iwh_ring_free(sc);
	iwh_free_kw(sc);
	iwh_free_shared(sc);
	mutex_exit(&sc->sc_glock);

	(void) ddi_intr_disable(sc->sc_intr_htable[0]);
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));

	(void) ddi_intr_remove_softint(sc->sc_soft_hdl);
	sc->sc_soft_hdl = NULL;

	/*
	 * detach from 80211 module
	 */
	ieee80211_detach(&sc->sc_ic);

	iwh_destroy_locks(sc);

	ddi_regs_map_free(&sc->sc_handle);
	ddi_regs_map_free(&sc->sc_cfg_handle);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(iwh_soft_state_p, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

/*
 * destroy all locks
 */
static void
iwh_destroy_locks(iwh_sc_t *sc)
{
	cv_destroy(&sc->sc_mt_cv);
	cv_destroy(&sc->sc_cmd_cv);
	cv_destroy(&sc->sc_put_seg_cv);
	cv_destroy(&sc->sc_ucode_cv);
	mutex_destroy(&sc->sc_mt_lock);
	mutex_destroy(&sc->sc_tx_lock);
	mutex_destroy(&sc->sc_glock);
}

/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
iwh_alloc_dma_mem(iwh_sc_t *sc, size_t memsize,
    ddi_dma_attr_t *dma_attr_p, ddi_device_acc_attr_t *acc_attr_p,
    uint_t dma_flags, iwh_dma_t *dma_p)
{
	caddr_t vaddr;
	int err = DDI_FAILURE;

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
iwh_free_dma_mem(iwh_dma_t *dma_p)
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
 * copy ucode into dma buffers
 */
static int
iwh_alloc_fw_dma(iwh_sc_t *sc)
{
	int err = DDI_FAILURE;
	iwh_dma_t *dma_p;
	char *t;

	/*
	 * firmware image layout:
	 * |HDR|<-TEXT->|<-DATA->|<-INIT_TEXT->|<-INIT_DATA->|<-BOOT->|
	 */

	/*
	 * copy text of runtime ucode
	 */
	t = (char *)(sc->sc_hdr + 1);
	err = iwh_alloc_dma_mem(sc, LE_32(sc->sc_hdr->textsz),
	    &fw_dma_attr, &iwh_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_text);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_alloc_fw_dma(): "
		    "failed to allocate text dma memory.\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_text;

	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_fw_dma(): "
	    "text[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	bcopy(t, dma_p->mem_va, LE_32(sc->sc_hdr->textsz));

	/*
	 * copy data and bak-data of runtime ucode
	 */
	t += LE_32(sc->sc_hdr->textsz);
	err = iwh_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_dma_attr, &iwh_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_alloc_fw_dma(): "
		    "failed to allocate data dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_data;

	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_fw_dma(): "
	    "data[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	bcopy(t, dma_p->mem_va, LE_32(sc->sc_hdr->datasz));

	err = iwh_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_dma_attr, &iwh_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data_bak);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_alloc_fw_dma(): "
		    "failed to allocate data bakup dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_data_bak;

	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_fw_dma(): "
	    "data_bak[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	bcopy(t, dma_p->mem_va, LE_32(sc->sc_hdr->datasz));

	/*
	 * copy text of init ucode
	 */
	t += LE_32(sc->sc_hdr->datasz);
	err = iwh_alloc_dma_mem(sc, LE_32(sc->sc_hdr->init_textsz),
	    &fw_dma_attr, &iwh_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_init_text);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_alloc_fw_dma(): "
		    "failed to allocate init text dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_init_text;

	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_fw_dma(): "
	    "init_text[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	bcopy(t, dma_p->mem_va, LE_32(sc->sc_hdr->init_textsz));

	/*
	 * copy data of init ucode
	 */
	t += LE_32(sc->sc_hdr->init_textsz);
	err = iwh_alloc_dma_mem(sc, LE_32(sc->sc_hdr->init_datasz),
	    &fw_dma_attr, &iwh_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_init_data);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwh_alloc_fw_dma(): "
		    "failed to allocate init data dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_init_data;

	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_fw_dma(): "
	    "init_data[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	bcopy(t, dma_p->mem_va, LE_32(sc->sc_hdr->init_datasz));

	sc->sc_boot = t + LE_32(sc->sc_hdr->init_datasz);

fail:
	return (err);
}

static void
iwh_free_fw_dma(iwh_sc_t *sc)
{
	iwh_free_dma_mem(&sc->sc_dma_fw_text);
	iwh_free_dma_mem(&sc->sc_dma_fw_data);
	iwh_free_dma_mem(&sc->sc_dma_fw_data_bak);
	iwh_free_dma_mem(&sc->sc_dma_fw_init_text);
	iwh_free_dma_mem(&sc->sc_dma_fw_init_data);
}

/*
 * Allocate a shared buffer between host and NIC.
 */
static int
iwh_alloc_shared(iwh_sc_t *sc)
{
#ifdef	DEBUG
	iwh_dma_t *dma_p;
#endif
	int err = DDI_FAILURE;

	/*
	 * must be aligned on a 4K-page boundary
	 */
	err = iwh_alloc_dma_mem(sc, sizeof (iwh_shared_t),
	    &sh_dma_attr, &iwh_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_sh);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

	sc->sc_shared = (iwh_shared_t *)sc->sc_dma_sh.mem_va;

#ifdef	DEBUG
	dma_p = &sc->sc_dma_sh;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_shared(): "
	    "sh[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);

fail:
	iwh_free_shared(sc);
	return (err);
}

static void
iwh_free_shared(iwh_sc_t *sc)
{
	iwh_free_dma_mem(&sc->sc_dma_sh);
}

/*
 * Allocate a keep warm page.
 */
static int
iwh_alloc_kw(iwh_sc_t *sc)
{
#ifdef	DEBUG
	iwh_dma_t *dma_p;
#endif
	int err = DDI_FAILURE;

	/*
	 * must be aligned on a 4K-page boundary
	 */
	err = iwh_alloc_dma_mem(sc, IWH_KW_SIZE,
	    &kw_dma_attr, &iwh_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_kw);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

#ifdef	DEBUG
	dma_p = &sc->sc_dma_kw;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_kw(): "
	    "kw[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);

fail:
	iwh_free_kw(sc);
	return (err);
}

static void
iwh_free_kw(iwh_sc_t *sc)
{
	iwh_free_dma_mem(&sc->sc_dma_kw);
}

/*
 * initialize RX ring buffers
 */
static int
iwh_alloc_rx_ring(iwh_sc_t *sc)
{
	iwh_rx_ring_t *ring;
	iwh_rx_data_t *data;
#ifdef	DEBUG
	iwh_dma_t *dma_p;
#endif
	int i, err = DDI_FAILURE;

	ring = &sc->sc_rxq;
	ring->cur = 0;

	/*
	 * allocate RX description ring buffer
	 */
	err = iwh_alloc_dma_mem(sc, RX_QUEUE_SIZE * sizeof (uint32_t),
	    &ring_desc_dma_attr, &iwh_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_rx_ring(): "
		    "dma alloc rx ring desc "
		    "failed\n"));
		goto fail;
	}

	ring->desc = (uint32_t *)ring->dma_desc.mem_va;
#ifdef	DEBUG
	dma_p = &ring->dma_desc;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_rx_ring(): "
	    "rx bd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	/*
	 * Allocate Rx frame buffers.
	 */
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		data = &ring->data[i];
		err = iwh_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &rx_buffer_dma_attr, &iwh_dma_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_rx_ring(): "
			    "dma alloc rx ring "
			    "buf[%d] failed\n", i));
			goto fail;
		}
		/*
		 * the physical address bit [8-36] are used,
		 * instead of bit [0-31] in 3945.
		 */
		ring->desc[i] = (uint32_t)
		    (data->dma_data.cookie.dmac_address >> 8);
	}

#ifdef	DEBUG
	dma_p = &ring->data[0].dma_data;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_rx_ring(): "
	    "rx buffer[0][ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	IWH_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	return (err);

fail:
	iwh_free_rx_ring(sc);
	return (err);
}

/*
 * disable RX ring
 */
static void
iwh_reset_rx_ring(iwh_sc_t *sc)
{
	int n;

	iwh_mac_access_enter(sc);
	IWH_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
	for (n = 0; n < 2000; n++) {
		if (IWH_READ(sc, FH_MEM_RSSR_RX_STATUS_REG) & (1 << 24)) {
			break;
		}
		DELAY(1000);
	}
#ifdef DEBUG
	if (2000 == n) {
		IWH_DBG((IWH_DEBUG_DMA, "iwh_reset_rx_ring(): "
		    "timeout resetting Rx ring\n"));
	}
#endif
	iwh_mac_access_exit(sc);

	sc->sc_rxq.cur = 0;
}

static void
iwh_free_rx_ring(iwh_sc_t *sc)
{
	int i;

	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		if (sc->sc_rxq.data[i].dma_data.dma_hdl) {
			IWH_DMA_SYNC(sc->sc_rxq.data[i].dma_data,
			    DDI_DMA_SYNC_FORCPU);
		}

		iwh_free_dma_mem(&sc->sc_rxq.data[i].dma_data);
	}

	if (sc->sc_rxq.dma_desc.dma_hdl) {
		IWH_DMA_SYNC(sc->sc_rxq.dma_desc, DDI_DMA_SYNC_FORDEV);
	}

	iwh_free_dma_mem(&sc->sc_rxq.dma_desc);
}

/*
 * initialize TX ring buffers
 */
static int
iwh_alloc_tx_ring(iwh_sc_t *sc, iwh_tx_ring_t *ring,
    int slots, int qid)
{
	iwh_tx_data_t *data;
	iwh_tx_desc_t *desc_h;
	uint32_t paddr_desc_h;
	iwh_cmd_t *cmd_h;
	uint32_t paddr_cmd_h;
#ifdef	DEBUG
	iwh_dma_t *dma_p;
#endif
	int i, err = DDI_FAILURE;

	ring->qid = qid;
	ring->count = TFD_QUEUE_SIZE_MAX;
	ring->window = slots;
	ring->queued = 0;
	ring->cur = 0;
	ring->desc_cur = 0;

	/*
	 * allocate buffer for TX descriptor ring
	 */
	err = iwh_alloc_dma_mem(sc,
	    TFD_QUEUE_SIZE_MAX * sizeof (iwh_tx_desc_t),
	    &ring_desc_dma_attr, &iwh_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
		    "dma alloc tx ring desc[%d] "
		    "failed\n", qid));
		goto fail;
	}

#ifdef	DEBUG
	dma_p = &ring->dma_desc;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
	    "tx bd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	desc_h = (iwh_tx_desc_t *)ring->dma_desc.mem_va;
	paddr_desc_h = ring->dma_desc.cookie.dmac_address;

	/*
	 * allocate buffer for ucode command
	 */
	err = iwh_alloc_dma_mem(sc,
	    TFD_QUEUE_SIZE_MAX * sizeof (iwh_cmd_t),
	    &cmd_dma_attr, &iwh_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_cmd);
	if (err != DDI_SUCCESS) {
		IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
		    "dma alloc tx ring cmd[%d]"
		    " failed\n", qid));
		goto fail;
	}

#ifdef	DEBUG
	dma_p = &ring->dma_cmd;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
	    "tx cmd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	cmd_h = (iwh_cmd_t *)ring->dma_cmd.mem_va;
	paddr_cmd_h = ring->dma_cmd.cookie.dmac_address;

	/*
	 * Allocate Tx frame buffers.
	 */
	ring->data = kmem_zalloc(sizeof (iwh_tx_data_t) * TFD_QUEUE_SIZE_MAX,
	    KM_NOSLEEP);
	if (NULL == ring->data) {
		IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
		    "could not allocate "
		    "tx data slots\n"));
		goto fail;
	}

	for (i = 0; i < TFD_QUEUE_SIZE_MAX; i++) {
		data = &ring->data[i];
		err = iwh_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &tx_buffer_dma_attr, &iwh_dma_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
			    "dma alloc tx "
			    "ring buf[%d] failed\n", i));
			goto fail;
		}

		data->desc = desc_h + i;
		data->paddr_desc = paddr_desc_h +
		    _PTRDIFF(data->desc, desc_h);
		data->cmd = cmd_h +  i;
		data->paddr_cmd = paddr_cmd_h +
		    _PTRDIFF(data->cmd, cmd_h);
	}
#ifdef	DEBUG
	dma_p = &ring->data[0].dma_data;
#endif
	IWH_DBG((IWH_DEBUG_DMA, "iwh_alloc_tx_ring(): "
	    "tx buffer[0][ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);

fail:
	iwh_free_tx_ring(ring);

	return (err);
}

/*
 * disable TX ring
 */
static void
iwh_reset_tx_ring(iwh_sc_t *sc, iwh_tx_ring_t *ring)
{
	iwh_tx_data_t *data;
	int i, n;

	iwh_mac_access_enter(sc);

	IWH_WRITE(sc, IWH_FH_TCSR_CHNL_TX_CONFIG_REG(ring->qid), 0);
	for (n = 0; n < 200; n++) {
		if (IWH_READ(sc, IWH_FH_TSSR_TX_STATUS_REG) &
		    IWH_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(ring->qid)) {
			break;
		}
		DELAY(10);
	}

#ifdef	DEBUG
	if (200 == n) {
		IWH_DBG((IWH_DEBUG_DMA, "iwh_reset_tx_ring(): "
		    "timeout reset tx ring %d\n",
		    ring->qid));
	}
#endif

	iwh_mac_access_exit(sc);

	/*
	 * by pass, if it's quiesce
	 */
	if (!(sc->sc_flags & IWH_F_QUIESCED)) {
		for (i = 0; i < ring->count; i++) {
			data = &ring->data[i];
			IWH_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
		}
	}

	ring->queued = 0;
	ring->cur = 0;
	ring->desc_cur = 0;
}

static void
iwh_free_tx_ring(iwh_tx_ring_t *ring)
{
	int i;

	if (ring->dma_desc.dma_hdl != NULL) {
		IWH_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);
	}
	iwh_free_dma_mem(&ring->dma_desc);

	if (ring->dma_cmd.dma_hdl != NULL) {
		IWH_DMA_SYNC(ring->dma_cmd, DDI_DMA_SYNC_FORDEV);
	}
	iwh_free_dma_mem(&ring->dma_cmd);

	if (ring->data != NULL) {
		for (i = 0; i < ring->count; i++) {
			if (ring->data[i].dma_data.dma_hdl) {
				IWH_DMA_SYNC(ring->data[i].dma_data,
				    DDI_DMA_SYNC_FORDEV);
			}
			iwh_free_dma_mem(&ring->data[i].dma_data);
		}
		kmem_free(ring->data, ring->count * sizeof (iwh_tx_data_t));
	}
}

/*
 * initialize TX and RX ring
 */
static int
iwh_ring_init(iwh_sc_t *sc)
{
	int i, err = DDI_FAILURE;

	for (i = 0; i < IWH_NUM_QUEUES; i++) {
		if (IWH_CMD_QUEUE_NUM == i) {
			continue;
		}

		err = iwh_alloc_tx_ring(sc, &sc->sc_txq[i], TFD_TX_CMD_SLOTS,
		    i);
		if (err != DDI_SUCCESS) {
			goto fail;
		}
	}

	/*
	 * initialize command queue
	 */
	err = iwh_alloc_tx_ring(sc, &sc->sc_txq[IWH_CMD_QUEUE_NUM],
	    TFD_CMD_SLOTS, IWH_CMD_QUEUE_NUM);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

	err = iwh_alloc_rx_ring(sc);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

fail:
	return (err);
}

static void
iwh_ring_free(iwh_sc_t *sc)
{
	int i = IWH_NUM_QUEUES;

	iwh_free_rx_ring(sc);
	while (--i >= 0) {
		iwh_free_tx_ring(&sc->sc_txq[i]);
	}
}

/* ARGSUSED */
static ieee80211_node_t *
iwh_node_alloc(ieee80211com_t *ic)
{
	iwh_amrr_t *amrr;

	amrr = kmem_zalloc(sizeof (iwh_amrr_t), KM_SLEEP);
	if (NULL == amrr) {
		cmn_err(CE_WARN, "iwh_node_alloc(): "
		    "failed to allocate memory for amrr structure\n");
		return (NULL);
	}

	iwh_amrr_init(amrr);

	return (&amrr->in);
}

static void
iwh_node_free(ieee80211_node_t *in)
{
	ieee80211com_t *ic;

	if ((NULL == in) ||
	    (NULL == in->in_ic)) {
		cmn_err(CE_WARN, "iwh_node_free() "
		    "Got a NULL point from Net80211 module\n");
		return;
	}
	ic = in->in_ic;

	if (ic->ic_node_cleanup != NULL) {
		ic->ic_node_cleanup(in);
	}

	if (in->in_wpa_ie != NULL) {
		ieee80211_free(in->in_wpa_ie);
	}

	if (in->in_wme_ie != NULL) {
		ieee80211_free(in->in_wme_ie);
	}

	if (in->in_htcap_ie != NULL) {
		ieee80211_free(in->in_htcap_ie);
	}

	kmem_free(in, sizeof (iwh_amrr_t));
}

/*
 * change station's state. this function will be invoked by 80211 module
 * when need to change staton's state.
 */
static int
iwh_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	iwh_sc_t *sc;
	ieee80211_node_t *in;
	enum ieee80211_state ostate;
	iwh_add_sta_t node;
	iwh_amrr_t *amrr;
	uint8_t r;
	int i, err = IWH_FAIL;

	if (NULL == ic) {
		return (err);
	}
	sc = (iwh_sc_t *)ic;
	in = ic->ic_bss;
	ostate = ic->ic_state;

	mutex_enter(&sc->sc_glock);

	switch (nstate) {
	case IEEE80211_S_SCAN:
		switch (ostate) {
		case IEEE80211_S_INIT:
			atomic_or_32(&sc->sc_flags, IWH_F_SCANNING);
			iwh_set_led(sc, 2, 10, 2);

			/*
			 * clear association to receive beacons from
			 * all BSS'es
			 */
			sc->sc_config.assoc_id = 0;
			sc->sc_config.filter_flags &=
			    ~LE_32(RXON_FILTER_ASSOC_MSK);

			IWH_DBG((IWH_DEBUG_80211, "iwh_newstate(): "
			    "config chan %d "
			    "flags %x filter_flags %x\n",
			    LE_16(sc->sc_config.chan),
			    LE_32(sc->sc_config.flags),
			    LE_32(sc->sc_config.filter_flags)));

			err = iwh_cmd(sc, REPLY_RXON, &sc->sc_config,
			    sizeof (iwh_rxon_cmd_t), 1);
			if (err != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_newstate(): "
				    "could not clear association\n");
				atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
				mutex_exit(&sc->sc_glock);
				return (err);
			}

			/*
			 * add broadcast node to send probe request
			 */
			(void) memset(&node, 0, sizeof (node));
			(void) memset(&node.sta.addr, 0xff, IEEE80211_ADDR_LEN);
			node.sta.sta_id = IWH_BROADCAST_ID;
			err = iwh_cmd(sc, REPLY_ADD_STA, &node,
			    sizeof (node), 1);
			if (err != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_newstate(): "
				    "could not add broadcast node\n");
				atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
				mutex_exit(&sc->sc_glock);
				return (err);
			}
			break;
		case IEEE80211_S_SCAN:
			mutex_exit(&sc->sc_glock);
			/* step to next channel before actual FW scan */
			err = sc->sc_newstate(ic, nstate, arg);
			mutex_enter(&sc->sc_glock);
			if ((err != 0) || ((err = iwh_scan(sc)) != 0)) {
				cmn_err(CE_WARN, "iwh_newstate(): "
				    "could not initiate scan\n");
				atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
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
			atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
		}

		/*
		 * reset state to handle reassociations correctly
		 */
		sc->sc_config.assoc_id = 0;
		sc->sc_config.filter_flags &= ~LE_32(RXON_FILTER_ASSOC_MSK);

		/*
		 * before sending authentication and association request frame,
		 * we need do something in the hardware, such as setting the
		 * channel same to the target AP...
		 */
		if ((err = iwh_hw_set_before_auth(sc)) != 0) {
			IWH_DBG((IWH_DEBUG_80211, "iwh_newstate(): "
			    "could not send authentication request\n"));
			mutex_exit(&sc->sc_glock);
			return (err);
		}
		break;

	case IEEE80211_S_RUN:
		if (ostate == IEEE80211_S_SCAN) {
			atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
		}

		if (IEEE80211_M_MONITOR == ic->ic_opmode) {
			/*
			 * let LED blink when monitoring
			 */
			iwh_set_led(sc, 2, 10, 10);
			break;
		}

		IWH_DBG((IWH_DEBUG_80211, "iwh_newstate(): "
		    "associated.\n"));

		err = iwh_run_state_config(sc);
		if (err != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_newstate(): "
			    "failed to set up association\n");
			mutex_exit(&sc->sc_glock);
			return (err);
		}

		/*
		 * start automatic rate control
		 */
		if ((in->in_flags & IEEE80211_NODE_HT) &&
		    (sc->sc_ht_conf.ht_support) &&
		    (in->in_htrates.rs_nrates > 0) &&
		    (in->in_htrates.rs_nrates <= IEEE80211_HTRATE_MAXSIZE)) {
			amrr = (iwh_amrr_t *)in;

			for (i = in->in_htrates.rs_nrates - 1; i > 0; i--) {

				r = in->in_htrates.rs_rates[i] &
				    IEEE80211_RATE_VAL;
				if ((r != 0) && (r <= 0xd) &&
				    (sc->sc_ht_conf.tx_support_mcs[r/8] &
				    (1 << (r%8)))) {
					amrr->ht_mcs_idx = r;
					atomic_or_32(&sc->sc_flags,
					    IWH_F_RATE_AUTO_CTL);
					break;
				}
			}
		} else {
			if (IEEE80211_FIXED_RATE_NONE == ic->ic_fixed_rate) {
				atomic_or_32(&sc->sc_flags,
				    IWH_F_RATE_AUTO_CTL);

				/*
				 * set rate to some reasonable initial value
				 */
				i = in->in_rates.ir_nrates - 1;
				while (i > 0 && IEEE80211_RATE(i) > 72) {
					i--;
				}
				in->in_txrate = i;

			} else {
				atomic_and_32(&sc->sc_flags,
				    ~IWH_F_RATE_AUTO_CTL);
			}
		}

		/*
		 * set LED on after associated
		 */
		iwh_set_led(sc, 2, 0, 1);
		break;

	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_SCAN) {
			atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
		}
		/*
		 * set LED off after init
		 */
		iwh_set_led(sc, 2, 1, 0);
		break;

	case IEEE80211_S_ASSOC:
		if (ostate == IEEE80211_S_SCAN) {
			atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
		}
		break;
	}

	mutex_exit(&sc->sc_glock);

	return (sc->sc_newstate(ic, nstate, arg));
}

/*
 * exclusive access to mac begin.
 */
static void
iwh_mac_access_enter(iwh_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWH_READ(sc, CSR_GP_CNTRL);
	IWH_WRITE(sc, CSR_GP_CNTRL,
	    tmp | CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

	/*
	 * wait until we succeed
	 */
	for (n = 0; n < 1000; n++) {
		if ((IWH_READ(sc, CSR_GP_CNTRL) &
		    (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
		    CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP)) ==
		    CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN) {
			break;
		}
		DELAY(10);
	}

#ifdef	DEBUG
	if (1000 == n) {
		IWH_DBG((IWH_DEBUG_PIO, "iwh_mac_access_enter(): "
		    "could not lock memory\n"));
	}
#endif
}

/*
 * exclusive access to mac end.
 */
static void
iwh_mac_access_exit(iwh_sc_t *sc)
{
	uint32_t tmp = IWH_READ(sc, CSR_GP_CNTRL);
	IWH_WRITE(sc, CSR_GP_CNTRL,
	    tmp & ~CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
}

/*
 * this function defined here for future use.
 * static uint32_t
 * iwh_mem_read(iwh_sc_t *sc, uint32_t addr)
 * {
 * 	IWH_WRITE(sc, HBUS_TARG_MEM_RADDR, addr);
 * 	return (IWH_READ(sc, HBUS_TARG_MEM_RDAT));
 * }
 */

/*
 * write mac memory
 */
static void
iwh_mem_write(iwh_sc_t *sc, uint32_t addr, uint32_t data)
{
	IWH_WRITE(sc, HBUS_TARG_MEM_WADDR, addr);
	IWH_WRITE(sc, HBUS_TARG_MEM_WDAT, data);
}

/*
 * read mac register
 */
static uint32_t
iwh_reg_read(iwh_sc_t *sc, uint32_t addr)
{
	IWH_WRITE(sc, HBUS_TARG_PRPH_RADDR, addr | (3 << 24));
	return (IWH_READ(sc, HBUS_TARG_PRPH_RDAT));
}

/*
 * write mac register
 */
static void
iwh_reg_write(iwh_sc_t *sc, uint32_t addr, uint32_t data)
{
	IWH_WRITE(sc, HBUS_TARG_PRPH_WADDR, addr | (3 << 24));
	IWH_WRITE(sc, HBUS_TARG_PRPH_WDAT, data);
}


/*
 * steps of loading ucode:
 * load init ucode=>init alive=>calibrate=>
 * receive calibration result=>reinitialize NIC=>
 * load runtime ucode=>runtime alive=>
 * send calibration result=>running.
 */
static int
iwh_load_init_firmware(iwh_sc_t *sc)
{
	int err = IWH_FAIL;
	clock_t	clk;

	atomic_and_32(&sc->sc_flags, ~IWH_F_PUT_SEG);

	/*
	 * load init_text section of uCode to hardware
	 */
	err = iwh_put_seg_fw(sc, sc->sc_dma_fw_init_text.cookie.dmac_address,
	    RTC_INST_LOWER_BOUND, sc->sc_dma_fw_init_text.cookie.dmac_size);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_load_init_firmware(): "
		    "failed to write init uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/*
	 * wait loading init_text until completed or timeout
	 */
	while (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwh_load_init_firmware(): "
		    "timeout waiting for init uCode load.\n");
		return (IWH_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWH_F_PUT_SEG);

	/*
	 * load init_data section of uCode to hardware
	 */
	err = iwh_put_seg_fw(sc, sc->sc_dma_fw_init_data.cookie.dmac_address,
	    RTC_DATA_LOWER_BOUND, sc->sc_dma_fw_init_data.cookie.dmac_size);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_load_init_firmware(): "
		    "failed to write init_data uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/*
	 * wait loading init_data until completed or timeout
	 */
	while (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwh_load_init_firmware(): "
		    "timeout waiting for init_data uCode load.\n");
		return (IWH_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWH_F_PUT_SEG);

	return (err);
}

static int
iwh_load_run_firmware(iwh_sc_t *sc)
{
	int err = IWH_FAIL;
	clock_t	clk;

	atomic_and_32(&sc->sc_flags, ~IWH_F_PUT_SEG);

	/*
	 * load init_text section of uCode to hardware
	 */
	err = iwh_put_seg_fw(sc, sc->sc_dma_fw_text.cookie.dmac_address,
	    RTC_INST_LOWER_BOUND, sc->sc_dma_fw_text.cookie.dmac_size);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_load_run_firmware(): "
		    "failed to write run uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/*
	 * wait loading run_text until completed or timeout
	 */
	while (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwh_load_run_firmware(): "
		    "timeout waiting for run uCode load.\n");
		return (IWH_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWH_F_PUT_SEG);

	/*
	 * load run_data section of uCode to hardware
	 */
	err = iwh_put_seg_fw(sc, sc->sc_dma_fw_data_bak.cookie.dmac_address,
	    RTC_DATA_LOWER_BOUND, sc->sc_dma_fw_data.cookie.dmac_size);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_load_run_firmware(): "
		    "failed to write run_data uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/*
	 * wait loading run_data until completed or timeout
	 */
	while (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWH_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwh_load_run_firmware(): "
		    "timeout waiting for run_data uCode load.\n");
		return (IWH_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWH_F_PUT_SEG);

	return (err);
}

/*
 * this function will be invoked to receive phy information
 * when a frame is received.
 */
static void
iwh_rx_phy_intr(iwh_sc_t *sc, iwh_rx_desc_t *desc)
{

	sc->sc_rx_phy_res.flag = 1;

	bcopy((uint8_t *)(desc + 1), sc->sc_rx_phy_res.buf,
	    sizeof (iwh_rx_phy_res_t));
}

/*
 * this function will be invoked to receive body of frame when
 * a frame is received.
 */
static void
iwh_rx_mpdu_intr(iwh_sc_t *sc, iwh_rx_desc_t *desc)
{
	ieee80211com_t *ic = &sc->sc_ic;
#ifdef	DEBUG
	iwh_rx_ring_t *ring = &sc->sc_rxq;
#endif
	struct ieee80211_frame *wh;
	struct iwh_rx_non_cfg_phy *phyinfo;
	struct iwh_rx_mpdu_body_size *mpdu_size;
	mblk_t *mp;
	int16_t t;
	uint16_t len, rssi, agc;
	uint32_t temp, crc, *tail;
	uint32_t arssi, brssi, crssi, mrssi;
	iwh_rx_phy_res_t *stat;
	ieee80211_node_t *in;

	/*
	 * assuming not 11n here. cope with 11n in phase-II
	 */
	mpdu_size = (struct iwh_rx_mpdu_body_size *)(desc + 1);
	stat = (iwh_rx_phy_res_t *)sc->sc_rx_phy_res.buf;
	if (stat->cfg_phy_cnt > 20) {
		return;
	}

	phyinfo = (struct iwh_rx_non_cfg_phy *)stat->non_cfg_phy;
	temp = LE_32(phyinfo->non_cfg_phy[IWH_RX_RES_AGC_IDX]);
	agc = (temp & IWH_OFDM_AGC_MSK) >> IWH_OFDM_AGC_BIT_POS;

	temp = LE_32(phyinfo->non_cfg_phy[IWH_RX_RES_RSSI_AB_IDX]);
	arssi = (temp & IWH_OFDM_RSSI_A_MSK) >> IWH_OFDM_RSSI_A_BIT_POS;
	brssi = (temp & IWH_OFDM_RSSI_B_MSK) >> IWH_OFDM_RSSI_B_BIT_POS;

	temp = LE_32(phyinfo->non_cfg_phy[IWH_RX_RES_RSSI_C_IDX]);
	crssi = (temp & IWH_OFDM_RSSI_C_MSK) >> IWH_OFDM_RSSI_C_BIT_POS;

	mrssi = MAX(arssi, brssi);
	mrssi = MAX(mrssi, crssi);

	t = mrssi - agc - IWH_RSSI_OFFSET;
	/*
	 * convert dBm to percentage
	 */
	rssi = (100 * 75 * 75 - (-20 - t) * (15 * 75 + 62 * (-20 - t)))
	    / (75 * 75);
	if (rssi > 100) {
		rssi = 100;
	}
	if (rssi < 1) {
		rssi = 1;
	}

	/*
	 * size of frame, not include FCS
	 */
	len = LE_16(mpdu_size->byte_count);
	tail = (uint32_t *)((uint8_t *)(desc + 1) +
	    sizeof (struct iwh_rx_mpdu_body_size) + len);
	bcopy(tail, &crc, 4);

	IWH_DBG((IWH_DEBUG_RX, "iwh_rx_mpdu_intr(): "
	    "rx intr: idx=%d phy_len=%x len=%d "
	    "rate=%x chan=%d tstamp=%x non_cfg_phy_count=%x "
	    "cfg_phy_count=%x tail=%x", ring->cur, sizeof (*stat),
	    len, stat->rate.r.s.rate, stat->channel,
	    LE_32(stat->timestampl), stat->non_cfg_phy_cnt,
	    stat->cfg_phy_cnt, LE_32(crc)));

	if ((len < 16) || (len > sc->sc_dmabuf_sz)) {
		IWH_DBG((IWH_DEBUG_RX, "iwh_rx_mpdu_intr(): "
		    "rx frame oversize\n"));
		return;
	}

	/*
	 * discard Rx frames with bad CRC
	 */
	if ((LE_32(crc) &
	    (RX_RES_STATUS_NO_CRC32_ERROR | RX_RES_STATUS_NO_RXE_OVERFLOW)) !=
	    (RX_RES_STATUS_NO_CRC32_ERROR | RX_RES_STATUS_NO_RXE_OVERFLOW)) {
		IWH_DBG((IWH_DEBUG_RX, "iwh_rx_mpdu_intr(): "
		    "rx crc error tail: %x\n",
		    LE_32(crc)));
		sc->sc_rx_err++;
		return;
	}

	wh = (struct ieee80211_frame *)
	    ((uint8_t *)(desc + 1)+ sizeof (struct iwh_rx_mpdu_body_size));

	if (IEEE80211_FC0_SUBTYPE_ASSOC_RESP == *(uint8_t *)wh) {
		sc->sc_assoc_id = *((uint16_t *)(wh + 1) + 2);
		IWH_DBG((IWH_DEBUG_RX, "iwh_rx_mpdu_intr(): "
		    "rx : association id = %x\n",
		    sc->sc_assoc_id));
	}

#ifdef DEBUG
	if (iwh_dbg_flags & IWH_DEBUG_RX) {
		ieee80211_dump_pkt((uint8_t *)wh, len, 0, 0);
	}
#endif

	in = ieee80211_find_rxnode(ic, wh);
	mp = allocb(len, BPRI_MED);
	if (mp) {
		bcopy(wh, mp->b_wptr, len);
		mp->b_wptr += len;

		/*
		 * send the frame to the 802.11 layer
		 */
		(void) ieee80211_input(ic, mp, in, rssi, 0);
	} else {
		sc->sc_rx_nobuf++;
		IWH_DBG((IWH_DEBUG_RX, "iwh_rx_mpdu_intr(): "
		    "alloc rx buf failed\n"));
	}

	/*
	 * release node reference
	 */
	ieee80211_free_node(in);
}

/*
 * process correlative affairs after a frame is sent.
 */
static void
iwh_tx_intr(iwh_sc_t *sc, iwh_rx_desc_t *desc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwh_tx_ring_t *ring = &sc->sc_txq[desc->hdr.qid & 0x3];
	iwh_tx_stat_t *stat = (iwh_tx_stat_t *)(desc + 1);
	iwh_amrr_t *amrr;

	if (NULL == ic->ic_bss) {
		return;
	}

	amrr = (iwh_amrr_t *)ic->ic_bss;

	amrr->txcnt++;
	IWH_DBG((IWH_DEBUG_RATECTL, "iwh_tx_intr(): "
	    "tx: %d cnt\n", amrr->txcnt));

	if (stat->ntries > 0) {
		amrr->retrycnt++;
		sc->sc_tx_retries++;
		IWH_DBG((IWH_DEBUG_TX, "iwh_tx_intr(): "
		    "tx: %d retries\n",
		    sc->sc_tx_retries));
	}

	mutex_enter(&sc->sc_mt_lock);
	sc->sc_tx_timer = 0;
	mutex_exit(&sc->sc_mt_lock);

	mutex_enter(&sc->sc_tx_lock);

	ring->queued--;
	if (ring->queued < 0) {
		ring->queued = 0;
	}

	if ((sc->sc_need_reschedule) && (ring->queued <= (ring->count >> 3))) {
		sc->sc_need_reschedule = 0;
		mutex_exit(&sc->sc_tx_lock);
		mac_tx_update(ic->ic_mach);
		mutex_enter(&sc->sc_tx_lock);
	}

	mutex_exit(&sc->sc_tx_lock);
}

/*
 * inform a given command has been executed
 */
static void
iwh_cmd_intr(iwh_sc_t *sc, iwh_rx_desc_t *desc)
{
	if ((desc->hdr.qid & 7) != 4) {
		return;
	}

	if (sc->sc_cmd_accum > 0) {
		sc->sc_cmd_accum--;
		return;
	}

	mutex_enter(&sc->sc_glock);

	sc->sc_cmd_flag = SC_CMD_FLG_DONE;

	cv_signal(&sc->sc_cmd_cv);

	mutex_exit(&sc->sc_glock);

	IWH_DBG((IWH_DEBUG_CMD, "iwh_cmd_intr(): "
	    "qid=%x idx=%d flags=%x type=0x%x\n",
	    desc->hdr.qid, desc->hdr.idx, desc->hdr.flags,
	    desc->hdr.type));
}

/*
 * this function will be invoked when alive notification occur.
 */
static void
iwh_ucode_alive(iwh_sc_t *sc, iwh_rx_desc_t *desc)
{
	uint32_t rv;
	struct iwh_calib_cfg_cmd cmd;
	struct iwh_alive_resp *ar =
	    (struct iwh_alive_resp *)(desc + 1);
	struct iwh_calib_results *res_p = &sc->sc_calib_results;

	/*
	 * the microcontroller is ready
	 */
	IWH_DBG((IWH_DEBUG_FW, "iwh_ucode_alive(): "
	    "microcode alive notification minor: %x major: %x type: "
	    "%x subtype: %x\n",
	    ar->ucode_minor, ar->ucode_minor, ar->ver_type, ar->ver_subtype));

#ifdef	DEBUG
	if (LE_32(ar->is_valid) != UCODE_VALID_OK) {
		IWH_DBG((IWH_DEBUG_FW, "iwh_ucode_alive(): "
		    "microcontroller initialization failed\n"));
	}
#endif

	/*
	 * determine if init alive or runtime alive.
	 */
	if (INITIALIZE_SUBTYPE == ar->ver_subtype) {
		IWH_DBG((IWH_DEBUG_FW, "iwh_ucode_alive(): "
		    "initialization alive received.\n"));

		bcopy(ar, &sc->sc_card_alive_init,
		    sizeof (struct iwh_init_alive_resp));

		/*
		 * necessary configuration to NIC
		 */
		mutex_enter(&sc->sc_glock);

		rv = iwh_alive_common(sc);
		if (rv != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_ucode_alive(): "
			    "common alive process failed in init alive.\n");
			mutex_exit(&sc->sc_glock);
			return;
		}

		(void) memset(&cmd, 0, sizeof (cmd));

		cmd.ucd_calib_cfg.once.is_enable = IWH_CALIB_INIT_CFG_ALL;
		cmd.ucd_calib_cfg.once.start = IWH_CALIB_INIT_CFG_ALL;
		cmd.ucd_calib_cfg.once.send_res = IWH_CALIB_INIT_CFG_ALL;
		cmd.ucd_calib_cfg.flags = IWH_CALIB_INIT_CFG_ALL;

		/*
		 * require ucode execute calibration
		 */
		rv = iwh_cmd(sc, CALIBRATION_CFG_CMD, &cmd, sizeof (cmd), 1);
		if (rv != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_ucode_alive(): "
			    "failed to send calibration configure command.\n");
			mutex_exit(&sc->sc_glock);
			return;
		}

		mutex_exit(&sc->sc_glock);

	} else {	/* runtime alive */

		IWH_DBG((IWH_DEBUG_FW, "iwh_ucode_alive(): "
		    "runtime alive received.\n"));

		bcopy(ar, &sc->sc_card_alive_run,
		    sizeof (struct iwh_alive_resp));

		mutex_enter(&sc->sc_glock);

		/*
		 * necessary configuration to NIC
		 */
		rv = iwh_alive_common(sc);
		if (rv != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_ucode_alive(): "
			    "common alive process failed in run alive.\n");
			mutex_exit(&sc->sc_glock);
			return;
		}

		/*
		 * send the result of local oscilator calibration to uCode.
		 */
		if (res_p->lo_res != NULL) {
			rv = iwh_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->lo_res, res_p->lo_res_len, 1);
			if (rv != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_ucode_alive(): "
				    "failed to send local"
				    "oscilator calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		/*
		 * send the result of TX IQ calibration to uCode.
		 */
		if (res_p->tx_iq_res != NULL) {
			rv = iwh_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->tx_iq_res, res_p->tx_iq_res_len, 1);
			if (rv != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_ucode_alive(): "
				    "failed to send TX IQ"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		/*
		 * sned the result of TX IQ perd calibration to uCode.
		 */
		if (res_p->tx_iq_perd_res != NULL) {
			rv = iwh_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->tx_iq_perd_res,
			    res_p->tx_iq_perd_res_len, 1);
			if (rv != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_ucode_alive(): "
				    "failed to send TX IQ perd"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		/*
		 * send the result of DC calibration to uCode.
		 */
		if (res_p->dc_res != NULL) {
			rv = iwh_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->dc_res,
			    res_p->dc_res_len, 1);
			if (rv != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_ucode_alive(): "
				    "failed to send DC"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		/*
		 * send the result of BASE BAND calibration to uCode.
		 */
		if (res_p->base_band_res != NULL) {
			rv = iwh_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->base_band_res,
			    res_p->base_band_res_len, 1);
			if (rv != IWH_SUCCESS) {
				cmn_err(CE_WARN, "iwh_ucode_alive(): "
				    "failed to send BASE BAND"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		atomic_or_32(&sc->sc_flags, IWH_F_FW_INIT);
		cv_signal(&sc->sc_ucode_cv);

		mutex_exit(&sc->sc_glock);
	}

}

/*
 * deal with receiving frames, command response
 * and all notifications from ucode.
 */
/* ARGSUSED */
static uint_t
iwh_rx_softintr(caddr_t arg, caddr_t unused)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	iwh_rx_desc_t *desc;
	iwh_rx_data_t *data;
	uint32_t index;

	if (NULL == arg) {
		return (DDI_INTR_UNCLAIMED);
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	/*
	 * firmware has moved the index of the rx queue, driver get it,
	 * and deal with it.
	 */
	index = (sc->sc_shared->val0) & 0xfff;

	while (sc->sc_rxq.cur != index) {
		data = &sc->sc_rxq.data[sc->sc_rxq.cur];
		desc = (iwh_rx_desc_t *)data->dma_data.mem_va;

		IWH_DBG((IWH_DEBUG_INTR, "iwh_rx_softintr(): "
		    "rx notification index = %d"
		    " cur = %d qid=%x idx=%d flags=%x type=%x len=%d\n",
		    index, sc->sc_rxq.cur, desc->hdr.qid, desc->hdr.idx,
		    desc->hdr.flags, desc->hdr.type, LE_32(desc->len)));

		/*
		 * a command other than a tx need to be replied
		 */
		if (!(desc->hdr.qid & 0x80) &&
		    (desc->hdr.type != REPLY_SCAN_CMD) &&
		    (desc->hdr.type != REPLY_TX)) {
			iwh_cmd_intr(sc, desc);
		}

		switch (desc->hdr.type) {
		case REPLY_RX_PHY_CMD:
			iwh_rx_phy_intr(sc, desc);
			break;

		case REPLY_RX_MPDU_CMD:
			iwh_rx_mpdu_intr(sc, desc);
			break;

		case REPLY_TX:
			iwh_tx_intr(sc, desc);
			break;

		case REPLY_ALIVE:
			iwh_ucode_alive(sc, desc);
			break;

		case CARD_STATE_NOTIFICATION:
		{
			uint32_t *status = (uint32_t *)(desc + 1);

			IWH_DBG((IWH_DEBUG_RADIO, "iwh_rx_softintr(): "
			    "state changed to %x\n",
			    LE_32(*status)));

			if (LE_32(*status) & 1) {
				/*
				 * the radio button has to be pushed(OFF). It
				 * is considered as a hw error, the
				 * iwh_thread() tries to recover it after the
				 * button is pushed again(ON)
				 */
				cmn_err(CE_NOTE, "iwh_rx_softintr(): "
				    "radio transmitter is off\n");
				sc->sc_ostate = sc->sc_ic.ic_state;
				ieee80211_new_state(&sc->sc_ic,
				    IEEE80211_S_INIT, -1);
				atomic_or_32(&sc->sc_flags,
				    (IWH_F_HW_ERR_RECOVER | IWH_F_RADIO_OFF));
			}

			break;
		}

		case SCAN_START_NOTIFICATION:
		{
			iwh_start_scan_t *scan =
			    (iwh_start_scan_t *)(desc + 1);

			IWH_DBG((IWH_DEBUG_SCAN, "iwh_rx_softintr(): "
			    "scanning channel %d status %x\n",
			    scan->chan, LE_32(scan->status)));

			ic->ic_curchan = &ic->ic_sup_channels[scan->chan];
			break;
		}

		case SCAN_COMPLETE_NOTIFICATION:
		{
#ifdef	DEBUG
			iwh_stop_scan_t *scan =
			    (iwh_stop_scan_t *)(desc + 1);

			IWH_DBG((IWH_DEBUG_SCAN, "iwh_rx_softintr(): "
			    "completed channel %d (burst of %d) status %02x\n",
			    scan->chan, scan->nchan, scan->status));
#endif

			sc->sc_scan_pending++;
			break;
		}

		case STATISTICS_NOTIFICATION:
		{
			/*
			 * handle statistics notification
			 */
			break;
		}

		case CALIBRATION_RES_NOTIFICATION:
			iwh_save_calib_result(sc, desc);
			break;

		case CALIBRATION_COMPLETE_NOTIFICATION:
			mutex_enter(&sc->sc_glock);
			atomic_or_32(&sc->sc_flags, IWH_F_FW_INIT);
			cv_signal(&sc->sc_ucode_cv);
			mutex_exit(&sc->sc_glock);
			break;

		case MISSED_BEACONS_NOTIFICATION:
			/* handle beacon miss by software mechanism */
			break;
		}

		sc->sc_rxq.cur = (sc->sc_rxq.cur + 1) % RX_QUEUE_SIZE;
	}

	/*
	 * driver dealt with what received in rx queue and tell the information
	 * to the firmware.
	 */
	index = (0 == index) ? RX_QUEUE_SIZE - 1 : index - 1;
	IWH_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, index & (~7));

	/*
	 * re-enable interrupts
	 */
	IWH_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	return (DDI_INTR_CLAIMED);
}

/*
 * the handle of interrupt
 */
/* ARGSUSED */
static uint_t
iwh_intr(caddr_t arg, caddr_t unused)
{
	iwh_sc_t *sc;
	uint32_t r, rfh;

	if (NULL == arg) {
		return (DDI_INTR_UNCLAIMED);
	}
	sc = (iwh_sc_t *)arg;

	r = IWH_READ(sc, CSR_INT);
	if (0 == r || 0xffffffff == r) {
		return (DDI_INTR_UNCLAIMED);
	}

	IWH_DBG((IWH_DEBUG_INTR, "iwh_intr(): "
	    "interrupt reg %x\n", r));

	rfh = IWH_READ(sc, CSR_FH_INT_STATUS);

	IWH_DBG((IWH_DEBUG_INTR, "iwh_intr(): "
	    "FH interrupt reg %x\n", rfh));

	/*
	 * disable interrupts
	 */
	IWH_WRITE(sc, CSR_INT_MASK, 0);

	/*
	 * ack interrupts
	 */
	IWH_WRITE(sc, CSR_INT, r);
	IWH_WRITE(sc, CSR_FH_INT_STATUS, rfh);

	if (r & (BIT_INT_SWERROR | BIT_INT_ERR)) {
		IWH_DBG((IWH_DEBUG_FW, "iwh_intr(): "
		    "fatal firmware error\n"));
		iwh_stop(sc);
		sc->sc_ostate = sc->sc_ic.ic_state;

		/*
		 * notify upper layer
		 */
		if (!IWH_CHK_FAST_RECOVER(sc)) {
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		}

		atomic_or_32(&sc->sc_flags, IWH_F_HW_ERR_RECOVER);
		return (DDI_INTR_CLAIMED);
	}

	if (r & BIT_INT_RF_KILL) {
		uint32_t tmp = IWH_READ(sc, CSR_GP_CNTRL);
		if (tmp & (1 << 27)) {
			cmn_err(CE_NOTE, "RF switch: radio on\n");
		}
	}

	if ((r & (BIT_INT_FH_RX | BIT_INT_SW_RX)) ||
	    (rfh & FH_INT_RX_MASK)) {
		(void) ddi_intr_trigger_softint(sc->sc_soft_hdl, NULL);
		return (DDI_INTR_CLAIMED);
	}

	if (r & BIT_INT_FH_TX) {
		mutex_enter(&sc->sc_glock);
		atomic_or_32(&sc->sc_flags, IWH_F_PUT_SEG);
		cv_signal(&sc->sc_put_seg_cv);
		mutex_exit(&sc->sc_glock);
	}

#ifdef	DEBUG
	if (r & BIT_INT_ALIVE)	{
		IWH_DBG((IWH_DEBUG_FW, "iwh_intr(): "
		    "firmware initialized.\n"));
	}
#endif

	/*
	 * re-enable interrupts
	 */
	IWH_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	return (DDI_INTR_CLAIMED);
}

static uint8_t
iwh_rate_to_plcp(int rate)
{
	uint8_t ret;

	switch (rate) {
	/*
	 * CCK rates
	 */
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

	/*
	 * OFDM rates
	 */
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

/*
 * invoked by GLD send frames
 */
static mblk_t *
iwh_m_tx(void *arg, mblk_t *mp)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	mblk_t *next;

	if (NULL == arg) {
		return (NULL);
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	if (sc->sc_flags & IWH_F_SUSPEND) {
		freemsgchain(mp);
		return (NULL);
	}

	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsgchain(mp);
		return (NULL);
	}

	if ((sc->sc_flags & IWH_F_HW_ERR_RECOVER) &&
	    IWH_CHK_FAST_RECOVER(sc)) {
		IWH_DBG((IWH_DEBUG_FW, "iwh_m_tx(): "
		    "hold queue\n"));
		return (mp);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (iwh_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != 0) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	return (mp);
}

/*
 * send frames
 */
static int
iwh_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	iwh_sc_t *sc;
	iwh_tx_ring_t *ring;
	iwh_tx_desc_t *desc;
	iwh_tx_data_t *data;
	iwh_tx_data_t *desc_data;
	iwh_cmd_t *cmd;
	iwh_tx_cmd_t *tx;
	ieee80211_node_t *in;
	struct ieee80211_frame *wh, *mp_wh;
	struct ieee80211_key *k = NULL;
	mblk_t *m, *m0;
	int hdrlen, len, len0, mblen, off, err = IWH_SUCCESS;
	uint16_t masks = 0;
	uint32_t rate, s_id = 0;
	int txq_id = NON_QOS_TXQ;
	struct ieee80211_qosframe *qwh = NULL;
	int tid = WME_TID_INVALID;

	if (NULL == ic) {
		return (IWH_FAIL);
	}
	sc = (iwh_sc_t *)ic;

	if (sc->sc_flags & IWH_F_SUSPEND) {
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		err = IWH_FAIL;
		goto exit;
	}

	if ((NULL == mp) || (MBLKL(mp) <= 0)) {
		return (IWH_FAIL);
	}

	mp_wh = (struct ieee80211_frame *)mp->b_rptr;

	/*
	 * Determine send which AP or station in IBSS
	 */
	in = ieee80211_find_txnode(ic, mp_wh->i_addr1);
	if (NULL == in) {
		cmn_err(CE_WARN, "iwh_send(): "
		    "failed to find tx node\n");
		freemsg(mp);
		sc->sc_tx_err++;
		err = IWH_SUCCESS;
		goto exit;
	}

	/*
	 * Determine TX queue according to traffic ID in frame
	 * if working in QoS mode.
	 */
	if (in->in_flags & IEEE80211_NODE_QOS) {

		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {

			if (mp_wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
				qwh = (struct ieee80211_qosframe *)mp_wh;

				tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
				txq_id = iwh_wme_tid_to_txq(tid);

				if (txq_id < TXQ_FOR_AC_MIN ||
				    (txq_id > TXQ_FOR_AC_MAX)) {
					freemsg(mp);
					sc->sc_tx_err++;
					err = IWH_SUCCESS;
					goto exit;
				}

			} else {
				txq_id = NON_QOS_TXQ;
			}

		} else if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_MGT) {
			txq_id = QOS_TXQ_FOR_MGT;
		} else {
			txq_id = NON_QOS_TXQ;
		}

	} else {
		txq_id = NON_QOS_TXQ;
	}

	mutex_enter(&sc->sc_tx_lock);
	ring = &sc->sc_txq[txq_id];
	data = &ring->data[ring->cur];
	cmd = data->cmd;
	bzero(cmd, sizeof (*cmd));

	ring->cur = (ring->cur + 1) % ring->count;

	/*
	 * Need reschedule TX if TX buffer is full.
	 */
	if (ring->queued > ring->count - IWH_MAX_WIN_SIZE) {
		IWH_DBG((IWH_DEBUG_TX, "iwh_send(): "
		"no txbuf\n"));

		sc->sc_need_reschedule = 1;
		mutex_exit(&sc->sc_tx_lock);

		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		sc->sc_tx_nobuf++;
		err = IWH_FAIL;
		goto exit;
	}

	ring->queued++;

	mutex_exit(&sc->sc_tx_lock);

	hdrlen = ieee80211_hdrspace(ic, mp->b_rptr);

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (NULL == m) { /* can not alloc buf, drop this package */
		cmn_err(CE_WARN, "iwh_send(): "
		    "failed to allocate msgbuf\n");
		freemsg(mp);

		mutex_enter(&sc->sc_tx_lock);
		ring->queued--;
		if ((sc->sc_need_reschedule) && (ring->queued <= 0)) {
			sc->sc_need_reschedule = 0;
			mutex_exit(&sc->sc_tx_lock);
			mac_tx_update(ic->ic_mach);
			mutex_enter(&sc->sc_tx_lock);
		}
		mutex_exit(&sc->sc_tx_lock);

		err = IWH_SUCCESS;
		goto exit;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		bcopy(m0->b_rptr, m->b_rptr + off, mblen);
		off += mblen;
	}

	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;

	/*
	 * Net80211 module encapsulate outbound data frames.
	 * Add some feilds of 80211 frame.
	 */
	if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA) {
		(void) ieee80211_encap(ic, m, in);
	}

	freemsg(mp);

	cmd->hdr.type = REPLY_TX;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;

	tx = (iwh_tx_cmd_t *)cmd->data;
	tx->tx_flags = 0;

	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		tx->tx_flags &= ~(LE_32(TX_CMD_FLG_ACK_MSK));
	} else {
		tx->tx_flags |= LE_32(TX_CMD_FLG_ACK_MSK);
	}

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (NULL == k) {
			freemsg(m);
			sc->sc_tx_err++;

			mutex_enter(&sc->sc_tx_lock);
			ring->queued--;
			if ((sc->sc_need_reschedule) && (ring->queued <= 0)) {
				sc->sc_need_reschedule = 0;
				mutex_exit(&sc->sc_tx_lock);
				mac_tx_update(ic->ic_mach);
				mutex_enter(&sc->sc_tx_lock);
			}
			mutex_exit(&sc->sc_tx_lock);

			err = IWH_SUCCESS;
			goto exit;
		}

		/*
		 * packet header may have moved, reset our local pointer
		 */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	len = msgdsize(m);

#ifdef DEBUG
	if (iwh_dbg_flags & IWH_DEBUG_TX) {
		ieee80211_dump_pkt((uint8_t *)wh, hdrlen, 0, 0);
	}
#endif

	tx->rts_retry_limit = IWH_TX_RTS_RETRY_LIMIT;
	tx->data_retry_limit = IWH_TX_DATA_RETRY_LIMIT;

	/*
	 * specific TX parameters for management frames
	 */
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_MGT) {
		/*
		 * mgmt frames are sent at 1M
		 */
		if ((in->in_rates.ir_rates[0] &
		    IEEE80211_RATE_VAL) != 0) {
			rate = in->in_rates.ir_rates[0] & IEEE80211_RATE_VAL;
		} else {
			rate = 2;
		}

		tx->tx_flags |= LE_32(TX_CMD_FLG_SEQ_CTL_MSK);

		/*
		 * tell h/w to set timestamp in probe responses
		 */
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
			tx->tx_flags |= LE_32(TX_CMD_FLG_TSF_MSK);

			tx->data_retry_limit = 3;
			if (tx->data_retry_limit < tx->rts_retry_limit) {
				tx->rts_retry_limit = tx->data_retry_limit;
			}
		}

		if (((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_ASSOC_REQ) ||
		    ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_REASSOC_REQ)) {
			tx->timeout.pm_frame_timeout = LE_16(3);
		} else {
			tx->timeout.pm_frame_timeout = LE_16(2);
		}

	} else {
		/*
		 * do it here for the software way rate scaling.
		 * later for rate scaling in hardware.
		 *
		 * now the txrate is determined in tx cmd flags, set to the
		 * max value 54M for 11g and 11M for 11b and 96M for 11n
		 * originally.
		 */
		if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
			rate = ic->ic_fixed_rate;
		} else {
			if ((in->in_flags & IEEE80211_NODE_HT) &&
			    (sc->sc_ht_conf.ht_support)) {
				iwh_amrr_t *amrr = (iwh_amrr_t *)in;
				rate = amrr->ht_mcs_idx;
			} else {
				if ((in->in_rates.ir_rates[in->in_txrate] &
				    IEEE80211_RATE_VAL) != 0) {
					rate = in->in_rates.
					    ir_rates[in->in_txrate] &
					    IEEE80211_RATE_VAL;
				}
			}
		}

		if (tid != WME_TID_INVALID) {
			tx->tid_tspec = (uint8_t)tid;
			tx->tx_flags &= LE_32(~TX_CMD_FLG_SEQ_CTL_MSK);
		} else {
			tx->tx_flags |= LE_32(TX_CMD_FLG_SEQ_CTL_MSK);
		}

		tx->timeout.pm_frame_timeout = 0;
	}

	IWH_DBG((IWH_DEBUG_TX, "iwh_send(): "
	    "tx rate[%d of %d] = %x",
	    in->in_txrate, in->in_rates.ir_nrates, rate));

	len0 = roundup(4 + sizeof (iwh_tx_cmd_t) + hdrlen, 4);
	if (len0 != (4 + sizeof (iwh_tx_cmd_t) + hdrlen)) {
		tx->tx_flags |= LE_32(TX_CMD_FLG_MH_PAD_MSK);
	}

	/*
	 * retrieve destination node's id
	 */
	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		tx->sta_id = IWH_BROADCAST_ID;
	} else {
		tx->sta_id = IWH_AP_ID;
	}

	if ((in->in_flags & IEEE80211_NODE_HT) &&
	    (sc->sc_ht_conf.ht_support) &&
	    ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA)) {
		if (rate >= HT_2CHAIN_RATE_MIN_IDX) {
			rate |= LE_32(RATE_MCS_ANT_AB_MSK);
		} else {
			rate |= LE_32(RATE_MCS_ANT_B_MSK);
		}

		rate |= LE_32((1 << RATE_MCS_HT_POS));

		tx->rate.r.rate_n_flags = rate;

	} else {
		if (2 == rate || 4 == rate || 11 == rate || 22 == rate) {
			masks |= RATE_MCS_CCK_MSK;
		}

		masks |= RATE_MCS_ANT_B_MSK;
		tx->rate.r.rate_n_flags = LE_32(iwh_rate_to_plcp(rate) | masks);
	}

	IWH_DBG((IWH_DEBUG_TX, "iwh_send(): "
	    "tx flag = %x",
	    tx->tx_flags));

	tx->stop_time.life_time  = LE_32(0xffffffff);

	tx->len = LE_16(len);

	tx->dram_lsb_ptr =
	    LE_32(data->paddr_cmd + 4 + offsetof(iwh_tx_cmd_t, scratch));
	tx->dram_msb_ptr = 0;
	tx->driver_txop = 0;
	tx->next_frame_len = 0;

	bcopy(m->b_rptr, tx + 1, hdrlen);
	m->b_rptr += hdrlen;
	bcopy(m->b_rptr, data->dma_data.mem_va, (len - hdrlen));

	IWH_DBG((IWH_DEBUG_TX, "iwh_send(): "
	    "sending data: qid=%d idx=%d len=%d",
	    ring->qid, ring->cur, len));

	/*
	 * first segment includes the tx cmd plus the 802.11 header,
	 * the second includes the remaining of the 802.11 frame.
	 */

	mutex_enter(&sc->sc_tx_lock);
	cmd->hdr.idx = ring->desc_cur;
	desc_data = &ring->data[ring->desc_cur];
	desc = desc_data->desc;
	bzero(desc, sizeof (*desc));
	desc->val0 = 2 << 24;
	desc->pa[0].tb1_addr = data->paddr_cmd;
	desc->pa[0].val1 = ((len0 << 4) & 0xfff0) |
	    ((data->dma_data.cookie.dmac_address & 0xffff) << 16);
	desc->pa[0].val2 =
	    ((data->dma_data.cookie.dmac_address & 0xffff0000) >> 16) |
	    ((len - hdrlen) << 20);
	IWH_DBG((IWH_DEBUG_TX, "iwh_send(): "
	    "phy addr1 = 0x%x phy addr2 = 0x%x "
	    "len1 = 0x%x, len2 = 0x%x val1 = 0x%x val2 = 0x%x",
	    data->paddr_cmd, data->dma_data.cookie.dmac_address,
	    len0, len - hdrlen, desc->pa[0].val1, desc->pa[0].val2));

	/*
	 * kick ring
	 */
	s_id = tx->sta_id;

	sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
	    tfd_offset[ring->desc_cur].val =
	    (8 + len) | (s_id << 12);
	if (ring->desc_cur < IWH_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWH_QUEUE_SIZE + ring->desc_cur].val =
		    (8 + len) | (s_id << 12);
	}

	IWH_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
	IWH_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	ring->desc_cur = (ring->desc_cur + 1) % ring->count;
	IWH_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->desc_cur);

	mutex_exit(&sc->sc_tx_lock);
	freemsg(m);

	/*
	 * release node reference
	 */
	ieee80211_free_node(in);

	ic->ic_stats.is_tx_bytes += len;
	ic->ic_stats.is_tx_frags++;

	mutex_enter(&sc->sc_mt_lock);
	if (0 == sc->sc_tx_timer) {
		sc->sc_tx_timer = 4;
	}
	mutex_exit(&sc->sc_mt_lock);

exit:
	return (err);
}

/*
 * invoked by GLD to deal with IOCTL affaires
 */
static void
iwh_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	int err = EINVAL;

	if (NULL == arg) {
		return;
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	err = ieee80211_ioctl(ic, wq, mp);
	if (ENETRESET == err) {
		/*
		 * This is special for the hidden AP connection.
		 * In any case, we should make sure only one 'scan'
		 * in the driver for a 'connect' CLI command. So
		 * when connecting to a hidden AP, the scan is just
		 * sent out to the air when we know the desired
		 * essid of the AP we want to connect.
		 */
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & IWH_F_RUNNING) {
				iwh_m_stop(sc);
				(void) iwh_m_start(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
	}
}

/*
 * Call back functions for get/set proporty
 */
static int
iwh_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	iwh_sc_t *sc;
	int err = EINVAL;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwh_sc_t *)arg;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
iwh_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t mph)
{
	iwh_sc_t	*sc = (iwh_sc_t *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, mph);
}

static int
iwh_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	int err = EINVAL;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);

	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & IWH_F_RUNNING) {
				iwh_m_stop(sc);
				(void) iwh_m_start(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
		err = 0;
	}
	return (err);
}

/*
 * invoked by GLD supply statistics NIC and driver
 */
static int
iwh_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	ieee80211_node_t *in;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	mutex_enter(&sc->sc_glock);

	switch (stat) {
	case MAC_STAT_IFSPEED:
		in = ic->ic_bss;
		*val = ((IEEE80211_FIXED_RATE_NONE == ic->ic_fixed_rate) ?
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

	return (IWH_SUCCESS);
}

/*
 * invoked by GLD to start or open NIC
 */
static int
iwh_m_start(void *arg)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	int err = IWH_FAIL;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	err = iwh_init(sc);
	if (err != IWH_SUCCESS) {
		/*
		 * The hw init err(eg. RF is OFF). Return Success to make
		 * the 'plumb' succeed. The iwh_thread() tries to re-init
		 * background.
		 */
		atomic_or_32(&sc->sc_flags, IWH_F_HW_ERR_RECOVER);
		return (IWH_SUCCESS);
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	atomic_or_32(&sc->sc_flags, IWH_F_RUNNING);

	return (IWH_SUCCESS);
}

/*
 * invoked by GLD to stop or down NIC
 */
static void
iwh_m_stop(void *arg)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;

	if (NULL == arg) {
		return;
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	iwh_stop(sc);

	/*
	 * release buffer for calibration
	 */
	iwh_release_calib_buffer(sc);

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	atomic_and_32(&sc->sc_flags, ~IWH_F_HW_ERR_RECOVER);
	atomic_and_32(&sc->sc_flags, ~IWH_F_RATE_AUTO_CTL);

	atomic_and_32(&sc->sc_flags, ~IWH_F_RUNNING);
	atomic_and_32(&sc->sc_flags, ~IWH_F_SCANNING);
}

/*
 * invoked by GLD to configure NIC
 */
static int
iwh_m_unicst(void *arg, const uint8_t *macaddr)
{
	iwh_sc_t *sc;
	ieee80211com_t *ic;
	int err = IWH_SUCCESS;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwh_sc_t *)arg;
	ic = &sc->sc_ic;

	if (!IEEE80211_ADDR_EQ(ic->ic_macaddr, macaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
		mutex_enter(&sc->sc_glock);
		err = iwh_config(sc);
		mutex_exit(&sc->sc_glock);
		if (err != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_m_unicst(): "
			    "failed to configure device\n");
			goto fail;
		}
	}

fail:
	return (err);
}

/* ARGSUSED */
static int
iwh_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	return (IWH_SUCCESS);
}

/* ARGSUSED */
static int
iwh_m_promisc(void *arg, boolean_t on)
{
	return (IWH_SUCCESS);
}

/*
 * kernel thread to deal with exceptional situation
 */
static void
iwh_thread(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	clock_t clk;
	int err, n = 0, timeout = 0;
	uint32_t tmp;
#ifdef	DEBUG
	int times = 0;
#endif

	while (sc->sc_mf_thread_switch) {
		tmp = IWH_READ(sc, CSR_GP_CNTRL);
		if (tmp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) {
			atomic_and_32(&sc->sc_flags, ~IWH_F_RADIO_OFF);
		} else {
			atomic_or_32(&sc->sc_flags, IWH_F_RADIO_OFF);
		}

		/*
		 * If  in SUSPEND or the RF is OFF, do nothing.
		 */
		if (sc->sc_flags & IWH_F_RADIO_OFF) {
			delay(drv_usectohz(100000));
			continue;
		}

		/*
		 * recovery fatal error
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IWH_F_HW_ERR_RECOVER)) {

			IWH_DBG((IWH_DEBUG_FW, "iwh_thread(): "
			    "try to recover fatal hw error: %d\n", times++));

			iwh_stop(sc);

			if (IWH_CHK_FAST_RECOVER(sc)) {
				/*
				 * save runtime configuration
				 */
				bcopy(&sc->sc_config, &sc->sc_config_save,
				    sizeof (sc->sc_config));
			} else {
				ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
				delay(drv_usectohz(2000000 + n*500000));
			}

			err = iwh_init(sc);
			if (err != IWH_SUCCESS) {
				n++;
				if (n < 20) {
					continue;
				}
			}

			n = 0;
			if (!err) {
				atomic_or_32(&sc->sc_flags, IWH_F_RUNNING);
			}


			if (!IWH_CHK_FAST_RECOVER(sc) ||
			    iwh_fast_recover(sc) != IWH_SUCCESS) {
				atomic_and_32(&sc->sc_flags,
				    ~IWH_F_HW_ERR_RECOVER);

				delay(drv_usectohz(2000000));
				if (sc->sc_ostate != IEEE80211_S_INIT) {
					ieee80211_new_state(ic,
					    IEEE80211_S_SCAN, 0);
				}
			}
		}

		if (ic->ic_mach &&
		    (sc->sc_flags & IWH_F_SCANNING) && sc->sc_scan_pending) {
			IWH_DBG((IWH_DEBUG_SCAN, "iwh_thread(): "
			    "wait for probe response\n"));

			sc->sc_scan_pending--;
			delay(drv_usectohz(200000));
			ieee80211_next_scan(ic);
		}

		/*
		 * rate ctl
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IWH_F_RATE_AUTO_CTL)) {
			clk = ddi_get_lbolt();
			if (clk > sc->sc_clk + drv_usectohz(1000000)) {
				iwh_amrr_timeout(sc);
			}
		}

		if ((ic->ic_state == IEEE80211_S_RUN) &&
		    (ic->ic_beaconmiss++ > 100)) {	/* 10 seconds */
			cmn_err(CE_WARN, "iwh: beacon missed for 10 seconds\n");
			(void) ieee80211_new_state(ic,
			    IEEE80211_S_INIT, -1);
		}

		delay(drv_usectohz(100000));

		mutex_enter(&sc->sc_mt_lock);
		if (sc->sc_tx_timer) {
			timeout++;
			if (10 == timeout) {
				sc->sc_tx_timer--;
				if (0 == sc->sc_tx_timer) {
					atomic_or_32(&sc->sc_flags,
					    IWH_F_HW_ERR_RECOVER);
					sc->sc_ostate = IEEE80211_S_RUN;
					IWH_DBG((IWH_DEBUG_FW, "iwh_thread(): "
					    "try to recover from "
					    "send fail\n"));
				}
				timeout = 0;
			}
		}
		mutex_exit(&sc->sc_mt_lock);
	}

	mutex_enter(&sc->sc_mt_lock);
	sc->sc_mf_thread = NULL;
	cv_signal(&sc->sc_mt_cv);
	mutex_exit(&sc->sc_mt_lock);
}

/*
 * Send a command to the ucode.
 */
static int
iwh_cmd(iwh_sc_t *sc, int code, const void *buf, int size, int async)
{
	iwh_tx_ring_t *ring = &sc->sc_txq[IWH_CMD_QUEUE_NUM];
	iwh_tx_desc_t *desc;
	iwh_cmd_t *cmd;

	ASSERT(size <= sizeof (cmd->data));
	ASSERT(mutex_owned(&sc->sc_glock));

	IWH_DBG((IWH_DEBUG_CMD, "iwh_cmd() "
	    "code[%d]", code));
	desc = ring->data[ring->cur].desc;
	cmd = ring->data[ring->cur].cmd;

	cmd->hdr.type = (uint8_t)code;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur;
	bcopy(buf, cmd->data, size);
	(void) memset(desc, 0, sizeof (*desc));

	desc->val0 = 1 << 24;
	desc->pa[0].tb1_addr =
	    (uint32_t)(ring->data[ring->cur].paddr_cmd & 0xffffffff);
	desc->pa[0].val1 = ((4 + size) << 4) & 0xfff0;

	if (async) {
		sc->sc_cmd_accum++;
	}

	/*
	 * kick cmd ring XXX
	 */
	sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
	    tfd_offset[ring->cur].val = 8;
	if (ring->cur < IWH_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWH_QUEUE_SIZE + ring->cur].val = 8;
	}
	ring->cur = (ring->cur + 1) % ring->count;
	IWH_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	if (async) {
		return (IWH_SUCCESS);
	} else {
		clock_t clk;

		clk = ddi_get_lbolt() + drv_usectohz(2000000);
		while (sc->sc_cmd_flag != SC_CMD_FLG_DONE) {
			if (cv_timedwait(&sc->sc_cmd_cv,
			    &sc->sc_glock, clk) < 0) {
				break;
			}
		}

		if (SC_CMD_FLG_DONE == sc->sc_cmd_flag) {
			sc->sc_cmd_flag = SC_CMD_FLG_NONE;
			return (IWH_SUCCESS);
		} else {
			sc->sc_cmd_flag = SC_CMD_FLG_NONE;
			return (IWH_FAIL);
		}
	}
}

/*
 * require ucode seting led of NIC
 */
static void
iwh_set_led(iwh_sc_t *sc, uint8_t id, uint8_t off, uint8_t on)
{
	iwh_led_cmd_t led;

	led.interval = LE_32(100000);	/* unit: 100ms */
	led.id = id;
	led.off = off;
	led.on = on;

	(void) iwh_cmd(sc, REPLY_LEDS_CMD, &led, sizeof (led), 1);
}

/*
 * necessary setting to NIC before authentication
 */
static int
iwh_hw_set_before_auth(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	int err = IWH_FAIL;

	/*
	 * update adapter's configuration according
	 * the info of target AP
	 */
	IEEE80211_ADDR_COPY(sc->sc_config.bssid, in->in_bssid);
	sc->sc_config.chan = LE_16(ieee80211_chan2ieee(ic, in->in_chan));

	if (ic->ic_curmode != IEEE80211_MODE_11NG) {

		sc->sc_config.ofdm_ht_triple_stream_basic_rates = 0;
		sc->sc_config.ofdm_ht_dual_stream_basic_rates = 0;
		sc->sc_config.ofdm_ht_single_stream_basic_rates = 0;

		if (IEEE80211_MODE_11B == ic->ic_curmode) {
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
	}

	sc->sc_config.flags &= ~LE_32(RXON_FLG_SHORT_PREAMBLE_MSK |
	    RXON_FLG_SHORT_SLOT_MSK);

	if (ic->ic_flags & IEEE80211_F_SHSLOT) {
		sc->sc_config.flags |= LE_32(RXON_FLG_SHORT_SLOT_MSK);
	} else {
		sc->sc_config.flags &= LE_32(~RXON_FLG_SHORT_SLOT_MSK);
	}

	if (ic->ic_flags & IEEE80211_F_SHPREAMBLE) {
		sc->sc_config.flags |= LE_32(RXON_FLG_SHORT_PREAMBLE_MSK);
	} else {
		sc->sc_config.flags &= LE_32(~RXON_FLG_SHORT_PREAMBLE_MSK);
	}

	IWH_DBG((IWH_DEBUG_80211, "iwh_hw_set_before_auth(): "
	    "config chan %d flags %x "
	    "filter_flags %x  cck %x ofdm %x"
	    " bssid:%02x:%02x:%02x:%02x:%02x:%2x\n",
	    LE_16(sc->sc_config.chan), LE_32(sc->sc_config.flags),
	    LE_32(sc->sc_config.filter_flags),
	    sc->sc_config.cck_basic_rates, sc->sc_config.ofdm_basic_rates,
	    sc->sc_config.bssid[0], sc->sc_config.bssid[1],
	    sc->sc_config.bssid[2], sc->sc_config.bssid[3],
	    sc->sc_config.bssid[4], sc->sc_config.bssid[5]));

	err = iwh_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwh_rxon_cmd_t), 1);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_hw_set_before_auth(): "
		    "failed to config chan%d\n", sc->sc_config.chan);
		return (err);
	}

	if ((sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		err = iwh_tx_power_table(sc, 1);
		if (err != IWH_SUCCESS) {
			return (err);
		}
	}

	/*
	 * add default AP node
	 */
	err = iwh_add_ap_sta(sc);
	if (err != IWH_SUCCESS) {
		return (err);
	}

	if ((sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		/*
		 * set up retry rate table for AP node
		 */
		err = iwh_ap_lq(sc);
		if (err != IWH_SUCCESS) {
			return (err);
		}
	}

	return (err);
}

/*
 * Send a scan request(assembly scan cmd) to the firmware.
 */
static int
iwh_scan(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwh_tx_ring_t *ring = &sc->sc_txq[IWH_CMD_QUEUE_NUM];
	iwh_tx_desc_t *desc;
	iwh_tx_data_t *data;
	iwh_cmd_t *cmd;
	iwh_scan_hdr_t *hdr;
	iwh_scan_chan_t chan;
	struct ieee80211_frame *wh;
	ieee80211_node_t *in = ic->ic_bss;
	uint8_t essid[IEEE80211_NWID_LEN+1];
	struct ieee80211_rateset *rs;
	enum ieee80211_phymode mode;
	uint8_t *frm;
	int i, pktlen, nrates;

	data = &ring->data[ring->cur];
	desc = data->desc;
	cmd = (iwh_cmd_t *)data->dma_data.mem_va;

	cmd->hdr.type = REPLY_SCAN_CMD;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur | 0x40;

	hdr = (iwh_scan_hdr_t *)cmd->data;
	(void) memset(hdr, 0, sizeof (iwh_scan_hdr_t));
	hdr->nchan = 1;
	hdr->quiet_time = LE_16(50);
	hdr->quiet_plcp_th = LE_16(1);

	hdr->flags = LE_32(RXON_FLG_BAND_24G_MSK);
	hdr->rx_chain = LE_16(RXON_RX_CHAIN_DRIVER_FORCE_MSK |
	    (0x7 << RXON_RX_CHAIN_VALID_POS) |
	    (0x2 << RXON_RX_CHAIN_FORCE_SEL_POS) |
	    (0x2 << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS));

	hdr->tx_cmd.tx_flags = LE_32(TX_CMD_FLG_SEQ_CTL_MSK);
	hdr->tx_cmd.sta_id = IWH_BROADCAST_ID;
	hdr->tx_cmd.stop_time.life_time = LE_32(0xffffffff);
	hdr->tx_cmd.rate.r.rate_n_flags = LE_32(iwh_rate_to_plcp(2));
	hdr->tx_cmd.rate.r.rate_n_flags |=
	    LE_32(RATE_MCS_ANT_B_MSK |RATE_MCS_CCK_MSK);
	hdr->direct_scan[0].len = ic->ic_des_esslen;
	hdr->direct_scan[0].id  = IEEE80211_ELEMID_SSID;

	hdr->filter_flags = LE_32(RXON_FILTER_ACCEPT_GRP_MSK |
	    RXON_FILTER_BCON_AWARE_MSK);

	if (ic->ic_des_esslen) {
		bcopy(ic->ic_des_essid, essid, ic->ic_des_esslen);
		essid[ic->ic_des_esslen] = '\0';
		IWH_DBG((IWH_DEBUG_SCAN, "iwh_scan(): "
		    "directed scan %s\n", essid));

		bcopy(ic->ic_des_essid, hdr->direct_scan[0].ssid,
		    ic->ic_des_esslen);
	} else {
		bzero(hdr->direct_scan[0].ssid,
		    sizeof (hdr->direct_scan[0].ssid));
	}

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

	/*
	 * essid IE
	 */
	if (in->in_esslen) {
		bcopy(in->in_essid, essid, in->in_esslen);
		essid[in->in_esslen] = '\0';
		IWH_DBG((IWH_DEBUG_SCAN, "iwh_scan(): "
		    "probe with ESSID %s\n",
		    essid));
	}
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = in->in_esslen;
	bcopy(in->in_essid, frm, in->in_esslen);
	frm += in->in_esslen;

	mode = ieee80211_chan2mode(ic, ic->ic_curchan);
	rs = &ic->ic_sup_rates[mode];

	/*
	 * supported rates IE
	 */
	*frm++ = IEEE80211_ELEMID_RATES;
	nrates = rs->ir_nrates;
	if (nrates > IEEE80211_RATE_SIZE) {
		nrates = IEEE80211_RATE_SIZE;
	}

	*frm++ = (uint8_t)nrates;
	bcopy(rs->ir_rates, frm, nrates);
	frm += nrates;

	/*
	 * supported xrates IE
	 */
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;
		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = (uint8_t)nrates;
		bcopy(rs->ir_rates + IEEE80211_RATE_SIZE, frm, nrates);
		frm += nrates;
	}

	/*
	 * optionnal IE (usually for wpa)
	 */
	if (ic->ic_opt_ie != NULL) {
		bcopy(ic->ic_opt_ie, frm, ic->ic_opt_ie_len);
		frm += ic->ic_opt_ie_len;
	}

	/* setup length of probe request */
	hdr->tx_cmd.len = LE_16(_PTRDIFF(frm, wh));
	hdr->len = LE_16(hdr->nchan * sizeof (iwh_scan_chan_t) +
	    LE_16(hdr->tx_cmd.len) + sizeof (iwh_scan_hdr_t));

	/*
	 * the attribute of the scan channels are required after the probe
	 * request frame.
	 */
	for (i = 1; i <= hdr->nchan; i++) {
		if (ic->ic_des_esslen) {
			chan.type = LE_32(3);
		} else {
			chan.type = LE_32(1);
		}

		chan.chan = LE_16(ieee80211_chan2ieee(ic, ic->ic_curchan));
		chan.tpc.tx_gain = 0x28;
		chan.tpc.dsp_atten = 110;
		chan.active_dwell = LE_16(50);
		chan.passive_dwell = LE_16(120);

		bcopy(&chan, frm, sizeof (iwh_scan_chan_t));
		frm += sizeof (iwh_scan_chan_t);
	}

	pktlen = _PTRDIFF(frm, cmd);

	(void) memset(desc, 0, sizeof (*desc));
	desc->val0 = 1 << 24;
	desc->pa[0].tb1_addr =
	    (uint32_t)(data->dma_data.cookie.dmac_address & 0xffffffff);
	desc->pa[0].val1 = (pktlen << 4) & 0xfff0;

	/*
	 * maybe for cmd, filling the byte cnt table is not necessary.
	 * anyway, we fill it here.
	 */
	sc->sc_shared->queues_byte_cnt_tbls[ring->qid]
	    .tfd_offset[ring->cur].val = 8;
	if (ring->cur < IWH_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWH_QUEUE_SIZE + ring->cur].val = 8;
	}

	/*
	 * kick cmd ring
	 */
	ring->cur = (ring->cur + 1) % ring->count;
	IWH_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	return (IWH_SUCCESS);
}

/*
 * configure NIC by using ucode commands after loading ucode.
 */
static int
iwh_config(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwh_powertable_cmd_t powertable;
	iwh_bt_cmd_t bt;
	iwh_add_sta_t node;
	iwh_rem_sta_t rm_sta;
	const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	iwh_link_quality_cmd_t link_quality;
	int i, err = IWH_FAIL;
	uint16_t masks = 0;

	/*
	 * set power mode. Disable power management at present, do it later
	 */
	(void) memset(&powertable, 0, sizeof (powertable));
	powertable.flags = LE_16(0x8);
	err = iwh_cmd(sc, POWER_TABLE_CMD, &powertable,
	    sizeof (powertable), 0);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_config(): "
		    "failed to set power mode\n");
		return (err);
	}

	/*
	 * configure bt coexistence
	 */
	(void) memset(&bt, 0, sizeof (bt));
	bt.flags = 3;
	bt.lead_time = 0xaa;
	bt.max_kill = 1;
	err = iwh_cmd(sc, REPLY_BT_CONFIG, &bt,
	    sizeof (bt), 0);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_config(): "
		    "failed to configurate bt coexistence\n");
		return (err);
	}

	/*
	 * configure rxon
	 */
	(void) memset(&sc->sc_config, 0, sizeof (iwh_rxon_cmd_t));
	IEEE80211_ADDR_COPY(sc->sc_config.node_addr, ic->ic_macaddr);
	IEEE80211_ADDR_COPY(sc->sc_config.wlap_bssid, ic->ic_macaddr);
	sc->sc_config.chan = LE_16(ieee80211_chan2ieee(ic, ic->ic_curchan));
	sc->sc_config.flags = LE_32(RXON_FLG_BAND_24G_MSK);
	sc->sc_config.flags &= LE_32(~(RXON_FLG_CHANNEL_MODE_MIXED_MSK |
	    RXON_FLG_CHANNEL_MODE_PURE_40_MSK));

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

		sc->sc_config.flags |= LE_32(RXON_FLG_SHORT_PREAMBLE_MSK);
		sc->sc_config.filter_flags = LE_32(RXON_FILTER_ACCEPT_GRP_MSK |
		    RXON_FILTER_DIS_DECRYPT_MSK |
		    RXON_FILTER_DIS_GRP_DECRYPT_MSK);
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

	/*
	 * Support all CCK rates.
	 */
	sc->sc_config.cck_basic_rates  = 0x0f;

	/*
	 * Support all OFDM rates.
	 */
	sc->sc_config.ofdm_basic_rates = 0xff;

	/*
	 * Determine HT supported rates.
	 */
	switch (sc->sc_ht_conf.rx_stream_count) {
	case 3:
		sc->sc_config.ofdm_ht_triple_stream_basic_rates = 0xff;
		sc->sc_config.ofdm_ht_dual_stream_basic_rates = 0xff;
		sc->sc_config.ofdm_ht_single_stream_basic_rates = 0xff;
		break;
	case 2:
		sc->sc_config.ofdm_ht_dual_stream_basic_rates = 0xff;
		sc->sc_config.ofdm_ht_single_stream_basic_rates = 0xff;
		break;
	case 1:
		sc->sc_config.ofdm_ht_single_stream_basic_rates = 0xff;
		break;
	default:
		cmn_err(CE_WARN, "iwh_config(): "
		    "RX stream count %d is not in suitable range\n",
		    sc->sc_ht_conf.rx_stream_count);
		return (IWH_FAIL);
	}

	/*
	 * set RX chains/antennas.
	 */
	iwh_config_rxon_chain(sc);

	err = iwh_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwh_rxon_cmd_t), 0);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_config(): "
		    "failed to set configure command\n");
		return (err);
	}

	/*
	 * remove all nodes in NIC
	 */
	(void) memset(&rm_sta, 0, sizeof (rm_sta));
	rm_sta.num_sta = 1;
	bcopy(bcast, rm_sta.addr, 6);

	err = iwh_cmd(sc, REPLY_REMOVE_STA, &rm_sta, sizeof (iwh_rem_sta_t), 0);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_config(): "
		    "failed to remove broadcast node in hardware.\n");
		return (err);
	}

	if ((sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		/*
		 * configure TX power table
		 */
		err = iwh_tx_power_table(sc, 0);
		if (err != IWH_SUCCESS) {
			return (err);
		}
	}

	/*
	 * add broadcast node so that we can send broadcast frame
	 */
	(void) memset(&node, 0, sizeof (node));
	(void) memset(node.sta.addr, 0xff, 6);
	node.mode = 0;
	node.sta.sta_id = IWH_BROADCAST_ID;
	node.station_flags = 0;

	err = iwh_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 0);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_config(): "
		    "failed to add broadcast node\n");
		return (err);
	}

	if ((sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		/*
		 * TX_LINK_QUALITY cmd
		 */
		(void) memset(&link_quality, 0, sizeof (link_quality));
		for (i = 0; i < LINK_QUAL_MAX_RETRY_NUM; i++) {
			masks |= RATE_MCS_CCK_MSK;
			masks |= RATE_MCS_ANT_B_MSK;
			masks &= ~RATE_MCS_ANT_A_MSK;
			link_quality.rate_n_flags[i] =
			    LE_32(iwh_rate_to_plcp(2) | masks);
		}

		link_quality.general_params.single_stream_ant_msk = 2;
		link_quality.general_params.dual_stream_ant_msk = 3;
		link_quality.agg_params.agg_dis_start_th = 3;
		link_quality.agg_params.agg_time_limit = LE_16(4000);
		link_quality.sta_id = IWH_BROADCAST_ID;
		err = iwh_cmd(sc, REPLY_TX_LINK_QUALITY_CMD, &link_quality,
		    sizeof (link_quality), 0);
		if (err != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_config(): "
			    "failed to config link quality table\n");
			return (err);
		}
	}

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
iwh_quiesce(dev_info_t *dip)
{
	iwh_sc_t *sc;

	sc = ddi_get_soft_state(iwh_soft_state_p, ddi_get_instance(dip));
	if (sc == NULL) {
		return (DDI_FAILURE);
	}

#ifdef DEBUG
	/*
	 * by pass any messages, if it's quiesce
	 */
	iwh_dbg_flags = 0;
#endif

	/*
	 * No more blocking is allowed while we are in the
	 * quiesce(9E) entry point.
	 */
	atomic_or_32(&sc->sc_flags, IWH_F_QUIESCED);

	/*
	 * Disable and mask all interrupts.
	 */
	iwh_stop(sc);

	return (DDI_SUCCESS);
}

static void
iwh_stop_master(iwh_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWH_READ(sc, CSR_RESET);
	IWH_WRITE(sc, CSR_RESET, tmp | CSR_RESET_REG_FLAG_STOP_MASTER);

	tmp = IWH_READ(sc, CSR_GP_CNTRL);
	if ((tmp & CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE) ==
	    CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE) {
		return;
	}

	for (n = 0; n < 2000; n++) {
		if (IWH_READ(sc, CSR_RESET) &
		    CSR_RESET_REG_FLAG_MASTER_DISABLED) {
			break;
		}
		DELAY(1000);
	}

#ifdef	DEBUG
	if (2000 == n) {
		IWH_DBG((IWH_DEBUG_HW, "iwh_stop_master(): "
		    "timeout waiting for master stop\n"));
	}
#endif
}

static int
iwh_power_up(iwh_sc_t *sc)
{
	uint32_t tmp;

	iwh_mac_access_enter(sc);
	tmp = iwh_reg_read(sc, ALM_APMG_PS_CTL);
	tmp &= ~APMG_PS_CTRL_REG_MSK_POWER_SRC;
	tmp |= APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN;
	iwh_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	iwh_mac_access_exit(sc);

	DELAY(5000);
	return (IWH_SUCCESS);
}

/*
 * hardware initialization
 */
static int
iwh_preinit(iwh_sc_t *sc)
{
	int n;
	uint8_t vlink;
	uint16_t radio_cfg;
	uint32_t tmp;

	/*
	 * clear any pending interrupts
	 */
	IWH_WRITE(sc, CSR_INT, 0xffffffff);

	tmp = IWH_READ(sc, CSR_GIO_CHICKEN_BITS);
	IWH_WRITE(sc, CSR_GIO_CHICKEN_BITS,
	    tmp | CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER);

	tmp = IWH_READ(sc, CSR_ANA_PLL_CFG);
	IWH_WRITE(sc, CSR_ANA_PLL_CFG, tmp | IWH_CSR_ANA_PLL_CFG);

	tmp = IWH_READ(sc, CSR_GP_CNTRL);
	IWH_WRITE(sc, CSR_GP_CNTRL, tmp | CSR_GP_CNTRL_REG_FLAG_INIT_DONE);

	/*
	 * wait for clock ready
	 */
	for (n = 0; n < 1000; n++) {
		if (IWH_READ(sc, CSR_GP_CNTRL) &
		    CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) {
			break;
		}
		DELAY(10);
	}

	if (1000 == n) {
		return (ETIMEDOUT);
	}

	iwh_mac_access_enter(sc);

	iwh_reg_write(sc, ALM_APMG_CLK_EN, APMG_CLK_REG_VAL_DMA_CLK_RQT);

	DELAY(20);
	tmp = iwh_reg_read(sc, ALM_APMG_PCIDEV_STT);
	iwh_reg_write(sc, ALM_APMG_PCIDEV_STT, tmp |
	    APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE);
	iwh_mac_access_exit(sc);

	radio_cfg = IWH_READ_EEP_SHORT(sc, EEP_SP_RADIO_CONFIGURATION);
	if (SP_RADIO_TYPE_MSK(radio_cfg) < SP_RADIO_TYPE_MAX) {
		tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
		IWH_WRITE(sc, CSR_HW_IF_CONFIG_REG,
		    tmp | SP_RADIO_TYPE_MSK(radio_cfg) |
		    SP_RADIO_STEP_MSK(radio_cfg) |
		    SP_RADIO_DASH_MSK(radio_cfg));
	} else {
		cmn_err(CE_WARN, "iwh_preinit(): "
		    "radio configuration information in eeprom is wrong\n");
		return (IWH_FAIL);
	}


	IWH_WRITE(sc, CSR_INT_COALESCING, 512 / 32);

	(void) iwh_power_up(sc);

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

	tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
	tmp |= CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
	    CSR_HW_IF_CONFIG_REG_BIT_MAC_SI;
	IWH_WRITE(sc, CSR_SW_VER, tmp);

	/*
	 * make sure power supply on each part of the hardware
	 */
	iwh_mac_access_enter(sc);
	tmp = iwh_reg_read(sc, ALM_APMG_PS_CTL);
	tmp |= APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ;
	iwh_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	DELAY(5);

	tmp = iwh_reg_read(sc, ALM_APMG_PS_CTL);
	tmp &= ~APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ;
	iwh_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	iwh_mac_access_exit(sc);

	return (IWH_SUCCESS);
}

/*
 * set up semphore flag to own EEPROM
 */
static int
iwh_eep_sem_down(iwh_sc_t *sc)
{
	int count1, count2;
	uint32_t tmp;

	for (count1 = 0; count1 < 1000; count1++) {
		tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
		IWH_WRITE(sc, CSR_HW_IF_CONFIG_REG,
		    tmp | CSR_HW_IF_CONFIG_REG_EEP_SEM);

		for (count2 = 0; count2 < 2; count2++) {
			if (IWH_READ(sc, CSR_HW_IF_CONFIG_REG) &
			    CSR_HW_IF_CONFIG_REG_EEP_SEM) {
				return (IWH_SUCCESS);
			}
			DELAY(10000);
		}
	}

	return (IWH_FAIL);
}

/*
 * reset semphore flag to release EEPROM
 */
static void
iwh_eep_sem_up(iwh_sc_t *sc)
{
	uint32_t tmp;

	tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
	IWH_WRITE(sc, CSR_HW_IF_CONFIG_REG,
	    tmp & (~CSR_HW_IF_CONFIG_REG_EEP_SEM));
}

/*
 * This function read all infomation from eeprom
 */
static int
iwh_eep_load(iwh_sc_t *sc)
{
	int i, rr;
	uint32_t rv, tmp, eep_gp;
	uint16_t addr, eep_sz = sizeof (sc->sc_eep_map);
	uint16_t *eep_p = (uint16_t *)&sc->sc_eep_map;

	/*
	 * read eeprom gp register in CSR
	 */
	eep_gp = IWH_READ(sc, CSR_EEPROM_GP);
	if ((eep_gp & CSR_EEPROM_GP_VALID_MSK) ==
	    CSR_EEPROM_GP_BAD_SIGNATURE) {
		IWH_DBG((IWH_DEBUG_EEPROM, "iwh_eep_load(): "
		    "not find eeprom\n"));
		return (IWH_FAIL);
	}

	rr = iwh_eep_sem_down(sc);
	if (rr != 0) {
		IWH_DBG((IWH_DEBUG_EEPROM, "iwh_eep_load(): "
		    "driver failed to own EEPROM\n"));
		return (IWH_FAIL);
	}

	for (addr = 0; addr < eep_sz; addr += 2) {
		IWH_WRITE(sc, CSR_EEPROM_REG, addr<<1);
		tmp = IWH_READ(sc, CSR_EEPROM_REG);
		IWH_WRITE(sc, CSR_EEPROM_REG, tmp & ~(0x2));

		for (i = 0; i < 10; i++) {
			rv = IWH_READ(sc, CSR_EEPROM_REG);
			if (rv & 1) {
				break;
			}
			DELAY(10);
		}

		if (!(rv & 1)) {
			IWH_DBG((IWH_DEBUG_EEPROM, "iwh_eep_load(): "
			    "time out when read eeprome\n"));
			iwh_eep_sem_up(sc);
			return (IWH_FAIL);
		}

		eep_p[addr/2] = LE_16(rv >> 16);
	}

	iwh_eep_sem_up(sc);
	return (IWH_SUCCESS);
}

/*
 * initialize mac address in ieee80211com_t struct
 */
static void
iwh_get_mac_from_eep(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	IEEE80211_ADDR_COPY(ic->ic_macaddr, &sc->sc_eep_map[EEP_MAC_ADDRESS]);

	IWH_DBG((IWH_DEBUG_EEPROM, "iwh_get_mac_from_eep(): "
	    "mac:%2x:%2x:%2x:%2x:%2x:%2x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1], ic->ic_macaddr[2],
	    ic->ic_macaddr[3], ic->ic_macaddr[4], ic->ic_macaddr[5]));
}

/*
 * main initialization function
 */
static int
iwh_init(iwh_sc_t *sc)
{
	int err = IWH_FAIL;
	clock_t clk;

	/*
	 * release buffer for calibration
	 */
	iwh_release_calib_buffer(sc);

	mutex_enter(&sc->sc_glock);
	atomic_and_32(&sc->sc_flags, ~IWH_F_FW_INIT);

	err = iwh_init_common(sc);
	if (err != IWH_SUCCESS) {
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	/*
	 * backup ucode data part for future use.
	 */
	bcopy(sc->sc_dma_fw_data.mem_va,
	    sc->sc_dma_fw_data_bak.mem_va,
	    sc->sc_dma_fw_data.alength);

	/* load firmware init segment into NIC */
	err = iwh_load_init_firmware(sc);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_init(): "
		    "failed to setup init firmware\n");
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	/*
	 * now press "execute" start running
	 */
	IWH_WRITE(sc, CSR_RESET, 0);

	clk = ddi_get_lbolt() + drv_usectohz(1000000);
	while (!(sc->sc_flags & IWH_F_FW_INIT)) {
		if (cv_timedwait(&sc->sc_ucode_cv,
		    &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWH_F_FW_INIT)) {
		cmn_err(CE_WARN, "iwh_init(): "
		    "failed to process init alive.\n");
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	mutex_exit(&sc->sc_glock);

	/*
	 * stop chipset for initializing chipset again
	 */
	iwh_stop(sc);

	mutex_enter(&sc->sc_glock);
	atomic_and_32(&sc->sc_flags, ~IWH_F_FW_INIT);

	err = iwh_init_common(sc);
	if (err != IWH_SUCCESS) {
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	/*
	 * load firmware run segment into NIC
	 */
	err = iwh_load_run_firmware(sc);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_init(): "
		    "failed to setup run firmware\n");
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	/*
	 * now press "execute" start running
	 */
	IWH_WRITE(sc, CSR_RESET, 0);

	clk = ddi_get_lbolt() + drv_usectohz(1000000);
	while (!(sc->sc_flags & IWH_F_FW_INIT)) {
		if (cv_timedwait(&sc->sc_ucode_cv,
		    &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWH_F_FW_INIT)) {
		cmn_err(CE_WARN, "iwh_init(): "
		    "failed to process runtime alive.\n");
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	mutex_exit(&sc->sc_glock);

	DELAY(1000);

	mutex_enter(&sc->sc_glock);
	atomic_and_32(&sc->sc_flags, ~IWH_F_FW_INIT);

	/*
	 * at this point, the firmware is loaded OK, then config the hardware
	 * with the ucode API, including rxon, txpower, etc.
	 */
	err = iwh_config(sc);
	if (err) {
		cmn_err(CE_WARN, "iwh_init(): "
		    "failed to configure device\n");
		mutex_exit(&sc->sc_glock);
		return (IWH_FAIL);
	}

	/*
	 * at this point, hardware may receive beacons :)
	 */
	mutex_exit(&sc->sc_glock);
	return (IWH_SUCCESS);
}

/*
 * stop or disable NIC
 */
static void
iwh_stop(iwh_sc_t *sc)
{
	uint32_t tmp;
	int i;

	/*
	 * by pass if it's quiesced
	 */
	if (!(sc->sc_flags & IWH_F_QUIESCED)) {
		mutex_enter(&sc->sc_glock);
	}

	IWH_WRITE(sc, CSR_RESET, CSR_RESET_REG_FLAG_NEVO_RESET);
	/*
	 * disable interrupts
	 */
	IWH_WRITE(sc, CSR_INT_MASK, 0);
	IWH_WRITE(sc, CSR_INT, CSR_INI_SET_MASK);
	IWH_WRITE(sc, CSR_FH_INT_STATUS, 0xffffffff);

	/*
	 * reset all Tx rings
	 */
	for (i = 0; i < IWH_NUM_QUEUES; i++) {
		iwh_reset_tx_ring(sc, &sc->sc_txq[i]);
	}

	/*
	 * reset Rx ring
	 */
	iwh_reset_rx_ring(sc);

	iwh_mac_access_enter(sc);
	iwh_reg_write(sc, ALM_APMG_CLK_DIS, APMG_CLK_REG_VAL_DMA_CLK_RQT);
	iwh_mac_access_exit(sc);

	DELAY(5);

	iwh_stop_master(sc);

	mutex_enter(&sc->sc_mt_lock);
	sc->sc_tx_timer = 0;
	mutex_exit(&sc->sc_mt_lock);

	tmp = IWH_READ(sc, CSR_RESET);
	IWH_WRITE(sc, CSR_RESET, tmp | CSR_RESET_REG_FLAG_SW_RESET);

	/*
	 * by pass if it's quiesced
	 */
	if (!(sc->sc_flags & IWH_F_QUIESCED)) {
		mutex_exit(&sc->sc_glock);
	}
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
	((amrr)->txcnt > 200)
#define	not_very_few(amrr)	\
	((amrr)->txcnt > 40)
#define	is_min_rate(in)		\
	(0 == (in)->in_txrate)
#define	is_max_rate(in)		\
	((in)->in_rates.ir_nrates - 1 == (in)->in_txrate)
#define	increase_rate(in)	\
	((in)->in_txrate++)
#define	decrease_rate(in)	\
	((in)->in_txrate--)
#define	reset_cnt(amrr)		\
	{ (amrr)->txcnt = (amrr)->retrycnt = 0; }

#define	IWH_AMRR_MIN_SUCCESS_THRESHOLD	 1
#define	IWH_AMRR_MAX_SUCCESS_THRESHOLD	15

static void
iwh_amrr_init(iwh_amrr_t *amrr)
{
	amrr->success = 0;
	amrr->recovery = 0;
	amrr->txcnt = amrr->retrycnt = 0;
	amrr->success_threshold = IWH_AMRR_MIN_SUCCESS_THRESHOLD;
	amrr->ht_mcs_idx = 0;	/* 6Mbps */
}

static void
iwh_amrr_timeout(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	IWH_DBG((IWH_DEBUG_RATECTL, "iwh_amrr_timeout(): "
	    "enter\n"));

	if (IEEE80211_M_STA == ic->ic_opmode) {
		iwh_amrr_ratectl(NULL, ic->ic_bss);
	} else {
		ieee80211_iterate_nodes(&ic->ic_sta, iwh_amrr_ratectl, NULL);
	}

	sc->sc_clk = ddi_get_lbolt();
}

static int
iwh_is_max_rate(ieee80211_node_t *in)
{
	int i;
	iwh_amrr_t *amrr = (iwh_amrr_t *)in;
	uint8_t r = (uint8_t)amrr->ht_mcs_idx;
	ieee80211com_t *ic = in->in_ic;
	iwh_sc_t *sc = (iwh_sc_t *)ic;

	if (in->in_flags & IEEE80211_NODE_HT) {
		for (i = in->in_htrates.rs_nrates - 1; i >= 0; i--) {
			r = in->in_htrates.rs_rates[i] &
			    IEEE80211_RATE_VAL;
			if (sc->sc_ht_conf.tx_support_mcs[r/8] &
			    (1 << (r%8))) {
				break;
			}
		}

		return (r == (uint8_t)amrr->ht_mcs_idx);
	} else {
		return (is_max_rate(in));
	}
}

static int
iwh_is_min_rate(ieee80211_node_t *in)
{
	int i;
	uint8_t r = 0;
	iwh_amrr_t *amrr = (iwh_amrr_t *)in;
	ieee80211com_t *ic = in->in_ic;
	iwh_sc_t *sc = (iwh_sc_t *)ic;

	if (in->in_flags & IEEE80211_NODE_HT) {
		for (i = 0; i < in->in_htrates.rs_nrates; i++) {
			r = in->in_htrates.rs_rates[i] &
			    IEEE80211_RATE_VAL;
			if (sc->sc_ht_conf.tx_support_mcs[r/8] &
			    (1 << (r%8))) {
				break;
			}
		}

		return (r == (uint8_t)amrr->ht_mcs_idx);
	} else {
		return (is_min_rate(in));
	}
}

static void
iwh_increase_rate(ieee80211_node_t *in)
{
	int i;
	uint8_t r;
	iwh_amrr_t *amrr = (iwh_amrr_t *)in;
	ieee80211com_t *ic = in->in_ic;
	iwh_sc_t *sc = (iwh_sc_t *)ic;

	if (in->in_flags & IEEE80211_NODE_HT) {
again:
		amrr->ht_mcs_idx++;

		for (i = 0; i < in->in_htrates.rs_nrates; i++) {
			r = in->in_htrates.rs_rates[i] &
			    IEEE80211_RATE_VAL;
			if ((r == (uint8_t)amrr->ht_mcs_idx) &&
			    (sc->sc_ht_conf.tx_support_mcs[r/8] &
			    (1 << (r%8)))) {
				break;
			}
		}

		if (i >= in->in_htrates.rs_nrates) {
			goto again;
		}
	} else {
		increase_rate(in);
	}
}

static void
iwh_decrease_rate(ieee80211_node_t *in)
{
	int i;
	uint8_t r;
	iwh_amrr_t *amrr = (iwh_amrr_t *)in;
	ieee80211com_t *ic = in->in_ic;
	iwh_sc_t *sc = (iwh_sc_t *)ic;

	if (in->in_flags & IEEE80211_NODE_HT) {
again:
		amrr->ht_mcs_idx--;

		for (i = 0; i < in->in_htrates.rs_nrates; i++) {
			r = in->in_htrates.rs_rates[i] &
			    IEEE80211_RATE_VAL;
			if ((r == (uint8_t)amrr->ht_mcs_idx) &&
			    (sc->sc_ht_conf.tx_support_mcs[r/8] &
			    (1 << (r%8)))) {
				break;
			}
		}

		if (i >= in->in_htrates.rs_nrates) {
			goto again;
		}
	} else {
		decrease_rate(in);
	}
}

/* ARGSUSED */
static void
iwh_amrr_ratectl(void *arg, ieee80211_node_t *in)
{
	iwh_amrr_t *amrr = (iwh_amrr_t *)in;
	int need_change = 0;

	if (is_success(amrr) && is_enough(amrr)) {
		amrr->success++;
		if (amrr->success >= amrr->success_threshold &&
		    !iwh_is_max_rate(in)) {
			amrr->recovery = 1;
			amrr->success = 0;
			iwh_increase_rate(in);
			IWH_DBG((IWH_DEBUG_RATECTL, "iwh_amrr_ratectl(): "
			    "AMRR increasing rate %d "
			    "(txcnt=%d retrycnt=%d), mcs_idx=%d\n",
			    in->in_txrate, amrr->txcnt,
			    amrr->retrycnt, amrr->ht_mcs_idx));
			need_change = 1;
		} else {
			amrr->recovery = 0;
		}
	} else if (not_very_few(amrr) && is_failure(amrr)) {
		amrr->success = 0;
		if (!iwh_is_min_rate(in)) {
			if (amrr->recovery) {
				amrr->success_threshold++;
				if (amrr->success_threshold >
				    IWH_AMRR_MAX_SUCCESS_THRESHOLD) {
					amrr->success_threshold =
					    IWH_AMRR_MAX_SUCCESS_THRESHOLD;
				}
			} else {
				amrr->success_threshold =
				    IWH_AMRR_MIN_SUCCESS_THRESHOLD;
			}
			iwh_decrease_rate(in);
			IWH_DBG((IWH_DEBUG_RATECTL, "iwh_amrr_ratectl(): "
			    "AMRR decreasing rate %d "
			    "(txcnt=%d retrycnt=%d), mcs_idx=%d\n",
			    in->in_txrate, amrr->txcnt,
			    amrr->retrycnt, amrr->ht_mcs_idx));
			need_change = 1;
		}
		amrr->recovery = 0;	/* paper is incorrect */
	}

	if (is_enough(amrr) || need_change) {
		reset_cnt(amrr);
	}
}

/*
 * translate indirect address in eeprom to direct address
 * in eeprom and return address of entry whos indirect address
 * is indi_addr
 */
static uint8_t *
iwh_eep_addr_trans(iwh_sc_t *sc, uint32_t indi_addr)
{
	uint32_t di_addr;
	uint16_t temp;

	if (!(indi_addr & INDIRECT_ADDRESS)) {
		di_addr = indi_addr;
		return (&sc->sc_eep_map[di_addr]);
	}

	switch (indi_addr & INDIRECT_TYPE_MSK) {
	case INDIRECT_GENERAL:
		temp = IWH_READ_EEP_SHORT(sc, EEP_LINK_GENERAL);
		break;

	case	INDIRECT_HOST:
		temp = IWH_READ_EEP_SHORT(sc, EEP_LINK_HOST);
		break;

	case	INDIRECT_REGULATORY:
		temp = IWH_READ_EEP_SHORT(sc, EEP_LINK_REGULATORY);
		break;

	case	INDIRECT_CALIBRATION:
		temp = IWH_READ_EEP_SHORT(sc, EEP_LINK_CALIBRATION);
		break;

	case	INDIRECT_PROCESS_ADJST:
		temp = IWH_READ_EEP_SHORT(sc, EEP_LINK_PROCESS_ADJST);
		break;

	case	INDIRECT_OTHERS:
		temp = IWH_READ_EEP_SHORT(sc, EEP_LINK_OTHERS);
		break;

	default:
		temp = 0;
		cmn_err(CE_WARN, "iwh_eep_addr_trans(): "
		    "incorrect indirect eeprom address.\n");
		break;
	}

	di_addr = (indi_addr & ADDRESS_MSK) + (temp << 1);

	return (&sc->sc_eep_map[di_addr]);
}

/*
 * loade a section of ucode into NIC
 */
static int
iwh_put_seg_fw(iwh_sc_t *sc, uint32_t addr_s, uint32_t addr_d, uint32_t len)
{

	iwh_mac_access_enter(sc);

	IWH_WRITE(sc, IWH_FH_TCSR_CHNL_TX_CONFIG_REG(IWH_FH_SRVC_CHNL),
	    IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);

	IWH_WRITE(sc, IWH_FH_SRVC_CHNL_SRAM_ADDR_REG(IWH_FH_SRVC_CHNL), addr_d);

	IWH_WRITE(sc, IWH_FH_TFDIB_CTRL0_REG(IWH_FH_SRVC_CHNL),
	    (addr_s & FH_MEM_TFDIB_DRAM_ADDR_LSB_MASK));

	IWH_WRITE(sc, IWH_FH_TFDIB_CTRL1_REG(IWH_FH_SRVC_CHNL), len);

	IWH_WRITE(sc, IWH_FH_TCSR_CHNL_TX_BUF_STS_REG(IWH_FH_SRVC_CHNL),
	    (1 << IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM) |
	    (1 << IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX) |
	    IWH_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID);

	IWH_WRITE(sc, IWH_FH_TCSR_CHNL_TX_CONFIG_REG(IWH_FH_SRVC_CHNL),
	    IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
	    IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL |
	    IWH_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD);

	iwh_mac_access_exit(sc);

	return (IWH_SUCCESS);
}

/*
 * necessary setting during alive notification
 */
static int
iwh_alive_common(iwh_sc_t *sc)
{
	uint32_t base;
	uint32_t i;
	iwh_wimax_coex_cmd_t w_cmd;
	iwh_calibration_crystal_cmd_t c_cmd;
	uint32_t rv = IWH_FAIL;

	/*
	 * initialize SCD related registers to make TX work.
	 */
	iwh_mac_access_enter(sc);

	/*
	 * read sram address of data base.
	 */
	sc->sc_scd_base = iwh_reg_read(sc, IWH_SCD_SRAM_BASE_ADDR);

	for (base = sc->sc_scd_base + IWH_SCD_CONTEXT_DATA_OFFSET;
	    base < sc->sc_scd_base + IWH_SCD_TX_STTS_BITMAP_OFFSET;
	    base += 4) {
		iwh_mem_write(sc, base, 0);
	}

	for (; base < sc->sc_scd_base + IWH_SCD_TRANSLATE_TBL_OFFSET;
	    base += 4) {
		iwh_mem_write(sc, base, 0);
	}

	for (i = 0; i < sizeof (uint16_t) * IWH_NUM_QUEUES; i += 4) {
		iwh_mem_write(sc, base + i, 0);
	}

	iwh_reg_write(sc, IWH_SCD_DRAM_BASE_ADDR,
	    sc->sc_dma_sh.cookie.dmac_address >> 10);

	iwh_reg_write(sc, IWH_SCD_QUEUECHAIN_SEL,
	    IWH_SCD_QUEUECHAIN_SEL_ALL(IWH_NUM_QUEUES));

	iwh_reg_write(sc, IWH_SCD_AGGR_SEL, 0);

	for (i = 0; i < IWH_NUM_QUEUES; i++) {
		iwh_reg_write(sc, IWH_SCD_QUEUE_RDPTR(i), 0);
		IWH_WRITE(sc, HBUS_TARG_WRPTR, 0 | (i << 8));
		iwh_mem_write(sc, sc->sc_scd_base +
		    IWH_SCD_CONTEXT_QUEUE_OFFSET(i), 0);
		iwh_mem_write(sc, sc->sc_scd_base +
		    IWH_SCD_CONTEXT_QUEUE_OFFSET(i) +
		    sizeof (uint32_t),
		    ((SCD_WIN_SIZE << IWH_SCD_QUEUE_CTX_REG2_WIN_SIZE_POS) &
		    IWH_SCD_QUEUE_CTX_REG2_WIN_SIZE_MSK) |
		    ((SCD_FRAME_LIMIT <<
		    IWH_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS) &
		    IWH_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK));
	}

	iwh_reg_write(sc, IWH_SCD_INTERRUPT_MASK, (1 << IWH_NUM_QUEUES) - 1);

	iwh_reg_write(sc, (IWH_SCD_BASE + 0x10),
	    SCD_TXFACT_REG_TXFIFO_MASK(0, 7));

	IWH_WRITE(sc, HBUS_TARG_WRPTR, (IWH_CMD_QUEUE_NUM << 8));
	iwh_reg_write(sc, IWH_SCD_QUEUE_RDPTR(IWH_CMD_QUEUE_NUM), 0);

	/*
	 * queue 0-7 map to FIFO 0-7 and
	 * all queues work under FIFO mode(none-scheduler_ack)
	 */
	for (i = 0; i < 4; i++) {
		iwh_reg_write(sc, IWH_SCD_QUEUE_STATUS_BITS(i),
		    (1 << IWH_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
		    ((3-i) << IWH_SCD_QUEUE_STTS_REG_POS_TXF) |
		    (1 << IWH_SCD_QUEUE_STTS_REG_POS_WSL) |
		    IWH_SCD_QUEUE_STTS_REG_MSK);
	}

	iwh_reg_write(sc, IWH_SCD_QUEUE_STATUS_BITS(IWH_CMD_QUEUE_NUM),
	    (1 << IWH_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
	    (IWH_CMD_FIFO_NUM << IWH_SCD_QUEUE_STTS_REG_POS_TXF) |
	    (1 << IWH_SCD_QUEUE_STTS_REG_POS_WSL) |
	    IWH_SCD_QUEUE_STTS_REG_MSK);

	for (i = 5; i < 7; i++) {
		iwh_reg_write(sc, IWH_SCD_QUEUE_STATUS_BITS(i),
		    (1 << IWH_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
		    (i << IWH_SCD_QUEUE_STTS_REG_POS_TXF) |
		    (1 << IWH_SCD_QUEUE_STTS_REG_POS_WSL) |
		    IWH_SCD_QUEUE_STTS_REG_MSK);
	}

	iwh_mac_access_exit(sc);

	(void) memset(&w_cmd, 0, sizeof (w_cmd));

	rv = iwh_cmd(sc, COEX_PRIORITY_TABLE_CMD, &w_cmd, sizeof (w_cmd), 1);
	if (rv != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_alive_common(): "
		    "failed to send wimax coexist command.\n");
		return (rv);
	}

	if ((sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		(void) memset(&c_cmd, 0, sizeof (c_cmd));

		c_cmd.opCode = PHY_CALIBRATE_CRYSTAL_FRQ_CMD;
		c_cmd.data.cap_pin1 = LE_16(sc->sc_eep_calib->xtal_calib[0]);
		c_cmd.data.cap_pin2 = LE_16(sc->sc_eep_calib->xtal_calib[1]);

		rv = iwh_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
		    &c_cmd, sizeof (c_cmd), 1);
		if (rv != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_alive_common(): "
			    "failed to send crystal"
			    "frq calibration command.\n");
			return (rv);
		}

		/*
		 * make sure crystal frequency calibration ready
		 * before next operations.
		 */
		DELAY(1000);
	}

	return (IWH_SUCCESS);
}

/*
 * save results of calibration from ucode
 */
static void
iwh_save_calib_result(iwh_sc_t *sc, iwh_rx_desc_t *desc)
{
	struct iwh_calib_results *res_p = &sc->sc_calib_results;
	struct iwh_calib_hdr *calib_hdr = (struct iwh_calib_hdr *)(desc + 1);
	int len = LE_32(desc->len);

	/*
	 * ensure the size of buffer is not too big
	 */
	len = (len & FH_RSCSR_FRAME_SIZE_MASK) - 4;

	switch (calib_hdr->op_code) {
	case PHY_CALIBRATE_LO_CMD:
		if (NULL == res_p->lo_res) {
			res_p->lo_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->lo_res) {
			cmn_err(CE_WARN, "iwh_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->lo_res_len = len;
		bcopy(calib_hdr, res_p->lo_res, len);
		break;

	case PHY_CALIBRATE_TX_IQ_CMD:
		if (NULL == res_p->tx_iq_res) {
			res_p->tx_iq_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->tx_iq_res) {
			cmn_err(CE_WARN, "iwh_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->tx_iq_res_len = len;
		bcopy(calib_hdr, res_p->tx_iq_res, len);
		break;

	case PHY_CALIBRATE_TX_IQ_PERD_CMD:
		if (NULL == res_p->tx_iq_perd_res) {
			res_p->tx_iq_perd_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->tx_iq_perd_res) {
			cmn_err(CE_WARN, "iwh_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->tx_iq_perd_res_len = len;
		bcopy(calib_hdr, res_p->tx_iq_perd_res, len);
		break;

	case PHY_CALIBRATE_DC_CMD:
		if (NULL == res_p->dc_res) {
			res_p->dc_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->dc_res) {
			cmn_err(CE_WARN, "iwh_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->dc_res_len = len;
		bcopy(calib_hdr, res_p->dc_res, len);
		break;

	case PHY_CALIBRATE_BASE_BAND_CMD:
		if (NULL == res_p->base_band_res) {
			res_p->base_band_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->base_band_res) {
			cmn_err(CE_WARN, "iwh_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->base_band_res_len = len;
		bcopy(calib_hdr, res_p->base_band_res, len);
		break;

	default:
		cmn_err(CE_WARN, "iwh_save_calib_result(): "
		    "incorrect calibration type(%d).\n", calib_hdr->op_code);
		break;
	}

}

/*
 * configure TX pwoer table
 */
static int
iwh_tx_power_table(iwh_sc_t *sc, int async)
{
	iwh_tx_power_table_cmd_t txpower;
	int i, err = IWH_FAIL;

	(void) memset(&txpower, 0, sizeof (txpower));

	txpower.band = 1; /* for 2.4G */
	txpower.channel = (uint8_t)LE_16(sc->sc_config.chan);
	txpower.pa_measurements = 1;
	txpower.max_mcs = 23;

	for (i = 0; i < 24; i++) {
		txpower.db.ht_ofdm_power[i].s.radio_tx_gain[0] = 0x16;
		txpower.db.ht_ofdm_power[i].s.radio_tx_gain[1] = 0x16;
		txpower.db.ht_ofdm_power[i].s.radio_tx_gain[2] = 0x16;
		txpower.db.ht_ofdm_power[i].s.dsp_predis_atten[0] = 0x6E;
		txpower.db.ht_ofdm_power[i].s.dsp_predis_atten[1] = 0x6E;
		txpower.db.ht_ofdm_power[i].s.dsp_predis_atten[2] = 0x6E;
	}

	for (i = 0; i < 2; i++) {
		txpower.db.cck_power[i].s.radio_tx_gain[0] = 0x16;
		txpower.db.cck_power[i].s.radio_tx_gain[1] = 0x16;
		txpower.db.cck_power[i].s.radio_tx_gain[2] = 0x16;
		txpower.db.cck_power[i].s.dsp_predis_atten[0] = 0x6E;
		txpower.db.cck_power[i].s.dsp_predis_atten[1] = 0x6E;
		txpower.db.cck_power[i].s.dsp_predis_atten[2] = 0x6E;
	}

	err = iwh_cmd(sc, REPLY_TX_PWR_TABLE_CMD, &txpower,
	    sizeof (txpower), async);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_tx_power_table(): "
		    "failed to set tx power table.\n");
		return (err);
	}

	return (err);
}

static void
iwh_release_calib_buffer(iwh_sc_t *sc)
{
	if (sc->sc_calib_results.lo_res != NULL) {
		kmem_free(sc->sc_calib_results.lo_res,
		    sc->sc_calib_results.lo_res_len);
		sc->sc_calib_results.lo_res = NULL;
	}

	if (sc->sc_calib_results.tx_iq_res != NULL) {
		kmem_free(sc->sc_calib_results.tx_iq_res,
		    sc->sc_calib_results.tx_iq_res_len);
		sc->sc_calib_results.tx_iq_res = NULL;
	}

	if (sc->sc_calib_results.tx_iq_perd_res != NULL) {
		kmem_free(sc->sc_calib_results.tx_iq_perd_res,
		    sc->sc_calib_results.tx_iq_perd_res_len);
		sc->sc_calib_results.tx_iq_perd_res = NULL;
	}

	if (sc->sc_calib_results.dc_res != NULL) {
		kmem_free(sc->sc_calib_results.dc_res,
		    sc->sc_calib_results.dc_res_len);
		sc->sc_calib_results.dc_res = NULL;
	}

	if (sc->sc_calib_results.base_band_res != NULL) {
		kmem_free(sc->sc_calib_results.base_band_res,
		    sc->sc_calib_results.base_band_res_len);
		sc->sc_calib_results.base_band_res = NULL;
	}
}

/*
 * common section of intialization
 */
static int
iwh_init_common(iwh_sc_t *sc)
{
	int32_t	qid;
	uint32_t tmp;

	if (iwh_reset_hw(sc) != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_init_common(): "
		    "failed to reset hardware\n");
		return (IWH_FAIL);
	}

	(void) iwh_preinit(sc);

	tmp = IWH_READ(sc, CSR_GP_CNTRL);
	if (!(tmp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)) {
		cmn_err(CE_NOTE, "iwh_init_common(): "
		    "radio transmitter is off\n");
		return (IWH_FAIL);
	}

	/*
	 * init Rx ring
	 */
	iwh_mac_access_enter(sc);
	IWH_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);

	IWH_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, 0);
	IWH_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_BASE_REG,
	    sc->sc_rxq.dma_desc.cookie.dmac_address >> 8);

	IWH_WRITE(sc, FH_RSCSR_CHNL0_STTS_WPTR_REG,
	    ((uint32_t)(sc->sc_dma_sh.cookie.dmac_address +
	    offsetof(struct iwh_shared, val0)) >> 4));

	IWH_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG,
	    FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL |
	    FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL |
	    IWH_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_8K |
	    (RX_QUEUE_SIZE_LOG <<
	    FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT));
	iwh_mac_access_exit(sc);
	IWH_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG,
	    (RX_QUEUE_SIZE - 1) & ~0x7);

	/*
	 * init Tx rings
	 */
	iwh_mac_access_enter(sc);
	iwh_reg_write(sc, IWH_SCD_TXFACT, 0);

	/*
	 * keep warm page
	 */
	IWH_WRITE(sc, IWH_FH_KW_MEM_ADDR_REG,
	    sc->sc_dma_kw.cookie.dmac_address >> 4);

	for (qid = 0; qid < IWH_NUM_QUEUES; qid++) {
		IWH_WRITE(sc, FH_MEM_CBBC_QUEUE(qid),
		    sc->sc_txq[qid].dma_desc.cookie.dmac_address >> 8);
		IWH_WRITE(sc, IWH_FH_TCSR_CHNL_TX_CONFIG_REG(qid),
		    IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
		    IWH_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL);
	}

	iwh_mac_access_exit(sc);

	/*
	 * clear "radio off" and "disable command" bits
	 */
	IWH_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	IWH_WRITE(sc, CSR_UCODE_DRV_GP1_CLR,
	    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);

	/*
	 * clear any pending interrupts
	 */
	IWH_WRITE(sc, CSR_INT, 0xffffffff);

	/*
	 * enable interrupts
	 */
	IWH_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	IWH_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	IWH_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	return (IWH_SUCCESS);
}

static int
iwh_fast_recover(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	int err = IWH_FAIL;

	mutex_enter(&sc->sc_glock);

	/*
	 * restore runtime configuration
	 */
	bcopy(&sc->sc_config_save, &sc->sc_config,
	    sizeof (sc->sc_config));

	sc->sc_config.assoc_id = 0;
	sc->sc_config.filter_flags &= ~LE_32(RXON_FILTER_ASSOC_MSK);

	if ((err = iwh_hw_set_before_auth(sc)) != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_fast_recover(): "
		    "could not setup authentication\n");
		mutex_exit(&sc->sc_glock);
		return (err);
	}

	bcopy(&sc->sc_config_save, &sc->sc_config,
	    sizeof (sc->sc_config));

	/*
	 * update adapter's configuration
	 */
	err = iwh_run_state_config(sc);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_fast_recover(): "
		    "failed to setup association\n");
		mutex_exit(&sc->sc_glock);
		return (err);
	}

	/*
	 * set LED on
	 */
	iwh_set_led(sc, 2, 0, 1);

	mutex_exit(&sc->sc_glock);

	atomic_and_32(&sc->sc_flags, ~IWH_F_HW_ERR_RECOVER);

	/*
	 * start queue
	 */
	IWH_DBG((IWH_DEBUG_FW, "iwh_fast_recover(): "
	    "resume xmit\n"));
	mac_tx_update(ic->ic_mach);

	return (IWH_SUCCESS);
}

static int
iwh_run_state_config(iwh_sc_t *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	uint32_t ht_protec = (uint32_t)(-1);
	int err = IWH_FAIL;

	/*
	 * update adapter's configuration
	 */
	sc->sc_config.assoc_id = in->in_associd & 0x3fff;

	/*
	 * short preamble/slot time are
	 * negotiated when associating
	 */
	sc->sc_config.flags &=
	    ~LE_32(RXON_FLG_SHORT_PREAMBLE_MSK |
	    RXON_FLG_SHORT_SLOT_MSK);

	if (ic->ic_flags & IEEE80211_F_SHSLOT) {
		sc->sc_config.flags |=
		    LE_32(RXON_FLG_SHORT_SLOT_MSK);
	}

	if (ic->ic_flags & IEEE80211_F_SHPREAMBLE) {
		sc->sc_config.flags |=
		    LE_32(RXON_FLG_SHORT_PREAMBLE_MSK);
	}

	if (in->in_flags & IEEE80211_NODE_HT) {
		ht_protec = in->in_htopmode;
		if (ht_protec > 3) {
			cmn_err(CE_WARN, "iwh_run_state_config(): "
			    "HT protection mode is not correct.\n");
			return (IWH_FAIL);
		} else if (NO_HT_PROT == ht_protec) {
			ht_protec = sc->sc_ht_conf.ht_protection;
		}

		sc->sc_config.flags |=
		    LE_32(ht_protec << RXON_FLG_HT_OPERATING_MODE_POS);
	}

	/*
	 * set RX chains/antennas.
	 */
	iwh_config_rxon_chain(sc);

	sc->sc_config.filter_flags |=
	    LE_32(RXON_FILTER_ASSOC_MSK);

	if (ic->ic_opmode != IEEE80211_M_STA) {
		sc->sc_config.filter_flags |=
		    LE_32(RXON_FILTER_BCON_AWARE_MSK);
	}

	IWH_DBG((IWH_DEBUG_80211, "iwh_run_state_config(): "
	    "config chan %d flags %x"
	    " filter_flags %x\n",
	    sc->sc_config.chan, sc->sc_config.flags,
	    sc->sc_config.filter_flags));

	err = iwh_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwh_rxon_cmd_t), 1);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_run_state_config(): "
		    "could not update configuration\n");
		return (err);
	}

	if ((sc->sc_dev_id != 0x423c) &&
	    (sc->sc_dev_id != 0x423d)) {
		/*
		 * send tx power table command
		 */
		err = iwh_tx_power_table(sc, 1);
		if (err != IWH_SUCCESS) {
			return (err);
		}
	}

	/*
	 * Not need to update retry rate table for AP node
	 */
	err = iwh_qosparam_to_hw(sc, 1);
	if (err != IWH_SUCCESS) {
		return (err);
	}

	return (err);
}

/*
 * This function is only for compatibility with Net80211 module.
 * iwh_qosparam_to_hw() is the actual function updating EDCA
 * parameters to hardware.
 */
/* ARGSUSED */
static int
iwh_wme_update(ieee80211com_t *ic)
{
	return (0);
}

static int
iwh_wme_to_qos_ac(int wme_ac)
{
	int qos_ac = QOS_AC_INVALID;

	if (wme_ac < WME_AC_BE || wme_ac > WME_AC_VO) {
		cmn_err(CE_WARN, "iwh_wme_to_qos_ac(): "
		    "WME AC index is not in suitable range.\n");
		return (qos_ac);
	}

	switch (wme_ac) {
	case WME_AC_BE:
		qos_ac = QOS_AC_BK;
		break;
	case WME_AC_BK:
		qos_ac = QOS_AC_BE;
		break;
	case WME_AC_VI:
		qos_ac = QOS_AC_VI;
		break;
	case WME_AC_VO:
		qos_ac = QOS_AC_VO;
		break;
	}

	return (qos_ac);
}

static uint16_t
iwh_cw_e_to_cw(uint8_t cw_e)
{
	uint16_t cw = 1;

	while (cw_e > 0) {
		cw <<= 1;
		cw_e--;
	}

	cw -= 1;
	return (cw);
}

static int
iwh_wmeparam_check(struct wmeParams *wmeparam)
{
	int i;

	for (i = 0; i < WME_NUM_AC; i++) {

		if ((wmeparam[i].wmep_logcwmax > QOS_CW_RANGE_MAX) ||
		    (wmeparam[i].wmep_logcwmin >= wmeparam[i].wmep_logcwmax)) {
			cmn_err(CE_WARN, "iwh_wmeparam_check(): "
			    "Contention window is not in suitable range.\n");
			return (IWH_FAIL);
		}

		if ((wmeparam[i].wmep_aifsn < QOS_AIFSN_MIN) ||
		    (wmeparam[i].wmep_aifsn > QOS_AIFSN_MAX)) {
			cmn_err(CE_WARN, "iwh_wmeparam_check(): "
			    "Arbitration interframe space number"
			    "is not in suitable range.\n");
			return (IWH_FAIL);
		}
	}

	return (IWH_SUCCESS);
}

/*
 * This function updates EDCA parameters into hardware.
 * FIFO0-background, FIFO1-best effort, FIFO2-viedo, FIFO3-voice.
 */
static int
iwh_qosparam_to_hw(iwh_sc_t *sc, int async)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	struct wmeParams *wmeparam;
	iwh_qos_param_cmd_t qosparam_cmd;
	int i, j;
	int err = IWH_FAIL;

	if ((in->in_flags & IEEE80211_NODE_QOS) &&
	    (IEEE80211_M_STA == ic->ic_opmode)) {
		wmeparam = ic->ic_wme.wme_chanParams.cap_wmeParams;
	} else {
		return (IWH_SUCCESS);
	}

	(void) memset(&qosparam_cmd, 0, sizeof (qosparam_cmd));

	err = iwh_wmeparam_check(wmeparam);
	if (err != IWH_SUCCESS) {
		return (err);
	}

	if (in->in_flags & IEEE80211_NODE_QOS) {
		qosparam_cmd.flags |= QOS_PARAM_FLG_UPDATE_EDCA;
	}

	if (in->in_flags & (IEEE80211_NODE_QOS | IEEE80211_NODE_HT)) {
		qosparam_cmd.flags |= QOS_PARAM_FLG_TGN;
	}

	for (i = 0; i < WME_NUM_AC; i++) {

		j = iwh_wme_to_qos_ac(i);
		if (j < QOS_AC_BK || j > QOS_AC_VO) {
			return (IWH_FAIL);
		}

		qosparam_cmd.ac[j].cw_min =
		    iwh_cw_e_to_cw(wmeparam[i].wmep_logcwmin);
		qosparam_cmd.ac[j].cw_max =
		    iwh_cw_e_to_cw(wmeparam[i].wmep_logcwmax);
		qosparam_cmd.ac[j].aifsn =
		    wmeparam[i].wmep_aifsn;
		qosparam_cmd.ac[j].txop =
		    (uint16_t)(wmeparam[i].wmep_txopLimit * 32);
	}

	err = iwh_cmd(sc, REPLY_QOS_PARAM, &qosparam_cmd,
	    sizeof (qosparam_cmd), async);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_qosparam_to_hw(): "
		    "failed to update QoS parameters into hardware.\n");
		return (err);
	}

#ifdef	DEBUG
	IWH_DBG((IWH_DEBUG_QOS, "iwh_qosparam_to_hw(): "
	    "EDCA parameters are as follows:\n"));

	IWH_DBG((IWH_DEBUG_QOS, "BK parameters are: "
	    "cw_min = %d, cw_max = %d, aifsn = %d, txop = %d\n",
	    qosparam_cmd.ac[0].cw_min, qosparam_cmd.ac[0].cw_max,
	    qosparam_cmd.ac[0].aifsn, qosparam_cmd.ac[0].txop));

	IWH_DBG((IWH_DEBUG_QOS, "BE parameters are: "
	    "cw_min = %d, cw_max = %d, aifsn = %d, txop = %d\n",
	    qosparam_cmd.ac[1].cw_min, qosparam_cmd.ac[1].cw_max,
	    qosparam_cmd.ac[1].aifsn, qosparam_cmd.ac[1].txop));

	IWH_DBG((IWH_DEBUG_QOS, "VI parameters are: "
	    "cw_min = %d, cw_max = %d, aifsn = %d, txop = %d\n",
	    qosparam_cmd.ac[2].cw_min, qosparam_cmd.ac[2].cw_max,
	    qosparam_cmd.ac[2].aifsn, qosparam_cmd.ac[2].txop));

	IWH_DBG((IWH_DEBUG_QOS, "VO parameters are: "
	    "cw_min = %d, cw_max = %d, aifsn = %d, txop = %d\n",
	    qosparam_cmd.ac[3].cw_min, qosparam_cmd.ac[3].cw_max,
	    qosparam_cmd.ac[3].aifsn, qosparam_cmd.ac[3].txop));
#endif
	return (err);
}

static inline int
iwh_wme_tid_qos_ac(int tid)
{
	switch (tid) {
	case 1:
	case 2:
		return (QOS_AC_BK);
	case 0:
	case 3:
		return (QOS_AC_BE);
	case 4:
	case 5:
		return (QOS_AC_VI);
	case 6:
	case 7:
		return (QOS_AC_VO);
	}

	return (QOS_AC_BE);
}

static inline int
iwh_qos_ac_to_txq(int qos_ac)
{
	switch (qos_ac) {
	case QOS_AC_BK:
		return (QOS_AC_BK_TO_TXQ);
	case QOS_AC_BE:
		return (QOS_AC_BE_TO_TXQ);
	case QOS_AC_VI:
		return (QOS_AC_VI_TO_TXQ);
	case QOS_AC_VO:
		return (QOS_AC_VO_TO_TXQ);
	}

	return (QOS_AC_BE_TO_TXQ);
}

static int
iwh_wme_tid_to_txq(int tid)
{
	int queue_n = TXQ_FOR_AC_INVALID;
	int qos_ac;

	if (tid < WME_TID_MIN ||
	    tid > WME_TID_MAX) {
		cmn_err(CE_WARN, "wme_tid_to_txq(): "
		    "TID is not in suitable range.\n");
		return (queue_n);
	}

	qos_ac = iwh_wme_tid_qos_ac(tid);
	queue_n = iwh_qos_ac_to_txq(qos_ac);

	return (queue_n);
}

/*
 * This function is used for intializing HT relevant configurations.
 */
static void
iwh_init_ht_conf(iwh_sc_t *sc)
{
	(void) memset(&sc->sc_ht_conf, 0, sizeof (iwh_ht_conf_t));

	if ((0x4235 == sc->sc_dev_id) ||
	    (0x4236 == sc->sc_dev_id) ||
	    (0x423a == sc->sc_dev_id)) {
		sc->sc_ht_conf.ht_support = 1;

		sc->sc_ht_conf.valid_chains = 3;
		sc->sc_ht_conf.tx_stream_count = 2;
		sc->sc_ht_conf.rx_stream_count = 2;

		sc->sc_ht_conf.tx_support_mcs[0] = 0xff;
		sc->sc_ht_conf.tx_support_mcs[1] = 0xff;
		sc->sc_ht_conf.rx_support_mcs[0] = 0xff;
		sc->sc_ht_conf.rx_support_mcs[1] = 0xff;
	} else {
		sc->sc_ht_conf.ht_support = 1;

		sc->sc_ht_conf.valid_chains = 2;
		sc->sc_ht_conf.tx_stream_count = 1;
		sc->sc_ht_conf.rx_stream_count = 2;

		sc->sc_ht_conf.tx_support_mcs[0] = 0xff;
		sc->sc_ht_conf.rx_support_mcs[0] = 0xff;
		sc->sc_ht_conf.rx_support_mcs[1] = 0xff;
	}

	if (sc->sc_ht_conf.ht_support) {
		sc->sc_ht_conf.cap |= HT_CAP_GRN_FLD;
		sc->sc_ht_conf.cap |= HT_CAP_SGI_20;
		sc->sc_ht_conf.cap |= HT_CAP_MAX_AMSDU;
		/* should disable MIMO */
		sc->sc_ht_conf.cap |= HT_CAP_MIMO_PS;

		sc->sc_ht_conf.ampdu_p.factor = HT_RX_AMPDU_FACTOR;
		sc->sc_ht_conf.ampdu_p.density = HT_MPDU_DENSITY;

		sc->sc_ht_conf.ht_protection = HT_PROT_CHAN_NON_HT;
	}
}

/*
 * This function overwrites default ieee80211_rateset_11n struc.
 */
static void
iwh_overwrite_11n_rateset(iwh_sc_t *sc)
{
	uint8_t *ht_rs = sc->sc_ht_conf.rx_support_mcs;
	int mcs_idx, mcs_count = 0;
	int i, j;

	for (i = 0; i < HT_RATESET_NUM; i++) {
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

#ifdef	DEBUG
	IWH_DBG((IWH_DEBUG_HTRATE, "iwh_overwrite_11n_rateset(): "
	    "HT rates supported by this station is as follows:\n"));

	for (i = 0; i < ieee80211_rateset_11n.rs_nrates; i++) {
		IWH_DBG((IWH_DEBUG_HTRATE, "Rate %d is %d\n",
		    i, ieee80211_rateset_11n.rs_rates[i]));
	}
#endif
}

/*
 * This function overwrites default configurations of
 * ieee80211com structure in Net80211 module.
 */
static void
iwh_overwrite_ic_default(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = iwh_newstate;
	ic->ic_node_alloc = iwh_node_alloc;
	ic->ic_node_free = iwh_node_free;

	if (sc->sc_ht_conf.ht_support) {
		sc->sc_recv_action = ic->ic_recv_action;
		ic->ic_recv_action = iwh_recv_action;
		sc->sc_send_action = ic->ic_send_action;
		ic->ic_send_action = iwh_send_action;

		ic->ic_ampdu_rxmax = sc->sc_ht_conf.ampdu_p.factor;
		ic->ic_ampdu_density = sc->sc_ht_conf.ampdu_p.density;
		ic->ic_ampdu_limit = ic->ic_ampdu_rxmax;
	}
}

/*
 * This function sets "RX chain selection" feild
 * in RXON command during plumb driver.
 */
static void
iwh_config_rxon_chain(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;

	if (3 == sc->sc_ht_conf.valid_chains) {
		sc->sc_config.rx_chain = LE_16((RXON_RX_CHAIN_A_MSK |
		    RXON_RX_CHAIN_B_MSK | RXON_RX_CHAIN_C_MSK) <<
		    RXON_RX_CHAIN_VALID_POS);

		sc->sc_config.rx_chain |= LE_16((RXON_RX_CHAIN_A_MSK |
		    RXON_RX_CHAIN_B_MSK | RXON_RX_CHAIN_C_MSK) <<
		    RXON_RX_CHAIN_FORCE_SEL_POS);

		sc->sc_config.rx_chain |= LE_16((RXON_RX_CHAIN_A_MSK |
		    RXON_RX_CHAIN_B_MSK | RXON_RX_CHAIN_C_MSK) <<
		    RXON_RX_CHAIN_FORCE_MIMO_SEL_POS);
	} else {
		sc->sc_config.rx_chain = LE_16((RXON_RX_CHAIN_A_MSK |
		    RXON_RX_CHAIN_B_MSK) << RXON_RX_CHAIN_VALID_POS);

		sc->sc_config.rx_chain |= LE_16((RXON_RX_CHAIN_A_MSK |
		    RXON_RX_CHAIN_B_MSK) << RXON_RX_CHAIN_FORCE_SEL_POS);

		sc->sc_config.rx_chain |= LE_16((RXON_RX_CHAIN_A_MSK |
		    RXON_RX_CHAIN_B_MSK) <<
		    RXON_RX_CHAIN_FORCE_MIMO_SEL_POS);
	}

	sc->sc_config.rx_chain |= LE_16(RXON_RX_CHAIN_DRIVER_FORCE_MSK);

	if ((in != NULL) &&
	    (in->in_flags & IEEE80211_NODE_HT) &&
	    sc->sc_ht_conf.ht_support) {
		if (3 == sc->sc_ht_conf.valid_chains) {
			sc->sc_config.rx_chain |= LE_16(3 <<
			    RXON_RX_CHAIN_CNT_POS);
			sc->sc_config.rx_chain |= LE_16(3 <<
			    RXON_RX_CHAIN_MIMO_CNT_POS);
		} else {
			sc->sc_config.rx_chain |= LE_16(2 <<
			    RXON_RX_CHAIN_CNT_POS);
			sc->sc_config.rx_chain |= LE_16(2 <<
			    RXON_RX_CHAIN_MIMO_CNT_POS);
		}

		sc->sc_config.rx_chain |= LE_16(1 <<
		    RXON_RX_CHAIN_MIMO_FORCE_POS);
	}

	IWH_DBG((IWH_DEBUG_RXON, "iwh_config_rxon_chain(): "
	    "rxon->rx_chain = %x\n", sc->sc_config.rx_chain));
}

/*
 * This function adds AP station into hardware.
 */
static int
iwh_add_ap_sta(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	iwh_add_sta_t node;
	uint32_t ampdu_factor, ampdu_density;
	int err = IWH_FAIL;

	/*
	 * Add AP node into hardware.
	 */
	(void) memset(&node, 0, sizeof (node));
	IEEE80211_ADDR_COPY(node.sta.addr, in->in_bssid);
	node.mode = STA_MODE_ADD_MSK;
	node.sta.sta_id = IWH_AP_ID;

	if (sc->sc_ht_conf.ht_support &&
	    (in->in_htcap_ie != NULL) &&
	    (in->in_htcap != 0) &&
	    (in->in_htparam != 0)) {

		if (((in->in_htcap & HT_CAP_MIMO_PS) >> 2)
		    == HT_CAP_MIMO_PS_DYNAMIC) {
			node.station_flags |= LE_32(STA_FLG_RTS_MIMO_PROT);
		}

		ampdu_factor = in->in_htparam & HT_RX_AMPDU_FACTOR_MSK;
		node.station_flags |=
		    LE_32(ampdu_factor << STA_FLG_MAX_AMPDU_POS);

		ampdu_density = (in->in_htparam & HT_MPDU_DENSITY_MSK) >>
		    HT_MPDU_DENSITY_POS;
		node.station_flags |=
		    LE_32(ampdu_density << STA_FLG_AMPDU_DENSITY_POS);

		if (in->in_htcap & LE_16(HT_CAP_SUP_WIDTH)) {
			node.station_flags |=
			    LE_32(STA_FLG_FAT_EN);
		}
	}

	err = iwh_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_add_ap_lq(): "
		    "failed to add AP node\n");
		return (err);
	}

	return (err);
}

/*
 * Each station in the Shirley Peak's internal station table has
 * its own table of 16 TX rates and modulation modes for retrying
 * TX when an ACK is not received. This function replaces the entire
 * table for one station.Station must already be in Shirley Peak's
 * station talbe.
 */
static int
iwh_ap_lq(iwh_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	iwh_link_quality_cmd_t link_quality;
	const struct ieee80211_rateset *rs_sup = NULL;
	uint32_t masks = 0, rate;
	int i, err = IWH_FAIL;

	/*
	 * TX_LINK_QUALITY cmd
	 */
	(void) memset(&link_quality, 0, sizeof (link_quality));
	if (in->in_chan == IEEE80211_CHAN_ANYC)	/* skip null node */
		return (err);
	rs_sup = ieee80211_get_suprates(ic, in->in_chan);

	for (i = 0; i < LINK_QUAL_MAX_RETRY_NUM; i++) {
		if (i < rs_sup->ir_nrates) {
			rate = rs_sup->ir_rates[rs_sup->ir_nrates - i] &
			    IEEE80211_RATE_VAL;
		} else {
			rate = 2;
		}

		if (2 == rate || 4 == rate ||
		    11 == rate || 22 == rate) {
			masks |= LE_32(RATE_MCS_CCK_MSK);
		}

		masks |= LE_32(RATE_MCS_ANT_B_MSK);

		link_quality.rate_n_flags[i] =
		    LE_32(iwh_rate_to_plcp(rate) | masks);
	}

	link_quality.general_params.single_stream_ant_msk = LINK_QUAL_ANT_B_MSK;
	link_quality.general_params.dual_stream_ant_msk = LINK_QUAL_ANT_MSK;
	link_quality.agg_params.agg_dis_start_th = 3;
	link_quality.agg_params.agg_time_limit = LE_16(4000);
	link_quality.sta_id = IWH_AP_ID;
	err = iwh_cmd(sc, REPLY_TX_LINK_QUALITY_CMD, &link_quality,
	    sizeof (link_quality), 1);
	if (err != IWH_SUCCESS) {
		cmn_err(CE_WARN, "iwh_ap_lq(): "
		    "failed to config link quality table\n");
		return (err);
	}

#ifdef	DEBUG
	IWH_DBG((IWH_DEBUG_HWRATE, "iwh_ap_lq(): "
	    "Rates in HW are as follows:\n"));

	for (i = 0; i < LINK_QUAL_MAX_RETRY_NUM; i++) {
		IWH_DBG((IWH_DEBUG_HWRATE,
		    "Rate %d in HW is %x\n", i, link_quality.rate_n_flags[i]));
	}
#endif

	return (err);
}

/*
 * When block ACK agreement has been set up between station and AP,
 * Net80211 module will call this function to inform hardware about
 * informations of this BA agreement.
 * When AP wants to delete BA agreement that was originated by it,
 * Net80211 modele will call this function to clean up relevant
 * information in hardware.
 */
static void
iwh_recv_action(struct ieee80211_node *in,
    const uint8_t *frm, const uint8_t *efrm)
{
	struct ieee80211com *ic;
	iwh_sc_t *sc;
	const struct ieee80211_action *ia;
	uint16_t baparamset, baseqctl;
	uint32_t tid, ssn;
	iwh_add_sta_t node;
	int err = IWH_FAIL;

	if ((NULL == in) || (NULL == frm)) {
		return;
	}

	ic = in->in_ic;
	if (NULL == ic) {
		return;
	}

	sc = (iwh_sc_t *)ic;

	sc->sc_recv_action(in, frm, efrm);

	ia = (const struct ieee80211_action *)frm;
	if (ia->ia_category != IEEE80211_ACTION_CAT_BA) {
		return;
	}

	switch (ia->ia_action) {
	case IEEE80211_ACTION_BA_ADDBA_REQUEST:
		baparamset = *(uint16_t *)(frm + 3);
		baseqctl = *(uint16_t *)(frm + 7);

		tid = MS(baparamset, IEEE80211_BAPS_TID);
		ssn = MS(baseqctl, IEEE80211_BASEQ_START);

		(void) memset(&node, 0, sizeof (node));
		IEEE80211_ADDR_COPY(node.sta.addr, in->in_bssid);
		node.mode = STA_MODE_MODIFY_MSK;
		node.sta.sta_id = IWH_AP_ID;

		node.station_flags_msk = 0;
		node.sta.modify_mask = STA_MODIFY_ADDBA_TID_MSK;
		node.add_immediate_ba_tid = (uint8_t)tid;
		node.add_immediate_ba_ssn = LE_16(ssn);

		mutex_enter(&sc->sc_glock);
		err = iwh_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
		if (err != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_recv_action(): "
			    "failed to setup RX block ACK\n");
			mutex_exit(&sc->sc_glock);
			return;
		}
		mutex_exit(&sc->sc_glock);

		IWH_DBG((IWH_DEBUG_BA, "iwh_recv_action(): "
		    "RX block ACK "
		    "was setup on TID %d and SSN is %d.\n", tid, ssn));

		return;

	case IEEE80211_ACTION_BA_DELBA:
		baparamset = *(uint16_t *)(frm + 2);

		if ((baparamset & IEEE80211_DELBAPS_INIT) == 0) {
			return;
		}

		tid = MS(baparamset, IEEE80211_DELBAPS_TID);

		(void) memset(&node, 0, sizeof (node));
		IEEE80211_ADDR_COPY(node.sta.addr, in->in_bssid);
		node.mode = STA_MODE_MODIFY_MSK;
		node.sta.sta_id = IWH_AP_ID;

		node.station_flags_msk = 0;
		node.sta.modify_mask = STA_MODIFY_DELBA_TID_MSK;
		node.add_immediate_ba_tid = (uint8_t)tid;

		mutex_enter(&sc->sc_glock);
		err = iwh_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
		if (err != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_recv_action(): "
			    "failed to delete RX block ACK\n");
			mutex_exit(&sc->sc_glock);
			return;
		}
		mutex_exit(&sc->sc_glock);

		IWH_DBG((IWH_DEBUG_BA, "iwh_recv_action(): "
		    "RX block ACK "
		    "was deleted on TID %d.\n", tid));

		return;
	}
}

/*
 * When local station wants to delete BA agreement that was originated by AP,
 * Net80211 module will call this function to clean up relevant information
 * in hardware.
 */
static int
iwh_send_action(struct ieee80211_node *in,
    int category, int action, uint16_t args[4])
{
	struct ieee80211com *ic;
	iwh_sc_t *sc;
	uint32_t tid;
	iwh_add_sta_t node;
	int ret = EIO;
	int err = IWH_FAIL;


	if (NULL == in) {
		return (ret);
	}

	ic = in->in_ic;
	if (NULL == ic) {
		return (ret);
	}

	sc = (iwh_sc_t *)ic;

	ret = sc->sc_send_action(in, category, action, args);

	if (category != IEEE80211_ACTION_CAT_BA) {
		return (ret);
	}

	switch (action) {
	case IEEE80211_ACTION_BA_DELBA:
		if (IEEE80211_DELBAPS_INIT == args[1]) {
			return (ret);
		}

		tid = args[0];

		(void) memset(&node, 0, sizeof (node));
		IEEE80211_ADDR_COPY(node.sta.addr, in->in_bssid);
		node.mode = STA_MODE_MODIFY_MSK;
		node.sta.sta_id = IWH_AP_ID;

		node.station_flags_msk = 0;
		node.sta.modify_mask = STA_MODIFY_DELBA_TID_MSK;
		node.add_immediate_ba_tid = (uint8_t)tid;

		mutex_enter(&sc->sc_glock);
		err = iwh_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
		if (err != IWH_SUCCESS) {
			cmn_err(CE_WARN, "iwh_send_action(): "
			    "failed to delete RX balock ACK\n");
			mutex_exit(&sc->sc_glock);
			return (EIO);
		}
		mutex_exit(&sc->sc_glock);

		IWH_DBG((IWH_DEBUG_BA, "iwh_send_action(): "
		    "RX block ACK "
		    "was deleted on TID %d.\n", tid));

		break;
	}

	return (ret);
}

static int
iwh_reset_hw(iwh_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
	IWH_WRITE(sc, CSR_HW_IF_CONFIG_REG,
	    tmp | CSR_HW_IF_CONFIG_REG_BITS_NIC_READY);

	/*
	 * wait for HW ready
	 */
	for (n = 0; n < 5; n++) {
		if (IWH_READ(sc, CSR_HW_IF_CONFIG_REG) &
		    CSR_HW_IF_CONFIG_REG_BITS_NIC_READY) {
			break;
		}
		DELAY(10);
	}

	if (n != 5) {
		return (IWH_SUCCESS);
	}

	tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
	IWH_WRITE(sc, CSR_HW_IF_CONFIG_REG,
	    tmp | CSR_HW_IF_CONFIG_REG_BITS_PREPARE);

	for (n = 0; n < 15000; n++) {
		if (0 == (IWH_READ(sc, CSR_HW_IF_CONFIG_REG) &
		    CSR_HW_IF_CONFIG_REG_BITS_NIC_PREPARE_DONE)) {
			break;
		}
		DELAY(10);
	}

	if (15000 == n) {
		return (ETIMEDOUT);
	}

	tmp = IWH_READ(sc, CSR_HW_IF_CONFIG_REG);
	IWH_WRITE(sc, CSR_HW_IF_CONFIG_REG,
	    tmp | CSR_HW_IF_CONFIG_REG_BITS_NIC_READY);

	/*
	 * wait for HW ready
	 */
	for (n = 0; n < 5; n++) {
		if (IWH_READ(sc, CSR_HW_IF_CONFIG_REG) &
		    CSR_HW_IF_CONFIG_REG_BITS_NIC_READY) {
			break;
		}
		DELAY(10);
	}

	if (n != 5) {
		return (IWH_SUCCESS);
	} else {
		return (ETIMEDOUT);
	}
}
