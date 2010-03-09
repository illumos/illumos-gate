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
 * Intel(R) WiFi Link 6000 Driver
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

#include "iwp_calibration.h"
#include "iwp_hw.h"
#include "iwp_eeprom.h"
#include "iwp_var.h"
#include <inet/wifi_ioctl.h>

#ifdef DEBUG
#define	IWP_DEBUG_80211		(1 << 0)
#define	IWP_DEBUG_CMD		(1 << 1)
#define	IWP_DEBUG_DMA		(1 << 2)
#define	IWP_DEBUG_EEPROM	(1 << 3)
#define	IWP_DEBUG_FW		(1 << 4)
#define	IWP_DEBUG_HW		(1 << 5)
#define	IWP_DEBUG_INTR		(1 << 6)
#define	IWP_DEBUG_MRR		(1 << 7)
#define	IWP_DEBUG_PIO		(1 << 8)
#define	IWP_DEBUG_RX		(1 << 9)
#define	IWP_DEBUG_SCAN		(1 << 10)
#define	IWP_DEBUG_TX		(1 << 11)
#define	IWP_DEBUG_RATECTL	(1 << 12)
#define	IWP_DEBUG_RADIO		(1 << 13)
#define	IWP_DEBUG_RESUME	(1 << 14)
#define	IWP_DEBUG_CALIBRATION	(1 << 15)
/*
 * if want to see debug message of a given section,
 * please set this flag to one of above values
 */
uint32_t iwp_dbg_flags = 0;
#define	IWP_DBG(x) \
	iwp_dbg x
#else
#define	IWP_DBG(x)
#endif

static void	*iwp_soft_state_p = NULL;

/*
 * ucode will be compiled into driver image
 */
static uint8_t iwp_fw_bin [] = {
#include "fw-iw/iwp.ucode"
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
static ddi_device_acc_attr_t iwp_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptor
 */
static ddi_device_acc_attr_t iwp_dma_descattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes
 */
static ddi_device_acc_attr_t iwp_dma_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static int	iwp_ring_init(iwp_sc_t *);
static void	iwp_ring_free(iwp_sc_t *);
static int	iwp_alloc_shared(iwp_sc_t *);
static void	iwp_free_shared(iwp_sc_t *);
static int	iwp_alloc_kw(iwp_sc_t *);
static void	iwp_free_kw(iwp_sc_t *);
static int	iwp_alloc_fw_dma(iwp_sc_t *);
static void	iwp_free_fw_dma(iwp_sc_t *);
static int	iwp_alloc_rx_ring(iwp_sc_t *);
static void	iwp_reset_rx_ring(iwp_sc_t *);
static void	iwp_free_rx_ring(iwp_sc_t *);
static int	iwp_alloc_tx_ring(iwp_sc_t *, iwp_tx_ring_t *,
    int, int);
static void	iwp_reset_tx_ring(iwp_sc_t *, iwp_tx_ring_t *);
static void	iwp_free_tx_ring(iwp_tx_ring_t *);
static ieee80211_node_t *iwp_node_alloc(ieee80211com_t *);
static void	iwp_node_free(ieee80211_node_t *);
static int	iwp_newstate(ieee80211com_t *, enum ieee80211_state, int);
static void	iwp_mac_access_enter(iwp_sc_t *);
static void	iwp_mac_access_exit(iwp_sc_t *);
static uint32_t	iwp_reg_read(iwp_sc_t *, uint32_t);
static void	iwp_reg_write(iwp_sc_t *, uint32_t, uint32_t);
static int	iwp_load_init_firmware(iwp_sc_t *);
static int	iwp_load_run_firmware(iwp_sc_t *);
static void	iwp_tx_intr(iwp_sc_t *, iwp_rx_desc_t *);
static void	iwp_cmd_intr(iwp_sc_t *, iwp_rx_desc_t *);
static uint_t   iwp_intr(caddr_t, caddr_t);
static int	iwp_eep_load(iwp_sc_t *);
static void	iwp_get_mac_from_eep(iwp_sc_t *);
static int	iwp_eep_sem_down(iwp_sc_t *);
static void	iwp_eep_sem_up(iwp_sc_t *);
static uint_t   iwp_rx_softintr(caddr_t, caddr_t);
static uint8_t	iwp_rate_to_plcp(int);
static int	iwp_cmd(iwp_sc_t *, int, const void *, int, int);
static void	iwp_set_led(iwp_sc_t *, uint8_t, uint8_t, uint8_t);
static int	iwp_hw_set_before_auth(iwp_sc_t *);
static int	iwp_scan(iwp_sc_t *);
static int	iwp_config(iwp_sc_t *);
static void	iwp_stop_master(iwp_sc_t *);
static int	iwp_power_up(iwp_sc_t *);
static int	iwp_preinit(iwp_sc_t *);
static int	iwp_init(iwp_sc_t *);
static void	iwp_stop(iwp_sc_t *);
static int	iwp_quiesce(dev_info_t *t);
static void	iwp_amrr_init(iwp_amrr_t *);
static void	iwp_amrr_timeout(iwp_sc_t *);
static void	iwp_amrr_ratectl(void *, ieee80211_node_t *);
static void	iwp_ucode_alive(iwp_sc_t *, iwp_rx_desc_t *);
static void	iwp_rx_phy_intr(iwp_sc_t *, iwp_rx_desc_t *);
static void	iwp_rx_mpdu_intr(iwp_sc_t *, iwp_rx_desc_t *);
static void	iwp_release_calib_buffer(iwp_sc_t *);
static int	iwp_init_common(iwp_sc_t *);
static uint8_t	*iwp_eep_addr_trans(iwp_sc_t *, uint32_t);
static int	iwp_put_seg_fw(iwp_sc_t *, uint32_t, uint32_t, uint32_t);
static	int	iwp_alive_common(iwp_sc_t *);
static void	iwp_save_calib_result(iwp_sc_t *, iwp_rx_desc_t *);
static int	iwp_attach(dev_info_t *, ddi_attach_cmd_t);
static int	iwp_detach(dev_info_t *, ddi_detach_cmd_t);
static void	iwp_destroy_locks(iwp_sc_t *);
static int	iwp_send(ieee80211com_t *, mblk_t *, uint8_t);
static void	iwp_thread(iwp_sc_t *);
static int	iwp_run_state_config(iwp_sc_t *);
static int	iwp_fast_recover(iwp_sc_t *);
static void	iwp_overwrite_ic_default(iwp_sc_t *);
static int	iwp_add_ap_sta(iwp_sc_t *);
static int	iwp_alloc_dma_mem(iwp_sc_t *, size_t,
    ddi_dma_attr_t *, ddi_device_acc_attr_t *,
    uint_t, iwp_dma_t *);
static void	iwp_free_dma_mem(iwp_dma_t *);
static int	iwp_eep_ver_chk(iwp_sc_t *);
static void	iwp_set_chip_param(iwp_sc_t *);

/*
 * GLD specific operations
 */
static int	iwp_m_stat(void *, uint_t, uint64_t *);
static int	iwp_m_start(void *);
static void	iwp_m_stop(void *);
static int	iwp_m_unicst(void *, const uint8_t *);
static int	iwp_m_multicst(void *, boolean_t, const uint8_t *);
static int	iwp_m_promisc(void *, boolean_t);
static mblk_t	*iwp_m_tx(void *, mblk_t *);
static void	iwp_m_ioctl(void *, queue_t *, mblk_t *);
static int	iwp_m_setprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, const void *wldp_buf);
static int	iwp_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, void *wldp_buf);
static void	iwp_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

/*
 * Supported rates for 802.11b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset iwp_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset iwp_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

/*
 * For mfthread only
 */
extern pri_t minclsyspri;

#define	DRV_NAME_SP	"iwp"

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(iwp_devops, nulldev, nulldev, iwp_attach,
    iwp_detach, nodev, NULL, D_MP, NULL, iwp_quiesce);

static struct modldrv iwp_modldrv = {
	&mod_driverops,
	"Intel(R) PumaPeak driver(N)",
	&iwp_devops
};

static struct modlinkage iwp_modlinkage = {
	MODREV_1,
	&iwp_modldrv,
	NULL
};

int
_init(void)
{
	int	status;

	status = ddi_soft_state_init(&iwp_soft_state_p,
	    sizeof (iwp_sc_t), 1);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	mac_init_ops(&iwp_devops, DRV_NAME_SP);
	status = mod_install(&iwp_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&iwp_devops);
		ddi_soft_state_fini(&iwp_soft_state_p);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&iwp_modlinkage);
	if (DDI_SUCCESS == status) {
		mac_fini_ops(&iwp_devops);
		ddi_soft_state_fini(&iwp_soft_state_p);
	}

	return (status);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&iwp_modlinkage, mip));
}

/*
 * Mac Call Back entries
 */
mac_callbacks_t	iwp_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	iwp_m_stat,
	iwp_m_start,
	iwp_m_stop,
	iwp_m_promisc,
	iwp_m_multicst,
	iwp_m_unicst,
	iwp_m_tx,
	NULL,
	iwp_m_ioctl,
	NULL,
	NULL,
	NULL,
	iwp_m_setprop,
	iwp_m_getprop,
	iwp_m_propinfo
};

#ifdef DEBUG
void
iwp_dbg(uint32_t flags, const char *fmt, ...)
{
	va_list	ap;

	if (flags & iwp_dbg_flags) {
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
iwp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	iwp_sc_t		*sc;
	ieee80211com_t		*ic;
	int			instance, i;
	char			strbuf[32];
	wifi_data_t		wd = { 0 };
	mac_register_t		*macp;
	int			intr_type;
	int			intr_count;
	int			intr_actual;
	int			err = DDI_FAILURE;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		instance = ddi_get_instance(dip);
		sc = ddi_get_soft_state(iwp_soft_state_p,
		    instance);
		ASSERT(sc != NULL);

		if (sc->sc_flags & IWP_F_RUNNING) {
			(void) iwp_init(sc);
		}

		atomic_and_32(&sc->sc_flags, ~IWP_F_SUSPEND);

		IWP_DBG((IWP_DEBUG_RESUME, "iwp_attach(): "
		    "resume\n"));
		return (DDI_SUCCESS);
	default:
		goto attach_fail1;
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(iwp_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to allocate soft state\n");
		goto attach_fail1;
	}

	sc = ddi_get_soft_state(iwp_soft_state_p, instance);
	ASSERT(sc != NULL);

	sc->sc_dip = dip;

	/*
	 * map configure space
	 */
	err = ddi_regs_map_setup(dip, 0, &sc->sc_cfg_base, 0, 0,
	    &iwp_reg_accattr, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to map config spaces regs\n");
		goto attach_fail2;
	}

	sc->sc_dev_id = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)(sc->sc_cfg_base + PCI_CONF_DEVID));
	if ((sc->sc_dev_id != 0x422B) &&
	    (sc->sc_dev_id != 0x422C) &&
	    (sc->sc_dev_id != 0x4238) &&
	    (sc->sc_dev_id != 0x4239) &&
	    (sc->sc_dev_id != 0x008d) &&
	    (sc->sc_dev_id != 0x008e)) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "Do not support this device\n");
		goto attach_fail3;
	}

	iwp_set_chip_param(sc);

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

	sc->sc_dmabuf_sz = roundup(0x1000 + sizeof (struct ieee80211_frame) +
	    IEEE80211_MTU + IEEE80211_CRC_LEN +
	    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_CRCLEN), sc->sc_clsz);

	/*
	 * Map operating registers
	 */
	err = ddi_regs_map_setup(dip, 1, &sc->sc_base,
	    0, 0, &iwp_reg_accattr, &sc->sc_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to map device regs\n");
		goto attach_fail3;
	}

	/*
	 * this is used to differentiate type of hardware
	 */
	sc->sc_hw_rev = IWP_READ(sc, CSR_HW_REV);

	err = ddi_intr_get_supported_types(dip, &intr_type);
	if ((err != DDI_SUCCESS) || (!(intr_type & DDI_INTR_TYPE_FIXED))) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "fixed type interrupt is not supported\n");
		goto attach_fail4;
	}

	err = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &intr_count);
	if ((err != DDI_SUCCESS) || (intr_count != 1)) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "no fixed interrupts\n");
		goto attach_fail4;
	}

	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);

	err = ddi_intr_alloc(dip, sc->sc_intr_htable, DDI_INTR_TYPE_FIXED, 0,
	    intr_count, &intr_actual, 0);
	if ((err != DDI_SUCCESS) || (intr_actual != 1)) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "ddi_intr_alloc() failed 0x%x\n", err);
		goto attach_fail5;
	}

	err = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_pri);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
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
	err = iwp_alloc_shared(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to allocate shared page\n");
		goto attach_fail7;
	}

	(void) memset(sc->sc_shared, 0, sizeof (iwp_shared_t));

	/*
	 * Allocate keep warm page.
	 */
	err = iwp_alloc_kw(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to allocate keep warm page\n");
		goto attach_fail8;
	}

	/*
	 * Do some necessary hardware initializations.
	 */
	err = iwp_preinit(sc);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to initialize hardware\n");
		goto attach_fail9;
	}

	/*
	 * get hardware configurations from eeprom
	 */
	err = iwp_eep_load(sc);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to load eeprom\n");
		goto attach_fail9;
	}

	/*
	 * calibration information from EEPROM
	 */
	sc->sc_eep_calib = (struct iwp_eep_calibration *)
	    iwp_eep_addr_trans(sc, EEP_CALIBRATION);

	err = iwp_eep_ver_chk(sc);
	if (err != IWP_SUCCESS) {
		goto attach_fail9;
	}

	/*
	 * get MAC address of this chipset
	 */
	iwp_get_mac_from_eep(sc);


	/*
	 * initialize TX and RX ring buffers
	 */
	err = iwp_ring_init(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to allocate and initialize ring\n");
		goto attach_fail9;
	}

	sc->sc_hdr = (iwp_firmware_hdr_t *)iwp_fw_bin;

	/*
	 * copy ucode to dma buffer
	 */
	err = iwp_alloc_fw_dma(sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to allocate firmware dma\n");
		goto attach_fail10;
	}

	/*
	 * Initialize the wifi part, which will be used by
	 * 802.11 module
	 */
	ic = &sc->sc_ic;
	ic->ic_phytype  = IEEE80211_T_OFDM;
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
	 * set supported .11b and .11g rates
	 */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = iwp_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = iwp_rateset_11g;

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
	}

	ic->ic_ibss_chan = &ic->ic_sup_channels[0];
	ic->ic_xmit = iwp_send;

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
	iwp_overwrite_ic_default(sc);

	/*
	 * initialize 802.11 module
	 */
	ieee80211_media_init(ic);

	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	err = ddi_intr_add_softint(dip, &sc->sc_soft_hdl, DDI_INTR_SOFTPRI_MAX,
	    iwp_rx_softintr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "add soft interrupt failed\n");
		goto attach_fail12;
	}

	err = ddi_intr_add_handler(sc->sc_intr_htable[0], iwp_intr,
	    (caddr_t)sc, NULL);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
		    "ddi_intr_add_handle() failed\n");
		goto attach_fail13;
	}

	err = ddi_intr_enable(sc->sc_intr_htable[0]);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_attach(): "
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
		cmn_err(CE_WARN, "iwp_attach(): "
		    "failed to do mac_alloc()\n");
		goto attach_fail15;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &iwp_m_callbacks;
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
		cmn_err(CE_WARN, "iwp_attach(): "
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
		cmn_err(CE_WARN, "iwp_attach(): "
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
		    iwp_thread, sc, 0, &p0, TS_RUN, minclsyspri);
	}

	atomic_or_32(&sc->sc_flags, IWP_F_ATTACHED);

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
	iwp_free_fw_dma(sc);
attach_fail10:
	iwp_ring_free(sc);
attach_fail9:
	iwp_free_kw(sc);
attach_fail8:
	iwp_free_shared(sc);
attach_fail7:
	iwp_destroy_locks(sc);
attach_fail6:
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
attach_fail5:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));
attach_fail4:
	ddi_regs_map_free(&sc->sc_handle);
attach_fail3:
	ddi_regs_map_free(&sc->sc_cfg_handle);
attach_fail2:
	ddi_soft_state_free(iwp_soft_state_p, instance);
attach_fail1:
	return (DDI_FAILURE);
}

int
iwp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	iwp_sc_t *sc;
	ieee80211com_t	*ic;
	int err;

	sc = ddi_get_soft_state(iwp_soft_state_p, ddi_get_instance(dip));
	ASSERT(sc != NULL);
	ic = &sc->sc_ic;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		atomic_and_32(&sc->sc_flags, ~IWP_F_HW_ERR_RECOVER);
		atomic_and_32(&sc->sc_flags, ~IWP_F_RATE_AUTO_CTL);

		atomic_or_32(&sc->sc_flags, IWP_F_SUSPEND);

		if (sc->sc_flags & IWP_F_RUNNING) {
			iwp_stop(sc);
			ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

		}

		IWP_DBG((IWP_DEBUG_RESUME, "iwp_detach(): "
		    "suspend\n"));
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (!(sc->sc_flags & IWP_F_ATTACHED)) {
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
	iwp_stop(sc);

	DELAY(500000);

	/*
	 * release buffer for calibration
	 */
	iwp_release_calib_buffer(sc);

	/*
	 * Unregiste from GLD
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	mutex_enter(&sc->sc_glock);
	iwp_free_fw_dma(sc);
	iwp_ring_free(sc);
	iwp_free_kw(sc);
	iwp_free_shared(sc);
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

	iwp_destroy_locks(sc);

	ddi_regs_map_free(&sc->sc_handle);
	ddi_regs_map_free(&sc->sc_cfg_handle);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(iwp_soft_state_p, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

/*
 * destroy all locks
 */
static void
iwp_destroy_locks(iwp_sc_t *sc)
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
iwp_alloc_dma_mem(iwp_sc_t *sc, size_t memsize,
    ddi_dma_attr_t *dma_attr_p, ddi_device_acc_attr_t *acc_attr_p,
    uint_t dma_flags, iwp_dma_t *dma_p)
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
iwp_free_dma_mem(iwp_dma_t *dma_p)
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
iwp_alloc_fw_dma(iwp_sc_t *sc)
{
	int err = DDI_FAILURE;
	iwp_dma_t *dma_p;
	char *t;

	/*
	 * firmware image layout:
	 * |HDR|<-TEXT->|<-DATA->|<-INIT_TEXT->|<-INIT_DATA->|<-BOOT->|
	 */

	/*
	 * Check firmware image size.
	 */
	if (LE_32(sc->sc_hdr->init_textsz) > RTC_INST_SIZE) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "firmware init text size 0x%x is too large\n",
		    LE_32(sc->sc_hdr->init_textsz));

		goto fail;
	}

	if (LE_32(sc->sc_hdr->init_datasz) > RTC_DATA_SIZE) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "firmware init data size 0x%x is too large\n",
		    LE_32(sc->sc_hdr->init_datasz));

		goto fail;
	}

	if (LE_32(sc->sc_hdr->textsz) > RTC_INST_SIZE) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "firmware text size 0x%x is too large\n",
		    LE_32(sc->sc_hdr->textsz));

		goto fail;
	}

	if (LE_32(sc->sc_hdr->datasz) > RTC_DATA_SIZE) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "firmware data size 0x%x is too large\n",
		    LE_32(sc->sc_hdr->datasz));

		goto fail;
	}

	/*
	 * copy text of runtime ucode
	 */
	t = (char *)(sc->sc_hdr + 1);
	err = iwp_alloc_dma_mem(sc, LE_32(sc->sc_hdr->textsz),
	    &fw_dma_attr, &iwp_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_text);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "failed to allocate text dma memory.\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_text;

	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_fw_dma(): "
	    "text[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->textsz));

	/*
	 * copy data and bak-data of runtime ucode
	 */
	t += LE_32(sc->sc_hdr->textsz);
	err = iwp_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_dma_attr, &iwp_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "failed to allocate data dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_data;

	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_fw_dma(): "
	    "data[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->datasz));

	err = iwp_alloc_dma_mem(sc, LE_32(sc->sc_hdr->datasz),
	    &fw_dma_attr, &iwp_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_data_bak);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "failed to allocate data bakup dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_data_bak;

	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_fw_dma(): "
	    "data_bak[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->datasz));

	/*
	 * copy text of init ucode
	 */
	t += LE_32(sc->sc_hdr->datasz);
	err = iwp_alloc_dma_mem(sc, LE_32(sc->sc_hdr->init_textsz),
	    &fw_dma_attr, &iwp_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_init_text);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "failed to allocate init text dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_init_text;

	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_fw_dma(): "
	    "init_text[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->init_textsz));

	/*
	 * copy data of init ucode
	 */
	t += LE_32(sc->sc_hdr->init_textsz);
	err = iwp_alloc_dma_mem(sc, LE_32(sc->sc_hdr->init_datasz),
	    &fw_dma_attr, &iwp_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_fw_init_data);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alloc_fw_dma(): "
		    "failed to allocate init data dma memory\n");
		goto fail;
	}

	dma_p = &sc->sc_dma_fw_init_data;

	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_fw_dma(): "
	    "init_data[ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	(void) memcpy(dma_p->mem_va, t, LE_32(sc->sc_hdr->init_datasz));

	sc->sc_boot = t + LE_32(sc->sc_hdr->init_datasz);
fail:
	return (err);
}

static void
iwp_free_fw_dma(iwp_sc_t *sc)
{
	iwp_free_dma_mem(&sc->sc_dma_fw_text);
	iwp_free_dma_mem(&sc->sc_dma_fw_data);
	iwp_free_dma_mem(&sc->sc_dma_fw_data_bak);
	iwp_free_dma_mem(&sc->sc_dma_fw_init_text);
	iwp_free_dma_mem(&sc->sc_dma_fw_init_data);
}

/*
 * Allocate a shared buffer between host and NIC.
 */
static int
iwp_alloc_shared(iwp_sc_t *sc)
{
#ifdef	DEBUG
	iwp_dma_t *dma_p;
#endif
	int err = DDI_FAILURE;

	/*
	 * must be aligned on a 4K-page boundary
	 */
	err = iwp_alloc_dma_mem(sc, sizeof (iwp_shared_t),
	    &sh_dma_attr, &iwp_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_sh);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

	sc->sc_shared = (iwp_shared_t *)sc->sc_dma_sh.mem_va;

#ifdef	DEBUG
	dma_p = &sc->sc_dma_sh;
#endif
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_shared(): "
	    "sh[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);
fail:
	iwp_free_shared(sc);
	return (err);
}

static void
iwp_free_shared(iwp_sc_t *sc)
{
	iwp_free_dma_mem(&sc->sc_dma_sh);
}

/*
 * Allocate a keep warm page.
 */
static int
iwp_alloc_kw(iwp_sc_t *sc)
{
#ifdef	DEBUG
	iwp_dma_t *dma_p;
#endif
	int err = DDI_FAILURE;

	/*
	 * must be aligned on a 4K-page boundary
	 */
	err = iwp_alloc_dma_mem(sc, IWP_KW_SIZE,
	    &kw_dma_attr, &iwp_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_dma_kw);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

#ifdef	DEBUG
	dma_p = &sc->sc_dma_kw;
#endif
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_kw(): "
	    "kw[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);
fail:
	iwp_free_kw(sc);
	return (err);
}

static void
iwp_free_kw(iwp_sc_t *sc)
{
	iwp_free_dma_mem(&sc->sc_dma_kw);
}

/*
 * initialize RX ring buffers
 */
static int
iwp_alloc_rx_ring(iwp_sc_t *sc)
{
	iwp_rx_ring_t *ring;
	iwp_rx_data_t *data;
#ifdef	DEBUG
	iwp_dma_t *dma_p;
#endif
	int i, err = DDI_FAILURE;

	ring = &sc->sc_rxq;
	ring->cur = 0;

	/*
	 * allocate RX description ring buffer
	 */
	err = iwp_alloc_dma_mem(sc, RX_QUEUE_SIZE * sizeof (uint32_t),
	    &ring_desc_dma_attr, &iwp_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_rx_ring(): "
		    "dma alloc rx ring desc "
		    "failed\n"));
		goto fail;
	}

	ring->desc = (uint32_t *)ring->dma_desc.mem_va;
#ifdef	DEBUG
	dma_p = &ring->dma_desc;
#endif
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_rx_ring(): "
	    "rx bd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	/*
	 * Allocate Rx frame buffers.
	 */
	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		data = &ring->data[i];
		err = iwp_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &rx_buffer_dma_attr, &iwp_dma_accattr,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_rx_ring(): "
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
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_rx_ring(): "
	    "rx buffer[0][ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	IWP_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	return (err);

fail:
	iwp_free_rx_ring(sc);
	return (err);
}

/*
 * disable RX ring
 */
static void
iwp_reset_rx_ring(iwp_sc_t *sc)
{
	int n;

	iwp_mac_access_enter(sc);
	IWP_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
	for (n = 0; n < 2000; n++) {
		if (IWP_READ(sc, FH_MEM_RSSR_RX_STATUS_REG) & (1 << 24)) {
			break;
		}
		DELAY(1000);
	}
#ifdef DEBUG
	if (2000 == n) {
		IWP_DBG((IWP_DEBUG_DMA, "iwp_reset_rx_ring(): "
		    "timeout resetting Rx ring\n"));
	}
#endif
	iwp_mac_access_exit(sc);

	sc->sc_rxq.cur = 0;
}

static void
iwp_free_rx_ring(iwp_sc_t *sc)
{
	int i;

	for (i = 0; i < RX_QUEUE_SIZE; i++) {
		if (sc->sc_rxq.data[i].dma_data.dma_hdl) {
			IWP_DMA_SYNC(sc->sc_rxq.data[i].dma_data,
			    DDI_DMA_SYNC_FORCPU);
		}

		iwp_free_dma_mem(&sc->sc_rxq.data[i].dma_data);
	}

	if (sc->sc_rxq.dma_desc.dma_hdl) {
		IWP_DMA_SYNC(sc->sc_rxq.dma_desc, DDI_DMA_SYNC_FORDEV);
	}

	iwp_free_dma_mem(&sc->sc_rxq.dma_desc);
}

/*
 * initialize TX ring buffers
 */
static int
iwp_alloc_tx_ring(iwp_sc_t *sc, iwp_tx_ring_t *ring,
    int slots, int qid)
{
	iwp_tx_data_t *data;
	iwp_tx_desc_t *desc_h;
	uint32_t paddr_desc_h;
	iwp_cmd_t *cmd_h;
	uint32_t paddr_cmd_h;
#ifdef	DEBUG
	iwp_dma_t *dma_p;
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
	err = iwp_alloc_dma_mem(sc,
	    TFD_QUEUE_SIZE_MAX * sizeof (iwp_tx_desc_t),
	    &ring_desc_dma_attr, &iwp_dma_descattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_desc);
	if (err != DDI_SUCCESS) {
		IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
		    "dma alloc tx ring desc[%d] "
		    "failed\n", qid));
		goto fail;
	}

#ifdef	DEBUG
	dma_p = &ring->dma_desc;
#endif
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
	    "tx bd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	desc_h = (iwp_tx_desc_t *)ring->dma_desc.mem_va;
	paddr_desc_h = ring->dma_desc.cookie.dmac_address;

	/*
	 * allocate buffer for ucode command
	 */
	err = iwp_alloc_dma_mem(sc,
	    TFD_QUEUE_SIZE_MAX * sizeof (iwp_cmd_t),
	    &cmd_dma_attr, &iwp_dma_accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->dma_cmd);
	if (err != DDI_SUCCESS) {
		IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
		    "dma alloc tx ring cmd[%d]"
		    " failed\n", qid));
		goto fail;
	}

#ifdef	DEBUG
	dma_p = &ring->dma_cmd;
#endif
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
	    "tx cmd[ncookies:%d addr:%lx size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	cmd_h = (iwp_cmd_t *)ring->dma_cmd.mem_va;
	paddr_cmd_h = ring->dma_cmd.cookie.dmac_address;

	/*
	 * Allocate Tx frame buffers.
	 */
	ring->data = kmem_zalloc(sizeof (iwp_tx_data_t) * TFD_QUEUE_SIZE_MAX,
	    KM_NOSLEEP);
	if (NULL == ring->data) {
		IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
		    "could not allocate "
		    "tx data slots\n"));
		goto fail;
	}

	for (i = 0; i < TFD_QUEUE_SIZE_MAX; i++) {
		data = &ring->data[i];
		err = iwp_alloc_dma_mem(sc, sc->sc_dmabuf_sz,
		    &tx_buffer_dma_attr, &iwp_dma_accattr,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &data->dma_data);
		if (err != DDI_SUCCESS) {
			IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
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
	IWP_DBG((IWP_DEBUG_DMA, "iwp_alloc_tx_ring(): "
	    "tx buffer[0][ncookies:%d addr:%lx "
	    "size:%lx]\n",
	    dma_p->ncookies, dma_p->cookie.dmac_address,
	    dma_p->cookie.dmac_size));

	return (err);

fail:
	iwp_free_tx_ring(ring);

	return (err);
}

/*
 * disable TX ring
 */
static void
iwp_reset_tx_ring(iwp_sc_t *sc, iwp_tx_ring_t *ring)
{
	iwp_tx_data_t *data;
	int i, n;

	iwp_mac_access_enter(sc);

	IWP_WRITE(sc, IWP_FH_TCSR_CHNL_TX_CONFIG_REG(ring->qid), 0);
	for (n = 0; n < 200; n++) {
		if (IWP_READ(sc, IWP_FH_TSSR_TX_STATUS_REG) &
		    IWP_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(ring->qid)) {
			break;
		}
		DELAY(10);
	}

#ifdef	DEBUG
	if (200 == n) {
		IWP_DBG((IWP_DEBUG_DMA, "iwp_reset_tx_ring(): "
		    "timeout reset tx ring %d\n",
		    ring->qid));
	}
#endif

	iwp_mac_access_exit(sc);

	/* by pass, if it's quiesce */
	if (!(sc->sc_flags & IWP_F_QUIESCED)) {
		for (i = 0; i < ring->count; i++) {
			data = &ring->data[i];
			IWP_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
		}
	}

	ring->queued = 0;
	ring->cur = 0;
	ring->desc_cur = 0;
}

static void
iwp_free_tx_ring(iwp_tx_ring_t *ring)
{
	int i;

	if (ring->dma_desc.dma_hdl != NULL) {
		IWP_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);
	}
	iwp_free_dma_mem(&ring->dma_desc);

	if (ring->dma_cmd.dma_hdl != NULL) {
		IWP_DMA_SYNC(ring->dma_cmd, DDI_DMA_SYNC_FORDEV);
	}
	iwp_free_dma_mem(&ring->dma_cmd);

	if (ring->data != NULL) {
		for (i = 0; i < ring->count; i++) {
			if (ring->data[i].dma_data.dma_hdl) {
				IWP_DMA_SYNC(ring->data[i].dma_data,
				    DDI_DMA_SYNC_FORDEV);
			}
			iwp_free_dma_mem(&ring->data[i].dma_data);
		}
		kmem_free(ring->data, ring->count * sizeof (iwp_tx_data_t));
	}
}

/*
 * initialize TX and RX ring
 */
static int
iwp_ring_init(iwp_sc_t *sc)
{
	int i, err = DDI_FAILURE;

	for (i = 0; i < IWP_NUM_QUEUES; i++) {
		if (IWP_CMD_QUEUE_NUM == i) {
			continue;
		}

		err = iwp_alloc_tx_ring(sc, &sc->sc_txq[i], TFD_TX_CMD_SLOTS,
		    i);
		if (err != DDI_SUCCESS) {
			goto fail;
		}
	}

	/*
	 * initialize command queue
	 */
	err = iwp_alloc_tx_ring(sc, &sc->sc_txq[IWP_CMD_QUEUE_NUM],
	    TFD_CMD_SLOTS, IWP_CMD_QUEUE_NUM);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

	err = iwp_alloc_rx_ring(sc);
	if (err != DDI_SUCCESS) {
		goto fail;
	}

fail:
	return (err);
}

static void
iwp_ring_free(iwp_sc_t *sc)
{
	int i = IWP_NUM_QUEUES;

	iwp_free_rx_ring(sc);
	while (--i >= 0) {
		iwp_free_tx_ring(&sc->sc_txq[i]);
	}
}

/* ARGSUSED */
static ieee80211_node_t *
iwp_node_alloc(ieee80211com_t *ic)
{
	iwp_amrr_t *amrr;

	amrr = kmem_zalloc(sizeof (iwp_amrr_t), KM_SLEEP);
	if (NULL == amrr) {
		cmn_err(CE_WARN, "iwp_node_alloc(): "
		    "failed to allocate memory for amrr structure\n");
		return (NULL);
	}

	iwp_amrr_init(amrr);

	return (&amrr->in);
}

static void
iwp_node_free(ieee80211_node_t *in)
{
	ieee80211com_t *ic;

	if ((NULL == in) ||
	    (NULL == in->in_ic)) {
		cmn_err(CE_WARN, "iwp_node_free() "
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

	kmem_free(in, sizeof (iwp_amrr_t));
}


/*
 * change station's state. this function will be invoked by 80211 module
 * when need to change staton's state.
 */
static int
iwp_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	iwp_sc_t *sc;
	ieee80211_node_t *in;
	enum ieee80211_state ostate;
	iwp_add_sta_t node;
	int i, err = IWP_FAIL;

	if (NULL == ic) {
		return (err);
	}
	sc = (iwp_sc_t *)ic;
	in = ic->ic_bss;
	ostate = ic->ic_state;

	mutex_enter(&sc->sc_glock);

	switch (nstate) {
	case IEEE80211_S_SCAN:
		switch (ostate) {
		case IEEE80211_S_INIT:
			atomic_or_32(&sc->sc_flags, IWP_F_SCANNING);
			iwp_set_led(sc, 2, 10, 2);

			/*
			 * clear association to receive beacons from
			 * all BSS'es
			 */
			sc->sc_config.assoc_id = 0;
			sc->sc_config.filter_flags &=
			    ~LE_32(RXON_FILTER_ASSOC_MSK);

			IWP_DBG((IWP_DEBUG_80211, "iwp_newstate(): "
			    "config chan %d "
			    "flags %x filter_flags %x\n",
			    LE_16(sc->sc_config.chan),
			    LE_32(sc->sc_config.flags),
			    LE_32(sc->sc_config.filter_flags)));

			err = iwp_cmd(sc, REPLY_RXON, &sc->sc_config,
			    sizeof (iwp_rxon_cmd_t), 1);
			if (err != IWP_SUCCESS) {
				cmn_err(CE_WARN, "iwp_newstate(): "
				    "could not clear association\n");
				atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
				mutex_exit(&sc->sc_glock);
				return (err);
			}

			/* add broadcast node to send probe request */
			(void) memset(&node, 0, sizeof (node));
			(void) memset(&node.sta.addr, 0xff, IEEE80211_ADDR_LEN);
			node.sta.sta_id = IWP_BROADCAST_ID;
			err = iwp_cmd(sc, REPLY_ADD_STA, &node,
			    sizeof (node), 1);
			if (err != IWP_SUCCESS) {
				cmn_err(CE_WARN, "iwp_newstate(): "
				    "could not add broadcast node\n");
				atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
				mutex_exit(&sc->sc_glock);
				return (err);
			}
			break;
		case IEEE80211_S_SCAN:
			mutex_exit(&sc->sc_glock);
			/* step to next channel before actual FW scan */
			err = sc->sc_newstate(ic, nstate, arg);
			mutex_enter(&sc->sc_glock);
			if ((err != 0) || ((err = iwp_scan(sc)) != 0)) {
				cmn_err(CE_WARN, "iwp_newstate(): "
				    "could not initiate scan\n");
				atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
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
			atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
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
		if ((err = iwp_hw_set_before_auth(sc)) != 0) {
			IWP_DBG((IWP_DEBUG_80211, "iwp_newstate(): "
			    "could not send authentication request\n"));
			mutex_exit(&sc->sc_glock);
			return (err);
		}
		break;

	case IEEE80211_S_RUN:
		if (ostate == IEEE80211_S_SCAN) {
			atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
		}

		if (IEEE80211_M_MONITOR == ic->ic_opmode) {
			/* let LED blink when monitoring */
			iwp_set_led(sc, 2, 10, 10);
			break;
		}

		IWP_DBG((IWP_DEBUG_80211, "iwp_newstate(): "
		    "associated.\n"));

		err = iwp_run_state_config(sc);
		if (err != IWP_SUCCESS) {
			cmn_err(CE_WARN, "iwp_newstate(): "
			    "failed to set up association\n");
			mutex_exit(&sc->sc_glock);
			return (err);
		}

		/*
		 * start automatic rate control
		 */
		if (IEEE80211_FIXED_RATE_NONE == ic->ic_fixed_rate) {
			atomic_or_32(&sc->sc_flags, IWP_F_RATE_AUTO_CTL);

			/*
			 * set rate to some reasonable initial value
			 */
			i = in->in_rates.ir_nrates - 1;
			while (i > 0 && IEEE80211_RATE(i) > 72) {
				i--;
			}
			in->in_txrate = i;

		} else {
			atomic_and_32(&sc->sc_flags, ~IWP_F_RATE_AUTO_CTL);
		}

		/*
		 * set LED on after associated
		 */
		iwp_set_led(sc, 2, 0, 1);
		break;

	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_SCAN) {
			atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
		}
		/*
		 * set LED off after init
		 */
		iwp_set_led(sc, 2, 1, 0);
		break;

	case IEEE80211_S_ASSOC:
		if (ostate == IEEE80211_S_SCAN) {
			atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
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
iwp_mac_access_enter(iwp_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWP_READ(sc, CSR_GP_CNTRL);
	IWP_WRITE(sc, CSR_GP_CNTRL,
	    tmp | CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);

	/* wait until we succeed */
	for (n = 0; n < 1000; n++) {
		if ((IWP_READ(sc, CSR_GP_CNTRL) &
		    (CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY |
		    CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP)) ==
		    CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN) {
			break;
		}
		DELAY(10);
	}

#ifdef	DEBUG
	if (1000 == n) {
		IWP_DBG((IWP_DEBUG_PIO, "iwp_mac_access_enter(): "
		    "could not lock memory\n"));
	}
#endif
}

/*
 * exclusive access to mac end.
 */
static void
iwp_mac_access_exit(iwp_sc_t *sc)
{
	uint32_t tmp = IWP_READ(sc, CSR_GP_CNTRL);
	IWP_WRITE(sc, CSR_GP_CNTRL,
	    tmp & ~CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
}

/*
 * this function defined here for future use.
 * static uint32_t
 * iwp_mem_read(iwp_sc_t *sc, uint32_t addr)
 * {
 * 	IWP_WRITE(sc, HBUS_TARG_MEM_RADDR, addr);
 * 	return (IWP_READ(sc, HBUS_TARG_MEM_RDAT));
 * }
 */

/*
 * write mac memory
 */
static void
iwp_mem_write(iwp_sc_t *sc, uint32_t addr, uint32_t data)
{
	IWP_WRITE(sc, HBUS_TARG_MEM_WADDR, addr);
	IWP_WRITE(sc, HBUS_TARG_MEM_WDAT, data);
}

/*
 * read mac register
 */
static uint32_t
iwp_reg_read(iwp_sc_t *sc, uint32_t addr)
{
	IWP_WRITE(sc, HBUS_TARG_PRPH_RADDR, addr | (3 << 24));
	return (IWP_READ(sc, HBUS_TARG_PRPH_RDAT));
}

/*
 * write mac register
 */
static void
iwp_reg_write(iwp_sc_t *sc, uint32_t addr, uint32_t data)
{
	IWP_WRITE(sc, HBUS_TARG_PRPH_WADDR, addr | (3 << 24));
	IWP_WRITE(sc, HBUS_TARG_PRPH_WDAT, data);
}


/*
 * steps of loading ucode:
 * load init ucode=>init alive=>calibrate=>
 * receive calibration result=>reinitialize NIC=>
 * load runtime ucode=>runtime alive=>
 * send calibration result=>running.
 */
static int
iwp_load_init_firmware(iwp_sc_t *sc)
{
	int	err = IWP_FAIL;
	clock_t	clk;

	atomic_and_32(&sc->sc_flags, ~IWP_F_PUT_SEG);

	/*
	 * load init_text section of uCode to hardware
	 */
	err = iwp_put_seg_fw(sc, sc->sc_dma_fw_init_text.cookie.dmac_address,
	    RTC_INST_LOWER_BOUND, sc->sc_dma_fw_init_text.cookie.dmac_size);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_load_init_firmware(): "
		    "failed to write init uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/* wait loading init_text until completed or timeout */
	while (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwp_load_init_firmware(): "
		    "timeout waiting for init uCode load.\n");
		return (IWP_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWP_F_PUT_SEG);

	/*
	 * load init_data section of uCode to hardware
	 */
	err = iwp_put_seg_fw(sc, sc->sc_dma_fw_init_data.cookie.dmac_address,
	    RTC_DATA_LOWER_BOUND, sc->sc_dma_fw_init_data.cookie.dmac_size);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_load_init_firmware(): "
		    "failed to write init_data uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/*
	 * wait loading init_data until completed or timeout
	 */
	while (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwp_load_init_firmware(): "
		    "timeout waiting for init_data uCode load.\n");
		return (IWP_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWP_F_PUT_SEG);

	return (err);
}

static int
iwp_load_run_firmware(iwp_sc_t *sc)
{
	int	err = IWP_FAIL;
	clock_t	clk;

	atomic_and_32(&sc->sc_flags, ~IWP_F_PUT_SEG);

	/*
	 * load init_text section of uCode to hardware
	 */
	err = iwp_put_seg_fw(sc, sc->sc_dma_fw_text.cookie.dmac_address,
	    RTC_INST_LOWER_BOUND, sc->sc_dma_fw_text.cookie.dmac_size);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_load_run_firmware(): "
		    "failed to write run uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/* wait loading run_text until completed or timeout */
	while (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwp_load_run_firmware(): "
		    "timeout waiting for run uCode load.\n");
		return (IWP_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWP_F_PUT_SEG);

	/*
	 * load run_data section of uCode to hardware
	 */
	err = iwp_put_seg_fw(sc, sc->sc_dma_fw_data_bak.cookie.dmac_address,
	    RTC_DATA_LOWER_BOUND, sc->sc_dma_fw_data.cookie.dmac_size);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_load_run_firmware(): "
		    "failed to write run_data uCode.\n");
		return (err);
	}

	clk = ddi_get_lbolt() + drv_usectohz(1000000);

	/*
	 * wait loading run_data until completed or timeout
	 */
	while (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		if (cv_timedwait(&sc->sc_put_seg_cv, &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWP_F_PUT_SEG)) {
		cmn_err(CE_WARN, "iwp_load_run_firmware(): "
		    "timeout waiting for run_data uCode load.\n");
		return (IWP_FAIL);
	}

	atomic_and_32(&sc->sc_flags, ~IWP_F_PUT_SEG);

	return (err);
}

/*
 * this function will be invoked to receive phy information
 * when a frame is received.
 */
static void
iwp_rx_phy_intr(iwp_sc_t *sc, iwp_rx_desc_t *desc)
{

	sc->sc_rx_phy_res.flag = 1;

	(void) memcpy(sc->sc_rx_phy_res.buf, (uint8_t *)(desc + 1),
	    sizeof (iwp_rx_phy_res_t));
}

/*
 * this function will be invoked to receive body of frame when
 * a frame is received.
 */
static void
iwp_rx_mpdu_intr(iwp_sc_t *sc, iwp_rx_desc_t *desc)
{
	ieee80211com_t	*ic = &sc->sc_ic;
#ifdef	DEBUG
	iwp_rx_ring_t	*ring = &sc->sc_rxq;
#endif
	struct ieee80211_frame		*wh;
	struct iwp_rx_non_cfg_phy	*phyinfo;
	struct	iwp_rx_mpdu_body_size	*mpdu_size;

	mblk_t			*mp;
	int16_t			t;
	uint16_t		len, rssi, agc;
	uint32_t		temp, crc, *tail;
	uint32_t		arssi, brssi, crssi, mrssi;
	iwp_rx_phy_res_t	*stat;
	ieee80211_node_t	*in;

	/*
	 * assuming not 11n here. cope with 11n in phase-II
	 */
	mpdu_size = (struct iwp_rx_mpdu_body_size *)(desc + 1);
	stat = (iwp_rx_phy_res_t *)sc->sc_rx_phy_res.buf;
	if (stat->cfg_phy_cnt > 20) {
		return;
	}

	phyinfo = (struct iwp_rx_non_cfg_phy *)stat->non_cfg_phy;
	temp = LE_32(phyinfo->non_cfg_phy[IWP_RX_RES_AGC_IDX]);
	agc = (temp & IWP_OFDM_AGC_MSK) >> IWP_OFDM_AGC_BIT_POS;

	temp = LE_32(phyinfo->non_cfg_phy[IWP_RX_RES_RSSI_AB_IDX]);
	arssi = (temp & IWP_OFDM_RSSI_A_MSK) >> IWP_OFDM_RSSI_A_BIT_POS;
	brssi = (temp & IWP_OFDM_RSSI_B_MSK) >> IWP_OFDM_RSSI_B_BIT_POS;

	temp = LE_32(phyinfo->non_cfg_phy[IWP_RX_RES_RSSI_C_IDX]);
	crssi = (temp & IWP_OFDM_RSSI_C_MSK) >> IWP_OFDM_RSSI_C_BIT_POS;

	mrssi = MAX(arssi, brssi);
	mrssi = MAX(mrssi, crssi);

	t = mrssi - agc - IWP_RSSI_OFFSET;
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
	    sizeof (struct iwp_rx_mpdu_body_size) + len);
	bcopy(tail, &crc, 4);

	IWP_DBG((IWP_DEBUG_RX, "iwp_rx_mpdu_intr(): "
	    "rx intr: idx=%d phy_len=%x len=%d "
	    "rate=%x chan=%d tstamp=%x non_cfg_phy_count=%x "
	    "cfg_phy_count=%x tail=%x", ring->cur, sizeof (*stat),
	    len, stat->rate.r.s.rate, stat->channel,
	    LE_32(stat->timestampl), stat->non_cfg_phy_cnt,
	    stat->cfg_phy_cnt, LE_32(crc)));

	if ((len < 16) || (len > sc->sc_dmabuf_sz)) {
		IWP_DBG((IWP_DEBUG_RX, "iwp_rx_mpdu_intr(): "
		    "rx frame oversize\n"));
		return;
	}

	/*
	 * discard Rx frames with bad CRC
	 */
	if ((LE_32(crc) &
	    (RX_RES_STATUS_NO_CRC32_ERROR | RX_RES_STATUS_NO_RXE_OVERFLOW)) !=
	    (RX_RES_STATUS_NO_CRC32_ERROR | RX_RES_STATUS_NO_RXE_OVERFLOW)) {
		IWP_DBG((IWP_DEBUG_RX, "iwp_rx_mpdu_intr(): "
		    "rx crc error tail: %x\n",
		    LE_32(crc)));
		sc->sc_rx_err++;
		return;
	}

	wh = (struct ieee80211_frame *)
	    ((uint8_t *)(desc + 1)+ sizeof (struct iwp_rx_mpdu_body_size));

	if (IEEE80211_FC0_SUBTYPE_ASSOC_RESP == *(uint8_t *)wh) {
		sc->sc_assoc_id = *((uint16_t *)(wh + 1) + 2);
		IWP_DBG((IWP_DEBUG_RX, "iwp_rx_mpdu_intr(): "
		    "rx : association id = %x\n",
		    sc->sc_assoc_id));
	}

#ifdef DEBUG
	if (iwp_dbg_flags & IWP_DEBUG_RX) {
		ieee80211_dump_pkt((uint8_t *)wh, len, 0, 0);
	}
#endif

	in = ieee80211_find_rxnode(ic, wh);
	mp = allocb(len, BPRI_MED);
	if (mp) {
		(void) memcpy(mp->b_wptr, wh, len);
		mp->b_wptr += len;

		/*
		 * send the frame to the 802.11 layer
		 */
		(void) ieee80211_input(ic, mp, in, rssi, 0);
	} else {
		sc->sc_rx_nobuf++;
		IWP_DBG((IWP_DEBUG_RX, "iwp_rx_mpdu_intr(): "
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
iwp_tx_intr(iwp_sc_t *sc, iwp_rx_desc_t *desc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwp_tx_ring_t *ring = &sc->sc_txq[desc->hdr.qid & 0x3];
	iwp_tx_stat_t *stat = (iwp_tx_stat_t *)(desc + 1);
	iwp_amrr_t *amrr;

	if (NULL == ic->ic_bss) {
		return;
	}

	amrr = (iwp_amrr_t *)ic->ic_bss;

	amrr->txcnt++;
	IWP_DBG((IWP_DEBUG_RATECTL, "iwp_tx_intr(): "
	    "tx: %d cnt\n", amrr->txcnt));

	if (stat->ntries > 0) {
		amrr->retrycnt++;
		sc->sc_tx_retries++;
		IWP_DBG((IWP_DEBUG_TX, "iwp_tx_intr(): "
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
iwp_cmd_intr(iwp_sc_t *sc, iwp_rx_desc_t *desc)
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

	IWP_DBG((IWP_DEBUG_CMD, "iwp_cmd_intr(): "
	    "qid=%x idx=%d flags=%x type=0x%x\n",
	    desc->hdr.qid, desc->hdr.idx, desc->hdr.flags,
	    desc->hdr.type));
}

/*
 * this function will be invoked when alive notification occur.
 */
static void
iwp_ucode_alive(iwp_sc_t *sc, iwp_rx_desc_t *desc)
{
	uint32_t rv;
	struct iwp_calib_cfg_cmd cmd;
	struct iwp_alive_resp *ar =
	    (struct iwp_alive_resp *)(desc + 1);
	struct iwp_calib_results *res_p = &sc->sc_calib_results;

	/*
	 * the microcontroller is ready
	 */
	IWP_DBG((IWP_DEBUG_FW, "iwp_ucode_alive(): "
	    "microcode alive notification minor: %x major: %x type: "
	    "%x subtype: %x\n",
	    ar->ucode_minor, ar->ucode_minor, ar->ver_type, ar->ver_subtype));

#ifdef	DEBUG
	if (LE_32(ar->is_valid) != UCODE_VALID_OK) {
		IWP_DBG((IWP_DEBUG_FW, "iwp_ucode_alive(): "
		    "microcontroller initialization failed\n"));
	}
#endif

	/*
	 * determine if init alive or runtime alive.
	 */
	if (INITIALIZE_SUBTYPE == ar->ver_subtype) {
		IWP_DBG((IWP_DEBUG_FW, "iwp_ucode_alive(): "
		    "initialization alive received.\n"));

		(void) memcpy(&sc->sc_card_alive_init, ar,
		    sizeof (struct iwp_init_alive_resp));

		/*
		 * necessary configuration to NIC
		 */
		mutex_enter(&sc->sc_glock);

		rv = iwp_alive_common(sc);
		if (rv != IWP_SUCCESS) {
			cmn_err(CE_WARN, "iwp_ucode_alive(): "
			    "common alive process failed in init alive.\n");
			mutex_exit(&sc->sc_glock);
			return;
		}

		(void) memset(&cmd, 0, sizeof (cmd));

		cmd.ucd_calib_cfg.once.is_enable = IWP_CALIB_INIT_CFG_ALL;
		cmd.ucd_calib_cfg.once.start = IWP_CALIB_INIT_CFG_ALL;
		cmd.ucd_calib_cfg.once.send_res = IWP_CALIB_INIT_CFG_ALL;
		cmd.ucd_calib_cfg.flags = IWP_CALIB_INIT_CFG_ALL;

		/*
		 * require ucode execute calibration
		 */
		rv = iwp_cmd(sc, CALIBRATION_CFG_CMD, &cmd, sizeof (cmd), 1);
		if (rv != IWP_SUCCESS) {
			cmn_err(CE_WARN, "iwp_ucode_alive(): "
			    "failed to send calibration configure command.\n");
			mutex_exit(&sc->sc_glock);
			return;
		}

		mutex_exit(&sc->sc_glock);

	} else {	/* runtime alive */

		IWP_DBG((IWP_DEBUG_FW, "iwp_ucode_alive(): "
		    "runtime alive received.\n"));

		(void) memcpy(&sc->sc_card_alive_run, ar,
		    sizeof (struct iwp_alive_resp));

		mutex_enter(&sc->sc_glock);

		/*
		 * necessary configuration to NIC
		 */
		rv = iwp_alive_common(sc);
		if (rv != IWP_SUCCESS) {
			cmn_err(CE_WARN, "iwp_ucode_alive(): "
			    "common alive process failed in run alive.\n");
			mutex_exit(&sc->sc_glock);
			return;
		}

		/*
		 * send the result of local oscilator calibration to uCode.
		 */
		if (res_p->lo_res != NULL) {
			rv = iwp_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->lo_res, res_p->lo_res_len, 1);
			if (rv != IWP_SUCCESS) {
				cmn_err(CE_WARN, "iwp_ucode_alive(): "
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
			rv = iwp_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->tx_iq_res, res_p->tx_iq_res_len, 1);
			if (rv != IWP_SUCCESS) {
				cmn_err(CE_WARN, "iwp_ucode_alive(): "
				    "failed to send TX IQ"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		/*
		 * send the result of TX IQ perd calibration to uCode.
		 */
		if (res_p->tx_iq_perd_res != NULL) {
			rv = iwp_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->tx_iq_perd_res,
			    res_p->tx_iq_perd_res_len, 1);
			if (rv != IWP_SUCCESS) {
				cmn_err(CE_WARN, "iwp_ucode_alive(): "
				    "failed to send TX IQ perd"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		/*
		 * send the result of Base Band calibration to uCode.
		 */
		if (res_p->base_band_res != NULL) {
			rv = iwp_cmd(sc, REPLY_PHY_CALIBRATION_CMD,
			    res_p->base_band_res,
			    res_p->base_band_res_len, 1);
			if (rv != IWP_SUCCESS) {
				cmn_err(CE_WARN, "iwp_ucode_alive(): "
				    "failed to send Base Band"
				    "calibration command.\n");
				mutex_exit(&sc->sc_glock);
				return;
			}

			DELAY(1000);
		}

		atomic_or_32(&sc->sc_flags, IWP_F_FW_INIT);
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
iwp_rx_softintr(caddr_t arg, caddr_t unused)
{
	iwp_sc_t *sc;
	ieee80211com_t *ic;
	iwp_rx_desc_t *desc;
	iwp_rx_data_t *data;
	uint32_t index;

	if (NULL == arg) {
		return (DDI_INTR_UNCLAIMED);
	}
	sc = (iwp_sc_t *)arg;
	ic = &sc->sc_ic;

	/*
	 * firmware has moved the index of the rx queue, driver get it,
	 * and deal with it.
	 */
	index = (sc->sc_shared->val0) & 0xfff;

	while (sc->sc_rxq.cur != index) {
		data = &sc->sc_rxq.data[sc->sc_rxq.cur];
		desc = (iwp_rx_desc_t *)data->dma_data.mem_va;

		IWP_DBG((IWP_DEBUG_INTR, "iwp_rx_softintr(): "
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
			iwp_cmd_intr(sc, desc);
		}

		switch (desc->hdr.type) {
		case REPLY_RX_PHY_CMD:
			iwp_rx_phy_intr(sc, desc);
			break;

		case REPLY_RX_MPDU_CMD:
			iwp_rx_mpdu_intr(sc, desc);
			break;

		case REPLY_TX:
			iwp_tx_intr(sc, desc);
			break;

		case REPLY_ALIVE:
			iwp_ucode_alive(sc, desc);
			break;

		case CARD_STATE_NOTIFICATION:
		{
			uint32_t *status = (uint32_t *)(desc + 1);

			IWP_DBG((IWP_DEBUG_RADIO, "iwp_rx_softintr(): "
			    "state changed to %x\n",
			    LE_32(*status)));

			if (LE_32(*status) & 1) {
				/*
				 * the radio button has to be pushed(OFF). It
				 * is considered as a hw error, the
				 * iwp_thread() tries to recover it after the
				 * button is pushed again(ON)
				 */
				cmn_err(CE_NOTE, "iwp_rx_softintr(): "
				    "radio transmitter is off\n");
				sc->sc_ostate = sc->sc_ic.ic_state;
				ieee80211_new_state(&sc->sc_ic,
				    IEEE80211_S_INIT, -1);
				atomic_or_32(&sc->sc_flags,
				    IWP_F_HW_ERR_RECOVER | IWP_F_RADIO_OFF);
			}

			break;
		}

		case SCAN_START_NOTIFICATION:
		{
			iwp_start_scan_t *scan =
			    (iwp_start_scan_t *)(desc + 1);

			IWP_DBG((IWP_DEBUG_SCAN, "iwp_rx_softintr(): "
			    "scanning channel %d status %x\n",
			    scan->chan, LE_32(scan->status)));

			ic->ic_curchan = &ic->ic_sup_channels[scan->chan];
			break;
		}

		case SCAN_COMPLETE_NOTIFICATION:
		{
#ifdef	DEBUG
			iwp_stop_scan_t *scan =
			    (iwp_stop_scan_t *)(desc + 1);

			IWP_DBG((IWP_DEBUG_SCAN, "iwp_rx_softintr(): "
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
			iwp_save_calib_result(sc, desc);
			break;

		case CALIBRATION_COMPLETE_NOTIFICATION:
			mutex_enter(&sc->sc_glock);
			atomic_or_32(&sc->sc_flags, IWP_F_FW_INIT);
			cv_signal(&sc->sc_ucode_cv);
			mutex_exit(&sc->sc_glock);
			break;

		case MISSED_BEACONS_NOTIFICATION:
		{
			struct iwp_beacon_missed *miss =
			    (struct iwp_beacon_missed *)(desc + 1);

			if ((ic->ic_state == IEEE80211_S_RUN) &&
			    (LE_32(miss->consecutive) > 50)) {
				cmn_err(CE_NOTE, "iwp: iwp_rx_softintr(): "
				    "beacon missed %d/%d\n",
				    LE_32(miss->consecutive),
				    LE_32(miss->total));
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_INIT, -1);
			}
			break;
		}
		}

		sc->sc_rxq.cur = (sc->sc_rxq.cur + 1) % RX_QUEUE_SIZE;
	}

	/*
	 * driver dealt with what received in rx queue and tell the information
	 * to the firmware.
	 */
	index = (0 == index) ? RX_QUEUE_SIZE - 1 : index - 1;
	IWP_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, index & (~7));

	/*
	 * re-enable interrupts
	 */
	IWP_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	return (DDI_INTR_CLAIMED);
}

/*
 * the handle of interrupt
 */
/* ARGSUSED */
static uint_t
iwp_intr(caddr_t arg, caddr_t unused)
{
	iwp_sc_t *sc;
	uint32_t r, rfh;

	if (NULL == arg) {
		return (DDI_INTR_UNCLAIMED);
	}
	sc = (iwp_sc_t *)arg;

	r = IWP_READ(sc, CSR_INT);
	if (0 == r || 0xffffffff == r) {
		return (DDI_INTR_UNCLAIMED);
	}

	IWP_DBG((IWP_DEBUG_INTR, "iwp_intr(): "
	    "interrupt reg %x\n", r));

	rfh = IWP_READ(sc, CSR_FH_INT_STATUS);

	IWP_DBG((IWP_DEBUG_INTR, "iwp_intr(): "
	    "FH interrupt reg %x\n", rfh));

	/*
	 * disable interrupts
	 */
	IWP_WRITE(sc, CSR_INT_MASK, 0);

	/*
	 * ack interrupts
	 */
	IWP_WRITE(sc, CSR_INT, r);
	IWP_WRITE(sc, CSR_FH_INT_STATUS, rfh);

	if (r & (BIT_INT_SWERROR | BIT_INT_ERR)) {
		IWP_DBG((IWP_DEBUG_FW, "iwp_intr(): "
		    "fatal firmware error\n"));
		iwp_stop(sc);
		sc->sc_ostate = sc->sc_ic.ic_state;

		/* notify upper layer */
		if (!IWP_CHK_FAST_RECOVER(sc)) {
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		}

		atomic_or_32(&sc->sc_flags, IWP_F_HW_ERR_RECOVER);
		return (DDI_INTR_CLAIMED);
	}

	if (r & BIT_INT_RF_KILL) {
		uint32_t tmp = IWP_READ(sc, CSR_GP_CNTRL);
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
		atomic_or_32(&sc->sc_flags, IWP_F_PUT_SEG);
		cv_signal(&sc->sc_put_seg_cv);
		mutex_exit(&sc->sc_glock);
	}

#ifdef	DEBUG
	if (r & BIT_INT_ALIVE)	{
		IWP_DBG((IWP_DEBUG_FW, "iwp_intr(): "
		    "firmware initialized.\n"));
	}
#endif

	/*
	 * re-enable interrupts
	 */
	IWP_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	return (DDI_INTR_CLAIMED);
}

static uint8_t
iwp_rate_to_plcp(int rate)
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
iwp_m_tx(void *arg, mblk_t *mp)
{
	iwp_sc_t	*sc;
	ieee80211com_t	*ic;
	mblk_t		*next;

	if (NULL == arg) {
		return (NULL);
	}
	sc = (iwp_sc_t *)arg;
	ic = &sc->sc_ic;

	if (sc->sc_flags & IWP_F_SUSPEND) {
		freemsgchain(mp);
		return (NULL);
	}

	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsgchain(mp);
		return (NULL);
	}

	if ((sc->sc_flags & IWP_F_HW_ERR_RECOVER) &&
	    IWP_CHK_FAST_RECOVER(sc)) {
		IWP_DBG((IWP_DEBUG_FW, "iwp_m_tx(): "
		    "hold queue\n"));
		return (mp);
	}


	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (iwp_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != 0) {
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
iwp_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	iwp_sc_t *sc;
	iwp_tx_ring_t *ring;
	iwp_tx_desc_t *desc;
	iwp_tx_data_t *data;
	iwp_tx_data_t *desc_data;
	iwp_cmd_t *cmd;
	iwp_tx_cmd_t *tx;
	ieee80211_node_t *in;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k = NULL;
	mblk_t *m, *m0;
	int hdrlen, len, len0, mblen, off, err = IWP_SUCCESS;
	uint16_t masks = 0;
	uint32_t rate, s_id = 0;

	if (NULL == ic) {
		return (IWP_FAIL);
	}
	sc = (iwp_sc_t *)ic;

	if (sc->sc_flags & IWP_F_SUSPEND) {
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		err = IWP_FAIL;
		goto exit;
	}

	mutex_enter(&sc->sc_tx_lock);
	ring = &sc->sc_txq[0];
	data = &ring->data[ring->cur];
	cmd = data->cmd;
	bzero(cmd, sizeof (*cmd));

	ring->cur = (ring->cur + 1) % ring->count;

	/*
	 * Need reschedule TX if TX buffer is full.
	 */
	if (ring->queued > ring->count - IWP_MAX_WIN_SIZE) {
		IWP_DBG((IWP_DEBUG_TX, "iwp_send(): "
		"no txbuf\n"));

		sc->sc_need_reschedule = 1;
		mutex_exit(&sc->sc_tx_lock);

		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		sc->sc_tx_nobuf++;
		err = IWP_FAIL;
		goto exit;
	}

	ring->queued++;

	mutex_exit(&sc->sc_tx_lock);

	hdrlen = ieee80211_hdrspace(ic, mp->b_rptr);

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (NULL == m) { /* can not alloc buf, drop this package */
		cmn_err(CE_WARN, "iwp_send(): "
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

		err = IWP_SUCCESS;
		goto exit;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) memcpy(m->b_rptr + off, m0->b_rptr, mblen);
		off += mblen;
	}

	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;

	/*
	 * determine send which AP or station in IBSS
	 */
	in = ieee80211_find_txnode(ic, wh->i_addr1);
	if (NULL == in) {
		cmn_err(CE_WARN, "iwp_send(): "
		    "failed to find tx node\n");
		freemsg(mp);
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

		err = IWP_SUCCESS;
		goto exit;
	}

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

	tx = (iwp_tx_cmd_t *)cmd->data;
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

			err = IWP_SUCCESS;
			goto exit;
		}

		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	len = msgdsize(m);

#ifdef DEBUG
	if (iwp_dbg_flags & IWP_DEBUG_TX) {
		ieee80211_dump_pkt((uint8_t *)wh, hdrlen, 0, 0);
	}
#endif

	tx->rts_retry_limit = IWP_TX_RTS_RETRY_LIMIT;
	tx->data_retry_limit = IWP_TX_DATA_RETRY_LIMIT;

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
		 * max value 54M for 11g and 11M for 11b originally.
		 */
		if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
			rate = ic->ic_fixed_rate;
		} else {
			if ((in->in_rates.ir_rates[in->in_txrate] &
			    IEEE80211_RATE_VAL) != 0) {
				rate = in->in_rates.
				    ir_rates[in->in_txrate] &
				    IEEE80211_RATE_VAL;
			}
		}

		tx->tx_flags |= LE_32(TX_CMD_FLG_SEQ_CTL_MSK);

		tx->timeout.pm_frame_timeout = 0;
	}

	IWP_DBG((IWP_DEBUG_TX, "iwp_send(): "
	    "tx rate[%d of %d] = %x",
	    in->in_txrate, in->in_rates.ir_nrates, rate));

	len0 = roundup(4 + sizeof (iwp_tx_cmd_t) + hdrlen, 4);
	if (len0 != (4 + sizeof (iwp_tx_cmd_t) + hdrlen)) {
		tx->tx_flags |= LE_32(TX_CMD_FLG_MH_PAD_MSK);
	}

	/*
	 * retrieve destination node's id
	 */
	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		tx->sta_id = IWP_BROADCAST_ID;
	} else {
		tx->sta_id = IWP_AP_ID;
	}

	if (2 == rate || 4 == rate || 11 == rate || 22 == rate) {
		masks |= RATE_MCS_CCK_MSK;
	}

	masks |= RATE_MCS_ANT_B_MSK;
	tx->rate.r.rate_n_flags = LE_32(iwp_rate_to_plcp(rate) | masks);

	IWP_DBG((IWP_DEBUG_TX, "iwp_send(): "
	    "tx flag = %x",
	    tx->tx_flags));

	tx->stop_time.life_time  = LE_32(0xffffffff);

	tx->len = LE_16(len);

	tx->dram_lsb_ptr =
	    LE_32(data->paddr_cmd + 4 + offsetof(iwp_tx_cmd_t, scratch));
	tx->dram_msb_ptr = 0;
	tx->driver_txop = 0;
	tx->next_frame_len = 0;

	(void) memcpy(tx + 1, m->b_rptr, hdrlen);
	m->b_rptr += hdrlen;
	(void) memcpy(data->dma_data.mem_va, m->b_rptr, len - hdrlen);

	IWP_DBG((IWP_DEBUG_TX, "iwp_send(): "
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
	IWP_DBG((IWP_DEBUG_TX, "iwp_send(): "
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
	if (ring->desc_cur < IWP_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWP_QUEUE_SIZE + ring->desc_cur].val =
		    (8 + len) | (s_id << 12);
	}

	IWP_DMA_SYNC(data->dma_data, DDI_DMA_SYNC_FORDEV);
	IWP_DMA_SYNC(ring->dma_desc, DDI_DMA_SYNC_FORDEV);

	ring->desc_cur = (ring->desc_cur + 1) % ring->count;
	IWP_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->desc_cur);

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
iwp_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	iwp_sc_t	*sc;
	ieee80211com_t	*ic;
	int		err = EINVAL;

	if (NULL == arg) {
		return;
	}
	sc = (iwp_sc_t *)arg;
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
			if (sc->sc_flags & IWP_F_RUNNING) {
				iwp_m_stop(sc);
				(void) iwp_m_start(sc);
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
iwp_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	iwp_sc_t	*sc;
	int		err = EINVAL;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwp_sc_t *)arg;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
iwp_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	iwp_sc_t	*sc;

	sc = (iwp_sc_t *)arg;
	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static int
iwp_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	iwp_sc_t		*sc;
	ieee80211com_t		*ic;
	int			err = EINVAL;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwp_sc_t *)arg;
	ic = &sc->sc_ic;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);

	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (sc->sc_flags & IWP_F_RUNNING) {
				iwp_m_stop(sc);
				(void) iwp_m_start(sc);
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
iwp_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	iwp_sc_t	*sc;
	ieee80211com_t	*ic;
	ieee80211_node_t *in;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwp_sc_t *)arg;
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

	return (IWP_SUCCESS);

}

/*
 * invoked by GLD to start or open NIC
 */
static int
iwp_m_start(void *arg)
{
	iwp_sc_t *sc;
	ieee80211com_t	*ic;
	int err = IWP_FAIL;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwp_sc_t *)arg;
	ic = &sc->sc_ic;

	err = iwp_init(sc);
	if (err != IWP_SUCCESS) {
		/*
		 * The hw init err(eg. RF is OFF). Return Success to make
		 * the 'plumb' succeed. The iwp_thread() tries to re-init
		 * background.
		 */
		atomic_or_32(&sc->sc_flags, IWP_F_HW_ERR_RECOVER);
		return (IWP_SUCCESS);
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	atomic_or_32(&sc->sc_flags, IWP_F_RUNNING);

	return (IWP_SUCCESS);
}

/*
 * invoked by GLD to stop or down NIC
 */
static void
iwp_m_stop(void *arg)
{
	iwp_sc_t *sc;
	ieee80211com_t	*ic;

	if (NULL == arg) {
		return;
	}
	sc = (iwp_sc_t *)arg;
	ic = &sc->sc_ic;

	iwp_stop(sc);

	/*
	 * release buffer for calibration
	 */
	iwp_release_calib_buffer(sc);

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	atomic_and_32(&sc->sc_flags, ~IWP_F_HW_ERR_RECOVER);
	atomic_and_32(&sc->sc_flags, ~IWP_F_RATE_AUTO_CTL);

	atomic_and_32(&sc->sc_flags, ~IWP_F_RUNNING);
	atomic_and_32(&sc->sc_flags, ~IWP_F_SCANNING);
}

/*
 * invoked by GLD to configure NIC
 */
static int
iwp_m_unicst(void *arg, const uint8_t *macaddr)
{
	iwp_sc_t *sc;
	ieee80211com_t	*ic;
	int err = IWP_SUCCESS;

	if (NULL == arg) {
		return (EINVAL);
	}
	sc = (iwp_sc_t *)arg;
	ic = &sc->sc_ic;

	if (!IEEE80211_ADDR_EQ(ic->ic_macaddr, macaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
		mutex_enter(&sc->sc_glock);
		err = iwp_config(sc);
		mutex_exit(&sc->sc_glock);
		if (err != IWP_SUCCESS) {
			cmn_err(CE_WARN, "iwp_m_unicst(): "
			    "failed to configure device\n");
			goto fail;
		}
	}

	return (err);

fail:
	return (err);
}

/* ARGSUSED */
static int
iwp_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	return (IWP_SUCCESS);
}

/* ARGSUSED */
static int
iwp_m_promisc(void *arg, boolean_t on)
{
	return (IWP_SUCCESS);
}

/*
 * kernel thread to deal with exceptional situation
 */
static void
iwp_thread(iwp_sc_t *sc)
{
	ieee80211com_t	*ic = &sc->sc_ic;
	clock_t clk;
	int err, n = 0, timeout = 0;
	uint32_t tmp;
#ifdef	DEBUG
	int times = 0;
#endif

	while (sc->sc_mf_thread_switch) {
		tmp = IWP_READ(sc, CSR_GP_CNTRL);
		if (tmp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) {
			atomic_and_32(&sc->sc_flags, ~IWP_F_RADIO_OFF);
		} else {
			atomic_or_32(&sc->sc_flags, IWP_F_RADIO_OFF);
		}

		/*
		 * If  in SUSPEND or the RF is OFF, do nothing.
		 */
		if (sc->sc_flags & IWP_F_RADIO_OFF) {
			delay(drv_usectohz(100000));
			continue;
		}

		/*
		 * recovery fatal error
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IWP_F_HW_ERR_RECOVER)) {

			IWP_DBG((IWP_DEBUG_FW, "iwp_thread(): "
			    "try to recover fatal hw error: %d\n", times++));

			iwp_stop(sc);

			if (IWP_CHK_FAST_RECOVER(sc)) {
				/* save runtime configuration */
				bcopy(&sc->sc_config, &sc->sc_config_save,
				    sizeof (sc->sc_config));
			} else {
				ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
				delay(drv_usectohz(2000000 + n*500000));
			}

			err = iwp_init(sc);
			if (err != IWP_SUCCESS) {
				n++;
				if (n < 20) {
					continue;
				}
			}

			n = 0;
			if (!err) {
				atomic_or_32(&sc->sc_flags, IWP_F_RUNNING);
			}


			if (!IWP_CHK_FAST_RECOVER(sc) ||
			    iwp_fast_recover(sc) != IWP_SUCCESS) {
				atomic_and_32(&sc->sc_flags,
				    ~IWP_F_HW_ERR_RECOVER);

				delay(drv_usectohz(2000000));
				if (sc->sc_ostate != IEEE80211_S_INIT) {
					ieee80211_new_state(ic,
					    IEEE80211_S_SCAN, 0);
				}
			}
		}

		if (ic->ic_mach &&
		    (sc->sc_flags & IWP_F_SCANNING) && sc->sc_scan_pending) {
			IWP_DBG((IWP_DEBUG_SCAN, "iwp_thread(): "
			    "wait for probe response\n"));

			sc->sc_scan_pending--;
			delay(drv_usectohz(200000));
			ieee80211_next_scan(ic);
		}

		/*
		 * rate ctl
		 */
		if (ic->ic_mach &&
		    (sc->sc_flags & IWP_F_RATE_AUTO_CTL)) {
			clk = ddi_get_lbolt();
			if (clk > sc->sc_clk + drv_usectohz(1000000)) {
				iwp_amrr_timeout(sc);
			}
		}

		delay(drv_usectohz(100000));

		mutex_enter(&sc->sc_mt_lock);
		if (sc->sc_tx_timer) {
			timeout++;
			if (10 == timeout) {
				sc->sc_tx_timer--;
				if (0 == sc->sc_tx_timer) {
					atomic_or_32(&sc->sc_flags,
					    IWP_F_HW_ERR_RECOVER);
					sc->sc_ostate = IEEE80211_S_RUN;
					IWP_DBG((IWP_DEBUG_FW, "iwp_thread(): "
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
iwp_cmd(iwp_sc_t *sc, int code, const void *buf, int size, int async)
{
	iwp_tx_ring_t *ring = &sc->sc_txq[IWP_CMD_QUEUE_NUM];
	iwp_tx_desc_t *desc;
	iwp_cmd_t *cmd;

	ASSERT(size <= sizeof (cmd->data));
	ASSERT(mutex_owned(&sc->sc_glock));

	IWP_DBG((IWP_DEBUG_CMD, "iwp_cmd() "
	    "code[%d]", code));
	desc = ring->data[ring->cur].desc;
	cmd = ring->data[ring->cur].cmd;

	cmd->hdr.type = (uint8_t)code;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur;
	(void) memcpy(cmd->data, buf, size);
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
	if (ring->cur < IWP_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWP_QUEUE_SIZE + ring->cur].val = 8;
	}
	ring->cur = (ring->cur + 1) % ring->count;
	IWP_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	if (async) {
		return (IWP_SUCCESS);
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
			return (IWP_SUCCESS);
		} else {
			sc->sc_cmd_flag = SC_CMD_FLG_NONE;
			return (IWP_FAIL);
		}
	}
}

/*
 * require ucode seting led of NIC
 */
static void
iwp_set_led(iwp_sc_t *sc, uint8_t id, uint8_t off, uint8_t on)
{
	iwp_led_cmd_t led;

	led.interval = LE_32(100000);	/* unit: 100ms */
	led.id = id;
	led.off = off;
	led.on = on;

	(void) iwp_cmd(sc, REPLY_LEDS_CMD, &led, sizeof (led), 1);
}

/*
 * necessary setting to NIC before authentication
 */
static int
iwp_hw_set_before_auth(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	int err = IWP_FAIL;

	/*
	 * update adapter's configuration according
	 * the info of target AP
	 */
	IEEE80211_ADDR_COPY(sc->sc_config.bssid, in->in_bssid);
	sc->sc_config.chan = LE_16(ieee80211_chan2ieee(ic, in->in_chan));

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

	IWP_DBG((IWP_DEBUG_80211, "iwp_hw_set_before_auth(): "
	    "config chan %d flags %x "
	    "filter_flags %x  cck %x ofdm %x"
	    " bssid:%02x:%02x:%02x:%02x:%02x:%2x\n",
	    LE_16(sc->sc_config.chan), LE_32(sc->sc_config.flags),
	    LE_32(sc->sc_config.filter_flags),
	    sc->sc_config.cck_basic_rates, sc->sc_config.ofdm_basic_rates,
	    sc->sc_config.bssid[0], sc->sc_config.bssid[1],
	    sc->sc_config.bssid[2], sc->sc_config.bssid[3],
	    sc->sc_config.bssid[4], sc->sc_config.bssid[5]));

	err = iwp_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwp_rxon_cmd_t), 1);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_hw_set_before_auth(): "
		    "failed to config chan%d\n", sc->sc_config.chan);
		return (err);
	}

	/*
	 * add default AP node
	 */
	err = iwp_add_ap_sta(sc);
	if (err != IWP_SUCCESS) {
		return (err);
	}


	return (err);
}

/*
 * Send a scan request(assembly scan cmd) to the firmware.
 */
static int
iwp_scan(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwp_tx_ring_t *ring = &sc->sc_txq[IWP_CMD_QUEUE_NUM];
	iwp_tx_desc_t *desc;
	iwp_tx_data_t *data;
	iwp_cmd_t *cmd;
	iwp_scan_hdr_t *hdr;
	iwp_scan_chan_t chan;
	struct ieee80211_frame *wh;
	ieee80211_node_t *in = ic->ic_bss;
	uint8_t essid[IEEE80211_NWID_LEN+1];
	struct ieee80211_rateset *rs;
	enum ieee80211_phymode mode;
	uint8_t *frm;
	int i, pktlen, nrates;

	data = &ring->data[ring->cur];
	desc = data->desc;
	cmd = (iwp_cmd_t *)data->dma_data.mem_va;

	cmd->hdr.type = REPLY_SCAN_CMD;
	cmd->hdr.flags = 0;
	cmd->hdr.qid = ring->qid;
	cmd->hdr.idx = ring->cur | 0x40;

	hdr = (iwp_scan_hdr_t *)cmd->data;
	(void) memset(hdr, 0, sizeof (iwp_scan_hdr_t));
	hdr->nchan = 1;
	hdr->quiet_time = LE_16(50);
	hdr->quiet_plcp_th = LE_16(1);

	hdr->flags = LE_32(RXON_FLG_BAND_24G_MSK);
	hdr->rx_chain = LE_16(RXON_RX_CHAIN_DRIVER_FORCE_MSK |
	    (0x7 << RXON_RX_CHAIN_VALID_POS) |
	    (0x2 << RXON_RX_CHAIN_FORCE_SEL_POS) |
	    (0x2 << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS));

	hdr->tx_cmd.tx_flags = LE_32(TX_CMD_FLG_SEQ_CTL_MSK);
	hdr->tx_cmd.sta_id = IWP_BROADCAST_ID;
	hdr->tx_cmd.stop_time.life_time = LE_32(0xffffffff);
	hdr->tx_cmd.rate.r.rate_n_flags = LE_32(iwp_rate_to_plcp(2));
	hdr->tx_cmd.rate.r.rate_n_flags |=
	    LE_32(RATE_MCS_ANT_B_MSK |RATE_MCS_CCK_MSK);
	hdr->direct_scan[0].len = ic->ic_des_esslen;
	hdr->direct_scan[0].id  = IEEE80211_ELEMID_SSID;

	hdr->filter_flags = LE_32(RXON_FILTER_ACCEPT_GRP_MSK |
	    RXON_FILTER_BCON_AWARE_MSK);

	if (ic->ic_des_esslen) {
		bcopy(ic->ic_des_essid, essid, ic->ic_des_esslen);
		essid[ic->ic_des_esslen] = '\0';
		IWP_DBG((IWP_DEBUG_SCAN, "iwp_scan(): "
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
		IWP_DBG((IWP_DEBUG_SCAN, "iwp_scan(): "
		    "probe with ESSID %s\n",
		    essid));
	}
	*frm++ = IEEE80211_ELEMID_SSID;
	*frm++ = in->in_esslen;
	(void) memcpy(frm, in->in_essid, in->in_esslen);
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
	(void) memcpy(frm, rs->ir_rates, nrates);
	frm += nrates;

	/*
	 * supported xrates IE
	 */
	if (rs->ir_nrates > IEEE80211_RATE_SIZE) {
		nrates = rs->ir_nrates - IEEE80211_RATE_SIZE;
		*frm++ = IEEE80211_ELEMID_XRATES;
		*frm++ = (uint8_t)nrates;
		(void) memcpy(frm, rs->ir_rates + IEEE80211_RATE_SIZE, nrates);
		frm += nrates;
	}

	/*
	 * optionnal IE (usually for wpa)
	 */
	if (ic->ic_opt_ie != NULL) {
		(void) memcpy(frm, ic->ic_opt_ie, ic->ic_opt_ie_len);
		frm += ic->ic_opt_ie_len;
	}

	/* setup length of probe request */
	hdr->tx_cmd.len = LE_16(_PTRDIFF(frm, wh));
	hdr->len = LE_16(hdr->nchan * sizeof (iwp_scan_chan_t) +
	    LE_16(hdr->tx_cmd.len) + sizeof (iwp_scan_hdr_t));

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

		bcopy(&chan, frm, sizeof (iwp_scan_chan_t));
		frm += sizeof (iwp_scan_chan_t);
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
	if (ring->cur < IWP_MAX_WIN_SIZE) {
		sc->sc_shared->queues_byte_cnt_tbls[ring->qid].
		    tfd_offset[IWP_QUEUE_SIZE + ring->cur].val = 8;
	}

	/*
	 * kick cmd ring
	 */
	ring->cur = (ring->cur + 1) % ring->count;
	IWP_WRITE(sc, HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);

	return (IWP_SUCCESS);
}

/*
 * configure NIC by using ucode commands after loading ucode.
 */
static int
iwp_config(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	iwp_powertable_cmd_t powertable;
	iwp_bt_cmd_t bt;
	iwp_add_sta_t node;
	iwp_rem_sta_t	rm_sta;
	const uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	int err = IWP_FAIL;

	/*
	 * set power mode. Disable power management at present, do it later
	 */
	(void) memset(&powertable, 0, sizeof (powertable));
	powertable.flags = LE_16(0x8);
	err = iwp_cmd(sc, POWER_TABLE_CMD, &powertable,
	    sizeof (powertable), 0);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_config(): "
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
	err = iwp_cmd(sc, REPLY_BT_CONFIG, &bt,
	    sizeof (bt), 0);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_config(): "
		    "failed to configurate bt coexistence\n");
		return (err);
	}

	/*
	 * configure rxon
	 */
	(void) memset(&sc->sc_config, 0, sizeof (iwp_rxon_cmd_t));
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

	sc->sc_config.rx_chain = LE_16(RXON_RX_CHAIN_DRIVER_FORCE_MSK |
	    (0x7 << RXON_RX_CHAIN_VALID_POS) |
	    (0x2 << RXON_RX_CHAIN_FORCE_SEL_POS) |
	    (0x2 << RXON_RX_CHAIN_FORCE_MIMO_SEL_POS));

	err = iwp_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwp_rxon_cmd_t), 0);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_config(): "
		    "failed to set configure command\n");
		return (err);
	}

	/*
	 * remove all nodes in NIC
	 */
	(void) memset(&rm_sta, 0, sizeof (rm_sta));
	rm_sta.num_sta = 1;
	(void) memcpy(rm_sta.addr, bcast, 6);

	err = iwp_cmd(sc, REPLY_REMOVE_STA, &rm_sta, sizeof (iwp_rem_sta_t), 0);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_config(): "
		    "failed to remove broadcast node in hardware.\n");
		return (err);
	}

	/*
	 * add broadcast node so that we can send broadcast frame
	 */
	(void) memset(&node, 0, sizeof (node));
	(void) memset(node.sta.addr, 0xff, 6);
	node.mode = 0;
	node.sta.sta_id = IWP_BROADCAST_ID;
	node.station_flags = 0;

	err = iwp_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 0);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_config(): "
		    "failed to add broadcast node\n");
		return (err);
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
iwp_quiesce(dev_info_t *dip)
{
	iwp_sc_t *sc;

	sc = ddi_get_soft_state(iwp_soft_state_p, ddi_get_instance(dip));
	if (NULL == sc) {
		return (DDI_FAILURE);
	}

#ifdef DEBUG
	/* by pass any messages, if it's quiesce */
	iwp_dbg_flags = 0;
#endif

	/*
	 * No more blocking is allowed while we are in the
	 * quiesce(9E) entry point.
	 */
	atomic_or_32(&sc->sc_flags, IWP_F_QUIESCED);

	/*
	 * Disable and mask all interrupts.
	 */
	iwp_stop(sc);

	return (DDI_SUCCESS);
}

static void
iwp_stop_master(iwp_sc_t *sc)
{
	uint32_t tmp;
	int n;

	tmp = IWP_READ(sc, CSR_RESET);
	IWP_WRITE(sc, CSR_RESET, tmp | CSR_RESET_REG_FLAG_STOP_MASTER);

	tmp = IWP_READ(sc, CSR_GP_CNTRL);
	if ((tmp & CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE) ==
	    CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE) {
		return;
	}

	for (n = 0; n < 2000; n++) {
		if (IWP_READ(sc, CSR_RESET) &
		    CSR_RESET_REG_FLAG_MASTER_DISABLED) {
			break;
		}
		DELAY(1000);
	}

#ifdef	DEBUG
	if (2000 == n) {
		IWP_DBG((IWP_DEBUG_HW, "iwp_stop_master(): "
		    "timeout waiting for master stop\n"));
	}
#endif
}

static int
iwp_power_up(iwp_sc_t *sc)
{
	uint32_t tmp;

	iwp_mac_access_enter(sc);
	tmp = iwp_reg_read(sc, ALM_APMG_PS_CTL);
	tmp &= ~APMG_PS_CTRL_REG_MSK_POWER_SRC;
	tmp |= APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN;
	iwp_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	iwp_mac_access_exit(sc);

	DELAY(5000);
	return (IWP_SUCCESS);
}

/*
 * hardware initialization
 */
static int
iwp_preinit(iwp_sc_t *sc)
{
	int		n;
	uint8_t		vlink;
	uint16_t	radio_cfg;
	uint32_t	tmp;

	/*
	 * clear any pending interrupts
	 */
	IWP_WRITE(sc, CSR_INT, 0xffffffff);

	tmp = IWP_READ(sc, CSR_GIO_CHICKEN_BITS);
	IWP_WRITE(sc, CSR_GIO_CHICKEN_BITS,
	    tmp | CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER);

	tmp = IWP_READ(sc, CSR_GP_CNTRL);
	IWP_WRITE(sc, CSR_GP_CNTRL, tmp | CSR_GP_CNTRL_REG_FLAG_INIT_DONE);

	/*
	 * wait for clock ready
	 */
	for (n = 0; n < 1000; n++) {
		if (IWP_READ(sc, CSR_GP_CNTRL) &
		    CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY) {
			break;
		}
		DELAY(10);
	}

	if (1000 == n) {
		return (ETIMEDOUT);
	}

	iwp_mac_access_enter(sc);

	iwp_reg_write(sc, ALM_APMG_CLK_EN, APMG_CLK_REG_VAL_DMA_CLK_RQT);

	DELAY(20);
	tmp = iwp_reg_read(sc, ALM_APMG_PCIDEV_STT);
	iwp_reg_write(sc, ALM_APMG_PCIDEV_STT, tmp |
	    APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE);
	iwp_mac_access_exit(sc);

	radio_cfg = IWP_READ_EEP_SHORT(sc, EEP_SP_RADIO_CONFIGURATION);
	if (SP_RADIO_TYPE_MSK(radio_cfg) < SP_RADIO_TYPE_MAX) {
		tmp = IWP_READ(sc, CSR_HW_IF_CONFIG_REG);
		IWP_WRITE(sc, CSR_HW_IF_CONFIG_REG,
		    tmp | SP_RADIO_TYPE_MSK(radio_cfg) |
		    SP_RADIO_STEP_MSK(radio_cfg) |
		    SP_RADIO_DASH_MSK(radio_cfg));
	} else {
		cmn_err(CE_WARN, "iwp_preinit(): "
		    "radio configuration information in eeprom is wrong\n");
		return (IWP_FAIL);
	}


	IWP_WRITE(sc, CSR_INT_COALESCING, 512 / 32);

	(void) iwp_power_up(sc);

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

	tmp = IWP_READ(sc, CSR_HW_IF_CONFIG_REG);
	tmp |= CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
	    CSR_HW_IF_CONFIG_REG_BIT_MAC_SI;
	IWP_WRITE(sc, CSR_HW_IF_CONFIG_REG, tmp);

	/*
	 * make sure power supply on each part of the hardware
	 */
	iwp_mac_access_enter(sc);
	tmp = iwp_reg_read(sc, ALM_APMG_PS_CTL);
	tmp |= APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ;
	iwp_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	DELAY(5);

	tmp = iwp_reg_read(sc, ALM_APMG_PS_CTL);
	tmp &= ~APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ;
	iwp_reg_write(sc, ALM_APMG_PS_CTL, tmp);
	iwp_mac_access_exit(sc);

	if (PA_TYPE_MIX == sc->sc_chip_param.pa_type) {
		IWP_WRITE(sc, CSR_GP_DRIVER_REG,
		    CSR_GP_DRIVER_REG_BIT_RADIO_SKU_2x2_MIX);
	}

	if (PA_TYPE_INTER == sc->sc_chip_param.pa_type) {

		IWP_WRITE(sc, CSR_GP_DRIVER_REG,
		    CSR_GP_DRIVER_REG_BIT_RADIO_SKU_2x2_IPA);
	}

	return (IWP_SUCCESS);
}

/*
 * set up semphore flag to own EEPROM
 */
static int
iwp_eep_sem_down(iwp_sc_t *sc)
{
	int count1, count2;
	uint32_t tmp;

	for (count1 = 0; count1 < 1000; count1++) {
		tmp = IWP_READ(sc, CSR_HW_IF_CONFIG_REG);
		IWP_WRITE(sc, CSR_HW_IF_CONFIG_REG,
		    tmp | CSR_HW_IF_CONFIG_REG_EEP_SEM);

		for (count2 = 0; count2 < 2; count2++) {
			if (IWP_READ(sc, CSR_HW_IF_CONFIG_REG) &
			    CSR_HW_IF_CONFIG_REG_EEP_SEM) {
				return (IWP_SUCCESS);
			}
			DELAY(10000);
		}
	}
	return (IWP_FAIL);
}

/*
 * reset semphore flag to release EEPROM
 */
static void
iwp_eep_sem_up(iwp_sc_t *sc)
{
	uint32_t tmp;

	tmp = IWP_READ(sc, CSR_HW_IF_CONFIG_REG);
	IWP_WRITE(sc, CSR_HW_IF_CONFIG_REG,
	    tmp & (~CSR_HW_IF_CONFIG_REG_EEP_SEM));
}

/*
 * This function read all infomation from eeprom
 */
static int
iwp_eep_load(iwp_sc_t *sc)
{
	int i, rr;
	uint32_t rv, tmp, eep_gp;
	uint16_t addr, eep_sz = sizeof (sc->sc_eep_map);
	uint16_t *eep_p = (uint16_t *)&sc->sc_eep_map;

	/*
	 * read eeprom gp register in CSR
	 */
	eep_gp = IWP_READ(sc, CSR_EEPROM_GP);
	if ((eep_gp & CSR_EEPROM_GP_VALID_MSK) ==
	    CSR_EEPROM_GP_BAD_SIGNATURE) {
		IWP_DBG((IWP_DEBUG_EEPROM, "iwp_eep_load(): "
		    "not find eeprom\n"));
		return (IWP_FAIL);
	}

	rr = iwp_eep_sem_down(sc);
	if (rr != 0) {
		IWP_DBG((IWP_DEBUG_EEPROM, "iwp_eep_load(): "
		    "driver failed to own EEPROM\n"));
		return (IWP_FAIL);
	}

	for (addr = 0; addr < eep_sz; addr += 2) {
		IWP_WRITE(sc, CSR_EEPROM_REG, addr<<1);
		tmp = IWP_READ(sc, CSR_EEPROM_REG);
		IWP_WRITE(sc, CSR_EEPROM_REG, tmp & ~(0x2));

		for (i = 0; i < 10; i++) {
			rv = IWP_READ(sc, CSR_EEPROM_REG);
			if (rv & 1) {
				break;
			}
			DELAY(10);
		}

		if (!(rv & 1)) {
			IWP_DBG((IWP_DEBUG_EEPROM, "iwp_eep_load(): "
			    "time out when read eeprome\n"));
			iwp_eep_sem_up(sc);
			return (IWP_FAIL);
		}

		eep_p[addr/2] = LE_16(rv >> 16);
	}

	iwp_eep_sem_up(sc);
	return (IWP_SUCCESS);
}

/*
 * initialize mac address in ieee80211com_t struct
 */
static void
iwp_get_mac_from_eep(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	IEEE80211_ADDR_COPY(ic->ic_macaddr, &sc->sc_eep_map[EEP_MAC_ADDRESS]);

	IWP_DBG((IWP_DEBUG_EEPROM, "iwp_get_mac_from_eep(): "
	    "mac:%2x:%2x:%2x:%2x:%2x:%2x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1], ic->ic_macaddr[2],
	    ic->ic_macaddr[3], ic->ic_macaddr[4], ic->ic_macaddr[5]));
}

/*
 * main initialization function
 */
static int
iwp_init(iwp_sc_t *sc)
{
	int err = IWP_FAIL;
	clock_t clk;

	/*
	 * release buffer for calibration
	 */
	iwp_release_calib_buffer(sc);

	mutex_enter(&sc->sc_glock);
	atomic_and_32(&sc->sc_flags, ~IWP_F_FW_INIT);

	err = iwp_init_common(sc);
	if (err != IWP_SUCCESS) {
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	/*
	 * backup ucode data part for future use.
	 */
	(void) memcpy(sc->sc_dma_fw_data_bak.mem_va,
	    sc->sc_dma_fw_data.mem_va,
	    sc->sc_dma_fw_data.alength);

	/* load firmware init segment into NIC */
	err = iwp_load_init_firmware(sc);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_init(): "
		    "failed to setup init firmware\n");
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	/*
	 * now press "execute" start running
	 */
	IWP_WRITE(sc, CSR_RESET, 0);

	clk = ddi_get_lbolt() + drv_usectohz(1000000);
	while (!(sc->sc_flags & IWP_F_FW_INIT)) {
		if (cv_timedwait(&sc->sc_ucode_cv,
		    &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWP_F_FW_INIT)) {
		cmn_err(CE_WARN, "iwp_init(): "
		    "failed to process init alive.\n");
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	mutex_exit(&sc->sc_glock);

	/*
	 * stop chipset for initializing chipset again
	 */
	iwp_stop(sc);

	mutex_enter(&sc->sc_glock);
	atomic_and_32(&sc->sc_flags, ~IWP_F_FW_INIT);

	err = iwp_init_common(sc);
	if (err != IWP_SUCCESS) {
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	/*
	 * load firmware run segment into NIC
	 */
	err = iwp_load_run_firmware(sc);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_init(): "
		    "failed to setup run firmware\n");
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	/*
	 * now press "execute" start running
	 */
	IWP_WRITE(sc, CSR_RESET, 0);

	clk = ddi_get_lbolt() + drv_usectohz(1000000);
	while (!(sc->sc_flags & IWP_F_FW_INIT)) {
		if (cv_timedwait(&sc->sc_ucode_cv,
		    &sc->sc_glock, clk) < 0) {
			break;
		}
	}

	if (!(sc->sc_flags & IWP_F_FW_INIT)) {
		cmn_err(CE_WARN, "iwp_init(): "
		    "failed to process runtime alive.\n");
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	mutex_exit(&sc->sc_glock);

	DELAY(1000);

	mutex_enter(&sc->sc_glock);
	atomic_and_32(&sc->sc_flags, ~IWP_F_FW_INIT);

	/*
	 * at this point, the firmware is loaded OK, then config the hardware
	 * with the ucode API, including rxon, txpower, etc.
	 */
	err = iwp_config(sc);
	if (err) {
		cmn_err(CE_WARN, "iwp_init(): "
		    "failed to configure device\n");
		mutex_exit(&sc->sc_glock);
		return (IWP_FAIL);
	}

	/*
	 * at this point, hardware may receive beacons :)
	 */
	mutex_exit(&sc->sc_glock);
	return (IWP_SUCCESS);
}

/*
 * stop or disable NIC
 */
static void
iwp_stop(iwp_sc_t *sc)
{
	uint32_t tmp;
	int i;

	/* by pass if it's quiesced */
	if (!(sc->sc_flags & IWP_F_QUIESCED)) {
		mutex_enter(&sc->sc_glock);
	}

	IWP_WRITE(sc, CSR_RESET, CSR_RESET_REG_FLAG_NEVO_RESET);
	/*
	 * disable interrupts
	 */
	IWP_WRITE(sc, CSR_INT_MASK, 0);
	IWP_WRITE(sc, CSR_INT, CSR_INI_SET_MASK);
	IWP_WRITE(sc, CSR_FH_INT_STATUS, 0xffffffff);

	/*
	 * reset all Tx rings
	 */
	for (i = 0; i < IWP_NUM_QUEUES; i++) {
		iwp_reset_tx_ring(sc, &sc->sc_txq[i]);
	}

	/*
	 * reset Rx ring
	 */
	iwp_reset_rx_ring(sc);

	iwp_mac_access_enter(sc);
	iwp_reg_write(sc, ALM_APMG_CLK_DIS, APMG_CLK_REG_VAL_DMA_CLK_RQT);
	iwp_mac_access_exit(sc);

	DELAY(5);

	iwp_stop_master(sc);

	mutex_enter(&sc->sc_mt_lock);
	sc->sc_tx_timer = 0;
	mutex_exit(&sc->sc_mt_lock);

	tmp = IWP_READ(sc, CSR_RESET);
	IWP_WRITE(sc, CSR_RESET, tmp | CSR_RESET_REG_FLAG_SW_RESET);

	/* by pass if it's quiesced */
	if (!(sc->sc_flags & IWP_F_QUIESCED)) {
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

#define	IWP_AMRR_MIN_SUCCESS_THRESHOLD	 1
#define	IWP_AMRR_MAX_SUCCESS_THRESHOLD	15

static void
iwp_amrr_init(iwp_amrr_t *amrr)
{
	amrr->success = 0;
	amrr->recovery = 0;
	amrr->txcnt = amrr->retrycnt = 0;
	amrr->success_threshold = IWP_AMRR_MIN_SUCCESS_THRESHOLD;
}

static void
iwp_amrr_timeout(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	IWP_DBG((IWP_DEBUG_RATECTL, "iwp_amrr_timeout(): "
	    "enter\n"));

	if (IEEE80211_M_STA == ic->ic_opmode) {
		iwp_amrr_ratectl(NULL, ic->ic_bss);
	} else {
		ieee80211_iterate_nodes(&ic->ic_sta, iwp_amrr_ratectl, NULL);
	}

	sc->sc_clk = ddi_get_lbolt();
}

/* ARGSUSED */
static void
iwp_amrr_ratectl(void *arg, ieee80211_node_t *in)
{
	iwp_amrr_t *amrr = (iwp_amrr_t *)in;
	int need_change = 0;

	if (is_success(amrr) && is_enough(amrr)) {
		amrr->success++;
		if (amrr->success >= amrr->success_threshold &&
		    !is_max_rate(in)) {
			amrr->recovery = 1;
			amrr->success = 0;
			increase_rate(in);
			IWP_DBG((IWP_DEBUG_RATECTL, "iwp_amrr_ratectl(): "
			    "AMRR increasing rate %d "
			    "(txcnt=%d retrycnt=%d)\n",
			    in->in_txrate, amrr->txcnt,
			    amrr->retrycnt));
			need_change = 1;
		} else {
			amrr->recovery = 0;
		}
	} else if (not_very_few(amrr) && is_failure(amrr)) {
		amrr->success = 0;
		if (!is_min_rate(in)) {
			if (amrr->recovery) {
				amrr->success_threshold++;
				if (amrr->success_threshold >
				    IWP_AMRR_MAX_SUCCESS_THRESHOLD) {
					amrr->success_threshold =
					    IWP_AMRR_MAX_SUCCESS_THRESHOLD;
				}
			} else {
				amrr->success_threshold =
				    IWP_AMRR_MIN_SUCCESS_THRESHOLD;
			}
			decrease_rate(in);
			IWP_DBG((IWP_DEBUG_RATECTL, "iwp_amrr_ratectl(): "
			    "AMRR decreasing rate %d "
			    "(txcnt=%d retrycnt=%d)\n",
			    in->in_txrate, amrr->txcnt,
			    amrr->retrycnt));
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
iwp_eep_addr_trans(iwp_sc_t *sc, uint32_t indi_addr)
{
	uint32_t	di_addr;
	uint16_t	temp;

	if (!(indi_addr & INDIRECT_ADDRESS)) {
		di_addr = indi_addr;
		return (&sc->sc_eep_map[di_addr]);
	}

	switch (indi_addr & INDIRECT_TYPE_MSK) {
	case INDIRECT_GENERAL:
		temp = IWP_READ_EEP_SHORT(sc, EEP_LINK_GENERAL);
		break;
	case	INDIRECT_HOST:
		temp = IWP_READ_EEP_SHORT(sc, EEP_LINK_HOST);
		break;
	case	INDIRECT_REGULATORY:
		temp = IWP_READ_EEP_SHORT(sc, EEP_LINK_REGULATORY);
		break;
	case	INDIRECT_CALIBRATION:
		temp = IWP_READ_EEP_SHORT(sc, EEP_LINK_CALIBRATION);
		break;
	case	INDIRECT_PROCESS_ADJST:
		temp = IWP_READ_EEP_SHORT(sc, EEP_LINK_PROCESS_ADJST);
		break;
	case	INDIRECT_OTHERS:
		temp = IWP_READ_EEP_SHORT(sc, EEP_LINK_OTHERS);
		break;
	default:
		temp = 0;
		cmn_err(CE_WARN, "iwp_eep_addr_trans(): "
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
iwp_put_seg_fw(iwp_sc_t *sc, uint32_t addr_s, uint32_t addr_d, uint32_t len)
{

	iwp_mac_access_enter(sc);

	IWP_WRITE(sc, IWP_FH_TCSR_CHNL_TX_CONFIG_REG(IWP_FH_SRVC_CHNL),
	    IWP_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_PAUSE);

	IWP_WRITE(sc, IWP_FH_SRVC_CHNL_SRAM_ADDR_REG(IWP_FH_SRVC_CHNL), addr_d);

	IWP_WRITE(sc, IWP_FH_TFDIB_CTRL0_REG(IWP_FH_SRVC_CHNL),
	    (addr_s & FH_MEM_TFDIB_DRAM_ADDR_LSB_MASK));

	IWP_WRITE(sc, IWP_FH_TFDIB_CTRL1_REG(IWP_FH_SRVC_CHNL), len);

	IWP_WRITE(sc, IWP_FH_TCSR_CHNL_TX_BUF_STS_REG(IWP_FH_SRVC_CHNL),
	    (1 << IWP_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_NUM) |
	    (1 << IWP_FH_TCSR_CHNL_TX_BUF_STS_REG_POS_TB_IDX) |
	    IWP_FH_TCSR_CHNL_TX_BUF_STS_REG_VAL_TFDB_VALID);

	IWP_WRITE(sc, IWP_FH_TCSR_CHNL_TX_CONFIG_REG(IWP_FH_SRVC_CHNL),
	    IWP_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
	    IWP_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_DISABLE_VAL |
	    IWP_FH_TCSR_TX_CONFIG_REG_VAL_CIRQ_HOST_ENDTFD);

	iwp_mac_access_exit(sc);

	return (IWP_SUCCESS);
}

/*
 * necessary setting during alive notification
 */
static int
iwp_alive_common(iwp_sc_t *sc)
{
	uint32_t	base;
	uint32_t	i;
	iwp_wimax_coex_cmd_t	w_cmd;
	iwp_calibration_crystal_cmd_t	c_cmd;
	uint32_t	rv = IWP_FAIL;

	/*
	 * initialize SCD related registers to make TX work.
	 */
	iwp_mac_access_enter(sc);

	/*
	 * read sram address of data base.
	 */
	sc->sc_scd_base = iwp_reg_read(sc, IWP_SCD_SRAM_BASE_ADDR);

	for (base = sc->sc_scd_base + IWP_SCD_CONTEXT_DATA_OFFSET;
	    base < sc->sc_scd_base + IWP_SCD_TX_STTS_BITMAP_OFFSET;
	    base += 4) {
		iwp_mem_write(sc, base, 0);
	}

	for (; base < sc->sc_scd_base + IWP_SCD_TRANSLATE_TBL_OFFSET;
	    base += 4) {
		iwp_mem_write(sc, base, 0);
	}

	for (i = 0; i < sizeof (uint16_t) * IWP_NUM_QUEUES; i += 4) {
		iwp_mem_write(sc, base + i, 0);
	}

	iwp_reg_write(sc, IWP_SCD_DRAM_BASE_ADDR,
	    sc->sc_dma_sh.cookie.dmac_address >> 10);

	iwp_reg_write(sc, IWP_SCD_QUEUECHAIN_SEL,
	    IWP_SCD_QUEUECHAIN_SEL_ALL(IWP_NUM_QUEUES));

	iwp_reg_write(sc, IWP_SCD_AGGR_SEL, 0);

	for (i = 0; i < IWP_NUM_QUEUES; i++) {
		iwp_reg_write(sc, IWP_SCD_QUEUE_RDPTR(i), 0);
		IWP_WRITE(sc, HBUS_TARG_WRPTR, 0 | (i << 8));
		iwp_mem_write(sc, sc->sc_scd_base +
		    IWP_SCD_CONTEXT_QUEUE_OFFSET(i), 0);
		iwp_mem_write(sc, sc->sc_scd_base +
		    IWP_SCD_CONTEXT_QUEUE_OFFSET(i) +
		    sizeof (uint32_t),
		    ((SCD_WIN_SIZE << IWP_SCD_QUEUE_CTX_REG2_WIN_SIZE_POS) &
		    IWP_SCD_QUEUE_CTX_REG2_WIN_SIZE_MSK) |
		    ((SCD_FRAME_LIMIT <<
		    IWP_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS) &
		    IWP_SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK));
	}

	iwp_reg_write(sc, IWP_SCD_INTERRUPT_MASK, (1 << IWP_NUM_QUEUES) - 1);

	iwp_reg_write(sc, (IWP_SCD_BASE + 0x10),
	    SCD_TXFACT_REG_TXFIFO_MASK(0, 7));

	IWP_WRITE(sc, HBUS_TARG_WRPTR, (IWP_CMD_QUEUE_NUM << 8));
	iwp_reg_write(sc, IWP_SCD_QUEUE_RDPTR(IWP_CMD_QUEUE_NUM), 0);

	/*
	 * queue 0-7 map to FIFO 0-7 and
	 * all queues work under FIFO mode(none-scheduler_ack)
	 */
	for (i = 0; i < 4; i++) {
		iwp_reg_write(sc, IWP_SCD_QUEUE_STATUS_BITS(i),
		    (1 << IWP_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
		    ((3-i) << IWP_SCD_QUEUE_STTS_REG_POS_TXF) |
		    (1 << IWP_SCD_QUEUE_STTS_REG_POS_WSL) |
		    IWP_SCD_QUEUE_STTS_REG_MSK);
	}

	iwp_reg_write(sc, IWP_SCD_QUEUE_STATUS_BITS(IWP_CMD_QUEUE_NUM),
	    (1 << IWP_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
	    (IWP_CMD_FIFO_NUM << IWP_SCD_QUEUE_STTS_REG_POS_TXF) |
	    (1 << IWP_SCD_QUEUE_STTS_REG_POS_WSL) |
	    IWP_SCD_QUEUE_STTS_REG_MSK);

	for (i = 5; i < 7; i++) {
		iwp_reg_write(sc, IWP_SCD_QUEUE_STATUS_BITS(i),
		    (1 << IWP_SCD_QUEUE_STTS_REG_POS_ACTIVE) |
		    (i << IWP_SCD_QUEUE_STTS_REG_POS_TXF) |
		    (1 << IWP_SCD_QUEUE_STTS_REG_POS_WSL) |
		    IWP_SCD_QUEUE_STTS_REG_MSK);
	}

	iwp_mac_access_exit(sc);

	(void) memset(&w_cmd, 0, sizeof (w_cmd));

	rv = iwp_cmd(sc, COEX_PRIORITY_TABLE_CMD, &w_cmd, sizeof (w_cmd), 1);
	if (rv != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alive_common(): "
		    "failed to send wimax coexist command.\n");
		return (rv);
	}

	(void) memset(&c_cmd, 0, sizeof (c_cmd));

	c_cmd.opCode = PHY_CALIBRATE_CRYSTAL_FRQ_CMD;
	c_cmd.data.cap_pin1 = LE_16(sc->sc_eep_calib->xtal_calib[0]);
	c_cmd.data.cap_pin2 = LE_16(sc->sc_eep_calib->xtal_calib[1]);

	rv = iwp_cmd(sc, REPLY_PHY_CALIBRATION_CMD, &c_cmd, sizeof (c_cmd), 1);
	if (rv != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_alive_common(): "
		    "failed to send crystal frq calibration command.\n");
		return (rv);
	}

	/*
	 * make sure crystal frequency calibration ready
	 * before next operations.
	 */
	DELAY(1000);

	return (IWP_SUCCESS);
}

/*
 * save results of calibration from ucode
 */
static void
iwp_save_calib_result(iwp_sc_t *sc, iwp_rx_desc_t *desc)
{
	struct iwp_calib_results *res_p = &sc->sc_calib_results;
	struct iwp_calib_hdr *calib_hdr = (struct iwp_calib_hdr *)(desc + 1);
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
			cmn_err(CE_WARN, "iwp_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->lo_res_len = len;
		(void) memcpy(res_p->lo_res, calib_hdr, len);
		break;
	case PHY_CALIBRATE_TX_IQ_CMD:
		if (NULL == res_p->tx_iq_res) {
			res_p->tx_iq_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->tx_iq_res) {
			cmn_err(CE_WARN, "iwp_save_calib_result(): "
			    "failed to allocate memory.\n");
			return;
		}

		res_p->tx_iq_res_len = len;
		(void) memcpy(res_p->tx_iq_res, calib_hdr, len);
		break;
	case PHY_CALIBRATE_TX_IQ_PERD_CMD:
		if (NULL == res_p->tx_iq_perd_res) {
			res_p->tx_iq_perd_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->tx_iq_perd_res) {
			cmn_err(CE_WARN, "iwp_save_calib_result(): "
			    "failed to allocate memory.\n");
		}

		res_p->tx_iq_perd_res_len = len;
		(void) memcpy(res_p->tx_iq_perd_res, calib_hdr, len);
		break;
	case PHY_CALIBRATE_BASE_BAND_CMD:
		if (NULL == res_p->base_band_res) {
			res_p->base_band_res = kmem_alloc(len, KM_NOSLEEP);
		}

		if (NULL == res_p->base_band_res) {
			cmn_err(CE_WARN, "iwp_save_calib_result(): "
			    "failed to allocate memory.\n");
		}

		res_p->base_band_res_len = len;
		(void) memcpy(res_p->base_band_res, calib_hdr, len);
		break;
	default:
		cmn_err(CE_WARN, "iwp_save_calib_result(): "
		    "incorrect calibration type(%d).\n", calib_hdr->op_code);
		break;
	}

}

static void
iwp_release_calib_buffer(iwp_sc_t *sc)
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
iwp_init_common(iwp_sc_t *sc)
{
	int32_t	qid;
	uint32_t tmp;

	(void) iwp_preinit(sc);

	tmp = IWP_READ(sc, CSR_GP_CNTRL);
	if (!(tmp & CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW)) {
		cmn_err(CE_NOTE, "iwp_init_common(): "
		    "radio transmitter is off\n");
		return (IWP_FAIL);
	}

	/*
	 * init Rx ring
	 */
	iwp_mac_access_enter(sc);
	IWP_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);

	IWP_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, 0);
	IWP_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_BASE_REG,
	    sc->sc_rxq.dma_desc.cookie.dmac_address >> 8);

	IWP_WRITE(sc, FH_RSCSR_CHNL0_STTS_WPTR_REG,
	    ((uint32_t)(sc->sc_dma_sh.cookie.dmac_address +
	    offsetof(struct iwp_shared, val0)) >> 4));

	IWP_WRITE(sc, FH_MEM_RCSR_CHNL0_CONFIG_REG,
	    FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL |
	    FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL |
	    IWP_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K |
	    (RX_QUEUE_SIZE_LOG <<
	    FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT));
	iwp_mac_access_exit(sc);
	IWP_WRITE(sc, FH_RSCSR_CHNL0_RBDCB_WPTR_REG,
	    (RX_QUEUE_SIZE - 1) & ~0x7);

	/*
	 * init Tx rings
	 */
	iwp_mac_access_enter(sc);
	iwp_reg_write(sc, IWP_SCD_TXFACT, 0);

	/*
	 * keep warm page
	 */
	IWP_WRITE(sc, IWP_FH_KW_MEM_ADDR_REG,
	    sc->sc_dma_kw.cookie.dmac_address >> 4);

	for (qid = 0; qid < IWP_NUM_QUEUES; qid++) {
		IWP_WRITE(sc, FH_MEM_CBBC_QUEUE(qid),
		    sc->sc_txq[qid].dma_desc.cookie.dmac_address >> 8);
		IWP_WRITE(sc, IWP_FH_TCSR_CHNL_TX_CONFIG_REG(qid),
		    IWP_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
		    IWP_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL);
	}

	iwp_mac_access_exit(sc);

	/*
	 * clear "radio off" and "disable command" bits
	 */
	IWP_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	IWP_WRITE(sc, CSR_UCODE_DRV_GP1_CLR,
	    CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);

	/*
	 * clear any pending interrupts
	 */
	IWP_WRITE(sc, CSR_INT, 0xffffffff);

	/*
	 * enable interrupts
	 */
	IWP_WRITE(sc, CSR_INT_MASK, CSR_INI_SET_MASK);

	IWP_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);
	IWP_WRITE(sc, CSR_UCODE_DRV_GP1_CLR, CSR_UCODE_SW_BIT_RFKILL);

	return (IWP_SUCCESS);
}

static int
iwp_fast_recover(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	int err = IWP_FAIL;

	mutex_enter(&sc->sc_glock);

	/* restore runtime configuration */
	bcopy(&sc->sc_config_save, &sc->sc_config,
	    sizeof (sc->sc_config));

	sc->sc_config.assoc_id = 0;
	sc->sc_config.filter_flags &= ~LE_32(RXON_FILTER_ASSOC_MSK);

	if ((err = iwp_hw_set_before_auth(sc)) != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_fast_recover(): "
		    "could not setup authentication\n");
		mutex_exit(&sc->sc_glock);
		return (err);
	}

	bcopy(&sc->sc_config_save, &sc->sc_config,
	    sizeof (sc->sc_config));

	/* update adapter's configuration */
	err = iwp_run_state_config(sc);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_fast_recover(): "
		    "failed to setup association\n");
		mutex_exit(&sc->sc_glock);
		return (err);
	}
	/* set LED on */
	iwp_set_led(sc, 2, 0, 1);

	mutex_exit(&sc->sc_glock);

	atomic_and_32(&sc->sc_flags, ~IWP_F_HW_ERR_RECOVER);

	/* start queue */
	IWP_DBG((IWP_DEBUG_FW, "iwp_fast_recover(): "
	    "resume xmit\n"));
	mac_tx_update(ic->ic_mach);

	return (IWP_SUCCESS);
}

static int
iwp_run_state_config(iwp_sc_t *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	int err = IWP_FAIL;

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

	sc->sc_config.filter_flags |=
	    LE_32(RXON_FILTER_ASSOC_MSK);

	if (ic->ic_opmode != IEEE80211_M_STA) {
		sc->sc_config.filter_flags |=
		    LE_32(RXON_FILTER_BCON_AWARE_MSK);
	}

	IWP_DBG((IWP_DEBUG_80211, "iwp_run_state_config(): "
	    "config chan %d flags %x"
	    " filter_flags %x\n",
	    sc->sc_config.chan, sc->sc_config.flags,
	    sc->sc_config.filter_flags));

	err = iwp_cmd(sc, REPLY_RXON, &sc->sc_config,
	    sizeof (iwp_rxon_cmd_t), 1);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_run_state_config(): "
		    "could not update configuration\n");
		return (err);
	}

	return (err);
}

/*
 * This function overwrites default configurations of
 * ieee80211com structure in Net80211 module.
 */
static void
iwp_overwrite_ic_default(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;

	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = iwp_newstate;
	ic->ic_node_alloc = iwp_node_alloc;
	ic->ic_node_free = iwp_node_free;
}


/*
 * This function adds AP station into hardware.
 */
static int
iwp_add_ap_sta(iwp_sc_t *sc)
{
	ieee80211com_t *ic = &sc->sc_ic;
	ieee80211_node_t *in = ic->ic_bss;
	iwp_add_sta_t node;
	int err = IWP_FAIL;

	/*
	 * Add AP node into hardware.
	 */
	(void) memset(&node, 0, sizeof (node));
	IEEE80211_ADDR_COPY(node.sta.addr, in->in_bssid);
	node.mode = STA_MODE_ADD_MSK;
	node.sta.sta_id = IWP_AP_ID;

	err = iwp_cmd(sc, REPLY_ADD_STA, &node, sizeof (node), 1);
	if (err != IWP_SUCCESS) {
		cmn_err(CE_WARN, "iwp_add_ap_sta(): "
		    "failed to add AP node\n");
		return (err);
	}

	return (err);
}

/*
 * Check EEPROM version and Calibration version.
 */
static int
iwp_eep_ver_chk(iwp_sc_t *sc)
{
	if ((IWP_READ_EEP_SHORT(sc, EEP_VERSION) < 0x011a) ||
	    (sc->sc_eep_calib->tx_pow_calib_hdr.calib_version < 4)) {
		cmn_err(CE_WARN, "iwp_eep_ver_chk(): "
		    "unsupported eeprom detected\n");
		return (IWP_FAIL);
	}

	return (IWP_SUCCESS);
}

/*
 * Determine parameters for all supported chips.
 */
static void
iwp_set_chip_param(iwp_sc_t *sc)
{
	if ((0x008d == sc->sc_dev_id) ||
	    (0x008e == sc->sc_dev_id)) {
		sc->sc_chip_param.phy_mode = PHY_MODE_G |
		    PHY_MODE_A | PHY_MODE_N;

		sc->sc_chip_param.tx_ant = ANT_A | ANT_B;
		sc->sc_chip_param.rx_ant = ANT_A | ANT_B;

		sc->sc_chip_param.pa_type = PA_TYPE_MIX;
	}

	if ((0x422c == sc->sc_dev_id) ||
	    (0x4239 == sc->sc_dev_id)) {
		sc->sc_chip_param.phy_mode = PHY_MODE_G |
		    PHY_MODE_A | PHY_MODE_N;

		sc->sc_chip_param.tx_ant = ANT_B | ANT_C;
		sc->sc_chip_param.rx_ant = ANT_B | ANT_C;

		sc->sc_chip_param.pa_type = PA_TYPE_INTER;
	}

	if ((0x422b == sc->sc_dev_id) ||
	    (0x4238 == sc->sc_dev_id)) {
		sc->sc_chip_param.phy_mode = PHY_MODE_G |
		    PHY_MODE_A | PHY_MODE_N;

		sc->sc_chip_param.tx_ant = ANT_A | ANT_B | ANT_C;
		sc->sc_chip_param.rx_ant = ANT_A | ANT_B | ANT_C;

		sc->sc_chip_param.pa_type = PA_TYPE_SYSTEM;
	}
}
