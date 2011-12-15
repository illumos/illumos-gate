/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/* Copyright © 2003-2011 Emulex. All rights reserved.  */


/*
 * Source file containing the implementation of the driver entry points
 * and related helper functions
 */

#include <oce_impl.h>
#include <oce_stat.h>
#include <oce_ioctl.h>

#define	ATTACH_DEV_INIT 	0x1
#define	ATTACH_FM_INIT		0x2
#define	ATTACH_PCI_CFG		0x4
#define	ATTACH_LOCK_INIT	0x8
#define	ATTACH_PCI_INIT 	0x10
#define	ATTACH_HW_INIT		0x20
#define	ATTACH_SETUP_TXRX 	0x40
#define	ATTACH_SETUP_ADAP	0x80
#define	ATTACH_SETUP_INTR	0x100
#define	ATTACH_STAT_INIT	0x200
#define	ATTACH_MAC_REG		0x400

/* ---[ globals and externs ]-------------------------------------------- */
const char oce_ident_string[] = OCE_IDENT_STRING;
const char oce_mod_name[] = OCE_MOD_NAME;
struct oce_dev *oce_dev_list[MAX_DEVS + 1];	/* Last entry is invalid */

/* driver properties */
static const char flow_control[]	 = "flow_control";
static const char mtu_prop_name[]	 = "oce_default_mtu";
static const char tx_ring_size_name[]	 = "tx_ring_size";
static const char tx_bcopy_limit_name[]	 = "tx_bcopy_limit";
static const char rx_bcopy_limit_name[]	 = "rx_bcopy_limit";
static const char rx_frag_size_name[]	 = "rx_frag_size";
static const char rx_max_bufs_name[]	 = "rx_max_bufs";
static const char fm_cap_name[]		 = "oce_fm_capability";
static const char log_level_name[]	 = "oce_log_level";
static const char lso_capable_name[]	 = "lso_capable";
static const char rx_pkt_per_intr_name[] = "rx_pkts_per_intr";
static const char tx_reclaim_threshold_name[] = "tx_reclaim_threshold";
static const char rx_rings_name[]	 = "max_rx_rings";
static const char tx_rings_name[]	 = "max_tx_rings";

/* --[ static function prototypes here ]------------------------------- */
static int oce_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd);
static int oce_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int oce_quiesce(dev_info_t *dip);
static int oce_suspend(dev_info_t *dip);
static int oce_resume(dev_info_t *dip);
static void oce_unconfigure(struct oce_dev *dev);
static void oce_init_locks(struct oce_dev *dev);
static void oce_destroy_locks(struct oce_dev *dev);
static void oce_get_params(struct oce_dev *dev);
static int oce_get_prop(struct oce_dev *dev, char *propname, int minval,
    int maxval, int defval, uint32_t *values);

static struct cb_ops oce_cb_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,	/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops oce_dev_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	NULL,		/* devo_getinfo */
	NULL,		/* devo_identify */
	nulldev,	/* devo_probe */
	oce_attach,	/* devo_attach */
	oce_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	&oce_cb_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	nodev,		/* devo_power */
	oce_quiesce	/* devo_quiesce */
};

static struct modldrv oce_drv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	(char *)oce_ident_string, /* Description string */
	&oce_dev_ops,	/* driver ops */
};

static struct modlinkage oce_mod_linkage = {
	MODREV_1, &oce_drv, NULL
};

#define	OCE_M_CB_FLAGS	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP | \
    MC_PROPINFO)
static mac_callbacks_t oce_mac_cb = {
	OCE_M_CB_FLAGS,		/* mc_callbacks */
	oce_m_stat,		/* mc_getstat */
	oce_m_start,		/* mc_start */
	oce_m_stop,		/* mc_stop */
	oce_m_promiscuous,	/* mc_setpromisc */
	oce_m_multicast,	/* mc_multicast */
	oce_m_unicast,		/* mc_unicast */
	oce_m_send,		/* mc_tx */
	NULL,			/* mc_reserve */
	oce_m_ioctl,		/* mc_ioctl */
	oce_m_getcap,		/* mc_getcapab */
	NULL,			/* open */
	NULL,			/* close */
	oce_m_setprop,		/* set properties */
	oce_m_getprop,		/* get properties */
	oce_m_propinfo		/* properties info */
};

extern char *oce_priv_props[];

/* Module Init */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&oce_mod_linkage, modinfop));
} /* _info */

int
_init(void)
{
	int ret = 0;

	/* install the module */
	mac_init_ops(&oce_dev_ops, "oce");

	ret = mod_install(&oce_mod_linkage);
	if (ret) {
		cmn_err(CE_WARN, "mod_install failed  rval=%x", ret);
	}

	return (ret);
} /* _init */


int
_fini(void)
{
	int ret = 0;
	/* remove the module */
	ret = mod_remove(&oce_mod_linkage);
	if (ret != 0) {
		return (ret);
	}

	mac_fini_ops(&oce_dev_ops);

	return (ret);
} /* _fini */


static int
oce_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret = 0;
	struct oce_dev *dev = NULL;
	mac_register_t *mac;
	uint8_t dev_index = 0;

	switch (cmd) {
	case DDI_RESUME:
		return (oce_resume(dip));
	default:
		return (DDI_FAILURE);

	case DDI_ATTACH:
		break;
	}

	/* allocate dev */
	dev = kmem_zalloc(sizeof (struct oce_dev), KM_SLEEP);

	/* populate the dev structure */
	dev->dip = dip;
	dev->dev_id = ddi_get_instance(dip);
	dev->suspended = B_FALSE;

	dev->dev_list_index = MAX_DEVS;
	while (dev_index < MAX_DEVS) {
		(void) atomic_cas_ptr(&oce_dev_list[dev_index], NULL, dev);
		if (oce_dev_list[dev_index] == dev) {
			break;
		}
		dev_index++;
	}
	if (dev_index == MAX_DEVS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Too many oce devices on the system. Failed to attach.");
		goto attach_fail;
	}
	dev->dev_list_index = dev_index;

	/* get the parameters */
	oce_get_params(dev);

	/*
	 * set the ddi driver private data pointer. This is
	 * sent to all mac callback entry points
	 */
	ddi_set_driver_private(dip, dev);

	dev->attach_state |= ATTACH_DEV_INIT;

	oce_fm_init(dev);
	dev->attach_state |= ATTACH_FM_INIT;

	ret = pci_config_setup(dev->dip, &dev->pci_cfg_handle);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Map PCI config failed with  %d", ret);
		goto attach_fail;
	}
	dev->attach_state |= ATTACH_PCI_CFG;

	ret = oce_identify_hw(dev);

	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Device Unknown");
		goto attach_fail;
	}

	ret = oce_get_bdf(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Failed to read BDF, status = 0x%x", ret);
		goto attach_fail;
	}
	/* Update the dev->rss */
	oce_dev_rss_ready(dev);

	/* setup PCI bars */
	ret = oce_pci_init(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "PCI initialization failed with %d", ret);
		goto attach_fail;
	}
	dev->attach_state |= ATTACH_PCI_INIT;

	ret = oce_setup_intr(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "Interrupt setup failed with %d", ret);
		goto attach_fail;

	}
	dev->attach_state |= ATTACH_SETUP_INTR;

	/* initialize locks */
	oce_init_locks(dev);
	dev->attach_state |= ATTACH_LOCK_INIT;


	/* HW init */
	ret = oce_hw_init(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "HW initialization failed with %d", ret);
		goto attach_fail;
	}
	dev->attach_state |= ATTACH_HW_INIT;

	ret = oce_init_txrx(dev);
	if (ret  != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to init rings");
		goto attach_fail;
	}
	dev->attach_state |= ATTACH_SETUP_TXRX;

	ret = oce_setup_adapter(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to setup adapter");
		goto attach_fail;
	}
	dev->attach_state |=  ATTACH_SETUP_ADAP;


	ret = oce_stat_init(dev);
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "kstat setup Failed with %d", ret);
		goto attach_fail;
	}
	dev->attach_state |= ATTACH_STAT_INIT;

	/* mac_register_t */
	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "MAC_VERSION = 0x%x", MAC_VERSION);
	mac = mac_alloc(MAC_VERSION);
	if (mac == NULL) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "MAC allocation Failed");
		goto attach_fail;
	}
	/*
	 * fill the mac structure before calling mac_register
	 */
	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = dev;
	mac->m_dip = dip;
	mac->m_src_addr = dev->mac_addr;
	mac->m_callbacks = &oce_mac_cb;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = dev->mtu;
	mac->m_margin = VTAG_SIZE;
	mac->m_priv_props = oce_priv_props;

	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "Driver Private structure = 0x%p", (void *)dev);

	/* now register with GLDv3 */
	ret = mac_register(mac, (mac_handle_t *)&dev->mac_handle);
	/* regardless of the status, free mac_register */
	mac_free(mac);
	mac = NULL;
	if (ret != DDI_SUCCESS) {
		oce_log(dev, CE_WARN, MOD_CONFIG,
		    "MAC registration failed :0x%x", ret);
		goto attach_fail;

	}

	/* correct link status only after start */
	dev->link_status = LINK_STATE_UNKNOWN;
	mac_link_update(dev->mac_handle, dev->link_status);

	dev->attach_state |= ATTACH_MAC_REG;
	dev->state |= STATE_INIT;

	oce_log(dev, CE_NOTE, MOD_CONFIG, "%s",
	    "ATTACH SUCCESS");

	return (DDI_SUCCESS);

attach_fail:
	oce_unconfigure(dev);
	return (DDI_FAILURE);
} /* oce_attach */

static int
oce_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct oce_dev *dev;
	int pcnt = 0;
	int qid;

	dev = ddi_get_driver_private(dip);
	if (dev == NULL) {
		return (DDI_FAILURE);
	}
	oce_log(dev, CE_NOTE, MOD_CONFIG,
	    "Detaching driver: cmd = 0x%x", cmd);

	switch (cmd) {
	default:
		return (DDI_FAILURE);
	case DDI_SUSPEND:
		return (oce_suspend(dip));
	case DDI_DETACH:
		break;
	} /* switch cmd */

	/* Fail detach if MAC unregister is unsuccessfule */
	if (mac_unregister(dev->mac_handle) != 0) {
		oce_log(dev, CE_WARN, MOD_CONFIG, "%s",
		    "Failed to unregister MAC ");
	}
	dev->attach_state &= ~ATTACH_MAC_REG;

	/* check if the detach is called with out stopping */
	DEV_LOCK(dev);
	if (dev->state & STATE_MAC_STARTED) {
		dev->state &= ~STATE_MAC_STARTED;
		oce_stop(dev);
		DEV_UNLOCK(dev);
	} else
		DEV_UNLOCK(dev);

	/*
	 * Wait for Packets sent up to be freed
	 */
	for (qid = 0; qid < dev->rx_rings; qid++) {
		pcnt = oce_rx_pending(dev, dev->rq[qid], DEFAULT_DRAIN_TIME);
		if (pcnt != 0) {
			oce_log(dev, CE_WARN, MOD_CONFIG,
			    "%d Pending Buffers Detach failed", pcnt);
			return (DDI_FAILURE);
		}
	}
	oce_unconfigure(dev);

	return (DDI_SUCCESS);
} /* oce_detach */

static int
oce_quiesce(dev_info_t *dip)
{
	int ret = DDI_SUCCESS;
	struct oce_dev *dev = ddi_get_driver_private(dip);

	if (dev == NULL) {
		return (DDI_FAILURE);
	}
	if (dev->suspended) {
		return (DDI_SUCCESS);
	}

	oce_chip_di(dev);

	ret = oce_reset_fun(dev);

	return (ret);
}

static int
oce_suspend(dev_info_t *dip)
{
	struct oce_dev *dev = ddi_get_driver_private(dip);

	mutex_enter(&dev->dev_lock);
	/* Suspend the card */
	dev->suspended = B_TRUE;
	/* stop the adapter */
	if (dev->state & STATE_MAC_STARTED) {
		oce_stop(dev);
		oce_unsetup_adapter(dev);
	}
	dev->state &= ~STATE_MAC_STARTED;
	mutex_exit(&dev->dev_lock);
	return (DDI_SUCCESS);
} /* oce_suspend */

static int
oce_resume(dev_info_t *dip)
{
	struct oce_dev *dev;
	int ret;

	/* get the dev pointer from dip */
	dev = ddi_get_driver_private(dip);
	mutex_enter(&dev->dev_lock);
	if (!dev->suspended) {
		mutex_exit(&dev->dev_lock);
		return (DDI_SUCCESS);
	}
	if (!(dev->state & STATE_MAC_STARTED)) {
		ret = oce_setup_adapter(dev);
		if (ret != DDI_SUCCESS) {
			mutex_exit(&dev->dev_lock);
			return (DDI_FAILURE);
		}
		ret = oce_start(dev);
		if (ret != DDI_SUCCESS) {
			mutex_exit(&dev->dev_lock);
			return (DDI_FAILURE);
		}
	}
	dev->suspended = B_FALSE;
	dev->state |= STATE_MAC_STARTED;
	mutex_exit(&dev->dev_lock);
	return (ret);
} /* oce_resume */

static void
oce_init_locks(struct oce_dev *dev)
{
	/* initialize locks */
	mutex_init(&dev->dev_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->intr_pri));
	mutex_init(&dev->bmbx_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(dev->intr_pri));
} /* oce_init_locks */

static void
oce_destroy_locks(struct oce_dev *dev)
{
	mutex_destroy(&dev->dev_lock);
	mutex_destroy(&dev->bmbx_lock);
} /* oce_destroy_locks */

static void
oce_unconfigure(struct oce_dev *dev)
{
	uint32_t state = dev->attach_state;

	if (state & ATTACH_MAC_REG) {
		(void) mac_unregister(dev->mac_handle);
	}
	if (state & ATTACH_STAT_INIT) {
		oce_stat_fini(dev);
	}
	if (state & ATTACH_SETUP_ADAP) {
		oce_unsetup_adapter(dev);
	}
	if (state & ATTACH_SETUP_TXRX) {
		oce_fini_txrx(dev);
	}
	if (state & ATTACH_HW_INIT) {
		oce_hw_fini(dev);
	}
	if (state & ATTACH_LOCK_INIT) {
		oce_destroy_locks(dev);
	}
	if (state & ATTACH_SETUP_INTR) {
		(void) oce_teardown_intr(dev);
	}
	if (state & ATTACH_PCI_INIT) {
		oce_pci_fini(dev);
	}
	if (state & ATTACH_PCI_CFG) {
		pci_config_teardown(&dev->pci_cfg_handle);
	}
	if (state & ATTACH_FM_INIT) {
		oce_fm_fini(dev);
	}
	if (state & ATTACH_DEV_INIT) {
		ddi_set_driver_private(dev->dip, NULL);
		oce_dev_list[dev->dev_list_index] = NULL;
		kmem_free(dev, sizeof (struct oce_dev));
	}
} /* oce_unconfigure */

static void
oce_get_params(struct oce_dev *dev)
{
	uint32_t log_level;
	uint16_t mod_mask;
	uint16_t severity;
	/*
	 * Allowed values for the driver parameters. If all values in a range
	 * is allowed, the the array has only one value.
	 */
	uint32_t fc_values[] = {OCE_FC_NONE, OCE_FC_TX, OCE_FC_RX,
	    OCE_DEFAULT_FLOW_CONTROL, END};
	uint32_t mtu_values[] = {OCE_MIN_MTU, OCE_MAX_MTU, END};
	uint32_t tx_rs_values[] = {SIZE_256, SIZE_512, SIZE_1K, SIZE_2K, END};
	uint32_t tx_bcl_values[] = {SIZE_128, SIZE_256, SIZE_512, SIZE_1K,
	    SIZE_2K, END};
	uint32_t rx_bcl_values[] = {SIZE_128, SIZE_256, SIZE_512, SIZE_1K,
	    SIZE_2K, END};
	uint32_t rq_fs_values[] = {SIZE_2K, SIZE_4K, SIZE_8K, END};
	uint32_t rq_mb_values[] = {SIZE_2K, SIZE_4K, SIZE_8K, END};
	uint32_t lso_capable_values[] = {0, 1, END};
	uint32_t fm_caps_values[] = {DDI_FM_NOT_CAPABLE, OCE_FM_CAPABILITY,
	    END};
	uint32_t tx_rt_values[] = {END};
	uint32_t rx_ppi_values[] = {END};
	uint32_t rx_rings_values[] = {END};
	uint32_t tx_rings_values[] = {END};
	uint32_t log_level_values[] = {END};

	/* non tunables  */
	dev->rx_ring_size = OCE_DEFAULT_RX_RING_SIZE;

	/* configurable parameters */
	dev->flow_control = oce_get_prop(dev, (char *)flow_control, OCE_FC_NONE,
	    OCE_DEFAULT_FLOW_CONTROL, OCE_DEFAULT_FLOW_CONTROL, fc_values);

	dev->mtu = oce_get_prop(dev, (char *)mtu_prop_name, OCE_MIN_MTU,
	    OCE_MAX_MTU, OCE_MIN_MTU, mtu_values);

	dev->tx_ring_size = oce_get_prop(dev, (char *)tx_ring_size_name,
	    SIZE_256, SIZE_2K, OCE_DEFAULT_TX_RING_SIZE, tx_rs_values);

	dev->tx_bcopy_limit = oce_get_prop(dev, (char *)tx_bcopy_limit_name,
	    SIZE_128, SIZE_2K, OCE_DEFAULT_TX_BCOPY_LIMIT, tx_bcl_values);

	dev->rx_bcopy_limit = oce_get_prop(dev, (char *)rx_bcopy_limit_name,
	    SIZE_128, SIZE_2K, OCE_DEFAULT_RX_BCOPY_LIMIT, rx_bcl_values);

	dev->rq_frag_size = oce_get_prop(dev, (char *)rx_frag_size_name,
	    SIZE_2K, SIZE_8K, OCE_RQ_BUF_SIZE, rq_fs_values);

	dev->rq_max_bufs = oce_get_prop(dev, (char *)rx_max_bufs_name, SIZE_2K,
	    SIZE_8K, OCE_RQ_NUM_BUFFERS, rq_mb_values);

	dev->lso_capable = oce_get_prop(dev, (char *)lso_capable_name, 0,
	    1, 1, lso_capable_values);

	dev->fm_caps = oce_get_prop(dev, (char *)fm_cap_name,
	    DDI_FM_NOT_CAPABLE, OCE_FM_CAPABILITY, OCE_FM_CAPABILITY,
	    fm_caps_values);

	dev->tx_reclaim_threshold = oce_get_prop(dev,
	    (char *)tx_reclaim_threshold_name, 0, dev->tx_ring_size/2,
	    OCE_DEFAULT_TX_RECLAIM_THRESHOLD, tx_rt_values);

	dev->rx_pkt_per_intr = oce_get_prop(dev, (char *)rx_pkt_per_intr_name,
	    0, dev->rx_ring_size/2, OCE_DEFAULT_RX_PKT_PER_INTR, rx_ppi_values);

	dev->rx_rings = oce_get_prop(dev, (char *)rx_rings_name,
	    OCE_MIN_RQ, OCE_MAX_RQ, OCE_DEFAULT_RQS, rx_rings_values);

	dev->tx_rings = oce_get_prop(dev, (char *)tx_rings_name,
	    OCE_DEFAULT_WQS, OCE_DEFAULT_WQS, OCE_DEFAULT_WQS, tx_rings_values);

	log_level = oce_get_prop(dev, (char *)log_level_name, 0,
	    OCE_MAX_LOG_SETTINGS, OCE_DEFAULT_LOG_SETTINGS, log_level_values);

	severity = (uint16_t)(log_level & 0xffff);
	mod_mask = (uint16_t)(log_level >> 16);
	if (mod_mask > MOD_ISR) {
		mod_mask = 0;
	}
	if (severity > CE_IGNORE) {
		severity = 0;
	}

	dev->mod_mask = mod_mask;
	dev->severity = severity;
} /* oce_get_params */

static int
oce_get_prop(struct oce_dev *dev, char *propname, int minval, int maxval,
    int defval, uint32_t *values)
{
	int value = 0;
	int i = 0;

	value = ddi_prop_get_int(DDI_DEV_T_ANY, dev->dip,
	    DDI_PROP_DONTPASS, propname, defval);

	if (value > maxval)
		value = maxval;

	if (value < minval)
		value = minval;

	while (values[i] != 0xdeadface) {
		if (values[i] == value) {
			break;
		}
		i++;
	}

	if ((i != 0) && (values[i] == 0xdeadface)) {
		value = defval;
	}

	return (value);
}
