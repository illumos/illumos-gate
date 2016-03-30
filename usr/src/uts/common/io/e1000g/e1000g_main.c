/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_main.c							*
 *									*
 * Abstract:								*
 *   This file contains the interface routines for the solaris OS.	*
 *   It has all DDI entry point routines and GLD entry point routines.	*
 *									*
 *   This file also contains routines that take care of initialization	*
 *   uninit routine and interrupt routine.				*
 *									*
 * **********************************************************************
 */

#include <sys/dlpi.h>
#include <sys/mac.h>
#include "e1000g_sw.h"
#include "e1000g_debug.h"

static char ident[] = "Intel PRO/1000 Ethernet";
/* LINTED E_STATIC_UNUSED */
static char e1000g_version[] = "Driver Ver. 5.3.24";

/*
 * Proto types for DDI entry points
 */
static int e1000g_attach(dev_info_t *, ddi_attach_cmd_t);
static int e1000g_detach(dev_info_t *, ddi_detach_cmd_t);
static int e1000g_quiesce(dev_info_t *);

/*
 * init and intr routines prototype
 */
static int e1000g_resume(dev_info_t *);
static int e1000g_suspend(dev_info_t *);
static uint_t e1000g_intr_pciexpress(caddr_t);
static uint_t e1000g_intr(caddr_t);
static void e1000g_intr_work(struct e1000g *, uint32_t);
#pragma inline(e1000g_intr_work)
static int e1000g_init(struct e1000g *);
static int e1000g_start(struct e1000g *, boolean_t);
static void e1000g_stop(struct e1000g *, boolean_t);
static int e1000g_m_start(void *);
static void e1000g_m_stop(void *);
static int e1000g_m_promisc(void *, boolean_t);
static boolean_t e1000g_m_getcapab(void *, mac_capab_t, void *);
static int e1000g_m_multicst(void *, boolean_t, const uint8_t *);
static void e1000g_m_ioctl(void *, queue_t *, mblk_t *);
static int e1000g_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int e1000g_m_getprop(void *, const char *, mac_prop_id_t,
			    uint_t, void *);
static void e1000g_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int e1000g_set_priv_prop(struct e1000g *, const char *, uint_t,
    const void *);
static int e1000g_get_priv_prop(struct e1000g *, const char *, uint_t, void *);
static void e1000g_init_locks(struct e1000g *);
static void e1000g_destroy_locks(struct e1000g *);
static int e1000g_identify_hardware(struct e1000g *);
static int e1000g_regs_map(struct e1000g *);
static int e1000g_set_driver_params(struct e1000g *);
static void e1000g_set_bufsize(struct e1000g *);
static int e1000g_register_mac(struct e1000g *);
static boolean_t e1000g_rx_drain(struct e1000g *);
static boolean_t e1000g_tx_drain(struct e1000g *);
static void e1000g_init_unicst(struct e1000g *);
static int e1000g_unicst_set(struct e1000g *, const uint8_t *, int);
static int e1000g_alloc_rx_data(struct e1000g *);
static void e1000g_release_multicast(struct e1000g *);
static void e1000g_pch_limits(struct e1000g *);
static uint32_t e1000g_mtu2maxframe(uint32_t);

/*
 * Local routines
 */
static boolean_t e1000g_reset_adapter(struct e1000g *);
static void e1000g_tx_clean(struct e1000g *);
static void e1000g_rx_clean(struct e1000g *);
static void e1000g_link_timer(void *);
static void e1000g_local_timer(void *);
static boolean_t e1000g_link_check(struct e1000g *);
static boolean_t e1000g_stall_check(struct e1000g *);
static void e1000g_smartspeed(struct e1000g *);
static void e1000g_get_conf(struct e1000g *);
static boolean_t e1000g_get_prop(struct e1000g *, char *, int, int, int,
    int *);
static void enable_watchdog_timer(struct e1000g *);
static void disable_watchdog_timer(struct e1000g *);
static void start_watchdog_timer(struct e1000g *);
static void restart_watchdog_timer(struct e1000g *);
static void stop_watchdog_timer(struct e1000g *);
static void stop_link_timer(struct e1000g *);
static void stop_82547_timer(e1000g_tx_ring_t *);
static void e1000g_force_speed_duplex(struct e1000g *);
static void e1000g_setup_max_mtu(struct e1000g *);
static void e1000g_get_max_frame_size(struct e1000g *);
static boolean_t is_valid_mac_addr(uint8_t *);
static void e1000g_unattach(dev_info_t *, struct e1000g *);
static int e1000g_get_bar_info(dev_info_t *, int, bar_info_t *);
#ifdef E1000G_DEBUG
static void e1000g_ioc_peek_reg(struct e1000g *, e1000g_peekpoke_t *);
static void e1000g_ioc_poke_reg(struct e1000g *, e1000g_peekpoke_t *);
static void e1000g_ioc_peek_mem(struct e1000g *, e1000g_peekpoke_t *);
static void e1000g_ioc_poke_mem(struct e1000g *, e1000g_peekpoke_t *);
static enum ioc_reply e1000g_pp_ioctl(struct e1000g *,
    struct iocblk *, mblk_t *);
#endif
static enum ioc_reply e1000g_loopback_ioctl(struct e1000g *,
    struct iocblk *, mblk_t *);
static boolean_t e1000g_check_loopback_support(struct e1000_hw *);
static boolean_t e1000g_set_loopback_mode(struct e1000g *, uint32_t);
static void e1000g_set_internal_loopback(struct e1000g *);
static void e1000g_set_external_loopback_1000(struct e1000g *);
static void e1000g_set_external_loopback_100(struct e1000g *);
static void e1000g_set_external_loopback_10(struct e1000g *);
static int e1000g_add_intrs(struct e1000g *);
static int e1000g_intr_add(struct e1000g *, int);
static int e1000g_rem_intrs(struct e1000g *);
static int e1000g_enable_intrs(struct e1000g *);
static int e1000g_disable_intrs(struct e1000g *);
static boolean_t e1000g_link_up(struct e1000g *);
#ifdef __sparc
static boolean_t e1000g_find_mac_address(struct e1000g *);
#endif
static void e1000g_get_phy_state(struct e1000g *);
static int e1000g_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data);
static void e1000g_fm_init(struct e1000g *Adapter);
static void e1000g_fm_fini(struct e1000g *Adapter);
static void e1000g_param_sync(struct e1000g *);
static void e1000g_get_driver_control(struct e1000_hw *);
static void e1000g_release_driver_control(struct e1000_hw *);
static void e1000g_restore_promisc(struct e1000g *Adapter);

char *e1000g_priv_props[] = {
	"_tx_bcopy_threshold",
	"_tx_interrupt_enable",
	"_tx_intr_delay",
	"_tx_intr_abs_delay",
	"_rx_bcopy_threshold",
	"_max_num_rcv_packets",
	"_rx_intr_delay",
	"_rx_intr_abs_delay",
	"_intr_throttling_rate",
	"_intr_adaptive",
	"_adv_pause_cap",
	"_adv_asym_pause_cap",
	NULL
};

static struct cb_ops cb_ws_ops = {
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
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops ws_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	e1000g_attach,		/* devo_attach */
	e1000g_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_ws_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power,		/* devo_power */
	e1000g_quiesce		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	ident,			/* Discription string */
	&ws_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/* Access attributes for register mapping */
static ddi_device_acc_attr_t e1000g_regs_acc_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

#define	E1000G_M_CALLBACK_FLAGS \
	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO)

static mac_callbacks_t e1000g_m_callbacks = {
	E1000G_M_CALLBACK_FLAGS,
	e1000g_m_stat,
	e1000g_m_start,
	e1000g_m_stop,
	e1000g_m_promisc,
	e1000g_m_multicst,
	NULL,
	e1000g_m_tx,
	NULL,
	e1000g_m_ioctl,
	e1000g_m_getcapab,
	NULL,
	NULL,
	e1000g_m_setprop,
	e1000g_m_getprop,
	e1000g_m_propinfo
};

/*
 * Global variables
 */
uint32_t e1000g_jumbo_mtu = MAXIMUM_MTU_9K;
uint32_t e1000g_mblks_pending = 0;
/*
 * Workaround for Dynamic Reconfiguration support, for x86 platform only.
 * Here we maintain a private dev_info list if e1000g_force_detach is
 * enabled. If we force the driver to detach while there are still some
 * rx buffers retained in the upper layer, we have to keep a copy of the
 * dev_info. In some cases (Dynamic Reconfiguration), the dev_info data
 * structure will be freed after the driver is detached. However when we
 * finally free those rx buffers released by the upper layer, we need to
 * refer to the dev_info to free the dma buffers. So we save a copy of
 * the dev_info for this purpose. On x86 platform, we assume this copy
 * of dev_info is always valid, but on SPARC platform, it could be invalid
 * after the system board level DR operation. For this reason, the global
 * variable e1000g_force_detach must be B_FALSE on SPARC platform.
 */
#ifdef __sparc
boolean_t e1000g_force_detach = B_FALSE;
#else
boolean_t e1000g_force_detach = B_TRUE;
#endif
private_devi_list_t *e1000g_private_devi_list = NULL;

/*
 * The mutex e1000g_rx_detach_lock is defined to protect the processing of
 * the private dev_info list, and to serialize the processing of rx buffer
 * freeing and rx buffer recycling.
 */
kmutex_t e1000g_rx_detach_lock;
/*
 * The rwlock e1000g_dma_type_lock is defined to protect the global flag
 * e1000g_dma_type. For SPARC, the initial value of the flag is "USE_DVMA".
 * If there are many e1000g instances, the system may run out of DVMA
 * resources during the initialization of the instances, then the flag will
 * be changed to "USE_DMA". Because different e1000g instances are initialized
 * in parallel, we need to use this lock to protect the flag.
 */
krwlock_t e1000g_dma_type_lock;

/*
 * The 82546 chipset is a dual-port device, both the ports share one eeprom.
 * Based on the information from Intel, the 82546 chipset has some hardware
 * problem. When one port is being reset and the other port is trying to
 * access the eeprom, it could cause system hang or panic. To workaround this
 * hardware problem, we use a global mutex to prevent such operations from
 * happening simultaneously on different instances. This workaround is applied
 * to all the devices supported by this driver.
 */
kmutex_t e1000g_nvm_lock;

/*
 * Loadable module configuration entry points for the driver
 */

/*
 * _init - module initialization
 */
int
_init(void)
{
	int status;

	mac_init_ops(&ws_ops, WSNAME);
	status = mod_install(&modlinkage);
	if (status != DDI_SUCCESS)
		mac_fini_ops(&ws_ops);
	else {
		mutex_init(&e1000g_rx_detach_lock, NULL, MUTEX_DRIVER, NULL);
		rw_init(&e1000g_dma_type_lock, NULL, RW_DRIVER, NULL);
		mutex_init(&e1000g_nvm_lock, NULL, MUTEX_DRIVER, NULL);
	}

	return (status);
}

/*
 * _fini - module finalization
 */
int
_fini(void)
{
	int status;

	if (e1000g_mblks_pending != 0)
		return (EBUSY);

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&ws_ops);

		if (e1000g_force_detach) {
			private_devi_list_t *devi_node;

			mutex_enter(&e1000g_rx_detach_lock);
			while (e1000g_private_devi_list != NULL) {
				devi_node = e1000g_private_devi_list;
				e1000g_private_devi_list =
				    e1000g_private_devi_list->next;

				kmem_free(devi_node->priv_dip,
				    sizeof (struct dev_info));
				kmem_free(devi_node,
				    sizeof (private_devi_list_t));
			}
			mutex_exit(&e1000g_rx_detach_lock);
		}

		mutex_destroy(&e1000g_rx_detach_lock);
		rw_destroy(&e1000g_dma_type_lock);
		mutex_destroy(&e1000g_nvm_lock);
	}

	return (status);
}

/*
 * _info - module information
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * e1000g_attach - driver attach
 *
 * This function is the device-specific initialization entry
 * point. This entry point is required and must be written.
 * The DDI_ATTACH command must be provided in the attach entry
 * point. When attach() is called with cmd set to DDI_ATTACH,
 * all normal kernel services (such as kmem_alloc(9F)) are
 * available for use by the driver.
 *
 * The attach() function will be called once for each instance
 * of  the  device  on  the  system with cmd set to DDI_ATTACH.
 * Until attach() succeeds, the only driver entry points which
 * may be called are open(9E) and getinfo(9E).
 */
static int
e1000g_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;
	struct e1000g_osdep *osdep;
	int instance;

	switch (cmd) {
	default:
		e1000g_log(NULL, CE_WARN,
		    "Unsupported command send to e1000g_attach... ");
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (e1000g_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	/*
	 * get device instance number
	 */
	instance = ddi_get_instance(devinfo);

	/*
	 * Allocate soft data structure
	 */
	Adapter =
	    (struct e1000g *)kmem_zalloc(sizeof (*Adapter), KM_SLEEP);

	Adapter->dip = devinfo;
	Adapter->instance = instance;
	Adapter->tx_ring->adapter = Adapter;
	Adapter->rx_ring->adapter = Adapter;

	hw = &Adapter->shared;
	osdep = &Adapter->osdep;
	hw->back = osdep;
	osdep->adapter = Adapter;

	ddi_set_driver_private(devinfo, (caddr_t)Adapter);

	/*
	 * Initialize for fma support
	 */
	(void) e1000g_get_prop(Adapter, "fm-capable",
	    0, 0x0f,
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE,
	    &Adapter->fm_capabilities);
	e1000g_fm_init(Adapter);
	Adapter->attach_progress |= ATTACH_PROGRESS_FMINIT;

	/*
	 * PCI Configure
	 */
	if (pci_config_setup(devinfo, &osdep->cfg_handle) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "PCI configuration failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_PCI_CONFIG;

	/*
	 * Setup hardware
	 */
	if (e1000g_identify_hardware(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Identify hardware failed");
		goto attach_fail;
	}

	/*
	 * Map in the device registers.
	 */
	if (e1000g_regs_map(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Mapping registers failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_REGS_MAP;

	/*
	 * Initialize driver parameters
	 */
	if (e1000g_set_driver_params(Adapter) != DDI_SUCCESS) {
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_SETUP;

	if (e1000g_check_acc_handle(Adapter->osdep.cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);
		goto attach_fail;
	}

	/*
	 * Disable ULP support
	 */
	(void) e1000_disable_ulp_lpt_lp(hw, TRUE);

	/*
	 * Initialize interrupts
	 */
	if (e1000g_add_intrs(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Add interrupts failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_ADD_INTR;

	/*
	 * Initialize mutex's for this device.
	 * Do this before enabling the interrupt handler and
	 * register the softint to avoid the condition where
	 * interrupt handler can try using uninitialized mutex
	 */
	e1000g_init_locks(Adapter);
	Adapter->attach_progress |= ATTACH_PROGRESS_LOCKS;

	/*
	 * Initialize Driver Counters
	 */
	if (e1000g_init_stats(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Init stats failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_KSTATS;

	/*
	 * Initialize chip hardware and software structures
	 */
	rw_enter(&Adapter->chip_lock, RW_WRITER);
	if (e1000g_init(Adapter) != DDI_SUCCESS) {
		rw_exit(&Adapter->chip_lock);
		e1000g_log(Adapter, CE_WARN, "Adapter initialization failed");
		goto attach_fail;
	}
	rw_exit(&Adapter->chip_lock);
	Adapter->attach_progress |= ATTACH_PROGRESS_INIT;

	/*
	 * Register the driver to the MAC
	 */
	if (e1000g_register_mac(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Register MAC failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_MAC;

	/*
	 * Now that mutex locks are initialized, and the chip is also
	 * initialized, enable interrupts.
	 */
	if (e1000g_enable_intrs(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Enable DDI interrupts failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_ENABLE_INTR;

	/*
	 * If e1000g_force_detach is enabled, in global private dip list,
	 * we will create a new entry, which maintains the priv_dip for DR
	 * supports after driver detached.
	 */
	if (e1000g_force_detach) {
		private_devi_list_t *devi_node;

		Adapter->priv_dip =
		    kmem_zalloc(sizeof (struct dev_info), KM_SLEEP);
		bcopy(DEVI(devinfo), DEVI(Adapter->priv_dip),
		    sizeof (struct dev_info));

		devi_node =
		    kmem_zalloc(sizeof (private_devi_list_t), KM_SLEEP);

		mutex_enter(&e1000g_rx_detach_lock);
		devi_node->priv_dip = Adapter->priv_dip;
		devi_node->flag = E1000G_PRIV_DEVI_ATTACH;
		devi_node->pending_rx_count = 0;

		Adapter->priv_devi_node = devi_node;

		if (e1000g_private_devi_list == NULL) {
			devi_node->prev = NULL;
			devi_node->next = NULL;
			e1000g_private_devi_list = devi_node;
		} else {
			devi_node->prev = NULL;
			devi_node->next = e1000g_private_devi_list;
			e1000g_private_devi_list->prev = devi_node;
			e1000g_private_devi_list = devi_node;
		}
		mutex_exit(&e1000g_rx_detach_lock);
	}

	Adapter->e1000g_state = E1000G_INITIALIZED;
	return (DDI_SUCCESS);

attach_fail:
	e1000g_unattach(devinfo, Adapter);
	return (DDI_FAILURE);
}

static int
e1000g_register_mac(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	mac_register_t *mac;
	int err;

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (DDI_FAILURE);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = Adapter;
	mac->m_dip = Adapter->dip;
	mac->m_src_addr = hw->mac.addr;
	mac->m_callbacks = &e1000g_m_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = Adapter->default_mtu;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_priv_props = e1000g_priv_props;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	err = mac_register(mac, &Adapter->mh);
	mac_free(mac);

	return (err == 0 ? DDI_SUCCESS : DDI_FAILURE);
}

static int
e1000g_identify_hardware(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	struct e1000g_osdep *osdep = &Adapter->osdep;

	/* Get the device id */
	hw->vendor_id =
	    pci_config_get16(osdep->cfg_handle, PCI_CONF_VENID);
	hw->device_id =
	    pci_config_get16(osdep->cfg_handle, PCI_CONF_DEVID);
	hw->revision_id =
	    pci_config_get8(osdep->cfg_handle, PCI_CONF_REVID);
	hw->subsystem_device_id =
	    pci_config_get16(osdep->cfg_handle, PCI_CONF_SUBSYSID);
	hw->subsystem_vendor_id =
	    pci_config_get16(osdep->cfg_handle, PCI_CONF_SUBVENID);

	if (e1000_set_mac_type(hw) != E1000_SUCCESS) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
		    "MAC type could not be set properly.");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
e1000g_regs_map(struct e1000g *Adapter)
{
	dev_info_t *devinfo = Adapter->dip;
	struct e1000_hw *hw = &Adapter->shared;
	struct e1000g_osdep *osdep = &Adapter->osdep;
	off_t mem_size;
	bar_info_t bar_info;
	int offset, rnumber;

	rnumber = ADAPTER_REG_SET;
	/* Get size of adapter register memory */
	if (ddi_dev_regsize(devinfo, rnumber, &mem_size) !=
	    DDI_SUCCESS) {
		E1000G_DEBUGLOG_0(Adapter, CE_WARN,
		    "ddi_dev_regsize for registers failed");
		return (DDI_FAILURE);
	}

	/* Map adapter register memory */
	if ((ddi_regs_map_setup(devinfo, rnumber,
	    (caddr_t *)&hw->hw_addr, 0, mem_size, &e1000g_regs_acc_attr,
	    &osdep->reg_handle)) != DDI_SUCCESS) {
		E1000G_DEBUGLOG_0(Adapter, CE_WARN,
		    "ddi_regs_map_setup for registers failed");
		goto regs_map_fail;
	}

	/* ICH needs to map flash memory */
	switch (hw->mac.type) {
	case e1000_ich8lan:
	case e1000_ich9lan:
	case e1000_ich10lan:
	case e1000_pchlan:
	case e1000_pch2lan:
	case e1000_pch_lpt:
		rnumber = ICH_FLASH_REG_SET;

		/* get flash size */
		if (ddi_dev_regsize(devinfo, rnumber,
		    &mem_size) != DDI_SUCCESS) {
			E1000G_DEBUGLOG_0(Adapter, CE_WARN,
			    "ddi_dev_regsize for ICH flash failed");
			goto regs_map_fail;
		}

		/* map flash in */
		if (ddi_regs_map_setup(devinfo, rnumber,
		    (caddr_t *)&hw->flash_address, 0,
		    mem_size, &e1000g_regs_acc_attr,
		    &osdep->ich_flash_handle) != DDI_SUCCESS) {
			E1000G_DEBUGLOG_0(Adapter, CE_WARN,
			    "ddi_regs_map_setup for ICH flash failed");
			goto regs_map_fail;
		}
		break;
	case e1000_pch_spt:
		/*
		 * On the SPT, the device flash is actually in BAR0, not a
		 * separate BAR. Therefore we end up setting the
		 * ich_flash_handle to be the same as the register handle.
		 * We mark the same to reduce the confusion in the other
		 * functions and macros. Though this does make the set up and
		 * tear-down path slightly more complicated.
		 */
		osdep->ich_flash_handle = osdep->reg_handle;
		hw->flash_address = hw->hw_addr;
	default:
		break;
	}

	/* map io space */
	switch (hw->mac.type) {
	case e1000_82544:
	case e1000_82540:
	case e1000_82545:
	case e1000_82546:
	case e1000_82541:
	case e1000_82541_rev_2:
		/* find the IO bar */
		rnumber = -1;
		for (offset = PCI_CONF_BASE1;
		    offset <= PCI_CONF_BASE5; offset += 4) {
			if (e1000g_get_bar_info(devinfo, offset, &bar_info)
			    != DDI_SUCCESS)
				continue;
			if (bar_info.type == E1000G_BAR_IO) {
				rnumber = bar_info.rnumber;
				break;
			}
		}

		if (rnumber < 0) {
			E1000G_DEBUGLOG_0(Adapter, CE_WARN,
			    "No io space is found");
			goto regs_map_fail;
		}

		/* get io space size */
		if (ddi_dev_regsize(devinfo, rnumber,
		    &mem_size) != DDI_SUCCESS) {
			E1000G_DEBUGLOG_0(Adapter, CE_WARN,
			    "ddi_dev_regsize for io space failed");
			goto regs_map_fail;
		}

		/* map io space */
		if ((ddi_regs_map_setup(devinfo, rnumber,
		    (caddr_t *)&hw->io_base, 0, mem_size,
		    &e1000g_regs_acc_attr,
		    &osdep->io_reg_handle)) != DDI_SUCCESS) {
			E1000G_DEBUGLOG_0(Adapter, CE_WARN,
			    "ddi_regs_map_setup for io space failed");
			goto regs_map_fail;
		}
		break;
	default:
		hw->io_base = 0;
		break;
	}

	return (DDI_SUCCESS);

regs_map_fail:
	if (osdep->reg_handle != NULL)
		ddi_regs_map_free(&osdep->reg_handle);
	if (osdep->ich_flash_handle != NULL && hw->mac.type != e1000_pch_spt)
		ddi_regs_map_free(&osdep->ich_flash_handle);
	return (DDI_FAILURE);
}

static int
e1000g_set_driver_params(struct e1000g *Adapter)
{
	struct e1000_hw *hw;

	hw = &Adapter->shared;

	/* Set MAC type and initialize hardware functions */
	if (e1000_setup_init_funcs(hw, B_TRUE) != E1000_SUCCESS) {
		E1000G_DEBUGLOG_0(Adapter, CE_WARN,
		    "Could not setup hardware functions");
		return (DDI_FAILURE);
	}

	/* Get bus information */
	if (e1000_get_bus_info(hw) != E1000_SUCCESS) {
		E1000G_DEBUGLOG_0(Adapter, CE_WARN,
		    "Could not get bus information");
		return (DDI_FAILURE);
	}

	e1000_read_pci_cfg(hw, PCI_COMMAND_REGISTER, &hw->bus.pci_cmd_word);

	hw->mac.autoneg_failed = B_TRUE;

	/* Set the autoneg_wait_to_complete flag to B_FALSE */
	hw->phy.autoneg_wait_to_complete = B_FALSE;

	/* Adaptive IFS related changes */
	hw->mac.adaptive_ifs = B_TRUE;

	/* Enable phy init script for IGP phy of 82541/82547 */
	if ((hw->mac.type == e1000_82547) ||
	    (hw->mac.type == e1000_82541) ||
	    (hw->mac.type == e1000_82547_rev_2) ||
	    (hw->mac.type == e1000_82541_rev_2))
		e1000_init_script_state_82541(hw, B_TRUE);

	/* Enable the TTL workaround for 82541/82547 */
	e1000_set_ttl_workaround_state_82541(hw, B_TRUE);

#ifdef __sparc
	Adapter->strip_crc = B_TRUE;
#else
	Adapter->strip_crc = B_FALSE;
#endif

	/* setup the maximum MTU size of the chip */
	e1000g_setup_max_mtu(Adapter);

	/* Get speed/duplex settings in conf file */
	hw->mac.forced_speed_duplex = ADVERTISE_100_FULL;
	hw->phy.autoneg_advertised = AUTONEG_ADVERTISE_SPEED_DEFAULT;
	e1000g_force_speed_duplex(Adapter);

	/* Get Jumbo Frames settings in conf file */
	e1000g_get_max_frame_size(Adapter);

	/* Get conf file properties */
	e1000g_get_conf(Adapter);

	/* enforce PCH limits */
	e1000g_pch_limits(Adapter);

	/* Set Rx/Tx buffer size */
	e1000g_set_bufsize(Adapter);

	/* Master Latency Timer */
	Adapter->master_latency_timer = DEFAULT_MASTER_LATENCY_TIMER;

	/* copper options */
	if (hw->phy.media_type == e1000_media_type_copper) {
		hw->phy.mdix = 0;	/* AUTO_ALL_MODES */
		hw->phy.disable_polarity_correction = B_FALSE;
		hw->phy.ms_type = e1000_ms_hw_default;	/* E1000_MASTER_SLAVE */
	}

	/* The initial link state should be "unknown" */
	Adapter->link_state = LINK_STATE_UNKNOWN;

	/* Initialize rx parameters */
	Adapter->rx_intr_delay = DEFAULT_RX_INTR_DELAY;
	Adapter->rx_intr_abs_delay = DEFAULT_RX_INTR_ABS_DELAY;

	/* Initialize tx parameters */
	Adapter->tx_intr_enable = DEFAULT_TX_INTR_ENABLE;
	Adapter->tx_bcopy_thresh = DEFAULT_TX_BCOPY_THRESHOLD;
	Adapter->tx_intr_delay = DEFAULT_TX_INTR_DELAY;
	Adapter->tx_intr_abs_delay = DEFAULT_TX_INTR_ABS_DELAY;

	/* Initialize rx parameters */
	Adapter->rx_bcopy_thresh = DEFAULT_RX_BCOPY_THRESHOLD;

	return (DDI_SUCCESS);
}

static void
e1000g_setup_max_mtu(struct e1000g *Adapter)
{
	struct e1000_mac_info *mac = &Adapter->shared.mac;
	struct e1000_phy_info *phy = &Adapter->shared.phy;

	switch (mac->type) {
	/* types that do not support jumbo frames */
	case e1000_ich8lan:
	case e1000_82573:
	case e1000_82583:
		Adapter->max_mtu = ETHERMTU;
		break;
	/* ich9 supports jumbo frames except on one phy type */
	case e1000_ich9lan:
		if (phy->type == e1000_phy_ife)
			Adapter->max_mtu = ETHERMTU;
		else
			Adapter->max_mtu = MAXIMUM_MTU_9K;
		break;
	/* pch can do jumbo frames up to 4K */
	case e1000_pchlan:
		Adapter->max_mtu = MAXIMUM_MTU_4K;
		break;
	/* pch2 can do jumbo frames up to 9K */
	case e1000_pch2lan:
	case e1000_pch_lpt:
	case e1000_pch_spt:
		Adapter->max_mtu = MAXIMUM_MTU_9K;
		break;
	/* types with a special limit */
	case e1000_82571:
	case e1000_82572:
	case e1000_82574:
	case e1000_80003es2lan:
	case e1000_ich10lan:
		if (e1000g_jumbo_mtu >= ETHERMTU &&
		    e1000g_jumbo_mtu <= MAXIMUM_MTU_9K) {
			Adapter->max_mtu = e1000g_jumbo_mtu;
		} else {
			Adapter->max_mtu = MAXIMUM_MTU_9K;
		}
		break;
	/* default limit is 16K */
	default:
		Adapter->max_mtu = FRAME_SIZE_UPTO_16K -
		    sizeof (struct ether_vlan_header) - ETHERFCSL;
		break;
	}
}

static void
e1000g_set_bufsize(struct e1000g *Adapter)
{
	struct e1000_mac_info *mac = &Adapter->shared.mac;
	uint64_t rx_size;
	uint64_t tx_size;

	dev_info_t *devinfo = Adapter->dip;
#ifdef __sparc
	ulong_t iommu_pagesize;
#endif
	/* Get the system page size */
	Adapter->sys_page_sz = ddi_ptob(devinfo, (ulong_t)1);

#ifdef __sparc
	iommu_pagesize = dvma_pagesize(devinfo);
	if (iommu_pagesize != 0) {
		if (Adapter->sys_page_sz == iommu_pagesize) {
			if (iommu_pagesize > 0x4000)
				Adapter->sys_page_sz = 0x4000;
		} else {
			if (Adapter->sys_page_sz > iommu_pagesize)
				Adapter->sys_page_sz = iommu_pagesize;
		}
	}
	if (Adapter->lso_enable) {
		Adapter->dvma_page_num = E1000_LSO_MAXLEN /
		    Adapter->sys_page_sz + E1000G_DEFAULT_DVMA_PAGE_NUM;
	} else {
		Adapter->dvma_page_num = Adapter->max_frame_size /
		    Adapter->sys_page_sz + E1000G_DEFAULT_DVMA_PAGE_NUM;
	}
	ASSERT(Adapter->dvma_page_num >= E1000G_DEFAULT_DVMA_PAGE_NUM);
#endif

	Adapter->min_frame_size = ETHERMIN + ETHERFCSL;

	if (Adapter->mem_workaround_82546 &&
	    ((mac->type == e1000_82545) ||
	    (mac->type == e1000_82546) ||
	    (mac->type == e1000_82546_rev_3))) {
		Adapter->rx_buffer_size = E1000_RX_BUFFER_SIZE_2K;
	} else {
		rx_size = Adapter->max_frame_size;
		if ((rx_size > FRAME_SIZE_UPTO_2K) &&
		    (rx_size <= FRAME_SIZE_UPTO_4K))
			Adapter->rx_buffer_size = E1000_RX_BUFFER_SIZE_4K;
		else if ((rx_size > FRAME_SIZE_UPTO_4K) &&
		    (rx_size <= FRAME_SIZE_UPTO_8K))
			Adapter->rx_buffer_size = E1000_RX_BUFFER_SIZE_8K;
		else if ((rx_size > FRAME_SIZE_UPTO_8K) &&
		    (rx_size <= FRAME_SIZE_UPTO_16K))
			Adapter->rx_buffer_size = E1000_RX_BUFFER_SIZE_16K;
		else
			Adapter->rx_buffer_size = E1000_RX_BUFFER_SIZE_2K;
	}
	Adapter->rx_buffer_size += E1000G_IPALIGNROOM;

	tx_size = Adapter->max_frame_size;
	if ((tx_size > FRAME_SIZE_UPTO_2K) && (tx_size <= FRAME_SIZE_UPTO_4K))
		Adapter->tx_buffer_size = E1000_TX_BUFFER_SIZE_4K;
	else if ((tx_size > FRAME_SIZE_UPTO_4K) &&
	    (tx_size <= FRAME_SIZE_UPTO_8K))
		Adapter->tx_buffer_size = E1000_TX_BUFFER_SIZE_8K;
	else if ((tx_size > FRAME_SIZE_UPTO_8K) &&
	    (tx_size <= FRAME_SIZE_UPTO_16K))
		Adapter->tx_buffer_size = E1000_TX_BUFFER_SIZE_16K;
	else
		Adapter->tx_buffer_size = E1000_TX_BUFFER_SIZE_2K;

	/*
	 * For Wiseman adapters we have an requirement of having receive
	 * buffers aligned at 256 byte boundary. Since Livengood does not
	 * require this and forcing it for all hardwares will have
	 * performance implications, I am making it applicable only for
	 * Wiseman and for Jumbo frames enabled mode as rest of the time,
	 * it is okay to have normal frames...but it does involve a
	 * potential risk where we may loose data if buffer is not
	 * aligned...so all wiseman boards to have 256 byte aligned
	 * buffers
	 */
	if (mac->type < e1000_82543)
		Adapter->rx_buf_align = RECEIVE_BUFFER_ALIGN_SIZE;
	else
		Adapter->rx_buf_align = 1;
}

/*
 * e1000g_detach - driver detach
 *
 * The detach() function is the complement of the attach routine.
 * If cmd is set to DDI_DETACH, detach() is used to remove  the
 * state  associated  with  a  given  instance of a device node
 * prior to the removal of that instance from the system.
 *
 * The detach() function will be called once for each  instance
 * of the device for which there has been a successful attach()
 * once there are no longer  any  opens  on  the  device.
 *
 * Interrupts routine are disabled, All memory allocated by this
 * driver are freed.
 */
static int
e1000g_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct e1000g *Adapter;
	boolean_t rx_drain;

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (e1000g_suspend(devinfo));

	case DDI_DETACH:
		break;
	}

	Adapter = (struct e1000g *)ddi_get_driver_private(devinfo);
	if (Adapter == NULL)
		return (DDI_FAILURE);

	rx_drain = e1000g_rx_drain(Adapter);
	if (!rx_drain && !e1000g_force_detach)
		return (DDI_FAILURE);

	if (mac_unregister(Adapter->mh) != 0) {
		e1000g_log(Adapter, CE_WARN, "Unregister MAC failed");
		return (DDI_FAILURE);
	}
	Adapter->attach_progress &= ~ATTACH_PROGRESS_MAC;

	ASSERT(!(Adapter->e1000g_state & E1000G_STARTED));

	if (!e1000g_force_detach && !rx_drain)
		return (DDI_FAILURE);

	e1000g_unattach(devinfo, Adapter);

	return (DDI_SUCCESS);
}

/*
 * e1000g_free_priv_devi_node - free a priv_dip entry for driver instance
 */
void
e1000g_free_priv_devi_node(private_devi_list_t *devi_node)
{
	ASSERT(e1000g_private_devi_list != NULL);
	ASSERT(devi_node != NULL);

	if (devi_node->prev != NULL)
		devi_node->prev->next = devi_node->next;
	if (devi_node->next != NULL)
		devi_node->next->prev = devi_node->prev;
	if (devi_node == e1000g_private_devi_list)
		e1000g_private_devi_list = devi_node->next;

	kmem_free(devi_node->priv_dip,
	    sizeof (struct dev_info));
	kmem_free(devi_node,
	    sizeof (private_devi_list_t));
}

static void
e1000g_unattach(dev_info_t *devinfo, struct e1000g *Adapter)
{
	private_devi_list_t *devi_node;
	int result;

	if (Adapter->attach_progress & ATTACH_PROGRESS_ENABLE_INTR) {
		(void) e1000g_disable_intrs(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_MAC) {
		(void) mac_unregister(Adapter->mh);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_ADD_INTR) {
		(void) e1000g_rem_intrs(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_SETUP) {
		(void) ddi_prop_remove_all(devinfo);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_KSTATS) {
		kstat_delete((kstat_t *)Adapter->e1000g_ksp);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_INIT) {
		stop_link_timer(Adapter);

		mutex_enter(&e1000g_nvm_lock);
		result = e1000_reset_hw(&Adapter->shared);
		mutex_exit(&e1000g_nvm_lock);

		if (result != E1000_SUCCESS) {
			e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
			ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);
		}
	}

	e1000g_release_multicast(Adapter);

	if (Adapter->attach_progress & ATTACH_PROGRESS_REGS_MAP) {
		if (Adapter->osdep.reg_handle != NULL)
			ddi_regs_map_free(&Adapter->osdep.reg_handle);
		if (Adapter->osdep.ich_flash_handle != NULL &&
		    Adapter->shared.mac.type != e1000_pch_spt)
			ddi_regs_map_free(&Adapter->osdep.ich_flash_handle);
		if (Adapter->osdep.io_reg_handle != NULL)
			ddi_regs_map_free(&Adapter->osdep.io_reg_handle);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_PCI_CONFIG) {
		if (Adapter->osdep.cfg_handle != NULL)
			pci_config_teardown(&Adapter->osdep.cfg_handle);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_LOCKS) {
		e1000g_destroy_locks(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_FMINIT) {
		e1000g_fm_fini(Adapter);
	}

	mutex_enter(&e1000g_rx_detach_lock);
	if (e1000g_force_detach && (Adapter->priv_devi_node != NULL)) {
		devi_node = Adapter->priv_devi_node;
		devi_node->flag |= E1000G_PRIV_DEVI_DETACH;

		if (devi_node->pending_rx_count == 0) {
			e1000g_free_priv_devi_node(devi_node);
		}
	}
	mutex_exit(&e1000g_rx_detach_lock);

	kmem_free((caddr_t)Adapter, sizeof (struct e1000g));

	/*
	 * Another hotplug spec requirement,
	 * run ddi_set_driver_private(devinfo, null);
	 */
	ddi_set_driver_private(devinfo, NULL);
}

/*
 * Get the BAR type and rnumber for a given PCI BAR offset
 */
static int
e1000g_get_bar_info(dev_info_t *dip, int bar_offset, bar_info_t *bar_info)
{
	pci_regspec_t *regs;
	uint_t regs_length;
	int type, rnumber, rcount;

	ASSERT((bar_offset >= PCI_CONF_BASE0) &&
	    (bar_offset <= PCI_CONF_BASE5));

	/*
	 * Get the DDI "reg" property
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&regs,
	    &regs_length) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	rcount = regs_length * sizeof (int) / sizeof (pci_regspec_t);
	/*
	 * Check the BAR offset
	 */
	for (rnumber = 0; rnumber < rcount; ++rnumber) {
		if (PCI_REG_REG_G(regs[rnumber].pci_phys_hi) == bar_offset) {
			type = regs[rnumber].pci_phys_hi & PCI_ADDR_MASK;
			break;
		}
	}

	ddi_prop_free(regs);

	if (rnumber >= rcount)
		return (DDI_FAILURE);

	switch (type) {
	case PCI_ADDR_CONFIG:
		bar_info->type = E1000G_BAR_CONFIG;
		break;
	case PCI_ADDR_IO:
		bar_info->type = E1000G_BAR_IO;
		break;
	case PCI_ADDR_MEM32:
		bar_info->type = E1000G_BAR_MEM32;
		break;
	case PCI_ADDR_MEM64:
		bar_info->type = E1000G_BAR_MEM64;
		break;
	default:
		return (DDI_FAILURE);
	}
	bar_info->rnumber = rnumber;
	return (DDI_SUCCESS);
}

static void
e1000g_init_locks(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	rw_init(&Adapter->chip_lock, NULL,
	    RW_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&Adapter->link_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&Adapter->watchdog_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));

	tx_ring = Adapter->tx_ring;

	mutex_init(&tx_ring->tx_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&tx_ring->usedlist_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&tx_ring->freelist_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));

	rx_ring = Adapter->rx_ring;

	mutex_init(&rx_ring->rx_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
}

static void
e1000g_destroy_locks(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	tx_ring = Adapter->tx_ring;
	mutex_destroy(&tx_ring->tx_lock);
	mutex_destroy(&tx_ring->usedlist_lock);
	mutex_destroy(&tx_ring->freelist_lock);

	rx_ring = Adapter->rx_ring;
	mutex_destroy(&rx_ring->rx_lock);

	mutex_destroy(&Adapter->link_lock);
	mutex_destroy(&Adapter->watchdog_lock);
	rw_destroy(&Adapter->chip_lock);

	/* destory mutex initialized in shared code */
	e1000_destroy_hw_mutex(&Adapter->shared);
}

static int
e1000g_resume(dev_info_t *devinfo)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)ddi_get_driver_private(devinfo);
	if (Adapter == NULL)
		e1000g_log(Adapter, CE_PANIC,
		    "Instance pointer is null\n");

	if (Adapter->dip != devinfo)
		e1000g_log(Adapter, CE_PANIC,
		    "Devinfo is not the same as saved devinfo\n");

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_STARTED) {
		if (e1000g_start(Adapter, B_FALSE) != DDI_SUCCESS) {
			rw_exit(&Adapter->chip_lock);
			/*
			 * We note the failure, but return success, as the
			 * system is still usable without this controller.
			 */
			e1000g_log(Adapter, CE_WARN,
			    "e1000g_resume: failed to restart controller\n");
			return (DDI_SUCCESS);
		}
		/* Enable and start the watchdog timer */
		enable_watchdog_timer(Adapter);
	}

	Adapter->e1000g_state &= ~E1000G_SUSPENDED;

	rw_exit(&Adapter->chip_lock);

	return (DDI_SUCCESS);
}

static int
e1000g_suspend(dev_info_t *devinfo)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)ddi_get_driver_private(devinfo);
	if (Adapter == NULL)
		return (DDI_FAILURE);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	Adapter->e1000g_state |= E1000G_SUSPENDED;

	/* if the port isn't plumbed, we can simply return */
	if (!(Adapter->e1000g_state & E1000G_STARTED)) {
		rw_exit(&Adapter->chip_lock);
		return (DDI_SUCCESS);
	}

	e1000g_stop(Adapter, B_FALSE);

	rw_exit(&Adapter->chip_lock);

	/* Disable and stop all the timers */
	disable_watchdog_timer(Adapter);
	stop_link_timer(Adapter);
	stop_82547_timer(Adapter->tx_ring);

	return (DDI_SUCCESS);
}

static int
e1000g_init(struct e1000g *Adapter)
{
	uint32_t pba;
	uint32_t high_water;
	struct e1000_hw *hw;
	clock_t link_timeout;
	int result;

	hw = &Adapter->shared;

	/*
	 * reset to put the hardware in a known state
	 * before we try to do anything with the eeprom
	 */
	mutex_enter(&e1000g_nvm_lock);
	result = e1000_reset_hw(hw);
	mutex_exit(&e1000g_nvm_lock);

	if (result != E1000_SUCCESS) {
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	mutex_enter(&e1000g_nvm_lock);
	result = e1000_validate_nvm_checksum(hw);
	if (result < E1000_SUCCESS) {
		/*
		 * Some PCI-E parts fail the first check due to
		 * the link being in sleep state.  Call it again,
		 * if it fails a second time its a real issue.
		 */
		result = e1000_validate_nvm_checksum(hw);
	}
	mutex_exit(&e1000g_nvm_lock);

	if (result < E1000_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
		    "Invalid NVM checksum. Please contact "
		    "the vendor to update the NVM.");
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	result = 0;
#ifdef __sparc
	/*
	 * First, we try to get the local ethernet address from OBP. If
	 * failed, then we get it from the EEPROM of NIC card.
	 */
	result = e1000g_find_mac_address(Adapter);
#endif
	/* Get the local ethernet address. */
	if (!result) {
		mutex_enter(&e1000g_nvm_lock);
		result = e1000_read_mac_addr(hw);
		mutex_exit(&e1000g_nvm_lock);
	}

	if (result < E1000_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Read mac addr failed");
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	/* check for valid mac address */
	if (!is_valid_mac_addr(hw->mac.addr)) {
		e1000g_log(Adapter, CE_WARN, "Invalid mac addr");
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	/* Set LAA state for 82571 chipset */
	e1000_set_laa_state_82571(hw, B_TRUE);

	/* Master Latency Timer implementation */
	if (Adapter->master_latency_timer) {
		pci_config_put8(Adapter->osdep.cfg_handle,
		    PCI_CONF_LATENCY_TIMER, Adapter->master_latency_timer);
	}

	if (hw->mac.type < e1000_82547) {
		/*
		 * Total FIFO is 64K
		 */
		if (Adapter->max_frame_size > FRAME_SIZE_UPTO_8K)
			pba = E1000_PBA_40K;	/* 40K for Rx, 24K for Tx */
		else
			pba = E1000_PBA_48K;	/* 48K for Rx, 16K for Tx */
	} else if ((hw->mac.type == e1000_82571) ||
	    (hw->mac.type == e1000_82572) ||
	    (hw->mac.type == e1000_80003es2lan)) {
		/*
		 * Total FIFO is 48K
		 */
		if (Adapter->max_frame_size > FRAME_SIZE_UPTO_8K)
			pba = E1000_PBA_30K;	/* 30K for Rx, 18K for Tx */
		else
			pba = E1000_PBA_38K;	/* 38K for Rx, 10K for Tx */
	} else if (hw->mac.type == e1000_82573) {
		pba = E1000_PBA_20K;		/* 20K for Rx, 12K for Tx */
	} else if (hw->mac.type == e1000_82574) {
		/* Keep adapter default: 20K for Rx, 20K for Tx */
		pba = E1000_READ_REG(hw, E1000_PBA);
	} else if (hw->mac.type == e1000_ich8lan) {
		pba = E1000_PBA_8K;		/* 8K for Rx, 12K for Tx */
	} else if (hw->mac.type == e1000_ich9lan) {
		pba = E1000_PBA_10K;
	} else if (hw->mac.type == e1000_ich10lan) {
		pba = E1000_PBA_10K;
	} else if (hw->mac.type == e1000_pchlan) {
		pba = E1000_PBA_26K;
	} else if (hw->mac.type == e1000_pch2lan) {
		pba = E1000_PBA_26K;
	} else if (hw->mac.type == e1000_pch_lpt) {
		pba = E1000_PBA_26K;
	} else if (hw->mac.type == e1000_pch_spt) {
		pba = E1000_PBA_26K;
	} else {
		/*
		 * Total FIFO is 40K
		 */
		if (Adapter->max_frame_size > FRAME_SIZE_UPTO_8K)
			pba = E1000_PBA_22K;	/* 22K for Rx, 18K for Tx */
		else
			pba = E1000_PBA_30K;	/* 30K for Rx, 10K for Tx */
	}
	E1000_WRITE_REG(hw, E1000_PBA, pba);

	/*
	 * These parameters set thresholds for the adapter's generation(Tx)
	 * and response(Rx) to Ethernet PAUSE frames.  These are just threshold
	 * settings.  Flow control is enabled or disabled in the configuration
	 * file.
	 * High-water mark is set down from the top of the rx fifo (not
	 * sensitive to max_frame_size) and low-water is set just below
	 * high-water mark.
	 * The high water mark must be low enough to fit one full frame above
	 * it in the rx FIFO.  Should be the lower of:
	 * 90% of the Rx FIFO size and the full Rx FIFO size minus the early
	 * receive size (assuming ERT set to E1000_ERT_2048), or the full
	 * Rx FIFO size minus one full frame.
	 */
	high_water = min(((pba << 10) * 9 / 10),
	    ((hw->mac.type == e1000_82573 || hw->mac.type == e1000_82574 ||
	    hw->mac.type == e1000_ich9lan || hw->mac.type == e1000_ich10lan) ?
	    ((pba << 10) - (E1000_ERT_2048 << 3)) :
	    ((pba << 10) - Adapter->max_frame_size)));

	hw->fc.high_water = high_water & 0xFFF8;
	hw->fc.low_water = hw->fc.high_water - 8;

	if (hw->mac.type == e1000_80003es2lan)
		hw->fc.pause_time = 0xFFFF;
	else
		hw->fc.pause_time = E1000_FC_PAUSE_TIME;
	hw->fc.send_xon = B_TRUE;

	/*
	 * Reset the adapter hardware the second time.
	 */
	mutex_enter(&e1000g_nvm_lock);
	result = e1000_reset_hw(hw);
	mutex_exit(&e1000g_nvm_lock);

	if (result != E1000_SUCCESS) {
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	/* disable wakeup control by default */
	if (hw->mac.type >= e1000_82544)
		E1000_WRITE_REG(hw, E1000_WUC, 0);

	/*
	 * MWI should be disabled on 82546.
	 */
	if (hw->mac.type == e1000_82546)
		e1000_pci_clear_mwi(hw);
	else
		e1000_pci_set_mwi(hw);

	/*
	 * Configure/Initialize hardware
	 */
	mutex_enter(&e1000g_nvm_lock);
	result = e1000_init_hw(hw);
	mutex_exit(&e1000g_nvm_lock);

	if (result < E1000_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Initialize hw failed");
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	/*
	 * Restore LED settings to the default from EEPROM
	 * to meet the standard for Sun platforms.
	 */
	(void) e1000_cleanup_led(hw);

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	/* Make sure driver has control */
	e1000g_get_driver_control(hw);

	/*
	 * Initialize unicast addresses.
	 */
	e1000g_init_unicst(Adapter);

	/*
	 * Setup and initialize the mctable structures.  After this routine
	 * completes  Multicast table will be set
	 */
	e1000_update_mc_addr_list(hw,
	    (uint8_t *)Adapter->mcast_table, Adapter->mcast_count);
	msec_delay(5);

	/*
	 * Implement Adaptive IFS
	 */
	e1000_reset_adaptive(hw);

	/* Setup Interrupt Throttling Register */
	if (hw->mac.type >= e1000_82540) {
		E1000_WRITE_REG(hw, E1000_ITR, Adapter->intr_throttling_rate);
	} else
		Adapter->intr_adaptive = B_FALSE;

	/* Start the timer for link setup */
	if (hw->mac.autoneg)
		link_timeout = PHY_AUTO_NEG_LIMIT * drv_usectohz(100000);
	else
		link_timeout = PHY_FORCE_LIMIT * drv_usectohz(100000);

	mutex_enter(&Adapter->link_lock);
	if (hw->phy.autoneg_wait_to_complete) {
		Adapter->link_complete = B_TRUE;
	} else {
		Adapter->link_complete = B_FALSE;
		Adapter->link_tid = timeout(e1000g_link_timer,
		    (void *)Adapter, link_timeout);
	}
	mutex_exit(&Adapter->link_lock);

	/* Save the state of the phy */
	e1000g_get_phy_state(Adapter);

	e1000g_param_sync(Adapter);

	Adapter->init_count++;

	if (e1000g_check_acc_handle(Adapter->osdep.cfg_handle) != DDI_FM_OK) {
		goto init_fail;
	}
	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		goto init_fail;
	}

	Adapter->poll_mode = e1000g_poll_mode;

	return (DDI_SUCCESS);

init_fail:
	ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);
	return (DDI_FAILURE);
}

static int
e1000g_alloc_rx_data(struct e1000g *Adapter)
{
	e1000g_rx_ring_t *rx_ring;
	e1000g_rx_data_t *rx_data;

	rx_ring = Adapter->rx_ring;

	rx_data = kmem_zalloc(sizeof (e1000g_rx_data_t), KM_NOSLEEP);

	if (rx_data == NULL)
		return (DDI_FAILURE);

	rx_data->priv_devi_node = Adapter->priv_devi_node;
	rx_data->rx_ring = rx_ring;

	mutex_init(&rx_data->freelist_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&rx_data->recycle_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));

	rx_ring->rx_data = rx_data;

	return (DDI_SUCCESS);
}

void
e1000g_free_rx_pending_buffers(e1000g_rx_data_t *rx_data)
{
	rx_sw_packet_t *packet, *next_packet;

	if (rx_data == NULL)
		return;

	packet = rx_data->packet_area;
	while (packet != NULL) {
		next_packet = packet->next;
		e1000g_free_rx_sw_packet(packet, B_TRUE);
		packet = next_packet;
	}
	rx_data->packet_area = NULL;
}

void
e1000g_free_rx_data(e1000g_rx_data_t *rx_data)
{
	if (rx_data == NULL)
		return;

	mutex_destroy(&rx_data->freelist_lock);
	mutex_destroy(&rx_data->recycle_lock);

	kmem_free(rx_data, sizeof (e1000g_rx_data_t));
}

/*
 * Check if the link is up
 */
static boolean_t
e1000g_link_up(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	boolean_t link_up = B_FALSE;

	/*
	 * get_link_status is set in the interrupt handler on link-status-change
	 * or rx sequence error interrupt.  get_link_status will stay
	 * false until the e1000_check_for_link establishes link only
	 * for copper adapters.
	 */
	switch (hw->phy.media_type) {
	case e1000_media_type_copper:
		if (hw->mac.get_link_status) {
			/*
			 * SPT devices need a bit of extra time before we ask
			 * them.
			 */
			if (hw->mac.type == e1000_pch_spt)
				msec_delay(50);
			(void) e1000_check_for_link(hw);
			if ((E1000_READ_REG(hw, E1000_STATUS) &
			    E1000_STATUS_LU)) {
				link_up = B_TRUE;
			} else {
				link_up = !hw->mac.get_link_status;
			}
		} else {
			link_up = B_TRUE;
		}
		break;
	case e1000_media_type_fiber:
		(void) e1000_check_for_link(hw);
		link_up = (E1000_READ_REG(hw, E1000_STATUS) &
		    E1000_STATUS_LU);
		break;
	case e1000_media_type_internal_serdes:
		(void) e1000_check_for_link(hw);
		link_up = hw->mac.serdes_has_link;
		break;
	}

	return (link_up);
}

static void
e1000g_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	struct e1000g *e1000gp;
	enum ioc_reply status;

	iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	iocp->ioc_error = 0;
	e1000gp = (struct e1000g *)arg;

	ASSERT(e1000gp);
	if (e1000gp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	rw_enter(&e1000gp->chip_lock, RW_READER);
	if (e1000gp->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&e1000gp->chip_lock);
		miocnak(q, mp, 0, EINVAL);
		return;
	}
	rw_exit(&e1000gp->chip_lock);

	switch (iocp->ioc_cmd) {

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = e1000g_loopback_ioctl(e1000gp, iocp, mp);
		break;


#ifdef E1000G_DEBUG
	case E1000G_IOC_REG_PEEK:
	case E1000G_IOC_REG_POKE:
		status = e1000g_pp_ioctl(e1000gp, iocp, mp);
		break;
	case E1000G_IOC_CHIP_RESET:
		e1000gp->reset_count++;
		if (e1000g_reset_adapter(e1000gp))
			status = IOC_ACK;
		else
			status = IOC_INVAL;
		break;
#endif
	default:
		status = IOC_INVAL;
		break;
	}

	/*
	 * Decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(q, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(q, mp, 0, 0);
		break;

	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK;
		qreply(q, mp);
		break;
	}
}

/*
 * The default value of e1000g_poll_mode == 0 assumes that the NIC is
 * capable of supporting only one interrupt and we shouldn't disable
 * the physical interrupt. In this case we let the interrupt come and
 * we queue the packets in the rx ring itself in case we are in polling
 * mode (better latency but slightly lower performance and a very
 * high intrrupt count in mpstat which is harmless).
 *
 * e1000g_poll_mode == 1 assumes that we have per Rx ring interrupt
 * which can be disabled in poll mode. This gives better overall
 * throughput (compared to the mode above), shows very low interrupt
 * count but has slightly higher latency since we pick the packets when
 * the poll thread does polling.
 *
 * Currently, this flag should be enabled only while doing performance
 * measurement or when it can be guaranteed that entire NIC going
 * in poll mode will not harm any traffic like cluster heartbeat etc.
 */
int e1000g_poll_mode = 0;

/*
 * Called from the upper layers when driver is in polling mode to
 * pick up any queued packets. Care should be taken to not block
 * this thread.
 */
static mblk_t *e1000g_poll_ring(void *arg, int bytes_to_pickup)
{
	e1000g_rx_ring_t	*rx_ring = (e1000g_rx_ring_t *)arg;
	mblk_t			*mp = NULL;
	mblk_t			*tail;
	struct e1000g 		*adapter;

	adapter = rx_ring->adapter;

	rw_enter(&adapter->chip_lock, RW_READER);

	if (adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&adapter->chip_lock);
		return (NULL);
	}

	mutex_enter(&rx_ring->rx_lock);
	mp = e1000g_receive(rx_ring, &tail, bytes_to_pickup);
	mutex_exit(&rx_ring->rx_lock);
	rw_exit(&adapter->chip_lock);
	return (mp);
}

static int
e1000g_m_start(void *arg)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	if (e1000g_start(Adapter, B_TRUE) != DDI_SUCCESS) {
		rw_exit(&Adapter->chip_lock);
		return (ENOTACTIVE);
	}

	Adapter->e1000g_state |= E1000G_STARTED;

	rw_exit(&Adapter->chip_lock);

	/* Enable and start the watchdog timer */
	enable_watchdog_timer(Adapter);

	return (0);
}

static int
e1000g_start(struct e1000g *Adapter, boolean_t global)
{
	e1000g_rx_data_t *rx_data;

	if (global) {
		if (e1000g_alloc_rx_data(Adapter) != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN, "Allocate rx data failed");
			goto start_fail;
		}

		/* Allocate dma resources for descriptors and buffers */
		if (e1000g_alloc_dma_resources(Adapter) != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "Alloc DMA resources failed");
			goto start_fail;
		}
		Adapter->rx_buffer_setup = B_FALSE;
	}

	if (!(Adapter->attach_progress & ATTACH_PROGRESS_INIT)) {
		if (e1000g_init(Adapter) != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "Adapter initialization failed");
			goto start_fail;
		}
	}

	/* Setup and initialize the transmit structures */
	e1000g_tx_setup(Adapter);
	msec_delay(5);

	/* Setup and initialize the receive structures */
	e1000g_rx_setup(Adapter);
	msec_delay(5);

	/* Restore the e1000g promiscuous mode */
	e1000g_restore_promisc(Adapter);

	e1000g_mask_interrupt(Adapter);

	Adapter->attach_progress |= ATTACH_PROGRESS_INIT;

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);
		goto start_fail;
	}

	return (DDI_SUCCESS);

start_fail:
	rx_data = Adapter->rx_ring->rx_data;

	if (global) {
		e1000g_release_dma_resources(Adapter);
		e1000g_free_rx_pending_buffers(rx_data);
		e1000g_free_rx_data(rx_data);
	}

	mutex_enter(&e1000g_nvm_lock);
	(void) e1000_reset_hw(&Adapter->shared);
	mutex_exit(&e1000g_nvm_lock);

	return (DDI_FAILURE);
}

/*
 * The I219 has the curious property that if the descriptor rings are not
 * emptied before resetting the hardware or before changing the device state
 * based on runtime power management, it'll cause the card to hang. This can
 * then only be fixed by a PCI reset. As such, for the I219 and it alone, we
 * have to flush the rings if we're in this state.
 */
static void
e1000g_flush_desc_rings(struct e1000g *Adapter)
{
	struct e1000_hw	*hw = &Adapter->shared;
	u16		hang_state;
	u32		fext_nvm11, tdlen;

	/* First, disable MULR fix in FEXTNVM11 */
	fext_nvm11 = E1000_READ_REG(hw, E1000_FEXTNVM11);
	fext_nvm11 |= E1000_FEXTNVM11_DISABLE_MULR_FIX;
	E1000_WRITE_REG(hw, E1000_FEXTNVM11, fext_nvm11);

	/* do nothing if we're not in faulty state, or if the queue is empty */
	tdlen = E1000_READ_REG(hw, E1000_TDLEN(0));
	hang_state = pci_config_get16(Adapter->osdep.cfg_handle,
	    PCICFG_DESC_RING_STATUS);
	if (!(hang_state & FLUSH_DESC_REQUIRED) || !tdlen)
		return;
	e1000g_flush_tx_ring(Adapter);

	/* recheck, maybe the fault is caused by the rx ring */
	hang_state = pci_config_get16(Adapter->osdep.cfg_handle,
	    PCICFG_DESC_RING_STATUS);
	if (hang_state & FLUSH_DESC_REQUIRED)
		e1000g_flush_rx_ring(Adapter);

}

static void
e1000g_m_stop(void *arg)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	/* Drain tx sessions */
	(void) e1000g_tx_drain(Adapter);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return;
	}
	Adapter->e1000g_state &= ~E1000G_STARTED;
	e1000g_stop(Adapter, B_TRUE);

	rw_exit(&Adapter->chip_lock);

	/* Disable and stop all the timers */
	disable_watchdog_timer(Adapter);
	stop_link_timer(Adapter);
	stop_82547_timer(Adapter->tx_ring);
}

static void
e1000g_stop(struct e1000g *Adapter, boolean_t global)
{
	private_devi_list_t *devi_node;
	e1000g_rx_data_t *rx_data;
	int result;

	Adapter->attach_progress &= ~ATTACH_PROGRESS_INIT;

	/* Stop the chip and release pending resources */

	/* Tell firmware driver is no longer in control */
	e1000g_release_driver_control(&Adapter->shared);

	e1000g_clear_all_interrupts(Adapter);

	mutex_enter(&e1000g_nvm_lock);
	result = e1000_reset_hw(&Adapter->shared);
	mutex_exit(&e1000g_nvm_lock);

	if (result != E1000_SUCCESS) {
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_INVAL_STATE);
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);
	}

	mutex_enter(&Adapter->link_lock);
	Adapter->link_complete = B_FALSE;
	mutex_exit(&Adapter->link_lock);

	/* Release resources still held by the TX descriptors */
	e1000g_tx_clean(Adapter);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);

	/* Clean the pending rx jumbo packet fragment */
	e1000g_rx_clean(Adapter);

	/*
	 * The I219, eg. the pch_spt, has bugs such that we must ensure that
	 * rings are flushed before we do anything else. This must be done
	 * before we release DMA resources.
	 */
	if (Adapter->shared.mac.type == e1000_pch_spt)
		e1000g_flush_desc_rings(Adapter);

	if (global) {
		e1000g_release_dma_resources(Adapter);

		mutex_enter(&e1000g_rx_detach_lock);
		rx_data = Adapter->rx_ring->rx_data;
		rx_data->flag |= E1000G_RX_STOPPED;

		if (rx_data->pending_count == 0) {
			e1000g_free_rx_pending_buffers(rx_data);
			e1000g_free_rx_data(rx_data);
		} else {
			devi_node = rx_data->priv_devi_node;
			if (devi_node != NULL)
				atomic_inc_32(&devi_node->pending_rx_count);
			else
				atomic_inc_32(&Adapter->pending_rx_count);
		}
		mutex_exit(&e1000g_rx_detach_lock);
	}

	if (Adapter->link_state != LINK_STATE_UNKNOWN) {
		Adapter->link_state = LINK_STATE_UNKNOWN;
		if (!Adapter->reset_flag)
			mac_link_update(Adapter->mh, Adapter->link_state);
	}
}

static void
e1000g_rx_clean(struct e1000g *Adapter)
{
	e1000g_rx_data_t *rx_data = Adapter->rx_ring->rx_data;

	if (rx_data == NULL)
		return;

	if (rx_data->rx_mblk != NULL) {
		freemsg(rx_data->rx_mblk);
		rx_data->rx_mblk = NULL;
		rx_data->rx_mblk_tail = NULL;
		rx_data->rx_mblk_len = 0;
	}
}

static void
e1000g_tx_clean(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	p_tx_sw_packet_t packet;
	mblk_t *mp;
	mblk_t *nmp;
	uint32_t packet_count;

	tx_ring = Adapter->tx_ring;

	/*
	 * Here we don't need to protect the lists using
	 * the usedlist_lock and freelist_lock, for they
	 * have been protected by the chip_lock.
	 */
	mp = NULL;
	nmp = NULL;
	packet_count = 0;
	packet = (p_tx_sw_packet_t)QUEUE_GET_HEAD(&tx_ring->used_list);
	while (packet != NULL) {
		if (packet->mp != NULL) {
			/* Assemble the message chain */
			if (mp == NULL) {
				mp = packet->mp;
				nmp = packet->mp;
			} else {
				nmp->b_next = packet->mp;
				nmp = packet->mp;
			}
			/* Disconnect the message from the sw packet */
			packet->mp = NULL;
		}

		e1000g_free_tx_swpkt(packet);
		packet_count++;

		packet = (p_tx_sw_packet_t)
		    QUEUE_GET_NEXT(&tx_ring->used_list, &packet->Link);
	}

	if (mp != NULL)
		freemsgchain(mp);

	if (packet_count > 0) {
		QUEUE_APPEND(&tx_ring->free_list, &tx_ring->used_list);
		QUEUE_INIT_LIST(&tx_ring->used_list);

		/* Setup TX descriptor pointers */
		tx_ring->tbd_next = tx_ring->tbd_first;
		tx_ring->tbd_oldest = tx_ring->tbd_first;

		/* Setup our HW Tx Head & Tail descriptor pointers */
		E1000_WRITE_REG(&Adapter->shared, E1000_TDH(0), 0);
		E1000_WRITE_REG(&Adapter->shared, E1000_TDT(0), 0);
	}
}

static boolean_t
e1000g_tx_drain(struct e1000g *Adapter)
{
	int i;
	boolean_t done;
	e1000g_tx_ring_t *tx_ring;

	tx_ring = Adapter->tx_ring;

	/* Allow up to 'wsdraintime' for pending xmit's to complete. */
	for (i = 0; i < TX_DRAIN_TIME; i++) {
		mutex_enter(&tx_ring->usedlist_lock);
		done = IS_QUEUE_EMPTY(&tx_ring->used_list);
		mutex_exit(&tx_ring->usedlist_lock);

		if (done)
			break;

		msec_delay(1);
	}

	return (done);
}

static boolean_t
e1000g_rx_drain(struct e1000g *Adapter)
{
	int i;
	boolean_t done;

	/*
	 * Allow up to RX_DRAIN_TIME for pending received packets to complete.
	 */
	for (i = 0; i < RX_DRAIN_TIME; i++) {
		done = (Adapter->pending_rx_count == 0);

		if (done)
			break;

		msec_delay(1);
	}

	return (done);
}

static boolean_t
e1000g_reset_adapter(struct e1000g *Adapter)
{
	/* Disable and stop all the timers */
	disable_watchdog_timer(Adapter);
	stop_link_timer(Adapter);
	stop_82547_timer(Adapter->tx_ring);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->stall_flag) {
		Adapter->stall_flag = B_FALSE;
		Adapter->reset_flag = B_TRUE;
	}

	if (!(Adapter->e1000g_state & E1000G_STARTED)) {
		rw_exit(&Adapter->chip_lock);
		return (B_TRUE);
	}

	e1000g_stop(Adapter, B_FALSE);

	if (e1000g_start(Adapter, B_FALSE) != DDI_SUCCESS) {
		rw_exit(&Adapter->chip_lock);
		e1000g_log(Adapter, CE_WARN, "Reset failed");
			return (B_FALSE);
	}

	rw_exit(&Adapter->chip_lock);

	/* Enable and start the watchdog timer */
	enable_watchdog_timer(Adapter);

	return (B_TRUE);
}

boolean_t
e1000g_global_reset(struct e1000g *Adapter)
{
	/* Disable and stop all the timers */
	disable_watchdog_timer(Adapter);
	stop_link_timer(Adapter);
	stop_82547_timer(Adapter->tx_ring);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	e1000g_stop(Adapter, B_TRUE);

	Adapter->init_count = 0;

	if (e1000g_start(Adapter, B_TRUE) != DDI_SUCCESS) {
		rw_exit(&Adapter->chip_lock);
		e1000g_log(Adapter, CE_WARN, "Reset failed");
		return (B_FALSE);
	}

	rw_exit(&Adapter->chip_lock);

	/* Enable and start the watchdog timer */
	enable_watchdog_timer(Adapter);

	return (B_TRUE);
}

/*
 * e1000g_intr_pciexpress - ISR for PCI Express chipsets
 *
 * This interrupt service routine is for PCI-Express adapters.
 * The ICR contents is valid only when the E1000_ICR_INT_ASSERTED
 * bit is set.
 */
static uint_t
e1000g_intr_pciexpress(caddr_t arg)
{
	struct e1000g *Adapter;
	uint32_t icr;

	Adapter = (struct e1000g *)(uintptr_t)arg;
	icr = E1000_READ_REG(&Adapter->shared, E1000_ICR);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		return (DDI_INTR_CLAIMED);
	}

	if (icr & E1000_ICR_INT_ASSERTED) {
		/*
		 * E1000_ICR_INT_ASSERTED bit was set:
		 * Read(Clear) the ICR, claim this interrupt,
		 * look for work to do.
		 */
		e1000g_intr_work(Adapter, icr);
		return (DDI_INTR_CLAIMED);
	} else {
		/*
		 * E1000_ICR_INT_ASSERTED bit was not set:
		 * Don't claim this interrupt, return immediately.
		 */
		return (DDI_INTR_UNCLAIMED);
	}
}

/*
 * e1000g_intr - ISR for PCI/PCI-X chipsets
 *
 * This interrupt service routine is for PCI/PCI-X adapters.
 * We check the ICR contents no matter the E1000_ICR_INT_ASSERTED
 * bit is set or not.
 */
static uint_t
e1000g_intr(caddr_t arg)
{
	struct e1000g *Adapter;
	uint32_t icr;

	Adapter = (struct e1000g *)(uintptr_t)arg;
	icr = E1000_READ_REG(&Adapter->shared, E1000_ICR);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		return (DDI_INTR_CLAIMED);
	}

	if (icr) {
		/*
		 * Any bit was set in ICR:
		 * Read(Clear) the ICR, claim this interrupt,
		 * look for work to do.
		 */
		e1000g_intr_work(Adapter, icr);
		return (DDI_INTR_CLAIMED);
	} else {
		/*
		 * No bit was set in ICR:
		 * Don't claim this interrupt, return immediately.
		 */
		return (DDI_INTR_UNCLAIMED);
	}
}

/*
 * e1000g_intr_work - actual processing of ISR
 *
 * Read(clear) the ICR contents and call appropriate interrupt
 * processing routines.
 */
static void
e1000g_intr_work(struct e1000g *Adapter, uint32_t icr)
{
	struct e1000_hw *hw;
	hw = &Adapter->shared;
	e1000g_tx_ring_t *tx_ring = Adapter->tx_ring;

	Adapter->rx_pkt_cnt = 0;
	Adapter->tx_pkt_cnt = 0;

	rw_enter(&Adapter->chip_lock, RW_READER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return;
	}
	/*
	 * Here we need to check the "e1000g_state" flag within the chip_lock to
	 * ensure the receive routine will not execute when the adapter is
	 * being reset.
	 */
	if (!(Adapter->e1000g_state & E1000G_STARTED)) {
		rw_exit(&Adapter->chip_lock);
		return;
	}

	if (icr & E1000_ICR_RXT0) {
		mblk_t			*mp = NULL;
		mblk_t			*tail = NULL;
		e1000g_rx_ring_t	*rx_ring;

		rx_ring = Adapter->rx_ring;
		mutex_enter(&rx_ring->rx_lock);
		/*
		 * Sometimes with legacy interrupts, it possible that
		 * there is a single interrupt for Rx/Tx. In which
		 * case, if poll flag is set, we shouldn't really
		 * be doing Rx processing.
		 */
		if (!rx_ring->poll_flag)
			mp = e1000g_receive(rx_ring, &tail,
			    E1000G_CHAIN_NO_LIMIT);
		mutex_exit(&rx_ring->rx_lock);
		rw_exit(&Adapter->chip_lock);
		if (mp != NULL)
			mac_rx_ring(Adapter->mh, rx_ring->mrh,
			    mp, rx_ring->ring_gen_num);
	} else
		rw_exit(&Adapter->chip_lock);

	if (icr & E1000_ICR_TXDW) {
		if (!Adapter->tx_intr_enable)
			e1000g_clear_tx_interrupt(Adapter);

		/* Recycle the tx descriptors */
		rw_enter(&Adapter->chip_lock, RW_READER);
		(void) e1000g_recycle(tx_ring);
		E1000G_DEBUG_STAT(tx_ring->stat_recycle_intr);
		rw_exit(&Adapter->chip_lock);

		if (tx_ring->resched_needed &&
		    (tx_ring->tbd_avail > DEFAULT_TX_UPDATE_THRESHOLD)) {
			tx_ring->resched_needed = B_FALSE;
			mac_tx_update(Adapter->mh);
			E1000G_STAT(tx_ring->stat_reschedule);
		}
	}

	/*
	 * The Receive Sequence errors RXSEQ and the link status change LSC
	 * are checked to detect that the cable has been pulled out. For
	 * the Wiseman 2.0 silicon, the receive sequence errors interrupt
	 * are an indication that cable is not connected.
	 */
	if ((icr & E1000_ICR_RXSEQ) ||
	    (icr & E1000_ICR_LSC) ||
	    (icr & E1000_ICR_GPI_EN1)) {
		boolean_t link_changed;
		timeout_id_t tid = 0;

		stop_watchdog_timer(Adapter);

		rw_enter(&Adapter->chip_lock, RW_WRITER);

		/*
		 * Because we got a link-status-change interrupt, force
		 * e1000_check_for_link() to look at phy
		 */
		Adapter->shared.mac.get_link_status = B_TRUE;

		/* e1000g_link_check takes care of link status change */
		link_changed = e1000g_link_check(Adapter);

		/* Get new phy state */
		e1000g_get_phy_state(Adapter);

		/*
		 * If the link timer has not timed out, we'll not notify
		 * the upper layer with any link state until the link is up.
		 */
		if (link_changed && !Adapter->link_complete) {
			if (Adapter->link_state == LINK_STATE_UP) {
				mutex_enter(&Adapter->link_lock);
				Adapter->link_complete = B_TRUE;
				tid = Adapter->link_tid;
				Adapter->link_tid = 0;
				mutex_exit(&Adapter->link_lock);
			} else {
				link_changed = B_FALSE;
			}
		}
		rw_exit(&Adapter->chip_lock);

		if (link_changed) {
			if (tid != 0)
				(void) untimeout(tid);

			/*
			 * Workaround for esb2. Data stuck in fifo on a link
			 * down event. Stop receiver here and reset in watchdog.
			 */
			if ((Adapter->link_state == LINK_STATE_DOWN) &&
			    (Adapter->shared.mac.type == e1000_80003es2lan)) {
				uint32_t rctl = E1000_READ_REG(hw, E1000_RCTL);
				E1000_WRITE_REG(hw, E1000_RCTL,
				    rctl & ~E1000_RCTL_EN);
				e1000g_log(Adapter, CE_WARN,
				    "ESB2 receiver disabled");
				Adapter->esb2_workaround = B_TRUE;
			}
			if (!Adapter->reset_flag)
				mac_link_update(Adapter->mh,
				    Adapter->link_state);
			if (Adapter->link_state == LINK_STATE_UP)
				Adapter->reset_flag = B_FALSE;
		}

		start_watchdog_timer(Adapter);
	}
}

static void
e1000g_init_unicst(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	int slot;

	hw = &Adapter->shared;

	if (Adapter->init_count == 0) {
		/* Initialize the multiple unicast addresses */
		Adapter->unicst_total = min(hw->mac.rar_entry_count,
		    MAX_NUM_UNICAST_ADDRESSES);

		/*
		 * The common code does not correctly calculate the number of
		 * rar's that could be reserved by firmware for the pch_lpt and
		 * pch_spt macs. The interface has one primary rar, and 11
		 * additional ones. Those 11 additional ones are not always
		 * available.  According to the datasheet, we need to check a
		 * few of the bits set in the FWSM register. If the value is
		 * zero, everything is available. If the value is 1, none of the
		 * additional registers are available. If the value is 2-7, only
		 * that number are available.
		 */
		if (hw->mac.type == e1000_pch_lpt ||
		    hw->mac.type == e1000_pch_spt) {
			uint32_t locked, rar;

			locked = E1000_READ_REG(hw, E1000_FWSM) &
			    E1000_FWSM_WLOCK_MAC_MASK;
			locked >>= E1000_FWSM_WLOCK_MAC_SHIFT;
			rar = 1;
			if (locked == 0)
				rar += 11;
			else if (locked == 1)
				rar += 0;
			else
				rar += locked;
			Adapter->unicst_total = min(rar,
			    MAX_NUM_UNICAST_ADDRESSES);
		}

		/* Workaround for an erratum of 82571 chipst */
		if ((hw->mac.type == e1000_82571) &&
		    (e1000_get_laa_state_82571(hw) == B_TRUE))
			Adapter->unicst_total--;

		/* VMware doesn't support multiple mac addresses properly */
		if (hw->subsystem_vendor_id == 0x15ad)
			Adapter->unicst_total = 1;

		Adapter->unicst_avail = Adapter->unicst_total;

		for (slot = 0; slot < Adapter->unicst_total; slot++) {
			/* Clear both the flag and MAC address */
			Adapter->unicst_addr[slot].reg.high = 0;
			Adapter->unicst_addr[slot].reg.low = 0;
		}
	} else {
		/* Workaround for an erratum of 82571 chipst */
		if ((hw->mac.type == e1000_82571) &&
		    (e1000_get_laa_state_82571(hw) == B_TRUE))
			(void) e1000_rar_set(hw, hw->mac.addr, LAST_RAR_ENTRY);

		/* Re-configure the RAR registers */
		for (slot = 0; slot < Adapter->unicst_total; slot++)
			if (Adapter->unicst_addr[slot].mac.set == 1)
				(void) e1000_rar_set(hw,
				    Adapter->unicst_addr[slot].mac.addr, slot);
	}

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
}

static int
e1000g_unicst_set(struct e1000g *Adapter, const uint8_t *mac_addr,
    int slot)
{
	struct e1000_hw *hw;

	hw = &Adapter->shared;

	/*
	 * The first revision of Wiseman silicon (rev 2.0) has an errata
	 * that requires the receiver to be in reset when any of the
	 * receive address registers (RAR regs) are accessed.  The first
	 * rev of Wiseman silicon also requires MWI to be disabled when
	 * a global reset or a receive reset is issued.  So before we
	 * initialize the RARs, we check the rev of the Wiseman controller
	 * and work around any necessary HW errata.
	 */
	if ((hw->mac.type == e1000_82542) &&
	    (hw->revision_id == E1000_REVISION_2)) {
		e1000_pci_clear_mwi(hw);
		E1000_WRITE_REG(hw, E1000_RCTL, E1000_RCTL_RST);
		msec_delay(5);
	}
	if (mac_addr == NULL) {
		E1000_WRITE_REG_ARRAY(hw, E1000_RA, slot << 1, 0);
		E1000_WRITE_FLUSH(hw);
		E1000_WRITE_REG_ARRAY(hw, E1000_RA, (slot << 1) + 1, 0);
		E1000_WRITE_FLUSH(hw);
		/* Clear both the flag and MAC address */
		Adapter->unicst_addr[slot].reg.high = 0;
		Adapter->unicst_addr[slot].reg.low = 0;
	} else {
		bcopy(mac_addr, Adapter->unicst_addr[slot].mac.addr,
		    ETHERADDRL);
		(void) e1000_rar_set(hw, (uint8_t *)mac_addr, slot);
		Adapter->unicst_addr[slot].mac.set = 1;
	}

	/* Workaround for an erratum of 82571 chipst */
	if (slot == 0) {
		if ((hw->mac.type == e1000_82571) &&
		    (e1000_get_laa_state_82571(hw) == B_TRUE))
			if (mac_addr == NULL) {
				E1000_WRITE_REG_ARRAY(hw, E1000_RA,
				    slot << 1, 0);
				E1000_WRITE_FLUSH(hw);
				E1000_WRITE_REG_ARRAY(hw, E1000_RA,
				    (slot << 1) + 1, 0);
				E1000_WRITE_FLUSH(hw);
			} else {
				(void) e1000_rar_set(hw, (uint8_t *)mac_addr,
				    LAST_RAR_ENTRY);
			}
	}

	/*
	 * If we are using Wiseman rev 2.0 silicon, we will have previously
	 * put the receive in reset, and disabled MWI, to work around some
	 * HW errata.  Now we should take the receiver out of reset, and
	 * re-enabled if MWI if it was previously enabled by the PCI BIOS.
	 */
	if ((hw->mac.type == e1000_82542) &&
	    (hw->revision_id == E1000_REVISION_2)) {
		E1000_WRITE_REG(hw, E1000_RCTL, 0);
		msec_delay(1);
		if (hw->bus.pci_cmd_word & CMD_MEM_WRT_INVALIDATE)
			e1000_pci_set_mwi(hw);
		e1000g_rx_setup(Adapter);
	}

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

static int
multicst_add(struct e1000g *Adapter, const uint8_t *multiaddr)
{
	struct e1000_hw *hw = &Adapter->shared;
	struct ether_addr *newtable;
	size_t new_len;
	size_t old_len;
	int res = 0;

	if ((multiaddr[0] & 01) == 0) {
		res = EINVAL;
		e1000g_log(Adapter, CE_WARN, "Illegal multicast address");
		goto done;
	}

	if (Adapter->mcast_count >= Adapter->mcast_max_num) {
		res = ENOENT;
		e1000g_log(Adapter, CE_WARN,
		    "Adapter requested more than %d mcast addresses",
		    Adapter->mcast_max_num);
		goto done;
	}


	if (Adapter->mcast_count == Adapter->mcast_alloc_count) {
		old_len = Adapter->mcast_alloc_count *
		    sizeof (struct ether_addr);
		new_len = (Adapter->mcast_alloc_count + MCAST_ALLOC_SIZE) *
		    sizeof (struct ether_addr);

		newtable = kmem_alloc(new_len, KM_NOSLEEP);
		if (newtable == NULL) {
			res = ENOMEM;
			e1000g_log(Adapter, CE_WARN,
			    "Not enough memory to alloc mcast table");
			goto done;
		}

		if (Adapter->mcast_table != NULL) {
			bcopy(Adapter->mcast_table, newtable, old_len);
			kmem_free(Adapter->mcast_table, old_len);
		}
		Adapter->mcast_alloc_count += MCAST_ALLOC_SIZE;
		Adapter->mcast_table = newtable;
	}

	bcopy(multiaddr,
	    &Adapter->mcast_table[Adapter->mcast_count], ETHERADDRL);
	Adapter->mcast_count++;

	/*
	 * Update the MC table in the hardware
	 */
	e1000g_clear_interrupt(Adapter);

	e1000_update_mc_addr_list(hw,
	    (uint8_t *)Adapter->mcast_table, Adapter->mcast_count);

	e1000g_mask_interrupt(Adapter);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		res = EIO;
	}

done:
	return (res);
}

static int
multicst_remove(struct e1000g *Adapter, const uint8_t *multiaddr)
{
	struct e1000_hw *hw = &Adapter->shared;
	struct ether_addr *newtable;
	size_t new_len;
	size_t old_len;
	unsigned i;

	for (i = 0; i < Adapter->mcast_count; i++) {
		if (bcmp(multiaddr, &Adapter->mcast_table[i],
		    ETHERADDRL) == 0) {
			for (i++; i < Adapter->mcast_count; i++) {
				Adapter->mcast_table[i - 1] =
				    Adapter->mcast_table[i];
			}
			Adapter->mcast_count--;
			break;
		}
	}

	if ((Adapter->mcast_alloc_count - Adapter->mcast_count) >
	    MCAST_ALLOC_SIZE) {
		old_len = Adapter->mcast_alloc_count *
		    sizeof (struct ether_addr);
		new_len = (Adapter->mcast_alloc_count - MCAST_ALLOC_SIZE) *
		    sizeof (struct ether_addr);

		newtable = kmem_alloc(new_len, KM_NOSLEEP);
		if (newtable != NULL) {
			bcopy(Adapter->mcast_table, newtable, new_len);
			kmem_free(Adapter->mcast_table, old_len);

			Adapter->mcast_alloc_count -= MCAST_ALLOC_SIZE;
			Adapter->mcast_table = newtable;
		}
	}

	/*
	 * Update the MC table in the hardware
	 */
	e1000g_clear_interrupt(Adapter);

	e1000_update_mc_addr_list(hw,
	    (uint8_t *)Adapter->mcast_table, Adapter->mcast_count);

	e1000g_mask_interrupt(Adapter);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

static void
e1000g_release_multicast(struct e1000g *Adapter)
{
	if (Adapter->mcast_table != NULL) {
		kmem_free(Adapter->mcast_table,
		    Adapter->mcast_alloc_count * sizeof (struct ether_addr));
		Adapter->mcast_table = NULL;
	}
}

int
e1000g_m_multicst(void *arg, boolean_t add, const uint8_t *addr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	int result;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		result = ECANCELED;
		goto done;
	}

	result = (add) ? multicst_add(Adapter, addr)
	    : multicst_remove(Adapter, addr);

done:
	rw_exit(&Adapter->chip_lock);
	return (result);

}

int
e1000g_m_promisc(void *arg, boolean_t on)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	uint32_t rctl;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	rctl = E1000_READ_REG(&Adapter->shared, E1000_RCTL);

	if (on)
		rctl |=
		    (E1000_RCTL_UPE | E1000_RCTL_MPE | E1000_RCTL_BAM);
	else
		rctl &= (~(E1000_RCTL_UPE | E1000_RCTL_MPE));

	E1000_WRITE_REG(&Adapter->shared, E1000_RCTL, rctl);

	Adapter->e1000g_promisc = on;

	rw_exit(&Adapter->chip_lock);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * Entry points to enable and disable interrupts at the granularity of
 * a group.
 * Turns the poll_mode for the whole adapter on and off to enable or
 * override the ring level polling control over the hardware interrupts.
 */
static int
e1000g_rx_group_intr_enable(mac_intr_handle_t arg)
{
	struct e1000g		*adapter = (struct e1000g *)arg;
	e1000g_rx_ring_t *rx_ring = adapter->rx_ring;

	/*
	 * Later interrupts at the granularity of the this ring will
	 * invoke mac_rx() with NULL, indicating the need for another
	 * software classification.
	 * We have a single ring usable per adapter now, so we only need to
	 * reset the rx handle for that one.
	 * When more RX rings can be used, we should update each one of them.
	 */
	mutex_enter(&rx_ring->rx_lock);
	rx_ring->mrh = NULL;
	adapter->poll_mode = B_FALSE;
	mutex_exit(&rx_ring->rx_lock);
	return (0);
}

static int
e1000g_rx_group_intr_disable(mac_intr_handle_t arg)
{
	struct e1000g *adapter = (struct e1000g *)arg;
	e1000g_rx_ring_t *rx_ring = adapter->rx_ring;

	mutex_enter(&rx_ring->rx_lock);

	/*
	 * Later interrupts at the granularity of the this ring will
	 * invoke mac_rx() with the handle for this ring;
	 */
	adapter->poll_mode = B_TRUE;
	rx_ring->mrh = rx_ring->mrh_init;
	mutex_exit(&rx_ring->rx_lock);
	return (0);
}

/*
 * Entry points to enable and disable interrupts at the granularity of
 * a ring.
 * adapter poll_mode controls whether we actually proceed with hardware
 * interrupt toggling.
 */
static int
e1000g_rx_ring_intr_enable(mac_intr_handle_t intrh)
{
	e1000g_rx_ring_t	*rx_ring = (e1000g_rx_ring_t *)intrh;
	struct e1000g 		*adapter = rx_ring->adapter;
	struct e1000_hw 	*hw = &adapter->shared;
	uint32_t		intr_mask;

	rw_enter(&adapter->chip_lock, RW_READER);

	if (adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&adapter->chip_lock);
		return (0);
	}

	mutex_enter(&rx_ring->rx_lock);
	rx_ring->poll_flag = 0;
	mutex_exit(&rx_ring->rx_lock);

	/* Rx interrupt enabling for MSI and legacy */
	intr_mask = E1000_READ_REG(hw, E1000_IMS);
	intr_mask |= E1000_IMS_RXT0;
	E1000_WRITE_REG(hw, E1000_IMS, intr_mask);
	E1000_WRITE_FLUSH(hw);

	/* Trigger a Rx interrupt to check Rx ring */
	E1000_WRITE_REG(hw, E1000_ICS, E1000_IMS_RXT0);
	E1000_WRITE_FLUSH(hw);

	rw_exit(&adapter->chip_lock);
	return (0);
}

static int
e1000g_rx_ring_intr_disable(mac_intr_handle_t intrh)
{
	e1000g_rx_ring_t	*rx_ring = (e1000g_rx_ring_t *)intrh;
	struct e1000g 		*adapter = rx_ring->adapter;
	struct e1000_hw 	*hw = &adapter->shared;

	rw_enter(&adapter->chip_lock, RW_READER);

	if (adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&adapter->chip_lock);
		return (0);
	}
	mutex_enter(&rx_ring->rx_lock);
	rx_ring->poll_flag = 1;
	mutex_exit(&rx_ring->rx_lock);

	/* Rx interrupt disabling for MSI and legacy */
	E1000_WRITE_REG(hw, E1000_IMC, E1000_IMS_RXT0);
	E1000_WRITE_FLUSH(hw);

	rw_exit(&adapter->chip_lock);
	return (0);
}

/*
 * e1000g_unicst_find - Find the slot for the specified unicast address
 */
static int
e1000g_unicst_find(struct e1000g *Adapter, const uint8_t *mac_addr)
{
	int slot;

	for (slot = 0; slot < Adapter->unicst_total; slot++) {
		if ((Adapter->unicst_addr[slot].mac.set == 1) &&
		    (bcmp(Adapter->unicst_addr[slot].mac.addr,
		    mac_addr, ETHERADDRL) == 0))
				return (slot);
	}

	return (-1);
}

/*
 * Entry points to add and remove a MAC address to a ring group.
 * The caller takes care of adding and removing the MAC addresses
 * to the filter via these two routines.
 */

static int
e1000g_addmac(void *arg, const uint8_t *mac_addr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	int slot, err;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	if (e1000g_unicst_find(Adapter, mac_addr) != -1) {
		/* The same address is already in slot */
		rw_exit(&Adapter->chip_lock);
		return (0);
	}

	if (Adapter->unicst_avail == 0) {
		/* no slots available */
		rw_exit(&Adapter->chip_lock);
		return (ENOSPC);
	}

	/* Search for a free slot */
	for (slot = 0; slot < Adapter->unicst_total; slot++) {
		if (Adapter->unicst_addr[slot].mac.set == 0)
			break;
	}
	ASSERT(slot < Adapter->unicst_total);

	err = e1000g_unicst_set(Adapter, mac_addr, slot);
	if (err == 0)
		Adapter->unicst_avail--;

	rw_exit(&Adapter->chip_lock);

	return (err);
}

static int
e1000g_remmac(void *arg, const uint8_t *mac_addr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	int slot, err;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	slot = e1000g_unicst_find(Adapter, mac_addr);
	if (slot == -1) {
		rw_exit(&Adapter->chip_lock);
		return (EINVAL);
	}

	ASSERT(Adapter->unicst_addr[slot].mac.set);

	/* Clear this slot */
	err = e1000g_unicst_set(Adapter, NULL, slot);
	if (err == 0)
		Adapter->unicst_avail++;

	rw_exit(&Adapter->chip_lock);

	return (err);
}

static int
e1000g_ring_start(mac_ring_driver_t rh, uint64_t mr_gen_num)
{
	e1000g_rx_ring_t *rx_ring = (e1000g_rx_ring_t *)rh;

	mutex_enter(&rx_ring->rx_lock);
	rx_ring->ring_gen_num = mr_gen_num;
	mutex_exit(&rx_ring->rx_lock);
	return (0);
}

/*
 * Callback funtion for MAC layer to register all rings.
 *
 * The hardware supports a single group with currently only one ring
 * available.
 * Though not offering virtualization ability per se, exposing the
 * group/ring still enables the polling and interrupt toggling.
 */
/* ARGSUSED */
void
e1000g_fill_ring(void *arg, mac_ring_type_t rtype, const int grp_index,
    const int ring_index, mac_ring_info_t *infop, mac_ring_handle_t rh)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	e1000g_rx_ring_t *rx_ring = Adapter->rx_ring;
	mac_intr_t *mintr;

	/*
	 * We advertised only RX group/rings, so the MAC framework shouldn't
	 * ask for any thing else.
	 */
	ASSERT(rtype == MAC_RING_TYPE_RX && grp_index == 0 && ring_index == 0);

	rx_ring->mrh = rx_ring->mrh_init = rh;
	infop->mri_driver = (mac_ring_driver_t)rx_ring;
	infop->mri_start = e1000g_ring_start;
	infop->mri_stop = NULL;
	infop->mri_poll = e1000g_poll_ring;
	infop->mri_stat = e1000g_rx_ring_stat;

	/* Ring level interrupts */
	mintr = &infop->mri_intr;
	mintr->mi_handle = (mac_intr_handle_t)rx_ring;
	mintr->mi_enable = e1000g_rx_ring_intr_enable;
	mintr->mi_disable = e1000g_rx_ring_intr_disable;
	if (Adapter->msi_enable)
		mintr->mi_ddi_handle = Adapter->htable[0];
}

/* ARGSUSED */
static void
e1000g_fill_group(void *arg, mac_ring_type_t rtype, const int grp_index,
    mac_group_info_t *infop, mac_group_handle_t gh)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	mac_intr_t *mintr;

	/*
	 * We advertised a single RX ring. Getting a request for anything else
	 * signifies a bug in the MAC framework.
	 */
	ASSERT(rtype == MAC_RING_TYPE_RX && grp_index == 0);

	Adapter->rx_group = gh;

	infop->mgi_driver = (mac_group_driver_t)Adapter;
	infop->mgi_start = NULL;
	infop->mgi_stop = NULL;
	infop->mgi_addmac = e1000g_addmac;
	infop->mgi_remmac = e1000g_remmac;
	infop->mgi_count = 1;

	/* Group level interrupts */
	mintr = &infop->mgi_intr;
	mintr->mi_handle = (mac_intr_handle_t)Adapter;
	mintr->mi_enable = e1000g_rx_group_intr_enable;
	mintr->mi_disable = e1000g_rx_group_intr_disable;
}

static boolean_t
e1000g_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		if (Adapter->tx_hcksum_enable)
			*txflags = HCKSUM_IPHDRCKSUM |
			    HCKSUM_INET_PARTIAL;
		else
			return (B_FALSE);
		break;
	}

	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		if (Adapter->lso_enable) {
			cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
			cap_lso->lso_basic_tcp_ipv4.lso_max =
			    E1000_LSO_MAXLEN;
		} else
			return (B_FALSE);
		break;
	}
	case MAC_CAPAB_RINGS: {
		mac_capab_rings_t *cap_rings = cap_data;

		/* No TX rings exposed yet */
		if (cap_rings->mr_type != MAC_RING_TYPE_RX)
			return (B_FALSE);

		cap_rings->mr_group_type = MAC_GROUP_TYPE_STATIC;
		cap_rings->mr_rnum = 1;
		cap_rings->mr_gnum = 1;
		cap_rings->mr_rget = e1000g_fill_ring;
		cap_rings->mr_gget = e1000g_fill_group;
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
e1000g_param_locked(mac_prop_id_t pr_num)
{
	/*
	 * All en_* parameters are locked (read-only) while
	 * the device is in any sort of loopback mode ...
	 */
	switch (pr_num) {
		case MAC_PROP_EN_1000FDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_EN_100FDX_CAP:
		case MAC_PROP_EN_100HDX_CAP:
		case MAC_PROP_EN_10FDX_CAP:
		case MAC_PROP_EN_10HDX_CAP:
		case MAC_PROP_AUTONEG:
		case MAC_PROP_FLOWCTRL:
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * callback function for set/get of properties
 */
static int
e1000g_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	struct e1000g *Adapter = arg;
	struct e1000_hw *hw = &Adapter->shared;
	struct e1000_fc_info *fc = &Adapter->shared.fc;
	int err = 0;
	link_flowctrl_t flowctrl;
	uint32_t cur_mtu, new_mtu;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if (Adapter->e1000g_state & E1000G_SUSPENDED) {
		rw_exit(&Adapter->chip_lock);
		return (ECANCELED);
	}

	if (Adapter->loopback_mode != E1000G_LB_NONE &&
	    e1000g_param_locked(pr_num)) {
		/*
		 * All en_* parameters are locked (read-only)
		 * while the device is in any sort of loopback mode.
		 */
		rw_exit(&Adapter->chip_lock);
		return (EBUSY);
	}

	switch (pr_num) {
		case MAC_PROP_EN_1000FDX_CAP:
			if (hw->phy.media_type != e1000_media_type_copper) {
				err = ENOTSUP;
				break;
			}
			Adapter->param_en_1000fdx = *(uint8_t *)pr_val;
			Adapter->param_adv_1000fdx = *(uint8_t *)pr_val;
			goto reset;
		case MAC_PROP_EN_100FDX_CAP:
			if (hw->phy.media_type != e1000_media_type_copper) {
				err = ENOTSUP;
				break;
			}
			Adapter->param_en_100fdx = *(uint8_t *)pr_val;
			Adapter->param_adv_100fdx = *(uint8_t *)pr_val;
			goto reset;
		case MAC_PROP_EN_100HDX_CAP:
			if (hw->phy.media_type != e1000_media_type_copper) {
				err = ENOTSUP;
				break;
			}
			Adapter->param_en_100hdx = *(uint8_t *)pr_val;
			Adapter->param_adv_100hdx = *(uint8_t *)pr_val;
			goto reset;
		case MAC_PROP_EN_10FDX_CAP:
			if (hw->phy.media_type != e1000_media_type_copper) {
				err = ENOTSUP;
				break;
			}
			Adapter->param_en_10fdx = *(uint8_t *)pr_val;
			Adapter->param_adv_10fdx = *(uint8_t *)pr_val;
			goto reset;
		case MAC_PROP_EN_10HDX_CAP:
			if (hw->phy.media_type != e1000_media_type_copper) {
				err = ENOTSUP;
				break;
			}
			Adapter->param_en_10hdx = *(uint8_t *)pr_val;
			Adapter->param_adv_10hdx = *(uint8_t *)pr_val;
			goto reset;
		case MAC_PROP_AUTONEG:
			if (hw->phy.media_type != e1000_media_type_copper) {
				err = ENOTSUP;
				break;
			}
			Adapter->param_adv_autoneg = *(uint8_t *)pr_val;
			goto reset;
		case MAC_PROP_FLOWCTRL:
			fc->send_xon = B_TRUE;
			bcopy(pr_val, &flowctrl, sizeof (flowctrl));

			switch (flowctrl) {
			default:
				err = EINVAL;
				break;
			case LINK_FLOWCTRL_NONE:
				fc->requested_mode = e1000_fc_none;
				break;
			case LINK_FLOWCTRL_RX:
				fc->requested_mode = e1000_fc_rx_pause;
				break;
			case LINK_FLOWCTRL_TX:
				fc->requested_mode = e1000_fc_tx_pause;
				break;
			case LINK_FLOWCTRL_BI:
				fc->requested_mode = e1000_fc_full;
				break;
			}
reset:
			if (err == 0) {
				/* check PCH limits & reset the link */
				e1000g_pch_limits(Adapter);
				if (e1000g_reset_link(Adapter) != DDI_SUCCESS)
					err = EINVAL;
			}
			break;
		case MAC_PROP_ADV_1000FDX_CAP:
		case MAC_PROP_ADV_1000HDX_CAP:
		case MAC_PROP_ADV_100FDX_CAP:
		case MAC_PROP_ADV_100HDX_CAP:
		case MAC_PROP_ADV_10FDX_CAP:
		case MAC_PROP_ADV_10HDX_CAP:
		case MAC_PROP_EN_1000HDX_CAP:
		case MAC_PROP_STATUS:
		case MAC_PROP_SPEED:
		case MAC_PROP_DUPLEX:
			err = ENOTSUP; /* read-only prop. Can't set this. */
			break;
		case MAC_PROP_MTU:
			/* adapter must be stopped for an MTU change */
			if (Adapter->e1000g_state & E1000G_STARTED) {
				err = EBUSY;
				break;
			}

			cur_mtu = Adapter->default_mtu;

			/* get new requested MTU */
			bcopy(pr_val, &new_mtu, sizeof (new_mtu));
			if (new_mtu == cur_mtu) {
				err = 0;
				break;
			}

			if ((new_mtu < DEFAULT_MTU) ||
			    (new_mtu > Adapter->max_mtu)) {
				err = EINVAL;
				break;
			}

			/* inform MAC framework of new MTU */
			err = mac_maxsdu_update(Adapter->mh, new_mtu);

			if (err == 0) {
				Adapter->default_mtu = new_mtu;
				Adapter->max_frame_size =
				    e1000g_mtu2maxframe(new_mtu);

				/*
				 * check PCH limits & set buffer sizes to
				 * match new MTU
				 */
				e1000g_pch_limits(Adapter);
				e1000g_set_bufsize(Adapter);

				/*
				 * decrease the number of descriptors and free
				 * packets for jumbo frames to reduce tx/rx
				 * resource consumption
				 */
				if (Adapter->max_frame_size >=
				    (FRAME_SIZE_UPTO_4K)) {
					if (Adapter->tx_desc_num_flag == 0)
						Adapter->tx_desc_num =
						    DEFAULT_JUMBO_NUM_TX_DESC;

					if (Adapter->rx_desc_num_flag == 0)
						Adapter->rx_desc_num =
						    DEFAULT_JUMBO_NUM_RX_DESC;

					if (Adapter->tx_buf_num_flag == 0)
						Adapter->tx_freelist_num =
						    DEFAULT_JUMBO_NUM_TX_BUF;

					if (Adapter->rx_buf_num_flag == 0)
						Adapter->rx_freelist_limit =
						    DEFAULT_JUMBO_NUM_RX_BUF;
				} else {
					if (Adapter->tx_desc_num_flag == 0)
						Adapter->tx_desc_num =
						    DEFAULT_NUM_TX_DESCRIPTOR;

					if (Adapter->rx_desc_num_flag == 0)
						Adapter->rx_desc_num =
						    DEFAULT_NUM_RX_DESCRIPTOR;

					if (Adapter->tx_buf_num_flag == 0)
						Adapter->tx_freelist_num =
						    DEFAULT_NUM_TX_FREELIST;

					if (Adapter->rx_buf_num_flag == 0)
						Adapter->rx_freelist_limit =
						    DEFAULT_NUM_RX_FREELIST;
				}
			}
			break;
		case MAC_PROP_PRIVATE:
			err = e1000g_set_priv_prop(Adapter, pr_name,
			    pr_valsize, pr_val);
			break;
		default:
			err = ENOTSUP;
			break;
	}
	rw_exit(&Adapter->chip_lock);
	return (err);
}

static int
e1000g_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	struct e1000g *Adapter = arg;
	struct e1000_fc_info *fc = &Adapter->shared.fc;
	int err = 0;
	link_flowctrl_t flowctrl;
	uint64_t tmp = 0;

	switch (pr_num) {
		case MAC_PROP_DUPLEX:
			ASSERT(pr_valsize >= sizeof (link_duplex_t));
			bcopy(&Adapter->link_duplex, pr_val,
			    sizeof (link_duplex_t));
			break;
		case MAC_PROP_SPEED:
			ASSERT(pr_valsize >= sizeof (uint64_t));
			tmp = Adapter->link_speed * 1000000ull;
			bcopy(&tmp, pr_val, sizeof (tmp));
			break;
		case MAC_PROP_AUTONEG:
			*(uint8_t *)pr_val = Adapter->param_adv_autoneg;
			break;
		case MAC_PROP_FLOWCTRL:
			ASSERT(pr_valsize >= sizeof (link_flowctrl_t));
			switch (fc->current_mode) {
				case e1000_fc_none:
					flowctrl = LINK_FLOWCTRL_NONE;
					break;
				case e1000_fc_rx_pause:
					flowctrl = LINK_FLOWCTRL_RX;
					break;
				case e1000_fc_tx_pause:
					flowctrl = LINK_FLOWCTRL_TX;
					break;
				case e1000_fc_full:
					flowctrl = LINK_FLOWCTRL_BI;
					break;
			}
			bcopy(&flowctrl, pr_val, sizeof (flowctrl));
			break;
		case MAC_PROP_ADV_1000FDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_1000fdx;
			break;
		case MAC_PROP_EN_1000FDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_en_1000fdx;
			break;
		case MAC_PROP_ADV_1000HDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_1000hdx;
			break;
		case MAC_PROP_EN_1000HDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_en_1000hdx;
			break;
		case MAC_PROP_ADV_100FDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_100fdx;
			break;
		case MAC_PROP_EN_100FDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_en_100fdx;
			break;
		case MAC_PROP_ADV_100HDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_100hdx;
			break;
		case MAC_PROP_EN_100HDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_en_100hdx;
			break;
		case MAC_PROP_ADV_10FDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_10fdx;
			break;
		case MAC_PROP_EN_10FDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_en_10fdx;
			break;
		case MAC_PROP_ADV_10HDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_10hdx;
			break;
		case MAC_PROP_EN_10HDX_CAP:
			*(uint8_t *)pr_val = Adapter->param_en_10hdx;
			break;
		case MAC_PROP_ADV_100T4_CAP:
		case MAC_PROP_EN_100T4_CAP:
			*(uint8_t *)pr_val = Adapter->param_adv_100t4;
			break;
		case MAC_PROP_PRIVATE:
			err = e1000g_get_priv_prop(Adapter, pr_name,
			    pr_valsize, pr_val);
			break;
		default:
			err = ENOTSUP;
			break;
	}

	return (err);
}

static void
e1000g_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	struct e1000g *Adapter = arg;
	struct e1000_hw *hw = &Adapter->shared;

	switch (pr_num) {
	case MAC_PROP_DUPLEX:
	case MAC_PROP_SPEED:
	case MAC_PROP_ADV_1000FDX_CAP:
	case MAC_PROP_ADV_1000HDX_CAP:
	case MAC_PROP_ADV_100FDX_CAP:
	case MAC_PROP_ADV_100HDX_CAP:
	case MAC_PROP_ADV_10FDX_CAP:
	case MAC_PROP_ADV_10HDX_CAP:
	case MAC_PROP_ADV_100T4_CAP:
	case MAC_PROP_EN_100T4_CAP:
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_EN_1000FDX_CAP:
		if (hw->phy.media_type != e1000_media_type_copper) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else {
			mac_prop_info_set_default_uint8(prh,
			    ((Adapter->phy_ext_status &
			    IEEE_ESR_1000T_FD_CAPS) ||
			    (Adapter->phy_ext_status &
			    IEEE_ESR_1000X_FD_CAPS)) ? 1 : 0);
		}
		break;

	case MAC_PROP_EN_100FDX_CAP:
		if (hw->phy.media_type != e1000_media_type_copper) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else {
			mac_prop_info_set_default_uint8(prh,
			    ((Adapter->phy_status & MII_SR_100X_FD_CAPS) ||
			    (Adapter->phy_status & MII_SR_100T2_FD_CAPS))
			    ? 1 : 0);
		}
		break;

	case MAC_PROP_EN_100HDX_CAP:
		if (hw->phy.media_type != e1000_media_type_copper) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else {
			mac_prop_info_set_default_uint8(prh,
			    ((Adapter->phy_status & MII_SR_100X_HD_CAPS) ||
			    (Adapter->phy_status & MII_SR_100T2_HD_CAPS))
			    ? 1 : 0);
		}
		break;

	case MAC_PROP_EN_10FDX_CAP:
		if (hw->phy.media_type != e1000_media_type_copper) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else {
			mac_prop_info_set_default_uint8(prh,
			    (Adapter->phy_status & MII_SR_10T_FD_CAPS) ? 1 : 0);
		}
		break;

	case MAC_PROP_EN_10HDX_CAP:
		if (hw->phy.media_type != e1000_media_type_copper) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else {
			mac_prop_info_set_default_uint8(prh,
			    (Adapter->phy_status & MII_SR_10T_HD_CAPS) ? 1 : 0);
		}
		break;

	case MAC_PROP_EN_1000HDX_CAP:
		if (hw->phy.media_type != e1000_media_type_copper)
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		break;

	case MAC_PROP_AUTONEG:
		if (hw->phy.media_type != e1000_media_type_copper) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		} else {
			mac_prop_info_set_default_uint8(prh,
			    (Adapter->phy_status & MII_SR_AUTONEG_CAPS)
			    ? 1 : 0);
		}
		break;

	case MAC_PROP_FLOWCTRL:
		mac_prop_info_set_default_link_flowctrl(prh, LINK_FLOWCTRL_BI);
		break;

	case MAC_PROP_MTU: {
		struct e1000_mac_info *mac = &Adapter->shared.mac;
		struct e1000_phy_info *phy = &Adapter->shared.phy;
		uint32_t max;

		/* some MAC types do not support jumbo frames */
		if ((mac->type == e1000_ich8lan) ||
		    ((mac->type == e1000_ich9lan) && (phy->type ==
		    e1000_phy_ife))) {
			max = DEFAULT_MTU;
		} else {
			max = Adapter->max_mtu;
		}

		mac_prop_info_set_range_uint32(prh, DEFAULT_MTU, max);
		break;
	}
	case MAC_PROP_PRIVATE: {
		char valstr[64];
		int value;

		if (strcmp(pr_name, "_adv_pause_cap") == 0 ||
		    strcmp(pr_name, "_adv_asym_pause_cap") == 0) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
			return;
		} else if (strcmp(pr_name, "_tx_bcopy_threshold") == 0) {
			value = DEFAULT_TX_BCOPY_THRESHOLD;
		} else if (strcmp(pr_name, "_tx_interrupt_enable") == 0) {
			value = DEFAULT_TX_INTR_ENABLE;
		} else if (strcmp(pr_name, "_tx_intr_delay") == 0) {
			value = DEFAULT_TX_INTR_DELAY;
		} else if (strcmp(pr_name, "_tx_intr_abs_delay") == 0) {
			value = DEFAULT_TX_INTR_ABS_DELAY;
		} else if (strcmp(pr_name, "_rx_bcopy_threshold") == 0) {
			value = DEFAULT_RX_BCOPY_THRESHOLD;
		} else if (strcmp(pr_name, "_max_num_rcv_packets") == 0) {
			value = DEFAULT_RX_LIMIT_ON_INTR;
		} else if (strcmp(pr_name, "_rx_intr_delay") == 0) {
			value = DEFAULT_RX_INTR_DELAY;
		} else if (strcmp(pr_name, "_rx_intr_abs_delay") == 0) {
			value = DEFAULT_RX_INTR_ABS_DELAY;
		} else if (strcmp(pr_name, "_intr_throttling_rate") == 0) {
			value = DEFAULT_INTR_THROTTLING;
		} else if (strcmp(pr_name, "_intr_adaptive") == 0) {
			value = 1;
		} else {
			return;
		}

		(void) snprintf(valstr, sizeof (valstr), "%d", value);
		mac_prop_info_set_default_str(prh, valstr);
		break;
	}
	}
}

/* ARGSUSED2 */
static int
e1000g_set_priv_prop(struct e1000g *Adapter, const char *pr_name,
    uint_t pr_valsize, const void *pr_val)
{
	int err = 0;
	long result;
	struct e1000_hw *hw = &Adapter->shared;

	if (strcmp(pr_name, "_tx_bcopy_threshold") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_BCOPY_THRESHOLD ||
		    result > MAX_TX_BCOPY_THRESHOLD)
			err = EINVAL;
		else {
			Adapter->tx_bcopy_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_interrupt_enable") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 0 || result > 1)
			err = EINVAL;
		else {
			Adapter->tx_intr_enable = (result == 1) ?
			    B_TRUE: B_FALSE;
			if (Adapter->tx_intr_enable)
				e1000g_mask_tx_interrupt(Adapter);
			else
				e1000g_clear_tx_interrupt(Adapter);
			if (e1000g_check_acc_handle(
			    Adapter->osdep.reg_handle) != DDI_FM_OK) {
				ddi_fm_service_impact(Adapter->dip,
				    DDI_SERVICE_DEGRADED);
				err = EIO;
			}
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_intr_delay") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_INTR_DELAY ||
		    result > MAX_TX_INTR_DELAY)
			err = EINVAL;
		else {
			Adapter->tx_intr_delay = (uint32_t)result;
			E1000_WRITE_REG(hw, E1000_TIDV, Adapter->tx_intr_delay);
			if (e1000g_check_acc_handle(
			    Adapter->osdep.reg_handle) != DDI_FM_OK) {
				ddi_fm_service_impact(Adapter->dip,
				    DDI_SERVICE_DEGRADED);
				err = EIO;
			}
		}
		return (err);
	}
	if (strcmp(pr_name, "_tx_intr_abs_delay") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_TX_INTR_ABS_DELAY ||
		    result > MAX_TX_INTR_ABS_DELAY)
			err = EINVAL;
		else {
			Adapter->tx_intr_abs_delay = (uint32_t)result;
			E1000_WRITE_REG(hw, E1000_TADV,
			    Adapter->tx_intr_abs_delay);
			if (e1000g_check_acc_handle(
			    Adapter->osdep.reg_handle) != DDI_FM_OK) {
				ddi_fm_service_impact(Adapter->dip,
				    DDI_SERVICE_DEGRADED);
				err = EIO;
			}
		}
		return (err);
	}
	if (strcmp(pr_name, "_rx_bcopy_threshold") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_RX_BCOPY_THRESHOLD ||
		    result > MAX_RX_BCOPY_THRESHOLD)
			err = EINVAL;
		else
			Adapter->rx_bcopy_thresh = (uint32_t)result;
		return (err);
	}
	if (strcmp(pr_name, "_max_num_rcv_packets") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_RX_LIMIT_ON_INTR ||
		    result > MAX_RX_LIMIT_ON_INTR)
			err = EINVAL;
		else
			Adapter->rx_limit_onintr = (uint32_t)result;
		return (err);
	}
	if (strcmp(pr_name, "_rx_intr_delay") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_RX_INTR_DELAY ||
		    result > MAX_RX_INTR_DELAY)
			err = EINVAL;
		else {
			Adapter->rx_intr_delay = (uint32_t)result;
			E1000_WRITE_REG(hw, E1000_RDTR, Adapter->rx_intr_delay);
			if (e1000g_check_acc_handle(
			    Adapter->osdep.reg_handle) != DDI_FM_OK) {
				ddi_fm_service_impact(Adapter->dip,
				    DDI_SERVICE_DEGRADED);
				err = EIO;
			}
		}
		return (err);
	}
	if (strcmp(pr_name, "_rx_intr_abs_delay") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_RX_INTR_ABS_DELAY ||
		    result > MAX_RX_INTR_ABS_DELAY)
			err = EINVAL;
		else {
			Adapter->rx_intr_abs_delay = (uint32_t)result;
			E1000_WRITE_REG(hw, E1000_RADV,
			    Adapter->rx_intr_abs_delay);
			if (e1000g_check_acc_handle(
			    Adapter->osdep.reg_handle) != DDI_FM_OK) {
				ddi_fm_service_impact(Adapter->dip,
				    DDI_SERVICE_DEGRADED);
				err = EIO;
			}
		}
		return (err);
	}
	if (strcmp(pr_name, "_intr_throttling_rate") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < MIN_INTR_THROTTLING ||
		    result > MAX_INTR_THROTTLING)
			err = EINVAL;
		else {
			if (hw->mac.type >= e1000_82540) {
				Adapter->intr_throttling_rate =
				    (uint32_t)result;
				E1000_WRITE_REG(hw, E1000_ITR,
				    Adapter->intr_throttling_rate);
				if (e1000g_check_acc_handle(
				    Adapter->osdep.reg_handle) != DDI_FM_OK) {
					ddi_fm_service_impact(Adapter->dip,
					    DDI_SERVICE_DEGRADED);
					err = EIO;
				}
			} else
				err = EINVAL;
		}
		return (err);
	}
	if (strcmp(pr_name, "_intr_adaptive") == 0) {
		if (pr_val == NULL) {
			err = EINVAL;
			return (err);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 0 || result > 1)
			err = EINVAL;
		else {
			if (hw->mac.type >= e1000_82540) {
				Adapter->intr_adaptive = (result == 1) ?
				    B_TRUE : B_FALSE;
			} else {
				err = EINVAL;
			}
		}
		return (err);
	}
	return (ENOTSUP);
}

static int
e1000g_get_priv_prop(struct e1000g *Adapter, const char *pr_name,
    uint_t pr_valsize, void *pr_val)
{
	int err = ENOTSUP;
	int value;

	if (strcmp(pr_name, "_adv_pause_cap") == 0) {
		value = Adapter->param_adv_pause;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_adv_asym_pause_cap") == 0) {
		value = Adapter->param_adv_asym_pause;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_bcopy_threshold") == 0) {
		value = Adapter->tx_bcopy_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_interrupt_enable") == 0) {
		value = Adapter->tx_intr_enable;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_intr_delay") == 0) {
		value = Adapter->tx_intr_delay;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_tx_intr_abs_delay") == 0) {
		value = Adapter->tx_intr_abs_delay;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_bcopy_threshold") == 0) {
		value = Adapter->rx_bcopy_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_max_num_rcv_packets") == 0) {
		value = Adapter->rx_limit_onintr;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_intr_delay") == 0) {
		value = Adapter->rx_intr_delay;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_rx_intr_abs_delay") == 0) {
		value = Adapter->rx_intr_abs_delay;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_intr_throttling_rate") == 0) {
		value = Adapter->intr_throttling_rate;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_intr_adaptive") == 0) {
		value = Adapter->intr_adaptive;
		err = 0;
		goto done;
	}
done:
	if (err == 0) {
		(void) snprintf(pr_val, pr_valsize, "%d", value);
	}
	return (err);
}

/*
 * e1000g_get_conf - get configurations set in e1000g.conf
 * This routine gets user-configured values out of the configuration
 * file e1000g.conf.
 *
 * For each configurable value, there is a minimum, a maximum, and a
 * default.
 * If user does not configure a value, use the default.
 * If user configures below the minimum, use the minumum.
 * If user configures above the maximum, use the maxumum.
 */
static void
e1000g_get_conf(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	boolean_t tbi_compatibility = B_FALSE;
	boolean_t is_jumbo = B_FALSE;
	int propval;
	/*
	 * decrease the number of descriptors and free packets
	 * for jumbo frames to reduce tx/rx resource consumption
	 */
	if (Adapter->max_frame_size >= FRAME_SIZE_UPTO_4K) {
		is_jumbo = B_TRUE;
	}

	/*
	 * get each configurable property from e1000g.conf
	 */

	/*
	 * NumTxDescriptors
	 */
	Adapter->tx_desc_num_flag =
	    e1000g_get_prop(Adapter, "NumTxDescriptors",
	    MIN_NUM_TX_DESCRIPTOR, MAX_NUM_TX_DESCRIPTOR,
	    is_jumbo ? DEFAULT_JUMBO_NUM_TX_DESC
	    : DEFAULT_NUM_TX_DESCRIPTOR, &propval);
	Adapter->tx_desc_num = propval;

	/*
	 * NumRxDescriptors
	 */
	Adapter->rx_desc_num_flag =
	    e1000g_get_prop(Adapter, "NumRxDescriptors",
	    MIN_NUM_RX_DESCRIPTOR, MAX_NUM_RX_DESCRIPTOR,
	    is_jumbo ? DEFAULT_JUMBO_NUM_RX_DESC
	    : DEFAULT_NUM_RX_DESCRIPTOR, &propval);
	Adapter->rx_desc_num = propval;

	/*
	 * NumRxFreeList
	 */
	Adapter->rx_buf_num_flag =
	    e1000g_get_prop(Adapter, "NumRxFreeList",
	    MIN_NUM_RX_FREELIST, MAX_NUM_RX_FREELIST,
	    is_jumbo ? DEFAULT_JUMBO_NUM_RX_BUF
	    : DEFAULT_NUM_RX_FREELIST, &propval);
	Adapter->rx_freelist_limit = propval;

	/*
	 * NumTxPacketList
	 */
	Adapter->tx_buf_num_flag =
	    e1000g_get_prop(Adapter, "NumTxPacketList",
	    MIN_NUM_TX_FREELIST, MAX_NUM_TX_FREELIST,
	    is_jumbo ? DEFAULT_JUMBO_NUM_TX_BUF
	    : DEFAULT_NUM_TX_FREELIST, &propval);
	Adapter->tx_freelist_num = propval;

	/*
	 * FlowControl
	 */
	hw->fc.send_xon = B_TRUE;
	(void) e1000g_get_prop(Adapter, "FlowControl",
	    e1000_fc_none, 4, DEFAULT_FLOW_CONTROL, &propval);
	hw->fc.requested_mode = propval;
	/* 4 is the setting that says "let the eeprom decide" */
	if (hw->fc.requested_mode == 4)
		hw->fc.requested_mode = e1000_fc_default;

	/*
	 * Max Num Receive Packets on Interrupt
	 */
	(void) e1000g_get_prop(Adapter, "MaxNumReceivePackets",
	    MIN_RX_LIMIT_ON_INTR, MAX_RX_LIMIT_ON_INTR,
	    DEFAULT_RX_LIMIT_ON_INTR, &propval);
	Adapter->rx_limit_onintr = propval;

	/*
	 * PHY master slave setting
	 */
	(void) e1000g_get_prop(Adapter, "SetMasterSlave",
	    e1000_ms_hw_default, e1000_ms_auto,
	    e1000_ms_hw_default, &propval);
	hw->phy.ms_type = propval;

	/*
	 * Parameter which controls TBI mode workaround, which is only
	 * needed on certain switches such as Cisco 6500/Foundry
	 */
	(void) e1000g_get_prop(Adapter, "TbiCompatibilityEnable",
	    0, 1, DEFAULT_TBI_COMPAT_ENABLE, &propval);
	tbi_compatibility = (propval == 1);
	e1000_set_tbi_compatibility_82543(hw, tbi_compatibility);

	/*
	 * MSI Enable
	 */
	(void) e1000g_get_prop(Adapter, "MSIEnable",
	    0, 1, DEFAULT_MSI_ENABLE, &propval);
	Adapter->msi_enable = (propval == 1);

	/*
	 * Interrupt Throttling Rate
	 */
	(void) e1000g_get_prop(Adapter, "intr_throttling_rate",
	    MIN_INTR_THROTTLING, MAX_INTR_THROTTLING,
	    DEFAULT_INTR_THROTTLING, &propval);
	Adapter->intr_throttling_rate = propval;

	/*
	 * Adaptive Interrupt Blanking Enable/Disable
	 * It is enabled by default
	 */
	(void) e1000g_get_prop(Adapter, "intr_adaptive", 0, 1, 1,
	    &propval);
	Adapter->intr_adaptive = (propval == 1);

	/*
	 * Hardware checksum enable/disable parameter
	 */
	(void) e1000g_get_prop(Adapter, "tx_hcksum_enable",
	    0, 1, DEFAULT_TX_HCKSUM_ENABLE, &propval);
	Adapter->tx_hcksum_enable = (propval == 1);
	/*
	 * Checksum on/off selection via global parameters.
	 *
	 * If the chip is flagged as not capable of (correctly)
	 * handling checksumming, we don't enable it on either
	 * Rx or Tx side.  Otherwise, we take this chip's settings
	 * from the patchable global defaults.
	 *
	 * We advertise our capabilities only if TX offload is
	 * enabled.  On receive, the stack will accept checksummed
	 * packets anyway, even if we haven't said we can deliver
	 * them.
	 */
	switch (hw->mac.type) {
		case e1000_82540:
		case e1000_82544:
		case e1000_82545:
		case e1000_82545_rev_3:
		case e1000_82546:
		case e1000_82546_rev_3:
		case e1000_82571:
		case e1000_82572:
		case e1000_82573:
		case e1000_80003es2lan:
			break;
		/*
		 * For the following Intel PRO/1000 chipsets, we have not
		 * tested the hardware checksum offload capability, so we
		 * disable the capability for them.
		 *	e1000_82542,
		 *	e1000_82543,
		 *	e1000_82541,
		 *	e1000_82541_rev_2,
		 *	e1000_82547,
		 *	e1000_82547_rev_2,
		 */
		default:
			Adapter->tx_hcksum_enable = B_FALSE;
	}

	/*
	 * Large Send Offloading(LSO) Enable/Disable
	 * If the tx hardware checksum is not enabled, LSO should be
	 * disabled.
	 */
	(void) e1000g_get_prop(Adapter, "lso_enable",
	    0, 1, DEFAULT_LSO_ENABLE, &propval);
	Adapter->lso_enable = (propval == 1);

	switch (hw->mac.type) {
		case e1000_82546:
		case e1000_82546_rev_3:
			if (Adapter->lso_enable)
				Adapter->lso_premature_issue = B_TRUE;
			/* FALLTHRU */
		case e1000_82571:
		case e1000_82572:
		case e1000_82573:
		case e1000_80003es2lan:
			break;
		default:
			Adapter->lso_enable = B_FALSE;
	}

	if (!Adapter->tx_hcksum_enable) {
		Adapter->lso_premature_issue = B_FALSE;
		Adapter->lso_enable = B_FALSE;
	}

	/*
	 * If mem_workaround_82546 is enabled, the rx buffer allocated by
	 * e1000_82545, e1000_82546 and e1000_82546_rev_3
	 * will not cross 64k boundary.
	 */
	(void) e1000g_get_prop(Adapter, "mem_workaround_82546",
	    0, 1, DEFAULT_MEM_WORKAROUND_82546, &propval);
	Adapter->mem_workaround_82546 = (propval == 1);

	/*
	 * Max number of multicast addresses
	 */
	(void) e1000g_get_prop(Adapter, "mcast_max_num",
	    MIN_MCAST_NUM, MAX_MCAST_NUM, hw->mac.mta_reg_count * 32,
	    &propval);
	Adapter->mcast_max_num = propval;
}

/*
 * e1000g_get_prop - routine to read properties
 *
 * Get a user-configure property value out of the configuration
 * file e1000g.conf.
 *
 * Caller provides name of the property, a default value, a minimum
 * value, a maximum value and a pointer to the returned property
 * value.
 *
 * Return B_TRUE if the configured value of the property is not a default
 * value, otherwise return B_FALSE.
 */
static boolean_t
e1000g_get_prop(struct e1000g *Adapter,	/* point to per-adapter structure */
    char *propname,		/* name of the property */
    int minval,			/* minimum acceptable value */
    int maxval,			/* maximim acceptable value */
    int defval,			/* default value */
    int *propvalue)		/* property value return to caller */
{
	int propval;		/* value returned for requested property */
	int *props;		/* point to array of properties returned */
	uint_t nprops;		/* number of property value returned */
	boolean_t ret = B_TRUE;

	/*
	 * get the array of properties from the config file
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, Adapter->dip,
	    DDI_PROP_DONTPASS, propname, &props, &nprops) == DDI_PROP_SUCCESS) {
		/* got some properties, test if we got enough */
		if (Adapter->instance < nprops) {
			propval = props[Adapter->instance];
		} else {
			/* not enough properties configured */
			propval = defval;
			E1000G_DEBUGLOG_2(Adapter, E1000G_INFO_LEVEL,
			    "Not Enough %s values found in e1000g.conf"
			    " - set to %d\n",
			    propname, propval);
			ret = B_FALSE;
		}

		/* free memory allocated for properties */
		ddi_prop_free(props);

	} else {
		propval = defval;
		ret = B_FALSE;
	}

	/*
	 * enforce limits
	 */
	if (propval > maxval) {
		propval = maxval;
		E1000G_DEBUGLOG_2(Adapter, E1000G_INFO_LEVEL,
		    "Too High %s value in e1000g.conf - set to %d\n",
		    propname, propval);
	}

	if (propval < minval) {
		propval = minval;
		E1000G_DEBUGLOG_2(Adapter, E1000G_INFO_LEVEL,
		    "Too Low %s value in e1000g.conf - set to %d\n",
		    propname, propval);
	}

	*propvalue = propval;
	return (ret);
}

static boolean_t
e1000g_link_check(struct e1000g *Adapter)
{
	uint16_t speed, duplex, phydata;
	boolean_t link_changed = B_FALSE;
	struct e1000_hw *hw;
	uint32_t reg_tarc;

	hw = &Adapter->shared;

	if (e1000g_link_up(Adapter)) {
		/*
		 * The Link is up, check whether it was marked as down earlier
		 */
		if (Adapter->link_state != LINK_STATE_UP) {
			(void) e1000_get_speed_and_duplex(hw, &speed, &duplex);
			Adapter->link_speed = speed;
			Adapter->link_duplex = duplex;
			Adapter->link_state = LINK_STATE_UP;
			link_changed = B_TRUE;

			if (Adapter->link_speed == SPEED_1000)
				Adapter->stall_threshold = TX_STALL_TIME_2S;
			else
				Adapter->stall_threshold = TX_STALL_TIME_8S;

			Adapter->tx_link_down_timeout = 0;

			if ((hw->mac.type == e1000_82571) ||
			    (hw->mac.type == e1000_82572)) {
				reg_tarc = E1000_READ_REG(hw, E1000_TARC(0));
				if (speed == SPEED_1000)
					reg_tarc |= (1 << 21);
				else
					reg_tarc &= ~(1 << 21);
				E1000_WRITE_REG(hw, E1000_TARC(0), reg_tarc);
			}
		}
		Adapter->smartspeed = 0;
	} else {
		if (Adapter->link_state != LINK_STATE_DOWN) {
			Adapter->link_speed = 0;
			Adapter->link_duplex = 0;
			Adapter->link_state = LINK_STATE_DOWN;
			link_changed = B_TRUE;

			/*
			 * SmartSpeed workaround for Tabor/TanaX, When the
			 * driver loses link disable auto master/slave
			 * resolution.
			 */
			if (hw->phy.type == e1000_phy_igp) {
				(void) e1000_read_phy_reg(hw,
				    PHY_1000T_CTRL, &phydata);
				phydata |= CR_1000T_MS_ENABLE;
				(void) e1000_write_phy_reg(hw,
				    PHY_1000T_CTRL, phydata);
			}
		} else {
			e1000g_smartspeed(Adapter);
		}

		if (Adapter->e1000g_state & E1000G_STARTED) {
			if (Adapter->tx_link_down_timeout <
			    MAX_TX_LINK_DOWN_TIMEOUT) {
				Adapter->tx_link_down_timeout++;
			} else if (Adapter->tx_link_down_timeout ==
			    MAX_TX_LINK_DOWN_TIMEOUT) {
				e1000g_tx_clean(Adapter);
				Adapter->tx_link_down_timeout++;
			}
		}
	}

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);

	return (link_changed);
}

/*
 * e1000g_reset_link - Using the link properties to setup the link
 */
int
e1000g_reset_link(struct e1000g *Adapter)
{
	struct e1000_mac_info *mac;
	struct e1000_phy_info *phy;
	struct e1000_hw *hw;
	boolean_t invalid;

	mac = &Adapter->shared.mac;
	phy = &Adapter->shared.phy;
	hw = &Adapter->shared;
	invalid = B_FALSE;

	if (hw->phy.media_type != e1000_media_type_copper)
		goto out;

	if (Adapter->param_adv_autoneg == 1) {
		mac->autoneg = B_TRUE;
		phy->autoneg_advertised = 0;

		/*
		 * 1000hdx is not supported for autonegotiation
		 */
		if (Adapter->param_adv_1000fdx == 1)
			phy->autoneg_advertised |= ADVERTISE_1000_FULL;

		if (Adapter->param_adv_100fdx == 1)
			phy->autoneg_advertised |= ADVERTISE_100_FULL;

		if (Adapter->param_adv_100hdx == 1)
			phy->autoneg_advertised |= ADVERTISE_100_HALF;

		if (Adapter->param_adv_10fdx == 1)
			phy->autoneg_advertised |= ADVERTISE_10_FULL;

		if (Adapter->param_adv_10hdx == 1)
			phy->autoneg_advertised |= ADVERTISE_10_HALF;

		if (phy->autoneg_advertised == 0)
			invalid = B_TRUE;
	} else {
		mac->autoneg = B_FALSE;

		/*
		 * For Intel copper cards, 1000fdx and 1000hdx are not
		 * supported for forced link
		 */
		if (Adapter->param_adv_100fdx == 1)
			mac->forced_speed_duplex = ADVERTISE_100_FULL;
		else if (Adapter->param_adv_100hdx == 1)
			mac->forced_speed_duplex = ADVERTISE_100_HALF;
		else if (Adapter->param_adv_10fdx == 1)
			mac->forced_speed_duplex = ADVERTISE_10_FULL;
		else if (Adapter->param_adv_10hdx == 1)
			mac->forced_speed_duplex = ADVERTISE_10_HALF;
		else
			invalid = B_TRUE;

	}

	if (invalid) {
		e1000g_log(Adapter, CE_WARN,
		    "Invalid link settings. Setup link to "
		    "support autonegotiation with all link capabilities.");
		mac->autoneg = B_TRUE;
		phy->autoneg_advertised = AUTONEG_ADVERTISE_SPEED_DEFAULT;
	}

out:
	return (e1000_setup_link(&Adapter->shared));
}

static void
e1000g_timer_tx_resched(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring = Adapter->tx_ring;

	rw_enter(&Adapter->chip_lock, RW_READER);

	if (tx_ring->resched_needed &&
	    ((ddi_get_lbolt() - tx_ring->resched_timestamp) >
	    drv_usectohz(1000000)) &&
	    (Adapter->e1000g_state & E1000G_STARTED) &&
	    (tx_ring->tbd_avail >= DEFAULT_TX_NO_RESOURCE)) {
		tx_ring->resched_needed = B_FALSE;
		mac_tx_update(Adapter->mh);
		E1000G_STAT(tx_ring->stat_reschedule);
		E1000G_STAT(tx_ring->stat_timer_reschedule);
	}

	rw_exit(&Adapter->chip_lock);
}

static void
e1000g_local_timer(void *ws)
{
	struct e1000g *Adapter = (struct e1000g *)ws;
	struct e1000_hw *hw;
	e1000g_ether_addr_t ether_addr;
	boolean_t link_changed;

	hw = &Adapter->shared;

	if (Adapter->e1000g_state & E1000G_ERROR) {
		rw_enter(&Adapter->chip_lock, RW_WRITER);
		Adapter->e1000g_state &= ~E1000G_ERROR;
		rw_exit(&Adapter->chip_lock);

		Adapter->reset_count++;
		if (e1000g_global_reset(Adapter)) {
			ddi_fm_service_impact(Adapter->dip,
			    DDI_SERVICE_RESTORED);
			e1000g_timer_tx_resched(Adapter);
		} else
			ddi_fm_service_impact(Adapter->dip,
			    DDI_SERVICE_LOST);
		return;
	}

	if (e1000g_stall_check(Adapter)) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
		    "Tx stall detected. Activate automatic recovery.\n");
		e1000g_fm_ereport(Adapter, DDI_FM_DEVICE_STALL);
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_LOST);
		Adapter->reset_count++;
		if (e1000g_reset_adapter(Adapter)) {
			ddi_fm_service_impact(Adapter->dip,
			    DDI_SERVICE_RESTORED);
			e1000g_timer_tx_resched(Adapter);
		}
		return;
	}

	link_changed = B_FALSE;
	rw_enter(&Adapter->chip_lock, RW_READER);
	if (Adapter->link_complete)
		link_changed = e1000g_link_check(Adapter);
	rw_exit(&Adapter->chip_lock);

	if (link_changed) {
		if (!Adapter->reset_flag &&
		    (Adapter->e1000g_state & E1000G_STARTED) &&
		    !(Adapter->e1000g_state & E1000G_SUSPENDED))
			mac_link_update(Adapter->mh, Adapter->link_state);
		if (Adapter->link_state == LINK_STATE_UP)
			Adapter->reset_flag = B_FALSE;
	}
	/*
	 * Workaround for esb2. Data stuck in fifo on a link
	 * down event. Reset the adapter to recover it.
	 */
	if (Adapter->esb2_workaround) {
		Adapter->esb2_workaround = B_FALSE;
		(void) e1000g_reset_adapter(Adapter);
		return;
	}

	/*
	 * With 82571 controllers, any locally administered address will
	 * be overwritten when there is a reset on the other port.
	 * Detect this circumstance and correct it.
	 */
	if ((hw->mac.type == e1000_82571) &&
	    (e1000_get_laa_state_82571(hw) == B_TRUE)) {
		ether_addr.reg.low = E1000_READ_REG_ARRAY(hw, E1000_RA, 0);
		ether_addr.reg.high = E1000_READ_REG_ARRAY(hw, E1000_RA, 1);

		ether_addr.reg.low = ntohl(ether_addr.reg.low);
		ether_addr.reg.high = ntohl(ether_addr.reg.high);

		if ((ether_addr.mac.addr[5] != hw->mac.addr[0]) ||
		    (ether_addr.mac.addr[4] != hw->mac.addr[1]) ||
		    (ether_addr.mac.addr[3] != hw->mac.addr[2]) ||
		    (ether_addr.mac.addr[2] != hw->mac.addr[3]) ||
		    (ether_addr.mac.addr[1] != hw->mac.addr[4]) ||
		    (ether_addr.mac.addr[0] != hw->mac.addr[5])) {
			(void) e1000_rar_set(hw, hw->mac.addr, 0);
		}
	}

	/*
	 * Long TTL workaround for 82541/82547
	 */
	(void) e1000_igp_ttl_workaround_82547(hw);

	/*
	 * Check for Adaptive IFS settings If there are lots of collisions
	 * change the value in steps...
	 * These properties should only be set for 10/100
	 */
	if ((hw->phy.media_type == e1000_media_type_copper) &&
	    ((Adapter->link_speed == SPEED_100) ||
	    (Adapter->link_speed == SPEED_10))) {
		e1000_update_adaptive(hw);
	}
	/*
	 * Set Timer Interrupts
	 */
	E1000_WRITE_REG(hw, E1000_ICS, E1000_IMS_RXT0);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
	else
		e1000g_timer_tx_resched(Adapter);

	restart_watchdog_timer(Adapter);
}

/*
 * The function e1000g_link_timer() is called when the timer for link setup
 * is expired, which indicates the completion of the link setup. The link
 * state will not be updated until the link setup is completed. And the
 * link state will not be sent to the upper layer through mac_link_update()
 * in this function. It will be updated in the local timer routine or the
 * interrupt service routine after the interface is started (plumbed).
 */
static void
e1000g_link_timer(void *arg)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	mutex_enter(&Adapter->link_lock);
	Adapter->link_complete = B_TRUE;
	Adapter->link_tid = 0;
	mutex_exit(&Adapter->link_lock);
}

/*
 * e1000g_force_speed_duplex - read forced speed/duplex out of e1000g.conf
 *
 * This function read the forced speed and duplex for 10/100 Mbps speeds
 * and also for 1000 Mbps speeds from the e1000g.conf file
 */
static void
e1000g_force_speed_duplex(struct e1000g *Adapter)
{
	int forced;
	int propval;
	struct e1000_mac_info *mac = &Adapter->shared.mac;
	struct e1000_phy_info *phy = &Adapter->shared.phy;

	/*
	 * get value out of config file
	 */
	(void) e1000g_get_prop(Adapter, "ForceSpeedDuplex",
	    GDIAG_10_HALF, GDIAG_ANY, GDIAG_ANY, &forced);

	switch (forced) {
	case GDIAG_10_HALF:
		/*
		 * Disable Auto Negotiation
		 */
		mac->autoneg = B_FALSE;
		mac->forced_speed_duplex = ADVERTISE_10_HALF;
		break;
	case GDIAG_10_FULL:
		/*
		 * Disable Auto Negotiation
		 */
		mac->autoneg = B_FALSE;
		mac->forced_speed_duplex = ADVERTISE_10_FULL;
		break;
	case GDIAG_100_HALF:
		/*
		 * Disable Auto Negotiation
		 */
		mac->autoneg = B_FALSE;
		mac->forced_speed_duplex = ADVERTISE_100_HALF;
		break;
	case GDIAG_100_FULL:
		/*
		 * Disable Auto Negotiation
		 */
		mac->autoneg = B_FALSE;
		mac->forced_speed_duplex = ADVERTISE_100_FULL;
		break;
	case GDIAG_1000_FULL:
		/*
		 * The gigabit spec requires autonegotiation.  Therefore,
		 * when the user wants to force the speed to 1000Mbps, we
		 * enable AutoNeg, but only allow the harware to advertise
		 * 1000Mbps.  This is different from 10/100 operation, where
		 * we are allowed to link without any negotiation.
		 */
		mac->autoneg = B_TRUE;
		phy->autoneg_advertised = ADVERTISE_1000_FULL;
		break;
	default:	/* obey the setting of AutoNegAdvertised */
		mac->autoneg = B_TRUE;
		(void) e1000g_get_prop(Adapter, "AutoNegAdvertised",
		    0, AUTONEG_ADVERTISE_SPEED_DEFAULT,
		    AUTONEG_ADVERTISE_SPEED_DEFAULT, &propval);
		phy->autoneg_advertised = (uint16_t)propval;
		break;
	}	/* switch */
}

/*
 * e1000g_get_max_frame_size - get jumbo frame setting from e1000g.conf
 *
 * This function reads MaxFrameSize from e1000g.conf
 */
static void
e1000g_get_max_frame_size(struct e1000g *Adapter)
{
	int max_frame;

	/*
	 * get value out of config file
	 */
	(void) e1000g_get_prop(Adapter, "MaxFrameSize", 0, 3, 0,
	    &max_frame);

	switch (max_frame) {
	case 0:
		Adapter->default_mtu = ETHERMTU;
		break;
	case 1:
		Adapter->default_mtu = FRAME_SIZE_UPTO_4K -
		    sizeof (struct ether_vlan_header) - ETHERFCSL;
		break;
	case 2:
		Adapter->default_mtu = FRAME_SIZE_UPTO_8K -
		    sizeof (struct ether_vlan_header) - ETHERFCSL;
		break;
	case 3:
		Adapter->default_mtu = FRAME_SIZE_UPTO_16K -
		    sizeof (struct ether_vlan_header) - ETHERFCSL;
		break;
	default:
		Adapter->default_mtu = ETHERMTU;
		break;
	}	/* switch */

	/*
	 * If the user configed MTU is larger than the deivce's maximum MTU,
	 * the MTU is set to the deivce's maximum value.
	 */
	if (Adapter->default_mtu > Adapter->max_mtu)
		Adapter->default_mtu = Adapter->max_mtu;

	Adapter->max_frame_size = e1000g_mtu2maxframe(Adapter->default_mtu);
}

/*
 * e1000g_pch_limits - Apply limits of the PCH silicon type
 *
 * At any frame size larger than the ethernet default,
 * prevent linking at 10/100 speeds.
 */
static void
e1000g_pch_limits(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;

	/* only applies to PCH silicon type */
	if (hw->mac.type != e1000_pchlan && hw->mac.type != e1000_pch2lan)
		return;

	/* only applies to frames larger than ethernet default */
	if (Adapter->max_frame_size > DEFAULT_FRAME_SIZE) {
		hw->mac.autoneg = B_TRUE;
		hw->phy.autoneg_advertised = ADVERTISE_1000_FULL;

		Adapter->param_adv_autoneg = 1;
		Adapter->param_adv_1000fdx = 1;

		Adapter->param_adv_100fdx = 0;
		Adapter->param_adv_100hdx = 0;
		Adapter->param_adv_10fdx = 0;
		Adapter->param_adv_10hdx = 0;

		e1000g_param_sync(Adapter);
	}
}

/*
 * e1000g_mtu2maxframe - convert given MTU to maximum frame size
 */
static uint32_t
e1000g_mtu2maxframe(uint32_t mtu)
{
	uint32_t maxframe;

	maxframe = mtu + sizeof (struct ether_vlan_header) + ETHERFCSL;

	return (maxframe);
}

static void
arm_watchdog_timer(struct e1000g *Adapter)
{
	Adapter->watchdog_tid =
	    timeout(e1000g_local_timer,
	    (void *)Adapter, 1 * drv_usectohz(1000000));
}
#pragma inline(arm_watchdog_timer)

static void
enable_watchdog_timer(struct e1000g *Adapter)
{
	mutex_enter(&Adapter->watchdog_lock);

	if (!Adapter->watchdog_timer_enabled) {
		Adapter->watchdog_timer_enabled = B_TRUE;
		Adapter->watchdog_timer_started = B_TRUE;
		arm_watchdog_timer(Adapter);
	}

	mutex_exit(&Adapter->watchdog_lock);
}

static void
disable_watchdog_timer(struct e1000g *Adapter)
{
	timeout_id_t tid;

	mutex_enter(&Adapter->watchdog_lock);

	Adapter->watchdog_timer_enabled = B_FALSE;
	Adapter->watchdog_timer_started = B_FALSE;
	tid = Adapter->watchdog_tid;
	Adapter->watchdog_tid = 0;

	mutex_exit(&Adapter->watchdog_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

static void
start_watchdog_timer(struct e1000g *Adapter)
{
	mutex_enter(&Adapter->watchdog_lock);

	if (Adapter->watchdog_timer_enabled) {
		if (!Adapter->watchdog_timer_started) {
			Adapter->watchdog_timer_started = B_TRUE;
			arm_watchdog_timer(Adapter);
		}
	}

	mutex_exit(&Adapter->watchdog_lock);
}

static void
restart_watchdog_timer(struct e1000g *Adapter)
{
	mutex_enter(&Adapter->watchdog_lock);

	if (Adapter->watchdog_timer_started)
		arm_watchdog_timer(Adapter);

	mutex_exit(&Adapter->watchdog_lock);
}

static void
stop_watchdog_timer(struct e1000g *Adapter)
{
	timeout_id_t tid;

	mutex_enter(&Adapter->watchdog_lock);

	Adapter->watchdog_timer_started = B_FALSE;
	tid = Adapter->watchdog_tid;
	Adapter->watchdog_tid = 0;

	mutex_exit(&Adapter->watchdog_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

static void
stop_link_timer(struct e1000g *Adapter)
{
	timeout_id_t tid;

	/* Disable the link timer */
	mutex_enter(&Adapter->link_lock);

	tid = Adapter->link_tid;
	Adapter->link_tid = 0;

	mutex_exit(&Adapter->link_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

static void
stop_82547_timer(e1000g_tx_ring_t *tx_ring)
{
	timeout_id_t tid;

	/* Disable the tx timer for 82547 chipset */
	mutex_enter(&tx_ring->tx_lock);

	tx_ring->timer_enable_82547 = B_FALSE;
	tid = tx_ring->timer_id_82547;
	tx_ring->timer_id_82547 = 0;

	mutex_exit(&tx_ring->tx_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

void
e1000g_clear_interrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->shared, E1000_IMC,
	    0xffffffff & ~E1000_IMS_RXSEQ);
}

void
e1000g_mask_interrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->shared, E1000_IMS,
	    IMS_ENABLE_MASK & ~E1000_IMS_TXDW);

	if (Adapter->tx_intr_enable)
		e1000g_mask_tx_interrupt(Adapter);
}

/*
 * This routine is called by e1000g_quiesce(), therefore must not block.
 */
void
e1000g_clear_all_interrupts(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->shared, E1000_IMC, 0xffffffff);
}

void
e1000g_mask_tx_interrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->shared, E1000_IMS, E1000_IMS_TXDW);
}

void
e1000g_clear_tx_interrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->shared, E1000_IMC, E1000_IMS_TXDW);
}

static void
e1000g_smartspeed(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	uint16_t phy_status;
	uint16_t phy_ctrl;

	/*
	 * If we're not T-or-T, or we're not autoneg'ing, or we're not
	 * advertising 1000Full, we don't even use the workaround
	 */
	if ((hw->phy.type != e1000_phy_igp) ||
	    !hw->mac.autoneg ||
	    !(hw->phy.autoneg_advertised & ADVERTISE_1000_FULL))
		return;

	/*
	 * True if this is the first call of this function or after every
	 * 30 seconds of not having link
	 */
	if (Adapter->smartspeed == 0) {
		/*
		 * If Master/Slave config fault is asserted twice, we
		 * assume back-to-back
		 */
		(void) e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT))
			return;

		(void) e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT))
			return;
		/*
		 * We're assuming back-2-back because our status register
		 * insists! there's a fault in the master/slave
		 * relationship that was "negotiated"
		 */
		(void) e1000_read_phy_reg(hw, PHY_1000T_CTRL, &phy_ctrl);
		/*
		 * Is the phy configured for manual configuration of
		 * master/slave?
		 */
		if (phy_ctrl & CR_1000T_MS_ENABLE) {
			/*
			 * Yes.  Then disable manual configuration (enable
			 * auto configuration) of master/slave
			 */
			phy_ctrl &= ~CR_1000T_MS_ENABLE;
			(void) e1000_write_phy_reg(hw,
			    PHY_1000T_CTRL, phy_ctrl);
			/*
			 * Effectively starting the clock
			 */
			Adapter->smartspeed++;
			/*
			 * Restart autonegotiation
			 */
			if (!e1000_phy_setup_autoneg(hw) &&
			    !e1000_read_phy_reg(hw, PHY_CONTROL, &phy_ctrl)) {
				phy_ctrl |= (MII_CR_AUTO_NEG_EN |
				    MII_CR_RESTART_AUTO_NEG);
				(void) e1000_write_phy_reg(hw,
				    PHY_CONTROL, phy_ctrl);
			}
		}
		return;
		/*
		 * Has 6 seconds transpired still without link? Remember,
		 * you should reset the smartspeed counter once you obtain
		 * link
		 */
	} else if (Adapter->smartspeed == E1000_SMARTSPEED_DOWNSHIFT) {
		/*
		 * Yes.  Remember, we did at the start determine that
		 * there's a master/slave configuration fault, so we're
		 * still assuming there's someone on the other end, but we
		 * just haven't yet been able to talk to it. We then
		 * re-enable auto configuration of master/slave to see if
		 * we're running 2/3 pair cables.
		 */
		/*
		 * If still no link, perhaps using 2/3 pair cable
		 */
		(void) e1000_read_phy_reg(hw, PHY_1000T_CTRL, &phy_ctrl);
		phy_ctrl |= CR_1000T_MS_ENABLE;
		(void) e1000_write_phy_reg(hw, PHY_1000T_CTRL, phy_ctrl);
		/*
		 * Restart autoneg with phy enabled for manual
		 * configuration of master/slave
		 */
		if (!e1000_phy_setup_autoneg(hw) &&
		    !e1000_read_phy_reg(hw, PHY_CONTROL, &phy_ctrl)) {
			phy_ctrl |=
			    (MII_CR_AUTO_NEG_EN | MII_CR_RESTART_AUTO_NEG);
			(void) e1000_write_phy_reg(hw, PHY_CONTROL, phy_ctrl);
		}
		/*
		 * Hopefully, there are no more faults and we've obtained
		 * link as a result.
		 */
	}
	/*
	 * Restart process after E1000_SMARTSPEED_MAX iterations (30
	 * seconds)
	 */
	if (Adapter->smartspeed++ == E1000_SMARTSPEED_MAX)
		Adapter->smartspeed = 0;
}

static boolean_t
is_valid_mac_addr(uint8_t *mac_addr)
{
	const uint8_t addr_test1[6] = { 0, 0, 0, 0, 0, 0 };
	const uint8_t addr_test2[6] =
	    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	if (!(bcmp(addr_test1, mac_addr, ETHERADDRL)) ||
	    !(bcmp(addr_test2, mac_addr, ETHERADDRL)))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * e1000g_stall_check - check for tx stall
 *
 * This function checks if the adapter is stalled (in transmit).
 *
 * It is called each time the watchdog timeout is invoked.
 * If the transmit descriptor reclaim continuously fails,
 * the watchdog value will increment by 1. If the watchdog
 * value exceeds the threshold, the adapter is assumed to
 * have stalled and need to be reset.
 */
static boolean_t
e1000g_stall_check(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;

	tx_ring = Adapter->tx_ring;

	if (Adapter->link_state != LINK_STATE_UP)
		return (B_FALSE);

	(void) e1000g_recycle(tx_ring);

	if (Adapter->stall_flag)
		return (B_TRUE);

	return (B_FALSE);
}

#ifdef E1000G_DEBUG
static enum ioc_reply
e1000g_pp_ioctl(struct e1000g *e1000gp, struct iocblk *iocp, mblk_t *mp)
{
	void (*ppfn)(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd);
	e1000g_peekpoke_t *ppd;
	uint64_t mem_va;
	uint64_t maxoff;
	boolean_t peek;

	switch (iocp->ioc_cmd) {

	case E1000G_IOC_REG_PEEK:
		peek = B_TRUE;
		break;

	case E1000G_IOC_REG_POKE:
		peek = B_FALSE;
		break;

	deault:
		E1000G_DEBUGLOG_1(e1000gp, E1000G_INFO_LEVEL,
		    "e1000g_diag_ioctl: invalid ioctl command 0x%X\n",
		    iocp->ioc_cmd);
		return (IOC_INVAL);
	}

	/*
	 * Validate format of ioctl
	 */
	if (iocp->ioc_count != sizeof (e1000g_peekpoke_t))
		return (IOC_INVAL);
	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	ppd = (e1000g_peekpoke_t *)(uintptr_t)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters
	 */
	switch (ppd->pp_acc_space) {

	default:
		E1000G_DEBUGLOG_1(e1000gp, E1000G_INFO_LEVEL,
		    "e1000g_diag_ioctl: invalid access space 0x%X\n",
		    ppd->pp_acc_space);
		return (IOC_INVAL);

	case E1000G_PP_SPACE_REG:
		/*
		 * Memory-mapped I/O space
		 */
		ASSERT(ppd->pp_acc_size == 4);
		if (ppd->pp_acc_size != 4)
			return (IOC_INVAL);

		if ((ppd->pp_acc_offset % ppd->pp_acc_size) != 0)
			return (IOC_INVAL);

		mem_va = 0;
		maxoff = 0x10000;
		ppfn = peek ? e1000g_ioc_peek_reg : e1000g_ioc_poke_reg;
		break;

	case E1000G_PP_SPACE_E1000G:
		/*
		 * E1000g data structure!
		 */
		mem_va = (uintptr_t)e1000gp;
		maxoff = sizeof (struct e1000g);
		ppfn = peek ? e1000g_ioc_peek_mem : e1000g_ioc_poke_mem;
		break;

	}

	if (ppd->pp_acc_offset >= maxoff)
		return (IOC_INVAL);

	if (ppd->pp_acc_offset + ppd->pp_acc_size > maxoff)
		return (IOC_INVAL);

	/*
	 * All OK - go!
	 */
	ppd->pp_acc_offset += mem_va;
	(*ppfn)(e1000gp, ppd);
	return (peek ? IOC_REPLY : IOC_ACK);
}

static void
e1000g_ioc_peek_reg(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd)
{
	ddi_acc_handle_t handle;
	uint32_t *regaddr;

	handle = e1000gp->osdep.reg_handle;
	regaddr = (uint32_t *)((uintptr_t)e1000gp->shared.hw_addr +
	    (uintptr_t)ppd->pp_acc_offset);

	ppd->pp_acc_data = ddi_get32(handle, regaddr);
}

static void
e1000g_ioc_poke_reg(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd)
{
	ddi_acc_handle_t handle;
	uint32_t *regaddr;
	uint32_t value;

	handle = e1000gp->osdep.reg_handle;
	regaddr = (uint32_t *)((uintptr_t)e1000gp->shared.hw_addr +
	    (uintptr_t)ppd->pp_acc_offset);
	value = (uint32_t)ppd->pp_acc_data;

	ddi_put32(handle, regaddr, value);
}

static void
e1000g_ioc_peek_mem(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd)
{
	uint64_t value;
	void *vaddr;

	vaddr = (void *)(uintptr_t)ppd->pp_acc_offset;

	switch (ppd->pp_acc_size) {
	case 1:
		value = *(uint8_t *)vaddr;
		break;

	case 2:
		value = *(uint16_t *)vaddr;
		break;

	case 4:
		value = *(uint32_t *)vaddr;
		break;

	case 8:
		value = *(uint64_t *)vaddr;
		break;
	}

	E1000G_DEBUGLOG_4(e1000gp, E1000G_INFO_LEVEL,
	    "e1000g_ioc_peek_mem($%p, $%p) peeked 0x%llx from $%p\n",
	    (void *)e1000gp, (void *)ppd, value, vaddr);

	ppd->pp_acc_data = value;
}

static void
e1000g_ioc_poke_mem(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd)
{
	uint64_t value;
	void *vaddr;

	vaddr = (void *)(uintptr_t)ppd->pp_acc_offset;
	value = ppd->pp_acc_data;

	E1000G_DEBUGLOG_4(e1000gp, E1000G_INFO_LEVEL,
	    "e1000g_ioc_poke_mem($%p, $%p) poking 0x%llx at $%p\n",
	    (void *)e1000gp, (void *)ppd, value, vaddr);

	switch (ppd->pp_acc_size) {
	case 1:
		*(uint8_t *)vaddr = (uint8_t)value;
		break;

	case 2:
		*(uint16_t *)vaddr = (uint16_t)value;
		break;

	case 4:
		*(uint32_t *)vaddr = (uint32_t)value;
		break;

	case 8:
		*(uint64_t *)vaddr = (uint64_t)value;
		break;
	}
}
#endif

/*
 * Loopback Support
 */
static lb_property_t lb_normal =
	{ normal,	"normal",	E1000G_LB_NONE		};
static lb_property_t lb_external1000 =
	{ external,	"1000Mbps",	E1000G_LB_EXTERNAL_1000	};
static lb_property_t lb_external100 =
	{ external,	"100Mbps",	E1000G_LB_EXTERNAL_100	};
static lb_property_t lb_external10 =
	{ external,	"10Mbps",	E1000G_LB_EXTERNAL_10	};
static lb_property_t lb_phy =
	{ internal,	"PHY",		E1000G_LB_INTERNAL_PHY	};

static enum ioc_reply
e1000g_loopback_ioctl(struct e1000g *Adapter, struct iocblk *iocp, mblk_t *mp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	struct e1000_hw *hw;
	uint32_t *lbmp;
	uint32_t size;
	uint32_t value;

	hw = &Adapter->shared;

	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	if (!e1000g_check_loopback_support(hw)) {
		e1000g_log(NULL, CE_WARN,
		    "Loopback is not supported on e1000g%d", Adapter->instance);
		return (IOC_INVAL);
	}

	switch (iocp->ioc_cmd) {
	default:
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		size = sizeof (lb_info_sz_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		rw_enter(&Adapter->chip_lock, RW_WRITER);
		e1000g_get_phy_state(Adapter);

		/*
		 * Workaround for hardware faults. In order to get a stable
		 * state of phy, we will wait for a specific interval and
		 * try again. The time delay is an experiential value based
		 * on our testing.
		 */
		msec_delay(100);
		e1000g_get_phy_state(Adapter);
		rw_exit(&Adapter->chip_lock);

		value = sizeof (lb_normal);
		if ((Adapter->phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (Adapter->phy_ext_status & IEEE_ESR_1000X_FD_CAPS) ||
		    (hw->phy.media_type == e1000_media_type_fiber) ||
		    (hw->phy.media_type == e1000_media_type_internal_serdes)) {
			value += sizeof (lb_phy);
			switch (hw->mac.type) {
			case e1000_82571:
			case e1000_82572:
			case e1000_80003es2lan:
				value += sizeof (lb_external1000);
				break;
			}
		}
		if ((Adapter->phy_status & MII_SR_100X_FD_CAPS) ||
		    (Adapter->phy_status & MII_SR_100T2_FD_CAPS))
			value += sizeof (lb_external100);
		if (Adapter->phy_status & MII_SR_10T_FD_CAPS)
			value += sizeof (lb_external10);

		lbsp = (lb_info_sz_t *)(uintptr_t)mp->b_cont->b_rptr;
		*lbsp = value;
		break;

	case LB_GET_INFO:
		value = sizeof (lb_normal);
		if ((Adapter->phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (Adapter->phy_ext_status & IEEE_ESR_1000X_FD_CAPS) ||
		    (hw->phy.media_type == e1000_media_type_fiber) ||
		    (hw->phy.media_type == e1000_media_type_internal_serdes)) {
			value += sizeof (lb_phy);
			switch (hw->mac.type) {
			case e1000_82571:
			case e1000_82572:
			case e1000_80003es2lan:
				value += sizeof (lb_external1000);
				break;
			}
		}
		if ((Adapter->phy_status & MII_SR_100X_FD_CAPS) ||
		    (Adapter->phy_status & MII_SR_100T2_FD_CAPS))
			value += sizeof (lb_external100);
		if (Adapter->phy_status & MII_SR_10T_FD_CAPS)
			value += sizeof (lb_external10);

		size = value;
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		value = 0;
		lbpp = (lb_property_t *)(uintptr_t)mp->b_cont->b_rptr;
		lbpp[value++] = lb_normal;
		if ((Adapter->phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (Adapter->phy_ext_status & IEEE_ESR_1000X_FD_CAPS) ||
		    (hw->phy.media_type == e1000_media_type_fiber) ||
		    (hw->phy.media_type == e1000_media_type_internal_serdes)) {
			lbpp[value++] = lb_phy;
			switch (hw->mac.type) {
			case e1000_82571:
			case e1000_82572:
			case e1000_80003es2lan:
				lbpp[value++] = lb_external1000;
				break;
			}
		}
		if ((Adapter->phy_status & MII_SR_100X_FD_CAPS) ||
		    (Adapter->phy_status & MII_SR_100T2_FD_CAPS))
			lbpp[value++] = lb_external100;
		if (Adapter->phy_status & MII_SR_10T_FD_CAPS)
			lbpp[value++] = lb_external10;
		break;

	case LB_GET_MODE:
		size = sizeof (uint32_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		lbmp = (uint32_t *)(uintptr_t)mp->b_cont->b_rptr;
		*lbmp = Adapter->loopback_mode;
		break;

	case LB_SET_MODE:
		size = 0;
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);

		lbmp = (uint32_t *)(uintptr_t)mp->b_cont->b_rptr;
		if (!e1000g_set_loopback_mode(Adapter, *lbmp))
			return (IOC_INVAL);
		break;
	}

	iocp->ioc_count = size;
	iocp->ioc_error = 0;

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
		return (IOC_INVAL);
	}

	return (IOC_REPLY);
}

static boolean_t
e1000g_check_loopback_support(struct e1000_hw *hw)
{
	switch (hw->mac.type) {
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
	case e1000_82541:
	case e1000_82541_rev_2:
	case e1000_82547:
	case e1000_82547_rev_2:
	case e1000_82571:
	case e1000_82572:
	case e1000_82573:
	case e1000_82574:
	case e1000_80003es2lan:
	case e1000_ich9lan:
	case e1000_ich10lan:
		return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
e1000g_set_loopback_mode(struct e1000g *Adapter, uint32_t mode)
{
	struct e1000_hw *hw;
	int i, times;
	boolean_t link_up;

	if (mode == Adapter->loopback_mode)
		return (B_TRUE);

	hw = &Adapter->shared;
	times = 0;

	Adapter->loopback_mode = mode;

	if (mode == E1000G_LB_NONE) {
		/* Reset the chip */
		hw->phy.autoneg_wait_to_complete = B_TRUE;
		(void) e1000g_reset_adapter(Adapter);
		hw->phy.autoneg_wait_to_complete = B_FALSE;
		return (B_TRUE);
	}

again:

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	switch (mode) {
	default:
		rw_exit(&Adapter->chip_lock);
		return (B_FALSE);

	case E1000G_LB_EXTERNAL_1000:
		e1000g_set_external_loopback_1000(Adapter);
		break;

	case E1000G_LB_EXTERNAL_100:
		e1000g_set_external_loopback_100(Adapter);
		break;

	case E1000G_LB_EXTERNAL_10:
		e1000g_set_external_loopback_10(Adapter);
		break;

	case E1000G_LB_INTERNAL_PHY:
		e1000g_set_internal_loopback(Adapter);
		break;
	}

	times++;

	rw_exit(&Adapter->chip_lock);

	/* Wait for link up */
	for (i = (PHY_FORCE_LIMIT * 2); i > 0; i--)
		msec_delay(100);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	link_up = e1000g_link_up(Adapter);

	rw_exit(&Adapter->chip_lock);

	if (!link_up) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
		    "Failed to get the link up");
		if (times < 2) {
			/* Reset the link */
			E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
			    "Reset the link ...");
			(void) e1000g_reset_adapter(Adapter);
			goto again;
		}

		/*
		 * Reset driver to loopback none when set loopback failed
		 * for the second time.
		 */
		Adapter->loopback_mode = E1000G_LB_NONE;

		/* Reset the chip */
		hw->phy.autoneg_wait_to_complete = B_TRUE;
		(void) e1000g_reset_adapter(Adapter);
		hw->phy.autoneg_wait_to_complete = B_FALSE;

		E1000G_DEBUGLOG_0(Adapter, E1000G_INFO_LEVEL,
		    "Set loopback mode failed, reset to loopback none");

		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * The following loopback settings are from Intel's technical
 * document - "How To Loopback". All the register settings and
 * time delay values are directly inherited from the document
 * without more explanations available.
 */
static void
e1000g_set_internal_loopback(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	uint32_t ctrl;
	uint32_t status;
	uint16_t phy_ctrl;
	uint16_t phy_reg;
	uint32_t txcw;

	hw = &Adapter->shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	(void) e1000_read_phy_reg(hw, PHY_CONTROL, &phy_ctrl);
	phy_ctrl &= ~(MII_CR_AUTO_NEG_EN | MII_CR_SPEED_100 | MII_CR_SPEED_10);
	phy_ctrl |= MII_CR_FULL_DUPLEX | MII_CR_SPEED_1000;

	switch (hw->mac.type) {
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
	case e1000_82573:
		/* Auto-MDI/MDIX off */
		(void) e1000_write_phy_reg(hw, M88E1000_PHY_SPEC_CTRL, 0x0808);
		/* Reset PHY to update Auto-MDI/MDIX */
		(void) e1000_write_phy_reg(hw, PHY_CONTROL,
		    phy_ctrl | MII_CR_RESET | MII_CR_AUTO_NEG_EN);
		/* Reset PHY to auto-neg off and force 1000 */
		(void) e1000_write_phy_reg(hw, PHY_CONTROL,
		    phy_ctrl | MII_CR_RESET);
		/*
		 * Disable PHY receiver for 82540/545/546 and 82573 Family.
		 * See comments above e1000g_set_internal_loopback() for the
		 * background.
		 */
		(void) e1000_write_phy_reg(hw, 29, 0x001F);
		(void) e1000_write_phy_reg(hw, 30, 0x8FFC);
		(void) e1000_write_phy_reg(hw, 29, 0x001A);
		(void) e1000_write_phy_reg(hw, 30, 0x8FF0);
		break;
	case e1000_80003es2lan:
		/* Force Link Up */
		(void) e1000_write_phy_reg(hw, GG82563_PHY_KMRN_MODE_CTRL,
		    0x1CC);
		/* Sets PCS loopback at 1Gbs */
		(void) e1000_write_phy_reg(hw, GG82563_PHY_MAC_SPEC_CTRL,
		    0x1046);
		break;
	}

	/*
	 * The following registers should be set for e1000_phy_bm phy type.
	 * e1000_82574, e1000_ich10lan and some e1000_ich9lan use this phy.
	 * For others, we do not need to set these registers.
	 */
	if (hw->phy.type == e1000_phy_bm) {
		/* Set Default MAC Interface speed to 1GB */
		(void) e1000_read_phy_reg(hw, PHY_REG(2, 21), &phy_reg);
		phy_reg &= ~0x0007;
		phy_reg |= 0x006;
		(void) e1000_write_phy_reg(hw, PHY_REG(2, 21), phy_reg);
		/* Assert SW reset for above settings to take effect */
		(void) e1000_phy_commit(hw);
		msec_delay(1);
		/* Force Full Duplex */
		(void) e1000_read_phy_reg(hw, PHY_REG(769, 16), &phy_reg);
		(void) e1000_write_phy_reg(hw, PHY_REG(769, 16),
		    phy_reg | 0x000C);
		/* Set Link Up (in force link) */
		(void) e1000_read_phy_reg(hw, PHY_REG(776, 16), &phy_reg);
		(void) e1000_write_phy_reg(hw, PHY_REG(776, 16),
		    phy_reg | 0x0040);
		/* Force Link */
		(void) e1000_read_phy_reg(hw, PHY_REG(769, 16), &phy_reg);
		(void) e1000_write_phy_reg(hw, PHY_REG(769, 16),
		    phy_reg | 0x0040);
		/* Set Early Link Enable */
		(void) e1000_read_phy_reg(hw, PHY_REG(769, 20), &phy_reg);
		(void) e1000_write_phy_reg(hw, PHY_REG(769, 20),
		    phy_reg | 0x0400);
	}

	/* Set loopback */
	(void) e1000_write_phy_reg(hw, PHY_CONTROL, phy_ctrl | MII_CR_LOOPBACK);

	msec_delay(250);

	/* Now set up the MAC to the same speed/duplex as the PHY. */
	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	ctrl &= ~E1000_CTRL_SPD_SEL;	/* Clear the speed sel bits */
	ctrl |= (E1000_CTRL_FRCSPD |	/* Set the Force Speed Bit */
	    E1000_CTRL_FRCDPX |		/* Set the Force Duplex Bit */
	    E1000_CTRL_SPD_1000 |	/* Force Speed to 1000 */
	    E1000_CTRL_FD);		/* Force Duplex to FULL */

	switch (hw->mac.type) {
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
		/*
		 * For some serdes we'll need to commit the writes now
		 * so that the status is updated on link
		 */
		if (hw->phy.media_type == e1000_media_type_internal_serdes) {
			E1000_WRITE_REG(hw, E1000_CTRL, ctrl);
			msec_delay(100);
			ctrl = E1000_READ_REG(hw, E1000_CTRL);
		}

		if (hw->phy.media_type == e1000_media_type_copper) {
			/* Invert Loss of Signal */
			ctrl |= E1000_CTRL_ILOS;
		} else {
			/* Set ILOS on fiber nic if half duplex is detected */
			status = E1000_READ_REG(hw, E1000_STATUS);
			if ((status & E1000_STATUS_FD) == 0)
				ctrl |= E1000_CTRL_ILOS | E1000_CTRL_SLU;
		}
		break;

	case e1000_82571:
	case e1000_82572:
		/*
		 * The fiber/SerDes versions of this adapter do not contain an
		 * accessible PHY. Therefore, loopback beyond MAC must be done
		 * using SerDes analog loopback.
		 */
		if (hw->phy.media_type != e1000_media_type_copper) {
			/* Disable autoneg by setting bit 31 of TXCW to zero */
			txcw = E1000_READ_REG(hw, E1000_TXCW);
			txcw &= ~((uint32_t)1 << 31);
			E1000_WRITE_REG(hw, E1000_TXCW, txcw);

			/*
			 * Write 0x410 to Serdes Control register
			 * to enable Serdes analog loopback
			 */
			E1000_WRITE_REG(hw, E1000_SCTL, 0x0410);
			msec_delay(10);
		}

		status = E1000_READ_REG(hw, E1000_STATUS);
		/* Set ILOS on fiber nic if half duplex is detected */
		if ((hw->phy.media_type == e1000_media_type_fiber) &&
		    ((status & E1000_STATUS_FD) == 0 ||
		    (status & E1000_STATUS_LU) == 0))
			ctrl |= E1000_CTRL_ILOS | E1000_CTRL_SLU;
		else if (hw->phy.media_type == e1000_media_type_internal_serdes)
			ctrl |= E1000_CTRL_SLU;
		break;

	case e1000_82573:
		ctrl |= E1000_CTRL_ILOS;
		break;
	case e1000_ich9lan:
	case e1000_ich10lan:
		ctrl |= E1000_CTRL_SLU;
		break;
	}
	if (hw->phy.type == e1000_phy_bm)
		ctrl |= E1000_CTRL_SLU | E1000_CTRL_ILOS;

	E1000_WRITE_REG(hw, E1000_CTRL, ctrl);
}

static void
e1000g_set_external_loopback_1000(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	uint32_t rctl;
	uint32_t ctrl_ext;
	uint32_t ctrl;
	uint32_t status;
	uint32_t txcw;
	uint16_t phydata;

	hw = &Adapter->shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	switch (hw->mac.type) {
	case e1000_82571:
	case e1000_82572:
		switch (hw->phy.media_type) {
		case e1000_media_type_copper:
			/* Force link up (Must be done before the PHY writes) */
			ctrl = E1000_READ_REG(hw, E1000_CTRL);
			ctrl |= E1000_CTRL_SLU;	/* Force Link Up */
			E1000_WRITE_REG(hw, E1000_CTRL, ctrl);

			rctl = E1000_READ_REG(hw, E1000_RCTL);
			rctl |= (E1000_RCTL_EN |
			    E1000_RCTL_SBP |
			    E1000_RCTL_UPE |
			    E1000_RCTL_MPE |
			    E1000_RCTL_LPE |
			    E1000_RCTL_BAM);		/* 0x803E */
			E1000_WRITE_REG(hw, E1000_RCTL, rctl);

			ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
			ctrl_ext |= (E1000_CTRL_EXT_SDP4_DATA |
			    E1000_CTRL_EXT_SDP6_DATA |
			    E1000_CTRL_EXT_SDP3_DATA |
			    E1000_CTRL_EXT_SDP4_DIR |
			    E1000_CTRL_EXT_SDP6_DIR |
			    E1000_CTRL_EXT_SDP3_DIR);	/* 0x0DD0 */
			E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);

			/*
			 * This sequence tunes the PHY's SDP and no customer
			 * settable values. For background, see comments above
			 * e1000g_set_internal_loopback().
			 */
			(void) e1000_write_phy_reg(hw, 0x0, 0x140);
			msec_delay(10);
			(void) e1000_write_phy_reg(hw, 0x9, 0x1A00);
			(void) e1000_write_phy_reg(hw, 0x12, 0xC10);
			(void) e1000_write_phy_reg(hw, 0x12, 0x1C10);
			(void) e1000_write_phy_reg(hw, 0x1F37, 0x76);
			(void) e1000_write_phy_reg(hw, 0x1F33, 0x1);
			(void) e1000_write_phy_reg(hw, 0x1F33, 0x0);

			(void) e1000_write_phy_reg(hw, 0x1F35, 0x65);
			(void) e1000_write_phy_reg(hw, 0x1837, 0x3F7C);
			(void) e1000_write_phy_reg(hw, 0x1437, 0x3FDC);
			(void) e1000_write_phy_reg(hw, 0x1237, 0x3F7C);
			(void) e1000_write_phy_reg(hw, 0x1137, 0x3FDC);

			msec_delay(50);
			break;
		case e1000_media_type_fiber:
		case e1000_media_type_internal_serdes:
			status = E1000_READ_REG(hw, E1000_STATUS);
			if (((status & E1000_STATUS_LU) == 0) ||
			    (hw->phy.media_type ==
			    e1000_media_type_internal_serdes)) {
				ctrl = E1000_READ_REG(hw, E1000_CTRL);
				ctrl |= E1000_CTRL_ILOS | E1000_CTRL_SLU;
				E1000_WRITE_REG(hw, E1000_CTRL, ctrl);
			}

			/* Disable autoneg by setting bit 31 of TXCW to zero */
			txcw = E1000_READ_REG(hw, E1000_TXCW);
			txcw &= ~((uint32_t)1 << 31);
			E1000_WRITE_REG(hw, E1000_TXCW, txcw);

			/*
			 * Write 0x410 to Serdes Control register
			 * to enable Serdes analog loopback
			 */
			E1000_WRITE_REG(hw, E1000_SCTL, 0x0410);
			msec_delay(10);
			break;
		default:
			break;
		}
		break;
	case e1000_82574:
	case e1000_80003es2lan:
	case e1000_ich9lan:
	case e1000_ich10lan:
		(void) e1000_read_phy_reg(hw, GG82563_REG(6, 16), &phydata);
		(void) e1000_write_phy_reg(hw, GG82563_REG(6, 16),
		    phydata | (1 << 5));
		Adapter->param_adv_autoneg = 1;
		Adapter->param_adv_1000fdx = 1;
		(void) e1000g_reset_link(Adapter);
		break;
	}
}

static void
e1000g_set_external_loopback_100(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	uint32_t ctrl;
	uint16_t phy_ctrl;

	hw = &Adapter->shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	phy_ctrl = (MII_CR_FULL_DUPLEX |
	    MII_CR_SPEED_100);

	/* Force 100/FD, reset PHY */
	(void) e1000_write_phy_reg(hw, PHY_CONTROL,
	    phy_ctrl | MII_CR_RESET);	/* 0xA100 */
	msec_delay(10);

	/* Force 100/FD */
	(void) e1000_write_phy_reg(hw, PHY_CONTROL,
	    phy_ctrl);			/* 0x2100 */
	msec_delay(10);

	/* Now setup the MAC to the same speed/duplex as the PHY. */
	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	ctrl &= ~E1000_CTRL_SPD_SEL;	/* Clear the speed sel bits */
	ctrl |= (E1000_CTRL_SLU |	/* Force Link Up */
	    E1000_CTRL_FRCSPD |		/* Set the Force Speed Bit */
	    E1000_CTRL_FRCDPX |		/* Set the Force Duplex Bit */
	    E1000_CTRL_SPD_100 |	/* Force Speed to 100 */
	    E1000_CTRL_FD);		/* Force Duplex to FULL */

	E1000_WRITE_REG(hw, E1000_CTRL, ctrl);
}

static void
e1000g_set_external_loopback_10(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	uint32_t ctrl;
	uint16_t phy_ctrl;

	hw = &Adapter->shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	phy_ctrl = (MII_CR_FULL_DUPLEX |
	    MII_CR_SPEED_10);

	/* Force 10/FD, reset PHY */
	(void) e1000_write_phy_reg(hw, PHY_CONTROL,
	    phy_ctrl | MII_CR_RESET);	/* 0x8100 */
	msec_delay(10);

	/* Force 10/FD */
	(void) e1000_write_phy_reg(hw, PHY_CONTROL,
	    phy_ctrl);			/* 0x0100 */
	msec_delay(10);

	/* Now setup the MAC to the same speed/duplex as the PHY. */
	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	ctrl &= ~E1000_CTRL_SPD_SEL;	/* Clear the speed sel bits */
	ctrl |= (E1000_CTRL_SLU |	/* Force Link Up */
	    E1000_CTRL_FRCSPD |		/* Set the Force Speed Bit */
	    E1000_CTRL_FRCDPX |		/* Set the Force Duplex Bit */
	    E1000_CTRL_SPD_10 |		/* Force Speed to 10 */
	    E1000_CTRL_FD);		/* Force Duplex to FULL */

	E1000_WRITE_REG(hw, E1000_CTRL, ctrl);
}

#ifdef __sparc
static boolean_t
e1000g_find_mac_address(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;
	uchar_t *bytes;
	struct ether_addr sysaddr;
	uint_t nelts;
	int err;
	boolean_t found = B_FALSE;

	/*
	 * The "vendor's factory-set address" may already have
	 * been extracted from the chip, but if the property
	 * "local-mac-address" is set we use that instead.
	 *
	 * We check whether it looks like an array of 6
	 * bytes (which it should, if OBP set it).  If we can't
	 * make sense of it this way, we'll ignore it.
	 */
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, Adapter->dip,
	    DDI_PROP_DONTPASS, "local-mac-address", &bytes, &nelts);
	if (err == DDI_PROP_SUCCESS) {
		if (nelts == ETHERADDRL) {
			while (nelts--)
				hw->mac.addr[nelts] = bytes[nelts];
			found = B_TRUE;
		}
		ddi_prop_free(bytes);
	}

	/*
	 * Look up the OBP property "local-mac-address?". If the user has set
	 * 'local-mac-address? = false', use "the system address" instead.
	 */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, Adapter->dip, 0,
	    "local-mac-address?", &bytes, &nelts) == DDI_PROP_SUCCESS) {
		if (strncmp("false", (caddr_t)bytes, (size_t)nelts) == 0) {
			if (localetheraddr(NULL, &sysaddr) != 0) {
				bcopy(&sysaddr, hw->mac.addr, ETHERADDRL);
				found = B_TRUE;
			}
		}
		ddi_prop_free(bytes);
	}

	/*
	 * Finally(!), if there's a valid "mac-address" property (created
	 * if we netbooted from this interface), we must use this instead
	 * of any of the above to ensure that the NFS/install server doesn't
	 * get confused by the address changing as Solaris takes over!
	 */
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, Adapter->dip,
	    DDI_PROP_DONTPASS, "mac-address", &bytes, &nelts);
	if (err == DDI_PROP_SUCCESS) {
		if (nelts == ETHERADDRL) {
			while (nelts--)
				hw->mac.addr[nelts] = bytes[nelts];
			found = B_TRUE;
		}
		ddi_prop_free(bytes);
	}

	if (found) {
		bcopy(hw->mac.addr, hw->mac.perm_addr,
		    ETHERADDRL);
	}

	return (found);
}
#endif

static int
e1000g_add_intrs(struct e1000g *Adapter)
{
	dev_info_t *devinfo;
	int intr_types;
	int rc;

	devinfo = Adapter->dip;

	/* Get supported interrupt types */
	rc = ddi_intr_get_supported_types(devinfo, &intr_types);

	if (rc != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Get supported interrupt types failed: %d\n", rc);
		return (DDI_FAILURE);
	}

	/*
	 * Based on Intel Technical Advisory document (TA-160), there are some
	 * cases where some older Intel PCI-X NICs may "advertise" to the OS
	 * that it supports MSI, but in fact has problems.
	 * So we should only enable MSI for PCI-E NICs and disable MSI for old
	 * PCI/PCI-X NICs.
	 */
	if (Adapter->shared.mac.type < e1000_82571)
		Adapter->msi_enable = B_FALSE;

	if ((intr_types & DDI_INTR_TYPE_MSI) && Adapter->msi_enable) {
		rc = e1000g_intr_add(Adapter, DDI_INTR_TYPE_MSI);

		if (rc != DDI_SUCCESS) {
			/* EMPTY */
			E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
			    "Add MSI failed, trying Legacy interrupts\n");
		} else {
			Adapter->intr_type = DDI_INTR_TYPE_MSI;
		}
	}

	if ((Adapter->intr_type == 0) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		rc = e1000g_intr_add(Adapter, DDI_INTR_TYPE_FIXED);

		if (rc != DDI_SUCCESS) {
			E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
			    "Add Legacy interrupts failed\n");
			return (DDI_FAILURE);
		}

		Adapter->intr_type = DDI_INTR_TYPE_FIXED;
	}

	if (Adapter->intr_type == 0) {
		E1000G_DEBUGLOG_0(Adapter, E1000G_WARN_LEVEL,
		    "No interrupts registered\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * e1000g_intr_add() handles MSI/Legacy interrupts
 */
static int
e1000g_intr_add(struct e1000g *Adapter, int intr_type)
{
	dev_info_t *devinfo;
	int count, avail, actual;
	int x, y, rc, inum = 0;
	int flag;
	ddi_intr_handler_t *intr_handler;

	devinfo = Adapter->dip;

	/* get number of interrupts */
	rc = ddi_intr_get_nintrs(devinfo, intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		E1000G_DEBUGLOG_2(Adapter, E1000G_WARN_LEVEL,
		    "Get interrupt number failed. Return: %d, count: %d\n",
		    rc, count);
		return (DDI_FAILURE);
	}

	/* get number of available interrupts */
	rc = ddi_intr_get_navail(devinfo, intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		E1000G_DEBUGLOG_2(Adapter, E1000G_WARN_LEVEL,
		    "Get interrupt available number failed. "
		    "Return: %d, available: %d\n", rc, avail);
		return (DDI_FAILURE);
	}

	if (avail < count) {
		/* EMPTY */
		E1000G_DEBUGLOG_2(Adapter, E1000G_WARN_LEVEL,
		    "Interrupts count: %d, available: %d\n",
		    count, avail);
	}

	/* Allocate an array of interrupt handles */
	Adapter->intr_size = count * sizeof (ddi_intr_handle_t);
	Adapter->htable = kmem_alloc(Adapter->intr_size, KM_SLEEP);

	/* Set NORMAL behavior for both MSI and FIXED interrupt */
	flag = DDI_INTR_ALLOC_NORMAL;

	/* call ddi_intr_alloc() */
	rc = ddi_intr_alloc(devinfo, Adapter->htable, intr_type, inum,
	    count, &actual, flag);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Allocate interrupts failed: %d\n", rc);

		kmem_free(Adapter->htable, Adapter->intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		/* EMPTY */
		E1000G_DEBUGLOG_2(Adapter, E1000G_WARN_LEVEL,
		    "Interrupts requested: %d, received: %d\n",
		    count, actual);
	}

	Adapter->intr_cnt = actual;

	/* Get priority for first msi, assume remaining are all the same */
	rc = ddi_intr_get_pri(Adapter->htable[0], &Adapter->intr_pri);

	if (rc != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Get interrupt priority failed: %d\n", rc);

		/* Free already allocated intr */
		for (y = 0; y < actual; y++)
			(void) ddi_intr_free(Adapter->htable[y]);

		kmem_free(Adapter->htable, Adapter->intr_size);
		return (DDI_FAILURE);
	}

	/*
	 * In Legacy Interrupt mode, for PCI-Express adapters, we should
	 * use the interrupt service routine e1000g_intr_pciexpress()
	 * to avoid interrupt stealing when sharing interrupt with other
	 * devices.
	 */
	if (Adapter->shared.mac.type < e1000_82571)
		intr_handler = (ddi_intr_handler_t *)e1000g_intr;
	else
		intr_handler = (ddi_intr_handler_t *)e1000g_intr_pciexpress;

	/* Call ddi_intr_add_handler() */
	for (x = 0; x < actual; x++) {
		rc = ddi_intr_add_handler(Adapter->htable[x],
		    intr_handler, (caddr_t)Adapter, NULL);

		if (rc != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Add interrupt handler failed: %d\n", rc);

			/* Remove already added handler */
			for (y = 0; y < x; y++)
				(void) ddi_intr_remove_handler(
				    Adapter->htable[y]);

			/* Free already allocated intr */
			for (y = 0; y < actual; y++)
				(void) ddi_intr_free(Adapter->htable[y]);

			kmem_free(Adapter->htable, Adapter->intr_size);
			return (DDI_FAILURE);
		}
	}

	rc = ddi_intr_get_cap(Adapter->htable[0], &Adapter->intr_cap);

	if (rc != DDI_SUCCESS) {
		E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
		    "Get interrupt cap failed: %d\n", rc);

		/* Free already allocated intr */
		for (y = 0; y < actual; y++) {
			(void) ddi_intr_remove_handler(Adapter->htable[y]);
			(void) ddi_intr_free(Adapter->htable[y]);
		}

		kmem_free(Adapter->htable, Adapter->intr_size);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
e1000g_rem_intrs(struct e1000g *Adapter)
{
	int x;
	int rc;

	for (x = 0; x < Adapter->intr_cnt; x++) {
		rc = ddi_intr_remove_handler(Adapter->htable[x]);
		if (rc != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Remove intr handler failed: %d\n", rc);
			return (DDI_FAILURE);
		}

		rc = ddi_intr_free(Adapter->htable[x]);
		if (rc != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Free intr failed: %d\n", rc);
			return (DDI_FAILURE);
		}
	}

	kmem_free(Adapter->htable, Adapter->intr_size);

	return (DDI_SUCCESS);
}

static int
e1000g_enable_intrs(struct e1000g *Adapter)
{
	int x;
	int rc;

	/* Enable interrupts */
	if (Adapter->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI */
		rc = ddi_intr_block_enable(Adapter->htable,
		    Adapter->intr_cnt);
		if (rc != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Enable block intr failed: %d\n", rc);
			return (DDI_FAILURE);
		}
	} else {
		/* Call ddi_intr_enable() for Legacy/MSI non block enable */
		for (x = 0; x < Adapter->intr_cnt; x++) {
			rc = ddi_intr_enable(Adapter->htable[x]);
			if (rc != DDI_SUCCESS) {
				E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
				    "Enable intr failed: %d\n", rc);
				return (DDI_FAILURE);
			}
		}
	}

	return (DDI_SUCCESS);
}

static int
e1000g_disable_intrs(struct e1000g *Adapter)
{
	int x;
	int rc;

	/* Disable all interrupts */
	if (Adapter->intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_disable(Adapter->htable,
		    Adapter->intr_cnt);
		if (rc != DDI_SUCCESS) {
			E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
			    "Disable block intr failed: %d\n", rc);
			return (DDI_FAILURE);
		}
	} else {
		for (x = 0; x < Adapter->intr_cnt; x++) {
			rc = ddi_intr_disable(Adapter->htable[x]);
			if (rc != DDI_SUCCESS) {
				E1000G_DEBUGLOG_1(Adapter, E1000G_WARN_LEVEL,
				    "Disable intr failed: %d\n", rc);
				return (DDI_FAILURE);
			}
		}
	}

	return (DDI_SUCCESS);
}

/*
 * e1000g_get_phy_state - get the state of PHY registers, save in the adapter
 */
static void
e1000g_get_phy_state(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->shared;

	if (hw->phy.media_type == e1000_media_type_copper) {
		(void) e1000_read_phy_reg(hw, PHY_CONTROL, &Adapter->phy_ctrl);
		(void) e1000_read_phy_reg(hw, PHY_STATUS, &Adapter->phy_status);
		(void) e1000_read_phy_reg(hw, PHY_AUTONEG_ADV,
		    &Adapter->phy_an_adv);
		(void) e1000_read_phy_reg(hw, PHY_AUTONEG_EXP,
		    &Adapter->phy_an_exp);
		(void) e1000_read_phy_reg(hw, PHY_EXT_STATUS,
		    &Adapter->phy_ext_status);
		(void) e1000_read_phy_reg(hw, PHY_1000T_CTRL,
		    &Adapter->phy_1000t_ctrl);
		(void) e1000_read_phy_reg(hw, PHY_1000T_STATUS,
		    &Adapter->phy_1000t_status);
		(void) e1000_read_phy_reg(hw, PHY_LP_ABILITY,
		    &Adapter->phy_lp_able);

		Adapter->param_autoneg_cap =
		    (Adapter->phy_status & MII_SR_AUTONEG_CAPS) ? 1 : 0;
		Adapter->param_pause_cap =
		    (Adapter->phy_an_adv & NWAY_AR_PAUSE) ? 1 : 0;
		Adapter->param_asym_pause_cap =
		    (Adapter->phy_an_adv & NWAY_AR_ASM_DIR) ? 1 : 0;
		Adapter->param_1000fdx_cap =
		    ((Adapter->phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (Adapter->phy_ext_status & IEEE_ESR_1000X_FD_CAPS)) ? 1 : 0;
		Adapter->param_1000hdx_cap =
		    ((Adapter->phy_ext_status & IEEE_ESR_1000T_HD_CAPS) ||
		    (Adapter->phy_ext_status & IEEE_ESR_1000X_HD_CAPS)) ? 1 : 0;
		Adapter->param_100t4_cap =
		    (Adapter->phy_status & MII_SR_100T4_CAPS) ? 1 : 0;
		Adapter->param_100fdx_cap =
		    ((Adapter->phy_status & MII_SR_100X_FD_CAPS) ||
		    (Adapter->phy_status & MII_SR_100T2_FD_CAPS)) ? 1 : 0;
		Adapter->param_100hdx_cap =
		    ((Adapter->phy_status & MII_SR_100X_HD_CAPS) ||
		    (Adapter->phy_status & MII_SR_100T2_HD_CAPS)) ? 1 : 0;
		Adapter->param_10fdx_cap =
		    (Adapter->phy_status & MII_SR_10T_FD_CAPS) ? 1 : 0;
		Adapter->param_10hdx_cap =
		    (Adapter->phy_status & MII_SR_10T_HD_CAPS) ? 1 : 0;

		Adapter->param_adv_autoneg = hw->mac.autoneg;
		Adapter->param_adv_pause =
		    (Adapter->phy_an_adv & NWAY_AR_PAUSE) ? 1 : 0;
		Adapter->param_adv_asym_pause =
		    (Adapter->phy_an_adv & NWAY_AR_ASM_DIR) ? 1 : 0;
		Adapter->param_adv_1000hdx =
		    (Adapter->phy_1000t_ctrl & CR_1000T_HD_CAPS) ? 1 : 0;
		Adapter->param_adv_100t4 =
		    (Adapter->phy_an_adv & NWAY_AR_100T4_CAPS) ? 1 : 0;
		if (Adapter->param_adv_autoneg == 1) {
			Adapter->param_adv_1000fdx =
			    (Adapter->phy_1000t_ctrl & CR_1000T_FD_CAPS)
			    ? 1 : 0;
			Adapter->param_adv_100fdx =
			    (Adapter->phy_an_adv & NWAY_AR_100TX_FD_CAPS)
			    ? 1 : 0;
			Adapter->param_adv_100hdx =
			    (Adapter->phy_an_adv & NWAY_AR_100TX_HD_CAPS)
			    ? 1 : 0;
			Adapter->param_adv_10fdx =
			    (Adapter->phy_an_adv & NWAY_AR_10T_FD_CAPS) ? 1 : 0;
			Adapter->param_adv_10hdx =
			    (Adapter->phy_an_adv & NWAY_AR_10T_HD_CAPS) ? 1 : 0;
		}

		Adapter->param_lp_autoneg =
		    (Adapter->phy_an_exp & NWAY_ER_LP_NWAY_CAPS) ? 1 : 0;
		Adapter->param_lp_pause =
		    (Adapter->phy_lp_able & NWAY_LPAR_PAUSE) ? 1 : 0;
		Adapter->param_lp_asym_pause =
		    (Adapter->phy_lp_able & NWAY_LPAR_ASM_DIR) ? 1 : 0;
		Adapter->param_lp_1000fdx =
		    (Adapter->phy_1000t_status & SR_1000T_LP_FD_CAPS) ? 1 : 0;
		Adapter->param_lp_1000hdx =
		    (Adapter->phy_1000t_status & SR_1000T_LP_HD_CAPS) ? 1 : 0;
		Adapter->param_lp_100t4 =
		    (Adapter->phy_lp_able & NWAY_LPAR_100T4_CAPS) ? 1 : 0;
		Adapter->param_lp_100fdx =
		    (Adapter->phy_lp_able & NWAY_LPAR_100TX_FD_CAPS) ? 1 : 0;
		Adapter->param_lp_100hdx =
		    (Adapter->phy_lp_able & NWAY_LPAR_100TX_HD_CAPS) ? 1 : 0;
		Adapter->param_lp_10fdx =
		    (Adapter->phy_lp_able & NWAY_LPAR_10T_FD_CAPS) ? 1 : 0;
		Adapter->param_lp_10hdx =
		    (Adapter->phy_lp_able & NWAY_LPAR_10T_HD_CAPS) ? 1 : 0;
	} else {
		/*
		 * 1Gig Fiber adapter only offers 1Gig Full Duplex. Meaning,
		 * it can only work with 1Gig Full Duplex Link Partner.
		 */
		Adapter->param_autoneg_cap = 0;
		Adapter->param_pause_cap = 1;
		Adapter->param_asym_pause_cap = 1;
		Adapter->param_1000fdx_cap = 1;
		Adapter->param_1000hdx_cap = 0;
		Adapter->param_100t4_cap = 0;
		Adapter->param_100fdx_cap = 0;
		Adapter->param_100hdx_cap = 0;
		Adapter->param_10fdx_cap = 0;
		Adapter->param_10hdx_cap = 0;

		Adapter->param_adv_autoneg = 0;
		Adapter->param_adv_pause = 1;
		Adapter->param_adv_asym_pause = 1;
		Adapter->param_adv_1000fdx = 1;
		Adapter->param_adv_1000hdx = 0;
		Adapter->param_adv_100t4 = 0;
		Adapter->param_adv_100fdx = 0;
		Adapter->param_adv_100hdx = 0;
		Adapter->param_adv_10fdx = 0;
		Adapter->param_adv_10hdx = 0;

		Adapter->param_lp_autoneg = 0;
		Adapter->param_lp_pause = 0;
		Adapter->param_lp_asym_pause = 0;
		Adapter->param_lp_1000fdx = 0;
		Adapter->param_lp_1000hdx = 0;
		Adapter->param_lp_100t4 = 0;
		Adapter->param_lp_100fdx = 0;
		Adapter->param_lp_100hdx = 0;
		Adapter->param_lp_10fdx = 0;
		Adapter->param_lp_10hdx = 0;
	}
}

/*
 * FMA support
 */

int
e1000g_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

int
e1000g_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * The IO fault service error handling callback function
 */
/* ARGSUSED2 */
static int
e1000g_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
e1000g_fm_init(struct e1000g *Adapter)
{
	ddi_iblock_cookie_t iblk;
	int fma_dma_flag;

	/* Only register with IO Fault Services if we have some capability */
	if (Adapter->fm_capabilities & DDI_FM_ACCCHK_CAPABLE) {
		e1000g_regs_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		e1000g_regs_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if (Adapter->fm_capabilities & DDI_FM_DMACHK_CAPABLE) {
		fma_dma_flag = 1;
	} else {
		fma_dma_flag = 0;
	}

	(void) e1000g_set_fma_flags(fma_dma_flag);

	if (Adapter->fm_capabilities) {

		/* Register capabilities with IO Fault Services */
		ddi_fm_init(Adapter->dip, &Adapter->fm_capabilities, &iblk);

		/*
		 * Initialize pci ereport capabilities if ereport capable
		 */
		if (DDI_FM_EREPORT_CAP(Adapter->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(Adapter->fm_capabilities))
			pci_ereport_setup(Adapter->dip);

		/*
		 * Register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(Adapter->fm_capabilities))
			ddi_fm_handler_register(Adapter->dip,
			    e1000g_fm_error_cb, (void*) Adapter);
	}
}

static void
e1000g_fm_fini(struct e1000g *Adapter)
{
	/* Only unregister FMA capabilities if we registered some */
	if (Adapter->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(Adapter->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(Adapter->fm_capabilities))
			pci_ereport_teardown(Adapter->dip);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(Adapter->fm_capabilities))
			ddi_fm_handler_unregister(Adapter->dip);

		/* Unregister from IO Fault Services */
		mutex_enter(&e1000g_rx_detach_lock);
		ddi_fm_fini(Adapter->dip);
		if (Adapter->priv_dip != NULL) {
			DEVI(Adapter->priv_dip)->devi_fmhdl = NULL;
		}
		mutex_exit(&e1000g_rx_detach_lock);
	}
}

void
e1000g_fm_ereport(struct e1000g *Adapter, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(Adapter->fm_capabilities)) {
		ddi_fm_ereport_post(Adapter->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
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
static int
e1000g_quiesce(dev_info_t *devinfo)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)ddi_get_driver_private(devinfo);

	if (Adapter == NULL)
		return (DDI_FAILURE);

	e1000g_clear_all_interrupts(Adapter);

	(void) e1000_reset_hw(&Adapter->shared);

	/* Setup our HW Tx Head & Tail descriptor pointers */
	E1000_WRITE_REG(&Adapter->shared, E1000_TDH(0), 0);
	E1000_WRITE_REG(&Adapter->shared, E1000_TDT(0), 0);

	/* Setup our HW Rx Head & Tail descriptor pointers */
	E1000_WRITE_REG(&Adapter->shared, E1000_RDH(0), 0);
	E1000_WRITE_REG(&Adapter->shared, E1000_RDT(0), 0);

	return (DDI_SUCCESS);
}

/*
 * synchronize the adv* and en* parameters.
 *
 * See comments in <sys/dld.h> for details of the *_en_*
 * parameters. The usage of ndd for setting adv parameters will
 * synchronize all the en parameters with the e1000g parameters,
 * implicitly disabling any settings made via dladm.
 */
static void
e1000g_param_sync(struct e1000g *Adapter)
{
	Adapter->param_en_1000fdx = Adapter->param_adv_1000fdx;
	Adapter->param_en_1000hdx = Adapter->param_adv_1000hdx;
	Adapter->param_en_100fdx = Adapter->param_adv_100fdx;
	Adapter->param_en_100hdx = Adapter->param_adv_100hdx;
	Adapter->param_en_10fdx = Adapter->param_adv_10fdx;
	Adapter->param_en_10hdx = Adapter->param_adv_10hdx;
}

/*
 * e1000g_get_driver_control - tell manageability firmware that the driver
 * has control.
 */
static void
e1000g_get_driver_control(struct e1000_hw *hw)
{
	uint32_t ctrl_ext;
	uint32_t swsm;

	/* tell manageability firmware the driver has taken over */
	switch (hw->mac.type) {
	case e1000_82573:
		swsm = E1000_READ_REG(hw, E1000_SWSM);
		E1000_WRITE_REG(hw, E1000_SWSM, swsm | E1000_SWSM_DRV_LOAD);
		break;
	case e1000_82571:
	case e1000_82572:
	case e1000_82574:
	case e1000_80003es2lan:
	case e1000_ich8lan:
	case e1000_ich9lan:
	case e1000_ich10lan:
	case e1000_pchlan:
	case e1000_pch2lan:
		ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
		E1000_WRITE_REG(hw, E1000_CTRL_EXT,
		    ctrl_ext | E1000_CTRL_EXT_DRV_LOAD);
		break;
	default:
		/* no manageability firmware: do nothing */
		break;
	}
}

/*
 * e1000g_release_driver_control - tell manageability firmware that the driver
 * has released control.
 */
static void
e1000g_release_driver_control(struct e1000_hw *hw)
{
	uint32_t ctrl_ext;
	uint32_t swsm;

	/* tell manageability firmware the driver has released control */
	switch (hw->mac.type) {
	case e1000_82573:
		swsm = E1000_READ_REG(hw, E1000_SWSM);
		E1000_WRITE_REG(hw, E1000_SWSM, swsm & ~E1000_SWSM_DRV_LOAD);
		break;
	case e1000_82571:
	case e1000_82572:
	case e1000_82574:
	case e1000_80003es2lan:
	case e1000_ich8lan:
	case e1000_ich9lan:
	case e1000_ich10lan:
	case e1000_pchlan:
	case e1000_pch2lan:
		ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
		E1000_WRITE_REG(hw, E1000_CTRL_EXT,
		    ctrl_ext & ~E1000_CTRL_EXT_DRV_LOAD);
		break;
	default:
		/* no manageability firmware: do nothing */
		break;
	}
}

/*
 * Restore e1000g promiscuous mode.
 */
static void
e1000g_restore_promisc(struct e1000g *Adapter)
{
	if (Adapter->e1000g_promisc) {
		uint32_t rctl;

		rctl = E1000_READ_REG(&Adapter->shared, E1000_RCTL);
		rctl |= (E1000_RCTL_UPE | E1000_RCTL_MPE | E1000_RCTL_BAM);
		E1000_WRITE_REG(&Adapter->shared, E1000_RCTL, rctl);
	}
}
