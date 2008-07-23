/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ixgbe_sw.h"

static char ident[] = "Intel 10Gb Ethernet 1.0.1";

/*
 * Local function protoypes
 */
static int ixgbe_register_mac(ixgbe_t *);
static int ixgbe_identify_hardware(ixgbe_t *);
static int ixgbe_regs_map(ixgbe_t *);
static void ixgbe_init_properties(ixgbe_t *);
static int ixgbe_init_driver_settings(ixgbe_t *);
static void ixgbe_init_locks(ixgbe_t *);
static void ixgbe_destroy_locks(ixgbe_t *);
static int ixgbe_init(ixgbe_t *);
static int ixgbe_chip_start(ixgbe_t *);
static void ixgbe_chip_stop(ixgbe_t *);
static int ixgbe_reset(ixgbe_t *);
static void ixgbe_tx_clean(ixgbe_t *);
static boolean_t ixgbe_tx_drain(ixgbe_t *);
static boolean_t ixgbe_rx_drain(ixgbe_t *);
static int ixgbe_alloc_rings(ixgbe_t *);
static int ixgbe_init_rings(ixgbe_t *);
static void ixgbe_free_rings(ixgbe_t *);
static void ixgbe_fini_rings(ixgbe_t *);
static void ixgbe_setup_rings(ixgbe_t *);
static void ixgbe_setup_rx(ixgbe_t *);
static void ixgbe_setup_tx(ixgbe_t *);
static void ixgbe_setup_rx_ring(ixgbe_rx_ring_t *);
static void ixgbe_setup_tx_ring(ixgbe_tx_ring_t *);
static void ixgbe_setup_rss(ixgbe_t *);
static void ixgbe_init_unicst(ixgbe_t *);
static void ixgbe_setup_multicst(ixgbe_t *);
static void ixgbe_get_hw_state(ixgbe_t *);
static void ixgbe_get_conf(ixgbe_t *);
static int ixgbe_get_prop(ixgbe_t *, char *, int, int, int);
static boolean_t ixgbe_driver_link_check(ixgbe_t *);
static void ixgbe_local_timer(void *);
static void ixgbe_arm_watchdog_timer(ixgbe_t *);
static void ixgbe_start_watchdog_timer(ixgbe_t *);
static void ixgbe_restart_watchdog_timer(ixgbe_t *);
static void ixgbe_stop_watchdog_timer(ixgbe_t *);
static void ixgbe_disable_adapter_interrupts(ixgbe_t *);
static void ixgbe_enable_adapter_interrupts(ixgbe_t *);
static boolean_t is_valid_mac_addr(uint8_t *);
static boolean_t ixgbe_stall_check(ixgbe_t *);
static boolean_t ixgbe_set_loopback_mode(ixgbe_t *, uint32_t);
static void ixgbe_set_internal_mac_loopback(ixgbe_t *);
static boolean_t ixgbe_find_mac_address(ixgbe_t *);
static int ixgbe_alloc_intrs(ixgbe_t *);
static int ixgbe_alloc_intr_handles(ixgbe_t *, int);
static int ixgbe_add_intr_handlers(ixgbe_t *);
static void ixgbe_map_rxring_to_vector(ixgbe_t *, int, int);
static void ixgbe_map_txring_to_vector(ixgbe_t *, int, int);
static void ixgbe_set_ivar(ixgbe_t *, uint16_t, uint8_t);
static int ixgbe_map_rings_to_vectors(ixgbe_t *);
static void ixgbe_setup_adapter_vector(ixgbe_t *);
static void ixgbe_rem_intr_handlers(ixgbe_t *);
static void ixgbe_rem_intrs(ixgbe_t *);
static int ixgbe_enable_intrs(ixgbe_t *);
static int ixgbe_disable_intrs(ixgbe_t *);
static uint_t ixgbe_intr_legacy(void *, void *);
static uint_t ixgbe_intr_msi(void *, void *);
static uint_t ixgbe_intr_rx(void *, void *);
static uint_t ixgbe_intr_tx_other(void *, void *);
static void ixgbe_intr_rx_work(ixgbe_rx_ring_t *);
static void ixgbe_intr_tx_work(ixgbe_tx_ring_t *);
static void ixgbe_intr_other_work(ixgbe_t *);
static void ixgbe_get_driver_control(struct ixgbe_hw *);
static void ixgbe_release_driver_control(struct ixgbe_hw *);

static int ixgbe_attach(dev_info_t *, ddi_attach_cmd_t);
static int ixgbe_detach(dev_info_t *, ddi_detach_cmd_t);
static int ixgbe_resume(dev_info_t *);
static int ixgbe_suspend(dev_info_t *);
static void ixgbe_unconfigure(dev_info_t *, ixgbe_t *);
static uint8_t *ixgbe_mc_table_itr(struct ixgbe_hw *, uint8_t **, uint32_t *);

static int ixgbe_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data);
static void ixgbe_fm_init(ixgbe_t *);
static void ixgbe_fm_fini(ixgbe_t *);

static struct cb_ops ixgbe_cb_ops = {
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

static struct dev_ops ixgbe_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ixgbe_attach,		/* devo_attach */
	ixgbe_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ixgbe_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power		/* devo_power */
};

static struct modldrv ixgbe_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	ident,			/* Discription string */
	&ixgbe_dev_ops		/* driver ops */
};

static struct modlinkage ixgbe_modlinkage = {
	MODREV_1, &ixgbe_modldrv, NULL
};

/*
 * Access attributes for register mapping
 */
ddi_device_acc_attr_t ixgbe_regs_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

/*
 * Loopback property
 */
static lb_property_t lb_normal = {
	normal,	"normal", IXGBE_LB_NONE
};

static lb_property_t lb_mac = {
	internal, "MAC", IXGBE_LB_INTERNAL_MAC
};

#define	IXGBE_M_CALLBACK_FLAGS	(MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t ixgbe_m_callbacks = {
	IXGBE_M_CALLBACK_FLAGS,
	ixgbe_m_stat,
	ixgbe_m_start,
	ixgbe_m_stop,
	ixgbe_m_promisc,
	ixgbe_m_multicst,
	ixgbe_m_unicst,
	ixgbe_m_tx,
	NULL,
	ixgbe_m_ioctl,
	ixgbe_m_getcapab
};

/*
 * Module Initialization Functions.
 */

int
_init(void)
{
	int status;

	mac_init_ops(&ixgbe_dev_ops, MODULE_NAME);

	status = mod_install(&ixgbe_modlinkage);

	if (status != DDI_SUCCESS) {
		mac_fini_ops(&ixgbe_dev_ops);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&ixgbe_modlinkage);

	if (status == DDI_SUCCESS) {
		mac_fini_ops(&ixgbe_dev_ops);
	}

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	int status;

	status = mod_info(&ixgbe_modlinkage, modinfop);

	return (status);
}

/*
 * ixgbe_attach - Driver attach.
 *
 * This function is the device specific initialization entry
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
ixgbe_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	ixgbe_t *ixgbe;
	struct ixgbe_osdep *osdep;
	struct ixgbe_hw *hw;
	int instance;

	/*
	 * Check the command and perform corresponding operations
	 */
	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (ixgbe_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	/* Get the device instance */
	instance = ddi_get_instance(devinfo);

	/* Allocate memory for the instance data structure */
	ixgbe = kmem_zalloc(sizeof (ixgbe_t), KM_SLEEP);

	ixgbe->dip = devinfo;
	ixgbe->instance = instance;

	hw = &ixgbe->hw;
	osdep = &ixgbe->osdep;
	hw->back = osdep;
	osdep->ixgbe = ixgbe;

	/* Attach the instance pointer to the dev_info data structure */
	ddi_set_driver_private(devinfo, ixgbe);

	/*
	 * Initialize for fma support
	 */
	ixgbe->fm_capabilities = ixgbe_get_prop(ixgbe, PROP_FM_CAPABLE,
	    0, 0x0f, DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);
	ixgbe_fm_init(ixgbe);
	ixgbe->attach_progress |= ATTACH_PROGRESS_FM_INIT;

	/*
	 * Map PCI config space registers
	 */
	if (pci_config_setup(devinfo, &osdep->cfg_handle) != DDI_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to map PCI configurations");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_PCI_CONFIG;

	/*
	 * Identify the chipset family
	 */
	if (ixgbe_identify_hardware(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to identify hardware");
		goto attach_fail;
	}

	/*
	 * Map device registers
	 */
	if (ixgbe_regs_map(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to map device registers");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_REGS_MAP;

	/*
	 * Initialize driver parameters
	 */
	ixgbe_init_properties(ixgbe);
	ixgbe->attach_progress |= ATTACH_PROGRESS_PROPS;

	/*
	 * Allocate interrupts
	 */
	if (ixgbe_alloc_intrs(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to allocate interrupts");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_ALLOC_INTR;

	/*
	 * Allocate rx/tx rings based on the ring numbers.
	 * The actual numbers of rx/tx rings are decided by the number of
	 * allocated interrupt vectors, so we should allocate the rings after
	 * interrupts are allocated.
	 */
	if (ixgbe_alloc_rings(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to allocate rx and tx rings");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_ALLOC_RINGS;

	/*
	 * Map rings to interrupt vectors
	 */
	if (ixgbe_map_rings_to_vectors(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to map rings to vectors");
		goto attach_fail;
	}

	/*
	 * Add interrupt handlers
	 */
	if (ixgbe_add_intr_handlers(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to add interrupt handlers");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_ADD_INTR;

	/*
	 * Initialize driver parameters
	 */
	if (ixgbe_init_driver_settings(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to initialize driver settings");
		goto attach_fail;
	}

	/*
	 * Initialize mutexes for this device.
	 * Do this before enabling the interrupt handler and
	 * register the softint to avoid the condition where
	 * interrupt handler can try using uninitialized mutex.
	 */
	ixgbe_init_locks(ixgbe);
	ixgbe->attach_progress |= ATTACH_PROGRESS_LOCKS;

	/*
	 * Initialize chipset hardware
	 */
	if (ixgbe_init(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to initialize adapter");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_INIT;

	if (ixgbe_check_acc_handle(ixgbe->osdep.cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_LOST);
		goto attach_fail;
	}

	/*
	 * Initialize DMA and hardware settings for rx/tx rings
	 */
	if (ixgbe_init_rings(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to initialize rings");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_INIT_RINGS;

	/*
	 * Initialize statistics
	 */
	if (ixgbe_init_stats(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to initialize statistics");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_STATS;

	/*
	 * Initialize NDD parameters
	 */
	if (ixgbe_nd_init(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to initialize ndd");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_NDD;

	/*
	 * Register the driver to the MAC
	 */
	if (ixgbe_register_mac(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to register MAC");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_MAC;

	/*
	 * Now that mutex locks are initialized, and the chip is also
	 * initialized, enable interrupts.
	 */
	if (ixgbe_enable_intrs(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to enable DDI interrupts");
		goto attach_fail;
	}
	ixgbe->attach_progress |= ATTACH_PROGRESS_ENABLE_INTR;

	ixgbe->ixgbe_state |= IXGBE_INITIALIZED;

	return (DDI_SUCCESS);

attach_fail:
	ixgbe_unconfigure(devinfo, ixgbe);
	return (DDI_FAILURE);
}

/*
 * ixgbe_detach - Driver detach.
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
ixgbe_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	ixgbe_t *ixgbe;

	/*
	 * Check detach command
	 */
	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (ixgbe_suspend(devinfo));

	case DDI_DETACH:
		break;
	}


	/*
	 * Get the pointer to the driver private data structure
	 */
	ixgbe = (ixgbe_t *)ddi_get_driver_private(devinfo);
	if (ixgbe == NULL)
		return (DDI_FAILURE);

	/*
	 * Unregister MAC. If failed, we have to fail the detach
	 */
	if (mac_unregister(ixgbe->mac_hdl) != 0) {
		ixgbe_error(ixgbe, "Failed to unregister MAC");
		return (DDI_FAILURE);
	}
	ixgbe->attach_progress &= ~ATTACH_PROGRESS_MAC;

	/*
	 * If the device is still running, it needs to be stopped first.
	 * This check is necessary because under some specific circumstances,
	 * the detach routine can be called without stopping the interface
	 * first.
	 */
	mutex_enter(&ixgbe->gen_lock);
	if (ixgbe->ixgbe_state & IXGBE_STARTED) {
		ixgbe->ixgbe_state &= ~IXGBE_STARTED;
		ixgbe_stop(ixgbe);
		mutex_exit(&ixgbe->gen_lock);
		/* Disable and stop the watchdog timer */
		ixgbe_disable_watchdog_timer(ixgbe);
	} else
		mutex_exit(&ixgbe->gen_lock);

	/*
	 * Check if there are still rx buffers held by the upper layer.
	 * If so, fail the detach.
	 */
	if (!ixgbe_rx_drain(ixgbe))
		return (DDI_FAILURE);

	/*
	 * Do the remaining unconfigure routines
	 */
	ixgbe_unconfigure(devinfo, ixgbe);

	return (DDI_SUCCESS);
}

static void
ixgbe_unconfigure(dev_info_t *devinfo, ixgbe_t *ixgbe)
{
	/*
	 * Disable interrupt
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_ENABLE_INTR) {
		(void) ixgbe_disable_intrs(ixgbe);
	}

	/*
	 * Unregister MAC
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_MAC) {
		(void) mac_unregister(ixgbe->mac_hdl);
	}

	/*
	 * Free ndd parameters
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_NDD) {
		ixgbe_nd_cleanup(ixgbe);
	}

	/*
	 * Free statistics
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_STATS) {
		kstat_delete((kstat_t *)ixgbe->ixgbe_ks);
	}

	/*
	 * Remove interrupt handlers
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_ADD_INTR) {
		ixgbe_rem_intr_handlers(ixgbe);
	}

	/*
	 * Remove interrupts
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_ALLOC_INTR) {
		ixgbe_rem_intrs(ixgbe);
	}

	/*
	 * Remove driver properties
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_PROPS) {
		(void) ddi_prop_remove_all(devinfo);
	}

	/*
	 * Release the DMA resources of rx/tx rings
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_INIT_RINGS) {
		ixgbe_fini_rings(ixgbe);
	}

	/*
	 * Stop the chipset
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_INIT) {
		mutex_enter(&ixgbe->gen_lock);
		ixgbe_chip_stop(ixgbe);
		mutex_exit(&ixgbe->gen_lock);
	}

	/*
	 * Free register handle
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_REGS_MAP) {
		if (ixgbe->osdep.reg_handle != NULL)
			ddi_regs_map_free(&ixgbe->osdep.reg_handle);
	}

	/*
	 * Free PCI config handle
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_PCI_CONFIG) {
		if (ixgbe->osdep.cfg_handle != NULL)
			pci_config_teardown(&ixgbe->osdep.cfg_handle);
	}

	/*
	 * Free locks
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_LOCKS) {
		ixgbe_destroy_locks(ixgbe);
	}

	/*
	 * Free the rx/tx rings
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_ALLOC_RINGS) {
		ixgbe_free_rings(ixgbe);
	}

	/*
	 * Unregister FMA capabilities
	 */
	if (ixgbe->attach_progress & ATTACH_PROGRESS_FM_INIT) {
		ixgbe_fm_fini(ixgbe);
	}

	/*
	 * Free the driver data structure
	 */
	kmem_free(ixgbe, sizeof (ixgbe_t));

	ddi_set_driver_private(devinfo, NULL);
}

/*
 * ixgbe_register_mac - Register the driver and its function pointers with
 * the GLD interface.
 */
static int
ixgbe_register_mac(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	mac_register_t *mac;
	int status;

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (IXGBE_FAILURE);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = ixgbe;
	mac->m_dip = ixgbe->dip;
	mac->m_src_addr = hw->mac.addr;
	mac->m_callbacks = &ixgbe_m_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = ixgbe->default_mtu;
	mac->m_margin = VLAN_TAGSZ;

	status = mac_register(mac, &ixgbe->mac_hdl);

	mac_free(mac);

	return ((status == 0) ? IXGBE_SUCCESS : IXGBE_FAILURE);
}

/*
 * ixgbe_identify_hardware - Identify the type of the chipset.
 */
static int
ixgbe_identify_hardware(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	struct ixgbe_osdep *osdep = &ixgbe->osdep;

	/*
	 * Get the device id
	 */
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

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_regs_map - Map the device registers.
 *
 */
static int
ixgbe_regs_map(ixgbe_t *ixgbe)
{
	dev_info_t *devinfo = ixgbe->dip;
	struct ixgbe_hw *hw = &ixgbe->hw;
	struct ixgbe_osdep *osdep = &ixgbe->osdep;
	off_t mem_size;

	/*
	 * First get the size of device registers to be mapped.
	 */
	if (ddi_dev_regsize(devinfo, 1, &mem_size) != DDI_SUCCESS) {
		return (IXGBE_FAILURE);
	}

	/*
	 * Call ddi_regs_map_setup() to map registers
	 */
	if ((ddi_regs_map_setup(devinfo, 1,
	    (caddr_t *)&hw->hw_addr, 0,
	    mem_size, &ixgbe_regs_acc_attr,
	    &osdep->reg_handle)) != DDI_SUCCESS) {
		return (IXGBE_FAILURE);
	}

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_init_properties - Initialize driver properties.
 */
static void
ixgbe_init_properties(ixgbe_t *ixgbe)
{
	/*
	 * Get conf file properties, including link settings
	 * jumbo frames, ring number, descriptor number, etc.
	 */
	ixgbe_get_conf(ixgbe);
}

/*
 * ixgbe_init_driver_settings - Initialize driver settings.
 *
 * The settings include hardware function pointers, bus information,
 * rx/tx rings settings, link state, and any other parameters that
 * need to be setup during driver initialization.
 */
static int
ixgbe_init_driver_settings(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	ixgbe_rx_ring_t *rx_ring;
	ixgbe_tx_ring_t *tx_ring;
	uint32_t rx_size;
	uint32_t tx_size;
	int i;

	/*
	 * Initialize chipset specific hardware function pointers
	 */
	if (ixgbe_init_shared_code(hw) != IXGBE_SUCCESS) {
		return (IXGBE_FAILURE);
	}

	/*
	 * Set rx buffer size
	 *
	 * The IP header alignment room is counted in the calculation.
	 * The rx buffer size is in unit of 1K that is required by the
	 * chipset hardware.
	 */
	rx_size = ixgbe->max_frame_size + IPHDR_ALIGN_ROOM;
	ixgbe->rx_buf_size = ((rx_size >> 10) +
	    ((rx_size & (((uint32_t)1 << 10) - 1)) > 0 ? 1 : 0)) << 10;

	/*
	 * Set tx buffer size
	 */
	tx_size = ixgbe->max_frame_size;
	ixgbe->tx_buf_size = ((tx_size >> 10) +
	    ((tx_size & (((uint32_t)1 << 10) - 1)) > 0 ? 1 : 0)) << 10;

	/*
	 * Initialize rx/tx rings parameters
	 */
	for (i = 0; i < ixgbe->num_rx_rings; i++) {
		rx_ring = &ixgbe->rx_rings[i];
		rx_ring->index = i;
		rx_ring->ixgbe = ixgbe;

		rx_ring->ring_size = ixgbe->rx_ring_size;
		rx_ring->free_list_size = ixgbe->rx_ring_size;
		rx_ring->copy_thresh = ixgbe->rx_copy_thresh;
		rx_ring->limit_per_intr = ixgbe->rx_limit_per_intr;
	}

	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		tx_ring = &ixgbe->tx_rings[i];
		tx_ring->index = i;
		tx_ring->ixgbe = ixgbe;
		if (ixgbe->tx_head_wb_enable)
			tx_ring->tx_recycle = ixgbe_tx_recycle_head_wb;
		else
			tx_ring->tx_recycle = ixgbe_tx_recycle_legacy;

		tx_ring->ring_size = ixgbe->tx_ring_size;
		tx_ring->free_list_size = ixgbe->tx_ring_size +
		    (ixgbe->tx_ring_size >> 1);
		tx_ring->copy_thresh = ixgbe->tx_copy_thresh;
		tx_ring->recycle_thresh = ixgbe->tx_recycle_thresh;
		tx_ring->overload_thresh = ixgbe->tx_overload_thresh;
	tx_ring->resched_thresh = ixgbe->tx_resched_thresh;
	}

	/*
	 * Initialize values of interrupt throttling rate
	 */
	for (i = 1; i < IXGBE_MAX_RING_VECTOR; i++)
		ixgbe->intr_throttling[i] = ixgbe->intr_throttling[0];

	/*
	 * The initial link state should be "unknown"
	 */
	ixgbe->link_state = LINK_STATE_UNKNOWN;
	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_init_locks - Initialize locks.
 */
static void
ixgbe_init_locks(ixgbe_t *ixgbe)
{
	ixgbe_rx_ring_t *rx_ring;
	ixgbe_tx_ring_t *tx_ring;
	int i;

	for (i = 0; i < ixgbe->num_rx_rings; i++) {
		rx_ring = &ixgbe->rx_rings[i];
		mutex_init(&rx_ring->rx_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
		mutex_init(&rx_ring->recycle_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
	}

	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		tx_ring = &ixgbe->tx_rings[i];
		mutex_init(&tx_ring->tx_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
		mutex_init(&tx_ring->recycle_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
		mutex_init(&tx_ring->tcb_head_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
		mutex_init(&tx_ring->tcb_tail_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
	}

	mutex_init(&ixgbe->gen_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));

	mutex_init(&ixgbe->watchdog_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(ixgbe->intr_pri));
}

/*
 * ixgbe_destroy_locks - Destroy locks.
 */
static void
ixgbe_destroy_locks(ixgbe_t *ixgbe)
{
	ixgbe_rx_ring_t *rx_ring;
	ixgbe_tx_ring_t *tx_ring;
	int i;

	for (i = 0; i < ixgbe->num_rx_rings; i++) {
		rx_ring = &ixgbe->rx_rings[i];
		mutex_destroy(&rx_ring->rx_lock);
		mutex_destroy(&rx_ring->recycle_lock);
	}

	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		tx_ring = &ixgbe->tx_rings[i];
		mutex_destroy(&tx_ring->tx_lock);
		mutex_destroy(&tx_ring->recycle_lock);
		mutex_destroy(&tx_ring->tcb_head_lock);
		mutex_destroy(&tx_ring->tcb_tail_lock);
	}

	mutex_destroy(&ixgbe->gen_lock);
	mutex_destroy(&ixgbe->watchdog_lock);
}

static int
ixgbe_resume(dev_info_t *devinfo)
{
	ixgbe_t *ixgbe;

	ixgbe = (ixgbe_t *)ddi_get_driver_private(devinfo);
	if (ixgbe == NULL)
		return (DDI_FAILURE);

	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_STARTED) {
		if (ixgbe_start(ixgbe) != IXGBE_SUCCESS) {
			mutex_exit(&ixgbe->gen_lock);
			return (DDI_FAILURE);
		}

		/*
		 * Enable and start the watchdog timer
		 */
		ixgbe_enable_watchdog_timer(ixgbe);
	}

	ixgbe->ixgbe_state &= ~IXGBE_SUSPENDED;

	mutex_exit(&ixgbe->gen_lock);

	return (DDI_SUCCESS);
}

static int
ixgbe_suspend(dev_info_t *devinfo)
{
	ixgbe_t *ixgbe;

	ixgbe = (ixgbe_t *)ddi_get_driver_private(devinfo);
	if (ixgbe == NULL)
		return (DDI_FAILURE);

	mutex_enter(&ixgbe->gen_lock);

	ixgbe->ixgbe_state |= IXGBE_SUSPENDED;

	ixgbe_stop(ixgbe);

	mutex_exit(&ixgbe->gen_lock);

	/*
	 * Disable and stop the watchdog timer
	 */
	ixgbe_disable_watchdog_timer(ixgbe);

	return (DDI_SUCCESS);
}

/*
 * ixgbe_init - Initialize the device.
 */
static int
ixgbe_init(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;

	mutex_enter(&ixgbe->gen_lock);

	/*
	 * Reset chipset to put the hardware in a known state
	 * before we try to do anything with the eeprom.
	 */
	if (ixgbe_reset_hw(hw) != IXGBE_SUCCESS) {
		ixgbe_fm_ereport(ixgbe, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	/*
	 * Need to init eeprom before validating the checksum.
	 */
	if (ixgbe_init_eeprom_params(hw) < 0) {
		ixgbe_error(ixgbe,
		    "Unable to intitialize the eeprom interface.");
		ixgbe_fm_ereport(ixgbe, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	/*
	 * NVM validation
	 */
	if (ixgbe_validate_eeprom_checksum(hw, NULL) < 0) {
		/*
		 * Some PCI-E parts fail the first check due to
		 * the link being in sleep state.  Call it again,
		 * if it fails a second time it's a real issue.
		 */
		if (ixgbe_validate_eeprom_checksum(hw, NULL) < 0) {
			ixgbe_error(ixgbe,
			    "Invalid NVM checksum. Please contact "
			    "the vendor to update the NVM.");
			ixgbe_fm_ereport(ixgbe, DDI_FM_DEVICE_INVAL_STATE);
			goto init_fail;
		}
	}

	/*
	 * Setup default flow control thresholds - enable/disable
	 * & flow control type is controlled by ixgbe.conf
	 */
	hw->fc.high_water = DEFAULT_FCRTH;
	hw->fc.low_water = DEFAULT_FCRTL;
	hw->fc.pause_time = DEFAULT_FCPAUSE;
	hw->fc.send_xon = B_TRUE;

	/*
	 * Don't wait for auto-negotiation to complete
	 */
	hw->phy.autoneg_wait_to_complete = B_FALSE;

	/*
	 * Initialize link settings
	 */
	(void) ixgbe_driver_setup_link(ixgbe, B_FALSE);

	/*
	 * Initialize the chipset hardware
	 */
	if (ixgbe_chip_start(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_fm_ereport(ixgbe, DDI_FM_DEVICE_INVAL_STATE);
		goto init_fail;
	}

	if (ixgbe_check_acc_handle(ixgbe->osdep.cfg_handle) != DDI_FM_OK) {
		goto init_fail;
	}
	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		goto init_fail;
	}

	mutex_exit(&ixgbe->gen_lock);
	return (IXGBE_SUCCESS);

init_fail:
	/*
	 * Reset PHY
	 */
	(void) ixgbe_reset_phy(hw);

	mutex_exit(&ixgbe->gen_lock);
	ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_LOST);
	return (IXGBE_FAILURE);
}

/*
 * ixgbe_init_rings - Allocate DMA resources for all rx/tx rings and
 * initialize relevant hardware settings.
 */
static int
ixgbe_init_rings(ixgbe_t *ixgbe)
{
	int i;

	/*
	 * Allocate buffers for all the rx/tx rings
	 */
	if (ixgbe_alloc_dma(ixgbe) != IXGBE_SUCCESS)
		return (IXGBE_FAILURE);

	/*
	 * Setup the rx/tx rings
	 */
	mutex_enter(&ixgbe->gen_lock);

	for (i = 0; i < ixgbe->num_rx_rings; i++)
		mutex_enter(&ixgbe->rx_rings[i].rx_lock);
	for (i = 0; i < ixgbe->num_tx_rings; i++)
		mutex_enter(&ixgbe->tx_rings[i].tx_lock);

	ixgbe_setup_rings(ixgbe);

	for (i = ixgbe->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->tx_rings[i].tx_lock);
	for (i = ixgbe->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->rx_rings[i].rx_lock);

	mutex_exit(&ixgbe->gen_lock);

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_fini_rings - Release DMA resources of all rx/tx rings.
 */
static void
ixgbe_fini_rings(ixgbe_t *ixgbe)
{
	/*
	 * Release the DMA/memory resources of rx/tx rings
	 */
	ixgbe_free_dma(ixgbe);
}

/*
 * ixgbe_chip_start - Initialize and start the chipset hardware.
 */
static int
ixgbe_chip_start(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	int i;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	/*
	 * Get the mac address
	 * This function should handle SPARC case correctly.
	 */
	if (!ixgbe_find_mac_address(ixgbe)) {
		ixgbe_error(ixgbe, "Failed to get the mac address");
		return (IXGBE_FAILURE);
	}

	/*
	 * Validate the mac address
	 */
	(void) ixgbe_init_rx_addrs(hw);
	if (!is_valid_mac_addr(hw->mac.addr)) {
		ixgbe_error(ixgbe, "Invalid mac address");
		return (IXGBE_FAILURE);
	}

	/*
	 * Configure/Initialize hardware
	 */
	if (ixgbe_init_hw(hw) != IXGBE_SUCCESS) {
		ixgbe_error(ixgbe, "Failed to initialize hardware");
		return (IXGBE_FAILURE);
	}

	/*
	 * Setup adapter interrupt vectors
	 */
	ixgbe_setup_adapter_vector(ixgbe);

	/*
	 * Initialize unicast addresses.
	 */
	ixgbe_init_unicst(ixgbe);

	/*
	 * Setup and initialize the mctable structures.
	 */
	ixgbe_setup_multicst(ixgbe);

	/*
	 * Set interrupt throttling rate
	 */
	for (i = 0; i < ixgbe->intr_cnt; i++)
		IXGBE_WRITE_REG(hw, IXGBE_EITR(i), ixgbe->intr_throttling[i]);

	/*
	 * Save the state of the phy
	 */
	ixgbe_get_hw_state(ixgbe);

	/*
	 * Make sure driver has control
	 */
	ixgbe_get_driver_control(hw);

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_chip_stop - Stop the chipset hardware
 */
static void
ixgbe_chip_stop(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	/*
	 * Tell firmware driver is no longer in control
	 */
	ixgbe_release_driver_control(hw);

	/*
	 * Reset the chipset
	 */
	(void) ixgbe_reset_hw(hw);

	/*
	 * Reset PHY
	 */
	(void) ixgbe_reset_phy(hw);
}

/*
 * ixgbe_reset - Reset the chipset and re-start the driver.
 *
 * It involves stopping and re-starting the chipset,
 * and re-configuring the rx/tx rings.
 */
static int
ixgbe_reset(ixgbe_t *ixgbe)
{
	int i;

	mutex_enter(&ixgbe->gen_lock);

	ASSERT(ixgbe->ixgbe_state & IXGBE_STARTED);
	ixgbe->ixgbe_state &= ~IXGBE_STARTED;

	/*
	 * Disable the adapter interrupts to stop any rx/tx activities
	 * before draining pending data and resetting hardware.
	 */
	ixgbe_disable_adapter_interrupts(ixgbe);

	/*
	 * Drain the pending transmit packets
	 */
	(void) ixgbe_tx_drain(ixgbe);

	for (i = 0; i < ixgbe->num_rx_rings; i++)
		mutex_enter(&ixgbe->rx_rings[i].rx_lock);
	for (i = 0; i < ixgbe->num_tx_rings; i++)
		mutex_enter(&ixgbe->tx_rings[i].tx_lock);

	/*
	 * Stop the chipset hardware
	 */
	ixgbe_chip_stop(ixgbe);

	/*
	 * Clean the pending tx data/resources
	 */
	ixgbe_tx_clean(ixgbe);

	/*
	 * Start the chipset hardware
	 */
	if (ixgbe_chip_start(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_fm_ereport(ixgbe, DDI_FM_DEVICE_INVAL_STATE);
		goto reset_failure;
	}

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		goto reset_failure;
	}

	/*
	 * Setup the rx/tx rings
	 */
	ixgbe_setup_rings(ixgbe);

	/*
	 * Enable adapter interrupts
	 * The interrupts must be enabled after the driver state is START
	 */
	ixgbe_enable_adapter_interrupts(ixgbe);

	for (i = ixgbe->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->tx_rings[i].tx_lock);
	for (i = ixgbe->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->rx_rings[i].rx_lock);

	ixgbe->ixgbe_state |= IXGBE_STARTED;
	mutex_exit(&ixgbe->gen_lock);

	return (IXGBE_SUCCESS);

reset_failure:
	for (i = ixgbe->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->tx_rings[i].tx_lock);
	for (i = ixgbe->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->rx_rings[i].rx_lock);

	mutex_exit(&ixgbe->gen_lock);

	ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_LOST);

	return (IXGBE_FAILURE);
}

/*
 * ixgbe_tx_clean - Clean the pending transmit packets and DMA resources.
 */
static void
ixgbe_tx_clean(ixgbe_t *ixgbe)
{
	ixgbe_tx_ring_t *tx_ring;
	tx_control_block_t *tcb;
	link_list_t pending_list;
	uint32_t desc_num;
	struct ixgbe_hw *hw = &ixgbe->hw;
	int i, j;

	LINK_LIST_INIT(&pending_list);

	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		tx_ring = &ixgbe->tx_rings[i];

		mutex_enter(&tx_ring->recycle_lock);

		/*
		 * Clean the pending tx data - the pending packets in the
		 * work_list that have no chances to be transmitted again.
		 *
		 * We must ensure the chipset is stopped or the link is down
		 * before cleaning the transmit packets.
		 */
		desc_num = 0;
		for (j = 0; j < tx_ring->ring_size; j++) {
			tcb = tx_ring->work_list[j];
			if (tcb != NULL) {
				desc_num += tcb->desc_num;

				tx_ring->work_list[j] = NULL;

				ixgbe_free_tcb(tcb);

				LIST_PUSH_TAIL(&pending_list, &tcb->link);
			}
		}

		if (desc_num > 0) {
			atomic_add_32(&tx_ring->tbd_free, desc_num);
			ASSERT(tx_ring->tbd_free == tx_ring->ring_size);

			/*
			 * Reset the head and tail pointers of the tbd ring;
			 * Reset the writeback head if it's enable.
			 */
			tx_ring->tbd_head = 0;
			tx_ring->tbd_tail = 0;
			if (ixgbe->tx_head_wb_enable)
				*tx_ring->tbd_head_wb = 0;

			IXGBE_WRITE_REG(&ixgbe->hw,
			    IXGBE_TDH(tx_ring->index), 0);
			IXGBE_WRITE_REG(&ixgbe->hw,
			    IXGBE_TDT(tx_ring->index), 0);
		}

		mutex_exit(&tx_ring->recycle_lock);

		/*
		 * Add the tx control blocks in the pending list to
		 * the free list.
		 */
		ixgbe_put_free_list(tx_ring, &pending_list);
	}
}

/*
 * ixgbe_tx_drain - Drain the tx rings to allow pending packets to be
 * transmitted.
 */
static boolean_t
ixgbe_tx_drain(ixgbe_t *ixgbe)
{
	ixgbe_tx_ring_t *tx_ring;
	boolean_t done;
	int i, j;

	/*
	 * Wait for a specific time to allow pending tx packets
	 * to be transmitted.
	 *
	 * Check the counter tbd_free to see if transmission is done.
	 * No lock protection is needed here.
	 *
	 * Return B_TRUE if all pending packets have been transmitted;
	 * Otherwise return B_FALSE;
	 */
	for (i = 0; i < TX_DRAIN_TIME; i++) {

		done = B_TRUE;
		for (j = 0; j < ixgbe->num_tx_rings; j++) {
			tx_ring = &ixgbe->tx_rings[j];
			done = done &&
			    (tx_ring->tbd_free == tx_ring->ring_size);
		}

		if (done)
			break;

		msec_delay(1);
	}

	return (done);
}

/*
 * ixgbe_rx_drain - Wait for all rx buffers to be released by upper layer.
 */
static boolean_t
ixgbe_rx_drain(ixgbe_t *ixgbe)
{
	ixgbe_rx_ring_t *rx_ring;
	boolean_t done;
	int i, j;

	/*
	 * Polling the rx free list to check if those rx buffers held by
	 * the upper layer are released.
	 *
	 * Check the counter rcb_free to see if all pending buffers are
	 * released. No lock protection is needed here.
	 *
	 * Return B_TRUE if all pending buffers have been released;
	 * Otherwise return B_FALSE;
	 */
	for (i = 0; i < RX_DRAIN_TIME; i++) {

		done = B_TRUE;
		for (j = 0; j < ixgbe->num_rx_rings; j++) {
			rx_ring = &ixgbe->rx_rings[j];
			done = done &&
			    (rx_ring->rcb_free == rx_ring->free_list_size);
		}

		if (done)
			break;

		msec_delay(1);
	}

	return (done);
}

/*
 * ixgbe_start - Start the driver/chipset.
 */
int
ixgbe_start(ixgbe_t *ixgbe)
{
	int i;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	for (i = 0; i < ixgbe->num_rx_rings; i++)
		mutex_enter(&ixgbe->rx_rings[i].rx_lock);
	for (i = 0; i < ixgbe->num_tx_rings; i++)
		mutex_enter(&ixgbe->tx_rings[i].tx_lock);

	/*
	 * Start the chipset hardware
	 */
	if (ixgbe_chip_start(ixgbe) != IXGBE_SUCCESS) {
		ixgbe_fm_ereport(ixgbe, DDI_FM_DEVICE_INVAL_STATE);
		goto start_failure;
	}

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		goto start_failure;
	}

	/*
	 * Setup the rx/tx rings
	 */
	ixgbe_setup_rings(ixgbe);

	/*
	 * Enable adapter interrupts
	 * The interrupts must be enabled after the driver state is START
	 */
	ixgbe_enable_adapter_interrupts(ixgbe);

	for (i = ixgbe->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->tx_rings[i].tx_lock);
	for (i = ixgbe->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->rx_rings[i].rx_lock);

	return (IXGBE_SUCCESS);

start_failure:
	for (i = ixgbe->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->tx_rings[i].tx_lock);
	for (i = ixgbe->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->rx_rings[i].rx_lock);

	ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_LOST);

	return (IXGBE_FAILURE);
}

/*
 * ixgbe_stop - Stop the driver/chipset.
 */
void
ixgbe_stop(ixgbe_t *ixgbe)
{
	int i;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	/*
	 * Disable the adapter interrupts
	 */
	ixgbe_disable_adapter_interrupts(ixgbe);

	/*
	 * Drain the pending tx packets
	 */
	(void) ixgbe_tx_drain(ixgbe);

	for (i = 0; i < ixgbe->num_rx_rings; i++)
		mutex_enter(&ixgbe->rx_rings[i].rx_lock);
	for (i = 0; i < ixgbe->num_tx_rings; i++)
		mutex_enter(&ixgbe->tx_rings[i].tx_lock);

	/*
	 * Stop the chipset hardware
	 */
	ixgbe_chip_stop(ixgbe);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_LOST);
	}

	/*
	 * Clean the pending tx data/resources
	 */
	ixgbe_tx_clean(ixgbe);

	for (i = ixgbe->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->tx_rings[i].tx_lock);
	for (i = ixgbe->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&ixgbe->rx_rings[i].rx_lock);
}

/*
 * ixgbe_alloc_rings - Allocate memory space for rx/tx rings.
 */
static int
ixgbe_alloc_rings(ixgbe_t *ixgbe)
{
	/*
	 * Allocate memory space for rx rings
	 */
	ixgbe->rx_rings = kmem_zalloc(
	    sizeof (ixgbe_rx_ring_t) * ixgbe->num_rx_rings,
	    KM_NOSLEEP);

	if (ixgbe->rx_rings == NULL) {
		return (IXGBE_FAILURE);
	}

	/*
	 * Allocate memory space for tx rings
	 */
	ixgbe->tx_rings = kmem_zalloc(
	    sizeof (ixgbe_tx_ring_t) * ixgbe->num_tx_rings,
	    KM_NOSLEEP);

	if (ixgbe->tx_rings == NULL) {
		kmem_free(ixgbe->rx_rings,
		    sizeof (ixgbe_rx_ring_t) * ixgbe->num_rx_rings);
		ixgbe->rx_rings = NULL;
		return (IXGBE_FAILURE);
	}

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_free_rings - Free the memory space of rx/tx rings.
 */
static void
ixgbe_free_rings(ixgbe_t *ixgbe)
{
	if (ixgbe->rx_rings != NULL) {
		kmem_free(ixgbe->rx_rings,
		    sizeof (ixgbe_rx_ring_t) * ixgbe->num_rx_rings);
		ixgbe->rx_rings = NULL;
	}

	if (ixgbe->tx_rings != NULL) {
		kmem_free(ixgbe->tx_rings,
		    sizeof (ixgbe_tx_ring_t) * ixgbe->num_tx_rings);
		ixgbe->tx_rings = NULL;
	}
}

/*
 * ixgbe_setup_rings - Setup rx/tx rings.
 */
static void
ixgbe_setup_rings(ixgbe_t *ixgbe)
{
	/*
	 * Setup the rx/tx rings, including the following:
	 *
	 * 1. Setup the descriptor ring and the control block buffers;
	 * 2. Initialize necessary registers for receive/transmit;
	 * 3. Initialize software pointers/parameters for receive/transmit;
	 */
	ixgbe_setup_rx(ixgbe);

	ixgbe_setup_tx(ixgbe);
}

static void
ixgbe_setup_rx_ring(ixgbe_rx_ring_t *rx_ring)
{
	ixgbe_t *ixgbe = rx_ring->ixgbe;
	struct ixgbe_hw *hw = &ixgbe->hw;
	rx_control_block_t *rcb;
	union ixgbe_adv_rx_desc	*rbd;
	uint32_t size;
	uint32_t buf_low;
	uint32_t buf_high;
	uint32_t reg_val;
	int i;

	ASSERT(mutex_owned(&rx_ring->rx_lock));
	ASSERT(mutex_owned(&ixgbe->gen_lock));

	for (i = 0; i < ixgbe->rx_ring_size; i++) {
		rcb = rx_ring->work_list[i];
		rbd = &rx_ring->rbd_ring[i];

		rbd->read.pkt_addr = rcb->rx_buf.dma_address;
		rbd->read.hdr_addr = NULL;
	}

	/*
	 * Initialize the length register
	 */
	size = rx_ring->ring_size * sizeof (union ixgbe_adv_rx_desc);
	IXGBE_WRITE_REG(hw, IXGBE_RDLEN(rx_ring->index), size);

	/*
	 * Initialize the base address registers
	 */
	buf_low = (uint32_t)rx_ring->rbd_area.dma_address;
	buf_high = (uint32_t)(rx_ring->rbd_area.dma_address >> 32);
	IXGBE_WRITE_REG(hw, IXGBE_RDBAH(rx_ring->index), buf_high);
	IXGBE_WRITE_REG(hw, IXGBE_RDBAL(rx_ring->index), buf_low);

	/*
	 * Setup head & tail pointers
	 */
	IXGBE_WRITE_REG(hw, IXGBE_RDT(rx_ring->index), rx_ring->ring_size - 1);
	IXGBE_WRITE_REG(hw, IXGBE_RDH(rx_ring->index), 0);

	rx_ring->rbd_next = 0;

	/*
	 * Note: Considering the case that the chipset is being reset
	 * and there are still some buffers held by the upper layer,
	 * we should not reset the values of rcb_head, rcb_tail and
	 * rcb_free if the state is not IXGBE_UNKNOWN.
	 */
	if (ixgbe->ixgbe_state == IXGBE_UNKNOWN) {
		rx_ring->rcb_head = 0;
		rx_ring->rcb_tail = 0;
		rx_ring->rcb_free = rx_ring->free_list_size;
	}

	/*
	 * Setup the Receive Descriptor Control Register (RXDCTL)
	 * PTHRESH=32 descriptors (half the internal cache)
	 * HTHRESH=0 descriptors (to minimize latency on fetch)
	 * WTHRESH defaults to 1 (writeback each descriptor)
	 */
	reg_val = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rx_ring->index));
	reg_val |= IXGBE_RXDCTL_ENABLE;	/* enable queue */
	reg_val |= 0x0020;		/* pthresh */
	IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rx_ring->index), reg_val);

	/*
	 * Setup the Split and Replication Receive Control Register.
	 * Set the rx buffer size and the advanced descriptor type.
	 */
	reg_val = (ixgbe->rx_buf_size >> IXGBE_SRRCTL_BSIZEPKT_SHIFT) |
	    IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

	IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(rx_ring->index), reg_val);
}

static void
ixgbe_setup_rx(ixgbe_t *ixgbe)
{
	ixgbe_rx_ring_t *rx_ring;
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t reg_val;
	int i;

	/*
	 * Set filter control in FCTRL to accept broadcast packets and do
	 * not pass pause frames to host.  Flow control settings are already
	 * in this register, so preserve them.
	 */
	reg_val = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	reg_val |= IXGBE_FCTRL_BAM;	/* broadcast accept mode */
	reg_val |= IXGBE_FCTRL_DPF;	/* discard pause frames */
	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, reg_val);

	/*
	 * Enable the receive unit.  This must be done after filter
	 * control is set in FCTRL.
	 */
	reg_val = (IXGBE_RXCTRL_RXEN	/* Enable Receive Unit */
	    | IXGBE_RXCTRL_DMBYPS);	/* descriptor monitor bypass */
	IXGBE_WRITE_REG(hw, IXGBE_RXCTRL, reg_val);

	/*
	 * ixgbe_setup_rx_ring must be called after configuring RXCTRL
	 */
	for (i = 0; i < ixgbe->num_rx_rings; i++) {
		rx_ring = &ixgbe->rx_rings[i];
		ixgbe_setup_rx_ring(rx_ring);
	}

	/*
	 * The Max Frame Size in MHADD will be internally increased by four
	 * bytes if the packet has a VLAN field, so includes MTU, ethernet
	 * header and frame check sequence.
	 */
	reg_val = (ixgbe->default_mtu + sizeof (struct ether_header)
	    + ETHERFCSL) << IXGBE_MHADD_MFS_SHIFT;
	IXGBE_WRITE_REG(hw, IXGBE_MHADD, reg_val);

	/*
	 * Setup Jumbo Frame enable bit
	 */
	if (ixgbe->default_mtu > ETHERMTU) {
		reg_val = IXGBE_READ_REG(hw, IXGBE_HLREG0);
		reg_val |= IXGBE_HLREG0_JUMBOEN;
		IXGBE_WRITE_REG(hw, IXGBE_HLREG0, reg_val);
	}

	/*
	 * Hardware checksum settings
	 */
	if (ixgbe->rx_hcksum_enable) {
		reg_val = IXGBE_RXCSUM_IPPCSE;	/* IP checksum */
		IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, reg_val);
	}

	/*
	 * Setup RSS for multiple receive queues
	 */
	if (ixgbe->num_rx_rings > 1)
		ixgbe_setup_rss(ixgbe);
}

static void
ixgbe_setup_tx_ring(ixgbe_tx_ring_t *tx_ring)
{
	ixgbe_t *ixgbe = tx_ring->ixgbe;
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t size;
	uint32_t buf_low;
	uint32_t buf_high;
	uint32_t reg_val;

	ASSERT(mutex_owned(&tx_ring->tx_lock));
	ASSERT(mutex_owned(&ixgbe->gen_lock));

	/*
	 * Initialize the length register
	 */
	size = tx_ring->ring_size * sizeof (union ixgbe_adv_tx_desc);
	IXGBE_WRITE_REG(hw, IXGBE_TDLEN(tx_ring->index), size);

	/*
	 * Initialize the base address registers
	 */
	buf_low = (uint32_t)tx_ring->tbd_area.dma_address;
	buf_high = (uint32_t)(tx_ring->tbd_area.dma_address >> 32);
	IXGBE_WRITE_REG(hw, IXGBE_TDBAL(tx_ring->index), buf_low);
	IXGBE_WRITE_REG(hw, IXGBE_TDBAH(tx_ring->index), buf_high);

	/*
	 * setup TXDCTL(tx_ring->index)
	 */
	reg_val = IXGBE_TXDCTL_ENABLE;
	IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(tx_ring->index), reg_val);

	/*
	 * Setup head & tail pointers
	 */
	IXGBE_WRITE_REG(hw, IXGBE_TDH(tx_ring->index), 0);
	IXGBE_WRITE_REG(hw, IXGBE_TDT(tx_ring->index), 0);

	/*
	 * Setup head write-back
	 */
	if (ixgbe->tx_head_wb_enable) {
		/*
		 * The memory of the head write-back is allocated using
		 * the extra tbd beyond the tail of the tbd ring.
		 */
		tx_ring->tbd_head_wb = (uint32_t *)
		    ((uintptr_t)tx_ring->tbd_area.address + size);
		*tx_ring->tbd_head_wb = 0;

		buf_low = (uint32_t)
		    (tx_ring->tbd_area.dma_address + size);
		buf_high = (uint32_t)
		    ((tx_ring->tbd_area.dma_address + size) >> 32);

		/* Set the head write-back enable bit */
		buf_low |= IXGBE_TDWBAL_HEAD_WB_ENABLE;

		IXGBE_WRITE_REG(hw, IXGBE_TDWBAL(tx_ring->index), buf_low);
		IXGBE_WRITE_REG(hw, IXGBE_TDWBAH(tx_ring->index), buf_high);

		/*
		 * Turn off relaxed ordering for head write back or it will
		 * cause problems with the tx recycling
		 */
		reg_val = IXGBE_READ_REG(hw,
		    IXGBE_DCA_TXCTRL(tx_ring->index));
		reg_val &= ~IXGBE_DCA_TXCTRL_TX_WB_RO_EN;
		IXGBE_WRITE_REG(hw,
		    IXGBE_DCA_TXCTRL(tx_ring->index), reg_val);
	} else {
		tx_ring->tbd_head_wb = NULL;
	}

	tx_ring->tbd_head = 0;
	tx_ring->tbd_tail = 0;
	tx_ring->tbd_free = tx_ring->ring_size;

	/*
	 * Note: Considering the case that the chipset is being reset,
	 * and there are still some tcb in the pending list,
	 * we should not reset the values of tcb_head, tcb_tail and
	 * tcb_free if the state is not IXGBE_UNKNOWN.
	 */
	if (ixgbe->ixgbe_state == IXGBE_UNKNOWN) {
		tx_ring->tcb_head = 0;
		tx_ring->tcb_tail = 0;
		tx_ring->tcb_free = tx_ring->free_list_size;
	}

	/*
	 * Initialize hardware checksum offload settings
	 */
	tx_ring->tx_context.hcksum_flags = 0;
	tx_ring->tx_context.ip_hdr_len = 0;
	tx_ring->tx_context.mac_hdr_len = 0;
	tx_ring->tx_context.l4_proto = 0;
}

static void
ixgbe_setup_tx(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	ixgbe_tx_ring_t *tx_ring;
	uint32_t reg_val;
	int i;

	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		tx_ring = &ixgbe->tx_rings[i];
		ixgbe_setup_tx_ring(tx_ring);
	}

	/*
	 * Enable CRC appending and TX padding (for short tx frames)
	 */
	reg_val = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	reg_val |= IXGBE_HLREG0_TXCRCEN | IXGBE_HLREG0_TXPADEN;
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, reg_val);
}

/*
 * ixgbe_setup_rss - Setup receive-side scaling feature.
 */
static void
ixgbe_setup_rss(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t i, mrqc, rxcsum;
	uint32_t random;
	uint32_t reta;

	/*
	 * Fill out redirection table
	 */
	reta = 0;
	for (i = 0; i < 128; i++) {
		reta = (reta << 8) | (i % ixgbe->num_rx_rings);
		if ((i & 3) == 3)
			IXGBE_WRITE_REG(hw, IXGBE_RETA(i >> 2), reta);
	}

	/*
	 * Fill out hash function seeds with a random constant
	 */
	for (i = 0; i < 10; i++) {
		(void) random_get_pseudo_bytes((uint8_t *)&random,
		    sizeof (uint32_t));
		IXGBE_WRITE_REG(hw, IXGBE_RSSRK(i), random);
	}

	/*
	 * Enable RSS & perform hash on these packet types
	 */
	mrqc = IXGBE_MRQC_RSSEN |
	    IXGBE_MRQC_RSS_FIELD_IPV4 |
	    IXGBE_MRQC_RSS_FIELD_IPV4_TCP |
	    IXGBE_MRQC_RSS_FIELD_IPV4_UDP |
	    IXGBE_MRQC_RSS_FIELD_IPV6_EX_TCP |
	    IXGBE_MRQC_RSS_FIELD_IPV6_EX |
	    IXGBE_MRQC_RSS_FIELD_IPV6 |
	    IXGBE_MRQC_RSS_FIELD_IPV6_TCP |
	    IXGBE_MRQC_RSS_FIELD_IPV6_UDP |
	    IXGBE_MRQC_RSS_FIELD_IPV6_EX_UDP;
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);

	/*
	 * Disable Packet Checksum to enable RSS for multiple receive queues.
	 * It is an adapter hardware limitation that Packet Checksum is
	 * mutually exclusive with RSS.
	 */
	rxcsum = IXGBE_READ_REG(hw, IXGBE_RXCSUM);
	rxcsum |= IXGBE_RXCSUM_PCSD;
	rxcsum &= ~IXGBE_RXCSUM_IPPCSE;
	IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, rxcsum);
}

/*
 * ixgbe_init_unicst - Initialize the unicast addresses.
 */
static void
ixgbe_init_unicst(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	int slot;
	/*
	 * Here we should consider two situations:
	 *
	 * 1. Chipset is initialized the first time
	 *    Initialize the multiple unicast addresses, and
	 *    save the default mac address.
	 *
	 * 2. Chipset is reset
	 *    Recover the multiple unicast addresses from the
	 *    software data structure to the RAR registers.
	 */
	if (!ixgbe->unicst_init) {
		/*
		 * Initialize the multiple unicast addresses
		 */
		ixgbe->unicst_total = MAX_NUM_UNICAST_ADDRESSES;

		ixgbe->unicst_avail = ixgbe->unicst_total - 1;

		bcopy(hw->mac.addr, ixgbe->unicst_addr[0].mac.addr,
		    ETHERADDRL);
		ixgbe->unicst_addr[0].mac.set = 1;

		for (slot = 1; slot < ixgbe->unicst_total; slot++)
			ixgbe->unicst_addr[slot].mac.set = 0;

		ixgbe->unicst_init = B_TRUE;
	} else {
		/*
		 * Recover the default mac address
		 */
		bcopy(ixgbe->unicst_addr[0].mac.addr, hw->mac.addr,
		    ETHERADDRL);

		/* Re-configure the RAR registers */
		for (slot = 1; slot < ixgbe->unicst_total; slot++)
			(void) ixgbe_set_rar(hw, slot,
			    ixgbe->unicst_addr[slot].mac.addr, NULL, NULL);
	}
}
/*
 * ixgbe_unicst_set - Set the unicast address to the specified slot.
 */
int
ixgbe_unicst_set(ixgbe_t *ixgbe, const uint8_t *mac_addr,
    mac_addr_slot_t slot)
{
	struct ixgbe_hw *hw = &ixgbe->hw;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	/*
	 * Save the unicast address in the software data structure
	 */
	bcopy(mac_addr, ixgbe->unicst_addr[slot].mac.addr, ETHERADDRL);

	/*
	 * Set the unicast address to the RAR register
	 */
	(void) ixgbe_set_rar(hw, slot, (uint8_t *)mac_addr, NULL, NULL);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * ixgbe_multicst_add - Add a multicst address.
 */
int
ixgbe_multicst_add(ixgbe_t *ixgbe, const uint8_t *multiaddr)
{
	ASSERT(mutex_owned(&ixgbe->gen_lock));

	if ((multiaddr[0] & 01) == 0) {
		return (EINVAL);
	}

	if (ixgbe->mcast_count >= MAX_NUM_MULTICAST_ADDRESSES) {
		return (ENOENT);
	}

	bcopy(multiaddr,
	    &ixgbe->mcast_table[ixgbe->mcast_count], ETHERADDRL);
	ixgbe->mcast_count++;

	/*
	 * Update the multicast table in the hardware
	 */
	ixgbe_setup_multicst(ixgbe);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * ixgbe_multicst_remove - Remove a multicst address.
 */
int
ixgbe_multicst_remove(ixgbe_t *ixgbe, const uint8_t *multiaddr)
{
	int i;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	for (i = 0; i < ixgbe->mcast_count; i++) {
		if (bcmp(multiaddr, &ixgbe->mcast_table[i],
		    ETHERADDRL) == 0) {
			for (i++; i < ixgbe->mcast_count; i++) {
				ixgbe->mcast_table[i - 1] =
				    ixgbe->mcast_table[i];
			}
			ixgbe->mcast_count--;
			break;
		}
	}

	/*
	 * Update the multicast table in the hardware
	 */
	ixgbe_setup_multicst(ixgbe);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * ixgbe_setup_multicast - Setup multicast data structures.
 *
 * This routine initializes all of the multicast related structures
 * and save them in the hardware registers.
 */
static void
ixgbe_setup_multicst(ixgbe_t *ixgbe)
{
	uint8_t *mc_addr_list;
	uint32_t mc_addr_count;
	struct ixgbe_hw *hw = &ixgbe->hw;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	ASSERT(ixgbe->mcast_count <= MAX_NUM_MULTICAST_ADDRESSES);

	mc_addr_list = (uint8_t *)ixgbe->mcast_table;
	mc_addr_count = ixgbe->mcast_count;

	/*
	 * Update the multicast addresses to the MTA registers
	 */
	(void) ixgbe_update_mc_addr_list(hw, mc_addr_list, mc_addr_count,
	    ixgbe_mc_table_itr);
}

/*
 * ixgbe_get_conf - Get driver configurations set in driver.conf.
 *
 * This routine gets user-configured values out of the configuration
 * file ixgbe.conf.
 *
 * For each configurable value, there is a minimum, a maximum, and a
 * default.
 * If user does not configure a value, use the default.
 * If user configures below the minimum, use the minumum.
 * If user configures above the maximum, use the maxumum.
 */
static void
ixgbe_get_conf(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t flow_control;

	/*
	 * ixgbe driver supports the following user configurations:
	 *
	 * Jumbo frame configuration:
	 *    default_mtu
	 *
	 * Ethernet flow control configuration:
	 *    flow_control
	 *
	 * Multiple rings configurations:
	 *    tx_queue_number
	 *    tx_ring_size
	 *    rx_queue_number
	 *    rx_ring_size
	 *
	 * Call ixgbe_get_prop() to get the value for a specific
	 * configuration parameter.
	 */

	/*
	 * Jumbo frame configuration - max_frame_size controls host buffer
	 * allocation, so includes MTU, ethernet header, vlan tag and
	 * frame check sequence.
	 */
	ixgbe->default_mtu = ixgbe_get_prop(ixgbe, PROP_DEFAULT_MTU,
	    MIN_MTU, MAX_MTU, DEFAULT_MTU);

	ixgbe->max_frame_size = ixgbe->default_mtu +
	    sizeof (struct ether_vlan_header) + ETHERFCSL;

	/*
	 * Ethernet flow control configuration
	 */
	flow_control = ixgbe_get_prop(ixgbe, PROP_FLOW_CONTROL,
	    ixgbe_fc_none, 3, ixgbe_fc_full);
	if (flow_control == 3)
		flow_control = ixgbe_fc_default;

	hw->fc.type = flow_control;

	/*
	 * Multiple rings configurations
	 */
	ixgbe->num_tx_rings = ixgbe_get_prop(ixgbe, PROP_TX_QUEUE_NUM,
	    MIN_TX_QUEUE_NUM, MAX_TX_QUEUE_NUM, DEFAULT_TX_QUEUE_NUM);
	ixgbe->tx_ring_size = ixgbe_get_prop(ixgbe, PROP_TX_RING_SIZE,
	    MIN_TX_RING_SIZE, MAX_TX_RING_SIZE, DEFAULT_TX_RING_SIZE);

	ixgbe->num_rx_rings = ixgbe_get_prop(ixgbe, PROP_RX_QUEUE_NUM,
	    MIN_RX_QUEUE_NUM, MAX_RX_QUEUE_NUM, DEFAULT_RX_QUEUE_NUM);
	ixgbe->rx_ring_size = ixgbe_get_prop(ixgbe, PROP_RX_RING_SIZE,
	    MIN_RX_RING_SIZE, MAX_RX_RING_SIZE, DEFAULT_RX_RING_SIZE);

	/*
	 * Tunable used to force an interrupt type. The only use is
	 * for testing of the lesser interrupt types.
	 * 0 = don't force interrupt type
	 * 1 = force interrupt type MSIX
	 * 2 = force interrupt type MSI
	 * 3 = force interrupt type Legacy
	 */
	ixgbe->intr_force = ixgbe_get_prop(ixgbe, PROP_INTR_FORCE,
	    IXGBE_INTR_NONE, IXGBE_INTR_LEGACY, IXGBE_INTR_NONE);
	ixgbe_log(ixgbe, "interrupt force: %d\n", ixgbe->intr_force);

	ixgbe->tx_hcksum_enable = ixgbe_get_prop(ixgbe, PROP_TX_HCKSUM_ENABLE,
	    0, 1, DEFAULT_TX_HCKSUM_ENABLE);
	ixgbe->rx_hcksum_enable = ixgbe_get_prop(ixgbe, PROP_RX_HCKSUM_ENABLE,
	    0, 1, DEFAULT_RX_HCKSUM_ENABLE);
	ixgbe->lso_enable = ixgbe_get_prop(ixgbe, PROP_LSO_ENABLE,
	    0, 1, DEFAULT_LSO_ENABLE);
	ixgbe->tx_head_wb_enable = ixgbe_get_prop(ixgbe, PROP_TX_HEAD_WB_ENABLE,
	    0, 1, DEFAULT_TX_HEAD_WB_ENABLE);

	/*
	 * ixgbe LSO needs the tx h/w checksum support.
	 * LSO will be disabled if tx h/w checksum is not
	 * enabled.
	 */
	if (ixgbe->tx_hcksum_enable == B_FALSE) {
		ixgbe->lso_enable = B_FALSE;
	}

	ixgbe->tx_copy_thresh = ixgbe_get_prop(ixgbe, PROP_TX_COPY_THRESHOLD,
	    MIN_TX_COPY_THRESHOLD, MAX_TX_COPY_THRESHOLD,
	    DEFAULT_TX_COPY_THRESHOLD);
	ixgbe->tx_recycle_thresh = ixgbe_get_prop(ixgbe,
	    PROP_TX_RECYCLE_THRESHOLD, MIN_TX_RECYCLE_THRESHOLD,
	    MAX_TX_RECYCLE_THRESHOLD, DEFAULT_TX_RECYCLE_THRESHOLD);
	ixgbe->tx_overload_thresh = ixgbe_get_prop(ixgbe,
	    PROP_TX_OVERLOAD_THRESHOLD, MIN_TX_OVERLOAD_THRESHOLD,
	    MAX_TX_OVERLOAD_THRESHOLD, DEFAULT_TX_OVERLOAD_THRESHOLD);
	ixgbe->tx_resched_thresh = ixgbe_get_prop(ixgbe,
	    PROP_TX_RESCHED_THRESHOLD, MIN_TX_RESCHED_THRESHOLD,
	    MAX_TX_RESCHED_THRESHOLD, DEFAULT_TX_RESCHED_THRESHOLD);

	ixgbe->rx_copy_thresh = ixgbe_get_prop(ixgbe, PROP_RX_COPY_THRESHOLD,
	    MIN_RX_COPY_THRESHOLD, MAX_RX_COPY_THRESHOLD,
	    DEFAULT_RX_COPY_THRESHOLD);
	ixgbe->rx_limit_per_intr = ixgbe_get_prop(ixgbe, PROP_RX_LIMIT_PER_INTR,
	    MIN_RX_LIMIT_PER_INTR, MAX_RX_LIMIT_PER_INTR,
	    DEFAULT_RX_LIMIT_PER_INTR);

	ixgbe->intr_throttling[0] = ixgbe_get_prop(ixgbe, PROP_INTR_THROTTLING,
	    MIN_INTR_THROTTLING, MAX_INTR_THROTTLING,
	    DEFAULT_INTR_THROTTLING);
}

/*
 * ixgbe_get_prop - Get a property value out of the configuration file
 * ixgbe.conf.
 *
 * Caller provides the name of the property, a default value, a minimum
 * value, and a maximum value.
 *
 * Return configured value of the property, with default, minimum and
 * maximum properly applied.
 */
static int
ixgbe_get_prop(ixgbe_t *ixgbe,
    char *propname,	/* name of the property */
    int minval,		/* minimum acceptable value */
    int maxval,		/* maximim acceptable value */
    int defval)		/* default value */
{
	int value;

	/*
	 * Call ddi_prop_get_int() to read the conf settings
	 */
	value = ddi_prop_get_int(DDI_DEV_T_ANY, ixgbe->dip,
	    DDI_PROP_DONTPASS, propname, defval);
	if (value > maxval)
		value = maxval;

	if (value < minval)
		value = minval;

	return (value);
}

/*
 * ixgbe_driver_setup_link - Using the link properties to setup the link.
 */
int
ixgbe_driver_setup_link(ixgbe_t *ixgbe, boolean_t setup_hw)
{
	struct ixgbe_mac_info *mac;
	struct ixgbe_phy_info *phy;
	boolean_t invalid;

	mac = &ixgbe->hw.mac;
	phy = &ixgbe->hw.phy;
	invalid = B_FALSE;

	if (ixgbe->param_adv_autoneg_cap == 1) {
		mac->autoneg = B_TRUE;
		phy->autoneg_advertised = 0;

		/*
		 * No half duplex support with 10Gb parts
		 */
		if (ixgbe->param_adv_10000fdx_cap == 1)
			phy->autoneg_advertised |= IXGBE_LINK_SPEED_10GB_FULL;

		if (ixgbe->param_adv_1000fdx_cap == 1)
			phy->autoneg_advertised |= IXGBE_LINK_SPEED_1GB_FULL;

		if (ixgbe->param_adv_100fdx_cap == 1)
			phy->autoneg_advertised |= IXGBE_LINK_SPEED_100_FULL;

		if (phy->autoneg_advertised == 0)
			invalid = B_TRUE;
	} else {
		ixgbe->hw.mac.autoneg = B_FALSE;
	}

	if (invalid) {
		ixgbe_notice(ixgbe, "Invalid link settings. Setup link to "
		    "autonegotiation with full link capabilities.");
		ixgbe->hw.mac.autoneg = B_TRUE;
	}

	if (setup_hw) {
		if (ixgbe_setup_link(&ixgbe->hw) != IXGBE_SUCCESS)
			return (IXGBE_FAILURE);
	}

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_driver_link_check - Link status processing.
 */
static boolean_t
ixgbe_driver_link_check(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	ixgbe_link_speed speed = IXGBE_LINK_SPEED_UNKNOWN;
	boolean_t link_up = B_FALSE;
	boolean_t link_changed = B_FALSE;

	ASSERT(mutex_owned(&ixgbe->gen_lock));

	(void) ixgbe_check_link(hw, &speed, &link_up);
	if (link_up) {
		/*
		 * The Link is up, check whether it was marked as down earlier
		 */
		if (ixgbe->link_state != LINK_STATE_UP) {
			switch (speed) {
				case IXGBE_LINK_SPEED_10GB_FULL:
					ixgbe->link_speed = SPEED_10GB;
					break;
				case IXGBE_LINK_SPEED_1GB_FULL:
					ixgbe->link_speed = SPEED_1GB;
					break;
				case IXGBE_LINK_SPEED_100_FULL:
					ixgbe->link_speed = SPEED_100;
			}
			ixgbe->link_duplex = LINK_DUPLEX_FULL;
			ixgbe->link_state = LINK_STATE_UP;
			ixgbe->link_down_timeout = 0;
			link_changed = B_TRUE;
		}
	} else {
		if (ixgbe->link_state != LINK_STATE_DOWN) {
			ixgbe->link_speed = 0;
			ixgbe->link_duplex = 0;
			ixgbe->link_state = LINK_STATE_DOWN;
			link_changed = B_TRUE;
		}

		if (ixgbe->ixgbe_state & IXGBE_STARTED) {
			if (ixgbe->link_down_timeout < MAX_LINK_DOWN_TIMEOUT) {
				ixgbe->link_down_timeout++;
			} else if (ixgbe->link_down_timeout ==
			    MAX_LINK_DOWN_TIMEOUT) {
				ixgbe_tx_clean(ixgbe);
				ixgbe->link_down_timeout++;
			}
		}
	}

	return (link_changed);
}

/*
 * ixgbe_local_timer - Driver watchdog function.
 *
 * This function will handle the transmit stall check, link status check and
 * other routines.
 */
static void
ixgbe_local_timer(void *arg)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;

	if (ixgbe_stall_check(ixgbe)) {
		ixgbe->reset_count++;
		if (ixgbe_reset(ixgbe) == IXGBE_SUCCESS)
			ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_RESTORED);
	}

	ixgbe_restart_watchdog_timer(ixgbe);
}

/*
 * ixgbe_stall_check - Check for transmit stall.
 *
 * This function checks if the adapter is stalled (in transmit).
 *
 * It is called each time the watchdog timeout is invoked.
 * If the transmit descriptor reclaim continuously fails,
 * the watchdog value will increment by 1. If the watchdog
 * value exceeds the threshold, the ixgbe is assumed to
 * have stalled and need to be reset.
 */
static boolean_t
ixgbe_stall_check(ixgbe_t *ixgbe)
{
	ixgbe_tx_ring_t *tx_ring;
	boolean_t result;
	int i;

	if (ixgbe->link_state != LINK_STATE_UP)
		return (B_FALSE);

	/*
	 * If any tx ring is stalled, we'll reset the chipset
	 */
	result = B_FALSE;
	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		tx_ring = &ixgbe->tx_rings[i];

		if (tx_ring->recycle_fail > 0)
			tx_ring->stall_watchdog++;
		else
			tx_ring->stall_watchdog = 0;

		if (tx_ring->stall_watchdog >= STALL_WATCHDOG_TIMEOUT) {
			result = B_TRUE;
			break;
		}
	}

	if (result) {
		tx_ring->stall_watchdog = 0;
		tx_ring->recycle_fail = 0;
	}

	return (result);
}


/*
 * is_valid_mac_addr - Check if the mac address is valid.
 */
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

static boolean_t
ixgbe_find_mac_address(ixgbe_t *ixgbe)
{
#ifdef __sparc
	struct ixgbe_hw *hw = &ixgbe->hw;
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
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ixgbe->dip,
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
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ixgbe->dip, 0,
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
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ixgbe->dip,
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
		bcopy(hw->mac.addr, hw->mac.perm_addr, ETHERADDRL);
		return (B_TRUE);
	}
#else
	_NOTE(ARGUNUSED(ixgbe));
#endif

	return (B_TRUE);
}

#pragma inline(ixgbe_arm_watchdog_timer)
static void
ixgbe_arm_watchdog_timer(ixgbe_t *ixgbe)
{
	/*
	 * Fire a watchdog timer
	 */
	ixgbe->watchdog_tid =
	    timeout(ixgbe_local_timer,
	    (void *)ixgbe, 1 * drv_usectohz(1000000));

}

/*
 * ixgbe_enable_watchdog_timer - Enable and start the driver watchdog timer.
 */
void
ixgbe_enable_watchdog_timer(ixgbe_t *ixgbe)
{
	mutex_enter(&ixgbe->watchdog_lock);

	if (!ixgbe->watchdog_enable) {
		ixgbe->watchdog_enable = B_TRUE;
		ixgbe->watchdog_start = B_TRUE;
		ixgbe_arm_watchdog_timer(ixgbe);
	}

	mutex_exit(&ixgbe->watchdog_lock);
}

/*
 * ixgbe_disable_watchdog_timer - Disable and stop the driver watchdog timer.
 */
void
ixgbe_disable_watchdog_timer(ixgbe_t *ixgbe)
{
	timeout_id_t tid;

	mutex_enter(&ixgbe->watchdog_lock);

	ixgbe->watchdog_enable = B_FALSE;
	ixgbe->watchdog_start = B_FALSE;
	tid = ixgbe->watchdog_tid;
	ixgbe->watchdog_tid = 0;

	mutex_exit(&ixgbe->watchdog_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

/*
 * ixgbe_start_watchdog_timer - Start the driver watchdog timer.
 */
static void
ixgbe_start_watchdog_timer(ixgbe_t *ixgbe)
{
	mutex_enter(&ixgbe->watchdog_lock);

	if (ixgbe->watchdog_enable) {
		if (!ixgbe->watchdog_start) {
			ixgbe->watchdog_start = B_TRUE;
			ixgbe_arm_watchdog_timer(ixgbe);
		}
	}

	mutex_exit(&ixgbe->watchdog_lock);
}

/*
 * ixgbe_restart_watchdog_timer - Restart the driver watchdog timer.
 */
static void
ixgbe_restart_watchdog_timer(ixgbe_t *ixgbe)
{
	mutex_enter(&ixgbe->watchdog_lock);

	if (ixgbe->watchdog_start)
		ixgbe_arm_watchdog_timer(ixgbe);

	mutex_exit(&ixgbe->watchdog_lock);
}

/*
 * ixgbe_stop_watchdog_timer - Stop the driver watchdog timer.
 */
static void
ixgbe_stop_watchdog_timer(ixgbe_t *ixgbe)
{
	timeout_id_t tid;

	mutex_enter(&ixgbe->watchdog_lock);

	ixgbe->watchdog_start = B_FALSE;
	tid = ixgbe->watchdog_tid;
	ixgbe->watchdog_tid = 0;

	mutex_exit(&ixgbe->watchdog_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

/*
 * ixgbe_disable_adapter_interrupts - Disable all adapter interrupts.
 */
static void
ixgbe_disable_adapter_interrupts(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;

	/*
	 * mask all interrupts off
	 */
	IXGBE_WRITE_REG(hw, IXGBE_EIMC, 0xffffffff);

	/*
	 * for MSI-X, also disable autoclear
	 */
	if (ixgbe->intr_type == DDI_INTR_TYPE_MSIX) {
		IXGBE_WRITE_REG(hw, IXGBE_EIAC, 0x0);
	}

	IXGBE_WRITE_FLUSH(hw);
}

/*
 * ixgbe_enable_adapter_interrupts - Enable all hardware interrupts.
 */
static void
ixgbe_enable_adapter_interrupts(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t eims, eiac, gpie;

	gpie = 0;
	eims = IXGBE_EIMS_ENABLE_MASK;	/* shared code default */
	eims &= ~IXGBE_EIMS_TCP_TIMER;	/* minus tcp timer */

	/*
	 * msi-x mode
	 */
	if (ixgbe->intr_type == DDI_INTR_TYPE_MSIX) {
		/* enable autoclear but not on bits 29:20 */
		eiac = (eims & ~0x3ff00000);

		/* general purpose interrupt enable */
		gpie |= (IXGBE_GPIE_MSIX_MODE |
		    IXGBE_GPIE_PBA_SUPPORT |IXGBE_GPIE_OCD);
	/*
	 * non-msi-x mode
	 */
	} else {

		/* disable autoclear, leave gpie at default */
		eiac = 0;
	}

	IXGBE_WRITE_REG(hw, IXGBE_EIMS, eims);
	IXGBE_WRITE_REG(hw, IXGBE_EIAC, eiac);
	IXGBE_WRITE_REG(hw, IXGBE_GPIE, gpie);
	IXGBE_WRITE_FLUSH(hw);
}

/*
 * ixgbe_loopback_ioctl - Loopback support.
 */
enum ioc_reply
ixgbe_loopback_ioctl(ixgbe_t *ixgbe, struct iocblk *iocp, mblk_t *mp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	uint32_t *lbmp;
	uint32_t size;
	uint32_t value;

	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	switch (iocp->ioc_cmd) {
	default:
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		size = sizeof (lb_info_sz_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		value = sizeof (lb_normal);
		value += sizeof (lb_mac);

		lbsp = (lb_info_sz_t *)(uintptr_t)mp->b_cont->b_rptr;
		*lbsp = value;
		break;

	case LB_GET_INFO:
		value = sizeof (lb_normal);
		value += sizeof (lb_mac);

		size = value;
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		value = 0;
		lbpp = (lb_property_t *)(uintptr_t)mp->b_cont->b_rptr;

		lbpp[value++] = lb_normal;
		lbpp[value++] = lb_mac;
		break;

	case LB_GET_MODE:
		size = sizeof (uint32_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		lbmp = (uint32_t *)(uintptr_t)mp->b_cont->b_rptr;
		*lbmp = ixgbe->loopback_mode;
		break;

	case LB_SET_MODE:
		size = 0;
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);

		lbmp = (uint32_t *)(uintptr_t)mp->b_cont->b_rptr;
		if (!ixgbe_set_loopback_mode(ixgbe, *lbmp))
			return (IOC_INVAL);
		break;
	}

	iocp->ioc_count = size;
	iocp->ioc_error = 0;

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
		return (IOC_INVAL);
	}

	return (IOC_REPLY);
}

/*
 * ixgbe_set_loopback_mode - Setup loopback based on the loopback mode.
 */
static boolean_t
ixgbe_set_loopback_mode(ixgbe_t *ixgbe, uint32_t mode)
{
	struct ixgbe_hw *hw;

	if (mode == ixgbe->loopback_mode)
		return (B_TRUE);

	hw = &ixgbe->hw;

	ixgbe->loopback_mode = mode;

	if (mode == IXGBE_LB_NONE) {
		/*
		 * Reset the chip
		 */
		hw->phy.autoneg_wait_to_complete = B_TRUE;
		(void) ixgbe_reset(ixgbe);
		hw->phy.autoneg_wait_to_complete = B_FALSE;
		return (B_TRUE);
	}

	mutex_enter(&ixgbe->gen_lock);

	switch (mode) {
	default:
		mutex_exit(&ixgbe->gen_lock);
		return (B_FALSE);

	case IXGBE_LB_INTERNAL_MAC:
		ixgbe_set_internal_mac_loopback(ixgbe);
		break;
	}

	mutex_exit(&ixgbe->gen_lock);

	return (B_TRUE);
}

/*
 * ixgbe_set_internal_mac_loopback - Set the internal MAC loopback mode.
 */
static void
ixgbe_set_internal_mac_loopback(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw;
	uint32_t reg;
	uint8_t atlas;

	hw = &ixgbe->hw;

	/*
	 * Setup MAC loopback
	 */
	reg = IXGBE_READ_REG(&ixgbe->hw, IXGBE_HLREG0);
	reg |= IXGBE_HLREG0_LPBK;
	IXGBE_WRITE_REG(&ixgbe->hw, IXGBE_HLREG0, reg);

	reg = IXGBE_READ_REG(&ixgbe->hw, IXGBE_AUTOC);
	reg &= ~IXGBE_AUTOC_LMS_MASK;
	IXGBE_WRITE_REG(&ixgbe->hw, IXGBE_AUTOC, reg);

	/*
	 * Disable Atlas Tx lanes to keep packets in loopback and not on wire
	 */
	if (hw->mac.type == ixgbe_mac_82598EB) {
		(void) ixgbe_read_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_LPBK,
		    &atlas);
		atlas |= IXGBE_ATLAS_PDN_TX_REG_EN;
		(void) ixgbe_write_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_LPBK,
		    atlas);

		(void) ixgbe_read_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_10G,
		    &atlas);
		atlas |= IXGBE_ATLAS_PDN_TX_10G_QL_ALL;
		(void) ixgbe_write_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_10G,
		    atlas);

		(void) ixgbe_read_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_1G,
		    &atlas);
		atlas |= IXGBE_ATLAS_PDN_TX_1G_QL_ALL;
		(void) ixgbe_write_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_1G,
		    atlas);

		(void) ixgbe_read_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_AN,
		    &atlas);
		atlas |= IXGBE_ATLAS_PDN_TX_AN_QL_ALL;
		(void) ixgbe_write_analog_reg8(&ixgbe->hw, IXGBE_ATLAS_PDN_AN,
		    atlas);
	}
}

#pragma inline(ixgbe_intr_rx_work)
/*
 * ixgbe_intr_rx_work - RX processing of ISR.
 */
static void
ixgbe_intr_rx_work(ixgbe_rx_ring_t *rx_ring)
{
	mblk_t *mp;

	mutex_enter(&rx_ring->rx_lock);

	mp = ixgbe_rx(rx_ring);
	mutex_exit(&rx_ring->rx_lock);

	if (mp != NULL)
		mac_rx(rx_ring->ixgbe->mac_hdl, NULL, mp);
}

#pragma inline(ixgbe_intr_tx_work)
/*
 * ixgbe_intr_tx_work - TX processing of ISR.
 */
static void
ixgbe_intr_tx_work(ixgbe_tx_ring_t *tx_ring)
{
	/*
	 * Recycle the tx descriptors
	 */
	tx_ring->tx_recycle(tx_ring);

	/*
	 * Schedule the re-transmit
	 */
	if (tx_ring->reschedule &&
	    (tx_ring->tbd_free >= tx_ring->resched_thresh)) {
		tx_ring->reschedule = B_FALSE;
		mac_tx_update(tx_ring->ixgbe->mac_hdl);
		IXGBE_DEBUG_STAT(tx_ring->stat_reschedule);
	}
}

#pragma inline(ixgbe_intr_other_work)
/*
 * ixgbe_intr_other_work - Other processing of ISR.
 */
static void
ixgbe_intr_other_work(ixgbe_t *ixgbe)
{
	boolean_t link_changed;

	ixgbe_stop_watchdog_timer(ixgbe);

	mutex_enter(&ixgbe->gen_lock);

	/*
	 * Take care of link status change
	 */
	link_changed = ixgbe_driver_link_check(ixgbe);

	/*
	 * Get new phy state
	 */
	ixgbe_get_hw_state(ixgbe);

	mutex_exit(&ixgbe->gen_lock);

	if (link_changed)
		mac_link_update(ixgbe->mac_hdl, ixgbe->link_state);

	ixgbe_start_watchdog_timer(ixgbe);
}

/*
 * ixgbe_intr_legacy - Interrupt handler for legacy interrupts.
 */
static uint_t
ixgbe_intr_legacy(void *arg1, void *arg2)
{
	_NOTE(ARGUNUSED(arg2));
	ixgbe_t *ixgbe = (ixgbe_t *)arg1;
	struct ixgbe_hw *hw = &ixgbe->hw;
	ixgbe_tx_ring_t *tx_ring;
	uint32_t eicr;
	mblk_t *mp;
	boolean_t tx_reschedule;
	boolean_t link_changed;
	uint_t result;


	mutex_enter(&ixgbe->gen_lock);

	if (ixgbe->ixgbe_state & IXGBE_SUSPENDED) {
		mutex_exit(&ixgbe->gen_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	mp = NULL;
	tx_reschedule = B_FALSE;
	link_changed = B_FALSE;

	/*
	 * Any bit set in eicr: claim this interrupt
	 */
	eicr = IXGBE_READ_REG(hw, IXGBE_EICR);
	if (eicr) {
		/*
		 * For legacy interrupt, we have only one interrupt,
		 * so we have only one rx ring and one tx ring enabled.
		 */
		ASSERT(ixgbe->num_rx_rings == 1);
		ASSERT(ixgbe->num_tx_rings == 1);

		/*
		 * For legacy interrupt, we can't differentiate
		 * between tx and rx, so always clean both
		 */
		if (eicr & IXGBE_EICR_RTX_QUEUE) {

			/*
			 * Clean the rx descriptors
			 */
			mp = ixgbe_rx(&ixgbe->rx_rings[0]);

			/*
			 * Recycle the tx descriptors
			 */
			tx_ring = &ixgbe->tx_rings[0];
			tx_ring->tx_recycle(tx_ring);

			/*
			 * Schedule the re-transmit
			 */
			tx_reschedule = (tx_ring->reschedule &&
			    (tx_ring->tbd_free >= tx_ring->resched_thresh));
		}

		if (eicr & IXGBE_EICR_LSC) {

			/* take care of link status change */
			link_changed = ixgbe_driver_link_check(ixgbe);

			/* Get new phy state */
			ixgbe_get_hw_state(ixgbe);
		}

		result = DDI_INTR_CLAIMED;
	} else {
		/*
		 * No interrupt cause bits set: don't claim this interrupt.
		 */
		result = DDI_INTR_UNCLAIMED;
	}

	mutex_exit(&ixgbe->gen_lock);

	/*
	 * Do the following work outside of the gen_lock
	 */
	if (mp != NULL)
		mac_rx(ixgbe->mac_hdl, NULL, mp);

	if (tx_reschedule)  {
		tx_ring->reschedule = B_FALSE;
		mac_tx_update(ixgbe->mac_hdl);
		IXGBE_DEBUG_STAT(tx_ring->stat_reschedule);
	}

	if (link_changed)
		mac_link_update(ixgbe->mac_hdl, ixgbe->link_state);

	return (result);
}

/*
 * ixgbe_intr_msi - Interrupt handler for MSI.
 */
static uint_t
ixgbe_intr_msi(void *arg1, void *arg2)
{
	_NOTE(ARGUNUSED(arg2));
	ixgbe_t *ixgbe = (ixgbe_t *)arg1;
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t eicr;

	eicr = IXGBE_READ_REG(hw, IXGBE_EICR);

	/*
	 * For MSI interrupt, we have only one vector,
	 * so we have only one rx ring and one tx ring enabled.
	 */
	ASSERT(ixgbe->num_rx_rings == 1);
	ASSERT(ixgbe->num_tx_rings == 1);

	/*
	 * For MSI interrupt, we can't differentiate
	 * between tx and rx, so always clean both.
	 */
	if (eicr & IXGBE_EICR_RTX_QUEUE) {
		ixgbe_intr_rx_work(&ixgbe->rx_rings[0]);
		ixgbe_intr_tx_work(&ixgbe->tx_rings[0]);
	}

	if (eicr & IXGBE_EICR_LSC) {
		ixgbe_intr_other_work(ixgbe);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * ixgbe_intr_rx - Interrupt handler for rx.
 */
static uint_t
ixgbe_intr_rx(void *arg1, void *arg2)
{
	_NOTE(ARGUNUSED(arg2));
	ixgbe_ring_vector_t	*vect = (ixgbe_ring_vector_t *)arg1;
	ixgbe_t			*ixgbe = vect->ixgbe;
	int			r_idx;

	/*
	 * clean each rx ring that has its bit set in the map
	 */
	r_idx = bt_getlowbit(vect->rx_map, 0, (ixgbe->num_rx_rings - 1));

	while (r_idx >= 0) {
		ixgbe_intr_rx_work(&ixgbe->rx_rings[r_idx]);
		r_idx = bt_getlowbit(vect->rx_map, (r_idx + 1),
		    (ixgbe->num_rx_rings - 1));
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * ixgbe_intr_tx_other - Interrupt handler for both tx and other.
 *
 * Always look for Tx cleanup work.  Only look for other work if the right
 * bits are set in the Interrupt Cause Register.
 */
static uint_t
ixgbe_intr_tx_other(void *arg1, void *arg2)
{
	_NOTE(ARGUNUSED(arg2));
	ixgbe_t *ixgbe = (ixgbe_t *)arg1;
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t eicr;

	eicr = IXGBE_READ_REG(hw, IXGBE_EICR);

	/*
	 * Always look for Tx cleanup work.  We don't have separate
	 * transmit vectors, so we have only one tx ring enabled.
	 */
	ASSERT(ixgbe->num_tx_rings == 1);
	ixgbe_intr_tx_work(&ixgbe->tx_rings[0]);

	/*
	 * Check for "other" causes.
	 */
	if (eicr & IXGBE_EICR_LSC) {
		ixgbe_intr_other_work(ixgbe);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * ixgbe_alloc_intrs - Allocate interrupts for the driver.
 *
 * Normal sequence is to try MSI-X; if not sucessful, try MSI;
 * if not successful, try Legacy.
 * ixgbe->intr_force can be used to force sequence to start with
 * any of the 3 types.
 * If MSI-X is not used, number of tx/rx rings is forced to 1.
 */
static int
ixgbe_alloc_intrs(ixgbe_t *ixgbe)
{
	dev_info_t *devinfo;
	int intr_types;
	int rc;

	devinfo = ixgbe->dip;

	/*
	 * Get supported interrupt types
	 */
	rc = ddi_intr_get_supported_types(devinfo, &intr_types);

	if (rc != DDI_SUCCESS) {
		ixgbe_log(ixgbe,
		    "Get supported interrupt types failed: %d", rc);
		return (IXGBE_FAILURE);
	}
	IXGBE_DEBUGLOG_1(ixgbe, "Supported interrupt types: %x", intr_types);

	ixgbe->intr_type = 0;

	/*
	 * Install MSI-X interrupts
	 */
	if ((intr_types & DDI_INTR_TYPE_MSIX) &&
	    (ixgbe->intr_force <= IXGBE_INTR_MSIX)) {
		rc = ixgbe_alloc_intr_handles(ixgbe, DDI_INTR_TYPE_MSIX);
		if (rc == IXGBE_SUCCESS)
			return (IXGBE_SUCCESS);

		ixgbe_log(ixgbe,
		    "Allocate MSI-X failed, trying MSI interrupts...");
	}

	/*
	 * MSI-X not used, force rings to 1
	 */
	ixgbe->num_rx_rings = 1;
	ixgbe->num_tx_rings = 1;
	ixgbe_log(ixgbe,
	    "MSI-X not used, force rx and tx queue number to 1");

	/*
	 * Install MSI interrupts
	 */
	if ((intr_types & DDI_INTR_TYPE_MSI) &&
	    (ixgbe->intr_force <= IXGBE_INTR_MSI)) {
		rc = ixgbe_alloc_intr_handles(ixgbe, DDI_INTR_TYPE_MSI);
		if (rc == IXGBE_SUCCESS)
			return (IXGBE_SUCCESS);

		ixgbe_log(ixgbe,
		    "Allocate MSI failed, trying Legacy interrupts...");
	}

	/*
	 * Install legacy interrupts
	 */
	if (intr_types & DDI_INTR_TYPE_FIXED) {
		rc = ixgbe_alloc_intr_handles(ixgbe, DDI_INTR_TYPE_FIXED);
		if (rc == IXGBE_SUCCESS)
			return (IXGBE_SUCCESS);

		ixgbe_log(ixgbe,
		    "Allocate Legacy interrupts failed");
	}

	/*
	 * If none of the 3 types succeeded, return failure
	 */
	return (IXGBE_FAILURE);
}

/*
 * ixgbe_alloc_intr_handles - Allocate interrupt handles.
 *
 * For legacy and MSI, only 1 handle is needed.  For MSI-X,
 * if fewer than 2 handles are available, return failure.
 * Upon success, this sets the number of Rx rings to a number that
 * matches the handles available for Rx interrupts.
 */
static int
ixgbe_alloc_intr_handles(ixgbe_t *ixgbe, int intr_type)
{
	dev_info_t *devinfo;
	int request, count, avail, actual;
	int rx_rings, minimum;
	int rc;

	devinfo = ixgbe->dip;

	/*
	 * Currently only 1 tx ring is supported. More tx rings
	 * will be supported with future enhancement.
	 */
	if (ixgbe->num_tx_rings > 1) {
		ixgbe->num_tx_rings = 1;
		ixgbe_log(ixgbe,
		    "Use only 1 MSI-X vector for tx, "
		    "force tx queue number to 1");
	}

	switch (intr_type) {
	case DDI_INTR_TYPE_FIXED:
		request = 1;	/* Request 1 legacy interrupt handle */
		minimum = 1;
		IXGBE_DEBUGLOG_0(ixgbe, "interrupt type: legacy");
		break;

	case DDI_INTR_TYPE_MSI:
		request = 1;	/* Request 1 MSI interrupt handle */
		minimum = 1;
		IXGBE_DEBUGLOG_0(ixgbe, "interrupt type: MSI");
		break;

	case DDI_INTR_TYPE_MSIX:
		/*
		 * Best number of vectors for the adapter is
		 * # rx rings + # tx rings + 1 for other
		 * But currently we only support number of vectors of
		 * # rx rings + 1 for tx & other
		 */
		request = ixgbe->num_rx_rings + 1;
		minimum = 2;
		IXGBE_DEBUGLOG_0(ixgbe, "interrupt type: MSI-X");
		break;

	default:
		ixgbe_log(ixgbe,
		    "invalid call to ixgbe_alloc_intr_handles(): %d\n",
		    intr_type);
		return (IXGBE_FAILURE);
	}
	IXGBE_DEBUGLOG_2(ixgbe, "interrupt handles requested: %d  minimum: %d",
	    request, minimum);

	/*
	 * Get number of supported interrupts
	 */
	rc = ddi_intr_get_nintrs(devinfo, intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count < minimum)) {
		ixgbe_log(ixgbe,
		    "Get interrupt number failed. Return: %d, count: %d",
		    rc, count);
		return (IXGBE_FAILURE);
	}
	IXGBE_DEBUGLOG_1(ixgbe, "interrupts supported: %d", count);

	/*
	 * Get number of available interrupts
	 */
	rc = ddi_intr_get_navail(devinfo, intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail < minimum)) {
		ixgbe_log(ixgbe,
		    "Get interrupt available number failed. "
		    "Return: %d, available: %d", rc, avail);
		return (IXGBE_FAILURE);
	}
	IXGBE_DEBUGLOG_1(ixgbe, "interrupts available: %d", avail);

	if (avail < request) {
		ixgbe_log(ixgbe, "Request %d handles, %d available",
		    request, avail);
		request = avail;
	}

	actual = 0;
	ixgbe->intr_cnt = 0;

	/*
	 * Allocate an array of interrupt handles
	 */
	ixgbe->intr_size = request * sizeof (ddi_intr_handle_t);
	ixgbe->htable = kmem_alloc(ixgbe->intr_size, KM_SLEEP);

	rc = ddi_intr_alloc(devinfo, ixgbe->htable, intr_type, 0,
	    request, &actual, DDI_INTR_ALLOC_NORMAL);
	if (rc != DDI_SUCCESS) {
		ixgbe_log(ixgbe, "Allocate interrupts failed. "
		    "return: %d, request: %d, actual: %d",
		    rc, request, actual);
		goto alloc_handle_fail;
	}
	IXGBE_DEBUGLOG_1(ixgbe, "interrupts actually allocated: %d", actual);

	ixgbe->intr_cnt = actual;

	/*
	 * Now we know the actual number of vectors.  Here we assume that
	 * tx and other will share 1 vector and all remaining (must be at
	 * least 1 remaining) will be used for rx.
	 */
	if (actual < minimum) {
		ixgbe_log(ixgbe, "Insufficient interrupt handles available: %d",
		    actual);
		goto alloc_handle_fail;
	}

	/*
	 * For MSI-X, actual might force us to reduce number of rx rings
	 */
	if (intr_type == DDI_INTR_TYPE_MSIX) {
		rx_rings = actual - 1;
		if (rx_rings < ixgbe->num_rx_rings) {
			ixgbe_log(ixgbe,
			    "MSI-X vectors force Rx queue number to %d",
			    rx_rings);
			ixgbe->num_rx_rings = rx_rings;
		}
	}

	/*
	 * Get priority for first vector, assume remaining are all the same
	 */
	rc = ddi_intr_get_pri(ixgbe->htable[0], &ixgbe->intr_pri);
	if (rc != DDI_SUCCESS) {
		ixgbe_log(ixgbe,
		    "Get interrupt priority failed: %d", rc);
		goto alloc_handle_fail;
	}

	rc = ddi_intr_get_cap(ixgbe->htable[0], &ixgbe->intr_cap);
	if (rc != DDI_SUCCESS) {
		ixgbe_log(ixgbe,
		    "Get interrupt cap failed: %d", rc);
		goto alloc_handle_fail;
	}

	ixgbe->intr_type = intr_type;

	return (IXGBE_SUCCESS);

alloc_handle_fail:
	ixgbe_rem_intrs(ixgbe);

	return (IXGBE_FAILURE);
}

/*
 * ixgbe_add_intr_handlers - Add interrupt handlers based on the interrupt type.
 *
 * Before adding the interrupt handlers, the interrupt vectors have
 * been allocated, and the rx/tx rings have also been allocated.
 */
static int
ixgbe_add_intr_handlers(ixgbe_t *ixgbe)
{
	ixgbe_rx_ring_t *rx_ring;
	int vector;
	int rc;
	int i;

	vector = 0;

	switch (ixgbe->intr_type) {
	case DDI_INTR_TYPE_MSIX:
		/*
		 * Add interrupt handler for tx + other
		 */
		rc = ddi_intr_add_handler(ixgbe->htable[vector],
		    (ddi_intr_handler_t *)ixgbe_intr_tx_other,
		    (void *)ixgbe, NULL);
		if (rc != DDI_SUCCESS) {
			ixgbe_log(ixgbe,
			    "Add tx/other interrupt handler failed: %d", rc);
			return (IXGBE_FAILURE);
		}
		vector++;

		/*
		 * Add interrupt handler for each rx ring
		 */
		for (i = 0; i < ixgbe->num_rx_rings; i++) {
			rx_ring = &ixgbe->rx_rings[i];

			/*
			 * install pointer to vect_map[vector]
			 */
			rc = ddi_intr_add_handler(ixgbe->htable[vector],
			    (ddi_intr_handler_t *)ixgbe_intr_rx,
			    (void *)&ixgbe->vect_map[vector], NULL);

			if (rc != DDI_SUCCESS) {
				ixgbe_log(ixgbe,
				    "Add rx interrupt handler failed. "
				    "return: %d, rx ring: %d", rc, i);
				for (vector--; vector >= 0; vector--) {
					(void) ddi_intr_remove_handler(
					    ixgbe->htable[vector]);
				}
				return (IXGBE_FAILURE);
			}

			rx_ring->intr_vector = vector;

			vector++;
		}
		break;

	case DDI_INTR_TYPE_MSI:
		/*
		 * Add interrupt handlers for the only vector
		 */
		rc = ddi_intr_add_handler(ixgbe->htable[vector],
		    (ddi_intr_handler_t *)ixgbe_intr_msi,
		    (void *)ixgbe, NULL);

		if (rc != DDI_SUCCESS) {
			ixgbe_log(ixgbe,
			    "Add MSI interrupt handler failed: %d", rc);
			return (IXGBE_FAILURE);
		}

		rx_ring = &ixgbe->rx_rings[0];
		rx_ring->intr_vector = vector;

		vector++;
		break;

	case DDI_INTR_TYPE_FIXED:
		/*
		 * Add interrupt handlers for the only vector
		 */
		rc = ddi_intr_add_handler(ixgbe->htable[vector],
		    (ddi_intr_handler_t *)ixgbe_intr_legacy,
		    (void *)ixgbe, NULL);

		if (rc != DDI_SUCCESS) {
			ixgbe_log(ixgbe,
			    "Add legacy interrupt handler failed: %d", rc);
			return (IXGBE_FAILURE);
		}

		rx_ring = &ixgbe->rx_rings[0];
		rx_ring->intr_vector = vector;

		vector++;
		break;

	default:
		return (IXGBE_FAILURE);
	}

	ASSERT(vector == ixgbe->intr_cnt);

	return (IXGBE_SUCCESS);
}

#pragma inline(ixgbe_map_rxring_to_vector)
/*
 * ixgbe_map_rxring_to_vector - Map given rx ring to given interrupt vector.
 */
static void
ixgbe_map_rxring_to_vector(ixgbe_t *ixgbe, int r_idx, int v_idx)
{
	ixgbe->vect_map[v_idx].ixgbe = ixgbe;

	/*
	 * Set bit in map
	 */
	BT_SET(ixgbe->vect_map[v_idx].rx_map, r_idx);

	/*
	 * Count bits set
	 */
	ixgbe->vect_map[v_idx].rxr_cnt++;

	/*
	 * Remember bit position
	 */
	ixgbe->rx_rings[r_idx].vect_bit = 1 << v_idx;
}

#pragma inline(ixgbe_map_txring_to_vector)
/*
 * ixgbe_map_txring_to_vector - Map given tx ring to given interrupt vector.
 */
static void
ixgbe_map_txring_to_vector(ixgbe_t *ixgbe, int t_idx, int v_idx)
{
	ixgbe->vect_map[v_idx].ixgbe = ixgbe;

	/*
	 * Set bit in map
	 */
	BT_SET(ixgbe->vect_map[v_idx].tx_map, t_idx);

	/*
	 * Count bits set
	 */
	ixgbe->vect_map[v_idx].txr_cnt++;

	/*
	 * Remember bit position
	 */
	ixgbe->tx_rings[t_idx].vect_bit = 1 << v_idx;
}

/*
 * ixgbe_set_ivar - Set the given entry in the given interrupt vector
 * allocation register (IVAR).
 */
static void
ixgbe_set_ivar(ixgbe_t *ixgbe, uint16_t int_alloc_entry, uint8_t msix_vector)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	u32 ivar, index;

	msix_vector |= IXGBE_IVAR_ALLOC_VAL;
	index = (int_alloc_entry >> 2) & 0x1F;
	ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(index));
	ivar &= ~(0xFF << (8 * (int_alloc_entry & 0x3)));
	ivar |= (msix_vector << (8 * (int_alloc_entry & 0x3)));
	IXGBE_WRITE_REG(hw, IXGBE_IVAR(index), ivar);
}

/*
 * ixgbe_map_rings_to_vectors - Map descriptor rings to interrupt vectors.
 *
 * For msi-x, this currently implements only the scheme which is
 * 1 vector for tx + other, 1 vector for each rx ring.
 */
static int
ixgbe_map_rings_to_vectors(ixgbe_t *ixgbe)
{
	int i, vector = 0;
	int vect_remain = ixgbe->intr_cnt;

	/* initialize vector map */
	bzero(&ixgbe->vect_map, sizeof (ixgbe->vect_map));

	/*
	 * non-MSI-X case is very simple: all interrupts on vector 0
	 */
	if (ixgbe->intr_type != DDI_INTR_TYPE_MSIX) {
		ixgbe_map_rxring_to_vector(ixgbe, 0, 0);
		ixgbe_map_txring_to_vector(ixgbe, 0, 0);
		return (IXGBE_SUCCESS);
	}

	/*
	 * Ring/vector mapping for MSI-X
	 */

	/*
	 * Map vector 0 to tx
	 */
	ixgbe_map_txring_to_vector(ixgbe, 0, vector++);
	vect_remain--;

	/*
	 * Map remaining vectors to rx rings
	 */
	for (i = 0; i < vect_remain; i++) {
		ixgbe_map_rxring_to_vector(ixgbe, i, vector++);
	}

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_setup_adapter_vector - Setup the adapter interrupt vector(s).
 *
 * This relies on queue/vector mapping already set up in the
 * vect_map[] structures
 */
static void
ixgbe_setup_adapter_vector(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	ixgbe_ring_vector_t	*vect;	/* vector bitmap */
	int			r_idx;	/* ring index */
	int			v_idx;	/* vector index */

	/*
	 * Clear any previous entries
	 */
	for (v_idx = 0; v_idx < IXGBE_IVAR_REG_NUM; v_idx++)
		IXGBE_WRITE_REG(hw, IXGBE_IVAR(v_idx), 0);

	/*
	 * "Other" is always on vector 0
	 */
	ixgbe_set_ivar(ixgbe, IXGBE_IVAR_OTHER_CAUSES_INDEX, 0);

	/*
	 * For each interrupt vector, populate the IVAR table
	 */
	for (v_idx = 0; v_idx < ixgbe->intr_cnt; v_idx++) {
		vect = &ixgbe->vect_map[v_idx];

		/*
		 * For each rx ring bit set
		 */
		r_idx = bt_getlowbit(vect->rx_map, 0,
		    (ixgbe->num_rx_rings - 1));

		while (r_idx >= 0) {
			ixgbe_set_ivar(ixgbe, IXGBE_IVAR_RX_QUEUE(r_idx),
			    v_idx);
			r_idx = bt_getlowbit(vect->rx_map, (r_idx + 1),
			    (ixgbe->num_rx_rings - 1));
		}

		/*
		 * For each tx ring bit set
		 */
		r_idx = bt_getlowbit(vect->tx_map, 0,
		    (ixgbe->num_tx_rings - 1));

		while (r_idx >= 0) {
			ixgbe_set_ivar(ixgbe, IXGBE_IVAR_TX_QUEUE(r_idx),
			    v_idx);
			r_idx = bt_getlowbit(vect->tx_map, (r_idx + 1),
			    (ixgbe->num_tx_rings - 1));
		}
	}
}

/*
 * ixgbe_rem_intr_handlers - Remove the interrupt handlers.
 */
static void
ixgbe_rem_intr_handlers(ixgbe_t *ixgbe)
{
	int i;
	int rc;

	for (i = 0; i < ixgbe->intr_cnt; i++) {
		rc = ddi_intr_remove_handler(ixgbe->htable[i]);
		if (rc != DDI_SUCCESS) {
			IXGBE_DEBUGLOG_1(ixgbe,
			    "Remove intr handler failed: %d", rc);
		}
	}
}

/*
 * ixgbe_rem_intrs - Remove the allocated interrupts.
 */
static void
ixgbe_rem_intrs(ixgbe_t *ixgbe)
{
	int i;
	int rc;

	for (i = 0; i < ixgbe->intr_cnt; i++) {
		rc = ddi_intr_free(ixgbe->htable[i]);
		if (rc != DDI_SUCCESS) {
			IXGBE_DEBUGLOG_1(ixgbe,
			    "Free intr failed: %d", rc);
		}
	}

	kmem_free(ixgbe->htable, ixgbe->intr_size);
	ixgbe->htable = NULL;
}

/*
 * ixgbe_enable_intrs - Enable all the ddi interrupts.
 */
static int
ixgbe_enable_intrs(ixgbe_t *ixgbe)
{
	int i;
	int rc;

	/*
	 * Enable interrupts
	 */
	if (ixgbe->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/*
		 * Call ddi_intr_block_enable() for MSI
		 */
		rc = ddi_intr_block_enable(ixgbe->htable, ixgbe->intr_cnt);
		if (rc != DDI_SUCCESS) {
			ixgbe_log(ixgbe,
			    "Enable block intr failed: %d", rc);
			return (IXGBE_FAILURE);
		}
	} else {
		/*
		 * Call ddi_intr_enable() for Legacy/MSI non block enable
		 */
		for (i = 0; i < ixgbe->intr_cnt; i++) {
			rc = ddi_intr_enable(ixgbe->htable[i]);
			if (rc != DDI_SUCCESS) {
				ixgbe_log(ixgbe,
				    "Enable intr failed: %d", rc);
				return (IXGBE_FAILURE);
			}
		}
	}

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_disable_intrs - Disable all the interrupts.
 */
static int
ixgbe_disable_intrs(ixgbe_t *ixgbe)
{
	int i;
	int rc;

	/*
	 * Disable all interrupts
	 */
	if (ixgbe->intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_disable(ixgbe->htable, ixgbe->intr_cnt);
		if (rc != DDI_SUCCESS) {
			ixgbe_log(ixgbe,
			    "Disable block intr failed: %d", rc);
			return (IXGBE_FAILURE);
		}
	} else {
		for (i = 0; i < ixgbe->intr_cnt; i++) {
			rc = ddi_intr_disable(ixgbe->htable[i]);
			if (rc != DDI_SUCCESS) {
				ixgbe_log(ixgbe,
				    "Disable intr failed: %d", rc);
				return (IXGBE_FAILURE);
			}
		}
	}

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_get_hw_state - Get and save parameters related to adapter hardware.
 */
static void
ixgbe_get_hw_state(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint32_t links;
	uint32_t pcs1g_anlp = 0;
	uint32_t pcs1g_ana = 0;

	ASSERT(mutex_owned(&ixgbe->gen_lock));
	ixgbe->param_lp_1000fdx_cap = 0;
	ixgbe->param_lp_100fdx_cap  = 0;

	links = IXGBE_READ_REG(hw, IXGBE_LINKS);
	if (links & IXGBE_LINKS_PCS_1G_EN) {
		pcs1g_anlp = IXGBE_READ_REG(hw, IXGBE_PCS1GANLP);
		pcs1g_ana = IXGBE_READ_REG(hw, IXGBE_PCS1GANA);

		ixgbe->param_lp_1000fdx_cap =
		    (pcs1g_anlp & IXGBE_PCS1GANLP_LPFD) ? 1 : 0;
		ixgbe->param_lp_100fdx_cap =
		    (pcs1g_anlp & IXGBE_PCS1GANLP_LPFD) ? 1 : 0;
	}

	ixgbe->param_1000fdx_cap = (pcs1g_ana & IXGBE_PCS1GANA_FDC)  ? 1 : 0;
	ixgbe->param_100fdx_cap = (pcs1g_ana & IXGBE_PCS1GANA_FDC)  ? 1 : 0;
}

/*
 * ixgbe_get_driver_control - Notify that driver is in control of device.
 */
static void
ixgbe_get_driver_control(struct ixgbe_hw *hw)
{
	uint32_t ctrl_ext;

	/*
	 * Notify firmware that driver is in control of device
	 */
	ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ctrl_ext |= IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);
}

/*
 * ixgbe_release_driver_control - Notify that driver is no longer in control
 * of device.
 */
static void
ixgbe_release_driver_control(struct ixgbe_hw *hw)
{
	uint32_t ctrl_ext;

	/*
	 * Notify firmware that driver is no longer in control of device
	 */
	ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ctrl_ext &= ~IXGBE_CTRL_EXT_DRV_LOAD;
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);
}

/*
 * ixgbe_atomic_reserve - Atomic decrease operation.
 */
int
ixgbe_atomic_reserve(uint32_t *count_p, uint32_t n)
{
	uint32_t oldval;
	uint32_t newval;

	/*
	 * ATOMICALLY
	 */
	do {
		oldval = *count_p;
		if (oldval < n)
			return (-1);
		newval = oldval - n;
	} while (atomic_cas_32(count_p, oldval, newval) != oldval);

	return (newval);
}

/*
 * ixgbe_mc_table_itr - Traverse the entries in the multicast table.
 */
static uint8_t *
ixgbe_mc_table_itr(struct ixgbe_hw *hw, uint8_t **upd_ptr, uint32_t *vmdq)
{
	_NOTE(ARGUNUSED(hw));
	_NOTE(ARGUNUSED(vmdq));
	uint8_t *addr = *upd_ptr;
	uint8_t *new_ptr;

	new_ptr = addr + IXGBE_ETH_LENGTH_OF_ADDRESS;
	*upd_ptr = new_ptr;
	return (addr);
}

/*
 * FMA support
 */
int
ixgbe_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

int
ixgbe_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * ixgbe_fm_error_cb - The IO fault service error handling callback function.
 */
static int
ixgbe_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	_NOTE(ARGUNUSED(impl_data));
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
ixgbe_fm_init(ixgbe_t *ixgbe)
{
	ddi_iblock_cookie_t iblk;
	int fma_acc_flag, fma_dma_flag;

	/*
	 * Only register with IO Fault Services if we have some capability
	 */
	if (ixgbe->fm_capabilities & DDI_FM_ACCCHK_CAPABLE) {
		ixgbe_regs_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		fma_acc_flag = 1;
	} else {
		ixgbe_regs_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		fma_acc_flag = 0;
	}

	if (ixgbe->fm_capabilities & DDI_FM_DMACHK_CAPABLE) {
		fma_dma_flag = 1;
	} else {
		fma_dma_flag = 0;
	}

	ixgbe_set_fma_flags(fma_acc_flag, fma_dma_flag);

	if (ixgbe->fm_capabilities) {

		/*
		 * Register capabilities with IO Fault Services
		 */
		ddi_fm_init(ixgbe->dip, &ixgbe->fm_capabilities, &iblk);

		/*
		 * Initialize pci ereport capabilities if ereport capable
		 */
		if (DDI_FM_EREPORT_CAP(ixgbe->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(ixgbe->fm_capabilities))
			pci_ereport_setup(ixgbe->dip);

		/*
		 * Register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(ixgbe->fm_capabilities))
			ddi_fm_handler_register(ixgbe->dip,
			    ixgbe_fm_error_cb, (void*) ixgbe);
	}
}

static void
ixgbe_fm_fini(ixgbe_t *ixgbe)
{
	/*
	 * Only unregister FMA capabilities if they are registered
	 */
	if (ixgbe->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(ixgbe->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(ixgbe->fm_capabilities))
			pci_ereport_teardown(ixgbe->dip);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(ixgbe->fm_capabilities))
			ddi_fm_handler_unregister(ixgbe->dip);

		/*
		 * Unregister from IO Fault Service
		 */
		ddi_fm_fini(ixgbe->dip);
	}
}

void
ixgbe_fm_ereport(ixgbe_t *ixgbe, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(ixgbe->fm_capabilities)) {
		ddi_fm_ereport_post(ixgbe->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}
