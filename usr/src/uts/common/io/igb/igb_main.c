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

/*
 * Copyright (c) 2007-2012 Intel Corporation. All rights reserved.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Nexenta Systems, Inc. All rights reserved.
 */

#include "igb_sw.h"

static char ident[] = "Intel 1Gb Ethernet";
static char igb_version[] = "igb 2.3.8-ish";

/*
 * Local function protoypes
 */
static int igb_register_mac(igb_t *);
static int igb_identify_hardware(igb_t *);
static int igb_regs_map(igb_t *);
static void igb_init_properties(igb_t *);
static int igb_init_driver_settings(igb_t *);
static void igb_init_locks(igb_t *);
static void igb_destroy_locks(igb_t *);
static int igb_init_mac_address(igb_t *);
static int igb_init(igb_t *);
static int igb_init_adapter(igb_t *);
static void igb_stop_adapter(igb_t *);
static int igb_reset(igb_t *);
static void igb_tx_clean(igb_t *);
static boolean_t igb_tx_drain(igb_t *);
static boolean_t igb_rx_drain(igb_t *);
static int igb_alloc_rings(igb_t *);
static int igb_alloc_rx_data(igb_t *);
static void igb_free_rx_data(igb_t *);
static void igb_free_rings(igb_t *);
static void igb_setup_rings(igb_t *);
static void igb_setup_rx(igb_t *);
static void igb_setup_tx(igb_t *);
static void igb_setup_rx_ring(igb_rx_ring_t *);
static void igb_setup_tx_ring(igb_tx_ring_t *);
static void igb_setup_rss(igb_t *);
static void igb_setup_mac_rss_classify(igb_t *);
static void igb_setup_mac_classify(igb_t *);
static void igb_init_unicst(igb_t *);
static void igb_setup_multicst(igb_t *);
static void igb_get_phy_state(igb_t *);
static void igb_param_sync(igb_t *);
static void igb_get_conf(igb_t *);
static int igb_get_prop(igb_t *, char *, int, int, int);
static boolean_t igb_is_link_up(igb_t *);
static boolean_t igb_link_check(igb_t *);
static void igb_local_timer(void *);
static void igb_link_timer(void *);
static void igb_arm_watchdog_timer(igb_t *);
static void igb_start_watchdog_timer(igb_t *);
static void igb_restart_watchdog_timer(igb_t *);
static void igb_stop_watchdog_timer(igb_t *);
static void igb_start_link_timer(igb_t *);
static void igb_stop_link_timer(igb_t *);
static void igb_disable_adapter_interrupts(igb_t *);
static void igb_enable_adapter_interrupts_82575(igb_t *);
static void igb_enable_adapter_interrupts_82576(igb_t *);
static void igb_enable_adapter_interrupts_82580(igb_t *);
static boolean_t is_valid_mac_addr(uint8_t *);
static boolean_t igb_stall_check(igb_t *);
static boolean_t igb_set_loopback_mode(igb_t *, uint32_t);
static void igb_set_external_loopback(igb_t *);
static void igb_set_internal_phy_loopback(igb_t *);
static void igb_set_internal_serdes_loopback(igb_t *);
static boolean_t igb_find_mac_address(igb_t *);
static int igb_alloc_intrs(igb_t *);
static int igb_alloc_intr_handles(igb_t *, int);
static int igb_add_intr_handlers(igb_t *);
static void igb_rem_intr_handlers(igb_t *);
static void igb_rem_intrs(igb_t *);
static int igb_enable_intrs(igb_t *);
static int igb_disable_intrs(igb_t *);
static void igb_setup_msix_82575(igb_t *);
static void igb_setup_msix_82576(igb_t *);
static void igb_setup_msix_82580(igb_t *);
static uint_t igb_intr_legacy(void *, void *);
static uint_t igb_intr_msi(void *, void *);
static uint_t igb_intr_rx(void *, void *);
static uint_t igb_intr_tx(void *, void *);
static uint_t igb_intr_tx_other(void *, void *);
static void igb_intr_rx_work(igb_rx_ring_t *);
static void igb_intr_tx_work(igb_tx_ring_t *);
static void igb_intr_link_work(igb_t *);
static void igb_get_driver_control(struct e1000_hw *);
static void igb_release_driver_control(struct e1000_hw *);

static int igb_attach(dev_info_t *, ddi_attach_cmd_t);
static int igb_detach(dev_info_t *, ddi_detach_cmd_t);
static int igb_resume(dev_info_t *);
static int igb_suspend(dev_info_t *);
static int igb_quiesce(dev_info_t *);
static void igb_unconfigure(dev_info_t *, igb_t *);
static int igb_fm_error_cb(dev_info_t *, ddi_fm_error_t *,
    const void *);
static void igb_fm_init(igb_t *);
static void igb_fm_fini(igb_t *);
static void igb_release_multicast(igb_t *);

char *igb_priv_props[] = {
	"_eee_support",
	"_tx_copy_thresh",
	"_tx_recycle_thresh",
	"_tx_overload_thresh",
	"_tx_resched_thresh",
	"_rx_copy_thresh",
	"_rx_limit_per_intr",
	"_intr_throttling",
	"_adv_pause_cap",
	"_adv_asym_pause_cap",
	NULL
};

static struct cb_ops igb_cb_ops = {
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

static struct dev_ops igb_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	igb_attach,		/* devo_attach */
	igb_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&igb_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power,		/* devo_power */
	igb_quiesce,	/* devo_quiesce */
};

static struct modldrv igb_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	ident,			/* Discription string */
	&igb_dev_ops,		/* driver ops */
};

static struct modlinkage igb_modlinkage = {
	MODREV_1, &igb_modldrv, NULL
};

/* Access attributes for register mapping */
ddi_device_acc_attr_t igb_regs_acc_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

#define	IGB_M_CALLBACK_FLAGS \
	(MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO)

static mac_callbacks_t igb_m_callbacks = {
	IGB_M_CALLBACK_FLAGS,
	igb_m_stat,
	igb_m_start,
	igb_m_stop,
	igb_m_promisc,
	igb_m_multicst,
	NULL,
	NULL,
	NULL,
	igb_m_ioctl,
	igb_m_getcapab,
	NULL,
	NULL,
	igb_m_setprop,
	igb_m_getprop,
	igb_m_propinfo
};

/*
 * Initialize capabilities of each supported adapter type
 */
static adapter_info_t igb_82575_cap = {
	/* limits */
	4,		/* maximum number of rx queues */
	1,		/* minimum number of rx queues */
	4,		/* default number of rx queues */
	4,		/* maximum number of tx queues */
	1,		/* minimum number of tx queues */
	4,		/* default number of tx queues */
	65535,		/* maximum interrupt throttle rate */
	0,		/* minimum interrupt throttle rate */
	200,		/* default interrupt throttle rate */

	/* function pointers */
	igb_enable_adapter_interrupts_82575,
	igb_setup_msix_82575,

	/* capabilities */
	(IGB_FLAG_HAS_DCA |	/* capability flags */
	IGB_FLAG_VMDQ_POOL),

	0xffc00000		/* mask for RXDCTL register */
};

static adapter_info_t igb_82576_cap = {
	/* limits */
	16,		/* maximum number of rx queues */
	1,		/* minimum number of rx queues */
	4,		/* default number of rx queues */
	16,		/* maximum number of tx queues */
	1,		/* minimum number of tx queues */
	4,		/* default number of tx queues */
	65535,		/* maximum interrupt throttle rate */
	0,		/* minimum interrupt throttle rate */
	200,		/* default interrupt throttle rate */

	/* function pointers */
	igb_enable_adapter_interrupts_82576,
	igb_setup_msix_82576,

	/* capabilities */
	(IGB_FLAG_HAS_DCA |	/* capability flags */
	IGB_FLAG_VMDQ_POOL |
	IGB_FLAG_NEED_CTX_IDX),

	0xffe00000		/* mask for RXDCTL register */
};

static adapter_info_t igb_82580_cap = {
	/* limits */
	8,		/* maximum number of rx queues */
	1,		/* minimum number of rx queues */
	4,		/* default number of rx queues */
	8,		/* maximum number of tx queues */
	1,		/* minimum number of tx queues */
	4,		/* default number of tx queues */
	65535,		/* maximum interrupt throttle rate */
	0,		/* minimum interrupt throttle rate */
	200,		/* default interrupt throttle rate */

	/* function pointers */
	igb_enable_adapter_interrupts_82580,
	igb_setup_msix_82580,

	/* capabilities */
	(IGB_FLAG_HAS_DCA |	/* capability flags */
	IGB_FLAG_VMDQ_POOL |
	IGB_FLAG_NEED_CTX_IDX),

	0xffe00000		/* mask for RXDCTL register */
};

static adapter_info_t igb_i350_cap = {
	/* limits */
	8,		/* maximum number of rx queues */
	1,		/* minimum number of rx queues */
	4,		/* default number of rx queues */
	8,		/* maximum number of tx queues */
	1,		/* minimum number of tx queues */
	4,		/* default number of tx queues */
	65535,		/* maximum interrupt throttle rate */
	0,		/* minimum interrupt throttle rate */
	200,		/* default interrupt throttle rate */

	/* function pointers */
	igb_enable_adapter_interrupts_82580,
	igb_setup_msix_82580,

	/* capabilities */
	(IGB_FLAG_HAS_DCA |	/* capability flags */
	IGB_FLAG_VMDQ_POOL |
	IGB_FLAG_NEED_CTX_IDX),

	0xffe00000		/* mask for RXDCTL register */
};

static adapter_info_t igb_i210_cap = {
	/* limits */
	4,		/* maximum number of rx queues */
	1,		/* minimum number of rx queues */
	4,		/* default number of rx queues */
	4,		/* maximum number of tx queues */
	1,		/* minimum number of tx queues */
	4,		/* default number of tx queues */
	65535,		/* maximum interrupt throttle rate */
	0,		/* minimum interrupt throttle rate */
	200,		/* default interrupt throttle rate */

	/* function pointers */
	igb_enable_adapter_interrupts_82580,
	igb_setup_msix_82580,

	/* capabilities */
	(IGB_FLAG_HAS_DCA |	/* capability flags */
	IGB_FLAG_VMDQ_POOL |
	IGB_FLAG_NEED_CTX_IDX),

	0xfff00000		/* mask for RXDCTL register */
};

static adapter_info_t igb_i354_cap = {
	/* limits */
	8,		/* maximum number of rx queues */
	1,		/* minimum number of rx queues */
	4,		/* default number of rx queues */
	8,		/* maximum number of tx queues */
	1,		/* minimum number of tx queues */
	4,		/* default number of tx queues */
	65535,		/* maximum interrupt throttle rate */
	0,		/* minimum interrupt throttle rate */
	200,		/* default interrupt throttle rate */

	/* function pointers */
	igb_enable_adapter_interrupts_82580,
	igb_setup_msix_82580,

	/* capabilities */
	(IGB_FLAG_HAS_DCA |	/* capability flags */
	IGB_FLAG_VMDQ_POOL |
	IGB_FLAG_NEED_CTX_IDX),

	0xfff00000		/* mask for RXDCTL register */
};

/*
 * Module Initialization Functions
 */

int
_init(void)
{
	int status;

	mac_init_ops(&igb_dev_ops, MODULE_NAME);

	status = mod_install(&igb_modlinkage);

	if (status != DDI_SUCCESS) {
		mac_fini_ops(&igb_dev_ops);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&igb_modlinkage);

	if (status == DDI_SUCCESS) {
		mac_fini_ops(&igb_dev_ops);
	}

	return (status);

}

int
_info(struct modinfo *modinfop)
{
	int status;

	status = mod_info(&igb_modlinkage, modinfop);

	return (status);
}

/*
 * igb_attach - driver attach
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
igb_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	igb_t *igb;
	struct igb_osdep *osdep;
	struct e1000_hw *hw;
	int instance;

	/*
	 * Check the command and perform corresponding operations
	 */
	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		return (igb_resume(devinfo));

	case DDI_ATTACH:
		break;
	}

	/* Get the device instance */
	instance = ddi_get_instance(devinfo);

	/* Allocate memory for the instance data structure */
	igb = kmem_zalloc(sizeof (igb_t), KM_SLEEP);

	igb->dip = devinfo;
	igb->instance = instance;

	hw = &igb->hw;
	osdep = &igb->osdep;
	hw->back = osdep;
	osdep->igb = igb;

	/* Attach the instance pointer to the dev_info data structure */
	ddi_set_driver_private(devinfo, igb);


	/* Initialize for fma support */
	igb->fm_capabilities = igb_get_prop(igb, "fm-capable",
	    0, 0x0f,
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);
	igb_fm_init(igb);
	igb->attach_progress |= ATTACH_PROGRESS_FMINIT;

	/*
	 * Map PCI config space registers
	 */
	if (pci_config_setup(devinfo, &osdep->cfg_handle) != DDI_SUCCESS) {
		igb_error(igb, "Failed to map PCI configurations");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_PCI_CONFIG;

	/*
	 * Identify the chipset family
	 */
	if (igb_identify_hardware(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to identify hardware");
		goto attach_fail;
	}

	/*
	 * Map device registers
	 */
	if (igb_regs_map(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to map device registers");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_REGS_MAP;

	/*
	 * Initialize driver parameters
	 */
	igb_init_properties(igb);
	igb->attach_progress |= ATTACH_PROGRESS_PROPS;

	/*
	 * Allocate interrupts
	 */
	if (igb_alloc_intrs(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to allocate interrupts");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_ALLOC_INTR;

	/*
	 * Allocate rx/tx rings based on the ring numbers.
	 * The actual numbers of rx/tx rings are decided by the number of
	 * allocated interrupt vectors, so we should allocate the rings after
	 * interrupts are allocated.
	 */
	if (igb_alloc_rings(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to allocate rx/tx rings or groups");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_ALLOC_RINGS;

	/*
	 * Add interrupt handlers
	 */
	if (igb_add_intr_handlers(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to add interrupt handlers");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_ADD_INTR;

	/*
	 * Initialize driver parameters
	 */
	if (igb_init_driver_settings(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to initialize driver settings");
		goto attach_fail;
	}

	if (igb_check_acc_handle(igb->osdep.cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);
		goto attach_fail;
	}

	/*
	 * Initialize mutexes for this device.
	 * Do this before enabling the interrupt handler and
	 * register the softint to avoid the condition where
	 * interrupt handler can try using uninitialized mutex
	 */
	igb_init_locks(igb);
	igb->attach_progress |= ATTACH_PROGRESS_LOCKS;

	/*
	 * Initialize the adapter
	 */
	if (igb_init(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to initialize adapter");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_INIT_ADAPTER;

	/*
	 * Initialize statistics
	 */
	if (igb_init_stats(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to initialize statistics");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_STATS;

	/*
	 * Register the driver to the MAC
	 */
	if (igb_register_mac(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to register MAC");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_MAC;

	/*
	 * Now that mutex locks are initialized, and the chip is also
	 * initialized, enable interrupts.
	 */
	if (igb_enable_intrs(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to enable DDI interrupts");
		goto attach_fail;
	}
	igb->attach_progress |= ATTACH_PROGRESS_ENABLE_INTR;

	igb_log(igb, "%s", igb_version);
	atomic_or_32(&igb->igb_state, IGB_INITIALIZED);

	/*
	 * Newer models have Energy Efficient Ethernet, let's disable this by
	 * default.
	 */
	if (igb->hw.mac.type == e1000_i350)
		(void) e1000_set_eee_i350(&igb->hw);
	else if (igb->hw.mac.type == e1000_i354)
		(void) e1000_set_eee_i354(&igb->hw);

	return (DDI_SUCCESS);

attach_fail:
	igb_unconfigure(devinfo, igb);
	return (DDI_FAILURE);
}

/*
 * igb_detach - driver detach
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
igb_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	igb_t *igb;

	/*
	 * Check detach command
	 */
	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (igb_suspend(devinfo));

	case DDI_DETACH:
		break;
	}


	/*
	 * Get the pointer to the driver private data structure
	 */
	igb = (igb_t *)ddi_get_driver_private(devinfo);
	if (igb == NULL)
		return (DDI_FAILURE);

	/*
	 * Unregister MAC. If failed, we have to fail the detach
	 */
	if (mac_unregister(igb->mac_hdl) != 0) {
		igb_error(igb, "Failed to unregister MAC");
		return (DDI_FAILURE);
	}
	igb->attach_progress &= ~ATTACH_PROGRESS_MAC;

	/*
	 * If the device is still running, it needs to be stopped first.
	 * This check is necessary because under some specific circumstances,
	 * the detach routine can be called without stopping the interface
	 * first.
	 */
	mutex_enter(&igb->gen_lock);
	if (igb->igb_state & IGB_STARTED) {
		atomic_and_32(&igb->igb_state, ~IGB_STARTED);
		igb_stop(igb, B_TRUE);
		mutex_exit(&igb->gen_lock);
		/* Disable and stop the watchdog timer */
		igb_disable_watchdog_timer(igb);
	} else
		mutex_exit(&igb->gen_lock);

	/*
	 * Check if there are still rx buffers held by the upper layer.
	 * If so, fail the detach.
	 */
	if (!igb_rx_drain(igb))
		return (DDI_FAILURE);

	/*
	 * Do the remaining unconfigure routines
	 */
	igb_unconfigure(devinfo, igb);

	return (DDI_SUCCESS);
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
igb_quiesce(dev_info_t *devinfo)
{
	igb_t *igb;
	struct e1000_hw *hw;

	igb = (igb_t *)ddi_get_driver_private(devinfo);

	if (igb == NULL)
		return (DDI_FAILURE);

	hw = &igb->hw;

	/*
	 * Disable the adapter interrupts
	 */
	igb_disable_adapter_interrupts(igb);

	/* Tell firmware driver is no longer in control */
	igb_release_driver_control(hw);

	/*
	 * Reset the chipset
	 */
	(void) e1000_reset_hw(hw);

	/*
	 * Reset PHY if possible
	 */
	if (e1000_check_reset_block(hw) == E1000_SUCCESS)
		(void) e1000_phy_hw_reset(hw);

	return (DDI_SUCCESS);
}

/*
 * igb_unconfigure - release all resources held by this instance
 */
static void
igb_unconfigure(dev_info_t *devinfo, igb_t *igb)
{
	/*
	 * Disable interrupt
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_ENABLE_INTR) {
		(void) igb_disable_intrs(igb);
	}

	/*
	 * Unregister MAC
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_MAC) {
		(void) mac_unregister(igb->mac_hdl);
	}

	/*
	 * Free statistics
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_STATS) {
		kstat_delete((kstat_t *)igb->igb_ks);
	}

	/*
	 * Remove interrupt handlers
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_ADD_INTR) {
		igb_rem_intr_handlers(igb);
	}

	/*
	 * Remove interrupts
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_ALLOC_INTR) {
		igb_rem_intrs(igb);
	}

	/*
	 * Remove driver properties
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_PROPS) {
		(void) ddi_prop_remove_all(devinfo);
	}

	/*
	 * Stop the adapter
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_INIT_ADAPTER) {
		mutex_enter(&igb->gen_lock);
		igb_stop_adapter(igb);
		mutex_exit(&igb->gen_lock);
		if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK)
			ddi_fm_service_impact(igb->dip, DDI_SERVICE_UNAFFECTED);
	}

	/*
	 * Free multicast table
	 */
	igb_release_multicast(igb);

	/*
	 * Free register handle
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_REGS_MAP) {
		if (igb->osdep.reg_handle != NULL)
			ddi_regs_map_free(&igb->osdep.reg_handle);
	}

	/*
	 * Free PCI config handle
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_PCI_CONFIG) {
		if (igb->osdep.cfg_handle != NULL)
			pci_config_teardown(&igb->osdep.cfg_handle);
	}

	/*
	 * Free locks
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_LOCKS) {
		igb_destroy_locks(igb);
	}

	/*
	 * Free the rx/tx rings
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_ALLOC_RINGS) {
		igb_free_rings(igb);
	}

	/*
	 * Remove FMA
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_FMINIT) {
		igb_fm_fini(igb);
	}

	/*
	 * Free the driver data structure
	 */
	kmem_free(igb, sizeof (igb_t));

	ddi_set_driver_private(devinfo, NULL);
}

/*
 * igb_register_mac - Register the driver and its function pointers with
 * the GLD interface
 */
static int
igb_register_mac(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	mac_register_t *mac;
	int status;

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (IGB_FAILURE);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = igb;
	mac->m_dip = igb->dip;
	mac->m_src_addr = hw->mac.addr;
	mac->m_callbacks = &igb_m_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu = igb->max_frame_size -
	    sizeof (struct ether_vlan_header) - ETHERFCSL;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_priv_props = igb_priv_props;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	status = mac_register(mac, &igb->mac_hdl);

	mac_free(mac);

	return ((status == 0) ? IGB_SUCCESS : IGB_FAILURE);
}

/*
 * igb_identify_hardware - Identify the type of the chipset
 */
static int
igb_identify_hardware(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	struct igb_osdep *osdep = &igb->osdep;

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

	/*
	 * Set the mac type of the adapter based on the device id
	 */
	if (e1000_set_mac_type(hw) != E1000_SUCCESS) {
		return (IGB_FAILURE);
	}

	/*
	 * Install adapter capabilities based on mac type
	 */
	switch (hw->mac.type) {
	case e1000_82575:
		igb->capab = &igb_82575_cap;
		break;
	case e1000_82576:
		igb->capab = &igb_82576_cap;
		break;
	case e1000_82580:
		igb->capab = &igb_82580_cap;
		break;
	case e1000_i350:
		igb->capab = &igb_i350_cap;
		break;
	case e1000_i210:
	case e1000_i211:
		igb->capab = &igb_i210_cap;
		break;
	case e1000_i354:
		igb->capab = &igb_i354_cap;
		break;
	default:
		return (IGB_FAILURE);
	}

	return (IGB_SUCCESS);
}

/*
 * igb_regs_map - Map the device registers
 */
static int
igb_regs_map(igb_t *igb)
{
	dev_info_t *devinfo = igb->dip;
	struct e1000_hw *hw = &igb->hw;
	struct igb_osdep *osdep = &igb->osdep;
	off_t mem_size;

	/*
	 * First get the size of device registers to be mapped.
	 */
	if (ddi_dev_regsize(devinfo, IGB_ADAPTER_REGSET, &mem_size) !=
	    DDI_SUCCESS) {
		return (IGB_FAILURE);
	}

	/*
	 * Call ddi_regs_map_setup() to map registers
	 */
	if ((ddi_regs_map_setup(devinfo, IGB_ADAPTER_REGSET,
	    (caddr_t *)&hw->hw_addr, 0,
	    mem_size, &igb_regs_acc_attr,
	    &osdep->reg_handle)) != DDI_SUCCESS) {
		return (IGB_FAILURE);
	}

	return (IGB_SUCCESS);
}

/*
 * igb_init_properties - Initialize driver properties
 */
static void
igb_init_properties(igb_t *igb)
{
	/*
	 * Get conf file properties, including link settings
	 * jumbo frames, ring number, descriptor number, etc.
	 */
	igb_get_conf(igb);
}

/*
 * igb_init_driver_settings - Initialize driver settings
 *
 * The settings include hardware function pointers, bus information,
 * rx/tx rings settings, link state, and any other parameters that
 * need to be setup during driver initialization.
 */
static int
igb_init_driver_settings(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	igb_rx_ring_t *rx_ring;
	igb_tx_ring_t *tx_ring;
	uint32_t rx_size;
	uint32_t tx_size;
	int i;

	/*
	 * Initialize chipset specific hardware function pointers
	 */
	if (e1000_setup_init_funcs(hw, B_TRUE) != E1000_SUCCESS) {
		return (IGB_FAILURE);
	}

	/*
	 * Get bus information
	 */
	if (e1000_get_bus_info(hw) != E1000_SUCCESS) {
		return (IGB_FAILURE);
	}

	/*
	 * Get the system page size
	 */
	igb->page_size = ddi_ptob(igb->dip, (ulong_t)1);

	/*
	 * Set rx buffer size
	 * The IP header alignment room is counted in the calculation.
	 * The rx buffer size is in unit of 1K that is required by the
	 * chipset hardware.
	 */
	rx_size = igb->max_frame_size + IPHDR_ALIGN_ROOM;
	igb->rx_buf_size = ((rx_size >> 10) +
	    ((rx_size & (((uint32_t)1 << 10) - 1)) > 0 ? 1 : 0)) << 10;

	/*
	 * Set tx buffer size
	 */
	tx_size = igb->max_frame_size;
	igb->tx_buf_size = ((tx_size >> 10) +
	    ((tx_size & (((uint32_t)1 << 10) - 1)) > 0 ? 1 : 0)) << 10;

	/*
	 * Initialize rx/tx rings parameters
	 */
	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];
		rx_ring->index = i;
		rx_ring->igb = igb;
	}

	for (i = 0; i < igb->num_tx_rings; i++) {
		tx_ring = &igb->tx_rings[i];
		tx_ring->index = i;
		tx_ring->igb = igb;
		if (igb->tx_head_wb_enable)
			tx_ring->tx_recycle = igb_tx_recycle_head_wb;
		else
			tx_ring->tx_recycle = igb_tx_recycle_legacy;

		tx_ring->ring_size = igb->tx_ring_size;
		tx_ring->free_list_size = igb->tx_ring_size +
		    (igb->tx_ring_size >> 1);
	}

	/*
	 * Initialize values of interrupt throttling rates
	 */
	for (i = 1; i < MAX_NUM_EITR; i++)
		igb->intr_throttling[i] = igb->intr_throttling[0];

	/*
	 * The initial link state should be "unknown"
	 */
	igb->link_state = LINK_STATE_UNKNOWN;

	return (IGB_SUCCESS);
}

/*
 * igb_init_locks - Initialize locks
 */
static void
igb_init_locks(igb_t *igb)
{
	igb_rx_ring_t *rx_ring;
	igb_tx_ring_t *tx_ring;
	int i;

	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];
		mutex_init(&rx_ring->rx_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));
	}

	for (i = 0; i < igb->num_tx_rings; i++) {
		tx_ring = &igb->tx_rings[i];
		mutex_init(&tx_ring->tx_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));
		mutex_init(&tx_ring->recycle_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));
		mutex_init(&tx_ring->tcb_head_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));
		mutex_init(&tx_ring->tcb_tail_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));
	}

	mutex_init(&igb->gen_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));

	mutex_init(&igb->watchdog_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));

	mutex_init(&igb->link_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(igb->intr_pri));
}

/*
 * igb_destroy_locks - Destroy locks
 */
static void
igb_destroy_locks(igb_t *igb)
{
	igb_rx_ring_t *rx_ring;
	igb_tx_ring_t *tx_ring;
	int i;

	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];
		mutex_destroy(&rx_ring->rx_lock);
	}

	for (i = 0; i < igb->num_tx_rings; i++) {
		tx_ring = &igb->tx_rings[i];
		mutex_destroy(&tx_ring->tx_lock);
		mutex_destroy(&tx_ring->recycle_lock);
		mutex_destroy(&tx_ring->tcb_head_lock);
		mutex_destroy(&tx_ring->tcb_tail_lock);
	}

	mutex_destroy(&igb->gen_lock);
	mutex_destroy(&igb->watchdog_lock);
	mutex_destroy(&igb->link_lock);
}

static int
igb_resume(dev_info_t *devinfo)
{
	igb_t *igb;

	igb = (igb_t *)ddi_get_driver_private(devinfo);
	if (igb == NULL)
		return (DDI_FAILURE);

	mutex_enter(&igb->gen_lock);

	/*
	 * Enable interrupts
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_ENABLE_INTR) {
		if (igb_enable_intrs(igb) != IGB_SUCCESS) {
			igb_error(igb, "Failed to enable DDI interrupts");
			mutex_exit(&igb->gen_lock);
			return (DDI_FAILURE);
		}
	}

	if (igb->igb_state & IGB_STARTED) {
		if (igb_start(igb, B_FALSE) != IGB_SUCCESS) {
			mutex_exit(&igb->gen_lock);
			return (DDI_FAILURE);
		}

		/*
		 * Enable and start the watchdog timer
		 */
		igb_enable_watchdog_timer(igb);
	}

	atomic_and_32(&igb->igb_state, ~IGB_SUSPENDED);

	mutex_exit(&igb->gen_lock);

	return (DDI_SUCCESS);
}

static int
igb_suspend(dev_info_t *devinfo)
{
	igb_t *igb;

	igb = (igb_t *)ddi_get_driver_private(devinfo);
	if (igb == NULL)
		return (DDI_FAILURE);

	mutex_enter(&igb->gen_lock);

	atomic_or_32(&igb->igb_state, IGB_SUSPENDED);

	/*
	 * Disable interrupts
	 */
	if (igb->attach_progress & ATTACH_PROGRESS_ENABLE_INTR) {
		(void) igb_disable_intrs(igb);
	}

	if (!(igb->igb_state & IGB_STARTED)) {
		mutex_exit(&igb->gen_lock);
		return (DDI_SUCCESS);
	}

	igb_stop(igb, B_FALSE);

	mutex_exit(&igb->gen_lock);

	/*
	 * Disable and stop the watchdog timer
	 */
	igb_disable_watchdog_timer(igb);

	return (DDI_SUCCESS);
}

static int
igb_init(igb_t *igb)
{
	mutex_enter(&igb->gen_lock);

	/*
	 * Initilize the adapter
	 */
	if (igb_init_adapter(igb) != IGB_SUCCESS) {
		mutex_exit(&igb->gen_lock);
		igb_fm_ereport(igb, DDI_FM_DEVICE_INVAL_STATE);
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);
		return (IGB_FAILURE);
	}

	mutex_exit(&igb->gen_lock);

	return (IGB_SUCCESS);
}

/*
 * igb_init_mac_address - Initialize the default MAC address
 *
 * On success, the MAC address is entered in the igb->hw.mac.addr
 * and hw->mac.perm_addr fields and the adapter's RAR(0) receive
 * address register.
 *
 * Important side effects:
 * 1. adapter is reset - this is required to put it in a known state.
 * 2. all of non-volatile memory (NVM) is read & checksummed - NVM is where
 * MAC address and all default settings are stored, so a valid checksum
 * is required.
 */
static int
igb_init_mac_address(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;

	ASSERT(mutex_owned(&igb->gen_lock));

	/*
	 * Reset chipset to put the hardware in a known state
	 * before we try to get MAC address from NVM.
	 */
	if (e1000_reset_hw(hw) != E1000_SUCCESS) {
		igb_error(igb, "Adapter reset failed.");
		goto init_mac_fail;
	}

	/*
	 * NVM validation
	 */
	if (((igb->hw.mac.type != e1000_i210) &&
	    (igb->hw.mac.type != e1000_i211)) &&
	    (e1000_validate_nvm_checksum(hw) < 0)) {
		/*
		 * Some PCI-E parts fail the first check due to
		 * the link being in sleep state.  Call it again,
		 * if it fails a second time its a real issue.
		 */
		if (e1000_validate_nvm_checksum(hw) < 0) {
			igb_error(igb,
			    "Invalid NVM checksum. Please contact "
			    "the vendor to update the NVM.");
			goto init_mac_fail;
		}
	}

	/*
	 * Get the mac address
	 * This function should handle SPARC case correctly.
	 */
	if (!igb_find_mac_address(igb)) {
		igb_error(igb, "Failed to get the mac address");
		goto init_mac_fail;
	}

	/* Validate mac address */
	if (!is_valid_mac_addr(hw->mac.addr)) {
		igb_error(igb, "Invalid mac address");
		goto init_mac_fail;
	}

	return (IGB_SUCCESS);

init_mac_fail:
	return (IGB_FAILURE);
}

/*
 * igb_init_adapter - Initialize the adapter
 */
static int
igb_init_adapter(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t pba;
	int oemid[2];
	uint16_t nvmword;
	uint32_t hwm;
	uint32_t default_mtu;
	u8 pbanum[E1000_PBANUM_LENGTH];
	char eepromver[5];	/* f.ff */
	int i;

	ASSERT(mutex_owned(&igb->gen_lock));

	/*
	 * In order to obtain the default MAC address, this will reset the
	 * adapter and validate the NVM that the address and many other
	 * default settings come from.
	 */
	if (igb_init_mac_address(igb) != IGB_SUCCESS) {
		igb_error(igb, "Failed to initialize MAC address");
		goto init_adapter_fail;
	}

	/*
	 * Packet Buffer Allocation (PBA)
	 * Writing PBA sets the receive portion of the buffer
	 * the remainder is used for the transmit buffer.
	 */
	switch (hw->mac.type) {
	case e1000_82575:
		pba = E1000_PBA_32K;
		break;
	case e1000_82576:
		pba = E1000_READ_REG(hw, E1000_RXPBS);
		pba &= E1000_RXPBS_SIZE_MASK_82576;
		break;
	case e1000_82580:
	case e1000_i350:
	case e1000_i354:
		pba = E1000_READ_REG(hw, E1000_RXPBS);
		pba = e1000_rxpbs_adjust_82580(pba);
		break;
	case e1000_i210:
	case e1000_i211:
		pba = E1000_PBA_34K;
	default:
		break;
	}

	/* Special needs in case of Jumbo frames */
	default_mtu = igb_get_prop(igb, PROP_DEFAULT_MTU,
	    MIN_MTU, MAX_MTU, DEFAULT_MTU);
	if ((hw->mac.type == e1000_82575) && (default_mtu > ETHERMTU)) {
		u32 tx_space, min_tx, min_rx;
		pba = E1000_READ_REG(hw, E1000_PBA);
		tx_space = pba >> 16;
		pba &= 0xffff;
		min_tx = (igb->max_frame_size +
		    sizeof (struct e1000_tx_desc) - ETHERNET_FCS_SIZE) * 2;
		min_tx = roundup(min_tx, 1024);
		min_tx >>= 10;
		min_rx = igb->max_frame_size;
		min_rx = roundup(min_rx, 1024);
		min_rx >>= 10;
		if (tx_space < min_tx &&
		    ((min_tx - tx_space) < pba)) {
			pba = pba - (min_tx - tx_space);
			/*
			 * if short on rx space, rx wins
			 * and must trump tx adjustment
			 */
			if (pba < min_rx)
				pba = min_rx;
		}
		E1000_WRITE_REG(hw, E1000_PBA, pba);
	}

	DEBUGOUT1("igb_init: pba=%dK", pba);

	/*
	 * These parameters control the automatic generation (Tx) and
	 * response (Rx) to Ethernet PAUSE frames.
	 * - High water mark should allow for at least two frames to be
	 *   received after sending an XOFF.
	 * - Low water mark works best when it is very near the high water mark.
	 *   This allows the receiver to restart by sending XON when it has
	 *   drained a bit.
	 */
	hwm = min(((pba << 10) * 9 / 10),
	    ((pba << 10) - 2 * igb->max_frame_size));

	if (hw->mac.type < e1000_82576) {
		hw->fc.high_water = hwm & 0xFFF8;  /* 8-byte granularity */
		hw->fc.low_water = hw->fc.high_water - 8;
	} else {
		hw->fc.high_water = hwm & 0xFFF0;  /* 16-byte granularity */
		hw->fc.low_water = hw->fc.high_water - 16;
	}

	hw->fc.pause_time = E1000_FC_PAUSE_TIME;
	hw->fc.send_xon = B_TRUE;

	(void) e1000_validate_mdi_setting(hw);

	/*
	 * Reset the chipset hardware the second time to put PBA settings
	 * into effect.
	 */
	if (e1000_reset_hw(hw) != E1000_SUCCESS) {
		igb_error(igb, "Second reset failed");
		goto init_adapter_fail;
	}

	/*
	 * Don't wait for auto-negotiation to complete
	 */
	hw->phy.autoneg_wait_to_complete = B_FALSE;

	/*
	 * Copper options
	 */
	if (hw->phy.media_type == e1000_media_type_copper) {
		hw->phy.mdix = 0;	/* AUTO_ALL_MODES */
		hw->phy.disable_polarity_correction = B_FALSE;
		hw->phy.ms_type = e1000_ms_hw_default; /* E1000_MASTER_SLAVE */
	}

	/*
	 * Initialize link settings
	 */
	(void) igb_setup_link(igb, B_FALSE);

	/*
	 * Configure/Initialize hardware
	 */
	if (e1000_init_hw(hw) != E1000_SUCCESS) {
		igb_error(igb, "Failed to initialize hardware");
		goto init_adapter_fail;
	}

	/*
	 *  Start the link setup timer
	 */
	igb_start_link_timer(igb);

	/*
	 * Disable wakeup control by default
	 */
	E1000_WRITE_REG(hw, E1000_WUC, 0);

	/*
	 * Record phy info in hw struct
	 */
	(void) e1000_get_phy_info(hw);

	/*
	 * Make sure driver has control
	 */
	igb_get_driver_control(hw);

	/*
	 * Restore LED settings to the default from EEPROM
	 * to meet the standard for Sun platforms.
	 */
	(void) e1000_cleanup_led(hw);

	/*
	 * Setup MSI-X interrupts
	 */
	if (igb->intr_type == DDI_INTR_TYPE_MSIX)
		igb->capab->setup_msix(igb);

	/*
	 * Initialize unicast addresses.
	 */
	igb_init_unicst(igb);

	/*
	 * Setup and initialize the mctable structures.
	 */
	igb_setup_multicst(igb);

	/*
	 * Set interrupt throttling rate
	 */
	for (i = 0; i < igb->intr_cnt; i++)
		E1000_WRITE_REG(hw, E1000_EITR(i), igb->intr_throttling[i]);

	/*
	 * Read identifying information and place in devinfo.
	 */
	nvmword = 0xffff;
	(void) e1000_read_nvm(&igb->hw, NVM_OEM_OFFSET_0, 1, &nvmword);
	oemid[0] = (int)nvmword;
	(void) e1000_read_nvm(&igb->hw, NVM_OEM_OFFSET_1, 1, &nvmword);
	oemid[1] = (int)nvmword;
	(void) ddi_prop_update_int_array(DDI_DEV_T_NONE, igb->dip,
	    "oem-identifier", oemid, 2);

	pbanum[0] = '\0';
	(void) e1000_read_pba_string(&igb->hw, pbanum, sizeof (pbanum));
	if (*pbanum != '\0') {
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, igb->dip,
		    "printed-board-assembly", (char *)pbanum);
	}

	nvmword = 0xffff;
	(void) e1000_read_nvm(&igb->hw, NVM_VERSION, 1, &nvmword);
	if ((nvmword & 0xf00) == 0) {
		(void) snprintf(eepromver, sizeof (eepromver), "%x.%x",
		    (nvmword & 0xf000) >> 12, (nvmword & 0xff));
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, igb->dip,
		    "nvm-version", eepromver);
	}

	/*
	 * Save the state of the phy
	 */
	igb_get_phy_state(igb);

	igb_param_sync(igb);

	return (IGB_SUCCESS);

init_adapter_fail:
	/*
	 * Reset PHY if possible
	 */
	if (e1000_check_reset_block(hw) == E1000_SUCCESS)
		(void) e1000_phy_hw_reset(hw);

	return (IGB_FAILURE);
}

/*
 * igb_stop_adapter - Stop the adapter
 */
static void
igb_stop_adapter(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;

	ASSERT(mutex_owned(&igb->gen_lock));

	/* Stop the link setup timer */
	igb_stop_link_timer(igb);

	/* Tell firmware driver is no longer in control */
	igb_release_driver_control(hw);

	/*
	 * Reset the chipset
	 */
	if (e1000_reset_hw(hw) != E1000_SUCCESS) {
		igb_fm_ereport(igb, DDI_FM_DEVICE_INVAL_STATE);
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);
	}

	/*
	 * e1000_phy_hw_reset is not needed here, MAC reset above is sufficient
	 */
}

/*
 * igb_reset - Reset the chipset and restart the driver.
 *
 * It involves stopping and re-starting the chipset,
 * and re-configuring the rx/tx rings.
 */
static int
igb_reset(igb_t *igb)
{
	int i;

	mutex_enter(&igb->gen_lock);

	ASSERT(igb->igb_state & IGB_STARTED);
	atomic_and_32(&igb->igb_state, ~IGB_STARTED);

	/*
	 * Disable the adapter interrupts to stop any rx/tx activities
	 * before draining pending data and resetting hardware.
	 */
	igb_disable_adapter_interrupts(igb);

	/*
	 * Drain the pending transmit packets
	 */
	(void) igb_tx_drain(igb);

	for (i = 0; i < igb->num_rx_rings; i++)
		mutex_enter(&igb->rx_rings[i].rx_lock);
	for (i = 0; i < igb->num_tx_rings; i++)
		mutex_enter(&igb->tx_rings[i].tx_lock);

	/*
	 * Stop the adapter
	 */
	igb_stop_adapter(igb);

	/*
	 * Clean the pending tx data/resources
	 */
	igb_tx_clean(igb);

	/*
	 * Start the adapter
	 */
	if (igb_init_adapter(igb) != IGB_SUCCESS) {
		igb_fm_ereport(igb, DDI_FM_DEVICE_INVAL_STATE);
		goto reset_failure;
	}

	/*
	 * Setup the rx/tx rings
	 */
	igb->tx_ring_init = B_FALSE;
	igb_setup_rings(igb);

	atomic_and_32(&igb->igb_state, ~(IGB_ERROR | IGB_STALL));

	/*
	 * Enable adapter interrupts
	 * The interrupts must be enabled after the driver state is START
	 */
	igb->capab->enable_intr(igb);

	if (igb_check_acc_handle(igb->osdep.cfg_handle) != DDI_FM_OK)
		goto reset_failure;

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK)
		goto reset_failure;

	for (i = igb->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->tx_rings[i].tx_lock);
	for (i = igb->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->rx_rings[i].rx_lock);

	atomic_or_32(&igb->igb_state, IGB_STARTED);

	mutex_exit(&igb->gen_lock);

	return (IGB_SUCCESS);

reset_failure:
	for (i = igb->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->tx_rings[i].tx_lock);
	for (i = igb->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->rx_rings[i].rx_lock);

	mutex_exit(&igb->gen_lock);

	ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);

	return (IGB_FAILURE);
}

/*
 * igb_tx_clean - Clean the pending transmit packets and DMA resources
 */
static void
igb_tx_clean(igb_t *igb)
{
	igb_tx_ring_t *tx_ring;
	tx_control_block_t *tcb;
	link_list_t pending_list;
	uint32_t desc_num;
	int i, j;

	LINK_LIST_INIT(&pending_list);

	for (i = 0; i < igb->num_tx_rings; i++) {
		tx_ring = &igb->tx_rings[i];

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

				igb_free_tcb(tcb);

				LIST_PUSH_TAIL(&pending_list, &tcb->link);
			}
		}

		if (desc_num > 0) {
			atomic_add_32(&tx_ring->tbd_free, desc_num);
			ASSERT(tx_ring->tbd_free == tx_ring->ring_size);

			/*
			 * Reset the head and tail pointers of the tbd ring;
			 * Reset the head write-back if it is enabled.
			 */
			tx_ring->tbd_head = 0;
			tx_ring->tbd_tail = 0;
			if (igb->tx_head_wb_enable)
				*tx_ring->tbd_head_wb = 0;

			E1000_WRITE_REG(&igb->hw, E1000_TDH(tx_ring->index), 0);
			E1000_WRITE_REG(&igb->hw, E1000_TDT(tx_ring->index), 0);
		}

		mutex_exit(&tx_ring->recycle_lock);

		/*
		 * Add the tx control blocks in the pending list to
		 * the free list.
		 */
		igb_put_free_list(tx_ring, &pending_list);
	}
}

/*
 * igb_tx_drain - Drain the tx rings to allow pending packets to be transmitted
 */
static boolean_t
igb_tx_drain(igb_t *igb)
{
	igb_tx_ring_t *tx_ring;
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
		for (j = 0; j < igb->num_tx_rings; j++) {
			tx_ring = &igb->tx_rings[j];
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
 * igb_rx_drain - Wait for all rx buffers to be released by upper layer
 */
static boolean_t
igb_rx_drain(igb_t *igb)
{
	boolean_t done;
	int i;

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
		done = (igb->rcb_pending == 0);

		if (done)
			break;

		msec_delay(1);
	}

	return (done);
}

/*
 * igb_start - Start the driver/chipset
 */
int
igb_start(igb_t *igb, boolean_t alloc_buffer)
{
	int i;

	ASSERT(mutex_owned(&igb->gen_lock));

	if (alloc_buffer) {
		if (igb_alloc_rx_data(igb) != IGB_SUCCESS) {
			igb_error(igb,
			    "Failed to allocate software receive rings");
			return (IGB_FAILURE);
		}

		/* Allocate buffers for all the rx/tx rings */
		if (igb_alloc_dma(igb) != IGB_SUCCESS) {
			igb_error(igb, "Failed to allocate DMA resource");
			return (IGB_FAILURE);
		}

		igb->tx_ring_init = B_TRUE;
	} else {
		igb->tx_ring_init = B_FALSE;
	}

	for (i = 0; i < igb->num_rx_rings; i++)
		mutex_enter(&igb->rx_rings[i].rx_lock);
	for (i = 0; i < igb->num_tx_rings; i++)
		mutex_enter(&igb->tx_rings[i].tx_lock);

	/*
	 * Start the adapter
	 */
	if ((igb->attach_progress & ATTACH_PROGRESS_INIT_ADAPTER) == 0) {
		if (igb_init_adapter(igb) != IGB_SUCCESS) {
			igb_fm_ereport(igb, DDI_FM_DEVICE_INVAL_STATE);
			goto start_failure;
		}
		igb->attach_progress |= ATTACH_PROGRESS_INIT_ADAPTER;
	}

	/*
	 * Setup the rx/tx rings
	 */
	igb_setup_rings(igb);

	/*
	 * Enable adapter interrupts
	 * The interrupts must be enabled after the driver state is START
	 */
	igb->capab->enable_intr(igb);

	if (igb_check_acc_handle(igb->osdep.cfg_handle) != DDI_FM_OK)
		goto start_failure;

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK)
		goto start_failure;

	if (igb->hw.mac.type == e1000_i350)
		(void) e1000_set_eee_i350(&igb->hw);
	else if (igb->hw.mac.type == e1000_i354)
		(void) e1000_set_eee_i354(&igb->hw);

	for (i = igb->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->tx_rings[i].tx_lock);
	for (i = igb->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->rx_rings[i].rx_lock);

	return (IGB_SUCCESS);

start_failure:
	for (i = igb->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->tx_rings[i].tx_lock);
	for (i = igb->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->rx_rings[i].rx_lock);

	ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);

	return (IGB_FAILURE);
}

/*
 * igb_stop - Stop the driver/chipset
 */
void
igb_stop(igb_t *igb, boolean_t free_buffer)
{
	int i;

	ASSERT(mutex_owned(&igb->gen_lock));

	igb->attach_progress &= ~ATTACH_PROGRESS_INIT_ADAPTER;

	/*
	 * Disable the adapter interrupts
	 */
	igb_disable_adapter_interrupts(igb);

	/*
	 * Drain the pending tx packets
	 */
	(void) igb_tx_drain(igb);

	for (i = 0; i < igb->num_rx_rings; i++)
		mutex_enter(&igb->rx_rings[i].rx_lock);
	for (i = 0; i < igb->num_tx_rings; i++)
		mutex_enter(&igb->tx_rings[i].tx_lock);

	/*
	 * Stop the adapter
	 */
	igb_stop_adapter(igb);

	/*
	 * Clean the pending tx data/resources
	 */
	igb_tx_clean(igb);

	for (i = igb->num_tx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->tx_rings[i].tx_lock);
	for (i = igb->num_rx_rings - 1; i >= 0; i--)
		mutex_exit(&igb->rx_rings[i].rx_lock);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);

	if (igb->link_state == LINK_STATE_UP) {
		igb->link_state = LINK_STATE_UNKNOWN;
		mac_link_update(igb->mac_hdl, igb->link_state);
	}

	if (free_buffer) {
		/*
		 * Release the DMA/memory resources of rx/tx rings
		 */
		igb_free_dma(igb);
		igb_free_rx_data(igb);
	}
}

/*
 * igb_alloc_rings - Allocate memory space for rx/tx rings
 */
static int
igb_alloc_rings(igb_t *igb)
{
	/*
	 * Allocate memory space for rx rings
	 */
	igb->rx_rings = kmem_zalloc(
	    sizeof (igb_rx_ring_t) * igb->num_rx_rings,
	    KM_NOSLEEP);

	if (igb->rx_rings == NULL) {
		return (IGB_FAILURE);
	}

	/*
	 * Allocate memory space for tx rings
	 */
	igb->tx_rings = kmem_zalloc(
	    sizeof (igb_tx_ring_t) * igb->num_tx_rings,
	    KM_NOSLEEP);

	if (igb->tx_rings == NULL) {
		kmem_free(igb->rx_rings,
		    sizeof (igb_rx_ring_t) * igb->num_rx_rings);
		igb->rx_rings = NULL;
		return (IGB_FAILURE);
	}

	/*
	 * Allocate memory space for rx ring groups
	 */
	igb->rx_groups = kmem_zalloc(
	    sizeof (igb_rx_group_t) * igb->num_rx_groups,
	    KM_NOSLEEP);

	if (igb->rx_groups == NULL) {
		kmem_free(igb->rx_rings,
		    sizeof (igb_rx_ring_t) * igb->num_rx_rings);
		kmem_free(igb->tx_rings,
		    sizeof (igb_tx_ring_t) * igb->num_tx_rings);
		igb->rx_rings = NULL;
		igb->tx_rings = NULL;
		return (IGB_FAILURE);
	}

	return (IGB_SUCCESS);
}

/*
 * igb_free_rings - Free the memory space of rx/tx rings.
 */
static void
igb_free_rings(igb_t *igb)
{
	if (igb->rx_rings != NULL) {
		kmem_free(igb->rx_rings,
		    sizeof (igb_rx_ring_t) * igb->num_rx_rings);
		igb->rx_rings = NULL;
	}

	if (igb->tx_rings != NULL) {
		kmem_free(igb->tx_rings,
		    sizeof (igb_tx_ring_t) * igb->num_tx_rings);
		igb->tx_rings = NULL;
	}

	if (igb->rx_groups != NULL) {
		kmem_free(igb->rx_groups,
		    sizeof (igb_rx_group_t) * igb->num_rx_groups);
		igb->rx_groups = NULL;
	}
}

static int
igb_alloc_rx_data(igb_t *igb)
{
	igb_rx_ring_t *rx_ring;
	int i;

	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];
		if (igb_alloc_rx_ring_data(rx_ring) != IGB_SUCCESS)
			goto alloc_rx_rings_failure;
	}
	return (IGB_SUCCESS);

alloc_rx_rings_failure:
	igb_free_rx_data(igb);
	return (IGB_FAILURE);
}

static void
igb_free_rx_data(igb_t *igb)
{
	igb_rx_ring_t *rx_ring;
	igb_rx_data_t *rx_data;
	int i;

	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];

		mutex_enter(&igb->rx_pending_lock);
		rx_data = rx_ring->rx_data;

		if (rx_data != NULL) {
			rx_data->flag |= IGB_RX_STOPPED;

			if (rx_data->rcb_pending == 0) {
				igb_free_rx_ring_data(rx_data);
				rx_ring->rx_data = NULL;
			}
		}

		mutex_exit(&igb->rx_pending_lock);
	}
}

/*
 * igb_setup_rings - Setup rx/tx rings
 */
static void
igb_setup_rings(igb_t *igb)
{
	/*
	 * Setup the rx/tx rings, including the following:
	 *
	 * 1. Setup the descriptor ring and the control block buffers;
	 * 2. Initialize necessary registers for receive/transmit;
	 * 3. Initialize software pointers/parameters for receive/transmit;
	 */
	igb_setup_rx(igb);

	igb_setup_tx(igb);
}

static void
igb_setup_rx_ring(igb_rx_ring_t *rx_ring)
{
	igb_t *igb = rx_ring->igb;
	igb_rx_data_t *rx_data = rx_ring->rx_data;
	struct e1000_hw *hw = &igb->hw;
	rx_control_block_t *rcb;
	union e1000_adv_rx_desc	*rbd;
	uint32_t size;
	uint32_t buf_low;
	uint32_t buf_high;
	uint32_t rxdctl;
	int i;

	ASSERT(mutex_owned(&rx_ring->rx_lock));
	ASSERT(mutex_owned(&igb->gen_lock));

	/*
	 * Initialize descriptor ring with buffer addresses
	 */
	for (i = 0; i < igb->rx_ring_size; i++) {
		rcb = rx_data->work_list[i];
		rbd = &rx_data->rbd_ring[i];

		rbd->read.pkt_addr = rcb->rx_buf.dma_address;
		rbd->read.hdr_addr = NULL;
	}

	/*
	 * Initialize the base address registers
	 */
	buf_low = (uint32_t)rx_data->rbd_area.dma_address;
	buf_high = (uint32_t)(rx_data->rbd_area.dma_address >> 32);
	E1000_WRITE_REG(hw, E1000_RDBAH(rx_ring->index), buf_high);
	E1000_WRITE_REG(hw, E1000_RDBAL(rx_ring->index), buf_low);

	/*
	 * Initialize the length register
	 */
	size = rx_data->ring_size * sizeof (union e1000_adv_rx_desc);
	E1000_WRITE_REG(hw, E1000_RDLEN(rx_ring->index), size);

	/*
	 * Initialize buffer size & descriptor type
	 */
	E1000_WRITE_REG(hw, E1000_SRRCTL(rx_ring->index),
	    ((igb->rx_buf_size >> E1000_SRRCTL_BSIZEPKT_SHIFT) |
	    E1000_SRRCTL_DESCTYPE_ADV_ONEBUF));

	/*
	 * Setup the Receive Descriptor Control Register (RXDCTL)
	 */
	rxdctl = E1000_READ_REG(hw, E1000_RXDCTL(rx_ring->index));
	rxdctl &= igb->capab->rxdctl_mask;
	rxdctl |= E1000_RXDCTL_QUEUE_ENABLE;
	rxdctl |= 16;		/* pthresh */
	rxdctl |= 8 << 8;	/* hthresh */
	rxdctl |= 1 << 16;	/* wthresh */
	E1000_WRITE_REG(hw, E1000_RXDCTL(rx_ring->index), rxdctl);

	rx_data->rbd_next = 0;
}

static void
igb_setup_rx(igb_t *igb)
{
	igb_rx_ring_t *rx_ring;
	igb_rx_data_t *rx_data;
	igb_rx_group_t *rx_group;
	struct e1000_hw *hw = &igb->hw;
	uint32_t rctl, rxcsum;
	uint32_t ring_per_group;
	int i;

	/*
	 * Setup the Receive Control Register (RCTL), and enable the
	 * receiver. The initial configuration is to: enable the receiver,
	 * accept broadcasts, discard bad packets, accept long packets,
	 * disable VLAN filter checking, and set receive buffer size to
	 * 2k.  For 82575, also set the receive descriptor minimum
	 * threshold size to 1/2 the ring.
	 */
	rctl = E1000_READ_REG(hw, E1000_RCTL);

	/*
	 * Clear the field used for wakeup control.  This driver doesn't do
	 * wakeup but leave this here for completeness.
	 */
	rctl &= ~(3 << E1000_RCTL_MO_SHIFT);
	rctl &= ~(E1000_RCTL_LBM_TCVR | E1000_RCTL_LBM_MAC);

	rctl |= (E1000_RCTL_EN |	/* Enable Receive Unit */
	    E1000_RCTL_BAM |		/* Accept Broadcast Packets */
	    E1000_RCTL_LPE |		/* Large Packet Enable */
					/* Multicast filter offset */
	    (hw->mac.mc_filter_type << E1000_RCTL_MO_SHIFT) |
	    E1000_RCTL_RDMTS_HALF |	/* rx descriptor threshold */
	    E1000_RCTL_SECRC);		/* Strip Ethernet CRC */

	for (i = 0; i < igb->num_rx_groups; i++) {
		rx_group = &igb->rx_groups[i];
		rx_group->index = i;
		rx_group->igb = igb;
	}

	/*
	 * Set up all rx descriptor rings - must be called before receive unit
	 * enabled.
	 */
	ring_per_group = igb->num_rx_rings / igb->num_rx_groups;
	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];
		igb_setup_rx_ring(rx_ring);

		/*
		 * Map a ring to a group by assigning a group index
		 */
		rx_ring->group_index = i / ring_per_group;
	}

	/*
	 * Setup the Rx Long Packet Max Length register
	 */
	E1000_WRITE_REG(hw, E1000_RLPML, igb->max_frame_size);

	/*
	 * Hardware checksum settings
	 */
	if (igb->rx_hcksum_enable) {
		rxcsum =
		    E1000_RXCSUM_TUOFL |	/* TCP/UDP checksum */
		    E1000_RXCSUM_IPOFL;		/* IP checksum */

		E1000_WRITE_REG(hw, E1000_RXCSUM, rxcsum);
	}

	/*
	 * Setup classify and RSS for multiple receive queues
	 */
	switch (igb->vmdq_mode) {
	case E1000_VMDQ_OFF:
		/*
		 * One ring group, only RSS is needed when more than
		 * one ring enabled.
		 */
		if (igb->num_rx_rings > 1)
			igb_setup_rss(igb);
		break;
	case E1000_VMDQ_MAC:
		/*
		 * Multiple groups, each group has one ring,
		 * only the MAC classification is needed.
		 */
		igb_setup_mac_classify(igb);
		break;
	case E1000_VMDQ_MAC_RSS:
		/*
		 * Multiple groups and multiple rings, both
		 * MAC classification and RSS are needed.
		 */
		igb_setup_mac_rss_classify(igb);
		break;
	}

	/*
	 * Enable the receive unit - must be done after all
	 * the rx setup above.
	 */
	E1000_WRITE_REG(hw, E1000_RCTL, rctl);

	/*
	 * Initialize all adapter ring head & tail pointers - must
	 * be done after receive unit is enabled
	 */
	for (i = 0; i < igb->num_rx_rings; i++) {
		rx_ring = &igb->rx_rings[i];
		rx_data = rx_ring->rx_data;
		E1000_WRITE_REG(hw, E1000_RDH(i), 0);
		E1000_WRITE_REG(hw, E1000_RDT(i), rx_data->ring_size - 1);
	}

	/*
	 * 82575 with manageability enabled needs a special flush to make
	 * sure the fifos start clean.
	 */
	if ((hw->mac.type == e1000_82575) &&
	    (E1000_READ_REG(hw, E1000_MANC) & E1000_MANC_RCV_TCO_EN)) {
		e1000_rx_fifo_flush_82575(hw);
	}
}

static void
igb_setup_tx_ring(igb_tx_ring_t *tx_ring)
{
	igb_t *igb = tx_ring->igb;
	struct e1000_hw *hw = &igb->hw;
	uint32_t size;
	uint32_t buf_low;
	uint32_t buf_high;
	uint32_t reg_val;

	ASSERT(mutex_owned(&tx_ring->tx_lock));
	ASSERT(mutex_owned(&igb->gen_lock));


	/*
	 * Initialize the length register
	 */
	size = tx_ring->ring_size * sizeof (union e1000_adv_tx_desc);
	E1000_WRITE_REG(hw, E1000_TDLEN(tx_ring->index), size);

	/*
	 * Initialize the base address registers
	 */
	buf_low = (uint32_t)tx_ring->tbd_area.dma_address;
	buf_high = (uint32_t)(tx_ring->tbd_area.dma_address >> 32);
	E1000_WRITE_REG(hw, E1000_TDBAL(tx_ring->index), buf_low);
	E1000_WRITE_REG(hw, E1000_TDBAH(tx_ring->index), buf_high);

	/*
	 * Setup head & tail pointers
	 */
	E1000_WRITE_REG(hw, E1000_TDH(tx_ring->index), 0);
	E1000_WRITE_REG(hw, E1000_TDT(tx_ring->index), 0);

	/*
	 * Setup head write-back
	 */
	if (igb->tx_head_wb_enable) {
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
		buf_low |= E1000_TX_HEAD_WB_ENABLE;

		E1000_WRITE_REG(hw, E1000_TDWBAL(tx_ring->index), buf_low);
		E1000_WRITE_REG(hw, E1000_TDWBAH(tx_ring->index), buf_high);

		/*
		 * Turn off relaxed ordering for head write back or it will
		 * cause problems with the tx recycling
		 */
		reg_val = E1000_READ_REG(hw,
		    E1000_DCA_TXCTRL(tx_ring->index));
		reg_val &= ~E1000_DCA_TXCTRL_TX_WB_RO_EN;
		E1000_WRITE_REG(hw,
		    E1000_DCA_TXCTRL(tx_ring->index), reg_val);
	} else {
		tx_ring->tbd_head_wb = NULL;
	}

	tx_ring->tbd_head = 0;
	tx_ring->tbd_tail = 0;
	tx_ring->tbd_free = tx_ring->ring_size;

	if (igb->tx_ring_init == B_TRUE) {
		tx_ring->tcb_head = 0;
		tx_ring->tcb_tail = 0;
		tx_ring->tcb_free = tx_ring->free_list_size;
	}

	/*
	 * Enable TXDCTL per queue
	 */
	reg_val = E1000_READ_REG(hw, E1000_TXDCTL(tx_ring->index));
	reg_val |= E1000_TXDCTL_QUEUE_ENABLE;
	E1000_WRITE_REG(hw, E1000_TXDCTL(tx_ring->index), reg_val);

	/*
	 * Initialize hardware checksum offload settings
	 */
	bzero(&tx_ring->tx_context, sizeof (tx_context_t));
}

static void
igb_setup_tx(igb_t *igb)
{
	igb_tx_ring_t *tx_ring;
	struct e1000_hw *hw = &igb->hw;
	uint32_t reg_val;
	int i;

	for (i = 0; i < igb->num_tx_rings; i++) {
		tx_ring = &igb->tx_rings[i];
		igb_setup_tx_ring(tx_ring);
	}

	/*
	 * Setup the Transmit Control Register (TCTL)
	 */
	reg_val = E1000_READ_REG(hw, E1000_TCTL);
	reg_val &= ~E1000_TCTL_CT;
	reg_val |= E1000_TCTL_PSP | E1000_TCTL_RTLC |
	    (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	/* Enable transmits */
	reg_val |= E1000_TCTL_EN;

	E1000_WRITE_REG(hw, E1000_TCTL, reg_val);
}

/*
 * igb_setup_rss - Setup receive-side scaling feature
 */
static void
igb_setup_rss(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t i, mrqc, rxcsum;
	int shift = 0;
	uint32_t random;
	union e1000_reta {
		uint32_t	dword;
		uint8_t		bytes[4];
	} reta;

	/* Setup the Redirection Table */
	if (hw->mac.type == e1000_82576) {
		shift = 3;
	} else if (hw->mac.type == e1000_82575) {
		shift = 6;
	}
	for (i = 0; i < (32 * 4); i++) {
		reta.bytes[i & 3] = (i % igb->num_rx_rings) << shift;
		if ((i & 3) == 3) {
			E1000_WRITE_REG(hw,
			    (E1000_RETA(0) + (i & ~3)), reta.dword);
		}
	}

	/* Fill out hash function seeds */
	for (i = 0; i < 10; i++) {
		(void) random_get_pseudo_bytes((uint8_t *)&random,
		    sizeof (uint32_t));
		E1000_WRITE_REG(hw, E1000_RSSRK(i), random);
	}

	/* Setup the Multiple Receive Queue Control register */
	mrqc = E1000_MRQC_ENABLE_RSS_4Q;
	mrqc |= (E1000_MRQC_RSS_FIELD_IPV4 |
	    E1000_MRQC_RSS_FIELD_IPV4_TCP |
	    E1000_MRQC_RSS_FIELD_IPV6 |
	    E1000_MRQC_RSS_FIELD_IPV6_TCP |
	    E1000_MRQC_RSS_FIELD_IPV4_UDP |
	    E1000_MRQC_RSS_FIELD_IPV6_UDP |
	    E1000_MRQC_RSS_FIELD_IPV6_UDP_EX |
	    E1000_MRQC_RSS_FIELD_IPV6_TCP_EX);

	E1000_WRITE_REG(hw, E1000_MRQC, mrqc);

	/*
	 * Disable Packet Checksum to enable RSS for multiple receive queues.
	 *
	 * The Packet Checksum is not ethernet CRC. It is another kind of
	 * checksum offloading provided by the 82575 chipset besides the IP
	 * header checksum offloading and the TCP/UDP checksum offloading.
	 * The Packet Checksum is by default computed over the entire packet
	 * from the first byte of the DA through the last byte of the CRC,
	 * including the Ethernet and IP headers.
	 *
	 * It is a hardware limitation that Packet Checksum is mutually
	 * exclusive with RSS.
	 */
	rxcsum = E1000_READ_REG(hw, E1000_RXCSUM);
	rxcsum |= E1000_RXCSUM_PCSD;
	E1000_WRITE_REG(hw, E1000_RXCSUM, rxcsum);
}

/*
 * igb_setup_mac_rss_classify - Setup MAC classification and rss
 */
static void
igb_setup_mac_rss_classify(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t i, mrqc, vmdctl, rxcsum;
	uint32_t ring_per_group;
	int shift_group0, shift_group1;
	uint32_t random;
	union e1000_reta {
		uint32_t	dword;
		uint8_t		bytes[4];
	} reta;

	ring_per_group = igb->num_rx_rings / igb->num_rx_groups;

	/* Setup the Redirection Table, it is shared between two groups */
	shift_group0 = 2;
	shift_group1 = 6;
	for (i = 0; i < (32 * 4); i++) {
		reta.bytes[i & 3] = ((i % ring_per_group) << shift_group0) |
		    ((ring_per_group + (i % ring_per_group)) << shift_group1);
		if ((i & 3) == 3) {
			E1000_WRITE_REG(hw,
			    (E1000_RETA(0) + (i & ~3)), reta.dword);
		}
	}

	/* Fill out hash function seeds */
	for (i = 0; i < 10; i++) {
		(void) random_get_pseudo_bytes((uint8_t *)&random,
		    sizeof (uint32_t));
		E1000_WRITE_REG(hw, E1000_RSSRK(i), random);
	}

	/*
	 * Setup the Multiple Receive Queue Control register,
	 * enable VMDq based on packet destination MAC address and RSS.
	 */
	mrqc = E1000_MRQC_ENABLE_VMDQ_MAC_RSS_GROUP;
	mrqc |= (E1000_MRQC_RSS_FIELD_IPV4 |
	    E1000_MRQC_RSS_FIELD_IPV4_TCP |
	    E1000_MRQC_RSS_FIELD_IPV6 |
	    E1000_MRQC_RSS_FIELD_IPV6_TCP |
	    E1000_MRQC_RSS_FIELD_IPV4_UDP |
	    E1000_MRQC_RSS_FIELD_IPV6_UDP |
	    E1000_MRQC_RSS_FIELD_IPV6_UDP_EX |
	    E1000_MRQC_RSS_FIELD_IPV6_TCP_EX);

	E1000_WRITE_REG(hw, E1000_MRQC, mrqc);


	/* Define the default group and default queues */
	vmdctl = E1000_VMDQ_MAC_GROUP_DEFAULT_QUEUE;
	E1000_WRITE_REG(hw, E1000_VT_CTL, vmdctl);

	/*
	 * Disable Packet Checksum to enable RSS for multiple receive queues.
	 *
	 * The Packet Checksum is not ethernet CRC. It is another kind of
	 * checksum offloading provided by the 82575 chipset besides the IP
	 * header checksum offloading and the TCP/UDP checksum offloading.
	 * The Packet Checksum is by default computed over the entire packet
	 * from the first byte of the DA through the last byte of the CRC,
	 * including the Ethernet and IP headers.
	 *
	 * It is a hardware limitation that Packet Checksum is mutually
	 * exclusive with RSS.
	 */
	rxcsum = E1000_READ_REG(hw, E1000_RXCSUM);
	rxcsum |= E1000_RXCSUM_PCSD;
	E1000_WRITE_REG(hw, E1000_RXCSUM, rxcsum);
}

/*
 * igb_setup_mac_classify - Setup MAC classification feature
 */
static void
igb_setup_mac_classify(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t mrqc, rxcsum;

	/*
	 * Setup the Multiple Receive Queue Control register,
	 * enable VMDq based on packet destination MAC address.
	 */
	mrqc = E1000_MRQC_ENABLE_VMDQ_MAC_GROUP;
	E1000_WRITE_REG(hw, E1000_MRQC, mrqc);

	/*
	 * Disable Packet Checksum to enable RSS for multiple receive queues.
	 *
	 * The Packet Checksum is not ethernet CRC. It is another kind of
	 * checksum offloading provided by the 82575 chipset besides the IP
	 * header checksum offloading and the TCP/UDP checksum offloading.
	 * The Packet Checksum is by default computed over the entire packet
	 * from the first byte of the DA through the last byte of the CRC,
	 * including the Ethernet and IP headers.
	 *
	 * It is a hardware limitation that Packet Checksum is mutually
	 * exclusive with RSS.
	 */
	rxcsum = E1000_READ_REG(hw, E1000_RXCSUM);
	rxcsum |= E1000_RXCSUM_PCSD;
	E1000_WRITE_REG(hw, E1000_RXCSUM, rxcsum);

}

/*
 * igb_init_unicst - Initialize the unicast addresses
 */
static void
igb_init_unicst(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	int slot;

	/*
	 * Here we should consider two situations:
	 *
	 * 1. Chipset is initialized the first time
	 *    Initialize the multiple unicast addresses, and
	 *    save the default MAC address.
	 *
	 * 2. Chipset is reset
	 *    Recover the multiple unicast addresses from the
	 *    software data structure to the RAR registers.
	 */

	/*
	 * Clear the default MAC address in the RAR0 rgister,
	 * which is loaded from EEPROM when system boot or chipreset,
	 * this will cause the conficts with add_mac/rem_mac entry
	 * points when VMDq is enabled. For this reason, the RAR0
	 * must be cleared for both cases mentioned above.
	 */
	e1000_rar_clear(hw, 0);

	if (!igb->unicst_init) {

		/* Initialize the multiple unicast addresses */
		igb->unicst_total = MAX_NUM_UNICAST_ADDRESSES;
		igb->unicst_avail = igb->unicst_total;

		for (slot = 0; slot < igb->unicst_total; slot++)
			igb->unicst_addr[slot].mac.set = 0;

		igb->unicst_init = B_TRUE;
	} else {
		/* Re-configure the RAR registers */
		for (slot = 0; slot < igb->unicst_total; slot++) {
			(void) e1000_rar_set_vmdq(hw,
			    igb->unicst_addr[slot].mac.addr,
			    slot, igb->vmdq_mode,
			    igb->unicst_addr[slot].mac.group_index);
		}
	}
}

/*
 * igb_unicst_find - Find the slot for the specified unicast address
 */
int
igb_unicst_find(igb_t *igb, const uint8_t *mac_addr)
{
	int slot;

	ASSERT(mutex_owned(&igb->gen_lock));

	for (slot = 0; slot < igb->unicst_total; slot++) {
		if (bcmp(igb->unicst_addr[slot].mac.addr,
		    mac_addr, ETHERADDRL) == 0)
			return (slot);
	}

	return (-1);
}

/*
 * igb_unicst_set - Set the unicast address to the specified slot
 */
int
igb_unicst_set(igb_t *igb, const uint8_t *mac_addr,
    int slot)
{
	struct e1000_hw *hw = &igb->hw;

	ASSERT(mutex_owned(&igb->gen_lock));

	/*
	 * Save the unicast address in the software data structure
	 */
	bcopy(mac_addr, igb->unicst_addr[slot].mac.addr, ETHERADDRL);

	/*
	 * Set the unicast address to the RAR register
	 */
	(void) e1000_rar_set(hw, (uint8_t *)mac_addr, slot);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * igb_multicst_add - Add a multicst address
 */
int
igb_multicst_add(igb_t *igb, const uint8_t *multiaddr)
{
	struct ether_addr *new_table;
	size_t new_len;
	size_t old_len;

	ASSERT(mutex_owned(&igb->gen_lock));

	if ((multiaddr[0] & 01) == 0) {
		igb_error(igb, "Illegal multicast address");
		return (EINVAL);
	}

	if (igb->mcast_count >= igb->mcast_max_num) {
		igb_error(igb, "Adapter requested more than %d mcast addresses",
		    igb->mcast_max_num);
		return (ENOENT);
	}

	if (igb->mcast_count == igb->mcast_alloc_count) {
		old_len = igb->mcast_alloc_count *
		    sizeof (struct ether_addr);
		new_len = (igb->mcast_alloc_count + MCAST_ALLOC_COUNT) *
		    sizeof (struct ether_addr);

		new_table = kmem_alloc(new_len, KM_NOSLEEP);
		if (new_table == NULL) {
			igb_error(igb,
			    "Not enough memory to alloc mcast table");
			return (ENOMEM);
		}

		if (igb->mcast_table != NULL) {
			bcopy(igb->mcast_table, new_table, old_len);
			kmem_free(igb->mcast_table, old_len);
		}
		igb->mcast_alloc_count += MCAST_ALLOC_COUNT;
		igb->mcast_table = new_table;
	}

	bcopy(multiaddr,
	    &igb->mcast_table[igb->mcast_count], ETHERADDRL);
	igb->mcast_count++;

	/*
	 * Update the multicast table in the hardware
	 */
	igb_setup_multicst(igb);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

/*
 * igb_multicst_remove - Remove a multicst address
 */
int
igb_multicst_remove(igb_t *igb, const uint8_t *multiaddr)
{
	struct ether_addr *new_table;
	size_t new_len;
	size_t old_len;
	int i;

	ASSERT(mutex_owned(&igb->gen_lock));

	for (i = 0; i < igb->mcast_count; i++) {
		if (bcmp(multiaddr, &igb->mcast_table[i],
		    ETHERADDRL) == 0) {
			for (i++; i < igb->mcast_count; i++) {
				igb->mcast_table[i - 1] =
				    igb->mcast_table[i];
			}
			igb->mcast_count--;
			break;
		}
	}

	if ((igb->mcast_alloc_count - igb->mcast_count) >
	    MCAST_ALLOC_COUNT) {
		old_len = igb->mcast_alloc_count *
		    sizeof (struct ether_addr);
		new_len = (igb->mcast_alloc_count - MCAST_ALLOC_COUNT) *
		    sizeof (struct ether_addr);

		new_table = kmem_alloc(new_len, KM_NOSLEEP);
		if (new_table != NULL) {
			bcopy(igb->mcast_table, new_table, new_len);
			kmem_free(igb->mcast_table, old_len);
			igb->mcast_alloc_count -= MCAST_ALLOC_COUNT;
			igb->mcast_table = new_table;
		}
	}

	/*
	 * Update the multicast table in the hardware
	 */
	igb_setup_multicst(igb);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		return (EIO);
	}

	return (0);
}

static void
igb_release_multicast(igb_t *igb)
{
	if (igb->mcast_table != NULL) {
		kmem_free(igb->mcast_table,
		    igb->mcast_alloc_count * sizeof (struct ether_addr));
		igb->mcast_table = NULL;
	}
}

/*
 * igb_setup_multicast - setup multicast data structures
 *
 * This routine initializes all of the multicast related structures
 * and save them in the hardware registers.
 */
static void
igb_setup_multicst(igb_t *igb)
{
	uint8_t *mc_addr_list;
	uint32_t mc_addr_count;
	struct e1000_hw *hw = &igb->hw;

	ASSERT(mutex_owned(&igb->gen_lock));
	ASSERT(igb->mcast_count <= igb->mcast_max_num);

	mc_addr_list = (uint8_t *)igb->mcast_table;
	mc_addr_count = igb->mcast_count;

	/*
	 * Update the multicase addresses to the MTA registers
	 */
	e1000_update_mc_addr_list(hw, mc_addr_list, mc_addr_count);
}

/*
 * igb_get_conf - Get driver configurations set in driver.conf
 *
 * This routine gets user-configured values out of the configuration
 * file igb.conf.
 *
 * For each configurable value, there is a minimum, a maximum, and a
 * default.
 * If user does not configure a value, use the default.
 * If user configures below the minimum, use the minumum.
 * If user configures above the maximum, use the maxumum.
 */
static void
igb_get_conf(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t default_mtu;
	uint32_t flow_control;
	uint32_t ring_per_group;
	int i;

	/*
	 * igb driver supports the following user configurations:
	 *
	 * Link configurations:
	 *    adv_autoneg_cap
	 *    adv_1000fdx_cap
	 *    adv_100fdx_cap
	 *    adv_100hdx_cap
	 *    adv_10fdx_cap
	 *    adv_10hdx_cap
	 * Note: 1000hdx is not supported.
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
	 * Call igb_get_prop() to get the value for a specific
	 * configuration parameter.
	 */

	/*
	 * Link configurations
	 */
	igb->param_adv_autoneg_cap = igb_get_prop(igb,
	    PROP_ADV_AUTONEG_CAP, 0, 1, 1);
	igb->param_adv_1000fdx_cap = igb_get_prop(igb,
	    PROP_ADV_1000FDX_CAP, 0, 1, 1);
	igb->param_adv_100fdx_cap = igb_get_prop(igb,
	    PROP_ADV_100FDX_CAP, 0, 1, 1);
	igb->param_adv_100hdx_cap = igb_get_prop(igb,
	    PROP_ADV_100HDX_CAP, 0, 1, 1);
	igb->param_adv_10fdx_cap = igb_get_prop(igb,
	    PROP_ADV_10FDX_CAP, 0, 1, 1);
	igb->param_adv_10hdx_cap = igb_get_prop(igb,
	    PROP_ADV_10HDX_CAP, 0, 1, 1);

	/*
	 * Jumbo frame configurations
	 */
	default_mtu = igb_get_prop(igb, PROP_DEFAULT_MTU,
	    MIN_MTU, MAX_MTU, DEFAULT_MTU);

	igb->max_frame_size = default_mtu +
	    sizeof (struct ether_vlan_header) + ETHERFCSL;

	/*
	 * Ethernet flow control configuration
	 */
	flow_control = igb_get_prop(igb, PROP_FLOW_CONTROL,
	    e1000_fc_none, 4, e1000_fc_full);
	if (flow_control == 4)
		flow_control = e1000_fc_default;

	hw->fc.requested_mode = flow_control;

	/*
	 * Multiple rings configurations
	 */
	igb->tx_ring_size = igb_get_prop(igb, PROP_TX_RING_SIZE,
	    MIN_TX_RING_SIZE, MAX_TX_RING_SIZE, DEFAULT_TX_RING_SIZE);
	igb->rx_ring_size = igb_get_prop(igb, PROP_RX_RING_SIZE,
	    MIN_RX_RING_SIZE, MAX_RX_RING_SIZE, DEFAULT_RX_RING_SIZE);

	igb->mr_enable = igb_get_prop(igb, PROP_MR_ENABLE, 0, 1, 0);
	igb->num_rx_groups = igb_get_prop(igb, PROP_RX_GROUP_NUM,
	    MIN_RX_GROUP_NUM, MAX_RX_GROUP_NUM, DEFAULT_RX_GROUP_NUM);
	/*
	 * Currently we do not support VMDq for 82576 and 82580.
	 * If it is e1000_82576, set num_rx_groups to 1.
	 */
	if (hw->mac.type >= e1000_82576)
		igb->num_rx_groups = 1;

	if (igb->mr_enable) {
		igb->num_tx_rings = igb->capab->def_tx_que_num;
		igb->num_rx_rings = igb->capab->def_rx_que_num;
	} else {
		igb->num_tx_rings = 1;
		igb->num_rx_rings = 1;

		if (igb->num_rx_groups > 1) {
			igb_error(igb,
			    "Invalid rx groups number. Please enable multiple "
			    "rings first");
			igb->num_rx_groups = 1;
		}
	}

	/*
	 * Check the divisibility between rx rings and rx groups.
	 */
	for (i = igb->num_rx_groups; i > 0; i--) {
		if ((igb->num_rx_rings % i) == 0)
			break;
	}
	if (i != igb->num_rx_groups) {
		igb_error(igb,
		    "Invalid rx groups number. Downgrade the rx group "
		    "number to %d.", i);
		igb->num_rx_groups = i;
	}

	/*
	 * Get the ring number per group.
	 */
	ring_per_group = igb->num_rx_rings / igb->num_rx_groups;

	if (igb->num_rx_groups == 1) {
		/*
		 * One rx ring group, the rx ring number is num_rx_rings.
		 */
		igb->vmdq_mode = E1000_VMDQ_OFF;
	} else if (ring_per_group == 1) {
		/*
		 * Multiple rx groups, each group has one rx ring.
		 */
		igb->vmdq_mode = E1000_VMDQ_MAC;
	} else {
		/*
		 * Multiple groups and multiple rings.
		 */
		igb->vmdq_mode = E1000_VMDQ_MAC_RSS;
	}

	/*
	 * Tunable used to force an interrupt type. The only use is
	 * for testing of the lesser interrupt types.
	 * 0 = don't force interrupt type
	 * 1 = force interrupt type MSIX
	 * 2 = force interrupt type MSI
	 * 3 = force interrupt type Legacy
	 */
	igb->intr_force = igb_get_prop(igb, PROP_INTR_FORCE,
	    IGB_INTR_NONE, IGB_INTR_LEGACY, IGB_INTR_NONE);

	igb->tx_hcksum_enable = igb_get_prop(igb, PROP_TX_HCKSUM_ENABLE,
	    0, 1, 1);
	igb->rx_hcksum_enable = igb_get_prop(igb, PROP_RX_HCKSUM_ENABLE,
	    0, 1, 1);
	igb->lso_enable = igb_get_prop(igb, PROP_LSO_ENABLE,
	    0, 1, 1);
	igb->tx_head_wb_enable = igb_get_prop(igb, PROP_TX_HEAD_WB_ENABLE,
	    0, 1, 1);

	/*
	 * igb LSO needs the tx h/w checksum support.
	 * Here LSO will be disabled if tx h/w checksum has been disabled.
	 */
	if (igb->tx_hcksum_enable == B_FALSE)
		igb->lso_enable = B_FALSE;

	igb->tx_copy_thresh = igb_get_prop(igb, PROP_TX_COPY_THRESHOLD,
	    MIN_TX_COPY_THRESHOLD, MAX_TX_COPY_THRESHOLD,
	    DEFAULT_TX_COPY_THRESHOLD);
	igb->tx_recycle_thresh = igb_get_prop(igb, PROP_TX_RECYCLE_THRESHOLD,
	    MIN_TX_RECYCLE_THRESHOLD, MAX_TX_RECYCLE_THRESHOLD,
	    DEFAULT_TX_RECYCLE_THRESHOLD);
	igb->tx_overload_thresh = igb_get_prop(igb, PROP_TX_OVERLOAD_THRESHOLD,
	    MIN_TX_OVERLOAD_THRESHOLD, MAX_TX_OVERLOAD_THRESHOLD,
	    DEFAULT_TX_OVERLOAD_THRESHOLD);
	igb->tx_resched_thresh = igb_get_prop(igb, PROP_TX_RESCHED_THRESHOLD,
	    MIN_TX_RESCHED_THRESHOLD,
	    MIN(igb->tx_ring_size, MAX_TX_RESCHED_THRESHOLD),
	    igb->tx_ring_size > DEFAULT_TX_RESCHED_THRESHOLD ?
	    DEFAULT_TX_RESCHED_THRESHOLD : DEFAULT_TX_RESCHED_THRESHOLD_LOW);

	igb->rx_copy_thresh = igb_get_prop(igb, PROP_RX_COPY_THRESHOLD,
	    MIN_RX_COPY_THRESHOLD, MAX_RX_COPY_THRESHOLD,
	    DEFAULT_RX_COPY_THRESHOLD);
	igb->rx_limit_per_intr = igb_get_prop(igb, PROP_RX_LIMIT_PER_INTR,
	    MIN_RX_LIMIT_PER_INTR, MAX_RX_LIMIT_PER_INTR,
	    DEFAULT_RX_LIMIT_PER_INTR);

	igb->intr_throttling[0] = igb_get_prop(igb, PROP_INTR_THROTTLING,
	    igb->capab->min_intr_throttle,
	    igb->capab->max_intr_throttle,
	    igb->capab->def_intr_throttle);

	/*
	 * Max number of multicast addresses
	 */
	igb->mcast_max_num =
	    igb_get_prop(igb, PROP_MCAST_MAX_NUM,
	    MIN_MCAST_NUM, MAX_MCAST_NUM, DEFAULT_MCAST_NUM);
}

/*
 * igb_get_prop - Get a property value out of the configuration file igb.conf
 *
 * Caller provides the name of the property, a default value, a minimum
 * value, and a maximum value.
 *
 * Return configured value of the property, with default, minimum and
 * maximum properly applied.
 */
static int
igb_get_prop(igb_t *igb,
    char *propname,	/* name of the property */
    int minval,		/* minimum acceptable value */
    int maxval,		/* maximim acceptable value */
    int defval)		/* default value */
{
	int value;

	/*
	 * Call ddi_prop_get_int() to read the conf settings
	 */
	value = ddi_prop_get_int(DDI_DEV_T_ANY, igb->dip,
	    DDI_PROP_DONTPASS, propname, defval);

	if (value > maxval)
		value = maxval;

	if (value < minval)
		value = minval;

	return (value);
}

/*
 * igb_setup_link - Using the link properties to setup the link
 */
int
igb_setup_link(igb_t *igb, boolean_t setup_hw)
{
	struct e1000_mac_info *mac;
	struct e1000_phy_info *phy;
	boolean_t invalid;

	mac = &igb->hw.mac;
	phy = &igb->hw.phy;
	invalid = B_FALSE;

	if (igb->param_adv_autoneg_cap == 1) {
		mac->autoneg = B_TRUE;
		phy->autoneg_advertised = 0;

		/*
		 * 1000hdx is not supported for autonegotiation
		 */
		if (igb->param_adv_1000fdx_cap == 1)
			phy->autoneg_advertised |= ADVERTISE_1000_FULL;

		if (igb->param_adv_100fdx_cap == 1)
			phy->autoneg_advertised |= ADVERTISE_100_FULL;

		if (igb->param_adv_100hdx_cap == 1)
			phy->autoneg_advertised |= ADVERTISE_100_HALF;

		if (igb->param_adv_10fdx_cap == 1)
			phy->autoneg_advertised |= ADVERTISE_10_FULL;

		if (igb->param_adv_10hdx_cap == 1)
			phy->autoneg_advertised |= ADVERTISE_10_HALF;

		if (phy->autoneg_advertised == 0)
			invalid = B_TRUE;
	} else {
		mac->autoneg = B_FALSE;

		/*
		 * 1000fdx and 1000hdx are not supported for forced link
		 */
		if (igb->param_adv_100fdx_cap == 1)
			mac->forced_speed_duplex = ADVERTISE_100_FULL;
		else if (igb->param_adv_100hdx_cap == 1)
			mac->forced_speed_duplex = ADVERTISE_100_HALF;
		else if (igb->param_adv_10fdx_cap == 1)
			mac->forced_speed_duplex = ADVERTISE_10_FULL;
		else if (igb->param_adv_10hdx_cap == 1)
			mac->forced_speed_duplex = ADVERTISE_10_HALF;
		else
			invalid = B_TRUE;
	}

	if (invalid) {
		igb_notice(igb, "Invalid link settings. Setup link to "
		    "autonegotiation with full link capabilities.");
		mac->autoneg = B_TRUE;
		phy->autoneg_advertised = ADVERTISE_1000_FULL |
		    ADVERTISE_100_FULL | ADVERTISE_100_HALF |
		    ADVERTISE_10_FULL | ADVERTISE_10_HALF;
	}

	if (setup_hw) {
		if (e1000_setup_link(&igb->hw) != E1000_SUCCESS)
			return (IGB_FAILURE);
	}

	return (IGB_SUCCESS);
}


/*
 * igb_is_link_up - Check if the link is up
 */
static boolean_t
igb_is_link_up(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	boolean_t link_up = B_FALSE;

	ASSERT(mutex_owned(&igb->gen_lock));

	/*
	 * get_link_status is set in the interrupt handler on link-status-change
	 * or rx sequence error interrupt.  get_link_status will stay
	 * false until the e1000_check_for_link establishes link only
	 * for copper adapters.
	 */
	switch (hw->phy.media_type) {
	case e1000_media_type_copper:
		if (hw->mac.get_link_status) {
			(void) e1000_check_for_link(hw);
			link_up = !hw->mac.get_link_status;
		} else {
			link_up = B_TRUE;
		}
		break;
	case e1000_media_type_fiber:
		(void) e1000_check_for_link(hw);
		link_up = (E1000_READ_REG(hw, E1000_STATUS) & E1000_STATUS_LU);
		break;
	case e1000_media_type_internal_serdes:
		(void) e1000_check_for_link(hw);
		link_up = hw->mac.serdes_has_link;
		break;
	}

	return (link_up);
}

/*
 * igb_link_check - Link status processing
 */
static boolean_t
igb_link_check(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint16_t speed = 0, duplex = 0;
	boolean_t link_changed = B_FALSE;

	ASSERT(mutex_owned(&igb->gen_lock));

	if (igb_is_link_up(igb)) {
		/*
		 * The Link is up, check whether it was marked as down earlier
		 */
		if (igb->link_state != LINK_STATE_UP) {
			(void) e1000_get_speed_and_duplex(hw, &speed, &duplex);
			igb->link_speed = speed;
			igb->link_duplex = duplex;
			igb->link_state = LINK_STATE_UP;
			link_changed = B_TRUE;
			if (!igb->link_complete)
				igb_stop_link_timer(igb);
		}
	} else if (igb->link_complete) {
		if (igb->link_state != LINK_STATE_DOWN) {
			igb->link_speed = 0;
			igb->link_duplex = 0;
			igb->link_state = LINK_STATE_DOWN;
			link_changed = B_TRUE;
		}
	}

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		return (B_FALSE);
	}

	return (link_changed);
}

/*
 * igb_local_timer - driver watchdog function
 *
 * This function will handle the hardware stall check, link status
 * check and other routines.
 */
static void
igb_local_timer(void *arg)
{
	igb_t *igb = (igb_t *)arg;
	boolean_t link_changed = B_FALSE;

	if (igb->igb_state & IGB_ERROR) {
		igb->reset_count++;
		if (igb_reset(igb) == IGB_SUCCESS)
			ddi_fm_service_impact(igb->dip, DDI_SERVICE_RESTORED);

		igb_restart_watchdog_timer(igb);
		return;
	}

	if (igb_stall_check(igb) || (igb->igb_state & IGB_STALL)) {
		igb_fm_ereport(igb, DDI_FM_DEVICE_STALL);
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_LOST);
		igb->reset_count++;
		if (igb_reset(igb) == IGB_SUCCESS)
			ddi_fm_service_impact(igb->dip, DDI_SERVICE_RESTORED);

		igb_restart_watchdog_timer(igb);
		return;
	}

	mutex_enter(&igb->gen_lock);
	if (!(igb->igb_state & IGB_SUSPENDED) && (igb->igb_state & IGB_STARTED))
		link_changed = igb_link_check(igb);
	mutex_exit(&igb->gen_lock);

	if (link_changed)
		mac_link_update(igb->mac_hdl, igb->link_state);

	igb_restart_watchdog_timer(igb);
}

/*
 * igb_link_timer - link setup timer function
 *
 * It is called when the timer for link setup is expired, which indicates
 * the completion of the link setup. The link state will not be updated
 * until the link setup is completed. And the link state will not be sent
 * to the upper layer through mac_link_update() in this function. It will
 * be updated in the local timer routine or the interrupts service routine
 * after the interface is started (plumbed).
 */
static void
igb_link_timer(void *arg)
{
	igb_t *igb = (igb_t *)arg;

	mutex_enter(&igb->link_lock);
	igb->link_complete = B_TRUE;
	igb->link_tid = 0;
	mutex_exit(&igb->link_lock);
}
/*
 * igb_stall_check - check for transmit stall
 *
 * This function checks if the adapter is stalled (in transmit).
 *
 * It is called each time the watchdog timeout is invoked.
 * If the transmit descriptor reclaim continuously fails,
 * the watchdog value will increment by 1. If the watchdog
 * value exceeds the threshold, the igb is assumed to
 * have stalled and need to be reset.
 */
static boolean_t
igb_stall_check(igb_t *igb)
{
	igb_tx_ring_t *tx_ring;
	struct e1000_hw *hw = &igb->hw;
	boolean_t result;
	int i;

	if (igb->link_state != LINK_STATE_UP)
		return (B_FALSE);

	/*
	 * If any tx ring is stalled, we'll reset the chipset
	 */
	result = B_FALSE;
	for (i = 0; i < igb->num_tx_rings; i++) {
		tx_ring = &igb->tx_rings[i];

		if (tx_ring->recycle_fail > 0)
			tx_ring->stall_watchdog++;
		else
			tx_ring->stall_watchdog = 0;

		if (tx_ring->stall_watchdog >= STALL_WATCHDOG_TIMEOUT) {
			result = B_TRUE;
			if (hw->mac.type == e1000_82580) {
				hw->dev_spec._82575.global_device_reset
				    = B_TRUE;
			}
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
 * is_valid_mac_addr - Check if the mac address is valid
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
igb_find_mac_address(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
#ifdef __sparc
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
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, igb->dip,
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
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, igb->dip, 0,
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
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, igb->dip,
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
#endif

	/*
	 * Read the device MAC address from the EEPROM
	 */
	if (e1000_read_mac_addr(hw) != E1000_SUCCESS)
		return (B_FALSE);

	return (B_TRUE);
}

#pragma inline(igb_arm_watchdog_timer)

static void
igb_arm_watchdog_timer(igb_t *igb)
{
	/*
	 * Fire a watchdog timer
	 */
	igb->watchdog_tid =
	    timeout(igb_local_timer,
	    (void *)igb, 1 * drv_usectohz(1000000));

}

/*
 * igb_enable_watchdog_timer - Enable and start the driver watchdog timer
 */
void
igb_enable_watchdog_timer(igb_t *igb)
{
	mutex_enter(&igb->watchdog_lock);

	if (!igb->watchdog_enable) {
		igb->watchdog_enable = B_TRUE;
		igb->watchdog_start = B_TRUE;
		igb_arm_watchdog_timer(igb);
	}

	mutex_exit(&igb->watchdog_lock);

}

/*
 * igb_disable_watchdog_timer - Disable and stop the driver watchdog timer
 */
void
igb_disable_watchdog_timer(igb_t *igb)
{
	timeout_id_t tid;

	mutex_enter(&igb->watchdog_lock);

	igb->watchdog_enable = B_FALSE;
	igb->watchdog_start = B_FALSE;
	tid = igb->watchdog_tid;
	igb->watchdog_tid = 0;

	mutex_exit(&igb->watchdog_lock);

	if (tid != 0)
		(void) untimeout(tid);

}

/*
 * igb_start_watchdog_timer - Start the driver watchdog timer
 */
static void
igb_start_watchdog_timer(igb_t *igb)
{
	mutex_enter(&igb->watchdog_lock);

	if (igb->watchdog_enable) {
		if (!igb->watchdog_start) {
			igb->watchdog_start = B_TRUE;
			igb_arm_watchdog_timer(igb);
		}
	}

	mutex_exit(&igb->watchdog_lock);
}

/*
 * igb_restart_watchdog_timer - Restart the driver watchdog timer
 */
static void
igb_restart_watchdog_timer(igb_t *igb)
{
	mutex_enter(&igb->watchdog_lock);

	if (igb->watchdog_start)
		igb_arm_watchdog_timer(igb);

	mutex_exit(&igb->watchdog_lock);
}

/*
 * igb_stop_watchdog_timer - Stop the driver watchdog timer
 */
static void
igb_stop_watchdog_timer(igb_t *igb)
{
	timeout_id_t tid;

	mutex_enter(&igb->watchdog_lock);

	igb->watchdog_start = B_FALSE;
	tid = igb->watchdog_tid;
	igb->watchdog_tid = 0;

	mutex_exit(&igb->watchdog_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

/*
 * igb_start_link_timer - Start the link setup timer
 */
static void
igb_start_link_timer(struct igb *igb)
{
	struct e1000_hw *hw = &igb->hw;
	clock_t link_timeout;

	if (hw->mac.autoneg)
		link_timeout = PHY_AUTO_NEG_LIMIT *
		    drv_usectohz(100000);
	else
		link_timeout = PHY_FORCE_LIMIT * drv_usectohz(100000);

	mutex_enter(&igb->link_lock);
	if (hw->phy.autoneg_wait_to_complete) {
		igb->link_complete = B_TRUE;
	} else {
		igb->link_complete = B_FALSE;
		igb->link_tid = timeout(igb_link_timer, (void *)igb,
		    link_timeout);
	}
	mutex_exit(&igb->link_lock);
}

/*
 * igb_stop_link_timer - Stop the link setup timer
 */
static void
igb_stop_link_timer(struct igb *igb)
{
	timeout_id_t tid;

	mutex_enter(&igb->link_lock);
	igb->link_complete = B_TRUE;
	tid = igb->link_tid;
	igb->link_tid = 0;
	mutex_exit(&igb->link_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

/*
 * igb_disable_adapter_interrupts - Clear/disable all hardware interrupts
 */
static void
igb_disable_adapter_interrupts(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;

	/*
	 * Set the IMC register to mask all the interrupts,
	 * including the tx interrupts.
	 */
	E1000_WRITE_REG(hw, E1000_IMC, ~0);
	E1000_WRITE_REG(hw, E1000_IAM, 0);

	/*
	 * Additional disabling for MSI-X
	 */
	if (igb->intr_type == DDI_INTR_TYPE_MSIX) {
		E1000_WRITE_REG(hw, E1000_EIMC, ~0);
		E1000_WRITE_REG(hw, E1000_EIAC, 0);
		E1000_WRITE_REG(hw, E1000_EIAM, 0);
	}

	E1000_WRITE_FLUSH(hw);
}

/*
 * igb_enable_adapter_interrupts_82580 - Enable NIC interrupts for 82580
 */
static void
igb_enable_adapter_interrupts_82580(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;

	/* Clear any pending interrupts */
	(void) E1000_READ_REG(hw, E1000_ICR);
	igb->ims_mask |= E1000_IMS_DRSTA;

	if (igb->intr_type == DDI_INTR_TYPE_MSIX) {

		/* Interrupt enabling for MSI-X */
		E1000_WRITE_REG(hw, E1000_EIMS, igb->eims_mask);
		E1000_WRITE_REG(hw, E1000_EIAC, igb->eims_mask);
		igb->ims_mask = (E1000_IMS_LSC | E1000_IMS_DRSTA);
		E1000_WRITE_REG(hw, E1000_IMS, igb->ims_mask);
	} else { /* Interrupt enabling for MSI and legacy */
		E1000_WRITE_REG(hw, E1000_IVAR0, E1000_IVAR_VALID);
		igb->ims_mask = IMS_ENABLE_MASK | E1000_IMS_TXQE;
		igb->ims_mask |= E1000_IMS_DRSTA;
		E1000_WRITE_REG(hw, E1000_IMS, igb->ims_mask);
	}

	/* Disable auto-mask for ICR interrupt bits */
	E1000_WRITE_REG(hw, E1000_IAM, 0);

	E1000_WRITE_FLUSH(hw);
}

/*
 * igb_enable_adapter_interrupts_82576 - Enable NIC interrupts for 82576
 */
static void
igb_enable_adapter_interrupts_82576(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;

	/* Clear any pending interrupts */
	(void) E1000_READ_REG(hw, E1000_ICR);

	if (igb->intr_type == DDI_INTR_TYPE_MSIX) {

		/* Interrupt enabling for MSI-X */
		E1000_WRITE_REG(hw, E1000_EIMS, igb->eims_mask);
		E1000_WRITE_REG(hw, E1000_EIAC, igb->eims_mask);
		igb->ims_mask = E1000_IMS_LSC;
		E1000_WRITE_REG(hw, E1000_IMS, E1000_IMS_LSC);
	} else {
		/* Interrupt enabling for MSI and legacy */
		E1000_WRITE_REG(hw, E1000_IVAR0, E1000_IVAR_VALID);
		igb->ims_mask = IMS_ENABLE_MASK | E1000_IMS_TXQE;
		E1000_WRITE_REG(hw, E1000_IMS,
		    (IMS_ENABLE_MASK | E1000_IMS_TXQE));
	}

	/* Disable auto-mask for ICR interrupt bits */
	E1000_WRITE_REG(hw, E1000_IAM, 0);

	E1000_WRITE_FLUSH(hw);
}

/*
 * igb_enable_adapter_interrupts_82575 - Enable NIC interrupts for 82575
 */
static void
igb_enable_adapter_interrupts_82575(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t reg;

	/* Clear any pending interrupts */
	(void) E1000_READ_REG(hw, E1000_ICR);

	if (igb->intr_type == DDI_INTR_TYPE_MSIX) {
		/* Interrupt enabling for MSI-X */
		E1000_WRITE_REG(hw, E1000_EIMS, igb->eims_mask);
		E1000_WRITE_REG(hw, E1000_EIAC, igb->eims_mask);
		igb->ims_mask = E1000_IMS_LSC;
		E1000_WRITE_REG(hw, E1000_IMS, E1000_IMS_LSC);

		/* Enable MSI-X PBA support */
		reg = E1000_READ_REG(hw, E1000_CTRL_EXT);
		reg |= E1000_CTRL_EXT_PBA_CLR;

		/* Non-selective interrupt clear-on-read */
		reg |= E1000_CTRL_EXT_IRCA;	/* Called NSICR in the EAS */

		E1000_WRITE_REG(hw, E1000_CTRL_EXT, reg);
	} else {
		/* Interrupt enabling for MSI and legacy */
		igb->ims_mask = IMS_ENABLE_MASK;
		E1000_WRITE_REG(hw, E1000_IMS, IMS_ENABLE_MASK);
	}

	E1000_WRITE_FLUSH(hw);
}

/*
 * Loopback Support
 */
static lb_property_t lb_normal =
	{ normal,	"normal",	IGB_LB_NONE		};
static lb_property_t lb_external =
	{ external,	"External",	IGB_LB_EXTERNAL		};
static lb_property_t lb_phy =
	{ internal,	"PHY",		IGB_LB_INTERNAL_PHY	};
static lb_property_t lb_serdes =
	{ internal,	"SerDes",	IGB_LB_INTERNAL_SERDES	};

enum ioc_reply
igb_loopback_ioctl(igb_t *igb, struct iocblk *iocp, mblk_t *mp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	struct e1000_hw *hw;
	uint32_t *lbmp;
	uint32_t size;
	uint32_t value;

	hw = &igb->hw;

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
		if (hw->phy.media_type == e1000_media_type_copper)
			value += sizeof (lb_phy);
		else
			value += sizeof (lb_serdes);
		value += sizeof (lb_external);

		lbsp = (lb_info_sz_t *)(uintptr_t)mp->b_cont->b_rptr;
		*lbsp = value;
		break;

	case LB_GET_INFO:
		value = sizeof (lb_normal);
		if (hw->phy.media_type == e1000_media_type_copper)
			value += sizeof (lb_phy);
		else
			value += sizeof (lb_serdes);
		value += sizeof (lb_external);

		size = value;
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		value = 0;
		lbpp = (lb_property_t *)(uintptr_t)mp->b_cont->b_rptr;

		lbpp[value++] = lb_normal;
		if (hw->phy.media_type == e1000_media_type_copper)
			lbpp[value++] = lb_phy;
		else
			lbpp[value++] = lb_serdes;
		lbpp[value++] = lb_external;
		break;

	case LB_GET_MODE:
		size = sizeof (uint32_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		lbmp = (uint32_t *)(uintptr_t)mp->b_cont->b_rptr;
		*lbmp = igb->loopback_mode;
		break;

	case LB_SET_MODE:
		size = 0;
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);

		lbmp = (uint32_t *)(uintptr_t)mp->b_cont->b_rptr;
		if (!igb_set_loopback_mode(igb, *lbmp))
			return (IOC_INVAL);
		break;
	}

	iocp->ioc_count = size;
	iocp->ioc_error = 0;

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		return (IOC_INVAL);
	}

	return (IOC_REPLY);
}

/*
 * igb_set_loopback_mode - Setup loopback based on the loopback mode
 */
static boolean_t
igb_set_loopback_mode(igb_t *igb, uint32_t mode)
{
	struct e1000_hw *hw;
	int i;

	if (mode == igb->loopback_mode)
		return (B_TRUE);

	hw = &igb->hw;

	igb->loopback_mode = mode;

	if (mode == IGB_LB_NONE) {
		/* Reset the chip */
		hw->phy.autoneg_wait_to_complete = B_TRUE;
		(void) igb_reset(igb);
		hw->phy.autoneg_wait_to_complete = B_FALSE;
		return (B_TRUE);
	}

	mutex_enter(&igb->gen_lock);

	switch (mode) {
	default:
		mutex_exit(&igb->gen_lock);
		return (B_FALSE);

	case IGB_LB_EXTERNAL:
		igb_set_external_loopback(igb);
		break;

	case IGB_LB_INTERNAL_PHY:
		igb_set_internal_phy_loopback(igb);
		break;

	case IGB_LB_INTERNAL_SERDES:
		igb_set_internal_serdes_loopback(igb);
		break;
	}

	mutex_exit(&igb->gen_lock);

	/*
	 * When external loopback is set, wait up to 1000ms to get the link up.
	 * According to test, 1000ms can work and it's an experimental value.
	 */
	if (mode == IGB_LB_EXTERNAL) {
		for (i = 0; i <= 10; i++) {
			mutex_enter(&igb->gen_lock);
			(void) igb_link_check(igb);
			mutex_exit(&igb->gen_lock);

			if (igb->link_state == LINK_STATE_UP)
				break;

			msec_delay(100);
		}

		if (igb->link_state != LINK_STATE_UP) {
			/*
			 * Does not support external loopback.
			 * Reset driver to loopback none.
			 */
			igb->loopback_mode = IGB_LB_NONE;

			/* Reset the chip */
			hw->phy.autoneg_wait_to_complete = B_TRUE;
			(void) igb_reset(igb);
			hw->phy.autoneg_wait_to_complete = B_FALSE;

			IGB_DEBUGLOG_0(igb, "Set external loopback failed, "
			    "reset to loopback none.");

			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * igb_set_external_loopback - Set the external loopback mode
 */
static void
igb_set_external_loopback(igb_t *igb)
{
	struct e1000_hw *hw;
	uint32_t ctrl_ext;

	hw = &igb->hw;

	/* Set link mode to PHY (00b) in the Extended Control register */
	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
	ctrl_ext &= ~E1000_CTRL_EXT_LINK_MODE_MASK;
	E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);

	(void) e1000_write_phy_reg(hw, 0x0, 0x0140);
	(void) e1000_write_phy_reg(hw, 0x9, 0x1a00);
	(void) e1000_write_phy_reg(hw, 0x12, 0x1610);
	(void) e1000_write_phy_reg(hw, 0x1f37, 0x3f1c);
}

/*
 * igb_set_internal_phy_loopback - Set the internal PHY loopback mode
 */
static void
igb_set_internal_phy_loopback(igb_t *igb)
{
	struct e1000_hw *hw;
	uint32_t ctrl_ext;
	uint16_t phy_ctrl;
	uint16_t phy_pconf;

	hw = &igb->hw;

	/* Set link mode to PHY (00b) in the Extended Control register */
	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
	ctrl_ext &= ~E1000_CTRL_EXT_LINK_MODE_MASK;
	E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);

	/*
	 * Set PHY control register (0x4140):
	 *    Set full duplex mode
	 *    Set loopback bit
	 *    Clear auto-neg enable bit
	 *    Set PHY speed
	 */
	phy_ctrl = MII_CR_FULL_DUPLEX | MII_CR_SPEED_1000 | MII_CR_LOOPBACK;
	(void) e1000_write_phy_reg(hw, PHY_CONTROL, phy_ctrl);

	/* Set the link disable bit in the Port Configuration register */
	(void) e1000_read_phy_reg(hw, 0x10, &phy_pconf);
	phy_pconf |= (uint16_t)1 << 14;
	(void) e1000_write_phy_reg(hw, 0x10, phy_pconf);
}

/*
 * igb_set_internal_serdes_loopback - Set the internal SerDes loopback mode
 */
static void
igb_set_internal_serdes_loopback(igb_t *igb)
{
	struct e1000_hw *hw;
	uint32_t ctrl_ext;
	uint32_t ctrl;
	uint32_t pcs_lctl;
	uint32_t connsw;

	hw = &igb->hw;

	/* Set link mode to SerDes (11b) in the Extended Control register */
	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
	ctrl_ext |= E1000_CTRL_EXT_LINK_MODE_PCIE_SERDES;
	E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);

	/* Configure the SerDes to loopback */
	E1000_WRITE_REG(hw, E1000_SCTL, 0x410);

	/* Set Device Control register */
	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	ctrl |= (E1000_CTRL_FD |	/* Force full duplex */
	    E1000_CTRL_SLU);		/* Force link up */
	ctrl &= ~(E1000_CTRL_RFCE |	/* Disable receive flow control */
	    E1000_CTRL_TFCE |		/* Disable transmit flow control */
	    E1000_CTRL_LRST);		/* Clear link reset */
	E1000_WRITE_REG(hw, E1000_CTRL, ctrl);

	/* Set PCS Link Control register */
	pcs_lctl = E1000_READ_REG(hw, E1000_PCS_LCTL);
	pcs_lctl |= (E1000_PCS_LCTL_FORCE_LINK |
	    E1000_PCS_LCTL_FSD |
	    E1000_PCS_LCTL_FDV_FULL |
	    E1000_PCS_LCTL_FLV_LINK_UP);
	pcs_lctl &= ~E1000_PCS_LCTL_AN_ENABLE;
	E1000_WRITE_REG(hw, E1000_PCS_LCTL, pcs_lctl);

	/* Set the Copper/Fiber Switch Control - CONNSW register */
	connsw = E1000_READ_REG(hw, E1000_CONNSW);
	connsw &= ~E1000_CONNSW_ENRGSRC;
	E1000_WRITE_REG(hw, E1000_CONNSW, connsw);
}

#pragma inline(igb_intr_rx_work)
/*
 * igb_intr_rx_work - rx processing of ISR
 */
static void
igb_intr_rx_work(igb_rx_ring_t *rx_ring)
{
	mblk_t *mp;

	mutex_enter(&rx_ring->rx_lock);
	mp = igb_rx(rx_ring, IGB_NO_POLL);
	mutex_exit(&rx_ring->rx_lock);

	if (mp != NULL)
		mac_rx_ring(rx_ring->igb->mac_hdl, rx_ring->ring_handle, mp,
		    rx_ring->ring_gen_num);
}

#pragma inline(igb_intr_tx_work)
/*
 * igb_intr_tx_work - tx processing of ISR
 */
static void
igb_intr_tx_work(igb_tx_ring_t *tx_ring)
{
	igb_t *igb = tx_ring->igb;

	/* Recycle the tx descriptors */
	tx_ring->tx_recycle(tx_ring);

	/* Schedule the re-transmit */
	if (tx_ring->reschedule &&
	    (tx_ring->tbd_free >= igb->tx_resched_thresh)) {
		tx_ring->reschedule = B_FALSE;
		mac_tx_ring_update(tx_ring->igb->mac_hdl, tx_ring->ring_handle);
		IGB_DEBUG_STAT(tx_ring->stat_reschedule);
	}
}

#pragma inline(igb_intr_link_work)
/*
 * igb_intr_link_work - link-status-change processing of ISR
 */
static void
igb_intr_link_work(igb_t *igb)
{
	boolean_t link_changed;

	igb_stop_watchdog_timer(igb);

	mutex_enter(&igb->gen_lock);

	/*
	 * Because we got a link-status-change interrupt, force
	 * e1000_check_for_link() to look at phy
	 */
	igb->hw.mac.get_link_status = B_TRUE;

	/* igb_link_check takes care of link status change */
	link_changed = igb_link_check(igb);

	/* Get new phy state */
	igb_get_phy_state(igb);

	mutex_exit(&igb->gen_lock);

	if (link_changed)
		mac_link_update(igb->mac_hdl, igb->link_state);

	igb_start_watchdog_timer(igb);
}

/*
 * igb_intr_legacy - Interrupt handler for legacy interrupts
 */
static uint_t
igb_intr_legacy(void *arg1, void *arg2)
{
	igb_t *igb = (igb_t *)arg1;
	igb_tx_ring_t *tx_ring;
	uint32_t icr;
	mblk_t *mp;
	boolean_t tx_reschedule;
	boolean_t link_changed;
	uint_t result;

	_NOTE(ARGUNUSED(arg2));

	mutex_enter(&igb->gen_lock);

	if (igb->igb_state & IGB_SUSPENDED) {
		mutex_exit(&igb->gen_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	mp = NULL;
	tx_reschedule = B_FALSE;
	link_changed = B_FALSE;
	icr = E1000_READ_REG(&igb->hw, E1000_ICR);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		mutex_exit(&igb->gen_lock);
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&igb->igb_state, IGB_ERROR);
		return (DDI_INTR_UNCLAIMED);
	}

	if (icr & E1000_ICR_INT_ASSERTED) {
		/*
		 * E1000_ICR_INT_ASSERTED bit was set:
		 * Read(Clear) the ICR, claim this interrupt,
		 * look for work to do.
		 */
		ASSERT(igb->num_rx_rings == 1);
		ASSERT(igb->num_tx_rings == 1);

		/* Make sure all interrupt causes cleared */
		(void) E1000_READ_REG(&igb->hw, E1000_EICR);

		if (icr & E1000_ICR_RXT0) {
			mp = igb_rx(&igb->rx_rings[0], IGB_NO_POLL);
		}

		if (icr & E1000_ICR_TXDW) {
			tx_ring = &igb->tx_rings[0];

			/* Recycle the tx descriptors */
			tx_ring->tx_recycle(tx_ring);

			/* Schedule the re-transmit */
			tx_reschedule = (tx_ring->reschedule &&
			    (tx_ring->tbd_free >= igb->tx_resched_thresh));
		}

		if (icr & E1000_ICR_LSC) {
			/*
			 * Because we got a link-status-change interrupt, force
			 * e1000_check_for_link() to look at phy
			 */
			igb->hw.mac.get_link_status = B_TRUE;

			/* igb_link_check takes care of link status change */
			link_changed = igb_link_check(igb);

			/* Get new phy state */
			igb_get_phy_state(igb);
		}

		if (icr & E1000_ICR_DRSTA) {
			/* 82580 Full Device Reset needed */
			atomic_or_32(&igb->igb_state, IGB_STALL);
		}

		result = DDI_INTR_CLAIMED;
	} else {
		/*
		 * E1000_ICR_INT_ASSERTED bit was not set:
		 * Don't claim this interrupt.
		 */
		result = DDI_INTR_UNCLAIMED;
	}

	mutex_exit(&igb->gen_lock);

	/*
	 * Do the following work outside of the gen_lock
	 */
	if (mp != NULL)
		mac_rx(igb->mac_hdl, NULL, mp);

	if (tx_reschedule)  {
		tx_ring->reschedule = B_FALSE;
		mac_tx_ring_update(igb->mac_hdl, tx_ring->ring_handle);
		IGB_DEBUG_STAT(tx_ring->stat_reschedule);
	}

	if (link_changed)
		mac_link_update(igb->mac_hdl, igb->link_state);

	return (result);
}

/*
 * igb_intr_msi - Interrupt handler for MSI
 */
static uint_t
igb_intr_msi(void *arg1, void *arg2)
{
	igb_t *igb = (igb_t *)arg1;
	uint32_t icr;

	_NOTE(ARGUNUSED(arg2));

	icr = E1000_READ_REG(&igb->hw, E1000_ICR);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&igb->igb_state, IGB_ERROR);
		return (DDI_INTR_CLAIMED);
	}

	/* Make sure all interrupt causes cleared */
	(void) E1000_READ_REG(&igb->hw, E1000_EICR);

	/*
	 * For MSI interrupt, we have only one vector,
	 * so we have only one rx ring and one tx ring enabled.
	 */
	ASSERT(igb->num_rx_rings == 1);
	ASSERT(igb->num_tx_rings == 1);

	if (icr & E1000_ICR_RXT0) {
		igb_intr_rx_work(&igb->rx_rings[0]);
	}

	if (icr & E1000_ICR_TXDW) {
		igb_intr_tx_work(&igb->tx_rings[0]);
	}

	if (icr & E1000_ICR_LSC) {
		igb_intr_link_work(igb);
	}

	if (icr & E1000_ICR_DRSTA) {
		/* 82580 Full Device Reset needed */
		atomic_or_32(&igb->igb_state, IGB_STALL);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * igb_intr_rx - Interrupt handler for rx
 */
static uint_t
igb_intr_rx(void *arg1, void *arg2)
{
	igb_rx_ring_t *rx_ring = (igb_rx_ring_t *)arg1;

	_NOTE(ARGUNUSED(arg2));

	/*
	 * Only used via MSI-X vector so don't check cause bits
	 * and only clean the given ring.
	 */
	igb_intr_rx_work(rx_ring);

	return (DDI_INTR_CLAIMED);
}

/*
 * igb_intr_tx - Interrupt handler for tx
 */
static uint_t
igb_intr_tx(void *arg1, void *arg2)
{
	igb_tx_ring_t *tx_ring = (igb_tx_ring_t *)arg1;

	_NOTE(ARGUNUSED(arg2));

	/*
	 * Only used via MSI-X vector so don't check cause bits
	 * and only clean the given ring.
	 */
	igb_intr_tx_work(tx_ring);

	return (DDI_INTR_CLAIMED);
}

/*
 * igb_intr_tx_other - Interrupt handler for both tx and other
 *
 */
static uint_t
igb_intr_tx_other(void *arg1, void *arg2)
{
	igb_t *igb = (igb_t *)arg1;
	uint32_t icr;

	_NOTE(ARGUNUSED(arg2));

	icr = E1000_READ_REG(&igb->hw, E1000_ICR);

	if (igb_check_acc_handle(igb->osdep.reg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(igb->dip, DDI_SERVICE_DEGRADED);
		atomic_or_32(&igb->igb_state, IGB_ERROR);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Look for tx reclaiming work first. Remember, in the
	 * case of only interrupt sharing, only one tx ring is
	 * used
	 */
	igb_intr_tx_work(&igb->tx_rings[0]);

	/*
	 * Check for "other" causes.
	 */
	if (icr & E1000_ICR_LSC) {
		igb_intr_link_work(igb);
	}

	/*
	 * The DOUTSYNC bit indicates a tx packet dropped because
	 * DMA engine gets "out of sync". There isn't a real fix
	 * for this. The Intel recommendation is to count the number
	 * of occurrences so user can detect when it is happening.
	 * The issue is non-fatal and there's no recovery action
	 * available.
	 */
	if (icr & E1000_ICR_DOUTSYNC) {
		IGB_STAT(igb->dout_sync);
	}

	if (icr & E1000_ICR_DRSTA) {
		/* 82580 Full Device Reset needed */
		atomic_or_32(&igb->igb_state, IGB_STALL);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * igb_alloc_intrs - Allocate interrupts for the driver
 *
 * Normal sequence is to try MSI-X; if not sucessful, try MSI;
 * if not successful, try Legacy.
 * igb->intr_force can be used to force sequence to start with
 * any of the 3 types.
 * If MSI-X is not used, number of tx/rx rings is forced to 1.
 */
static int
igb_alloc_intrs(igb_t *igb)
{
	dev_info_t *devinfo;
	int intr_types;
	int rc;

	devinfo = igb->dip;

	/* Get supported interrupt types */
	rc = ddi_intr_get_supported_types(devinfo, &intr_types);

	if (rc != DDI_SUCCESS) {
		igb_log(igb,
		    "Get supported interrupt types failed: %d", rc);
		return (IGB_FAILURE);
	}
	IGB_DEBUGLOG_1(igb, "Supported interrupt types: %x", intr_types);

	igb->intr_type = 0;

	/* Install MSI-X interrupts */
	if ((intr_types & DDI_INTR_TYPE_MSIX) &&
	    (igb->intr_force <= IGB_INTR_MSIX)) {
		rc = igb_alloc_intr_handles(igb, DDI_INTR_TYPE_MSIX);

		if (rc == IGB_SUCCESS)
			return (IGB_SUCCESS);

		igb_log(igb,
		    "Allocate MSI-X failed, trying MSI interrupts...");
	}

	/* MSI-X not used, force rings to 1 */
	igb->num_rx_rings = 1;
	igb->num_tx_rings = 1;
	igb_log(igb,
	    "MSI-X not used, force rx and tx queue number to 1");

	/* Install MSI interrupts */
	if ((intr_types & DDI_INTR_TYPE_MSI) &&
	    (igb->intr_force <= IGB_INTR_MSI)) {
		rc = igb_alloc_intr_handles(igb, DDI_INTR_TYPE_MSI);

		if (rc == IGB_SUCCESS)
			return (IGB_SUCCESS);

		igb_log(igb,
		    "Allocate MSI failed, trying Legacy interrupts...");
	}

	/* Install legacy interrupts */
	if (intr_types & DDI_INTR_TYPE_FIXED) {
		rc = igb_alloc_intr_handles(igb, DDI_INTR_TYPE_FIXED);

		if (rc == IGB_SUCCESS)
			return (IGB_SUCCESS);

		igb_log(igb,
		    "Allocate Legacy interrupts failed");
	}

	/* If none of the 3 types succeeded, return failure */
	return (IGB_FAILURE);
}

/*
 * igb_alloc_intr_handles - Allocate interrupt handles.
 *
 * For legacy and MSI, only 1 handle is needed.  For MSI-X,
 * if fewer than 2 handles are available, return failure.
 * Upon success, this sets the number of Rx rings to a number that
 * matches the handles available for Rx interrupts.
 */
static int
igb_alloc_intr_handles(igb_t *igb, int intr_type)
{
	dev_info_t *devinfo;
	int orig, request, count, avail, actual;
	int diff, minimum;
	int rc;

	devinfo = igb->dip;

	switch (intr_type) {
	case DDI_INTR_TYPE_FIXED:
		request = 1;	/* Request 1 legacy interrupt handle */
		minimum = 1;
		IGB_DEBUGLOG_0(igb, "interrupt type: legacy");
		break;

	case DDI_INTR_TYPE_MSI:
		request = 1;	/* Request 1 MSI interrupt handle */
		minimum = 1;
		IGB_DEBUGLOG_0(igb, "interrupt type: MSI");
		break;

	case DDI_INTR_TYPE_MSIX:
		/*
		 * Number of vectors for the adapter is
		 * # rx rings + # tx rings
		 * One of tx vectors is for tx & other
		 */
		request = igb->num_rx_rings + igb->num_tx_rings;
		orig = request;
		minimum = 2;
		IGB_DEBUGLOG_0(igb, "interrupt type: MSI-X");
		break;

	default:
		igb_log(igb,
		    "invalid call to igb_alloc_intr_handles(): %d\n",
		    intr_type);
		return (IGB_FAILURE);
	}
	IGB_DEBUGLOG_2(igb, "interrupt handles requested: %d  minimum: %d",
	    request, minimum);

	/*
	 * Get number of supported interrupts
	 */
	rc = ddi_intr_get_nintrs(devinfo, intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count < minimum)) {
		igb_log(igb,
		    "Get supported interrupt number failed. "
		    "Return: %d, count: %d", rc, count);
		return (IGB_FAILURE);
	}
	IGB_DEBUGLOG_1(igb, "interrupts supported: %d", count);

	/*
	 * Get number of available interrupts
	 */
	rc = ddi_intr_get_navail(devinfo, intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail < minimum)) {
		igb_log(igb,
		    "Get available interrupt number failed. "
		    "Return: %d, available: %d", rc, avail);
		return (IGB_FAILURE);
	}
	IGB_DEBUGLOG_1(igb, "interrupts available: %d", avail);

	if (avail < request) {
		igb_log(igb, "Request %d handles, %d available",
		    request, avail);
		request = avail;
	}

	actual = 0;
	igb->intr_cnt = 0;

	/*
	 * Allocate an array of interrupt handles
	 */
	igb->intr_size = request * sizeof (ddi_intr_handle_t);
	igb->htable = kmem_alloc(igb->intr_size, KM_SLEEP);

	rc = ddi_intr_alloc(devinfo, igb->htable, intr_type, 0,
	    request, &actual, DDI_INTR_ALLOC_NORMAL);
	if (rc != DDI_SUCCESS) {
		igb_log(igb, "Allocate interrupts failed. "
		    "return: %d, request: %d, actual: %d",
		    rc, request, actual);
		goto alloc_handle_fail;
	}
	IGB_DEBUGLOG_1(igb, "interrupts actually allocated: %d", actual);

	igb->intr_cnt = actual;

	if (actual < minimum) {
		igb_log(igb, "Insufficient interrupt handles allocated: %d",
		    actual);
		goto alloc_handle_fail;
	}

	/*
	 * For MSI-X, actual might force us to reduce number of tx & rx rings
	 */
	if ((intr_type == DDI_INTR_TYPE_MSIX) && (orig > actual)) {
		diff = orig - actual;
		if (diff < igb->num_tx_rings) {
			igb_log(igb,
			    "MSI-X vectors force Tx queue number to %d",
			    igb->num_tx_rings - diff);
			igb->num_tx_rings -= diff;
		} else {
			igb_log(igb,
			    "MSI-X vectors force Tx queue number to 1");
			igb->num_tx_rings = 1;

			igb_log(igb,
			    "MSI-X vectors force Rx queue number to %d",
			    actual - 1);
			igb->num_rx_rings = actual - 1;
		}
	}

	/*
	 * Get priority for first vector, assume remaining are all the same
	 */
	rc = ddi_intr_get_pri(igb->htable[0], &igb->intr_pri);
	if (rc != DDI_SUCCESS) {
		igb_log(igb,
		    "Get interrupt priority failed: %d", rc);
		goto alloc_handle_fail;
	}

	rc = ddi_intr_get_cap(igb->htable[0], &igb->intr_cap);
	if (rc != DDI_SUCCESS) {
		igb_log(igb,
		    "Get interrupt cap failed: %d", rc);
		goto alloc_handle_fail;
	}

	igb->intr_type = intr_type;

	return (IGB_SUCCESS);

alloc_handle_fail:
	igb_rem_intrs(igb);

	return (IGB_FAILURE);
}

/*
 * igb_add_intr_handlers - Add interrupt handlers based on the interrupt type
 *
 * Before adding the interrupt handlers, the interrupt vectors have
 * been allocated, and the rx/tx rings have also been allocated.
 */
static int
igb_add_intr_handlers(igb_t *igb)
{
	igb_rx_ring_t *rx_ring;
	igb_tx_ring_t *tx_ring;
	int vector;
	int rc;
	int i;

	vector = 0;

	switch (igb->intr_type) {
	case DDI_INTR_TYPE_MSIX:
		/* Add interrupt handler for tx + other */
		tx_ring = &igb->tx_rings[0];
		rc = ddi_intr_add_handler(igb->htable[vector],
		    (ddi_intr_handler_t *)igb_intr_tx_other,
		    (void *)igb, NULL);

		if (rc != DDI_SUCCESS) {
			igb_log(igb,
			    "Add tx/other interrupt handler failed: %d", rc);
			return (IGB_FAILURE);
		}
		tx_ring->intr_vector = vector;
		vector++;

		/* Add interrupt handler for each rx ring */
		for (i = 0; i < igb->num_rx_rings; i++) {
			rx_ring = &igb->rx_rings[i];

			rc = ddi_intr_add_handler(igb->htable[vector],
			    (ddi_intr_handler_t *)igb_intr_rx,
			    (void *)rx_ring, NULL);

			if (rc != DDI_SUCCESS) {
				igb_log(igb,
				    "Add rx interrupt handler failed. "
				    "return: %d, rx ring: %d", rc, i);
				for (vector--; vector >= 0; vector--) {
					(void) ddi_intr_remove_handler(
					    igb->htable[vector]);
				}
				return (IGB_FAILURE);
			}

			rx_ring->intr_vector = vector;

			vector++;
		}

		/* Add interrupt handler for each tx ring from 2nd ring */
		for (i = 1; i < igb->num_tx_rings; i++) {
			tx_ring = &igb->tx_rings[i];

			rc = ddi_intr_add_handler(igb->htable[vector],
			    (ddi_intr_handler_t *)igb_intr_tx,
			    (void *)tx_ring, NULL);

			if (rc != DDI_SUCCESS) {
				igb_log(igb,
				    "Add tx interrupt handler failed. "
				    "return: %d, tx ring: %d", rc, i);
				for (vector--; vector >= 0; vector--) {
					(void) ddi_intr_remove_handler(
					    igb->htable[vector]);
				}
				return (IGB_FAILURE);
			}

			tx_ring->intr_vector = vector;

			vector++;
		}

		break;

	case DDI_INTR_TYPE_MSI:
		/* Add interrupt handlers for the only vector */
		rc = ddi_intr_add_handler(igb->htable[vector],
		    (ddi_intr_handler_t *)igb_intr_msi,
		    (void *)igb, NULL);

		if (rc != DDI_SUCCESS) {
			igb_log(igb,
			    "Add MSI interrupt handler failed: %d", rc);
			return (IGB_FAILURE);
		}

		rx_ring = &igb->rx_rings[0];
		rx_ring->intr_vector = vector;

		vector++;
		break;

	case DDI_INTR_TYPE_FIXED:
		/* Add interrupt handlers for the only vector */
		rc = ddi_intr_add_handler(igb->htable[vector],
		    (ddi_intr_handler_t *)igb_intr_legacy,
		    (void *)igb, NULL);

		if (rc != DDI_SUCCESS) {
			igb_log(igb,
			    "Add legacy interrupt handler failed: %d", rc);
			return (IGB_FAILURE);
		}

		rx_ring = &igb->rx_rings[0];
		rx_ring->intr_vector = vector;

		vector++;
		break;

	default:
		return (IGB_FAILURE);
	}

	ASSERT(vector == igb->intr_cnt);

	return (IGB_SUCCESS);
}

/*
 * igb_setup_msix_82575 - setup 82575 adapter to use MSI-X interrupts
 *
 * For each vector enabled on the adapter, Set the MSIXBM register accordingly
 */
static void
igb_setup_msix_82575(igb_t *igb)
{
	uint32_t eims = 0;
	int i, vector;
	struct e1000_hw *hw = &igb->hw;

	/*
	 * Set vector for tx ring 0 and other causes.
	 * NOTE assumption that it is vector 0.
	 */
	vector = 0;

	igb->eims_mask = E1000_EICR_TX_QUEUE0 | E1000_EICR_OTHER;
	E1000_WRITE_REG(hw, E1000_MSIXBM(vector), igb->eims_mask);
	vector++;

	for (i = 0; i < igb->num_rx_rings; i++) {
		/*
		 * Set vector for each rx ring
		 */
		eims = (E1000_EICR_RX_QUEUE0 << i);
		E1000_WRITE_REG(hw, E1000_MSIXBM(vector), eims);

		/*
		 * Accumulate bits to enable in
		 * igb_enable_adapter_interrupts_82575()
		 */
		igb->eims_mask |= eims;

		vector++;
	}

	for (i = 1; i < igb->num_tx_rings; i++) {
		/*
		 * Set vector for each tx ring from 2nd tx ring
		 */
		eims = (E1000_EICR_TX_QUEUE0 << i);
		E1000_WRITE_REG(hw, E1000_MSIXBM(vector), eims);

		/*
		 * Accumulate bits to enable in
		 * igb_enable_adapter_interrupts_82575()
		 */
		igb->eims_mask |= eims;

		vector++;
	}

	ASSERT(vector == igb->intr_cnt);

	/*
	 * Disable IAM for ICR interrupt bits
	 */
	E1000_WRITE_REG(hw, E1000_IAM, 0);
	E1000_WRITE_FLUSH(hw);
}

/*
 * igb_setup_msix_82576 - setup 82576 adapter to use MSI-X interrupts
 *
 * 82576 uses a table based method for assigning vectors.  Each queue has a
 * single entry in the table to which we write a vector number along with a
 * "valid" bit.  The entry is a single byte in a 4-byte register.  Vectors
 * take a different position in the 4-byte register depending on whether
 * they are numbered above or below 8.
 */
static void
igb_setup_msix_82576(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t ivar, index, vector;
	int i;

	/* must enable msi-x capability before IVAR settings */
	E1000_WRITE_REG(hw, E1000_GPIE,
	    (E1000_GPIE_MSIX_MODE | E1000_GPIE_PBA | E1000_GPIE_NSICR));

	/*
	 * Set vector for tx ring 0 and other causes.
	 * NOTE assumption that it is vector 0.
	 * This is also interdependent with installation of interrupt service
	 * routines in igb_add_intr_handlers().
	 */

	/* assign "other" causes to vector 0 */
	vector = 0;
	ivar = ((vector | E1000_IVAR_VALID) << 8);
	E1000_WRITE_REG(hw, E1000_IVAR_MISC, ivar);

	/* assign tx ring 0 to vector 0 */
	ivar = ((vector | E1000_IVAR_VALID) << 8);
	E1000_WRITE_REG(hw, E1000_IVAR0, ivar);

	/* prepare to enable tx & other interrupt causes */
	igb->eims_mask = (1 << vector);

	vector ++;
	for (i = 0; i < igb->num_rx_rings; i++) {
		/*
		 * Set vector for each rx ring
		 */
		index = (i & 0x7);
		ivar = E1000_READ_REG_ARRAY(hw, E1000_IVAR0, index);

		if (i < 8) {
			/* vector goes into low byte of register */
			ivar = ivar & 0xFFFFFF00;
			ivar |= (vector | E1000_IVAR_VALID);
		} else {
			/* vector goes into third byte of register */
			ivar = ivar & 0xFF00FFFF;
			ivar |= ((vector | E1000_IVAR_VALID) << 16);
		}
		E1000_WRITE_REG_ARRAY(hw, E1000_IVAR0, index, ivar);

		/* Accumulate interrupt-cause bits to enable */
		igb->eims_mask |= (1 << vector);

		vector ++;
	}

	for (i = 1; i < igb->num_tx_rings; i++) {
		/*
		 * Set vector for each tx ring from 2nd tx ring.
		 * Note assumption that tx vectors numericall follow rx vectors.
		 */
		index = (i & 0x7);
		ivar = E1000_READ_REG_ARRAY(hw, E1000_IVAR0, index);

		if (i < 8) {
			/* vector goes into second byte of register */
			ivar = ivar & 0xFFFF00FF;
			ivar |= ((vector | E1000_IVAR_VALID) << 8);
		} else {
			/* vector goes into fourth byte of register */
			ivar = ivar & 0x00FFFFFF;
			ivar |= (vector | E1000_IVAR_VALID) << 24;
		}
		E1000_WRITE_REG_ARRAY(hw, E1000_IVAR0, index, ivar);

		/* Accumulate interrupt-cause bits to enable */
		igb->eims_mask |= (1 << vector);

		vector ++;
	}

	ASSERT(vector == igb->intr_cnt);
}

/*
 * igb_setup_msix_82580 - setup 82580 adapter to use MSI-X interrupts
 *
 * 82580 uses same table approach at 82576 but has fewer entries.  Each
 * queue has a single entry in the table to which we write a vector number
 * along with a "valid" bit.  Vectors take a different position in the
 * register depending on * whether * they are numbered above or below 4.
 */
static void
igb_setup_msix_82580(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint32_t ivar, index, vector;
	int i;

	/* must enable msi-x capability before IVAR settings */
	E1000_WRITE_REG(hw, E1000_GPIE, (E1000_GPIE_MSIX_MODE |
	    E1000_GPIE_PBA | E1000_GPIE_NSICR | E1000_GPIE_EIAME));
	/*
	 * Set vector for tx ring 0 and other causes.
	 * NOTE assumption that it is vector 0.
	 * This is also interdependent with installation of interrupt service
	 * routines in igb_add_intr_handlers().
	 */

	/* assign "other" causes to vector 0 */
	vector = 0;
	ivar = ((vector | E1000_IVAR_VALID) << 8);
	E1000_WRITE_REG(hw, E1000_IVAR_MISC, ivar);

	/* assign tx ring 0 to vector 0 */
	ivar = ((vector | E1000_IVAR_VALID) << 8);
	E1000_WRITE_REG(hw, E1000_IVAR0, ivar);

	/* prepare to enable tx & other interrupt causes */
	igb->eims_mask = (1 << vector);

	vector ++;

	for (i = 0; i < igb->num_rx_rings; i++) {
		/*
		 * Set vector for each rx ring
		 */
		index = (i >> 1);
		ivar = E1000_READ_REG_ARRAY(hw, E1000_IVAR0, index);

		if (i & 1) {
			/* vector goes into third byte of register */
			ivar = ivar & 0xFF00FFFF;
			ivar |= ((vector | E1000_IVAR_VALID) << 16);
		} else {
			/* vector goes into low byte of register */
			ivar = ivar & 0xFFFFFF00;
			ivar |= (vector | E1000_IVAR_VALID);
		}
		E1000_WRITE_REG_ARRAY(hw, E1000_IVAR0, index, ivar);

		/* Accumulate interrupt-cause bits to enable */
		igb->eims_mask |= (1 << vector);

		vector ++;
	}

	for (i = 1; i < igb->num_tx_rings; i++) {
		/*
		 * Set vector for each tx ring from 2nd tx ring.
		 * Note assumption that tx vectors numericall follow rx vectors.
		 */
		index = (i >> 1);
		ivar = E1000_READ_REG_ARRAY(hw, E1000_IVAR0, index);

		if (i & 1) {
			/* vector goes into high byte of register */
			ivar = ivar & 0x00FFFFFF;
			ivar |= ((vector | E1000_IVAR_VALID) << 24);
		} else {
			/* vector goes into second byte of register */
			ivar = ivar & 0xFFFF00FF;
			ivar |= (vector | E1000_IVAR_VALID) << 8;
		}
		E1000_WRITE_REG_ARRAY(hw, E1000_IVAR0, index, ivar);

		/* Accumulate interrupt-cause bits to enable */
		igb->eims_mask |= (1 << vector);

		vector ++;
	}
	ASSERT(vector == igb->intr_cnt);
}

/*
 * igb_rem_intr_handlers - remove the interrupt handlers
 */
static void
igb_rem_intr_handlers(igb_t *igb)
{
	int i;
	int rc;

	for (i = 0; i < igb->intr_cnt; i++) {
		rc = ddi_intr_remove_handler(igb->htable[i]);
		if (rc != DDI_SUCCESS) {
			IGB_DEBUGLOG_1(igb,
			    "Remove intr handler failed: %d", rc);
		}
	}
}

/*
 * igb_rem_intrs - remove the allocated interrupts
 */
static void
igb_rem_intrs(igb_t *igb)
{
	int i;
	int rc;

	for (i = 0; i < igb->intr_cnt; i++) {
		rc = ddi_intr_free(igb->htable[i]);
		if (rc != DDI_SUCCESS) {
			IGB_DEBUGLOG_1(igb,
			    "Free intr failed: %d", rc);
		}
	}

	kmem_free(igb->htable, igb->intr_size);
	igb->htable = NULL;
}

/*
 * igb_enable_intrs - enable all the ddi interrupts
 */
static int
igb_enable_intrs(igb_t *igb)
{
	int i;
	int rc;

	/* Enable interrupts */
	if (igb->intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI */
		rc = ddi_intr_block_enable(igb->htable, igb->intr_cnt);
		if (rc != DDI_SUCCESS) {
			igb_log(igb,
			    "Enable block intr failed: %d", rc);
			return (IGB_FAILURE);
		}
	} else {
		/* Call ddi_intr_enable() for Legacy/MSI non block enable */
		for (i = 0; i < igb->intr_cnt; i++) {
			rc = ddi_intr_enable(igb->htable[i]);
			if (rc != DDI_SUCCESS) {
				igb_log(igb,
				    "Enable intr failed: %d", rc);
				return (IGB_FAILURE);
			}
		}
	}

	return (IGB_SUCCESS);
}

/*
 * igb_disable_intrs - disable all the ddi interrupts
 */
static int
igb_disable_intrs(igb_t *igb)
{
	int i;
	int rc;

	/* Disable all interrupts */
	if (igb->intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_disable(igb->htable, igb->intr_cnt);
		if (rc != DDI_SUCCESS) {
			igb_log(igb,
			    "Disable block intr failed: %d", rc);
			return (IGB_FAILURE);
		}
	} else {
		for (i = 0; i < igb->intr_cnt; i++) {
			rc = ddi_intr_disable(igb->htable[i]);
			if (rc != DDI_SUCCESS) {
				igb_log(igb,
				    "Disable intr failed: %d", rc);
				return (IGB_FAILURE);
			}
		}
	}

	return (IGB_SUCCESS);
}

/*
 * igb_get_phy_state - Get and save the parameters read from PHY registers
 */
static void
igb_get_phy_state(igb_t *igb)
{
	struct e1000_hw *hw = &igb->hw;
	uint16_t phy_ctrl;
	uint16_t phy_status;
	uint16_t phy_an_adv;
	uint16_t phy_an_exp;
	uint16_t phy_ext_status;
	uint16_t phy_1000t_ctrl;
	uint16_t phy_1000t_status;
	uint16_t phy_lp_able;

	ASSERT(mutex_owned(&igb->gen_lock));

	if (hw->phy.media_type == e1000_media_type_copper) {
		(void) e1000_read_phy_reg(hw, PHY_CONTROL, &phy_ctrl);
		(void) e1000_read_phy_reg(hw, PHY_STATUS, &phy_status);
		(void) e1000_read_phy_reg(hw, PHY_AUTONEG_ADV, &phy_an_adv);
		(void) e1000_read_phy_reg(hw, PHY_AUTONEG_EXP, &phy_an_exp);
		(void) e1000_read_phy_reg(hw, PHY_EXT_STATUS, &phy_ext_status);
		(void) e1000_read_phy_reg(hw, PHY_1000T_CTRL, &phy_1000t_ctrl);
		(void) e1000_read_phy_reg(hw,
		    PHY_1000T_STATUS, &phy_1000t_status);
		(void) e1000_read_phy_reg(hw, PHY_LP_ABILITY, &phy_lp_able);

		igb->param_autoneg_cap =
		    (phy_status & MII_SR_AUTONEG_CAPS) ? 1 : 0;
		igb->param_pause_cap =
		    (phy_an_adv & NWAY_AR_PAUSE) ? 1 : 0;
		igb->param_asym_pause_cap =
		    (phy_an_adv & NWAY_AR_ASM_DIR) ? 1 : 0;
		igb->param_1000fdx_cap =
		    ((phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (phy_ext_status & IEEE_ESR_1000X_FD_CAPS)) ? 1 : 0;
		igb->param_1000hdx_cap =
		    ((phy_ext_status & IEEE_ESR_1000T_HD_CAPS) ||
		    (phy_ext_status & IEEE_ESR_1000X_HD_CAPS)) ? 1 : 0;
		igb->param_100t4_cap =
		    (phy_status & MII_SR_100T4_CAPS) ? 1 : 0;
		igb->param_100fdx_cap = ((phy_status & MII_SR_100X_FD_CAPS) ||
		    (phy_status & MII_SR_100T2_FD_CAPS)) ? 1 : 0;
		igb->param_100hdx_cap = ((phy_status & MII_SR_100X_HD_CAPS) ||
		    (phy_status & MII_SR_100T2_HD_CAPS)) ? 1 : 0;
		igb->param_10fdx_cap =
		    (phy_status & MII_SR_10T_FD_CAPS) ? 1 : 0;
		igb->param_10hdx_cap =
		    (phy_status & MII_SR_10T_HD_CAPS) ? 1 : 0;
		igb->param_rem_fault =
		    (phy_status & MII_SR_REMOTE_FAULT) ? 1 : 0;

		igb->param_adv_autoneg_cap = hw->mac.autoneg;
		igb->param_adv_pause_cap =
		    (phy_an_adv & NWAY_AR_PAUSE) ? 1 : 0;
		igb->param_adv_asym_pause_cap =
		    (phy_an_adv & NWAY_AR_ASM_DIR) ? 1 : 0;
		igb->param_adv_1000hdx_cap =
		    (phy_1000t_ctrl & CR_1000T_HD_CAPS) ? 1 : 0;
		igb->param_adv_100t4_cap =
		    (phy_an_adv & NWAY_AR_100T4_CAPS) ? 1 : 0;
		igb->param_adv_rem_fault =
		    (phy_an_adv & NWAY_AR_REMOTE_FAULT) ? 1 : 0;
		if (igb->param_adv_autoneg_cap == 1) {
			igb->param_adv_1000fdx_cap =
			    (phy_1000t_ctrl & CR_1000T_FD_CAPS) ? 1 : 0;
			igb->param_adv_100fdx_cap =
			    (phy_an_adv & NWAY_AR_100TX_FD_CAPS) ? 1 : 0;
			igb->param_adv_100hdx_cap =
			    (phy_an_adv & NWAY_AR_100TX_HD_CAPS) ? 1 : 0;
			igb->param_adv_10fdx_cap =
			    (phy_an_adv & NWAY_AR_10T_FD_CAPS) ? 1 : 0;
			igb->param_adv_10hdx_cap =
			    (phy_an_adv & NWAY_AR_10T_HD_CAPS) ? 1 : 0;
		}

		igb->param_lp_autoneg_cap =
		    (phy_an_exp & NWAY_ER_LP_NWAY_CAPS) ? 1 : 0;
		igb->param_lp_pause_cap =
		    (phy_lp_able & NWAY_LPAR_PAUSE) ? 1 : 0;
		igb->param_lp_asym_pause_cap =
		    (phy_lp_able & NWAY_LPAR_ASM_DIR) ? 1 : 0;
		igb->param_lp_1000fdx_cap =
		    (phy_1000t_status & SR_1000T_LP_FD_CAPS) ? 1 : 0;
		igb->param_lp_1000hdx_cap =
		    (phy_1000t_status & SR_1000T_LP_HD_CAPS) ? 1 : 0;
		igb->param_lp_100t4_cap =
		    (phy_lp_able & NWAY_LPAR_100T4_CAPS) ? 1 : 0;
		igb->param_lp_100fdx_cap =
		    (phy_lp_able & NWAY_LPAR_100TX_FD_CAPS) ? 1 : 0;
		igb->param_lp_100hdx_cap =
		    (phy_lp_able & NWAY_LPAR_100TX_HD_CAPS) ? 1 : 0;
		igb->param_lp_10fdx_cap =
		    (phy_lp_able & NWAY_LPAR_10T_FD_CAPS) ? 1 : 0;
		igb->param_lp_10hdx_cap =
		    (phy_lp_able & NWAY_LPAR_10T_HD_CAPS) ? 1 : 0;
		igb->param_lp_rem_fault =
		    (phy_lp_able & NWAY_LPAR_REMOTE_FAULT) ? 1 : 0;
	} else {
		/*
		 * 1Gig Fiber adapter only offers 1Gig Full Duplex.
		 */
		igb->param_autoneg_cap = 0;
		igb->param_pause_cap = 1;
		igb->param_asym_pause_cap = 1;
		igb->param_1000fdx_cap = 1;
		igb->param_1000hdx_cap = 0;
		igb->param_100t4_cap = 0;
		igb->param_100fdx_cap = 0;
		igb->param_100hdx_cap = 0;
		igb->param_10fdx_cap = 0;
		igb->param_10hdx_cap = 0;

		igb->param_adv_autoneg_cap = 0;
		igb->param_adv_pause_cap = 1;
		igb->param_adv_asym_pause_cap = 1;
		igb->param_adv_1000fdx_cap = 1;
		igb->param_adv_1000hdx_cap = 0;
		igb->param_adv_100t4_cap = 0;
		igb->param_adv_100fdx_cap = 0;
		igb->param_adv_100hdx_cap = 0;
		igb->param_adv_10fdx_cap = 0;
		igb->param_adv_10hdx_cap = 0;

		igb->param_lp_autoneg_cap = 0;
		igb->param_lp_pause_cap = 0;
		igb->param_lp_asym_pause_cap = 0;
		igb->param_lp_1000fdx_cap = 0;
		igb->param_lp_1000hdx_cap = 0;
		igb->param_lp_100t4_cap = 0;
		igb->param_lp_100fdx_cap = 0;
		igb->param_lp_100hdx_cap = 0;
		igb->param_lp_10fdx_cap = 0;
		igb->param_lp_10hdx_cap = 0;
		igb->param_lp_rem_fault = 0;
	}
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
igb_param_sync(igb_t *igb)
{
	igb->param_en_1000fdx_cap = igb->param_adv_1000fdx_cap;
	igb->param_en_1000hdx_cap = igb->param_adv_1000hdx_cap;
	igb->param_en_100t4_cap = igb->param_adv_100t4_cap;
	igb->param_en_100fdx_cap = igb->param_adv_100fdx_cap;
	igb->param_en_100hdx_cap = igb->param_adv_100hdx_cap;
	igb->param_en_10fdx_cap = igb->param_adv_10fdx_cap;
	igb->param_en_10hdx_cap = igb->param_adv_10hdx_cap;
}

/*
 * igb_get_driver_control
 */
static void
igb_get_driver_control(struct e1000_hw *hw)
{
	uint32_t ctrl_ext;

	/* Notify firmware that driver is in control of device */
	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
	ctrl_ext |= E1000_CTRL_EXT_DRV_LOAD;
	E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);
}

/*
 * igb_release_driver_control
 */
static void
igb_release_driver_control(struct e1000_hw *hw)
{
	uint32_t ctrl_ext;

	/* Notify firmware that driver is no longer in control of device */
	ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
	ctrl_ext &= ~E1000_CTRL_EXT_DRV_LOAD;
	E1000_WRITE_REG(hw, E1000_CTRL_EXT, ctrl_ext);
}

/*
 * igb_atomic_reserve - Atomic decrease operation
 */
int
igb_atomic_reserve(uint32_t *count_p, uint32_t n)
{
	uint32_t oldval;
	uint32_t newval;

	/* ATOMICALLY */
	do {
		oldval = *count_p;
		if (oldval < n)
			return (-1);
		newval = oldval - n;
	} while (atomic_cas_32(count_p, oldval, newval) != oldval);

	return (newval);
}

/*
 * FMA support
 */

int
igb_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
	return (de.fme_status);
}

int
igb_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * The IO fault service error handling callback function
 */
/*ARGSUSED*/
static int
igb_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
igb_fm_init(igb_t *igb)
{
	ddi_iblock_cookie_t iblk;
	int fma_dma_flag;

	/* Only register with IO Fault Services if we have some capability */
	if (igb->fm_capabilities & DDI_FM_ACCCHK_CAPABLE) {
		igb_regs_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		igb_regs_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if (igb->fm_capabilities & DDI_FM_DMACHK_CAPABLE) {
		fma_dma_flag = 1;
	} else {
		fma_dma_flag = 0;
	}

	(void) igb_set_fma_flags(fma_dma_flag);

	if (igb->fm_capabilities) {

		/* Register capabilities with IO Fault Services */
		ddi_fm_init(igb->dip, &igb->fm_capabilities, &iblk);

		/*
		 * Initialize pci ereport capabilities if ereport capable
		 */
		if (DDI_FM_EREPORT_CAP(igb->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(igb->fm_capabilities))
			pci_ereport_setup(igb->dip);

		/*
		 * Register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(igb->fm_capabilities))
			ddi_fm_handler_register(igb->dip,
			    igb_fm_error_cb, (void*) igb);
	}
}

static void
igb_fm_fini(igb_t *igb)
{
	/* Only unregister FMA capabilities if we registered some */
	if (igb->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(igb->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(igb->fm_capabilities))
			pci_ereport_teardown(igb->dip);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(igb->fm_capabilities))
			ddi_fm_handler_unregister(igb->dip);

		/* Unregister from IO Fault Services */
		ddi_fm_fini(igb->dip);
	}
}

void
igb_fm_ereport(igb_t *igb, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(igb->fm_capabilities)) {
		ddi_fm_ereport_post(igb->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0, NULL);
	}
}
