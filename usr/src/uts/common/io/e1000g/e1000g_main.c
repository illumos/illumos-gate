/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * **********************************************************************
 *									*
 * Module Name:								*
 *   e1000g_main.c							*
 *									*
 * Abstract:								*
 *   This file contains the interface routine for the solaris OS.	*
 *   It has all DDI entry point routines and GLD entry point		*
 *   routines.								*
 *   This file also contains routines that takes care of initialization	*
 *   uninit routine and interrupt routine				*
 *									*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * **********************************************************************
 */

#include <sys/dlpi.h>
#include <sys/mac.h>
#include "e1000g_sw.h"
#include "e1000g_debug.h"

#define	E1000_RX_INTPT_TIME	128
#define	E1000_RX_PKT_CNT	8

static char ident[] = "Intel PRO/1000 Ethernet 5.1.9";
static char e1000g_string[] = "Intel(R) PRO/1000 Network Connection";
static char e1000g_version[] = "Driver Ver. 5.1.9";

/*
 * Proto types for DDI entry points
 */
static int e1000gattach(dev_info_t *, ddi_attach_cmd_t);
static int e1000gdetach(dev_info_t *, ddi_detach_cmd_t);

/*
 * init and intr routines prototype
 */
static int e1000g_resume(dev_info_t *devinfo);
static int e1000g_suspend(dev_info_t *devinfo);
static uint_t e1000g_intr_pciexpress(caddr_t);
static uint_t e1000g_intr(caddr_t);
static void e1000g_intr_work(struct e1000g *, uint32_t);
#pragma inline(e1000g_intr_work)
static int e1000g_init(struct e1000g *);
static int e1000g_start(struct e1000g *);
static void e1000g_stop(struct e1000g *);
static int e1000g_m_start(void *);
static void e1000g_m_stop(void *);
static int e1000g_m_promisc(void *, boolean_t);
static boolean_t e1000g_m_getcapab(void *, mac_capab_t, void *);
static int e1000g_m_unicst(void *, const uint8_t *);
static int e1000g_m_unicst_add(void *, mac_multi_addr_t *);
static int e1000g_m_unicst_remove(void *, mac_addr_slot_t);
static int e1000g_m_unicst_modify(void *, mac_multi_addr_t *);
static int e1000g_m_unicst_get(void *, mac_multi_addr_t *);
static int e1000g_m_multicst(void *, boolean_t, const uint8_t *);
static void e1000g_m_blank(void *, time_t, uint32_t);
static void e1000g_m_resources(void *);
static void e1000g_m_ioctl(void *, queue_t *, mblk_t *);
static void e1000g_init_locks(struct e1000g *Adapter);
static void e1000g_destroy_locks(struct e1000g *Adapter);
static int e1000g_set_driver_params(struct e1000g *Adapter);
static int e1000g_register_mac(struct e1000g *Adapter);
static boolean_t e1000g_rx_drain(struct e1000g *Adapter);
static boolean_t e1000g_tx_drain(struct e1000g *Adapter);
static void e1000g_init_unicst(struct e1000g *Adapter);
static int e1000g_unicst_set(struct e1000g *, const uint8_t *, mac_addr_slot_t);

/*
 * Local routines
 */
static void e1000g_tx_drop(struct e1000g *Adapter);
static void e1000g_link_timer(void *);
static void e1000g_LocalTimer(void *);
static boolean_t e1000g_link_check(struct e1000g *);
static boolean_t e1000g_stall_check(struct e1000g *);
static void e1000g_smartspeed(struct e1000g *);
static void e1000g_getparam(struct e1000g *Adapter);
static int e1000g_getprop(struct e1000g *, char *, int, int, int);
static void e1000g_error(dev_info_t *dip, char *fmt, char *a1,
    char *a2, char *a3, char *a4, char *a5, char *a6);
static void enable_timeout(struct e1000g *Adapter);
static void disable_timeout(struct e1000g *Adapter);
static void start_timeout(struct e1000g *Adapter);
static void restart_timeout(struct e1000g *Adapter);
static void stop_timeout(struct e1000g *Adapter);
static void e1000g_force_speed_duplex(struct e1000g *Adapter);
static void e1000g_get_max_frame_size(struct e1000g *Adapter);
static boolean_t is_valid_mac_addr(uint8_t *mac_addr);
static void e1000g_unattach(dev_info_t *, struct e1000g *);
static void e1000g_ioc_peek_reg(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd);
static void e1000g_ioc_poke_reg(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd);
static void e1000g_ioc_peek_mem(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd);
static void e1000g_ioc_poke_mem(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd);
static enum ioc_reply e1000g_pp_ioctl(struct e1000g *e1000gp,
    struct iocblk *iocp, mblk_t *mp);
static enum ioc_reply e1000g_loopback_ioctl(struct e1000g *Adapter,
    struct iocblk *iocp, mblk_t *mp);
static boolean_t e1000g_set_loopback_mode(struct e1000g *Adapter,
    uint32_t mode);
static void e1000g_set_internal_loopback(struct e1000g *Adapter);
static void e1000g_set_external_loopback_1000(struct e1000g *Adapter);
static void e1000g_set_external_loopback_100(struct e1000g *Adapter);
static void e1000g_set_external_loopback_10(struct e1000g *Adapter);
static int e1000g_add_intrs(struct e1000g *Adapter);
static int e1000g_intr_add(struct e1000g *Adapter, int intr_type);
static int e1000g_rem_intrs(struct e1000g *Adapter);
static int e1000g_enable_intrs(struct e1000g *Adapter);
static int e1000g_disable_intrs(struct e1000g *Adapter);
static boolean_t e1000g_link_up(struct e1000g *Adapter);
#ifdef __sparc
static boolean_t e1000g_find_mac_address(struct e1000g *Adapter);
#endif

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
	e1000gattach,		/* devo_attach */
	e1000gdetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_ws_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power		/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	ident,			/* Discription string */
	&ws_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

/*
 * DMA access attributes <Little Endian Card>
 */
static ddi_device_acc_attr_t accattr1 = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};

#define	E1000G_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t e1000g_m_callbacks = {
	E1000G_M_CALLBACK_FLAGS,
	e1000g_m_stat,
	e1000g_m_start,
	e1000g_m_stop,
	e1000g_m_promisc,
	e1000g_m_multicst,
	e1000g_m_unicst,
	e1000g_m_tx,
	e1000g_m_resources,
	e1000g_m_ioctl,
	e1000g_m_getcapab
};

/*
 * Global variables
 */
boolean_t e1000g_force_detach = B_TRUE;
uint32_t e1000g_mblks_pending = 0;
/*
 * Here we maintain a private dev_info list if e1000g_force_detach is
 * enabled. If we force the driver to detach while there are still some
 * rx buffers retained in the upper layer, we have to keep a copy of the
 * dev_info. In some cases (Dynamic Reconfiguration), the dev_info data
 * structure will be freed after the driver is detached. However when we
 * finally free those rx buffers released by the upper layer, we need to
 * refer to the dev_info to free the dma buffers. So we save a copy of
 * the dev_info for this purpose.
 */
private_devi_list_t *e1000g_private_devi_list = NULL;
/*
 * The rwlock is defined to protect the whole processing of rx recycling
 * and the rx packets release in detach processing to make them mutually
 * exclusive.
 * The rx recycling processes different rx packets in different threads,
 * so it will be protected with RW_READER and it won't block any other rx
 * recycling threads.
 * While the detach processing will be protected with RW_WRITER to make
 * it mutually exclusive with the rx recycling.
 */
krwlock_t e1000g_rx_detach_lock;
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
 * Loadable module configuration entry points for the driver
 */

/*
 * **********************************************************************
 * Name:      _init							*
 *									*
 * Description:								*
 *     Initializes a loadable module. It is  called  before		*
 *     any other routine in a loadable module.				*
 *     All global locks are intialised here and it returns the retun 	*
 *     value from mod_install()						*
 *     This is mandotary function for the driver			*
 * Parameter Passed:							*
 *     None								*
 * Return Value:							*
 *     0 on success							*
 * Functions called							*
 *     mod_install()	     (system call)				*
 *									*
 * **********************************************************************
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
		rw_init(&e1000g_rx_detach_lock, NULL, RW_DRIVER, NULL);
		rw_init(&e1000g_dma_type_lock, NULL, RW_DRIVER, NULL);
	}

	return (status);
}

/*
 * **********************************************************************
 *  Name:      _fini							*
 *									*
 *  Description:							*
 *     Prepares a loadable module  for  unloading.   It  is		*
 *     called  when  the  system  wants to unload a module.		*
 *     This is mandotary function for the driver			*
 *  Parameter Passed:							*
 *     None								*
 *  Return Value:							*
 *     0 on success							*
 *  Functions called							*
 *     mod_remove()	      (system call)				*
 *									*
 *									*
 *									*
 * **********************************************************************
 */
int
_fini(void)
{
	int status;

	rw_enter(&e1000g_rx_detach_lock, RW_READER);
	if (e1000g_mblks_pending != 0) {
		rw_exit(&e1000g_rx_detach_lock);
		return (EBUSY);
	}
	rw_exit(&e1000g_rx_detach_lock);

	status = mod_remove(&modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&ws_ops);

		if (e1000g_force_detach) {
			private_devi_list_t *devi_node;

			rw_enter(&e1000g_rx_detach_lock, RW_WRITER);
			while (e1000g_private_devi_list != NULL) {
				devi_node = e1000g_private_devi_list;
				e1000g_private_devi_list =
				    e1000g_private_devi_list->next;

				kmem_free(devi_node->priv_dip,
				    sizeof (struct dev_info));
				kmem_free(devi_node,
				    sizeof (private_devi_list_t));
			}
			rw_exit(&e1000g_rx_detach_lock);
		}

		rw_destroy(&e1000g_rx_detach_lock);
		rw_destroy(&e1000g_dma_type_lock);
	}

	return (status);
}

/*
 * **********************************************************************
 * Name:      _info							*
 *									*
 * Description:								*
 *     Returns  information  about  a   loadable   module.		*
 *     This is mandotary function for the driver			*
 * Parameter Passed:							*
 *     module info structure						*
 * Return Value:							*
 *     0 on success							*
 * Functions called							*
 *     mod_info()		(system call)				*
 *									*
 *									*
 * **********************************************************************
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Interface exists: make available by filling in network interface
 * record.  System will initialize the interface when it is ready
 * to accept packets.
 */

/*
 * **********************************************************************
 * Name:      e1000gattach						*
 *									*
 * Description:								*
 *     This function is the device-specific  initialization		*
 *     entry point.  This entry point is required and must be writ-	*
 *     ten.  The DDI_ATTACH command must be provided in the  attach	*
 *     entry point. When attach() is called with cmd set to DDI_ATTACH,	*
 *     all normal kernel services (such as  kmem_alloc(9F))  are	*
 *     available  for  use by the driver. Device interrupts are not	*
 *     blocked when attaching a device to the system.			*
 *									*
 *     The attach() function will be called once for each  instance	*
 *     of  the  device  on  the  system with cmd set to DDI_ATTACH.	*
 *     Until attach() succeeds, the only driver entry points  which	*
 *     may  be called are open(9E) and getinfo(9E).			*
 *									*
 *									*
 *									*
 * Parameter Passed:							*
 *									*
 * Return Value:							*
 *									*
 * Functions called							*
 *									*
 *									*
 * **********************************************************************
 */
static int
e1000gattach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;
	ddi_acc_handle_t handle;
	off_t mem_size;
	int instance;

	switch (cmd) {
	default:
		e1000g_log(NULL, CE_WARN,
		    "Unsupported command send to e1000gattach... ");
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
	Adapter->AdapterInstance = instance;
	Adapter->tx_ring->adapter = Adapter;
	Adapter->rx_ring->adapter = Adapter;

	ddi_set_driver_private(devinfo, (caddr_t)Adapter);

	if (e1000g_force_detach) {
		private_devi_list_t *devi_node;
		boolean_t devi_existed;

		devi_existed = B_FALSE;
		devi_node = e1000g_private_devi_list;
		while (devi_node != NULL) {
			if (devi_node->dip == devinfo) {
				devi_existed = B_TRUE;
				break;
			}
			devi_node = devi_node->next;
		}

		if (devi_existed) {
			Adapter->priv_dip = devi_node->priv_dip;
		} else {
			Adapter->priv_dip =
			    kmem_zalloc(sizeof (struct dev_info), KM_SLEEP);
			bcopy(DEVI(devinfo), DEVI(Adapter->priv_dip),
			    sizeof (struct dev_info));

			devi_node =
			    kmem_zalloc(sizeof (private_devi_list_t), KM_SLEEP);

			rw_enter(&e1000g_rx_detach_lock, RW_WRITER);
			devi_node->dip = devinfo;
			devi_node->priv_dip = Adapter->priv_dip;
			devi_node->next = e1000g_private_devi_list;
			e1000g_private_devi_list = devi_node;
			rw_exit(&e1000g_rx_detach_lock);
		}
	}

	hw = &Adapter->Shared;

	/*
	 * Map in the device registers.
	 *
	 * first get the size of device register to be mapped. The
	 * second parameter is the register we are interested. I our
	 * wiseman 0 is for config registers and 1 is for memory mapped
	 * registers Mem size should have memory mapped region size
	 */
	ddi_dev_regsize(devinfo, 1, /* register of interest */
	    (off_t *)&mem_size);

	if ((ddi_regs_map_setup(devinfo, 1, /* register of interest */
	    (caddr_t *)&hw->hw_addr,
	    0, mem_size, &accattr1, &Adapter->E1000_handle))
	    != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "ddi_regs_map_setup failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_REGSMAPPED;

	Adapter->osdep.E1000_handle = Adapter->E1000_handle;
	hw->back = &Adapter->osdep;

	/*
	 * PCI Configure
	 */
	if (pci_config_setup(devinfo, &handle) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
		    "PCI configuration could not be read.");
		goto attach_fail;
	}

	Adapter->handle = handle;
	Adapter->osdep.handle = handle;

	hw->vendor_id =
	    pci_config_get16(handle, PCI_CONF_VENID);
	hw->device_id =
	    pci_config_get16(handle, PCI_CONF_DEVID);
	hw->revision_id =
	    pci_config_get8(handle, PCI_CONF_REVID);
	hw->subsystem_id =
	    pci_config_get16(handle, PCI_CONF_SUBSYSID);
	hw->subsystem_vendor_id =
	    pci_config_get16(handle, PCI_CONF_SUBVENID);

	Adapter->attach_progress |= ATTACH_PROGRESS_PCICONFIG;

	/*
	 * Initialize driver parameters
	 */
	if (e1000g_set_driver_params(Adapter) != DDI_SUCCESS) {
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_PROP;

	/*
	 * Initialize interrupts
	 */
	if (e1000g_add_intrs(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Add interrupts failed");
		goto attach_fail;
	}
	Adapter->tx_softint_pri = DDI_INTR_SOFTPRI_MAX;
	Adapter->attach_progress |= ATTACH_PROGRESS_INTRADDED;

	/*
	 * Initialize mutex's for this device.
	 * Do this before enabling the interrupt handler and
	 * register the softint to avoid the condition where
	 * interrupt handler can try using uninitialized mutex
	 */
	e1000g_init_locks(Adapter);
	Adapter->attach_progress |= ATTACH_PROGRESS_LOCKS;

	if (ddi_intr_add_softint(devinfo,
	    &Adapter->tx_softint_handle, Adapter->tx_softint_pri,
	    e1000g_tx_freemsg, (caddr_t)Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Add soft intr failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_SOFTINTR;

	/*
	 * Initialize Driver Counters
	 */
	if (InitStatsCounters(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Init stats failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_KSTATS;

	/*
	 * Allocate dma resources for descriptors and buffers
	 */
	if (e1000g_alloc_dma_resources(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Alloc dma resources failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_ALLOC;

	/*
	 * Initialize chip hardware and software structures
	 */
	if (e1000g_init(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Adapter initialization failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_INIT;

	/*
	 * Initialize NDD parameters
	 */
	if (e1000g_nd_init(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Init NDD failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_NDD;

	/*
	 * Register the driver to the MAC
	 */
	if (e1000g_register_mac(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Register MAC failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_MACREGISTERED;

	/*
	 * Now that mutex locks are initialized, and the chip is also
	 * initialized, enable interrupts.
	 */
	if (e1000g_enable_intrs(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN, "Enable DDI interrupts failed");
		goto attach_fail;
	}
	Adapter->attach_progress |= ATTACH_PROGRESS_INTRENABLED;

	cmn_err(CE_CONT, "!%s, %s\n", e1000g_string, e1000g_version);

	return (DDI_SUCCESS);

attach_fail:
	e1000g_unattach(devinfo, Adapter);
	return (DDI_FAILURE);
}

static int
e1000g_register_mac(struct e1000g *Adapter)
{
	struct e1000_hw *hw = &Adapter->Shared;
	mac_register_t *mac;
	int err;

	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		return (DDI_FAILURE);
	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = Adapter;
	mac->m_dip = Adapter->dip;
	mac->m_src_addr = hw->mac_addr;
	mac->m_callbacks = &e1000g_m_callbacks;
	mac->m_min_sdu = 0;
	mac->m_max_sdu =
	    (hw->max_frame_size > FRAME_SIZE_UPTO_8K) ?
	    hw->max_frame_size - 256 :
	    (hw->max_frame_size != ETHERMAX) ?
	    hw->max_frame_size - 24 : ETHERMTU;
	err = mac_register(mac, &Adapter->mh);
	mac_free(mac);
	return (err == 0 ? DDI_SUCCESS : DDI_FAILURE);
}

static int
e1000g_set_driver_params(struct e1000g *Adapter)
{
	dev_info_t *devinfo;
	ddi_acc_handle_t handle;
	struct e1000_hw *hw;
	uint32_t mem_bar, io_bar;
#ifdef __sparc
	ulong_t iommu_pagesize;
#endif

	devinfo = Adapter->dip;
	handle = Adapter->handle;
	hw = &Adapter->Shared;

	/* Set Mac Type */
	if (e1000_set_mac_type(hw) != 0) {
		e1000g_log(Adapter, CE_WARN,
		    "Could not identify hardware");
		return (DDI_FAILURE);
	}

	/* ich8 needs to map flash memory */
	if (hw->mac_type == e1000_ich8lan) {
		/* get flash size */
		if (ddi_dev_regsize(devinfo, ICH_FLASH_REG_SET,
		    &Adapter->osdep.ich_flash_size) != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "ddi_dev_regsize for ich8 flash failed");
			return (DDI_FAILURE);
		}

		/* map flash in */
		if (ddi_regs_map_setup(devinfo, ICH_FLASH_REG_SET,
		    &Adapter->osdep.ich_flash_base, 0,
		    Adapter->osdep.ich_flash_size,
		    &accattr1,
		    &Adapter->osdep.ich_flash_handle) != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "ddi_regs_map_setup for for ich8 flash failed");
			return (DDI_FAILURE);
		}
	}

	/* get mem_base addr */
	mem_bar = pci_config_get32(handle, PCI_CONF_BASE0);
	Adapter->bar64 = mem_bar & PCI_BASE_TYPE_ALL;

	/* get io_base addr */
	if (hw->mac_type >= e1000_82544) {
		if (Adapter->bar64) {
			/* IO BAR is different for 64 bit BAR mode */
			io_bar = pci_config_get32(handle, PCI_CONF_BASE4);
		} else {
			/* normal 32-bit BAR mode */
			io_bar = pci_config_get32(handle, PCI_CONF_BASE2);
		}
		hw->io_base = io_bar & PCI_BASE_IO_ADDR_M;
	} else {
		/* no I/O access for adapters prior to 82544 */
		hw->io_base = 0x0;
	}

	e1000_read_pci_cfg(hw,
	    PCI_COMMAND_REGISTER, &(hw->pci_cmd_word));

	/* Set the wait_autoneg_complete flag to B_FALSE */
	hw->wait_autoneg_complete = B_FALSE;

	/* Adaptive IFS related changes */
	hw->adaptive_ifs = B_TRUE;

	/* set phy init script revision */
	if ((hw->mac_type == e1000_82547) ||
	    (hw->mac_type == e1000_82541) ||
	    (hw->mac_type == e1000_82547_rev_2) ||
	    (hw->mac_type == e1000_82541_rev_2))
		hw->phy_init_script = 1;

	/* Enable the TTL workaround for TnT: DCR 49 */
	hw->ttl_wa_activation = 1;

	if (hw->mac_type == e1000_82571)
		hw->laa_is_present = B_TRUE;

	/* Get conf file properties */
	e1000g_getparam(Adapter);

	hw->forced_speed_duplex = e1000_100_full;
	hw->autoneg_advertised = AUTONEG_ADVERTISE_SPEED_DEFAULT;
	e1000g_force_speed_duplex(Adapter);

	e1000g_get_max_frame_size(Adapter);
	hw->min_frame_size =
	    MINIMUM_ETHERNET_PACKET_SIZE + CRC_LENGTH;

#ifdef __sparc
	/* Get the system page size */
	Adapter->sys_page_sz = ddi_ptob(devinfo, (ulong_t)1);
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
	Adapter->dvma_page_num = hw->max_frame_size /
	    Adapter->sys_page_sz + E1000G_DEFAULT_DVMA_PAGE_NUM;
	ASSERT(Adapter->dvma_page_num >= E1000G_DEFAULT_DVMA_PAGE_NUM);
#endif

	/* Set Rx/Tx buffer size */
	switch (hw->max_frame_size) {
	case ETHERMAX:
		Adapter->RxBufferSize = E1000_RX_BUFFER_SIZE_2K;
		Adapter->TxBufferSize = E1000_TX_BUFFER_SIZE_2K;
		break;
	case FRAME_SIZE_UPTO_4K:
		Adapter->RxBufferSize = E1000_RX_BUFFER_SIZE_4K;
		Adapter->TxBufferSize = E1000_TX_BUFFER_SIZE_4K;
		break;
	case FRAME_SIZE_UPTO_8K:
		Adapter->RxBufferSize = E1000_RX_BUFFER_SIZE_8K;
		Adapter->TxBufferSize = E1000_TX_BUFFER_SIZE_8K;
		break;
	case FRAME_SIZE_UPTO_10K:
	case FRAME_SIZE_UPTO_16K:
		Adapter->RxBufferSize = E1000_RX_BUFFER_SIZE_16K;
		Adapter->TxBufferSize = E1000_TX_BUFFER_SIZE_16K;
		break;
	default:
		Adapter->RxBufferSize = E1000_RX_BUFFER_SIZE_2K;
		Adapter->TxBufferSize = E1000_TX_BUFFER_SIZE_2K;
		break;
	}
	Adapter->RxBufferSize += E1000G_IPALIGNPRESERVEROOM;

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
	if (hw->mac_type < e1000_82543)
		Adapter->RcvBufferAlignment = RECEIVE_BUFFER_ALIGN_SIZE;
	else
		/*
		 * For livengood, there is no such Rcv buf alignment
		 * requirement
		 */
		Adapter->RcvBufferAlignment = 1;

	/* DmaFairness */
	if (hw->mac_type <= e1000_82543)
		hw->dma_fairness = DEFAULTRXPCIPRIORITYVAL;
	else
		hw->dma_fairness = 0;

	/* MasterLatencyTimer */
	Adapter->MasterLatencyTimer = DEFAULTMASTERLATENCYTIMERVAL;

	/* MWIEnable */
	Adapter->MWIEnable = DEFAULTMWIENABLEVAL;

	/* profile jumbo traffic */
	Adapter->ProfileJumboTraffic = DEFAULTPROFILEJUMBOTRAFFIC;

	e1000_set_media_type(hw);
	/* copper options */
	if (hw->media_type == e1000_media_type_copper) {
		hw->mdix = 0;	/* AUTO_ALL_MODES */
		hw->disable_polarity_correction = B_FALSE;
		hw->master_slave = e1000_ms_hw_default;	/* E1000_MASTER_SLAVE */
	}

	Adapter->link_state = LINK_STATE_UNKNOWN;

	return (DDI_SUCCESS);
}

/*
 * **********************************************************************
 * Name:      e1000gdettach						*
 *									*
 * Description:								*
 *    The detach() function is the complement of the attach routine.	*
 *    If cmd is set to DDI_DETACH, detach() is used to remove  the	*
 *    state  associated  with  a  given  instance of a device node	*
 *    prior to the removal of that instance from the system.		*
 *									*
 *    The detach() function will be called once for each  instance	*
 *    of the device for which there has been a successful attach()	*
 *    once there are no longer  any  opens  on  the  device.		*
 *									*
 *    Interrupts routine are disabled, All memory allocated by this	*
 *    driver are freed.							*
 *									*
 * Parameter Passed:							*
 *    devinfo structure, cmd						*
 *									*
 * Return Value:							*
 *    DDI_SUCCESS on success						*
 *									*
 * Functions called							*
 *									*
 *									*
 * **********************************************************************
 */
static int
e1000gdetach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct e1000g *Adapter;

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

	if (Adapter->started)
		e1000g_stop(Adapter);

	if (!e1000g_rx_drain(Adapter)) {
		if (!e1000g_force_detach)
			return (DDI_FAILURE);
	}

	if (e1000g_disable_intrs(Adapter) != DDI_SUCCESS) {
		e1000g_log(Adapter, CE_WARN,
		    "Disable DDI interrupts failed");
		return (DDI_FAILURE);
	}
	Adapter->attach_progress &= ~ATTACH_PROGRESS_INTRENABLED;

	if (mac_unregister(Adapter->mh) != 0) {
		e1000g_log(Adapter, CE_WARN,
		    "Unregister MAC failed");
		return (DDI_FAILURE);
	}
	Adapter->attach_progress &= ~ATTACH_PROGRESS_MACREGISTERED;

	e1000g_unattach(devinfo, Adapter);

	return (DDI_SUCCESS);
}

static void
e1000g_unattach(dev_info_t *devinfo, struct e1000g *Adapter)
{
	if (Adapter->attach_progress & ATTACH_PROGRESS_INTRENABLED) {
		(void) e1000g_disable_intrs(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_MACREGISTERED) {
		(void) mac_unregister(Adapter->mh);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_NDD) {
		e1000g_nd_cleanup(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_INTRADDED) {
		(void) e1000g_rem_intrs(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_SOFTINTR) {
		(void) ddi_intr_remove_softint(Adapter->tx_softint_handle);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_PROP) {
		(void) ddi_prop_remove_all(devinfo);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_KSTATS) {
		kstat_delete((kstat_t *)Adapter->e1000g_ksp);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_INIT) {
		timeout_id_t tid = 0;

		/* Disable the link timer */
		mutex_enter(&Adapter->e1000g_linklock);
		tid = Adapter->link_tid;
		Adapter->link_tid = 0;
		mutex_exit(&Adapter->e1000g_linklock);

		if (tid != 0)
			(void) untimeout(tid);

		e1000_reset_hw(&Adapter->Shared);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_REGSMAPPED) {
		ddi_regs_map_free(&Adapter->E1000_handle);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_PCICONFIG) {
		pci_config_teardown(&Adapter->handle);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_ALLOC) {
		e1000g_release_dma_resources(Adapter);
	}

	if (Adapter->attach_progress & ATTACH_PROGRESS_LOCKS) {
		e1000g_destroy_locks(Adapter);
	}

	kmem_free((caddr_t)Adapter, sizeof (struct e1000g));

	/*
	 * Another hotplug spec requirement,
	 * run ddi_set_driver_private(devinfo, null);
	 */
	ddi_set_driver_private(devinfo, NULL);
}

static void
e1000g_init_locks(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_rx_ring_t *rx_ring;

	rw_init(&Adapter->chip_lock, NULL,
	    RW_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&Adapter->e1000g_linklock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&Adapter->e1000g_timeout_lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));
	mutex_init(&Adapter->TbiCntrMutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->intr_pri));

	mutex_init(&Adapter->tx_msg_chain->lock, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(Adapter->tx_softint_pri));

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
	mutex_init(&rx_ring->freelist_lock, NULL,
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
	mutex_destroy(&rx_ring->freelist_lock);

	mutex_destroy(&Adapter->tx_msg_chain->lock);
	mutex_destroy(&Adapter->e1000g_linklock);
	mutex_destroy(&Adapter->TbiCntrMutex);
	mutex_destroy(&Adapter->e1000g_timeout_lock);
	rw_destroy(&Adapter->chip_lock);
}

static int
e1000g_resume(dev_info_t *devinfo)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)ddi_get_driver_private(devinfo);
	if (Adapter == NULL)
		return (DDI_FAILURE);

	if (e1000g_start(Adapter))
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static int
e1000g_suspend(dev_info_t *devinfo)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)ddi_get_driver_private(devinfo);
	if (Adapter == NULL)
		return (DDI_FAILURE);

	e1000g_stop(Adapter);

	return (DDI_SUCCESS);
}

static int
e1000g_init(struct e1000g *Adapter)
{
	uint32_t pba;
	uint32_t ctrl;
	struct e1000_hw *hw;
	clock_t link_timeout;

	hw = &Adapter->Shared;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	/* Preserve manageability features */
	e1000_check_phy_reset_block(hw);

	/*
	 * reset to put the hardware in a known state
	 * before we try to do anything with the eeprom
	 */
	(void) e1000_reset_hw(hw);

	(void) e1000_init_eeprom_params(hw);

	if (e1000_validate_eeprom_checksum(hw) < 0) {
		/*
		 * Some PCI-E parts fail the first check due to
		 * the link being in sleep state.  Call it again,
		 * if it fails a second time its a real issue.
		 */
		if (e1000_validate_eeprom_checksum(hw) < 0) {
			e1000g_log(Adapter, CE_WARN,
			    "Invalid EEPROM checksum. Please contact "
			    "the vendor to update the EEPROM.");
			goto init_fail;
		}
	}

#ifdef __sparc
	/*
	 * Firstly, we try to get the local ethernet address from OBP. If
	 * fail, we get from EEPROM of NIC card.
	 */
	if (!e1000g_find_mac_address(Adapter)) {
		if (e1000_read_mac_addr(hw) < 0) {
			e1000g_log(Adapter, CE_WARN, "Read mac addr failed");
			goto init_fail;
		}
	}
#else
	/* Get the local ethernet address. */
	if (e1000_read_mac_addr(hw) < 0) {
		e1000g_log(Adapter, CE_WARN, "Read mac addr failed");
		goto init_fail;
	}
#endif

	/* check for valid mac address */
	if (!is_valid_mac_addr(hw->mac_addr)) {
		e1000g_log(Adapter, CE_WARN, "Invalid mac addr");
		goto init_fail;
	}

	e1000_get_bus_info(hw);

	/* Master Latency Timer implementation */
	if (Adapter->MasterLatencyTimer) {
		pci_config_put8(Adapter->handle, PCI_CONF_LATENCY_TIMER,
		    Adapter->MasterLatencyTimer);
	}

	if (hw->mac_type < e1000_82547) {
		/*
		 * Total FIFO is 64K
		 */
		if (hw->max_frame_size > FRAME_SIZE_UPTO_8K)
			pba = E1000_PBA_40K;	/* 40K for Rx, 24K for Tx */
		else
			pba = E1000_PBA_48K;	/* 48K for Rx, 16K for Tx */
	} else if (hw->mac_type >= e1000_82571 &&
	    hw->mac_type <= e1000_82572) {
		/*
		 * Total FIFO is 48K
		 */
		if (hw->max_frame_size > FRAME_SIZE_UPTO_8K)
			pba = E1000_PBA_30K;	/* 30K for Rx, 18K for Tx */
		else
			pba = E1000_PBA_38K;	/* 38K for Rx, 10K for Tx */
	} else if (hw->mac_type == e1000_ich8lan) {
		pba = E1000_PBA_8K;		/* 8K for Rx, 12K for Tx */
	} else {
		/*
		 * Total FIFO is 40K
		 */
		if (hw->max_frame_size > FRAME_SIZE_UPTO_8K)
			pba = E1000_PBA_22K;	/* 22K for Rx, 18K for Tx */
		else
			pba = E1000_PBA_30K;	/* 30K for Rx, 10K for Tx */
	}
	E1000_WRITE_REG(hw, PBA, pba);

	/*
	 * These parameters set thresholds for the adapter's generation(Tx)
	 * and response(Rx) to Ethernet PAUSE frames.  These are just threshold
	 * settings.  Flow control is enabled or disabled in the configuration
	 * file.
	 * High-water mark is set down from the top of the rx fifo (not
	 * sensitive to max_frame_size) and low-water is set just below
	 * high-water mark.
	 */
	hw->fc_high_water =
	    ((pba & E1000_PBA_MASK) << E1000_PBA_SHIFT) -
	    E1000_FC_HIGH_DIFF;
	hw->fc_low_water =
	    ((pba & E1000_PBA_MASK) << E1000_PBA_SHIFT) -
	    E1000_FC_LOW_DIFF;
	hw->fc_pause_time = E1000_FC_PAUSE_TIME;
	hw->fc_send_xon = B_TRUE;

	/*
	 * Reset the adapter hardware the second time.
	 */
	(void) e1000_reset_hw(hw);

	/* disable wakeup control by default */
	if (hw->mac_type >= e1000_82544)
		E1000_WRITE_REG(hw, WUC, 0);

	/* MWI setup */
	if (Adapter->MWIEnable) {
		hw->pci_cmd_word |= CMD_MEM_WRT_INVALIDATE;
		e1000_pci_set_mwi(hw);
	} else
		e1000_pci_clear_mwi(hw);

	/*
	 * Configure/Initialize hardware
	 */
	if (e1000_init_hw(hw) < 0) {
		e1000g_log(Adapter, CE_WARN, "Initialize hw failed");
		goto init_fail;
	}

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	/*
	 * Initialize unicast addresses.
	 */
	e1000g_init_unicst(Adapter);

	/*
	 * Setup and initialize the transmit structures.
	 */
	SetupTransmitStructures(Adapter);
	DelayInMilliseconds(5);

	/*
	 * Setup and initialize the mctable structures.  After this routine
	 * completes  Multicast table will be set
	 */
	SetupMulticastTable(Adapter);
	DelayInMilliseconds(5);

	/*
	 * Setup and initialize the receive structures.  After this routine
	 * completes we can receive packets off of the wire.
	 */
	SetupReceiveStructures(Adapter);
	DelayInMilliseconds(5);

	/*
	 * Implement Adaptive IFS
	 */
	e1000_reset_adaptive(hw);

	/* Setup Interrupt Throttling Register */
	E1000_WRITE_REG(hw, ITR, Adapter->intr_throttling_rate);

	/* Start the timer for link setup */
	if (hw->autoneg)
		link_timeout = PHY_AUTO_NEG_TIME * drv_usectohz(100000);
	else
		link_timeout = PHY_FORCE_TIME * drv_usectohz(100000);

	mutex_enter(&Adapter->e1000g_linklock);
	if (hw->wait_autoneg_complete) {
		Adapter->link_complete = B_TRUE;
	} else {
		Adapter->link_complete = B_FALSE;
		Adapter->link_tid = timeout(e1000g_link_timer,
		    (void *)Adapter, link_timeout);
	}
	mutex_exit(&Adapter->e1000g_linklock);

	/* Enable PCI-Ex master */
	if (hw->bus_type == e1000_bus_type_pci_express) {
		e1000_enable_pciex_master(hw);
	}

	Adapter->init_count++;

	rw_exit(&Adapter->chip_lock);

	return (DDI_SUCCESS);

init_fail:
	rw_exit(&Adapter->chip_lock);
	return (DDI_FAILURE);
}

/*
 * Check if the link is up
 */
static boolean_t
e1000g_link_up(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	boolean_t link_up;

	hw = &Adapter->Shared;

	/* Ensure this is set to get accurate copper link status */
	hw->get_link_status = B_TRUE;

	e1000_check_for_link(hw);

	if ((E1000_READ_REG(hw, STATUS) & E1000_STATUS_LU) ||
	    ((!hw->get_link_status) && (hw->mac_type == e1000_82543)) ||
	    ((hw->media_type == e1000_media_type_internal_serdes) &&
	    (!hw->serdes_link_down))) {
		link_up = B_TRUE;
	} else {
		link_up = B_FALSE;
	}

	return (link_up);
}

static void
e1000g_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	struct e1000g *e1000gp;
	enum ioc_reply status;
	int err;

	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = 0;
	e1000gp = (struct e1000g *)arg;

	ASSERT(e1000gp);
	if (e1000gp == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	switch (iocp->ioc_cmd) {

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = e1000g_loopback_ioctl(e1000gp, iocp, mp);
		break;

	case ND_GET:
	case ND_SET:
		status = e1000g_nd_ioctl(e1000gp, q, mp, iocp);
		break;

	case E1000G_IOC_REG_PEEK:
	case E1000G_IOC_REG_POKE:
		status = e1000g_pp_ioctl(e1000gp, iocp, mp);
		break;
	case E1000G_IOC_CHIP_RESET:
		e1000gp->reset_count++;
		if (e1000g_reset(e1000gp))
			status = IOC_ACK;
		else
			status = IOC_INVAL;
		break;
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

static void e1000g_m_blank(void *arg, time_t ticks, uint32_t count)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)arg;

	/*
	 * Adjust ITR (Interrupt Throttling Register) to coalesce
	 * interrupts. This formula and its coefficient come from
	 * our experiments.
	 */
	if (Adapter->intr_adaptive) {
		Adapter->intr_throttling_rate = count << 5;
		E1000_WRITE_REG(&Adapter->Shared, ITR,
		    Adapter->intr_throttling_rate);
	}
}

static void
e1000g_m_resources(void *arg)
{
	struct e1000g *adapter = (struct e1000g *)arg;
	mac_rx_fifo_t mrf;

	mrf.mrf_type = MAC_RX_FIFO;
	mrf.mrf_blank = e1000g_m_blank;
	mrf.mrf_arg = (void *)adapter;
	mrf.mrf_normal_blank_time = E1000_RX_INTPT_TIME;
	mrf.mrf_normal_pkt_count = E1000_RX_PKT_CNT;

	adapter->mrh = mac_resource_add(adapter->mh, (mac_resource_t *)&mrf);
}

static int
e1000g_m_start(void *arg)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	return (e1000g_start(Adapter));
}

static int
e1000g_start(struct e1000g *Adapter)
{
	if (!(Adapter->attach_progress & ATTACH_PROGRESS_INIT)) {
		if (e1000g_init(Adapter) != DDI_SUCCESS) {
			e1000g_log(Adapter, CE_WARN,
			    "Adapter initialization failed");
			return (ENOTACTIVE);
		}
	}

	enable_timeout(Adapter);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	e1000g_EnableInterrupt(Adapter);
	if (Adapter->tx_intr_enable)
		e1000g_EnableTxInterrupt(Adapter);

	Adapter->started = B_TRUE;
	Adapter->attach_progress |= ATTACH_PROGRESS_INIT;

	rw_exit(&Adapter->chip_lock);

	return (0);
}

static void
e1000g_m_stop(void *arg)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	e1000g_stop(Adapter);
}

static void
e1000g_stop(struct e1000g *Adapter)
{
	timeout_id_t tid;
	e1000g_tx_ring_t *tx_ring;
	boolean_t link_changed;

	tx_ring = Adapter->tx_ring;

	/* Set stop flags */
	rw_enter(&Adapter->chip_lock, RW_WRITER);

	Adapter->started = B_FALSE;
	Adapter->attach_progress &= ~ATTACH_PROGRESS_INIT;

	rw_exit(&Adapter->chip_lock);

	/* Drain tx sessions */
	(void) e1000g_tx_drain(Adapter);

	/* Disable timers */
	disable_timeout(Adapter);

	/* Disable the tx timer for 82547 chipset */
	mutex_enter(&tx_ring->tx_lock);
	tx_ring->timer_enable_82547 = B_FALSE;
	tid = tx_ring->timer_id_82547;
	tx_ring->timer_id_82547 = 0;
	mutex_exit(&tx_ring->tx_lock);

	if (tid != 0)
		(void) untimeout(tid);

	/* Disable the link timer */
	mutex_enter(&Adapter->e1000g_linklock);
	tid = Adapter->link_tid;
	Adapter->link_tid = 0;
	mutex_exit(&Adapter->e1000g_linklock);

	if (tid != 0)
		(void) untimeout(tid);

	/* Stop the chip and release pending resources */
	rw_enter(&Adapter->chip_lock, RW_WRITER);

	e1000g_DisableAllInterrupts(Adapter);

	e1000_reset_hw(&Adapter->Shared);

	/* Release resources still held by the TX descriptors */
	e1000g_tx_drop(Adapter);

	/* Clean the pending rx jumbo packet fragment */
	if (Adapter->rx_mblk != NULL) {
		freemsg(Adapter->rx_mblk);
		Adapter->rx_mblk = NULL;
		Adapter->rx_mblk_tail = NULL;
		Adapter->rx_packet_len = 0;
	}

	rw_exit(&Adapter->chip_lock);
}

static void
e1000g_tx_drop(struct e1000g *Adapter)
{
	e1000g_tx_ring_t *tx_ring;
	e1000g_msg_chain_t *msg_chain;
	PTX_SW_PACKET packet;
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
	packet = (PTX_SW_PACKET) QUEUE_GET_HEAD(&tx_ring->used_list);
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

		FreeTxSwPacket(packet);
		packet_count++;

		packet = (PTX_SW_PACKET)
		    QUEUE_GET_NEXT(&tx_ring->used_list, &packet->Link);
	}

	if (mp != NULL) {
		msg_chain = Adapter->tx_msg_chain;
		mutex_enter(&msg_chain->lock);
		if (msg_chain->head == NULL) {
			msg_chain->head = mp;
			msg_chain->tail = nmp;
		} else {
			msg_chain->tail->b_next = mp;
			msg_chain->tail = nmp;
		}
		mutex_exit(&msg_chain->lock);
	}

	ddi_intr_trigger_softint(Adapter->tx_softint_handle, NULL);

	if (packet_count > 0) {
		QUEUE_APPEND(&tx_ring->free_list, &tx_ring->used_list);
		QUEUE_INIT_LIST(&tx_ring->used_list);

		/* Setup TX descriptor pointers */
		tx_ring->tbd_next = tx_ring->tbd_first;
		tx_ring->tbd_oldest = tx_ring->tbd_first;

		/* Setup our HW Tx Head & Tail descriptor pointers */
		E1000_WRITE_REG(&Adapter->Shared, TDH, 0);
		E1000_WRITE_REG(&Adapter->Shared, TDT, 0);
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
	for (i = 0; i < WSDRAINTIME; i++) {
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
	boolean_t done;

	mutex_enter(&Adapter->rx_ring->freelist_lock);
	done = (Adapter->rx_avail_freepkt == Adapter->NumRxFreeList);
	mutex_exit(&Adapter->rx_ring->freelist_lock);

	return (done);
}

boolean_t
e1000g_reset(struct e1000g *Adapter)
{
	e1000g_stop(Adapter);

	if (e1000g_start(Adapter)) {
		e1000g_log(Adapter, CE_WARN, "Reset failed");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * **********************************************************************
 * Name:	e1000g_intr_pciexpress					*
 *									*
 * Description:								*
 *	This interrupt service routine is for PCI-Express adapters.	*
 *	The ICR contents is valid only when the E1000_ICR_INT_ASSERTED	*
 *	bit is set.							*
 *									*
 * Parameter Passed:							*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 *	e1000g_intr_work						*
 *									*
 * **********************************************************************
 */
static uint_t
e1000g_intr_pciexpress(caddr_t arg)
{
	struct e1000g *Adapter;
	uint32_t ICRContents;

	Adapter = (struct e1000g *)arg;
	ICRContents = E1000_READ_REG(&Adapter->Shared, ICR);

	if (ICRContents & E1000_ICR_INT_ASSERTED) {
		/*
		 * E1000_ICR_INT_ASSERTED bit was set:
		 * Read(Clear) the ICR, claim this interrupt,
		 * look for work to do.
		 */
		e1000g_intr_work(Adapter, ICRContents);
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
 * **********************************************************************
 * Name:	e1000g_intr						*
 *									*
 * Description:								*
 *	This interrupt service routine is for PCI/PCI-X adapters.	*
 *	We check the ICR contents no matter the E1000_ICR_INT_ASSERTED	*
 *	bit is set or not.						*
 *									*
 * Parameter Passed:							*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 *	e1000g_intr_work						*
 *									*
 * **********************************************************************
 */
static uint_t
e1000g_intr(caddr_t arg)
{
	struct e1000g *Adapter;
	uint32_t ICRContents;

	Adapter = (struct e1000g *)arg;
	ICRContents = E1000_READ_REG(&Adapter->Shared, ICR);

	if (ICRContents) {
		/*
		 * Any bit was set in ICR:
		 * Read(Clear) the ICR, claim this interrupt,
		 * look for work to do.
		 */
		e1000g_intr_work(Adapter, ICRContents);
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
 * **********************************************************************
 * Name:	e1000g_intr_work					*
 *									*
 * Description:								*
 *	Called from interrupt service routines.				*
 *	Read(clear) the ICR contents and call appropriate interrupt	*
 *	processing routines.						*
 *									*
 * Parameter Passed:							*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 *	e1000g_receive							*
 *	e1000g_link_check						*
 *	e1000g_recycle							*
 *									*
 * **********************************************************************
 */
static void
e1000g_intr_work(struct e1000g *Adapter, uint32_t ICRContents)
{
	if (ICRContents & E1000_ICR_RXT0) {
		mblk_t *mp;

		rw_enter(&Adapter->chip_lock, RW_READER);
		/*
		 * Here we need to check the "started" flag to ensure the
		 * receive routine will not execute when the adapter is
		 * stopped or being reset.
		 */
		if (Adapter->started) {
			mutex_enter(&Adapter->rx_ring->rx_lock);
			mp = e1000g_receive(Adapter);
			mutex_exit(&Adapter->rx_ring->rx_lock);

			rw_exit(&Adapter->chip_lock);

			if (mp != NULL)
				mac_rx(Adapter->mh, Adapter->mrh, mp);
		} else {
			rw_exit(&Adapter->chip_lock);
		}
	}

	/*
	 * The Receive Sequence errors RXSEQ and the link status change LSC
	 * are checked to detect that the cable has been pulled out. For
	 * the Wiseman 2.0 silicon, the receive sequence errors interrupt
	 * are an indication that cable is not connected.
	 */
	if ((ICRContents & E1000_ICR_RXSEQ) ||
	    (ICRContents & E1000_ICR_LSC) ||
	    (ICRContents & E1000_ICR_GPI_EN1)) {
		boolean_t link_changed;
		timeout_id_t tid = 0;

		/*
		 * Encountered RX Sequence Error!!! Link maybe forced and
		 * the cable may have just been disconnected so we will
		 * read the LOS to see.
		 */
		if (ICRContents & E1000_ICR_RXSEQ)
			Adapter->rx_seq_intr++;

		stop_timeout(Adapter);

		mutex_enter(&Adapter->e1000g_linklock);
		/* e1000g_link_check takes care of link status change */
		link_changed = e1000g_link_check(Adapter);
		/*
		 * If the link timer has not timed out, we'll not notify
		 * the upper layer with any link state until the link
		 * is up.
		 */
		if (link_changed && !Adapter->link_complete) {
			if (Adapter->link_state == LINK_STATE_UP) {
				Adapter->link_complete = B_TRUE;
				tid = Adapter->link_tid;
				Adapter->link_tid = 0;
			} else {
				link_changed = B_FALSE;
			}
		}
		mutex_exit(&Adapter->e1000g_linklock);

		if (link_changed) {
			if (tid != 0)
				(void) untimeout(tid);

			/*
			 * Workaround for esb2. Data stuck in fifo on a link
			 * down event. Reset the adapter to recover it.
			 */
			if ((Adapter->link_state == LINK_STATE_DOWN) &&
			    (Adapter->Shared.mac_type == e1000_80003es2lan))
				(void) e1000g_reset(Adapter);

			mac_link_update(Adapter->mh, Adapter->link_state);
		}

		start_timeout(Adapter);
	}

	if (ICRContents & E1000G_ICR_TX_INTR) {
		if (!Adapter->tx_intr_enable)
			e1000g_DisableTxInterrupt(Adapter);
		/* Schedule the re-transmit */
		if (Adapter->resched_needed) {
			Adapter->tx_reschedule++;
			Adapter->resched_needed = B_FALSE;
			mac_tx_update(Adapter->mh);
		}
		if (Adapter->tx_intr_enable) {
			/* Recycle the tx descriptors */
			rw_enter(&Adapter->chip_lock, RW_READER);
			Adapter->tx_recycle_intr++;
			e1000g_recycle(Adapter->tx_ring);
			rw_exit(&Adapter->chip_lock);
			/* Free the recycled messages */
			ddi_intr_trigger_softint(Adapter->tx_softint_handle,
			    NULL);
		}
	}
}

static void
e1000g_init_unicst(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	int slot;

	hw = &Adapter->Shared;

	if (Adapter->init_count == 0) {
		/* Initialize the multiple unicast addresses */
		Adapter->unicst_total = MAX_NUM_UNICAST_ADDRESSES;

		if ((hw->mac_type == e1000_82571) && hw->laa_is_present)
			Adapter->unicst_total--;

		Adapter->unicst_avail = Adapter->unicst_total - 1;

		/* Store the default mac address */
		e1000_rar_set(hw, hw->mac_addr, 0);
		if ((hw->mac_type == e1000_82571) && hw->laa_is_present)
			e1000_rar_set(hw, hw->mac_addr, LAST_RAR_ENTRY);

		bcopy(hw->mac_addr, Adapter->unicst_addr[0].mac.addr,
		    ETHERADDRL);
		Adapter->unicst_addr[0].mac.set = 1;

		for (slot = 1; slot < Adapter->unicst_total; slot++)
			Adapter->unicst_addr[slot].mac.set = 0;
	} else {
		/* Recover the default mac address */
		bcopy(Adapter->unicst_addr[0].mac.addr, hw->mac_addr,
		    ETHERADDRL);

		/* Store the default mac address */
		e1000_rar_set(hw, hw->mac_addr, 0);
		if ((hw->mac_type == e1000_82571) && hw->laa_is_present)
			e1000_rar_set(hw, hw->mac_addr, LAST_RAR_ENTRY);

		/* Re-configure the RAR registers */
		for (slot = 1; slot < Adapter->unicst_total; slot++)
			e1000_rar_set(hw,
			    Adapter->unicst_addr[slot].mac.addr, slot);
	}
}

static int
e1000g_m_unicst(void *arg, const uint8_t *mac_addr)
{
	struct e1000g *Adapter;

	Adapter = (struct e1000g *)arg;

	/* Store the default MAC address */
	bcopy(mac_addr, Adapter->Shared.mac_addr, ETHERADDRL);

	/* Set MAC address in address slot 0, which is the default address */
	return (e1000g_unicst_set(Adapter, mac_addr, 0));
}

static int
e1000g_unicst_set(struct e1000g *Adapter, const uint8_t *mac_addr,
    mac_addr_slot_t slot)
{
	struct e1000_hw *hw;

	hw = &Adapter->Shared;

	/*
	 * Error if the address specified is a multicast or broadcast
	 * address.
	 */
	if (((mac_addr[0] & 01) == 1) ||
	    (bcmp(mac_addr, &etherbroadcastaddr, ETHERADDRL) == 0))
		return (EINVAL);

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	/*
	 * The first revision of Wiseman silicon (rev 2.0) has an errata
	 * that requires the receiver to be in reset when any of the
	 * receive address registers (RAR regs) are accessed.  The first
	 * rev of Wiseman silicon also requires MWI to be disabled when
	 * a global reset or a receive reset is issued.  So before we
	 * initialize the RARs, we check the rev of the Wiseman controller
	 * and work around any necessary HW errata.
	 */
	if (hw->mac_type == e1000_82542_rev2_0) {
		e1000_pci_clear_mwi(hw);
		E1000_WRITE_REG(hw, RCTL, E1000_RCTL_RST);
		DelayInMilliseconds(5);
	}

	bcopy(mac_addr, Adapter->unicst_addr[slot].mac.addr, ETHERADDRL);
	e1000_rar_set(hw, (uint8_t *)mac_addr, slot);

	if (slot == 0) {
		if ((hw->mac_type == e1000_82571) && hw->laa_is_present)
			e1000_rar_set(hw, hw->mac_addr, LAST_RAR_ENTRY);
	}

	/*
	 * If we are using Wiseman rev 2.0 silicon, we will have previously
	 * put the receive in reset, and disabled MWI, to work around some
	 * HW errata.  Now we should take the receiver out of reset, and
	 * re-enabled if MWI if it was previously enabled by the PCI BIOS.
	 */
	if (hw->mac_type == e1000_82542_rev2_0) {
		E1000_WRITE_REG(hw, RCTL, 0);
		DelayInMilliseconds(1);
		if (hw->pci_cmd_word & CMD_MEM_WRT_INVALIDATE)
			e1000_pci_set_mwi(hw);
		SetupReceiveStructures(Adapter);
	}

	rw_exit(&Adapter->chip_lock);

	return (0);
}

/*
 * e1000g_m_unicst_add() - will find an unused address slot, set the
 * address value to the one specified, reserve that slot and enable
 * the NIC to start filtering on the new MAC address.
 * Returns 0 on success.
 */
static int
e1000g_m_unicst_add(void *arg, mac_multi_addr_t *maddr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	mac_addr_slot_t slot;
	int err;

	if (mac_unicst_verify(Adapter->mh,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE)
		return (EINVAL);

	rw_enter(&Adapter->chip_lock, RW_WRITER);
	if (Adapter->unicst_avail == 0) {
		/* no slots available */
		rw_exit(&Adapter->chip_lock);
		return (ENOSPC);
	}

	/*
	 * Primary/default address is in slot 0. The next addresses
	 * are the multiple MAC addresses. So multiple MAC address 0
	 * is in slot 1, 1 in slot 2, and so on. So the first multiple
	 * MAC address resides in slot 1.
	 */
	for (slot = 1; slot < Adapter->unicst_total; slot++) {
		if (Adapter->unicst_addr[slot].mac.set == 0) {
			Adapter->unicst_addr[slot].mac.set = 1;
			break;
		}
	}

	ASSERT((slot > 0) && (slot < Adapter->unicst_total));

	Adapter->unicst_avail--;
	rw_exit(&Adapter->chip_lock);

	maddr->mma_slot = slot;

	if ((err = e1000g_unicst_set(Adapter, maddr->mma_addr, slot)) != 0) {
		rw_enter(&Adapter->chip_lock, RW_WRITER);
		Adapter->unicst_addr[slot].mac.set = 0;
		Adapter->unicst_avail++;
		rw_exit(&Adapter->chip_lock);
	}

	return (err);
}

/*
 * e1000g_m_unicst_remove() - removes a MAC address that was added by a
 * call to e1000g_m_unicst_add(). The slot number that was returned in
 * e1000g_m_unicst_add() is passed in the call to remove the address.
 * Returns 0 on success.
 */
static int
e1000g_m_unicst_remove(void *arg, mac_addr_slot_t slot)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	int err;

	if ((slot <= 0) || (slot >= Adapter->unicst_total))
		return (EINVAL);

	rw_enter(&Adapter->chip_lock, RW_WRITER);
	if (Adapter->unicst_addr[slot].mac.set == 1) {
		Adapter->unicst_addr[slot].mac.set = 0;
		Adapter->unicst_avail++;
		rw_exit(&Adapter->chip_lock);

		/* Copy the default address to the passed slot */
		if (err = e1000g_unicst_set(Adapter,
		    Adapter->unicst_addr[0].mac.addr, slot) != 0) {
			rw_enter(&Adapter->chip_lock, RW_WRITER);
			Adapter->unicst_addr[slot].mac.set = 1;
			Adapter->unicst_avail--;
			rw_exit(&Adapter->chip_lock);
		}
		return (err);
	}
	rw_exit(&Adapter->chip_lock);

	return (EINVAL);
}

/*
 * e1000g_m_unicst_modify() - modifies the value of an address that
 * has been added by e1000g_m_unicst_add(). The new address, address
 * length and the slot number that was returned in the call to add
 * should be passed to e1000g_m_unicst_modify(). mma_flags should be
 * set to 0. Returns 0 on success.
 */
static int
e1000g_m_unicst_modify(void *arg, mac_multi_addr_t *maddr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	mac_addr_slot_t slot;

	if (mac_unicst_verify(Adapter->mh,
	    maddr->mma_addr, maddr->mma_addrlen) == B_FALSE)
		return (EINVAL);

	slot = maddr->mma_slot;

	if ((slot <= 0) || (slot >= Adapter->unicst_total))
		return (EINVAL);

	rw_enter(&Adapter->chip_lock, RW_WRITER);
	if (Adapter->unicst_addr[slot].mac.set == 1) {
		rw_exit(&Adapter->chip_lock);

		return (e1000g_unicst_set(Adapter, maddr->mma_addr, slot));
	}
	rw_exit(&Adapter->chip_lock);

	return (EINVAL);
}

/*
 * e1000g_m_unicst_get() - will get the MAC address and all other
 * information related to the address slot passed in mac_multi_addr_t.
 * mma_flags should be set to 0 in the call.
 * On return, mma_flags can take the following values:
 * 1) MMAC_SLOT_UNUSED
 * 2) MMAC_SLOT_USED | MMAC_VENDOR_ADDR
 * 3) MMAC_SLOT_UNUSED | MMAC_VENDOR_ADDR
 * 4) MMAC_SLOT_USED
 */
static int
e1000g_m_unicst_get(void *arg, mac_multi_addr_t *maddr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	mac_addr_slot_t slot;

	slot = maddr->mma_slot;

	if ((slot <= 0) || (slot >= Adapter->unicst_total))
		return (EINVAL);

	rw_enter(&Adapter->chip_lock, RW_WRITER);
	if (Adapter->unicst_addr[slot].mac.set == 1) {
		bcopy(Adapter->unicst_addr[slot].mac.addr,
		    maddr->mma_addr, ETHERADDRL);
		maddr->mma_flags = MMAC_SLOT_USED;
	} else {
		maddr->mma_flags = MMAC_SLOT_UNUSED;
	}
	rw_exit(&Adapter->chip_lock);

	return (0);
}

static int
multicst_add(struct e1000g *Adapter, const uint8_t *multiaddr)
{
	unsigned i;
	int res = 0;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	if ((multiaddr[0] & 01) == 0) {
		res = EINVAL;
		goto done;
	}

	if (Adapter->mcast_count >= MAX_NUM_MULTICAST_ADDRESSES) {
		res = ENOENT;
		goto done;
	}

	bcopy(multiaddr,
	    &Adapter->mcast_table[Adapter->mcast_count], ETHERADDRL);
	Adapter->mcast_count++;

	/*
	 * Update the MC table in the hardware
	 */
	e1000g_DisableInterrupt(Adapter);

	SetupMulticastTable(Adapter);

	if (Adapter->Shared.mac_type == e1000_82542_rev2_0)
		SetupReceiveStructures(Adapter);

	e1000g_EnableInterrupt(Adapter);

done:
	rw_exit(&Adapter->chip_lock);
	return (res);
}

static int
multicst_remove(struct e1000g *Adapter, const uint8_t *multiaddr)
{
	unsigned i;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

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

	/*
	 * Update the MC table in the hardware
	 */
	e1000g_DisableInterrupt(Adapter);

	SetupMulticastTable(Adapter);

	if (Adapter->Shared.mac_type == e1000_82542_rev2_0)
		SetupReceiveStructures(Adapter);

	e1000g_EnableInterrupt(Adapter);

done:
	rw_exit(&Adapter->chip_lock);
	return (0);
}

int
e1000g_m_multicst(void *arg, boolean_t add, const uint8_t *addr)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	return ((add) ? multicst_add(Adapter, addr)
	    : multicst_remove(Adapter, addr));
}

int
e1000g_m_promisc(void *arg, boolean_t on)
{
	struct e1000g *Adapter = (struct e1000g *)arg;
	ULONG RctlRegValue;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	RctlRegValue = E1000_READ_REG(&Adapter->Shared, RCTL);

	if (on)
		RctlRegValue |=
		    (E1000_RCTL_UPE | E1000_RCTL_MPE | E1000_RCTL_BAM);
	else
		RctlRegValue &= (~(E1000_RCTL_UPE | E1000_RCTL_MPE));

	E1000_WRITE_REG(&Adapter->Shared, RCTL, RctlRegValue);

	Adapter->e1000g_promisc = on;

	rw_exit(&Adapter->chip_lock);

	return (0);
}

static boolean_t
e1000g_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	struct e1000g *Adapter = (struct e1000g *)arg;

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		/*
		 * In Jumbo mode, enabling hardware checksum will cause
		 * port hang.
		 */
		if (Adapter->Shared.max_frame_size > ETHERMAX)
			return (B_FALSE);

		/*
		 * Checksum on/off selection via global parameters.
		 *
		 * If the chip is flagged as not capable of (correctly)
		 * handling FULL checksumming, we don't enable it on either
		 * Rx or Tx side.  Otherwise, we take this chip's settings
		 * from the patchable global defaults.
		 *
		 * We advertise our capabilities only if TX offload is
		 * enabled.  On receive, the stack will accept checksummed
		 * packets anyway, even if we haven't said we can deliver
		 * them.
		 */
		switch (Adapter->Shared.mac_type) {
		/*
		 * Switch on hardware checksum offload of
		 * chip 82540, 82545, 82546
		 */
		case e1000_82540:
		case e1000_82544:	/* pci8086,1008 */
		case e1000_82545:
		case e1000_82545_rev_3:	/* pci8086,1026 */
		case e1000_82571:
		case e1000_82572:
		case e1000_82573:
		case e1000_80003es2lan:
			*txflags = HCKSUM_IPHDRCKSUM | HCKSUM_INET_PARTIAL;
			break;

		case e1000_82546:	/* 82546EB. devID: 1010, 101d */
		case e1000_82546_rev_3:	/* 82546GB. devID: 1079, 107a */
#if !defined(__sparc) && !defined(__amd64)
			/* Workaround for Galaxy on 32bit */
			return (B_FALSE);
#else
			*txflags = HCKSUM_IPHDRCKSUM | HCKSUM_INET_PARTIAL;
			break;
#endif

		/*
		 * We don't have the following PRO 1000 chip types at
		 * hand and haven't tested their hardware checksum
		 * offload capability.  We had better switch them off.
		 *	e1000_undefined = 0,
		 *	e1000_82542_rev2_0,
		 *	e1000_82542_rev2_1,
		 *	e1000_82543,
		 *	e1000_82541,
		 *	e1000_82541_rev_2,
		 *	e1000_82547,
		 *	e1000_82547_rev_2,
		 *	e1000_num_macs
		 */
		default:
			return (B_FALSE);
		}

		break;
	}
	case MAC_CAPAB_POLL:
		/*
		 * There's nothing for us to fill in, simply returning
		 * B_TRUE stating that we support polling is sufficient.
		 */
		break;

	case MAC_CAPAB_MULTIADDRESS: {
		multiaddress_capab_t *mmacp = cap_data;

		/*
		 * The number of MAC addresses made available by
		 * this capability is one less than the total as
		 * the primary address in slot 0 is counted in
		 * the total.
		 */
		mmacp->maddr_naddr = Adapter->unicst_total - 1;
		mmacp->maddr_naddrfree = Adapter->unicst_avail;
		/* No multiple factory addresses, set mma_flag to 0 */
		mmacp->maddr_flag = 0;
		mmacp->maddr_handle = Adapter;
		mmacp->maddr_add = e1000g_m_unicst_add;
		mmacp->maddr_remove = e1000g_m_unicst_remove;
		mmacp->maddr_modify = e1000g_m_unicst_modify;
		mmacp->maddr_get = e1000g_m_unicst_get;
		mmacp->maddr_reserve = NULL;
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * **********************************************************************
 * Name:	 e1000g_getparam					*
 *									*
 * Description: This routine gets user-configured values out of the	*
 *	      configuration file e1000g.conf.				*
 * For each configurable value, there is a minimum, a maximum, and a	*
 * default.								*
 * If user does not configure a value, use the default.			*
 * If user configures below the minimum, use the minumum.		*
 * If user configures above the maximum, use the maxumum.		*
 *									*
 * Arguments:								*
 *      Adapter - A pointer to our adapter structure			*
 *									*
 * Returns:     None							*
 * **********************************************************************
 */
static void
e1000g_getparam(struct e1000g *Adapter)
{
	/*
	 * get each configurable property from e1000g.conf
	 */

	/*
	 * NumTxDescriptors
	 */
	Adapter->NumTxDescriptors =
	    e1000g_getprop(Adapter, "NumTxDescriptors",
	    MINNUMTXDESCRIPTOR, MAXNUMTXDESCRIPTOR,
	    DEFAULTNUMTXDESCRIPTOR);

	/*
	 * NumRxDescriptors
	 */
	Adapter->NumRxDescriptors =
	    e1000g_getprop(Adapter, "NumRxDescriptors",
	    MINNUMRXDESCRIPTOR, MAXNUMRXDESCRIPTOR,
	    DEFAULTNUMRXDESCRIPTOR);

	/*
	 * NumRxFreeList
	 */
	Adapter->NumRxFreeList =
	    e1000g_getprop(Adapter, "NumRxFreeList",
	    MINNUMRXFREELIST, MAXNUMRXFREELIST,
	    DEFAULTNUMRXFREELIST);

	/*
	 * NumTxPacketList
	 */
	Adapter->NumTxSwPacket =
	    e1000g_getprop(Adapter, "NumTxPacketList",
	    MINNUMTXSWPACKET, MAXNUMTXSWPACKET,
	    DEFAULTNUMTXSWPACKET);

	/*
	 * FlowControl
	 */
	Adapter->Shared.fc_send_xon = B_TRUE;
	Adapter->Shared.fc =
	    e1000g_getprop(Adapter, "FlowControl",
	    E1000_FC_NONE, 4, DEFAULTFLOWCONTROLVAL);
	/* 4 is the setting that says "let the eeprom decide" */
	if (Adapter->Shared.fc == 4)
		Adapter->Shared.fc = E1000_FC_DEFAULT;

	/*
	 * MaxNumReceivePackets
	 */
	Adapter->MaxNumReceivePackets =
	    e1000g_getprop(Adapter, "MaxNumReceivePackets",
	    MINNUMRCVPKTONINTR, MAXNUMRCVPKTONINTR,
	    DEFAULTMAXNUMRCVPKTONINTR);

	/*
	 * TxInterruptDelay
	 */
	Adapter->TxInterruptDelay =
	    e1000g_getprop(Adapter, "TxInterruptDelay",
	    MINTXINTERRUPTDELAYVAL, MAXTXINTERRUPTDELAYVAL,
	    DEFAULTTXINTERRUPTDELAYVAL);

	/*
	 * PHY master slave setting
	 */
	Adapter->Shared.master_slave =
	    e1000g_getprop(Adapter, "SetMasterSlave",
	    e1000_ms_hw_default, e1000_ms_auto,
	    e1000_ms_hw_default);

	/*
	 * Parameter which controls TBI mode workaround, which is only
	 * needed on certain switches such as Cisco 6500/Foundry
	 */
	Adapter->Shared.tbi_compatibility_en =
	    e1000g_getprop(Adapter, "TbiCompatibilityEnable",
	    0, 1, DEFAULTTBICOMPATIBILITYENABLE);

	/*
	 * MSI Enable
	 */
	Adapter->msi_enabled =
	    e1000g_getprop(Adapter, "MSIEnable",
	    0, 1, DEFAULTMSIENABLE);

	/*
	 * Interrupt Throttling Rate
	 */
	Adapter->intr_throttling_rate =
	    e1000g_getprop(Adapter, "intr_throttling_rate",
	    MININTERRUPTTHROTTLINGVAL, MAXINTERRUPTTHROTTLINGVAL,
	    DEFAULTINTERRUPTTHROTTLINGVAL);

	/*
	 * Adaptive Interrupt Blanking Enable/Disable
	 * It is enabled by default
	 */
	Adapter->intr_adaptive =
	    (e1000g_getprop(Adapter, "intr_adaptive", 0, 1, 1) == 1) ?
	    B_TRUE : B_FALSE;
}

/*
 * **********************************************************************
 * Name:	 e1000g_getprop						*
 *									*
 * Description: get a user-configure property value out of the		*
 *   configuration file e1000g.conf.					*
 *   Caller provides name of the property, a default value, a		*
 *   minimum value, and a maximum value.				*
 *									*
 * Returns: configured value of the property, with default, minimum and	*
 *   maximum properly applied.						*
 * **********************************************************************
 */
static int
e1000g_getprop(struct e1000g *Adapter,	/* point to per-adapter structure */
    char *propname,		/* name of the property */
    int minval,			/* minimum acceptable value */
    int maxval,			/* maximim acceptable value */
    int defval)			/* default value */
{
	int propval;		/* value returned for requested property */
	int *props;		/* point to array of properties returned */
	uint_t nprops;		/* number of property value returned */

	/*
	 * get the array of properties from the config file
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, Adapter->dip,
	    DDI_PROP_DONTPASS, propname, &props, &nprops) == DDI_PROP_SUCCESS) {
		/* got some properties, test if we got enough */
		if (Adapter->AdapterInstance < nprops) {
			propval = props[Adapter->AdapterInstance];
		} else {
			/* not enough properties configured */
			propval = defval;
			e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
			    "Not Enough %s values found in e1000g.conf"
			    " - set to %d\n",
			    propname, propval);
		}

		/* free memory allocated for properties */
		ddi_prop_free(props);

	} else {
		propval = defval;
	}

	/*
	 * enforce limits
	 */
	if (propval > maxval) {
		propval = maxval;
		e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
		    "Too High %s value in e1000g.conf - set to %d\n",
		    propname, propval);
	}

	if (propval < minval) {
		propval = minval;
		e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
		    "Too Low %s value in e1000g.conf - set to %d\n",
		    propname, propval);
	}

	return (propval);
}

static boolean_t
e1000g_link_check(struct e1000g *Adapter)
{
	uint16_t speed, duplex, phydata;
	boolean_t link_changed = B_FALSE;
	struct e1000_hw *hw;
	uint32_t reg_tarc;

	hw = &Adapter->Shared;

	if (e1000g_link_up(Adapter)) {
		/*
		 * The Link is up, check whether it was marked as down earlier
		 */
		if (Adapter->link_state != LINK_STATE_UP) {
			e1000_get_speed_and_duplex(hw, &speed, &duplex);
			Adapter->link_speed = speed;
			Adapter->link_duplex = duplex;
			Adapter->link_state = LINK_STATE_UP;
			link_changed = B_TRUE;

			Adapter->tx_link_down_timeout = 0;

			if ((hw->mac_type == e1000_82571) ||
			    (hw->mac_type == e1000_82572)) {
				reg_tarc = E1000_READ_REG(hw, TARC0);
				if (speed == SPEED_1000)
					reg_tarc |= (1 << 21);
				else
					reg_tarc &= ~(1 << 21);
				E1000_WRITE_REG(hw, TARC0, reg_tarc);
			}

			e1000g_log(Adapter, CE_NOTE,
			    "Adapter %dMbps %s %s link is up.", speed,
			    ((duplex == FULL_DUPLEX) ?
			    "full duplex" : "half duplex"),
			    ((hw->media_type == e1000_media_type_copper) ?
			    "copper" : "fiber"));
		}
		Adapter->smartspeed = 0;
	} else {
		if (Adapter->link_state != LINK_STATE_DOWN) {
			Adapter->link_speed = 0;
			Adapter->link_duplex = 0;
			Adapter->link_state = LINK_STATE_DOWN;
			link_changed = B_TRUE;

			e1000g_log(Adapter, CE_NOTE,
			    "Adapter %s link is down.",
			    ((hw->media_type == e1000_media_type_copper) ?
			    "copper" : "fiber"));

			/*
			 * SmartSpeed workaround for Tabor/TanaX, When the
			 * driver loses link disable auto master/slave
			 * resolution.
			 */
			if (hw->phy_type == e1000_phy_igp) {
				e1000_read_phy_reg(hw,
				    PHY_1000T_CTRL, &phydata);
				phydata |= CR_1000T_MS_ENABLE;
				e1000_write_phy_reg(hw,
				    PHY_1000T_CTRL, phydata);
			}
		} else {
			e1000g_smartspeed(Adapter);
		}

		if (Adapter->started) {
			if (Adapter->tx_link_down_timeout <
			    MAX_TX_LINK_DOWN_TIMEOUT) {
				Adapter->tx_link_down_timeout++;
			} else if (Adapter->tx_link_down_timeout ==
			    MAX_TX_LINK_DOWN_TIMEOUT) {
				rw_enter(&Adapter->chip_lock, RW_WRITER);
				e1000g_tx_drop(Adapter);
				rw_exit(&Adapter->chip_lock);
				Adapter->tx_link_down_timeout++;
			}
		}
	}

	return (link_changed);
}

static void
e1000g_LocalTimer(void *ws)
{
	struct e1000g *Adapter = (struct e1000g *)ws;
	struct e1000_hw *hw;
	e1000g_ether_addr_t ether_addr;
	boolean_t link_changed;

	hw = &Adapter->Shared;

	(void) e1000g_tx_freemsg((caddr_t)Adapter, NULL);

	if (e1000g_stall_check(Adapter)) {
		e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
		    "Tx stall detected. Activate automatic recovery.\n");
		Adapter->StallWatchdog = 0;
		Adapter->tx_recycle_fail = 0;
		Adapter->reset_count++;
		(void) e1000g_reset(Adapter);
	}

	link_changed = B_FALSE;
	mutex_enter(&Adapter->e1000g_linklock);
	if (Adapter->link_complete)
		link_changed = e1000g_link_check(Adapter);
	mutex_exit(&Adapter->e1000g_linklock);

	if (link_changed) {
		/*
		 * Workaround for esb2. Data stuck in fifo on a link
		 * down event. Reset the adapter to recover it.
		 */
		if ((Adapter->link_state == LINK_STATE_DOWN) &&
		    (hw->mac_type == e1000_80003es2lan))
			(void) e1000g_reset(Adapter);

		mac_link_update(Adapter->mh, Adapter->link_state);
	}

	/*
	 * With 82571 controllers, any locally administered address will
	 * be overwritten when there is a reset on the other port.
	 * Detect this circumstance and correct it.
	 */
	if ((hw->mac_type == e1000_82571) && hw->laa_is_present) {
		ether_addr.reg.low = E1000_READ_REG_ARRAY(hw, RA, 0);
		ether_addr.reg.high = E1000_READ_REG_ARRAY(hw, RA, 1);

		ether_addr.reg.low = ntohl(ether_addr.reg.low);
		ether_addr.reg.high = ntohl(ether_addr.reg.high);

		if ((ether_addr.mac.addr[5] != hw->mac_addr[0]) ||
		    (ether_addr.mac.addr[4] != hw->mac_addr[1]) ||
		    (ether_addr.mac.addr[3] != hw->mac_addr[2]) ||
		    (ether_addr.mac.addr[2] != hw->mac_addr[3]) ||
		    (ether_addr.mac.addr[1] != hw->mac_addr[4]) ||
		    (ether_addr.mac.addr[0] != hw->mac_addr[5])) {
			e1000_rar_set(hw, hw->mac_addr, 0);
		}
	}

	/*
	 * RP: ttl_workaround : DCR 49
	 */
	e1000_igp_ttl_workaround(hw);

	/*
	 * Check for Adaptive IFS settings If there are lots of collisions
	 * change the value in steps...
	 * These properties should only be set for 10/100
	 */
	if ((hw->media_type == e1000_media_type_copper) &&
	    ((Adapter->link_speed == SPEED_100) ||
	    (Adapter->link_speed == SPEED_10))) {
		e1000_update_adaptive(hw);
	}
	/*
	 * Set Timer Interrupts
	 */
	E1000_WRITE_REG(hw, ICS, E1000_IMS_RXT0);

	restart_timeout(Adapter);
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

	mutex_enter(&Adapter->e1000g_linklock);
	Adapter->link_complete = B_TRUE;
	Adapter->link_tid = 0;
	mutex_exit(&Adapter->e1000g_linklock);
}

/*
 * **********************************************************************
 * Name:      e1000g_force_speed_duplex					*
 *									*
 * Description:								*
 *   This function forces speed and duplex for 10/100 Mbps speeds	*
 *   and also for 1000 Mbps speeds, it advertises half or full duplex	*
 *									*
 * Parameter Passed:							*
 *   struct e1000g* (information of adpater)				*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 * **********************************************************************
 */
static void
e1000g_force_speed_duplex(struct e1000g *Adapter)
{
	int forced;

	/*
	 * get value out of config file
	 */
	forced = e1000g_getprop(Adapter, "ForceSpeedDuplex",
	    GDIAG_10_HALF, GDIAG_ANY, GDIAG_ANY);

	switch (forced) {
	case GDIAG_10_HALF:
		/*
		 * Disable Auto Negotiation
		 */
		Adapter->Shared.autoneg = B_FALSE;
		Adapter->Shared.forced_speed_duplex = e1000_10_half;
		break;
	case GDIAG_10_FULL:
		/*
		 * Disable Auto Negotiation
		 */
		Adapter->Shared.autoneg = B_FALSE;
		Adapter->Shared.forced_speed_duplex = e1000_10_full;
		break;
	case GDIAG_100_HALF:
		/*
		 * Disable Auto Negotiation
		 */
		Adapter->Shared.autoneg = B_FALSE;
		Adapter->Shared.forced_speed_duplex = e1000_100_half;
		break;
	case GDIAG_100_FULL:
		/*
		 * Disable Auto Negotiation
		 */
		Adapter->Shared.autoneg = B_FALSE;
		Adapter->Shared.forced_speed_duplex = e1000_100_full;
		break;
	case GDIAG_1000_FULL:
		/*
		 * The gigabit spec requires autonegotiation.  Therefore,
		 * when the user wants to force the speed to 1000Mbps, we
		 * enable AutoNeg, but only allow the harware to advertise
		 * 1000Mbps.  This is different from 10/100 operation, where
		 * we are allowed to link without any negotiation.
		 */
		Adapter->Shared.autoneg = B_TRUE;
		Adapter->Shared.autoneg_advertised = ADVERTISE_1000_FULL;
		break;
	default:	/* obey the setting of AutoNegAdvertised */
		Adapter->Shared.autoneg = B_TRUE;
		Adapter->Shared.autoneg_advertised =
		    (uint16_t)e1000g_getprop(Adapter, "AutoNegAdvertised",
		    0, AUTONEG_ADVERTISE_SPEED_DEFAULT,
		    AUTONEG_ADVERTISE_SPEED_DEFAULT);
		break;
	}	/* switch */
}

/*
 * **********************************************************************
 * Name:      e1000g_get_max_frame_size					*
 *									*
 * Description:								*
 *   This function reads MaxFrameSize from e1000g.conf and sets it for	*
 *   adapter.								*
 *									*
 * Parameter Passed:							*
 *   struct e1000g* (information of adpater)				*
 *									*
 * Return Value:							*
 *									*
 * Functions called:							*
 * **********************************************************************
 */
static void
e1000g_get_max_frame_size(struct e1000g *Adapter)
{
	int max_frame;

	/*
	 * get value out of config file
	 */
	max_frame = e1000g_getprop(Adapter, "MaxFrameSize", 0, 3, 0);

	switch (max_frame) {
	case 0:
		Adapter->Shared.max_frame_size = ETHERMAX;
		break;
	case 1:
		Adapter->Shared.max_frame_size = FRAME_SIZE_UPTO_4K;
		break;
	case 2:
		Adapter->Shared.max_frame_size = FRAME_SIZE_UPTO_8K;
		break;
	case 3:
		if (Adapter->Shared.mac_type < e1000_82571)
			Adapter->Shared.max_frame_size = FRAME_SIZE_UPTO_16K;
		else
			Adapter->Shared.max_frame_size = FRAME_SIZE_UPTO_10K;
		break;
	default:
		Adapter->Shared.max_frame_size = ETHERMAX;
		break;
	}	/* switch */

	/* ich8 does not do jumbo frames */
	if (Adapter->Shared.mac_type == e1000_ich8lan) {
		Adapter->Shared.max_frame_size = ETHERMAX;
	}
}

static void
arm_timer(struct e1000g *Adapter)
{
	Adapter->WatchDogTimer_id =
	    timeout(e1000g_LocalTimer,
	    (void *)Adapter, 1 * drv_usectohz(1000000));
}

static void
enable_timeout(struct e1000g *Adapter)
{
	mutex_enter(&Adapter->e1000g_timeout_lock);

	if (!Adapter->timeout_enabled) {
		Adapter->timeout_enabled = B_TRUE;
		Adapter->timeout_started = B_TRUE;

		arm_timer(Adapter);
	}

	mutex_exit(&Adapter->e1000g_timeout_lock);
}

static void
disable_timeout(struct e1000g *Adapter)
{
	timeout_id_t tid;

	mutex_enter(&Adapter->e1000g_timeout_lock);

	Adapter->timeout_enabled = B_FALSE;
	Adapter->timeout_started = B_FALSE;

	tid = Adapter->WatchDogTimer_id;
	Adapter->WatchDogTimer_id = 0;

	mutex_exit(&Adapter->e1000g_timeout_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

static void
start_timeout(struct e1000g *Adapter)
{
	mutex_enter(&Adapter->e1000g_timeout_lock);

	if (Adapter->timeout_enabled) {
		if (!Adapter->timeout_started) {
			Adapter->timeout_started = B_TRUE;
			arm_timer(Adapter);
		}
	}

	mutex_exit(&Adapter->e1000g_timeout_lock);
}

static void
restart_timeout(struct e1000g *Adapter)
{
	mutex_enter(&Adapter->e1000g_timeout_lock);

	if (Adapter->timeout_started)
		arm_timer(Adapter);

	mutex_exit(&Adapter->e1000g_timeout_lock);
}

static void
stop_timeout(struct e1000g *Adapter)
{
	timeout_id_t tid;

	mutex_enter(&Adapter->e1000g_timeout_lock);

	Adapter->timeout_started = B_FALSE;

	tid = Adapter->WatchDogTimer_id;
	Adapter->WatchDogTimer_id = 0;

	mutex_exit(&Adapter->e1000g_timeout_lock);

	if (tid != 0)
		(void) untimeout(tid);
}

void
e1000g_DisableInterrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->Shared, IMC,
	    0xffffffff & ~E1000_IMC_RXSEQ);
}

void
e1000g_EnableInterrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->Shared, IMS,
	    IMS_ENABLE_MASK & ~E1000_IMS_TXDW & ~E1000_IMS_TXQE);
}

void
e1000g_DisableAllInterrupts(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->Shared, IMC, 0xffffffff)
}

void
e1000g_EnableTxInterrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->Shared, IMS, E1000G_IMS_TX_INTR);
}

void
e1000g_DisableTxInterrupt(struct e1000g *Adapter)
{
	E1000_WRITE_REG(&Adapter->Shared, IMC, E1000G_IMC_TX_INTR);
}

void
e1000_pci_set_mwi(struct e1000_hw *hw)
{
	uint16_t val = hw->pci_cmd_word | CMD_MEM_WRT_INVALIDATE;
	e1000_write_pci_cfg(hw, PCI_COMMAND_REGISTER, &val);
}

void
e1000_pci_clear_mwi(struct e1000_hw *hw)
{
	uint16_t val = hw->pci_cmd_word & ~CMD_MEM_WRT_INVALIDATE;
	e1000_write_pci_cfg(hw, PCI_COMMAND_REGISTER, &val);
}

void
e1000_write_pci_cfg(struct e1000_hw *adapter,
    uint32_t reg, uint16_t *value)
{
	pci_config_put16(((struct e1000g_osdep *)(adapter->back))->handle,
	    reg, *value);
}

void
e1000_read_pci_cfg(struct e1000_hw *adapter,
    uint32_t reg, uint16_t *value)
{
	*value =
	    pci_config_get16(((struct e1000g_osdep *)(adapter->back))->
	    handle, reg);
}

#ifndef __sparc
void
e1000_io_write(struct e1000_hw *hw, unsigned long port, uint32_t value)
{
	outl(port, value);
}

uint32_t
e1000_io_read(struct e1000_hw *hw, unsigned long port)
{
	return (inl(port));
}
#endif

static void
e1000g_smartspeed(struct e1000g *adapter)
{
	uint16_t phy_status;
	uint16_t phy_ctrl;

	/*
	 * If we're not T-or-T, or we're not autoneg'ing, or we're not
	 * advertising 1000Full, we don't even use the workaround
	 */
	if ((adapter->Shared.phy_type != e1000_phy_igp) ||
	    !adapter->Shared.autoneg ||
	    !(adapter->Shared.autoneg_advertised & ADVERTISE_1000_FULL))
		return;

	/*
	 * True if this is the first call of this function or after every
	 * 30 seconds of not having link
	 */
	if (adapter->smartspeed == 0) {
		/*
		 * If Master/Slave config fault is asserted twice, we
		 * assume back-to-back
		 */
		e1000_read_phy_reg(&adapter->Shared, PHY_1000T_STATUS,
		    &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT))
			return;

		e1000_read_phy_reg(&adapter->Shared, PHY_1000T_STATUS,
		    &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT))
			return;
		/*
		 * We're assuming back-2-back because our status register
		 * insists! there's a fault in the master/slave
		 * relationship that was "negotiated"
		 */
		e1000_read_phy_reg(&adapter->Shared, PHY_1000T_CTRL,
		    &phy_ctrl);
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
			e1000_write_phy_reg(&adapter->Shared,
			    PHY_1000T_CTRL, phy_ctrl);
			/*
			 * Effectively starting the clock
			 */
			adapter->smartspeed++;
			/*
			 * Restart autonegotiation
			 */
			if (!e1000_phy_setup_autoneg(&adapter->Shared) &&
			    !e1000_read_phy_reg(&adapter->Shared, PHY_CTRL,
			    &phy_ctrl)) {
				phy_ctrl |= (MII_CR_AUTO_NEG_EN |
				    MII_CR_RESTART_AUTO_NEG);
				e1000_write_phy_reg(&adapter->Shared,
				    PHY_CTRL, phy_ctrl);
			}
		}
		return;
		/*
		 * Has 6 seconds transpired still without link? Remember,
		 * you should reset the smartspeed counter once you obtain
		 * link
		 */
	} else if (adapter->smartspeed == E1000_SMARTSPEED_DOWNSHIFT) {
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
		e1000_read_phy_reg(&adapter->Shared, PHY_1000T_CTRL,
		    &phy_ctrl);
		phy_ctrl |= CR_1000T_MS_ENABLE;
		e1000_write_phy_reg(&adapter->Shared, PHY_1000T_CTRL,
		    phy_ctrl);
		/*
		 * Restart autoneg with phy enabled for manual
		 * configuration of master/slave
		 */
		if (!e1000_phy_setup_autoneg(&adapter->Shared) &&
		    !e1000_read_phy_reg(&adapter->Shared, PHY_CTRL,
		    &phy_ctrl)) {
			phy_ctrl |=
			    (MII_CR_AUTO_NEG_EN | MII_CR_RESTART_AUTO_NEG);
			e1000_write_phy_reg(&adapter->Shared, PHY_CTRL,
			    phy_ctrl);
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
	if (adapter->smartspeed++ == E1000_SMARTSPEED_MAX)
		adapter->smartspeed = 0;
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
 * **********************************************************************
 * Name:								*
 *	e1000g_stall_check						*
 *									*
 * Description:								*
 *	This function checks if the adapter is stalled. (In transmit)	*
 *									*
 *	It is called each time the timeout is invoked.			*
 *	If the transmit descriptor reclaim continuously fails,		*
 *	the watchdog value will increment by 1. If the watchdog		*
 *	value exceeds the threshold, the adapter is assumed to		*
 *	have stalled and need to be reset.				*
 *									*
 * Arguments:								*
 *	Adapter - A pointer to our context sensitive "Adapter"		*
 *	structure.							*
 *									*
 * Returns:								*
 *	B_TRUE - The dapter is assumed to have stalled.			*
 *	B_FALSE								*
 *									*
 * **********************************************************************
 */
static boolean_t
e1000g_stall_check(struct e1000g *Adapter)
{
	if (Adapter->link_state != LINK_STATE_UP)
		return (B_FALSE);

	if (Adapter->tx_recycle_fail > 0)
		Adapter->StallWatchdog++;
	else
		Adapter->StallWatchdog = 0;

	if (Adapter->StallWatchdog < E1000G_STALL_WATCHDOG_COUNT)
		return (B_FALSE);

	return (B_TRUE);
}


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
		e1000g_DEBUGLOG_1(e1000gp, e1000g_INFO_LEVEL,
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

	ppd = (e1000g_peekpoke_t *)mp->b_cont->b_rptr;

	/*
	 * Validate request parameters
	 */
	switch (ppd->pp_acc_space) {

	default:
		e1000g_DEBUGLOG_1(e1000gp, e1000g_INFO_LEVEL,
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

	handle =
	    ((struct e1000g_osdep *)(&e1000gp->Shared)->back)->E1000_handle;
	regaddr =
	    (uint32_t *)((&e1000gp->Shared)->hw_addr + ppd->pp_acc_offset);

	ppd->pp_acc_data = ddi_get32(handle, regaddr);
}

static void
e1000g_ioc_poke_reg(struct e1000g *e1000gp, e1000g_peekpoke_t *ppd)
{
	ddi_acc_handle_t handle;
	uint32_t *regaddr;
	uint32_t value;

	handle =
	    ((struct e1000g_osdep *)(&e1000gp->Shared)->back)->E1000_handle;
	regaddr =
	    (uint32_t *)((&e1000gp->Shared)->hw_addr + ppd->pp_acc_offset);
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

	e1000g_DEBUGLOG_4(e1000gp, e1000g_INFO_LEVEL,
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

	e1000g_DEBUGLOG_4(e1000gp, e1000g_INFO_LEVEL,
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
	uint16_t phy_status;
	uint16_t phy_ext_status;

	hw = &Adapter->Shared;

	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	switch (iocp->ioc_cmd) {
	default:
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		size = sizeof (lb_info_sz_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		e1000_read_phy_reg(hw, PHY_EXT_STATUS, &phy_ext_status);
		e1000_read_phy_reg(hw, PHY_STATUS, &phy_status);

		value = sizeof (lb_normal);
		if ((phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (phy_ext_status & IEEE_ESR_1000X_FD_CAPS) ||
		    (hw->media_type == e1000_media_type_fiber) ||
		    (hw->media_type == e1000_media_type_internal_serdes)) {
			value += sizeof (lb_phy);
			switch (hw->mac_type) {
			case e1000_82571:
			case e1000_82572:
				value += sizeof (lb_external1000);
				break;
			}
		}
		if ((phy_status & MII_SR_100X_FD_CAPS) ||
		    (phy_status & MII_SR_100T2_FD_CAPS))
			value += sizeof (lb_external100);
		if (phy_status & MII_SR_10T_FD_CAPS)
			value += sizeof (lb_external10);

		lbsp = (lb_info_sz_t *)mp->b_cont->b_rptr;
		*lbsp = value;
		break;

	case LB_GET_INFO:
		e1000_read_phy_reg(hw, PHY_EXT_STATUS, &phy_ext_status);
		e1000_read_phy_reg(hw, PHY_STATUS, &phy_status);

		value = sizeof (lb_normal);
		if ((phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (phy_ext_status & IEEE_ESR_1000X_FD_CAPS) ||
		    (hw->media_type == e1000_media_type_fiber) ||
		    (hw->media_type == e1000_media_type_internal_serdes)) {
			value += sizeof (lb_phy);
			switch (hw->mac_type) {
			case e1000_82571:
			case e1000_82572:
				value += sizeof (lb_external1000);
				break;
			}
		}
		if ((phy_status & MII_SR_100X_FD_CAPS) ||
		    (phy_status & MII_SR_100T2_FD_CAPS))
			value += sizeof (lb_external100);
		if (phy_status & MII_SR_10T_FD_CAPS)
			value += sizeof (lb_external10);

		size = value;
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		value = 0;
		lbpp = (lb_property_t *)mp->b_cont->b_rptr;
		lbpp[value++] = lb_normal;
		if ((phy_ext_status & IEEE_ESR_1000T_FD_CAPS) ||
		    (phy_ext_status & IEEE_ESR_1000X_FD_CAPS) ||
		    (hw->media_type == e1000_media_type_fiber) ||
		    (hw->media_type == e1000_media_type_internal_serdes)) {
			lbpp[value++] = lb_phy;
			switch (hw->mac_type) {
			case e1000_82571:
			case e1000_82572:
				lbpp[value++] = lb_external1000;
				break;
			}
		}
		if ((phy_status & MII_SR_100X_FD_CAPS) ||
		    (phy_status & MII_SR_100T2_FD_CAPS))
			lbpp[value++] = lb_external100;
		if (phy_status & MII_SR_10T_FD_CAPS)
			lbpp[value++] = lb_external10;
		break;

	case LB_GET_MODE:
		size = sizeof (uint32_t);
		if (iocp->ioc_count != size)
			return (IOC_INVAL);

		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		*lbmp = Adapter->loopback_mode;
		break;

	case LB_SET_MODE:
		size = 0;
		if (iocp->ioc_count != sizeof (uint32_t))
			return (IOC_INVAL);

		lbmp = (uint32_t *)mp->b_cont->b_rptr;
		if (!e1000g_set_loopback_mode(Adapter, *lbmp))
			return (IOC_INVAL);
		break;
	}

	iocp->ioc_count = size;
	iocp->ioc_error = 0;

	return (IOC_REPLY);
}

static boolean_t
e1000g_set_loopback_mode(struct e1000g *Adapter, uint32_t mode)
{
	struct e1000_hw *hw;
#ifndef __sparc
	uint32_t reg_rctl;
#endif
	int i, times;

	if (mode == Adapter->loopback_mode)
		return (B_TRUE);

	hw = &Adapter->Shared;
	times = 0;

again:
	switch (mode) {
	default:
		return (B_FALSE);

	case E1000G_LB_NONE:
		/* Get original speed and duplex settings */
		e1000g_force_speed_duplex(Adapter);
		/* Reset the chip */
		hw->wait_autoneg_complete = B_TRUE;
		(void) e1000g_reset(Adapter);
		hw->wait_autoneg_complete = B_FALSE;
		break;

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

	switch (mode) {
	case E1000G_LB_EXTERNAL_1000:
	case E1000G_LB_EXTERNAL_100:
	case E1000G_LB_EXTERNAL_10:
	case E1000G_LB_INTERNAL_PHY:
#ifndef __sparc
		/* Enable the CRC stripping for loopback */
		reg_rctl = E1000_READ_REG(hw, RCTL);
		reg_rctl |= E1000_RCTL_SECRC;
		E1000_WRITE_REG(hw, RCTL, reg_rctl);
#endif
		/* Wait for link up */
		for (i = (PHY_FORCE_TIME * 2); i > 0; i--)
			msec_delay(100);

		if (!e1000g_link_up(Adapter)) {
			e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
			    "Failed to get the link up");
			if (times < 2) {
				/* Reset the link */
				e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
				    "Reset the link ...");
				(void) e1000g_reset(Adapter);
				goto again;
			}
		}
		break;
	}

	Adapter->loopback_mode = mode;

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

	hw = &Adapter->Shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	e1000_read_phy_reg(hw, PHY_CTRL, &phy_ctrl);
	phy_ctrl &= ~(MII_CR_AUTO_NEG_EN | MII_CR_SPEED_100 | MII_CR_SPEED_10);
	phy_ctrl |= MII_CR_FULL_DUPLEX | MII_CR_SPEED_1000;

	switch (hw->mac_type) {
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
	case e1000_82573:
		/* Auto-MDI/MDIX off */
		e1000_write_phy_reg(hw, M88E1000_PHY_SPEC_CTRL, 0x0808);
		/* Reset PHY to update Auto-MDI/MDIX */
		e1000_write_phy_reg(hw, PHY_CTRL,
		    phy_ctrl | MII_CR_RESET | MII_CR_AUTO_NEG_EN);
		/* Reset PHY to auto-neg off and force 1000 */
		e1000_write_phy_reg(hw, PHY_CTRL,
		    phy_ctrl | MII_CR_RESET);
		break;
	}

	/* Set loopback */
	e1000_write_phy_reg(hw, PHY_CTRL, phy_ctrl | MII_CR_LOOPBACK);

	msec_delay(250);

	/* Now set up the MAC to the same speed/duplex as the PHY. */
	ctrl = E1000_READ_REG(hw, CTRL);
	ctrl &= ~E1000_CTRL_SPD_SEL;	/* Clear the speed sel bits */
	ctrl |= (E1000_CTRL_FRCSPD |	/* Set the Force Speed Bit */
	    E1000_CTRL_FRCDPX |		/* Set the Force Duplex Bit */
	    E1000_CTRL_SPD_1000 |	/* Force Speed to 1000 */
	    E1000_CTRL_FD);		/* Force Duplex to FULL */

	switch (hw->mac_type) {
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
		/*
		 * For some serdes we'll need to commit the writes now
		 * so that the status is updated on link
		 */
		if (hw->media_type == e1000_media_type_internal_serdes) {
			E1000_WRITE_REG(hw, CTRL, ctrl);
			msec_delay(100);
			ctrl = E1000_READ_REG(hw, CTRL);
		}

		if (hw->media_type == e1000_media_type_copper) {
			/* Invert Loss of Signal */
			ctrl |= E1000_CTRL_ILOS;
		} else {
			/* Set ILOS on fiber nic if half duplex is detected */
			status = E1000_READ_REG(hw, STATUS);
			if ((status & E1000_STATUS_FD) == 0)
				ctrl |= E1000_CTRL_ILOS | E1000_CTRL_SLU;
		}
		break;

	case e1000_82571:
	case e1000_82572:
		if (hw->media_type != e1000_media_type_copper) {
			/* Set ILOS on fiber nic if half duplex is detected */
			status = E1000_READ_REG(hw, STATUS);
			if ((status & E1000_STATUS_FD) == 0)
				ctrl |= E1000_CTRL_ILOS | E1000_CTRL_SLU;
		}
		break;

	case e1000_82573:
		ctrl |= E1000_CTRL_ILOS;
		break;
	}

	E1000_WRITE_REG(hw, CTRL, ctrl);

	/*
	 * Disable PHY receiver for 82540/545/546 and 82573 Family.
	 * For background, see comments above e1000g_set_internal_loopback().
	 */
	switch (hw->mac_type) {
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
	case e1000_82573:
		e1000_write_phy_reg(hw, 29, 0x001F);
		e1000_write_phy_reg(hw, 30, 0x8FFC);
		e1000_write_phy_reg(hw, 29, 0x001A);
		e1000_write_phy_reg(hw, 30, 0x8FF0);
		break;
	}
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

	hw = &Adapter->Shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	switch (hw->media_type) {
	case e1000_media_type_copper:
		/* Force link up (Must be done before the PHY writes) */
		ctrl = E1000_READ_REG(hw, CTRL);
		ctrl |= E1000_CTRL_SLU;	/* Force Link Up */
		E1000_WRITE_REG(hw, CTRL, ctrl);

		rctl = E1000_READ_REG(hw, RCTL);
		rctl |= (E1000_RCTL_EN |
		    E1000_RCTL_SBP |
		    E1000_RCTL_UPE |
		    E1000_RCTL_MPE |
		    E1000_RCTL_LPE |
		    E1000_RCTL_BAM);		/* 0x803E */
		E1000_WRITE_REG(hw, RCTL, rctl);

		ctrl_ext = E1000_READ_REG(hw, CTRL_EXT);
		ctrl_ext |= (E1000_CTRL_EXT_SDP4_DATA |
		    E1000_CTRL_EXT_SDP6_DATA |
		    E1000_CTRL_EXT_SDP7_DATA |
		    E1000_CTRL_EXT_SDP4_DIR |
		    E1000_CTRL_EXT_SDP6_DIR |
		    E1000_CTRL_EXT_SDP7_DIR);	/* 0x0DD0 */
		E1000_WRITE_REG(hw, CTRL_EXT, ctrl_ext);

		/*
		 * This sequence tunes the PHY's SDP and no customer
		 * settable values. For background, see comments above
		 * e1000g_set_internal_loopback().
		 */
		e1000_write_phy_reg(hw, 0x0, 0x140);
		msec_delay(10);
		e1000_write_phy_reg(hw, 0x9, 0x1A00);
		e1000_write_phy_reg(hw, 0x12, 0xC10);
		e1000_write_phy_reg(hw, 0x12, 0x1C10);
		e1000_write_phy_reg(hw, 0x1F37, 0x76);
		e1000_write_phy_reg(hw, 0x1F33, 0x1);
		e1000_write_phy_reg(hw, 0x1F33, 0x0);

		e1000_write_phy_reg(hw, 0x1F35, 0x65);
		e1000_write_phy_reg(hw, 0x1837, 0x3F7C);
		e1000_write_phy_reg(hw, 0x1437, 0x3FDC);
		e1000_write_phy_reg(hw, 0x1237, 0x3F7C);
		e1000_write_phy_reg(hw, 0x1137, 0x3FDC);

		msec_delay(50);
		break;
	case e1000_media_type_fiber:
	case e1000_media_type_internal_serdes:
		status = E1000_READ_REG(hw, STATUS);
		if (((status & E1000_STATUS_LU) == 0) ||
		    (hw->media_type == e1000_media_type_internal_serdes)) {
			ctrl = E1000_READ_REG(hw, CTRL);
			ctrl |= E1000_CTRL_ILOS | E1000_CTRL_SLU;
			E1000_WRITE_REG(hw, CTRL, ctrl);
		}

		/* Disable autoneg by setting bit 31 of TXCW to zero */
		txcw = E1000_READ_REG(hw, TXCW);
		txcw &= ~((uint32_t)1 << 31);
		E1000_WRITE_REG(hw, TXCW, txcw);

		/*
		 * Write 0x410 to Serdes Control register
		 * to enable Serdes analog loopback
		 */
		E1000_WRITE_REG(hw, SCTL, 0x0410);
		msec_delay(10);
		break;
	default:
		break;
	}
}

static void
e1000g_set_external_loopback_100(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	uint32_t ctrl;
	uint16_t phy_ctrl;

	hw = &Adapter->Shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	phy_ctrl = (MII_CR_FULL_DUPLEX |
	    MII_CR_SPEED_100);

	/* Force 100/FD, reset PHY */
	e1000_write_phy_reg(hw, PHY_CTRL,
	    phy_ctrl | MII_CR_RESET);	/* 0xA100 */
	msec_delay(10);

	/* Force 100/FD */
	e1000_write_phy_reg(hw, PHY_CTRL,
	    phy_ctrl);			/* 0x2100 */
	msec_delay(10);

	/* Now setup the MAC to the same speed/duplex as the PHY. */
	ctrl = E1000_READ_REG(hw, CTRL);
	ctrl &= ~E1000_CTRL_SPD_SEL;	/* Clear the speed sel bits */
	ctrl |= (E1000_CTRL_SLU |	/* Force Link Up */
	    E1000_CTRL_FRCSPD |		/* Set the Force Speed Bit */
	    E1000_CTRL_FRCDPX |		/* Set the Force Duplex Bit */
	    E1000_CTRL_SPD_100 |	/* Force Speed to 100 */
	    E1000_CTRL_FD);		/* Force Duplex to FULL */

	E1000_WRITE_REG(hw, CTRL, ctrl);
}

static void
e1000g_set_external_loopback_10(struct e1000g *Adapter)
{
	struct e1000_hw *hw;
	uint32_t ctrl;
	uint16_t phy_ctrl;

	hw = &Adapter->Shared;

	/* Disable Smart Power Down */
	phy_spd_state(hw, B_FALSE);

	phy_ctrl = (MII_CR_FULL_DUPLEX |
	    MII_CR_SPEED_10);

	/* Force 10/FD, reset PHY */
	e1000_write_phy_reg(hw, PHY_CTRL,
	    phy_ctrl | MII_CR_RESET);	/* 0x8100 */
	msec_delay(10);

	/* Force 10/FD */
	e1000_write_phy_reg(hw, PHY_CTRL,
	    phy_ctrl);			/* 0x0100 */
	msec_delay(10);

	/* Now setup the MAC to the same speed/duplex as the PHY. */
	ctrl = E1000_READ_REG(hw, CTRL);
	ctrl &= ~E1000_CTRL_SPD_SEL;	/* Clear the speed sel bits */
	ctrl |= (E1000_CTRL_SLU |	/* Force Link Up */
	    E1000_CTRL_FRCSPD |		/* Set the Force Speed Bit */
	    E1000_CTRL_FRCDPX |		/* Set the Force Duplex Bit */
	    E1000_CTRL_SPD_10 |		/* Force Speed to 10 */
	    E1000_CTRL_FD);		/* Force Duplex to FULL */

	E1000_WRITE_REG(hw, CTRL, ctrl);
}

#ifdef __sparc
static boolean_t
e1000g_find_mac_address(struct e1000g *Adapter)
{
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
				Adapter->Shared.mac_addr[nelts] = bytes[nelts];
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
				bcopy(&sysaddr, Adapter->Shared.mac_addr,
				    ETHERADDRL);
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
				Adapter->Shared.mac_addr[nelts] = bytes[nelts];
			found = B_TRUE;
		}
		ddi_prop_free(bytes);
	}

	if (found) {
		bcopy(Adapter->Shared.mac_addr, Adapter->Shared.perm_mac_addr,
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
		e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
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
	if (Adapter->Shared.mac_type < e1000_82571)
		Adapter->msi_enabled = B_FALSE;

	if ((intr_types & DDI_INTR_TYPE_MSI) && Adapter->msi_enabled) {
		rc = e1000g_intr_add(Adapter, DDI_INTR_TYPE_MSI);

		if (rc != DDI_SUCCESS) {
			e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
			    "Add MSI failed, trying Legacy interrupts\n");
		} else {
			Adapter->intr_type = DDI_INTR_TYPE_MSI;
		}
	}

	if ((Adapter->intr_type == 0) &&
	    (intr_types & DDI_INTR_TYPE_FIXED)) {
		rc = e1000g_intr_add(Adapter, DDI_INTR_TYPE_FIXED);

		if (rc != DDI_SUCCESS) {
			e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
			    "Add Legacy interrupts failed\n");
			return (DDI_FAILURE);
		}

		Adapter->intr_type = DDI_INTR_TYPE_FIXED;
	}

	if (Adapter->intr_type == 0) {
		e1000g_DEBUGLOG_0(Adapter, e1000g_INFO_LEVEL,
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
		e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
		    "Get interrupt number failed. Return: %d, count: %d\n",
		    rc, count);
		return (DDI_FAILURE);
	}

	/* get number of available interrupts */
	rc = ddi_intr_get_navail(devinfo, intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
		    "Get interrupt available number failed. "
		    "Return: %d, available: %d\n", rc, avail);
		return (DDI_FAILURE);
	}

	if (avail < count) {
		e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
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
		e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
		    "Allocate interrupts failed: %d\n", rc);

		kmem_free(Adapter->htable, Adapter->intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
		    "Interrupts requested: %d, received: %d\n",
		    count, actual);
	}

	Adapter->intr_cnt = actual;

	/* Get priority for first msi, assume remaining are all the same */
	rc = ddi_intr_get_pri(Adapter->htable[0], &Adapter->intr_pri);

	if (rc != DDI_SUCCESS) {
		e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
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
	if (Adapter->Shared.mac_type < e1000_82571)
		intr_handler = (ddi_intr_handler_t *)e1000g_intr;
	else
		intr_handler = (ddi_intr_handler_t *)e1000g_intr_pciexpress;

	/* Call ddi_intr_add_handler() */
	for (x = 0; x < actual; x++) {
		rc = ddi_intr_add_handler(Adapter->htable[x],
		    intr_handler, (caddr_t)Adapter, NULL);

		if (rc != DDI_SUCCESS) {
			e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
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
		e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
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
			e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
			    "Remove intr handler failed: %d\n", rc);
			return (DDI_FAILURE);
		}

		rc = ddi_intr_free(Adapter->htable[x]);
		if (rc != DDI_SUCCESS) {
			e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
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
			e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
			    "Enable block intr failed: %d\n", rc);
			return (DDI_FAILURE);
		}
	} else {
		/* Call ddi_intr_enable() for Legacy/MSI non block enable */
		for (x = 0; x < Adapter->intr_cnt; x++) {
			rc = ddi_intr_enable(Adapter->htable[x]);
			if (rc != DDI_SUCCESS) {
				e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
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
			e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
			    "Disable block intr failed: %d\n", rc);
			return (DDI_FAILURE);
		}
	} else {
		for (x = 0; x < Adapter->intr_cnt; x++) {
			rc = ddi_intr_disable(Adapter->htable[x]);
			if (rc != DDI_SUCCESS) {
				e1000g_DEBUGLOG_1(Adapter, e1000g_INFO_LEVEL,
				    "Disable intr failed: %d\n", rc);
				return (DDI_FAILURE);
			}
		}
	}

	return (DDI_SUCCESS);
}

/*
 * phy_spd_state - set smart-power-down (SPD) state
 *
 * This only acts on the 82541/47 family and the 82571/72 family.
 * For any others, return without doing anything.
 */
void
phy_spd_state(struct e1000_hw *hw, boolean_t enable)
{
	int32_t offset;		/* offset to register */
	uint16_t spd_bit;	/* bit to be set */
	uint16_t reg;		/* register contents */

	switch (hw->mac_type) {
	case e1000_82541:
	case e1000_82547:
	case e1000_82541_rev_2:
	case e1000_82547_rev_2:
		offset = IGP01E1000_GMII_FIFO;
		spd_bit = IGP01E1000_GMII_SPD;
		break;
	case e1000_82571:
	case e1000_82572:
		offset = IGP02E1000_PHY_POWER_MGMT;
		spd_bit = IGP02E1000_PM_SPD;
		break;
	default:
		return;		/* no action */
	}

	e1000_read_phy_reg(hw, offset, &reg);

	if (enable)
		reg |= spd_bit;		/* enable: set the spd bit */
	else
		reg &= ~spd_bit;	/* disable: clear the spd bit */

	e1000_write_phy_reg(hw, offset, reg);
}

/*
 * The real intent of this routine is to return the value from pci-e
 * config space at offset reg into the capability space.
 * ICH devices are "PCI Express"-ish.  They have a configuration space,
 * but do not contain PCI Express Capability registers, so this returns
 * the equivalent of "not supported"
 */
int32_t
e1000_read_pcie_cap_reg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
	*value = pci_config_get16(((struct e1000g_osdep *)hw->back)->handle,
	    PCI_EX_CONF_CAP + reg);

	return (0);
}

/*
 * Enables PCI-Express master access.
 *
 * hw: Struct containing variables accessed by shared code
 *
 * returns: - none.
 */
void
e1000_enable_pciex_master(struct e1000_hw *hw)
{
	uint32_t ctrl;

	if (hw->bus_type != e1000_bus_type_pci_express)
		return;

	ctrl = E1000_READ_REG(hw, CTRL);
	ctrl &= ~E1000_CTRL_GIO_MASTER_DISABLE;
	E1000_WRITE_REG(hw, CTRL, ctrl);
}
