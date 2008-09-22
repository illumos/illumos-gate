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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PCI-E to PCI bus bridge nexus driver
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddifm.h>
#include <sys/ndifm.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/hotplug/hpctrl.h>
#include <io/pciex/pcie_nvidia.h>
#include <io/pciex/pcie_nb5000.h>

#ifdef DEBUG
static int pepb_debug = 0;
#define	PEPB_DEBUG(args)	if (pepb_debug) cmn_err args
#else
#define	PEPB_DEBUG(args)
#endif

/*
 * interfaces from misc/pcie
 */
static int	pepb_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *, off_t,
		    off_t, caddr_t *);
static int	pepb_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
		    void *);
static int	pepb_fm_init(dev_info_t *, dev_info_t *, int,
		    ddi_iblock_cookie_t *);

struct bus_ops pepb_bus_ops = {
	BUSO_REV,
	pepb_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	ddi_dma_map,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	pepb_ctlops,
	ddi_bus_prop_op,
	0,		/* (*bus_get_eventcookie)();	*/
	0,		/* (*bus_add_eventcall)();	*/
	0,		/* (*bus_remove_eventcall)();	*/
	0,		/* (*bus_post_event)();		*/
	0,		/* (*bus_intr_ctl)();		*/
	0,		/* (*bus_config)(); 		*/
	0,		/* (*bus_unconfig)(); 		*/
	pepb_fm_init,	/* (*bus_fm_init)(); 		*/
	NULL,		/* (*bus_fm_fini)(); 		*/
	NULL,		/* (*bus_fm_access_enter)(); 	*/
	NULL,		/* (*bus_fm_access_exit)(); 	*/
	NULL,		/* (*bus_power)(); 	*/
	i_ddi_intr_ops	/* (*bus_intr_op)(); 		*/
};

/*
 * The goal here is to leverage off of the pcihp.c source without making
 * changes to it.  Call into it's cb_ops directly if needed.
 */
static int	pepb_open(dev_t *, int, int, cred_t *);
static int	pepb_close(dev_t, int, int, cred_t *);
static int	pepb_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	pepb_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
		    caddr_t, int *);
static int	pepb_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static void	pepb_peekpoke_cb(dev_info_t *, ddi_fm_error_t *);

struct cb_ops pepb_cb_ops = {
	pepb_open,			/* open */
	pepb_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pepb_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pepb_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static int	pepb_probe(dev_info_t *);
static int	pepb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int	pepb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int	pepb_check_slot_disabled(dev_info_t *dip);

struct dev_ops pepb_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	pepb_info,		/* info */
	nulldev,		/* identify */
	pepb_probe,		/* probe */
	pepb_attach,		/* attach */
	pepb_detach,		/* detach */
	nulldev,		/* reset */
	&pepb_cb_ops,		/* driver operations */
	&pepb_bus_ops,		/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"PCIe to PCI nexus driver",
	&pepb_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};


/*
 * soft state pointer and structure template:
 */
static void *pepb_state;

typedef struct {
	dev_info_t *dip;

	/*
	 * cpr support:
	 */
	uint_t	config_state_index;
	struct {
		dev_info_t	*dip;
		ushort_t	command;
		uchar_t		cache_line_size;
		uchar_t		latency_timer;
		uchar_t		header_type;
		uchar_t		sec_latency_timer;
		ushort_t	bridge_control;
	} config_state[PCI_MAX_CHILDREN];

	/*
	 * hot plug support
	 */
	int			inband_hpc;	/* inband HPC type */

	/*
	 * interrupt support
	 */
	ddi_intr_handle_t	*htable;	/* interrupt handles */
	int			htable_size;	/* htable size */
	int			intr_count;	/* Num of Intr */
	uint_t			intr_priority;	/* Intr Priority */
	int			intr_type;	/* (MSI | FIXED) */
	uint32_t		soft_state;	/* soft state flags */
	kmutex_t		pepb_mutex;	/* Mutex for this ctrl */
	kmutex_t		pepb_err_mutex;	/* Error handling mutex */
	kmutex_t		pepb_peek_poke_mutex;
	int			pepb_fmcap;
	ddi_iblock_cookie_t	pepb_fm_ibc;
	int			port_type;
} pepb_devstate_t;

/* soft state flags */
#define	PEPB_SOFT_STATE_INIT_HTABLE	0x01	/* htable kmem_alloced */
#define	PEPB_SOFT_STATE_INIT_ALLOC	0x02	/* ddi_intr_alloc called */
#define	PEPB_SOFT_STATE_INIT_HANDLER	0x04	/* ddi_intr_add_handler done */
#define	PEPB_SOFT_STATE_INIT_ENABLE	0x08	/* ddi_intr_enable called */
#define	PEPB_SOFT_STATE_INIT_BLOCK	0x10	/* ddi_intr_block_enable done */
#define	PEPB_SOFT_STATE_INIT_MUTEX	0x20	/* mutex initialized */

/* default interrupt priority for all interrupts (hotplug or non-hotplug */
#define	PEPB_INTR_PRI	1

/* flag to turn on MSI support */
static int pepb_enable_msi = 1;

/* panic on PF_PANIC flag */
static int pepb_die = PF_ERR_FATAL_FLAGS;

extern errorq_t *pci_target_queue;

/*
 * forward function declarations:
 */
static void	pepb_uninitchild(dev_info_t *);
static int 	pepb_initchild(dev_info_t *child);
static void 	pepb_save_config_regs(pepb_devstate_t *pepb_p);
static void	pepb_restore_config_regs(pepb_devstate_t *pepb_p);
static int	pepb_pcie_device_type(dev_info_t *dip, int *port_type);
static int	pepb_pcie_port_type(dev_info_t *dip,
			ddi_acc_handle_t config_handle);

/* interrupt related declarations */
static uint_t	pepb_intx_intr(caddr_t arg, caddr_t arg2);
static uint_t	pepb_pwr_msi_intr(caddr_t arg, caddr_t arg2);
static uint_t	pepb_err_msi_intr(caddr_t arg, caddr_t arg2);
static int	pepb_intr_on_root_port(dev_info_t *);
static int	pepb_intr_init(pepb_devstate_t *pepb_p, int intr_type);
static void	pepb_intr_fini(pepb_devstate_t *pepb_p);

/* Intel Workarounds */
static void	pepb_intel_serr_workaround(dev_info_t *dip);
static void	pepb_intel_rber_workaround(dev_info_t *dip);
static void	pepb_intel_sw_workaround(dev_info_t *dip);
int pepb_intel_workaround_disable = 0;

/* state variable used to apply workaround on current system to RBER devices */
static boolean_t pepb_do_rber_sev = B_FALSE;

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&pepb_state, sizeof (pepb_devstate_t),
	    1)) == 0 && (e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pepb_state);
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) == 0) {
		/*
		 * Destroy pci_target_queue, and set it to NULL.
		 */
		if (pci_target_queue)
			errorq_destroy(pci_target_queue);
		pci_target_queue = NULL;
		ddi_soft_state_fini(&pepb_state);
	}
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pepb_probe(dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

static int
pepb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int			instance;
	int			intr_types;
	char			device_type[8];
	pepb_devstate_t		*pepb;
	ddi_acc_handle_t	config_handle;

	switch (cmd) {
	case DDI_RESUME:

		/*
		 * Get the soft state structure for the bridge.
		 */
		pepb = ddi_get_soft_state(pepb_state, ddi_get_instance(devi));
		pepb_restore_config_regs(pepb);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	case DDI_ATTACH:
		break;
	}

	/*
	 * If PCIE_LINKCTL_LINK_DISABLE bit in the PCIe Config
	 * Space (PCIe Capability Link Control Register) is set,
	 * then do not bind the driver.
	 */
	if (pepb_check_slot_disabled(devi) == 1)
		return (DDI_FAILURE);

	/*
	 * Allocate and get soft state structure.
	 */
	instance = ddi_get_instance(devi);
	if (ddi_soft_state_zalloc(pepb_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	pepb = ddi_get_soft_state(pepb_state, instance);
	pepb->dip = devi;

	/*
	 * initialize fma support before we start accessing config space
	 */
	pci_targetq_init();
	pepb->pepb_fmcap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE;
	ddi_fm_init(devi, &pepb->pepb_fmcap, &pepb->pepb_fm_ibc);

	mutex_init(&pepb->pepb_err_mutex, NULL, MUTEX_DRIVER,
	    (void *)pepb->pepb_fm_ibc);
	mutex_init(&pepb->pepb_peek_poke_mutex, NULL, MUTEX_DRIVER,
	    (void *)pepb->pepb_fm_ibc);

	/*
	 * Make sure the "device_type" property exists.
	 */
	if (pepb_pcie_device_type(devi, &pepb->port_type) == DDI_SUCCESS)
		(void) strcpy(device_type, "pciex");
	else
		(void) strcpy(device_type, "pci");
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "device_type", device_type);

	/* probe for inband HPC */
	pepb->inband_hpc = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, "pci-hotplug-type", INBAND_HPC_NONE);

	/*
	 * Initialize interrupt handlers.
	 */
	if (ddi_intr_get_supported_types(devi, &intr_types) != DDI_SUCCESS)
		goto next_step;

	PEPB_DEBUG((CE_NOTE, "%s#%d: intr_types = 0x%x\n",
	    ddi_driver_name(devi), ddi_get_instance(devi), intr_types));

	if (pepb_enable_msi && (intr_types & DDI_INTR_TYPE_MSI) &&
	    pepb_intr_on_root_port(devi) == DDI_SUCCESS) {
		if (pepb_intr_init(pepb, DDI_INTR_TYPE_MSI) == DDI_SUCCESS)
			goto next_step;
		else
			PEPB_DEBUG((CE_WARN,
			    "%s#%d: Unable to attach MSI handler",
			    ddi_driver_name(devi), ddi_get_instance(devi)));
	}

	/*
	 * Only register hotplug interrupts for now.
	 * Check if device supports PCIe hotplug or not?
	 * If yes, register fixed interrupts if ILINE is valid.
	 */
	if (pepb->inband_hpc == INBAND_HPC_PCIE) {
		uint8_t iline;

		(void) pci_config_setup(devi, &config_handle);
		iline = pci_config_get8(config_handle, PCI_CONF_ILINE);
		pci_config_teardown(&config_handle);

		if (iline == 0 || iline > 15)
			goto next_step;

		if (pepb_intr_init(pepb, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS)
			PEPB_DEBUG((CE_WARN,
			    "%s#%d: Unable to attach INTx handler",
			    ddi_driver_name(devi), ddi_get_instance(devi)));
	}

next_step:
	/*
	 * Initialize hotplug support on this bus. At minimum
	 * (for non hotplug bus) this would create ":devctl" minor
	 * node to support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls
	 * to this bus.
	 */
	if (pcihp_init(devi) != DDI_SUCCESS)
		cmn_err(CE_WARN, "Failed to setup hotplug framework");
	else {
		/*
		 * If there is an inband PCI-E HPC then initialize it.
		 * The failure is not considered fatal for the system
		 * so log the message and ignore the failure.
		 */
		if (pepb->inband_hpc == INBAND_HPC_PCIE &&
		    pciehpc_init(devi, NULL) != DDI_SUCCESS) {
			pepb->inband_hpc = INBAND_HPC_NONE;
			cmn_err(CE_CONT, "!Failed to initialize inband hotplug "
			    "controller");
		}
	}

	/* Must apply workaround only after all initialization is done */
	pepb_intel_serr_workaround(devi);
	pepb_intel_rber_workaround(devi);
	pepb_intel_sw_workaround(devi);

	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

static int
pepb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	pepb_devstate_t *pepb;

	switch (cmd) {
	case DDI_SUSPEND:
		pepb = ddi_get_soft_state(pepb_state, ddi_get_instance(devi));
		pepb_save_config_regs(pepb);
		return (DDI_SUCCESS);

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");
	pepb = ddi_get_soft_state(pepb_state, ddi_get_instance(devi));

	/* remove interrupt handlers */
	pepb_intr_fini(pepb);

	/* uninitialize inband PCI-E HPC if present */
	if (pepb->inband_hpc == INBAND_HPC_PCIE)
		(void) pciehpc_uninit(devi);

	/*
	 * Uninitialize hotplug support on this bus.
	 */
	(void) pcihp_uninit(devi);

	mutex_destroy(&pepb->pepb_err_mutex);
	mutex_destroy(&pepb->pepb_peek_poke_mutex);
	ddi_fm_fini(devi);

	/*
	 * And finally free the per-pci soft state.
	 */
	ddi_soft_state_free(pepb_state, ddi_get_instance(devi));

	return (DDI_SUCCESS);
}

static int
pepb_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	dev_info_t *pdip;

	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)(pdip, rdip, mp,
	    offset, len, vaddrp));
}

static int
pepb_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	int	reglen;
	int	rn;
	int	totreg;
	pepb_devstate_t *pepb = ddi_get_soft_state(pepb_state,
	    ddi_get_instance(dip));
	struct detachspec *ds;
	struct attachspec *as;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCIE-device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (pepb_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		pepb_uninitchild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		break;

	case DDI_CTLOPS_PEEK:
	case DDI_CTLOPS_POKE:
		if (pepb->port_type != PCIE_PCIECAP_DEV_TYPE_ROOT)
			return (ddi_ctlops(dip, rdip, ctlop, arg, result));
		return (pci_peekpoke_check(dip, rdip, ctlop, arg, result,
		    ddi_ctlops, &pepb->pepb_err_mutex,
		    &pepb->pepb_peek_poke_mutex,
		    pepb_peekpoke_cb));

	case DDI_CTLOPS_ATTACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		as = (struct attachspec *)arg;
		if ((as->when == DDI_POST) && (as->result == DDI_SUCCESS)) {
			pf_init(rdip, (void *)pepb->pepb_fm_ibc, as->cmd);
			(void) pcie_postattach_child(rdip);

			/*
			 * For leaf devices supporting RBER and AER, we need
			 * to apply this workaround on them after attach to be
			 * notified of UEs that would otherwise be ignored
			 * as CEs on Intel chipsets currently
			 */
			pepb_intel_rber_workaround(rdip);
		}

		if (as->cmd == DDI_RESUME && as->when == DDI_PRE)
			if (pci_pre_resume(rdip) != DDI_SUCCESS)
				return (DDI_FAILURE);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		ds = (struct detachspec *)arg;
		if (ds->when == DDI_PRE)
			pf_fini(rdip, ds->cmd);

		if (ds->cmd == DDI_SUSPEND && ds->when == DDI_POST)
			if (pci_post_suspend(rdip) != DDI_SUCCESS)
				return (DDI_FAILURE);

		return (DDI_SUCCESS);
	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	*(int *)result = 0;
	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "reg", (caddr_t)&drv_regp,
	    &reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	totreg = reglen / sizeof (pci_regspec_t);
	if (ctlop == DDI_CTLOPS_NREGS)
		*(int *)result = totreg;
	else if (ctlop == DDI_CTLOPS_REGSIZE) {
		rn = *(int *)arg;
		if (rn >= totreg) {
			kmem_free(drv_regp, reglen);
			return (DDI_FAILURE);
		}
		*(off_t *)result = drv_regp[rn].pci_size_low;
	}

	kmem_free(drv_regp, reglen);
	return (DDI_SUCCESS);
}

static int
pepb_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	uint_t slot, func;
	char **unit_addr;
	uint_t n;

	/*
	 * For .conf nodes, use unit-address property as name
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
			    "cannot find unit-address in %s.conf",
			    ddi_driver_name(child));
			return (DDI_FAILURE);
		}
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_driver_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_SUCCESS);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	/* get child "reg" property */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp, &n) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* copy the device identifications */
	slot = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	if (func != 0)
		(void) snprintf(name, namelen, "%x,%x", slot, func);
	else
		(void) snprintf(name, namelen, "%x", slot);

	ddi_prop_free(pci_rp);
	return (DDI_SUCCESS);
}

static int
pepb_initchild(dev_info_t *child)
{
	struct ddi_parent_private_data *pdptr;
	struct pcie_bus *bus_p;
	char name[MAXNAMELEN];

	if (pepb_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
		return (DDI_FAILURE);
	ddi_set_name_addr(child, name);

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		extern int pci_allow_pseudo_children;

		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, pepb_name_child) != DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for ddivs to run under PCI-E */
		if (pci_allow_pseudo_children)
			return (DDI_SUCCESS);

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_driver_name(child), ddi_get_name_addr(child),
		    ddi_driver_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	if (ddi_getprop(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS, "interrupts",
	    -1) != -1) {
		pdptr = kmem_zalloc((sizeof (struct ddi_parent_private_data) +
		    sizeof (struct intrspec)), KM_SLEEP);
		pdptr->par_intr = (struct intrspec *)(pdptr + 1);
		pdptr->par_nintr = 1;
		ddi_set_parent_data(child, pdptr);
	} else
		ddi_set_parent_data(child, NULL);

	bus_p = pcie_init_bus(child);
	if (!bus_p || pcie_initchild(child) != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static void
pepb_uninitchild(dev_info_t *dip)
{
	struct ddi_parent_private_data	*pdptr;

	pcie_uninitchild(dip);

	if ((pdptr = ddi_get_parent_data(dip)) != NULL) {
		kmem_free(pdptr, (sizeof (*pdptr) + sizeof (struct intrspec)));
		ddi_set_parent_data(dip, NULL);
	}

	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	ddi_prop_remove_all(dip);
}

/*
 * pepb_save_config_regs
 *
 * This routine saves the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: pepb_detach() on suspends
 *
 * return value: none
 *
 * XXX: Need to save PCI-E config registers including MSI
 */
static void
pepb_save_config_regs(pepb_devstate_t *pepb_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;

	for (i = 0, dip = ddi_get_child(pepb_p->dip); dip != NULL;
	    i++, dip = ddi_get_next_sibling(dip)) {

		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't config space for %s%d\n",
			    ddi_driver_name(pepb_p->dip),
			    ddi_get_instance(pepb_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}

		pepb_p->config_state[i].dip = dip;
		pepb_p->config_state[i].command =
		    pci_config_get16(config_handle, PCI_CONF_COMM);
		pepb_p->config_state[i].header_type =
		    pci_config_get8(config_handle, PCI_CONF_HEADER);

		if ((pepb_p->config_state[i].header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE)
			pepb_p->config_state[i].bridge_control =
			    pci_config_get16(config_handle, PCI_BCNF_BCNTRL);

		pepb_p->config_state[i].cache_line_size =
		    pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		pepb_p->config_state[i].latency_timer =
		    pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);

		if ((pepb_p->config_state[i].header_type &
		    PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pepb_p->config_state[i].sec_latency_timer =
			    pci_config_get8(config_handle,
			    PCI_BCNF_LATENCY_TIMER);

		pci_config_teardown(&config_handle);
	}
	pepb_p->config_state_index = i;
}


/*
 * pepb_restore_config_regs
 *
 * This routine restores the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: pepb_attach() on resume
 *
 * return value: none
 *
 * XXX: Need to restore PCI-E config registers including MSI
 */
static void
pepb_restore_config_regs(pepb_devstate_t *pepb_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;

	for (i = 0; i < pepb_p->config_state_index; i++) {
		dip = pepb_p->config_state[i].dip;
		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't config space for %s%d\n",
			    ddi_driver_name(pepb_p->dip),
			    ddi_get_instance(pepb_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}
		pci_config_put16(config_handle, PCI_CONF_COMM,
		    pepb_p->config_state[i].command);
		if ((pepb_p->config_state[i].header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE)
			pci_config_put16(config_handle, PCI_BCNF_BCNTRL,
			    pepb_p->config_state[i].bridge_control);

		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    pepb_p->config_state[i].cache_line_size);
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
		    pepb_p->config_state[i].latency_timer);

		if ((pepb_p->config_state[i].header_type &
		    PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
			    pepb_p->config_state[i].sec_latency_timer);

		pci_config_teardown(&config_handle);
	}
}

static int
pepb_pcie_device_type(dev_info_t *dip, int *port_type)
{
	ddi_acc_handle_t handle;

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);
	*port_type = pepb_pcie_port_type(dip, handle);
	pci_config_teardown(&handle);

	/* No PCIe CAP regs, we are not PCIe device_type */
	if (*port_type < 0)
		return (DDI_FAILURE);

	/* check for all PCIe device_types */
	if ((*port_type == PCIE_PCIECAP_DEV_TYPE_UP) ||
	    (*port_type == PCIE_PCIECAP_DEV_TYPE_DOWN) ||
	    (*port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    (*port_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);

}

/*
 * This function initializes internally generated interrupts only.
 * It does not affect any interrupts generated by downstream devices
 * or the forwarding of them.
 *
 * Enable Device Specific Interrupts or Hotplug features here.
 * Enabling features may change how many interrupts are requested
 * by the device.  If features are not enabled first, the
 * device might not ask for any interrupts.
 */
static int
pepb_intr_init(pepb_devstate_t *pepb_p, int intr_type)
{
	dev_info_t	*dip = pepb_p->dip;
	int		request = 1, count, x;
	int		ret;
	int		intr_cap = 0;
	int		inum = 0;
	ddi_intr_handler_t	**isr_tab = NULL;
	int		isr_tab_size = 0;

	PEPB_DEBUG((CE_NOTE, "pepb_intr_init: Attaching %s handler\n",
	    (intr_type == DDI_INTR_TYPE_MSI) ? "MSI" : "INTx"));

	/*
	 * Get number of requested interrupts.	If none requested or DDI_FAILURE
	 * just return DDI_SUCCESS.
	 *
	 * Several Bridges/Switches will not have this property set, resulting
	 * in a FAILURE, if the device is not configured in a way that
	 * interrupts are needed. (eg. hotplugging)
	 */
	ret = ddi_intr_get_nintrs(dip, intr_type, &request);
	if ((ret != DDI_SUCCESS) || (request == 0)) {
		PEPB_DEBUG((CE_NOTE, "ddi_intr_get_nintrs ret:%d req:%d\n",
		    ret, request));
		return (DDI_FAILURE);
	}

	PEPB_DEBUG((CE_NOTE, "ddi_intr_get_nintrs: NINTRS = %x\n", request));

	/* Allocate an array of interrupt handlers */
	pepb_p->htable_size = sizeof (ddi_intr_handle_t) * request;
	pepb_p->htable = kmem_zalloc(pepb_p->htable_size, KM_SLEEP);
	pepb_p->soft_state |= PEPB_SOFT_STATE_INIT_HTABLE;

	ret = ddi_intr_alloc(dip, pepb_p->htable, intr_type, inum, request,
	    &count, DDI_INTR_ALLOC_NORMAL);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		PEPB_DEBUG((CE_NOTE, "ddi_intr_alloc() ret: %d ask: %d"
		    " actual: %d\n", ret, request, count));
		goto fail;
	}

	/* Save the actual number of interrupts allocated */
	pepb_p->intr_count = count;
#ifdef	DEBUG
	if (count < request)
		PEPB_DEBUG((CE_WARN, "Requested Intr: %d Received: %d\n",
		    request, count));
#endif	/* DEBUG */
	pepb_p->soft_state |= PEPB_SOFT_STATE_INIT_ALLOC;

	/* Get interrupt priority */
	ret = ddi_intr_get_pri(pepb_p->htable[0], &pepb_p->intr_priority);
	if (ret != DDI_SUCCESS) {
		PEPB_DEBUG((CE_WARN, "ddi_intr_get_pri() ret: %d\n", ret));
		goto fail;
	}

	/* initialize the interrupt mutex */
	mutex_init(&pepb_p->pepb_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pepb_p->intr_priority));
	pepb_p->soft_state |= PEPB_SOFT_STATE_INIT_MUTEX;

	isr_tab_size = sizeof (*isr_tab) * pepb_p->intr_count;
	isr_tab = kmem_alloc(isr_tab_size, KM_SLEEP);
	if (pepb_enable_msi && pepb_p->intr_count == 2 &&
	    intr_type == DDI_INTR_TYPE_MSI &&
	    pepb_intr_on_root_port(dip) == DDI_SUCCESS) {
		isr_tab[0] = pepb_pwr_msi_intr;
		isr_tab[1] = pepb_err_msi_intr;
	} else
		isr_tab[0] = pepb_intx_intr;

	for (count = 0; count < pepb_p->intr_count; count++) {
		ret = ddi_intr_add_handler(pepb_p->htable[count],
		    isr_tab[count], (caddr_t)pepb_p,
		    (caddr_t)(uintptr_t)(inum + count));

		if (ret != DDI_SUCCESS) {
			PEPB_DEBUG((CE_WARN, "Cannot add interrupt(%d)\n",
			    ret));
			break;
		}
	}

	kmem_free(isr_tab, isr_tab_size);

	/* If unsucessful, remove the added handlers */
	if (ret != DDI_SUCCESS) {
		for (x = 0; x < count; x++) {
			(void) ddi_intr_remove_handler(pepb_p->htable[x]);
		}
		goto fail;
	}

	pepb_p->soft_state |= PEPB_SOFT_STATE_INIT_HANDLER;

	(void) ddi_intr_get_cap(pepb_p->htable[0], &intr_cap);

	if (intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(pepb_p->htable,
		    pepb_p->intr_count);
		pepb_p->soft_state |= PEPB_SOFT_STATE_INIT_BLOCK;
	} else {
		for (count = 0; count < pepb_p->intr_count; count++) {
			(void) ddi_intr_enable(pepb_p->htable[count]);
		}
	}
	pepb_p->soft_state |= PEPB_SOFT_STATE_INIT_ENABLE;

	/* Save the interrupt type */
	pepb_p->intr_type = intr_type;

	return (DDI_SUCCESS);

fail:
	pepb_intr_fini(pepb_p);

	return (DDI_FAILURE);
}

static void
pepb_intr_fini(pepb_devstate_t *pepb_p)
{
	int x;
	int count = pepb_p->intr_count;
	int flags = pepb_p->soft_state;

	if ((flags & PEPB_SOFT_STATE_INIT_ENABLE) &&
	    (flags & PEPB_SOFT_STATE_INIT_BLOCK)) {
		(void) ddi_intr_block_disable(pepb_p->htable, count);
		flags &= ~(PEPB_SOFT_STATE_INIT_ENABLE |
		    PEPB_SOFT_STATE_INIT_BLOCK);
	}

	if (flags & PEPB_SOFT_STATE_INIT_MUTEX) {
		/* destroy the mutex */
		mutex_destroy(&pepb_p->pepb_mutex);
	}

	for (x = 0; x < count; x++) {
		if (flags & PEPB_SOFT_STATE_INIT_ENABLE)
			(void) ddi_intr_disable(pepb_p->htable[x]);

		if (flags & PEPB_SOFT_STATE_INIT_HANDLER)
			(void) ddi_intr_remove_handler(pepb_p->htable[x]);

		if (flags & PEPB_SOFT_STATE_INIT_ALLOC)
			(void) ddi_intr_free(pepb_p->htable[x]);
	}

	flags &= ~(PEPB_SOFT_STATE_INIT_ENABLE |
	    PEPB_SOFT_STATE_INIT_HANDLER |
	    PEPB_SOFT_STATE_INIT_ALLOC | PEPB_SOFT_STATE_INIT_MUTEX);

	if (flags & PEPB_SOFT_STATE_INIT_HTABLE)
		kmem_free(pepb_p->htable, pepb_p->htable_size);

	flags &= ~PEPB_SOFT_STATE_INIT_HTABLE;

	pepb_p->soft_state &= flags;
}

/*
 * pepb_intx_intr()
 *
 * This is the common interrupt handler for both hotplug and non-hotplug
 * interrupts. For handling hot plug interrupts it calls pciehpc_intr().
 *
 * NOTE: Currently only hot plug interrupts are enabled so it simply
 * calls pciehpc_intr(). This is for INTx interrupts *ONLY*.
 */
/*ARGSUSED*/
static uint_t
pepb_intx_intr(caddr_t arg, caddr_t arg2)
{
	pepb_devstate_t *pepb_p = (pepb_devstate_t *)arg;
	int ret = DDI_INTR_UNCLAIMED;

	if (!(pepb_p->soft_state & PEPB_SOFT_STATE_INIT_ENABLE))
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&pepb_p->pepb_mutex);

	/* if HPC is initialized then call the interrupt handler */
	if (pepb_p->inband_hpc == INBAND_HPC_PCIE)
		ret =  pciehpc_intr(pepb_p->dip);

	mutex_exit(&pepb_p->pepb_mutex);

	return (ret);
}

/*
 * pepb_intr_on_root_port()
 *
 * This helper function checks if the device is a Nvidia RC, Intel 5000 or 7300
 * or not
 */
static int
pepb_intr_on_root_port(dev_info_t *dip)
{
	int ret = DDI_FAILURE;
	ddi_acc_handle_t handle;
	uint16_t vendor_id, device_id;

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (ret);

	vendor_id = pci_config_get16(handle, PCI_CONF_VENID);
	device_id = pci_config_get16(handle, PCI_CONF_DEVID);
	if ((vendor_id == NVIDIA_VENDOR_ID) && NVIDIA_PCIE_RC_DEV_ID(device_id))
		ret = DDI_SUCCESS;
	else if ((vendor_id == INTEL_VENDOR_ID) &&
	    INTEL_NB5000_PCIE_DEV_ID(device_id) && !pcie_intel_error_disable)
		ret = DDI_SUCCESS;

	pci_config_teardown(&handle);
	return (ret);
}

/*
 * pepb_pwr_msi_intr()
 *
 * This is the MSI interrupt handler for PM related events.
 */
/*ARGSUSED*/
static uint_t
pepb_pwr_msi_intr(caddr_t arg, caddr_t arg2)
{
	pepb_devstate_t	*pepb_p = (pepb_devstate_t *)arg;

	if (!(pepb_p->soft_state & PEPB_SOFT_STATE_INIT_ENABLE))
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&pepb_p->pepb_mutex);
	PEPB_DEBUG((CE_NOTE, "pepb_pwr_msi_intr: received intr number %d\n",
	    (int)(uintptr_t)arg2));
	mutex_exit(&pepb_p->pepb_mutex);
	return (DDI_INTR_CLAIMED);
}

static int
pepb_pcie_port_type(dev_info_t *dip, ddi_acc_handle_t handle)
{
	uint_t cap_loc;

	/* Need to look at the port type information here */
	cap_loc = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", PCI_CAP_NEXT_PTR_NULL);

	return (cap_loc == PCI_CAP_NEXT_PTR_NULL ? -1 :
	    pci_config_get16(handle, cap_loc + PCIE_PCIECAP) &
	    PCIE_PCIECAP_DEV_TYPE_MASK);
}

/*ARGSUSED*/
int
pepb_fm_init(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pepb_devstate_t  *pepb = ddi_get_soft_state(pepb_state,
	    ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = pepb->pepb_fm_ibc;

	return (pepb->pepb_fmcap);
}

/*ARGSUSED*/
static uint_t
pepb_err_msi_intr(caddr_t arg, caddr_t arg2)
{
	pepb_devstate_t *pepb_p = (pepb_devstate_t *)arg;
	dev_info_t	*dip = pepb_p->dip;
	ddi_fm_error_t	derr;
	int		sts;

	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;

	if (!(pepb_p->soft_state & PEPB_SOFT_STATE_INIT_ENABLE))
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&pepb_p->pepb_peek_poke_mutex);
	mutex_enter(&pepb_p->pepb_err_mutex);
	PEPB_DEBUG((CE_NOTE, "pepb_err_msi_intr: received intr number %d\n",
	    (int)(uintptr_t)arg2));

	if (pepb_p->pepb_fmcap & DDI_FM_EREPORT_CAPABLE)
		sts = pf_scan_fabric(dip, &derr, NULL);

	mutex_exit(&pepb_p->pepb_err_mutex);
	mutex_exit(&pepb_p->pepb_peek_poke_mutex);

	if (pepb_die & sts)
		fm_panic("%s-%d: PCI(-X) Express Fatal Error",
		    ddi_driver_name(dip), ddi_get_instance(dip));

	return (DDI_INTR_CLAIMED);
}

static int
pepb_check_slot_disabled(dev_info_t *dip)
{
	int			rval = 0;
	uint8_t			pcie_cap_ptr;
	ddi_acc_handle_t	config_handle;

	if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS)
		return (rval);

	pcie_cap_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", PCI_CAP_NEXT_PTR_NULL);

	if (pcie_cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		if (pci_config_get16(config_handle,
		    pcie_cap_ptr + PCIE_LINKCTL) & PCIE_LINKCTL_LINK_DISABLE)
			rval = 1;
	}

	pci_config_teardown(&config_handle);
	return (rval);
}

static int
pepb_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_open(devp, flags, otyp, credp));
}

static int
pepb_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_close(dev, flags, otyp, credp));
}

static int
pepb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	int			rv, inst;
	pepb_devstate_t		*pepb;
	dev_info_t		*dip;

	rv = (pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode, credp,
	    rvalp);

	/*
	 * like in attach, since hotplugging can change error registers,
	 * we need to ensure that the proper bits are set on this port
	 * after a configure operation
	 */
	if (rv == HPC_SUCCESS && cmd == DEVCTL_AP_CONFIGURE) {
		inst = PCIHP_AP_MINOR_NUM_TO_INSTANCE(getminor(dev));
		pepb = ddi_get_soft_state(pepb_state, inst);
		dip = pepb->dip;

		pepb_intel_serr_workaround(dip);
		pepb_intel_rber_workaround(dip);
		pepb_intel_sw_workaround(dip);
	}

	return (rv);
}

static int
pepb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int flags, char *name, caddr_t valuep, int *lengthp)
{
	return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

static int
pepb_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	return (pcihp_info(dip, cmd, arg, result));
}

void
pepb_peekpoke_cb(dev_info_t *dip, ddi_fm_error_t *derr) {
	(void) pf_scan_fabric(dip, derr, NULL);
}

typedef struct x86_error_reg {
	uint32_t	offset;
	uint_t		size;
	uint32_t	mask;
	uint32_t	value;
} x86_error_reg_t;

typedef struct x86_error_tbl {
	uint16_t	vendor_id;
	uint16_t	device_id_low;
	uint16_t	device_id_high;
	uint8_t		rev_id_low;
	uint8_t		rev_id_high;
	x86_error_reg_t	*error_regs;
	int		error_regs_len;
} x86_error_tbl_t;

/*
 * Chipset and device specific settings that are required for error handling
 * (reporting, fowarding, and response at the RC) beyond the standard
 * registers in the PCIE and AER caps.
 *
 * The Northbridge Root Port settings also apply to the ESI port.  The ESI
 * port is a special leaf device but functions like a root port connected
 * to the Southbridge and receives all the onboard Southbridge errors
 * including those from Southbridge Root Ports.  However, this does not
 * include the Southbridge Switch Ports which act like normal switch ports
 * and is connected to the Northbridge through a separate link.
 *
 * PCIE errors from the ESB2 Southbridge RPs are simply fowarded to the ESI
 * port on the Northbridge.
 *
 * Currently without FMA support, we want UEs (Fatal and Non-Fatal) to panic
 * the system, except for URs.  We do this by having the Root Ports respond
 * with a System Error and having that trigger a Machine Check (MCE).
 */

/*
 * 7300 Northbridge Root Ports
 */
static x86_error_reg_t intel_7300_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE */
	{0x88,  16, 0x0,	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0,	PCIE_AER_UCE_UR},

	/* PEXCTRL[21] check for certain malformed TLP types */
	{0x48,	32, 0xFFFFFFFF, 0x200000},

	/* PEX_ERR_DOCMD[7:0] SERR on FE & NFE triggers MCE */
	{0x144,	8,  0x0, 	0xF0},

	/* EMASK_UNCOR_PEX[21:0] UE mask */
	{0x148,	32, 0x0, 	PCIE_AER_UCE_UR},

	/* EMASK_RP_PEX[2:0] FE, UE, CE message detect mask */
	{0x150,	8,  0x0, 	0x1},
};
#define	INTEL_7300_RP_REGS_LEN \
	(sizeof (intel_7300_rp_regs) / sizeof (x86_error_reg_t))


/*
 * 5000 Northbridge Root Ports
 */
#define	intel_5000_rp_regs		intel_7300_rp_regs
#define	INTEL_5000_RP_REGS_LEN		INTEL_7300_RP_REGS_LEN


/*
 * 5400 Northbridge Root Ports
 */
static x86_error_reg_t intel_5400_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE */
	{0x88,  16, 0x0,	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0,	PCIE_AER_UCE_UR},

	/* PEXCTRL[21] check for certain malformed TLP types */
	{0x48,	32, 0xFFFFFFFF, 0x200000},

	/* PEX_ERR_DOCMD[11:0] SERR on FE, NFE from PCIE & Unit triggers MCE */
	{0x144,	16,  0x0, 	0xFF0},

	/* PEX_ERR_PIN_MASK[4:0] do not mask ERR[2:0] pins used by DOCMD */
	{0x146,	16,  0x0, 	0x10},

	/* EMASK_UNCOR_PEX[21:0] UE mask */
	{0x148,	32, 0x0, 	PCIE_AER_UCE_UR},

	/* EMASK_RP_PEX[2:0] FE, UE, CE message detect mask */
	{0x150,	8,  0x0, 	0x1},
};
#define	INTEL_5400_RP_REGS_LEN \
	(sizeof (intel_5400_rp_regs) / sizeof (x86_error_reg_t))


/*
 * ESB2 Southbridge Root Ports
 */
static x86_error_reg_t intel_esb2_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE */
	{0x5c,  16, 0x0,	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* UEM[20:0] UE mask (write-once) */
	{0x148, 32, 0x0,	PCIE_AER_UCE_UR},
};
#define	INTEL_ESB2_RP_REGS_LEN \
	(sizeof (intel_esb2_rp_regs) / sizeof (x86_error_reg_t))


/*
 * ESB2 Southbridge Switch Ports
 */
static x86_error_reg_t intel_esb2_sw_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0,	PCIE_AER_UCE_UR},
};
#define	INTEL_ESB2_SW_REGS_LEN \
	(sizeof (intel_esb2_sw_regs) / sizeof (x86_error_reg_t))


x86_error_tbl_t x86_error_init_tbl[] = {
	/* Intel 7300: 3600 = ESI, 3604-360A = NB root ports */
	{0x8086, 0x3600, 0x3600, 0x0, 0xFF,
		intel_7300_rp_regs, INTEL_7300_RP_REGS_LEN},
	{0x8086, 0x3604, 0x360A, 0x0, 0xFF,
		intel_7300_rp_regs, INTEL_7300_RP_REGS_LEN},

	/* Intel 5000: 25C0, 25D0, 25D4, 25D8 = ESI */
	{0x8086, 0x25C0, 0x25C0, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25D0, 0x25D0, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25D4, 0x25D4, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25D8, 0x25D8, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},

	/* Intel 5000: 25E2-25E7 and 25F7-25FA = NB root ports */
	{0x8086, 0x25E2, 0x25E7, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25F7, 0x25FA, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},

	/* Intel 5400: 4000-4001, 4003 = ESI and 4021-4029 = NB root ports */
	{0x8086, 0x4000, 0x4001, 0x0, 0xFF,
		intel_5400_rp_regs, INTEL_5400_RP_REGS_LEN},
	{0x8086, 0x4003, 0x4003, 0x0, 0xFF,
		intel_5400_rp_regs, INTEL_5400_RP_REGS_LEN},
	{0x8086, 0x4021, 0x4029, 0x0, 0xFF,
		intel_5400_rp_regs, INTEL_5400_RP_REGS_LEN},

	/* Intel 631xESB/632xESB aka ESB2: 2690-2697 = SB root ports */
	{0x8086, 0x2690, 0x2697, 0x0, 0xFF,
		intel_esb2_rp_regs, INTEL_ESB2_RP_REGS_LEN},

	/* Intel Switches on esb2: 3500-3503, 3510-351B */
	{0x8086, 0x3500, 0x3503, 0x0, 0xFF,
		intel_esb2_sw_regs, INTEL_ESB2_SW_REGS_LEN},
	{0x8086, 0x3510, 0x351B, 0x0, 0xFF,
		intel_esb2_sw_regs, INTEL_ESB2_SW_REGS_LEN},

	/* XXX Intel PCIe-PCIx on esb2: 350C */
};
static int x86_error_init_tbl_len =
	sizeof (x86_error_init_tbl) / sizeof (x86_error_tbl_t);


static int
pepb_get_bdf(dev_info_t *dip, int *busp, int *devp, int *funcp)
{
	pci_regspec_t	*regspec;
	int		reglen;
	int		rv;

	rv = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&regspec, (uint_t *)&reglen);
	if (rv != DDI_SUCCESS)
		return (rv);

	if (reglen < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(regspec);
		return (DDI_FAILURE);
	}

	/* Get phys_hi from first element.  All have same bdf. */
	*busp = PCI_REG_BUS_G(regspec->pci_phys_hi);
	*devp = PCI_REG_DEV_G(regspec->pci_phys_hi);
	*funcp = PCI_REG_FUNC_G(regspec->pci_phys_hi);

	ddi_prop_free(regspec);
	return (DDI_SUCCESS);
}

/*
 * Temporary workaround until there is full error handling support on Intel.
 * The main goal of this workaround is to make the system Machine Check/Panic if
 * an UE is detected in the fabric.
 */
static void
pepb_intel_serr_workaround(dev_info_t *dip)
{
	uint16_t		vid, did;
	uint8_t			rid;
	int			bus, dev, func;
	int			i, j;
	x86_error_tbl_t		*tbl;
	x86_error_reg_t		*reg;
	uint32_t		data, value;
	ddi_acc_handle_t	cfg_hdl;

	if (pepb_intel_workaround_disable)
		return;

	(void) pci_config_setup(dip, &cfg_hdl);
	vid = pci_config_get16(cfg_hdl, PCI_CONF_VENID);
	did = pci_config_get16(cfg_hdl, PCI_CONF_DEVID);
	rid = pci_config_get8(cfg_hdl, PCI_CONF_REVID);

	if (pepb_get_bdf(dip, &bus, &dev, &func) != DDI_SUCCESS) {
		PEPB_DEBUG((CE_WARN, "%s#%d: pepb_get_bdf() failed",
		    ddi_driver_name(dip), ddi_get_instance(dip)));
		return;
	}

	PEPB_DEBUG((CE_NOTE, "VID:0x%x DID:0x%x RID:0x%x bdf=%x.%x.%x, "
	    "dip:0x%p", vid, did, rid, bus, dev, func, (void *)dip));

	tbl = x86_error_init_tbl;
	for (i = 0; i < x86_error_init_tbl_len; i++, tbl++) {
		if (!((vid == tbl->vendor_id) &&
		    (did >= tbl->device_id_low) &&
		    (did <= tbl->device_id_high) &&
		    (rid >= tbl->rev_id_low) &&
		    (rid <= tbl->rev_id_high)))
			continue;

		reg = tbl->error_regs;
		for (j = 0; j < tbl->error_regs_len; j++, reg++) {
			data = 0xDEADBEEF;
			value = 0xDEADBEEF;
			switch (reg->size) {
			case 32:
				data = (uint32_t)pci_config_get32(cfg_hdl,
				    reg->offset);
				value = (data & reg->mask) | reg->value;
				pci_config_put32(cfg_hdl, reg->offset, value);
				value = (uint32_t)pci_config_get32(cfg_hdl,
				    reg->offset);
				break;
			case 16:
				data = (uint32_t)pci_config_get16(cfg_hdl,
				    reg->offset);
				value = (data & reg->mask) | reg->value;
				pci_config_put16(cfg_hdl, reg->offset,
				    (uint16_t)value);
				value = (uint32_t)pci_config_get16(cfg_hdl,
				    reg->offset);
				break;
			case 8:
				data = (uint32_t)pci_config_get8(cfg_hdl,
				    reg->offset);
				value = (data & reg->mask) | reg->value;
				pci_config_put8(cfg_hdl, reg->offset,
				    (uint8_t)value);
				value = (uint32_t)pci_config_get8(cfg_hdl,
				    reg->offset);
				break;
			}
			PEPB_DEBUG((CE_NOTE, "size:%d off:0x%x mask:0x%x "
			    "value:0x%x + orig:0x%x -> 0x%x",
			    reg->size, reg->offset, reg->mask, reg->value,
			    data, value));
		}

		/*
		 * Make sure on this platform that devices supporting RBER
		 * will set their UE severity appropriately
		 */
		pepb_do_rber_sev = B_TRUE;
	}

	pci_config_teardown(&cfg_hdl);
}

/*
 * For devices that support Role Base Errors, make several UE have a FATAL
 * severity.  That way a Fatal Message will be sent instead of a Correctable
 * Message.  Without full FMA support, CEs will be ignored.
 */
uint32_t pepb_rber_sev = (PCIE_AER_UCE_TRAINING | PCIE_AER_UCE_DLP |
    PCIE_AER_UCE_SD | PCIE_AER_UCE_PTLP | PCIE_AER_UCE_FCP | PCIE_AER_UCE_TO |
    PCIE_AER_UCE_CA | PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP | PCIE_AER_UCE_ECRC);

static void
pepb_intel_rber_workaround(dev_info_t *dip)
{
	uint16_t pcie_off, aer_off;
	ddi_acc_handle_t cfg_hdl;
	uint32_t rber;

	if (pepb_intel_workaround_disable)
		return;
	if (!pepb_do_rber_sev)
		return;

	/* check config setup since it can be called on other dips */
	if (pci_config_setup(dip, &cfg_hdl) != DDI_SUCCESS) {
		PEPB_DEBUG((CE_NOTE, "pepb_intel_rber_workaround: config "
		    "setup failed on dip 0x%p", (void *)dip));
		return;
	}

	if (PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_ID_PCI_E, &pcie_off) ==
	    DDI_FAILURE)
		goto done;

	if (PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_AER),
	    &aer_off) == DDI_FAILURE)
		goto done;

	rber = PCI_CAP_GET16(cfg_hdl, NULL, pcie_off, PCIE_DEVCAP) &
	    PCIE_DEVCAP_ROLE_BASED_ERR_REP;
	if (!rber)
		goto done;

	PCI_XCAP_PUT32(cfg_hdl, NULL, aer_off, PCIE_AER_UCE_SERV,
	    pepb_rber_sev);

done:
	pci_config_teardown(&cfg_hdl);
}

/*
 * Workaround for certain switches regardless of platform
 */
static void
pepb_intel_sw_workaround(dev_info_t *dip)
{
	uint16_t		vid, regw;
	int			port_type;
	ddi_acc_handle_t	cfg_hdl;

	if (pepb_intel_workaround_disable)
		return;

	(void) pepb_pcie_device_type(dip, &port_type);
	if (!((port_type == PCIE_PCIECAP_DEV_TYPE_UP) ||
	    (port_type == PCIE_PCIECAP_DEV_TYPE_DOWN)))
		return;

	(void) pci_config_setup(dip, &cfg_hdl);
	vid = pci_config_get16(cfg_hdl, PCI_CONF_VENID);

	/*
	 * Intel and PLX switches require SERR in CMD reg to foward error
	 * messages, though this is not PCIE spec-compliant behavior.
	 * To prevent the switches themselves from reporting errors on URs
	 * when the CMD reg has SERR enabled (which is expected according to
	 * the PCIE spec) we rely on masking URs in the AER cap.
	 */
	if (vid == 0x8086 || vid == 0x10B5) {
		regw = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
		pci_config_put16(cfg_hdl, PCI_CONF_COMM,
		    regw | PCI_COMM_SERR_ENABLE);
	}

	pci_config_teardown(&cfg_hdl);
}
