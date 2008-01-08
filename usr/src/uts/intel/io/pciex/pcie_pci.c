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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


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
#include <sys/pcie_impl.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/hotplug/pci/pciehpc_impl.h>
#include <io/pciex/pcie_error.h>
#include <io/pciex/pcie_nvidia.h>
#include <io/pciex/pcie_nb5000.h>

#ifdef	DEBUG
int pepb_debug = 0;
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

static int	pepb_fm_callback(dev_info_t *, ddi_fm_error_t *, const void *);

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
	&pepb_bus_ops		/* bus operations */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"PCIe to PCI nexus driver 1.10",
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
	ddi_acc_handle_t	config_handle;
	int			port_type;
	int			inband_hpc;

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
	 * interrupt support
	 */
	pcie_bridge_intr_state_t	istate;

	kmutex_t		pepb_err_mutex;	/* Error handling mutex */
	kmutex_t		pepb_peek_poke_mutex;
	int			pepb_fmcap;
	ddi_iblock_cookie_t	pepb_fm_ibc;
} pepb_devstate_t;


/* undefined port_type; cannot be 0 or a valid PCIE device type value */
#define	PEPB_PORT_TYPE_NULL	-1


/* panic on unknown flag, defaulted to on */
int pepb_panic_unknown = 1;
int pepb_panic_fatal = 1;


extern errorq_t *pci_target_queue;

/*
 * forward function declarations:
 */
static void	pepb_uninitchild(dev_info_t *);
static int 	pepb_initchild(dev_info_t *child);
static void 	pepb_save_config_regs(pepb_devstate_t *pepb_p);
static void	pepb_restore_config_regs(pepb_devstate_t *pepb_p);
static int	pepb_pcie_device_type(pepb_devstate_t *pepb_p);
static uint_t	pepb_intr_handler(caddr_t arg1, caddr_t arg2);


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
	const char		*drvnm;
	int			rv;
	char			*device_type;
	pepb_devstate_t		*pepb;
	ddi_acc_handle_t	config_handle;
	pciehpc_hp_mode_t	hp_mode;

	drvnm = ddi_driver_name(devi);
	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_RESUME:

		/*
		 * Get the soft state structure for the bridge.
		 */
		pepb = ddi_get_soft_state(pepb_state, instance);
		pepb_restore_config_regs(pepb);

		if (pcie_bridge_intr_reinit(&pepb->istate) != DDI_SUCCESS)
			cmn_err(CE_CONT, "?%s%d: Failed to reinitialize "
			    "interrupts on resume\n", drvnm, instance);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	case DDI_ATTACH:
		break;
	}

	if (pci_config_setup(devi, &config_handle) != DDI_SUCCESS) {
		PEPB_DEBUG((CE_WARN, "%s%d: pci_config_setup() failed",
		    drvnm, instance));
		return (DDI_FAILURE);
	}

	/*
	 * If the link is disabled then there is no need to attach
	 */
	if (pcie_bridge_is_link_disabled(devi, config_handle)) {
		PEPB_DEBUG((CE_NOTE, "%s%d: link disabled",
		    drvnm, instance));
		pci_config_teardown(&config_handle);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate and get soft state structure.
	 */
	if (ddi_soft_state_zalloc(pepb_state, instance) != DDI_SUCCESS) {
		pci_config_teardown(&config_handle);
		return (DDI_FAILURE);
	}
	pepb = ddi_get_soft_state(pepb_state, instance);
	pepb->dip = devi;
	pepb->config_handle = config_handle;

	/*
	 * initialize fma support
	 */
	pci_targetq_init();
	pepb->pepb_fmcap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;
	ddi_fm_init(devi, &pepb->pepb_fmcap, &pepb->pepb_fm_ibc);

	mutex_init(&pepb->pepb_err_mutex, NULL, MUTEX_DRIVER,
	    (void *)pepb->pepb_fm_ibc);
	mutex_init(&pepb->pepb_peek_poke_mutex, NULL, MUTEX_DRIVER,
	    (void *)pepb->pepb_fm_ibc);

	if (pepb->pepb_fmcap & (DDI_FM_ERRCB_CAPABLE | DDI_FM_EREPORT_CAPABLE))
		pci_ereport_setup(devi);

	if (pepb->pepb_fmcap & DDI_FM_ERRCB_CAPABLE)
		ddi_fm_handler_register(devi, pepb_fm_callback, NULL);

	/*
	 * Property setup
	 * - device_type: IEEE1275 prop denoting type of child/secondary bus
	 * - pci-hotplug-type: type of hotplug potentially supported derived
	 *   from bridge config regs
	 */
	if (pepb_pcie_device_type(pepb) == DDI_SUCCESS)
		device_type = "pciex";
	else
		device_type = "pci";

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "device_type", device_type);

	pepb->inband_hpc = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, "pci-hotplug-type", INBAND_HPC_NONE);

	/*
	 * Initialize interrupt handlers.
	 * Failure means no PCIE advanced error reporting and partial native
	 * hotplug functionality
	 */
	pepb->istate.dip = pepb->dip;
	pepb->istate.cfghdl = pepb->config_handle;
	pepb->istate.datap = pepb;

	rv = pcie_bridge_intr_init(&pepb->istate, pepb_intr_handler);
	if (rv != DDI_SUCCESS && rv != DDI_ENOTSUP)
		cmn_err(CE_CONT, "?%s%d: Failed to initialize interrupts\n",
		    drvnm, instance);

	/*
	 * Initialize hotplug support on this bus. At minimum
	 * (for non hotplug bus) this would create ":devctl" minor
	 * node to support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls
	 * to this bus.
	 */
	if (pcihp_init(devi) != DDI_SUCCESS)
		cmn_err(CE_WARN, "%s%d: Failed to setup hotplug framework",
		    drvnm, instance);
	else {
		/*
		 * grab istate lock if interrupts are enabled to update
		 * inband_hpc after HP framework initializes
		 */
		if (pepb->istate.iflags & PCIE_BRIDGE_INTR_INIT_ENABLE)
			mutex_enter(&pepb->istate.ilock);

		/*
		 * If there is an inband PCI-E HPC then initialize it.
		 * The failure is not considered fatal for the system
		 * so log the message and ignore the failure.
		 *
		 * Also optimize intr handling where if we are not using
		 * native hotplug mode, we do not ask the hotplug
		 * framework to check interrupt status.  Note that in
		 * this case, istate.inband_hpc will differ from
		 * pepb->inband_hpc.
		 */
		if (pepb->inband_hpc == INBAND_HPC_PCIE &&
		    pciehpc_init(devi, NULL) == DDI_SUCCESS) {

			hp_mode = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
			    DDI_PROP_DONTPASS, "pcie-hotplug-mode", -1);

			if (hp_mode != PCIEHPC_NATIVE_HP_MODE) {
				PEPB_DEBUG((CE_NOTE, "%s%d: not native "
				    "hotplug mode; disabling hp intr checking",
				    drvnm, instance));
				pepb->istate.inband_hpc = INBAND_HPC_NONE;
			}

		} else if (pepb->inband_hpc == INBAND_HPC_PCIE) {
			pepb->inband_hpc = INBAND_HPC_NONE;
			pepb->istate.inband_hpc = INBAND_HPC_NONE;
			cmn_err(CE_CONT, "!%s%d: Failed to initialize inband "
			"hotplug controller\n", drvnm, instance);
		}

		if (pepb->istate.iflags & PCIE_BRIDGE_INTR_INIT_ENABLE)
			mutex_exit(&pepb->istate.ilock);
	}

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
	pcie_bridge_intr_fini(&pepb->istate);

	/* uninitialize inband PCI-E HPC if present */
	if (pepb->inband_hpc == INBAND_HPC_PCIE)
		(void) pciehpc_uninit(devi);

	/*
	 * Uninitialize hotplug support on this bus.
	 */
	(void) pcihp_uninit(devi);
	if (pepb->pepb_fmcap & DDI_FM_ERRCB_CAPABLE)
		ddi_fm_handler_unregister(devi);

	if (pepb->pepb_fmcap & (DDI_FM_ERRCB_CAPABLE | DDI_FM_EREPORT_CAPABLE))
		pci_ereport_teardown(devi);

	mutex_destroy(&pepb->pepb_err_mutex);
	mutex_destroy(&pepb->pepb_peek_poke_mutex);
	ddi_fm_fini(devi);

	pci_config_teardown(&pepb->config_handle);

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
	pepb_devstate_t		*pepb;

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
		pepb = ddi_get_soft_state(pepb_state, ddi_get_instance(dip));
		if (pepb->port_type != PCIE_PCIECAP_DEV_TYPE_ROOT)
			return (ddi_ctlops(dip, rdip, ctlop, arg, result));
		return (pci_peekpoke_check(dip, rdip, ctlop, arg, result,
		    ddi_ctlops, &pepb->pepb_err_mutex,
		    &pepb->pepb_peek_poke_mutex));

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
	ddi_acc_handle_t cfg_hdl;
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

	if (pci_config_setup(child, &cfg_hdl) == DDI_SUCCESS) {
		(void) pcie_error_enable(child, cfg_hdl);
		pci_config_teardown(&cfg_hdl);
	}

	return (DDI_SUCCESS);
}

static void
pepb_uninitchild(dev_info_t *dip)
{
	ddi_acc_handle_t		cfg_hdl;
	struct ddi_parent_private_data	*pdptr;

	/*
	 * Do it way early.
	 * Otherwise ddi_map() call form pcie_error_fini crashes
	 */
	if (pci_config_setup(dip, &cfg_hdl) == DDI_SUCCESS) {
		pcie_error_disable(dip, cfg_hdl);
		pci_config_teardown(&cfg_hdl);
	}

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
	ddi_acc_handle_t config_handle = pepb_p->config_handle;

	for (i = 0, dip = ddi_get_child(pepb_p->dip); dip != NULL;
	    i++, dip = ddi_get_next_sibling(dip)) {

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
	ddi_acc_handle_t config_handle = pepb_p->config_handle;

	for (i = 0; i < pepb_p->config_state_index; i++) {
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
	}
}

/*
 * sets pepb_p->port_type to a PCIE defined device type
 * and returns DDI_SUCCESS if the downstream/secondary side is a PCIE bus
 */
static int
pepb_pcie_device_type(pepb_devstate_t *pepb_p)
{
	int pcie_loc;
	dev_info_t *dip = pepb_p->dip;
	ddi_acc_handle_t cfghdl = pepb_p->config_handle;

	pepb_p->port_type = PEPB_PORT_TYPE_NULL;

	pcie_loc = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", 0);
	if (pcie_loc == 0)
		return (DDI_FAILURE);

	pepb_p->port_type = pci_config_get16(cfghdl, pcie_loc + PCIE_PCIECAP) &
	    PCIE_PCIECAP_DEV_TYPE_MASK;

	switch (pepb_p->port_type) {
	case PCIE_PCIECAP_DEV_TYPE_UP:
	case PCIE_PCIECAP_DEV_TYPE_DOWN:
	case PCIE_PCIECAP_DEV_TYPE_ROOT:
	case PCIE_PCIECAP_DEV_TYPE_PCI2PCIE:
		return (DDI_SUCCESS);
	default:
		break;
	}
	return (DDI_FAILURE);
}


/*
 * <arg1> contains the softstate while <arg2> contains the inum
 * responsible for the invocation
 */
static uint_t
pepb_intr_handler(caddr_t arg1, caddr_t arg2)
{
	pcie_bridge_intr_state_t *istatep =
	    (pcie_bridge_intr_state_t *)(uintptr_t)arg1;
	int isrc = istatep->isrc_tab[(int)(uintptr_t)arg2];

	dev_info_t *dip = istatep->dip;
	ddi_acc_handle_t cfghdl = istatep->cfghdl;
	pepb_devstate_t *pepb = (pepb_devstate_t *)istatep->datap;
	int pcie_loc = istatep->pcie_loc;

	int ret = DDI_INTR_UNCLAIMED;
	ddi_fm_error_t derr;

#ifdef	DEBUG
	int inst = ddi_get_instance(dip);
	const char *drvnm = ddi_driver_name(dip);
#endif

	if (!(istatep->iflags & PCIE_BRIDGE_INTR_INIT_ENABLE))
		return (DDI_INTR_UNCLAIMED);

	if (istatep->itype == DDI_INTR_TYPE_FIXED &&
	    !(pci_config_get16(cfghdl, PCI_CONF_STAT) & PCI_STAT_INTR))
		return (DDI_INTR_UNCLAIMED);

	/*
	 * We must check all interrupt sources associated with this vector.
	 * We cannot expect to be interrupted again for each unacknowleged
	 * source.
	 */
	PEPB_DEBUG((CE_NOTE, "%s%d: Checking interrupt sources: 0x%x",
	    drvnm, inst, isrc));

	if (isrc == PCIE_BRIDGE_INTR_SRC_UNKNOWN)
		goto OUT;

	mutex_enter(&istatep->ilock);

	/*
	 * if HPC is initialized then call the hotplug interrupt handler
	 */
	if ((isrc & PCIE_BRIDGE_INTR_SRC_HP) &&
	    istatep->inband_hpc == INBAND_HPC_PCIE) {
		if (pciehpc_intr(dip) == DDI_INTR_CLAIMED) {
			ret = DDI_INTR_CLAIMED;
			PEPB_DEBUG((CE_NOTE, "%s%d: Got hotplug interrupt",
			    drvnm, inst));
		}
	}

	/*
	 * PME: just check and clear status
	 */
	if (isrc & PCIE_BRIDGE_INTR_SRC_PME &&
	    istatep->port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		uint32_t sts;

		sts = pci_config_get32(cfghdl, pcie_loc + PCIE_ROOTSTS);
		if (sts & PCIE_ROOTSTS_PME_STATUS) {
			pci_config_put32(cfghdl, pcie_loc + PCIE_ROOTSTS, sts);

			ret = DDI_INTR_CLAIMED;
			PEPB_DEBUG((CE_NOTE, "%s%d: Got PME interrupt",
			    drvnm, inst));
		}
	}

	mutex_exit(&istatep->ilock);

	/*
	 * AER
	 */
	if (isrc & PCIE_BRIDGE_INTR_SRC_AER) {
		bzero(&derr, sizeof (ddi_fm_error_t));
		derr.fme_version = DDI_FME_VERSION;

		mutex_enter(&pepb->pepb_peek_poke_mutex);
		mutex_enter(&pepb->pepb_err_mutex);

		if (pepb->pepb_fmcap & DDI_FM_EREPORT_CAPABLE)
			pci_ereport_post(dip, &derr, NULL);

		if (derr.fme_status != DDI_FM_OK) {
			ret = DDI_INTR_CLAIMED;
			PEPB_DEBUG((CE_NOTE, "%s%d: Got error interrupt",
			    drvnm, inst));
		}

		if ((pepb_panic_fatal && derr.fme_status == DDI_FM_FATAL) ||
		    (pepb_panic_unknown && derr.fme_status == DDI_FM_UNKNOWN))
			fm_panic("%s-%d: PCI(-X) Express Fatal Error",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));

		mutex_exit(&pepb->pepb_err_mutex);
		mutex_exit(&pepb->pepb_peek_poke_mutex);
	}

OUT:
#ifdef	DEBUG
	if (ret != DDI_INTR_CLAIMED)
		PEPB_DEBUG((CE_NOTE, "%s%d: Got unknown interrupt",
		    drvnm, inst));
#endif

	ret = DDI_INTR_CLAIMED;
	return (ret);
}


/*ARGSUSED*/
static int
pepb_fm_init(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pepb_devstate_t	 *pepb = ddi_get_soft_state(pepb_state,
	    ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = pepb->pepb_fm_ibc;

	return (pepb->pepb_fmcap);
}

/*ARGSUSED*/
static int
pepb_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *no_used)
{
	pepb_devstate_t *pepb_p = (pepb_devstate_t *)
	    ddi_get_soft_state(pepb_state, ddi_get_instance(dip));

	mutex_enter(&pepb_p->pepb_err_mutex);
	pci_ereport_post(dip, derr, NULL);
	mutex_exit(&pepb_p->pepb_err_mutex);
	return (derr->fme_status);
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
	return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode, credp,
	    rvalp));
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
