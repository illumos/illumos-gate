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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCI to PCI bus bridge nexus driver
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
#include <sys/hotplug/pci/pcihp.h>
#if defined(__i386) || defined(__amd64)
#include <sys/pci_intr_lib.h>
#include <sys/psm.h>
#endif

/*
 * For PCI Hotplug support, the misc/pcihp module provides devctl control
 * device and cb_ops functions to support hotplug operations.
 */
char _depends_on[] = "misc/pcihp";

/*
 * The variable controls the default setting of the command register
 * for pci devices.  See ppb_initchild() for details.
 */
#if defined(__i386) || defined(__amd64)
static ushort_t ppb_command_default = PCI_COMM_ME |
					PCI_COMM_MAE |
					PCI_COMM_IO;
#else
static ushort_t ppb_command_default = PCI_COMM_SERR_ENABLE |
					PCI_COMM_WAIT_CYC_ENAB |
					PCI_COMM_PARITY_DETECT |
					PCI_COMM_ME |
					PCI_COMM_MAE |
					PCI_COMM_IO;
#endif


static int ppb_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
	off_t, off_t, caddr_t *);
static int ppb_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
	void *, void *);
#if defined(__i386) || defined(__amd64)
static int ppb_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
	ddi_intr_handle_impl_t *, void *);

/*
 * Not to allow MSI by default except special case like AMD8132 with
 * MSI enabled.
 * However, this flag can be patched to allow MSI if needed.
 *  0 = default value, MSI is allowed only for special case
 *  1 = MSI supported without check
 * -1 = MSI not supported at all
 */
int ppb_support_msi = 0;
#endif

struct bus_ops ppb_bus_ops = {
	BUSO_REV,
	ppb_bus_map,
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
	ppb_ctlops,
	ddi_bus_prop_op,
	0,		/* (*bus_get_eventcookie)();	*/
	0,		/* (*bus_add_eventcall)();	*/
	0,		/* (*bus_remove_eventcall)();	*/
	0,		/* (*bus_post_event)();		*/
	0,		/* (*bus_intr_ctl)();		*/
	0,		/* (*bus_config)(); 		*/
	0,		/* (*bus_unconfig)(); 		*/
	NULL,		/* (*bus_fm_init)(); 		*/
	NULL,		/* (*bus_fm_fini)(); 		*/
	NULL,		/* (*bus_fm_access_enter)(); 	*/
	NULL,		/* (*bus_fm_access_exit)(); 	*/
	NULL,		/* (*bus_power)(); 	*/
#if defined(__i386) || defined(__amd64)
	ppb_intr_ops	/* (*bus_intr_op)(); 		*/
#else
	i_ddi_intr_ops	/* (*bus_intr_op)(); 		*/
#endif
};

/*
 * The goal here is to leverage off of the pcihp.c source without making
 * changes to it.  Call into it's cb_ops directly if needed.
 */
static int	ppb_open(dev_t *, int, int, cred_t *);
static int	ppb_close(dev_t, int, int, cred_t *);
static int	ppb_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	ppb_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
		    caddr_t, int *);
static int	ppb_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

struct cb_ops ppb_cb_ops = {
	ppb_open,			/* open */
	ppb_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ppb_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ppb_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};


static int ppb_probe(dev_info_t *);
static int ppb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int ppb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

struct dev_ops ppb_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	ppb_info,		/* info */
	nulldev,		/* identify */
	ppb_probe,		/* probe */
	ppb_attach,		/* attach */
	ppb_detach,		/* detach */
	nulldev,		/* reset */
	&ppb_cb_ops,		/* driver operations */
	&ppb_bus_ops		/* bus operations */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"PCI to PCI bridge nexus driver %I%",
	&ppb_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * soft state pointer and structure template:
 */
static void *ppb_state;

typedef struct {

	dev_info_t *dip;

#if defined(__sparc)
	/*
	 * configuration register state for the bus:
	 */
	uchar_t ppb_cache_line_size;
	uchar_t ppb_latency_timer;
#endif

	/*
	 * cpr support:
	 */
#define	PCI_MAX_DEVICES		32
#define	PCI_MAX_FUNCTIONS	8
#define	PCI_MAX_CHILDREN	PCI_MAX_DEVICES * PCI_MAX_FUNCTIONS
	uint_t config_state_index;
	struct {
		dev_info_t *dip;
		ushort_t command;
		uchar_t cache_line_size;
		uchar_t latency_timer;
		uchar_t header_type;
		uchar_t sec_latency_timer;
		ushort_t bridge_control;
	} config_state[PCI_MAX_CHILDREN];
} ppb_devstate_t;

#if defined(__sparc)
/*
 * The following variable enables a workaround for the following obp bug:
 *
 *	1234181 - obp should set latency timer registers in pci
 *		configuration header
 *
 * Until this bug gets fixed in the obp, the following workaround should
 * be enabled.
 */
static uint_t ppb_set_latency_timer_register = 1;

/*
 * The following variable enables a workaround for an obp bug to be
 * submitted.  A bug requesting a workaround fof this problem has
 * been filed:
 *
 *	1235094 - need workarounds on positron nexus drivers to set cache
 *		line size registers
 *
 * Until this bug gets fixed in the obp, the following workaround should
 * be enabled.
 */
static uint_t ppb_set_cache_line_size_register = 1;
#endif


/*
 * forward function declarations:
 */
static void ppb_removechild(dev_info_t *);
static int ppb_initchild(dev_info_t *child);
static void ppb_save_config_regs(ppb_devstate_t *ppb_p);
static void ppb_restore_config_regs(ppb_devstate_t *ppb_p);
#if	defined(__sparc)
static int ppb_create_pci_prop(dev_info_t *);
#endif	/* defined(__sparc) */


int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&ppb_state, sizeof (ppb_devstate_t),
	    1)) == 0 && (e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&ppb_state);
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&ppb_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
ppb_probe(dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

/*ARGSUSED*/
static int
ppb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	ppb_devstate_t *ppb;
	ddi_acc_handle_t config_handle;

	switch (cmd) {
	case DDI_ATTACH:

		/*
		 * Make sure the "device_type" property exists.
		 */
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
		    "device_type", "pci");

		/*
		 * Allocate and get soft state structure.
		 */
		instance = ddi_get_instance(devi);
		if (ddi_soft_state_zalloc(ppb_state, instance) != DDI_SUCCESS)
			return (DDI_FAILURE);
		ppb = ddi_get_soft_state(ppb_state, instance);
		ppb->dip = devi;
		if (pci_config_setup(devi, &config_handle) != DDI_SUCCESS) {
			ddi_soft_state_free(ppb_state, instance);
			return (DDI_FAILURE);
		}
#if defined(__sparc)
		ppb->ppb_cache_line_size =
			pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		ppb->ppb_latency_timer =
			pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
#endif
		pci_config_teardown(&config_handle);

		/*
		 * Initialize hotplug support on this bus. At minimum
		 * (for non hotplug bus) this would create ":devctl" minor
		 * node to support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls
		 * to this bus.
		 */
		if (pcihp_init(devi) != DDI_SUCCESS)
		    cmn_err(CE_WARN, "pci: Failed to setup hotplug framework");

		ddi_report_dev(devi);
		return (DDI_SUCCESS);

	case DDI_RESUME:

		/*
		 * Get the soft state structure for the bridge.
		 */
		ppb = ddi_get_soft_state(ppb_state, ddi_get_instance(devi));
		ppb_restore_config_regs(ppb);
		return (DDI_SUCCESS);

	default:
		break;
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ppb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	ppb_devstate_t *ppb;

	switch (cmd) {
	case DDI_DETACH:
		(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");
		/*
		 * And finally free the per-pci soft state.
		 */
		ddi_soft_state_free(ppb_state, ddi_get_instance(devi));

		/*
		 * Uninitialize hotplug support on this bus.
		 */
		(void) pcihp_uninit(devi);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		ppb = ddi_get_soft_state(ppb_state, ddi_get_instance(devi));
		ppb_save_config_regs(ppb);
		return (DDI_SUCCESS);

	default:
		break;
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ppb_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	dev_info_t *pdip;

	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)(pdip,
			rdip, mp, offset, len, vaddrp));
}

/*ARGSUSED*/
static int
ppb_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	int	reglen;
	int	rn;
	int	totreg;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCI-device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (ppb_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		ppb_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		break;

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	*(int *)result = 0;
	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip,
		DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "reg",
		(caddr_t)&drv_regp, &reglen) != DDI_SUCCESS)
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
ppb_name_child(dev_info_t *child, char *name, int namelen)
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
ppb_initchild(dev_info_t *child)
{
	struct ddi_parent_private_data *pdptr;
	char name[MAXNAMELEN];
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;
#if !defined(__i386) && !defined(__amd64)
	ushort_t bcr;
	uchar_t header_type;
#endif
#if defined(__sparc)
	int ret;
	uchar_t min_gnt, latency_timer;
	ppb_devstate_t *ppb;
#endif

	if (ppb_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
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
		if (ndi_merge_node(child, ppb_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for ddivs to run under PCI */
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

	/* transfer select properties from PROM to kernel */
#if	defined(__sparc)
	if ((ret = ppb_create_pci_prop(child)) != DDI_SUCCESS)
		return (ret);
#endif	/* defined(__sparc) */

	if (ddi_getprop(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS, "interrupts",
		-1) != -1) {
		pdptr = kmem_zalloc((sizeof (struct ddi_parent_private_data) +
		    sizeof (struct intrspec)), KM_SLEEP);
		pdptr->par_intr = (struct intrspec *)(pdptr + 1);
		pdptr->par_nintr = 1;
		ddi_set_parent_data(child, pdptr);
	} else
		ddi_set_parent_data(child, NULL);

	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

#if !defined(__i386) && !defined(__amd64)
	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
#endif

	/*
	 * Support for the "command-preserve" property.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
						DDI_PROP_DONTPASS,
						"command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (ppb_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

#if !defined(__i386) && !defined(__amd64)
	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		/*
		 * These flags should be moved to uts/common/sys/pci.h:
		 */
#ifndef PCI_BCNF_BCNTRL
#define	PCI_BCNF_BCNTRL			0x3e
#define	PCI_BCNF_BCNTRL_PARITY_ENABLE	0x0001
#define	PCI_BCNF_BCNTRL_SERR_ENABLE	0x0002
#define	PCI_BCNF_BCNTRL_MAST_AB_MODE	0x0020
#endif
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (ppb_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (ppb_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}
#endif

#if defined(__sparc)
	/*
	 * Initialize cache-line-size configuration register if needed.
	 */
	if (ppb_set_cache_line_size_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {
		ppb = ddi_get_soft_state(ppb_state,
		    ddi_get_instance(ddi_get_parent(child)));
		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    ppb->ppb_cache_line_size);
		n = pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		if (n != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "cache-line-size", n);
		}
	}

	/*
	 * Initialize latency timer configuration registers if needed.
	 */
	if (ppb_set_latency_timer_register &&
			ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
					"latency-timer", 0) == 0) {

		if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
			latency_timer = ppb->ppb_latency_timer;
		/*
		 * This flags should be moved to uts/common/sys/pci.h:
		 */
#ifndef	PCI_BCNF_LATENCY_TIMER
#define	PCI_BCNF_LATENCY_TIMER		0x1b
#endif
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
					ppb->ppb_latency_timer);
		} else {
			min_gnt = pci_config_get8(config_handle,
						    PCI_CONF_MIN_G);
			latency_timer = min_gnt * 8;
		}
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
				latency_timer);
		n = pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if (n != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
					"latency-timer", n);
		}
	}
#endif

	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

static void
ppb_removechild(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;

	if ((pdptr = ddi_get_parent_data(dip)) != NULL) {
		kmem_free(pdptr, (sizeof (*pdptr) + sizeof (struct intrspec)));
		ddi_set_parent_data(dip, NULL);
	}
	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	impl_rem_dev_props(dip);
}

/*
 * Transfer select properties from PROM to kernel.
 * For x86 pci is already enumerated by the kernel.
 */
#if	defined(__sparc)
static int
ppb_create_pci_prop(dev_info_t *child)
{
	pci_regspec_t *pci_rp;
	int	length;
	int	value;

	/* get child "reg" property */
	value = ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_CANSLEEP,
		"reg", (caddr_t)&pci_rp, &length);
	if (value != DDI_SUCCESS)
		return (value);

	(void) ndi_prop_update_byte_array(DDI_DEV_T_NONE, child, "reg",
		(uchar_t *)pci_rp, length);

	/*
	 * free the memory allocated by ddi_getlongprop ().
	 */
	kmem_free(pci_rp, length);

	/* assign the basic PCI Properties */

	value = ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_CANSLEEP,
		"vendor-id", -1);
	if (value != -1)
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
		"vendor-id", value);

	value = ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_CANSLEEP,
		"device-id", -1);
	if (value != -1)
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
		"device-id", value);

	value = ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_CANSLEEP,
		"interrupts", -1);
	if (value != -1)
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
		"interrupts", value);
	return (DDI_SUCCESS);
}
#endif	/* defined(__sparc) */


/*
 * ppb_save_config_regs
 *
 * This routine saves the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: ppb_detach() on suspends
 *
 * return value: none
 */
static void
ppb_save_config_regs(ppb_devstate_t *ppb_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;

	for (i = 0, dip = ddi_get_child(ppb_p->dip); dip != NULL;
			i++, dip = ddi_get_next_sibling(dip)) {

		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't config space for %s%d\n",
				ddi_driver_name(ppb_p->dip),
				ddi_get_instance(ppb_p->dip),
				ddi_driver_name(dip),
				ddi_get_instance(dip));
			continue;
		}

		ppb_p->config_state[i].dip = dip;
		ppb_p->config_state[i].command =
			pci_config_get16(config_handle, PCI_CONF_COMM);
#if !defined(__i386) && !defined(__amd64)
		ppb_p->config_state[i].header_type =
			pci_config_get8(config_handle, PCI_CONF_HEADER);
		if ((ppb_p->config_state[i].header_type & PCI_HEADER_TYPE_M) ==
				PCI_HEADER_ONE)
			ppb_p->config_state[i].bridge_control =
				pci_config_get16(config_handle,
						PCI_BCNF_BCNTRL);
#endif
#if defined(__sparc)
		ppb_p->config_state[i].cache_line_size =
			pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		ppb_p->config_state[i].latency_timer =
			pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if ((ppb_p->config_state[i].header_type &
				PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			ppb_p->config_state[i].sec_latency_timer =
				pci_config_get8(config_handle,
						PCI_BCNF_LATENCY_TIMER);
#endif
		pci_config_teardown(&config_handle);
	}
	ppb_p->config_state_index = i;
}


/*
 * ppb_restore_config_regs
 *
 * This routine restores the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: ppb_attach() on resume
 *
 * return value: none
 */
static void
ppb_restore_config_regs(ppb_devstate_t *ppb_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t config_handle;

	for (i = 0; i < ppb_p->config_state_index; i++) {
		dip = ppb_p->config_state[i].dip;
		if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't config space for %s%d\n",
				ddi_driver_name(ppb_p->dip),
				ddi_get_instance(ppb_p->dip),
				ddi_driver_name(dip),
				ddi_get_instance(dip));
			continue;
		}
		pci_config_put16(config_handle, PCI_CONF_COMM,
				ppb_p->config_state[i].command);
#if !defined(__i386) && !defined(__amd64)
		if ((ppb_p->config_state[i].header_type & PCI_HEADER_TYPE_M) ==
				PCI_HEADER_ONE)
			pci_config_put16(config_handle, PCI_BCNF_BCNTRL,
					ppb_p->config_state[i].bridge_control);
#endif
#if defined(__sparc)
		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
				ppb_p->config_state[i].cache_line_size);
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
				ppb_p->config_state[i].latency_timer);
		if ((ppb_p->config_state[i].header_type &
				PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
				ppb_p->config_state[i].sec_latency_timer);
#endif
		pci_config_teardown(&config_handle);
	}
}

#if defined(__i386) || defined(__amd64)

#define	PCI_VENID_AMD			0x1022
#define	PCI_DEVID_8132			0x7458
#define	PCI_MSI_MAPPING_CAP_OFF		0xF4
#define	PCI_MSI_MAPPING_CAP_MASK	0xFF01000F
#define	PCI_MSI_MAPPING_ENABLE		0xA8010008

extern int (*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *,
		psm_intr_op_t, int *);

/*
 * ppb_intr_ops
 */
static int
ppb_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	ddi_acc_handle_t config_handle;
	ddi_intr_handle_impl_t tmp_hdl;
	uint_t msi_mapping;
	int types = 0;

	if (intr_op != DDI_INTROP_SUPPORTED_TYPES)
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));

	DDI_INTR_NEXDBG((CE_CONT,
	    "ppb_intr_ops: pdip 0x%p, rdip 0x%p, op %x handle 0x%p\n",
	    (void *)pdip, (void *)rdip, intr_op, (void *)hdlp));

	/* Fixed interrupt is supported by default */
	*(int *)result = DDI_INTR_TYPE_FIXED;

	if (psm_intr_ops == NULL || ppb_support_msi == -1) {
		/* MSI is not allowed */
		DDI_INTR_NEXDBG((CE_CONT, "ppb_intr_ops: psm_intr_ops == NULL "
		    "or MSI is not allowed\n"));
	} else if (ppb_support_msi == 1) {
		/* MSI is always allowed */
		DDI_INTR_NEXDBG((CE_CONT,
		    "ppb_intr_ops: MSI is always allowed\n"));
		if (pci_msi_get_supported_type(rdip, &types) == DDI_SUCCESS) {
			*(int *)result |= types;
			bzero(&tmp_hdl, sizeof (ddi_intr_handle_impl_t));
			tmp_hdl.ih_type = *(int *)result;
			(void) (*psm_intr_ops)(rdip, &tmp_hdl,
			    PSM_INTR_OP_CHECK_MSI, result);
		}
	} else if (pci_config_setup(pdip, &config_handle) == DDI_SUCCESS) {
		/*
		 * ppb_support_msi == 0
		 * only for check special case like AMD8132 which supports MSI
		 */
		if ((pci_config_get16(config_handle, PCI_CONF_VENID) ==
		    PCI_VENID_AMD) && (pci_config_get16(config_handle,
		    PCI_CONF_DEVID) == PCI_DEVID_8132)) {
			msi_mapping = pci_config_get32(config_handle,
					PCI_MSI_MAPPING_CAP_OFF);
			/* make sure MSI enable bit is on */
			if ((msi_mapping & PCI_MSI_MAPPING_CAP_MASK) ==
				PCI_MSI_MAPPING_ENABLE) {
				/* MSI/X is enable */
				DDI_INTR_NEXDBG((CE_CONT, "ppb_intr_ops: "
				    "MSI is allowed for AMD8132\n"));
				if (pci_msi_get_supported_type(rdip, &types)
				    == DDI_SUCCESS) {
					*(int *)result |= types;
					bzero(&tmp_hdl,
					    sizeof (ddi_intr_handle_impl_t));
					tmp_hdl.ih_type = *(int *)result;
					(void) (*psm_intr_ops)(rdip, &tmp_hdl,
					    PSM_INTR_OP_CHECK_MSI, result);
				}
			}
		}
		pci_config_teardown(&config_handle);
	}
	DDI_INTR_NEXDBG((CE_CONT,
	    "ppb_intr_ops: rdip 0x%p, returns supported types: 0x%x\n",
	    (void *)rdip, *(int *)result));
	return (DDI_SUCCESS);
}
#endif

static int
ppb_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_open(devp, flags, otyp, credp));
}

static int
ppb_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_close(dev, flags, otyp, credp));
}

static int
ppb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode, credp,
	    rvalp));
}

static int
ppb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int flags, char *name, caddr_t valuep, int *lengthp)
{
	return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

static int
ppb_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	return (pcihp_info(dip, cmd, arg, result));
}
