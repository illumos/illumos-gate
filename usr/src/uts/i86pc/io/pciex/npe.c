/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Host to PCI-Express local bus driver
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/pcie.h>
#include <sys/pci_impl.h>
#include <sys/sysmacros.h>
#include <sys/ddi_intr.h>
#include <sys/sunndi.h>
#include <sys/hotplug/pci/pcihp.h>
#include <io/pci/pci_common.h>
#include <io/pci/pci_tools_ext.h>
#include <io/pci/pci_var.h>
#include <io/pciex/pcie_error.h>

/*
 * Bus Operation functions
 */
static int	npe_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
		    off_t, off_t, caddr_t *);
static int	npe_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
		    void *, void *);
static int	npe_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
		    ddi_intr_handle_impl_t *, void *);

struct bus_ops npe_bus_ops = {
	BUSO_REV,
	npe_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_dma_map,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	npe_ctlops,
	ddi_bus_prop_op,
	0,		/* (*bus_get_eventcookie)();	*/
	0,		/* (*bus_add_eventcall)();	*/
	0,		/* (*bus_remove_eventcall)();	*/
	0,		/* (*bus_post_event)();		*/
	0,		/* (*bus_intr_ctl)(); */
	0,		/* (*bus_config)(); */
	0,		/* (*bus_unconfig)(); */
	NULL,		/* (*bus_fm_init)(); */
	NULL,		/* (*bus_fm_fini)(); */
	NULL,		/* (*bus_fm_access_enter)(); */
	NULL,		/* (*bus_fm_access_exit)(); */
	NULL,		/* (*bus_power)(); */
	npe_intr_ops	/* (*bus_intr_op)(); */
};

/*
 * One goal here is to leverage off of the pcihp.c source without making
 * changes to it.  Call into it's cb_ops directly if needed, piggybacking
 * anything else needed by the pci_tools.c module.  Only pci_tools and pcihp
 * will be using the PCI devctl node.
 */
static int	npe_open(dev_t *, int, int, cred_t *);
static int	npe_close(dev_t, int, int, cred_t *);
static int	npe_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	npe_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
		    caddr_t, int *);
static int	npe_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

struct cb_ops npe_cb_ops = {
	npe_open,			/* open */
	npe_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	npe_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	npe_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};


/*
 * Device Node Operation functions
 */
static int	npe_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int	npe_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

struct dev_ops npe_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	pcihp_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	npe_attach,		/* attach */
	npe_detach,		/* detach */
	nulldev,		/* reset */
	&npe_cb_ops,		/* driver operations */
	&npe_bus_ops		/* bus operations */
};

/*
 * Internal routines in support of particular npe_ctlops.
 */
static int npe_removechild(dev_info_t *child);
static int npe_initchild(dev_info_t *child);

/*
 * External support routine
 */
extern void	npe_query_acpi_mcfg(dev_info_t *dip);
extern void	npe_ck804_fix_aer_ptr(dev_info_t *child);

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"Host to PCIe nexus driver %I%",
	&npe_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/* Save minimal state. */
void *npe_statep;


int
_init(void)
{
	int e;

	/*
	 * Initialize per-pci bus soft state pointer.
	 */
	e = ddi_soft_state_init(&npe_statep, sizeof (pci_state_t), 1);
	if (e != 0)
		return (e);

	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&npe_statep);

	return (e);
}


int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);
	if (rc != 0)
		return (rc);

	ddi_soft_state_fini(&npe_statep);
	return (rc);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*ARGSUSED*/
static int
npe_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	/*
	 * Use the minor number as constructed by pcihp, as the index value to
	 * ddi_soft_state_zalloc.
	 */
	int instance = ddi_get_instance(devi);
	pci_state_t *pcip = NULL;

	if (ddi_prop_update_string(DDI_DEV_T_NONE, devi, "device_type",
	    "pciex") != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "npe:  'device_type' prop create failed");
	}

	if (ddi_soft_state_zalloc(npe_statep, instance) == DDI_SUCCESS)
		pcip = ddi_get_soft_state(npe_statep, instance);

	if (pcip == NULL)
		return (DDI_FAILURE);

	pcip->pci_dip = devi;

	/*
	 * Initialize hotplug support on this bus. At minimum
	 * (for non hotplug bus) this would create ":devctl" minor
	 * node to support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls
	 * to this bus.
	 */
	if (pcihp_init(devi) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "npe: Failed to setup hotplug framework");
		ddi_soft_state_free(npe_statep, instance);
		return (DDI_FAILURE);
	}

	if (pcitool_init(devi, B_TRUE) != DDI_SUCCESS) {
		(void) pcihp_uninit(devi);
		ddi_soft_state_free(npe_statep, instance);
		return (DDI_FAILURE);
	}

	npe_query_acpi_mcfg(devi);
	ddi_report_dev(devi);
	return (DDI_SUCCESS);

}


/*ARGSUSED*/
static int
npe_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);

	/* Uninitialize pcitool support. */
	pcitool_uninit(devi);

	/*
	 * Uninitialize hotplug support on this bus.
	 */
	(void) pcihp_uninit(devi);
	ddi_soft_state_free(npe_statep, instance);
	return (DDI_SUCCESS);
}


static int
npe_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	int 		rnumber;
	int		length;
	int		space;
	ddi_acc_hdl_t	*hp;
	ddi_map_req_t	mr;
	pci_regspec_t	pci_reg;
	pci_regspec_t	*pci_rp;
	struct regspec	reg;
	pci_acc_cfblk_t	*cfp;


	mr = *mp; /* Get private copy of request */
	mp = &mr;

	/*
	 * check for register number
	 */
	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		pci_reg = *(pci_regspec_t *)(mp->map_obj.rp);
		pci_rp = &pci_reg;
		if (pci_common_get_reg_prop(rdip, pci_rp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		break;
	case DDI_MT_RNUMBER:
		rnumber = mp->map_obj.rnumber;
		/*
		 * get ALL "reg" properties for dip, select the one of
		 * of interest. In x86, "assigned-addresses" property
		 * is identical to the "reg" property, so there is no
		 * need to cross check the two to determine the physical
		 * address of the registers.
		 * This routine still performs some validity checks to
		 * make sure that everything is okay.
		 */
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
		    (uint_t *)&length) != DDI_PROP_SUCCESS)
			return (DDI_FAILURE);

		/*
		 * validate the register number.
		 */
		length /= (sizeof (pci_regspec_t) / sizeof (int));
		if (rnumber >= length) {
			ddi_prop_free(pci_rp);
			return (DDI_FAILURE);
		}

		/*
		 * copy the required entry.
		 */
		pci_reg = pci_rp[rnumber];

		/*
		 * free the memory allocated by ddi_prop_lookup_int_array
		 */
		ddi_prop_free(pci_rp);

		pci_rp = &pci_reg;
		if (pci_common_get_reg_prop(rdip, pci_rp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		mp->map_type = DDI_MT_REGSPEC;
		break;
	default:
		return (DDI_ME_INVAL);
	}

	space = pci_rp->pci_phys_hi & PCI_REG_ADDR_M;

	/*
	 * check for unmap and unlock of address space
	 */
	if ((mp->map_op == DDI_MO_UNMAP) || (mp->map_op == DDI_MO_UNLOCK)) {
		/*
		 * Adjust offset and length
		 * A non-zero length means override the one in the regspec.
		 */
		pci_rp->pci_phys_low += (uint_t)offset;
		if (len != 0)
			pci_rp->pci_size_low = len;

		switch (space) {
		case PCI_ADDR_IO:
			reg.regspec_bustype = 1;
			break;

		case PCI_ADDR_CONFIG:
			/* Just fall through */
		case PCI_ADDR_MEM64:
			/*
			 * MEM64 requires special treatment on map, to check
			 * that the device is below 4G.  On unmap, however,
			 * we can assume that everything is OK... the map
			 * must have succeeded.
			 */
			/* FALLTHROUGH */
		case PCI_ADDR_MEM32:
			reg.regspec_bustype = 0;
			break;

		default:
			return (DDI_FAILURE);
		}
		reg.regspec_addr = pci_rp->pci_phys_low;
		reg.regspec_size = pci_rp->pci_size_low;

		mp->map_obj.rp = &reg;
		return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));

	}

	/* check for user mapping request - not legal for Config */
	if (mp->map_op == DDI_MO_MAP_HANDLE && space == PCI_ADDR_CONFIG) {
		cmn_err(CE_NOTE, "npe: Config mapping request from user\n");
		return (DDI_FAILURE);
	}


	if (space == PCI_ADDR_CONFIG) {
		/* Can't map config space without a handle */
		hp = (ddi_acc_hdl_t *)mp->map_handlep;
		if (hp == NULL)
			return (DDI_FAILURE);

		pci_rp->pci_phys_low = ddi_prop_get_int64(DDI_DEV_T_ANY,
		    rdip, 0, "ecfga-base-address", 0);

		/* record the device address for future reference */
		cfp = (pci_acc_cfblk_t *)&hp->ah_bus_private;
		cfp->c_busnum = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
		cfp->c_devnum = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
		cfp->c_funcnum = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

		pci_rp->pci_phys_low += ((cfp->c_busnum << 20) |
		    (cfp->c_devnum) << 15 | (cfp->c_funcnum << 12));

		pci_rp->pci_size_low = PCIE_CONF_HDR_SIZE;
	}

	length = pci_rp->pci_size_low;

	/*
	 * range check
	 */
	if ((offset >= length) || (len > length) || (offset + len > length))
		return (DDI_FAILURE);

	/*
	 * Adjust offset and length
	 * A non-zero length means override the one in the regspec.
	 */
	pci_rp->pci_phys_low += (uint_t)offset;
	if (len != 0)
		pci_rp->pci_size_low = len;

	/*
	 * convert the pci regsec into the generic regspec used by the
	 * parent root nexus driver.
	 */
	switch (space) {
	case PCI_ADDR_IO:
		reg.regspec_bustype = 1;
		break;
	case PCI_ADDR_CONFIG:
	case PCI_ADDR_MEM64:
		/*
		 * We can't handle 64-bit devices that are mapped above
		 * 4G or that are larger than 4G.
		 */
		if (pci_rp->pci_phys_mid != 0 || pci_rp->pci_size_hi != 0)
			return (DDI_FAILURE);
		/*
		 * Other than that, we can treat them as 32-bit mappings
		 */
		/* FALLTHROUGH */
	case PCI_ADDR_MEM32:
		reg.regspec_bustype = 0;
		break;
	default:
		return (DDI_FAILURE);
	}

	reg.regspec_addr = pci_rp->pci_phys_low;
	reg.regspec_size = pci_rp->pci_size_low;

	mp->map_obj.rp = &reg;
	return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));
}


/*ARGSUSED*/
static int
npe_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	int		rn;
	int		totreg;
	uint_t		reglen;
	pci_regspec_t	*drv_regp;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCI Express-device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (npe_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (npe_removechild((dev_info_t *)arg));

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);

		*(int *)result = 0;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "reg", (int **)&drv_regp,
		    &reglen) != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}

		totreg = (reglen * sizeof (int)) / sizeof (pci_regspec_t);
		if (ctlop == DDI_CTLOPS_NREGS)
			*(int *)result = totreg;
		else if (ctlop == DDI_CTLOPS_REGSIZE) {
			rn = *(int *)arg;
			if (rn >= totreg) {
				ddi_prop_free(drv_regp);
				return (DDI_FAILURE);
			}
			*(off_t *)result = drv_regp[rn].pci_size_low;
		}
		ddi_prop_free(drv_regp);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_POWER:
	{
		power_req_t	*reqp = (power_req_t *)arg;
		/*
		 * We currently understand reporting of PCI_PM_IDLESPEED
		 * capability. Everything else is passed up.
		 */
		if ((reqp->request_type == PMR_REPORT_PMCAP) &&
		    (reqp->req.report_pmcap_req.cap ==  PCI_PM_IDLESPEED))
			return (DDI_SUCCESS);

		break;
	}

	default:
		break;
	}

	return (ddi_ctlops(dip, rdip, ctlop, arg, result));

}


/*
 * npe_intr_ops
 */
static int
npe_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (pci_common_intr_ops(pdip, rdip, intr_op, hdlp, result));
}


static int
npe_initchild(dev_info_t *child)
{
	char	name[80];

	if (pci_common_name_child(child, name, 80) != DDI_SUCCESS)
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
		if (ndi_merge_node(child, pci_common_name_child) ==
		    DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for DDIVS to run under PCI Express */
		if (pci_allow_pseudo_children) {
			/*
			 * If the "interrupts" property doesn't exist,
			 * this must be the ddivs no-intr case, and it returns
			 * DDI_SUCCESS instead of DDI_FAILURE.
			 */
			if (ddi_prop_get_int(DDI_DEV_T_ANY, child,
			    DDI_PROP_DONTPASS, "interrupts", -1) == -1)
				return (DDI_SUCCESS);
			/*
			 * Create the ddi_parent_private_data for a pseudo
			 * child.
			 */
			pci_common_set_parent_private_data(child);
			return (DDI_SUCCESS);
		}

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_get_name(child), ddi_get_name_addr(child),
		    ddi_get_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "interrupts", -1) != -1)
		pci_common_set_parent_private_data(child);
	else
		ddi_set_parent_data(child, NULL);

	/*
	 * Enable AER next pointer being displayed
	 */
	npe_ck804_fix_aer_ptr(child);

	(void) pcie_error_init(child);

	return (DDI_SUCCESS);
}


static int
npe_removechild(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;

	/*
	 * Do it way early.
	 * Otherwise ddi_map() call form pcie_error_fini crashes
	 */
	pcie_error_fini(dip);

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

	return (DDI_SUCCESS);
}


/*
 * When retrofitting this module for pci_tools, functions such as open, close,
 * and ioctl are now pulled into this module.  Before this, the functions in
 * the pcihp module were referenced directly.  Now they are called or
 * referenced through the pcihp cb_ops structure from functions in this module.
 */
static int
npe_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_open(devp, flags, otyp, credp));
}

static int
npe_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_close(dev, flags, otyp, credp));
}

static int
npe_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);
	pci_state_t	*pci_p = ddi_get_soft_state(npe_statep, instance);
	dev_info_t	*dip;

	if (pci_p == NULL)
		return (ENXIO);

	dip = pci_p->pci_dip;
	return (pci_common_ioctl(dip, dev, cmd, arg, mode, credp, rvalp));
}

static int
npe_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int flags, char *name, caddr_t valuep, int *lengthp)
{
	return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

static int
npe_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	return (pcihp_info(dip, cmd, arg, result));
}
