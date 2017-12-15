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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

/*
 *	Host to PCI local bus driver
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sysmacros.h>
#include <sys/sunndi.h>
#include <sys/ddifm.h>
#include <sys/ndifm.h>
#include <sys/fm/protocol.h>
#include <sys/hotplug/pci/pcihp.h>
#include <io/pci/pci_common.h>
#include <io/pci/pci_tools_ext.h>

/* Save minimal state. */
void *pci_statep;

/*
 * Bus Operation functions
 */
static int	pci_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
		    off_t, off_t, caddr_t *);
static int	pci_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
		    void *, void *);
static int	pci_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
		    ddi_intr_handle_impl_t *, void *);
static int	pci_fm_init(dev_info_t *, dev_info_t *, int,
		    ddi_iblock_cookie_t *);
static int	pci_fm_callback(dev_info_t *, ddi_fm_error_t *, const void *);

struct bus_ops pci_bus_ops = {
	BUSO_REV,
	pci_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	NULL,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	pci_ctlops,
	ddi_bus_prop_op,
	0,		/* (*bus_get_eventcookie)();	*/
	0,		/* (*bus_add_eventcall)();	*/
	0,		/* (*bus_remove_eventcall)();	*/
	0,		/* (*bus_post_event)();		*/
	0,		/* (*bus_intr_ctl)(); */
	0,		/* (*bus_config)(); */
	0,		/* (*bus_unconfig)(); */
	pci_fm_init,	/* (*bus_fm_init)(); */
	NULL,		/* (*bus_fm_fini)(); */
	NULL,		/* (*bus_fm_access_enter)(); */
	NULL,		/* (*bus_fm_access_exit)(); */
	NULL,		/* (*bus_power)(); */
	pci_intr_ops	/* (*bus_intr_op)(); */
};

/*
 * One goal here is to leverage off of the pcihp.c source without making
 * changes to it.  Call into it's cb_ops directly if needed, piggybacking
 * anything else needed by the pci_tools.c module.  Only pci_tools and pcihp
 * will be opening PCI nexus driver file descriptors.
 */
static int	pci_open(dev_t *, int, int, cred_t *);
static int	pci_close(dev_t, int, int, cred_t *);
static int	pci_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	pci_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
		    caddr_t, int *);
static int	pci_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static void	pci_peekpoke_cb(dev_info_t *, ddi_fm_error_t *);

struct cb_ops pci_cb_ops = {
	pci_open,			/* open */
	pci_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pci_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pci_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * Device Node Operation functions
 */
static int pci_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int pci_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

struct dev_ops pci_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	pci_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pci_attach,		/* attach */
	pci_detach,		/* detach */
	nulldev,		/* reset */
	&pci_cb_ops,		/* driver operations */
	&pci_bus_ops,		/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed		/* quiesce */
};

/*
 * This variable controls the default setting of the command register
 * for pci devices.  See pci_initchild() for details.
 */
static ushort_t pci_command_default = PCI_COMM_ME |
					PCI_COMM_MAE |
					PCI_COMM_IO;

/*
 * Internal routines in support of particular pci_ctlops.
 */
static int pci_removechild(dev_info_t *child);
static int pci_initchild(dev_info_t *child);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, 			/* Type of module */
	"x86 Host to PCI nexus driver",		/* Name of module */
	&pci_ops,				/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int e;

	/*
	 * Initialize per-pci bus soft state pointer.
	 */
	e = ddi_soft_state_init(&pci_statep, sizeof (pci_state_t), 1);
	if (e != 0)
		return (e);

	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pci_statep);

	return (e);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);
	if (rc != 0)
		return (rc);

	ddi_soft_state_fini(&pci_statep);

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pci_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	/*
	 * Use the minor number as constructed by pcihp, as the index value to
	 * ddi_soft_state_zalloc.
	 */
	int instance = ddi_get_instance(devi);
	pci_state_t *pcip = NULL;
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, devi, "device_type", "pci")
	    != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "pci:  'device_type' prop create failed");
	}

	if (ddi_soft_state_zalloc(pci_statep, instance) == DDI_SUCCESS) {
		pcip = ddi_get_soft_state(pci_statep, instance);
	}

	if (pcip == NULL) {
		goto bad_soft_state;
	}

	pcip->pci_dip = devi;
	pcip->pci_soft_state = PCI_SOFT_STATE_CLOSED;

	/*
	 * Initialize hotplug support on this bus. At minimum
	 * (for non hotplug bus) this would create ":devctl" minor
	 * node to support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls
	 * to this bus.
	 */
	if (pcihp_init(devi) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pci: Failed to setup hotplug framework");
		goto bad_pcihp_init;
	}

	/* Second arg: initialize for pci, not pci_express */
	if (pcitool_init(devi, B_FALSE) != DDI_SUCCESS) {
		goto bad_pcitool_init;
	}

	pcip->pci_fmcap = DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;
	ddi_fm_init(devi, &pcip->pci_fmcap, &pcip->pci_fm_ibc);
	mutex_init(&pcip->pci_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pcip->pci_err_mutex, NULL, MUTEX_DRIVER,
	    (void *)pcip->pci_fm_ibc);
	mutex_init(&pcip->pci_peek_poke_mutex, NULL, MUTEX_DRIVER,
	    (void *)pcip->pci_fm_ibc);
	if (pcip->pci_fmcap & DDI_FM_ERRCB_CAPABLE) {
		pci_ereport_setup(devi);
		ddi_fm_handler_register(devi, pci_fm_callback, NULL);
	}

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad_pcitool_init:
	(void) pcihp_uninit(devi);
bad_pcihp_init:
	ddi_soft_state_free(pci_statep, instance);
bad_soft_state:
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pci_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	pci_state_t *pcip;

	pcip = ddi_get_soft_state(pci_statep, ddi_get_instance(devi));


	switch (cmd) {
	case DDI_DETACH:
		if (pcip->pci_fmcap & DDI_FM_ERRCB_CAPABLE) {
			ddi_fm_handler_unregister(devi);
			pci_ereport_teardown(devi);
		}
		mutex_destroy(&pcip->pci_peek_poke_mutex);
		mutex_destroy(&pcip->pci_err_mutex);
		mutex_destroy(&pcip->pci_mutex);
		ddi_fm_fini(devi);	/* Uninitialize pcitool support. */
		pcitool_uninit(devi);

		/* Uninitialize hotplug support on this bus. */
		(void) pcihp_uninit(devi);

		ddi_soft_state_free(pci_statep, instance);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
pci_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	struct regspec64 reg;
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	ddi_acc_impl_t *hdlp;
	pci_regspec_t pci_reg;
	pci_regspec_t *pci_rp;
	int 	rnumber;
	uint64_t pci_rlength;
	uint_t	nelems;
	pci_acc_cfblk_t *cfp;
	int	space;
	pci_state_t *pcip;

	mr = *mp; /* Get private copy of request */
	mp = &mr;

	if (mp->map_handlep != NULL) {
		pcip = ddi_get_soft_state(pci_statep, ddi_get_instance(dip));
		hdlp = (ddi_acc_impl_t *)(mp->map_handlep)->ah_platform_private;
		hdlp->ahi_err_mutexp = &pcip->pci_err_mutex;
		hdlp->ahi_peekpoke_mutexp = &pcip->pci_peek_poke_mutex;
		hdlp->ahi_scan_dip = dip;
		hdlp->ahi_scan = pci_peekpoke_cb;
	}

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
		    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp, &nelems) !=
		    DDI_PROP_SUCCESS)
			return (DDI_FAILURE);

		/*
		 * validate the register number.
		 */
		nelems /= (sizeof (pci_regspec_t) / sizeof (int));
		if (rnumber >= nelems) {
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
		switch (space) {
		case PCI_ADDR_CONFIG:
			/* No work required on unmap of Config space */
			return (DDI_SUCCESS);

		case PCI_ADDR_IO:
			reg.regspec_bustype = 1;
			break;

		case PCI_ADDR_MEM64:
		case PCI_ADDR_MEM32:
			reg.regspec_bustype = 0;
			break;

		default:
			return (DDI_FAILURE);
		}

		reg.regspec_addr = (uint64_t)pci_rp->pci_phys_mid << 32 |
		    (uint64_t)pci_rp->pci_phys_low;
		reg.regspec_size = (uint64_t)pci_rp->pci_size_hi << 32 |
		    (uint64_t)pci_rp->pci_size_low;

		/*
		 * Adjust offset and length
		 * A non-zero length means override the one in the regspec.
		 */
		if (reg.regspec_addr + offset < MAX(reg.regspec_addr, offset))
			return (DDI_FAILURE);
		reg.regspec_addr += offset;
		if (len != 0)
			reg.regspec_size = len;

		mp->map_obj.rp = (struct regspec *)&reg;
		mp->map_flags |= DDI_MF_EXT_REGSPEC;
		return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));

	}

	/* check for user mapping request - not legal for Config */
	if (mp->map_op == DDI_MO_MAP_HANDLE && space == PCI_ADDR_CONFIG) {
		return (DDI_FAILURE);
	}

	/*
	 * check for config space
	 * On x86, CONFIG is not mapped via MMU and there is
	 * no endian-ness issues. Set the attr field in the handle to
	 * indicate that the common routines to call the nexus driver.
	 */
	if (space == PCI_ADDR_CONFIG) {
		/* Can't map config space without a handle */
		hp = (ddi_acc_hdl_t *)mp->map_handlep;
		if (hp == NULL)
			return (DDI_FAILURE);

		/* record the device address for future reference */
		cfp = (pci_acc_cfblk_t *)&hp->ah_bus_private;
		cfp->c_busnum = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
		cfp->c_devnum = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
		cfp->c_funcnum = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

		*vaddrp = (caddr_t)offset;
		return (pci_fm_acc_setup(hp, offset, len));
	}

	/*
	 * range check
	 */
	pci_rlength = (uint64_t)pci_rp->pci_size_low |
	    (uint64_t)pci_rp->pci_size_hi << 32;
	if ((offset >= pci_rlength) || (len > pci_rlength) ||
	    (offset + len > pci_rlength) || (offset + len < MAX(offset, len))) {
		return (DDI_FAILURE);
	}

	/*
	 * convert the pci regsec into the generic regspec used by the
	 * parent root nexus driver.
	 */
	switch (space) {
	case PCI_ADDR_IO:
		reg.regspec_bustype = 1;
		break;
	case PCI_ADDR_MEM64:
	case PCI_ADDR_MEM32:
		reg.regspec_bustype = 0;
		break;
	default:
		return (DDI_FAILURE);
	}

	reg.regspec_addr = (uint64_t)pci_rp->pci_phys_mid << 32 |
	    (uint64_t)pci_rp->pci_phys_low;
	reg.regspec_size = pci_rlength;

	/*
	 * Adjust offset and length
	 * A non-zero length means override the one in the regspec.
	 */
	if (reg.regspec_addr + offset < MAX(reg.regspec_addr, offset))
		return (DDI_FAILURE);
	reg.regspec_addr += offset;
	if (len != 0)
		reg.regspec_size = len;

	mp->map_obj.rp = (struct regspec *)&reg;
	mp->map_flags |= DDI_MF_EXT_REGSPEC;
	return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));
}


/*ARGSUSED*/
static int
pci_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	uint_t	reglen;
	int	totreg;
	pci_state_t *pcip;
	struct  attachspec *asp;
	struct  detachspec *dsp;

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
		return (pci_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (pci_removechild((dev_info_t *)arg));

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
			uint64_t val;
			int rn;

			rn = *(int *)arg;
			if (rn >= totreg) {
				ddi_prop_free(drv_regp);
				return (DDI_FAILURE);
			}
			val = drv_regp[rn].pci_size_low |
			    (uint64_t)drv_regp[rn].pci_size_hi << 32;
			if (val > OFF_MAX) {
				int ce = CE_NOTE;
#ifdef DEBUG
				ce = CE_WARN;
#endif
				dev_err(rdip, ce, "failed to get register "
				    "size, value larger than OFF_MAX: 0x%"
				    PRIx64 "\n", val);
				return (DDI_FAILURE);
			}
			*(off_t *)result = (off_t)val;
		}
		ddi_prop_free(drv_regp);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_POWER: {
		power_req_t	*reqp = (power_req_t *)arg;
		/*
		 * We currently understand reporting of PCI_PM_IDLESPEED
		 * capability. Everything else is passed up.
		 */
		if ((reqp->request_type == PMR_REPORT_PMCAP) &&
		    (reqp->req.report_pmcap_req.cap ==  PCI_PM_IDLESPEED)) {

			return (DDI_SUCCESS);
		}
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	case DDI_CTLOPS_PEEK:
	case DDI_CTLOPS_POKE:
		pcip = ddi_get_soft_state(pci_statep, ddi_get_instance(dip));
		return (pci_peekpoke_check(dip, rdip, ctlop, arg, result,
		    pci_common_peekpoke, &pcip->pci_err_mutex,
		    &pcip->pci_peek_poke_mutex, pci_peekpoke_cb));

	/* for now only X86 systems support PME wakeup from suspended state */
	case DDI_CTLOPS_ATTACH:
		asp = (struct attachspec *)arg;
		if (asp->cmd == DDI_RESUME && asp->when == DDI_PRE)
			if (pci_pre_resume(rdip) != DDI_SUCCESS)
				return (DDI_FAILURE);
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));

	case DDI_CTLOPS_DETACH:
		dsp = (struct detachspec *)arg;
		if (dsp->cmd == DDI_SUSPEND && dsp->when == DDI_POST)
			if (pci_post_suspend(rdip) != DDI_SUCCESS)
				return (DDI_FAILURE);
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	/* NOTREACHED */

}

/*
 * pci_intr_ops
 */
static int
pci_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (pci_common_intr_ops(pdip, rdip, intr_op, hdlp, result));
}


static int
pci_initchild(dev_info_t *child)
{
	char name[80];
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;

	if (pci_common_name_child(child, name, 80) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
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

		/* workaround for ddivs to run under PCI */
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
	 * initialize command register
	 */
	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Support for the "command-preserve" property.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (pci_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

static int
pci_removechild(dev_info_t *dip)
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

	return (DDI_SUCCESS);
}


/*
 * When retrofitting this module for pci_tools, functions such as open, close,
 * and ioctl are now pulled into this module.  Before this, the functions in
 * the pcihp module were referenced directly.  Now they are called or
 * referenced through the pcihp cb_ops structure from functions in this module.
 */

static int
pci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_open(devp, flags, otyp, credp));
}

static int
pci_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_get_cb_ops())->cb_close(dev, flags, otyp, credp));
}

static int
pci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	minor_t		minor = getminor(dev);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	pci_state_t	*pci_p = ddi_get_soft_state(pci_statep, instance);
	int		ret = ENOTTY;

	if (pci_p == NULL)
		return (ENXIO);

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
	case PCI_TOOL_INTR_MINOR_NUM:
		/* To handle pcitool related ioctls */
		ret =  pci_common_ioctl(pci_p->pci_dip, dev, cmd, arg, mode,
		    credp, rvalp);
		break;
	default:
		/* To handle devctl and hotplug related ioctls */
		ret = (pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode,
		    credp, rvalp);
		break;
	}

	return (ret);
}


static int
pci_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

static int
pci_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	return (pcihp_info(dip, cmd, arg, result));
}

void pci_peekpoke_cb(dev_info_t *dip, ddi_fm_error_t *derr) {
	(void) pci_ereport_post(dip, derr, NULL);
}

/*ARGSUSED*/
static int
pci_fm_init(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pci_state_t  *pcip = ddi_get_soft_state(pci_statep,
	    ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = pcip->pci_fm_ibc;

	return (pcip->pci_fmcap);
}

/*ARGSUSED*/
static int
pci_fm_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *no_used)
{
	pci_state_t  *pcip = ddi_get_soft_state(pci_statep,
	    ddi_get_instance(dip));

	mutex_enter(&pcip->pci_err_mutex);
	pci_ereport_post(dip, derr, NULL);
	mutex_exit(&pcip->pci_err_mutex);
	return (derr->fme_status);
}
