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
 * PCI Express nexus driver interface
 */

#include <sys/types.h>
#include <sys/conf.h>		/* nulldev */
#include <sys/stat.h>		/* devctl */
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/spl.h>
#include <sys/epm.h>
#include <sys/iommutsb.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include "px_obj.h"
#include <sys/pci_tools.h>
#include "px_tools_ext.h"
#include "pcie_pwr.h"

/*LINTLIBRARY*/

/*
 * function prototypes for dev ops routines:
 */
static int px_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int px_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int px_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result);
static int px_cb_attach(px_t *);
static void px_cb_detach(px_t *);
static int px_pwr_setup(dev_info_t *dip);
static void px_pwr_teardown(dev_info_t *dip);

extern errorq_t *pci_target_queue;

/*
 * function prototypes for hotplug routines:
 */
static int px_init_hotplug(px_t *px_p);
static int px_uninit_hotplug(dev_info_t *dip);

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops px_bus_ops = {
	BUSO_REV,
	px_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	px_dma_setup,
	px_dma_allochdl,
	px_dma_freehdl,
	px_dma_bindhdl,
	px_dma_unbindhdl,
	px_lib_dma_sync,
	px_dma_win,
	px_dma_ctlops,
	px_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,
	ndi_busop_add_eventcall,
	ndi_busop_remove_eventcall,
	ndi_post_event,
	NULL,
	NULL,			/* (*bus_config)(); */
	NULL,			/* (*bus_unconfig)(); */
	px_fm_init_child,	/* (*bus_fm_init)(); */
	NULL,			/* (*bus_fm_fini)(); */
	px_bus_enter,		/* (*bus_fm_access_enter)(); */
	px_bus_exit,		/* (*bus_fm_access_fini)(); */
	pcie_bus_power,		/* (*bus_power)(); */
	px_intr_ops		/* (*bus_intr_op)(); */
};

extern struct cb_ops px_cb_ops;

static struct dev_ops px_ops = {
	DEVO_REV,
	0,
	px_info,
	nulldev,
	0,
	px_attach,
	px_detach,
	nodev,
	&px_cb_ops,
	&px_bus_ops,
	nulldev
};

/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, 		/* Type of module - driver */
	"PCI Express nexus driver %I%",	/* Name of module. */
	&px_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/* driver soft state */
void *px_state_p;

int
_init(void)
{
	int e;

	/*
	 * Initialize per-px bus soft state pointer.
	 */
	e = ddi_soft_state_init(&px_state_p, sizeof (px_t), 1);
	if (e != DDI_SUCCESS)
		return (e);

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != DDI_SUCCESS)
		ddi_soft_state_fini(&px_state_p);
	return (e);
}

int
_fini(void)
{
	int e;

	/*
	 * Remove the module.
	 */
	e = mod_remove(&modlinkage);
	if (e != DDI_SUCCESS)
		return (e);
	/*
	 * Destroy pci_target_queue, and set it to NULL.
	 */
	if (pci_target_queue)
		errorq_destroy(pci_target_queue);

	pci_target_queue = NULL;

	/* Free px soft state */
	ddi_soft_state_fini(&px_state_p);

	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
px_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int	instance = getminor((dev_t)arg);
	px_t	*px_p = INST_TO_STATE(instance);

	/*
	 * Allow hotplug to deal with ones it manages
	 * Hot Plug will be done later.
	 */
	if (px_p && (px_p->px_dev_caps & PX_HOTPLUG_CAPABLE))
		return (pcihp_info(dip, infocmd, arg, result));

	/* non-hotplug or not attached */
	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (px_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)px_p->px_dip;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/* device driver entry points */
/*
 * attach entry point:
 */
/*ARGSUSED*/
static int
px_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	px_t		*px_p;	/* per bus state pointer */
	int		instance = DIP_TO_INST(dip);
	int		ret = DDI_SUCCESS;
	devhandle_t	dev_hdl = NULL;

	switch (cmd) {
	case DDI_ATTACH:
		DBG(DBG_ATTACH, dip, "DDI_ATTACH\n");

		/*
		 * Allocate and get the per-px soft state structure.
		 */
		if (ddi_soft_state_zalloc(px_state_p, instance)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't allocate px state",
			    ddi_driver_name(dip), instance);
			goto err_bad_px_softstate;
		}
		px_p = INST_TO_STATE(instance);
		px_p->px_dip = dip;
		mutex_init(&px_p->px_mutex, NULL, MUTEX_DRIVER, NULL);
		px_p->px_soft_state = PX_SOFT_STATE_CLOSED;
		px_p->px_open_count = 0;

		(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "pciex");

		/* Initialize px_dbg for high pil printing */
		px_dbg_attach(dip, &px_p->px_dbg_hdl);

		/*
		 * Get key properties of the pci bridge node and
		 * determine it's type (psycho, schizo, etc ...).
		 */
		if (px_get_props(px_p, dip) == DDI_FAILURE)
			goto err_bad_px_prop;

		if (px_lib_dev_init(dip, &dev_hdl) != DDI_SUCCESS)
			goto err_bad_dev_init;

		/* Initialize device handle */
		px_p->px_dev_hdl = dev_hdl;

		/* Cache the BDF of the root port nexus */
		px_p->px_bdf = px_lib_get_bdf(px_p);

		/*
		 * Initialize interrupt block.  Note that this
		 * initialize error handling for the PEC as well.
		 */
		if ((ret = px_ib_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_ib;

		if (px_cb_attach(px_p) != DDI_SUCCESS)
			goto err_bad_cb;

		/*
		 * Start creating the modules.
		 * Note that attach() routines should
		 * register and enable their own interrupts.
		 */

		if ((px_mmu_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_mmu;

		if ((px_msiq_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_msiq;

		if ((px_msi_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_msi;

		if ((px_pec_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_pec;

		if ((px_dma_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_dma; /* nothing to uninitialize on DMA */

		if ((px_fm_attach(px_p)) != DDI_SUCCESS)
			goto err_bad_dma;

		/*
		 * All of the error handlers have been registered
		 * by now so it's time to activate the interrupt.
		 */
		if ((ret = px_err_add_intr(&px_p->px_fault)) != DDI_SUCCESS)
			goto err_bad_intr;

		(void) px_init_hotplug(px_p);

		/*
		 * Create the "devctl" node for hotplug and pcitool support.
		 * For non-hotplug bus, we still need ":devctl" to
		 * support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls.
		 */
		if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
		    PCIHP_AP_MINOR_NUM(instance, PCIHP_DEVCTL_MINOR),
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
			goto err_bad_devctl_node;
		}

		if (pxtool_init(dip) != DDI_SUCCESS)
			goto err_bad_pcitool_node;

		/*
		 * power management setup. Even if it fails, attach will
		 * succeed as this is a optional feature. Since we are
		 * always at full power, this is not critical.
		 */
		if (pwr_common_setup(dip) != DDI_SUCCESS) {
			DBG(DBG_PWR, dip, "pwr_common_setup failed\n");
		} else if (px_pwr_setup(dip) != DDI_SUCCESS) {
			DBG(DBG_PWR, dip, "px_pwr_setup failed \n");
			pwr_common_teardown(dip);
		}

		/*
		 * add cpr callback
		 */
		px_cpr_add_callb(px_p);

		ddi_report_dev(dip);

		px_p->px_state = PX_ATTACHED;
		DBG(DBG_ATTACH, dip, "attach success\n");
		break;

err_bad_pcitool_node:
		ddi_remove_minor_node(dip, "devctl");
err_bad_devctl_node:
		px_err_rem_intr(&px_p->px_fault);
err_bad_intr:
		px_fm_detach(px_p);
err_bad_dma:
		px_pec_detach(px_p);
err_bad_pec:
		px_msi_detach(px_p);
err_bad_msi:
		px_msiq_detach(px_p);
err_bad_msiq:
		px_mmu_detach(px_p);
err_bad_mmu:
		px_cb_detach(px_p);
err_bad_cb:
		px_ib_detach(px_p);
err_bad_ib:
		if (px_lib_dev_fini(dip) != DDI_SUCCESS) {
			DBG(DBG_ATTACH, dip, "px_lib_dev_fini failed\n");
		}
err_bad_dev_init:
		px_free_props(px_p);
err_bad_px_prop:
		px_dbg_detach(dip, &px_p->px_dbg_hdl);
		mutex_destroy(&px_p->px_mutex);
		ddi_soft_state_free(px_state_p, instance);
err_bad_px_softstate:
		ret = DDI_FAILURE;
		break;

	case DDI_RESUME:
		DBG(DBG_ATTACH, dip, "DDI_RESUME\n");

		px_p = INST_TO_STATE(instance);

		mutex_enter(&px_p->px_mutex);

		/* suspend might have not succeeded */
		if (px_p->px_state != PX_SUSPENDED) {
			DBG(DBG_ATTACH, px_p->px_dip,
			    "instance NOT suspended\n");
			ret = DDI_FAILURE;
			break;
		}

		px_msiq_resume(px_p);
		px_lib_resume(dip);
		(void) pcie_pwr_resume(dip);
		px_p->px_state = PX_ATTACHED;

		mutex_exit(&px_p->px_mutex);

		break;
	default:
		DBG(DBG_ATTACH, dip, "unsupported attach op\n");
		ret = DDI_FAILURE;
		break;
	}

	return (ret);
}

/*
 * detach entry point:
 */
/*ARGSUSED*/
static int
px_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	px_t *px_p = INST_TO_STATE(instance);
	int ret;

	/*
	 * Make sure we are currently attached
	 */
	if (px_p->px_state != PX_ATTACHED) {
		DBG(DBG_DETACH, dip, "Instance not attached\n");
		return (DDI_FAILURE);
	}

	mutex_enter(&px_p->px_mutex);

	switch (cmd) {
	case DDI_DETACH:
		DBG(DBG_DETACH, dip, "DDI_DETACH\n");

		/*
		 * remove cpr callback
		 */
		px_cpr_rem_callb(px_p);

		if (px_p->px_dev_caps & PX_HOTPLUG_CAPABLE)
			if (px_uninit_hotplug(dip) != DDI_SUCCESS) {
				mutex_exit(&px_p->px_mutex);
				return (DDI_FAILURE);
			}

		/*
		 * things which used to be done in obj_destroy
		 * are now in-lined here.
		 */

		px_p->px_state = PX_DETACHED;

		pxtool_uninit(dip);

		ddi_remove_minor_node(dip, "devctl");
		px_err_rem_intr(&px_p->px_fault);
		px_fm_detach(px_p);
		px_pec_detach(px_p);
		px_pwr_teardown(dip);
		pwr_common_teardown(dip);
		px_msi_detach(px_p);
		px_msiq_detach(px_p);
		px_mmu_detach(px_p);
		px_cb_detach(px_p);
		px_ib_detach(px_p);
		if (px_lib_dev_fini(dip) != DDI_SUCCESS) {
			DBG(DBG_DETACH, dip, "px_lib_dev_fini failed\n");
		}

		/*
		 * Free the px soft state structure and the rest of the
		 * resources it's using.
		 */
		px_free_props(px_p);
		px_dbg_detach(dip, &px_p->px_dbg_hdl);
		mutex_exit(&px_p->px_mutex);
		mutex_destroy(&px_p->px_mutex);

		/* Free the interrupt-priorities prop if we created it. */
		{
			int len;

			if (ddi_getproplen(DDI_DEV_T_ANY, dip,
			    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
			    "interrupt-priorities", &len) == DDI_PROP_SUCCESS)
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    "interrupt-priorities");
		}

		px_p->px_dev_hdl = NULL;
		ddi_soft_state_free(px_state_p, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		if (pcie_pwr_suspend(dip) != DDI_SUCCESS) {
			mutex_exit(&px_p->px_mutex);
			return (DDI_FAILURE);
		}
		if ((ret = px_lib_suspend(dip)) == DDI_SUCCESS)
			px_p->px_state = PX_SUSPENDED;
		mutex_exit(&px_p->px_mutex);

		return (ret);

	default:
		DBG(DBG_DETACH, dip, "unsupported detach op\n");
		mutex_exit(&px_p->px_mutex);
		return (DDI_FAILURE);
	}
}

int
px_cb_attach(px_t *px_p)
{
	px_fault_t	*fault_p = &px_p->px_cb_fault;
	dev_info_t	*dip = px_p->px_dip;
	sysino_t	sysino;

	if (px_lib_intr_devino_to_sysino(dip,
	    px_p->px_inos[PX_INTR_XBC], &sysino) != DDI_SUCCESS)
		return (DDI_FAILURE);

	fault_p->px_fh_dip = dip;
	fault_p->px_fh_sysino = sysino;
	fault_p->px_err_func = px_err_cb_intr;
	fault_p->px_intr_ino = px_p->px_inos[PX_INTR_XBC];

	return (px_cb_add_intr(fault_p));
}

void
px_cb_detach(px_t *px_p)
{
	px_cb_rem_intr(&px_p->px_cb_fault);
}

/*
 * power management related initialization specific to px
 * called by px_attach()
 */
static int
px_pwr_setup(dev_info_t *dip)
{
	pcie_pwr_t *pwr_p;
	int instance = ddi_get_instance(dip);
	px_t *px_p = INST_TO_STATE(instance);
	ddi_intr_handle_impl_t hdl;

	ASSERT(PCIE_PMINFO(dip));
	pwr_p = PCIE_NEXUS_PMINFO(dip);
	ASSERT(pwr_p);

	/*
	 * indicate support LDI (Layered Driver Interface)
	 * Create the property, if it is not already there
	 */
	if (!ddi_prop_exists(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    DDI_KERNEL_IOCTL)) {
		if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
		    DDI_KERNEL_IOCTL, NULL, 0) != DDI_PROP_SUCCESS) {
			DBG(DBG_PWR, dip, "can't create kernel ioctl prop\n");
			return (DDI_FAILURE);
		}
	}
	/* No support for device PM. We are always at full power */
	pwr_p->pwr_func_lvl = PM_LEVEL_D0;

	mutex_init(&px_p->px_l23ready_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(px_pwr_pil));
	cv_init(&px_p->px_l23ready_cv, NULL, CV_DRIVER, NULL);

	/* Initialize handle */
	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_cb_arg1 = px_p;
	hdl.ih_ver = DDI_INTR_VERSION;
	hdl.ih_state = DDI_IHDL_STATE_ALLOC;
	hdl.ih_dip = dip;
	hdl.ih_pri = px_pwr_pil;

	/* Add PME_TO_ACK message handler */
	hdl.ih_cb_func = (ddi_intr_handler_t *)px_pmeq_intr;
	if (px_add_msiq_intr(dip, dip, &hdl, MSG_REC,
	    (msgcode_t)PCIE_PME_ACK_MSG, &px_p->px_pm_msiq_id) != DDI_SUCCESS) {
		DBG(DBG_PWR, dip, "px_pwr_setup: couldn't add "
		    " PME_TO_ACK intr\n");
		goto pwr_setup_err1;
	}
	px_lib_msg_setmsiq(dip, PCIE_PME_ACK_MSG, px_p->px_pm_msiq_id);
	px_lib_msg_setvalid(dip, PCIE_PME_ACK_MSG, PCIE_MSG_VALID);

	if (px_ib_update_intr_state(px_p, px_p->px_dip, hdl.ih_inum,
	    px_msiqid_to_devino(px_p, px_p->px_pm_msiq_id), px_pwr_pil,
	    PX_INTR_STATE_ENABLE, MSG_REC, PCIE_PME_ACK_MSG) != DDI_SUCCESS) {
		DBG(DBG_PWR, dip, "px_pwr_setup: PME_TO_ACK update interrupt"
		    " state failed\n");
		goto px_pwrsetup_err_state;
	}

	return (DDI_SUCCESS);

px_pwrsetup_err_state:
	px_lib_msg_setvalid(dip, PCIE_PME_ACK_MSG, PCIE_MSG_INVALID);
	(void) px_rem_msiq_intr(dip, dip, &hdl, MSG_REC, PCIE_PME_ACK_MSG,
	    px_p->px_pm_msiq_id);
pwr_setup_err1:
	mutex_destroy(&px_p->px_l23ready_lock);
	cv_destroy(&px_p->px_l23ready_cv);

	return (DDI_FAILURE);
}

/*
 * undo whatever is done in px_pwr_setup. called by px_detach()
 */
static void
px_pwr_teardown(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	px_t *px_p = INST_TO_STATE(instance);
	ddi_intr_handle_impl_t	hdl;

	if (!PCIE_PMINFO(dip) || !PCIE_NEXUS_PMINFO(dip))
		return;

	/* Initialize handle */
	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_ver = DDI_INTR_VERSION;
	hdl.ih_state = DDI_IHDL_STATE_ALLOC;
	hdl.ih_dip = dip;
	hdl.ih_pri = px_pwr_pil;

	px_lib_msg_setvalid(dip, PCIE_PME_ACK_MSG, PCIE_MSG_INVALID);
	(void) px_rem_msiq_intr(dip, dip, &hdl, MSG_REC, PCIE_PME_ACK_MSG,
	    px_p->px_pm_msiq_id);

	(void) px_ib_update_intr_state(px_p, px_p->px_dip, hdl.ih_inum,
	    px_msiqid_to_devino(px_p, px_p->px_pm_msiq_id), px_pwr_pil,
	    PX_INTR_STATE_DISABLE, MSG_REC, PCIE_PME_ACK_MSG);

	px_p->px_pm_msiq_id = (msiqid_t)-1;

	cv_destroy(&px_p->px_l23ready_cv);
	mutex_destroy(&px_p->px_l23ready_lock);
}

/* bus driver entry points */

/*
 * bus map entry point:
 *
 * 	if map request is for an rnumber
 *		get the corresponding regspec from device node
 * 	build a new regspec in our parent's format
 *	build a new map_req with the new regspec
 *	call up the tree to complete the mapping
 */
int
px_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	px_t *px_p = DIP_TO_STATE(dip);
	struct regspec p_regspec;
	ddi_map_req_t p_mapreq;
	int reglen, rval, r_no;
	pci_regspec_t reloc_reg, *rp = &reloc_reg;

	DBG(DBG_MAP, dip, "rdip=%s%d:",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	if (mp->map_flags & DDI_MF_USER_MAPPING)
		return (DDI_ME_UNIMPLEMENTED);

	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		reloc_reg = *(pci_regspec_t *)mp->map_obj.rp;	/* dup whole */
		break;

	case DDI_MT_RNUMBER:
		r_no = mp->map_obj.rnumber;
		DBG(DBG_MAP | DBG_CONT, dip, " r#=%x", r_no);

		if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&rp, &reglen) != DDI_SUCCESS)
			return (DDI_ME_RNUMBER_RANGE);

		if (r_no < 0 || r_no >= reglen / sizeof (pci_regspec_t)) {
			kmem_free(rp, reglen);
			return (DDI_ME_RNUMBER_RANGE);
		}
		rp += r_no;
		break;

	default:
		return (DDI_ME_INVAL);
	}
	DBG(DBG_MAP | DBG_CONT, dip, "\n");

	if ((rp->pci_phys_hi & PCI_REG_ADDR_M) == PCI_ADDR_CONFIG) {
		/*
		 * There may be a need to differentiate between PCI
		 * and PCI-Ex devices so the following range check is
		 * done correctly, depending on the implementation of
		 * px_pci bridge nexus driver.
		 */
		if ((off >= PCIE_CONF_HDR_SIZE) ||
		    (len > PCIE_CONF_HDR_SIZE) ||
		    (off + len > PCIE_CONF_HDR_SIZE))
			return (DDI_ME_INVAL);
		/*
		 * the following function returning a DDI_FAILURE assumes
		 * that there are no virtual config space access services
		 * defined in this layer. Otherwise it is availed right
		 * here and we return.
		 */
		rval = px_lib_map_vconfig(dip, mp, off, rp, addrp);
		if (rval == DDI_SUCCESS)
			goto done;
	}

	/*
	 * No virtual config space services or we are mapping
	 * a region of memory mapped config/IO/memory space, so proceed
	 * to the parent.
	 */

	/* relocate within 64-bit pci space through "assigned-addresses" */
	if (rval = px_reloc_reg(dip, rdip, px_p, rp))
		goto done;

	if (len)	/* adjust regspec according to mapping request */
		rp->pci_size_low = len;	/* MIN ? */
	rp->pci_phys_low += off;

	/* translate relocated pci regspec into parent space through "ranges" */
	if (rval = px_xlate_reg(px_p, rp, &p_regspec))
		goto done;

	p_mapreq = *mp;		/* dup the whole structure */
	p_mapreq.map_type = DDI_MT_REGSPEC;
	p_mapreq.map_obj.rp = &p_regspec;
	px_lib_map_attr_check(&p_mapreq);
	rval = ddi_map(dip, &p_mapreq, 0, 0, addrp);

	if (rval == DDI_SUCCESS) {
		/*
		 * Set-up access functions for FM access error capable drivers.
		 */
		if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(rdip)))
			px_fm_acc_setup(mp, rdip, rp);
	}

done:
	if (mp->map_type == DDI_MT_RNUMBER)
		kmem_free(rp - r_no, reglen);

	return (rval);
}

/*
 * bus dma map entry point
 * return value:
 *	DDI_DMA_PARTIAL_MAP	 1
 *	DDI_DMA_MAPOK		 0
 *	DDI_DMA_MAPPED		 0
 *	DDI_DMA_NORESOURCES	-1
 *	DDI_DMA_NOMAPPING	-2
 *	DDI_DMA_TOOBIG		-3
 */
int
px_dma_setup(dev_info_t *dip, dev_info_t *rdip, ddi_dma_req_t *dmareq,
	ddi_dma_handle_t *handlep)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_mmu_t *mmu_p = px_p->px_mmu_p;
	ddi_dma_impl_t *mp;
	int ret;

	DBG(DBG_DMA_MAP, dip, "mapping - rdip=%s%d type=%s\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    handlep ? "alloc" : "advisory");

	if (!(mp = px_dma_lmts2hdl(dip, rdip, mmu_p, dmareq)))
		return (DDI_DMA_NORESOURCES);
	if (mp == (ddi_dma_impl_t *)DDI_DMA_NOMAPPING)
		return (DDI_DMA_NOMAPPING);
	if (ret = px_dma_type(px_p, dmareq, mp))
		goto freehandle;
	if (ret = px_dma_pfn(px_p, dmareq, mp))
		goto freehandle;

	switch (PX_DMA_TYPE(mp)) {
	case PX_DMAI_FLAGS_DVMA:	/* LINTED E_EQUALITY_NOT_ASSIGNMENT */
		if ((ret = px_dvma_win(px_p, dmareq, mp)) || !handlep)
			goto freehandle;
		if (!PX_DMA_CANCACHE(mp)) {	/* try fast track */
			if (PX_DMA_CANFAST(mp)) {
				if (!px_dvma_map_fast(mmu_p, mp))
					break;
			/* LINTED E_NOP_ELSE_STMT */
			} else {
				PX_DVMA_FASTTRAK_PROF(mp);
			}
		}
		if (ret = px_dvma_map(mp, dmareq, mmu_p))
			goto freehandle;
		break;
	case PX_DMAI_FLAGS_PTP:	/* LINTED E_EQUALITY_NOT_ASSIGNMENT */
		if ((ret = px_dma_physwin(px_p, dmareq, mp)) || !handlep)
			goto freehandle;
		break;
	case PX_DMAI_FLAGS_BYPASS:
	default:
		cmn_err(CE_PANIC, "%s%d: px_dma_setup: bad dma type 0x%x",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    PX_DMA_TYPE(mp));
		/*NOTREACHED*/
	}
	*handlep = (ddi_dma_handle_t)mp;
	mp->dmai_flags |= PX_DMAI_FLAGS_INUSE;
	px_dump_dma_handle(DBG_DMA_MAP, dip, mp);

	return ((mp->dmai_nwin == 1) ? DDI_DMA_MAPPED : DDI_DMA_PARTIAL_MAP);
freehandle:
	if (ret == DDI_DMA_NORESOURCES)
		px_dma_freemp(mp); /* don't run_callback() */
	else
		(void) px_dma_freehdl(dip, rdip, (ddi_dma_handle_t)mp);
	return (ret);
}


/*
 * bus dma alloc handle entry point:
 */
int
px_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attrp,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	px_t *px_p = DIP_TO_STATE(dip);
	ddi_dma_impl_t *mp;
	int rval;

	DBG(DBG_DMA_ALLOCH, dip, "rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	if (attrp->dma_attr_version != DMA_ATTR_V0)
		return (DDI_DMA_BADATTR);

	if (!(mp = px_dma_allocmp(dip, rdip, waitfp, arg)))
		return (DDI_DMA_NORESOURCES);

	/*
	 * Save requestor's information
	 */
	mp->dmai_attr	= *attrp; /* whole object - augmented later  */
	*PX_DEV_ATTR(mp)	= *attrp; /* whole object - device orig attr */
	DBG(DBG_DMA_ALLOCH, dip, "mp=%p\n", mp);

	/* check and convert dma attributes to handle parameters */
	if (rval = px_dma_attr2hdl(px_p, mp)) {
		px_dma_freehdl(dip, rdip, (ddi_dma_handle_t)mp);
		*handlep = NULL;
		return (rval);
	}
	*handlep = (ddi_dma_handle_t)mp;
	return (DDI_SUCCESS);
}


/*
 * bus dma free handle entry point:
 */
/*ARGSUSED*/
int
px_dma_freehdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	DBG(DBG_DMA_FREEH, dip, "rdip=%s%d mp=%p\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), handle);
	px_dma_freemp((ddi_dma_impl_t *)handle);

	if (px_kmem_clid) {
		DBG(DBG_DMA_FREEH, dip, "run handle callback\n");
		ddi_run_callback(&px_kmem_clid);
	}
	return (DDI_SUCCESS);
}


/*
 * bus dma bind handle entry point:
 */
int
px_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, ddi_dma_req_t *dmareq,
	ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	px_t *px_p = DIP_TO_STATE(dip);
	px_mmu_t *mmu_p = px_p->px_mmu_p;
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	int ret;

	DBG(DBG_DMA_BINDH, dip, "rdip=%s%d mp=%p dmareq=%p\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), mp, dmareq);

	if (mp->dmai_flags & PX_DMAI_FLAGS_INUSE)
		return (DDI_DMA_INUSE);

	ASSERT((mp->dmai_flags & ~PX_DMAI_FLAGS_PRESERVE) == 0);
	mp->dmai_flags |= PX_DMAI_FLAGS_INUSE;

	if (ret = px_dma_type(px_p, dmareq, mp))
		goto err;
	if (ret = px_dma_pfn(px_p, dmareq, mp))
		goto err;

	switch (PX_DMA_TYPE(mp)) {
	case PX_DMAI_FLAGS_DVMA:
		if (ret = px_dvma_win(px_p, dmareq, mp))
			goto map_err;
		if (!PX_DMA_CANCACHE(mp)) {	/* try fast track */
			if (PX_DMA_CANFAST(mp)) {
				if (!px_dvma_map_fast(mmu_p, mp))
					goto mapped; /*LINTED E_NOP_ELSE_STMT*/
			} else {
				PX_DVMA_FASTTRAK_PROF(mp);
			}
		}
		if (ret = px_dvma_map(mp, dmareq, mmu_p))
			goto map_err;
mapped:
		*ccountp = 1;
		MAKE_DMA_COOKIE(cookiep, mp->dmai_mapping, mp->dmai_size);
		break;
	case PX_DMAI_FLAGS_BYPASS:
	case PX_DMAI_FLAGS_PTP:
		if (ret = px_dma_physwin(px_p, dmareq, mp))
			goto map_err;
		*ccountp = PX_WINLST(mp)->win_ncookies;
		*cookiep =
		    *(ddi_dma_cookie_t *)(PX_WINLST(mp) + 1); /* wholeobj */
		break;
	default:
		cmn_err(CE_PANIC, "%s%d: px_dma_bindhdl(%p): bad dma type",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), mp);
		/*NOTREACHED*/
	}
	DBG(DBG_DMA_BINDH, dip, "cookie %" PRIx64 "+%x\n",
	    cookiep->dmac_address, cookiep->dmac_size);
	px_dump_dma_handle(DBG_DMA_MAP, dip, mp);

	/* insert dma handle into FMA cache */
	if (mp->dmai_attr.dma_attr_flags & DDI_DMA_FLAGERR) {
		(void) ndi_fmc_insert(rdip, DMA_HANDLE, mp, NULL);
		mp->dmai_error.err_cf = px_err_dma_hdl_check;
	}

	return (mp->dmai_nwin == 1 ? DDI_DMA_MAPPED : DDI_DMA_PARTIAL_MAP);
map_err:
	px_dma_freepfn(mp);
err:
	mp->dmai_flags &= PX_DMAI_FLAGS_PRESERVE;
	return (ret);
}


/*
 * bus dma unbind handle entry point:
 */
/*ARGSUSED*/
int
px_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	px_t *px_p = DIP_TO_STATE(dip);
	px_mmu_t *mmu_p = px_p->px_mmu_p;

	DBG(DBG_DMA_UNBINDH, dip, "rdip=%s%d, mp=%p\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), handle);
	if ((mp->dmai_flags & PX_DMAI_FLAGS_INUSE) == 0) {
		DBG(DBG_DMA_UNBINDH, dip, "handle not inuse\n");
		return (DDI_FAILURE);
	}

	/* remove dma handle from FMA cache */
	if (mp->dmai_attr.dma_attr_flags & DDI_DMA_FLAGERR) {
		if (DEVI(rdip)->devi_fmhdl != NULL &&
		    DDI_FM_DMA_ERR_CAP(DEVI(rdip)->devi_fmhdl->fh_cap)) {
			(void) ndi_fmc_remove(rdip, DMA_HANDLE, mp);
		}
	}

	/*
	 * Here if the handle is using the iommu.  Unload all the iommu
	 * translations.
	 */
	switch (PX_DMA_TYPE(mp)) {
	case PX_DMAI_FLAGS_DVMA:
		px_mmu_unmap_window(mmu_p, mp);
		px_dvma_unmap(mmu_p, mp);
		px_dma_freepfn(mp);
		break;
	case PX_DMAI_FLAGS_BYPASS:
	case PX_DMAI_FLAGS_PTP:
		px_dma_freewin(mp);
		break;
	default:
		cmn_err(CE_PANIC, "%s%d: px_dma_unbindhdl:bad dma type %p",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), mp);
		/*NOTREACHED*/
	}
	if (mmu_p->mmu_dvma_clid != 0) {
		DBG(DBG_DMA_UNBINDH, dip, "run dvma callback\n");
		ddi_run_callback(&mmu_p->mmu_dvma_clid);
	}
	if (px_kmem_clid) {
		DBG(DBG_DMA_UNBINDH, dip, "run handle callback\n");
		ddi_run_callback(&px_kmem_clid);
	}
	mp->dmai_flags &= PX_DMAI_FLAGS_PRESERVE;

	return (DDI_SUCCESS);
}

/*
 * bus dma win entry point:
 */
int
px_dma_win(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, uint_t win, off_t *offp,
	size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	ddi_dma_impl_t	*mp = (ddi_dma_impl_t *)handle;
	int		ret;

	DBG(DBG_DMA_WIN, dip, "rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	px_dump_dma_handle(DBG_DMA_WIN, dip, mp);
	if (win >= mp->dmai_nwin) {
		DBG(DBG_DMA_WIN, dip, "%x out of range\n", win);
		return (DDI_FAILURE);
	}

	switch (PX_DMA_TYPE(mp)) {
	case PX_DMAI_FLAGS_DVMA:
		if (win != PX_DMA_CURWIN(mp)) {
			px_t *px_p = DIP_TO_STATE(dip);
			px_mmu_t *mmu_p = px_p->px_mmu_p;
			px_mmu_unmap_window(mmu_p, mp);

			/* map_window sets dmai_mapping/size/offset */
			px_mmu_map_window(mmu_p, mp, win);
			if ((ret = px_mmu_map_window(mmu_p,
			    mp, win)) != DDI_SUCCESS)
				return (ret);
		}
		if (cookiep)
			MAKE_DMA_COOKIE(cookiep, mp->dmai_mapping,
			    mp->dmai_size);
		if (ccountp)
			*ccountp = 1;
		break;
	case PX_DMAI_FLAGS_PTP:
	case PX_DMAI_FLAGS_BYPASS: {
		int i;
		ddi_dma_cookie_t *ck_p;
		px_dma_win_t *win_p = mp->dmai_winlst;

		for (i = 0; i < win; win_p = win_p->win_next, i++) {};
		ck_p = (ddi_dma_cookie_t *)(win_p + 1);
		*cookiep = *ck_p;
		mp->dmai_offset = win_p->win_offset;
		mp->dmai_size   = win_p->win_size;
		mp->dmai_mapping = ck_p->dmac_laddress;
		mp->dmai_cookie = ck_p + 1;
		win_p->win_curseg = 0;
		if (ccountp)
			*ccountp = win_p->win_ncookies;
		}
		break;
	default:
		cmn_err(CE_WARN, "%s%d: px_dma_win:bad dma type 0x%x",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    PX_DMA_TYPE(mp));
		return (DDI_FAILURE);
	}
	if (cookiep)
		DBG(DBG_DMA_WIN, dip,
		    "cookie - dmac_address=%x dmac_size=%x\n",
		    cookiep->dmac_address, cookiep->dmac_size);
	if (offp)
		*offp = (off_t)mp->dmai_offset;
	if (lenp)
		*lenp = mp->dmai_size;
	return (DDI_SUCCESS);
}

#ifdef	DEBUG
static char *px_dmactl_str[] = {
	"DDI_DMA_FREE",
	"DDI_DMA_SYNC",
	"DDI_DMA_HTOC",
	"DDI_DMA_KVADDR",
	"DDI_DMA_MOVWIN",
	"DDI_DMA_REPWIN",
	"DDI_DMA_GETERR",
	"DDI_DMA_COFF",
	"DDI_DMA_NEXTWIN",
	"DDI_DMA_NEXTSEG",
	"DDI_DMA_SEGTOC",
	"DDI_DMA_RESERVE",
	"DDI_DMA_RELEASE",
	"DDI_DMA_RESETH",
	"DDI_DMA_CKSYNC",
	"DDI_DMA_IOPB_ALLOC",
	"DDI_DMA_IOPB_FREE",
	"DDI_DMA_SMEM_ALLOC",
	"DDI_DMA_SMEM_FREE",
	"DDI_DMA_SET_SBUS64"
};
#endif	/* DEBUG */

/*
 * bus dma control entry point:
 */
/*ARGSUSED*/
int
px_dma_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;

#ifdef	DEBUG
	DBG(DBG_DMA_CTL, dip, "%s: rdip=%s%d\n", px_dmactl_str[cmd],
	    ddi_driver_name(rdip), ddi_get_instance(rdip));
#endif	/* DEBUG */

	switch (cmd) {
	case DDI_DMA_FREE:
		(void) px_dma_unbindhdl(dip, rdip, handle);
		(void) px_dma_freehdl(dip, rdip, handle);
		return (DDI_SUCCESS);
	case DDI_DMA_RESERVE: {
		px_t *px_p = DIP_TO_STATE(dip);
		return (px_fdvma_reserve(dip, rdip, px_p,
		    (ddi_dma_req_t *)offp, (ddi_dma_handle_t *)objp));
		}
	case DDI_DMA_RELEASE: {
		px_t *px_p = DIP_TO_STATE(dip);
		return (px_fdvma_release(dip, px_p, mp));
		}
	default:
		break;
	}

	switch (PX_DMA_TYPE(mp)) {
	case PX_DMAI_FLAGS_DVMA:
		return (px_dvma_ctl(dip, rdip, mp, cmd, offp, lenp, objp,
		    cache_flags));
	case PX_DMAI_FLAGS_PTP:
	case PX_DMAI_FLAGS_BYPASS:
		return (px_dma_ctl(dip, rdip, mp, cmd, offp, lenp, objp,
		    cache_flags));
	default:
		cmn_err(CE_PANIC, "%s%d: px_dma_ctlops(%x):bad dma type %x",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), cmd,
		    mp->dmai_flags);
		/*NOTREACHED*/
	}
	return (0);
}

/*
 * control ops entry point:
 *
 * Requests handled completely:
 *	DDI_CTLOPS_INITCHILD	see init_child() for details
 *	DDI_CTLOPS_UNINITCHILD
 *	DDI_CTLOPS_REPORTDEV	see report_dev() for details
 *	DDI_CTLOPS_IOMIN	cache line size if streaming otherwise 1
 *	DDI_CTLOPS_REGSIZE
 *	DDI_CTLOPS_NREGS
 *	DDI_CTLOPS_DVMAPAGESIZE
 *	DDI_CTLOPS_POKE
 *	DDI_CTLOPS_PEEK
 *
 * All others passed to parent.
 */
int
px_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result)
{
	px_t *px_p = DIP_TO_STATE(dip);
	struct detachspec *ds;
	struct attachspec *as;

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		return (px_init_child(px_p, (dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (px_uninit_child(px_p, (dev_info_t *)arg));

	case DDI_CTLOPS_ATTACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		as = (struct attachspec *)arg;
		switch (as->when) {
		case DDI_PRE:
			if (as->cmd == DDI_ATTACH) {
				DBG(DBG_PWR, dip, "PRE_ATTACH for %s@%d\n",
				    ddi_driver_name(rdip),
				    ddi_get_instance(rdip));
				return (pcie_pm_hold(dip));
			}
			if (as->cmd == DDI_RESUME) {
				DBG(DBG_PWR, dip, "PRE_RESUME for %s@%d\n",
				    ddi_driver_name(rdip),
				    ddi_get_instance(rdip));

				pcie_clear_errors(rdip);
			}
			return (DDI_SUCCESS);

		case DDI_POST:
			DBG(DBG_PWR, dip, "POST_ATTACH for %s@%d\n",
			    ddi_driver_name(rdip), ddi_get_instance(rdip));
			if (as->cmd == DDI_ATTACH && as->result != DDI_SUCCESS)
				pcie_pm_release(dip);

			if (as->result == DDI_SUCCESS)
				pf_init(rdip, (void *)px_p->px_fm_ibc, as->cmd);

			(void) pcie_postattach_child(rdip);

			return (DDI_SUCCESS);
		default:
			break;
		}
		break;

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		ds = (struct detachspec *)arg;
		switch (ds->when) {
		case DDI_POST:
			if (ds->cmd == DDI_DETACH &&
			    ds->result == DDI_SUCCESS) {
				DBG(DBG_PWR, dip, "POST_DETACH for %s@%d\n",
				    ddi_driver_name(rdip),
				    ddi_get_instance(rdip));
				return (pcie_pm_remove_child(dip, rdip));
			}
			return (DDI_SUCCESS);
		case DDI_PRE:
			pf_fini(rdip, ds->cmd);
			return (DDI_SUCCESS);
		default:
			break;
		}
		break;

	case DDI_CTLOPS_REPORTDEV:
		return (px_report_dev(rdip));

	case DDI_CTLOPS_IOMIN:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
		*((off_t *)result) = px_get_reg_set_size(rdip, *((int *)arg));
		return (*((off_t *)result) == 0 ? DDI_FAILURE : DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		*((uint_t *)result) = px_get_nreg_set(rdip);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_DVMAPAGESIZE:
		*((ulong_t *)result) = MMU_PAGE_SIZE;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_POKE:	/* platform dependent implementation. */
		return (px_lib_ctlops_poke(dip, rdip,
		    (peekpoke_ctlops_t *)arg));

	case DDI_CTLOPS_PEEK:	/* platform dependent implementation. */
		return (px_lib_ctlops_peek(dip, rdip,
		    (peekpoke_ctlops_t *)arg, result));

	case DDI_CTLOPS_POWER:
	default:
		break;
	}

	/*
	 * Now pass the request up to our parent.
	 */
	DBG(DBG_CTLOPS, dip, "passing request to parent: rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));
	return (ddi_ctlops(dip, rdip, op, arg, result));
}

/* ARGSUSED */
int
px_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	intr_types, ret = DDI_SUCCESS;

	DBG(DBG_INTROPS, dip, "px_intr_ops: rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	/* Process DDI_INTROP_SUPPORTED_TYPES request here */
	if (intr_op == DDI_INTROP_SUPPORTED_TYPES) {
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;

		if ((pci_msi_get_supported_type(rdip,
		    &intr_types)) == DDI_SUCCESS) {
			/*
			 * Double check supported interrupt types vs.
			 * what the host bridge supports.
			 */
			*(int *)result |= intr_types;
		}

		return (ret);
	}

	/*
	 * PCI-E nexus driver supports fixed, MSI and MSI-X interrupts.
	 * Return failure if interrupt type is not supported.
	 */
	switch (hdlp->ih_type) {
	case DDI_INTR_TYPE_FIXED:
		ret = px_intx_ops(dip, rdip, intr_op, hdlp, result);
		break;
	case DDI_INTR_TYPE_MSI:
	case DDI_INTR_TYPE_MSIX:
		ret = px_msix_ops(dip, rdip, intr_op, hdlp, result);
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

static int
px_init_hotplug(px_t *px_p)
{
	px_bus_range_t bus_range;
	dev_info_t *dip;
	pciehpc_regops_t regops;

	dip = px_p->px_dip;

	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "hotplug-capable") == 0)
		return (DDI_FAILURE);

	/*
	 * Before initializing hotplug - open up bus range.  The busra
	 * module will initialize its pool of bus numbers from this.
	 * "busra" will be the agent that keeps track of them during
	 * hotplug.  Also, note, that busra will remove any bus numbers
	 * already in use from boot time.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bus-range") == 0) {
		cmn_err(CE_WARN, "%s%d: bus-range not found\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
#ifdef	DEBUG
		bus_range.lo = 0x0;
		bus_range.hi = 0xff;

		if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
		    dip, "bus-range", (int *)&bus_range, 2)
		    != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}
#else
		return (DDI_FAILURE);
#endif
	}

	if (px_lib_hotplug_init(dip, (void *)&regops) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (pciehpc_init(dip, &regops) != DDI_SUCCESS) {
		px_lib_hotplug_uninit(dip);
		return (DDI_FAILURE);
	}

	if (pcihp_init(dip) != DDI_SUCCESS) {
		(void) pciehpc_uninit(dip);
		px_lib_hotplug_uninit(dip);
		return (DDI_FAILURE);
	}

	if (pcihp_get_cb_ops() != NULL) {
		DBG(DBG_ATTACH, dip, "%s%d hotplug enabled",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		px_p->px_dev_caps |= PX_HOTPLUG_CAPABLE;
	}

	return (DDI_SUCCESS);
}

static int
px_uninit_hotplug(dev_info_t *dip)
{
	if (pcihp_uninit(dip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (pciehpc_uninit(dip) != DDI_SUCCESS)
		return (DDI_FAILURE);

	px_lib_hotplug_uninit(dip);

	return (DDI_SUCCESS);
}
