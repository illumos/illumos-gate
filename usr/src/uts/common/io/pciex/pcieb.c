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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 * Common x86 and SPARC PCI-E to PCI bus bridge nexus driver
 */

#include <sys/sysmacros.h>
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
#include <sys/fm/util.h>
#include <sys/pci_cap.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/promif.h>		/* prom_printf */
#include <sys/disp.h>
#include <sys/pcie_pwr.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include "pcieb.h"
#ifdef PX_PLX
#include <io/pciex/pcieb_plx.h>
#endif /* PX_PLX */

/*LINTLIBRARY*/

/* panic flag */
int pcieb_die = PF_ERR_FATAL_FLAGS;
int pcieb_disable_41210_wkarnd = 0;

/* flag to turn on MSI support */
int pcieb_enable_msi = 1;

#if defined(DEBUG)
uint_t pcieb_dbg_print = 0;

static char *pcieb_debug_sym [] = {	/* same sequence as pcieb_debug_bit */
	/*  0 */ "attach",
	/*  1 */ "pwr",
	/*  2 */ "intr"
};
#endif /* DEBUG */

static int pcieb_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *, off_t,
	off_t, caddr_t *);
static int pcieb_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
	void *);
static int pcieb_fm_init(pcieb_devstate_t *pcieb_p);
static void pcieb_fm_fini(pcieb_devstate_t *pcieb_p);
static int pcieb_fm_init_child(dev_info_t *dip, dev_info_t *cdip, int cap,
    ddi_iblock_cookie_t *ibc_p);
static int pcieb_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_attr_t *attr_p, int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_handle_t *handlep);
static int pcieb_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, enum ddi_dma_ctlops cmd, off_t *offp,
	size_t *lenp, caddr_t *objp, uint_t cache_flags);
static int pcieb_intr_ops(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);

static struct bus_ops pcieb_bus_ops = {
	BUSO_REV,
	pcieb_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	0,
	pcieb_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	pcieb_dma_mctl,
	pcieb_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,	/* (*bus_get_eventcookie)();	*/
	ndi_busop_add_eventcall,	/* (*bus_add_eventcall)();	*/
	ndi_busop_remove_eventcall,	/* (*bus_remove_eventcall)();	*/
	ndi_post_event,			/* (*bus_post_event)();		*/
	NULL,				/* (*bus_intr_ctl)();		*/
	NULL,				/* (*bus_config)();		*/
	NULL,				/* (*bus_unconfig)();		*/
	pcieb_fm_init_child,		/* (*bus_fm_init)();		*/
	NULL,				/* (*bus_fm_fini)();		*/
	i_ndi_busop_access_enter,	/* (*bus_fm_access_enter)();	*/
	i_ndi_busop_access_exit,	/* (*bus_fm_access_exit)();	*/
	pcie_bus_power,			/* (*bus_power)();		*/
	pcieb_intr_ops,			/* (*bus_intr_op)();		*/
	pcie_hp_common_ops		/* (*bus_hp_op)();		*/
};

static int	pcieb_open(dev_t *, int, int, cred_t *);
static int	pcieb_close(dev_t, int, int, cred_t *);
static int	pcieb_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int	pcieb_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static uint_t	pcieb_intr_handler(caddr_t arg1, caddr_t arg2);

/* PM related functions */
static int	pcieb_pwr_setup(dev_info_t *dip);
static int	pcieb_pwr_init_and_raise(dev_info_t *dip, pcie_pwr_t *pwr_p);
static void	pcieb_pwr_teardown(dev_info_t *dip);
static int	pcieb_pwr_disable(dev_info_t *dip);

/* Hotplug related functions */
static void pcieb_id_props(pcieb_devstate_t *pcieb);

/*
 * soft state pointer
 */
void *pcieb_state;

static struct cb_ops pcieb_cb_ops = {
	pcieb_open,			/* open */
	pcieb_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pcieb_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pcie_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static int	pcieb_probe(dev_info_t *);
static int	pcieb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int	pcieb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

static struct dev_ops pcieb_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	pcieb_info,		/* info */
	nulldev,		/* identify */
	pcieb_probe,		/* probe */
	pcieb_attach,		/* attach */
	pcieb_detach,		/* detach */
	nulldev,		/* reset */
	&pcieb_cb_ops,		/* driver operations */
	&pcieb_bus_ops,		/* bus operations */
	pcie_power,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"PCIe bridge/switch driver",
	&pcieb_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * forward function declarations:
 */
static void	pcieb_uninitchild(dev_info_t *);
static int	pcieb_initchild(dev_info_t *child);
static void	pcieb_create_ranges_prop(dev_info_t *, ddi_acc_handle_t);
static boolean_t pcieb_is_pcie_device_type(dev_info_t *dip);

/* interrupt related declarations */
static int	pcieb_msi_supported(dev_info_t *);
static int	pcieb_intr_attach(pcieb_devstate_t *pcieb);
static int	pcieb_intr_init(pcieb_devstate_t *pcieb_p, int intr_type);
static void	pcieb_intr_fini(pcieb_devstate_t *pcieb_p);

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&pcieb_state, sizeof (pcieb_devstate_t),
	    1)) == 0 && (e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pcieb_state);
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&pcieb_state);
	}
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
pcieb_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	minor_t		minor = getminor((dev_t)arg);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state, instance);
	int		ret = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		if (pcieb == NULL) {
			ret = DDI_FAILURE;
			break;
		}

		*result = (void *)pcieb->pcieb_dip;
		break;
	default:
		ret = DDI_FAILURE;
		break;
	}

	return (ret);
}


/*ARGSUSED*/
static int
pcieb_probe(dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

/*
 * This is a workaround for an undocumented HW erratum with the
 * multi-function, F0 and F2, Intel 41210 PCIe-to-PCI bridge. When
 * Fn (cdip) attaches, this workaround is called to initialize Fn's
 * sibling (sdip) with MPS/MRRS if it isn't already configured.
 * Doing so prevents a malformed TLP panic.
 */
static void
pcieb_41210_mps_wkrnd(dev_info_t *cdip)
{
	dev_info_t *sdip;
	ddi_acc_handle_t cfg_hdl;
	uint16_t cdip_dev_ctrl, cdip_mrrs_mps;
	pcie_bus_t *cdip_bus_p = PCIE_DIP2BUS(cdip);

	/* Get cdip's MPS/MRRS already setup by pcie_initchild_mps() */
	ASSERT(cdip_bus_p);
	cdip_dev_ctrl  = PCIE_CAP_GET(16, cdip_bus_p, PCIE_DEVCTL);
	cdip_mrrs_mps  = cdip_dev_ctrl &
	    (PCIE_DEVCTL_MAX_READ_REQ_MASK | PCIE_DEVCTL_MAX_PAYLOAD_MASK);

	/* Locate sdip and set its MPS/MRRS when applicable */
	for (sdip = ddi_get_child(ddi_get_parent(cdip)); sdip;
	    sdip = ddi_get_next_sibling(sdip)) {
		uint16_t sdip_dev_ctrl, sdip_mrrs_mps, cap_ptr;
		uint32_t bus_dev_ven_id;

		if (sdip == cdip || pci_config_setup(sdip, &cfg_hdl)
		    != DDI_SUCCESS)
			continue;

		/* must be an Intel 41210 bridge */
		bus_dev_ven_id = pci_config_get32(cfg_hdl, PCI_CONF_VENID);
		if (!PCIEB_IS_41210_BRIDGE(bus_dev_ven_id)) {
			pci_config_teardown(&cfg_hdl);
			continue;
		}

		if (PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_ID_PCI_E, &cap_ptr)
		    != DDI_SUCCESS) {
			pci_config_teardown(&cfg_hdl);
			continue;
		}

		/* get sdip's MPS/MRRS to compare to cdip's */
		sdip_dev_ctrl = PCI_CAP_GET16(cfg_hdl, 0, cap_ptr,
		    PCIE_DEVCTL);
		sdip_mrrs_mps = sdip_dev_ctrl &
		    (PCIE_DEVCTL_MAX_READ_REQ_MASK |
		    PCIE_DEVCTL_MAX_PAYLOAD_MASK);

		/* if sdip already attached then its MPS/MRRS is configured */
		if (i_ddi_devi_attached(sdip)) {
			ASSERT(sdip_mrrs_mps == cdip_mrrs_mps);
			pci_config_teardown(&cfg_hdl);
			continue;
		}

		/* otherwise, update sdip's MPS/MRRS if different from cdip's */
		if (sdip_mrrs_mps != cdip_mrrs_mps) {
			sdip_dev_ctrl = (sdip_dev_ctrl &
			    ~(PCIE_DEVCTL_MAX_READ_REQ_MASK |
			    PCIE_DEVCTL_MAX_PAYLOAD_MASK)) | cdip_mrrs_mps;

			PCI_CAP_PUT16(cfg_hdl, 0, cap_ptr, PCIE_DEVCTL,
			    sdip_dev_ctrl);
		}

		/*
		 * note: sdip's bus_mps will be updated by
		 * pcie_initchild_mps()
		 */

		pci_config_teardown(&cfg_hdl);

		break;
	}
}

static int
pcieb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int			instance;
	char			device_type[8];
	pcieb_devstate_t	*pcieb;
	pcie_bus_t		*bus_p = PCIE_DIP2UPBUS(devi);
	ddi_acc_handle_t	config_handle = bus_p->bus_cfg_hdl;

	switch (cmd) {
	case DDI_RESUME:
		(void) pcie_pwr_resume(devi);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	case DDI_ATTACH:
		break;
	}

	if (!(PCIE_IS_BDG(bus_p))) {
		PCIEB_DEBUG(DBG_ATTACH, devi, "This is not a switch or"
		" bridge\n");
		return (DDI_FAILURE);
	}

	/*
	 * If PCIE_LINKCTL_LINK_DISABLE bit in the PCIe Config
	 * Space (PCIe Capability Link Control Register) is set,
	 * then do not bind the driver.
	 */
	if (PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL) & PCIE_LINKCTL_LINK_DISABLE)
		return (DDI_FAILURE);

	/*
	 * Allocate and get soft state structure.
	 */
	instance = ddi_get_instance(devi);
	if (ddi_soft_state_zalloc(pcieb_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	pcieb = ddi_get_soft_state(pcieb_state, instance);
	pcieb->pcieb_dip = devi;

	if ((pcieb_fm_init(pcieb)) != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_ATTACH, devi, "Failed in pcieb_fm_init\n");
		goto fail;
	}
	pcieb->pcieb_init_flags |= PCIEB_INIT_FM;

	mutex_init(&pcieb->pcieb_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pcieb->pcieb_err_mutex, NULL, MUTEX_DRIVER,
	    (void *)pcieb->pcieb_fm_ibc);
	mutex_init(&pcieb->pcieb_peek_poke_mutex, NULL, MUTEX_DRIVER,
	    (void *)pcieb->pcieb_fm_ibc);

	/* create special properties for device identification */
	pcieb_id_props(pcieb);

	/*
	 * Power management setup. This also makes sure that switch/bridge
	 * is at D0 during attach.
	 */
	if (pwr_common_setup(devi) != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_PWR, devi, "pwr_common_setup failed\n");
		goto fail;
	}

	if (pcieb_pwr_setup(devi) != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_PWR, devi, "pxb_pwr_setup failed \n");
		goto fail;
	}

	/*
	 * Make sure the "device_type" property exists.
	 */
	if (pcieb_is_pcie_device_type(devi))
		(void) strcpy(device_type, "pciex");
	else
		(void) strcpy(device_type, "pci");

	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "device_type", device_type);

	/*
	 * Check whether the "ranges" property is present.
	 * Otherwise create the ranges property by reading
	 * the configuration registers
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "ranges") == 0) {
		pcieb_create_ranges_prop(devi, config_handle);
	}

	if (PCIE_IS_PCI_BDG(bus_p))
		pcieb_set_pci_perf_parameters(devi, config_handle);

#ifdef PX_PLX
	pcieb_attach_plx_workarounds(pcieb);
#endif /* PX_PLX */

	if (pcie_init(devi, NULL) != DDI_SUCCESS)
		goto fail;

	/* Intel PCIe-to-PCI 41210 bridge workaround -- if applicable */
	if (pcieb_disable_41210_wkarnd == 0 &&
	    PCIEB_IS_41210_BRIDGE(bus_p->bus_dev_ven_id))
		pcieb_41210_mps_wkrnd(devi);

	/*
	 * Initialize interrupt handlers. Ignore return value.
	 */
	(void) pcieb_intr_attach(pcieb);

	(void) pcie_hpintr_enable(devi);

	/* Do any platform specific workarounds needed at this time */
	pcieb_plat_attach_workaround(devi);

	/*
	 * If this is a root port, determine and set the max payload size.
	 * Since this will involve scanning the fabric, all error enabling
	 * and sw workarounds should be in place before doing this.
	 */
	if (PCIE_IS_RP(bus_p))
		pcie_init_root_port_mps(devi);

	ddi_report_dev(devi);
	return (DDI_SUCCESS);

fail:
	(void) pcieb_detach(devi, DDI_DETACH);
	return (DDI_FAILURE);
}

static int
pcieb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	pcieb_devstate_t *pcieb;
	int error = DDI_SUCCESS;

	switch (cmd) {
	case DDI_SUSPEND:
		error = pcie_pwr_suspend(devi);
		return (error);

	case DDI_DETACH:
		break;

	default:
		return (DDI_FAILURE);
	}

	pcieb = ddi_get_soft_state(pcieb_state, ddi_get_instance(devi));

	/* disable hotplug interrupt */
	(void) pcie_hpintr_disable(devi);

	/* remove interrupt handlers */
	pcieb_intr_fini(pcieb);

	/* uninitialize inband PCI-E HPC if present */
	(void) pcie_uninit(devi);

	(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");

	(void) ndi_prop_remove(DDI_DEV_T_NONE, pcieb->pcieb_dip,
	    "pcie_ce_mask");

	if (pcieb->pcieb_init_flags & PCIEB_INIT_FM)
		pcieb_fm_fini(pcieb);

	pcieb_pwr_teardown(devi);
	pwr_common_teardown(devi);

	mutex_destroy(&pcieb->pcieb_peek_poke_mutex);
	mutex_destroy(&pcieb->pcieb_err_mutex);
	mutex_destroy(&pcieb->pcieb_mutex);

	/*
	 * And finally free the per-pci soft state.
	 */
	ddi_soft_state_free(pcieb_state, ddi_get_instance(devi));

	return (DDI_SUCCESS);
}

static int
pcieb_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	dev_info_t *pdip;

	if (PCIE_IS_RP(PCIE_DIP2BUS(dip)) && mp->map_handlep != NULL) {
		ddi_acc_impl_t *hdlp =
		    (ddi_acc_impl_t *)(mp->map_handlep)->ah_platform_private;

		pcieb_set_prot_scan(dip, hdlp);
	}
	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)(pdip, rdip, mp,
	    offset, len, vaddrp));
}

static int
pcieb_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	int	reglen;
	int	rn;
	int	totreg;
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));
	struct detachspec *ds;
	struct attachspec *as;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);

		if (ddi_get_parent(rdip) == dip) {
			cmn_err(CE_CONT, "?PCIE-device: %s@%s, %s%d\n",
			    ddi_node_name(rdip), ddi_get_name_addr(rdip),
			    ddi_driver_name(rdip), ddi_get_instance(rdip));
		}

		/* Pass it up for fabric sync */
		(void) ddi_ctlops(dip, rdip, ctlop, arg, result);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (pcieb_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		pcieb_uninitchild((dev_info_t *)arg);
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
		return (pcieb_plat_peekpoke(dip, rdip, ctlop, arg, result));
	case DDI_CTLOPS_ATTACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		as = (struct attachspec *)arg;
		switch (as->when) {
		case DDI_PRE:
			if (as->cmd == DDI_RESUME) {
				pcie_clear_errors(rdip);
				if (pcieb_plat_ctlops(rdip, ctlop, arg) !=
				    DDI_SUCCESS)
					return (DDI_FAILURE);
			}

			if (as->cmd == DDI_ATTACH)
				return (pcie_pm_hold(dip));

			return (DDI_SUCCESS);

		case DDI_POST:
			if (as->cmd == DDI_ATTACH &&
			    as->result != DDI_SUCCESS) {
				/*
				 * Attach failed for the child device. The child
				 * driver may have made PM calls before the
				 * attach failed. pcie_pm_remove_child() should
				 * cleanup PM state and holds (if any)
				 * associated with the child device.
				 */
				return (pcie_pm_remove_child(dip, rdip));
			}

			if (as->result == DDI_SUCCESS) {
				pf_init(rdip, (void *)pcieb->pcieb_fm_ibc,
				    as->cmd);

				(void) pcieb_plat_ctlops(rdip, ctlop, arg);
			}

			/*
			 * For empty hotplug-capable slots, we should explicitly
			 * disable the errors, so that we won't panic upon
			 * unsupported hotplug messages.
			 */
			if ((!ddi_prop_exists(DDI_DEV_T_ANY, rdip,
			    DDI_PROP_DONTPASS, "hotplug-capable")) ||
			    ddi_get_child(rdip)) {
				(void) pcie_postattach_child(rdip);
				return (DDI_SUCCESS);
			}

			pcie_disable_errors(rdip);

			return (DDI_SUCCESS);
		default:
			break;
		}
		return (DDI_SUCCESS);

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		ds = (struct detachspec *)arg;
		switch (ds->when) {
		case DDI_PRE:
			pf_fini(rdip, ds->cmd);
			return (DDI_SUCCESS);

		case DDI_POST:
			if (pcieb_plat_ctlops(rdip, ctlop, arg) != DDI_SUCCESS)
				return (DDI_FAILURE);
			if (ds->cmd == DDI_DETACH &&
			    ds->result == DDI_SUCCESS) {
				return (pcie_pm_remove_child(dip, rdip));
			}
			return (DDI_SUCCESS);
		default:
			break;
		}
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

		*(off_t *)result = drv_regp[rn].pci_size_low |
		    ((uint64_t)drv_regp[rn].pci_size_hi << 32);
	}

	kmem_free(drv_regp, reglen);
	return (DDI_SUCCESS);
}

/*
 * name_child
 *
 * This function is called from init_child to name a node. It is
 * also passed as a callback for node merging functions.
 *
 * return value: DDI_SUCCESS, DDI_FAILURE
 */
static int
pcieb_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	uint_t device, func;
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
			return (DDI_FAILURE);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	/*
	 * Get the address portion of the node name based on
	 * the function and device number.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp, &n) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* copy the device identifications */
	device = PCI_REG_DEV_G(pci_rp[0].pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp[0].pci_phys_hi);

	if (pcie_ari_is_enabled(ddi_get_parent(child))
	    == PCIE_ARI_FORW_ENABLED) {
		func = (device << 3) | func;
		device = 0;
	}

	if (func != 0)
		(void) snprintf(name, namelen, "%x,%x", device, func);
	else
		(void) snprintf(name, namelen, "%x", device);

	ddi_prop_free(pci_rp);
	return (DDI_SUCCESS);
}

static int
pcieb_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];
	int result = DDI_FAILURE;
	pcieb_devstate_t *pcieb =
	    (pcieb_devstate_t *)ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(ddi_get_parent(child)));

	/*
	 * Name the child
	 */
	if (pcieb_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS) {
		result = DDI_FAILURE;
		goto done;
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

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, pcieb_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			result = DDI_FAILURE;
			goto done;
		}

		/* workaround for ddivs to run under PCI-E */
		if (pci_allow_pseudo_children) {
			result = DDI_SUCCESS;
			goto done;
		}

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_driver_name(child), ddi_get_name_addr(child),
		    ddi_driver_name(child));
		ddi_set_name_addr(child, NULL);
		result = DDI_NOT_WELL_FORMED;
		goto done;
	}

	/* platform specific initchild */
	pcieb_plat_initchild(child);

	if (pcie_pm_hold(pcieb->pcieb_dip) != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_PWR, pcieb->pcieb_dip,
		    "INITCHILD: px_pm_hold failed\n");
		result = DDI_FAILURE;
		goto done;
	}
	/* Any return from here must call pcie_pm_release */

	/*
	 * If configuration registers were previously saved by
	 * child (before it entered D3), then let the child do the
	 * restore to set up the config regs as it'll first need to
	 * power the device out of D3.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "config-regs-saved-by-child") == 1) {
		PCIEB_DEBUG(DBG_PWR, ddi_get_parent(child),
		    "INITCHILD: config regs to be restored by child"
		    " for %s@%s\n", ddi_node_name(child),
		    ddi_get_name_addr(child));

		result = DDI_SUCCESS;
		goto cleanup;
	}

	PCIEB_DEBUG(DBG_PWR, ddi_get_parent(child),
	    "INITCHILD: config regs setup for %s@%s\n",
	    ddi_node_name(child), ddi_get_name_addr(child));

	pcie_init_dom(child);

	if (pcie_initchild(child) != DDI_SUCCESS) {
		result = DDI_FAILURE;
		pcie_fini_dom(child);
		goto cleanup;
	}

#ifdef PX_PLX
	if (pcieb_init_plx_workarounds(pcieb, child) == DDI_FAILURE) {
		result = DDI_FAILURE;
		pcie_fini_dom(child);
		goto cleanup;
	}
#endif /* PX_PLX */

	result = DDI_SUCCESS;
cleanup:
	pcie_pm_release(pcieb->pcieb_dip);
done:
	return (result);
}

static void
pcieb_uninitchild(dev_info_t *dip)
{

	pcie_uninitchild(dip);

	pcieb_plat_uninitchild(dip);

	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	ddi_prop_remove_all(dip);
}

static boolean_t
pcieb_is_pcie_device_type(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_SW(bus_p) || PCIE_IS_RP(bus_p) || PCIE_IS_PCI2PCIE(bus_p))
		return (B_TRUE);

	return (B_FALSE);
}

static int
pcieb_intr_attach(pcieb_devstate_t *pcieb)
{
	int			intr_types;
	dev_info_t		*dip = pcieb->pcieb_dip;

	/* Allow platform specific code to do any initialization first */
	pcieb_plat_intr_attach(pcieb);

	/*
	 * Initialize interrupt handlers.
	 * If both MSI and FIXED are supported, try to attach MSI first.
	 * If MSI fails for any reason, then try FIXED, but only allow one
	 * type to be attached.
	 */
	if (ddi_intr_get_supported_types(dip, &intr_types) != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_ATTACH, dip, "ddi_intr_get_supported_types"
		    " failed\n");
		goto FAIL;
	}

	if ((intr_types & DDI_INTR_TYPE_MSI) &&
	    (pcieb_msi_supported(dip) == DDI_SUCCESS)) {
		if (pcieb_intr_init(pcieb, DDI_INTR_TYPE_MSI) == DDI_SUCCESS)
			intr_types = DDI_INTR_TYPE_MSI;
		else {
			PCIEB_DEBUG(DBG_ATTACH, dip, "Unable to attach MSI"
			    " handler\n");
		}
	}

	if (intr_types != DDI_INTR_TYPE_MSI) {
		/*
		 * MSIs are not supported or MSI initialization failed. For Root
		 * Ports mark this so error handling might try to fallback to
		 * some other mechanism if available (machinecheck etc.).
		 */
		if (PCIE_IS_RP(PCIE_DIP2UPBUS(dip)))
			pcieb->pcieb_no_aer_msi = B_TRUE;
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (pcieb_intr_init(pcieb, DDI_INTR_TYPE_FIXED) !=
		    DDI_SUCCESS) {
			PCIEB_DEBUG(DBG_ATTACH, dip,
			    "Unable to attach INTx handler\n");
			goto FAIL;
		}
	}
	return (DDI_SUCCESS);

FAIL:
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
pcieb_intr_init(pcieb_devstate_t *pcieb, int intr_type)
{
	dev_info_t	*dip = pcieb->pcieb_dip;
	int		nintrs, request, count, x;
	int		intr_cap = 0;
	int		inum = 0;
	int		ret, hp_msi_off;
	pcie_bus_t	*bus_p = PCIE_DIP2UPBUS(dip);
	uint16_t	vendorid = bus_p->bus_dev_ven_id & 0xFFFF;
	boolean_t	is_hp = B_FALSE;
	boolean_t	is_pme = B_FALSE;

	PCIEB_DEBUG(DBG_ATTACH, dip, "pcieb_intr_init: Attaching %s handler\n",
	    (intr_type == DDI_INTR_TYPE_MSI) ? "MSI" : "INTx");

	request = 0;
	if (PCIE_IS_HOTPLUG_ENABLED(dip)) {
		request++;
		is_hp = B_TRUE;
	}

	/*
	 * Hotplug and PME share the same MSI vector. If hotplug is not
	 * supported check if MSI is needed for PME.
	 */
	if ((intr_type == DDI_INTR_TYPE_MSI) && PCIE_IS_RP(bus_p) &&
	    (vendorid == NVIDIA_VENDOR_ID)) {
		is_pme = B_TRUE;
		if (!is_hp)
			request++;
	}

	/*
	 * Setup MSI if this device is a Rootport and has AER. Currently no
	 * SPARC Root Port supports fabric errors being reported through it.
	 */
	if (intr_type == DDI_INTR_TYPE_MSI) {
		if (PCIE_IS_RP(bus_p) && PCIE_HAS_AER(bus_p))
			request++;
	}

	if (request == 0)
		return (DDI_SUCCESS);

	/*
	 * Get number of supported interrupts.
	 *
	 * Several Bridges/Switches will not have this property set, resulting
	 * in a FAILURE, if the device is not configured in a way that
	 * interrupts are needed. (eg. hotplugging)
	 */
	ret = ddi_intr_get_nintrs(dip, intr_type, &nintrs);
	if ((ret != DDI_SUCCESS) || (nintrs == 0)) {
		PCIEB_DEBUG(DBG_ATTACH, dip, "ddi_intr_get_nintrs ret:%d"
		    " req:%d\n", ret, nintrs);
		return (DDI_FAILURE);
	}

	PCIEB_DEBUG(DBG_ATTACH, dip, "bdf 0x%x: ddi_intr_get_nintrs: nintrs %d",
	    " request %d\n", bus_p->bus_bdf, nintrs, request);

	if (request > nintrs)
		request = nintrs;

	/* Allocate an array of interrupt handlers */
	pcieb->pcieb_htable_size = sizeof (ddi_intr_handle_t) * request;
	pcieb->pcieb_htable = kmem_zalloc(pcieb->pcieb_htable_size,
	    KM_SLEEP);
	pcieb->pcieb_init_flags |= PCIEB_INIT_HTABLE;

	ret = ddi_intr_alloc(dip, pcieb->pcieb_htable, intr_type, inum,
	    request, &count, DDI_INTR_ALLOC_NORMAL);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		PCIEB_DEBUG(DBG_ATTACH, dip, "ddi_intr_alloc() ret: %d ask: %d"
		    " actual: %d\n", ret, request, count);
		goto FAIL;
	}
	pcieb->pcieb_init_flags |= PCIEB_INIT_ALLOC;

	/* Save the actual number of interrupts allocated */
	pcieb->pcieb_intr_count = count;
	if (count < request) {
		PCIEB_DEBUG(DBG_ATTACH, dip, "bdf 0%x: Requested Intr: %d"
		    " Received: %d\n", bus_p->bus_bdf, request, count);
	}

	/*
	 * NVidia (MCP55 and other) chipsets have a errata that if the number
	 * of requested MSI intrs is not allocated we have to fall back to INTx.
	 */
	if (intr_type == DDI_INTR_TYPE_MSI) {
		if (PCIE_IS_RP(bus_p) && (vendorid == NVIDIA_VENDOR_ID)) {
			if (request != count)
				goto FAIL;
		}
	}

	/* Get interrupt priority */
	ret = ddi_intr_get_pri(pcieb->pcieb_htable[0],
	    &pcieb->pcieb_intr_priority);
	if (ret != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_ATTACH, dip, "ddi_intr_get_pri() ret: %d\n",
		    ret);
		goto FAIL;
	}

	if (pcieb->pcieb_intr_priority >= LOCK_LEVEL) {
		pcieb->pcieb_intr_priority = LOCK_LEVEL - 1;
		ret = ddi_intr_set_pri(pcieb->pcieb_htable[0],
		    pcieb->pcieb_intr_priority);
		if (ret != DDI_SUCCESS) {
			PCIEB_DEBUG(DBG_ATTACH, dip, "ddi_intr_set_pri() ret:"
			" %d\n", ret);

			goto FAIL;
		}
	}

	mutex_init(&pcieb->pcieb_intr_mutex, NULL, MUTEX_DRIVER, NULL);

	pcieb->pcieb_init_flags |= PCIEB_INIT_MUTEX;

	for (count = 0; count < pcieb->pcieb_intr_count; count++) {
		ret = ddi_intr_add_handler(pcieb->pcieb_htable[count],
		    pcieb_intr_handler, (caddr_t)pcieb,
		    (caddr_t)(uintptr_t)(inum + count));

		if (ret != DDI_SUCCESS) {
			PCIEB_DEBUG(DBG_ATTACH, dip, "Cannot add "
			    "interrupt(%d)\n", ret);
			break;
		}
	}

	/* If unsucessful, remove the added handlers */
	if (ret != DDI_SUCCESS) {
		for (x = 0; x < count; x++) {
			(void) ddi_intr_remove_handler(pcieb->pcieb_htable[x]);
		}
		goto FAIL;
	}

	pcieb->pcieb_init_flags |= PCIEB_INIT_HANDLER;

	(void) ddi_intr_get_cap(pcieb->pcieb_htable[0], &intr_cap);

	/*
	 * Get this intr lock because we are not quite ready to handle
	 * interrupts immediately after enabling it. The MSI multi register
	 * gets programmed in ddi_intr_enable after which we need to get the
	 * MSI offsets for Hotplug/AER.
	 */
	mutex_enter(&pcieb->pcieb_intr_mutex);

	if (intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(pcieb->pcieb_htable,
		    pcieb->pcieb_intr_count);
		pcieb->pcieb_init_flags |= PCIEB_INIT_BLOCK;
	} else {
		for (count = 0; count < pcieb->pcieb_intr_count; count++) {
			(void) ddi_intr_enable(pcieb->pcieb_htable[count]);
		}
	}
	pcieb->pcieb_init_flags |= PCIEB_INIT_ENABLE;

	/* Save the interrupt type */
	pcieb->pcieb_intr_type = intr_type;

	/* Get the MSI offset for hotplug/PME from the PCIe cap reg */
	if (intr_type == DDI_INTR_TYPE_MSI) {
		hp_msi_off = PCI_CAP_GET16(bus_p->bus_cfg_hdl, 0,
		    bus_p->bus_pcie_off, PCIE_PCIECAP) &
		    PCIE_PCIECAP_INT_MSG_NUM;

		if (hp_msi_off >= count) {
			PCIEB_DEBUG(DBG_ATTACH, dip, "MSI number %d in PCIe "
			    "cap > max allocated %d\n", hp_msi_off, count);
			mutex_exit(&pcieb->pcieb_intr_mutex);
			goto FAIL;
		}

		if (is_hp)
			pcieb->pcieb_isr_tab[hp_msi_off] |= PCIEB_INTR_SRC_HP;

		if (is_pme)
			pcieb->pcieb_isr_tab[hp_msi_off] |= PCIEB_INTR_SRC_PME;
	} else {
		/* INTx handles only Hotplug interrupts */
		if (is_hp)
			pcieb->pcieb_isr_tab[0] |= PCIEB_INTR_SRC_HP;
	}


	/*
	 * Get the MSI offset for errors from the AER Root Error status
	 * register.
	 */
	if ((intr_type == DDI_INTR_TYPE_MSI) && PCIE_IS_RP(bus_p)) {
		if (PCIE_HAS_AER(bus_p)) {
			int aer_msi_off;
			aer_msi_off = (PCI_XCAP_GET32(bus_p->bus_cfg_hdl, 0,
			    bus_p->bus_aer_off, PCIE_AER_RE_STS) >>
			    PCIE_AER_RE_STS_MSG_NUM_SHIFT) &
			    PCIE_AER_RE_STS_MSG_NUM_MASK;

			if (aer_msi_off >= count) {
				PCIEB_DEBUG(DBG_ATTACH, dip, "MSI number %d in"
				    " AER cap > max allocated %d\n",
				    aer_msi_off, count);
				mutex_exit(&pcieb->pcieb_intr_mutex);
				goto FAIL;
			}
			pcieb->pcieb_isr_tab[aer_msi_off] |= PCIEB_INTR_SRC_AER;
		} else {
			/*
			 * This RP does not have AER. Fallback to the
			 * SERR+Machinecheck approach if available.
			 */
			pcieb->pcieb_no_aer_msi = B_TRUE;
		}
	}

	mutex_exit(&pcieb->pcieb_intr_mutex);
	return (DDI_SUCCESS);

FAIL:
	pcieb_intr_fini(pcieb);
	return (DDI_FAILURE);
}

static void
pcieb_intr_fini(pcieb_devstate_t *pcieb)
{
	int x;
	int count = pcieb->pcieb_intr_count;
	int flags = pcieb->pcieb_init_flags;

	if ((flags & PCIEB_INIT_ENABLE) &&
	    (flags & PCIEB_INIT_BLOCK)) {
		(void) ddi_intr_block_disable(pcieb->pcieb_htable, count);
		flags &= ~(PCIEB_INIT_ENABLE |
		    PCIEB_INIT_BLOCK);
	}

	if (flags & PCIEB_INIT_MUTEX)
		mutex_destroy(&pcieb->pcieb_intr_mutex);

	for (x = 0; x < count; x++) {
		if (flags & PCIEB_INIT_ENABLE)
			(void) ddi_intr_disable(pcieb->pcieb_htable[x]);

		if (flags & PCIEB_INIT_HANDLER)
			(void) ddi_intr_remove_handler(pcieb->pcieb_htable[x]);

		if (flags & PCIEB_INIT_ALLOC)
			(void) ddi_intr_free(pcieb->pcieb_htable[x]);
	}

	flags &= ~(PCIEB_INIT_ENABLE | PCIEB_INIT_HANDLER | PCIEB_INIT_ALLOC |
	    PCIEB_INIT_MUTEX);

	if (flags & PCIEB_INIT_HTABLE)
		kmem_free(pcieb->pcieb_htable, pcieb->pcieb_htable_size);

	flags &= ~PCIEB_INIT_HTABLE;

	pcieb->pcieb_init_flags &= flags;
}

/*
 * Checks if this device needs MSIs enabled or not.
 */
/*ARGSUSED*/
static int
pcieb_msi_supported(dev_info_t *dip)
{
	return ((pcieb_enable_msi && pcieb_plat_msi_supported(dip)) ?
	    DDI_SUCCESS: DDI_FAILURE);
}

/*ARGSUSED*/
static int
pcieb_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pcieb_devstate_t  *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));

	ASSERT(ibc != NULL);
	*ibc = pcieb->pcieb_fm_ibc;

	return (DEVI(dip)->devi_fmhdl->fh_cap | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE);
}

static int
pcieb_fm_init(pcieb_devstate_t *pcieb_p)
{
	dev_info_t	*dip = pcieb_p->pcieb_dip;
	int		fm_cap = DDI_FM_EREPORT_CAPABLE;

	/*
	 * Request our capability level and get our parents capability
	 * and ibc.
	 */
	ddi_fm_init(dip, &fm_cap, &pcieb_p->pcieb_fm_ibc);

	return (DDI_SUCCESS);
}

/*
 * Breakdown our FMA resources
 */
static void
pcieb_fm_fini(pcieb_devstate_t *pcieb_p)
{
	/*
	 * Clean up allocated fm structures
	 */
	ddi_fm_fini(pcieb_p->pcieb_dip);
}

static int
pcieb_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int		inst = PCI_MINOR_NUM_TO_INSTANCE(getminor(*devp));
	pcieb_devstate_t	*pcieb = ddi_get_soft_state(pcieb_state, inst);
	int	rv;

	if (pcieb == NULL)
		return (ENXIO);

	mutex_enter(&pcieb->pcieb_mutex);
	rv = pcie_open(pcieb->pcieb_dip, devp, flags, otyp, credp);
	mutex_exit(&pcieb->pcieb_mutex);

	return (rv);
}

static int
pcieb_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int		inst = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	pcieb_devstate_t	*pcieb = ddi_get_soft_state(pcieb_state, inst);
	int	rv;

	if (pcieb == NULL)
		return (ENXIO);

	mutex_enter(&pcieb->pcieb_mutex);
	rv = pcie_close(pcieb->pcieb_dip, dev, flags, otyp, credp);
	mutex_exit(&pcieb->pcieb_mutex);

	return (rv);
}

static int
pcieb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int		inst = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	pcieb_devstate_t	*pcieb = ddi_get_soft_state(pcieb_state, inst);
	int		rv;

	if (pcieb == NULL)
		return (ENXIO);

	/* To handle devctl and hotplug related ioctls */
	rv = pcie_ioctl(pcieb->pcieb_dip, dev, cmd, arg, mode, credp, rvalp);

	return (rv);
}

/*
 * Common interrupt handler for hotplug, PME and errors.
 */
static uint_t
pcieb_intr_handler(caddr_t arg1, caddr_t arg2)
{
	pcieb_devstate_t *pcieb_p = (pcieb_devstate_t *)arg1;
	dev_info_t	*dip = pcieb_p->pcieb_dip;
	ddi_fm_error_t	derr;
	int		sts = 0;
	int		ret = DDI_INTR_UNCLAIMED;
	int		isrc;

	if (!(pcieb_p->pcieb_init_flags & PCIEB_INIT_ENABLE))
		goto FAIL;

	mutex_enter(&pcieb_p->pcieb_intr_mutex);
	isrc = pcieb_p->pcieb_isr_tab[(int)(uintptr_t)arg2];
	mutex_exit(&pcieb_p->pcieb_intr_mutex);

	PCIEB_DEBUG(DBG_INTR, dip, "Received intr number %d\n",
	    (int)(uintptr_t)arg2);

	if (isrc == PCIEB_INTR_SRC_UNKNOWN)
		goto FAIL;

	if (isrc & PCIEB_INTR_SRC_HP)
		ret = pcie_intr(dip);

	if (isrc & PCIEB_INTR_SRC_PME)
		ret = DDI_INTR_CLAIMED;

	/* AER Error */
	if (isrc & PCIEB_INTR_SRC_AER) {
		/*
		 *  If MSI is shared with PME/hotplug then check Root Error
		 *  Status Reg before claiming it. For now it's ok since
		 *  we know we get 2 MSIs.
		 */
		ret = DDI_INTR_CLAIMED;
		bzero(&derr, sizeof (ddi_fm_error_t));
		derr.fme_version = DDI_FME_VERSION;
		mutex_enter(&pcieb_p->pcieb_peek_poke_mutex);
		mutex_enter(&pcieb_p->pcieb_err_mutex);

		pf_eh_enter(PCIE_DIP2BUS(dip));
		PCIE_ROOT_EH_SRC(PCIE_DIP2PFD(dip))->intr_type =
		    PF_INTR_TYPE_AER;

		if ((DEVI(dip)->devi_fmhdl->fh_cap) & DDI_FM_EREPORT_CAPABLE)
			sts = pf_scan_fabric(dip, &derr, NULL);
		pf_eh_exit(PCIE_DIP2BUS(dip));

		mutex_exit(&pcieb_p->pcieb_err_mutex);
		mutex_exit(&pcieb_p->pcieb_peek_poke_mutex);
		if (pcieb_die & sts)
			fm_panic("%s-%d: PCI(-X) Express Fatal Error. (0x%x)",
			    ddi_driver_name(dip), ddi_get_instance(dip), sts);
	}
FAIL:
	return (ret);
}

/*
 * Some PCI-X to PCI-E bridges do not support full 64-bit addressing on the
 * PCI-X side of the bridge.  We build a special version of this driver for
 * those bridges, which uses PCIEB_ADDR_LIMIT_LO and/or PCIEB_ADDR_LIMIT_HI
 * to define the range of values which the chip can handle.  The code below
 * then clamps the DMA address range supplied by the driver, preventing the
 * PCI-E nexus driver from allocating any memory the bridge can't deal
 * with.
 */
static int
pcieb_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_attr_t *attr_p, int (*waitfp)(caddr_t), caddr_t arg,
    ddi_dma_handle_t *handlep)
{
	int		ret;
#ifdef	PCIEB_BCM
	uint64_t	lim;

	/*
	 * If the leaf device's limits are outside than what the Broadcom
	 * bridge can handle, we need to clip the values passed up the chain.
	 */
	lim = attr_p->dma_attr_addr_lo;
	attr_p->dma_attr_addr_lo = MAX(lim, PCIEB_ADDR_LIMIT_LO);

	lim = attr_p->dma_attr_addr_hi;
	attr_p->dma_attr_addr_hi = MIN(lim, PCIEB_ADDR_LIMIT_HI);

#endif	/* PCIEB_BCM */

	/*
	 * This is a software workaround to fix the Broadcom 5714/5715 PCIe-PCI
	 * bridge prefetch bug. Intercept the DMA alloc handle request and set
	 * PX_DMAI_FLAGS_MAP_BUFZONE flag in the handle. If this flag is set,
	 * the px nexus driver will allocate an extra page & make it valid one,
	 * for any DVMA request that comes from any of the Broadcom bridge child
	 * devices.
	 */
	if ((ret = ddi_dma_allochdl(dip, rdip, attr_p, waitfp, arg,
	    handlep)) == DDI_SUCCESS) {
		ddi_dma_impl_t	*mp = (ddi_dma_impl_t *)*handlep;
#ifdef	PCIEB_BCM
		mp->dmai_inuse |= PX_DMAI_FLAGS_MAP_BUFZONE;
#endif	/* PCIEB_BCM */
		/*
		 * For a given rdip, update mp->dmai_bdf with the bdf value
		 * of pcieb's immediate child or secondary bus-id of the
		 * PCIe2PCI bridge.
		 */
		mp->dmai_minxfer = pcie_get_bdf_for_dma_xfer(dip, rdip);
	}

	return (ret);
}

/*
 * FDVMA feature is not supported for any child device of Broadcom 5714/5715
 * PCIe-PCI bridge due to prefetch bug. Return failure immediately, so that
 * these drivers will switch to regular DVMA path.
 */
/*ARGSUSED*/
static int
pcieb_dma_mctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
    enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
    uint_t cache_flags)
{
	int	ret;

#ifdef	PCIEB_BCM
	if (cmd == DDI_DMA_RESERVE)
		return (DDI_FAILURE);
#endif	/* PCIEB_BCM */

	if (((ret = ddi_dma_mctl(dip, rdip, handle, cmd, offp, lenp, objp,
	    cache_flags)) == DDI_SUCCESS) && (cmd == DDI_DMA_RESERVE)) {
		ddi_dma_impl_t	*mp = (ddi_dma_impl_t *)*objp;

		/*
		 * For a given rdip, update mp->dmai_bdf with the bdf value
		 * of pcieb's immediate child or secondary bus-id of the
		 * PCIe2PCI bridge.
		 */
		mp->dmai_minxfer = pcie_get_bdf_for_dma_xfer(dip, rdip);
	}

	return (ret);
}

static int
pcieb_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (pcieb_plat_intr_ops(dip, rdip, intr_op, hdlp, result));

}

/*
 * Power management related initialization specific to pcieb.
 * Called by pcieb_attach()
 */
static int
pcieb_pwr_setup(dev_info_t *dip)
{
	char *comp_array[5];
	int i;
	ddi_acc_handle_t conf_hdl;
	uint16_t pmcap, cap_ptr;
	pcie_pwr_t *pwr_p;

	/* Some platforms/devices may choose to disable PM */
	if (pcieb_plat_pwr_disable(dip)) {
		(void) pcieb_pwr_disable(dip);
		return (DDI_SUCCESS);
	}

	ASSERT(PCIE_PMINFO(dip));
	pwr_p = PCIE_NEXUS_PMINFO(dip);
	ASSERT(pwr_p);

	/* Code taken from pci_pci driver */
	if (pci_config_setup(dip, &pwr_p->pwr_conf_hdl) != DDI_SUCCESS) {
		PCIEB_DEBUG(DBG_PWR, dip, "pcieb_pwr_setup: pci_config_setup "
		    "failed\n");
		return (DDI_FAILURE);
	}
	conf_hdl = pwr_p->pwr_conf_hdl;

	/*
	 * Walk the capabilities searching for a PM entry.
	 */
	if ((PCI_CAP_LOCATE(conf_hdl, PCI_CAP_ID_PM, &cap_ptr)) ==
	    DDI_FAILURE) {
		PCIEB_DEBUG(DBG_PWR, dip, "switch/bridge does not support PM. "
		    " PCI PM data structure not found in config header\n");
		pci_config_teardown(&conf_hdl);
		return (DDI_SUCCESS);
	}
	/*
	 * Save offset to pmcsr for future references.
	 */
	pwr_p->pwr_pmcsr_offset = cap_ptr + PCI_PMCSR;
	pmcap = PCI_CAP_GET16(conf_hdl, 0, cap_ptr, PCI_PMCAP);
	if (pmcap & PCI_PMCAP_D1) {
		PCIEB_DEBUG(DBG_PWR, dip, "D1 state supported\n");
		pwr_p->pwr_pmcaps |= PCIE_SUPPORTS_D1;
	}
	if (pmcap & PCI_PMCAP_D2) {
		PCIEB_DEBUG(DBG_PWR, dip, "D2 state supported\n");
		pwr_p->pwr_pmcaps |= PCIE_SUPPORTS_D2;
	}

	i = 0;
	comp_array[i++] = "NAME=PCIe switch/bridge PM";
	comp_array[i++] = "0=Power Off (D3)";
	if (pwr_p->pwr_pmcaps & PCIE_SUPPORTS_D2)
		comp_array[i++] = "1=D2";
	if (pwr_p->pwr_pmcaps & PCIE_SUPPORTS_D1)
		comp_array[i++] = "2=D1";
	comp_array[i++] = "3=Full Power D0";

	/*
	 * Create pm-components property, if it does not exist already.
	 */
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", comp_array, i) != DDI_PROP_SUCCESS) {
		PCIEB_DEBUG(DBG_PWR, dip, "could not create pm-components "
		    " prop\n");
		pci_config_teardown(&conf_hdl);
		return (DDI_FAILURE);
	}
	return (pcieb_pwr_init_and_raise(dip, pwr_p));
}

/*
 * undo whatever is done in pcieb_pwr_setup. called by pcieb_detach()
 */
static void
pcieb_pwr_teardown(dev_info_t *dip)
{
	pcie_pwr_t	*pwr_p;

	if (!PCIE_PMINFO(dip) || !(pwr_p = PCIE_NEXUS_PMINFO(dip)))
		return;

	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "pm-components");
	if (pwr_p->pwr_conf_hdl)
		pci_config_teardown(&pwr_p->pwr_conf_hdl);
}

/*
 * Initializes the power level and raise the power to D0, if it is
 * not at D0.
 */
static int
pcieb_pwr_init_and_raise(dev_info_t *dip, pcie_pwr_t *pwr_p)
{
	uint16_t pmcsr;
	int ret = DDI_SUCCESS;

	/*
	 * Intialize our power level from PMCSR. The common code initializes
	 * this to UNKNOWN. There is no guarantee that we will be at full
	 * power at attach. If we are not at D0, raise the power.
	 */
	pmcsr = pci_config_get16(pwr_p->pwr_conf_hdl, pwr_p->pwr_pmcsr_offset);
	pmcsr &= PCI_PMCSR_STATE_MASK;
	switch (pmcsr) {
	case PCI_PMCSR_D0:
		pwr_p->pwr_func_lvl = PM_LEVEL_D0;
		break;

	case PCI_PMCSR_D1:
		pwr_p->pwr_func_lvl = PM_LEVEL_D1;
		break;

	case PCI_PMCSR_D2:
		pwr_p->pwr_func_lvl = PM_LEVEL_D2;
		break;

	case PCI_PMCSR_D3HOT:
		pwr_p->pwr_func_lvl = PM_LEVEL_D3;
		break;

	default:
		break;
	}

	/* Raise the power to D0. */
	if (pwr_p->pwr_func_lvl != PM_LEVEL_D0 &&
	    ((ret = pm_raise_power(dip, 0, PM_LEVEL_D0)) != DDI_SUCCESS)) {
		/*
		 * Read PMCSR again. If it is at D0, ignore the return
		 * value from pm_raise_power.
		 */
		pmcsr = pci_config_get16(pwr_p->pwr_conf_hdl,
		    pwr_p->pwr_pmcsr_offset);
		if ((pmcsr & PCI_PMCSR_STATE_MASK) == PCI_PMCSR_D0)
			ret = DDI_SUCCESS;
		else {
			PCIEB_DEBUG(DBG_PWR, dip, "pcieb_pwr_setup: could not "
			    "raise power to D0 \n");
		}
	}
	if (ret == DDI_SUCCESS)
		pwr_p->pwr_func_lvl = PM_LEVEL_D0;
	return (ret);
}

/*
 * Disable PM for x86 and PLX 8532 switch.
 * For PLX Transitioning one port on this switch to low power causes links
 * on other ports on the same station to die. Due to PLX erratum #34, we
 * can't allow the downstream device go to non-D0 state.
 */
static int
pcieb_pwr_disable(dev_info_t *dip)
{
	pcie_pwr_t *pwr_p;

	ASSERT(PCIE_PMINFO(dip));
	pwr_p = PCIE_NEXUS_PMINFO(dip);
	ASSERT(pwr_p);
	PCIEB_DEBUG(DBG_PWR, dip, "pcieb_pwr_disable: disabling PM\n");
	pwr_p->pwr_func_lvl = PM_LEVEL_D0;
	pwr_p->pwr_flags = PCIE_NO_CHILD_PM;
	return (DDI_SUCCESS);
}

#ifdef DEBUG
int pcieb_dbg_intr_print = 0;
void
pcieb_dbg(uint_t bit, dev_info_t *dip, char *fmt, ...)
{
	va_list ap;

	if (!pcieb_dbg_print)
		return;

	if (dip)
		prom_printf("%s(%d): %s", ddi_driver_name(dip),
		    ddi_get_instance(dip), pcieb_debug_sym[bit]);

	va_start(ap, fmt);
	if (servicing_interrupt()) {
		if (pcieb_dbg_intr_print)
			prom_vprintf(fmt, ap);
	} else {
		prom_vprintf(fmt, ap);
	}

	va_end(ap);
}
#endif

static void
pcieb_id_props(pcieb_devstate_t *pcieb)
{
	uint64_t serialid = 0;	/* 40b field of EUI-64 serial no. register */
	uint16_t cap_ptr;
	uint8_t fic = 0;	/* 1 = first in chassis device */
	pcie_bus_t *bus_p = PCIE_DIP2BUS(pcieb->pcieb_dip);
	ddi_acc_handle_t config_handle = bus_p->bus_cfg_hdl;

	/*
	 * Identify first in chassis.  In the special case of a Sun branded
	 * PLX device, it obviously is first in chassis.  Otherwise, in the
	 * general case, look for an Expansion Slot Register and check its
	 * first-in-chassis bit.
	 */
#ifdef	PX_PLX
	uint16_t vendor_id = bus_p->bus_dev_ven_id & 0xFFFF;
	uint16_t device_id = bus_p->bus_dev_ven_id >> 16;
	if ((vendor_id == PXB_VENDOR_SUN) &&
	    ((device_id == PXB_DEVICE_PLX_PCIX) ||
	    (device_id == PXB_DEVICE_PLX_PCIE))) {
		fic = 1;
	}
#endif	/* PX_PLX */
	if ((fic == 0) && ((PCI_CAP_LOCATE(config_handle,
	    PCI_CAP_ID_SLOT_ID, &cap_ptr)) != DDI_FAILURE)) {
		uint8_t esr = PCI_CAP_GET8(config_handle, 0,
		    cap_ptr, PCI_CAP_ID_REGS_OFF);
		if (PCI_CAPSLOT_FIC(esr))
			fic = 1;
	}

	if ((PCI_CAP_LOCATE(config_handle,
	    PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_SER), &cap_ptr)) != DDI_FAILURE) {
		/* Serialid can be 0 thru a full 40b number */
		serialid = PCI_XCAP_GET32(config_handle, 0,
		    cap_ptr, PCIE_SER_SID_UPPER_DW);
		serialid <<= 32;
		serialid |= PCI_XCAP_GET32(config_handle, 0,
		    cap_ptr, PCIE_SER_SID_LOWER_DW);
	}

	if (fic)
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, pcieb->pcieb_dip,
		    "first-in-chassis");
	if (serialid)
		(void) ddi_prop_update_int64(DDI_DEV_T_NONE, pcieb->pcieb_dip,
		    "serialid#", serialid);
}

static void
pcieb_create_ranges_prop(dev_info_t *dip,
    ddi_acc_handle_t config_handle)
{
	uint32_t base, limit;
	ppb_ranges_t	ranges[PCIEB_RANGE_LEN];
	uint8_t io_base_lo, io_limit_lo;
	uint16_t io_base_hi, io_limit_hi, mem_base, mem_limit;
	int i = 0, rangelen = sizeof (ppb_ranges_t)/sizeof (int);

	io_base_lo = pci_config_get8(config_handle, PCI_BCNF_IO_BASE_LOW);
	io_limit_lo = pci_config_get8(config_handle, PCI_BCNF_IO_LIMIT_LOW);
	io_base_hi = pci_config_get16(config_handle, PCI_BCNF_IO_BASE_HI);
	io_limit_hi = pci_config_get16(config_handle, PCI_BCNF_IO_LIMIT_HI);
	mem_base = pci_config_get16(config_handle, PCI_BCNF_MEM_BASE);
	mem_limit = pci_config_get16(config_handle, PCI_BCNF_MEM_LIMIT);

	/*
	 * Create ranges for IO space
	 */
	ranges[i].size_low = ranges[i].size_high = 0;
	ranges[i].parent_mid = ranges[i].child_mid = ranges[i].parent_high = 0;
	ranges[i].child_high = ranges[i].parent_high |=
	    (PCI_REG_REL_M | PCI_ADDR_IO);
	base = PCIEB_16bit_IOADDR(io_base_lo);
	limit = PCIEB_16bit_IOADDR(io_limit_lo);

	if ((io_base_lo & 0xf) == PCIEB_32BIT_IO) {
		base = PCIEB_LADDR(base, io_base_hi);
	}
	if ((io_limit_lo & 0xf) == PCIEB_32BIT_IO) {
		limit = PCIEB_LADDR(limit, io_limit_hi);
	}

	if ((io_base_lo & PCIEB_32BIT_IO) && (io_limit_hi > 0)) {
		base = PCIEB_LADDR(base, io_base_hi);
		limit = PCIEB_LADDR(limit, io_limit_hi);
	}

	/*
	 * Create ranges for 32bit memory space
	 */
	base = PCIEB_32bit_MEMADDR(mem_base);
	limit = PCIEB_32bit_MEMADDR(mem_limit);
	ranges[i].size_low = ranges[i].size_high = 0;
	ranges[i].parent_mid = ranges[i].child_mid = ranges[i].parent_high = 0;
	ranges[i].child_high = ranges[i].parent_high |=
	    (PCI_REG_REL_M | PCI_ADDR_MEM32);
	ranges[i].child_low = ranges[i].parent_low = base;
	if (limit >= base) {
		ranges[i].size_low = limit - base + PCIEB_MEMGRAIN;
		i++;
	}

	if (i) {
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "ranges",
		    (int *)ranges, i * rangelen);
	}
}

/*
 * For PCI and PCI-X devices including PCIe2PCI bridge, initialize
 * cache-line-size and latency timer configuration registers.
 */
void
pcieb_set_pci_perf_parameters(dev_info_t *dip, ddi_acc_handle_t cfg_hdl)
{
	uint_t	n;

	/* Initialize cache-line-size configuration register if needed */
	if (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {
		pci_config_put8(cfg_hdl, PCI_CONF_CACHE_LINESZ,
		    PCIEB_CACHE_LINE_SIZE);
		n = pci_config_get8(cfg_hdl, PCI_CONF_CACHE_LINESZ);
		if (n != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "cache-line-size", n);
		}
	}

	/* Initialize latency timer configuration registers if needed */
	if (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "latency-timer", 0) == 0) {
		uchar_t	min_gnt, latency_timer;
		uchar_t header_type;

		/* Determine the configuration header type */
		header_type = pci_config_get8(cfg_hdl, PCI_CONF_HEADER);

		if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
			latency_timer = PCIEB_LATENCY_TIMER;
			pci_config_put8(cfg_hdl, PCI_BCNF_LATENCY_TIMER,
			    latency_timer);
		} else {
			min_gnt = pci_config_get8(cfg_hdl, PCI_CONF_MIN_G);
			latency_timer = min_gnt * 8;
		}

		pci_config_put8(cfg_hdl, PCI_CONF_LATENCY_TIMER,
		    latency_timer);
		n = pci_config_get8(cfg_hdl, PCI_CONF_LATENCY_TIMER);
		if (n != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "latency-timer", n);
		}
	}
}
