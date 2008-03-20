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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Sun4 PCI Express to PCI bus bridge nexus driver
 */

#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/condvar.h>
#include <sys/callb.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>
#include <sys/pci_impl.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/pci_cap.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/hotplug/pci/pciehpc.h>
#include <sys/hotplug/pci/pcishpc.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/promif.h>		/* prom_printf */
#include "pcie_pwr.h"
#include "px_pci.h"
#ifdef	PX_PLX
#include "pxb_plx.h"
#endif	/* PX_PLX */

#if defined(DEBUG)
#define	DBG pxb_dbg
static void pxb_dbg(uint_t bit, dev_info_t *dip, char *fmt, ...);
static uint_t pxb_dbg_print = 0;

#else /* DEBUG */

#define	DBG 0 &&

#endif /* DEBUG */

typedef enum {	/* same sequence as px_debug_sym[] */
	/*  0 */ DBG_ATTACH,
	/*  1 */ DBG_PWR
} pxb_debug_bit_t;

static char *pxb_debug_sym [] = {	/* same sequence as px_debug_bit */
	/*  0 */ "attach",
	/*  1 */ "pwr"
};

/* Tunables. Beware: Some are for debug purpose only. */
/*
 * PXB MSI tunable:
 *
 * By default MSI is enabled on all supported platforms.
 */
static boolean_t pxb_enable_msi = B_TRUE; /* MSI enabled if TRUE, else INTX */

static int pxb_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
	off_t, off_t, caddr_t *);
static int pxb_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_attr_t *attr_p, int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_handle_t *handlep);
static int pxb_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_handle_t handle, enum ddi_dma_ctlops cmd, off_t *offp,
	size_t *lenp, caddr_t *objp, uint_t cache_flags);
static int pxb_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
	void *, void *);
static int pxb_intr_ops(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);

/*
 * FMA functions
 */
static int pxb_fm_init(pxb_devstate_t *pxb_p);
static void pxb_fm_fini(pxb_devstate_t *pxb_p);
static int pxb_fm_init_child(dev_info_t *dip, dev_info_t *cdip, int cap,
    ddi_iblock_cookie_t *ibc_p);
static int pxb_fm_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data);

static int pxb_pcie_device_type(pxb_devstate_t *pxb_p);
static void pxb_set_pci_perf_parameters(dev_info_t *dip,
	ddi_acc_handle_t config_handle);
#ifdef	PRINT_PLX_SEEPROM_CRC
static void pxb_print_plx_seeprom_crc_data(pxb_devstate_t *pxb_p);
#endif

static struct bus_ops pxb_bus_ops = {
	BUSO_REV,
	pxb_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	ddi_dma_map,
	pxb_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	pxb_dma_mctl,
	pxb_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,	/* (*bus_get_eventcookie)();	*/
	ndi_busop_add_eventcall,	/* (*bus_add_eventcall)();	*/
	ndi_busop_remove_eventcall,	/* (*bus_remove_eventcall)();	*/
	ndi_post_event,			/* (*bus_post_event)();		*/
	NULL,				/* (*bus_intr_ctl)(); */
	NULL,				/* (*bus_config)(); */
	NULL,				/* (*bus_unconfig)(); */
	pxb_fm_init_child,		/* (*bus_fm_init)(); */
	NULL,				/* (*bus_fm_fini)(); */
	i_ndi_busop_access_enter,	/* (*bus_fm_access_enter)(); */
	i_ndi_busop_access_exit,	/* (*bus_fm_access_fini)(); */
	pcie_bus_power,			/* (*bus_power)(); */
	pxb_intr_ops			/* (*bus_intr_op)();		*/
};

static int pxb_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int pxb_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int pxb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int pxb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

static struct cb_ops pxb_cb_ops = {
	pxb_open,			/* open */
	pxb_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nulldev,			/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	pxb_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pxb_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static int pxb_probe(dev_info_t *);
static int pxb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int pxb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int pxb_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static int pxb_pwr_setup(dev_info_t *dip);
static int pxb_pwr_init_and_raise(dev_info_t *dip, pcie_pwr_t *pwr_p);
static void pxb_pwr_teardown(dev_info_t *dip);

/* PLX specific functions */
#ifdef	PX_PLX
static int plx_pwr_disable(dev_info_t *dip);
static void plx_ro_disable(pxb_devstate_t *pxb);
#endif	/* PX_PLX */


/* Hotplug related functions */
static int pxb_pciehpc_probe(dev_info_t *dip, ddi_acc_handle_t config_handle);
static int pxb_pcishpc_probe(dev_info_t *dip, ddi_acc_handle_t config_handle);
static int pxb_init_hotplug(pxb_devstate_t *pxb);
static void pxb_id_props(pxb_devstate_t *pxb);

static struct dev_ops pxb_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	pxb_info,		/* info */
	nulldev,		/* identify */
	pxb_probe,		/* probe */
	pxb_attach,		/* attach */
	pxb_detach,		/* detach */
	nulldev,		/* reset */
	&pxb_cb_ops,		/* driver operations */
	&pxb_bus_ops,		/* bus operations */
	pcie_power		/* power entry */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"PCIe/PCI nexus driver %I%",
	&pxb_ops,   /* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * soft state pointer and structure template:
 */
void *pxb_state;

/*
 * SW workaround for PLX HW bug Flag
 */
static int pxb_tlp_count = 64;

/*
 * forward function declarations:
 */
static int pxb_intr_init(pxb_devstate_t *pxb, int intr_type);
static void pxb_intr_fini(pxb_devstate_t *pxb);
static uint_t pxb_intr(caddr_t arg1, caddr_t arg2);
static int pxb_intr_attach(pxb_devstate_t *pxb);

static void pxb_removechild(dev_info_t *);
static int pxb_initchild(dev_info_t *child);
static void pxb_create_ranges_prop(dev_info_t *, ddi_acc_handle_t);

int
_init(void)
{
	int e;
	if ((e = ddi_soft_state_init(&pxb_state, sizeof (pxb_devstate_t),
	    1)) == 0 && (e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pxb_state);
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&pxb_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pxb_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	pxb_devstate_t *pxb_p;	/* per pxb state pointer */
	minor_t		minor = getminor((dev_t)arg);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	pxb_p = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    instance);

	switch (infocmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (pxb_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)pxb_p->pxb_dip;
		return (DDI_SUCCESS);
	}
}

/*ARGSUSED*/
static int
pxb_probe(register dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

/*ARGSUSED*/
static int
pxb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int			instance;
	pxb_devstate_t		*pxb;
	ddi_acc_handle_t	config_handle;
	char			device_type[8];
	uint16_t		cap_ptr;
#ifdef PX_PLX
	uint_t			bus_num, primary, secondary;
#endif /* PX_PLX */

	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_RESUME:
		DBG(DBG_ATTACH, devi, "DDI_RESUME\n");
		/*
		 * Get the soft state structure for the bridge.
		 */
		pxb = (pxb_devstate_t *)
		    ddi_get_soft_state(pxb_state, instance);
		(void) pcie_pwr_resume(devi);

		return (DDI_SUCCESS);

	case DDI_ATTACH:
		DBG(DBG_ATTACH, devi, "DDI_ATTACH\n");

		/* Follow through to below the switch statement */
		break;
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate and get soft state structure.
	 */
	if (ddi_soft_state_zalloc(pxb_state, instance) != DDI_SUCCESS) {
		DBG(DBG_ATTACH, devi, "Unable to allocate soft state.\n");
		return (DDI_FAILURE);
	}

	pxb = (pxb_devstate_t *)ddi_get_soft_state(pxb_state, instance);
	pxb->pxb_dip = devi;
	pxb->pxb_soft_state = PXB_SOFT_STATE_CLOSED;

	/* Create Mutex */
	mutex_init(&pxb->pxb_mutex, NULL, MUTEX_DRIVER, NULL);
	pxb->pxb_init_flags = PXB_INIT_MUTEX;

	/* Setup and save the config space pointer */
	if (pci_config_setup(devi, &config_handle) != DDI_SUCCESS) {
		DBG(DBG_ATTACH, devi, "Failed in pci_config_setup call\n");
		goto fail;
	}
	pxb->pxb_config_handle = config_handle;
	pxb->pxb_init_flags |= PXB_INIT_CONFIG_HANDLE;

	/* Save the vendor id and device id */
	pxb->pxb_vendor_id = pci_config_get16(config_handle, PCI_CONF_VENID);
	pxb->pxb_device_id = pci_config_get16(config_handle, PCI_CONF_DEVID);
	pxb->pxb_rev_id = pci_config_get8(config_handle, PCI_CONF_REVID);

	/* create special properties for device identification */
	pxb_id_props(pxb);

	/*
	 * Power management setup. This also makes sure that switch/bridge
	 * is at D0 during attach.
	 */
	if (pwr_common_setup(devi) != DDI_SUCCESS) {
		DBG(DBG_PWR, devi, "pwr_common_setup failed\n");
		goto fail;
	}

#ifdef PX_PLX
	if (plx_pwr_disable(devi) != DDI_SUCCESS) {
		DBG(DBG_PWR, devi, "plx_pwr_disable failed \n");
#else
	if (pxb_pwr_setup(devi) != DDI_SUCCESS) {
		DBG(DBG_PWR, devi, "pxb_pwr_setup failed \n");
#endif /* PX_PLX */
		goto fail;
	}

	if ((PCI_CAP_LOCATE(pxb->pxb_config_handle, PCI_CAP_ID_PCI_E,
	    &cap_ptr)) != DDI_FAILURE)
		pxb->pxb_port_type = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		    PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;
	else
		pxb->pxb_port_type = PCIE_PCIECAP_DEV_TYPE_PCIE_DEV;

	if ((pxb->pxb_port_type != PCIE_PCIECAP_DEV_TYPE_UP) &&
	    (pxb->pxb_port_type != PCIE_PCIECAP_DEV_TYPE_DOWN) &&
	    (pxb->pxb_port_type != PCIE_PCIECAP_DEV_TYPE_ROOT) &&
	    (pxb->pxb_port_type != PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) &&
	    (pxb->pxb_port_type != PCIE_PCIECAP_DEV_TYPE_PCI2PCIE)) {
		DBG(DBG_ATTACH, devi, "This is not a switch or bridge\n");
		goto fail;
	}

	/*
	 * Make sure the "device_type" property exists.
	 */
	if (pxb_pcie_device_type(pxb) == DDI_SUCCESS)
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
		pxb_create_ranges_prop(devi, config_handle);
	}

	/*
	 * Create an integer property with PCIE2PCI bridge's secondary
	 * PCI bus number. This property will be read and saved in all
	 * PCI and PCI-X device driver's parent private data structure
	 * as part of their init child function.
	 */
	if (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, pxb->pxb_dip,
		    "pcie2pci-sec-bus", pci_config_get8(config_handle,
		    PCI_BCNF_SECBUS)) != DDI_PROP_SUCCESS) {
			DBG(DBG_ATTACH, pxb->pxb_dip,
			    "ndi_prop_update_int() failed\n");
			goto fail;
		}

		pxb_set_pci_perf_parameters(devi, config_handle);
	}

	/*
	 * Initialize hotplug support on this bus except for the PLX 8532
	 * revision AA. At a minimum (for non hotplug bus) this would create
	 * ":devctl" minor node to support DEVCTL_DEVICE_* and DEVCTL_BUS_*
	 * ioctls to this bus. This all takes place if this nexus has hot-plug
	 * slots and successfully initializes Hot Plug Framework.
	 */
	pxb->pxb_hotplug_capable = B_FALSE;

#ifdef PX_PLX
	/*
	 * Due to a PLX HW bug we need to disable the receiver error CE on all
	 * ports. To this end we create a property "pcie_ce_mask" with value
	 * set to PCIE_AER_CE_RECEIVER_ERR. The pcie module will check for this
	 * property before setting the AER CE mask.
	 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, pxb->pxb_dip,
	    "pcie_ce_mask", PCIE_AER_CE_RECEIVER_ERR);

	/*
	 * There is a bug in the PLX 8114 bridge, such that an 8-bit
	 * write to the secondary bus number register will corrupt an
	 * internal shadow copy of the primary bus number.  Reading
	 * out the registers and writing the same values back as
	 * 16-bits resolves the problem.  This bug was reported by
	 * PLX as errata #19.
	 */
	primary = pci_config_get8(config_handle, PCI_BCNF_PRIBUS);
	secondary = pci_config_get8(config_handle, PCI_BCNF_SECBUS);
	bus_num = (secondary << 8) | primary;
	pci_config_put16(config_handle, PCI_BCNF_PRIBUS, bus_num);

	/*
	 * Disable PLX Special Relaxed Ordering
	 */
	plx_ro_disable(pxb);

	if ((pxb->pxb_device_id == PXB_DEVICE_PLX_8532) &&
	    (pxb->pxb_rev_id <= PXB_DEVICE_PLX_AA_REV))
		goto hotplug_done;
#endif /* PX_PLX */

	if ((pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_DOWN) ||
	    (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) ||
	    (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE)) {
#ifdef PX_PLX
		/*
		 * Workaround for a race condition between hotplug
		 * initialization and actual MSI interrupt registration
		 * for hotplug functionality. The hotplug initialization
		 * generates an INTx interrupt for hotplug events and this
		 * INTx interrupt may interfere with shared leaf drivers
		 * using same INTx interrupt, which may eventually block
		 * the leaf drivers.
		 */
		pci_config_put16(config_handle, PCI_CONF_COMM,
		    pci_config_get16(config_handle, PCI_CONF_COMM) |
		    PCI_COMM_INTX_DISABLE);
#endif /* PX_PLX */

		if (pxb_init_hotplug(pxb) != DDI_SUCCESS)
			goto fail;
	}

hotplug_done:
#ifdef	PRINT_PLX_SEEPROM_CRC
	/* check seeprom CRC to ensure the platform config is right */
	(void) pxb_print_plx_seeprom_crc_data(pxb);
#endif

	if (pxb->pxb_hotplug_capable == B_FALSE) {
		/*
		 * create minor node for devctl interfaces
		 */
		if (ddi_create_minor_node(devi, "devctl", S_IFCHR,
		    PCIHP_AP_MINOR_NUM(instance, PCIHP_DEVCTL_MINOR),
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS)
			goto fail;
	}

	DBG(DBG_ATTACH, devi,
	    "pxb_attach(): this nexus %s hotplug slots\n",
	    pxb->pxb_hotplug_capable == B_TRUE ? "has":"has no");

	if ((pxb_fm_init(pxb)) != DDI_SUCCESS) {
		DBG(DBG_ATTACH, devi, "Failed in px_pci_fm_attach\n");
		goto fail;
	}
	pxb->pxb_init_flags |= PXB_INIT_FM;

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

fail:
	(void) pxb_detach(devi, DDI_DETACH);

	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pxb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	pxb_devstate_t *pxb;
	int error = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH:
		/*
		 * And finally free the per-pci soft state after
		 * uninitializing hotplug support for this bus in
		 * opposite order of attach.
		 */
		pxb = (pxb_devstate_t *)
		    ddi_get_soft_state(pxb_state, ddi_get_instance(devi));

#ifdef PX_PLX
		(void) ndi_prop_remove(DDI_DEV_T_NONE, pxb->pxb_dip,
		    "pcie_ce_mask");
#endif /* PX_PLX */

		if (pxb->pxb_hotplug_capable == B_TRUE) {
			if (pcihp_uninit(devi) == DDI_FAILURE)
				error = DDI_FAILURE;

			if (pxb->pxb_hpc_type == HPC_PCIE)
				(void) pciehpc_uninit(devi);
			else if (pxb->pxb_hpc_type == HPC_SHPC)
				(void) pcishpc_uninit(devi);

			pxb_intr_fini(pxb);
		}
		else
			ddi_remove_minor_node(devi, "devctl");

		(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");

		if (pxb->pxb_init_flags & PXB_INIT_FM)
			pxb_fm_fini(pxb);

		(void) ndi_prop_remove(DDI_DEV_T_NONE, pxb->pxb_dip,
		    "pcie2pci-sec-bus");

		if (pxb->pxb_init_flags & PXB_INIT_CONFIG_HANDLE)
			pci_config_teardown(&pxb->pxb_config_handle);

		pxb_pwr_teardown(devi);
		pwr_common_teardown(devi);
		if (pxb->pxb_init_flags & PXB_INIT_MUTEX)
			mutex_destroy(&pxb->pxb_mutex);

		ddi_soft_state_free(pxb_state, ddi_get_instance(devi));

		return (error);

	case DDI_SUSPEND:
		pxb = (pxb_devstate_t *)
		    ddi_get_soft_state(pxb_state, ddi_get_instance(devi));

		error = pcie_pwr_suspend(devi);

		return (error);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pxb_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	register dev_info_t *pdip;

	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
	    (pdip, rdip, mp, offset, len, vaddrp));
}

/*ARGSUSED*/
static int
pxb_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	int	reglen;
	int	rn;
	int	totreg;
	struct detachspec *ds;
	struct attachspec *as;
	pxb_devstate_t	*pxb_p;

	pxb_p = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    ddi_get_instance(dip));

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
		return (pxb_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		pxb_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		break;

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
				ddi_acc_handle_t	config_handle;
				DBG(DBG_PWR, dip, "PRE_RESUME for %s@%d\n",
				    ddi_driver_name(rdip),
				    ddi_get_instance(rdip));


				if (pci_config_setup(rdip, &config_handle) ==
				    DDI_SUCCESS) {
					pcie_clear_errors(rdip, config_handle);
					pci_config_teardown(&config_handle);
				}
			}
			return (DDI_SUCCESS);

		case DDI_POST: {
			ddi_acc_handle_t	config_handle;
			DBG(DBG_PWR, dip, "POST_ATTACH for %s@%d\n",
			    ddi_driver_name(rdip), ddi_get_instance(rdip));
			if (as->cmd == DDI_ATTACH && as->result != DDI_SUCCESS)
				pcie_pm_release(dip);

			if (as->result == DDI_SUCCESS)
				pf_init(rdip, (void *)pxb_p->pxb_fm_ibc,
				    as->cmd);

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

			if (pci_config_setup(rdip, &config_handle) ==
			    DDI_SUCCESS) {
				pcie_disable_errors(rdip, config_handle);
				pci_config_teardown(&config_handle);
			}

			return (DDI_SUCCESS);
		}
		default:
			break;
		}
		break;

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		ds = (struct detachspec *)arg;
		switch (ds->when) {
		case DDI_PRE:
			pf_fini(rdip, ds->cmd);
			return (DDI_SUCCESS);

		case DDI_POST:
			if (ds->cmd == DDI_DETACH &&
			    ds->result == DDI_SUCCESS) {
				DBG(DBG_PWR, dip, "POST_DETACH for %s@%d\n",
				    ddi_driver_name(rdip),
				    ddi_get_instance(rdip));
				return (pcie_pm_remove_child(dip, rdip));
			}
			return (DDI_SUCCESS);
		default:
			break;
		}
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
		*(off_t *)result = drv_regp[rn].pci_size_low |
		    ((uint64_t)drv_regp[rn].pci_size_hi << 32);
	}

	kmem_free(drv_regp, reglen);
	return (DDI_SUCCESS);
}


static int
pxb_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	dev_info_t	*cdip = rdip;
	pci_regspec_t	*pci_rp;
	int		reglen, len;
	uint32_t	d, intr;

	if ((intr_op == DDI_INTROP_SUPPORTED_TYPES) ||
	    (hdlp->ih_type != DDI_INTR_TYPE_FIXED))
		goto done;

	/*
	 * If the interrupt-map property is defined at this
	 * node, it will have performed the interrupt
	 * translation as part of the property, so no
	 * rotation needs to be done.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-map", &len) == DDI_PROP_SUCCESS)
		goto done;

	cdip = pcie_get_my_childs_dip(dip, rdip);

	/*
	 * Use the devices reg property to determine its
	 * PCI bus number and device number.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&pci_rp, &reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	intr = hdlp->ih_vector;

	/* spin the interrupt */
	d = PCI_REG_DEV_G(pci_rp[0].pci_phys_hi);
	if ((intr >= PCI_INTA) && (intr <= PCI_INTD))
		hdlp->ih_vector = ((intr - 1 + (d % 4)) % 4 + 1);
	else
		cmn_err(CE_WARN, "%s%d: %s: PCI intr=%x out of range",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), intr);

	kmem_free(pci_rp, reglen);

done:
	/* Pass up the request to our parent. */
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
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
pxb_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	uint_t slot, func;
	char **unit_addr;
	uint_t n;

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "cannot name node from %s.conf",
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
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, &n) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	slot = PCI_REG_DEV_G(pci_rp[0].pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp[0].pci_phys_hi);

	if (func != 0)
		(void) snprintf(name, namelen, "%x,%x", slot, func);
	else
		(void) snprintf(name, namelen, "%x", slot);

	ddi_prop_free(pci_rp);
	return (DDI_SUCCESS);
}

static int
pxb_initchild(dev_info_t *child)
{
	char 			name[MAXNAMELEN];
	pxb_devstate_t		*pxb;
	int			result = DDI_FAILURE;
#ifdef PX_PLX
	int			i;
	uint16_t		reg = 0;
	ddi_acc_handle_t	config_handle;
#endif /* PX_PLX */

	/*
	 * Name the child
	 */
	if (pxb_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS) {
		result = DDI_FAILURE;
		goto done;
	}

	ddi_set_name_addr(child, name);
	ddi_set_parent_data(child, NULL);

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
		if (ndi_merge_node(child, pxb_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			ddi_remove_minor_node(child, NULL);
			result = DDI_FAILURE;
			goto done;
		}

		/* workaround for ddivs to run under PCI */
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
		ddi_remove_minor_node(child, NULL);
		result = DDI_NOT_WELL_FORMED;
		goto done;
	}

	ddi_set_parent_data(child, NULL);

	pxb = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    ddi_get_instance(ddi_get_parent(child)));

	if (pcie_pm_hold(pxb->pxb_dip) != DDI_SUCCESS) {
		DBG(DBG_PWR, pxb->pxb_dip,
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
		DBG(DBG_PWR, ddi_get_parent(child),
		    "INITCHILD: config regs to be restored by child"
		    " for %s@%s\n", ddi_node_name(child),
		    ddi_get_name_addr(child));

		result = DDI_SUCCESS;
		goto cleanup;
	}

	DBG(DBG_PWR, ddi_get_parent(child),
	    "INITCHILD: config regs setup for %s@%s\n",
	    ddi_node_name(child), ddi_get_name_addr(child));

	if (pcie_initchild(child) != DDI_SUCCESS) {
		result = DDI_FAILURE;
		goto cleanup;
	}

#ifdef PX_PLX
	/*
	 * Due to a PLX HW bug, a SW workaround to prevent the chip from
	 * wedging is needed.  SW just needs to tranfer 64 TLPs from
	 * the downstream port to the child device.
	 * The most benign way of doing this is to read the ID register
	 * 64 times.  This SW workaround should have minimum performance
	 * impact and shouldn't cause a problem for all other bridges
	 * and switches.
	 *
	 * The code needs to be written in a way to make sure it isn't
	 * optimized out.
	 */
	if (!pxb_tlp_count) {
		result = DDI_SUCCESS;
		goto cleanup;
	}

	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS) {
		result = DDI_FAILURE;
		goto cleanup;
	}

	for (i = 0; i < pxb_tlp_count; i += 1)
		reg |= pci_config_get16(config_handle, PCI_CONF_VENID);

	if (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)
		pxb_set_pci_perf_parameters(child, config_handle);

	pci_config_teardown(&config_handle);
#endif /* PX_PLX */

	result = DDI_SUCCESS;
cleanup:
	pcie_pm_release(pxb->pxb_dip);
done:
	return (result);
}

static int
pxb_intr_attach(pxb_devstate_t *pxb)
{
	int			intr_types;
	dev_info_t		*devi;

	devi = pxb->pxb_dip;
	/*
	 * Initialize interrupt handlers.
	 * If both MSI and FIXED are supported, try to attach MSI first.
	 * If MSI fails for any reason, then try FIXED, but only allow one
	 * type to be attached.
	 */
	if (ddi_intr_get_supported_types(devi, &intr_types) != DDI_SUCCESS) {
		DBG(DBG_ATTACH, devi, "ddi_intr_get_supported_types failed\n");
		return (DDI_FAILURE);
	}

	if ((intr_types & DDI_INTR_TYPE_MSI) && pxb_enable_msi) {
		if (pxb_intr_init(pxb, DDI_INTR_TYPE_MSI) == DDI_SUCCESS)
			intr_types = DDI_INTR_TYPE_MSI;
		else
			DBG(DBG_ATTACH, devi, "Unable to attach MSI handler\n");
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (pxb_intr_init(pxb, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS) {
			DBG(DBG_ATTACH, devi,
			    "Unable to attach INTx handler\n");
			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
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
pxb_intr_init(pxb_devstate_t *pxb, int intr_type)
{
	dev_info_t	*dip = pxb->pxb_dip;
	int		request, count, x;
	int		ret;
	int		intr_cap = 0;

	DBG(DBG_ATTACH, dip,
	    "Attaching %s handler\n",
	    (intr_type == DDI_INTR_TYPE_MSI) ? "MSI" : "INTx");

	/*
	 * Get number of requested interrupts.	If none requested or DDI_FAILURE
	 * just return DDI_SUCCESS.
	 *
	 * Several Bridges/Switches will not have this property set, resulting
	 * in a FAILURE, if the device is not configured in a way that
	 * interrupts are needed. (eg. hotplugging)
	 */
	ret = ddi_intr_get_nintrs(dip, intr_type, &request);
	if (ret != DDI_SUCCESS || request == 0) {
		DBG(DBG_ATTACH, dip,
		    "ddi_intr_get_nintrs() ret: %d req %d\n", ret, request);

		return (DDI_SUCCESS);
	}

	/* Find out how many MSI's are available. */
	if (intr_type == DDI_INTR_TYPE_MSI) {
		ret = ddi_intr_get_navail(dip, intr_type, &count);
		if ((ret != DDI_SUCCESS) || (count == 0)) {
			DBG(DBG_ATTACH, dip,
			    "ddi_intr_get_navail() ret: %d available: %d\n",
			    ret, count);

			goto fail;
		}

		if (request < count) {
			DBG(DBG_ATTACH, dip,
			    "Requested Intr: %d Available: %d\n",
			    request, count);

			request = count;
		}
	}

	/* Allocate an array of interrupt handlers */
	pxb->pxb_htable_size = sizeof (ddi_intr_handle_t) * request;
	pxb->pxb_htable = kmem_zalloc(pxb->pxb_htable_size, KM_SLEEP);
	pxb->pxb_init_flags |= PXB_INIT_HTABLE;

	ret = ddi_intr_alloc(dip, pxb->pxb_htable, intr_type,
	    0, request, &count, DDI_INTR_ALLOC_NORMAL);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		DBG(DBG_ATTACH, dip,
		    "ddi_intr_alloc() ret: %d ask: %d actual: %d\n",
		    ret, request, count);

		goto fail;
	}

	/* Save the actually number of interrupts allocated */
	pxb->pxb_intr_count = count;
	if (count < request) {
		DBG(DBG_ATTACH, dip,
		    "Requested Intr: %d Received: %d\n",
		    request, count);
	}
	pxb->pxb_init_flags |= PXB_INIT_ALLOC;


	/* Get interrupt priority */
	ret = ddi_intr_get_pri(pxb->pxb_htable[0], &pxb->pxb_intr_priority);
	if (ret != DDI_SUCCESS) {
		DBG(DBG_ATTACH, dip, "ddi_intr_get_pri() ret: %d\n", ret);

		goto fail;
	}

	if (pxb->pxb_intr_priority >= LOCK_LEVEL) {
		pxb->pxb_intr_priority = LOCK_LEVEL - 1;
		ret = ddi_intr_set_pri(pxb->pxb_htable[0],
		    pxb->pxb_intr_priority);
		if (ret != DDI_SUCCESS) {
			DBG(DBG_ATTACH, dip, "ddi_intr_set_pri() ret: %d\n",
			    ret);

			goto fail;
		}
	}

	for (count = 0; count < pxb->pxb_intr_count; count++) {
		ret = ddi_intr_add_handler(pxb->pxb_htable[count],
		    pxb_intr, (caddr_t)pxb, NULL);

		if (ret != DDI_SUCCESS) {
			DBG(DBG_ATTACH, dip,
			    "ddi_intr_add_handler() ret: %d\n",
			    ret);

			break;
		}
	}

	/* If unsucessful remove the added handlers */
	if (ret != DDI_SUCCESS) {
		for (x = 0; x < count; x++) {
			(void) ddi_intr_remove_handler(pxb->pxb_htable[x]);
		}
		goto fail;
	}

	pxb->pxb_init_flags |= PXB_INIT_HANDLER;

	(void) ddi_intr_get_cap(pxb->pxb_htable[0], &intr_cap);

	if (intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(pxb->pxb_htable,
		    pxb->pxb_intr_count);
		pxb->pxb_init_flags |= PXB_INIT_BLOCK;
	} else {
		for (count = 0; count < pxb->pxb_intr_count; count++) {
			(void) ddi_intr_enable(pxb->pxb_htable[count]);
		}
	}
	pxb->pxb_init_flags |= PXB_INIT_ENABLE;

	/* Save the interrupt type */
	pxb->pxb_intr_type = intr_type;

	return (DDI_SUCCESS);

fail:
	pxb_intr_fini(pxb);

	return (DDI_FAILURE);
}

static void
pxb_intr_fini(pxb_devstate_t *pxb)
{
	int x;
	int count = pxb->pxb_intr_count;
	int flags = pxb->pxb_init_flags;

	if ((flags & PXB_INIT_ENABLE) && (flags & PXB_INIT_BLOCK)) {
		(void) ddi_intr_block_disable(pxb->pxb_htable, count);
		flags &= ~(PXB_INIT_ENABLE | PXB_INIT_BLOCK);
	}

	for (x = 0; x < count; x++) {
		if (flags & PXB_INIT_ENABLE)
			(void) ddi_intr_disable(pxb->pxb_htable[x]);

		if (flags & PXB_INIT_HANDLER)
			(void) ddi_intr_remove_handler(pxb->pxb_htable[x]);

		if (flags & PXB_INIT_ALLOC)
			(void) ddi_intr_free(pxb->pxb_htable[x]);
	}

	flags &= ~(PXB_INIT_ENABLE | PXB_INIT_HANDLER | PXB_INIT_ALLOC);

	if (flags & PXB_INIT_HTABLE)
		kmem_free(pxb->pxb_htable, pxb->pxb_htable_size);

	flags &= ~PXB_INIT_HTABLE;

	pxb->pxb_init_flags &= flags;
}

/*
 * This only handles internal errors, not bus errors.
 * Currently the only known interrupt would be from hotplugging.
 */
/*ARGSUSED*/
static uint_t
pxb_intr(caddr_t arg1, caddr_t arg2)
{
	pxb_devstate_t	*pxb = (pxb_devstate_t *)arg1;
	dev_info_t	*dip = pxb->pxb_dip;
	int rval = DDI_INTR_UNCLAIMED;

	if (pxb->pxb_hotplug_capable == B_TRUE) {
		if (pxb->pxb_hpc_type == HPC_PCIE)
			rval = pciehpc_intr(pxb->pxb_dip);
		else
		if (pxb->pxb_hpc_type == HPC_SHPC)
			rval = pcishpc_intr(pxb->pxb_dip);
	}
	if ((rval == DDI_INTR_UNCLAIMED) && (pxb->pxb_intr_type ==
	    DDI_INTR_TYPE_MSI))
		cmn_err(CE_WARN, "%s%d: Cannot handle interrupt",
		    ddi_driver_name(dip), ddi_get_instance(dip));

	return (rval);
}

static void
pxb_removechild(dev_info_t *dip)
{
	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	impl_rem_dev_props(dip);

	pcie_uninitchild(dip);
}

/*
 * Initialize hotplug framework if we are hotpluggable.
 * Sets flag in the soft state if Hot Plug is supported and initialized
 * properly.
 */
/*ARGSUSED*/
static int
pxb_init_hotplug(pxb_devstate_t *pxb)
{
	int rv = DDI_FAILURE;

	if (((pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_DOWN) ||
	    (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    (pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE)) &&
	    (pxb_pciehpc_probe(pxb->pxb_dip,
	    pxb->pxb_config_handle) == DDI_SUCCESS)) {
		pxb->pxb_hpc_type = HPC_PCIE;
	} else if ((pxb->pxb_port_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) &&
	    (pxb_pcishpc_probe(pxb->pxb_dip,
	    pxb->pxb_config_handle) == DDI_SUCCESS)) {
		pxb->pxb_hpc_type = HPC_SHPC;
	} else {
		pxb->pxb_hpc_type = HPC_NONE;
		return (DDI_SUCCESS);
	}

	pxb->pxb_hotplug_capable = B_TRUE;
	if (pxb_intr_attach(pxb) != DDI_SUCCESS)
		goto fail;

	if (pxb->pxb_hpc_type == HPC_PCIE)
		rv = pciehpc_init(pxb->pxb_dip, NULL);
	else if (pxb->pxb_hpc_type == HPC_SHPC)
		rv = pcishpc_init(pxb->pxb_dip);

	if (rv != DDI_SUCCESS)
		goto fail;

	if (pcihp_init(pxb->pxb_dip) != DDI_SUCCESS) {
		if (pxb->pxb_hpc_type == HPC_PCIE)
			(void) pciehpc_uninit(pxb->pxb_dip);
		else if (pxb->pxb_hpc_type == HPC_SHPC)
			(void) pcishpc_uninit(pxb->pxb_dip);

		goto fail;
	}

	(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, pxb->pxb_dip,
	    "hotplug-capable");

	return (DDI_SUCCESS);

fail:
	pxb->pxb_hpc_type = HPC_NONE;
	pxb->pxb_hotplug_capable = B_FALSE;
	cmn_err(CE_WARN, "%s%d: Failed setting hotplug framework",
	    ddi_driver_name(pxb->pxb_dip), ddi_get_instance(pxb->pxb_dip));

	return (DDI_FAILURE);
}

static void
pxb_create_ranges_prop(dev_info_t *dip,
	ddi_acc_handle_t config_handle)
{
	uint32_t base, limit;
	pxb_ranges_t	ranges[PXB_RANGE_LEN];
	uint8_t io_base_lo, io_limit_lo;
	uint16_t io_base_hi, io_limit_hi, mem_base, mem_limit;
	int i = 0, rangelen = sizeof (pxb_ranges_t)/sizeof (int);

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
	ranges[i].parent_mid = ranges[i].child_mid =
	    ranges[i].parent_high = 0;
	ranges[i].child_high = ranges[i].parent_high |=
	    (PCI_REG_REL_M | PCI_ADDR_IO);
	base = PXB_16bit_IOADDR(io_base_lo);
	limit = PXB_16bit_IOADDR(io_limit_lo);

	if ((io_base_lo & 0xf) == PXB_32BIT_IO) {
		base = PXB_LADDR(base, io_base_hi);
	}
	if ((io_limit_lo & 0xf) == PXB_32BIT_IO) {
		limit = PXB_LADDR(limit, io_limit_hi);
	}

	if ((io_base_lo & PXB_32BIT_IO) && (io_limit_hi > 0)) {
		base = PXB_LADDR(base, io_base_hi);
		limit = PXB_LADDR(limit, io_limit_hi);
	}

	/*
	 * Create ranges for 32bit memory space
	 */
	base = PXB_32bit_MEMADDR(mem_base);
	limit = PXB_32bit_MEMADDR(mem_limit);
	ranges[i].size_low = ranges[i].size_high = 0;
	ranges[i].parent_mid = ranges[i].child_mid =
	    ranges[i].parent_high = 0;
	ranges[i].child_high = ranges[i].parent_high |=
	    (PCI_REG_REL_M | PCI_ADDR_MEM32);
	ranges[i].child_low = ranges[i].parent_low = base;
	if (limit >= base) {
		ranges[i].size_low = limit - base + PXB_MEMGRAIN;
		i++;
	}

	if (i) {
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "ranges",
		    (int *)ranges, i * rangelen);
	}
}

/*ARGSUSED*/
static int
pxb_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	pxb_devstate_t *pxb_p;
	minor_t		minor = getminor(*devp);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	pxb_p = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    instance);

	if (pxb_p == NULL)
		return (ENXIO);

	if (pxb_p->pxb_hotplug_capable == B_TRUE)
		return ((pcihp_get_cb_ops())->cb_open(devp, flags,
		    otyp, credp));

	/*
	 * Handle the open by tracking the device state.
	 */
	mutex_enter(&pxb_p->pxb_mutex);
	if (flags & FEXCL) {
		if (pxb_p->pxb_soft_state != PXB_SOFT_STATE_CLOSED) {
			mutex_exit(&pxb_p->pxb_mutex);
			return (EBUSY);
		}
		pxb_p->pxb_soft_state = PXB_SOFT_STATE_OPEN_EXCL;
	} else {
		if (pxb_p->pxb_soft_state == PXB_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&pxb_p->pxb_mutex);
			return (EBUSY);
		}
		pxb_p->pxb_soft_state = PXB_SOFT_STATE_OPEN;
	}
	mutex_exit(&pxb_p->pxb_mutex);
	return (0);
}


/*ARGSUSED*/
static int
pxb_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	pxb_devstate_t *pxb_p;
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	pxb_p = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    instance);

	if (pxb_p == NULL)
		return (ENXIO);

	if (pxb_p->pxb_hotplug_capable == B_TRUE)
		return ((pcihp_get_cb_ops())->cb_close(dev, flags,
		    otyp, credp));

	mutex_enter(&pxb_p->pxb_mutex);
	pxb_p->pxb_soft_state = PXB_SOFT_STATE_CLOSED;
	mutex_exit(&pxb_p->pxb_mutex);
	return (0);
}


/*
 * pxb_ioctl: devctl hotplug controls
 */
/*ARGSUSED*/
static int
pxb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	pxb_devstate_t *pxb_p;
	dev_info_t *self;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	pxb_p = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    instance);

	if (pxb_p == NULL)
		return (ENXIO);

	if (pxb_p->pxb_hotplug_capable == B_TRUE)
		return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd,
		    arg, mode, credp, rvalp));

	self = pxb_p->pxb_dip;

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(self, cmd, arg, mode, 0));
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(self, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		rv = ENOTSUP;
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}

static int pxb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	pxb_devstate_t *pxb_p;
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);

	pxb_p = (pxb_devstate_t *)ddi_get_soft_state(pxb_state,
	    instance);

	if (pxb_p == NULL)
		return (ENXIO);

	if (pxb_p->pxb_hotplug_capable == B_TRUE)
		return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op,
		    flags, name, valuep, lengthp));

	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

#ifdef PX_PLX
/*
 * Disable PM for PLX 8532 switch. Transitioning one port on
 * this switch to low power causes links on other ports on the
 * same station to die.
 * Due to PLX erratum #34, we can't allow the downstream device
 * go to non-D0 state.
 */
static int
plx_pwr_disable(dev_info_t *dip)
{
	pcie_pwr_t *pwr_p;

	ASSERT(PCIE_PMINFO(dip));
	pwr_p = PCIE_NEXUS_PMINFO(dip);
	ASSERT(pwr_p);
	DBG(DBG_PWR, dip, "plx_pwr_disable: PLX8532/PLX8516 found "
	    "disabling PM\n");
	pwr_p->pwr_func_lvl = PM_LEVEL_D0;
	pwr_p->pwr_flags = PCIE_NO_CHILD_PM;
	return (DDI_SUCCESS);
}
#endif /* PX_PLX */

/*
 * Power management related initialization specific to px_pci.
 * Called by pxb_attach()
 */
static int
pxb_pwr_setup(dev_info_t *dip)
{
	char *comp_array[5];
	int i;
	ddi_acc_handle_t conf_hdl;
	uint16_t pmcap, cap_ptr;
	pcie_pwr_t *pwr_p;

	ASSERT(PCIE_PMINFO(dip));
	pwr_p = PCIE_NEXUS_PMINFO(dip);
	ASSERT(pwr_p);

	/* Code taken from pci_pci driver */
	if (pci_config_setup(dip, &pwr_p->pwr_conf_hdl) != DDI_SUCCESS) {
		DBG(DBG_PWR, dip, "pxb_pwr_setup: pci_config_setup failed\n");
		return (DDI_FAILURE);
	}
	conf_hdl = pwr_p->pwr_conf_hdl;

	/*
	 * Walk the capabilities searching for a PM entry.
	 */
	if ((PCI_CAP_LOCATE(conf_hdl, PCI_CAP_ID_PM, &cap_ptr))
	    == DDI_FAILURE) {
		DBG(DBG_PWR, dip, "switch/bridge does not support PM. PCI"
		    " PM data structure not found in config header\n");
		pci_config_teardown(&conf_hdl);
		return (DDI_SUCCESS);
	}
	/*
	 * Save offset to pmcsr for future references.
	 */
	pwr_p->pwr_pmcsr_offset = cap_ptr + PCI_PMCSR;
	pmcap = PCI_CAP_GET16(conf_hdl, NULL, cap_ptr, PCI_PMCAP);
	if (pmcap & PCI_PMCAP_D1) {
		DBG(DBG_PWR, dip, "D1 state supported\n");
		pwr_p->pwr_pmcaps |= PCIE_SUPPORTS_D1;
	}
	if (pmcap & PCI_PMCAP_D2) {
		DBG(DBG_PWR, dip, "D2 state supported\n");
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
		DBG(DBG_PWR, dip, "could not create pm-components prop\n");
		pci_config_teardown(&conf_hdl);
		return (DDI_FAILURE);
	}
	return (pxb_pwr_init_and_raise(dip, pwr_p));
}

/*
 * Initializes the power level and raise the power to D0, if it is
 * not at D0.
 */
static int
pxb_pwr_init_and_raise(dev_info_t *dip, pcie_pwr_t *pwr_p)
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
			DBG(DBG_PWR, dip, "pxb_pwr_setup: could not raise "
			    "power to D0 \n");
		}
	}
	if (ret == DDI_SUCCESS)
		pwr_p->pwr_func_lvl = PM_LEVEL_D0;
	return (ret);
}

static int
pxb_fm_init(pxb_devstate_t *pxb_p)
{
	dev_info_t	*dip = pxb_p->pxb_dip;

	pxb_p->pxb_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Request our capability level and get our parents capability
	 * and ibc.
	 */
	ddi_fm_init(dip, &pxb_p->pxb_fm_cap, &pxb_p->pxb_fm_ibc);

	pci_ereport_setup(dip);

	/*
	 * Register error callback with our parent.
	 */
	ddi_fm_handler_register(pxb_p->pxb_dip, pxb_fm_err_callback,
	    (void *)&pxb_p->pxb_config_handle);
	return (DDI_SUCCESS);
}

/*
 * Breakdown our FMA resources
 */
static void
pxb_fm_fini(pxb_devstate_t *pxb_p)
{
	dev_info_t *dip = pxb_p->pxb_dip;
	/*
	 * Clean up allocated fm structures
	 */
	ddi_fm_handler_unregister(dip);
	pci_ereport_teardown(dip);
	ddi_fm_fini(dip);
}

/*
 * Function used to initialize FMA for our children nodes. Called
 * through pci busops when child node calls ddi_fm_init.
 */
/*ARGSUSED*/
int
pxb_fm_init_child(dev_info_t *dip, dev_info_t *cdip, int cap,
    ddi_iblock_cookie_t *ibc_p)
{
	pxb_devstate_t *pxb_p = (pxb_devstate_t *)
	    ddi_get_soft_state(pxb_state, ddi_get_instance(dip));
	*ibc_p = pxb_p->pxb_fm_ibc;
	return (pxb_p->pxb_fm_cap | DDI_FM_DMACHK_CAPABLE);
}

/*
 * FMA Error callback handler.
 * Need to revisit when pcie fm is supported.
 */
/*ARGSUSED*/
static int
pxb_fm_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data)
{
	return (DDI_FM_OK);
}

/*
 * undo whatever is done in pxb_pwr_setup. called by pxb_detach()
 */
static void
pxb_pwr_teardown(dev_info_t *dip)
{
	pcie_pwr_t	*pwr_p;

	if (!PCIE_PMINFO(dip) || !(pwr_p = PCIE_NEXUS_PMINFO(dip)))
		return;

	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "pm-components");
	if (pwr_p->pwr_conf_hdl)
		pci_config_teardown(&pwr_p->pwr_conf_hdl);
}

/*ARGSUSED*/
static int pxb_pciehpc_probe(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t cap_ptr;

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr))
	    != DDI_FAILURE) {
		uint16_t slotimpl = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		    PCIE_PCIECAP) & PCIE_PCIECAP_SLOT_IMPL;
		if (slotimpl)
			if (PCI_CAP_GET32(config_handle, NULL, cap_ptr,
			    PCIE_SLOTCAP) & PCIE_SLOTCAP_HP_CAPABLE)
				return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);

}

/*ARGSUSED*/
static int pxb_pcishpc_probe(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t cap_ptr;

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_HOTPLUG, &cap_ptr))
	    != DDI_FAILURE) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);

}

/* check if this device has PCIe link underneath. */
static int
pxb_pcie_device_type(pxb_devstate_t *pxb_p)
{
	int port_type = pxb_p->pxb_port_type;

	/* No PCIe CAP regs, we are not PCIe device_type */
	if (port_type < 0)
		return (DDI_FAILURE);

	/* check for all PCIe device_types */
	if ((port_type == PCIE_PCIECAP_DEV_TYPE_UP) ||
	    (port_type == PCIE_PCIECAP_DEV_TYPE_DOWN) ||
	    (port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    (port_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

/*
 * For PCI and PCI-X devices including PCIe2PCI bridge, initialize
 * cache-line-size and latency timer configuration registers.
 */
static void
pxb_set_pci_perf_parameters(dev_info_t *dip, ddi_acc_handle_t cfg_hdl)
{
	uint_t	n;

	/* Initialize cache-line-size configuration register if needed */
	if (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {
		pci_config_put8(cfg_hdl, PCI_CONF_CACHE_LINESZ,
		    PXB_CACHE_LINE_SIZE);
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
			latency_timer = PXB_LATENCY_TIMER;
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

#ifdef	PRINT_PLX_SEEPROM_CRC
static void
pxb_print_plx_seeprom_crc_data(pxb_devstate_t *pxb_p)
{
	ddi_acc_handle_t h;
	dev_info_t *dip = pxb_p->pxb_dip;
	int nregs;
	caddr_t mp;
	off_t bar_size;
	ddi_device_acc_attr_t mattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC
	};
	uint32_t addr_reg_off = 0x260, data_reg_off = 0x264, data = 0x6BE4;

	if (pxb_p->pxb_vendor_id != PXB_VENDOR_PLX)
		return;
	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS)
		return;
	if (nregs < 2)	/* check for CONF entry only, no BARs */
		return;
	if (ddi_dev_regsize(dip, 1, &bar_size) != DDI_SUCCESS)
		return;
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&mp, 0, bar_size,
	    &mattr, &h) != DDI_SUCCESS)
		return;
	ddi_put32(h, (uint32_t *)((uchar_t *)mp + addr_reg_off), data);
	delay(drv_usectohz(1000000));
	printf("%s#%d: EEPROM StatusReg = %x, CRC = %x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_get32(h, (uint32_t *)((uchar_t *)mp + addr_reg_off)),
	    ddi_get32(h, (uint32_t *)((uchar_t *)mp + data_reg_off)));
#ifdef PLX_HOT_RESET_DISABLE
	/* prevent hot reset from propogating downstream. */
	data = ddi_get32(h, (uint32_t *)((uchar_t *)mp + 0x1DC));
	ddi_put32(h, (uint32_t *)((uchar_t *)mp + 0x1DC), data | 0x80000);
	delay(drv_usectohz(1000000));
	printf("%s#%d: EEPROM 0x1DC prewrite=%x postwrite=%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), data,
	    ddi_get32(h, (uint32_t *)((uchar_t *)mp + 0x1DC)));
#endif
	ddi_regs_map_free(&h);
}
#endif

static void
pxb_id_props(pxb_devstate_t *pxb)
{
	uint64_t serialid = 0;	/* 40b field of EUI-64 serial no. register */
	uint16_t cap_ptr;
	uint8_t fic = 0;	/* 1 = first in chassis device */

	/*
	 * Identify first in chassis.  In the special case of a Sun branded
	 * PLX device, it obviously is first in chassis.  Otherwise, in the
	 * general case, look for an Expansion Slot Register and check its
	 * first-in-chassis bit.
	 */
#ifdef	PX_PLX
	if ((pxb->pxb_vendor_id == PXB_VENDOR_SUN) &&
	    ((pxb->pxb_device_id == PXB_DEVICE_PLX_PCIX) ||
	    (pxb->pxb_device_id == PXB_DEVICE_PLX_PCIE))) {
		fic = 1;
	}
#endif	/* PX_PLX */
	if ((fic == 0) && ((PCI_CAP_LOCATE(pxb->pxb_config_handle,
	    PCI_CAP_ID_SLOT_ID, &cap_ptr)) != DDI_FAILURE)) {
		uint8_t esr = PCI_CAP_GET8(pxb->pxb_config_handle, NULL,
		    cap_ptr, PCI_CAP_ID_REGS_OFF);
		if (PCI_CAPSLOT_FIC(esr))
			fic = 1;
	}

	if ((PCI_CAP_LOCATE(pxb->pxb_config_handle,
	    PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_SER), &cap_ptr)) != DDI_FAILURE) {
		/* Serialid can be 0 thru a full 40b number */
		serialid = PCI_XCAP_GET32(pxb->pxb_config_handle, NULL,
		    cap_ptr, PCIE_SER_SID_UPPER_DW);
		serialid <<= 32;
		serialid |= PCI_XCAP_GET32(pxb->pxb_config_handle, NULL,
		    cap_ptr, PCIE_SER_SID_LOWER_DW);
	}

	if (fic)
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, pxb->pxb_dip,
		    "first-in-chassis");
	if (serialid)
		(void) ddi_prop_update_int64(DDI_DEV_T_NONE, pxb->pxb_dip,
		    "serialid#", serialid);
}

/*
 * Some PCI-X to PCI-E bridges do not support full 64-bit addressing on the
 * PCI-X side of the bridge.  We build a special version of this driver for
 * those bridges, which uses PXB_ADDR_LIMIT_LO and/or PXB_ADDR_LIMIT_HI
 * to define the range of values which the chip can handle.  The code below
 * then clamps the DMA address range supplied by the driver, preventing the
 * PCI-E nexus driver from allocating any memory the bridge can't deal
 * with.
 */
static int
pxb_dma_allochdl(dev_info_t *dip, dev_info_t *rdip,
	ddi_dma_attr_t *attr_p, int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_handle_t *handlep)
{
	int		ret;
#ifdef	BCM_SW_WORKAROUNDS
	uint64_t	lim;

	/*
	 * If the leaf device's limits are outside than what the Broadcom
	 * bridge can handle, we need to clip the values passed up the chain.
	 */
	lim = attr_p->dma_attr_addr_lo;
	attr_p->dma_attr_addr_lo = MAX(lim, PXB_ADDR_LIMIT_LO);

	lim = attr_p->dma_attr_addr_hi;
	attr_p->dma_attr_addr_hi = MIN(lim, PXB_ADDR_LIMIT_HI);

#endif	/* BCM_SW_WORKAROUNDS */

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
#ifdef	BCM_SW_WORKAROUNDS
		mp->dmai_inuse |= PX_DMAI_FLAGS_MAP_BUFZONE;
#endif	/* BCM_SW_WORKAROUNDS */
		/*
		 * For a given rdip, update mp->dmai_bdf with the bdf value
		 * of px_pci's immediate child or secondary bus-id of the
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
pxb_dma_mctl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
	enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
	uint_t cache_flags)
{
	int	ret;

#ifdef	BCM_SW_WORKAROUNDS
	if (cmd == DDI_DMA_RESERVE)
		return (DDI_FAILURE);
#endif	/* BCM_SW_WORKAROUNDS */

	if (((ret = ddi_dma_mctl(dip, rdip, handle, cmd, offp, lenp, objp,
	    cache_flags)) == DDI_SUCCESS) && (cmd == DDI_DMA_RESERVE)) {
		ddi_dma_impl_t	*mp = (ddi_dma_impl_t *)*objp;

		/*
		 * For a given rdip, update mp->dmai_bdf with the bdf value
		 * of px_pci's immediate child or secondary bus-id of the
		 * PCIe2PCI bridge.
		 */
		mp->dmai_minxfer = pcie_get_bdf_for_dma_xfer(dip, rdip);
	}

	return (ret);
}

#ifdef DEBUG
static void
pxb_dbg(uint_t bit, dev_info_t *dip, char *fmt, ...)
{
	va_list ap;

	if (!(bit & pxb_dbg_print))
		return;

	if (dip)
		prom_printf("%s(%d): %s", ddi_driver_name(dip),
		    ddi_get_instance(dip), pxb_debug_sym[bit]);
body:
	va_start(ap, fmt);
	if (ap)
		prom_vprintf(fmt, ap);
	else
		prom_printf(fmt);

	va_end(ap);
}
#endif

#ifdef PX_PLX
/*
 * Disable PLX specific relaxed ordering mode.  Due to PLX
 * erratum #6, use of this mode with Cut-Through Cancellation
 * can result in dropped Completion type packets.
 */
static void
plx_ro_disable(pxb_devstate_t *pxb)
{
	uint32_t		val;
	ddi_acc_handle_t	hdl = pxb->pxb_config_handle;

	switch (pxb->pxb_device_id) {
	case PXB_DEVICE_PLX_8533:
	case PXB_DEVICE_PLX_8548:
		/*
		 * Clear the Relaxed Ordering Mode bit of the Egress
		 * Performance Counter register on 8533 and 8548 switches.
		 */
		val = pci_config_get32(hdl, PLX_EGRESS_PERFCTR_OFFSET);
		if (val & PLX_RO_MODE_BIT) {
			val ^= PLX_RO_MODE_BIT;
			pci_config_put32(hdl, PLX_EGRESS_PERFCTR_OFFSET, val);
		}
		break;
	}
}
#endif /* PX_PLX */
