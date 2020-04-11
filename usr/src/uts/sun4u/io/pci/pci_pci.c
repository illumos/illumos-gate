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
 */

/*
 *	Sun4u PCI to PCI bus bridge nexus driver
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/pci_impl.h>
#include <sys/pcie_impl.h>
#include <sys/pci_cap.h>
#include <sys/pci/pci_nexus.h>
#include <sys/pci/pci_regs.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/ddifm.h>
#include <sys/pci/pci_pwr.h>
#include <sys/pci/pci_debug.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/file.h>

#define	NUM_LOGICAL_SLOTS	32

#define	PPB_RANGE_LEN 2

#define	PPB_32BIT_IO 1
#define	PPB_32bit_MEM 1

#define	PPB_MEMGRAIN 0x100000
#define	PPB_IOGRAIN 0x1000

#define	PPB_16bit_IOADDR(addr) ((uint16_t)(((uint8_t)(addr) & 0xF0) << 8))
#define	PPB_LADDR(lo, hi) (((uint16_t)(hi) << 16) | (uint16_t)(lo))
#define	PPB_32bit_MEMADDR(addr) (PPB_LADDR(0, ((uint16_t)(addr) & 0xFFF0)))

typedef struct	slot_table {
	uchar_t		bus_id[128];
	uchar_t		slot_name[32];
	uint8_t		device_no;
	uint8_t		phys_slot_num;
} slot_table_t;

/*
 * The variable controls the default setting of the command register
 * for pci devices.  See ppb_initchild() for details.
 */
static ushort_t ppb_command_default = PCI_COMM_SERR_ENABLE |
					PCI_COMM_WAIT_CYC_ENAB |
					PCI_COMM_PARITY_DETECT |
					PCI_COMM_ME |
					PCI_COMM_MAE |
					PCI_COMM_IO;

static int ppb_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
	off_t, off_t, caddr_t *);
static int ppb_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
	void *, void *);
static int ppb_intr_ops(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);

/*
 * fm_init busop to initialize our children
 */
static int ppb_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
		ddi_iblock_cookie_t *ibc);
static void ppb_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle);
static void ppb_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle);
static int ppb_bus_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result);

struct bus_ops ppb_bus_ops = {
	BUSO_REV,
	ppb_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	0,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	ppb_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,	/* (*bus_get_eventcookie)();    */
	ndi_busop_add_eventcall,	/* (*bus_add_eventcall)();	*/
	ndi_busop_remove_eventcall,	/* (*bus_remove_eventcall)();   */
	ndi_post_event,			/* (*bus_post_event)();		*/
	0,				/* (*bus_intr_ctl)();		*/
	0,				/* (*bus_config)();		*/
	0,				/* (*bus_unconfig)();		*/
	ppb_fm_init_child,		/* (*bus_fm_init)();		*/
	NULL,				/* (*bus_fm_fini)();		*/
	ppb_bus_enter,			/* (*bus_enter)()		*/
	ppb_bus_exit,			/* (*bus_exit)()		*/
	ppb_bus_power,			/* (*bus_power)()		*/
	ppb_intr_ops,			/* (*bus_intr_op)();		*/
	pcie_hp_common_ops		/* (*bus_hp_op)();		*/
};

static int ppb_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int ppb_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int ppb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int ppb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

static struct cb_ops ppb_cb_ops = {
	ppb_open,			/* open */
	ppb_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nulldev,			/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
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
static int ppb_info(dev_info_t *dip, ddi_info_cmd_t cmd,
    void *arg, void **result);
static int ppb_pwr(dev_info_t *dip, int component, int level);

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
	&ppb_bus_ops,		/* bus operations */
	ppb_pwr,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"Standard PCI to PCI bridge nexus driver",
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

struct ppb_cfg_state {
	dev_info_t *dip;
	ushort_t command;
	uchar_t cache_line_size;
	uchar_t latency_timer;
	uchar_t header_type;
	uchar_t sec_latency_timer;
	ushort_t bridge_control;
};

typedef struct {

	dev_info_t *dip;

	/*
	 * configuration register state for the bus:
	 */
	uchar_t ppb_cache_line_size;
	uchar_t ppb_latency_timer;

	/*
	 * PM support
	 */
	ddi_acc_handle_t	ppb_conf_hdl;
	uint16_t		ppb_pm_cap_ptr;
	pci_pwr_t		*ppb_pwr_p;

	/*
	 * HP support
	 */
	boolean_t		hotplug_capable;

	kmutex_t ppb_mutex;
	uint_t ppb_soft_state;
	int fm_cap;
	ddi_iblock_cookie_t fm_ibc;

	uint16_t parent_bus;
} ppb_devstate_t;

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

/*
 * forward function declarations:
 */

/*
 * FMA error callback
 * Register error handling callback with our parent. We will just call
 * our children's error callbacks and return their status.
 */
static int ppb_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data);

/*
 * init/fini routines to alloc/dealloc fm structures and
 * register/unregister our callback.
 */
static void ppb_fm_init(ppb_devstate_t *ppb_p);
static void ppb_fm_fini(ppb_devstate_t *ppb_p);

static void ppb_removechild(dev_info_t *);
static int ppb_initchild(dev_info_t *child);
static void ppb_uninitchild(dev_info_t *child);
static dev_info_t *get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);
static void ppb_pwr_setup(ppb_devstate_t *ppb, dev_info_t *dip);
static void ppb_pwr_teardown(ppb_devstate_t *ppb, dev_info_t *dip);
static void ppb_init_hotplug(ppb_devstate_t *ppb);
static void ppb_create_ranges_prop(dev_info_t *, ddi_acc_handle_t);
uint64_t pci_debug_flags = 0;

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
ppb_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	minor_t		minor = getminor((dev_t)arg);
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(minor);
	ppb_devstate_t	*ppb_p = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    instance);


	if (ppb_p->parent_bus != PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (pcihp_info(dip, cmd, arg, result));

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (ppb_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)ppb_p->dip;
		return (DDI_SUCCESS);
	}
}

/*ARGSUSED*/
static int
ppb_probe(register dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

/*ARGSUSED*/
static int
ppb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	dev_info_t *root = ddi_root_node();
	int instance;
	ppb_devstate_t *ppb;
	dev_info_t *pdip;
	ddi_acc_handle_t config_handle;
	char *bus;

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
		ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state, instance);
		ppb->dip = devi;
		mutex_init(&ppb->ppb_mutex, NULL, MUTEX_DRIVER, NULL);
		ppb->ppb_soft_state = PCI_SOFT_STATE_CLOSED;
		if (pci_config_setup(devi, &config_handle) != DDI_SUCCESS) {
			mutex_destroy(&ppb->ppb_mutex);
			ddi_soft_state_free(ppb_state, instance);
			return (DDI_FAILURE);
		}
		ppb_pwr_setup(ppb, devi);

		if (PM_CAPABLE(ppb->ppb_pwr_p)) {
			mutex_enter(&ppb->ppb_pwr_p->pwr_mutex);

			/*
			 * Before reading config registers, make sure power is
			 * on, and remains on.
			 */
			ppb->ppb_pwr_p->pwr_fp++;

			pci_pwr_change(ppb->ppb_pwr_p,
			    ppb->ppb_pwr_p->current_lvl,
			    pci_pwr_new_lvl(ppb->ppb_pwr_p));
		}

		ppb->ppb_cache_line_size =
		    pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		ppb->ppb_latency_timer =
		    pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);

		/*
		 * Check whether the "ranges" property is present.
		 * Otherwise create the ranges property by reading
		 * the configuration registers
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
		    "ranges") == 0) {
			ppb_create_ranges_prop(devi, config_handle);
		}

		pci_config_teardown(&config_handle);

		if (PM_CAPABLE(ppb->ppb_pwr_p)) {
			ppb->ppb_pwr_p->pwr_fp--;

			pci_pwr_change(ppb->ppb_pwr_p,
			    ppb->ppb_pwr_p->current_lvl,
			    pci_pwr_new_lvl(ppb->ppb_pwr_p));

			mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);
		}

		ppb->parent_bus = PCIE_PCIECAP_DEV_TYPE_PCI_PSEUDO;
		for (pdip = ddi_get_parent(ppb->dip); pdip && (pdip != root) &&
		    (ppb->parent_bus != PCIE_PCIECAP_DEV_TYPE_PCIE_DEV);
		    pdip = ddi_get_parent(pdip)) {
			if (ddi_prop_lookup_string(DDI_DEV_T_ANY, pdip,
			    DDI_PROP_DONTPASS, "device_type", &bus) !=
			    DDI_PROP_SUCCESS)
				break;

			if (strcmp(bus, "pciex") == 0)
				ppb->parent_bus =
				    PCIE_PCIECAP_DEV_TYPE_PCIE_DEV;

			ddi_prop_free(bus);
		}

		/*
		 * Initialize hotplug support on this bus.
		 */
		if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
			if (pcie_init(devi, NULL) != DDI_SUCCESS) {
				(void) ppb_detach(devi, DDI_DETACH);
				return (DDI_FAILURE);
			}
		else
			ppb_init_hotplug(ppb);

		DEBUG1(DBG_ATTACH, devi,
		    "ppb_attach(): this nexus %s hotplug slots\n",
		    ppb->hotplug_capable == B_TRUE ? "has":"has no");

		ppb_fm_init(ppb);
		ddi_report_dev(devi);

		return (DDI_SUCCESS);

	case DDI_RESUME:
		/*
		 * Get the soft state structure for the bridge.
		 */
		ppb = (ppb_devstate_t *)
		    ddi_get_soft_state(ppb_state, ddi_get_instance(devi));

		pci_pwr_resume(devi, ppb->ppb_pwr_p);

		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ppb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	ppb_devstate_t *ppb;
	int		ret = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH:
		/*
		 * And finally free the per-pci soft state after
		 * uninitializing hotplug support for this bus.
		 */
		ppb = (ppb_devstate_t *)
		    ddi_get_soft_state(ppb_state, ddi_get_instance(devi));

		ppb_fm_fini(ppb);

		if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
			ret = pcie_uninit(devi);
		else if (ppb->hotplug_capable == B_TRUE)
			ret = pcihp_init(devi);
		else
			ddi_remove_minor_node(devi, "devctl");

		if (ret != DDI_SUCCESS)
			return (DDI_FAILURE);

		(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");

		if (ppb->ppb_pwr_p != NULL) {
			ppb_pwr_teardown(ppb, devi);
		}
		mutex_destroy(&ppb->ppb_mutex);
		ddi_soft_state_free(ppb_state, ddi_get_instance(devi));

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		ppb = (ppb_devstate_t *)
		    ddi_get_soft_state(ppb_state, ddi_get_instance(devi));

		pci_pwr_suspend(devi, ppb->ppb_pwr_p);

		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ppb_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	register dev_info_t *pdip;

	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
	    (pdip, rdip, mp, offset, len, vaddrp));
}

/*ARGSUSED*/
static int
ppb_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	int	reglen;
	int	rn;
	struct	attachspec *as;
	struct	detachspec *ds;
	int	totreg;
	ppb_devstate_t *ppb_p;

	ppb_p = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
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
		return (ppb_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		ppb_uninitchild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_ATTACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		as = (struct attachspec *)arg;
		if ((ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) &&
		    (as->when == DDI_POST) && (as->result == DDI_SUCCESS))
			pf_init(rdip, ppb_p->fm_ibc, as->cmd);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_DETACH:
		if (!pcie_is_child(dip, rdip))
			return (DDI_SUCCESS);

		ds = (struct detachspec *)arg;
		if ((ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) &&
		    (ds->when == DDI_PRE))
			pf_fini(rdip, ds->cmd);

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
		*(off_t *)result = drv_regp[rn].pci_size_low |
		    ((uint64_t)drv_regp[rn].pci_size_hi << 32);
	}

	kmem_free(drv_regp, reglen);
	return (DDI_SUCCESS);
}


static dev_info_t *
get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}


static int
ppb_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
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

	cdip = get_my_childs_dip(dip, rdip);

	/*
	 * Use the devices reg property to determine its
	 * PCI bus number and device number.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&pci_rp, &reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	intr = hdlp->ih_vector;

	/* Spin the interrupt */
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

static int
ppb_bus_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	ppb_devstate_t *ppb;

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));

	return (pci_pwr_ops(ppb->ppb_pwr_p, dip, impl_arg, op, arg, result));
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
ppb_name_child(dev_info_t *child, char *name, int namelen)
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
ppb_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;
	uint_t n;
	ushort_t bcr;
	uchar_t header_type;
	uchar_t min_gnt, latency_timer;
	ppb_devstate_t *ppb;

	/*
	 * Name the child
	 */
	if (ppb_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
		return (DDI_FAILURE);

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
		if (ndi_merge_node(child, ppb_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ppb_removechild(child);
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
		ppb_removechild(child);
		return (DDI_NOT_WELL_FORMED);
	}

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(ddi_get_parent(child)));

	ddi_set_parent_data(child, NULL);

	/*
	 * If hardware is PM capable, set up the power info structure.
	 * This also ensures the the bus will not be off (0MHz) otherwise
	 * system panics during a bus access.
	 */
	if (PM_CAPABLE(ppb->ppb_pwr_p)) {
		/*
		 * Create a pwr_info struct for child.  Bus will be
		 * at full speed after creating info.
		 */
		pci_pwr_create_info(ppb->ppb_pwr_p, child);
#ifdef DEBUG
		ASSERT(ppb->ppb_pwr_p->current_lvl == PM_LEVEL_B0);
#endif
	}

	/*
	 * If configuration registers were previously saved by
	 * child (before it entered D3), then let the child do the
	 * restore to set up the config regs as it'll first need to
	 * power the device out of D3.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "config-regs-saved-by-child") == 1) {
		DEBUG2(DBG_PWR, ddi_get_parent(child),
		    "INITCHILD: config regs to be restored by child"
		    " for %s@%s\n", ddi_node_name(child),
		    ddi_get_name_addr(child));

		return (DDI_SUCCESS);
	}

	DEBUG2(DBG_PWR, ddi_get_parent(child),
	    "INITCHILD: config regs setup for %s@%s\n",
	    ddi_node_name(child), ddi_get_name_addr(child));

	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS) {
		if (PM_CAPABLE(ppb->ppb_pwr_p)) {
			pci_pwr_rm_info(ppb->ppb_pwr_p, child);
		}

		return (DDI_FAILURE);
	}

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);

	/*
	 * Support for the "command-preserve" property.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (ppb_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type  & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (ppb_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (ppb_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	/*
	 * Initialize cache-line-size configuration register if needed.
	 */
	if (ppb_set_cache_line_size_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {
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

	/*
	 * SPARC PCIe FMA specific
	 *
	 * Note: parent_data for parent is created only if this is sparc PCI-E
	 * platform, for which, SG take a different route to handle device
	 * errors.
	 */
	if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		if (pcie_init_cfghdl(child) != DDI_SUCCESS) {
			pci_config_teardown(&config_handle);
			return (DDI_FAILURE);
		}
		pcie_init_dom(child);
	}

	/*
	 * Check to see if the XMITS/PCI-X workaround applies.
	 */
	n = ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_NOTPROM,
	    "pcix-update-cmd-reg", -1);

	if (n != -1) {
		extern void pcix_set_cmd_reg(dev_info_t *child, uint16_t value);
		DEBUG1(DBG_INIT_CLD, child, "Turning on XMITS NCPQ "
		    "Workaround: value = %x\n", n);
		pcix_set_cmd_reg(child, n);
	}
	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

static void
ppb_uninitchild(dev_info_t *child)
{
	ppb_devstate_t *ppb;

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(ddi_get_parent(child)));

	/*
	 * SG OPL FMA specific
	 */
	if (ppb->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		pcie_fini_dom(child);
		pcie_fini_cfghdl(child);
	}

	ppb_removechild(child);
}

static void
ppb_removechild(dev_info_t *dip)
{
	ppb_devstate_t *ppb;

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(ddi_get_parent(dip)));

	if (PM_CAPABLE(ppb->ppb_pwr_p)) {

		DEBUG2(DBG_PWR, ddi_get_parent(dip),
		    "UNINITCHILD: removing pwr_info for %s@%s\n",
		    ddi_node_name(dip), ddi_get_name_addr(dip));
		pci_pwr_rm_info(ppb->ppb_pwr_p, dip);
	}

	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	impl_rem_dev_props(dip);
}

/*
 * If bridge is PM capable, set up PM state for nexus.
 */
static void
ppb_pwr_setup(ppb_devstate_t *ppb, dev_info_t *pdip)
{
	char *comp_array[5];
	int i;
	ddi_acc_handle_t conf_hdl;
	uint8_t pmcsr_bse;
	uint16_t pmcap;

	/*
	 * Determine if bridge is PM capable.  If not, leave ppb_pwr_p NULL
	 * and return.
	 */
	if (pci_config_setup(pdip, &ppb->ppb_conf_hdl) != DDI_SUCCESS) {

		return;
	}

	conf_hdl = ppb->ppb_conf_hdl;

	/*
	 * Locate and store the power management cap_ptr for future references.
	 */
	if ((PCI_CAP_LOCATE(conf_hdl, PCI_CAP_ID_PM, &ppb->ppb_pm_cap_ptr))
	    == DDI_FAILURE) {
		DEBUG0(DBG_PWR, pdip, "bridge does not support PM. PCI"
		    " PM data structure not found in config header\n");
		pci_config_teardown(&conf_hdl);

		return;
	}

	/*
	 * Allocate PM state structure for ppb.
	 */
	ppb->ppb_pwr_p = (pci_pwr_t *)
	    kmem_zalloc(sizeof (pci_pwr_t), KM_SLEEP);
	ppb->ppb_pwr_p->pwr_fp = 0;

	pmcsr_bse = PCI_CAP_GET8(conf_hdl, 0, ppb->ppb_pm_cap_ptr,
	    PCI_PMCSR_BSE);

	pmcap = PCI_CAP_GET16(conf_hdl, 0, ppb->ppb_pm_cap_ptr,
	    PCI_PMCAP);

	if (pmcap == PCI_CAP_EINVAL16 || pmcsr_bse == PCI_CAP_EINVAL8) {
		pci_config_teardown(&conf_hdl);
		return;
	}

	if (pmcap & PCI_PMCAP_D1) {
		DEBUG0(DBG_PWR, pdip, "setup: B1 state supported\n");
		ppb->ppb_pwr_p->pwr_flags |= PCI_PWR_B1_CAPABLE;
	} else {
		DEBUG0(DBG_PWR, pdip, "setup: B1 state NOT supported\n");
	}
	if (pmcap & PCI_PMCAP_D2) {
		DEBUG0(DBG_PWR, pdip, "setup: B2 state supported\n");
		ppb->ppb_pwr_p->pwr_flags |= PCI_PWR_B2_CAPABLE;
	} else {
		DEBUG0(DBG_PWR, pdip, "setup: B2 via D2 NOT supported\n");
	}

	if (pmcsr_bse & PCI_PMCSR_BSE_BPCC_EN) {
		DEBUG0(DBG_PWR, pdip,
		"setup: bridge power/clock control enable\n");
	} else {
		DEBUG0(DBG_PWR, pdip,
		"setup: bridge power/clock control disabled\n");

		kmem_free(ppb->ppb_pwr_p, sizeof (pci_pwr_t));
		ppb->ppb_pwr_p = NULL;
		pci_config_teardown(&conf_hdl);

		return;
	}

	/*
	 * PCI states D0 and D3 always are supported for normal PCI
	 * devices.  D1 and D2 are optional which are checked for above.
	 * Bridge function states D0-D3 correspond to secondary bus states
	 * B0-B3, EXCEPT if PCI_PMCSR_BSE_B2_B3 is set.  In this case, setting
	 * the bridge function to D3 will set the bridge bus to state B2 instead
	 * of B3.  D2 will not correspond to B2 (and in fact, probably
	 * won't be D2 capable).  Implicitly, this means that if
	 * PCI_PMCSR_BSE_B2_B3 is set, the bus will not be B3 capable.
	 */
	if (pmcsr_bse & PCI_PMCSR_BSE_B2_B3) {
		ppb->ppb_pwr_p->pwr_flags |= PCI_PWR_B2_CAPABLE;
		DEBUG0(DBG_PWR, pdip, "B2 supported via D3\n");
	} else {
		ppb->ppb_pwr_p->pwr_flags |= PCI_PWR_B3_CAPABLE;
		DEBUG0(DBG_PWR, pdip, "B3 supported via D3\n");
	}

	ppb->ppb_pwr_p->pwr_dip = pdip;
	mutex_init(&ppb->ppb_pwr_p->pwr_mutex, NULL, MUTEX_DRIVER, NULL);

	i = 0;
	comp_array[i++] = "NAME=PCI bridge PM";
	if (ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B3_CAPABLE) {
		comp_array[i++] = "0=Clock/Power Off (B3)";
	}
	if (ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B2_CAPABLE) {
		comp_array[i++] = "1=Clock Off (B2)";
	}
	if (ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B1_CAPABLE) {
		comp_array[i++] = "2=Bus Inactive (B1)";
	}
	comp_array[i++] = "3=Full Power (B0)";

	/*
	 * Create pm-components property. It does not already exist.
	 */
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, pdip,
	    "pm-components", comp_array, i) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d pm-components prop update failed",
		    ddi_driver_name(pdip), ddi_get_instance(pdip));
		pci_config_teardown(&conf_hdl);
		mutex_destroy(&ppb->ppb_pwr_p->pwr_mutex);
		kmem_free(ppb->ppb_pwr_p, sizeof (pci_pwr_t));
		ppb->ppb_pwr_p = NULL;

		return;
	}

	if (ddi_prop_create(DDI_DEV_T_NONE, pdip, DDI_PROP_CANSLEEP,
	    "pm-want-child-notification?", NULL, 0) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d fail to create pm-want-child-notification? prop",
		    ddi_driver_name(pdip), ddi_get_instance(pdip));

		(void) ddi_prop_remove(DDI_DEV_T_NONE, pdip, "pm-components");
		pci_config_teardown(&conf_hdl);
		mutex_destroy(&ppb->ppb_pwr_p->pwr_mutex);
		kmem_free(ppb->ppb_pwr_p, sizeof (pci_pwr_t));
		ppb->ppb_pwr_p = NULL;

		return;
	}

	ppb->ppb_pwr_p->current_lvl =
	    pci_pwr_current_lvl(ppb->ppb_pwr_p);
}

/*
 * Remove PM state for nexus.
 */
static void
ppb_pwr_teardown(ppb_devstate_t *ppb, dev_info_t *dip)
{
	int low_lvl;

	/*
	 * Determine the lowest power level supported.
	 */
	if (ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B3_CAPABLE) {
		low_lvl = PM_LEVEL_B3;
	} else {
		low_lvl = PM_LEVEL_B2;
	}

	if (pm_lower_power(dip, PCI_PM_COMP_0, low_lvl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d failed to lower power",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}

	pci_config_teardown(&ppb->ppb_conf_hdl);
	mutex_destroy(&ppb->ppb_pwr_p->pwr_mutex);
	kmem_free(ppb->ppb_pwr_p, sizeof (pci_pwr_t));

	if (ddi_prop_remove(DDI_DEV_T_NONE, dip, "pm-components") !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d unable to remove prop pm-components",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}

	if (ddi_prop_remove(DDI_DEV_T_NONE, dip,
	    "pm-want-child-notification?") != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d unable to remove prop pm-want_child_notification?",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}
}

/*
 * Examine the pmcsr register and return the software defined
 * state (the difference being whether D3 means B2 or B3).
 */
int
pci_pwr_current_lvl(pci_pwr_t *pwr_p)
{
	ppb_devstate_t *ppb;
	uint16_t pmcsr;

	/*
	 * Find out current power level
	 */
	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(pwr_p->pwr_dip));

	if ((pmcsr = PCI_CAP_GET16(ppb->ppb_conf_hdl, 0,
	    ppb->ppb_pm_cap_ptr, PCI_PMCSR)) == PCI_CAP_EINVAL16)
		return (DDI_FAILURE);

	switch (pmcsr & PCI_PMCSR_STATE_MASK) {
	case PCI_PMCSR_D0:

		return (PM_LEVEL_B0);
	case PCI_PMCSR_D1:

		return (PM_LEVEL_B1);
	case PCI_PMCSR_D2:

		return (PM_LEVEL_B2);
	case PCI_PMCSR_D3HOT:
		if ((ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B3_CAPABLE) == 0) {

			return (PM_LEVEL_B2);
		} else {

			return (PM_LEVEL_B3);
		}
	}
	/*NOTREACHED*/
	return (PM_LEVEL_B3);
}

/*
 * Power entry point.  Called by the PM framework to change the
 * current power state of the bus.  This function must first verify that
 * the requested power change is still valid.
 */
/*ARGSUSED*/
static int
ppb_pwr(dev_info_t *dip, int component, int lvl)
{
	ppb_devstate_t *ppb;
	uint16_t pmcsr;
	char *str;
	int lowest_lvl;
	int old_lvl;
	int new_lvl;

	ppb = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));
	if (ppb == NULL) {
		cmn_err(CE_WARN, "%s%d ppb_pwr: can't get soft state",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (DDI_FAILURE);
	}

	DEBUG1(DBG_PWR, dip, "ppb_pwr(): ENTER level = %d\n", lvl);

	mutex_enter(&ppb->ppb_pwr_p->pwr_mutex);

	/*
	 * Find out if the power setting is possible.  If it is not,
	 * set component busy and return failure.  If it is possible,
	 * and it is the lowest pwr setting possible, set component
	 * busy so that the framework does not try to lower any further.
	 */
	lowest_lvl = pci_pwr_new_lvl(ppb->ppb_pwr_p);
	if (lowest_lvl > lvl) {
		pci_pwr_component_busy(ppb->ppb_pwr_p);
		DEBUG2(DBG_PWR, dip, "ppb_pwr: failing power request "
		    "lowest allowed is %d requested is %d\n",
		    lowest_lvl, lvl);
		mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);

		return (DDI_FAILURE);
	} else if (lowest_lvl == lvl) {
		pci_pwr_component_busy(ppb->ppb_pwr_p);
	} else {
		pci_pwr_component_idle(ppb->ppb_pwr_p);
	}

	if ((pmcsr = PCI_CAP_GET16(ppb->ppb_conf_hdl, 0,
	    ppb->ppb_pm_cap_ptr, PCI_PMCSR)) == PCI_CAP_EINVAL16)
		return (DDI_FAILURE);

	/*
	 * Save the current power level.  This is the actual function level,
	 * not the translated bridge level stored in pwr_p->current_lvl
	 */
	old_lvl = pmcsr & PCI_PMCSR_STATE_MASK;

	pmcsr &= ~PCI_PMCSR_STATE_MASK;
	switch (lvl) {
	case PM_LEVEL_B0:
		str = "PM_LEVEL_B0 (full speed)";
		pmcsr |= PCI_PMCSR_D0;
		break;
	case PM_LEVEL_B1:
		str = "PM_LEVEL_B1 (light sleep. No bus traffic allowed)";
		if ((ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B1_CAPABLE) == 0) {
			cmn_err(CE_WARN, "%s%d PCI PM state B1 not supported",
			    ddi_driver_name(dip), ddi_get_instance(dip));

			mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);
			return (DDI_FAILURE);
		}
		pmcsr |= PCI_PMCSR_D1;
		break;
	case PM_LEVEL_B2:
		str = "PM_LEVEL_B2 (clock off)";
		if ((ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B2_CAPABLE) == 0) {
			cmn_err(CE_WARN, "%s%d PM state B2 not supported...",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);

			return (DDI_FAILURE);
		}

		if ((ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B3_CAPABLE) == 0) {
			/*
			 * If B3 isn't supported, use D3 for B2 to avoid the
			 * possible case that D2 for B2 isn't supported.
			 * Saves and extra check and state flag..
			 */
			pmcsr |= PCI_PMCSR_D3HOT;
		} else {
			pmcsr |= PCI_PMCSR_D2;
		}
		break;
	case PM_LEVEL_B3:
		str = "PM_LEVEL_B30 (clock and power off)";
		if ((ppb->ppb_pwr_p->pwr_flags & PCI_PWR_B3_CAPABLE) == 0) {
			cmn_err(CE_WARN, "%s%d PM state B3 not supported...",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);

			return (DDI_FAILURE);
		}
		pmcsr |= PCI_PMCSR_D3HOT;

		break;

	default:
		cmn_err(CE_WARN, "%s%d Unknown PM state %d",
		    ddi_driver_name(dip), ddi_get_instance(dip), lvl);
		mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);

		return (DDI_FAILURE);
	}

	new_lvl = pmcsr & PCI_PMCSR_STATE_MASK;

	/*
	 * Save config regs if going into HW state D3 (B2 or B3)
	 */
	if ((old_lvl != PCI_PMCSR_D3HOT) && (new_lvl == PCI_PMCSR_D3HOT)) {
		DEBUG0(DBG_PWR, dip, "ppb_pwr(): SAVING CONFIG REGS\n");
		if (pci_save_config_regs(dip) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d Save config regs failed",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);

			return (DDI_FAILURE);
		}
	}

	PCI_CAP_PUT16(ppb->ppb_conf_hdl, 0, ppb->ppb_pm_cap_ptr, PCI_PMCSR,
	    pmcsr);

	/*
	 * No bus transactions should occur without waiting for
	 * settle time specified in PCI PM spec rev 2.1 sec 5.6.1
	 * To make things simple, just use the max time specified for
	 * all state transitions.
	 */
	delay(drv_usectohz(PCI_CLK_SETTLE_TIME));

	/*
	 * Restore configuration registers if coming out of HW state D3
	 */
	if ((old_lvl == PCI_PMCSR_D3HOT) && (new_lvl != PCI_PMCSR_D3HOT)) {
		DEBUG0(DBG_PWR, dip, "ppb_pwr(): RESTORING CONFIG REGS\n");
		if (pci_restore_config_regs(dip) != DDI_SUCCESS) {
			panic("%s%d restore config regs failed",
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
		/*NOTREACHED*/
	}

	ppb->ppb_pwr_p->current_lvl = lvl;

	mutex_exit(&ppb->ppb_pwr_p->pwr_mutex);

	DEBUG1(DBG_PWR, dip, "ppb_set_pwr: set PM state to %s\n\n", str);

	return (DDI_SUCCESS);
}

/*
 * Initialize hotplug framework if we are hotpluggable.
 * Sets flag in the soft state if Hot Plug is supported and initialized
 * properly.
 */
/*ARGSUSED*/
static void
ppb_init_hotplug(ppb_devstate_t *ppb)
{
	ppb->hotplug_capable = B_FALSE;

	if (ddi_prop_exists(DDI_DEV_T_ANY, ppb->dip, DDI_PROP_DONTPASS,
	    "hotplug-capable")) {
		(void) modload("misc", "pcihp");

		if (pcihp_init(ppb->dip) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s #%d: Failed setting hotplug framework",
			    ddi_driver_name(ppb->dip),
			    ddi_get_instance(ppb->dip));
		} else
			ppb->hotplug_capable = B_TRUE;
	}

	if (ppb->hotplug_capable == B_FALSE) {
		/*
		 * create minor node for devctl interfaces
		 */
		if (ddi_create_minor_node(ppb->dip, "devctl", S_IFCHR,
		    PCI_MINOR_NUM(ddi_get_instance(ppb->dip), PCI_DEVCTL_MINOR),
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "%s #%d: Failed to create a minor node",
			    ddi_driver_name(ppb->dip),
			    ddi_get_instance(ppb->dip));
	}
}

static void
ppb_create_ranges_prop(dev_info_t *dip,
    ddi_acc_handle_t config_handle)
{
	uint32_t base, limit;
	ppb_ranges_t	ranges[PPB_RANGE_LEN];
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
	ranges[i].parent_mid = ranges[i].child_mid =
	    ranges[i].parent_high = 0;
	ranges[i].child_high = ranges[i].parent_high |=
	    (PCI_REG_REL_M | PCI_ADDR_IO);
	base = PPB_16bit_IOADDR(io_base_lo);
	limit = PPB_16bit_IOADDR(io_limit_lo);

	/*
	 * Check for 32-bit I/O support as per PCI-to-PCI Bridge Arch Spec
	 */
	if ((io_base_lo & 0xf) == PPB_32BIT_IO) {
		base = PPB_LADDR(base, io_base_hi);
		limit = PPB_LADDR(limit, io_limit_hi);
	}

	/*
	 * Check if the bridge implements an I/O address range as per
	 * PCI-to-PCI Bridge Arch Spec
	 */
	if ((io_base_lo != 0 || io_limit_lo != 0) && limit >= base) {
		ranges[i].parent_low = ranges[i].child_low =
		    base;
		ranges[i].size_low = limit - base + PPB_IOGRAIN;
		i++;
	}

	/*
	 * Create ranges for 32bit memory space
	 */
	base = PPB_32bit_MEMADDR(mem_base);
	limit = PPB_32bit_MEMADDR(mem_limit);
	ranges[i].size_low = ranges[i].size_high = 0;
	ranges[i].parent_mid = ranges[i].child_mid =
	    ranges[i].parent_high = 0;
	ranges[i].child_high = ranges[i].parent_high |=
	    (PCI_REG_REL_M | PCI_ADDR_MEM32);
	ranges[i].child_low = ranges[i].parent_low = base;
	if (limit >= base) {
		ranges[i].size_low = limit - base + PPB_MEMGRAIN;
		i++;
	}

	if (i) {
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "ranges",
		    (int *)ranges, i * rangelen);
	}
}

/* ARGSUSED */
static int
ppb_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(*devp));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (ppb_p == NULL)
		return (ENXIO);

	mutex_enter(&ppb_p->ppb_mutex);

	/*
	 * Ioctls will be handled by SPARC PCI Express framework for all
	 * PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		int	rv;

		rv = pcie_open(ppb_p->dip, devp, flags, otyp, credp);
		mutex_exit(&ppb_p->ppb_mutex);

		return (rv);
	} else if (ppb_p->hotplug_capable == B_TRUE) {
		mutex_exit(&ppb_p->ppb_mutex);

		return ((pcihp_get_cb_ops())->cb_open(devp, flags, otyp,
		    credp));
	}

	/*
	 * Handle the open by tracking the device state.
	 */
	if (flags & FEXCL) {
		if (ppb_p->ppb_soft_state != PCI_SOFT_STATE_CLOSED) {
			mutex_exit(&ppb_p->ppb_mutex);
			return (EBUSY);
		}
		ppb_p->ppb_soft_state = PCI_SOFT_STATE_OPEN_EXCL;
	} else {
		if (ppb_p->ppb_soft_state == PCI_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&ppb_p->ppb_mutex);
			return (EBUSY);
		}
		ppb_p->ppb_soft_state = PCI_SOFT_STATE_OPEN;
	}
	mutex_exit(&ppb_p->ppb_mutex);
	return (0);
}


/* ARGSUSED */
static int
ppb_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (ppb_p == NULL)
		return (ENXIO);

	mutex_enter(&ppb_p->ppb_mutex);
	/*
	 * Ioctls will be handled by SPARC PCI Express framework for all
	 * PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV) {
		int	rv;

		rv = pcie_close(ppb_p->dip, dev, flags, otyp, credp);
		mutex_exit(&ppb_p->ppb_mutex);

		return (rv);
	} else if (ppb_p->hotplug_capable == B_TRUE) {
		mutex_exit(&ppb_p->ppb_mutex);
		return ((pcihp_get_cb_ops())->cb_close(dev, flags, otyp,
		    credp));
	}

	ppb_p->ppb_soft_state = PCI_SOFT_STATE_CLOSED;
	mutex_exit(&ppb_p->ppb_mutex);
	return (0);
}


/*
 * ppb_ioctl: devctl hotplug controls
 */
/* ARGSUSED */
static int
ppb_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	ppb_devstate_t	*ppb_p = ddi_get_soft_state(ppb_state, instance);
	struct devctl_iocdata *dcp;
	uint_t		bus_state;
	dev_info_t	*self;
	int		rv = 0;

	if (ppb_p == NULL)
		return (ENXIO);

	/*
	 * Ioctls will be handled by SPARC PCI Express framework for all
	 * PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (pcie_ioctl(ppb_p->dip, dev, cmd, arg, mode, credp,
		    rvalp));
	else if (ppb_p->hotplug_capable == B_TRUE)
		return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode,
		    credp, rvalp));

	self = ppb_p->dip;

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

static int
ppb_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int		instance = PCI_MINOR_NUM_TO_INSTANCE(getminor(dev));
	ppb_devstate_t	*ppb_p = (ppb_devstate_t *)
	    ddi_get_soft_state(ppb_state, instance);

	if (ppb_p == NULL)
		return (ENXIO);

	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (pcie_prop_op(dev, dip, prop_op, flags, name,
		    valuep, lengthp));

	return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

/*
 * Initialize our FMA resources
 */
static void
ppb_fm_init(ppb_devstate_t *ppb_p)
{
	ppb_p->fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Request our capability level and get our parents capability
	 * and ibc.
	 */
	ddi_fm_init(ppb_p->dip, &ppb_p->fm_cap, &ppb_p->fm_ibc);
	ASSERT((ppb_p->fm_cap & DDI_FM_EREPORT_CAPABLE) &&
	    (ppb_p->fm_cap & DDI_FM_ERRCB_CAPABLE));

	pci_ereport_setup(ppb_p->dip);

	/*
	 * Register error callback with our parent.
	 */
	ddi_fm_handler_register(ppb_p->dip, ppb_err_callback, NULL);
}

/*
 * Breakdown our FMA resources
 */
static void
ppb_fm_fini(ppb_devstate_t *ppb_p)
{
	/*
	 * Clean up allocated fm structures
	 */
	ddi_fm_handler_unregister(ppb_p->dip);
	pci_ereport_teardown(ppb_p->dip);
	ddi_fm_fini(ppb_p->dip);
}

/*
 * Initialize FMA resources for children devices. Called when
 * child calls ddi_fm_init().
 */
/*ARGSUSED*/
static int
ppb_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	ppb_devstate_t *ppb_p = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));
	*ibc = ppb_p->fm_ibc;
	return (ppb_p->fm_cap);
}

/*
 * FMA registered error callback
 */
static int
ppb_err_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	ppb_devstate_t *ppb_p = (ppb_devstate_t *)ddi_get_soft_state(ppb_state,
	    ddi_get_instance(dip));

	/*
	 * errors handled by SPARC PCI-E framework for PCIe platforms
	 */
	if (ppb_p->parent_bus == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV)
		return (DDI_FM_OK);

	/*
	 * do the following for SPARC PCI platforms
	 */
	ASSERT(impl_data == NULL);
	pci_ereport_post(dip, derr, NULL);
	return (derr->fme_status);
}

static void
ppb_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle)
{
	i_ndi_busop_access_enter(dip, handle);
}

/* ARGSUSED */
static void
ppb_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle)
{
	i_ndi_busop_access_exit(dip, handle);
}
