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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */


/*
 *	PCI to PCI bus bridge nexus driver
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/ddifm.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/pci.h>
#include <sys/pci/pci_nexus.h>
#include <sys/pci/pci_regs.h>
#include <sys/pci/pci_simba.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/promif.h>		/* prom_printf */
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/file.h>

#if defined(DEBUG) && !defined(lint)
static uint_t simba_debug_flags = 0;
#define	D_IDENTIFY	0x00000001
#define	D_ATTACH	0x00000002
#define	D_DETACH	0x00000004
#define	D_MAP		0x00000008
#define	D_CTLOPS	0x00000010
#define	D_G_ISPEC	0x00000020
#define	D_A_ISPEC	0x00000040
#define	D_INIT_CLD	0x00400000
#define	D_FAULT		0x00000080

#define	DEBUG0(f, s) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n")

#define	DEBUG1(f, s, a) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n", a)

#define	DEBUG2(f, s, a, b) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n", a, b)

#define	DEBUG3(f, s, a, b, c) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n", a, b, c)

#define	DEBUG4(f, s, a, b, c, d) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n", a, b, c, d)

#define	DEBUG5(f, s, a, b, c, d, e) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n", a, b, c, d, e)

#define	DEBUG6(f, s, a, b, c, d, e, ff) if ((f)& simba_debug_flags) \
	prom_printf("simba: " s "\n", a, b, c, d, e, ff)

#else

#define	DEBUG0(f, s)
#define	DEBUG1(f, s, a)
#define	DEBUG2(f, s, a, b)
#define	DEBUG3(f, s, a, b, c)
#define	DEBUG4(f, s, a, b, c, d)
#define	DEBUG5(f, s, a, b, c, d, e)
#define	DEBUG6(f, s, a, b, c, d, e, ff)

#endif

/*
 * The variable controls the default setting of the command register
 * for pci devices.  See simba_initchild() for details.
 */
static ushort_t simba_command_default = PCI_COMM_SERR_ENABLE |
					PCI_COMM_WAIT_CYC_ENAB |
					PCI_COMM_PARITY_DETECT |
					PCI_COMM_ME |
					PCI_COMM_MAE |
					PCI_COMM_IO;

static int simba_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
	off_t, off_t, caddr_t *);
static int simba_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
	void *, void *);
static int simba_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
		ddi_iblock_cookie_t *ibc);
static void simba_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle);
static void simba_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle);

struct bus_ops simba_bus_ops = {
	BUSO_REV,
	simba_bus_map,
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
	simba_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,
	ndi_busop_add_eventcall,
	ndi_busop_remove_eventcall,
	ndi_post_event,
	0,
	0,
	0,
	simba_fm_init_child,
	NULL,
	simba_bus_enter,
	simba_bus_exit,
	0,
	i_ddi_intr_ops
};

static int simba_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int simba_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int simba_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);

static struct cb_ops simba_cb_ops = {
	simba_open,			/* open */
	simba_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nulldev,			/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	simba_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static int simba_probe(dev_info_t *);
static int simba_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int simba_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
static int simba_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result);

struct dev_ops simba_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	simba_info,		/* info */
	nulldev,		/* identify */
	simba_probe,		/* probe */
	simba_attach,		/* attach */
	simba_detach,		/* detach */
	nulldev,		/* reset */
	&simba_cb_ops,		/* driver operations */
	&simba_bus_ops,		/* bus operations */
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"SIMBA PCI to PCI bridge nexus driver",
	&simba_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * Simba specific error state structure
 */
struct simba_errstate {
	char *error;
	ushort_t pci_cfg_stat;
	ushort_t pci_cfg_sec_stat;
	uint64_t afsr;
	uint64_t afar;
	int bridge_secondary;
};

struct simba_cfg_state {
	dev_info_t *dip;
	ushort_t command;
	uchar_t cache_line_size;
	uchar_t latency_timer;
	uchar_t header_type;
	uchar_t bus_number;
	uchar_t sec_bus_number;
	uchar_t sub_bus_number;
	uchar_t sec_latency_timer;
	ushort_t bridge_control;
};

/*
 * soft state pointer and structure template:
 */
static void *simba_state;

typedef struct {

	dev_info_t *dip;

	/*
	 * configuration register state for the bus:
	 */
	ddi_acc_handle_t config_handle;
	uchar_t simba_cache_line_size;
	uchar_t simba_latency_timer;

	/*
	 * cpr support:
	 */
	uint_t config_state_index;
	struct simba_cfg_state *simba_config_state_p;
	ddi_iblock_cookie_t fm_ibc;
	int fm_cap;
	kmutex_t simba_mutex;
	uint_t simba_soft_state;
#define	SIMBA_SOFT_STATE_CLOSED		0x00
#define	SIMBA_SOFT_STATE_OPEN		0x01
#define	SIMBA_SOFT_STATE_OPEN_EXCL	0x02
} simba_devstate_t;

/*
 * The following variable enables a workaround for the following obp bug:
 *
 *	1234181 - obp should set latency timer registers in pci
 *		configuration header
 *
 * Until this bug gets fixed in the obp, the following workaround should
 * be enabled.
 */
static uint_t simba_set_latency_timer_register = 1;

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
static uint_t simba_set_cache_line_size_register = 1;


/*
 * forward function declarations:
 */
static void simba_uninitchild(dev_info_t *);
static int simba_initchild(dev_info_t *child);
static void simba_save_config_regs(simba_devstate_t *simba_p);
static void simba_restore_config_regs(simba_devstate_t *simba_p);
static int simba_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data);

int
_init(void)
{
	int e;

	DEBUG0(D_ATTACH, "_init() installing module...\n");
	if ((e = ddi_soft_state_init(&simba_state, sizeof (simba_devstate_t),
	    1)) == 0 && (e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&simba_state);

	DEBUG0(D_ATTACH, "_init() module installed\n");
	return (e);
}

int
_fini(void)
{
	int e;
	DEBUG0(D_ATTACH, "_fini() removing module...\n");
	if ((e = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&simba_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	DEBUG0(D_ATTACH, "_info() called.\n");
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
simba_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	simba_devstate_t *simba_p;	/* per simba state pointer */
	int instance;

	instance = getminor((dev_t)arg);
	simba_p = (simba_devstate_t *)ddi_get_soft_state(simba_state,
	    instance);

	switch (infocmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (simba_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)simba_p->dip;
		return (DDI_SUCCESS);
	}
}

/*ARGSUSED*/
static int
simba_probe(register dev_info_t *devi)
{
	DEBUG0(D_ATTACH, "simba_probe() called.\n");
	return (DDI_PROBE_SUCCESS);
}

/*ARGSUSED*/
static int
simba_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	simba_devstate_t *simba;

	switch (cmd) {
	case DDI_ATTACH:

		DEBUG1(D_ATTACH, "attach(%p) ATTACH\n", devi);

		/*
		 * Make sure the "device_type" property exists.
		 */
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
		    "device_type", "pci");

		/*
		 * Allocate and get soft state structure.
		 */
		instance = ddi_get_instance(devi);
		if (ddi_soft_state_zalloc(simba_state, instance) != DDI_SUCCESS)
			return (DDI_FAILURE);
		simba = (simba_devstate_t *)ddi_get_soft_state(simba_state,
		    instance);
		simba->dip = devi;
		mutex_init(&simba->simba_mutex, NULL, MUTEX_DRIVER, NULL);
		simba->simba_soft_state = SIMBA_SOFT_STATE_CLOSED;

		/*
		 * create minor node for devctl interfaces
		 */
		if (ddi_create_minor_node(devi, "devctl", S_IFCHR, instance,
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
			mutex_destroy(&simba->simba_mutex);
			ddi_soft_state_free(simba_state, instance);
			return (DDI_FAILURE);
		}

		if (pci_config_setup(devi, &simba->config_handle) !=
		    DDI_SUCCESS) {
			ddi_remove_minor_node(devi, "devctl");
			mutex_destroy(&simba->simba_mutex);
			ddi_soft_state_free(simba_state, instance);
			return (DDI_FAILURE);
		}

		/*
		 * Simba cache line size is 64 bytes and hardwired.
		 */
		simba->simba_cache_line_size =
		    pci_config_get8(simba->config_handle,
		    PCI_CONF_CACHE_LINESZ);
		simba->simba_latency_timer =
		    pci_config_get8(simba->config_handle,
		    PCI_CONF_LATENCY_TIMER);

		/* simba specific, clears up the pri/sec status registers */
		pci_config_put16(simba->config_handle, 0x6, 0xffff);
		pci_config_put16(simba->config_handle, 0x1e, 0xffff);

		DEBUG2(D_ATTACH, "simba_attach(): clsz=%x, lt=%x\n",
		    simba->simba_cache_line_size,
		    simba->simba_latency_timer);

		/*
		 * Initialize FMA support
		 */
		simba->fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
		    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

		/*
		 * Call parent to get it's capablity
		 */
		ddi_fm_init(devi, &simba->fm_cap, &simba->fm_ibc);

		ASSERT((simba->fm_cap & DDI_FM_ERRCB_CAPABLE) &&
		    (simba->fm_cap & DDI_FM_EREPORT_CAPABLE));

		pci_ereport_setup(devi);

		ddi_fm_handler_register(devi, simba_err_callback, simba);

		ddi_report_dev(devi);
		DEBUG0(D_ATTACH, "attach(): ATTACH done\n");
		return (DDI_SUCCESS);

	case DDI_RESUME:

		/*
		 * Get the soft state structure for the bridge.
		 */
		simba = (simba_devstate_t *)
		    ddi_get_soft_state(simba_state, ddi_get_instance(devi));
		simba_restore_config_regs(simba);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
simba_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	simba_devstate_t *simba;
	simba = (simba_devstate_t *)
	    ddi_get_soft_state(simba_state, ddi_get_instance(devi));

	switch (cmd) {
	case DDI_DETACH:
		DEBUG0(D_DETACH, "detach() called\n");
		ddi_fm_handler_unregister(devi);
		pci_ereport_teardown(devi);
		ddi_fm_fini(devi);
		pci_config_teardown(&simba->config_handle);
		(void) ddi_prop_remove(DDI_DEV_T_NONE, devi, "device_type");
		ddi_remove_minor_node(devi, "devctl");
		mutex_destroy(&simba->simba_mutex);
		ddi_soft_state_free(simba_state, ddi_get_instance(devi));
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		simba_save_config_regs(simba);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
simba_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	register dev_info_t *pdip;

	DEBUG3(D_MAP, "simba_bus_map(): dip=%p, rdip=%p, mp=%p", dip, rdip, mp);
	DEBUG3(D_MAP, "simba_bus_map(): offset=%lx, len=%lx, vaddrp=%p",
	    offset, len, vaddrp);

	pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
	    (pdip, rdip, mp, offset, len, vaddrp));
}

/*
 * Registered error handling callback with our parent
 */
static int
simba_err_callback(dev_info_t *dip, ddi_fm_error_t *derr, const void *impl_data)
{
	simba_devstate_t *simba = (simba_devstate_t *)impl_data;
	struct simba_errstate simba_err;
	int ret = 0;

	bzero(&simba_err, sizeof (struct simba_errstate));
	simba_err.afsr = pci_config_get64(simba->config_handle, 0xe8);
	simba_err.afar = pci_config_get64(simba->config_handle, 0xf0);
	derr->fme_ena = fm_ena_generate(0, FM_ENA_FMT1);

	pci_ereport_post(dip, derr, NULL);
	ret = derr->fme_status;

	DEBUG6(D_FAULT, "%s-%d: cleaning up fault bits %x %x %x.%8x\n",
	    ddi_driver_name(simba->dip), ddi_get_instance(simba->dip),
	    simba_err.pci_cfg_stat, simba_err.pci_cfg_sec_stat,
	    (uint_t)(simba_err.afsr >> 32), (uint_t)simba_err.afsr);
	pci_config_put64(simba->config_handle, 0xe8, simba_err.afsr);

	return (ret);
}

#if defined(DEBUG) && !defined(lint)
static char *ops[] =
{
	"DDI_CTLOPS_DMAPMAPC",
	"DDI_CTLOPS_INITCHILD",
	"DDI_CTLOPS_UNINITCHILD",
	"DDI_CTLOPS_REPORTDEV",
	"DDI_CTLOPS_REPORTINT",
	"DDI_CTLOPS_REGSIZE",
	"DDI_CTLOPS_NREGS",
	"DDI_CTLOPS_RESERVED0",
	"DDI_CTLOPS_SIDDEV",
	"DDI_CTLOPS_SLAVEONLY",
	"DDI_CTLOPS_AFFINITY",
	"DDI_CTLOPS_IOMIN",
	"DDI_CTLOPS_PTOB",
	"DDI_CTLOPS_BTOP",
	"DDI_CTLOPS_BTOPR",
	"DDI_CTLOPS_RESERVED1",
	"DDI_CTLOPS_RESERVED2",
	"DDI_CTLOPS_RESERVED3",
	"DDI_CTLOPS_RESERVED4",
	"DDI_CTLOPS_RESERVED5",
	"DDI_CTLOPS_DVMAPAGESIZE",
	"DDI_CTLOPS_POWER",
	"DDI_CTLOPS_ATTACH",
	"DDI_CTLOPS_DETACH",
	"DDI_CTLOPS_POKE",
	"DDI_CTLOPS_PEEK"
};
#endif

/*ARGSUSED*/
static int
simba_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
	void *arg, void *result)
{
	int reglen;
	int rn;
	int totreg;
	pci_regspec_t *drv_regp;

	DEBUG6(D_CTLOPS,
	    "simba_ctlops(): dip=%p rdip=%p ctlop=%x-%s arg=%p result=%p",
	    dip, rdip, ctlop, ctlop < (sizeof (ops) / sizeof (ops[0])) ?
	    ops[ctlop] : "Unknown", arg, result);

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
		return (simba_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		simba_uninitchild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		break;

	default:
		DEBUG0(D_CTLOPS, "simba_ctlops(): calling ddi_ctlops()");
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
	DEBUG1(D_CTLOPS, "simba_ctlops(): *result=%lx\n", *(off_t *)result);
	return (DDI_SUCCESS);
}

static int
simba_name_child(dev_info_t *child, char *name, int namelen)
{
	uint_t n, slot, func;
	pci_regspec_t *pci_rp;

	if (ndi_dev_is_persistent_node(child) == 0) {
		char **unit_addr;

		/* name .conf nodes by "unit-address" property" */
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

	/* name hardware nodes by "reg" property */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, 0, "reg",
	    (int **)&pci_rp, &n) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* get the device identifications */
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
simba_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];
	int i;
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;
	uchar_t header_type;
	uchar_t min_gnt, latency_timer;
	simba_devstate_t *simba;
	uint_t n;

	DEBUG1(D_INIT_CLD, "simba_initchild(): child=%p\n", child);

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		extern int pci_allow_pseudo_children;
		pci_regspec_t *pci_rp;

		if (ddi_getlongprop(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "reg", (caddr_t)&pci_rp, &i) ==
		    DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "cannot merge prototype from %s.conf",
			    ddi_driver_name(child));
			kmem_free(pci_rp, i);
			return (DDI_NOT_WELL_FORMED);
		}

		if (simba_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
			return (DDI_NOT_WELL_FORMED);

		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, simba_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			simba_uninitchild(child);
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
		simba_uninitchild(child);
		return (DDI_NOT_WELL_FORMED);
	}

	/*
	 * Initialize real h/w nodes
	 */
	if (simba_name_child(child, name, MAXNAMELEN) != DDI_SUCCESS)
		return (DDI_FAILURE);

	ddi_set_name_addr(child, name);
	ddi_set_parent_data(child, NULL);

	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS) {
		simba_uninitchild(child);
		return (DDI_FAILURE);
	}

	DEBUG0(D_INIT_CLD, "simba_initchild(): pci_config_setup success!\n");

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
	command |= (simba_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

	/* clean up all PCI child devices status register */
	pci_config_put16(config_handle, PCI_CONF_STAT, 0xffff);

	/*
	 * If the device has a primary bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		ushort_t bcr =
		    pci_config_get16(config_handle, PCI_BCNF_BCNTRL);
		if (simba_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (simba_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	simba = (simba_devstate_t *)ddi_get_soft_state(simba_state,
	    ddi_get_instance(ddi_get_parent(child)));
	/*
	 * Initialize cache-line-size configuration register if needed.
	 */
	if (simba_set_cache_line_size_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "cache-line-size", 0) == 0) {
		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    simba->simba_cache_line_size);
		n = pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		if (n != 0)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "cache-line-size", n);
	}

	/*
	 * Initialize latency timer configuration registers if needed.
	 */
	if (simba_set_latency_timer_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "latency-timer", 0) == 0) {

		if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
			latency_timer = simba->simba_latency_timer;
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
			    simba->simba_latency_timer);
		} else {
			min_gnt = pci_config_get8(config_handle,
			    PCI_CONF_MIN_G);
			latency_timer = min_gnt * 8;
		}
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
		    latency_timer);
		n = pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if (n != 0)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "latency-timer", n);
	}

	pci_config_teardown(&config_handle);
	DEBUG0(D_INIT_CLD, "simba_initchild(): pci_config_teardown called\n");
	return (DDI_SUCCESS);
}

static void
simba_uninitchild(dev_info_t *dip)
{
	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	impl_rem_dev_props(dip);
}

/*
 * simba_save_config_regs
 *
 * This routine saves the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: simba_detach() on suspends
 *
 * return value: none
 */
static void
simba_save_config_regs(simba_devstate_t *simba_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t ch;
	struct simba_cfg_state *statep;

	for (i = 0, dip = ddi_get_child(simba_p->dip); dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {
		if (i_ddi_devi_attached(dip))
			i++;
	}
	if (!i)
		return;
	simba_p->simba_config_state_p =
	    kmem_zalloc(i * sizeof (struct simba_cfg_state), KM_NOSLEEP);
	if (!simba_p->simba_config_state_p) {
		cmn_err(CE_WARN, "not enough memrory to save simba child\n");
		return;
	}
	simba_p->config_state_index = i;

	for (statep = simba_p->simba_config_state_p,
	    dip = ddi_get_child(simba_p->dip);
	    dip != NULL;
	    dip = ddi_get_next_sibling(dip)) {

		if (!i_ddi_devi_attached(dip)) {
			DEBUG4(D_DETACH, "%s%d: skipping unattached %s%d\n",
			    ddi_driver_name(simba_p->dip),
			    ddi_get_instance(simba_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}

		DEBUG4(D_DETACH, "%s%d: saving regs for %s%d\n",
		    ddi_driver_name(simba_p->dip),
		    ddi_get_instance(simba_p->dip),
		    ddi_driver_name(dip),
		    ddi_get_instance(dip));

		if (pci_config_setup(dip, &ch) != DDI_SUCCESS) {
			DEBUG4(D_DETACH, "%s%d: can't config space for %s%d\n",
			    ddi_driver_name(simba_p->dip),
			    ddi_get_instance(simba_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}

		DEBUG3(D_DETACH, "%s%d: saving child dip=%p\n",
		    ddi_driver_name(simba_p->dip),
		    ddi_get_instance(simba_p->dip),
		    dip);

		statep->dip = dip;
		statep->command = pci_config_get16(ch, PCI_CONF_COMM);
		statep->header_type = pci_config_get8(ch, PCI_CONF_HEADER);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			statep->bridge_control =
			    pci_config_get16(ch, PCI_BCNF_BCNTRL);
		statep->cache_line_size =
		    pci_config_get8(ch, PCI_CONF_CACHE_LINESZ);
		statep->latency_timer =
		    pci_config_get8(ch, PCI_CONF_LATENCY_TIMER);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			statep->sec_latency_timer =
			    pci_config_get8(ch, PCI_BCNF_LATENCY_TIMER);
		/*
		 * Simba specific.
		 */
		if (pci_config_get16(ch, PCI_CONF_VENID) == PCI_SIMBA_VENID &&
		    pci_config_get16(ch, PCI_CONF_DEVID) == PCI_SIMBA_DEVID) {

			statep->bus_number =
			    pci_config_get8(ch, PCI_BCNF_PRIBUS);
			statep->sec_bus_number =
			    pci_config_get8(ch, PCI_BCNF_SECBUS);
			statep->sub_bus_number =
			    pci_config_get8(ch, PCI_BCNF_SUBBUS);
			statep->bridge_control =
			    pci_config_get16(ch, PCI_BCNF_BCNTRL);
		}
		pci_config_teardown(&ch);
		statep++;
	}
}


/*
 * simba_restore_config_regs
 *
 * This routine restores the state of the configuration registers of all
 * the child nodes of each PBM.
 *
 * used by: simba_attach() on resume
 *
 * return value: none
 */
static void
simba_restore_config_regs(simba_devstate_t *simba_p)
{
	int i;
	dev_info_t *dip;
	ddi_acc_handle_t ch;
	struct simba_cfg_state *statep = simba_p->simba_config_state_p;
	if (!simba_p->config_state_index)
		return;

	for (i = 0; i < simba_p->config_state_index; i++, statep++) {
		dip = statep->dip;
		if (!dip) {
			cmn_err(CE_WARN,
			    "%s%d: skipping bad dev info (%d)\n",
			    ddi_driver_name(simba_p->dip),
			    ddi_get_instance(simba_p->dip),
			    i);
			continue;
		}

		DEBUG5(D_ATTACH, "%s%d: restoring regs for %p-%s%d\n",
		    ddi_driver_name(simba_p->dip),
		    ddi_get_instance(simba_p->dip),
		    dip,
		    ddi_driver_name(dip),
		    ddi_get_instance(dip));

		if (pci_config_setup(dip, &ch) != DDI_SUCCESS) {
			DEBUG4(D_ATTACH, "%s%d: can't config space for %s%d\n",
			    ddi_driver_name(simba_p->dip),
			    ddi_get_instance(simba_p->dip),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip));
			continue;
		}
		pci_config_put16(ch, PCI_CONF_COMM, statep->command);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pci_config_put16(ch, PCI_BCNF_BCNTRL,
			    statep->bridge_control);
		/*
		 * Simba specific.
		 */
		if (pci_config_get16(ch, PCI_CONF_VENID) == PCI_SIMBA_VENID &&
		    pci_config_get16(ch, PCI_CONF_DEVID) == PCI_SIMBA_DEVID) {
			pci_config_put8(ch, PCI_BCNF_PRIBUS,
			    statep->bus_number);
			pci_config_put8(ch, PCI_BCNF_SECBUS,
			    statep->sec_bus_number);
			pci_config_put8(ch, PCI_BCNF_SUBBUS,
			    statep->sub_bus_number);
			pci_config_put16(ch, PCI_BCNF_BCNTRL,
			    statep->bridge_control);
		}

		pci_config_put8(ch, PCI_CONF_CACHE_LINESZ,
		    statep->cache_line_size);
		pci_config_put8(ch, PCI_CONF_LATENCY_TIMER,
		    statep->latency_timer);
		if ((statep->header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE)
			pci_config_put8(ch, PCI_BCNF_LATENCY_TIMER,
			    statep->sec_latency_timer);
		pci_config_teardown(&ch);
	}

	kmem_free(simba_p->simba_config_state_p,
	    simba_p->config_state_index * sizeof (struct simba_cfg_state));
	simba_p->simba_config_state_p = NULL;
	simba_p->config_state_index = 0;
}

/* ARGSUSED */
static int
simba_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	simba_devstate_t *simba_p;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	simba_p = (simba_devstate_t *)ddi_get_soft_state(simba_state,
	    getminor(*devp));
	if (simba_p == NULL)
		return (ENXIO);

	/*
	 * Handle the open by tracking the device state.
	 */
	mutex_enter(&simba_p->simba_mutex);
	if (flags & FEXCL) {
		if (simba_p->simba_soft_state != SIMBA_SOFT_STATE_CLOSED) {
			mutex_exit(&simba_p->simba_mutex);
			return (EBUSY);
		}
		simba_p->simba_soft_state = SIMBA_SOFT_STATE_OPEN_EXCL;
	} else {
		if (simba_p->simba_soft_state == SIMBA_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&simba_p->simba_mutex);
			return (EBUSY);
		}
		simba_p->simba_soft_state = SIMBA_SOFT_STATE_OPEN;
	}
	mutex_exit(&simba_p->simba_mutex);
	return (0);
}


/* ARGSUSED */
static int
simba_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	simba_devstate_t *simba_p;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	simba_p = (simba_devstate_t *)ddi_get_soft_state(simba_state,
	    getminor(dev));
	if (simba_p == NULL)
		return (ENXIO);

	mutex_enter(&simba_p->simba_mutex);
	simba_p->simba_soft_state = SIMBA_SOFT_STATE_CLOSED;
	mutex_exit(&simba_p->simba_mutex);
	return (0);
}


/*
 * simba_ioctl: devctl hotplug controls
 */
/* ARGSUSED */
static int
simba_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	simba_devstate_t *simba_p;
	dev_info_t *self;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;

	simba_p = (simba_devstate_t *)ddi_get_soft_state(simba_state,
	    getminor(dev));
	if (simba_p == NULL)
		return (ENXIO);

	self = simba_p->dip;

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

/*
 * Initialize FMA resources for children devices. Called when
 * child calls ddi_fm_init().
 */
/*ARGSUSED*/
static int
simba_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
		ddi_iblock_cookie_t *ibc)
{
	simba_devstate_t *simba_p = ddi_get_soft_state(simba_state,
	    ddi_get_instance(dip));

	*ibc = simba_p->fm_ibc;
	return (simba_p->fm_cap);
}

static void
simba_bus_enter(dev_info_t *dip, ddi_acc_handle_t handle)
{
	i_ndi_busop_access_enter(dip, handle);
}

/* ARGSUSED */
static void
simba_bus_exit(dev_info_t *dip, ddi_acc_handle_t handle)
{
	i_ndi_busop_access_exit(dip, handle);
}
