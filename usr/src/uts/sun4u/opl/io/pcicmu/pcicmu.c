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
 * OPL CMU-CH PCI nexus driver.
 *
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/intreg.h>
#include <sys/intr.h>
#include <sys/machsystm.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/ivintr.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndifm.h>
#include <sys/ontrap.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/epm.h>
#include <sys/spl.h>
#include <sys/fm/util.h>
#include <sys/fm/util.h>
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/pcicmu/pcicmu.h>

#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/pci.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/errno.h>
#include <sys/file.h>


uint32_t pcmu_spurintr_duration = 60000000; /* One minute */

/*
 * The variable controls the default setting of the command register
 * for pci devices.  See pcmu_init_child() for details.
 *
 * This flags also controls the setting of bits in the bridge control
 * register pci to pci bridges.  See pcmu_init_child() for details.
 */
ushort_t pcmu_command_default = PCI_COMM_SERR_ENABLE |
				PCI_COMM_WAIT_CYC_ENAB |
				PCI_COMM_PARITY_DETECT |
				PCI_COMM_ME |
				PCI_COMM_MAE |
				PCI_COMM_IO;
/*
 * The following driver parameters are defined as variables to allow
 * patching for debugging and tuning.  Flags that can be set on a per
 * PBM basis are bit fields where the PBM device instance number maps
 * to the bit position.
 */
#ifdef DEBUG
uint64_t pcmu_debug_flags = 0;
#endif
uint_t ecc_error_intr_enable = 1;

uint_t pcmu_ecc_afsr_retries = 100;	/* XXX - what's a good value? */

uint_t pcmu_intr_retry_intv = 5;	/* for interrupt retry reg */
uint_t pcmu_panic_on_fatal_errors = 1;	/* should be 1 at beta */

hrtime_t pcmu_intrpend_timeout = 5ll * NANOSEC;	/* 5 seconds in nanoseconds */

uint64_t pcmu_errtrig_pa = 0x0;


/*
 * The following value is the number of consecutive unclaimed interrupts that
 * will be tolerated for a particular ino_p before the interrupt is deemed to
 * be jabbering and is blocked.
 */
uint_t pcmu_unclaimed_intr_max = 20;

/*
 * function prototypes for dev ops routines:
 */
static int pcmu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcmu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int pcmu_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static int pcmu_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int pcmu_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int pcmu_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int pcmu_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);
static int pcmu_ctlops_poke(pcmu_t *pcmu_p, peekpoke_ctlops_t *in_args);
static int pcmu_ctlops_peek(pcmu_t *pcmu_p, peekpoke_ctlops_t *in_args,
    void *result);

static int map_pcmu_registers(pcmu_t *, dev_info_t *);
static void unmap_pcmu_registers(pcmu_t *);
static void pcmu_pbm_clear_error(pcmu_pbm_t *);

static int pcmu_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
    void *, void *);
static int pcmu_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
    off_t, off_t, caddr_t *);
static int pcmu_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
    ddi_intr_handle_impl_t *, void *);

static uint32_t pcmu_identity_init(pcmu_t *pcmu_p);
static int pcmu_intr_setup(pcmu_t *pcmu_p);
static void pcmu_pbm_errstate_get(pcmu_t *pcmu_p,
    pcmu_pbm_errstate_t *pbm_err_p);
static int pcmu_obj_setup(pcmu_t *pcmu_p);
static void pcmu_obj_destroy(pcmu_t *pcmu_p);
static void pcmu_obj_resume(pcmu_t *pcmu_p);
static void pcmu_obj_suspend(pcmu_t *pcmu_p);

static void u2u_ittrans_init(pcmu_t *, u2u_ittrans_data_t **);
static void u2u_ittrans_resume(u2u_ittrans_data_t **);
static void u2u_ittrans_uninit(u2u_ittrans_data_t *);

static pcmu_ksinfo_t	*pcmu_name_kstat;

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops pcmu_bus_ops = {
	BUSO_REV,
	pcmu_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	pcmu_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,	/* (*bus_get_eventcookie)(); */
	ndi_busop_add_eventcall,	/* (*bus_add_eventcall)(); */
	ndi_busop_remove_eventcall,	/* (*bus_remove_eventcall)(); */
	ndi_post_event,			/* (*bus_post_event)(); */
	NULL,				/* (*bus_intr_ctl)(); */
	NULL,				/* (*bus_config)(); */
	NULL,				/* (*bus_unconfig)(); */
	NULL,				/* (*bus_fm_init)(); */
	NULL,				/* (*bus_fm_fini)(); */
	NULL,				/* (*bus_fm_access_enter)(); */
	NULL,				/* (*bus_fm_access_fini)(); */
	NULL,				/* (*bus_power)(); */
	pcmu_intr_ops			/* (*bus_intr_op)(); */
};

struct cb_ops pcmu_cb_ops = {
	pcmu_open,			/* open */
	pcmu_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pcmu_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pcmu_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops pcmu_ops = {
	DEVO_REV,
	0,
	pcmu_info,
	nulldev,
	0,
	pcmu_attach,
	pcmu_detach,
	nodev,
	&pcmu_cb_ops,
	&pcmu_bus_ops,
	0
};

/*
 * module definitions:
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,				/* Type of module - driver */
	"OPL CMU-CH PCI Nexus driver %I%",	/* Name of module. */
	&pcmu_ops,				/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * driver global data:
 */
void *per_pcmu_state;			/* per-pbm soft state pointer */
kmutex_t pcmu_global_mutex;		/* attach/detach common struct lock */
errorq_t *pcmu_ecc_queue = NULL;	/* per-system ecc handling queue */

extern void pcmu_child_cfg_save(dev_info_t *dip);
extern void pcmu_child_cfg_restore(dev_info_t *dip);

int
_init(void)
{
	int e;

	/*
	 * Initialize per-pci bus soft state pointer.
	 */
	e = ddi_soft_state_init(&per_pcmu_state, sizeof (pcmu_t), 1);
	if (e != 0)
		return (e);

	/*
	 * Initialize global mutexes.
	 */
	mutex_init(&pcmu_global_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Create the performance kstats.
	 */
	pcmu_kstat_init();

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0) {
		ddi_soft_state_fini(&per_pcmu_state);
		mutex_destroy(&pcmu_global_mutex);
	}
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
	if (e != 0) {
		return (e);
	}

	/*
	 * Destroy pcmu_ecc_queue, and set it to NULL.
	 */
	if (pcmu_ecc_queue) {
		errorq_destroy(pcmu_ecc_queue);
		pcmu_ecc_queue = NULL;
	}

	/*
	 * Destroy the performance kstats.
	 */
	pcmu_kstat_fini();

	/*
	 * Free the per-pci and per-CMU-CH soft state info and destroy
	 * mutex for per-CMU-CH soft state.
	 */
	ddi_soft_state_fini(&per_pcmu_state);
	mutex_destroy(&pcmu_global_mutex);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pcmu_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int	instance = getminor((dev_t)arg) >> 8;
	pcmu_t	*pcmu_p = get_pcmu_soft_state(instance);

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (pcmu_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)pcmu_p->pcmu_dip;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/* device driver entry points */
/*
 * attach entry point:
 */
static int
pcmu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pcmu_t *pcmu_p;
	int instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		PCMU_DBG0(PCMU_DBG_ATTACH, dip, "DDI_ATTACH\n");

		/*
		 * Allocate and get the per-pci soft state structure.
		 */
		if (alloc_pcmu_soft_state(instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't allocate pci state",
			    ddi_driver_name(dip), instance);
			goto err_bad_pcmu_softstate;
		}
		pcmu_p = get_pcmu_soft_state(instance);
		pcmu_p->pcmu_dip = dip;
		mutex_init(&pcmu_p->pcmu_mutex, NULL, MUTEX_DRIVER, NULL);
		pcmu_p->pcmu_soft_state = PCMU_SOFT_STATE_CLOSED;
		pcmu_p->pcmu_open_count = 0;

		/*
		 * Get key properties of the pci bridge node.
		 */
		if (get_pcmu_properties(pcmu_p, dip) == DDI_FAILURE) {
			goto err_bad_pcmu_prop;
		}

		/*
		 * Map in the registers.
		 */
		if (map_pcmu_registers(pcmu_p, dip) == DDI_FAILURE) {
			goto err_bad_reg_prop;
		}
		if (pcmu_obj_setup(pcmu_p) != DDI_SUCCESS) {
			goto err_bad_objs;
		}

		if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
		    (uint_t)instance<<8 | 0xff,
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
			goto err_bad_devctl_node;
		}

		/*
		 * Due to unresolved hardware issues, disable PCIPM until
		 * the problem is fully understood.
		 *
		 * pcmu_pwr_setup(pcmu_p, dip);
		 */

		ddi_report_dev(dip);

		pcmu_p->pcmu_state = PCMU_ATTACHED;
		PCMU_DBG0(PCMU_DBG_ATTACH, dip, "attach success\n");
		break;

err_bad_objs:
		ddi_remove_minor_node(dip, "devctl");
err_bad_devctl_node:
		unmap_pcmu_registers(pcmu_p);
err_bad_reg_prop:
		free_pcmu_properties(pcmu_p);
err_bad_pcmu_prop:
		mutex_destroy(&pcmu_p->pcmu_mutex);
		free_pcmu_soft_state(instance);
err_bad_pcmu_softstate:
		return (DDI_FAILURE);

	case DDI_RESUME:
		PCMU_DBG0(PCMU_DBG_ATTACH, dip, "DDI_RESUME\n");

		/*
		 * Make sure the CMU-CH control registers
		 * are configured properly.
		 */
		pcmu_p = get_pcmu_soft_state(instance);
		mutex_enter(&pcmu_p->pcmu_mutex);

		/*
		 * Make sure this instance has been suspended.
		 */
		if (pcmu_p->pcmu_state != PCMU_SUSPENDED) {
			PCMU_DBG0(PCMU_DBG_ATTACH, dip,
			    "instance NOT suspended\n");
			mutex_exit(&pcmu_p->pcmu_mutex);
			return (DDI_FAILURE);
		}
		pcmu_obj_resume(pcmu_p);
		pcmu_p->pcmu_state = PCMU_ATTACHED;

		pcmu_child_cfg_restore(dip);

		mutex_exit(&pcmu_p->pcmu_mutex);
		break;

	default:
		PCMU_DBG0(PCMU_DBG_ATTACH, dip, "unsupported attach op\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * detach entry point:
 */
static int
pcmu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	pcmu_t *pcmu_p = get_pcmu_soft_state(instance);
	int len;

	/*
	 * Make sure we are currently attached
	 */
	if (pcmu_p->pcmu_state != PCMU_ATTACHED) {
		PCMU_DBG0(PCMU_DBG_ATTACH, dip,
		    "failed - instance not attached\n");
		return (DDI_FAILURE);
	}

	mutex_enter(&pcmu_p->pcmu_mutex);

	switch (cmd) {
	case DDI_DETACH:
		PCMU_DBG0(PCMU_DBG_DETACH, dip, "DDI_DETACH\n");
		pcmu_obj_destroy(pcmu_p);

		/*
		 * Free the pci soft state structure and the rest of the
		 * resources it's using.
		 */
		free_pcmu_properties(pcmu_p);
		unmap_pcmu_registers(pcmu_p);
		mutex_exit(&pcmu_p->pcmu_mutex);
		mutex_destroy(&pcmu_p->pcmu_mutex);
		free_pcmu_soft_state(instance);

		/* Free the interrupt-priorities prop if we created it. */
		if (ddi_getproplen(DDI_DEV_T_ANY, dip,
		    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
		    "interrupt-priorities", &len) == DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
			    "interrupt-priorities");
		}
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		pcmu_child_cfg_save(dip);
		pcmu_obj_suspend(pcmu_p);
		pcmu_p->pcmu_state = PCMU_SUSPENDED;

		mutex_exit(&pcmu_p->pcmu_mutex);
		return (DDI_SUCCESS);

	default:
		PCMU_DBG0(PCMU_DBG_DETACH, dip, "unsupported detach op\n");
		mutex_exit(&pcmu_p->pcmu_mutex);
		return (DDI_FAILURE);
	}
}

/* ARGSUSED3 */
static int
pcmu_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	pcmu_t *pcmu_p;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	/*
	 * Get the soft state structure for the device.
	 */
	pcmu_p = DEV_TO_SOFTSTATE(*devp);
	if (pcmu_p == NULL) {
		return (ENXIO);
	}

	/*
	 * Handle the open by tracking the device state.
	 */
	PCMU_DBG2(PCMU_DBG_OPEN, pcmu_p->pcmu_dip,
	    "devp=%x: flags=%x\n", devp, flags);
	mutex_enter(&pcmu_p->pcmu_mutex);
	if (flags & FEXCL) {
		if (pcmu_p->pcmu_soft_state != PCMU_SOFT_STATE_CLOSED) {
			mutex_exit(&pcmu_p->pcmu_mutex);
			PCMU_DBG0(PCMU_DBG_OPEN, pcmu_p->pcmu_dip, "busy\n");
			return (EBUSY);
		}
		pcmu_p->pcmu_soft_state = PCMU_SOFT_STATE_OPEN_EXCL;
	} else {
		if (pcmu_p->pcmu_soft_state == PCMU_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&pcmu_p->pcmu_mutex);
			PCMU_DBG0(PCMU_DBG_OPEN, pcmu_p->pcmu_dip, "busy\n");
			return (EBUSY);
		}
		pcmu_p->pcmu_soft_state = PCMU_SOFT_STATE_OPEN;
	}
	pcmu_p->pcmu_open_count++;
	mutex_exit(&pcmu_p->pcmu_mutex);
	return (0);
}


/* ARGSUSED */
static int
pcmu_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	pcmu_t *pcmu_p;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	pcmu_p = DEV_TO_SOFTSTATE(dev);
	if (pcmu_p == NULL) {
		return (ENXIO);
	}

	PCMU_DBG2(PCMU_DBG_CLOSE, pcmu_p->pcmu_dip,
	    "dev=%x: flags=%x\n", dev, flags);
	mutex_enter(&pcmu_p->pcmu_mutex);
	pcmu_p->pcmu_soft_state = PCMU_SOFT_STATE_CLOSED;
	pcmu_p->pcmu_open_count = 0;
	mutex_exit(&pcmu_p->pcmu_mutex);
	return (0);
}

/* ARGSUSED */
static int
pcmu_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	pcmu_t *pcmu_p;
	dev_info_t *dip;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;

	pcmu_p = DEV_TO_SOFTSTATE(dev);
	if (pcmu_p == NULL) {
		return (ENXIO);
	}

	dip = pcmu_p->pcmu_dip;
	PCMU_DBG2(PCMU_DBG_IOCTL, dip, "dev=%x: cmd=%x\n", dev, cmd);

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(dip, cmd, arg, mode, 0));
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		PCMU_DBG0(PCMU_DBG_IOCTL, dip, "DEVCTL_DEVICE_RESET\n");
		rv = ENOTSUP;
		break;


	case DEVCTL_BUS_QUIESCE:
		PCMU_DBG0(PCMU_DBG_IOCTL, dip, "DEVCTL_BUS_QUIESCE\n");
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS) {
			if (bus_state == BUS_QUIESCED) {
				break;
			}
		}
		(void) ndi_set_bus_state(dip, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		PCMU_DBG0(PCMU_DBG_IOCTL, dip, "DEVCTL_BUS_UNQUIESCE\n");
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS) {
			if (bus_state == BUS_ACTIVE) {
				break;
			}
		}
		(void) ndi_set_bus_state(dip, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		PCMU_DBG0(PCMU_DBG_IOCTL, dip, "DEVCTL_BUS_RESET\n");
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		PCMU_DBG0(PCMU_DBG_IOCTL, dip, "DEVCTL_BUS_RESETALL\n");
		rv = ENOTSUP;
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}

static int pcmu_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}
/* bus driver entry points */

/*
 * bus map entry point:
 *
 *	if map request is for an rnumber
 *		get the corresponding regspec from device node
 *	build a new regspec in our parent's format
 *	build a new map_req with the new regspec
 *	call up the tree to complete the mapping
 */
static int
pcmu_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	pcmu_t *pcmu_p = get_pcmu_soft_state(ddi_get_instance(dip));
	struct regspec p_regspec;
	ddi_map_req_t p_mapreq;
	int reglen, rval, r_no;
	pci_regspec_t reloc_reg, *rp = &reloc_reg;

	PCMU_DBG2(PCMU_DBG_MAP, dip, "rdip=%s%d:",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	if (mp->map_flags & DDI_MF_USER_MAPPING) {
		return (DDI_ME_UNIMPLEMENTED);
	}

	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		reloc_reg = *(pci_regspec_t *)mp->map_obj.rp;	/* dup whole */
		break;

	case DDI_MT_RNUMBER:
		r_no = mp->map_obj.rnumber;
		PCMU_DBG1(PCMU_DBG_MAP | PCMU_DBG_CONT, dip, " r#=%x", r_no);

		if (ddi_getlongprop(DDI_DEV_T_NONE, rdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&rp, &reglen) != DDI_SUCCESS) {
			return (DDI_ME_RNUMBER_RANGE);
		}

		if (r_no < 0 || r_no >= reglen / sizeof (pci_regspec_t)) {
			kmem_free(rp, reglen);
			return (DDI_ME_RNUMBER_RANGE);
		}
		rp += r_no;
		break;

	default:
		return (DDI_ME_INVAL);
	}
	PCMU_DBG0(PCMU_DBG_MAP | PCMU_DBG_CONT, dip, "\n");

	/* use "assigned-addresses" to relocate regspec within pci space */
	if (rval = pcmu_reloc_reg(dip, rdip, pcmu_p, rp)) {
		goto done;
	}

	/* adjust regspec according to mapping request */
	if (len) {
		rp->pci_size_low = (uint_t)len;
	}
	rp->pci_phys_low += off;

	/* use "ranges" to translate relocated pci regspec into parent space */
	if (rval = pcmu_xlate_reg(pcmu_p, rp, &p_regspec)) {
		goto done;
	}

	p_mapreq = *mp;		/* dup the whole structure */
	p_mapreq.map_type = DDI_MT_REGSPEC;
	p_mapreq.map_obj.rp = &p_regspec;
	rval = ddi_map(dip, &p_mapreq, 0, 0, addrp);

done:
	if (mp->map_type == DDI_MT_RNUMBER) {
		kmem_free(rp - r_no, reglen);
	}
	return (rval);
}

#ifdef  DEBUG
int	pcmu_peekfault_cnt = 0;
int	pcmu_pokefault_cnt = 0;
#endif  /* DEBUG */

static int
pcmu_do_poke(pcmu_t *pcmu_p, peekpoke_ctlops_t *in_args)
{
	pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	mutex_enter(&pcbm_p->pcbm_pokeflt_mutex);
	pcbm_p->pcbm_ontrap_data = &otd;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		otd.ot_trampoline = (uintptr_t)&poke_fault;
		err = do_poke(in_args->size, (void *)in_args->dev_addr,
		    (void *)in_args->host_addr);
		otd.ot_trampoline = tramp;
	} else {
		err = DDI_FAILURE;
	}

	/*
	 * Read the async fault register for the PBM to see it sees
	 * a master-abort.
	 */
	pcmu_pbm_clear_error(pcbm_p);

	if (otd.ot_trap & OT_DATA_ACCESS) {
		err = DDI_FAILURE;
	}

	/* Take down protected environment. */
	no_trap();

	pcbm_p->pcbm_ontrap_data = NULL;
	mutex_exit(&pcbm_p->pcbm_pokeflt_mutex);

#ifdef  DEBUG
	if (err == DDI_FAILURE)
		pcmu_pokefault_cnt++;
#endif
	return (err);
}


static int
pcmu_ctlops_poke(pcmu_t *pcmu_p, peekpoke_ctlops_t *in_args)
{
	return (pcmu_do_poke(pcmu_p, in_args));
}

/* ARGSUSED */
static int
pcmu_do_peek(pcmu_t *pcmu_p, peekpoke_ctlops_t *in_args)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		otd.ot_trampoline = (uintptr_t)&peek_fault;
		err = do_peek(in_args->size, (void *)in_args->dev_addr,
		    (void *)in_args->host_addr);
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	no_trap();

#ifdef  DEBUG
	if (err == DDI_FAILURE)
		pcmu_peekfault_cnt++;
#endif
	return (err);
}


static int
pcmu_ctlops_peek(pcmu_t *pcmu_p, peekpoke_ctlops_t *in_args, void *result)
{
	result = (void *)in_args->host_addr;
	return (pcmu_do_peek(pcmu_p, in_args));
}

/*
 * control ops entry point:
 *
 * Requests handled completely:
 *	DDI_CTLOPS_INITCHILD	see pcmu_init_child() for details
 *	DDI_CTLOPS_UNINITCHILD
 *	DDI_CTLOPS_REPORTDEV	see report_dev() for details
 *	DDI_CTLOPS_XLATE_INTRS	nothing to do
 *	DDI_CTLOPS_IOMIN	cache line size if streaming otherwise 1
 *	DDI_CTLOPS_REGSIZE
 *	DDI_CTLOPS_NREGS
 *	DDI_CTLOPS_NINTRS
 *	DDI_CTLOPS_DVMAPAGESIZE
 *	DDI_CTLOPS_POKE
 *	DDI_CTLOPS_PEEK
 *	DDI_CTLOPS_QUIESCE
 *	DDI_CTLOPS_UNQUIESCE
 *
 * All others passed to parent.
 */
static int
pcmu_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result)
{
	pcmu_t *pcmu_p = get_pcmu_soft_state(ddi_get_instance(dip));

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		return (pcmu_init_child(pcmu_p, (dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (pcmu_uninit_child(pcmu_p, (dev_info_t *)arg));

	case DDI_CTLOPS_REPORTDEV:
		return (pcmu_report_dev(rdip));

	case DDI_CTLOPS_IOMIN:
		/*
		 * If we are using the streaming cache, align at
		 * least on a cache line boundary. Otherwise use
		 * whatever alignment is passed in.
		 */
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
		*((off_t *)result) = pcmu_get_reg_set_size(rdip, *((int *)arg));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		*((uint_t *)result) = pcmu_get_nreg_set(rdip);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_DVMAPAGESIZE:
		*((ulong_t *)result) = 0;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_POKE:
		return (pcmu_ctlops_poke(pcmu_p, (peekpoke_ctlops_t *)arg));

	case DDI_CTLOPS_PEEK:
		return (pcmu_ctlops_peek(pcmu_p, (peekpoke_ctlops_t *)arg,
		    result));

	case DDI_CTLOPS_AFFINITY:
		break;

	case DDI_CTLOPS_QUIESCE:
		return (DDI_FAILURE);

	case DDI_CTLOPS_UNQUIESCE:
		return (DDI_FAILURE);

	default:
		break;
	}

	/*
	 * Now pass the request up to our parent.
	 */
	PCMU_DBG2(PCMU_DBG_CTLOPS, dip,
	    "passing request to parent: rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));
	return (ddi_ctlops(dip, rdip, op, arg, result));
}


/* ARGSUSED */
static int
pcmu_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	pcmu_t		*pcmu_p = get_pcmu_soft_state(ddi_get_instance(dip));
	int		ret = DDI_SUCCESS;

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		/* GetCap will always fail for all non PCI devices */
		(void) pci_intx_get_cap(rdip, (int *)result);
		break;
	case DDI_INTROP_SETCAP:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = hdlp->ih_pri ? hdlp->ih_pri : 0;
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = pcmu_add_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		ret = pcmu_remove_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_ENABLE:
		ret = pcmu_ib_update_intr_state(pcmu_p, rdip, hdlp,
		    PCMU_INTR_STATE_ENABLE);
		break;
	case DDI_INTROP_DISABLE:
		ret = pcmu_ib_update_intr_state(pcmu_p, rdip, hdlp,
		    PCMU_INTR_STATE_DISABLE);
		break;
	case DDI_INTROP_SETMASK:
		ret = pci_intx_set_mask(rdip);
		break;
	case DDI_INTROP_CLRMASK:
		ret = pci_intx_clr_mask(rdip);
		break;
	case DDI_INTROP_GETPENDING:
		ret = pci_intx_get_pending(rdip, (int *)result);
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* PCI nexus driver supports only fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

/*
 * CMU-CH specifics implementation:
 *	interrupt mapping register
 *	PBM configuration
 *	ECC and PBM error handling
 */

/* called by pcmu_attach() DDI_ATTACH to initialize pci objects */
static int
pcmu_obj_setup(pcmu_t *pcmu_p)
{
	int ret;

	mutex_enter(&pcmu_global_mutex);
	pcmu_p->pcmu_rev = ddi_prop_get_int(DDI_DEV_T_ANY, pcmu_p->pcmu_dip,
	    DDI_PROP_DONTPASS, "module-revision#", 0);

	pcmu_ib_create(pcmu_p);
	pcmu_cb_create(pcmu_p);
	pcmu_ecc_create(pcmu_p);
	pcmu_pbm_create(pcmu_p);
	pcmu_err_create(pcmu_p);
	if ((ret = pcmu_intr_setup(pcmu_p)) != DDI_SUCCESS)
		goto done;

	/*
	 * Due to a hardware bug, do not create kstat for DC systems
	 * with PCI hw revision less than 5.
	 */
	if ((strncmp(ddi_binding_name(pcmu_p->pcmu_dip),
	    PCICMU_OPL_DC_BINDING_NAME, strlen(PCICMU_OPL_DC_BINDING_NAME))
	    != 0) || (pcmu_p->pcmu_rev > 4)) {
		pcmu_kstat_create(pcmu_p);
	}
done:
	mutex_exit(&pcmu_global_mutex);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "Interrupt register failure, returning 0x%x\n",
		    ret);
	}
	return (ret);
}

/* called by pcmu_detach() DDI_DETACH to destroy pci objects */
static void
pcmu_obj_destroy(pcmu_t *pcmu_p)
{
	mutex_enter(&pcmu_global_mutex);

	pcmu_kstat_destroy(pcmu_p);
	pcmu_pbm_destroy(pcmu_p);
	pcmu_err_destroy(pcmu_p);
	pcmu_ecc_destroy(pcmu_p);
	pcmu_cb_destroy(pcmu_p);
	pcmu_ib_destroy(pcmu_p);
	pcmu_intr_teardown(pcmu_p);

	mutex_exit(&pcmu_global_mutex);
}

/* called by pcmu_attach() DDI_RESUME to (re)initialize pci objects */
static void
pcmu_obj_resume(pcmu_t *pcmu_p)
{
	mutex_enter(&pcmu_global_mutex);

	pcmu_ib_configure(pcmu_p->pcmu_ib_p);
	pcmu_ecc_configure(pcmu_p);
	pcmu_ib_resume(pcmu_p->pcmu_ib_p);
	u2u_ittrans_resume((u2u_ittrans_data_t **)
	    &(pcmu_p->pcmu_cb_p->pcb_ittrans_cookie));

	pcmu_pbm_configure(pcmu_p->pcmu_pcbm_p);

	pcmu_cb_resume(pcmu_p->pcmu_cb_p);

	pcmu_pbm_resume(pcmu_p->pcmu_pcbm_p);

	mutex_exit(&pcmu_global_mutex);
}

/* called by pcmu_detach() DDI_SUSPEND to suspend pci objects */
static void
pcmu_obj_suspend(pcmu_t *pcmu_p)
{
	mutex_enter(&pcmu_global_mutex);

	pcmu_pbm_suspend(pcmu_p->pcmu_pcbm_p);
	pcmu_ib_suspend(pcmu_p->pcmu_ib_p);
	pcmu_cb_suspend(pcmu_p->pcmu_cb_p);

	mutex_exit(&pcmu_global_mutex);
}

static int
pcmu_intr_setup(pcmu_t *pcmu_p)
{
	dev_info_t *dip = pcmu_p->pcmu_dip;
	pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;
	pcmu_cb_t *pcb_p = pcmu_p->pcmu_cb_p;
	int i, no_of_intrs;

	/*
	 * Get the interrupts property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "interrupts", (caddr_t)&pcmu_p->pcmu_inos,
	    &pcmu_p->pcmu_inos_len) != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "%s%d: no interrupts property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}

	/*
	 * figure out number of interrupts in the "interrupts" property
	 * and convert them all into ino.
	 */
	i = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "#interrupt-cells", 1);
	i = CELLS_1275_TO_BYTES(i);
	no_of_intrs = pcmu_p->pcmu_inos_len / i;
	for (i = 0; i < no_of_intrs; i++) {
		pcmu_p->pcmu_inos[i] =
		    PCMU_IB_MONDO_TO_INO(pcmu_p->pcmu_inos[i]);
	}

	pcb_p->pcb_no_of_inos = no_of_intrs;
	if (i = pcmu_ecc_register_intr(pcmu_p)) {
		goto teardown;
	}

	intr_dist_add(pcmu_cb_intr_dist, pcb_p);
	pcmu_ecc_enable_intr(pcmu_p);

	if (i = pcmu_pbm_register_intr(pcbm_p)) {
		intr_dist_rem(pcmu_cb_intr_dist, pcb_p);
		goto teardown;
	}
	intr_dist_add(pcmu_pbm_intr_dist, pcbm_p);
	pcmu_ib_intr_enable(pcmu_p, pcmu_p->pcmu_inos[CBNINTR_PBM]);

	intr_dist_add_weighted(pcmu_ib_intr_dist_all, pcmu_p->pcmu_ib_p);
	return (DDI_SUCCESS);
teardown:
	pcmu_intr_teardown(pcmu_p);
	return (i);
}

/*
 * pcmu_fix_ranges - fixes the config space entry of the "ranges"
 *	property on CMU-CH platforms
 */
void
pcmu_fix_ranges(pcmu_ranges_t *rng_p, int rng_entries)
{
	int i;
	for (i = 0; i < rng_entries; i++, rng_p++) {
		if ((rng_p->child_high & PCI_REG_ADDR_M) == PCI_ADDR_CONFIG)
			rng_p->parent_low |= rng_p->child_high;
	}
}

/*
 * map_pcmu_registers
 *
 * This function is called from the attach routine to map the registers
 * accessed by this driver.
 *
 * used by: pcmu_attach()
 *
 * return value: DDI_FAILURE on failure
 */
static int
map_pcmu_registers(pcmu_t *pcmu_p, dev_info_t *dip)
{
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	if (ddi_regs_map_setup(dip, 0, &pcmu_p->pcmu_address[0], 0, 0,
	    &attr, &pcmu_p->pcmu_ac[0]) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: unable to map reg entry 0\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/*
	 * We still use pcmu_address[2]
	 */
	if (ddi_regs_map_setup(dip, 2, &pcmu_p->pcmu_address[2], 0, 0,
	    &attr, &pcmu_p->pcmu_ac[2]) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: unable to map reg entry 2\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ddi_regs_map_free(&pcmu_p->pcmu_ac[0]);
		return (DDI_FAILURE);
	}

	/*
	 * The second register set contains the bridge's configuration
	 * header.  This header is at the very beginning of the bridge's
	 * configuration space.  This space has litte-endian byte order.
	 */
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	if (ddi_regs_map_setup(dip, 1, &pcmu_p->pcmu_address[1], 0,
	    PCI_CONF_HDR_SIZE, &attr, &pcmu_p->pcmu_ac[1]) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "%s%d: unable to map reg entry 1\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ddi_regs_map_free(&pcmu_p->pcmu_ac[0]);
		return (DDI_FAILURE);
	}
	PCMU_DBG2(PCMU_DBG_ATTACH, dip, "address (%p,%p)\n",
	    pcmu_p->pcmu_address[0], pcmu_p->pcmu_address[1]);
	return (DDI_SUCCESS);
}

/*
 * unmap_pcmu_registers:
 *
 * This routine unmap the registers mapped by map_pcmu_registers.
 *
 * used by: pcmu_detach()
 *
 * return value: none
 */
static void
unmap_pcmu_registers(pcmu_t *pcmu_p)
{
	ddi_regs_map_free(&pcmu_p->pcmu_ac[0]);
	ddi_regs_map_free(&pcmu_p->pcmu_ac[1]);
	ddi_regs_map_free(&pcmu_p->pcmu_ac[2]);
}

/*
 * These convenience wrappers relies on map_pcmu_registers() to setup
 * pcmu_address[0-2] correctly at first.
 */
static uintptr_t
get_reg_base(pcmu_t *pcmu_p)
{
	return ((uintptr_t)pcmu_p->pcmu_address[2]);
}

/* The CMU-CH config reg base is always the 2nd reg entry */
static uintptr_t
get_config_reg_base(pcmu_t *pcmu_p)
{
	return ((uintptr_t)(pcmu_p->pcmu_address[1]));
}

uint64_t
ib_get_map_reg(pcmu_ib_mondo_t mondo, uint32_t cpu_id)
{
	return ((mondo) | (cpu_id << PCMU_INTR_MAP_REG_TID_SHIFT) |
	    PCMU_INTR_MAP_REG_VALID);

}

uint32_t
ib_map_reg_get_cpu(volatile uint64_t reg)
{
	return ((reg & PCMU_INTR_MAP_REG_TID) >>
	    PCMU_INTR_MAP_REG_TID_SHIFT);
}

uint64_t *
ib_intr_map_reg_addr(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino)
{
	uint64_t *addr;

	ASSERT(ino & 0x20);
	addr = (uint64_t *)(pib_p->pib_obio_intr_map_regs +
	    (((uint_t)ino & 0x1f) << 3));
	return (addr);
}

uint64_t *
ib_clear_intr_reg_addr(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino)
{
	uint64_t *addr;

	ASSERT(ino & 0x20);
	addr = (uint64_t *)(pib_p->pib_obio_clear_intr_regs +
	    (((uint_t)ino & 0x1f) << 3));
	return (addr);
}

uintptr_t
pcmu_ib_setup(pcmu_ib_t *pib_p)
{
	pcmu_t *pcmu_p = pib_p->pib_pcmu_p;
	uintptr_t a = get_reg_base(pcmu_p);

	pib_p->pib_ign = PCMU_ID_TO_IGN(pcmu_p->pcmu_id);
	pib_p->pib_max_ino = PCMU_MAX_INO;
	pib_p->pib_obio_intr_map_regs = a + PCMU_IB_OBIO_INTR_MAP_REG_OFFSET;
	pib_p->pib_obio_clear_intr_regs =
	    a + PCMU_IB_OBIO_CLEAR_INTR_REG_OFFSET;
	return (a);
}

/*
 * Return the cpuid to to be used for an ino.
 *
 * On multi-function pci devices, functions have separate devinfo nodes and
 * interrupts.
 *
 * This function determines if there is already an established slot-oriented
 * interrupt-to-cpu binding established, if there is then it returns that
 * cpu.  Otherwise a new cpu is selected by intr_dist_cpuid().
 *
 * The devinfo node we are trying to associate a cpu with is
 * ino_p->pino_ih_head->ih_dip.
 */
uint32_t
pcmu_intr_dist_cpuid(pcmu_ib_t *pib_p, pcmu_ib_ino_info_t *ino_p)
{
	dev_info_t	*rdip = ino_p->pino_ih_head->ih_dip;
	dev_info_t	*prdip = ddi_get_parent(rdip);
	pcmu_ib_ino_info_t	*sino_p;
	dev_info_t	*sdip;
	dev_info_t	*psdip;
	char		*buf1 = NULL, *buf2 = NULL;
	char		*s1, *s2, *s3;
	int		l2;
	int		cpu_id;

	/* must be CMU-CH driver parent (not ebus) */
	if (strcmp(ddi_driver_name(prdip), "pcicmu") != 0)
		goto newcpu;

	/*
	 * From PCI 1275 binding: 2.2.1.3 Unit Address representation:
	 *   Since the "unit-number" is the address that appears in on Open
	 *   Firmware 'device path', it follows that only the DD and DD,FF
	 *   forms of the text representation can appear in a 'device path'.
	 *
	 * The rdip unit address is of the form "DD[,FF]".  Define two
	 * unit address strings that represent same-slot use: "DD" and "DD,".
	 * The first compare uses strcmp, the second uses strncmp.
	 */
	s1 = ddi_get_name_addr(rdip);
	if (s1 == NULL) {
		goto newcpu;
	}

	buf1 = kmem_alloc(MAXNAMELEN, KM_SLEEP);	/* strcmp */
	buf2 = kmem_alloc(MAXNAMELEN, KM_SLEEP);	/* strncmp */
	s1 = strcpy(buf1, s1);
	s2 = strcpy(buf2, s1);

	s1 = strrchr(s1, ',');
	if (s1) {
		*s1 = '\0';			/* have "DD,FF" */
		s1 = buf1;			/* search via strcmp "DD" */

		s2 = strrchr(s2, ',');
		*(s2 + 1) = '\0';
		s2 = buf2;
		l2 = strlen(s2);		/* search via strncmp "DD," */
	} else {
		(void) strcat(s2, ",");		/* have "DD" */
		l2 = strlen(s2);		/* search via strncmp "DD," */
	}

	/*
	 * Search the established ino list for devinfo nodes bound
	 * to an ino that matches one of the slot use strings.
	 */
	ASSERT(MUTEX_HELD(&pib_p->pib_ino_lst_mutex));
	for (sino_p = pib_p->pib_ino_lst; sino_p; sino_p = sino_p->pino_next) {
		/* skip self and non-established */
		if ((sino_p == ino_p) || (sino_p->pino_established == 0))
			continue;

		/* skip non-siblings */
		sdip = sino_p->pino_ih_head->ih_dip;
		psdip = ddi_get_parent(sdip);
		if (psdip != prdip)
			continue;

		/* must be CMU-CH driver parent (not ebus) */
		if (strcmp(ddi_driver_name(psdip), "pcicmu") != 0)
			continue;

		s3 = ddi_get_name_addr(sdip);
		if ((s1 && (strcmp(s1, s3) == 0)) ||
		    (strncmp(s2, s3, l2) == 0)) {
			extern int intr_dist_debug;

			if (intr_dist_debug) {
				cmn_err(CE_CONT, "intr_dist: "
				    "pcicmu`pcmu_intr_dist_cpuid "
				    "%s#%d %s: cpu %d established "
				    "by %s#%d %s\n", ddi_driver_name(rdip),
				    ddi_get_instance(rdip),
				    ddi_deviname(rdip, buf1),
				    sino_p->pino_cpuid,
				    ddi_driver_name(sdip),
				    ddi_get_instance(sdip),
				    ddi_deviname(sdip, buf2));
			}
			break;
		}
	}

	/* If a slot use match is found then use established cpu */
	if (sino_p) {
		cpu_id = sino_p->pino_cpuid;	/* target established cpu */
		goto out;
	}

newcpu:	cpu_id = intr_dist_cpuid();		/* target new cpu */

out:	if (buf1)
		kmem_free(buf1, MAXNAMELEN);
	if (buf2)
		kmem_free(buf2, MAXNAMELEN);
	return (cpu_id);
}

void
pcmu_cb_teardown(pcmu_t *pcmu_p)
{
	pcmu_cb_t	*pcb_p = pcmu_p->pcmu_cb_p;

	u2u_ittrans_uninit((u2u_ittrans_data_t *)pcb_p->pcb_ittrans_cookie);
}

int
pcmu_ecc_add_intr(pcmu_t *pcmu_p, int inum, pcmu_ecc_intr_info_t *eii_p)
{
	uint32_t mondo;

	mondo = ((pcmu_p->pcmu_cb_p->pcb_ign << PCMU_INO_BITS) |
	    pcmu_p->pcmu_inos[inum]);

	VERIFY(add_ivintr(mondo, pcmu_pil[inum], (intrfunc)pcmu_ecc_intr,
	    (caddr_t)eii_p, NULL, NULL) == 0);

	return (PCMU_ATTACH_RETCODE(PCMU_ECC_OBJ,
	    PCMU_OBJ_INTR_ADD, DDI_SUCCESS));
}

/* ARGSUSED */
void
pcmu_ecc_rem_intr(pcmu_t *pcmu_p, int inum, pcmu_ecc_intr_info_t *eii_p)
{
	uint32_t mondo;

	mondo = ((pcmu_p->pcmu_cb_p->pcb_ign << PCMU_INO_BITS) |
	    pcmu_p->pcmu_inos[inum]);

	VERIFY(rem_ivintr(mondo, pcmu_pil[inum]) == 0);
}

void
pcmu_pbm_configure(pcmu_pbm_t *pcbm_p)
{
	pcmu_t *pcmu_p = pcbm_p->pcbm_pcmu_p;
	dev_info_t *dip = pcmu_p->pcmu_dip;

#define	pbm_err	((PCMU_PCI_AFSR_E_MASK << PCMU_PCI_AFSR_PE_SHIFT) |	\
		(PCMU_PCI_AFSR_E_MASK << PCMU_PCI_AFSR_SE_SHIFT))
#define	csr_err	(PCI_STAT_PERROR | PCI_STAT_S_PERROR |		\
		PCI_STAT_R_MAST_AB | PCI_STAT_R_TARG_AB |	\
		PCI_STAT_S_TARG_AB | PCI_STAT_S_PERROR)

	/*
	 * Clear any PBM errors.
	 */
	*pcbm_p->pcbm_async_flt_status_reg = pbm_err;

	/*
	 * Clear error bits in configuration status register.
	 */
	PCMU_DBG1(PCMU_DBG_ATTACH, dip,
	    "pcmu_pbm_configure: conf status reg=%x\n", csr_err);

	pcbm_p->pcbm_config_header->ch_status_reg = csr_err;

	PCMU_DBG1(PCMU_DBG_ATTACH, dip,
	    "pcmu_pbm_configure: conf status reg==%x\n",
	    pcbm_p->pcbm_config_header->ch_status_reg);

	(void) ndi_prop_update_int(DDI_DEV_T_ANY, dip, "latency-timer",
	    (int)pcbm_p->pcbm_config_header->ch_latency_timer_reg);
#undef	pbm_err
#undef	csr_err
}

uint_t
pcmu_pbm_disable_errors(pcmu_pbm_t *pcbm_p)
{
	pcmu_t *pcmu_p = pcbm_p->pcbm_pcmu_p;
	pcmu_ib_t *pib_p = pcmu_p->pcmu_ib_p;

	/*
	 * Disable error and streaming byte hole interrupts via the
	 * PBM control register.
	 */
	*pcbm_p->pcbm_ctrl_reg &= ~PCMU_PCI_CTRL_ERR_INT_EN;

	/*
	 * Disable error interrupts via the interrupt mapping register.
	 */
	pcmu_ib_intr_disable(pib_p,
	    pcmu_p->pcmu_inos[CBNINTR_PBM], PCMU_IB_INTR_NOWAIT);
	return (BF_NONE);
}

void
pcmu_cb_setup(pcmu_t *pcmu_p)
{
	uint64_t csr, csr_pa, pa;
	pcmu_cb_t *pcb_p = pcmu_p->pcmu_cb_p;

	pcb_p->pcb_ign = PCMU_ID_TO_IGN(pcmu_p->pcmu_id);
	pa = (uint64_t)hat_getpfnum(kas.a_hat, pcmu_p->pcmu_address[0]);
	pcb_p->pcb_base_pa  = pa = pa >> (32 - MMU_PAGESHIFT) << 32;
	pcb_p->pcb_map_pa = pa + PCMU_IB_OBIO_INTR_MAP_REG_OFFSET;
	pcb_p->pcb_clr_pa = pa + PCMU_IB_OBIO_CLEAR_INTR_REG_OFFSET;
	pcb_p->pcb_obsta_pa = pa + PCMU_IB_OBIO_INTR_STATE_DIAG_REG;

	csr_pa = pa + PCMU_CB_CONTROL_STATUS_REG_OFFSET;
	csr = lddphysio(csr_pa);

	/*
	 * Clear any pending address parity errors.
	 */
	if (csr & PCMU_CB_CONTROL_STATUS_APERR) {
		csr |= PCMU_CB_CONTROL_STATUS_APERR;
		cmn_err(CE_WARN, "clearing UPA address parity error\n");
	}
	csr |= PCMU_CB_CONTROL_STATUS_APCKEN;
	csr &= ~PCMU_CB_CONTROL_STATUS_IAP;
	stdphysio(csr_pa, csr);

	u2u_ittrans_init(pcmu_p,
	    (u2u_ittrans_data_t **)&pcb_p->pcb_ittrans_cookie);
}

void
pcmu_ecc_setup(pcmu_ecc_t *pecc_p)
{
	pecc_p->pecc_ue.pecc_errpndg_mask = 0;
	pecc_p->pecc_ue.pecc_offset_mask = PCMU_ECC_UE_AFSR_DW_OFFSET;
	pecc_p->pecc_ue.pecc_offset_shift = PCMU_ECC_UE_AFSR_DW_OFFSET_SHIFT;
	pecc_p->pecc_ue.pecc_size_log2 = 3;
}

static uintptr_t
get_pbm_reg_base(pcmu_t *pcmu_p)
{
	return ((uintptr_t)(pcmu_p->pcmu_address[0]));
}

void
pcmu_pbm_setup(pcmu_pbm_t *pcbm_p)
{
	pcmu_t *pcmu_p = pcbm_p->pcbm_pcmu_p;

	/*
	 * Get the base virtual address for the PBM control block.
	 */
	uintptr_t a = get_pbm_reg_base(pcmu_p);

	/*
	 * Get the virtual address of the PCI configuration header.
	 * This should be mapped little-endian.
	 */
	pcbm_p->pcbm_config_header =
	    (config_header_t *)get_config_reg_base(pcmu_p);

	/*
	 * Get the virtual addresses for control, error and diag
	 * registers.
	 */
	pcbm_p->pcbm_ctrl_reg = (uint64_t *)(a + PCMU_PCI_CTRL_REG_OFFSET);
	pcbm_p->pcbm_diag_reg = (uint64_t *)(a + PCMU_PCI_DIAG_REG_OFFSET);
	pcbm_p->pcbm_async_flt_status_reg =
	    (uint64_t *)(a + PCMU_PCI_ASYNC_FLT_STATUS_REG_OFFSET);
	pcbm_p->pcbm_async_flt_addr_reg =
	    (uint64_t *)(a + PCMU_PCI_ASYNC_FLT_ADDR_REG_OFFSET);
}

/*ARGSUSED*/
void
pcmu_pbm_teardown(pcmu_pbm_t *pcbm_p)
{
}

int
pcmu_get_numproxy(dev_info_t *dip)
{
	return (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "#upa-interrupt-proxies", 1));
}

int
pcmu_get_portid(dev_info_t *dip)
{
	return (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "portid", -1));
}

/*
 * CMU-CH Performance Events.
 */
static pcmu_kev_mask_t
pcicmu_pcmu_events[] = {
	{"pio_cycles_b", 0xf},		{"interrupts", 0x11},
	{"upa_inter_nack", 0x12},	{"pio_reads", 0x13},
	{"pio_writes", 0x14},
	{"clear_pic", 0x1f}
};

/*
 * Create the picN kstat's.
 */
void
pcmu_kstat_init()
{
	pcmu_name_kstat = (pcmu_ksinfo_t *)kmem_alloc(sizeof (pcmu_ksinfo_t),
	    KM_NOSLEEP);

	if (pcmu_name_kstat == NULL) {
		cmn_err(CE_WARN, "pcicmu : no space for kstat\n");
	} else {
		pcmu_name_kstat->pic_no_evs =
		    sizeof (pcicmu_pcmu_events) / sizeof (pcmu_kev_mask_t);
		pcmu_name_kstat->pic_shift[0] = PCMU_SHIFT_PIC0;
		pcmu_name_kstat->pic_shift[1] = PCMU_SHIFT_PIC1;
		pcmu_create_name_kstat("pcmup",
		    pcmu_name_kstat, pcicmu_pcmu_events);
	}
}

/*
 * Called from _fini()
 */
void
pcmu_kstat_fini()
{
	if (pcmu_name_kstat != NULL) {
		pcmu_delete_name_kstat(pcmu_name_kstat);
		kmem_free(pcmu_name_kstat, sizeof (pcmu_ksinfo_t));
		pcmu_name_kstat = NULL;
	}
}

/*
 * Create the performance 'counters' kstat.
 */
void
pcmu_add_upstream_kstat(pcmu_t *pcmu_p)
{
	pcmu_cntr_pa_t	*cntr_pa_p = &pcmu_p->pcmu_uks_pa;
	uint64_t regbase = va_to_pa((void *)get_reg_base(pcmu_p));

	cntr_pa_p->pcr_pa = regbase + PCMU_PERF_PCR_OFFSET;
	cntr_pa_p->pic_pa = regbase + PCMU_PERF_PIC_OFFSET;
	pcmu_p->pcmu_uksp = pcmu_create_cntr_kstat(pcmu_p, "pcmup",
	    NUM_OF_PICS, pcmu_cntr_kstat_pa_update, cntr_pa_p);
}

/*
 * u2u_ittrans_init() is caled from in pci.c's pcmu_cb_setup() per CMU.
 * Second argument "ittrans_cookie" is address of pcb_ittrans_cookie in
 * pcb_p member. allocated interrupt block is returned in it.
 */
static void
u2u_ittrans_init(pcmu_t *pcmu_p, u2u_ittrans_data_t **ittrans_cookie)
{

	u2u_ittrans_data_t *u2u_trans_p;
	ddi_device_acc_attr_t attr;
	int ret;
	int board;

	/*
	 * Allocate the data structure to support U2U's
	 * interrupt target translations.
	 */
	u2u_trans_p = (u2u_ittrans_data_t *)
	    kmem_zalloc(sizeof (u2u_ittrans_data_t), KM_SLEEP);

	/*
	 * Get other properties, "board#"
	 */
	board = ddi_getprop(DDI_DEV_T_ANY, pcmu_p->pcmu_dip,
	    DDI_PROP_DONTPASS, "board#", -1);

	u2u_trans_p->u2u_board = board;

	if (board == -1) {
		/* this cannot happen on production systems */
		cmn_err(CE_PANIC, "u2u:Invalid property;board = %d", board);
	}

	/*
	 * Initialize interrupt target translations mutex.
	 */
	mutex_init(&(u2u_trans_p->u2u_ittrans_lock), "u2u_ittrans_lock",
	    MUTEX_DEFAULT, NULL);

	/*
	 * Get U2U's registers space by ddi_regs_map_setup(9F)
	 */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	ret = ddi_regs_map_setup(pcmu_p->pcmu_dip,
	    REGS_INDEX_OF_U2U, (caddr_t *)(&(u2u_trans_p->u2u_regs_base)),
	    0, 0, &attr, &(u2u_trans_p->u2u_acc));

	/*
	 * check result of ddi_regs_map_setup().
	 */
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_PANIC, "u2u%d: registers map setup failed", board);
	}

	/*
	 * Read Port-id(1 byte) in u2u
	 */
	u2u_trans_p->u2u_port_id = *(volatile int32_t *)
	    (u2u_trans_p->u2u_regs_base + U2U_PID_REGISTER_OFFSET);

	if (pcmu_p->pcmu_id != u2u_trans_p->u2u_port_id) {
		cmn_err(CE_PANIC, "u2u%d: Invalid Port-ID", board);
	}

	*ittrans_cookie = u2u_trans_p;
}

/*
 * u2u_ittras_resume() is called from pcmu_obj_resume() at DDI_RESUME entry.
 */
static void
u2u_ittrans_resume(u2u_ittrans_data_t **ittrans_cookie)
{

	u2u_ittrans_data_t *u2u_trans_p;
	u2u_ittrans_id_t *ittrans_id_p;
	uintptr_t  data_reg_addr;
	int ix;

	u2u_trans_p = *ittrans_cookie;

	/*
	 * Set U2U Data Register
	 */
	for (ix = 0; ix < U2U_DATA_NUM; ix++) {
		ittrans_id_p = &(u2u_trans_p->u2u_ittrans_id[ix]);
		data_reg_addr = u2u_trans_p->u2u_regs_base +
		    U2U_DATA_REGISTER_OFFSET + (ix * sizeof (uint64_t));
		if (ittrans_id_p->u2u_ino_map_reg == NULL) {
			/* This index was not set */
			continue;
		}
		*(volatile uint32_t *) (data_reg_addr) =
		    (uint32_t)ittrans_id_p->u2u_tgt_cpu_id;

	}
}

/*
 * u2u_ittras_uninit() is called from ib_destroy() at detach,
 * or occuring error in attach.
 */
static void
u2u_ittrans_uninit(u2u_ittrans_data_t *ittrans_cookie)
{

	if (ittrans_cookie == NULL) {
		return;	/* not support */
	}

	if (ittrans_cookie == (u2u_ittrans_data_t *)(-1)) {
		return;	 /* illeagal case */
	}

	ddi_regs_map_free(&(ittrans_cookie->u2u_acc));
	mutex_destroy(&(ittrans_cookie->u2u_ittrans_lock));
	kmem_free((void *)ittrans_cookie, sizeof (u2u_ittrans_data_t));
}

/*
 * This routine,u2u_translate_tgtid(, , cpu_id, pino_map_reg),
 * searches index having same value of pino_map_reg, or empty.
 * Then, stores cpu_id in a U2U Data Register as this index,
 * and return this index.
 */
int
u2u_translate_tgtid(pcmu_t *pcmu_p, uint_t cpu_id,
    volatile uint64_t *pino_map_reg)
{

	int index = -1;
	int ix;
	int err_level;	/* severity level for cmn_err */
	u2u_ittrans_id_t *ittrans_id_p;
	uintptr_t  data_reg_addr;
	u2u_ittrans_data_t *ittrans_cookie;

	ittrans_cookie =
	    (u2u_ittrans_data_t *)(pcmu_p->pcmu_cb_p->pcb_ittrans_cookie);

	if (ittrans_cookie == NULL) {
		return (cpu_id);
	}

	if (ittrans_cookie == (u2u_ittrans_data_t *)(-1)) {
		return (-1);	 /* illeagal case */
	}

	mutex_enter(&(ittrans_cookie->u2u_ittrans_lock));

	/*
	 * Decide index No. of U2U Data registers in either
	 * already used by same pino_map_reg, or empty.
	 */
	for (ix = 0; ix < U2U_DATA_NUM; ix++) {
		ittrans_id_p = &(ittrans_cookie->u2u_ittrans_id[ix]);
		if (ittrans_id_p->u2u_ino_map_reg == pino_map_reg) {
			/* already used this pino_map_reg */
			index = ix;
			break;
		}
		if (index == -1 &&
		    ittrans_id_p->u2u_ino_map_reg == NULL) {
			index = ix;
		}
	}

	if (index == -1) {
		if (panicstr) {
			err_level = CE_WARN;
		} else {
			err_level = CE_PANIC;
		}
		cmn_err(err_level, "u2u%d:No more U2U-Data regs!!",
		    ittrans_cookie->u2u_board);
		return (cpu_id);
	}

	/*
	 * For U2U
	 * set cpu_id into u2u_data_reg by index.
	 * ((uint64_t)(u2u_regs_base
	 *	+ U2U_DATA_REGISTER_OFFSET))[index] = cpu_id;
	 */

	data_reg_addr = ittrans_cookie->u2u_regs_base
	    + U2U_DATA_REGISTER_OFFSET
	    + (index * sizeof (uint64_t));

	/*
	 * Set cpu_id into U2U Data register[index]
	 */
	*(volatile uint32_t *) (data_reg_addr) = (uint32_t)cpu_id;

	/*
	 * Setup for software, excepting at panicing.
	 * and rebooting, etc...?
	 */
	if (!panicstr) {
		ittrans_id_p = &(ittrans_cookie->u2u_ittrans_id[index]);
		ittrans_id_p->u2u_tgt_cpu_id = cpu_id;
		ittrans_id_p->u2u_ino_map_reg = pino_map_reg;
	}

	mutex_exit(&(ittrans_cookie->u2u_ittrans_lock));

	return (index);
}

/*
 * u2u_ittrans_cleanup() is called from common_pcmu_ib_intr_disable()
 * after called intr_rem_cpu(mondo).
 */
void
u2u_ittrans_cleanup(u2u_ittrans_data_t *ittrans_cookie,
			volatile uint64_t *pino_map_reg)
{

	int ix;
	u2u_ittrans_id_t *ittrans_id_p;

	if (ittrans_cookie == NULL) {
		return;
	}

	if (ittrans_cookie == (u2u_ittrans_data_t *)(-1)) {
		return;	 /* illeagal case */
	}

	mutex_enter(&(ittrans_cookie->u2u_ittrans_lock));

	for (ix = 0; ix < U2U_DATA_NUM; ix++) {
		ittrans_id_p = &(ittrans_cookie->u2u_ittrans_id[ix]);
		if (ittrans_id_p->u2u_ino_map_reg == pino_map_reg) {
			ittrans_id_p->u2u_ino_map_reg = NULL;
			break;
		}
	}

	mutex_exit(&(ittrans_cookie->u2u_ittrans_lock));
}

/*
 * pcmu_ecc_classify, called by ecc_handler to classify ecc errors
 * and determine if we should panic or not.
 */
void
pcmu_ecc_classify(uint64_t err, pcmu_ecc_errstate_t *ecc_err_p)
{
	struct async_flt *ecc = &ecc_err_p->ecc_aflt;
	/* LINTED */
	pcmu_t *pcmu_p = ecc_err_p->ecc_ii_p.pecc_p->pecc_pcmu_p;

	ASSERT(MUTEX_HELD(&pcmu_p->pcmu_err_mutex));

	ecc_err_p->ecc_bridge_type = PCI_OPLCMU;	/* RAGS */
	/*
	 * Get the parent bus id that caused the error.
	 */
	ecc_err_p->ecc_dev_id = (ecc_err_p->ecc_afsr & PCMU_ECC_UE_AFSR_ID)
	    >> PCMU_ECC_UE_AFSR_ID_SHIFT;
	/*
	 * Determine the doubleword offset of the error.
	 */
	ecc_err_p->ecc_dw_offset = (ecc_err_p->ecc_afsr &
	    PCMU_ECC_UE_AFSR_DW_OFFSET) >> PCMU_ECC_UE_AFSR_DW_OFFSET_SHIFT;
	/*
	 * Determine the primary error type.
	 */
	switch (err) {
	case PCMU_ECC_UE_AFSR_E_PIO:
		if (ecc_err_p->pecc_pri) {
			ecc->flt_erpt_class = PCI_ECC_PIO_UE;
		} else {
			ecc->flt_erpt_class = PCI_ECC_SEC_PIO_UE;
		}
		/* For CMU-CH, a UE is always fatal. */
		ecc->flt_panic = 1;
		break;

	default:
		return;
	}
}

/*
 * pcmu_pbm_classify, called by pcmu_pbm_afsr_report to classify piow afsr.
 */
int
pcmu_pbm_classify(pcmu_pbm_errstate_t *pbm_err_p)
{
	uint32_t e;
	int nerr = 0;
	char **tmp_class;

	if (pbm_err_p->pcbm_pri) {
		tmp_class = &pbm_err_p->pcbm_pci.pcmu_err_class;
		e = PBM_AFSR_TO_PRIERR(pbm_err_p->pbm_afsr);
		pbm_err_p->pbm_log = FM_LOG_PCI;
	} else {
		tmp_class = &pbm_err_p->pbm_err_class;
		e = PBM_AFSR_TO_SECERR(pbm_err_p->pbm_afsr);
		pbm_err_p->pbm_log = FM_LOG_PBM;
	}

	if (e & PCMU_PCI_AFSR_E_MA) {
		*tmp_class = pbm_err_p->pcbm_pri ? PCI_MA : PCI_SEC_MA;
		nerr++;
	}
	return (nerr);
}

/*
 * Function used to clear PBM/PCI/IOMMU error state after error handling
 * is complete. Only clearing error bits which have been logged. Called by
 * pcmu_pbm_err_handler and pcmu_bus_exit.
 */
static void
pcmu_clear_error(pcmu_t *pcmu_p, pcmu_pbm_errstate_t *pbm_err_p)
{
	pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;

	ASSERT(MUTEX_HELD(&pcbm_p->pcbm_pcmu_p->pcmu_err_mutex));

	*pcbm_p->pcbm_ctrl_reg = pbm_err_p->pbm_ctl_stat;
	*pcbm_p->pcbm_async_flt_status_reg = pbm_err_p->pbm_afsr;
	pcbm_p->pcbm_config_header->ch_status_reg =
	    pbm_err_p->pcbm_pci.pcmu_cfg_stat;
}

/*ARGSUSED*/
int
pcmu_pbm_err_handler(dev_info_t *dip, ddi_fm_error_t *derr,
		const void *impl_data, int caller)
{
	int fatal = 0;
	int nonfatal = 0;
	int unknown = 0;
	uint32_t prierr, secerr;
	pcmu_pbm_errstate_t pbm_err;
	pcmu_t *pcmu_p = (pcmu_t *)impl_data;
	int ret = 0;

	ASSERT(MUTEX_HELD(&pcmu_p->pcmu_err_mutex));
	pcmu_pbm_errstate_get(pcmu_p, &pbm_err);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena :
	    fm_ena_generate(0, FM_ENA_FMT1);

	prierr = PBM_AFSR_TO_PRIERR(pbm_err.pbm_afsr);
	secerr = PBM_AFSR_TO_SECERR(pbm_err.pbm_afsr);

	if (derr->fme_flag == DDI_FM_ERR_PEEK) {
		/*
		 * For ddi_peek treat all events as nonfatal. We only
		 * really call this function so that pcmu_clear_error()
		 * and ndi_fm_handler_dispatch() will get called.
		 */
		nonfatal++;
		goto done;
	} else if (derr->fme_flag == DDI_FM_ERR_POKE) {
		/*
		 * For ddi_poke we can treat as nonfatal if the
		 * following conditions are met :
		 * 1. Make sure only primary error is MA/TA
		 * 2. Make sure no secondary error
		 * 3. check pci config header stat reg to see MA/TA is
		 *    logged. We cannot verify only MA/TA is recorded
		 *    since it gets much more complicated when a
		 *    PCI-to-PCI bridge is present.
		 */
		if ((prierr == PCMU_PCI_AFSR_E_MA) && !secerr &&
		    (pbm_err.pcbm_pci.pcmu_cfg_stat & PCI_STAT_R_MAST_AB)) {
			nonfatal++;
			goto done;
		}
	}

	if (prierr || secerr) {
		ret = pcmu_pbm_afsr_report(dip, derr->fme_ena, &pbm_err);
		if (ret == DDI_FM_FATAL) {
			fatal++;
		} else {
			nonfatal++;
		}
	}

	ret = pcmu_cfg_report(dip, derr, &pbm_err.pcbm_pci, caller, prierr);
	if (ret == DDI_FM_FATAL) {
		fatal++;
	} else if (ret == DDI_FM_NONFATAL) {
		nonfatal++;
	}

done:
	if (ret == DDI_FM_FATAL) {
		fatal++;
	} else if (ret == DDI_FM_NONFATAL) {
		nonfatal++;
	} else if (ret == DDI_FM_UNKNOWN) {
		unknown++;
	}

	/* Cleanup and reset error bits */
	pcmu_clear_error(pcmu_p, &pbm_err);

	return (fatal ? DDI_FM_FATAL : (nonfatal ? DDI_FM_NONFATAL :
	    (unknown ? DDI_FM_UNKNOWN : DDI_FM_OK)));
}

int
pcmu_check_error(pcmu_t *pcmu_p)
{
	pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;
	uint16_t pcmu_cfg_stat;
	uint64_t pbm_afsr;

	ASSERT(MUTEX_HELD(&pcmu_p->pcmu_err_mutex));

	pcmu_cfg_stat = pcbm_p->pcbm_config_header->ch_status_reg;
	pbm_afsr = *pcbm_p->pcbm_async_flt_status_reg;

	if ((pcmu_cfg_stat & (PCI_STAT_S_PERROR | PCI_STAT_S_TARG_AB |
	    PCI_STAT_R_TARG_AB | PCI_STAT_R_MAST_AB |
	    PCI_STAT_S_SYSERR | PCI_STAT_PERROR)) ||
	    (PBM_AFSR_TO_PRIERR(pbm_afsr))) {
		return (1);
	}
	return (0);

}

/*
 * Function used to gather PBM/PCI error state for the
 * pcmu_pbm_err_handler. This function must be called while pcmu_err_mutex
 * is held.
 */
static void
pcmu_pbm_errstate_get(pcmu_t *pcmu_p, pcmu_pbm_errstate_t *pbm_err_p)
{
	pcmu_pbm_t *pcbm_p = pcmu_p->pcmu_pcbm_p;

	ASSERT(MUTEX_HELD(&pcmu_p->pcmu_err_mutex));
	bzero(pbm_err_p, sizeof (pcmu_pbm_errstate_t));

	/*
	 * Capture all pbm error state for later logging
	 */
	pbm_err_p->pbm_bridge_type = PCI_OPLCMU;	/* RAGS */
	pbm_err_p->pcbm_pci.pcmu_cfg_stat =
	    pcbm_p->pcbm_config_header->ch_status_reg;
	pbm_err_p->pbm_ctl_stat = *pcbm_p->pcbm_ctrl_reg;
	pbm_err_p->pcbm_pci.pcmu_cfg_comm =
	    pcbm_p->pcbm_config_header->ch_command_reg;
	pbm_err_p->pbm_afsr = *pcbm_p->pcbm_async_flt_status_reg;
	pbm_err_p->pbm_afar = *pcbm_p->pcbm_async_flt_addr_reg;
	pbm_err_p->pcbm_pci.pcmu_pa = *pcbm_p->pcbm_async_flt_addr_reg;
}

static void
pcmu_pbm_clear_error(pcmu_pbm_t *pcbm_p)
{
	uint64_t pbm_afsr;

	/*
	 * for poke() support - called from POKE_FLUSH. Spin waiting
	 * for MA, TA or SERR to be cleared by a pcmu_pbm_error_intr().
	 * We have to wait for SERR too in case the device is beyond
	 * a pci-pci bridge.
	 */
	pbm_afsr = *pcbm_p->pcbm_async_flt_status_reg;
	while (((pbm_afsr >> PCMU_PCI_AFSR_PE_SHIFT) &
	    (PCMU_PCI_AFSR_E_MA | PCMU_PCI_AFSR_E_TA))) {
		pbm_afsr = *pcbm_p->pcbm_async_flt_status_reg;
	}
}

void
pcmu_err_create(pcmu_t *pcmu_p)
{
	/*
	 * PCI detected ECC errorq, to schedule async handling
	 * of ECC errors and logging.
	 * The errorq is created here but destroyed when _fini is called
	 * for the pci module.
	 */
	if (pcmu_ecc_queue == NULL) {
		pcmu_ecc_queue = errorq_create("pcmu_ecc_queue",
		    (errorq_func_t)pcmu_ecc_err_drain,
		    (void *)NULL,
		    ECC_MAX_ERRS, sizeof (pcmu_ecc_errstate_t),
		    PIL_2, ERRORQ_VITAL);
		if (pcmu_ecc_queue == NULL)
			panic("failed to create required system error queue");
	}

	/*
	 * Initialize error handling mutex.
	 */
	mutex_init(&pcmu_p->pcmu_err_mutex, NULL, MUTEX_DRIVER,
	    (void *)pcmu_p->pcmu_fm_ibc);
}

void
pcmu_err_destroy(pcmu_t *pcmu_p)
{
	mutex_destroy(&pcmu_p->pcmu_err_mutex);
}

/*
 * Function used to post PCI block module specific ereports.
 */
void
pcmu_pbm_ereport_post(dev_info_t *dip, uint64_t ena,
    pcmu_pbm_errstate_t *pbm_err)
{
	char *aux_msg;
	uint32_t prierr, secerr;
	pcmu_t *pcmu_p;
	int instance = ddi_get_instance(dip);

	ena = ena ? ena : fm_ena_generate(0, FM_ENA_FMT1);

	pcmu_p = get_pcmu_soft_state(instance);
	prierr = PBM_AFSR_TO_PRIERR(pbm_err->pbm_afsr);
	secerr = PBM_AFSR_TO_SECERR(pbm_err->pbm_afsr);
	if (prierr)
		aux_msg = "PCI primary error: Master Abort";
	else if (secerr)
		aux_msg = "PCI secondary error: Master Abort";
	else
		aux_msg = "";
	cmn_err(CE_WARN, "%s %s: %s %s=0x%lx, %s=0x%lx, %s=0x%lx %s=0x%x",
	    (pcmu_p->pcmu_pcbm_p)->pcbm_nameinst_str,
	    (pcmu_p->pcmu_pcbm_p)->pcbm_nameaddr_str,
	    aux_msg,
	    PCI_PBM_AFAR, pbm_err->pbm_afar,
	    PCI_PBM_AFSR, pbm_err->pbm_afsr,
	    PCI_PBM_CSR, pbm_err->pbm_ctl_stat,
	    "portid", pcmu_p->pcmu_id);
}
