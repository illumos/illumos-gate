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
 * The tvhci driver can be used to exercise the mpxio framework together
 * with tphci/tclient.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/disp.h>

/* cb_ops entry points */
static int tvhci_open(dev_t *, int, int, cred_t *);
static int tvhci_close(dev_t, int, int, cred_t *);
static int tvhci_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int tvhci_attach(dev_info_t *, ddi_attach_cmd_t);
static int tvhci_detach(dev_info_t *, ddi_detach_cmd_t);
static int tvhci_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/* bus_ops entry points */
static int tvhci_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);
static int tvhci_initchild(dev_info_t *, dev_info_t *);
static int tvhci_uninitchild(dev_info_t *, dev_info_t *);
static int tvhci_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t, void *,
    dev_info_t **);
static int tvhci_bus_unconfig(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *);
static int tvhci_intr_op(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t op, ddi_intr_handle_impl_t *hdlp, void *result);

/* vhci ops */
static int tvhci_pi_init(dev_info_t *, mdi_pathinfo_t *, int);
static int tvhci_pi_uninit(dev_info_t *, mdi_pathinfo_t *, int);
static int tvhci_pi_state_change(dev_info_t *, mdi_pathinfo_t *,
    mdi_pathinfo_state_t, uint32_t, int);
static int tvhci_failover(dev_info_t *, dev_info_t *, int);

static void *tvhci_state;
struct tvhci_state {
	dev_info_t *dip;
};

static mdi_vhci_ops_t tvhci_opinfo = {
	MDI_VHCI_OPS_REV,
	tvhci_pi_init,
	tvhci_pi_uninit,
	tvhci_pi_state_change,
	tvhci_failover
};

static struct cb_ops tvhci_cb_ops = {
	tvhci_open,			/* open */
	tvhci_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	tvhci_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP,			/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};

static struct bus_ops tvhci_bus_ops = {
	BUSO_REV,			/* busops_rev */
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_interspec */
	NULL,				/* bus_remove_interspec */
	i_ddi_map_fault,		/* bus_map_fault */
	ddi_no_dma_map,			/* bus_dma_map */
	ddi_no_dma_allochdl,		/* bus_dma_allochdl */
	NULL,				/* bus_dma_freehdl */
	NULL,				/* bus_dma_bindhdl */
	NULL,				/* bus_dma_unbindhdl */
	NULL,				/* bus_dma_flush */
	NULL,				/* bus_dma_win */
	NULL,				/* bus_dma_ctl */
	tvhci_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_event */
	NULL,				/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	tvhci_bus_config,		/* bus_config */
	tvhci_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
	tvhci_intr_op			/* bus_intr_op */
};

static struct dev_ops tvhci_ops = {
	DEVO_REV,
	0,
	tvhci_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	tvhci_attach,		/* attach and detach are mandatory */
	tvhci_detach,
	nodev,			/* reset */
	&tvhci_cb_ops,		/* cb_ops */
	&tvhci_bus_ops,		/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"test vhci driver",
	&tvhci_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int rval;

	if ((rval = ddi_soft_state_init(&tvhci_state,
	    sizeof (struct tvhci_state), 2)) != 0) {
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&tvhci_state);
	}
	return (rval);
}


int
_fini(void)
{
	int rval;

	/*
	 * don't start cleaning up until we know that the module remove
	 * has worked  -- if this works, then we know that each instance
	 * has successfully been detached
	 */
	if ((rval = mod_remove(&modlinkage)) != 0) {
		return (rval);
	}

	ddi_soft_state_fini(&tvhci_state);

	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
tvhci_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	struct tvhci_state *vhci;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	vhci = ddi_get_soft_state(tvhci_state, getminor(*devp));
	if (vhci == NULL) {
		return (ENXIO);
	}

	return (0);
}


/* ARGSUSED */
static int
tvhci_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	struct tvhci_state *vhci;
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	vhci = ddi_get_soft_state(tvhci_state, getminor(dev));
	if (vhci == NULL) {
		return (ENXIO);
	}

	return (0);
}

/* ARGSUSED */
static int
tvhci_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval)
{
	return (0);
}

/*
 * attach the module
 */
static int
tvhci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char *vclass;
	int instance, vhci_regis = 0;
	struct tvhci_state *vhci = NULL;
	dev_info_t *pdip;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		return (0);	/* nothing to do */

	default:
		return (DDI_FAILURE);
	}

	/*
	 * Allocate vhci data structure.
	 */
	if (ddi_soft_state_zalloc(tvhci_state, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	vhci = ddi_get_soft_state(tvhci_state, instance);
	ASSERT(vhci != NULL);
	vhci->dip = dip;

	/* parent must be /pshot */
	pdip = ddi_get_parent(dip);
	if (strcmp(ddi_driver_name(pdip), "pshot") != 0 ||
	    ddi_get_parent(pdip) != ddi_root_node()) {
		cmn_err(CE_NOTE, "tvhci must be under /pshot/");
		goto attach_fail;
	}

	/*
	 * XXX add mpxio-disable property. need to remove the check
	 *	from the framework
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "mpxio-disable", "no");

	/* bus_addr is the <vhci_class> */
	vclass = ddi_get_name_addr(dip);
	if (vclass == NULL || vclass[1] == '\0') {
		cmn_err(CE_NOTE, "tvhci invalid vhci class");
		goto attach_fail;
	}

	/*
	 * Attach this instance with the mpxio framework
	 */
	if (mdi_vhci_register(vclass, dip, &tvhci_opinfo, 0) != MDI_SUCCESS) {
		cmn_err(CE_WARN, "%s mdi_vhci_register failed",
		    ddi_node_name(dip));
		goto attach_fail;
	}
	vhci_regis++;

	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    instance, DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "%s ddi_create_minor_node failed",
		    ddi_node_name(dip));
		goto attach_fail;
	}

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, DDI_NO_AUTODETACH, 1);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

attach_fail:
	if (vhci_regis)
		(void) mdi_vhci_unregister(dip, 0);

	ddi_soft_state_free(tvhci_state, instance);
	return (DDI_FAILURE);
}


/*ARGSUSED*/
static int
tvhci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		return (0);	/* nothing to do */

	default:
		return (DDI_FAILURE);
	}

	if (mdi_vhci_unregister(dip, 0) != MDI_SUCCESS)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(tvhci_state, instance);

	return (DDI_SUCCESS);
}

/*
 * tvhci_getinfo()
 * Given the device number, return the devinfo pointer or the
 * instance number.
 * Note: always succeed DDI_INFO_DEVT2INSTANCE, even before attach.
 */

/*ARGSUSED*/
static int
tvhci_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	struct tvhci_state *vhci;
	int instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		vhci = ddi_get_soft_state(tvhci_state, instance);
		if (vhci != NULL)
			*result = vhci->dip;
		else {
			*result = NULL;
			return (DDI_FAILURE);
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tvhci_pi_init(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags)
{
	return (MDI_SUCCESS);
}

/*ARGSUSED*/
static int
tvhci_pi_uninit(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags)
{
	return (MDI_SUCCESS);
}

/*ARGSUSED*/
static int
tvhci_pi_state_change(dev_info_t *vdip, mdi_pathinfo_t *pip,
    mdi_pathinfo_state_t state, uint32_t ext_state, int flags)
{
	return (MDI_SUCCESS);
}

/*ARGSUSED*/
static int
tvhci_failover(dev_info_t *vdip, dev_info_t *cdip, int flags)
{
	return (MDI_SUCCESS);
}

/*
 * Interrupt stuff. NO OP for pseudo drivers.
 */
/*ARGSUSED*/
static int
tvhci_intr_op(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
tvhci_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?tvhci-device: %s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;
		return (tvhci_initchild(dip, child));
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;
		return (tvhci_uninitchild(dip, child));
	}

	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		/*
		 * These ops correspond to functions that "shouldn't" be called
		 * by a pseudo driver.  So we whine when we're called.
		 */
		cmn_err(CE_CONT, "%s%d: invalid op (%d) from %s%d\n",
		    ddi_get_name(dip), ddi_get_instance(dip),
		    ctlop, ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);

	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_BTOP:
	case DDI_CTLOPS_BTOPR:
	case DDI_CTLOPS_DETACH:
	case DDI_CTLOPS_DVMAPAGESIZE:
	case DDI_CTLOPS_IOMIN:
	case DDI_CTLOPS_POWER:
	case DDI_CTLOPS_PTOB:
	default:
		/*
		 * The ops that we pass up (default).  We pass up memory
		 * allocation oriented ops that we receive - these may be
		 * associated with pseudo HBA drivers below us with target
		 * drivers below them that use ddi memory allocation
		 * interfaces like scsi_alloc_consistent_buf.
		 */
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

/* set devi_addr to "g<guid>" */
static int
tvhci_initchild(dev_info_t *dip, dev_info_t *child)
{
	_NOTE(ARGUNUSED(dip))
	char *guid, *addr;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    MDI_CLIENT_GUID_PROP, &guid) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "tvhci_initchild - no guid property");
		return (DDI_FAILURE);
	}

	addr = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	(void) snprintf(addr, MAXNAMELEN, "g%s", guid);
	ddi_set_name_addr(child, addr);

	kmem_free(addr, MAXNAMELEN);
	ddi_prop_free(guid);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tvhci_uninitchild(dev_info_t *dip, dev_info_t *child)
{
	ddi_set_name_addr(child, NULL);
	return (DDI_SUCCESS);
}

/* form paddr by cname@<phci_inst>,<guid> */
static char *
tvh_get_phci_devname(char *cname, char *guid,
    dev_info_t *pdip, char *pname, int len)
{
	(void) snprintf(pname, len, "%s@%d,%s",
	    cname, ddi_get_instance(pdip), guid);
	return (pname);
}

/*
 * Return a pointer to the guid part of the devnm.
 * devnm format is "nodename@busaddr", busaddr format is "gGUID".
 */
static char *
tvhci_devnm_to_guid(char *devnm)
{
	char *cp = devnm;

	if (devnm == NULL)
		return (NULL);

	while (*cp != '\0' && *cp != '@')
		cp++;
	if (*cp == '@' && *(cp + 1) == 'g')
		return (cp + 2);
	return (NULL);
}

static int
tvhci_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	char *guid;

	if (op == BUS_CONFIG_ONE || op == BUS_UNCONFIG_ONE)
		guid = tvhci_devnm_to_guid((char *)arg);
	else
		guid = NULL;

	if (mdi_vhci_bus_config(pdip, flags, op, arg, child, guid)
	    == MDI_SUCCESS)
		return (NDI_SUCCESS);
	else
		return (NDI_FAILURE);
}

static int
tvhci_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	return (ndi_busop_bus_unconfig(parent, flags, op, arg));
}
