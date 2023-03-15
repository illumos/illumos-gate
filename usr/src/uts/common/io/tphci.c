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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * The tphci driver can be used to exercise the mpxio framework together
 * with tvhci/tclient.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/disp.h>

/* cb_ops entry points */
static int tphci_open(dev_t *, int, int, cred_t *);
static int tphci_close(dev_t, int, int, cred_t *);
static int tphci_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int tphci_attach(dev_info_t *, ddi_attach_cmd_t);
static int tphci_detach(dev_info_t *, ddi_detach_cmd_t);
static int tphci_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/* bus_ops entry points */
static int tphci_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);
static int tphci_initchild(dev_info_t *, dev_info_t *);
static int tphci_uninitchild(dev_info_t *, dev_info_t *);
static int tphci_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t, void *,
    dev_info_t **);
static int tphci_bus_unconfig(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *);
static int tphci_intr_op(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t op, ddi_intr_handle_impl_t *hdlp, void *result);


static void *tphci_state;
struct tphci_state {
	dev_info_t *dip;
};

static struct cb_ops tphci_cb_ops = {
	tphci_open,			/* open */
	tphci_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	tphci_ioctl,			/* ioctl */
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

static struct bus_ops tphci_bus_ops = {
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
	tphci_ctl,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	NULL,				/* bus_get_eventcookie */
	NULL,				/* bus_add_eventcall */
	NULL,				/* bus_remove_event */
	NULL,				/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	tphci_bus_config,		/* bus_config */
	tphci_bus_unconfig,		/* bus_unconfig */
	NULL,				/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
	tphci_intr_op			/* bus_intr_op */
};

static struct dev_ops tphci_ops = {
	DEVO_REV,
	0,
	tphci_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	tphci_attach,		/* attach and detach are mandatory */
	tphci_detach,
	nodev,			/* reset */
	&tphci_cb_ops,		/* cb_ops */
	&tphci_bus_ops,		/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"test phci driver",
	&tphci_ops
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

	if ((rval = ddi_soft_state_init(&tphci_state,
	    sizeof (struct tphci_state), 2)) != 0) {
		return (rval);
	}

	if ((rval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&tphci_state);
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

	ddi_soft_state_fini(&tphci_state);

	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
tphci_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	struct tphci_state *phci;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	phci = ddi_get_soft_state(tphci_state, getminor(*devp));
	if (phci == NULL) {
		return (ENXIO);
	}

	return (0);
}


/* ARGSUSED */
static int
tphci_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	struct tphci_state *phci;
	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	phci = ddi_get_soft_state(tphci_state, getminor(dev));
	if (phci == NULL) {
		return (ENXIO);
	}

	return (0);
}

/* ARGSUSED */
static int
tphci_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval)
{
	return (0);
}

/*
 * attach the module
 */
static int
tphci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char *vclass;
	int instance, phci_regis = 0;
	struct tphci_state *phci = NULL;

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
	 * Allocate phci data structure.
	 */
	if (ddi_soft_state_zalloc(tphci_state, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	phci = ddi_get_soft_state(tphci_state, instance);
	ASSERT(phci != NULL);
	phci->dip = dip;

	/* bus_addr has the form #,<vhci_class> */
	vclass = strchr(ddi_get_name_addr(dip), ',');
	if (vclass == NULL || vclass[1] == '\0') {
		cmn_err(CE_NOTE, "tphci invalid bus_addr %s",
		    ddi_get_name_addr(dip));
		goto attach_fail;
	}

	/*
	 * Attach this instance with the mpxio framework
	 */
	if (mdi_phci_register(vclass + 1, dip, 0) != MDI_SUCCESS) {
		cmn_err(CE_WARN, "%s mdi_phci_register failed",
		    ddi_node_name(dip));
		goto attach_fail;
	}
	phci_regis++;

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
	if (phci_regis)
		(void) mdi_phci_unregister(dip, 0);

	ddi_soft_state_free(tphci_state, instance);
	return (DDI_FAILURE);
}


/*ARGSUSED*/
static int
tphci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
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

	if (mdi_phci_unregister(dip, 0) != MDI_SUCCESS)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(tphci_state, instance);

	return (DDI_SUCCESS);
}

/*
 * tphci_getinfo()
 * Given the device number, return the devinfo pointer or the
 * instance number.
 * Note: always succeed DDI_INFO_DEVT2INSTANCE, even before attach.
 */

/*ARGSUSED*/
static int
tphci_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	struct tphci_state *phci;
	int instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		phci = ddi_get_soft_state(tphci_state, instance);
		if (phci != NULL)
			*result = phci->dip;
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

/*
 * Interrupt stuff. NO OP for pseudo drivers.
 */
/*ARGSUSED*/
static int
tphci_intr_op(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (DDI_FAILURE);
}

static int
tphci_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?tphci-device: %s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;
		return (tphci_initchild(dip, child));
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;
		return (tphci_uninitchild(dip, child));
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

static int
tphci_initchild(dev_info_t *dip, dev_info_t *child)
{
	_NOTE(ARGUNUSED(dip))
	ddi_set_name_addr(child, "0");
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tphci_uninitchild(dev_info_t *dip, dev_info_t *child)
{
	ddi_set_name_addr(child, NULL);
	return (DDI_SUCCESS);
}

static int
tp_decode_name(char *devnm, char **cname, char **paddr, char **guid)
{
	char *tmp;

	i_ddi_parse_name(devnm, cname, paddr, NULL);
	if ((strcmp(*cname, "tclient") != 0) &&
	    (strcmp(*cname, "tphci") != 0) || *paddr == NULL)
		return (-1);

	tmp = strchr(*paddr, ',');
	if (tmp == NULL || tmp[1] == '\0')
		return (-1);

	*guid = tmp + 1;
	return (0);
}

static int
tphci_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	_NOTE(ARGUNUSED(flags))
	char		*cname, *paddr, *guid, *devnm;
	mdi_pathinfo_t	*pip;
	int		len, rval;
	boolean_t	enteredv;

	switch (op) {
	case BUS_CONFIG_ONE:
		break;
	case BUS_CONFIG_DRIVER:	/* no direct children to configure */
	case BUS_CONFIG_ALL:
		return (NDI_SUCCESS);
	default:
		return (NDI_FAILURE);
	}

	/* only implement BUS_CONFIG_ONE */
	devnm = i_ddi_strdup((char *)arg, KM_SLEEP);
	len = strlen(devnm) + 1;

	/* caddr is hardcoded in the form *,<guid> */
	if (tp_decode_name(devnm, &cname, &paddr, &guid) != 0) {
		cmn_err(CE_NOTE, "tphci_bus_config -- invalid device %s",
		    (char *)arg);
		kmem_free(devnm, len);
		return (NDI_FAILURE);
	}

	mdi_devi_enter(parent, &enteredv);
	rval = mdi_pi_alloc(parent, cname, guid, paddr, 0, &pip);
	kmem_free(devnm, len);
	if (rval != MDI_SUCCESS) {
		cmn_err(CE_NOTE, "tphci_bus_config -- mdi_pi_alloc failed");
		mdi_devi_exit(parent, enteredv);
		return (NDI_FAILURE);
	}

	/*
	 * Hold the path and exit the pHCI while calling mdi_pi_online
	 * to avoid deadlock with power management of pHCI.
	 */
	mdi_hold_path(pip);
	mdi_devi_exit_phci(parent);
	rval = mdi_pi_online(pip, 0);
	mdi_devi_enter_phci(parent);
	mdi_rele_path(pip);

	if (rval != MDI_SUCCESS) {
		cmn_err(CE_NOTE, "tphci_bus_config -- mdi_pi_online failed");
		(void) mdi_pi_free(pip, 0);
		mdi_devi_exit(parent, enteredv);
		return (NDI_FAILURE);
	}

	if (childp) {
		*childp = mdi_pi_get_client(pip);
		ndi_hold_devi(*childp);
	}
	mdi_devi_exit(parent, enteredv);

	return (NDI_SUCCESS);
}

static int
tphci_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	int		rval = MDI_SUCCESS;
	boolean_t	enteredv;
	mdi_pathinfo_t	*pip, *next;
	char		*devnm, *cname, *caddr;

	switch (op) {
	case BUS_UNCONFIG_ONE:
		devnm = (char *)arg;
		i_ddi_parse_name(devnm, &cname, &caddr, NULL);
		if (strcmp(cname, "tclient") != 0)
			return (NDI_SUCCESS);	/* no such device */

		mdi_devi_enter(parent, &enteredv);
		pip = mdi_pi_find(parent, NULL, caddr);
		if (pip) {
			mdi_hold_path(pip);
			mdi_devi_exit_phci(parent);
			rval = mdi_pi_offline(pip, NDI_DEVI_REMOVE);
			mdi_devi_enter_phci(parent);
			mdi_rele_path(pip);

			if (rval == MDI_SUCCESS)
				(void) mdi_pi_free(pip, 0);
		}
		mdi_devi_exit(parent, enteredv);
		return (rval == MDI_SUCCESS ? NDI_SUCCESS : NDI_FAILURE);

	case BUS_UNCONFIG_ALL:
		if (flags & NDI_AUTODETACH)
			return (NDI_FAILURE);

		mdi_devi_enter(parent, &enteredv);
		next = mdi_get_next_client_path(parent, NULL);
		while ((pip = next) != NULL) {
			next = mdi_get_next_client_path(parent, pip);

			mdi_hold_path(pip);
			mdi_devi_exit_phci(parent);
			rval = mdi_pi_offline(pip, NDI_DEVI_REMOVE);
			mdi_devi_enter_phci(parent);
			mdi_rele_path(pip);

			if (rval != MDI_SUCCESS)
				break;
			(void) mdi_pi_free(pip, 0);
		}
		mdi_devi_exit(parent, enteredv);
		return (rval == MDI_SUCCESS ? NDI_SUCCESS : NDI_FAILURE);

	case BUS_UNCONFIG_DRIVER:	/* nothing to do */
		return (NDI_SUCCESS);

	default:
		return (NDI_FAILURE);
	}
	/*NOTREACHED*/
}
