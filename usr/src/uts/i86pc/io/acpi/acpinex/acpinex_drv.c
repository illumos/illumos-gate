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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */
/*
 * This module implements a nexus driver for the ACPI virtual bus.
 * It does not handle any of the DDI functions passed up to it by the child
 * drivers, but instead allows them to bubble up to the root node.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddifm.h>
#include <sys/note.h>
#include <sys/ndifm.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpidev.h>
#include <sys/acpinex.h>

/* Patchable through /etc/system. */
#ifdef	DEBUG
int acpinex_debug = 1;
#else
int acpinex_debug = 0;
#endif

/*
 * Driver globals
 */
static kmutex_t acpinex_lock;
static void *acpinex_softstates;

static int acpinex_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int acpinex_attach(dev_info_t *, ddi_attach_cmd_t);
static int acpinex_detach(dev_info_t *, ddi_detach_cmd_t);
static int acpinex_open(dev_t *, int, int, cred_t *);
static int acpinex_close(dev_t, int, int, cred_t *);
static int acpinex_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int acpinex_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp);
static int acpinex_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);
static int acpinex_fm_init_child(dev_info_t *, dev_info_t *, int,
    ddi_iblock_cookie_t *);
static void acpinex_fm_init(acpinex_softstate_t *softsp);
static void acpinex_fm_fini(acpinex_softstate_t *softsp);

extern void make_ddi_ppd(dev_info_t *, struct ddi_parent_private_data **);

/*
 * Configuration data structures
 */
static struct bus_ops acpinex_bus_ops = {
	BUSO_REV,			/* busops_rev */
	acpinex_bus_map,		/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	i_ddi_map_fault,		/* bus_map_fault */
	NULL,				/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_dma_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	acpinex_ctlops,			/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	ndi_busop_get_eventcookie,	/* bus_get_eventcookie */
	ndi_busop_add_eventcall,	/* bus_add_eventcall */
	ndi_busop_remove_eventcall,	/* bus_remove_eventcall */
	ndi_post_event,			/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	NULL,				/* bus_config */
	NULL,				/* bus_unconfig */
	acpinex_fm_init_child,		/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	NULL,				/* bus_power */
	i_ddi_intr_ops			/* bus_intr_op */
};

static struct cb_ops acpinex_cb_ops = {
	acpinex_open,			/* cb_open */
	acpinex_close,			/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	nodev,				/* cb_read */
	nodev,				/* cb_write */
	acpinex_ioctl,			/* cb_ioctl */
	nodev,				/* cb_devmap */
	nodev,				/* cb_mmap */
	nodev,				/* cb_segmap */
	nochpoll,			/* cb_poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* cb_str */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops acpinex_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* devo_refcnt */
	acpinex_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	acpinex_attach,			/* devo_attach */
	acpinex_detach,			/* devo_detach */
	nulldev,			/* devo_reset */
	&acpinex_cb_ops,		/* devo_cb_ops */
	&acpinex_bus_ops,		/* devo_bus_ops */
	nulldev,			/* devo_power */
	ddi_quiesce_not_needed		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module */
	"ACPI virtual bus driver",	/* name of module */
	&acpinex_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* rev */
	(void *)&modldrv,
	NULL
};

/*
 * Module initialization routines.
 */
int
_init(void)
{
	int error;

	/* Initialize soft state pointer. */
	if ((error = ddi_soft_state_init(&acpinex_softstates,
	    sizeof (acpinex_softstate_t), 8)) != 0) {
		cmn_err(CE_WARN,
		    "acpinex: failed to initialize soft state structure.");
		return (error);
	}

	/* Initialize event subsystem. */
	acpinex_event_init();

	/* Install the module. */
	if ((error = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "acpinex: failed to install module.");
		ddi_soft_state_fini(&acpinex_softstates);
		return (error);
	}

	mutex_init(&acpinex_lock, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_fini(void)
{
	int error;

	/* Remove the module. */
	if ((error = mod_remove(&modlinkage)) != 0) {
		return (error);
	}

	/* Shut down event subsystem. */
	acpinex_event_fini();

	/* Free the soft state info. */
	ddi_soft_state_fini(&acpinex_softstates);

	mutex_destroy(&acpinex_lock);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
acpinex_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip));

	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = ACPINEX_GET_INSTANCE(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
acpinex_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	acpinex_softstate_t *softsp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* Get and check instance number. */
	instance = ddi_get_instance(devi);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		cmn_err(CE_WARN, "acpinex: instance number %d is out of range "
		    "in acpinex_attach(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (DDI_FAILURE);
	}

	/* Get soft state structure. */
	if (ddi_soft_state_zalloc(acpinex_softstates, instance)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!acpinex: failed to allocate soft state "
		    "object in acpinex_attach().");
		return (DDI_FAILURE);
	}
	softsp = ddi_get_soft_state(acpinex_softstates, instance);

	/* Initialize soft state structure */
	softsp->ans_dip = devi;
	(void) ddi_pathname(devi, softsp->ans_path);
	if (ACPI_FAILURE(acpica_get_handle(devi, &softsp->ans_hdl))) {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: failed to get ACPI handle for %s.",
		    softsp->ans_path);
		ddi_soft_state_free(acpinex_softstates, instance);
		return (DDI_FAILURE);
	}
	mutex_init(&softsp->ans_lock, NULL, MUTEX_DRIVER, NULL);

	/* Install event handler for child/descendant objects. */
	if (acpinex_event_scan(softsp, B_TRUE) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!acpinex: failed to install event handler "
		    "for children of %s.", softsp->ans_path);
	}

	/* nothing to suspend/resume here */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, devi,
	    DDI_NO_AUTODETACH, 1);

	acpinex_fm_init(softsp);
	ddi_report_dev(devi);

	return (DDI_SUCCESS);
}

static int
acpinex_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	acpinex_softstate_t *softsp;

	instance = ddi_get_instance(devi);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		cmn_err(CE_WARN, "acpinex: instance number %d is out of range "
		    "in acpinex_detach(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (DDI_FAILURE);
	}

	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_detach()", instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		if (acpinex_event_scan(softsp, B_FALSE) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!acpinex: failed to uninstall event "
			    "handler for children of %s.", softsp->ans_path);
			return (DDI_FAILURE);
		}
		ddi_remove_minor_node(devi, NULL);
		acpinex_fm_fini(softsp);
		mutex_destroy(&softsp->ans_lock);
		ddi_soft_state_free(acpinex_softstates, instance);
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, devi,
		    DDI_NO_AUTODETACH, 0);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
name_child(dev_info_t *child, char *name, int namelen)
{
	char *unitaddr;

	ddi_set_parent_data(child, NULL);

	name[0] = '\0';
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    ACPIDEV_PROP_NAME_UNIT_ADDR, &unitaddr) == DDI_SUCCESS) {
		(void) strlcpy(name, unitaddr, namelen);
		ddi_prop_free(unitaddr);
	} else {
		ACPINEX_DEBUG(CE_NOTE, "!acpinex: failed to lookup child "
		    "unit-address prop for %p.", (void *)child);
	}

	return (DDI_SUCCESS);
}

static int
init_child(dev_info_t *child)
{
	char name[MAXNAMELEN];

	(void) name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);
	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, name_child) == DDI_SUCCESS)) {
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Control ops entry point:
 *
 * Requests handled completely:
 *      DDI_CTLOPS_INITCHILD
 *      DDI_CTLOPS_UNINITCHILD
 * All others are passed to the parent.
 */
static int
acpinex_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	int rval = DDI_SUCCESS;

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		rval = init_child((dev_info_t *)arg);
		break;

	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild((dev_info_t *)arg);
		break;

	case DDI_CTLOPS_REPORTDEV: {
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?acpinex: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	}

	default:
		rval = ddi_ctlops(dip, rdip, op, arg, result);
		break;
	}

	return (rval);
}

/* ARGSUSED */
static int
acpinex_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	ACPINEX_DEBUG(CE_WARN,
	    "!acpinex: acpinex_bus_map called and it's unimplemented.");
	return (DDI_ME_UNIMPLEMENTED);
}

static int
acpinex_open(dev_t *devi, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp));

	minor_t minor, instance;
	acpinex_softstate_t *softsp;

	minor = getminor(*devi);
	instance = ACPINEX_GET_INSTANCE(minor);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: instance number %d out of "
		    "range in acpinex_open, max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (EINVAL);
	}

	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_open().", instance);
		return (EINVAL);
	}

	if (ACPINEX_IS_DEVCTL(minor)) {
		return (0);
	} else {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: invalid minor number %d in acpinex_open().",
		    minor);
		return (EINVAL);
	}
}

static int
acpinex_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp));

	minor_t minor, instance;
	acpinex_softstate_t *softsp;

	minor = getminor(dev);
	instance = ACPINEX_GET_INSTANCE(minor);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: instance number %d out of "
		    "range in acpinex_close(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (EINVAL);
	}

	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_close().", instance);
		return (EINVAL);
	}

	if (ACPINEX_IS_DEVCTL(minor)) {
		return (0);
	} else {
		ACPINEX_DEBUG(CE_WARN,
		    "!acpinex: invalid minor number %d in acpinex_close().",
		    minor);
		return (EINVAL);
	}
}

static int
acpinex_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	_NOTE(ARGUNUSED(cmd, arg, mode, credp, rvalp));

	int rv = 0;
	minor_t minor, instance;
	acpinex_softstate_t *softsp;

	minor = getminor(dev);
	instance = ACPINEX_GET_INSTANCE(minor);
	if (instance >= ACPINEX_INSTANCE_MAX) {
		ACPINEX_DEBUG(CE_NOTE, "!acpinex: instance number %d out of "
		    "range in acpinex_ioctl(), max %d.",
		    instance, ACPINEX_INSTANCE_MAX - 1);
		return (EINVAL);
	}
	softsp = ddi_get_soft_state(acpinex_softstates, instance);
	if (softsp == NULL) {
		ACPINEX_DEBUG(CE_WARN, "!acpinex: failed to get soft state "
		    "object for instance %d in acpinex_ioctl().", instance);
		return (EINVAL);
	}

	rv = ENOTSUP;
	ACPINEX_DEBUG(CE_WARN,
	    "!acpinex: invalid minor number %d in acpinex_ioctl().", minor);

	return (rv);
}

/*
 * FMA error callback.
 * Register error handling callback with our parent. We will just call
 * our children's error callbacks and return their status.
 */
static int
acpinex_err_callback(dev_info_t *dip, ddi_fm_error_t *derr,
    const void *impl_data)
{
	_NOTE(ARGUNUSED(impl_data));

	/* Call our childrens error handlers */
	return (ndi_fm_handler_dispatch(dip, NULL, derr));
}

/*
 * Initialize our FMA resources
 */
static void
acpinex_fm_init(acpinex_softstate_t *softsp)
{
	softsp->ans_fm_cap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE;

	/*
	 * Request our capability level and get our parent's capability and ibc.
	 */
	ddi_fm_init(softsp->ans_dip, &softsp->ans_fm_cap, &softsp->ans_fm_ibc);
	if (softsp->ans_fm_cap & DDI_FM_ERRCB_CAPABLE) {
		/*
		 * Register error callback with our parent if supported.
		 */
		ddi_fm_handler_register(softsp->ans_dip, acpinex_err_callback,
		    softsp);
	}
}

/*
 * Breakdown our FMA resources
 */
static void
acpinex_fm_fini(acpinex_softstate_t *softsp)
{
	/* Clean up allocated fm structures */
	if (softsp->ans_fm_cap & DDI_FM_ERRCB_CAPABLE) {
		ddi_fm_handler_unregister(softsp->ans_dip);
	}
	ddi_fm_fini(softsp->ans_dip);
}

/*
 * Initialize FMA resources for child devices.
 * Called when child calls ddi_fm_init().
 */
static int
acpinex_fm_init_child(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	_NOTE(ARGUNUSED(tdip, cap));

	acpinex_softstate_t *softsp = ddi_get_soft_state(acpinex_softstates,
	    ddi_get_instance(dip));

	*ibc = softsp->ans_fm_ibc;

	return (softsp->ans_fm_cap);
}
