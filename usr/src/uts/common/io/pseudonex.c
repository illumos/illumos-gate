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
 * Pseudo devices are devices implemented entirely in software; pseudonex
 * (pseudo) is the traditional nexus for pseudodevices.  Instances are
 * typically specified via driver.conf files; e.g. a leaf device which
 * should be attached below pseudonex will have an entry like:
 *
 *	name="foo" parent="/pseudo" instance=0;
 *
 * pseudonex also supports the devctl (see <sys/devctl.h>) interface via
 * its :devctl minor node.  This allows priveleged userland applications to
 * online/offline children of pseudo as needed.
 *
 * In general, we discourage widespread use of this tactic, as it may lead to a
 * proliferation of nodes in /pseudo.  It is preferred that implementors update
 * pseudo.conf, adding another 'pseudo' nexus child of /pseudo, and then use
 * that for their collection of device nodes.  To do so, add a driver alias
 * for the name of the nexus child and a line in pseudo.conf such as:
 *
 * 	name="foo" parent="/pseudo" instance=<n> valid-children="bar","baz";
 *
 * Setting 'valid-children' is important because we have an annoying problem;
 * we need to prevent pseudo devices with 'parent="pseudo"' set from binding
 * to our new pseudonex child node.  A better way might be to teach the
 * spec-node code to understand that parent="pseudo" really means
 * parent="/pseudo".
 *
 * At some point in the future, it would be desirable to extend the instance
 * database to include nexus children of pseudo.  Then we could use devctl
 * or devfs to online nexus children of pseudo, auto-selecting an instance #,
 * and the instance number selected would be preserved across reboot in
 * path_to_inst.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/devops.h>
#include <sys/instance.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/systm.h>
#include <sys/mkdev.h>

/*
 * Config information
 */
static int pseudonex_intr_op(dev_info_t *dip, dev_info_t *rdip,
	    ddi_intr_op_t op, ddi_intr_handle_impl_t *hdlp, void *result);

static int pseudonex_attach(dev_info_t *, ddi_attach_cmd_t);
static int pseudonex_detach(dev_info_t *, ddi_detach_cmd_t);
static int pseudonex_open(dev_t *, int, int, cred_t *);
static int pseudonex_close(dev_t, int, int, cred_t *);
static int pseudonex_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int pseudonex_fm_init(dev_info_t *, dev_info_t *, int,
    ddi_iblock_cookie_t *);
static int pseudonex_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);

static void *pseudonex_state;

typedef struct pseudonex_state {
	dev_info_t *pnx_devi;
	int pnx_fmcap;
	ddi_iblock_cookie_t pnx_fm_ibc;
} pseudonex_state_t;

static struct bus_ops pseudonex_bus_ops = {
	BUSO_REV,
	nullbusmap,		/* bus_map */
	NULL,			/* bus_get_intrspec */
	NULL,			/* bus_add_intrspec */
	NULL,			/* bus_remove_intrspec */
	i_ddi_map_fault,	/* bus_map_fault */
	ddi_no_dma_map,		/* bus_dma_map */
	ddi_no_dma_allochdl,	/* bus_dma_allochdl */
	NULL,			/* bus_dma_freehdl */
	NULL,			/* bus_dma_bindhdl */
	NULL,			/* bus_dma_unbindhdl */
	NULL,			/* bus_dma_flush */
	NULL,			/* bus_dma_win */
	NULL,			/* bus_dma_ctl */
	pseudonex_ctl,		/* bus_ctl */
	ddi_bus_prop_op,	/* bus_prop_op */
	0,			/* bus_get_eventcookie */
	0,			/* bus_add_eventcall */
	0,			/* bus_remove_eventcall	*/
	0,			/* bus_post_event */
	NULL,			/* bus_intr_ctl */
	NULL,			/* bus_config */
	NULL,			/* bus_unconfig */
	pseudonex_fm_init,	/* bus_fm_init */
	NULL,			/* bus_fm_fini */
	NULL,			/* bus_fm_access_enter */
	NULL,			/* bus_fm_access_exit */
	NULL,			/* bus_power */
	pseudonex_intr_op	/* bus_intr_op */
};

static struct cb_ops pseudonex_cb_ops = {
	pseudonex_open,			/* open */
	pseudonex_close,		/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pseudonex_ioctl,		/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG	/* Driver compatibility flag */
};

static struct dev_ops pseudo_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_getinfo_1to1,	/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pseudonex_attach,	/* attach */
	pseudonex_detach,	/* detach */
	nodev,			/* reset */
	&pseudonex_cb_ops,	/* driver operations */
	&pseudonex_bus_ops,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"nexus driver for 'pseudo' 1.31",
	&pseudo_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&pseudonex_state,
	    sizeof (pseudonex_state_t), 0)) != 0) {
		return (err);
	}
	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pseudonex_state);
		return (err);
	}
	return (0);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);
	ddi_soft_state_fini(&pseudonex_state);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pseudonex_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	pseudonex_state_t *pnx_state;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Save the devi for this instance in the soft_state data.
	 */
	instance = ddi_get_instance(devi);
	if (ddi_soft_state_zalloc(pseudonex_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	pnx_state = ddi_get_soft_state(pseudonex_state, instance);
	pnx_state->pnx_devi = devi;

	pnx_state->pnx_fmcap = DDI_FM_EREPORT_CAPABLE;
	ddi_fm_init(devi, &pnx_state->pnx_fmcap, &pnx_state->pnx_fm_ibc);

	if (ddi_create_minor_node(devi, "devctl", S_IFCHR, instance,
	    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
		ddi_remove_minor_node(devi, NULL);
		ddi_soft_state_free(pseudonex_state, instance);
		return (DDI_FAILURE);
	}
	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pseudonex_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);

	if (cmd == DDI_SUSPEND)
		return (DDI_SUCCESS);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_fm_fini(devi);
	ddi_remove_minor_node(devi, NULL);
	ddi_soft_state_free(pseudonex_state, instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pseudonex_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int instance;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	if (ddi_get_soft_state(pseudonex_state, instance) == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
pseudonex_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	int instance;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(dev);
	if (ddi_get_soft_state(pseudonex_state, instance) == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
pseudonex_ioctl(dev_t dev,
    int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	int instance;
	pseudonex_state_t *pnx_state;

	instance = getminor(dev);
	if ((pnx_state = ddi_get_soft_state(pseudonex_state, instance)) == NULL)
		return (ENXIO);
	ASSERT(pnx_state->pnx_devi);
	return (ndi_devctl_ioctl(pnx_state->pnx_devi, cmd, arg, mode, 0));
}

/*
 * pseudonex_intr_op: pseudonex convert an interrupt number to an
 *			interrupt. NO OP for pseudo drivers.
 */
/*ARGSUSED*/
static int
pseudonex_intr_op(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (DDI_FAILURE);
}

static int
pseudonex_check_assignment(dev_info_t *child, int test_inst)
{
	dev_info_t	*tdip;
	kmutex_t	*dmp;
	const char 	*childname = ddi_driver_name(child);
	major_t		childmaj = ddi_name_to_major((char *)childname);

	dmp = &devnamesp[childmaj].dn_lock;
	LOCK_DEV_OPS(dmp);
	for (tdip = devnamesp[childmaj].dn_head;
	    tdip != NULL; tdip = ddi_get_next(tdip)) {
		/* is this the current node? */
		if (tdip == child)
			continue;
		/* is this a duplicate instance? */
		if (test_inst == ddi_get_instance(tdip)) {
			UNLOCK_DEV_OPS(dmp);
			return (DDI_FAILURE);
		}
	}
	UNLOCK_DEV_OPS(dmp);
	return (DDI_SUCCESS);
}

/*
 * This is a nasty, slow hack.  But we're stuck with it until we do some
 * major surgery on the instance assignment subsystem, to allow pseudonode
 * instance assignment to be tracked there.
 *
 * To auto-assign an instance number, we exhaustively search the instance
 * list for each possible instance number until we find one which is unused.
 */
static int
pseudonex_auto_assign(dev_info_t *child)
{
	dev_info_t	*tdip;
	kmutex_t	*dmp;
	const char 	*childname = ddi_driver_name(child);
	major_t		childmaj = ddi_name_to_major((char *)childname);
	int inst = 0;

	dmp = &devnamesp[childmaj].dn_lock;
	LOCK_DEV_OPS(dmp);
	for (inst = 0; inst <= MAXMIN32; inst++) {
		for (tdip = devnamesp[childmaj].dn_head; tdip != NULL;
		    tdip = ddi_get_next(tdip)) {
			/* is this the current node? */
			if (tdip == child)
				continue;
			if (inst == ddi_get_instance(tdip)) {
				break;
			}
		}
		if (tdip == NULL) {
			UNLOCK_DEV_OPS(dmp);
			return (inst);
		}
	}
	UNLOCK_DEV_OPS(dmp);
	return (-1);
}

/* ARGSUSED */
static int
pseudonex_fm_init(dev_info_t *dip, dev_info_t *tdip, int cap,
    ddi_iblock_cookie_t *ibc)
{
	pseudonex_state_t *pnx_state;

	pnx_state = ddi_get_soft_state(pseudonex_state, ddi_get_instance(dip));
	ASSERT(pnx_state != NULL);
	ASSERT(ibc != NULL);
	*ibc = pnx_state->pnx_fm_ibc;
	return (pnx_state->pnx_fmcap & cap);
}

static int
pseudonex_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?pseudo-device: %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		char name[12];	/* enough for a decimal integer */
		int instance = -1;
		dev_info_t *child = (dev_info_t *)arg;
		const char *childname = ddi_driver_name(child);
		char **childlist;
		uint_t nelems;
		int auto_assign = 0;

		/*
		 * If this pseudonex node has a valid-children property,
		 * then that acts as an access control list for children
		 * allowed to attach beneath this node.  Honor it.
		 */
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "valid-children", &childlist,
		    &nelems) == DDI_PROP_SUCCESS) {
			int i, ok = 0;
			for (i = 0; i < nelems; i++) {
				if (strcmp(childlist[i], childname) == 0) {
					ok = 1;
					break;
				}
			}
			ddi_prop_free(childlist);
			if (!ok)
				return (DDI_FAILURE);
		}

		/*
		 * Look up the "instance" property. If it does not exist,
		 * check to see if the "auto-assign-instance" property is set.
		 * If not, default to using instance 0; while not ideal, this
		 * is a legacy behavior we must continue to support.
		 */
		instance = ddi_prop_get_int(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "instance", -1);
		auto_assign = ddi_prop_exists(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "auto-assign-instance");
		NDI_CONFIG_DEBUG((CE_NOTE,
		    "pseudonex: DDI_CTLOPS_INITCHILD(instance=%d, "
		    "auto-assign=%d)", instance, auto_assign));

		if (instance != -1 && auto_assign != 0) {
			NDI_CONFIG_DEBUG((CE_NOTE, "both instance and "
			    "auto-assign-instance properties specified. "
			    "Node rejected."));
			return (DDI_FAILURE);
		}

		if (instance == -1 && auto_assign == 0) {
			/* default to instance 0 if not specified */
			NDI_CONFIG_DEBUG((CE_NOTE, "defaulting to 0"));
			instance = 0;
		}

		/*
		 * If an instance has been specified, determine if this
		 * instance is already in use; if we need to pick an instance,
		 * we do it here.
		 */
		if (auto_assign) {
			if ((instance = pseudonex_auto_assign(child)) == -1) {
				NDI_CONFIG_DEBUG((CE_NOTE, "failed to "
				    "auto-select instance for %s", childname));
				return (DDI_FAILURE);
			}
			NDI_CONFIG_DEBUG((CE_NOTE,
			    "auto-selected instance for %s: %d",
			    childname, instance));
		} else {
			if (pseudonex_check_assignment(child, instance) ==
			    DDI_FAILURE) {
				NDI_CONFIG_DEBUG((CE_WARN,
				    "Duplicate instance %d of node \"%s\" "
				    "ignored.", instance, childname));
				return (DDI_FAILURE);
			}
			NDI_CONFIG_DEBUG((CE_NOTE,
			    "using fixed-assignment instance for %s: %d",
			    childname, instance));
		}

		/*
		 * Attach the instance number to the node. This allows
		 * us to have multiple instances of the same pseudo
		 * device, they will be named 'device@instance'. If this
		 * breaks programs, we may need to special-case instance 0
		 * into 'device'. Ick. devlinks appears to handle the
		 * new names ok, so if only names in /dev are used
		 * this may not be necessary.
		 */
		(void) snprintf(name, sizeof (name), "%d", instance);
		DEVI(child)->devi_instance = instance;
		ddi_set_name_addr(child, name);
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		NDI_CONFIG_DEBUG((CE_NOTE,
		    "DDI_CTLOPS_UNINITCHILD(%s, instance=%d)",
		    ddi_driver_name(child), DEVI(child)->devi_instance));

		ddi_set_name_addr(child, NULL);

		return (DDI_SUCCESS);
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
		    ddi_driver_name(dip), ddi_get_instance(dip), ctlop,
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
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
