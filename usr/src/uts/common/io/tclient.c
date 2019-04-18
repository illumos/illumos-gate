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
 * generic mpxio leaf driver
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>


static int tcli_open(dev_t *, int, int, cred_t *);
static int tcli_close(dev_t, int, int, cred_t *);
static int tcli_read(dev_t, struct uio *, cred_t *);
static int tcli_write(dev_t, struct uio *, cred_t *);
static int tcli_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int tcli_attach(dev_info_t *, ddi_attach_cmd_t);
static int tcli_detach(dev_info_t *, ddi_detach_cmd_t);

static int tcli_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

struct dstate {
	dev_info_t *dip;
	int oflag;
};

static void *dstates;

#define	INST_TO_MINOR(i)	(i)
#define	MINOR_TO_INST(mn)	(mn)

static struct cb_ops tcli_cb_ops = {
	tcli_open,			/* open */
	tcli_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	tcli_read,			/* read */
	tcli_write,			/* write */
	tcli_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* flag */
	CB_REV,				/* cb_rev */
	nodev,				/* aread */
	nodev				/* awrite */
};


static struct dev_ops tcli_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	tcli_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	tcli_attach,		/* attach */
	tcli_detach,		/* detach */
	nodev,			/* reset */
	&tcli_cb_ops,		/* driver ops */
	(struct bus_ops *)0,	/* bus ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"vhci client test driver",
	&tcli_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&dstates,
	    sizeof (struct dstate), 0)) != 0) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0)  {
		ddi_soft_state_fini(&dstates);
	}

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)  {
		return (e);
	}
	ddi_soft_state_fini(&dstates);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
tcli_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	struct dstate *dstatep;
	int rval;

	if (cmd != DDI_ATTACH)
		return (DDI_SUCCESS);

	if (ddi_soft_state_zalloc(dstates, instance) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "%s%d: can't allocate state\n",
		    ddi_get_name(devi), instance);
		return (DDI_FAILURE);
	}

	dstatep = ddi_get_soft_state(dstates, instance);
	dstatep->dip = devi;

	rval = ddi_create_minor_node(devi, "client", S_IFCHR,
	    (INST_TO_MINOR(instance)), DDI_PSEUDO, 0);
	if (rval == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		ddi_soft_state_free(dstates, instance);
		cmn_err(CE_WARN, "%s%d: can't create minor nodes",
		    ddi_get_name(devi), instance);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tcli_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;

	if (cmd != DDI_DETACH)
		return (DDI_SUCCESS);

	ddi_remove_minor_node(devi, NULL);
	instance = ddi_get_instance(devi);
	ddi_soft_state_free(dstates, instance);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
tcli_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd != DDI_INFO_DEVT2INSTANCE)
		return (DDI_FAILURE);

	dev = (dev_t)arg;
	instance = MINOR_TO_INST(getminor(dev));
	*result = (void *)(uintptr_t)instance;
	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
tcli_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	minor_t minor;
	struct dstate *dstatep;

	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	minor = getminor(*devp);
	if ((dstatep = ddi_get_soft_state(dstates,
	    MINOR_TO_INST(minor))) == NULL)
		return (ENXIO);

	dstatep->oflag = 1;

	return (0);
}

/*ARGSUSED*/
static int
tcli_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	struct dstate *dstatep;
	minor_t minor = getminor(dev);

	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	dstatep = ddi_get_soft_state(dstates, MINOR_TO_INST(minor));

	if (dstatep == NULL)
		return (ENXIO);

	dstatep->oflag = 0;

	return (0);
}

/*ARGSUSED*/
static int
tcli_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct dstate *dstatep;
	int instance;

	instance = MINOR_TO_INST(getminor(dev));
	dstatep = ddi_get_soft_state(dstates, instance);

	if (dstatep == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
tcli_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
tcli_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return (0);
}
