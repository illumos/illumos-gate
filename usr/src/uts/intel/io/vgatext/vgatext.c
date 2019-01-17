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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/visual_io.h>
#include <sys/font.h>
#include <sys/fbio.h>

#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/vgareg.h>
#include <sys/vgasubr.h>
#include <sys/pci.h>
#include <sys/kd.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunldi.h>
#include <sys/gfx_private.h>

#define	MYNAME	"vgatext"

/*
 * Each instance of this driver has 2 minor nodes:
 * 0: for common graphics operations
 * 1: for agpmaster operations
 */
#define	GFX_MINOR		0
#define	AGPMASTER_MINOR		1

#define	MY_NBITSMINOR		1
#define	DEV2INST(dev)		(getminor(dev) >> MY_NBITSMINOR)
#define	DEV2MINOR(dev)		(getminor(dev) & ((1 << MY_NBITSMINOR) - 1))
#define	INST2NODE1(inst)	(((inst) << MY_NBITSMINOR) + GFX_MINOR)
#define	INST2NODE2(inst)	(((inst) << MY_NBITSMINOR) + AGPMASTER_MINOR)

/*
 * This variable allows for this driver to suspend even if it
 * shouldn't.  Note that by setting it, the framebuffer will probably
 * not come back.  So use it with a serial console, or with serial
 * line debugging (say, for example, if this driver is being modified
 * to support _some_ hardware doing suspend and resume).
 */
int vgatext_force_suspend = 0;

static int vgatext_open(dev_t *, int, int, cred_t *);
static int vgatext_close(dev_t, int, int, cred_t *);
static int vgatext_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int vgatext_devmap(dev_t, devmap_cookie_t, offset_t, size_t,
			    size_t *, uint_t);

static 	struct cb_ops cb_vgatext_ops = {
	vgatext_open,		/* cb_open */
	vgatext_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	vgatext_ioctl,		/* cb_ioctl */
	vgatext_devmap,		/* cb_devmap */
	nodev,			/* cb_mmap */
	ddi_devmap_segmap,	/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* cb_stream */
	D_NEW | D_MTSAFE	/* cb_flag */
};

static int vgatext_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int vgatext_attach(dev_info_t *, ddi_attach_cmd_t);
static int vgatext_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops vgatext_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	vgatext_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	vgatext_attach,		/* devo_attach */
	vgatext_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_vgatext_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

struct vgatext_softc {
	gfxp_fb_softc_ptr_t gfxp_state;
	dev_info_t		*devi;
};

static void	*vgatext_softc_head;

/* Loadable Driver stuff */

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"VGA text driver",	/* Name of the module. */
	&vgatext_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modldrv, NULL
};

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&vgatext_softc_head,
		    sizeof (struct vgatext_softc), 1)) != 0) {
	    return (e);
	}

	e = mod_install(&modlinkage);

	if (e) {
		ddi_soft_state_fini(&vgatext_softc_head);
	}
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)
		return (e);

	ddi_soft_state_fini(&vgatext_softc_head);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * handy macros
 */

#define	getsoftc(instance) ((struct vgatext_softc *)	\
			ddi_get_soft_state(vgatext_softc_head, (instance)))

#define	STREQ(a, b)	(strcmp((a), (b)) == 0)

static int
vgatext_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct vgatext_softc *softc;
	int	unit = ddi_get_instance(devi);
	int	error;
	char	name[80];


	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/*
		 * Though vgatext doesn't really know how to resume
		 * on a generic framebuffer, we should succeed, as
		 * it is far better to have no console, than potentiall
		 * have no machine.
		 */
		softc = getsoftc(unit);
		return (gfxp_fb_attach(devi, cmd, softc->gfxp_state));
	default:
		return (DDI_FAILURE);
	}

	/* DDI_ATTACH */

	/* Allocate softc struct */
	if (ddi_soft_state_zalloc(vgatext_softc_head, unit) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	softc = getsoftc(unit);
	softc->gfxp_state = gfxp_fb_softc_alloc();
	if (softc->gfxp_state == NULL) {
		(void) ddi_soft_state_free(vgatext_softc_head, unit);
		return (DDI_FAILURE);
	}

	if (gfxp_fb_attach(devi, cmd, softc->gfxp_state) != DDI_SUCCESS) {
		gfxp_fb_softc_free(softc->gfxp_state);
		(void) ddi_soft_state_free(vgatext_softc_head, unit);
		return (DDI_FAILURE);
	}

	/* link it in */
	softc->devi = devi;
	ddi_set_driver_private(devi, softc);

	(void) snprintf(name, sizeof (name), "text-%d", unit);
	error = ddi_create_minor_node(devi, name, S_IFCHR,
	    INST2NODE1(unit), DDI_NT_DISPLAY, NULL);
	if (error == DDI_SUCCESS)
		return (DDI_SUCCESS);

	(void) vgatext_detach(devi, DDI_DETACH);
	return (error);
}

static int
vgatext_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	struct vgatext_softc *softc = getsoftc(instance);


	switch (cmd) {
	case DDI_DETACH:
		(void) gfxp_fb_detach(devi, cmd, softc->gfxp_state);

		if (softc->gfxp_state != NULL)
			gfxp_fb_softc_free(softc->gfxp_state);
		ddi_remove_minor_node(devi, NULL);
		(void) ddi_soft_state_free(vgatext_softc_head, instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/*
		 * This is a generic VGA file, and therefore, cannot
		 * understand how to deal with suspend and resume on
		 * a generic interface.  So we fail any attempt to
		 * suspend.  At some point in the future, we might use
		 * this as an entrypoint for display drivers and this
		 * assumption may change.
		 *
		 * However, from a platform development perspective,
		 * it is important that this driver suspend if a
		 * developer is using a serial console and/or working
		 * on a framebuffer driver that will support suspend
		 * and resume.  Therefore, we have this module tunable
		 * (purposely using a long name) that will allow for
		 * suspend it it is set.  Otherwise we fail.
		 */
		if (vgatext_force_suspend != 0)
			return (gfxp_fb_detach(devi, cmd, softc->gfxp_state));
		else
			return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "vgatext_detach: unknown cmd 0x%x\n", cmd);
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
vgatext_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	int error;
	int instance;
	struct vgatext_softc *softc;

	error = DDI_SUCCESS;

	dev = (dev_t)arg;
	instance = DEV2INST(dev);
	softc = getsoftc(instance);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (softc == NULL || softc->devi == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) softc->devi;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}


static int
vgatext_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	struct vgatext_softc *softc = getsoftc(DEV2INST(*devp));

	if (softc == NULL)
		return (ENXIO);

	return (gfxp_fb_open(devp, flag, otyp, cred, softc->gfxp_state));
}

static int
vgatext_close(dev_t devp, int flag, int otyp, cred_t *cred)
{
	struct vgatext_softc *softc = getsoftc(DEV2INST(devp));

	if (softc == NULL)
		return (ENXIO);

	return (gfxp_fb_close(devp, flag, otyp, cred, softc->gfxp_state));
}

static int
vgatext_ioctl(
    dev_t dev,
    int cmd,
    intptr_t data,
    int mode,
    cred_t *cred,
    int *rval)
{
	struct vgatext_softc *softc = getsoftc(DEV2INST(dev));
	int err;

	switch (DEV2MINOR(dev)) {
	case GFX_MINOR:
		err = gfxp_fb_ioctl(dev, cmd, data, mode, cred, rval,
		    softc->gfxp_state);
		break;

	case AGPMASTER_MINOR:
		/*
		 * This is apparently not used anymore.  Let's log a
		 * message so we'll know if some consumer shows up.
		 * If it turns out that we actually do need to keep
		 * support for this pass-through to agpmaster, it
		 * would probably be better to use "layered" access
		 * to the AGP device (ldi_open, ldi_ioctl, ldi_close)
		 */
		cmn_err(CE_NOTE, "!vgatext wants agpmaster");
		return (EBADF);

	default:
		/* not a valid minor node */
		return (EBADF);
	}
	return (err);
}

static int
vgatext_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	struct vgatext_softc *softc;

	softc = getsoftc(DEV2INST(dev));
	if (softc == NULL) {
		cmn_err(CE_WARN, "vgatext: Can't find softstate");
		return (-1);
	}

	return (gfxp_fb_devmap(dev, dhp, off, len, maplen, model,
	    softc->gfxp_state));
}
