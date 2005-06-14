/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1990-1992,1996,1998-2003 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
					/* from S5R4 1.22 */

/*
 * Indirect driver for controlling tty.
 */
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/session.h>
#include <sys/ddi.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/fs/snode.h>
#include <sys/file.h>

#define	IS_STREAM(dev) (devopsp[getmajor(dev)]->devo_cb_ops->cb_str != NULL)

int syopen(dev_t *, int, int, cred_t *);
int syclose(dev_t, int, int, cred_t *);
int syread(dev_t, struct uio *, cred_t *);
int sywrite(dev_t, struct uio *, cred_t *);
int sypoll(dev_t, short, int, short *, struct pollhead **);
int syioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int sy_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sy_attach(dev_info_t *, ddi_attach_cmd_t);
static dev_info_t *sy_dip;		/* private copy of devinfo pointer */

struct cb_ops	sy_cb_ops = {

	syopen,			/* open */
	syclose,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	syread,			/* read */
	sywrite,		/* write */
	syioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev, 			/* segmap */
	sypoll,			/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */

};

struct dev_ops	sy_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sy_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sy_attach,		/* attach */
	nodev,			/* detach */
	nodev,			/* reset */
	&sy_cb_ops,		/* driver operations */
	(struct bus_ops *)0	/* bus operations */

};


extern int nodev(void);
extern int nulldev(void);
extern int dseekneg_flag;
extern struct mod_ops mod_driverops;
extern struct dev_ops sy_ops;

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"Indirect driver for tty 'sy' %I%",
	&sy_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}


int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
sy_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (ddi_create_minor_node(devi, "tty", S_IFCHR,
	    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (-1);
	}
	sy_dip = devi;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
sy_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev = (dev_t)arg;
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (sy_dip == NULL) {
			*result = (void *)NULL;
			error = DDI_FAILURE;
		} else {
			*result = (void *) sy_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		if (getminor(dev) != 0) {
			*result = (void *)-1;
			error = DDI_FAILURE;
		} else {
			*result = (void *)0;
			error = DDI_SUCCESS;
		}
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}


/* ARGSUSED */
int
syopen(dev_t *devp, int flag, int otyp, struct cred *cr)
{
	dev_t	ttyd;
	vnode_t	*ttyvp;
	sess_t	*sp = curproc->p_sessp;
	int	error;

	if ((ttyd = sp->s_dev) == NODEV)
		return (ENXIO);
	TTY_HOLD(sp);
	if ((ttyvp = sp->s_vp) == NULL) {
		TTY_RELE(sp);
		return (EIO);
	}

	/*
	 * Open the control terminal. The control terminal may be
	 * opened multiple times and it is closed in freectty().
	 * The multi-open, single-clone means that no cloning
	 * can happen via this open, hence the assertion.
	 */
	error = VOP_OPEN(&ttyvp, FNOCTTY | flag, cr);
	if (error == 0) {
		struct snode *csp;

		/*
		 * XXX: This driver binds a single minor number to the
		 * current controlling tty of the process issueing the
		 * open / close.  If we implement a traditional close
		 * for this driver then specfs will only invoke this driver
		 * on the last close of our one minor number - which is not
		 * what we want.  Since we already get the open / close
		 * semantic that we want from makectty and freectty, we reach
		 * back into the common snode and decrease the open count so
		 * that the specfs filtering of all but the last close
		 * does not get in our way.  To clean this up, a new cb_flag
		 * that causes specfs to call the driver on each close
		 * should be considered.
		 */
		ASSERT(ttyd == ttyvp->v_rdev);
		ASSERT(vn_matchops(ttyvp, spec_getvnodeops()));
		csp = VTOS(VTOS(ttyvp)->s_commonvp);
		mutex_enter(&csp->s_lock);
		csp->s_count--;
		mutex_exit(&csp->s_lock);
	}
	TTY_RELE(sp);
	return (error);
}

/* ARGSUSED */
int
syclose(dev_t dev, int flag, int otyp, struct cred *cr)
{
	return (0);
}

/* ARGSUSED */
int
syread(dev_t dev, struct uio *uiop, struct cred *cr)
{
	vnode_t *ttyvp;
	sess_t	*sp = curproc->p_sessp;
	int	error;

	if (sp->s_dev == NODEV)
		return (ENXIO);
	TTY_HOLD(sp);
	if ((ttyvp = sp->s_vp) == NULL) {
		TTY_RELE(sp);
		return (EIO);
	}
	error = VOP_READ(ttyvp, uiop, 0, cr, NULL);
	TTY_RELE(sp);
	return (error);

}

/* ARGSUSED */
int
sywrite(dev_t dev, struct uio *uiop, struct cred *cr)
{
	vnode_t *ttyvp;
	sess_t	*sp = curproc->p_sessp;
	int	error;

	if (sp->s_dev == NODEV)
		return (ENXIO);
	TTY_HOLD(sp);
	if ((ttyvp = sp->s_vp) == NULL) {
		TTY_RELE(sp);
		return (EIO);
	}

	error = VOP_WRITE(ttyvp, uiop, 0, cr, NULL);
	TTY_RELE(sp);
	return (error);
}


/* ARGSUSED */
int
syioctl(dev_t dev, int cmd, intptr_t arg, int mode, struct cred *cr,
	int *rvalp)
{
	vnode_t *ttyvp;
	sess_t	*sp = curproc->p_sessp;
	int	error;

	if (sp->s_dev == NODEV)
		return (ENXIO);
	TTY_HOLD(sp);
	if ((ttyvp = sp->s_vp) == NULL) {
		TTY_RELE(sp);
		return (EIO);
	}
	error = VOP_IOCTL(ttyvp, cmd, arg, mode, cr, rvalp);
	TTY_RELE(sp);
	return (error);
}



/* ARGSUSED */
int
sypoll(dev_t dev, short events, int anyyet, short *reventsp,
	struct pollhead **phpp)
{
	vnode_t *ttyvp;
	sess_t  *sp = curproc->p_sessp;
	int	error;

	if (sp->s_dev == NODEV)
		return (ENXIO);
	TTY_HOLD(sp);
	if ((ttyvp = sp->s_vp) == NULL) {
		TTY_RELE(sp);
		return (EIO);
	}
	error = VOP_POLL(ttyvp, events, anyyet, reventsp, phpp);
	TTY_RELE(sp);
	return (error);
}
