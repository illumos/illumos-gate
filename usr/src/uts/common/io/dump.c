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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Delphix (c) 2012 by Delphix. All rights reserved.
 */


/*
 * Dump driver.  Provides ioctls to get/set crash dump configuration.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/dumphdr.h>
#include <sys/dumpadm.h>
#include <sys/pathname.h>
#include <sys/file.h>
#include <vm/anon.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

static dev_info_t *dump_devi;

static int
dump_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	if (ddi_create_minor_node(devi, "dump", S_IFCHR, 0, DDI_PSEUDO, NULL) ==
	    DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	dump_devi = devi;
	return (DDI_SUCCESS);
}

static int
dump_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
dump_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = dump_devi;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
dump_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	uint64_t size;
	uint64_t dumpsize_in_pages;
	int error = 0;
	char *pathbuf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	char uuidbuf[36 + 1];
	size_t len;
	vnode_t *vp;

	switch (cmd) {
	case DIOCGETDUMPSIZE:
		if (dump_conflags & DUMP_ALL)
			size = ptob((uint64_t)physmem) / DUMP_COMPRESS_RATIO;
		else {
			/*
			 * We can't give a good answer for the DUMP_CURPROC
			 * because we won't know which process to use until it
			 * causes a panic.  We'll therefore punt and give the
			 * caller the size for the kernel.
			 *
			 * This kernel size equation takes care of the
			 * boot time kernel footprint and also accounts
			 * for availrmem changes due to user explicit locking.
			 * Refer to common/vm/vm_page.c for an explanation
			 * of these counters.
			 */
			dumpsize_in_pages = (physinstalled - obp_pages -
			    availrmem -
			    anon_segkp_pages_locked -
			    k_anoninfo.ani_mem_resv -
			    pages_locked -
			    pages_claimed -
			    pages_useclaim);

			/*
			 * Protect against vm vagaries.
			 */
			if (dumpsize_in_pages > (uint64_t)physmem)
				dumpsize_in_pages = (uint64_t)physmem;

			size = ptob(dumpsize_in_pages) / DUMP_COMPRESS_RATIO;
		}
		if (copyout(&size, (void *)arg, sizeof (size)) < 0)
			error = EFAULT;
		break;

	case DIOCGETCONF:
		mutex_enter(&dump_lock);
		*rvalp = dump_conflags;
		if (dumpvp && !(dumpvp->v_flag & VISSWAP))
			*rvalp |= DUMP_EXCL;
		mutex_exit(&dump_lock);
		break;

	case DIOCSETCONF:
		mutex_enter(&dump_lock);
		if (arg == DUMP_KERNEL || arg == DUMP_ALL ||
		    arg == DUMP_CURPROC)
			dump_conflags = arg;
		else
			error = EINVAL;
		mutex_exit(&dump_lock);
		break;

	case DIOCGETDEV:
		mutex_enter(&dump_lock);
		if (dumppath == NULL) {
			mutex_exit(&dump_lock);
			error = ENODEV;
			break;
		}
		(void) strcpy(pathbuf, dumppath);
		mutex_exit(&dump_lock);
		error = copyoutstr(pathbuf, (void *)arg, MAXPATHLEN, NULL);
		break;

	case DIOCSETDEV:
	case DIOCTRYDEV:
		if ((error = copyinstr((char *)arg, pathbuf, MAXPATHLEN,
		    NULL)) != 0 || (error = lookupname(pathbuf, UIO_SYSSPACE,
		    FOLLOW, NULLVPP, &vp)) != 0)
			break;
		mutex_enter(&dump_lock);
		if (vp->v_type == VBLK)
			error = dumpinit(vp, pathbuf, cmd == DIOCTRYDEV);
		else
			error = ENOTBLK;
		mutex_exit(&dump_lock);
		VN_RELE(vp);
		break;

	case DIOCDUMP:
		mutex_enter(&dump_lock);
		if (dumpvp == NULL)
			error = ENODEV;
		else if (dumpvp->v_flag & VISSWAP)
			error = EBUSY;
		else
			dumpsys();
		mutex_exit(&dump_lock);
		break;

	case DIOCSETUUID:
		if ((error = copyinstr((char *)arg, uuidbuf, sizeof (uuidbuf),
		    &len)) != 0)
			break;

		if (len != 37) {
			error = EINVAL;
			break;
		}

		error = dump_set_uuid(uuidbuf);
		break;

	case DIOCGETUUID:
		error = copyoutstr(dump_get_uuid(), (void *)arg, 37, NULL);
		break;

	case DIOCRMDEV:
		mutex_enter(&dump_lock);
		if (dumpvp != NULL)
			dumpfini();
		mutex_exit(&dump_lock);
		break;

	default:
		error = ENXIO;
	}

	kmem_free(pathbuf, MAXPATHLEN);
	return (error);
}

struct cb_ops dump_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	dump_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev, 			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW|D_MP		/* Driver compatibility flag */
};

struct dev_ops dump_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	dump_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	dump_attach,		/* attach */
	dump_detach,		/* detach */
	nodev,			/* reset */
	&dump_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "crash dump driver", &dump_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
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
