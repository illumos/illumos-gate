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


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/* #define SBUSMEM_DEBUG */

#ifdef SBUSMEM_DEBUG
#include <sys/ddi_impldefs.h>

int sbusmem_debug_flag;
#define	sbusmem_debug	if (sbusmem_debug_flag) printf
#endif /* SBUSMEM_DEBUG */

static void *sbusmem_state_head;

struct sbusmem_unit {
	uint_t size;
	uint_t pagesize;
	dev_info_t *dip;
};

static int sbmem_open(dev_t *, int, int, cred_t *);
static int sbmem_close(dev_t, int, int, struct cred *);
static int sbmem_read(dev_t, struct uio *, cred_t *);
static int sbmem_write(dev_t, struct uio *, cred_t *);
static int sbmem_devmap(dev_t, devmap_cookie_t, offset_t, size_t,
		size_t *, uint_t);

static struct cb_ops sbmem_cb_ops = {
	sbmem_open,		/* open */
	sbmem_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	sbmem_read,		/* read */
	sbmem_write,		/* write */
	nodev,			/* ioctl */
	sbmem_devmap,		/* devmap */
	nodev,			/* mmap */
	ddi_devmap_segmap,	/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW|D_MP|D_DEVMAP|D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

static int sbmem_attach(dev_info_t *, ddi_attach_cmd_t);
static int sbmem_detach(dev_info_t *, ddi_detach_cmd_t);
static int sbmem_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct dev_ops sbmem_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sbmem_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sbmem_attach,		/* attach */
	sbmem_detach,		/* detach */
	nodev,			/* reset */
	&sbmem_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"SBus memory driver", /* Name of module. */
	&sbmem_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

static int sbmem_rw(dev_t, struct uio *, enum uio_rw, cred_t *);

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&sbusmem_state_head,
	    sizeof (struct sbusmem_unit), 1)) != 0) {
		return (error);
	}
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&sbusmem_state_head);
	}
	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&sbusmem_state_head);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
sbmem_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	struct sbusmem_unit *un;
	int error = DDI_FAILURE;
	int instance, ilen;
	uint_t size;
	char *ident;

	switch (cmd) {
	case DDI_ATTACH:
		instance = ddi_get_instance(devi);

		size = ddi_getprop(DDI_DEV_T_NONE, devi,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "size", -1);
		if (size == (uint_t)-1) {
#ifdef SBUSMEM_DEBUG
			sbusmem_debug(
			    "sbmem_attach%d: No size property\n", instance);
#endif /* SBUSMEM_DEBUG */
			break;
		}

#ifdef SBUSMEM_DEBUG
		{
			struct regspec *rp = ddi_rnumber_to_regspec(devi, 0);

			if (rp == NULL) {
				sbusmem_debug(
			    "sbmem_attach%d: No reg property\n", instance);
			} else {
				sbusmem_debug(
			    "sbmem_attach%d: slot 0x%x size 0x%x\n", instance,
				    rp->regspec_bustype, rp->regspec_size);
			}
		}
#endif /* SBUSMEM_DEBUG */

		if (ddi_getlongprop(DDI_DEV_T_ANY, devi,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "ident",
		    (caddr_t)&ident, &ilen) != DDI_PROP_SUCCESS) {
#ifdef SBUSMEM_DEBUG
			sbusmem_debug(
			    "sbmem_attach%d: No ident property\n", instance);
#endif /* SBUSMEM_DEBUG */
			break;
		}

		if (ddi_soft_state_zalloc(sbusmem_state_head,
		    instance) != DDI_SUCCESS)
			break;

		if ((un = ddi_get_soft_state(sbusmem_state_head,
		    instance)) == NULL) {
			ddi_soft_state_free(sbusmem_state_head, instance);
			break;
		}

		if (ddi_create_minor_node(devi, ident, S_IFCHR, instance,
		    DDI_PSEUDO, 0) == DDI_FAILURE) {
			kmem_free(ident, ilen);
			ddi_remove_minor_node(devi, NULL);
			ddi_soft_state_free(sbusmem_state_head, instance);
			break;
		}
		kmem_free(ident, ilen);
		un->dip = devi;
		un->size = size;
		un->pagesize = ddi_ptob(devi, 1);

#ifdef SBUSMEM_DEBUG
		sbusmem_debug("sbmem_attach%d: dip 0x%p size 0x%x\n",
		    instance, devi, size);
#endif /* SBUSMEM_DEBUG */

		ddi_report_dev(devi);
		error = DDI_SUCCESS;
		break;
	case DDI_RESUME:
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (error);
}

static int
sbmem_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;

	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(devi);
		ddi_remove_minor_node(devi, NULL);
		ddi_soft_state_free(sbusmem_state_head, instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED1*/
static int
sbmem_open(dev_t *devp, int flag, int typ, cred_t *cred)
{
	int instance;

	if (typ != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	if (ddi_get_soft_state(sbusmem_state_head, instance) == NULL) {
		return (ENXIO);
	}
	return (0);
}

/*ARGSUSED*/
static int
sbmem_close(dev_t dev, int flag, int otyp, struct cred *cred)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	return (0);
}

static int
sbmem_info(dev_info_t *dip __unused, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int instance, error = DDI_FAILURE;
	struct sbusmem_unit *un;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = getminor((dev_t)arg);
		if ((un = ddi_get_soft_state(sbusmem_state_head,
		    instance)) != NULL) {
			*result = (void *)un->dip;
			error = DDI_SUCCESS;
#ifdef SBUSMEM_DEBUG
		sbusmem_debug(
		    "sbmem_info%d: returning dip 0x%p\n", instance, un->dip);
#endif /* SBUSMEM_DEBUG */

		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		instance = getminor((dev_t)arg);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}
	return (error);
}

static int
sbmem_read(dev_t dev, struct uio *uio, cred_t *cred)
{
	return (sbmem_rw(dev, uio, UIO_READ, cred));
}

static int
sbmem_write(dev_t dev, struct uio *uio, cred_t *cred)
{
	return (sbmem_rw(dev, uio, UIO_WRITE, cred));
}

static int
sbmem_rw(dev_t dev, struct uio *uio, enum uio_rw rw, cred_t *cred __unused)
{
	uint_t c;
	struct iovec *iov;
	struct sbusmem_unit *un;
	uint_t pagesize, msize;
	int instance, error = 0;
	dev_info_t *dip;
	caddr_t reg;

	instance = getminor(dev);
	if ((un = ddi_get_soft_state(sbusmem_state_head, instance)) == NULL) {
		return (ENXIO);
	}
	dip = un->dip;
	pagesize = un->pagesize;

	while (uio->uio_resid > 0 && error == 0) {
		iov = uio->uio_iov;
		if (iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			if (uio->uio_iovcnt < 0)
				cmn_err(CE_PANIC, "sbmem_rw");
			continue;
		}

		if (uio->uio_offset > un->size) {
			return (EFAULT);
		}

		if (uio->uio_offset == un->size) {
			return (0);		/* EOF */
		}
		msize = pagesize - (uio->uio_offset & (pagesize - 1));
		if (ddi_map_regs(dip, 0, &reg, uio->uio_offset,
		    (off_t)msize) != DDI_SUCCESS) {
			return (EFAULT);
		}
		c = min(msize, (uint_t)iov->iov_len);
		if (ddi_peekpokeio(dip, uio, rw, reg, (int)c,
		    sizeof (int)) != DDI_SUCCESS)
			error = EFAULT;

		ddi_unmap_regs(dip, 0, &reg, uio->uio_offset, (off_t)msize);
	}
	return (error);
}

static int
sbmem_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model __unused)
{
	struct sbusmem_unit *un;
	int instance, error;

	instance = getminor(dev);
	if ((un = ddi_get_soft_state(sbusmem_state_head, instance)) == NULL) {
		return (ENXIO);
	}
	if (off + len > un->size) {
		return (ENXIO);
	}
	if ((error = devmap_devmem_setup(dhp, un->dip, NULL, 0,
	    off, len, PROT_ALL, DEVMAP_DEFAULTS, NULL)) < 0) {
		return (error);
	}
	*maplen = ptob(btopr(len));
	return (0);
}
