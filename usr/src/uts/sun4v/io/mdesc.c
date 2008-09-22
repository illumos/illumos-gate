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
 * sun4v machine description driver
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/mdesc.h>
#include <sys/mach_descrip.h>

#define	MDESC_NAME	"mdesc"

/*
 * Operational state flags
 */

#define	MDESC_GOT_HANDLE	0x10		/* Got mdesc handle */
#define	MDESC_BUSY		0x20		/* Device is busy */

static void		*mdesc_state_head;
static vmem_t		*mdesc_minor;
static uint16_t 	mdesc_max_opens = 256;
static uint16_t		mdesc_opens = 0;
static int		mdesc_attached = 0;
static dev_info_t	*mdesc_devi;
static kmutex_t		mdesc_lock;

struct mdesc_state {
	int		instance;
	dev_t		dev;
	kmutex_t	lock;
	kcondvar_t	cv;
	size_t		mdesc_len;
	md_t		*mdesc;
	int		flags;
};

typedef struct mdesc_state mdesc_state_t;

static int mdesc_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int mdesc_attach(dev_info_t *, ddi_attach_cmd_t);
static int mdesc_detach(dev_info_t *, ddi_detach_cmd_t);
static int mdesc_open(dev_t *, int, int, cred_t *);
static int mdesc_close(dev_t, int, int, cred_t *);
static int mdesc_read(dev_t, struct uio *, cred_t *);
static int mdesc_write(dev_t, struct uio *, cred_t *);
static int mdesc_rw(dev_t, struct uio *, enum uio_rw);
static int mdesc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops mdesc_cb_ops = {
	mdesc_open,		/* cb_open */
	mdesc_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	mdesc_read,		/* cb_read */
	nodev,			/* cb_write */
	mdesc_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	(struct streamtab *)NULL, /* cb_str */
	D_MP | D_64BIT,		/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops mdesc_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	mdesc_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	mdesc_attach,		/* devo_attach */
	mdesc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&mdesc_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Machine Description Driver",
	&mdesc_dev_ops};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};


int
_init(void)
{
	int retval;

	if ((retval = ddi_soft_state_init(&mdesc_state_head,
	    sizeof (struct mdesc_state), mdesc_max_opens)) != 0)
		return (retval);
	if ((retval = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&mdesc_state_head);
		return (retval);
	}

	return (retval);
}




int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}




int
_fini(void)
{
	int retval;

	if ((retval = mod_remove(&modlinkage)) != 0)
		return (retval);
	ddi_soft_state_fini(&mdesc_state_head);

	return (retval);
}




/*ARGSUSED*/
static int
mdesc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	struct mdesc_state *mdsp;
	int retval = DDI_FAILURE;

	ASSERT(resultp != NULL);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		mdsp = ddi_get_soft_state(mdesc_state_head,
		    getminor((dev_t)arg));
		if (mdsp != NULL) {
			*resultp = mdesc_devi;
			retval = DDI_SUCCESS;
		} else
			*resultp = NULL;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)getminor((dev_t)arg);
		retval = DDI_SUCCESS;
		break;
	}

	return (retval);
}




static int
mdesc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:

		if (ddi_create_minor_node(dip, MDESC_NAME, S_IFCHR, instance,
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s@%d: Unable to create minor node",
			    MDESC_NAME, instance);
			return (DDI_FAILURE);
		}
		ddi_report_dev(dip);
		mdesc_devi = dip;
		mdesc_minor = vmem_create("mdesc_minor", (void *) 1,
		    mdesc_max_opens, 1, NULL, NULL, NULL, 0,
		    VM_SLEEP | VMC_IDENTIFIER);
		mutex_init(&mdesc_lock, NULL, MUTEX_DRIVER, NULL);
		mdesc_attached = 1;
		return (DDI_SUCCESS);
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
mdesc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		mutex_destroy(&mdesc_lock);
		vmem_destroy(mdesc_minor);
		ddi_remove_minor_node(mdesc_devi, NULL);
		mdesc_attached = 0;
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static void
mdesc_destroy_state(mdesc_state_t *mdsp)
{
	minor_t minor = getminor(mdsp->dev);

	if (mdsp->flags & MDESC_GOT_HANDLE)
		(void) md_fini_handle(mdsp->mdesc);

	cv_destroy(&mdsp->cv);
	mutex_destroy(&mdsp->lock);
	ddi_soft_state_free(mdesc_state_head, minor);
	vmem_free(mdesc_minor, (void *)(uintptr_t)minor, 1);
}

static mdesc_state_t *
mdesc_create_state(dev_t *devp)
{
	major_t	major;
	minor_t	minor;
	mdesc_state_t *mdsp;

	minor = (minor_t)(uintptr_t)vmem_alloc(mdesc_minor, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(mdesc_state_head, minor) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s@%d: Unable to allocate state",
		    MDESC_NAME, minor);
		vmem_free(mdesc_minor, (void *)(uintptr_t)minor, 1);
		return (NULL);
	}

	mdsp = ddi_get_soft_state(mdesc_state_head, minor);

	if (devp != NULL) {
		major = getemajor(*devp);
	} else {
		major = ddi_driver_major(mdesc_devi);
	}

	mdsp->dev = makedevice(major, minor);

	if (devp != NULL)
		*devp = mdsp->dev;

	mdsp->instance = minor;

	mutex_init(&mdsp->lock, NULL, MUTEX_DRIVER, NULL);

	cv_init(&mdsp->cv, NULL, CV_DRIVER, NULL);

	mdsp->mdesc = md_get_handle();

	if (mdsp->mdesc == NULL) {
		mdesc_destroy_state(mdsp);
		return (NULL);
	}
	mdsp->flags |= MDESC_GOT_HANDLE;

	mdsp->mdesc_len = md_get_bin_size(mdsp->mdesc);

	if (mdsp->mdesc_len == 0) {
		mdesc_destroy_state(mdsp);
		mdsp = NULL;
	}

	return (mdsp);
}


/*ARGSUSED*/
static int
mdesc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	struct mdesc_state *mdsp;

	if (otyp != OTYP_CHR)
		return (EINVAL);
	if (!mdesc_attached)
		return (ENXIO);

	mutex_enter(&mdesc_lock);

	if (mdesc_opens >= mdesc_max_opens) {
		mutex_exit(&mdesc_lock);
		return (ENXIO);
	}

	mdsp = mdesc_create_state(devp);

	if (mdsp == NULL) {
		mutex_exit(&mdesc_lock);
		return (ENXIO);
	}

	mdesc_opens++;

	mutex_exit(&mdesc_lock);

	return (0);
}

/*ARGSUSED*/
static int
mdesc_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	struct mdesc_state *mdsp;
	int instance = getminor(dev);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	mutex_enter(&mdesc_lock);
	if (mdesc_opens == 0) {
		mutex_exit(&mdesc_lock);
		return (0);
	}
	mutex_exit(&mdesc_lock);

	if ((mdsp = ddi_get_soft_state(mdesc_state_head, instance)) == NULL)
		return (ENXIO);

	ASSERT(mdsp->instance == instance);

	mdesc_destroy_state(mdsp);
	mutex_enter(&mdesc_lock);
	mdesc_opens--;
	mutex_exit(&mdesc_lock);

	return (0);
}




/*ARGSUSED*/
static int
mdesc_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return (mdesc_rw(dev, uiop, UIO_READ));
}




/*ARGSUSED*/
static int
mdesc_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return (ENXIO);	/* This driver version does not allow updates */
}




static int
mdesc_rw(dev_t dev, struct uio *uiop, enum uio_rw rw)
{
	struct mdesc_state *mdsp;
	int instance = getminor(dev);
	size_t len;
	int retval;
	caddr_t buf;

	len = uiop->uio_resid;

	if ((mdsp = ddi_get_soft_state(mdesc_state_head, instance)) == NULL)
		return (ENXIO);

	ASSERT(mdsp->instance == instance);

	if (len == 0)
		return (0);

	mutex_enter(&mdsp->lock);

	while (mdsp->flags & MDESC_BUSY) {
		if (cv_wait_sig(&mdsp->cv, &mdsp->lock) == 0) {
			mutex_exit(&mdsp->lock);
			return (EINTR);
		}
	}

	if (uiop->uio_offset < 0 || uiop->uio_offset > mdsp->mdesc_len) {
		mutex_exit(&mdsp->lock);
		return (EINVAL);
	}

	if (len > (mdsp->mdesc_len - uiop->uio_offset))
		len = mdsp->mdesc_len - uiop->uio_offset;

		/* already checked that offset<mdesc_len above */
	if (len == 0) {
		mutex_exit(&mdsp->lock);
		return (rw == UIO_WRITE ? ENOSPC : 0);
	}

	mdsp->flags |= MDESC_BUSY;
	mutex_exit(&mdsp->lock);

	buf = md_get_md_raw(mdsp->mdesc);
	if (buf == NULL)
		return (ENXIO);

	retval = uiomove((void *)(buf + uiop->uio_offset),
	    len, rw, uiop);

	mutex_enter(&mdsp->lock);
	mdsp->flags &= ~MDESC_BUSY;
	cv_broadcast(&mdsp->cv);
	mutex_exit(&mdsp->lock);

	return (retval);
}




/*ARGSUSED*/
static int
mdesc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct mdesc_state *mdsp;
	int instance = getminor(dev);

	if ((mdsp = ddi_get_soft_state(mdesc_state_head, instance)) == NULL)
		return (ENXIO);

	ASSERT(mdsp->instance == instance);

	switch (cmd) {
	case MDESCIOCGSZ: {
		/*
		 * We are not guaranteed that ddi_copyout(9F) will read
		 * atomically anything larger than a byte.  Therefore we
		 * must duplicate the size before copying it out to the user.
		 */
		size_t sz = mdsp->mdesc_len;

		if (!(mode & FREAD))
			return (EACCES);

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			size32_t sz32 = (size32_t)sz;
			if (ddi_copyout(&sz32, (void *)arg, sizeof (size32_t),
			    mode) != 0)
				return (EFAULT);
			return (0);
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout(&sz, (void *)arg, sizeof (size_t),
			    mode) != 0)
				return (EFAULT);
			return (0);
		default:
			cmn_err(CE_WARN,
			    "mdesc: Invalid data model %d in ioctl\n",
			    ddi_model_convert_from(mode & FMODELS));
			return (ENOTSUP);
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&sz, (void *)arg, sizeof (size_t), mode) != 0)
			return (EFAULT);
		return (0);
#endif /* _MULTI_DATAMODEL */
	}

	default:
		return (ENOTTY);
	}
}
