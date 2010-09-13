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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/cpuvar.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/open.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/policy.h>
#include <sys/pci_tools.h>
#include <sys/pci_impl.h>
#include <sys/hypervisor_api.h>
#include <sys/hotplug/pci/pcihp.h>
#include "niumx_var.h"

/*
 * NIUMX PCITool interface
 */
/*LINTLIBRARY*/

static int niumx_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int niumx_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int niumx_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int niumx_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

struct cb_ops niumx_cb_ops = {
	niumx_open,			/* open */
	niumx_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	niumx_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	niumx_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static void niumxtool_fill_in_intr_devs(pcitool_intr_dev_t *dev,
    char *driver_name, char *path_name, int instance);

static int niumxtool_intr(dev_info_t *dip, void *arg, int cmd, int mode);

int niumx_set_intr_target(niumx_devstate_t *niumxds_p, niudevino_t ino,
    niucpuid_t cpu_id);

extern void *niumx_state;
/* ARGSUSED3 */
static int
niumx_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	niumx_devstate_t *niumxds_p;
	minor_t minor = getminor(*devp);

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	niumxds_p = (niumx_devstate_t *)ddi_get_soft_state(niumx_state,
	    PCI_MINOR_NUM_TO_INSTANCE(minor));
	if (niumxds_p == NULL)
		return (ENXIO);

	/*
	 * Handle the open by tracking the device state.
	 */
	mutex_enter(&niumxds_p->niumx_mutex);
	if (flags & FEXCL) {
		if (niumxds_p->niumx_soft_state != NIUMX_SOFT_STATE_CLOSED) {
			mutex_exit(&niumxds_p->niumx_mutex);
			return (EBUSY);
		}
		niumxds_p->niumx_soft_state = NIUMX_SOFT_STATE_OPEN_EXCL;
	} else {
		if (niumxds_p->niumx_soft_state == NIUMX_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&niumxds_p->niumx_mutex);
			return (EBUSY);
		}
		niumxds_p->niumx_soft_state = NIUMX_SOFT_STATE_OPEN;
	}

	niumxds_p->niumx_open_count++;
	mutex_exit(&niumxds_p->niumx_mutex);
	return (0);
}

/* ARGSUSED */
static int
niumx_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	niumx_devstate_t *niumxds_p;
	minor_t minor = getminor(dev);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	niumxds_p = (niumx_devstate_t *)ddi_get_soft_state(niumx_state,
	    PCI_MINOR_NUM_TO_INSTANCE(minor));

	if (niumxds_p == NULL)
		return (ENXIO);

	mutex_enter(&niumxds_p->niumx_mutex);

	niumxds_p->niumx_soft_state = NIUMX_SOFT_STATE_CLOSED;
	niumxds_p->niumx_open_count = 0;
	mutex_exit(&niumxds_p->niumx_mutex);
	return (0);
}

/* ARGSUSED */
int
niumx_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	niumx_devstate_t *niumxds_p;
	dev_info_t *dip;
	int rv = DDI_SUCCESS;
	int minor = getminor(dev);

	/*
	 * Get the soft state structure for the device.
	 */
	niumxds_p = (niumx_devstate_t *)ddi_get_soft_state(niumx_state,
	    PCI_MINOR_NUM_TO_INSTANCE(minor));

	if (niumxds_p == NULL) {
		return (ENXIO);
	}

	dip = niumxds_p->dip;

	switch (minor & 0xff) {

	/*
	 * PCI tools.
	 */

	case PCI_TOOL_INTR_MINOR_NUM:

		switch (cmd) {
		case PCITOOL_DEVICE_SET_INTR:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp)) {
				rv = EPERM;
				break;
			}

		/*FALLTHRU*/
		/* These require no special privileges. */
		case PCITOOL_DEVICE_GET_INTR:
		case PCITOOL_SYSTEM_INTR_INFO:
			rv = niumxtool_intr(dip, (void *)arg, cmd, mode);
			break;

		default:
			rv = ENOTTY;
		}
		return (rv);

	default:
		break;
	}
	return (rv);
}

static int niumx_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

int
niumxtool_init(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);

	if (ddi_create_minor_node(dip, PCI_MINOR_INTR, S_IFCHR,
	    PCI_MINOR_NUM(instance, PCI_TOOL_INTR_MINOR_NUM),
	    DDI_NT_INTRCTL, 0) != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, PCI_MINOR_REG);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

void
niumxtool_uninit(dev_info_t *dip)
{
	ddi_remove_minor_node(dip, PCI_MINOR_INTR);
}

static void
niumxtool_fill_in_intr_devs(pcitool_intr_dev_t *dev, char *driver_name,
    char *path_name, int instance)
{
	(void) strncpy(dev->driver_name, driver_name, MAXMODCONFNAME-1);
	dev->driver_name[MAXMODCONFNAME] = '\0';
	(void) strncpy(dev->path, path_name, MAXPATHLEN-1);
	dev->dev_inst = instance;
}

/*ARGSUSED*/
static int
niumxtool_intr_info(dev_info_t *dip, void *arg, int mode)
{
	pcitool_intr_info_t intr_info;
	int rval = DDI_SUCCESS;

	/* If we need user_version, and to ret same user version as passed in */
	if (ddi_copyin(arg, &intr_info, sizeof (pcitool_intr_info_t), mode) !=
	    DDI_SUCCESS) {
		return (EFAULT);
	}

	intr_info.ctlr_version = 0;	/* XXX how to get real version? */
	intr_info.ctlr_type = PCITOOL_CTLR_TYPE_RISC;
	if (intr_info.flags & PCITOOL_INTR_FLAG_GET_MSI)
		intr_info.num_intr = 0;
	else
		intr_info.num_intr = NIUMX_MAX_INTRS;

	intr_info.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&intr_info, arg, sizeof (pcitool_intr_info_t), mode) !=
	    DDI_SUCCESS) {
		rval = EFAULT;
	}

	return (rval);
}


/*
 * Get interrupt information for a given ino.
 * Returns info only for inos mapped to devices.
 *
 * Returned info is valid only when iget.num_devs is returned > 0.
 * If ino is not enabled or is not mapped to a device,
 * iget.num_devs will be returned as = 0.
 */
/*ARGSUSED*/
static int
niumxtool_get_intr(dev_info_t *dip, void *arg, int mode)
{
	/* Array part isn't used here, but oh well... */
	pcitool_intr_get_t partial_iget;
	pcitool_intr_get_t *iget_p = &partial_iget;
	int copyout_rval;
	niusysino_t sysino;
	niucpuid_t cpu_id;
	niumx_devstate_t *niumxds_p;
	dev_info_t *ih_dip;
	size_t	iget_kmem_alloc_size = 0;
	char pathname[MAXPATHLEN];
	int rval = EIO;

	niumxds_p = (niumx_devstate_t *)
	    ddi_get_soft_state(niumx_state, ddi_get_instance(dip));

	/* Read in just the header part, no array section. */
	if (ddi_copyin(arg, &partial_iget, PCITOOL_IGET_SIZE(0), mode) !=
	    DDI_SUCCESS)
		return (EFAULT);

	iget_p->status = PCITOOL_IO_ERROR;
	iget_p->msi = (uint32_t)-1;

	if (iget_p->flags & PCITOOL_INTR_FLAG_GET_MSI) {
		iget_p->status = PCITOOL_INVALID_MSI;
		rval = EINVAL;
		goto done_get_intr;
	}

	/* Validate argument. */
	if (iget_p->ino > NIUMX_MAX_INTRS) {
		iget_p->status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_get_intr;
	}

	/* Caller wants device information returned. */
	if (iget_p->num_devs_ret > 0) {
		/*
		 * Allocate room.
		 * Note if num_devs == 0 iget_p remains pointing to
		 * partial_iget.
		 */
		iget_kmem_alloc_size = PCITOOL_IGET_SIZE(iget_p->num_devs_ret);
		iget_p = kmem_zalloc(iget_kmem_alloc_size, KM_SLEEP);

		/* Read in whole structure to verify there's room. */
		if (ddi_copyin(arg, iget_p, iget_kmem_alloc_size, mode) !=
		    DDI_SUCCESS) {

			/* Be consistent and just return EFAULT here. */
			kmem_free(iget_p, iget_kmem_alloc_size);

			return (EFAULT);
		}
	}

	sysino = niumxds_p->niumx_ihtable[iget_p->ino].ih_sysino;
	if (sysino == 0) {
		iget_p->status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_get_intr;
	}

	ih_dip = niumxds_p->niumx_ihtable[iget_p->ino].ih_dip;

	ddi_pathname(ih_dip, pathname);

	niumxtool_fill_in_intr_devs(&iget_p->dev[0],
	    (char *)ddi_driver_name(ih_dip),  pathname,
	    ddi_get_instance(ih_dip));

	if (hvio_intr_gettarget(sysino, &cpu_id) != H_EOK) {
		iget_p->status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_get_intr;
	}
	if (niumxds_p->niumx_ihtable[iget_p->ino].ih_cpuid != cpu_id) {
		cmn_err(CE_WARN, "CPU Does not match %x %x", cpu_id,
		    niumxds_p->niumx_ihtable[iget_p->ino].ih_cpuid);
		iget_p->status = PCITOOL_IO_ERROR;
		rval = EIO;
		goto done_get_intr;
	}
	iget_p->num_devs = 1;
	iget_p->cpu_id = niumxds_p->niumx_ihtable[iget_p->ino].ih_cpuid;
	iget_p->status = PCITOOL_SUCCESS;
	rval = DDI_SUCCESS;

done_get_intr:
	iget_p->drvr_version = PCITOOL_VERSION;
	copyout_rval =
	    ddi_copyout(iget_p, arg, PCITOOL_IGET_SIZE(iget_p->num_devs_ret),
	    mode);

	if (iget_kmem_alloc_size > 0)
		kmem_free(iget_p, iget_kmem_alloc_size);

	if (copyout_rval != DDI_SUCCESS)
		rval = EFAULT;

	return (rval);
}


/*
 * Associate a new CPU with a given ino.
 *
 * Operate only on inos which are already mapped to devices.
 */
static int
niumxtool_set_intr(dev_info_t *dip, void *arg, int mode)
{
	pcitool_intr_set_t iset;
	niucpuid_t old_cpu_id;
	int rval = EIO;
	int ret = DDI_SUCCESS;
	size_t copyinout_size;
	niumx_devstate_t *niumxds_p;

	niumxds_p = (niumx_devstate_t *)
	    ddi_get_soft_state(niumx_state, ddi_get_instance(dip));

	bzero(&iset, sizeof (pcitool_intr_set_t));

	/* Version 1 of pcitool_intr_set_t doesn't have flags. */
	copyinout_size = (size_t)&iset.flags - (size_t)&iset;

	if (ddi_copyin(arg, &iset, copyinout_size, mode) != DDI_SUCCESS)
		return (EFAULT);

	switch (iset.user_version) {
	case PCITOOL_V1:
		break;

	case PCITOOL_V2:
		copyinout_size = sizeof (pcitool_intr_set_t);
		if (ddi_copyin(arg, &iset, copyinout_size, mode) != DDI_SUCCESS)
			return (EFAULT);
		break;

	default:
		iset.status = PCITOOL_OUT_OF_RANGE;
		rval = ENOTSUP;
		goto done_set_intr;
	}

	if (iset.flags & PCITOOL_INTR_FLAG_SET_GROUP) {
		iset.status = PCITOOL_IO_ERROR;
		rval = ENOTSUP;
		goto done_set_intr;
	}

	iset.status = PCITOOL_IO_ERROR;

	iset.msi = (uint32_t)-1;

	/* Validate input argument. */
	if (iset.ino > NIUMX_MAX_INTRS) {
		iset.status = PCITOOL_INVALID_INO;
		rval = EINVAL;
		goto done_set_intr;
	}

	old_cpu_id = niumxds_p->niumx_ihtable[iset.ino].ih_cpuid;

	if ((ret = niumx_set_intr_target(niumxds_p, iset.ino,
	    iset.cpu_id)) == DDI_SUCCESS) {
		iset.cpu_id = old_cpu_id;
		iset.status = PCITOOL_SUCCESS;
		rval = DDI_SUCCESS;
		goto done_set_intr;
	}

	switch (ret) {
	case DDI_EPENDING:
		iset.status = PCITOOL_PENDING_INTRTIMEOUT;
		rval = ETIME;
		break;
	case DDI_EINVAL:
		iset.status = PCITOOL_INVALID_CPUID;
		rval = EINVAL;
		break;
	default:
		iset.status = PCITOOL_IO_ERROR;
		rval = EIO;
		break;
	}

done_set_intr:
	iset.drvr_version = PCITOOL_VERSION;
	if (ddi_copyout(&iset, arg, copyinout_size, mode) != DDI_SUCCESS)
		rval = EFAULT;

	return (rval);
}


/* Main function for handling interrupt CPU binding requests and queries. */
static int
niumxtool_intr(dev_info_t *dip, void *arg, int cmd, int mode)
{

	int rval = DDI_SUCCESS;

	switch (cmd) {

	/* Get system interrupt information. */
	case PCITOOL_SYSTEM_INTR_INFO:
		rval = niumxtool_intr_info(dip, arg, mode);
		break;

	/* Get interrupt information for a given ino. */
	case PCITOOL_DEVICE_GET_INTR:
		rval = niumxtool_get_intr(dip, arg, mode);
		break;

	/* Associate a new CPU with a given ino. */
	case PCITOOL_DEVICE_SET_INTR:
		rval = niumxtool_set_intr(dip, arg, mode);
		break;

	default:
		rval = ENOTTY;
	}

	return (rval);
}
