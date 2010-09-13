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
 * PCI nexus HotPlug devctl interface
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci/pci_obj.h>
#include <sys/pci_tools.h>
#include <sys/pci/pci_tools_ext.h>
#include <sys/open.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/policy.h>
#include <sys/hotplug/pci/pcihp.h>

/*LINTLIBRARY*/

static int pci_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int pci_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int pci_devctl_ioctl(dev_info_t *dip, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int pci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int pci_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

struct cb_ops pci_cb_ops = {
	pci_open,			/* open */
	pci_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pci_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pci_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

extern struct cb_ops *pcihp_ops;

/* ARGSUSED3 */
static int
pci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	pci_t *pci_p;
	int rval;
	uint_t orig_pci_soft_state;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	pci_p = DEV_TO_SOFTSTATE(*devp);
	if (pci_p == NULL)
		return (ENXIO);

	/*
	 * Handle the open by tracking the device state.
	 */
	DEBUG2(DBG_OPEN, pci_p->pci_dip, "devp=%x: flags=%x\n", devp, flags);
	mutex_enter(&pci_p->pci_mutex);
	orig_pci_soft_state = pci_p->pci_soft_state;
	if (flags & FEXCL) {
		if (pci_p->pci_soft_state != PCI_SOFT_STATE_CLOSED) {
			mutex_exit(&pci_p->pci_mutex);
			DEBUG0(DBG_OPEN, pci_p->pci_dip, "busy\n");
			return (EBUSY);
		}
		pci_p->pci_soft_state = PCI_SOFT_STATE_OPEN_EXCL;
	} else {
		if (pci_p->pci_soft_state == PCI_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&pci_p->pci_mutex);
			DEBUG0(DBG_OPEN, pci_p->pci_dip, "busy\n");
			return (EBUSY);
		}
		pci_p->pci_soft_state = PCI_SOFT_STATE_OPEN;
	}

	if (pci_p->hotplug_capable == B_TRUE) {
		if (rval = pcihp_ops->cb_open(devp, flags, otyp, credp)) {
			pci_p->pci_soft_state = orig_pci_soft_state;
			mutex_exit(&pci_p->pci_mutex);
			return (rval);
		}
	}

	mutex_exit(&pci_p->pci_mutex);

	return (0);
}


/* ARGSUSED */
static int
pci_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	pci_t *pci_p;
	int rval;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	pci_p = DEV_TO_SOFTSTATE(dev);
	if (pci_p == NULL)
		return (ENXIO);

	DEBUG2(DBG_CLOSE, pci_p->pci_dip, "dev=%x: flags=%x\n", dev, flags);
	mutex_enter(&pci_p->pci_mutex);

	if (pci_p->hotplug_capable == B_TRUE)
		if (rval = pcihp_ops->cb_close(dev, flags, otyp, credp)) {
			mutex_exit(&pci_p->pci_mutex);
			return (rval);
		}

	pci_p->pci_soft_state = PCI_SOFT_STATE_CLOSED;
	mutex_exit(&pci_p->pci_mutex);
	return (0);
}

/* ARGSUSED */
static int
pci_devctl_ioctl(dev_info_t *dip, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int rv = 0;
	struct devctl_iocdata *dcp;
	uint_t bus_state;

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(dip, cmd, arg, mode, 0));
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		DEBUG0(DBG_IOCTL, dip, "DEVCTL_DEVICE_RESET\n");
		rv = ENOTSUP;
		break;


	case DEVCTL_BUS_QUIESCE:
		DEBUG0(DBG_IOCTL, dip, "DEVCTL_BUS_QUIESCE\n");
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(dip, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		DEBUG0(DBG_IOCTL, dip, "DEVCTL_BUS_UNQUIESCE\n");
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(dip, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		DEBUG0(DBG_IOCTL, dip, "DEVCTL_BUS_RESET\n");
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		DEBUG0(DBG_IOCTL, dip, "DEVCTL_BUS_RESETALL\n");
		rv = ENOTSUP;
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}


static int
pci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	pci_t *pci_p;
	dev_info_t *dip;
	minor_t minor = getminor(dev);
	int rv = ENOTTY;

	pci_p = DEV_TO_SOFTSTATE(dev);
	if (pci_p == NULL)
		return (ENXIO);

	dip = pci_p->pci_dip;
	DEBUG2(DBG_IOCTL, dip, "dev=%x: cmd=%x\n", dev, cmd);

#ifdef PCI_DMA_TEST
	if (IS_DMATEST(cmd)) {
		*rvalp = pci_dma_test(cmd, dip, pci_p, arg);
		return (0);
	}
#endif

	switch (PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:

		switch (cmd) {
		case PCITOOL_DEVICE_SET_REG:
		case PCITOOL_DEVICE_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_dev_reg_ops(
				    dev, (void *)arg, cmd, mode);
			break;

		case PCITOOL_NEXUS_SET_REG:
		case PCITOOL_NEXUS_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_bus_reg_ops(
				    dev, (void *)arg, cmd, mode);
			break;
		}

		break;

	case PCI_TOOL_INTR_MINOR_NUM:

		switch (cmd) {
		case PCITOOL_DEVICE_SET_INTR:

			/* Require PRIV_SYS_RES_CONFIG, same as psradm */
			if (secpolicy_ponline(credp)) {
				rv = EPERM;
				break;
			}

		/*FALLTHRU*/
		/* These require no special privileges. */
		case PCITOOL_DEVICE_GET_INTR:
		case PCITOOL_SYSTEM_INTR_INFO:
			rv = pcitool_intr_admn(dev, (void *)arg, cmd, mode);
			break;
		}

		break;

	/*
	 * All non-PCItool ioctls go through here, including:
	 *   devctl ioctls with minor number PCIHP_DEVCTL_MINOR and
	 *   those for attachment points with where minor number is the
	 *   device number.
	 */
	default:
		if (pci_p->hotplug_capable == B_TRUE)
			rv = pcihp_ops->cb_ioctl(
			    dev, cmd, arg, mode, credp, rvalp);
		else
			rv = pci_devctl_ioctl(
			    dip, cmd, arg, mode, credp, rvalp);
		break;
	}

	return (rv);
}

static int pci_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "hotplug-capable"))
		return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip,
		    prop_op, flags, name, valuep, lengthp));

	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}
