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
#include <sys/open.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/policy.h>
#include "px_obj.h"
#include <sys/pci_tools.h>
#include "px_tools_ext.h"
#include <sys/pcie_pwr.h>

/*LINTLIBRARY*/

static int px_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int px_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int px_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);

struct cb_ops px_cb_ops = {
	px_open,			/* open */
	px_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	px_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pcie_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/* ARGSUSED3 */
static int
px_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	px_t		*px_p = PX_DEV_TO_SOFTSTATE(*devp);
	int		minor = getminor(*devp);
	int		rval;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	if (px_p == NULL)
		return (ENXIO);

	DBG(DBG_OPEN, px_p->px_dip, "devp=%x: flags=%x\n", devp, flags);

	/*
	 * Handle the open by tracking the device state.
	 */
	mutex_enter(&px_p->px_mutex);

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
	case PCI_TOOL_INTR_MINOR_NUM:
		break;
	default:
		/* To handle devctl and hotplug related ioctls */
		if (rval = pcie_open(px_p->px_dip, devp, flags, otyp, credp)) {
			mutex_exit(&px_p->px_mutex);
			return (rval);
		}
	}

	if (flags & FEXCL) {
		if (px_p->px_soft_state != PCI_SOFT_STATE_CLOSED) {
			mutex_exit(&px_p->px_mutex);
			DBG(DBG_OPEN, px_p->px_dip, "busy\n");
			return (EBUSY);
		}
		px_p->px_soft_state = PCI_SOFT_STATE_OPEN_EXCL;
	} else {
		if (px_p->px_soft_state == PCI_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&px_p->px_mutex);
			DBG(DBG_OPEN, px_p->px_dip, "busy\n");
			return (EBUSY);
		}
		px_p->px_soft_state = PCI_SOFT_STATE_OPEN;
	}

	mutex_exit(&px_p->px_mutex);
	return (0);
}


/* ARGSUSED */
static int
px_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	px_t		*px_p = PX_DEV_TO_SOFTSTATE(dev);
	int		minor = getminor(dev);
	int		rval;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (px_p == NULL)
		return (ENXIO);

	DBG(DBG_CLOSE, px_p->px_dip, "dev=%x: flags=%x\n", dev, flags);
	mutex_enter(&px_p->px_mutex);

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:
	case PCI_TOOL_INTR_MINOR_NUM:
		break;
	default:
		/* To handle devctl and hotplug related ioctls */
		if (rval = pcie_close(px_p->px_dip, dev, flags, otyp, credp)) {
			mutex_exit(&px_p->px_mutex);
			return (rval);
		}
	}

	px_p->px_soft_state = PCI_SOFT_STATE_CLOSED;
	mutex_exit(&px_p->px_mutex);
	return (0);
}

/* ARGSUSED */
static int
px_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	px_t		*px_p = PX_DEV_TO_SOFTSTATE(dev);
	int		minor = getminor(dev);
	dev_info_t	*dip;
	int		rv = ENOTTY;

	if (px_p == NULL)
		return (ENXIO);

	dip = px_p->px_dip;
	DBG(DBG_IOCTL, dip, "dev=%x: cmd=%x\n", dev, cmd);

#ifdef	PX_DMA_TEST
	if (IS_DMATEST(cmd)) {
		*rvalp = px_dma_test(cmd, dip, px_p, arg);
		return (0);
	}
#endif	/* PX_DMA_TEST */

	switch (PCI_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	/*
	 * PCI tools.
	 */
	case PCI_TOOL_REG_MINOR_NUM:
		switch (cmd) {
		case PCITOOL_DEVICE_SET_REG:
		case PCITOOL_DEVICE_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pxtool_dev_reg_ops(dip,
				    (void *)arg, cmd, mode);
			break;

		case PCITOOL_NEXUS_SET_REG:
		case PCITOOL_NEXUS_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pxtool_bus_reg_ops(dip,
				    (void *)arg, cmd, mode);
			break;

		default:
			rv = ENOTTY;
		}
		return (rv);
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
			rv = pxtool_intr(dip, (void *)arg, cmd, mode);
			break;

		default:
			rv = ENOTTY;
		}
		return (rv);
	default:
		/* To handle devctl and hotplug related ioctls */
		rv = pcie_ioctl(dip, dev, cmd, arg, mode, credp, rvalp);
		break;
	}

	if ((cmd & ~PPMREQ_MASK) == PPMREQ) {

		/* Need privileges to use these ioctls. */
		if (drv_priv(credp)) {
			DBG(DBG_TOOLS, dip,
			    "px_tools: Insufficient privileges\n");

			return (EPERM);
		}
		return (px_lib_pmctl(cmd, px_p));
	}

	return (rv);
}
