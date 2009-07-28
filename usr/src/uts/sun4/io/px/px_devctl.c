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
#include <sys/hotplug/pci/pcihp.h>
#include "px_obj.h"
#include <sys/pci_tools.h>
#include "px_tools_ext.h"
#include <sys/pcie_pwr.h>

/*LINTLIBRARY*/

static int px_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int px_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int px_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
static int px_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

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
	px_prop_op,			/* cb_prop_op */
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
	px_t *px_p;
	int rval;
	uint_t orig_px_soft_state;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	px_p = PX_DEV_TO_SOFTSTATE(*devp);
	if (px_p == NULL)
		return (ENXIO);

	/*
	 * Handle the open by tracking the device state.
	 */
	DBG(DBG_OPEN, px_p->px_dip, "devp=%x: flags=%x\n", devp, flags);
	mutex_enter(&px_p->px_mutex);
	orig_px_soft_state = px_p->px_soft_state;
	if (flags & FEXCL) {
		if (px_p->px_soft_state != PX_SOFT_STATE_CLOSED) {
			mutex_exit(&px_p->px_mutex);
			DBG(DBG_OPEN, px_p->px_dip, "busy\n");
			return (EBUSY);
		}
		px_p->px_soft_state = PX_SOFT_STATE_OPEN_EXCL;
	} else {
		if (px_p->px_soft_state == PX_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&px_p->px_mutex);
			DBG(DBG_OPEN, px_p->px_dip, "busy\n");
			return (EBUSY);
		}
		px_p->px_soft_state = PX_SOFT_STATE_OPEN;
	}

	if (px_p->px_dev_caps & PX_HOTPLUG_CAPABLE)
		if (rval = (pcihp_get_cb_ops())->cb_open(devp, flags,
		    otyp, credp)) {
			px_p->px_soft_state = orig_px_soft_state;
			mutex_exit(&px_p->px_mutex);
			return (rval);
		}

	px_p->px_open_count++;
	mutex_exit(&px_p->px_mutex);
	return (0);
}


/* ARGSUSED */
static int
px_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	px_t *px_p;
	int rval;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	px_p = PX_DEV_TO_SOFTSTATE(dev);
	if (px_p == NULL)
		return (ENXIO);

	DBG(DBG_CLOSE, px_p->px_dip, "dev=%x: flags=%x\n", dev, flags);
	mutex_enter(&px_p->px_mutex);

	if (px_p->px_dev_caps & PX_HOTPLUG_CAPABLE)
		if (rval = (pcihp_get_cb_ops())->cb_close(dev, flags,
		    otyp, credp)) {
			mutex_exit(&px_p->px_mutex);
			return (rval);
		}

	px_p->px_soft_state = PX_SOFT_STATE_CLOSED;
	px_p->px_open_count = 0;
	mutex_exit(&px_p->px_mutex);
	return (0);
}

/* ARGSUSED */
static int
px_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	px_t *px_p;
	dev_info_t *dip;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = DDI_SUCCESS;
	int minor = getminor(dev);

	px_p = PX_DEV_TO_SOFTSTATE(dev);
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

	switch (PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(minor)) {

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
		if (px_p->px_dev_caps & PX_HOTPLUG_CAPABLE)
			return ((pcihp_get_cb_ops())->cb_ioctl(dev, cmd,
			    arg, mode, credp, rvalp));
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
		DBG(DBG_IOCTL, dip, "DEVCTL_DEVICE_RESET\n");
		rv = ENOTSUP;
		break;


	case DEVCTL_BUS_QUIESCE:
		DBG(DBG_IOCTL, dip, "DEVCTL_BUS_QUIESCE\n");
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(dip, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		DBG(DBG_IOCTL, dip, "DEVCTL_BUS_UNQUIESCE\n");
		if (ndi_get_bus_state(dip, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(dip, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		DBG(DBG_IOCTL, dip, "DEVCTL_BUS_RESET\n");
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		DBG(DBG_IOCTL, dip, "DEVCTL_BUS_RESETALL\n");
		rv = ENOTSUP;
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}

static int px_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "hotplug-capable"))
		return ((pcihp_get_cb_ops())->cb_prop_op(dev, dip,
		    prop_op, flags, name, valuep, lengthp));

	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}
