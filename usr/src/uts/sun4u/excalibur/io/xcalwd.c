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
 * Excalibur fans watchdog module
 */

#include <sys/conf.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ksynch.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/xcalwd.h>
#include <sys/policy.h>
#include <sys/platform_module.h>

extern	struct	mod_ops	mod_driverops;

#define	MINOR_DEVICE_NAME	"xcalwd"

/*
 * Define your per instance state data
 */
typedef	struct xcalwd_state {
	kmutex_t	lock;
	boolean_t	started;
	int		intvl;
	timeout_id_t	tid;
	dev_info_t	*dip;
} xcalwd_state_t;

/*
 * Pointer to soft states
 */
static	void	*xcalwd_statep;

/*
 * dev_ops
 */
static	int	xcalwd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
	void *arg, void **resultp);
static	int	xcalwd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static	int	xcalwd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * cb_ops
 */
static	int	xcalwd_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static	int	xcalwd_close(dev_t dev, int flag, int otyp, cred_t *credp);
static	int	xcalwd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);
/*
 * timeout handler
 */
static	void	xcalwd_timeout(void *arg);

/*
 * cb_ops
 */
static struct cb_ops xcalwd_cb_ops = {
	xcalwd_open,			/* open */
	xcalwd_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	xcalwd_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_64BIT,		/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * dev_ops
 */
static struct dev_ops xcalwd_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	xcalwd_getinfo,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	xcalwd_attach,			/* attach */
	xcalwd_detach,			/* detach */
	nodev,				/* devo_reset */
	&xcalwd_cb_ops,			/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL,				/* devo_power */
	ddi_quiesce_not_needed,			/* devo_quiesce */
};

/*
 * modldrv
 */
static struct modldrv xcalwd_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Excalibur watchdog timer v1.7 ",	/* drv_linkinfo */
	&xcalwd_dev_ops		/* drv_dev_ops */
};

/*
 * modlinkage
 */
static struct modlinkage xcalwd_modlinkage = {
	MODREV_1,
	&xcalwd_modldrv,
	NULL
};

int
_init(void)
{
	int		error;

	/*
	 * Initialize the module state structure
	 */
	error = ddi_soft_state_init(&xcalwd_statep,
	    sizeof (xcalwd_state_t), 0);
	if (error) {
		return (error);
	}

	/*
	 * Link the driver into the system
	 */
	error = mod_install(&xcalwd_modlinkage);
	if (error) {
		ddi_soft_state_fini(&xcalwd_statep);
		return (error);
	}
	return (0);
}

int
_fini(void)
{
	int		error;

	error = mod_remove(&xcalwd_modlinkage);
	if (error != 0) {
		return (error);
	}

	/*
	 * Cleanup resources allocated in _init
	 */
	ddi_soft_state_fini(&xcalwd_statep);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&xcalwd_modlinkage, modinfop));
}

/*ARGSUSED*/
static int
xcalwd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
    void *arg, void **resultp)
{
	int	retval;
	dev_t	dev = (dev_t)arg;
	int	instance;
	xcalwd_state_t	*tsp;

	retval = DDI_FAILURE;
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = getminor(dev);
		tsp = ddi_get_soft_state(xcalwd_statep, instance);
		if (tsp == NULL)
			*resultp = NULL;
		else {
			*resultp = tsp->dip;
			retval = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)getminor(dev);
		retval = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (retval);
}

static int
xcalwd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	xcalwd_state_t	*tsp;

	switch (cmd) {
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);

		if (&plat_fan_blast == NULL) {
			cmn_err(CE_WARN, "missing plat_fan_blast function");
			return (DDI_FAILURE);
		}

		if (ddi_soft_state_zalloc(xcalwd_statep, instance) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "attach could not alloc"
			    "%d state structure", instance);
			return (DDI_FAILURE);
		}

		tsp = ddi_get_soft_state(xcalwd_statep, instance);
		if (tsp == NULL) {
			cmn_err(CE_WARN, "get state failed %d",
			    instance);
			return (DDI_FAILURE);
		}

		if (ddi_create_minor_node(dip, MINOR_DEVICE_NAME,
		    S_IFCHR, instance, DDI_PSEUDO, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "create minor node failed\n");
			return (DDI_FAILURE);
		}

		mutex_init(&tsp->lock, NULL, MUTEX_DRIVER, NULL);
		tsp->started = B_FALSE;
		tsp->intvl = 0;
		tsp->tid = 0;
		tsp->dip = dip;
		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		break;
	}
	return (DDI_FAILURE);
}

static int
xcalwd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xcalwd_state_t	*tsp;
	int			instance;

	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(dip);
		tsp = ddi_get_soft_state(xcalwd_statep, instance);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&tsp->lock);
		ddi_soft_state_free(xcalwd_statep, instance);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		break;
	}
	return (DDI_FAILURE);
}

/*
 * Watchdog timeout handler that calls plat_fan_blast to take
 * the failsafe action.
 */
static void
xcalwd_timeout(void *arg)
{
	int	instance = (int)(uintptr_t)arg;
	xcalwd_state_t	*tsp;

	if (instance < 0)
		return;

	tsp = ddi_get_soft_state(xcalwd_statep, instance);
	if (tsp == NULL)
		return;

	mutex_enter(&tsp->lock);
	if (tsp->started == B_FALSE || tsp->tid == 0) {
		tsp->tid = 0;
		mutex_exit(&tsp->lock);
		return;
	}
	mutex_exit(&tsp->lock);

	plat_fan_blast();
}

/*ARGSUSED*/
static int
xcalwd_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int			instance;

	if (secpolicy_sys_config(credp, B_FALSE) != 0)
		return (EPERM);

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	if (instance < 0)
		return (ENXIO);

	if (ddi_get_soft_state(xcalwd_statep, instance) == NULL) {
		return (ENXIO);
	}

	return (0);
}

/*ARGSUSED*/
static int
xcalwd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	xcalwd_state_t	*tsp;
	int			instance;
	timeout_id_t		tid;

	instance = getminor(dev);
	if (instance < 0)
		return (ENXIO);
	tsp = ddi_get_soft_state(xcalwd_statep, instance);
	if (tsp == NULL)
		return (ENXIO);

	mutex_enter(&tsp->lock);
	if (tsp->started == B_FALSE) {
		tsp->tid = 0;
		mutex_exit(&tsp->lock);
		return (0);
	}
	/*
	 * The watchdog is enabled. Cancel the pending timer
	 * and call plat_fan_blast.
	 */
	tsp->started = B_FALSE;
	tid = tsp->tid;
	tsp->tid = 0;
	mutex_exit(&tsp->lock);
	if (tid != 0)
		(void) untimeout(tid);
	plat_fan_blast();

	return (0);
}

/*
 * These are private ioctls for PICL environmental control plug-in
 * to use. The plug-in enables the watchdog before performing
 * altering fan speeds. It also periodically issues a keepalive
 * to the watchdog to cancel and reinstate the watchdog timer.
 * The watchdog timeout handler when executed with the watchdog
 * enabled sets fans to full blast by calling plat_fan_blast.
 */
/*ARGSUSED*/
static int
xcalwd_ioctl(dev_t dev, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rvalp)
{
	int		instance;
	xcalwd_state_t	*tsp;
	int		intvl;
	int		o_intvl;
	boolean_t	curstate;
	timeout_id_t	tid;

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	instance = getminor(dev);
	if (instance < 0)
		return (ENXIO);

	tsp = ddi_get_soft_state(xcalwd_statep, instance);
	if (tsp == NULL)
		return (ENXIO);

	switch (cmd) {
	case XCALWD_STOPWATCHDOG:
		/*
		 * cancels any pending timer and disables the timer.
		 */
		tid = 0;
		mutex_enter(&tsp->lock);
		if (tsp->started == B_FALSE) {
			mutex_exit(&tsp->lock);
			return (0);
		}
		tid = tsp->tid;
		tsp->started = B_FALSE;
		tsp->tid = 0;
		mutex_exit(&tsp->lock);
		if (tid != 0)
			(void) untimeout(tid);
		return (0);
	case XCALWD_STARTWATCHDOG:
		if (ddi_copyin((void *)arg, &intvl, sizeof (intvl), flag))
			return (EFAULT);
		if (intvl == 0)
			return (EINVAL);

		mutex_enter(&tsp->lock);
		o_intvl = tsp->intvl;
		mutex_exit(&tsp->lock);

		if (ddi_copyout((const void *)&o_intvl, (void *)arg,
		    sizeof (o_intvl), flag))
			return (EFAULT);

		mutex_enter(&tsp->lock);
		if (tsp->started == B_TRUE) {
			mutex_exit(&tsp->lock);
			return (EINVAL);
		}
		tsp->intvl = intvl;
		tsp->tid = realtime_timeout(xcalwd_timeout,
		    (void *)(uintptr_t)instance,
		    drv_usectohz(1000000) * tsp->intvl);
		tsp->started = B_TRUE;
		mutex_exit(&tsp->lock);
		return (0);
	case XCALWD_KEEPALIVE:
		tid = 0;
		mutex_enter(&tsp->lock);
		tid = tsp->tid;
		tsp->tid = 0;
		mutex_exit(&tsp->lock);
		if (tid != 0)
			(void) untimeout(tid);	/* cancel */

		mutex_enter(&tsp->lock);
		if (tsp->started == B_TRUE)	/* reinstate */
			tsp->tid = realtime_timeout(xcalwd_timeout,
			    (void *)(uintptr_t)instance,
			    drv_usectohz(1000000) * tsp->intvl);
		mutex_exit(&tsp->lock);
		return (0);
	case XCALWD_GETSTATE:
		mutex_enter(&tsp->lock);
		curstate = tsp->started;
		mutex_exit(&tsp->lock);
		if (ddi_copyout((const void *)&curstate, (void *)arg,
		    sizeof (curstate), flag))
			return (EFAULT);
		return (0);
	default:
		return (EINVAL);
	}
	/*NOTREACHED*/
}
