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
#include <sys/time.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/tod.h>
#include <sys/todio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>


#define	getsoftc(minor)	\
		((struct tod_softc *)ddi_get_soft_state(statep, (minor)))

/* dev_ops and cb_ops entry point function declarations */

static int	tod_attach(dev_info_t *, ddi_attach_cmd_t);
static int	tod_detach(dev_info_t *, ddi_detach_cmd_t);
static int	tod_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static int	tod_open(dev_t *, int, int, cred_t *);
static int	tod_close(dev_t, int, int, cred_t *);
static int	tod_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

struct cb_ops tod_cb_ops = {
	tod_open,
	tod_close,
	nodev,
	nodev,
	nodev,			/* dump */
	nodev,
	nodev,
	tod_ioctl,
	nodev,			/* devmap */
	nodev,
	ddi_segmap,		/* segmap */
	nochpoll,
	ddi_prop_op,
	NULL,			/* for STREAMS drivers */
	D_NEW | D_MP		/* driver compatibility flag */
};

static struct dev_ops tod_dev_ops = {
	DEVO_REV,		/* driver build version */
	0,			/* device reference count */
	tod_getinfo,
	nulldev,
	nulldev,		/* probe */
	tod_attach,
	tod_detach,
	nulldev,		/* reset */
	&tod_cb_ops,
	(struct bus_ops *)NULL,
	nulldev,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/* module configuration stuff */
static void    *statep;
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"tod driver",
	&tod_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};


int
_init(void)
{
	int    e;

	if (e = ddi_soft_state_init(&statep, sizeof (struct tod_softc), 1)) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&statep);
	}

	return (e);
}


int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0) {
		return (e);
	}

	ddi_soft_state_fini(&statep);

	return (DDI_SUCCESS);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/* ARGSUSED */
static int
tod_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	inst = getminor((dev_t)arg);
	int	retval = DDI_SUCCESS;
	struct tod_softc *softc;

	switch (cmd) {

	case DDI_INFO_DEVT2DEVINFO:
		if ((softc = getsoftc(inst)) == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else {
			*result = (void *)softc->dip;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)inst;
		break;

	default:
		retval = DDI_FAILURE;
	}

	return (retval);
}

static int
tod_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	int inst;
	struct tod_softc *softc = NULL;
	char name[80];

	switch (cmd) {

	case DDI_ATTACH:
		inst = ddi_get_instance(dip);
		/*
		 * Create minor node.  The minor device number, inst, has no
		 * meaning.  The model number above, which will be added to
		 * the device's softc, is used to direct peculiar behavior.
		 */
		(void) sprintf(name, "tod%d", inst);
		if (ddi_create_minor_node(dip, name, S_IFCHR, inst,
		    DDI_PSEUDO, NULL) == DDI_FAILURE)
			goto attach_failed;

		/*
		 * Allocate a soft state structure for this instance.
		 */
		if (ddi_soft_state_zalloc(statep, inst) != DDI_SUCCESS)
			goto attach_failed;

		softc = getsoftc(inst);
		softc->dip = dip;
		softc->cpr_stage = ~TOD_SUSPENDED;
		mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, NULL);
		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		inst = ddi_get_instance(dip);
		softc = getsoftc(inst);
		mutex_enter(&softc->mutex);
		softc->cpr_stage = ~TOD_SUSPENDED;
		mutex_exit(&softc->mutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:
	/* Free soft state, if allocated. remove minor node if added earlier */
	if (softc)
		ddi_soft_state_free(statep, inst);

	ddi_remove_minor_node(dip, NULL);

	return (DDI_FAILURE);
}

static int
tod_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	struct tod_softc *softc;

	switch (cmd) {

	case DDI_DETACH:
		inst = ddi_get_instance(dip);
		if ((softc = getsoftc(inst)) == NULL)
			return (ENXIO);
		/*
		 * Free the soft state and remove minor node added earlier.
		 */
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		inst = ddi_get_instance(dip);
		softc = getsoftc(inst);
		mutex_enter(&softc->mutex);
		softc->cpr_stage = TOD_SUSPENDED;
		mutex_exit(&softc->mutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}
}

/* ARGSUSED */
static int
tod_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	inst = getminor(*devp);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}


/* ARGSUSED */
static int
tod_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int	inst = getminor(dev);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}


/* ARGSUSED */
static int
tod_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	int		inst = getminor(dev);
	struct tod_softc *softc;
	timestruc_t	ts;

	if ((softc = getsoftc(inst)) == NULL)
		return (ENXIO);

	mutex_enter(&softc->mutex);
	while (softc->cpr_stage == TOD_SUSPENDED) {
		mutex_exit(&softc->mutex);
		(void) ddi_dev_is_needed(softc->dip, 0, 1);
		mutex_enter(&softc->mutex);
	}

	switch (cmd) {

	case TOD_CLEAR_ALARM:
		mutex_enter(&tod_lock);
		tod_ops.tod_clear_power_alarm();
		mutex_exit(&tod_lock);
		break;

	case TOD_SET_ALARM:
		if ((mode & FMODELS) == FNATIVE) {
			if (ddi_copyin((caddr_t)arg, (caddr_t)&ts.tv_sec,
			    sizeof (ts.tv_sec), mode) != 0) {
				mutex_exit(&softc->mutex);
				return (EFAULT);
			}
		} else {
			time32_t time32;

			if (ddi_copyin((caddr_t)arg,
			    &time32, sizeof (time32), mode) != 0) {
				mutex_exit(&softc->mutex);
				return (EFAULT);
			}
			ts.tv_sec = (time_t)time32;
		}
		ts.tv_nsec = 0;

		mutex_enter(&tod_lock);
		tod_ops.tod_set_power_alarm(ts);
		mutex_exit(&tod_lock);
		break;

	case TOD_GET_DATE:
		mutex_enter(&tod_lock);
		ts = tod_ops.tod_get();
		mutex_exit(&tod_lock);

		if ((mode & FMODELS) == FNATIVE) {
			if (ddi_copyout((caddr_t)&ts.tv_sec, (caddr_t)arg,
			    sizeof (ts.tv_sec), mode) != 0) {
				mutex_exit(&softc->mutex);
				return (EFAULT);
			}
		} else {
			time32_t time32;

			if (TIMEVAL_OVERFLOW(&ts)) {
				mutex_exit(&softc->mutex);
				return (EOVERFLOW);
			}

			time32 = (time32_t)ts.tv_sec;
			if (ddi_copyout(&time32,
			    (caddr_t)arg, sizeof (time32), mode) != 0) {
				mutex_exit(&softc->mutex);
				return (EFAULT);
			}
		}
		break;

	default:
		mutex_exit(&softc->mutex);
		return (EINVAL);
	}

	mutex_exit(&softc->mutex);
	return (0);
}
