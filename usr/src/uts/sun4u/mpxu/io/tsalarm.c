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
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
#include <sys/strlog.h>
#include <sys/file.h>
#include <sys/lom_io.h>
#include <sys/ddi.h>
#include <sys/time.h>

#define	LOMIOCALCTL_OLD		_IOW('a', 4, ts_aldata_t)
#define	LOMIOCALSTATE_OLD	_IOWR('a', 5, ts_aldata_t)

struct tsalarm_softc {
	dev_info_t *dip;
	kmutex_t mutex;
};

#define	getsoftc(minor)	\
		((struct tsalarm_softc *)ddi_get_soft_state(statep, (minor)))
/*
 * Driver entry points
 */

/* dev_ops and cb_ops entry point function declarations */

static int	tsalarm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	tsalarm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	tsalarm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static int	tsalarm_open(dev_t *, int, int, cred_t *);
static int	tsalarm_close(dev_t, int, int, cred_t *);
static int	tsalarm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops tsalarm_cb_ops = {
	tsalarm_open,	/* open */
	tsalarm_close,	/* close */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	nodev,		/* read() */
	nodev,		/* write() */
	tsalarm_ioctl,	/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops tsalarm_ops = {
	DEVO_REV,
	0,			/* ref count */
	tsalarm_getinfo,	/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	tsalarm_attach,		/* attach() */
	tsalarm_detach,		/* detach */
	nodev,			/* reset */
	&tsalarm_cb_ops,		/* pointer to cb_ops structure */
	(struct bus_ops *)NULL,
	nulldev,		/* power() */
	ddi_quiesce_not_needed,		/* quiesce() */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;
static void    *statep;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. This is a driver */
	"tsalarm control driver",	/* Name of the module */
	&tsalarm_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

extern int rmclomv_alarm_get(int alarm_type, int *alarm_state);
extern int rmclomv_alarm_set(int alarm_type, int new_state);

int
_init(void)
{
	int    e;

	if (e = ddi_soft_state_init(&statep,
				sizeof (struct tsalarm_softc), 1)) {
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
tsalarm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int	inst = getminor((dev_t)arg);
	int	retval = DDI_SUCCESS;
	struct tsalarm_softc *softc;

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
tsalarm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	int inst;
	struct tsalarm_softc *softc = NULL;

	switch (cmd) {

	case DDI_ATTACH:
		inst = ddi_get_instance(dip);
		/*
		 * Allocate a soft state structure for this instance.
		 */
		if (ddi_soft_state_zalloc(statep, inst) != DDI_SUCCESS)
			goto attach_failed;

		softc = getsoftc(inst);
		softc->dip = dip;
		mutex_init(&softc->mutex, NULL, MUTEX_DRIVER, NULL);
		/*
		 * Create minor node.  The minor device number, inst, has no
		 * meaning.  The model number above, which will be added to
		 * the device's softc, is used to direct peculiar behavior.
		 */
		if (ddi_create_minor_node(dip, "lom", S_IFCHR, 0,
		    DDI_PSEUDO, 0) == DDI_FAILURE)
			goto attach_failed;

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:
	/* Free soft state, if allocated. remove minor node if added earlier */
	if (softc) {
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
	}

	ddi_remove_minor_node(dip, NULL);

	return (DDI_FAILURE);
}

static int
tsalarm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst;
	struct tsalarm_softc *softc;

	switch (cmd) {

	case DDI_DETACH:
		inst = ddi_get_instance(dip);
		if ((softc = getsoftc(inst)) == NULL)
			return (DDI_FAILURE);
		/*
		 * Free the soft state and remove minor node added earlier.
		 */
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&softc->mutex);
		ddi_soft_state_free(statep, inst);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}
}

/* ARGSUSED */
static int
tsalarm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int	inst = getminor(*devp);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}


/* ARGSUSED */
static int
tsalarm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int	inst = getminor(dev);

	return (getsoftc(inst) == NULL ? ENXIO : 0);
}


/* ARGSUSED */
static int
tsalarm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int		inst = getminor(dev);
	struct tsalarm_softc *softc;
	int retval = 0;
	ts_aldata_t ts_alinfo;
	int alarm_type, alarm_state = 0;

	if ((softc = getsoftc(inst)) == NULL)
		return (ENXIO);

	mutex_enter(&softc->mutex);

	switch (cmd) {

	case LOMIOCALSTATE:
	case LOMIOCALSTATE_OLD:
		{
			if (ddi_copyin((caddr_t)arg, (caddr_t)&ts_alinfo,
			    sizeof (ts_aldata_t), mode) != 0) {
				retval = EFAULT;
				goto end;
			}

			alarm_type = ts_alinfo.alarm_no;
			if ((alarm_type < ALARM_CRITICAL) ||
			    (alarm_type > ALARM_USER)) {
				retval = EINVAL;
				goto end;
			}

			retval = rmclomv_alarm_get(alarm_type, &alarm_state);

			if (retval != 0)
				goto end;

			if ((alarm_state != 0) && (alarm_state != 1)) {
				retval = EIO;
				goto end;
			}

			ts_alinfo.alarm_state = alarm_state;
			if (ddi_copyout((caddr_t)&ts_alinfo, (caddr_t)arg,
			    sizeof (ts_aldata_t), mode) != 0) {
				retval = EFAULT;
				goto end;
			}

		}
		break;

	case LOMIOCALCTL:
	case LOMIOCALCTL_OLD:
		{
			if (ddi_copyin((caddr_t)arg, (caddr_t)&ts_alinfo,
			    sizeof (ts_aldata_t), mode) != 0) {
				retval = EFAULT;
				goto end;
			}

			alarm_type = ts_alinfo.alarm_no;
			alarm_state = ts_alinfo.alarm_state;

			if ((alarm_type < ALARM_CRITICAL) ||
			    (alarm_type > ALARM_USER)) {
				retval = EINVAL;
				goto end;
			}
			if ((alarm_state < ALARM_OFF) ||
			    (alarm_state > ALARM_ON)) {
				retval = EINVAL;
				goto end;
			}

			retval = rmclomv_alarm_set(alarm_type, alarm_state);
		}
		break;

	default:
		retval = EINVAL;
		break;
	}

end:
	mutex_exit(&softc->mutex);

	return (retval);
}
