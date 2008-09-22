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


#include <sys/stat.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/mode.h>
#include <sys/note.h>
#include <sys/i2c/misc/i2c_svc.h>
#include <sys/i2c/clients/tda8444_impl.h>

/*
 * cb ops
 */
static int tda8444_open(dev_t *, int, int, cred_t *);
static int tda8444_close(dev_t, int, int, cred_t *);
static int tda8444_read(dev_t dev, struct uio *uiop, cred_t *cred_p);
static int tda8444_write(dev_t dev, struct uio *uiop, cred_t *cred_p);
static int tda8444_io(dev_t dev, struct uio *uiop, int rw);
/*
 * dev ops
 */
static int tda8444_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int tda8444_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int tda8444_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct cb_ops tda8444_cbops = {
	tda8444_open,			/* open */
	tda8444_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	tda8444_read,			/* read */
	tda8444_write,			/* write */
	nodev,				/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops tda8444_ops = {
	DEVO_REV,
	0,
	tda8444_info,
	nulldev,
	nulldev,
	tda8444_attach,
	tda8444_detach,
	nodev,
	&tda8444_cbops,
	NULL,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv tda8444_modldrv = {
	&mod_driverops,		/* type of module - driver */
	"tda8444 device driver",
	&tda8444_ops,
};

static struct modlinkage tda8444_modlinkage = {
	MODREV_1,
	&tda8444_modldrv,
	0
};

static void *tda8444_soft_statep;
static int tda8444_debug = 0;

int
_init(void)
{
	int    error;

	error = mod_install(&tda8444_modlinkage);
	if (error == 0) {
		(void) ddi_soft_state_init(&tda8444_soft_statep,
		    sizeof (struct tda8444_unit), TDA8444_MAX_DACS);
	}

	return (error);
}

int
_fini(void)
{
	int    error;

	error = mod_remove(&tda8444_modlinkage);
	if (error == 0) {
		ddi_soft_state_fini(&tda8444_soft_statep);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&tda8444_modlinkage, modinfop));
}

/* ARGSUSED */
static int
tda8444_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = TDA8444_MINOR_TO_DEVINST(dev);
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
tda8444_do_resume(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	struct tda8444_unit *unitp;
	int channel;
	int ret = DDI_SUCCESS;

	unitp = (struct tda8444_unit *)
	    ddi_get_soft_state(tda8444_soft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	for (channel = 0; channel < TDA8444_CHANS; channel++) {
		unitp->tda8444_transfer->i2c_wbuf[0] = TDA8444_REGBASE |
		    channel;
		unitp->tda8444_transfer->i2c_wbuf[1] =
		    unitp->tda8444_output[channel];
		DPRINTF(RESUME, ("tda8444_resume: setting channel %d to %d",
		    channel, unitp->tda8444_output[channel]));
		if (i2c_transfer(unitp->tda8444_hdl,
		    unitp->tda8444_transfer) != I2C_SUCCESS) {
			ret = DDI_FAILURE;
		}
	}

	mutex_enter(&unitp->tda8444_mutex);
	unitp->tda8444_flags = 0;
	cv_signal(&unitp->tda8444_cv);
	mutex_exit(&unitp->tda8444_mutex);

	return (ret);
}

static int
tda8444_do_attach(dev_info_t *dip)
{
	struct tda8444_unit *unitp;
	char name[MAXNAMELEN];
	int instance;
	minor_t minor;
	int i;

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(tda8444_soft_statep, instance) != 0) {
		cmn_err(CE_WARN, "%s%d failed to zalloc softstate",
		    ddi_get_name(dip), instance);

		return (DDI_FAILURE);
	}

	unitp = ddi_get_soft_state(tda8444_soft_statep, instance);

	if (unitp == NULL) {
		return (DDI_FAILURE);
	}

	(void) snprintf(unitp->tda8444_name, sizeof (unitp->tda8444_name),
	    "%s%d", ddi_driver_name(dip), instance);

	for (i = 0; i < TDA8444_CHANS; i++) {
		(void) sprintf(name, "%d", i);
		minor = TDA8444_CHANNEL_TO_MINOR(i) |
		    TDA8444_DEVINST_TO_MINOR(instance);
		if (ddi_create_minor_node(dip, name, S_IFCHR, minor,
		    TDA8444_NODE_TYPE, NULL) == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s ddi_create_minor_node failed",
			    unitp->tda8444_name);
			ddi_soft_state_free(tda8444_soft_statep, instance);
			ddi_remove_minor_node(dip, NULL);

			return (DDI_FAILURE);
		}
		unitp->tda8444_output[i] = TDA8444_UNKNOWN_OUT;
	}

	/*
	 * preallocate a single buffer for all writes
	 */
	if (i2c_transfer_alloc(unitp->tda8444_hdl, &unitp->tda8444_transfer,
	    2, 0, I2C_SLEEP) != I2C_SUCCESS) {
		cmn_err(CE_WARN, "i2c_transfer_alloc failed");
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(tda8444_soft_statep, instance);

		return (DDI_FAILURE);
	}
	unitp->tda8444_transfer->i2c_flags = I2C_WR;
	unitp->tda8444_transfer->i2c_version = I2C_XFER_REV;

	if (i2c_client_register(dip, &unitp->tda8444_hdl) != I2C_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		cmn_err(CE_WARN, "i2c_client_register failed");
		ddi_soft_state_free(tda8444_soft_statep, instance);
		i2c_transfer_free(unitp->tda8444_hdl, unitp->tda8444_transfer);

		return (DDI_FAILURE);
	}

	mutex_init(&unitp->tda8444_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&unitp->tda8444_cv, NULL, CV_DRIVER, NULL);

	return (DDI_SUCCESS);
}

static int
tda8444_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:

		return (tda8444_do_attach(dip));
	case DDI_RESUME:

		return (tda8444_do_resume(dip));
	default:

		return (DDI_FAILURE);
	}
}

static int
tda8444_do_detach(dev_info_t *dip)
{
	struct tda8444_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(tda8444_soft_statep, instance);

	i2c_transfer_free(unitp->tda8444_hdl, unitp->tda8444_transfer);
	i2c_client_unregister(unitp->tda8444_hdl);
	ddi_remove_minor_node(dip, NULL);
	mutex_destroy(&unitp->tda8444_mutex);
	cv_destroy(&unitp->tda8444_cv);
	ddi_soft_state_free(tda8444_soft_statep, instance);

	return (DDI_SUCCESS);
}

static int
tda8444_do_suspend(dev_info_t *dip)
{
	struct tda8444_unit *unitp;
	int instance;

	instance = ddi_get_instance(dip);
	unitp = ddi_get_soft_state(tda8444_soft_statep, instance);

	/*
	 * Set the busy flag so that future transactions block
	 * until resume.
	 */
	mutex_enter(&unitp->tda8444_mutex);
	while (unitp->tda8444_flags == TDA8444_BUSY) {
		if (cv_wait_sig(&unitp->tda8444_cv,
		    &unitp->tda8444_mutex) <= 0) {
			mutex_exit(&unitp->tda8444_mutex);

			return (DDI_FAILURE);
		}
	}
	unitp->tda8444_flags = TDA8444_SUSPENDED;
	mutex_exit(&unitp->tda8444_mutex);
	return (DDI_SUCCESS);
}

static int
tda8444_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:

		return (tda8444_do_detach(dip));
	case DDI_SUSPEND:

		return (tda8444_do_suspend(dip));
	default:

		return (DDI_FAILURE);
	}
}

static int
tda8444_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(credp))
	struct tda8444_unit *unitp;
	int err = 0;
	int instance = TDA8444_MINOR_TO_DEVINST(*devp);
	int channel = TDA8444_MINOR_TO_CHANNEL(*devp);

	if (instance < 0) {

		return (ENXIO);
	}

	unitp = (struct tda8444_unit *)
	    ddi_get_soft_state(tda8444_soft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	if (otyp != OTYP_CHR) {

		return (EINVAL);
	}

	mutex_enter(&unitp->tda8444_mutex);

	if (flags & FEXCL) {
		if (unitp->tda8444_oflag[channel] != 0) {
			err = EBUSY;
		} else {
			unitp->tda8444_oflag[channel] = FEXCL;
		}
	} else {
		if (unitp->tda8444_oflag[channel] == FEXCL) {
			err = EBUSY;
		} else {
			unitp->tda8444_oflag[channel] = (uint16_t)FOPEN;
		}
	}

	mutex_exit(&unitp->tda8444_mutex);

	return (err);
}

static int
tda8444_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	_NOTE(ARGUNUSED(flags, otyp, credp))
	struct tda8444_unit *unitp;
	int instance = TDA8444_MINOR_TO_DEVINST(dev);
	int channel = TDA8444_MINOR_TO_CHANNEL(dev);

	if (instance < 0) {

		return (ENXIO);
	}

	unitp = (struct tda8444_unit *)
	    ddi_get_soft_state(tda8444_soft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	mutex_enter(&unitp->tda8444_mutex);

	unitp->tda8444_oflag[channel] = 0;

	mutex_exit(&unitp->tda8444_mutex);

	return (DDI_SUCCESS);
}

static int
tda8444_read(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p))
	return (tda8444_io(dev, uiop, B_READ));
}

static int
tda8444_write(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p))
	return (tda8444_io(dev, uiop, B_WRITE));
}

static int
tda8444_io(dev_t dev, struct uio *uiop, int rw)
{
	struct tda8444_unit *unitp;
	int instance = TDA8444_MINOR_TO_DEVINST(getminor(dev));
	int channel = TDA8444_MINOR_TO_CHANNEL(getminor(dev));
	int ret = 0;
	size_t len = uiop->uio_resid;
	int8_t out_value;

	if (instance < 0) {

		return (ENXIO);
	}

	if (len == 0) {
		return (0);
	}

	unitp = (struct tda8444_unit *)
	    ddi_get_soft_state(tda8444_soft_statep, instance);

	if (unitp == NULL) {

		return (ENXIO);
	}

	if (rw == B_READ) {
		if (unitp->tda8444_output[channel] != TDA8444_UNKNOWN_OUT) {
			return (uiomove(&unitp->tda8444_output[channel], 1,
			    UIO_READ, uiop));
		} else {
			return (EIO);
		}
	}

	/*
	 * rw == B_WRITE.  Make sure each write to a device is single
	 * threaded since we pre-allocate a single write buffer.  This is not a
	 * bottleneck since concurrent writes would serialize at the
	 * transport level anyway.
	 */
	mutex_enter(&unitp->tda8444_mutex);
	if (unitp->tda8444_flags == TDA8444_SUSPENDED) {
		mutex_exit(&unitp->tda8444_mutex);

		return (EAGAIN);
	}

	while (unitp->tda8444_flags == TDA8444_BUSY) {
		if (cv_wait_sig(&unitp->tda8444_cv,
		    &unitp->tda8444_mutex) <= 0) {
			mutex_exit(&unitp->tda8444_mutex);

			return (EINTR);
		}
	}
	unitp->tda8444_flags = TDA8444_BUSY;
	mutex_exit(&unitp->tda8444_mutex);

	unitp->tda8444_transfer->i2c_wbuf[0] = (TDA8444_REGBASE | channel);
	if ((ret = uiomove(&out_value, sizeof (out_value), UIO_WRITE,
	    uiop)) == 0) {

		/*
		 * Check bounds
		 */
		if ((out_value > TDA8444_MAX_OUT) ||
		    (out_value < TDA8444_MIN_OUT)) {
			ret = EINVAL;
		} else {
			unitp->tda8444_transfer->i2c_wbuf[1] =
			    (uchar_t)out_value;
			DPRINTF(IO, ("setting channel %d to %d", channel,
			    unitp->tda8444_transfer->i2c_wbuf[1]));

			if (i2c_transfer(unitp->tda8444_hdl,
			    unitp->tda8444_transfer) != I2C_SUCCESS) {
				ret = EIO;
			} else {
				unitp->tda8444_output[channel] = out_value;
			}
		}
	} else {
		ret = EFAULT;
	}

	mutex_enter(&unitp->tda8444_mutex);
	unitp->tda8444_flags = 0;
	cv_signal(&unitp->tda8444_cv);
	mutex_exit(&unitp->tda8444_mutex);

	return (ret);
}
