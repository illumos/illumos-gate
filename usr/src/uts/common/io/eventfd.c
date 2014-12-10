/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Support for the eventfd facility, a Linux-borne facility for user-generated
 * file descriptor-based events.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/eventfd.h>
#include <sys/conf.h>
#include <sys/vmem.h>
#include <sys/sysmacros.h>
#include <sys/filio.h>
#include <sys/stat.h>
#include <sys/file.h>

struct eventfd_state;
typedef struct eventfd_state eventfd_state_t;

struct eventfd_state {
	kmutex_t efd_lock;			/* lock protecting state */
	boolean_t efd_semaphore;		/* boolean: sema. semantics */
	kcondvar_t efd_cv;			/* condvar */
	pollhead_t efd_pollhd;			/* poll head */
	uint64_t efd_value;			/* value */
	eventfd_state_t *efd_next;		/* next state on global list */
};

/*
 * Internal global variables.
 */
static kmutex_t		eventfd_lock;		/* lock protecting state */
static dev_info_t	*eventfd_devi;		/* device info */
static vmem_t		*eventfd_minor;		/* minor number arena */
static void		*eventfd_softstate;	/* softstate pointer */
static eventfd_state_t	*eventfd_state;		/* global list of state */

/*ARGSUSED*/
static int
eventfd_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	eventfd_state_t *state;
	major_t major = getemajor(*devp);
	minor_t minor = getminor(*devp);

	if (minor != EVENTFDMNRN_INOTIFY)
		return (ENXIO);

	mutex_enter(&eventfd_lock);

	minor = (minor_t)(uintptr_t)vmem_alloc(eventfd_minor, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(eventfd_softstate, minor) != DDI_SUCCESS) {
		vmem_free(eventfd_minor, (void *)(uintptr_t)minor, 1);
		mutex_exit(&eventfd_lock);
		return (NULL);
	}

	state = ddi_get_soft_state(eventfd_softstate, minor);
	*devp = makedevice(major, minor);

	state->efd_next = eventfd_state;
	eventfd_state = state;

	mutex_exit(&eventfd_lock);

	return (0);
}

/*ARGSUSED*/
static int
eventfd_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	eventfd_state_t *state;
	minor_t minor = getminor(dev);
	uint64_t val, oval;
	int err;

	if (uio->uio_resid < sizeof (val))
		return (EINVAL);

	state = ddi_get_soft_state(eventfd_softstate, minor);

	mutex_enter(&state->efd_lock);

	while (state->efd_value == 0) {
		if (uio->uio_fmode & (FNDELAY|FNONBLOCK)) {
			mutex_exit(&state->efd_lock);
			return (EAGAIN);
		}

		if (!cv_wait_sig_swap(&state->efd_cv, &state->efd_lock)) {
			mutex_exit(&state->efd_lock);
			return (EINTR);
		}
	}

	/*
	 * We have a non-zero value and we own the lock; our behavior now
	 * depends on whether or not EFD_SEMAPHORE was set when the eventfd
	 * was created.
	 */
	val = oval = state->efd_value;

	if (state->efd_semaphore) {
		state->efd_value--;
		val = 1;
	} else {
		state->efd_value = 0;
	}

	err = uiomove(&val, sizeof (val), UIO_READ, uio);

	mutex_exit(&state->efd_lock);

	if (oval == EVENTFD_VALMAX) {
		cv_broadcast(&state->efd_cv);
		pollwakeup(&state->efd_pollhd, POLLWRNORM | POLLOUT);
	}

	return (err);
}

/*ARGSUSED*/
static int
eventfd_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	eventfd_state_t *state;
	minor_t minor = getminor(dev);
	uint64_t val, oval;
	int err;

	if (uio->uio_resid < sizeof (val))
		return (EINVAL);

	if ((err = uiomove(&val, sizeof (val), UIO_WRITE, uio)) != 0)
		return (err);

	if (val > EVENTFD_VALMAX)
		return (EINVAL);

	state = ddi_get_soft_state(eventfd_softstate, minor);

	mutex_enter(&state->efd_lock);

	while (val > EVENTFD_VALMAX - state->efd_value) {
		if (uio->uio_fmode & (FNDELAY|FNONBLOCK)) {
			mutex_exit(&state->efd_lock);
			return (EAGAIN);
		}

		if (!cv_wait_sig_swap(&state->efd_cv, &state->efd_lock)) {
			mutex_exit(&state->efd_lock);
			return (EINTR);
		}
	}

	/*
	 * We now know that we can add the value without overflowing.
	 */
	state->efd_value = (oval = state->efd_value) + val;

	mutex_exit(&state->efd_lock);

	if (oval == 0) {
		cv_broadcast(&state->efd_cv);
		pollwakeup(&state->efd_pollhd, POLLRDNORM | POLLIN);
	}

	return (0);
}

/*ARGSUSED*/
static int
eventfd_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	eventfd_state_t *state;
	minor_t minor = getminor(dev);
	short revents = 0;

	state = ddi_get_soft_state(eventfd_softstate, minor);

	mutex_enter(&state->efd_lock);

	if (state->efd_value > 0)
		revents |= POLLRDNORM | POLLIN;

	if (state->efd_value < EVENTFD_VALMAX)
		revents |= POLLWRNORM | POLLOUT;

	*reventsp = revents & events;

	if (!revents && !anyyet)
		*phpp = &state->efd_pollhd;

	mutex_exit(&state->efd_lock);

	return (0);
}

/*ARGSUSED*/
static int
eventfd_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	eventfd_state_t *state;
	minor_t minor = getminor(dev);

	state = ddi_get_soft_state(eventfd_softstate, minor);

	switch (cmd) {
	case EVENTFDIOC_SEMAPHORE: {
		mutex_enter(&state->efd_lock);
		state->efd_semaphore ^= 1;
		mutex_exit(&state->efd_lock);

		return (0);
	}

	default:
		break;
	}

	return (ENOTTY);
}

/*ARGSUSED*/
static int
eventfd_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	eventfd_state_t *state, **sp;
	minor_t minor = getminor(dev);

	state = ddi_get_soft_state(eventfd_softstate, minor);

	mutex_enter(&eventfd_lock);

	/*
	 * Remove our state from our global list.
	 */
	for (sp = &eventfd_state; *sp != state; sp = &((*sp)->efd_next))
		VERIFY(*sp != NULL);

	*sp = (*sp)->efd_next;

	ddi_soft_state_free(eventfd_softstate, minor);
	vmem_free(eventfd_minor, (void *)(uintptr_t)minor, 1);

	mutex_exit(&eventfd_lock);

	return (0);
}

/*ARGSUSED*/
static int
eventfd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	mutex_enter(&eventfd_lock);

	if (ddi_soft_state_init(&eventfd_softstate,
	    sizeof (eventfd_state_t), 0) != 0) {
		cmn_err(CE_NOTE, "/dev/eventfd failed to create soft state");
		mutex_exit(&eventfd_lock);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "eventfd", S_IFCHR,
	    EVENTFDMNRN_INOTIFY, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "/dev/eventfd couldn't create minor node");
		ddi_soft_state_fini(&eventfd_softstate);
		mutex_exit(&eventfd_lock);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	eventfd_devi = devi;

	eventfd_minor = vmem_create("eventfd_minor", (void *)EVENTFDMNRN_CLONE,
	    UINT32_MAX - EVENTFDMNRN_CLONE, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	mutex_exit(&eventfd_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
eventfd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&eventfd_lock);
	vmem_destroy(eventfd_minor);

	ddi_remove_minor_node(eventfd_devi, NULL);
	eventfd_devi = NULL;

	ddi_soft_state_fini(&eventfd_softstate);
	mutex_exit(&eventfd_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
eventfd_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)eventfd_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static struct cb_ops eventfd_cb_ops = {
	eventfd_open,		/* open */
	eventfd_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	eventfd_read,		/* read */
	eventfd_write,		/* write */
	eventfd_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	eventfd_poll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops eventfd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	eventfd_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	eventfd_attach,		/* attach */
	eventfd_detach,		/* detach */
	nodev,			/* reset */
	&eventfd_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"eventfd support",	/* name of module */
	&eventfd_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
