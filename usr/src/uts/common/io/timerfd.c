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
 * Copyright (c) 2015 Joyent, Inc.  All rights reserved.
 */

/*
 * Support for the timerfd facility, a Linux-borne facility that allows
 * POSIX.1b timers to be created and manipulated via a file descriptor
 * interface.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/timerfd.h>
#include <sys/conf.h>
#include <sys/vmem.h>
#include <sys/sysmacros.h>
#include <sys/filio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/timer.h>

struct timerfd_state;
typedef struct timerfd_state timerfd_state_t;

struct timerfd_state {
	kmutex_t tfd_lock;			/* lock protecting state */
	kcondvar_t tfd_cv;			/* condvar */
	pollhead_t tfd_pollhd;			/* poll head */
	uint64_t tfd_fired;			/* # of times fired */
	itimer_t tfd_itimer;			/* underlying itimer */
	timerfd_state_t *tfd_next;		/* next state on global list */
};

/*
 * Internal global variables.
 */
static kmutex_t		timerfd_lock;		/* lock protecting state */
static dev_info_t	*timerfd_devi;		/* device info */
static vmem_t		*timerfd_minor;		/* minor number arena */
static void		*timerfd_softstate;	/* softstate pointer */
static timerfd_state_t	*timerfd_state;		/* global list of state */

static itimer_t *
timerfd_itimer_lock(timerfd_state_t *state)
{
	itimer_t *it = &state->tfd_itimer;

	mutex_enter(&state->tfd_lock);

	while (it->it_lock & ITLK_LOCKED) {
		it->it_blockers++;
		cv_wait(&it->it_cv, &state->tfd_lock);
		it->it_blockers--;
	}

	it->it_lock |= ITLK_LOCKED;

	mutex_exit(&state->tfd_lock);

	return (it);
}

static void
timerfd_itimer_unlock(timerfd_state_t *state, itimer_t *it)
{
	VERIFY(it == &state->tfd_itimer);
	VERIFY(it->it_lock & ITLK_LOCKED);

	mutex_enter(&state->tfd_lock);

	it->it_lock &= ~ITLK_LOCKED;

	if (it->it_blockers)
		cv_signal(&it->it_cv);

	mutex_exit(&state->tfd_lock);
}

static void
timerfd_fire(itimer_t *it)
{
	timerfd_state_t *state = it->it_frontend;
	uint64_t oval;

	mutex_enter(&state->tfd_lock);
	oval = state->tfd_fired++;
	mutex_exit(&state->tfd_lock);

	if (oval == 0) {
		cv_broadcast(&state->tfd_cv);
		pollwakeup(&state->tfd_pollhd, POLLRDNORM | POLLIN);
	}
}

/*ARGSUSED*/
static int
timerfd_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	timerfd_state_t *state;
	major_t major = getemajor(*devp);
	minor_t minor = getminor(*devp);

	if (minor != TIMERFDMNRN_TIMERFD)
		return (ENXIO);

	mutex_enter(&timerfd_lock);

	minor = (minor_t)(uintptr_t)vmem_alloc(timerfd_minor, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(timerfd_softstate, minor) != DDI_SUCCESS) {
		vmem_free(timerfd_minor, (void *)(uintptr_t)minor, 1);
		mutex_exit(&timerfd_lock);
		return (NULL);
	}

	state = ddi_get_soft_state(timerfd_softstate, minor);
	*devp = makedevice(major, minor);

	state->tfd_next = timerfd_state;
	timerfd_state = state;

	mutex_exit(&timerfd_lock);

	return (0);
}

/*ARGSUSED*/
static int
timerfd_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	timerfd_state_t *state;
	minor_t minor = getminor(dev);
	uint64_t val;
	int err;

	if (uio->uio_resid < sizeof (val))
		return (EINVAL);

	state = ddi_get_soft_state(timerfd_softstate, minor);

	mutex_enter(&state->tfd_lock);

	while (state->tfd_fired == 0) {
		if (uio->uio_fmode & (FNDELAY|FNONBLOCK)) {
			mutex_exit(&state->tfd_lock);
			return (EAGAIN);
		}

		if (!cv_wait_sig_swap(&state->tfd_cv, &state->tfd_lock)) {
			mutex_exit(&state->tfd_lock);
			return (EINTR);
		}
	}

	/*
	 * Our tfd_fired is non-zero; slurp its value and then clear it.
	 */
	val = state->tfd_fired;
	state->tfd_fired = 0;
	mutex_exit(&state->tfd_lock);

	err = uiomove(&val, sizeof (val), UIO_READ, uio);

	return (err);
}

/*ARGSUSED*/
static int
timerfd_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	timerfd_state_t *state;
	minor_t minor = getminor(dev);
	short revents = 0;

	state = ddi_get_soft_state(timerfd_softstate, minor);

	mutex_enter(&state->tfd_lock);

	if (state->tfd_fired > 0)
		revents |= POLLRDNORM | POLLIN;

	if (!(*reventsp = revents & events) && !anyyet)
		*phpp = &state->tfd_pollhd;

	mutex_exit(&state->tfd_lock);

	return (0);
}

static int
timerfd_copyin(uintptr_t addr, itimerspec_t *dest)
{
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin((void *)addr, dest, sizeof (itimerspec_t)) != 0)
			return (EFAULT);
	} else {
		itimerspec32_t dest32;

		if (copyin((void *)addr, &dest32, sizeof (itimerspec32_t)) != 0)
			return (EFAULT);

		ITIMERSPEC32_TO_ITIMERSPEC(dest, &dest32);
	}

	if (itimerspecfix(&dest->it_value) ||
	    (itimerspecfix(&dest->it_interval) &&
	    timerspecisset(&dest->it_value))) {
		return (EINVAL);
	}

	return (0);
}

static int
timerfd_copyout(itimerspec_t *src, uintptr_t addr)
{
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(src, (void *)addr, sizeof (itimerspec_t)) != 0)
			return (EFAULT);
	} else {
		itimerspec32_t src32;

		if (ITIMERSPEC_OVERFLOW(src))
			return (EOVERFLOW);

		ITIMERSPEC_TO_ITIMERSPEC32(&src32, src);

		if (copyout(&src32, (void *)addr, sizeof (itimerspec32_t)) != 0)
			return (EFAULT);
	}

	return (0);
}

/*ARGSUSED*/
static int
timerfd_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	itimerspec_t when, oval;
	timerfd_state_t *state;
	minor_t minor = getminor(dev);
	int err;
	itimer_t *it;

	state = ddi_get_soft_state(timerfd_softstate, minor);

	switch (cmd) {
	case TIMERFDIOC_CREATE: {
		if (arg == TIMERFD_MONOTONIC)
			arg = CLOCK_MONOTONIC;

		it = timerfd_itimer_lock(state);

		if (it->it_backend != NULL) {
			timerfd_itimer_unlock(state, it);
			return (EEXIST);
		}

		if ((it->it_backend = clock_get_backend(arg)) == NULL) {
			timerfd_itimer_unlock(state, it);
			return (EINVAL);
		}

		/*
		 * We need to provide a proc structure only for purposes
		 * of locking CLOCK_REALTIME-based timers -- it is safe to
		 * provide p0 here.
		 */
		it->it_proc = &p0;

		err = it->it_backend->clk_timer_create(it, timerfd_fire);

		if (err != 0) {
			it->it_backend = NULL;
			timerfd_itimer_unlock(state, it);
			return (err);
		}

		it->it_frontend = state;
		timerfd_itimer_unlock(state, it);

		return (0);
	}

	case TIMERFDIOC_GETTIME: {
		it = timerfd_itimer_lock(state);

		if (it->it_backend == NULL) {
			timerfd_itimer_unlock(state, it);
			return (ENODEV);
		}

		err = it->it_backend->clk_timer_gettime(it, &when);
		timerfd_itimer_unlock(state, it);

		if (err != 0)
			return (err);

		if ((err = timerfd_copyout(&when, arg)) != 0)
			return (err);

		return (0);
	}

	case TIMERFDIOC_SETTIME: {
		timerfd_settime_t st;

		if (copyin((void *)arg, &st, sizeof (st)) != 0)
			return (EFAULT);

		if ((err = timerfd_copyin(st.tfd_settime_value, &when)) != 0)
			return (err);

		it = timerfd_itimer_lock(state);

		if (it->it_backend == NULL) {
			timerfd_itimer_unlock(state, it);
			return (ENODEV);
		}

		if (st.tfd_settime_ovalue != NULL) {
			err = it->it_backend->clk_timer_gettime(it, &oval);

			if (err != 0) {
				timerfd_itimer_unlock(state, it);
				return (err);
			}
		}

		/*
		 * Before we set the time, we're going to clear tfd_fired.
		 * This can potentially race with the (old) timer firing, but
		 * the window is deceptively difficult to close:  if we were
		 * to simply clear tfd_fired after the call to the backend
		 * returned, we would run the risk of plowing a firing of the
		 * new timer.  Ultimately, the race can only be resolved by
		 * the backend, which would likely need to be extended with a
		 * function to call back into when the timer is between states
		 * (that is, after the timer can no longer fire with the old
		 * timer value, but before it can fire with the new one).
		 * This is straightforward enough for backends that set a
		 * timer's value by deleting the old one and adding the new
		 * one, but for those that modify the timer value in place
		 * (e.g., cyclics), the required serialization is necessarily
		 * delicate:  the function would have to be callable from
		 * arbitrary interrupt context.  While implementing all of
		 * this is possible, it does not (for the moment) seem worth
		 * it: if the timer is firing at essentially the same moment
		 * that it's being reprogrammed, there is a higher-level race
		 * with respect to timerfd usage that the progam itself will
		 * have to properly resolve -- and it seems reasonable to
		 * simply allow the program to resolve it in this case.
		 */
		mutex_enter(&state->tfd_lock);
		state->tfd_fired = 0;
		mutex_exit(&state->tfd_lock);

		err = it->it_backend->clk_timer_settime(it,
		    st.tfd_settime_flags & TFD_TIMER_ABSTIME ?
		    TIMER_ABSTIME : TIMER_RELTIME, &when);
		timerfd_itimer_unlock(state, it);

		if (err != 0 || st.tfd_settime_ovalue == NULL)
			return (err);

		if ((err = timerfd_copyout(&oval, st.tfd_settime_ovalue)) != 0)
			return (err);

		return (0);
	}

	default:
		break;
	}

	return (ENOTTY);
}

/*ARGSUSED*/
static int
timerfd_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	timerfd_state_t *state, **sp;
	itimer_t *it;
	minor_t minor = getminor(dev);

	state = ddi_get_soft_state(timerfd_softstate, minor);

	if (state->tfd_pollhd.ph_list != NULL) {
		pollwakeup(&state->tfd_pollhd, POLLERR);
		pollhead_clean(&state->tfd_pollhd);
	}

	/*
	 * No one can get to this timer; we don't need to lock it -- we can
	 * just call on the backend to delete it.
	 */
	it = &state->tfd_itimer;

	if (it->it_backend != NULL)
		it->it_backend->clk_timer_delete(it);

	mutex_enter(&timerfd_lock);

	/*
	 * Remove our state from our global list.
	 */
	for (sp = &timerfd_state; *sp != state; sp = &((*sp)->tfd_next))
		VERIFY(*sp != NULL);

	*sp = (*sp)->tfd_next;

	ddi_soft_state_free(timerfd_softstate, minor);
	vmem_free(timerfd_minor, (void *)(uintptr_t)minor, 1);

	mutex_exit(&timerfd_lock);

	return (0);
}

static int
timerfd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&timerfd_lock);

	if (ddi_soft_state_init(&timerfd_softstate,
	    sizeof (timerfd_state_t), 0) != 0) {
		cmn_err(CE_NOTE, "/dev/timerfd failed to create soft state");
		mutex_exit(&timerfd_lock);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "timerfd", S_IFCHR,
	    TIMERFDMNRN_TIMERFD, DDI_PSEUDO, NULL) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "/dev/timerfd couldn't create minor node");
		ddi_soft_state_fini(&timerfd_softstate);
		mutex_exit(&timerfd_lock);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	timerfd_devi = devi;

	timerfd_minor = vmem_create("timerfd_minor", (void *)TIMERFDMNRN_CLONE,
	    UINT32_MAX - TIMERFDMNRN_CLONE, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	mutex_exit(&timerfd_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
timerfd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&timerfd_lock);
	vmem_destroy(timerfd_minor);

	ddi_remove_minor_node(timerfd_devi, NULL);
	timerfd_devi = NULL;

	ddi_soft_state_fini(&timerfd_softstate);
	mutex_exit(&timerfd_lock);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
timerfd_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)timerfd_devi;
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

static struct cb_ops timerfd_cb_ops = {
	timerfd_open,		/* open */
	timerfd_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	timerfd_read,		/* read */
	nodev,			/* write */
	timerfd_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	timerfd_poll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops timerfd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	timerfd_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	timerfd_attach,		/* attach */
	timerfd_detach,		/* detach */
	nodev,			/* reset */
	&timerfd_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"timerfd support",	/* name of module */
	&timerfd_ops,		/* driver ops */
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
