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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <door.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <atomic.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>

#include "libsysevent.h"
#include "libsysevent_impl.h"

/*
 * The functions below deal with the General Purpose Event Handling framework
 *
 * sysevent_evc_bind	    - create/bind application to named channel
 * sysevent_evc_unbind	    - unbind from previously bound/created channel
 * sysevent_evc_subscribe   - subscribe to existing event channel
 * sysevent_evc_unsubscribe - unsubscribe from existing event channel
 * sysevent_evc_publish	    - generate a system event via an event channel
 * sysevent_evc_control	    - various channel based control operation
 */

static void kill_door_servers(evchan_subscr_t *);

#define	misaligned(p)	((uintptr_t)(p) & 3)	/* 4-byte alignment required */

static pthread_key_t nrkey = PTHREAD_ONCE_KEY_NP;

/*
 * If the current thread is a door server thread servicing a door created
 * for us in sysevent_evc_xsubscribe, then an attempt to unsubscribe from
 * within door invocation context on the same channel will deadlock in the
 * kernel waiting for our own invocation to complete.  Such calls are
 * forbidden, and we abort if they are encountered (better than hanging
 * unkillably).
 *
 * We'd like to offer this detection to subscriptions established with
 * sysevent_evc_subscribe, but we don't have control over the door service
 * threads in that case.  Perhaps the fix is to always use door_xcreate
 * even for sysevent_evc_subscribe?
 */
static boolean_t
will_deadlock(evchan_t *scp)
{
	evchan_subscr_t *subp = pthread_getspecific(nrkey);
	evchan_impl_hdl_t *hdl = EVCHAN_IMPL_HNDL(scp);

	return (subp != NULL && subp->ev_subhead == hdl ? B_TRUE : B_FALSE);
}

/*
 * Check syntax of a channel name
 */
static int
sysevent_is_chan_name(const char *str)
{
	for (; *str != '\0'; str++) {
		if (!EVCH_ISCHANCHAR(*str))
			return (0);
	}

	return (1);
}

/*
 * Check for printable characters
 */
static int
strisprint(const char *s)
{
	for (; *s != '\0'; s++) {
		if (*s < ' ' || *s > '~')
			return (0);
	}

	return (1);
}

/*
 * sysevent_evc_bind - Create/bind application to named channel
 */
int
sysevent_evc_bind(const char *channel, evchan_t **scpp, uint32_t flags)
{
	int chanlen;
	evchan_t *scp;
	sev_bind_args_t uargs;
	int ec;

	if (scpp == NULL || misaligned(scpp)) {
		return (errno = EINVAL);
	}

	/* Provide useful value in error case */
	*scpp = NULL;

	if (channel == NULL ||
	    (chanlen = strlen(channel) + 1) > MAX_CHNAME_LEN) {
		return (errno = EINVAL);
	}

	/* Check channel syntax */
	if (!sysevent_is_chan_name(channel)) {
		return (errno = EINVAL);
	}

	if (flags & ~EVCH_B_FLAGS) {
		return (errno = EINVAL);
	}

	scp = calloc(1, sizeof (evchan_impl_hdl_t));
	if (scp == NULL) {
		return (errno = ENOMEM);
	}

	/*
	 * Enable sysevent driver.  Fallback if the device link doesn't exist;
	 * this situation can arise if a channel is bound early in system
	 * startup, prior to devfsadm(1M) being invoked.
	 */
	EV_FD(scp) = open(DEVSYSEVENT, O_RDWR);
	if (EV_FD(scp) == -1) {
		if (errno != ENOENT) {
			ec = errno == EACCES ? EPERM : errno;
			free(scp);
			return (errno = ec);
		}

		EV_FD(scp) = open(DEVICESYSEVENT, O_RDWR);
		if (EV_FD(scp) == -1) {
			ec = errno == EACCES ? EPERM : errno;
			free(scp);
			return (errno = ec);
		}
	}

	/*
	 * Force to close the fd's when process is doing exec.
	 * The driver will then release stale binding handles.
	 * The driver will release also the associated subscriptions
	 * if EVCH_SUB_KEEP flag was not set.
	 */
	(void) fcntl(EV_FD(scp), F_SETFD, FD_CLOEXEC);

	uargs.chan_name.name = (uintptr_t)channel;
	uargs.chan_name.len = chanlen;
	uargs.flags = flags;

	if (ioctl(EV_FD(scp), SEV_CHAN_OPEN, &uargs) != 0) {
		ec = errno;
		(void) close(EV_FD(scp));
		free(scp);
		return (errno = ec);
	}

	/* Needed to detect a fork() */
	EV_PID(scp) = getpid();
	(void) mutex_init(EV_LOCK(scp), USYNC_THREAD, NULL);

	*scpp = scp;

	return (0);
}

/*
 * sysevent_evc_unbind - Unbind from previously bound/created channel
 */
int
sysevent_evc_unbind(evchan_t *scp)
{
	sev_unsubscribe_args_t uargs;
	evchan_subscr_t *subp;
	int errcp;

	if (scp == NULL || misaligned(scp))
		return (errno = EINVAL);

	if (will_deadlock(scp))
		return (errno = EDEADLK);

	(void) mutex_lock(EV_LOCK(scp));

	/*
	 * Unsubscribe, if we are in the process which did the bind.
	 */
	if (EV_PID(scp) == getpid()) {
		uargs.sid.name = (uintptr_t)NULL;
		uargs.sid.len = 0;
		/*
		 * The unsubscribe ioctl will block until all door upcalls have
		 * drained.
		 */
		if (ioctl(EV_FD(scp), SEV_UNSUBSCRIBE, (intptr_t)&uargs) != 0) {
			errcp = errno;
			(void) mutex_unlock(EV_LOCK(scp));
			return (errno = errcp);
		}
	}

	while ((subp =  EV_SUB_NEXT(scp)) != NULL) {
		EV_SUB_NEXT(scp) = subp->evsub_next;

		/* If door_xcreate was applied we can clean up */
		if (subp->evsub_attr)
			kill_door_servers(subp);

		if (door_revoke(subp->evsub_door_desc) != 0 && errno == EPERM)
			(void) close(subp->evsub_door_desc);

		free(subp->evsub_sid);
		free(subp);
	}

	(void) mutex_unlock(EV_LOCK(scp));

	/*
	 * The close of the driver will do the unsubscribe if a) it is the last
	 * close and b) we are in a child which inherited subscriptions.
	 */
	(void) close(EV_FD(scp));
	(void) mutex_destroy(EV_LOCK(scp));
	free(scp);

	return (0);
}

/*
 * sysevent_evc_publish - Generate a system event via an event channel
 */
int
sysevent_evc_publish(evchan_t *scp, const char *class,
    const char *subclass, const char *vendor,
    const char *pub_name, nvlist_t *attr_list,
    uint32_t flags)
{
	sysevent_t *ev;
	sev_publish_args_t uargs;
	int rc;
	int ec;

	if (scp == NULL || misaligned(scp)) {
		return (errno = EINVAL);
	}

	/* No inheritance of binding handles via fork() */
	if (EV_PID(scp) != getpid()) {
		return (errno = EINVAL);
	}

	ev = sysevent_alloc_event((char *)class, (char *)subclass,
	    (char *)vendor, (char *)pub_name, attr_list);
	if (ev == NULL) {
		return (errno);
	}

	uargs.ev.name = (uintptr_t)ev;
	uargs.ev.len = SE_SIZE(ev);
	uargs.flags = flags;

	(void) mutex_lock(EV_LOCK(scp));

	rc = ioctl(EV_FD(scp), SEV_PUBLISH, (intptr_t)&uargs);
	ec = errno;

	(void) mutex_unlock(EV_LOCK(scp));

	sysevent_free(ev);

	if (rc != 0) {
		return (ec);
	}
	return (0);
}

/*
 * Generic callback which catches events from the kernel and calls
 * subscribers call back routine.
 *
 * Kernel guarantees that door_upcalls are disabled when unsubscription
 * was issued that's why cookie points always to a valid evchan_subscr_t *.
 *
 * Furthermore it's not necessary to lock subp because the sysevent
 * framework guarantees no unsubscription until door_return.
 */
/*ARGSUSED3*/
static void
door_upcall(void *cookie, char *args, size_t alen,
    door_desc_t *ddp, uint_t ndid)
{
	evchan_subscr_t *subp = EVCHAN_SUBSCR(cookie);
	int rval = 0;

	/*
	 * If we've been invoked simply to kill the thread then
	 * exit now.
	 */
	if (subp->evsub_state == EVCHAN_SUB_STATE_CLOSING)
		pthread_exit(NULL);

	if (args == NULL || alen <= (size_t)0) {
		/* Skip callback execution */
		rval = EINVAL;
	} else {
		rval = subp->evsub_func((sysevent_t *)(void *)args,
		    subp->evsub_cookie);
	}

	/*
	 * Fill in return values for door_return
	 */
	alen = sizeof (rval);
	bcopy(&rval, args, alen);

	(void) door_return(args, alen, NULL, 0);
}

static pthread_once_t xsub_thrattr_once = PTHREAD_ONCE_INIT;
static pthread_attr_t xsub_thrattr;

static void
xsub_thrattr_init(void)
{
	(void) pthread_attr_init(&xsub_thrattr);
	(void) pthread_attr_setdetachstate(&xsub_thrattr,
	    PTHREAD_CREATE_DETACHED);
	(void) pthread_attr_setscope(&xsub_thrattr, PTHREAD_SCOPE_SYSTEM);
}

/*
 * Our door server create function is only called during initial
 * door_xcreate since we specify DOOR_NO_DEPLETION_CB.
 */
int
xsub_door_server_create(door_info_t *dip, void *(*startf)(void *),
    void *startfarg, void *cookie)
{
	evchan_subscr_t *subp = EVCHAN_SUBSCR(cookie);
	struct sysevent_subattr_impl *xsa = subp->evsub_attr;
	pthread_attr_t *thrattr;
	sigset_t oset;
	int err;

	if (subp->evsub_state == EVCHAN_SUB_STATE_CLOSING)
		return (0);	/* shouldn't happen, but just in case */

	/*
	 * If sysevent_evc_xsubscribe was called electing to use a
	 * different door server create function then let it take it
	 * from here.
	 */
	if (xsa->xs_thrcreate) {
		return (xsa->xs_thrcreate(dip, startf, startfarg,
		    xsa->xs_thrcreate_cookie));
	}

	if (xsa->xs_thrattr == NULL) {
		(void) pthread_once(&xsub_thrattr_once, xsub_thrattr_init);
		thrattr = &xsub_thrattr;
	} else {
		thrattr = xsa->xs_thrattr;
	}

	(void) pthread_sigmask(SIG_SETMASK, &xsa->xs_sigmask, &oset);
	err = pthread_create(NULL, thrattr, startf, startfarg);
	(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);

	return (err == 0 ? 1 : -1);
}

void
xsub_door_server_setup(void *cookie)
{
	evchan_subscr_t *subp = EVCHAN_SUBSCR(cookie);
	struct sysevent_subattr_impl *xsa = subp->evsub_attr;

	if (xsa->xs_thrsetup == NULL) {
		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		(void) pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	}

	(void) pthread_setspecific(nrkey, (void *)subp);

	if (xsa->xs_thrsetup)
		xsa->xs_thrsetup(xsa->xs_thrsetup_cookie);
}

/*
 * Cause private door server threads to exit.  We have already performed the
 * unsubscribe ioctl which stops new invocations and waits until all
 * existing invocations are complete.  So all server threads should be
 * blocked in door_return.  The door has not yet been revoked.  We will
 * invoke repeatedly after setting the evsub_state to be noticed on
 * wakeup; each invocation will result in the death of one server thread.
 *
 * You'd think it would be easier to kill these threads, such as through
 * pthread_cancel.  Unfortunately door_return is not a cancellation point,
 * and if you do cancel a thread blocked in door_return the EINTR check in
 * the door_return assembly logic causes us to loop with EINTR forever!
 */
static void
kill_door_servers(evchan_subscr_t *subp)
{
	door_arg_t da;

	bzero(&da, sizeof (da));
	subp->evsub_state = EVCHAN_SUB_STATE_CLOSING;
	membar_producer();

	(void) door_call(subp->evsub_door_desc, &da);
}

static int
sysevent_evc_subscribe_cmn(evchan_t *scp, const char *sid, const char *class,
    int (*event_handler)(sysevent_t *ev, void *cookie),
    void *cookie, uint32_t flags, struct sysevent_subattr_impl *xsa)
{
	evchan_subscr_t *subp;
	int upcall_door;
	sev_subscribe_args_t uargs;
	uint32_t sid_len;
	uint32_t class_len;
	int ec;

	if (scp == NULL || misaligned(scp) || sid == NULL || class == NULL) {
		return (errno = EINVAL);
	}

	/* No inheritance of binding handles via fork() */
	if (EV_PID(scp) != getpid()) {
		return (errno = EINVAL);
	}

	if ((sid_len = strlen(sid) + 1) > MAX_SUBID_LEN || sid_len == 1 ||
	    (class_len = strlen(class) + 1) > MAX_CLASS_LEN) {
		return (errno = EINVAL);
	}

	/* Check for printable characters */
	if (!strisprint(sid)) {
		return (errno = EINVAL);
	}

	if (event_handler == NULL) {
		return (errno = EINVAL);
	}

	if (pthread_key_create_once_np(&nrkey, NULL) != 0)
		return (errno);	/* ENOMEM or EAGAIN */

	/* Create subscriber data */
	if ((subp = calloc(1, sizeof (evchan_subscr_t))) == NULL) {
		return (errno);
	}

	if ((subp->evsub_sid = strdup(sid)) == NULL) {
		ec = errno;
		free(subp);
		return (ec);
	}

	/*
	 * EC_ALL string will not be copied to kernel - NULL is assumed
	 */
	if (strcmp(class, EC_ALL) == 0) {
		class = NULL;
		class_len = 0;
	}

	/*
	 * Fill this in now for the xsub_door_server_setup dance
	 */
	subp->ev_subhead = EVCHAN_IMPL_HNDL(scp);
	subp->evsub_state = EVCHAN_SUB_STATE_ACTIVE;

	if (xsa == NULL) {
		upcall_door = door_create(door_upcall, (void *)subp,
		    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	} else {
		subp->evsub_attr = xsa;

		/*
		 * Create a private door with exactly one thread to
		 * service the callbacks (the GPEC kernel implementation
		 * serializes deliveries for each subscriber id).
		 */
		upcall_door = door_xcreate(door_upcall, (void *)subp,
		    DOOR_REFUSE_DESC | DOOR_NO_CANCEL | DOOR_NO_DEPLETION_CB,
		    xsub_door_server_create, xsub_door_server_setup,
		    (void *)subp, 1);
	}

	if (upcall_door == -1) {
		ec = errno;
		free(subp->evsub_sid);
		free(subp);
		return (ec);
	}

	/* Complete subscriber information */
	subp->evsub_door_desc = upcall_door;
	subp->evsub_func = event_handler;
	subp->evsub_cookie = cookie;

	(void) mutex_lock(EV_LOCK(scp));

	uargs.sid.name = (uintptr_t)sid;
	uargs.sid.len = sid_len;
	uargs.class_info.name = (uintptr_t)class;
	uargs.class_info.len = class_len;
	uargs.door_desc = subp->evsub_door_desc;
	uargs.flags = flags;
	if (ioctl(EV_FD(scp), SEV_SUBSCRIBE, (intptr_t)&uargs) != 0) {
		ec = errno;
		(void) mutex_unlock(EV_LOCK(scp));
		if (xsa)
			kill_door_servers(subp);
		(void) door_revoke(upcall_door);
		free(subp->evsub_sid);
		free(subp);
		return (ec);
	}

	/* Attach to subscriber list */
	subp->evsub_next = EV_SUB_NEXT(scp);
	EV_SUB_NEXT(scp) = subp;

	(void) mutex_unlock(EV_LOCK(scp));

	return (0);
}

/*
 * sysevent_evc_subscribe - subscribe to an existing event channel
 * using a non-private door (which will create as many server threads
 * as the apparent maximum concurrency requirements suggest).
 */
int
sysevent_evc_subscribe(evchan_t *scp, const char *sid, const char *class,
    int (*event_handler)(sysevent_t *ev, void *cookie),
    void *cookie, uint32_t flags)
{
	return (sysevent_evc_subscribe_cmn(scp, sid, class, event_handler,
	    cookie, flags, NULL));
}

static void
subattr_dfltinit(struct sysevent_subattr_impl *xsa)
{
	(void) sigfillset(&xsa->xs_sigmask);
	(void) sigdelset(&xsa->xs_sigmask, SIGABRT);
}

static struct sysevent_subattr_impl dfltsa;
pthread_once_t dfltsa_inited = PTHREAD_ONCE_INIT;

static void
init_dfltsa(void)
{
	subattr_dfltinit(&dfltsa);
}

/*
 * sysevent_evc_subscribe - subscribe to an existing event channel
 * using a private door with control over thread creation.
 */
int
sysevent_evc_xsubscribe(evchan_t *scp, const char *sid, const char *class,
    int (*event_handler)(sysevent_t *ev, void *cookie),
    void *cookie, uint32_t flags, sysevent_subattr_t *attr)
{
	struct sysevent_subattr_impl *xsa;

	if (attr != NULL) {
		xsa = (struct sysevent_subattr_impl *)attr;
	} else {
		xsa = &dfltsa;
		(void) pthread_once(&dfltsa_inited, init_dfltsa);
	}

	return (sysevent_evc_subscribe_cmn(scp, sid, class, event_handler,
	    cookie, flags, xsa));
}

sysevent_subattr_t *
sysevent_subattr_alloc(void)
{
	struct sysevent_subattr_impl *xsa = calloc(1, sizeof (*xsa));

	if (xsa != NULL)
		subattr_dfltinit(xsa);

	return (xsa != NULL ? (sysevent_subattr_t *)xsa : NULL);
}

void
sysevent_subattr_free(sysevent_subattr_t *attr)
{
	struct sysevent_subattr_impl *xsa =
	    (struct sysevent_subattr_impl *)attr;

	free(xsa);
}

void
sysevent_subattr_thrcreate(sysevent_subattr_t *attr,
    door_xcreate_server_func_t *thrcreate, void *cookie)
{
	struct sysevent_subattr_impl *xsa =
	    (struct sysevent_subattr_impl *)attr;

	xsa->xs_thrcreate = thrcreate;
	xsa->xs_thrcreate_cookie = cookie;
}

void
sysevent_subattr_thrsetup(sysevent_subattr_t *attr,
    door_xcreate_thrsetup_func_t *thrsetup, void *cookie)
{
	struct sysevent_subattr_impl *xsa =
	    (struct sysevent_subattr_impl *)attr;

	xsa->xs_thrsetup = thrsetup;
	xsa->xs_thrsetup_cookie = cookie;
}

void
sysevent_subattr_sigmask(sysevent_subattr_t *attr, sigset_t *set)
{
	struct sysevent_subattr_impl *xsa =
	    (struct sysevent_subattr_impl *)attr;

	if (set) {
		xsa->xs_sigmask = *set;
	} else {
		(void) sigfillset(&xsa->xs_sigmask);
		(void) sigdelset(&xsa->xs_sigmask, SIGABRT);
	}
}

void
sysevent_subattr_thrattr(sysevent_subattr_t *attr, pthread_attr_t *thrattr)
{
	struct sysevent_subattr_impl *xsa =
	    (struct sysevent_subattr_impl *)attr;

	xsa->xs_thrattr = thrattr;
}

/*
 * sysevent_evc_unsubscribe - Unsubscribe from an existing event channel
 */
int
sysevent_evc_unsubscribe(evchan_t *scp, const char *sid)
{
	int all_subscribers = 0;
	sev_unsubscribe_args_t uargs;
	evchan_subscr_t *subp, *prevsubp, *tofree;
	int errcp;
	int rc;

	if (scp == NULL || misaligned(scp))
		return (errno = EINVAL);

	if (sid == NULL || strlen(sid) == 0 ||
	    (strlen(sid) >= MAX_SUBID_LEN))
		return (errno = EINVAL);

	/* No inheritance of binding handles via fork() */
	if (EV_PID(scp) != getpid())
		return (errno = EINVAL);

	if (strcmp(sid, EVCH_ALLSUB) == 0) {
		all_subscribers++;
		/* Indicates all subscriber id's for this channel */
		uargs.sid.name = (uintptr_t)NULL;
		uargs.sid.len = 0;
	} else {
		uargs.sid.name = (uintptr_t)sid;
		uargs.sid.len = strlen(sid) + 1;
	}

	if (will_deadlock(scp))
		return (errno = EDEADLK);

	(void) mutex_lock(EV_LOCK(scp));

	/*
	 * The unsubscribe ioctl will block until all door upcalls have drained.
	 */
	rc = ioctl(EV_FD(scp), SEV_UNSUBSCRIBE, (intptr_t)&uargs);

	if (rc != 0) {
		errcp = errno;
		(void) mutex_unlock(EV_LOCK(scp));
		return (errno = errcp); /* EFAULT, ENXIO, EINVAL possible */
	}


	/*
	 * Search for the matching subscriber.  If EVCH_ALLSUB was specified
	 * then the ioctl above will have returned 0 even if there are
	 * no subscriptions, so the initial EV_SUB_NEXT can be NULL.
	 */
	prevsubp = NULL;
	subp =  EV_SUB_NEXT(scp);
	while (subp != NULL) {
		if (all_subscribers || strcmp(subp->evsub_sid, sid) == 0) {
			if (prevsubp == NULL) {
				EV_SUB_NEXT(scp) = subp->evsub_next;
			} else {
				prevsubp->evsub_next = subp->evsub_next;
			}

			tofree = subp;
			subp = subp->evsub_next;

			/* If door_xcreate was applied we can clean up */
			if (tofree->evsub_attr)
				kill_door_servers(tofree);

			(void) door_revoke(tofree->evsub_door_desc);
			free(tofree->evsub_sid);
			free(tofree);

			/* Freed single subscriber already? */
			if (all_subscribers == 0)
				break;
		} else {
			prevsubp = subp;
			subp = subp->evsub_next;
		}
	}

	(void) mutex_unlock(EV_LOCK(scp));

	return (0);
}

/*
 * sysevent_evc_control - Various channel based control operation
 */
int
sysevent_evc_control(evchan_t *scp, int cmd, /* arg */ ...)
{
	va_list ap;
	uint32_t *chlenp;
	sev_control_args_t uargs;
	int rc = 0;

	if (scp == NULL || misaligned(scp)) {
		return (errno = EINVAL);
	}

	/* No inheritance of binding handles via fork() */
	if (EV_PID(scp) != getpid()) {
		return (errno = EINVAL);
	}

	va_start(ap, cmd);

	uargs.cmd = cmd;

	(void) mutex_lock(EV_LOCK(scp));

	switch (cmd) {
	case EVCH_GET_CHAN_LEN:
	case EVCH_GET_CHAN_LEN_MAX:
		chlenp = va_arg(ap, uint32_t *);
		if (chlenp == NULL || misaligned(chlenp)) {
			rc = EINVAL;
			break;
		}
		rc = ioctl(EV_FD(scp), SEV_CHAN_CONTROL, (intptr_t)&uargs);
		*chlenp = uargs.value;
		break;

	case EVCH_SET_CHAN_LEN:
		/* Range change will be handled in framework */
		uargs.value = va_arg(ap, uint32_t);
		rc = ioctl(EV_FD(scp), SEV_CHAN_CONTROL, (intptr_t)&uargs);
		break;

	default:
		rc = EINVAL;
	}

	(void) mutex_unlock(EV_LOCK(scp));

	if (rc == -1) {
		rc = errno;
	}

	va_end(ap);

	return (errno = rc);
}

int
sysevent_evc_setpropnvl(evchan_t *scp, nvlist_t *nvl)
{
	sev_propnvl_args_t uargs;
	char *buf = NULL;
	size_t nvlsz = 0;
	int rc;

	if (scp == NULL || misaligned(scp))
		return (errno = EINVAL);

	if (nvl != NULL &&
	    nvlist_pack(nvl, &buf, &nvlsz, NV_ENCODE_NATIVE, 0) != 0)
		return (errno);

	uargs.packednvl.name = (uint64_t)(uintptr_t)buf;
	uargs.packednvl.len = (uint32_t)nvlsz;

	rc = ioctl(EV_FD(scp), SEV_SETPROPNVL, (intptr_t)&uargs);

	if (buf)
		free(buf);

	return (rc);
}

int
sysevent_evc_getpropnvl(evchan_t *scp, nvlist_t **nvlp)
{
	sev_propnvl_args_t uargs;
	char buf[1024], *bufp = buf;	/* stack buffer */
	size_t sz = sizeof (buf);
	char *buf2 = NULL;		/* allocated if stack buf too small */
	int64_t expgen = -1;
	int rc;

	if (scp == NULL || misaligned(scp) || nvlp == NULL)
		return (errno = EINVAL);

	*nvlp = NULL;

again:
	uargs.packednvl.name = (uint64_t)(uintptr_t)bufp;
	uargs.packednvl.len = (uint32_t)sz;

	rc = ioctl(EV_FD(scp), SEV_GETPROPNVL, (intptr_t)&uargs);

	if (rc == E2BIG)
		return (errno = E2BIG);	/* driver refuses to copyout */

	/*
	 * If the packed nvlist is too big for the buffer size we offered
	 * then the ioctl returns EOVERFLOW and indicates in the 'len'
	 * the size required for the current property nvlist generation
	 * (itself returned in the generation member).
	 */
	if (rc == EOVERFLOW &&
	    (buf2 == NULL || uargs.generation != expgen)) {
		if (buf2 != NULL)
			free(buf2);

		if ((sz = uargs.packednvl.len) > 1024 * 1024)
			return (E2BIG);

		bufp = buf2 = malloc(sz);

		if (buf2 == NULL)
			return (errno = ENOMEM);

		expgen = uargs.generation;
		goto again;
	}

	/*
	 * The chan prop nvlist can be absent, in which case the ioctl
	 * returns success and uargs.packednvl.len of 0;  we have already
	 * set *nvlp to NULL.  Otherwise we must unpack the nvl.
	 */
	if (rc == 0 && uargs.packednvl.len != 0 &&
	    nvlist_unpack(bufp, uargs.packednvl.len, nvlp, 0) != 0)
		rc = EINVAL;

	if (buf2 != NULL)
		free(buf2);

	return (rc ? errno = rc : 0);
}
