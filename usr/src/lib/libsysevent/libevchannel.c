/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <door.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <strings.h>
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

#define	misaligned(p)	((uintptr_t)(p) & 3)	/* 4-byte alignment required */

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
void
sysevent_evc_unbind(evchan_t *scp)
{
	sev_unsubscribe_args_t uargs;
	evchan_subscr_t *subp, *tofree;

	if (scp == NULL || misaligned(scp))
		return;

	(void) mutex_lock(EV_LOCK(scp));

	/*
	 * Unsubscribe, if we are in the process which did the bind.
	 */
	if (EV_PID(scp) == getpid()) {
		uargs.sid.name = NULL;
		uargs.sid.len = 0;
		/*
		 * The unsubscribe ioctl will block until all door upcalls have
		 * drained.
		 */
		if (ioctl(EV_FD(scp), SEV_UNSUBSCRIBE, (intptr_t)&uargs) != 0) {
			(void) mutex_unlock(EV_LOCK(scp));
			return;
		}
	}

	subp =  (evchan_subscr_t *)(void*)EV_SUB(scp);
	while (subp->evsub_next != NULL) {
		tofree = subp->evsub_next;
		subp->evsub_next = tofree->evsub_next;
		if (door_revoke(tofree->evsub_door_desc) != 0 && errno == EPERM)
			(void) close(tofree->evsub_door_desc);
		free(tofree->evsub_sid);
		free(tofree);
	}

	(void) mutex_unlock(EV_LOCK(scp));

	/*
	 * The close of the driver will do the unsubscribe if a) it is the last
	 * close and b) we are in a child which inherited subscriptions.
	 */
	(void) close(EV_FD(scp));
	(void) mutex_destroy(EV_LOCK(scp));
	free(scp);
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

/*
 * sysevent_evc_subscribe - Subscribe to an existing event channel
 */
int
sysevent_evc_subscribe(evchan_t *scp, const char *sid, const char *class,
    int (*event_handler)(sysevent_t *ev, void *cookie),
    void *cookie, uint32_t flags)
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

	upcall_door = door_create(door_upcall, (void *)subp,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
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

	subp->ev_subhead = EVCHAN_IMPL_HNDL(scp);

	uargs.sid.name = (uintptr_t)sid;
	uargs.sid.len = sid_len;
	uargs.class_info.name = (uintptr_t)class;
	uargs.class_info.len = class_len;
	uargs.door_desc = subp->evsub_door_desc;
	uargs.flags = flags;
	if (ioctl(EV_FD(scp), SEV_SUBSCRIBE, (intptr_t)&uargs) != 0) {
		ec = errno;
		(void) mutex_unlock(EV_LOCK(scp));
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
 * sysevent_evc_unsubscribe - Unsubscribe from an existing event channel
 */
void
sysevent_evc_unsubscribe(evchan_t *scp, const char *sid)
{
	int all_subscribers = 0;
	sev_unsubscribe_args_t uargs;
	evchan_subscr_t *subp, *tofree;
	int rc;

	if (scp == NULL || misaligned(scp))
		return;

	if (sid == NULL || strlen(sid) == 0 ||
	    (strlen(sid) >= MAX_SUBID_LEN))
		return;

	/* No inheritance of binding handles via fork() */
	if (EV_PID(scp) != getpid()) {
		return;
	}

	if (strcmp(sid, EVCH_ALLSUB) == 0) {
		all_subscribers++;
		/* Indicates all subscriber id's for this channel */
		uargs.sid.name = NULL;
		uargs.sid.len = 0;
	} else {
		uargs.sid.name = (uintptr_t)sid;
		uargs.sid.len = strlen(sid) + 1;
	}

	(void) mutex_lock(EV_LOCK(scp));

	/*
	 * The unsubscribe ioctl will block until all door upcalls have drained.
	 */
	rc = ioctl(EV_FD(scp), SEV_UNSUBSCRIBE, (intptr_t)&uargs);

	if (rc != 0) {
		(void) mutex_unlock(EV_LOCK(scp));
		return;
	}

	/* Search for the matching subscriber */
	subp =  (evchan_subscr_t *)(void*)EV_SUB(scp);
	while (subp->evsub_next != NULL) {

		if (all_subscribers ||
		    (strcmp(subp->evsub_next->evsub_sid, sid) == 0)) {

			tofree = subp->evsub_next;
			subp->evsub_next = tofree->evsub_next;
			(void) door_revoke(tofree->evsub_door_desc);
			free(tofree->evsub_sid);
			free(tofree);
			/* Freed single subscriber already */
			if (all_subscribers == 0) {
				break;
			}
		} else
			subp = subp->evsub_next;
	}

	(void) mutex_unlock(EV_LOCK(scp));
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
