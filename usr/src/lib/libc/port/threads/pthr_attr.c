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
 * Copyright 2015, Joyent, Inc.
 */

#include "lint.h"
#include "thr_uberdata.h"
#include <sched.h>

/*
 * Default attribute object for pthread_create() with NULL attr pointer.
 * Note that the 'guardsize' field is initialized on the first call.
 */
const thrattr_t *
def_thrattr(void)
{
	static thrattr_t thrattr = {
		0,				/* stksize */
		NULL,				/* stkaddr */
		PTHREAD_CREATE_JOINABLE,	/* detachstate */
		PTHREAD_CREATE_NONDAEMON_NP,	/* daemonstate */
		PTHREAD_SCOPE_PROCESS,		/* scope */
		0,				/* prio */
		SCHED_OTHER,			/* policy */
		PTHREAD_INHERIT_SCHED,		/* inherit */
		0				/* guardsize */
	};
	if (thrattr.guardsize == 0)
		thrattr.guardsize = _sysconf(_SC_PAGESIZE);
	return (&thrattr);
}

/*
 * pthread_attr_init: allocates the attribute object and initializes it
 * with the default values.
 */
#pragma weak _pthread_attr_init = pthread_attr_init
int
pthread_attr_init(pthread_attr_t *attr)
{
	thrattr_t *ap;

	if ((ap = lmalloc(sizeof (thrattr_t))) != NULL) {
		*ap = *def_thrattr();
		attr->__pthread_attrp = ap;
		return (0);
	}
	return (ENOMEM);
}

/*
 * pthread_attr_destroy: frees the attribute object and invalidates it
 * with NULL value.
 */
int
pthread_attr_destroy(pthread_attr_t *attr)
{
	if (attr == NULL || attr->__pthread_attrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_attrp, sizeof (thrattr_t));
	attr->__pthread_attrp = NULL;
	return (0);
}

/*
 * pthread_attr_clone: make a copy of a pthread_attr_t.
 */
int
pthread_attr_clone(pthread_attr_t *attr, const pthread_attr_t *old_attr)
{
	thrattr_t *ap;
	const thrattr_t *old_ap =
	    old_attr? old_attr->__pthread_attrp : def_thrattr();

	if (old_ap == NULL)
		return (EINVAL);
	if ((ap = lmalloc(sizeof (thrattr_t))) == NULL)
		return (ENOMEM);
	*ap = *old_ap;
	attr->__pthread_attrp = ap;
	return (0);
}

/*
 * pthread_attr_equal: compare two pthread_attr_t's, return 1 if equal.
 * A NULL pthread_attr_t pointer implies default attributes.
 * This is a consolidation-private interface, for librt.
 */
int
pthread_attr_equal(const pthread_attr_t *attr1, const pthread_attr_t *attr2)
{
	const thrattr_t *ap1 = attr1? attr1->__pthread_attrp : def_thrattr();
	const thrattr_t *ap2 = attr2? attr2->__pthread_attrp : def_thrattr();

	if (ap1 == NULL || ap2 == NULL)
		return (0);
	return (ap1 == ap2 || memcmp(ap1, ap2, sizeof (thrattr_t)) == 0);
}

/*
 * pthread_attr_setstacksize: sets the user stack size, minimum should
 * be PTHREAD_STACK_MIN (MINSTACK).
 * This is equivalent to stksize argument in thr_create().
 */
int
pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    stacksize >= MINSTACK) {
		ap->stksize = stacksize;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getstacksize: gets the user stack size.
 */
#pragma weak _pthread_attr_getstacksize = pthread_attr_getstacksize
int
pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    stacksize != NULL) {
		*stacksize = ap->stksize;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setstackaddr: sets the user stack addr.
 * This is equivalent to stkaddr argument in thr_create().
 */
int
pthread_attr_setstackaddr(pthread_attr_t *attr, void *stackaddr)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL) {
		ap->stkaddr = stackaddr;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getstackaddr: gets the user stack addr.
 */
#pragma weak _pthread_attr_getstackaddr = pthread_attr_getstackaddr
int
pthread_attr_getstackaddr(const pthread_attr_t *attr, void **stackaddr)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    stackaddr != NULL) {
		*stackaddr = ap->stkaddr;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setdetachstate: sets the detach state to DETACHED or JOINABLE.
 * PTHREAD_CREATE_DETACHED is equivalent to thr_create(THR_DETACHED).
 */
int
pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    (detachstate == PTHREAD_CREATE_DETACHED ||
	    detachstate == PTHREAD_CREATE_JOINABLE)) {
		ap->detachstate = detachstate;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getdetachstate: gets the detach state.
 */
#pragma weak _pthread_attr_getdetachstate = pthread_attr_getdetachstate
int
pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    detachstate != NULL) {
		*detachstate = ap->detachstate;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setdaemonstate_np: sets the daemon state to DAEMON or NONDAEMON.
 * PTHREAD_CREATE_DAEMON is equivalent to thr_create(THR_DAEMON).
 * For now, this is a private interface in libc.
 */
int
pthread_attr_setdaemonstate_np(pthread_attr_t *attr, int daemonstate)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    (daemonstate == PTHREAD_CREATE_DAEMON_NP ||
	    daemonstate == PTHREAD_CREATE_NONDAEMON_NP)) {
		ap->daemonstate = daemonstate;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getdaemonstate_np: gets the daemon state.
 * For now, this is a private interface in libc, but it is exposed in the
 * mapfile for the purposes of testing only.
 */
int
pthread_attr_getdaemonstate_np(const pthread_attr_t *attr, int *daemonstate)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    daemonstate != NULL) {
		*daemonstate = ap->daemonstate;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setscope: sets the scope to SYSTEM or PROCESS.
 * This is equivalent to setting THR_BOUND flag in thr_create().
 */
int
pthread_attr_setscope(pthread_attr_t *attr, int scope)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    (scope == PTHREAD_SCOPE_SYSTEM ||
	    scope == PTHREAD_SCOPE_PROCESS)) {
		ap->scope = scope;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getscope: gets the scheduling scope.
 */
#pragma weak _pthread_attr_getscope = pthread_attr_getscope
int
pthread_attr_getscope(const pthread_attr_t *attr, int *scope)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    scope != NULL) {
		*scope = ap->scope;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setinheritsched: sets the scheduling parameters to be
 * EXPLICIT or INHERITED from parent thread.
 */
int
pthread_attr_setinheritsched(pthread_attr_t *attr, int inherit)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    (inherit == PTHREAD_EXPLICIT_SCHED ||
	    inherit == PTHREAD_INHERIT_SCHED)) {
		ap->inherit = inherit;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getinheritsched: gets the scheduling inheritance.
 */
#pragma weak _pthread_attr_getinheritsched = pthread_attr_getinheritsched
int
pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inherit)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    inherit != NULL) {
		*inherit = ap->inherit;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setschedpolicy: sets the scheduling policy.
 */
int
pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    policy != SCHED_SYS && get_info_by_policy(policy) != NULL) {
		ap->policy = policy;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getpolicy: gets the scheduling policy.
 */
#pragma weak _pthread_attr_getschedpolicy = pthread_attr_getschedpolicy
int
pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *policy)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    policy != NULL) {
		*policy = ap->policy;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setschedparam: sets the scheduling parameters.
 * Currently, we support priority only.
 */
int
pthread_attr_setschedparam(pthread_attr_t *attr,
    const struct sched_param *param)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    param != NULL) {
		ap->prio = param->sched_priority;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getschedparam: gets the scheduling parameters.
 * Currently, only priority is defined as sched parameter.
 */
#pragma weak _pthread_attr_getschedparam = pthread_attr_getschedparam
int
pthread_attr_getschedparam(const pthread_attr_t *attr,
    struct sched_param *param)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    param != NULL) {
		param->sched_priority = ap->prio;
		return (0);
	}
	return (EINVAL);
}

/*
 * UNIX98
 * pthread_attr_setguardsize: sets the guardsize
 */
int
pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL) {
		ap->guardsize = guardsize;
		return (0);
	}
	return (EINVAL);
}

/*
 * UNIX98
 * pthread_attr_getguardsize: gets the guardsize
 */
int
pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *guardsize)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    guardsize != NULL) {
		*guardsize = ap->guardsize;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_setstack: sets the user stack addr and stack size.
 * This is equivalent to the stack_base and stack_size arguments
 * to thr_create().
 */
int
pthread_attr_setstack(pthread_attr_t *attr,
    void *stackaddr, size_t stacksize)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    stacksize >= MINSTACK) {
		ap->stkaddr = stackaddr;
		ap->stksize = stacksize;
		if (stackaddr != NULL &&
		    setup_top_frame(stackaddr, stacksize, NULL) == NULL)
			return (EACCES);
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_attr_getstack: gets the user stack addr and stack size.
 */
int
pthread_attr_getstack(const pthread_attr_t *attr,
    void **stackaddr, size_t *stacksize)
{
	thrattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_attrp) != NULL &&
	    stackaddr != NULL && stacksize != NULL) {
		*stackaddr = ap->stkaddr;
		*stacksize = ap->stksize;
		return (0);
	}
	return (EINVAL);
}

/*
 * This function is a common BSD extension to pthread which is used to obtain
 * the attributes of a thread that might have changed after its creation, for
 * example, it's stack address.
 *
 * Note, there is no setattr analogue, nor do we desire to add one at this time.
 * Similarly there is no native threads API analogue (nor should we add one for
 * C11).
 *
 * The astute reader may note that there is a GNU version of this called
 * pthread_getattr_np(). The two functions are similar, but subtley different in
 * a rather important way. While the pthread_attr_get_np() expects to be given
 * a pthread_attr_t that has had pthread_attr_init() called on in,
 * pthread_getattr_np() does not. However, on GNU systems, where the function
 * originates, the pthread_attr_t is not opaque and thus it is entirely safe to
 * both call pthread_attr_init() and then call pthread_getattr_np() on the same
 * attributes object. On illumos, since the pthread_attr_t is opaque, that would
 * be a memory leak. As such, we don't provide it.
 */
int
pthread_attr_get_np(pthread_t tid, pthread_attr_t *attr)
{
	int ret;
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *target = NULL;
	thrattr_t *ap;

	/*
	 * To ensure that information about the target thread does not change or
	 * disappear while we're trying to interrogate it, we grab the uwlp
	 * lock.
	 */
	if (self->ul_lwpid == tid) {
		ulwp_lock(self, udp);
		target = self;
	} else {
		target = find_lwp(tid);
		if (target == NULL)
			return (ESRCH);
	}

	if (attr == NULL) {
		ret = EINVAL;
		goto out;
	}

	if ((ap = attr->__pthread_attrp) == NULL) {
		ret = EINVAL;
		goto out;
	}

	ap->stksize = target->ul_stksiz;
	ap->stkaddr = target->ul_stk;
	if (target->ul_usropts & THR_DETACHED) {
		ap->detachstate = PTHREAD_CREATE_DETACHED;
	} else {
		ap->detachstate = PTHREAD_CREATE_JOINABLE;
	}

	if (target->ul_usropts & THR_DAEMON) {
		ap->daemonstate = PTHREAD_CREATE_DAEMON_NP;
	} else {
		ap->daemonstate = PTHREAD_CREATE_NONDAEMON_NP;
	}

	if (target->ul_usropts & THR_BOUND) {
		ap->scope = PTHREAD_SCOPE_SYSTEM;
	} else {
		ap->scope = PTHREAD_SCOPE_PROCESS;
	}
	ap->prio = target->ul_pri;
	ap->policy = target->ul_policy;
	ap->inherit = target->ul_ptinherit;
	ap->guardsize = target->ul_guardsize;

	ret = 0;
out:
	ulwp_unlock(target, udp);
	return (ret);
}
