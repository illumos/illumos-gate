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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include "lint.h"
#include "thr_uberdata.h"

const char *panicstr;
ulwp_t *panic_thread;

static mutex_t assert_lock = DEFAULTMUTEX;
static ulwp_t *assert_thread = NULL;

mutex_t *panic_mutex = NULL;

/*
 * Called from __assert() to set panicstr and panic_thread.
 */
void
__set_panicstr(const char *msg)
{
	panicstr = msg;
	panic_thread = __curthread();
}

/*
 * Called from exit() (atexit function) to give precedence
 * to assertion failures and a core dump over _exit().
 */
void
grab_assert_lock()
{
	(void) _lwp_mutex_lock(&assert_lock);
}

static void
Abort(const char *msg)
{
	ulwp_t *self;
	struct sigaction act;
	sigset_t sigmask;
	lwpid_t lwpid;

	/* to help with core file debugging */
	panicstr = msg;
	if ((self = __curthread()) != NULL) {
		panic_thread = self;
		lwpid = self->ul_lwpid;
	} else {
		lwpid = _lwp_self();
	}

	/* set SIGABRT signal handler to SIG_DFL w/o grabbing any locks */
	(void) memset(&act, 0, sizeof (act));
	act.sa_sigaction = SIG_DFL;
	(void) __sigaction(SIGABRT, &act, NULL);

	/* delete SIGABRT from the signal mask */
	(void) sigemptyset(&sigmask);
	(void) sigaddset(&sigmask, SIGABRT);
	(void) __lwp_sigmask(SIG_UNBLOCK, &sigmask);

	(void) _lwp_kill(lwpid, SIGABRT);	/* never returns */
	(void) kill(getpid(), SIGABRT);	/* if it does, try harder */
	_exit(127);
}

/*
 * Write a panic message w/o grabbing any locks other than assert_lock.
 * We have no idea what locks are held at this point.
 */
static void
common_panic(const char *head, const char *why)
{
	char msg[400];	/* no panic() message in the library is this long */
	ulwp_t *self;
	size_t len1, len2;

	if ((self = __curthread()) != NULL)
		enter_critical(self);
	(void) _lwp_mutex_lock(&assert_lock);

	(void) memset(msg, 0, sizeof (msg));
	(void) strcpy(msg, head);
	len1 = strlen(msg);
	len2 = strlen(why);
	if (len1 + len2 >= sizeof (msg))
		len2 = sizeof (msg) - len1 - 1;
	(void) strncat(msg, why, len2);
	len1 = strlen(msg);
	if (msg[len1 - 1] != '\n')
		msg[len1++] = '\n';
	(void) __write(2, msg, len1);
	Abort(msg);
}

void
thr_panic(const char *why)
{
	common_panic("*** libc thread failure: ", why);
}

void
aio_panic(const char *why)
{
	common_panic("*** libc aio system failure: ", why);
}

void
mutex_panic(mutex_t *mp, const char *why)
{
	panic_mutex = mp;
	common_panic("*** libc mutex system failure: ", why);
}

/*
 * Utility function for converting a long integer to a string, avoiding stdio.
 * 'base' must be one of 10 or 16
 */
void
ultos(uint64_t n, int base, char *s)
{
	char lbuf[24];		/* 64 bits fits in 16 hex digits, 20 decimal */
	char *cp = lbuf;

	do {
		*cp++ = "0123456789abcdef"[n%base];
		n /= base;
	} while (n);
	if (base == 16) {
		*s++ = '0';
		*s++ = 'x';
	}
	do {
		*s++ = *--cp;
	} while (cp > lbuf);
	*s = '\0';
}

/*
 * Report application lock usage error for mutexes and condvars.
 * Not called if _THREAD_ERROR_DETECTION=0.
 * Continue execution if _THREAD_ERROR_DETECTION=1.
 * Dump core if _THREAD_ERROR_DETECTION=2.
 */
void
lock_error(const mutex_t *mp, const char *who, void *cv, const char *msg)
{
	mutex_t mcopy;
	char buf[800];
	uberdata_t *udp;
	ulwp_t *self;
	lwpid_t lwpid;
	pid_t pid;

	/*
	 * Take a snapshot of the mutex before it changes (we hope!).
	 * Use memcpy() rather than 'mcopy = *mp' in case mp is unaligned.
	 */
	(void) memcpy(&mcopy, mp, sizeof (mcopy));

	/* avoid recursion deadlock */
	if ((self = __curthread()) != NULL) {
		if (assert_thread == self)
			_exit(127);
		enter_critical(self);
		(void) _lwp_mutex_lock(&assert_lock);
		assert_thread = self;
		lwpid = self->ul_lwpid;
		udp = self->ul_uberdata;
		pid = udp->pid;
	} else {
		self = NULL;
		(void) _lwp_mutex_lock(&assert_lock);
		lwpid = _lwp_self();
		udp = &__uberdata;
		pid = getpid();
	}

	(void) strcpy(buf,
	    "\n*** _THREAD_ERROR_DETECTION: lock usage error detected ***\n");
	(void) strcat(buf, who);
	(void) strcat(buf, "(");
	if (cv != NULL) {
		ultos((uint64_t)(uintptr_t)cv, 16, buf + strlen(buf));
		(void) strcat(buf, ", ");
	}
	ultos((uint64_t)(uintptr_t)mp, 16, buf + strlen(buf));
	(void) strcat(buf, ")");
	if (msg != NULL) {
		(void) strcat(buf, ": ");
		(void) strcat(buf, msg);
	} else if (!mutex_held(&mcopy)) {
		(void) strcat(buf, ": calling thread does not own the lock");
	} else if (mcopy.mutex_rcount) {
		(void) strcat(buf, ": mutex rcount = ");
		ultos((uint64_t)mcopy.mutex_rcount, 10, buf + strlen(buf));
	} else {
		(void) strcat(buf, ": calling thread already owns the lock");
	}
	(void) strcat(buf, "\ncalling thread is ");
	ultos((uint64_t)(uintptr_t)self, 16, buf + strlen(buf));
	(void) strcat(buf, " thread-id ");
	ultos((uint64_t)lwpid, 10, buf + strlen(buf));
	if (msg != NULL || mutex_held(&mcopy))
		/* EMPTY */;
	else if (mcopy.mutex_lockw == 0)
		(void) strcat(buf, "\nthe lock is unowned");
	else if (!(mcopy.mutex_type & USYNC_PROCESS)) {
		(void) strcat(buf, "\nthe lock owner is ");
		ultos((uint64_t)mcopy.mutex_owner, 16, buf + strlen(buf));
	} else {
		(void) strcat(buf, " in process ");
		ultos((uint64_t)pid, 10, buf + strlen(buf));
		(void) strcat(buf, "\nthe lock owner is ");
		ultos((uint64_t)mcopy.mutex_owner, 16, buf + strlen(buf));
		(void) strcat(buf, " in process ");
		ultos((uint64_t)mcopy.mutex_ownerpid, 10, buf + strlen(buf));
	}
	(void) strcat(buf, "\n\n");
	(void) __write(2, buf, strlen(buf));
	if (udp->uberflags.uf_thread_error_detection >= 2)
		Abort(buf);
	assert_thread = NULL;
	(void) _lwp_mutex_unlock(&assert_lock);
	if (self != NULL)
		exit_critical(self);
}

/*
 * Report application lock usage error for rwlocks.
 * Not called if _THREAD_ERROR_DETECTION=0.
 * Continue execution if _THREAD_ERROR_DETECTION=1.
 * Dump core if _THREAD_ERROR_DETECTION=2.
 */
void
rwlock_error(const rwlock_t *rp, const char *who, const char *msg)
{
	rwlock_t rcopy;
	uint32_t rwstate;
	char buf[800];
	uberdata_t *udp;
	ulwp_t *self;
	lwpid_t lwpid;
	pid_t pid;
	int process;

	/*
	 * Take a snapshot of the rwlock before it changes (we hope!).
	 * Use memcpy() rather than 'rcopy = *rp' in case rp is unaligned.
	 */
	(void) memcpy(&rcopy, rp, sizeof (rcopy));

	/* avoid recursion deadlock */
	if ((self = __curthread()) != NULL) {
		if (assert_thread == self)
			_exit(127);
		enter_critical(self);
		(void) _lwp_mutex_lock(&assert_lock);
		assert_thread = self;
		lwpid = self->ul_lwpid;
		udp = self->ul_uberdata;
		pid = udp->pid;
	} else {
		self = NULL;
		(void) _lwp_mutex_lock(&assert_lock);
		lwpid = _lwp_self();
		udp = &__uberdata;
		pid = getpid();
	}

	rwstate = (uint32_t)rcopy.rwlock_readers;
	process = (rcopy.rwlock_type & USYNC_PROCESS);

	(void) strcpy(buf,
	    "\n*** _THREAD_ERROR_DETECTION: lock usage error detected ***\n");
	(void) strcat(buf, who);
	(void) strcat(buf, "(");
	ultos((uint64_t)(uintptr_t)rp, 16, buf + strlen(buf));
	(void) strcat(buf, "): ");
	(void) strcat(buf, msg);
	(void) strcat(buf, "\ncalling thread is ");
	ultos((uint64_t)(uintptr_t)self, 16, buf + strlen(buf));
	(void) strcat(buf, " thread-id ");
	ultos((uint64_t)lwpid, 10, buf + strlen(buf));
	if (process) {
		(void) strcat(buf, " in process ");
		ultos((uint64_t)pid, 10, buf + strlen(buf));
	}
	if (rwstate & URW_WRITE_LOCKED) {
		(void) strcat(buf, "\nthe writer lock owner is ");
		ultos((uint64_t)rcopy.rwlock_owner, 16,
		    buf + strlen(buf));
		if (process) {
			(void) strcat(buf, " in process ");
			ultos((uint64_t)rcopy.rwlock_ownerpid, 10,
			    buf + strlen(buf));
		}
	} else if (rwstate & URW_READERS_MASK) {
		(void) strcat(buf, "\nthe reader lock is held by ");
		ultos((uint64_t)(rwstate & URW_READERS_MASK), 10,
		    buf + strlen(buf));
		(void) strcat(buf, " readers");
	} else {
		(void) strcat(buf, "\nthe lock is unowned");
	}
	if (rwstate & URW_HAS_WAITERS)
		(void) strcat(buf, "\nand the lock appears to have waiters");
	(void) strcat(buf, "\n\n");
	(void) __write(2, buf, strlen(buf));
	if (udp->uberflags.uf_thread_error_detection >= 2)
		Abort(buf);
	assert_thread = NULL;
	(void) _lwp_mutex_unlock(&assert_lock);
	if (self != NULL)
		exit_critical(self);
}

/*
 * Report a thread usage error.
 * Not called if _THREAD_ERROR_DETECTION=0.
 * Writes message and continues execution if _THREAD_ERROR_DETECTION=1.
 * Writes message and dumps core if _THREAD_ERROR_DETECTION=2.
 */
void
thread_error(const char *msg)
{
	char buf[800];
	uberdata_t *udp;
	ulwp_t *self;
	lwpid_t lwpid;

	/* avoid recursion deadlock */
	if ((self = __curthread()) != NULL) {
		if (assert_thread == self)
			_exit(127);
		enter_critical(self);
		(void) _lwp_mutex_lock(&assert_lock);
		assert_thread = self;
		lwpid = self->ul_lwpid;
		udp = self->ul_uberdata;
	} else {
		self = NULL;
		(void) _lwp_mutex_lock(&assert_lock);
		lwpid = _lwp_self();
		udp = &__uberdata;
	}

	(void) strcpy(buf, "\n*** _THREAD_ERROR_DETECTION: "
	    "thread usage error detected ***\n*** ");
	(void) strcat(buf, msg);

	(void) strcat(buf, "\n*** calling thread is ");
	ultos((uint64_t)(uintptr_t)self, 16, buf + strlen(buf));
	(void) strcat(buf, " thread-id ");
	ultos((uint64_t)lwpid, 10, buf + strlen(buf));
	(void) strcat(buf, "\n\n");
	(void) __write(2, buf, strlen(buf));
	if (udp->uberflags.uf_thread_error_detection >= 2)
		Abort(buf);
	assert_thread = NULL;
	(void) _lwp_mutex_unlock(&assert_lock);
	if (self != NULL)
		exit_critical(self);
}

/*
 * We use __assfail() because the libc __assert() calls
 * gettext() which calls malloc() which grabs a mutex.
 * We do everything without calling standard i/o.
 * assfail() and _assfail() are exported functions;
 * __assfail() is private to libc.
 */
#pragma weak _assfail = __assfail
void
__assfail(const char *assertion, const char *filename, int line_num)
{
	char buf[800];	/* no assert() message in the library is this long */
	ulwp_t *self;
	lwpid_t lwpid;

	/* avoid recursion deadlock */
	if ((self = __curthread()) != NULL) {
		if (assert_thread == self)
			_exit(127);
		enter_critical(self);
		(void) _lwp_mutex_lock(&assert_lock);
		assert_thread = self;
		lwpid = self->ul_lwpid;
	} else {
		self = NULL;
		(void) _lwp_mutex_lock(&assert_lock);
		lwpid = _lwp_self();
	}

	/*
	 * This is a hack, but since the Abort function isn't exported
	 * to outside consumers, libzpool's vpanic() function calls
	 * assfail() with a filename set to NULL. In that case, it'd be
	 * best not to print "assertion failed" since it was a panic and
	 * not an assertion failure.
	 */
	if (filename == NULL) {
		(void) strcpy(buf, "failure for thread ");
	} else {
		(void) strcpy(buf, "assertion failed for thread ");
	}

	ultos((uint64_t)(uintptr_t)self, 16, buf + strlen(buf));
	(void) strcat(buf, ", thread-id ");
	ultos((uint64_t)lwpid, 10, buf + strlen(buf));
	(void) strcat(buf, ": ");
	(void) strcat(buf, assertion);

	if (filename != NULL) {
		(void) strcat(buf, ", file ");
		(void) strcat(buf, filename);
		(void) strcat(buf, ", line ");
		ultos((uint64_t)line_num, 10, buf + strlen(buf));
	}

	(void) strcat(buf, "\n");
	(void) __write(2, buf, strlen(buf));
	/*
	 * We could replace the call to Abort() with the following code
	 * if we want just to issue a warning message and not die.
	 *	assert_thread = NULL;
	 *	_lwp_mutex_unlock(&assert_lock);
	 *	if (self != NULL)
	 *		exit_critical(self);
	 */
	Abort(buf);
}

/*
 * We define and export this version of assfail() just because libaio
 * used to define and export it, needlessly.  Now that libaio is folded
 * into libc, we need to continue this for ABI/version reasons.
 * We don't use "#pragma weak assfail __assfail" in order to avoid
 * warnings from the check_fnames utility at build time for libraries
 * that define their own version of assfail().
 */
void
assfail(const char *assertion, const char *filename, int line_num)
{
	__assfail(assertion, filename, line_num);
}

void
assfail3(const char *assertion, uintmax_t lv, const char *op, uintmax_t rv,
    const char *filename, int line_num)
{
	char buf[1000];
	(void) strcpy(buf, assertion);
	(void) strcat(buf, " (");
	ultos((uint64_t)lv, 16, buf + strlen(buf));
	(void) strcat(buf, " ");
	(void) strcat(buf, op);
	(void) strcat(buf, " ");
	ultos((uint64_t)rv, 16, buf + strlen(buf));
	(void) strcat(buf, ")");
	__assfail(buf, filename, line_num);
}
