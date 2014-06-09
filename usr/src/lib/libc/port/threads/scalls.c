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
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

/* Copyright (c) 2013, OmniTI Computer Consulting, Inc. All rights reserved. */

#include "lint.h"
#include "thr_uberdata.h"
#include <stdarg.h>
#include <poll.h>
#include <stropts.h>
#include <dlfcn.h>
#include <wait.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/door.h>

/*
 * These leading-underbar symbols exist because mistakes were made
 * in the past that put them into non-SUNWprivate versions of
 * the libc mapfiles.  They should be eliminated, but oh well...
 */
#pragma weak _fork = fork
#pragma weak _read = read
#pragma weak _write = write
#pragma weak _getmsg = getmsg
#pragma weak _getpmsg = getpmsg
#pragma weak _putmsg = putmsg
#pragma weak _putpmsg = putpmsg
#pragma weak _sleep = sleep
#pragma weak _close = close
#pragma weak _creat = creat
#pragma weak _fcntl = fcntl
#pragma weak _fsync = fsync
#pragma weak _lockf = lockf
#pragma weak _msgrcv = msgrcv
#pragma weak _msgsnd = msgsnd
#pragma weak _msync = msync
#pragma weak _open = open
#pragma weak _openat = openat
#pragma weak _pause = pause
#pragma weak _readv = readv
#pragma weak _sigpause = sigpause
#pragma weak _sigsuspend = sigsuspend
#pragma weak _tcdrain = tcdrain
#pragma weak _waitid = waitid
#pragma weak _writev = writev

#if !defined(_LP64)
#pragma weak _creat64 = creat64
#pragma weak _lockf64 = lockf64
#pragma weak _open64 = open64
#pragma weak _openat64 = openat64
#pragma weak _pread64 = pread64
#pragma weak _pwrite64 = pwrite64
#endif

/*
 * These are SUNWprivate, but they are being used by Sun Studio libcollector.
 */
#pragma weak _fork1 = fork1
#pragma weak _forkall = forkall

/*
 * atfork_lock protects the pthread_atfork() data structures.
 *
 * fork_lock does double-duty.  Not only does it (and atfork_lock)
 * serialize calls to fork() and forkall(), but it also serializes calls
 * to thr_suspend() and thr_continue() (because fork() and forkall() also
 * suspend and continue other threads and they want no competition).
 *
 * Functions called in dlopen()ed L10N objects can do anything, including
 * call malloc() and free().  Such calls are not fork-safe when protected
 * by an ordinary mutex that is acquired in libc's prefork processing
 * because, with an interposed malloc library present, there would be a
 * lock ordering violation due to the pthread_atfork() prefork function
 * in the interposition library acquiring its malloc lock(s) before the
 * ordinary mutex in libc being acquired by libc's prefork functions.
 *
 * Within libc, calls to malloc() and free() are fork-safe if the calls
 * are made while holding no other libc locks.  This covers almost all
 * of libc's malloc() and free() calls.  For those libc code paths, such
 * as the above-mentioned L10N calls, that require serialization and that
 * may call malloc() or free(), libc uses callout_lock_enter() to perform
 * the serialization.  This works because callout_lock is not acquired as
 * part of running the pthread_atfork() prefork handlers (to avoid the
 * lock ordering violation described above).  Rather, it is simply
 * reinitialized in postfork1_child() to cover the case that some
 * now-defunct thread might have been suspended while holding it.
 */

void
fork_lock_enter(void)
{
	ASSERT(curthread->ul_critical == 0);
	(void) mutex_lock(&curthread->ul_uberdata->fork_lock);
}

void
fork_lock_exit(void)
{
	ASSERT(curthread->ul_critical == 0);
	(void) mutex_unlock(&curthread->ul_uberdata->fork_lock);
}

/*
 * Use cancel_safe_mutex_lock() to protect against being cancelled while
 * holding callout_lock and calling outside of libc (via L10N plugins).
 * We will honor a pending cancellation request when callout_lock_exit()
 * is called, by calling cancel_safe_mutex_unlock().
 */
void
callout_lock_enter(void)
{
	ASSERT(curthread->ul_critical == 0);
	cancel_safe_mutex_lock(&curthread->ul_uberdata->callout_lock);
}

void
callout_lock_exit(void)
{
	ASSERT(curthread->ul_critical == 0);
	cancel_safe_mutex_unlock(&curthread->ul_uberdata->callout_lock);
}

pid_t
forkx(int flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	pid_t pid;

	if (self->ul_vfork) {
		/*
		 * We are a child of vfork(); omit all of the fork
		 * logic and go straight to the system call trap.
		 * A vfork() child of a multithreaded parent
		 * must never call fork().
		 */
		if (udp->uberflags.uf_mt) {
			errno = ENOTSUP;
			return (-1);
		}
		pid = __forkx(flags);
		if (pid == 0) {		/* child */
			udp->pid = getpid();
			self->ul_vfork = 0;
		}
		return (pid);
	}

	sigoff(self);
	if (self->ul_fork) {
		/*
		 * Cannot call fork() from a fork handler.
		 */
		sigon(self);
		errno = EDEADLK;
		return (-1);
	}
	self->ul_fork = 1;

	/*
	 * The functions registered by pthread_atfork() are defined by
	 * the application and its libraries and we must not hold any
	 * internal lmutex_lock()-acquired locks while invoking them.
	 * We hold only udp->atfork_lock to protect the atfork linkages.
	 * If one of these pthread_atfork() functions attempts to fork
	 * or to call pthread_atfork(), libc will detect the error and
	 * fail the call with EDEADLK.  Otherwise, the pthread_atfork()
	 * functions are free to do anything they please (except they
	 * will not receive any signals).
	 */
	(void) mutex_lock(&udp->atfork_lock);

	/*
	 * Posix (SUSv3) requires fork() to be async-signal-safe.
	 * This cannot be made to happen with fork handlers in place
	 * (they grab locks).  To be in nominal compliance, don't run
	 * any fork handlers if we are called within a signal context.
	 * This leaves the child process in a questionable state with
	 * respect to its locks, but at least the parent process does
	 * not become deadlocked due to the calling thread attempting
	 * to acquire a lock that it already owns.
	 */
	if (self->ul_siglink == NULL)
		_prefork_handler();

	/*
	 * Block every other thread attempting thr_suspend() or thr_continue().
	 */
	(void) mutex_lock(&udp->fork_lock);

	/*
	 * Block all signals.
	 * Just deferring them via sigoff() is not enough.
	 * We have to avoid taking a deferred signal in the child
	 * that was actually sent to the parent before __forkx().
	 */
	block_all_signals(self);

	/*
	 * This suspends all threads but this one, leaving them
	 * suspended outside of any critical regions in the library.
	 * Thus, we are assured that no lmutex_lock()-acquired library
	 * locks are held while we invoke fork() from the current thread.
	 */
	suspend_fork();

	pid = __forkx(flags);

	if (pid == 0) {		/* child */
		/*
		 * Clear our schedctl pointer.
		 * Discard any deferred signal that was sent to the parent.
		 * Because we blocked all signals before __forkx(), a
		 * deferred signal cannot have been taken by the child.
		 */
		self->ul_schedctl_called = NULL;
		self->ul_schedctl = NULL;
		self->ul_cursig = 0;
		self->ul_siginfo.si_signo = 0;
		udp->pid = getpid();
		/* reset the library's data structures to reflect one thread */
		unregister_locks();
		postfork1_child();
		restore_signals(self);
		(void) mutex_unlock(&udp->fork_lock);
		if (self->ul_siglink == NULL)
			_postfork_child_handler();
	} else {
		/* restart all threads that were suspended for fork() */
		continue_fork(0);
		restore_signals(self);
		(void) mutex_unlock(&udp->fork_lock);
		if (self->ul_siglink == NULL)
			_postfork_parent_handler();
	}

	(void) mutex_unlock(&udp->atfork_lock);
	self->ul_fork = 0;
	sigon(self);

	return (pid);
}

/*
 * fork() is fork1() for both Posix threads and Solaris threads.
 * The forkall() interface exists for applications that require
 * the semantics of replicating all threads.
 */
#pragma weak fork1 = fork
pid_t
fork(void)
{
	return (forkx(0));
}

/*
 * Much of the logic here is the same as in forkx().
 * See the comments in forkx(), above.
 */
pid_t
forkallx(int flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	pid_t pid;

	if (self->ul_vfork) {
		if (udp->uberflags.uf_mt) {
			errno = ENOTSUP;
			return (-1);
		}
		pid = __forkallx(flags);
		if (pid == 0) {		/* child */
			udp->pid = getpid();
			self->ul_vfork = 0;
		}
		return (pid);
	}

	sigoff(self);
	if (self->ul_fork) {
		sigon(self);
		errno = EDEADLK;
		return (-1);
	}
	self->ul_fork = 1;
	(void) mutex_lock(&udp->atfork_lock);
	(void) mutex_lock(&udp->fork_lock);
	block_all_signals(self);
	suspend_fork();

	pid = __forkallx(flags);

	if (pid == 0) {
		self->ul_schedctl_called = NULL;
		self->ul_schedctl = NULL;
		self->ul_cursig = 0;
		self->ul_siginfo.si_signo = 0;
		udp->pid = getpid();
		unregister_locks();
		continue_fork(1);
	} else {
		continue_fork(0);
	}
	restore_signals(self);
	(void) mutex_unlock(&udp->fork_lock);
	(void) mutex_unlock(&udp->atfork_lock);
	self->ul_fork = 0;
	sigon(self);

	return (pid);
}

pid_t
forkall(void)
{
	return (forkallx(0));
}

/*
 * For the implementation of cancellation at cancellation points.
 */
#define	PROLOGUE							\
{									\
	ulwp_t *self = curthread;					\
	int nocancel =							\
	    (self->ul_vfork | self->ul_nocancel | self->ul_libc_locks |	\
	    self->ul_critical | self->ul_sigdefer);			\
	int abort = 0;							\
	if (nocancel == 0) {						\
		self->ul_save_async = self->ul_cancel_async;		\
		if (!self->ul_cancel_disabled) {			\
			self->ul_cancel_async = 1;			\
			if (self->ul_cancel_pending)			\
				pthread_exit(PTHREAD_CANCELED);		\
		}							\
		self->ul_sp = stkptr();					\
	} else if (self->ul_cancel_pending &&				\
	    !self->ul_cancel_disabled) {				\
		set_cancel_eintr_flag(self);				\
		abort = 1;						\
	}

#define	EPILOGUE							\
	if (nocancel == 0) {						\
		self->ul_sp = 0;					\
		self->ul_cancel_async = self->ul_save_async;		\
	}								\
}

/*
 * Perform the body of the action required by most of the cancelable
 * function calls.  The return(function_call) part is to allow the
 * compiler to make the call be executed with tail recursion, which
 * saves a register window on sparc and slightly (not much) improves
 * the code for x86/x64 compilations.
 */
#define	PERFORM(function_call)						\
	PROLOGUE							\
	if (abort) {							\
		*self->ul_errnop = EINTR;				\
		return (-1);						\
	}								\
	if (nocancel)							\
		return (function_call);					\
	rv = function_call;						\
	EPILOGUE							\
	return (rv);

/*
 * Specialized prologue for sigsuspend() and pollsys().
 * These system calls pass a signal mask to the kernel.
 * The kernel replaces the thread's signal mask with the
 * temporary mask before the thread goes to sleep.  If
 * a signal is received, the signal handler will execute
 * with the temporary mask, as modified by the sigaction
 * for the particular signal.
 *
 * We block all signals until we reach the kernel with the
 * temporary mask.  This eliminates race conditions with
 * setting the signal mask while signals are being posted.
 */
#define	PROLOGUE_MASK(sigmask)						\
{									\
	ulwp_t *self = curthread;					\
	int nocancel =							\
	    (self->ul_vfork | self->ul_nocancel | self->ul_libc_locks |	\
	    self->ul_critical | self->ul_sigdefer);			\
	if (!self->ul_vfork) {						\
		if (sigmask) {						\
			block_all_signals(self);			\
			self->ul_tmpmask = *sigmask;			\
			delete_reserved_signals(&self->ul_tmpmask);	\
			self->ul_sigsuspend = 1;			\
		}							\
		if (nocancel == 0) {					\
			self->ul_save_async = self->ul_cancel_async;	\
			if (!self->ul_cancel_disabled) {		\
				self->ul_cancel_async = 1;		\
				if (self->ul_cancel_pending) {		\
					if (self->ul_sigsuspend) {	\
						self->ul_sigsuspend = 0;\
						restore_signals(self);	\
					}				\
					pthread_exit(PTHREAD_CANCELED);	\
				}					\
			}						\
			self->ul_sp = stkptr();				\
		}							\
	}

/*
 * If a signal is taken, we return from the system call wrapper with
 * our original signal mask restored (see code in call_user_handler()).
 * If not (self->ul_sigsuspend is still non-zero), we must restore our
 * original signal mask ourself.
 */
#define	EPILOGUE_MASK							\
	if (nocancel == 0) {						\
		self->ul_sp = 0;					\
		self->ul_cancel_async = self->ul_save_async;		\
	}								\
	if (self->ul_sigsuspend) {					\
		self->ul_sigsuspend = 0;				\
		restore_signals(self);					\
	}								\
}

/*
 * Cancellation prologue and epilogue functions,
 * for cancellation points too complex to include here.
 */
void
_cancel_prologue(void)
{
	ulwp_t *self = curthread;

	self->ul_cancel_prologue =
	    (self->ul_vfork | self->ul_nocancel | self->ul_libc_locks |
	    self->ul_critical | self->ul_sigdefer) != 0;
	if (self->ul_cancel_prologue == 0) {
		self->ul_save_async = self->ul_cancel_async;
		if (!self->ul_cancel_disabled) {
			self->ul_cancel_async = 1;
			if (self->ul_cancel_pending)
				pthread_exit(PTHREAD_CANCELED);
		}
		self->ul_sp = stkptr();
	} else if (self->ul_cancel_pending &&
	    !self->ul_cancel_disabled) {
		set_cancel_eintr_flag(self);
	}
}

void
_cancel_epilogue(void)
{
	ulwp_t *self = curthread;

	if (self->ul_cancel_prologue == 0) {
		self->ul_sp = 0;
		self->ul_cancel_async = self->ul_save_async;
	}
}

/*
 * Called from _thrp_join() (thr_join() is a cancellation point)
 */
int
lwp_wait(thread_t tid, thread_t *found)
{
	int error;

	PROLOGUE
	if (abort)
		return (EINTR);
	while ((error = __lwp_wait(tid, found)) == EINTR && !cancel_active())
		continue;
	EPILOGUE
	return (error);
}

ssize_t
read(int fd, void *buf, size_t size)
{
	extern ssize_t __read(int, void *, size_t);
	ssize_t rv;

	PERFORM(__read(fd, buf, size))
}

ssize_t
write(int fd, const void *buf, size_t size)
{
	extern ssize_t __write(int, const void *, size_t);
	ssize_t rv;

	PERFORM(__write(fd, buf, size))
}

int
getmsg(int fd, struct strbuf *ctlptr, struct strbuf *dataptr,
	int *flagsp)
{
	extern int __getmsg(int, struct strbuf *, struct strbuf *, int *);
	int rv;

	PERFORM(__getmsg(fd, ctlptr, dataptr, flagsp))
}

int
getpmsg(int fd, struct strbuf *ctlptr, struct strbuf *dataptr,
	int *bandp, int *flagsp)
{
	extern int __getpmsg(int, struct strbuf *, struct strbuf *,
	    int *, int *);
	int rv;

	PERFORM(__getpmsg(fd, ctlptr, dataptr, bandp, flagsp))
}

int
putmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int flags)
{
	extern int __putmsg(int, const struct strbuf *,
	    const struct strbuf *, int);
	int rv;

	PERFORM(__putmsg(fd, ctlptr, dataptr, flags))
}

int
__xpg4_putmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int flags)
{
	extern int __putmsg(int, const struct strbuf *,
	    const struct strbuf *, int);
	int rv;

	PERFORM(__putmsg(fd, ctlptr, dataptr, flags|MSG_XPG4))
}

int
putpmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int band, int flags)
{
	extern int __putpmsg(int, const struct strbuf *,
	    const struct strbuf *, int, int);
	int rv;

	PERFORM(__putpmsg(fd, ctlptr, dataptr, band, flags))
}

int
__xpg4_putpmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int band, int flags)
{
	extern int __putpmsg(int, const struct strbuf *,
	    const struct strbuf *, int, int);
	int rv;

	PERFORM(__putpmsg(fd, ctlptr, dataptr, band, flags|MSG_XPG4))
}

int
nanosleep(const timespec_t *rqtp, timespec_t *rmtp)
{
	int error;

	PROLOGUE
	error = abort? EINTR : __nanosleep(rqtp, rmtp);
	EPILOGUE
	if (error) {
		errno = error;
		return (-1);
	}
	return (0);
}

int
clock_nanosleep(clockid_t clock_id, int flags,
	const timespec_t *rqtp, timespec_t *rmtp)
{
	timespec_t reltime;
	hrtime_t start;
	hrtime_t rqlapse;
	hrtime_t lapse;
	int error;

	switch (clock_id) {
	case CLOCK_VIRTUAL:
	case CLOCK_PROCESS_CPUTIME_ID:
	case CLOCK_THREAD_CPUTIME_ID:
		return (ENOTSUP);
	case CLOCK_REALTIME:
	case CLOCK_HIGHRES:
		break;
	default:
		return (EINVAL);
	}
	if (flags & TIMER_ABSTIME) {
		abstime_to_reltime(clock_id, rqtp, &reltime);
		rmtp = NULL;
	} else {
		reltime = *rqtp;
		if (clock_id == CLOCK_HIGHRES)
			start = gethrtime();
	}
restart:
	PROLOGUE
	error = abort? EINTR : __nanosleep(&reltime, rmtp);
	EPILOGUE
	if (error == 0 && clock_id == CLOCK_HIGHRES) {
		/*
		 * Don't return yet if we didn't really get a timeout.
		 * This can happen if we return because someone resets
		 * the system clock.
		 */
		if (flags & TIMER_ABSTIME) {
			if ((hrtime_t)(uint32_t)rqtp->tv_sec * NANOSEC +
			    rqtp->tv_nsec > gethrtime()) {
				abstime_to_reltime(clock_id, rqtp, &reltime);
				goto restart;
			}
		} else {
			rqlapse = (hrtime_t)(uint32_t)rqtp->tv_sec * NANOSEC +
			    rqtp->tv_nsec;
			lapse = gethrtime() - start;
			if (rqlapse > lapse) {
				hrt2ts(rqlapse - lapse, &reltime);
				goto restart;
			}
		}
	}
	if (error == 0 && clock_id == CLOCK_REALTIME &&
	    (flags & TIMER_ABSTIME)) {
		/*
		 * Don't return yet just because someone reset the
		 * system clock.  Recompute the new relative time
		 * and reissue the nanosleep() call if necessary.
		 *
		 * Resetting the system clock causes all sorts of
		 * problems and the SUSV3 standards body should
		 * have made the behavior of clock_nanosleep() be
		 * implementation-defined in such a case rather than
		 * being specific about honoring the new system time.
		 * Standards bodies are filled with fools and idiots.
		 */
		abstime_to_reltime(clock_id, rqtp, &reltime);
		if (reltime.tv_sec != 0 || reltime.tv_nsec != 0)
			goto restart;
	}
	return (error);
}

unsigned int
sleep(unsigned int sec)
{
	unsigned int rem = 0;
	timespec_t ts;
	timespec_t tsr;

	ts.tv_sec = (time_t)sec;
	ts.tv_nsec = 0;
	if (nanosleep(&ts, &tsr) == -1 && errno == EINTR) {
		rem = (unsigned int)tsr.tv_sec;
		if (tsr.tv_nsec >= NANOSEC / 2)
			rem++;
	}
	return (rem);
}

int
usleep(useconds_t usec)
{
	timespec_t ts;

	ts.tv_sec = usec / MICROSEC;
	ts.tv_nsec = (long)(usec % MICROSEC) * 1000;
	(void) nanosleep(&ts, NULL);
	return (0);
}

int
close(int fildes)
{
	extern void _aio_close(int);
	extern int __close(int);
	int rv;

	/*
	 * If we call _aio_close() while in a critical region,
	 * we will draw an ASSERT() failure, so don't do it.
	 * No calls to close() from within libc need _aio_close();
	 * only the application's calls to close() need this,
	 * and such calls are never from a libc critical region.
	 */
	if (curthread->ul_critical == 0)
		_aio_close(fildes);
	PERFORM(__close(fildes))
}

int
door_call(int d, door_arg_t *params)
{
	extern int __door_call(int, door_arg_t *);
	int rv;

	PERFORM(__door_call(d, params))
}

int
fcntl(int fildes, int cmd, ...)
{
	extern int __fcntl(int, int, ...);
	intptr_t arg;
	int rv;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, intptr_t);
	va_end(ap);
	if (cmd != F_SETLKW)
		return (__fcntl(fildes, cmd, arg));
	PERFORM(__fcntl(fildes, cmd, arg))
}

int
fdatasync(int fildes)
{
	extern int __fdsync(int, int);
	int rv;

	PERFORM(__fdsync(fildes, FDSYNC))
}

int
fsync(int fildes)
{
	extern int __fdsync(int, int);
	int rv;

	PERFORM(__fdsync(fildes, FSYNC))
}

int
lockf(int fildes, int function, off_t size)
{
	extern int __lockf(int, int, off_t);
	int rv;

	PERFORM(__lockf(fildes, function, size))
}

#if !defined(_LP64)
int
lockf64(int fildes, int function, off64_t size)
{
	extern int __lockf64(int, int, off64_t);
	int rv;

	PERFORM(__lockf64(fildes, function, size))
}
#endif	/* !_LP64 */

ssize_t
msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	extern ssize_t __msgrcv(int, void *, size_t, long, int);
	ssize_t rv;

	PERFORM(__msgrcv(msqid, msgp, msgsz, msgtyp, msgflg))
}

int
msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
	extern int __msgsnd(int, const void *, size_t, int);
	int rv;

	PERFORM(__msgsnd(msqid, msgp, msgsz, msgflg))
}

int
msync(caddr_t addr, size_t len, int flags)
{
	extern int __msync(caddr_t, size_t, int);
	int rv;

	PERFORM(__msync(addr, len, flags))
}

int
openat(int fd, const char *path, int oflag, ...)
{
	mode_t mode;
	int rv;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	PERFORM(__openat(fd, path, oflag, mode))
}

int
open(const char *path, int oflag, ...)
{
	mode_t mode;
	int rv;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	PERFORM(__open(path, oflag, mode))
}

int
creat(const char *path, mode_t mode)
{
	return (open(path, O_WRONLY | O_CREAT | O_TRUNC, mode));
}

#if !defined(_LP64)
int
openat64(int fd, const char *path, int oflag, ...)
{
	mode_t mode;
	int rv;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	PERFORM(__openat64(fd, path, oflag, mode))
}

int
open64(const char *path, int oflag, ...)
{
	mode_t mode;
	int rv;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	PERFORM(__open64(path, oflag, mode))
}

int
creat64(const char *path, mode_t mode)
{
	return (open64(path, O_WRONLY | O_CREAT | O_TRUNC, mode));
}
#endif	/* !_LP64 */

int
pause(void)
{
	extern int __pause(void);
	int rv;

	PERFORM(__pause())
}

ssize_t
pread(int fildes, void *buf, size_t nbyte, off_t offset)
{
	extern ssize_t __pread(int, void *, size_t, off_t);
	ssize_t rv;

	PERFORM(__pread(fildes, buf, nbyte, offset))
}

#if !defined(_LP64)
ssize_t
pread64(int fildes, void *buf, size_t nbyte, off64_t offset)
{
	extern ssize_t __pread64(int, void *, size_t, off64_t);
	ssize_t rv;

	PERFORM(__pread64(fildes, buf, nbyte, offset))
}

ssize_t
preadv64(int fildes, const struct iovec *iov, int iovcnt, off64_t offset)
{

	extern ssize_t __preadv64(int, const struct iovec *, int, off_t, off_t);
	ssize_t rv;

	PERFORM(__preadv64(fildes, iov, iovcnt, offset & 0xffffffffULL,
	    offset>>32))
}
#endif	/* !_LP64 */

ssize_t
preadv(int fildes, const struct iovec *iov, int iovcnt, off_t offset)
{

	extern ssize_t __preadv(int, const struct iovec *, int, off_t, off_t);
	ssize_t rv;

	PERFORM(__preadv(fildes, iov, iovcnt, offset, 0))
}
ssize_t
pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
{
	extern ssize_t __pwrite(int, const void *, size_t, off_t);
	ssize_t rv;

	PERFORM(__pwrite(fildes, buf, nbyte, offset))
}

#if !defined(_LP64)
ssize_t
pwrite64(int fildes, const void *buf, size_t nbyte, off64_t offset)
{
	extern ssize_t __pwrite64(int, const void *, size_t, off64_t);
	ssize_t rv;

	PERFORM(__pwrite64(fildes, buf, nbyte, offset))
}

ssize_t
pwritev64(int fildes, const struct iovec *iov, int iovcnt, off64_t offset)
{

	extern ssize_t __pwritev64(int,
	    const struct iovec *, int, off_t, off_t);
	ssize_t rv;

	PERFORM(__pwritev64(fildes, iov, iovcnt, offset &
	    0xffffffffULL, offset>>32))
}

#endif	/* !_LP64 */

ssize_t
pwritev(int fildes, const struct iovec *iov, int iovcnt, off_t offset)
{
	extern ssize_t __pwritev(int, const struct iovec *, int, off_t, off_t);
	ssize_t rv;

	PERFORM(__pwritev(fildes, iov, iovcnt, offset, 0))
}

ssize_t
readv(int fildes, const struct iovec *iov, int iovcnt)
{
	extern ssize_t __readv(int, const struct iovec *, int);
	ssize_t rv;

	PERFORM(__readv(fildes, iov, iovcnt))
}

int
sigpause(int sig)
{
	extern int __sigpause(int);
	int rv;

	PERFORM(__sigpause(sig))
}

int
sigsuspend(const sigset_t *set)
{
	extern int __sigsuspend(const sigset_t *);
	int rv;

	PROLOGUE_MASK(set)
	rv = __sigsuspend(set);
	EPILOGUE_MASK
	return (rv);
}

int
_pollsys(struct pollfd *fds, nfds_t nfd, const timespec_t *timeout,
	const sigset_t *sigmask)
{
	extern int __pollsys(struct pollfd *, nfds_t, const timespec_t *,
	    const sigset_t *);
	int rv;

	PROLOGUE_MASK(sigmask)
	rv = __pollsys(fds, nfd, timeout, sigmask);
	EPILOGUE_MASK
	return (rv);
}

int
sigtimedwait(const sigset_t *set, siginfo_t *infop, const timespec_t *timeout)
{
	extern int __sigtimedwait(const sigset_t *, siginfo_t *,
	    const timespec_t *);
	siginfo_t info;
	int sig;

	PROLOGUE
	if (abort) {
		*self->ul_errnop = EINTR;
		sig = -1;
	} else {
		sig = __sigtimedwait(set, &info, timeout);
		if (sig == SIGCANCEL &&
		    (SI_FROMKERNEL(&info) || info.si_code == SI_LWP)) {
			do_sigcancel();
			*self->ul_errnop = EINTR;
			sig = -1;
		}
	}
	EPILOGUE
	if (sig != -1 && infop)
		(void) memcpy(infop, &info, sizeof (*infop));
	return (sig);
}

int
sigwait(sigset_t *set)
{
	return (sigtimedwait(set, NULL, NULL));
}

int
sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
	return (sigtimedwait(set, info, NULL));
}

int
sigqueue(pid_t pid, int signo, const union sigval value)
{
	extern int __sigqueue(pid_t pid, int signo,
	    /* const union sigval */ void *value, int si_code, int block);
	return (__sigqueue(pid, signo, value.sival_ptr, SI_QUEUE, 0));
}

int
_so_accept(int sock, struct sockaddr *addr, uint_t *addrlen, int version,
    int flags)
{
	extern int __so_accept(int, struct sockaddr *, uint_t *, int, int);
	int rv;

	PERFORM(__so_accept(sock, addr, addrlen, version, flags))
}

int
_so_connect(int sock, struct sockaddr *addr, uint_t addrlen, int version)
{
	extern int __so_connect(int, struct sockaddr *, uint_t, int);
	int rv;

	PERFORM(__so_connect(sock, addr, addrlen, version))
}

int
_so_recv(int sock, void *buf, size_t len, int flags)
{
	extern int __so_recv(int, void *, size_t, int);
	int rv;

	PERFORM(__so_recv(sock, buf, len, flags))
}

int
_so_recvfrom(int sock, void *buf, size_t len, int flags,
    struct sockaddr *addr, int *addrlen)
{
	extern int __so_recvfrom(int, void *, size_t, int,
	    struct sockaddr *, int *);
	int rv;

	PERFORM(__so_recvfrom(sock, buf, len, flags, addr, addrlen))
}

int
_so_recvmsg(int sock, struct msghdr *msg, int flags)
{
	extern int __so_recvmsg(int, struct msghdr *, int);
	int rv;

	PERFORM(__so_recvmsg(sock, msg, flags))
}

int
_so_send(int sock, const void *buf, size_t len, int flags)
{
	extern int __so_send(int, const void *, size_t, int);
	int rv;

	PERFORM(__so_send(sock, buf, len, flags))
}

int
_so_sendmsg(int sock, const struct msghdr *msg, int flags)
{
	extern int __so_sendmsg(int, const struct msghdr *, int);
	int rv;

	PERFORM(__so_sendmsg(sock, msg, flags))
}

int
_so_sendto(int sock, const void *buf, size_t len, int flags,
    const struct sockaddr *addr, int *addrlen)
{
	extern int __so_sendto(int, const void *, size_t, int,
	    const struct sockaddr *, int *);
	int rv;

	PERFORM(__so_sendto(sock, buf, len, flags, addr, addrlen))
}

int
tcdrain(int fildes)
{
	extern int __tcdrain(int);
	int rv;

	PERFORM(__tcdrain(fildes))
}

int
waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	extern int __waitid(idtype_t, id_t, siginfo_t *, int);
	int rv;

	if (options & WNOHANG)
		return (__waitid(idtype, id, infop, options));
	PERFORM(__waitid(idtype, id, infop, options))
}

ssize_t
writev(int fildes, const struct iovec *iov, int iovcnt)
{
	extern ssize_t __writev(int, const struct iovec *, int);
	ssize_t rv;

	PERFORM(__writev(fildes, iov, iovcnt))
}
