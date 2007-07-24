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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"
#include <stdarg.h>
#include <poll.h>
#include <stropts.h>
#include <dlfcn.h>
#include <sys/uio.h>

/*
 * fork_lock is special -- We can't use lmutex_lock() (and thereby enter
 * a critical region) because the second thread to reach this point would
 * become unstoppable and the first thread would hang waiting for the
 * second thread to stop itself.  Therefore we don't use lmutex_lock() in
 * fork_lock_enter(), but we do defer signals (the other form of concurrency).
 *
 * fork_lock_enter() does triple-duty.  Not only does it serialize
 * calls to fork() and forkall(), but it also serializes calls to
 * thr_suspend() (fork() and forkall() also suspend other threads),
 * and furthermore it serializes I18N calls to functions in other
 * dlopen()ed L10N objects that might be calling malloc()/free().
 */

static void
fork_lock_error(const char *who)
{
	char msg[200];

	(void) strlcpy(msg, "deadlock condition: ", sizeof (msg));
	(void) strlcat(msg, who, sizeof (msg));
	(void) strlcat(msg, "() called from a fork handler", sizeof (msg));
	thread_error(msg);
}

int
fork_lock_enter(const char *who)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int error = 0;

	ASSERT(self->ul_critical == 0);
	sigoff(self);
	(void) _private_mutex_lock(&udp->fork_lock);
	if (udp->fork_count) {
		ASSERT(udp->fork_owner == self);
		/*
		 * This is a simple recursive lock except that we
		 * inform the caller if we have been called from
		 * a fork handler and let it deal with that fact.
		 */
		if (self->ul_fork) {
			/*
			 * We have been called from a fork handler.
			 */
			if (who != NULL &&
			    udp->uberflags.uf_thread_error_detection)
				fork_lock_error(who);
			error = EDEADLK;
		}
	}
	udp->fork_owner = self;
	udp->fork_count++;
	return (error);
}

void
fork_lock_exit(void)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	ASSERT(self->ul_critical == 0);
	ASSERT(udp->fork_count != 0 && udp->fork_owner == self);
	if (--udp->fork_count == 0)
		udp->fork_owner = NULL;
	(void) _private_mutex_unlock(&udp->fork_lock);
	sigon(self);
}

/*
 * Note: Instead of making this function static, we reduce it to local
 * scope in the mapfile. That allows the linker to prevent it from
 * appearing in the .SUNW_dynsymsort section.
 */
#pragma weak forkx = _private_forkx
#pragma weak _forkx = _private_forkx
pid_t
_private_forkx(int flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	pid_t pid;
	int error;

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
			udp->pid = _private_getpid();
			self->ul_vfork = 0;
		}
		return (pid);
	}

	if ((error = fork_lock_enter("fork")) != 0) {
		/*
		 * Cannot call fork() from a fork handler.
		 */
		fork_lock_exit();
		errno = error;
		return (-1);
	}
	self->ul_fork = 1;

	/*
	 * The functions registered by pthread_atfork() are defined by
	 * the application and its libraries and we must not hold any
	 * internal libc locks while invoking them.  The fork_lock_enter()
	 * function serializes fork(), thr_suspend(), pthread_atfork() and
	 * dlclose() (which destroys whatever pthread_atfork() functions
	 * the library may have set up).  If one of these pthread_atfork()
	 * functions attempts to fork or suspend another thread or call
	 * pthread_atfork() or dlclose a library, it will detect a deadlock
	 * in fork_lock_enter().  Otherwise, the pthread_atfork() functions
	 * are free to do anything they please (except they will not
	 * receive any signals).
	 */
	_prefork_handler();

	/*
	 * Block all signals.
	 * Just deferring them via sigon() is not enough.
	 * We have to avoid taking a deferred signal in the child
	 * that was actually sent to the parent before __forkx().
	 */
	block_all_signals(self);

	/*
	 * This suspends all threads but this one, leaving them
	 * suspended outside of any critical regions in the library.
	 * Thus, we are assured that no library locks are held
	 * while we invoke fork() from the current thread.
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
		udp->pid = _private_getpid();
		/* reset the library's data structures to reflect one thread */
		unregister_locks();
		postfork1_child();
		restore_signals(self);
		_postfork_child_handler();
	} else {
		/* restart all threads that were suspended for fork() */
		continue_fork(0);
		restore_signals(self);
		_postfork_parent_handler();
	}

	self->ul_fork = 0;
	fork_lock_exit();

	return (pid);
}

/*
 * fork() is fork1() for both Posix threads and Solaris threads.
 * The forkall() interface exists for applications that require
 * the semantics of replicating all threads.
 */
#pragma weak fork1 = _fork
#pragma weak _fork1 = _fork
#pragma weak fork = _fork
pid_t
_fork(void)
{
	return (_private_forkx(0));
}

/*
 * Much of the logic here is the same as in forkx().
 * See the comments in forkx(), above.
 */
#pragma weak forkallx = _private_forkallx
#pragma weak _forkallx = _private_forkallx
pid_t
_private_forkallx(int flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	pid_t pid;
	int error;

	if (self->ul_vfork) {
		if (udp->uberflags.uf_mt) {
			errno = ENOTSUP;
			return (-1);
		}
		pid = __forkallx(flags);
		if (pid == 0) {		/* child */
			udp->pid = _private_getpid();
			self->ul_vfork = 0;
		}
		return (pid);
	}

	if ((error = fork_lock_enter("forkall")) != 0) {
		fork_lock_exit();
		errno = error;
		return (-1);
	}
	self->ul_fork = 1;
	block_all_signals(self);
	suspend_fork();

	pid = __forkallx(flags);

	if (pid == 0) {
		self->ul_schedctl_called = NULL;
		self->ul_schedctl = NULL;
		self->ul_cursig = 0;
		self->ul_siginfo.si_signo = 0;
		udp->pid = _private_getpid();
		unregister_locks();
		continue_fork(1);
	} else {
		continue_fork(0);
	}
	restore_signals(self);
	self->ul_fork = 0;
	fork_lock_exit();

	return (pid);
}

#pragma weak forkall = _forkall
pid_t
_forkall(void)
{
	return (_private_forkallx(0));
}

/*
 * Hacks for system calls to provide cancellation
 * and improve java garbage collection.
 */
#define	PROLOGUE							\
{									\
	ulwp_t *self = curthread;					\
	int nocancel = (self->ul_vfork | self->ul_nocancel);		\
	if (nocancel == 0) {						\
		self->ul_save_async = self->ul_cancel_async;		\
		if (!self->ul_cancel_disabled) {			\
			self->ul_cancel_async = 1;			\
			if (self->ul_cancel_pending)			\
				_pthread_exit(PTHREAD_CANCELED);	\
		}							\
		self->ul_sp = stkptr();					\
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
	int nocancel = (self->ul_vfork | self->ul_nocancel);		\
	if (!self->ul_vfork) {						\
		if (sigmask) {						\
			block_all_signals(self);			\
			self->ul_tmpmask.__sigbits[0] = sigmask->__sigbits[0]; \
			self->ul_tmpmask.__sigbits[1] = sigmask->__sigbits[1]; \
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
					_pthread_exit(PTHREAD_CANCELED);\
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

	self->ul_cancel_prologue = (self->ul_vfork | self->ul_nocancel);
	if (self->ul_cancel_prologue == 0) {
		self->ul_save_async = self->ul_cancel_async;
		if (!self->ul_cancel_disabled) {
			self->ul_cancel_async = 1;
			if (self->ul_cancel_pending)
				_pthread_exit(PTHREAD_CANCELED);
		}
		self->ul_sp = stkptr();
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
	while ((error = __lwp_wait(tid, found)) == EINTR)
		;
	EPILOGUE
	return (error);
}

ssize_t
read(int fd, void *buf, size_t size)
{
	extern ssize_t _read(int, void *, size_t);
	ssize_t rv;

	PERFORM(_read(fd, buf, size))
}

ssize_t
write(int fd, const void *buf, size_t size)
{
	extern ssize_t _write(int, const void *, size_t);
	ssize_t rv;

	PERFORM(_write(fd, buf, size))
}

int
getmsg(int fd, struct strbuf *ctlptr, struct strbuf *dataptr,
	int *flagsp)
{
	extern int _getmsg(int, struct strbuf *, struct strbuf *, int *);
	int rv;

	PERFORM(_getmsg(fd, ctlptr, dataptr, flagsp))
}

int
getpmsg(int fd, struct strbuf *ctlptr, struct strbuf *dataptr,
	int *bandp, int *flagsp)
{
	extern int _getpmsg(int, struct strbuf *, struct strbuf *,
		int *, int *);
	int rv;

	PERFORM(_getpmsg(fd, ctlptr, dataptr, bandp, flagsp))
}

int
putmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int flags)
{
	extern int _putmsg(int, const struct strbuf *,
		const struct strbuf *, int);
	int rv;

	PERFORM(_putmsg(fd, ctlptr, dataptr, flags))
}

int
__xpg4_putmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int flags)
{
	extern int _putmsg(int, const struct strbuf *,
		const struct strbuf *, int);
	int rv;

	PERFORM(_putmsg(fd, ctlptr, dataptr, flags|MSG_XPG4))
}

int
putpmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int band, int flags)
{
	extern int _putpmsg(int, const struct strbuf *,
		const struct strbuf *, int, int);
	int rv;

	PERFORM(_putpmsg(fd, ctlptr, dataptr, band, flags))
}

int
__xpg4_putpmsg(int fd, const struct strbuf *ctlptr,
	const struct strbuf *dataptr, int band, int flags)
{
	extern int _putpmsg(int, const struct strbuf *,
		const struct strbuf *, int, int);
	int rv;

	PERFORM(_putpmsg(fd, ctlptr, dataptr, band, flags|MSG_XPG4))
}

#pragma weak nanosleep = _nanosleep
int
_nanosleep(const timespec_t *rqtp, timespec_t *rmtp)
{
	int error;

	PROLOGUE
	error = __nanosleep(rqtp, rmtp);
	EPILOGUE
	if (error) {
		errno = error;
		return (-1);
	}
	return (0);
}

#pragma weak clock_nanosleep = _clock_nanosleep
int
_clock_nanosleep(clockid_t clock_id, int flags,
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
	error = __nanosleep(&reltime, rmtp);
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

#pragma weak sleep = _sleep
unsigned int
_sleep(unsigned int sec)
{
	unsigned int rem = 0;
	int error;
	timespec_t ts;
	timespec_t tsr;

	ts.tv_sec = (time_t)sec;
	ts.tv_nsec = 0;
	PROLOGUE
	error = __nanosleep(&ts, &tsr);
	EPILOGUE
	if (error == EINTR) {
		rem = (unsigned int)tsr.tv_sec;
		if (tsr.tv_nsec >= NANOSEC / 2)
			rem++;
	}
	return (rem);
}

#pragma weak usleep = _usleep
int
_usleep(useconds_t usec)
{
	timespec_t ts;

	ts.tv_sec = usec / MICROSEC;
	ts.tv_nsec = (long)(usec % MICROSEC) * 1000;
	PROLOGUE
	(void) __nanosleep(&ts, NULL);
	EPILOGUE
	return (0);
}

int
close(int fildes)
{
	extern void _aio_close(int);
	extern int _close(int);
	int rv;

	_aio_close(fildes);
	PERFORM(_close(fildes))
}

int
creat(const char *path, mode_t mode)
{
	extern int _creat(const char *, mode_t);
	int rv;

	PERFORM(_creat(path, mode))
}

#if !defined(_LP64)
int
creat64(const char *path, mode_t mode)
{
	extern int _creat64(const char *, mode_t);
	int rv;

	PERFORM(_creat64(path, mode))
}
#endif	/* !_LP64 */

int
fcntl(int fildes, int cmd, ...)
{
	extern int _fcntl(int, int, ...);
	intptr_t arg;
	int rv;
	va_list ap;

	va_start(ap, cmd);
	arg = va_arg(ap, intptr_t);
	va_end(ap);
	if (cmd != F_SETLKW)
		return (_fcntl(fildes, cmd, arg));
	PERFORM(_fcntl(fildes, cmd, arg))
}

int
fdatasync(int fildes)
{
	extern int _fdatasync(int);
	int rv;

	PERFORM(_fdatasync(fildes))
}

int
fsync(int fildes)
{
	extern int _fsync(int);
	int rv;

	PERFORM(_fsync(fildes))
}

int
lockf(int fildes, int function, off_t size)
{
	extern int _lockf(int, int, off_t);
	int rv;

	PERFORM(_lockf(fildes, function, size))
}

#if !defined(_LP64)
int
lockf64(int fildes, int function, off64_t size)
{
	extern int _lockf64(int, int, off64_t);
	int rv;

	PERFORM(_lockf64(fildes, function, size))
}
#endif	/* !_LP64 */

ssize_t
msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	extern ssize_t _msgrcv(int, void *, size_t, long, int);
	ssize_t rv;

	PERFORM(_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg))
}

int
msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
	extern int _msgsnd(int, const void *, size_t, int);
	int rv;

	PERFORM(_msgsnd(msqid, msgp, msgsz, msgflg))
}

int
msync(caddr_t addr, size_t len, int flags)
{
	extern int _msync(caddr_t, size_t, int);
	int rv;

	PERFORM(_msync(addr, len, flags))
}

int
open(const char *path, int oflag, ...)
{
	extern int _open(const char *, int, ...);
	mode_t mode;
	int rv;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	PERFORM(_open(path, oflag, mode))
}

#if !defined(_LP64)
int
open64(const char *path, int oflag, ...)
{
	extern int _open64(const char *, int, ...);
	mode_t mode;
	int rv;
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, mode_t);
	va_end(ap);
	PERFORM(_open64(path, oflag, mode))
}
#endif	/* !_LP64 */

int
pause(void)
{
	extern int _pause(void);
	int rv;

	PERFORM(_pause())
}

ssize_t
pread(int fildes, void *buf, size_t nbyte, off_t offset)
{
	extern ssize_t _pread(int, void *, size_t, off_t);
	ssize_t rv;

	PERFORM(_pread(fildes, buf, nbyte, offset))
}

#if !defined(_LP64)
ssize_t
pread64(int fildes, void *buf, size_t nbyte, off64_t offset)
{
	extern ssize_t _pread64(int, void *, size_t, off64_t);
	ssize_t rv;

	PERFORM(_pread64(fildes, buf, nbyte, offset))
}
#endif	/* !_LP64 */

ssize_t
pwrite(int fildes, const void *buf, size_t nbyte, off_t offset)
{
	extern ssize_t _pwrite(int, const void *, size_t, off_t);
	ssize_t rv;

	PERFORM(_pwrite(fildes, buf, nbyte, offset))
}

#if !defined(_LP64)
ssize_t
pwrite64(int fildes, const void *buf, size_t nbyte, off64_t offset)
{
	extern ssize_t _pwrite64(int, const void *, size_t, off64_t);
	ssize_t rv;

	PERFORM(_pwrite64(fildes, buf, nbyte, offset))
}
#endif	/* !_LP64 */

ssize_t
readv(int fildes, const struct iovec *iov, int iovcnt)
{
	extern ssize_t _readv(int, const struct iovec *, int);
	ssize_t rv;

	PERFORM(_readv(fildes, iov, iovcnt))
}

int
sigpause(int sig)
{
	extern int _sigpause(int);
	int rv;

	PERFORM(_sigpause(sig))
}

#pragma weak sigsuspend = _sigsuspend
int
_sigsuspend(const sigset_t *set)
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

#pragma weak sigtimedwait = _sigtimedwait
int
_sigtimedwait(const sigset_t *set, siginfo_t *infop, const timespec_t *timeout)
{
	extern int __sigtimedwait(const sigset_t *, siginfo_t *,
		const timespec_t *);
	siginfo_t info;
	int sig;

	PROLOGUE
	sig = __sigtimedwait(set, &info, timeout);
	if (sig == SIGCANCEL &&
	    (SI_FROMKERNEL(&info) || info.si_code == SI_LWP)) {
		do_sigcancel();
		errno = EINTR;
		sig = -1;
	}
	EPILOGUE
	if (sig != -1 && infop)
		(void) _private_memcpy(infop, &info, sizeof (*infop));
	return (sig);
}

#pragma weak sigwait = _sigwait
int
_sigwait(sigset_t *set)
{
	return (_sigtimedwait(set, NULL, NULL));
}

#pragma weak sigwaitinfo = _sigwaitinfo
int
_sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
	return (_sigtimedwait(set, info, NULL));
}

#pragma weak sigqueue = _sigqueue
int
_sigqueue(pid_t pid, int signo, const union sigval value)
{
	extern int __sigqueue(pid_t pid, int signo,
		/* const union sigval */ void *value, int si_code, int block);
	return (__sigqueue(pid, signo, value.sival_ptr, SI_QUEUE, 0));
}

int
tcdrain(int fildes)
{
	extern int _tcdrain(int);
	int rv;

	PERFORM(_tcdrain(fildes))
}

pid_t
wait(int *stat_loc)
{
	extern pid_t _wait(int *);
	pid_t rv;

	PERFORM(_wait(stat_loc))
}

pid_t
wait3(int *statusp, int options, struct rusage *rusage)
{
	extern pid_t _wait3(int *, int, struct rusage *);
	pid_t rv;

	PERFORM(_wait3(statusp, options, rusage))
}

int
waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	extern int _waitid(idtype_t, id_t, siginfo_t *, int);
	int rv;

	PERFORM(_waitid(idtype, id, infop, options))
}

/*
 * waitpid_cancel() is a libc-private symbol for internal use
 * where cancellation semantics is desired (see system()).
 */
#pragma weak waitpid_cancel = waitpid
pid_t
waitpid(pid_t pid, int *stat_loc, int options)
{
	extern pid_t _waitpid(pid_t, int *, int);
	pid_t rv;

	PERFORM(_waitpid(pid, stat_loc, options))
}

ssize_t
writev(int fildes, const struct iovec *iov, int iovcnt)
{
	extern ssize_t _writev(int, const struct iovec *, int);
	ssize_t rv;

	PERFORM(_writev(fildes, iov, iovcnt))
}
