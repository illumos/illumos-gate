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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SIGNAL_H
#define	_SIGNAL_H

#include <sys/feature_tests.h>

#if defined(__EXTENSIONS__) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)
#include <sys/types.h>	/* need pid_t/uid_t/size_t/clock_t/caddr_t/pthread_t */
#endif

#include <iso/signal_iso.h>
#include <sys/signal.h>

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/signal_iso.h>.
 */
#if __cplusplus >= 199711L
using std::sig_atomic_t;
using std::signal;
using std::raise;
#endif

#ifdef	__cplusplus
extern "C" {
#endif


extern const char	**_sys_siglistp;	/* signal descriptions */
extern const int	_sys_siglistn;		/* # of signal descriptions */

#if defined(__EXTENSIONS__) || !defined(__XOPEN_OR_POSIX)
#define	_sys_siglist	_sys_siglistp
#define	_sys_nsig	_sys_siglistn
#endif

#if defined(__EXTENSIONS__) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)
extern int kill(pid_t, int);
extern int sigaction(int, const struct sigaction *_RESTRICT_KYWD,
	struct sigaction *_RESTRICT_KYWD);
#ifndef	_KERNEL
extern int sigaddset(sigset_t *, int);
extern int sigdelset(sigset_t *, int);
extern int sigemptyset(sigset_t *);
extern int sigfillset(sigset_t *);
extern int sigismember(const sigset_t *, int);
#endif
extern int sigpending(sigset_t *);
extern int sigprocmask(int, const sigset_t *_RESTRICT_KYWD,
	sigset_t *_RESTRICT_KYWD);
extern int sigsuspend(const sigset_t *);
#endif /* defined(__EXTENSIONS__) || !defined(_STRICT_STDC)... */

#if defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) && \
	!defined(__XOPEN_OR_POSIX))
#include <sys/procset.h>
extern int gsignal(int);
extern int (*ssignal(int, int (*)(int)))(int);
extern int sigsend(idtype_t, id_t, int);
extern int sigsendset(const procset_t *, int);
extern int sig2str(int, char *);
extern int str2sig(const char *, int *);
#define	SIG2STR_MAX	32
#endif /* defined(__EXTENSIONS__) || (!defined(_STRICT_STDC)... */

#if defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) && \
	!defined(__XOPEN_OR_POSIX)) || defined(_XPG4_2)
extern void (*bsd_signal(int, void (*)(int)))(int);
extern int killpg(pid_t, int);
extern int siginterrupt(int, int);
extern int sigaltstack(const stack_t *_RESTRICT_KYWD, stack_t *_RESTRICT_KYWD);
extern int sighold(int);
extern int sigignore(int);
extern int sigpause(int);
extern int sigrelse(int);
extern void (*sigset(int, void (*)(int)))(int);
#endif /* defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) && ... */

/* Marked as LEGACY in SUSv2 and removed in SUSv3 */
#if defined(__EXTENSIONS__) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	(defined(_XPG4_2) && !defined(_XPG6))
extern int sigstack(struct sigstack *, struct sigstack *);
#endif

#if defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) && \
	!defined(__XOPEN_OR_POSIX)) || (_POSIX_C_SOURCE > 2)
#include <sys/siginfo.h>
#include <time.h>
extern int pthread_kill(pthread_t, int);
extern int pthread_sigmask(int, const sigset_t *_RESTRICT_KYWD,
	sigset_t *_RESTRICT_KYWD);
extern int sigwaitinfo(const sigset_t *_RESTRICT_KYWD,
	siginfo_t *_RESTRICT_KYWD);
extern int sigtimedwait(const sigset_t *_RESTRICT_KYWD,
	siginfo_t *_RESTRICT_KYWD, const struct timespec *_RESTRICT_KYWD);
extern int sigqueue(pid_t, int, const union sigval);
#endif /* defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) && */

/*
 * sigwait() prototype is defined here.
 */

#if	defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) && \
	!defined(__XOPEN_OR_POSIX)) || (_POSIX_C_SOURCE - 0 >= 199506L) || \
	defined(_POSIX_PTHREAD_SEMANTICS)

#if	(_POSIX_C_SOURCE - 0 >= 199506L) || defined(_POSIX_PTHREAD_SEMANTICS)

#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname sigwait __posix_sigwait
extern int sigwait(const sigset_t *_RESTRICT_KYWD, int *_RESTRICT_KYWD);
#else  /* __PRAGMA_REDEFINE_EXTNAME */

extern int __posix_sigwait(const sigset_t *_RESTRICT_KYWD,
    int *_RESTRICT_KYWD);

#ifdef	__lint
#define	sigwait __posix_sigwait
#else	/* !__lint */

static int
sigwait(const sigset_t *_RESTRICT_KYWD __setp, int *_RESTRICT_KYWD __signo)
{
	return (__posix_sigwait(__setp, __signo));
}

#endif /* !__lint */
#endif /* __PRAGMA_REDEFINE_EXTNAME */

#else  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

extern int sigwait(sigset_t *);

#endif  /* (_POSIX_C_SOURCE - 0 >= 199506L) || ... */

#endif /* defined(__EXTENSIONS__) || (!defined(_STRICT_STDC) ... */

#ifdef	__cplusplus
}
#endif

#endif	/* _SIGNAL_H */
