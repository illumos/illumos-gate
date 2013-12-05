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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _SYS_SIGNAL_H
#define	_SYS_SIGNAL_H

#include <sys/feature_tests.h>
#include <sys/iso/signal_iso.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(__EXTENSIONS__) || defined(_KERNEL) || !defined(_STRICT_STDC) || \
	defined(__XOPEN_OR_POSIX)

#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	(_POSIX_C_SOURCE > 2) || defined(_XPG4_2)
/*
 * We need <sys/siginfo.h> for the declaration of siginfo_t.
 */
#include <sys/siginfo.h>
#endif

/* Duplicated in <sys/ucontext.h> as a result of XPG4v2 requirements */
#ifndef	_SIGSET_T
#define	_SIGSET_T
typedef struct {		/* signal set type */
	unsigned int	__sigbits[4];
} sigset_t;
#endif	/* _SIGSET_T */

typedef	struct {
	unsigned int	__sigbits[3];
} k_sigset_t;

/*
 * The signal handler routine can have either one or three arguments.
 * Existing C code has used either form so not specifing the arguments
 * neatly finesses the problem.  C++ doesn't accept this.  To C++
 * "(*sa_handler)()" indicates a routine with no arguments (ANSI C would
 * specify this as "(*sa_handler)(void)").  One or the other form must be
 * used for C++ and the only logical choice is "(*sa_handler)(int)" to allow
 * the SIG_* defines to work.  "(*sa_sigaction)(int, siginfo_t *, void *)"
 * can be used for the three argument form.
 */

/*
 * Note: storage overlap by sa_handler and sa_sigaction
 */
struct sigaction {
	int sa_flags;
	union {
#ifdef	__cplusplus
		void (*_handler)(int);
#else
		void (*_handler)();
#endif
#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	(_POSIX_C_SOURCE > 2) || defined(_XPG4_2)
		void (*_sigaction)(int, siginfo_t *, void *);
#endif
	}	_funcptr;
	sigset_t sa_mask;
#ifndef _LP64
	int sa_resv[2];
#endif
};
#define	sa_handler	_funcptr._handler
#define	sa_sigaction	_funcptr._sigaction

#if defined(_SYSCALL32)

/* Kernel view of the ILP32 user sigaction structure */

struct sigaction32 {
	int32_t		sa_flags;
	union {
		caddr32_t	_handler;
		caddr32_t	_sigaction;
	}	_funcptr;
	sigset_t	sa_mask;
	int32_t		sa_resv[2];
};

#endif	/* _SYSCALL32 */

/* this is only valid for SIGCLD */
#define	SA_NOCLDSTOP	0x00020000	/* don't send job control SIGCLD's */
#endif

#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)) || \
	defined(_XPG4_2)

			/* non-conformant ANSI compilation	*/

/* definitions for the sa_flags field */
#define	SA_ONSTACK	0x00000001
#define	SA_RESETHAND	0x00000002
#define	SA_RESTART	0x00000004
#endif

#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(_POSIX_C_SOURCE)) || \
	(_POSIX_C_SOURCE > 2) || defined(_XPG4_2)
#define	SA_SIGINFO	0x00000008
#endif

#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG4_2)
#define	SA_NODEFER	0x00000010

/* this is only valid for SIGCLD */
#define	SA_NOCLDWAIT	0x00010000	/* don't save zombie children	 */

#if defined(__EXTENSIONS__) || !defined(_XPG4_2)
/*
 * use of these symbols by applications is injurious
 *	to binary compatibility
 */
#define	NSIG	74	/* valid signals range from 1 to NSIG-1 */
#define	MAXSIG	73	/* size of u_signal[], NSIG-1 <= MAXSIG */
#endif /* defined(__EXTENSIONS__) || !defined(_XPG4_2) */

#define	MINSIGSTKSZ	2048
#define	SIGSTKSZ	8192

#define	SS_ONSTACK	0x00000001
#define	SS_DISABLE	0x00000002

/* Duplicated in <sys/ucontext.h> as a result of XPG4v2 requirements. */
#ifndef	_STACK_T
#define	_STACK_T
#if defined(__EXTENSIONS__) || !defined(_XPG4_2)
typedef struct sigaltstack {
#else
typedef struct {
#endif
	void	*ss_sp;
	size_t	ss_size;
	int	ss_flags;
} stack_t;

#if defined(_SYSCALL32)

/* Kernel view of the ILP32 user sigaltstack structure */

typedef struct sigaltstack32 {
	caddr32_t	ss_sp;
	size32_t	ss_size;
	int32_t		ss_flags;
} stack32_t;

#endif /* _SYSCALL32 */

#endif /* _STACK_T */

#endif /* defined(__EXTENSIONS__) || defined(_KERNEL) ... */

#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX))

/* signotify id used only by libc for mq_notify()/aio_notify() */
typedef struct signotify_id {		/* signotify id struct		*/
	pid_t	sn_pid;			/* pid of proc to be notified	*/
	int	sn_index;		/* index in preallocated pool	*/
	int	sn_pad;			/* reserved			*/
} signotify_id_t;

#if defined(_SYSCALL32)

/* Kernel view of the ILP32 user signotify_id structure */

typedef struct signotify32_id {
	pid32_t	sn_pid;			/* pid of proc to be notified */
	int32_t	sn_index;		/* index in preallocated pool */
	int32_t	sn_pad;			/* reserved */
} signotify32_id_t;

#endif	/* _SYSCALL32 */

/* Command codes for sig_notify call */

#define	SN_PROC		1		/* queue signotify for process	*/
#define	SN_CANCEL	2		/* cancel the queued signotify	*/
#define	SN_SEND		3		/* send the notified signal	*/

#endif /* defined(__EXTENSIONS__) || defined(_KERNEL) ... */

/* Added as per XPG4v2 */
#if defined(__EXTENSIONS__) || defined(_KERNEL) || \
	(!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(_XPG4_2)
struct sigstack {
	void	*ss_sp;
	int	ss_onstack;
};
#endif /* defined(__EXTENSIONS__) || defined(_KERNEL) ... */

/*
 * For definition of ucontext_t; must follow struct definition
 * for  sigset_t
 */
#if defined(_XPG4_2)
#include <sys/ucontext.h>
#endif /* defined(_XPG4_2) */

#ifdef _KERNEL
#include <sys/t_lock.h>

extern const k_sigset_t nullsmask;	/* a null signal mask */
extern const k_sigset_t fillset;	/* all signals, guaranteed contiguous */
extern const k_sigset_t cantmask;	/* cannot be caught or ignored */
extern const k_sigset_t cantreset;	/* cannot be reset after catching */
extern const k_sigset_t ignoredefault;	/* ignored by default */
extern const k_sigset_t stopdefault;	/* stop by default */
extern const k_sigset_t coredefault;	/* dumps core by default */
extern const k_sigset_t holdvfork;	/* held while doing vfork */

#define	sigmask(n)		((unsigned int)1 << (((n) - 1) & (32 - 1)))
#define	sigword(n)		(((unsigned int)((n) - 1))>>5)

#if ((MAXSIG > (2 * 32)) && (MAXSIG <= (3 * 32)))
#define	FILLSET0	0xffffffffu
#define	FILLSET1	0xffffffffu
#define	FILLSET2	((1u << (MAXSIG - 64)) - 1)
#else
#error "fix me: MAXSIG out of bounds"
#endif

#define	CANTMASK0	(sigmask(SIGKILL)|sigmask(SIGSTOP))
#define	CANTMASK1	0
#define	CANTMASK2	0

#define	sigemptyset(s)		(*(s) = nullsmask)
#define	sigfillset(s)		(*(s) = fillset)
#define	sigaddset(s, n)		((s)->__sigbits[sigword(n)] |= sigmask(n))
#define	sigdelset(s, n)		((s)->__sigbits[sigword(n)] &= ~sigmask(n))
#define	sigismember(s, n)	(sigmask(n) & (s)->__sigbits[sigword(n)])
#define	sigisempty(s)		(!((s)->__sigbits[0] | (s)->__sigbits[1] | \
				(s)->__sigbits[2]))
#define	sigutok(us, ks)		\
	((ks)->__sigbits[0] = (us)->__sigbits[0] & (FILLSET0 & ~CANTMASK0), \
	(ks)->__sigbits[1] = (us)->__sigbits[1] & (FILLSET1 & ~CANTMASK1), \
	(ks)->__sigbits[2] = (us)->__sigbits[2] & (FILLSET2 & ~CANTMASK2))
#define	sigktou(ks, us)		((us)->__sigbits[0] = (ks)->__sigbits[0], \
				(us)->__sigbits[1] = (ks)->__sigbits[1], \
				(us)->__sigbits[2] = (ks)->__sigbits[2], \
				(us)->__sigbits[3] = 0)
typedef struct {
	int	sig;				/* signal no.		*/
	int	perm;				/* flag for EPERM	*/
	int	checkperm;			/* check perm or not	*/
	int	sicode;				/* has siginfo.si_code	*/
	union sigval value;			/* user specified value	*/
} sigsend_t;

typedef struct {
	sigqueue_t	sn_sigq;	/* sigq struct for notification */
	u_longlong_t	sn_snid;	/* unique id for notification	*/
} signotifyq_t;

typedef struct sigqhdr {		/* sigqueue pool header		*/
	sigqueue_t	*sqb_free;	/* free sigq struct list	*/
	int		sqb_count;	/* sigq free count		*/
	uint_t		sqb_maxcount;	/* sigq max free count		*/
	size_t		sqb_size;	/* size of header+free structs	*/
	uchar_t		sqb_pexited;	/* process has exited		*/
	uint_t		sqb_sent;	/* number of sigq sent		*/
	kcondvar_t	sqb_cv;		/* waiting for a sigq struct	*/
	kmutex_t	sqb_lock;	/* lock for sigq pool		*/
} sigqhdr_t;

#define	_SIGQUEUE_SIZE_BASIC		128	/* basic limit */
#define	_SIGQUEUE_SIZE_PRIVILEGED	512	/* privileged limit */

#define	_SIGNOTIFY_MAX	32

extern	void	setsigact(int, void (*)(int), const k_sigset_t *, int);
extern	void	sigorset(k_sigset_t *, const k_sigset_t *);
extern	void	sigandset(k_sigset_t *, const k_sigset_t *);
extern	void	sigdiffset(k_sigset_t *, const k_sigset_t *);
extern	void	sigintr(k_sigset_t *, int);
extern	void	sigunintr(k_sigset_t *);
extern	void	sigreplace(k_sigset_t *, k_sigset_t *);

extern	int	kill(pid_t, int);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SIGNAL_H */
