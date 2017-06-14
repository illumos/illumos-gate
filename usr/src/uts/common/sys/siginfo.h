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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef _SYS_SIGINFO_H
#define	_SYS_SIGINFO_H

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE > 2) || \
	defined(__EXTENSIONS__)

/*
 * The union sigval is also defined in <time.h> as per X/Open and
 * POSIX requirements.
 */
#ifndef	_SIGVAL
#define	_SIGVAL
union sigval {
	int	sival_int;	/* integer value */
	void	*sival_ptr;	/* pointer value */
};
#endif /* _SIGVAL */

#if defined(_SYSCALL32)

/* Kernel view of user ILP32 sigval */

union sigval32 {
	int32_t	sival_int;	/* integer value */
	caddr32_t sival_ptr;	/* pointer value */
};

#endif	/* _SYSCALL32 */

#else 				/* needed in siginfo_t structure */

union __sigval {
	int	__sival_int;	/* integer value */
	void	*__sival_ptr;	/* pointer value */
};

#endif /* !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE > 2)... */

#if !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE > 2) || \
	defined(__EXTENSIONS__)

/*
 * The sigevent structure is also defined in <time.h> as per X/Open and
 * POSIX requirements.
 */
#ifndef	_SIGEVENT
#define	_SIGEVENT
struct sigevent {
	int		sigev_notify;	/* notification mode */
	int		sigev_signo;	/* signal number */
	union sigval	sigev_value;	/* signal value */
	void		(*sigev_notify_function)(union sigval);
	pthread_attr_t	*sigev_notify_attributes;
	int		__sigev_pad2;
};
#endif	/* _SIGEVENT */

/* values of sigev_notify */
#define	SIGEV_NONE	1		/* no notification */
#define	SIGEV_SIGNAL	2		/* queued signal notification */
#define	SIGEV_THREAD	3		/* call back from another thread */
#define	SIGEV_PORT	4		/* use event port for notification */

#if defined(_SYSCALL32)

/* Kernel view of user ILP32 sigevent */

struct sigevent32 {
	int32_t		sigev_notify;	/* notification mode */
	int32_t		sigev_signo;	/* signal number */
	union sigval32	sigev_value;	/* signal value */
	caddr32_t	sigev_notify_function;
	caddr32_t	sigev_notify_attributes;
	int32_t		__sigev_pad2;
};

#endif	/* _SYSCALL32 */

#endif /* !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE > 2)... */

#if !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE > 2) || \
	defined(__EXTENSIONS__)
/*
 * negative signal codes are reserved for future use for user generated
 * signals
 */

#define	SI_FROMUSER(sip)	((sip)->si_code <= 0)
#define	SI_FROMKERNEL(sip)	((sip)->si_code > 0)

#define	SI_NOINFO	32767	/* no signal information */
#define	SI_DTRACE	2050	/* kernel generated signal via DTrace action */
#define	SI_RCTL		2049	/* kernel generated signal via rctl action */
#define	SI_USER		0	/* user generated signal via kill() */
#define	SI_LWP		(-1)	/* user generated signal via lwp_kill() */
#define	SI_QUEUE	(-2)	/* user generated signal via sigqueue() */
#define	SI_TIMER	(-3)	/* from timer expiration */
#define	SI_ASYNCIO	(-4)	/* from asynchronous I/O completion */
#define	SI_MESGQ	(-5)	/* from message arrival */
#endif /* !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE > 2)... */

#if !defined(_POSIX_C_SOURCE) || defined(_XPG4_2) || defined(__EXTENSIONS__)
/*
 * Get the machine dependent signal codes (SIGILL, SIGFPE, SIGSEGV, and
 * SIGBUS) from <sys/machsig.h>
 */

#include <sys/machsig.h>

/*
 * SIGTRAP signal codes
 */

#define	TRAP_BRKPT	1	/* breakpoint trap */
#define	TRAP_TRACE	2	/* trace trap */
#define	TRAP_RWATCH	3	/* read access watchpoint trap */
#define	TRAP_WWATCH	4	/* write access watchpoint trap */
#define	TRAP_XWATCH	5	/* execute access watchpoint trap */
#define	TRAP_DTRACE	6	/* problem with fasttrap DTrace provider */
#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#define	NSIGTRAP	6
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

/*
 * SIGCLD signal codes
 */

#define	CLD_EXITED	1	/* child has exited */
#define	CLD_KILLED	2	/* child was killed */
#define	CLD_DUMPED	3	/* child has coredumped */
#define	CLD_TRAPPED	4	/* traced child has stopped */
#define	CLD_STOPPED	5	/* child has stopped on signal */
#define	CLD_CONTINUED	6	/* stopped child has continued */

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#define	NSIGCLD		6
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

/*
 * SIGPOLL signal codes
 */

#define	POLL_IN		1	/* input available */
#define	POLL_OUT	2	/* output possible */
#define	POLL_MSG	3	/* message available */
#define	POLL_ERR	4	/* I/O error */
#define	POLL_PRI	5	/* high priority input available */
#define	POLL_HUP	6	/* device disconnected */

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#define	NSIGPOLL	6
#endif /* !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__) */

#endif /* !defined(_POSIX_C_SOURCE) || defined(_XPG4_2) ... */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
/*
 * SIGPROF signal codes
 */

#define	PROF_SIG	1	/* have to set code non-zero */
#define	NSIGPROF	1

#endif /* !defined(__XOPEN_OR_POSIX) || defined (__EXTENSIONS__) */

#if !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE > 2) || \
	defined(__EXTENSIONS__)

#ifdef _LP64
#define	SI_MAXSZ	256
#define	SI_PAD		((SI_MAXSZ / sizeof (int)) - 4)
#else
#define	SI_MAXSZ	128
#define	SI_PAD		((SI_MAXSZ / sizeof (int)) - 3)
#endif

/*
 * Inclusion of <sys/time_impl.h> is needed for the declaration of
 * timestruc_t.  However, since inclusion of <sys/time_impl.h> results
 * in X/Open and POSIX namespace pollution, the definition for
 * timestruct_t has been duplicated in a standards namespace safe header
 * <sys/time_std_impl.h>.  In <sys/time_std_impl.h>, the structure
 * name, tag, and member names, as well as the type itself, all have
 * leading underscores to protect namespace.
 */
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#include <sys/time_impl.h>
#else
#include <sys/time_std_impl.h>
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

/*
 * The inclusion of <sys/types.h> is needed for definitions of pid_t, etc.
 * Placement here is due to a dependency in <sys/select.h> which is included
 * by <sys/types.h> for the sigevent structure.  Hence this inclusion must
 * follow that definition.
 */
#include <sys/types.h>		/* for definitions of pid_t, etc. */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
typedef struct siginfo { 		/* pollutes POSIX/XOPEN namespace */
#else
typedef struct {
#endif
	int	si_signo;			/* signal from signal.h	*/
	int 	si_code;			/* code from above	*/
	int	si_errno;			/* error from errno.h	*/
#ifdef _LP64
	int	si_pad;		/* _LP64 union starts on an 8-byte boundary */
#endif
	union {

		int	__pad[SI_PAD];		/* for future growth	*/

		struct {			/* kill(), SIGCLD, siqqueue() */
			pid_t	__pid;		/* process ID		*/
			union {
				struct {
					uid_t	__uid;
#if !defined(__XOPEN_OR_POSIX) || (_POSIX_C_SOURCE > 2) || \
	defined(__EXTENSIONS__)
					union sigval	__value;
#else
					union __sigval	__value;
#endif
				} __kill;
				struct {
					clock_t __utime;
					int	__status;
					clock_t __stime;
				} __cld;
			} __pdata;
			ctid_t	__ctid;		/* contract ID		*/
			zoneid_t __zoneid;	/* zone ID		*/
		} __proc;

		struct {	/* SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE */
			void 	*__addr;	/* faulting address	*/
			int	__trapno;	/* illegal trap number	*/
			caddr_t	__pc;		/* instruction address	*/
		} __fault;

		struct {			/* SIGPOLL, SIGXFSZ	*/
		/* fd not currently available for SIGPOLL */
			int	__fd;		/* file descriptor	*/
			long	__band;
		} __file;

		struct {			/* SIGPROF */
			caddr_t	__faddr;	/* last fault address	*/
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
			timestruc_t __tstamp;	/* real time stamp	*/
#else
			_timestruc_t __tstamp;	/* real time stamp	*/
#endif
			short	__syscall;	/* current syscall	*/
			char	__nsysarg;	/* number of arguments	*/
			char	__fault;	/* last fault type	*/
			long	__sysarg[8];	/* syscall arguments	*/
			int	__mstate[10];	/* see <sys/msacct.h>	*/
		} __prof;

		struct {			/* SI_RCTL */
			int32_t	__entity;	/* type of entity exceeding */
		} __rctl;
	} __data;

} siginfo_t;

#if defined(_SYSCALL32)

/* Kernel view of user ILP32 siginfo struct */

#define	SI32_MAXSZ	128
#define	SI32_PAD	((SI32_MAXSZ / sizeof (int32_t)) - 3)

typedef struct siginfo32 {

	int32_t	si_signo;			/* signal from signal.h	*/
	int32_t	si_code;			/* code from above	*/
	int32_t	si_errno;			/* error from errno.h	*/

	union {

		int32_t	__pad[SI32_PAD];	/* for future growth	*/

		struct {			/* kill(), SIGCLD, siqqueue() */
			pid32_t	__pid;		/* process ID		*/
			union {
				struct {
					uid32_t	__uid;
					union sigval32	__value;
				} __kill;
				struct {
					clock32_t __utime;
					int32_t	__status;
					clock32_t __stime;
				} __cld;
			} __pdata;
			id32_t	__ctid;		/* contract ID		*/
			id32_t __zoneid;	/* zone ID		*/
		} __proc;

		struct {	/* SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE */
			caddr32_t __addr;	/* faulting address	*/
			int32_t	__trapno;	/* illegal trap number	*/
			caddr32_t __pc;		/* instruction address	*/
		} __fault;

		struct {			/* SIGPOLL, SIGXFSZ	*/
		/* fd not currently available for SIGPOLL */
			int32_t	__fd;		/* file descriptor	*/
			int32_t	__band;
		} __file;

		struct {			/* SIGPROF */
			caddr32_t __faddr;	/* last fault address	*/
			timestruc32_t __tstamp; /* real time stamp	*/
			int16_t	__syscall;	/* current syscall	*/
			int8_t	__nsysarg;	/* number of arguments	*/
			int8_t	__fault;	/* last fault type	*/
			int32_t	__sysarg[8];	/* syscall arguments	*/
			int32_t	__mstate[10];	/* see <sys/msacct.h>	*/
		} __prof;

		struct {			/* SI_RCTL */
			int32_t	__entity;	/* type of entity exceeding */
		} __rctl;

	} __data;

} siginfo32_t;

#endif	/* _SYSCALL32 */

/*
 * XXX -- internal version is identical to siginfo_t but without the padding.
 * This must be maintained in sync with it.
 */

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)

typedef struct k_siginfo {
	int	si_signo;			/* signal from signal.h	*/
	int 	si_code;			/* code from above	*/
	int	si_errno;			/* error from errno.h	*/
#ifdef _LP64
	int	si_pad;		/* _LP64 union starts on an 8-byte boundary */
#endif
	union {
		struct {			/* kill(), SIGCLD, siqqueue() */
			pid_t	__pid;		/* process ID		*/
			union {
				struct {
					uid_t	__uid;
					union sigval	__value;
				} __kill;
				struct {
					clock_t __utime;
					int	__status;
					clock_t __stime;
				} __cld;
			} __pdata;
			ctid_t	__ctid;		/* contract ID		*/
			zoneid_t __zoneid;	/* zone ID		*/
		} __proc;

		struct {	/* SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE */
			void 	*__addr;	/* faulting address	*/
			int	__trapno;	/* illegal trap number	*/
			caddr_t	__pc;		/* instruction address	*/
		} __fault;

		struct {			/* SIGPOLL, SIGXFSZ	*/
		/* fd not currently available for SIGPOLL */
			int	__fd;		/* file descriptor	*/
			long	__band;
		} __file;

		struct {			/* SIGPROF */
			caddr_t	__faddr;	/* last fault address	*/

#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
			timestruc_t __tstamp;	/* real time stamp	*/
#else
			_timestruc_t __tstamp;	/* real time stamp	*/
#endif
			short	__syscall;	/* current syscall	*/
			char	__nsysarg;	/* number of arguments	*/
			char	__fault;	/* last fault type	*/
			/* these are omitted to keep k_siginfo_t small	*/
			/* long	__sysarg[8]; */
			/* int	__mstate[10]; */
		} __prof;

		struct {			/* SI_RCTL */
			int32_t	__entity;	/* type of entity exceeding */
		} __rctl;

	} __data;

} k_siginfo_t;

typedef struct sigqueue {
	struct sigqueue	*sq_next;
	k_siginfo_t	sq_info;
	void		(*sq_func)(struct sigqueue *); /* destructor function */
	void		*sq_backptr;	/* pointer to the data structure */
					/* associated by sq_func()	*/
	int		sq_external;	/* comes from outside the contract */
} sigqueue_t;

/*  indication whether to queue the signal or not */
#define	SI_CANQUEUE(c)	((c) <= SI_QUEUE)

#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

#define	si_pid		__data.__proc.__pid
#define	si_ctid		__data.__proc.__ctid
#define	si_zoneid	__data.__proc.__zoneid
#define	si_status	__data.__proc.__pdata.__cld.__status
#define	si_stime	__data.__proc.__pdata.__cld.__stime
#define	si_utime	__data.__proc.__pdata.__cld.__utime
#define	si_uid		__data.__proc.__pdata.__kill.__uid
#define	si_value	__data.__proc.__pdata.__kill.__value
#define	si_addr		__data.__fault.__addr
#define	si_trapno	__data.__fault.__trapno
#define	si_trapafter	__data.__fault.__trapno
#define	si_pc		__data.__fault.__pc
#define	si_fd		__data.__file.__fd
#define	si_band		__data.__file.__band
#define	si_tstamp	__data.__prof.__tstamp
#define	si_syscall	__data.__prof.__syscall
#define	si_nsysarg	__data.__prof.__nsysarg
#define	si_sysarg	__data.__prof.__sysarg
#define	si_fault	__data.__prof.__fault
#define	si_faddr	__data.__prof.__faddr
#define	si_mstate	__data.__prof.__mstate
#define	si_entity	__data.__rctl.__entity

#endif /* !defined(_POSIX_C_SOURCE) || (_POSIX_C_SOURCE > 2) ... */


#if defined(_SYSCALL32_IMPL)

extern void siginfo_kto32(const k_siginfo_t *, siginfo32_t *);
extern void siginfo_32tok(const siginfo32_t *, k_siginfo_t *);

#endif /* _SYSCALL32_IMPL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SIGINFO_H */
