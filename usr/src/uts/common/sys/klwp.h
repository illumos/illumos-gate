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

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_KLWP_H
#define	_SYS_KLWP_H

#include <sys/types.h>
#include <sys/condvar.h>
#include <sys/thread.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/pcb.h>
#include <sys/time.h>
#include <sys/msacct.h>
#include <sys/ucontext.h>
#include <sys/lwp.h>
#include <sys/contract.h>

#if (defined(_KERNEL) || defined(_KMEMUSER)) && defined(_MACHDEP)
#include <sys/machparam.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The light-weight process object and the methods by which it
 * is accessed.
 */

#define	MAXSYSARGS	8	/* Maximum # of arguments passed to a syscall */

/* lwp_eosys values */
#define	NORMALRETURN	0	/* normal return; adjusts PC, registers */
#define	JUSTRETURN	1	/* just return, leave registers alone */

/*
 * Resource usage, per-lwp plus per-process (sum over defunct lwps).
 */
struct lrusage {
	u_longlong_t	minflt;		/* minor page faults */
	u_longlong_t	majflt;		/* major page faults */
	u_longlong_t	nswap;		/* swaps */
	u_longlong_t	inblock;	/* input blocks */
	u_longlong_t	oublock;	/* output blocks */
	u_longlong_t	msgsnd;		/* messages sent */
	u_longlong_t	msgrcv;		/* messages received */
	u_longlong_t	nsignals;	/* signals received */
	u_longlong_t	nvcsw;		/* voluntary context switches */
	u_longlong_t	nivcsw;		/* involuntary context switches */
	u_longlong_t	sysc;		/* system calls */
	u_longlong_t	ioch;		/* chars read and written */
};

typedef struct _klwp	*klwp_id_t;

typedef struct _klwp {
	/*
	 * user-mode context
	 */
	struct pcb	lwp_pcb;		/* user regs save pcb */
	uintptr_t	lwp_oldcontext;		/* previous user context */

	/*
	 * system-call interface
	 */
	long	*lwp_ap;	/* pointer to arglist */
	int	lwp_errno;	/* error for current syscall (private) */
	/*
	 * support for I/O
	 */
	char	lwp_error;	/* return error code */
	char	lwp_eosys;	/* special action on end of syscall */
	char	lwp_argsaved;	/* are all args in lwp_arg */
	char	lwp_watchtrap;	/* lwp undergoing watchpoint single-step */
	long	lwp_arg[MAXSYSARGS];	/* args to current syscall */
	void	*lwp_regs;	/* pointer to saved regs on stack */
	void	*lwp_fpu;	/* pointer to fpu regs */
	label_t	lwp_qsav;	/* longjmp label for quits and interrupts */

	/*
	 * signal handling and debugger (/proc) interface
	 */
	uchar_t	lwp_cursig;		/* current signal */
	uchar_t	lwp_curflt;		/* current fault */
	uchar_t	lwp_sysabort;		/* if set, abort syscall */
	uchar_t	lwp_asleep;		/* lwp asleep in syscall */
	uchar_t lwp_extsig;		/* cursig sent from another contract */
	stack_t lwp_sigaltstack;	/* alternate signal stack */
	struct sigqueue *lwp_curinfo;	/* siginfo for current signal */
	k_siginfo_t	lwp_siginfo;	/* siginfo for stop-on-fault */
	k_sigset_t	lwp_sigoldmask;	/* for sigsuspend */
	struct lwp_watch {		/* used in watchpoint single-stepping */
		caddr_t	wpaddr;
		size_t	wpsize;
		int	wpcode;
		int	wpmapped;
		greg_t	wppc;
	} lwp_watch[4];		/* one for each of exec/write/read/read */

	uint32_t lwp_oweupc;		/* profil(2) ticks owed to this lwp */

	/*
	 * Microstate accounting.  Timestamps are made at the start and the
	 * end of each microstate (see <sys/msacct.h> for state definitions)
	 * and the corresponding accounting info is updated.  The current
	 * microstate is kept in the thread struct, since there are cases
	 * when one thread must update another thread's state (a no-no
	 * for an lwp since it may be swapped/paged out).  The rest of the
	 * microstate stuff is kept here to avoid wasting space on things
	 * like kernel threads that don't have an associated lwp.
	 */
	struct mstate {
		int ms_prev;			/* previous running mstate */
		hrtime_t ms_start;		/* lwp creation time */
		hrtime_t ms_term;		/* lwp termination time */
		hrtime_t ms_state_start;	/* start time of this mstate */
		hrtime_t ms_acct[NMSTATES];	/* per mstate accounting */
	} lwp_mstate;

	/*
	 * Per-lwp resource usage.
	 */
	struct lrusage lwp_ru;

	/*
	 * Things to keep for real-time (SIGPROF) profiling.
	 */
	int	lwp_lastfault;
	caddr_t	lwp_lastfaddr;

	/*
	 * timers. Protected by lwp->procp->p_lock
	 */
	struct itimerval lwp_timer[3];

	/*
	 * used to stop/alert lwps
	 */
	char	lwp_unused;
	char	lwp_state;	/* Running in User/Kernel mode (no lock req) */
	ushort_t lwp_nostop;	/* Don't stop this lwp (no lock required) */
	ushort_t lwp_pad;	/* Reserved for future use */

	/*
	 * Last failed privilege.
	 */
	short	lwp_badpriv;

	/*
	 * linkage
	 */
	struct _kthread	*lwp_thread;
	struct proc	*lwp_procp;

	size_t lwp_childstksz;	/* kernel stksize for this lwp's descendants */

	uintptr_t	lwp_ustack;		/* current stack bounds */
	size_t		lwp_old_stk_ctl;	/* old stack limit */

	/*
	 * Contracts
	 */
	struct ct_template *lwp_ct_active[CTT_MAXTYPE]; /* active templates */
	struct contract	*lwp_ct_latest[CTT_MAXTYPE]; /* last created contract */

	void	*lwp_brand;		/* per-lwp brand data */
	struct psinfo *lwp_spymaster;	/* if an agent LWP, our spymaster */
} klwp_t;

/* lwp states */
#define	LWP_USER	0x01		/* Running in user mode */
#define	LWP_SYS		0x02		/* Running in kernel mode */

#if	defined(_KERNEL)
extern	int	lwp_default_stksize;
extern	int	lwp_reapcnt;

extern	struct _kthread *lwp_deathrow;
extern	kmutex_t	reaplock;
extern	struct kmem_cache *lwp_cache;
extern	void		*segkp_lwp;
extern	klwp_t		lwp0;

/* where newly-created lwps normally start */
extern	void	lwp_rtt(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KLWP_H */
