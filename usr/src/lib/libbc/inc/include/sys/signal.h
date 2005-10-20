/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	__sys_signal_h
#define	__sys_signal_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <vm/faultcode.h>
#define	NSIG	32

/*
 * If any signal defines (SIG*) are added, deleted, or changed, the same
 * changes must be made in /usr/include/signal.h as well.
 */
#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt */
#define	SIGQUIT	3	/* quit */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */

#define	ILL_STACK		0x00	/* bad stack */
#define	ILL_ILLINSTR_FAULT	0x02	/* illegal instruction fault */
#define	ILL_PRIVINSTR_FAULT	0x03	/* privileged instruction fault */
/* codes from 0x80 to 0xff are software traps */
#define	ILL_TRAP_FAULT(n)	((n)+0x80) /* trap n fault */

#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#define	SIGIOT	6	/* IOT instruction */
#define	SIGABRT 6	/* used by abort, replace SIGIOT in the future */
#define	SIGEMT	7	/* EMT instruction */

#define	EMT_TAG		0x0a	/* tag overflow */

#define	SIGFPE	8	/* floating point exception */

#define	FPE_INTOVF_TRAP	0x1	/* integer overflow */
#define	FPE_STARTSIG_TRAP	0x2	/* process using fp */
#define	FPE_INTDIV_TRAP	0x14	/* integer divide by zero */
#define	FPE_FLTINEX_TRAP	0xc4	/* [floating inexact result] */
#define	FPE_FLTDIV_TRAP	0xc8	/* [floating divide by zero] */
#define	FPE_FLTUND_TRAP	0xcc	/* [floating underflow] */
#define	FPE_FLTOPERR_TRAP	0xd0	/* [floating operand error] */
#define	FPE_FLTOVF_TRAP	0xd4	/* [floating overflow] */

#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
/*
 * The codes for SIGBUS and SIGSEGV are described in <vm/faultcode.h>
 */
#define	SIGBUS	10	/* bus error */
#define	BUS_HWERR	FC_HWERR	/* misc hardware error (e.g. timeout) */
#define	BUS_ALIGN	FC_ALIGN	/* hardware alignment error */
#define	BUS_OBJERR	FC_OBJERR	/* object returned errno value */
/*
 * The BUS_CODE(code) will be one of the above.  In the BUS_OBJERR case,
 * doing a BUS_ERRNO(code) gives an errno value reported by the underlying
 * file object mapped at the fault address.  Note that this appears to be
 * duplicated with the segmentation fault case below -- unfortunate, since
 * the specification has always claimed that such errors produce SIGBUS.
 * The segmentation cases are left defined as a transition aid.
 */
#define	BUS_CODE(C)		FC_CODE(C)
#define	BUS_ERRNO(C)	FC_ERRNO(C)
#define	SIGSEGV	11	/* segmentation violation */
#define	SEGV_NOMAP	FC_NOMAP	/* no mapping at the fault address */
#define	SEGV_PROT	FC_PROT		/* access exceeded protections */
#define	SEGV_OBJERR	FC_OBJERR	/* object returned errno value */
/*
 * The SEGV_CODE(code) will be SEGV_NOMAP, SEGV_PROT, or SEGV_OBJERR.
 * In the SEGV_OBJERR case, doing a SEGV_ERRNO(code) gives an errno value
 * reported by the underlying file object mapped at the fault address.
 */
#define	SEGV_CODE(C)	FC_CODE(C)
#define	SEGV_ERRNO(C)	FC_ERRNO(C)
#define	SIGSYS	12	/* bad argument to system call */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */
#define	SIGURG	16	/* urgent condition on IO channel */
#define	SIGSTOP	17	/* sendable stop signal not from tty */
#define	SIGTSTP	18	/* stop signal from tty */
#define	SIGCONT	19	/* continue a stopped process */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define	SIGCLD	20	/* System V name for SIGCHLD */
#define	SIGTTIN	21	/* to readers pgrp upon background tty read */
#define	SIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define	SIGIO	23	/* input/output possible signal */
#define	SIGPOLL	SIGIO	/* System V name for SIGIO */
#define	SIGXCPU	24	/* exceeded CPU time limit */
#define	SIGXFSZ	25	/* exceeded file size limit */
#define	SIGVTALRM 26	/* virtual time alarm */
#define	SIGPROF	27	/* profiling time alarm */
#define	SIGWINCH 28	/* window changed */
#define	SIGLOST 29	/* resource lost (eg, record-lock lost) */
#define	SIGUSR1 30	/* user defined signal 1 */
#define	SIGUSR2 31	/* user defined signal 2 */
/*
 * If addr cannot be computed it is set to SIG_NOADDR.
 */
#define	SIG_NOADDR	((char *)~0)

#if	!defined(KERNEL)  &&  !defined(LOCORE)
void	(*signal())();
/*
 * Define BSD 4.1 reliable signals for SVID compatibility.
 * These functions may go away in a future release.
 */
void  (*sigset())();
int   sighold();
int   sigrelse();
int   sigignore();
#endif	/* !KERNEL  &&  !LOCORE */

#ifndef	LOCORE
/*
 * Signal vector "template" used in sigvec call.
 */
struct	sigvec {
	void	(*sv_handler)();	/* signal handler */
	int	sv_mask;		/* signal mask to apply */
	int	sv_flags;		/* see signal options below */
};
#define	SV_ONSTACK	0x0001	/* take signal on signal stack */
#define	SV_INTERRUPT	0x0002	/* do not restart system on signal return */
#define	SV_RESETHAND	0x0004	/* reset signal handler to SIG_DFL when signal taken */
/*
 * If any SA_NOCLDSTOP or SV_NOCLDSTOP is change, the same
 * changes must be made in /usr/include/signal.h as well.
 */
#define	SV_NOCLDSTOP	0x0008	/* don't send a SIGCHLD on child stop */
#define	SA_ONSTACK	SV_ONSTACK
#define	SA_INTERRUPT	SV_INTERRUPT
#define	SA_RESETHAND	SV_RESETHAND

#define	SA_NOCLDSTOP	SV_NOCLDSTOP
#define	sv_onstack sv_flags	/* isn't compatibility wonderful! */

/*
 * Structure used in sigstack call.
 */
struct	sigstack {
	char	*ss_sp;			/* signal stack pointer */
	int	ss_onstack;		/* current status */
};

/*
 * Information pushed on stack when a signal is delivered.
 * This is used by the kernel to restore state following
 * execution of the signal handler.  It is also made available
 * to the handler to allow it to properly restore state if
 * a non-standard exit is performed.
 */
struct	sigcontext {
	int	sc_onstack;		/* sigstack state to restore */
	int	sc_mask;		/* signal mask to restore */
#define	SPARC_MAXREGWINDOW	31	/* max usable windows in sparc */
	int	sc_sp;			/* sp to restore */
	int	sc_pc;			/* pc to retore */
	int	sc_npc;			/* next pc to restore */
	int	sc_psr;			/* psr to restore */
	int	sc_g1;			/* register that must be restored */
	int	sc_o0;
	int	sc_wbcnt;		/* number of outstanding windows */
	char	*sc_spbuf[SPARC_MAXREGWINDOW]; /* sp's for each wbuf */
	int	sc_wbuf[SPARC_MAXREGWINDOW][16]; /* window save buf */
};
#endif	/* !LOCORE */

#define	BADSIG		(void (*)())-1

/*
 * If SIG_ERR, SIG_DFL, SIG_IGN, or SIG_HOLD are changed, the same changes
 * must be made in /usr/include/signal.h as well.
 */
#define	SIG_ERR		(void (*)())-1
#define	SIG_DFL		(void (*)())0
#define	SIG_IGN		(void (*)())1

#define	SIG_HOLD	(void (*)())3

/*
 * Macro for converting signal number to a mask suitable for sigblock().
 */
#define	sigmask(m)	(1 << ((m)-1))
/*
 * signals that can't caught, blocked, or ignored
 */

/*
 * If SIG_BLOCK, SIG_UNBLOCK, or SIG_SETMASK are changed, the same changes
 * must be made in /usr/include/signal.h as well.
 */
#define	SIG_BLOCK		0x0001
#define	SIG_UNBLOCK		0x0002
#define	SIG_SETMASK		0x0004

#if	!defined(LOCORE) && !defined(KERNEL)

/*
 * If changes are made to sigset_t or struct sigaction, the same changes
 * must be made in /usr/include/signal.h as well.
 */
#include <sys/stdtypes.h>

struct	sigaction {
	void 		(*sa_handler)();
	sigset_t	sa_mask;
	int		sa_flags;
};

/*
 * If changes are made to the function prototypes, the same changes
 * must be made in /usr/include/signal.h as well.
 */
void	(*signal())();
int	kill(/* pid_t p, int sig */);
int	sigaction(/* int signo,
	    struct sigaction *act, struct sigaction *oldact */);
int	sigaddset(/* sigset_t *mask, int signo */);
int	sigdelset(/* sigset_t *mask, int signo */);
int	sigemptyset(/* sigset_t *mask */);
int	sigfillset(/* sigset_t *mask */);
int	sigismember(/* sigset_t *mask, int signo */);
int	sigpending(/* sigset_t *set */);
int	sigprocmask(/* int how, sigset_t *set, *oldset */);
int	sigsuspend(/* sigset_t *mask */);

#endif	/* !LOCORE && !KERNEL */
#endif	/* !__sys_signal_h */
