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

#ifndef _UCB_SYS_SIGNAL_H
#define	_UCB_SYS_SIGNAL_H

/*
 * 4.3BSD signal compatibility header
 *
 * this file includes all standard SVR4 header info, plus the 4.3BSD
 * structures  - 4.3BSD signal codes are translated to SVR4 generic
 * signal codes where applicable
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SysV <signal.h>
 */

/* ---- <signal.h> ---- */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SIGNAL_H
#define	_SIGNAL_H

/* ---- <sys/signal.h> ---- */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_SIGNAL_H
#define	_SYS_SIGNAL_H

#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt (rubout) */
#define	SIGQUIT	3	/* quit (ASCII FS) */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */
#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#define	SIGIOT	6	/* IOT instruction */
#define	SIGABRT 6	/* used by abort, replace SIGIOT in the future */
#define	SIGEMT	7	/* EMT instruction */
#define	SIGFPE	8	/* floating point exception */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	SIGBUS	10	/* bus error */
#define	SIGSEGV	11	/* segmentation violation */
#define	SIGSYS	12	/* bad argument to system call */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */
#define	SIGUSR1	16	/* user defined signal 1 */
#define	SIGUSR2	17	/* user defined signal 2 */
#define	SIGCLD	18	/* child status change */
#define	SIGCHLD	18	/* child status change alias (POSIX) */
#define	SIGPWR	19	/* power-fail restart */
#define	SIGWINCH 20	/* window size change */
#define	SIGURG	21	/* urgent socket condition */
#define	SIGPOLL 22	/* pollable event occured */
#define	SIGIO	SIGPOLL	/* socket I/O possible (SIGPOLL alias) */
#define	SIGSTOP 23	/* stop (cannot be caught or ignored) */
#define	SIGTSTP 24	/* user stop requested from tty */
#define	SIGCONT 25	/* stopped process has been continued */
#define	SIGTTIN 26	/* background tty read attempted */
#define	SIGTTOU 27	/* background tty write attempted */
#define	SIGVTALRM 28	/* virtual timer expired */
#define	SIGPROF 29	/* profiling timer expired */
#define	SIGXCPU 30	/* exceeded cpu limit */
#define	SIGXFSZ 31	/* exceeded file size limit */
#define	SIGWAITING 32	/* process's lwps are blocked */
#define	SIGLWP	33	/* special signal used by thread library */

#if	defined(__cplusplus)

typedef	void SIG_FUNC_TYP(int);
typedef	SIG_FUNC_TYP *SIG_TYP;
#define	SIG_PF SIG_TYP

#define	SIG_DFL	(SIG_PF)0
#define	SIG_ERR (SIG_PF)-1
#define	SIG_IGN	(SIG_PF)1
#define	SIG_HOLD (SIG_PF)2

#elif	defined(lint)

#define	SIG_DFL	(void(*)(int))0
#define	SIG_ERR (void(*)(int))0
#define	SIG_IGN	(void (*)(int))0
#define	SIG_HOLD (void(*)(int))0

#else

#define	SIG_DFL	(void(*)())0
#define	SIG_ERR	(void(*)())-1
#define	SIG_IGN	(void (*)())1
#define	SIG_HOLD (void(*)())2

#endif

#define	SIG_BLOCK	1
#define	SIG_UNBLOCK	2
#define	SIG_SETMASK	3

#define	SIGNO_MASK	0xFF
#define	SIGDEFER	0x100
#define	SIGHOLD		0x200
#define	SIGRELSE	0x400
#define	SIGIGNORE	0x800
#define	SIGPAUSE	0x1000

#if !defined(_STRICT_STDC) || defined(_POSIX_SOURCE)

#ifndef	_SIGSET_T
#define	_SIGSET_T
typedef struct {		/* signal set type */
	unsigned int	__sigbits[4];
} sigset_t;
#endif	/* _SIGSET_T */

struct sigaction {
	int sa_flags;
#if defined(__cplusplus)
	void (*sa_handler)(int);
#else
	void (*sa_handler)();
#endif
	sigset_t sa_mask;
	int sa_resv[2];
};

/* this is only valid for SIGCLD */
#define	SA_NOCLDSTOP	0x00020000	/* don't send job control SIGCLD's */
#endif

#if !defined(_STRICT_STDC) && !defined(_POSIX_SOURCE)
			/* non-comformant ANSI compilation	*/

/* definitions for the sa_flags field */
#define	SA_ONSTACK	0x00000001
#define	SA_RESETHAND	0x00000002
#define	SA_RESTART	0x00000004
#define	SA_SIGINFO	0x00000008
#define	SA_NODEFER	0x00000010

/* this is only valid for SIGCLD */
#define	SA_NOCLDWAIT	0x00010000	/* don't save zombie children	 */

#define	NSIG	34	/* valid signals range from 1 to NSIG-1 */
#define	MAXSIG	33	/* size of u_signal[], NSIG-1 <= MAXSIG */

#define	MINSIGSTKSZ	2048
#define	SIGSTKSZ	8192

#define	SS_ONSTACK	0x00000001
#define	SS_DISABLE	0x00000002

struct sigaltstack {
	char	*ss_sp;
	int	ss_size;
	int	ss_flags;
};

typedef struct sigaltstack stack_t;

#endif /* __STDC__ && !POSIX */


#endif /* _SYS_SIGNAL_H */

/* ---- end of SysV <sys/signal.h> ---- */

typedef int	sig_atomic_t;

#if defined(__STDC__)

extern const char *_sys_siglist[];
extern const int _sys_nsig;

#ifdef __cplusplus
extern "C" SIG_PF signal(int, SIG_PF);
#else
extern void (*signal(int, void (*)(int)))(int);
#endif
extern int raise(int);

#if !defined(_STRICT_STDC) || defined(_POSIX_SOURCE) || \
	defined(_XOPEN_SOURCE)
extern int kill(pid_t, int);
extern int sigaction(int, const struct sigaction *, struct sigaction *);
extern int sigaddset(sigset_t *, int);
extern int sigdelset(sigset_t *, int);
extern int sigemptyset(sigset_t *);
extern int sigfillset(sigset_t *);
extern int sigismember(const sigset_t *, int);
extern int sigpending(sigset_t *);
extern int sigprocmask(int, const sigset_t *, sigset_t *);
extern int sigsuspend(const sigset_t *);
#endif

#if !defined(_STRICT_STDC) && !defined(_POSIX_SOURCE)
extern int gsignal(int);
extern void (*sigset(int, void (*)(int)))(int);
extern int sighold(int);
extern int sigrelse(int);
extern int sigignore(int);
extern int sigpause(int);
extern int (*ssignal(int, int (*)(int)))(int);
extern int sigaltstack(const stack_t *, stack_t *);
/* extern int sigsend(idtype_t, id_t, int); */
/* extern int sigsendset(const procset_t *, int); */
#endif

#else

extern char *_sys_siglist[];
extern int _sys_nsig;

extern	void(*signal())();
extern  void(*sigset())();

#endif	/* __STDC__ */

#endif	/* _SIGNAL_H */
/* ---- end of SysV <signal.h> ---- */

#define	sigmask(m)	(m > 32 ? 0 : (1 << ((m)-1)))

/*
 * 4.3BSD structure used in sigstack call.
 */

struct  sigstack {
	char	*ss_sp;			/* signal stack pointer */
	int	ss_onstack;		/* current status */
};

#define	SV_ONSTACK	0x0001  /* take signal on signal stack */
#define	SV_INTERRUPT    0x0002  /* do not restart system on signal return */
#define	SV_RESETHAND    0x0004  /* reset handler to SIG_DFL when signal taken */

#define	sv_onstack sv_flags

struct  sigcontext {
	int	sc_onstack;		/* sigstack state to restore */
	int	sc_mask;		/* signal mask to restore */
#ifdef u3b2
	int	sc_sp;			/* sp to restore */
	int	sc_fp;			/* fp to restore */
	int	sc_ap;			/* ap to restore */
	int	sc_pc;			/* pc to restore */
	int	sc_ps;			/* psw to restore */
#endif
#ifdef vax
	int	sc_sp;			/* sp to restore */
	int	sc_fp;			/* fp to restore */
	int	sc_ap;			/* ap to restore */
	int	sc_pc;			/* pc to restore */
	int	sc_ps;			/* psl to restore */
#endif /* vax */
#ifdef mc68000
	int	sc_sp;			/* sp to restore */
	int	sc_pc;			/* pc to retore */
	int	sc_ps;			/* psl to restore */
#endif /* mc68000 */
#ifdef __sparc
#define	MAXWINDOW	31		/* max usable windows in sparc */
	long	sc_sp;			/* sp to restore */
	long	sc_pc;			/* pc to retore */
	long	sc_npc;			/* next pc to restore */
	long	sc_psr;			/* psr to restore */
					/* aliased to REG_CCR for sparcv9 */
	long	sc_g1;			/* register that must be restored */
	long	sc_o0;
	int	sc_wbcnt;		/* number of outstanding windows */
	char	*sc_spbuf[MAXWINDOW];	/* sp's for each wbuf */
	long	sc_wbuf[MAXWINDOW][16];	/* outstanding window save buffer */
#endif /* __sparc */
#if defined(__amd64)
	long	sc_sp;			/* sp to restore */
	long	sc_pc;			/* pc to retore */
	long	sc_ps;			/* psl to restore */
	long	sc_rax;			/* rax to restore */
	long	sc_rdx;			/* rdx to restore */
#define	sc_r0	sc_rax
#define	sc_r1	sc_rdx
#elif defined(__i386)
	int	sc_sp;			/* sp to restore */
	int	sc_pc;			/* pc to retore */
	int	sc_ps;			/* psl to restore */
	int	sc_eax;			/* eax to restore */
	int	sc_edx;			/* edx to restore */
#define	sc_r0	sc_eax
#define	sc_r1	sc_edx
#endif
};

/*
 * 4.3BSD signal vector structure used in sigvec call.
 */
struct  sigvec {
#if defined(__cplusplus)
	void	(*sv_handler)(int, int, struct sigcontext *, char *);
#else
	void	(*sv_handler)();	/* signal handler */
#endif
	int	sv_mask;		/* signal mask to apply */
	int	sv_flags;		/* see signal options below */
};

#if defined(__STDC__)
extern int sigvec(int, struct sigvec *, struct sigvec *);
extern int sigblock(int);
extern int sigsetmask(int);
#endif

/*
 * Signal codes taken verbatim from SunOS4.1
 */
#ifdef	vax
#define	    ILL_RESAD_FAULT	0x0	/* reserved addressing fault */
#define	    ILL_PRIVIN_FAULT	0x1	/* privileged instruction fault */
#define	    ILL_RESOP_FAULT	0x2	/* reserved operand fault */
#endif	/* vax */
#ifdef	mc68000
#define	    ILL_ILLINSTR_FAULT	0x10	/* illegal instruction fault */
#define	    ILL_PRIVVIO_FAULT	0x20	/* privilege violation fault */
#define	    ILL_COPROCERR_FAULT	0x34	/* [coprocessor protocol error fault] */
#define	    ILL_TRAP1_FAULT	0x84	/* trap #1 fault */
#define	    ILL_TRAP2_FAULT	0x88	/* trap #2 fault */
#define	    ILL_TRAP3_FAULT	0x8c	/* trap #3 fault */
#define	    ILL_TRAP4_FAULT	0x90	/* trap #4 fault */
#define	    ILL_TRAP5_FAULT	0x94	/* trap #5 fault */
#define	    ILL_TRAP6_FAULT	0x98	/* trap #6 fault */
#define	    ILL_TRAP7_FAULT	0x9c	/* trap #7 fault */
#define	    ILL_TRAP8_FAULT	0xa0	/* trap #8 fault */
#define	    ILL_TRAP9_FAULT	0xa4	/* trap #9 fault */
#define	    ILL_TRAP10_FAULT	0xa8	/* trap #10 fault */
#define	    ILL_TRAP11_FAULT	0xac	/* trap #11 fault */
#define	    ILL_TRAP12_FAULT	0xb0	/* trap #12 fault */
#define	    ILL_TRAP13_FAULT	0xb4	/* trap #13 fault */
#define	    ILL_TRAP14_FAULT	0xb8	/* trap #14 fault */
#endif	/* mc68000 */
#ifdef	sparc
#define	    ILL_STACK		0x00	/* bad stack */
#define	    ILL_ILLINSTR_FAULT	0x02	/* illegal instruction fault */
#define	    ILL_PRIVINSTR_FAULT	0x03	/* privileged instruction fault */
/* codes from 0x80 to 0xff are software traps */
#define	    ILL_TRAP_FAULT(n)	((n)+0x80) /* trap n fault */
#endif	/* sparc */
#if defined(__i386) || defined(__amd64)
#define	    ILL_ILLINSTR_FAULT	0x02	/* illegal instruction fault */
#endif

#ifdef	mc68000
#define	    EMT_EMU1010		0x28	/* line 1010 emulator trap */
#define	    EMT_EMU1111		0x2c	/* line 1111 emulator trap */
#endif	/* mc68000 */
#ifdef	sparc
#define	    EMT_TAG		0x0a	/* tag overflow */
#endif	/* sparc */

#ifdef	vax
#define	    FPE_INTOVF_TRAP	0x1	/* integer overflow */
#define	    FPE_INTDIV_TRAP	0x2	/* integer divide by zero */
#define	    FPE_FLTOVF_TRAP	0x3	/* floating overflow */
#define	    FPE_FLTDIV_TRAP	0x4	/* floating/decimal divide by zero */
#define	    FPE_FLTUND_TRAP	0x5	/* floating underflow */
#define	    FPE_DECOVF_TRAP	0x6	/* decimal overflow */
#define	    FPE_SUBRNG_TRAP	0x7	/* subscript out of range */
#define	    FPE_FLTOVF_FAULT	0x8	/* floating overflow fault */
#define	    FPE_FLTDIV_FAULT	0x9	/* divide by zero floating fault */
#define	    FPE_FLTUND_FAULT	0xa	/* floating underflow fault */
#endif	/* vax */
#ifdef	mc68000
#define	    FPE_INTDIV_TRAP	0x14	/* integer divide by zero */
#define	    FPE_CHKINST_TRAP	0x18	/* CHK [CHK2] instruction */
#define	    FPE_TRAPV_TRAP	0x1c	/* TRAPV [cpTRAPcc TRAPcc] instr */
#define	    FPE_FLTBSUN_TRAP	0xc0	/* [branch or set on unordered cond] */
#define	    FPE_FLTINEX_TRAP	0xc4	/* [floating inexact result] */
#define	    FPE_FLTDIV_TRAP	0xc8	/* [floating divide by zero] */
#define	    FPE_FLTUND_TRAP	0xcc	/* [floating underflow] */
#define	    FPE_FLTOPERR_TRAP	0xd0	/* [floating operand error] */
#define	    FPE_FLTOVF_TRAP	0xd4	/* [floating overflow] */
#define	    FPE_FLTNAN_TRAP	0xd8	/* [floating Not-A-Number] */
#ifdef	sun
#define	    FPE_FPA_ENABLE	0x400	/* [FPA not enabled] */
#define	    FPE_FPA_ERROR	0x404	/* [FPA arithmetic exception] */
#endif	/* sun */
#endif	/* mc68000 */
#ifdef	sparc
#define	    FPE_INTOVF_TRAP	0x1	/* integer overflow */
#define	    FPE_STARTSIG_TRAP	0x2	/* process using fp */
#define	    FPE_INTDIV_TRAP	0x14	/* integer divide by zero */
#define	    FPE_FLTINEX_TRAP	0xc4	/* [floating inexact result] */
#define	    FPE_FLTDIV_TRAP	0xc8	/* [floating divide by zero] */
#define	    FPE_FLTUND_TRAP	0xcc	/* [floating underflow] */
#define	    FPE_FLTOPERR_TRAP	0xd0	/* [floating operand error] */
#define	    FPE_FLTOVF_TRAP	0xd4	/* [floating overflow] */
#endif	/* sparc */

/*
 * The codes for SIGBUS and SIGSEGV are described in <vm/faultcode.h>
 * These are the same between SunOS4.1 and SunOS5.0
 */

#include <vm/faultcode.h>

#define	    BUS_HWERR	FC_HWERR	/* misc hardware error (e.g. timeout) */
#define	    BUS_ALIGN	FC_ALIGN	/* hardware alignment error */
#ifdef	BUS_OBJERR	/* namespace conflict with SysV */
#undef	BUS_OBJERR
#endif
#define	    BUS_OBJERR	FC_OBJERR	/* object returned errno value */
/*
 * The BUS_CODE(code) will be one of the above.  In the BUS_OBJERR case,
 * doing a BUS_ERRNO(code) gives an errno value reported by the underlying
 * file object mapped at the fault address.  Note that this appears to be
 * duplicated with the segmentation fault case below -- unfortunate, since
 * the specification has always claimed that such errors produce SIGBUS.
 * The segmentation cases are left defined as a transition aid.
 */
#define	    BUS_CODE(C)		FC_CODE(C)
#define	    BUS_ERRNO(C)	FC_ERRNO(C)

#define	    SEGV_NOMAP	FC_NOMAP	/* no mapping at the fault address */
#define	    SEGV_PROT	FC_PROT		/* access exceeded protections */
#define	    SEGV_OBJERR	FC_OBJERR	/* object returned errno value */
/*
 * The SEGV_CODE(code) will be SEGV_NOMAP, SEGV_PROT, or SEGV_OBJERR.
 * In the SEGV_OBJERR case, doing a SEGV_ERRNO(code) gives an errno value
 * reported by the underlying file object mapped at the fault address.
 */
#define	    SEGV_CODE(C)	FC_CODE(C)
#define	    SEGV_ERRNO(C)	FC_ERRNO(C)
#define	    SEGV_MAKE_ERR(e)	FC_MAKE_ERR(e)

#define	SIG_NOADDR	((char *)~0)

#if defined(lint)
#define	BADSIG (void(*)())0
#else
#define	BADSIG (void(*)())-1
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _UCB_SYS_SIGNAL_H */
