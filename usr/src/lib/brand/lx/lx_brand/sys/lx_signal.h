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

#ifndef _SYS_LX_SIGNAL_H
#define	_SYS_LX_SIGNAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(_ASM)
#include <sys/lx_types.h>
#include <lx_signum.h>

#endif	/* !defined(_ASM) */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Linux sigaction flags
 */
#define	LX_SA_NOCLDSTOP		0x00000001
#define	LX_SA_NOCLDWAIT		0x00000002
#define	LX_SA_SIGINFO		0x00000004
#define	LX_SA_RESTORER		0x04000000
#define	LX_SA_ONSTACK		0x08000000
#define	LX_SA_RESTART		0x10000000
#define	LX_SA_NODEFER		0x40000000
#define	LX_SA_RESETHAND		0x80000000
#define	LX_SA_NOMASK		LX_SA_NODEFER
#define	LX_SA_ONESHOT		LX_SA_RESETHAND

#define	LX_SIG_BLOCK		0
#define	LX_SIG_UNBLOCK		1
#define	LX_SIG_SETMASK		2

#define	LX_MINSIGSTKSZ		2048
#define	LX_SS_ONSTACK		1
#define	LX_SS_DISABLE		2

#define	LX_SIGRT_MAGIC		0xdeadf00d

#if !defined(_ASM)

/*
 * NOTE:  Linux uses different definitions for sigset_ts and sigaction_ts
 *	  depending on whether the definition is for user space or the kernel.
 *
 *	  The definitions below MUST correspond to the Linux kernel versions,
 *	  as glibc will do the necessary translation from the Linux user
 *	  versions.
 */
typedef struct {
	ulong_t	__bits[LX_NSIG_WORDS];
} lx_sigset_t;

#define	LX_NBITS		(sizeof (ulong_t) * NBBY)
#define	lx_sigmask(n)		(1UL << (((n) - 1) % LX_NBITS))
#define	lx_sigword(n)		(((ulong_t)((n) - 1))>>5)
#define	lx_sigismember(s, n)	(lx_sigmask(n) & (s)->__bits[lx_sigword(n)])
#define	lx_sigaddset(s, n)	((s)->__bits[lx_sigword(n)] |= lx_sigmask(n))

typedef struct lx_sigaction {
	void (*lxsa_handler)();
	int lxsa_flags;
	void (*lxsa_restorer)(void);
	lx_sigset_t lxsa_mask;
} lx_sigaction_t;

typedef	uint32_t lx_osigset_t;

#define	OSIGSET_NBITS		(sizeof (lx_osigset_t) * NBBY)
#define	OSIGSET_BITSET(sig)	(1U << (((sig) - 1) % OSIGSET_NBITS))

/*
 * Flag settings to determine whether common routines should operate on
 * lx_sigset_ts or lx_osigset_ts.
 */
#define	USE_OSIGSET	0
#define	USE_SIGSET	1

typedef struct lx_osigaction {
	void (*lxsa_handler)();
	lx_osigset_t lxsa_mask;
	int lxsa_flags;
	void (*lxsa_restorer)(void);
} lx_osigaction_t;

#define	LX_SI_MAX_SIZE	128
#define	LX_SI_PAD_SIZE	((LX_SI_MAX_SIZE/sizeof (int)) - 3)

typedef struct lx_siginfo {
	int lsi_signo;
	int lsi_errno;
	int lsi_code;
	union {
		int _pad[LX_SI_PAD_SIZE];

		struct {
			pid_t _pid;
			lx_uid16_t _uid;
		} _kill;

		struct {
			uint_t _timer1;
			uint_t _timer2;
		} _timer;

		struct {
			pid_t _pid;		/* sender's pid */
			lx_uid16_t _uid;	/* sender's uid */
			union sigval _sigval;
		} _rt;

		struct {
			pid_t _pid;		/* which child */
			lx_uid16_t _uid;	/* sender's uid */
			int _status;		/* exit code */
			clock_t _utime;
			clock_t _stime;
		} _sigchld;

		struct {
			void *_addr; 		/* faulting insn/memory ref. */
		} _sigfault;

		struct {
			int _band;  		/* POLL_IN,POLL_OUT,POLL_MSG */
			int _fd;
		} _sigpoll;
	} _sifields;
} lx_siginfo_t;

/*
 * lx_siginfo_t lsi_code values
 *
 *	LX_SI_ASYNCNL:	Sent by asynch name lookup completion
 *	LX_SI_TKILL:	Sent by tkill
 *	LX_SI_SIGIO:	Sent by queued SIGIO
 *	LX_SI_ASYNCIO:	Sent by asynchronous I/O completion
 *	LX_SI_MESGQ:	Sent by real time message queue state change
 *	LX_SI_TIMER:	Sent by timer expiration
 *	LX_SI_QUEUE:	Sent by sigqueue
 *	LX_SI_USER:	Sent by kill, sigsend, raise, etc.
 *	LX_SI_KERNEL:	Sent by kernel
 *
 * At present, LX_SI_ASYNCNL and LX_SI_SIGIO are unused by BrandZ.
 */
#define	LX_SI_ASYNCNL	(-60)
#define	LX_SI_TKILL	(-6)
#define	LX_SI_SIGIO	(-5)
#define	LX_SI_ASYNCIO	(-4)
#define	LX_SI_MESGQ	(-3)
#define	LX_SI_TIMER	(-2)
#define	LX_SI_QUEUE	(-1)
#define	LX_SI_USER	(0)
#define	LX_SI_KERNEL	(0x80)

typedef struct lx_sighandlers {
	struct lx_sigaction lx_sa[LX_NSIG];
} lx_sighandlers_t;

typedef struct lx_sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
} lx_stack_t;

struct lx_fpreg {
	ushort_t significand[4];
	ushort_t exponent;
};

struct lx_fpxreg {
	ushort_t significand[4];
	ushort_t exponent;
	ushort_t padding[3];
};

struct lx_xmmreg {
	uint32_t element[4];
};

#define	LX_X86_FXSR_MAGIC	0x0000
#define	LX_X86_FXSR_NONE	0xffff

typedef struct lx_fpstate {
	/* Regular FPU environment */
	ulong_t cw;
	ulong_t sw;
	ulong_t tag;
	ulong_t ipoff;
	ulong_t cssel;
	ulong_t dataoff;
	ulong_t datasel;
	struct lx_fpreg _st[8];
	ushort_t status;
	ushort_t magic;  		/* 0xffff = regular FPU data */

	/* FXSR FPU environment */
	ulong_t _fxsr_env[6]; 		/* env is ignored */
	ulong_t mxcsr;
	ulong_t reserved;
	struct lx_fpxreg _fxsr_st[8];  /* reg data is ignored */
	struct lx_xmmreg _xmm[8];
	ulong_t padding[56];
} lx_fpstate_t;

typedef struct lx_sigcontext {
	ulong_t sc_gs;
	ulong_t sc_fs;
	ulong_t sc_es;
	ulong_t sc_ds;
	ulong_t sc_edi;
	ulong_t sc_esi;
	ulong_t sc_ebp;
	ulong_t sc_esp;
	ulong_t sc_ebx;
	ulong_t sc_edx;
	ulong_t sc_ecx;
	ulong_t sc_eax;
	ulong_t sc_trapno;
	ulong_t sc_err;
	ulong_t sc_eip;
	ulong_t sc_cs;
	ulong_t sc_eflags;
	ulong_t sc_esp_at_signal;
	ulong_t  sc_ss;
	lx_fpstate_t *sc_fpstate;
	ulong_t sc_mask;
	ulong_t sc_cr2;
} lx_sigcontext_t;

typedef struct lx_ucontext {
	ulong_t uc_flags;
	struct lx_ucontext *uc_link;
	lx_stack_t uc_stack;
	lx_sigcontext_t uc_sigcontext;
	lx_sigset_t uc_sigmask;
} lx_ucontext_t;

#define	LX_SI_MAX_SIZE	128
#define	LX_SI_PAD_SIZE	((LX_SI_MAX_SIZE/sizeof (int)) - 3)

#define	lsi_pid		_sifields._kill._pid
#define	lsi_uid		_sifields._kill._uid
#define	lsi_status	_sifields._sigchld._status
#define	lsi_utime	_sifields._sigchld._utime
#define	lsi_stime	_sifields._sigchld._stime
#define	lsi_value	_sifields._rt._sigval
#define	lsi_int		_sifields._rt._sigval.sivalx_int
#define	lsi_ptr		_sifields._rt._sigval.sivalx_ptr
#define	lsi_addr	_sifields._sigfault._addr
#define	lsi_band	_sifields._sigpoll._band
#define	lsi_fd		_sifields._sigpoll._fd

extern const int ltos_signo[];
extern const int stol_signo[];

extern void setsigacthandler(void (*)(int, siginfo_t *, void *),
    void (**)(int, siginfo_t *, void *));

extern int lx_siginit(void);

extern void lx_sigreturn_tolibc(uintptr_t);
extern void lx_sigdeliver(int, siginfo_t *, void *, size_t, void (*)(),
    void (*)(), uintptr_t);

extern int stol_siginfo(siginfo_t *siginfop, lx_siginfo_t *lx_siginfop);

#endif	/* !defined(_ASM) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SIGNAL_H */
