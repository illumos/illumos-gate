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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_LX_SIGNAL_H
#define	_SYS_LX_SIGNAL_H

#if !defined(_ASM)
#include <sys/lx_types.h>
#include <sys/ucontext.h>
#include <sys/lx_siginfo.h>
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

typedef struct lx_sigaction {
	void (*lxsa_handler)();
	int lxsa_flags;
	void (*lxsa_restorer)(void);
	lx_sigset_t lxsa_mask;
} lx_sigaction_t;

#if defined(_ILP32)
typedef	uint32_t lx_osigset_t;

#define	OSIGSET_NBITS		(sizeof (lx_osigset_t) * NBBY)
#define	OSIGSET_BITSET(sig)	(1U << (((sig) - 1) % OSIGSET_NBITS))

typedef struct lx_osigaction {
	void (*lxsa_handler)();
	lx_osigset_t lxsa_mask;
	int lxsa_flags;
	void (*lxsa_restorer)(void);
} lx_osigaction_t;
#endif

/*
 * Flag settings to determine whether common routines should operate on
 * lx_sigset_ts or lx_osigset_ts.
 */
#define	USE_OSIGSET	0
#define	USE_SIGSET	1

typedef struct lx_sighandlers {
	struct lx_sigaction lx_sa[LX_NSIG + 1];
} lx_sighandlers_t;

typedef struct lx_sigaltstack {
	void *ss_sp;
	int ss_flags;
	size_t ss_size;
} lx_stack_t;

/*
 * _fpreg, _fpxreg, _xmmreg and _fpstate are defined in Linux src in:
 *     arch/x86/include/uapi/asm/sigcontext.h
 */
#define	LX_X86_FXSR_MAGIC	0x0000
#define	LX_X86_FXSR_NONE	0xffff

#if defined(_LP64)

typedef struct lx_fpstate {
	ushort_t cwd;
	ushort_t swd;
	ushort_t twd; /* Note this is not the same as the 32bit/x87/FSAVE twd */
	ushort_t fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcsr_mask;
	uint32_t st_space[32];   /* 8 * 16 bytes for each FP-reg */
	uint32_t xmm_space[64];  /* 16 * 16 bytes for each XMM-reg  */
	uint32_t reserved2[12];
	uint32_t reserved3[12];
} lx_fpstate_t;

/*
 * The Linux layout is defined in the Linux src tree in:
 *     arch/x86/include/asm/sigcontext.h
 * and the user-level def (which is what we want) at:
 *     arch/x86/include/uapi/asm/sigcontext.h
 *
 * The Illumos offsets of the registers in the context are defined in:
 *     usr/src/uts/intel/sys/regset.h
 * this is an mcontext_t from uc_mcontext.
 *
 * For the 64-bit case the register layout is completely different in the
 * context.
 */
typedef struct lx_sigcontext {
	ulong_t sc_r8;
	ulong_t sc_r9;
	ulong_t sc_r10;
	ulong_t sc_r11;
	ulong_t sc_r12;
	ulong_t sc_r13;
	ulong_t sc_r14;
	ulong_t sc_r15;
	ulong_t sc_rdi;
	ulong_t sc_rsi;
	ulong_t sc_rbp;
	ulong_t sc_rbx;
	ulong_t sc_rdx;
	ulong_t sc_rax;
	ulong_t sc_rcx;
	ulong_t sc_rsp;
	ulong_t sc_rip;
	ulong_t sc_eflags;
	ushort_t sc_cs;
	ushort_t sc_gs;
	ushort_t sc_fs;
	ushort_t sc_pad0;
	ulong_t sc_err;
	ulong_t sc_trapno;

	ulong_t sc_mask;
	ulong_t sc_cr2;
	lx_fpstate_t *sc_fpstate;

	ulong_t reserved[8];
} lx_sigcontext_t;

#else /* is _ILP32 */

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

/*
 * The Linux layout is defined in the Linux src tree in:
 *     arch/x86/include/asm/sigcontext.h
 * and the user-level def (which is what we want) at:
 *     arch/x86/include/uapi/asm/sigcontext.h
 *
 * The Illumos offsets of the registers in the context are defined by the
 * i386 ABI (see usr/src/uts/intel/sys/regset.h).
 *
 * Both Illumos and Linux match up here.
 */
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
	ulong_t sc_ss;

	lx_fpstate_t *sc_fpstate;
	ulong_t sc_mask;
	ulong_t sc_cr2;
} lx_sigcontext_t;
#endif

typedef struct lx_ucontext {
	ulong_t uc_flags;		/* Linux always sets this to 0 */
	struct lx_ucontext *uc_link;	/* Linux always sets this to NULL */
	lx_stack_t uc_stack;
	lx_sigcontext_t uc_sigcontext;
	lx_sigset_t uc_sigmask;
} lx_ucontext_t;

typedef struct lx_sigbackup lx_sigbackup_t;
struct lx_sigbackup {
	ucontext_t *lxsb_retucp;
	ucontext_t *lxsb_sigucp;
	uintptr_t lxsb_sigdeliver_frame;
	lx_sigbackup_t *lxsb_previous;
};

extern const int ltos_signo[];
extern const int stol_signo[];

extern void setsigacthandler(void (*)(int, siginfo_t *, void *),
    void (**)(int, siginfo_t *, void *),
    int (*)(const ucontext_t *));

extern int lx_siginit(void);
extern void lx_sighandlers_save(lx_sighandlers_t *);
extern void lx_sighandlers_restore(lx_sighandlers_t *);

extern int stol_siginfo(siginfo_t *siginfop, lx_siginfo_t *lx_siginfop);
extern int stol_status(int);

#endif	/* !defined(_ASM) */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SIGNAL_H */
