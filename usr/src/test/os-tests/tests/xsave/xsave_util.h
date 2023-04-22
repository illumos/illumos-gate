/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _XSAVE_UTIL_H
#define	_XSAVE_UTIL_H

/*
 * This file contains misc. pieces for use between our tests. This is
 * implemented in both xsave_util.c and xsave_asm32.s and xsave_asm64.s.
 */

#ifndef	_ASM
#include <sys/types.h>
#include <stdint.h>
#include <ucontext.h>
#include <stdio.h>
#include <procfs.h>
#include <libproc.h>
#endif	/* !_ASM */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * While we would prefer an enum, this is a macro so it can be shared with the
 * assembler code.
 */
#define	XSU_XMM	0
#define	XSU_YMM	1
#define	XSU_ZMM	2

/*
 * These are definitions that vary based on whether we're in an ILP32 or LP64
 * environment because of how the ISA works.
 */
#ifdef __amd64
#define	XSU_MAX_XMM	16
#define	XSU_MAX_YMM	16
#define	XSU_MAX_ZMM	32
#else
#define	XSU_MAX_XMM	8
#define	XSU_MAX_YMM	8
#define	XSU_MAX_ZMM	8
#endif

#define	XSU_XMM_U32	4
#define	XSU_YMM_U32	8
#define	XSU_ZMM_U32	16

#ifndef	_ASM

/*
 * Redefine the xsave header here for the test cases so we can avoid exposing
 * this out of the kernel. Right now the uc_xsave_t isn't defined under
 * _KMEMUSER and we're trying to hold onto that (or a similar style solution)
 * while we can.
 */
#define	UC_XSAVE_VERS	(('u' << 24) | ('c' << 16) | 0x01)
typedef struct uc_xsave {
	uint32_t ucx_vers;
	uint32_t ucx_len;
	uint64_t ucx_bv;
} uc_xsave_t;

/*
 * This structure represents a generic AVX-512 FPU state that can hold up to 32
 * registers. If only XMM or YMM are valid, then the first 8 and 16 bytes will
 * be valid respectively and the latter 16 entries won't be used in 64-bit code.
 * In 32-bit code only the valid FPU entries will present.
 */
typedef struct xsu_fpu {
	upad512_t	xf_reg[32];
	uint64_t	xf_opmask[8];
} xsu_fpu_t;

extern uint32_t xsu_hwsupport(void);

/*
 * This deterministically fills the contents of an FPU structure. It will zero
 * the entire structure and then fill in the appropriate parts based on the type
 * of FPU we have.
 */
extern void xsu_fill(xsu_fpu_t *, uint32_t, uint32_t);

/*
 * Dump the contents of the FPU in a deterministic fashion to a specified file.
 */
extern void xsu_dump(FILE *, const xsu_fpu_t *, uint32_t);

/*
 * These routines read and write the state of the FPU. This will cover the
 * selected hardware bits.
 */
extern void xsu_setfpu(const xsu_fpu_t *, uint32_t);
extern void xsu_getfpu(xsu_fpu_t *, uint32_t);

/*
 * This is used to overwrite the contents of a ucontext_t with the resulting FPU
 * state. The xc_xsave will be replaced with a pointer to something of our own
 * sizing.
 */
extern void xsu_overwrite_uctx(ucontext_t *, const xsu_fpu_t *, uint32_t);

/*
 * Diff two different fpu sets and see if they're identical or not. Only the
 * bytes that correspond to the indicated pieces will be checked.
 */
extern boolean_t xsu_same(const xsu_fpu_t *, const xsu_fpu_t *, uint32_t);

/*
 * This function allocates and sets up the prxregset_hdr_t and associated notes
 * with their expected values based on the hardware support values.
 */
extern void xsu_xregs_alloc(void **, size_t *, uint32_t);

/*
 * This is a common function that just sleeps and is meant to be here for test
 * programs that want a thread to mess with.
 */
extern void *xsu_sleeper_thread(void *);

/*
 * Convert a given xsu_fpu_t state into something that we can set via xregs.
 */
extern void xsu_fpu_to_xregs(const xsu_fpu_t *, uint32_t, prxregset_t **,
    size_t *);

typedef struct xsu_proc {
	char *xp_prog;
	char *xp_arg;
	const char *xp_object;
	const char *xp_symname;
	struct ps_prochandle *xp_proc;
	uintptr_t xp_addr;
	ulong_t xp_instr;
	int xp_wait;
} xsu_proc_t;

/*
 * This pair of functions gives us a mini-debugging context. The first sets up a
 * program that is ready and paused at a breakpoint.
 */
extern void xsu_proc_bkpt(xsu_proc_t *);
extern void xsu_proc_finish(xsu_proc_t *);

/*
 * Set the xmm portion of an fpregset based on a seed.
 */
extern void xsu_fpregset_xmm_set(fpregset_t *, uint32_t);
extern void xsu_xregs_xmm_set(prxregset_t *, uint32_t);

/*
 * Go through and see if the data in an fpregs section is equivalent to an xregs
 * XMM section. This focuses on the control words and xmm data, we do not bother
 * with the x87 registers themselves and not all of the 32-bit pieces.
 */
extern boolean_t xsu_fpregs_cmp(const fpregset_t *, const prxregset_t *);

/*
 * Given two xregs structures, check if the given component in them has
 * identical data. Note, this assumes that the structure is valid-ish. That is,
 * that all the info structures point to valid data.
 */
extern boolean_t xsu_xregs_comp_equal(const prxregset_t *, const prxregset_t *,
    uint32_t);

/*
 * Allocate a stack and fill out the uc_stack member for a ucontext_t.
 * Subsequent calls will reuse the same allocated stack.
 */
extern void xsu_ustack_alloc(ucontext_t *);

#endif	/* !_ASM */

#ifdef __cplusplus
}
#endif

#endif /* _XSAVE_UTIL_H */
