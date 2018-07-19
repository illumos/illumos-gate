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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 *
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*		All Rights Reserved				*/

#ifndef _SYS_FP_H
#define	_SYS_FP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 80287/80387 and SSE/SSE2 floating point processor definitions
 */

/*
 * values that go into fp_kind
 */
#define	FP_NO	0	/* no fp chip, no emulator (no fp support)	*/
#define	FP_SW	1	/* no fp chip, using software emulator		*/
#define	FP_HW	2	/* chip present bit				*/
#define	FP_287	2	/* 80287 chip present				*/
#define	FP_387	3	/* 80387 chip present				*/
#define	FP_487	6	/* 80487 chip present				*/
#define	FP_486	6	/* 80486 chip present				*/
/*
 * The following values are bit flags instead of actual values.
 * E.g. to know if we are using SSE, test (value & __FP_SSE) instead
 * of (value == __FP_SSE).
 */
#define	__FP_SSE	0x100	/* .. plus SSE-capable CPU		*/
#define	__FP_AVX	0x200	/* .. plus AVX-capable CPU		*/

/*
 * values that go into fp_save_mech
 */
#define	FP_FNSAVE	1	/* fnsave/frstor instructions		*/
#define	FP_FXSAVE	2	/* fxsave/fxrstor instructions		*/
#define	FP_XSAVE	3	/* xsave/xrstor instructions		*/

/*
 * masks for 80387 control word
 */
#define	FPIM	0x00000001	/* invalid operation			*/
#define	FPDM	0x00000002	/* denormalized operand			*/
#define	FPZM	0x00000004	/* zero divide				*/
#define	FPOM	0x00000008	/* overflow				*/
#define	FPUM	0x00000010	/* underflow				*/
#define	FPPM	0x00000020	/* precision				*/
#define	FPPC	0x00000300	/* precision control			*/
#define	FPRC	0x00000C00	/* rounding control			*/
#define	FPIC	0x00001000	/* infinity control			*/
#define	WFPDE	0x00000080	/* data chain exception			*/

/*
 * (Old symbol compatibility)
 */
#define	FPINV	FPIM
#define	FPDNO	FPDM
#define	FPZDIV	FPZM
#define	FPOVR	FPOM
#define	FPUNR	FPUM
#define	FPPRE	FPPM

/*
 * precision, rounding, and infinity options in control word
 */
#define	FPSIG24 0x00000000	/* 24-bit significand precision (short) */
#define	FPSIG53 0x00000200	/* 53-bit significand precision (long)	*/
#define	FPSIG64 0x00000300	/* 64-bit significand precision (temp)	*/
#define	FPRTN	0x00000000	/* round to nearest or even		*/
#define	FPRD	0x00000400	/* round down				*/
#define	FPRU	0x00000800	/* round up				*/
#define	FPCHOP	0x00000C00	/* chop (truncate toward zero)		*/
#define	FPP	0x00000000	/* projective infinity			*/
#define	FPA	0x00001000	/* affine infinity			*/
#define	WFPB17	0x00020000	/* bit 17				*/
#define	WFPB24	0x00040000	/* bit 24				*/

/*
 * masks for 80387 status word
 */
#define	FPS_IE	0x00000001	/* invalid operation			*/
#define	FPS_DE	0x00000002	/* denormalized operand			*/
#define	FPS_ZE	0x00000004	/* zero divide				*/
#define	FPS_OE	0x00000008	/* overflow				*/
#define	FPS_UE	0x00000010	/* underflow				*/
#define	FPS_PE	0x00000020	/* precision				*/
#define	FPS_SF	0x00000040	/* stack fault				*/
#define	FPS_ES	0x00000080	/* error summary bit			*/
#define	FPS_C0	0x00000100	/* C0 bit				*/
#define	FPS_C1	0x00000200	/* C1 bit				*/
#define	FPS_C2	0x00000400	/* C2 bit				*/
#define	FPS_TOP	0x00003800	/* top of stack pointer			*/
#define	FPS_C3	0x00004000	/* C3 bit				*/
#define	FPS_B	0x00008000	/* busy bit				*/

/*
 * Exception flags manually cleared during x87 exception handling.
 */
#define	FPS_SW_EFLAGS	\
	(FPS_IE|FPS_DE|FPS_ZE|FPS_OE|FPS_UE|FPS_PE|FPS_SF|FPS_ES|FPS_B)

/*
 * Initial value of FPU control word as per 4th ed. ABI document
 * - affine infinity
 * - round to nearest or even
 * - 64-bit double precision
 * - all exceptions masked
 */
#define	FPU_CW_INIT	0x133f

/*
 * masks and flags for SSE/SSE2 MXCSR
 */
#define	SSE_IE	0x00000001	/* invalid operation			*/
#define	SSE_DE	0x00000002	/* denormalized operand			*/
#define	SSE_ZE	0x00000004	/* zero divide				*/
#define	SSE_OE	0x00000008	/* overflow				*/
#define	SSE_UE	0x00000010	/* underflow				*/
#define	SSE_PE	0x00000020	/* precision				*/
#define	SSE_DAZ	0x00000040	/* denormals are zero			*/
#define	SSE_IM	0x00000080	/* invalid op exception mask		*/
#define	SSE_DM	0x00000100	/* denormalize exception mask		*/
#define	SSE_ZM	0x00000200	/* zero-divide exception mask		*/
#define	SSE_OM	0x00000400	/* overflow exception mask		*/
#define	SSE_UM	0x00000800	/* underflow exception mask		*/
#define	SSE_PM	0x00001000	/* precision exception mask		*/
#define	SSE_RC	0x00006000	/* rounding control			*/
#define	SSE_RD	0x00002000	/* rounding control: round down		*/
#define	SSE_RU	0x00004000	/* rounding control: round up		*/
#define	SSE_FZ	0x00008000	/* flush to zero for masked underflow	*/

#define	SSE_MXCSR_EFLAGS	\
	(SSE_IE|SSE_DE|SSE_ZE|SSE_OE|SSE_UE|SSE_PE)	/* 0x3f */

#define	SSE_MXCSR_INIT	\
	(SSE_IM|SSE_DM|SSE_ZM|SSE_OM|SSE_UM|SSE_PM)	/* 0x1f80 */

#define	SSE_MXCSR_MASK_DEFAULT	\
	(0xffff & ~SSE_DAZ)				/* 0xffbf */

#define	SSE_FMT_MXCSR	\
	"\20\20fz\17ru\16rd\15pm\14um\13om\12zm\11dm"	\
	"\10im\7daz\6pe\5ue\4oe\3ze\2de\1ie"

/*
 * This structure is written to memory by an 'fnsave' instruction
 */
struct fnsave_state {
	uint16_t	f_fcw;
	uint16_t	__f_ign0;
	uint16_t	f_fsw;
	uint16_t	__f_ign1;
	uint16_t	f_ftw;
	uint16_t	__f_ign2;
	uint32_t	f_eip;
	uint16_t	f_cs;
	uint16_t	f_fop;
	uint32_t	f_dp;
	uint16_t	f_ds;
	uint16_t	__f_ign3;
	union {
		uint16_t fpr_16[5];	/* 80-bits of x87 state */
	} f_st[8];
};	/* 108 bytes */

/*
 * This structure is written to memory by an 'fxsave' instruction
 * Note the variant behaviour of this instruction between long mode
 * and legacy environments!
 */
struct fxsave_state {
	uint16_t	fx_fcw;
	uint16_t	fx_fsw;
	uint16_t	fx_fctw;	/* compressed tag word */
	uint16_t	fx_fop;
#if defined(__amd64)
	uint64_t	fx_rip;
	uint64_t	fx_rdp;
#else
	uint32_t	fx_eip;
	uint16_t	fx_cs;
	uint16_t	__fx_ign0;
	uint32_t	fx_dp;
	uint16_t	fx_ds;
	uint16_t	__fx_ign1;
#endif
	uint32_t	fx_mxcsr;
	uint32_t	fx_mxcsr_mask;
	union {
		uint16_t fpr_16[5];	/* 80-bits of x87 state */
		u_longlong_t fpr_mmx;	/* 64-bit mmx register */
		uint32_t __fpr_pad[4];	/* (pad out to 128-bits) */
	} fx_st[8];
#if defined(__amd64)
	upad128_t	fx_xmm[16];	/* 128-bit registers */
	upad128_t	__fx_ign2[6];
#else
	upad128_t	fx_xmm[8];	/* 128-bit registers */
	upad128_t	__fx_ign2[14];
#endif
} __aligned(16);	/* 512 bytes */

/*
 * This structure is written to memory by one of the 'xsave' instruction
 * variants. The first 512 bytes are compatible with the format of the 'fxsave'
 * area. The header portion of the xsave layout is documented in section
 * 13.4.2 of the Intel 64 and IA-32 Architectures Software Developer’s Manual,
 * Volume 1 (IASDv1). The extended portion is documented in section 13.4.3.
 *
 * Our size is at least AVX_XSAVE_SIZE (832 bytes), which is asserted
 * statically.  Enabling additional xsave-related CPU features requires an
 * increase in the size. We dynamically allocate the per-lwp xsave area at
 * runtime, based on the size needed for the CPU-specific features. This
 * xsave_state structure simply defines our historical layout for the beginning
 * of the xsave area. The locations and size of new, extended, components is
 * determined dynamically by querying the CPU. See the xsave_info structure in
 * cpuid.c.
 *
 * xsave component usage is tracked using bits in the xs_xstate_bv field. The
 * components are documented in section 13.1 of IASDv1. For easy reference,
 * this is a summary of the currently defined component bit definitions:
 *	x87			0x0001
 *	SSE			0x0002
 *	AVX			0x0004
 *	bndreg (MPX)		0x0008
 *	bndcsr (MPX)		0x0010
 *	opmask (AVX512)		0x0020
 *	zmm hi256 (AVX512)	0x0040
 *	zmm hi16 (AVX512)	0x0080
 *	PT			0x0100
 *	PKRU			0x0200
 * When xsaveopt_ctxt is being used to save into the xsave_state area, the
 * xs_xstate_bv field is updated by the xsaveopt instruction to indicate which
 * elements of the xsave area are active.
 *
 * xs_xcomp_bv should always be 0, since we do not currently use the compressed
 * form of xsave (xsavec).
 */
struct xsave_state {
	struct fxsave_state	xs_fxsave;	/* 0-511 legacy region */
	uint64_t		xs_xstate_bv;	/* 512-519 start xsave header */
	uint64_t		xs_xcomp_bv;	/* 520-527 */
	uint64_t		xs_reserved[6];	/* 528-575 end xsave header */
	upad128_t		xs_ymm[16];	/* 576 AVX component */
} __aligned(64);

/*
 * Kernel's FPU save area
 */
typedef struct {
	union _kfpu_u {
		void *kfpu_generic;
		struct fxsave_state *kfpu_fx;
#if defined(__i386)
		struct fnsave_state *kfpu_fn;
#endif
		struct xsave_state *kfpu_xs;
	} kfpu_u;
	uint32_t kfpu_status;		/* saved at #mf exception */
	uint32_t kfpu_xstatus;		/* saved at #xm exception */
} kfpu_t;

extern int fp_kind;		/* kind of fp support			*/
extern int fp_save_mech;	/* fp save/restore mechanism		*/
extern int fpu_exists;		/* FPU hw exists			*/

#ifdef _KERNEL

extern int fpu_ignored;
extern int fpu_pentium_fdivbug;

extern uint32_t sse_mxcsr_mask;

extern void fpu_probe(void);
extern uint_t fpu_initial_probe(void);

extern void fpu_auxv_info(int *, size_t *);

extern void fpnsave_ctxt(void *);
extern void fpxsave_ctxt(void *);
extern void xsave_ctxt(void *);
extern void xsaveopt_ctxt(void *);
extern void fpxsave_excp_clr_ctxt(void *);
extern void xsave_excp_clr_ctxt(void *);
extern void xsaveopt_excp_clr_ctxt(void *);
extern void (*fpsave_ctxt)(void *);
extern void (*xsavep)(struct xsave_state *, uint64_t);

extern void fpxrestore_ctxt(void *);
extern void xrestore_ctxt(void *);
extern void (*fprestore_ctxt)(void *);

extern void fxsave_insn(struct fxsave_state *);
extern void fpsave(struct fnsave_state *);
extern void fprestore(struct fnsave_state *);
extern void fpxsave(struct fxsave_state *);
extern void fpxrestore(struct fxsave_state *);
extern void xsave(struct xsave_state *, uint64_t);
extern void xsaveopt(struct xsave_state *, uint64_t);
extern void xrestore(struct xsave_state *, uint64_t);

extern void fpenable(void);
extern void fpdisable(void);
extern void fpinit(void);

extern uint32_t fperr_reset(void);
extern uint32_t fpxerr_reset(void);

extern uint32_t fpgetcwsw(void);
extern uint32_t fpgetmxcsr(void);

struct regs;
extern int fpexterrflt(struct regs *);
extern int fpsimderrflt(struct regs *);
extern void fpsetcw(uint16_t, uint32_t);
extern void fp_seed(void);
extern void fp_exec(void);
struct _klwp;
extern void fp_lwp_init(struct _klwp *);
extern void fp_lwp_cleanup(struct _klwp *);
extern void fp_lwp_dup(struct _klwp *);

extern const struct fxsave_state sse_initial;
extern const struct xsave_state avx_initial;

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_FP_H */
