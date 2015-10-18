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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FPU_FPU_SIMULATOR_H
#define	_SYS_FPU_FPU_SIMULATOR_H

/* SunOS-4.0 1.10	*/

/*
 * sparc floating-point simulator definitions.
 */

#ifndef	_ASM
#include <sys/types.h>
#include <sys/ieeefp.h>
#include <vm/seg.h>
#include <sys/kstat.h>
#endif /* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Constants to decode/extract "fitos" instruction fields
 */
#define	FITOS_INSTR_MASK	0xc1f83fe0
#define	FITOS_INSTR		0x81a01880
#define	FITOS_RS2_SHIFT		0
#define	FITOS_RD_SHIFT		25
#define	FITOS_REG_MASK		0x1f

#ifndef _ASM
/*	PUBLIC TYPES	*/

enum fcc_type {			/* relationships */
	fcc_equal	= 0,
	fcc_less	= 1,
	fcc_greater	= 2,
	fcc_unordered	= 3
};

enum cc_type {			/* icc/fcc number */
	fcc_0	= 0,
	fcc_1	= 1,
	fcc_2	= 2,
	fcc_3	= 3,
	icc	= 4,
	xcc	= 6
};

/* FSR types. */

enum ftt_type {			/* types of traps */
	ftt_none	= 0,
	ftt_ieee	= 1,
	ftt_unfinished	= 2,
	ftt_unimplemented = 3,
	ftt_sequence	= 4,
	ftt_alignment	= 5,	/* defined by software convention only */
	ftt_fault	= 6,	/* defined by software convention only */
	ftt_7		= 7
};

typedef	struct {		/* sparc V9 FSR. */
	unsigned int			: 26;
	unsigned int		fcc3	: 2;	/* fp condition code 3 */
	unsigned int		fcc2	: 2;	/* fp condition code 2 */
	unsigned int		fcc1	: 2;	/* fp condition code 1 */
						/* enum fp_direction_type */
	unsigned int		rnd	: 2;	/* rounding direction */
	unsigned int		rnp	: 2;	/* for v7 compatibility only */
	unsigned int		tem	: 5;	/* trap enable mask */
	unsigned int		 ns	: 1;	/* non-standard */
	unsigned int			: 5;
						/* enum ftt_type */
	unsigned int 		ftt	: 3;	/* FPU trap type */
	unsigned int		qne	: 1;	/* FPQ not empty */
	unsigned int		 pr	: 1;	/* partial result */
						/* enum fcc_type */
	unsigned int 		fcc	: 2;	/* fp condition code 0 */
	unsigned int		aexc	: 5;	/* accumulated exceptions */
	unsigned int		cexc	: 5;	/* current exception */
} fsr_types;

/*
 * The C compiler and the C spec do not support bitfields in a long long,
 * as per fsr_types above, so don't hold your breath waiting for this
 * workaround cruft to disappear.
 */

typedef union {
	fsr_types	fsr;
	uint64_t	ll;
} fsr_type;

#define	fcc3	fsr.fcc3
#define	fcc2	fsr.fcc2
#define	fcc1	fsr.fcc1
#define	fcc0	fsr.fcc
#define	rnd	fsr.rnd
#define	rnp	fsr.rnp
#define	tem	fsr.tem
#define	aexc	fsr.aexc
#define	cexc	fsr.cexc

typedef			/* FPU register viewed as single components. */
	struct {
	uint32_t sign :		1;
	uint32_t exponent :	8;
	uint32_t significand : 23;
} single_type;

typedef			/* FPU register viewed as double components. */
	struct {
	uint32_t sign :		1;
	uint32_t exponent :    11;
	uint32_t significand : 20;
} double_type;

typedef			/* FPU register viewed as extended components. */
	struct {
	uint32_t sign :		 1;
	uint32_t exponent :	15;
	uint32_t significand :	16;
} extended_type;

typedef			/* FPU register with multiple data views. */
	union {
	int32_t		int32_reg;
	int64_t		int64_reg;
	uint32_t	uint32_reg;
	uint64_t	uint64_reg;
	float		float_reg;
	single_type	single_reg;
	double_type	double_reg;
	extended_type	extended_reg;
} freg_type;

enum fp_op_type {		/* Type specifiers in FPU instructions. */
	fp_op_int32	= 0,	/* Not in hardware, but convenient to define. */
	fp_op_single	= 1,
	fp_op_double	= 2,
	fp_op_extended	= 3,
	fp_op_int64	= 4
};

enum fp_opcode {	/* FPU op codes, minus precision and leading 0. */
	fmovs		= 0x0,
	fnegs		= 0x1,
	fabss		= 0x2,
	fp_op_3 = 3, fp_op_4 = 4, fp_op_5 = 5, fp_op_6 = 6, fp_op_7 = 7,
	fp_op_8		= 0x8,
	fp_op_9		= 0x9,
	fsqrt		= 0xa,
	fp_op_b = 0xb, fp_op_c = 0xc, fp_op_d = 0xd,
	fp_op_e = 0xe, fp_op_f = 0xf,
	fadd		= 0x10,
	fsub		= 0x11,
	fmul		= 0x12,
	fdiv		= 0x13,
	fcmp		= 0x14,
	fcmpe		= 0x15,
	fp_op_16 = 0x16, fp_op_17 = 0x17,
	fp_op_18	= 0x18,
	fp_op_19	= 0x19,
	fsmuld		= 0x1a,
	fdmulx		= 0x1b,
	ftoll		= 0x20,
	flltos		= 0x21,
	flltod		= 0x22,
	flltox		= 0x23,
	fp_op_24 = 0x24, fp_op_25 = 0x25, fp_op_26 = 0x26, fp_op_27 = 0x27,
	fp_op_28 = 0x28, fp_op_29 = 0x29, fp_op_2a = 0x2a, fp_op_2b = 0x2b,
	fp_op_2c = 0x2c, fp_op_2d = 0x2d, fp_op_2e = 0x2e, fp_op_2f = 0x2f,
	fp_op_30	= 0x30,
	fitos		= 0x31,
	fitod		= 0x32,
	fitox		= 0x33,
	ftoi		= 0x34,
	fp_op_35 = 0x35, fp_op_36 = 0x36, fp_op_37 = 0x37,
	ft_op_38	= 0x38,
	fp_op_39 = 0x39, fp_op_3a = 0x3a, fp_op_3b = 0x3b,
	fp_op_3c	= 0x3c,
	fp_op_3d = 0x3d, fp_op_3e = 0x3e, fp_op_3f = 0x3f
};

typedef			/* FPU instruction. */
	struct {
	uint32_t		hibits	: 2;	/* Top two bits. */
	uint32_t		rd	: 5;	/* Destination. */
	uint32_t		op3	: 6;	/* Main op code. */
	uint32_t		rs1	: 5;	/* First operand. */
	uint32_t		ibit	: 1;	/* I format bit. */
	uint32_t /* enum fp_opcode */  opcode : 6; /* Floating-point op code. */
	uint32_t /* enum fp_op_type */ prec   : 2; /* Precision. */
	uint32_t		rs2	: 5;	/* Second operand. */
} fp_inst_type;

enum fp_op_fma_var {	/* IMPDEP2B FMA-fused instr. variations */
	fmadd	=	0,
	fmsub	=	1,
	fnmsub	=	2,
	fnmadd	=	3
};

typedef		/* IMPDEP2B FPU FMA-fused instruction. */
	struct {
	uint32_t		hibits	: 2;	/* Top two bits. */
	uint32_t		rd	: 5;	/* Destination. */
	uint32_t		op3	: 6;	/* Main op code. */
	uint32_t		rs1	: 5;	/* First operand. */
	uint32_t		rs3	: 5;	/* Third operand */
	uint32_t /* enum fp_op_fma_var */ var : 2; /* Instr. variation */
	uint32_t		sz	: 2;	/* Size */
	uint32_t		rs2	: 5;	/* Second operand. */
} fp_fma_inst_type;

typedef			/* Integer condition code. */
	struct {
	uint32_t			: 28;	/* the unused part */
	uint32_t		n	: 1;	/* Negative bit. */
	uint32_t		z	: 1;	/* Zero bit. */
	uint32_t		v	: 1;	/* Overflow bit. */
	uint32_t		c	: 1;	/* Carry bit. */
} ccr_type;

typedef			/* FPU data used by simulator. */
	struct {
	uint_t			fp_fsrtem;
	enum fp_direction_type	fp_direction;
	enum fp_precision_type	fp_precision;
	uint_t			fp_current_exceptions;
	kfpu_t			*fp_current_pfregs;
	void			(*fp_current_read_freg) ();
	void			(*fp_current_write_freg) ();
	void			(*fp_current_read_dreg) ();
	void			(*fp_current_write_dreg) ();
	uint64_t		(*fp_current_read_gsr) (kfpu_t *);
	void			(*fp_current_write_gsr) (uint64_t, kfpu_t *);
	int			fp_trapcode;
	char			*fp_trapaddr;
	struct	regs		*fp_traprp;
	enum	seg_rw		fp_traprw;
} fp_simd_type;

/*
 * FPU related kstat structures
 */
struct fpustat_kstat  {
	struct kstat_named		fpu_ieee_traps;
	struct kstat_named		fpu_unfinished_traps;
	struct kstat_named		fpu_unimplemented_traps;
};

struct fpuinfo_kstat {
	struct kstat_named		fpu_sim_fmovs;
	struct kstat_named		fpu_sim_fmovd;
	struct kstat_named		fpu_sim_fmovq;
	struct kstat_named		fpu_sim_fnegs;
	struct kstat_named		fpu_sim_fnegd;
	struct kstat_named		fpu_sim_fnegq;
	struct kstat_named		fpu_sim_fabss;
	struct kstat_named		fpu_sim_fabsd;
	struct kstat_named		fpu_sim_fabsq;
	struct kstat_named		fpu_sim_fsqrts;
	struct kstat_named		fpu_sim_fsqrtd;
	struct kstat_named		fpu_sim_fsqrtq;
	struct kstat_named		fpu_sim_fadds;
	struct kstat_named		fpu_sim_faddd;
	struct kstat_named		fpu_sim_faddq;
	struct kstat_named		fpu_sim_fsubs;
	struct kstat_named		fpu_sim_fsubd;
	struct kstat_named		fpu_sim_fsubq;
	struct kstat_named		fpu_sim_fmuls;
	struct kstat_named		fpu_sim_fmuld;
	struct kstat_named		fpu_sim_fmulq;
	struct kstat_named		fpu_sim_fdivs;
	struct kstat_named		fpu_sim_fdivd;
	struct kstat_named		fpu_sim_fdivq;
	struct kstat_named		fpu_sim_fcmps;
	struct kstat_named		fpu_sim_fcmpd;
	struct kstat_named		fpu_sim_fcmpq;
	struct kstat_named		fpu_sim_fcmpes;
	struct kstat_named		fpu_sim_fcmped;
	struct kstat_named		fpu_sim_fcmpeq;
	struct kstat_named		fpu_sim_fsmuld;
	struct kstat_named		fpu_sim_fdmulx;
	struct kstat_named		fpu_sim_fstox;
	struct kstat_named		fpu_sim_fdtox;
	struct kstat_named		fpu_sim_fqtox;
	struct kstat_named		fpu_sim_fxtos;
	struct kstat_named		fpu_sim_fxtod;
	struct kstat_named		fpu_sim_fxtoq;
	struct kstat_named		fpu_sim_fitos;
	struct kstat_named		fpu_sim_fitod;
	struct kstat_named		fpu_sim_fitoq;
	struct kstat_named		fpu_sim_fstoi;
	struct kstat_named		fpu_sim_fdtoi;
	struct kstat_named		fpu_sim_fqtoi;
	struct kstat_named		fpu_sim_fmovcc;
	struct kstat_named		fpu_sim_fmovr;
	struct kstat_named		fpu_sim_fmadds;
	struct kstat_named		fpu_sim_fmaddd;
	struct kstat_named		fpu_sim_fmsubs;
	struct kstat_named		fpu_sim_fmsubd;
	struct kstat_named		fpu_sim_fnmadds;
	struct kstat_named		fpu_sim_fnmaddd;
	struct kstat_named		fpu_sim_fnmsubs;
	struct kstat_named		fpu_sim_fnmsubd;
	struct kstat_named		fpu_sim_invalid;
};

struct visinfo_kstat {
	struct kstat_named		vis_edge8;
	struct kstat_named		vis_edge8n;
	struct kstat_named		vis_edge8l;
	struct kstat_named		vis_edge8ln;
	struct kstat_named		vis_edge16;
	struct kstat_named		vis_edge16n;
	struct kstat_named		vis_edge16l;
	struct kstat_named		vis_edge16ln;
	struct kstat_named		vis_edge32;
	struct kstat_named		vis_edge32n;
	struct kstat_named		vis_edge32l;
	struct kstat_named		vis_edge32ln;
	struct kstat_named		vis_array8;
	struct kstat_named		vis_array16;
	struct kstat_named		vis_array32;
	struct kstat_named		vis_bmask;
	struct kstat_named		vis_fcmple16;
	struct kstat_named		vis_fcmpne16;
	struct kstat_named		vis_fcmpgt16;
	struct kstat_named		vis_fcmpeq16;
	struct kstat_named		vis_fcmple32;
	struct kstat_named		vis_fcmpne32;
	struct kstat_named		vis_fcmpgt32;
	struct kstat_named		vis_fcmpeq32;
	struct kstat_named		vis_fmul8x16;
	struct kstat_named		vis_fmul8x16au;
	struct kstat_named		vis_fmul8x16al;
	struct kstat_named		vis_fmul8sux16;
	struct kstat_named		vis_fmul8ulx16;
	struct kstat_named		vis_fmuld8sux16;
	struct kstat_named		vis_fmuld8ulx16;
	struct kstat_named		vis_fpack16;
	struct kstat_named		vis_fpack32;
	struct kstat_named		vis_fpackfix;
	struct kstat_named		vis_fexpand;
	struct kstat_named		vis_fpmerge;
	struct kstat_named		vis_pdist;
	struct kstat_named		vis_pdistn;
	struct kstat_named		vis_bshuffle;
};

#define	VISINFO_KSTAT(opcode)	{					\
	extern void __dtrace_probe___visinfo_##opcode(uint64_t *);	\
	uint64_t *stataddr = &visinfo.opcode.value.ui64;		\
	__dtrace_probe___visinfo_##opcode(stataddr);       		\
	atomic_inc_64(&visinfo.opcode.value.ui64);			\
}


/* PUBLIC FUNCTIONS */

#ifdef	__STDC__

/*
 * fpu_vis_sim simulates FPU VIS Partial load store instructions; reads and
 * writes FPU data registers directly or works with the PCB image if fpu_exists
 * is 0.
 */
extern enum ftt_type fpu_vis_sim(fp_simd_type *pfpsd, fp_inst_type *pinst,
	struct regs *pregs, fsr_type *pfsr, uint64_t gsr, uint32_t inst);
/*
 * fpu_simulator simulates FPU instructions only; reads and writes FPU data
 * registers directly.
 */
extern enum ftt_type fpu_simulator(fp_simd_type *pfpsd, fp_inst_type *pinst,
	fsr_type *pfsr, uint64_t gsr, uint32_t inst);
/*
 * fp_emulator simulates FPU and CPU-FPU instructions; reads and writes FPU
 * data registers from image in pfpu.
 */
extern enum ftt_type fp_emulator(fp_simd_type *pfpsd, fp_inst_type *pinst,
	struct regs *rp, void *prw, kfpu_t *pfpu);
/*
 * fp_traps handles passing exception conditions to the kernel.
 * It is called after fp_simulator or fp_emulator fail (return a non-zero ftt).
 */
extern void fp_traps(fp_simd_type *pfpsd, enum ftt_type ftt, struct regs *rp);

/*
 * fp_kstat_update tracks fpu exception conditions.
 * It is called after a hardware trap returns a non-zero ftt.
 */
extern void fp_kstat_update(enum ftt_type ftt);

/*
 * fp_precise handles floating point unimplemented and unfinished traps,
 * for sparc V9 hardware. These traps are normally passed along to the
 * fpu_simulator, to see if it can run the unimplemented instruction or
 * finish the unfinished instruction. Needless to say, this takes time.
 */
extern void fp_precise(struct regs *rp);

/*
 * fpu_trap handles V9 floating point ieee and other floating point traps.
 * It is called after fp_simulator or fp_emulator fail (return a non-zero ftt),
 * and from the _fp_ieee_exception trap handler.
 */
extern void fpu_trap(struct regs *rp, caddr_t addr, uint32_t type,
			uint32_t code);

#else	/* ! __STDC__ */

/*
 * fpu_simulator simulates FPU instructions only; reads and writes FPU data
 * registers directly.
 */
extern enum ftt_type fpu_simulator(
	fp_simd_type	*pfpsd,	 /* Pointer to FPU simulator data */
	fp_inst_type	*pinst,	 /* Pointer to FPU instruction to simulate. */
	fsr_type	*pfsr,	 /* Pointer to image of FSR to read & write. */
	int		instr);	 /* Instruction to emulate. */

/*
 * fp_emulator simulates FPU and CPU-FPU instructions; reads and writes FPU
 * data registers from image in pfpu.
 */
extern enum ftt_type fp_emulator(
	fp_simd_type	*pfpsd,	   /* Pointer to FPU simulator data */
	fp_inst_type	*pinst,    /* Pointer to FPU instruction to simulate. */
	struct regs	*pregs,    /* Pointer to PCB image of registers. */
	struct rwindow	*pwindow,  /* Pointer to locals and ins. */
	struct fpu	*pfpu);	   /* Pointer to FPU register block. */

/*
 * fp_traps handles passing exception conditions to the kernel.
 * It is called after fp_simulator or fp_emulator fail (return a non-zero ftt).
 */
extern void fp_traps(
	fp_simd_type	*pfpsd,	 /* Pointer to FPU simulator data */
	enum ftt_type	ftt,	 /* Type of trap. */
	struct regs	*rp);	 /* Pointer to PCB image of registers. */

/*
 * fp_kstat_update tracks fpu exception conditions.
 * It is called after a hardware trap returns a non-zero ftt.
 */
extern void fp_kstat_update(enum ftt_type ftt);	/* Type of trap. */

/*
 * fp_precise handles floating point unimplemented and unfinished traps,
 * for sparc V9 hardware. These traps are normally passed along to the
 * fpu_simulator, to see if it can run the unimplemented instruction or
 * finish the unfinished instruction. Needless to say, this takes time.
 */
extern void fp_precise(
	struct regs *rp);	/* Pointer to PCB image of registers. */

/*
 * fpu_trap handles V9 floating point ieee and other floating point traps.
 * It is called after fp_simulator or fp_emulator fail (return a non-zero ftt),
 * and from the _fp_ieee_exception trap handler.
 */
extern void fpu_trap(
	struct regs *rp,	/* Pointer to PCB image of registers. */
	caddr_t addr,		/* Address of trapping instruction. */
	uint32_t type,		/* Type of trapping exception. */
	uint32_t code);		/* Trap code -> si_code. */

#endif	/* __STDC__ */
#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FPU_FPU_SIMULATOR_H */
