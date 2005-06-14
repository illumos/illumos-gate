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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_VIS_SIMULATOR_H
#define	_SYS_VIS_SIMULATOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * VIS opf codes, instruction type
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* kstat structure for reporting kstats */
extern struct visinfo_kstat visinfo;

typedef			/* typical VIS instruction. */
	struct {
	unsigned int		op	: 2;	/* Top two bits. */
	unsigned int		rd	: 5;	/* Destination. */
	unsigned int		op3	: 6;	/* Main op code. */
	unsigned int		rs1	: 5;	/* First operand. */
	unsigned int		opf	: 9;	/* Floating-point op code. */
	unsigned int		rs2	: 5;	/* Second operand. */
} vis_inst_type;

enum vis_opf {		/* VIS opf codes. */
	edge8		= 0x0,
	edge8n		= 0x1,
	edge8l		= 0x2,
	edge8ln		= 0x3,
	edge16		= 0x4,
	edge16n		= 0x5,
	edge16l		= 0x6,
	edge16ln	= 0x7,
	edge32		= 0x8,
	edge32n		= 0x9,
	edge32l		= 0xa,
	edge32ln	= 0xb,
	array8		= 0x10,
	array16		= 0x12,
	array32		= 0x14,
	alignaddr	= 0x18,
	bmask		= 0x19,
	alignaddrl	= 0x1a,
	fcmple16	= 0x20,
	fcmpne16	= 0x22,
	fcmple32	= 0x24,
	fcmpne32	= 0x26,
	fcmpgt16	= 0x28,
	fcmpeq16	= 0x2a,
	fcmpgt32	= 0x2c,
	fcmpeq32	= 0x2e,
	fmul8x16	= 0x31,
	fmul8x16au	= 0x33,
	fmul8x16al	= 0x35,
	fmul8sux16	= 0x36,
	fmul8ulx16	= 0x37,
	fmuld8sux16	= 0x38,
	fmuld8ulx16	= 0x39,
	fpack32		= 0x3a,
	fpack16		= 0x3b,
	fpackfix	= 0x3d,
	pdist		= 0x3e,
	faligndata	= 0x48,
	fpmerge		= 0x4b,
	bshuffle	= 0x4c,
	fexpand		= 0x4d,
	fpadd16		= 0x50,
	fpadd16s	= 0x51,
	fpadd32		= 0x52,
	fpadd32s	= 0x53,
	fpsub16		= 0x54,
	fpsub16s	= 0x55,
	fpsub32		= 0x56,
	fpsub32s	= 0x57,
	fzero		= 0x60,
	fzeros		= 0x61,
	fnor		= 0x62,
	fnors		= 0x63,
	fandnot2	= 0x64,
	fandnot2s	= 0x65,
	fnot2		= 0x66,
	fnot2s		= 0x67,
	fandnot1	= 0x68,
	fandnot1s	= 0x69,
	fnot1		= 0x6a,
	fnot1s		= 0x6b,
	fxor		= 0x6c,
	fxors		= 0x6d,
	fnand		= 0x6e,
	fnands		= 0x6f,
	fand		= 0x70,
	fands		= 0x71,
	fxnor		= 0x72,
	fxnors		= 0x73,
	fsrc1		= 0x74,
	fsrc1s		= 0x75,
	fornot2		= 0x76,
	fornot2s	= 0x77,
	fsrc2		= 0x78,
	fsrc2s		= 0x79,
	fornot1		= 0x7a,
	fornot1s	= 0x7b,
	for_op		= 0x7c,		/* compiler does not like the use */
	fors_op		= 0x7d,		/* of the key word "for" ! */
	fone		= 0x7e,
	fones		= 0x7f,
	siam		= 0x81
};

#define	GSR_ALIGN_MASK	UINT64_C(0x0000000000000007)
#define	GSR_ALIGN_SHIFT	0
#define	GSR_SCALE_MASK	UINT64_C(0x00000000000000f8)
#define	GSR_SCALE_SHIFT	3
#define	GSR_IRND_MASK	UINT64_C(0x0000000006000000)
#define	GSR_IRND_SHIFT	25
#define	GSR_IM_MASK	UINT64_C(0x0000000008000000)
#define	GSR_IM_SHIFT	27
#define	GSR_MASK_MASK	UINT64_C(0xffffffff00000000)
#define	GSR_MASK_SHIFT	32

#define	GSR_IM_IRND_MASK	(GSR_IM_MASK | GSR_IRND_MASK)
#define	GSR_ALIGN(gsr)	((gsr & GSR_ALIGN_MASK) >> GSR_ALIGN_SHIFT)
#define	GSR_SCALE(gsr)	((gsr & GSR_SCALE_MASK) >> GSR_SCALE_SHIFT)
#define	GSR_IRND(gsr)	((gsr & GSR_IRND_MASK) >> GSR_IRND_SHIFT)
#define	GSR_IM(gsr)	((gsr & GSR_IM_MASK) >> GSR_IM_SHIFT)
#define	GSR_MASK(gsr)	((gsr & GSR_MASK_MASK) >> GSR_MASK_SHIFT)

/* PUBLIC FUNCTIONS */

/*
 * vis_fpu_simulator simulates VIS FPU instructions only; reads and writes
 * FPU data registers directly.
 */

extern enum ftt_type vis_fpu_simulator(fp_simd_type *, fp_inst_type,
			struct regs *, void *, kfpu_t *);

/*
 * Simulator for VIS loads and stores between floating-point unit and memory.
 */
enum ftt_type vis_fldst(fp_simd_type *, fp_inst_type, struct regs *,
			void *, unsigned);

/*
 * Simulator for rd %gsr instruction.
 */
enum ftt_type vis_rdgsr(fp_simd_type *, fp_inst_type, struct regs *,
			void *, kfpu_t *);

/*
 * Simulator for wr %gsr instruction.
 */
enum ftt_type vis_wrgsr(fp_simd_type *, fp_inst_type, struct regs *,
			void *, kfpu_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VIS_SIMULATOR_H */
