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
 * Copyright 2007 Jason King.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIS_SPARC_FMT_H
#define	_DIS_SPARC_FMT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include "libdisasm.h"
#include "dis_sparc.h"

/* which set of registers are used with an instruction */
#define	REG_INT		0x00   /* regular integer registers */
#define	REG_FP		0x01   /* single-precision fp registers */
#define	REG_FPD		0x02   /* double-precision fp registers */
#define	REG_FPQ		0x03   /* quad-precision fp registers */
#define	REG_CP		0x04   /* coprocessor registers (v8) */
#define	REG_ICC		0x05   /* %icc / % xcc */
#define	REG_FCC		0x06   /* %fccn */
#define	REG_FSR		0x07   /* %fsr */
#define	REG_CSR		0x08   /* %csr */
#define	REG_CQ		0x09   /* %cq */
#define	REG_NONE	0x0a   /* no registers */

/* the size fo the displacement for branches */
#define	DISP22	0x00
#define	DISP19	0x01
#define	DISP16	0x02
#define	CONST22	0x03

/* get/set the register set name for the rd field of an instruction */
#define	FLG_RD(x)	(x)
#define	FLG_RD_VAL(x)	(x & 0xfL)

#define	FLG_STORE	(0x1L << 24) /* the instruction is not a load */
#define	FLG_ASI		(0x2L << 24) /* the load/store includes an asi value */


/* flags for ALU instructions */

/* set/get register set name for 1st argument position */
#define	FLG_P1(x)	(x << 8)
#define	FLG_P1_VAL(x)	((x >> 8) & 0xfL)

/* get/set reg set for 2nd argument position */
#define	FLG_P2(x)	(x << 4)
#define	FLG_P2_VAL(x)	((x >> 4) & 0xfL)

/* get/set for 3rd argument position */
#define	FLG_P3(x)	(x)
#define	FLG_P3_VAL(x)	(x & 0xfL)

/* set if the arguments do not contain immediate values */
#define	FLG_NOIMM	(0x01L << 24)



/* flags for branch instructions */

/* has branch prediction */
#define	FLG_PRED	(0x01L << 24)

/* get/set condition code register set -- usually REG_NONE */
#define	FLG_RS1(x)	(x)
#define	FLG_RS1_VAL(x)	(x & 0xfL)

/* get/set displacement size */
#define	FLG_DISP(x)	(x << 4L)
#define	FLG_DISP_VAL(x)	((x >> 4L) & 0x0fL)


int fmt_call(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_ls(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_alu(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_branch(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_sethi(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_fpop1(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_fpop2(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_vis(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_trap(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_regwin(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_trap_ret(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_movcc(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_movr(dis_handle_t *, uint32_t, const inst_t *, int);
int fmt_fused(dis_handle_t *, uint32_t, const inst_t *, int);

#ifdef __cplusplus
}
#endif

#endif /* _DIS_SPARC_FMT_H */
