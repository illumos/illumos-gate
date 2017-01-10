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
 * Copyright 1986-1999,2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PRIVREGS_H
#define	_SYS_PRIVREGS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is kernel isa dependent.
 */

/*
 * This file describes the cpu's privileged register set, and
 * how the machine state is saved on the stack when a trap occurs.
 */

#include <v7/sys/psr.h>
#include <sys/fsr.h>

#ifndef	_ASM

/*
 * This structure is only here for compatibility.  It is not used by the kernel
 * and may be removed in a future release.  A better way to access this data
 * is to use gregset_t; see proc(4) and ucontext(3HEAD).
 */
struct regs {
	long	r_psr;		/* processor status register */
	long	r_pc;		/* program counter */
	long	r_npc;		/* next program counter */
	long	r_y;		/* the y register */
	long	r_g1;		/* user global regs */
	long	r_g2;
	long	r_g3;
	long	r_g4;
	long	r_g5;
	long	r_g6;
	long	r_g7;
	long	r_o0;
	long	r_o1;
	long	r_o2;
	long	r_o3;
	long	r_o4;
	long	r_o5;
	long	r_o6;
	long	r_o7;
};

#define	r_ps	r_psr		/* for portablility */
#define	r_r0	r_o0
#define	r_sp	r_o6

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PRIVREGS_H */
