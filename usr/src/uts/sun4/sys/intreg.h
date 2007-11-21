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

#ifndef _SYS_INTREG_H
#define	_SYS_INTREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/machintreg.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	INO_SIZE	6		/* Interrupt Number Offset bit size */
#define	INR_SIZE	(IGN_SIZE + INO_SIZE)	/* Interrupt Number bit size */
#define	MAX_IGN		(1 << IGN_SIZE) /* Max Interrupt Group Number size */
#define	MAX_INO		(1 << INO_SIZE) /* Max Interrupt Number per group */
#define	MAXDEVINTRS	(MAX_IGN * MAX_INO) /* Max hardware intrs allowed */

/*
 * A platform may require use of the system interrupt table beyond
 * the maximum hardware interrupts specified above for virtual device
 * interrupts. If the platform does not specify MAXVINTRS we default to 0.
 */
#ifndef MAXVINTRS
#define	MAXVINTRS	0
#endif

/*
 * maximum system interrupts allowed
 */
#define	MAXIVNUM	(MAXDEVINTRS + MAXVINTRS)

/*
 * Interrupt State Machine
 *	Each interrupt source has a 2-bit state machine which ensures that
 *	software sees exactly one interrupt packet per assertion of the
 *	interrupt signal.
 */
#define	ISM_IDLE	0x0	/* not asserted or pending */
#define	ISM_TRANSMIT	0x1	/* asserted but is not dispatched */
#define	ISM_PENDING	0x2	/* dispatched to a processor or is in transit */

/*
 * Per-Processor Soft Interrupt Register
 * XXX use %asr when the new assembler supports them
 */
#define	SET_SOFTINT	%asr20		/* ASR 0x14 */
#define	CLEAR_SOFTINT	%asr21		/* ASR 0x15 */
#define	SOFTINT		%asr22		/* ASR 0x16 */
#define	SOFTINT_MASK	0xFFFE		/* <15:1> */
#define	TICK_INT_MASK	0x1		/* <0> */
#define	STICK_INT_MASK	0x10000		/* <0> */

/*
 * Per-Processor TICK Register and TICK_Compare registers
 *
 */
#define	TICK_COMPARE	%asr23		/* ASR 0x17 */
#define	STICK		%asr24		/* ASR 0x18 */
#define	STICK_COMPARE	%asr25		/* ASR 0x19 */
#define	TICKINT_DIS_SHFT	0x3f

#ifndef _ASM

/*
 * Interrupt Packet (mondo)
 */
struct intr_packet {
	uint64_t intr_data0; /* can be an interrupt number or a pc */
	uint64_t intr_data1;
	uint64_t intr_data2;
};

/*
 * Leftover bogus stuff; removed them later
 */
struct cpu_intreg {
	uint_t	pend;
	uint_t	clr_pend;
	uint_t	set_pend;
	uchar_t	filler[0x1000 - 0xc];
};

struct sys_intreg {
	uint_t	sys_pend;
	uint_t	sys_m;
	uint_t	sys_mclear;
	uint_t	sys_mset;
	uint_t	itr;
};

#endif  /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_INTREG_H */
