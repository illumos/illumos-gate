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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_SYS_DEBUGREG_H
#define	_SYS_DEBUGREG_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Specify masks for accessing the i386 debug registers.
 */

/*
 * The debug registers are found in an array (debugreg) in the u block.
 * On the i386, there are 4 registers to specify linear addresses.
 * dr4 and dr5 are reserved.
 */
#define	DR_FIRSTADDR	0	/* u.u_debugreg[DR_FIRSTADDR] */
#define	DR_LASTADDR	3	/* u.u_debugreg[DR_LASTADDR]  */

/*
 * The debug status is found in dr6 after a debug trap.
 */
#define	DR_STATUS	6	/* u.u_debugreg[DR_STATUS] */
#define	DR_TRAP0	0x1	/* Trap from debug register #0 */
#define	DR_TRAP1	0x2	/* Trap from debug register #1 */
#define	DR_TRAP2	0x4	/* Trap from debug register #2 */
#define	DR_TRAP3	0x8	/* Trap from debug register #3 */
#define	DR_ICEALSO	0x2000	/* Flag bit reserved for in-circuit-emulator */
#define	DR_SINGLESTEP	0x4000	/* Trap resulting from the single-step flag */
#define	DR_TASKSWITCH	0x8000	/* Trap resulting from a task-switch */

/*
 * dr7 controls the rest of the debug registers.
 * use shifts and masks because arrays of fields tend to get aligned.
 * For example,
 *    dr7 & DR_LOCAL_ENABLE_MASK
 *    dr7 >> (DR_LOCAL_ENABLE_SHIFT + r# * DR_ENABLE_SIZE) & 0x1
 *    dr7 >> (DR_CONTROL_SHIFT + r# * DR_CONTROL_SIZE) & DR_RW_MASK
 * Note that the GLOBAL bits below and always turned off by the kernel.
 */
#define	DR_CONTROL		7	/* u.u_debugreg[DR_CONTROL] */
#define	DR_LOCAL_ENABLE_MASK	0x55	/* Enable all 4 regs for ldt addrs */
#define	DR_GLOBAL_ENABLE_MASK	0xAA	/* Enable all 4 regs for gdt addrs */
#define	DR_CONTROL_RESERVED	0xFC00	/* Bits reserved by Intel */
#define	DR_LOCAL_SLOWDOWN	0x100	/* Slow the pipeline for ldt addrs */
#define	DR_GLOBAL_SLOWDOWN	0x200	/* Slow the pipeline for gdt addrs */

#define	DR_LOCAL_ENABLE_SHIFT	0	/* Additional shift: local enable  */
#define	DR_GLOBAL_ENABLE_SHIFT	1	/* Additional shift: global enable */
#define	DR_ENABLE_SIZE		2	/* 2 enable bits per register  */

#define	DR_TRAPS	(DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)
#define	DR_ENABLE0	0x03	/* Local or Global enable of trap 0 */
#define	DR_ENABLE1	0x0C	/* Local or Global enable of trap 1 */
#define	DR_ENABLE2	0x30	/* Local or Global enable of trap 2 */
#define	DR_ENABLE3	0xC0	/* Local or Global enable of trap 3 */

#define	DR_CONTROL_SHIFT	16	/* Shift to register control bits */
#define	DR_CONTROL_SIZE		4	/* 4 control bits per register */
#define	DR_RW_MASK		0x3	/* Two bits specify r/w access */
#define	DR_RW_EXECUTE		0x0	/* Settings for the read/write mask */
#define	DR_RW_WRITE		0x1
#define	DR_RW_IO_RW		0x2	/* I/O space on Pentium and beyond */
#define	DR_RW_READ		0x3
#define	DR_LEN_MASK		0xC	/* Two bits specify data length */
#define	DR_LEN_1		0x0	/* Settings for data length */
#define	DR_LEN_2		0x4
#define	DR_LEN_4		0xC

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEBUGREG_H */
