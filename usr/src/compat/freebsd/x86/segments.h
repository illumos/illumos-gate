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
 * Copyright 2015 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_X86_SEGMENTS_H_
#define	_COMPAT_FREEBSD_X86_SEGMENTS_H_

/*
 * Entries in the Interrupt Descriptor Table (IDT)
 */
#define	IDT_BP		3	/* #BP: Breakpoint */
#define	IDT_UD		6	/* #UD: Undefined/Invalid Opcode */
#define	IDT_SS		12	/* #SS: Stack Segment Fault */
#define	IDT_GP		13	/* #GP: General Protection Fault */
#define	IDT_AC		17	/* #AC: Alignment Check */

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_SEGMENTS_H_ */
