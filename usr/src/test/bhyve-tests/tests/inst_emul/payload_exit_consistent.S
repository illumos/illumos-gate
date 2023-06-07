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

#include <sys/asm_linkage.h>

ENTRY(start)
	movl	$0x12345678, %ecx
	xorl	%eax, %eax
	xorl	%edx, %edx
	/* Incur an exit for an unhandled rdmsr */
	rdmsr

	nop
	nop

	/* Incur an exit for MMIO */
	movl	$0xc0000000, %eax
	movl	(%eax), %ecx

	nop
	nop

	hlt
SET_SIZE(start)
