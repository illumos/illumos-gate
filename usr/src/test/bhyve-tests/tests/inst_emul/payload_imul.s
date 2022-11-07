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
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/asm_linkage.h>
#include "payload_common.h"

ENTRY(start)
	/* check that the mmio values we expect are emitted */
	movw	0x10001234, %ax
	cmpw	$0x1234, %ax
	jne		fail
	movl	0x10001232, %eax
	cmpl	$0x12341232, %eax
	jne		fail
	movq	0x10001230, %rax
	movq	$0x1236123412321230, %rdx
	cmpq	%rdx, %rax
	jne		fail

	/* attempt the imul at 2/4/8 byte widths */
	movl	$0x2, %eax
	imulw	0x10001234, %ax
	cmpw	$0x2468, %ax
	jne		fail

	movl	$0x2, %eax
	imull	0x10001232, %eax
	cmpl	$0x24682464, %eax
	jne		fail

	movl	$0x10, %eax
	imulq	0x10001230, %rax
	movq	$0x2361234123212300, %rcx
	cmpq	%rcx, %rax
	jne		fail

	movw    $IOP_TEST_RESULT, %dx
	movb    $TEST_RESULT_PASS, %al
	outb    (%dx)
	hlt

fail:
	movw    $IOP_TEST_RESULT, %dx
	movb    $TEST_RESULT_FAIL, %al
	outb    (%dx)
	hlt
SET_SIZE(start)
