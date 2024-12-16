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
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/asm_linkage.h>
#include "payload_common.h"

ENTRY(start)
	/*
	 * `ins` and `outs` access memory through rdi, so reserve a few
	 * bytes of stack and make rdi point into it so we don't clobber
	 * something important along the way.
	 */
	subq %rsp, 8
	mov %rsp, %rdi
	/*
	 * Port 0x55aa is just a convenient value we can check after the
	 * exit.
	 */
	movw $0x55aa, %dx
	movl $0x01, %ecx
	rep insb
	movl $0x01, %ecx
	rep outsb

	movw    $IOP_TEST_RESULT, %dx
	movb    $TEST_RESULT_PASS, %al
	outb    (%dx)
	hlt
SET_SIZE(start)
