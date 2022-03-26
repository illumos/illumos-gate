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

ENTRY(start)
	/*
	 * Pad test value with garbage to make sure it is properly trimmed off
	 * when the emulation handles the exit.
	 */
	movq    $0xff01020304, %rcx
	rdmsr
	hlt
SET_SIZE(start)
