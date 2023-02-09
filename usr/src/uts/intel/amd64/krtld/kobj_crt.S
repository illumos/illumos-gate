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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * exit routine from linker/loader to kernel
 */

#include <sys/asm_linkage.h>
#include <sys/reboot.h>

/*
 *  exitto is called from main() and does 1 things
 *	It then jumps directly to the just-loaded standalone.
 *	There is NO RETURN from exitto().
 */


	ENTRY(exitto)

	/preserve destination in temporary register %r11
	movq	%rdi, %r11

	/holds address of array of pointers to functions
	/ $arg1
	movq	$romp, %rax
	movq    (%rax), %rdi

	/holds address of bootops structure
	/ $arg2
	movq	$ops, %rax
	movq    (%rax), %rdx

	/ Call destination
	INDIRECT_CALL_REG(r11)

	SET_SIZE(exitto)

