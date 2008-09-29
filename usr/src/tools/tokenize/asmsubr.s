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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"asmsubr.s"

#define	_ASM	1
#include <sys/asm_linkage.h>

	ENTRY(get_g5)
	retl
	mov	%g5, %o0
	SET_SIZE(get_g5)

	ENTRY(set_g5)
	retl
	mov	%o0, %g5
	SET_SIZE(set_g5)

	ENTRY(get_g7)
	.register %g7, #scratch
	retl
	mov	%g7, %o0
	SET_SIZE(get_g7)

	ENTRY(set_g7)
	.register %g7, #scratch
	retl
	mov	%o0, %g7
	SET_SIZE(set_g7)
