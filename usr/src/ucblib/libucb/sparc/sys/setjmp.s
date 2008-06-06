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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

/*
 * The UCB setjmp(env) is the same as SYSV's sigsetjmp(env, 1)
 * while _setjmp(env) is the same as SYSV's sigsetjmp(env, 0)
 * Both longjmp(env, val) and _longjmp(env, val) are the same
 * as SYSV's siglongjmp(env, val).
 *
 * These are #defined as such in /usr/ucbinclude/setjmp.h
 * but setjmp/longjmp and _setjmp/_longjmp have historically
 * been entry points in libucb, so for binary compatibility
 * we implement them as tail calls into libc in order to make
 * them appear as direct calls to sigsetjmp/siglongjmp, which
 * is essential for the correct operation of sigsetjmp.
 */

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(longjmp,function)

	ENTRY_NP(setjmp)
	mov	%o7, %g1
	mov	1, %o1
	call	_sigsetjmp
	mov	%g1, %o7
	SET_SIZE(setjmp)

	ENTRY_NP(_setjmp)
	mov	%o7, %g1
	clr	%o1
	call	_sigsetjmp
	mov	%g1, %o7
	SET_SIZE(_setjmp)

	ENTRY_NP(longjmp)
	mov	%o7, %g1
	call	_siglongjmp
	mov	%g1, %o7
	SET_SIZE(longjmp)
