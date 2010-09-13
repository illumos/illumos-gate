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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#include <sys/asm_linkage.h>

	.file		__FILE__
/*
 * int tnfw_b_get_lock(tnf_byte_lock_t *);
 */
	ENTRY(tnfw_b_get_lock)
	ldstub	[%o0], %o1
	jmpl	%o7+8, %g0
	mov	%o1, %o0
	SET_SIZE(tnfw_b_get_lock)

/*
 * void tnfw_b_clear_lock(tnf_byte_lock_t *);
 */
	ENTRY(tnfw_b_clear_lock)
	jmpl	%o7+8, %g0
	stb	%g0, [%o0]
	SET_SIZE(tnfw_b_clear_lock)

/*
 * u_long tnfw_b_atomic_swap(u_long *, u_long);
 */
	ENTRY(tnfw_b_atomic_swap)
	swap	[%o0], %o1
	jmpl	%o7+8, %g0
	mov	%o1, %o0
	SET_SIZE(tnfw_b_atomic_swap)
