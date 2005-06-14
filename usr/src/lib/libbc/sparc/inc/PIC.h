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

#ifdef PIC 
#define PIC_SETUP(r) \
	or	%g0,%o7,%g1; \
1: \
	call	2f; \
	nop; \
2: \
	sethi	%hi(_GLOBAL_OFFSET_TABLE_ - (1b-.)), %r; \
	or	%r, %lo(_GLOBAL_OFFSET_TABLE_ - (1b-.)),%r; \
	add	%r, %o7, %r; \
	or	%g0,%g1,%o7
#else 
#define PIC_SETUP()
#endif 

