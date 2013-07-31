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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(lint) || defined(__lint)

#include "arcfour.h"

/* ARGSUSED */
void
arcfour_crypt_aligned(ARCFour_key *key, size_t len, uchar_t *in, uchar_t *out)
{}

#else	/* lint || __lint */

	.register	%g2,#scratch
	.register	%g3,#scratch

	.section	".text",#alloc,#execinstr
	.file	"arcfour_crypt_asm.s"

	.section	".text",#alloc
	.align	32

	.section	".text",#alloc,#execinstr
	.align	32
	.skip	32

/*
 * SUBROUTINE arcfour_crypt_aligned
 *
 * void arcfour_crypt_aligned(ARCFour_key *key, size_t len,
 *			uchar_t *in, uchar_t *out);
 *
 * in and out should be aligned on an 8-byte boundary, but len can be anything
 */
	.global arcfour_crypt_aligned


arcfour_crypt_aligned:
	save	%sp,-144,%sp

	srl	%i1, 3, %l7
	ldub	[%i0+256], %g1

	orcc	%l7, %g0, %g0
	ldub	[%i0+257], %g2

	add	%g1, 1, %o1
	bz	%icc, .Loop2
	add	%i0, 0, %i5

	add	%o1, 1, %g1
	and	%o1, 255, %o1

	and	%g1, 255, %g1
	ldub	[%i5 + %o1], %o3

	ldub	[%i5 + %g1], %g3

	add	%g2, %o3, %o2

	add	%o2, %g3, %g2
	and	%o2, 255, %o2

	and	%g2, 255, %g2
	ldub	[%i5 + %o2], %o4

	stb	%o3, [%i5+%o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L1A
	add	%o3,%o4,%o5
.L1B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4

	ldub	[%i5 + %o5], %o5
	add	%g1, 1, %o1

	and	%o1, 255, %o1
	stb	%g3, [%i5 + %g2]
	add	%g3, %g4, %g5

	and	%g5, 255, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1


	sllx	%o5, 56, %o0
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	ldub	[%i5 + %g1], %g3

	add	%g2, %o3, %o2
	ldub	[%i5 + %g5], %g5

	add	%o2, %g3, %g2
	and	%o2, 255, %o2

	sllx	%g5, 48, %g5
	ldub	[%i5 + %o2], %o4
	and	%g2, 255, %g2

	or	%o0, %g5, %o0
	stb	%o3, [%i5+%o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L2A
	add	%o3,%o4,%o5
.L2B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4

	ldub	[%i5 + %o5], %o5
	add	%g1, 1, %o1

	and	%o1, 255, %o1
	stb	%g3, [%i5 + %g2]
	add	%g3, %g4, %g5

	and	%g5, 255, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1


	sllx	%o5, 40, %o5
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	ldub	[%i5 + %g1], %g3
	or	%o0, %o5, %o0

	add	%g2, %o3, %o2
	ldub	[%i5 + %g5], %g5

	add	%o2, %g3, %g2
	and	%o2, 255, %o2

	sllx	%g5, 32, %g5
	ldub	[%i5 + %o2], %o4
	and	%g2, 255, %g2

	or	%o0, %g5, %o0
	stb	%o3, [%i5+%o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L3A
	add	%o3,%o4,%o5
.L3B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4

	ldub	[%i5 + %o5], %o5
	add	%g1, 1, %o1

	and	%o1, 255, %o1
	stb	%g3, [%i5 + %g2]
	add	%g3, %g4, %g5

	and	%g5, 255, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1


	sll	%o5, 24, %o5
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	sub	%i1, 8, %i1
	ldub	[%i5 + %g1], %g3
	or	%o0, %o5, %o0

	srl	%i1, 3, %l7
	ldub	[%i5 + %g5], %g5
	add	%g2, %o3, %o2

	add	%o2, %g3, %g2
	and	%o2, 255, %o2

	sll	%g5, 16, %g5
	ldub	[%i5 + %o2], %o4
	and	%g2, 255, %g2

	or	%o0, %g5, %o0
	stb	%o3, [%i5+%o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L4A
	add	%o3,%o4,%o5
.L4B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4
	add	%g1, 1, %o1

	orcc	%l7, %g0, %g0
	ldub	[%i5 + %o5], %o5
	and	%o1, 255, %o1

	add	%g3, %g4, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1

	stb	%g3, [%i5 + %g2]
	bz	%icc, .EndLoop1
	and	%g5, 255, %g5


.Loop1:
	sll	%o5, 8, %o5
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	ldub	[%i5 + %g1], %g3
	or	%o0, %o5, %o0

	ldub	[%i5 + %g5], %g5
	add	%g2, %o3, %o2

	add	%o2, %g3, %g2
	ldx	[%i2], %o7
	and	%o2, 255, %o2

	and	%g2, 255, %g2
	ldub	[%i5 + %o2], %o4

	or	%o0, %g5, %o0
	stb	%o3, [%i5+%o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L5A
	add	%o3,%o4,%o5
.L5B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4

	ldub	[%i5 + %o5], %o5
	add	%g1, 1, %o1

	and	%o1, 255, %o1
	stb	%g3, [%i5 + %g2]
	add	%g3, %g4, %g5

	and	%g5, 255, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1


	xor	%o0, %o7, %o7
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	sllx	%o5, 56, %o0
	ldub	[%i5 + %g1], %g3

	add	%g2, %o3, %o2
	ldub	[%i5 + %g5], %g5

	add	%o2, %g3, %g2
	stx	%o7, [%i3]
	and	%o2, 255, %o2

	sllx	%g5, 48, %g5
	ldub	[%i5 + %o2], %o4
	and	%g2, 255, %g2

	or	%o0, %g5, %o0
	stb	%o3, [%i5+%o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L6A
	add	%o3,%o4,%o5
.L6B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4
	add	%i3, 8, %i3

	add	%i2, 8, %i2
	ldub	[%i5 + %o5], %o5
	add	%g1, 1, %o1

	and	%o1, 255, %o1
	stb	%g3, [%i5 + %g2]
	add	%g3, %g4, %g5

	and	%g5, 255, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1


	sllx	%o5, 40, %o5
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	ldub	[%i5 + %g1], %g3
	or	%o0, %o5, %o0

	add	%g2, %o3, %o2
	ldub	[%i5 + %g5], %g5

	add	%o2, %g3, %g2
	and	%o2, 255, %o2

	sllx	%g5, 32, %g5
	ldub	[%i5 + %o2], %o4
	and	%g2, 255, %g2

	or	%o0, %g5, %o0
	stb	%o3, [%i5 + %o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L7A
	add	%o3,%o4,%o5
.L7B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4

	ldub	[%i5 + %o5], %o5
	add	%g1, 1, %o1

	and	%o1, 255, %o1
	stb	%g3, [%i5 + %g2]
	add	%g3, %g4, %g5

	and	%g5, 255, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1


	sll	%o5, 24, %o5
	ldub	[%i5 + %o1], %o3
	and	%g1, 255, %g1

	sub	%i1, 8, %i1
	ldub	[%i5 + %g1], %g3
	or	%o0, %o5, %o0

	srl	%i1, 3, %l7
	ldub	[%i5 + %g5], %g5
	add	%g2, %o3, %o2

	add	%o2, %g3, %g2
	and	%o2, 255, %o2

	sll	%g5, 16, %g5
	ldub	[%i5 + %o2], %o4
	and	%g2, 255, %g2

	or	%o0, %g5, %o0
	stb	%o3, [%i5 + %o2]
	subcc	%o2, %g1, %g0

	stb	%o4, [%i5 + %o1]
	bz	%icc, .L8A
	add	%o3,%o4,%o5
.L8B:
	and	%o5, 255, %o5
	ldub	[%i5 + %g2], %g4
	add	%g1, 1, %o1

	orcc	%l7, %g0, %g0
	ldub	[%i5 + %o5], %o5
	and	%o1, 255, %o1

	add	%g3, %g4, %g5
	stb	%g4, [%i5 + %g1]
	add	%o1, 1, %g1

	stb	%g3, [%i5 + %g2]
	bnz	%icc, .Loop1
	and	%g5, 255, %g5


.EndLoop1:
	sll	%o5, 8, %o5
	ldub	[%i5 + %g5], %g5
	orcc	%i1, %g0, %g0

	or	%o0, %o5, %o0
	ldx	[%i2], %o7
	sub	%g1, 2, %g1

	and	%g1, 255, %g1
	stb	%g1, [%i0 + 256]
	or	%o0, %g5, %o0

	xor	%o0, %o7, %o7
	stx	%o7, [%i3]
	add	%i2, 8, %i2

	add	%i3, 8, %i3
	bnz	%icc, .Loop2_1
	stb	%g2, [%i0 + 257]

	ret
	restore	%g0,%g0,%g0


.Loop2:
	orcc	%i1, %g0, %g0
	bnz	.Loop2_1
	nop
	ret
	restore	%g0,%g0,%g0

.Loop2_1:
	and	%o1, 255, %g1
	ldub	[%i5 + %g1], %g3

	add	%g2, %g3, %g2

	and	%g2, 255, %g2

	ldub	[%i5 + %g2], %g4

	stb	%g3, [%i5 + %g2]

	add	%g3, %g4, %g5
	stb	%g4, [%i5 + %g1]

	and	%g5, 255, %g5
	ldub	[%i2], %o0

	add	%g1, 1, %o1
	ldub	[%i5 + %g5], %g5
	subcc	%i1, 1, %i1

	add	%i2, 1, %i2
	add	%i3, 1, %i3

	xor	%o0, %g5, %o0
	bnz	%icc, .Loop2_1
	stb	%o0, [%i3 - 1]

	stb	%g1, [%i0 + 256]

	stb	%g2, [%i0 + 257]

	ret
	restore	%g0,%g0,%g0

.L1A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L1B
	and	%g2, 255, %g2

.L2A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L2B
	and	%g2, 255, %g2

.L3A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L3B
	and	%g2, 255, %g2

.L4A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L4B
	and	%g2, 255, %g2

.L5A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L5B
	and	%g2, 255, %g2

.L6A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L6B
	and	%g2, 255, %g2

.L7A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L7B
	and	%g2, 255, %g2

.L8A:
	add	%o2, %o3, %g2
	or	%o3, %g0, %g3
	ba	.L8B
	and	%g2, 255, %g2

	.type	arcfour_crypt_aligned,2
	.size	arcfour_crypt_aligned,(. - arcfour_crypt_aligned)

#endif	/* lint || __lint */
