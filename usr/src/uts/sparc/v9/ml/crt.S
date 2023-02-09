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
/*
 *	Copyright (c) 1988-1991 by Sun Microsystems, Inc.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* From SunOS 4.1 1.6 */

#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/simulate.h>

/*
 * C run time subroutines.
 *
 *	Those beginning in `.' are not callable from C and hence do not
 *	get lint prototypes.
 */

/*
 * Structure return
 */
#define UNIMP		0
#define MASK		0x00000fff
#define STRUCT_VAL_OFF	(16*4)

	RTENTRY(.stret4)
	RTENTRY(.stret8)
	!
	! see if key matches: if not, structure value not expected,
	! so just return
	!
	ld	[%i7 + 8], %o3
	and	%o1, MASK, %o4
	sethi	%hi(UNIMP), %o5
	or	%o4, %o5, %o5
	cmp	%o5, %o3
	be,a	0f
	ld	[%fp + STRUCT_VAL_OFF], %i0	! set expected return value
	ret
	restore
0:						! copy the struct
	subcc	%o1, 4, %o1
	ld	[%o0 + %o1], %o4
	bg	0b
	st	%o4, [%i0 + %o1]		! delay slot
	add	%i7, 0x4, %i7			! bump return address
	ret
	restore
	SET_SIZE(.stret4)
	SET_SIZE(.stret8)

	RTENTRY(.stret2)
	!
	! see if key matches: if not, structure value not expected,
	! so just return
	!
	ld	[%i7 + 8], %o3
	and	%o1, MASK, %o4
	sethi	%hi(UNIMP), %o5
	or	%o4, %o5, %o5
	cmp	%o5, %o3
	be,a	0f
	ld	[%fp + STRUCT_VAL_OFF], %i0	! set expected return value
	ret
	restore
0:						! copy the struct
	subcc	%o1, 2, %o1
	lduh	[%o0 + %o1], %o4
	bg	0b
	sth	%o4, [%i0 + %o1]		! delay slot
	add	%i7, 0x4, %i7			! bump return address
	ret
	restore
	SET_SIZE(.stret2)

/*
 * Convert 32-bit arg pairs in %o0:o1 and %o2:%o3 to 64-bit args in %o1 and %o2
 */
#define	ARGS_TO_64				\
	sllx	%o0, 32, %o0;			\
	srl	%o1, 0, %o1;			\
	sllx	%o2, 32, %o2;			\
	srl	%o3, 0, %o3;			\
	or	%o0, %o1, %o1;			\
	or	%o2, %o3, %o2

	RTENTRY(__mul64)
	ALTENTRY(__umul64)
	ARGS_TO_64
	sub	%o1, %o2, %o0	! %o0 = a - b
	movrlz	%o0, %g0, %o0	! %o0 = (a < b) ? 0 : a - b
	sub	%o1, %o0, %o1	! %o1 = (a < b) ? a : b = min(a, b)
	add	%o2, %o0, %o2	! %o2 = (a < b) ? b : a = max(a, b)
	mulx	%o1, %o2, %o1	! min(a, b) in "rs1" for early exit
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__mul64)
	SET_SIZE(__umul64)

	RTENTRY(__div64)
	ARGS_TO_64
	sdivx	%o1, %o2, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__div64)

	RTENTRY(__udiv64)
	ARGS_TO_64
	udivx	%o1, %o2, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__udiv64)

	RTENTRY(__rem64)
	ARGS_TO_64
	sdivx	%o1, %o2, %o3
	mulx	%o2, %o3, %o3
	sub	%o1, %o3, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__rem64)

	RTENTRY(__urem64)
	ARGS_TO_64
	udivx	%o1, %o2, %o3
	mulx	%o2, %o3, %o3
	sub	%o1, %o3, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__urem64)

