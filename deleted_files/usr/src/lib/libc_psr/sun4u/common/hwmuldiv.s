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
 * Copyright (c) 1997,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

.ident	"%Z%%M%	%I%	%E% SMI"

	.file   "%M%"

#include <sys/asm_linkage.h>
#include "synonyms.h"

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

!
! division, signed
!
	ENTRY(__div64)
	ARGS_TO_64
	sdivx	%o1, %o2, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__div64)

!
! division, unsigned
!
	ENTRY(__udiv64)
	ARGS_TO_64
	udivx	%o1, %o2, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__udiv64)

!
! multiplication, signed and unsigned
!
	ENTRY(__mul64)
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

!
! unsigned remainder 
!
	ENTRY(__urem64)
	ARGS_TO_64
	udivx	%o1, %o2, %o3
	mulx	%o3, %o2, %o3
        sub     %o1, %o3, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__urem64)

!
! signed remainder
!
	ENTRY(__rem64)
	ARGS_TO_64
	sdivx	%o1, %o2, %o3
	mulx	%o2, %o3, %o3
	sub	%o1, %o3, %o1
	retl
	srax	%o1, 32, %o0
	SET_SIZE(__rem64)
