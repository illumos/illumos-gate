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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Assembly language support for sun4v px driver
 */
 
#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>

/*LINTLIBRARY*/

#if defined(lint)

/*
 * First arg to both of these functions is a dummy, to accomodate how
 * hv_hpriv() works.
 */

/*ARGSUSED*/
int
px_phys_peek_4v(uint64_t dummy, uint64_t paddr, uint64_t *value, int type)
{ return (0); }

/*ARGSUSED*/
int
px_phys_poke_4v(uint64_t dummy, uint64_t paddr, uint64_t *value, int type)
{ return (0); }

#else /* lint */

#define	SHIFT_REGS	mov %o1,%o0; mov %o2,%o1; mov %o3,%o2; mov %o4,%o3

! px_phys_peek_4v: Do physical address read.
!
! After SHIFT_REGS:
! %o0 is address to read
! %o1 is address to save value into
! %o2 is 0 for little endian, non-zero for big endian
!
! Assumes 8 byte data and that alignment is correct.
!
! Always returns success (0) in %o0

	ENTRY(px_phys_peek_4v)

	SHIFT_REGS
	tst	%o2			! Set up %asi with modifier for
	movz	%xcc, ASI_IOL, %g1	! Big/little endian physical space
	movnz	%xcc, ASI_IO, %g1
	mov	%g1, %asi

	ldxa	[%o0]%asi, %g1
	stx	%g1, [%o1]
	membar	#Sync			! Make sure the loads take
	mov     %g0, %o0
	done
	SET_SIZE(px_phys_peek_4v)


! px_phys_poke_4v: Do physical address write.
!
! After SHIFT_REGS:
! %o0 is address to write to
! %o1 is address to read from
! %o2 is 0 for little endian, non-zero for big endian
!
! Assumes 8 byte data and that alignment is correct.
!
! Always returns success (0) in %o0

	ENTRY(px_phys_poke_4v)

	SHIFT_REGS
	tst	%o2
	movz	%xcc, ASI_IOL, %g1	! Big/little endian physical space
	movnz	%xcc, ASI_IO, %g1
	mov	%g1, %asi

	ldx	[%o1], %g1
	stxa	%g1, [%o0]%asi
	membar	#Sync
	mov	%g0, %o0
	done
	SET_SIZE(px_phys_poke_4v)

#endif
