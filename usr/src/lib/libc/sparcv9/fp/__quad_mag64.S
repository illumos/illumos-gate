!
! Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
! Use is subject to license terms.
!
! CDDL HEADER START
!
! The contents of this file are subject to the terms of the
! Common Development and Distribution License, Version 1.0 only
! (the "License").  You may not use this file except in compliance
! with the License.
!
! You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
! or http://www.opensolaris.org/os/licensing.
! See the License for the specific language governing permissions
! and limitations under the License.
!
! When distributing Covered Code, include this CDDL HEADER in each
! file and include the License file at usr/src/OPENSOLARIS.LICENSE.
! If applicable, add the following below this CDDL HEADER, with the
! fields enclosed by brackets "[]" replaced with your own identifying
! information: Portions Copyright [yyyy] [name of copyright owner]
!
! CDDL HEADER END
!

.ident	"%Z%%M%	%I%	%E% SMI"

! /*
!  * This file contains __quad_mag_add and __quad_mag_sub, the core
!  * of the quad precision add and subtract operations.
!  */
! SPARC V9 version hand-coded in assembly to use 64-bit integer registers

	.file	"__quad_mag64.s"

#include <sys/asm_linkage.h>

! union longdouble {
! 	struct {
! 		unsigned int	msw;
! 		unsigned int	frac2;
! 		unsigned int	frac3;
! 		unsigned int	frac4;
! 	} l;
! 	struct {
! 		unsigned long	msll;
! 		unsigned long	frac;
! 	} ll;
! 	long double	d;
! };
!
! /*
!  * __quad_mag_add(x, y, z, fsr)
!  *
!  * Sets *z = *x + *y, rounded according to the rounding mode in *fsr,
!  * and updates the current exceptions in *fsr.  This routine assumes
!  * *x and *y are finite, with the same sign (i.e., an addition of
!  * magnitudes), |*x| >= |*y|, and *z already has its sign bit set.
!  */
! void
! __quad_mag_add(const union longdouble *x, const union longdouble *y,
! 	union longdouble *z, unsigned int *fsr)
! {
! 	unsigned long	lx, ly, frac, sticky;
! 	unsigned int	ex, ey, round, rm;
! 	int		e, uflo;
!
! 	/* get the leading significand double-words and exponents */
! 	ex = (x->ll.msll >> 48) & 0x7fff;
! 	lx = x->ll.msll & ~0xffff000000000000ul;
! 	if (ex == 0)
! 		ex = 1;
! 	else
! 		lx |= 0x0001000000000000ul;
!
! 	ey = (y->ll.msll >> 48) & 0x7fff;
! 	ly = y->ll.msll & ~0xffff000000000000ul;
! 	if (ey == 0)
! 		ey = 1;
! 	else
! 		ly |= 0x0001000000000000ul;
!
! 	/* prenormalize y */
! 	e = (int) ex - (int) ey;
! 	round = sticky = 0;
! 	if (e >= 114) {
! 		frac = x->ll.frac;
! 		sticky = ly | y->ll.frac;
! 	} else {
! 		frac = y->ll.frac;
! 		if (e >= 64) {
! 			sticky = frac & 0x7ffffffffffffffful;
! 			round = frac >> 63;
! 			frac = ly;
! 			ly = 0;
! 			e -= 64;
! 		}
! 		if (e) {
! 			sticky |= round | (frac & ((1ul << (e - 1)) - 1));
! 			round = (frac >> (e - 1)) & 1;
! 			frac = (frac >> e) | (ly << (64 - e));
! 			ly >>= e;
! 		}
!
! 		/* add, propagating carries */
! 		frac += x->ll.frac;
! 		lx += ly;
! 		if (frac < x->ll.frac)
! 			lx++;
!
! 		/* postnormalize */
! 		if (lx >= 0x0002000000000000ul) {
! 			sticky |= round;
! 			round = frac & 1;
! 			frac = (frac >> 1) | (lx << 63);
! 			lx >>= 1;
! 			ex++;
! 		}
! 	}
!
! 	/* keep track of whether the result before rounding is tiny */
! 	uflo = (lx < 0x0001000000000000ul);
!
! 	/* get the rounding mode, fudging directed rounding modes
! 	   as though the result were positive */
! 	rm = *fsr >> 30;
! 	if (z->l.msw)
! 		rm ^= (rm >> 1);
!
! 	/* see if we need to round */
! 	if (round | sticky) {
! 		*fsr |= FSR_NXC;
!
! 		/* round up if necessary */
! 		if (rm == FSR_RP || (rm == FSR_RN && round &&
! 			(sticky || (frac & 1)))) {
! 			if (++frac == 0)
! 				if (++lx >= 0x0002000000000000ul) {
! 					lx >>= 1;
! 					ex++;
! 				}
! 		}
! 	}
!
! 	/* check for overflow */
! 	if (ex >= 0x7fff) {
! 		/* store the default overflowed result */
! 		*fsr |= FSR_OFC | FSR_NXC;
! 		if (rm == FSR_RN || rm == FSR_RP) {
! 			z->l.msw |= 0x7fff0000;
! 			z->l.frac2 = 0;
! 			z->ll.frac = 0;
! 		} else {
! 			z->l.msw |= 0x7ffeffff;
! 			z->l.frac2 = 0xffffffff;
! 			z->ll.frac = 0xfffffffffffffffful;
! 		}
! 	} else {
! 		/* store the result */
! 		if (lx >= 0x0001000000000000ul)
! 			z->l.msw |= (ex << 16);
! 		z->l.msw |= (lx >> 32) & 0xffff;
! 		z->l.frac2 = (lx & 0xffffffff);
! 		z->ll.frac = frac;
!
! 		/* if the pre-rounded result was tiny and underflow trapping
! 		   is enabled, simulate underflow */
! 		if (uflo && (*fsr & FSR_UFM))
! 			*fsr |= FSR_UFC;
! 	}
! }

	ENTRY(__quad_mag_add)
	save	%sp,-SA(MINFRAME),%sp

	sethi	%hi(0xffff0000),%g1
	sllx	%g1,32,%g1		! g1 = 0xffff000000000000

	sethi	%hi(0x7fff),%l7
	or	%l7,%lo(0x7fff),%l7	! l7 = 0x7fff

	ldx	[%i0],%o0
	srlx	%o0,48,%l0
	andcc	%l0,%l7,%l0		! l0 = ex
	beq,pn	%icc,1f
	andn	%o0,%g1,%o0		! o0 = lx
	ba,pt	%icc,2f
	sub	%o0,%g1,%o0
1:
	mov	1,%l0
2:

	ldx	[%i1],%o1
	srlx	%o1,48,%l1
	andcc	%l1,%l7,%l1		! l1 = ey
	beq,pn	%icc,1f
	andn	%o1,%g1,%o1		! o1 = ly
	ba,pt	%icc,2f
	sub	%o1,%g1,%o1
1:
	mov	1,%l1
2:

	sub	%l0,%l1,%l1		! l1 = e = ex - ey
	cmp	%l1,114			! see if we need to prenormalize
	bge,pn	%icc,1f
	mov	0,%l6			! l6 = round
	mov	0,%o7			! o7 = sticky
	cmp	%l1,64
	bl,pt	%icc,3f
	ldx	[%i1+8],%o2		! o2 = frac
	sllx	%o2,1,%o7		! lop off high order bit
	srlx	%o2,63,%l6
	mov	%o1,%o2
	mov	0,%o1
	sub	%l1,64,%l1
3:
	tst	%l1
	beq,pn	%icc,4f
	sub	%l1,1,%l2
	mov	1,%o3
	sllx	%o3,%l2,%o3
	sub	%o3,1,%o3
	and	%o3,%o2,%o3
	or	%o3,%l6,%o3
	or	%o7,%o3,%o7
	srlx	%o2,%l2,%o4
	and	%o4,1,%l6
	srlx	%o2,%l1,%o2
	mov	64,%l3
	sub	%l3,%l1,%l3
	sllx	%o1,%l3,%o5
	or	%o2,%o5,%o2
	srlx	%o1,%l1,%o1
4:
	ldx	[%i0+8],%o3
	add	%o2,%o3,%o2		! add, propagating carry
	cmp	%o2,%o3
	bgeu,pt %xcc,5f
	add	%o0,%o1,%o0
	add	%o0,1,%o0
5:
	srlx	%o0,49,%o5		! if sum carried out, postnormalize
	tst	%o5
	beq,pt	%icc,2f
	nop
	or	%o7,%l6,%o7
	and	%o2,1,%l6
	srlx	%o2,1,%o2
	sllx	%o0,63,%o3
	or	%o2,%o3,%o2
	srlx	%o0,1,%o0
	ba,pt	%icc,2f
	add	%l0,1,%l0
1:
	ldx	[%i0+8],%o2		! (full prenormalization shift case)
	ldx	[%i1+8],%o3
	or	%o1,%o3,%o7
2:

	add	%o0,%g1,%o1		! see if sum is tiny
	srlx	%o1,63,%l2		! l2 = uflo

	ld	[%i3],%i4		! get the rounding mode
	srl	%i4,30,%l3		! l3 = rm
	ld	[%i2],%l4		! l4 = z->l.msw
	tst	%l4
	beq,pn	%icc,1f
	srl	%l3,1,%l5
	xor	%l3,%l5,%l3
1:

	orcc	%o7,%l6,%g0		! see if we need to round
	beq,pn	%xcc,1f
	andcc	%l3,1,%g0
	or	%i4,1,%i4
	bne,pn	%icc,1f
	tst	%l3
	bne,pn	%icc,2f
	tst	%l6
	beq,pn	%icc,1f
	and	%o2,1,%o3
	orcc	%o3,%o7,%g0
	beq,pn	%xcc,1f
	nop
2:
	addcc	%o2,1,%o2		! round up and check for carry out
	bne,pt	%xcc,1f
	nop
	add	%o0,1,%o0
	srlx	%o0,49,%o1
	tst	%o1
	beq,pt	%icc,1f
	nop
	srlx	%o0,1,%o0
	add	%l0,1,%l0
1:

	cmp	%l0,%l7			! check for overflow
	bge,pn	%icc,1f
	addcc	%o0,%g1,%g0
	bl,pn	%xcc,2f
	sll	%l0,16,%l1
	or	%l4,%l1,%l4
2:
	sllx	%o0,16,%o1
	srlx	%o1,48,%o1
	or	%l4,%o1,%l4
	st	%l4,[%i2]
	st	%o0,[%i2+4]
	stx	%o2,[%i2+8]
	tst	%l2			! see if we need to raise underflow
	beq,pt	%icc,3f
	srl	%i4,23,%i5
	andcc	%i5,4,%i5
	ba,pt	%icc,3f
	or	%i4,%i5,%i4

1:
	andcc	%l3,1,%g0
	bne,pn	%icc,2f
	or	%i4,9,%i4		! overflow
	sll	%l7,16,%l7		! 7fff00000...
	or	%l4,%l7,%l4
	st	%l4,[%i2]
	st	%g0,[%i2+4]
	ba,pt	%icc,3f
	stx	%g0,[%i2+8]
2:
	mov	-1,%o0			! 7ffeffff...
	sll	%l7,16,%l7
	add	%o0,%l7,%l7
	or	%l4,%l7,%l4
	st	%l4,[%i2]
	st	%o0,[%i2+4]
	stx	%o0,[%i2+8]

3:
	st	%i4,[%i3]
	ret
	restore

	SET_SIZE(__quad_mag_add)

! /*
!  * __quad_mag_sub(x, y, z, fsr)
!  *
!  * Sets *z = *x - *y, rounded according to the rounding mode in *fsr,
!  * and updates the current exceptions in *fsr.  This routine assumes
!  * *x and *y are finite, with opposite signs (i.e., a subtraction of
!  * magnitudes), |*x| >= |*y|, and *z already has its sign bit set.
!  */
! void
! __quad_mag_sub(const union longdouble *x, const union longdouble *y,
! 	union longdouble *z, unsigned int *fsr)
! {
! 	unsigned long	lx, ly, frac, sticky;
! 	unsigned int	ex, ey, gr, borrow, rm;
! 	int		e;
!
! 	/* get the leading significand double-words and exponents */
! 	ex = (x->ll.msll >> 48) & 0x7fff;
! 	lx = x->ll.msll & ~0xffff000000000000ul;
! 	if (ex == 0)
! 		ex = 1;
! 	else
! 		lx |= 0x0001000000000000ul;
!
! 	ey = (y->ll.msll >> 48) & 0x7fff;
! 	ly = y->ll.msll & ~0xffff000000000000ul;
! 	if (ey == 0)
! 		ey = 1;
! 	else
! 		ly |= 0x0001000000000000ul;
!
! 	/* prenormalize y */
! 	e = (int) ex - (int) ey;
! 	gr = sticky = 0;
! 	if (e > 114) {
! 		sticky = ly | y->ll.frac;
! 		ly = frac = 0;
! 	} else {
! 		frac = y->ll.frac;
! 		if (e >= 64) {
! 			gr = frac >> 62;
! 			sticky = frac << 2;
! 			frac = ly;
! 			ly = 0;
! 			e -= 64;
! 		}
! 		if (e > 1) {
! 			sticky |= gr | (frac & ((1ul << (e - 2)) - 1));
! 			gr = (frac >> (e - 2)) & 3;
! 			frac = (frac >> e) | (ly << (64 - e));
! 			ly >>= e;
! 		} else if (e == 1) {
! 			sticky |= (gr & 1);
! 			gr = (gr >> 1) | ((frac & 1) << 1);
! 			frac = (frac >> 1) | (ly << 63);
! 			ly >>= 1;
! 		}
! 	}
!
! 	/* complement guard, round, and sticky as need be */
! 	gr <<= 1;
! 	if (sticky)
! 		gr |= 1;
! 	gr = (-gr & 7);
!	if (gr)
!		if (++frac == 0)
!			ly++;
!
! 	/* subtract, propagating borrows */
! 	frac = x->ll.frac - frac;
! 	lx -= ly;
! 	if (frac > x->ll.frac)
! 		lx--;
!
! 	/* get the rounding mode */
! 	rm = *fsr >> 30;
!
! 	/* handle zero result */
! 	if (!(lx | frac | gr)) {
! 		z->l.msw = ((rm == FSR_RM)? 0x80000000 : 0);
! 		z->l.frac2 = z->l.frac3 = z->l.frac4 = 0;
! 		return;
! 	}
!
! 	/* postnormalize */
! 	if (lx < 0x0001000000000000ul) {
! 		/* if cancellation occurred or the exponent is 1,
! 		   the result is exact */
! 		if (lx < 0x0000800000000000ul || ex == 1) {
! 			if ((lx | (frac & 0xfffe000000000000ul)) == 0 &&
! 				ex > 64) {
! 				lx = frac;
! 				frac = (unsigned long) gr << 61;
! 				gr = 0;
! 				ex -= 64;
! 			}
! 			while (lx < 0x0001000000000000ul && ex > 1) {
! 				lx = (lx << 1) | (frac >> 63);
! 				frac = (frac << 1) | (gr >> 2);
! 				gr = 0;
! 				ex--;
! 			}
! 			if (lx >= 0x0001000000000000ul)
! 				z->l.msw |= (ex << 16);
! 			z->l.msw |= ((lx >> 32) & 0xffff);
! 			z->l.frac2 = (lx & 0xffffffff);
! 			z->ll.frac = frac;
!
! 			/* if the result is tiny and underflow trapping is
! 			   enabled, simulate underflow */
! 			if (lx < 0x0001000000000000ul && (*fsr & FSR_UFM))
! 				*fsr |= FSR_UFC;
! 			return;
! 		}
!
! 		/* otherwise we only borrowed one place */
! 		lx = (lx << 1) | (frac >> 63);
! 		frac = (frac << 1) | (gr >> 2);
! 		gr &= 3;
! 		ex--;
! 	}
! 	else
! 		gr = (gr >> 1) | (gr & 1);
!
! 	/* fudge directed rounding modes as though the result were positive */
! 	if (z->l.msw)
! 		rm ^= (rm >> 1);
!
! 	/* see if we need to round */
! 	if (gr) {
! 		*fsr |= FSR_NXC;
!
! 		/* round up if necessary */
! 		if (rm == FSR_RP || (rm == FSR_RN && (gr & 2) &&
! 			((gr & 1) || (frac & 1)))) {
! 			if (++frac == 0)
! 				if (++lx >= 0x0002000000000000ul) {
! 					lx >>= 1;
! 					ex++;
! 				}
! 		}
! 	}
!
! 	/* store the result */
! 	z->l.msw |= (ex << 16) | ((lx >> 32) & 0xffff);
! 	z->l.frac2 = (lx & 0xffffffff);
! 	z->ll.frac = frac;
! }

	ENTRY(__quad_mag_sub)
	save	%sp,-SA(MINFRAME),%sp

	sethi	%hi(0xffff0000),%g1
	sllx	%g1,32,%g1		! g1 = 0xffff000000000000

	sethi	%hi(0x7fff),%l7
	or	%l7,%lo(0x7fff),%l7	! l7 = 0x7fff

	ldx	[%i0],%o0
	srlx	%o0,48,%l0
	andcc	%l0,%l7,%l0		! l0 = ex
	beq,pn	%icc,1f
	andn	%o0,%g1,%o0		! o0 = lx
	ba,pt	%icc,2f
	sub	%o0,%g1,%o0
1:
	mov	1,%l0
2:

	ldx	[%i1],%o1
	srlx	%o1,48,%l1
	andcc	%l1,%l7,%l1		! l1 = ey
	beq,pn	%icc,1f
	andn	%o1,%g1,%o1		! o1 = ly
	ba,pt	%icc,2f
	sub	%o1,%g1,%o1
1:
	mov	1,%l1
2:

	sub	%l0,%l1,%l1		! l1 = e = ex - ey
	cmp	%l1,114			! see if we need to prenormalize y
	bg,pn	%icc,1f
	mov	0,%l6			! l6 = gr
	mov	0,%o7			! o7 = sticky
	cmp	%l1,64
	bl,pt	%icc,3f
	ldx	[%i1+8],%o2		! o2 = frac
	srlx	%o2,62,%l6
	sllx	%o2,2,%o7		! lop off top two bits
	mov	%o1,%o2
	mov	0,%o1
	sub	%l1,64,%l1
3:
	cmp	%l1,1
	ble,pn	%icc,4f
	sub	%l1,2,%l2		! shift more than one bit
	mov	1,%o3
	sllx	%o3,%l2,%o3
	sub	%o3,1,%o3
	and	%o3,%o2,%o3
	or	%o3,%l6,%o3
	or	%o7,%o3,%o7
	srlx	%o2,%l2,%o4
	and	%o4,3,%l6
	srlx	%o2,%l1,%o2
	mov	64,%l3
	sub	%l3,%l1,%l3
	sllx	%o1,%l3,%o5
	or	%o2,%o5,%o2
	ba,pt	%icc,2f
	srlx	%o1,%l1,%o1
4:
	bne,pn	%icc,2f
	and	%l6,1,%o3		! shift one bit
	or	%o7,%o3,%o7
	and	%o2,1,%o4
	sllx	%o4,1,%o4
	srl	%l6,1,%l6
	or	%l6,%o4,%l6
	srlx	%o2,1,%o2
	sllx	%o1,63,%o5
	or	%o2,%o5,%o2
	ba,pt	%icc,2f
	srlx	%o1,1,%o1
1:
	ldx	[%i1+8],%o3		! (full prenormalization shift case)
	or	%o1,%o3,%o7
	mov	0,%o1
	mov	0,%o2
2:

	tst	%o7			! complement guard, round, and
	beq,pn	%xcc,1f			! sticky as need be
	sll	%l6,1,%l6
	or	%l6,1,%l6
1:
	subcc	%g0,%l6,%l6
	beq,pn	%icc,1f
	and	%l6,7,%l6
	addcc	%o2,1,%o2
	beq,a,pn %xcc,1f
	add	%o1,1,%o1
1:

	ldx	[%i0+8],%o3		! subtract, propagating borrows
	sub	%o3,%o2,%o2
	cmp	%o3,%o2
	bgeu,pt	%xcc,5f
	sub	%o0,%o1,%o0
	sub	%o0,1,%o0
5:

	ld	[%i3],%i4		! get the rounding mode
	srl	%i4,30,%l3		! l3 = rm

	or	%o0,%o2,%o1		! look for zero result
	orcc	%o1,%l6,%g0
	bne,pt	%xcc,1f
	srl	%l3,1,%l4
	and	%l3,%l4,%l4
	sll	%l4,31,%l4
	st	%l4,[%i2]
	st	%g0,[%i2+4]
	stx	%g0,[%i2+8]
	ret
	restore

1:
	addcc	%o0,%g1,%g0		! postnormalize
	bl,pt	%xcc,1f
	ld	[%i2],%l4		! l4 = z->l.msw
	and	%l6,1,%l5		! (no cancellation or borrow case)
	srl	%l6,1,%l6
	ba,pt	%icc,2f
	or	%l6,%l5,%l6
1:
	srax	%g1,1,%o7
	addcc	%o0,%o7,%g0
	bl,pn	%xcc,1f
	cmp	%l0,1
	beq,pt	%icc,1f
	srlx	%o2,63,%o3		! borrowed one place
	sllx	%o0,1,%o0
	or	%o0,%o3,%o0
	srl	%l6,2,%o4
	sllx	%o2,1,%o2
	or	%o2,%o4,%o2
	and	%l6,3,%l6
	ba,pt	%icc,2f
	sub	%l0,1,%l0
1:
	srlx	%o2,49,%o3		! cancellation or tiny result
	orcc	%o0,%o3,%g0
	bne,pt	%xcc,1f
	cmp	%l0,64
	ble,pn	%icc,1f
	nop
	mov	%o2,%o0
	sllx	%l6,61,%o2
	mov	0,%l6
	sub	%l0,64,%l0
1:
	addcc	%o0,%g1,%g0		! normalization loop
	bge,pn	%xcc,1f
	cmp	%l0,1
	ble,pn	%icc,1f
	srl	%l6,2,%l6
	srlx	%o2,63,%o3
	sllx	%o0,1,%o0
	or	%o0,%o3,%o0
	sllx	%o2,1,%o2
	or	%o2,%l6,%o2
	ba,pt	%icc,1b
	sub	%l0,1,%l0
1:
	sllx	%o0,16,%o1
	srlx	%o1,48,%l5
	or	%l4,%l5,%l4
	addcc	%o0,%g1,%g0		! see if result is tiny
	bl,pn	%xcc,1f
	sll	%l0,16,%l5
	or	%l4,%l5,%l4
1:
	st	%l4,[%i2]
	st	%o0,[%i2+4]
	bge,pt	%xcc,1f
	stx	%o2,[%i2+8]
	srl	%i4,23,%i5
	andcc	%i5,4,%g0		! see if we need to raise underflow
	beq,pt	%icc,1f
	or	%i4,4,%i4
	st	%i4,[%i3]
1:
	ret
	restore

2:
	tst	%l4			! fudge directect rounding modes
	beq,pn	%icc,1f
	srl	%l3,1,%l5
	xor	%l3,%l5,%l3
1:

	tst	%l6			! see if we need to round
	beq,pn	%icc,1f
	or	%i4,1,%i4
	st	%i4,[%i3]
	andcc	%l3,1,%g0
	bne,pn	%icc,1f
	tst	%l3
	bne,pn	%icc,2f
	andcc	%l6,2,%g0
	beq,pn	%icc,1f
	or	%l6,%o2,%o3
	andcc	%o3,1,%o3
	beq,pn	%xcc,1f
	nop
2:
	addcc	%o2,1,%o2		! round up and check for carry
	bne,pt	%xcc,1f
	nop
	add	%o0,1,%o0
	srlx	%o0,49,%o1
	tst	%o1
	beq,pt	%icc,1f
	nop
	srlx	%o0,1,%o0
	add	%l0,1,%l0
1:

	sllx	%o0,16,%o1
	srlx	%o1,48,%o1
	or	%l4,%o1,%l4
	sll	%l0,16,%l5
	or	%l4,%l5,%l4
	st	%l4,[%i2]
	st	%o0,[%i2+4]
	stx	%o2,[%i2+8]
	ret
	restore

	SET_SIZE(__quad_mag_sub)
