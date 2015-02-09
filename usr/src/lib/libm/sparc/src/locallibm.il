!
! CDDL HEADER START
!
! The contents of this file are subject to the terms of the
! Common Development and Distribution License (the "License").
! You may not use this file except in compliance with the License.
!
! You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
! or http://www.opensolaris.org/os/licensing.
! See the License for the specific language governing permissions
! and limitations under the License.
!
! When distributing Covered Code,  this CDDL HEADER in each
! file and  the License file at usr/src/OPENSOLARIS.LICENSE.
! If applicable, add the following below this CDDL HEADER, with the
! fields enclosed by brackets "[]" replaced with your own identifying
! information: Portions Copyright [yyyy] [name of copyright owner]
!
! CDDL HEADER END
!
! Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
!
! Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
! Use is subject to license terms.
!

! Portions of this file are duplicated as GCC inline assembly in
! libm_inlines.h.  Keep them in sync.

 	.inline	__r_hypot_,2
	ld	[%o0],%o4
	sethi	0x1fffff,%o5
	or	%o5,1023,%o5
	and	%o4,%o5,%o4
	sethi	0x1fe000,%o3
	cmp	%o4,%o3
	ld	[%o0],%f0	! load result with first argument
	bne	2f
	nop
	fabss	%f0,%f0
	ld	[%o1],%f1
	.volatile
	fcmps	%f0,%f1		! generate invalid for Snan
	.nonvolatile
	nop
	fba	5f
	nop
2:
	ld	[%o1],%o4
	sethi	0x1fffff,%o5
	or	%o5,1023,%o5
	and	%o4,%o5,%o4
	sethi	0x1fe000,%o3
	cmp	%o4,%o3
	bne	4f
	nop
	ld	[%o1],%f0	! second argument inf
	fabss	%f0,%f0
	ld	[%o0],%f1
	.volatile
	fcmps	%f0,%f1		! generate invalid for Snan
	.nonvolatile
	nop
	fba	5f
	nop
4:
	ld	[%o1],%f3
	fsmuld	%f0,%f0,%f0
	fsmuld	%f3,%f3,%f2
	faddd	%f2,%f0,%f0
	fsqrtd	%f0,%f0
	fdtos	%f0,%f0
5:
	.end

	.inline	__c_abs,1
	ld	[%o0],%o4
	sethi	0x1fffff,%o5
	or	%o5,1023,%o5
	and	%o4,%o5,%o4
	sethi	0x1fe000,%o3
	cmp	%o4,%o3
	ld	[%o0],%f0
	bne	2f
	nop
	fabss	%f0,%f0
	ld	[%o0+4],%f1
	.volatile
	fcmps	%f0,%f1		! generate invalid for Snan
	.nonvolatile
	nop
	fba	5f
	nop
2:
	ld	[%o0+4],%o4
	sethi	0x1fffff,%o5
	or	%o5,1023,%o5
	and	%o4,%o5,%o4
	sethi	0x1fe000,%o3
	cmp	%o4,%o3
	bne	4f
	nop
	ld	[%o0+4],%f0
	fabss	%f0,%f0
	ld	[%o0],%f1
	.volatile
	fcmps	%f0,%f1		! generate invalid for Snan
	.nonvolatile
	nop
	fba	5f
	nop
! store to 8-aligned address
4:
	ld	[%o0+4],%f3
	fsmuld	%f0,%f0,%f0
	fsmuld	%f3,%f3,%f2
	faddd	%f2,%f0,%f0
	fsqrtd	%f0,%f0
	fdtos	%f0,%f0
5:
	.end
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fc_mult(c, a, b)
! complex *c, *a, *b;
! {

	.inline	__Fc_mult,3
!    21		c->real = (a->real *  b->real) - (a->imag *  b->imag)
	ld	[%o1+4],%f0	! f0 = a->imag
	ld	[%o2+4],%f1	! f1 = b->imag
	ld	[%o1],%f2	! f2 = a->real
	fsmuld	 %f0,%f1,%f4	 ! f4 = (a->imag *  b->imag)
	ld	[%o2],%f3	! f3 = b->real
	fsmuld	 %f2,%f1,%f6	! f6 = a->real * b->imag
	fsmuld	 %f2,%f3,%f8	! f8 =	a->real * b->real
	fsmuld	 %f0,%f3,%f10	! f10 = a->imag * b->real
	fsubd	%f8,%f4,%f0	! f0 =	ar*br - ai*bi
	faddd	%f6,%f10,%f2	! f2 = ai*br + ar*bi
	fdtos	%f0,%f4
	fdtos	%f2,%f6
	st	%f4,[%o0]
	st	%f6,[%o0+4]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fc_div(c, a, b)
! complex *c, *a, *b;
! {
	.inline	__Fc_div,3
	ld	[%o2+4],%o3
	sethi	%hi(0x7fffffff),%o4
	or	%o4,%lo(0x7fffffff),%o4 ! [internal]
	andcc	%o3,%o4,%g0
	ld	[%o2],%f6		! f6 gets reb
	bne	1f
	nop
	ld	[%o1],%f0
	ld	[%o2],%f1
	fdivs	%f0,%f1,%f0
	st	%f0,[%o0]
	ld	[%o1+4],%f3
	fdivs	%f3,%f1,%f3
	st	%f3,[%o0+4]
	ba	2f
	nop
1:					! [internal]
	sethi	%hi(0x3ff00000),%o4
	or	%g0,0,%o5
	std	%o4,[%sp+0x48]
	ldd	[%sp+0x48],%f8
	ld	[%o2+4],%f10		! f10 gets imb
	fsmuld	%f6,%f6,%f16		! f16/17 gets reb**2
	ld	[%o1+4],%f4		! f4 gets ima
	fsmuld	%f10,%f10,%f12		! f12/13 gets imb**2
	ld	[%o1],%f19		! f19 gets rea
	fsmuld	%f4,%f10,%f0		! f0/f1 gets ima*imb
	fsmuld	%f19,%f6,%f2		! f2/3 gets rea*reb
	faddd	%f12,%f16,%f12		! f12/13 gets reb**2+imb**2
	fdivd	%f8,%f12,%f12		! f12/13 gets 1/(reb**2+imb**2)
	faddd	%f2,%f0,%f2		! f2/3 gets rea*reb+ima*imb
	fsmuld	%f4,%f6,%f24		! f24/5 gets ima*reb
	fmuld	%f2,%f12,%f2		! f2/3 gets rec
	fsmuld	%f19,%f10,%f10		! f10/11 gets rea*imb
	fsubd	%f24,%f10,%f10		! f10/11 gets ima*reb-rea*imb
	fmuld	%f10,%f12,%f12		! f12 gets imc
	fdtos	%f2,%f7			! f7 gets rec
	fdtos	%f12,%f15		! f15 gets imc
	st	%f7,[%o0]
	st	%f15,[%o0+4]
2:
	.end
! }

	.inline	.mul,2
	.volatile
	smul	%o0,%o1,%o0
	rd	%y,%o1
	sra	%o0,31,%o2
	cmp	%o1,%o2
	.nonvolatile
	.end

	.inline	.umul,2
	.volatile
	umul	%o0,%o1,%o0
	rd	%y,%o1
	tst	%o1
	.nonvolatile
	.end

	.inline	.div,2
	sra	%o0,31,%o4	! extend sign
	.volatile
	wr	%o4,%g0,%y
	cmp	%o1,0xffffffff	! is divisor -1?
	be,a	1f		! if yes
	.volatile
	subcc	%g0,%o0,%o0	! simply negate dividend
	nop			! RT620 FABs A.0/A.1
	sdiv	%o0,%o1,%o0	! o0 contains quotient a/b
	.nonvolatile
1:
	.end

	.inline	.udiv,2
	.volatile
	wr	%g0,%g0,%y
	nop
	nop
	nop
	udiv	%o0,%o1,%o0	! o0 contains quotient a/b
	.nonvolatile
	.end

	.inline	.rem,2
	sra	%o0,31,%o4	! extend sign
	.volatile
	wr	%o4,%g0,%y
	cmp	%o1,0xffffffff	! is divisor -1?
	be,a	1f		! if yes
	.volatile
	or	%g0,%g0,%o0	! simply return 0
	nop			! RT620 FABs A.0/A.1
	sdiv	%o0,%o1,%o2	! o2 contains quotient a/b
	.nonvolatile
	smul	%o2,%o1,%o4	! o4 contains q*b
	sub	%o0,%o4,%o0	! o0 gets a-q*b
1:
	.end

	.inline	.urem,2
	.volatile
	wr	%g0,%g0,%y
	nop
	nop
	nop
	udiv	%o0,%o1,%o2	! o2 contains quotient a/b
	.nonvolatile
	umul	%o2,%o1,%o4	! o4 contains q*b
	sub	%o0,%o4,%o0	! o0 gets a-q*b
	.end

	.inline	.div_o3,2
	sra	%o0,31,%o4	! extend sign
	.volatile
	wr	%o4,%g0,%y
	cmp	%o1,0xffffffff	! is divisor -1?
	be,a	1f		! if yes
	.volatile
	subcc	%g0,%o0,%o0	! simply negate dividend
	mov	%o0,%o3		! o3 gets __remainder
	sdiv	%o0,%o1,%o0	! o0 contains quotient a/b
	.nonvolatile
	smul	%o0,%o1,%o4	! o4 contains q*b
	ba	2f
	sub	%o3,%o4,%o3	! o3 gets a-q*b
1:
	mov	%g0,%o3		! __remainder is 0
2:
	.end

	.inline	.udiv_o3,2
	.volatile
	wr	%g0,%g0,%y
	mov	%o0,%o3		! o3 gets __remainder
	nop
	nop
	udiv	%o0,%o1,%o0	! o0 contains quotient a/b
	.nonvolatile
	umul	%o0,%o1,%o4	! o4 contains q*b
	sub	%o3,%o4,%o3	! o3 gets a-q*b
	.end

	.inline	__ieee754_sqrt,2
	std	%o0,[%sp+0x48]		! store to 8-aligned address
	ldd	[%sp+0x48],%f0
	fsqrtd	%f0,%f0
	.end

	.inline	__inline_sqrtf,1
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	fsqrts	%f0,%f0
	.end

	.inline	__inline_sqrt,2
	std	%o0,[%sp+0x48]		! store to 8-aligned address
	ldd	[%sp+0x48],%f0
	fsqrtd	%f0,%f0
	.end

	.inline	sqrtf,1
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	fsqrts	%f0,%f0
	.end

	.inline	sqrt,2
	std	%o0,[%sp+0x48]		! store to 8-aligned address
	ldd	[%sp+0x48],%f0
	fsqrtd	%f0,%f0
	.end

	.inline	__r_sqrt_,1
	ld	[%o0],%f0
	fsqrts	%f0,%f0
	.end

	.inline	__d_sqrt_,1
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	fsqrtd	%f0,%f0
	.end

	.inline	__ceil,2
	std	%o0,[%sp+0x48]
	sethi	%hi(0x80000000),%o5
	andn	%o0,%o5,%o2
	sethi	%hi(0x43300000),%o3
	st	%g0,[%sp+0x54]
	subcc	%o2,%o3,%g0
	bl	1f
	nop
	sethi	%hi(0x3ff00000),%o2
	st	%o2,[%sp+0x50]
	ldd	[%sp+0x48],%f0
	ldd	[%sp+0x50],%f2
	fmuld	%f0,%f2,%f0
	ba	4f
	nop
1:
	tst	%o0
	st	%o3,[%sp+0x50]
	ldd	[%sp+0x50],%f2
	bge	2f
	nop
	fnegs	%f2,%f2
2:
	ldd	[%sp+0x48],%f4
	faddd	%f4,%f2,%f0
	fsubd	%f0,%f2,%f0
	fcmpd	%f0,%f4
	sethi	%hi(0x3ff00000),%o2
	st	%o2,[%sp+0x50]
	and	%o0,%o5,%o4
	fbge	3f
	nop
	ldd	[%sp+0x50],%f4
	faddd	%f0,%f4,%f0
3:
	st	%f0,[%sp+0x48]
	ld	[%sp+0x48],%o3
	andn	%o3,%o5,%o3
	or	%o4,%o3,%o3
	st	%o3,[%sp+0x48]
	ld	[%sp+0x48],%f0
4:
	.end

	.inline	__floor,2
	std	%o0,[%sp+0x48]
	sethi	%hi(0x80000000),%o5
	andn	%o0,%o5,%o2
	sethi	%hi(0x43300000),%o3
	st	%g0,[%sp+0x54]
	subcc	%o2,%o3,%g0
	bl	1f
	nop
	sethi	%hi(0x3ff00000),%o2
	st	%o2,[%sp+0x50]
	ldd	[%sp+0x48],%f0
	ldd	[%sp+0x50],%f2
	fmuld	%f0,%f2,%f0
	ba	4f
	nop
1:
	tst	%o0
	st	%o3,[%sp+0x50]
	ldd	[%sp+0x50],%f2
	bge	2f
	nop
	fnegs	%f2,%f2
2:
	ldd	[%sp+0x48],%f4
	faddd	%f4,%f2,%f0
	fsubd	%f0,%f2,%f0
	fcmpd	%f0,%f4
	sethi	%hi(0x3ff00000),%o2
	st	%o2,[%sp+0x50]
	ldd	[%sp+0x50],%f4
	and	%o0,%o5,%o4
	fble	3f
	nop
	fsubd	%f0,%f4,%f0
3:
	st	%f0,[%sp+0x48]
	ld	[%sp+0x48],%o3
	andn	%o3,%o5,%o3
	or	%o4,%o3,%o3
	st	%o3,[%sp+0x48]
	ld	[%sp+0x48],%f0
4:
	.end

	.inline	__ilogb,2
	sethi	%hi(0x7ff00000),%o4
	andcc	%o4,%o0,%o2
	bne	1f
	nop
	sethi	%hi(0x43500000),%o3
	std	%o0,[%sp+0x48]
	st	%o3,[%sp+0x50]
	st	%g0,[%sp+0x54]
	ldd	[%sp+0x48],%f0
	ldd	[%sp+0x50],%f2
	fmuld	%f0,%f2,%f0
	sethi	%hi(0x80000001),%o0
	or	%o0,%lo(0x80000001),%o0
	st	%f0,[%sp+0x48]
	ld	[%sp+0x48],%o2
	andcc	%o2,%o4,%o2
	srl	%o2,20,%o2
	be	2f
	nop
	sub	%o2,0x435,%o0
	ba	2f
	nop
1:
	subcc	%o4,%o2,%g0
	srl	%o2,20,%o3
	bne	0f
	nop
	sethi	%hi(0x7fffffff),%o0
	or	%o0,%lo(0x7fffffff),%o0
	ba	2f
	nop
0:
	sub	%o3,0x3ff,%o0
2:
	.end

	.inline	__rint,2
	std	%o0,[%sp+0x48]
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o2
	ldd	[%sp+0x48],%f0
	sethi	%hi(0x43300000),%o3
	st	%g0,[%sp+0x50]
	st	%g0,[%sp+0x54]
	subcc	%o2,%o3,%g0
	bl	1f
	nop
	sethi	%hi(0x3ff00000),%o2
	st	%o2,[%sp+0x50]
	ldd	[%sp+0x50],%f2
	fmuld	%f0,%f2,%f0
	ba	3f
	nop
1:
	tst	%o0
	st	%o3,[%sp+0x48]
	st	%g0,[%sp+0x4c]
	ldd	[%sp+0x48],%f2
	bge	2f
	nop
	fnegs	%f2,%f2
2:
	faddd	%f0,%f2,%f0
	fcmpd	%f0,%f2
	fbne	0f
	nop
	ldd	[%sp+0x50],%f0
	bge	3f
	nop
	fnegs	%f0,%f0
	ba	3f
	nop
0:
	fsubd	%f0,%f2,%f0
3:
	.end

	.inline	__rintf,1
	st	%o0,[%sp+0x48]
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o2
	ld	[%sp+0x48],%f0
	sethi	%hi(0x4b000000),%o3
	st	%g0,[%sp+0x50]
	subcc	%o2,%o3,%g0
	bl	1f
	nop
	sethi	%hi(0x3f800000),%o2
	st	%o2,[%sp+0x50]
	ld	[%sp+0x50],%f2
	fmuls	%f0,%f2,%f0
	ba	3f
	nop
1:
	tst	%o0
	st	%o3,[%sp+0x48]
	ld	[%sp+0x48],%f2
	bge	2f
	nop
	fnegs	%f2,%f2
2:
	fadds	%f0,%f2,%f0
	fcmps	%f0,%f2
	fbne	0f
	nop
	ld	[%sp+0x50],%f0
	bge	3f
	nop
	fnegs	%f0,%f0
	ba	3f
	nop
0:
	fsubs	%f0,%f2,%f0
3:
	.end

	.inline	__min_subnormal,0
	set	0x0,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0x1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__d_min_subnormal_,0
	set	0x0,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0x1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__min_subnormalf,0
	set	0x1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_min_subnormal_,0
	set	0x1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__max_subnormal,0
	set	0x000fffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0xffffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__d_max_subnormal_,0
	set	0x000fffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0xffffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__max_subnormalf,0
	set	0x007fffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_max_subnormal_,0
	set	0x007fffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__min_normal,0
        set     0x00100000,%o0
        set     0x0,%o1
        std     %o0,[%sp+0x48]
        ldd     [%sp+0x48],%f0
	.end

	.inline	__d_min_normal_,0
	set	0x00100000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0x0,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__min_normalf,0
	set	0x00800000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_min_normal_,0
	set	0x00800000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__max_normal,0
        set     0x7fefffff,%o0
        set     0xffffffff,%o1
        std     %o0,[%sp+0x48]
        ldd     [%sp+0x48],%f0
	.end

	.inline	__d_max_normal_,0
	set	0x7fefffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0xffffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__max_normalf,0
	set	0x7f7fffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_max_normal_,0
	set	0x7f7fffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__infinity,0
        set      0x7ff00000,%o0
        set      0x0,%o1
        std      %o0,[%sp+0x48]
        ldd      [%sp+0x48],%f0
        .end

	.inline	__infinity,0
        set      0x7ff00000,%o0
        set      0x0,%o1
        std      %o0,[%sp+0x48]
        ldd      [%sp+0x48],%f0
        .end

	.inline	__d_infinity_,0
	set	0x7ff00000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0x0,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__infinityf,0
	set	0x7f800000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_infinity_,0
	set	0x7f800000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__signaling_nan,0
        set     0x7ff00000,%o0
        set     0x1,%o1
        std     %o0,[%sp+0x48]
        ldd     [%sp+0x48],%f0
	.end

	.inline	__d_signaling_nan_,0
	set	0x7ff00000,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0x1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__signaling_nanf,0
	set	0x7f800001,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_signaling_nan_,0
	set	0x7f800001,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__quiet_nan,0
	set	0x7fffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0xffffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__d_quiet_nan_,0
	set	0x7fffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	set	0xffffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f1
	.end

	.inline	__quiet_nanf,0
	set	0x7fffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_quiet_nan_,0
	set	0x7fffffff,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__swapEX,1
	and     %o0,0x1f,%o1
	sll     %o1,5,%o1               ! shift input to aexc bit location
	.volatile
	st      %fsr,[%sp+0x44]
	ld      [%sp+0x44],%o0          ! o0 = fsr
	andn    %o0,0x3e0,%o2
	or      %o1,%o2,%o1             ! o1 = new fsr
	st      %o1,[%sp+0x44]
	ld      [%sp+0x44],%fsr
	srl     %o0,5,%o0
	and     %o0,0x1f,%o0
	.nonvolatile
	.end

	.inline	_QgetRD,0
	st	%fsr,[%sp+0x44]
	ld	[%sp+0x44],%o0		! o0 = fsr
	srl	%o0,30,%o0		! return __round control value
	.end

	.inline	_QgetRP,0
	or	%g0,%g0,%o0
	.end

	.inline	__swapRD,1
	and	%o0,0x3,%o0
	sll     %o0,30,%o1              ! shift input to RD bit location
	.volatile
	st      %fsr,[%sp+0x44]
	ld      [%sp+0x44],%o0          ! o0 = fsr
	set     0xc0000000,%o4          ! mask of rounding direction bits
	andn    %o0,%o4,%o2
	or      %o1,%o2,%o1             ! o1 = new fsr
	st      %o1,[%sp+0x44]
	ld      [%sp+0x44],%fsr
	srl     %o0,30,%o0
	and     %o0,0x3,%o0
	.nonvolatile
	.end
!
! On the SPARC, __swapRP is a no-op; always return 0 for backward compatibility
!

	.inline	__swapRP,1
	or	%g0,%g0,%o0
	.end

	.inline	__swapTE,1
	and	%o0,0x1f,%o0
	sll     %o0,23,%o1              ! shift input to TEM bit location
	.volatile
	st      %fsr,[%sp+0x44]
	ld      [%sp+0x44],%o0            ! o0 = fsr
	set     0x0f800000,%o4          ! mask of TEM (Trap Enable Mode bits)
	andn    %o0,%o4,%o2
	or      %o1,%o2,%o1             ! o1 = new fsr
	st      %o1,[%sp+0x48]
	ld      [%sp+0x48],%fsr
	srl     %o0,23,%o0
	and     %o0,0x1f,%o0
	.nonvolatile
	.end

	.inline	fp_class,2
	sethi	%hi(0x80000000),%o2	! o2 gets 80000000
	andn	%o0,%o2,%o0		! o0-o1 gets abs(x)
	orcc	%o0,%o1,%g0		! set cc as x is zero/nonzero
	bne	1f			! branch if x is nonzero
	nop
	mov	0,%o0
	ba	2f			! x is 0
	nop
1:
	sethi	%hi(0x7ff00000),%o2	! o2 gets 7ff00000
	andcc	%o0,%o2,%g0		! cc set by __exp field of x
	bne	1f			! branch if normal or max __exp
	nop
	mov	1,%o0
	ba	2f			! x is subnormal
	nop
1:
	cmp	%o0,%o2
	bge	1f			! branch if x is max __exp
	nop
	mov	2,%o0
	ba	2f			! x is normal
	nop
1:
	andn	%o0,%o2,%o0		! o0 gets msw __significand field
	orcc	%o0,%o1,%g0		! set cc by OR __significand
	bne	1f			! Branch if __nan
	nop
	mov	3,%o0
	ba	2f			! x is __infinity
	nop
1:
	sethi	%hi(0x00080000),%o2
	andcc	%o0,%o2,%g0		! set cc by quiet/sig bit
	be	1f			! Branch if signaling
	nop
	mov	4,%o0			! x is quiet NaN
	ba	2f
	nop
1:
	mov	5,%o0			! x is signaling NaN
2:
	.end

	.inline	fp_classf,1
	sethi	%hi(0x80000000),%o2
	andncc	%o0,%o2,%o0
	bne	1f
	nop
	mov	0,%o0
	ba	2f			! x is 0
	nop
1:
	sethi	%hi(0x7f800000),%o2
	andcc	%o0,%o2,%g0
	bne	1f
	nop
	mov	1,%o0
	ba	2f			! x is subnormal
	nop
1:
	cmp	%o0,%o2
	bge	1f
	nop
	mov	2,%o0
	ba	2f			! x is normal
	nop
1:
	bg	1f
	nop
	mov	3,%o0
	ba	2f			! x is __infinity
	nop
1:
	sethi	%hi(0x00400000),%o2
	andcc	%o0,%o2,%g0
	mov	4,%o0			! x is quiet NaN
	bne	2f
	nop
	mov	5,%o0			! x is signaling NaN
2:
	.end

	.inline	__ir_fp_class_,1
	ld	[%o0],%o0
	sethi	%hi(0x80000000),%o2
	andncc	%o0,%o2,%o0
	bne	1f
	nop
	mov	0,%o0
	ba	2f			! x is 0
	nop
1:
	sethi	%hi(0x7f800000),%o2
	andcc	%o0,%o2,%g0
	bne	1f
	nop
	mov	1,%o0
	ba	2f			! x is subnormal
	nop
1:
	cmp	%o0,%o2
	bge	1f
	nop
	mov	2,%o0
	ba	2f			! x is normal
	nop
1:
	bg	1f
	nop
	mov	3,%o0
	ba	2f			! x is __infinity
	nop
1:
	sethi	%hi(0x00400000),%o2
	andcc	%o0,%o2,%g0
	mov	4,%o0			! x is quiet NaN
	bne	2f
	nop
	mov	5,%o0			! x is signaling NaN
2:
	.end

	.inline	__copysign,4
        set     0x80000000,%o3
        and     %o2,%o3,%o2
        andn    %o0,%o3,%o0
        or      %o0,%o2,%o0
        std      %o0,[%sp+0x48]
        ldd     [%sp+0x48],%f0
        .end

	.inline	__copysignf,2
	set	0x80000000,%o2
	andn	%o0,%o2,%o0
	and	%o1,%o2,%o1
	or	%o0,%o1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	__r_copysign_,2
	ld	[%o0],%o0
	ld	[%o1],%o1
	set	0x80000000,%o2
	andn	%o0,%o2,%o0
	and	%o1,%o2,%o1
	or	%o0,%o1,%o0
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	.end

	.inline	_finite,2
	set	0x7ff00000,%o1
	and	%o0,%o1,%o0
	cmp	%o0,%o1
	mov	1,%o0
	bne	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	__finitef,2
	set	0x7f800000,%o1
	and	%o0,%o1,%o0
	cmp	%o0,%o1
	mov	1,%o0
	bne	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	__ir_finite_,1
	ld	[%o0],%o0
	set	0x7f800000,%o1
	and	%o0,%o1,%o0
	cmp	%o0,%o1
	mov	1,%o0
	bne	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	__signbit,1
	srl	%o0,31,%o0
	.end

	.inline	__signbitf,1
	srl	%o0,31,%o0
	.end

	.inline	__ir_signbit_,1
	ld	[%o0],%o0
	srl	%o0,31,%o0
	.end

	.inline	__isinf,2
	tst	%o1
	sethi	%hi(0x80000000),%o2
	bne	1f
	nop
	andn	%o0,%o2,%o0
	sethi	%hi(0x7ff00000),%o2
	cmp	%o0,%o2
	mov	1,%o0
	be	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__isinff,1
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0		! o0 gets abs(x)
	sethi	%hi(0x7f800000),%o2
	cmp	%o0,%o2
	mov	0,%o0
	bne	1f			! Branch if not inf.
	nop
	mov	1,%o0
1:
	.end

	.inline	__ir_isinf_,1
	ld	[%o0],%o0
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0		! o0 gets abs(x)
	sethi	%hi(0x7f800000),%o2
	cmp	%o0,%o2
	mov	0,%o0
	bne	1f			! Branch if not inf.
	nop
	mov	1,%o0
1:
	.end

	.inline	__isnan,2
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sub	%g0,%o1,%o3
	or	%o1,%o3,%o1
	srl	%o1,31,%o1
	or	%o0,%o1,%o0
	sethi	%hi(0x7ff00000),%o4
	sub	%o4,%o0,%o0
	srl	%o0,31,%o0
	.end

	.inline	__isnanf,1
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sethi	%hi(0x7f800000),%o1
	sub	%o1,%o0,%o0
	srl	%o0,31,%o0
	.end

	.inline	__ir_isnan_,1
	ld	[%o0],%o0
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sethi	%hi(0x7f800000),%o1
	sub	%o1,%o0,%o0
	srl	%o0,31,%o0
	.end

	.inline	__isnormal,2
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sethi	%hi(0x7ff00000),%o2
	cmp	%o0,%o2
	sethi	%hi(0x00100000),%o2
	bge	1f
	nop
	cmp	%o0,%o2
	mov	1,%o0
	bge	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__isnormalf,1
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sethi	%hi(0x7f800000),%o2
	cmp	%o0,%o2
	sethi	%hi(0x00800000),%o2
	bge	1f
	nop
	cmp	%o0,%o2
	mov	1,%o0
	bge	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__ir_isnormal_,1
	ld	[%o0],%o0
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sethi	%hi(0x7f800000),%o2
	cmp	%o0,%o2
	sethi	%hi(0x00800000),%o2
	bge	1f
	nop
	cmp	%o0,%o2
	mov	1,%o0
	bge	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__issubnormal,2
	sethi	%hi(0x80000000),%o2	! o2 gets 80000000
	andn	%o0,%o2,%o0		! o0/o1 gets abs(x)
	sethi	%hi(0x00100000),%o2	! o2 gets 00100000
	cmp	%o0,%o2
	bge	1f			! branch if x norm or max __exp
	nop
	orcc	%o0,%o1,%g0
	be	1f			! Branch if x zero
	nop
	mov	1,%o0			! x is subnormal
	ba	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__issubnormalf,1
	sethi	%hi(0x80000000),%o2	! o2 gets 80000000
	andn	%o0,%o2,%o0		! o0 gets abs(x)
	sethi	%hi(0x00800000),%o2	! o2 gets 00800000
	cmp	%o0,%o2
	bge	1f			! branch if x norm or max __exp
	nop
	orcc	%o0,%g0,%g0
	be	1f			! Branch if x zero
	nop
	mov	1,%o0			! x is subnormal
	ba	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__ir_issubnormal_,1
	ld	[%o0],%o0
	sethi	%hi(0x80000000),%o2	! o2 gets 80000000
	andn	%o0,%o2,%o0		! o0 gets abs(x)
	sethi	%hi(0x00800000),%o2	! o2 gets 00800000
	cmp	%o0,%o2
	bge	1f			! branch if x norm or max __exp
	nop
	orcc	%o0,%g0,%g0
	be	1f			! Branch if x zero
	nop
	mov	1,%o0			! x is subnormal
	ba	2f
	nop
1:
	mov	0,%o0
2:
	.end

	.inline	__iszero,2
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	orcc	%o0,%o1,%g0
	mov	1,%o0
	be	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	__iszerof,1
	sethi	%hi(0x80000000),%o2
	andncc	%o0,%o2,%o0
	mov	1,%o0
	be	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	__ir_iszero_,1
	ld	[%o0],%o0
	sethi	%hi(0x80000000),%o2
	andncc	%o0,%o2,%o0
	mov	1,%o0
	be	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	abs,1
	sra	%o0,31,%o1
	xor	%o0,%o1,%o0
        sub	%o0,%o1,%o0
        .end

	.inline	fabs,2
	st	%o0,[%sp+0x48]
	st	%o1,[%sp+0x4c]
	ldd	[%sp+0x48],%f0
	fabsd	%f0,%f0
	.end

	.inline	fabsf,1
	st	%o0,[%sp+0x44]
	ld	[%sp+0x44],%f0
	fabss	%f0,%f0
	.end

	.inline	__r_fabs_,1
	ld	[%o0],%f0
	fabss	%f0,%f0
	.end
!
!	__nintf - f77 NINT(REAL*4)
!

	.inline	__nintf,1
	srl	%o0,30-7,%g1
	sethi	%hi(0x7fffff),%o2
	st	%o0,[%sp+0x44]
	and	%g1,0xff,%g1
	or	%o2,%lo(0x7fffff),%o2
	sethi	%hi(1<<22),%o4
	subcc	%g1,127+31,%g0
	and	%o0,%o2,%o3
	bl	0f
	nop
	sethi	%hi(0xcf000000),%o2
	sethi	%hi(0x80000000),%g1
	subcc	%o0,%o2,%g0
	or	%g1,%g0,%o0
	be	9f
	nop
	ld	[%sp+0x44],%f0
	fstoi	%f0,%f0
	st	%f0,[%sp+0x44]
	ld	[%sp+0x44],%o0
	ba	9f
	nop
0:
	add	%o4,%o4,%o5
	or	%o3,%o5,%o3
	sra	%o0,31-0,%o2
	subcc	%g1,127,%g1
	srl	%o4,%g1,%o4
	bge	1f
	nop
	subcc	%g1,-1,%g0
	or	%g0,0,%o0
	bne	2f
	nop
	or	%g0,1,%o0
	ba	2f
	nop
1:
	add	%o3,%o4,%o3
	or	%g0,23,%o0
	subcc	%o0,%g1,%o0
	bl	1f
	nop
	srl	%o3,%o0,%o0
	ba	2f
	nop
1:
	sub	%g0,%o0,%o0
	sll	%o3,%o0,%o0
2:
	xor	%o0,%o2,%o0
	and	%o2,1,%o2
	add	%o0,%o2,%o0
9:
	.end

	.inline	__il_nint,1
	ld	[%o0],%o0
	sra	%o0,0,%o0
	srlx	%o0,31-8,%g1
	or	%g0,1,%o2
	sllx	%o2,23-1,%o4
	and	%g1,0xff,%g1
	sllx	%o2,63-0,%o2
	subcc	%g1,127+63,%g0
	bl	0f
	nop
	st	%o0,[%sp+0x48]
	ld	[%sp+0x48],%f0
	fstox	%f0,%f0
	std	%f0,[%sp+0x48]
	ldx	[%sp+0x48],%o1
	ba	9f
	nop
0:
	add	%o4,%o4,%o5
	srax	%o2,63-23,%o2
	sub	%g1,127+23,%o1
	xnor	%o2,%g0,%o2
	and	%o0,%o2,%o3
	or	%o3,%o5,%o3
	srax	%o0,63-0,%o2
	subcc	%g1,127,%g1
	bge	1f
	nop
	subcc	%g1,-1,%g0
	or	%g0,0,%o0
	bne	2f
	nop
	or	%g0,1,%o0
	ba	2f
	nop
1:
	brlz,pt	%o1,3f
	nop
	sub	%g1,23,%o0
	sllx	%o3,%o0,%o0
	ba	2f
	nop
3:
	srlx	%o4,%g1,%o4
	add	%o3,%o4,%o3
	or	%g0,23,%o0
	sub	%o0,%g1,%o0
	srlx	%o3,%o0,%o0
2:
	xor	%o0,%o2,%o0
	sub	%o0,%o2,%o1
9:
	srlx	%o1,32,%o0
	.end
!
!	__i_dnnt - f77 NINT(REAL*8)
!

	.inline	__i_dnnt,1
	ld	[%o0],%o1
	sllx	%o1,32,%o1
	ld	[%o0+4],%o0
	or	%o0,%o1,%o0
	srlx	%o0,63-11,%g1
	or	%g0,1,%o2
	stx	%o0,[%sp+0x48]
	sllx	%o2,52-1,%o4
	and	%g1,0x7ff,%g1
	sllx	%o2,63-0,%o2
	subcc	%g1,1023+32,%g0
	bl	0f
	nop
	ldd	[%sp+0x48],%f0
	ba	8f
	nop
0:
	add	%o4,%o4,%o5
	srax	%o2,63-52,%o2
	sub	%g1,1023+30,%o1
	xnor	%o2,%g0,%o2
	and	%o0,%o2,%o3
	or	%o3,%o5,%o3
	srax	%o0,63-0,%o2
	subcc	%g1,1023,%g1
	bge	1f
	nop
	subcc	%g1,-1,%g0
	or	%g0,0,%o0
	bne	2f
	nop
	or	%g0,1,%o0
	ba	2f
	nop
1:
	srlx	%o4,%g1,%o4
	add	%o3,%o4,%o3
	or	%g0,52,%o0
	sub	%o0,%g1,%o0
	srlx	%o3,%o0,%o0
2:
	xor	%o0,%o2,%o0
	sub	%o0,%o2,%o0
	brlz,pt	%o1,9f
	nop
	stx	%o0,[%sp+0x48]
	ldd	[%sp+0x48],%f0
	fxtod	%f0,%f0
8:
	fdtoi	%f0,%f0
	st	%f0,[%sp+0x44]
	ld	[%sp+0x44],%o0
9:
	.end

	.inline	__il_dnnt,1
	ld	[%o0],%o1
	sllx	%o1,32,%o1
	ld	[%o0+4],%o0
	or	%o0,%o1,%o0
	srlx	%o0,63-11,%g1
	or	%g0,1,%o2
	sllx	%o2,52-1,%o4
	and	%g1,0x7ff,%g1
	sllx	%o2,63-0,%o2
	subcc	%g1,1023+63,%g0
	bl	0f
	nop
	stx	%o0,[%sp+0x48]
	ldd	[%sp+0x48],%f0
	fdtox	%f0,%f0
	std	%f0,[%sp+0x48]
	ldx	[%sp+0x48],%o1
	ba	9f
	nop
0:
	add	%o4,%o4,%o5
	srax	%o2,63-52,%o2
	sub	%g1,1023+52,%o1
	xnor	%o2,%g0,%o2
	and	%o0,%o2,%o3
	or	%o3,%o5,%o3
	srax	%o0,63-0,%o2
	subcc	%g1,1023,%g1
	bge	1f
	nop
	subcc	%g1,-1,%g0
	or	%g0,0,%o0
	bne	2f
	nop
	or	%g0,1,%o0
	ba	2f
	nop
1:
	brlz,pt	%o1,3f
	nop
	sub	%g1,52,%o0
	sllx	%o3,%o0,%o0
	ba	2f
	nop
3:
	srlx	%o4,%g1,%o4
	add	%o3,%o4,%o3
	or	%g0,52,%o0
	sub	%o0,%g1,%o0
	srlx	%o3,%o0,%o0
2:
	xor	%o0,%o2,%o0
	sub	%o0,%o2,%o1
9:
	srlx	%o1,32,%o0
	.end

	.inline	__anintf,1
	or	%g0,1,%o1
	srl	%o0,23,%g1
	and	%g1,0xff,%g1
	sub	%g0,%g1,%g1
	add	%g1,0x95,%g1
	subcc	%g1,23,%g0
	sll	%o1,%g1,%o1
	sub	%o1,1,%o2
	bcs	1f
	nop
	be	2f
	nop
	bl	3f
	nop
	sethi	%hi(0x80000000),%o1
	and	%o0,%o1,%o0
	ba	3f
	nop
1:
	and	%o0,%o1,%o1
2:
	add	%o0,%o1,%o0
	andn	%o0,%o2,%o0
3:
	st	%o0,[%sp+0x48]
	ld	[%sp+0x48],%f0
	.end

	.inline	__anint,2
	sllx	%o0,32,%o0
	or	%o0,%o1,%o0
	or	%g0,1,%o1
	srlx	%o0,52,%g1
	and	%g1,0x7ff,%g1
	sub	%g0,%g1,%g1
	add	%g1,0x432,%g1
	subcc	%g1,52,%g0
	sllx	%o1,%g1,%o1
	sub	%o1,1,%o2
	bcs,pt	%icc,1f
	nop
	be,pt	%icc,2f
	nop
	bl,pt	%icc,3f
	nop
	srlx	%o0,63,%o0
	sllx	%o0,63,%o0
	ba	3f
	nop
1:
	and	%o0,%o1,%o1
2:
	add	%o0,%o1,%o0
	andn	%o0,%o2,%o0
3:
	stx	%o0,[%sp+0x48]
	ldd	[%sp+0x48],%f0
	.end

	.inline	__Fz_minus,3
	ld	[%o1],%f0
	ld	[%o1+0x4],%f1
	ld	[%o2],%f4
	ld	[%o2+0x4],%f5
	fsubd	%f0,%f4,%f0
	ld	[%o1+8],%f2
	ld	[%o1+0xc],%f3
	ld	[%o2+8],%f6
	ld	[%o2+0xc],%f7
	fsubd	%f2,%f6,%f2
	st	%f0,[%o0+0x0]
	st	%f1,[%o0+0x4]
	st	%f2,[%o0+0x8]
	st	%f3,[%o0+0xc]
	.end

	.inline	__Fz_add,3
	ld	[%o1],%f0
	ld	[%o1+0x4],%f1
	ld	[%o2],%f4
	ld	[%o2+0x4],%f5
	faddd	%f0,%f4,%f0
	ld	[%o1+8],%f2
	ld	[%o1+0xc],%f3
	ld	[%o2+8],%f6
	ld	[%o2+0xc],%f7
	faddd	%f2,%f6,%f2
	st	%f0,[%o0+0x0]
	st	%f1,[%o0+0x4]
	st	%f2,[%o0+0x8]
	st	%f3,[%o0+0xc]
	.end

	.inline	__Fz_neg,2
	ld	[%o1],%f0
	fnegs	%f0,%f0
	ld	[%o1+0x4],%f1
	st	%f1,[%o0+0x4]
	ld	[%o1+8],%f2
	fnegs	%f2,%f2
	ld	[%o1+0xc],%f3
	st	%f3,[%o0+0xc]
	st	%f0,[%o0]
	st	%f2,[%o0+0x8]
	.end

	.inline	__Ff_conv_z,2
	st	%o1,[%sp+0x44]
	ld	[%sp+0x44],%f0
	fstod	%f0,%f0
	st	%g0,[%o0+0x8]
	st	%g0,[%o0+0xc]
	st	%f1,[%o0+0x4]
	st	%f0,[%o0]
	.end

	.inline	__Fz_conv_f,1
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	fdtos	%f0,%f0
	.end

	.inline	__Fz_conv_i,1
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	fdtoi	%f0,%f0
	st	%f0,[%sp+0x44]
	ld	[%sp+0x44],%o0
	.end

	.inline	__Fi_conv_z,2
	st	%o1,[%sp+0x44]
	ld	[%sp+0x44],%f0
	fitod	%f0,%f0
	st	%g0,[%o0+0x8]
	st	%g0,[%o0+0xc]
	st	%f1,[%o0+0x4]
	st	%f0,[%o0]
	.end

	.inline	__Fz_conv_d,1
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	.end

	.inline	__Fd_conv_z,3
	st	%o1,[%o0]
	st	%o2,[%o0+0x4]
	st	%g0,[%o0+0x8]
	st	%g0,[%o0+0xc]
	.end

	.inline	__Fz_conv_c,2
	ldd     [%o1],%f0
        fdtos   %f0,%f0
        st      %f0,[%o0]
        ldd     [%o1+0x8],%f2
        fdtos   %f2,%f1
        st      %f1,[%o0+0x4]
	.end

	.inline	__Fz_eq,2
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	ld	[%o1],%f2
	ld	[%o1+4],%f3
	fcmpd	%f0,%f2
	mov	%o0,%o2
	mov	0,%o0
	fbne	1f
	nop
	ld	[%o2+8],%f0
	ld	[%o2+12],%f1
	ld	[%o1+8],%f2
	ld	[%o1+12],%f3
	fcmpd	%f0,%f2
	nop
	fbne	1f
	nop
	mov	1,%o0
1:
	.end

	.inline	__Fz_ne,2
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	ld	[%o1],%f2
	ld	[%o1+4],%f3
	fcmpd	%f0,%f2
	mov	%o0,%o2
	mov	1,%o0
	fbne	1f
	nop
	ld	[%o2+8],%f0
	ld	[%o2+12],%f1
	ld	[%o1+8],%f2
	ld	[%o1+12],%f3
	fcmpd	%f0,%f2
	nop
	fbne	1f
	nop
	mov	0,%o0
1:
	.end

	.inline	__c_cmplx,3
	ld	[%o1],%o1
	st	%o1,[%o0]
	ld	[%o2],%o2
	st	%o2,[%o0+4]
	.end

	.inline	__d_cmplx,3
	ld	[%o1],%f0
	st	%f0,[%o0]
	ld	[%o1+4],%f1
	st	%f1,[%o0+4]
	ld	[%o2],%f0
	st	%f0,[%o0+0x8]
	ld	[%o2+4],%f1
	st	%f1,[%o0+0xc]
	.end

	.inline	__r_cnjg,2
	ld	[%o1+0x4],%f1
	fnegs	%f1,%f1
	ld	[%o1],%f0
	st	%f0,[%o0]
	st	%f1,[%o0+4]
	.end

	.inline	__d_cnjg,2
	ld	[%o1+0x8],%f0
	fnegs	%f0,%f0
	ld	[%o1+0xc],%f1
	st	%f1,[%o0+0xc]
	ld	[%o1+0x0],%f1
	st	%f1,[%o0+0x0]
	ld	[%o1+0x4],%f1
	st	%f1,[%o0+0x4]
	st	%f0,[%o0+0x8]
	.end

	.inline	__r_dim,2
	st	%g0,[%sp+0x48]
	ld	[%sp+0x48],%f4
	ld	[%o0],%f0
	ld	[%o1],%f2
	fcmps	%fcc0,%f0,%f2
	fmovsule %fcc0,%f4,%f2
	fsubs	%f0,%f2,%f0
	fmovsule %fcc0,%f4,%f0
	.end

	.inline	__d_dim,2
	stx	%g0,[%sp+0x48]
	ldd	[%sp+0x48],%f4
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	ld	[%o1],%f2
	ld	[%o1+4],%f3
	fcmpd	%fcc0,%f0,%f2
	fmovdule %fcc0,%f4,%f2
	fsubd	%f0,%f2,%f0
	fmovdule %fcc0,%f4,%f0
	.end

	.inline	__r_imag,1
	ld	[%o0+4],%f0
	.end

	.inline	__d_imag,1
	ld	[%o0+8],%f0
	ld	[%o0+0xc],%f1
	.end

	.inline	__f95_signf,2
	ld	[%o0],%f0
	ld	[%o1],%o1
	fabss	%f0,%f0
	fnegs	%f0,%f1
	sra	%o1,0,%o1
	fmovrslz %o1,%f1,%f0
	.end

	.inline	__f95_sign,2
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	ld	[%o1],%o1
	fabsd	%f0,%f0
	fnegd	%f0,%f2
	sra	%o1,0,%o1
	fmovrdlz %o1,%f2,%f0
	.end

	.inline	__r_sign,2
	ld	[%o0],%f0
	ld	[%o1],%o1
	fabss	%f0,%f0
	fnegs	%f0,%f1
	sub	%o1,1,%o0
	and	%o1,%o0,%o1
	sra	%o1,0,%o1
	fmovrslz %o1,%f1,%f0
	.end

	.inline	__d_sign,2
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	ld	[%o1],%o0
	sllx	%o0,32,%o0
	ld	[%o1+4],%o1
	or	%o1,%o0,%o1
	fabsd	%f0,%f0
	fnegd	%f0,%f2
	sub	%o1,1,%o0
	and	%o1,%o0,%o1
	fmovrdlz %o1,%f2,%f0
	.end

	.inline	__Fz_mult,3
	ld	[%o1],%f0
	ld	[%o1+0x4],%f1
	ld	[%o2],%f4
	ld	[%o2+0x4],%f5
	fmuld	%f0,%f4,%f8	! f8 = r1*r2
	ld	[%o1+0x8],%f2
	ld	[%o1+0xc],%f3
	ld	[%o2+0x8],%f6
	ld	[%o2+0xc],%f7
	fmuld	%f2,%f6,%f10	! f10= i1*i2
	fsubd	%f8,%f10,%f12	! f12= r1*r2-i1*i2
	st	%f12,[%o0]
	st	%f13,[%o0+4]
	fmuld	%f0,%f6,%f14	! f14= r1*i2
	fmuld	%f2,%f4,%f16	! f16= r2*i1
	faddd	%f14,%f16,%f2	! f2 = r1*i2+r2*i1
	st	%f2,[%o0+8]
	st	%f3,[%o0+12]
	.end
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fc_minus(c, a, b)
! complex *c, *a, *b;
! {

	.inline	__Fc_minus,3
!    30	 	c->real = a->real - b->real
	ld	[%o1],%f0
	ld	[%o2],%f1
	fsubs	%f0,%f1,%f2
!    31	  	c->imag = a->imag - b->imag
	ld	[%o1+4],%f3
	ld	[%o2+4],%f4
	fsubs	%f3,%f4,%f5
	st	%f2,[%o0]
	st	%f5,[%o0+4]
	.end
 }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fc_add(c, a, b)
! complex *c, *a, *b;
! {

	.inline	__Fc_add,3
!    39	 	c->real = a->real + b->real
	ld	[%o1],%f0
	ld	[%o2],%f1
	fadds	%f0,%f1,%f2
!    40	 	c->imag = a->imag + b->imag
	ld	[%o1+4],%f3
	ld	[%o2+4],%f4
	fadds	%f3,%f4,%f5
	st	%f2,[%o0]
	st	%f5,[%o0+4]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fc_neg(c, a)
! complex *c, *a;
! {

	.inline	__Fc_neg,2
!    48	  	c->real = - a->real
	ld	[%o1],%f0
	fnegs	%f0,%f1
!    49	  	c->imag = - a->imag
	ld	[%o1+4],%f2
	fnegs	%f2,%f3
	st	%f1,[%o0]
	st	%f3,[%o0+4]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Ff_conv_c(c, x)
! complex *c;
! FLOATPARAMETER x;
! {

	.inline	__Ff_conv_c,2
!    59		c->real = x
	st	%o1,[%o0]
!    60		c->imag = 0.0
	st	%g0,[%o0+4]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! FLOATFUNCTIONTYPE
! __Fc_conv_f(c)
! complex *c;
! {

	.inline	__Fc_conv_f,1
!    69  	RETURNFLOAT(c->real)
	ld	[%o0],%f0
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! int
! __Fc_conv_i(c)
! complex *c;
! {

	.inline	__Fc_conv_i,1
!    78		return (int)c->real
	ld	[%o0],%f0
	fstoi	%f0,%f1
	st	%f1,[%sp+68]
	ld	[%sp+68],%o0
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fi_conv_c(c, i)
! complex *c;
! int i;
! {

	.inline	__Fi_conv_c,2
!    88		c->real = (float)i
	st	%o1,[%sp+68]
	ld	[%sp+68],%f0
	fitos	%f0,%f1
	st	%f1,[%o0]
!    89		c->imag = 0.0
	st	%g0,[%o0+4]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! double
! __Fc_conv_d(c)
! complex *c;
! {

	.inline	__Fc_conv_d,1
!    98		return (double)c->real
	ld	[%o0],%f2
	fstod	%f2,%f0
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fd_conv_c(c, x)
! complex *c;
! double x;
! {

	.inline	__Fd_conv_c,2
	st	%o1,[%sp+72]
	st	%o2,[%sp+76]
!   109		c->real = (float)(x)
	ldd	[%sp+72],%f0
	fdtos	%f0,%f1
	st	%f1,[%o0]
!   110		c->imag = 0.0
	st	%g0,[%o0+4]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! void
! __Fc_conv_z(result, c)
! dcomplex *result;
! complex *c;
! {

	.inline	__Fc_conv_z,2
!   120		result->dreal = (double)c->real
	ld	[%o1],%f0
	fstod	%f0,%f2
	st	%f2,[%o0]
	st	%f3,[%o0+4]
!   121		result->dimag = (double)c->imag
	ld	[%o1+4],%f3
	fstod	%f3,%f4
	st	%f4,[%o0+8]
	st	%f5,[%o0+12]
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! int
! __Fc_eq(x, y)
! complex *x, *y;
! {

	.inline	__Fc_eq,2
!	return  (x->real == y->real) && (x->imag == y->imag);
	ld	[%o0],%f0
	ld	[%o1],%f2
	mov	%o0,%o2
	fcmps	%f0,%f2
	mov	0,%o0
	fbne	1f
	nop
	ld	[%o2+4],%f0
	ld	[%o1+4],%f2
	fcmps	%f0,%f2
	nop
	fbne	1f
	nop
	mov	1,%o0
1:
	.end
! }
!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
! int
! __Fc_ne(x, y)
! complex *x, *y;
! {

	.inline	__Fc_ne,2
!	return  (x->real != y->real) || (x->imag != y->imag);
	ld	[%o0],%f0
	ld	[%o1],%f2
	mov	%o0,%o2
	fcmps	%f0,%f2
	mov	1,%o0
	fbne	1f
	nop
	ld	[%o2+4],%f0
	ld	[%o1+4],%f2
	fcmps	%f0,%f2
	nop
	fbne	1f
	nop
	mov	0,%o0
1:
	.end
! }
