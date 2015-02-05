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

	.inline	__ieee754_sqrt,1
	fsqrtd	%f0,%f0
	.end

	.inline	__inline_sqrtf,1
	fsqrts	%f1,%f0
	.end

	.inline	__inline_sqrt,1
	fsqrtd	%f0,%f0
	.end

	.inline	sqrtf,1
	fsqrts	%f1,%f0
	.end

	.inline	sqrt,1
	fsqrtd	%f0,%f0
	.end

	.inline	__ceil,1
	sethi	%hi(0x43300000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f2
	fabsd	%f0,%f4
	fsubd	%f2,%f2,%f6
	fcmpd	%fcc0,%f4,%f2
	fbl,pt	%fcc0,1f
	nop
	sethi	%hi(0x3ff00000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f6
	fmuld	%f0,%f6,%f0
	ba	4f
	nop
1:
	fcmpd	%fcc1,%f0,%f6
	fbg,pt	%fcc1,2f
	nop
	fbe,pn	%fcc1,4f
	nop
	fnegd	%f2,%f2
2:
	faddd	%f0,%f2,%f4
	fsubd	%f4,%f2,%f4
	fcmpd	%fcc0,%f4,%f0
	fbge,pt	%fcc0,3f
	nop
	sethi	%hi(0x3ff00000),%o0
	st	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f2
	faddd	%f4,%f2,%f4
3:
	fabsd	%f4,%f0
	fbge,pt	%fcc1,4f
	nop
	fnegd	%f0,%f0
4:
	.end

	.inline	__floor,1
	sethi	%hi(0x43300000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f2
	fabsd	%f0,%f4
	fsubd	%f2,%f2,%f6
	fcmpd	%fcc0,%f4,%f2
	fbl,pt	%fcc0,1f
	nop
	sethi	%hi(0x3ff00000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f6
	fmuld	%f0,%f6,%f0
	ba	4f
	nop
1:
	fcmpd	%fcc1,%f0,%f6
	fbg,pt	%fcc1,2f
	nop
	fbe,pn	%fcc1,4f
	nop
	fnegd	%f2,%f2
2:
	faddd	%f0,%f2,%f4
	fsubd	%f4,%f2,%f4
	fcmpd	%fcc0,%f4,%f0
	fble,pt	%fcc0,3f
	nop
	sethi	%hi(0x3ff00000),%o0
	st	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f2
	fsubd	%f4,%f2,%f4
3:
	fabsd	%f4,%f0
	fbge,pt	%fcc1,4f
	nop
	fnegd	%f0,%f0
4:
	.end

	.inline	__ilogb,1
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x7ff00000),%o1
	andcc	%o0,%o1,%o0
	bne,pt	%icc,2f
	nop
	sethi	%hi(0x43500000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f2
	fmuld	%f0,%f2,%f0
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	andcc	%o0,%o1,%o0
	bne,pt	%icc,1f
	nop
	sethi	%hi(0x80000001),%o0
	or	%o0,%lo(0x80000001),%o0
	ba	4f
	nop
1:
	srl	%o0,20,%o0
	sub	%o0,0x435,%o0
	ba	4f
	nop
2:
	subcc	%o1,%o0,%g0
	bne,pt	%icc,3f
	nop
	sethi	%hi(0x7fffffff),%o0
	or	%o0,%lo(0x7fffffff),%o0
	ba	4f
	nop
3:
	srl	%o0,20,%o0
	sub	%o0,0x3ff,%o0
4:
	.end

	.inline	__rint,1
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
	sethi	%hi(0x80000000),%o2
	sllx	%o2,32,%o2
	andn	%o0,%o2,%o2
	sethi	%hi(0x43300000),%o3
	sllx	%o3,32,%o3
	stx	%g0,[%sp+0x887]
	subcc	%o2,%o3,%g0
	bl,pt	%xcc,1f
	nop
	sethi	%hi(0x3ff00000),%o2
	sllx	%o2,32,%o2
	stx	%o2,[%sp+0x887]
	ldd	[%sp+0x887],%f2
	fmuld	%f0,%f2,%f0
	ba	3f
	nop
1:
	orcc	%o0,0,%g0
	stx	%o3,[%sp+0x87f]
	ldd	[%sp+0x87f],%f2
	bge,pt	%xcc,2f
	nop
	fnegd	%f2,%f2
2:
	faddd	%f0,%f2,%f0
	fcmpd	%f0,%f2
	fbne,pt	%fcc0,0f
	nop
	ldd	[%sp+0x887],%f0
	bge,pt	%xcc,3f
	nop
	fnegd	%f0,%f0
	ba	3f
	nop
0:
	fsubd	%f0,%f2,%f0
3:
	.end

	.inline	__rintf,1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o2
	sethi	%hi(0x4b000000),%o3
	st	%g0,[%sp+0x887]
	subcc	%o2,%o3,%g0
	bl	1f
	nop
	sethi	%hi(0x3f800000),%o2
	st	%o2,[%sp+0x887]
	ld	[%sp+0x887],%f2
	fmuls	%f1,%f2,%f0
	ba	3f
	nop
1:
	tst	%o0
	st	%o3,[%sp+0x87f]
	ld	[%sp+0x87f],%f2
	bge	2f
	nop
	fnegs	%f2,%f2
2:
	fadds	%f1,%f2,%f0
	fcmps	%f0,%f2
	fbne	0f
	nop
	ld	[%sp+0x887],%f0
	bge	3f
	nop
	fnegs	%f0,%f0
	ba	3f
	nop
0:
	fsubs	%f0,%f2,%f0
3:
	.end

	.inline	__min_subnormal,1
	or	%g0,1,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__min_subnormalf,1
	or	%g0,1,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__max_subnormal,1
	xnor	%g0,%g0,%o0
	srlx	%o0,12,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__max_subnormalf,1
	xnor	%g0,%g0,%o0
	srl	%o0,9,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__min_normal,1
	sethi	%hi(0x00100000),%o0
	sllx	%o0,32,%o0
        stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__min_normalf,1
	sethi	%hi(0x00800000),%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__max_normal,1
	sethi	%hi(0x80100000),%o1
	sllx	%o1,32,%o1
	xnor	%g0,%g0,%o0
	andn	%o0,%o1,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__max_normalf,1
	sethi	%hi(0x7f7ffc00),%o0
	or	%o0,0x3ff,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__infinity,1
	sethi	%hi(0x7ff00000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__infinity,1
	sethi	%hi(0x7ff00000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__infinityf,1
	sethi	%hi(0x7f800000),%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__signaling_nan,1
	sethi	%hi(0x7ff00000),%o0
	sllx	%o0,32,%o0
	or	%o0,0x1,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__signaling_nanf,1
	sethi	%hi(0x7f800000),%o0
	or	%o0,1,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__quiet_nan,1
	xnor	%g0,%g0,%o0
	srlx	%o0,1,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__quiet_nanf,1
	xnor	%g0,%g0,%o0
	srl	%o0,1,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__swapEX,1
	and	%o0,0x1f,%o1
	sll	%o1,5,%o1
	.volatile
	st	%fsr,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	andn	%o0,0x3e0,%o2
	or	%o1,%o2,%o1
	st	%o1,[%sp+0x87f]
	ld	[%sp+0x87f],%fsr
	srl	%o0,5,%o0
	and	%o0,0x1f,%o0
	.nonvolatile
	.end

	.inline	_QgetRD,0
	st	%fsr,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	srl	%o0,30,%o0
	.end

	.inline	_QgetRP,0
	or	%g0,%g0,%o0
	.end

	.inline	__swapRD,1
	and	%o0,0x3,%o0
	sll	%o0,30,%o1
	.volatile
	st	%fsr,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0xc0000000),%o4
	andn	%o0,%o4,%o2
	or	%o1,%o2,%o1
	st	%o1,[%sp+0x87f]
	ld	[%sp+0x87f],%fsr
	srl	%o0,30,%o0
	and	%o0,0x3,%o0
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
	sll	%o0,23,%o1
	.volatile
	st	%fsr,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x0f800000),%o4
	andn	%o0,%o4,%o2
	or	%o1,%o2,%o1
	st	%o1,[%sp+0x87f]
	ld	[%sp+0x87f],%fsr
	srl	%o0,23,%o0
	and	%o0,0x1f,%o0
	.nonvolatile
	.end

	.inline	fp_class,1
	fabsd	%f0,%f0
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
	orcc	%g0,%o0,%g0
	be,pn	%xcc,2f
	nop
	sethi	%hi(0x7ff00000),%o1
	sllx	%o1,32,%o1
	andcc	%o0,%o1,%g0
	bne,pt	%xcc,1f
	nop
	or	%g0,1,%o0
	ba	2f
	nop
1:
	subcc	%o0,%o1,%g0
	bge,pn	%xcc,1f
	nop
	or	%g0,2,%o0
	ba	2f
	nop
1:
	andncc	%o0,%o1,%o0
	bne,pn	%xcc,1f
	nop
	or	%g0,3,%o0
	ba	2f
	nop
1:
	sethi	%hi(0x00080000),%o1
	sllx	%o1,32,%o1
	andcc	%o0,%o1,%g0
	or	%g0,4,%o0
	bne,pt	%xcc,2f
	nop
	or	%g0,5,%o0
2:
	.end

	.inline	fp_classf,1
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	orcc	%g0,%o0,%g0
	be,pn	%icc,2f
	nop
1:
	sethi	%hi(0x7f800000),%o1
	andcc	%o0,%o1,%g0
	bne,pt	%icc,1f
	nop
	or	%g0,1,%o0
	ba	2f
	nop
1:
	subcc	%o0,%o1,%g0
	bge,pn	%icc,1f
	nop
	or	%g0,2,%o0
	ba	2f
	nop
1:
	bg,pn	%icc,1f
	nop
	or	%g0,3,%o0
	ba	2f
	nop
1:
	sethi	%hi(0x00400000),%o1
	andcc	%o0,%o1,%g0
	or	%g0,4,%o0
	bne,pt	%icc,2f
	nop
	or	%g0,5,%o0
2:
	.end

	.inline	__copysign,2
	fabsd	%f0,%f0
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	st	%f2,[%sp+0x887]
	ld	[%sp+0x887],%o1
	srl	%o1,31,%o1
	sll	%o1,31,%o1
	or	%o0,%o1,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__copysignf,2
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	st	%f3,[%sp+0x887]
	ld	[%sp+0x887],%o1
	srl	%o1,31,%o1
	sll	%o1,31,%o1
	or	%o0,%o1,%o0
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	_finite,1
	fabsd	%f0,%f0
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x7ff00000),%o1
	sub	%o0,%o1,%o0
	srl	%o0,31,%o0
	.end

	.inline	__finitef,1
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x7f800000),%o1
	sub	%o0,%o1,%o0
	srl	%o0,31,%o0
	.end

	.inline	__signbit,1
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	srl	%o0,31,%o0
	.end

	.inline	__signbitf,1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	srl	%o0,31,%o0
	.end

	.inline	__isinf,1
	fabsd	%f0,%f0
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
	sethi	%hi(0x7ff00000),%o1
	sllx	%o1,32,%o1
	sub	%o0,%o1,%o0
	sub	%g0,%o0,%o1
	or	%o0,%o1,%o0
	xnor	%o0,%g0,%o0
	srlx	%o0,63,%o0
	.end

	.inline	__isinff,1
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x7f800000),%o1
	sub	%o0,%o1,%o0
	sub	%g0,%o0,%o1
	or	%o0,%o1,%o0
	xnor	%o0,%g0,%o0
	srl	%o0,31,%o0
	.end

	.inline	__isnan,1
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
	sllx	%o0,1,%o0
	srlx	%o0,1,%o0
	sethi	%hi(0x7ff00000),%o1
	sllx	%o1,32,%o1
	sub	%o1,%o0,%o0
	srlx	%o0,63,%o0
	.end

	.inline	__isnanf,1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x80000000),%o2
	andn	%o0,%o2,%o0
	sethi	%hi(0x7f800000),%o1
	sub	%o1,%o0,%o0
	srl	%o0,31,%o0
	.end

	.inline	__isnormal,1
	fabsd	%f0,%f0
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x7ff00000),%o1
	sub	%o0,%o1,%o2
	sethi	%hi(0x00100000),%o1
	sub	%o0,%o1,%o1
	andn	%o2,%o1,%o0
	srl	%o0,31,%o0
	.end

	.inline	__isnormalf,1
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x7f800000),%o1
	sub	%o0,%o1,%o2
	sethi	%hi(0x00800000),%o1
	sub	%o0,%o1,%o1
	andn	%o2,%o1,%o0
	srl	%o0,31,%o0
	.end

	.inline	__issubnormal,1
	fabsd	%f0,%f0
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
	sethi	%hi(0x00100000),%o1
	sllx	%o1,32,%o1
	sub	%o0,%o1,%o1
	sub	%g0,%o0,%o2
	or	%o0,%o2,%o0
	and	%o0,%o1,%o0
	srlx	%o0,63,%o0
	.end

	.inline	__issubnormalf,1
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sethi	%hi(0x00800000),%o1
	sub	%o0,%o1,%o1
	sub	%g0,%o0,%o2
	or	%o0,%o2,%o0
	and	%o0,%o1,%o0
	srl	%o0,31,%o0
	.end

	.inline	__iszero,1
	fabsd	%f0,%f0
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
	sub	%g0,%o0,%o1
	or	%o0,%o1,%o0
	xnor	%o0,%g0,%o0
	srlx	%o0,63,%o0
	.end

	.inline	__iszerof,1
	fabss	%f1,%f1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sub	%g0,%o0,%o1
	or	%o0,%o1,%o0
	xnor	%o0,%g0,%o0
	srl	%o0,31,%o0
	.end

	.inline	abs,1
	sra	%o0,31,%o1
	xor	%o0,%o1,%o0
	sub	%o0,%o1,%o0
	sra	%o0,0,%o0
	.end

	.inline	fabs,1
	fabsd	%f0,%f0
	.end

	.inline	fabsf,1
	fabss	%f1,%f0
	.end
!
!	__nintf - f77 NINT(REAL*4)
!

	.inline	__nintf,1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	srl	%o0,30-7,%g1
	sethi	%hi(0x7fffff),%o2
	and	%g1,0xff,%g1
	or	%o2,%lo(0x7fffff),%o2
	sethi	%hi(1<<22),%o4
	subcc	%g1,127+31,%g0
	and	%o0,%o2,%o3
	bl	1f
	nop
	sethi	%hi(0xcf000000),%o2
	sethi	%hi(0x80000000),%g1
	subcc	%o0,%o2,%g0
	or	%g1,%g0,%o0
	be	0f
	nop
	fstoi	%f1,%f0
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
0:
	sra	%o0,0,%o0
	ba	9f
	nop
1:
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
	sra	%o0,0,%o0
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
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	fstox	%f0,%f0
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
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
	sub	%o0,%o2,%o0
9:
	.end
!
!	__i_dnnt - f77 NINT(REAL*8)
!

	.inline	__i_dnnt,1
	ldx	[%o0],%o0
	srlx	%o0,63-11,%g1
	or	%g0,1,%o2
	stx	%o0,[%sp+0x87f]
	sllx	%o2,52-1,%o4
	and	%g1,0x7ff,%g1
	sllx	%o2,63-0,%o2
	subcc	%g1,1023+32,%g0
	bl	0f
	nop
	ldd	[%sp+0x87f],%f0
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
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	fxtod	%f0,%f0
8:
	fdtoi	%f0,%f0
	st	%f0,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
	sra	%o0,0,%o0
9:
	.end

	.inline	__il_dnnt,1
	ldx	[%o0],%o0
	srlx	%o0,63-11,%g1
	or	%g0,1,%o2
	sllx	%o2,52-1,%o4
	and	%g1,0x7ff,%g1
	sllx	%o2,63-0,%o2
	subcc	%g1,1023+63,%g0
	bl	0f
	nop
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	fdtox	%f0,%f0
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
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
	sub	%o0,%o2,%o0
9:
	.end

	.inline	__anintf,1
	st	%f1,[%sp+0x87f]
	ld	[%sp+0x87f],%o0
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
	st	%o0,[%sp+0x87f]
	ld	[%sp+0x87f],%f0
	.end

	.inline	__anint,1
	std	%f0,[%sp+0x87f]
	ldx	[%sp+0x87f],%o0
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
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f0
	.end

	.inline	__r_dim,2
	st	%g0,[%sp+0x87f]
	ld	[%sp+0x87f],%f4
	ld	[%o0],%f0
	ld	[%o1],%f2
	fcmps	%fcc0,%f0,%f2
	fmovsule %fcc0,%f4,%f2
	fsubs	%f0,%f2,%f0
	fmovsule %fcc0,%f4,%f0
	.end

	.inline	__d_dim,2
	stx	%g0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f4
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	ld	[%o1],%f2
	ld	[%o1+4],%f3
	fcmpd	%fcc0,%f0,%f2
	fmovdule %fcc0,%f4,%f2
	fsubd	%f0,%f2,%f0
	fmovdule %fcc0,%f4,%f0
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
	ldd	[%o0],%f0
	ldx	[%o1],%o1
	fabsd	%f0,%f0
	fnegd	%f0,%f2
	sub	%o1,1,%o0
	and	%o1,%o0,%o1
	fmovrdlz %o1,%f2,%f0
	.end
!
! complex __Fc_div_f(complex a, complex b);
!

	.inline	__Fc_div_f,0
	st	%g0,[%sp+0x87f]
	ld	[%sp+0x87f],%f4
	fcmps	%fcc0,%f3,%f4
	fbne,pn	%fcc0,1f
	nop
	fdivs	%f0,%f2,%f0
	fdivs	%f1,%f2,%f1
	ba	2f
	nop
1:
	sethi	%hi(0x3ff00000),%o0
	sllx	%o0,32,%o0
	stx	%o0,[%sp+0x87f]
	ldd	[%sp+0x87f],%f16
	fsmuld	%f2,%f2,%f4
	fsmuld	%f3,%f3,%f6
	fsmuld	%f1,%f3,%f8
	fsmuld	%f0,%f2,%f10
	faddd	%f6,%f4,%f6
	fdivd	%f16,%f6,%f6
	faddd	%f10,%f8,%f10
	fsmuld	%f1,%f2,%f12
	fmuld	%f10,%f6,%f10
	fsmuld	%f0,%f3,%f14
	fsubd	%f12,%f14,%f14
	fmuld	%f14,%f6,%f6
	fdtos	%f10,%f0
	fdtos	%f6,%f1
2:
	.end
