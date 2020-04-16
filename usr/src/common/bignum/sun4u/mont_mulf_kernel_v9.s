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

/*
 * This file is mostly a result of compiling the mont_mulf.c file to generate an
 * assembly output and then hand-editing that output to replace the
 * compiler-generated loop for the 512-bit case (nlen == 16) in the
 * mont_mulf_noconv routine with a hand-crafted version. This file also
 * has big_savefp() and big_restorefp() routines added by hand.
 */

#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/stack.h>
#include <sys/privregs.h>
#include <sys/regset.h>
#include <sys/vis.h>
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/machsig.h>

	.section	".text",#alloc,#execinstr
	.file	"mont_mulf.s"

	.section	".bss",#alloc,#write
Bbss.bss:

	.section	".data",#alloc,#write
Ddata.data:

	.section	".rodata",#alloc
!
! CONSTANT POOL
!
Drodata.rodata:
	.global	TwoTo16
	.align	8
!
! CONSTANT POOL
!
	.global TwoTo16
TwoTo16:
	.word	1089470464
	.word	0
	.type	TwoTo16,#object
	.size	TwoTo16,8
	.global	TwoToMinus16
!
! CONSTANT POOL
!
	.global TwoToMinus16
TwoToMinus16:
	.word	1055916032
	.word	0
	.type	TwoToMinus16,#object
	.size	TwoToMinus16,8
	.global	Zero
!
! CONSTANT POOL
!
	.global Zero
Zero:
	.word	0
	.word	0
	.type	Zero,#object
	.size	Zero,8
	.global	TwoTo32
!
! CONSTANT POOL
!
	.global TwoTo32
TwoTo32:
	.word	1106247680
	.word	0
	.type	TwoTo32,#object
	.size	TwoTo32,8
	.global	TwoToMinus32
!
! CONSTANT POOL
!
	.global TwoToMinus32
TwoToMinus32:
	.word	1039138816
	.word	0
	.type	TwoToMinus32,#object
	.size	TwoToMinus32,8

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.register	%g3,#scratch
/* 000000	     */		.register	%g2,#scratch
/* 000000	   0 */		.align	32
! FILE mont_mulf.c

!    1		      !/*
!    2		      ! * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
!    3		      ! * Use is subject to license terms.
!    4		      ! */
!    6		      !#pragma ident	"@(#)mont_mulf.c	1.2	01/09/24 SMI"
!    9		      !/*
!   10		      ! * If compiled without -DRF_INLINE_MACROS then needs -lm at link time
!   11		      ! * If compiled with -DRF_INLINE_MACROS then needs conv.il at compile time
!   12		      ! * (i.e. cc <compileer_flags> -DRF_INLINE_MACROS conv.il mont_mulf.c )
!   13		      ! */
!   15		      !#include <sys/types.h>
!   16		      !#include <math.h>
!   18		      !static const double TwoTo16 = 65536.0;
!   19		      !static const double TwoToMinus16 = 1.0/65536.0;
!   20		      !static const double Zero = 0.0;
!   21		      !static const double TwoTo32 = 65536.0 * 65536.0;
!   22		      !static const double TwoToMinus32 = 1.0 / (65536.0 * 65536.0);
!   24		      !#ifdef RF_INLINE_MACROS
!   26		      !double upper32(double);
!   27		      !double lower32(double, double);
!   28		      !double mod(double, double, double);
!   30		      !#else
!   32		      !static double
!   33		      !upper32(double x)
!   34		      !{
!   35		      !	return (floor(x * TwoToMinus32));
!   36		      !}
!   39		      !/* ARGSUSED */
!   40		      !static double
!   41		      !lower32(double x, double y)
!   42		      !{
!   43		      !	return (x - TwoTo32 * floor(x * TwoToMinus32));
!   44		      !}
!   46		      !static double
!   47		      !mod(double x, double oneoverm, double m)
!   48		      !{
!   49		      !	return (x - m * floor(x * oneoverm));
!   50		      !}
!   52		      !#endif
!   55		      !static void
!   56		      !cleanup(double *dt, int from, int tlen)
!   57		      !{

!
! SUBROUTINE cleanup
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       cleanup:
/* 000000	  57 */		sra	%o1,0,%o4
/* 0x0004	     */		sra	%o2,0,%o5

!   58		      !	int i;
!   59		      !	double tmp, tmp1, x, x1;
!   61		      !	tmp = tmp1 = Zero;

/* 0x0008	  61 */		sll	%o5,1,%g5

!   63		      !	for (i = 2 * from; i < 2 * tlen; i += 2) {

/* 0x000c	  63 */		sll	%o4,1,%g3
/* 0x0010	     */		cmp	%g3,%g5
/* 0x0014	     */		bge,pn	%icc,.L77000188
/* 0x0018	   0 */		sethi	%hi(Zero),%o3
                       .L77000197:
/* 0x001c	  63 */		ldd	[%o3+%lo(Zero)],%f8
/* 0x0020	     */		sra	%g3,0,%o1
/* 0x0024	     */		sub	%g5,1,%g2
/* 0x0028	     */		sllx	%o1,3,%g4

!   64		      !		x = dt[i];

/* 0x002c	  64 */		ldd	[%g4+%o0],%f10
/* 0x0030	  63 */		add	%g4,%o0,%g1
/* 0x0034	     */		fmovd	%f8,%f18
/* 0x0038	     */		fmovd	%f8,%f16

!   65		      !		x1 = dt[i + 1];
!   66		      !		dt[i] = lower32(x, Zero) + tmp;

                       .L900000110:
/* 0x003c	  66 */		fdtox	%f10,%f0
/* 0x0040	  65 */		ldd	[%g1+8],%f12

!   67		      !		dt[i + 1] = lower32(x1, Zero) + tmp1;
!   68		      !		tmp = upper32(x);
!   69		      !		tmp1 = upper32(x1);

/* 0x0044	  69 */		add	%g3,2,%g3
/* 0x0048	     */		cmp	%g3,%g2
/* 0x004c	  67 */		fdtox	%f12,%f2
/* 0x0050	  68 */		fmovd	%f0,%f4
/* 0x0054	  66 */		fmovs	%f8,%f0
/* 0x0058	  67 */		fmovs	%f8,%f2
/* 0x005c	  66 */		fxtod	%f0,%f0
/* 0x0060	  67 */		fxtod	%f2,%f2
/* 0x0064	  69 */		fdtox	%f12,%f6
/* 0x0068	  66 */		faddd	%f0,%f18,%f10
/* 0x006c	     */		std	%f10,[%g1]
/* 0x0070	  67 */		faddd	%f2,%f16,%f14
/* 0x0074	     */		std	%f14,[%g1+8]
/* 0x0078	  68 */		fitod	%f4,%f18
/* 0x007c	  69 */		add	%g1,16,%g1
/* 0x0080	     */		fitod	%f6,%f16
/* 0x0084	     */		ble,a,pt	%icc,.L900000110
/* 0x0088	  64 */		ldd	[%g1],%f10
                       .L77000188:
/* 0x008c	  69 */		retl	! Result =
/* 0x0090	     */		nop
/* 0x0094	   0 */		.type	cleanup,2
/* 0x0094	   0 */		.size	cleanup,(.-cleanup)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
/* 000000	     */		.skip	24
/* 0x0018	     */		.align	32

!   70		      !	}
!   71		      !}
!   75		      !#ifdef _KERNEL
!   76		      !/*
!   77		      ! * This only works if  0 <= d < 2^53
!   78		      ! */
!   79		      !uint64_t
!   80		      !double2uint64_t(double* d)
!   81		      !{
!   82		      !	uint64_t x;
!   83		      !	uint64_t exp;
!   84		      !	uint64_t man;
!   86		      !	x = *((uint64_t *)d);

!
! SUBROUTINE double2uint64_t
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

			.global double2uint64_t
                       double2uint64_t:
/* 000000	  86 */		ldx	[%o0],%o2

!   87		      !	if (x == 0) {

/* 0x0004	  87 */		cmp	%o2,0
/* 0x0008	     */		bne,pn	%xcc,.L900000206
/* 0x000c	  94 */		sethi	%hi(0xfff00000),%o5
                       .L77000202:
/* 0x0010	  94 */		retl	! Result =  %o0

!   88		      !		return (0ULL);

/* 0x0014	  88 */		or	%g0,0,%o0

!   89		      !	}
!   90		      !	exp = (x >> 52) - 1023;
!   91		      !	man = (x & 0xfffffffffffffULL) | 0x10000000000000ULL;
!   92		      !	x = man >> (52 - exp);
!   94		      !	return (x);

                       .L900000206:
/* 0x0018	  94 */		sllx	%o5,32,%o4
/* 0x001c	     */		srlx	%o2,52,%o0
/* 0x0020	     */		sethi	%hi(0x40000000),%o1
/* 0x0024	     */		or	%g0,1023,%g5
/* 0x0028	     */		sllx	%o1,22,%g4
/* 0x002c	     */		xor	%o4,-1,%o3
/* 0x0030	     */		sub	%g5,%o0,%g3
/* 0x0034	     */		and	%o2,%o3,%g2
/* 0x0038	     */		or	%g2,%g4,%o5
/* 0x003c	     */		add	%g3,52,%g1
/* 0x0040	     */		retl	! Result =  %o0
/* 0x0044	     */		srlx	%o5,%g1,%o0
/* 0x0048	   0 */		.type	double2uint64_t,2
/* 0x0048	   0 */		.size	double2uint64_t,(.-double2uint64_t)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
/* 000000	     */		.skip	24
/* 0x0018	     */		.align	32

!   95		      !}
!   96		      !#else
!   97		      !/*
!   98		      ! * This only works if  0 <= d < 2^63
!   99		      ! */
!  100		      !uint64_t
!  101		      !double2uint64_t(double* d)
!  102		      !{
!  103		      !	return ((int64_t)(*d));
!  104		      !}
!  105		      !#endif
!  107		      !/* ARGSUSED */
!  108		      !void
!  109		      !conv_d16_to_i32(uint32_t *i32, double *d16, int64_t *tmp, int ilen)
!  110		      !{

!
! SUBROUTINE conv_d16_to_i32
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

			.global conv_d16_to_i32
                       conv_d16_to_i32:
/* 000000	 110 */		save	%sp,-176,%sp

!  111		      !	int i;
!  112		      !	int64_t t, t1,		/* using int64_t and not uint64_t */
!  113		      !		a, b, c, d;	/* because more efficient code is */
!  114		      !				/* generated this way, and there  */
!  115		      !				/* is no overflow  */
!  116		      !	t1 = 0;
!  117		      !	a = double2uint64_t(&(d16[0]));

/* 0x0004	 117 */		ldx	[%i1],%o0
/* 0x0008	 118 */		ldx	[%i1+8],%i2
/* 0x000c	 117 */		cmp	%o0,0
/* 0x0010	     */		bne,pn	%xcc,.L77000216
/* 0x0014	     */		or	%g0,0,%i4
                       .L77000215:
/* 0x0018	 117 */		ba	.L900000316
/* 0x001c	 118 */		cmp	%i2,0
                       .L77000216:
/* 0x0020	 117 */		srlx	%o0,52,%o5
/* 0x0024	     */		sethi	%hi(0xfff00000),%i4
/* 0x0028	     */		sllx	%i4,32,%o2
/* 0x002c	     */		sethi	%hi(0x40000000),%o7
/* 0x0030	     */		sllx	%o7,22,%o3
/* 0x0034	     */		or	%g0,1023,%o4
/* 0x0038	     */		xor	%o2,-1,%g5
/* 0x003c	     */		sub	%o4,%o5,%l0
/* 0x0040	     */		and	%o0,%g5,%o1
/* 0x0044	     */		add	%l0,52,%l1
/* 0x0048	     */		or	%o1,%o3,%g4

!  118		      !	b = double2uint64_t(&(d16[1]));

/* 0x004c	 118 */		cmp	%i2,0
/* 0x0050	 117 */		srlx	%g4,%l1,%i4
                       .L900000316:
/* 0x0054	 118 */		bne,pn	%xcc,.L77000222
/* 0x0058	 134 */		sub	%i3,1,%l3
                       .L77000221:
/* 0x005c	 118 */		or	%g0,0,%i2
/* 0x0060	     */		ba	.L900000315
/* 0x0064	 116 */		or	%g0,0,%o3
                       .L77000222:
/* 0x0068	 118 */		srlx	%i2,52,%l6
/* 0x006c	     */		sethi	%hi(0xfff00000),%g4
/* 0x0070	     */		sllx	%g4,32,%i5
/* 0x0074	     */		sethi	%hi(0x40000000),%l5
/* 0x0078	     */		xor	%i5,-1,%l4
/* 0x007c	     */		or	%g0,1023,%l2
/* 0x0080	     */		and	%i2,%l4,%l7
/* 0x0084	     */		sllx	%l5,22,%i2
/* 0x0088	     */		sub	%l2,%l6,%g1
/* 0x008c	     */		or	%l7,%i2,%g3
/* 0x0090	     */		add	%g1,52,%g2
/* 0x0094	 116 */		or	%g0,0,%o3
/* 0x0098	 118 */		srlx	%g3,%g2,%i2

!  119		      !	for (i = 0; i < ilen - 1; i++) {

                       .L900000315:
/* 0x009c	 119 */		cmp	%l3,0
/* 0x00a0	     */		ble,pn	%icc,.L77000210
/* 0x00a4	     */		or	%g0,0,%l4
                       .L77000245:
/* 0x00a8	 118 */		sethi	%hi(0xfff00000),%l7
/* 0x00ac	     */		or	%g0,-1,%l6
/* 0x00b0	     */		sllx	%l7,32,%l3
/* 0x00b4	     */		srl	%l6,0,%l6
/* 0x00b8	     */		sethi	%hi(0x40000000),%l1
/* 0x00bc	     */		sethi	%hi(0xfc00),%l2
/* 0x00c0	     */		xor	%l3,-1,%l7
/* 0x00c4	     */		sllx	%l1,22,%l3
/* 0x00c8	     */		sub	%i3,2,%l5
/* 0x00cc	     */		add	%l2,1023,%l2
/* 0x00d0	     */		or	%g0,2,%g2
/* 0x00d4	     */		or	%g0,%i0,%g1

!  120		      !		c = double2uint64_t(&(d16[2 * i + 2]));

                       .L77000208:
/* 0x00d8	 120 */		sra	%g2,0,%g3
/* 0x00dc	 123 */		add	%g2,1,%o2
/* 0x00e0	 120 */		sllx	%g3,3,%i3

!  121		      !		t1 += a & 0xffffffff;
!  122		      !		t = (a >> 32);
!  123		      !		d = double2uint64_t(&(d16[2 * i + 3]));

/* 0x00e4	 123 */		sra	%o2,0,%g5
/* 0x00e8	 120 */		ldx	[%i1+%i3],%o5
/* 0x00ec	 123 */		sllx	%g5,3,%o0
/* 0x00f0	 121 */		and	%i4,%l6,%g4
/* 0x00f4	 123 */		ldx	[%i1+%o0],%i3
/* 0x00f8	 120 */		cmp	%o5,0
/* 0x00fc	     */		bne,pn	%xcc,.L77000228
/* 0x0100	 124 */		and	%i2,%l2,%i5
                       .L77000227:
/* 0x0104	 120 */		or	%g0,0,%l1
/* 0x0108	     */		ba	.L900000314
/* 0x010c	 121 */		add	%o3,%g4,%o0
                       .L77000228:
/* 0x0110	 120 */		srlx	%o5,52,%o7
/* 0x0114	     */		and	%o5,%l7,%o5
/* 0x0118	     */		or	%g0,52,%l0
/* 0x011c	     */		sub	%o7,1023,%o4
/* 0x0120	     */		or	%o5,%l3,%l1
/* 0x0124	     */		sub	%l0,%o4,%o1
/* 0x0128	     */		srlx	%l1,%o1,%l1
/* 0x012c	 121 */		add	%o3,%g4,%o0
                       .L900000314:
/* 0x0130	 122 */		srax	%i4,32,%g3
/* 0x0134	 123 */		cmp	%i3,0
/* 0x0138	     */		bne,pn	%xcc,.L77000234
/* 0x013c	 124 */		sllx	%i5,16,%g5
                       .L77000233:
/* 0x0140	 123 */		or	%g0,0,%o2
/* 0x0144	     */		ba	.L900000313
/* 0x0148	 124 */		add	%o0,%g5,%o7
                       .L77000234:
/* 0x014c	 123 */		srlx	%i3,52,%o2
/* 0x0150	     */		and	%i3,%l7,%i4
/* 0x0154	     */		sub	%o2,1023,%o1
/* 0x0158	     */		or	%g0,52,%g4
/* 0x015c	     */		sub	%g4,%o1,%i5
/* 0x0160	     */		or	%i4,%l3,%i3
/* 0x0164	     */		srlx	%i3,%i5,%o2

!  124		      !		t1 += (b & 0xffff) << 16;

/* 0x0168	 124 */		add	%o0,%g5,%o7

!  125		      !		t += (b >> 16) + (t1 >> 32);

                       .L900000313:
/* 0x016c	 125 */		srax	%i2,16,%l0
/* 0x0170	     */		srax	%o7,32,%o4
/* 0x0174	     */		add	%l0,%o4,%o3

!  126		      !		i32[i] = t1 & 0xffffffff;
!  127		      !		t1 = t;
!  128		      !		a = c;
!  129		      !		b = d;

/* 0x0178	 129 */		add	%l4,1,%l4
/* 0x017c	 126 */		and	%o7,%l6,%o5
/* 0x0180	 125 */		add	%g3,%o3,%o3
/* 0x0184	 126 */		st	%o5,[%g1]
/* 0x0188	 128 */		or	%g0,%l1,%i4
/* 0x018c	 129 */		or	%g0,%o2,%i2
/* 0x0190	     */		add	%g2,2,%g2
/* 0x0194	     */		cmp	%l4,%l5
/* 0x0198	     */		ble,pt	%icc,.L77000208
/* 0x019c	     */		add	%g1,4,%g1

!  130		      !	}
!  131		      !	t1 += a & 0xffffffff;
!  132		      !	t = (a >> 32);
!  133		      !	t1 += (b & 0xffff) << 16;
!  134		      !	i32[i] = t1 & 0xffffffff;

                       .L77000210:
/* 0x01a0	 134 */		sra	%l4,0,%l4
/* 0x01a4	     */		sethi	%hi(0xfc00),%i1
/* 0x01a8	     */		add	%o3,%i4,%l2
/* 0x01ac	     */		add	%i1,1023,%i5
/* 0x01b0	     */		and	%i2,%i5,%l5
/* 0x01b4	     */		sllx	%l4,2,%i2
/* 0x01b8	     */		sllx	%l5,16,%l6
/* 0x01bc	     */		add	%l2,%l6,%l7
/* 0x01c0	     */		st	%l7,[%i0+%i2]
/* 0x01c4	 129 */		ret	! Result =
/* 0x01c8	     */		restore	%g0,%g0,%g0
/* 0x01cc	   0 */		.type	conv_d16_to_i32,2
/* 0x01cc	   0 */		.size	conv_d16_to_i32,(.-conv_d16_to_i32)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       ___const_seg_900000401:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	     */		.word	1127219200
/* 0x000c	   0 */		.type	___const_seg_900000401,1
/* 0x000c	   0 */		.size	___const_seg_900000401,(.-___const_seg_900000401)
/* 0x000c	   0 */		.align	8
/* 0x0010	     */		.skip	24
/* 0x0028	     */		.align	32

!  135		      !}
!  138		      !void
!  139		      !conv_i32_to_d32(double *d32, uint32_t *i32, int len)
!  140		      !{

!
! SUBROUTINE conv_i32_to_d32
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

			.global conv_i32_to_d32
                       conv_i32_to_d32:
/* 000000	 140 */		orcc	%g0,%o2,%o2

!  141		      !	int i;
!  143		      !#pragma pipeloop(0)
!  144		      !	for (i = 0; i < len; i++)

/* 0x0004	 144 */		ble,pn	%icc,.L77000254
/* 0x0008	     */		sub	%o2,1,%o3
                       .L77000263:
/* 0x000c	 140 */		or	%g0,%o0,%o2

!  145		      !		d32[i] = (double)(i32[i]);

/* 0x0010	 145 */		add	%o3,1,%o5
/* 0x0014	 144 */		or	%g0,0,%g5
/* 0x0018	 145 */		cmp	%o5,10
/* 0x001c	     */		bl,pn	%icc,.L77000261
/* 0x0020	     */		sethi	%hi(___const_seg_900000401),%g4
                       .L900000407:
/* 0x0024	 145 */		prefetch	[%o1],0
/* 0x0028	     */		prefetch	[%o0],22
/* 0x002c	     */		sethi	%hi(___const_seg_900000401+8),%o4
/* 0x0030	     */		or	%g0,%o0,%o2
/* 0x0034	     */		prefetch	[%o1+64],0
/* 0x0038	     */		add	%o1,8,%o0
/* 0x003c	     */		sub	%o3,7,%o5
/* 0x0040	     */		prefetch	[%o2+64],22
/* 0x0044	     */		or	%g0,2,%g5
/* 0x0048	     */		prefetch	[%o2+128],22
/* 0x004c	     */		prefetch	[%o2+192],22
/* 0x0050	     */		prefetch	[%o1+128],0
/* 0x0054	     */		ld	[%o4+%lo(___const_seg_900000401+8)],%f2
/* 0x0058	     */		ldd	[%g4+%lo(___const_seg_900000401)],%f16
/* 0x005c	     */		fmovs	%f2,%f0
/* 0x0060	     */		prefetch	[%o2+256],22
/* 0x0064	     */		prefetch	[%o2+320],22
/* 0x0068	     */		ld	[%o1],%f3
/* 0x006c	     */		prefetch	[%o1+192],0
/* 0x0070	     */		ld	[%o1+4],%f1
                       .L900000405:
/* 0x0074	 145 */		prefetch	[%o0+188],0
/* 0x0078	     */		fsubd	%f2,%f16,%f22
/* 0x007c	     */		add	%g5,8,%g5
/* 0x0080	     */		add	%o0,32,%o0
/* 0x0084	     */		ld	[%o4+%lo(___const_seg_900000401+8)],%f4
/* 0x0088	     */		std	%f22,[%o2]
/* 0x008c	     */		cmp	%g5,%o5
/* 0x0090	     */		ld	[%o0-32],%f5
/* 0x0094	     */		fsubd	%f0,%f16,%f24
/* 0x0098	     */		add	%o2,64,%o2
/* 0x009c	     */		fmovs	%f4,%f0
/* 0x00a0	     */		std	%f24,[%o2-56]
/* 0x00a4	     */		ld	[%o0-28],%f1
/* 0x00a8	     */		fsubd	%f4,%f16,%f26
/* 0x00ac	     */		fmovs	%f0,%f6
/* 0x00b0	     */		prefetch	[%o2+312],22
/* 0x00b4	     */		std	%f26,[%o2-48]
/* 0x00b8	     */		ld	[%o0-24],%f7
/* 0x00bc	     */		fsubd	%f0,%f16,%f28
/* 0x00c0	     */		fmovs	%f6,%f8
/* 0x00c4	     */		std	%f28,[%o2-40]
/* 0x00c8	     */		ld	[%o0-20],%f9
/* 0x00cc	     */		fsubd	%f6,%f16,%f30
/* 0x00d0	     */		fmovs	%f8,%f10
/* 0x00d4	     */		std	%f30,[%o2-32]
/* 0x00d8	     */		ld	[%o0-16],%f11
/* 0x00dc	     */		prefetch	[%o2+344],22
/* 0x00e0	     */		fsubd	%f8,%f16,%f48
/* 0x00e4	     */		fmovs	%f10,%f12
/* 0x00e8	     */		std	%f48,[%o2-24]
/* 0x00ec	     */		ld	[%o0-12],%f13
/* 0x00f0	     */		fsubd	%f10,%f16,%f50
/* 0x00f4	     */		fmovs	%f12,%f2
/* 0x00f8	     */		std	%f50,[%o2-16]
/* 0x00fc	     */		ld	[%o0-8],%f3
/* 0x0100	     */		fsubd	%f12,%f16,%f52
/* 0x0104	     */		fmovs	%f2,%f0
/* 0x0108	     */		std	%f52,[%o2-8]
/* 0x010c	     */		ble,pt	%icc,.L900000405
/* 0x0110	     */		ld	[%o0-4],%f1
                       .L900000408:
/* 0x0114	 145 */		fsubd	%f2,%f16,%f18
/* 0x0118	     */		add	%o2,16,%o2
/* 0x011c	     */		cmp	%g5,%o3
/* 0x0120	     */		std	%f18,[%o2-16]
/* 0x0124	     */		fsubd	%f0,%f16,%f20
/* 0x0128	     */		or	%g0,%o0,%o1
/* 0x012c	     */		bg,pn	%icc,.L77000254
/* 0x0130	     */		std	%f20,[%o2-8]
                       .L77000261:
/* 0x0134	 145 */		ld	[%o1],%f15
                       .L900000409:
/* 0x0138	 145 */		sethi	%hi(___const_seg_900000401+8),%o4
/* 0x013c	     */		ldd	[%g4+%lo(___const_seg_900000401)],%f16
/* 0x0140	     */		add	%g5,1,%g5
/* 0x0144	     */		ld	[%o4+%lo(___const_seg_900000401+8)],%f14
/* 0x0148	     */		add	%o1,4,%o1
/* 0x014c	     */		cmp	%g5,%o3
/* 0x0150	     */		fsubd	%f14,%f16,%f54
/* 0x0154	     */		std	%f54,[%o2]
/* 0x0158	     */		add	%o2,8,%o2
/* 0x015c	     */		ble,a,pt	%icc,.L900000409
/* 0x0160	     */		ld	[%o1],%f15
                       .L77000254:
/* 0x0164	 145 */		retl	! Result =
/* 0x0168	     */		nop
/* 0x016c	   0 */		.type	conv_i32_to_d32,2
/* 0x016c	   0 */		.size	conv_i32_to_d32,(.-conv_i32_to_d32)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       ___const_seg_900000501:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	     */		.word	1127219200
/* 0x000c	   0 */		.type	___const_seg_900000501,1
/* 0x000c	   0 */		.size	___const_seg_900000501,(.-___const_seg_900000501)
/* 0x000c	   0 */		.align	8
/* 0x0010	     */		.skip	24
/* 0x0028	     */		.align	32

!  146		      !}
!  149		      !void
!  150		      !conv_i32_to_d16(double *d16, uint32_t *i32, int len)
!  151		      !{

!
! SUBROUTINE conv_i32_to_d16
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

			.global conv_i32_to_d16
                       conv_i32_to_d16:
/* 000000	 151 */		save	%sp,-368,%sp
/* 0x0004	     */		orcc	%g0,%i2,%i2

!  152		      !	int i;
!  153		      !	uint32_t a;
!  155		      !#pragma pipeloop(0)
!  156		      !	for (i = 0; i < len; i++) {

/* 0x0008	 156 */		ble,pn	%icc,.L77000272
/* 0x000c	     */		sub	%i2,1,%l6
                       .L77000281:
/* 0x0010	 156 */		sethi	%hi(0xfc00),%i3

!  157		      !		a = i32[i];

/* 0x0014	 157 */		or	%g0,%i2,%l1
/* 0x0018	 156 */		add	%i3,1023,%i4
/* 0x001c	 157 */		cmp	%i2,4
/* 0x0020	 151 */		or	%g0,%i1,%l7
/* 0x0024	     */		or	%g0,%i0,%i2
/* 0x0028	 156 */		or	%g0,0,%i5
/* 0x002c	     */		or	%g0,0,%i3
/* 0x0030	 157 */		bl,pn	%icc,.L77000279
/* 0x0034	   0 */		sethi	%hi(___const_seg_900000501),%i1
                       .L900000508:
/* 0x0038	 157 */		prefetch	[%i0+8],22
/* 0x003c	     */		prefetch	[%i0+72],22
/* 0x0040	     */		or	%g0,%i0,%l2

!  158		      !		d16[2 * i] = (double)(a & 0xffff);

/* 0x0044	 158 */		sethi	%hi(___const_seg_900000501+8),%l1
/* 0x0048	 157 */		prefetch	[%i0+136],22
/* 0x004c	     */		sub	%l6,1,%i0
/* 0x0050	     */		or	%g0,0,%i3
/* 0x0054	     */		prefetch	[%i2+200],22
/* 0x0058	     */		or	%g0,2,%i5
/* 0x005c	     */		prefetch	[%i2+264],22
/* 0x0060	     */		prefetch	[%i2+328],22
/* 0x0064	     */		prefetch	[%i2+392],22
/* 0x0068	     */		ld	[%l7],%l3
/* 0x006c	     */		ld	[%l7+4],%l4
/* 0x0070	 158 */		ldd	[%i1+%lo(___const_seg_900000501)],%f20

!  159		      !		d16[2 * i + 1] = (double)(a >> 16);

/* 0x0074	 159 */		srl	%l3,16,%o1
/* 0x0078	 158 */		and	%l3,%i4,%o3
/* 0x007c	     */		st	%o3,[%sp+2335]
/* 0x0080	 159 */		srl	%l4,16,%g4
/* 0x0084	 158 */		and	%l4,%i4,%o0
/* 0x0088	     */		st	%o0,[%sp+2303]
/* 0x008c	 159 */		add	%l7,8,%l7
/* 0x0090	     */		st	%o1,[%sp+2271]
/* 0x0094	     */		st	%g4,[%sp+2239]
/* 0x0098	 157 */		prefetch	[%i2+456],22
/* 0x009c	     */		prefetch	[%i2+520],22
                       .L900000506:
/* 0x00a0	 157 */		prefetch	[%l2+536],22
/* 0x00a4	 159 */		add	%i5,2,%i5
/* 0x00a8	 157 */		add	%l2,32,%l2
/* 0x00ac	     */		ld	[%l7],%g2
/* 0x00b0	 159 */		cmp	%i5,%i0
/* 0x00b4	     */		add	%l7,8,%l7
/* 0x00b8	 158 */		ld	[%sp+2335],%f9
/* 0x00bc	 159 */		add	%i3,4,%i3
/* 0x00c0	 158 */		ld	[%l1+%lo(___const_seg_900000501+8)],%f8
/* 0x00c4	 159 */		ld	[%sp+2271],%f11
/* 0x00c8	 158 */		and	%g2,%i4,%g3
/* 0x00cc	 159 */		fmovs	%f8,%f10
/* 0x00d0	 158 */		st	%g3,[%sp+2335]
/* 0x00d4	     */		fsubd	%f8,%f20,%f28
/* 0x00d8	     */		std	%f28,[%l2-32]
/* 0x00dc	 159 */		srl	%g2,16,%g1
/* 0x00e0	     */		st	%g1,[%sp+2271]
/* 0x00e4	     */		fsubd	%f10,%f20,%f30
/* 0x00e8	     */		std	%f30,[%l2-24]
/* 0x00ec	 157 */		ld	[%l7-4],%l0
/* 0x00f0	 158 */		ld	[%sp+2303],%f13
/* 0x00f4	     */		ld	[%l1+%lo(___const_seg_900000501+8)],%f12
/* 0x00f8	 159 */		ld	[%sp+2239],%f15
/* 0x00fc	 158 */		and	%l0,%i4,%l5
/* 0x0100	 159 */		fmovs	%f12,%f14
/* 0x0104	 158 */		st	%l5,[%sp+2303]
/* 0x0108	     */		fsubd	%f12,%f20,%f44
/* 0x010c	     */		std	%f44,[%l2-16]
/* 0x0110	 159 */		srl	%l0,16,%o5
/* 0x0114	     */		st	%o5,[%sp+2239]
/* 0x0118	     */		fsubd	%f14,%f20,%f46
/* 0x011c	     */		ble,pt	%icc,.L900000506
/* 0x0120	     */		std	%f46,[%l2-8]
                       .L900000509:
/* 0x0124	 158 */		ld	[%l1+%lo(___const_seg_900000501+8)],%f0
/* 0x0128	 159 */		cmp	%i5,%l6
/* 0x012c	     */		add	%i3,4,%i3
/* 0x0130	 158 */		ld	[%sp+2335],%f1
/* 0x0134	     */		ld	[%sp+2303],%f5
/* 0x0138	 159 */		fmovs	%f0,%f2
/* 0x013c	     */		ld	[%sp+2271],%f3
/* 0x0140	 158 */		fmovs	%f0,%f4
/* 0x0144	 159 */		ld	[%sp+2239],%f7
/* 0x0148	     */		fmovs	%f0,%f6
/* 0x014c	 158 */		fsubd	%f0,%f20,%f22
/* 0x0150	     */		std	%f22,[%l2]
/* 0x0154	 159 */		fsubd	%f2,%f20,%f24
/* 0x0158	     */		std	%f24,[%l2+8]
/* 0x015c	 158 */		fsubd	%f4,%f20,%f26
/* 0x0160	     */		std	%f26,[%l2+16]
/* 0x0164	 159 */		fsubd	%f6,%f20,%f20
/* 0x0168	     */		bg,pn	%icc,.L77000272
/* 0x016c	     */		std	%f20,[%l2+24]
                       .L77000279:
/* 0x0170	 157 */		ld	[%l7],%l2
                       .L900000510:
/* 0x0174	 158 */		and	%l2,%i4,%o4
/* 0x0178	     */		st	%o4,[%sp+2399]
/* 0x017c	 159 */		srl	%l2,16,%o2
/* 0x0180	     */		st	%o2,[%sp+2367]
/* 0x0184	 158 */		sethi	%hi(___const_seg_900000501+8),%l1
/* 0x0188	     */		sra	%i3,0,%i0
/* 0x018c	     */		ld	[%l1+%lo(___const_seg_900000501+8)],%f16
/* 0x0190	     */		sllx	%i0,3,%o1
/* 0x0194	 159 */		add	%i3,1,%o3
/* 0x0198	 158 */		ldd	[%i1+%lo(___const_seg_900000501)],%f20
/* 0x019c	 159 */		sra	%o3,0,%l3
/* 0x01a0	     */		add	%i5,1,%i5
/* 0x01a4	 158 */		ld	[%sp+2399],%f17
/* 0x01a8	 159 */		sllx	%l3,3,%o0
/* 0x01ac	     */		add	%l7,4,%l7
/* 0x01b0	     */		fmovs	%f16,%f18
/* 0x01b4	     */		cmp	%i5,%l6
/* 0x01b8	     */		add	%i3,2,%i3
/* 0x01bc	 158 */		fsubd	%f16,%f20,%f48
/* 0x01c0	     */		std	%f48,[%i2+%o1]
/* 0x01c4	 159 */		ld	[%sp+2367],%f19
/* 0x01c8	     */		fsubd	%f18,%f20,%f50
/* 0x01cc	     */		std	%f50,[%i2+%o0]
/* 0x01d0	     */		ble,a,pt	%icc,.L900000510
/* 0x01d4	 157 */		ld	[%l7],%l2
                       .L77000272:
/* 0x01d8	 159 */		ret	! Result =
/* 0x01dc	     */		restore	%g0,%g0,%g0
/* 0x01e0	   0 */		.type	conv_i32_to_d16,2
/* 0x01e0	   0 */		.size	conv_i32_to_d16,(.-conv_i32_to_d16)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       ___const_seg_900000601:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	     */		.word	1127219200
/* 0x000c	   0 */		.type	___const_seg_900000601,1
/* 0x000c	   0 */		.size	___const_seg_900000601,(.-___const_seg_900000601)
/* 0x000c	   0 */		.align	8
/* 0x0010	     */		.skip	24
/* 0x0028	     */		.align	32

!  160		      !	}
!  161		      !}
!  163		      !#ifdef RF_INLINE_MACROS
!  165		      !void
!  166		      !i16_to_d16_and_d32x4(const double *,	/* 1/(2^16) */
!  167		      !			const double *,	/* 2^16 */
!  168		      !			const double *,	/* 0 */
!  169		      !			double *,	/* result16 */
!  170		      !			double *,	/* result32 */
!  171		      !			float *);	/* source - should be unsigned int* */
!  172		      !					/* converted to float* */
!  174		      !#else
!  177		      !/* ARGSUSED */
!  178		      !static void
!  179		      !i16_to_d16_and_d32x4(const double *dummy1,	/* 1/(2^16) */
!  180		      !			const double *dummy2,	/* 2^16 */
!  181		      !			const double *dummy3,	/* 0 */
!  182		      !			double *result16,
!  183		      !			double *result32,
!  184		      !			float *src)	/* source - should be unsigned int* */
!  185		      !					/* converted to float* */
!  186		      !{
!  187		      !	uint32_t *i32;
!  188		      !	uint32_t a, b, c, d;
!  190		      !	i32 = (uint32_t *)src;
!  191		      !	a = i32[0];
!  192		      !	b = i32[1];
!  193		      !	c = i32[2];
!  194		      !	d = i32[3];
!  195		      !	result16[0] = (double)(a & 0xffff);
!  196		      !	result16[1] = (double)(a >> 16);
!  197		      !	result32[0] = (double)a;
!  198		      !	result16[2] = (double)(b & 0xffff);
!  199		      !	result16[3] = (double)(b >> 16);
!  200		      !	result32[1] = (double)b;
!  201		      !	result16[4] = (double)(c & 0xffff);
!  202		      !	result16[5] = (double)(c >> 16);
!  203		      !	result32[2] = (double)c;
!  204		      !	result16[6] = (double)(d & 0xffff);
!  205		      !	result16[7] = (double)(d >> 16);
!  206		      !	result32[3] = (double)d;
!  207		      !}
!  209		      !#endif
!  212		      !void
!  213		      !conv_i32_to_d32_and_d16(double *d32, double *d16, uint32_t *i32, int len)
!  214		      !{

!
! SUBROUTINE conv_i32_to_d32_and_d16
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

			.global conv_i32_to_d32_and_d16
                       conv_i32_to_d32_and_d16:
/* 000000	 214 */		save	%sp,-368,%sp

!  215		      !	int i;
!  216		      !	uint32_t a;
!  218		      !#pragma pipeloop(0)
!  219		      !	for (i = 0; i < len - 3; i += 4) {
!  220		      !		i16_to_d16_and_d32x4(&TwoToMinus16, &TwoTo16, &Zero,
!  221		      !					&(d16[2*i]), &(d32[i]),
!  222		      !					(float *)(&(i32[i])));
!  223		      !	}
!  224		      !	for (; i < len; i++) {
!  225		      !		a = i32[i];
!  226		      !		d32[i] = (double)(i32[i]);
!  227		      !		d16[2 * i] = (double)(a & 0xffff);
!  228		      !		d16[2 * i + 1] = (double)(a >> 16);

/* 0x0004	 228 */		sub	%i3,3,%i4
/* 0x0008	 219 */		cmp	%i4,0
/* 0x000c	     */		ble,pn	%icc,.L77000289
/* 0x0010	     */		or	%g0,0,%i5
                       .L77000306:
/* 0x0014	 222 */		sethi	%hi(Zero),%g3
/* 0x0018	     */		sethi	%hi(TwoToMinus16),%g2
/* 0x001c	     */		sethi	%hi(TwoTo16),%o5
/* 0x0020	     */		ldd	[%g3+%lo(Zero)],%f2
/* 0x0024	 219 */		sub	%i3,4,%o4
/* 0x0028	     */		or	%g0,0,%o3
/* 0x002c	     */		or	%g0,%i0,%l6
/* 0x0030	     */		or	%g0,%i2,%l5
                       .L900000615:
/* 0x0034	 222 */		fmovd	%f2,%f26
/* 0x0038	     */		ld	[%l5],%f27
/* 0x003c	     */		sra	%o3,0,%o0
/* 0x0040	     */		add	%i5,4,%i5
/* 0x0044	     */		fmovd	%f2,%f28
/* 0x0048	     */		ld	[%l5+4],%f29
/* 0x004c	     */		sllx	%o0,3,%g5
/* 0x0050	     */		cmp	%i5,%o4
/* 0x0054	     */		fmovd	%f2,%f30
/* 0x0058	     */		ld	[%l5+8],%f31
/* 0x005c	     */		add	%i1,%g5,%g4
/* 0x0060	     */		add	%o3,8,%o3
/* 0x0064	     */		ld	[%l5+12],%f3
/* 0x0068	     */		fxtod	%f26,%f26
/* 0x006c	     */		ldd	[%g2+%lo(TwoToMinus16)],%f32
/* 0x0070	     */		fxtod	%f28,%f28
/* 0x0074	     */		add	%l5,16,%l5
/* 0x0078	     */		fxtod	%f30,%f30
/* 0x007c	     */		ldd	[%o5+%lo(TwoTo16)],%f34
/* 0x0080	     */		fxtod	%f2,%f2
/* 0x0084	     */		std	%f2,[%l6+24]
/* 0x0088	     */		fmuld	%f32,%f26,%f36
/* 0x008c	     */		std	%f26,[%l6]
/* 0x0090	     */		fmuld	%f32,%f28,%f38
/* 0x0094	     */		std	%f28,[%l6+8]
/* 0x0098	     */		fmuld	%f32,%f30,%f40
/* 0x009c	     */		std	%f30,[%l6+16]
/* 0x00a0	     */		fmuld	%f32,%f2,%f42
/* 0x00a4	     */		add	%l6,32,%l6
/* 0x00a8	     */		fdtox	%f36,%f36
/* 0x00ac	     */		fdtox	%f38,%f38
/* 0x00b0	     */		fdtox	%f40,%f40
/* 0x00b4	     */		fdtox	%f42,%f42
/* 0x00b8	     */		fxtod	%f36,%f36
/* 0x00bc	     */		std	%f36,[%g4+8]
/* 0x00c0	     */		fxtod	%f38,%f38
/* 0x00c4	     */		std	%f38,[%g4+24]
/* 0x00c8	     */		fxtod	%f40,%f40
/* 0x00cc	     */		std	%f40,[%g4+40]
/* 0x00d0	     */		fxtod	%f42,%f42
/* 0x00d4	     */		std	%f42,[%g4+56]
/* 0x00d8	     */		fmuld	%f36,%f34,%f36
/* 0x00dc	     */		fmuld	%f38,%f34,%f38
/* 0x00e0	     */		fmuld	%f40,%f34,%f40
/* 0x00e4	     */		fmuld	%f42,%f34,%f42
/* 0x00e8	     */		fsubd	%f26,%f36,%f36
/* 0x00ec	     */		std	%f36,[%i1+%g5]
/* 0x00f0	     */		fsubd	%f28,%f38,%f38
/* 0x00f4	     */		std	%f38,[%g4+16]
/* 0x00f8	     */		fsubd	%f30,%f40,%f40
/* 0x00fc	     */		std	%f40,[%g4+32]
/* 0x0100	     */		fsubd	%f2,%f42,%f42
/* 0x0104	     */		std	%f42,[%g4+48]
/* 0x0108	     */		ble,a,pt	%icc,.L900000615
/* 0x010c	     */		ldd	[%g3+%lo(Zero)],%f2
                       .L77000289:
/* 0x0110	 224 */		cmp	%i5,%i3
/* 0x0114	     */		bge,pn	%icc,.L77000294
/* 0x0118	     */		sethi	%hi(0xfc00),%l0
                       .L77000307:
/* 0x011c	 224 */		sra	%i5,0,%l2
/* 0x0120	     */		sll	%i5,1,%i4
/* 0x0124	     */		sllx	%l2,3,%l1
/* 0x0128	     */		sllx	%l2,2,%o1
/* 0x012c	 225 */		sub	%i3,%i5,%l3
/* 0x0130	 224 */		add	%l0,1023,%l0
/* 0x0134	     */		add	%l1,%i0,%l1
/* 0x0138	     */		add	%o1,%i2,%i2
/* 0x013c	 225 */		cmp	%l3,5
/* 0x0140	     */		bl,pn	%icc,.L77000291
/* 0x0144	   0 */		sethi	%hi(___const_seg_900000601),%l7
                       .L900000612:
/* 0x0148	 225 */		prefetch	[%l1],22
/* 0x014c	     */		prefetch	[%l1+64],22
/* 0x0150	     */		sra	%i4,0,%l6
/* 0x0154	 226 */		sethi	%hi(___const_seg_900000601+8),%l2
/* 0x0158	 225 */		prefetch	[%l1+128],22
/* 0x015c	     */		add	%l6,-2,%l5
/* 0x0160	     */		sub	%i3,3,%i0
/* 0x0164	     */		prefetch	[%l1+192],22
/* 0x0168	     */		sllx	%l5,3,%o4
/* 0x016c	 228 */		add	%i5,1,%i5
/* 0x0170	 225 */		add	%i1,%o4,%o3
/* 0x0174	     */		or	%g0,%i3,%g1
/* 0x0178	     */		ld	[%i2],%l4
/* 0x017c	     */		prefetch	[%o3+16],22
/* 0x0180	     */		add	%o3,16,%l3
/* 0x0184	 228 */		add	%i2,4,%i2
/* 0x0188	 225 */		prefetch	[%o3+80],22
/* 0x018c	 228 */		srl	%l4,16,%o1
/* 0x0190	 227 */		and	%l4,%l0,%o0
/* 0x0194	 225 */		prefetch	[%o3+144],22
/* 0x0198	 228 */		st	%o1,[%sp+2271]
/* 0x019c	 227 */		st	%o0,[%sp+2239]
/* 0x01a0	 226 */		ldd	[%l7+%lo(___const_seg_900000601)],%f32
/* 0x01a4	 228 */		ld	[%l2+%lo(___const_seg_900000601+8)],%f0
/* 0x01a8	 225 */		prefetch	[%o3+208],22
/* 0x01ac	     */		prefetch	[%o3+272],22
/* 0x01b0	     */		prefetch	[%o3+336],22
                       .L900000610:
/* 0x01b4	 225 */		prefetch	[%l1+192],22
/* 0x01b8	 228 */		add	%i5,4,%i5
/* 0x01bc	 225 */		add	%l3,64,%l3
/* 0x01c0	 227 */		ld	[%l2+%lo(___const_seg_900000601+8)],%f8
/* 0x01c4	 228 */		cmp	%i5,%i0
/* 0x01c8	 225 */		ld	[%i2],%g5
/* 0x01cc	 228 */		add	%i2,16,%i2
/* 0x01d0	     */		add	%l1,32,%l1
/* 0x01d4	     */		add	%i4,8,%i4
/* 0x01d8	 226 */		ld	[%i2-20],%f7
/* 0x01dc	 228 */		srl	%g5,16,%i3
/* 0x01e0	 226 */		fmovs	%f8,%f6
/* 0x01e4	 228 */		st	%i3,[%sp+2335]
/* 0x01e8	 227 */		and	%g5,%l0,%g4
/* 0x01ec	     */		st	%g4,[%sp+2303]
/* 0x01f0	 226 */		fsubd	%f6,%f32,%f40
/* 0x01f4	 227 */		ld	[%sp+2239],%f9
/* 0x01f8	 228 */		ld	[%sp+2271],%f1
/* 0x01fc	     */		fmovs	%f8,%f12
/* 0x0200	 226 */		std	%f40,[%l1-32]
/* 0x0204	 227 */		fsubd	%f8,%f32,%f42
/* 0x0208	     */		std	%f42,[%l3-64]
/* 0x020c	 228 */		fsubd	%f0,%f32,%f44
/* 0x0210	     */		std	%f44,[%l3-56]
/* 0x0214	 227 */		fmovs	%f12,%f10
/* 0x0218	 225 */		ld	[%i2-12],%g2
/* 0x021c	 226 */		ld	[%i2-16],%f1
/* 0x0220	 228 */		srl	%g2,16,%g3
/* 0x0224	 226 */		fmovs	%f12,%f0
/* 0x0228	 225 */		prefetch	[%l3+320],22
/* 0x022c	 228 */		st	%g3,[%sp+2271]
/* 0x0230	 227 */		and	%g2,%l0,%l6
/* 0x0234	     */		st	%l6,[%sp+2239]
/* 0x0238	 226 */		fsubd	%f0,%f32,%f46
/* 0x023c	 227 */		ld	[%sp+2303],%f11
/* 0x0240	 228 */		ld	[%sp+2335],%f13
/* 0x0244	     */		fmovs	%f12,%f18
/* 0x0248	 226 */		std	%f46,[%l1-24]
/* 0x024c	 227 */		fsubd	%f10,%f32,%f48
/* 0x0250	     */		std	%f48,[%l3-48]
/* 0x0254	 228 */		fsubd	%f12,%f32,%f50
/* 0x0258	     */		std	%f50,[%l3-40]
/* 0x025c	 227 */		fmovs	%f18,%f16
/* 0x0260	 225 */		ld	[%i2-8],%o5
/* 0x0264	 226 */		ld	[%i2-12],%f15
/* 0x0268	 228 */		srl	%o5,16,%l5
/* 0x026c	 226 */		fmovs	%f18,%f14
/* 0x0270	 228 */		st	%l5,[%sp+2335]
/* 0x0274	 227 */		and	%o5,%l0,%o4
/* 0x0278	     */		st	%o4,[%sp+2303]
/* 0x027c	 226 */		fsubd	%f14,%f32,%f52
/* 0x0280	 227 */		ld	[%sp+2239],%f17
/* 0x0284	 228 */		ld	[%sp+2271],%f19
/* 0x0288	 225 */		prefetch	[%l3+352],22
/* 0x028c	 228 */		fmovs	%f18,%f24
/* 0x0290	 226 */		std	%f52,[%l1-16]
/* 0x0294	 227 */		fsubd	%f16,%f32,%f54
/* 0x0298	     */		std	%f54,[%l3-32]
/* 0x029c	 228 */		fsubd	%f18,%f32,%f56
/* 0x02a0	     */		std	%f56,[%l3-24]
/* 0x02a4	 227 */		fmovs	%f24,%f22
/* 0x02a8	 225 */		ld	[%i2-4],%l4
/* 0x02ac	 226 */		ld	[%i2-8],%f21
/* 0x02b0	 228 */		srl	%l4,16,%o3
/* 0x02b4	 226 */		fmovs	%f24,%f20
/* 0x02b8	 228 */		st	%o3,[%sp+2271]
/* 0x02bc	 227 */		and	%l4,%l0,%o2
/* 0x02c0	     */		st	%o2,[%sp+2239]
/* 0x02c4	 226 */		fsubd	%f20,%f32,%f58
/* 0x02c8	 227 */		ld	[%sp+2303],%f23
/* 0x02cc	 228 */		ld	[%sp+2335],%f25
/* 0x02d0	     */		fmovs	%f24,%f0
/* 0x02d4	 226 */		std	%f58,[%l1-8]
/* 0x02d8	 227 */		fsubd	%f22,%f32,%f60
/* 0x02dc	     */		std	%f60,[%l3-16]
/* 0x02e0	 228 */		fsubd	%f24,%f32,%f62
/* 0x02e4	     */		bl,pt	%icc,.L900000610
/* 0x02e8	     */		std	%f62,[%l3-8]
                       .L900000613:
/* 0x02ec	 227 */		ld	[%l2+%lo(___const_seg_900000601+8)],%f4
/* 0x02f0	 228 */		add	%l1,8,%l1
/* 0x02f4	     */		cmp	%i5,%g1
/* 0x02f8	 226 */		ld	[%i2-4],%f3
/* 0x02fc	 225 */		or	%g0,%g1,%i3
/* 0x0300	 228 */		add	%i4,2,%i4
/* 0x0304	 227 */		ld	[%sp+2239],%f5
/* 0x0308	 226 */		fmovs	%f4,%f2
/* 0x030c	 228 */		ld	[%sp+2271],%f1
/* 0x0310	 226 */		fsubd	%f2,%f32,%f34
/* 0x0314	     */		std	%f34,[%l1-8]
/* 0x0318	 227 */		fsubd	%f4,%f32,%f36
/* 0x031c	     */		std	%f36,[%l3]
/* 0x0320	 228 */		fsubd	%f0,%f32,%f38
/* 0x0324	     */		bge,pn	%icc,.L77000294
/* 0x0328	     */		std	%f38,[%l3+8]
                       .L77000291:
/* 0x032c	 225 */		ld	[%i2],%o2
                       .L900000614:
/* 0x0330	 226 */		ldd	[%l7+%lo(___const_seg_900000601)],%f32
/* 0x0334	 228 */		srl	%o2,16,%l3
/* 0x0338	 227 */		sra	%i4,0,%i0
/* 0x033c	 228 */		st	%l3,[%sp+2367]
/* 0x0340	 227 */		and	%o2,%l0,%g1
/* 0x0344	 226 */		sethi	%hi(___const_seg_900000601+8),%l2
/* 0x0348	 227 */		st	%g1,[%sp+2399]
/* 0x034c	     */		sllx	%i0,3,%o0
/* 0x0350	 228 */		add	%i4,1,%l4
/* 0x0354	 226 */		ld	[%l2+%lo(___const_seg_900000601+8)],%f4
/* 0x0358	 228 */		sra	%l4,0,%o1
/* 0x035c	     */		add	%i5,1,%i5
/* 0x0360	 226 */		ld	[%i2],%f5
/* 0x0364	 228 */		sllx	%o1,3,%g5
/* 0x0368	     */		cmp	%i5,%i3
/* 0x036c	     */		ld	[%sp+2367],%f9
/* 0x0370	     */		add	%i2,4,%i2
/* 0x0374	     */		add	%i4,2,%i4
/* 0x0378	 227 */		fmovs	%f4,%f6
/* 0x037c	 226 */		fsubd	%f4,%f32,%f44
/* 0x0380	     */		std	%f44,[%l1]
/* 0x0384	 227 */		ld	[%sp+2399],%f7
/* 0x0388	 228 */		fmovs	%f6,%f8
/* 0x038c	     */		add	%l1,8,%l1
/* 0x0390	     */		fsubd	%f8,%f32,%f48
/* 0x0394	 227 */		fsubd	%f6,%f32,%f46
/* 0x0398	     */		std	%f46,[%i1+%o0]
/* 0x039c	 228 */		std	%f48,[%i1+%g5]
/* 0x03a0	     */		bl,a,pt	%icc,.L900000614
/* 0x03a4	 225 */		ld	[%i2],%o2
                       .L77000294:
/* 0x03a8	 222 */		ret	! Result =
/* 0x03ac	     */		restore	%g0,%g0,%g0
/* 0x03b0	   0 */		.type	conv_i32_to_d32_and_d16,2
/* 0x03b0	   0 */		.size	conv_i32_to_d32_and_d16,(.-conv_i32_to_d32_and_d16)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	32

!  229		      !	}
!  230		      !}
!  232		      !extern long long c1, c2, c3, c4;
!  234		      !static void
!  235		      !adjust_montf_result(uint32_t *i32, uint32_t *nint, int len)
!  236		      !{

!
! SUBROUTINE adjust_montf_result
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       adjust_montf_result:
/* 000000	 236 */		sra	%o2,0,%g2
/* 0x0004	     */		or	%g0,%o0,%o4

!  237		      !	int64_t acc;
!  238		      !	int i;
!  240		      !	if (i32[len] > 0) {

/* 0x0008	 240 */		sllx	%g2,2,%g3
/* 0x000c	     */		ld	[%o0+%g3],%o0
/* 0x0010	     */		cmp	%o0,0
/* 0x0014	     */		bleu,pn	%icc,.L77000316
/* 0x0018	 236 */		or	%g0,%o1,%o5

!  241		      !		i = -1;

                       .L77000315:
/* 0x001c	 241 */		sub	%g2,1,%g3
/* 0x0020	     */		ba	.L900000712
/* 0x0024	 249 */		cmp	%g2,0

!  242		      !	} else {
!  243		      !		for (i = len - 1; i >= 0; i--) {

                       .L77000316:
/* 0x0028	 243 */		subcc	%g2,1,%g3
/* 0x002c	     */		bneg,pn	%icc,.L77000340
/* 0x0030	     */		or	%g0,%g3,%o3
                       .L77000348:
/* 0x0034	 243 */		sra	%g3,0,%o1
/* 0x0038	     */		sllx	%o1,2,%g1

!  244		      !			if (i32[i] != nint[i]) break;

/* 0x003c	 244 */		ld	[%g1+%o5],%g4
/* 0x0040	 243 */		add	%g1,%o4,%o2
/* 0x0044	     */		add	%g1,%o5,%o1
                       .L900000713:
/* 0x0048	 244 */		ld	[%o2],%o0
/* 0x004c	     */		cmp	%o0,%g4
/* 0x0050	     */		bne,pn	%icc,.L77000324
/* 0x0054	     */		sub	%o2,4,%o2
                       .L77000320:
/* 0x0058	 244 */		sub	%o1,4,%o1
/* 0x005c	     */		subcc	%o3,1,%o3
/* 0x0060	     */		bpos,a,pt	%icc,.L900000713
/* 0x0064	     */		ld	[%o1],%g4
                       .L900000706:
/* 0x0068	 244 */		ba	.L900000712
/* 0x006c	 249 */		cmp	%g2,0
                       .L77000324:
/* 0x0070	 244 */		sra	%o3,0,%o0
/* 0x0074	     */		sllx	%o0,2,%g1
/* 0x0078	     */		ld	[%o5+%g1],%o3
/* 0x007c	     */		ld	[%o4+%g1],%g5
/* 0x0080	     */		cmp	%g5,%o3
/* 0x0084	     */		bleu,pt	%icc,.L77000332
/* 0x0088	     */		nop

!  245		      !		}
!  246		      !	}
!  247		      !	if ((i < 0) || (i32[i] > nint[i])) {
!  248		      !		acc = 0;
!  249		      !		for (i = 0; i < len; i++) {

                       .L77000340:
/* 0x008c	 249 */		cmp	%g2,0
                       .L900000712:
/* 0x0090	 249 */		ble,pn	%icc,.L77000332
/* 0x0094	 250 */		or	%g0,%g2,%o3
                       .L77000347:
/* 0x0098	 249 */		or	%g0,0,%o0

!  250		      !			acc = acc + (uint64_t)(i32[i]) - (uint64_t)(nint[i]);

/* 0x009c	 250 */		cmp	%o3,10
/* 0x00a0	     */		bl,pn	%icc,.L77000341
/* 0x00a4	 249 */		or	%g0,0,%g2
                       .L900000709:
/* 0x00a8	 250 */		prefetch	[%o4],22
/* 0x00ac	     */		prefetch	[%o4+64],22

!  251		      !			i32[i] = acc & 0xffffffff;
!  252		      !			acc = acc >> 32;

/* 0x00b0	 252 */		add	%o5,4,%o1
/* 0x00b4	     */		add	%o4,8,%o2
/* 0x00b8	 250 */		prefetch	[%o4+128],22
/* 0x00bc	     */		sub	%o3,8,%o5
/* 0x00c0	     */		or	%g0,2,%o0
/* 0x00c4	     */		prefetch	[%o4+192],22
/* 0x00c8	     */		prefetch	[%o4+256],22
/* 0x00cc	     */		prefetch	[%o4+320],22
/* 0x00d0	     */		prefetch	[%o4+384],22
/* 0x00d4	     */		ld	[%o2-4],%g5
/* 0x00d8	     */		prefetch	[%o2+440],22
/* 0x00dc	     */		prefetch	[%o2+504],22
/* 0x00e0	     */		ld	[%o4],%g4
/* 0x00e4	     */		ld	[%o1-4],%o4
/* 0x00e8	     */		sub	%g4,%o4,%o3
/* 0x00ec	 251 */		st	%o3,[%o2-8]
/* 0x00f0	 252 */		srax	%o3,32,%g4
                       .L900000707:
/* 0x00f4	 252 */		add	%o0,8,%o0
/* 0x00f8	     */		add	%o2,32,%o2
/* 0x00fc	 250 */		ld	[%o1],%g1
/* 0x0100	     */		prefetch	[%o2+496],22
/* 0x0104	 252 */		cmp	%o0,%o5
/* 0x0108	     */		add	%o1,32,%o1
/* 0x010c	 250 */		sub	%g5,%g1,%g5
/* 0x0110	     */		add	%g5,%g4,%o4
/* 0x0114	     */		ld	[%o2-32],%g4
/* 0x0118	 251 */		st	%o4,[%o2-36]
/* 0x011c	 252 */		srax	%o4,32,%g1
/* 0x0120	 250 */		ld	[%o1-28],%o3
/* 0x0124	     */		sub	%g4,%o3,%g2
/* 0x0128	     */		add	%g2,%g1,%g5
/* 0x012c	     */		ld	[%o2-28],%o3
/* 0x0130	 251 */		st	%g5,[%o2-32]
/* 0x0134	 252 */		srax	%g5,32,%g4
/* 0x0138	 250 */		ld	[%o1-24],%o4
/* 0x013c	     */		sub	%o3,%o4,%g1
/* 0x0140	     */		add	%g1,%g4,%g2
/* 0x0144	     */		ld	[%o2-24],%o3
/* 0x0148	 251 */		st	%g2,[%o2-28]
/* 0x014c	 252 */		srax	%g2,32,%g5
/* 0x0150	 250 */		ld	[%o1-20],%o4
/* 0x0154	     */		sub	%o3,%o4,%g4
/* 0x0158	     */		add	%g4,%g5,%g1
/* 0x015c	     */		ld	[%o2-20],%o4
/* 0x0160	 251 */		st	%g1,[%o2-24]
/* 0x0164	 252 */		srax	%g1,32,%o3
/* 0x0168	 250 */		ld	[%o1-16],%g2
/* 0x016c	     */		sub	%o4,%g2,%g5
/* 0x0170	     */		add	%g5,%o3,%g1
/* 0x0174	     */		ld	[%o2-16],%g4
/* 0x0178	 251 */		st	%g1,[%o2-20]
/* 0x017c	 252 */		srax	%g1,32,%o4
/* 0x0180	 250 */		ld	[%o1-12],%g2
/* 0x0184	     */		sub	%g4,%g2,%o3
/* 0x0188	     */		add	%o3,%o4,%g5
/* 0x018c	     */		ld	[%o2-12],%g2
/* 0x0190	 251 */		st	%g5,[%o2-16]
/* 0x0194	 252 */		srax	%g5,32,%g4
/* 0x0198	 250 */		ld	[%o1-8],%g1
/* 0x019c	     */		sub	%g2,%g1,%o4
/* 0x01a0	     */		add	%o4,%g4,%o3
/* 0x01a4	     */		ld	[%o2-8],%g2
/* 0x01a8	 251 */		st	%o3,[%o2-12]
/* 0x01ac	 252 */		srax	%o3,32,%g5
/* 0x01b0	 250 */		ld	[%o1-4],%g1
/* 0x01b4	     */		sub	%g2,%g1,%g4
/* 0x01b8	     */		add	%g4,%g5,%o4
/* 0x01bc	     */		ld	[%o2-4],%g5
/* 0x01c0	 251 */		st	%o4,[%o2-8]
/* 0x01c4	 252 */		ble,pt	%icc,.L900000707
/* 0x01c8	     */		srax	%o4,32,%g4
                       .L900000710:
/* 0x01cc	 250 */		ld	[%o1],%o3
/* 0x01d0	 252 */		add	%o1,4,%o5
/* 0x01d4	 250 */		or	%g0,%o2,%o4
/* 0x01d8	 252 */		cmp	%o0,%g3
/* 0x01dc	 250 */		sub	%g5,%o3,%g2
/* 0x01e0	     */		add	%g2,%g4,%g1
/* 0x01e4	 251 */		st	%g1,[%o2-4]
/* 0x01e8	 252 */		bg,pn	%icc,.L77000332
/* 0x01ec	     */		srax	%g1,32,%g2
                       .L77000341:
/* 0x01f0	 250 */		ld	[%o4],%g5
                       .L900000711:
/* 0x01f4	 250 */		ld	[%o5],%o2
/* 0x01f8	     */		add	%g2,%g5,%g4
/* 0x01fc	 252 */		add	%o0,1,%o0
/* 0x0200	     */		cmp	%o0,%g3
/* 0x0204	     */		add	%o5,4,%o5
/* 0x0208	 250 */		sub	%g4,%o2,%o1
/* 0x020c	 251 */		st	%o1,[%o4]
/* 0x0210	 252 */		srax	%o1,32,%g2
/* 0x0214	     */		add	%o4,4,%o4
/* 0x0218	     */		ble,a,pt	%icc,.L900000711
/* 0x021c	 250 */		ld	[%o4],%g5
                       .L77000332:
/* 0x0220	 252 */		retl	! Result =
/* 0x0224	     */		nop
/* 0x0228	   0 */		.type	adjust_montf_result,2
/* 0x0228	   0 */		.size	adjust_montf_result,(.-adjust_montf_result)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	32

!  253		      !		}
!  254		      !	}
!  255		      !}
!  257		      !/*************
!  258		      !static void
!  259		      !adjust_montf_result_bad(uint32_t *i32, uint32_t *nint, int len)
!  260		      !{
!  261		      !	int64_t acc;
!  262		      !	int i;
!  264		      !	c4++;
!  265		      !
!  266		      !	if (i32[len] > 0) {
!  267		      !		i = -1;
!  268		      !		c1++;
!  269		      !	} else {
!  270		      !		for (i = len - 1; i >= 0; i++) {
!  271		      !			if (i32[i] != nint[i]) break;
!  272		      !			c2++;
!  273		      !		}
!  274		      !	}
!  275		      !	if ((i < 0) || (i32[i] > nint[i])) {
!  276		      !		c3++;
!  277		      !		acc = 0;
!  278		      !		for (i = 0; i < len; i++) {
!  279		      !			acc = acc + (uint64_t)(i32[i]) - (uint64_t)(nint[i]);
!  280		      !			i32[i] = acc & 0xffffffff;
!  281		      !			acc = acc >> 32;
!  282		      !		}
!  283		      !	}
!  284		      !}
!  285		      !uint32_t saveresult[1000];
!  286		      !void printarray(char *name, uint32_t *arr, int len)
!  287		      !{
!  288		      !	int i, j;
!  289		      !	uint64_t tmp;
!  291		      !	printf("uint64_t %s[%d] =\n{\n",name,(len+1)/2);
!  292		      !	for(i=j=0; i<len; i+=2,j+=2){
!  293		      !		if(j == 6){
!  294		      !			printf("\n");
!  295		      !			j=0;
!  296		      !		}
!  297		      !		tmp = (((uint64_t)arr[i])<<32) | ((uint64_t)arr[i+1]);
!  298		      !		printf("0x%016llx",tmp);
!  299		      !		if((i/2)!=(((len+1)/2)-1))printf(",");
!  300		      !		if(j!=4)printf(" ");
!  301		      !	}
!  302		      !	if(j!=0) printf("\n");
!  303		      !	printf("};\n");
!  304		      !}
!  305		      !**************/
!  308		      !/*
!  309		      ! * the lengths of the input arrays should be at least the following:
!  310		      ! * result[nlen+1], dm1[nlen], dm2[2*nlen+1], dt[4*nlen+2], dn[nlen], nint[nlen]
!  311		      ! * all of them should be different from one another
!  312		      ! */
!  313		      !void mont_mulf_noconv(uint32_t *result,
!  314		      !			double *dm1, double *dm2, double *dt,
!  315		      !			double *dn, uint32_t *nint,
!  316		      !			int nlen, double dn0)
!  317		      !{

!
! SUBROUTINE mont_mulf_noconv
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

			.global mont_mulf_noconv
                       mont_mulf_noconv:
/* 000000	 317 */		save	%sp,-176,%sp
/* 0x0004	     */		ldx	[%fp+2223],%g1
/* 0x0008	   0 */		sethi	%hi(Zero),%l5
/* 0x000c	 317 */		or	%g0,%i2,%l0

!  318		      !	int i, j, jj;
!  319		      !	double digit, m2j, a, b;
!  320		      !	double *pdm1, *pdm2, *pdn, *pdtj, pdn_0, pdm1_0;
!  322		      !	pdm1 = &(dm1[0]);
!  323		      !	pdm2 = &(dm2[0]);
!  324		      !	pdn = &(dn[0]);
!  325		      !	pdm2[2 * nlen] = Zero;

/* 0x0010	 325 */		ldd	[%l5+%lo(Zero)],%f0
/* 0x0014	 317 */		or	%g0,%i0,%i2
/* 0x0018	 325 */		sll	%g1,1,%o3

!  327		      !	if (nlen != 16) {

/* 0x001c	 327 */		cmp	%g1,16
/* 0x0020	 325 */		sra	%o3,0,%i0
/* 0x0024	     */		sllx	%i0,3,%o0
/* 0x0028	 317 */		or	%g0,%i5,%i0
/* 0x002c	 327 */		bne,pn	%icc,.L77000476
/* 0x0030	 325 */		std	%f0,[%l0+%o0]
                       .L77000488:
/* 0x0034	   0 */		sethi	%hi(TwoToMinus16),%o2
/* 0x0038	   0 */		sethi	%hi(TwoTo16),%l3

!  328		      !		for (i = 0; i < 4 * nlen + 2; i++)
!  329		      !			dt[i] = Zero;
!  330		      !		a = dt[0] = pdm1[0] * pdm2[0];
!  331		      !		digit = mod(lower32(a, Zero) * dn0, TwoToMinus16, TwoTo16);
!  333		      !		pdtj = &(dt[0]);
!  334		      !		for (j = jj = 0; j < 2 * nlen; j++, jj++, pdtj++) {
!  335		      !			m2j = pdm2[j];
!  336		      !			a = pdtj[0] + pdn[0] * digit;
!  337		      !			b = pdtj[1] + pdm1[0] * pdm2[j + 1] + a * TwoToMinus16;
!  338		      !			pdtj[1] = b;
!  340		      !#pragma pipeloop(0)
!  341		      !			for (i = 1; i < nlen; i++) {
!  342		      !				pdtj[2 * i] += pdm1[i] * m2j + pdn[i] * digit;
!  343		      !			}
!  344		      !			if (jj == 15) {
!  345		      !				cleanup(dt, j / 2 + 1, 2 * nlen + 1);
!  346		      !				jj = 0;
!  347		      !			}
!  349		      !			digit = mod(lower32(b, Zero) * dn0,
!  350		      !				    TwoToMinus16, TwoTo16);
!  351		      !		}
!  352		      !	} else {
!  353		      !		a = dt[0] = pdm1[0] * pdm2[0];

/* 0x003c	 353 */		ldd	[%i1],%f40

!  355		      !		dt[65] = dt[64] = dt[63] = dt[62] = dt[61] = dt[60] =
!  356		      !			dt[59] = dt[58] = dt[57] = dt[56] = dt[55] =
!  357		      !			dt[54] = dt[53] = dt[52] = dt[51] = dt[50] =
!  358		      !			dt[49] = dt[48] = dt[47] = dt[46] = dt[45] =
!  359		      !			dt[44] = dt[43] = dt[42] = dt[41] = dt[40] =
!  360		      !			dt[39] = dt[38] = dt[37] = dt[36] = dt[35] =
!  361		      !			dt[34] = dt[33] = dt[32] = dt[31] = dt[30] =
!  362		      !			dt[29] = dt[28] = dt[27] = dt[26] = dt[25] =
!  363		      !			dt[24] = dt[23] = dt[22] = dt[21] = dt[20] =
!  364		      !			dt[19] = dt[18] = dt[17] = dt[16] = dt[15] =
!  365		      !			dt[14] = dt[13] = dt[12] = dt[11] = dt[10] =
!  366		      !			dt[9] = dt[8] = dt[7] = dt[6] = dt[5] = dt[4] =
!  367		      !			dt[3] = dt[2] = dt[1] = Zero;
!  369		      !		pdn_0 = pdn[0];
!  370		      !		pdm1_0 = pdm1[0];
!  372		      !		digit = mod(lower32(a, Zero) * dn0, TwoToMinus16, TwoTo16);
!  373		      !		pdtj = &(dt[0]);

/* 0x0040	 373 */		or	%g0,%i3,%o3

!  375		      !		for (j = 0; j < 32; j++, pdtj++) {

/* 0x0044	 375 */		or	%g0,0,%l1
/* 0x0048	 353 */		ldd	[%l0],%f42
/* 0x004c	 372 */		ldd	[%o2+%lo(TwoToMinus16)],%f44
/* 0x0050	     */		ldd	[%l3+%lo(TwoTo16)],%f46
/* 0x0054	 367 */		std	%f0,[%i3+8]
/* 0x0058	 353 */		fmuld	%f40,%f42,%f38
/* 0x005c	     */		std	%f38,[%i3]
/* 0x0060	 367 */		std	%f0,[%i3+16]
/* 0x0064	     */		std	%f0,[%i3+24]
/* 0x0068	     */		std	%f0,[%i3+32]
/* 0x006c	 372 */		fdtox	%f38,%f4
/* 0x0070	 367 */		std	%f0,[%i3+40]
/* 0x0074	     */		std	%f0,[%i3+48]
/* 0x0078	     */		std	%f0,[%i3+56]
/* 0x007c	 372 */		fmovs	%f0,%f4
/* 0x0080	 367 */		std	%f0,[%i3+64]
/* 0x0084	     */		std	%f0,[%i3+72]
/* 0x0088	 372 */		fxtod	%f4,%f52
/* 0x008c	 367 */		std	%f0,[%i3+80]
/* 0x0090	     */		std	%f0,[%i3+88]
/* 0x0094	     */		std	%f0,[%i3+96]
/* 0x0098	     */		std	%f0,[%i3+104]
/* 0x009c	 372 */		fmuld	%f52,%f14,%f60
/* 0x00a0	 367 */		std	%f0,[%i3+112]
/* 0x00a4	     */		std	%f0,[%i3+120]
/* 0x00a8	     */		std	%f0,[%i3+128]
/* 0x00ac	     */		std	%f0,[%i3+136]
/* 0x00b0	 372 */		fmuld	%f60,%f44,%f62
/* 0x00b4	 367 */		std	%f0,[%i3+144]
/* 0x00b8	     */		std	%f0,[%i3+152]
/* 0x00bc	     */		std	%f0,[%i3+160]
/* 0x00c0	     */		std	%f0,[%i3+168]
/* 0x00c4	 372 */		fdtox	%f62,%f32
/* 0x00c8	 367 */		std	%f0,[%i3+176]
/* 0x00cc	     */		std	%f0,[%i3+184]
/* 0x00d0	     */		std	%f0,[%i3+192]
/* 0x00d4	     */		std	%f0,[%i3+200]
/* 0x00d8	 372 */		fxtod	%f32,%f50
/* 0x00dc	 367 */		std	%f0,[%i3+208]
/* 0x00e0	     */		std	%f0,[%i3+216]
/* 0x00e4	     */		std	%f0,[%i3+224]
/* 0x00e8	     */		std	%f0,[%i3+232]
/* 0x00ec	 372 */		fmuld	%f50,%f46,%f34
/* 0x00f0	 367 */		std	%f0,[%i3+240]
/* 0x00f4	     */		std	%f0,[%i3+248]
/* 0x00f8	     */		std	%f0,[%i3+256]
/* 0x00fc	     */		std	%f0,[%i3+264]
/* 0x0100	 372 */		fsubd	%f60,%f34,%f40
/* 0x0104	 367 */		std	%f0,[%i3+272]
/* 0x0108	     */		std	%f0,[%i3+280]
/* 0x010c	     */		std	%f0,[%i3+288]
/* 0x0110	     */		std	%f0,[%i3+296]
/* 0x0114	     */		std	%f0,[%i3+304]
/* 0x0118	     */		std	%f0,[%i3+312]
/* 0x011c	     */		std	%f0,[%i3+320]
/* 0x0120	     */		std	%f0,[%i3+328]
/* 0x0124	     */		std	%f0,[%i3+336]
/* 0x0128	     */		std	%f0,[%i3+344]
/* 0x012c	     */		std	%f0,[%i3+352]
/* 0x0130	     */		std	%f0,[%i3+360]
/* 0x0134	     */		std	%f0,[%i3+368]
/* 0x0138	 375 */		sub	%g1,1,%l3
/* 0x013c	     */		add	%i3,8,%o7
/* 0x0140	 367 */		std	%f0,[%i3+376]
/* 0x0144	     */		std	%f0,[%i3+384]
/* 0x0148	     */		std	%f0,[%i3+392]
/* 0x014c	     */		std	%f0,[%i3+400]
/* 0x0150	     */		std	%f0,[%i3+408]
/* 0x0154	     */		std	%f0,[%i3+416]
/* 0x0158	     */		std	%f0,[%i3+424]
/* 0x015c	     */		std	%f0,[%i3+432]
/* 0x0160	     */		std	%f0,[%i3+440]
/* 0x0164	     */		std	%f0,[%i3+448]
/* 0x0168	     */		std	%f0,[%i3+456]
/* 0x016c	     */		std	%f0,[%i3+464]
/* 0x0170	     */		std	%f0,[%i3+472]
/* 0x0174	     */		std	%f0,[%i3+480]
/* 0x0178	     */		std	%f0,[%i3+488]
/* 0x017c	     */		std	%f0,[%i3+496]
/* 0x0180	     */		std	%f0,[%i3+504]
/* 0x0184	     */		std	%f0,[%i3+512]
/* 0x0188	     */		std	%f0,[%i3+520]

!BEGIN HAND CODED PART

! cheetah schedule, no even-odd trick


	add	%i3,%g0,%o5

	fmovd	%f40,%f0
	fmovd	%f14,%f2
	fmovd	%f44,%f8
	sethi	%hi(TwoTo32),%l5
	fmovd	%f46,%f10
	sethi	%hi(TwoToMinus32),%g5
	ldd	[%i3],%f6
	ldd	[%l0],%f4

	ldd	[%i1],%f40
	ldd	[%i1+8],%f42
	ldd	[%i1+16],%f52
	ldd	[%i1+48],%f54
	ldd	[%i1+56],%f36
	ldd	[%i1+64],%f56
	ldd	[%i1+104],%f48
	ldd	[%i1+112],%f58

	ldd	[%i4],%f44
	ldd	[%i4+8],%f46
	ldd	[%i4+104],%f50
	ldd	[%i4+112],%f60


	.L99999999:
!1
	ldd	[%i1+24],%f20
	fmuld	%f0,%f44,%f12
!2
	ldd	[%i4+24],%f22
	fmuld	%f42,%f4,%f16
!3
	ldd	[%i1+40],%f24
	fmuld	%f46,%f0,%f18
!4
	ldd	[%i4+40],%f26
	fmuld	%f20,%f4,%f20
!5
	ldd	[%l0+8],%f38
	faddd	%f12,%f6,%f12
	fmuld	%f22,%f0,%f22
!6
	add	%l0,8,%l0
	ldd	[%i4+56],%f30
	fmuld	%f24,%f4,%f24
!7
	ldd	[%i1+72],%f32
	faddd	%f16,%f18,%f16
	fmuld	%f26,%f0,%f26
!8
	ldd	[%i3+16],%f18
	fmuld	%f40,%f38,%f14
!9
	ldd	[%i4+72],%f34
	faddd	%f20,%f22,%f20
	fmuld	%f8,%f12,%f12
!10
	ldd	[%i3+48],%f22
	fmuld	%f36,%f4,%f28
!11
	ldd	[%i3+8],%f6
	faddd	%f16,%f18,%f16
	fmuld	%f30,%f0,%f30
!12
	std	%f16,[%i3+16]
	faddd	%f24,%f26,%f24
	fmuld	%f32,%f4,%f32
!13
	ldd	[%i3+80],%f26
	faddd	%f12,%f14,%f12
	fmuld	%f34,%f0,%f34
!14
	ldd	[%i1+88],%f16
	faddd	%f20,%f22,%f20
!15
	ldd	[%i4+88],%f18
	faddd	%f28,%f30,%f28
!16
	ldd	[%i3+112],%f30
	faddd	%f32,%f34,%f32
!17
	ldd	[%i3+144],%f34
	faddd	%f12,%f6,%f6
	fmuld	%f16,%f4,%f16
!18
	std	%f20,[%i3+48]
	faddd	%f24,%f26,%f24
	fmuld	%f18,%f0,%f18
!19
	std	%f24,[%i3+80]
	faddd	%f28,%f30,%f28
	fmuld	%f48,%f4,%f20
!20
	std	%f28,[%i3+112]
	faddd	%f32,%f34,%f32
	fmuld	%f50,%f0,%f22
!21
	ldd	[%i1+120],%f24
	fdtox	%f6,%f12
!22
	std	%f32,[%i3+144]
	faddd	%f16,%f18,%f16
!23
	ldd	[%i4+120],%f26
!24
	ldd	[%i3+176],%f18
	faddd	%f20,%f22,%f20
	fmuld	%f24,%f4,%f24
!25
	ldd	[%i4+16],%f30
	fmovs	%f11,%f12
!26
	ldd	[%i1+32],%f32
	fmuld	%f26,%f0,%f26
!27
	ldd	[%i4+32],%f34
	fmuld	%f52,%f4,%f28
!28
	ldd	[%i3+208],%f22
	faddd	%f16,%f18,%f16
	fmuld	%f30,%f0,%f30
!29
	std	%f16,[%i3+176]
	fxtod	%f12,%f12
	fmuld	%f32,%f4,%f32
!30
	ldd	[%i4+48],%f18
	faddd	%f24,%f26,%f24
	fmuld	%f34,%f0,%f34
!31
	ldd	[%i3+240],%f26
	faddd	%f20,%f22,%f20
!32
	std	%f20,[%i3+208]
	faddd	%f28,%f30,%f28
	fmuld	%f54,%f4,%f16
!33
	ldd	[%i3+32],%f30
	fmuld	%f12,%f2,%f14
!34
	ldd	[%i4+64],%f22
	faddd	%f32,%f34,%f32
	fmuld	%f18,%f0,%f18
!35
	ldd	[%i3+64],%f34
	faddd	%f24,%f26,%f24
!36
	std	%f24,[%i3+240]
	faddd	%f28,%f30,%f28
	fmuld	%f56,%f4,%f20
!37
	std	%f28,[%i3+32]
	fmuld	%f14,%f8,%f12
!38
	ldd	[%i1+80],%f24
	faddd	%f32,%f34,%f34	! yes, tmp52!
	fmuld	%f22,%f0,%f22
!39
	ldd	[%i4+80],%f26
	faddd	%f16,%f18,%f16
!40
	ldd	[%i1+96],%f28
	fmuld	%f58,%f4,%f32
!41
	ldd	[%i4+96],%f30
	fdtox	%f12,%f12
	fmuld	%f24,%f4,%f24
!42
	std	%f34,[%i3+64]	! yes, tmp52!
	faddd	%f20,%f22,%f20
	fmuld	%f26,%f0,%f26
!43
	ldd	[%i3+96],%f18
	fmuld	%f28,%f4,%f28
!44
	ldd	[%i3+128],%f22
	fmovd	%f38,%f4
	fmuld	%f30,%f0,%f30
!45
	fxtod	%f12,%f12
	fmuld	%f60,%f0,%f34
!46
	add	%i3,8,%i3
	faddd	%f24,%f26,%f24
!47
	ldd	[%i3+160-8],%f26
	faddd	%f16,%f18,%f16
!48
	std	%f16,[%i3+96-8]
	faddd	%f28,%f30,%f28
!49
	ldd	[%i3+192-8],%f30
	faddd	%f32,%f34,%f32
	fmuld	%f12,%f10,%f12
!50
	ldd	[%i3+224-8],%f34
	faddd	%f20,%f22,%f20
!51
	std	%f20,[%i3+128-8]
	faddd	%f24,%f26,%f24
!52
	add	%l1,1,%l1
	std	%f24,[%i3+160-8]
	faddd	%f28,%f30,%f28
!53
	cmp	%l1,15
	std	%f28,[%i3+192-8]
	fsubd	%f14,%f12,%f0
!54
	faddd	%f32,%f34,%f32
	ble,pt	%icc,.L99999999
	std	%f32,[%i3+224-8]


!
	ldd	[%g5+%lo(TwoToMinus32)],%f8
!
	ldd	[%i3+8],%f16
!
	ldd	[%i3+16],%f20
!
	fmuld	%f8,%f16,%f18
	ldd	[%i3+24],%f24
!
	fmuld	%f8,%f20,%f22
	ldd	[%i3+32],%f28
!
	fmuld	%f8,%f24,%f26
	ldd	[%l5+%lo(TwoTo32)],%f10
!
	fmuld	%f8,%f28,%f30
!
	fdtox	%f18,%f18
!
	fdtox	%f22,%f22
!
	fdtox	%f26,%f26
	ldd	[%i3+40],%f32
!
	fdtox	%f30,%f30
	ldd	[%i3+48],%f56
!
	fxtod	%f18,%f18
	fmuld	%f8,%f32,%f34
	ldd	[%i3+56],%f36
!
	fxtod	%f22,%f22
	fmuld	%f8,%f56,%f58
	ldd	[%i3+64],%f38
!
	fxtod	%f26,%f26
	fmuld	%f8,%f36,%f60
!
	fxtod	%f30,%f30
	fmuld	%f8,%f38,%f62
!
	fdtox	%f34,%f34
	fmuld	%f10,%f18,%f40
!
	fdtox	%f58,%f58
	fmuld	%f10,%f22,%f42
!
	fdtox	%f60,%f60
	fmuld	%f10,%f26,%f44
!
	fdtox	%f62,%f62
	fmuld	%f10,%f30,%f46
!
	fxtod	%f34,%f34
!
	fxtod	%f58,%f58
!
	fxtod	%f60,%f60
!
	fxtod	%f62,%f62
!
	fsubd	%f16,%f40,%f40
	fmuld	%f10,%f34,%f48
!
	fsubd	%f20,%f42,%f42
	fmuld	%f10,%f58,%f50
!
	fsubd	%f24,%f44,%f44
	fmuld	%f10,%f60,%f52
!
	fsubd	%f28,%f46,%f46
	fmuld	%f10,%f62,%f54
!
	std	%f40,[%i3+8]
!
	std	%f42,[%i3+16]
!
	faddd	%f18,%f44,%f44
	std	%f44,[%i3+24]
!
	faddd	%f22,%f46,%f46
	std	%f46,[%i3+32]
!



	fsubd	%f32,%f48,%f48
	ldd	[%i3+64+8],%f16
!
	fsubd	%f56,%f50,%f50
	ldd	[%i3+64+16],%f20
!
	fsubd	%f36,%f52,%f52
	ldd	[%i3+64+24],%f24
!
	fsubd	%f38,%f54,%f54
	ldd	[%i3+64+32],%f28
!
	faddd	%f26,%f48,%f48
	fmuld	%f8,%f16,%f18
	std	%f48,[%i3+40]
!
	faddd	%f30,%f50,%f50
	fmuld	%f8,%f20,%f22
	std	%f50,[%i3+48]
!
	faddd	%f34,%f52,%f52
	fmuld	%f8,%f24,%f26
	std	%f52,[%i3+56]
!
	faddd	%f58,%f54,%f54
	fmuld	%f8,%f28,%f30
	std	%f54,[%i3+64]
!


	fdtox	%f18,%f18
!
	fdtox	%f22,%f22
!
	fdtox	%f26,%f26
	ldd	[%i3+64+40],%f32
!
	fdtox	%f30,%f30
	ldd	[%i3+64+48],%f56
!
	fxtod	%f18,%f18
	fmuld	%f8,%f32,%f34
	ldd	[%i3+64+56],%f36
!
	fxtod	%f22,%f22
	fmuld	%f8,%f56,%f58
	ldd	[%i3+64+64],%f38
!
	fxtod	%f26,%f26
	fmuld	%f8,%f36,%f12
!
	fxtod	%f30,%f30
	fmuld	%f8,%f38,%f14
!
	fdtox	%f34,%f34
	fmuld	%f10,%f18,%f40
!
	fdtox	%f58,%f58
	fmuld	%f10,%f22,%f42
!
	fdtox	%f12,%f12
	fmuld	%f10,%f26,%f44
!
	fdtox	%f14,%f14
	fmuld	%f10,%f30,%f46
!
	fxtod	%f34,%f34
!
	fxtod	%f58,%f58
!
	fxtod	%f12,%f12
!
	fxtod	%f14,%f14
!
	fsubd	%f16,%f40,%f40
	fmuld	%f10,%f34,%f48
!
	fsubd	%f20,%f42,%f42
	fmuld	%f10,%f58,%f50
!
	fsubd	%f24,%f44,%f44
	fmuld	%f10,%f12,%f52
!
	fsubd	%f28,%f46,%f46
	fmuld	%f10,%f14,%f54
!
	faddd	%f60,%f40,%f40
	std	%f40,[%i3+64+8]
!
	faddd	%f62,%f42,%f42
	std	%f42,[%i3+64+16]
!
	faddd	%f18,%f44,%f44
	std	%f44,[%i3+64+24]
!
	faddd	%f22,%f46,%f46
	std	%f46,[%i3+64+32]
!



	fsubd	%f32,%f48,%f48
	ldd	[%i3+64+64+8],%f16
!
	fsubd	%f56,%f50,%f50
	ldd	[%i3+64+64+16],%f20
!
	fsubd	%f36,%f52,%f52
	ldd	[%i3+64+64+24],%f24
!
	fsubd	%f38,%f54,%f54
	ldd	[%i3+64+64+32],%f28
!
	faddd	%f26,%f48,%f48
	fmuld	%f8,%f16,%f18
	std	%f48,[%i3+64+40]
!
	faddd	%f30,%f50,%f50
	fmuld	%f8,%f20,%f22
	std	%f50,[%i3+64+48]
!
	faddd	%f34,%f52,%f52
	fmuld	%f8,%f24,%f26
	std	%f52,[%i3+64+56]
!
	faddd	%f58,%f54,%f54
	fmuld	%f8,%f28,%f30
	std	%f54,[%i3+64+64]
!



	fdtox	%f18,%f18
!
	fdtox	%f22,%f22
!
	fdtox	%f26,%f26
	ldd	[%i3+64+64+40],%f32
!
	fdtox	%f30,%f30
	ldd	[%i3+64+64+48],%f56
!
	fxtod	%f18,%f18
	fmuld	%f8,%f32,%f34
	ldd	[%i3+64+64+56],%f36
!
	fxtod	%f22,%f22
	fmuld	%f8,%f56,%f58
	ldd	[%i3+64+64+64],%f38
!
	fxtod	%f26,%f26
	fmuld	%f8,%f36,%f60
!
	fxtod	%f30,%f30
	fmuld	%f8,%f38,%f62
!
	fdtox	%f34,%f34
	fmuld	%f10,%f18,%f40
!
	fdtox	%f58,%f58
	fmuld	%f10,%f22,%f42
!
	fdtox	%f60,%f60
	fmuld	%f10,%f26,%f44
!
	fdtox	%f62,%f62
	fmuld	%f10,%f30,%f46
!
	fxtod	%f34,%f34
!
	fxtod	%f58,%f58
!
	fxtod	%f60,%f60
!
	fxtod	%f62,%f62
!
	fsubd	%f16,%f40,%f40
	fmuld	%f10,%f34,%f48
!
	fsubd	%f20,%f42,%f42
	fmuld	%f10,%f58,%f50
!
	fsubd	%f24,%f44,%f44
	fmuld	%f10,%f60,%f52
!
	fsubd	%f28,%f46,%f46
	fmuld	%f10,%f62,%f54
!
	faddd	%f12,%f40,%f40
	std	%f40,[%i3+64+64+8]
!
	faddd	%f14,%f42,%f42
	std	%f42,[%i3+64+64+16]
!
	faddd	%f18,%f44,%f44
	std	%f44,[%i3+64+64+24]
!
	faddd	%f22,%f46,%f46
	std	%f46,[%i3+64+64+32]
!


	fsubd	%f32,%f48,%f48
	ldd	[%i3+64+64+64+8],%f16
!
	fsubd	%f56,%f50,%f50
	ldd	[%i3+64+64+64+16],%f20
!
	fsubd	%f36,%f52,%f52
	ldd	[%i3+64+64+64+24],%f24
!
	fsubd	%f38,%f54,%f54
	ldd	[%i3+64+64+64+32],%f28
!
	faddd	%f26,%f48,%f48
	fmuld	%f8,%f16,%f18
	std	%f48,[%i3+64+64+40]
!
	faddd	%f30,%f50,%f50
	fmuld	%f8,%f20,%f22
	std	%f50,[%i3+64+64+48]
!
	faddd	%f34,%f52,%f52
	fmuld	%f8,%f24,%f26
	std	%f52,[%i3+64+64+56]
!
	faddd	%f58,%f54,%f54
	fmuld	%f8,%f28,%f30
	std	%f54,[%i3+64+64+64]
!


	fdtox	%f18,%f18
!
	fdtox	%f22,%f22
!
	fdtox	%f26,%f26
	ldd	[%i3+64+64+64+40],%f32
!
	fdtox	%f30,%f30
	ldd	[%i3+64+64+64+48],%f56
!
	fxtod	%f18,%f18
	fmuld	%f8,%f32,%f34
	ldd	[%i3+64+64+64+56],%f36
!
	fxtod	%f22,%f22
	fmuld	%f8,%f56,%f58
	ldd	[%i3+64+64+64+64],%f38
!
	fxtod	%f26,%f26
	fmuld	%f8,%f36,%f12
!
	fxtod	%f30,%f30
	fmuld	%f8,%f38,%f14
!
	fdtox	%f34,%f34
	fmuld	%f10,%f18,%f40
!
	fdtox	%f58,%f58
	fmuld	%f10,%f22,%f42
!
	fdtox	%f12,%f12
	fmuld	%f10,%f26,%f44
!
	fdtox	%f14,%f14
	fmuld	%f10,%f30,%f46
!
	sethi	%hi(TwoToMinus16),%g5
	fxtod	%f34,%f34
!
	sethi	%hi(TwoTo16),%l5
	fxtod	%f58,%f58
!
	fxtod	%f12,%f12
!
	fxtod	%f14,%f14
!
	fsubd	%f16,%f40,%f16
	fmuld	%f10,%f34,%f48
	ldd	[%g5+%lo(TwoToMinus16)],%f8
!
	fsubd	%f20,%f42,%f20
	fmuld	%f10,%f58,%f50
	ldd	[%i1],%f40	! should be %f40
!
	fsubd	%f24,%f44,%f24
	fmuld	%f10,%f12,%f52
	ldd	[%i1+8],%f42	! should be %f42
!
	fsubd	%f28,%f46,%f28
	fmuld	%f10,%f14,%f54
	ldd	[%i4],%f44	! should be %f44
!
	faddd	%f60,%f16,%f16
	std	%f16,[%i3+64+64+64+8]
!
	faddd	%f62,%f20,%f20
	std	%f20,[%i3+64+64+64+16]
!
	faddd	%f18,%f24,%f24
	std	%f24,[%i3+64+64+64+24]
!
	faddd	%f22,%f28,%f28
	std	%f28,[%i3+64+64+64+32]
!
	fsubd	%f32,%f48,%f32
	ldd	[%i4+8],%f46	 ! should be %f46
!
	fsubd	%f56,%f50,%f56
	ldd	[%i1+104],%f48	! should be %f48
!
	fsubd	%f36,%f52,%f36
	ldd	[%i4+104],%f50	! should be %f50
!
	fsubd	%f38,%f54,%f38
	ldd	[%i1+16],%f52	! should be %f52
!
	faddd	%f26,%f32,%f32
	std	%f32,[%i3+64+64+64+40]
!
	faddd	%f30,%f56,%f56
	std	%f56,[%i3+64+64+64+48]
!
	faddd	%f34,%f36,%f36
	std	%f36,[%i3+64+64+64+56]
!
	faddd	%f58,%f38,%f38
	std	%f38,[%i3+64+64+64+64]
!
	std	%f12,[%i3+64+64+64+64+8]
!
	std	%f14,[%i3+64+64+64+64+16]
!

	ldd	[%l5+%lo(TwoTo16)],%f10
	ldd	[%i1+48],%f54
	ldd	[%i1+56],%f36
	ldd	[%i1+64],%f56
	ldd	[%i1+112],%f58

	ldd	[%i4+104],%f50
	ldd	[%i4+112],%f60


	.L99999998:
!1
	ldd	[%i1+24],%f20
	fmuld	%f0,%f44,%f12
!2
	ldd	[%i4+24],%f22
	fmuld	%f42,%f4,%f16
!3
	ldd	[%i1+40],%f24
	fmuld	%f46,%f0,%f18
!4
	ldd	[%i4+40],%f26
	fmuld	%f20,%f4,%f20
!5
	ldd	[%l0+8],%f38
	faddd	%f12,%f6,%f12
	fmuld	%f22,%f0,%f22
!6
	add	%l0,8,%l0
	ldd	[%i4+56],%f30
	fmuld	%f24,%f4,%f24
!7
	ldd	[%i1+72],%f32
	faddd	%f16,%f18,%f16
	fmuld	%f26,%f0,%f26
!8
	ldd	[%i3+16],%f18
	fmuld	%f40,%f38,%f14
!9
	ldd	[%i4+72],%f34
	faddd	%f20,%f22,%f20
	fmuld	%f8,%f12,%f12
!10
	ldd	[%i3+48],%f22
	fmuld	%f36,%f4,%f28
!11
	ldd	[%i3+8],%f6
	faddd	%f16,%f18,%f16
	fmuld	%f30,%f0,%f30
!12
	std	%f16,[%i3+16]
	faddd	%f24,%f26,%f24
	fmuld	%f32,%f4,%f32
!13
	ldd	[%i3+80],%f26
	faddd	%f12,%f14,%f12
	fmuld	%f34,%f0,%f34
!14
	ldd	[%i1+88],%f16
	faddd	%f20,%f22,%f20
!15
	ldd	[%i4+88],%f18
	faddd	%f28,%f30,%f28
!16
	ldd	[%i3+112],%f30
	faddd	%f32,%f34,%f32
!17
	ldd	[%i3+144],%f34
	faddd	%f12,%f6,%f6
	fmuld	%f16,%f4,%f16
!18
	std	%f20,[%i3+48]
	faddd	%f24,%f26,%f24
	fmuld	%f18,%f0,%f18
!19
	std	%f24,[%i3+80]
	faddd	%f28,%f30,%f28
	fmuld	%f48,%f4,%f20
!20
	std	%f28,[%i3+112]
	faddd	%f32,%f34,%f32
	fmuld	%f50,%f0,%f22
!21
	ldd	[%i1+120],%f24
	fdtox	%f6,%f12
!22
	std	%f32,[%i3+144]
	faddd	%f16,%f18,%f16
!23
	ldd	[%i4+120],%f26
!24
	ldd	[%i3+176],%f18
	faddd	%f20,%f22,%f20
	fmuld	%f24,%f4,%f24
!25
	ldd	[%i4+16],%f30
	fmovs	%f11,%f12
!26
	ldd	[%i1+32],%f32
	fmuld	%f26,%f0,%f26
!27
	ldd	[%i4+32],%f34
	fmuld	%f52,%f4,%f28
!28
	ldd	[%i3+208],%f22
	faddd	%f16,%f18,%f16
	fmuld	%f30,%f0,%f30
!29
	std	%f16,[%i3+176]
	fxtod	%f12,%f12
	fmuld	%f32,%f4,%f32
!30
	ldd	[%i4+48],%f18
	faddd	%f24,%f26,%f24
	fmuld	%f34,%f0,%f34
!31
	ldd	[%i3+240],%f26
	faddd	%f20,%f22,%f20
!32
	std	%f20,[%i3+208]
	faddd	%f28,%f30,%f28
	fmuld	%f54,%f4,%f16
!33
	ldd	[%i3+32],%f30
	fmuld	%f12,%f2,%f14
!34
	ldd	[%i4+64],%f22
	faddd	%f32,%f34,%f32
	fmuld	%f18,%f0,%f18
!35
	ldd	[%i3+64],%f34
	faddd	%f24,%f26,%f24
!36
	std	%f24,[%i3+240]
	faddd	%f28,%f30,%f28
	fmuld	%f56,%f4,%f20
!37
	std	%f28,[%i3+32]
	fmuld	%f14,%f8,%f12
!38
	ldd	[%i1+80],%f24
	faddd	%f32,%f34,%f34	!	yes, tmp52!
	fmuld	%f22,%f0,%f22
!39
	ldd	[%i4+80],%f26
	faddd	%f16,%f18,%f16
!40
	ldd	[%i1+96],%f28
	fmuld	%f58,%f4,%f32
!41
	ldd	[%i4+96],%f30
	fdtox	%f12,%f12
	fmuld	%f24,%f4,%f24
!42
	std	%f34,[%i3+64]	! yes, tmp52!
	faddd	%f20,%f22,%f20
	fmuld	%f26,%f0,%f26
!43
	ldd	[%i3+96],%f18
	fmuld	%f28,%f4,%f28
!44
	ldd	[%i3+128],%f22
	fmovd	%f38,%f4
	fmuld	%f30,%f0,%f30
!45
	fxtod	%f12,%f12
	fmuld	%f60,%f0,%f34
!46
	add	%i3,8,%i3
	faddd	%f24,%f26,%f24
!47
	ldd	[%i3+160-8],%f26
	faddd	%f16,%f18,%f16
!48
	std	%f16,[%i3+96-8]
	faddd	%f28,%f30,%f28
!49
	ldd	[%i3+192-8],%f30
	faddd	%f32,%f34,%f32
	fmuld	%f12,%f10,%f12
!50
	ldd	[%i3+224-8],%f34
	faddd	%f20,%f22,%f20
!51
	std	%f20,[%i3+128-8]
	faddd	%f24,%f26,%f24
!52
	add	%l1,1,%l1
	std	%f24,[%i3+160-8]
	faddd	%f28,%f30,%f28
!53
	cmp	%l1,31
	std	%f28,[%i3+192-8]
	fsubd	%f14,%f12,%f0
!54
	faddd	%f32,%f34,%f32
	ble,pt	%icc,.L99999998
	std	%f32,[%i3+224-8]
!55
	std	%f6,[%i3]

	add	%o5,%g0,%i3


!END HAND CODED PART
                       .L900000828:
/* 0x03e4	 405 */		ba	.L900000852
/* 0x03e8	 409 */		ldx	[%i3+%o0],%l1

!  406		      !		}
!  407		      !	}
!  409		      !	conv_d16_to_i32(result, dt + 2 * nlen, (int64_t *)dt, nlen + 1);
!  411		      !/*for(i=0;i<nlen+1;i++) saveresult[i]=result[i];*/
!  413		      !	adjust_montf_result(result, nint, nlen);

                       .L77000476:
/* 0x03ec	 413 */		sll	%g1,2,%l3
/* 0x03f0	   0 */		sethi	%hi(TwoTo16),%g5
/* 0x03f4	 413 */		add	%l3,2,%l2
/* 0x03f8	 328 */		cmp	%l2,0
/* 0x03fc	     */		ble,pn	%icc,.L77000482
/* 0x0400	   0 */		sethi	%hi(TwoToMinus16),%o2
                       .L77000514:
/* 0x0404	 329 */		add	%l3,2,%l2
/* 0x0408	 328 */		add	%l3,1,%o4
/* 0x040c	     */		or	%g0,0,%l3
/* 0x0410	 329 */		cmp	%l2,8
/* 0x0414	     */		bl,pn	%icc,.L77000477
/* 0x0418	 328 */		or	%g0,%i3,%l1
                       .L900000831:
/* 0x041c	 329 */		prefetch	[%i3],22
/* 0x0420	     */		sub	%o4,7,%l4
/* 0x0424	     */		or	%g0,0,%l3
/* 0x0428	     */		or	%g0,%i3,%l1
                       .L900000829:
/* 0x042c	 329 */		prefetch	[%l1+528],22
/* 0x0430	     */		std	%f0,[%l1]
/* 0x0434	     */		add	%l3,8,%l3
/* 0x0438	     */		add	%l1,64,%l1
/* 0x043c	     */		std	%f0,[%l1-56]
/* 0x0440	     */		cmp	%l3,%l4
/* 0x0444	     */		std	%f0,[%l1-48]
/* 0x0448	     */		std	%f0,[%l1-40]
/* 0x044c	     */		prefetch	[%l1+496],22
/* 0x0450	     */		std	%f0,[%l1-32]
/* 0x0454	     */		std	%f0,[%l1-24]
/* 0x0458	     */		std	%f0,[%l1-16]
/* 0x045c	     */		ble,pt	%icc,.L900000829
/* 0x0460	     */		std	%f0,[%l1-8]
                       .L900000832:
/* 0x0464	 329 */		cmp	%l3,%o4
/* 0x0468	     */		bg,pn	%icc,.L77000482
/* 0x046c	     */		nop
                       .L77000477:
/* 0x0470	 329 */		add	%l3,1,%l3
                       .L900000851:
/* 0x0474	 329 */		std	%f0,[%l1]
/* 0x0478	     */		cmp	%l3,%o4
/* 0x047c	     */		add	%l1,8,%l1
/* 0x0480	     */		ble,pt	%icc,.L900000851
/* 0x0484	     */		add	%l3,1,%l3
                       .L77000482:
/* 0x0488	 330 */		ldd	[%i1],%f40
/* 0x048c	 334 */		cmp	%o3,0
/* 0x0490	     */		sub	%g1,1,%l3
/* 0x0494	 330 */		ldd	[%l0],%f42
/* 0x0498	 331 */		ldd	[%o2+%lo(TwoToMinus16)],%f36
/* 0x049c	     */		ldd	[%g5+%lo(TwoTo16)],%f38
/* 0x04a0	 330 */		fmuld	%f40,%f42,%f52
/* 0x04a4	 331 */		fdtox	%f52,%f8
/* 0x04a8	     */		fmovs	%f0,%f8
/* 0x04ac	     */		fxtod	%f8,%f62
/* 0x04b0	     */		fmuld	%f62,%f14,%f60
/* 0x04b4	     */		fmuld	%f60,%f36,%f32
/* 0x04b8	     */		fdtox	%f32,%f50
/* 0x04bc	     */		fxtod	%f50,%f34
/* 0x04c0	     */		fmuld	%f34,%f38,%f46
/* 0x04c4	     */		fsubd	%f60,%f46,%f40
/* 0x04c8	 334 */		ble,pn	%icc,.L77000378
/* 0x04cc	 330 */		std	%f52,[%i3]
                       .L77000509:
/* 0x04d0	 345 */		add	%o3,1,%g5
/* 0x04d4	     */		sll	%g5,1,%o2
/* 0x04d8	     */		or	%g0,0,%l1
/* 0x04dc	 337 */		ldd	[%i4],%f42
/* 0x04e0	 345 */		sub	%o3,1,%o3
/* 0x04e4	     */		or	%g0,0,%o5
/* 0x04e8	     */		or	%g0,%i3,%l2
/* 0x04ec	     */		add	%i4,8,%o1
/* 0x04f0	     */		add	%i1,8,%g5
                       .L900000848:
/* 0x04f4	 337 */		fmuld	%f40,%f42,%f34
/* 0x04f8	     */		ldd	[%l0+8],%f32
/* 0x04fc	 341 */		cmp	%g1,1
/* 0x0500	 337 */		ldd	[%i1],%f50
/* 0x0504	     */		ldd	[%l2],%f46
/* 0x0508	     */		ldd	[%l2+8],%f44
/* 0x050c	     */		fmuld	%f50,%f32,%f60
/* 0x0510	 335 */		ldd	[%l0],%f42
/* 0x0514	 337 */		faddd	%f46,%f34,%f48
/* 0x0518	     */		faddd	%f44,%f60,%f58
/* 0x051c	     */		fmuld	%f36,%f48,%f54
/* 0x0520	     */		faddd	%f58,%f54,%f34
/* 0x0524	 341 */		ble,pn	%icc,.L77000368
/* 0x0528	 338 */		std	%f34,[%l2+8]
                       .L77000507:
/* 0x052c	 341 */		or	%g0,1,%l5
/* 0x0530	     */		or	%g0,2,%l4
/* 0x0534	     */		or	%g0,%g5,%g4
/* 0x0538	 342 */		cmp	%l3,12
/* 0x053c	     */		bl,pn	%icc,.L77000481
/* 0x0540	 341 */		or	%g0,%o1,%g3
                       .L900000839:
/* 0x0544	 342 */		prefetch	[%i1+8],0
/* 0x0548	     */		prefetch	[%i1+72],0
/* 0x054c	     */		add	%i4,40,%l6
/* 0x0550	     */		add	%i1,40,%l7
/* 0x0554	     */		prefetch	[%l2+16],0
/* 0x0558	     */		or	%g0,%l2,%o7
/* 0x055c	     */		sub	%l3,7,%i5
/* 0x0560	     */		prefetch	[%l2+80],0
/* 0x0564	     */		add	%l2,80,%g2
/* 0x0568	     */		or	%g0,2,%l4
/* 0x056c	     */		prefetch	[%i1+136],0
/* 0x0570	     */		or	%g0,5,%l5
/* 0x0574	     */		prefetch	[%i1+200],0
/* 0x0578	     */		prefetch	[%l2+144],0
/* 0x057c	     */		ldd	[%i4+8],%f52
/* 0x0580	     */		ldd	[%i4+16],%f44
/* 0x0584	     */		ldd	[%i4+24],%f56
/* 0x0588	     */		fmuld	%f40,%f52,%f48
/* 0x058c	     */		fmuld	%f40,%f44,%f46
/* 0x0590	     */		fmuld	%f40,%f56,%f44
/* 0x0594	     */		ldd	[%l2+48],%f56
/* 0x0598	     */		prefetch	[%l2+208],0
/* 0x059c	     */		prefetch	[%l2+272],0
/* 0x05a0	     */		prefetch	[%l2+336],0
/* 0x05a4	     */		prefetch	[%l2+400],0
/* 0x05a8	     */		ldd	[%i1+8],%f32
/* 0x05ac	     */		ldd	[%i1+16],%f60
/* 0x05b0	     */		ldd	[%i1+24],%f50
/* 0x05b4	     */		fmuld	%f42,%f32,%f62
/* 0x05b8	     */		ldd	[%i1+32],%f32
/* 0x05bc	     */		fmuld	%f42,%f60,%f58
/* 0x05c0	     */		ldd	[%l2+16],%f52
/* 0x05c4	     */		ldd	[%l2+32],%f54
/* 0x05c8	     */		faddd	%f62,%f48,%f60
/* 0x05cc	     */		fmuld	%f42,%f50,%f48
/* 0x05d0	     */		faddd	%f58,%f46,%f62
/* 0x05d4	     */		ldd	[%i4+32],%f46
/* 0x05d8	     */		ldd	[%l2+64],%f58
                       .L900000837:
/* 0x05dc	 342 */		prefetch	[%l7+192],0
/* 0x05e0	     */		fmuld	%f40,%f46,%f46
/* 0x05e4	     */		faddd	%f60,%f52,%f60
/* 0x05e8	     */		ldd	[%l6],%f52
/* 0x05ec	     */		std	%f60,[%g2-64]
/* 0x05f0	     */		fmuld	%f42,%f32,%f50
/* 0x05f4	     */		add	%l5,8,%l5
/* 0x05f8	     */		ldd	[%l7],%f60
/* 0x05fc	     */		faddd	%f48,%f44,%f48
/* 0x0600	     */		cmp	%l5,%i5
/* 0x0604	     */		ldd	[%g2],%f32
/* 0x0608	     */		add	%g2,128,%g2
/* 0x060c	     */		prefetch	[%g2+256],0
/* 0x0610	     */		fmuld	%f40,%f52,%f52
/* 0x0614	     */		faddd	%f62,%f54,%f44
/* 0x0618	     */		ldd	[%l6+8],%f54
/* 0x061c	     */		std	%f44,[%g2-176]
/* 0x0620	     */		fmuld	%f42,%f60,%f44
/* 0x0624	     */		add	%l6,64,%l6
/* 0x0628	     */		ldd	[%l7+8],%f60
/* 0x062c	     */		faddd	%f50,%f46,%f50
/* 0x0630	     */		add	%l7,64,%l7
/* 0x0634	     */		add	%l4,16,%l4
/* 0x0638	     */		ldd	[%g2-112],%f46
/* 0x063c	     */		fmuld	%f40,%f54,%f54
/* 0x0640	     */		faddd	%f48,%f56,%f62
/* 0x0644	     */		ldd	[%l6-48],%f56
/* 0x0648	     */		std	%f62,[%g2-160]
/* 0x064c	     */		fmuld	%f42,%f60,%f48
/* 0x0650	     */		ldd	[%l7-48],%f60
/* 0x0654	     */		faddd	%f44,%f52,%f52
/* 0x0658	     */		ldd	[%g2-96],%f30
/* 0x065c	     */		prefetch	[%g2+288],0
/* 0x0660	     */		fmuld	%f40,%f56,%f56
/* 0x0664	     */		faddd	%f50,%f58,%f62
/* 0x0668	     */		ldd	[%l6-40],%f58
/* 0x066c	     */		std	%f62,[%g2-144]
/* 0x0670	     */		fmuld	%f42,%f60,%f50
/* 0x0674	     */		ldd	[%l7-40],%f62
/* 0x0678	     */		faddd	%f48,%f54,%f54
/* 0x067c	     */		ldd	[%g2-80],%f28
/* 0x0680	     */		prefetch	[%l7+160],0
/* 0x0684	     */		fmuld	%f40,%f58,%f48
/* 0x0688	     */		faddd	%f52,%f32,%f44
/* 0x068c	     */		ldd	[%l6-32],%f58
/* 0x0690	     */		std	%f44,[%g2-128]
/* 0x0694	     */		fmuld	%f42,%f62,%f44
/* 0x0698	     */		ldd	[%l7-32],%f60
/* 0x069c	     */		faddd	%f50,%f56,%f56
/* 0x06a0	     */		ldd	[%g2-64],%f52
/* 0x06a4	     */		prefetch	[%g2+320],0
/* 0x06a8	     */		fmuld	%f40,%f58,%f50
/* 0x06ac	     */		faddd	%f54,%f46,%f32
/* 0x06b0	     */		ldd	[%l6-24],%f62
/* 0x06b4	     */		std	%f32,[%g2-112]
/* 0x06b8	     */		fmuld	%f42,%f60,%f46
/* 0x06bc	     */		ldd	[%l7-24],%f60
/* 0x06c0	     */		faddd	%f44,%f48,%f48
/* 0x06c4	     */		ldd	[%g2-48],%f54
/* 0x06c8	     */		fmuld	%f40,%f62,%f26
/* 0x06cc	     */		faddd	%f56,%f30,%f32
/* 0x06d0	     */		ldd	[%l6-16],%f58
/* 0x06d4	     */		std	%f32,[%g2-96]
/* 0x06d8	     */		fmuld	%f42,%f60,%f30
/* 0x06dc	     */		ldd	[%l7-16],%f32
/* 0x06e0	     */		faddd	%f46,%f50,%f60
/* 0x06e4	     */		ldd	[%g2-32],%f56
/* 0x06e8	     */		prefetch	[%g2+352],0
/* 0x06ec	     */		fmuld	%f40,%f58,%f44
/* 0x06f0	     */		faddd	%f48,%f28,%f62
/* 0x06f4	     */		ldd	[%l6-8],%f46
/* 0x06f8	     */		std	%f62,[%g2-80]
/* 0x06fc	     */		fmuld	%f42,%f32,%f48
/* 0x0700	     */		ldd	[%l7-8],%f32
/* 0x0704	     */		faddd	%f30,%f26,%f62
/* 0x0708	     */		ble,pt	%icc,.L900000837
/* 0x070c	     */		ldd	[%g2-16],%f58
                       .L900000840:
/* 0x0710	 342 */		fmuld	%f40,%f46,%f46
/* 0x0714	     */		faddd	%f62,%f54,%f62
/* 0x0718	     */		std	%f62,[%g2-48]
/* 0x071c	     */		cmp	%l5,%l3
/* 0x0720	     */		fmuld	%f42,%f32,%f50
/* 0x0724	     */		faddd	%f48,%f44,%f48
/* 0x0728	     */		or	%g0,%l7,%g4
/* 0x072c	     */		or	%g0,%l6,%g3
/* 0x0730	     */		faddd	%f60,%f52,%f60
/* 0x0734	     */		std	%f60,[%g2-64]
/* 0x0738	     */		or	%g0,%o7,%l2
/* 0x073c	     */		add	%l4,8,%l4
/* 0x0740	     */		faddd	%f50,%f46,%f54
/* 0x0744	     */		faddd	%f48,%f56,%f56
/* 0x0748	     */		std	%f56,[%g2-32]
/* 0x074c	     */		faddd	%f54,%f58,%f58
/* 0x0750	     */		bg,pn	%icc,.L77000368
/* 0x0754	     */		std	%f58,[%g2-16]
                       .L77000481:
/* 0x0758	 342 */		ldd	[%g4],%f44
                       .L900000850:
/* 0x075c	 342 */		ldd	[%g3],%f48
/* 0x0760	     */		fmuld	%f42,%f44,%f58
/* 0x0764	     */		sra	%l4,0,%l7
/* 0x0768	     */		add	%l5,1,%l5
/* 0x076c	     */		sllx	%l7,3,%g2
/* 0x0770	     */		add	%g4,8,%g4
/* 0x0774	     */		ldd	[%l2+%g2],%f56
/* 0x0778	     */		cmp	%l5,%l3
/* 0x077c	     */		add	%l4,2,%l4
/* 0x0780	     */		fmuld	%f40,%f48,%f54
/* 0x0784	     */		add	%g3,8,%g3
/* 0x0788	     */		faddd	%f58,%f54,%f52
/* 0x078c	     */		faddd	%f52,%f56,%f62
/* 0x0790	     */		std	%f62,[%l2+%g2]
/* 0x0794	     */		ble,a,pt	%icc,.L900000850
/* 0x0798	     */		ldd	[%g4],%f44
                       .L77000368:
/* 0x079c	 344 */		cmp	%o5,15
/* 0x07a0	     */		bne,pn	%icc,.L77000483
/* 0x07a4	 345 */		srl	%l1,31,%g4
                       .L77000478:
/* 0x07a8	 345 */		add	%l1,%g4,%l4
/* 0x07ac	     */		sra	%l4,1,%o7
/* 0x07b0	     */		add	%o7,1,%o4
/* 0x07b4	     */		sll	%o4,1,%l6
/* 0x07b8	     */		cmp	%l6,%o2
/* 0x07bc	     */		bge,pn	%icc,.L77000392
/* 0x07c0	     */		fmovd	%f0,%f42
                       .L77000508:
/* 0x07c4	 345 */		sra	%l6,0,%l4
/* 0x07c8	     */		sllx	%l4,3,%g2
/* 0x07cc	     */		fmovd	%f0,%f32
/* 0x07d0	     */		sub	%o2,1,%l5
/* 0x07d4	     */		ldd	[%g2+%i3],%f40
/* 0x07d8	     */		add	%g2,%i3,%g3
                       .L900000849:
/* 0x07dc	 345 */		fdtox	%f40,%f10
/* 0x07e0	     */		ldd	[%g3+8],%f52
/* 0x07e4	     */		add	%l6,2,%l6
/* 0x07e8	     */		cmp	%l6,%l5
/* 0x07ec	     */		fdtox	%f52,%f2
/* 0x07f0	     */		fmovd	%f10,%f30
/* 0x07f4	     */		fmovs	%f0,%f10
/* 0x07f8	     */		fmovs	%f0,%f2
/* 0x07fc	     */		fxtod	%f10,%f10
/* 0x0800	     */		fxtod	%f2,%f2
/* 0x0804	     */		fdtox	%f52,%f28
/* 0x0808	     */		faddd	%f10,%f32,%f56
/* 0x080c	     */		std	%f56,[%g3]
/* 0x0810	     */		faddd	%f2,%f42,%f62
/* 0x0814	     */		std	%f62,[%g3+8]
/* 0x0818	     */		fitod	%f30,%f32
/* 0x081c	     */		add	%g3,16,%g3
/* 0x0820	     */		fitod	%f28,%f42
/* 0x0824	     */		ble,a,pt	%icc,.L900000849
/* 0x0828	     */		ldd	[%g3],%f40
                       .L77000392:
/* 0x082c	 346 */		or	%g0,0,%o5
                       .L77000483:
/* 0x0830	 350 */		fdtox	%f34,%f6
/* 0x0834	     */		add	%l1,1,%l1
/* 0x0838	     */		cmp	%l1,%o3
/* 0x083c	     */		add	%o5,1,%o5
/* 0x0840	     */		add	%l2,8,%l2
/* 0x0844	     */		add	%l0,8,%l0
/* 0x0848	     */		fmovs	%f0,%f6
/* 0x084c	     */		fxtod	%f6,%f46
/* 0x0850	     */		fmuld	%f46,%f14,%f56
/* 0x0854	     */		fmuld	%f56,%f36,%f44
/* 0x0858	     */		fdtox	%f44,%f48
/* 0x085c	     */		fxtod	%f48,%f58
/* 0x0860	     */		fmuld	%f58,%f38,%f54
/* 0x0864	     */		fsubd	%f56,%f54,%f40
/* 0x0868	     */		ble,a,pt	%icc,.L900000848
/* 0x086c	 337 */		ldd	[%i4],%f42
                       .L77000378:
/* 0x0870	 409 */		ldx	[%i3+%o0],%l1
                       .L900000852:
/* 0x0874	 409 */		add	%i3,%o0,%l4
/* 0x0878	     */		ldx	[%l4+8],%i1
/* 0x087c	     */		cmp	%l1,0
/* 0x0880	     */		bne,pn	%xcc,.L77000403
/* 0x0884	     */		or	%g0,0,%g5
                       .L77000402:
/* 0x0888	 409 */		or	%g0,0,%i3
/* 0x088c	     */		ba	.L900000847
/* 0x0890	     */		cmp	%i1,0
                       .L77000403:
/* 0x0894	 409 */		srlx	%l1,52,%o5
/* 0x0898	     */		sethi	%hi(0xfff00000),%i3
/* 0x089c	     */		sllx	%i3,32,%o2
/* 0x08a0	     */		sethi	%hi(0x40000000),%o0
/* 0x08a4	     */		sllx	%o0,22,%o4
/* 0x08a8	     */		or	%g0,1023,%l0
/* 0x08ac	     */		xor	%o2,-1,%o3
/* 0x08b0	     */		sub	%l0,%o5,%o7
/* 0x08b4	     */		and	%l1,%o3,%l1
/* 0x08b8	     */		add	%o7,52,%i4
/* 0x08bc	     */		or	%l1,%o4,%o1
/* 0x08c0	     */		cmp	%i1,0
/* 0x08c4	     */		srlx	%o1,%i4,%i3
                       .L900000847:
/* 0x08c8	 409 */		bne,pn	%xcc,.L77000409
/* 0x08cc	     */		or	%g0,0,%o7
                       .L77000408:
/* 0x08d0	 409 */		ba	.L900000846
/* 0x08d4	 350 */		cmp	%g1,0
                       .L77000409:
/* 0x08d8	 409 */		srlx	%i1,52,%l2
/* 0x08dc	     */		sethi	%hi(0xfff00000),%o7
/* 0x08e0	     */		sllx	%o7,32,%i4
/* 0x08e4	     */		sethi	%hi(0x40000000),%i5
/* 0x08e8	     */		sllx	%i5,22,%l6
/* 0x08ec	     */		or	%g0,1023,%l5
/* 0x08f0	     */		xor	%i4,-1,%o1
/* 0x08f4	     */		sub	%l5,%l2,%g2
/* 0x08f8	     */		and	%i1,%o1,%l7
/* 0x08fc	     */		add	%g2,52,%g3
/* 0x0900	     */		or	%l7,%l6,%g4
/* 0x0904	 350 */		cmp	%g1,0
/* 0x0908	 409 */		srlx	%g4,%g3,%o7
                       .L900000846:
/* 0x090c	 350 */		ble,pn	%icc,.L77000397
/* 0x0910	     */		or	%g0,0,%l5
                       .L77000510:
/* 0x0914	 409 */		sethi	%hi(0xfff00000),%g4
/* 0x0918	     */		sllx	%g4,32,%o0
/* 0x091c	   0 */		or	%g0,-1,%i5
/* 0x0920	 409 */		srl	%i5,0,%l7
/* 0x0924	     */		sethi	%hi(0x40000000),%i1
/* 0x0928	     */		sllx	%i1,22,%l6
/* 0x092c	     */		sethi	%hi(0xfc00),%i4
/* 0x0930	     */		xor	%o0,-1,%g2
/* 0x0934	     */		add	%i4,1023,%l2
/* 0x0938	     */		or	%g0,2,%g4
/* 0x093c	     */		or	%g0,%i2,%g3
                       .L77000395:
/* 0x0940	 409 */		sra	%g4,0,%o2
/* 0x0944	     */		add	%g4,1,%o3
/* 0x0948	     */		sllx	%o2,3,%o0
/* 0x094c	     */		sra	%o3,0,%o5
/* 0x0950	     */		ldx	[%l4+%o0],%o4
/* 0x0954	     */		sllx	%o5,3,%l0
/* 0x0958	     */		and	%i3,%l7,%o1
/* 0x095c	     */		ldx	[%l4+%l0],%i4
/* 0x0960	     */		cmp	%o4,0
/* 0x0964	     */		bne,pn	%xcc,.L77000415
/* 0x0968	 350 */		and	%o7,%l2,%i5
                       .L77000414:
/* 0x096c	 409 */		or	%g0,0,%l1
/* 0x0970	     */		ba	.L900000845
/* 0x0974	     */		add	%g5,%o1,%i1
                       .L77000415:
/* 0x0978	 409 */		srlx	%o4,52,%o3
/* 0x097c	     */		and	%o4,%g2,%l1
/* 0x0980	     */		or	%g0,52,%o0
/* 0x0984	     */		sub	%o3,1023,%l0
/* 0x0988	     */		or	%l1,%l6,%o4
/* 0x098c	     */		sub	%o0,%l0,%o5
/* 0x0990	     */		srlx	%o4,%o5,%l1
/* 0x0994	     */		add	%g5,%o1,%i1
                       .L900000845:
/* 0x0998	 409 */		srax	%i3,32,%g5
/* 0x099c	     */		cmp	%i4,0
/* 0x09a0	     */		bne,pn	%xcc,.L77000421
/* 0x09a4	 350 */		sllx	%i5,16,%o2
                       .L77000420:
/* 0x09a8	 409 */		or	%g0,0,%o4
/* 0x09ac	     */		ba	.L900000844
/* 0x09b0	 350 */		add	%i1,%o2,%o5
                       .L77000421:
/* 0x09b4	 409 */		srlx	%i4,52,%o4
/* 0x09b8	     */		or	%g0,52,%o0
/* 0x09bc	     */		sub	%o4,1023,%o3
/* 0x09c0	     */		and	%i4,%g2,%i3
/* 0x09c4	     */		or	%i3,%l6,%o5
/* 0x09c8	     */		sub	%o0,%o3,%l0
/* 0x09cc	     */		srlx	%o5,%l0,%o4
/* 0x09d0	 350 */		add	%i1,%o2,%o5
                       .L900000844:
/* 0x09d4	 350 */		srax	%o7,16,%i4
/* 0x09d8	     */		srax	%o5,32,%i5
/* 0x09dc	     */		add	%i4,%i5,%o1
/* 0x09e0	     */		add	%l5,1,%l5
/* 0x09e4	     */		and	%o5,%l7,%i1
/* 0x09e8	     */		add	%g5,%o1,%g5
/* 0x09ec	     */		st	%i1,[%g3]
/* 0x09f0	     */		or	%g0,%l1,%i3
/* 0x09f4	     */		or	%g0,%o4,%o7
/* 0x09f8	     */		add	%g4,2,%g4
/* 0x09fc	     */		cmp	%l5,%l3
/* 0x0a00	     */		ble,pt	%icc,.L77000395
/* 0x0a04	     */		add	%g3,4,%g3
                       .L77000397:
/* 0x0a08	 409 */		sethi	%hi(0xfc00),%l4
/* 0x0a0c	     */		sra	%l5,0,%i5
/* 0x0a10	     */		add	%l4,1023,%i1
/* 0x0a14	     */		add	%g5,%i3,%l5
/* 0x0a18	     */		and	%o7,%i1,%g5
/* 0x0a1c	     */		sllx	%g5,16,%l2
/* 0x0a20	     */		sllx	%i5,2,%l7
/* 0x0a24	 413 */		sra	%g1,0,%g2
/* 0x0a28	 409 */		add	%l5,%l2,%l6
/* 0x0a2c	     */		st	%l6,[%i2+%l7]
/* 0x0a30	 413 */		sllx	%g2,2,%g3
/* 0x0a34	     */		ld	[%i2+%g3],%g4
/* 0x0a38	     */		cmp	%g4,0
/* 0x0a3c	     */		bgu,pn	%icc,.L77000486
/* 0x0a40	     */		cmp	%l3,0
                       .L77000427:
/* 0x0a44	 413 */		bl,pn	%icc,.L77000486
/* 0x0a48	     */		or	%g0,%l3,%i5
                       .L77000512:
/* 0x0a4c	 413 */		sra	%l3,0,%o5
/* 0x0a50	     */		sllx	%o5,2,%l7
/* 0x0a54	     */		ld	[%l7+%i0],%o5
/* 0x0a58	     */		add	%l7,%i2,%o1
/* 0x0a5c	     */		add	%l7,%i0,%i4
                       .L900000843:
/* 0x0a60	 413 */		ld	[%o1],%i1
/* 0x0a64	     */		cmp	%i1,%o5
/* 0x0a68	     */		bne,pn	%icc,.L77000435
/* 0x0a6c	     */		sub	%o1,4,%o1
                       .L77000431:
/* 0x0a70	 413 */		sub	%i4,4,%i4
/* 0x0a74	     */		subcc	%i5,1,%i5
/* 0x0a78	     */		bpos,a,pt	%icc,.L900000843
/* 0x0a7c	     */		ld	[%i4],%o5
                       .L900000827:
/* 0x0a80	 413 */		ba	.L900000842
/* 0x0a84	 350 */		cmp	%g1,0
                       .L77000435:
/* 0x0a88	 413 */		sra	%i5,0,%o0
/* 0x0a8c	     */		sllx	%o0,2,%l1
/* 0x0a90	     */		ld	[%i0+%l1],%i3
/* 0x0a94	     */		ld	[%i2+%l1],%l0
/* 0x0a98	     */		cmp	%l0,%i3
/* 0x0a9c	     */		bleu,pt	%icc,.L77000379
/* 0x0aa0	     */		nop
                       .L77000486:
/* 0x0aa4	 350 */		cmp	%g1,0
                       .L900000842:
/* 0x0aa8	 350 */		ble,pn	%icc,.L77000379
/* 0x0aac	     */		add	%l3,1,%g3
                       .L77000511:
/* 0x0ab0	 350 */		or	%g0,0,%l5
/* 0x0ab4	     */		cmp	%g3,10
/* 0x0ab8	     */		bl,pn	%icc,.L77000487
/* 0x0abc	     */		or	%g0,0,%g1
                       .L900000835:
/* 0x0ac0	 350 */		prefetch	[%i2],22
/* 0x0ac4	     */		add	%i0,4,%l2
/* 0x0ac8	     */		prefetch	[%i2+64],22
/* 0x0acc	     */		add	%i2,8,%o5
/* 0x0ad0	     */		sub	%l3,7,%i0
/* 0x0ad4	     */		prefetch	[%i2+128],22
/* 0x0ad8	     */		or	%g0,2,%l5
/* 0x0adc	     */		prefetch	[%i2+192],22
/* 0x0ae0	     */		prefetch	[%i2+256],22
/* 0x0ae4	     */		prefetch	[%i2+320],22
/* 0x0ae8	     */		prefetch	[%i2+384],22
/* 0x0aec	     */		ld	[%l2-4],%l7
/* 0x0af0	     */		ld	[%o5-4],%l6
/* 0x0af4	     */		prefetch	[%o5+440],22
/* 0x0af8	     */		prefetch	[%o5+504],22
/* 0x0afc	     */		ld	[%i2],%i2
/* 0x0b00	     */		sub	%i2,%l7,%g3
/* 0x0b04	     */		st	%g3,[%o5-8]
/* 0x0b08	     */		srax	%g3,32,%l7
                       .L900000833:
/* 0x0b0c	 350 */		add	%l5,8,%l5
/* 0x0b10	     */		add	%o5,32,%o5
/* 0x0b14	     */		ld	[%l2],%i5
/* 0x0b18	     */		prefetch	[%o5+496],22
/* 0x0b1c	     */		cmp	%l5,%i0
/* 0x0b20	     */		add	%l2,32,%l2
/* 0x0b24	     */		sub	%l6,%i5,%g5
/* 0x0b28	     */		add	%g5,%l7,%o0
/* 0x0b2c	     */		ld	[%o5-32],%l4
/* 0x0b30	     */		st	%o0,[%o5-36]
/* 0x0b34	     */		srax	%o0,32,%i3
/* 0x0b38	     */		ld	[%l2-28],%i1
/* 0x0b3c	     */		sub	%l4,%i1,%i4
/* 0x0b40	     */		add	%i4,%i3,%o1
/* 0x0b44	     */		ld	[%o5-28],%o3
/* 0x0b48	     */		st	%o1,[%o5-32]
/* 0x0b4c	     */		srax	%o1,32,%l1
/* 0x0b50	     */		ld	[%l2-24],%o2
/* 0x0b54	     */		sub	%o3,%o2,%g2
/* 0x0b58	     */		add	%g2,%l1,%o7
/* 0x0b5c	     */		ld	[%o5-24],%l0
/* 0x0b60	     */		st	%o7,[%o5-28]
/* 0x0b64	     */		srax	%o7,32,%l6
/* 0x0b68	     */		ld	[%l2-20],%o4
/* 0x0b6c	     */		sub	%l0,%o4,%g1
/* 0x0b70	     */		add	%g1,%l6,%l7
/* 0x0b74	     */		ld	[%o5-20],%i2
/* 0x0b78	     */		st	%l7,[%o5-24]
/* 0x0b7c	     */		srax	%l7,32,%g4
/* 0x0b80	     */		ld	[%l2-16],%g3
/* 0x0b84	     */		sub	%i2,%g3,%i5
/* 0x0b88	     */		add	%i5,%g4,%g5
/* 0x0b8c	     */		ld	[%o5-16],%i1
/* 0x0b90	     */		st	%g5,[%o5-20]
/* 0x0b94	     */		srax	%g5,32,%l4
/* 0x0b98	     */		ld	[%l2-12],%o0
/* 0x0b9c	     */		sub	%i1,%o0,%i3
/* 0x0ba0	     */		add	%i3,%l4,%i4
/* 0x0ba4	     */		ld	[%o5-12],%o2
/* 0x0ba8	     */		st	%i4,[%o5-16]
/* 0x0bac	     */		srax	%i4,32,%o3
/* 0x0bb0	     */		ld	[%l2-8],%o1
/* 0x0bb4	     */		sub	%o2,%o1,%l1
/* 0x0bb8	     */		add	%l1,%o3,%g2
/* 0x0bbc	     */		ld	[%o5-8],%o4
/* 0x0bc0	     */		st	%g2,[%o5-12]
/* 0x0bc4	     */		srax	%g2,32,%l0
/* 0x0bc8	     */		ld	[%l2-4],%o7
/* 0x0bcc	     */		sub	%o4,%o7,%l6
/* 0x0bd0	     */		add	%l6,%l0,%g1
/* 0x0bd4	     */		ld	[%o5-4],%l6
/* 0x0bd8	     */		st	%g1,[%o5-8]
/* 0x0bdc	     */		ble,pt	%icc,.L900000833
/* 0x0be0	     */		srax	%g1,32,%l7
                       .L900000836:
/* 0x0be4	 350 */		ld	[%l2],%l0
/* 0x0be8	     */		add	%l2,4,%i0
/* 0x0bec	     */		or	%g0,%o5,%i2
/* 0x0bf0	     */		cmp	%l5,%l3
/* 0x0bf4	     */		sub	%l6,%l0,%l6
/* 0x0bf8	     */		add	%l6,%l7,%g1
/* 0x0bfc	     */		st	%g1,[%o5-4]
/* 0x0c00	     */		bg,pn	%icc,.L77000379
/* 0x0c04	     */		srax	%g1,32,%g1
                       .L77000487:
/* 0x0c08	 350 */		ld	[%i2],%o4
                       .L900000841:
/* 0x0c0c	 350 */		ld	[%i0],%i3
/* 0x0c10	     */		add	%g1,%o4,%l0
/* 0x0c14	     */		add	%l5,1,%l5
/* 0x0c18	     */		cmp	%l5,%l3
/* 0x0c1c	     */		add	%i0,4,%i0
/* 0x0c20	     */		sub	%l0,%i3,%l6
/* 0x0c24	     */		st	%l6,[%i2]
/* 0x0c28	     */		srax	%l6,32,%g1
/* 0x0c2c	     */		add	%i2,4,%i2
/* 0x0c30	     */		ble,a,pt	%icc,.L900000841
/* 0x0c34	     */		ld	[%i2],%o4
                       .L77000379:
/* 0x0c38	 405 */		ret	! Result =
/* 0x0c3c	     */		restore	%g0,%g0,%g0
/* 0x0c40	   0 */		.type	mont_mulf_noconv,2
/* 0x0c40	   0 */		.size	mont_mulf_noconv,(.-mont_mulf_noconv)

! Begin Disassembling Debug Info
	.xstabs ".stab.index","V=10.0;DBG_GEN=4.14.14;cd;backend;Xa;O;R=Sun C 5.5 Patch 112760-07 2004/02/03",60,0,0,0
	.xstabs ".stab.index","/workspace/ferenc/algorithms/bignum/unified/mont_mulf; /ws/onnv-tools/SUNWspro/SOS8/prod/bin/cc -D_KERNEL -DRF_INLINE_MACROS -fast -xarch=v9 -xO5 -xstrconst -xdepend -Xa -xchip=ultra3 -xcode=abs32 -Wc,-Qrm-Qd -Wc,-Qrm-Qf -Wc,-assembly -V -W0,-xp -c conv_v9.il -o mont_mulf.o  mont_mulf.c",52,0,0,0

! End Disassembling Debug Info

! Begin Disassembling Ident
	.ident	"cg: Sun Compiler Common 7.1 Patch 112763-10 2004/01/27"	! (NO SOURCE LINE)
	.ident	"@(#)mont_mulf.c\t1.2\t01/09/24 SMI"	! (/tmp/acompAAApja4Fx:8)
	.ident	"@(#)types.h\t1.74\t03/08/07 SMI"	! (/tmp/acompAAApja4Fx:9)
	.ident	"@(#)isa_defs.h\t1.20\t99/05/04 SMI"	! (/tmp/acompAAApja4Fx:10)
	.ident	"@(#)feature_tests.h\t1.18\t99/07/26 SMI"	! (/tmp/acompAAApja4Fx:11)
	.ident	"@(#)machtypes.h\t1.13\t99/05/04 SMI"	! (/tmp/acompAAApja4Fx:12)
	.ident	"@(#)inttypes.h\t1.2\t98/01/16 SMI"	! (/tmp/acompAAApja4Fx:13)
	.ident	"@(#)int_types.h\t1.6\t97/08/20 SMI"	! (/tmp/acompAAApja4Fx:14)
	.ident	"@(#)int_limits.h\t1.6\t99/08/06 SMI"	! (/tmp/acompAAApja4Fx:15)
	.ident	"@(#)int_const.h\t1.2\t96/07/08 SMI"	! (/tmp/acompAAApja4Fx:16)
	.ident	"@(#)int_fmtio.h\t1.2\t96/07/08 SMI"	! (/tmp/acompAAApja4Fx:17)
	.ident	"@(#)types32.h\t1.4\t98/02/13 SMI"	! (/tmp/acompAAApja4Fx:18)
	.ident	"@(#)select.h\t1.17\t01/08/15 SMI"	! (/tmp/acompAAApja4Fx:19)
	.ident	"@(#)math.h\t2.11\t00/09/07 SMI"	! (/tmp/acompAAApja4Fx:20)
	.ident	"@(#)math_iso.h\t1.2\t00/09/07 SMI"	! (/tmp/acompAAApja4Fx:21)
	.ident	"@(#)floatingpoint.h\t2.5\t99/06/22 SMI"	! (/tmp/acompAAApja4Fx:22)
	.ident	"@(#)stdio_tag.h\t1.3\t98/04/20 SMI"	! (/tmp/acompAAApja4Fx:23)
	.ident	"@(#)ieeefp.h\t2.8 99/10/29"	! (/tmp/acompAAApja4Fx:24)
	.ident	"acomp: Sun C 5.5 Patch 112760-07 2004/02/03"	! (/tmp/acompAAApja4Fx:57)
	.ident	"iropt: Sun Compiler Common 7.1 Patch 112763-10 2004/01/27"	! (/tmp/acompAAApja4Fx:58)
	.ident	"cg: Sun Compiler Common 7.1 Patch 112763-10 2004/01/27"	! (NO SOURCE LINE)
! End Disassembling Ident

#define	FZERO				\
	fzero	%f0			;\
	fzero	%f2			;\
	faddd	%f0, %f2, %f4		;\
	fmuld	%f0, %f2, %f6		;\
	faddd	%f0, %f2, %f8		;\
	fmuld	%f0, %f2, %f10		;\
	faddd	%f0, %f2, %f12		;\
	fmuld	%f0, %f2, %f14		;\
	faddd	%f0, %f2, %f16		;\
	fmuld	%f0, %f2, %f18		;\
	faddd	%f0, %f2, %f20		;\
	fmuld	%f0, %f2, %f22		;\
	faddd	%f0, %f2, %f24		;\
	fmuld	%f0, %f2, %f26		;\
	faddd	%f0, %f2, %f28		;\
	fmuld	%f0, %f2, %f30		;\
	faddd	%f0, %f2, %f32		;\
	fmuld	%f0, %f2, %f34		;\
	faddd	%f0, %f2, %f36		;\
	fmuld	%f0, %f2, %f38		;\
	faddd	%f0, %f2, %f40		;\
	fmuld	%f0, %f2, %f42		;\
	faddd	%f0, %f2, %f44		;\
	fmuld	%f0, %f2, %f46		;\
	faddd	%f0, %f2, %f48		;\
	fmuld	%f0, %f2, %f50		;\
	faddd	%f0, %f2, %f52		;\
	fmuld	%f0, %f2, %f54		;\
	faddd	%f0, %f2, %f56		;\
	fmuld	%f0, %f2, %f58		;\
	faddd	%f0, %f2, %f60		;\
	fmuld	%f0, %f2, %f62

#include "assym.h"

/*
 * In the routine below, we check/set FPRS_FEF bit since
 * we don't want to take a fp_disabled trap. We need not
 * check/set PSTATE_PEF bit as it is done early during boot.
 */
	ENTRY(big_savefp)
	rd	%fprs, %o2
	st	%o2, [%o0 + FPU_FPRS]
	andcc	%o2, FPRS_FEF, %g0		! is FPRS_FEF set?
	bnz,a,pt	%icc, .fregs_save	! yes, go to save
	nop
	wr	%g0, FPRS_FEF, %fprs		! else, set the bit
        stx     %fsr, [%o0 + FPU_FSR]	! store %fsr
	retl
	nop
.fregs_save:
	BSTORE_FPREGS(%o0, %o4)
        stx     %fsr, [%o0 + FPU_FSR]	! store %fsr
	retl
	nop
	SET_SIZE(big_savefp)


	ENTRY(big_restorefp)
	ldx     [%o0 + FPU_FSR], %fsr	! restore %fsr
	ld	[%o0 + FPU_FPRS], %o1
	andcc   %o1, FPRS_FEF, %g0	! is FPRS_FEF set in saved %fprs?
	bnz,pt	%icc, .fregs_restore	! yes, go to restore
	nop
	FZERO				! zero out to avoid leaks
	wr	%g0, 0, %fprs
	retl
	nop
.fregs_restore:
	BLOAD_FPREGS(%o0, %o2)
	wr      %o1, 0, %fprs
	retl
	nop
	SET_SIZE(big_restorefp)
