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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.section	".text",#alloc,#execinstr
	.file	"mont_mulf_asm_v9.s"

	.section	".rodata",#alloc
	.align	8
!
! CONSTANT POOL
!
TwoTo16:
	.word	1089470464
	.word	0
	.type	TwoTo16,#object
	.size	TwoTo16,8
!
! CONSTANT POOL
!
TwoToMinus16:
	.word	1055916032
	.word	0
	.type	TwoToMinus16,#object
	.size	TwoToMinus16,8
!
! CONSTANT POOL
!
Zero:
	.word	0
	.word	0
	.type	Zero,#object
	.size	Zero,8
!
! CONSTANT POOL
!
TwoTo32:
	.word	1106247680
	.word	0
	.type	TwoTo32,#object
	.size	TwoTo32,8
!
! CONSTANT POOL
!
TwoToMinus32:
	.word	1039138816
	.word	0
	.type	TwoToMinus32,#object
	.size	TwoToMinus32,8

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.register	%g3,#scratch
/* 000000	     */		.register	%g2,#scratch
/* 000000	   0 */		.align	8
/* 000000	     */		.skip	24
/* 0x0018	     */		.align	4
! FILE mont_mulf.c

!    1		      !/*
!    2		      ! * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
!    3		      ! * Use is subject to license terms.
!    4		      ! */
!    6		      !#pragma ident	"%Z%%M%	%I%	%E% SMI"
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
/* 000000	  57 */		or	%g0,%o7,%g3
/* 0x0004	   0 */		sethi	%hi(Zero),%o3
                       .L900000110:
/* 0x0008	  57 */		call	.+8
/* 0x000c	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000110-.)),%g2
/* 0x0010	   0 */		add	%o3,%lo(Zero),%o3
/* 0x0014	  57 */		add	%g2,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000110-.)),%g2
/* 0x0018	     */		add	%g2,%o7,%o4
/* 0x001c	     */		or	%g0,%g3,%o7
/* 0x0020	   0 */		ldx	[%o4+%o3],%o5
/* 0x0024	  57 */		sra	%o1,0,%o3
/* 0x0028	     */		or	%g0,%o0,%o4
/* 0x002c	     */		sra	%o2,0,%o1

!   58		      !	int i;
!   59		      !	double tmp, tmp1, x, x1;
!   61		      !	tmp = tmp1 = Zero;
!   63		      !	for (i = 2 * from; i < 2 * tlen; i += 2) {

/* 0x0030	  63 */		sll	%o3,1,%g2
/* 0x0034	  61 */		ldd	[%o5],%f12
/* 0x0038	  63 */		sll	%o1,1,%o1
/* 0x003c	  57 */		add	%g2,1,%o2
/* 0x0040	  63 */		cmp	%g2,%o1
/* 0x0044	     */		bge,pt	%icc,.L77000145
/* 0x0048	     */		fmovd	%f12,%f10

!   64		      !		x = dt[i];

/* 0x004c	  64 */		sra	%g2,0,%o0
/* 0x0050	  57 */		sub	%o1,1,%o3
                       .L900000111:
/* 0x0054	  64 */		sllx	%o0,3,%o0

!   65		      !		x1 = dt[i + 1];
!   66		      !		dt[i] = lower32(x, Zero) + tmp;

/* 0x0058	  66 */		ldd	[%o5],%f4

!   67		      !		dt[i + 1] = lower32(x1, Zero) + tmp1;
!   68		      !		tmp = upper32(x);
!   69		      !		tmp1 = upper32(x1);

/* 0x005c	  69 */		add	%g2,2,%g2
/* 0x0060	  65 */		sra	%o2,0,%o1
/* 0x0064	  64 */		ldd	[%o4+%o0],%f6
/* 0x0068	  69 */		add	%o2,2,%o2
/* 0x006c	  65 */		sllx	%o1,3,%o1
/* 0x0070	  69 */		cmp	%g2,%o3
/* 0x0074	  65 */		ldd	[%o4+%o1],%f8
/* 0x0078	     */		fdtox	%f6,%f0
/* 0x007c	     */		fdtox	%f8,%f2
/* 0x0080	     */		fmovs	%f4,%f0
/* 0x0084	     */		fmovs	%f4,%f2
/* 0x0088	     */		fxtod	%f0,%f0
/* 0x008c	     */		fdtox	%f6,%f4
/* 0x0090	     */		fxtod	%f2,%f2
/* 0x0094	     */		fdtox	%f8,%f6
/* 0x0098	  66 */		faddd	%f0,%f10,%f0
/* 0x009c	     */		std	%f0,[%o4+%o0]
/* 0x00a0	  67 */		faddd	%f2,%f12,%f0
/* 0x00a4	     */		std	%f0,[%o4+%o1]
/* 0x00a8	     */		fitod	%f4,%f10
/* 0x00ac	     */		fitod	%f6,%f12
/* 0x00b0	  69 */		ble,pt	%icc,.L900000111
/* 0x00b4	     */		sra	%g2,0,%o0
                       .L77000145:
/* 0x00b8	     */		retl	! Result =
/* 0x00bc	     */		nop
/* 0x00c0	   0 */		.type	cleanup,2
/* 0x00c0	   0 */		.size	cleanup,(.-cleanup)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	4

!   70		      !	}
!   71		      !}
!   74		      !/* ARGSUSED */
!   75		      !void
!   76		      !conv_d16_to_i32(uint32_t *i32, double *d16, int64_t *tmp, int ilen)
!   77		      !{

!
! SUBROUTINE conv_d16_to_i32
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_d16_to_i32
                       conv_d16_to_i32:
/* 000000	  77 */		save	%sp,-208,%sp

!   78		      !	int i;
!   79		      !	int64_t t, t1,		/* using int64_t and not uint64_t */
!   80		      !		a, b, c, d;	/* because more efficient code is */
!   81		      !				/* generated this way, and there  */
!   82		      !				/* is no overflow  */
!   83		      !	t1 = 0;
!   84		      !	a = (int64_t)d16[0];

/* 0x0004	  84 */		ldd	[%i1],%f0
/* 0x0008	  77 */		sra	%i3,0,%g5
/* 0x000c	     */		or	%g0,%i0,%l1

!   85		      !	b = (int64_t)d16[1];

/* 0x0010	  85 */		ldd	[%i1+8],%f2

!   86		      !	for (i = 0; i < ilen - 1; i++) {

/* 0x0014	  86 */		sub	%g5,1,%g2
/* 0x0018	  83 */		or	%g0,0,%l7
/* 0x001c	  84 */		fdtox	%f0,%f0
/* 0x0020	     */		std	%f0,[%sp+2247]
/* 0x0024	  86 */		cmp	%g2,0
/* 0x0028	  85 */		fdtox	%f2,%f0
/* 0x002c	     */		std	%f0,[%sp+2239]
/* 0x0030	  86 */		or	%g0,0,%o5
/* 0x0034	     */		sub	%g5,1,%g4
/* 0x0038	  77 */		or	%g0,-1,%g3
/* 0x003c	     */		srl	%g3,0,%l4
/* 0x0040	     */		sub	%g5,2,%l0
/* 0x0044	     */		or	%g0,%i1,%l2
/* 0x0048	     */		or	%g0,%i0,%o7
/* 0x004c	  84 */		ldx	[%sp+2247],%o1
/* 0x0050	  77 */		or	%g0,2,%o2

!   87		      !		c = (int64_t)d16[2 * i + 2];
!   88		      !		t1 += a & 0xffffffff;
!   89		      !		t = (a >> 32);
!   90		      !		d = (int64_t)d16[2 * i + 3];
!   91		      !		t1 += (b & 0xffff) << 16;
!   92		      !		t += (b >> 16) + (t1 >> 32);
!   93		      !		i32[i] = t1 & 0xffffffff;
!   94		      !		t1 = t;
!   95		      !		a = c;
!   96		      !		b = d;

/* 0x0054	  96 */		or	%g0,8,%i2
/* 0x0058	  85 */		ldx	[%sp+2239],%o0
/* 0x005c	  86 */		ble,pt	%icc,.L900000212
/* 0x0060	 101 */		sethi	%hi(0xfc00),%g2
/* 0x0064	  77 */		sethi	%hi(0xfc00),%g2
/* 0x0068	  86 */		cmp	%g4,7
/* 0x006c	  77 */		add	%g2,1023,%l3
/* 0x0070	  86 */		bl,pn	%icc,.L77000169
/* 0x0074	     */		or	%g0,3,%g5
/* 0x0078	  87 */		ldd	[%i1+16],%f0
/* 0x007c	     */		or	%g0,32,%g5
/* 0x0080	  90 */		or	%g0,40,%g4
/* 0x0084	     */		ldd	[%i1+24],%f2
/* 0x0088	  91 */		and	%o0,%l3,%g3
/* 0x008c	  88 */		and	%o1,%l4,%l6
/* 0x0090	  92 */		srax	%o0,16,%o0
/* 0x0094	  87 */		fdtox	%f0,%f0
/* 0x0098	     */		std	%f0,[%sp+2231]
/* 0x009c	  86 */		sub	%l0,3,%o2
/* 0x00a0	  90 */		fdtox	%f2,%f0
/* 0x00a4	     */		std	%f0,[%sp+2223]
/* 0x00a8	     */		ldd	[%i1+%g4],%f2
/* 0x00ac	     */		or	%g0,56,%g4
/* 0x00b0	  96 */		or	%g0,3,%o5
/* 0x00b4	  87 */		ldd	[%i1+%g5],%f0
/* 0x00b8	  91 */		sllx	%g3,16,%g5
/* 0x00bc	  87 */		or	%g0,48,%g3
/* 0x00c0	  86 */		add	%l6,%g5,%l7
/* 0x00c4	  90 */		fdtox	%f2,%f2
/* 0x00c8	  87 */		ldx	[%sp+2231],%g2
/* 0x00cc	  92 */		srax	%l7,32,%o3
/* 0x00d0	  87 */		fdtox	%f0,%f0
/* 0x00d4	     */		std	%f0,[%sp+2231]
/* 0x00d8	     */		ldd	[%i1+%g3],%f0
/* 0x00dc	  89 */		srax	%g2,32,%l6
/* 0x00e0	  96 */		or	%g0,9,%i1
/* 0x00e4	  89 */		srax	%o1,32,%g3
/* 0x00e8	  88 */		and	%g2,%l4,%g2
/* 0x00ec	  90 */		ldx	[%sp+2223],%g5
/* 0x00f0	     */		std	%f2,[%sp+2223]
/* 0x00f4	     */		ldd	[%l2+%g4],%f2
/* 0x00f8	  92 */		srax	%g5,16,%i0
/* 0x00fc	  91 */		and	%g5,%l3,%g4
/* 0x0100	  87 */		ldx	[%sp+2231],%l5
                       .L900000207:
/* 0x0104	  87 */		sra	%i2,0,%g5
/* 0x0108	  92 */		add	%o0,%o3,%o0
/* 0x010c	  90 */		ldx	[%sp+2223],%o1
/* 0x0110	  87 */		fdtox	%f0,%f0
/* 0x0114	     */		std	%f0,[%sp+2231]
/* 0x0118	     */		sllx	%g5,3,%g5
/* 0x011c	  92 */		add	%g3,%o0,%o0
/* 0x0120	  90 */		sra	%i1,0,%g3
/* 0x0124	  93 */		and	%l7,%l4,%o3
/* 0x0128	  87 */		ldd	[%l2+%g5],%f0
/* 0x012c	  90 */		fdtox	%f2,%f2
/* 0x0130	     */		std	%f2,[%sp+2223]
/* 0x0134	     */		sllx	%g3,3,%g3
/* 0x0138	  96 */		add	%i1,2,%g5
/* 0x013c	  91 */		sllx	%g4,16,%o4
/* 0x0140	  96 */		add	%i2,2,%g4
/* 0x0144	  90 */		ldd	[%l2+%g3],%f2
/* 0x0148	  93 */		st	%o3,[%o7]
/* 0x014c	  86 */		add	%g2,%o4,%g2
/* 0x0150	  96 */		add	%o5,3,%o5
/* 0x0154	  86 */		add	%g2,%o0,%g3
/* 0x0158	  89 */		srax	%l5,32,%g2
/* 0x015c	  88 */		and	%l5,%l4,%l5
/* 0x0160	  92 */		srax	%g3,32,%o4
/* 0x0164	  87 */		ldx	[%sp+2231],%o0
/* 0x0168	  92 */		srax	%o1,16,%o3
/* 0x016c	  91 */		and	%o1,%l3,%l7
/* 0x0170	  87 */		sra	%g4,0,%o1
/* 0x0174	  92 */		add	%i0,%o4,%i0
/* 0x0178	  90 */		ldx	[%sp+2223],%o4
/* 0x017c	  87 */		fdtox	%f0,%f0
/* 0x0180	     */		std	%f0,[%sp+2231]
/* 0x0184	     */		sllx	%o1,3,%o1
/* 0x0188	  92 */		add	%l6,%i0,%i0
/* 0x018c	  90 */		sra	%g5,0,%l6
/* 0x0190	  93 */		and	%g3,%l4,%g3
/* 0x0194	  87 */		ldd	[%l2+%o1],%f0
/* 0x0198	  90 */		fdtox	%f2,%f2
/* 0x019c	     */		std	%f2,[%sp+2223]
/* 0x01a0	     */		sllx	%l6,3,%o1
/* 0x01a4	  96 */		add	%i1,4,%g5
/* 0x01a8	  91 */		sllx	%l7,16,%l6
/* 0x01ac	  96 */		add	%i2,4,%g4
/* 0x01b0	  90 */		ldd	[%l2+%o1],%f2
/* 0x01b4	  93 */		st	%g3,[%o7+4]
/* 0x01b8	  86 */		add	%l5,%l6,%g3
/* 0x01bc	  96 */		cmp	%o5,%o2
/* 0x01c0	  86 */		add	%g3,%i0,%l7
/* 0x01c4	  89 */		srax	%o0,32,%g3
/* 0x01c8	  88 */		and	%o0,%l4,%l6
/* 0x01cc	  92 */		srax	%l7,32,%o1
/* 0x01d0	  87 */		ldx	[%sp+2231],%l5
/* 0x01d4	  92 */		srax	%o4,16,%o0
/* 0x01d8	  91 */		and	%o4,%l3,%o4
/* 0x01dc	  87 */		sra	%g4,0,%i0
/* 0x01e0	  92 */		add	%o3,%o1,%o3
/* 0x01e4	  90 */		ldx	[%sp+2223],%o1
/* 0x01e8	  87 */		fdtox	%f0,%f0
/* 0x01ec	     */		std	%f0,[%sp+2231]
/* 0x01f0	     */		sllx	%i0,3,%i0
/* 0x01f4	  92 */		add	%g2,%o3,%g2
/* 0x01f8	  90 */		sra	%g5,0,%i1
/* 0x01fc	  93 */		and	%l7,%l4,%o3
/* 0x0200	  87 */		ldd	[%l2+%i0],%f0
/* 0x0204	  90 */		fdtox	%f2,%f2
/* 0x0208	     */		std	%f2,[%sp+2223]
/* 0x020c	     */		sllx	%i1,3,%l7
/* 0x0210	  96 */		add	%g5,2,%i1
/* 0x0214	  91 */		sllx	%o4,16,%g5
/* 0x0218	  96 */		add	%i2,6,%i2
/* 0x021c	  90 */		ldd	[%l2+%l7],%f2
/* 0x0220	  93 */		st	%o3,[%o7+8]
/* 0x0224	  86 */		add	%l6,%g5,%g4
/* 0x0228	  96 */		add	%o7,12,%o7
/* 0x022c	  86 */		add	%g4,%g2,%l7
/* 0x0230	  89 */		srax	%l5,32,%l6
/* 0x0234	  88 */		and	%l5,%l4,%g2
/* 0x0238	  92 */		srax	%l7,32,%o3
/* 0x023c	  87 */		ldx	[%sp+2231],%l5
/* 0x0240	  92 */		srax	%o1,16,%i0
/* 0x0244	  96 */		ble,pt	%icc,.L900000207
/* 0x0248	     */		and	%o1,%l3,%g4
                       .L900000210:
/* 0x024c	  91 */		sllx	%g4,16,%g4
/* 0x0250	  90 */		ldx	[%sp+2223],%o1
/* 0x0254	  92 */		add	%o0,%o3,%g5
/* 0x0258	     */		add	%g3,%g5,%g3
/* 0x025c	  86 */		add	%g2,%g4,%g2
/* 0x0260	  90 */		fdtox	%f2,%f2
/* 0x0264	     */		sra	%i1,0,%g4
/* 0x0268	     */		std	%f2,[%sp+2223]
/* 0x026c	  86 */		add	%g2,%g3,%o2
/* 0x0270	  87 */		sra	%i2,0,%g2
/* 0x0274	  91 */		and	%o1,%l3,%g5
/* 0x0278	  87 */		fdtox	%f0,%f0
/* 0x027c	  92 */		srax	%o2,32,%g3
/* 0x0280	  87 */		std	%f0,[%sp+2231]
/* 0x0284	  88 */		and	%l5,%l4,%o0
/* 0x0288	  87 */		sllx	%g2,3,%g2
/* 0x028c	  92 */		add	%i0,%g3,%g3
/* 0x0290	  90 */		sllx	%g4,3,%g4
/* 0x0294	  87 */		ldd	[%l2+%g2],%f0
/* 0x0298	  92 */		add	%l6,%g3,%g2
/* 0x029c	  91 */		sllx	%g5,16,%g3
/* 0x02a0	  90 */		ldd	[%l2+%g4],%f2
/* 0x02a4	  93 */		and	%l7,%l4,%g5
/* 0x02a8	  92 */		srax	%o1,16,%o1
/* 0x02ac	  90 */		ldx	[%sp+2223],%o3
/* 0x02b0	  86 */		add	%o0,%g3,%g3
/* 0x02b4	  89 */		srax	%l5,32,%l5
/* 0x02b8	  87 */		ldx	[%sp+2231],%o4
/* 0x02bc	  86 */		add	%g3,%g2,%g2
/* 0x02c0	  92 */		srax	%g2,32,%o0
/* 0x02c4	  93 */		st	%g5,[%o7]
/* 0x02c8	  91 */		and	%o3,%l3,%g3
/* 0x02cc	     */		sllx	%g3,16,%g3
/* 0x02d0	  88 */		and	%o4,%l4,%g4
/* 0x02d4	  87 */		fdtox	%f0,%f0
/* 0x02d8	     */		std	%f0,[%sp+2231]
/* 0x02dc	  92 */		add	%o1,%o0,%o0
/* 0x02e0	  86 */		add	%g4,%g3,%g3
/* 0x02e4	  93 */		and	%o2,%l4,%g4
/* 0x02e8	     */		st	%g4,[%o7+4]
/* 0x02ec	  92 */		add	%l5,%o0,%l5
/* 0x02f0	     */		srax	%o3,16,%g4
/* 0x02f4	  87 */		ldx	[%sp+2231],%o1
/* 0x02f8	  86 */		add	%g3,%l5,%g3
/* 0x02fc	  92 */		srax	%g3,32,%o3
/* 0x0300	  90 */		fdtox	%f2,%f2
/* 0x0304	     */		std	%f2,[%sp+2223]
/* 0x0308	  96 */		add	%o7,16,%o7
/* 0x030c	  93 */		and	%g2,%l4,%g2
/* 0x0310	     */		st	%g2,[%o7-8]
/* 0x0314	  92 */		add	%g4,%o3,%g4
/* 0x0318	  96 */		add	%o5,1,%o5
/* 0x031c	  89 */		srax	%o4,32,%o3
/* 0x0320	  90 */		ldx	[%sp+2223],%o0
/* 0x0324	  93 */		and	%g3,%l4,%g2
/* 0x0328	  96 */		cmp	%o5,%l0
/* 0x032c	  93 */		st	%g2,[%o7-4]
/* 0x0330	  96 */		bg,pn	%icc,.L77000162
/* 0x0334	     */		add	%o3,%g4,%l7
/* 0x0338	     */		add	%i1,2,%g5
/* 0x033c	     */		add	%i2,2,%o2
                       .L77000169:
/* 0x0340	  87 */		sra	%o2,0,%g2
                       .L900000211:
/* 0x0344	  90 */		sra	%g5,0,%g4
/* 0x0348	  91 */		and	%o0,%l3,%o3
/* 0x034c	  87 */		sllx	%g2,3,%g2
/* 0x0350	  88 */		and	%o1,%l4,%g3
/* 0x0354	  90 */		sllx	%g4,3,%g4
/* 0x0358	  87 */		ldd	[%l2+%g2],%f0
/* 0x035c	  88 */		add	%l7,%g3,%g3
/* 0x0360	  90 */		ldd	[%l2+%g4],%f2
/* 0x0364	  91 */		sllx	%o3,16,%g2
/* 0x0368	  96 */		add	%o5,1,%o5
/* 0x036c	  87 */		fdtox	%f0,%f0
/* 0x0370	     */		std	%f0,[%sp+2231]
/* 0x0374	  92 */		srax	%o0,16,%o3
/* 0x0378	  90 */		fdtox	%f2,%f0
/* 0x037c	  89 */		srax	%o1,32,%o1
/* 0x0380	  90 */		std	%f0,[%sp+2223]
/* 0x0384	  91 */		add	%g3,%g2,%g2
/* 0x0388	  96 */		add	%o2,2,%o2
/* 0x038c	  92 */		srax	%g2,32,%o0
/* 0x0390	  93 */		and	%g2,%l4,%g3
/* 0x0394	     */		st	%g3,[%o7]
/* 0x0398	  87 */		ldx	[%sp+2231],%g2
/* 0x039c	  92 */		add	%o3,%o0,%o0
/* 0x03a0	  96 */		add	%g5,2,%g5
/* 0x03a4	  92 */		add	%o1,%o0,%l7
/* 0x03a8	  96 */		add	%o7,4,%o7
/* 0x03ac	  90 */		ldx	[%sp+2223],%g4
/* 0x03b0	  95 */		or	%g0,%g2,%o1
/* 0x03b4	  96 */		cmp	%o5,%l0
/* 0x03b8	     */		or	%g0,%g4,%o0
/* 0x03bc	     */		ble,pt	%icc,.L900000211
/* 0x03c0	     */		sra	%o2,0,%g2

!   97		      !	}
!   98		      !	t1 += a & 0xffffffff;
!   99		      !	t = (a >> 32);
!  100		      !	t1 += (b & 0xffff) << 16;
!  101		      !	i32[i] = t1 & 0xffffffff;

                       .L77000162:
/* 0x03c4	 101 */		sethi	%hi(0xfc00),%g2
                       .L900000212:
/* 0x03c8	 101 */		or	%g0,-1,%g3
/* 0x03cc	     */		srl	%g3,0,%g3
/* 0x03d0	     */		add	%g2,1023,%g2
/* 0x03d4	     */		and	%o1,%g3,%g4
/* 0x03d8	     */		and	%o0,%g2,%g2
/* 0x03dc	     */		sllx	%g2,16,%g2
/* 0x03e0	     */		add	%l7,%g4,%g4
/* 0x03e4	     */		sra	%o5,0,%g5
/* 0x03e8	     */		add	%g4,%g2,%g4
/* 0x03ec	     */		sllx	%g5,2,%g2
/* 0x03f0	     */		and	%g4,%g3,%g3
/* 0x03f4	     */		st	%g3,[%l1+%g2]
/* 0x03f8	     */		ret	! Result =
/* 0x03fc	     */		restore	%g0,%g0,%g0
/* 0x0400	   0 */		.type	conv_d16_to_i32,2
/* 0x0400	   0 */		.size	conv_d16_to_i32,(.-conv_d16_to_i32)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       ___const_seg_900000301:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	   0 */		.type	___const_seg_900000301,1
/* 0x0008	   0 */		.size	___const_seg_900000301,(.-___const_seg_900000301)
/* 0x0008	   0 */		.align	8
/* 0x0008	     */		.skip	24
/* 0x0020	     */		.align	4

!  102		      !}
!  104		      !void
!  105		      !conv_i32_to_d32(double *d32, uint32_t *i32, int len)
!  106		      !{

!
! SUBROUTINE conv_i32_to_d32
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_i32_to_d32
                       conv_i32_to_d32:
/* 000000	 106 */		or	%g0,%o7,%g2

!  107		      !	int i;
!  109		      !#pragma pipeloop(0)
!  110		      !	for (i = 0; i < len; i++)
!  111		      !		d32[i] = (double)(i32[i]);

/* 0x0004	 111 */		sethi	%hi(___const_seg_900000301),%g1
                       .L900000309:
/* 0x0008	 106 */		call	.+8
/* 0x000c	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000309-.)),%o4
/* 0x0010	     */		add	%o4,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000309-.)),%o4
/* 0x0014	     */		sra	%o2,0,%o2
/* 0x0018	     */		add	%o4,%o7,%o5
/* 0x001c	 110 */		cmp	%o2,0
/* 0x0020	     */		ble,pt	%icc,.L77000181
/* 0x0024	     */		or	%g0,%g2,%o7
/* 0x0028	     */		sub	%o2,1,%o4
/* 0x002c	 111 */		add	%g1,%lo(___const_seg_900000301),%o2
/* 0x0030	     */		ldx	[%o5+%o2],%o5
/* 0x0034	 110 */		add	%o4,1,%o3
/* 0x0038	     */		cmp	%o3,9
/* 0x003c	     */		bl,pn	%icc,.L77000185
/* 0x0040	     */		or	%g0,0,%o2
/* 0x0044	 111 */		ld	[%o1],%f3
/* 0x0048	 110 */		sub	%o4,4,%o3
/* 0x004c	 111 */		or	%g0,4,%o2
/* 0x0050	     */		ld	[%o1+12],%f9
/* 0x0054	     */		ldd	[%o5],%f6
/* 0x0058	     */		ld	[%o1+8],%f11
/* 0x005c	     */		ld	[%o1+4],%f13
/* 0x0060	     */		fmovs	%f6,%f2
/* 0x0064	     */		add	%o1,16,%o1
                       .L900000305:
/* 0x0068	 111 */		ld	[%o1],%f1
/* 0x006c	     */		add	%o2,5,%o2
/* 0x0070	     */		add	%o1,20,%o1
/* 0x0074	     */		fsubd	%f2,%f6,%f2
/* 0x0078	     */		std	%f2,[%o0]
/* 0x007c	     */		cmp	%o2,%o3
/* 0x0080	     */		add	%o0,40,%o0
/* 0x0084	     */		fmovs	%f6,%f12
/* 0x0088	     */		fsubd	%f12,%f6,%f4
/* 0x008c	     */		ld	[%o1-16],%f3
/* 0x0090	     */		std	%f4,[%o0-32]
/* 0x0094	     */		fmovs	%f6,%f10
/* 0x0098	     */		fsubd	%f10,%f6,%f4
/* 0x009c	     */		ld	[%o1-12],%f13
/* 0x00a0	     */		std	%f4,[%o0-24]
/* 0x00a4	     */		fmovs	%f6,%f8
/* 0x00a8	     */		fsubd	%f8,%f6,%f4
/* 0x00ac	     */		ld	[%o1-8],%f11
/* 0x00b0	     */		std	%f4,[%o0-16]
/* 0x00b4	     */		fmovs	%f6,%f0
/* 0x00b8	     */		fsubd	%f0,%f6,%f0
/* 0x00bc	     */		ld	[%o1-4],%f9
/* 0x00c0	     */		std	%f0,[%o0-8]
/* 0x00c4	     */		ble,pt	%icc,.L900000305
/* 0x00c8	     */		fmovs	%f6,%f2
                       .L900000308:
/* 0x00cc	 111 */		fmovs	%f6,%f12
/* 0x00d0	     */		add	%o0,32,%o0
/* 0x00d4	     */		cmp	%o2,%o4
/* 0x00d8	     */		fmovs	%f6,%f10
/* 0x00dc	     */		fmovs	%f6,%f8
/* 0x00e0	     */		fsubd	%f2,%f6,%f0
/* 0x00e4	     */		std	%f0,[%o0-32]
/* 0x00e8	     */		fsubd	%f12,%f6,%f0
/* 0x00ec	     */		std	%f0,[%o0-24]
/* 0x00f0	     */		fsubd	%f10,%f6,%f0
/* 0x00f4	     */		std	%f0,[%o0-16]
/* 0x00f8	     */		fsubd	%f8,%f6,%f0
/* 0x00fc	     */		bg,pn	%icc,.L77000181
/* 0x0100	     */		std	%f0,[%o0-8]
                       .L77000185:
/* 0x0104	 111 */		ld	[%o1],%f1
                       .L900000310:
/* 0x0108	 111 */		ldd	[%o5],%f6
/* 0x010c	     */		add	%o2,1,%o2
/* 0x0110	     */		add	%o1,4,%o1
/* 0x0114	     */		cmp	%o2,%o4
/* 0x0118	     */		fmovs	%f6,%f0
/* 0x011c	     */		fsubd	%f0,%f6,%f0
/* 0x0120	     */		std	%f0,[%o0]
/* 0x0124	     */		add	%o0,8,%o0
/* 0x0128	     */		ble,a,pt	%icc,.L900000310
/* 0x012c	     */		ld	[%o1],%f1
                       .L77000181:
/* 0x0130	     */		retl	! Result =
/* 0x0134	     */		nop
/* 0x0138	   0 */		.type	conv_i32_to_d32,2
/* 0x0138	   0 */		.size	conv_i32_to_d32,(.-conv_i32_to_d32)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       ___const_seg_900000401:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	   0 */		.type	___const_seg_900000401,1
/* 0x0008	   0 */		.size	___const_seg_900000401,(.-___const_seg_900000401)
/* 0x0008	   0 */		.align	8
/* 0x0008	     */		.skip	24
/* 0x0020	     */		.align	4

!  112		      !}
!  115		      !void
!  116		      !conv_i32_to_d16(double *d16, uint32_t *i32, int len)
!  117		      !{

!
! SUBROUTINE conv_i32_to_d16
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_i32_to_d16
                       conv_i32_to_d16:
/* 000000	 117 */		save	%sp,-192,%sp
                       .L900000410:
/* 0x0004	 117 */		call	.+8
/* 0x0008	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000410-.)),%g3
/* 0x000c	   0 */		sethi	%hi(___const_seg_900000401),%g2
/* 0x0010	 117 */		sra	%i2,0,%o0
/* 0x0014	     */		add	%g3,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000410-.)),%g3

!  118		      !	int i;
!  119		      !	uint32_t a;
!  121		      !#pragma pipeloop(0)
!  122		      !	for (i = 0; i < len; i++) {

/* 0x0018	 122 */		cmp	%o0,0
/* 0x001c	     */		ble,pt	%icc,.L77000197
/* 0x0020	     */		add	%g3,%o7,%g5
/* 0x0024	   0 */		add	%g2,%lo(___const_seg_900000401),%g2
/* 0x0028	 122 */		or	%g0,%o0,%g4
/* 0x002c	   0 */		ldx	[%g5+%g2],%o5
/* 0x0030	 122 */		sethi	%hi(0xfc00),%g3
/* 0x0034	     */		sub	%o0,1,%o2
/* 0x0038	     */		add	%g3,1023,%o3
/* 0x003c	 117 */		or	%g0,%i1,%o1
/* 0x0040	 122 */		or	%g0,0,%o0
/* 0x0044	     */		or	%g0,0,%g5

!  123		      !		a = i32[i];
!  124		      !		d16[2 * i] = (double)(a & 0xffff);

/* 0x0048	 124 */		ldd	[%o5],%f2
/* 0x004c	 122 */		cmp	%g4,4
/* 0x0050	     */		bl,pn	%icc,.L77000201
/* 0x0054	     */		or	%g0,1,%l0
/* 0x0058	 123 */		ld	[%i1],%g3
/* 0x005c	 124 */		fmovs	%f2,%f0
/* 0x0060	     */		or	%g0,0,%g4

!  125		      !		d16[2 * i + 1] = (double)(a >> 16);

/* 0x0064	 125 */		fmovs	%f2,%f4
/* 0x0068	     */		add	%i1,12,%o1
/* 0x006c	     */		or	%g0,3,%o0
/* 0x0070	 124 */		and	%g3,%o3,%g5
/* 0x0074	     */		st	%g5,[%sp+2227]
/* 0x0078	 125 */		or	%g0,2,%l1
/* 0x007c	     */		srl	%g3,16,%g3
/* 0x0080	     */		st	%g3,[%sp+2223]
/* 0x0084	     */		or	%g0,8,%g5
/* 0x0088	 123 */		ld	[%i1+4],%g3
/* 0x008c	 125 */		or	%g0,3,%l0
/* 0x0090	 124 */		and	%g3,%o3,%g2
/* 0x0094	     */		ld	[%sp+2227],%f1
/* 0x0098	 125 */		ld	[%sp+2223],%f5
/* 0x009c	 124 */		st	%g2,[%sp+2227]
/* 0x00a0	     */		fsubd	%f0,%f2,%f0
/* 0x00a4	 125 */		srl	%g3,16,%g2
/* 0x00a8	     */		st	%g2,[%sp+2223]
/* 0x00ac	 124 */		std	%f0,[%i0+%g4]
/* 0x00b0	 125 */		fsubd	%f4,%f2,%f0
/* 0x00b4	 123 */		ld	[%i1+8],%g2
/* 0x00b8	 125 */		std	%f0,[%i0+%g5]
                       .L900000406:
/* 0x00bc	 125 */		add	%o0,1,%o0
/* 0x00c0	     */		add	%o1,4,%o1
/* 0x00c4	 124 */		ld	[%sp+2227],%f1
/* 0x00c8	 125 */		cmp	%o0,%o2
/* 0x00cc	     */		ld	[%sp+2223],%f5
/* 0x00d0	 122 */		nop ! volatile
/* 0x00d4	     */		nop ! volatile
/* 0x00d8	     */		nop ! volatile
/* 0x00dc	 124 */		and	%g2,%o3,%g3
/* 0x00e0	 125 */		srl	%g2,16,%g2
/* 0x00e4	 124 */		st	%g3,[%sp+2227]
/* 0x00e8	 125 */		st	%g2,[%sp+2223]
/* 0x00ec	 123 */		ld	[%o1-4],%g2
/* 0x00f0	 125 */		fmovs	%f2,%f4
/* 0x00f4	     */		sra	%l0,0,%g4
/* 0x00f8	 124 */		fmovs	%f2,%f0
/* 0x00fc	     */		sra	%l1,0,%g3
/* 0x0100	     */		fsubd	%f0,%f2,%f0
/* 0x0104	     */		sllx	%g3,3,%g3
/* 0x0108	 125 */		sllx	%g4,3,%g4
/* 0x010c	 124 */		std	%f0,[%i0+%g3]
/* 0x0110	 125 */		add	%l1,2,%l1
/* 0x0114	     */		fsubd	%f4,%f2,%f0
/* 0x0118	     */		std	%f0,[%i0+%g4]
/* 0x011c	     */		ble,pt	%icc,.L900000406
/* 0x0120	     */		add	%l0,2,%l0
                       .L900000409:
/* 0x0124	 124 */		and	%g2,%o3,%g3
/* 0x0128	 125 */		ld	[%sp+2223],%f5
/* 0x012c	 124 */		fmovs	%f2,%f0
/* 0x0130	     */		ld	[%sp+2227],%f1
/* 0x0134	     */		sra	%l1,0,%g4
/* 0x0138	 125 */		add	%l1,2,%g5
/* 0x013c	     */		srl	%g2,16,%g2
/* 0x0140	     */		st	%g2,[%sp+2223]
/* 0x0144	     */		fmovs	%f2,%f4
/* 0x0148	 124 */		sllx	%g4,3,%g2
/* 0x014c	     */		st	%g3,[%sp+2227]
/* 0x0150	 125 */		add	%l0,2,%g4
/* 0x0154	 124 */		fsubd	%f0,%f2,%f0
/* 0x0158	     */		std	%f0,[%i0+%g2]
/* 0x015c	 125 */		sra	%l0,0,%g3
/* 0x0160	     */		fsubd	%f4,%f2,%f0
/* 0x0164	     */		sllx	%g3,3,%g3
/* 0x0168	     */		std	%f0,[%i0+%g3]
/* 0x016c	 124 */		sra	%g5,0,%g2
/* 0x0170	     */		ld	[%sp+2227],%f1
/* 0x0174	 125 */		sra	%g4,0,%g3
/* 0x0178	     */		ld	[%sp+2223],%f5
/* 0x017c	 124 */		sllx	%g2,3,%g2
/* 0x0180	     */		fmovs	%f2,%f0
/* 0x0184	 125 */		sllx	%g3,3,%g3
/* 0x0188	     */		fmovs	%f2,%f4
/* 0x018c	 124 */		fsubd	%f0,%f2,%f0
/* 0x0190	     */		std	%f0,[%i0+%g2]
/* 0x0194	 125 */		fsubd	%f4,%f2,%f0
/* 0x0198	     */		std	%f0,[%i0+%g3]
/* 0x019c	     */		ret	! Result =
/* 0x01a0	     */		restore	%g0,%g0,%g0
                       .L77000201:
/* 0x01a4	 123 */		ld	[%o1],%g3
                       .L900000411:
/* 0x01a8	 124 */		sra	%g5,0,%g2
/* 0x01ac	     */		ldd	[%o5],%f2
/* 0x01b0	 125 */		add	%o0,1,%o0
/* 0x01b4	 124 */		sllx	%g2,3,%g4
/* 0x01b8	     */		and	%g3,%o3,%g2
/* 0x01bc	     */		st	%g2,[%sp+2227]
/* 0x01c0	     */		fmovs	%f2,%f0
/* 0x01c4	 125 */		srl	%g3,16,%g3
/* 0x01c8	     */		add	%o1,4,%o1
/* 0x01cc	     */		sra	%l0,0,%g2
/* 0x01d0	     */		add	%g5,2,%g5
/* 0x01d4	     */		sllx	%g2,3,%g2
/* 0x01d8	     */		cmp	%o0,%o2
/* 0x01dc	 124 */		ld	[%sp+2227],%f1
/* 0x01e0	 125 */		add	%l0,2,%l0
/* 0x01e4	 124 */		fsubd	%f0,%f2,%f0
/* 0x01e8	     */		std	%f0,[%i0+%g4]
/* 0x01ec	 125 */		st	%g3,[%sp+2223]
/* 0x01f0	     */		fmovs	%f2,%f0
/* 0x01f4	     */		ld	[%sp+2223],%f1
/* 0x01f8	     */		fsubd	%f0,%f2,%f0
/* 0x01fc	     */		std	%f0,[%i0+%g2]
/* 0x0200	     */		ble,a,pt	%icc,.L900000411
/* 0x0204	     */		ld	[%o1],%g3
                       .L77000197:
/* 0x0208	     */		ret	! Result =
/* 0x020c	     */		restore	%g0,%g0,%g0
/* 0x0210	   0 */		.type	conv_i32_to_d16,2
/* 0x0210	   0 */		.size	conv_i32_to_d16,(.-conv_i32_to_d16)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       ___const_seg_900000501:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	   0 */		.type	___const_seg_900000501,1
/* 0x0008	   0 */		.size	___const_seg_900000501,(.-___const_seg_900000501)
/* 0x0008	   0 */		.align	8
/* 0x0008	     */		.skip	24
/* 0x0020	     */		.align	4

!  126		      !	}
!  127		      !}
!  129		      !#ifdef RF_INLINE_MACROS
!  131		      !void
!  132		      !i16_to_d16_and_d32x4(const double *,	/* 1/(2^16) */
!  133		      !			const double *,	/* 2^16 */
!  134		      !			const double *,	/* 0 */
!  135		      !			double *,	/* result16 */
!  136		      !			double *,	/* result32 */
!  137		      !			float *);	/* source - should be unsigned int* */
!  138		      !					/* converted to float* */
!  140		      !#else
!  143		      !/* ARGSUSED */
!  144		      !static void
!  145		      !i16_to_d16_and_d32x4(const double *dummy1,	/* 1/(2^16) */
!  146		      !			const double *dummy2,	/* 2^16 */
!  147		      !			const double *dummy3,	/* 0 */
!  148		      !			double *result16,
!  149		      !			double *result32,
!  150		      !			float *src)	/* source - should be unsigned int* */
!  151		      !					/* converted to float* */
!  152		      !{
!  153		      !	uint32_t *i32;
!  154		      !	uint32_t a, b, c, d;
!  156		      !	i32 = (uint32_t *)src;
!  157		      !	a = i32[0];
!  158		      !	b = i32[1];
!  159		      !	c = i32[2];
!  160		      !	d = i32[3];
!  161		      !	result16[0] = (double)(a & 0xffff);
!  162		      !	result16[1] = (double)(a >> 16);
!  163		      !	result32[0] = (double)a;
!  164		      !	result16[2] = (double)(b & 0xffff);
!  165		      !	result16[3] = (double)(b >> 16);
!  166		      !	result32[1] = (double)b;
!  167		      !	result16[4] = (double)(c & 0xffff);
!  168		      !	result16[5] = (double)(c >> 16);
!  169		      !	result32[2] = (double)c;
!  170		      !	result16[6] = (double)(d & 0xffff);
!  171		      !	result16[7] = (double)(d >> 16);
!  172		      !	result32[3] = (double)d;
!  173		      !}
!  175		      !#endif
!  178		      !void
!  179		      !conv_i32_to_d32_and_d16(double *d32, double *d16, uint32_t *i32, int len)
!  180		      !{

!
! SUBROUTINE conv_i32_to_d32_and_d16
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_i32_to_d32_and_d16
                       conv_i32_to_d32_and_d16:
/* 000000	 180 */		save	%sp,-192,%sp
                       .L900000512:
/* 0x0004	 180 */		call	.+8
/* 0x0008	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000512-.)),%g4

!  181		      !	int i;
!  182		      !	uint32_t a;
!  184		      !#pragma pipeloop(0)
!  185		      !	for (i = 0; i < len - 3; i += 4) {

/* 0x000c	 185 */		or	%g0,0,%g5
/* 0x0010	 180 */		sra	%i3,0,%l1
/* 0x0014	     */		add	%g4,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000512-.)),%g4
/* 0x0018	 185 */		sub	%l1,3,%g2
/* 0x001c	 180 */		add	%g4,%o7,%o0
/* 0x0020	 185 */		cmp	%g2,0
/* 0x0024	     */		or	%g0,0,%o7
/* 0x0028	     */		ble,pt	%icc,.L900000515
/* 0x002c	 190 */		cmp	%o7,%l1
/* 0x0030	   0 */		sethi	%hi(Zero),%g2
/* 0x0034	   0 */		add	%g2,%lo(Zero),%g2
/* 0x0038	 185 */		sub	%l1,4,%o1
/* 0x003c	   0 */		ldx	[%o0+%g2],%o2
/* 0x0040	     */		ldd	[%o2],%f8

!  186		      !		i16_to_d16_and_d32x4(&TwoToMinus16, &TwoTo16, &Zero,
!  187		      !					&(d16[2*i]), &(d32[i]),
!  188		      !					(float *)(&(i32[i])));

                       .L900000514:
/* 0x0044	 188 */		sra	%o7,0,%g2
/* 0x0048	     */		fmovd	%f8,%f10
/* 0x004c	     */		ldd	[%o2-8],%f6
/* 0x0050	     */		sllx	%g2,2,%g3
/* 0x0054	     */		fmovd	%f8,%f12
/* 0x0058	     */		ldd	[%o2-16],%f16
/* 0x005c	     */		ld	[%i2+%g3],%f11
/* 0x0060	     */		add	%i2,%g3,%g3
/* 0x0064	     */		fmovd	%f8,%f14
/* 0x0068	     */		ld	[%g3+4],%f13
/* 0x006c	     */		sra	%g5,0,%g4
/* 0x0070	     */		add	%o7,4,%o7
/* 0x0074	     */		ld	[%g3+8],%f15
/* 0x0078	     */		fxtod	%f10,%f10
/* 0x007c	     */		sllx	%g2,3,%g2
/* 0x0080	     */		ld	[%g3+12],%f9
/* 0x0084	     */		fxtod	%f12,%f12
/* 0x0088	     */		sllx	%g4,3,%g3
/* 0x008c	     */		fxtod	%f14,%f14
/* 0x0090	     */		std	%f10,[%i0+%g2]
/* 0x0094	     */		add	%i0,%g2,%g4
/* 0x0098	     */		fxtod	%f8,%f8
/* 0x009c	     */		fmuld	%f6,%f10,%f0
/* 0x00a0	     */		std	%f8,[%g4+24]
/* 0x00a4	     */		fmuld	%f6,%f12,%f2
/* 0x00a8	     */		std	%f12,[%g4+8]
/* 0x00ac	     */		add	%i1,%g3,%g2
/* 0x00b0	     */		fmuld	%f6,%f14,%f4
/* 0x00b4	     */		std	%f14,[%g4+16]
/* 0x00b8	     */		cmp	%o7,%o1
/* 0x00bc	     */		fmuld	%f6,%f8,%f6
/* 0x00c0	     */		fdtox	%f0,%f0
/* 0x00c4	     */		add	%g5,8,%g5
/* 0x00c8	     */		fdtox	%f2,%f2
/* 0x00cc	     */		fdtox	%f4,%f4
/* 0x00d0	     */		fdtox	%f6,%f6
/* 0x00d4	     */		fxtod	%f0,%f0
/* 0x00d8	     */		std	%f0,[%g2+8]
/* 0x00dc	     */		fxtod	%f2,%f2
/* 0x00e0	     */		std	%f2,[%g2+24]
/* 0x00e4	     */		fxtod	%f4,%f4
/* 0x00e8	     */		std	%f4,[%g2+40]
/* 0x00ec	     */		fxtod	%f6,%f6
/* 0x00f0	     */		std	%f6,[%g2+56]
/* 0x00f4	     */		fmuld	%f0,%f16,%f0
/* 0x00f8	     */		fmuld	%f2,%f16,%f2
/* 0x00fc	     */		fmuld	%f4,%f16,%f4
/* 0x0100	     */		fsubd	%f10,%f0,%f0
/* 0x0104	     */		std	%f0,[%i1+%g3]
/* 0x0108	     */		fmuld	%f6,%f16,%f6
/* 0x010c	     */		fsubd	%f12,%f2,%f2
/* 0x0110	     */		std	%f2,[%g2+16]
/* 0x0114	     */		fsubd	%f14,%f4,%f4
/* 0x0118	     */		std	%f4,[%g2+32]
/* 0x011c	     */		fsubd	%f8,%f6,%f6
/* 0x0120	     */		std	%f6,[%g2+48]
/* 0x0124	     */		ble,a,pt	%icc,.L900000514
/* 0x0128	     */		ldd	[%o2],%f8

!  189		      !	}
!  190		      !	for (; i < len; i++) {

                       .L77000212:
/* 0x012c	 190 */		cmp	%o7,%l1
                       .L900000515:
/* 0x0130	 190 */		bge,pt	%icc,.L77000217
/* 0x0134	     */		nop
/* 0x0138	     */		sll	%o7,1,%l0
/* 0x013c	   0 */		sethi	%hi(___const_seg_900000501),%g2
/* 0x0140	   0 */		add	%g2,%lo(___const_seg_900000501),%g2
/* 0x0144	 190 */		sub	%l1,%o7,%g4
/* 0x0148	   0 */		ldx	[%o0+%g2],%l6
/* 0x014c	 190 */		sethi	%hi(0xfc00),%g3
/* 0x0150	     */		cmp	%g4,7
/* 0x0154	     */		add	%g3,1023,%l2
/* 0x0158	     */		bl,pn	%icc,.L77000214
/* 0x015c	     */		add	%l0,1,%g2

!  191		      !		a = i32[i];

/* 0x0160	 191 */		sra	%o7,0,%o3

!  192		      !		d32[i] = (double)(i32[i]);

/* 0x0164	 192 */		ldd	[%l6],%f8

!  193		      !		d16[2 * i] = (double)(a & 0xffff);
!  194		      !		d16[2 * i + 1] = (double)(a >> 16);

/* 0x0168	 194 */		add	%o7,1,%g3
/* 0x016c	 191 */		sllx	%o3,2,%g5
/* 0x0170	 194 */		add	%o7,2,%o1
/* 0x0174	 191 */		sra	%g3,0,%o0
/* 0x0178	     */		ld	[%i2+%g5],%o2
/* 0x017c	 192 */		fmovs	%f8,%f6
/* 0x0180	 191 */		sllx	%o0,2,%o4
/* 0x0184	 193 */		fmovs	%f8,%f0
/* 0x0188	 194 */		add	%l0,2,%o5
/* 0x018c	 191 */		sra	%o1,0,%l7
/* 0x0190	 194 */		fmovs	%f8,%f2
/* 0x0194	 193 */		and	%o2,%l2,%g4
/* 0x0198	     */		st	%g4,[%sp+2227]
/* 0x019c	 194 */		srl	%o2,16,%o2
/* 0x01a0	     */		add	%l0,3,%g4
/* 0x01a4	 191 */		ld	[%i2+%o4],%o7
/* 0x01a8	 193 */		sra	%l0,0,%l0
/* 0x01ac	 190 */		sub	%l1,4,%g3
/* 0x01b0	 194 */		st	%o2,[%sp+2223]
/* 0x01b4	 191 */		sllx	%l7,2,%o2
/* 0x01b8	 192 */		ld	[%i2+%g5],%f7
/* 0x01bc	     */		sllx	%o3,3,%o3
/* 0x01c0	 193 */		and	%o7,%l2,%g5
/* 0x01c4	 194 */		srl	%o7,16,%o7
/* 0x01c8	     */		sra	%g2,0,%g2
/* 0x01cc	 192 */		fsubd	%f6,%f8,%f4
/* 0x01d0	 193 */		ld	[%sp+2227],%f1
/* 0x01d4	 194 */		sllx	%g2,3,%g2
/* 0x01d8	 193 */		st	%g5,[%sp+2227]
/* 0x01dc	 191 */		ld	[%i2+%o2],%g5
/* 0x01e0	 193 */		fsubd	%f0,%f8,%f0
/* 0x01e4	 194 */		ld	[%sp+2223],%f3
/* 0x01e8	     */		st	%o7,[%sp+2223]
/* 0x01ec	 193 */		sllx	%l0,3,%o7
/* 0x01f0	 192 */		std	%f4,[%i0+%o3]
/* 0x01f4	 193 */		std	%f0,[%i1+%o7]
/* 0x01f8	 194 */		fsubd	%f2,%f8,%f0
/* 0x01fc	 192 */		ld	[%i2+%o4],%f11
/* 0x0200	 194 */		std	%f0,[%i1+%g2]
                       .L900000508:
/* 0x0204	 193 */		ld	[%sp+2227],%f7
/* 0x0208	 190 */		nop ! volatile
/* 0x020c	     */		nop ! volatile
/* 0x0210	     */		nop ! volatile
/* 0x0214	     */		nop ! volatile
/* 0x0218	 194 */		add	%o1,1,%o1
/* 0x021c	     */		ld	[%sp+2223],%f1
/* 0x0220	 191 */		sra	%o1,0,%g2
/* 0x0224	     */		sllx	%g2,2,%o3
/* 0x0228	 193 */		and	%g5,%l2,%o4
/* 0x022c	 194 */		srl	%g5,16,%o7
/* 0x0230	 193 */		st	%o4,[%sp+2227]
/* 0x0234	     */		fmovs	%f8,%f6
/* 0x0238	 192 */		fmovs	%f8,%f10
/* 0x023c	 193 */		sra	%o5,0,%o4
/* 0x0240	 191 */		ld	[%i2+%o3],%g5
/* 0x0244	 194 */		st	%o7,[%sp+2223]
/* 0x0248	 192 */		fsubd	%f10,%f8,%f4
/* 0x024c	 193 */		sllx	%o4,3,%o4
/* 0x0250	     */		fsubd	%f6,%f8,%f6
/* 0x0254	 192 */		sllx	%o0,3,%o0
/* 0x0258	     */		ld	[%i2+%o2],%f3
/* 0x025c	     */		std	%f4,[%i0+%o0]
/* 0x0260	 194 */		sra	%g4,0,%o0
/* 0x0264	     */		add	%o5,2,%o2
/* 0x0268	     */		fmovs	%f8,%f0
/* 0x026c	 193 */		std	%f6,[%i1+%o4]
/* 0x0270	 194 */		sllx	%o0,3,%o0
/* 0x0274	     */		add	%g4,2,%o4
/* 0x0278	     */		fsubd	%f0,%f8,%f0
/* 0x027c	     */		std	%f0,[%i1+%o0]
/* 0x0280	 193 */		ld	[%sp+2227],%f1
/* 0x0284	 190 */		nop ! volatile
/* 0x0288	     */		nop ! volatile
/* 0x028c	     */		nop ! volatile
/* 0x0290	     */		nop ! volatile
/* 0x0294	 194 */		add	%o1,1,%o1
/* 0x0298	     */		ld	[%sp+2223],%f5
/* 0x029c	 191 */		sra	%o1,0,%o0
/* 0x02a0	     */		sllx	%o0,2,%g4
/* 0x02a4	 193 */		and	%g5,%l2,%o5
/* 0x02a8	 194 */		srl	%g5,16,%o7
/* 0x02ac	 193 */		st	%o5,[%sp+2227]
/* 0x02b0	     */		fmovs	%f8,%f0
/* 0x02b4	 192 */		fmovs	%f8,%f2
/* 0x02b8	 193 */		sra	%o2,0,%o5
/* 0x02bc	 191 */		ld	[%i2+%g4],%g5
/* 0x02c0	 194 */		st	%o7,[%sp+2223]
/* 0x02c4	 192 */		fsubd	%f2,%f8,%f2
/* 0x02c8	 193 */		sllx	%o5,3,%o5
/* 0x02cc	     */		fsubd	%f0,%f8,%f0
/* 0x02d0	 192 */		sllx	%l7,3,%o7
/* 0x02d4	     */		ld	[%i2+%o3],%f7
/* 0x02d8	     */		std	%f2,[%i0+%o7]
/* 0x02dc	 194 */		sra	%o4,0,%o7
/* 0x02e0	     */		add	%o2,2,%o3
/* 0x02e4	     */		fmovs	%f8,%f4
/* 0x02e8	 193 */		std	%f0,[%i1+%o5]
/* 0x02ec	 194 */		sllx	%o7,3,%o2
/* 0x02f0	     */		add	%o4,2,%o4
/* 0x02f4	     */		fsubd	%f4,%f8,%f0
/* 0x02f8	     */		std	%f0,[%i1+%o2]
/* 0x02fc	 193 */		ld	[%sp+2227],%f1
/* 0x0300	 190 */		nop ! volatile
/* 0x0304	     */		nop ! volatile
/* 0x0308	     */		nop ! volatile
/* 0x030c	     */		nop ! volatile
/* 0x0310	 194 */		add	%o1,1,%o1
/* 0x0314	     */		ld	[%sp+2223],%f3
/* 0x0318	 191 */		sra	%o1,0,%l7
/* 0x031c	     */		sllx	%l7,2,%o2
/* 0x0320	 193 */		and	%g5,%l2,%o5
/* 0x0324	 194 */		srl	%g5,16,%o7
/* 0x0328	 193 */		st	%o5,[%sp+2227]
/* 0x032c	     */		fmovs	%f8,%f0
/* 0x0330	 192 */		fmovs	%f8,%f6
/* 0x0334	 193 */		sra	%o3,0,%o5
/* 0x0338	 191 */		ld	[%i2+%o2],%g5
/* 0x033c	 194 */		st	%o7,[%sp+2223]
/* 0x0340	 192 */		fsubd	%f6,%f8,%f4
/* 0x0344	 193 */		sllx	%o5,3,%o7
/* 0x0348	     */		fsubd	%f0,%f8,%f0
/* 0x034c	 192 */		sllx	%g2,3,%g2
/* 0x0350	     */		ld	[%i2+%g4],%f11
/* 0x0354	     */		std	%f4,[%i0+%g2]
/* 0x0358	 194 */		sra	%o4,0,%g2
/* 0x035c	     */		add	%o3,2,%o5
/* 0x0360	     */		fmovs	%f8,%f2
/* 0x0364	 193 */		std	%f0,[%i1+%o7]
/* 0x0368	 194 */		sllx	%g2,3,%g2
/* 0x036c	     */		add	%o4,2,%g4
/* 0x0370	     */		fsubd	%f2,%f8,%f0
/* 0x0374	     */		cmp	%o1,%g3
/* 0x0378	     */		bl,pt	%icc,.L900000508
/* 0x037c	     */		std	%f0,[%i1+%g2]
                       .L900000511:
/* 0x0380	 194 */		add	%o1,1,%o7
/* 0x0384	 193 */		ld	[%sp+2227],%f1
/* 0x0388	 194 */		add	%o3,4,%g3
/* 0x038c	 192 */		fmovs	%f8,%f10
/* 0x0390	 191 */		sra	%o7,0,%o4
/* 0x0394	 193 */		and	%g5,%l2,%g2
/* 0x0398	     */		st	%g2,[%sp+2227]
/* 0x039c	 194 */		fmovs	%f8,%f2
/* 0x03a0	 191 */		sllx	%o4,2,%o3
/* 0x03a4	 193 */		fmovs	%f8,%f0
/* 0x03a8	 194 */		add	%g3,4,%l0
/* 0x03ac	     */		srl	%g5,16,%g2
/* 0x03b0	 191 */		ld	[%i2+%o3],%o1
/* 0x03b4	 192 */		fmovs	%f8,%f4
/* 0x03b8	 194 */		add	%g4,2,%g5
/* 0x03bc	     */		add	%o7,1,%o7
/* 0x03c0	     */		ld	[%sp+2223],%f3
/* 0x03c4	     */		sra	%g4,0,%g4
/* 0x03c8	 192 */		fsubd	%f10,%f8,%f6
/* 0x03cc	 194 */		st	%g2,[%sp+2223]
/* 0x03d0	 193 */		sra	%o5,0,%g2
/* 0x03d4	     */		fsubd	%f0,%f8,%f0
/* 0x03d8	 192 */		sllx	%o0,3,%o5
/* 0x03dc	     */		ld	[%i2+%o2],%f5
/* 0x03e0	 193 */		and	%o1,%l2,%o0
/* 0x03e4	     */		sllx	%g2,3,%g2
/* 0x03e8	 192 */		std	%f6,[%i0+%o5]
/* 0x03ec	 194 */		add	%g3,2,%o2
/* 0x03f0	 193 */		std	%f0,[%i1+%g2]
/* 0x03f4	 194 */		fsubd	%f2,%f8,%f0
/* 0x03f8	     */		sllx	%g4,3,%g4
/* 0x03fc	 193 */		sra	%g3,0,%g2
/* 0x0400	 194 */		std	%f0,[%i1+%g4]
/* 0x0404	 192 */		fsubd	%f4,%f8,%f4
/* 0x0408	 194 */		srl	%o1,16,%o1
/* 0x040c	     */		ld	[%sp+2223],%f3
/* 0x0410	     */		add	%g5,2,%o5
/* 0x0414	 193 */		ld	[%sp+2227],%f1
/* 0x0418	 192 */		sllx	%l7,3,%g3
/* 0x041c	 194 */		cmp	%o7,%l1
/* 0x0420	 193 */		st	%o0,[%sp+2227]
/* 0x0424	     */		sllx	%g2,3,%g4
/* 0x0428	 194 */		add	%g5,4,%g2
/* 0x042c	 193 */		fmovs	%f8,%f0
/* 0x0430	 194 */		st	%o1,[%sp+2223]
/* 0x0434	     */		sra	%g5,0,%g5
/* 0x0438	     */		fmovs	%f8,%f2
/* 0x043c	 192 */		std	%f4,[%i0+%g3]
/* 0x0440	 194 */		sllx	%g5,3,%g5
/* 0x0444	 192 */		ld	[%i2+%o3],%f7
/* 0x0448	 193 */		sra	%o2,0,%o0
/* 0x044c	     */		fsubd	%f0,%f8,%f0
/* 0x0450	     */		std	%f0,[%i1+%g4]
/* 0x0454	 192 */		sllx	%o4,3,%o1
/* 0x0458	 194 */		fsubd	%f2,%f8,%f0
/* 0x045c	     */		std	%f0,[%i1+%g5]
/* 0x0460	 193 */		sllx	%o0,3,%o0
/* 0x0464	 194 */		ld	[%sp+2223],%f3
/* 0x0468	     */		sra	%o5,0,%o2
/* 0x046c	 193 */		ld	[%sp+2227],%f1
/* 0x0470	 194 */		sllx	%o2,3,%g3
/* 0x0474	 192 */		fmovs	%f8,%f6
/* 0x0478	 193 */		fmovs	%f8,%f0
/* 0x047c	 194 */		fmovs	%f8,%f2
/* 0x0480	 192 */		fsubd	%f6,%f8,%f4
/* 0x0484	     */		std	%f4,[%i0+%o1]
/* 0x0488	 193 */		fsubd	%f0,%f8,%f0
/* 0x048c	     */		std	%f0,[%i1+%o0]
/* 0x0490	 194 */		fsubd	%f2,%f8,%f0
/* 0x0494	     */		bge,pn	%icc,.L77000217
/* 0x0498	     */		std	%f0,[%i1+%g3]
                       .L77000214:
/* 0x049c	 191 */		sra	%o7,0,%g3
                       .L900000513:
/* 0x04a0	 192 */		ldd	[%l6],%f8
/* 0x04a4	 191 */		sllx	%g3,2,%g4
/* 0x04a8	 194 */		add	%o7,1,%o7
/* 0x04ac	 192 */		ld	[%i2+%g4],%f1
/* 0x04b0	 193 */		sra	%l0,0,%g5
/* 0x04b4	 194 */		cmp	%o7,%l1
/* 0x04b8	 191 */		ld	[%i2+%g4],%g4
/* 0x04bc	 192 */		sllx	%g3,3,%g3
/* 0x04c0	 194 */		add	%l0,2,%l0
/* 0x04c4	 192 */		fmovs	%f8,%f0
/* 0x04c8	 193 */		sllx	%g5,3,%o0
/* 0x04cc	     */		and	%g4,%l2,%g5
/* 0x04d0	 192 */		fsubd	%f0,%f8,%f0
/* 0x04d4	     */		std	%f0,[%i0+%g3]
/* 0x04d8	 194 */		srl	%g4,16,%g3
/* 0x04dc	 193 */		st	%g5,[%sp+2227]
/* 0x04e0	 194 */		sra	%g2,0,%g4
/* 0x04e4	     */		add	%g2,2,%g2
/* 0x04e8	     */		sllx	%g4,3,%g4
/* 0x04ec	 193 */		fmovs	%f8,%f0
/* 0x04f0	     */		ld	[%sp+2227],%f1
/* 0x04f4	     */		fsubd	%f0,%f8,%f0
/* 0x04f8	     */		std	%f0,[%i1+%o0]
/* 0x04fc	 194 */		st	%g3,[%sp+2223]
/* 0x0500	     */		fmovs	%f8,%f0
/* 0x0504	     */		ld	[%sp+2223],%f1
/* 0x0508	     */		fsubd	%f0,%f8,%f0
/* 0x050c	     */		std	%f0,[%i1+%g4]
/* 0x0510	     */		bl,pt	%icc,.L900000513
/* 0x0514	     */		sra	%o7,0,%g3
                       .L77000217:
/* 0x0518	     */		ret	! Result =
/* 0x051c	     */		restore	%g0,%g0,%g0
/* 0x0520	   0 */		.type	conv_i32_to_d32_and_d16,2
/* 0x0520	   0 */		.size	conv_i32_to_d32_and_d16,(.-conv_i32_to_d32_and_d16)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	4

!  195		      !	}
!  196		      !}
!  199		      !static void
!  200		      !adjust_montf_result(uint32_t *i32, uint32_t *nint, int len)
!  201		      !{

!
! SUBROUTINE adjust_montf_result
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       adjust_montf_result:
/* 000000	 201 */		sra	%o2,0,%o3
/* 0x0004	     */		or	%g0,%o0,%o2

!  202		      !	int64_t acc;
!  203		      !	int i;
!  205		      !	if (i32[len] > 0)

/* 0x0008	 205 */		sllx	%o3,2,%o0
/* 0x000c	     */		ld	[%o2+%o0],%o0
/* 0x0010	     */		cmp	%o0,0
/* 0x0014	     */		bgu,pn	%icc,.L77000263
/* 0x0018	 208 */		subcc	%o3,1,%o5
/* 0x001c	     */		bneg,pn	%icc,.L77000263
/* 0x0020	 209 */		sra	%o5,0,%o0

!  206		      !		i = -1;
!  207		      !	else {
!  208		      !		for (i = len - 1; i >= 0; i--) {
!  209		      !			if (i32[i] != nint[i]) break;

                       .L900000612:
/* 0x0024	 209 */		sllx	%o0,2,%o0
/* 0x0028	     */		ld	[%o2+%o0],%o4
/* 0x002c	     */		ld	[%o1+%o0],%o0
/* 0x0030	     */		cmp	%o4,%o0
/* 0x0034	     */		bne,pn	%icc,.L77000248
/* 0x0038	     */		nop
/* 0x003c	     */		subcc	%o5,1,%o5
/* 0x0040	     */		bpos,pt	%icc,.L900000612
/* 0x0044	     */		sra	%o5,0,%o0
                       .L900000605:
/* 0x0048	 209 */		ba	.L900000611
/* 0x004c	 214 */		cmp	%o3,0
                       .L77000248:
/* 0x0050	 209 */		bleu,pt	%icc,.L77000256
/* 0x0054	     */		nop

!  210		      !		}
!  211		      !	}
!  212		      !	if ((i < 0) || (i32[i] > nint[i])) {
!  213		      !		acc = 0;
!  214		      !		for (i = 0; i < len; i++) {

                       .L77000263:
/* 0x0058	 214 */		cmp	%o3,0
                       .L900000611:
/* 0x005c	 214 */		ble,pt	%icc,.L77000256
/* 0x0060	     */		nop
/* 0x0064	 209 */		or	%g0,-1,%o4
/* 0x0068	 214 */		or	%g0,%o3,%o0
/* 0x006c	 209 */		sub	%o3,1,%g2
/* 0x0070	 214 */		or	%g0,0,%o3
/* 0x0074	 209 */		srl	%o4,0,%g3
/* 0x0078	 214 */		cmp	%o0,4
/* 0x007c	 213 */		or	%g0,0,%o5
/* 0x0080	 214 */		bl,pn	%icc,.L77000264
/* 0x0084	     */		or	%g0,%o1,%o4

!  215		      !			acc = acc + (uint64_t)(i32[i]) - (uint64_t)(nint[i]);

/* 0x0088	 215 */		ld	[%o2+4],%g5

!  216		      !			i32[i] = acc & 0xffffffff;
!  217		      !			acc = acc >> 32;

/* 0x008c	 217 */		add	%o1,4,%o4
/* 0x0090	     */		add	%o2,8,%o2
/* 0x0094	 214 */		sub	%o0,2,%g4
/* 0x0098	 215 */		ld	[%o2-8],%o1
/* 0x009c	 217 */		or	%g0,2,%o3
/* 0x00a0	 215 */		ld	[%o4-4],%o0
/* 0x00a4	 214 */		sub	%o1,%o0,%o0
/* 0x00a8	     */		or	%g0,%o0,%o1
/* 0x00ac	 216 */		and	%o0,%g3,%o0
/* 0x00b0	     */		st	%o0,[%o2-8]
/* 0x00b4	 217 */		srax	%o1,32,%o0
                       .L900000606:
/* 0x00b8	 217 */		add	%o3,1,%o3
/* 0x00bc	 215 */		ld	[%o4],%o1
/* 0x00c0	 217 */		add	%o4,4,%o4
/* 0x00c4	     */		cmp	%o3,%g4
/* 0x00c8	     */		add	%o2,4,%o2
/* 0x00cc	 214 */		sub	%g5,%o1,%o1
/* 0x00d0	     */		add	%o1,%o0,%o1
/* 0x00d4	 216 */		and	%o1,%g3,%o0
/* 0x00d8	 215 */		ld	[%o2-4],%g5
/* 0x00dc	 216 */		st	%o0,[%o2-8]
/* 0x00e0	 217 */		ble,pt	%icc,.L900000606
/* 0x00e4	     */		srax	%o1,32,%o0
                       .L900000609:
/* 0x00e8	 215 */		ld	[%o4],%o1
/* 0x00ec	 217 */		add	%o4,8,%o4
/* 0x00f0	     */		add	%o3,1,%o3
/* 0x00f4	 215 */		ld	[%o2],%o5
/* 0x00f8	 217 */		add	%o2,4,%o2
/* 0x00fc	     */		cmp	%o3,%g2
/* 0x0100	 214 */		sub	%g5,%o1,%o1
/* 0x0104	     */		add	%o1,%o0,%o1
/* 0x0108	 216 */		and	%o1,%g3,%o0
/* 0x010c	     */		st	%o0,[%o2-8]
/* 0x0110	 215 */		ld	[%o4-4],%o0
/* 0x0114	 217 */		srax	%o1,32,%o1
/* 0x0118	 214 */		sub	%o5,%o0,%o0
/* 0x011c	     */		add	%o0,%o1,%o1
/* 0x0120	 216 */		and	%o1,%g3,%o0
/* 0x0124	     */		st	%o0,[%o2-4]
/* 0x0128	 217 */		bg,pn	%icc,.L77000256
/* 0x012c	     */		srax	%o1,32,%o5
                       .L77000264:
/* 0x0130	 215 */		ld	[%o2],%o0
                       .L900000610:
/* 0x0134	 215 */		ld	[%o4],%o1
/* 0x0138	     */		add	%o5,%o0,%o0
/* 0x013c	 217 */		add	%o3,1,%o3
/* 0x0140	     */		add	%o4,4,%o4
/* 0x0144	     */		cmp	%o3,%g2
/* 0x0148	 215 */		sub	%o0,%o1,%o1
/* 0x014c	 216 */		and	%o1,%g3,%o0
/* 0x0150	     */		st	%o0,[%o2]
/* 0x0154	 217 */		add	%o2,4,%o2
/* 0x0158	     */		srax	%o1,32,%o5
/* 0x015c	     */		ble,a,pt	%icc,.L900000610
/* 0x0160	     */		ld	[%o2],%o0
                       .L77000256:
/* 0x0164	     */		retl	! Result =
/* 0x0168	     */		nop
/* 0x016c	   0 */		.type	adjust_montf_result,2
/* 0x016c	   0 */		.size	adjust_montf_result,(.-adjust_montf_result)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
/* 000000	     */		.skip	24
/* 0x0018	     */		.align	4

!  218		      !		}
!  219		      !	}
!  220		      !}
!  223		      !/*
!  224		      ! * the lengths of the input arrays should be at least the following:
!  225		      ! * result[nlen+1], dm1[nlen], dm2[2*nlen+1], dt[4*nlen+2], dn[nlen], nint[nlen]
!  226		      ! * all of them should be different from one another
!  227		      ! */
!  228		      !void mont_mulf_noconv(uint32_t *result,
!  229		      !			double *dm1, double *dm2, double *dt,
!  230		      !			double *dn, uint32_t *nint,
!  231		      !			int nlen, double dn0)
!  232		      !{

!
! SUBROUTINE mont_mulf_noconv
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global mont_mulf_noconv
                       mont_mulf_noconv:
/* 000000	 232 */		save	%sp,-224,%sp
                       .L900000738:
/* 0x0004	 232 */		call	.+8
/* 0x0008	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000738-.)),%g5
/* 0x000c	   0 */		sethi	%hi(Zero),%g2
/* 0x0010	 232 */		ldx	[%fp+2223],%g3
/* 0x0014	     */		fmovd	%f14,%f42
/* 0x0018	     */		add	%g5,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000738-.)),%g5
/* 0x001c	   0 */		add	%g2,%lo(Zero),%g2
/* 0x0020	 232 */		sra	%g3,0,%l4
/* 0x0024	     */		add	%g5,%o7,%o1

!  233		      !	int i, j, jj;
!  234		      !	double digit, m2j, a, b;
!  235		      !	double *pdm1, *pdm2, *pdn, *pdtj, pdn_0, pdm1_0;
!  237		      !	pdm1 = &(dm1[0]);
!  238		      !	pdm2 = &(dm2[0]);
!  239		      !	pdn = &(dn[0]);
!  240		      !	pdm2[2 * nlen] = Zero;

/* 0x0028	 240 */		sll	%l4,1,%g3
/* 0x002c	   0 */		ldx	[%o1+%g2],%o7
/* 0x0030	 232 */		or	%g0,%i2,%l3
/* 0x0034	 240 */		sra	%g3,0,%g2
/* 0x0038	 232 */		or	%g0,%i0,%l6
/* 0x003c	 240 */		sllx	%g2,3,%i2
/* 0x0040	     */		ldd	[%o7],%f0
/* 0x0044	 232 */		or	%g0,%i3,%l0
/* 0x0048	     */		or	%g0,%i5,%i0

!  242		      !	if (nlen != 16) {

/* 0x004c	 242 */		cmp	%l4,16
/* 0x0050	     */		be,pn	%icc,.L77000362
/* 0x0054	     */		std	%f0,[%l3+%i2]

!  243		      !		for (i = 0; i < 4 * nlen + 2; i++)

/* 0x0058	 243 */		sll	%l4,2,%g4
/* 0x005c	 232 */		or	%g0,%i1,%l5
/* 0x0060	 243 */		add	%g4,2,%g2
/* 0x0064	 232 */		or	%g0,%i4,%l7
/* 0x0068	 243 */		cmp	%g2,0
/* 0x006c	     */		ble,a,pt	%icc,.L900000752
/* 0x0070	 245 */		ldd	[%i1],%f4
/* 0x0074	 243 */		add	%g4,1,%o0
/* 0x0078	     */		or	%g0,0,%g4

!  244		      !			dt[i] = Zero;
!  245		      !		a = dt[0] = pdm1[0] * pdm2[0];
!  246		      !		digit = mod(lower32(a, Zero) * dn0, TwoToMinus16, TwoTo16);
!  248		      !		pdtj = &(dt[0]);
!  249		      !		for (j = jj = 0; j < 2 * nlen; j++, jj++, pdtj++) {
!  250		      !			m2j = pdm2[j];
!  251		      !			a = pdtj[0] + pdn[0] * digit;
!  252		      !			b = pdtj[1] + pdm1[0] * pdm2[j + 1] + a * TwoToMinus16;
!  253		      !			pdtj[1] = b;
!  255		      !#pragma pipeloop(0)
!  256		      !			for (i = 1; i < nlen; i++) {
!  257		      !				pdtj[2 * i] += pdm1[i] * m2j + pdn[i] * digit;
!  258		      !			}
!  259		      !			if (jj == 30) {
!  260		      !				cleanup(dt, j / 2 + 1, 2 * nlen + 1);
!  261		      !				jj = 0;
!  262		      !			}
!  264		      !			digit = mod(lower32(b, Zero) * dn0,
!  265		      !				    TwoToMinus16, TwoTo16);
!  266		      !		}
!  267		      !	} else {
!  268		      !		a = dt[0] = pdm1[0] * pdm2[0];
!  270		      !		dt[65] = dt[64] = dt[63] = dt[62] = dt[61] = dt[60] =
!  271		      !			dt[59] = dt[58] = dt[57] = dt[56] = dt[55] =
!  272		      !			dt[54] = dt[53] = dt[52] = dt[51] = dt[50] =
!  273		      !			dt[49] = dt[48] = dt[47] = dt[46] = dt[45] =
!  274		      !			dt[44] = dt[43] = dt[42] = dt[41] = dt[40] =
!  275		      !			dt[39] = dt[38] = dt[37] = dt[36] = dt[35] =
!  276		      !			dt[34] = dt[33] = dt[32] = dt[31] = dt[30] =
!  277		      !			dt[29] = dt[28] = dt[27] = dt[26] = dt[25] =
!  278		      !			dt[24] = dt[23] = dt[22] = dt[21] = dt[20] =
!  279		      !			dt[19] = dt[18] = dt[17] = dt[16] = dt[15] =
!  280		      !			dt[14] = dt[13] = dt[12] = dt[11] = dt[10] =
!  281		      !			dt[9] = dt[8] = dt[7] = dt[6] = dt[5] = dt[4] =
!  282		      !			dt[3] = dt[2] = dt[1] = Zero;
!  284		      !		pdn_0 = pdn[0];
!  285		      !		pdm1_0 = pdm1[0];
!  287		      !		digit = mod(lower32(a, Zero) * dn0, TwoToMinus16, TwoTo16);
!  288		      !		pdtj = &(dt[0]);
!  290		      !		for (j = 0; j < 32; j++, pdtj++) {

/* 0x007c	 290 */		add	%o0,1,%g2
/* 0x0080	     */		cmp	%g2,3
/* 0x0084	     */		bl,pn	%icc,.L77000363
/* 0x0088	     */		or	%g0,%i3,%g5
/* 0x008c	 244 */		std	%f0,[%i3]
/* 0x0090	     */		add	%i3,8,%g5
/* 0x0094	 290 */		sub	%o0,1,%g2
/* 0x0098	 244 */		or	%g0,1,%g4
                       .L900000722:
/* 0x009c	 244 */		std	%f0,[%g5]
/* 0x00a0	     */		add	%g4,2,%g4
/* 0x00a4	     */		add	%g5,16,%g5
/* 0x00a8	     */		cmp	%g4,%g2
/* 0x00ac	     */		ble,pt	%icc,.L900000722
/* 0x00b0	     */		std	%f0,[%g5-8]
                       .L900000725:
/* 0x00b4	 244 */		cmp	%g4,%o0
/* 0x00b8	     */		bg,pn	%icc,.L77000368
/* 0x00bc	     */		nop ! volatile
                       .L77000363:
/* 0x00c0	 244 */		ldd	[%o7],%f0
                       .L900000751:
/* 0x00c4	 244 */		std	%f0,[%g5]
/* 0x00c8	     */		add	%g4,1,%g4
/* 0x00cc	     */		add	%g5,8,%g5
/* 0x00d0	     */		cmp	%g4,%o0
/* 0x00d4	     */		ble,a,pt	%icc,.L900000751
/* 0x00d8	     */		ldd	[%o7],%f0
                       .L77000368:
/* 0x00dc	 245 */		ldd	[%i1],%f4
                       .L900000752:
/* 0x00e0	 249 */		cmp	%g3,0
/* 0x00e4	 260 */		add	%g3,1,%g2
/* 0x00e8	 245 */		ldd	[%l3],%f0
/* 0x00ec	 260 */		sll	%g2,1,%i1
/* 0x00f0	 248 */		or	%g0,%i3,%o4
/* 0x00f4	 246 */		ldd	[%o7],%f2
/* 0x00f8	 260 */		add	%l5,8,%g2
/* 0x00fc	 249 */		or	%g0,0,%i4
/* 0x0100	 245 */		fmuld	%f4,%f0,%f0
/* 0x0104	     */		std	%f0,[%i3]
/* 0x0108	 243 */		sub	%g3,1,%i3
/* 0x010c	 246 */		ldd	[%o7-8],%f28
/* 0x0110	 260 */		add	%l7,8,%g3
/* 0x0114	 249 */		or	%g0,0,%l1
/* 0x0118	 246 */		ldd	[%o7-16],%f30
/* 0x011c	 260 */		sub	%l4,1,%o5
/* 0x0120	     */		or	%g0,1,%l2
/* 0x0124	     */		fdtox	%f0,%f4
/* 0x0128	     */		fmovs	%f2,%f4
/* 0x012c	     */		fxtod	%f4,%f0
/* 0x0130	 246 */		fmuld	%f0,%f14,%f0
/* 0x0134	     */		fmuld	%f0,%f28,%f2
/* 0x0138	     */		fdtox	%f2,%f2
/* 0x013c	     */		fxtod	%f2,%f2
/* 0x0140	     */		fmuld	%f2,%f30,%f2
/* 0x0144	     */		fsubd	%f0,%f2,%f22
/* 0x0148	 249 */		ble,pt	%icc,.L900000745
/* 0x014c	 324 */		add	%l0,%i2,%g4
/* 0x0150	 252 */		ldd	[%l7],%f0
/* 0x0154	 260 */		stx	%g3,[%sp+2223]
/* 0x0158	     */		stx	%g2,[%sp+2231]
                       .L900000746:
/* 0x015c	 252 */		sra	%l2,0,%g2
/* 0x0160	     */		fmuld	%f0,%f22,%f4
/* 0x0164	     */		ldd	[%l5],%f2
/* 0x0168	     */		sllx	%g2,3,%g2
/* 0x016c	     */		ldd	[%o4],%f6
/* 0x0170	 256 */		cmp	%l4,1
/* 0x0174	 252 */		ldd	[%l3+%g2],%f0
/* 0x0178	 250 */		sra	%l1,0,%g2
/* 0x017c	 256 */		or	%g0,1,%g4
/* 0x0180	 252 */		faddd	%f6,%f4,%f6
/* 0x0184	 250 */		sllx	%g2,3,%g2
/* 0x0188	 260 */		ldx	[%sp+2231],%g5
/* 0x018c	 252 */		fmuld	%f2,%f0,%f0
/* 0x0190	     */		ldd	[%o4+8],%f2
/* 0x0194	 257 */		or	%g0,32,%o1
/* 0x0198	 250 */		ldd	[%l3+%g2],%f24
/* 0x019c	 256 */		sub	%l4,3,%i5
/* 0x01a0	 257 */		or	%g0,16,%o2
/* 0x01a4	 260 */		ldx	[%sp+2223],%g3
/* 0x01a8	 257 */		or	%g0,6,%o3
/* 0x01ac	 252 */		faddd	%f2,%f0,%f0
/* 0x01b0	     */		fmuld	%f6,%f28,%f2
/* 0x01b4	     */		faddd	%f0,%f2,%f26
/* 0x01b8	 253 */		std	%f26,[%o4+8]
/* 0x01bc	 256 */		ble,pt	%icc,.L900000750
/* 0x01c0	 259 */		cmp	%i4,30
/* 0x01c4	 256 */		cmp	%o5,7
/* 0x01c8	     */		bl,pn	%icc,.L77000367
/* 0x01cc	     */		or	%g0,2,%o0
/* 0x01d0	 257 */		ldd	[%l5+8],%f4
/* 0x01d4	     */		add	%l7,32,%g3
/* 0x01d8	     */		add	%l5,40,%g5
/* 0x01dc	     */		ldd	[%l7+8],%f0
/* 0x01e0	     */		or	%g0,5,%g4
/* 0x01e4	     */		or	%g0,6,%o0
/* 0x01e8	     */		ldd	[%l5+16],%f2
/* 0x01ec	     */		fmuld	%f4,%f24,%f10
/* 0x01f0	     */		ldd	[%l7+16],%f8
/* 0x01f4	     */		fmuld	%f0,%f22,%f0
/* 0x01f8	     */		ldd	[%o4+16],%f14
/* 0x01fc	     */		fmuld	%f2,%f24,%f4
/* 0x0200	     */		ldd	[%l5+24],%f2
/* 0x0204	     */		ldd	[%l7+24],%f6
/* 0x0208	     */		faddd	%f10,%f0,%f10
/* 0x020c	     */		ldd	[%o4+%o1],%f12
/* 0x0210	     */		ldd	[%l5+32],%f0
                       .L900000734:
/* 0x0214	 257 */		sllx	%o0,3,%g2
/* 0x0218	     */		add	%g4,3,%g4
/* 0x021c	     */		ldd	[%g3],%f16
/* 0x0220	     */		fmuld	%f8,%f22,%f8
/* 0x0224	     */		add	%o3,2,%o0
/* 0x0228	     */		cmp	%g4,%i5
/* 0x022c	     */		ldd	[%o4+%g2],%f18
/* 0x0230	     */		sra	%o0,0,%o3
/* 0x0234	     */		add	%g3,24,%g3
/* 0x0238	     */		ldd	[%g5],%f20
/* 0x023c	     */		faddd	%f14,%f10,%f10
/* 0x0240	     */		std	%f10,[%o4+%o2]
/* 0x0244	     */		faddd	%f4,%f8,%f4
/* 0x0248	     */		add	%g5,24,%g5
/* 0x024c	     */		fmuld	%f2,%f24,%f10
/* 0x0250	     */		fmuld	%f6,%f22,%f6
/* 0x0254	     */		sllx	%o3,3,%o2
/* 0x0258	     */		ldd	[%g3-16],%f8
/* 0x025c	     */		add	%o0,2,%o0
/* 0x0260	     */		ldd	[%o4+%o2],%f14
/* 0x0264	     */		sra	%o0,0,%o3
/* 0x0268	     */		faddd	%f12,%f4,%f4
/* 0x026c	     */		ldd	[%g5-16],%f2
/* 0x0270	     */		std	%f4,[%o4+%o1]
/* 0x0274	     */		faddd	%f10,%f6,%f4
/* 0x0278	     */		fmuld	%f0,%f24,%f10
/* 0x027c	     */		fmuld	%f16,%f22,%f16
/* 0x0280	     */		sllx	%o3,3,%o1
/* 0x0284	     */		ldd	[%g3-8],%f6
/* 0x0288	     */		add	%o0,2,%o3
/* 0x028c	     */		ldd	[%o4+%o1],%f12
/* 0x0290	     */		sra	%o3,0,%o0
/* 0x0294	     */		faddd	%f18,%f4,%f4
/* 0x0298	     */		ldd	[%g5-8],%f0
/* 0x029c	     */		std	%f4,[%o4+%g2]
/* 0x02a0	     */		faddd	%f10,%f16,%f10
/* 0x02a4	     */		ble,pt	%icc,.L900000734
/* 0x02a8	     */		fmuld	%f20,%f24,%f4
                       .L900000737:
/* 0x02ac	 257 */		fmuld	%f8,%f22,%f8
/* 0x02b0	     */		ldd	[%g3],%f16
/* 0x02b4	     */		sllx	%o0,3,%g2
/* 0x02b8	     */		faddd	%f14,%f10,%f10
/* 0x02bc	     */		ldd	[%o4+%g2],%f14
/* 0x02c0	     */		fmuld	%f2,%f24,%f2
/* 0x02c4	     */		add	%o3,2,%o0
/* 0x02c8	     */		fmuld	%f6,%f22,%f6
/* 0x02cc	     */		std	%f10,[%o4+%o2]
/* 0x02d0	     */		sra	%o0,0,%o2
/* 0x02d4	     */		faddd	%f4,%f8,%f4
/* 0x02d8	     */		fmuld	%f0,%f24,%f0
/* 0x02dc	     */		sllx	%o2,3,%o2
/* 0x02e0	     */		fmuld	%f16,%f22,%f8
/* 0x02e4	     */		cmp	%g4,%o5
/* 0x02e8	     */		add	%o3,4,%o0
/* 0x02ec	     */		faddd	%f2,%f6,%f2
/* 0x02f0	     */		add	%g3,8,%g3
/* 0x02f4	     */		ldd	[%o4+%o2],%f10
/* 0x02f8	     */		faddd	%f12,%f4,%f4
/* 0x02fc	     */		faddd	%f0,%f8,%f0
/* 0x0300	     */		std	%f4,[%o4+%o1]
/* 0x0304	     */		faddd	%f14,%f2,%f2
/* 0x0308	     */		std	%f2,[%o4+%g2]
/* 0x030c	     */		faddd	%f10,%f0,%f0
/* 0x0310	     */		bg,pn	%icc,.L77000296
/* 0x0314	     */		std	%f0,[%o4+%o2]
                       .L77000367:
/* 0x0318	 257 */		ldd	[%g5],%f2
                       .L900000749:
/* 0x031c	 257 */		ldd	[%g3],%f0
/* 0x0320	     */		fmuld	%f2,%f24,%f2
/* 0x0324	     */		sra	%o0,0,%g2
/* 0x0328	     */		sllx	%g2,3,%g2
/* 0x032c	     */		add	%g4,1,%g4
/* 0x0330	     */		fmuld	%f0,%f22,%f0
/* 0x0334	     */		ldd	[%o4+%g2],%f4
/* 0x0338	     */		add	%g5,8,%g5
/* 0x033c	     */		add	%g3,8,%g3
/* 0x0340	     */		add	%o0,2,%o0
/* 0x0344	     */		cmp	%g4,%o5
/* 0x0348	     */		faddd	%f2,%f0,%f0
/* 0x034c	     */		faddd	%f4,%f0,%f0
/* 0x0350	     */		std	%f0,[%o4+%g2]
/* 0x0354	     */		ble,a,pt	%icc,.L900000749
/* 0x0358	     */		ldd	[%g5],%f2
                       .L77000296:
/* 0x035c	 259 */		cmp	%i4,30
                       .L900000750:
/* 0x0360	 259 */		bne,a,pt	%icc,.L900000748
/* 0x0364	     */		fdtox	%f26,%f0
/* 0x0368	 260 */		srl	%l1,31,%g2
/* 0x036c	     */		ldd	[%o7],%f12
/* 0x0370	 259 */		sub	%i1,1,%o0
/* 0x0374	 260 */		add	%l1,%g2,%g2
/* 0x0378	     */		sra	%g2,1,%g2
/* 0x037c	     */		fmovd	%f12,%f10
/* 0x0380	     */		add	%g2,1,%g2
/* 0x0384	     */		sll	%g2,1,%g2
/* 0x0388	     */		cmp	%g2,%i1
/* 0x038c	     */		bge,pt	%icc,.L77000298
/* 0x0390	 261 */		or	%g0,0,%i4
/* 0x0394	 260 */		or	%g0,%g2,%g4
/* 0x0398	 259 */		add	%g2,1,%g5
/* 0x039c	 260 */		sra	%g4,0,%g2
                       .L900000747:
/* 0x03a0	 260 */		sllx	%g2,3,%g2
/* 0x03a4	     */		ldd	[%o7],%f4
/* 0x03a8	     */		add	%g4,2,%g4
/* 0x03ac	     */		sra	%g5,0,%g3
/* 0x03b0	     */		ldd	[%l0+%g2],%f6
/* 0x03b4	     */		add	%g5,2,%g5
/* 0x03b8	     */		sllx	%g3,3,%g3
/* 0x03bc	     */		cmp	%g4,%o0
/* 0x03c0	     */		ldd	[%l0+%g3],%f8
/* 0x03c4	     */		fdtox	%f6,%f0
/* 0x03c8	     */		fdtox	%f8,%f2
/* 0x03cc	     */		fmovs	%f4,%f0
/* 0x03d0	     */		fmovs	%f4,%f2
/* 0x03d4	     */		fxtod	%f0,%f0
/* 0x03d8	     */		fdtox	%f6,%f4
/* 0x03dc	     */		fxtod	%f2,%f2
/* 0x03e0	     */		fdtox	%f8,%f6
/* 0x03e4	     */		faddd	%f0,%f10,%f0
/* 0x03e8	     */		std	%f0,[%l0+%g2]
/* 0x03ec	     */		faddd	%f2,%f12,%f0
/* 0x03f0	     */		std	%f0,[%l0+%g3]
/* 0x03f4	     */		fitod	%f4,%f10
/* 0x03f8	     */		fitod	%f6,%f12
/* 0x03fc	     */		ble,pt	%icc,.L900000747
/* 0x0400	     */		sra	%g4,0,%g2
                       .L77000316:
/* 0x0404	 261 */		or	%g0,0,%i4
                       .L77000298:
/* 0x0408	     */		fdtox	%f26,%f0
                       .L900000748:
/* 0x040c	 265 */		ldd	[%o7],%f2
/* 0x0410	     */		add	%l1,1,%l1
/* 0x0414	     */		add	%l2,1,%l2
/* 0x0418	     */		add	%i4,1,%i4
/* 0x041c	     */		add	%o4,8,%o4
/* 0x0420	     */		cmp	%l1,%i3
/* 0x0424	     */		fmovs	%f2,%f0
/* 0x0428	     */		fxtod	%f0,%f0
/* 0x042c	     */		fmuld	%f0,%f42,%f0
/* 0x0430	     */		fmuld	%f0,%f28,%f2
/* 0x0434	     */		fdtox	%f2,%f2
/* 0x0438	     */		fxtod	%f2,%f2
/* 0x043c	     */		fmuld	%f2,%f30,%f2
/* 0x0440	     */		fsubd	%f0,%f2,%f22
/* 0x0444	     */		ble,a,pt	%icc,.L900000746
/* 0x0448	 252 */		ldd	[%l7],%f0
                       .L900000721:
/* 0x044c	 265 */		ba	.L900000745
/* 0x0450	 324 */		add	%l0,%i2,%g4
                       .L77000362:
/* 0x0454	 268 */		ldd	[%i1],%f4
/* 0x0458	 290 */		or	%g0,1,%g5
/* 0x045c	 288 */		or	%g0,%i3,%g4
/* 0x0460	 268 */		ldd	[%l3],%f2
/* 0x0464	 282 */		std	%f0,[%i3+8]
/* 0x0468	     */		std	%f0,[%i3+16]
/* 0x046c	 268 */		fmuld	%f4,%f2,%f2
/* 0x0470	     */		std	%f2,[%i3]
/* 0x0474	 282 */		std	%f0,[%i3+24]
/* 0x0478	     */		std	%f0,[%i3+32]
/* 0x047c	     */		fdtox	%f2,%f2
/* 0x0480	     */		std	%f0,[%i3+40]
/* 0x0484	     */		std	%f0,[%i3+48]
/* 0x0488	     */		std	%f0,[%i3+56]
/* 0x048c	     */		std	%f0,[%i3+64]
/* 0x0490	     */		fmovs	%f0,%f2
/* 0x0494	     */		std	%f0,[%i3+72]
/* 0x0498	     */		std	%f0,[%i3+80]
/* 0x049c	     */		fxtod	%f2,%f2
/* 0x04a0	     */		std	%f0,[%i3+88]
/* 0x04a4	     */		std	%f0,[%i3+96]
/* 0x04a8	     */		std	%f0,[%i3+104]
/* 0x04ac	     */		std	%f0,[%i3+112]
/* 0x04b0	     */		std	%f0,[%i3+120]
/* 0x04b4	     */		std	%f0,[%i3+128]
/* 0x04b8	     */		std	%f0,[%i3+136]
/* 0x04bc	     */		std	%f0,[%i3+144]
/* 0x04c0	     */		std	%f0,[%i3+152]
/* 0x04c4	     */		std	%f0,[%i3+160]
/* 0x04c8	     */		std	%f0,[%i3+168]
/* 0x04cc	     */		std	%f0,[%i3+176]
/* 0x04d0	     */		std	%f0,[%i3+184]
/* 0x04d4	     */		std	%f0,[%i3+192]
/* 0x04d8	     */		std	%f0,[%i3+200]
/* 0x04dc	     */		std	%f0,[%i3+208]
/* 0x04e0	     */		std	%f0,[%i3+216]
/* 0x04e4	     */		std	%f0,[%i3+224]
/* 0x04e8	     */		std	%f0,[%i3+232]
/* 0x04ec	     */		std	%f0,[%i3+240]
/* 0x04f0	     */		std	%f0,[%i3+248]
/* 0x04f4	 287 */		fmuld	%f2,%f14,%f6

!  292		      !			m2j = pdm2[j];
!  293		      !			a = pdtj[0] + pdn_0 * digit;
!  294		      !			b = pdtj[1] + pdm1_0 * pdm2[j + 1] + a * TwoToMinus16;

/* 0x04f8	 294 */		sra	%g5,0,%g2
/* 0x04fc	 282 */		std	%f0,[%i3+256]
/* 0x0500	 290 */		or	%g0,0,%g3
/* 0x0504	 282 */		std	%f0,[%i3+264]
/* 0x0508	     */		std	%f0,[%i3+272]
/* 0x050c	     */		std	%f0,[%i3+280]
/* 0x0510	     */		std	%f0,[%i3+288]
/* 0x0514	     */		std	%f0,[%i3+296]
/* 0x0518	     */		std	%f0,[%i3+304]
/* 0x051c	     */		std	%f0,[%i3+312]
/* 0x0520	     */		std	%f0,[%i3+320]
/* 0x0524	     */		std	%f0,[%i3+328]
/* 0x0528	     */		std	%f0,[%i3+336]
/* 0x052c	     */		std	%f0,[%i3+344]
/* 0x0530	     */		std	%f0,[%i3+352]
/* 0x0534	     */		std	%f0,[%i3+360]
/* 0x0538	     */		std	%f0,[%i3+368]
/* 0x053c	     */		std	%f0,[%i3+376]
/* 0x0540	     */		std	%f0,[%i3+384]
/* 0x0544	     */		std	%f0,[%i3+392]
/* 0x0548	     */		std	%f0,[%i3+400]
/* 0x054c	     */		std	%f0,[%i3+408]
/* 0x0550	 287 */		ldd	[%o7-8],%f44
/* 0x0554	     */		ldd	[%o7-16],%f46
/* 0x0558	 282 */		std	%f0,[%i3+416]
/* 0x055c	     */		fmuld	%f6,%f44,%f4
/* 0x0560	     */		std	%f0,[%i3+424]
/* 0x0564	     */		std	%f0,[%i3+432]
/* 0x0568	     */		std	%f0,[%i3+440]
/* 0x056c	     */		fdtox	%f4,%f2
/* 0x0570	     */		std	%f0,[%i3+448]
/* 0x0574	     */		std	%f0,[%i3+456]
/* 0x0578	     */		std	%f0,[%i3+464]
/* 0x057c	     */		fxtod	%f2,%f2
/* 0x0580	     */		std	%f0,[%i3+472]
/* 0x0584	     */		std	%f0,[%i3+480]
/* 0x0588	     */		std	%f0,[%i3+488]
/* 0x058c	     */		fmuld	%f2,%f46,%f2
/* 0x0590	     */		std	%f0,[%i3+496]
/* 0x0594	     */		std	%f0,[%i3+504]
/* 0x0598	     */		std	%f0,[%i3+512]
/* 0x059c	     */		fsubd	%f6,%f2,%f38
/* 0x05a0	     */		std	%f0,[%i3+520]
/* 0x05a4	 284 */		ldd	[%i4],%f36
/* 0x05a8	 285 */		ldd	[%i1],%f40
                       .L900000744:




	fmovd %f38,%f0
	fmovd %f42,%f18
	ldd [%i4],%f2
	ldd [%g4],%f8
	ldd [%i1],%f10
	ldd [%o7-8],%f14
	ldd [%o7-16],%f16
	ldd [%l3],%f24

	ldd [%i1+8],%f26
	ldd [%i1+16],%f40
	ldd [%i1+48],%f46
	ldd [%i1+56],%f30
	ldd [%i1+64],%f54
	ldd [%i1+104],%f34
	ldd [%i1+112],%f58

	ldd [%i4+8],%f28
	ldd [%i4+104],%f38
	ldd [%i4+112],%f60


	.L99999999:
!1
	ldd	[%i1+24],%f32
	fmuld	%f0,%f2,%f4
!2
	ldd	[%i4+24],%f36
	fmuld	%f26,%f24,%f20
!3
	ldd	[%i1+40],%f42
	fmuld	%f28,%f0,%f22
!4
	ldd	[%i4+40],%f44
	fmuld	%f32,%f24,%f32
!5
	ldd	[%l3+8],%f6
	faddd	%f4,%f8,%f4
	fmuld	%f36,%f0,%f36
!6
	add	%l3,8,%l3
	ldd	[%i4+56],%f50
	fmuld	%f42,%f24,%f42
!7
	ldd	[%i1+72],%f52
	faddd	%f20,%f22,%f20
	fmuld	%f44,%f0,%f44
!8
	ldd	[%g4+16],%f22
	fmuld	%f10,%f6,%f12
!9
	ldd	[%i4+72],%f56
	faddd	%f32,%f36,%f32
	fmuld	%f14,%f4,%f4
!10
	ldd	[%g4+48],%f36
	fmuld	%f30,%f24,%f48
!11
	ldd	[%g4+8],%f8
	faddd	%f20,%f22,%f20
	fmuld	%f50,%f0,%f50
!12
	std	%f20,[%g4+16]
	faddd	%f42,%f44,%f42
	fmuld	%f52,%f24,%f52
!13
	ldd	[%g4+80],%f44
	faddd	%f4,%f12,%f4
	fmuld	%f56,%f0,%f56
!14
	ldd	[%i1+88],%f20
	faddd	%f32,%f36,%f32
!15
	ldd	[%i4+88],%f22
	faddd	%f48,%f50,%f48
!16
	ldd	[%g4+112],%f50
	faddd	%f52,%f56,%f52
!17
	ldd	[%g4+144],%f56
	faddd	%f4,%f8,%f8
	fmuld	%f20,%f24,%f20
!18
	std	%f32,[%g4+48]
	faddd	%f42,%f44,%f42
	fmuld	%f22,%f0,%f22
!19
	std	%f42,[%g4+80]
	faddd	%f48,%f50,%f48
	fmuld	%f34,%f24,%f32
!20
	std	%f48,[%g4+112]
	faddd	%f52,%f56,%f52
	fmuld	%f38,%f0,%f36
!21
	ldd	[%i1+120],%f42
	fdtox	%f8,%f4
!22
	std	%f52,[%g4+144]
	faddd	%f20,%f22,%f20
!23
	ldd	[%i4+120],%f44
!24
	ldd	[%g4+176],%f22
	faddd	%f32,%f36,%f32
	fmuld	%f42,%f24,%f42
!25
	ldd	[%i4+16],%f50
	fmovs	%f17,%f4
!26
	ldd	[%i1+32],%f52
	fmuld	%f44,%f0,%f44
!27
	ldd	[%i4+32],%f56
	fmuld	%f40,%f24,%f48
!28
	ldd	[%g4+208],%f36
	faddd	%f20,%f22,%f20
	fmuld	%f50,%f0,%f50
!29
	std	%f20,[%g4+176]
	fxtod	%f4,%f4
	fmuld	%f52,%f24,%f52
!30
	ldd	[%i4+48],%f22
	faddd	%f42,%f44,%f42
	fmuld	%f56,%f0,%f56
!31
	ldd	[%g4+240],%f44
	faddd	%f32,%f36,%f32
!32
	std	%f32,[%g4+208]
	faddd	%f48,%f50,%f48
	fmuld	%f46,%f24,%f20
!33
	ldd	[%g4+32],%f50
	fmuld	%f4,%f18,%f12
!34
	ldd	[%i4+64],%f36
	faddd	%f52,%f56,%f52
	fmuld	%f22,%f0,%f22
!35
	ldd	[%g4+64],%f56
	faddd	%f42,%f44,%f42
!36
	std	%f42,[%g4+240]
	faddd	%f48,%f50,%f48
	fmuld	%f54,%f24,%f32
!37
	std	%f48,[%g4+32]
	fmuld	%f12,%f14,%f4
!38
	ldd	[%i1+80],%f42
	faddd	%f52,%f56,%f56	! yes, tmp52!
	fmuld	%f36,%f0,%f36
!39
	ldd	[%i4+80],%f44
	faddd	%f20,%f22,%f20
!40
	ldd	[%i1+96],%f48
	fmuld	%f58,%f24,%f52
!41
	ldd	[%i4+96],%f50
	fdtox	%f4,%f4
	fmuld	%f42,%f24,%f42
!42
	std	%f56,[%g4+64]	! yes, tmp52!
	faddd	%f32,%f36,%f32
	fmuld	%f44,%f0,%f44
!43
	ldd	[%g4+96],%f22
	fmuld	%f48,%f24,%f48
!44
	ldd	[%g4+128],%f36
	fmovd	%f6,%f24
	fmuld	%f50,%f0,%f50
!45
	fxtod	%f4,%f4
	fmuld	%f60,%f0,%f56
!46
	add	%g4,8,%g4
	faddd	%f42,%f44,%f42
!47
	ldd	[%g4+160-8],%f44
	faddd	%f20,%f22,%f20
!48
	std	%f20,[%g4+96-8]
	faddd	%f48,%f50,%f48
!49
	ldd	[%g4+192-8],%f50
	faddd	%f52,%f56,%f52
	fmuld	%f4,%f16,%f4
!50
	ldd	[%g4+224-8],%f56
	faddd	%f32,%f36,%f32
!51
	std	%f32,[%g4+128-8]
	faddd	%f42,%f44,%f42
!52
	add	%g3,1,%g3
	std	%f42,[%g4+160-8]
	faddd	%f48,%f50,%f48
!53
	cmp	%g3,31
	std	%f48,[%g4+192-8]
	fsubd	%f12,%f4,%f0
!54
	faddd	%f52,%f56,%f52
	ble,pt	%icc,.L99999999
	std	%f52,[%g4+224-8]
!55
	std %f8,[%g4]







!  321		      !		}
!  322		      !	}
!  324		      !	conv_d16_to_i32(result, dt + 2 * nlen, (int64_t *)dt, nlen + 1);

                       .L77000371:
/* 0x0808	 324 */		add	%l0,%i2,%g4
                       .L900000745:
/* 0x080c	 324 */		ldd	[%l0+%i2],%f0
/* 0x0810	   0 */		or	%g0,-1,%l3
/* 0x0814	 324 */		ldd	[%g4+8],%f2
/* 0x0818	     */		or	%g0,0,%i2
/* 0x081c	     */		or	%g0,0,%o5
/* 0x0820	     */		fdtox	%f0,%f0
/* 0x0824	     */		std	%f0,[%sp+2263]
/* 0x0828	     */		cmp	%l4,0
/* 0x082c	     */		fdtox	%f2,%f0
/* 0x0830	     */		std	%f0,[%sp+2255]
/* 0x0834	 320 */		srl	%l3,0,%l2
/* 0x0838	     */		or	%g0,2,%o0
/* 0x083c	     */		sub	%l4,1,%l0
/* 0x0840	     */		or	%g0,%l6,%o7
/* 0x0844	 324 */		or	%g0,32,%o3
/* 0x0848	     */		or	%g0,16,%g3
/* 0x084c	     */		or	%g0,40,%o4
/* 0x0850	     */		ldx	[%sp+2255],%g5
/* 0x0854	     */		or	%g0,9,%i3
/* 0x0858	     */		or	%g0,8,%i4
/* 0x085c	     */		ldx	[%sp+2263],%o1
/* 0x0860	     */		ble,pt	%icc,.L900000743
/* 0x0864	 320 */		sethi	%hi(0xfc00),%g2
/* 0x0868	     */		sethi	%hi(0xfc00),%g2
/* 0x086c	 324 */		cmp	%l4,7
/* 0x0870	 320 */		add	%g2,1023,%l1
/* 0x0874	 324 */		bl,pn	%icc,.L77000372
/* 0x0878	     */		or	%g0,3,%o2
/* 0x087c	     */		ldd	[%g4+16],%f0
/* 0x0880	     */		srax	%g5,16,%o2
/* 0x0884	     */		and	%g5,%l1,%g3
/* 0x0888	     */		ldd	[%g4+24],%f2
/* 0x088c	     */		sllx	%g3,16,%o0
/* 0x0890	     */		and	%o1,%l2,%i1
/* 0x0894	     */		fdtox	%f0,%f0
/* 0x0898	     */		std	%f0,[%sp+2247]
/* 0x089c	     */		add	%i1,%o0,%i1
/* 0x08a0	     */		fdtox	%f2,%f0
/* 0x08a4	     */		std	%f0,[%sp+2239]
/* 0x08a8	     */		or	%g0,48,%g3
/* 0x08ac	     */		ldd	[%g4+%o4],%f2
/* 0x08b0	     */		or	%g0,56,%o4
/* 0x08b4	     */		or	%g0,3,%o5
/* 0x08b8	     */		ldd	[%g4+%o3],%f0
/* 0x08bc	     */		sub	%l4,4,%o3
/* 0x08c0	     */		fdtox	%f2,%f2
/* 0x08c4	     */		ldx	[%sp+2247],%g2
/* 0x08c8	     */		fdtox	%f0,%f0
/* 0x08cc	     */		std	%f0,[%sp+2247]
/* 0x08d0	     */		srax	%g2,32,%l7
/* 0x08d4	     */		ldd	[%g4+%g3],%f0
/* 0x08d8	     */		and	%g2,%l2,%g2
/* 0x08dc	     */		srax	%o1,32,%g3
/* 0x08e0	     */		ldx	[%sp+2239],%o0
/* 0x08e4	     */		std	%f2,[%sp+2239]
/* 0x08e8	     */		srax	%o0,16,%i2
/* 0x08ec	     */		ldd	[%g4+%o4],%f2
/* 0x08f0	     */		and	%o0,%l1,%g5
/* 0x08f4	     */		srax	%i1,32,%o4
/* 0x08f8	     */		ldx	[%sp+2247],%l5
                       .L900000726:
/* 0x08fc	 324 */		sra	%i4,0,%o0
/* 0x0900	     */		add	%o2,%o4,%o1
/* 0x0904	     */		ldx	[%sp+2239],%o2
/* 0x0908	     */		fdtox	%f0,%f0
/* 0x090c	     */		std	%f0,[%sp+2247]
/* 0x0910	     */		sllx	%o0,3,%o0
/* 0x0914	     */		add	%g3,%o1,%o1
/* 0x0918	     */		sra	%i3,0,%g3
/* 0x091c	     */		and	%i1,%l2,%o4
/* 0x0920	     */		ldd	[%g4+%o0],%f0
/* 0x0924	     */		fdtox	%f2,%f2
/* 0x0928	     */		std	%f2,[%sp+2239]
/* 0x092c	     */		sllx	%g3,3,%g3
/* 0x0930	     */		add	%i3,2,%o0
/* 0x0934	     */		sllx	%g5,16,%i1
/* 0x0938	     */		add	%i4,2,%g5
/* 0x093c	     */		ldd	[%g4+%g3],%f2
/* 0x0940	     */		st	%o4,[%o7]
/* 0x0944	     */		add	%g2,%i1,%g2
/* 0x0948	     */		add	%o5,3,%o5
/* 0x094c	     */		add	%g2,%o1,%g3
/* 0x0950	     */		srax	%l5,32,%g2
/* 0x0954	     */		and	%l5,%l2,%i1
/* 0x0958	     */		srax	%g3,32,%l5
/* 0x095c	     */		ldx	[%sp+2247],%o4
/* 0x0960	     */		srax	%o2,16,%o1
/* 0x0964	     */		and	%o2,%l1,%i3
/* 0x0968	     */		sra	%g5,0,%o2
/* 0x096c	     */		add	%i2,%l5,%i2
/* 0x0970	     */		ldx	[%sp+2239],%l5
/* 0x0974	     */		fdtox	%f0,%f0
/* 0x0978	     */		std	%f0,[%sp+2247]
/* 0x097c	     */		sllx	%o2,3,%o2
/* 0x0980	     */		add	%l7,%i2,%i2
/* 0x0984	     */		sra	%o0,0,%l7
/* 0x0988	     */		and	%g3,%l2,%g3
/* 0x098c	     */		ldd	[%g4+%o2],%f0
/* 0x0990	     */		fdtox	%f2,%f2
/* 0x0994	     */		std	%f2,[%sp+2239]
/* 0x0998	     */		sllx	%l7,3,%o2
/* 0x099c	     */		add	%o0,2,%o0
/* 0x09a0	     */		sllx	%i3,16,%l7
/* 0x09a4	     */		add	%i4,4,%g5
/* 0x09a8	     */		ldd	[%g4+%o2],%f2
/* 0x09ac	     */		st	%g3,[%o7+4]
/* 0x09b0	     */		add	%i1,%l7,%g3
/* 0x09b4	     */		cmp	%o5,%o3
/* 0x09b8	     */		add	%g3,%i2,%i1
/* 0x09bc	     */		srax	%o4,32,%g3
/* 0x09c0	     */		and	%o4,%l2,%l7
/* 0x09c4	     */		srax	%i1,32,%i2
/* 0x09c8	     */		ldx	[%sp+2247],%o4
/* 0x09cc	     */		srax	%l5,16,%o2
/* 0x09d0	     */		and	%l5,%l1,%l5
/* 0x09d4	     */		sra	%g5,0,%i3
/* 0x09d8	     */		add	%o1,%i2,%i2
/* 0x09dc	     */		ldx	[%sp+2239],%o1
/* 0x09e0	     */		fdtox	%f0,%f0
/* 0x09e4	     */		std	%f0,[%sp+2247]
/* 0x09e8	     */		sllx	%i3,3,%i3
/* 0x09ec	     */		add	%g2,%i2,%g2
/* 0x09f0	     */		sra	%o0,0,%i2
/* 0x09f4	     */		and	%i1,%l2,%i1
/* 0x09f8	     */		ldd	[%g4+%i3],%f0
/* 0x09fc	     */		fdtox	%f2,%f2
/* 0x0a00	     */		std	%f2,[%sp+2239]
/* 0x0a04	     */		sllx	%i2,3,%i2
/* 0x0a08	     */		add	%o0,2,%i3
/* 0x0a0c	     */		sllx	%l5,16,%o0
/* 0x0a10	     */		add	%i4,6,%i4
/* 0x0a14	     */		ldd	[%g4+%i2],%f2
/* 0x0a18	     */		st	%i1,[%o7+8]
/* 0x0a1c	     */		add	%l7,%o0,%g5
/* 0x0a20	     */		add	%o7,12,%o7
/* 0x0a24	     */		add	%g5,%g2,%i1
/* 0x0a28	     */		srax	%o4,32,%l7
/* 0x0a2c	     */		and	%o4,%l2,%g2
/* 0x0a30	     */		srax	%i1,32,%o4
/* 0x0a34	     */		ldx	[%sp+2247],%l5
/* 0x0a38	     */		srax	%o1,16,%i2
/* 0x0a3c	     */		ble,pt	%icc,.L900000726
/* 0x0a40	     */		and	%o1,%l1,%g5
                       .L900000729:
/* 0x0a44	 324 */		sllx	%g5,16,%g5
/* 0x0a48	     */		ldx	[%sp+2239],%o1
/* 0x0a4c	     */		add	%o2,%o4,%o0
/* 0x0a50	     */		add	%g3,%o0,%g3
/* 0x0a54	     */		add	%g2,%g5,%g2
/* 0x0a58	     */		fdtox	%f2,%f2
/* 0x0a5c	     */		sra	%i3,0,%g5
/* 0x0a60	     */		std	%f2,[%sp+2239]
/* 0x0a64	     */		add	%g2,%g3,%o2
/* 0x0a68	     */		sra	%i4,0,%g2
/* 0x0a6c	     */		and	%o1,%l1,%o0
/* 0x0a70	     */		fdtox	%f0,%f0
/* 0x0a74	     */		srax	%o2,32,%g3
/* 0x0a78	     */		std	%f0,[%sp+2247]
/* 0x0a7c	     */		add	%o5,1,%o5
/* 0x0a80	     */		sllx	%g2,3,%g2
/* 0x0a84	     */		add	%i2,%g3,%g3
/* 0x0a88	     */		sllx	%g5,3,%g5
/* 0x0a8c	     */		ldd	[%g4+%g2],%f0
/* 0x0a90	     */		and	%l5,%l2,%i2
/* 0x0a94	     */		sllx	%o0,16,%g2
/* 0x0a98	     */		ldd	[%g4+%g5],%f2
/* 0x0a9c	     */		add	%l7,%g3,%g3
/* 0x0aa0	     */		srax	%o1,16,%o1
/* 0x0aa4	     */		ldx	[%sp+2239],%o3
/* 0x0aa8	     */		add	%i2,%g2,%g2
/* 0x0aac	     */		srax	%l5,32,%l5
/* 0x0ab0	     */		ldx	[%sp+2247],%o4
/* 0x0ab4	     */		add	%g2,%g3,%g2
/* 0x0ab8	     */		srax	%g2,32,%g5
/* 0x0abc	     */		and	%o3,%l1,%g3
/* 0x0ac0	     */		fdtox	%f0,%f0
/* 0x0ac4	     */		sllx	%g3,16,%g3
/* 0x0ac8	     */		std	%f0,[%sp+2247]
/* 0x0acc	     */		and	%o4,%l2,%o0
/* 0x0ad0	     */		srax	%o3,16,%o3
/* 0x0ad4	     */		add	%o1,%g5,%g5
/* 0x0ad8	     */		fdtox	%f2,%f2
/* 0x0adc	     */		std	%f2,[%sp+2239]
/* 0x0ae0	     */		srax	%o4,32,%o4
/* 0x0ae4	     */		add	%o0,%g3,%g3
/* 0x0ae8	     */		add	%l5,%g5,%l5
/* 0x0aec	     */		and	%o2,%l2,%o0
/* 0x0af0	     */		st	%o0,[%o7+4]
/* 0x0af4	     */		ldx	[%sp+2247],%o1
/* 0x0af8	     */		and	%i1,%l2,%l7
/* 0x0afc	     */		add	%g3,%l5,%g3
/* 0x0b00	     */		st	%l7,[%o7]
/* 0x0b04	     */		srax	%g3,32,%l5
/* 0x0b08	     */		add	%o7,16,%o7
/* 0x0b0c	     */		ldx	[%sp+2239],%g5
/* 0x0b10	     */		and	%g2,%l2,%g2
/* 0x0b14	     */		add	%o3,%l5,%o3
/* 0x0b18	     */		st	%g2,[%o7-8]
/* 0x0b1c	     */		and	%g3,%l2,%g2
/* 0x0b20	     */		cmp	%o5,%l0
/* 0x0b24	     */		st	%g2,[%o7-4]
/* 0x0b28	     */		bg,pn	%icc,.L77000319
/* 0x0b2c	     */		add	%o4,%o3,%i2
/* 0x0b30	     */		add	%i3,2,%o2
/* 0x0b34	     */		add	%i4,2,%o0
                       .L77000372:
/* 0x0b38	 324 */		sra	%o0,0,%g2
                       .L900000742:
/* 0x0b3c	 324 */		sllx	%g2,3,%g2
/* 0x0b40	     */		and	%g5,%l1,%o4
/* 0x0b44	     */		sra	%o2,0,%o3
/* 0x0b48	     */		ldd	[%g4+%g2],%f0
/* 0x0b4c	     */		and	%o1,%l2,%g3
/* 0x0b50	     */		sllx	%o3,3,%o3
/* 0x0b54	     */		add	%i2,%g3,%g3
/* 0x0b58	     */		sllx	%o4,16,%g2
/* 0x0b5c	     */		ldd	[%g4+%o3],%f2
/* 0x0b60	     */		fdtox	%f0,%f0
/* 0x0b64	     */		srax	%g5,16,%o4
/* 0x0b68	     */		std	%f0,[%sp+2247]
/* 0x0b6c	     */		add	%g3,%g2,%g2
/* 0x0b70	     */		srax	%g2,32,%o3
/* 0x0b74	     */		and	%g2,%l2,%g3
/* 0x0b78	     */		fdtox	%f2,%f0
/* 0x0b7c	     */		srax	%o1,32,%o1
/* 0x0b80	     */		std	%f0,[%sp+2239]
/* 0x0b84	     */		add	%o4,%o3,%o3
/* 0x0b88	     */		st	%g3,[%o7]
/* 0x0b8c	     */		add	%o5,1,%o5
/* 0x0b90	     */		add	%o1,%o3,%i2
/* 0x0b94	     */		ldx	[%sp+2247],%g2
/* 0x0b98	     */		add	%o0,2,%o0
/* 0x0b9c	     */		add	%o2,2,%o2
/* 0x0ba0	     */		ldx	[%sp+2239],%g5
/* 0x0ba4	     */		add	%o7,4,%o7
/* 0x0ba8	     */		cmp	%o5,%l0
/* 0x0bac	     */		or	%g0,%g2,%o1
/* 0x0bb0	     */		ble,pt	%icc,.L900000742
/* 0x0bb4	     */		sra	%o0,0,%g2
                       .L77000319:
/* 0x0bb8	 320 */		sethi	%hi(0xfc00),%g2
                       .L900000743:
/* 0x0bbc	 320 */		srl	%l3,0,%o0
/* 0x0bc0	     */		add	%g2,1023,%g2
/* 0x0bc4	     */		and	%g5,%g2,%g2
/* 0x0bc8	     */		and	%o1,%o0,%g3
/* 0x0bcc	     */		sllx	%g2,16,%g2
/* 0x0bd0	     */		add	%i2,%g3,%g3
/* 0x0bd4	     */		sra	%o5,0,%g4
/* 0x0bd8	     */		add	%g3,%g2,%g2
/* 0x0bdc	     */		sllx	%g4,2,%g3
/* 0x0be0	     */		and	%g2,%o0,%g2
/* 0x0be4	     */		st	%g2,[%l6+%g3]

!  325		      !	adjust_montf_result(result, nint, nlen);

/* 0x0be8	 325 */		sllx	%l4,2,%g2
/* 0x0bec	     */		ld	[%l6+%g2],%g2
/* 0x0bf0	     */		cmp	%g2,0
/* 0x0bf4	     */		bgu,pn	%icc,.L77000369
/* 0x0bf8	     */		subcc	%l4,1,%g4
/* 0x0bfc	     */		bneg,pn	%icc,.L77000369
/* 0x0c00	     */		sra	%g4,0,%g2
                       .L900000741:
/* 0x0c04	 325 */		sllx	%g2,2,%g2
/* 0x0c08	     */		ld	[%l6+%g2],%g3
/* 0x0c0c	     */		ld	[%i0+%g2],%g2
/* 0x0c10	     */		cmp	%g3,%g2
/* 0x0c14	     */		bne,pn	%icc,.L77000328
/* 0x0c18	     */		nop
/* 0x0c1c	     */		subcc	%g4,1,%g4
/* 0x0c20	     */		bpos,pt	%icc,.L900000741
/* 0x0c24	     */		sra	%g4,0,%g2
                       .L900000720:
/* 0x0c28	 325 */		ba	.L900000740
/* 0x0c2c	 249 */		cmp	%l4,0
                       .L77000328:
/* 0x0c30	 325 */		bleu,pt	%icc,.L77000307
/* 0x0c34	     */		nop
                       .L77000369:
/* 0x0c38	 249 */		cmp	%l4,0
                       .L900000740:
/* 0x0c3c	 249 */		ble,pt	%icc,.L77000307
/* 0x0c40	     */		nop
/* 0x0c44	     */		or	%g0,0,%g5
/* 0x0c48	     */		or	%g0,0,%g3
/* 0x0c4c	 325 */		or	%g0,%l6,%o1
/* 0x0c50	     */		sub	%l4,1,%g4
/* 0x0c54	 249 */		cmp	%l4,4
/* 0x0c58	     */		bl,pn	%icc,.L77000370
/* 0x0c5c	     */		or	%g0,%i0,%o3
/* 0x0c60	     */		ld	[%l6],%o2
/* 0x0c64	     */		add	%i0,4,%o3
/* 0x0c68	     */		add	%l6,8,%o1
/* 0x0c6c	     */		ld	[%i0],%g2
/* 0x0c70	     */		sub	%l4,2,%o4
/* 0x0c74	     */		or	%g0,2,%g3
/* 0x0c78	     */		ld	[%l6+4],%o5
/* 0x0c7c	     */		sub	%o2,%g2,%g2
/* 0x0c80	     */		or	%g0,%g2,%g5
/* 0x0c84	     */		and	%g2,%o0,%g2
/* 0x0c88	     */		st	%g2,[%l6]
/* 0x0c8c	     */		srax	%g5,32,%g2
                       .L900000730:
/* 0x0c90	 249 */		add	%g3,1,%g3
/* 0x0c94	     */		ld	[%o3],%g5
/* 0x0c98	     */		add	%o3,4,%o3
/* 0x0c9c	     */		cmp	%g3,%o4
/* 0x0ca0	     */		add	%o1,4,%o1
/* 0x0ca4	     */		sub	%o5,%g5,%g5
/* 0x0ca8	     */		add	%g5,%g2,%g5
/* 0x0cac	     */		and	%g5,%o0,%g2
/* 0x0cb0	     */		ld	[%o1-4],%o5
/* 0x0cb4	     */		st	%g2,[%o1-8]
/* 0x0cb8	     */		ble,pt	%icc,.L900000730
/* 0x0cbc	     */		srax	%g5,32,%g2
                       .L900000733:
/* 0x0cc0	 249 */		ld	[%o3],%g5
/* 0x0cc4	     */		add	%o3,8,%o3
/* 0x0cc8	     */		add	%g3,1,%g3
/* 0x0ccc	     */		ld	[%o1],%o2
/* 0x0cd0	     */		add	%o1,4,%o1
/* 0x0cd4	     */		cmp	%g3,%g4
/* 0x0cd8	     */		sub	%o5,%g5,%g5
/* 0x0cdc	     */		add	%g5,%g2,%g5
/* 0x0ce0	     */		and	%g5,%o0,%g2
/* 0x0ce4	     */		st	%g2,[%o1-8]
/* 0x0ce8	     */		ld	[%o3-4],%g2
/* 0x0cec	     */		srax	%g5,32,%g5
/* 0x0cf0	     */		sub	%o2,%g2,%g2
/* 0x0cf4	     */		add	%g2,%g5,%g5
/* 0x0cf8	     */		and	%g5,%o0,%g2
/* 0x0cfc	     */		st	%g2,[%o1-4]
/* 0x0d00	     */		bg,pn	%icc,.L77000307
/* 0x0d04	     */		srax	%g5,32,%g5
                       .L77000370:
/* 0x0d08	 249 */		ld	[%o1],%g2
                       .L900000739:
/* 0x0d0c	 249 */		ld	[%o3],%o2
/* 0x0d10	     */		add	%g5,%g2,%g2
/* 0x0d14	     */		add	%g3,1,%g3
/* 0x0d18	     */		add	%o3,4,%o3
/* 0x0d1c	     */		cmp	%g3,%g4
/* 0x0d20	     */		sub	%g2,%o2,%g5
/* 0x0d24	     */		and	%g5,%o0,%g2
/* 0x0d28	     */		st	%g2,[%o1]
/* 0x0d2c	     */		add	%o1,4,%o1
/* 0x0d30	     */		srax	%g5,32,%g5
/* 0x0d34	     */		ble,a,pt	%icc,.L900000739
/* 0x0d38	     */		ld	[%o1],%g2
                       .L77000307:
/* 0x0d3c	     */		ret	! Result =
/* 0x0d40	     */		restore	%g0,%g0,%g0
/* 0x0d44	   0 */		.type	mont_mulf_noconv,2
/* 0x0d44	   0 */		.size	mont_mulf_noconv,(.-mont_mulf_noconv)

! Begin Disassembling Stabs
	.xstabs	".stab.index","Xa ; O ; P ; V=3.1 ; R=Sun WorkShop 6 update 1 C 5.2 Patch 109513-02 2001/02/04",60,0,0,0	! (/tmp/acompAAAnPa4q5:1)
	.xstabs	".stab.index","/home/ferenc/venus/userland/rsa; /ws/cpg-tools/SUNWspro/SC6.1/bin/../WS6U1/bin/cc -DRF_INLINE_MACROS -fast -xarch=v9 -xO5 -xstrconst -xdepend -Xa -xchip=ultra2 -KPIC -Wc,-Qrm-Qd -Wc,-Qrm-Qf -Wc,-assembly -V -c conv_v9.il -o mont_mulf.o  mont_mulf.c -W0,-xp",52,0,0,0	! (/tmp/acompAAAnPa4q5:2)
! End Disassembling Stabs

! Begin Disassembling Ident
	.ident	"cg: Sun WorkShop 6 update 1 Compiler Common 6.1 Patch 109505-04 2001/03/07"	! (NO SOURCE LINE)
	.ident	"@(#)mont_mulf.c\t1.2\t01/09/24 SMI"	! (/tmp/acompAAAnPa4q5:4)
	.ident	"@(#)types.h\t1.66\t00/02/14 SMI"	! (/tmp/acompAAAnPa4q5:5)
	.ident	"@(#)isa_defs.h\t1.20\t99/05/04 SMI"	! (/tmp/acompAAAnPa4q5:6)
	.ident	"@(#)feature_tests.h\t1.18\t99/07/26 SMI"	! (/tmp/acompAAAnPa4q5:7)
	.ident	"@(#)machtypes.h\t1.13\t99/05/04 SMI"	! (/tmp/acompAAAnPa4q5:8)
	.ident	"@(#)int_types.h\t1.6\t97/08/20 SMI"	! (/tmp/acompAAAnPa4q5:9)
	.ident	"@(#)select.h\t1.16\t98/04/27 SMI"	! (/tmp/acompAAAnPa4q5:10)
	.ident	"@(#)time.h\t2.66\t01/01/17 SMI"	! (/tmp/acompAAAnPa4q5:11)
	.ident	"@(#)time.h\t1.39\t99/08/10 SMI"	! (/tmp/acompAAAnPa4q5:12)
	.ident	"@(#)time_iso.h\t1.1\t99/08/09 SMI"	! (/tmp/acompAAAnPa4q5:13)
	.ident	"@(#)time_impl.h\t1.5\t99/10/05 SMI"	! (/tmp/acompAAAnPa4q5:14)
	.ident	"@(#)math.h\t2.10\t99/07/29 SMI"	! (/tmp/acompAAAnPa4q5:15)
	.ident	"@(#)math_iso.h\t1.1\t99/07/30 SMI"	! (/tmp/acompAAAnPa4q5:16)
	.ident	"@(#)floatingpoint.h\t2.5\t99/06/22 SMI"	! (/tmp/acompAAAnPa4q5:17)
	.ident	"@(#)stdio_tag.h\t1.3\t98/04/20 SMI"	! (/tmp/acompAAAnPa4q5:18)
	.ident	"@(#)ieeefp.h\t2.8 99/10/29"	! (/tmp/acompAAAnPa4q5:19)
	.ident	"acomp: Sun WorkShop 6 update 1 C 5.2 Patch 109513-02 2001/02/04"	! (/tmp/acompAAAnPa4q5:47)
! End Disassembling Ident
