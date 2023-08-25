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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


	.section	".text",#alloc,#execinstr
	.file	"mont_mulf_asm_v8plus.s"

/*
 * This file is a result of compiling the mont_mulf.c file to generate an
 * assembly output and then hand-editing that output to replace the
 * compiler-generated loop for the 512-bit case (nlen == 16) in the
 * mont_mulf_noconv routine with a hand-crafted version.
 * To compile this:
 *
 * cc -c -xarch=v8plus -KPIC mont_mulf_asm.s
 *
 * Note, this file does not support sparcv9 (64-bit).
 */


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
/* 000000	   0 */		.align	4
!
! SUBROUTINE conv_d16_to_i32
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_d16_to_i32
                       conv_d16_to_i32:
/* 000000	     */		save	%sp,-128,%sp
! FILE mont_mulf.c

!    1		      !#define RF_INLINE_MACROS
!    3		      !static const double TwoTo16=65536.0;
!    4		      !static const double TwoToMinus16=1.0/65536.0;
!    5		      !static const double Zero=0.0;
!    6		      !static const double TwoTo32=65536.0*65536.0;
!    7		      !static const double TwoToMinus32=1.0/(65536.0*65536.0);
!    9		      !#ifdef RF_INLINE_MACROS
!   11		      !double upper32(double);
!   12		      !double lower32(double, double);
!   13		      !double mod(double, double, double);
!   15		      !#else
!   17		      !static double upper32(double x)
!   18		      !{
!   19		      !  return floor(x*TwoToMinus32);
!   20		      !}
!   22		      !static double lower32(double x, double y)
!   23		      !{
!   24		      !  return x-TwoTo32*floor(x*TwoToMinus32);
!   25		      !}
!   27		      !static double mod(double x, double oneoverm, double m)
!   28		      !{
!   29		      !  return x-m*floor(x*oneoverm);
!   30		      !}
!   32		      !#endif
!   35		      !static void cleanup(double *dt, int from, int tlen)
!   36		      !{
!   37		      ! int i;
!   38		      ! double tmp,tmp1,x,x1;
!   40		      ! tmp=tmp1=Zero;
!   41		      ! /* original code **
!   42		      ! for(i=2*from;i<2*tlen-2;i++)
!   43		      !   {
!   44		      !     x=dt[i];
!   45		      !     dt[i]=lower32(x,Zero)+tmp1;
!   46		      !     tmp1=tmp;
!   47		      !     tmp=upper32(x);
!   48		      !   }
!   49		      ! dt[tlen-2]+=tmp1;
!   50		      ! dt[tlen-1]+=tmp;
!   51		      ! **end original code ***/
!   52		      ! /* new code ***/
!   53		      ! for(i=2*from;i<2*tlen;i+=2)
!   54		      !   {
!   55		      !     x=dt[i];
!   56		      !     x1=dt[i+1];
!   57		      !     dt[i]=lower32(x,Zero)+tmp;
!   58		      !     dt[i+1]=lower32(x1,Zero)+tmp1;
!   59		      !     tmp=upper32(x);
!   60		      !     tmp1=upper32(x1);
!   61		      !   }
!   62		      !  /** end new code **/
!   63		      !}
!   66		      !void conv_d16_to_i32(unsigned int *i32, double *d16, long long *tmp, int ilen)
!   67		      !{
!   68		      !int i;
!   69		      !long long t, t1, a, b, c, d;
!   71		      ! t1=0;
!   72		      ! a=(long long)d16[0];

/* 0x0004	  72 */		ldd	[%i1],%f0
/* 0x0008	  67 */		or	%g0,%i1,%o0

!   73		      ! b=(long long)d16[1];
!   74		      ! for(i=0; i<ilen-1; i++)

/* 0x000c	  74 */		sub	%i3,1,%g2
/* 0x0010	     */		cmp	%g2,0
/* 0x0014	  71 */		or	%g0,0,%o4
/* 0x0018	  72 */		fdtox	%f0,%f0
/* 0x001c	     */		std	%f0,[%sp+120]
/* 0x0020	  74 */		or	%g0,0,%o7
/* 0x0024	  67 */		or	%g0,%i3,%o1
/* 0x0028	     */		sub	%i3,2,%o2
/* 0x002c	  73 */		ldd	[%o0+8],%f0
/* 0x0030	  67 */		sethi	%hi(0xfc00),%o1
/* 0x0034	     */		add	%o2,1,%g3
/* 0x0038	     */		add	%o1,1023,%o1
/* 0x003c	     */		or	%g0,%i0,%o5
/* 0x0040	  73 */		fdtox	%f0,%f0
/* 0x0044	     */		std	%f0,[%sp+112]
/* 0x0048	     */		ldx	[%sp+112],%g1
/* 0x004c	  72 */		ldx	[%sp+120],%g4
/* 0x0050	  74 */		ble,pt	%icc,.L900000117
/* 0x0054	     */		sethi	%hi(0xfc00),%g2
/* 0x0058	  67 */		or	%g0,-1,%g2
/* 0x005c	  74 */		cmp	%g3,3
/* 0x0060	  67 */		srl	%g2,0,%o3
/* 0x0064	  74 */		bl,pn	%icc,.L77000134
/* 0x0068	     */		or	%g0,%o0,%g2

!   75		      !   {
!   76		      !     c=(long long)d16[2*i+2];

/* 0x006c	  76 */		ldd	[%o0+16],%f0

!   77		      !     t1+=a&0xffffffff;
!   78		      !     t=(a>>32);
!   79		      !     d=(long long)d16[2*i+3];
!   80		      !     t1+=(b&0xffff)<<16;
!   81		      !     t+=(b>>16)+(t1>>32);
!   82		      !     i32[i]=t1&0xffffffff;
!   83		      !     t1=t;
!   84		      !     a=c;
!   85		      !     b=d;

/* 0x0070	  85 */		add	%o0,16,%g2
/* 0x0074	  80 */		and	%g1,%o1,%o0
/* 0x0078	     */		sllx	%o0,16,%g3
/* 0x007c	  77 */		and	%g4,%o3,%o0
/* 0x0080	  74 */		add	%o0,%g3,%o4
/* 0x0084	  76 */		fdtox	%f0,%f0
/* 0x0088	     */		std	%f0,[%sp+104]
/* 0x008c	  82 */		and	%o4,%o3,%g5
/* 0x0090	  79 */		ldd	[%g2+8],%f2
/* 0x0094	  85 */		add	%o5,4,%o5
/* 0x0098	  81 */		srax	%o4,32,%o4
/* 0x009c	     */		stx	%o4,[%sp+112]
/* 0x00a0	  79 */		fdtox	%f2,%f0
/* 0x00a4	     */		std	%f0,[%sp+96]
/* 0x00a8	  81 */		srax	%g1,16,%o0
/* 0x00ac	     */		ldx	[%sp+112],%o7
/* 0x00b0	  78 */		srax	%g4,32,%o4
/* 0x00b4	  81 */		add	%o0,%o7,%g4
/* 0x00b8	  85 */		or	%g0,1,%o7
/* 0x00bc	  76 */		ldx	[%sp+104],%g3
/* 0x00c0	  81 */		add	%o4,%g4,%o4
/* 0x00c4	  79 */		ldx	[%sp+96],%g1
/* 0x00c8	  82 */		st	%g5,[%o5-4]
/* 0x00cc	  84 */		or	%g0,%g3,%g4
                       .L900000112:
/* 0x00d0	  76 */		ldd	[%g2+16],%f0
/* 0x00d4	  85 */		add	%o7,1,%o7
/* 0x00d8	     */		add	%o5,4,%o5
/* 0x00dc	     */		cmp	%o7,%o2
/* 0x00e0	     */		add	%g2,16,%g2
/* 0x00e4	  76 */		fdtox	%f0,%f0
/* 0x00e8	     */		std	%f0,[%sp+104]
/* 0x00ec	  79 */		ldd	[%g2+8],%f0
/* 0x00f0	     */		fdtox	%f0,%f0
/* 0x00f4	     */		std	%f0,[%sp+96]
/* 0x00f8	  80 */		and	%g1,%o1,%g3
/* 0x00fc	     */		sllx	%g3,16,%g5
/* 0x0100	  77 */		and	%g4,%o3,%g3
/* 0x0104	  74 */		add	%g3,%g5,%g3
/* 0x0108	  81 */		srax	%g1,16,%g1
/* 0x010c	  74 */		add	%g3,%o4,%g3
/* 0x0110	  81 */		srax	%g3,32,%o4
/* 0x0114	     */		stx	%o4,[%sp+112]
/* 0x0118	  76 */		ldx	[%sp+104],%g5
/* 0x011c	  78 */		srax	%g4,32,%o4
/* 0x0120	  81 */		ldx	[%sp+112],%g4
/* 0x0124	     */		add	%g1,%g4,%g4
/* 0x0128	  79 */		ldx	[%sp+96],%g1
/* 0x012c	  81 */		add	%o4,%g4,%o4
/* 0x0130	  82 */		and	%g3,%o3,%g3
/* 0x0134	  84 */		or	%g0,%g5,%g4
/* 0x0138	  85 */		ble,pt	%icc,.L900000112
/* 0x013c	     */		st	%g3,[%o5-4]
                       .L900000115:
/* 0x0140	  85 */		ba	.L900000117
/* 0x0144	     */		sethi	%hi(0xfc00),%g2
                       .L77000134:
/* 0x0148	  76 */		ldd	[%g2+16],%f0
                       .L900000116:
/* 0x014c	  77 */		and	%g4,%o3,%o0
/* 0x0150	  80 */		and	%g1,%o1,%g3
/* 0x0154	  76 */		fdtox	%f0,%f0
/* 0x0158	  77 */		add	%o4,%o0,%o0
/* 0x015c	  76 */		std	%f0,[%sp+104]
/* 0x0160	  85 */		add	%o7,1,%o7
/* 0x0164	  80 */		sllx	%g3,16,%o4
/* 0x0168	  79 */		ldd	[%g2+24],%f2
/* 0x016c	  85 */		add	%g2,16,%g2
/* 0x0170	  80 */		add	%o0,%o4,%o0
/* 0x0174	  85 */		cmp	%o7,%o2
/* 0x0178	  82 */		and	%o0,%o3,%g3
/* 0x017c	  79 */		fdtox	%f2,%f0
/* 0x0180	     */		std	%f0,[%sp+96]
/* 0x0184	  81 */		srax	%o0,32,%o0
/* 0x0188	     */		stx	%o0,[%sp+112]
/* 0x018c	  78 */		srax	%g4,32,%o4
/* 0x0190	  79 */		ldx	[%sp+96],%o0
/* 0x0194	  81 */		srax	%g1,16,%g5
/* 0x0198	     */		ldx	[%sp+112],%g4
/* 0x019c	  76 */		ldx	[%sp+104],%g1
/* 0x01a0	  82 */		st	%g3,[%o5]
/* 0x01a4	  81 */		add	%g5,%g4,%g4
/* 0x01a8	  85 */		add	%o5,4,%o5
/* 0x01ac	  81 */		add	%o4,%g4,%o4
/* 0x01b0	  84 */		or	%g0,%g1,%g4
/* 0x01b4	  85 */		or	%g0,%o0,%g1
/* 0x01b8	     */		ble,a,pt	%icc,.L900000116
/* 0x01bc	     */		ldd	[%g2+16],%f0
                       .L77000127:

!   86		      !   }
!   87		      !     t1+=a&0xffffffff;
!   88		      !     t=(a>>32);
!   89		      !     t1+=(b&0xffff)<<16;
!   90		      !     i32[i]=t1&0xffffffff;

/* 0x01c0	  90 */		sethi	%hi(0xfc00),%g2
                       .L900000117:
/* 0x01c4	  90 */		or	%g0,-1,%g3
/* 0x01c8	     */		add	%g2,1023,%g2
/* 0x01cc	     */		srl	%g3,0,%g3
/* 0x01d0	     */		and	%g1,%g2,%g2
/* 0x01d4	     */		and	%g4,%g3,%g4
/* 0x01d8	     */		sllx	%g2,16,%g2
/* 0x01dc	     */		add	%o4,%g4,%g4
/* 0x01e0	     */		add	%g4,%g2,%g2
/* 0x01e4	     */		sll	%o7,2,%g4
/* 0x01e8	     */		and	%g2,%g3,%g2
/* 0x01ec	     */		st	%g2,[%i0+%g4]
/* 0x01f0	     */		ret	! Result =
/* 0x01f4	     */		restore	%g0,%g0,%g0
/* 0x01f8	   0 */		.type	conv_d16_to_i32,2
/* 0x01f8	     */		.size	conv_d16_to_i32,(.-conv_d16_to_i32)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       .L_const_seg_900000201:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	   0 */		.align	4
/* 0x0008	     */		.skip	16
!
! SUBROUTINE conv_i32_to_d32
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_i32_to_d32
                       conv_i32_to_d32:
/* 000000	     */		or	%g0,%o7,%g2
/* 0x0004	     */		or	%g0,%o1,%g4
                       .L900000210:
/* 0x0008	     */		call	.+8
/* 0x000c	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000210-.)),%g3

!   92		      !}
!   94		      !void conv_i32_to_d32(double *d32, unsigned int *i32, int len)
!   95		      !{
!   96		      !int i;
!   98		      !#pragma pipeloop(0)
!   99		      ! for(i=0;i<len;i++) d32[i]=(double)(i32[i]);

/* 0x0010	  99 */		or	%g0,0,%o5
/* 0x0014	  95 */		add	%g3,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000210-.)),%g3
/* 0x0018	     */		or	%g0,%o0,%g5
/* 0x001c	     */		add	%g3,%o7,%g1
/* 0x0020	     */		orcc	%g0,%o2,%g3
/* 0x0024	  99 */		ble,pt	%icc,.L77000140
/* 0x0028	     */		or	%g0,%g2,%o7
/* 0x002c	     */		sethi	%hi(.L_const_seg_900000201),%g2
/* 0x0030	     */		add	%g2,%lo(.L_const_seg_900000201),%g2
/* 0x0034	     */		sub	%o2,1,%g3
/* 0x0038	     */		ld	[%g1+%g2],%g2
/* 0x003c	     */		cmp	%o2,9
/* 0x0040	     */		bl,pn	%icc,.L77000144
/* 0x0044	     */		ldd	[%g2],%f8
/* 0x0048	     */		add	%o1,16,%g4
/* 0x004c	     */		sub	%o2,5,%g1
/* 0x0050	     */		ld	[%o1],%f7
/* 0x0054	     */		or	%g0,4,%o5
/* 0x0058	     */		ld	[%o1+4],%f5
/* 0x005c	     */		ld	[%o1+8],%f3
/* 0x0060	     */		fmovs	%f8,%f6
/* 0x0064	     */		ld	[%o1+12],%f1
                       .L900000205:
/* 0x0068	     */		ld	[%g4],%f11
/* 0x006c	     */		add	%o5,5,%o5
/* 0x0070	     */		add	%g4,20,%g4
/* 0x0074	     */		fsubd	%f6,%f8,%f6
/* 0x0078	     */		std	%f6,[%g5]
/* 0x007c	     */		cmp	%o5,%g1
/* 0x0080	     */		add	%g5,40,%g5
/* 0x0084	     */		fmovs	%f8,%f4
/* 0x0088	     */		ld	[%g4-16],%f7
/* 0x008c	     */		fsubd	%f4,%f8,%f12
/* 0x0090	     */		fmovs	%f8,%f2
/* 0x0094	     */		std	%f12,[%g5-32]
/* 0x0098	     */		ld	[%g4-12],%f5
/* 0x009c	     */		fsubd	%f2,%f8,%f12
/* 0x00a0	     */		fmovs	%f8,%f0
/* 0x00a4	     */		std	%f12,[%g5-24]
/* 0x00a8	     */		ld	[%g4-8],%f3
/* 0x00ac	     */		fsubd	%f0,%f8,%f12
/* 0x00b0	     */		fmovs	%f8,%f10
/* 0x00b4	     */		std	%f12,[%g5-16]
/* 0x00b8	     */		ld	[%g4-4],%f1
/* 0x00bc	     */		fsubd	%f10,%f8,%f10
/* 0x00c0	     */		fmovs	%f8,%f6
/* 0x00c4	     */		ble,pt	%icc,.L900000205
/* 0x00c8	     */		std	%f10,[%g5-8]
                       .L900000208:
/* 0x00cc	     */		fmovs	%f8,%f4
/* 0x00d0	     */		add	%g5,32,%g5
/* 0x00d4	     */		cmp	%o5,%g3
/* 0x00d8	     */		fmovs	%f8,%f2
/* 0x00dc	     */		fmovs	%f8,%f0
/* 0x00e0	     */		fsubd	%f6,%f8,%f6
/* 0x00e4	     */		std	%f6,[%g5-32]
/* 0x00e8	     */		fsubd	%f4,%f8,%f4
/* 0x00ec	     */		std	%f4,[%g5-24]
/* 0x00f0	     */		fsubd	%f2,%f8,%f2
/* 0x00f4	     */		std	%f2,[%g5-16]
/* 0x00f8	     */		fsubd	%f0,%f8,%f0
/* 0x00fc	     */		bg,pn	%icc,.L77000140
/* 0x0100	     */		std	%f0,[%g5-8]
                       .L77000144:
/* 0x0104	     */		ld	[%g4],%f1
                       .L900000211:
/* 0x0108	     */		ldd	[%g2],%f8
/* 0x010c	     */		add	%o5,1,%o5
/* 0x0110	     */		add	%g4,4,%g4
/* 0x0114	     */		cmp	%o5,%g3
/* 0x0118	     */		fmovs	%f8,%f0
/* 0x011c	     */		fsubd	%f0,%f8,%f0
/* 0x0120	     */		std	%f0,[%g5]
/* 0x0124	     */		add	%g5,8,%g5
/* 0x0128	     */		ble,a,pt	%icc,.L900000211
/* 0x012c	     */		ld	[%g4],%f1
                       .L77000140:
/* 0x0130	     */		retl	! Result =
/* 0x0134	     */		nop
/* 0x0138	   0 */		.type	conv_i32_to_d32,2
/* 0x0138	     */		.size	conv_i32_to_d32,(.-conv_i32_to_d32)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       .L_const_seg_900000301:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	   0 */		.align	4
/* 0x0008	     */		.skip	16
!
! SUBROUTINE conv_i32_to_d16
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_i32_to_d16
                       conv_i32_to_d16:
/* 000000	     */		save	%sp,-104,%sp
                       .L900000310:
/* 0x0004	     */		call	.+8
/* 0x0008	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000310-.)),%g3
/* 0x000c	     */		orcc	%g0,%i2,%o0
/* 0x0010	     */		add	%g3,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000310-.)),%g3

!  100		      !}
!  103		      !void conv_i32_to_d16(double *d16, unsigned int *i32, int len)
!  104		      !{
!  105		      !int i;
!  106		      !unsigned int a;
!  108		      !#pragma pipeloop(0)
!  109		      ! for(i=0;i<len;i++)

/* 0x0014	 109 */		ble,pt	%icc,.L77000150
/* 0x0018	     */		add	%g3,%o7,%o2

!  110		      !   {
!  111		      !     a=i32[i];
!  112		      !     d16[2*i]=(double)(a&0xffff);
!  113		      !     d16[2*i+1]=(double)(a>>16);

/* 0x001c	 113 */		sethi	%hi(.L_const_seg_900000301),%g2
/* 0x0020	 109 */		sub	%o0,1,%o5
/* 0x0024	 113 */		add	%g2,%lo(.L_const_seg_900000301),%o1
/* 0x0028	     */		ld	[%o2+%o1],%o3
/* 0x002c	 109 */		sethi	%hi(0xfc00),%o0
/* 0x0030	     */		add	%o5,1,%g2
/* 0x0034	     */		or	%g0,0,%g1
/* 0x0038	     */		cmp	%g2,3
/* 0x003c	 112 */		ldd	[%o3],%f0
/* 0x0040	     */		or	%g0,%i1,%o7
/* 0x0044	     */		add	%o0,1023,%o4
/* 0x0048	     */		or	%g0,%i0,%g3
/* 0x004c	 109 */		bl,pn	%icc,.L77000154
/* 0x0050	     */		add	%o7,4,%o0
/* 0x0054	 111 */		ld	[%o0-4],%o1
/* 0x0058	   0 */		or	%g0,%o0,%o7
/* 0x005c	 113 */		or	%g0,1,%g1
/* 0x0060	 112 */		and	%o1,%o4,%o0
                       .L900000306:
/* 0x0064	 112 */		st	%o0,[%sp+96]
/* 0x0068	 113 */		add	%g1,1,%g1
/* 0x006c	     */		add	%g3,16,%g3
/* 0x0070	     */		cmp	%g1,%o5
/* 0x0074	     */		add	%o7,4,%o7
/* 0x0078	 112 */		ld	[%sp+96],%f3
/* 0x007c	     */		fmovs	%f0,%f2
/* 0x0080	     */		fsubd	%f2,%f0,%f2
/* 0x0084	 113 */		srl	%o1,16,%o0
/* 0x0088	 112 */		std	%f2,[%g3-16]
/* 0x008c	 113 */		st	%o0,[%sp+92]
/* 0x0090	     */		ld	[%sp+92],%f3
/* 0x0094	 111 */		ld	[%o7-4],%o1
/* 0x0098	 113 */		fmovs	%f0,%f2
/* 0x009c	     */		fsubd	%f2,%f0,%f2
/* 0x00a0	 112 */		and	%o1,%o4,%o0
/* 0x00a4	 113 */		ble,pt	%icc,.L900000306
/* 0x00a8	     */		std	%f2,[%g3-8]
                       .L900000309:
/* 0x00ac	 112 */		st	%o0,[%sp+96]
/* 0x00b0	     */		fmovs	%f0,%f2
/* 0x00b4	 113 */		add	%g3,16,%g3
/* 0x00b8	     */		srl	%o1,16,%o0
/* 0x00bc	 112 */		ld	[%sp+96],%f3
/* 0x00c0	     */		fsubd	%f2,%f0,%f2
/* 0x00c4	     */		std	%f2,[%g3-16]
/* 0x00c8	 113 */		st	%o0,[%sp+92]
/* 0x00cc	     */		fmovs	%f0,%f2
/* 0x00d0	     */		ld	[%sp+92],%f3
/* 0x00d4	     */		fsubd	%f2,%f0,%f0
/* 0x00d8	     */		std	%f0,[%g3-8]
/* 0x00dc	     */		ret	! Result =
/* 0x00e0	     */		restore	%g0,%g0,%g0
                       .L77000154:
/* 0x00e4	 111 */		ld	[%o7],%o0
                       .L900000311:
/* 0x00e8	 112 */		and	%o0,%o4,%o1
/* 0x00ec	     */		st	%o1,[%sp+96]
/* 0x00f0	 113 */		add	%g1,1,%g1
/* 0x00f4	 112 */		ldd	[%o3],%f0
/* 0x00f8	 113 */		srl	%o0,16,%o0
/* 0x00fc	     */		add	%o7,4,%o7
/* 0x0100	     */		cmp	%g1,%o5
/* 0x0104	 112 */		fmovs	%f0,%f2
/* 0x0108	     */		ld	[%sp+96],%f3
/* 0x010c	     */		fsubd	%f2,%f0,%f2
/* 0x0110	     */		std	%f2,[%g3]
/* 0x0114	 113 */		st	%o0,[%sp+92]
/* 0x0118	     */		fmovs	%f0,%f2
/* 0x011c	     */		ld	[%sp+92],%f3
/* 0x0120	     */		fsubd	%f2,%f0,%f0
/* 0x0124	     */		std	%f0,[%g3+8]
/* 0x0128	     */		add	%g3,16,%g3
/* 0x012c	     */		ble,a,pt	%icc,.L900000311
/* 0x0130	     */		ld	[%o7],%o0
                       .L77000150:
/* 0x0134	     */		ret	! Result =
/* 0x0138	     */		restore	%g0,%g0,%g0
/* 0x013c	   0 */		.type	conv_i32_to_d16,2
/* 0x013c	     */		.size	conv_i32_to_d16,(.-conv_i32_to_d16)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	8
!
! CONSTANT POOL
!
                       .L_const_seg_900000401:
/* 000000	   0 */		.word	1127219200,0
/* 0x0008	   0 */		.align	4
/* 0x0008	     */		.skip	16
!
! SUBROUTINE conv_i32_to_d32_and_d16
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global conv_i32_to_d32_and_d16
                       conv_i32_to_d32_and_d16:
/* 000000	     */		save	%sp,-104,%sp
                       .L900000413:
/* 0x0004	     */		call	.+8
/* 0x0008	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000413-.)),%g4

!  114		      !   }
!  115		      !}
!  118		      !void i16_to_d16_and_d32x4(const double * /*1/(2^16)*/,
!  119		      !			  const double * /* 2^16*/, const double * /* 0 */,
!  120		      !			  double * /*result16*/, double * /* result32 */,
!  121		      !			  float *  /*source - should be */
!  122		      !		          unsigned int* converted to float* */);
!  126		      !void conv_i32_to_d32_and_d16(double *d32, double *d16,
!  127		      !			     unsigned int *i32, int len)
!  128		      !{
!  129		      !int i;
!  130		      !unsigned int a;
!  132		      !#pragma pipeloop(0)
!  133		      ! for(i=0;i<len-3;i+=4)

/* 0x000c	 133 */		sub	%i3,3,%g2
/* 0x0010	     */		cmp	%g2,0
/* 0x0014	 128 */		add	%g4,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000413-.)),%g4
/* 0x0018	     */		or	%g0,%i2,%g5

!  134		      !   {
!  135		      !     i16_to_d16_and_d32x4(&TwoToMinus16, &TwoTo16, &Zero,
!  136		      !			  &(d16[2*i]), &(d32[i]), (float *)(&(i32[i])));

/* 0x001c	 136 */		sethi	%hi(Zero),%g2
/* 0x0020	 128 */		add	%g4,%o7,%o2
/* 0x0024	 133 */		or	%g0,0,%g1
/* 0x0028	 128 */		or	%g0,%i0,%i4
/* 0x002c	 136 */		add	%g2,%lo(Zero),%g2
/* 0x0030	 133 */		ble,pt	%icc,.L900000416
/* 0x0034	     */		cmp	%g1,%i3
/* 0x0038	     */		or	%g0,%g5,%o4
/* 0x003c	 136 */		ld	[%o2+%g2],%o1
/* 0x0040	 133 */		sub	%i3,4,%o3
/* 0x0044	     */		or	%g0,0,%o7
/* 0x0048	     */		or	%g0,0,%o5
/* 0x004c	 136 */		or	%g0,%o4,%g4
                       .L900000415:
/* 0x0050	     */		ldd	[%o1],%f2
/* 0x0054	 136 */		add	%i4,%o7,%g2
/* 0x0058	     */		add	%i1,%o5,%g3
/* 0x005c	     */		ldd	[%o1-8],%f0
/* 0x0060	     */		add	%g1,4,%g1
/* 0x0064	     */		add	%o4,16,%o4
/* 0x0068	     */		fmovd	%f2,%f14
/* 0x006c	     */		ld	[%g4],%f15
/* 0x0070	     */		cmp	%g1,%o3
/* 0x0074	     */		fmovd	%f2,%f10
/* 0x0078	     */		ld	[%g4+4],%f11
/* 0x007c	     */		fmovd	%f2,%f6
/* 0x0080	     */		ld	[%g4+8],%f7
/* 0x0084	     */		ld	[%g4+12],%f3
/* 0x0088	     */		fxtod	%f14,%f14
/* 0x008c	     */		fxtod	%f10,%f10
/* 0x0090	     */		ldd	[%o1-16],%f16
/* 0x0094	     */		fxtod	%f6,%f6
/* 0x0098	     */		std	%f14,[%i4+%o7]
/* 0x009c	     */		add	%o7,32,%o7
/* 0x00a0	     */		fxtod	%f2,%f2
/* 0x00a4	     */		fmuld	%f0,%f14,%f12
/* 0x00a8	     */		std	%f10,[%g2+8]
/* 0x00ac	     */		fmuld	%f0,%f10,%f8
/* 0x00b0	     */		std	%f6,[%g2+16]
/* 0x00b4	     */		fmuld	%f0,%f6,%f4
/* 0x00b8	     */		std	%f2,[%g2+24]
/* 0x00bc	     */		fmuld	%f0,%f2,%f0
/* 0x00c0	     */		fdtox	%f12,%f12
/* 0x00c4	     */		fdtox	%f8,%f8
/* 0x00c8	     */		fdtox	%f4,%f4
/* 0x00cc	     */		fdtox	%f0,%f0
/* 0x00d0	     */		fxtod	%f12,%f12
/* 0x00d4	     */		std	%f12,[%g3+8]
/* 0x00d8	     */		fxtod	%f8,%f8
/* 0x00dc	     */		std	%f8,[%g3+24]
/* 0x00e0	     */		fxtod	%f4,%f4
/* 0x00e4	     */		std	%f4,[%g3+40]
/* 0x00e8	     */		fxtod	%f0,%f0
/* 0x00ec	     */		fmuld	%f12,%f16,%f12
/* 0x00f0	     */		std	%f0,[%g3+56]
/* 0x00f4	     */		fmuld	%f8,%f16,%f8
/* 0x00f8	     */		fmuld	%f4,%f16,%f4
/* 0x00fc	     */		fmuld	%f0,%f16,%f0
/* 0x0100	     */		fsubd	%f14,%f12,%f12
/* 0x0104	     */		std	%f12,[%i1+%o5]
/* 0x0108	     */		fsubd	%f10,%f8,%f8
/* 0x010c	     */		std	%f8,[%g3+16]
/* 0x0110	     */		add	%o5,64,%o5
/* 0x0114	     */		fsubd	%f6,%f4,%f4
/* 0x0118	     */		std	%f4,[%g3+32]
/* 0x011c	     */		fsubd	%f2,%f0,%f0
/* 0x0120	     */		std	%f0,[%g3+48]
/* 0x0124	     */		ble,pt	%icc,.L900000415
/* 0x0128	     */		or	%g0,%o4,%g4
                       .L77000159:

!  137		      !   }
!  138		      ! for(;i<len;i++)

/* 0x012c	 138 */		cmp	%g1,%i3
                       .L900000416:
/* 0x0130	 138 */		bge,pt	%icc,.L77000164
/* 0x0134	     */		nop

!  139		      !   {
!  140		      !     a=i32[i];
!  141		      !     d32[i]=(double)(i32[i]);
!  142		      !     d16[2*i]=(double)(a&0xffff);
!  143		      !     d16[2*i+1]=(double)(a>>16);

/* 0x0138	 143 */		sethi	%hi(.L_const_seg_900000401),%g2
/* 0x013c	     */		add	%g2,%lo(.L_const_seg_900000401),%o1
/* 0x0140	 138 */		sethi	%hi(0xfc00),%o0
/* 0x0144	     */		ld	[%o2+%o1],%o2
/* 0x0148	     */		sll	%g1,2,%o3
/* 0x014c	     */		sub	%i3,%g1,%g3
/* 0x0150	     */		sll	%g1,3,%g2
/* 0x0154	     */		add	%o0,1023,%o4
/* 0x0158	 141 */		ldd	[%o2],%f0
/* 0x015c	     */		add	%g5,%o3,%o0
/* 0x0160	 138 */		cmp	%g3,3
/* 0x0164	     */		add	%i4,%g2,%o3
/* 0x0168	     */		sub	%i3,1,%o1
/* 0x016c	     */		sll	%g1,4,%g4
/* 0x0170	     */		bl,pn	%icc,.L77000161
/* 0x0174	     */		add	%i1,%g4,%o5
/* 0x0178	 141 */		ld	[%o0],%f3
/* 0x017c	 143 */		add	%o3,8,%o3
/* 0x0180	 140 */		ld	[%o0],%o7
/* 0x0184	 143 */		add	%o5,16,%o5
/* 0x0188	     */		add	%g1,1,%g1
/* 0x018c	 141 */		fmovs	%f0,%f2
/* 0x0190	 143 */		add	%o0,4,%o0
/* 0x0194	 142 */		and	%o7,%o4,%g2
/* 0x0198	 141 */		fsubd	%f2,%f0,%f2
/* 0x019c	     */		std	%f2,[%o3-8]
/* 0x01a0	 143 */		srl	%o7,16,%o7
/* 0x01a4	 142 */		st	%g2,[%sp+96]
/* 0x01a8	     */		fmovs	%f0,%f2
/* 0x01ac	     */		ld	[%sp+96],%f3
/* 0x01b0	     */		fsubd	%f2,%f0,%f2
/* 0x01b4	     */		std	%f2,[%o5-16]
/* 0x01b8	 143 */		st	%o7,[%sp+92]
/* 0x01bc	     */		fmovs	%f0,%f2
/* 0x01c0	     */		ld	[%sp+92],%f3
/* 0x01c4	     */		fsubd	%f2,%f0,%f2
/* 0x01c8	     */		std	%f2,[%o5-8]
                       .L900000409:
/* 0x01cc	 141 */		ld	[%o0],%f3
/* 0x01d0	 143 */		add	%g1,2,%g1
/* 0x01d4	     */		add	%o5,32,%o5
/* 0x01d8	 140 */		ld	[%o0],%o7
/* 0x01dc	 143 */		cmp	%g1,%o1
/* 0x01e0	     */		add	%o3,16,%o3
/* 0x01e4	 141 */		fmovs	%f0,%f2
/* 0x01e8	     */		fsubd	%f2,%f0,%f2
/* 0x01ec	     */		std	%f2,[%o3-16]
/* 0x01f0	 142 */		and	%o7,%o4,%g2
/* 0x01f4	     */		st	%g2,[%sp+96]
/* 0x01f8	     */		ld	[%sp+96],%f3
/* 0x01fc	     */		fmovs	%f0,%f2
/* 0x0200	     */		fsubd	%f2,%f0,%f2
/* 0x0204	 143 */		srl	%o7,16,%o7
/* 0x0208	 142 */		std	%f2,[%o5-32]
/* 0x020c	 143 */		st	%o7,[%sp+92]
/* 0x0210	     */		ld	[%sp+92],%f3
/* 0x0214	     */		fmovs	%f0,%f2
/* 0x0218	     */		fsubd	%f2,%f0,%f2
/* 0x021c	     */		std	%f2,[%o5-24]
/* 0x0220	     */		add	%o0,4,%o0
/* 0x0224	 141 */		ld	[%o0],%f3
/* 0x0228	 140 */		ld	[%o0],%o7
/* 0x022c	 141 */		fmovs	%f0,%f2
/* 0x0230	     */		fsubd	%f2,%f0,%f2
/* 0x0234	     */		std	%f2,[%o3-8]
/* 0x0238	 142 */		and	%o7,%o4,%g2
/* 0x023c	     */		st	%g2,[%sp+96]
/* 0x0240	     */		ld	[%sp+96],%f3
/* 0x0244	     */		fmovs	%f0,%f2
/* 0x0248	     */		fsubd	%f2,%f0,%f2
/* 0x024c	 143 */		srl	%o7,16,%o7
/* 0x0250	 142 */		std	%f2,[%o5-16]
/* 0x0254	 143 */		st	%o7,[%sp+92]
/* 0x0258	     */		ld	[%sp+92],%f3
/* 0x025c	     */		fmovs	%f0,%f2
/* 0x0260	     */		fsubd	%f2,%f0,%f2
/* 0x0264	     */		std	%f2,[%o5-8]
/* 0x0268	     */		bl,pt	%icc,.L900000409
/* 0x026c	     */		add	%o0,4,%o0
                       .L900000412:
/* 0x0270	 143 */		cmp	%g1,%i3
/* 0x0274	     */		bge,pn	%icc,.L77000164
/* 0x0278	     */		nop
                       .L77000161:
/* 0x027c	 141 */		ld	[%o0],%f3
                       .L900000414:
/* 0x0280	 141 */		ldd	[%o2],%f0
/* 0x0284	 143 */		add	%g1,1,%g1
/* 0x0288	 140 */		ld	[%o0],%o1
/* 0x028c	 143 */		add	%o0,4,%o0
/* 0x0290	     */		cmp	%g1,%i3
/* 0x0294	 141 */		fmovs	%f0,%f2
/* 0x0298	 142 */		and	%o1,%o4,%o7
/* 0x029c	 141 */		fsubd	%f2,%f0,%f2
/* 0x02a0	     */		std	%f2,[%o3]
/* 0x02a4	 143 */		srl	%o1,16,%o1
/* 0x02a8	 142 */		st	%o7,[%sp+96]
/* 0x02ac	 143 */		add	%o3,8,%o3
/* 0x02b0	 142 */		fmovs	%f0,%f2
/* 0x02b4	     */		ld	[%sp+96],%f3
/* 0x02b8	     */		fsubd	%f2,%f0,%f2
/* 0x02bc	     */		std	%f2,[%o5]
/* 0x02c0	 143 */		st	%o1,[%sp+92]
/* 0x02c4	     */		fmovs	%f0,%f2
/* 0x02c8	     */		ld	[%sp+92],%f3
/* 0x02cc	     */		fsubd	%f2,%f0,%f0
/* 0x02d0	     */		std	%f0,[%o5+8]
/* 0x02d4	     */		add	%o5,16,%o5
/* 0x02d8	     */		bl,a,pt	%icc,.L900000414
/* 0x02dc	     */		ld	[%o0],%f3
                       .L77000164:
/* 0x02e0	     */		ret	! Result =
/* 0x02e4	     */		restore	%g0,%g0,%g0
/* 0x02e8	   0 */		.type	conv_i32_to_d32_and_d16,2
/* 0x02e8	     */		.size	conv_i32_to_d32_and_d16,(.-conv_i32_to_d32_and_d16)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	4
!
! SUBROUTINE adjust_montf_result
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global adjust_montf_result
                       adjust_montf_result:

!  144		      !   }
!  145		      !}
!  148		      !void adjust_montf_result(unsigned int *i32, unsigned int *nint, int len)
!  149		      !{
!  150		      !long long acc;
!  151		      !int i;
!  153		      ! if(i32[len]>0) i=-1;

/* 000000	 153 */		sll	%o2,2,%g1
/* 0x0004	     */		or	%g0,-1,%g3
/* 0x0008	     */		ld	[%o0+%g1],%g1
/* 0x000c	     */		cmp	%g1,0
/* 0x0010	     */		bleu,pn	%icc,.L77000175
/* 0x0014	     */		or	%g0,%o1,%o3
/* 0x0018	     */		ba	.L900000511
/* 0x001c	     */		cmp	%g3,0
                       .L77000175:

!  154		      ! else
!  155		      !   {
!  156		      !     for(i=len-1; i>=0; i--)

/* 0x0020	 156 */		subcc	%o2,1,%g3
/* 0x0024	     */		bneg,pt	%icc,.L900000511
/* 0x0028	     */		cmp	%g3,0
/* 0x002c	     */		sll	%g3,2,%g1
/* 0x0030	     */		add	%o0,%g1,%g2
/* 0x0034	     */		add	%o1,%g1,%g1

!  157		      !       {
!  158		      !	 if(i32[i]!=nint[i]) break;

/* 0x0038	 158 */		ld	[%g1],%g5
                       .L900000510:
/* 0x003c	 158 */		ld	[%g2],%o5
/* 0x0040	     */		sub	%g1,4,%g1
/* 0x0044	     */		sub	%g2,4,%g2
/* 0x0048	     */		cmp	%o5,%g5
/* 0x004c	     */		bne,pn	%icc,.L77000182
/* 0x0050	     */		nop
/* 0x0054	     */		subcc	%g3,1,%g3
/* 0x0058	     */		bpos,a,pt	%icc,.L900000510
/* 0x005c	     */		ld	[%g1],%g5
                       .L77000182:

!  159		      !       }
!  160		      !   }
!  161		      ! if((i<0)||(i32[i]>nint[i]))

/* 0x0060	 161 */		cmp	%g3,0
                       .L900000511:
/* 0x0064	 161 */		bl,pn	%icc,.L77000198
/* 0x0068	     */		sll	%g3,2,%g2
/* 0x006c	     */		ld	[%o1+%g2],%g1
/* 0x0070	     */		ld	[%o0+%g2],%g2
/* 0x0074	     */		cmp	%g2,%g1
/* 0x0078	     */		bleu,pt	%icc,.L77000191
/* 0x007c	     */		nop
                       .L77000198:

!  162		      !   {
!  163		      !     acc=0;
!  164		      !     for(i=0;i<len;i++)

/* 0x0080	 164 */		cmp	%o2,0
/* 0x0084	     */		ble,pt	%icc,.L77000191
/* 0x0088	     */		nop
/* 0x008c	 161 */		or	%g0,-1,%g2
/* 0x0090	     */		sub	%o2,1,%g4
/* 0x0094	     */		srl	%g2,0,%g3
/* 0x0098	 163 */		or	%g0,0,%g5
/* 0x009c	 164 */		or	%g0,0,%o5
/* 0x00a0	 161 */		or	%g0,%o0,%o4
/* 0x00a4	     */		cmp	%o2,3
/* 0x00a8	     */		add	%o1,4,%g2
/* 0x00ac	 164 */		bl,pn	%icc,.L77000199
/* 0x00b0	     */		add	%o0,8,%g1

!  165		      !       {
!  166		      !	 acc=acc+(unsigned long long)(i32[i])-(unsigned long long)(nint[i]);

/* 0x00b4	 166 */		ld	[%o0],%o2
/* 0x00b8	   0 */		or	%g0,%g2,%o3
/* 0x00bc	 166 */		ld	[%o1],%o1
/* 0x00c0	   0 */		or	%g0,%g1,%o4

!  167		      !	 i32[i]=acc&0xffffffff;
!  168		      !	 acc=acc>>32;

/* 0x00c4	 168 */		or	%g0,2,%o5
/* 0x00c8	 166 */		ld	[%o0+4],%g1
/* 0x00cc	 164 */		sub	%o2,%o1,%o2
/* 0x00d0	     */		or	%g0,%o2,%g5
/* 0x00d4	 167 */		and	%o2,%g3,%o2
/* 0x00d8	     */		st	%o2,[%o0]
/* 0x00dc	 168 */		srax	%g5,32,%g5
                       .L900000505:
/* 0x00e0	 166 */		ld	[%o3],%o2
/* 0x00e4	 168 */		add	%o5,1,%o5
/* 0x00e8	     */		add	%o3,4,%o3
/* 0x00ec	     */		cmp	%o5,%g4
/* 0x00f0	     */		add	%o4,4,%o4
/* 0x00f4	 164 */		sub	%g1,%o2,%g1
/* 0x00f8	     */		add	%g1,%g5,%g5
/* 0x00fc	 167 */		and	%g5,%g3,%o2
/* 0x0100	 166 */		ld	[%o4-4],%g1
/* 0x0104	 167 */		st	%o2,[%o4-8]
/* 0x0108	 168 */		ble,pt	%icc,.L900000505
/* 0x010c	     */		srax	%g5,32,%g5
                       .L900000508:
/* 0x0110	 166 */		ld	[%o3],%g2
/* 0x0114	 164 */		sub	%g1,%g2,%g1
/* 0x0118	     */		add	%g1,%g5,%g1
/* 0x011c	 167 */		and	%g1,%g3,%g2
/* 0x0120	     */		retl	! Result =
/* 0x0124	     */		st	%g2,[%o4-4]
                       .L77000199:
/* 0x0128	 166 */		ld	[%o4],%g1
                       .L900000509:
/* 0x012c	 166 */		ld	[%o3],%g2
/* 0x0130	     */		add	%g5,%g1,%g1
/* 0x0134	 168 */		add	%o5,1,%o5
/* 0x0138	     */		add	%o3,4,%o3
/* 0x013c	     */		cmp	%o5,%g4
/* 0x0140	 166 */		sub	%g1,%g2,%g1
/* 0x0144	 167 */		and	%g1,%g3,%g2
/* 0x0148	     */		st	%g2,[%o4]
/* 0x014c	 168 */		add	%o4,4,%o4
/* 0x0150	     */		srax	%g1,32,%g5
/* 0x0154	     */		ble,a,pt	%icc,.L900000509
/* 0x0158	     */		ld	[%o4],%g1
                       .L77000191:
/* 0x015c	     */		retl	! Result =
/* 0x0160	     */		nop
/* 0x0164	   0 */		.type	adjust_montf_result,2
/* 0x0164	     */		.size	adjust_montf_result,(.-adjust_montf_result)

	.section	".text",#alloc,#execinstr
/* 000000	   0 */		.align	4
/* 000000	     */		.skip	16
!
! SUBROUTINE mont_mulf_noconv
!
! OFFSET    SOURCE LINE	LABEL	INSTRUCTION

                       	.global mont_mulf_noconv
                       mont_mulf_noconv:
/* 000000	     */		save	%sp,-144,%sp
                       .L900000644:
/* 0x0004	     */		call	.+8
/* 0x0008	     */		sethi	/*X*/%hi(_GLOBAL_OFFSET_TABLE_-(.L900000644-.)),%g4

!  169		      !       }
!  170		      !   }
!  171		      !}
!  175		      !void cleanup(double *dt, int from, int tlen);
!  177		      !/*
!  178		      !** the lengths of the input arrays should be at least the following:
!  179		      !** result[nlen+1], dm1[nlen], dm2[2*nlen+1], dt[4*nlen+2], dn[nlen], nint[nlen]
!  180		      !** all of them should be different from one another
!  181		      !**
!  182		      !*/
!  183		      !void mont_mulf_noconv(unsigned int *result,
!  184		      !		     double *dm1, double *dm2, double *dt,
!  185		      !		     double *dn, unsigned int *nint,
!  186		      !		     int nlen, double dn0)
!  187		      !{
!  188		      ! int i, j, jj;
!  189		      ! int tmp;
!  190		      ! double digit, m2j, nextm2j, a, b;
!  191		      ! double *dptmp, *pdm1, *pdm2, *pdn, *pdtj, pdn_0, pdm1_0;
!  193		      ! pdm1=&(dm1[0]);
!  194		      ! pdm2=&(dm2[0]);
!  195		      ! pdn=&(dn[0]);
!  196		      ! pdm2[2*nlen]=Zero;

/* 0x000c	 196 */		sethi	%hi(Zero),%g2
/* 0x0010	     */		ld	[%fp+92],%o0
/* 0x0014	 187 */		add	%g4,/*X*/%lo(_GLOBAL_OFFSET_TABLE_-(.L900000644-.)),%g4
/* 0x0018	 196 */		add	%g2,%lo(Zero),%g2
/* 0x001c	 187 */		ldd	[%fp+96],%f2
/* 0x0020	     */		add	%g4,%o7,%o3
/* 0x0024	     */		st	%i0,[%fp+68]
/* 0x0028	     */		or	%g0,%i3,%o1
/* 0x002c	 196 */		ld	[%o3+%g2],%g3
/* 0x0030	     */		sll	%o0,4,%g2
/* 0x0034	 187 */		or	%g0,%i1,%g4
/* 0x0038	     */		fmovd	%f2,%f16
/* 0x003c	     */		st	%i5,[%fp+88]
/* 0x0040	     */		or	%g0,%o1,%g5
/* 0x0044	     */		or	%g0,%i2,%o2
/* 0x0048	 196 */		ldd	[%g3],%f0
/* 0x004c	     */		or	%g0,%o0,%g1

!  198		      ! if (nlen!=16)

/* 0x0050	 198 */		cmp	%o0,16
/* 0x0054	     */		be,pn	%icc,.L77000289
/* 0x0058	     */		std	%f0,[%o2+%g2]

!  199		      !   {
!  200		      !     for(i=0;i<4*nlen+2;i++) dt[i]=Zero;

/* 0x005c	 200 */		sll	%o0,2,%g2
/* 0x0060	 187 */		or	%g0,%i4,%i0
/* 0x0064	 196 */		sll	%o0,1,%o7
/* 0x0068	 200 */		add	%g2,2,%o2
/* 0x006c	     */		cmp	%o2,0
/* 0x0070	 196 */		or	%g0,%i2,%i1
/* 0x0074	 200 */		ble,a,pt	%icc,.L900000658
/* 0x0078	     */		ldd	[%g4],%f0

!  202		      !     a=dt[0]=pdm1[0]*pdm2[0];
!  203		      !     digit=mod(lower32(a,Zero)*dn0,TwoToMinus16,TwoTo16);
!  205		      !     pdtj=&(dt[0]);
!  206		      !     for(j=jj=0;j<2*nlen;j++,jj++,pdtj++)
!  207		      !       {
!  208		      !	 m2j=pdm2[j];
!  209		      !	 a=pdtj[0]+pdn[0]*digit;
!  210		      !	 b=pdtj[1]+pdm1[0]*pdm2[j+1]+a*TwoToMinus16;
!  211		      !	 pdtj[1]=b;
!  213		      !#pragma pipeloop(0)
!  214		      !	 for(i=1;i<nlen;i++)
!  215		      !	   {
!  216		      !	     pdtj[2*i]+=pdm1[i]*m2j+pdn[i]*digit;
!  217		      !	   }
!  218		      ! 	 if((jj==30)) {cleanup(dt,j/2+1,2*nlen+1); jj=0;}
!  219		      !
!  220		      !	 digit=mod(lower32(b,Zero)*dn0,TwoToMinus16,TwoTo16);
!  221		      !       }
!  222		      !   }
!  223		      ! else
!  224		      !   {
!  225		      !     a=dt[0]=pdm1[0]*pdm2[0];
!  227		      !     dt[65]=     dt[64]=     dt[63]=     dt[62]=     dt[61]=     dt[60]=
!  228		      !     dt[59]=     dt[58]=     dt[57]=     dt[56]=     dt[55]=     dt[54]=
!  229		      !     dt[53]=     dt[52]=     dt[51]=     dt[50]=     dt[49]=     dt[48]=
!  230		      !     dt[47]=     dt[46]=     dt[45]=     dt[44]=     dt[43]=     dt[42]=
!  231		      !     dt[41]=     dt[40]=     dt[39]=     dt[38]=     dt[37]=     dt[36]=
!  232		      !     dt[35]=     dt[34]=     dt[33]=     dt[32]=     dt[31]=     dt[30]=
!  233		      !     dt[29]=     dt[28]=     dt[27]=     dt[26]=     dt[25]=     dt[24]=
!  234		      !     dt[23]=     dt[22]=     dt[21]=     dt[20]=     dt[19]=     dt[18]=
!  235		      !     dt[17]=     dt[16]=     dt[15]=     dt[14]=     dt[13]=     dt[12]=
!  236		      !     dt[11]=     dt[10]=     dt[ 9]=     dt[ 8]=     dt[ 7]=     dt[ 6]=
!  237		      !     dt[ 5]=     dt[ 4]=     dt[ 3]=     dt[ 2]=     dt[ 1]=Zero;
!  239		      !     pdn_0=pdn[0];
!  240		      !     pdm1_0=pdm1[0];
!  242		      !     digit=mod(lower32(a,Zero)*dn0,TwoToMinus16,TwoTo16);
!  243		      !     pdtj=&(dt[0]);
!  245		      !     for(j=0;j<32;j++,pdtj++)
!  246		      !       {
!  248		      !	 m2j=pdm2[j];
!  249		      !	 a=pdtj[0]+pdn_0*digit;
!  250		      !	 b=pdtj[1]+pdm1_0*pdm2[j+1]+a*TwoToMinus16;
!  251		      !	 pdtj[1]=b;
!  253		      !	 /**** this loop will be fully unrolled:
!  254		      !	 for(i=1;i<16;i++)
!  255		      !	   {
!  256		      !	     pdtj[2*i]+=pdm1[i]*m2j+pdn[i]*digit;
!  257		      !	   }
!  258		      !	 *************************************/
!  259		      !	     pdtj[2]+=pdm1[1]*m2j+pdn[1]*digit;
!  260		      !	     pdtj[4]+=pdm1[2]*m2j+pdn[2]*digit;
!  261		      !	     pdtj[6]+=pdm1[3]*m2j+pdn[3]*digit;
!  262		      !	     pdtj[8]+=pdm1[4]*m2j+pdn[4]*digit;
!  263		      !	     pdtj[10]+=pdm1[5]*m2j+pdn[5]*digit;
!  264		      !	     pdtj[12]+=pdm1[6]*m2j+pdn[6]*digit;
!  265		      !	     pdtj[14]+=pdm1[7]*m2j+pdn[7]*digit;
!  266		      !	     pdtj[16]+=pdm1[8]*m2j+pdn[8]*digit;
!  267		      !	     pdtj[18]+=pdm1[9]*m2j+pdn[9]*digit;
!  268		      !	     pdtj[20]+=pdm1[10]*m2j+pdn[10]*digit;
!  269		      !	     pdtj[22]+=pdm1[11]*m2j+pdn[11]*digit;
!  270		      !	     pdtj[24]+=pdm1[12]*m2j+pdn[12]*digit;
!  271		      !	     pdtj[26]+=pdm1[13]*m2j+pdn[13]*digit;
!  272		      !	     pdtj[28]+=pdm1[14]*m2j+pdn[14]*digit;
!  273		      !	     pdtj[30]+=pdm1[15]*m2j+pdn[15]*digit;
!  274		      !	 /* no need for cleenup, cannot overflow */
!  275		      !	 digit=mod(lower32(b,Zero)*dn0,TwoToMinus16,TwoTo16);
!  276		      !       }
!  277		      !   }
!  279		      ! conv_d16_to_i32(result,dt+2*nlen,(long long *)dt,nlen+1);
!  281		      ! adjust_montf_result(result,nint,nlen);

/* 0x007c	 281 */		add	%g2,2,%o0
/* 0x0080	 200 */		add	%g2,1,%o2
/* 0x0084	 281 */		cmp	%o0,3
/* 0x0088	     */		bl,pn	%icc,.L77000279
/* 0x008c	     */		or	%g0,1,%o0
/* 0x0090	     */		add	%o1,8,%o1
/* 0x0094	     */		or	%g0,1,%o3
/* 0x0098	     */		std	%f0,[%g5]
                       .L900000628:
/* 0x009c	     */		std	%f0,[%o1]
/* 0x00a0	     */		add	%o3,2,%o3
/* 0x00a4	     */		add	%o1,16,%o1
/* 0x00a8	     */		cmp	%o3,%g2
/* 0x00ac	     */		ble,pt	%icc,.L900000628
/* 0x00b0	     */		std	%f0,[%o1-8]
                       .L900000631:
/* 0x00b4	     */		cmp	%o3,%o2
/* 0x00b8	     */		bg,pn	%icc,.L77000284
/* 0x00bc	     */		add	%o3,1,%o0
                       .L77000279:
/* 0x00c0	     */		std	%f0,[%o1]
                       .L900000657:
/* 0x00c4	     */		ldd	[%g3],%f0
/* 0x00c8	     */		cmp	%o0,%o2
/* 0x00cc	     */		add	%o1,8,%o1
/* 0x00d0	     */		add	%o0,1,%o0
/* 0x00d4	     */		ble,a,pt	%icc,.L900000657
/* 0x00d8	     */		std	%f0,[%o1]
                       .L77000284:
/* 0x00dc	 202 */		ldd	[%g4],%f0
                       .L900000658:
/* 0x00e0	 202 */		ldd	[%i2],%f2
/* 0x00e4	     */		add	%o7,1,%o2
/* 0x00e8	 206 */		cmp	%o7,0
/* 0x00ec	     */		sll	%o2,1,%o0
/* 0x00f0	     */		sub	%o7,1,%o1
/* 0x00f4	 202 */		fmuld	%f0,%f2,%f0
/* 0x00f8	     */		std	%f0,[%g5]
/* 0x00fc	     */		sub	%g1,1,%o7
/* 0x0100	     */		ldd	[%g3],%f6
/* 0x0104	   0 */		or	%g0,%o7,%i2
/* 0x0108	     */		or	%g0,0,%l0
/* 0x010c	     */		ldd	[%g3-8],%f2
/* 0x0110	     */		or	%g0,0,%i5
/* 0x0114	     */		or	%g0,%o1,%o5
/* 0x0118	     */		fdtox	%f0,%f0
/* 0x011c	     */		ldd	[%g3-16],%f4
/* 0x0120	     */		or	%g0,%o0,%o3
/* 0x0124	 210 */		add	%i1,8,%o4
/* 0x0128	     */		or	%g0,0,%i4
/* 0x012c	     */		fmovs	%f6,%f0
/* 0x0130	     */		fxtod	%f0,%f0
/* 0x0134	 203 */		fmuld	%f0,%f16,%f0
/* 0x0138	     */		fmuld	%f0,%f2,%f2
/* 0x013c	     */		fdtox	%f2,%f2
/* 0x0140	     */		fxtod	%f2,%f2
/* 0x0144	     */		fmuld	%f2,%f4,%f2
/* 0x0148	     */		fsubd	%f0,%f2,%f22
/* 0x014c	 206 */		ble,pt	%icc,.L900000651
/* 0x0150	     */		sll	%g1,4,%g2
/* 0x0154	 210 */		ldd	[%i0],%f0
                       .L900000652:
/* 0x0158	 210 */		fmuld	%f0,%f22,%f8
/* 0x015c	     */		ldd	[%g4],%f0
/* 0x0160	 214 */		cmp	%g1,1
/* 0x0164	 210 */		ldd	[%o4+%i4],%f6
/* 0x0168	     */		add	%g4,8,%o0
/* 0x016c	 214 */		or	%g0,1,%o1
/* 0x0170	 210 */		ldd	[%i3],%f2
/* 0x0174	     */		add	%i3,16,%l1
/* 0x0178	     */		fmuld	%f0,%f6,%f6
/* 0x017c	     */		ldd	[%g3-8],%f4
/* 0x0180	     */		faddd	%f2,%f8,%f2
/* 0x0184	     */		ldd	[%i3+8],%f0
/* 0x0188	 208 */		ldd	[%i1+%i4],%f20
/* 0x018c	 210 */		faddd	%f0,%f6,%f0
/* 0x0190	     */		fmuld	%f2,%f4,%f2
/* 0x0194	     */		faddd	%f0,%f2,%f18
/* 0x0198	 211 */		std	%f18,[%i3+8]
/* 0x019c	 214 */		ble,pt	%icc,.L900000656
/* 0x01a0	     */		srl	%i5,31,%g2
/* 0x01a4	     */		cmp	%i2,7
/* 0x01a8	 210 */		add	%i0,8,%g2
/* 0x01ac	 214 */		bl,pn	%icc,.L77000281
/* 0x01b0	     */		add	%g2,24,%o2
/* 0x01b4	 216 */		ldd	[%g4+8],%f2
/* 0x01b8	     */		add	%g4,40,%o0
/* 0x01bc	     */		ldd	[%g4+16],%f6
/* 0x01c0	   0 */		or	%g0,%o2,%g2
/* 0x01c4	 216 */		add	%i3,48,%l1
/* 0x01c8	     */		ldd	[%g2-24],%f0
/* 0x01cc	     */		fmuld	%f2,%f20,%f2
/* 0x01d0	 214 */		sub	%i2,2,%o2
/* 0x01d4	 216 */		ldd	[%g2-16],%f8
/* 0x01d8	     */		fmuld	%f6,%f20,%f10
/* 0x01dc	     */		or	%g0,5,%o1
/* 0x01e0	     */		ldd	[%g4+24],%f14
/* 0x01e4	     */		fmuld	%f0,%f22,%f4
/* 0x01e8	     */		ldd	[%i3+16],%f0
/* 0x01ec	     */		ldd	[%g2-8],%f6
/* 0x01f0	     */		ldd	[%g4+32],%f12
/* 0x01f4	     */		faddd	%f2,%f4,%f4
/* 0x01f8	     */		ldd	[%i3+32],%f2
                       .L900000640:
/* 0x01fc	 216 */		ldd	[%g2],%f24
/* 0x0200	     */		add	%o1,3,%o1
/* 0x0204	     */		add	%g2,24,%g2
/* 0x0208	     */		fmuld	%f8,%f22,%f8
/* 0x020c	     */		ldd	[%l1],%f28
/* 0x0210	     */		cmp	%o1,%o2
/* 0x0214	     */		add	%o0,24,%o0
/* 0x0218	     */		ldd	[%o0-24],%f26
/* 0x021c	     */		faddd	%f0,%f4,%f0
/* 0x0220	     */		add	%l1,48,%l1
/* 0x0224	     */		faddd	%f10,%f8,%f10
/* 0x0228	     */		fmuld	%f14,%f20,%f4
/* 0x022c	     */		std	%f0,[%l1-80]
/* 0x0230	     */		ldd	[%g2-16],%f8
/* 0x0234	     */		fmuld	%f6,%f22,%f6
/* 0x0238	     */		ldd	[%l1-32],%f0
/* 0x023c	     */		ldd	[%o0-16],%f14
/* 0x0240	     */		faddd	%f2,%f10,%f2
/* 0x0244	     */		faddd	%f4,%f6,%f10
/* 0x0248	     */		fmuld	%f12,%f20,%f4
/* 0x024c	     */		std	%f2,[%l1-64]
/* 0x0250	     */		ldd	[%g2-8],%f6
/* 0x0254	     */		fmuld	%f24,%f22,%f24
/* 0x0258	     */		ldd	[%l1-16],%f2
/* 0x025c	     */		ldd	[%o0-8],%f12
/* 0x0260	     */		faddd	%f28,%f10,%f10
/* 0x0264	     */		std	%f10,[%l1-48]
/* 0x0268	     */		fmuld	%f26,%f20,%f10
/* 0x026c	     */		ble,pt	%icc,.L900000640
/* 0x0270	     */		faddd	%f4,%f24,%f4
                       .L900000643:
/* 0x0274	 216 */		fmuld	%f8,%f22,%f28
/* 0x0278	     */		ldd	[%g2],%f24
/* 0x027c	     */		faddd	%f0,%f4,%f26
/* 0x0280	     */		fmuld	%f12,%f20,%f8
/* 0x0284	     */		add	%l1,32,%l1
/* 0x0288	     */		cmp	%o1,%i2
/* 0x028c	     */		fmuld	%f14,%f20,%f14
/* 0x0290	     */		ldd	[%l1-32],%f4
/* 0x0294	     */		add	%g2,8,%g2
/* 0x0298	     */		faddd	%f10,%f28,%f12
/* 0x029c	     */		fmuld	%f6,%f22,%f6
/* 0x02a0	     */		ldd	[%l1-16],%f0
/* 0x02a4	     */		fmuld	%f24,%f22,%f10
/* 0x02a8	     */		std	%f26,[%l1-64]
/* 0x02ac	     */		faddd	%f2,%f12,%f2
/* 0x02b0	     */		std	%f2,[%l1-48]
/* 0x02b4	     */		faddd	%f14,%f6,%f6
/* 0x02b8	     */		faddd	%f8,%f10,%f2
/* 0x02bc	     */		faddd	%f4,%f6,%f4
/* 0x02c0	     */		std	%f4,[%l1-32]
/* 0x02c4	     */		faddd	%f0,%f2,%f0
/* 0x02c8	     */		bg,pn	%icc,.L77000213
/* 0x02cc	     */		std	%f0,[%l1-16]
                       .L77000281:
/* 0x02d0	 216 */		ldd	[%o0],%f0
                       .L900000655:
/* 0x02d4	 216 */		ldd	[%g2],%f4
/* 0x02d8	     */		fmuld	%f0,%f20,%f2
/* 0x02dc	     */		add	%o1,1,%o1
/* 0x02e0	     */		ldd	[%l1],%f0
/* 0x02e4	     */		add	%o0,8,%o0
/* 0x02e8	     */		add	%g2,8,%g2
/* 0x02ec	     */		fmuld	%f4,%f22,%f4
/* 0x02f0	     */		cmp	%o1,%i2
/* 0x02f4	     */		faddd	%f2,%f4,%f2
/* 0x02f8	     */		faddd	%f0,%f2,%f0
/* 0x02fc	     */		std	%f0,[%l1]
/* 0x0300	     */		add	%l1,16,%l1
/* 0x0304	     */		ble,a,pt	%icc,.L900000655
/* 0x0308	     */		ldd	[%o0],%f0
                       .L77000213:
/* 0x030c	     */		srl	%i5,31,%g2
                       .L900000656:
/* 0x0310	 218 */		cmp	%l0,30
/* 0x0314	     */		bne,a,pt	%icc,.L900000654
/* 0x0318	     */		fdtox	%f18,%f0
/* 0x031c	     */		add	%i5,%g2,%g2
/* 0x0320	     */		sub	%o3,1,%o2
/* 0x0324	     */		sra	%g2,1,%o0
/* 0x0328	 216 */		ldd	[%g3],%f0
/* 0x032c	     */		add	%o0,1,%g2
/* 0x0330	     */		sll	%g2,1,%o0
/* 0x0334	     */		fmovd	%f0,%f2
/* 0x0338	     */		sll	%g2,4,%o1
/* 0x033c	     */		cmp	%o0,%o3
/* 0x0340	     */		bge,pt	%icc,.L77000215
/* 0x0344	     */		or	%g0,0,%l0
/* 0x0348	 218 */		add	%g5,%o1,%o1
/* 0x034c	 216 */		ldd	[%o1],%f6
                       .L900000653:
/* 0x0350	     */		fdtox	%f6,%f10
/* 0x0354	     */		ldd	[%o1+8],%f4
/* 0x0358	     */		add	%o0,2,%o0
/* 0x035c	     */		ldd	[%g3],%f12
/* 0x0360	     */		fdtox	%f6,%f6
/* 0x0364	     */		cmp	%o0,%o2
/* 0x0368	     */		fdtox	%f4,%f8
/* 0x036c	     */		fdtox	%f4,%f4
/* 0x0370	     */		fmovs	%f12,%f10
/* 0x0374	     */		fmovs	%f12,%f8
/* 0x0378	     */		fxtod	%f10,%f10
/* 0x037c	     */		fxtod	%f8,%f8
/* 0x0380	     */		faddd	%f10,%f2,%f2
/* 0x0384	     */		std	%f2,[%o1]
/* 0x0388	     */		faddd	%f8,%f0,%f0
/* 0x038c	     */		std	%f0,[%o1+8]
/* 0x0390	     */		add	%o1,16,%o1
/* 0x0394	     */		fitod	%f6,%f2
/* 0x0398	     */		fitod	%f4,%f0
/* 0x039c	     */		ble,a,pt	%icc,.L900000653
/* 0x03a0	     */		ldd	[%o1],%f6
                       .L77000233:
/* 0x03a4	     */		or	%g0,0,%l0
                       .L77000215:
/* 0x03a8	     */		fdtox	%f18,%f0
                       .L900000654:
/* 0x03ac	     */		ldd	[%g3],%f6
/* 0x03b0	 220 */		add	%i5,1,%i5
/* 0x03b4	     */		add	%i4,8,%i4
/* 0x03b8	     */		ldd	[%g3-8],%f2
/* 0x03bc	     */		add	%l0,1,%l0
/* 0x03c0	     */		add	%i3,8,%i3
/* 0x03c4	     */		fmovs	%f6,%f0
/* 0x03c8	     */		ldd	[%g3-16],%f4
/* 0x03cc	     */		cmp	%i5,%o5
/* 0x03d0	     */		fxtod	%f0,%f0
/* 0x03d4	     */		fmuld	%f0,%f16,%f0
/* 0x03d8	     */		fmuld	%f0,%f2,%f2
/* 0x03dc	     */		fdtox	%f2,%f2
/* 0x03e0	     */		fxtod	%f2,%f2
/* 0x03e4	     */		fmuld	%f2,%f4,%f2
/* 0x03e8	     */		fsubd	%f0,%f2,%f22
/* 0x03ec	     */		ble,a,pt	%icc,.L900000652
/* 0x03f0	     */		ldd	[%i0],%f0
                       .L900000627:
/* 0x03f4	 220 */		ba	.L900000651
/* 0x03f8	     */		sll	%g1,4,%g2
                       .L77000289:
/* 0x03fc	 225 */		ldd	[%o2],%f6
/* 0x0400	 243 */		or	%g0,%o1,%o4
/* 0x0404	 245 */		or	%g0,0,%o3
/* 0x0408	 225 */		ldd	[%g4],%f4
/* 0x040c	 237 */		std	%f0,[%o1+8]
/* 0x0410	     */		std	%f0,[%o1+16]
/* 0x0414	 225 */		fmuld	%f4,%f6,%f4
/* 0x0418	     */		std	%f4,[%o1]
/* 0x041c	 237 */		std	%f0,[%o1+24]
/* 0x0420	     */		std	%f0,[%o1+32]
/* 0x0424	     */		fdtox	%f4,%f4
/* 0x0428	     */		std	%f0,[%o1+40]
/* 0x042c	     */		std	%f0,[%o1+48]
/* 0x0430	     */		std	%f0,[%o1+56]
/* 0x0434	     */		std	%f0,[%o1+64]
/* 0x0438	     */		std	%f0,[%o1+72]
/* 0x043c	     */		std	%f0,[%o1+80]
/* 0x0440	     */		std	%f0,[%o1+88]
/* 0x0444	     */		std	%f0,[%o1+96]
/* 0x0448	     */		std	%f0,[%o1+104]
/* 0x044c	     */		std	%f0,[%o1+112]
/* 0x0450	     */		std	%f0,[%o1+120]
/* 0x0454	     */		std	%f0,[%o1+128]
/* 0x0458	     */		std	%f0,[%o1+136]
/* 0x045c	     */		std	%f0,[%o1+144]
/* 0x0460	     */		std	%f0,[%o1+152]
/* 0x0464	     */		std	%f0,[%o1+160]
/* 0x0468	     */		std	%f0,[%o1+168]
/* 0x046c	     */		fmovs	%f0,%f4
/* 0x0470	     */		std	%f0,[%o1+176]
/* 0x0474	 245 */		or	%g0,0,%o0
/* 0x0478	 237 */		std	%f0,[%o1+184]
/* 0x047c	     */		fxtod	%f4,%f4
/* 0x0480	     */		std	%f0,[%o1+192]
/* 0x0484	     */		std	%f0,[%o1+200]
/* 0x0488	     */		std	%f0,[%o1+208]
/* 0x048c	 242 */		fmuld	%f4,%f2,%f2
/* 0x0490	 237 */		std	%f0,[%o1+216]
/* 0x0494	     */		std	%f0,[%o1+224]
/* 0x0498	     */		std	%f0,[%o1+232]
/* 0x049c	     */		std	%f0,[%o1+240]
/* 0x04a0	     */		std	%f0,[%o1+248]
/* 0x04a4	     */		std	%f0,[%o1+256]
/* 0x04a8	     */		std	%f0,[%o1+264]
/* 0x04ac	     */		std	%f0,[%o1+272]
/* 0x04b0	     */		std	%f0,[%o1+280]
/* 0x04b4	     */		std	%f0,[%o1+288]
/* 0x04b8	     */		std	%f0,[%o1+296]
/* 0x04bc	     */		std	%f0,[%o1+304]
/* 0x04c0	     */		std	%f0,[%o1+312]
/* 0x04c4	     */		std	%f0,[%o1+320]
/* 0x04c8	     */		std	%f0,[%o1+328]
/* 0x04cc	     */		std	%f0,[%o1+336]
/* 0x04d0	     */		std	%f0,[%o1+344]
/* 0x04d4	     */		std	%f0,[%o1+352]
/* 0x04d8	     */		std	%f0,[%o1+360]
/* 0x04dc	     */		std	%f0,[%o1+368]
/* 0x04e0	     */		std	%f0,[%o1+376]
/* 0x04e4	     */		std	%f0,[%o1+384]
/* 0x04e8	     */		std	%f0,[%o1+392]
/* 0x04ec	     */		std	%f0,[%o1+400]
/* 0x04f0	     */		std	%f0,[%o1+408]
/* 0x04f4	     */		std	%f0,[%o1+416]
/* 0x04f8	     */		std	%f0,[%o1+424]
/* 0x04fc	     */		std	%f0,[%o1+432]
/* 0x0500	     */		std	%f0,[%o1+440]
/* 0x0504	     */		std	%f0,[%o1+448]
/* 0x0508	     */		std	%f0,[%o1+456]
/* 0x050c	     */		std	%f0,[%o1+464]
/* 0x0510	     */		std	%f0,[%o1+472]
/* 0x0514	     */		std	%f0,[%o1+480]
/* 0x0518	     */		std	%f0,[%o1+488]
/* 0x051c	     */		std	%f0,[%o1+496]
/* 0x0520	     */		std	%f0,[%o1+504]
/* 0x0524	     */		std	%f0,[%o1+512]
/* 0x0528	     */		std	%f0,[%o1+520]
/* 0x052c	     */		ldd	[%g3-8],%f0
/* 0x0530	     */		ldd	[%g3-16],%f8
/* 0x0534	     */		fmuld	%f2,%f0,%f6
/* 0x0538	 239 */		ldd	[%i4],%f4
/* 0x053c	 240 */		ldd	[%g4],%f0
/* 0x0540	     */		fdtox	%f6,%f6
/* 0x0544	     */		fxtod	%f6,%f6
/* 0x0548	     */		fmuld	%f6,%f8,%f6
/* 0x054c	     */		fsubd	%f2,%f6,%f2
/* 0x0550	 250 */		fmuld	%f4,%f2,%f12
                       .L900000650:


	fmovd %f2,%f0
	fmovd %f16,%f18
	ldd [%i4],%f2
	ldd [%o4],%f8
	ldd [%g4],%f10
	ldd [%g3-8],%f14
	ldd [%g3-16],%f16
	ldd [%i2],%f24

	ldd [%g4+8],%f26
	ldd [%g4+16],%f40
	ldd [%g4+48],%f46
	ldd [%g4+56],%f30
	ldd [%g4+64],%f54
	ldd [%g4+104],%f34
	ldd [%g4+112],%f58

	ldd [%i4+8],%f28
	ldd [%i4+104],%f38
	ldd [%i4+112],%f60


	.L99999999:
!1
	ldd	[%g4+24],%f32
	fmuld	%f0,%f2,%f4
!2
	ldd	[%i4+24],%f36
	fmuld	%f26,%f24,%f20
!3
	ldd	[%g4+40],%f42
	fmuld	%f28,%f0,%f22
!4
	ldd	[%i4+40],%f44
	fmuld	%f32,%f24,%f32
!5
	ldd	[%i2+8],%f6
	faddd	%f4,%f8,%f4
	fmuld	%f36,%f0,%f36
!6
	add	%i2,8,%i2
	ldd	[%i4+56],%f50
	fmuld	%f42,%f24,%f42
!7
	ldd	[%g4+72],%f52
	faddd	%f20,%f22,%f20
	fmuld	%f44,%f0,%f44
!8
	ldd	[%o4+16],%f22
	fmuld	%f10,%f6,%f12
!9
	ldd	[%i4+72],%f56
	faddd	%f32,%f36,%f32
	fmuld	%f14,%f4,%f4
!10
	ldd	[%o4+48],%f36
	fmuld	%f30,%f24,%f48
!11
	ldd	[%o4+8],%f8
	faddd	%f20,%f22,%f20
	fmuld	%f50,%f0,%f50
!12
	std	%f20,[%o4+16]
	faddd	%f42,%f44,%f42
	fmuld	%f52,%f24,%f52
!13
	ldd	[%o4+80],%f44
	faddd	%f4,%f12,%f4
	fmuld	%f56,%f0,%f56
!14
	ldd	[%g4+88],%f20
	faddd	%f32,%f36,%f32
!15
	ldd	[%i4+88],%f22
	faddd	%f48,%f50,%f48
!16
	ldd	[%o4+112],%f50
	faddd	%f52,%f56,%f52
!17
	ldd	[%o4+144],%f56
	faddd	%f4,%f8,%f8
	fmuld	%f20,%f24,%f20
!18
	std	%f32,[%o4+48]
	faddd	%f42,%f44,%f42
	fmuld	%f22,%f0,%f22
!19
	std	%f42,[%o4+80]
	faddd	%f48,%f50,%f48
	fmuld	%f34,%f24,%f32
!20
	std	%f48,[%o4+112]
	faddd	%f52,%f56,%f52
	fmuld	%f38,%f0,%f36
!21
	ldd	[%g4+120],%f42
	fdtox	%f8,%f4
!22
	std	%f52,[%o4+144]
	faddd	%f20,%f22,%f20
!23
	ldd	[%i4+120],%f44
!24
	ldd	[%o4+176],%f22
	faddd	%f32,%f36,%f32
	fmuld	%f42,%f24,%f42
!25
	ldd	[%i4+16],%f50
	fmovs	%f17,%f4
!26
	ldd	[%g4+32],%f52
	fmuld	%f44,%f0,%f44
!27
	ldd	[%i4+32],%f56
	fmuld	%f40,%f24,%f48
!28
	ldd	[%o4+208],%f36
	faddd	%f20,%f22,%f20
	fmuld	%f50,%f0,%f50
!29
	std	%f20,[%o4+176]
	fxtod	%f4,%f4
	fmuld	%f52,%f24,%f52
!30
	ldd	[%i4+48],%f22
	faddd	%f42,%f44,%f42
	fmuld	%f56,%f0,%f56
!31
	ldd	[%o4+240],%f44
	faddd	%f32,%f36,%f32
!32
	std	%f32,[%o4+208]
	faddd	%f48,%f50,%f48
	fmuld	%f46,%f24,%f20
!33
	ldd	[%o4+32],%f50
	fmuld	%f4,%f18,%f12
!34
	ldd	[%i4+64],%f36
	faddd	%f52,%f56,%f52
	fmuld	%f22,%f0,%f22
!35
	ldd	[%o4+64],%f56
	faddd	%f42,%f44,%f42
!36
	std	%f42,[%o4+240]
	faddd	%f48,%f50,%f48
	fmuld	%f54,%f24,%f32
!37
	std	%f48,[%o4+32]
	fmuld	%f12,%f14,%f4
!38
	ldd	[%g4+80],%f42
	faddd	%f52,%f56,%f56	! yes, tmp52!
	fmuld	%f36,%f0,%f36
!39
	ldd	[%i4+80],%f44
	faddd	%f20,%f22,%f20
!40
	ldd	[%g4+96],%f48
	fmuld	%f58,%f24,%f52
!41
	ldd	[%i4+96],%f50
	fdtox	%f4,%f4
	fmuld	%f42,%f24,%f42
!42
	std	%f56,[%o4+64]	! yes, tmp52!
	faddd	%f32,%f36,%f32
	fmuld	%f44,%f0,%f44
!43
	ldd	[%o4+96],%f22
	fmuld	%f48,%f24,%f48
!44
	ldd	[%o4+128],%f36
	fmovd	%f6,%f24
	fmuld	%f50,%f0,%f50
!45
	fxtod	%f4,%f4
	fmuld	%f60,%f0,%f56
!46
	add	%o4,8,%o4
	faddd	%f42,%f44,%f42
!47
	ldd	[%o4+160-8],%f44
	faddd	%f20,%f22,%f20
!48
	std	%f20,[%o4+96-8]
	faddd	%f48,%f50,%f48
!49
	ldd	[%o4+192-8],%f50
	faddd	%f52,%f56,%f52
	fmuld	%f4,%f16,%f4
!50
	ldd	[%o4+224-8],%f56
	faddd	%f32,%f36,%f32
!51
	std	%f32,[%o4+128-8]
	faddd	%f42,%f44,%f42
!52
	add	%o3,1,%o3
	std	%f42,[%o4+160-8]
	faddd	%f48,%f50,%f48
!53
	cmp	%o3,31
	std	%f48,[%o4+192-8]
	fsubd	%f12,%f4,%f0
!54
	faddd	%f52,%f56,%f52
	ble,pt	%icc,.L99999999
	std	%f52,[%o4+224-8]
!55
	std %f8,[%o4]


	                       .L77000285:
/* 0x07a8	 279 */		sll	%g1,4,%g2
                       .L900000651:
/* 0x07ac	 279 */		ldd	[%g5+%g2],%f0
/* 0x07b0	     */		add	%g5,%g2,%i1
/* 0x07b4	     */		or	%g0,0,%o4
/* 0x07b8	 206 */		ld	[%fp+68],%o0
/* 0x07bc	 279 */		or	%g0,0,%i0
/* 0x07c0	     */		cmp	%g1,0
/* 0x07c4	     */		fdtox	%f0,%f0
/* 0x07c8	     */		std	%f0,[%sp+120]
/* 0x07cc	 275 */		sethi	%hi(0xfc00),%o1
/* 0x07d0	 206 */		or	%g0,%o0,%o3
/* 0x07d4	 275 */		sub	%g1,1,%g4
/* 0x07d8	 279 */		ldd	[%i1+8],%f0
/* 0x07dc	     */		or	%g0,%o0,%g5
/* 0x07e0	     */		add	%o1,1023,%o1
/* 0x07e4	     */		fdtox	%f0,%f0
/* 0x07e8	     */		std	%f0,[%sp+112]
/* 0x07ec	     */		ldx	[%sp+112],%o5
/* 0x07f0	     */		ldx	[%sp+120],%o7
/* 0x07f4	     */		ble,pt	%icc,.L900000649
/* 0x07f8	     */		sethi	%hi(0xfc00),%g2
/* 0x07fc	 275 */		or	%g0,-1,%g2
/* 0x0800	 279 */		cmp	%g1,3
/* 0x0804	 275 */		srl	%g2,0,%o2
/* 0x0808	 279 */		bl,pn	%icc,.L77000286
/* 0x080c	     */		or	%g0,%i1,%g2
/* 0x0810	     */		ldd	[%i1+16],%f0
/* 0x0814	     */		and	%o5,%o1,%o0
/* 0x0818	     */		add	%i1,16,%g2
/* 0x081c	     */		sllx	%o0,16,%g3
/* 0x0820	     */		and	%o7,%o2,%o0
/* 0x0824	     */		fdtox	%f0,%f0
/* 0x0828	     */		std	%f0,[%sp+104]
/* 0x082c	     */		add	%o0,%g3,%o4
/* 0x0830	     */		ldd	[%i1+24],%f2
/* 0x0834	     */		srax	%o5,16,%o0
/* 0x0838	     */		add	%o3,4,%g5
/* 0x083c	     */		stx	%o0,[%sp+128]
/* 0x0840	     */		and	%o4,%o2,%o0
/* 0x0844	     */		or	%g0,1,%i0
/* 0x0848	     */		stx	%o0,[%sp+112]
/* 0x084c	     */		srax	%o4,32,%o0
/* 0x0850	     */		fdtox	%f2,%f0
/* 0x0854	     */		stx	%o0,[%sp+136]
/* 0x0858	     */		srax	%o7,32,%o4
/* 0x085c	     */		std	%f0,[%sp+96]
/* 0x0860	     */		ldx	[%sp+136],%o7
/* 0x0864	     */		ldx	[%sp+128],%o0
/* 0x0868	     */		ldx	[%sp+104],%g3
/* 0x086c	     */		add	%o0,%o7,%o0
/* 0x0870	     */		ldx	[%sp+112],%o7
/* 0x0874	     */		add	%o4,%o0,%o4
/* 0x0878	     */		ldx	[%sp+96],%o5
/* 0x087c	     */		st	%o7,[%o3]
/* 0x0880	     */		or	%g0,%g3,%o7
                       .L900000632:
/* 0x0884	     */		ldd	[%g2+16],%f0
/* 0x0888	     */		add	%i0,1,%i0
/* 0x088c	     */		add	%g5,4,%g5
/* 0x0890	     */		cmp	%i0,%g4
/* 0x0894	     */		add	%g2,16,%g2
/* 0x0898	     */		fdtox	%f0,%f0
/* 0x089c	     */		std	%f0,[%sp+104]
/* 0x08a0	     */		ldd	[%g2+8],%f0
/* 0x08a4	     */		fdtox	%f0,%f0
/* 0x08a8	     */		std	%f0,[%sp+96]
/* 0x08ac	     */		and	%o5,%o1,%g3
/* 0x08b0	     */		sllx	%g3,16,%g3
/* 0x08b4	     */		stx	%g3,[%sp+120]
/* 0x08b8	     */		and	%o7,%o2,%g3
/* 0x08bc	     */		stx	%o7,[%sp+128]
/* 0x08c0	     */		ldx	[%sp+120],%o7
/* 0x08c4	     */		add	%g3,%o7,%g3
/* 0x08c8	     */		ldx	[%sp+128],%o7
/* 0x08cc	     */		srax	%o5,16,%o5
/* 0x08d0	     */		add	%g3,%o4,%g3
/* 0x08d4	     */		srax	%g3,32,%o4
/* 0x08d8	     */		stx	%o4,[%sp+112]
/* 0x08dc	     */		srax	%o7,32,%o4
/* 0x08e0	     */		ldx	[%sp+112],%o7
/* 0x08e4	     */		add	%o5,%o7,%o7
/* 0x08e8	     */		ldx	[%sp+96],%o5
/* 0x08ec	     */		add	%o4,%o7,%o4
/* 0x08f0	     */		and	%g3,%o2,%g3
/* 0x08f4	     */		ldx	[%sp+104],%o7
/* 0x08f8	     */		ble,pt	%icc,.L900000632
/* 0x08fc	     */		st	%g3,[%g5-4]
                       .L900000635:
/* 0x0900	     */		ba	.L900000649
/* 0x0904	     */		sethi	%hi(0xfc00),%g2
                       .L77000286:
/* 0x0908	     */		ldd	[%g2+16],%f0
                       .L900000648:
/* 0x090c	     */		and	%o7,%o2,%o0
/* 0x0910	     */		and	%o5,%o1,%g3
/* 0x0914	     */		fdtox	%f0,%f0
/* 0x0918	     */		add	%o4,%o0,%o0
/* 0x091c	     */		std	%f0,[%sp+104]
/* 0x0920	     */		add	%i0,1,%i0
/* 0x0924	     */		sllx	%g3,16,%o4
/* 0x0928	     */		ldd	[%g2+24],%f2
/* 0x092c	     */		add	%g2,16,%g2
/* 0x0930	     */		add	%o0,%o4,%o4
/* 0x0934	     */		cmp	%i0,%g4
/* 0x0938	     */		srax	%o5,16,%o0
/* 0x093c	     */		stx	%o0,[%sp+112]
/* 0x0940	     */		and	%o4,%o2,%g3
/* 0x0944	     */		srax	%o4,32,%o5
/* 0x0948	     */		fdtox	%f2,%f0
/* 0x094c	     */		std	%f0,[%sp+96]
/* 0x0950	     */		srax	%o7,32,%o4
/* 0x0954	     */		ldx	[%sp+112],%o7
/* 0x0958	     */		add	%o7,%o5,%o7
/* 0x095c	     */		ldx	[%sp+104],%o5
/* 0x0960	     */		add	%o4,%o7,%o4
/* 0x0964	     */		ldx	[%sp+96],%o0
/* 0x0968	     */		st	%g3,[%g5]
/* 0x096c	     */		or	%g0,%o5,%o7
/* 0x0970	     */		add	%g5,4,%g5
/* 0x0974	     */		or	%g0,%o0,%o5
/* 0x0978	     */		ble,a,pt	%icc,.L900000648
/* 0x097c	     */		ldd	[%g2+16],%f0
                       .L77000236:
/* 0x0980	     */		sethi	%hi(0xfc00),%g2
                       .L900000649:
/* 0x0984	     */		or	%g0,-1,%o0
/* 0x0988	     */		add	%g2,1023,%g2
/* 0x098c	     */		ld	[%fp+88],%o1
/* 0x0990	     */		srl	%o0,0,%g3
/* 0x0994	     */		and	%o5,%g2,%g2
/* 0x0998	     */		and	%o7,%g3,%g4
/* 0x099c	     */		sllx	%g2,16,%g2
/* 0x09a0	     */		add	%o4,%g4,%g4
/* 0x09a4	     */		add	%g4,%g2,%g2
/* 0x09a8	     */		sll	%i0,2,%g4
/* 0x09ac	     */		and	%g2,%g3,%g2
/* 0x09b0	     */		st	%g2,[%o3+%g4]
/* 0x09b4	 281 */		sll	%g1,2,%g2
/* 0x09b8	     */		ld	[%o3+%g2],%g2
/* 0x09bc	     */		cmp	%g2,0
/* 0x09c0	     */		bleu,pn	%icc,.L77000241
/* 0x09c4	     */		or	%g0,-1,%o5
/* 0x09c8	     */		ba	.L900000647
/* 0x09cc	     */		cmp	%o5,0
                       .L77000241:
/* 0x09d0	     */		subcc	%g1,1,%o5
/* 0x09d4	     */		bneg,pt	%icc,.L900000647
/* 0x09d8	     */		cmp	%o5,0
/* 0x09dc	     */		sll	%o5,2,%g2
/* 0x09e0	     */		add	%o1,%g2,%o0
/* 0x09e4	     */		add	%o3,%g2,%o4
/* 0x09e8	     */		ld	[%o0],%g2
                       .L900000646:
/* 0x09ec	     */		ld	[%o4],%g3
/* 0x09f0	     */		sub	%o0,4,%o0
/* 0x09f4	     */		sub	%o4,4,%o4
/* 0x09f8	     */		cmp	%g3,%g2
/* 0x09fc	     */		bne,pn	%icc,.L77000244
/* 0x0a00	     */		nop
/* 0x0a04	     */		subcc	%o5,1,%o5
/* 0x0a08	     */		bpos,a,pt	%icc,.L900000646
/* 0x0a0c	     */		ld	[%o0],%g2
                       .L77000244:
/* 0x0a10	     */		cmp	%o5,0
                       .L900000647:
/* 0x0a14	     */		bl,pn	%icc,.L77000287
/* 0x0a18	     */		sll	%o5,2,%g2
/* 0x0a1c	     */		ld	[%o1+%g2],%g3
/* 0x0a20	     */		ld	[%o3+%g2],%g2
/* 0x0a24	     */		cmp	%g2,%g3
/* 0x0a28	     */		bleu,pt	%icc,.L77000224
/* 0x0a2c	     */		nop
                       .L77000287:
/* 0x0a30	     */		cmp	%g1,0
/* 0x0a34	     */		ble,pt	%icc,.L77000224
/* 0x0a38	     */		nop
/* 0x0a3c	 281 */		sub	%g1,1,%o7
/* 0x0a40	     */		or	%g0,-1,%g2
/* 0x0a44	     */		srl	%g2,0,%o4
/* 0x0a48	     */		add	%o7,1,%o0
/* 0x0a4c	     */		or	%g0,%o1,%o2
/* 0x0a50	 279 */		or	%g0,0,%o5
/* 0x0a54	     */		or	%g0,0,%g1
/* 0x0a58	     */		cmp	%o0,3
/* 0x0a5c	     */		add	%o1,4,%o0
/* 0x0a60	     */		bl,pn	%icc,.L77000288
/* 0x0a64	     */		add	%o3,8,%o1
/* 0x0a68	     */		ld	[%o0-4],%g3
/* 0x0a6c	   0 */		or	%g0,%o1,%o3
/* 0x0a70	     */		or	%g0,%o0,%o2
/* 0x0a74	 279 */		ld	[%o1-8],%g2
/* 0x0a78	     */		or	%g0,2,%g1
/* 0x0a7c	     */		ld	[%o3-4],%o0
/* 0x0a80	     */		sub	%g2,%g3,%g2
/* 0x0a84	     */		or	%g0,%g2,%o5
/* 0x0a88	     */		and	%g2,%o4,%g2
/* 0x0a8c	     */		st	%g2,[%o3-8]
/* 0x0a90	     */		srax	%o5,32,%o5
                       .L900000636:
/* 0x0a94	     */		ld	[%o2],%g2
/* 0x0a98	     */		add	%g1,1,%g1
/* 0x0a9c	     */		add	%o2,4,%o2
/* 0x0aa0	     */		cmp	%g1,%o7
/* 0x0aa4	     */		add	%o3,4,%o3
/* 0x0aa8	     */		sub	%o0,%g2,%o0
/* 0x0aac	     */		add	%o0,%o5,%o5
/* 0x0ab0	     */		and	%o5,%o4,%g2
/* 0x0ab4	     */		ld	[%o3-4],%o0
/* 0x0ab8	     */		st	%g2,[%o3-8]
/* 0x0abc	     */		ble,pt	%icc,.L900000636
/* 0x0ac0	     */		srax	%o5,32,%o5
                       .L900000639:
/* 0x0ac4	     */		ld	[%o2],%o1
/* 0x0ac8	     */		sub	%o0,%o1,%o0
/* 0x0acc	     */		add	%o0,%o5,%o0
/* 0x0ad0	     */		and	%o0,%o4,%o1
/* 0x0ad4	     */		st	%o1,[%o3-4]
/* 0x0ad8	     */		ret	! Result =
/* 0x0adc	     */		restore	%g0,%g0,%g0
                       .L77000288:
/* 0x0ae0	     */		ld	[%o3],%o0
                       .L900000645:
/* 0x0ae4	     */		ld	[%o2],%o1
/* 0x0ae8	     */		add	%o5,%o0,%o0
/* 0x0aec	     */		add	%g1,1,%g1
/* 0x0af0	     */		add	%o2,4,%o2
/* 0x0af4	     */		cmp	%g1,%o7
/* 0x0af8	     */		sub	%o0,%o1,%o0
/* 0x0afc	     */		and	%o0,%o4,%o1
/* 0x0b00	     */		st	%o1,[%o3]
/* 0x0b04	     */		add	%o3,4,%o3
/* 0x0b08	     */		srax	%o0,32,%o5
/* 0x0b0c	     */		ble,a,pt	%icc,.L900000645
/* 0x0b10	     */		ld	[%o3],%o0
                       .L77000224:
/* 0x0b14	     */		ret	! Result =
/* 0x0b18	     */		restore	%g0,%g0,%g0
/* 0x0b1c	   0 */		.type	mont_mulf_noconv,2
/* 0x0b1c	     */		.size	mont_mulf_noconv,(.-mont_mulf_noconv)

! Begin Disassembling Stabs
	.xstabs	".stab.index","Xa ; O ; P ; V=3.1 ; R=WorkShop Compilers 5.0 99/02/25 C 5.0 patch 107289-01",60,0,0,0	! (/tmp/acompAAAhNaOly:1)
	.xstabs	".stab.index","/home/ferenc/venus/userland/rsa; /usr/dist/pkgs/devpro,v5.0/5.x-sparc/SC5.0/bin/cc -fast -xarch=v8plus -xO5 -xstrconst -xdepend -Xa -xchip=ultra2 -KPIC -Wc,-Qrm-Qd -Wc,-Qrm-Qf -Wc,-assembly -V -c proba.il -o mont_mulf.o  mont_mulf.c -W0,-xp",52,0,0,0	! (/tmp/acompAAAhNaOly:2)
! End Disassembling Stabs

! Begin Disassembling Ident
	.ident	"cg: WorkShop Compilers 5.0 99/04/15 Compiler Common 5.0 Patch 107357-02"	! (NO SOURCE LINE)
	.ident	"acomp: WorkShop Compilers 5.0 99/02/25 C 5.0 patch 107289-01"	! (/tmp/acompAAAhNaOly:31)
! End Disassembling Ident
