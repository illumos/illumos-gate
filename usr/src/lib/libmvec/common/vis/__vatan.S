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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__vatan.S"

#include "libm.h"

	RO_DATA

! following is the C version of the ATAN algorithm
!  #include <math.h>
!  #include <stdio.h>
!  double jkatan(double *x)
!  {
!    double  f, z, ans, ansu, ansl, tmp, poly, conup, conlo, dummy;
!    int index, sign, intf, intz;
!    extern const double __vlibm_TBL_atan1[];
!    long *pf = (long *) &f, *pz = (long *) &z;
!  
!  /*    Power series  atan(x) = x + p1*x**3 + p2*x**5 + p3*x**7
!   *    Error =  -3.08254E-18   On the interval  |x| < 1/64 */
!  
!  /* define dummy names for readability.  Use parray to help compiler optimize loads */
!  #define p3    parray[0]
!  #define p2    parray[1]
!  #define p1    parray[2]
!  #define soffset      3  
!  
!    static const double parray[] = { 
!     -1.428029046844299722E-01,		/* p[3]		*/
!      1.999999917247000615E-01, 		/* p[2]		*/
!     -3.333333333329292858E-01, 		/* p[1]		*/
!      1.0, 				/* not used for p[0], though		*/
!     -1.0,				/* used to flip sign of answer 		*/
!    };
!  
!    f        = *x;				/* fetch argument		*/
!    intf     = pf[0];				/* grab upper half		*/
!    sign     = intf & 0x80000000;			/* sign of argument		*/
!    intf    ^= sign;				/* abs(upper argument)		*/
!    sign     = (unsigned) sign >> 31;		/* sign bit = 0 or 1		*/
!    pf[0]    = intf;
!  
!    if( (intf > 0x43600000) || (intf < 0x3e300000) ) /* filter out special cases */
!    {
!      if(  (intf > 0x7ff00000) || 
!        ((intf == 0x7ff00000) &&  (pf[1] !=0)) ) return (*x-*x);/* return NaN if x=NaN*/
!      if( intf < 0x3e300000 ) 			/* avoid underflow for small arg */
!      {
!        dummy = 1.0e37 + f;
!        dummy = dummy;
!        return (*x);
!      }
!      if( intf > 0x43600000 )			/* avoid underflow for big arg  */
!      {
!        index = 2;
!        f     = __vlibm_TBL_atan1[index] + __vlibm_TBL_atan1[index+1];/* pi/2 up + pi/2 low   */
!        f     = parray[soffset + sign] * f;	/* put sign bit on ans		*/
!        return (f);
!      }
!    }
!  
!    index    = 0;				/* points to 0,0 in table	*/
!    if (intf > 0x40500000)			/* if(|x| > 64               	*/
!    { f = -1.0/f;
!      index  = 2; 				/* point to pi/2 upper, lower	*/
!    }
!    else if( intf >= 0x3f900000 )		/* if |x| >= (1/64)... 		*/
!    {
!      intz   = (intf + 0x00008000) & 0x7fff0000;/* round arg, keep upper	*/
!      pz[0]  = intz;				/* store as a double (z)	*/
!      pz[1]  = 0;				/* ...lower			*/
!      f      = (f - z)/(1.0 + f*z); 		/* get reduced argument		*/
!      index  = (intz - 0x3f900000) >> 15;	/* (index >> 16) << 1)		*/
!      index += 4;				/* skip over 0,0,pi/2,pi/2	*/
!    }
!    conup    = __vlibm_TBL_atan1[index];	/* upper table 			*/
!    conlo    = __vlibm_TBL_atan1[index+1];	/* lower table 			*/
!    tmp      = f*f;
!    poly     = (f*tmp)*((p3*tmp + p2)*tmp + p1);
!    ansu     = conup + f;     			/* compute atan(f)  upper 	*/
!    ansl     = (((conup - ansu) + f) + poly) + conlo;
!    ans      = ansu + ansl;
!    ans      = parray[soffset + sign] * ans;
!    return ans;
!  }

/* 8 bytes = 1 double f.p. word */
#define WSIZE	8

	.align	32			!align with full D-cache line
.COEFFS:
	.double	0r-1.428029046844299722E-01 	!p[3]
        .double 0r1.999999917247000615E-01 	!p[2]
        .double 0r-3.333333333329292858E-01	!p[1]
        .double 0r-1.0, 			!constant -1.0
	.word   0x00008000,0x0			!for fp rounding of reduced arg
	.word   0x7fff0000,0x0			!for fp truncation
	.word	0x47900000,0			!a number close to 1.0E37
	.word   0x80000000,0x0			!mask for fp sign bit
	.word   0x3f800000,0x0			!1.0/128.0 dummy "safe" argument
	.type	.COEFFS,#object

	ENTRY(__vatan)
	save	%sp,-SA(MINFRAME)-16,%sp
	PIC_SETUP(g5)
	PIC_SET(g5,__vlibm_TBL_atan1,o4)
	PIC_SET(g5,.COEFFS,o0)
/*
   __vatan(int n, double *x, int stridex, double *y, stridey)
   computes y(i) = atan( x(i) ), for 1=1,n.  Stridex, stridey
   are the distance between x and y elements			 

	%i0    n
	%i1    address of x
	%i2    stride x
	%i3    address of y
	%i4    stride y
*/
	cmp	%i0,0			!if n <=0,
	ble,pn	%icc,.RETURN		!....then do nothing
	sll	%i2,3,%i2		!convert stride to byte count
	sll	%i4,3,%i4		!convert stride to byte count

/*  pre-load constants before beginning main loop */

	ldd	[%o0],%f58		!load p[3]
	mov	2,%i5			!argcount = 3 

	ldd	[%o0+WSIZE],%f60	!load p[2]
	add	%fp,STACK_BIAS-8,%l1		!yaddr1 = &dummy
	fzero   %f18			!ansu1 = 0

	ldd	[%o0+2*WSIZE],%f62	!load p[1]
	add	%fp,STACK_BIAS-8,%l2		!yaddr2 = &dummy
	fzero   %f12			!(poly1) = 0

	ldd 	[%o0+3*WSIZE],%f56	!-1.0 
	fzero   %f14			!tmp1 = 0

	ldd     [%o0+4*WSIZE],%f52	!load rounding mask
	fzero   %f16			!conup1 = 0

	ldd     [%o0+5*WSIZE],%f54	!load truncation mask
	fzero   %f36			!f1 = 0

	ldd	[%o0+6*WSIZE],%f50	!1.0e37
	fzero   %f38			!f2 = 0

	ldd	[%o0+7*WSIZE],%f32	!mask for sign bit

	ldd	[%o4+2*WSIZE],%f46	!pi/2 upper
	ldd	[%o4+(2*WSIZE+8)],%f48	!pi/2 lower 
	sethi	%hi(0x40500000),%l6	!64.0
	sethi	%hi(0x3f900000),%l7	!1/64.0
	mov     0,%l4			!index1 = 0
	mov     0,%l5			!index2 = 0

.MAINLOOP:

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

.LOOP0:
        deccc   %i0                     !--n
	bneg	1f
        mov	%i1,%o5			!xuse = x (delay slot)

	ba	2f
	nop				!delay slot
1:
	PIC_SET(g5,.COEFFS+8*WSIZE,o5)
	dec	%i5			!argcount--
2:
	sethi	%hi(0x80000000),%o7	!mask for sign bit
/*2 */  sethi	%hi(0x43600000),%o1	!big = 0x43600000,0
	ld	[%o5],%o0		!intf = pf[0] = f upper
	ldd     [%o4+%l5],%f26		!conup2 = __vlibm_TBL_atan1[index2]

	sethi	%hi(0x3e300000),%o2	!small = 0x3e300000,0
/*4 */  andn	%o0,%o7,%o0		!intf = fabs(intf)
	ldd 	[%o5],%f34		!f = *x into f34

	sub	%o1,%o0,%o1		!(-) if intf > big
/*6 */  sub	%o0,%o2,%o2		!(-) if intf < small
	fand 	%f34,%f32,%f40		!sign0 = sign bit 
            fmuld   %f38,%f38,%f24      !tmp2= f2*f2

/*7 */  orcc	%o1,%o2,%g0		!(-) if either true
 	bneg,pn  %icc,.SPECIAL0		!if (-) goto special cases below
	fabsd	%f34,%f34		!abs(f)  (delay slot)
	!----------------------


	sethi   %hi(0x8000),%o7		!rounding bit
/*8 */  fpadd32 %f34,%f52,%f0		!intf + 0x00008000 (again)
            faddd   %f26,%f38,%f28      !ansu2 = conup2 + f2

 	add	%o0,%o7,%o0		!intf + 0x00008000  (delay slot)
/*9*/   fand    %f0,%f54,%f0		!pz[0] = intz = (intf + 0x00008000) & 0x7fff0000 (again)
            fmuld   %f58,%f24,%f22      !p[3]*tmp2

/*10 */ sethi   %hi(0x7fff0000),%o7     !mask for rounding argument
	fmuld	%f34,%f0,%f10		!f*z
	fsubd	%f34,%f0,%f20		!f - z
          add     %o4,%l4,%l4           !base addr + index1
          fmuld   %f14,%f12,%f12        !poly1 = (f1*tmp1)*((p3*tmp1 + p2)*tmp1 + p1)
          faddd   %f16,%f36,%f16        !(conup1 - ansu1) + f1

/*12 */ and	%o0,%o7,%o0		!intz = (intf + 0x00008000) & 0x7fff0000
            faddd   %f22,%f60,%f22      !p[3]*tmp2 + p[2]
          ldd     [%l4+WSIZE],%f14      !conlo1 = __vlibm_TBL_atan1[index+1]

/*13 */ sub	%o0,%l7,%o2		!intz - 0x3f900000
	fsubd	%f10,%f56,%f10		!(f*z - (-1.0))
          faddd   %f16,%f12,%f12        !((conup1 - ansu1) + f1) + poly1

	cmp	%o0,%l6			!(|f| > 64)
        ble	.ELSE0			!if(|f| > 64) then
/*15 */ sra	  %o2,15,%o3		!index  = (intz - 0x3f900000) >> 15
	  mov	  2,%o1			!index == 2, point to conup, conlo = pi/2 upper, lower
          ba	  .ENDIF0		!continue
/*16 */   fdivd	  %f56,%f34,%f34	!f = -1.0/f (delay slot)
        .ELSE0:				!else f( |x| >= (1/64))
	cmp	%o0,%l7			!if intf >= 1/64
	bl  	.ENDIF0			!if( |x| >= (1/64) ) then...
	mov	0,%o1			!index == 0 , point to conup,conlo = 0,0
          add	  %o3,4,%o1		!index = index + 4
/*16 */   fdivd	  %f20,%f10,%f34	!f = (f - z)/(1.0 + f*z), reduced argument
	.ENDIF0:

/*17*/  sll	%o1,3,%l3		!index0 = index
	mov	%i3,%l0			!yaddr0 = address of y
          faddd   %f12,%f14,%f12        !ansl1 = (((conup1 - ansu)1 + f1) + poly1) + conlo1
            fmuld   %f22,%f24,%f22      !(p3*tmp2 + p2)*tmp2
            fsubd   %f26,%f28,%f26      !conup2 - ansu2

/*20*/  add	%i1,%i2,%i1		!x     += stridex
        add	%i3,%i4,%i3		!y     += stridey
          faddd   %f18,%f12,%f36        !ans1 = ansu1 + ansl1
            fmuld   %f38,%f24,%f24      !f*tmp2
            faddd   %f22,%f62,%f22      !(p3*tmp2 + p2)*tmp2 + p1

/*23*/    for     %f36,%f42,%f36        !sign(ans1) = sign of argument
          std     %f36,[%l1]            !*yaddr1 = ans1
            add     %o4,%l5,%l5         !base addr + index2
            fmuld   %f24,%f22,%f22      !poly2 = (f2*tmp2)*((p3*tmp2 + p2)*tmp2 + p1)
            faddd   %f26,%f38,%f26      !(conup2 - ansu2) + f2
	cmp	%i5,0			!if argcount =0, we are done
	be	.RETURN
	  nop

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

.LOOP1:
/*25*/  deccc   %i0                     !--n
        bneg    1f
        mov     %i1,%o5                 !xuse = x (delay slot)
        ba      2f
        nop                             !delay slot
1:
	PIC_SET(g5,.COEFFS+8*WSIZE,o5)
        dec     %i5                     !argcount--
2:

/*26*/  sethi	%hi(0x80000000),%o7	!mask for sign bit
	sethi	%hi(0x43600000),%o1	!big = 0x43600000,0
	ld	[%o5],%o0		!intf = pf[0] = f upper

/*28*/  sethi	%hi(0x3e300000),%o2	!small = 0x3e300000,0
	andn	%o0,%o7,%o0		!intf = fabs(intf)
	ldd 	[%o5],%f36		!f = *x into f36

/*30*/  sub	%o1,%o0,%o1		!(-) if intf > big
	sub	%o0,%o2,%o2		!(-) if intf < small
	fand 	%f36,%f32,%f42		!sign1 = sign bit 

/*31*/  orcc	%o1,%o2,%g0		!(-) if either true
 	bneg,pn  %icc,.SPECIAL1		!if (-) goto special cases below
	fabsd	%f36,%f36		!abs(f)  (delay slot)
	!----------------------

/*32*/  fpadd32 %f36,%f52,%f0		!intf + 0x00008000 (again)
          ldd     [%l5+WSIZE],%f24      !conlo2 = __vlibm_TBL_atan1[index2+1]

/*33*/  fand    %f0,%f54,%f0		!pz[0] = intz = (intf + 0x00008000) & 0x7fff0000 (again)
        sethi   %hi(0x8000),%o7		!rounding bit
          faddd   %f26,%f22,%f22        !((conup2 - ansu2) + f2) + poly2

/*34*/  add	%o0,%o7,%o0		!intf + 0x00008000  (delay slot)
	sethi   %hi(0x7fff0000),%o7	!mask for rounding argument
	fmuld	%f36,%f0,%f10		!f*z
	fsubd	%f36,%f0,%f20		!f - z

/*35*/  and	%o0,%o7,%o0		!intz = (intf + 0x00008000) & 0x7fff0000
          faddd   %f22,%f24,%f22        !ansl2 = (((conup2 - ansu2) + f2) + poly2) + conlo2

/*37*/  sub	%o0,%l7,%o2		!intz - 0x3f900000
	fsubd	%f10,%f56,%f10		!(f*z - (-1.0))
      ldd     [%o4+%l3],%f6             !conup0 = __vlibm_TBL_atan1[index0]

        cmp	%o0,%l6			!(|f| > 64)
	ble	.ELSE1			!if(|f| > 64) then
/*38*/  sra	%o2,15,%o3		!index  = (intz - 0x3f900000) >> 15
          mov	  2,%o1			!index == 2, point to conup, conlo = pi/2 upper, lower
	  ba	  .ENDIF1		!continue
/*40*/    fdivd	  %f56,%f36,%f36	!f = -1.0/f (delay slot)
        .ELSE1:				!else f( |x| >= (1/64))
	cmp	%o0,%l7			!if intf >= 1/64
	bl  	.ENDIF1			!if( |x| >= (1/64) ) then...
	mov	0,%o1			!index == 0 , point to conup,conlo = 0,0
          add	  %o3,4,%o1		!index = index + 4
/*40*/    fdivd	  %f20,%f10,%f36	!f = (f - z)/(1.0 + f*z), reduced argument
	.ENDIF1:

/*41*/sll     %o1,3,%l4		 	!index1 = index
      mov     %i3,%l1			!yaddr1 = address of y
      fmuld   %f34,%f34,%f4             !tmp0= f0*f0
          faddd   %f28,%f22,%f38        !ans2 = ansu2 + ansl2
        
/*44*/add	%i1,%i2,%i1		!x     += stridex
      add	%i3,%i4,%i3		!y     += stridey
    fmuld   %f58,%f4,%f2                !p[3]*tmp0
    faddd   %f6,%f34,%f8                !ansu0 = conup0 + f0
          for     %f38,%f44,%f38        !sign(ans2) = sign of argument
          std     %f38,[%l2]            !*yaddr2 = ans2
          cmp	%i5,0			!if argcount =0, we are done
	  be	.RETURN
	  nop

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

.LOOP2:
/*46*/  deccc   %i0                     !--n
        bneg    1f
        mov     %i1,%o5                 !xuse = x (delay slot)
        ba      2f
        nop                             !delay slot
1:
	PIC_SET(g5,.COEFFS+8*WSIZE,o5)
        dec     %i5                     !argcount--
2:

/*47*/  sethi	%hi(0x80000000),%o7	!mask for sign bit
	sethi	%hi(0x43600000),%o1	!big = 0x43600000,0
	ld	[%o5],%o0		!intf = pf[0] = f upper

/*49*/  sethi	%hi(0x3e300000),%o2	!small = 0x3e300000,0
	andn	%o0,%o7,%o0		!intf = fabs(intf)
	ldd 	[%o5],%f38		!f = *x into f38

/*51*/  sub	%o1,%o0,%o1		!(-) if intf > big
	sub	%o0,%o2,%o2		!(-) if intf < small
	fand 	%f38,%f32,%f44		!sign2 = sign bit 

/*52*/  orcc	%o1,%o2,%g0		!(-) if either true
 	bneg,pn  %icc,.SPECIAL2		!if (-) goto special cases below
	fabsd	%f38,%f38		!abs(f)  (delay slot)
	!----------------------

/*53*/  fpadd32 %f38,%f52,%f0		!intf + 0x00008000 (again)
      faddd   %f2,%f60,%f2              !p[3]*tmp0 + p[2]

/*54*/  sethi   %hi(0x8000),%o7		!rounding bit
	fand    %f0,%f54,%f0		!pz[0] = intz = (intf + 0x00008000) & 0x7fff0000 (again)

/*55*/  add	%o0,%o7,%o0		!intf + 0x00008000  (delay slot)
	sethi   %hi(0x7fff0000),%o7     !mask for rounding argument
	fmuld	%f38,%f0,%f10		!f*z
	fsubd	%f38,%f0,%f20		!f - z

/*56*/  and	%o0,%o7,%o0		!intz = (intf + 0x00008000) & 0x7fff0000
      fmuld   %f2,%f4,%f2               !(p3*tmp0 + p2)*tmp0
      fsubd   %f6,%f8,%f6               !conup0 - ansu0

/*58*/  sub	%o0,%l7,%o2		!intz - 0x3f900000
	fsubd	%f10,%f56,%f10		!(f*z - (-1.0))
            ldd     [%o4+%l4],%f16      !conup1 = __vlibm_TBL_atan1[index1]

	cmp	%o0,%l6			!(|f| > 64)
	ble	.ELSE2			!if(|f| > 64) then
/*60*/  sra	%o2,15,%o3		!index  = (intz - 0x3f900000) >> 15
	  mov	  2,%o1			!index == 2, point to conup, conlo = pi/2 upper, lower
	  ba	  .ENDIF2		!continue
/*61*/    fdivd	  %f56,%f38,%f38	!f = -1.0/f (delay slot)
        .ELSE2:				!else f( |x| >= (1/64))
	cmp	%o0,%l7			!if intf >= 1/64
	bl  	.ENDIF2			!if( |x| >= (1/64) ) then...
	mov	0,%o1			!index == 0 , point to conup,conlo = 0,0
          add	  %o3,4,%o1		!index = index + 4
/*61*/    fdivd	  %f20,%f10,%f38	!f = (f - z)/(1.0 + f*z), reduced argument
	.ENDIF2:

        
/*62*/  sll	%o1,3,%l5		!index2 = index
	mov	%i3,%l2			!yaddr2 = address of y
      fmuld   %f34,%f4,%f4              !f0*tmp0
      faddd   %f2,%f62,%f2              !(p3*tmp0 + p2)*tmp0 + p1
            fmuld   %f36,%f36,%f14      !tmp1= f1*f1

/*65*/add     %o4,%l3,%l3               !base addr + index0
      fmuld   %f4,%f2,%f2               !poly0 = (f0*tmp0)*((p3*tmp0 + p2)*tmp0 + p1)
      faddd   %f6,%f34,%f6              !(conup0 - ansu0) + f0
            fmuld   %f58,%f14,%f12      !p[3]*tmp1
            faddd   %f16,%f36,%f18      !ansu1 = conup1 + f1
      ldd     [%l3+WSIZE],%f4           !conlo0 = __vlibm_TBL_atan1[index0+1]

/*68*/  add	%i1,%i2,%i1		!x     += stridex
	add	%i3,%i4,%i3		!y     += stridey
      faddd   %f6,%f2,%f2               !((conup0 - ansu0) + f0) + poly0
            faddd   %f12,%f60,%f12      !p[3]*tmp1 + p[2]

/*71*/faddd   %f2,%f4,%f2               !ansl0 = (((conup0 - ansu)0 + f0) + poly0) + conlo0
            fmuld   %f12,%f14,%f12      !(p3*tmp1 + p2)*tmp1
            fsubd   %f16,%f18,%f16      !conup1 - ansu1

/*74*/faddd   %f8,%f2,%f34              !ans0 = ansu0 + ansl0
          fmuld   %f36,%f14,%f14        !f1*tmp1
          faddd   %f12,%f62,%f12        !(p3*tmp1 + p2)*tmp1 + p1

/*77*/  for     %f34,%f40,%f34          !sign(ans0) = sign of argument
        std     %f34,[%l0]              !*yaddr0 = ans, always gets stored (delay slot)
        cmp	%i5,0			!if argcount =0, we are done
	bg	.MAINLOOP
	  nop

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

.RETURN:
	ret
	restore	%g0,%g0,%g0

    /*--------------------------------------------------------------------------*/
    /*------------SPECIAL CASE HANDLING FOR LOOP0 ------------------------------*/
    /*--------------------------------------------------------------------------*/

/* at this point
   %i1     x address
   %o0     intf
   %o2     intf - 0x3e300000
   %f34,36,38     f0,f1,f2
   %f40,42,44     sign0,sign1,sign2
*/

 	.align	32				!align on I-cache boundary
.SPECIAL0:
	orcc	%o2,%g0,%g0			!(-) if intf < 0x3e300000
	bpos	1f  				!if >=...continue
	sethi	%hi(0x7ff00000),%g1	!upper word of Inf (we use 64-bit wide int for this)
	  ba	  3f
	  faddd	  %f34,%f50,%f30		!dummy op just to generate exception (delay slot)
1:
	ld	[%o5+4],%o5			!load x lower word  
	sllx	%o0,32,%o0			!left justify intf
	sllx	%g1,32,%g1		!left justify Inf
	or	%o0,%o5,%o0			!merge in lower intf
	cmp	%o0,%g1				!if intf > 0x7ff00000 00000000
	ble,pt	%xcc,2f				!pass thru if NaN
	  nop
	  fmuld	  %f34,%f34,%f34		!...... (x*x) trigger invalid exception
	  ba      3f
	  nop
2:
	faddd	%f46,%f48,%f34			!ans = pi/2 upper + pi/2 lower 
3:   
	add	%i1,%i2,%i1			!x += stridex
	for     %f34,%f40,%f34			!sign(ans) = sign of argument
	std	%f34,[%i3]			!*y = ans
	ba	.LOOP0				!keep looping
	add	%i3,%i4,%i3			!y += stridey (delay slot)

    /*--------------------------------------------------------------------------*/
    /*-----------SPECIAL CASE HANDLING FOR LOOP1 -------------------------------*/
    /*--------------------------------------------------------------------------*/

 	.align	32				!align on I-cache boundary
.SPECIAL1:
	orcc	%o2,%g0,%g0			!(-) if intf < 0x3e300000
	bpos	1f  				!if >=...continue
	sethi	%hi(0x7ff00000),%g1	!upper word of Inf (we use 64-bit wide int for this)
	  ba	  3f
	  faddd	  %f36,%f50,%f30		!dummy op just to generate exception (delay slot)
1:
	ld	[%o5+4],%o5			!load x lower word  
	sllx	%o0,32,%o0			!left justify intf
	sllx	%g1,32,%g1		!left justify Inf
	or	%o0,%o5,%o0			!merge in lower intf
	cmp	%o0,%g1				!if intf > 0x7ff00000 00000000
	ble,pt	%xcc,2f				!pass thru if NaN
	  nop
	  fmuld	  %f36,%f36,%f36		!...... (x*x) trigger invalid exception
	  ba      3f
	  nop
2:
	faddd	%f46,%f48,%f36			!ans = pi/2 upper + pi/2 lower 
3:   
	add	%i1,%i2,%i1			!x += stridex
	for     %f36,%f42,%f36			!sign(ans) = sign of argument
	std	%f36,[%i3]			!*y = ans
	ba      .LOOP1 				!keep looping
	add	%i3,%i4,%i3			!y += stridey (delay slot)

    /*--------------------------------------------------------------------------*/
    /*------------SPECIAL CASE HANDLING FOR LOOP2 ------------------------------*/
    /*--------------------------------------------------------------------------*/

 	.align	32				!align on I-cache boundary
.SPECIAL2:
	orcc	%o2,%g0,%g0			!(-) if intf < 0x3e300000
	bpos	1f  				!if >=...continue
	sethi	%hi(0x7ff00000),%g1	!upper word of Inf (we use 64-bit wide int for this)
	  ba	  3f
	  faddd	  %f38,%f50,%f30		!dummy op just to generate exception (delay slot)
1:
	ld	[%o5+4],%o5			!load x lower word  
	sllx	%o0,32,%o0			!left justify intf
	sllx	%g1,32,%g1		!left justify Inf
	or	%o0,%o5,%o0			!merge in lower intf
	cmp	%o0,%g1				!if intf > 0x7ff00000 00000000
	ble,pt	%xcc,2f				!pass thru if NaN
	  nop
	  fmuld	  %f38,%f38,%f38		!...... (x*x) trigger invalid exception
	  ba      3f
	  nop
2:
	faddd	%f46,%f48,%f38			!ans = pi/2 upper + pi/2 lower 
3:   
	add	%i1,%i2,%i1			!x += stridex
	for     %f38,%f44,%f38			!sign(ans) = sign of argument
	std	%f38,[%i3]			!*y = ans
	ba      .LOOP2 				!keep looping
	add	%i3,%i4,%i3			!y += stridey

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

	SET_SIZE(__vatan)

!	.ident	"03-20-96 Sparc V9 3-way-unrolled version"
