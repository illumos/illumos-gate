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

#include <sys/isa_defs.h>
#include "libm_inlines.h"

#ifdef _LITTLE_ENDIAN
#define HI(x)	*(1+(int*)x)
#define LO(x)	*(unsigned*)x
#else
#define HI(x)	*(int*)x
#define LO(x)	*(1+(unsigned*)x)
#endif

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

void
__vatan(int n, double * restrict x, int stridex, double * restrict y, int stridey)
{
  double  f, z, ans = 0.0L, ansu, ansl, tmp, poly, conup, conlo, dummy;
  double  f1,   ans1, ansu1, ansl1, tmp1, poly1, conup1, conlo1;
  double  f2,   ans2, ansu2, ansl2, tmp2, poly2, conup2, conlo2;
  int index, sign, intf, intflo, intz, argcount;
  int index1, sign1 = 0;
  int index2, sign2 = 0;
  double *yaddr,*yaddr1 = 0,*yaddr2 = 0;
  extern const double __vlibm_TBL_atan1[];
  extern double fabs(double);

/*    Power series  atan(x) = x + p1*x**3 + p2*x**5 + p3*x**7
 *    Error =  -3.08254E-18   On the interval  |x| < 1/64 */

/* define dummy names for readability.  Use parray to help compiler optimize loads */
#define p3    parray[0]
#define p2    parray[1]
#define p1    parray[2]

  static const double parray[] = { 
   -1.428029046844299722E-01,		/* p[3]		*/
    1.999999917247000615E-01, 		/* p[2]		*/
   -3.333333333329292858E-01, 		/* p[1]		*/
    1.0, 				/* not used for p[0], though		*/
   -1.0,				/* used to flip sign of answer 		*/
  };

  if (n <= 0) return;		/* if no. of elements is 0 or neg, do nothing */
  do
  {
  LOOP0:

    f        = fabs(*x);			/* fetch argument		*/
    intf     = HI(x);			/* upper half of x, as integer	*/
    intflo   = LO(x);			/* lower half of x, as integer	*/
    sign     = intf &  0x80000000;		/* sign of argument		*/
    intf     = intf & ~0x80000000;		/* abs(upper argument)		*/
  
    if ((intf > 0x43600000) || (intf < 0x3e300000)) /* filter out special cases */
    {
      if ( (intf > 0x7ff00000) || ((intf == 0x7ff00000) &&  (intflo !=0))) 
      {  
	ans   = f - f; 				/* return NaN if x=NaN*/
      }
      else if (intf < 0x3e300000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f;
        dummy = dummy;
	ans   = f;
      }
      else if (intf > 0x43600000)		/* avoid underflow for big arg  */
      {
        index = 2;
        ans   = __vlibm_TBL_atan1[index] + __vlibm_TBL_atan1[index+1];/* pi/2 up + pi/2 low   */
      }
      *y      = (sign) ? -ans: ans;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 0;				/* initialize argcount		*/
      if (--n <=0) break;			/* we are done 			*/
      goto LOOP0;				/* otherwise, examine next arg  */
    }
  
    index    = 0;				/* points to 0,0 in table	*/
    if (intf > 0x40500000)			/* if (|x| > 64               	*/
    { f = -1.0/f;
      index  = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3f900000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00008000) & 0x7fff0000;/* round arg, keep upper	*/
      HI(&z)  = intz;				/* store as a double (z)	*/
      LO(&z)  = 0;				/* ...lower			*/
      f      = (f - z)/(1.0 + f*z); 		/* get reduced argument		*/
      index  = (intz - 0x3f900000) >> 15;	/* (index >> 16) << 1)		*/
      index  = index + 4;			/* skip over 0,0,pi/2,pi/2	*/
    }
    yaddr    = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 1;				/* we now have 1 good argument  */
    if (--n <=0) 
    {
      f1      = 0.0;				/* put dummy values in args 1,2 */
      f2      = 0.0;
      index1  = 0;
      index2  = 0;
      goto UNROLL3;				/* finish up with 1 good arg 	*/
    }

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

  LOOP1:

    f1       = fabs(*x);			/* fetch argument		*/
    intf     = HI(x);			/* upper half of x, as integer	*/
    intflo   = LO(x);			/* lower half of x, as integer	*/
    sign1    = intf &  0x80000000;		/* sign of argument		*/
    intf     = intf & ~0x80000000;		/* abs(upper argument)		*/
  
    if ((intf > 0x43600000) || (intf < 0x3e300000)) /* filter out special cases */
    {
      if ( (intf > 0x7ff00000) || ((intf == 0x7ff00000) &&  (intflo !=0))) 
      {  
	ans   = f1 - f1;			/* return NaN if x=NaN*/
      }
      else if (intf < 0x3e300000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f1;
        dummy = dummy;
	ans   = f1;
      }
      else if (intf > 0x43600000)		/* avoid underflow for big arg  */
      {
        index1 = 2;
        ans   = __vlibm_TBL_atan1[index1] + __vlibm_TBL_atan1[index1+1];/* pi/2 up + pi/2 low   */
      }
      *y      = (sign1) ? -ans: ans;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 1;				/* we still have 1 good arg 	*/
      if (--n <=0) 
      {
        f1      = 0.0;				/* put dummy values in args 1,2 */
        f2      = 0.0;
        index1  = 0;
        index2  = 0;
        goto UNROLL3;				/* finish up with 1 good arg 	*/
      }
      goto LOOP1;				/* otherwise, examine next arg  */
    }
  
    index1   = 0;				/* points to 0,0 in table	*/
    if (intf > 0x40500000)			/* if (|x| > 64               	*/
    { f1 = -1.0/f1;
      index1 = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3f900000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00008000) & 0x7fff0000;/* round arg, keep upper	*/
      HI(&z) = intz;				/* store as a double (z)	*/
      LO(&z) = 0;				/* ...lower			*/
      f1     = (f1 - z)/(1.0 + f1*z); 		/* get reduced argument		*/
      index1 = (intz - 0x3f900000) >> 15;	/* (index >> 16) << 1)		*/
      index1 = index1 + 4;			/* skip over 0,0,pi/2,pi/2	*/
    }
    yaddr1   = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 2;				/* we now have 2 good arguments */
    if (--n <=0) 
    {
      f2      = 0.0;				/* put dummy value in arg 2 */
      index2  = 0;
      goto UNROLL3;				/* finish up with 2 good args 	*/
    }

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

  LOOP2:

    f2       = fabs(*x);			/* fetch argument		*/
    intf     = HI(x);			/* upper half of x, as integer	*/
    intflo   = LO(x);			/* lower half of x, as integer	*/
    sign2    = intf &  0x80000000;		/* sign of argument		*/
    intf     = intf & ~0x80000000;		/* abs(upper argument)		*/
  
    if ((intf > 0x43600000) || (intf < 0x3e300000)) /* filter out special cases */
    {
      if ( (intf > 0x7ff00000) || ((intf == 0x7ff00000) &&  (intflo !=0))) 
      {  
	ans   = f2 - f2;			/* return NaN if x=NaN*/
      }
      else if (intf < 0x3e300000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f2;
        dummy = dummy;
	ans   = f2;
      }
      else if (intf > 0x43600000)		/* avoid underflow for big arg  */
      {
        index2 = 2;
        ans   = __vlibm_TBL_atan1[index2] + __vlibm_TBL_atan1[index2+1];/* pi/2 up + pi/2 low   */
      }
      *y      = (sign2) ? -ans: ans;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 2;				/* we still have 2 good args 	*/
      if (--n <=0) 
      {
        f2      = 0.0;				/* put dummy value in arg 2 */
        index2  = 0;
        goto UNROLL3;				/* finish up with 2 good args 	*/
      }
      goto LOOP2;				/* otherwise, examine next arg  */
    }
  
    index2   = 0;				/* points to 0,0 in table	*/
    if (intf > 0x40500000)			/* if (|x| > 64               	*/
    { f2 = -1.0/f2;
      index2 = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3f900000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00008000) & 0x7fff0000;/* round arg, keep upper	*/
      HI(&z) = intz;				/* store as a double (z)	*/
      LO(&z) = 0;				/* ...lower			*/
      f2     = (f2 - z)/(1.0 + f2*z); 		/* get reduced argument		*/
      index2 = (intz - 0x3f900000) >> 15;	/* (index >> 16) << 1)		*/
      index2 = index2 + 4;			/* skip over 0,0,pi/2,pi/2	*/
    }
    yaddr2   = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 3;				/* we now have 3 good arguments */


/* here is the 3 way unrolled section, 
   note, we may actually only have 
   1,2, or 3 'real' arguments at this point
*/

UNROLL3:

    conup    = __vlibm_TBL_atan1[index ];	/* upper table 			*/
    conup1   = __vlibm_TBL_atan1[index1];	/* upper table 			*/
    conup2   = __vlibm_TBL_atan1[index2];	/* upper table 			*/

    conlo    = __vlibm_TBL_atan1[index +1];	/* lower table 			*/
    conlo1   = __vlibm_TBL_atan1[index1+1];	/* lower table 			*/
    conlo2   = __vlibm_TBL_atan1[index2+1];	/* lower table 			*/

    tmp      = f *f ;
    tmp1     = f1*f1;
    tmp2     = f2*f2;

    poly     = f *((p3*tmp  + p2)*tmp  + p1)*tmp ;
    poly1    = f1*((p3*tmp1 + p2)*tmp1 + p1)*tmp1;
    poly2    = f2*((p3*tmp2 + p2)*tmp2 + p1)*tmp2;

    ansu     = conup  + f ;    			/* compute atan(f)  upper 	*/
    ansu1    = conup1 + f1;    			/* compute atan(f)  upper 	*/
    ansu2    = conup2 + f2;    			/* compute atan(f)  upper 	*/

    ansl     = (((conup  - ansu) + f) + poly) + conlo ;
    ansl1    = (((conup1 - ansu1) + f1) + poly1) + conlo1;
    ansl2    = (((conup2 - ansu2) + f2) + poly2) + conlo2;

    ans      = ansu  + ansl ;
    ans1     = ansu1 + ansl1;
    ans2     = ansu2 + ansl2;

/* now check to see if these are 'real' or 'dummy' arguments BEFORE storing */

   *yaddr    = sign ? -ans: ans;		/* this one is always good	*/
   if (argcount < 3) break;			/* end loop and finish up 	*/
     *yaddr1   = sign1 ? -ans1: ans1;
     *yaddr2   = sign2 ? -ans2: ans2;

  }  while (--n > 0);

 if (argcount == 2) 
   {  *yaddr1  = sign1 ? -ans1: ans1;
   }
}
