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

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

void
__vatanf(int n, float * restrict x, int stridex, float * restrict y, int stridey)
{
  extern const double __vlibm_TBL_atan1[];
  double  conup0, conup1, conup2;
  float dummy, ansf = 0.0;
  float f0, f1, f2;
  float ans0, ans1, ans2;
  float poly0, poly1, poly2;
  float sign0, sign1, sign2;
  int intf, intz, argcount;
  int index0, index1, index2; 
  float z,*yaddr0,*yaddr1,*yaddr2;
  int *pz = (int *) &z;
#ifdef UNROLL4
  double conup3;
  int index3;
  float f3, ans3, poly3, sign3, *yaddr3;
#endif

/*    Power series  atan(x) = x + p1*x**3 + p2*x**5 + p3*x**7
 *    Error =  -3.08254E-18   On the interval  |x| < 1/64 */

  static const float p1 = -0.33329644f /* -3.333333333329292858E-01f */ ;
  static const float pone = 1.0f;

  if (n <= 0) return;		/* if no. of elements is 0 or neg, do nothing */
  do
  {
  LOOP0:

	intf     = *(int *) x;		/* upper half of x, as integer */
	f0 = *x;
	sign0 = pone;
    	if (intf < 0) {
    		intf = intf & ~0x80000000; /* abs(upper argument) */
		f0 = -f0;
		sign0 = -sign0;
	}
  
    if ((intf > 0x5B000000) || (intf < 0x31800000)) /* filter out special cases */
    {
      if (intf > 0x7f800000) 
      {  
	ansf  = f0- f0; 				/* return NaN if x=NaN*/
      }
      else if (intf < 0x31800000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f0;
        dummy = dummy;
	ansf  = f0;
      }
      else if (intf > 0x5B000000)		/* avoid underflow for big arg  */
      {
        index0= 2;
        ansf  = __vlibm_TBL_atan1[index0];/* pi/2 up */
      }
      *y      = sign0*ansf;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 0;				/* initialize argcount		*/
      if (--n <=0) break;			/* we are done 			*/
      goto LOOP0;				/* otherwise, examine next arg  */
    }
  
    if (intf > 0x42800000)			/* if (|x| > 64               	*/
    { 
    f0 = -pone/f0;
	index0 = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3C800000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00040000) & 0x7ff80000;/* round arg, keep upper	*/
      pz[0]  = intz;				/* store as a float (z)		*/
    f0 = (f0 - z)/(pone + f0*z);
	index0 = (intz - 0x3C800000) >> 18;	/* (index >> 19) << 1)		*/
	index0 = index0+ 4;			/* skip over 0,0,pi/2,pi/2	*/
    } 
    else					/* |x| < 1/64 */
    {
	index0   = 0;				/* points to 0,0 in table	*/
    }
    yaddr0   = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 1;				/* we now have 1 good argument  */
    if (--n <=0) 
    {
      goto UNROLL;				/* finish up with 1 good arg 	*/
    }

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

  LOOP1:

	intf     = *(int *) x;		/* upper half of x, as integer */
	f1 = *x;
	sign1 = pone;
    	if (intf < 0) {
    		intf = intf & ~0x80000000; /* abs(upper argument) */
		f1 = -f1;
		sign1 = -sign1;
	}
  
    if ((intf > 0x5B000000) || (intf < 0x31800000)) /* filter out special cases */
    {
      if (intf > 0x7f800000) 
      {  
	ansf   = f1 - f1;			/* return NaN if x=NaN*/
      }
      else if (intf < 0x31800000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f1;
        dummy = dummy;
	ansf   = f1;
      }
      else if (intf > 0x5B000000)		/* avoid underflow for big arg  */
      {
        index1 = 2;
        ansf   = __vlibm_TBL_atan1[index1] ;/* pi/2 up */
      }
      *y      = sign1 * ansf;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 1;				/* we still have 1 good arg 	*/
      if (--n <=0) 
      {
        goto UNROLL;				/* finish up with 1 good arg 	*/
      }
      goto LOOP1;				/* otherwise, examine next arg  */
    }
  
    if (intf > 0x42800000)			/* if (|x| > 64               	*/
    { 
    f1 = -pone/f1;
      index1 = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3C800000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00040000) & 0x7ff80000;/* round arg, keep upper	*/
      pz[0]  = intz;				/* store as a float (z)		*/
    f1 = (f1 - z)/(pone + f1*z); 
      index1 = (intz - 0x3C800000) >> 18;	/* (index >> 19) << 1)		*/
      index1 = index1 + 4;			/* skip over 0,0,pi/2,pi/2	*/
    }
    else
    {
	index1   = 0;				/* points to 0,0 in table	*/
    }

    yaddr1   = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 2;				/* we now have 2 good arguments */
    if (--n <=0) 
    {
      goto UNROLL;				/* finish up with 2 good args 	*/
    }

    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

  LOOP2:

	intf     = *(int *) x;		/* upper half of x, as integer */
	f2 = *x;
	sign2 = pone;
    	if (intf < 0) {
    		intf = intf & ~0x80000000; /* abs(upper argument) */
		f2 = -f2;
		sign2 = -sign2;
	}
  
    if ((intf > 0x5B000000) || (intf < 0x31800000)) /* filter out special cases */
    {
      if (intf > 0x7f800000) 
      {  
	ansf   = f2 - f2;			/* return NaN if x=NaN*/
      }
      else if (intf < 0x31800000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f2;
        dummy = dummy;
	ansf   = f2;
      }
      else if (intf > 0x5B000000)		/* avoid underflow for big arg  */
      {
        index2 = 2;
        ansf   = __vlibm_TBL_atan1[index2] ;/* pi/2 up */
      }
      *y      = sign2 * ansf;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 2;				/* we still have 2 good args 	*/
      if (--n <=0) 
      {
        goto UNROLL;				/* finish up with 2 good args 	*/
      }
      goto LOOP2;				/* otherwise, examine next arg  */
    }
  
    if (intf > 0x42800000)			/* if (|x| > 64               	*/
    { 
    f2 = -pone/f2;
      index2 = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3C800000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00040000) & 0x7ff80000;/* round arg, keep upper	*/
      pz[0]  = intz;				/* store as a float (z)		*/
    f2 = (f2 - z)/(pone + f2*z);
      index2 = (intz - 0x3C800000) >> 18;	/* (index >> 19) << 1)		*/
      index2 = index2 + 4;			/* skip over 0,0,pi/2,pi/2	*/
    }
    else
    {
	index2   = 0;				/* points to 0,0 in table	*/
    }
    yaddr2   = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 3;				/* we now have 3 good arguments */
    if (--n <=0) 
    {
      goto UNROLL;				/* finish up with 2 good args 	*/
    }


    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/
    /*--------------------------------------------------------------------------*/

#ifdef UNROLL4
  LOOP3:

	intf     = *(int *) x;		/* upper half of x, as integer */
	f3 = *x;
	sign3 = pone;
    	if (intf < 0) {
    		intf = intf & ~0x80000000; /* abs(upper argument) */
		f3 = -f3;
		sign3 = -sign3;
	}
  
    if ((intf > 0x5B000000) || (intf < 0x31800000)) /* filter out special cases */
    {
      if (intf > 0x7f800000) 
      {  
	ansf   = f3 - f3;			/* return NaN if x=NaN*/
      }
      else if (intf < 0x31800000) 		/* avoid underflow for small arg */
      {
        dummy = 1.0e37 + f3;
        dummy = dummy;
	ansf   = f3;
      }
      else if (intf > 0x5B000000)		/* avoid underflow for big arg  */
      {
        index3 = 2;
        ansf   = __vlibm_TBL_atan1[index3] ;/* pi/2 up */
      }
      *y      = sign3 * ansf;		/* store answer, with sign bit 	*/
      x      += stridex;
      y      += stridey;
      argcount = 3;				/* we still have 3 good args 	*/
      if (--n <=0) 
      {
        goto UNROLL;				/* finish up with 3 good args 	*/
      }
      goto LOOP3;				/* otherwise, examine next arg  */
    }
  
    if (intf > 0x42800000)			/* if (|x| > 64               	*/
    { 
	n3 = -pone;
        d3 = f3;
    f3 = n3/d3;
      index3 = 2; 				/* point to pi/2 upper, lower	*/
    }
    else if (intf >= 0x3C800000)		/* if |x| >= (1/64)... 		*/
    {
      intz   = (intf + 0x00040000) & 0x7ff80000;/* round arg, keep upper	*/
      pz[0]  = intz;				/* store as a float (z)		*/
	n3     = (f3 - z);
	d3     = (pone + f3*z); 		/* get reduced argument		*/
    f3 = n3/d3;
      index3 = (intz - 0x3C800000) >> 18;	/* (index >> 19) << 1)		*/
      index3 = index3 + 4;			/* skip over 0,0,pi/2,pi/2	*/
    }
    else
    {
	n3 = f3;
	d3 = pone;
	index3   = 0;				/* points to 0,0 in table	*/
    }
    yaddr3   = y;				/* address to store this answer */ 
    x       += stridex;				/* point to next arg		*/
    y       += stridey;				/* point to next result		*/
    argcount = 4;				/* we now have 4 good arguments */
    if (--n <=0) 
    {
      goto UNROLL;				/* finish up with 3 good args 	*/
    }
#endif /* UNROLL4 */

/* here is the n-way unrolled section, 
   but we may actually have less than n 
   arguments at this point
*/

UNROLL:

#ifdef UNROLL4
    if (argcount == 4)
    {
    conup0   = __vlibm_TBL_atan1[index0];
    conup1   = __vlibm_TBL_atan1[index1];
    conup2   = __vlibm_TBL_atan1[index2];
    conup3   = __vlibm_TBL_atan1[index3];
    poly0    = p1*f0*f0*f0 + f0;
    ans0     = sign0 * (float)(conup0 + poly0);
    poly1    = p1*f1*f1*f1 + f1;
    ans1     = sign1 * (float)(conup1 + poly1);
    poly2    = p1*f2*f2*f2 + f2;
    ans2     = sign2 * (float)(conup2 + poly2);
    poly3    = p1*f3*f3*f3 + f3;
    ans3     = sign3 * (float)(conup3 + poly3);
    *yaddr0  = ans0;
    *yaddr1  = ans1;
    *yaddr2  = ans2;
    *yaddr3  = ans3;
    }
    else 
#endif
    if (argcount == 3)
    {
    conup0   = __vlibm_TBL_atan1[index0];
    conup1   = __vlibm_TBL_atan1[index1];
    conup2   = __vlibm_TBL_atan1[index2];
    poly0    = p1*f0*f0*f0 + f0;
    poly1    = p1*f1*f1*f1 + f1;
    poly2    = p1*f2*f2*f2 + f2;
    ans0     = sign0 * (float)(conup0 + poly0);
    ans1     = sign1 * (float)(conup1 + poly1);
    ans2     = sign2 * (float)(conup2 + poly2);
    *yaddr0  = ans0;
    *yaddr1  = ans1;
    *yaddr2  = ans2;
    }
    else 
    if (argcount == 2)
    {
    conup0   = __vlibm_TBL_atan1[index0];
    conup1   = __vlibm_TBL_atan1[index1];
    poly0    = p1*f0*f0*f0 + f0;
    poly1    = p1*f1*f1*f1 + f1;
    ans0     = sign0 * (float)(conup0 + poly0);
    ans1     = sign1 * (float)(conup1 + poly1);
    *yaddr0  = ans0;
    *yaddr1  = ans1;
    }
    else 
    if (argcount == 1)
    {
    conup0   = __vlibm_TBL_atan1[index0];
    poly0    = p1*f0*f0*f0 + f0;
    ans0     = sign0 * (float)(conup0 + poly0);
    *yaddr0  = ans0;
     }

  }  while (n > 0);

}
