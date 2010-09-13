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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

#include "_Qquad.h"
#include "_Qglobals.h"


void
_fp_mul(px, py, pz)
	unpacked       *px, *py, *pz;

{
	unpacked       *pt;
	unsigned       acc[4];		/* Product accumulator. */
	unsigned       i,j,y,*x,s,r,c;

	if ((int) px->fpclass < (int) py->fpclass) {
		pt = px;
		px = py;
		py = pt;
	}
	/* Now class(x) >= class(y).  */

	*pz = *px;
	pz->sign = px->sign ^ py->sign;

	switch (px->fpclass) {
	case fp_quiet:
	case fp_signaling:
	case fp_zero:
		return;
	case fp_infinity:
		if (py->fpclass == fp_zero) {
			fpu_error_nan(pz);
			pz->fpclass = fp_quiet;
		}
		return;
	case fp_normal:
		if (py->fpclass == fp_zero) {
			pz->fpclass = fp_zero;
			return;
		}
	}

	/* Now x and y are both normal or subnormal. */

	x = px->significand;	/* save typing */

	s=r=acc[0]=acc[1]=acc[2]=acc[3]=0;	/* intialize acc to zero */

	y = py->significand[3];		/* py->significand[3] * x */
	if(y!=0) { 
	    j=1;
	    do {
		s |= r;		/* shift acc right one bit */
		r  = acc[3]&1;
		acc[3] = ((acc[2]&1)<<31)|(acc[3]>>1);
		acc[2] = ((acc[1]&1)<<31)|(acc[2]>>1);
		acc[1] = ((acc[0]&1)<<31)|(acc[1]>>1);
		acc[0] = (acc[0]>>1);
		if(j&y) {		/* bit i of y != 0, add x to acc */
			c = 0;
			c = fpu_add3wc(&acc[3],acc[3],x[3],c);
			c = fpu_add3wc(&acc[2],acc[2],x[2],c);
			c = fpu_add3wc(&acc[1],acc[1],x[1],c);
			c = fpu_add3wc(&acc[0],acc[0],x[0],c);
		}
		j += j;
	    } while (j!=0);
	} 

	y = py->significand[2];		/* py->significand[2] * x */
	if(y!=0) { 
	    j=1;
	    do {
		s |= r;		/* shift acc right one bit */
		r  = acc[3]&1;
		acc[3] = ((acc[2]&1)<<31)|(acc[3]>>1);
		acc[2] = ((acc[1]&1)<<31)|(acc[2]>>1);
		acc[1] = ((acc[0]&1)<<31)|(acc[1]>>1);
		acc[0] = (acc[0]>>1);
		if(j&y) {		/* bit i of y != 0, add x to acc */
			c = 0;
			c = fpu_add3wc(&acc[3],acc[3],x[3],c);
			c = fpu_add3wc(&acc[2],acc[2],x[2],c);
			c = fpu_add3wc(&acc[1],acc[1],x[1],c);
			c = fpu_add3wc(&acc[0],acc[0],x[0],c);
		}
		j += j;
	    } while (j!=0);
	} else {
		s |= r|(acc[3]&0x7fffffff);
		r  = (acc[3]&0x80000000)>>31;
		acc[3]=acc[2];acc[2]=acc[1];acc[1]=acc[0];acc[0]=0;
	}

	y = py->significand[1];		/* py->significand[1] * x */
	if(y!=0) { 
	    j=1;
	    do {
		s |= r;		/* shift acc right one bit */
		r  = acc[3]&1;
		acc[3] = ((acc[2]&1)<<31)|(acc[3]>>1);
		acc[2] = ((acc[1]&1)<<31)|(acc[2]>>1);
		acc[1] = ((acc[0]&1)<<31)|(acc[1]>>1);
		acc[0] = (acc[0]>>1);
		if(j&y) {		/* bit i of y != 0, add x to acc */
			c = 0;
			c = fpu_add3wc(&acc[3],acc[3],x[3],c);
			c = fpu_add3wc(&acc[2],acc[2],x[2],c);
			c = fpu_add3wc(&acc[1],acc[1],x[1],c);
			c = fpu_add3wc(&acc[0],acc[0],x[0],c);
		}
		j += j;
	    } while (j!=0);
	} else {
		s |= r|(acc[3]&0x7fffffff);
		r  = (acc[3]&0x80000000)>>31;
		acc[3]=acc[2];acc[2]=acc[1];acc[1]=acc[0];acc[0]=0;
	}

    					/* py->significand[0] * x */
	y = py->significand[0];		/* y is of form 0x0001???? */
	j=1;
	do {
		s |= r;		/* shift acc right one bit */
		r  = acc[3]&1;
		acc[3] = ((acc[2]&1)<<31)|(acc[3]>>1);
		acc[2] = ((acc[1]&1)<<31)|(acc[2]>>1);
		acc[1] = ((acc[0]&1)<<31)|(acc[1]>>1);
		acc[0] = (acc[0]>>1);
		if(j&y) {		/* bit i of y != 0, add x to acc */
			c = 0;
			c = fpu_add3wc(&acc[3],acc[3],x[3],c);
			c = fpu_add3wc(&acc[2],acc[2],x[2],c);
			c = fpu_add3wc(&acc[1],acc[1],x[1],c);
			c = fpu_add3wc(&acc[0],acc[0],x[0],c);
		}
		j += j;
	} while (j<=y);

	if(acc[0]>=0x20000) {	/* right shift one bit to normalize */
		pz->exponent = px->exponent + py->exponent + 1;
		pz->sticky = s|r;
		pz->rounded = acc[3]&1;
		pz->significand[3]=((acc[2]&1)<<31)|(acc[3]>>1);
		pz->significand[2]=((acc[1]&1)<<31)|(acc[2]>>1);
		pz->significand[1]=((acc[0]&1)<<31)|(acc[1]>>1);
		pz->significand[0]=(acc[0]>>1);
	} else {
		pz->exponent = px->exponent + py->exponent;
		pz->sticky = s;
		pz->rounded = r;
		pz->significand[3]=acc[3];
		pz->significand[2]=acc[2];
		pz->significand[1]=acc[1];
		pz->significand[0]=acc[0];
	}
}
