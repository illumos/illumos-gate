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

/* Unpack procedures for Sparc FPU simulator. */

#include "_Qquad.h"
#include "_Qglobals.h"

PRIVATE void
unpackinteger(pu, x)
	unpacked       *pu;	/* unpacked result */
	int             x;	/* packed integer */
{
	unsigned ux;
	pu->sticky = pu->rounded = 0;
	if (x == 0) {
		pu->sign = 0;
		pu->fpclass = fp_zero;
	} else {
		(*pu).sign = x < 0;
		(*pu).fpclass = fp_normal;
		(*pu).exponent = INTEGER_BIAS;
		if(x<0) ux = -x; else ux = x;
		(*pu).significand[0] = ux>>15;
		(*pu).significand[1] = (ux&0x7fff)<<17;
		(*pu).significand[2] = 0;
		(*pu).significand[3] = 0;
		fpu_normalize(pu);
	}
}

void
unpacksingle(pu, x)
	unpacked       *pu;	/* unpacked result */
	single_type     x;	/* packed single */
{
	unsigned u;
	pu->sticky = pu->rounded = 0;
	u = x.significand;
	(*pu).sign = x.sign;
	pu->significand[1] = 0;
	pu->significand[2] = 0;
	pu->significand[3] = 0;
	if (x.exponent == 0) {	/* zero or sub */
		if (x.significand == 0) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {	/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = -SINGLE_BIAS-6;
			pu->significand[0]=u;
			fpu_normalize(pu);
			return;
		}
	} else if (x.exponent == 0xff) {	/* inf or nan */
		if (x.significand == 0) {	/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {	/* nan */
			if ((u & 0x400000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_signaling;
				fpu_set_exception(fp_invalid);
			}
			pu->significand[0] = 0x18000 | (u >> 7);
			(*pu).significand[1]=((u&0x7f)<<25);
			return;
		}
	}
	(*pu).exponent = x.exponent - SINGLE_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0]=0x10000|(u>>7);
	(*pu).significand[1]=((u&0x7f)<<25);
}

void
unpackdouble(pu, x, y)
	unpacked       *pu;	/* unpacked result */
	double_type     x;	/* packed double */
	unsigned        y;
{
	unsigned u;
	pu->sticky = pu->rounded = 0;
	u = x.significand;
	(*pu).sign = x.sign;
	pu->significand[1] = y;
	pu->significand[2] = 0;
	pu->significand[3] = 0;
	if (x.exponent == 0) {	/* zero or sub */
		if ((x.significand == 0) && (y == 0)) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {	/* subnormal */
			pu->fpclass = fp_normal;
			pu->exponent = -DOUBLE_BIAS-3;
			pu->significand[0] = u;
			fpu_normalize(pu);
			return;
		}
	} else if (x.exponent == 0x7ff) {	/* inf or nan */
		if ((u|y) == 0) {	/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {	/* nan */
			if ((u & 0x80000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_signaling;
				fpu_set_exception(fp_invalid);
			}
			pu->significand[0] = 0x18000 | (u >> 4);
			(*pu).significand[1]=((u&0xf)<<28)|(y>>4);
			(*pu).significand[2]=((y&0xf)<<28);
			return;
		}
	}
	(*pu).exponent = x.exponent - DOUBLE_BIAS;
	(*pu).fpclass = fp_normal;
	(*pu).significand[0]=0x10000|(u>>4);
	(*pu).significand[1]=((u&0xf)<<28)|(y>>4);
	(*pu).significand[2]=((y&0xf)<<28);
}

PRIVATE void
unpackextended(pu, x, y, z, w)
	unpacked       *pu;	/* unpacked result */
	extended_type   x;	/* packed extended */
	unsigned        y, z, w;
{
	unsigned u;
	pu->sticky = pu->rounded = 0;
	u = x.significand;
	(*pu).sign = x.sign;
	(*pu).fpclass = fp_normal;
	(*pu).exponent = x.exponent - EXTENDED_BIAS;
	(*pu).significand[0] = (x.exponent==0)? u:0x10000|u;
	(*pu).significand[1] = y;
	(*pu).significand[2] = z;
	(*pu).significand[3] = w;
	if (x.exponent < 0x7fff) {	/* zero, normal, or subnormal */
		if ((z|y|w|pu->significand[0]) == 0) {	/* zero */
			pu->fpclass = fp_zero;
			return;
		} else {	/* normal or subnormal */
			if(x.exponent==0) {
				fpu_normalize(pu);
				pu->exponent += 1;
			}
			return;
		}
	} else {	/* inf or nan */
		if ((u|z|y|w) == 0) {	/* inf */
			pu->fpclass = fp_infinity;
			return;
		} else {	/* nan */
			if ((u & 0x00008000) != 0) {	/* quiet */
				pu->fpclass = fp_quiet;
			} else {/* signaling */
				pu->fpclass = fp_signaling;
				fpu_set_exception(fp_invalid);
			}
			pu->significand[0] |= 0x8000; /* make quiet */
			return;
		}
}
}

void
_fp_unpack(pu, n, dtype)
	unpacked       *pu;	/* unpacked result */
	int        	*n;	/* input array */
	enum fp_op_type dtype;	/* type of datum */

{
	switch ((int) dtype) {
	case fp_op_integer:
		unpackinteger(pu, n[0]);
		break;
	case fp_op_single:
		{
			single_type x;
			*(int*)&x = n[0];
			unpacksingle(pu, x);
			break;
		}
	case fp_op_double:
		{ 	
			double_type x;
			double t=1.0; int i0,i1;
			if((*(int*)&t)!=0) {i0=0;i1=1;} else {i0=1;i1=0;}
			*(int*)&x = n[i0];
			unpackdouble(pu, x, n[i1]);
			break;
		}
	case fp_op_extended:
		{
			extended_type x;
			double t=1.0; int i0,i1,i2,i3;
			if((*(int*)&t)!=0) {i0=0;i1=1;i2=2;i3=3;}
			else {i0=3;i1=2;i2=1;i3=0;}
			*(int*)&x = n[i0];
			unpackextended(pu, x, n[i1], n[i2], n[i3]);
			break;
		}
	}
}
