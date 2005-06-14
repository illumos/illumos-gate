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

/* Pack procedures for Sparc FPU simulator. */

#include "_Qquad.h"
#include "_Qglobals.h"

PRIVATE int
overflow_to_infinity(sign)
	int             sign;

/* Returns 1 if overflow should go to infinity, 0 if to max finite. */

{
	int             inf;

	switch (fp_direction) {
	case fp_nearest:
		inf = 1;
		break;
	case fp_tozero:
		inf = 0;
		break;
	case fp_positive:
		inf = !sign;
		break;
	case fp_negative:
		inf = sign;
		break;
	}
	return (inf);
}

PRIVATE void
round(pu)
	unpacked       *pu;

/* Round according to current rounding mode.	 */

{
	int             increment;	/* boolean to indicate round up */
	int sr;
	sr = pu->sticky|pu->rounded;

	if (sr == 0)
		return;
	fpu_set_exception(fp_inexact);
	switch (fp_direction) {
	case fp_nearest:
		increment = pu->rounded;
		break;
	case fp_tozero:
		increment = 0;
		break;
	case fp_positive:
		increment = (pu->sign == 0) & (sr != 0);
		break;
	case fp_negative:
		increment = (pu->sign != 0) & (sr != 0);
		break;
	}
	if (increment) {
	    pu->significand[3]++;
	    if (pu->significand[3] == 0) {	
		pu->significand[2]++;
		if (pu->significand[2] == 0) {	
		    pu->significand[1]++;
		    if (pu->significand[1] == 0) {	
			pu->significand[0]++;	/* rounding carried out */
			if( pu->significand[0] == 0x20000) {
			    pu->exponent++;
			    pu->significand[0] = 0x10000;
			}
		    }
		}
	    }
	}
	if ((fp_direction == fp_nearest) && 
		(pu->sticky == 0) && increment!=0) {	/* ambiguous case */
		pu->significand[3] &= 0xfffffffe;	/* force round to even */
	}
}

PRIVATE void
packinteger(pu, px)
	unpacked       *pu;	/* unpacked result */
	int            *px;	/* packed integer */
{
	switch (pu->fpclass) {
	case fp_zero:
		*px = 0;
		break;
	case fp_normal:
		if (pu->exponent >= 32)
			goto overflow;
		fpu_rightshift(pu, 112 - pu->exponent);
		round(pu);
		if (pu->significand[3] >= 0x80000000)
			if ((pu->sign == 0)||(pu->significand[3] > 0x80000000))
				goto overflow;
		*px = pu->significand[3];
		if (pu->sign)
			*px = -*px;
		break;
	case fp_infinity:
	case fp_quiet:
	case fp_signaling:
overflow:
		if (pu->sign)
			*px = 0x80000000;
		else
			*px = 0x7fffffff;
		_fp_current_exceptions &= ~(1 << (int) fp_inexact);
		fpu_set_exception(fp_invalid);
		break;
	}
}

PRIVATE void
packsingle(pu, px)
	unpacked       *pu;	/* unpacked result */
	single_type    *px;	/* packed single */
{
	px->sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		px->exponent = 0;
		px->significand = 0;
		break;
	case fp_infinity:
infinity:
		px->exponent = 0xff;
		px->significand = 0;
		break;
	case fp_quiet:
	case fp_signaling:
		fpu_rightshift(pu, 113-24);
		px->exponent = 0xff;
		px->significand = 0x400000|(0x3fffff&pu->significand[3]);
		break;
	case fp_normal:
		fpu_rightshift(pu, 113-24);
		pu->exponent += SINGLE_BIAS;
		if (pu->exponent <= 0) {
			px->exponent = 0;
			fpu_rightshift(pu, 1 - pu->exponent);
			round(pu);
			if (pu->significand[3] == 0x800000) {	/* rounded
								 * back up to
								 * normal */
				px->exponent = 1;
				px->significand = 0;
				return;
			}
			if (_fp_current_exceptions & (1 << fp_inexact))
				fpu_set_exception(fp_underflow);
			px->significand = 0x7fffff & pu->significand[3];
			return;
		}
		round(pu);
		if (pu->significand[3] == 0x1000000) {	/* rounding overflow */
			pu->significand[3] = 0x800000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0xff) {
			fpu_set_exception(fp_overflow);
			fpu_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			px->exponent = 0xfe;
			px->significand = 0x7fffff;
			return;
		}
		px->exponent = pu->exponent;
		px->significand = 0x7fffff & pu->significand[3];
	}
}

PRIVATE void
packdouble(pu, px, py)
	unpacked       *pu;	/* unpacked result */
	double_type    *px;	/* packed double */
	unsigned       *py;
{
	px->sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		px->exponent = 0;
		px->significand = 0;
		*py = 0;
		break;
	case fp_infinity:
infinity:
		px->exponent = 0x7ff;
		px->significand = 0;
		*py = 0;
		break;
	case fp_quiet:
	case fp_signaling:
		fpu_rightshift(pu, 113-53);
		px->exponent = 0x7ff;
		px->significand = 0x80000 | (0x7ffff & pu->significand[2]);
		*py = pu->significand[3];
		break;
	case fp_normal:
		fpu_rightshift(pu, 113-53);
		pu->exponent += DOUBLE_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			px->exponent = 0;
			fpu_rightshift(pu, 1 - pu->exponent);
			round(pu);
			if (pu->significand[2] == 0x100000) {	/* rounded 
								 * back up to
								 * normal */
				px->exponent = 1;
				px->significand = 0;
				*py = 0;
				return;
			}
			if (_fp_current_exceptions & (1 << fp_inexact))
				fpu_set_exception(fp_underflow);
			px->exponent = 0;
			px->significand = 0xfffff & pu->significand[2];
			*py = pu->significand[3];
			return;
		}
		round(pu);
		if (pu->significand[2] == 0x200000) {	/* rounding overflow */
			pu->significand[2] = 0x100000;
			pu->exponent += 1;
		}
		if (pu->exponent >= 0x7ff) {	/* overflow */
			fpu_set_exception(fp_overflow);
			fpu_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			px->exponent = 0x7fe;
			px->significand = 0xfffff;
			*py = 0xffffffff;
			return;
		}
		px->exponent = pu->exponent;
		px->significand = 0xfffff & pu->significand[2];
		*py = pu->significand[3];
		break;
	}
}

PRIVATE void
packextended(pu, px, py, pz, pw)
	unpacked       *pu;	/* unpacked result */
	extended_type  *px;	/* packed extended */
	unsigned       *py, *pz, *pw;
{
	px->sign = pu->sign;
	switch (pu->fpclass) {
	case fp_zero:
		px->exponent = 0;
		px->significand = 0;
		*pz = 0;
		*py = 0;
		*pw = 0;
		break;
	case fp_infinity:
infinity:
		px->exponent = 0x7fff;
		px->significand = 0;
		*pz = 0;
		*py = 0;
		*pw = 0;
		break;
	case fp_quiet:
	case fp_signaling:
		px->exponent = 0x7fff;
		px->significand = 0x8000 | pu->significand[0];	/* Insure quiet
								 * nan. */
		*py = pu->significand[1];
		*pz = pu->significand[2];
		*pw = pu->significand[3];
		break;
	case fp_normal:
		pu->exponent += EXTENDED_BIAS;
		if (pu->exponent <= 0) {	/* underflow */
			fpu_rightshift(pu, 1-pu->exponent);
			round(pu);
			if (pu->significand[0] < 0x00010000) {	/* not rounded 
								 * back up
								 * to normal */
				if (_fp_current_exceptions & (1 << fp_inexact))
					fpu_set_exception(fp_underflow);
				px->exponent = 0;
			} else
				px->exponent = 1;
			px->significand = pu->significand[0];
			*py = pu->significand[1];
			*pz = pu->significand[2];
			*pw = pu->significand[3];
			return;
		}
		round(pu);	/* rounding overflow handled in round() */
		if (pu->exponent >= 0x7fff) {	/* overflow */
			fpu_set_exception(fp_overflow);
			fpu_set_exception(fp_inexact);
			if (overflow_to_infinity(pu->sign))
				goto infinity;
			px->exponent = 0x7ffe;	/* overflow to max norm */
			px->significand = 0xffff;
			*py = 0xffffffff;
			*pz = 0xffffffff;
			*pw = 0xffffffff;
			return;
		}
		px->exponent = pu->exponent;
		px->significand = pu->significand[0];
		*py = pu->significand[1];
		*pz = pu->significand[2];
		*pw = pu->significand[3];
		break;
	}
}

void
_fp_pack(pu, n, type)
	unpacked       *pu;	/* unpacked operand */
	int 		*n;	/* output result's address */
	enum fp_op_type type;	/* type of datum */

{
	switch (type) {
	case fp_op_integer:
		{
			packinteger(pu, n);
			break;
		}
	case fp_op_single:
		{
			single_type     x;
			packsingle(pu, &x);
			n[0] = *(int*)&x;
			break;
		}
	case fp_op_double:
		{
			double_type     x;
			double		t=1.0;
			int		i0,i1;
			if((*(int*)&t)!=0) {i0=0;i1=1;} else {i0=1;i1=0;}
			packdouble(pu, &x,&n[i1]);
			n[i0] = *(int*)&x;
			break;
		}
	case fp_op_extended:
		{
			extended_type   x;
			unsigned        y, z, w;
			unpacked        u;
			int		k;
			switch (fp_precision) {	/* Implement extended
						 * rounding precision mode. */
			case fp_single:
				{
					single_type     tx;
					packsingle(pu, &tx);
					pu = &u;
					unpacksingle(pu, tx);
					break;
				}
			case fp_double:
				{
					double_type     tx;
					unsigned        ty;
					packdouble(pu, &tx, &ty);
					pu = &u;
					unpackdouble(pu, tx, ty);
					break;
				}
			case fp_precision_3:	/* rounded to 64 bits */
				{
					k = pu->exponent+ EXTENDED_BIAS;
					if(k>=0) k = 113-64;
					else     k = 113-64-k;
					fpu_rightshift(pu,113-64);
					round(pu);
					pu->sticky=pu->rounded=0;
					pu->exponent += k;
					fpu_normalize(pu);
					break;
				}
			}
			{
			int		i0,i1,i2,i3;
			double t = 1.0;
			if((*(int*)&t)!=0) {i0=0;i1=1;i2=2;i3=3;}
			else {i0=3;i1=2;i2=1;i3=0;}
			packextended(pu, &x, &n[i1], &n[i2], &n[i3]);
			n[i0] = *(int*)&x;
			}

			break;
		}
	}
}

