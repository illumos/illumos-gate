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

/* Utility functions for Sparc FPU simulator. */

#include "_Qquad.h"
#include "_Qglobals.h"


void
fpu_normalize(pu)
	unpacked       *pu;

/* Normalize a number.  Does not affect zeros, infs, or NaNs. */
/* The number will be normalized to 113 bit extended: 
 * 		0x0001####,0x########,0x########,0x########.
 */

{
	unsigned u,u0,u1,u2,u3,m,n,k;
	u0 = pu->significand[0];
	u1 = pu->significand[1];
	u2 = pu->significand[2];
	u3 = pu->significand[3];
	if ((*pu).fpclass == fp_normal) {
		if ((u0|u1|u2|u3)==0) {
			(*pu).fpclass = fp_zero;
			return;
		}
		while (u0 == 0) { 
			u0 = u1; u1=u2; u2=u3; u3=0;
			(*pu).exponent = (*pu).exponent - 32;
		}
		if (u0>=0x20000) { 	/* u3 should be zero */
			n=1; u = u0>>1;
			while(u>=0x20000) {u >>= 1; n += 1;}
			m = (1<<n)-1;
			k = 32-n;
			(*pu).exponent += n;
			u3 = ((u2&m)<<k)|(u3>>n);
			u2 = ((u1&m)<<k)|(u2>>n);
			u1 = ((u0&m)<<k)|(u1>>n);
			u0 = u;
		} else if(u0<0x10000) {
			n=1; u = u0<<1;
			while(u<0x10000) {u <<= 1; n += 1;}
			k = 32-n;
			m = -(1<<k);
			(*pu).exponent -= n;
			u0 = (u0<<n)|((u1&m)>>k);
			u1 = (u1<<n)|((u2&m)>>k);
			u2 = (u2<<n)|((u3&m)>>k);
			u3 = (u3<<n);
		}
		pu->significand[0] = u0;
		pu->significand[1] = u1;
		pu->significand[2] = u2;
		pu->significand[3] = u3;
	}
}

void
fpu_rightshift(pu, n)
	unpacked       *pu;
	int             n;

/* Right shift significand sticky by n bits.  */

{
	unsigned m,k,j,u0,u1,u2,u3;
	if (n > 113) {		/* drastic */
		if (((*pu).significand[0] | (*pu).significand[1] 
			| (*pu).significand[2] | (*pu).significand[3]) == 0){
						/* really zero */
			pu->fpclass = fp_zero;
			return;
		} else {
			pu->rounded = 0;
			pu->sticky  = 1;
			pu->significand[3] = 0;
			pu->significand[2] = 0;
			pu->significand[1] = 0;
			pu->significand[0] = 0;
			return;
		}
	}
	while (n >= 32) {	/* big shift */
		pu->sticky  |= pu->rounded | (pu->significand[3]&0x7fffffff);
		pu->rounded  = (*pu).significand[3]>>31;
		(*pu).significand[3] = (*pu).significand[2];
		(*pu).significand[2] = (*pu).significand[1];
		(*pu).significand[1] = (*pu).significand[0];
		(*pu).significand[0] = 0;
		n -= 32;
	}
	if (n > 0) {		/* small shift */
		u0 = pu->significand[0];
		u1 = pu->significand[1];
		u2 = pu->significand[2];
		u3 = pu->significand[3];
		m = (1<<n)-1;
		k = 32 - n;
		j = (1<<(n-1))-1;
		pu->sticky |= pu->rounded | (u3&j);
		pu->rounded = (u3&m)>>(n-1);
		pu->significand[3] = ((u2&m)<<k)|(u3>>n);
		pu->significand[2] = ((u1&m)<<k)|(u2>>n);
		pu->significand[1] = ((u0&m)<<k)|(u1>>n);
		pu->significand[0] = u0>>n;
	}
}

void
fpu_set_exception(ex)
	enum fp_exception_type ex;

/* Set the exception bit in the current exception register. */

{
	_fp_current_exceptions |= 1 << (int) ex;
}

void
fpu_error_nan(pu)
	unpacked       *pu;

{				/* Set invalid exception and error nan in *pu */

	fpu_set_exception(fp_invalid);
	pu->significand[0] = 0x7fffffff|((pu->sign)<<31);
	pu->significand[1] = 0xffffffff;
	pu->significand[2] = 0xffffffff;
	pu->significand[3] = 0xffffffff;
}

/* the following fpu_add3wc should be inlined as
 *	.inline	_fpu_add3wc,3
 *	ld	[%o1],%o4		! sum = x
 *	addcc	-1,%o3,%g0		! restore last carry in cc reg
 *	addxcc	%o4,%o2,%o4		! sum = sum + y + last carry
 *	st	%o4,[%o0]		! *z  = sum
 *	addx	%g0,%g0,%o0		! return new carry
 *	.end
 */

unsigned
fpu_add3wc(z,x,y,carry) 
	unsigned *z,x,y,carry;
{				/*  *z = x + y + carry, set carry; */
	if(carry==0) {
		*z = x+y;
		return (*z<y);
	} else {
		*z = x+y+1;
		return (*z<=y);
	}
}

/* the following fpu_sub3wc should be inlined as
 *	.inline	_fpu_sub3wc,3
 *	ld	[%o1],%o4		! sum = *x
 *	addcc	-1,%o3,%g0		! restore last carry in cc reg
 *	subxcc	%o4,%o2,%o4		! sum = sum - y - last carry
 *	st	%o4,[%o0]		! *x  = sum
 *	addx	%g0,%g0,%o0		! return new carry
 *	.end
 */

unsigned
fpu_sub3wc(z,x,y,carry) 
	unsigned *z,x,y,carry;
{				/*  *z = x - y - carry, set carry; */
	if(carry==0) {
		*z = x-y;
		return (*z>x);
	} else {
		*z = x-y-1;
		return (*z>=x);
	}
}

/* the following fpu_neg2wc should be inlined as
 *	.inline	_fpu_neg2wc,2
 *	ld	[%o1],%o3		! tmp = *x
 *	addcc	-1,%o2,%g0		! restore last carry in cc reg
 *	subxcc	%g0,%o3,%o3		! sum = 0 - tmp - last carry
 *	st	%o3,[%o0]		! *x  = sum
 *	addx	%g0,%g0,%o0		! return new carry
 *	.end
 */

unsigned
fpu_neg2wc(z,x,carry) 
	unsigned *z,x,carry;
{				/*  *x = 0 - *x - carry, set carry; */
	if(carry==0) {
		*z = -x;
		return ((*z)!=0);
	} else {
		*z = -x-1;
		return 1;
	}
}

int
fpu_cmpli(x,y,n)
	unsigned x[],y[]; int n;
{				/* compare two unsigned array */ 
	int i;
	i=0;
	while(i<n)  {
		if(x[i]>y[i]) return 1;
		else if(x[i]<y[i]) return -1;
		i++;
	}
	return 0;
}

#ifdef DEBUG
void
display_unpacked(pu)
	unpacked       *pu;

/* Print out unpacked record.	 */

{
	(void) printf(" unpacked ");
	if (pu->sign)
		(void) printf("-");
	else
		(void) printf("+");

	switch (pu->fpclass) {
	case fp_zero:
		(void) printf("0     ");
		break;
	case fp_normal:
		(void) printf("normal");
		break;
	case fp_infinity:
		(void) printf("Inf   ");
		break;
	case fp_quiet:
	case fp_signaling:
		(void) printf("nan   ");
		break;
	}
	(void) printf(" %X %X %X %X (%X,%X) exponent %X \n", 
		pu->significand[0], pu->significand[1],pu->significand[2],
		pu->significand[3], (pu->rounded!=0),
		(pu->sticky!=0),pu->exponent);
}
#endif

