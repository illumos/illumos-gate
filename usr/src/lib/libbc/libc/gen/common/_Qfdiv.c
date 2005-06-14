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
_fp_div(px, py, pz)
	unpacked       *px, *py, *pz;

{
	unsigned	r[4],*y,q,c;
	int		n;

	*pz = *px;
	pz->sign = px->sign ^ py->sign;

	if ((py->fpclass == fp_quiet) || (py->fpclass == fp_signaling)) {
		*pz = *py;
		return;
	}
	switch (px->fpclass) {
	case fp_quiet:
	case fp_signaling:
		return;
	case fp_zero:
	case fp_infinity:
		if (px->fpclass == py->fpclass) {	/* 0/0 or inf/inf */
			fpu_error_nan(pz);
			pz->fpclass = fp_quiet;
		}
		return;
	case fp_normal:
		switch (py->fpclass) {
		case fp_zero:	/* number/0 */
			fpu_set_exception(fp_division);
			pz->fpclass = fp_infinity;
			return;
		case fp_infinity:	/* number/inf */
			pz->fpclass = fp_zero;
			return;
		}
	}

	/* Now x and y are both normal or subnormal. */

	r[0] = px->significand[0];
	r[1] = px->significand[1];
	r[2] = px->significand[2];
	r[3] = px->significand[3];
	y = py->significand;

	if(fpu_cmpli(r,y,4)>=0)
		pz->exponent = px->exponent - py->exponent;
	else
		pz->exponent = px->exponent - py->exponent - 1;
	
	q=0;
	while(q<0x10000) {	/* generate quo[0] */
		q<<=1;
		if(fpu_cmpli(r,y,4)>=0) {
			q += 1; 	/* if r>y do r-=y and q+=1 */
			c  = 0;
			c = fpu_sub3wc(&r[3],r[3],y[3],c);
			c = fpu_sub3wc(&r[2],r[2],y[2],c);
			c = fpu_sub3wc(&r[1],r[1],y[1],c);
			c = fpu_sub3wc(&r[0],r[0],y[0],c);
		}
		r[0] = (r[0]<<1)|((r[1]&0x80000000)>>31);  /* r << 1 */
		r[1] = (r[1]<<1)|((r[2]&0x80000000)>>31);
		r[2] = (r[2]<<1)|((r[3]&0x80000000)>>31);
		r[3] = (r[3]<<1);
	}
	pz->significand[0]=q;
	q=0;			/* generate quo[1] */
	n = 32;
	while(n--) {
		q<<=1;
		if(fpu_cmpli(r,y,4)>=0) {
			q += 1; 	/* if r>y do r-=y and q+=1 */
			c  = 0;
			c = fpu_sub3wc(&r[3],r[3],y[3],c);
			c = fpu_sub3wc(&r[2],r[2],y[2],c);
			c = fpu_sub3wc(&r[1],r[1],y[1],c);
			c = fpu_sub3wc(&r[0],r[0],y[0],c);
		}
		r[0] = (r[0]<<1)|((r[1]&0x80000000)>>31);  /* r << 1 */
		r[1] = (r[1]<<1)|((r[2]&0x80000000)>>31);
		r[2] = (r[2]<<1)|((r[3]&0x80000000)>>31);
		r[3] = (r[3]<<1);
	}
	pz->significand[1] = q;
	q=0;			/* generate quo[2] */
	n = 32;
	while(n--) {
		q<<=1;
		if(fpu_cmpli(r,y,4)>=0) {
			q += 1; 	/* if r>y do r-=y and q+=1 */
			c  = 0;
			c = fpu_sub3wc(&r[3],r[3],y[3],c);
			c = fpu_sub3wc(&r[2],r[2],y[2],c);
			c = fpu_sub3wc(&r[1],r[1],y[1],c);
			c = fpu_sub3wc(&r[0],r[0],y[0],c);
		}
		r[0] = (r[0]<<1)|((r[1]&0x80000000)>>31);  /* r << 1 */
		r[1] = (r[1]<<1)|((r[2]&0x80000000)>>31);
		r[2] = (r[2]<<1)|((r[3]&0x80000000)>>31);
		r[3] = (r[3]<<1);
	}
	pz->significand[2] = q;
	q=0;			/* generate quo[3] */
	n = 32;
	while(n--) {
		q<<=1;
		if(fpu_cmpli(r,y,4)>=0) {
			q += 1; 	/* if r>y do r-=y and q+=1 */
			c  = 0;
			c = fpu_sub3wc(&r[3],r[3],y[3],c);
			c = fpu_sub3wc(&r[2],r[2],y[2],c);
			c = fpu_sub3wc(&r[1],r[1],y[1],c);
			c = fpu_sub3wc(&r[0],r[0],y[0],c);
		}
		r[0] = (r[0]<<1)|((r[1]&0x80000000)>>31);  /* r << 1 */
		r[1] = (r[1]<<1)|((r[2]&0x80000000)>>31);
		r[2] = (r[2]<<1)|((r[3]&0x80000000)>>31);
		r[3] = (r[3]<<1);
	}
	pz->significand[3] = q;
	if((r[0]|r[1]|r[2]|r[3])==0) pz->sticky = pz->rounded = 0;
	else {
		pz->sticky = 1;		/* half way case won't occur */
		if(fpu_cmpli(r,y,4)>=0) pz->rounded = 1;
	}
}

void
_fp_sqrt(px, pz)
	unpacked       *px, *pz;

{				/* *pz gets sqrt(*px) */

	unsigned *x,r,c,q,t[4],s[4];
	*pz = *px;
	switch (px->fpclass) {
	case fp_quiet:
	case fp_signaling:
	case fp_zero:
		return;
	case fp_infinity:
		if (px->sign == 1) {	/* sqrt(-inf) */
			fpu_error_nan(pz);
			pz->fpclass = fp_quiet;
		}
		return;
	case fp_normal:
		if (px->sign == 1) {	/* sqrt(-norm) */
			fpu_error_nan(pz);
			pz->fpclass = fp_quiet;
			return;
		}
	}

	/* Now x is normal. */
	x = px->significand;
	if (px->exponent & 1) {	/* sqrt(1.f * 2**odd) = sqrt (2.+2f) *
				 * 2**(odd-1)/2 */
		pz->exponent = (px->exponent - 1) / 2;
		x[0] = (x[0]<<1)|((x[1]&0x80000000)>>31);	/* x<<1 */
		x[1] = (x[1]<<1)|((x[2]&0x80000000)>>31);
		x[2] = (x[2]<<1)|((x[3]&0x80000000)>>31);
		x[3] = (x[3]<<1);
	} else {		/* sqrt(1.f * 2**even) = sqrt (1.f) *
				 * 2**(even)/2 */
		pz->exponent = px->exponent / 2;
	}
	s[0]=s[1]=s[2]=s[3]=t[0]=t[1]=t[2]=t[3]=0;
	q = 0;
	r = 0x00010000;
	while(r!=0) {			/* compute sqrt[0] */
		t[0] = s[0]+r;
		if(t[0]<=x[0]) {
			s[0] = t[0]+r;
			x[0] -= t[0];
			q    += r;
		}
		x[0] = (x[0]<<1)|((x[1]&0x80000000)>>31);	/* x<<1 */
		x[1] = (x[1]<<1)|((x[2]&0x80000000)>>31);
		x[2] = (x[2]<<1)|((x[3]&0x80000000)>>31);
		x[3] = (x[3]<<1);
		r>>=1;
	}
	pz->significand[0] = q;
	q = 0;
	r = 0x80000000;
	while(r!=0) {			/* compute sqrt[1] */
		t[1] = s[1]+r;	/* no carry */
		t[0] = s[0];
		if(fpu_cmpli(t,x,2)<=0) {
			c = 0;
			c = fpu_add3wc(&s[1],t[1],r,c);
			c = fpu_add3wc(&s[0],t[0],0,c);
			c = 0;
			c = fpu_sub3wc(&x[1],x[1],t[1],c);
			c = fpu_sub3wc(&x[0],x[0],t[0],c);
			q    += r;
		}
		x[0] = (x[0]<<1)|((x[1]&0x80000000)>>31);	/* x<<1 */
		x[1] = (x[1]<<1)|((x[2]&0x80000000)>>31);
		x[2] = (x[2]<<1)|((x[3]&0x80000000)>>31);
		x[3] = (x[3]<<1);
		r>>=1;
	}
	pz->significand[1] = q;
	q = 0;
	r = 0x80000000;
	while(r!=0) {			/* compute sqrt[2] */
		t[2] = s[2]+r;	/* no carry */
		t[1] = s[1];
		t[0] = s[0];
		if(fpu_cmpli(t,x,3)<=0) {
			c = 0;
			c = fpu_add3wc(&s[2],t[2],r,c);
			c = fpu_add3wc(&s[1],t[1],0,c);
			c = fpu_add3wc(&s[0],t[0],0,c);
			c = 0;
			c = fpu_sub3wc(&x[2],x[2],t[2],c);
			c = fpu_sub3wc(&x[1],x[1],t[1],c);
			c = fpu_sub3wc(&x[0],x[0],t[0],c);
			q    += r;
		}
		x[0] = (x[0]<<1)|((x[1]&0x80000000)>>31);	/* x<<1 */
		x[1] = (x[1]<<1)|((x[2]&0x80000000)>>31);
		x[2] = (x[2]<<1)|((x[3]&0x80000000)>>31);
		x[3] = (x[3]<<1);
		r>>=1;
	}
	pz->significand[2] = q;
	q = 0;
	r = 0x80000000;
	while(r!=0) {			/* compute sqrt[3] */
		t[3] = s[3]+r;	/* no carry */
		t[2] = s[2];
		t[1] = s[1];
		t[0] = s[0];
		if(fpu_cmpli(t,x,4)<=0) {
			c = 0;
			c = fpu_add3wc(&s[3],t[3],r,c);
			c = fpu_add3wc(&s[2],t[2],0,c);
			c = fpu_add3wc(&s[1],t[1],0,c);
			c = fpu_add3wc(&s[0],t[0],0,c);
			c = 0;
			c = fpu_sub3wc(&x[3],x[3],t[3],c);
			c = fpu_sub3wc(&x[2],x[2],t[2],c);
			c = fpu_sub3wc(&x[1],x[1],t[1],c);
			c = fpu_sub3wc(&x[0],x[0],t[0],c);
			q    += r;
		}
		x[0] = (x[0]<<1)|((x[1]&0x80000000)>>31);	/* x<<1 */
		x[1] = (x[1]<<1)|((x[2]&0x80000000)>>31);
		x[2] = (x[2]<<1)|((x[3]&0x80000000)>>31);
		x[3] = (x[3]<<1);
		r>>=1;
	}
	pz->significand[3] = q;
	if((x[0]|x[1]|x[2]|x[3])==0) {
		pz->sticky = pz->rounded = 0;
	} else {
		pz->sticky = 1;
		if(fpu_cmpli(s,x,4)<0) pz->rounded=1; else pz->rounded = 0;
	}
}
