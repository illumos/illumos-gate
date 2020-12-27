/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#include "FEATURE/uwin"

#if !_UWIN || _lib_srand48

void _STUB_srand48(){}

#else

#define drand48	______drand48
#define erand48	______erand48
#define jrand48	______jrand48
#define lcong48	______lcong48
#define lrand48	______lrand48
#define mrand48	______mrand48
#define nrand48	______nrand48
#define seed48	______seed48
#define srand48	______srand48

#include	<stdlib.h>

#undef	drand48
#undef	erand48
#undef	jrand48
#undef	lcong48
#undef	lrand48
#undef	mrand48
#undef	nrand48
#undef	seed48
#undef	srand48

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#define A	0x5DEECE66D
#define A0	0X5
#define A1	0xDEEC
#define A2	0xE66D
#define C	0xB
#define XINIT	0x330E
#define SCALE	3.55271e-15

static unsigned short oldval[3];
static unsigned short X[3] = { 0, 0, XINIT};
static unsigned short a[3] = { A0, A1, A2};
static unsigned short c = C;

static void multadd(unsigned short x[3], unsigned short a[3], unsigned short c)
{
	register unsigned long r = c;
	unsigned short x2 = x[2];
	unsigned short x1 = x[1];
	r += a[2]*x2;
	x[2] = (unsigned short)r;
	r >>= 16;
	r += a[1]*x2;
	r += a[2]*x1;
	x[1] = (unsigned short)r;
	r >>= 16;
	r += a[2]*x[0];
	r += a[1]*x1;
	r += a[0]*x2;
	x[0] = (unsigned short)r;
}

extern double drand48(void)
{
	double d;
	unsigned long u;
	multadd(X,a,c);
	u = (X[0]<<16) + X[1];
	d = (u*65536.) + X[2];
	return(d*SCALE);
}

extern double erand48(unsigned short xsubi[3])
{
	double d;
	unsigned long u;
	multadd(xsubi,a,c);
	u = (xsubi[0]<<16) + xsubi[1];
	d = (u*65536.) + xsubi[2];
	return(d*SCALE);
}

extern long jrand48(unsigned short xsubi[3])
{
	long u;
	multadd(xsubi,a,c);
	u = (xsubi[0]<<16) | xsubi[1];
	return((long)u);
}

extern void lcong48(unsigned short param[7])
{
	X[0] = param[0];
	X[1] = param[1];
	X[2] = param[2];
	a[0] = param[3];
	a[1] = param[4];
	a[2] = param[5];
	c = param[6];
}

extern long lrand48(void)
{
	long l;
	multadd(X,a,c);
	l = (X[0]<<15)|(X[1]>>1);
	return(l);
}

extern long mrand48(void)
{
	unsigned long u;
	multadd(X,a,c);
	u = (X[0]<<16) | X[1];
	return((long)u);
}

extern long nrand48(unsigned short xsubi[3])
{
	long l;
	multadd(xsubi,a,c);
	l = (xsubi[0]<<15)|(xsubi[1]>>1);
	return(l);
}

extern unsigned short *seed48(unsigned short seed[3])
{
	unsigned short *sp = (unsigned short*)&X;
	a[0] = A0;
	a[1] = A1;
	a[2] = A2;
	c = C;
	oldval[0] = X[2];
	oldval[1] = X[1];
	oldval[2] = X[0];
	X[0] = seed[2];
	X[1] = seed[1];
	X[2] = seed[0];
	return(oldval);
}

extern void srand48(long seedval)
{
	a[0] = A0;
	a[1] = A1;
	a[2] = A2;
	c = C;
	X[0] = (unsigned short)(((unsigned long)seedval) >> 16);
	X[1] = (unsigned short)seedval;
	X[2] = XINIT; 
}

#endif
