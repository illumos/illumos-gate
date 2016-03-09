/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011, Richard Lowe
 */

#ifndef _FENV_INLINES_H
#define	_FENV_INLINES_H

#ifdef __GNUC__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#if defined(__x86)

/*
 * Floating point Control Word and Status Word
 * Definition should actually be shared with x86
 * (much of this 'amd64' code can be, in fact.)
 */
union fp_cwsw {
	uint32_t cwsw;
	struct {
		uint16_t cw;
		uint16_t sw;
	} words;
};

extern __GNU_INLINE void
__fenv_getcwsw(unsigned int *value)
{
	union fp_cwsw *u = (union fp_cwsw *)value;

	__asm__ __volatile__(
	    "fstsw %0\n\t"
	    "fstcw %1\n\t"
	    : "=m" (u->words.cw), "=m" (u->words.sw));
}

extern __GNU_INLINE void
__fenv_setcwsw(const unsigned int *value)
{
	union fp_cwsw cwsw;
	short fenv[16];

	cwsw.cwsw = *value;

	__asm__ __volatile__(
	    "fstenv %0\n\t"
	    "movw   %4,%1\n\t"
	    "movw   %3,%2\n\t"
	    "fldenv %0\n\t"
	    "fwait\n\t"
	    : "=m" (fenv), "=m" (fenv[0]), "=m" (fenv[2])
	    : "r" (cwsw.words.cw), "r" (cwsw.words.sw)
	    /* For practical purposes, we clobber the whole FPU */
	    : "cc", "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)",
	      "st(6)", "st(7)");
}

extern __GNU_INLINE void
__fenv_getmxcsr(unsigned int *value)
{
	__asm__ __volatile__("stmxcsr %0" : "=m" (*value));
}

extern __GNU_INLINE void
__fenv_setmxcsr(const unsigned int *value)
{
	__asm__ __volatile__("ldmxcsr %0" : : "m" (*value));
}

extern __GNU_INLINE long double
f2xm1(long double x)
{
	long double ret;

	__asm__ __volatile__("f2xm1" : "=t" (ret) : "0" (x) : "cc");
	return (ret);
}

extern __GNU_INLINE long double
fyl2x(long double y, long double x)
{
	long double ret;

	__asm__ __volatile__("fyl2x"
	    : "=t" (ret)
	    : "0" (x), "u" (y)
	    : "st(1)", "cc");
	return (ret);
}

extern __GNU_INLINE long double
fptan(long double x)
{
	/*
	 * fptan pushes 1.0 then the result on completion, so we want to pop
	 * the FP stack twice, so we need a dummy value into which to pop it.
	 */
	long double ret;
	long double dummy;

	__asm__ __volatile__("fptan"
	    : "=t" (dummy), "=u" (ret)
	    : "0" (x)
	    : "cc");
	return (ret);
}

extern __GNU_INLINE long double
fpatan(long double x, long double y)
{
	long double ret;

	__asm__ __volatile__("fpatan"
	    : "=t" (ret)
	    : "0" (y), "u" (x)
	    : "st(1)", "cc");
	return (ret);
}

extern __GNU_INLINE long double
fxtract(long double x)
{
	__asm__ __volatile__("fxtract" : "+t" (x) : : "cc");
	return (x);
}

extern __GNU_INLINE long double
fprem1(long double idend, long double div)
{
	__asm__ __volatile__("fprem1" : "+t" (div) : "u" (idend) : "cc");
	return (div);
}

extern __GNU_INLINE long double
fprem(long double idend, long double div)
{
	__asm__ __volatile__("fprem" : "+t" (div) : "u" (idend) : "cc");
	return (div);
}

extern __GNU_INLINE long double
fyl2xp1(long double y, long double x)
{
	long double ret;

	__asm__ __volatile__("fyl2xp1"
	    : "=t" (ret)
	    : "0" (x), "u" (y)
	    : "st(1)", "cc");
	return (ret);
}

extern __GNU_INLINE long double
fsqrt(long double x)
{
	__asm__ __volatile__("fsqrt" : "+t" (x) : : "cc");
	return (x);
}

extern __GNU_INLINE long double
fsincos(long double x)
{
	long double dummy;

	__asm__ __volatile__("fsincos" : "+t" (x), "=u" (dummy) : : "cc");
	return (x);
}

extern __GNU_INLINE long double
frndint(long double x)
{
	__asm__ __volatile__("frndint" : "+t" (x) : : "cc");
	return (x);
}

extern __GNU_INLINE long double
fscale(long double x, long double y)
{
	long double ret;

	__asm__ __volatile__("fscale" : "=t" (ret) : "0" (y), "u" (x) : "cc");
	return (ret);
}

extern __GNU_INLINE long double
fsin(long double x)
{
	__asm__ __volatile__("fsin" : "+t" (x) : : "cc");
	return (x);
}

extern __GNU_INLINE long double
fcos(long double x)
{
	__asm__ __volatile__("fcos" : "+t" (x) : : "cc");
	return (x);
}

extern __GNU_INLINE void
sse_cmpeqss(float *f1, float *f2, int *i1)
{
	__asm__ __volatile__(
	    "cmpeqss %2, %1\n\t"
	    "movss   %1, %0"
	    : "=m" (*i1), "+x" (*f1)
	    : "x" (*f2)
	    : "cc");
}

extern __GNU_INLINE void
sse_cmpltss(float *f1, float *f2, int *i1)
{
	__asm__ __volatile__(
	    "cmpltss %2, %1\n\t"
	    "movss   %1, %0"
	    : "=m" (*i1), "+x" (*f1)
	    : "x" (*f2)
	    : "cc");
}

extern __GNU_INLINE void
sse_cmpless(float *f1, float *f2, int *i1)
{
	__asm__ __volatile__(
	    "cmpless %2, %1\n\t"
	    "movss   %1, %0"
	    : "=m" (*i1), "+x" (*f1)
	    : "x" (*f2)
	    : "cc");
}

extern __GNU_INLINE void
sse_cmpunordss(float *f1, float *f2, int *i1)
{
	__asm__ __volatile__(
	    "cmpunordss %2, %1\n\t"
	    "movss      %1, %0"
	    : "=m" (*i1), "+x" (*f1)
	    : "x" (*f2)
	    : "cc");
}

extern __GNU_INLINE void
sse_minss(float *f1, float *f2, float *f3)
{
	__asm__ __volatile__(
	    "minss %2, %1\n\t"
	    "movss %1, %0"
	    : "=m" (*f3), "+x" (*f1)
	    : "x" (*f2));
}

extern __GNU_INLINE void
sse_maxss(float *f1, float *f2, float *f3)
{
	__asm__ __volatile__(
	    "maxss %2, %1\n\t"
	    "movss %1, %0"
	    : "=m" (*f3), "+x" (*f1)
	    : "x" (*f2));
}

extern __GNU_INLINE void
sse_addss(float *f1, float *f2, float *f3)
{
	__asm__ __volatile__(
	    "addss %2, %1\n\t"
	    "movss %1, %0"
	    : "=m" (*f3), "+x" (*f1)
	    : "x" (*f2));
}

extern __GNU_INLINE void
sse_subss(float *f1, float *f2, float *f3)
{
	__asm__ __volatile__(
	    "subss %2, %1\n\t"
	    "movss %1, %0"
	    : "=m" (*f3), "+x" (*f1)
	    : "x" (*f2));
}

extern __GNU_INLINE void
sse_mulss(float *f1, float *f2, float *f3)
{
	__asm__ __volatile__(
	    "mulss %2, %1\n\t"
	    "movss %1, %0"
	    : "=m" (*f3), "+x" (*f1)
	    : "x" (*f2));
}

extern __GNU_INLINE void
sse_divss(float *f1, float *f2, float *f3)
{
	__asm__ __volatile__(
	    "divss %2, %1\n\t"
	    "movss %1, %0"
	    : "=m" (*f3), "+x" (*f1)
	    : "x" (*f2));
}

extern __GNU_INLINE void
sse_sqrtss(float *f1, float *f2)
{
	double tmp;

	__asm__ __volatile__(
	    "sqrtss %2, %1\n\t"
	    "movss  %1, %0"
	    : "=m" (*f2), "=x" (tmp)
	    : "m" (*f1));
}

extern __GNU_INLINE void
sse_ucomiss(float *f1, float *f2)
{
	__asm__ __volatile__("ucomiss %1, %0" : : "x" (*f1), "x" (*f2));

}

extern __GNU_INLINE void
sse_comiss(float *f1, float *f2)
{
	__asm__ __volatile__("comiss %1, %0" : : "x" (*f1), "x" (*f2));
}

extern __GNU_INLINE void
sse_cvtss2sd(float *f1, double *d1)
{
	double tmp;

	__asm__ __volatile__(
	    "cvtss2sd %2, %1\n\t"
	    "movsd    %1, %0"
	    : "=m" (*d1), "=x" (tmp)
	    : "m" (*f1));
}

extern __GNU_INLINE void
sse_cvtsi2ss(int *i1, float *f1)
{
	double tmp;

	__asm__ __volatile__(
	    "cvtsi2ss %2, %1\n\t"
	    "movss    %1, %0"
	    : "=m" (*f1), "=x" (tmp)
	    : "m" (*i1));
}

extern __GNU_INLINE void
sse_cvttss2si(float *f1, int *i1)
{
	int tmp;

	__asm__ __volatile__(
	    "cvttss2si %2, %1\n\t"
	    "movl      %1, %0"
	    : "=m" (*i1), "=r" (tmp)
	    : "m" (*f1));
}

extern __GNU_INLINE void
sse_cvtss2si(float *f1, int *i1)
{
	int tmp;

	__asm__ __volatile__(
	    "cvtss2si %2, %1\n\t"
	    "movl     %1, %0"
	    : "=m" (*i1), "=r" (tmp)
	    : "m" (*f1));
}

#if defined(__amd64)
extern __GNU_INLINE void
sse_cvtsi2ssq(long long *ll1, float *f1)
{
	double tmp;

	__asm__ __volatile__(
	    "cvtsi2ssq %2, %1\n\t"
	    "movss     %1, %0"
	    : "=m" (*f1), "=x" (tmp)
	    : "m" (*ll1));
}

extern __GNU_INLINE void
sse_cvttss2siq(float *f1, long long *ll1)
{
	uint64_t tmp;

	__asm__ __volatile__(
	    "cvttss2siq %2, %1\n\t"
	    "movq       %1, %0"
	    : "=m" (*ll1), "=r" (tmp)
	    : "m" (*f1));
}

extern __GNU_INLINE void
sse_cvtss2siq(float *f1, long long *ll1)
{
	uint64_t tmp;

	__asm__ __volatile__(
	    "cvtss2siq %2, %1\n\t"
	    "movq      %1, %0"
	    : "=m" (*ll1), "=r" (tmp)
	    : "m" (*f1));
}

#endif

extern __GNU_INLINE void
sse_cmpeqsd(double *d1, double *d2, long long *ll1)
{
	__asm__ __volatile__(
	    "cmpeqsd %2,%1\n\t"
	    "movsd   %1,%0"
	    : "=m" (*ll1), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_cmpltsd(double *d1, double *d2, long long *ll1)
{
	__asm__ __volatile__(
	    "cmpltsd %2,%1\n\t"
	    "movsd   %1,%0"
	    : "=m" (*ll1), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_cmplesd(double *d1, double *d2, long long *ll1)
{
	__asm__ __volatile__(
	    "cmplesd %2,%1\n\t"
	    "movsd   %1,%0"
	    : "=m" (*ll1), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_cmpunordsd(double *d1, double *d2, long long *ll1)
{
	__asm__ __volatile__(
	    "cmpunordsd %2,%1\n\t"
	    "movsd      %1,%0"
	    : "=m" (*ll1), "+x" (*d1)
	    : "x" (*d2));
}


extern __GNU_INLINE void
sse_minsd(double *d1, double *d2, double *d3)
{
	__asm__ __volatile__(
	    "minsd %2,%1\n\t"
	    "movsd %1,%0"
	    : "=m" (*d3), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_maxsd(double *d1, double *d2, double *d3)
{
	__asm__ __volatile__(
	    "maxsd %2,%1\n\t"
	    "movsd %1,%0"
	    : "=m" (*d3), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_addsd(double *d1, double *d2, double *d3)
{
	__asm__ __volatile__(
	    "addsd %2,%1\n\t"
	    "movsd %1,%0"
	    : "=m" (*d3), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_subsd(double *d1, double *d2, double *d3)
{
	__asm__ __volatile__(
	    "subsd %2,%1\n\t"
	    "movsd %1,%0"
	    : "=m" (*d3), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_mulsd(double *d1, double *d2, double *d3)
{
	__asm__ __volatile__(
	    "mulsd %2,%1\n\t"
	    "movsd %1,%0"
	    : "=m" (*d3), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_divsd(double *d1, double *d2, double *d3)
{
	__asm__ __volatile__(
	    "divsd %2,%1\n\t"
	    "movsd %1,%0"
	    : "=m" (*d3), "+x" (*d1)
	    : "x" (*d2));
}

extern __GNU_INLINE void
sse_sqrtsd(double *d1, double *d2)
{
	double tmp;

	__asm__ __volatile__(
	    "sqrtsd %2, %1\n\t"
	    "movsd %1, %0"
	    : "=m" (*d2), "=x" (tmp)
	    : "m" (*d1));
}

extern __GNU_INLINE void
sse_ucomisd(double *d1, double *d2)
{
	__asm__ __volatile__("ucomisd %1, %0" : : "x" (*d1), "x" (*d2));
}

extern __GNU_INLINE void
sse_comisd(double *d1, double *d2)
{
	__asm__ __volatile__("comisd %1, %0" : : "x" (*d1), "x" (*d2));
}

extern __GNU_INLINE void
sse_cvtsd2ss(double *d1, float *f1)
{
	double tmp;

	__asm__ __volatile__(
	    "cvtsd2ss %2,%1\n\t"
	    "movss    %1,%0"
	    : "=m" (*f1), "=x" (tmp)
	    : "m" (*d1));
}

extern __GNU_INLINE void
sse_cvtsi2sd(int *i1, double *d1)
{
	double tmp;
	__asm__ __volatile__(
	    "cvtsi2sd %2,%1\n\t"
	    "movsd    %1,%0"
	    : "=m" (*d1), "=x" (tmp)
	    : "m" (*i1));
}

extern __GNU_INLINE void
sse_cvttsd2si(double *d1, int *i1)
{
	int tmp;

	__asm__ __volatile__(
	    "cvttsd2si %2,%1\n\t"
	    "movl      %1,%0"
	    : "=m" (*i1), "=r" (tmp)
	    : "m" (*d1));
}

extern __GNU_INLINE void
sse_cvtsd2si(double *d1, int *i1)
{
	int tmp;

	__asm__ __volatile__(
	    "cvtsd2si %2,%1\n\t"
	    "movl     %1,%0"
	    : "=m" (*i1), "=r" (tmp)
	    : "m" (*d1));
}

#if defined(__amd64)
extern __GNU_INLINE void
sse_cvtsi2sdq(long long *ll1, double *d1)
{
	double tmp;

	__asm__ __volatile__(
	    "cvtsi2sdq %2,%1\n\t"
	    "movsd     %1,%0"
	    : "=m" (*d1), "=x" (tmp)
	    : "m" (*ll1));
}

extern __GNU_INLINE void
sse_cvttsd2siq(double *d1, long long *ll1)
{
	uint64_t tmp;

	__asm__ __volatile__(
	    "cvttsd2siq %2,%1\n\t"
	    "movq       %1,%0"
	    : "=m" (*ll1), "=r" (tmp)
	    : "m" (*d1));
}

extern __GNU_INLINE void
sse_cvtsd2siq(double *d1, long long *ll1)
{
	uint64_t tmp;

	__asm__ __volatile__(
	    "cvtsd2siq %2,%1\n\t"
	    "movq      %1,%0"
	    : "=m" (*ll1), "=r" (tmp)
	    : "m" (*d1));
}
#endif

#elif defined(__sparc)
extern __GNU_INLINE void
__fenv_getfsr(unsigned long *l)
{
	__asm__ __volatile__(
#if defined(__sparcv9)
	    "stx %%fsr,%0\n\t"
#else
	    "st  %%fsr,%0\n\t"
#endif
	    : "=m" (*l));
}

extern __GNU_INLINE void
__fenv_setfsr(const unsigned long *l)
{
	__asm__ __volatile__(
#if defined(__sparcv9)
	    "ldx %0,%%fsr\n\t"
#else
	    "ld %0,%%fsr\n\t"
#endif
	    : : "m" (*l) : "cc");
}

extern __GNU_INLINE void
__fenv_getfsr32(unsigned int *l)
{
	__asm__ __volatile__("st %%fsr,%0\n\t" : "=m" (*l));
}

extern __GNU_INLINE void
__fenv_setfsr32(const unsigned int *l)
{
	__asm__ __volatile__("ld %0,%%fsr\n\t" : : "m" (*l));
}
#else
#error "GCC FENV inlines not implemented for this platform"
#endif

#ifdef __cplusplus
}
#endif

#endif  /* __GNUC__ */

#endif /* _FENV_INLINES_H */
