/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
#if __STDC__
#include	"FEATURE/isoc99"
#endif
#include	"sfhdr.h"

/*	Convert a floating point value to ASCII.
**
**	Written by Kiem-Phong Vo and Glenn Fowler (SFFMT_AFORMAT)
*/

static char		*lc_inf = "inf", *uc_inf = "INF";
static char		*lc_nan = "nan", *uc_nan = "NAN";
static char		*Zero = "0";
#define SF_INF		((_Sfi = 3), strncpy(buf, (format & SFFMT_UPPER) ? uc_inf : lc_inf, size))
#define SF_NAN		((_Sfi = 3), strncpy(buf, (format & SFFMT_UPPER) ? uc_nan : lc_nan, size))
#define SF_ZERO		((_Sfi = 1), strncpy(buf, Zero, size))
#define SF_INTPART	(SF_IDIGITS/2)

#if ! _lib_isnan
#if _lib_fpclassify
#define isnan(n)	(fpclassify(n)==FP_NAN)
#define isnanl(n)	(fpclassify(n)==FP_NAN)
#else
#define isnan(n)	(memcmp((void*)&n,(void*)&_Sfdnan,sizeof(n))==0)
#define isnanl(n)	(memcmp((void*)&n,(void*)&_Sflnan,sizeof(n))==0)
#endif
#else
#if ! _lib_isnanl
#define isnanl(n)	isnan(n)
#endif
#endif

#if ! _lib_signbit && defined(signbit)
#undef	_lib_signbit
#define _lib_signbit	1
#endif

#if ! _lib_signbit
#if ! _ast_fltmax_double
static int neg0ld(Sfdouble_t f)
{
	Sfdouble_t	z = -0.0;
	return !memcmp(&f, &z, sizeof(f));
}
#endif
static int neg0d(double f)
{
	double		z = -0.0;
	return !memcmp(&f, &z, sizeof(f));
}
#endif

#if ULONG_DIG && ULONG_DIG < (DBL_DIG-1)
#define CVT_LDBL_INT	long
#define CVT_LDBL_MAXINT	LONG_MAX
#else
#if UINT_DIG && UINT_DIG < (DBL_DIG-1)
#define CVT_LDBL_INT	int
#define CVT_LDBL_MAXINT	INT_MAX
#else
#define CVT_LDBL_INT	long
#define CVT_LDBL_MAXINT	SF_MAXLONG
#endif
#endif

#if ULONG_DIG && ULONG_DIG < (DBL_DIG-1)
#define CVT_DBL_INT	long
#define CVT_DBL_MAXINT	LONG_MAX
#else
#if UINT_DIG && UINT_DIG < (DBL_DIG-1)
#define CVT_DBL_INT	int
#define CVT_DBL_MAXINT	INT_MAX
#else
#define CVT_DBL_INT	long
#define CVT_DBL_MAXINT	SF_MAXLONG
#endif
#endif

#if __STD_C
char* _sfcvt(Void_t* vp, char* buf, size_t size, int n_digit,
		int* decpt, int* sign, int* len, int format)
#else
char* _sfcvt(vp,buf,size,n_digit,decpt,sign,len,format)
Void_t*		vp;		/* pointer to value to convert	*/
char*		buf;		/* conversion goes here		*/
size_t		size;		/* size of buf			*/
int		n_digit;	/* number of digits wanted	*/
int*		decpt;		/* to return decimal point	*/
int*		sign;		/* to return sign		*/
int*		len;		/* return string length		*/
int		format;		/* conversion format		*/
#endif
{
	reg char		*sp;
	reg long		n, v;
	reg char		*ep, *b, *endsp, *t;
	int			x;
	_ast_flt_unsigned_max_t	m;

	static char		lx[] = "0123456789abcdef";
	static char		ux[] = "0123456789ABCDEF";

	*sign = *decpt = 0;

#if !_ast_fltmax_double
	if(format&SFFMT_LDOUBLE)
	{	Sfdouble_t	f = *(Sfdouble_t*)vp;

		if(isnanl(f))
		{	
#if _lib_signbit
			if (signbit(f))
#else
			if (f < 0)
#endif
				*sign = 1;
			return SF_NAN;
		}
#if _lib_isinf
		if (n = isinf(f))
		{	
#if _lib_signbit
			if (signbit(f))
#else
			if (n < 0 || f < 0)
#endif
				*sign = 1;
			return SF_INF;
		}
#endif
# if _c99_in_the_wild
#  if _lib_signbit
		if (signbit(f))
#  else
#   if _lib_copysignl
		if (copysignl(1.0, f) < 0.0)
#   else
#    if _lib_copysign
		if (copysign(1.0, (double)f) < 0.0)
#    else
		if (f < 0.0)
#    endif
#   endif
#  endif
		{	f = -f;
			*sign = 1;
		}
#  if _lib_fpclassify
		switch (fpclassify(f))
		{
		case FP_INFINITE:
			return SF_INF;
		case FP_NAN:
			return SF_NAN;
		case FP_ZERO:
			return SF_ZERO;
		}
#  endif
# else
#  if _lib_signbit
		if (signbit(f))
#  else
		if (f < 0.0 || f == 0.0 && neg0ld(f))
#  endif
		{	f = -f;
			*sign = 1;
		}
# endif
		if(f < LDBL_MIN)
			return SF_ZERO;
		if(f > LDBL_MAX)
			return SF_INF;

		if(format & SFFMT_AFORMAT)
		{	Sfdouble_t	g;
			b = sp = buf;
			ep = (format & SFFMT_UPPER) ? ux : lx;
			if(n_digit <= 0 || n_digit >= (size - 9))
				n_digit = size - 9;
			endsp = sp + n_digit + 1;

			g = frexpl(f, &x);
			*decpt = x;
			f = ldexpl(g, 8 * sizeof(m) - 3);

			for (;;)
			{	m = f;
				x = 8 * sizeof(m);
				while ((x -= 4) >= 0)
				{	*sp++ = ep[(m >> x) & 0xf];
					if (sp >= endsp)
						goto around;
				}
				f -= m;
				f = ldexpl(f, 8 * sizeof(m));
			}
		}

		n = 0;
		if(f >= (Sfdouble_t)CVT_LDBL_MAXINT)
		{	/* scale to a small enough number to fit an int */
			v = SF_MAXEXP10-1;
			do
			{	if(f < _Sfpos10[v])
					v -= 1;
				else
				{
					f *= _Sfneg10[v];
					if((n += (1<<v)) >= SF_IDIGITS)
						return SF_INF;
				}
			} while(f >= (Sfdouble_t)CVT_LDBL_MAXINT);
		}
		else if(f > 0.0 && f < 0.1)
		{	/* scale to avoid excessive multiply by 10 below */
			v = SF_MAXEXP10-1;
			do
			{	if(f <= _Sfneg10[v])
				{	f *= _Sfpos10[v];
					if((n += (1<<v)) >= SF_IDIGITS)
						return SF_INF;
				}
				else if (--v < 0)
					break;
			} while(f < 0.1);
			n = -n;
		}
		*decpt = (int)n;

		b = sp = buf + SF_INTPART;
		if((v = (CVT_LDBL_INT)f) != 0)
		{	/* translate the integer part */
			f -= (Sfdouble_t)v;

			sfucvt(v,sp,n,ep,CVT_LDBL_INT,unsigned CVT_LDBL_INT);

			n = b-sp;
			if((*decpt += (int)n) >= SF_IDIGITS)
				return SF_INF;
			b = sp;
			sp = buf + SF_INTPART;
		}
		else	n = 0;

		/* remaining number of digits to compute; add 1 for later rounding */
		n = (((format&SFFMT_EFORMAT) || *decpt <= 0) ? 1 : *decpt+1) - n;
		if(n_digit > 0)
		{	if(n_digit > LDBL_DIG)
				n_digit = LDBL_DIG;
			n += n_digit;
		}

		if((ep = (sp+n)) > (endsp = buf+(size-2)))
			ep = endsp; 
		if(sp > ep)
			sp = ep;
		else
		{
			if((format&SFFMT_EFORMAT) && *decpt == 0 && f > 0.)
			{	Sfdouble_t	d;
				while((long)(d = f*10.) == 0)
				{	f = d;
					*decpt -= 1;
				}
			}

			while(sp < ep)
			{	/* generate fractional digits */
				if(f <= 0.)
				{	/* fill with 0's */
					do { *sp++ = '0'; } while(sp < ep);
					goto done;
				}
				else if((n = (long)(f *= 10.)) < 10)
				{	*sp++ = '0' + n;
					f -= n;
				}
				else /* n == 10 */
				{	do { *sp++ = '9'; } while(sp < ep);
				}
			}
		}
	} else
#endif
	{	double	f = *(double*)vp;

		if(isnan(f))
		{	
#if _lib_signbit
			if (signbit(f))
#else
			if (f < 0)
#endif
				*sign = 1;
			return SF_NAN;
		}
#if _lib_isinf
		if (n = isinf(f))
		{	
#if _lib_signbit
			if (signbit(f))
#else
			if (n < 0 || f < 0)
#endif
				*sign = 1;
			return SF_INF;
		}
#endif
#if _c99_in_the_wild
# if _lib_signbit
		if (signbit(f))
# else
#  if _lib_copysign
		if (copysign(1.0, f) < 0.0)
#  else
		if (f < 0.0)
#  endif
# endif
		{	f = -f;
			*sign = 1;
		}
# if _lib_fpclassify
		switch (fpclassify(f))
		{
		case FP_INFINITE:
			return SF_INF;
		case FP_NAN:
			return SF_NAN;
		case FP_ZERO:
			return SF_ZERO;
		}
# endif
#else
# if _lib_signbit
		if (signbit(f))
# else
		if (f < 0.0 || f == 0.0 && neg0d(f))
# endif
		{	f = -f;
			*sign = 1;
		}
#endif
		if(f < DBL_MIN)
			return SF_ZERO;
		if(f > DBL_MAX)
			return SF_INF;

		if(format & SFFMT_AFORMAT)
		{	double		g;
			b = sp = buf;
			ep = (format & SFFMT_UPPER) ? ux : lx;
			if(n_digit <= 0 || n_digit >= (size - 9))
				n_digit = size - 9;
			endsp = sp + n_digit + 1;

			g = frexp(f, &x);
			*decpt = x;
			f = ldexp(g, 8 * sizeof(m) - 3);

			for (;;)
			{	m = f;
				x = 8 * sizeof(m);
				while ((x -= 4) >= 0)
				{	*sp++ = ep[(m >> x) & 0xf];
					if (sp >= endsp)
						goto around;
				}
				f -= m;
				f = ldexp(f, 8 * sizeof(m));
			}
		}
		n = 0;
		if(f >= (double)CVT_DBL_MAXINT)
		{	/* scale to a small enough number to fit an int */
			v = SF_MAXEXP10-1;
			do
			{	if(f < _Sfpos10[v])
					v -= 1;
				else
				{	f *= _Sfneg10[v];
					if((n += (1<<v)) >= SF_IDIGITS)
						return SF_INF;
				}
			} while(f >= (double)CVT_DBL_MAXINT);
		}
		else if(f > 0.0 && f < 1e-8)
		{	/* scale to avoid excessive multiply by 10 below */
			v = SF_MAXEXP10-1;
			do
			{	if(f <= _Sfneg10[v])
				{	f *= _Sfpos10[v];
					if((n += (1<<v)) >= SF_IDIGITS)
						return SF_INF;
				}
				else if(--v < 0)
					break;
			} while(f < 0.1);
			n = -n;
		}
		*decpt = (int)n;

		b = sp = buf + SF_INTPART;
		if((v = (CVT_DBL_INT)f) != 0)
		{	/* translate the integer part */
			f -= (double)v;

			sfucvt(v,sp,n,ep,CVT_DBL_INT,unsigned CVT_DBL_INT);

			n = b-sp;
			if((*decpt += (int)n) >= SF_IDIGITS)
				return SF_INF;
			b = sp;
			sp = buf + SF_INTPART;
		}
		else	n = 0;

		/* remaining number of digits to compute; add 1 for later rounding */
		n = (((format&SFFMT_EFORMAT) || *decpt <= 0) ? 1 : *decpt+1) - n;
		if(n_digit > 0)
		{	if(n_digit > DBL_DIG)
				n_digit = DBL_DIG;
			n += n_digit;
		}

		if((ep = (sp+n)) > (endsp = buf+(size-2)))
			ep = endsp; 
		if(sp > ep)
			sp = ep;
		else
		{
			if((format&SFFMT_EFORMAT) && *decpt == 0 && f > 0.)
			{	reg double	d;
				while((long)(d = f*10.) == 0)
				{	f = d;
					*decpt -= 1;
				}
			}

			while(sp < ep)
			{	/* generate fractional digits */
				if(f <= 0.)
				{	/* fill with 0's */
					do { *sp++ = '0'; } while(sp < ep);
					goto done;
				}
				else if((n = (long)(f *= 10.)) < 10)
				{	*sp++ = (char)('0' + n);
					f -= n;
				}
				else /* n == 10 */
				{	do { *sp++ = '9'; } while(sp < ep);
					break;
				}
			}
		}
	}

	if(ep <= b)
		ep = b+1;
	else if(ep < endsp)
	{	/* round the last digit */
		*--sp += 5;
		while(*sp > '9')
		{	*sp = '0';
			if(sp > b)
				*--sp += 1;
			else
			{	/* next power of 10 */
				*sp = '1';
				*decpt += 1;
				if(!(format&SFFMT_EFORMAT))
				{	/* add one more 0 for %f precision */
					ep[-1] = '0';
					ep += 1;
				}
			}
		}
	}

 done:
	*--ep = '\0';
	if(len)
		*len = ep-b;
	return b;
 around:
	if (((m >> x) & 0xf) >= 8)
	{	t = sp - 1;
		for (;;)
		{	if (--t <= b)
			{	(*decpt)++;
				break;
			}
			switch (*t)
			{
			case 'f':
			case 'F':
				*t = '0';
				continue;
			case '9':
				*t = ep[10];
				break;
			default:
				(*t)++;
				break;
			}
			break;
		}
	}
	ep = sp + 1;
	goto done;
}
