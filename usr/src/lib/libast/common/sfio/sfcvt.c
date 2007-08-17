/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1985-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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

#if __STD_C
char* _sfcvt(Sfdouble_t dv, char* buf, size_t size, int n_digit,
		int* decpt, int* sign, int* len, int format)
#else
char* _sfcvt(dv,buf,size,n_digit,decpt,sign,len,format)
Sfdouble_t	dv;		/* value to convert		*/
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
	reg char		*ep, *b, *endsp;
	_ast_flt_unsigned_max_t	m;

	static char		lx[] = "0123456789abcdef";
	static char		ux[] = "0123456789ABCDEF";

	*sign = *decpt = 0;

	if(isnanl(dv))
		return SF_NAN;
#if _lib_isinf
	if (n = isinf(dv))
	{	if (n < 0)
			*sign = 1;
		return SF_INF;
	}
#endif
#if !_ast_fltmax_double
	if(format&SFFMT_LDOUBLE)
	{	Sfdouble_t	f = dv;
#if _c99_in_the_wild
#if _lib_signbit
		if (signbit(f))
#else
#if _lib_copysignl
		if (copysignl(1.0, f) < 0.0)
#else
#if _lib_copysign
		if (copysign(1.0, (double)f) < 0.0)
#else
		if (f < 0.0)
#endif
#endif
#endif
		{	f = -f;
			*sign = 1;
		}
#if _lib_fpclassify
		switch (fpclassify(f))
		{
		case FP_INFINITE:
			return SF_INF;
		case FP_NAN:
			return SF_NAN;
		case FP_ZERO:
			return SF_ZERO;
		}
#endif
#else
		if (f < 0.0)
		{	f = -f;
			*sign = 1;
		}
#endif
		if(f < LDBL_MIN)
			return SF_ZERO;
		if(f > LDBL_MAX)
			return SF_INF;

		if(format & SFFMT_AFORMAT)
		{	Sfdouble_t	g;
			int		x;
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
					{	ep = sp + 1;
						goto done;
					}
				}
				f -= m;
				f = ldexpl(f, 8 * sizeof(m));
			}
		}

		n = 0;
		if(f >= (Sfdouble_t)SF_MAXLONG)
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
			} while(f >= (Sfdouble_t)SF_MAXLONG);
		}
		*decpt = (int)n;

		b = sp = buf + SF_INTPART;
		if((v = (long)f) != 0)
		{	/* translate the integer part */
			f -= (Sfdouble_t)v;

			sfucvt(v,sp,n,ep,long,ulong);

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
	{	double	f = (double)dv;

#if _lib_isinf
		if (n = isinf(f))
		{	if (n < 0)
				*sign = 1;
			return SF_INF;
		}
#endif
#if _c99_in_the_wild
#if _lib_signbit
		if (signbit(f))
#else
#if _lib_copysign
		if (copysign(1.0, f) < 0.0)
#else
		if (f < 0.0)
#endif
#endif
		{	f = -f;
			*sign = 1;
		}
#if _lib_fpclassify
		switch (fpclassify(f))
		{
		case FP_INFINITE:
			return SF_INF;
		case FP_NAN:
			return SF_NAN;
		case FP_ZERO:
			return SF_ZERO;
		}
#endif
#else
		if (f < 0.0)
		{	f = -f;
			*sign = 1;
		}
#endif
		if(f < DBL_MIN)
			return SF_ZERO;
		if(f > DBL_MAX)
			return SF_INF;

		if(format & SFFMT_AFORMAT)
		{	double	g;
			int	x;
			b = sp = buf;
			ep = (format & SFFMT_UPPER) ? ux : lx;
			if(n_digit <= 0 || n_digit >= (size - 9))
				n_digit = size - 9;
			endsp = sp + n_digit;

			g = frexp(f, &x);
			*decpt = x;
			f = ldexp(g, 8 * sizeof(m) - 3);

			for (;;)
			{	m = f;
				x = 8 * sizeof(m);
				while ((x -= 4) >= 0)
				{	*sp++ = ep[(m >> x) & 0xf];
					if (sp >= endsp)
					{	ep = sp + 1;
						goto done;
					}
				}
				f -= m;
				f = ldexp(f, 8 * sizeof(m));
			}
		}
		n = 0;
		if(f >= (double)SF_MAXLONG)
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
			} while(f >= (double)SF_MAXLONG);
		}
		*decpt = (int)n;

		b = sp = buf + SF_INTPART;
		if((v = (long)f) != 0)
		{	/* translate the integer part */
			f -= (double)v;

			sfucvt(v,sp,n,ep,long,ulong);

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
}
