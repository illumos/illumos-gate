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
/*
 * AT&T Research
 * Glenn Fowler & Phong Vo
 *
 * common header and implementation for
 *
 *	strtof		strtod		strtold		_sfdscan
 *	strntof		strntod		strntold
 *
 * define these macros to instantiate an implementation:
 *
 *	S2F_function	the function name
 *	S2F_static	<0:export =0:extern >0:static
 *	S2F_type	0:float 1:double 2:long.double
 *	S2F_qualifier	1 for optional [fFlL] qualifier suffix
 *	S2F_size	1 for interface with size_t second arg
 *	S2F_scan	1 for alternate interface with these arguments:
 *				void* handle
 *				int (*getchar)(void* handle, int flag)
 *			exactly one extra (*getchar)() is done, i.e.,
 *			the caller must do the pushback
 *				flag==0		get next char
 *				flag==1		no number seen
 *			return 0 on error or EOF
 */

#include "sfhdr.h"
#include "FEATURE/float"

/*
 * the default is _sfdscan for standalone sfio compatibility
 */

#if !defined(S2F_function)
#define S2F_function	_sfdscan
#define S2F_static	1
#define S2F_type	2
#define S2F_scan	1
#ifndef elementsof
#define elementsof(a)	(sizeof(a)/sizeof(a[0]))
#endif
#endif

#if S2F_type == 2 && _ast_fltmax_double
#undef	S2F_type
#define S2F_type	1
#endif

#if S2F_type == 0
#define S2F_number	float
#define S2F_ldexp	ldexp
#define S2F_pow10	_Sffpow10
#define S2F_inf		_Sffinf
#define S2F_nan		_Sffnan
#define S2F_min		(FLT_MIN)
#define S2F_max		(FLT_MAX)
#define S2F_exp_10_min	(FLT_MIN_10_EXP)
#define S2F_exp_10_max	(FLT_MAX_10_EXP)
#define S2F_exp_2_min	(FLT_MIN_EXP)
#define S2F_exp_2_max	(FLT_MAX_EXP)
#endif
#if S2F_type == 1
#define S2F_number	double
#define S2F_ldexp	ldexp
#define S2F_pow10	_Sfdpow10
#define S2F_inf		_Sfdinf
#define S2F_nan		_Sfdnan
#define S2F_min		(DBL_MIN)
#define S2F_max		(DBL_MAX)
#define S2F_exp_10_min	(DBL_MIN_10_EXP)
#define S2F_exp_10_max	(DBL_MAX_10_EXP)
#define S2F_exp_2_min	(DBL_MIN_EXP)
#define S2F_exp_2_max	(DBL_MAX_EXP)
#endif
#if S2F_type == 2
#define S2F_number	long double
#define S2F_ldexp	ldexpl
#define S2F_pow10	_Sflpow10
#define S2F_inf		_Sflinf
#define S2F_nan		_Sflnan
#define S2F_min		(LDBL_MIN)
#define S2F_max		(LDBL_MAX)
#define S2F_exp_10_min	(LDBL_MIN_10_EXP)
#define S2F_exp_10_max	(LDBL_MAX_10_EXP)
#define S2F_exp_2_min	(LDBL_MIN_EXP)
#define S2F_exp_2_max	(LDBL_MAX_EXP)
#endif

#if -S2F_exp_10_min < S2F_exp_10_max
#define S2F_exp_10_abs	(-S2F_exp_10_min)
#else
#define S2F_exp_10_abs	S2F_exp_10_max
#endif

#define S2F_batch	_ast_flt_unsigned_max_t

#undef	ERR		/* who co-opted this namespace? */

#if S2F_scan

typedef int (*S2F_get_f)_ARG_((void*, int));

#define ERR(e)
#define GET(p)		(*get)(p,0)
#define NON(p)		(*get)(p,1)
#define PUT(p)
#define REV(p,t,b)
#define SET(p,t,b)

#else

#define ERR(e)		(errno=(e))
#define NON(p)

#if S2F_size
#define GET(p)		(((p)<(z))?(*p++):(back=0))
#define PUT(p)		(end?(*end=(char*)p-back):(char*)0)
#define REV(p,t,b)	(p=t,back=b)
#define SET(p,t,b)	(t=p,b=back)
#else
#define GET(p)		(*p++)
#define PUT(p)		(end?(*end=(char*)p-1):(char*)0)
#define REV(p,t,b)	(p=t)
#define SET(p,t,b)	(t=p)
#endif

#endif

typedef struct S2F_part_s
{
	S2F_batch	batch;
	int		digits;
} S2F_part_t;

#if !defined(ERANGE)
#define ERANGE		EINVAL
#endif

#if S2F_static > 0
static
#else
#if S2F_static < 0 || !defined(S2F_static)
#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif
extern
#undef	extern
#endif
#endif
S2F_number
#if S2F_scan
#if __STD_C
S2F_function(void* s, S2F_get_f get)
#else
S2F_function(s, get) void* s; S2F_get_f get;
#endif
#else
#if S2F_size
#if __STD_C
S2F_function(const char* str, size_t size, char** end)
#else
S2F_function(str, size, end) char* str; size_t size; char** end;
#endif
#else
#if __STD_C
S2F_function(const char* str, char** end)
#else
S2F_function(str, end) char* str; char** end;
#endif
#endif
#endif
{
#if !S2F_scan
	register unsigned char*	s = (unsigned char*)str;
#if S2F_size
	register unsigned char*	z = s + size;
	int			back = 1;
	int			b;
#endif
	unsigned char*		t;
#endif
	register S2F_batch	n;
	register int		c;
	register int		digits;
	register int		m;
	register unsigned char*	cv;
	int			negative;
	int			enegative;
	int			fraction;
	int			decimal = 0;
	int			thousand = 0;
	int			part = 0;
	S2F_number		v;
	S2F_number		p;
	S2F_part_t		parts[16];

	/*
	 * radix char and thousands separator are locale specific
	 */

	SFSETLOCALE(&decimal, &thousand);
	SFCVINIT();

	/*
	 * skip initial blanks
	 */

	do c = GET(s); while (isspace(c));
	SET(s, t, b);

	/*
	 * get the sign
	 */

	if ((negative = (c == '-')) || c == '+')
		c = GET(s);

	/*
	 * drop leading 0's
	 */

	digits = 0;
	fraction = -1;
	if (c == '0')
	{
		c = GET(s);
		if (c == 'x' || c == 'X')
		{
			/*
			 * hex floating point -- easy
			 */

			cv = _Sfcv36;
			v = 0;
			for (;;)
			{
				c = GET(s);
				if ((part = cv[c]) < 16)
				{
					digits++;
					v *= 16;
					v += part;
				}
				else if (c == decimal)
				{
					decimal = -1;
					fraction = digits;
				}
				else
					break;
			}
			m = 0;
			if (c == 'p' || c == 'P')
			{
				c = GET(s);
				if ((enegative = c == '-') || c == '+')
					c = GET(s);
				while (c >= '0' && c <= '9')
				{
					m = (m << 3) + (m << 1) + (c - '0');
					c = GET(s);
				}
				if (enegative)
					m = -m;
			}

#if S2F_qualifier

			/*
			 * consume the optional suffix
			 */

			switch (c)
			{
			case 'f':
			case 'F':
			case 'l':
			case 'L':
				c = GET(s);
				break;
			}
#endif
			PUT(s);
			if (v == 0)
				return negative ? -v : v;
			if (fraction >= 0)
				m -= 4 * (digits - fraction);
			if (m < S2F_exp_2_min)
			{
				if ((m -= S2F_exp_2_min) < S2F_exp_2_min)
				{
					ERR(ERANGE);
					return 0;
				}
				v = S2F_ldexp(v, S2F_exp_2_min);
			}
			else if (m > S2F_exp_2_max)
			{
				ERR(ERANGE);
				return negative ? -S2F_inf : S2F_inf;
			}
			v = S2F_ldexp(v, m);
			goto check;
		}
		while (c == '0')
			c = GET(s);
	}
	else if (c == decimal)
	{
		decimal = -1;
		fraction = 0;
		for (;;)
		{
			c = GET(s);
			if (c != '0')
				break;
			digits++;
		}
	}
	else if (c == 'i' || c == 'I')
	{
		if ((c = GET(s)) != 'n' && c != 'N' ||
		    (c = GET(s)) != 'f' && c != 'F')
		{
			REV(s, t, b);
			PUT(s);
			return 0;
		}
		c = GET(s);
		SET(s, t, b);
		if (((c)          == 'i' || c == 'I') &&
		    ((c = GET(s)) == 'n' || c == 'N') &&
		    ((c = GET(s)) == 'i' || c == 'I') &&
		    ((c = GET(s)) == 't' || c == 'T') &&
		    ((c = GET(s)) == 'y' || c == 'Y'))
		{
			c = GET(s);
			SET(s, t, b);
		}
		REV(s, t, b);
		PUT(s);
		return negative ? -S2F_inf : S2F_inf;
	}
	else if (c == 'n' || c == 'N')
	{
		if ((c = GET(s)) != 'a' && c != 'A' ||
		    (c = GET(s)) != 'n' && c != 'N')
		{
			REV(s, t, b);
			PUT(s);
			return 0;
		}
		do c = GET(s); while (c && !isspace(c));
		PUT(s);
		return negative ? -S2F_nan : S2F_nan;
	}
	else if (c < '1' || c > '9')
	{
		REV(s, t, b);
		PUT(s);
		NON(s);
		return 0;
	}

	/*
	 * consume the integral and fractional parts
	 */

	n = 0;
	m = 0;
	for (;;)
	{
		if (c >= '0' && c <= '9')
		{
			digits++;
			n = (n << 3) + (n << 1) + (c - '0');
			if (n >= ((~((S2F_batch)0)) / 10) && part < elementsof(parts))
			{
				parts[part].batch = n;
				n = 0;
				parts[part].digits = digits;
				part++;
			}
		}
		else if (m && (digits - m) != 3)
			break;
		else if (c == decimal)
		{
			decimal = -1;
			thousand = -1;
			m = 0;
			fraction = digits;
		}
		else if (c != thousand)
			break;
		else if (!(m = digits))
			break;
		c = GET(s);
	}

	/*
	 * don't forget the last part
	 */

	if (n && part < elementsof(parts))
	{
		parts[part].batch = n;
		parts[part].digits = digits;
		part++;
	}

	/*
	 * consume the exponent
	 */

	if (fraction >= 0)
		digits = fraction;
	if (c == 'e' || c == 'E')
	{
		c = GET(s);
		if ((enegative = (c == '-')) || c == '+')
			c = GET(s);
		n = 0;
		while (c >= '0' && c <= '9')
		{
			n = (n << 3) + (n << 1) + (c - '0');
			c = GET(s);
		}
		if (enegative)
			digits -= n;
		else
			digits += n;
	}

#if S2F_qualifier

	/*
	 * consume the optional suffix
	 */

	switch (c)
	{
	case 'f':
	case 'F':
	case 'l':
	case 'L':
		c = GET(s);
		break;
	}
#endif
	PUT(s);

	/*
	 * adjust for at most one multiply per part
	 * and at most one divide overall
	 */

	v = 0;
	if (!part)
		return negative ? -v : v;
	else if ((m = parts[part-1].digits - digits) > 0)
		digits += m;
	else
		m = 0;

	/*
	 * combine the parts
	 */

	while (part--)
	{
		p = parts[part].batch;
		c = digits - parts[part].digits;
		if (c > S2F_exp_10_max)
		{
			ERR(ERANGE);
			return negative ? -S2F_inf : S2F_inf;
		}
		if (c > 0)
		{
#if _ast_mpy_overflow_fpe
			if ((S2F_max / p) < S2F_pow10[c])
			{
				ERR(ERANGE);
				return negative ? -S2F_inf : S2F_inf;
			}
#endif
			p *= S2F_pow10[c];
		}
		v += p;
	}
	if (m)
	{
		while (m > S2F_exp_10_max)
		{
			m -= S2F_exp_10_max;
			v /= S2F_pow10[S2F_exp_10_max];
		}
#if _ast_div_underflow_fpe
		if ((S2F_min * p) > S2F_pow10[c])
		{
			ERR(ERANGE);
			return negative ? -S2F_inf : S2F_inf;
		}
#endif
		v /= S2F_pow10[m];
	}

	/*
	 * check the range
	 */

 check:
	if (v < S2F_min)
	{
		ERR(ERANGE);
		v = 0;
	}
	else if (v > S2F_max)
	{
		ERR(ERANGE);
		v = S2F_inf;
	}

	/*
	 * done
	 */

	return negative ? -v : v;
}
