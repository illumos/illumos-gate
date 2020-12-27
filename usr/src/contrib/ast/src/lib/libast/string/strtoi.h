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
/*
 * AT&T Research
 * Glenn Fowler
 * Phong Vo
 *
 * common header and implementation for
 *
 *	strtol		strtoul		strton
 *	strtoll		strtoull	strtonll
 *	strntol		strntoul	strnton
 *	strntoll	strntoull	strntonll
 *
 * define these macros to instantiate an implementation:
 *
 *	S2I_function	the function name
 *	S2I_number	the signed number type
 *	S2I_unumber	the unsigned number type
 *	S2I_unsigned	1 for unsigned, 0 for signed
 *	S2I_qualifier	1 for optional qualifier suffix, 0 otherwise
 *	S2I_multiplier	1 for optional multiplier suffix, 0 otherwise
 *	S2I_size	the second argument is the input string size
 *
 * convert string to number
 * errno=ERANGE on overflow (LONG_MAX) or underflow (LONG_MIN)
 * if non-null e will point to first unrecognized char in s
 * if basep!=0 it points to the default base on input and
 * will point to the explicit base on return
 * a default base of 0 will determine the base from the input
 * a default base of 1 will determine the base from the input using bb#*
 * a base prefix in the string overrides *b
 * *b will not be set if the string has no base prefix
 * if m>1 and no multipler was specified then the result is multiplied by m
 * if m<0 then multipliers are not consumed
 * if a base arg or prefix is specified then multiplier is not consumed
 *
 * integer numbers are of the form:
 *
 *	[sign][base][number[qualifier]][multiplier]
 *
 *	base:		nnn#		base nnn
 *			0[xX]		hex
 *			0		octal
 *			[1-9]		decimal
 *
 *	number:		[0-9a-zA-Z]*
 *
 *	qualifier:	[lL]
 *			[uU]
 *			[uU][lL] 
 *			[lL][uU]
 *			[lL][lL][uU]
 *			[uU][lL][lL]
 *
 *	multiplier:	.		pseudo-float if m>1
 *			[bB]		block (512)
 *			[cC]		char (1)
 *			[gG]		giga (1000*1000*1000)
 *			[gG]i		gibi (1024*1024*1024)
 *			[kK]		kilo (1000)
 *			[kK]i		kibi (1024)
 *			[mM]		mega (1000*1000)
 *			[mM]i		mibi (1024*1024)
 */

#include <ast.h>
#include <ctype.h>

#include "sfhdr.h"

#if !__STD_C && !defined(const)
#define const
#endif

#ifndef ERANGE
#define ERANGE		EINVAL
#endif

#define QL		01
#define QU		02

#define S2I_umax	(~((S2I_unumber)0))

#if S2I_unsigned
#define S2I_type	S2I_unumber
#define S2I_min		0
#define S2I_max		S2I_umax
#else
#define S2I_type	S2I_number
#define S2I_min		(-S2I_max-1)
#define S2I_max		(S2I_umax>>1)
#endif

#if S2I_size
#define S2I_valid(s)	((s)<(z))
#else
#define S2I_valid(s)	1
#endif

#define ADDOVER(n,c,s)	((S2I_umax-(n))<((S2I_unumber)((c)+(s))))
#define MPYOVER(n,c)	(((S2I_unumber)(n))>(S2I_umax/(c)))

static const S2I_unumber	mm[] =
{
	0,
	S2I_umax /  1,
	S2I_umax /  2,
	S2I_umax /  3,
	S2I_umax /  4,
	S2I_umax /  5,
	S2I_umax /  6,
	S2I_umax /  7,
	S2I_umax /  8,
	S2I_umax /  9,
	S2I_umax / 10,
	S2I_umax / 11,
	S2I_umax / 12,
	S2I_umax / 13,
	S2I_umax / 14,
	S2I_umax / 15,
	S2I_umax / 16,
	S2I_umax / 17,
	S2I_umax / 18,
	S2I_umax / 19,
	S2I_umax / 20,
	S2I_umax / 21,
	S2I_umax / 22,
	S2I_umax / 23,
	S2I_umax / 24,
	S2I_umax / 25,
	S2I_umax / 26,
	S2I_umax / 27,
	S2I_umax / 28,
	S2I_umax / 29,
	S2I_umax / 30,
	S2I_umax / 31,
	S2I_umax / 32,
	S2I_umax / 33,
	S2I_umax / 34,
	S2I_umax / 35,
	S2I_umax / 36,
	S2I_umax / 37,
	S2I_umax / 38,
	S2I_umax / 39,
	S2I_umax / 40,
	S2I_umax / 41,
	S2I_umax / 42,
	S2I_umax / 43,
	S2I_umax / 44,
	S2I_umax / 45,
	S2I_umax / 46,
	S2I_umax / 47,
	S2I_umax / 48,
	S2I_umax / 49,
	S2I_umax / 50,
	S2I_umax / 51,
	S2I_umax / 52,
	S2I_umax / 53,
	S2I_umax / 54,
	S2I_umax / 55,
	S2I_umax / 56,
	S2I_umax / 57,
	S2I_umax / 58,
	S2I_umax / 59,
	S2I_umax / 60,
	S2I_umax / 61,
	S2I_umax / 62,
	S2I_umax / 63,
	S2I_umax / 64,
};

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif
extern S2I_type
#undef	extern
#if S2I_size
#if S2I_multiplier
#if __STD_C
S2I_function(const char* a, size_t size, char** e, char* basep, int m)
#else
S2I_function(a, size, e, basep, m) const char* a; size_t size; char** e; char* basep; int m;
#endif
#else
#if __STD_C
S2I_function(const char* a, size_t size, char** e, int base)
#else
S2I_function(a, size, e, base) const char* a; size_t size; char** e; int base;
#endif
#endif
#else
#if S2I_multiplier
#if __STD_C
S2I_function(const char* a, char** e, char* basep, int m)
#else
S2I_function(a, e, basep, m) const char* a; char** e; char* basep; int m;
#endif
#else
#if __STD_C
S2I_function(const char* a, char** e, int base)
#else
S2I_function(a, e, base) const char* a; char** e; int base;
#endif
#endif
#endif
{
	register unsigned char*	s = (unsigned char*)a;
#if S2I_size
	register unsigned char*	z = s + size;
#endif
	register S2I_unumber	n;
	register S2I_unumber	x;
	register int		c;
	register int		shift;
	register unsigned char*	p;
	register unsigned char*	cv;
	unsigned char*		b;
	unsigned char*		k;
	S2I_unumber		v;
#if S2I_multiplier
	register int		base;
#endif
	int			negative;
	int			overflow = 0;
	int			decimal = 0;
	int			thousand = 0;
#if !S2I_unsigned
	int			qualifier = 0;
#endif

#if S2I_multiplier
	base = basep ? *((unsigned char*)basep) : 0;
#else
	if (base > 36 && base <= SF_RADIX)
	{
		static int	conformance = -1;

		if (conformance < 0)
			conformance = !strcmp(astconf("CONFORMANCE", NiL, NiL), "standard");
		if (conformance)
			base = 1;
	}
#endif
	if (base && (base < 2 || base > SF_RADIX))
	{
		errno = EINVAL;
		return 0;
	}
	while (S2I_valid(s) && isspace(*s))
		s++;
	if ((negative = S2I_valid(s) && (*s == '-')) || S2I_valid(s) && *s == '+')
		k = ++s;
	else
		k = 0;
	p = s;
	if (!base)
	{
		if (S2I_valid(p) && (c = *p++) >= '0' && c <= '9')
		{
			n = c - '0';
			if (S2I_valid(p) && (c = *p) >= '0' && c <= '9')
			{
				n = (n << 3) + (n << 1) + c - '0';
				p++;
			}
			if (S2I_valid(p) && *p == '#')
			{
				if (n >= 2 && n <= 64)
				{
					k = s = p + 1;
					base = n;
				}
			}
			else if (base)
				base = 0;
			else if (S2I_valid(s) && *s == '0' && S2I_valid(s + 1))
			{
				if ((c = *(s + 1)) == 'x' || c == 'X')
				{
					k = s += 2;
					base = 16;
				}
				else if (c >= '0' && c <= '7')
				{
					s++;
					base = 8;
				}
			}
		}
		if (!base)
			base = 10;
		else if (base < 2 || base > SF_RADIX)
		{
			errno = EINVAL;
			return 0;
		}
#if S2I_multiplier
		else
		{
			if (basep)
				*basep = base;
			m = -1;
		}
#endif
	}
#if S2I_multiplier
	else
		m = -1;
#endif

	/*
	 * this part transcribed from sfvscanf()
	 */

	SFSETLOCALE(&decimal, &thousand);
	x = mm[base];
	n = 0;
	if (base == 10)
	{
		b = s;
		p = 0;
		for (;;)
		{
			if (S2I_valid(s) && (c = *s++) >= '0' && c <= '9')
			{
				if (n > x)
					overflow = 1;
				else
				{
					n = (n << 3) + (n << 1);
					c -= '0';
					if (ADDOVER(n, c, negative))
						overflow = 1;
					n += c;
				}
			}
			else if (p && (s - p) != (3 + S2I_valid(s)))
			{
				s = p;
				n = v;
				c = 0;
				break;
			}
			else if (!S2I_valid(s) || c != thousand)
				break;
			else if (!p && (s - b) > 4)
			{
				if (e)
					*e = (char*)s - 1;
				if (overflow)
				{
					errno = ERANGE;
#if S2I_unsigned
					n = S2I_max;
#else
					n = negative ? S2I_min : S2I_max;
#endif
				}
				return n;
			}
			else
			{
				p = s;
				v = n;
			}
		}
	}
	else
	{
		SFCVINIT();
		cv = base <= 36 ? _Sfcv36 : _Sfcv64;
		if ((base & ~(base - 1)) == base)
		{	
#if !S2I_unsigned
			qualifier |= QU;
#endif
			if (base < 8)
				shift = base <  4 ? 1 : 2;
			else if (base < 32)
				shift = base < 16 ? 3 : 4;
			else
				shift = base < 64 ? 5 : 6;
			while (S2I_valid(s) && (c = cv[*s++]) < base)
			{
				if (n > x)
					overflow = 1;
				else
				{
					n <<= shift;
					if (ADDOVER(n, c, negative))
						overflow = 1;
					n += c;
				}
			}
		}
		else
			while (S2I_valid(s) && (c = cv[*s++]) < base)
			{
				if (n > x)
					overflow = 1;
				else
				{
					n *= base;
					if (ADDOVER(n, c, negative))
						overflow = 1;
					n += c;
				}
			}
		c = *(s - 1);
	}

#if S2I_qualifier

	/*
	 * optional qualifier suffix
	 */

	if (S2I_valid(s) && s > (unsigned char*)(a + 1))
	{
		base = 0;
		for (;;)
		{
			if (!(base & QL) && (c == 'l' || c == 'L'))
			{
				base |= QL;
				if (!S2I_valid(s))
					break;
				c = *s++;
				if (c == 'l' || c == 'L')
				{
					if (!S2I_valid(s))
						break;
					c = *s++;
				}
			}
			else if (!(base & QU) && (c == 'u' || c == 'U'))
			{
				base |= QU;
#if !S2I_unsigned
				qualifier |= QU;
#endif
				if (!S2I_valid(s))
					break;
				c = *s++;
			}
			else
				break;
		}
	}
#endif
	if (S2I_valid(s))
	{
#if S2I_multiplier
		/*
		 * optional multiplier suffix
		 */

		if (m < 0 || s == (unsigned char*)(a + 1))
			s--;
		else
		{
			x = m != 1;
			switch (c)
			{
			case 'b':
			case 'B':
				shift = 9;
				x = 0;
				break;
			case 'k':
			case 'K':
				shift = 10;
				break;
			case 'm':
			case 'M':
				shift = 20;
				break;
			case 'g':
			case 'G':
				shift = 30;
				break;
			case 't':
			case 'T':
				shift = 40;
				break;
			case 'p':
			case 'P':
				shift = 50;
				break;
			case 'e':
			case 'E':
				shift = 60;
				break;
			default:
				if (m <= 1)
					v = 0;
				else if (c == decimal && S2I_valid(s))
				{
					if (MPYOVER(n, m))
						overflow = 1;
					n *= m;
					v = 0;
					while (S2I_valid(s) && (c = *s++) >= '0' && c <= '9')
						v += (m /= 10) * (c - '0');
					if (ADDOVER(n, v, negative))
						overflow = 1;
					n += v;
					v = 0;
				}
				else
					v = m;
				s--;
				shift = 0;
				break;
			}
			if (shift)
			{
				if (S2I_valid(s))
					switch (*s)
					{
					case 'i':
					case 'I':
						s++;
						x = 0;
						break;
					}
				if (S2I_valid(s))
					switch (*s)
					{
					case 'b':
					case 'B':
						s++;
						break;
					}
				if (x)
				{
					v = 1;
					for (shift /= 10; shift; shift--)
					{
						if (v >= (S2I_max/1000))
						{
							v = 0;
							overflow = 1;
						}
						v *= 1000;
					}
				}
				else
#if S2I_unsigned
				if (shift >= (sizeof(S2I_type) * CHAR_BIT))
#else
				if (shift >= (sizeof(S2I_type) * CHAR_BIT - 1))
#endif
				{
					v = 0;
					overflow = 1;
				}
				else
					v = ((S2I_unumber)1) << shift;
			}
			if (v)
			{
				if (MPYOVER(n, v))
					overflow = 1;
				n *= v;
			}
		}
#else
		s--;
#endif
	}
	if (s == k)
	{
		s--;
#if S2I_multiplier
		if (basep)
			*basep = 10;
#endif
	}
#if !S2I_unsigned
	else if (!(qualifier & QU))
	{
		if (negative)
		{
			if (!n)
			{
				b = k;
				do
				{
					if (b >= s)
					{
						negative = 0;
						break;
					}
				} while (*b++ == '0');
			}
			if (negative && (n - 1) > S2I_max)
				overflow = 1;
		}
		else if (n > S2I_max)
			overflow = 1;
	}
#endif
	if (e)
		*e = (char*)s;
	if (overflow)
	{
#if !S2I_unsigned
		if (negative)
		{
			if (x << 1)
				errno = ERANGE;
			return (S2I_type)S2I_min;
		}
#endif
		errno = ERANGE;
		return (S2I_type)S2I_max;
	}
	return negative ? -n : n;
}
