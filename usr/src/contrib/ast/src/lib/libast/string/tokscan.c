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
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * scan s for tokens in fmt
 * s modified in place and not restored
 * if nxt!=0 then it will point to the first unread char in s
 * the number of scanned tokens is returned
 * -1 returned if s was not empty and fmt failed to match
 *
 * ' ' in fmt matches 0 or more {space,tab}
 * '\n' in fmt eats remainder of current line
 * "..." and '...' quotes interpreted
 * newline is equivalent to end of buf except when quoted
 * \\ quotes following char
 *
 * message support for %s and %v data
 *
 *	(5:12345)		fixed length strings, ) may be \t
 *	(null)			NiL
 *
 * "..." and '...' may span \n, and \\n is the line splice
 * quoted '\r' translated to '\n'
 * otherwise tokenizing is unconditionally terminated by '\n'
 *
 * a null arg pointer skips that arg
 *
 *	%c		char
 *	%[hl]d		[short|int|long] base 10
 *	%f		double
 *	%g		double
 *	%[hl]n		[short|int|long] C-style base
 *	%[hl]o		[short|int|long] base 8
 *	%s		string
 *	%[hl]u		same as %[hl]n
 *	%v		argv, elements
 *	%[hl]x		[short|int|long] base 16
 *
 * unmatched char args are set to "", int args to 0
 */

#include <ast.h>
#include <tok.h>

static char	empty[1];

/*
 * get one string token into p
 */

static char*
lextok(register char* s, register int c, char** p, int* n)
{
	register char*	t;
	register int	q;
	char*		b;
	char*		u;

	if (*s == '(' && (!c || c == ' ' || c == '\n'))
	{
		q = strtol(s + 1, &b, 10);
		if (*b == ':')
		{
			if (*(t = ++b + q) == ')' || *t == '\t')
			{
				s = t;
				*s++ = 0;
				goto end;
			}
		}
		else if (strneq(b, "null)", 5))
		{
			s = b + 5;
			b = 0;
			goto end;
		}
	}
	b = s;
	q = 0;
	t = 0;
	for (;;)
	{
		if (!*s || !q && *s == '\n')
		{
			if (!q)
			{
				if (!c || c == ' ' || c == '\n') (*n)++;
				else
				{
					s = b;
					b = empty;
					break;
				}
			}
			if (t) *t = 0;
			break;
		}
		else if (*s == '\\')
		{
			u = s;
			if (!*++s || *s == '\n' && (!*++s || *s == '\n')) continue;
			if (p)
			{
				if (b == u) b = s;
				else if (!t) t = u;
			}
		}
		else if (q)
		{
			if (*s == q)
			{
				q = 0;
				if (!t) t = s;
				s++;
				continue;
			}
			else if (*s == '\r') *s = '\n';
		}
		else if (*s == '"' || *s == '\'')
		{
			q = *s++;
			if (p)
			{
				if (b == (s - 1)) b = s;
				else if (!t) t = s - 1;
			}
			continue;
		}
		else if (*s == c || c == ' ' && *s == '\t')
		{
			*s++ = 0;
			if (t) *t = 0;
		end:
			if (c == ' ') while (*s == ' ' || *s == '\t') s++;
			(*n)++;
			break;
		}
		if (t) *t++ = *s;
		s++;
	}
	if (p) *p = b;
	return(s);
}

/*
 * scan entry
 */

int
tokscan(register char* s, char** nxt, const char* fmt, ...)
{
	register int	c;
	register char*	f;
	int		num = 0;
	char*		skip = 0;
	int		q;
	int		onum;
	long		val;
	double		dval;
	va_list		ap;
	char*		p_char;
	double*		p_double;
	int*		p_int;
	long*		p_long;
	short*		p_short;
	char**		p_string;
	char*		prv_f = 0;
	va_list		prv_ap;

	va_start(ap, fmt);
	if (!*s || *s == '\n')
	{
		skip = s;
		s = empty;
	}
	f = (char*)fmt;
	for (;;) switch (c = *f++)
	{
	case 0:
		if (f = prv_f)
		{
			prv_f = 0;
			/* prv_ap value is guarded by prv_f */
			va_copy(ap, prv_ap);
			continue;
		}
		goto done;
	case ' ':
		while (*s == ' ' || *s == '\t') s++;
		break;
	case '%':
		onum = num;
		switch (c = *f++)
		{
		case 'h':
		case 'l':
			q = c;
			c = *f++;
			break;
		default:
			q = 0;
			break;
		}
		switch (c)
		{
		case 0:
		case '%':
			f--;
			continue;
		case ':':
			prv_f = f;
			f = va_arg(ap, char*);
			va_copy(prv_ap, ap);
			va_copy(ap, va_listval(va_arg(ap, va_listarg)));
			continue;
		case 'c':
			p_char = va_arg(ap, char*);
			if (!(c = *s) || c == '\n')
			{
				if (p_char) *p_char = 0;
			}
			else
			{
				if (p_char) *p_char = c;
				s++;
				num++;
			}
			break;
		case 'd':
		case 'n':
		case 'o':
		case 'u':
		case 'x':
			switch (c)
			{
			case 'd':
				c = 10;
				break;
			case 'n':
			case 'u':
				c = 0;
				break;
			case 'o':
				c = 8;
				break;
			case 'x':
				c = 16;
				break;
			}
			if (!*s || *s == '\n')
			{
				val = 0;
				p_char = s;
			}
			else val = strtol(s, &p_char, c);
			switch (q)
			{
			case 'h':
				if (p_short = va_arg(ap, short*)) *p_short = (short)val;
				break;
			case 'l':
				if (p_long = va_arg(ap, long*)) *p_long = val;
				break;
			default:
				if (p_int = va_arg(ap, int*)) *p_int = (int)val;
				break;
			}
			if (s != p_char)
			{
				s = p_char;
				num++;
			}
			break;
		case 'f':
		case 'g':
			if (!*s || *s == '\n')
			{
				dval = 0;
				p_char = s;
			}
			else dval = strtod(s, &p_char);
			if (p_double = va_arg(ap, double*)) *p_double = dval;
			if (s != p_char)
			{
				s = p_char;
				num++;
			}
			break;
		case 's':
			p_string = va_arg(ap, char**);
			if (q = *f) f++;
			if (!*s || *s == '\n')
			{
				if (p_string) *p_string = s;
			}
			else s = lextok(s, q, p_string, &num);
			break;
		case 'v':
			p_string = va_arg(ap, char**);
			c = va_arg(ap, int);
			if (q = *f) f++;
			if ((!*s || *s == '\n') && p_string)
			{
				*p_string = 0;
				p_string = 0;
			}
			while (*s && *s != '\n' && --c > 0)
			{
				s = lextok(s, q, p_string, &num);
				if (p_string) p_string++;
			}
			if (p_string) *p_string = 0;
			break;
		}
		if (skip) num = onum;
		else if (num == onum)
		{
			if (!num) num = -1;
			skip = s;
			s = empty;
		}
		break;
	case '\n':
		goto done;
	default:
		if ((*s++ != c) && !skip)
		{
			skip = s - 1;
			s = empty;
		}
		break;
	}
 done:
	va_end(ap);
	if (*s == '\n') *s++ = 0;
	if (nxt) *nxt = skip ? skip : s;
	return(num);
}
