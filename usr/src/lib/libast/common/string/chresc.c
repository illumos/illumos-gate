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
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * return the next character in the string s
 * \ character constants are converted
 * p is updated to point to the next character in s
 */

#include <ast.h>
#include <ctype.h>

#include <ccode.h>
#if !_PACKAGE_astsa
#include <regex.h>
#endif

int
chresc(register const char* s, char** p)
{
	register const char*	q;
	register int		c;
	const char*		e;
#if !_PACKAGE_astsa
	int			n;
	char			buf[64];
#endif

	switch (c = mbchar(s))
	{
	case 0:
		s--;
		break;
	case '\\':
		switch (c = *s++)
		{
		case '0': case '1': case '2': case '3':
		case '4': case '5': case '6': case '7':
			c -= '0';
			q = s + 2;
			while (s < q)
				switch (*s)
				{
				case '0': case '1': case '2': case '3':
				case '4': case '5': case '6': case '7':
					c = (c << 3) + *s++ - '0';
					break;
				default:
					q = s;
					break;
				}
			break;
		case 'a':
			c = CC_bel;
			break;
		case 'b':
			c = '\b';
			break;
		case 'c':
		control:
			if (c = *s)
			{
				s++;
				if (islower(c))
					c = toupper(c);
			}
			c = ccmapc(c, CC_NATIVE, CC_ASCII);
			c ^= 0x40;
			c = ccmapc(c, CC_ASCII, CC_NATIVE);
			break;
		case 'C':
			if (*s == '-' && *(s + 1))
			{
				s++;
				goto control;
			}
#if !_PACKAGE_astsa
			if (*s == '[' && (n = regcollate(s + 1, (char**)&e, buf, sizeof(buf))) >= 0)
			{
				if (n == 1)
					c = buf[0];
				s = e;
			}
#endif
			break;
		case 'e':
		case 'E':
			c = CC_esc;
			break;
		case 'f':
			c = '\f';
			break;
		case 'M':
			if (*s == '-')
			{
				s++;
				c = CC_esc;
			}
			break;
		case 'n':
			c = '\n';
			break;
		case 'r':
			c = '\r';
			break;
		case 't':
			c = '\t';
			break;
		case 'v':
			c = CC_vt;
			break;
		case 'u':
		case 'U':
		case 'x':
			c = 0;
			q = c == 'u' ? (s + 4) : c == 'U' ? (s + 8) : (char*)0;
			e = s;
			while (!e || !q || s < q)
			{
				switch (*s)
				{
				case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
					c = (c << 4) + *s++ - 'a' + 10;
					continue;
				case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
					c = (c << 4) + *s++ - 'A' + 10;
					continue;
				case '0': case '1': case '2': case '3': case '4':
				case '5': case '6': case '7': case '8': case '9':
					c = (c << 4) + *s++ - '0';
					continue;
				case '{':
				case '[':
					if (s != e)
						break;
					e = 0;
					s++;
					continue;
				case '}':
				case ']':
					if (!e)
						s++;
					break;
				default:
					break;
				}
				break;
			}
			break;
		case 0:
			s--;
			break;
		}
		break;
	}
	if (p)
		*p = (char*)s;
	return c;
}
