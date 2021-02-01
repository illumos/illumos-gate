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
 */

#include <ast.h>
#include <ccode.h>
#include <ctype.h>

#if CC_NATIVE == CC_ASCII
#define MAP(m,c)	(c)
#else
#define MAP(m,c)	m[c]
#endif

/*
 * return a pointer to the isalpha() identifier matching
 * name in the CC_ASCII sorted tab of num elements of
 * size siz where the first member of each
 * element is a char*
 *
 * [xxx] brackets optional identifier characters
 * * starts optional identifier characters
 *
 * 0 returned if name not found
 * otherwise if next!=0 then it points to the next
 * unmatched char in name
 */

void*
strpsearch(const void* tab, size_t num, size_t siz, const char* name, char** next)
{
	register char*		lo = (char*)tab;
	register char*		hi = lo + (num - 1) * siz;
	register char*		mid;
#if CC_NATIVE != CC_ASCII
	register unsigned char*	m;
#endif
	register unsigned char*	s;
	register unsigned char*	t;
	register int		c;
	register int		v;
	int			sequential = 0;

#if CC_NATIVE != CC_ASCII
	m = ccmap(CC_NATIVE, CC_ASCII);
#endif
	c = MAP(m, *((unsigned char*)name));
	while (lo <= hi)
	{
		mid = lo + (sequential ? 0 : (((hi - lo) / siz) / 2) * siz);
		if (!(v = c - MAP(m, *(s = *((unsigned char**)mid)))) || *s == '[' && !(v = c - MAP(m, *++s)) && (v = 1))
		{
			t = (unsigned char*)name;
			for (;;)
			{
				if (!v && (*s == '[' || *s == '*'))
				{
					v = 1;
					s++;
				}
				else if (v && *s == ']')
				{
					v = 0;
					s++;
				}
				else if (!isalpha(*t))
				{
					if (v || !*s)
					{
						if (next)
							*next = (char*)t;
						return (void*)mid;
					}
					if (!sequential)
					{
						while ((mid -= siz) >= lo && (s = *((unsigned char**)mid)) && ((c == MAP(m, *s)) || *s == '[' && c == MAP(m, *(s + 1))));
						sequential = 1;
					}
					v = 1;
					break;
				}
				else if (*t != *s)
				{
					v = MAP(m, *t) - MAP(m, *s);
					break;
				}
				else
				{
					t++;
					s++;
				}
			}
		}
		else if (sequential)
			break;
		if (v > 0)
			lo = mid + siz;
		else
			hi = mid - siz;
	}
	return 0;
}
