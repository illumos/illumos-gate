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

#include <ast.h>
#include <ctype.h>

static char**		ids;

static const char*	dflt[] = { "ast", "standard", 0 };

/*
 * initialize the conformance() id list
 */

static char**
initconformance(void)
{
	char*			m;
	char**			p;
	char*			t;
	int			h;
	int			i;
	int			j;
	int			c;
	Sfio_t*			sp;

	static const char*	conf[] = { "CONFORMANCE", "HOSTTYPE", "UNIVERSE" };

	p = 0;
	if (sp = sfstropen())
	{
		for (i = h = 0, j = 1; i < elementsof(conf); i++)
			if (*(m = astconf(conf[i], NiL, NiL)) && (h |= (1<<i)) || !i && (m = "ast"))
			{
				t = m;
				while ((c = *m++) && c != '.')
				{
					if (isupper(c))
						c = tolower(c);
					sfputc(sp, c);
				}
				sfputc(sp, 0);
				j++;
				if ((c = (m - t)) == 6 && strneq(t, "linux", 5))
				{
					sfputr(sp, "gnu", 0);
					j++;
				}
				else if (c > 3 && strneq(t, "bsd", 3) || c == 7 && strneq(t, "debian", 7))
				{
					sfputr(sp, "bsd", 0);
					j++;
				}
				if (h & 1)
					break;
			}
		i = sfstrtell(sp);
		sfstrseek(sp, 0, SEEK_SET);
		if (p = newof(0, char*, j, i))
		{
			m = (char*)(p + j--);
			memcpy(m, sfstrbase(sp), i);
			i = 0;
			p[i++] = m;
			while (i < j)
			{
				while (*m++);
				p[i++] = m;
			}
			p[i] = 0;
		}
		sfstrclose(sp);
	}
	if (!p)
		p = (char**)dflt;
	return ids = p;
}

/*
 * return conformance id if s size n is in conformance
 * prefix match of s on the conformance id table
 * s==0 => "standard"
 */

char*
conformance(const char* s, size_t n)
{
	char**		p;
	char**		q;
	char*		m;
	const char*	e;
	const char*	t;

	static uint32_t	serial = ~(uint32_t)0;

	if (!(p = ids) || serial != ast.env_serial)
	{
		serial = ast.env_serial;
		if (ids)
		{
			if (ids != (char**)dflt)
				free(ids);
			ids = 0;
		}
		p = initconformance();
	}
	if (!s)
		s = dflt[1];
	if (!n)
		n = strlen(s);
	e = s + n;
	if (*s == '(')
		s++;
	do
	{
		while (s < e && (isspace(*s) || *s == ',' || *s == '|'))
			s++;
		if (*s == ')')
			break;
		for (t = s; s < e && !isspace(*s) && *s != ',' && *s != '|' && *s != ')'; s++);
		if (s == t)
			break;
		q = p;
		while (m = *q++)
			if (strneq(t, m, s - t))
				return m;
		if (s < e)
			s++;
	} while (s < e);
	return 0;
}
