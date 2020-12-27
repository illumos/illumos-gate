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
 * standalone mini ast+sfio implementation
 */

#include <ast.h>

#define CHUNK		1024

_Ast_info_t		ast;

int
astwinsize(int fd, int* lines, int* columns)
{
	if (lines)
		*lines = 24;
	if (columns)
		*columns = 80;
	return 0;
}

char*
sfgetr(Sfio_t* sp, int c, int z)
{
	register char*		s;
	register char*		e;

	static char*		buf;
	static unsigned long	siz;

	if (!buf)
	{
		siz = CHUNK;
		if (!(buf = newof(0, char, siz, 0)))
			return 0;
	}
	if (z < 0)
		return *buf ? buf : (char*)0;
	s = buf;
	e = s + siz;
	for (;;)
	{
		if (s >= e)
		{
			siz += CHUNK;
			if (!(buf = newof(buf, char, siz, 0)))
				return 0;
			s = buf + (siz - CHUNK);
			e = s + siz;
		}
		if ((c = sfgetc(sp)) == EOF)
		{
			*s = 0;
			return 0;
		}
		if (c == '\n')
		{
			*s = z ? 0 : c;
			break;
		}
		*s++ = c;
	}
	return buf;
}
