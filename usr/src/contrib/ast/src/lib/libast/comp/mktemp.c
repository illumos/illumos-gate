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
 * mktemp,mkstemp implementation
 */

#define mktemp		______mktemp
#define mkstemp		______mkstemp

#include <ast.h>
#include <stdio.h>

#undef	mktemp
#undef	mkstemp

#undef	_def_map_ast
#include <ast_map.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

static char*
temp(char* buf, int* fdp)
{
	char*	s;
	char*	d;
	int	n;
	size_t	len;

	len = strlen(buf);
	if (s = strrchr(buf, '/'))
	{
		*s++ = 0;
		d = buf;
	}
	else
	{
		s = buf;
		d = "";
	}
	if ((n = strlen(s)) < 6 || strcmp(s + n - 6, "XXXXXX"))
		*buf = 0;
	else
	{
		*(s + n - 6) = 0;
		if (!pathtemp(buf, len, d, s, fdp))
			*buf = 0;
	}
	return buf;
}

extern char*
mktemp(char* buf)
{
	return temp(buf, NiL);
}

extern int
mkstemp(char* buf)
{
	int	fd;

	return *temp(buf, &fd) ? fd : -1;
}
