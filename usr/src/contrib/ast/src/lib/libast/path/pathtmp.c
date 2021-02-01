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
 * obsolete -- use pathtemp()
 */

#include <ast.h>
#include <stdio.h>

#ifndef L_tmpnam
#define L_tmpnam	25
#endif

char*
pathtmp(char* buf, const char* dir, const char* pfx, int* fdp)
{
	size_t	len;

	len = !buf ? 0 : !dir ? L_tmpnam : (strlen(dir) + 14);
	return pathtemp(buf, len, dir, pfx, fdp);
}
