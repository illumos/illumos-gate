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
#if defined(_UWIN) && defined(_BLD_ast)

void _STUB_vmstrdup(){}

#else

#include "vmhdr.h"

/*
 * return a copy of s using vmalloc
 */

#if __STD_C
char* vmstrdup(Vmalloc_t* v, register const char* s)
#else
char* vmstrdup(v, s)
Vmalloc_t*	v;
register char*	s;
#endif
{
	register char*	t;
	register int	n;

	return (s && (t = vmalloc(v, n = strlen(s) + 1))) ? (char*)memcpy(t, s, n) : (char*)0;
}

#endif
