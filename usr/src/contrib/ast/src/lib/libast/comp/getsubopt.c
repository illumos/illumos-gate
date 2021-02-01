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
 * Xopen 4.2 compatibility
 */

#include <ast.h>

#undef	_lib_getsubopt	/* we can satisfy the api */

#if _lib_getsubopt

NoN(getsubopt)

#else

#undef	_BLD_ast	/* enable ast imports since we're user static */

#include <error.h>

extern int
getsubopt(register char** op, char* const* tp, char** vp)
{
	register char*	b;
	register char*	s;
	register char*	v;

	if (*(b = *op))
	{
		v = 0;
		s = b;
		for (;;)
		{
			switch (*s++)
			{
			case 0:
				s--;
				break;
			case ',':
				*(s - 1) = 0;
				break;
			case '=':
				if (!v)
				{
					*(s - 1) = 0;
					v = s;
				}
				continue;
			default:
				continue;
			}
			break;
		}
		*op = s;
		*vp = v;
		for (op = (char**)tp; *op; op++)
			if (streq(b, *op))
				return op - (char**)tp;
	}
	*vp = b;
	return -1;
}

#endif
