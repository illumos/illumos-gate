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

#if !defined(getgroups) && defined(_lib_getgroups)

NoN(getgroups)

#else

#include <error.h>

#if defined(getgroups)
#undef	getgroups
#define	ast_getgroups	_ast_getgroups
#define botched		1
extern int		getgroups(int, int*);
#else
#define ast_getgroups	getgroups
#endif

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int
ast_getgroups(int len, gid_t* set)
{
#if botched
#if NGROUPS_MAX < 1
#undef	NGROUPS_MAX
#define NGROUPS_MAX	1
#endif
	register int	i;
	int		big[NGROUPS_MAX];
#else
#undef	NGROUPS_MAX
#define NGROUPS_MAX	1
#endif
	if (!len) return(NGROUPS_MAX);
	if (len < 0 || !set)
	{
		errno = EINVAL;
		return(-1);
	}
#if botched
	len = getgroups(len > NGROUPS_MAX ? NGROUPS_MAX : len, big);
	for (i = 0; i < len; i++)
		set[i] = big[i];
	return(len);
#else
	*set = getgid();
	return(1);
#endif
}

#endif
