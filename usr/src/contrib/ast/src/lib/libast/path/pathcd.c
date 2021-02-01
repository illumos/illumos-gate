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
 * K. P. Vo
 * G. S. Fowler
 * AT&T Research
 */

#include <ast.h>
#include <error.h>
#include <stk.h>

#if DEBUG

#undef	PATH_MAX

#define PATH_MAX	16

static int
vchdir(const char* path)
{
	int	n;

	if (strlen(path) >= PATH_MAX)
	{
		errno = ENAMETOOLONG;
		n = -1;
	}
	else n = chdir(path);
	return n;
}

#define chdir(p)	vchdir(p)

#endif

/*
 * set the current directory to path
 * if path is long and home!=0 then pathcd(home,0)
 * is called on intermediate chdir errors
 */

int
pathcd(const char* path, const char* home)
{
	register char*	p = (char*)path;
	register char*	s;
	register int	n;
	int		i;
	int		r;

	r = 0;
	for (;;)
	{
		/*
		 * this should work 99% of the time
		 */

		if (!chdir(p))
			return r;

		/*
		 * chdir failed
		 */

		if ((n = strlen(p)) < PATH_MAX)
			return -1;
#ifdef ENAMETOOLONG
		if (errno != ENAMETOOLONG)
			return -1;
#endif

		/*
		 * path is too long -- copy so it can be modified in place
		 */

		i = stktell(stkstd);
		sfputr(stkstd, p, 0);
		stkseek(stkstd, i);
		p = stkptr(stkstd, i);
		for (;;)
		{
			/*
			 * get a short prefix component
			 */

			s = p + PATH_MAX;
			while (--s >= p && *s != '/');
			if (s <= p)
				break;

			/*
			 * chdir to the prefix
			 */

			*s++ = 0;
			if (chdir(p))
				break;

			/*
			 * do the remainder
			 */

			if ((n -= s - p) < PATH_MAX)
			{
				if (chdir(s))
					break;
				return r;
			}
			p = s;
		}

		/*
		 * try to recover back to home
		 */

		if (!(p = (char*)home))
			return -1;
		home = 0;
		r = -1;
	}
}
