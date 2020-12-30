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
 * G. S. Fowler
 * D. G. Korn
 * AT&T Bell Laboratories
 *
 * shell library support
 */

#include <ast.h>
#include <sys/stat.h>

/*
 * return pointer to the full path name of the shell
 *
 * SHELL is read from the environment and must start with /
 *
 * if set-uid or set-gid then the executable and its containing
 * directory must not be owned by the real user/group
 *
 * root/administrator has its own test
 *
 * astconf("SH",NiL,NiL) is returned by default
 *
 * NOTE: csh is rejected because the bsh/csh differentiation is
 *       not done for `csh script arg ...'
 */

char*
pathshell(void)
{
	register char*	sh;
	int		ru;
	int		eu;
	int		rg;
	int		eg;
	struct stat	st;

	static char*	val;

	if ((sh = getenv("SHELL")) && *sh == '/' && strmatch(sh, "*/(sh|*[!cC]sh)*([[:digit:]])?(-+([.[:alnum:]]))?(.exe)"))
	{
		if (!(ru = getuid()) || !eaccess("/bin", W_OK))
		{
			if (stat(sh, &st))
				goto defshell;
			if (ru != st.st_uid && !strmatch(sh, "?(/usr)?(/local)/?([ls])bin/?([[:lower:]])sh?(.exe)"))
				goto defshell;
		}
		else
		{
			eu = geteuid();
			rg = getgid();
			eg = getegid();
			if (ru != eu || rg != eg)
			{
				char*	s;
				char	dir[PATH_MAX];

				s = sh;
				for (;;)
				{
					if (stat(s, &st))
						goto defshell;
					if (ru != eu && st.st_uid == ru)
						goto defshell;
					if (rg != eg && st.st_gid == rg)
						goto defshell;
					if (s != sh)
						break;
					if (strlen(s) >= sizeof(dir))
						goto defshell;
					strcpy(dir, s);
					if (!(s = strrchr(dir, '/')))
						break;
					*s = 0;
					s = dir;
				}
			}
		}
		return sh;
	}
 defshell:
	if (!(sh = val))
	{
		if (!*(sh = astconf("SH", NiL, NiL)) || *sh != '/' || eaccess(sh, X_OK) || !(sh = strdup(sh)))
			sh = "/bin/sh";
		val = sh;
	}
	return sh;
}
