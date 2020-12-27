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
 *
 * return error message string given errno
 */

#include "lclib.h"

#include "FEATURE/errno"

#undef	strerror

#if !defined(sys_errlist) && !_def_errno_sys_errlist
#if _dat_sys_errlist
extern char*	sys_errlist[];
#else
#undef		_dat_sys_nerr
char*		sys_errlist[] = { 0 };
#endif
#endif

#if !defined(sys_nerr) && !_def_errno_sys_nerr
#if _dat_sys_nerr
extern int	sys_nerr;
#else
#undef		_dat_sys_nerr
int		sys_nerr = 0;
#endif
#endif

#if _lib_strerror
extern char*	strerror(int);
#endif

#if _PACKAGE_astsa

#define fmtbuf(n)	((n),tmp)

static char		tmp[32];

#endif

char*
_ast_strerror(int err)
{
	char*		msg;
	int		z;

#if _lib_strerror
	z = errno;
	msg = strerror(err);
	errno = z;
#else
	if (err > 0 && err <= sys_nerr)
		msg = (char*)sys_errlist[err];
	else
		msg = 0;
#endif
	if (msg)
	{
#if !_PACKAGE_astsa
		if (ERROR_translating())
		{
#if _lib_strerror
			static int	sys;

			if (!sys)
			{
				char*	s;
				char*	t;
				char*	p;

#if _lib_strerror
				/*
				 * stash the pending strerror() msg
				 */

				msg = strcpy(fmtbuf(strlen(msg) + 1), msg);
#endif

				/*
				 * make sure that strerror() translates
				 */

				if (!(s = strerror(1)))
					sys = -1;
				else
				{
					t = fmtbuf(z = strlen(s) + 1);
					strcpy(t, s);
					ast.locale.set |= AST_LC_internal;
					p = setlocale(LC_MESSAGES, NiL);
					setlocale(LC_MESSAGES, "C");
					sys = (s = strerror(1)) && strcmp(s, t) ? 1 : -1;
					setlocale(LC_MESSAGES, p);
					ast.locale.set &= ~AST_LC_internal;
				}
			}
			if (sys > 0)
				return msg;
#endif
			return ERROR_translate(NiL, NiL, "errlist", msg);
		}
#endif
		return msg;
	}
	msg = fmtbuf(z = 32);
	sfsprintf(msg, z, ERROR_translate(NiL, NiL, "errlist", "Error %d"), err);
	return msg;
}

#if !_lib_strerror

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern char*
strerror(int err)
{
	return _ast_strerror(err);
}

#endif
