/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Research
 *
 * logname
 */

static const char usage[] =
"[-?\n@(#)$Id: logname (AT&T Research) 1999-04-30 $\n]"
USAGE_LICENSE
"[+NAME?logname - return the user's login name]"
"[+DESCRIPTION?\blogname\b writes the users's login name to standard "
	"output.  The login name is the string that is returned by the "
	"\bgetlogin\b(2) function.  If \bgetlogin\b(2) does not return "
	"successfully, the corresponding to the real user id of the calling "
	"process is used instead.]"

"\n"
"\n\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Successful Completion.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bgetlogin\b(2)]"
;


#include <cmd.h>

int
b_logname(int argc, char** argv, Shbltin_t* context)
{
	register char*	logname;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			continue;
		}
		break;
	}
	if (error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (!(logname = getlogin()))
		logname = fmtuid(getuid());
	sfputr(sfstdout, logname, '\n');
	return 0;
}

