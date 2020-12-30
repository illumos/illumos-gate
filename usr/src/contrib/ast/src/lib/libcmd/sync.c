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
 * Glenn Fowler
 * AT&T Research
 */

static const char usage[] =
"[-?\n@(#)$Id: sync (AT&T Research) 2006-10-04 $\n]"
USAGE_LICENSE
"[+NAME?sync - schedule file system updates]"
"[+DESCRIPTION?\bsync\b calls \bsync\b(2), which causes all information "
    "in memory that updates file systems to be scheduled for writing out to "
    "all file systems. The writing, although scheduled, is not necessarily "
    "complete upon return from \bsync\b.]"
"[+?Since \bsync\b(2) has no failure indication, \bsync\b only fails for "
    "option/operand syntax errors, or when \bsync\b(2) does not return, in "
    "which case \bsync\b also does not return.]"
"[+?At minimum \bsync\b should be called before halting the system. Most "
    "systems provide graceful shutdown procedures that include \bsync\b -- "
    "use them if possible.]"
"[+EXIT STATUS?]"
    "{"
        "[+0?\bsync\b(2) returned.]"
        "[+>0?Option/operand syntax error.]"
    "}"
"[+SEE ALSO?\bsync\b(2), \bshutdown\b(8)]"
;

#include <cmd.h>
#include <ls.h>

int
b_sync(int argc, char** argv, Shbltin_t* context)
{
	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || *argv)
		error(ERROR_usage(2), "%s", optusage(NiL));
#if _lib_sync
	sync();
#else
	error(ERROR_usage(2), "failed -- the native system does not provide a sync(2) call");
#endif
	return 0;
}
