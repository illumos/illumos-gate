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
 * AT&T Bell Laboratories
 *
 * tty
 */

static const char usage[] =
"[-?\n@(#)$Id: tty (AT&T Research) 2008-03-13 $\n]"
USAGE_LICENSE
"[+NAME?tty - write the name of the terminal to standard output]"
"[+DESCRIPTION?\btty\b writes the name of the terminal that is connected "
	"to standard input onto standard output.  If the standard input is not "
	"a terminal, \"\bnot a tty\b\" will be written to standard output.]"
"[l:line-number?Write the synchronous line number of the terminal on a "
	"separate line following the terminal name line. If the standard "
	"input is not a synchronous  terminal then "
	"\"\bnot on an active synchronous line\b\" is written.]"
"[s:silent|quiet?Disable the terminal name line. Use \b[[ -t 0 ]]]]\b instead.]"
"[+EXIT STATUS?]{"
        "[+0?Standard input is a tty.]"
        "[+1?Standard input is not a tty.]"
        "[+2?Invalid arguments.]"
        "[+3?A an error occurred.]"
"}"
;


#include <cmd.h>

#if _mac_STWLINE
#include <sys/stermio.h>
#endif

int
b_tty(int argc, char** argv, Shbltin_t* context)
{
	register int	sflag = 0;
	register int	lflag = 0;
	register char*	tty;
#if _mac_STWLINE
	int		n;
#endif

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'l':
			lflag++;
			continue;
		case 's':
			sflag++;
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		break;
	}
	if(error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	if(!(tty=ttyname(0)))
	{
		tty = ERROR_translate(0, 0, 0, "not a tty");
		error_info.errors++;
	}
	if(!sflag)
		sfputr(sfstdout,tty,'\n');
	if(lflag)
	{
#if _mac_STWLINE
		if ((n = ioctl(0, STWLINE, 0)) >= 0)
			error(ERROR_OUTPUT, 1, "synchronous line %d", n);
		else
#endif
			error(ERROR_OUTPUT, 1, "not on an active synchronous line");
	}
	return(error_info.errors);
}
