/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2010 AT&T Intellectual Property          *
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
b_tty(int argc, char *argv[], void* context)
{
	register int n,sflag=0,lflag=0;
	register char *tty;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	while (n = optget(argv, usage)) switch (n)
	{
	case 'l':
		lflag++;
		break;
	case 's':
		sflag++;
		break;
	case ':':
		error(2, "%s", opt_info.arg);
		break;
	case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
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
		if (n = ioctl(0, STWLINE, 0)) >= 0)
			error(ERROR_OUTPUT, 1, "synchronous line %d", n);
		else
#endif
			error(ERROR_OUTPUT, 1, "not on an active synchronous line");
	}
	return(error_info.errors);
}
