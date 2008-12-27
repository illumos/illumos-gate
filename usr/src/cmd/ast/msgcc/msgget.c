/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 2000-2008 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 */

static const char usage[] =
"[-?\n@(#)$Id: msgget (AT&T Research) 2001-04-21 $\n]"
USAGE_LICENSE
"[+NAME?msgget - get a message from a message catalog]"
"[+DESCRIPTION?\bmsgget\b gets the message corresponding to the parameters."
"	If \alocale\a is \b-\b then the current locale is used. \acommand\a"
"	may be specified for command specific messages. \acatalog\a specifies"
"	the message catalog name. [\aset\a.]]\anumber\a identifies the message"
"	by message \anumber\a and an optional message \aset\a; if specified as"
"	\b-\b then the message set and number are determined by looking up"
"	\atext\a in the corresponding \bC\b locale message catalog.]"

"\n"
"\nlocale [command:]catalog [set.]number [ text ]\n"
"\n"

"[+SEE ALSO?\biconv\b(1), \bmsgcc\b(1), \bmsggen\b(1)]"
;

#include <ast.h>
#include <error.h>
#include <mc.h>

int
main(int argc, char** argv)
{
	register Mc_t*	mc;
	register char*	s;
	char*		loc;
	char*		cmd;
	char*		cat;
	char*		msg;
	int		set;
	int		num;
	Sfio_t*		sp;
	char		path[PATH_MAX];

	NoP(argc);
	error_info.id = "msgget";
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || !(loc = *argv++) || !(cmd = *argv++) || !(s = *argv++))
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	if (streq(s, "-"))
		set = num = 0;
	else
		mcindex(s, NiL, &set, &num);
	if (!(msg = *argv++))
		msg = "";
	else if (*argv)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	if (streq(loc, "-"))
		loc = 0;
	if (cat = strchr(cmd, ':'))
		*cat++ = 0;
	if (!mcfind(path, loc, cmd, LC_MESSAGES, 0) && (!cat || !mcfind(path, loc, cat, LC_MESSAGES, 0)))
	{
		if (cat)
			*--cat = ':';
		error(3, "%s: cannot locate message catalog", cmd);
	}
	if (!(sp = sfopen(NiL, path, "r")))
		error(ERROR_SYSTEM|3, "%s: cannot read message catalog", path);
	if (!(mc = mcopen(sp)))
		error(3, "%s: invalid message catalog", path);
	if (set)
		s = mcget(mc, set, num, msg);
	else
		s = errorx(loc, cmd, cat, msg);
	sfputr(sfstdout, s, '\n');
	return error_info.errors != 0;
}
