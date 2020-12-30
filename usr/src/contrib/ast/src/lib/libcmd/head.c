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
 * output the beginning portion of one or more files
 */

static const char usage[] =
"[-n?\n@(#)$Id: head (AT&T Research) 2012-05-31 $\n]"
USAGE_LICENSE
"[+NAME?head - output beginning portion of one or more files ]"
"[+DESCRIPTION?\bhead\b copies one or more input files to standard "
    "output stopping at a designated point for each file or to the end of "
    "the file whichever comes first. Copying ends at the point indicated by "
    "the options. By default a header of the form \b==> \b\afilename\a\b "
    "<==\b is output before all but the first file but this can be changed "
    "with the \b-q\b and \b-v\b options.]"
"[+?If no \afile\a is given, or if the \afile\a is \b-\b, \bhead\b "
    "copies from standard input starting at the current location.]"
"[+?The option argument for \b-c\b, and \b-s\b can optionally be "
    "followed by one of the following characters to specify a different unit "
    "other than a single byte:]"
    "{"
        "[+b?512 bytes.]"
        "[+k?1-killobyte.]"
        "[+m?1-megabyte.]"
    "}"
"[+?For backwards compatibility, \b-\b\anumber\a is equivalent to \b-n\b "
    "\anumber\a.]"
"[n:lines?Copy \alines\a lines from each file.]#[lines:=10]"
"[c:bytes?Copy \achars\a bytes from each file.]#[chars]"
"[q:quiet|silent?Never ouput filename headers.]"
"[s:skip?Skip \askip\a characters or lines from each file before "
    "copying.]#[skip]"
"[v:verbose?Always ouput filename headers.]"
    "\n\n"
"[ file ... ]"
    "\n\n"
"[+EXIT STATUS?]"
    "{"
        "[+0?All files copied successfully.]"
        "[+>0?One or more files did not copy.]"
    "}"
"[+SEE ALSO?\bcat\b(1), \btail\b(1)]"
;

#include <cmd.h>

int
b_head(int argc, register char** argv, Shbltin_t* context)
{
	static const char	header_fmt[] = "\n==> %s <==\n";

	register Sfio_t*	fp;
	register char*		cp;
	register off_t		keep = 10;
	register off_t		skip = 0;
	register int		delim = '\n';
	int			header = 1;
	char*			format = (char*)header_fmt+1;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'c':
			delim = -1;
			/*FALLTHROUGH*/
		case 'n':
			if (opt_info.offset && argv[opt_info.index][opt_info.offset] == 'c')
			{
				delim = -1;
				opt_info.offset++;
			}
			if ((keep = opt_info.number) <=0)
				error(2, "%s: %I*d: positive numeric option argument expected", opt_info.name, sizeof(keep), keep);
			continue;
		case 'q':
			header = argc;
			continue;
		case 'v':
			header = 0;
			continue;
		case 's':
			skip = opt_info.number;
			continue;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if (error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (cp = *argv)
		argv++;
	do
	{
		if (!cp || streq(cp, "-"))
		{
			cp = "/dev/stdin";
			fp = sfstdin;
			sfset(fp, SF_SHARE, 1);
		}
		else if (!(fp = sfopen(NiL, cp, "r")))
		{
			error(ERROR_system(0), "%s: cannot open", cp);
			continue;
		}
		if (argc > header)
			sfprintf(sfstdout, format, cp);
		format = (char*)header_fmt;
		if (skip > 0)
			sfmove(fp, NiL, skip, delim);
		if (sfmove(fp, sfstdout, keep, delim) < 0 && !ERROR_PIPE(errno) && errno != EINTR)
			error(ERROR_system(0), "%s: read error", cp);
		if (fp != sfstdin)
			sfclose(fp);
	} while (cp = *argv++);
	if (sfsync(sfstdout))
		error(ERROR_system(0), "write error");
	return error_info.errors != 0;
}
