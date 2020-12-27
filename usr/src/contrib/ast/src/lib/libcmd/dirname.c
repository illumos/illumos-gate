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
 * dirname path [suffix]
 *
 * print the dirname of a pathname
 */

static const char usage[] =
"[-?\n@(#)$Id: dirname (AT&T Research) 2009-01-31 $\n]"
USAGE_LICENSE
"[+NAME?dirname - return directory portion of file name]"
"[+DESCRIPTION?\bdirname\b treats \astring\a as a file name and returns "
	"the name of the directory containing the file name by deleting "
	"the last component from \astring\a.]"
"[+?If \astring\a consists solely of \b/\b characters the output will "
	"be a single \b/\b unless \bPATH_LEADING_SLASHES\b returned by "
	"\bgetconf\b(1) is \b1\b and \astring\a consists of multiple "
	"\b/\b characters in which case \b//\b will be output.  "
	"Otherwise, trailing \b/\b characters are removed, and if "
	"there are no remaining \b/\b characters in \astring\a, "
	"the string \b.\b will be written to standard output.  "
	"Otherwise, all characters following the last \b/\b are removed. "
	"If the remaining string consists solely of \b/\b characters, "
	"the output will be as if the original string had consisted solely "
	"as \b/\b characters as described above.  Otherwise, all "
	"trailing slashes are removed and the output will be this string "
	"unless this string is empty.  If empty the output will be \b.\b.]" 
"[f:file?Print the \b$PATH\b relative regular file path for \astring\a.]"
"[r:relative?Print the \b$PATH\b relative readable file path for \astring\a.]"
"[x:executable?Print the \b$PATH\b relative executable file path for \astring\a.]"
"\n"
"\nstring\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Successful Completion.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bbasename\b(1), \bgetconf\b(1), \bdirname\b(3), \bpathname\b(3)]"
;

#include <cmd.h>

static void l_dirname(register Sfio_t *outfile, register const char *pathname)
{
	register const char  *last;
	/* go to end of path */
	for(last=pathname; *last; last++);
	/* back over trailing '/' */
	while(last>pathname && *--last=='/');
	/* back over non-slash chars */
	for(;last>pathname && *last!='/';last--);
	if(last==pathname)
	{
		/* all '/' or "" */
		if(*pathname!='/')
			last = pathname = ".";
	}
	else
	{
		/* back over trailing '/' */
		for(;*last=='/' && last > pathname; last--);
	}
	/* preserve // */
	if(last!=pathname && pathname[0]=='/' && pathname[1]=='/')
	{
		while(pathname[2]=='/' && pathname<last)
			pathname++;
		if(last!=pathname && pathname[0]=='/' && pathname[1]=='/' && *astconf("PATH_LEADING_SLASHES",NiL,NiL)!='1')
			pathname++;
	}
	sfwrite(outfile,pathname,last+1-pathname);
	sfputc(outfile,'\n');
}

int
b_dirname(int argc, char** argv, Shbltin_t* context)
{
	int	mode = 0;
	char	buf[PATH_MAX];

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'f':
			mode |= PATH_REGULAR;
			continue;
		case 'r':
			mode &= ~PATH_REGULAR;
			mode |= PATH_READ;
			continue;
		case 'x':
			mode |= PATH_EXECUTE;
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
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors || argc != 1)
		error(ERROR_usage(2),"%s", optusage(NiL));
	if(!mode)
		l_dirname(sfstdout,argv[0]);
	else if(pathpath(argv[0], "", mode, buf, sizeof(buf)))
		sfputr(sfstdout, buf, '\n');
	else
		error(1|ERROR_WARNING, "%s: relative path not found", argv[0]);
	return 0;
}
