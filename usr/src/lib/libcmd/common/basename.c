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
 * namebase pathname [suffix]
 *
 * print the namebase of a pathname
 */

static const char usage[] =
"[-?\n@(#)$Id: basename (AT&T Research) 1999-04-10 $\n]"
USAGE_LICENSE
"[+NAME?basename - strip directory and suffix from filenames]"
"[+DESCRIPTION?\bbasename\b removes all leading directory components "
	"from the file name defined by \astring\a.  If the file name "
	"defined by \astring\a has a suffix that ends in \asuffix\a, "
	"it is removed as well.]"
"[+?If \astring\a consists solely of \b/\b characters the output will "
	"be a single \b/\b unless \bPATH_LEADING_SLASHES\b returned by "
	"\bgetconf\b(1) is \b1\b and \astring\a consists of multiple "
	"\b/\b characters in which case \b//\b will be output.  "
	"Otherwise, trailing \b/\b characters are removed, and if "
	"there are any remaining \b/\b characters in \astring\a, "
	"all characters up to and including the last \b/\b are removed.  "
	"Finally, if \asuffix\a is specified, and is identical the end "
	"of \astring\a, these characters are removed.  The characters "
	"not removed from \astring\a will be written to standard output.]"
"\n"
"\n string [suffix]\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Successful Completion.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bdirname\b(1), \bgetconf\b(1), \bbasename\b(3)]"
;


#include <cmd.h>

static void namebase(Sfio_t *outfile, register char *pathname, char *suffix)
{
	register char *first, *last;
	register int n=0;
	for(first=last=pathname; *last; last++);
	/* back over trailing '/' */
	if(last>first)
		while(*--last=='/' && last > first);
	if(last==first && *last=='/')
	{
		/* all '/' or "" */
		if(*first=='/')
			if(*++last=='/')	/* keep leading // */
				last++;
	}
	else
	{
		for(first=last++;first>pathname && *first!='/';first--);
		if(*first=='/')
			first++;
		/* check for trailing suffix */
		if(suffix && (n=strlen(suffix)) && n<(last-first))
		{
			if(memcmp(last-n,suffix,n)==0)
				last -=n;
		}
	}
	if(last>first)
		sfwrite(outfile,first,last-first);
	sfputc(outfile,'\n');
}

int
b_basename(int argc,register char *argv[], void* context)
{
	register int  n;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	while (n = optget(argv, usage)) switch (n)
	{
	case ':':
		error(2, "%s", opt_info.arg);
		break;
	case '?':
		error(ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors || argc < 1 || argc > 2)
		error(ERROR_usage(2), "%s", optusage(NiL));
	namebase(sfstdout,argv[0],argv[1]);
	return(0);
}

