/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2007 AT&T Intellectual Property          *
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
*		  Glenn Fowler <gsf@research.att.com>		       *
*		   David Korn <dgk@research.att.com>		       *
*                                                                      *
***********************************************************************/
#pragma prototyped

static const char usage[] =
"[-?\n@(#)$Id: readlink (AT&T Research) 2008-06-08 $\n]"
USAGE_LICENSE
"[+NAME?readlink - read the contents of a symbolic link]"
"[+DESCRIPTION?\breadlink\b returns the contents of the symbolic "
       "link referred to by the path argument. Unless the \b-f\b "
       "option is specified an error will be returned when the path "
       "is not a symbolic link.]"
"[f:canonicalize?The returned value will be an absolute pathname that names "
       "the same file, whose resolution does not involve \".\", \"..\", or "
       "symbolic links, otherwise only the exact (relative) value will be returned.]"
"[n:no-newline?Supress newline at the end.]"
"[v:verbose?Verbose - print errors.]"
"[+SEE ALSO?\bbasename\b(1),\bdirname\b(2),\breadlink\b(2),\breadpath\n(2)]"
;

#include <cmd.h>

int
b_readlink(int argc, char** argv, void* context)
{
       register char*	       s;
       register int	       i;
       register char*	       m;
       register char*	       x;
       int		       canonicalize = 0,
			       nonewline = 0,
			       verbose = 0;
       char		       buf[PATH_MAX+2];
       int		       len = 0;
       char		      *filename,
			      *resolvedname = NULL;

       cmdinit(argc, argv, context, ERROR_CATALOG, 0);
       for (;;)
       {
	       switch (optget(argv, usage))
	       {
	       case 'f':
		       canonicalize = opt_info.num;
		       continue;
	       case 'n':
		       nonewline = opt_info.num;
		       continue;
	       case 'v':
		       verbose = opt_info.num;
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
       if(error_info.errors || argc != 1)
	       error(ERROR_usage(2),"%s", optusage(NiL));
       filename = argv[0];
       
       if (canonicalize)
       {
	       len = resolvepath(filename, buf, sizeof(buf)-2);
       }
       else
       {
	       len = readlink(filename, buf, sizeof(buf)-2);
       }

       if (len != -1)
	       resolvedname = buf;

       if (!resolvedname)
       {
	       if (verbose)
		       error(ERROR_system(1),"%s: readlink failed", filename);
	       else
		       return 1;
       }

       if (!nonewline)
	       resolvedname[len++] = '\n';

       sfwrite(sfstdout, resolvedname, len);

       return 0;
}
