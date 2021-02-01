/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
/*
 * AT&T Bell Laboratories
 * make abstract machine file state support
 *
 * mamstate reference [ file ... | <files ]
 *
 * stdout is list of <file,delta> pairs where delta
 * is diff between reference and file times
 * non-existent files are not listed
 */

#if !lint
static char id[] = "\n@(#)$Id: mamstate (AT&T Bell Laboratories) 1989-06-26 $\0\n";
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

main(argc, argv)
int		argc;
register char**	argv;
{
	register char*	s;
	register int	c;
	long		ref;
	struct stat	st;
	char		buf[1024];

	if (!(s = *++argv) || stat(s, &st))
	{
		fprintf(stderr, "Usage: mamstate reference [ file ... | <files ]\n");
		exit(1);
	}
	ref = (long)st.st_mtime;
	if (s = *++argv) do
	{
		if (!stat(s, &st))
			printf("%s %ld\n", s, (long)st.st_mtime - ref);
	} while (s = *++argv);
	else do
	{
		s = buf;
		while ((c = getchar()) != EOF && c != ' ' && c != '\n')
			if (s < buf + sizeof(buf) - 1) *s++ = c;
		if (s > buf)
		{
			*s = 0;
			if (!stat(buf, &st))
				printf("%s %ld\n", buf, (long)st.st_mtime - ref);
		}
	} while (c != EOF);
	exit(0);
}
