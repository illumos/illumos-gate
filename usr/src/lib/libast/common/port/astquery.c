/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * AT&T Research
 *
 * output printf prompt and read response
 * if format==0 then verify that interaction is possible
 *
 * return:
 *
 *	0	[1yY+]
 *	-1	[qQ] or EOF
 *	1	otherwise
 *
 * if (quit&ERROR_PROMPT) then tty forced for IO
 * if quit>=0 then [qQ] or EOF calls exit(quit)
 */

#include <ast.h>
#include <error.h>

int
astquery(int quit, const char* format, ...)
{
	va_list		ap;
	register int	n;
	register int	c;
	Sfio_t*		ip;
	Sfio_t*		op;

	static Sfio_t*	rfp;
	static Sfio_t*	wfp;

	va_start(ap, format);
	if (!format)
		return 0;
	if (!rfp)
	{
		c = errno;
		if (isatty(sffileno(sfstdin)))
			rfp = sfstdin;
		else if (!(rfp = sfopen(NiL, "/dev/tty", "r")))
			return -1;
		if (isatty(sffileno(sfstderr)))
			wfp = sfstderr;
		else if (!(wfp = sfopen(NiL, "/dev/tty", "w")))
			return -1;
		errno = c;
	}
	if (quit & ERROR_PROMPT)
	{
		quit &= ~ERROR_PROMPT;
		ip = rfp;
		op = wfp;
	}
	else
	{
		ip = sfstdin;
		op = sfstderr;
	}
	sfsync(sfstdout);
	sfvprintf(op, format, ap);
	sfsync(op);
	for (n = c = sfgetc(ip);; c = sfgetc(ip))
		switch (c)
		{
		case EOF:
			n = c;
			/*FALLTHROUGH*/
		case '\n':
			switch (n)
			{
			case EOF:
			case 'q':
			case 'Q':
				if (quit >= 0)
					exit(quit);
				return -1;
			case '1':
			case 'y':
			case 'Y':
			case '+':
				return 0;
			}
			return 1;
		}
	va_end(ap);
	/*NOTREACHED*/
}
