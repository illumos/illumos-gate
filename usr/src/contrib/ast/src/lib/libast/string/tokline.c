/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * return an Sfio_t* to a file or string that
 *
 *	splices \\n to single lines
 *	checks for "..." and '...' spanning newlines
 *	drops #...\n comments
 *
 * if <arg> is a file and first line matches
 *	#!!! <level> <message> !!!
 * then error(<lev>,"%s: %s",<arg>,<msg>) called
 *
 * NOTE: seek disabled and string disciplines cannot be composed
 *	 quoted \n translated to \r
 */

#include <ast.h>
#include <error.h>
#include <tok.h>

typedef struct
{
	Sfdisc_t	disc;
	Sfio_t*		sp;
	int		quote;
	int*		line;
} Splice_t;

/*
 * the splicer
 */

static int
spliceline(Sfio_t* s, int op, void* val, Sfdisc_t* ad)
{
	Splice_t*	d = (Splice_t*)ad;
	register char*	b;
	register int	c;
	register int	n;
	register int	q;
	register int	j;
	register char*	e;
	char*		buf;

	NoP(val);
	switch (op)
	{
	case SF_CLOSING:
		sfclose(d->sp);
		return 0;
	case SF_DPOP:
		free(d);
		return 0;
	case SF_READ:
		do
		{
			if (!(buf = sfgetr(d->sp, '\n', 0)) && !(buf = sfgetr(d->sp, '\n', -1)))
				return 0;
			n = sfvalue(d->sp);
			q = d->quote;
			j = 0;
			(*d->line)++;
			if (n > 1 && buf[n - 2] == '\\')
			{
				j = 1;
				n -= 2;
				if (q == '#')
				{
					n = 0;
					continue;
				}
			}
			else if (q == '#')
			{
				q = 0;
				n = 0;
				continue;
			}
			if (n > 0)
			{
				e = (b = buf) + n;
				while (b < e)
				{
					if ((c = *b++) == '\\')
						b++;
					else if (c == q)
						q = 0;
					else if (!q)
					{
						if (c == '\'' || c == '"')
							q = c;
						else if (c == '#' && (b == (buf + 1) || (c = *(b - 2)) == ' ' || c == '\t'))
						{
							if (buf[n - 1] != '\n')
							{
								q = '#';
								n = b - buf - 2;
							}
							else if (n = b - buf - 1)
								buf[n - 1] = '\n';
							break;
						}
					}
				}
				if (n > 0)
				{
					if (!j && buf[n - 1] != '\n' && (s->_flags & SF_STRING))
						buf[n++] = '\n';
					if (q && buf[n - 1] == '\n')
						buf[n - 1] = '\r';
				}
			}
		} while (n <= 0);
		sfsetbuf(s, buf, n);
		d->quote = q;
		return 1;
	default:
		return 0;
	}
}

/*
 * open a stream to parse lines
 *
 *	flags: 0		arg: open Sfio_t* 
 *	flags: SF_READ		arg: file name
 *	flags: SF_STRING	arg: null terminated char*
 *
 * if line!=0 then it points to a line count that starts at 0
 * and is incremented for each input line
 */

Sfio_t*
tokline(const char* arg, int flags, int* line)
{
	Sfio_t*		f;
	Sfio_t*		s;
	Splice_t*	d;
	char*		p;
	char*		e;

	static int	hidden;

	if (!(d = newof(0, Splice_t, 1, 0)))
		return 0;
	if (!(s = sfopen(NiL, NiL, "s")))
	{
		free(d);
		return 0;
	}
	if (!(flags & (SF_STRING|SF_READ)))
		f = (Sfio_t*)arg;
	else if (!(f = sfopen(NiL, arg, (flags & SF_STRING) ? "s" : "r")))
	{
		free(d);
		sfclose(s);
		return 0;
	}
	else if ((p = sfreserve(f, 0, 0)) && sfvalue(f) > 11 && strmatch(p, "#!!! +([-0-9]) *([!\n]) !!!\n*") && (e = strchr(p, '\n')))
	{
		flags = strtol(p + 5, &p, 10);
		error(flags, "%s:%-.*s", arg, e - p - 4, p);
	}
	d->disc.exceptf = spliceline;
	d->sp = f;
	*(d->line = line ? line : &hidden) = 0;
	sfdisc(s, (Sfdisc_t*)d);
	return s;
}
