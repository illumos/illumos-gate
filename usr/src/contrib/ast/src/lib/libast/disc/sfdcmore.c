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
#include "sfdchdr.h"

#if _PACKAGE_ast
#include <ast_tty.h>
#include <signal.h>
#endif

/*
 * a simple but fast more style pager discipline
 * if on sfstdout then sfstdin ops reset the page state
 *
 * Glenn Fowler
 * AT&T Research
 *
 * @(#)$Id: sfdcmore (AT&T Research) 1998-06-25 $
 */

typedef struct
{	
	Sfdisc_t	disc;		/* sfio discipline		*/
	Sfio_t*		input;		/* tied with this input stream	*/
	Sfio_t*		error;		/* tied with this error stream	*/
	int		rows;		/* max rows			*/
	int		cols;		/* max cols			*/
	int		row;		/* current row			*/
	int		col;		/* current col			*/
	int		match;		/* match length, 0 if none	*/
	char		pattern[128];	/* match pattern		*/
	char		prompt[1];	/* prompt string		*/
} More_t;

/*
 * more read
 * we assume line-at-a-time input
 */

#if __STD_C
static ssize_t moreread(Sfio_t* f, void* buf, size_t n, Sfdisc_t* dp)
#else
static ssize_t moreread(f, buf, n, dp)
Sfio_t*		f;
void*		buf;
size_t		n;
Sfdisc_t*	dp;
#endif
{
	register More_t*	more = (More_t*)dp;

	more->match = 0;
	more->row = 2;
	more->col = 1;
	return sfrd(f, buf, n, dp);
}

/*
 * output label on wfd and return next char on rfd with no echo
 * return < -1 is -(signal + 1)
 */

#if __STD_C
static int ttyquery(Sfio_t* rp, Sfio_t* wp, const char* label, Sfdisc_t* dp)
#else
static int ttyquery(rp, wp, label, dp)
Sfio_t*		rp;
Sfio_t*		wp;
char*		label;
Sfdisc_t*	dp;
#endif
{
	register int	r;
	int		n;

#ifdef TCSADRAIN
	unsigned char	c;
	struct termios	old;
	struct termios	tty;
	int		rfd = sffileno(rp);
	int		wfd = sffileno(rp);

	if (!label)
		n = 0;
	else if (n = strlen(label))
		write(wfd, label, n);
	tcgetattr(rfd, &old);
	tty = old;
	tty.c_cc[VTIME] = 0;
	tty.c_cc[VMIN] = 1;
	tty.c_lflag &= ~(ICANON|ECHO|ECHOK|ISIG);
	tcsetattr(rfd, TCSADRAIN, &tty);
	if ((r = read(rfd, &c, 1)) == 1)
	{
		if (c == old.c_cc[VEOF])
			r = -1;
		else if (c == old.c_cc[VINTR])
			r = -(SIGINT + 1);
		else if (c == old.c_cc[VQUIT])
			r = -(SIGQUIT + 1);
		else if (c == '\r')
			r = '\n';
		else
			r = c;
	}
	tcsetattr(rfd, TCSADRAIN, &old);
	if (n)
	{
		write(wfd, "\r", 1);
		while (n-- > 0)
			write(wfd, " ", 1);
		write(wfd, "\r", 1);
	}
#else
	register char*	s;

	if (label && (n = strlen(label)))
		sfwr(wp, label, n, dp);
	r = (s = sfgetr(rp, '\n', 0)) ? *s : -1;
#endif
	return r;
}

/*
 * more write
 */

#if __STD_C
static ssize_t morewrite(Sfio_t* f, const Void_t* buf, register size_t n, Sfdisc_t* dp)
#else
static ssize_t morewrite(f, buf, n, dp)
Sfio_t* 	f;
Void_t*		buf;
register size_t	n;
Sfdisc_t*	dp;
#endif
{
	register More_t*	more = (More_t*)dp;
	register char*		b;
	register char*		s;
	register char*		e;
	register ssize_t	w;
	register int		r;

	if (!more->row)
		return n;
	if (!more->col)
		return sfwr(f, buf, n, dp);
	w = 0;
	b = (char*)buf;
	s = b;
	e = s + n;
	if (more->match)
	{
 match:
		for (r = more->pattern[0];; s++)
		{
			if (s >= e)
				return n;
			if (*s == '\n')
				b = s + 1;
			else if (*s == r && (e - s) >= more->match && !strncmp(s, more->pattern, more->match))
				break;
		}
		s = b;
		w += b - (char*)buf;
		more->match = 0;
	}
	while (s < e)
	{
		switch (*s++)
		{
		case '\t':
			more->col = ((more->col + 8) & ~7) - 1;
			/*FALLTHROUGH*/
		default:
			if (++more->col <= more->cols || s < e && *s == '\n')
				continue;
			/*FALLTHROUGH*/
		case '\n':
			more->col = 1;
			if (++more->row < more->rows)
				continue;
			break;
		case '\b':
			if (more->col > 1)
				more->col--;
			continue;
		case '\r':
			more->col = 1;
			continue;
		}
		w += sfwr(f, b, s - b, dp);
		b = s;
		r = ttyquery(sfstdin, f, more->prompt, dp);
		if (r == '/' || r == 'n')
		{
			if (r == '/')
			{
				sfwr(f, "/", 1, dp);
				if ((s = sfgetr(sfstdin, '\n', 1)) && (n = sfvalue(sfstdin) - 1) > 0)
				{
					if (n >= sizeof(more->pattern))
						n = sizeof(more->pattern) - 1;
					memcpy(more->pattern, s, n);
					more->pattern[n] = 0;
				}
			}
			if (more->match = strlen(more->pattern))
			{
				more->row = 1;
				more->col = 1;
				goto match;
			}
		}
		switch (r)
		{
		case '\n':
		case '\r':
			more->row--;
			more->col = 1;
			break;
		case ' ':
			more->row = 2;
			more->col = 1;
			break;
		default:
			more->row = 0;
			return n;
		}
	}
	if (s > b)
		w += sfwr(f, b, s - b, dp);
	return w;
}

/*
 * remove the discipline on close
 */

#if __STD_C
static int moreexcept(Sfio_t* f, int type, Void_t* data, Sfdisc_t* dp)
#else
static int moreexcept(f, type, data, dp)
Sfio_t*		f;
int		type;
Void_t*		data;
Sfdisc_t*	dp;
#endif
{
	register More_t*	more = (More_t*)dp;

	if (type == SF_FINAL || type == SF_DPOP)
	{
		if (f = more->input)
		{
			more->input = 0;
			sfdisc(f, SF_POPDISC);
		}
		else if (f = more->error)
		{
			more->error = 0;
			sfdisc(f, SF_POPDISC);
		}
		else
			free(dp);
	}
	else if (type == SF_SYNC)
	{
		more->match = 0;
		more->row = 1;
		more->col = 1;
	}
	return 0;
}

/*
 * push the more discipline on f
 * if prompt==0 then a default ansi prompt is used
 * if rows==0 or cols==0 then they are deterimined from the tty
 * if f==sfstdout then input on sfstdin also resets the state
 */

#if __STD_C
int sfdcmore(Sfio_t* f, const char* prompt, int rows, int cols)
#else
int sfdcmore(f, prompt, rows, cols)
Sfio_t*		f;
char*		prompt;
int		rows;
int		cols;
#endif
{
	register More_t*	more;
	size_t			n;

	/*
	 * this is a writeonly discipline for interactive io
	 */

	if (!(sfset(f, 0, 0) & SF_WRITE) || !isatty(sffileno(sfstdin)) || !isatty(sffileno(sfstdout)))
		return -1;
	if (!prompt)
		prompt = "\033[7m More\033[m";
	n = strlen(prompt) + 1;
	if (!(more = (More_t*)malloc(sizeof(More_t) + n)))
		return -1;
	memset(more, 0, sizeof(*more));

	more->disc.readf = moreread;
	more->disc.writef = morewrite;
	more->disc.exceptf = moreexcept;
	memcpy(more->prompt, prompt, n);
	if (!rows || !cols)
	{
#if _PACKAGE_ast
		astwinsize(sffileno(sfstdin), &rows, &cols);
#endif
		if (!rows)
			rows = 24;
		if (!cols)
			cols = 80;
	}
	more->rows = rows;
	more->cols = cols;
	more->row = 1;
	more->col = 1;

	if (sfdisc(f, &more->disc) != &more->disc)
	{	
		free(more);
		return -1;
	}
	if (f == sfstdout)
	{
		if (sfdisc(sfstdin, &more->disc) != &more->disc)
		{
			sfdisc(f, SF_POPDISC);
			return -1;
		}
		more->input = sfstdin;
		if (sfdisc(sfstderr, &more->disc) != &more->disc)
		{
			sfdisc(f, SF_POPDISC);
			return -1;
		}
		more->error = sfstdin;
	}

	return 0;
}
