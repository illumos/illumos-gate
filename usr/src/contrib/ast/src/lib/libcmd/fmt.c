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

static const char usage[] =
"[-?\n@(#)$Id: fmt (AT&T Research) 2007-01-02 $\n]"
USAGE_LICENSE
"[+NAME?fmt - simple text formatter]"
"[+DESCRIPTION?\bfmt\b reads the input files and left justifies space "
    "separated words into lines \awidth\a characters or less in length and "
    "writes the lines to the standard output. The standard input is read if "
    "\b-\b or no files are specified. Blank lines and interword spacing are "
    "preserved in the output. Indentation is preserved, and lines with "
    "identical indentation are joined and justified.]"
"[+?\bfmt\b is meant to format mail messages prior to sending, but may "
    "also be useful for other simple tasks. For example, in \bvi\b(1) the "
    "command \b:!}fmt\b will justify the lines in the current paragraph.]"
"[c:crown-margin?Preserve the indentation of the first two lines within "
    "a paragraph, and align the left margin of each subsequent line with "
    "that of the second line.]"
"[o:optget?Format concatenated \boptget\b(3) usage strings.]"
"[s:split-only?Split lines only; do not join short lines to form longer "
    "ones.]"
"[u:uniform-spacing?One space between words, two after sentences.]"
"[w:width?Set the output line width to \acolumns\a.]#[columns:=72]"
    "\n\n"
"[ file ... ]"
    "\n\n"
"[+SEE ALSO?\bmailx\b(1), \bnroff\b(1), \btroff\b(1), \bvi\b(1), "
    "\boptget\b(3)]"
;

#include <cmd.h>
#include <ctype.h>

typedef struct Fmt_s
{
	long	flags;
	char*	outp;
	char*	outbuf;
	char*	endbuf;
	Sfio_t*	in;
	Sfio_t*	out;
	int	indent;
	int	nextdent;
	int	nwords;
	int	prefix;
	int	quote;
	int	retain;
	int	section;
} Fmt_t;

#define INDENT		4
#define TABSZ		8

#define isoption(fp,c)	((fp)->flags&(1L<<((c)-'a')))
#define setoption(fp,c)	((fp)->flags|=(1L<<((c)-'a')))
#define clroption(fp,c)	((fp)->flags&=~(1L<<((c)-'a')))

static void
outline(Fmt_t* fp)
{
	register char*	cp = fp->outbuf;
	int		n = 0;
	int		c;
	int		d;

	if (!fp->outp)
		return;
	while (fp->outp[-1] == ' ')
		fp->outp--;
	*fp->outp = 0;
	while (*cp++ == ' ')
		n++;
	if (n >= TABSZ)
	{
		n /= TABSZ;
		cp = &fp->outbuf[TABSZ*n];
		while (n--)
			*--cp = '\t';
	}
	else
		cp = fp->outbuf;
	fp->nwords = 0;
	if (!isoption(fp, 'o'))
		sfputr(fp->out, cp, '\n');
	else if (*cp)
	{
		n = fp->indent;
		if (*cp != '[')
		{
			if (*cp == ' ')
				cp++;
			n += INDENT;
		}
		while (n--)
			sfputc(fp->out, ' ');
		if (fp->quote)
		{
			if ((d = (fp->outp - cp)) <= 0)
				c = 0;
			else if ((c = fp->outp[-1]) == 'n' && d > 1 && fp->outp[-2] == '\\')
				c = '}';
			sfprintf(fp->out, "\"%s%s\"\n", cp, c == ']' || c == '{' || c == '}' ? "" : " ");
		}
		else
			sfputr(fp->out, cp, '\n');
		if (fp->nextdent)
		{
			fp->indent += fp->nextdent;
			fp->endbuf -= fp->nextdent;
			fp->nextdent = 0;
		}
	}
	fp->outp = 0;
}

static void
split(Fmt_t* fp, char* buf, int splice)
{
	register char*	cp;
	register char*	ep;
	register char*	qp;
	register int	c = 1;
	register int	q = 0;
	register int	n;
	int		prefix;

	for (ep = buf; *ep == ' '; ep++);
	prefix = ep - buf;

	/*
	 * preserve blank lines
	 */

	if ((*ep == 0 || *buf == '.') && !isoption(fp, 'o'))
	{
		if (*ep)
			prefix = strlen(buf);
		outline(fp);
		strcpy(fp->outbuf, buf);
		fp->outp = fp->outbuf+prefix;
		outline(fp);
		return;
	}
	if (fp->prefix < prefix && !isoption(fp, 'c'))
		outline(fp);
	if (!fp->outp || prefix < fp->prefix)
		fp->prefix = prefix;
	while (c)
	{
		cp = ep;
		while (*ep == ' ')
			ep++;
		if (cp != ep && isoption(fp, 'u'))
			cp = ep-1;
		while (c = *ep)
		{
			if (c == ' ')
				break;
			ep++;

			/*
			 * skip over \space
			 */

			if (c == '\\' && *ep)
				ep++;
		}
		n = (ep-cp);
		if (n && isoption(fp, 'o'))
		{
			for (qp = cp; qp < ep; qp++)
				if (*qp == '\\')
					qp++;
				else if (*qp == '"')
					q = !q;
			if (*(ep-1) == '"')
				goto skip;
		}
		if (fp->nwords > 0 && &fp->outp[n] >= fp->endbuf && !fp->retain && !q)
			outline(fp);
	skip:
		if (fp->nwords == 0)
		{
			if (fp->prefix)
				memset(fp->outbuf, ' ', fp->prefix);
			fp->outp = &fp->outbuf[fp->prefix];
			while (*cp == ' ')
				cp++;
			n = (ep-cp);
		}
		memcpy(fp->outp, cp, n);
		fp->outp += n;
		fp->nwords++;
	}
	if (isoption(fp, 's') || *buf == 0)
		outline(fp);
	else if (fp->outp)
	{
		/*
		 * two spaces at ends of sentences
		 */

		if (!isoption(fp, 'o') && strchr(".:!?", fp->outp[-1]))
			*fp->outp++ = ' ';
		if (!splice && !fp->retain && (!fp->quote || (fp->outp - fp->outbuf) < 2 || fp->outp[-2] != '\\' || fp->outp[-1] != 'n' && fp->outp[-1] != 't' && fp->outp[-1] != ' '))
			*fp->outp++ = ' ';
	}
}

static int
dofmt(Fmt_t* fp)
{
	register int	c;
	int		b;
	int		x;
	int		splice;
	char*		cp;
	char*		dp;
	char*		ep;
	char*		lp;
	char*		tp;
	char		buf[8192];

	cp = 0;
	while (cp || (cp = sfgetr(fp->in, '\n', 0)) && !(splice = 0) && (lp = cp + sfvalue(fp->in) - 1) || (cp = sfgetr(fp->in, '\n', SF_LASTR)) && (splice = 1) && (lp = cp + sfvalue(fp->in)))
	{
		if (isoption(fp, 'o'))
		{
			if (!isoption(fp, 'i'))
			{
				setoption(fp, 'i');
				b = 0;
				while (cp < lp)
				{
					if (*cp == ' ')
						b += 1;
					else if (*cp == '\t')
						b += INDENT;
					else
						break;
					cp++;
				}
				fp->indent = roundof(b, INDENT);
			}
			else
				while (cp < lp && (*cp == ' ' || *cp == '\t'))
					cp++;
			if (!isoption(fp, 'q') && cp < lp)
			{
				setoption(fp, 'q');
				if (*cp == '"')
				{
					ep = lp;
					while (--ep > cp)
						if (*ep == '"')
						{
							fp->quote = 1;
							break;
						}
						else if (*ep != ' ' && *ep != '\t')
							break;
				}
			}
		}
	again:
		dp = buf;
		ep = 0;
		for (b = 1;; b = 0)
		{
			if (cp >= lp)
			{
				cp = 0;
				break;
			}
			c = *cp++;
			if (isoption(fp, 'o'))
			{
				if (c == '\\')
				{
					x = 0;
					c = ' ';
					cp--;
					while (cp < lp)
					{
						if (*cp == '\\')
						{
							cp++;
							if ((lp - cp) < 1)
							{
								c = '\\';
								break;
							}
							if (*cp == 'n')
							{
								cp++;
								c = '\n';
								if ((lp - cp) > 2)
								{
									if (*cp == ']' || *cp == '@' && *(cp + 1) == '(')
									{
										*dp++ = '\\';
										*dp++ = 'n';
										c = *cp++;
										break;
									}
									if (*cp == '\\' && *(cp + 1) == 'n')
									{
										cp += 2;
										*dp++ = '\n';
										break;
									}
								}
							}
							else if (*cp == 't' || *cp == ' ')
							{
								cp++;
								x = 1;
								c = ' ';
							}
							else
							{
								if (x && dp != buf && *(dp - 1) != ' ')
									*dp++ = ' ';
								*dp++ = '\\';
								c = *cp++;
								break;
							}
						}
						else if (*cp == ' ' || *cp == '\t')
						{
							cp++;
							c = ' ';
							x = 1;
						}
						else
						{
							if (x && c != '\n' && dp != buf && *(dp - 1) != ' ')
								*dp++ = ' ';
							break;
						}
					}
					if (c == '\n')
					{
						c = 0;
						goto flush;
					}
					if (c == ' ' && (dp == buf || *(dp - 1) == ' '))
						continue;
				}
				else if (c == '"')
				{
					if (b || cp >= lp)
					{
						if (fp->quote)
							continue;
						fp->section = 0;
					}
				}
				else if (c == '\a')
				{
					*dp++ = '\\';
					c = 'a';
				}
				else if (c == '\b')
				{
					*dp++ = '\\';
					c = 'b';
				}
				else if (c == '\f')
				{
					*dp++ = '\\';
					c = 'f';
				}
				else if (c == '\v')
				{
					*dp++ = '\\';
					c = 'v';
				}
				else if (c == ']' && (cp >= lp || *cp != ':' && *cp != '#' && *cp != '!'))
				{
					if (cp < lp && *cp == ']')
					{
						cp++;
						*dp++ = c;
					}
					else
					{
						fp->section = 1;
						fp->retain = 0;
					flush:
						*dp++ = c;
						*dp = 0;
						split(fp, buf, 0);
						outline(fp);
						goto again;
					}
				}
				else if (fp->section)
				{
					if (c == '[')
					{
						if (b)
							fp->retain = 1;
						else
						{
							cp--;
							c = 0;
							goto flush;
						}
						fp->section = 0;
					}
					else if (c == '{')
					{
						x = 1;
						for (tp = cp; tp < lp; tp++)
						{
							if (*tp == '[' || *tp == '\n')
								break;
							if (*tp == ' ' || *tp == '\t' || *tp == '"')
								continue;
							if (*tp == '\\' && (lp - tp) > 1)
							{
								if (*++tp == 'n')
									break;
								if (*tp == 't' || *tp == '\n')
									continue;
							}
							x = 0;
							break;
						}
						if (x)
						{
							if (fp->endbuf > (fp->outbuf + fp->indent + 2*INDENT))
								fp->nextdent = 2*INDENT;
							goto flush;
						}
						else
							fp->section = 0;
					}
					else if (c == '}')
					{
						if (fp->indent && (b || *(cp - 2) != 'f'))
						{
							if (b)
							{
								fp->indent -= 2*INDENT;
								fp->endbuf += 2*INDENT;
							}
							else
							{
								cp--;
								c = 0;
							}
							goto flush;
						}
						else
							fp->section = 0;
					}
					else if (c == ' ' || c == '\t')
						continue;
					else
						fp->section = 0;
				}
				else if (c == '?' && (cp >= lp || *cp != '?'))
				{
					if (fp->retain)
					{
						cp--;
						while (cp < lp && *cp != ' ' && *cp != '\t' && *cp != ']' && dp < &buf[sizeof(buf)-3])
							*dp++ = *cp++;
						if (cp < lp && (*cp == ' ' || *cp == '\t'))
							*dp++ = *cp++;
						*dp = 0;
						split(fp, buf, 0);
						dp = buf;
						ep = 0;
						fp->retain = 0;
						if (fp->outp >= fp->endbuf)
							outline(fp);
						continue;
					}
				}
				else if (c == ' ' || c == '\t')
					for (c = ' '; *cp == ' ' || *cp == '\t'; cp++);
			}
			else if (c == '\b')
			{
				if (dp > buf)
				{
					dp--;
					if (ep)
						ep--;
				}
				continue;
			}
			else if (c == '\t')
			{
				/*
				 * expand tabs
				 */

				if (!ep)
					ep = dp;
				c = isoption(fp, 'o') ? 1 : TABSZ - (dp - buf) % TABSZ;
				if (dp >= &buf[sizeof(buf) - c - 3])
				{
					cp--;
					break;
				}
				while (c-- > 0)
					*dp++ = ' ';
				continue;
			}
			else if (!isprint(c))
				continue;
			if (dp >= &buf[sizeof(buf) - 3])
			{
				tp = dp;
				while (--tp > buf)
					if (isspace(*tp))
					{
						cp -= dp - tp;
						dp = tp;
						break;
					}
				ep = 0;
				break;
			}
			if (c != ' ')
				ep = 0;
			else if (!ep)
				ep = dp;
			*dp++ = c;
		}
		if (ep)
			*ep = 0;
		else
			*dp = 0;
		split(fp, buf, splice);
	}
	return 0;
}

int
b_fmt(int argc, char** argv, Shbltin_t* context)
{
	register int	n;
	char*		cp;
	Fmt_t		fmt;
	char		outbuf[8 * 1024];

	fmt.flags = 0;
	fmt.out = sfstdout;
	fmt.outbuf = outbuf;
	fmt.outp = 0;
	fmt.endbuf = &outbuf[72];
	fmt.indent = 0;
	fmt.nextdent = 0;
	fmt.nwords = 0;
	fmt.prefix = 0;
	fmt.quote = 0;
	fmt.retain = 0;
	fmt.section = 1;
	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	for (;;)
	{
		switch (n = optget(argv, usage))
		{
		case 'c':
		case 'o':
		case 's':
		case 'u':
			setoption(&fmt, n);
			continue;
		case 'w':
			if (opt_info.num < TABSZ || opt_info.num>= sizeof(outbuf))
				error(2, "width out of range");
			fmt.endbuf = &outbuf[opt_info.num];
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
	if (error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	if (isoption(&fmt, 'o'))
		setoption(&fmt, 'c');
	if (isoption(&fmt, 's'))
		clroption(&fmt, 'u');
	if (cp = *argv)
		argv++;
	do {
		if (!cp || streq(cp, "-"))
			fmt.in = sfstdin;
		else if (!(fmt.in = sfopen(NiL, cp, "r")))
		{
			error(ERROR_system(0), "%s: cannot open", cp);
			error_info.errors = 1;
			continue;
		}
		dofmt(&fmt);
		if (fmt.in != sfstdin)
			sfclose(fmt.in);
	} while (cp = *argv++);
	outline(&fmt);
	if (sfsync(sfstdout))
		error(ERROR_system(0), "write error");
	return error_info.errors != 0;
}
