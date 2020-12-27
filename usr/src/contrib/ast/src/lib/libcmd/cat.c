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
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * cat
 */

#include <cmd.h>
#include <fcntl.h>

static const char usage[] =
"[-?\n@(#)$Id: cat (AT&T Research) 2012-05-31 $\n]"
USAGE_LICENSE
"[+NAME?cat - concatenate files]"
"[+DESCRIPTION?\bcat\b copies each \afile\a in sequence to the standard"
"	output. If no \afile\a is given, or if the \afile\a is \b-\b,"
"	\bcat\b copies from standard input starting at the current location.]"

"[b:number-nonblank?Number lines as with \b-n\b but omit line numbers from"
"	blank lines.]"
"[d:dos-input?Input files are opened in \atext\amode which removes carriage"
"	returns in front of new-lines on some systems.]"
"[e?Equivalent to \b-vE\b.]"
"[n:number?Causes a line number to be inserted at the beginning of each line.]"
"[s?Equivalent to \b-S\b for \aatt\a universe and \b-B\b otherwise.]"
"[t?Equivalent to \b-vT\b.]"
"[u:unbuffer?The output is not delayed by buffering.]"
"[v:show-nonprinting|print-chars?Print characters as follows: space and "
    "printable characters as themselves; control characters as \b^\b "
    "followed by a letter of the alphabet; and characters with the high bit "
    "set as the lower 7 bit character prefixed by \bM^\b for 7 bit "
    "non-printable characters and \bM-\b for all other characters. If the 7 "
    "bit character encoding is not ASCII then the characters are converted "
    "to ASCII to determine \ahigh bit set\a, and if set it is cleared and "
    "converted back to the native encoding. Multibyte characters in the "
    "current locale are treated as printable characters.]"
"[A:show-all?Equivalent to \b-vET\b.]"
"[B:squeeze-blank?Multiple adjacent new-line characters are replace by one"
"	new-line.]"
"[D:dos-output?Output files are opened in \atext\amode which inserts carriage"
"	returns in front of new-lines on some systems.]"
"[E:show-ends?Causes a \b$\b to be inserted before each new-line.]"
"[R:regress?Regression test defaults: \b-v\b buffer size 4.]"
"[S:silent?\bcat\b is silent about non-existent files.]"
"[T:show-blank?Causes tabs to be copied as \b^I\b and formfeeds as \b^L\b.]"

"\n"
"\n[file ...]\n"
"\n"

"[+SEE ALSO?\bcp\b(1), \bgetconf\b(1), \bpr\b(1)]"
;

#define RUBOUT	0177

/* control flags */
#define B_FLAG		(1<<0)
#define E_FLAG		(1<<1)
#define F_FLAG		(1<<2)
#define N_FLAG		(1<<3)
#define S_FLAG		(1<<4)
#define T_FLAG		(1<<5)
#define U_FLAG		(1<<6)
#define V_FLAG		(1<<7)
#define D_FLAG		(1<<8)
#define d_FLAG		(1<<9)

/* character types */
#define T_ERROR		1
#define T_EOF		2
#define T_ENDBUF	3
#define T_NEWLINE	4
#define T_CONTROL	5
#define T_EIGHTBIT	6
#define T_CNTL8BIT	7

#define printof(c)	((c)^0100)

typedef void* (*Reserve_f)(Sfio_t*, ssize_t, int);

#ifndef sfvalue
#define sfvalue(f)	((f)->_val)
#endif

static void*
regress(Sfio_t* sp, ssize_t n, int f)
{
	void*	r;

	if (!(r = sfreserve(sp, 4, f)))
		r = sfreserve(sp, n, f);
	else if (sfvalue(sp) > 4)
		sfvalue(sp) = 4;
	return r;
}

/*
 * called for any special output processing
 */

static int
vcat(register char* states, Sfio_t* ip, Sfio_t* op, Reserve_f reserve, int flags)
{
	register unsigned char*	cp;
	register unsigned char*	pp;
	unsigned char*		cur;
	unsigned char*		end;
	unsigned char*		buf;
	unsigned char*		nxt;
	register int		n;
	register int		line;
	register int		raw;
	int			last;
	int			c;
	int			m;
	int			any;
	int			header;

	unsigned char		meta[3];
	unsigned char		tmp[32];

	meta[0] = 'M';
	last = -1;
	*(cp = buf = end = tmp) = 0;
	any = 0;
	header = flags & (B_FLAG|N_FLAG);
	line = 1;
	states[0] = T_ENDBUF;
	raw = !mbwide();
	for (;;)
	{
		cur = cp;
		if (raw)
			while (!(n = states[*cp++]));
		else
			for (;;)
			{
				while (!(n = states[*cp++]));
				if (n < T_CONTROL)
					break;
				if ((m = mbsize(pp = cp - 1)) > 1)
					cp += m - 1;
				else
				{
					if (m <= 0)
					{
						if (cur == pp)
						{
							if (last > 0)
							{
								*end = last;
								last = -1;
								c = end - pp + 1;
								if ((m = mbsize(pp)) == c)
								{
									any = 1;
									if (header)
									{
										header = 0;
										sfprintf(op, "%6d\t", line);
									}
									sfwrite(op, cur, m);
									*(cp = cur = end) = 0;
								}
								else
								{
									memcpy(tmp, pp, c);
									if (!(nxt = (unsigned char*)(*reserve)(ip, SF_UNBOUND, 0)))
									{
										states[0] = sfvalue(ip) ? T_ERROR : T_EOF;
										*(cp = end = tmp + sizeof(tmp) - 1) = 0;
										last = -1;
									}
									else if ((n = sfvalue(ip)) <= 0)
									{
										states[0] = n ? T_ERROR : T_EOF;
										*(cp = end = tmp + sizeof(tmp) - 1) = 0;
										last = -1;
									}
									else
									{
										cp = buf = nxt;
										end = buf + n - 1;
										last = *end;
										*end = 0;
									}
 mb:
									if ((n = end - cp + 1) >= (sizeof(tmp) - c))
										n = sizeof(tmp) - c - 1;
									memcpy(tmp + c, cp, n);
									if ((m = mbsize(tmp)) >= c)
									{
										any = 1;
										if (header)
										{
											header = 0;
											sfprintf(op, "%6d\t", line);
										}
										sfwrite(op, tmp, m);
										cur = cp += m - c;
									}
								}
								continue;
							}
						}
						else
						{
							cp = pp + 1;
							n = 0;
						}
					}
					break;
				}
			}
		c = *--cp;
		if ((m = cp - cur) || n >= T_CONTROL)
		{
 flush:
			any = 1;
			if (header)
			{
				header = 0;
				sfprintf(op, "%6d\t", line);
			}
			if (m)
				sfwrite(op, cur, m);
		}
 special:
		switch (n)
		{
		case T_ERROR:
			if (cp < end)
			{
				n = T_CONTROL;
				goto flush;
			}
			return -1;
		case T_EOF:
			if (cp < end)
			{
				n = T_CONTROL;
				goto flush;
			}
			return 0;
		case T_ENDBUF:
			if (cp < end)
			{
				n = T_CONTROL;
				goto flush;
			}
			c = last;
			if (!(nxt = (unsigned char*)(*reserve)(ip, SF_UNBOUND, 0)))
			{
				*(cp = end = tmp + sizeof(tmp) - 1) = 0;
				states[0] = (m = sfvalue(ip)) ? T_ERROR : T_EOF;
				last = -1;
			}
			else if ((m = sfvalue(ip)) <= 0)
			{
				*(cp = end = tmp + sizeof(tmp) - 1) = 0;
				states[0] = m ? T_ERROR : T_EOF;
				last = -1;
			}
			else
			{
				buf = nxt;
				end = buf + m - 1;
				last = *end;
				*end = 0;
				cp = buf;
			}
			if (c >= 0)
			{
				if (!(n = states[c]))
				{
					*(cur = tmp) = c;
					m = 1;
					goto flush;
				}
				if (raw || n < T_CONTROL)
				{
					cp--;
					goto special;
				}
				tmp[0] = c;
				c = 1;
				goto mb;
			}
			break;
		case T_CONTROL:
			do
			{
				sfputc(op, '^');
				sfputc(op, printof(c));
			} while (states[c = *++cp] == T_CONTROL);
			break;
		case T_CNTL8BIT:
			meta[1] = '^';
			do
			{
				n = c & ~0200;
				meta[2] = printof(n);
				sfwrite(op, (char*)meta, 3);
			} while (states[c = *++cp] == T_CNTL8BIT && raw);
			break;
		case T_EIGHTBIT:
			meta[1] = '-';
			do
			{
				meta[2] = c & ~0200;
				sfwrite(op, (char*)meta, 3);
			} while (states[c = *++cp] == T_EIGHTBIT && raw);
			break;
		case T_NEWLINE:
			if (header && !(flags & B_FLAG))
				sfprintf(op, "%6d\t", line);
			if (flags & E_FLAG)
				sfputc(op, '$');
			sfputc(op, '\n');
			if (!header || !(flags & B_FLAG))
				line++;
			header = !(flags & S_FLAG);
			for (;;)
			{
				if ((n = states[*++cp]) == T_ENDBUF)
				{
					if (cp < end || last != '\n')
						break;
					if (!(nxt = (unsigned char*)(*reserve)(ip, SF_UNBOUND, 0)))
					{
						states[0] = sfvalue(ip) ? T_ERROR : T_EOF;
						cp = end = tmp;
						*cp-- = 0;
						last = -1;
					}
					else if ((n = sfvalue(ip)) <= 0)
					{
						states[0] = n ? T_ERROR : T_EOF;
						cp = end = tmp;
						*cp-- = 0;
						last = -1;
					}
					else
					{
						buf = nxt;
						end = buf + n - 1;
						last = *end;
						*end = 0;
						cp = buf - 1;
					}
				}
				else if (n != T_NEWLINE)
					break;
				if (!(flags & S_FLAG) || any || header)
				{
					any = 0;
					header = 0;
					if ((flags & (B_FLAG|N_FLAG)) == N_FLAG)
						sfprintf(op, "%6d\t", line);
					if (flags & E_FLAG)
						sfputc(op, '$');
					sfputc(op, '\n');
				}
				if (!(flags & B_FLAG))
					line++;
			}
			header = flags & (B_FLAG|N_FLAG);
			break;
		}
	}
}

int
b_cat(int argc, char** argv, Shbltin_t* context)
{
	register int		n;
	register int		flags = 0;
	register char*		cp;
	register Sfio_t*	fp;
	char*			mode;
	Reserve_f		reserve = sfreserve;
	int			att;
	int			dovcat = 0;
	char			states[UCHAR_MAX+1];

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	att = !strcmp(astconf("UNIVERSE", NiL, NiL), "att");
	mode = "r";
	for (;;)
	{
		n = 0;
		switch (optget(argv, usage))
		{
		case 'A':
			n = T_FLAG|E_FLAG|V_FLAG;
			break;
		case 'B':
			n = S_FLAG;
			break;
		case 'b':
			n = B_FLAG;
			break;
		case 'd':
			mode = opt_info.num ? "rt" : "r";
			continue;
		case 'D':
			n = d_FLAG;
			break;
		case 'E':
			n = E_FLAG;
			break;
		case 'e':
			n = E_FLAG|V_FLAG;
			break;
		case 'n':
			n = N_FLAG;
			break;
		case 'R':
			reserve = opt_info.num ? regress : sfreserve;
			continue;
		case 's':
			n = att ? F_FLAG : S_FLAG;
			break;
		case 'S':
			n = F_FLAG;
			break;
		case 'T':
			n = T_FLAG;
			break;
		case 't':
			n = T_FLAG|V_FLAG;
			break;
		case 'u':
			n = U_FLAG;
			break;
		case 'v':
			n = V_FLAG;
			break;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		case '?':
			error(ERROR_usage(2), "%s", opt_info.arg);
			break;
		}
		if (!n)
			break;
		if (opt_info.num)
			flags |= n;
		else
			flags &= ~n;
	}
	argv += opt_info.index;
	if (error_info.errors)
		error(ERROR_usage(2), "%s", optusage(NiL));
	memset(states, 0, sizeof(states));
	if (flags&V_FLAG)
	{
		memset(states, T_CONTROL, ' ');
		states[RUBOUT] = T_CONTROL;
		memset(states+0200, T_EIGHTBIT, 0200);
		memset(states+0200, T_CNTL8BIT, ' ');
		states[RUBOUT|0200] = T_CNTL8BIT;
		states['\n'] = 0;
	}
	if (flags&T_FLAG)
		states['\t'] = T_CONTROL;
	states[0] = T_ENDBUF;
	if (att)
	{
		if (flags&V_FLAG)
		{
			states['\n'|0200] = T_EIGHTBIT;
			if (!(flags&T_FLAG))
			{
				states['\t'] = states['\f'] = 0;
				states['\t'|0200] = states['\f'|0200] = T_EIGHTBIT;
			}
		}
	}
	else if (flags)
	{
		if (!(flags&T_FLAG))
			states['\t'] = 0;
	}
	if (flags&(V_FLAG|T_FLAG|N_FLAG|E_FLAG|B_FLAG|S_FLAG))
	{
		states['\n'] = T_NEWLINE;
		dovcat = 1;
	}
	if (flags&d_FLAG)
		sfopen(sfstdout, NiL, "wt");
	if (cp = *argv)
		argv++;
	do
	{
		if (!cp || streq(cp, "-"))
		{
			fp = sfstdin;
			if (flags&D_FLAG)
				sfopen(fp, NiL, mode);
		}
		else if (!(fp = sfopen(NiL, cp, mode)))
		{
			if (!(flags&F_FLAG))
				error(ERROR_system(0), "%s: cannot open", cp);
			error_info.errors = 1;
			continue;
		}
		if (flags&U_FLAG)
			sfsetbuf(fp, (void*)fp, -1);
		if (dovcat)
			n = vcat(states, fp, sfstdout, reserve, flags);
		else if (sfmove(fp, sfstdout, SF_UNBOUND, -1) >= 0 && sfeof(fp))
			n = 0;
		else
			n = -1;
		if (fp != sfstdin)
			sfclose(fp);
		if (n < 0 && !ERROR_PIPE(errno) && errno != EINTR)
		{
			if (cp)
				error(ERROR_system(0), "%s: read error", cp);
			else
				error(ERROR_system(0), "read error");
		}
		if (sferror(sfstdout))
			break;
	} while (cp = *argv++);
	if (sfsync(sfstdout))
		error(ERROR_system(0), "write error");
	if (flags&d_FLAG)
		sfopen(sfstdout, NiL, "w");
	return error_info.errors;
}
