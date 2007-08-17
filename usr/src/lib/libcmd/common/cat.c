/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1992-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * cat
 */

#include <cmd.h>
#include <fcntl.h>

static const char usage[] =
"[-?\n@(#)$Id: cat (AT&T Research) 2006-05-17 $\n]"
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
"[v:show-nonprinting?Causes non-printing characters (whith the exception of"
"	tabs, new-lines, and form-feeds) to be output as printable charater"
"	sequences. ASCII control characters are printed as \b^\b\an\a,"
"	where \an\a is the corresponding ASCII character in the range"
"	octal 100-137. The DEL character (octal 0177) is copied"
"	as \b^?\b. Other non-printable characters are copied as \bM-\b\ax\a"
"	where \ax\a is the ASCII character specified by the low-order seven"
"	bits.  Multibyte characters in the current locale are treated as"
"	printable characters.]"
"[A:show-all?Equivalent to \b-vET\b.]"
"[B:squeeze-blank?Multiple adjacent new-line characters are replace by one"
"	new-line.]"
"[D:dos-output?Output files are opened in \atext\amode which inserts carriage"
"	returns in front of new-lines on some systems.]"
"[E:show-ends?Causes a \b$\b to be inserted before each new-line.]"
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
#define T_ENDBUF	1
#define T_CONTROL	2
#define T_NEWLINE	3
#define T_EIGHTBIT	4
#define T_CNTL8BIT	5

#define printof(c)	((c)^0100)

/*
 * called for any special output processing
 */

static int
vcat(register char* states, Sfio_t *fdin, Sfio_t *fdout, int flags)
{
	register unsigned char*	cp;
	register unsigned char*	cpold;
	register int		n;
	register int		m;
	register int		line = 1;
	register unsigned char*	endbuff;
	unsigned char*		inbuff;
	int			printdefer = (flags&(B_FLAG|N_FLAG));
	int			lastchar;

	unsigned char		meta[4];

	meta[0] = 'M';
	meta[1] = '-';
	for (;;)
	{
		/* read in a buffer full */
		if (!(inbuff = (unsigned char*)sfreserve(fdin, SF_UNBOUND, 0)))
			return sfvalue(fdin) ? -1 : 0;
		if ((n = sfvalue(fdin)) <= 0)
			return n;
		cp = inbuff;
		lastchar = *(endbuff = cp + --n);
		*endbuff = 0;
		if (printdefer)
		{
			if (states[*cp]!=T_NEWLINE || !(flags&B_FLAG))
				sfprintf(fdout,"%6d\t",line);
			printdefer = 0;
		}
		while (endbuff)
		{
			cpold = cp;
			/* skip over printable characters */
			if (mbwide())
				while ((n = (m = mbsize(cp)) < 2 ? states[*cp++] : (cp += m, states['a'])) == 0);
			else
				while ((n = states[*cp++]) == 0);
			if (n==T_ENDBUF)
			{
				if (cp>endbuff)
				{
					if (!(n = states[lastchar]))
					{
						*endbuff = lastchar;
						cp++;
					}
					else
					{
						if (--cp > cpold)
							sfwrite(fdout,(char*)cpold,cp-cpold);
						if (endbuff==inbuff)
							*++endbuff = 0;
						cp = cpold = endbuff;
						cp[-1] = lastchar;
						if (n==T_ENDBUF)
							n = T_CONTROL;
						
					}
					endbuff = 0;
				}
				else n = T_CONTROL;
			}
			if (--cp>cpold)
				sfwrite(fdout,(char*)cpold,cp-cpold);
			switch(n)
			{
				case T_CNTL8BIT:
					meta[2] = '^';
					do
					{
						n = (*cp++)&~0200;
						meta[3] = printof(n);
						sfwrite(fdout,(char*)meta,4);
					}
					while ((n=states[*cp])==T_CNTL8BIT);
					break;
				case T_EIGHTBIT:
					do
					{
						meta[2] = (*cp++)&~0200;
						sfwrite(fdout,(char*)meta,3);
					}
					while ((n=states[*cp])==T_EIGHTBIT);
					break;
				case T_CONTROL:
					do
					{
						n = *cp++;
						sfputc(fdout,'^');
						sfputc(fdout,printof(n));
					}
					while ((n=states[*cp])==T_CONTROL);
					break;
				case T_NEWLINE:
					if (flags&S_FLAG)
					{
						while (states[*++cp]==T_NEWLINE)
							line++;
						cp--;
					}
					do
					{
						cp++;
						if (flags&E_FLAG)
							sfputc(fdout,'$');
						sfputc(fdout,'\n');
						if (!(flags&(N_FLAG|B_FLAG)))
							continue;
						line++;
						if (cp < endbuff)
							sfprintf(fdout,"%6d\t",line);
						else printdefer = 1;
					}
					while (states[*cp]==T_NEWLINE);
					break;
			}
		}
	}
}

int
b_cat(int argc, char** argv, void* context)
{
	register int		n;
	register int		flags = 0;
	register char*		cp;
	register Sfio_t*	fp;
	char*			mode;
	int			att;
	int			dovcat=0;
	char			states[UCHAR_MAX+1];

	NoP(argc);
	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	att = !strcmp(astconf("UNIVERSE", NiL, NiL), "att");
	mode = "r";
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'A':
			flags |= T_FLAG|E_FLAG|V_FLAG;
			continue;
		case 'B':
			flags |= S_FLAG;
			continue;
		case 'b':
			flags |= B_FLAG;
			continue;
		case 'E':
			flags |= E_FLAG;
			continue;
		case 'e':
			flags |= E_FLAG|V_FLAG;
			continue;
		case 'n':
			flags |= N_FLAG;
			continue;
		case 's':
			flags |= att ? F_FLAG : S_FLAG;
			continue;
		case 'S':
			flags |= F_FLAG;
			continue;
		case 'T':
			flags |= T_FLAG;
			continue;
		case 't':
			flags |= T_FLAG|V_FLAG;
			continue;
		case 'u':
			flags |= U_FLAG;
			continue;
		case 'v':
			flags |= V_FLAG;
			continue;
		case 'd':
			mode = "rt";
			continue;
		case 'D':
			flags |= d_FLAG;
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
	if (flags&(V_FLAG|T_FLAG|N_FLAG|E_FLAG|B_FLAG))
	{
		states['\n'] = T_NEWLINE;
		dovcat = 1;
	}
	if (flags&B_FLAG)
		flags |= S_FLAG;
	if (flags&d_FLAG)
		sfopen(sfstdout, NiL, "wt");
	if (cp = *argv)
		argv++;
	do
	{
		if (!cp || streq(cp,"-"))
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
			n = vcat(states, fp, sfstdout, flags);
		else if (sfmove(fp, sfstdout, SF_UNBOUND, -1) >= 0 && sfeof(fp))
			n = 0;
		else
			n = -1;
		if (fp != sfstdin)
			sfclose(fp);
		if (n < 0 && errno != EPIPE)
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
