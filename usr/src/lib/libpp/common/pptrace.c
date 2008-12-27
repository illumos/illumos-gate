/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * preprocessor library trace and debug support
 */

#include "pplib.h"
#include "ppfsm.h"

#include <ctype.h>

/*
 * convert token string to printable form
 */

char*
pptokstr(register char* s, register int c)
{
	register char*	t;

	static char	buf[8];

	if (t = s)
	{
		while (*t == ' ' || *t == '\t') t++;
		c = *t ? *t : *s;
	}
	switch (c)
	{
	case 0:
	case 0400:
		return("`EOF'");
	case ' ':
		return("`space'");
	case '\f':
		return("`formfeed'");
	case '\n':
		return("`newline'");
	case '\t':
		return("`tab'");
	case '\v':
		return("`vertical-tab'");
	case T_TOKCAT:
		return("##");
	default:
		if (iscntrl(c) || !isprint(c)) sfsprintf(buf, sizeof(buf), "`%03o'", c);
		else if (s) return(s);
		else sfsprintf(buf, sizeof(buf), "%c", c);
		return(buf);
	}
}

#if DEBUG & TRACE_debug

#include "ppdebug.h"

/*
 * return input stream name given index
 */

char*
ppinstr(register struct ppinstk* p)
{
	register int	i;

	static char	buf[128];

	for (i = 0; i < elementsof(ppinmap); i++)
		if (p->type == ppinmap[i].val)
		{
			switch (p->type)
			{
			case IN_MACRO:
#if MACDEF
			case IN_MULTILINE:
#endif
				if (p->symbol)
				{
					sfsprintf(buf, sizeof(buf), "%s=%s", ppinmap[i].nam, p->symbol->name);
					return(buf);
				}
				break;
			}
			return(ppinmap[i].nam);
		}
	sfsprintf(buf, sizeof(buf), "UNKNOWN[%d]", p->type);
	return(buf);
}

/*
 * return string given fsm lex state
 */

char*
pplexstr(register int lex)
{
	register int	i;
	int		splice;
	static char	buf[64];

	if (lex < 0) lex &= ~lex;
	splice = (lex & SPLICE);
	lex &= 0x7f;
	for (i = 0; i < (elementsof(pplexmap) - 1) && (lex > pplexmap[i].val || lex == pplexmap[i+1].val); i++);
	if (lex != pplexmap[i].val)
	{
		if (pplexmap[i].val < 0) sfsprintf(buf, sizeof(buf), "%s|0x%04x%s", pplexmap[i].nam, lex, splice ? "|SPLICE" : "");
		else sfsprintf(buf, sizeof(buf), "%s+%d", pplexmap[i-1].nam, lex - pplexmap[i-1].val, splice ? "|SPLICE" : "");
		return(buf);
	}
	if (splice)
	{
		sfsprintf(buf, sizeof(buf), "%s|SPLICE", pplexmap[i].nam);
		return(buf);
	}
	return(pplexmap[i].nam);
}

/*
 * return string given map p of size n and flags
 */

static char*
ppflagstr(register struct map* p, int n, register long flags)
{
	register int	i;
	register int	k;
	register char*	s;

	static char	buf[128];

	s = buf;
	for (i = 0; i < n; i++)
		if (flags & p[i].val)
		{
			k = strlen(p[i].nam);
			if ((elementsof(buf) - 2 - (s - buf)) > k)
			{
				if (s > buf) *s++ = '|';
				strcpy(s, p[i].nam);
				s += k;
			}
		}
	*s = 0;
	return(buf);
}

/*
 * return string given pp.mode
 */

char*
ppmodestr(register long mode)
{
	return(ppflagstr(ppmodemap, elementsof(ppmodemap), mode));
}

/*
 * return string given pp.option
 */

char*
ppoptionstr(register long option)
{
	return(ppflagstr(ppoptionmap, elementsof(ppoptionmap), option));
}

/*
 * return string given pp.state
 */

char*
ppstatestr(register long state)
{
	return(ppflagstr(ppstatemap, elementsof(ppstatemap), state));
}

#include <sig.h>

/*
 * io stream stack trace
 * sig==0 registers the handler
 */

void
pptrace(int sig)
{
	register char*			s;
	register char*			x;
	register struct ppinstk*	p;
	static int			handling;

	if (!sig)
	{
#ifdef SIGBUS
		signal(SIGBUS, pptrace);
#endif
#ifdef SIGSEGV
		signal(SIGSEGV, pptrace);
#endif
#ifdef SIGILL
		signal(SIGILL, pptrace);
#endif
		signal(SIGQUIT, pptrace);
		return;
	}
	s = fmtsignal(sig);
	if (handling)
	{
		sfprintf(sfstderr, "\n%s during io stack trace\n", s);
		signal(handling, SIG_DFL);
		sigunblock(handling);
		kill(getpid(), handling);
		pause();
		error(PANIC, "signal not redelivered");
	}
	handling = sig;
	sfprintf(sfstderr, "\n%s - io stack trace\n", s);
	for (p = pp.in; p->prev; p = p->prev)
	{
		sfprintf(sfstderr, "\n[%s]\n", ppinstr(p));
		if ((s = pp.in->nextchr) && *s)
		{
			if (*s != '\n') sfputc(sfstderr, '\t');
			x = s + 256;
			while (*s && s < x)
			{
				sfputc(sfstderr, *s);
				if (*s++ == '\n' && *s && *s != '\n') sfputc(sfstderr, '\t');
			}
			if (*s) sfprintf(sfstderr, " ...");
		}
	}
	sfprintf(sfstderr, "\n");
	handling = 0;
	signal(sig, SIG_DFL);
	sigunblock(sig);
	kill(getpid(), sig);
	pause();
	error(PANIC, "signal not redelivered");
}

#endif
