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
 * preprocessor builtin macro support
 */

#include "pplib.h"

#include <times.h>

/*
 * process a #(...) builtin macro call
 * `#(' has already been seen
 */

void
ppbuiltin(void)
{
	register int		c;
	register char*		p;
	register char*		a;

	int			n;
	int			op;
	char*			token;
	char*			t;
	long			number;
	long			onumber;
	struct ppinstk*		in;
	struct pplist*		list;
	struct ppsymbol*	sym;
	Sfio_t*			sp;

	number = pp.state;
	pp.state |= DISABLE|FILEPOP|NOSPACE;
	token = pp.token;
	p = pp.token = pp.tmpbuf;
	*(a = pp.args) = 0;
	if ((c = pplex()) != T_ID)
	{
		error(2, "%s: #(<identifier>...) expected", p);
		*p = 0;
	}
	switch (op = (int)hashget(pp.strtab, p))
	{
	case V_DEFAULT:
		n = 0;
		p = pp.token = pp.valbuf;
		if ((c = pplex()) == ',')
		{
			op = -1;
			c = pplex();
		}
		pp.state &= ~NOSPACE;
		for (;;)
		{
			if (!c)
			{
				error(2, "%s in #(...) argument", pptokchr(c));
				break;
			}
			if (c == '(') n++;
			else if (c == ')' && !n--) break;
			else if (c == ',' && !n && op > 0) op = 0;
			if (op) pp.token = pp.toknxt;
			c = pplex();
		}
		*pp.token = 0;
		pp.token = token;
		pp.state = number;
		break;
	case V_EMPTY:
		p = pp.valbuf;
		if ((c = pplex()) == ')') *p = '1';
		else
		{
			*p = '0';
			n = 0;
			for (;;)
			{
				if (!c)
				{
					error(2, "%s in #(...) argument", pptokchr(c));
					break;
				}
				if (c == '(') n++;
				else if (c == ')' && !n--) break;
				c = pplex();
			}
		}
		*(p + 1) = 0;
		pp.token = token;
		pp.state = number;
		break;
	case V_ITERATE:
		n = 0;
		pp.token = pp.valbuf;
		if ((c = pplex()) != T_ID || !(sym = ppsymref(pp.symtab, pp.token)) || !sym->macro || sym->macro->arity != 1 || (c = pplex()) != ',')
		{
			error(2, "#(%s <macro(x)>, ...) expected", p);
			for (;;)
			{
				if (!c)
				{
					error(2, "%s in #(...) argument", pptokchr(c));
					break;
				}
				if (c == '(') n++;
				else if (c == ')' && !n--) break;
				c = pplex();
			}
			*pp.valbuf = 0;
		}
		else while (c != ')')
		{
			p = pp.token;
			if (pp.token > pp.valbuf) *pp.token++ = ' ';
			STRCOPY(pp.token, sym->name, a);
			*pp.token++ = '(';
			if (!c || !(c = pplex()))
			{
				pp.token = p;
				error(2, "%s in #(...) argument", pptokchr(c));
				break;
			}
			pp.state &= ~NOSPACE;
			while (c)
			{
				if (c == '(') n++;
				else if (c == ')' && !n--) break;
				else if (c == ',' && !n) break;
				pp.token = pp.toknxt;
				c = pplex();
			}
			*pp.token++ = ')';
			pp.state |= NOSPACE;
		}
		p = pp.valbuf;
		pp.token = token;
		pp.state = number;
		break;
	default:
		pp.token = token;
		while (c != ')')
		{
			if (!c)
			{
				error(2, "%s in #(...) argument", pptokchr(c));
				break;
			}
			if ((c = pplex()) == T_ID && !*a)
				strcpy(a, pp.token);
		}
		pp.state = number;
		switch (op)
		{
		case V_ARGC:
			c = -1;
			for (in = pp.in; in; in = in->prev)
				if ((in->type == IN_MACRO || in->type == IN_MULTILINE) && (in->symbol->flags & SYM_FUNCTION))
				{
					c = *((unsigned char*)(pp.macp->arg[0] - 2));
					break;
				}
			sfsprintf(p = pp.valbuf, MAXTOKEN, "%d", c);
			break;
		case V_BASE:
			p = (a = strrchr(error_info.file, '/')) ? a + 1 : error_info.file;
			break;
		case V_DATE:
			if (!(p = pp.date))
			{
				time_t	tm;

				time(&tm);
				a = p = ctime(&tm) + 4;
				*(p + 20) = 0;
				for (p += 7; *p = *(p + 9); p++);
				pp.date = p = strdup(a);
			}
			break;
		case V_FILE:
			p = error_info.file;
			break;
		case V_LINE:
			sfsprintf(p = pp.valbuf, MAXTOKEN, "%d", error_info.line);
			break;
		case V_PATH:
			p = pp.path;
			break;
		case V_SOURCE:
			p = error_info.file;
			for (in = pp.in; in->prev; in = in->prev)
				if (in->prev->type == IN_FILE && in->file)
					p = in->file;
			break;
		case V_STDC:
			p = pp.valbuf;
			p[0] = ((pp.state & (COMPATIBILITY|TRANSITION)) || (pp.mode & (HOSTED|HOSTEDTRANSITION)) == (HOSTED|HOSTEDTRANSITION)) ? '0' : '1';
			p[1] = 0;
			break;
		case V_TIME:
			if (!(p = pp.time))
			{
				time_t	tm;

				time(&tm);
				p = ctime(&tm) + 11;
				*(p + 8) = 0;
				pp.time = p = strdup(p);
			}
			break;
		case V_VERSION:
			p = (char*)pp.version;
			break;
		case V_DIRECTIVE:
			pp.state |= NEWLINE;
			pp.mode |= RELAX;
			strcpy(p = pp.valbuf, "#");
			break;
		case V_GETENV:
			if (!(p = getenv(a))) p = "";
			break;
		case V_GETMAC:
			p = (sym = pprefmac(a, REF_NORMAL)) ? sym->macro->value : "";
			break;
		case V_GETOPT:
			sfsprintf(p = pp.valbuf, MAXTOKEN, "%ld", ppoption(a));
			break;
		case V_GETPRD:
			p = (list = (struct pplist*)hashget(pp.prdtab, a)) ? list->value : "";
			break;
		case V__PRAGMA:
			if ((c = pplex()) == '(')
			{
				number = pp.state;
				pp.state |= NOSPACE|STRIP;
				c = pplex();
				pp.state = number;
				if (c == T_STRING || c == T_WSTRING)
				{
					if (!(sp = sfstropen()))
						error(3, "temporary buffer allocation error");
					sfprintf(sp, "#%s %s\n", dirname(PRAGMA), pp.token);
					a = sfstruse(sp);
					if ((c = pplex()) == ')')
					{
						pp.state |= NEWLINE;
						PUSH_BUFFER(p, a, 1);
					}
					sfstrclose(sp);
				}
			}
			if (c != ')')
				error(2, "%s: (\"...\") expected", p);
			return;
		case V_FUNCTION:

#define BACK(a,p)	((a>p)?*--a:(number++?0:((p=pp.outbuf+PPBUFSIZ),(a=pp.outbuf+2*PPBUFSIZ),*--a)))
#define PEEK(a,p)	((a>p)?*(a-1):(number?0:*(pp.outbuf+2*PPBUFSIZ-1)))

			number = pp.outbuf != pp.outb;
			a = pp.outp;
			p = pp.outb;
			op = 0;
			while (c = BACK(a, p))
			{
				if (c == '"' || c == '\'')
				{
					op = 0;
					while ((n = BACK(a, p)) && n != c || PEEK(a, p) == '\\');
				}
				else if (c == '\n')
				{
					token = a;
					while (c = BACK(a, p))
						if (c == '\n')
						{
							a = token;
							break;
						}
						else if (c == '#' && PEEK(a, p) == '\n')
							break;
				}
				else if (c == ' ')
					/*ignore*/;
				else if (c == '{') /* '}' */
					op = 1;
				else if (op == 1)
				{
					if (c == ')')
					{
						op = 2;
						n = 1;
					}
					else
						op = 0;
				}
				else if (op == 2)
				{
					if (c == ')')
						n++;
					else if (c == '(' && !--n)
						op = 3;
				}
				else if (op == 3)
				{
					if (ppisidig(c))
					{
						for (t = p, token = a, onumber = number; ppisidig(PEEK(a, p)) && a >= p; BACK(a, p));
						p = pp.valbuf + 1;
						if (a > token)
						{
							for (; a < pp.outbuf+2*PPBUFSIZ; *p++ = *a++);
							a = pp.outbuf;
						}
						for (; a <= token; *p++ = *a++);
						*p = 0;
						p = pp.valbuf + 1;
						if (streq(p, "for") || streq(p, "if") || streq(p, "switch") || streq(p, "while"))
						{
							op = 0;
							p = t;
							number = onumber;
							continue;
						}
					}
					else
						op = 0;
					break;
				}
			}
			if (op == 3)
				p = strncpy(pp.funbuf, p, sizeof(pp.funbuf) - 1);
			else if (*pp.funbuf)
				p = pp.funbuf;
			else
				p = "__FUNCTION__";
			break;
		default:
			if (pp.builtin && (a = (*pp.builtin)(pp.valbuf, p, a)))
				p = a;
			break;
		}
		break;
	}
	if (strchr(p, MARK))
	{
		a = pp.tmpbuf;
		strcpy(a, p);
		c = p != pp.valbuf;
		p = pp.valbuf + c;
		for (;;)
		{
			if (p < pp.valbuf + MAXTOKEN - 2)
				switch (*p++ = *a++)
				{
				case 0:
					break;
				case MARK:
					*p++ = MARK;
					/*FALLTHROUGH*/
				default:
					continue;
				}
			break;
		}
		p = pp.valbuf + c;
	}
	if (p == pp.valbuf)
		PUSH_STRING(p);
	else
	{
		if (p == pp.valbuf + 1)
			*pp.valbuf = '"';
		else
		{
			if (strlen(p) > MAXTOKEN - 2)
				error(1, "%-.16s: builtin value truncated", p);
			sfsprintf(pp.valbuf, MAXTOKEN, "\"%-.*s", MAXTOKEN - 2, p);
		}
		PUSH_QUOTE(pp.valbuf, 1);
	}
}
