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
 * preprocessor macro call
 */

#include "pplib.h"

#include <ctype.h>

/*
 * call a macro by pushing its value on the input stream
 * only the macro token itself has been consumed
 * -1 returned if macro disabled
 *  0 returned if tok==0 and sym->mac->value to be copied to output by caller
 *  1 returned if value pushed on input
 */

int
ppcall(register struct ppsymbol* sym, int tok)
{
	register int			c;
	register char*			p;
	register char*			q;
	register struct ppmacro*	mac;
	int				n;
	int				m;
	int				ret;
	int				old_hidden;
	int				last_line;
	long				old_state;
	char*				last_file;
	char*				old_token;
	struct ppmacstk*		mp;
	struct ppinstk*			old_in;
	struct ppinstk*			kp;
	struct pptuple*			tp;

	ret = -1;
	sym->flags |= SYM_NOTICED;
	if (mac = sym->macro)
	{
		count(macro);
		if ((sym->flags & SYM_PREDICATE) && (pp.state & (CONDITIONAL|WARN)) == (CONDITIONAL|WARN))
			error(1, "%s: macro definition overrides assertion: use #%s ...", sym->name, sym->name);
		if (sym->flags & SYM_DISABLED)
#if COMPATIBLE
			if ((pp.state & (COMPATIBILITY|TRANSITION)) != COMPATIBILITY || !mac->arity)
#endif
		{
			pp.mode |= MARKMACRO;
#if COMPATIBLE
			if ((pp.state & (COMPATIBILITY|STRICT)) == (COMPATIBILITY|STRICT))
				error(1, "%s: macro recursion inhibited", sym->name);
#endif
			goto disable;
		}
		if ((sym->flags & SYM_PREDEFINED) && !(pp.mode & (HOSTED|INACTIVE)))
		{
#if COMPATIBLE
			if (*sym->name != '_' && !(pp.state & COMPATIBILITY))
#else
			if (*sym->name != '_')
#endif
			{
				if (pp.state & STRICT)
				{
					error(1, "%s: obsolete predefined symbol expansion disabled", sym->name);
					goto disable;
				}
				error(1, "%s: obsolete predefined symbol expanded%s", sym->name, (pp.state & DIRECTIVE) ? "" : " outside of directive");
			}
			else if (!(pp.state & DIRECTIVE) && mac->value && (ppisdig(*mac->value) || *mac->value == '#'))
				error(1, "%s: predefined symbol expanded outside of directive", sym->name);
		}
		debug((-5, "macro %s = %s", sym->name, mac->value));
		if (pp.macref)
			(*pp.macref)(sym, error_info.file, error_info.line, (pp.state & CONDITIONAL) ? REF_IF : REF_NORMAL, 0L);
		if (tp = mac->tuple)
		{
			old_state = pp.state;
			pp.state |= DEFINITION|NOSPACE;
			old_token = pp.token;
			n = 2 * MAXTOKEN;
			pp.token = p = oldof(0, char, 0, n);
			q = p + MAXTOKEN;
			*pp.token++ = ' ';
			old_hidden = pp.hidden;
			while (c = pplex())
			{
				if (c == '\n')
				{
					pp.hidden++;
					pp.state |= HIDDEN|NEWLINE;
					old_state |= HIDDEN|NEWLINE;
					error_info.line++;
				}
				else if (c == '#')
				{
					ungetchr(c);
					break;
				}
				else
				{
					for (;;)
					{
						if (streq(pp.token, tp->token))
						{
							if (!(tp = tp->match))
								break;
							if (!tp->nomatch)
							{
								free(p);
								pp.state = old_state;
								pp.token = old_token;
								PUSH_TUPLE(sym, tp->token);
								ret = 1;
								goto disable;
							}
						}
						else if (!(tp = tp->nomatch))
							break;
					}
					if (!tp)
					{
						pp.token = pp.toknxt;
						break;
					}
				}
				if ((pp.token = pp.toknxt) > q)
				{
					c = pp.token - p;
					p = newof(p, char, n += MAXTOKEN, 0);
					q = p + n - MAXTOKEN;
					pp.token = p + c;
				}
				*pp.token++ = ' ';
			}
			if (pp.token > p && *(pp.token - 1) == ' ')
				pp.token--;
			if (pp.hidden != old_hidden)
				*pp.token++ = '\n';
			else
				*pp.token++ = ' ';
			*pp.token = 0;
			pp.state = old_state;
			pp.token = old_token;
			if (*p)
				PUSH_RESCAN(p);
			else
				free(p);
			if (!mac->value)
				goto disable;
		}
		if (sym->flags & SYM_FUNCTION)
		{
			/*
			 * a quick and dirty '(' peek to avoid possibly
			 * inappropriate ungetchr()'s below
			 */

			for (p = pp.in->nextchr; isspace(*p); p++);
			if ((c = *p) != '(' && c != '/' && c != 0 && c != MARK)
				goto disable;
			old_token = pp.token;
			mp = pp.macp->next;
			if ((pp.token = (char*)&mp->arg[mac->arity + 1]) > pp.maxmac)
				error(3, "%s: too many nested function-like macros", sym->name);
			old_hidden = pp.hidden;
			old_state = pp.state;
			pp.state |= DEFINITION|FILEPOP|NOSPACE;
			while ((c = pplex()) == '\n')
			{
				pp.hidden++;
				pp.state |= HIDDEN|NEWLINE;
				old_state |= HIDDEN|NEWLINE;
				error_info.line++;
			}
			if (c != '(')
			{
				pp.state = old_state;
				if (c)
				{
					p = pp.toknxt;
					while (p > pp.token)
						ungetchr(*--p);
#if COMPATIBLE
					if ((pp.state & (COMPATIBILITY|STRICT)) == (COMPATIBILITY|STRICT))
						error(1, "%s: macro arguments omitted", sym->name);
#endif
					if (c == T_ID && !(pp.state & HIDDEN))
						ungetchr(' ');
				}
				if (pp.hidden != old_hidden)
				{
					ungetchr('\n');
					error_info.line--;
					if (pp.hidden && !--pp.hidden)
						pp.state &= ~HIDDEN;
				}
				pp.token = old_token;
				goto disable;
			}
			pp.state = old_state;

			/*
			 * arg[i][-1] is an extra char for each actual i
			 * for a possible ungetchr('"') during IN_QUOTE
			 * arg[i][-1]==0 if arg i need not be expanded
			 * arg[0][-2] holds the actual arg count
			 */

			c = 0;
			m = 0;
			n = 0;
			mp = pp.macp->next;
			p = pp.token = (char*)&mp->arg[mac->arity + 1];
			pp.state |= COLLECTING|NOEXPAND;
			pp.state &= ~FILEPOP;
			sym->flags |= SYM_ACTIVE;
			old_in = pp.in;
			last_line = error_info.line;
			last_file = error_info.file;
			mp->line = error_info.line;
#if MACKEYARGS
			if (pp.option & KEYARGS)
			{
				for (c = 0; c < mac->arity; c++)
					mp->arg[c] = mac->args.key[c].value + 1;
				mp->arg[0]++;
			}
			else
#endif
			{
				*++p = ' ';
				mp->arg[0] = ++p;
			}
#if MACKEYARGS
		keyarg:
			if (pp.option & KEYARGS)
			{
				pp.state |= NOSPACE;
				switch (pplex())
				{
				case T_ID:
					break;
				case ')':	/* no actual key args */
					if (!(pp.state & NOEXPAND))
						pp.state |= NOEXPAND;
					for (c = 0; c < mac->arity; c++)
						mp->arg[c][-1] = 0;
					c = 0;
					goto endactuals;
				default:
					error(3, "%s: invalid keyword macro argument", pp.token);
					break;
				}
				for (c = 0; c < mac->arity; c++)
					if (streq(pp.token, mac->args.key[c].name)) break;
				if (c >= mac->arity)
					error(2, "%s: invalid macro argument keyword", pp.token);
				if (pplex() != '=')
					error(2, "= expected in keyword macro argument");
				pp.state &= ~NOSPACE;
				if (!c)
					p++;
				pp.token = mp->arg[c] = ++p;
			}
#endif
			for (;;)
			{
				if ((pp.mactop = pp.token = p) >= pp.maxmac)
					error(3, "%s: too many nested function-like macros", sym->name);
				switch (pplex())
				{
				case '(':
					n++;
					break;
				case ')':
					if (!n--)
					{
						if (p > mp->arg[c] && *(p - 1) == ' ')
							p--;
						if (p > mp->arg[c] && *(p - 1) == '\\')
						{
							for (q = mp->arg[c]; q < p; q++)
								if (*q == '\\')
									q++;
							if (q > p)
								*p++ = '\\';
						}
#if MACKEYARGS
						*p = 0;
						m++;
#endif
						goto endactuals;
					}
					break;
				case ',':
					if (!n && (m++, (c < mac->arity - 1 || !(sym->flags & SYM_VARIADIC))))
					{
						if (p > mp->arg[c] && *(p - 1) == ' ')
							p--;
						*p++ = 0;
						if (!(pp.state & NOEXPAND))
							pp.state |= NOEXPAND;
						else
							mp->arg[c][-1] = 0;
#if MACKEYARGS
						if (pp.option & KEYARGS)
						{
							pp.token = p + 1;
							goto keyarg;
						}
#endif
						{
							if ((pp.state & STRICT) && p == mp->arg[c])
								error(1, "%s: macro call argument %d is null", sym->name, c + 1);
							if (c < mac->arity)
								c++;
							*p++ = ' ';
						}
						pp.toknxt = mp->arg[c] = p;
					}
					break;
				case 0:
					if (pp.in == old_in)
						kp = 0;
					else
						for (kp = pp.in; kp && kp != old_in; kp = kp->prev);
					if (!kp)
					{
						error(
#if COMPATIBLE
							(pp.state & COMPATIBILITY) ? 3 :
#endif
							2, "%s: %s in macro argument list", sym->name, pptokchr(0));
						goto endactuals;
					}
					continue;
				case '\n':
					pp.state |= HIDDEN;
					error_info.line++;
					pp.hidden++;
					/*FALLTHROUGH*/
				case ' ':
					if (p > mp->arg[c] && *(p - 1) != ' ') *p++ = ' ';
					continue;
				}
				p = pp.toknxt;
				if (error_info.line != last_line)
				{
					SETLINE(p, error_info.line);
					last_line = error_info.line;
				}
				if (error_info.file != last_file)
				{
					SETFILE(p, error_info.file);
					last_file = error_info.file;
				}
			}
 endactuals:
			if (pp.state & NOEXPAND)
				mp->arg[c][-1] = 0;
			pp.token = old_token;
			if (pp.in != old_in)
			{
				for (kp = pp.in; kp && kp != old_in; kp = kp->prev);
				if (kp)
					error(2, "%s: macro call starts and ends in different files", sym->name);
			}
			pp.state &= ~(COLLECTING|FILEPOP|NOEXPAND);
			sym->flags &= ~SYM_ACTIVE;
#if MACKEYARGS
			if (!(pp.option & KEYARGS))
#endif
			{
				if (p > mp->arg[0] && ++m || (sym->flags & SYM_VARIADIC))
					c++;
				if (c != mac->arity && !(sym->flags & SYM_EMPTY))
				{
					n = mac->arity;
					if (!(sym->flags & SYM_VARIADIC))
						error(1, "%s: %d actual argument%s expected", sym->name, n, n == 1 ? "" : "s");
					else if (c < --n)
						error(1, "%s: at least %d actual argument%s expected", sym->name, n, n == 1 ? "" : "s");
#if COMPATIBLE
					if (!c && (pp.state & (COMPATIBILITY|STRICT)) == (COMPATIBILITY|STRICT))
						goto disable;
#endif
				}
				if (!c)
					++c;
				while (c < mac->arity)
					mp->arg[c++] = (char*)"\0" + 1;
			}
			mp->arg[0][-2] = m;
			*p++ = 0;
			nextframe(mp, p);
			count(function);
		}
		if (!tok && (sym->flags & SYM_NOEXPAND))
		{
			if (sym->flags & SYM_FUNCTION)
				popframe(mp);
			ret = !mac->size;
		}
		else if (!(pp.state & HEADER) || (pp.option & HEADEREXPANDALL)  || pp.in->type != IN_COPY)
		{
			if (sym->flags & SYM_MULTILINE)
				PUSH_MULTILINE(sym);
			else
				PUSH_MACRO(sym);
			ret = 1;
		}
	}
 disable:
	if (ret < 0 && sym->hidden && !(pp.mode & EXPOSE) && !(pp.state & HEADER) && (pp.in->type == IN_FILE || pp.in->type == IN_MACRO || pp.in->type == IN_EXPAND))
	{
		struct ppinstk*	inp;

		for (inp = pp.in; inp->type != IN_FILE && inp->prev; inp = inp->prev);
		sfsprintf(pp.hidebuf, MAXTOKEN, "_%d_%s_hIDe", inp->index, sym->name);
		PUSH_STRING(pp.hidebuf);
		ret = 1;
	}
	pp.state &= ~NEWLINE;
	pp.in->flags |= IN_tokens;
	count(token);
	return ret;
}
