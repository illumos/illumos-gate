/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2009 AT&T Intellectual Property          *
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
 * preprocessor control directive support
 */

#include "pplib.h"

#include <regex.h>

#define TOKOP_DUP	(1<<0)
#define TOKOP_STRING	(1<<1)
#define TOKOP_UNSET	(1<<2)

struct edit
{
	struct edit*	next;
	regex_t		re;
};

struct map
{
	struct map*	next;
	regex_t		re;
	struct edit*	edit;
};

#define RESTORE		(COLLECTING|CONDITIONAL|DEFINITION|DIRECTIVE|DISABLE|EOF2NL|HEADER|NOSPACE|NOVERTICAL|PASSEOF|STRIP)

/*
 * common predicate assertion operations
 * op is DEFINE or UNDEF
 */

static void
assert(int op, char* pred, char* args)
{
	register struct pplist*		a;
	register struct ppsymbol*	sym;
	register struct pplist*		p;
	register struct pplist*		q;

	if (!args) switch (op)
	{
	case DEFINE:
		goto mark;
	case UNDEF:
		a = 0;
		goto unmark;
	}
	if (a = (struct pplist*)hashget(pp.prdtab, pred))
	{
		p = 0;
		q = a;
		while (q)
		{
			if (streq(q->value, args))
			{
				if (op == DEFINE) return;
				q = q->next;
				if (p) p->next = q;
				else a = q;
			}
			else
			{
				p = q;
				q = q->next;
			}
		}
		if (op == UNDEF)
		{
		unmark:
			hashput(pp.prdtab, pred, a);
			if (sym = ppsymref(pp.symtab, pred))
				sym->flags &= ~SYM_PREDICATE;
			return;
		}
	}
	if (op == DEFINE)
	{
		p = newof(0, struct pplist, 1, 0);
		p->next = a;
		p->value = strdup(args);
		hashput(pp.prdtab, NiL, p);
	mark:
		if ((pp.state & COMPILE) && pp.truncate) return;
		if (sym = ppsymset(pp.symtab, pred))
			sym->flags |= SYM_PREDICATE;
	}
}

/*
 * tokenize string ppop()
 *
 *	op	PP_* op
 *	name	option name
 *	s	string of option values
 *	n	option sense
 *	flags	TOKOP_* flags
 */

static void
tokop(int op, char* name, register char* s, register int n, int flags)
{
	register int	c;
	register char*	t;

	if (!(flags & TOKOP_UNSET) && !n) error(2, "%s: option cannot be unset", name);
	else if (!s) ppop(op, s, n);
	else if (flags & TOKOP_STRING)
	{
		PUSH_LINE(s);
		for (;;)
		{
			pp.state &= ~NOSPACE;
			c = pplex();
			pp.state |= NOSPACE;
			if (!c) break;
			if (c != ' ')
				ppop(op, (flags & TOKOP_DUP) ? strdup(pp.token) : pp.token, n);
		}
		POP_LINE();
	}
	else do
	{
		while (*s == ' ') s++;
		for (t = s; *t && *t != ' '; t++);
		if (*t) *t++ = 0;
		else t = 0;
		if (*s) ppop(op, (flags & TOKOP_DUP) ? strdup(s) : s, n);
	} while (s = t);
}

/*
 * return symbol pointer for next token macro (re)definition
 */

static struct ppsymbol*
macsym(int tok)
{
	register struct ppsymbol*	sym;

	if (tok != T_ID)
	{
		error(2, "%s: invalid macro name", pptokstr(pp.token, 0));
		return 0;
	}
	sym = pprefmac(pp.token, REF_CREATE);
	if ((sym->flags & SYM_FINAL) && (pp.mode & HOSTED)) return 0;
	if (sym->flags & (SYM_ACTIVE|SYM_READONLY))
	{
		if (!(pp.option & ALLPOSSIBLE))
			error(2, "%s: macro is %s", sym->name, (sym->flags & SYM_READONLY) ? "readonly" : "active");
		return 0;
	}
	if (!sym->macro) sym->macro = newof(0, struct ppmacro, 1, 0);
	return sym;
}

/*
 * get one space canonical pplex() line, sans '\n', and place in p
 * x is max+1 pos in p
 * 0 returned if line too large
 * otherwise end of p ('\0') returned
 */

static char*
getline(register char* p, char* x, int disable)
{
	register int	c;
	register char*	s;
	char*		b;
	long		restore;

	restore = pp.state & (NOSPACE|STRIP);
	pp.state &= ~(NEWLINE|NOSPACE|STRIP);
	pp.state |= EOF2NL;
	b = p;
	while ((c = pplex()) != '\n')
	{
		if (disable)
		{
			if (c == ' ')
				/*ignore*/;
			else if (disable == 1)
				disable = (c == T_ID && streq(pp.token, pp.pass)) ? 2 : 0;
			else
			{
				disable = 0;
				if (c == ':')
					pp.state |= DISABLE;
			}
		}
		s = pp.token;
		while (*p = *s++)
			if (++p >= x)
			{
				p = 0;
				goto done;
			}
	}
	if (p > b && *(p - 1) == ' ')
		p--;
	if (p >= x)
		p = 0;
	else
		*p = 0;
 done:
	pp.state &= ~(NOSPACE|STRIP);
	pp.state |= restore;
	return p;
}

/*
 * regex error handler
 */

void
regfatal(regex_t* p, int level, int code)
{
	char	buf[128];

	regerror(code, p, buf, sizeof(buf));
	regfree(p);
	error(level, "regular expression: %s", buf);
}

/*
 * process a single directive line
 */

int
ppcontrol(void)
{
	register char*			p;
	register int			c;
	register int			n;
	register char*			s;
	register struct ppmacro*	mac;
	register struct ppsymbol*	sym;
	struct edit*			edit;
	struct map*			map;
	struct ppfile*			fp;
	int				o;
	int				directive;
	long				restore;
	struct pptuple*			rp;
	struct pptuple*			tp;
	char*				v;
	int				emitted;

	union
	{
		struct map*		best;
		struct ppinstk*		inp;
		struct pplist*		list;
		char*			string;
		struct ppsymbol*	symbol;
		int			type;
		PPLINESYNC		linesync;
	}				var;

	static char			__va_args__[] = "__VA_ARGS__";
	static int			i0;
	static int			i1;
	static int			i2;
	static int			i3;
	static int			i4;

	static long			n1;
	static long			n2;
	static long			n3;

	static char*			p0;
	static char*			p1;
	static char*			p2;
	static char*			p3;
	static char*			p4;
	static char*			p5;
	static char*			p6;

	static struct ppmacro		old;
	static char*			formargs[MAXFORMALS];
#if MACKEYARGS
	static char*			formvals[MAXFORMALS];
#endif

	emitted = 0;
	if (pp.state & SKIPCONTROL) pp.level--;
	restore = (pp.state & RESTORE)|NEWLINE;
	if (pp.state & PASSTHROUGH) restore |= DISABLE;
	else restore &= ~DISABLE;
	pp.state &= ~(NEWLINE|RESTORE|SKIPCONTROL);
	pp.state |= DIRECTIVE|DISABLE|EOF2NL|NOSPACE|NOVERTICAL;
#if COMPATIBLE
	if ((pp.state & (COMPATIBILITY|STRICT)) == COMPATIBILITY || (pp.mode & HOSTED)) pp.state &= ~NOVERTICAL;
#else
	if (pp.mode & HOSTED) pp.state &= ~NOVERTICAL;
#endif
	switch (c = pplex())
	{
	case T_DECIMAL:
	case T_OCTAL:
		if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
			error(1, "# <line> [ \"<file>\" [ <type> ] ]: non-standard directive");
		directive = INCLUDE;
		goto linesync;
	case T_ID:
		switch (directive = (int)hashref(pp.dirtab, pp.token))
		{
		case ELIF:
		else_if:
			if ((pp.option & ALLPOSSIBLE) && !pp.in->prev->prev)
				goto eatdirective;
			if (pp.control <= pp.in->control)
			{
				error(2, "no matching #%s for #%s", dirname(IF), dirname(ELIF));
				goto eatdirective;
			}
			if (pp.control == (pp.in->control + 1)) pp.in->flags |= IN_noguard;
			if (*pp.control & HADELSE)
			{
				error(2, "invalid #%s after #%s", dirname(ELIF), dirname(ELSE));
				*pp.control |= SKIP;
				goto eatdirective;
			}
			if (*pp.control & KEPT)
			{
				*pp.control |= SKIP;
				goto eatdirective;
			}
			if (directive == IFDEF || directive == IFNDEF)
			{
				*pp.control &= ~SKIP;
				goto else_ifdef;
			}
		conditional:
			if (ppexpr(&i1))
			{
				*pp.control &= ~SKIP;
				*pp.control |= KEPT;
			}
			else *pp.control |= SKIP;
			c = (pp.state & NEWLINE) ? '\n' : ' ';
			goto eatdirective;
		case ELSE:
			if ((pp.option & ALLPOSSIBLE) && !pp.in->prev->prev)
				goto eatdirective;
			if ((pp.option & ELSEIF) && (c = pplex()) == T_ID && ((n = (int)hashref(pp.dirtab, pp.token)) == IF || n == IFDEF || n == IFNDEF))
			{
				error(1, "#%s %s is non-standard -- use #%s", dirname(directive), dirname(n), dirname(ELIF));
				directive = n;
				goto else_if;
			}
			if (pp.control <= pp.in->control) error(2, "no matching #%s for #%s", dirname(IF), dirname(ELSE));
			else
			{
				if (pp.control == (pp.in->control + 1)) pp.in->flags |= IN_noguard;
				if (!(*pp.control & KEPT))
				{
					*pp.control &= ~SKIP;
					*pp.control |= HADELSE|KEPT;
				}
				else
				{
					if (*pp.control & HADELSE) error(2, "more than one #%s for #%s", dirname(ELSE), dirname(IF));
					*pp.control |= HADELSE|SKIP;
				}
			}
			goto enddirective;
		case ENDIF:
			if ((pp.option & ALLPOSSIBLE) && !pp.in->prev->prev)
				goto eatdirective;
			if (pp.control <= pp.in->control) error(2, "no matching #%s for #%s", dirname(IF), dirname(ENDIF));
			else if (--pp.control == pp.in->control && pp.in->symbol)
			{
				if (pp.in->flags & IN_endguard) pp.in->flags |= IN_noguard;
				else
				{
					pp.in->flags &= ~IN_tokens;
					pp.in->flags |= IN_endguard;
				}
			}
			goto enddirective;
		case IF:
		case IFDEF:
		case IFNDEF:
			if ((pp.option & ALLPOSSIBLE) && !pp.in->prev->prev)
				goto eatdirective;
			pushcontrol();
			SETIFBLOCK(pp.control);
			if (*pp.control & SKIP)
			{
				*pp.control |= KEPT;
				goto eatdirective;
			}
			if (directive == IF) goto conditional;
		else_ifdef:
			if ((c = pplex()) == T_ID)
			{
				sym = pprefmac(pp.token, REF_IF);
				if (directive == IFNDEF && pp.control == pp.in->control + 1)
				{
					if (pp.in->flags & (IN_defguard|IN_endguard))
						pp.in->flags |= IN_noguard;
					else
					{
						pp.in->flags |= IN_defguard;
						if (!(pp.in->flags & IN_tokens))
							pp.in->symbol = sym ? sym : pprefmac(pp.token, REF_CREATE);
					}
				}
			}
			else
			{
				sym = 0;
				if (!(pp.mode & HOSTED))
					error(1, "%s: invalid macro name", pptokstr(pp.token, 0));
			}
			*pp.control |= ((sym != 0) == (directive == IFDEF)) ? KEPT : SKIP;
			goto enddirective;
		case INCLUDE:
			if (*pp.control & SKIP)
			{
				pp.state |= HEADER;
				c = pplex();
				pp.state &= ~HEADER;
				goto eatdirective;
			}
			pp.state &= ~DISABLE;
			pp.state |= HEADER|STRIP;
			pp.in->flags |= IN_noguard;
			switch (c = pplex())
			{
			case T_STRING:
				p = pp.token;
				do pp.token = pp.toknxt; while ((c = pplex()) == T_STRING);
				*pp.token = 0;
				pp.token = p;
				/*FALLTHROUGH*/
			case T_HEADER:
			header:
				if (!*pp.token)
				{
					error(2, "#%s: null file name", dirname(INCLUDE));
					break;
				}
				if (*pp.token == '/' && !(pp.mode & (HOSTED|RELAX)))
					error(1, "#%s: reference to %s is not portable", dirname(INCLUDE), pp.token);
				n = ppsearch(pp.token, c, SEARCH_INCLUDE);
				break;
			case '<':
				/*
				 * HEADEREXPAND|HEADEREXPANDALL gets us here
				 */

				if (!(p = pp.hdrbuf) && !(p = pp.hdrbuf = newof(0, char, MAXTOKEN, 0)))
					error(3, "out of space");
				pp.state &= ~NOSPACE;
				while ((c = pplex()) && c != '>')
				{
					v = p + 1;
					STRCOPY(p, pp.token, s);
					if (p == v && *(p - 1) == ' ' && pp.in->type != IN_MACRO)
						p--;
				}
				pp.state |= NOSPACE;
				*p++ = 0;
				memcpy(pp.token, pp.hdrbuf, p - pp.hdrbuf);
				c = T_HEADER;
				goto header;
			default:
				error(2, "#%s: \"...\" or <...> argument expected", dirname(INCLUDE));
				goto eatdirective;
			}
			goto enddirective;
		case 0:
			{
				regmatch_t	match[10];

				/*UNDENT*/
	p = pp.valbuf;
	*p++ = '#';
	STRCOPY(p, pp.token, s);
	p0 = p;
	pp.mode |= EXPOSE;
	pp.state |= HEADER;
	p6 = getline(p, &pp.valbuf[MAXTOKEN], 0);
	pp.state &= ~HEADER;
	pp.mode &= ~EXPOSE;
	if (!p6)
	{
		*p0 = 0;
		error(2, "%s: directive too long", pp.valbuf);
		c = 0;
		goto eatdirective;
	}
	p1 = p2 = p3 = p4 = 0;
	p5 = *p ? p + 1 : 0;
 checkmap:
	i0 = *p0;
	p = pp.valbuf;
	var.best = 0;
	n = 0;
	for (map = (struct map*)pp.maps; map; map = map->next)
		if (!(i1 = regexec(&map->re, p, elementsof(match), match, 0)))
		{
			if ((c = match[0].rm_eo - match[0].rm_so) > n)
			{
				n = c;
				var.best = map;
			}
		}
		else if (i1 != REG_NOMATCH)
			regfatal(&map->re, 3, i1);
	c = '\n';
	if (map = var.best)
	{
		if ((pp.state & (STRICT|WARN)) && !(pp.mode & (HOSTED|RELAX)))
		{
			*p0 = 0;
			if (!(pp.state & WARN) || strcmp(p + 1, dirname(PRAGMA)))
				error(1, "%s: non-standard directive", p);
			*p0 = i0;
		}
		if (!(*pp.control & SKIP))
		{
			n = 0;
			for (edit = map->edit; edit; edit = edit->next)
				if (!(i0 = regexec(&edit->re, p, elementsof(match), match, 0)))
				{
					n++;
					if (i0 = regsubexec(&edit->re, p, elementsof(match), match))
						regfatal(&edit->re, 3, i0);
					p = edit->re.re_sub->re_buf;
					if (edit->re.re_sub->re_flags & REG_SUB_STOP)
						break;
				}
				else if (i0 != REG_NOMATCH)
					regfatal(&edit->re, 3, i0);
			if (n && *p)
			{
				p1 = s = oldof(0, char, 0, strlen(p) + 32);
				while (*s = *p++) s++;
				debug((-4, "map: %s", p1));
				*s++ = '\n';
				*s = 0;
				error_info.line++;
				PUSH_RESCAN(p1);
				error_info.line--;
				directive = LINE;
			}
		}
		goto donedirective;
	}
	if (directive != PRAGMA && (!(*pp.control & SKIP) || !(pp.mode & (HOSTED|RELAX))))
	{
		*p0 = 0;
		error(1, "%s: unknown directive", pptokstr(pp.valbuf, 0));
		*p0 = i0;
	}
 pass:
	if (!(*pp.control & SKIP) && pp.pragma && !(pp.state & NOTEXT) && (directive == PRAGMA || !(pp.mode & INIT)))
	{
		*p0 = 0;
		if (p2) *p2 = 0;
		if (p4)
		{
			if (p4 == p5)
			{
				p5 = strcpy(pp.tmpbuf, p5);
				if (p = strchr(p5, MARK))
				{
					s = p;
					while (*p)
						if ((*s++ = *p++) == MARK && *p == MARK) p++;
					*s = 0;
				}
			}
			*p4 = 0;
		}
		if (p = (char*)memchr(pp.valbuf + 1, MARK, p6 - pp.valbuf - 1))
		{
			s = p;
			while (p < p6) switch (*s++ = *p++)
			{
			case 0:
				s = p;
				break;
			case MARK:
				p++;
				break;
			}
			*s = 0;
		}
		(*pp.pragma)(pp.valbuf + 1, p1, p3, p5, (pp.state & COMPILE) || (pp.mode & INIT) != 0);
		emitted = 1;
	}
	goto donedirective;

				/*INDENT*/
			}
		}
		if (*pp.control & SKIP) goto eatdirective;
		switch (directive)
		{
#if MACDEF
		case ENDMAC:
			c = pplex();
			error(2, "no matching #%s for #%s", dirname(MACDEF), dirname(ENDMAC));
			goto enddirective;
#endif
#if MACDEF
		case MACDEF:
			if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "#%s: non-standard directive", pp.token);
#endif
			/*FALLTHROUGH*/
		case DEFINE:
			n2 = error_info.line;
			if ((c = pplex()) == '#' && directive == DEFINE)
				goto assertion;
			if (c == '<')
			{
				n = 1;
				c = pplex();
			}
			else
				n = 0;
			if (!(sym = macsym(c)))
				goto eatdirective;
			if (pp.truncate)
				ppfsm(FSM_MACRO, pp.token);
			mac = sym->macro;
			if ((pp.option & ALLPOSSIBLE) && !pp.in->prev->prev && mac->value)
				goto eatdirective;
			if (n)
				goto tuple;
			old = *mac;
			i0 = sym->flags;
			sym->flags &= ~(SYM_BUILTIN|SYM_EMPTY|SYM_FINAL|SYM_FUNCTION|SYM_INIT|SYM_INITIAL|SYM_MULTILINE|SYM_NOEXPAND|SYM_PREDEFINED|SYM_REDEFINE|SYM_VARIADIC);
#if MACDEF
			if (directive == MACDEF)
				sym->flags |= SYM_MULTILINE;
#endif
			mac->arity = 0;
			mac->formals = 0;
			mac->value = 0;
			pp.state &= ~NOSPACE;
			pp.state |= DEFINITION|NOEXPAND;
			switch (c = pplex())
			{
			case '(':
				sym->flags |= SYM_FUNCTION;
				pp.state |= NOSPACE;
#if MACKEYARGS
				if (pp.option & KEYARGS)
				{
					n = 2 * MAXTOKEN;
					p = mac->formals = oldof(0, char, 0, n);
					if ((c = pplex()) == T_ID) for (;;)
					{
						if (mac->arity < MAXFORMALS)
						{
							if (mac->arity) p++;
							formargs[mac->arity] = p;
							STRAPP(p, pp.token, s);
							formvals[mac->arity++] = p1 = p;
							if (mac->arity == 1) *p++ = ' ';
							*p++ = ' ';
							*p = 0;
						}
						else error(2, "%s: formal argument %s ignored", sym->name, pp.token);
						switch (c = pplex())
						{
						case '=':
							c = pplex();
							break;
						case ',':
							break;
						default:
							goto endformals;
						}
						pp.state &= ~NOSPACE;
						p0 = 0;
						for (;;)
						{
							switch (c)
							{
							case '\n':
								goto endformals;
							case '(':
								p0++;
								break;
							case ')':
								if (!p0--)
								{
									if (p > formvals[mac->arity - 1] && *(p - 1) == ' ') *--p = 0;
									goto endformals;
								}
								break;
							case ',':
								if (!p0)
								{
									if (p > formvals[mac->arity - 1] && *(p - 1) == ' ') *--p = 0;
									goto nextformal;
								}
								break;
							case ' ':
								if (p > formvals[mac->arity - 1] && *(p - 1) == ' ') continue;
								break;
							}
							STRCOPY(p, pp.token, s);
							if (p > &mac->formals[n - MAXTOKEN] && (s = newof(mac->formals, char, n += MAXTOKEN, 0)) != mac->formals)
							{
								n1 = s - mac->formals;
								for (n = 0; n < mac->arity; n++)
								{
									formargs[n] += n1;
									formvals[n] += n1;
								}
								c = p - mac->formals;
								mac->formals = s;
								p = mac->formals + c;
							}
							c = pplex();
						}
					nextformal:
						pp.state |= NOSPACE;
						if ((c = pplex()) != T_ID)
						{
							c = ',';
							break;
						}
					}
				endformals: /*NOP*/;
				}
				else
#endif
				{
					p = mac->formals = oldof(0, char, 0, MAXFORMALS * (MAXID + 1));
					c = pplex();
#if COMPATIBLE
					if ((pp.state & COMPATIBILITY) && c == ',')
					{
						if ((pp.state & WARN) && !(pp.mode & HOSTED))
							error(1, "%s: macro formal argument expected", sym->name);
						while ((c = pplex()) == ',');
					}
#endif
					for (;;)
					{
						if (c == T_VARIADIC)
						{
							if (sym->flags & SYM_VARIADIC)
								error(2, "%s: %s: duplicate macro formal argument", sym->name, pp.token);
							sym->flags |= SYM_VARIADIC;
							v = __va_args__;
						}
						else if (c == T_ID)
						{
							v = pp.token;
							if (sym->flags & SYM_VARIADIC)
								error(2, "%s: %s: macro formal argument cannot follow ...", sym->name, v);
							else if (streq(v, __va_args__))
								error(2, "%s: %s: invalid macro formal argument", sym->name, v);
						}
						else
							break;
						if (mac->arity < MAXFORMALS)
						{
							for (n = 0; n < mac->arity; n++)
								if (streq(formargs[n], v))
									error(2, "%s: %s: duplicate macro formal argument", sym->name, v);
							formargs[mac->arity++] = p;
							STRAPP(p, v, s);
						}
						else
							error(2, "%s: %s: macro formal argument ignored", sym->name, v);
						if ((c = pplex()) == ',')
						{
							c = pplex();
#if COMPATIBLE
							if ((pp.state & COMPATIBILITY) && c == ',')
							{
								if ((pp.state & WARN) && !(pp.mode & HOSTED))
									error(1, "%s: macro formal argument expected", sym->name);
								while ((c = pplex()) == ',');
							}
#endif
						}
						else if (c != T_VARIADIC)
							break;
						else
						{
							if (sym->flags & SYM_VARIADIC)
								error(2, "%s: %s: duplicate macro formal argument", sym->name, pp.token);
							sym->flags |= SYM_VARIADIC;
							c = pplex();
							break;
						}
					}
					if (mac->arity && (s = newof(mac->formals, char, p - mac->formals, 0)) != mac->formals)
					{
						n1 = s - mac->formals;
						for (n = 0; n < mac->arity; n++)
							formargs[n] += n1;
						mac->formals = s;
					}
				}
				if (!mac->arity)
				{
					free(mac->formals);
					mac->formals = 0;
				}
				switch (c)
				{
				case ')':
#if MACKEYARGS
					pp.state |= NOEXPAND|NOSPACE;
#else
					pp.state |= NOEXPAND;
#endif
					c = pplex();
					break;
				default:
					error(2, "%s: invalid macro formal argument list", sym->name);
					if (mac->formals)
					{
						free(mac->formals);
						mac->formals = 0;
						mac->arity = 0;
					}
					free(mac);
					sym->macro = 0;
					goto eatdirective;
				}
				pp.state &= ~NOSPACE;
				break;
			case ' ':
			case '\t':
				c = pplex();
				break;
			}
			n = 2 * MAXTOKEN;
#if MACKEYARGS
			p1 = p;
#endif
			p = mac->value = oldof(0, char, 0, n);
			var.type = 0;
			n1 = 0;
#if MACDEF
			i2 = i3 = 0;
			n3 = pp.state;
#endif
			if ((pp.option & PLUSPLUS) && (pp.state & (COMPATIBILITY|TRANSITION)) != COMPATIBILITY)
				switch (c)
				{
				case '+':
				case '-':
				case '&':
				case '|':
				case '<':
				case '>':
				case ':':
				case '=':
					*p++ = ' ';
					break;
				}
			o = 0;
			for (;;)
			{
				switch (c)
				{
				case T_ID:
					for (c = 0; c < mac->arity; c++)
						if (streq(formargs[c], pp.token))
						{
#if COMPATIBLE
							if (!(pp.state & COMPATIBILITY))
#endif
							if (var.type != TOK_TOKCAT && p > mac->value && *(p - 1) != ' ' && !(pp.option & PRESERVE)) *p++ = ' ';
							*p++ = MARK;
#if COMPATIBLE
							if ((pp.state & (COMPATIBILITY|TRANSITION)) == COMPATIBILITY) *p++ = 'C';
							else
#endif
							*p++ = (n1 || var.type == TOK_TOKCAT) ? 'C' : 'A';
							*p++ = c + ARGOFFSET;
							if ((pp.state & WARN) && !(pp.mode & (HOSTED|RELAX)) && var.type != TOK_TOKCAT && !(var.type & TOK_ID))
							{
								s = pp.in->nextchr;
								while ((c = *s++) && (c == ' ' || c == '\t'));
								if (c == '\n')
									c = 0;
								else if (c == '*' && *s == ')')
									c = ')';
								else if (c == '=' || ppisidig(c) || c == *s || *s == '=')
									c = 0;
								if (o != '.' && o != T_PTRMEM)
								{
									if ((var.type & TOK_ID) || o == ' ' || ppisseparate(o))
										o = 0;
									if (!((o == 0 || o == '(' || o == ')' || o == '[' || o == ']' || o == ',' || o == '|' || o == ';' || o == '{' || o == '}') && (c == '(' || c == ')' || c == '[' || c == ']' || c == ',' || c == '|' || c == ';' || c == '}' || c == 0)) && !(o == '*' && c == ')'))
										error(1, "%s: %s: formal should be parenthesized in macro value (t=%x o=%#c c=%#c)", sym->name, pp.token, var.type, o, c);
								}
							}
							var.type = TOK_FORMAL|TOK_ID;
							c = '>';
							goto checkvalue;
						}
					if (var.type == TOK_BUILTIN) switch ((int)hashget(pp.strtab, pp.token))
					{
					case V_DEFAULT:
					case V_EMPTY:
						sym->flags |= SYM_EMPTY;
						break;
					}
					else if (pp.hiding && (var.symbol = ppsymref(pp.symtab, pp.token)) && var.symbol->hidden)
					{
						for (var.inp = pp.in; var.inp->type != IN_FILE && var.inp->prev; var.inp = var.inp->prev);
						p += sfsprintf(p, MAXTOKEN, "_%d_%s_hIDe", var.inp->hide, pp.token);
						var.type = TOK_ID;
						goto checkvalue;
					}
					var.type = TOK_ID;
					break;
				case '#':
					var.type = 0;
#if MACDEF
					if (!(sym->flags & (SYM_FUNCTION|SYM_MULTILINE))) break;
#else
					if (!(sym->flags & SYM_FUNCTION)) break;
#endif
					pp.state |= NOSPACE;
					c = pplex();
					if (c == '@')
					{
						c = pplex();
						i4 = 'S';
					}
					else i4 = 'Q';
					pp.state &= ~NOSPACE;
					if (c != T_ID) c = mac->arity;
					else for (c = 0; c < mac->arity; c++)
						if (streq(formargs[c], pp.token))
							break;
					if (c >= mac->arity)
					{
#if MACDEF
						if (sym->flags & SYM_MULTILINE)
						{
							if (n3 & NEWLINE)
							{
								pp.state &= ~NOEXPAND;
								switch ((int)hashref(pp.dirtab, pp.token))
								{
								case ENDMAC:
									if (!i2--) goto gotdefinition;
									break;
								case INCLUDE:
									/* PARSE HEADER constant */
									break;
								case MACDEF:
									i2++;
									break;
								}
								*p++ = '#';
							}
						}
						else
#endif
#if COMPATIBLE
						if (pp.state & COMPATIBILITY) *p++ = '#';
						else
#endif
						error(2, "# must precede a formal parameter");
					}
					else
					{
						if (p > mac->value && ppisidig(*(p - 1)) && !(pp.option & PRESERVE)) *p++ = ' ';
						*p++ = MARK;
						*p++ = i4;
						*p++ = c + ARGOFFSET;
						goto checkvalue;
					}
					break;
				case T_TOKCAT:
					if (p <= mac->value) error(2, "%s lhs operand omitted", pp.token);
					else
					{
						if (*(p - 1) == ' ') p--;
						if (var.type == (TOK_FORMAL|TOK_ID)) *(p - 2) = 'C';
					}
					pp.state |= NOSPACE;
					c = pplex();
					pp.state &= ~NOSPACE;
					if (c == '\n') error(2, "%s rhs operand omitted", pptokchr(T_TOKCAT));
					var.type = TOK_TOKCAT;
					continue;
				case '(':
					if (*pp.token == '#')
					{
						var.type = TOK_BUILTIN;
						n1++;
					}
					else
					{
						var.type = 0;
						if (n1) n1++;
					}
					break;
				case ')':
					var.type = 0;
					if (n1) n1--;
					break;
				case T_STRING:
				case T_CHARCONST:
					pp.state &= ~NOEXPAND;
					var.type = 0;
					if (strchr(pp.token, MARK)) pp.state &= ~NOEXPAND;
#if COMPATIBLE
					/*UNDENT*/

	if ((sym->flags & SYM_FUNCTION) && (pp.state & (COMPATIBILITY|TRANSITION)))
	{
		char*	v;

		s = pp.token;
		for (;;)
		{
			if (!*s) goto checkvalue;
			if (ppisid(*s))
			{
				v = s;
				while (ppisid(*++s));
				i1 = *s;
				*s = 0;
				for (c = 0; c < mac->arity; c++)
					if (streq(formargs[c], v))
					{
						*p++ = MARK;
						*p++ = 'C';
						*p++ = c + ARGOFFSET;
						if (!(pp.mode & HOSTED) && (!(pp.state & COMPATIBILITY) || (pp.state & WARN))) switch (*pp.token)
						{
						case '"':
							error(1, "use the # operator to \"...\" quote macro arguments");
							break;
						case '\'':
							error(1, "macro arguments should be '...' quoted before substitution");
							break;
						}
						goto quotearg;
					}
				STRCOPY2(p, v);
			quotearg:
				*s = i1;
			}
			else *p++ = *s++;
		}
	}
					/*INDENT*/
#endif
					break;
				case '\n':
#if MACDEF
					if (sym->flags & SYM_MULTILINE)
					{
						if (pp.state & EOF2NL)
						{
							error_info.line++;
							pp.state |= HIDDEN;
							pp.hidden++;
							var.type = 0;
							if (!i3++)
								goto checkvalue;
							break;
						}
						pp.state |= EOF2NL;
						error(2, "%s: missing #%s", sym->name, dirname(ENDMAC));
					}
#endif
					goto gotdefinition;
				case 0:
					c = '\n';
					goto gotdefinition;
#if COMPATIBLE
				case ' ':
					if (pp.state & COMPATIBILITY) var.type = 0;
					if (pp.option & PRESERVE) break;
					if (p > mac->value && *(p - 1) != ' ') *p++ = ' ';
					goto checkvalue;
				case '\t':
					if (var.type & TOK_ID)
					{
						while ((c = pplex()) == '\t');
						if (c == T_ID)
						{
							if (var.type == (TOK_FORMAL|TOK_ID)) *(p - 2) = 'C';
							var.type = TOK_TOKCAT;
							if (pp.state & WARN) error(1, "use the ## operator to concatenate macro arguments");
						}
						else var.type = 0;
						continue;
					}
					var.type = 0;
					if (pp.option & PRESERVE) break;
					if (p > mac->value && *(p - 1) != ' ') *p++ = ' ';
					goto checkvalue;
#endif
				case MARK:
					pp.state &= ~NOEXPAND;
					/*FALLTHROUGH*/

				default:
					var.type = 0;
					break;
				}
				STRCOPY(p, pp.token, s);
			checkvalue:
				o = c;
				if (p > &mac->value[n - MAXTOKEN] && (s = newof(mac->value, char, n += MAXTOKEN, 0)) != mac->value)
				{
					c = p - mac->value;
					mac->value = s;
					p = mac->value + c;
				}
#if MACDEF
				n3 = pp.state;
#endif
				c = pplex();
			}
		gotdefinition:
			while (p > mac->value && *(p - 1) == ' ') p--;
			if (p > mac->value && (pp.option & PLUSPLUS) && (pp.state & (COMPATIBILITY|TRANSITION)) != COMPATIBILITY)
				switch (o)
				{
				case '+':
				case '-':
				case '&':
				case '|':
				case '<':
				case '>':
				case ':':
				case '=':
					*p++ = ' ';
					break;
				}
			*p = 0;
#if MACKEYARGS
			if (!mac->arity) /* ok */;
			else if (pp.option & KEYARGS)
			{
				p0 = mac->formals;
				mac->formkeys = newof(0, struct ppkeyarg, n, p1 - p0 + 1);
				s = (char*)&mac->formkeys[mac->arity];
				(void)memcpy(s, p0, p1 - p0 + 1);
				free(p0);
				for (n = 0; n < mac->arity; n++)
				{
					mac->formkeys[n].name = s + (formargs[n] - p0);
					mac->formkeys[n].value = s + (formvals[n] - p0);
				}
			}
			else
#endif
			for (n = 1; n < mac->arity; n++)
				*(formargs[n] - 1) = ',';
			if (old.value)
			{
				if ((i0 & SYM_FUNCTION) != (sym->flags & SYM_FUNCTION) || old.arity != mac->arity || !streq(old.value, mac->value)) goto redefined;
				if (!old.formals)
				{
					if (mac->formals) goto redefined;
				}
				else if (mac->formals)
				{
#if MACKEYARGS
					if (pp.option & KEYARGS)
					{
						for (n = 0; n < mac->arity; n++)
							if (!streq(mac->formkeys[n].name, old.formkeys[n].name) || !streq(mac->formkeys[n].value, old.formkeys[n].value))
								goto redefined;
					}
					else
#endif
					if (!streq(mac->formals, old.formals)) goto redefined;
				}
#if MACKEYARGS
				if (pp.option & KEYARGS)
				{
					if (mac->formkeys) free(mac->formkeys);
					mac->formkeys = old.formkeys;
				}
				else
#endif
				{
					if (mac->formals) free(mac->formals);
					mac->formals = old.formals;
				}
				free(mac->value);
				mac->value = old.value;
				goto benign;
			redefined:
				if (!(pp.mode & HOSTED) || !(i0 & SYM_INITIAL))
					error(1, "%s redefined", sym->name);
#if MACKEYARGS
				if ((pp.option & KEYARGS) && mac->formkeys)
					free(mac->formkeys);
#endif
#if MACKEYARGS
				if (!(pp.option & KEYARGS))
#endif
				if (old.formals) free(old.formals);
				free(old.value);
			}
			else if (!pp.truncate) ppfsm(FSM_MACRO, sym->name);
			mac->value = newof(mac->value, char, (mac->size = p - mac->value) + 1, 0);
			if ((pp.option & (DEFINITIONS|PREDEFINITIONS|REGUARD)) && !sym->hidden && !(sym->flags & SYM_MULTILINE) && ((pp.option & PREDEFINITIONS) || !(pp.mode & INIT)) && ((pp.option & (DEFINITIONS|PREDEFINITIONS)) || !(pp.state & NOTEXT)))
			{
				ppsync();
				ppprintf("#%s %s", dirname(DEFINE), sym->name);
				if (sym->flags & SYM_FUNCTION)
				{
					ppputchar('(');
					if (mac->formals)
						ppprintf("%s", mac->formals);
					ppputchar(')');
				}
				if ((p = mac->value) && *p)
				{
					ppputchar(' ');
					i0 = 0;
					while (n = *p++)
					{
						if (n != MARK || (n = *p++) == MARK)
						{
							ppputchar(n);
							i0 = ppisid(n);
						}
						else
						{
							if (n == 'Q')
								ppputchar('#');
							else if (i0)
							{
								ppputchar('#');
								ppputchar('#');
							}
							s = formargs[*p++ - ARGOFFSET];
							while ((n = *s++) && n != ',')
								ppputchar(n);
							if (ppisid(*p) || *p == MARK)
							{
								ppputchar('#');
								ppputchar('#');
							}
							i0 = 0;
						}
						ppcheckout();
					}
				}
				emitted = 1;
			}
		benign:
			if (pp.mode & BUILTIN) sym->flags |= SYM_BUILTIN;
			if (pp.option & FINAL) sym->flags |= SYM_FINAL;
			if (pp.mode & INIT) sym->flags |= SYM_INIT;
			if (pp.option & INITIAL) sym->flags |= SYM_INITIAL;
			if (pp.state & NOEXPAND)  sym->flags |= SYM_NOEXPAND;
			if (pp.option & PREDEFINED) sym->flags |= SYM_PREDEFINED;
			if (pp.mode & READONLY) sym->flags |= SYM_READONLY;
			if (pp.macref) (*pp.macref)(sym, error_info.file, n2, mac ? error_info.line - n2 + 1 : REF_UNDEF, mac ? strsum(mac->value, (long)mac->arity) : 0L);
			break;
		assertion:
			c = pplex();
			if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "#%s #%s: assertions are non-standard", dirname(directive), pptokstr(pp.token, 0));
			if (c != T_ID)
			{
				error(2, "%s: invalid predicate name", pptokstr(pp.token, 0));
				goto eatdirective;
			}
			switch ((int)hashref(pp.strtab, pp.token))
			{
			case X_DEFINED:
			case X_EXISTS:
			case X_STRCMP:
				error(2, "%s is a builtin predicate", pp.token);
				goto eatdirective;
			case X_SIZEOF:
				error(2, "%s cannot be a predicate", pp.token);
				goto eatdirective;
			}
			strcpy(pp.tmpbuf, pp.token);
			switch (pppredargs())
			{
			case T_ID:
			case T_STRING:
				assert(directive, pp.tmpbuf, pp.args);
				break;
			case 0:
				assert(directive, pp.tmpbuf, NiL);
				break;
			default:
				error(2, "invalid predicate argument list");
				goto eatdirective;
			}
			break;
		tuple:
			pp.state |= DEFINITION|NOEXPAND|NOSPACE;
			rp = 0;
			tp = mac->tuple;
			if (!tp && !mac->value)
				ppfsm(FSM_MACRO, sym->name);
			while ((c = pplex()) && c != '>' && c != '\n')
			{
				for (; tp; tp = tp->nomatch)
					if (streq(tp->token, pp.token))
						break;
				if (!tp)
				{
					if (!(tp = newof(0, struct pptuple, 1, strlen(pp.token))))
						error(3, "out of space");
					strcpy(tp->token, pp.token);
					if (rp)
					{
						tp->nomatch = rp;
						rp->nomatch = tp;
					}
					else
					{
						tp->nomatch = mac->tuple;
						mac->tuple = tp;
					}
				}
				rp = tp;
				tp = tp->match;
			}
			pp.state &= ~NOSPACE;
			if (!rp || c != '>')
				error(2, "%s: > omitted in tuple macro definition", sym->name);
			else
			{
				n = 2 * MAXTOKEN;
				p = v = oldof(0, char, 0, n);
				while ((c = pplex()) && c != '\n')
					if (p > v || c != ' ')
					{
						STRCOPY(p, pp.token, s);
						if (p > &v[n - MAXTOKEN] && (s = newof(v, char, n += MAXTOKEN, 0)) != v)
						{
							c = p - v;
							v = s;
							p = v + c;
						}
					}
				while (p > v && *(p - 1) == ' ')
					p--;
				n = p - v;
				tp = newof(0, struct pptuple, 1, n);
				strcpy(tp->token, v);
				tp->match = rp->match;
				rp->match = tp;
			}
			goto benign;
		case WARNING:
			if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "#%s: non-standard directive", pp.token);
			/*FALLTHROUGH*/
		case ERROR:
			pp.state &= ~DISABLE;
			p = pp.tmpbuf;
			while ((c = pplex()) != '\n')
				if (p + strlen(pp.token) < &pp.tmpbuf[MAXTOKEN])
				{
					STRCOPY(p, pp.token, s);
					pp.state &= ~NOSPACE;
				}
			*p = 0;
			p = *pp.tmpbuf ? pp.tmpbuf : ((directive == WARNING) ? "user warning" : "user error");
			n = (directive == WARNING) ? 1 : 3;
			error(n, "%s", p);
			break;
		case LET:
			n2 = error_info.line;
			if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "#%s: non-standard directive", pp.token);
			if (!(sym = macsym(c = pplex()))) goto eatdirective;
			if ((c = pplex()) != '=')
			{
				error(2, "%s: = expected", sym->name);
				goto eatdirective;
			}
			sym->flags &= ~(SYM_BUILTIN|SYM_FUNCTION|SYM_MULTILINE|SYM_PREDEFINED|SYM_VARIADIC);
			mac = sym->macro;
			mac->arity = 0;
			if (mac->value)
			{
				if (!(sym->flags & SYM_REDEFINE) && !sym->hidden)
					error(1, "%s: redefined", sym->name);
#if MACKEYARGS
				if ((pp.option & KEYARGS) && mac->formkeys) free(mac->formkeys);
				else
#endif
				free(mac->formals);
				mac->formals = 0;
				n = strlen(mac->value) + 1;
			}
			else
			{
				ppfsm(FSM_MACRO, sym->name);
				n = 0;
			}
			n1 = ppexpr(&i1);
			if (i1) c = sfsprintf(pp.tmpbuf, MAXTOKEN, "%luU", n1);
			else c = sfsprintf(pp.tmpbuf, MAXTOKEN, "%ld", n1);
			if (n < ++c)
			{
				if (mac->value) free(mac->value);
				mac->value = oldof(0, char, 0, c);
			}
			strcpy(mac->value, pp.tmpbuf);
			sym->flags |= SYM_REDEFINE;
			c = (pp.state & NEWLINE) ? '\n' : ' ';
			goto benign;
		case LINE:
			pp.state &= ~DISABLE;
			if ((c = pplex()) == '#')
			{
				c = pplex();
				directive = INCLUDE;
			}
			if (c != T_DECIMAL && c != T_OCTAL)
			{
				error(1, "#%s: line number expected", dirname(LINE));
				goto eatdirective;
			}
		linesync:
			n = error_info.line;
			error_info.line = strtol(pp.token, NiL, 0);
			if (error_info.line == 0 && directive == LINE && (pp.state & STRICT) && !(pp.mode & HOSTED))
				error(1, "#%s: line number should be > 0", dirname(LINE));
			pp.state &= ~DISABLE;
			pp.state |= STRIP;
			switch (c = pplex())
			{
			case T_STRING:
				s = error_info.file;
				if (*(p = pp.token))
					pathcanon(p, 0);
				fp = ppsetfile(p);
				error_info.file = fp->name;
				if (error_info.line == 1)
					ppmultiple(fp, INC_IGNORE);
				switch (c = pplex())
				{
				case '\n':
					break;
				case T_DECIMAL:
				case T_OCTAL:
					if (directive == LINE && (pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
						error(1, "#%s: integer file type argument is non-standard", dirname(LINE));
					break;
				default:
					error(1, "#%s: integer file type argument expected", dirname(LINE));
					break;
				}
				if (directive == LINE) pp.in->flags &= ~IN_ignoreline;
				else if (pp.incref)
				{
					if (error_info.file != s)
					{
						switch (*pp.token)
						{
						case PP_sync_push:
							if (pp.insert) (*pp.incref)(s, error_info.file, n, PP_SYNC_INSERT);
							else (*pp.incref)(s, error_info.file, n, PP_SYNC_PUSH);
							break;
						case PP_sync_pop:
							if (pp.insert) (*pp.incref)(s, error_info.file, n, PP_SYNC_INSERT);
							else (*pp.incref)(s, error_info.file, n - 1, PP_SYNC_POP);
							break;
						case PP_sync_ignore:
							if (pp.insert) (*pp.incref)(s, error_info.file, n, PP_SYNC_INSERT);
							else
							{
								(*pp.incref)(s, error_info.file, n, PP_SYNC_IGNORE);
								error_info.file = s;
							}
							break;
						default:
							if (*s)
							{
								if (fp == pp.insert)
									pp.insert = 0;
								else if (error_info.line == 1 && !pp.insert)
									(*pp.incref)(s, error_info.file, n, PP_SYNC_PUSH);
								else
								{
									if (!pp.insert) pp.insert = ppgetfile(s);
									(*pp.incref)(s, error_info.file, n, PP_SYNC_INSERT);
								}
							}
							break;
						}
					}
				}
				break;
			case '\n':
				break;
			default:
				error(1, "#%s: \"file-name\" expected", dirname(LINE));
				break;
			}
			if (directive == LINE && (pp.in->flags & IN_ignoreline))
				error_info.line = n + 1;
			else
			{
				pp.hidden = 0;
				pp.state &= ~HIDDEN;
				if (pp.linesync)
				{
#if CATSTRINGS
					if (pp.state & JOINING) pp.state |= HIDDEN|SYNCLINE;
					else
#endif
					{
						s = pp.lineid;
						n = pp.flags;
						if (directive == LINE)
						{
							pp.flags &= ~PP_linetype;
							if (pp.macref) pp.lineid = dirname(LINE);
						}
						(*pp.linesync)(error_info.line, error_info.file);
						pp.flags = n;
						pp.lineid = s;
					}
				}
			}
			directive = LINE;
			break;
		case PRAGMA:
			/*
			 * #pragma [STDC] [pass:] [no]option [arg ...]
			 *
			 * pragma args are not expanded by default
			 *
			 * if STDC is present then it is silently passed on
			 *
			 * if pass is pp.pass then the option is used
			 * and verified but is not passed on
			 *
			 * if pass is omitted then the option is passed on
			 *
			 * otherwise if pass is non-null and not pp.pass then
			 * the option is passed on but not used
			 *
			 * if the line does not match this form then
			 * it is passed on unchanged
			 *
			 *	#directive   pass:  option  [...]
			 *	^         ^  ^   ^  ^     ^  ^   ^
			 *	pp.valbuf p0 p1  p2 p3    p4 p5  p6
			 *
			 * p?	0 if component omitted
			 * i0	0 if ``no''option
			 */

			p = pp.valbuf;
			*p++ = '#';
			STRCOPY(p, pp.token, s);
			p0 = p;
			if (pp.option & PRAGMAEXPAND)
				pp.state &= ~DISABLE;
			if (!(p6 = getline(p, &pp.valbuf[MAXTOKEN], !!(pp.option & PRAGMAEXPAND))))
			{
				*p0 = 0;
				error(2, "%s: directive too long", pp.valbuf);
				c = 0;
				goto eatdirective;
			}
			p1 = ++p;
			while (ppisid(*p))
				p++;
			if (p == p1)
			{
				p5 = p;
				p4 = 0;
				p3 = 0;
				p2 = 0;
				p1 = 0;
			}
			else if (*p != ':')
			{
				p5 = *p ? p + (*p == ' ') : 0;
				p4 = p;
				p3 = p1;
				p2 = 0;
				p1 = 0;
			}
			else
			{
				p2 = p++;
				p3 = p;
				while (ppisid(*p))
					p++;
				if (p == p3)
				{
					p4 = p1;
					p3 = 0;
					p2 = 0;
					p1 = 0;
				}
				else
					p4 = p;
				p5 = *p4 ? p4 + (*p4 == ' ') : 0;
			}
			if (!p1 && p3 && (p4 - p3) == 4 && strneq(p3, "STDC", 4))
				goto pass;
			if ((pp.state & WARN) && (pp.mode & (HOSTED|RELAX|PEDANTIC)) == PEDANTIC)
				error(1, "#%s: non-standard directive", dirname(PRAGMA));
			i0 = !p3 || *p3 != 'n' || *(p3 + 1) != 'o';
			if (!p3)
				goto checkmap;
			if (p1)
			{
				*p2 = 0;
				n = streq(p1, pp.pass);
				*p2 = ':';
				if (!n)
					goto checkmap;
			}
			else
				n = 0;
			i2 = *p4;
			*p4 = 0;
			if (((i1 = (int)hashref(pp.strtab, p3 + (i0 ? 0 : 2))) < 1 || i1 > X_last_option) && (i0 || (i1 = (int)hashref(pp.strtab, p3)) > X_last_option))
				i1 = 0;
			if ((pp.state & (COMPATIBILITY|STRICT)) == STRICT && !(pp.mode & (HOSTED|RELAX)))
			{
				if (pp.optflags[i1] & OPT_GLOBAL)
					goto donedirective;
				if (n || (pp.mode & WARN))
				{
					n = 0;
					error(1, "#%s: non-standard directive ignored", dirname(PRAGMA));
				}
				i1 = 0;
			}
			if (!n)
			{
				if (!(pp.optflags[i1] & OPT_GLOBAL))
				{
					*p4 = i2;
					goto checkmap;
				}
				if (!(pp.optflags[i1] & OPT_PASS))
					n = 1;
			}
			else if (!i1)
				error(2, "%s: unknown option", p1);
			else if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "%s: non-standard option", p1);
			p = p5;
			switch (i1)
			{
			case X_ALLMULTIPLE:
				ppop(PP_MULTIPLE, i0);
				break;
			case X_ALLPOSSIBLE:
				setoption(ALLPOSSIBLE, i0);
				break;
			case X_BUILTIN:
				setmode(BUILTIN, i0);
				break;
			case X_CATLITERAL:
				setmode(CATLITERAL, i0);
				if (pp.mode & CATLITERAL)
					setoption(STRINGSPLIT, 0);
				break;
			case X_CDIR:
				tokop(PP_CDIR, p3, p, i0, TOKOP_UNSET|TOKOP_STRING|TOKOP_DUP);
				break;
			case X_CHECKPOINT:
#if CHECKPOINT
				ppload(p);
#else
				error(3, "%s: preprocessor not compiled with checkpoint enabled", p3);
#endif
				break;
			case X_CHOP:
				tokop(PP_CHOP, p3, p, i0, TOKOP_UNSET|TOKOP_STRING);
				break;
			case X_COMPATIBILITY:
				ppop(PP_COMPATIBILITY, i0);
				break;
			case X_DEBUG:
				error_info.trace = i0 ? (p ? -strtol(p, NiL, 0) : -1) : 0;
				break;
			case X_ELSEIF:
				setoption(ELSEIF, i0);
				break;
			case X_EXTERNALIZE:
				setmode(EXTERNALIZE, i0);
				break;
			case X_FINAL:
				setoption(FINAL, i0);
				break;
			case X_HEADEREXPAND:
				setoption(HEADEREXPAND, i0);
				break;
			case X_HEADEREXPANDALL:
				setoption(HEADEREXPANDALL, i0);
				break;
			case X_HIDE:
			case X_NOTE:
				PUSH_LINE(p);
				/* UNDENT...*/
	while (c = pplex())
	{
		if (c != T_ID) error(1, "%s: %s: identifier expected", p3, pp.token);
		else if (sym = ppsymset(pp.symtab, pp.token))
		{
			if (i1 == X_NOTE)
			{
				sym->flags &= ~SYM_NOTICED;
				ppfsm(FSM_MACRO, sym->name);
			}
			else if (i0)
			{
				if (!sym->hidden && !(sym->hidden = newof(0, struct pphide, 1, 0)))
					error(3, "out of space");
				if (!sym->macro)
					ppfsm(FSM_MACRO, sym->name);
				if (!sym->hidden->level++)
				{
					pp.hiding++;
					if (sym->macro && !(sym->flags & (SYM_ACTIVE|SYM_READONLY)))
					{
						sym->hidden->macro = sym->macro;
						sym->macro = 0;
						sym->hidden->flags = sym->flags;
						sym->flags &= ~(SYM_BUILTIN|SYM_FUNCTION|SYM_INIT|SYM_MULTILINE|SYM_PREDEFINED|SYM_REDEFINE|SYM_VARIADIC);
					}
				}
			}
			else if (sym->hidden)
			{
				if ((mac = sym->macro) && !(sym->flags & (SYM_ACTIVE|SYM_READONLY)))
				{
					if (mac->formals) free(mac->formals);
					free(mac->value);
					free(mac);
					sym->macro = 0;
					sym->flags &= ~(SYM_BUILTIN|SYM_FUNCTION|SYM_INIT|SYM_MULTILINE|SYM_PREDEFINED|SYM_REDEFINE|SYM_VARIADIC);
				}
				if (!--sym->hidden->level)
				{
					pp.hiding--;
					if (sym->hidden->macro)
					{
						sym->macro = sym->hidden->macro;
						sym->flags = sym->hidden->flags;
					}
					free(sym->hidden);
					sym->hidden = 0;
				}
			}
		}
	}
				/*...INDENT*/
				POP_LINE();
				break;
			case X_HOSTDIR:
				tokop(PP_HOSTDIR, p3, p, i0, TOKOP_UNSET|TOKOP_STRING|TOKOP_DUP);
				break;
			case X_HOSTED:
				setmode(HOSTED, i0);
				break;
			case X_HOSTEDTRANSITION:
				setmode(HOSTEDTRANSITION, i0);
				break;
			case X_ID:
				tokop(PP_ID, p3, p, i0, TOKOP_UNSET|TOKOP_STRING);
				break;
			case X_IGNORE:
				tokop(PP_IGNORE, p3, p, i0, TOKOP_UNSET|TOKOP_STRING);
				break;
			case X_INCLUDE:
				tokop(PP_INCLUDE, p3, p, i0, TOKOP_STRING|TOKOP_DUP);
				break;
			case X_INITIAL:
				setoption(INITIAL, i0);
				break;
			case X_KEYARGS:
				ppop(PP_KEYARGS, i0);
				break;
			case X_LINE:
				if (pp.linesync) pp.olinesync = pp.linesync;
				pp.linesync = i0 ? pp.olinesync : (PPLINESYNC)0;
				break;
			case X_LINEBASE:
				ppop(PP_LINEBASE, i0);
				break;
			case X_LINEFILE:
				ppop(PP_LINEFILE, i0);
				break;
			case X_LINEID:
				ppop(PP_LINEID, i0 ? p : (char*)0);
				break;
			case X_LINETYPE:
				ppop(PP_LINETYPE, i0 ? (p ? strtol(p, NiL, 0) : 1) : 0);
				break;
			case X_MACREF:
				if (!p)
				{
					if (i0 && !pp.macref)
					{
						ppop(PP_LINETYPE, 1);
						ppop(PP_MACREF, ppmacref);
					}
					else error(2, "%s: option cannot be unset", p3);
				}
				else if (s = strchr(p, ' '))
				{
					if (pp.macref && (s = strchr(p, ' ')))
					{
						*s++ = 0;
						c = strtol(s, NiL, 0);
						var.type = pp.truncate;
						pp.truncate = PPTOKSIZ;
						(*pp.macref)(pprefmac(p, REF_CREATE), error_info.file, error_info.line - (c == REF_NORMAL ? 2 : 1), c, (s = strchr(s, ' ')) ? strtol(s, NiL, 0) : 0L);
						pp.truncate = var.type;
					}
					error_info.line -= 2;
				}
				break;
			case X_MAP:
				/*UNDENT*/
	/*
	 * #pragma pp:map [id ...] "/from/[,/to/]" [ "/old/new/[glnu]" ... ]
	 */
	
	if (!i0)
	{
		error(2, "%s: option cannot be unset", p3);
		goto donedirective;
	}
	if (!p5)
	{
		error(2, "%s: address argument expected", p3);
		goto donedirective;
	}
	PUSH_LINE(p5);
	while ((c = pplex()) == T_ID)
	{
		sfsprintf(pp.tmpbuf, MAXTOKEN, "__%s__", s = pp.token);
		if (c = (int)hashget(pp.dirtab, s))
		{
			hashput(pp.dirtab, 0, 0);
			hashput(pp.dirtab, pp.tmpbuf, c);
		}
		if (c = (int)hashget(pp.strtab, s))
		{
			hashput(pp.strtab, 0, 0);
			hashput(pp.strtab, pp.tmpbuf, c);
		}
	}
	if (c != T_STRING || !*(s = pp.token))
	{
		if (c)
			error(2, "%s: %s: address argument expected", p3, pptokstr(pp.token, 0));
		goto eatmap;
	}
	map = newof(0, struct map, 1, 0);
	
	/*
	 * /from/
	 */
	
	if (i0 = regcomp(&map->re, s, REG_AUGMENTED|REG_DELIMITED|REG_LENIENT|REG_NULL))
		regfatal(&map->re, 3, i0);
	if (*(s += map->re.re_npat))
	{
		error(2, "%s: invalid characters after pattern: %s ", p3, s);
		goto eatmap;
	}

	/*
	 * /old/new/[flags]
	 */
	
	edit = 0;
	while ((c = pplex()) == T_STRING)
	{
		if (!*(s = pp.token))
		{
			error(2, "%s: substitution argument expected", p3);
			goto eatmap;
		}
		if (edit)
			edit = edit->next = newof(0, struct edit, 1, 0);
		else
			edit = map->edit = newof(0, struct edit, 1, 0);
		if (!(i0 = regcomp(&edit->re, s, REG_AUGMENTED|REG_DELIMITED|REG_LENIENT|REG_NULL)) && !(i0 = regsubcomp(&edit->re, s += edit->re.re_npat, NiL, 0, 0)))
			s += edit->re.re_npat;
		if (i0)
			regfatal(&edit->re, 3, i0);
		if (*s)
		{
			error(2, "%s: invalid characters after substitution: %s ", p3, s);
			goto eatmap;
		}
	}
	if (c)
	{
		error(2, "%s: %s: substitution argument expected", p3, pptokstr(pp.token, 0));
		goto eatmap;
	}
	map->next = (struct map*)pp.maps;
	pp.maps = (char*)map;
 eatmap:
	POP_LINE();
				/*INDENT*/
				break;
			case X_MAPINCLUDE:
				ppmapinclude(NiL, p5);
				break;
			case X_MODERN:
				setoption(MODERN, i0);
				break;
			case X_MULTIPLE:
				n = 1;
				if (pp.in->type == IN_FILE || pp.in->type == IN_RESCAN)
					ppmultiple(ppsetfile(error_info.file), i0 ? INC_CLEAR : INC_IGNORE);
				break;
			case X_NATIVE:
				setoption(NATIVE, i0);
				break;
			case X_OPSPACE:
				ppfsm(FSM_OPSPACE, i0 ? p4 : (char*)0);
				break;
			case X_PASSTHROUGH:
				ppop(PP_PASSTHROUGH, i0);
				break;
			case X_PEDANTIC:
				ppop(PP_PEDANTIC, i0);
				break;
			case X_PLUSCOMMENT:
				ppop(PP_PLUSCOMMENT, i0);
				break;
			case X_PLUSPLUS:
				ppop(PP_PLUSPLUS, i0);
				break;
			case X_PLUSSPLICE:
				setoption(PLUSSPLICE, i0);
				break;
			case X_PRAGMAEXPAND:
				setoption(PRAGMAEXPAND, i0);
				break;
			case X_PRAGMAFLAGS:
				tokop(PP_PRAGMAFLAGS, p3, p, i0, 0);
				break;
			case X_PREDEFINED:
				setoption(PREDEFINED, i0);
				break;
			case X_PREFIX:
				setoption(PREFIX, i0);
				break;
			case X_PRESERVE:
				setoption(PRESERVE, i0);
				if (pp.option & PRESERVE)
				{
					setmode(CATLITERAL, 0);
					ppop(PP_COMPATIBILITY, 1);
					ppop(PP_TRANSITION, 0);
					ppop(PP_PLUSCOMMENT, 1);
					ppop(PP_SPACEOUT, 1);
					setoption(STRINGSPAN, 1);
					setoption(STRINGSPLIT, 0);
					ppop(PP_HOSTDIR, "-", 1);
				}
				break;
			case X_PROTOTYPED:
				/*
				 * this option doesn't bump the token count
				 */

				n = 1;
				directive = ENDIF;
#if PROTOTYPE
				setoption(PROTOTYPED, i0);
#else
				error(1, "preprocessor not compiled with prototype conversion enabled");
#endif
				break;
			case X_PROTO:
				setoption(NOPROTO, !i0);
				break;
			case X_QUOTE:
				tokop(PP_QUOTE, p3, p, i0, TOKOP_UNSET|TOKOP_STRING);
				break;
			case X_READONLY:
				setmode(READONLY, i0);
				break;
			case X_REGUARD:
				setoption(REGUARD, i0);
				break;
			case X_RESERVED:
				tokop(PP_RESERVED, p3, p, i0, 0);
				break;
			case X_SPACEOUT:
				if (!(pp.state & (COMPATIBILITY|COMPILE)))
					ppop(PP_SPACEOUT, i0);
				break;
			case X_SPLICECAT:
				setoption(SPLICECAT, i0);
				break;
			case X_SPLICESPACE:
				setoption(SPLICESPACE, i0);
				break;
			case X_STANDARD:
				tokop(PP_STANDARD, p3, p, i0, TOKOP_UNSET|TOKOP_STRING|TOKOP_DUP);
				break;
			case X_STRICT:
				ppop(PP_STRICT, i0);
				break;
			case X_STRINGSPAN:
				setoption(STRINGSPAN, i0);
				break;
			case X_STRINGSPLIT:
				setoption(STRINGSPLIT, i0);
				if (pp.option & STRINGSPLIT)
					setmode(CATLITERAL, 0);
				break;
			case X_SYSTEM_HEADER:
				if (i0)
				{
					pp.mode |= HOSTED;
					pp.flags |= PP_hosted;
					pp.in->flags |= IN_hosted;
				}
				else
				{
					pp.mode &= ~HOSTED;
					pp.flags &= ~PP_hosted;
					pp.in->flags &= ~PP_hosted;
				}
				break;
			case X_TEST:
				ppop(PP_TEST, p);
				break;
			case X_TEXT:
				if (!(pp.option & KEEPNOTEXT))
					setstate(NOTEXT, !i0);
				break;
			case X_TRANSITION:
				ppop(PP_TRANSITION, i0);
				if (pp.state & TRANSITION) ppop(PP_COMPATIBILITY, i0);
				break;
			case X_TRUNCATE:
				ppop(PP_TRUNCATE, i0 ? (p ? strtol(p, NiL, 0) : TRUNCLENGTH) : 0);
				break;
			case X_VENDOR:
				tokop(PP_VENDOR, p3, p, i0, TOKOP_UNSET|TOKOP_STRING|TOKOP_DUP);
				break;
			case X_VERSION:
				if (!(*pp.control & SKIP) && pp.pragma && !(pp.state & NOTEXT))
				{
					sfsprintf(pp.tmpbuf, MAXTOKEN, "\"%s\"", pp.version);
					(*pp.pragma)(dirname(PRAGMA), pp.pass, p3, pp.tmpbuf, !n);
					if (pp.linesync && !n)
						(*pp.linesync)(error_info.line, error_info.file);
					emitted = 1;
				}
				break;
			case X_WARN:
				ppop(PP_WARN, i0);
				break;
			case X_ZEOF:
				setoption(ZEOF, i0);
				break;
#if DEBUG
			case 0:
			case X_INCLUDED:
			case X_NOTICED:
			case X_OPTION:
			case X_STATEMENT:
				break;
			default:
				error(PANIC, "%s: option recognized but not implemented", pp.valbuf);
				break;
#endif
			}
			*p4 = i2;
			if (!n)
				goto checkmap;
			goto donedirective;
		case RENAME:
			if ((pp.state & STRICT) && !(pp.mode & (HOSTED|RELAX)))
				error(1, "#%s: non-standard directive", pp.token);
			if ((c = pplex()) != T_ID)
			{
				error(1, "%s: invalid macro name", pptokstr(pp.token, 0));
				goto eatdirective;
			}
			if (!(sym = pprefmac(pp.token, REF_DELETE)) || !sym->macro)
				goto eatdirective;
			if (sym->flags & (SYM_ACTIVE|SYM_READONLY))
			{
				if (!(pp.option & ALLPOSSIBLE))
					error(2, "%s: macro is %s", sym->name, (sym->flags & SYM_READONLY) ? "readonly" : "active");
				goto eatdirective;
			}
			if ((c = pplex()) != T_ID)
			{
				error(1, "%s: invalid macro name", pptokstr(pp.token, 0));
				goto eatdirective;
			}
			var.symbol = pprefmac(pp.token, REF_CREATE);
			if (mac = var.symbol->macro)
			{
				if (var.symbol->flags & (SYM_ACTIVE|SYM_READONLY))
				{
					if (!(pp.option & ALLPOSSIBLE))
						error(2, "%s: macro is %s", var.symbol->name, (var.symbol->flags & SYM_READONLY) ? "readonly" : "active");
					goto eatdirective;
				}
				if (!(pp.mode & HOSTED) || !(var.symbol->flags & SYM_INITIAL))
					error(1, "%s redefined", var.symbol->name);
				if (mac->formals) free(mac->formals);
				free(mac->value);
				free(mac);
			}
			ppfsm(FSM_MACRO, var.symbol->name);
			var.symbol->flags = sym->flags;
			sym->flags &= ~(SYM_BUILTIN|SYM_FUNCTION|SYM_INIT|SYM_MULTILINE|SYM_PREDEFINED|SYM_REDEFINE|SYM_VARIADIC);
			var.symbol->macro = sym->macro;
			sym->macro = 0;
			break;
		case UNDEF:
			if ((c = pplex()) != T_ID)
			{
				error(1, "%s: invalid macro name", pptokstr(pp.token, 0));
				goto eatdirective;
			}
			if (sym = pprefmac(pp.token, REF_DELETE))
			{
				if (mac = sym->macro)
				{
					if (sym->flags & (SYM_ACTIVE|SYM_READONLY))
					{
						if (!(pp.option & ALLPOSSIBLE))
							error(2, "%s: macro is %s", sym->name, (sym->flags & SYM_READONLY) ? "readonly" : "active");
						goto eatdirective;
					}
					if (mac->formals) free(mac->formals);
					free(mac->value);
					free(mac);
					mac = sym->macro = 0;
				}
				if ((pp.option & (DEFINITIONS|PREDEFINITIONS|REGUARD)) && !sym->hidden && !(sym->flags & SYM_MULTILINE) && ((pp.option & PREDEFINITIONS) || !(pp.mode & INIT)) && ((pp.option & (DEFINITIONS|PREDEFINITIONS)) || !(pp.state & NOTEXT)))
				{
					ppsync();
					ppprintf("#%s %s", dirname(UNDEF), sym->name);
					emitted = 1;
				}
				sym->flags &= ~(SYM_BUILTIN|SYM_FUNCTION|SYM_INIT|SYM_MULTILINE|SYM_PREDEFINED|SYM_REDEFINE|SYM_VARIADIC);
				n2 = error_info.line;
				goto benign;
			}
			else pprefmac(pp.token, REF_UNDEF);
			break;
#if DEBUG
		default:
			error(PANIC, "#%s: directive recognized but not implemented", pp.token);
			goto eatdirective;
#endif
		}
		break;
	case '\n':
		break;
	default:
		error(1, "%s: invalid directive name", pptokstr(pp.token, 0));
		goto eatdirective;
	}
 enddirective:
#if COMPATIBLE
	if (c != '\n' && !(pp.state & COMPATIBILITY))
#else
	if (c != '\n')
#endif
	{
		pp.state |= DISABLE|NOSPACE;
		if ((c = pplex()) != '\n' && (pp.mode & (HOSTED|PEDANTIC)) == PEDANTIC)
			error(1, "%s: invalid characters after directive", pptokstr(pp.token, 0));
	}
 eatdirective:
	if (c != '\n')
	{
		pp.state |= DISABLE;
		while (pplex() != '\n');
	}
 donedirective:
#if _HUH_2002_05_09
	if (!(pp.state & EOF2NL))
		error(2, "%s in directive", pptokchr(0));
#endif
	pp.state &= ~RESTORE;
	pp.mode &= ~RELAX;
	if (!(*pp.control & SKIP))
	{
		pp.state |= restore;
		switch (directive)
		{
		case LINE:
			return 0;
		case INCLUDE:
			if (pp.include)
			{
				error_info.line++;
				PUSH_FILE(pp.include, n);
				if (!pp.vendor && (pp.found->type & TYPE_VENDOR))
					pp.vendor = 1;
				pp.include = 0;
				return 0;
			}
			if (pp.incref)
				(*pp.incref)(error_info.file, ppgetfile(pp.path)->name, error_info.line, PP_SYNC_IGNORE);
			else if (pp.linesync && pp.macref)
			{
				pp.flags |= PP_lineignore;
				(*pp.linesync)(error_info.line, ppgetfile(pp.path)->name);
			}
			/*FALLTHROUGH*/
		default:
			pp.in->flags |= IN_tokens;
			/*FALLTHROUGH*/
		case ENDIF:
			error_info.line++;
			if (emitted)
			{
				ppputchar('\n');
				ppcheckout();
			}
			else
			{
				pp.state |= HIDDEN;
				pp.hidden++;
			}
			return 0;
		}
	}
	pp.state |= restore|HIDDEN|SKIPCONTROL;
	pp.hidden++;
	pp.level++;
	error_info.line++;
	return 0;
}

/*
 * grow the pp nesting control stack
 */

void
ppnest(void)
{
	register struct ppinstk*	ip;
	int				oz;
	int				nz;
	long				adjust;
	long*				op;
	long*				np;

	oz = pp.constack;
	op = pp.maxcon - oz + 1;
	nz = oz * 2;
	np = newof(op, long, nz, 0);
	if (adjust = (np - op))
	{
		ip = pp.in;
		do
		{
			if (ip->control)
				ip->control += adjust;
		} while (ip = ip->prev);
	}
	pp.control = np + oz;
	pp.constack = nz;
	pp.maxcon = np + nz - 1;
}
