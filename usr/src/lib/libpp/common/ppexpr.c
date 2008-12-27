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
 * preprocessor expression evaluation support
 */

#include "pplib.h"

#include <regex.h>

#define lex(c)		((((c)=peektoken)>=0?(peektoken=(-1)):((c)=pplex())),(c))
#define unlex(c)	(peektoken=(c))

static int		peektoken;	/* expression lookahead token	*/
static char*		errmsg;		/* subexpr() error message	*/

/*
 * exists predicate evaluation
 */

static int
exists(int op, char* pred, register char* args)
{
	register int	c;
	register int	type;
	char*		pptoken;
	long		state;
	char		file[MAXTOKEN + 1];

	state = (pp.state & ~DISABLE);
	PUSH_STRING(args);
	pptoken = pp.token;
	pp.token = file;
	pp.state |= HEADER|PASSEOF;
	type = pplex();
	pp.state &= ~HEADER;
	pp.token = pptoken;
	switch (type)
	{
	case T_STRING:
	case T_HEADER:
		break;
	default:
		error(1, "%s: \"...\" or <...> argument expected", pred);
		c = 0;
		goto done;
	}
	if (op == X_EXISTS)
	{
		if ((c = pplex()) == ',')
		{
			while ((c = pplex()) == T_STRING)
			{
				if (pathaccess(pp.path, pp.token, file, NiL, 0))
				{
					pathcanon(pp.path, 0);
					message((-2, "%s: %s found", pred, pp.path));
					c = 1;
					goto done;
				}
				if ((c = pplex()) != ',') break;
			}
			if (c) error(1, "%s: \"...\" arguments expected", pred);
			strcpy(pp.path, file);
			message((-2, "%s: %s not found", pred, file));
			c = 0;
		}
		else c = ppsearch(file, type, SEARCH_EXISTS) >= 0;
	}
	else
	{
		register struct ppfile*	fp;

		fp = ppsetfile(file);
		c = fp->flags || fp->guard == INC_IGNORE;
	}
 done:
	while (pplex());
	pp.state = state;
	return c;
}

/*
 * strcmp/match predicate evaluation
 */

static int
compare(char* pred, char* args, int match)
{
	register int	c;
	char*		pptoken;
	long		state;
	regex_t		re;
	char		tmp[MAXTOKEN + 1];

	state = (pp.state & ~DISABLE);
	PUSH_STRING(args);
	pp.state |= PASSEOF;
	pptoken = pp.token;
	pp.token = tmp;
	if (!pplex())
		goto bad;
	pp.token = pptoken;
	if (pplex() != ',' || !pplex())
		goto bad;
	if (!match)
		c = strcmp(tmp, pp.token);
	else if ((c = regcomp(&re, pp.token, REG_AUGMENTED|REG_LENIENT|REG_NULL)) || (c = regexec(&re, tmp, NiL, 0, 0)) && c != REG_NOMATCH)
		regfatal(&re, 3, c);
	else
	{
		c = !c;
		regfree(&re);
	}
	if ((pp.state & PASSEOF) && pplex())
		goto bad;
	pp.state = state;
	return c;
 bad:
	pp.token = pptoken;
	error(2, "%s: 2 arguments expected", pred);
	while (pplex());
	pp.state = state;
	return 0;
}

/*
 * #if predicate parse and evaluation
 */

static int
predicate(int warn)
{
	register char*			args;
	register struct pplist*		p;
	register struct ppsymbol*	sym;
	register int			type;
	int				index;

	static char			pred[MAXID + 1];

	/*
	 * first gather the args
	 */

	index = (int)hashref(pp.strtab, pp.token);
	if (warn && peekchr() != '(') switch (index)
	{
	case X_DEFINED:
	case X_EXISTS:
	case X_INCLUDED:
	case X_MATCH:
	case X_NOTICED:
	case X_OPTION:
	case X_SIZEOF:
	case X_STRCMP:
		break;
	default:
		if (pp.macref) pprefmac(pp.token, REF_IF);
		return 0;
	}
	strcpy(pred, pp.token);
	pp.state |= DISABLE;
	type = pppredargs();
	pp.state &= ~DISABLE;
	switch (type)
	{
	case T_ID:
	case T_STRING:
		break;
	default:
		unlex(type);
		/*FALLTHROUGH*/
	case 0:
		if (index && !(pp.state & STRICT))
			error(1, "%s: predicate argument expected", pred);
		if (pp.macref) pprefmac(pred, REF_IF);
		return 0;
	}
	args = pp.args;

	/*
	 * now evaluate
	 */

	debug((-6, "pred=%s args=%s", pred, args));
	if ((pp.state & STRICT) && !(pp.mode & HOSTED)) switch (index)
	{
	case X_DEFINED:
	case X_SIZEOF:
		break;
	default:
		error(1, "%s(%s): non-standard predicate test", pred, args);
		return 0;
	}
	switch (index)
	{
	case X_DEFINED:
		if (type != T_ID) error(1, "%s: identifier argument expected", pred);
		else if ((sym = pprefmac(args, REF_IF)) && sym->macro) return 1;
		else if (args[0] == '_' && args[1] == '_' && !strncmp(args, "__STDPP__", 9))
		{
			if (pp.hosted == 1 && pp.in->prev->type == IN_FILE)
			{
				pp.mode |= HOSTED;
				pp.flags |= PP_hosted;
			}
			return *(args + 9) ? (int)hashref(pp.strtab, args + 9) : 1;
		}
		break;
	case X_EXISTS:
	case X_INCLUDED:
		return exists(index, pred, args);
	case X_MATCH:
	case X_STRCMP:
		return compare(pred, args, index == X_MATCH);
	case X_NOTICED:
		if (type != T_ID) error(1, "%s: identifier argument expected", pred);
		else if (((sym = pprefmac(args, REF_IF)) || (sym = ppsymref(pp.symtab, args))) && (sym->flags & SYM_NOTICED)) return 1;
		break;
	case X_OPTION:
		return ppoption(args);
	case X_SIZEOF:
		error(2, "%s invalid in #%s expressions", pred, dirname(IF));
		break;
	default:
		if (warn && !(pp.mode & HOSTED) && (sym = ppsymref(pp.symtab, pred)) && (sym->flags & SYM_PREDICATE))
			error(1, "use #%s(%s) to disambiguate", pred, args);
		if (p = (struct pplist*)hashget(pp.prdtab, pred))
		{
			if (!*args) return 1;
			while (p)
			{
				if (streq(p->value, args)) return 1;
				p = p->next;
			}
		}
		break;
	}
	return 0;
}

/*   
 * evaluate a long integer subexpression with precedence
 * taken from the library routine streval()
 * may be called recursively
 *
 * NOTE: all operands are evaluated as both the parse
 *	 and evaluation are done on the fly
 */

static long
subexpr(register int precedence, int* pun)
{
	register int		c;
	register long		n;
	register long		x;
	register int		operand = 1;
	int			un = 0;
	int			xn;

	switch (lex(c))
	{
	case 0:
	case '\n':
		unlex(c);
		if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "more tokens expected";
		return 0;
	case '-':
		n = -subexpr(13, &un);
		break;
	case '+':
		n = subexpr(13, &un);
		break;
	case '!':
		n = !subexpr(13, &un);
		break;
	case '~':
		n = ~subexpr(13, &un);
		break;
	default:
		unlex(c);
		n = 0;
		operand = 0;
		break;
	}
	un <<= 1;
	for (;;)
	{
		switch (lex(c))
		{
		case 0:
		case '\n':
			goto done;
		case ')':
			if (!precedence)
			{
				if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "too many )'s";
				return 0;
			}
			goto done;
		case '(':
			n = subexpr(1, &un);
			if (lex(c) != ')')
			{
				unlex(c);
				if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "closing ) expected";
				return 0;
			}
		gotoperand:
			if (operand)
			{
				if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "operator expected";
				return 0;
			}
			operand = 1;
			un <<= 1;
			continue;
		case '?':
			if (precedence > 1) goto done;
			un = 0;
			if (lex(c) == ':')
			{
				if (!n) n = subexpr(2, &un);
				else
				{
					x = pp.mode;
					pp.mode |= INACTIVE;
					subexpr(2, &xn);
					pp.mode = x;
				}
			}
			else
			{
				unlex(c);
				x = subexpr(2, &xn);
				if (lex(c) != ':')
				{
					unlex(c);
					if (!errmsg && !(pp.mode & INACTIVE)) errmsg = ": expected for ? operator";
					return 0;
				}
				if (n)
				{
					n = x;
					un = xn;
					subexpr(2, &xn);
				}
				else n = subexpr(2, &un);
			}
			break;
		case ':':
			goto done;
		case T_ANDAND:
		case T_OROR:
			xn = (c == T_ANDAND) ? 4 : 3;
			if (precedence >= xn) goto done;
			if ((n != 0) == (c == T_ANDAND)) n = subexpr(xn, &un) != 0;
			else
			{
				x = pp.mode;
				pp.mode |= INACTIVE;
				subexpr(xn, &un);
				pp.mode = x;
			}
			un = 0;
			break;
		case '|':
			if (precedence > 4) goto done;
			n |= subexpr(5, &un);
			break;
		case '^':
			if (precedence > 5) goto done;
			n ^= subexpr(6, &un);
			break;
		case '&':
			if (precedence > 6) goto done;
			n &= subexpr(7, &un);
			break;
		case T_EQ:
		case T_NE:
			if (precedence > 7) goto done;
			n = (n == subexpr(8, &un)) == (c == T_EQ);
			un = 0;
			break;
		case '<':
		case T_LE:
		case T_GE:
		case '>':
			if (precedence > 8) goto done;
			x = subexpr(9, &un);
			switch (c)
			{
			case '<':
				switch (un)
				{
				case 01:
					n = n < (unsigned long)x;
					break;
				case 02:
					n = (unsigned long)n < x;
					break;
				case 03:
					n = (unsigned long)n < (unsigned long)x;
					break;
				default:
					n = n < x;
					break;
				}
				break;
			case T_LE:
				switch (un)
				{
				case 01:
					n = n <= (unsigned long)x;
					break;
				case 02:
					n = (unsigned long)n <= x;
					break;
				case 03:
					n = (unsigned long)n <= (unsigned long)x;
					break;
				default:
					n = n <= x;
					break;
				}
				break;
			case T_GE:
				switch (un)
				{
				case 01:
					n = n >= (unsigned long)x;
					break;
				case 02:
					n = (unsigned long)n >= x;
					break;
				case 03:
					n = (unsigned long)n >= (unsigned long)x;
					break;
				default:
					n = n >= x;
					break;
				}
				break;
			case '>':
				switch (un)
				{
				case 01:
					n = n > (unsigned long)x;
					break;
				case 02:
					n = (unsigned long)n > x;
					break;
				case 03:
					n = (unsigned long)n > (unsigned long)x;
					break;
				default:
					n = n > x;
					break;
				}
				break;
			}
			un = 0;
			break;
		case T_LSHIFT:
		case T_RSHIFT:
			if (precedence > 9) goto done;
			x = subexpr(10, &un);
			if (c == T_LSHIFT) n <<= x;
			else n >>= x;
			un >>= 1;
			break;
		case '+':
		case '-':
			if (precedence > 10) goto done;
			x = subexpr(11, &un);
			if (c == '+') n += x;
			else n -= x;
			break;
		case '*':
		case '/':
		case '%':
			if (precedence > 11) goto done;
			x = subexpr(12, &un);
			if (c == '*') n *= x;
			else if (x == 0)
			{
				if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "divide by zero";
				return 0;
			}
			else if (c == '/') n /= x;
			else n %= x;
			break;
		case '#':
			pp.state |= DISABLE;
			c = pplex();
			pp.state &= ~DISABLE;
			if (c != T_ID)
			{
				if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "# must precede a predicate identifier";
				return 0;
			}
			n = predicate(0);
			goto gotoperand;
		case T_ID:
			n = predicate(1);
			goto gotoperand;
		case T_CHARCONST:
			c = *(pp.toknxt - 1);
			*(pp.toknxt - 1) = 0;
			n = chrtoi(pp.token + 1);
			*(pp.toknxt - 1) = c;
			if (n & ~((1<<CHAR_BIT)-1))
			{
				if (!(pp.mode & HOSTED))
					error(1, "'%s': multi-character character constants are not portable", pp.token);
			}
#if CHAR_MIN < 0
			else n = (char)n;
#endif
			goto gotoperand;
		case T_DECIMAL_U:
		case T_DECIMAL_UL:
		case T_OCTAL_U:
		case T_OCTAL_UL:
		case T_HEXADECIMAL_U:
		case T_HEXADECIMAL_UL:
			un |= 01;
			/*FALLTHROUGH*/
		case T_DECIMAL:
		case T_DECIMAL_L:
		case T_OCTAL:
		case T_OCTAL_L:
		case T_HEXADECIMAL:
		case T_HEXADECIMAL_L:
			n = strtoul(pp.token, NiL, 0);
			if ((unsigned long)n > LONG_MAX) un |= 01;
			goto gotoperand;
		case T_WCHARCONST:
			n = chrtoi(pp.token);
			goto gotoperand;
		default:
			if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "invalid token";
			return 0;
		}
		if (errmsg) return 0;
		if (!operand) goto nooperand;
	}
 done:
	unlex(c);
	if (!operand)
	{
	nooperand:
		if (!errmsg && !(pp.mode & INACTIVE)) errmsg = "operand expected";
		return 0;
	}
	if (un) *pun |= 01;
	return n;
}

/*
 * preprocessor expression evaluator using modified streval(3)
 * *pun!=0 if result is unsigned
 */

long
ppexpr(int* pun)
{
	long	n;
	int	opeektoken;
	long	ppstate;

	ppstate = (pp.state & (CONDITIONAL|DISABLE|NOSPACE|STRIP));
	pp.state &= ~(DISABLE|STRIP);
	pp.state |= CONDITIONAL|NOSPACE;
	opeektoken = peektoken;
	peektoken = -1;
	*pun = 0;
	n = subexpr(0, pun);
	if (peektoken == ':' && !errmsg && !(pp.mode & INACTIVE)) errmsg = "invalid use of :";
	if (errmsg)
	{
		error(2, "%s in expression", errmsg);
		errmsg = 0;
		n = 0;
	}
	peektoken = opeektoken;
	pp.state &= ~(CONDITIONAL|NOSPACE);
	pp.state |= ppstate;
	if (*pun) debug((-4, "ppexpr() = %luU", n));
	else debug((-4, "ppexpr() = %ld", n));
	return n;
}

/*
 * return non-zero if option s is set
 */

int
ppoption(char* s)
{
	switch ((int)hashget(pp.strtab, s))
	{
	case X_ALLMULTIPLE:
		return pp.mode & ALLMULTIPLE;
	case X_BUILTIN:
		return pp.mode & BUILTIN;
	case X_CATLITERAL:
		return pp.mode & CATLITERAL;
	case X_COMPATIBILITY:
		return pp.state & COMPATIBILITY;
	case X_DEBUG:
		return -error_info.trace;
	case X_ELSEIF:
		return pp.option & ELSEIF;
	case X_FINAL:
		return pp.option & FINAL;
	case X_HOSTDIR:
		return pp.mode & HOSTED;
	case X_HOSTED:
		return pp.flags & PP_hosted;
	case X_INITIAL:
		return pp.option & INITIAL;
	case X_KEYARGS:
		return pp.option & KEYARGS;
	case X_LINEBASE:
		return pp.flags & PP_linebase;
	case X_LINEFILE:
		return pp.flags & PP_linefile;
	case X_LINETYPE:
		return pp.flags & PP_linetype;
	case X_PLUSCOMMENT:
		return pp.option & PLUSCOMMENT;
	case X_PLUSPLUS:
		return pp.option & PLUSPLUS;
	case X_PLUSSPLICE:
		return pp.option & PLUSSPLICE;
	case X_PRAGMAEXPAND:
		return pp.option & PRAGMAEXPAND;
	case X_PREDEFINED:
		return pp.option & PREDEFINED;
	case X_PREFIX:
		return pp.option & PREFIX;
	case X_PROTOTYPED:
		return pp.option & PROTOTYPED;
	case X_READONLY:
		return pp.mode & READONLY;
	case X_REGUARD:
		return pp.option & REGUARD;
	case X_SPACEOUT:
		return pp.state & SPACEOUT;
	case X_SPLICECAT:
		return pp.option & SPLICECAT;
	case X_SPLICESPACE:
		return pp.option & SPLICESPACE;
	case X_STRICT:
		return pp.state & STRICT;
	case X_STRINGSPAN:
		return pp.option & STRINGSPAN;
	case X_STRINGSPLIT:
		return pp.option & STRINGSPLIT;
	case X_TEST:
		return pp.test;
	case X_TEXT:
		return !(pp.state & NOTEXT);
	case X_TRANSITION:
		return pp.state & TRANSITION;
	case X_TRUNCATE:
		return pp.truncate;
	case X_WARN:
		return pp.state & WARN;
	default:
		if (pp.state & WARN) error(1, "%s: unknown option name", s);
		return 0;
	}
}
