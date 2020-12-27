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
 * expr.c
 * Written by David Korn
 * Tue Oct 31 08:48:11 EST 1995
 */

static const char usage[] =
"[-?\n@(#)$Id: expr (AT&T Research) 2010-08-11 $\n]"
USAGE_LICENSE
"[+NAME?expr - evaluate arguments as an expression]"
"[+DESCRIPTION?\bexpr\b evaluates an expression given as arguments and writes "
	"the result to standard output.  The character \b0\b will be written "
	"to indicate a zero value and nothing will be written to indicate an "
	"empty string.]"
"[+?Most of the functionality of \bexpr\b is provided in a more natural "
	"way by the shell, \bsh\b(1), and \bexpr\b is provided primarily "
	"for backward compatibility.]"
"[+?Terms of the expression must be separate arguments.  A string argument is "
	"one that can not be identified as an integer.  Integer-valued "
	"arguments may be preceded by a unary plus or minus sign.  Because "
	"many of the operators use characters that have special meaning to "
	"the shell, they must be quoted when entered from the shell.]"

"[+?Expressions are formed from the operators listed below in order "
	"of increasing precedence within groups.  All of the operators are "
	"left associative. The symbols \aexpr1\a and \aexpr2\a represent "
	"expressions formed from strings and integers and the following "
	"operators:]{"
	"[+\aexpr1\a \b|\b \aexpr2\a?Returns the evaluation of \aexpr1\a if "
	"it is neither null nor 0, otherwise returns the evaluation of expr2.]"

	"[+\aexpr1\a \b&\b \aexpr2\a?Returns the evaluation of \aexpr1\a if "
	"neither expression evaluates to null or 0, otherwise returns 0.]"

	"[+\aexpr1\a \aop\a \aexpr2\a?Returns the result of a decimal integer "
	"comparison if both arguments are integers; otherwise, returns the "
	"result of a string comparison using the locale-specific collation "
	"sequence. The result of each comparison will be 1 if the specified "
	"relationship is true, or 0 if the relationship is false.  \aop\a "
	"can be one of the following:]{"
		"[+=?Equal.]"
		"[+==?Equal.]"
		"[+>?Greater than.]"
		"[+>=?Greater than or equal to.]"
		"[+<?Less than.]"
		"[+<=?Less than or equal to.]"
		"[+!=?Not equal to.]"
		"}"

	"[+\aexpr1\a \aop\a \aexpr2\a?Where \aop\a is \b+\b or \b-\b; "
		"addition or subtraction of decimal integer-valued arguments.]"
	"[+\aexpr1\a \aop\a \aexpr2\a?Where \aop\a is \b*\b, \b/\b or \b%\b; "
		"multiplication, division, or remainder of the	decimal	"
		"integer-valued arguments.]"
	"[+\aexpr1\a \b::\b \aexpr2\a?The matching operator : compares "
		"\aexpr1\a with \aexpr2\a, which must be a BRE.  Normally, "
		"the matching operator returns the number of bytes matched "
		"and 0 on failure.  However, if the pattern contains at "
		"least one sub-expression [\\( . . .\\)]], the string "
		"corresponding to \\1 will be returned.]"
	"[+( \aexpr1\a )?Grouping symbols.  An expression can "
		"be placed within parenthesis to change precedence.]"
	"[+match\b \astring\a \aexpr\a?Equivalent to \astring\a \b:\b "
		"\aexpr\a.]"
	"[+substr\b \astring\a \apos\a \alength\a?\alength\a character "
		"substring of \astring\a starting at \apos\a "
		"(counting from 1).]"
	"[+index\b \astring\a \achars\a?The position in \astring\a "
		"(counting from 1) of the leftmost occurrence of any "
		"character in \achars\a.]"
	"[+length\b \astring\a?The number of characters in \astring\a.]"
	"[+quote\b \atoken\a?Treat \atoken\a as a string operand.]"
	"}"
"[+?For backwards compatibility, unrecognized options beginning with "
	"a \b-\b will be treated as operands.  Portable applications "
	"should use \b--\b to indicate end of options.]"

"\n"
"\n operand ...\n"
"\n"

"[+EXIT STATUS?]{"
	"[+0?The expression is neither null nor	0.]"
	"[+1?The expression is null or 0.]"
	"[+2?Invalid expressions.]"
	"[+>2?An error occurred.]"
	"}"
"[+SEE ALSO?\bregcomp\b(5), \bgrep\b(1), \bsh\b(1)]"
;

#include	<cmd.h>
#include	<regex.h>

#define T_ADD	0x100
#define T_MULT	0x200
#define T_CMP	0x400
#define T_FUN	0x800
#define T_OP	7
#define T_NUM	1
#define T_STR	2

#define OP_EQ		(T_CMP|0)
#define OP_GT		(T_CMP|1)
#define OP_LT		(T_CMP|2)
#define OP_GE		(T_CMP|3)
#define OP_LE		(T_CMP|4)
#define OP_NE		(T_CMP|5)
#define OP_PLUS		(T_ADD|0)
#define OP_MINUS	(T_ADD|1)
#define OP_MULT		(T_MULT|0)
#define OP_DIV		(T_MULT|1)
#define OP_MOD		(T_MULT|2)
#define OP_INDEX	(T_FUN|0)
#define OP_LENGTH	(T_FUN|1)
#define OP_MATCH	(T_FUN|2)
#define OP_QUOTE	(T_FUN|3)
#define OP_SUBSTR	(T_FUN|4)

#define numeric(np)	((np)->type&T_NUM)

static const struct Optable_s
{
	const char	opname[3];
	int		op;
}
optable[] =
{
	"|",	'|',
	"&",	'&',
	"=",	OP_EQ,
	"==",	OP_EQ,
	">",	OP_GT,
	"<",	OP_LT,
	">=",	OP_GE,
	"<=",	OP_LE,
	"!=",	OP_NE,
	"+",	OP_PLUS,
	"-",	OP_MINUS,
	"*",	OP_MULT,
	"/",	OP_DIV,
	"%",	OP_MOD,
	":",	':',
	"(",	'(',
	")",	')'
};

typedef struct Node_s
{
	int	type;
	long	num;
	char	*str;
} Node_t;

typedef struct State_s
{
	int	standard;
	char**	arglist;
	char	buf[36];
} State_t;

static int expr_or(State_t*, Node_t*);

static int getnode(State_t* state, Node_t *np)
{
	register char*	sp;
	register char*	cp;
	register int	i;
	register int	j;
	register int	k;
	register int	tok;
	char*		ep;

	if (!(cp = *state->arglist++))
		error(ERROR_exit(2), "argument expected");
	if (!state->standard)
		switch (cp[0])
		{
		case 'i':
			if (cp[1] == 'n' && !strcmp(cp, "index"))
			{
				if (!(cp = *state->arglist++))
					error(ERROR_exit(2), "string argument expected");
				if (!(ep = *state->arglist++))
					error(ERROR_exit(2), "chars argument expected");
				np->num = (ep = strpbrk(cp, ep)) ? (ep - cp + 1) : 0;
				np->type = T_NUM;
				goto next;
			}
			break;
		case 'l':
			if (cp[1] == 'e' && !strcmp(cp, "length"))
			{
				if (!(cp = *state->arglist++))
					error(ERROR_exit(2), "string argument expected");
				np->num = strlen(cp);
				np->type = T_NUM;
				goto next;
			}
			break;
		case 'm':
			if (cp[1] == 'a' && !strcmp(cp, "match"))
			{
				if (!(np->str = *state->arglist++))
					error(ERROR_exit(2), "pattern argument expected");
				np->type = T_STR;
				return ':';
			}
			break;
		case 'q':
			if (cp[1] == 'u' && !strcmp(cp, "quote") && !(cp = *state->arglist++))
				error(ERROR_exit(2), "string argument expected");
			break;
		case 's':
			if (cp[1] == 'u' && !strcmp(cp, "substr"))
			{
				if (!(sp = *state->arglist++))
					error(ERROR_exit(2), "string argument expected");
				if (!(cp = *state->arglist++))
					error(ERROR_exit(2), "position argument expected");
				i = strtol(cp, &ep, 10);
				if (*ep || --i < 0)
					i = -1;
				if (!(cp = *state->arglist++))
					error(ERROR_exit(2), "length argument expected");
				j = strtol(cp, &ep, 10);
				if (*ep)
					j = -1;
				k = strlen(sp);
				if (i < 0 || i >= k || j < 0)
					sp = "";
				else
				{
					sp += i;
					k -= i;
					if (j < k)
						sp[j] = 0;
				}
				np->type = T_STR;
				np->str = sp;
				goto next;
			}
			break;
		}
	if (*cp=='(' && cp[1]==0)
	{
		tok = expr_or(state, np);
		if (tok != ')')
			error(ERROR_exit(2),"closing parenthesis missing");
	}
	else
	{
		np->type = T_STR;
		np->str = cp;
		if (*cp)
		{
			np->num = strtol(np->str,&ep,10);
			if (!*ep)
				np->type |= T_NUM;
		}
	}
 next:
	if (!(cp = *state->arglist))
		return 0;
	state->arglist++;
	for (i=0; i < sizeof(optable)/sizeof(*optable); i++)
		if (*cp==optable[i].opname[0] && cp[1]==optable[i].opname[1])
			return optable[i].op;
	error(ERROR_exit(2),"%s: unknown operator argument",cp);
	return 0;
}

static int expr_cond(State_t* state, Node_t *np)
{
	register int	tok = getnode(state, np);

	while (tok==':')
	{
		regex_t re;
		regmatch_t match[2];
		int n;
		Node_t rp;
		char *cp;
		tok = getnode(state, &rp);
		if (np->type&T_STR)
			cp = np->str;
		else
			sfsprintf(cp=state->buf,sizeof(state->buf),"%d",np->num);
		np->num = 0;
		np->type = T_NUM;
		if (n = regcomp(&re, rp.str, REG_LEFT|REG_LENIENT))
			regfatal(&re, ERROR_exit(2), n);
		if (!(n = regexec(&re, cp, elementsof(match), match, 0)))
		{
			if (re.re_nsub > 0)
			{
				np->type = T_STR;
				if (match[1].rm_so >= 0)
				{
					np->str = cp + match[1].rm_so;
					np->str[match[1].rm_eo - match[1].rm_so] = 0;
					np->num = strtol(np->str,&cp,10);
					if (cp!=np->str && *cp==0)
						np->type |= T_NUM;
				}
				else
					np->str = "";
			}
			else
				np->num = match[0].rm_eo - match[0].rm_so;
		}
		else if (n != REG_NOMATCH)
			regfatal(&re, ERROR_exit(2), n);
		else if (re.re_nsub)
		{
			np->str = "";
			np->type = T_STR;
		}
		regfree(&re);
	}
	return tok;
}

static int expr_mult(State_t* state, Node_t *np)
{
	register int	tok = expr_cond(state, np);

	while ((tok&~T_OP)==T_MULT)
	{
		Node_t rp;
		int op = (tok&T_OP);
		tok = expr_cond(state, &rp);
		if (!numeric(np) || !numeric(&rp))
			error(ERROR_exit(2),"non-numeric argument");
		if (op && rp.num==0)
			error(ERROR_exit(2),"division by zero");
		switch(op)
		{
		    case 0:
			np->num *= rp.num;
			break;
		    case 1:
			np->num /= rp.num;
			break;
		    case 2:
			np->num %= rp.num;
		}
		np->type = T_NUM;
	}
	return tok;
}

static int expr_add(State_t* state, Node_t *np)
{
	register int	tok = expr_mult(state, np);

	while ((tok&~T_OP)==T_ADD)
	{
		Node_t rp;
		int op = (tok&T_OP);
		tok = expr_mult(state, &rp);
		if (!numeric(np) || !numeric(&rp))
			error(ERROR_exit(2),"non-numeric argument");
		if (op)
			np->num -= rp.num;
		else
			np->num += rp.num;
		np->type = T_NUM;
	}
	return tok;
}

static int expr_cmp(State_t* state, Node_t *np)
{
	register int	tok = expr_add(state, np);

	while ((tok&~T_OP)==T_CMP)
	{
		Node_t rp;
		register char *left,*right;
		char buff1[36],buff2[36];
		int op = (tok&T_OP);
		tok = expr_add(state, &rp);
		if (numeric(&rp) && numeric(np))
			op |= 010;
		else
		{
			if (np->type&T_STR)
				left = np->str;
			else
				sfsprintf(left=buff1,sizeof(buff1),"%d",np->num);
			if (rp.type&T_STR)
				right = rp.str;
			else
				sfsprintf(right=buff2,sizeof(buff2),"%d",rp.num);
		}
		switch(op)
		{
		    case 0:
			np->num = streq(left,right);
			break;
		    case 1:
			np->num = (strcoll(left,right)>0);
			break;
		    case 2:
			np->num = (strcoll(left,right)<0);
			break;
		    case 3:
			np->num = (strcoll(left,right)>=0);
			break;
		    case 4:
			np->num = (strcoll(left,right)<=0);
			break;
		    case 5:
			np->num = !streq(left,right);
			break;
		    case 010:
			np->num = (np->num==rp.num);
			break;
		    case 011:
			np->num = (np->num>rp.num);
			break;
		    case 012:
			np->num = (np->num<rp.num);
			break;
		    case 013:
			np->num = (np->num>=rp.num);
			break;
		    case 014:
			np->num = (np->num<=rp.num);
			break;
		    case 015:
			np->num = (np->num!=rp.num);
			break;
		}
		np->type = T_NUM;
	}
	return tok;
}

static int expr_and(State_t* state, Node_t *np)
{
	register int	tok = expr_cmp(state, np);
	while (tok=='&')
	{
		Node_t rp;
		tok = expr_cmp(state, &rp);
		if ((numeric(&rp) && rp.num==0) || *rp.str==0)
		{
			np->num = 0;
			np->type=T_NUM;
		}
	}
	return tok;
}

static int expr_or(State_t* state, Node_t *np)
{
	register int	tok = expr_and(state, np);
	while (tok=='|')
	{
		Node_t rp;
		tok = expr_and(state, &rp);
		if ((numeric(np) && np->num==0) || *np->str==0)
			*np = rp;
	}
	return tok;
}

int
b_expr(int argc, char** argv, Shbltin_t* context)
{
	State_t	state;
	Node_t	node;
	int	n;

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	state.standard = !!conformance(0, 0);
#if 0
	if (state.standard)
		state.arglist = argv+1;
	else
#endif
	{
		while (n=optget(argv, usage))
		{
			/*
			 * NOTE: this loop ignores all but literal -- and -?
			 *	 out of kindness for obsolescent usage
			 *	 (and is ok with the standard) but strict
			 *	 getopt conformance would give usage for all
			 *	 unknown - options
			 */
			if(n=='?')
				error(ERROR_usage(2), "%s", opt_info.arg);
			if (opt_info.option[1] != '?')
				break;
			error(ERROR_usage(2), "%s", opt_info.arg);
		}
		if (error_info.errors)
			error(ERROR_usage(2),"%s",optusage((char*)0));
		state.arglist = argv+opt_info.index;
	}
	if (expr_or(&state, &node))
		error(ERROR_exit(2),"syntax error");
	if (node.type&T_STR)
	{
		if (*node.str)
			sfprintf(sfstdout,"%s\n",node.str);
	}
	else
		sfprintf(sfstdout,"%d\n",node.num);
	return numeric(&node)?node.num==0:*node.str==0;
}
