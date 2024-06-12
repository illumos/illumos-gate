%{
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
%}

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

%{
extern long	evalval;
#define	YYSTYPE	long
%}

%term DIGITS
%left OROR
%left ANDAND
%left '|' '^'
%left '&'
%right '!' '~'
%nonassoc GT GE LT LE NE EQ
%left '+' '-'
%left '*' '/' '%'
%right POWER
%right UMINUS
%%

s	: e	{ evalval = $1; }
	|	{ evalval = 0; }
	;

e	: e OROR e	{ $$ = ($1 != 0 || $3 != 0) ? 1 : 0; }
	| e ANDAND e	{ $$ = ($1 != 0 && $3 != 0) ? 1 : 0; }
	| '!' e		{ $$ = $2 == 0; }
	| '~' e		{ $$ = ~$2; }
	| e EQ e	{ $$ = $1 == $3; }
	| e NE e	{ $$ = $1 != $3; }
	| e GT e	{ $$ = $1 > $3; }
	| e GE e	{ $$ = $1 >= $3; }
	| e LT e	{ $$ = $1 < $3; }
	| e LE e	{ $$ = $1 <= $3; }
	| e '|' e	{ $$ = ($1 | $3); }
	| e '&' e	{ $$ = ($1 & $3); }
	| e '^' e	{ $$ = ($1 ^ $3); }
	| e '+' e	{ $$ = ($1 + $3); }
	| e '-' e	{ $$ = ($1 - $3); }
	| e '*' e	{ $$ = ($1 * $3); }
	| e '/' e	{ $$ = ($1 / $3); }
	| e '%' e	{ $$ = ($1 % $3); }
	| '(' e ')'	{ $$ = ($2); }
	| e POWER e	{ for ($$ = 1; $3-- > 0; $$ *= $1); }
	| '-' e %prec UMINUS	{ $$ = $2-1; $$ = -$2; }
	| '+' e %prec UMINUS	{ $$ = $2-1; $$ = $2; }
	| DIGITS	{ $$ = evalval; }
	;

%%

#include "m4.h"
extern wchar_t *pe;
static int peek(int c, int r1, int r2);

int
yylex(void)
{
	while (*pe == ' ' || *pe == '\t' || *pe == '\n')
		pe++;
	switch (*pe) {
	case '\0':
	case '+':
	case '-':
	case '/':
	case '%':
	case '^':
	case '~':
	case '(':
	case ')':
		return (*pe++);
	case '*':
		return (peek('*', POWER, '*'));
	case '>':
		return (peek('=', GE, GT));
	case '<':
		return (peek('=', LE, LT));
	case '=':
		return (peek('=', EQ, EQ));
	case '|':
		return (peek('|', OROR, '|'));
	case '&':
		return (peek('&', ANDAND, '&'));
	case '!':
		return (peek('=', NE, '!'));
	default: {
		int	base;

		evalval = 0;

		if (*pe == '0') {
			if (*++pe == 'x' || *pe == 'X') {
				base = 16;
				++pe;
			} else
				base = 8;
		} else
			base = 10;

		for (;;) {
			int	c, dig;

			c = *pe;

			if (is_digit(c))
				dig = c - '0';
			else if (c >= 'a' && c <= 'f')
				dig = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F')
				dig = c - 'A' + 10;
			else
				break;

			evalval = evalval*base + dig;
			++pe;
		}
		return (DIGITS);
	}
	}
}

static int
peek(int c, int r1, int r2)
{
	if (*++pe != c)
		return (r2);
	++pe;
	return (r1);
}

/*ARGSUSED*/
static void
yyerror(YYCONST char *msg)
{
}
