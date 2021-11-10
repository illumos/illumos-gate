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
/*	Copyright (c) 1989 AT&T	*/
/*	  All Rights Reserved	*/


#include <stdio.h>

#ifdef EUC
#include <euc.h>
#include <widec.h>
#include <limits.h>
#endif


#ifndef JLSLEX
#pragma weak yyinput
#pragma weak yyleng
#pragma weak yytext
#pragma weak yyunput

#define	CHR    char
#define	YYTEXT yytext
#define	YYLENG yyleng
#define	YYINPUT yyinput
#define	YYUNPUT yyunput
#define	YYOUTPUT yyoutput
#define	YYREJECT yyreject
#endif

#ifdef WOPTION
#pragma weak yyinput
#pragma weak yyleng
#pragma weak yytext
#pragma weak yyunput

#define	CHR    wchar_t
#define	YYTEXT yytext
#define	YYLENG yyleng
#define	YYINPUT yyinput
#define	YYUNPUT yyunput
#define	YYOUTPUT yyoutput
#define	YYREJECT yyreject_w
#endif

#ifdef EOPTION
#pragma weak yyleng
#pragma weak yytext
#pragma weak yywinput
#pragma weak yywleng
#pragma weak yywtext
#pragma weak yywunput

#define	CHR    wchar_t
#define	YYTEXT yywtext
#define	YYLENG yywleng
#define	YYINPUT yywinput
#define	YYUNPUT yywunput
#define	YYOUTPUT yywoutput
#define	YYREJECT yyreject_e
extern unsigned char yytext[];
extern int yyleng;
#endif

#pragma weak yyback
extern int	yyback(int *, int);
extern int	YYINPUT(void);
extern void	YYUNPUT(int);
#ifdef EUC
	static int	yyracc(int);
#else
	extern int	yyracc(int);
#endif
#ifdef EOPTION
	extern size_t	wcstombs(char *, const wchar_t *, size_t);
#endif

#pragma weak yyout
extern FILE *yyout, *yyin;

#pragma weak yyfnd
#pragma weak yyprevious
extern int yyprevious, *yyfnd;

#pragma weak yyextra
extern char yyextra[];

extern int YYLENG;
extern CHR YYTEXT[];

#pragma weak yylsp
#pragma weak yylstate
#pragma weak yyolsp
extern struct {int *yyaa, *yybb; int *yystops; } *yylstate[], **yylsp, **yyolsp;

int
YYREJECT(void)
{
	for (; yylsp < yyolsp; yylsp++)
		YYTEXT[YYLENG++] = YYINPUT();
	if (*yyfnd > 0)
		return (yyracc(*yyfnd++));
	while (yylsp-- > yylstate) {
		YYUNPUT(YYTEXT[YYLENG-1]);
		YYTEXT[--YYLENG] = 0;
		if (*yylsp != 0 && (yyfnd = (*yylsp)->yystops) && *yyfnd > 0)
			return (yyracc(*yyfnd++));
	}
#ifdef EOPTION
	yyleng = wcstombs((char *)yytext, YYTEXT, YYLENG*MB_LEN_MAX);
#endif
	if (YYTEXT[0] == 0)
		return (0);
	YYLENG = 0;
#ifdef EOPTION
	yyleng = 0;
#endif
	return (-1);
}

int
yyracc(int m)
{
	yyolsp = yylsp;
	if (yyextra[m]) {
		while (yyback((*yylsp)->yystops, -m) != 1 && yylsp > yylstate) {
			yylsp--;
			YYUNPUT(YYTEXT[--YYLENG]);
		}
	}
	yyprevious = YYTEXT[YYLENG-1];
	YYTEXT[YYLENG] = 0;
#ifdef EOPTION
	yyleng = wcstombs((char *)yytext, YYTEXT, YYLENG*MB_LEN_MAX);
#endif
	return (m);
}
