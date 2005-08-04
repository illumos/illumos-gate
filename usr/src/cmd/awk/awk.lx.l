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

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/
%}

%{
#pragma ident	"%Z%%M%	%I%	%E% SMI"
%}

%Start A str sc reg comment

%{

#include	<sys/types.h>
#include	"awk.h"
#include	"y.tab.h"

#undef	input	/* defeat lex */
#undef	unput

static void unput(int);
static void unputstr(char *);

extern YYSTYPE	yylval;
extern int	infunc;

off_t	lineno	= 1;
int	bracecnt = 0;
int	brackcnt  = 0;
int	parencnt = 0;
#define DEBUG
#ifdef	DEBUG
#	define	RET(x)	{if(dbg)printf("lex %s [%s]\n", tokname(x), yytext); return(x); }
#else
#	define	RET(x)	return(x)
#endif

/*
 * The standards (SUSV2) requires that Record size be atleast LINE_MAX.
 * LINE_MAX is a standard variable defined in limits.h.
 * Though nawk is not standards compliant, we let RECSIZE
 * grow with LINE_MAX instead of the magic number 1024.
 */
#define	CBUFLEN	(3 * LINE_MAX)

#define	CADD	cbuf[clen++] = yytext[0]; \
		if (clen >= CBUFLEN-1) { \
			ERROR "string/reg expr %.10s... too long", cbuf SYNTAX; \
			BEGIN A; \
		}

static uchar	cbuf[CBUFLEN];
static uchar	*s;
static int	clen, cflag;
%}

A	[a-zA-Z_]
B	[a-zA-Z0-9_]
D	[0-9]
O	[0-7]
H	[0-9a-fA-F]
WS	[ \t]

%%
	switch (yybgin-yysvec-1) {	/* witchcraft */
	case 0:
		BEGIN A;
		break;
	case sc:
		BEGIN A;
		RET('}');
	}

<A>\n		{ lineno++; RET(NL); }
<A>#.*		{ ; }	/* strip comments */
<A>{WS}+	{ ; }
<A>;		{ RET(';'); }

<A>"\\"\n	{ lineno++; }
<A>BEGIN	{ RET(XBEGIN); }
<A>END		{ RET(XEND); }
<A>func(tion)?	{ if (infunc) ERROR "illegal nested function" SYNTAX; RET(FUNC); }
<A>return	{ if (!infunc) ERROR "return not in function" SYNTAX; RET(RETURN); }
<A>"&&"		{ RET(AND); }
<A>"||"		{ RET(BOR); }
<A>"!"		{ RET(NOT); }
<A>"!="		{ yylval.i = NE; RET(NE); }
<A>"~"		{ yylval.i = MATCH; RET(MATCHOP); }
<A>"!~"		{ yylval.i = NOTMATCH; RET(MATCHOP); }
<A>"<"		{ yylval.i = LT; RET(LT); }
<A>"<="		{ yylval.i = LE; RET(LE); }
<A>"=="		{ yylval.i = EQ; RET(EQ); }
<A>">="		{ yylval.i = GE; RET(GE); }
<A>">"		{ yylval.i = GT; RET(GT); }
<A>">>"		{ yylval.i = APPEND; RET(APPEND); }
<A>"++"		{ yylval.i = INCR; RET(INCR); }
<A>"--"		{ yylval.i = DECR; RET(DECR); }
<A>"+="		{ yylval.i = ADDEQ; RET(ASGNOP); }
<A>"-="		{ yylval.i = SUBEQ; RET(ASGNOP); }
<A>"*="		{ yylval.i = MULTEQ; RET(ASGNOP); }
<A>"/="		{ yylval.i = DIVEQ; RET(ASGNOP); }
<A>"%="		{ yylval.i = MODEQ; RET(ASGNOP); }
<A>"^="		{ yylval.i = POWEQ; RET(ASGNOP); }
<A>"**="	{ yylval.i = POWEQ; RET(ASGNOP); }
<A>"="		{ yylval.i = ASSIGN; RET(ASGNOP); }
<A>"**"		{ RET(POWER); }
<A>"^"		{ RET(POWER); }

<A>"$"{D}+	{ yylval.cp = fieldadr(atoi(yytext+1)); RET(FIELD); }
<A>"$NF"	{ unputstr("(NF)"); return(INDIRECT); }
<A>"$"{A}{B}*	{ int c, n;
		  c = input(); unput(c);
		  if (c == '(' || c == '[' || infunc && (n=isarg(yytext+1)) >= 0) {
			unputstr(yytext+1);
			return(INDIRECT);
		  } else {
			yylval.cp = setsymtab((uchar *)yytext+1,
				(uchar *)"",0.0,STR|NUM,symtab);
			RET(IVAR);
		  }
		}
<A>"$"		{ RET(INDIRECT); }
<A>NF		{ yylval.cp = setsymtab((uchar *)yytext, (uchar *)"", 0.0, NUM, symtab); RET(VARNF); }

<A>({D}+("."?){D}*|"."{D}+)((e|E)("+"|-)?{D}+)?	{
		  yylval.cp = setsymtab((uchar *)yytext, tostring((uchar *)yytext), atof(yytext), CON|NUM, symtab);
		  RET(NUMBER); }

<A>while	{ RET(WHILE); }
<A>for		{ RET(FOR); }
<A>do		{ RET(DO); }
<A>if		{ RET(IF); }
<A>else		{ RET(ELSE); }
<A>next		{ RET(NEXT); }
<A>exit		{ RET(EXIT); }
<A>break	{ RET(BREAK); }
<A>continue	{ RET(CONTINUE); }
<A>print	{ yylval.i = PRINT; RET(PRINT); }
<A>printf	{ yylval.i = PRINTF; RET(PRINTF); }
<A>sprintf	{ yylval.i = SPRINTF; RET(SPRINTF); }
<A>split	{ yylval.i = SPLIT; RET(SPLIT); }
<A>substr	{ RET(SUBSTR); }
<A>sub		{ yylval.i = SUB; RET(SUB); }
<A>gsub		{ yylval.i = GSUB; RET(GSUB); }
<A>index	{ RET(INDEX); }
<A>match	{ RET(MATCHFCN); }
<A>in		{ RET(IN); }
<A>getline	{ RET(GETLINE); }
<A>close	{ RET(CLOSE); }
<A>delete	{ RET(DELETE); }
<A>length	{ yylval.i = FLENGTH; RET(BLTIN); }
<A>log		{ yylval.i = FLOG; RET(BLTIN); }
<A>int		{ yylval.i = FINT; RET(BLTIN); }
<A>exp		{ yylval.i = FEXP; RET(BLTIN); }
<A>sqrt		{ yylval.i = FSQRT; RET(BLTIN); }
<A>sin		{ yylval.i = FSIN; RET(BLTIN); }
<A>cos		{ yylval.i = FCOS; RET(BLTIN); }
<A>atan2	{ yylval.i = FATAN; RET(BLTIN); }
<A>system	{ yylval.i = FSYSTEM; RET(BLTIN); }
<A>rand		{ yylval.i = FRAND; RET(BLTIN); }
<A>srand	{ yylval.i = FSRAND; RET(BLTIN); }
<A>toupper	{ yylval.i = FTOUPPER; RET(BLTIN); }
<A>tolower	{ yylval.i = FTOLOWER; RET(BLTIN); }

<A>{A}{B}*	{ int n, c;
		  c = input(); unput(c);	/* look for '(' */
		  if (c != '(' && infunc && (n=isarg(yytext)) >= 0) {
			yylval.i = n;
			RET(ARG);
		  } else {
			yylval.cp = setsymtab((uchar *)yytext,
				(uchar *)"",0.0,STR|NUM,symtab);
			if (c == '(') {
				RET(CALL);
			} else {
				RET(VAR);
			}
		  }
		}
<A>\"		{ BEGIN str; clen = 0; }

<A>"}"		{ if (--bracecnt < 0) ERROR "extra }" SYNTAX; BEGIN sc; RET(';'); }
<A>"]"		{ if (--brackcnt < 0) ERROR "extra ]" SYNTAX; RET(']'); }
<A>")"		{ if (--parencnt < 0) ERROR "extra )" SYNTAX; RET(')'); }

<A>.		{ if (yytext[0] == '{') bracecnt++;
		  else if (yytext[0] == '[') brackcnt++;
		  else if (yytext[0] == '(') parencnt++;
		  RET(yylval.i = yytext[0]); /* everything else */ }

<reg>\\.	{ cbuf[clen++] = '\\'; cbuf[clen++] = yytext[1]; }
<reg>\n		{ ERROR "newline in regular expression %.10s...", cbuf SYNTAX; lineno++; BEGIN A; }
<reg>"/"	{ BEGIN A;
		  cbuf[clen] = 0;
		  yylval.s = tostring(cbuf);
		  unput('/');
		  RET(REGEXPR); }
<reg>.		{ CADD; }

<str>\"		{ BEGIN A;
		  cbuf[clen] = 0; s = tostring(cbuf);
		  cbuf[clen] = ' '; cbuf[++clen] = 0;
		  yylval.cp = setsymtab(cbuf, s, 0.0, CON|STR, symtab);
		  RET(STRING); }
<str>\n		{ ERROR "newline in string %.10s...", cbuf SYNTAX; lineno++; BEGIN A; }
<str>"\\\""	{ cbuf[clen++] = '"'; }
<str>"\\"n	{ cbuf[clen++] = '\n'; }
<str>"\\"t	{ cbuf[clen++] = '\t'; }
<str>"\\"f	{ cbuf[clen++] = '\f'; }
<str>"\\"r	{ cbuf[clen++] = '\r'; }
<str>"\\"b	{ cbuf[clen++] = '\b'; }
<str>"\\"v	{ cbuf[clen++] = '\v'; }	/* these ANSIisms may not be known by */
<str>"\\"a	{ cbuf[clen++] = '\007'; }	/* your compiler. hence 007 for bell */
<str>"\\\\"	{ cbuf[clen++] = '\\'; }
<str>"\\"({O}{O}{O}|{O}{O}|{O}) { int n;
		  sscanf(yytext+1, "%o", &n); cbuf[clen++] = n; }
<str>"\\"x({H}+) { int n;	/* ANSI permits any number! */
		  sscanf(yytext+2, "%x", &n); cbuf[clen++] = n; }
<str>"\\".	{ cbuf[clen++] = yytext[1]; }
<str>.		{ CADD; }

%%

void
startreg()
{
	BEGIN reg;
	clen = 0;
}

/* input() and unput() are transcriptions of the standard lex
   macros for input and output with additions for error message
   printing.  God help us all if someone changes how lex works.
*/

uchar	ebuf[300];
uchar	*ep = ebuf;

int
input(void)
{
	register int c;
	extern uchar *lexprog;

	if (yysptr > yysbuf)
		c = U(*--yysptr);
	else if (lexprog != NULL)	/* awk '...' */
		c = *lexprog++;
	else				/* awk -f ... */
		c = pgetc();
	if (c == '\n')
		yylineno++;
	else if (c == EOF)
		c = 0;
	if (ep >= ebuf + sizeof ebuf)
		ep = ebuf;
	return *ep++ = c;
}

static void
unput(int c)
{
	yytchar = c;
	if (yytchar == '\n')
		yylineno--;
	*yysptr++ = yytchar;
	if (--ep < ebuf)
		ep = ebuf + sizeof(ebuf) - 1;
}


static void
unputstr(char *s)
{
	int i;

	for (i = strlen(s)-1; i >= 0; i--)
		unput(s[i]);
}
