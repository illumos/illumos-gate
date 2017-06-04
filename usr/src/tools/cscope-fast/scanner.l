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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *	cscope - interactive C symbol cross-reference
 *
 *
 *	C symbol scanner
 */
#ident	"@(#)scanner.l	1.2	93/06/07 SMI"
#include "global.h"

/* the line counting has been moved from character reading for speed */
/* comments are discarded */
#undef	input
#define	input() \
	((yytchar = (yytchar = yysptr > yysbuf ? \
	    *--yysptr : getc(yyin)) == '/' ? comment() : yytchar) == \
	    EOF ? 0 : toascii(yytchar))
#define	noncommentinput() \
	((yytchar = yysptr > yysbuf ? *--yysptr : getc(yyin)) == \
	    EOF ? 0 : yytchar)
#undef	unput
#define	unput(c) (*yysptr++ = (c))

/* not a preprocessor line (allow Ingres(TM) "## char var;" lines) */
#define	notpp()	(ppdefine == NO && (*yytext != '#' || yytext[1] == '#'))

#define	IFLEVELINC	5	/* #if nesting level size increment */

/* keyword text for fast testing of keywords in the scanner */
extern	char	externtext[];
extern	char	typedeftext[];

int	first;	/* buffer index for first char of symbol */
int	last;	/* buffer index for last char of symbol */
int	lineno;	/* symbol line number */

static	BOOL	arraydimension;		/* inside array dimension declaration */
static	BOOL	bplisting;		/* breakpoint listing */
static	int	braces;			/* unmatched left brace count */
static	int	cesudeftoken;		/* class/enum/struct/union definition */
static	BOOL	classdef;		/* c++ class definition */
static	BOOL	elseelif;		/* #else or #elif found */
static	BOOL	esudef;			/* enum/struct/union definition */
static	int	esubraces;		/* outermost enum/struct/union */
					/* brace count */
static	BOOL	externdec;		/* extern declaration */
static	BOOL	fcndef;			/* function definition */
static	BOOL	globalscope;		/* file global scope */
					/* (outside functions) */
static	int	iflevel;		/* #if nesting level */
static	BOOL	initializer;		/* data initializer */
static	int	initializerbraces;	/* data initializer outer brace count */
static	BOOL	lex;			/* lex file */
static	BOOL	localdef;		/* function/block local definition */
static	int	miflevel = IFLEVELINC;	/* maximum #if nesting level */
static	int	*maxifbraces;		/* maximum brace count within #if */
static	int	*preifbraces;		/* brace count before #if */
static	int	parens;			/* unmatched left parenthesis count */
static	BOOL	ppdefine;		/* preprocessor define statement */
static	BOOL	psuedoelif;		/* psuedo-#elif */
static	BOOL	oldtype;		/* next identifier is an old type */
static	BOOL	rules;			/* lex/yacc rules */
static	BOOL	sdl;			/* SDL file */
static	BOOL	structfield;		/* structure field declaration */
static	BOOL	template;		/* function template */
static	int	templateparens;	/* function template outer parentheses count */
static	BOOL	typedefdef;	/* typedef name definition */
static	BOOL	typedefname;	/* typedef name use */
static	int	token;		/* token found */

static	BOOL	asy;			/* assembly file */

void multicharconstant(char terminator);
int do_assembly(int token);
%}
identifier	[a-zA-Z_][a-zA-Z_0-9]*
number		\.?[0-9][.0-9a-fA-FlLuUxX]*
%start SDL
%a 6000
%o 11000
%p 3000
%%
%\{		{	/* lex/yacc C declarations/definitions */
			globalscope = YES;
			goto more;
			/* NOTREACHED */
		}
%\}		{
			globalscope = NO;
			goto more;
			/* NOTREACHED */
		}
^%%		{	/* lex/yacc rules delimiter */
			braces = 0;
			if (rules == NO) {
				rules = YES;

				/* simulate a yylex() or yyparse() definition */
				(void) strcat(yytext, " /* ");
				first = strlen(yytext);
				if (lex == YES) {
					(void) strcat(yytext, "yylex");
				} else {
					/*
					 * yacc: yyparse implicitly calls yylex
					 */
					char *s = " yylex()";
					char *cp = s + strlen(s);
					while (--cp >= s) {
						unput(*cp);
					}
					(void) strcat(yytext, "yyparse");
				}
				last = strlen(yytext);
				(void) strcat(yytext, " */");
				yyleng = strlen(yytext);
				yymore();
				return (FCNDEF);
			} else {
				rules = NO;
				globalscope = YES;
				last = first;
				yymore();
				return (FCNEND);
			}
			/* NOTREACHED */
		}
<SDL>(PROCEDURE|STATE)[ \t]+({identifier}|\*)	{ /* SDL procedure or state */
			braces = 1;
			fcndef = YES;	/* treat as function definition */
			token = FCNDEF;
			globalscope = NO;
			goto findident;
			/* NOTREACHED */
		}
<SDL>(CALL|NEXTSTATE)[ \t]+({identifier}|\*)	{ /* SDL call or nextstate */
			token = FCNCALL;
			goto findident;	/* treat as function call */
			/* NOTREACHED */
		}
<SDL>END(PROCEDURE|STATE)[ \t]+({identifier}|\*)	{
			/* end of an SDL procedure or state */
			goto endstate;	/* treat as the end of a function */
			/* NOTREACHED */
		}
\{		{
			/* count unmatched left braces for fcn def detection */
			++braces;

			/*
			 * mark an untagged enum/struct/union so its beginning
			 * can be found
			 */
			if (cesudeftoken) {
				last = first;
				savesymbol(cesudeftoken);
				cesudeftoken = '\0';
			}
			goto more;
			/* NOTREACHED */
		}
\#[ \t]*endif/.*[\n\r][ \t\n\r]*#[ \t]*if	{
			/*
			 * attempt to correct erroneous brace count caused by:
			 *
			 * #if ...
			 * 	... {
			 * #endif
			 * #if ...
			 * 	... {
			 * #endif
			 */
			/* the current #if must not have an #else or #elif */
			if (elseelif == YES) {
				goto endif;
			}
			psuedoelif = YES;
			goto more;
			/* NOTREACHED */
		}
\#[ \t]*ifn?(def)?	{ /* #if, #ifdef or #ifndef */
			elseelif = NO;
			if (psuedoelif == YES) {
				psuedoelif = NO;
				goto elif;
			}
			/*
			 * make sure there is room for the current brace count
			 */
			if (iflevel == miflevel) {
				miflevel += IFLEVELINC;
				maxifbraces = myrealloc(maxifbraces,
				    miflevel * sizeof (int));
				preifbraces = myrealloc(preifbraces,
				    miflevel * sizeof (int));
			}
			/* push the current brace count */
			preifbraces[iflevel] = braces;
			maxifbraces[iflevel++] = 0;
			goto more;
			/* NOTREACHED */
		}
\#[ \t]*el(se|if)	{ /* #elif or #else */
			elseelif = YES;
		elif:
			if (iflevel > 0) {

				/* save the maximum brace count for this #if */
				if (braces > maxifbraces[iflevel]) {
					maxifbraces[iflevel - 1] = braces;
				}
				/* restore the brace count to before the #if */
				braces = preifbraces[iflevel - 1];
			}
			goto more;
			/* NOTREACHED */
		}
\#[ \t]*endif	{	/* #endif */
		endif:
			if (iflevel > 0) {

				/* get the maximum brace count for this #if */
				if (braces < maxifbraces[--iflevel]) {
					braces = maxifbraces[iflevel];
				}
			}
			goto more;
			/* NOTREACHED */
		}
\}		{
			/* could be the last enum member initializer */
			if (braces == initializerbraces) {
				initializerbraces = -1;
				initializer = NO;
			}
			if (--braces <= 0) {
		endstate:
				braces = 0;
				classdef = NO;
			}
			/*
			 * if the end of an outermost enum/struct/union
			 * definition
			 */
			if (esudef == YES && braces == esubraces) {
				esudef = NO;
				esubraces = -1;
				last = first;
				yymore();
				return (ESUEND);
			}
			/* if the end of a function */
			if ((braces == 0 || braces == 1 && classdef == YES) &&
			    fcndef == YES) {
				fcndef = NO;
				globalscope = YES;
				last = first;
				yymore();
				return (FCNEND);
			}
			goto more;
			/* NOTREACHED */
		}
\(		{
			/*
			 * count unmatched left parentheses for function
			 * templates
			 */
			++parens;
			goto more;
			/* NOTREACHED */
		}
\)		{
			if (--parens <= 0) {
				parens = 0;
			}
			/* if the end of a function template */
			if (parens == templateparens) {
				templateparens = -1;
				template = NO;
			}
			goto more;
			/* NOTREACHED */
		}
=		{	/* if a global definition initializer */
			if ((globalscope == YES || localdef == YES) &&
			    notpp()) {
				initializerbraces = braces;
				initializer = YES;
			}
			goto more;
			/* NOTREACHED */
		}
:		{	/* if a structure field */
			/* note: a pr header has a colon in the date */
			if (esudef == YES && notpp()) {
				structfield = YES;
			}
			goto more;
			/* NOTREACHED */
		}
\,		{
			if (braces == initializerbraces) {
				initializerbraces = -1;
				initializer = NO;
			}
			structfield = NO;
			goto more;
			/* NOTREACHED */
		}
"##"		|	/* start of Ingres(TM) code line */
;		{
			/* if not in an enum/struct/union declaration */
			if (esudef == NO) {
				externdec = NO;
				typedefdef = NO;
				localdef = NO;
			}
			structfield = NO;
			initializer = NO;
			oldtype = NO;
			goto more;
			/* NOTREACHED */
		}
\#[ \t]*define[ \t]+{identifier}	{

			/* preprocessor macro or constant definition */
			ppdefine = YES;
			token = DEFINE;
			if (compress == YES) {
				/* compress the keyword */
				yytext[0] = '\7';
			}
		findident:
			first = yyleng - 1;
			while (isalnum(yytext[first]) || yytext[first] == '_') {
				--first;
			}
			++first;
			goto iflongline;
			/* NOTREACHED */
		}
class[ \t]+{identifier}[ \t\n\ra-zA-Z0-9_():]*\{	{
			/* class definition */
			classdef = YES;
			cesudeftoken = 'c';
			REJECT;
			/* NOTREACHED */
		}
(enum|struct|union)/([ \t\n\r]+{identifier})?[ \t\n\r]*\{	{
			/* enum/struct/union definition */
			esudef = YES;
			if (esubraces < 0) {
				/* if outermost enum/struct/union */
				esubraces = braces;
			}
			cesudeftoken = *(yytext + first);
			goto iflongline;
			/* NOTREACHED */
		}
{identifier}/[ \t]*\(([ \t\n\ra-zA-Z0-9_*&[\]=,.]*|\([ \ta-zA-Z0-9_*[\],]*\))*\)[ \t\n\r()]*[:a-zA-Z_#{]	{

			/*
			 * warning: "if (...)" must not overflow yytext, so
			 * the content of function argument definitions is
			 * restricted, in particular parentheses are
			 * not allowed
			 */

			if (asy) {
				/*
				 * In assembly files, if it looks like
				 * a definition, pass it down as one and we'll
				 * take care of it later.
				 */
				token = FCNDEF;
				goto iflongline;
			}

			/* if a function definition */
			/*
			 * note: "#define a (b) {" and "#if defined(a)\n#"
			 * are not
			 */
			if (braces == 0 && notpp() && rules == NO ||
			    braces == 1 && classdef == YES) {
				fcndef = YES;
				token = FCNDEF;
				globalscope = NO;
				goto iflongline;
			}
			goto iffcncall;
			/* NOTREACHED */
		}
{identifier}/[ \t]*\(	{
			if (asy) {
				/*
				 * Macro calls can get here if they have
				 * arguments which contain %'s (i.e.,
				 * registers).
				 */
				token = FCNDEF;
				goto iflongline;
			}

			/* if a function call */
		iffcncall:
			if ((fcndef == YES || ppdefine == YES ||
			    rules == YES) && externdec == NO &&
			    (localdef == NO || initializer == YES)) {
				token = FCNCALL;
				goto iflongline;
			}
			if (template == NO && typedefdef == NO) {
				templateparens = parens;
				template = YES;
			}
			token = IDENT;
			goto iflongline;
			/* NOTREACHED */
		}
(\+\+|--)[ \t]*{identifier}	{	/* prefix increment or decrement */
			token = ASSIGNMENT;
			goto findident;
			/* NOTREACHED */
		}
{identifier}/[ \t]*(\+\+|--)	{	/* postfix increment or decrement */
			token = ASSIGNMENT;
			goto iflongline;
			/* NOTREACHED */
		}
\*[ \t]*{identifier}/[ \t]*[^a-zA-Z0-9_(+-][^+-]	{
			/* indirect assignment or dcl */
			while (!isalnum(yytext[first]) &&
			    yytext[first] != '_') {
				++first;
			}
			goto ident;
			/* NOTREACHED */
		}
{identifier}/[ \t\n\r]*(=[^=]|[-+*/%&^|]=|<<=|>>=)	{ /* assignment */
			if ((fcndef == YES || ppdefine == YES ||
			    rules == YES) && localdef == NO) {
				token = ASSIGNMENT;
				goto iflongline;
			}
			goto ident;
			/* NOTREACHED */
		}
{identifier}/[* \t\n\r]+[a-zA-Z0-9_]	{	/* possible typedef name use */
			if (notpp() && esudef == NO && fcndef == YES &&
			    typedefdef == NO && parens == 0) {
				char	c, *s = yytext + first - 1;

				while (--s >= yytext && (c = *s) != ';' &&
				    c != '{') {
					if (!isspace(c) && !isalpha(c)) {
						goto nottypedefname;
					}
				}
				typedefname = YES;
			}
		nottypedefname:
			/* skip the global/parameter/local tests */
			token = IDENT;
			goto iflongline;
			/* NOTREACHED */
		}
{identifier}	{
			struct	keystruct *p;
			char	*s;

		ident:	token = IDENT;
			if (notpp() && externdec == NO &&
			    arraydimension == NO && initializer == NO) {

				/* if an enum/struct/union member definition */
				if (esudef == YES) {
					if (structfield == NO) {
						token = MEMBERDEF;
					}
				} else if (typedefdef == YES && oldtype == NO) {
					/* if a typedef name */
					token = TYPEDEF;
				} else if (globalscope == YES &&
				    template == NO && oldtype == NO) {
					/* if a global definition */
					token = GLOBALDEF;
				} else if (fcndef == YES && braces == 0) {
					/* if a function parameter definition */
					token = PARAMETER;
				} else if (localdef == YES) {
					/* if a local definition */
					token = LOCALDEF;
				}
			}
		iflongline:
			/* if a long line */
			if (yyleng > STMTMAX) {
				int	c;

				/* skip to the end of the line */
				warning("line too long");
				while ((c = input()) != LEXEOF) {
					if (c == '\n') {
						unput(c);
						break;
					}
				}
			}
			/* truncate a long symbol */
			if (yyleng - first > PATLEN) {
				warning("symbol too long");
				yyleng = first + PATLEN;
				yytext[yyleng] = '\0';
			}

			yymore();

			if (asy) {
				int t;

				last = yyleng;
				t = do_assembly(token);
				if (t >= 0) {
					token = t;
					return (token);
				}

				goto end;
			}

			/* if a keyword */
			if ((p = lookup(yytext + first)) != NULL) {
				first = yyleng;
				s = p->text;

				/* if an extern declaration */
				if (s == externtext) {
					externdec = YES;
				} else if (s == typedeftext) {
					/* if a typedef name definition */
					typedefdef = YES;
					oldtype = YES;
				} else if (p->type == DECL && fcndef == YES &&
				    typedefdef == NO && parens == 0) {
					/* if a local definition */
					localdef = YES;
				} else if (templateparens == parens &&
				    template == YES) {
					/*
					 * keyword doesn't start a function
					 * template
					 */
					templateparens = -1;
					template = NO;
				} else {
					/*
					 * next identifier after typedef was
					 * a keyword
					 */
					oldtype = NO;
				}
				typedefname = NO;
			} else {	/* identifier */
				last = yyleng;

				/*
				 * if an enum/struct/union keyword preceded
				 * this ident.
				 */
				if (esudef == YES && cesudeftoken) {
					token = cesudeftoken;
					cesudeftoken = '\0';
				} else {
					oldtype = NO;
				}
				/* if a local definition using a typedef name */
				if (typedefname == YES) {
					localdef = YES;
				}
				typedefname = NO;
				return (token);
			}

		end:
			;
		}
\[		{	/* array dimension (don't worry about subscripts) */
			arraydimension = YES;
			goto more;
			/* NOTREACHED */
		}
\]		{
			arraydimension = NO;
			goto more;
			/* NOTREACHED */
		}
\\\n		{	/* preprocessor statement is continued on next line */
			goto eol;
			/* NOTREACHED */
		}
\n		{	/* end of the line */
			if (ppdefine == YES) {	/* end of a #define */
				ppdefine = NO;
				(void) yyless(yyleng - 1);	/* rescan \n */
				last = first;
				yymore();
				return (DEFINEEND);
			}
			/*
			 * skip the first 8 columns of a breakpoint listing
			 * line and skip the file path in the page header
			 */
			if (bplisting == YES) {
				int	c, i;

				switch (input()) {
				/* tab and EOF just fall through */
				case ' ':	/* breakpoint number line */
				case '[':
					for (i = 1; i < 8 && input() != LEXEOF;
					    ++i) {
					    /*EMPTY*/
					}
					break;
				case '.':	/* header line */
				case '/':
					/* skip to the end of the line */
					while ((c = input()) != LEXEOF) {
						if (c == '\n') {
							unput(c);
							break;
						}
					}
					break;
				case '\n':	/* empty line */
					unput('\n');
					break;
				}
			}
		eol:
			++yylineno;
			first = 0;
			last = 0;
			if (symbols > 0) {
				return (NEWLINE);
			}
			lineno = yylineno;
		}
\'		{	/* character constant */
			if (sdl == NO) {
				multicharconstant('\'');
			}
			goto more;
			/* NOTREACHED */
		}
\"		{	/* string constant */
			multicharconstant('"');
			goto more;
			/* NOTREACHED */
		}
^[ \t\f\b]+	{	/* don't save leading white space */
		}
\#[# \t]*include[ \t]*["<][^"> \t\n\r]+	{ /* #include or Ingres ##include */
			char	*s;

			s = strpbrk(yytext, "\"<");
			incfile(s + 1, *s);
			first = s - yytext;
			last = yyleng;
			if (compress == YES) {
				/* compress the keyword */
				yytext[0] = '\1';
			}
			/*
			 * avoid multicharconstant call triggered by trailing
			 * ", which puts a trailing comment in the database
			 */
			if (*s == '"') {
				int	c;

				while ((c = input()) != LEXEOF) {
					if (c == '"') {
						yytext[yyleng] = '"';
						yytext[++yyleng] = '\0';
						break;
					}
					/* the trailing '"' may be missing */
					if (c == '\n') {
						unput('\n');
						break;
					}
				}
			}
			yymore();
			return (INCLUDE);
			/* NOTREACHED */
		}
\#[ \t]*pragma[ \t]+weak[ \t]+{identifier} {
			ppdefine = YES;
			token = DEFINE;
			goto findident;

			/*NOTREACHED*/
		}
\#[ \t]*{identifier}	|	/* preprocessor keyword */
{number}	|	/* number */
.		{	/* punctuation and operators */
		more:	first = yyleng;
			yymore();
		}
%%

void
initscanner(char *srcfile)
{
	char	*s;

	if (maxifbraces == NULL) {
		maxifbraces = mymalloc(miflevel * sizeof (int));
		preifbraces = mymalloc(miflevel * sizeof (int));
	}
	first = 0;		/* buffer index for first char of symbol */
	last = 0;		/* buffer index for last char of symbol */
	lineno = 1;		/* symbol line number */
	yylineno = 1;		/* input line number */
	arraydimension = NO;	/* inside array dimension declaration */
	bplisting = NO;		/* breakpoint listing */
	braces = 0;		/* unmatched left brace count */
	cesudeftoken = '\0';	/* class/enum/struct/union definition */
	classdef = NO;		/* c++ class definition */
	elseelif = NO;		/* #else or #elif found */
	esudef = NO;		/* enum/struct/union definition */
	esubraces = -1;		/* outermost enum/struct/union brace count */
	externdec = NO;		/* extern declaration */
	fcndef = NO;		/* function definition */
	globalscope = YES;	/* file global scope (outside functions) */
	iflevel = 0;		/* #if nesting level */
	initializer = NO;	/* data initializer */
	initializerbraces = -1;	/* data initializer outer brace count */
	lex = NO;		/* lex file */
	localdef = NO;		/* function/block local definition */
	parens = 0;		/* unmatched left parenthesis count */
	ppdefine = NO;		/* preprocessor define statement */
	psuedoelif = NO;	/* psuedo-#elif */
	oldtype = NO;		/* next identifier is an old type */
	rules = NO;		/* lex/yacc rules */
	sdl = NO;		/* SDL file */
	structfield = NO;	/* structure field declaration */
	template = NO;		/* function template */
	templateparens = -1;	/* function template outer parentheses count */
	typedefdef = NO;	/* typedef name definition */
	typedefname = NO;	/* typedef name use */
	asy = NO;		/* assembly file */
	BEGIN 0;

	/* if this is not a C file */
	if ((s = strrchr(srcfile, '.')) != NULL) {
		switch (*++s) {	/* this switch saves time on C files */
		case 'b':
			if (strcmp(s, "bp") == 0) {	/* breakpoint listing */
				bplisting = YES;
			}
			break;
		case 'l':
			if (strcmp(s, "l") == 0) {	/* lex */
				lex = YES;
				globalscope = NO;
			}
			break;
		case 'p':
		case 's':
			if (strcmp(s, "pr") == 0 ||
			    strcmp(s, "sd") == 0) {	/* SDL */
				sdl = YES;
				BEGIN SDL;
			} else if (strcmp(s, "s") == 0) {
				asy = YES;
			}
			break;
		case 'y':
			if (strcmp(s, "y") == 0) {	/* yacc */
				globalscope = NO;
			}
			break;
		}
	}
}

int
comment(void)
{
	int	c, lastc;

	do {
		if ((c = getc(yyin)) == '*') {	/* C comment */
			lastc = '\0';
			while ((c = getc(yyin)) != EOF &&
			    (c != '/' || lastc != '*')) { /* fewer '/'s */
				if (c == '\n') {
					++yylineno;
				}
				lastc = c;
			}
			/* return a blank for Reiser cpp token concatenation */
			if ((c = getc(yyin)) == '_' || isalnum(c)) {
				(void) ungetc(c, yyin);
				c = ' ';
				break;
			}
		} else if (c == '/') {		/* C++ comment */
			while ((c = getc(yyin)) != EOF && c != '\n') {
				/*EMPTY*/
			}
			break;
		} else {	/* not a comment */
			(void) ungetc(c, yyin);
			c = '/';
			break;
		}

		/* there may be an immediately following comment */
	} while (c == '/');
	return (c);
}

void
multicharconstant(char terminator)
{
	char	c;

	/* scan until the terminator is found */
	while ((c = yytext[yyleng++] = noncommentinput()) != terminator) {
		switch (c) {
		case '\\':	/* escape character */
			if ((yytext[yyleng++] = noncommentinput()) == '\n') {
				++yylineno;
			}
			break;
		case '\t':	/* tab character */

			/* if not a lex program, continue */
			if (lex == NO) {
				break;
			}
			/* FALLTHROUGH */

		case '\n':	/* illegal character */

			/*
			 * assume the terminator is missing, so put
			 * this character back
			 */
			unput(c);
			yytext[--yyleng] = '\0';
			/* FALLTHROUGH */

		case LEXEOF:	/* end of file */
			return;

		default:
			/* change a control character to a blank */
			if (!isprint(c)) {
				yytext[yyleng - 1] = ' ';
			}
		}
		/* if this token will overflow the line buffer */
		/* note: '\\' may cause yyleng to be > STMTMAX */
		if (yyleng >= STMTMAX) {

			/* truncate the token */
			while ((c = noncommentinput()) != LEXEOF) {
				if (c == terminator) {
					unput(c);
					break;
				} else if (c == '\n') {
					++yylineno;
				}
			}
		}
	}
	yytext[yyleng] = '\0';
}

/*
 * Returns true if the beginning of str matches ident, and the next character
 * is not alphanumeric and not an underscore.
 */
int
identcmp(const char *str, const char *ident)
{
	int n = strlen(ident);

	return (strncmp(str, ident, n) == 0 && !isalnum(str[n]) &&
	    str[n] != '_');
}

/*
 * Here we want to
 *   - Make *ENTRY*() macro invocations into function definitions
 *   - Make SET_SIZE() macro calls into function ends
 *   - Make "call sym" instructions into function calls
 *   - Eliminate C function definitions (since they are for lint, and we want
 *     only one definition for each function)
 */
int
do_assembly(int token)
{
	/* Handle C keywords? */

	switch (token) {

	case FCNDEF:
		/*
		 * We have a symbol that looks like a C function definition or
		 * call.  (Note: That can include assembly instructions with
		 * the right parentheses.)  We want to convert assembly macro
		 * invocations to function calls, and ignore everything else.
		 * Since we technically can't tell the difference, we'll use
		 * an all-caps heuristic.
		 *
		 * ... except for SET_SIZE macros, since they will precede
		 * FUNCEND tokens, which will break code in find.c which
		 * assumes that FUNCEND tokens occur at the beginning of
		 * lines.
		 */
		if (isupper(yytext[first]) && strcmp(yytext, "SET_SIZE") != 0)
			return (FCNCALL);

		/* Don't return a token. */
		return (-1);

	case GLOBALDEF:
	case IDENT:
		/* Macro arguments come down as global variable definitions. */

		if (identcmp(yytext, "ENTRY") ||
		    identcmp(yytext, "ENTRY2") ||
		    identcmp(yytext, "ENTRY_NP") ||
		    identcmp(yytext, "ENTRY_NP2") ||
		    identcmp(yytext, "RTENTRY") ||
		    identcmp(yytext, "ALTENTRY")) {
			/*
			 * Identifiers on lines beginning with *ENTRY* macros
			 * are actually function definitions.
			 */
			return (FCNDEF);
		}

		if (identcmp(yytext, "SET_SIZE")) {
			/*
			 * Identifiers on lines beginning with SET_SIZE are
			 * actually function ends.
			 */
			return (FCNEND);
		}

		if (first != 0 && identcmp(yytext, "call")) {
			/*
			 * Make this a function call.  We exclude first == 0,
			 * because that happens when we're looking at "call"
			 * itself.  (Then we'd get function calls to "call"
			 * everywhere.)
			 */
			return (FCNCALL);
		}

		/* FALLTHROUGH */

	default:
		/* Default to normal behavior. */
		return (token);
	}
}
