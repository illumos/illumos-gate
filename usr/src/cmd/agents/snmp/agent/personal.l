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
 * Copyright 1998 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
#define DEBUG_LEX printf("\tLEX: %s(%d) at line %d\n", yytext, yyval, yylineno);
*/
#define DEBUG_LEX


#define QUOTED_STRING_SIZE	100

static int lex_bug4163217 = 1;
static char quoted_string[QUOTED_STRING_SIZE];
static int token_value;

static void get_quoted_string();

%}

%%

#.*\n					{ ; }
[ \t\n]*				{ ; }
\"					{ get_quoted_string();
					  if (lex_bug4163217) return QUOTEDSTRING;
					}

\{					{ DEBUG_LEX if (lex_bug4163217) return OPENBRACKET; }
\}					{ DEBUG_LEX if (lex_bug4163217) return CLOSEBRACKET; }
\.					{ DEBUG_LEX if (lex_bug4163217) return DOT; }
=					{ DEBUG_LEX if (lex_bug4163217) return EQUAL; }
\,					{ DEBUG_LEX if (lex_bug4163217) return COMA; }
\[					{ DEBUG_LEX if (lex_bug4163217) return OPENSQUAREBRACKET; }
\]					{ DEBUG_LEX if (lex_bug4163217) return CLOSESQUAREBRACKET; }
\-					{ DEBUG_LEX if (lex_bug4163217) return MINUS; }

[0-9]+					{ DEBUG_LEX token_value = atoi(yytext);
					  if (lex_bug4163217) return NUMBER;
					}

[mM][aA][cC][rR][oO][sS]		{ DEBUG_LEX if (lex_bug4163217) return MACROS; }
[aA][gG][eE][nN][tT][sS]		{ DEBUG_LEX if (lex_bug4163217) return AGENTS; }
[nN][aA][mM][eE]			{ DEBUG_LEX if (lex_bug4163217) return NAME; }
[sS][uU][bB][tT][rR][eE][eE][sS]	{ DEBUG_LEX if (lex_bug4163217) return SUBTREES; }
[tT][aA][bB][lL][eE][sS]		{ DEBUG_LEX if (lex_bug4163217) return TABLES; }
[tT][aA][bB][lL][eE]			{ DEBUG_LEX if (lex_bug4163217) return TABLE; }
[cC][oO][lL][uU][mM][nN][sS]		{ DEBUG_LEX if (lex_bug4163217) return COLUMNS; }
[iI][nN][dD][eE][xX][sS]		{ DEBUG_LEX if (lex_bug4163217) return INDEXS; }
[iI][nN][dD][eE][xX][eE][sS]		{ DEBUG_LEX if (lex_bug4163217) return INDEXS; }
[tT][iI][mM][eE][oO][uU][tT]		{ DEBUG_LEX if (lex_bug4163217) return TIMEOUT; }
[pP][oO][rR][tT]			{ DEBUG_LEX if (lex_bug4163217) return PORT; }
[wW][aA][tT][cC][hH][-_][dD][o0][gG][-_][tT][iI][mM][eE]        { DEBUG_LEX if (lex_bug4163217) return WATCHDOGTIME; }

[cC][oO][mM][mM][uU][nN][iI][tT][iI][eE][sS] { DEBUG_LEX if (lex_bug4163217) return COMMUNITIES; }
[rR][eE][aA][dD][-][oO][nN][lL][yY]     { DEBUG_LEX if (lex_bug4163217) return READONLY; }
[rR][eE][aA][dD][-][wW][rR][iI][tT][eE] { DEBUG_LEX if (lex_bug4163217) return READWRITE; }
[mM][aA][nN][aA][gG][eE][rR][sS]        { DEBUG_LEX if (lex_bug4163217) return MANAGERS; }
[tT][rR][aA][pP] { DEBUG_LEX if (lex_bug4163217) return TRAP; }
[tT][rR][aA][pP][-][nN][uU][mM] { DEBUG_LEX if (lex_bug4163217) return TRAPNUM; }
[tT][rR][aA][pP][-][cC][oO][mM][mM][uU][nN][iI][tT][yY] { DEBUG_LEX if (lex_bug4163217) return TRAPCOMMUNITY; }
[tT][rR][aA][pP][-][rR][eE][cC][iI][pP][iI][eE][nN][tT][sS] { DEBUG_LEX if (lex_bug4163217) return TRAPDESTINATORS; }

[aA][cC][lL]				{ DEBUG_LEX if (lex_bug4163217) return ACL; }
[aA][cC][cC][eE][sS][sS]                { DEBUG_LEX if (lex_bug4163217) return ACCESS; } 
[hH][oO][sS][tT][sS]			{ DEBUG_LEX if (lex_bug4163217) return HOSTS; }

mib-2					{ DEBUG_LEX if (lex_bug4163217) return MIB2; }
sun					{ DEBUG_LEX if (lex_bug4163217) return SUN; }
enterprise				{ DEBUG_LEX if (lex_bug4163217) return ENTERPRISE; }

[a-zA-Z\*][_a-zA-Z0-9-]*			{ DEBUG_LEX if (lex_bug4163217) return IDENTIFIER; }

.					{ error_exit("syntax error in %s at line %d: the token %s is not valid",
						current_filename, yylineno, yytext);
					}


%%

#undef input
#undef unput
#undef output

/*
# define input() (((yytchar=yysptr>yysbuf?U(*--yysptr):getc(yyin))==10?(yylineno++,yytchar):yytchar)==EOF?0:yytchar)
# define unput(c) {yytchar= (c);if(yytchar=='\n')yylineno--;*yysptr++=yytchar;}
# define output(c) (void)putc(c,yyout)
*/

#define input() (((yytchar=*lexinput++)=='\n'?(yylineno++,yytchar):yytchar)==EOF?0:yytchar)
#define unput(c) {yytchar= (c); if(yytchar=='\n')yylineno--;*--lexinput = yytchar;}
#define output(c)

/*************************************************************************/

static void get_quoted_string()
{
	int i = 0;
	int c;


	c = input();
	while( (c != 0) && (c != '"') )
	{
		if(c == '\n')
		{
			error_exit("syntax error at line %d: can not have a \\n in a quoted string", yylineno);
		}

		if(i < QUOTED_STRING_SIZE - 1)
		{
			quoted_string[i++] = c;
		}

		c = input();
	}
	quoted_string[i] = '\0';

	if(c == 0)
	{
		error_exit("syntax error at line %d: have not found a quote before the end of file", yylineno);
	}
}


