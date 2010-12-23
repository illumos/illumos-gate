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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * HISTORY
 * Date		Developer	Comment
 * 5-13-96	Jerry Yeung	combine agent/config
 * 6-25-96      Jerry Yeung     trap handling
 * 7-03-96	Jerry Yeung	WatchDogTime,MaxPollInterval,MaxAgentTimeOut
 * 7-17-96	Jerry Yeung	change personal to registration_file
 */

/*
#define DEBUG_LEX printf("\tLEX: %s(%d) at line %d\n", yytext, yyval, yylineno);
*/
#define DEBUG_LEX


#define QUOTED_STRING_SIZE	300

static char quoted_string[QUOTED_STRING_SIZE];
static int token_value;

static void get_quoted_string();

%}

%%

#.*\n					{ ; }
[ \t\n]*				{ ; }
\"					{ get_quoted_string();
					  return QUOTEDSTRING;
					}

\{					{ DEBUG_LEX return OPENBRACKET; }
\}					{ DEBUG_LEX return CLOSEBRACKET; }
\.					{ DEBUG_LEX return DOT; }
=					{ DEBUG_LEX return EQUAL; }
\,					{ DEBUG_LEX return COMMA; }
\[					{ DEBUG_LEX return OPENSQUAREBRACKET; }
\]					{ DEBUG_LEX return CLOSESQUAREBRACKET; }
\-					{ DEBUG_LEX return MINUS; }

[0-9]+					{ DEBUG_LEX token_value = atoi(yytext);
					  return NUMBER;
					}

[mM][aA][cC][rR][oO][sS]		{ DEBUG_LEX return MACROS; }
[aA][gG][eE][nN][tT][sS]		{ DEBUG_LEX return AGENTS; }
[nN][aA][mM][eE]			{ DEBUG_LEX return NAME; }
[sS][uU][bB][tT][rR][eE][eE][sS]	{ DEBUG_LEX return SUBTREES; }
[tT][aA][bB][lL][eE][sS]		{ DEBUG_LEX return TABLES; }
[tT][aA][bB][lL][eE]			{ DEBUG_LEX return TABLE; }
[cC][oO][lL][uU][mM][nN][sS]		{ DEBUG_LEX return COLUMNS; }
[iI][nN][dD][eE][xX][sS]		{ DEBUG_LEX return INDEXS; }
[iI][nN][dD][eE][xX][eE][sS]		{ DEBUG_LEX return INDEXS; }
[tT][iI][mM][eE][oO][uU][tT]		{ DEBUG_LEX return TIMEOUT; }
[pP][oO][rR][tT]			{ DEBUG_LEX return PORT; }
[wW][aA][tT][cC][hH][-_][dD][o0][gG][-_][tT][iI][mM][eE] 	{ DEBUG_LEX return WATCHDOGTIME; }
[pP][oO][lL][lL][-_][iI][nN][tT][eE][rR][vV][aA][lL] { DEBUG_LEX return POLLINTERVAL; }
[mM][aA][xX][-_][aA][gG][eE][nN][tT][-_][tT][iI][mM][eE][oO][uU][tT] { DEBUG_LEX return MAXAGENTTIMEOUT; }
[eE][nN][vV][iI][rR][oO][nN][mM][eE][nN][tT] 	{ DEBUG_LEX return ENVIRONMENT; }

[cC][oO][mM][mM][uU][nN][iI][tT][iI][eE][sS] { DEBUG_LEX return COMMUNITIES; }
[rR][eE][aA][dD][-_][oO][nN][lL][yY]     { DEBUG_LEX return READONLY; }
[rR][eE][aA][dD][-_][wW][rR][iI][tT][eE] { DEBUG_LEX return READWRITE; }
[mM][aA][nN][aA][gG][eE][rR][sS]        { DEBUG_LEX return MANAGERS; }
[tT][rR][aA][pP] { DEBUG_LEX return TRAP; }
[tT][rR][aA][pP][-_][nN][uU][mM] { DEBUG_LEX return TRAPNUM; }
[tT][rR][aA][pP][-_][cC][oO][mM][mM][uU][nN][iI][tT][yY] { DEBUG_LEX return TRAPCOMMUNITY; }
[tT][rR][aA][pP][-_][rR][eE][cC][iI][pP][iI][eE][nN][tT][sS] { DEBUG_LEX return TRAPDESTINATORS; }

[aA][cC][lL]				{ DEBUG_LEX return ACL; }
[aA][cC][cC][eE][sS][sS]		{ DEBUG_LEX return ACCESS; }
[hH][oO][sS][tT][sS]                    { DEBUG_LEX return HOSTS; }

[rR][eE][gG][iI][sS][tT][rR][aA][tT][iI][oO][nN][-_][fF][iI][lL][eE] { DEBUG_LEX	return REGISTRATION_FILE; }

[sS][eE][cC][uU][rR][iI][tT][yY] { DEBUG_LEX return SECURITY; }
[pP][oO][lL][iI][cC][yY] { DEBUG_LEX return POLICY; }
[tT][yY][pP][eE]	{ DEBUG_LEX return TYPE; }
[uU][sS][eE][rR]	{ DEBUG_LEX return USER; }
[cC][oO][mM][mM][aA][nN][dD] { DEBUG_LEX return COMMAND; }
[rR][eE][sS][oO][uU][rR][cC][eE] { DEBUG_LEX return RESOURCE; }
[dD][iI][rR][eE][cC][tT][oO][rR][yY] { DEBUG_LEX return DIRECTORY; }

mib-2					{ DEBUG_LEX return MIB2; }
sun					{ DEBUG_LEX return SUN; }
enterprise				{ DEBUG_LEX return ENTERPRISE; }

([a-zA-Z\*]|[\_\?\-0-9\*+$#%^@!|~&=`<>\\']*[a-zA-Z])[_0-9a-zA-Z-]*	{ DEBUG_LEX return IDENTIFIER; }

.					{ error_exit("syntax error in %s at line %d: the token %s is not valid",
						config_file_4_res, yylineno, yytext);
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


