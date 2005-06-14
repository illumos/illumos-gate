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
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/***** DEFINES *****/

/*
#define DEBUG_LEX printf("\tLEX: %s(%d) at line %d\n", yytext, yyval, yylineno);
*/
#define DEBUG_LEX


/***** STATIC VARIABLES *****/

static int token_value;


%}

%%

#.*\n					{ ; }
[ \t\n]*				{ ; }

\{					{ DEBUG_LEX return OPENBRACKET; }
\}					{ DEBUG_LEX return CLOSEBRACKET; }
=					{ DEBUG_LEX return EQUAL; }
\,					{ DEBUG_LEX return COMA; }

[cC][oO][mM][mM][uU][nN][iI][tT][iI][eE][sS] { DEBUG_LEX return COMMUNITIES; }
[rR][eE][aA][dD][-][oO][nN][lL][yY]	{ DEBUG_LEX return READONLY; }
[rR][eE][aA][dD][-][wW][rR][iI][tT][eE]	{ DEBUG_LEX return READWRITE; }

[mM][aA][nN][aA][gG][eE][rR][sS]	{ DEBUG_LEX return MANAGERS; }

[tT][rR][aA][pP][-][cC][oO][mM][mM][uU][nN][iI][tT][yY] { DEBUG_LEX return TRAPCOMMUNITY; }
[tT][rR][aA][pP][-][rR][eE][cC][iI][pP][iI][eE][nN][tT][sS] { DEBUG_LEX return TRAPDESTINATORS; }

[a-zA-Z][_a-zA-Z0-9-]*			{ DEBUG_LEX return IDENTIFIER; }

.					{ error_exit("syntax error in %s at line %d: the token %s is not valid",
						config_file, yylineno, yytext);
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

