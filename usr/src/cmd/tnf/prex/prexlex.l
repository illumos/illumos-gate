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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
%}

%a 10000
%o 10000

%{
#include "spec.h"
#include "expr.h"
#include "y.tab.h"
#include <stdlib.h>
#include <string.h>

char *	qtstr		(char *		instr);
char *	rgstr		(char *		instr);

/*
** we substitute i/o routines defined in main.c for the
** standard fare.  This allows us to support the "source"
** function by redirecting the input stream from different
** places
*/
#include "source.h"
#undef input
#undef unput
#undef output
#define	input()		source_input()
#define	unput(c)	source_unput(c)
#define	output(c)	source_output(c)
%}

IDFIRST			[a-zA-Z_\.%]
IDCHAR			({IDFIRST}|[0-9])
ID			{IDFIRST}{IDCHAR}*

%%

#.*			;		/* eat comments */
[ \t]+			;		/* eats whitespace */

\n			{ source_nl(); return NL; }
\\\n			{ source_nl(); } /* escaped newline */
=			return (EQ);
\,			return (COMMA);

add			{ yylval.intval = ADD; return (ADD); }
alloc			{ yylval.intval = ALLOC; return (ALLOC); }
buffer			{ yylval.intval = BUFFER; return (BUFFER); }
clear			{ yylval.intval = CLEAR; return (CLEAR); }
connect			{ yylval.intval = CONNECT; return (CONNECT); }
continue		{ yylval.intval = CONTINUE; return (CONTINUE); }
create			{ yylval.intval = CREATE; return (CREATE); }
dealloc			{ yylval.intval = DEALLOC; return (DEALLOC); }
delete			{ yylval.intval = DELETE; return (DELETE); }
disable			{ yylval.intval = DISABLE; return (DISABLE); }
enable			{ yylval.intval = ENABLE; return (ENABLE); }
fcns			{ yylval.intval = FCNS; return (FCNS); }
filter			{ yylval.intval = FILTER; return (FILTER); }
help			{ yylval.intval = HELP; return (HELP); }
history			{ yylval.intval = HISTORY; return (HISTORY); }
tracefile		{ yylval.intval = TRACEFILE; return (TRACEFILE); }
kill			{ yylval.intval = KILL; return (KILL); }
ktrace			{ yylval.intval = KTRACE; return (KTRACE); }
list			{ yylval.intval = LIST; return (LIST); }
off			{ yylval.intval = OFF; return (OFF); }
on			{ yylval.intval = ON; return (ON); }
pfilter			{ yylval.intval = PFILTER; return (PFILTER); }
probes			{ yylval.intval = PROBES; return (PROBES); }
quit			{ yylval.intval = QUIT; return (QUIT); }
resume			{ yylval.intval = RESUME; return (RESUME); }
sets			{ yylval.intval = SETS; return (SETS); }
source			{ yylval.intval = SOURCE; return (SOURCE); }
suspend			{ yylval.intval = SUSPEND; return (SUSPEND); }
trace			{ yylval.intval = TRACE; return (TRACE); }
untrace			{ yylval.intval = UNTRACE; return (UNTRACE); }
values			{ yylval.intval = VALUES; return (VALUES); }

${ID}			{ yylval.strval = strdup(&yytext[1]); return SETNAME; }
&{ID}			{ yylval.strval = strdup(&yytext[1]); return FCNNAME; }
{ID}			{ yylval.strval = strdup(yytext); return IDENT; }
\'[^'\n]*\'		{ yylval.strval = qtstr(yytext); return VALSTR; }

\/([^/\\\n]|\\.)*\/	{ yylval.strval = rgstr(yytext); return REGEXP; }

[0-9]+[KkMm]?		{
				char scale = yytext[yyleng - 1];
				yylval.intval = atoi(yytext);
				if (scale == 'k' || scale == 'K')
					yylval.intval *= 1024;
				else if (scale == 'm' || scale == 'M')
					yylval.intval *= 1024 * 1024;
				return (SCALED_INT);
			}

.			return (INVAL);	/* barf on anything else */

%%

/****************************************************************
qtstr() - shucks a quoted str, and copies it into new memory
****************************************************************/

char *
qtstr		(char *		instr)
{
	char	*ptr;
	int	indx;

	/* skip the leading quote in the copy */
	ptr = strdup(&instr[1]);

	/* null out the trailing quote */
	indx = strlen(ptr) - 1;
	indx = (indx < 0) ? 0 : indx;
	ptr[indx] = '\0';

	return ptr;
}   /* end qtstr */


/****************************************************************
rgstr() - shucks a decorated regular expression, and copies it
into new memory
****************************************************************/

char *
rgstr		(char *		instr)
{
	char	*ptr;
	int	indx;

	/* skip the leading slash in the copy */
	ptr = strdup(&instr[1]);

	/* null out the trailing slash */
	indx = strlen(ptr) - 1;
	indx = (indx < 0) ? 0 : indx;
	ptr[indx] = '\0';

	return (ptr);

}   /* end rgstr */


