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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"



#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "gram.h"
#include "rdb.h"
%}

ws		[ \t]+
nl		\n
symbol		[_a-zA-Z][_a-zA-Z0-9]*
varstring	\$[_a-zA-Z][_a-zA-Z0-9]*	/* $<name> */
hexnumber	0[xX][0-9a-zA-Z]+
decnumber	[0-9]+
qstring		\"[^\"\n]*[\"\n]

%%
\#[^\n]*		;	/* igore comments */
\\\n			;	/* perform line continuation... */
{ws}			;	/* ignore whitespace */
{hexnumber}		{yylval.addr = hexstr_to_num(yytext); return (NUMBER);}
{decnumber}		{yylval.addr = atoi(yytext); return (NUMBER);}
\+			{return (PLUS);}
^{ws}*break		{return (BREAK);}
^{ws}*cont		{return (CONT);}
^{ws}*echo		{return (ECHO_OUT);}
^{ws}*event		{return (EVENT);}
^{ws}*delete		{return (DELETE);}
^{ws}*dis		{return (DIS);}
^{ws}*getmaps		{return (GETMAPS);}
^{ws}*help		{return (HELP);}
^{ws}*linkmaps		{return (LINKMAPS);}
^{ws}*maps		{return (MAPS);}
^{ws}*objpad		{return (OBJPAD);}
^{ws}*pltskip		{return (PLTSKIP);}
^{ws}*print		{return (PRINT);}
^{ws}*step		{return (STEP);}
^{ws}*value		{return (VALUE);}
^{ws}*where		{return (WHERE);}
{symbol}		{yylval.str = strdup(yytext); return (SYMBOL);}
{varstring}		{
				yylval.str = strdup(yytext + 1);
				return (VARSTRING);
			}
{qstring}		{
				yylval.str = strdup(yytext + 1);
				if (yylval.str[yyleng - 2] == '"')
					yylval.str[yyleng - 2] = '\0';
				return (QSTRING);
			}
{nl}			{return (NEWLINE);}
%%
