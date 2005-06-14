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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <string.h>

#include <regexpr.h>

#include "iconv_tm.h"
#include "itmcomp.h"
#include "y.tab.h"

static itm_data_t	*hexadecimal_data(int, char *);
static itm_data_t	*name_data(int, char *);
static void		filename_lineno(void);
static int		at_name_to_token(char *);


%}

%start	norm comment

DECIMAL		([0-9]+)
OCTAL		(0[0-7][0-7]+)
HEXADECIMAL	(("0x"|"0X")([0-9A-Fa-f])+)
ITMNAME		(([^% \t\n\r])+"%"([^% \t\n\r])+)
ATNAME		"@"([0-9A-Za-z_]+)
NAME		([A-Za-z_][A-Za-z0-9_]*)
MAPTYPE_NAME	(automatic|dense|index|hash|binary)

%%

[ \t\n]+	;
"//".*"\n"	;

^"#"[ \t]*{DECIMAL}[ \t]*"\"".*"\"".*"\n" {
			filename_lineno();
		}

^"#".*"\n"	{
			if (NULL == cmd_opt.preprocess) {
				itm_error(
				gettext("warning: "
					"preprocess may be required\n"));
			}
		}

{DECIMAL}	{
			yylval.num = strtoul(yytext, (char **)NULL, 10);
			return (DECIMAL);
		}

{OCTAL}		{	yylval.num = strtoul(yytext, (char **)NULL, 8);
			return (DECIMAL);
		}

{HEXADECIMAL}	{	yylval.data = hexadecimal_data(yyleng - 2, yytext + 2);
			return (HEXADECIMAL);
		}

{ITMNAME}	{	yylval.data = str_to_data(yyleng, yytext);
			return (ITMNAME);
		}

{ATNAME}	{	return at_name_to_token(yytext);
		}

{MAPTYPE_NAME}	{	yylval.num = at_name_to_token(yytext);
			yylval.data = name_data(yyleng, yytext);
			return (MAPTYPE_NAME);

		}

{NAME}		{	yylval.num = at_name_to_token(yytext);
			if (0 != yylval.num) {
				return (yylval.num);
			} else {
				yylval.data = name_data(yyleng, yytext);
				return (NAME);
			}
		}


"{"		{return (CBO);}
"}"		{return (CBC);}
"["		{return (SBO);}
"]"		{return (SBC);}
"("		{return (PO);}
")"		{return (PC);}
";"		{return (SC);}
","		{return (COMMA);}
":"		{return (COLON);}
"..."		{return (ELLIPSES);}


"="		{return (ASSIGN);}
"||"		{return (LOR);}
"&&"		{return (LAND);}
"|"		{return (OR);}
"^"		{return (XOR);}
"&"		{return (AND);}
"=="		{return (EQ);}
"!="		{return (NE);}
"<"		{return (LT);}
"<="		{return (LE);}
">"		{return (GT);}
">="		{return (GE);}
"<<"		{return (SHL);}
">>"		{return (SHR);}
"+"		{return (PLUS);}
"-"		{return (MINUS);}
"*"		{return (MUL);}
"/"		{return (DIV);}
"%"		{return (MOD);}
"!"		{return (NOT);}
"~"		{return (NEG);}

.		{	itm_error(
				gettext("Unrecognized token '%1$c' \n"),
				cmd_opt.my_name, yytext[0]);
			return (0);
		}

%%

/*
 * lexinit - starts the Lexical Analyzer off in the right start condition
 */
void
lexinit()
{
	BEGIN norm;
}

/* does this really need to be here? */
int
yywrap()
{
	return (1);
}

void
yyerror(char *s)
{
	extern int	yylineno;

	itm_error(
		gettext("%1$s: file(%2$s) line(%3$d) last token(%4$s)\n"),
		s, itm_input_file, yylineno, yytext);

	exit(ITMC_STATUS_BT);
}

typedef struct {
	char	*name;
	int	token;
} at_name_token_t;

/*
 * NOT: This table must be sorted alphabetically.
 */
static at_name_token_t at_table[] = {
	"@automatic",	MAPTYPE_AUTO,
	"@binary",	MAPTYPE_BINARY,
	"@between",	BETWEEN,
	"@condition",	CONDITION,
	"@default",	ITM_DEFAULT,
	"@dense",	MAPTYPE_DENSE,
	"@direction",	DIRECTION,
	"@discard",	DISCARD,
	"@else",	ITM_ELSE,
	"@error",	ERROR,
	"@escapeseq",	ESCAPESEQ,
	"@false",	ITM_FALSE,
	"@hash",	MAPTYPE_HASH,
	"@identical",	ITM_IDENTICAL,
	"@if",		ITM_IF,
	"@in",		ITM_IN,
	"@index",	MAPTYPE_INDEX,
	"@init",	ITM_INIT,
	"@input",	ITM_IN,
	"@inputsize",	ITM_INSIZE,
	"@map",		MAP,
	"@maptype",	MAPTYPE,
	"@no_change_copy",	ITM_IDENTICAL,
	"@nop",		NOP,
	"@operation",	OPERATION,
	"@out",		ITM_OUT,
	"@output",	ITM_OUT,
	"@output_byte_length",	RESULTLEN,
	"@outputsize",	ITM_OUTSIZE,
	"@printchr",	PRINTCHR,
	"@printhd",	PRINTHD,
	"@printint",	PRINTINT,
	"@reset",	RESET,
	"@resultlen",	RESULTLEN,
	"@return",	RETURN,
	"@true",	ITM_TRUE,
	"automatic",	MAPTYPE_AUTO,
	"between",	BETWEEN,
	"binary",	MAPTYPE_BINARY,
	"break",	BREAK,
	"condition",	CONDITION,
	"default",	ITM_DEFAULT,
	"dense",	MAPTYPE_DENSE,
	"direction",	DIRECTION,
	"discard",	DISCARD,
	"else",		ITM_ELSE,
	"error",	ERROR,
	"escapeseq",	ESCAPESEQ,
	"false",	ITM_FALSE,
	"hash",		MAPTYPE_HASH,
	"if",		ITM_IF,
	"index",	MAPTYPE_INDEX,
	"init",		ITM_INIT,
	"input",	ITM_IN,
	"inputsize",	ITM_INSIZE,
	"map",		MAP,
	"maptype",	MAPTYPE,
	"no_change_copy",	ITM_IDENTICAL,
	"nop",		NOP,
	"operation",	OPERATION,
	"output",	ITM_OUT,
	"output_byte_length",	RESULTLEN,
	"outputsize",	ITM_OUTSIZE,
	"printchr",	PRINTCHR,
	"printhd",	PRINTHD,
	"printint",	PRINTINT,
	"reset",	RESET,
	"return",	RETURN,
	"true",		ITM_TRUE,
};

int
at_name_to_token(char *s)
{
	int	high;
	int	mid;
	int	low;
	int	result;

	TRACE_MESSAGE('l', ("at_name_to_token: %s", s));
	for (low = 0, high = (sizeof (at_table) /
				sizeof (at_name_token_t));
	    low < high; /* NOP */) {
		mid = (low + high) / 2;
		result = strcmp(s, at_table[mid].name);
		if (result < 0) {
			high = mid;
		} else if (0 < result) {
			low = mid + 1;
		} else { /* 0 == result */
			TRACE_MESSAGE('l', (" %d\n", at_table[mid].token));
			return (at_table[mid].token);
		}
	}
	TRACE_MESSAGE('l', (" - not found\n"));
	return (0);
}

static itm_data_t *
hexadecimal_data(int seqsize, char *seq)
{
	itm_data_t	*data;
	char		*binary;
	int		i, j;
	int		val;
	int		high;
	int		low;
	int		size;

	/* size is assured to be multiple of 2 */
	assert(seqsize != 0);
	size = seqsize + 1;
	size /= 2;
	if (size > MAXSEQUENCE) {
		itm_error(
		gettext(" specified sequence must be less than %$1d\n"),
		MAXSEQUENCE);
		return (NULL);
	}
	binary = malloc_vital(size);
	i = j = 0;
	if (seqsize % 2 != 0) {
		low =  *(seq);
		if (('0' <= low) && (low <= '9')) {
			val = (low - '0');
		} else if (('a' <= low) && (low <= 'f')) {
			val = (low - 'a' + 10);
		} else if (('A' <= low) && (low <= 'F')) {
			val = (low - 'A' + 10);
		}
		*(binary + i) = val;
		i++;
		j++;
	}
	for (/* NOP */; i < size; i++, j += 2) {
		high = *(seq + j);
		low =  *(seq + j + 1);
		if (('0' <= high) && (high <= '9')) {
			val = ((high - '0') << 4);
		} else if (('a' <= high) && (high <= 'f')) {
			val = ((high - 'a' + 10) << 4);
		} else if (('A' <= high) && (high <= 'F')) {
			val = ((high - 'A' + 10) << 4);
		}
		if (('0' <= low) && (low <= '9')) {
			val |= (low - '0');
		} else if (('a' <= low) && (low <= 'f')) {
			val |= (low - 'a' + 10);
		} else if (('A' <= low) && (low <= 'F')) {
			val |= (low - 'A' + 10);
		}
		*(binary + i) = val;
	}

	data = malloc_vital(sizeof (itm_data_t));

	data->size = size;
	if (size <= sizeof (data->place)) {
		(void) memmove(&(data->place), binary, size);
		free(binary);
	} else {
		data->place.itm_ptr = (itm_place2_t)binary;
	}

	return (data);
}

static itm_data_t *
name_data(int size, char *seq)
{
	itm_data_t *data;


	if (size > MAXNAMELENGTH) {
		itm_error(gettext("the length(%d) exceed limitation(%d)"),
		size, MAXNAMELENGTH);
		exit(ITMC_STATUS_BT2);
	}
	data = malloc_vital(sizeof (itm_data_t));

	data->size = size;
	if (size <= sizeof (data->place)) {
		(void) memmove(&(data->place), seq, size);
	} else {
		data->place.itm_ptr = (itm_place2_t)malloc_vital(size);
		(void) memmove((char *)(data->place.itm_ptr), seq, size);
	}

	return (data);
}

static void
filename_lineno(void)
{
	static char	*re;
	static char	restr[] =
			"^#[ \t]*\\([0-9]\\{1,\\}\\)[ \t]*\"\\(.*\\)\".*";
	int		match;
	extern char	*braslist[];
	extern char	*braelist[];
	static char	*filename;
	int		len;
	int		lineno;

	if (NULL == re) {
		re = compile(restr, NULL, NULL);
		if (NULL == re) {
			itm_error(
				gettext("REGEXP compile error\n"));
			exit(ITMC_STATUS_BT);
		}
	}
	match = step(yytext, re);
	if (0 != match) {
		lineno = atoi(braslist[0]);
		free(filename);
		len = braelist[1] - braslist[1];
		filename = malloc_vital(len + 1);
		(void) memcpy(filename, braslist[1], len);
		*(filename + len) = '\0';
		itm_input_file = filename;
		yylineno = lineno;
	}
}
