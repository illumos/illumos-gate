%{
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * POSIX iconv charmap grammar.
 */

#include <wchar.h>
#include <stdio.h>
#include <limits.h>
#include "charmap.h"

extern int yylex(void);

%}
%union {
	char		*token;
	int		num;
	char		mbs[MB_LEN_MAX + 2]; /* NB: [0] is length! */
}

%token		T_CODE_SET
%token		T_MB_CUR_MAX
%token		T_MB_CUR_MIN
%token		T_COM_CHAR
%token		T_ESC_CHAR
%token		T_LT
%token		T_GT
%token		T_NL
%token		T_SEMI
%token		T_COMMA
%token		T_ELLIPSIS
%token		T_RPAREN
%token		T_LPAREN
%token		T_QUOTE
%token		T_NULL
%token		T_END
%token		T_CHARMAP
%token		T_WIDTH
%token		T_WIDTH_DEFAULT
%token	<mbs>		T_CHAR
%token	<token>		T_NAME
%token	<num>		T_NUMBER
%token	<token>		T_SYMBOL

%%

goal		: setting_list charmap
		| charmap
		;

string		: T_QUOTE charlist T_QUOTE
		| T_QUOTE T_QUOTE
		;

charlist	: charlist T_CHAR
		| T_CHAR
		;

setting_list	: setting_list setting
		| setting
		;

setting		: T_COM_CHAR T_CHAR T_NL
		{
			com_char = $2[1];
		}
		| T_ESC_CHAR T_CHAR T_NL
		{
			esc_char = $2[1];
		}
		| T_MB_CUR_MAX T_NUMBER T_NL
		{
			mb_cur_max = $2;
		}
		| T_MB_CUR_MIN T_NUMBER T_NL
		{
			mb_cur_min = $2;
		}
		| T_CODE_SET T_NAME T_NL
		{
			/* ignore */
		}
		| T_CODE_SET string T_NL
		{
			/* ignore */
		}
		;

charmap		: T_CHARMAP T_NL charmap_list T_END T_CHARMAP T_NL

charmap_list	: charmap_list charmap_entry
		| charmap_entry
		;

charmap_entry	: T_SYMBOL T_CHAR
		{
			add_charmap($1, $2);
			scan_to_eol();
		}
		| T_SYMBOL T_ELLIPSIS T_SYMBOL T_CHAR
		{
			add_charmap_range($1, $3, $4);
			scan_to_eol();
		}
		| T_NL
		;
