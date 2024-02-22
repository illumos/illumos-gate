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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include "gnu_msgfmt.h"
#include "gnu_lex.h"

static int	plural_index;

%}

%union {
	char	*str;
	int	num;
	struct entry	msg;
	struct ch	c;
}

%token	<num> DOMAIN
%token	<num> MSGID
%token	<num> MSGID_PLURAL
%token	<num> MSGSTR
%token	<num> NUM
%token	<str> STR
%token	<str> COMMENT
%token	<str> SYMBOL
%token	<c>	CHR
%type	<msg> message_string plural_messages plural_message
%%

start	:
	| start po
	;

po	: comment
	| domain
	| body
	;

domain	: DOMAIN STR
	{
		handle_domain($2);
	}
	;

comment	: COMMENT
	{
		handle_comment($1);
	}

body	: MSGID message_string MSGSTR message_string
	{
		struct entry	och1, och2;

		och1.no = 1;
		och1.num = $1;
		och1.str = $2.str;
		och1.len = $2.len;
		och1.pos = NULL;

		och2.no = 1;
		och2.num = $3;
		och2.str = $4.str;
		och2.len = $4.len;
		och2.pos = NULL;

		handle_message(&och1, &och2);
		clear_state();
	}
	| MSGID message_string MSGID_PLURAL
		message_string {plural_index = 0;} plural_messages
	{
		size_t	len;
		struct entry	och1, och2;
		struct loc	*pos1;
		char	*id_str;

		len = $2.len + $4.len;
		id_str = (char *)Xmalloc(len);
		(void) memcpy(id_str, $2.str, $2.len);
		(void) memcpy(id_str + $2.len, $4.str, $4.len);
		free($2.str);
		free($4.str);

		pos1 = (struct loc *)Xmalloc(2 * sizeof (struct loc));
		pos1[0].off = 0;
		pos1[0].len = $2.len;
		pos1[0].num = $1;
		pos1[1].off = $2.len;
		pos1[1].len = $4.len;
		pos1[1].num = $3;
		och1.no = 2;
		och1.num = $1;
		och1.str = id_str;
		och1.len = len;
		och1.pos = pos1;

		och2 = $6;
		handle_message(&och1, &och2);
		clear_state();
	}
	| MSGID message_string
	{
		error(gettext(ERR_NO_MSGSTR), $1, cur_po);
		/* NOTREACHED */
	}
	| MSGID message_string MSGID_PLURAL message_string
	{
		error(gettext(ERR_NO_MSGSTRS), $1, cur_po);
		/* NOTRECHED */
	}
	| MSGID message_string plural_messages
	{
		error(gettext(ERR_NO_MSGID_PLURAL), $1, cur_po);
		/* NOTREACHED */
	}
	;

message_string	: STR
	{
		$$.str = $1;
		$$.len = strlen($1) + 1;
	}
	| message_string STR
	{
		size_t	len, len1, len2;
		char	*str;

		/* $1.len includes null-termination */
		len1 = $1.len - 1;
		len2 = strlen($2);

		/* len doesn't include null-termination */
		len = len1 + len2;

		str = (char *)Xmalloc(len + 1);
		(void) memcpy(str, $1.str, len1);
		(void) memcpy(str + len1, $2, len2 + 1);
		free($1.str);
		free($2);
		$$.str = str;
		$$.len = len + 1;
	}
	;

plural_messages	: plural_message
	{
		$$ = $1;
	}
	| plural_messages plural_message
	{
		struct loc	*tmp;
		size_t	len;
		char	*plural_str;
		int	no;

		no = $1.no + 1;
		tmp = (struct loc *)Xrealloc($1.pos,
			no * sizeof (struct loc));
		tmp[no - 1].off = $1.len;
		tmp[no - 1].len = $2.len;
		tmp[no - 1].num = $2.num;
		free($2.pos);

		len = $1.len + $2.len;
		plural_str = (char *)Xmalloc(len);
		(void) memcpy(plural_str, $1.str, $1.len);
		(void) memcpy(plural_str + $1.len, $2.str, $2.len);

		$$.no = no;
		$$.num = $1.num;
		$$.str = plural_str;
		$$.len = len;
		$$.pos = tmp;
		free($1.str);
		free($2.str);
	}
	;

plural_message	: MSGSTR '[' NUM ']' message_string
	{
		struct loc	*pos;
		if ($3 != plural_index) {
			error(gettext(ERR_INVALID_PLURALS), $1, cur_po);
			/* NOTREACHED */
		}
		plural_index++;
		pos = (struct loc *)Xmalloc(sizeof (struct loc));
		pos->off = 0;
		pos->len = $5.len;
		pos->num = $1;
		$$.no = 1;
		$$.num = $1;
		$$.str = $5.str;
		$$.len = $5.len;
		$$.pos = pos;
	}
	;
%%
int
yyerror(const char *err)
{
	(void) fprintf(stderr,
		gettext(ERR_LOCATION), cur_line, cur_po);
	(void) fprintf(stderr, "%s\n", err);

	exit(1);
}
