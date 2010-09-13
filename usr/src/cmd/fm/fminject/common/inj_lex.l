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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <inj.h>
#include <inj_lex.h>
#include <inj_string.h>
#include <inj_event.h>
#include <inj_grammar.h>

int yynerrors;
const char *yyinname;

%}

/*
 * S0 is for normal input processing.  SCOMMENT is used to process comments.
 * We need a separate state for comments to prevent the lex regexp engine from
 * overflowing its own buffers as it searches for the end of comments.
 */
%s		S0 SCOMMENT

RGX_IMM_SEQ	-?([0-9]+|0[xX][0-9A-Fa-f]+)
RGX_STR_SEQ	([^"\\\n]|\\[^"\n]|\\\")*
RGX_IDENT	[a-zA-Z][a-zA-Z0-9\-_]*

%%

<S0>"/*"		{ BEGIN(SCOMMENT); }
<SCOMMENT>.|\n		; /* discard */
<SCOMMENT>"*/"		{ BEGIN(S0); }

<S0>evdef		{ return (INJ_TOK_EVDEF); }
<S0>fmridef		{ return (INJ_TOK_FMRIDEF); }
<S0>authdef		{ return (INJ_TOK_AUTHDEF); }
<S0>listdef		{ return (INJ_TOK_LISTDEF); }

<S0>int8_t		{ return (INJ_TOK_INT8); }
<S0>int16_t		{ return (INJ_TOK_INT16); }
<S0>int32_t		{ return (INJ_TOK_INT32); }
<S0>int64_t		{ return (INJ_TOK_INT64); }
<S0>uint8_t		{ return (INJ_TOK_UINT8); }
<S0>uint16_t		{ return (INJ_TOK_UINT16); }
<S0>uint32_t		{ return (INJ_TOK_UINT32); }
<S0>uint64_t		{ return (INJ_TOK_UINT64); }
<S0>boolean		{ return (INJ_TOK_BOOLEAN); }
<S0>boolean_t		{ return (INJ_TOK_BOOLEAN); }
<S0>string		{ return (INJ_TOK_STRING); }
<S0>enum		{ return (INJ_TOK_ENUM); }

<S0>event		{ return (INJ_TOK_EVENT); }
<S0>fmri		{ return (INJ_TOK_FMRI); }
<S0>auth		{ return (INJ_TOK_AUTH); }
<S0>list		{ return (INJ_TOK_LIST); }

<S0>addhrtime		{ return (INJ_TOK_ADDHRT); }
<S0>endhrtime		{ return (INJ_TOK_ENDHRT); }
<S0>sleep		{ return (INJ_TOK_SLEEP); }
<S0>repeat		{ return (INJ_TOK_REPEAT); }
<S0>randomize		{ return (INJ_TOK_RANDOMIZE); }

<S0>\"{RGX_STR_SEQ}$	{ yyerror("syntax error: \" unmatched"); }

<S0>\"{RGX_STR_SEQ}\" {
		/* Quoted string */
		yylval.l_string = inj_strndup(yytext + 1, yyleng - 2);
		return (INJ_TOK_QSTRING);
	}

<S0>{RGX_IDENT}("."{RGX_IDENT})+ {
		yylval.l_string = inj_strdup(yytext);
		return (INJ_TOK_FMACLASS);
	}

<S0>{RGX_IDENT}	{
		yylval.l_string = inj_strdup(yytext);
		return (INJ_TOK_IDENT);
	}

<S0>{RGX_IMM_SEQ} {
		yylval.l_string = inj_strdup(yytext);
		return (INJ_TOK_IMM);
	}

<S0>[ \t\n]		;	/* Ignore whitespace */

.			{ return (yytext[0]); }

%%

void
yyerror(const char *format, ...)
{
	int err = errno;
	va_list ap;
	char *s;

	/* Don't print the line number if the message begins with a space */
	if (*format == ' ') {
		(void) fprintf(stderr, "%s: ", yyinname, yylineno);
		format++;
	} else
		(void) fprintf(stderr, "%s: %d: ", yyinname, yylineno);

	va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);

	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, " near \"%s\"\n", yytext);

	yynerrors++;
	errno = err;
}

int
yywrap(void)
{
	return (1);
}

void
yyreset(void)
{
	BEGIN(S0);
}
