%{
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * A scanner for SAM Media Manager Protocol
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cfg_yacc.h>

#undef	YYSTYPE
#define		YYSTYPE		mms_stype_t

#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>


/*
 * Redine yylex to accept a pointer to the work area
 */
#undef	YY_DECL
#define		YY_DECL	int yylex(YYSTYPE *lvalp, void *wka)

#define		SAVE_TOKEN(src) {					\
		int	index = (mms_pwka->par_wka_token_index++) % 2;	\
		int	len;						\
		if ((len = strlen(src)) > MMS_PAR_MAX_TOKEN) {		\
			len = MMS_PAR_MAX_TOKEN;			\
		}							\
		strlcpy(mms_pwka->par_wka_token[index], src,		\
		    MMS_PAR_MAX_TOKEN);					\
		lvalp->str = mms_pwka->par_wka_token[index];		\
	}



%}

%option noyywrap debug prefix = "mms_cfg_"
%x prolog comment

DIGIT		[+-]*[0-9]+
DECNUM		(\"[\+-]*[0-9]+\")|('[\+-]*[0-9]+')
WORD		[a-zA-Z][a-zA-Z0-9_]*
STRING		(\"[^"]*\")|(\'[^']*\')
BADSTRING	(\"[^"]*)|(\'[^']*)


%%

\<\!--		{
			BEGIN(comment);
		}
<comment>--\>	{
			BEGIN(INITIAL);
		}
<comment>\n	{
			mms_pwka->par_wka_line++;
			mms_pwka->par_wka_col = 1;
		}
<comment>.	{
			mms_pwka->par_wka_col++;
		}
\<\?		{
			BEGIN(prolog);
		}
<prolog>\?>	{
			BEGIN(INITIAL);
		}
<prolog>\n	{
			mms_pwka->par_wka_line++;
			mms_pwka->par_wka_col = 1;
		}
<prolog>.	{
			mms_pwka->par_wka_col++;
		}

"\<\/"		{
			mms_pwka->par_wka_col += yyleng;
			return (LT_SLASH);
		}
"/>"		{
			mms_pwka->par_wka_col += yyleng;
			return (SLASH_GT);
		}
\<\?[^?]*\?>	{
			;
		}
{DECNUM}	{
			yytext[yyleng - 1] = '\0';
			if (yyleng - 2 > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(yytext + 1);
			mms_pwka->par_wka_col += yyleng;
			return (NUMERIC);
		}

{WORD}		{
			mms_sym_t  *syment = NULL;
			if (yyleng > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(yytext);
			mms_pwka->par_wka_col += yyleng;
			if (strcmp(yytext, "mms_cfg") == 0) {
				return (MMS_CFG);
			} else if (strcmp(yytext, "lm_cfg") == 0) {
				return (LM_CFG);
			} else if (strcmp(yytext, "dm_cfg") == 0) {
				return (DM_CFG);
			} else {
				return (KEYWORD);
			}
		}

{STRING}	{
			mms_sym_t  *syment = NULL;
			char   *text;
			/* Remove the enclosing quotes */
			yytext[yyleng - 1] = '\0';
			text = mms_par_xml_escape_to_char(yytext + 1);
			if (text == NULL) {
				mms_par_error(mms_pwka, "Out of memory");
				return (NO_MEM);
			}
			if (strlen(text) > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(text);
			free(text);
			mms_pwka->par_wka_col += yyleng;
			return (STRING);
		}
{BADSTRING}	{
			mms_par_error(mms_pwka, "No ending quote");
			return (NO_ENDING_QUOTE);
		}
\xfe		{
			mms_par_error(mms_pwka, "Input function returned "
			    "too many characters");
			return (INCORRECT_INPUT_SIZE);
		}
" "|\t		{
			mms_pwka->par_wka_col++; /* discard white spaces */
		}
\n		{
			mms_pwka->par_wka_line++;
			mms_pwka->par_wka_col = 1;
		}
.		{
			mms_pwka->par_wka_col++;
			SAVE_TOKEN(yytext);
			return (yytext[0]);
		}


%%

static YY_BUFFER_STATE	buffer;

void
mms_cfg_scan_string(char *str)
{
	buffer = yy_scan_string(str);
}

void
mms_cfg_delete_buffer()
{
	yy_delete_buffer(buffer);
}
