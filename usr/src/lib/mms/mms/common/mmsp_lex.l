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
#include <mmsp_yacc.h>

#undef	YYSTYPE
#define	YYSTYPE		mms_stype_t

#include <mms_list.h>
#include <mms_sym.h>
#include <mms_parser.h>
#include <mms_par_impl.h>


/*
 * Redefine yylex to accept a pointer to the work area
 */
#undef	YY_DECL
#define	YY_DECL	int yylex(YYSTYPE *lvalp, void *wka)

#define	SAVE_TOKEN(src) {						\
		int	index = (mms_pwka->par_wka_token_index++) % 2;	\
		int	len;						\
		if ((len = strlen(src)) > MMS_PAR_MAX_TOKEN) {		\
			len = MMS_PAR_MAX_TOKEN;			\
		}							\
		strncpy(mms_pwka->par_wka_token[index], src, len);	\
		mms_pwka->par_wka_token[index][len] = '\0';		\
		lvalp->str = mms_pwka->par_wka_token[index];		\
	}
%}

%option noyywrap
%option debug prefix = "mms_mmsp_"
%x prolog comment

DIGIT		([+-]*[0-9]+)
DECNUM		(([\+-]*[0-9]+)|([\+-]*[0-9]+))
DECNUM_STR	((\"[\+-]*[0-9]+\")|('[\+-]*[0-9]+'))
WORD		([a-zA-Z][a-zA-Z0-9_]*)
STRING		((\"[^"]*\")|(\'[^']*\'))
BADSTRING	((\"[^"]+)|(\'[^']+))
RANGE		(\.\.)
MMP_COMMENT	(#[^\n]*)


%%

{RANGE}		{
			SAVE_TOKEN(yytext);
			mms_pwka->par_wka_col += yyleng;
			return (RANGE);
		}

{DECNUM_STR}	{
			yytext[yyleng - 1] = '\0';
			if (yyleng - 2 > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(yytext + 1);
			mms_pwka->par_wka_col += yyleng;
			mms_pwka->par_wka_flags &= ~MMS_PW_KEYWORD;
			return (NUMERIC_STR);
		}

{DECNUM}	{
			if (yyleng > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(yytext);
			mms_pwka->par_wka_col += yyleng;
			mms_pwka->par_wka_flags &= ~MMS_PW_KEYWORD;
			return (NUMERIC);
		}

{WORD}		{
			mms_sym_t *syment = NULL;
			if (yyleng > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(yytext);
			mms_pwka->par_wka_col += yyleng;
			mms_pwka->par_wka_flags &= ~MMS_PW_KEYWORD;
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR_CODE) {
				/* Error code may be any word */
				mms_pwka->par_wka_flags &= ~MMS_PW_ERROR_CODE;
				return (ERROR_CODE);
			}
			syment = mms_par_lookup_sym(yytext, mms_pwka);
			if (syment == NULL) {
				return (UNKNOWN_KEYWORD);
			}
			return (syment->sym_code);
		}

{STRING}	{
			mms_sym_t *syment = NULL;

			/* Remove the enclosing quotes */
			yytext[yyleng - 1] = '\0';
			if (strlen(yytext + 1) > MMS_PAR_MAX_TOKEN) {
				mms_par_error(mms_pwka, "token size exceeded "
				    "MMS_PAR_MAX_TOKEN");
				return (ERR_TOKEN_TOO_BIG);
			}
			SAVE_TOKEN(yytext + 1);
			mms_pwka->par_wka_col += yyleng;
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR_CODE) {
				/* Error code may be any string */
				mms_pwka->par_wka_flags &= ~MMS_PW_ERROR_CODE;
				return (ERROR_CODE);
			}
			if (mms_pwka->par_wka_flags & MMS_PW_KEYWORD) {
				/* Looking for a keyword or an objectname */
				mms_pwka->par_wka_flags &= ~MMS_PW_KEYWORD;
				syment = mms_par_lookup_sym(lvalp->str,
				    mms_pwka);
				if (syment != NULL) {
					return (syment->sym_code);
				}
			}
			return (STRING);
		}

{BADSTRING}	{
			mms_par_error(mms_pwka, "No ending quote");
			mms_pwka->par_wka_flags &= ~MMS_PW_KEYWORD;
			return (NO_ENDING_QUOTE);
		}

\xfe		{
			mms_par_error(mms_pwka, "Input function returned "
			    "too many characters");
			return (INCORRECT_INPUT_SIZE);
		}

" "|\t|\r	{
			/* discard white spaces */
			mms_pwka->par_wka_col++;
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

static	YY_BUFFER_STATE	mmsp_buffer;

void
mms_mmsp_scan_string(char *str)
{
	mmsp_buffer = yy_scan_string(str);
}

void
mms_mmsp_delete_buffer()
{
	yy_delete_buffer(mmsp_buffer);
}
