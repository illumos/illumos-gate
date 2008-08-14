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


#include <thread.h>
#include <synch.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/int_types.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_par_impl.h>

#define		YYPARSE_PARAM	wka
#define		YYLEX_PARAM	wka
#define		YYERROR_VERBOSE	1

#undef	YYSTYPE
#define		YYSTYPE	mms_stype_t

int	yylex(YYSTYPE *lvalp, void *wka);

#define		mms_cfg_error(msg)	{				\
		mms_par_error(mms_pwka, msg);				\
		if (mms_pwka->par_wka_err_count >= MMS_PE_MAX) {	\
			mms_par_error(mms_pwka, "Too many errors");	\
			YYABORT;					\
		}							\
	}

mms_sym_t	mms_cfg_tab[] = {
	"mms_cfg",			MMS_CFG,
};
mms_sym_t	*mms_config_symtab = mms_cfg_tab;
int	mms_num_config_syms = sizeof (mms_cfg_tab) / sizeof (mms_sym_t);



%}

%name-prefix = "mms_cfg_"
%defines
%pure_parser

%token	TOKEN_MIN

%token	MMS_CFG LM_CFG DM_CFG KEYWORD STRING NUMERIC LT_SLASH SLASH_GT
%token	ERR_TOKEN_TOO_BIG NO_ENDING_QUOTE NO_MEM INCORRECT_INPUT_SIZE
%token	NULL_STRING

%token	TOKEN_MAX


%%

/*
 * MMS cfg file
 */

mms_cfg
	: L config_name R section_content_list LS config_name_spec R
		{
			mms_list_move_tail(&$2.nodep->pn_arglist, $4.listp);
			if (strcmp(mms_pn_token($2.nodep), $6.str)) {
				char    msg[200];
				sprintf(msg, "Unexpected tag \"%s\", "
				    "expecting \"%s\"", $6.str,
				    mms_pn_token($2.nodep));
				yyerror(msg);
				YYERROR;
			}
			$$.nodep = $2.nodep;
		}
	;

section	: L section_name R section_content_list LS KEYWORD R
		{
			mms_list_move_tail(&$2.nodep->pn_arglist, $4.listp);
			if (strcmp(mms_pn_token($2.nodep), $6.str)) {
				char    msg[200];
				sprintf(msg, "Unexpected tag \"%s\", "
				    "expecting \"%s\"", $6.str,
				    mms_pn_token($2.nodep));
				yyerror(msg);
				YYERROR;
			}
			$$.nodep = $2.nodep;
		}
	;

section_content_list
	: section_content
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_list_insert_tail($$.listp, $1.nodep);
		}
	| section_content_list section_content
		{
			mms_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

section_content
	: section
	| L option_name attr_list SR
		{
			mms_list_move_tail(&$2.nodep->pn_arglist, $3.listp);
			$$.nodep = $2.nodep;
		}
	;


attr_list
	: attr
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_list_insert_tail($$.listp, $1.nodep);
		}
	| attr_list attr
		{
			mms_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

attr	: cfg_keyword '=' value
		{
			mms_list_insert_tail(&$1.nodep->pn_arglist, $3.nodep);
			$$.nodep = $1.nodep;
		}
	;

value	: string
	| number
	;

option_name
	: KEYWORD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_OPTION);
		}
	;

config_name
	: config_name_spec
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_CONFIG);
		}
	;

config_name_spec
	: MMS_CFG | LM_CFG | DM_CFG
	;

section_name
	: KEYWORD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_SECTION);
		}
	;

cfg_keyword
	: KEYWORD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

string	: STRING
		{
			if (strlen($1.str) == 0) {
				yyerror("Null string");
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_STRING);
		}
	;

number	: NUMERIC
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
			    MMS_PN_NUMERIC | MMS_PN_STRING);
		}
	;

L	: '<'
	;

R	: '>'
	;

LS	: LT_SLASH
	;

SR	: SLASH_GT
	;

%%
