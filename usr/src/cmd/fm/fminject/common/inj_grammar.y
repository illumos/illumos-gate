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

/*
 * FMA Event Injector language parser
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <inj.h>
#include <inj_err.h>
#include <inj_event.h>
#include <inj_hash.h>
#include <inj_lex.h>

%}

%union {
	inj_decl_t *l_decl;
	inj_declmem_t *l_declmem;
	inj_defn_t *l_defn;
	inj_defnmem_t *l_defnmem;
	inj_cmd_t *l_command;
	inj_randelem_t *l_randelem;

	inj_hash_t *l_hash;

	char *l_string;
	uint_t l_number;
	hrtime_t l_hrtime;
}

%type	<l_decl>	decl_memlist
%type	<l_declmem>	decl_mem
%type	<l_declmem>	decl_baremem
%type	<l_declmem>	decl_mem_intr
%type	<l_number>	decl_intr_type
%type	<l_number>	decl_arraydim
%type	<l_declmem>	decl_mem_cplx
%type	<l_hash>	decl_enumlist

%type	<l_defn>	defn_memlist
%type	<l_defnmem>	defn_memvals
%type	<l_defnmem>	defn_val

%type	<l_command>	command
%type	<l_command>	cmd_repeatable
%type	<l_randelem>	rand_problist
%type	<l_randelem>	rand_element

%type	<l_defn>	defined_event
%type	<l_number>	number
%type	<l_hrtime>	hrtime

%token	INJ_TOK_EVDEF
%token	INJ_TOK_FMRIDEF
%token	INJ_TOK_AUTHDEF
%token	INJ_TOK_LISTDEF

%token	INJ_TOK_INT8
%token	INJ_TOK_INT16
%token	INJ_TOK_INT32
%token	INJ_TOK_INT64
%token	INJ_TOK_UINT8
%token	INJ_TOK_UINT16
%token	INJ_TOK_UINT32
%token	INJ_TOK_UINT64
%token	INJ_TOK_BOOLEAN
%token	INJ_TOK_STRING
%token	INJ_TOK_ENUM

%token	INJ_TOK_EVENT
%token	INJ_TOK_FMRI
%token	INJ_TOK_AUTH
%token	INJ_TOK_LIST

%token	INJ_TOK_ADDHRT
%token	INJ_TOK_ENDHRT
%token	INJ_TOK_SLEEP
%token	INJ_TOK_REPEAT
%token	INJ_TOK_RANDOMIZE

%token	<l_string> INJ_TOK_IDENT
%token	<l_string> INJ_TOK_FMACLASS
%token	<l_string> INJ_TOK_IMM
%token	<l_string> INJ_TOK_QSTRING

%%

statement_list:	/* EMPTY */
	|	statement_list statement ';'
	;

statement:	decl
	|	defn
	|	command {
			if ($1 != NULL)
				inj_cmds_add($1);
		}
	;

/*
 * Event, FMRI, Authority, and list declarations
 */

decl:		INJ_TOK_EVDEF INJ_TOK_FMACLASS '{' decl_memlist '}' {
			if ($4 != NULL)
				inj_decl_finish($4, $2, ITEMTYPE_EVENT);
		}
	|	INJ_TOK_FMRIDEF INJ_TOK_IDENT '{' decl_memlist '}' {
			if ($4 != NULL)
				inj_decl_finish($4, $2, ITEMTYPE_FMRI);
		}
	|	INJ_TOK_AUTHDEF INJ_TOK_IDENT '{' decl_memlist '}' {
			if ($4 != NULL)
				inj_decl_finish($4, $2, ITEMTYPE_AUTH);
		}
	|	INJ_TOK_LISTDEF INJ_TOK_IDENT '{' decl_memlist '}' {
			if ($4 != NULL)
				inj_decl_finish($4, $2, ITEMTYPE_LIST);
		}
	;

decl_memlist:	/* EMPTY */	{ $$ = NULL; }
	|	decl_memlist decl_mem ';' {
			if ($2 == NULL) {
				$$ = $1;
			} else if ($1 == NULL) {
				$$ = inj_decl_create($2);
			} else {
				inj_decl_addmem($1, $2);
				$$ = $1;
			}
		}
	;

decl_mem:	decl_baremem
	|	decl_baremem decl_arraydim {
			if ($1 != NULL)
				inj_decl_mem_make_array($1, $2);
			$$ = $1;
		}
	;

decl_baremem:	decl_mem_intr
	|	decl_mem_cplx
	;

decl_mem_intr:	decl_intr_type INJ_TOK_IDENT {
			$$ = inj_decl_mem_create($2, $1);
		}
	;

decl_intr_type:	INJ_TOK_INT8		{ $$ = MEMTYPE_INT8; }
	|	INJ_TOK_INT16		{ $$ = MEMTYPE_INT16; }
	|	INJ_TOK_INT32		{ $$ = MEMTYPE_INT32; }
	|	INJ_TOK_INT64		{ $$ = MEMTYPE_INT64; }
	|	INJ_TOK_UINT8		{ $$ = MEMTYPE_UINT8; }
	|	INJ_TOK_UINT16		{ $$ = MEMTYPE_UINT16; }
	|	INJ_TOK_UINT32		{ $$ = MEMTYPE_UINT32; }
	|	INJ_TOK_UINT64		{ $$ = MEMTYPE_UINT64; }
	|	INJ_TOK_BOOLEAN		{ $$ = MEMTYPE_BOOL; }
	|	INJ_TOK_STRING		{ $$ = MEMTYPE_STRING; }
	;

decl_arraydim:	'[' number ']' {
			$$ = $2;
		}
	|	'[' ']' {
			$$ = 0;
		}
	;

decl_mem_cplx:	INJ_TOK_ENUM INJ_TOK_IDENT '{' decl_enumlist '}' {
			$$ = inj_decl_mem_create_enum($2, $4);
		}
	|	INJ_TOK_EVENT INJ_TOK_FMACLASS INJ_TOK_IDENT {
			$$ = inj_decl_mem_create_defined($3, $2,
			    ITEMTYPE_EVENT);
		}
	|	INJ_TOK_FMRI INJ_TOK_IDENT INJ_TOK_IDENT {
			$$ = inj_decl_mem_create_defined($3, $2,
			    ITEMTYPE_FMRI);
		}
	|	INJ_TOK_AUTH INJ_TOK_IDENT INJ_TOK_IDENT {
			$$ = inj_decl_mem_create_defined($3, $2,
			    ITEMTYPE_AUTH);
		}
	|	INJ_TOK_LIST INJ_TOK_IDENT INJ_TOK_IDENT {
			$$ = inj_decl_mem_create_defined($3, $2,
			    ITEMTYPE_LIST);
		}
	;

decl_enumlist:	INJ_TOK_IDENT {
			$$ = inj_zalloc(sizeof (inj_hash_t));
			inj_strhash_create($$);

			inj_strhash_insert($$, $1, 1);
		}
	|	decl_enumlist ',' INJ_TOK_IDENT {
			if (inj_strhash_lookup($1, $3) != NULL)
				yyerror("duplicate enum value \"%s\"", $3);
			else
				inj_strhash_insert($1, $3, 1);
			$$ = $1;
		}
	;

/*
 * Event, FMRI, Authority, and list definitions
 */

defn:		INJ_TOK_EVENT INJ_TOK_FMACLASS INJ_TOK_IDENT '='
		    '{' defn_memlist '}' {
			inj_defn_finish($6, $2, $3, ITEMTYPE_EVENT);
			inj_strfree($2);
		}
	|	INJ_TOK_FMRI INJ_TOK_IDENT INJ_TOK_IDENT '='
		    '{' defn_memlist '}' {
			inj_defn_finish($6, $2, $3, ITEMTYPE_FMRI);
			inj_strfree($2);
		}
	|	INJ_TOK_AUTH INJ_TOK_IDENT INJ_TOK_IDENT '='
		    '{' defn_memlist '}' {
			inj_defn_finish($6, $2, $3, ITEMTYPE_AUTH);
			inj_strfree($2);
		}
	;

defn_memlist:	defn_memvals {
			$$ = inj_defn_create($1);
		}
	|	defn_memlist ',' defn_memvals {
			inj_defn_addmem($1, $3);
			$$ = $1;
		}
	;

defn_memvals:	defn_val
	|	INJ_TOK_EVENT INJ_TOK_FMACLASS {
			$$ = inj_defn_mem_create($2, DEFNMEM_EVENT);
		}
	|	INJ_TOK_FMRI INJ_TOK_IDENT {
			$$ = inj_defn_mem_create($2, DEFNMEM_FMRI);
		}
	|	INJ_TOK_AUTH INJ_TOK_IDENT {
			$$ = inj_defn_mem_create($2, DEFNMEM_AUTH);
		}
	|	'[' defn_memlist ']' {
			$$ = inj_defn_mem_create_list($2, DEFNMEM_ARRAY);
		}
	|	'{' defn_memlist '}' {
			$$ = inj_defn_mem_create_list($2, DEFNMEM_LIST);
		}
	;

defn_val:	INJ_TOK_IMM {
			$$ = inj_defn_mem_create($1, DEFNMEM_IMM);
		}
	|	INJ_TOK_IDENT {
			$$ = inj_defn_mem_create($1, DEFNMEM_IDENT);
		}
	|	INJ_TOK_QSTRING {
			$$ = inj_defn_mem_create($1, DEFNMEM_QSTRING);
		}
	;

/*
 * Commands
 */

command:	cmd_repeatable
	|	INJ_TOK_ADDHRT hrtime { $$ = inj_cmd_addhrt($2); }
	|	INJ_TOK_ENDHRT { $$ = inj_cmd_endhrt(); }
	|	INJ_TOK_SLEEP number { $$ = inj_cmd_sleep($2); }
	|	INJ_TOK_REPEAT number cmd_repeatable {
			$$ = ($3 == NULL ? NULL : inj_cmd_repeat($3, $2));
		}
	;

cmd_repeatable:	defined_event {
			$$ = ($1 == NULL ? NULL : inj_cmd_send($1));
		}
	|	INJ_TOK_RANDOMIZE '{' rand_problist '}' {
			$$ = ($3 == NULL ? NULL : inj_cmd_rand($3));
		}
	;

rand_problist:	rand_element
	|	rand_problist ',' rand_element {
			$$ = ($1 == NULL || $3 == NULL) ?
			    NULL : inj_rand_add($1, $3);
		}
	;

rand_element:	'{' defined_event ',' number '}' {
			$$ = ($2 == NULL ? NULL : inj_rand_create($2, $4));
		}
	;

defined_event:	INJ_TOK_IDENT {
			inj_defn_t *ev;

			if ((ev = inj_defn_lookup($1, MEMTYPE_EVENT)) ==
			    NULL) {
				yyerror("unknown event \"%s\"\n", $1);
				$$ = NULL;
			} else
				$$ = ev;
		}

number:		INJ_TOK_IMM {
			u_longlong_t val;

			if (inj_strtoull($1, 32, &val) < 0) {
				yyerror("invalid number");
				$$ = 0;
			} else
				$$ = (uint32_t)val;
		}

hrtime:		INJ_TOK_IMM INJ_TOK_IDENT {
			longlong_t val;

			if (inj_strtoll($1, 64, &val) < 0 ||
			    inj_strtime(&val, $2) < 0) {
				yyerror("invalid time");
				$$ = 0;
			} else
				$$ = val;
		}

%%

inj_list_t *
inj_program_read(const char *file)
{
	if (strcmp(file, "-") == 0) {
		yyin = stdin;
		yyinname = "stdin";
	} else {
		if ((yyin = fopen(file, "r")) == NULL)
			die("failed to open %s", file);

		yyinname = strrchr(file, '/');
		if (yyinname != NULL)
			yyinname++;
		else
			yyinname = file;
	}

	yyreset();
	(void) yyparse();

	if (yyin != stdin)
		(void) fclose(yyin);

	if (yynerrors != 0) {
		die("parsing failed - %d error%s\n", yynerrors,
		    (yynerrors > 1 ? "s" : ""));
	}

	return (inj_cmds_get());
}
