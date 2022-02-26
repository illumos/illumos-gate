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
 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file defines zonecfg(8)'s grammar.
 *
 * Reduction rules that consume TOKENs must invoke claim_token() immediately
 * before freeing the TOKENs or adding them to data structures (e.g., cmd) that
 * will be cleaned up when the parser finishes or encounters errors.
 */

#include <stdio.h>
#include <strings.h>

#include "zonecfg.h"

static cmd_t *cmd = NULL;		/* Command being processed */
static complex_property_ptr_t complex = NULL;
static list_property_ptr_t new_list = NULL, tmp_list, last,
    list[MAX_EQ_PROP_PAIRS];
static property_value_t property[MAX_EQ_PROP_PAIRS];

extern boolean_t newline_terminated;
extern int num_prop_vals;		/* # of property values */

/* yacc externals */
extern int yydebug;
extern void yyerror(char *s);

/*
 * This function is used by the simple_prop_val reduction rules to set up
 * a list_property_ptr_t and adjust the above global variables appropriately.
 * Note that this function duplicates the specified string and makes
 * the new list's lp_simple field point to the duplicate.  This function does
 * not free the original string.
 *
 * This function returns a pointer to the duplicated string or NULL if an error
 * occurred.  The simple_prop_val reduction rules that invoke this function
 * should set $$ to the returned pointer.
 */
static char *
simple_prop_val_func(const char *str)
{
	char *retstr;

	if ((new_list = alloc_list()) == NULL)
		return (NULL);
	if ((retstr = strdup(str)) == NULL) {
		free_list(new_list);
		return (NULL);
	}
	new_list->lp_simple = retstr;
	new_list->lp_complex = NULL;
	new_list->lp_next = NULL;
	if (list[num_prop_vals] == NULL) {
		list[num_prop_vals] = new_list;
	} else {
		for (tmp_list = list[num_prop_vals]; tmp_list != NULL;
		    tmp_list = tmp_list->lp_next)
			last = tmp_list;
		last->lp_next = new_list;
	}
	return (retstr);
}

/*
 * This function is used by the complex_piece reduction rules to set up a
 * complex_property_prt_t and adjust the above global variables appropriately.
 * Note that this function duplicates the specified string and makes the new
 * complex_property_ptr_t's cp_value field point to the duplicate.  It also sets
 * the complex_property_ptr_t's cp_type field to cp_type and its cp_next field
 * to cp_next.  This function does not free the original string.
 *
 * This function returns a pointer to the complex_property_t created for the
 * complex_piece or NULL if an error occurred.  The complex_piece reduction
 * rules that invoke this function should set $$ to the returned pointer.
 */
static complex_property_ptr_t
complex_piece_func(int cp_type, const char *str, complex_property_ptr_t cp_next)
{
	complex_property_ptr_t retval;

	if ((retval = alloc_complex()) == NULL)
		return (NULL);
	if ((retval->cp_value = strdup(str)) == NULL) {
		free_complex(retval);
		return (NULL);
	}
	retval->cp_type = cp_type;
	retval->cp_next = cp_next;
	complex = retval;
	return (retval);
}


%}

%union {
	int ival;
	char *strval;
	cmd_t *cmd;
	complex_property_ptr_t complex;
	list_property_ptr_t list;
}

%start commands

%token HELP CREATE EXPORT ADD DELETE REMOVE SELECT SET INFO CANCEL END VERIFY
%token COMMIT REVERT EXIT SEMICOLON TOKEN ZONENAME ZONEPATH AUTOBOOT POOL NET
%token FS ATTR DEVICE RCTL SPECIAL RAW DIR OPTIONS TYPE ADDRESS PHYSICAL
%token IPTYPE HOSTID FS_ALLOWED ALLOWED_ADDRESS
%token NAME MATCH PRIV LIMIT ACTION VALUE EQUAL OPEN_SQ_BRACKET CLOSE_SQ_BRACKET
%token OPEN_PAREN CLOSE_PAREN COMMA DATASET LIMITPRIV BOOTARGS BRAND PSET PCAP
%token MCAP NCPUS IMPORTANCE SHARES MAXLWPS MAXSHMMEM MAXSHMIDS MAXMSGIDS
%token MAXSEMIDS LOCKED SWAP SCHED CLEAR DEFROUTER ADMIN SECFLAGS USER AUTHS MAXPROCS
%token DEFAULT UPPER LOWER

%type <strval> TOKEN EQUAL OPEN_SQ_BRACKET CLOSE_SQ_BRACKET
    property_value OPEN_PAREN CLOSE_PAREN COMMA simple_prop_val
%type <complex> complex_piece complex_prop_val
%type <ival> resource_type NET FS DEVICE RCTL ATTR DATASET PSET PCAP MCAP
    ADMIN SECFLAGS
%type <ival> property_name SPECIAL RAW DIR OPTIONS TYPE ADDRESS PHYSICAL NAME
    MATCH ZONENAME ZONEPATH AUTOBOOT POOL LIMITPRIV BOOTARGS VALUE PRIV LIMIT
    ACTION BRAND SCHED IPTYPE DEFROUTER HOSTID USER AUTHS FS_ALLOWED
    ALLOWED_ADDRESS DEFAULT UPPER LOWER
%type <cmd> command
%type <cmd> add_command ADD
%type <cmd> cancel_command CANCEL
%type <cmd> commit_command COMMIT
%type <cmd> create_command CREATE
%type <cmd> delete_command DELETE
%type <cmd> end_command END
%type <cmd> exit_command EXIT
%type <cmd> export_command EXPORT
%type <cmd> help_command HELP
%type <cmd> info_command INFO
%type <cmd> remove_command REMOVE
%type <cmd> revert_command REVERT
%type <cmd> select_command SELECT
%type <cmd> set_command SET
%type <cmd> clear_command CLEAR
%type <cmd> verify_command VERIFY
%type <cmd> terminator

%%

/*
 * NOTE: Each commands reduction rule must invoke assert_no_unclaimed_tokens()
 * before it completes if it isn't processing an error.  This ensures that
 * reduction rules properly consume TOKENs.
 */
commands: command terminator
	{
		if ($1 != NULL) {
			if ($1->cmd_handler != NULL)
				$1->cmd_handler($1);
			free_cmd($1);
			bzero(list, sizeof (list_property_t));
			num_prop_vals = 0;
		}
		assert_no_unclaimed_tokens();
		return (0);
	}
	| command error terminator
	{
		if ($1 != NULL) {
			free_cmd($1);
			bzero(list, sizeof (list_property_t));
			num_prop_vals = 0;
		}
		if (YYRECOVERING())
			YYABORT;
		yyclearin;
		yyerrok;
	}
	| error terminator
	{
		if (YYRECOVERING())
			YYABORT;
		yyclearin;
		yyerrok;
	}
	| terminator
	{
		assert_no_unclaimed_tokens();
		return (0);
	}

command: add_command
	| cancel_command
	| clear_command
	| create_command
	| commit_command
	| delete_command
	| end_command
	| exit_command
	| export_command
	| help_command
	| info_command
	| remove_command
	| revert_command
	| select_command
	| set_command
	| verify_command

terminator:	'\n'	{ newline_terminated = B_TRUE; }
	|	';'	{ newline_terminated = B_FALSE; }

add_command: ADD
	{
		short_usage(CMD_ADD);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_RES_PROPS);
		YYERROR;
	}
	| ADD TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &add_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}
	| ADD resource_type
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &add_func;
		$$->cmd_argc = 0;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 0;
	}
	| ADD property_name property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &add_func;
		$$->cmd_argc = 0;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = $2;
		$$->cmd_property_ptr[0] = &property[0];
	}

cancel_command: CANCEL
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &cancel_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| CANCEL TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &cancel_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

create_command: CREATE
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &create_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| CREATE TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &create_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}
	| CREATE TOKEN TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &create_func;
		$$->cmd_argc = 2;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = claim_token($3);
		$$->cmd_argv[2] = NULL;
	}
	| CREATE TOKEN TOKEN TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &create_func;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = claim_token($3);
		$$->cmd_argv[2] = claim_token($4);
		$$->cmd_argv[3] = NULL;
	}

commit_command: COMMIT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &commit_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| COMMIT TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &commit_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

delete_command: DELETE
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &delete_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	DELETE TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &delete_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

end_command: END
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &end_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| END TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &end_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

exit_command: EXIT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &exit_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| EXIT TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &exit_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

export_command: EXPORT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| EXPORT TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}
	| EXPORT TOKEN TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 2;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = claim_token($3);
		$$->cmd_argv[2] = NULL;
	}

help_command:	HELP
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &help_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	HELP TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &help_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

info_command:	INFO
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_UNKNOWN;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO TOKEN
	{
		short_usage(CMD_INFO);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_RES_PROPS);
		free(claim_token($2));
		YYERROR;
	}
	|	INFO resource_type
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO ZONENAME
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_ZONENAME;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO ZONEPATH
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_ZONEPATH;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO BRAND
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_BRAND;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO AUTOBOOT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_AUTOBOOT;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO IPTYPE
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_IPTYPE;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO POOL
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_POOL;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO LIMITPRIV
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_LIMITPRIV;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO BOOTARGS
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_BOOTARGS;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO SCHED
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_SCHED;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO SHARES
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_SHARES;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO MAXLWPS
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_MAXLWPS;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO MAXPROCS
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_MAXPROCS;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO MAXSHMMEM
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_MAXSHMMEM;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO MAXSHMIDS
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_MAXSHMIDS;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO MAXMSGIDS
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_MAXMSGIDS;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO MAXSEMIDS
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_MAXSEMIDS;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO HOSTID
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_HOSTID;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO FS_ALLOWED
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = RT_FS_ALLOWED;
		$$->cmd_prop_nv_pairs = 0;
	}
	|	INFO resource_type property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
	}
	|	INFO resource_type property_name EQUAL property_value property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 2;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
		$$->cmd_prop_name[1] = $6;
		$$->cmd_property_ptr[1] = &property[1];
	}
	|	INFO resource_type property_name EQUAL property_value property_name EQUAL property_value property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &info_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 3;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
		$$->cmd_prop_name[1] = $6;
		$$->cmd_property_ptr[1] = &property[1];
		$$->cmd_prop_name[2] = $9;
		$$->cmd_property_ptr[2] = &property[2];
	}

remove_command: REMOVE
	{
		short_usage(CMD_REMOVE);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_RES_PROPS);
		YYERROR;
	}
	| REMOVE TOKEN
	{
		short_usage(CMD_REMOVE);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_RES_PROPS);
		free(claim_token($2));
		YYERROR;
	}
	| REMOVE resource_type
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &remove_func;
		$$->cmd_res_type = $2;
	}
	| REMOVE TOKEN resource_type
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &remove_func;
		$$->cmd_res_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}
	| REMOVE property_name property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &remove_func;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = $2;
		$$->cmd_property_ptr[0] = &property[0];
	}
	| REMOVE resource_type property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &remove_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
	}
	| REMOVE resource_type property_name EQUAL property_value property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &remove_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 2;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
		$$->cmd_prop_name[1] = $6;
		$$->cmd_property_ptr[1] = &property[1];
	}
	| REMOVE resource_type property_name EQUAL property_value property_name EQUAL property_value property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &remove_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 3;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
		$$->cmd_prop_name[1] = $6;
		$$->cmd_property_ptr[1] = &property[1];
		$$->cmd_prop_name[2] = $9;
		$$->cmd_property_ptr[2] = &property[2];
	}

revert_command: REVERT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &revert_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| REVERT TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &revert_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

select_command: SELECT
	{
		short_usage(CMD_SELECT);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_RES_PROPS);
		YYERROR;
	}
	| SELECT PSET
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &select_func;
		$$->cmd_res_type = RT_DCPU;
	}
	| SELECT PCAP
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &select_func;
		$$->cmd_res_type = RT_PCAP;
	}
	| SELECT MCAP
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &select_func;
		$$->cmd_res_type = RT_MCAP;
	}
	| SELECT resource_type
	{
		short_usage(CMD_SELECT);
		YYERROR;
	}
	| SELECT resource_type property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &select_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
	}
	| SELECT resource_type property_name EQUAL property_value property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &select_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 2;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
		$$->cmd_prop_name[1] = $6;
		$$->cmd_property_ptr[1] = &property[1];
	}
	| SELECT resource_type property_name EQUAL property_value property_name EQUAL property_value property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &select_func;
		$$->cmd_res_type = $2;
		$$->cmd_prop_nv_pairs = 3;
		$$->cmd_prop_name[0] = $3;
		$$->cmd_property_ptr[0] = &property[0];
		$$->cmd_prop_name[1] = $6;
		$$->cmd_property_ptr[1] = &property[1];
		$$->cmd_prop_name[2] = $9;
		$$->cmd_property_ptr[2] = &property[2];
	}

set_command: SET
	{
		short_usage(CMD_SET);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_PROPS);
		YYERROR;
	}
	| SET property_name EQUAL OPEN_SQ_BRACKET CLOSE_SQ_BRACKET
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &set_func;
		$$->cmd_prop_nv_pairs = 0;
		$$->cmd_prop_name[0] = $2;
		property[0].pv_type = PROP_VAL_LIST;
		property[0].pv_list = NULL;
		$$->cmd_property_ptr[0] = &property[0];
	}
	| SET property_name EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &set_func;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = $2;
		$$->cmd_property_ptr[0] = &property[0];
	}
	| SET TOKEN ZONEPATH EQUAL property_value
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
		$$->cmd_handler = &set_func;
		$$->cmd_prop_nv_pairs = 1;
		$$->cmd_prop_name[0] = PT_ZONEPATH;
		$$->cmd_property_ptr[0] = &property[0];
	}

clear_command: CLEAR
	{
		short_usage(CMD_CLEAR);
		(void) fputs("\n", stderr);
		usage(B_FALSE, HELP_PROPS);
		YYERROR;
	}
	| CLEAR property_name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &clear_func;
		$$->cmd_res_type = $2;
	}

verify_command: VERIFY
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &verify_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	| VERIFY TOKEN
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_handler = &verify_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = claim_token($2);
		$$->cmd_argv[1] = NULL;
	}

resource_type: NET	{ $$ = RT_NET; }
	| FS		{ $$ = RT_FS; }
	| DEVICE	{ $$ = RT_DEVICE; }
	| RCTL		{ $$ = RT_RCTL; }
	| ATTR		{ $$ = RT_ATTR; }
	| DATASET	{ $$ = RT_DATASET; }
	| PSET		{ $$ = RT_DCPU; }
	| PCAP		{ $$ = RT_PCAP; }
	| MCAP		{ $$ = RT_MCAP; }
	| ADMIN		{ $$ = RT_ADMIN; }
	| SECFLAGS	{ $$ = RT_SECFLAGS; }

property_name: SPECIAL	{ $$ = PT_SPECIAL; }
	| RAW		{ $$ = PT_RAW; }
	| DIR		{ $$ = PT_DIR; }
	| TYPE		{ $$ = PT_TYPE; }
	| OPTIONS	{ $$ = PT_OPTIONS; }
	| ZONENAME	{ $$ = PT_ZONENAME; }
	| ZONEPATH	{ $$ = PT_ZONEPATH; }
	| AUTOBOOT	{ $$ = PT_AUTOBOOT; }
	| IPTYPE	{ $$ = PT_IPTYPE; }
	| POOL		{ $$ = PT_POOL; }
	| LIMITPRIV	{ $$ = PT_LIMITPRIV; }
	| BOOTARGS	{ $$ = PT_BOOTARGS; }
	| ADDRESS	{ $$ = PT_ADDRESS; }
	| ALLOWED_ADDRESS	{ $$ = PT_ALLOWED_ADDRESS; }
	| PHYSICAL	{ $$ = PT_PHYSICAL; }
	| DEFROUTER	{ $$ = PT_DEFROUTER; }
	| NAME		{ $$ = PT_NAME; }
	| VALUE		{ $$ = PT_VALUE; }
	| MATCH		{ $$ = PT_MATCH; }
	| PRIV		{ $$ = PT_PRIV; }
	| LIMIT		{ $$ = PT_LIMIT; }
	| ACTION	{ $$ = PT_ACTION; }
	| BRAND		{ $$ = PT_BRAND; }
	| NCPUS		{ $$ = PT_NCPUS; }
	| LOCKED	{ $$ = PT_LOCKED; }
	| SWAP		{ $$ = PT_SWAP; }
	| IMPORTANCE	{ $$ = PT_IMPORTANCE; }
	| SHARES	{ $$ = PT_SHARES; }
	| MAXLWPS	{ $$ = PT_MAXLWPS; }
	| MAXPROCS	{ $$ = PT_MAXPROCS; }
	| MAXSHMMEM	{ $$ = PT_MAXSHMMEM; }
	| MAXSHMIDS	{ $$ = PT_MAXSHMIDS; }
	| MAXMSGIDS	{ $$ = PT_MAXMSGIDS; }
	| MAXSEMIDS	{ $$ = PT_MAXSEMIDS; }
	| SCHED		{ $$ = PT_SCHED; }
	| HOSTID	{ $$ = PT_HOSTID; }
	| USER		{ $$ = PT_USER; }
	| AUTHS 	{ $$ = PT_AUTHS; }
	| FS_ALLOWED	{ $$ = PT_FS_ALLOWED; }
	| DEFAULT	{ $$ = PT_DEFAULT; }
	| UPPER		{ $$ = PT_UPPER; }
	| LOWER		{ $$ = PT_LOWER; }

/*
 * The grammar builds data structures from the bottom up.  Thus various
 * strings are lexed into TOKENs or commands or resource or property values.
 * Below is where the resource and property values are built up into more
 * complex data structures.
 *
 * There are three kinds of properties: simple (single valued), complex
 * (one or more name=value pairs) and list (concatenation of one or more
 * simple or complex properties).
 *
 * So the property structure has a type which is one of these, and the
 * corresponding _simple, _complex or _list is set to the corresponding
 * lower-level data structure.
 */

property_value: simple_prop_val
	{
		property[num_prop_vals].pv_type = PROP_VAL_SIMPLE;
		property[num_prop_vals].pv_simple = $1;
		if (list[num_prop_vals] != NULL) {
			free_outer_list(list[num_prop_vals]);
			list[num_prop_vals] = NULL;
		}
		num_prop_vals++;
	}
	| complex_prop_val
	{
		property[num_prop_vals].pv_type = PROP_VAL_COMPLEX;
		property[num_prop_vals].pv_complex = complex;
		if (list[num_prop_vals] != NULL) {
			free_outer_list(list[num_prop_vals]);
			list[num_prop_vals] = NULL;
		}
		num_prop_vals++;
	}
	| list_prop_val
	{
		property[num_prop_vals].pv_type = PROP_VAL_LIST;
		property[num_prop_vals].pv_list = list[num_prop_vals];
		num_prop_vals++;
	}

/*
 * One level lower, lists are made up of simple or complex values, so
 * simple_prop_val and complex_prop_val fill in a list structure and
 * insert it into the linked list which is built up.  And because
 * complex properties can have multiple name=value pairs, we keep
 * track of them in another linked list.
 *
 * The complex and list structures for the linked lists are allocated
 * below, and freed by recursive functions which are ultimately called
 * by free_cmd(), which is called from the top-most "commands" part of
 * the grammar.
 *
 * NOTE: simple_prop_val and complex_piece need reduction rules for
 * property_name and resource_type so that the parser will accept property names
 * and resource type names as property values.
 */

simple_prop_val: TOKEN
	{
		$$ = simple_prop_val_func($1);
		free(claim_token($1));
		if ($$ == NULL)
			YYERROR;
	}
	| resource_type
	{
		if (($$ = simple_prop_val_func(res_types[$1])) == NULL)
			YYERROR;
	}
	| property_name
	{
		if (($$ = simple_prop_val_func(prop_types[$1])) == NULL)
			YYERROR;
	}

complex_prop_val: OPEN_PAREN complex_piece CLOSE_PAREN
	{
		if ((new_list = alloc_list()) == NULL)
			YYERROR;
		new_list->lp_simple = NULL;
		new_list->lp_complex = complex;
		new_list->lp_next = NULL;
		if (list[num_prop_vals] == NULL) {
			list[num_prop_vals] = new_list;
		} else {
			for (tmp_list = list[num_prop_vals]; tmp_list != NULL;
			    tmp_list = tmp_list->lp_next)
				last = tmp_list;
			last->lp_next = new_list;
		}
	}

complex_piece: property_name EQUAL TOKEN
	{
		$$ = complex_piece_func($1, $3, NULL);
		free(claim_token($3));
		if ($$ == NULL)
			YYERROR;
	}
	| property_name EQUAL resource_type
	{
		if (($$ = complex_piece_func($1, res_types[$3], NULL)) == NULL)
			YYERROR;
	}
	| property_name EQUAL property_name
	{
		if (($$ = complex_piece_func($1, prop_types[$3], NULL)) == NULL)
			YYERROR;
	}
	| property_name EQUAL TOKEN COMMA complex_piece
	{
		$$ = complex_piece_func($1, $3, complex);
		free(claim_token($3));
		if ($$ == NULL)
			YYERROR;
	}
	| property_name EQUAL resource_type COMMA complex_piece
	{
		if (($$ = complex_piece_func($1, res_types[$3], complex)) ==
		    NULL)
			YYERROR;
	}
	| property_name EQUAL property_name COMMA complex_piece
	{
		if (($$ = complex_piece_func($1, prop_types[$3], complex)) ==
		    NULL)
			YYERROR;
	}

list_piece: simple_prop_val
	| complex_prop_val
	| simple_prop_val COMMA list_piece
	| complex_prop_val COMMA list_piece

list_prop_val: OPEN_SQ_BRACKET list_piece CLOSE_SQ_BRACKET
%%
