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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <libintl.h>

#include "svccfg.h"

extern int yylex(void);

uu_list_pool_t *string_pool;

%}

%union {
	int tok;
	char *str;
	uu_list_t *uul;
}

%start commands

%token SCC_VALIDATE SCC_IMPORT SCC_EXPORT SCC_ARCHIVE SCC_APPLY SCC_EXTRACT
%token SCC_CLEANUP
%token SCC_REPOSITORY SCC_INVENTORY SCC_SET SCC_END SCC_HELP SCC_RESTORE
%token SCC_LIST SCC_ADD SCC_DELETE SCC_SELECT SCC_UNSELECT
%token SCC_LISTPG SCC_ADDPG SCC_DELPG SCC_DELHASH
%token SCC_LISTPROP SCC_SETPROP SCC_DELPROP SCC_EDITPROP
%token SCC_DESCRIBE
%token SCC_ADDPROPVALUE SCC_DELPROPVALUE SCC_SETENV SCC_UNSETENV
%token SCC_LISTSNAP SCC_SELECTSNAP SCC_REVERT SCC_REFRESH
%token SCS_REDIRECT SCS_NEWLINE SCS_EQUALS SCS_LPAREN SCS_RPAREN
%token SCV_WORD SCV_STRING
%token SCC_DELNOTIFY SCC_SETNOTIFY SCC_LISTNOTIFY

%type <tok> command_token
%type <str> SCV_WORD SCV_STRING
%type <str> string opt_word
%type <uul> string_list multiline_string_list

%%

/*
 * We could hoist the command terminator for all the rules up here, but then
 * the parser would reduce before shifting the terminator, which would require
 * an additional error rule (per command) to catch extra arguments.
 * This way requires all input to be terminated, which is done by input() in
 * svccfg.l.
 */

commands : command
	| commands command

command : terminator
	| validate_cmd
	| import_cmd
	| cleanup_cmd
	| export_cmd
	| archive_cmd
	| restore_cmd
	| apply_cmd
	| extract_cmd
	| repository_cmd
	| inventory_cmd
	| set_cmd
	| end_cmd
	| help_cmd
	| list_cmd
	| add_cmd
	| delete_cmd
	| select_cmd
	| unselect_cmd
	| listpg_cmd
	| addpg_cmd
	| delpg_cmd
	| delhash_cmd
	| listprop_cmd
	| setprop_cmd
	| delprop_cmd
	| editprop_cmd
	| describe_cmd
	| addpropvalue_cmd
	| delpropvalue_cmd
	| setenv_cmd
	| unsetenv_cmd
	| listsnap_cmd
	| selectsnap_cmd
	| revert_cmd
	| refresh_cmd
	| unknown_cmd
	| delnotify_cmd
	| listnotify_cmd
	| setnotify_cmd
	| error terminator	{ semerr(gettext("Syntax error.\n")); }

unknown_cmd : SCV_WORD terminator
	{
		semerr(gettext("Unknown command \"%s\".\n"), $1);
		free($1);
	}
	| SCV_WORD string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		semerr(gettext("Unknown command \"%s\".\n"), $1);

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
		free($1);
	}

validate_cmd : SCC_VALIDATE SCV_WORD terminator
	{
		lscf_validate($2);
		free($2);
	}
	| SCC_VALIDATE terminator { lscf_validate_fmri(NULL); }
	| SCC_VALIDATE error terminator	{ synerr(SCC_VALIDATE); return(0); }

import_cmd : SCC_IMPORT string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		if (engine_import($2) == -2) {
			synerr(SCC_IMPORT);
			return(0);
		}

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
	}
	| SCC_IMPORT error terminator	{ synerr(SCC_IMPORT); return(0); }

cleanup_cmd : SCC_CLEANUP terminator
	{
		engine_cleanup(0);
	}
	| SCC_CLEANUP SCV_WORD terminator
	{
		if (strcmp($2, "-a") == 0) {
			engine_cleanup(1);
			free($2);
		} else {
			synerr(SCC_CLEANUP);
			free($2);
			return (0);
		}
	}
	| SCC_CLEANUP error terminator { synerr(SCC_CLEANUP); return(0); }


export_cmd : SCC_EXPORT SCV_WORD terminator
	{
		lscf_service_export($2, NULL, 0);
		free($2);
	}
	| SCC_EXPORT SCV_WORD SCS_REDIRECT SCV_WORD terminator
	{
		lscf_service_export($2, $4, 0);
		free($2);
		free($4);
	}
	| SCC_EXPORT SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-a") == 0) {
			lscf_service_export($3, NULL, SCE_ALL_VALUES);
			free($2);
			free($3);
		} else {
			synerr(SCC_EXPORT);
			free($2);
			free($3);
			return (0);
		}
	}
	| SCC_EXPORT SCV_WORD SCV_WORD SCS_REDIRECT SCV_WORD terminator
	{
		if (strcmp($2, "-a") == 0) {
			lscf_service_export($3, $5, SCE_ALL_VALUES);
			free($2);
			free($3);
			free($5);
		} else {
			synerr(SCC_EXPORT);
			free($2);
			free($3);
			free($5);
			return (0);
		}
	}
	| SCC_EXPORT error terminator	{ synerr(SCC_EXPORT); return(0); }

archive_cmd : SCC_ARCHIVE terminator
	{
		lscf_archive(NULL, 0);
	}
	| SCC_ARCHIVE SCV_WORD terminator
	{
		if (strcmp($2, "-a") == 0) {
			lscf_archive(NULL, SCE_ALL_VALUES);
			free($2);
		} else {
			synerr(SCC_ARCHIVE);
			free($2);
			return (0);
		}
	}
	| SCC_ARCHIVE SCS_REDIRECT SCV_WORD terminator
	{
		lscf_archive($3, 0);
		free($3);
	}
	| SCC_ARCHIVE SCV_WORD SCS_REDIRECT SCV_WORD terminator
	{
		if (strcmp($2, "-a") == 0) {
			lscf_archive($4, SCE_ALL_VALUES);
			free($2);
			free($4);
		} else {
			synerr(SCC_ARCHIVE);
			free($2);
			free($4);
			return (0);
		}
	}
	| SCC_ARCHIVE error terminator	{ synerr(SCC_ARCHIVE); return(0); }

restore_cmd : SCC_RESTORE SCV_WORD terminator
	{
		(void) engine_restore($2);
		free($2);
	}
	| SCC_RESTORE error terminator	{ synerr(SCC_RESTORE); return(0); }

apply_cmd : SCC_APPLY SCV_WORD terminator
	{
		if (engine_apply($2, 1) == -1) {
			if ((est->sc_cmd_flags & (SC_CMD_IACTIVE|SC_CMD_DONT_EXIT)) == 0)
				exit(1);

			free($2);
			return (0);
		}

		free($2);
	}
	| SCC_APPLY SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-n") == 0) {
			(void) engine_apply($3, 0);
			free($2);
			free($3);
		} else {
			synerr(SCC_APPLY);
			free($2);
			free($3);
			return (0);
		}
	}
	| SCC_APPLY error terminator	{ synerr(SCC_APPLY); return(0); }

extract_cmd: SCC_EXTRACT terminator	{ lscf_profile_extract(NULL); }
	| SCC_EXTRACT SCS_REDIRECT SCV_WORD terminator
	{
		lscf_profile_extract($3);
		free($3);
	}
	| SCC_EXTRACT error terminator	{ synerr(SCC_EXTRACT); return(0); }

repository_cmd: SCC_REPOSITORY SCV_WORD terminator
	{
		if (strcmp($2, "-f") == 0) {
			synerr(SCC_REPOSITORY);
			return(0);
		}
		lscf_set_repository($2, 0);
		free($2);
	}
	| SCC_REPOSITORY SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-f") == 0) {
			lscf_set_repository($3, 1);
			free($2);
			free($3);
		} else {
			synerr(SCC_REPOSITORY);
			return(0);
		}
	}
	| SCC_REPOSITORY error terminator   { synerr(SCC_REPOSITORY); return(0); }

inventory_cmd : SCC_INVENTORY SCV_WORD terminator
					{ lxml_inventory($2); free($2); }
	| SCC_INVENTORY error terminator	{ synerr(SCC_INVENTORY); return(0); }

set_cmd : SCC_SET string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		(void) engine_set($2);

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
	}
	| SCC_SET error terminator		{ synerr(SCC_SET); return(0); }

end_cmd : SCC_END terminator			{ exit(0); }
	| SCC_END error terminator		{ synerr (SCC_END); return(0); }

help_cmd : SCC_HELP terminator			{ help(0); }
	| SCC_HELP command_token terminator	{ help($2); }
	| SCC_HELP error terminator		{ synerr(SCC_HELP); return(0); }

list_cmd : SCC_LIST opt_word terminator	{ lscf_list($2); free($2); }
	| SCC_LIST error terminator	{ synerr(SCC_LIST); return(0); }

add_cmd : SCC_ADD SCV_WORD terminator	{ lscf_add($2); free($2); }
	| SCC_ADD error terminator	{ synerr(SCC_ADD); return(0); }

delete_cmd : SCC_DELETE SCV_WORD terminator
					{ lscf_delete($2, 0); free($2); }
	| SCC_DELETE SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-f") == 0) {
			lscf_delete($3, 1);
			free($2);
			free($3);
		} else {
			synerr(SCC_DELETE);
			free($2);
			free($3);
			return(0);
		}
	}
	| SCC_DELETE error terminator	{ synerr(SCC_DELETE); return(0); }

select_cmd : SCC_SELECT SCV_WORD terminator	{ lscf_select($2); free($2); }
	| SCC_SELECT error terminator	{ synerr(SCC_SELECT); return(0) ;}

unselect_cmd : SCC_UNSELECT terminator	{ lscf_unselect(); }
	| SCC_UNSELECT error terminator	{ synerr(SCC_UNSELECT); return(0); }

listpg_cmd : SCC_LISTPG opt_word terminator
					{ lscf_listpg($2); free($2); }
	| SCC_LISTPG error terminator	{ synerr(SCC_LISTPG); return(0); }

addpg_cmd : SCC_ADDPG SCV_WORD SCV_WORD opt_word terminator
	{
		(void) lscf_addpg($2, $3, $4);
		free($2);
		free($3);
		free($4);
	}
	| SCC_ADDPG error terminator	{ synerr(SCC_ADDPG); return(0); }

delpg_cmd : SCC_DELPG SCV_WORD terminator
					{ lscf_delpg($2); free($2); }
	| SCC_DELPG error terminator	{ synerr(SCC_DELPG); return(0); }

delhash_cmd : SCC_DELHASH SCV_WORD terminator
	{
		lscf_delhash($2, 0); free($2);
	}
	| SCC_DELHASH SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-d") == 0) {
			lscf_delhash($3, 1);
			free($2);
			free($3);
		} else {
			synerr(SCC_DELHASH);
			free($2);
			free($3);
			return(0);
		}
	}
	| SCC_DELHASH error terminator	{ synerr(SCC_DELHASH); return(0); }

listprop_cmd : SCC_LISTPROP opt_word terminator
					{ lscf_listprop($2); free($2); }
	| SCC_LISTPROP error terminator	{ synerr(SCC_LISTPROP); return(0); }

setprop_cmd : SCC_SETPROP SCV_WORD SCS_EQUALS string terminator
	{
		lscf_setprop($2, NULL, $4, NULL);
		free($2);
		free($4);
	}
	| SCC_SETPROP SCV_WORD SCS_EQUALS SCV_WORD string terminator
	{
		(void) lscf_setprop($2, $4, $5, NULL);
		free($2);
		free($4);
		free($5);
	}
	| SCC_SETPROP SCV_WORD SCS_EQUALS opt_word SCS_LPAREN
	      multiline_string_list SCS_RPAREN terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		(void) lscf_setprop($2, $4, NULL, $6);

		free($2);
		free($4);

		while ((slp = uu_list_teardown($6, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($6);
	}
	| SCC_SETPROP error terminator	{ synerr(SCC_SETPROP); return(0); }
	| SCC_SETPROP error		{ synerr(SCC_SETPROP); return(0); }

delprop_cmd : SCC_DELPROP SCV_WORD terminator
					{ lscf_delprop($2); free($2); }
	| SCC_DELPROP error terminator	{ synerr(SCC_DELPROP); return(0); }

editprop_cmd : SCC_EDITPROP terminator	{ lscf_editprop(); }
	| SCC_EDITPROP error terminator	{ synerr(SCC_EDITPROP); return(0); }

describe_cmd : SCC_DESCRIBE string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		if (lscf_describe($2, 1) == -2) {
			synerr(SCC_DESCRIBE);
			return(0);
		}

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
	}
	| SCC_DESCRIBE terminator { lscf_describe(NULL, 0); }
	| SCC_DESCRIBE error terminator	 { synerr(SCC_DESCRIBE); return(0); }

addpropvalue_cmd : SCC_ADDPROPVALUE SCV_WORD string terminator
	{
		lscf_addpropvalue($2, NULL, $3);
		free($2);
		free($3);
	}
	| SCC_ADDPROPVALUE SCV_WORD string string terminator
	{
		(void) lscf_addpropvalue($2, $3, $4);
		free($2);
		free($3);
		free($4);
	}
	| SCC_ADDPROPVALUE error terminator { synerr(SCC_ADDPROPVALUE); return(0); }

delpropvalue_cmd : SCC_DELPROPVALUE SCV_WORD string terminator
	{
		lscf_delpropvalue($2, $3, 0);
		free($2);
		free($3);
	}
	| SCC_DELPROPVALUE error terminator { synerr(SCC_DELPROPVALUE); return(0); }

setenv_cmd : SCC_SETENV string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		if (lscf_setenv($2, 0) == -2) {
			synerr(SCC_SETENV);
			return(0);
		}

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
	}
	| SCC_SETENV error terminator		{ synerr(SCC_SETENV); return(0); }

unsetenv_cmd : SCC_UNSETENV string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		if (lscf_setenv($2, 1) == -2) {
			synerr(SCC_UNSETENV);
			return(0);
		}

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
	}
	| SCC_UNSETENV error terminator	{ synerr(SCC_UNSETENV); return(0); }

listsnap_cmd : SCC_LISTSNAP terminator	{ lscf_listsnap(); }
	| SCC_LISTSNAP error terminator	{ synerr(SCC_LISTSNAP); return(0); }

selectsnap_cmd : SCC_SELECTSNAP opt_word terminator
					{ lscf_selectsnap($2); free($2); }
	| SCC_SELECTSNAP error terminator
					{ synerr(SCC_SELECTSNAP); return(0); }

revert_cmd: SCC_REVERT opt_word terminator	{ lscf_revert($2); free ($2); }
	| SCC_REVERT error terminator		{ synerr(SCC_REVERT); return(0); }

refresh_cmd: SCC_REFRESH terminator	{ lscf_refresh(); }
	| SCC_REFRESH error terminator	{ synerr(SCC_REFRESH); return(0); }

delnotify_cmd : SCC_DELNOTIFY SCV_WORD terminator
	{
		lscf_delnotify($2, 0);
		free($2);
	}
	| SCC_DELNOTIFY SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-g") == 0) {
			lscf_delnotify($3, 1);
			free($2);
			free($3);
		} else {
			synerr(SCC_DELNOTIFY);
			free($2);
			free($3);
			return(0);
		}
	}
	| SCC_DELNOTIFY error terminator { synerr(SCC_DELNOTIFY); return(0); }

listnotify_cmd : SCC_LISTNOTIFY terminator
	{
		lscf_listnotify("all", 0);
	}
	| SCC_LISTNOTIFY SCV_WORD terminator
	{
		if (strcmp($2, "-g") == 0) {
			lscf_listnotify("all", 1);
		} else {
			lscf_listnotify($2, 0);
		}
		free($2);
	}
	| SCC_LISTNOTIFY SCV_WORD SCV_WORD terminator
	{
		if (strcmp($2, "-g") == 0) {
			lscf_listnotify($3, 1);
			free($2);
			free($3);
		} else {
			synerr(SCC_LISTNOTIFY);
			free($2);
			free($3);
			return(0);
		}
	}
	| SCC_LISTNOTIFY error terminator { synerr(SCC_LISTNOTIFY); return(0); }

setnotify_cmd : SCC_SETNOTIFY string_list terminator
	{
		string_list_t *slp;
		void *cookie = NULL;

		if (lscf_setnotify($2) == -2)
			synerr(SCC_SETNOTIFY);

		while ((slp = uu_list_teardown($2, &cookie)) != NULL) {
			free(slp->str);
			free(slp);
		}

		uu_list_destroy($2);
	}
	| SCC_SETNOTIFY error terminator { synerr(SCC_SETNOTIFY); return(0); }

terminator : SCS_NEWLINE

string_list :
	{
		$$ = uu_list_create(string_pool, NULL, 0);
		if ($$ == NULL)
			uu_die(gettext("Out of memory\n"));
	}
	| string_list string
	{
		string_list_t *slp;

		slp = safe_malloc(sizeof (*slp));

		slp->str = $2;
		uu_list_node_init(slp, &slp->node, string_pool);
		uu_list_append($1, slp);
		$$ = $1;
	}

multiline_string_list : string_list
	{
		$$ = $1;
	}
	| multiline_string_list SCS_NEWLINE string_list
	{
		void *cookie = NULL;
		string_list_t *slp;

		/* Append $3 to $1. */
		while ((slp = uu_list_teardown($3, &cookie)) != NULL)
			uu_list_append($1, slp);

		uu_list_destroy($3);
	}

string : SCV_WORD	{ $$ = $1; }
	| SCV_STRING	{ $$ = $1; }

opt_word :		{ $$ = NULL; }
	| SCV_WORD	{ $$ = $1; }

command_token : SCC_VALIDATE	{ $$ = SCC_VALIDATE; }
	| SCC_IMPORT		{ $$ = SCC_IMPORT; }
	| SCC_CLEANUP		{ $$ = SCC_CLEANUP; }
	| SCC_EXPORT		{ $$ = SCC_EXPORT; }
	| SCC_APPLY		{ $$ = SCC_APPLY; }
	| SCC_EXTRACT		{ $$ = SCC_EXTRACT; }
	| SCC_REPOSITORY	{ $$ = SCC_REPOSITORY; }
	| SCC_ARCHIVE		{ $$ = SCC_ARCHIVE; }
	| SCC_INVENTORY		{ $$ = SCC_INVENTORY; }
	| SCC_SET		{ $$ = SCC_SET; }
	| SCC_END		{ $$ = SCC_END; }
	| SCC_HELP		{ $$ = SCC_HELP; }
	| SCC_LIST		{ $$ = SCC_LIST; }
	| SCC_ADD		{ $$ = SCC_ADD; }
	| SCC_DELETE		{ $$ = SCC_DELETE; }
	| SCC_SELECT		{ $$ = SCC_SELECT; }
	| SCC_UNSELECT		{ $$ = SCC_UNSELECT; }
	| SCC_LISTPG		{ $$ = SCC_LISTPG; }
	| SCC_ADDPG		{ $$ = SCC_ADDPG; }
	| SCC_DELPG		{ $$ = SCC_DELPG; }
	| SCC_DELHASH		{ $$ = SCC_DELHASH; }
	| SCC_LISTPROP		{ $$ = SCC_LISTPROP; }
	| SCC_SETPROP		{ $$ = SCC_SETPROP; }
	| SCC_DELPROP		{ $$ = SCC_DELPROP; }
	| SCC_EDITPROP		{ $$ = SCC_EDITPROP; }
	| SCC_ADDPROPVALUE	{ $$ = SCC_ADDPROPVALUE; }
	| SCC_DELPROPVALUE	{ $$ = SCC_DELPROPVALUE; }
	| SCC_SETENV		{ $$ = SCC_SETENV; }
	| SCC_UNSETENV		{ $$ = SCC_UNSETENV; }
	| SCC_LISTSNAP		{ $$ = SCC_LISTSNAP; }
	| SCC_SELECTSNAP	{ $$ = SCC_SELECTSNAP; }
	| SCC_REVERT		{ $$ = SCC_REVERT; }
	| SCC_REFRESH		{ $$ = SCC_REFRESH; }
	| SCC_DESCRIBE		{ $$ = SCC_DESCRIBE; }
	| SCC_DELNOTIFY		{ $$ = SCC_DELNOTIFY; }
	| SCC_LISTNOTIFY	{ $$ = SCC_LISTNOTIFY; }
	| SCC_SETNOTIFY		{ $$ = SCC_SETNOTIFY; }
