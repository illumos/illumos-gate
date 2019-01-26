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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Overview of poolcfg(1)
 *
 * poolcfg(1) implements a small grammar for manipulating pools configurations.
 * yacc(1) is used to generate the parser and poolcfg.l contains a simple lexer
 * (generted by lex(1)) to perform lexical processsing of the input.
 *
 * Refer to the poolcfg(1) manpage for more details of the grammar.
 *
 * The parser is designed so that all operations implement the same interface.
 * This allows the parser to simply build up the command (using the cmd
 * variable) by storing arguments and a pointer to the desired function in the
 * cmd. The command is executed when the commands production is matched.
 *
 * Properties and associations are stored in simple linked lists and processed
 * in the order submitted by the user.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <sys/utsname.h>

#include <pool.h>
#include "utils.h"
#include "poolcfg.h"



#define	USAGE1	\
"Usage:\n" \
"%s -h\n" \
"%s -c command [ -d | [ file ] ]\n" \
"%s -f command-file [-d | [ file ] ]\n\n"

#define	USAGE2	\
"command:\n" \
"  info [entity name]\n" \
"         display configuration (or specified portion) in readable form\n" \
"  create entity name [property-list]\n" \
"         make an entity of the specified type and name\n" \
"  destroy entity name\n" \
"         remove the specified entity\n" \
"  modify entity name [property-list]\n" \
"         change the listed properties on the named entity\n" \
"  associate pool name [resource-list]\n" \
"         connect one or more resources to a pool, or replace one or more\n" \
"         existing connections\n" \
"  transfer to resource name [component-list]\n" \
"         transfer one or more discreet components to a resource\n" \
"  transfer [quantity] from resource src to tgt\n" \
"         transfer a resource quantity from src to tgt\n" \
"  transfer [quantity] to resource tgt from src\n" \
"         transfer a resource quantity to tgt from src\n" \
"  discover\n" \
"         create a system entity, with one pool entity and resources to\n" \
"         match current system configuration\n" \
"  rename entity old_name to new_name\n" \
"         change the name of the entity on the system to its new name\n\n" \
"property-list:\n" \
"  ( proptype name = value [ ; proptype name = value ]* )\n" \
"         where multiple definitions in the sentence for a given\n" \
"         proptype, name pair are ignored; the last one provided is used.\n" \
"         For property deletion, use \"~ proptype name\"\n\n" \
"resource-list:\n" \
"  ( resource name [; resource name ] )\n" \
"         where multiple uses of a resource are ignored; the last provided\n" \
"         is the one used.\n" \
"         There is no deletion syntax for resource lists.\n" \
"component-list:\n" \
"  ( cpu id [; cpu id ] )\n" \
"         where multiple uses of the same component cause the last provided\n" \
"         to be the one used.\n" \
"         There is no deletion syntax for component lists.\n" \
"entity:\n" \
"  system | pool | pset | cpu\n" \
"         where cpu is only valid for transfer, info and modify commands.\n" \
"resource:\n" \
"  pset\n\n" \
"proptype:\n" \
"  boolean | int | uint | string | float\n\n"

int dofile = PO_FALSE;			/* poolcfg.l uses this for errors */
int conf_edit_error = POE_OK;		/* cached error for error reporting */
int conf_edit_errno = 0;		/* cached errno for error reporting */
int conf_list_error = POE_OK;		/* cached error for error reporting */
int conf_list_errno = 0;		/* cached errno for error reporting */
static const char cmdname[] = "poolcfg";
static const char cmd_options[] = "c:df:h";
static void usage(int);
static const char *max_suffix = ".max";
static const char *min_suffix = ".min";

static const char *conf_file = NULL;	/* Location of target config */
static cmd_t *cmd = NULL;		/* Command being processed */
static pool_conf_t *conf = NULL;	/* Config to be processed */
static int edited = PO_FALSE;		/* Has the configuration been changed */

/* yacc externals */
extern FILE *yyin;
extern int yydebug;
extern void yyerror(char *s);

/* Utility functions */
static void arg_parse(const char *);
static void file_parse(const char *);
static cmd_t *alloc_cmd(void);
static prop_t *alloc_prop(prop_op_t);
static assoc_t *alloc_assoc(int, const char *);
static void free_cmd(cmd_t *);
static void check_conf_name(cmd_t *);
static void prop_list_walk(cmd_t *, pool_elem_t *);
static void assoc_list_walk(cmd_t *, pool_t *);
static void transfer_list_walk(cmd_t *, pool_resource_t *);
static void terminate(void);
static pool_component_t *get_cpu(const char *);
static void process_min_max(pool_resource_t *);

/* Info Commands */
static void parser_conf_info(cmd_t *);
static void parser_pool_info(cmd_t *);
static void parser_resource_info(cmd_t *, const char *);
static void parser_pset_info(cmd_t *);
static void parser_cpu_info(cmd_t *);

/* Create Commands */
static void parser_conf_create(cmd_t *);
static void parser_pool_create(cmd_t *);
static void parser_resource_create(cmd_t *, const char *);
static void parser_pset_create(cmd_t *);

/* Destroy Commands */
static void parser_conf_destroy(cmd_t *);
static void parser_pool_destroy(cmd_t *);
static void parser_resource_destroy(cmd_t *, const char *);
static void parser_pset_destroy(cmd_t *);

/* Modify Commands */
static void parser_conf_modify(cmd_t *);
static void parser_pool_modify(cmd_t *);
static void parser_resource_modify(cmd_t *, const char *);
static void parser_pset_modify(cmd_t *);
static void parser_cpu_modify(cmd_t *);

/* Associate Commands */
static void parser_pool_associate(cmd_t *);

/* Assign Commands */
static void parser_resource_xtransfer(cmd_t *);
static void parser_resource_transfer(cmd_t *);

/* Discover Commands */
static void parser_conf_discover(cmd_t *);

/* Rename Commands */
static void parser_rename(cmd_t *, pool_elem_t *, const char *);
static void parser_conf_rename(cmd_t *);
static void parser_pool_rename(cmd_t *);
static void parser_pset_rename(cmd_t *);


%}

%union {
	double dval;
	uint64_t uval;
	int64_t ival;
	char *sval;
	uchar_t bval;
	cmd_t *cmd;
	prop_t *prop;
	pv_u val;
	assoc_t *assoc;
}

%start commands

%token PCC_INFO PCC_CREATE PCC_DESTROY PCC_MODIFY PCC_ASSOC PCC_DISC PCC_RENAME
%token PCC_TRANSFER
%token PCK_FROM PCK_TO PCK_OPENLST PCK_CLOSELST PCK_SEPLST PCK_ASSIGN PCK_UNDEF
PCK_COMMAND
%token PCV_FILENAME PCV_SYMBOL PCV_VAL_INT PCV_VAL_UINT PCV_VAL_FLOAT
PCV_VAL_STRING PCV_VAL_BOOLEAN
%token PCT_INT PCT_UINT PCT_BOOLEAN PCT_FLOAT PCT_STRING
%token PCE_SYSTEM PCE_POOL PCE_PSET PCE_CPU

%type <ival> PCV_VAL_INT
%type <uval> PCV_VAL_UINT
%type <bval> PCV_VAL_BOOLEAN
%type <dval> PCV_VAL_FLOAT
%type <sval> PCV_VAL_STRING
%type <sval> PCV_SYMBOL
%type <sval> PCV_FILENAME

%type <ival> PCC_INFO
%type <ival> PCE_SYSTEM PCE_POOL PCE_PSET PCE_CPU
%type <ival> entity proptype info_entity modify_entity
%type <sval> name src tgt
%type <cmd> command
%type <cmd> list_command info_command edit_command create_command
destroy_command modify_command associate_command discover_command
rename_command transfer_command transfer_qty transfer_components
%type <prop> prop_remove prop_assign prop_op prop_ops property_list
%type <assoc> resource_assign resource_assigns resource_list
%type <assoc> component_assign component_assigns component_list
%type <val> value
%type <ival> resource component

%%

commands: command
	{
		if ($1->cmd != NULL)
			$1->cmd($1);
		free_cmd($1);
	}
	| commands command
	{
		if ($2->cmd != NULL)
			$2->cmd($2);
		free_cmd($2);
	}
	| command error { YYERROR;};

command: list_command
	| edit_command
	{
		if (conf_edit_error != POE_OK) {
			if ($1->cmd != parser_conf_create &&
			    $1->cmd != parser_conf_discover) {
				die(gettext(ERR_CONF_LOAD), conf_file,
				    get_errstr_err(conf_edit_error,
				        conf_edit_errno));
			}
		}
		edited = PO_TRUE;
	};

list_command: info_command
	{
		if (conf_list_error != POE_OK) {
			if ($1->cmd != parser_conf_create &&
			    $1->cmd != parser_conf_discover) {
				die(gettext(ERR_CONF_LOAD), conf_file,
				    get_errstr_err(conf_list_error,
				        conf_list_errno));
			}
		}
	}
	| discover_command {conf_list_error = conf_edit_error = POE_OK;};

edit_command: create_command
	| destroy_command
	| modify_command
	| associate_command
	| transfer_command
	| rename_command;

info_command: PCC_INFO
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd = &parser_conf_info;
	}
	| PCC_INFO info_entity name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		switch ($2) {
		case PCE_SYSTEM:
			$$->cmd = &parser_conf_info;
			break;
		case PCE_POOL:
			$$->cmd = &parser_pool_info;
			break;
		case PCE_PSET:
			$$->cmd = &parser_pset_info;
			break;
		case PCE_CPU:
			$$->cmd = &parser_cpu_info;
			break;
		default:
			warn(gettext(ERR_UNKNOWN_ENTITY), $2);
			YYERROR;
		}
		$$->cmd_tgt1 = $3;
	};

create_command: PCC_CREATE entity name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		switch ($2) {
		case PCE_SYSTEM:
			$$->cmd = &parser_conf_create;
			/*
			 * When creating a new system element, ensure
			 * pre-existing errors are ignored.
			 */
			conf_list_error = conf_edit_error = POE_OK;
			break;
		case PCE_POOL:
			$$->cmd = &parser_pool_create;
			break;
		case PCE_PSET:
			$$->cmd = &parser_pset_create;
			break;
		default:
			warn(gettext(ERR_UNKNOWN_ENTITY), $2);
			YYERROR;
		}
		$$->cmd_tgt1 = $3;
	}
	| create_command property_list;

destroy_command: PCC_DESTROY entity name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		switch ($2) {
		case PCE_SYSTEM:
			$$->cmd = &parser_conf_destroy;
			break;
		case PCE_POOL:
			$$->cmd = &parser_pool_destroy;
			break;
		case PCE_PSET:
			$$->cmd = &parser_pset_destroy;
			break;
		default:
			warn(gettext(ERR_UNKNOWN_ENTITY), $2);
			YYERROR;
		}
		$$->cmd_tgt1 = $3;
	};

modify_command: PCC_MODIFY modify_entity name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		switch ($2) {
		case PCE_SYSTEM:
			$$->cmd = &parser_conf_modify;
			break;
		case PCE_POOL:
			$$->cmd = &parser_pool_modify;
			break;
		case PCE_PSET:
			$$->cmd = &parser_pset_modify;
			break;
		case PCE_CPU:
			$$->cmd = &parser_cpu_modify;
			break;
		default:
			warn(gettext(ERR_UNKNOWN_ENTITY), $2);
			YYERROR;
		}
		$$->cmd_tgt1 = $3;
	}
	| modify_command property_list;

associate_command: PCC_ASSOC PCE_POOL name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd = &parser_pool_associate;
		cmd->cmd_tgt1 = $3;
	}
	| associate_command resource_list;

transfer_command: transfer_qty
	| transfer_components;

transfer_components: PCC_TRANSFER PCK_TO PCE_PSET name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd = &parser_resource_xtransfer;
		cmd->cmd_tgt1 = $4;
	}
	| transfer_components component_list;

transfer_qty: PCC_TRANSFER PCV_VAL_UINT PCK_FROM PCE_PSET src PCK_TO tgt
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd = &parser_resource_transfer;
		cmd->cmd_tgt1 = $5;
		cmd->cmd_tgt2 = $7;
		cmd->cmd_qty = $2;
	}
	| PCC_TRANSFER  PCV_VAL_UINT PCK_TO PCE_PSET tgt PCK_FROM src
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd = &parser_resource_transfer;
		cmd->cmd_tgt1 = $7;
		cmd->cmd_tgt2 = $5;
		cmd->cmd_qty = $2;
	};

discover_command: PCC_DISC
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd = &parser_conf_discover;
	};

rename_command: PCC_RENAME entity name PCK_TO name
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		switch ($2) {
		case PCE_SYSTEM:
			$$->cmd = &parser_conf_rename;
			break;
		case PCE_POOL:
			$$->cmd = &parser_pool_rename;
			break;
		case PCE_PSET:
			$$->cmd = &parser_pset_rename;
			break;
		default:
			warn(gettext(ERR_UNKNOWN_ENTITY), $2);
			YYERROR;
		}
		$$->cmd_tgt1 = $3;
		$$->cmd_tgt2 = $5;
	};

modify_entity: entity
	| PCE_CPU  {$$ = PCE_CPU;};

info_entity: entity
	| PCE_CPU  {$$ = PCE_CPU;};

entity: PCE_SYSTEM {$$ = PCE_SYSTEM;}
	| PCE_POOL {$$ = PCE_POOL;}
	| PCE_PSET {$$ = PCE_PSET;};

name: PCV_SYMBOL;

src: PCV_SYMBOL;

tgt: PCV_SYMBOL;

value: PCV_VAL_INT { $$.i = $1;}
	| PCV_VAL_UINT { $$.u = $1;}
	| PCV_VAL_FLOAT { $$.d = $1;}
	| PCV_VAL_BOOLEAN { $$.b = $1;}
	| PCV_VAL_STRING { $$.s = $1;};

prop_remove: PCK_UNDEF proptype name
	{
		if (($$ = alloc_prop(po_remove)) == NULL)
			YYERROR;
		$$->prop_name = $3;
	};

prop_op: prop_assign
	| prop_remove;

prop_ops: prop_op
	{
		prop_t *prop = NULL;
		prop_t *prev = NULL;

		for (prop = cmd->cmd_prop_list; prop != NULL;
		    prop = prop->prop_next)
			prev = prop; /* Find end of list */
		if (prev != NULL)
			prev->prop_next = $1;
		else
			cmd->cmd_prop_list = $1;
		$$ = cmd->cmd_prop_list;
	}
	| prop_ops PCK_SEPLST prop_op
	{
		prop_t *prop = NULL;
		prop_t *prev = NULL;

		for (prop = cmd->cmd_prop_list; prop != NULL;
		    prop = prop->prop_next)
			prev = prop; /* Find end of list */
		if (prev != NULL)
			prev->prop_next = $3;
		else
			cmd->cmd_prop_list = $3;
		$$ = cmd->cmd_prop_list;

	};

prop_assign: proptype name PCK_ASSIGN value
	{
		if (($$ = alloc_prop(po_create)) == NULL)
			YYERROR;
		$$->prop_name = $2;
		switch ($1) {
		case PCT_INT:
			pool_value_set_int64($$->prop_value, $4.i);
			break;
		case PCT_UINT:
			pool_value_set_uint64($$->prop_value, $4.u);
			break;
		case PCT_BOOLEAN:
			pool_value_set_bool($$->prop_value, $4.b);
			break;
		case PCT_FLOAT:
			pool_value_set_double($$->prop_value, $4.d);
			break;
		case PCT_STRING:
			pool_value_set_string($$->prop_value, $4.s);
			break;
		}
	};

property_list: PCK_OPENLST prop_ops PCK_CLOSELST
	{
		$$ = $2;
	};

resource_assigns: resource_assign
	{
		assoc_t *assoc = NULL;
		assoc_t *prev = NULL;

		for (assoc = cmd->cmd_assoc_list; assoc != NULL;
		    assoc = assoc->assoc_next)
			prev = assoc; /* Find end of list */
		if (prev != NULL)
			prev->assoc_next = $1;
		else
			cmd->cmd_assoc_list = $1;
		$$ = cmd->cmd_assoc_list;
	}

	| resource_assigns PCK_SEPLST resource_assign
	{
		assoc_t *assoc = NULL;
		assoc_t *prev = NULL;

		for (assoc = cmd->cmd_assoc_list; assoc != NULL;
		    assoc = assoc->assoc_next)
			prev = assoc; /* Find end of list */
		if (prev != NULL)
			prev->assoc_next = $3;
		$$ = $3;
	};

resource_assign: resource name
	{
		if (($$ = alloc_assoc($1, $2)) == NULL)
			YYERROR;
	};

resource: PCE_PSET {$$ = PCE_PSET;};

resource_list: PCK_OPENLST resource_assigns PCK_CLOSELST
	{
		$$ = $2;
	};

component_assigns: component_assign
	{
		assoc_t *assoc = NULL;
		assoc_t *prev = NULL;

		for (assoc = cmd->cmd_assoc_list; assoc != NULL;
		    assoc = assoc->assoc_next)
			prev = assoc; /* Find end of list */
		if (prev != NULL)
			prev->assoc_next = $1;
		else
			cmd->cmd_assoc_list = $1;
		$$ = cmd->cmd_assoc_list;
	}

	| component_assigns PCK_SEPLST component_assign
	{
		assoc_t *assoc = NULL;
		assoc_t *prev = NULL;

		for (assoc = cmd->cmd_assoc_list; assoc != NULL;
		    assoc = assoc->assoc_next)
			prev = assoc; /* Find end of list */
		if (prev != NULL)
			prev->assoc_next = $3;
		$$ = $3;
	};

component_list: PCK_OPENLST component_assigns PCK_CLOSELST
	{
		$$ = $2;
	};

component_assign: component name
	{
		if (($$ = alloc_assoc($1, $2)) == NULL)
			YYERROR;
	};

component: PCE_CPU {$$ = PCE_CPU;};

proptype: PCT_INT {$$ = PCT_INT;}
	| PCT_UINT {$$ = PCT_UINT;}
	| PCT_BOOLEAN {$$ = PCT_BOOLEAN;}
	| PCT_FLOAT {$$ = PCT_FLOAT;}
	| PCT_STRING {$$ = PCT_STRING;};

%%

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN "SYS_TEST"
#endif

int
main(int argc, char *argv[])
{
	int opt;
	int docmd = PO_FALSE;

	(void) getpname(argv[0]);
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	if (atexit(terminate) != 0) {
		die(gettext(ERR_SET_TERM), get_errstr());
	}

	conf_file = pool_static_location();

	yydebug = 0;
	while ((opt = getopt(argc, argv, cmd_options)) != (int)EOF) {

		switch (opt) {
		case 'c': /* Process command line */
			if (dofile == PO_TRUE)
				usage(1);
			arg_parse(optarg);
			docmd = PO_TRUE;
			break;
		case 'd': /* Manipulate dynamic configuration */
			conf_file = pool_dynamic_location();
			break;
		case 'f': /* Process command file */
			if (docmd == PO_TRUE)
				usage(1);
			file_parse(optarg);
			dofile = PO_TRUE;
			break;
		case 'h':
			usage(2);
			break;
		case '?':
		default:
			usage(1);
			break;
		}
	}
	if (docmd == PO_FALSE && dofile == PO_FALSE)
		usage(1);

	if (optind == argc - 1) {
		if (strcmp(conf_file, pool_dynamic_location()) == 0)
			usage(1);
		conf_file = argv[optind];
	} else if (optind <  argc - 1)
		usage(1);

	if ((conf = pool_conf_alloc()) == NULL) {
		die(gettext(ERR_ALLOC_ELEMENT), gettext(CONFIGURATION),
		    get_errstr());
	}
	/*
	 * Opening a conf is complex, since we may be opening one of the
	 * following:
	 *	- An existing configuration that we can modify
	 *	- An existing configuration that we can't modify
	 *	- A new configuration that we can modify
	 *	- A new configuration that we can't modify
	 * The parser_conf_discover() function closes the file and reopens
	 * in PO_CREAT mode, so we only need be concerned here with the
	 * first two cases.
	 * Always try to open RDWR, if fail try RDONLY. Don't check
	 * if that fails, since we may be trying to discover a configuration
	 * in which case it's valid for both open attempts to fail. Later, when
	 * processing commands, if we don't have a valid configuration and
	 * we are trying to process a command which isn't a create or a discover
	 * we will fail the command as there is no valid configuration to
	 * work with.
	 */
	if (pool_conf_open(conf, conf_file, PO_RDWR) != 0) {
		conf_edit_error = pool_error();
		conf_edit_errno = errno;
		if (pool_conf_open(conf, conf_file, PO_RDONLY) != 0) {
			conf_list_error = pool_error();
			conf_list_errno = errno;
		}
	}

	if (yyparse() == 0) {
		if (pool_conf_status(conf) >= POF_VALID) {
			if (pool_conf_validate(conf, POV_STRICT) == PO_FAIL) {
				die(gettext(ERR_VALIDATION_FAILED),
				    get_errstr());
			}
			/*
			 * If the user attempted to change the configuration,
			 * then we should try to save the changes.
			 */
			if (edited == PO_TRUE) {
				if (pool_conf_commit(conf, 0) == PO_FAIL) {
					die(gettext(ERR_CONFIG_SAVE_FAILED),
					    get_errstr());
				}
			}
			pool_conf_close(conf);
		}
	} else {
		die(gettext(ERR_CMDPARSE_FAILED));
	}

	/*
	 * Cleanup is performed in terminate(), using atexit
	 */
	return (0);
}

/*
 * Info Commands
 * Invoke the appropriate libpool info function and display the returned
 * information.
 */
static void
parser_conf_info(cmd_t *cmd)
{
	char *info_buf;
	const char *tgt = cmd->cmd_tgt1;
	pool_value_t *pv = NULL;
	pool_elem_t *pe;

	if ((pe = pool_conf_to_elem(conf)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS),
		    gettext(CONFIGURATION), "unknown", get_errstr());

	if (tgt != NULL)
		check_conf_name(cmd);
	else {
		if ((pv = pool_value_alloc()) == NULL)
			die(gettext(ERR_GET_ELEMENT_DETAILS),
			    gettext(CONFIGURATION), "unknown", get_errstr());
		if (pool_get_property(conf, pe, "system.name", pv) ==
		    POC_INVAL ||
		    pool_value_get_string(pv, &tgt) != PO_SUCCESS)
			die(gettext(ERR_GET_ELEMENT_DETAILS),
			    gettext(CONFIGURATION), "unknown", get_errstr());
	}
	if ((info_buf = pool_conf_info(conf, PO_TRUE)) == NULL) {
		die(gettext(ERR_GET_ELEMENT_DETAILS), gettext(CONFIGURATION),
		    tgt, get_errstr());
	}
	if (pv != NULL) {
		pool_value_free(pv);
	}
	(void) printf("%s\n", info_buf);
	free(info_buf);
}

static void
parser_pool_info(cmd_t *cmd)
{
	pool_t *pool;
	char *info_buf;

	if ((pool = pool_get_pool(conf, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());

	if ((info_buf = pool_info(conf, pool, PO_TRUE)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS), gettext(POOL),
		    cmd->cmd_tgt1, get_errstr());
	(void) printf("%s\n", info_buf);
	free(info_buf);
}

static void
parser_resource_info(cmd_t *cmd, const char *type)
{
	pool_resource_t *resource;
	char *info_buf;

	if ((resource = pool_get_resource(conf, type, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(RESOURCE),
		    cmd->cmd_tgt1, get_errstr());

	if ((info_buf = pool_resource_info(conf, resource, PO_TRUE)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS), gettext(RESOURCE),
		    cmd->cmd_tgt1, get_errstr());
	(void) printf("%s\n", info_buf);
	free(info_buf);
}

static void
parser_pset_info(cmd_t *cmd)
{
	parser_resource_info(cmd, PSET);
}

static void
parser_cpu_info(cmd_t *cmd)
{
	pool_component_t *comp;
	char *info_buf;

	if ((comp = get_cpu(cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(CPU),
		    cmd->cmd_tgt1, get_errstr());
	if ((info_buf = pool_component_info(conf, comp, PO_TRUE)) == NULL) {
		die(gettext(ERR_GET_ELEMENT_DETAILS), gettext(CPU),
		    cmd->cmd_tgt1, get_errstr());
	}
	(void) printf("%s\n", info_buf);
	free(info_buf);
}

/*
 * Create Commands
 * Invoke the appropriate libpool create function and perform any requested
 * property operations.
 */
static void
parser_conf_create(cmd_t *cmd)
{
	const char *tmp_name;
	pool_elem_t *pe;

	if (conf != NULL && pool_conf_status(conf) >= POF_VALID)
		pool_conf_close(conf);
	if (pool_conf_open(conf, conf_file, PO_CREAT) != 0) {
		die(gettext(ERR_CREATE_ELEMENT), gettext(CONFIGURATION),
		    cmd->cmd_tgt1, get_errstr());
	}
	tmp_name = cmd->cmd_tgt1;
	cmd->cmd_tgt1 = cmd->cmd_tgt2;
	cmd->cmd_tgt2 = tmp_name;
	parser_conf_rename(cmd);
	if ((pe = pool_conf_to_elem(conf)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS),
		    gettext(CONFIGURATION), "unknown", get_errstr());
	prop_list_walk(cmd, pe);
}

static void
parser_pool_create(cmd_t *cmd)
{
	pool_t *pool;

	if ((pool = pool_create(conf, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_CREATE_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());
	prop_list_walk(cmd, pool_to_elem(conf, pool));
}

static void
parser_resource_create(cmd_t *cmd, const char *type)
{
	pool_resource_t *resource;

	if ((resource = pool_resource_create(conf, type, cmd->cmd_tgt1))
	    == NULL)
		die(gettext(ERR_CREATE_ELEMENT), type, cmd->cmd_tgt1,
		    get_errstr());

	process_min_max(resource);

	prop_list_walk(cmd, pool_resource_to_elem(conf, resource));
}

static void
parser_pset_create(cmd_t *cmd)
{
	parser_resource_create(cmd, PSET);
}

/*
 * Rename Commands
 * Rename the target by calling pool_put_property for the name property.
 */
static void
parser_rename(cmd_t *cmd, pool_elem_t *pe, const char *name)
{
	pool_value_t *pv;

	if ((pv = pool_value_alloc()) == NULL) {
		die(gettext(ERR_ALLOC_ELEMENT), gettext(RESOURCE),
		    get_errstr());
	}
	pool_value_set_string(pv, cmd->cmd_tgt2);
	if (pool_put_property(conf, pe, name, pv) != 0)
		die(gettext(ERR_PUT_PROPERTY), name, get_errstr());
	pool_value_free(pv);
}

static void
parser_conf_rename(cmd_t *cmd)
{
	pool_elem_t *pe;

	if ((pe = pool_conf_to_elem(conf)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS),
		    gettext(CONFIGURATION), "unknown", get_errstr());

	if (cmd->cmd_tgt1 != NULL)
		check_conf_name(cmd);

	parser_rename(cmd, pe, SYSTEM_NAME);
}

static void
parser_pool_rename(cmd_t *cmd)
{
	pool_t *pool;

	if ((pool = pool_get_pool(conf, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());

	parser_rename(cmd, pool_to_elem(conf, pool), POOL_NAME);
}

static void
parser_pset_rename(cmd_t *cmd)
{
	pool_resource_t *resource;

	if ((resource = pool_get_resource(conf, PSET, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(PSET), cmd->cmd_tgt1,
		    get_errstr());

	parser_rename(cmd, pool_resource_to_elem(conf, resource), PSET_NAME);
}

/*
 * Destroy Commands
 * Invoke the appropriate libpool destroy function to remove the target of the
 * command from the configuration.
 */
static void
parser_conf_destroy(cmd_t *cmd)
{
	if (cmd->cmd_tgt1 != NULL)
		check_conf_name(cmd);

	if (pool_conf_remove(conf) != 0)
		die(gettext(ERR_DESTROY_ELEMENT), gettext(CONFIGURATION),
		    cmd->cmd_tgt1, get_errstr());
}

static void
parser_pool_destroy(cmd_t *cmd)
{
	pool_t *pool;

	if ((pool = pool_get_pool(conf, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());

	if (pool_destroy(conf, pool) != 0)
		die(gettext(ERR_DESTROY_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());
}

static void
parser_resource_destroy(cmd_t *cmd, const char *type)
{
	pool_resource_t *resource;

	if ((resource = pool_get_resource(conf, type, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), type, cmd->cmd_tgt1,
		    get_errstr());

	if (pool_resource_destroy(conf, resource) != 0)
		die(gettext(ERR_DESTROY_ELEMENT), type, cmd->cmd_tgt1,
		    get_errstr());
}

static void
parser_pset_destroy(cmd_t *cmd)
{
	parser_resource_destroy(cmd, PSET);
}

/*
 * Modify Commands
 * Perform any requested property operations.
 */
static void
parser_conf_modify(cmd_t *cmd)
{
	pool_elem_t *pe;

	if ((pe = pool_conf_to_elem(conf)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS),
		    gettext(CONFIGURATION), "unknown", get_errstr());

	if (cmd->cmd_tgt1 != NULL)
		check_conf_name(cmd);

	prop_list_walk(cmd, pe);
}

static void
parser_pool_modify(cmd_t *cmd)
{
	pool_t *pool;

	if ((pool = pool_get_pool(conf, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());
	prop_list_walk(cmd, pool_to_elem(conf, pool));
}

static void
parser_resource_modify(cmd_t *cmd, const char *type)
{
	pool_resource_t *resource;

	if ((resource = pool_get_resource(conf, type, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(RESOURCE),
		    cmd->cmd_tgt1, get_errstr());

	process_min_max(resource);

	prop_list_walk(cmd, pool_resource_to_elem(conf, resource));
}

static void
parser_pset_modify(cmd_t *cmd)
{
	parser_resource_modify(cmd, PSET);
}

static void
parser_cpu_modify(cmd_t *cmd)
{
	pool_component_t *comp;

	if ((comp = get_cpu(cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(CPU),
		    cmd->cmd_tgt1, get_errstr());
	prop_list_walk(cmd, pool_component_to_elem(conf, comp));
}

/*
 * Discover Commands
 * Invoke the libpool pool_conf_open function so that discovery will be
 * performed.
 */

/*ARGSUSED*/
static void
parser_conf_discover(cmd_t *cmd)
{
	struct utsname utsname;

	if (strcmp(conf_file, pool_dynamic_location()) == 0)
		return;

	if (uname(&utsname) < 0)
		die(gettext(ERR_CREATE_ELEMENT), gettext(CONFIGURATION),
		    "unknown", get_errstr());

	if (conf != NULL && pool_conf_status(conf) >= POF_VALID)
		pool_conf_close(conf);
	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY) != 0) {
		die(gettext(ERR_CREATE_ELEMENT), gettext(CONFIGURATION),
		    utsname.nodename, get_errstr());
	}
	if (pool_conf_export(conf, conf_file, POX_NATIVE) != 0) {
		die(gettext(ERR_CREATE_ELEMENT), gettext(CONFIGURATION),
		    utsname.nodename, get_errstr());
	}
	(void) pool_conf_close(conf);
	if (pool_conf_open(conf, conf_file, PO_RDWR) != 0) {
		die(gettext(ERR_CREATE_ELEMENT), gettext(CONFIGURATION),
		    utsname.nodename, get_errstr());
	}
}

/*
 * Associate Commands
 * Walk the list of specified associations so that the target pool will be
 * associated with the required resources.
 */

static void
parser_pool_associate(cmd_t *cmd)
{
	pool_t *pool;

	if ((pool = pool_get_pool(conf, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(POOL), cmd->cmd_tgt1,
		    get_errstr());
	assoc_list_walk(cmd, pool);
}

/*
 * Assign Commands
 * Walk the list of specified assignations so that the required
 * components will be assigned to the target resource.
 */

static void
parser_resource_xtransfer(cmd_t *cmd)
{
	pool_resource_t *resource;

	if ((resource = pool_get_resource(conf, PSET, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(RESOURCE),
		    cmd->cmd_tgt1, get_errstr());
	transfer_list_walk(cmd, resource);
}

/*
 * Transfer Commands
 * Transfer the specified quantity of resource between the src and the tgt.
 */

static void
parser_resource_transfer(cmd_t *cmd)
{
	pool_resource_t *src;
	pool_resource_t *tgt;

	if ((src = pool_get_resource(conf, PSET, cmd->cmd_tgt1)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(RESOURCE),
		    cmd->cmd_tgt1, get_errstr());
	if ((tgt = pool_get_resource(conf, PSET, cmd->cmd_tgt2)) == NULL)
		die(gettext(ERR_LOCATE_ELEMENT), gettext(RESOURCE),
		    cmd->cmd_tgt2, get_errstr());
	if (pool_resource_transfer(conf, src, tgt, cmd->cmd_qty) != PO_SUCCESS)
		die(gettext(ERR_XFER_QUANTITY), cmd->cmd_qty,
		    cmd->cmd_tgt1, cmd->cmd_tgt2, get_errstr());
}

/*
 * arg_parse() puts the parser into command parsing mode. Create a tmpfile
 * and instruct the parser to read instructions from this location by setting
 * yyin to the value returned by tmpfile. Write the command into the file.
 * Then seek back to to the start of the file so that the parser can read
 * the instructions.
 */
static void
arg_parse(const char *command)
{
	if ((yyin = tmpfile()) == NULL)
		die(gettext(ERR_CMD_FILE_INIT), strerror(errno));
	if (fwrite(command, strlen(command), 1, yyin) != 1)
		die(gettext(ERR_CMD_FILE_INIT), strerror(errno));
	if (fseek(yyin, 0, SEEK_SET) != 0)
		die(gettext(ERR_CMD_FILE_INIT), strerror(errno));
}

/*
 * file_parse() puts the parser into command file parsing mode. Firstly check
 * to see if the user wishes to parse from standard input, if so do nothing.
 * Attempt to open the specified file and instruct the parser to read
 * instructions from this location by setting yyin to the value returned by
 * fopen.
 */
static void
file_parse(const char *file)
{
	if (strcmp(file, "-") == 0)
		return;

	if ((yyin = fopen(file, "r")) == NULL) {
		die(gettext(ERR_CMD_FILE_INIT), strerror(errno));
	}
}

/*
 * free_cmd() releases the resources associated with the supplied cmd parameter.
 */
static void
free_cmd(cmd_t *cmd)
{
	prop_t *prop = cmd->cmd_prop_list;
	assoc_t *assoc = cmd->cmd_assoc_list;

	free((void *)cmd->cmd_tgt1);
	free((void *)cmd->cmd_tgt2);
	while (prop != NULL) {
		prop_t *tmp = prop;
		prop = prop->prop_next;
		pool_value_free(tmp->prop_value);
		free((void *)tmp->prop_name);
		free(tmp);
	}
	while (assoc != NULL) {
		assoc_t *tmp = assoc;
		assoc = assoc->assoc_next;
		free((void *)tmp->assoc_name);
		free(tmp);
	}
	free(cmd);
}

/*
 * alloc_cmd() allocates the required resources for a cmd_t. On failure, a
 * warning is issued and NULL is returned.
 */
static cmd_t *
alloc_cmd(void)
{
	cmd_t *cmd;

	if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
		warn(gettext(ERR_CMD_LINE_ALLOC));
		return (NULL);
	}

	(void) memset(cmd, 0, sizeof (cmd_t));

	return (cmd);
}

/*
 * alloc_prop() allocates the required resources for a prop_t. On failure, a
 * warning is issued and NULL is returned. The prop_t is initialised with
 * the prop_op_t parameter.
 */
static prop_t *
alloc_prop(prop_op_t op)
{
	prop_t *prop;

	if ((prop = malloc(sizeof (prop_t))) == NULL) {
		warn(gettext(ERR_PROP_ALLOC));
		return (NULL);
	}

	(void) memset(prop, 0, sizeof (prop_t));
	if ((prop->prop_value = pool_value_alloc()) == NULL) {
		warn(gettext(ERR_PROP_ALLOC));
		free(prop);
		return (NULL);
	}
	prop->prop_op = op;
	return (prop);
}

/*
 * alloc_assoc() allocates the required resources for an assoc_t. On failure, a
 * warning is issued and NULL is returned. The assoc_t is initialised with
 * the type and name of the association.
 */
static assoc_t *
alloc_assoc(int type, const char *name)
{
	assoc_t *assoc;

	if ((assoc = malloc(sizeof (assoc_t))) == NULL) {
		warn(gettext(ERR_ASSOC_ALLOC));
		return (NULL);
	}
	(void) memset(assoc, 0, sizeof (assoc_t));
	assoc->assoc_type = type;
	assoc->assoc_name = name;
	return (assoc);
}

/*
 * check_conf_name() ensures the the name of the system in the configuration
 * which is being manipulated matches the name of the system in the command.
 * If not, the command is terminated with an appropriate error message.
 */
static void
check_conf_name(cmd_t *cmd)
{
	pool_value_t *pv;
	const char *name;
	pool_elem_t *pe;

	if ((pe = pool_conf_to_elem(conf)) == NULL)
		die(gettext(ERR_GET_ELEMENT_DETAILS),
		    gettext(CONFIGURATION), "unknown", get_errstr());


	if ((pv = pool_value_alloc()) == NULL) {
		die(gettext(ERR_ALLOC_ELEMENT), gettext(RESOURCE),
		    get_errstr());
	}

	if (pool_get_property(conf, pe, SYSTEM_NAME, pv)
	    == POC_INVAL)
		die(gettext(ERR_GET_PROPERTY), gettext(SYSTEM_NAME),
		    get_errstr());

	if (pool_value_get_string(pv, &name) == PO_FAIL)
		die(gettext(ERR_GET_PROPERTY), gettext(SYSTEM_NAME),
		    get_errstr());

	if (strcmp(cmd->cmd_tgt1, name) != 0) {
		die(gettext(ERR_WRONG_SYSTEM_NAME), cmd->cmd_tgt1);
	}
	pool_value_free(pv);
}

/*
 * usage() display brief or verbose help for the poolcfg(1) command.
 */
static void
usage(int help)
{
	if (help >= 1)
		(void) fprintf(stderr, gettext(USAGE1), cmdname, cmdname,
		    cmdname);
	if (help >= 2)
		(void) fprintf(stderr, gettext(USAGE2));
	exit(E_USAGE);
}

/*
 * prop_list_walk() walks the property manipulation requests and either puts
 * or removes the property as appropriate.
 */
static void
prop_list_walk(cmd_t *cmd, pool_elem_t *pe)
{
	prop_t *prop;

	for (prop = cmd->cmd_prop_list; prop != NULL; prop = prop->prop_next) {
		switch (prop->prop_op) {
		case po_create:
			if (pool_put_property(conf, pe, prop->prop_name,
			    prop->prop_value) != 0)
				die(gettext(ERR_PUT_PROPERTY),
				    prop->prop_name, get_errstr());
			break;
		case po_remove:
			if (pool_rm_property(conf, pe, prop->prop_name) != 0)
				die(gettext(ERR_REMOVE_PROPERTY),
				    prop->prop_name, get_errstr());
			break;
		}
	}
}

/*
 * assoc_list_walk() walks the resource association requests and attempts
 * to associate the pool with the specified resource.
 */
static void
assoc_list_walk(cmd_t *cmd, pool_t *pool)
{
	assoc_t *assoc;

	for (assoc = cmd->cmd_assoc_list; assoc != NULL;
	    assoc = assoc->assoc_next) {
		pool_resource_t *resource;

		switch (assoc->assoc_type) {
		case PCE_PSET:
			if ((resource = pool_get_resource(conf,
			    PSET, assoc->assoc_name)) == NULL)
				die(gettext(ERR_LOCATE_ELEMENT), gettext(PSET),
				    assoc->assoc_name, get_errstr());
			break;
		default:
			die(gettext(ERR_UNKNOWN_RESOURCE),
			    assoc->assoc_type);
			break;
		}
		if (pool_associate(conf, pool, resource) != 0)
			die(gettext(ERR_ASSOC_RESOURCE), assoc->assoc_name,
			    get_errstr());
	}
}

/*
 * transfer_list_walk() walks the component assign requests and attempts
 * to assign the component with the specified resource.
 */
static void
transfer_list_walk(cmd_t *cmd, pool_resource_t *tgt)
{
	assoc_t *assoc;

	for (assoc = cmd->cmd_assoc_list; assoc != NULL;
	    assoc = assoc->assoc_next) {
		pool_component_t *comp;
		pool_resource_t *src;
		pool_component_t *xfer[2] = {NULL};

		if ((comp = get_cpu(assoc->assoc_name)) == NULL)
			die(gettext(ERR_LOCATE_ELEMENT), gettext(CPU),
			    assoc->assoc_name, get_errstr());
		if ((src = pool_get_owning_resource(conf, comp)) == NULL)
			die(gettext(ERR_XFER_COMPONENT), gettext(COMPONENT),
			    assoc->assoc_name, cmd->cmd_tgt1, get_errstr());
		xfer[0] = comp;
		if (pool_resource_xtransfer(conf, src, tgt, xfer) !=
		    PO_SUCCESS)
			die(gettext(ERR_XFER_COMPONENT), gettext(COMPONENT),
			    assoc->assoc_name, cmd->cmd_tgt1, get_errstr());
	}
}

/*
 * terminate() is invoked when poolcfg exits. It cleans up
 * configurations and closes the parser input stream.
 */
static void
terminate(void)
{
	if (conf != NULL) {
		(void) pool_conf_close(conf);
		pool_conf_free(conf);
	}
	if (yyin != stdin)
		(void) fclose(yyin);
}

/*
 * get_cpu() takes the name of a CPU components and attempts to locate
 * the element with that name. If the name is not formatted correctly
 * (i.e. contains non-numeric characters) then the function terminates
 * execution. If the components cannot be uniquely identified by the
 * name, then NULL is returned.
 */
static pool_component_t *
get_cpu(const char *name)
{
	pool_component_t **components;
	uint_t nelem;
	int64_t sysid;
	pool_value_t *vals[3] = {NULL};
	pool_component_t *ret;
	const char *c;

	if ((vals[0] = pool_value_alloc()) == NULL)
		return (NULL);
	if ((vals[1] = pool_value_alloc()) == NULL) {
		pool_value_free(vals[0]);
		return (NULL);
	}
	if (pool_value_set_string(vals[0], "cpu") != PO_SUCCESS ||
	    pool_value_set_name(vals[0], "type") != PO_SUCCESS) {
		pool_value_free(vals[0]);
		pool_value_free(vals[1]);
		return (NULL);
	}

	for (c = name; *c != '\0'; c++) {
		if (!isdigit(*c)){
			pool_value_free(vals[0]);
			pool_value_free(vals[1]);
			die(gettext(ERR_LOCATE_ELEMENT), gettext(CPU),
			    cmd->cmd_tgt1, gettext("CPU id should only contain "
			    "digits"));
		}
	}
	sysid = strtoll(name, NULL, 0);
	if (errno == ERANGE || errno == EINVAL) {
		pool_value_free(vals[0]);
		pool_value_free(vals[1]);
		return (NULL);
	}
	pool_value_set_int64(vals[1], sysid);
	if (pool_value_set_name(vals[1], CPU_SYSID) != PO_SUCCESS) {
		pool_value_free(vals[0]);
		pool_value_free(vals[1]);
		return (NULL);
	}
	if ((components = pool_query_components(conf, &nelem, vals)) ==
	    NULL) {
		pool_value_free(vals[0]);
		pool_value_free(vals[1]);
		return (NULL);
	}
	if (nelem != 1) {
		free(components);
		pool_value_free(vals[0]);
		pool_value_free(vals[1]);
		return (NULL);
	}
	pool_value_free(vals[0]);
	pool_value_free(vals[1]);
	ret = components[0];
	free(components);
	return (ret);
}

/*
 * process_min_max() ensures that "min" and "max" properties are
 * processed correctly by poolcfg. libpool enforces validity
 * constraints on these properties and so it's important that changes
 * to them are supplied to the library in the correct order.
 */
void
process_min_max(pool_resource_t *resource)
{
	prop_t *minprop = NULL;
	prop_t *maxprop = NULL;
	prop_t *prop;

	/*
	 * Before walking the list of properties, it has to be checked
	 * to ensure there are no clashes between min and max. If
	 * there are, then process these properties immediately.
	 */
	for (prop = cmd->cmd_prop_list; prop != NULL; prop = prop->prop_next) {
		const char *pos;

		if ((pos = strstr(prop->prop_name, min_suffix)) != NULL)
			if (pos == prop->prop_name + strlen(prop->prop_name)
			    - 4)
				minprop = prop;
		if ((pos = strstr(prop->prop_name, max_suffix)) != NULL)
			if (pos == prop->prop_name + strlen(prop->prop_name)
			    - 4)
				maxprop = prop;
	}
	if (minprop && maxprop) {
		pool_value_t *pv;
		uint64_t smin, smax, dmax;
		const char *type;
		char *prop_name;
		pool_elem_t *pe = pool_resource_to_elem(conf, resource);

		if ((pv = pool_value_alloc()) == NULL)
			die(gettext(ERR_NOMEM));

		(void) pool_get_property(conf, pe, "type", pv);
		(void) pool_value_get_string(pv, &type);

		if ((prop_name = malloc(strlen(type) + strlen(max_suffix)
		    + 1)) == NULL)
			die(gettext(ERR_NOMEM));

		(void) sprintf(prop_name, "%s%s", type, max_suffix);
		(void) pool_get_property(conf, pe, prop_name, pv);
		(void) pool_value_get_uint64(pv, &dmax);

		(void) pool_value_get_uint64(minprop->prop_value, &smin);

		(void) pool_value_get_uint64(maxprop->prop_value, &smax);
		if (smin < dmax) {
			(void) pool_put_property(conf, pe,
			minprop->prop_name, minprop->prop_value);
		} else {
			(void) pool_put_property(conf, pe,
			maxprop->prop_name, maxprop->prop_value);
		}
		free((void *)prop_name);
		pool_value_free(pv);
	}
}
