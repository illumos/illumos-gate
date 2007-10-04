
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%{
#pragma ident	"%Z%%M%	%I%	%E% SMI"
%}

%{

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <locale.h>
#include <sys/utsname.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#ifdef HAVE_LIBTECLA
#include <libtecla.h>
#endif
#include "parsertypes.h"
#include "filebench.h"
#include "utils.h"
#include "stats.h"
#include "vars.h"
#include "eventgen.h"
#ifdef HAVE_LIBTECLA
#include "auto_comp.h"
#endif

int dofile = FS_FALSE;
static const char cmdname[] = "filebench";
static const char cmd_options[] = "pa:f:hi:s:m:";
static void usage(int);

static cmd_t *cmd = NULL;		/* Command being processed */
#ifdef HAVE_LIBTECLA
static GetLine *gl;			/* GetLine resource object */
#endif

char *execname;
char *fscriptname;
int noproc = 0;
var_t *var_list = NULL;
pidlist_t *pidlist = NULL;
char *cwd = NULL;
FILE *parentscript = NULL;
	
/* yacc externals */
extern FILE *yyin;
extern int yydebug;
extern void yyerror(char *s);

/* utilities */
static void terminate(void);
static cmd_t *alloc_cmd(void);
static attr_t *alloc_attr(void);
static attr_t *get_attr(cmd_t *cmd, int64_t name);
static attr_t *get_attr_integer(cmd_t *cmd, int64_t name);
static attr_t *get_attr_bool(cmd_t *cmd, int64_t name);
static var_t *alloc_var(void);
static var_t *get_var(cmd_t *cmd, int64_t name);
static list_t *alloc_list();

/* Info Commands */
static void parser_show(cmd_t *);
static void parser_list(cmd_t *);

/* Define Commands */
static void parser_proc_define(cmd_t *);
static void parser_thread_define(cmd_t *, procflow_t *, int instances);
static void parser_flowop_define(cmd_t *, threadflow_t *);
static void parser_file_define(cmd_t *);
static void parser_fileset_define(cmd_t *);

/* Create Commands */
static void parser_proc_create(cmd_t *);
static void parser_thread_create(cmd_t *);
static void parser_flowop_create(cmd_t *);
static void parser_file_create(cmd_t *);
static void parser_fileset_create(cmd_t *);

/* Shutdown Commands */
static void parser_proc_shutdown(cmd_t *);
static void parser_filebench_shutdown(cmd_t *cmd);

/* Other Commands */
static void parser_foreach_integer(cmd_t *cmd);
static void parser_foreach_string(cmd_t *cmd);
static void parser_sleep(cmd_t *cmd);
static void parser_sleep_variable(cmd_t *cmd);
static void parser_log(cmd_t *cmd);
static void parser_statscmd(cmd_t *cmd);
static void parser_statsdump(cmd_t *cmd);
static void parser_statsxmldump(cmd_t *cmd);
static void parser_echo(cmd_t *cmd);
static void parser_usage(cmd_t *cmd);
static void parser_vars(cmd_t *cmd);
static void parser_printvars(cmd_t *cmd);
static void parser_system(cmd_t *cmd);
static void parser_statssnap(cmd_t *cmd);
static void parser_directory(cmd_t *cmd);
static void parser_eventgen(cmd_t *cmd);
static void parser_run(cmd_t *cmd);
static void parser_run_variable(cmd_t *cmd);
static void parser_help(cmd_t *cmd);
static void arg_parse(const char *command);
static void parser_abort(int arg);

%}

%union {
	int64_t	 ival;
	uchar_t  bval;
	char *	 sval;
	fs_u	 val;
	cmd_t	 *cmd;
	attr_t	 *attr;
	list_t	 *list;
}

%start commands

%token FSC_LIST FSC_DEFINE FSC_EXEC FSC_QUIT FSC_DEBUG FSC_CREATE
%token FSC_SLEEP FSC_STATS FSC_FOREACH FSC_SET FSC_SHUTDOWN FSC_LOG
%token FSC_SYSTEM FSC_FLOWOP FSC_EVENTGEN FSC_ECHO FSC_LOAD FSC_RUN
%token FSC_USAGE FSC_HELP FSC_VARS
%token FSV_STRING FSV_VAL_INT FSV_VAL_BOOLEAN FSV_VARIABLE FSV_WHITESTRING
%token FST_INT FST_BOOLEAN
%token FSE_FILE FSE_PROC FSE_THREAD FSE_CLEAR FSE_ALL FSE_SNAP FSE_DUMP
%token FSE_DIRECTORY FSE_COMMAND FSE_FILESET FSE_XMLDUMP
%token FSK_SEPLST FSK_OPENLST FSK_CLOSELST FSK_ASSIGN FSK_IN FSK_QUOTE
%token FSK_DIRSEPLST
%token FSA_SIZE FSA_PREALLOC FSA_PARALLOC FSA_PATH FSA_REUSE
%token FSA_PROCESS FSA_MEMSIZE FSA_RATE FSA_CACHED
%token FSA_IOSIZE FSA_FILE FSA_WSS FSA_NAME FSA_RANDOM FSA_INSTANCES
%token FSA_DSYNC FSA_TARGET FSA_ITERS FSA_NICE FSA_VALUE FSA_BLOCKING
%token FSA_HIGHWATER FSA_DIRECTIO FSA_DIRWIDTH FSA_FD FSA_SRCFD FSA_ROTATEFD
%token FSA_NAMELENGTH FSA_FILESIZE FSA_ENTRIES FSA_FILESIZEGAMMA
%token FSA_DIRGAMMA FSA_USEISM

%type <ival> FSV_VAL_INT
%type <bval> FSV_VAL_BOOLEAN
%type <sval> FSV_STRING
%type <sval> FSV_WHITESTRING
%type <sval> FSV_VARIABLE
%type <sval> FSK_ASSIGN

%type <ival> FSC_LIST FSC_DEFINE FSC_SET FSC_LOAD FSC_RUN
%type <ival> FSE_FILE FSE_PROC FSE_THREAD FSE_CLEAR FSC_HELP

%type <sval> name
%type <ival> entity
%type <val>  value

%type <cmd> command inner_commands load_command run_command
%type <cmd> list_command define_command debug_command create_command
%type <cmd> sleep_command stats_command set_command shutdown_command
%type <cmd> foreach_command log_command system_command flowop_command
%type <cmd> eventgen_command quit_command flowop_list thread_list
%type <cmd> thread echo_command usage_command help_command vars_command

%type <attr> attr_op attr_ops
%type <attr> attr_value
%type <list> integer_seplist string_seplist string_list var_string_list var_string
%type <list> whitevar_string whitevar_string_list
%type <ival> attrs_define_file attrs_define_thread attrs_flowop attrs_define_fileset
%type <ival> attrs_define_proc attrs_eventgen
%type <ival> attr_name

%%

commands: commands command
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	if ($2->cmd != NULL)
		$2->cmd($2);

	free($2);
}
| commands error
{
	if (dofile)
		YYABORT;
}
|;

inner_commands: command
{
	filebench_log(LOG_DEBUG_IMPL, "inner_command %zx", $1);
	$$ = $1;
}
| inner_commands command
{
	cmd_t *list = NULL;
	cmd_t *list_end = NULL;

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->cmd_next)
		list_end = list;

	list_end->cmd_next = $2;

	filebench_log(LOG_DEBUG_IMPL,
	    "inner_commands adding cmd %zx to list %zx", $2, $1);

	$$ = $1;
};

command:
  define_command
| debug_command
| eventgen_command
| create_command
| echo_command
| usage_command
| vars_command
| foreach_command
| help_command
| list_command
| load_command
| log_command
| run_command
| set_command
| shutdown_command
| sleep_command
| stats_command
| system_command
| quit_command;

foreach_command: FSC_FOREACH
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	filebench_log(LOG_DEBUG_IMPL, "foreach_command %zx", $$);
}
| foreach_command FSV_VARIABLE FSK_IN integer_seplist FSK_OPENLST inner_commands FSK_CLOSELST
{
	cmd_t *cmd, *inner_cmd;
	list_t *list;

	$$ = $1;
	$$->cmd_list = $6;
	$$->cmd_tgt1 = $2;
	$$->cmd_param_list = $4;
	$$->cmd = parser_foreach_integer;

	for (list = $$->cmd_param_list; list != NULL;
	    list = list->list_next) {
		for (inner_cmd = $$->cmd_list;
		    inner_cmd != NULL;
		    inner_cmd = inner_cmd->cmd_next) {
			filebench_log(LOG_DEBUG_IMPL,
			    "packing foreach: %zx %s=%lld, cmd %zx",
			    $$,
			    $$->cmd_tgt1,
			    *list->list_integer, inner_cmd);
		}
	}
}| foreach_command FSV_VARIABLE FSK_IN string_seplist FSK_OPENLST inner_commands FSK_CLOSELST
{
	cmd_t *cmd, *inner_cmd;
	list_t *list;

	$$ = $1;
	$$->cmd_list = $6;
	$$->cmd_tgt1 = $2;
	$$->cmd_param_list = $4;
	$$->cmd = parser_foreach_string;

	for (list = $$->cmd_param_list; list != NULL;
	    list = list->list_next) {
		for (inner_cmd = $$->cmd_list;
		    inner_cmd != NULL;
		    inner_cmd = inner_cmd->cmd_next) {
			filebench_log(LOG_DEBUG_IMPL,
			    "packing foreach: %zx %s=%s, cmd %zx",
			    $$,
			    $$->cmd_tgt1,
			    *list->list_string, inner_cmd);
		}
	}
};

integer_seplist: FSV_VAL_INT
{
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_integer = integer_alloc($1);
}
| integer_seplist FSK_SEPLST FSV_VAL_INT
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_integer = integer_alloc($3);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
};

string_seplist: FSK_QUOTE FSV_WHITESTRING FSK_QUOTE
{
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);
}
| string_seplist FSK_SEPLST FSK_QUOTE FSV_WHITESTRING FSK_QUOTE
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	if (($$ = alloc_list()) == NULL)
			YYERROR;

	$$->list_string = string_alloc($4);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
};

eventgen_command: FSC_EVENTGEN
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = &parser_eventgen;
}
| eventgen_command attr_ops
{
	$1->cmd_attr_list = $2;
};

system_command: FSC_SYSTEM whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd_param_list = $2;
	$$->cmd = parser_system;
};

echo_command: FSC_ECHO whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd_param_list = $2;
	$$->cmd = parser_echo;
};

usage_command: FSC_USAGE whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd_param_list = $2;
	$$->cmd = parser_usage;
};

vars_command: FSC_VARS
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd = parser_printvars;
};

string_list: FSV_VARIABLE
{
	if (($$ = alloc_list()) == NULL)
			YYERROR;

	$$->list_string = string_alloc($1);
}
| string_list FSK_SEPLST FSV_VARIABLE
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($3);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
};

var_string: FSV_VARIABLE
{
	if (($$ = alloc_list()) == NULL)
			YYERROR;

	$$->list_string = string_alloc($1);
}
| FSV_STRING
{
	if (($$ = alloc_list()) == NULL)
			YYERROR;

	$$->list_string = string_alloc($1);
};

var_string_list: var_string
{
	$$ = $1;
}| var_string FSV_STRING
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add string */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;

}| var_string FSV_VARIABLE
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add variable */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
} |var_string_list FSV_STRING
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add string */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;

}| var_string_list FSV_VARIABLE
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add variable */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
};

whitevar_string: FSK_QUOTE FSV_VARIABLE
{
	if (($$ = alloc_list()) == NULL)
			YYERROR;

	$$->list_string = string_alloc($2);
}
| FSK_QUOTE FSV_WHITESTRING
{
	if (($$ = alloc_list()) == NULL)
			YYERROR;

	$$->list_string = string_alloc($2);
};

whitevar_string_list: whitevar_string FSV_WHITESTRING
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add string */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;

}| whitevar_string FSV_VARIABLE
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add variable */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
} |whitevar_string_list FSV_WHITESTRING
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add string */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;

}| whitevar_string_list FSV_VARIABLE
{
	list_t *list = NULL;
	list_t *list_end = NULL;

	/* Add variable */
	if (($$ = alloc_list()) == NULL)
		YYERROR;

	$$->list_string = string_alloc($2);

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->list_next)
		list_end = list;
	list_end->list_next = $$;
	$$ = $1;
}| whitevar_string_list FSK_QUOTE
{
	$$ = $1;
}| whitevar_string FSK_QUOTE
{
	$$ = $1;
};

list_command: FSC_LIST
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = &parser_list;
};

log_command: FSC_LOG whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = &parser_log;
	$$->cmd_param_list = $2;
};

debug_command: FSC_DEBUG FSV_VAL_INT
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = NULL;
	filebench_shm->debug_level = $2;
	if (filebench_shm->debug_level > 9)
		yydebug = 1;
};

set_command: FSC_SET FSV_VARIABLE FSK_ASSIGN FSV_VAL_INT
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	var_assign_integer($2, $4);
	if (parentscript) {
		$$->cmd_tgt1 = $2;
		parser_vars($$);
	}
	$$->cmd = NULL;
}
| FSC_SET FSV_VARIABLE FSK_ASSIGN FSK_QUOTE FSV_WHITESTRING FSK_QUOTE
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	var_assign_string($2, $5);
	if (parentscript) {
		$$->cmd_tgt1 = $2;
		parser_vars($$);
	}
	$$->cmd = NULL;
}| FSC_SET FSV_VARIABLE FSK_ASSIGN FSV_STRING
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	var_assign_string($2, $4);
	if (parentscript) {
		$$->cmd_tgt1 = $2;
		parser_vars($$);
	}
	$$->cmd = NULL;
}| FSC_SET FSV_VARIABLE FSK_ASSIGN FSV_VARIABLE
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	var_assign_var($2, $4);
	if (parentscript) {
		$$->cmd_tgt1 = $2;
		parser_vars($$);
	}
	$$->cmd = NULL;
};

stats_command: FSC_STATS FSE_SNAP
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = (void (*)(struct cmd *))&parser_statssnap;
	break;

}
| FSC_STATS FSE_CLEAR
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = (void (*)(struct cmd *))&stats_clear;

}
| FSC_STATS FSE_DIRECTORY var_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd_param_list = $3;
	$$->cmd = (void (*)(struct cmd *))&parser_directory;

}
| FSC_STATS FSE_COMMAND whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd_param_list = $3;
	$$->cmd = parser_statscmd;

}| FSC_STATS FSE_DUMP whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd_param_list = $3;
	$$->cmd = parser_statsdump;
}| FSC_STATS FSE_XMLDUMP whitevar_string_list
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	$$->cmd_param_list = $3;
	$$->cmd = parser_statsxmldump;
};

quit_command: FSC_QUIT
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_filebench_shutdown;
};

flowop_list: flowop_command
{
	$$ = $1;
}| flowop_list flowop_command
{
	cmd_t *list = NULL;
	cmd_t *list_end = NULL;

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->cmd_next)
		list_end = list;

	list_end->cmd_next = $2;

	filebench_log(LOG_DEBUG_IMPL,
	    "flowop_list adding cmd %zx to list %zx", $2, $1);

	$$ = $1;
};

thread: FSE_THREAD attr_ops FSK_OPENLST flowop_list FSK_CLOSELST
{
	/*
	 * Allocate a cmd node per thread, with a
	 * list of flowops attached to the cmd_list
	 */
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd_list = $4;
	$$->cmd_attr_list = $2;
};

thread_list: thread
{
	$$ = $1;
}| thread_list thread
{
	cmd_t *list = NULL;
	cmd_t *list_end = NULL;

	/* Find end of list */
	for (list = $1; list != NULL;
	    list = list->cmd_next)
		list_end = list;

	list_end->cmd_next = $2;

	filebench_log(LOG_DEBUG_IMPL,
	    "thread_list adding cmd %zx to list %zx", $2, $1);

	$$ = $1;
};

define_command: FSC_DEFINE FSE_PROC attr_ops FSK_OPENLST thread_list FSK_CLOSELST
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = &parser_proc_define;
	$$->cmd_list = $5;
	$$->cmd_attr_list = $3;

}| FSC_DEFINE FSE_FILE
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = &parser_file_define;
}| FSC_DEFINE FSE_FILESET
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = &parser_fileset_define;
}
| define_command attr_ops
{
	$1->cmd_attr_list = $2;
};

create_command: FSC_CREATE entity
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	switch ($2) {
	case FSE_PROC:
		$$->cmd = &parser_proc_create;
		break;
	case FSE_FILE:
		$$->cmd = &parser_file_create;
		break;
	case FSE_FILESET:
		$$->cmd = &parser_fileset_create;
		break;
	default:
		filebench_log(LOG_ERROR, "unknown entity", $2);
		YYERROR;
	}

};

shutdown_command: FSC_SHUTDOWN entity
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	switch ($2) {
	case FSE_PROC:
		$$->cmd = &parser_proc_shutdown;
		break;
	default:
		filebench_log(LOG_ERROR, "unknown entity", $2);
		YYERROR;
	}

};

sleep_command: FSC_SLEEP FSV_VAL_INT
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_sleep;
	$$->cmd_qty = $2;
}
| FSC_SLEEP FSV_VARIABLE
{
	vinteger_t *integer;

	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_sleep_variable;
	$$->cmd_tgt1 = fb_stralloc($2);
};

run_command: FSC_RUN FSV_VAL_INT
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_run;
	$$->cmd_qty = $2;
}
| FSC_RUN FSV_VARIABLE
{
	vinteger_t *integer;

	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_run_variable;
	$$->cmd_tgt1 = fb_stralloc($2);
}
| FSC_RUN
{
	vinteger_t *integer;

	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_run;
	$$->cmd_qty = 60UL;
};

help_command: FSC_HELP
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd = parser_help;
};

flowop_command: FSC_FLOWOP name
{
	if (($$ = alloc_cmd()) == NULL)
		YYERROR;
	$$->cmd_name = fb_stralloc($2);
}
| flowop_command attr_ops
{
	$1->cmd_attr_list = $2;
};

load_command: FSC_LOAD FSV_STRING
{
	FILE *newfile;
	char loadfile[128];

	if (($$ = alloc_cmd()) == NULL)
		YYERROR;

	(void) strcpy(loadfile, $2);
	(void) strcat(loadfile, ".f");

	if ((newfile = fopen(loadfile, "r")) == NULL) {
		(void) strcpy(loadfile, FILEBENCHDIR);
		(void) strcat(loadfile, "/workloads/");
		(void) strcat(loadfile, $2);
		(void) strcat(loadfile, ".f");
		if ((newfile = fopen(loadfile, "r")) == NULL) {
			filebench_log(LOG_ERROR, "Cannot open %s", loadfile);
			YYERROR;
		}
	}

	parentscript = yyin;
	yyin = newfile;
	yy_switchfileparent(yyin);
};

entity: FSE_PROC {$$ = FSE_PROC;}
| FSE_THREAD {$$ = FSE_THREAD;}
| FSE_FILESET {$$ = FSE_FILESET;}
| FSE_FILE {$$ = FSE_FILE;};

value: FSV_VAL_INT { $$.i = $1;}
| FSV_STRING { $$.s = $1;}
| FSV_VAL_BOOLEAN { $$.b = $1;};

name: FSV_STRING;

attr_ops: attr_op
{
	$$ = $1;
}
| attr_ops FSK_SEPLST attr_op
{
	attr_t *attr = NULL;
	attr_t *list_end = NULL;

	for (attr = $1; attr != NULL;
	    attr = attr->attr_next)
		list_end = attr; /* Find end of list */

	list_end->attr_next = $3;

	$$ = $1;
};

attr_op: attr_name FSK_ASSIGN attr_value
{
	$$ = $3;
	$$->attr_name = $1;
}
| attr_name
{
	if (($$ = alloc_attr()) == NULL)
		YYERROR;
	$$->attr_name = $1;
}

attr_name: attrs_define_file
|attrs_define_fileset
|attrs_define_thread
|attrs_define_proc
|attrs_flowop
|attrs_eventgen;

attrs_define_proc:
FSA_NICE { $$ = FSA_NICE;}
|FSA_INSTANCES { $$ = FSA_INSTANCES;};

attrs_define_file:
FSA_SIZE { $$ = FSA_SIZE;}
| FSA_PATH { $$ = FSA_PATH;}
| FSA_REUSE { $$ = FSA_REUSE;}
| FSA_PREALLOC { $$ = FSA_PREALLOC;}
| FSA_PARALLOC { $$ = FSA_PARALLOC;};

attrs_define_fileset:
FSA_SIZE { $$ = FSA_SIZE;}
| FSA_PATH { $$ = FSA_PATH;}
| FSA_DIRWIDTH { $$ = FSA_DIRWIDTH;}
| FSA_PREALLOC { $$ = FSA_PREALLOC;}
| FSA_FILESIZEGAMMA { $$ = FSA_FILESIZEGAMMA;}
| FSA_DIRGAMMA { $$ = FSA_DIRGAMMA;}
| FSA_CACHED { $$ = FSA_CACHED;}
| FSA_ENTRIES { $$ = FSA_ENTRIES;};

attrs_define_thread:
FSA_PROCESS { $$ = FSA_PROCESS;}
|FSA_MEMSIZE { $$ = FSA_MEMSIZE;}
|FSA_USEISM { $$ = FSA_USEISM;}
|FSA_INSTANCES { $$ = FSA_INSTANCES;};

attrs_flowop:
FSA_WSS { $$ = FSA_WSS;}
|FSA_FILE { $$ = FSA_FILE;}
|FSA_NAME { $$ = FSA_NAME;}
|FSA_RANDOM { $$ = FSA_RANDOM;}
|FSA_FD { $$ = FSA_FD;}
|FSA_SRCFD { $$ = FSA_SRCFD;}
|FSA_ROTATEFD { $$ = FSA_ROTATEFD;}
|FSA_DSYNC { $$ = FSA_DSYNC;}
|FSA_DIRECTIO { $$ = FSA_DIRECTIO;}
|FSA_TARGET { $$ = FSA_TARGET;}
|FSA_ITERS { $$ = FSA_ITERS;}
|FSA_VALUE { $$ = FSA_VALUE;}
|FSA_BLOCKING { $$ = FSA_BLOCKING;}
|FSA_HIGHWATER { $$ = FSA_HIGHWATER;}
|FSA_IOSIZE { $$ = FSA_IOSIZE;};

attrs_eventgen:
FSA_RATE { $$ = FSA_RATE;};

attr_value: var_string_list {
	if (($$ = alloc_attr()) == NULL)
		YYERROR;
	$$->attr_param_list = $1;
} | FSV_STRING
{
	if (($$ = alloc_attr()) == NULL)
		YYERROR;
	$$->attr_string = string_alloc($1);
} | FSV_VAL_INT {
	if (($$ = alloc_attr()) == NULL)
		YYERROR;
	$$->attr_integer = integer_alloc($1);
} | FSV_VARIABLE {
	if (($$ = alloc_attr()) == NULL)
		YYERROR;
	$$->attr_integer = var_ref_integer($1);
	$$->attr_string = var_ref_string($1);
};

%%

/*
 *  The following 'c' routines implement the various commands defined in the
 * above yacc parser code. The yacc portion checks the syntax of the commands
 * found in a workload file, or typed on interactive command lines, parsing
 * the commands' parameters into lists. The lists are then passed in a cmd_t
 * struct for each command to its related routine in the following section
 * for actual execution. This section also includes a few utility routines
 * and the main entry point for the program.
 */

/*
 * Entry point for filebench. Processes command line arguements. The -f
 * option will read in a workload file (the full name and extension must
 * must be given). The -a, -s, -m and -i options are used by worker process
 * to receive their name, the base address of shared memory, its path, and
 * the process' instance number, respectively. This information is supplied
 * by the master process when it execs worker processes under the process
 * model of execution. If the worker process arguments are passed then main
 * will call the procflow_exec routine which creates worker threadflows and
 * flowops and executes the procflow's portion of the workload model until
 * completion. If worker process arguments are not passed to the process,
 * then it becomes the master process for a filebench run. It initializes
 * the various filebench components and either executes the supplied workload
 * file, or enters interactive mode.
 */

int
main(int argc, char *argv[])
{
	int opt;
	int docmd = FS_FALSE;
	int instance;
	char procname[128];
	caddr_t shmaddr;
	char dir[MAXPATHLEN];
#ifdef HAVE_SETRLIMIT
	struct rlimit rlp;
#endif
#ifdef HAVE_LIBTECLA
	char *line;
#else
	char line[1024];
#endif
	char shmpathtmp[1024];

#ifdef HAVE_SETRLIMIT
	/* Set resource limits */
	(void) getrlimit(RLIMIT_NOFILE, &rlp);
	rlp.rlim_cur = rlp.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rlp);
#endif

	yydebug = 0;
	execname = argv[0];
	*procname = 0;
	cwd = getcwd(dir, MAXPATHLEN);

	while ((opt = getopt(argc, argv, cmd_options)) != (int)EOF) {

		switch (opt) {
		case 'h':
			usage(2);
			break;

		case 'p':
			noproc = 1;
			break;

		case 'f':
			if (optarg == NULL)
				usage(1);
			if ((yyin = fopen(optarg, "r")) == NULL) {
				(void) fprintf(stderr,
				    "Cannot open file %s", optarg);
				exit(1);
			}
			dofile = FS_TRUE;
			fscriptname = optarg;

			break;

		case 'a':
			if (optarg == NULL)
				usage(1);
			sscanf(optarg, "%s", &procname[0]);
			break;

		case 's':
			if (optarg == NULL)
				usage(1);
#if defined(_LP64) || (__WORDSIZE == 64)
			sscanf(optarg, "%llx", &shmaddr);
#else
			sscanf(optarg, "%x", &shmaddr);
#endif
			break;

		case 'm':
			if (optarg == NULL)
				usage(1);
			sscanf(optarg, "%s", shmpathtmp);
			shmpath = shmpathtmp;
			break;

		case 'i':
			if (optarg == NULL)
				usage(1);
			sscanf(optarg, "%d", &instance);
			break;

		case '?':
		default:
			usage(1);
			break;
		}
	}

#ifdef USE_PROCESS_MODEL
	if (!(*procname))
#endif
	printf("FileBench Version %s\n", FILEBENCH_VERSION);
	filebench_init();

#ifdef USE_PROCESS_MODEL
	if (*procname) {
		pid = getpid();

		if (ipc_attach(shmaddr) < 0) {
			filebench_log(LOG_ERROR, "Cannot attach shm for %s",
			    procname);
			exit(1);
		}

		if (procflow_exec(procname, instance) < 0) {
			filebench_log(LOG_ERROR, "Cannot startup process %s",
			    procname);
			exit(1);
		}
		exit(1);
	}
#endif

	pid = getpid();
	ipc_init();

	if (fscriptname)
		(void) strcpy(filebench_shm->fscriptname, fscriptname);

	flowop_init();
	stats_init();
	eventgen_init();

	signal(SIGINT, parser_abort);

	if (dofile)
		yyparse();
	else {
#ifdef HAVE_LIBTECLA
		if ((gl = new_GetLine(MAX_LINE_LEN, MAX_CMD_HIST)) == NULL) {
			filebench_log(LOG_ERROR,
			    "Failed to create GetLine object");
			filebench_shutdown(1);
		}

		if (gl_customize_completion(gl, NULL, command_complete)) {
			filebench_log(LOG_ERROR,
			    "Failed to register auto-completion function");
			filebench_shutdown(1);
		}

		while (line = gl_get_line(gl, FILEBENCH_PROMPT, NULL, -1)) {
			arg_parse(line);
			yyparse();
		}

		del_GetLine(gl);
#else
		while (!feof(stdin)) {
			printf(FILEBENCH_PROMPT);
			fflush(stdout);
			if (fgets(line, sizeof (line), stdin) == NULL) {
				if (errno == EINTR)
					continue;
				else
					break;
			}
			arg_parse(line);
			yyparse();
		}
		printf("\n");
#endif	/* HAVE_LIBTECLA */
	}

	parser_filebench_shutdown((cmd_t *)0);

	return (0);
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
		filebench_log(LOG_FATAL,
		    "Cannot create tmpfile: %s", strerror(errno));

	if (fwrite(command, strlen(command), 1, yyin) != 1)
		filebench_log(LOG_FATAL,
		    "Cannot write tmpfile: %s", strerror(errno));

	if (fseek(yyin, 0, SEEK_SET) != 0)
		filebench_log(LOG_FATAL,
		    "Cannot seek tmpfile: %s", strerror(errno));
}

/*
 * Converts a list of var_strings or ordinary strings to a single ordinary
 * string. It returns a pointer to the string (in malloc'd memory) if found,
 * or NULL otherwise.
 */
char *
parser_list2string(list_t *list)
{
	list_t *l;
	char *string;
	char *tmp;
	vinteger_t *integer;

	if ((string = malloc(MAXPATHLEN)) == NULL) {
		filebench_log(LOG_ERROR, "Failed to allocate memory");
		return (NULL);
	}

	*string = 0;


	/* Format args */
	for (l = list; l != NULL;
	    l = l->list_next) {
		filebench_log(LOG_DEBUG_SCRIPT,
		    "converting string '%s'", *l->list_string);

		if ((tmp = var_to_string(*l->list_string)) != NULL) {
			(void) strcat(string, tmp);
			free(tmp);
		} else {
			(void) strcat(string, *l->list_string);
		}
	}
	return (string);
}

/*
 * If the list just contains a single string starting with '$', then find
 * or create the named var and return the var's var_string component.
 * Otherwise, convert the list to a string, and allocate a var_string
 * containing a copy of that string. On failure either returns NULL
 * or shuts down the run.
 */
var_string_t
parser_list2varstring(list_t *list)
{
	/* Special case - variable name */
	if ((list->list_next == NULL) && (*(*list->list_string) == '$'))
		return (var_ref_string(*list->list_string));

	return (string_alloc(parser_list2string(list)));
}

/*
 * Looks for the var named in list_string of the first element of the
 * supplied list. If found, returns the var_integer portion of the var.
 * If the var is not found, cannot be allocated, the supplied list is
 * NULL, or the list_string filed is empty, returns NULL.
 */
var_integer_t
parser_list2integer(list_t *list)
{
	var_integer_t v;

	if (list && (*(list->list_string) != NULL)) {
		v = var_ref_integer(*(list->list_string));
		return (v);
	}

	return (NULL);
}

/*
 * Sets the event generator rate from the attribute supplied with the
 * command. If the attribute doesn't exist the routine does nothing.
 */
static void
parser_eventgen(cmd_t *cmd)
{
	attr_t *attr;
	vinteger_t rate;

	/* Get the rate from attribute */
	if (attr = get_attr_integer(cmd, FSA_RATE)) {
		if (attr->attr_integer) {
			filebench_log(LOG_VERBOSE,
			    "Eventgen: %lld per second",
			    *attr->attr_integer);
			eventgen_setrate(*attr->attr_integer);
		}
	}

}

/*
 * Assigns the designated integer variable successive values from the
 * supplied comma seperated integer list. After each successive integer
 * assignment, it executes the bracket enclosed list of commands. For
 * example, repeated runs of a workload with increasing io sizes can
 * be done using the following command line:
 * 	foreach $iosize in 2k, 4k, 8k {run 60}
 */
static void
parser_foreach_integer(cmd_t *cmd)
{
	list_t *list = cmd->cmd_param_list;
	cmd_t *inner_cmd;

	for (; list != NULL; list = list->list_next) {
		var_assign_integer(cmd->cmd_tgt1, *list->list_integer);
		filebench_log(LOG_VERBOSE, "Iterating %s=%lld",
		    cmd->cmd_tgt1,
		    *list->list_integer);
		for (inner_cmd = cmd->cmd_list; inner_cmd != NULL;
		    inner_cmd = inner_cmd->cmd_next) {
			inner_cmd->cmd(inner_cmd);
		}
	}
}

/*
 * Similar to parser_foreach_integer(), except takes a list of strings after
 * the "in" token. For example, to run twice using a different directory,
 * perhaps using a different filesystem, the following command line
 * could be used:
 * 	foreach $dir in "/ufs_top/fbt", "/zfs_top/fbt" {run 60)
 */
static void
parser_foreach_string(cmd_t *cmd)
{
	list_t *list = cmd->cmd_param_list;
	cmd_t *inner_cmd;

	for (; list != NULL; list = list->list_next) {
		var_assign_string(cmd->cmd_tgt1, *list->list_string);
		filebench_log(LOG_VERBOSE, "Iterating %s=%s",
		    cmd->cmd_tgt1,
		    *list->list_string);
		for (inner_cmd = cmd->cmd_list; inner_cmd != NULL;
		    inner_cmd = inner_cmd->cmd_next) {
			inner_cmd->cmd(inner_cmd);
		}
	}
}

/*
 * Lists the file name, path name and file size for all defined file objects.
 */
static void
parser_list(cmd_t *cmd)
{
	(void) fileobj_iter(fileobj_print);
}

/*
 * Calls procflow_define() to allocate "instances" number of  procflow(s)
 * (processes) with the supplied name. The default number of instances is
 * one. An optional priority level attribute can be supplied and is stored in
 * pf_nice. Finally the routine loops through the list of inner commands, if
 * any, which are defines for threadflows, and passes them one at a time to
 * parser_thread_define() to allocate threadflow entities for the process(es).
 */
static void
parser_proc_define(cmd_t *cmd)
{
	procflow_t *procflow, template;
	char *name;
	attr_t *attr;
	var_integer_t instances = integer_alloc(1);
	cmd_t *inner_cmd;

	/* Get the name of the process */
	if (attr = get_attr(cmd, FSA_NAME)) {
		name = *attr->attr_string;
	} else {
		filebench_log(LOG_ERROR,
		    "define proc: proc specifies no name");
		filebench_shutdown(1);
	}

	/* Get the memory size from attribute */
	if (attr = get_attr_integer(cmd, FSA_INSTANCES)) {
		filebench_log(LOG_DEBUG_IMPL,
		    "Setting instances = %lld",
		    *attr->attr_integer);
		instances = attr->attr_integer;
	}

	if ((procflow = procflow_define(name, NULL, instances)) == NULL) {
		filebench_log(LOG_ERROR,
		    "Failed to instantiate %d %s process(es)\n",
		    instances, name);
		filebench_shutdown(1);
	}

	/* Get the pri from attribute */
	if (attr = get_attr_integer(cmd, FSA_NICE)) {
		filebench_log(LOG_DEBUG_IMPL, "Setting pri = %lld",
		    *attr->attr_integer);
		procflow->pf_nice = attr->attr_integer;
	} else
		procflow->pf_nice = integer_alloc(0);


	/* Create the list of threads for this process  */
	for (inner_cmd = cmd->cmd_list; inner_cmd != NULL;
	    inner_cmd = inner_cmd->cmd_next) {
		parser_thread_define(inner_cmd, procflow, *instances);
	}
}

/*
 * Calls threadflow_define() to allocate "instances" number of  threadflow(s)
 * (threads) with the supplied name. The default number of instances is
 * one. Two other optional attributes may be supplied, one to set the memory
 * size, stored in tf_memsize, and to select the use of Interprocess Shared
 * Memory, which sets the THREADFLOW_USEISM flag in tf_attrs. Finally
 * the routine loops through the list of inner commands, if any, which are
 * defines for flowops, and passes them one at a time to
 * parser_flowop_define() to allocate flowop entities for the threadflows.
 */
static void
parser_thread_define(cmd_t *cmd, procflow_t *procflow, int procinstances)
{
	threadflow_t *threadflow, template;
	attr_t *attr;
	var_integer_t instances = integer_alloc(1);
	cmd_t *inner_cmd;
	char *name;

	memset(&template, 0, sizeof (threadflow_t));

	/* Get the name of the thread */
	if (attr = get_attr(cmd, FSA_NAME)) {
		name = *attr->attr_string;
	} else {
		filebench_log(LOG_ERROR,
		    "define thread: thread in process %s specifies no name",
		    procflow->pf_name);
		filebench_shutdown(1);
	}

	/* Get the number of instances from attribute */
	if (attr = get_attr_integer(cmd, FSA_INSTANCES)) {
		filebench_log(LOG_DEBUG_IMPL,
		    "define thread: Setting instances = %lld",
		    *attr->attr_integer);
		instances = attr->attr_integer;
	}

	/* Get the memory size from attribute */
	if (attr = get_attr_integer(cmd, FSA_MEMSIZE)) {
		filebench_log(LOG_DEBUG_IMPL,
		    "define thread: Setting memsize = %lld",
		    *attr->attr_integer);
		template.tf_memsize = attr->attr_integer;
	} else
		template.tf_memsize = integer_alloc(0);

	if ((threadflow = threadflow_define(procflow, name,
	    &template, instances)) == NULL) {
		filebench_log(LOG_ERROR,
		    "define thread: Failed to instantiate thread\n");
		filebench_shutdown(1);
	}

	/* Use ISM Memory? */
	if (attr = get_attr(cmd, FSA_USEISM)) {
		threadflow->tf_attrs |= THREADFLOW_USEISM;
	}

	/* Create the list of flowops */
	for (inner_cmd = cmd->cmd_list; inner_cmd != NULL;
	    inner_cmd = inner_cmd->cmd_next) {
		parser_flowop_define(inner_cmd, threadflow);
	}
}

/*
 * Calls flowop_define() to allocate a flowop with the supplied name.
 * The allocated flowop inherits attributes from a base flowop of the
 * same type.  If the new flowop has a file or fileset attribute specified,
 * it must specify a defined fileobj or fileset or an error will be logged.
 * The new flowop may  also have the following attributes set by
 * the program:
 *  - file size (fo_iosize)
 *  - working set size (fo_wss)
 *  - do random io (fo_random)
 *  - do synchronous io (fo_dsync)
 *  - perform each operation multiple times before advancing (fo_iter)
 *  - target name (fo_targetname)
 *  - An integer value (fo_value)
 *  - a file descriptor (fo_fd)
 *  - specify to rotate file descriptors (fo_rotatefd)
 *  - a source fd (fo_srcfdnumber)
 *  - specify a blocking operation (fo_blocking)
 *  - specify a highwater mark (fo_highwater)
 *
 * After all the supplied attributes are stored in their respective locations
 * in the flowop object, the flowop's init function is called. No errors are
 * returned, but the filebench run will be terminated if the flowtype is not
 * specified, a name for the new flowop is not supplied, the flowop_define
 * call fails, or a file or fileset name is supplied but the corresponding
 * fileobj or fileset cannot be located.
 */
static void
parser_flowop_define(cmd_t *cmd, threadflow_t *thread)
{
	flowop_t *flowop, *flowop_type;
	fileobj_t *fileobj;
	char *type = (char *)cmd->cmd_name;
	char *name;
	attr_t *attr;

	/* Get the inherited flowop */
	flowop_type = flowop_find(type);
	if (flowop_type == NULL) {
		filebench_log(LOG_ERROR,
		    "define flowop: flowop type %s not found",
		    type);
		filebench_shutdown(1);
	}

	/* Get the name of the flowop */
	if (attr = get_attr(cmd, FSA_NAME)) {
		name = *attr->attr_string;
	} else {
		filebench_log(LOG_ERROR,
		    "define flowop: flowop %s specifies no name",
		    flowop_type->fo_name);
		filebench_shutdown(1);
	}

	if ((flowop = flowop_define(thread, name,
	    flowop_type, FLOW_MASTER, 0)) == NULL) {
		filebench_log(LOG_ERROR,
		    "define flowop: Failed to instantiate flowop %s\n",
		    cmd->cmd_name);
		filebench_shutdown(1);
	}

	/* Get the filename from attribute */
	if (attr = get_attr(cmd, FSA_FILE)) {
		flowop->fo_file = fileobj_find(*attr->attr_string);
		flowop->fo_fileset = fileset_find(*attr->attr_string);

		if ((flowop->fo_file == NULL) &&
		    (flowop->fo_fileset == NULL)) {
			filebench_log(LOG_ERROR,
			    "define flowop: file %s not found",
			    *attr->attr_string);
			filebench_shutdown(1);
		}
	}

	/* Get the iosize of the op */
	if (attr = get_attr_integer(cmd, FSA_IOSIZE))
		flowop->fo_iosize = attr->attr_integer;
	else
		flowop->fo_iosize = integer_alloc(0);

	/* Get the working set size of the op */
	if (attr = get_attr_integer(cmd, FSA_WSS))
		flowop->fo_wss = attr->attr_integer;
	else
		flowop->fo_wss = integer_alloc(0);

	/* Random I/O? */
	if (attr = get_attr_bool(cmd, FSA_RANDOM))
		flowop->fo_random = attr->attr_integer;
	else
		flowop->fo_random = integer_alloc(0);

	/* Sync I/O? */
	if (attr = get_attr_bool(cmd, FSA_DSYNC))
		flowop->fo_dsync = attr->attr_integer;
	else
		flowop->fo_dsync = integer_alloc(0);

	/* Iterations */
	if (attr = get_attr_integer(cmd, FSA_ITERS))
		flowop->fo_iters = attr->attr_integer;
	else
		flowop->fo_iters = integer_alloc(1);


	/* Target, for wakeup etc */
	if (attr = get_attr(cmd, FSA_TARGET))
		(void) strcpy(flowop->fo_targetname, *attr->attr_string);

	/* Value */
	if (attr = get_attr_integer(cmd, FSA_VALUE))
		flowop->fo_value = attr->attr_integer;
	else
		flowop->fo_value = integer_alloc(0);

	/* FD */
	if (attr = get_attr_integer(cmd, FSA_FD))
		flowop->fo_fdnumber = *attr->attr_integer;

	/* Rotatefd? */
	if (attr = get_attr_bool(cmd, FSA_ROTATEFD))
		flowop->fo_rotatefd = attr->attr_integer;
	else
		flowop->fo_rotatefd = integer_alloc(0);

	/* SRC FD, for copies etc... */
	if (attr = get_attr_integer(cmd, FSA_SRCFD))
		flowop->fo_srcfdnumber = *attr->attr_integer;

	/* Blocking operation? */
	if (attr = get_attr_bool(cmd, FSA_BLOCKING))
		flowop->fo_blocking = attr->attr_integer;
	else
		flowop->fo_blocking = integer_alloc(0);

	/* Blocking operation? */
	if (attr = get_attr_bool(cmd, FSA_DIRECTIO))
		flowop->fo_directio = attr->attr_integer;
	else
		flowop->fo_directio = integer_alloc(0);

	/* Highwater mark */
	if (attr = get_attr_integer(cmd, FSA_HIGHWATER))
		flowop->fo_highwater = attr->attr_integer;
	else
		flowop->fo_highwater = integer_alloc(1);
}

/*
 * Calls fileobj_define() to allocate a fileobj with the supplied name
 * and initializes the fileobj's pathname attribute, fo_path and fo_create,
 * and optionally the fo_prealloc, fo_paralloc, fo_reuse, fo_cached,
 * and fo_size attributes.
 */
static void
parser_file_define(cmd_t *cmd)
{
	fileobj_t *fileobj;
	char *name;
	attr_t *attr;
	var_string_t pathname;

	/* Get the name of the file */
	if (attr = get_attr(cmd, FSA_NAME)) {
		name = *attr->attr_string;
	} else {
		filebench_log(LOG_ERROR,
		    "define file: file specifies no name");
		return;
	}

	if ((fileobj = fileobj_define(name)) == NULL) {
		filebench_log(LOG_ERROR,
		    "define file: failed to instantiate file %s\n",
		    cmd->cmd_name);
		return;
	}

	/* Get the pathname from attribute */
	if ((attr = get_attr(cmd, FSA_PATH)) == NULL) {
		filebench_log(LOG_ERROR,
		    "define file: no pathname specified");
		return;
	}

	/* Expand variables in pathname */
	if ((pathname = parser_list2varstring(attr->attr_param_list))
	    == NULL) {
		filebench_log(LOG_ERROR, "Cannot interpret path");
		return;
	}

	fileobj->fo_path = pathname;

	/* For now, all files are pre-created */
	fileobj->fo_create = integer_alloc(1);

	/* Should we preallocate? */
	if (attr = get_attr_bool(cmd, FSA_PREALLOC)) {
		fileobj->fo_prealloc = attr->attr_integer;
	} else
		fileobj->fo_prealloc = integer_alloc(0);

	/* Should we prealloc in parallel? */
	if (attr = get_attr_bool(cmd, FSA_PARALLOC)) {
		fileobj->fo_paralloc = attr->attr_integer;
	} else
		fileobj->fo_paralloc = integer_alloc(0);

	/* Should we reuse the existing file? */
	if (attr = get_attr_bool(cmd, FSA_REUSE)) {
		fileobj->fo_reuse = attr->attr_integer;
	} else
		fileobj->fo_reuse = integer_alloc(0);

	/* Should we leave in cache? */
	if (attr = get_attr_bool(cmd, FSA_CACHED)) {
		fileobj->fo_cached = attr->attr_integer;
	} else
		fileobj->fo_cached = integer_alloc(0);

	/* Get the size of the file */
	if (attr = get_attr_integer(cmd, FSA_SIZE)) {
		fileobj->fo_size = attr->attr_integer;
	} else
		fileobj->fo_size = integer_alloc(0);

}

/*
 * Calls fileset_define() to allocate a fileset with the supplied name and
 * initializes the fileset's pathname attribute, and optionally the fs_cached,
 * fs_reuse, fs_preallocpercent, fs_prealloc, fs_entries, fs_dirwidth,
 * fs_size, fs_dirgamma, and fs_sizegamma attributes.
 */
static void
parser_fileset_define(cmd_t *cmd)
{
	fileset_t *fileset;
	char *name;
	attr_t *attr;
	var_string_t pathname;

	/* Get the name of the file */
	if (attr = get_attr(cmd, FSA_NAME)) {
		name = *attr->attr_string;
	} else {
		filebench_log(LOG_ERROR,
		    "define file: file specifies no name");
		return;
	}

	if ((fileset = fileset_define(name)) == NULL) {
		filebench_log(LOG_ERROR,
		    "define file: failed to instantiate file %s\n",
		    cmd->cmd_name);
		return;
	}

	/* Get the pathname from attribute */
	if ((attr = get_attr(cmd, FSA_PATH)) == NULL) {
		filebench_log(LOG_ERROR, "define file: no pathname specified");
		return;
	}

	/* Expand variables in pathname */
	if ((pathname = parser_list2varstring(attr->attr_param_list)) == NULL) {
		filebench_log(LOG_ERROR, "Cannot interpret path");
		return;
	}

	fileset->fs_path = pathname;

	/* Should we leave in cache? */
	if (attr = get_attr_bool(cmd, FSA_CACHED)) {
		fileset->fs_cached = attr->attr_integer;
	} else
		fileset->fs_cached = integer_alloc(0);

	/* Should we reuse the existing file? */
	if (attr = get_attr_bool(cmd, FSA_REUSE)) {
		fileset->fs_reuse = attr->attr_integer;
	} else
		fileset->fs_reuse = integer_alloc(0);

	/* How much should we prealloc */
	if ((attr = get_attr_integer(cmd, FSA_PREALLOC)) &&
	    attr->attr_integer) {
		fileset->fs_preallocpercent = attr->attr_integer;
	} else if (attr && !attr->attr_integer) {
		fileset->fs_preallocpercent = integer_alloc(100);
	} else {
		fileset->fs_preallocpercent = integer_alloc(0);
	}

	/* Should we preallocate? */
	if (attr = get_attr_bool(cmd, FSA_PREALLOC)) {
		fileset->fs_prealloc = attr->attr_integer;
	} else
		fileset->fs_prealloc = integer_alloc(0);

	/* Get the size of the fileset */
	if (attr = get_attr_integer(cmd, FSA_ENTRIES)) {
		fileset->fs_entries = attr->attr_integer;
	} else {
		filebench_log(LOG_ERROR, "Fileset has zero entries");
		fileset->fs_entries = integer_alloc(0);
	}

	/* Get the mean dir width of the fileset */
	if (attr = get_attr_integer(cmd, FSA_DIRWIDTH)) {
		fileset->fs_dirwidth = attr->attr_integer;
	} else {
		filebench_log(LOG_ERROR, "Fileset has zero directory width");
		fileset->fs_dirwidth = integer_alloc(0);
	}

	/* Get the mean or absolute size of the file */
	if (attr = get_attr_integer(cmd, FSA_SIZE)) {
		fileset->fs_size = attr->attr_integer;
	} else
		fileset->fs_size = integer_alloc(0);

	/* Get the gamma value for dir width distributions */
	if (attr = get_attr_integer(cmd, FSA_DIRGAMMA)) {
		fileset->fs_dirgamma = attr->attr_integer;
	} else
		fileset->fs_dirgamma = integer_alloc(1500);

	/* Get the gamma value for dir width distributions */
	if (attr = get_attr_integer(cmd, FSA_FILESIZEGAMMA)) {
		fileset->fs_sizegamma = attr->attr_integer;
	} else
		fileset->fs_sizegamma = integer_alloc(1500);
}

/*
 * Creates and starts all defined procflow processes. The call to
 * procflow_init() results in creation of the requested number of
 * process instances for each previously defined procflow. The
 * child processes exec() a new instance of filebench, passing it
 * the instance number and address of the shared memory region.
 * The child processes will then create their threads and flowops.
 * The routine then unlocks the run_lock to allow all the processes'
 * threads to start and  waits for all of them to begin execution.
 * Finally, it records the start time and resets the event generation
 * system.
 */
static void
parser_proc_create(cmd_t *cmd)
{
	if (procflow_init() != 0) {
		filebench_log(LOG_ERROR, "Failed to create processes\n");
		filebench_shutdown(1);
	}

	/* Release the read lock, allowing threads to start */
	(void) pthread_rwlock_unlock(&filebench_shm->run_lock);

	/* Wait for all threads to start */
	if (procflow_allstarted() != 0) {
		filebench_log(LOG_ERROR, "Could not start run");
		return;
	}


	if (filebench_shm->shm_required &&
	    (ipc_ismcreate(filebench_shm->shm_required) < 0)) {
		filebench_log(LOG_ERROR, "Could not allocate shared memory");
		return;
	}

	filebench_shm->starttime = gethrtime();
	eventgen_reset();
}

/*
 * Calls fileobj_init() to create  and optionally pre fill files
 * for all fileobjs on the master list of fileobjs (filelist).
 * If errors are encountered, calls filebench_shutdown()
 * to exit filebench.
 */
static void
parser_file_create(cmd_t *cmd)
{
	fileobj_t *fileobj;

	if (fileobj_init() != 0) {
		filebench_log(LOG_ERROR, "Failed to create files");
		filebench_shutdown(1);
	}
}

/*
 * Calls fileset_createset() to populate all filesets and create all
 * associated, initially existant,  files and subdirectories.
 * If errors are encountered, calls filebench_shutdown()
 * to exit filebench.
 */
static void
parser_fileset_create(cmd_t *cmd)
{
	fileset_t *fileset;

	if (fileset_createset(NULL) != 0) {
		filebench_log(LOG_ERROR, "Failed to create filesets");
		filebench_shutdown(1);
	}
}

/*
 * Shuts down all processes and their associated threads. When finished
 * it deletes interprocess shared memory and resets the event generator.
 * It does not exit the filebench program though.
 */
static void
parser_proc_shutdown(cmd_t *cmd)
{
	filebench_log(LOG_INFO, "Shutting down processes");
	procflow_shutdown();
	if (filebench_shm->shm_required)
		ipc_ismdelete();
	eventgen_reset();
}

/*
 * Ends filebench run after first destoring any interprocess
 * shared memory. The call to filebench_shutdown()
 * also causes filebench to exit.
 */
static void
parser_filebench_shutdown(cmd_t *cmd)
{
	ipc_cleanup();
	filebench_shutdown(1);
}

/*
 * Sleeps for cmd->cmd_qty seconds, one second at a time.
 */
static void
parser_sleep(cmd_t *cmd)
{
	int sleeptime;

	/* check for startup errors */
	if (filebench_shm->f_abort)
		return;

	sleeptime = cmd->cmd_qty;
	filebench_log(LOG_INFO, "Running...");
	while (sleeptime) {
		(void) sleep(1);
		sleeptime--;
		if (filebench_shm->f_abort)
			break;
	}
	filebench_log(LOG_INFO, "Run took %lld seconds...",
	    cmd->cmd_qty - sleeptime);
}

/*
 * Do a file bench run. Calls routines to create file sets, files, and
 * processes. It resets the statistics counters, then sleeps for the runtime
 * passed as an argument to it on the command line in 1 second increments.
 * When it is finished sleeping, it collects a snapshot of the statistics
 * and ends the run.
 */
static void
parser_run(cmd_t *cmd)
{
	int runtime;

	runtime = cmd->cmd_qty;
	parser_fileset_create(cmd);
	parser_file_create(cmd);
	parser_proc_create(cmd);

	/* check for startup errors */
	if (filebench_shm->f_abort)
		return;

	filebench_log(LOG_INFO, "Running...");
	stats_clear();
	while (runtime) {
		(void) sleep(1);
		runtime--;
		if (filebench_shm->f_abort)
			break;
	}
	filebench_log(LOG_INFO, "Run took %lld seconds...",
	    cmd->cmd_qty - runtime);
	parser_statssnap(cmd);
	parser_proc_shutdown(cmd);
}

/*
 * Similar to parser_run, but gets the sleep time from a variable
 * whose name is supplied as an argument to the command.
 */
static void
parser_run_variable(cmd_t *cmd)
{
	vinteger_t *integer = var_ref_integer(cmd->cmd_tgt1);
	int runtime;

	if (integer == NULL) {
		filebench_log(LOG_ERROR, "Unknown variable %s",
		cmd->cmd_tgt1);
		return;
	}

	runtime = *integer;

	/* check for startup errors */
	if (filebench_shm->f_abort)
		return;

	filebench_log(LOG_INFO, "Running...");
	stats_clear();
	while (runtime) {
		(void) sleep(1);
		runtime--;
		if (filebench_shm->f_abort)
			break;
	}
	filebench_log(LOG_INFO, "Run took %lld seconds...",
	    *integer - runtime);
	parser_statssnap(cmd);
}

char *usagestr = NULL;

/*
 * Prints usage string if defined, else just a message requesting load of a
 * personality.
 */
static void
parser_help(cmd_t *cmd)
{
	int runtime;

	if (usagestr) {
		filebench_log(LOG_INFO, "%s", usagestr);
	} else {
		filebench_log(LOG_INFO,
		    "load <personality> (ls "
		    "/usr/benchmarks/filebench/workloads for list)");
	}
}

char *varstr = NULL;

/*
 * Prints the string of all var definitions, if there is one.
 */
static void
parser_printvars(cmd_t *cmd)
{
	int runtime;
	char *str, *c;

	if (varstr) {
		str = strdup(varstr);
		for (c = str; *c != '\0'; c++) {
			if ((char)*c == '$')
				*c = ' ';
		}
		filebench_log(LOG_INFO, "%s", str);
		free(str);
	}
}

/*
 * Used by the SET command to add a var and default value string to the
 * varstr string. It allocates a new, larger varstr string, copies the
 * old contents of varstr into it, then adds the new var string on the end.
 */
static void
parser_vars(cmd_t *cmd)
{
	char *string = cmd->cmd_tgt1;
	char *newvars;

	if (string == NULL)
		return;

	if (dofile)
		return;

	if (varstr == NULL) {
		newvars = malloc(strlen(string) + 2);
		*newvars = 0;
	} else {
		newvars = malloc(strlen(varstr) + strlen(string) + 2);
		(void) strcpy(newvars, varstr);
	}
	(void) strcat(newvars, string);
	(void) strcat(newvars, " ");

	if (varstr)
		free(varstr);

	varstr = newvars;
}

/*
 * Same as parser_sleep, except the sleep time is obtained from a variable
 * whose name is passed to it as an argument on the command line.
 */
static void
parser_sleep_variable(cmd_t *cmd)
{
	vinteger_t *integer = var_ref_integer(cmd->cmd_tgt1);
	int sleeptime;

	if (integer == NULL) {
		filebench_log(LOG_ERROR, "Unknown variable %s",
		cmd->cmd_tgt1);
		return;
	}

	sleeptime = *integer;

	/* check for startup errors */
	if (filebench_shm->f_abort)
		return;

	filebench_log(LOG_INFO, "Running...");
	while (sleeptime) {
		(void) sleep(1);
		sleeptime--;
		if (filebench_shm->f_abort)
			break;
	}
	filebench_log(LOG_INFO, "Run took %lld seconds...",
	    *integer - sleeptime);
}

/*
 * Parser log prints the values of a list of variables to the log file.
 * The list of variables is placed on the command line, separated
 * by comas and the entire list is enclosed in quotes.
 * For example, if $dir contains "/export/home/tmp" and $filesize = 1048576,
 * then typing: log "$dir, $filesize" prints: log /export/home/tmp, 1048576
 */
static void
parser_log(cmd_t *cmd)
{
	char *string;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	filebench_log(LOG_VERBOSE, "log %s", string);
	filebench_log(LOG_LOG, "%s", string);
}

/*
 * Implements the stats directory command. changes the directory for
 * dumping statistics to supplied directory path. For example:
 * 	stats directory /tmp
 * changes the stats directory to "/tmp".
 */
static void
parser_directory(cmd_t *cmd)
{
	char newdir[MAXPATHLEN];
	char *dir;

	if ((dir = parser_list2string(cmd->cmd_param_list)) == NULL) {
		filebench_log(LOG_ERROR, "Cannot interpret directory");
		return;
	}

	*newdir = 0;
	/* Change dir relative to cwd if path not fully qualified */
	if (*dir != '/') {
		(void) strcat(newdir, cwd);
		(void) strcat(newdir, "/");
	}
	(void) strcat(newdir, dir);
	(void) mkdir(newdir, 0755);
	filebench_log(LOG_VERBOSE, "Change dir to %s", newdir);
	chdir(newdir);
	free(dir);
}

#define	PIPE_PARENT 1
#define	PIPE_CHILD  0

/*
 * Runs the quoted unix command as a background process. Intended for
 * running statistics gathering utilities such as mpstat while the filebench
 * workload is running. Also records the pid's of the background processes
 * so that parser_statssnap() can terminate them when the run completes.
 */
static void
parser_statscmd(cmd_t *cmd)
{
	char *string;
	pid_t pid;
	pidlist_t *pidlistent;
	int pipe_fd[2];
	int newstdout;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	if ((pipe(pipe_fd)) < 0) {
		filebench_log(LOG_ERROR, "statscmd pipe failed");
		return;
	}

#ifdef HAVE_FORK1
	if ((pid = fork1()) < 0) {
		filebench_log(LOG_ERROR, "statscmd fork failed");
		return;
	}
#elif HAVE_FORK
	if ((pid = fork()) < 0) {
		filebench_log(LOG_ERROR, "statscmd fork failed");
		return;
	}
#else
	Crash! - Need code to deal with no fork1!
#endif /* HAVE_FORK1 */

	if (pid == 0) {

		setsid();

		filebench_log(LOG_VERBOSE,
		    "Backgrounding %s", string);
		/*
		 * Child
		 * - close stdout
		 * - dup to create new stdout
		 * - close pipe fds
		 */
		(void) close(1);

		if ((newstdout = dup(pipe_fd[PIPE_CHILD])) < 0) {
			filebench_log(LOG_ERROR,
			    "statscmd dup failed: %s",
			    strerror(errno));
		}

		(void) close(pipe_fd[PIPE_PARENT]);
		(void) close(pipe_fd[PIPE_CHILD]);

		if (system(string) < 0) {
			filebench_log(LOG_ERROR,
			    "statscmd exec failed: %s",
			    strerror(errno));
		}
		/* Failed! */
		exit(1);

	} else {

		/* Record pid in pidlist for subsequent reaping by stats snap */
		if ((pidlistent = (pidlist_t *)malloc(sizeof (pidlist_t)))
		    == NULL) {
			filebench_log(LOG_ERROR, "pidlistent malloc failed");
			return;
		}

		pidlistent->pl_pid = pid;
		pidlistent->pl_fd = pipe_fd[PIPE_PARENT];
		(void) close(pipe_fd[PIPE_CHILD]);

		/* Add fileobj to global list */
		if (pidlist == NULL) {
			pidlist = pidlistent;
			pidlistent->pl_next = NULL;
		} else {
			pidlistent->pl_next = pidlist;
			pidlist = pidlistent;
		}
	}
}

/*
 * Launches a shell to run the unix command supplied in the argument.
 * The command should be enclosed in quotes, as in:
 * 	system "rm xyz"
 * which would run the "rm" utility to delete the file "xyz".
 */
static void
parser_system(cmd_t *cmd)
{
	char *string;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	filebench_log(LOG_VERBOSE,
	    "Running '%s'", string);

	if (system(string) < 0) {
		filebench_log(LOG_ERROR,
		    "system exec failed: %s",
		    strerror(errno));
	}
	free(string);
}

/*
 * Echos string supplied with command to the log.
 */
static void
parser_echo(cmd_t *cmd)
{
	char *string;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	filebench_log(LOG_INFO, "%s", string);
}


/*
 * Adds the string supplied as the argument to the usage command
 * to the end of the string printed by the help command.
 */
static void
parser_usage(cmd_t *cmd)
{
	char *string;
	char *newusage;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	if (dofile)
		return;

	if (usagestr == NULL) {
		newusage = malloc(strlen(string) + 2);
		*newusage = 0;
	} else {
		newusage = malloc(strlen(usagestr) + strlen(string) + 2);
		(void) strcpy(newusage, usagestr);
	}
	(void) strcat(newusage, "\n");
	(void) strcat(newusage, string);

	if (usagestr)
		free(usagestr);

	usagestr = newusage;

	filebench_log(LOG_INFO, "%s", string);
}

/*
 * Updates the global dump filename with the filename supplied
 * as the command's argument. Then dumps the statistics of each
 * worker flowop into the dump file, followed by a summary of
 * overall totals.
 */
static void
parser_statsdump(cmd_t *cmd)
{
	char *string;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	filebench_log(LOG_VERBOSE,
	    "Stats dump to file '%s'", string);

	stats_dump(string);

	free(string);
}

/*
 * Same as parser_statsdump, but in xml format.
 */
static void
parser_statsxmldump(cmd_t *cmd)
{
	char *string;

	if (cmd->cmd_param_list == NULL)
		return;

	string = parser_list2string(cmd->cmd_param_list);

	if (string == NULL)
		return;

	filebench_log(LOG_VERBOSE,
	    "Stats dump to file '%s'", string);

	stats_xmldump(string);

	free(string);
}

/*
 * Kills off background statistics collection processes, then takes a snapshot
 * of the filebench run's collected statistics using stats_snap() from
 * stats.c.
 */
static void
parser_statssnap(cmd_t *cmd)
{
	pidlist_t *pidlistent;
	int stat;
	pid_t pid;

	for (pidlistent = pidlist; pidlistent != NULL;
	    pidlistent = pidlistent->pl_next) {
		filebench_log(LOG_VERBOSE, "Killing session %d for pid %d",
		    getsid(pidlistent->pl_pid),
		    pidlistent->pl_pid);
		if (pidlistent->pl_fd)
			(void) close(pidlistent->pl_fd);
#ifdef HAVE_SIGSEND
		sigsend(P_SID, getsid(pidlistent->pl_pid), SIGTERM);
#else
		(void) kill(-1, SIGTERM);
#endif

		/* Close pipe */
		if (pidlistent->pl_fd)
			(void) close(pidlistent->pl_fd);

		/* Wait for cmd and all its children */
		while ((pid = waitpid(pidlistent->pl_pid * -1, &stat, 0)) > 0)
			filebench_log(LOG_DEBUG_IMPL,
			"Waited for pid %lld", pid);
	}

	for (pidlistent = pidlist; pidlistent != NULL;
	    pidlistent = pidlistent->pl_next) {
		free(pidlistent);
	}

	pidlist = NULL;
	stats_snap();
}

/*
 * Shutdown filebench.
 */
static void
parser_abort(int arg)
{
	(void) sigignore(SIGINT);
	filebench_log(LOG_INFO, "Aborting...");
	filebench_shutdown(1);
}

/*
 * alloc_cmd() allocates the required resources for a cmd_t. On failure, a
 * filebench_log is issued and NULL is returned.
 */
static cmd_t *
alloc_cmd(void)
{
	cmd_t *cmd;

	if ((cmd = malloc(sizeof (cmd_t))) == NULL) {
		filebench_log(LOG_ERROR, "Alloc cmd failed");
		return (NULL);
	}

	(void) memset(cmd, 0, sizeof (cmd_t));

	return (cmd);
}

/*
 * Frees the resources of a cmd_t and then the cmd_t "cmd" itself.
 */
static void
free_cmd(cmd_t *cmd)
{
	free((void *)cmd->cmd_tgt1);
	free((void *)cmd->cmd_tgt2);
	free(cmd);
}

/*
 * Allocates an attr_t structure and zeros it. Returns NULL on failure, or
 * a pointer to the attr_t.
 */
static attr_t *
alloc_attr()
{
	attr_t *attr;

	if ((attr = malloc(sizeof (attr_t))) == NULL) {
		return (NULL);
	}

	(void) memset(attr, 0, sizeof (attr_t));
	return (attr);
}

/*
 * Searches the attribute list for the command for the named attribute type.
 * The attribute list is created by the parser from the list of attributes
 * supplied with certain commands, such as the define and flowop commands.
 * Returns a pointer to the attribute structure if the named attribute is
 * found, otherwise returns NULL. If the attribute includes a parameter list,
 * the list is converted to a string and stored in the attr_string field of
 * the returned attr_t struct.
 */
static attr_t *
get_attr(cmd_t *cmd, int64_t name)
{
	attr_t *attr;
	attr_t *rtn = NULL;
	char *string;

	for (attr = cmd->cmd_attr_list; attr != NULL;
	    attr = attr->attr_next) {
		filebench_log(LOG_DEBUG_IMPL,
		    "attr %d = %d %llx?",
		    attr->attr_name,
		    name,
		    attr->attr_integer);

		if (attr->attr_name == name)
			rtn = attr;
	}

	if (rtn == NULL)
		return (NULL);

	if (rtn->attr_param_list) {
		filebench_log(LOG_DEBUG_SCRIPT, "attr is param list");
		string = parser_list2string(rtn->attr_param_list);
		if (string != NULL) {
			rtn->attr_string = string_alloc(string);
			filebench_log(LOG_DEBUG_SCRIPT,
			    "attr string %s", string);
		}
	}

	return (rtn);
}

/*
 * Similar to get_attr, but converts the parameter string supplied with the
 * named attribute to an integer and stores the integer in the attr_integer
 * portion of the returned attr_t struct.
 */
static attr_t *
get_attr_integer(cmd_t *cmd, int64_t name)
{
	attr_t *attr;
	attr_t *rtn = NULL;

	for (attr = cmd->cmd_attr_list; attr != NULL;
	    attr = attr->attr_next) {
		if (attr->attr_name == name)
			rtn = attr;
	}

	if (rtn == NULL)
		return (NULL);

	if (rtn->attr_param_list) {
		rtn->attr_integer = parser_list2integer(rtn->attr_param_list);
	}

	return (rtn);
}

/*
 * Similar to get_attr, but converts the parameter string supplied with the
 * named attribute to an integer and stores the integer in the attr_integer
 * portion of the returned attr_t struct. If no parameter string is supplied
 * then it defaults to TRUE (1).
 */
static attr_t *
get_attr_bool(cmd_t *cmd, int64_t name)
{
	attr_t *attr;
	attr_t *rtn = NULL;

	for (attr = cmd->cmd_attr_list; attr != NULL;
	    attr = attr->attr_next) {
		if (attr->attr_name == name)
			rtn = attr;
	}

	if (rtn == NULL)
		return (NULL);

	if (rtn->attr_param_list) {
		rtn->attr_integer = parser_list2integer(rtn->attr_param_list);
	} else if (rtn->attr_integer == 0) {
		rtn->attr_integer = integer_alloc(1);
	}

	return (rtn);
}

/*
 * Allocates memory for a list_t structure, initializes it to zero, and
 * returns a pointer to it. On failure, returns NULL.
 */
static list_t *
alloc_list()
{
	list_t *list;

	if ((list = malloc(sizeof (list_t))) == NULL) {
		return (NULL);
	}

	(void) memset(list, 0, sizeof (list_t));
	return (list);
}


#define	USAGE1	\
"Usage:\n" \
"%s: interpret f script and generate file workload\n" \
"Options:\n" \
"   [-h] Display verbose help\n" \
"   [-p] Disable opening /proc to set uacct to enable truss\n"

#define	PARSER_CMDS \
"create [files|filesets|processes]\n" \
"stats [clear|snap]\n" \
"stats command \"shell command $var1,$var2...\"\n" \
"stats directory <directory>\n" \
"sleep <sleep-value>\n" \
"quit\n\n" \
"Variables:\n" \
"set $var = value\n" \
"    $var   - regular variables\n" \
"    ${var} - internal special variables\n" \
"    $(var) - environment variables\n\n"

#define	PARSER_EXAMPLE \
"Example:\n\n" \
"#!/usr/bin/filebench -f\n" \
"\n" \
"define file name=bigfile,path=bigfile,size=1g,prealloc,reuse\n" \
"define process name=randomizer\n" \
"{\n" \
"  thread random-thread procname=randomizer\n"	\
"  {\n" \
"    flowop read name=random-read,filename=bigfile,iosize=16k,random\n" \
"  }\n" \
"}\n" \
"create files\n" \
"create processes\n" \
"stats clear\n" \
"sleep 30\n" \
"stats snap\n"

/*
 * usage() display brief or verbose help for the filebench(1) command.
 */
static void
usage(int help)
{
	if (help >= 1)
		(void) fprintf(stderr, USAGE1, cmdname);
	if (help >= 2) {

		(void) fprintf(stderr,
		    "\n'f' language definition:\n\n");
		fileobj_usage();
		fileset_usage();
		procflow_usage();
		threadflow_usage();
		flowoplib_usage();
		eventgen_usage();
		(void) fprintf(stderr, PARSER_CMDS);
		(void) fprintf(stderr, PARSER_EXAMPLE);
	}
	exit(E_USAGE);
}

int
yywrap()
{
	char buf[1024];

	if (parentscript) {
		yyin = parentscript;
		yy_switchfilescript(yyin);
		parentscript = NULL;
		return (0);
	} else
		return (1);
}
