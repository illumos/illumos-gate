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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#include <stdio.h>
#include <sys/types.h>

#include "nwamcfg.h"

static cmd_t *cmd = NULL;		/* Command being processed */

/* yacc externals */
extern int yydebug;
extern void yyerror(char *s);

extern boolean_t newline_terminated;

%}

%union {
	int ival;
	char *strval;
	cmd_t *cmd;
}

%start commands

%token CANCEL CLEAR COMMIT CREATE DESTROY END EXIT EXPORT GET HELP
%token LIST REVERT SELECT SET VERIFY WALKPROP
%token LOC NCP NCU ENM WLAN
%token PHYS IP
%token TOKEN EQUAL OPTION
%token UNKNOWN ACTIVATION_MODE CONDITIONS ENABLED
%token TYPE CLASS PARENT PRIORITY_GROUP PRIORITY_MODE
%token LINK_MACADDR LINK_AUTOPUSH LINK_MTU
%token IP_VERSION IPV4_ADDRSRC IPV4_ADDR IPV4_DEFAULT_ROUTE
%token IPV6_ADDRSRC IPV6_ADDR IPV6_DEFAULT_ROUTE
%token ENM_STATE ENM_FMRI ENM_START ENM_STOP
%token LOC_NAMESERVICES LOC_NAMESERVICES_CONFIG
%token LOC_DNS_CONFIGSRC LOC_DNS_DOMAIN LOC_DNS_SERVERS LOC_DNS_SEARCH
%token LOC_NIS_CONFIGSRC LOC_NIS_SERVERS
%token LOC_LDAP_CONFIGSRC LOC_LDAP_SERVERS
%token LOC_DEFAULT_DOMAIN LOC_NFSV4_DOMAIN
%token LOC_IPF_CONFIG LOC_IPF_V6_CONFIG
%token LOC_IPNAT_CONFIG LOC_IPPOOL_CONFIG LOC_IKE_CONFIG LOC_IPSECPOL_CONFIG
%token WLAN_BSSIDS WLAN_PRIORITY WLAN_KEYNAME WLAN_KEYSLOT WLAN_SECURITY_MODE
%token IP_PRIMARY IP_REQHOST

%type <strval> TOKEN EQUAL OPTION
%type <ival> resource1_type LOC NCP ENM WLAN
%type <ival> resource2_type NCU
%type <ival> ncu_class_type PHYS IP
%type <ival> property_type UNKNOWN ACTIVATION_MODE CONDITIONS ENABLED
    TYPE CLASS PARENT PRIORITY_GROUP PRIORITY_MODE
    LINK_MACADDR LINK_AUTOPUSH LINK_MTU
    IP_VERSION IPV4_ADDRSRC IPV4_ADDR IPV4_DEFAULT_ROUTE
    IPV6_ADDRSRC IPV6_ADDR IPV6_DEFAULT_ROUTE
    ENM_STATE ENM_FMRI ENM_START ENM_STOP
    LOC_NAMESERVICES LOC_NAMESERVICES_CONFIG
    LOC_DNS_CONFIGSRC LOC_DNS_DOMAIN LOC_DNS_SERVERS LOC_DNS_SEARCH
    LOC_NIS_CONFIGSRC LOC_NIS_SERVERS
    LOC_LDAP_CONFIGSRC LOC_LDAP_SERVERS
    LOC_DEFAULT_DOMAIN LOC_NFSV4_DOMAIN
    LOC_IPF_CONFIG LOC_IPF_V6_CONFIG
    LOC_IPNAT_CONFIG LOC_IPPOOL_CONFIG LOC_IKE_CONFIG LOC_IPSECPOL_CONFIG
    WLAN_BSSIDS WLAN_PRIORITY WLAN_KEYNAME WLAN_KEYSLOT WLAN_SECURITY_MODE
    IP_PRIMARY IP_REQHOST
%type <cmd> command
%type <cmd> cancel_command CANCEL
%type <cmd> clear_command CLEAR
%type <cmd> commit_command COMMIT
%type <cmd> create_command CREATE
%type <cmd> destroy_command DESTROY
%type <cmd> end_command END
%type <cmd> exit_command EXIT
%type <cmd> export_command EXPORT
%type <cmd> get_command GET
%type <cmd> help_command HELP
%type <cmd> list_command LIST
%type <cmd> revert_command REVERT
%type <cmd> select_command SELECT
%type <cmd> set_command SET
%type <cmd> verify_command VERIFY
%type <cmd> walkprop_command WALKPROP
%type <cmd> terminator

%%

commands: command terminator
	{
		if ($1 != NULL) {
			if ($1->cmd_handler != NULL)
				if (check_scope($1->cmd_num))
					$1->cmd_handler($1);
			free_cmd($1);
		}
		return (0);
	}
	| command error terminator
	{
		if ($1 != NULL)
			free_cmd($1);
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
		return (0);
	}

command: cancel_command
	| clear_command
	| commit_command
	| create_command
	| destroy_command
	| end_command
	| exit_command
	| export_command
	| get_command
	| help_command
	| list_command
	| revert_command
	| select_command
	| set_command
	| verify_command
	| walkprop_command

terminator:	'\n'	{ newline_terminated = B_TRUE; }
	|	';'	{ newline_terminated = B_FALSE; }

cancel_command: CANCEL
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_CANCEL;
		$$->cmd_handler = &cancel_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

clear_command: CLEAR
	{
		command_usage(CMD_CLEAR);
		YYERROR;
	}
	|	CLEAR TOKEN
	{
		properr($2);
		YYERROR;
	}		
	|	CLEAR property_type
	{
		/* clear prop */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_CLEAR;
		$$->cmd_handler = &clear_func;
		$$->cmd_prop_type = $2;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

commit_command: COMMIT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_COMMIT;
		$$->cmd_handler = &commit_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

create_command: CREATE
	{
		command_usage(CMD_CREATE);
		YYERROR;
	}
	|	CREATE TOKEN
	{
		command_usage(CMD_CREATE);
		YYERROR;
	}
	|	CREATE resource1_type
	{
		command_usage(CMD_CREATE);
		YYERROR;
	}
	|	CREATE resource2_type
	{
		command_usage(CMD_CREATE);
		YYERROR;
	}
	|	CREATE resource1_type TOKEN
	{
		/* create enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_CREATE;
		$$->cmd_handler = &create_func;
		$$->cmd_res1_type = $2;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	CREATE resource2_type ncu_class_type TOKEN
	{
		/* create ncu ip/phys test */	  
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_CREATE;
		$$->cmd_handler = &create_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = NULL;
	}
	|	CREATE OPTION TOKEN resource1_type TOKEN
	{
		/* create -t old enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_CREATE;
		$$->cmd_handler = &create_func;
		$$->cmd_res1_type = $4;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = $5;
		$$->cmd_argv[3] = NULL;
	}
	|	CREATE OPTION TOKEN resource2_type ncu_class_type TOKEN
	{
		/* create -t old ncu ip/phys test */	  
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_CREATE;
		$$->cmd_handler = &create_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $4;
		$$->cmd_ncu_class_type = $5;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = $6;
		$$->cmd_argv[3] = NULL;
	}

destroy_command: DESTROY
	{
		command_usage(CMD_DESTROY);
		YYERROR;
	}
	|	DESTROY OPTION
	{
		/* destroy -a */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_DESTROY;
		$$->cmd_handler = &destroy_func;
		$$->cmd_res1_type = -1; /* special value */
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = NULL;
	}
	|	DESTROY resource1_type
	{
		command_usage(CMD_DESTROY);
		YYERROR;
	}
	|	DESTROY resource2_type
	{
		command_usage(CMD_DESTROY);
		YYERROR;
	}
	|	DESTROY resource1_type TOKEN
	{
		/* destroy enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_DESTROY;
		$$->cmd_handler = &destroy_func;
		$$->cmd_res1_type = $2;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	DESTROY resource2_type TOKEN
	{
		/* destroy ncu test (class inferred) */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_DESTROY;
		$$->cmd_handler = &destroy_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = NCU_CLASS_ANY;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	DESTROY resource2_type ncu_class_type TOKEN
	{
		/* destroy ncu ip/phys test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_DESTROY;
		$$->cmd_handler = &destroy_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = NULL;
	}

end_command:	END
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_END;
		$$->cmd_handler = &end_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

exit_command:	EXIT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXIT;
		$$->cmd_handler = &exit_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

export_command:	EXPORT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	EXPORT TOKEN
	{
		command_usage(CMD_EXPORT);
		YYERROR;
	}
 	|	EXPORT OPTION
	{
		/* export -d */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = NULL;
	}
	|	EXPORT OPTION TOKEN
	{
		/* export -f file */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 2;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = NULL;
	}
	|	EXPORT OPTION OPTION TOKEN
	{
		/* export -d -f file */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = $4;
		$$->cmd_argv[3] = NULL;
	}
	|	EXPORT resource1_type TOKEN
	{
		/* export enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_res1_type = $2;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	EXPORT resource2_type TOKEN
	{
		/* export ncu test (all ncu's named test) */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = NCU_CLASS_ANY;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	EXPORT resource2_type ncu_class_type TOKEN
	{
		/* export ncu ip/phys test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = NULL;
	}
	|	EXPORT OPTION TOKEN resource1_type TOKEN
	{
		/* export -f file enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_res1_type = $4;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = $5;
		$$->cmd_argv[3] = NULL;
	}
	|	EXPORT OPTION TOKEN resource2_type TOKEN
	{
		/* export -f file ncu test (all ncu's named test) */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $4;
		$$->cmd_ncu_class_type = NCU_CLASS_ANY;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = $5;
		$$->cmd_argv[3] = NULL;
	}
	|	EXPORT OPTION TOKEN resource2_type ncu_class_type TOKEN
	{
		/* export -f file ncu ip/phys test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_EXPORT;
		$$->cmd_handler = &export_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $4;
		$$->cmd_ncu_class_type = $5;
		$$->cmd_argc = 3;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = $3;
		$$->cmd_argv[2] = $6;
		$$->cmd_argv[3] = NULL;
	}

get_command: GET
	{
		command_usage(CMD_GET);
		YYERROR;
	}
	|	GET TOKEN
	{
		properr($2);
		YYERROR;
	}		
	|	GET property_type
	{
		/* get prop */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_GET;
		$$->cmd_handler = &get_func;
		$$->cmd_prop_type = $2;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	GET OPTION property_type
	{
		/* get -V prop */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_GET;
		$$->cmd_handler = &get_func;
		$$->cmd_prop_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = NULL;
	}

help_command:	HELP
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_HELP;
		$$->cmd_handler = &help_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	HELP TOKEN
	{
		/* help command */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_HELP;
		$$->cmd_handler = &help_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = NULL;
	}

list_command:	LIST
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	LIST TOKEN
	{
		command_usage(CMD_LIST);
		YYERROR;
	}
	|	LIST OPTION
	{
		/* list -a */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = -1; /* special value */
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = NULL;
	}
	|	LIST resource1_type
	{
		command_usage(CMD_LIST);
		YYERROR;
	}
	|	LIST OPTION resource1_type
	{
		command_usage(CMD_LIST);
		YYERROR;
	}
	|	LIST resource2_type
	{
		command_usage(CMD_LIST);
		YYERROR;
	}
	|	LIST OPTION resource2_type
	{
		command_usage(CMD_LIST);
		YYERROR;
	}
	|	LIST OPTION resource2_type ncu_class_type
	{
		command_usage(CMD_LIST);
		YYERROR;
	}
	|	LIST resource1_type TOKEN
	{
		/* list enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = $2;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	LIST resource2_type TOKEN
	{
		/* list ncu test (all ncu's named test) */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = NCU_CLASS_ANY;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	LIST resource2_type ncu_class_type TOKEN
	{
		/* list ncu ip/phys test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = NULL;
	}
	|	LIST OPTION resource1_type TOKEN
	{
		/* list -a enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = $3;
		$$->cmd_argc = 2;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = $2;
		$$->cmd_argv[2] = NULL;
	}
	|	LIST OPTION resource2_type TOKEN
	{
		/* list -a ncu test (all ncu's named test) */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $3;
		$$->cmd_ncu_class_type = NCU_CLASS_ANY;
		$$->cmd_argc = 2;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = $2;
		$$->cmd_argv[2] = NULL;
	}
	|	LIST OPTION resource2_type ncu_class_type TOKEN
	{
		/* list -a ncu ip/phys test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_LIST;
		$$->cmd_handler = &list_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $3;
		$$->cmd_ncu_class_type = $4;
		$$->cmd_argc = 2;
		$$->cmd_argv[0] = $5;
		$$->cmd_argv[1] = $2;
		$$->cmd_argv[2] = NULL;
	}

revert_command: REVERT
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_REVERT;
		$$->cmd_handler = &revert_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

select_command:	SELECT
	{
		command_usage(CMD_SELECT);
		YYERROR;
	}
	|	SELECT TOKEN
	{
		command_usage(CMD_SELECT);
		YYERROR;
	}
	|	SELECT resource1_type
	{
		command_usage(CMD_SELECT);
		YYERROR;
	}
	|	SELECT resource2_type
	{
		command_usage(CMD_SELECT);
		YYERROR;
	}
	|	SELECT resource2_type ncu_class_type
	{
		command_usage(CMD_SELECT);
		YYERROR;
	}
	|	SELECT resource1_type TOKEN
	{
		/* select enm/loc/ncp test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_SELECT;
		$$->cmd_handler = &select_func;
		$$->cmd_res1_type = $2;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	SELECT resource2_type TOKEN
	{
		/* select ncu test (class inferred) */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_SELECT;
		$$->cmd_handler = &select_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = NCU_CLASS_ANY;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $3;
		$$->cmd_argv[1] = NULL;
	}
	|	SELECT resource2_type ncu_class_type TOKEN
	{
		/* select ncu ip/phys test */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_SELECT;
		$$->cmd_handler = &select_func;
		$$->cmd_res1_type = RT1_NCP;
		$$->cmd_res2_type = $2;
		$$->cmd_ncu_class_type = $3;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = NULL;
	}

set_command:	SET
	{
		command_usage(CMD_SET);
		YYERROR;
	}
	|	SET TOKEN
	{
		properr($2);
		YYERROR;
	}
	|	SET property_type EQUAL TOKEN
	{
		/* set prop=value */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_SET;
		$$->cmd_handler = &set_func;
		$$->cmd_prop_type = $2;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $4;
		$$->cmd_argv[1] = NULL;
	}

verify_command: VERIFY
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_VERIFY;
		$$->cmd_handler = &verify_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}

walkprop_command: WALKPROP
	{
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_WALKPROP;
		$$->cmd_handler = &walkprop_func;
		$$->cmd_argc = 0;
		$$->cmd_argv[0] = NULL;
	}
	|	WALKPROP OPTION
	{
		/* walkprop -a */
		if (($$ = alloc_cmd()) == NULL)
			YYERROR;
		cmd = $$;
		$$->cmd_num = CMD_WALKPROP;
		$$->cmd_handler = &walkprop_func;
		$$->cmd_argc = 1;
		$$->cmd_argv[0] = $2;
		$$->cmd_argv[1] = NULL;
	}

resource1_type: LOC	{ $$ = RT1_LOC; }
	|	NCP	{ $$ = RT1_NCP; }
	|	ENM	{ $$ = RT1_ENM; }
	|	WLAN	{ $$ = RT1_WLAN; }

resource2_type: NCU	{ $$ = RT2_NCU; }

ncu_class_type:	PHYS		{ $$ = NCU_CLASS_PHYS; }
	|	IP		{ $$ = NCU_CLASS_IP; }

property_type:	UNKNOWN			{ $$ = PT_UNKNOWN; }
	|	ACTIVATION_MODE		{ $$ = PT_ACTIVATION_MODE; }
	|	CONDITIONS		{ $$ = PT_CONDITIONS; }
	|	ENABLED			{ $$ = PT_ENABLED; }
	|	TYPE			{ $$ = PT_TYPE; }
	|	CLASS			{ $$ = PT_CLASS; }
	|	PARENT			{ $$ = PT_PARENT; }
	|	PRIORITY_GROUP		{ $$ = PT_PRIORITY_GROUP; }
	|	PRIORITY_MODE		{ $$ = PT_PRIORITY_MODE; }
	|	LINK_MACADDR		{ $$ = PT_LINK_MACADDR; }
	|	LINK_AUTOPUSH		{ $$ = PT_LINK_AUTOPUSH; }
	|	LINK_MTU		{ $$ = PT_LINK_MTU; }
	|	IP_VERSION		{ $$ = PT_IP_VERSION; }
	|	IPV4_ADDRSRC		{ $$ = PT_IPV4_ADDRSRC; }
	|	IPV4_ADDR		{ $$ = PT_IPV4_ADDR; }
	|	IPV4_DEFAULT_ROUTE	{ $$ = PT_IPV4_DEFAULT_ROUTE; }
	|	IPV6_ADDRSRC		{ $$ = PT_IPV6_ADDRSRC; }
	|	IPV6_ADDR		{ $$ = PT_IPV6_ADDR; }
	|	IPV6_DEFAULT_ROUTE	{ $$ = PT_IPV6_DEFAULT_ROUTE; }
	|	ENM_FMRI		{ $$ = PT_ENM_FMRI; }
	|	ENM_START		{ $$ = PT_ENM_START; }
	|	ENM_STOP		{ $$ = PT_ENM_STOP; }
	|	LOC_NAMESERVICES	{ $$ = PT_LOC_NAMESERVICES; }
	|	LOC_NAMESERVICES_CONFIG	{ $$ = PT_LOC_NAMESERVICES_CONFIG; }
	|	LOC_DNS_CONFIGSRC	{ $$ = PT_LOC_DNS_CONFIGSRC; }
	|	LOC_DNS_DOMAIN		{ $$ = PT_LOC_DNS_DOMAIN; }
	|	LOC_DNS_SERVERS		{ $$ = PT_LOC_DNS_SERVERS; }
	|	LOC_DNS_SEARCH		{ $$ = PT_LOC_DNS_SEARCH; }
	|	LOC_NIS_CONFIGSRC	{ $$ = PT_LOC_NIS_CONFIGSRC; }
	|	LOC_NIS_SERVERS		{ $$ = PT_LOC_NIS_SERVERS; }
	|	LOC_LDAP_CONFIGSRC	{ $$ = PT_LOC_LDAP_CONFIGSRC; }
	|	LOC_LDAP_SERVERS	{ $$ = PT_LOC_LDAP_SERVERS; }
	|	LOC_DEFAULT_DOMAIN	{ $$ = PT_LOC_DEFAULT_DOMAIN; }
	|	LOC_NFSV4_DOMAIN	{ $$ = PT_LOC_NFSV4_DOMAIN; }
	|	LOC_IPF_CONFIG		{ $$ = PT_LOC_IPF_CONFIG; }
	|	LOC_IPF_V6_CONFIG	{ $$ = PT_LOC_IPF_V6_CONFIG; }
	|	LOC_IPNAT_CONFIG	{ $$ = PT_LOC_IPNAT_CONFIG; }
	|	LOC_IPPOOL_CONFIG	{ $$ = PT_LOC_IPPOOL_CONFIG; }
	|	LOC_IKE_CONFIG		{ $$ = PT_LOC_IKE_CONFIG; }
	|	LOC_IPSECPOL_CONFIG	{ $$ = PT_LOC_IPSECPOL_CONFIG; }
	|	WLAN_BSSIDS		{ $$ = PT_WLAN_BSSIDS; }
	|	WLAN_PRIORITY		{ $$ = PT_WLAN_PRIORITY; }
	|	WLAN_KEYNAME		{ $$ = PT_WLAN_KEYNAME; }
	|	WLAN_KEYSLOT		{ $$ = PT_WLAN_KEYSLOT; }
	|	WLAN_SECURITY_MODE	{ $$ = PT_WLAN_SECURITY_MODE; }
	|	IP_PRIMARY		{ $$ = PT_IP_PRIMARY; }
	|	IP_REQHOST		{ $$ = PT_IP_REQHOST; }

%%
