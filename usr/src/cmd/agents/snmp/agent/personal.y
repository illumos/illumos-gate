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
 * Copyright 1998 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

%}

%start configuration

%token NUMBER
%token MACROS
%token EQUAL
%token OPENBRACKET
%token CLOSEBRACKET
%token IDENTIFIER
%token MIB2
%token SUN
%token ENTERPRISE
%token DOT
%token AGENTS
%token NAME
%token SUBTREES
%token TABLES
%token TABLE
%token COLUMNS
%token INDEXS
%token TIMEOUT
%token PORT
%token QUOTEDSTRING
%token COMA
%token MINUS
%token OPENSQUAREBRACKET
%token CLOSESQUAREBRACKET
%token WATCHDOGTIME

/* support SNMP security(5-13-96) */
%token COMMUNITIES
%token READONLY
%token READWRITE
%token MANAGERS
%token TRAPCOMMUNITY
%token TRAPDESTINATORS
%token ACL
%token ACCESS
%token TRAPNUM
%token HOSTS
%token TRAP

%{
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "pdu.h"

#include "pagent.h"
#include "subtree.h"

/** SNMP security (5-13-96) */
#include "trap.h"
#include "agent_msg.h"
#include "access.h"
#include "snmpd.h"


/***** DEFINE *****/

/*
#define DEBUG_YACC(string) printf("\t\tYACC: %s: %s at line %d\n", string, yytext, yylineno);
*/
#define DEBUG_YACC(string)

#define SNMPRELAY_SUFFIX	".snmprelay"


/***** TYPEDEF *****/

typedef struct _Macro {
	struct _Macro *next_macro;
	char *label;
	Oid name;
} Macro;

#include "table.h"
static int table_index=0;


/*
typedef struct _Table {
	struct _Table *next_table;
	Agent *agent;
	Oid name;
	Subid regTblStartColumn;
	Subid regTblEndColumn;
	Subid regTblStartRow;
	Subid regTblEndRow;
} Table;
*/



/***** STATIC VARIABLES AND FUNCTIONS *****/

/* access control(6-20-96) */
static AccessServer *static_access_server=NULL;
static AccessPolicy *static_access_policy=NULL;
static Community *static_community=NULL;

/* trap filter (6-25-96) */
static SubMember *static_sub_member=NULL;
static Manager *static_host=NULL;
static EFilter *static_filter=NULL;
static int static_trap_low=-1;
static int static_trap_high=-1;

/* snmp security(5-13-96) */
static int community_type = 0;
static char *current_filename = NULL;

/* lexinput points to the current focus point in the config file */
static char *lexinput;

/* first_macro is the begining of the list	*/
/* of the user defined macros			*/

static Macro *first_macro = NULL;


/* first_table is the begining of the list	*/
/* of tables supported by the agents		*/

static Table *first_table = NULL;
static Table *last_table = NULL;


/* the boolean parsing_oid is used to		*/
/* know if we are parsing an			*/
/* object identifier or not.			*/

static int parsing_oid = False;


/* here are the values of the predifined macros	*/
/* that can be used in the configuration file	*/

static Subid subids_mib2[] = { 1, 3, 6, 1, 2, 1 };
static int mib2_len = 6;
static Subid subids_enterprise[] = { 1, 3, 6, 1, 4, 1 };
static int enterprise_len = 6;
static Subid subids_sun[] = { 1, 3, 6, 1, 4, 1, 42 };
static int sun_len = 7;


/* the 2 static variables static_subids and	*/
/* static_len are used when parsing an	*/
/* object identifier. Then the boolean		*/
/* parsing_oid should be true. When a new sub-	*/
/* identifier (or a list of sub-identifiers)	*/
/* is found, we use the function		*/
/* subids_cat to append it to the static_subids.*/

static Subid *static_subids = NULL;
static int static_len = 0;
static int subids_cat(Subid *subids, int len);


/* macro_add() is used to append a macro to	*/
/* the macro list. macro_find is used to find	*/
/* a macro in the macro list			*/

static Macro *macro_add(char *label, Subid *subids, int len);
static Macro *macro_find(char *label);
static void macro_free(Macro *mp);
static void macro_list_delete();


static void table_free(Table *tp);
static void table_list_delete();

extern int SSARegSubagent(Agent *);
extern int SSASubagentOpen(int, char *);
extern int SSARegSubtable(SSA_Table *);

/* static_label is used when parsing a macro	*/
static char *static_label = NULL;

/* static_agent is used when parsing an agent	*/
static Agent *static_agent = NULL;

/* static_table is used when parsing n table	*/
static Table *static_table = NULL;

/* static_inf_value and static_max_value are	*/
/* used when parsing a range			*/
static int static_inf_value = -1;
static int static_sup_value = -1;

static int count;
%}

%%


configuration :	agents | macros agents | snmp_security
		{
			DEBUG_YACC("configuration")
		}

/******************* SNMP security (5-13-96) *********/
snmp_security : acls  trap_block  /*trapcommunity trapdestinators*/
                {
                        DEBUG_YACC("security configuration")
                }

/***************/
/* accesscontrol */
/***************/

acls :	/*empty */ | t_acls t_equal t_openbracket acls_list t_closebracket
		{
			DEBUG_YACC("acls_list")
		}
		| t_acls t_equal t_openbracket error t_closebracket
		{
		  error("BUG: acl stmt parsing error at line %d",yylineno);
		  if(static_access_policy != NULL){
			access_policy_list_free(static_access_policy);
			static_access_policy = NULL;
		  }
		}

acls_list : /*empty*/ | acls_list acl_item 
	{
		DEBUG_YACC("acls_list")
	}

acl_item : t_openbracket 
	{
		static_access_policy = calloc(1,sizeof(AccessPolicy));
		if(static_access_policy == NULL)
		{
			error("calloc() failed");
			YYERROR;
		}
	} communities_stmt acl_access
	{
		if(static_access_policy!=NULL)
			static_access_policy->access_type = community_type;	
	} hosts t_closebracket
	{
		/* create AccessServer */
		/* put the AccessPolicy into AccessServer */
		/* put AccessServer into corresponding manager */
		static_access_server = NULL;
		static_access_policy = NULL;
		static_community = NULL;
		community_type = 0;
	}

communities_stmt :      t_communities t_equal communities_set
        {
                DEBUG_YACC("communities_stmt");
        }

communities_set : communities_set t_coma community_elem | community_elem
	{
		DEBUG_YACC("communities_set");
	}

community_elem : ct_identifier
	{
		if(static_access_policy==NULL){
			error("acl statement error");
			YYERROR;
		}
		/* add community into AccessPolicy */
		static_community = calloc(1, sizeof(Community));
		if(static_community == NULL)
		{
			error("calloc() failed");
			YYERROR;
		}	
		static_community->name = strdup(yytext);
		community_attach(static_access_policy,static_community);
		static_community = NULL;
	}

acl_access:	t_access t_equal acl_access_type
	{
		DEBUG_YACC("acl_access")
	}

acl_access_type : t_readonly | t_readwrite
		{
			DEBUG_YACC("acl_access_type")
		}

hosts : t_managers t_equal hosts_list
        { 
                DEBUG_YACC("hosts") 
        } 

hosts_list : hosts_list t_coma host_item | host_item
	{
		DEBUG_YACC("hosts_list");
	}

host_item :  ct_identifier
	{
		/* add the host item to manager list */
		/* it should return the pointer if exists */
                Manager *res;
 
                DEBUG_YACC("manager_item")
 
                res = manager_add(yytext, error_label);
                if(res==NULL){
                                error("error in %s at line %d: %s",
                                        current_filename? current_filename:
"???",
                                        yylineno, error_label);
                } 
		static_access_server = calloc(1,sizeof(AccessServer));
		if(static_access_server == NULL)
		{
			error("malloc() failed");
			if(static_access_policy) 
			  access_policy_list_free(static_access_policy);
			YYERROR;
		}
		if(static_access_policy!=NULL)
			static_access_policy->count++;
		static_access_server->first_acc_policy = static_access_policy;
		access_server_add_tail(res,static_access_server);
		static_access_server = NULL;
	}


/************/
/* managers */
/************/
 
/*
managers :      t_managers t_equal t_openbracket managers_list t_closebracket
                {
                        DEBUG_YACC("agents")
                }
 
 
managers_list :  | managers_list list_separator manager_item
                {
                        DEBUG_YACC("managers_list")
                }
 
 
manager_item :  ct_identifier
                {
                        Manager *res;
 
                        DEBUG_YACC("manager_item")
 
                        res = manager_add(yytext, error_label);
			if(res==NULL){
                                        error("error in %s at line %d: %s",
                                                current_filename? current_filename:
"???",
                                                yylineno, error_label);
			}
                }
*/

/*** trap hanlding (6-25-96) */
trap_block :	t_trap t_equal t_openbracket trap_list t_closebracket
		{
			DEBUG_YACC("trap_block")
		}
		| t_trap t_equal t_openbracket error t_closebracket
		{
			/* clean up */
			if(static_sub_member != NULL){
			  sub_member_free(static_sub_member);
			  static_sub_member=NULL;
			}	
		}

trap_list : /*empty*/ | trap_list trap_item
	{
		DEBUG_YACC("trap_list")
	}

trap_item : t_openbracket
	{
		/* create submember */
		static_sub_member = calloc(1,sizeof(SubMember));
		if(static_sub_member == NULL)
		{
			error("malloc() failed");
			YYERROR;
		}
	} trap_community_string trap_interest_hosts
	{
		/* attach submember to subgroup */
	} enterprise_list t_closebracket
	{
		static_sub_member = NULL;
	}

trap_community_string : t_trapcommunity t_equal ct_identifier
	{
		/* set the community field in submember */
		if(static_sub_member != NULL)
		{
			static_sub_member->community_string = strdup(yytext);
			if(static_sub_member == NULL)
			{	
				error(ERR_MSG_ALLOC);
				YYERROR;
			}
		}else{
			error("BUG: missing trap community name");
		}
	}

trap_interest_hosts : t_hosts t_equal trap_interest_hosts_list
	{
		DEBUG_YACC("trap_interest_hosts")
	}

trap_interest_hosts_list : trap_interest_hosts_list t_coma 
		 trap_interest_host_item | trap_interest_host_item
	{
		DEBUG_YACC("trap_interest_hosts_list")
	}

trap_interest_host_item : ct_identifier
	{
		DEBUG_YACC("trap_interest_host_item")
		/* attach host to the submember */
		if(static_sub_member==NULL){
		 	error("trap statement error");
			YYERROR;
		}else{
		  static_host = calloc(1,sizeof(Manager));
		  if(static_host == NULL)
		  {
			error("malloc() failed");
			YYERROR;
		  }
		  static_host->name = strdup(yytext);
		  if(name_to_ip_address(static_host->name, 
			&static_host->ip_address,error_label)){
			error("unknown host %s",static_host->name);
			free(static_host);
			static_host=NULL;
			YYERROR;
		  }
		  static_host->next_manager = static_sub_member->first_manager;
		  static_sub_member->first_manager=static_host;
		  static_host=NULL;
		}
	}

enterprise_list : /* empty */ | enterprise_list enterprise_item
	{
		DEBUG_YACC("enterprise_list")
	}

enterprise_item : t_openbracket enterprise_stmt trap_number_stmt 
		  t_closebracket
		{
			DEBUG_YACC("enterprise_item")
		}

enterprise_stmt : ENTERPRISE t_equal t_quotedstring
		{
			/* currently, it supports single enterprise */

			DEBUG_YACC("enterprise_stmt")
			/* add or find the enterprise */
			static_filter = efilter_add(quoted_string,error_label);
			if(static_filter==NULL){
			  error("error in %s at line %d: %s",
				current_filename?current_filename:"???",
				yylineno,error_label);
			}
		}

trap_number_stmt : t_trap_num t_equal trap_number_list
		{
			DEBUG_YACC("trap_number_stmt")
		}

trap_number_list : trap_number_item
		{
			DEBUG_YACC("trap_number_list")
		}
		| trap_number_list t_coma trap_number_item
		{
			DEBUG_YACC("trap_number_list")
		}

trap_number_item : trap_range
	{
			DEBUG_YACC("trap_number_item")
			/* for each trap, find/add to the
			   enterprise, and add_tailthe subgroup 
			   to each trap */

			if(static_filter!=NULL){
				/* expand the trap */
				mem_filter_join(static_trap_low,
					static_trap_high,static_sub_member,
					static_filter);
			}else{
				error("error in enterprise statement");
				YYERROR;
			}
	}

trap_range :	 NUMBER
		{
			/* starting trap num */
		 	static_trap_low = token_value;
		}
		t_minus NUMBER
		{
			/* ending trap num */
			static_trap_high = token_value;
		}
		| NUMBER
		{
			/* start & end num the same */
			DEBUG_YACC("trap_range")
			static_trap_low=static_trap_high=token_value;
		}

 
/*
trapcommunity : t_trapcommunity t_equal ct_identifier
                {
                        DEBUG_YACC("trap_community")

                        if(trap_community)
                        {
                                error("BUG: trap_community not NULL in trap_community");
                        }

                        trap_community = strdup(yytext);
                        if(trap_community == NULL)
                        {
                                error(ERR_MSG_ALLOC);
                                YYERROR;
                        }
                }
*/

/*******************/
/* trapdestinators */
/*******************/
/*

trapdestinators : t_trapdestinators t_equal t_openbracket trapdestinators_list t_closebracket
                {
                        DEBUG_YACC("trapdestinators")
                }


trapdestinators_list :  | trapdestinators_list list_separator trapdestinator_item
                {
                        DEBUG_YACC("trapdestinators_list")
                }


trapdestinator_item : ct_identifier
                {
                        int res; 

                        DEBUG_YACC("trapdestinator_item")
 
                        res = trap_destinator_add(yytext, error_label);
                        switch(res)
                        {
                                case 0:
                                        break;
 
                                case 1:
                                        error("error in %s at line %d: %s",
                                                current_filename? current_filename:
"???",
                                                yylineno, error_label);
                                        break;
 
                                default:
                                        error("fatal error in %s at line %d: %s",
                                                current_filename? current_filename:
"???",
                                                yylineno, error_label);
                                        YYERROR;
                        }
                }

*/

/******************* SNMP security (5-13-96) *********/




/**********/
/* macros */
/**********/

macros :	t_macros t_equal t_openbracket macros_list t_closebracket
		{
			DEBUG_YACC("macros")
		}


macros_list :	/* empty */ | macros_list macro_item
		{
			DEBUG_YACC("macros_list")
		}


macro_item :	label t_equal
		{
			if(parsing_oid != False)
			{
				error("BUG at line %d: parsing_oid not False in macro_item", yylineno);
			}
			parsing_oid = True;

			if(static_subids != NULL)
			{
				error("BUG at line %d: static_subids not NULL in macro_item", yylineno);
			}
			if(static_len != 0)
			{
				error("BUG at line %d: static_len not 0 in macro_item", yylineno);
			}
		}
		subids_list
		{
			DEBUG_YACC("macro_item")
	
			if(macro_add(static_label, static_subids, static_len) == NULL)
			{
				error("error at line %d", yylineno);
				YYERROR;
			}

			parsing_oid = False;
			free(static_label);
			static_label = NULL;
			free(static_subids);
			static_subids = NULL;
			static_len = 0;
		}


label :		t_identifier
		{
			DEBUG_YACC("label")

			if(static_label != NULL)
			{
				error("BUG at line %d: static_label not NULL in label", yylineno);
			}
			static_label = strdup(yytext);
			if(static_label == NULL)
			{
				error("malloc() failed");
				YYERROR;
			}
		}



/**********/
/* agents */
/**********/

agents :	t_agents t_equal t_openbracket agents_list t_closebracket
		{
			DEBUG_YACC("agents")
		}


agents_list :	agent_item | agents_list agent_item
		{
			DEBUG_YACC("agents_list")
		}


agent_item :		t_openbracket
		{
			if(static_agent != NULL)
			{
				error("BUG at line %d: static_agent not NULL in agent", yylineno);
			}
			static_agent = malloc(sizeof(Agent));
			if(static_agent == NULL)
			{
				error("malloc() failed");
				YYERROR;
			}
			(void)memset(static_agent, 0, sizeof(Agent));
			/* LINTED */
			static_agent->agent_id = (int32_t)getpid();
			static_agent->agent_status = SSA_OPER_STATUS_NOT_IN_SERVICE;
			static_agent->personal_file = strdup (current_filename);
		}
		name subtrees_tables timeout optional_watch_dog_time optional_port t_closebracket
		{
			DEBUG_YACC("agent_item");

			/* add the agent id to agent, currently, agent_id is pid */
			if(first_agent == NULL)
			{
				static_agent->next_agent = NULL;
			}
			else
			{
				static_agent->next_agent = first_agent;
			}
			first_agent = static_agent;

			/* if port is 0, assigned a non-reserved available port */
			if(static_agent->address.sin_port == 0 && agent_port_number != -1)
			  static_agent->address.sin_port = agent_port_number;
			else if(static_agent->address.sin_port==0)
			  static_agent->address.sin_port =
				get_a_non_reserved_port();
			if (agent_port_number == -1)
			  agent_port_number = static_agent->address.sin_port;

			/* the registration is for confirmation and
	 		   fill in extra value */
			static_agent->agent_status = SSA_OPER_STATUS_ACTIVE;
			if(SSARegSubagent(static_agent) == 0)
			{
				error("subagent registration failed");
				YYERROR;
			}
			static_agent = NULL;
		}


name :		t_name t_equal t_quotedstring
		{
			DEBUG_YACC("name")

			if(static_agent->name != NULL)
			{
				error("BUG at line %d: static_agent->name not NULL in name", yylineno);
			}
			static_agent->name = strdup(quoted_string);
			if(static_agent->name == NULL)
			{
				error("malloc() failed");
				YYERROR;
			}
/*
 * Increased the num. of retries for SSASubagentOpen in order to insure success
 * typically for boot time race condition between the master and subagent
 * Initial sleep is introduced to increase the probability of success the very
 * first time. This could be removed at a later time, after modifying the timeout
 * parameters for the subagent
 */ 
                        (void)sleep(15);
                        count=1;
                        while(count) {
			if( (static_agent->agent_id =
			     SSASubagentOpen(max_agent_reg_retry,static_agent->name)) == INVALID_HANDLER )
			{
                              if (count == 5) {
				error_exit("subagent registration failed");
				YYERROR;
                              }
			}
                        if (static_agent->agent_id ) break;
                         count++;
                        }
			if(SSARegSubagent(static_agent) == 0)
			{
				error("subagent registration failed");
				YYERROR;
			}
			/* LINTED */
			static_agent->process_id = (int32_t)getpid();
		}


subtrees_tables :  subtrees tables | subtrees | tables
		{
			DEBUG_YACC("subtrees_tables")
		}


subtrees :	t_subtrees t_equal t_openbracket
		{
			if(parsing_oid != False)
			{
				error("BUG at line %d: parsing_oid is not False in subtrees", yylineno);
			}
			parsing_oid = True;

			if(static_subids != NULL)
			{
				error("BUG at line %d: static_subids not NULL in subtrees", yylineno);
			}
			if(static_len != 0)
			{
				error("BUG at line %d: static_len not 0 in subtrees", yylineno);
			}
		}
		subtrees_list t_closebracket
		{
			DEBUG_YACC("subtrees")

			if(parsing_oid != True)
			{
				error("BUG at line %d: parsing_oid is not True in subtrees", yylineno);
			}
			parsing_oid = False;
		}


subtrees_list : /* empty */ | subtrees_list_coma_separated
		{
			DEBUG_YACC("subtrees_list")
		}


subtrees_list_coma_separated : subtree_item | subtrees_list_coma_separated t_coma subtree_item
		{
			DEBUG_YACC("subtrees_list_coma_separated")
		}


subtree_item : subids_list
		{
			DEBUG_YACC("subtree_item")

			if(parsing_oid != True)
			{
				error("BUG at line %d: parsing_oid is not True in subtree_item", yylineno);
			}

			if(subtree_add(static_agent, static_subids, static_len) == -1)
			{
				error("error at line %d", yylineno);
				YYERROR;
			}

			free(static_subids);
			static_subids = NULL;
			static_len = 0;
		}


tables :	t_tables t_equal t_openbracket tables_list t_closebracket
		{
			DEBUG_YACC("tables")
		}


tables_list :	/* empty */ | tables_list table_item
		{
			DEBUG_YACC("tables_list")
		}


table_item :	t_openbracket
		{
			if(static_agent == NULL)
			{
				error("BUG at line %d: static_agent is NULL in table_item", yylineno);
			}

			if(static_table)
			{
				error("BUG at line %d: static_table not NULL in table_item", yylineno);
			}

			static_table = calloc(1,sizeof(Table));
			if(static_table == NULL)
			{
				error("malloc() failed");
				YYERROR;
			}
			static_table->regTblStatus =
			 SSA_OPER_STATUS_NOT_IN_SERVICE;
			static_table->next_table = NULL;
			static_table->agent = static_agent;
			if(static_agent!=NULL)
			  static_table->regTblAgentID =
			  static_agent->agent_id;
			static_table->regTblOID.subids = NULL;
			static_table->regTblOID.len = 0;
			static_table->regTblStartColumn = 0;
			static_table->regTblEndColumn = 0;
			static_table->regTblIndex = ++table_index;
/*
			static_table->indexs.subids = NULL;
			static_table->indexs.len = 0;
*/
		}
		table columns indexs t_closebracket
		{
			DEBUG_YACC("table_item")

			if(static_table == NULL)
			{
				error_exit("BUG at line %d: static_table is NULL in table_item", yylineno);
			}
	
		 	/* register the table, if register fails, delete 
			   the table */
			if(SSARegSubtable(static_table)==0){
				/* unregister the table */
				
				error_exit("TABLE CONFIG");
			}
	

			if(last_table)
			{
				last_table->next_table = static_table;
			}
			else
			{
				first_table = static_table;
			}
			last_table = static_table;
			static_table = NULL;
		}


table :		t_table t_equal
		{
			if(parsing_oid != False)
			{
				error("BUG at line %d: parsing_oid is not False in tables", yylineno);
			}

			parsing_oid = True;
		}
		subids_list
		{
			DEBUG_YACC("table")

			if(parsing_oid != True)
			{
				error("BUG at line %d: parsing_oid is not True in tables", yylineno);
			}
			parsing_oid = False;

			if(static_table == NULL)
			{
				error_exit("BUG at line %d: static_table is NULL in table", yylineno);
			}

			static_table->regTblOID.subids = static_subids;
			static_subids = NULL;
			static_table->regTblOID.len = static_len;
			static_len = 0;
		}


columns :	t_columns t_equal range
		{
			DEBUG_YACC("columns")

			if(static_table == NULL)
			{
				error_exit("BUG at line %d: static_table is NULL in columns", yylineno);
			}

			static_table->regTblStartColumn = static_inf_value;
			static_inf_value = -1;
			static_table->regTblEndColumn = static_sup_value;
			static_sup_value = -1;
		}


/*
indexs :	t_indexs t_equal
		{
			if(parsing_oid != False)
			{
				error("BUG at line %d: parsing_oid is not False in indexs", yylineno);
			}

			parsing_oid = True;
		}
		subids_list
		{
			DEBUG_YACC("indexs")

			if(parsing_oid != True)
			{
				error("BUG at line %d: parsing_oid is not True in indexs", yylineno);
			}
			parsing_oid = False;

			if(static_table == NULL)
			{
				error_exit("BUG at line %d: static_table is NULL in indexs", yylineno);
			}

			static_table->indexs.subids = static_subids;
			static_subids = NULL;
			static_table->indexs.len = static_len;
			static_len = 0;
		}
*/

indexs :	t_indexs t_equal range
		{
			DEBUG_YACC("indexs")

			if(static_inf_value == -1)
			{
				error("BUG at line %d: static_inf_value is -1", yylineno);
			}
			if(static_sup_value == -1)
			{
				error("BUG at line %d: static_sup_value is -1", yylineno);
			}
			static_table->regTblStartRow = static_inf_value;
			static_table->regTblEndRow = static_sup_value;
			static_inf_value = -1;
			static_sup_value = -1;
		}


range :		t_opensquarebracket t_number
		{
			if(static_inf_value != -1)
			{
				error("BUG at line %d: static_inf_value (%d) is not -1 in range",
					yylineno,
					static_inf_value);
			}

			static_inf_value = token_value;
		}
		t_minus t_number
		{
			if(static_sup_value != -1)
			{
				error("BUG at line %d: static_sup_value (%d) is not -1 in range",
					yylineno,
					static_inf_value);
			}

			static_sup_value = token_value;
		}
		t_closesquarebracket
		{
			DEBUG_YACC("range")
		}
		| t_number
		{
			if(static_inf_value != -1)
			{
				error("BUG at line %d: static_inf_value (%d) is not -1 in range",
					yylineno,
					static_inf_value);
			}
			if(static_sup_value != -1)
			{
				error("BUG at line %d: static_sup_value (%d) is not -1 in range",
					yylineno,
					static_sup_value);
			}

			static_inf_value = token_value;
			static_sup_value = token_value;
		}


timeout :	t_timeout t_equal t_number
		{
			DEBUG_YACC("subtree")

			static_agent->timeout = token_value;
		}

optional_watch_dog_time : /*empty*/ |   t_watch_dog_time t_equal NUMBER
                {
                        DEBUG_YACC("optional_watch_dog_time")
                        static_agent->watch_dog_time = token_value;
                }

optional_port:	/*empty*/ | port
	{
                        DEBUG_YACC("optional_port")
	}

port :		t_port t_equal t_number
		{
			DEBUG_YACC("port")

			if(token_value > 0xFFFF)
			{
				error("error at line %d: the port number (%d) should not be greater than %d", yylineno, token_value, 0xFFFF);
				YYERROR;
			}

			/* LINTED */
			static_agent->address.sin_port = (short) token_value;

			if(agent_find(&(static_agent->address)))
			{
				error("error at line %d: the port number %d is already used by another agent", yylineno, token_value);
				YYERROR;
			}
		}



/***************/
/* subids_list */
/***************/

subids_list :	subid | subids_list t_dot subid
		{
			DEBUG_YACC("subids_list")
		}


subid :		t_mib2 | t_sun | t_enterprise | t_identifier | t_number
		{
			DEBUG_YACC("subid")
		}



/*******************/
/* terminal tokens */
/*******************/

/**************** SNMP security (5-13-96) ***/
ct_identifier : IDENTIFIER
		{
			DEBUG_YACC("ct_indentifier")
		}

t_communities : COMMUNITIES
                {
                        DEBUG_YACC("t_communities")
                }

t_hosts : HOSTS
	{
		DEBUG_YACC("t_hosts")
	}

t_acls  : ACL
        {
                DEBUG_YACC("t_acls")
        }

t_access : ACCESS
	{
		DEBUG_YACC("t_access")
	}

t_readonly :    READONLY
                {
                        DEBUG_YACC("t_readonly")

                        community_type = READ_ONLY;
                }

t_readwrite :   READWRITE
                {
                        DEBUG_YACC("t_readwrite")

                        community_type = READ_WRITE;
                }

t_managers :    MANAGERS
                {
                        DEBUG_YACC("t_managers")
                }


t_trap :	TRAP
		{
			DEBUG_YACC("t_trap")
		}

t_trap_num:	TRAPNUM
		{
			DEBUG_YACC("t_trap_num")
		}

t_trapcommunity : TRAPCOMMUNITY
                {
                        DEBUG_YACC("t_trapcommunity")
                }


/*
t_trapdestinators : TRAPDESTINATORS
                {
                        DEBUG_YACC("t_trapdestinators")
                }

list_separator : | t_coma
                {
                        DEBUG_YACC("list_separator")
                }
*/


/**************** SNMP security (5-13-96) ***/


t_number :	NUMBER
		{
			DEBUG_YACC("t_number")

			if(parsing_oid == True)
			{
				if(subids_cat((Subid *) &token_value, 1) == -1)
				{
					YYERROR;
				}
			}
		}


t_macros :	MACROS
		{
			DEBUG_YACC("t_macros")
		}


t_equal :	EQUAL
		{
			DEBUG_YACC("t_equal")
		}


t_minus :	MINUS
		{
			DEBUG_YACC("t_minus")
		}


t_openbracket :	OPENBRACKET
		{
			DEBUG_YACC("t_openbracket")
		}


t_closebracket : CLOSEBRACKET
		{
			DEBUG_YACC("t_closebracket")
		}


t_opensquarebracket : OPENSQUAREBRACKET
		{
			DEBUG_YACC("t_opensquarebracket")
		}


t_closesquarebracket : CLOSESQUAREBRACKET
		{
			DEBUG_YACC("t_closesquarebracket")
		}


t_identifier :	IDENTIFIER
		{
			DEBUG_YACC("t_identifier")

			if(parsing_oid == True)
			{
				Macro *mp;


				mp = macro_find(yytext);
				if(mp == NULL)
				{
					error("error at line %d: %s is not a macro", yylineno, yytext);
					YYERROR;
				}

				if(subids_cat(mp->name.subids, mp->name.len) == -1)
				{
					YYERROR;	
				}
			}
		}


t_mib2 :	MIB2
		{
			DEBUG_YACC("t_mib2")

			if(parsing_oid == False)
			{
				error("BUG at line %d: parsing_oid not True in t_mib2", yylineno);
			}
			if(subids_cat(subids_mib2, mib2_len) == -1)
			{
				YYERROR;
			}
		}


t_sun :		SUN
		{
			DEBUG_YACC("t_sun")

			if(parsing_oid == False)
			{
				error("BUG at line %d: parsing_oid not True in t_sun", yylineno);
			}
			if(subids_cat(subids_sun, sun_len) == -1)
			{
				YYERROR;
			}
		}


t_enterprise :	ENTERPRISE
		{
			DEBUG_YACC("t_enterprise")

			if(parsing_oid == False)
			{
				error("BUG at line %d: parsing_oid not True in t_enterprise", yylineno);
			}
			if(subids_cat(subids_enterprise, enterprise_len) == -1)
			{
				YYERROR;
			}
		}

t_dot :		DOT
		{
			DEBUG_YACC("t_dot")
		}


t_agents :	AGENTS
		{
			DEBUG_YACC("t_agents")
		}


t_name :	NAME
		{
			DEBUG_YACC("t_name")
		}


t_subtrees :	SUBTREES
		{
			DEBUG_YACC("t_subtrees")
		}


t_tables :	TABLES
		{
			DEBUG_YACC("t_tables")
		}


t_table :	TABLE
		{
			DEBUG_YACC("t_table")
		}


t_columns :	COLUMNS
		{
			DEBUG_YACC("t_columns")
		}


t_indexs :	INDEXS
		{
			DEBUG_YACC("t_indexs")
		}


t_timeout :	TIMEOUT
		{
			DEBUG_YACC("t_timeout")
		}

t_watch_dog_time :      WATCHDOGTIME
                {
                        DEBUG_YACC("t_watch_dog_time")
                }

t_port :	PORT
		{
			DEBUG_YACC("t_port")
		}


t_quotedstring : QUOTEDSTRING
		{
			DEBUG_YACC("t_quotedstring\n")
		}


t_coma :	COMA
		{
			DEBUG_YACC("t_coma")
		}
%%

#include "personal.lex.c"

/****************************************************************/

static int subids_cat(Subid *subids, int len)
{
	Subid *new_subids;
	int new_len;


	new_len = static_len + len;
			/* LINTED */
	new_subids = (Subid *) malloc(new_len * (int32_t)sizeof(Subid));
	if(new_subids == NULL)
	{
		error("malloc() failed");
		if(static_subids)
		{
			free(static_subids);
		}
		static_subids = NULL;
		static_len = 0;
		return -1;
	}
			/* LINTED */
	(void)memcpy(new_subids, static_subids, static_len * (int32_t)sizeof(Subid));
			/* LINTED */
	(void)memcpy(&(new_subids[static_len]), subids, len * (int32_t)sizeof(Subid));


	if(static_subids)
	{
		free(static_subids);
	}
	static_subids = new_subids;
	static_len = new_len;

	return 0;
}


/****************************************************************/

static Macro *macro_add(char *label, Subid *subids, int len)
{
	Macro *new;


	if(macro_find(label) != NULL)
	{
		error("%s is already a macro", label);
		return NULL;
	}

	new = (Macro *) malloc(sizeof(Macro));
	if(new == NULL)
	{
		error("malloc() failed");
		return NULL;
	}
	new->label = NULL;
	new->name.subids = NULL;

	new->label = strdup(label);
	if(new->label == NULL)
	{
		error("malloc() failed");
		macro_free(new);
		return NULL;
	}
			/* LINTED */
	new->name.subids = (Subid *) malloc(len * (int32_t)sizeof(Subid));
	if(new->name.subids == NULL)
	{
		error("malloc() failed");
		macro_free(new);
		return NULL;
	}
			/* LINTED */
	(void)memcpy(new->name.subids, subids, len * (int32_t)sizeof(Subid));
	new->name.len = len;
	new->next_macro = first_macro;
	first_macro = new;

	return new;
}


/****************************************************************/

static Macro *macro_find(char *label)
{
	Macro *mp;


	for(mp = first_macro; mp; mp = mp->next_macro)
	{
		if(strcmp(mp->label, label) == 0)
		{
			return mp;
		}
	}

	return NULL;
}


/****************************************************************/

static void macro_free(Macro *mp)
{
	if(mp == NULL)
	{
		return;
	}

	if(mp->label)
	{
		free(mp->label);
	}

	if(mp->name.subids)
	{
		free(mp->name.subids);
	}

	free(mp);

	return;
}


/****************************************************************/

static void macro_list_delete()
{
	Macro *mp = first_macro;
	Macro *next;


	while(mp)
	{
		next = mp->next_macro;

		macro_free(mp);

		mp = next;
	}

	first_macro = NULL;

	return;
}



/****************************************************************/

int yyerror(char *s)
{
	error("%s at line %d: %s", s, yylineno, yytext);

	return (0);
}


/****************************************************************/

/* If we have a serious problem, this function will	*/
/* terminate (<==> exit) the program			*/

void config_init(char *filename)
{
		struct stat statb;
		char *fileaddr;
		int fd;


		yylineno = 1;

		if((fd = open(filename, O_RDONLY)) < 0)
		{
			error_exit(ERR_MSG_OPEN,
				filename, errno_string());
		}

		/* 
		 * get the size of the file
		 */
		if(fstat(fd, &statb) < 0)
		{
			error_exit(ERR_MSG_FSTAT,
				filename, errno_string());
		}
		if(!S_ISREG(statb.st_mode))
		{
			error_exit("filename: %s is not a file\n",filename);
		}

		/* 
		 * and map it into my address space
		 */
		if(statb.st_size != 0)
		{
			/* Purify IPR/IPW error - bug 4124843. yylook wants to
			   read the last + 1 byte to decide EOF */
			/* LINTED */
			if((fileaddr = (char *) mmap(0, (int32_t)statb.st_size+1, PROT_READ|PROT_WRITE,
				MAP_PRIVATE, fd, 0)) <= (char *) 0)
			{
				error_exit(ERR_MSG_MMAP,
					filename, errno_string());
			}

			/*
			 * set current lex focus on the file
			 */

			lexinput = fileaddr;

			/*
			 * and parse the file
			 */
			current_filename = filename;
			if(yyparse() == 1)
			{
				error_exit("parsing %s failed", filename);
			}
			current_filename = NULL;

			/*
			 * Parsing is finished
			 *
			 * unmap the file and close it
			 */

			/* Purify IPR/IPW error - bug 4124843 */
			/* LINTED */
			if(munmap(fileaddr, (int32_t)statb.st_size+1) == -1)
			{
				error(ERR_MSG_MUNMAP, errno_string());
			}
		}
		else
		{
			/* empty file, ignore it */

			error_exit("empty configuration file %s", filename);
		}

		if(close(fd) == -1)
		{
			error(ERR_MSG_CLOSE, errno_string());
		}

		macro_list_delete();


	table_list_delete();


	if(first_agent == NULL)
	{
		error_exit("No SNMP agent configured");
	}

	if(trace_level > 0)
	{
		trace_subtrees();
		trace_agents();
	}
}


/****************************************************************/

static void table_list_delete()
{
	Table *next;

	while(first_table)
	{
		next = first_table->next_table;
		table_free(first_table);
		first_table = next;
	}

	first_table = NULL;
	last_table = NULL;
}


/****************************************************************/

static void table_free(Table *tp)
{
	if(tp == NULL)
	{
		return;
	}

	if(tp->regTblOID.subids)
	{
		free(tp->regTblOID.subids);
	}

/*
	if(tp->indexs.subids)
	{
		free(tp->indexs.subids);
	}
*/

	free(tp);
}


/****************************************************************/


/*********** SNMP security (5-13-96) ******/
/* If we have a serious problem, this function will	*/
/* terminate (<==> exit) the program			*/

void sec_config_init(char *filename)
{
	struct stat statb;
	char *fileaddr;
	int fd;


	delete_manager_list();
	delete_community_list();
	if(trap_community)
	{
		free(trap_community);
		trap_community = NULL;
	}
	delete_trap_destinator_list();


	yylineno = 1;

	if((fd = open(filename, O_RDONLY)) < 0)
	{
		error_exit(ERR_MSG_OPEN,
			filename, errno_string());
	}

	/* 
	 * get the size of the file
	 */
	if(fstat(fd, &statb) < 0 )
	{
		error_exit(ERR_MSG_FSTAT,
			filename, errno_string());
	}
	if(!S_ISREG(statb.st_mode))
	{
		error_exit("filename: %s is not a file\n",filename);
	}

	/* 
	 * and map it into my address space
	 */
	if(statb.st_size)
	{
		/* Purify IPR/IPW error - bug 4124843. yylook wants to
		   read the last + 1 byte to decide EOF */
			/* LINTED */
		if((fileaddr = (char *) mmap(0, (int32_t)statb.st_size+1, PROT_READ|PROT_WRITE,
			MAP_PRIVATE, fd, 0)) <= (char *) 0)
		{
			error_exit(ERR_MSG_MMAP,
				filename, errno_string());
		}

		/*
		 * set current lex focus on the file
		 */

		lexinput = fileaddr;

		/*
		 * and parse the file
		 */

		current_filename = filename;
		if(yyparse() == 1)
		{
			error_exit("parsing %s failed", filename);
		}
		current_filename = NULL;

		/*
		 * Parsing is finished
		 *
		 * unmap the file and close it
		 */

		/* Purify IPR/IPW error - bug 4124843 */
			/* LINTED */
		if(munmap(fileaddr, (int32_t)statb.st_size+1) == -1)
		{
			error(ERR_MSG_MUNMAP,
				errno_string());
		}
	}
	else
	{
		/* empty file, ignore it */

		error_exit("empty configuration file %s", filename);
	}

	if(close(fd) == -1)
	{
		error(ERR_MSG_CLOSE, errno_string());
	}

	if(trace_level > 0)
	{
		trace("\n");
		trace_managers();
		trace_filter();
		trace_trap_destinators();
	}
}
/*********** SNMP security (5-13-96) ******/

int yywrap()
{
  return 1;
}

static int get_a_non_reserved_port()
{
  struct sockaddr_in me;
  socklen_t len;
  int cnt=0;
  int sd;

  sd = socket(AF_INET,SOCK_DGRAM,0);
  if(sd<0) return 0;
  me.sin_family = AF_INET;
  me.sin_addr.s_addr = INADDR_ANY;

  for(;cnt<5;cnt++){
    me.sin_port = htons(0);
    if(bind(sd,(struct sockaddr*)&me,sizeof(me))!=0)continue;
    len = (socklen_t) sizeof(me);
    if(getsockname(sd,(struct sockaddr*)&me, &len)==-1) continue;
    (void)close(sd);
    return me.sin_port;
  }
  (void)close(sd);
  return 0;
}
