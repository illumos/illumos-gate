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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * HISTORY
 * 5-13-96	Jerry Yeung		parse security config. file
 * 6-25-96      Jerry Yeung             parse trap info.
 * 6-27-96 	Jerry Yeung		optional port stmt
 * 6-28-96	Jerry Yeung		add setuid support
 * 7-03-96	Jerry Yeung		add watchdog, maxAgentTimeOut
 *					    pollInterval
 * 7-13-96	Jerry Yeung		remove resource_name
 * 7-17-96	Jerry Yeung		change reg file suffix
 * 7-17-96	Jerry Yeung		change personal to registration_file
 */
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
%token COMMA
%token MINUS
%token OPENSQUAREBRACKET
%token CLOSESQUAREBRACKET
%token WATCHDOGTIME
%token MAXAGENTTIMEOUT
%token POLLINTERVAL
%token ENVIRONMENT

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

/* support resource */
%token RESOURCE
%token REGISTRATION_FILE
%token SECURITY
%token POLICY
%token TYPE
%token COMMAND
%token DIRECTORY
%token USER

%{
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "pdu.h"

#include "snmprelay_msg.h"
#include "agent.h"
#include "subtree.h"
#include "session.h"
#include "dispatcher.h"

/** SNMP security (5-13-96) */
#include "trap.h"
#include "access.h"

#include "res.h"
#include "sh_table.h"


/***** DEFINE *****/

/*
 #define DEBUG_YACC(string) printf("\t\tYACC: %s: %s at line %d\n", string, yytext, yylineno);
*/

#define DEBUG_YACC(string) 

/*
#define SNMPRELAY_SUFFIX	".snmprelay" 
*/
#define SNMPRELAY_SUFFIX	".reg"
#define SNMPRESOURCE_SUFFIX	".rsrc"
#define SNMPRELAY_REG_FILE	"snmpdx.reg"
#define SNMPACL_SUFFIX		".acl"


/***** TYPEDEF *****/

typedef struct _Macro {
	struct _Macro *next_macro;
	char *label;
	Oid name;
} Macro;


/***** GLOBAL VARIABLES *****/

char config_file_4_res[300] = "";


/***** STATIC VARIABLES AND FUNCTIONS *****/
/*(6-18) reconfig */
#define RES_PARSING_STATE_FROM_SCRATCH 0
#define RES_PARSING_STATE_RE_READ 1
static time_t last_res_modify_time=0;
static int res_parsing_state =0; /* 0:init */

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
static void trace_macros();


/* static_label is used when parsing a macro	*/
static char *static_label = NULL;

/* static_agent is used when parsing an agent	*/
static Agent *static_agent = NULL;

/* resource support */
static SapResource *static_res = NULL;

/* static_table is used when parsing n table	*/
static Table *static_table = NULL;
Table *tmp_table;

/* static_inf_value and static_max_value are	*/
/* used when parsing a range			*/
static int static_inf_value = -1;
static int static_sup_value = -1;

char *save_string = NULL;
char *com_string = NULL;
char *host_string = NULL;
int found_dot=FALSE;
int found_comma=FALSE;


%}

%%


configuration :	agents | macros agents | snmp_security | environment resources
		{
			DEBUG_YACC("configuration")
		}

/******************* SNMP security (5-13-96) *********/
snmp_security : acls trap_block /*trapcommunity trapdestinators*/
                {
                        DEBUG_YACC("security configuration")
                }

/***************/
/* accesscontrol */
/***************/

acls :	/*empty*/ |t_acls t_equal t_openbracket acls_list t_closebracket
	{
		DEBUG_YACC("acls_list1")
	}
	| t_acls t_equal t_openbracket error t_closebracket
	{
	          DEBUG_YACC("acls_listError")	
		  error("BUG: acl stmt parsing error at line %d",yylineno);
                  if(static_access_policy != NULL){
                        access_policy_list_free(static_access_policy);
                        static_access_policy = NULL;
		  }
	}

acls_list : /*empty*/ | acls_list acl_item 
	{
		DEBUG_YACC("acls_list2")
	}

acl_item : t_openbracket 
	{
		static_access_policy = calloc(1,sizeof(AccessPolicy));
		if(static_access_policy == NULL)
		{
			error("malloc() failed");
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

                {
                        /* Hack to send last community string which is a dot string */

                        if (com_string != NULL)
                        {                  /* add community into AccessPolicy */
                           static_community = calloc(1,sizeof(Community));
                           if(static_community == NULL)
                           {
                              error("malloc() failed");
                              YYERROR;
                           }
                           static_community->name = strdup(com_string);
                           community_attach(static_access_policy,static_community);
                           static_community = NULL;
                           free(com_string);
			   com_string=NULL;
                           found_comma = FALSE;
                        }
                        /* Hack to send last manager host string which is a dot string */

                        if (host_string != NULL)
                        {
                            Manager *res;

                           res = manager_add(host_string, error_label);
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
			      free(host_string);
		              host_string=NULL;	
                   	      found_comma = FALSE;
                        }
                }
                static_access_server = NULL;
                static_access_policy = NULL;
                static_community = NULL;
                community_type = 0;
	}

communities_stmt :    t_communities t_equal communities_set
	{
		DEBUG_YACC("communities_stmt");
	}

communities_set : communities_set  t_comma community_elem | community_elem
	{
                DEBUG_YACC("communities_set");
	}

community_elem : community_elem  t_dot community_item | t_dot community_elem | community_item
        {
               DEBUG_YACC("community_elem")
        }

community_item : ct_identifier
 	{
		DEBUG_YACC("community_item")
		if(static_access_policy==NULL){
			error("acl statement error");
			YYERROR;
		}

                if (found_comma && (com_string != NULL))
                {
		     static_community = calloc(1,sizeof(Community));
                     if(static_community == NULL)
                     {
                        error("malloc() failed");
                        YYERROR;
                     }

	             static_community->name = strdup(com_string);
                     community_attach(static_access_policy,static_community);
                     static_community = NULL;
	             free(com_string);
	             com_string=NULL;	
                     found_comma=FALSE;
                }
                if (com_string == NULL && found_dot == FALSE)
	        {
                    /* com_string= strdup(save_string);*/
                    /* first part of community string */
                    com_string=malloc(50);
                    if(com_string == NULL){
                        error("malloc() failed");
                        YYERROR;
                    }
                    strcpy(com_string,save_string);
                    free(save_string);
                }

                 
		if (found_dot )
		{
			if (com_string == NULL)
				com_string = malloc(50);
			strcat(com_string,".");
					/* allow a dot in community string */
			strcat(com_string,save_string);
					/* add part after the dot    */
			free(save_string);
			found_dot=FALSE;
		}
	}

acl_access :	t_access t_equal acl_access_type
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

hosts_list : hosts_list t_comma host_elem | host_elem 
	{
		DEBUG_YACC("hosts_list");
	}

host_elem : host_elem t_dot host_item | host_item
        {
                DEBUG_YACC("host_elem");
	}

host_item :  ct_identifier 
	{
		/* add the host item to manager list */
		/* it should return the pointer if exists */
                Manager *res;
 
                DEBUG_YACC("manager_item")

		if (found_comma && (host_string != NULL))
		{
                	res = manager_add(host_string, error_label);
                	if(res==NULL)
			{
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
                        free(host_string);
			host_string=NULL;
			found_comma = FALSE;
		}
		if (host_string == NULL)
                {
		    /* host_string= strdup(save_string);*/
                    /* first part of host string */
                    host_string=malloc(50);
                    if(host_string == NULL){
                        error("malloc() failed");
                        YYERROR;
	            }	
                    strcpy(host_string,save_string);
                    free(save_string);
                }
                    

                if (found_dot )
                {
                     strcat(host_string,".");           /* allow a dot in hoststring */
                     strcat(host_string,save_string);   /* add part after the dot    */
                     free(save_string);
                     found_dot=FALSE;
                }

	}

/***************/
/* communities */
/***************/

/*

communities :	t_communities t_equal t_openbracket communities_list t_closebracket
		{
			DEBUG_YACC("communities")
		}
		| t_communities t_equal t_openbracket error t_closebracket
		{
		  error("BUG: community stmt parsing error at line %d",yylineno);
		  if(community_name != NULL) free(community_name);
		}


communities_list :  | communities_list community_item
		{
			DEBUG_YACC("communities_list")
		}


community_item : ct_identifier
		{
			DEBUG_YACC("community_item 1")

			if(community_name)
			{
				error("BUG: community_name is not NULL in community_item");
			}

			community_name = strdup(yytext);
			if(community_name == NULL)
			{
				error(ERR_MSG_ALLOC);
				YYERROR;
			}
		}
		communitytype
		{
			int res;

			DEBUG_YACC("community_item 2")

			if(community_name == NULL)
			{
				error("BUG: community_name is NULL in community_item");
			}

			res = community_add(community_name, community_type, error_label);
			switch(res)
			{
				case 0:
					break;

				case 1:
					error("error in %s at line %d: %s",
						current_filename? current_filename: "???",
						yylineno, error_label);
					break;

				default:
					error("fatal error in %s at line %d: %s",
						current_filename? current_filename: "???",
						yylineno, error_label);
					YYERROR;
			}

			free(community_name);
			community_name = NULL;
		}

communitytype : t_readonly | t_readwrite
		{
			DEBUG_YACC("community_type")
		}
*/

/************/
/* managers */
/************/
 
/*
managers :      t_managers t_equal t_openbracket managers_list t_closebracket
                {
                        DEBUG_YACC("agents")
                }
	 	| t_managers t_equal t_openbracket error t_closebracket
		{
		  error("BUG: managers stmt parsing error at line %d",yylineno);
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
trap_block :    t_trap t_equal t_openbracket trap_list t_closebracket
                {
                        DEBUG_YACC("trap_block")
			found_comma = FALSE;
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
 
trap_interest_hosts_list : trap_interest_hosts_list t_comma
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
                | trap_number_list t_comma trap_number_item
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

trap_range :    NUMBER
                {
                        /* starting trap num */
                        static_trap_low = token_value;
                }
                t_minus  NUMBER
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
		| t_trapdestinators t_equal t_openbracket error t_closebracket
		{
		  error("BUG: trapdestinators stmt parsing error at line %d",yylineno);
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
		| t_macros t_equal t_openbracket error t_closebracket
		{ error("BUG at line %d: macro-parsing error", yylineno); 
			parsing_oid = False;
			if(static_label != NULL) free(static_label);
			static_label = NULL;
			if(static_subids != NULL) free(static_subids);
			static_subids = NULL;
			static_len = 0;
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

/************/
/* environment */
/************/

environment:	/*empty*/ | t_environment t_equal t_openbracket environment_list 
		t_closebracket
		{
			DEBUG_YACC("environment")
		}

environment_list: /* empty */ | environment_list environment_item
		{
			DEBUG_YACC("environment_list")
		}

environment_item: 	poll_interval | max_agent_time_out
		{
			DEBUG_YACC("environment_item")
		}

poll_interval:	t_poll_interval t_equal NUMBER
		{
			DEBUG_YACC("poll_interval")
			relay_agent_poll_interval = token_value;
		}

max_agent_time_out:	t_max_agent_time_out t_equal NUMBER
		{
			DEBUG_YACC("max_agent_time_out")
			relay_agent_max_agent_time_out = token_value;
		}
			

/***********/
/* resouces */
/************/

resources:	/*empty*/ | t_resource t_equal t_openbracket resources_list t_closebracket
		{
			DEBUG_YACC("resources")
		}

resources_list:	/*empty*/ | resources_list resource_item
			{
				DEBUG_YACC("resources_list")
			}
resource_item:	t_openbracket
		{
		  if(static_res != NULL)
			error("BUG at line%d: static_res not NULL",yylineno);
		  static_res = malloc(sizeof(SapResource));
		  if(static_res == NULL)
		  {
			error("malloc() failed");
			YYERROR;
		  }
		  memset(static_res,0,sizeof(SapResource));
		}
		fileslist policy res_type user start_cmd t_closebracket
		{
			DEBUG_YACC("agent_item")
		   if(res_parsing_state == RES_PARSING_STATE_RE_READ){
			if(reconfig_first_res == NULL)
			{
				static_res->next_res = NULL;
			}
			else
			{
				static_res->next_res = reconfig_first_res;
			}
			reconfig_first_res = static_res;
		   }else{
			if(first_res == NULL)
			{
				static_res->next_res = NULL;
			}
			else
			{
				static_res->next_res = first_res;
			}
			first_res = static_res;
		  }
		  static_res = NULL;
		}
		| t_openbracket error t_closebracket
		{ 
			error("BUG at line %d: resource stmt error",yylineno);
		   if(static_res != NULL){
			if(static_res->dir_file != NULL)
				free(static_res->dir_file);
			if(static_res->personal_file != NULL)
				free(static_res->personal_file);
			if(static_res->sec_file != NULL)
				free(static_res->sec_file);
			if(static_res->policy != NULL)
				free(static_res->policy);
			if(static_res->type != NULL)
				free(static_res->type);
			if(static_res->start_cmd != NULL)
				free(static_res->start_cmd);
			free(static_res);
		   }
			static_res = NULL;
		}
	

fileslist:	file_item | fileslist file_item
		{
			DEBUG_YACC("fileslist");
		}
file_item:	personal_file | sec_file | directory_file
		{
			DEBUG_YACC("file_item");
		}

personal_file:	t_registration_file t_equal t_quotedstring
		{
		  DEBUG_YACC("personal_file")
		  if(static_res->personal_file != NULL) 
			error("BUG at line %d: static_res->personal_file not NULL ",yylineno);
		  static_res->personal_file = strdup(quoted_string);
		  if(static_res->personal_file == NULL){
			error("malloc() failed");
			YYERROR;
		  }			
		}
sec_file:	t_sec_fname t_equal t_quotedstring
		{
		  DEBUG_YACC("sec_file")
		  if(static_res->sec_file != NULL) 
			error("BUG at line %d: static_res->sec_file not NULL ",yylineno);
		  static_res->sec_file = strdup(quoted_string);
		  if(static_res->sec_file == NULL){
			error("malloc() failed");
			YYERROR;
		  }			
		}

directory_file:	t_dir_fname t_equal t_quotedstring
		{
		  DEBUG_YACC("directory_file")
		  if(static_res->dir_file != NULL) 
			error("BUG at line %d: static_res->dir_file not NULL ",yylineno);
		  static_res->dir_file = strdup(quoted_string);
		  if(static_res->dir_file == NULL){
			error("malloc() failed");
			YYERROR;
		  }			
		}

policy: 	/*empty*/ | t_policy t_equal t_quotedstring
		{
		  DEBUG_YACC("policy")
		  if(static_res->policy != NULL) 
			error("BUG at line %d: static_res->policy not NULL ",yylineno);
		  static_res->policy = strdup(quoted_string);
		  if(static_res->policy == NULL){
			error("malloc() failed");
			YYERROR;
		  }
		}


user: 	/*empty*/ | t_user t_equal t_quotedstring
		{
		  DEBUG_YACC("user")
		  if(static_res->user != NULL) 
			error("BUG at line %d: static_res->user not NULL ",yylineno);
		  static_res->user = strdup(quoted_string);
		  if(static_res->user == NULL){
			error("malloc() failed");
			YYERROR;
		  }
		}

res_type: 	/*empty*/ | t_res_type t_equal t_quotedstring
		{
		  DEBUG_YACC("res_type")
		  if(static_res->type != NULL) 
			error("BUG at line %d: static_res->type not NULL ",yylineno);
		  static_res->type = strdup(quoted_string);
		  if(static_res->type == NULL){
			error("malloc() failed");
			YYERROR;
		  }
		}



start_cmd:	t_command t_equal t_quotedstring
		{
		  DEBUG_YACC("start_cmd")
		  if(static_res->start_cmd != NULL) 
			error("BUG at line %d: static_res->start_cmd not NULL ",yylineno);
		  static_res->start_cmd = strdup(quoted_string);
		  if(static_res->start_cmd == NULL){
			error("malloc() failed");
			YYERROR;
		  }			
		}

t_resource:	RESOURCE
		{
			DEBUG_YACC("t_resource");
		}

t_registration_file:	REGISTRATION_FILE
		{
			DEBUG_YACC("t_registration_file");
		}

t_sec_fname:	SECURITY
		{
			DEBUG_YACC("t_sec_file");
		}

t_dir_fname:	DIRECTORY
		{
			DEBUG_YACC("t_dir_fname");
		}

t_policy:	POLICY
		{
			DEBUG_YACC("t_policy");
		}

t_res_type:	TYPE
		{
			DEBUG_YACC("t_res_type");
		}

t_user:		USER
		{
			DEBUG_YACC("t_user");
		}

t_command:	COMMAND
		{
			DEBUG_YACC("t_command");
		}

/**********/
/* agents */
/**********/

agents :	t_agents t_equal t_openbracket agents_list t_closebracket
		{
			DEBUG_YACC("agents")
		}


agents_list :	/*empty */ | agents_list agent_item
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
			memset(static_agent, 0, sizeof(Agent));
			static_agent->agentID = sap_agent_id++;
			/* Bug fix 4145620 - The subagents listen on the loopback driver */
			static_agent->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			static_agent->agentStatus = SSA_OPER_STATUS_INIT;
		}
		name subtrees_tables timeout optional_watch_dog_time optional_port t_closebracket
		{
			DEBUG_YACC("agent_item");

			if(first_agent == NULL)
			{
				static_agent->next_agent = NULL;
			}
			else
			{
				static_agent->next_agent = first_agent;
			}
			first_agent = static_agent;
			static_agent = NULL;
		}
		| t_openbracket error t_closebracket
		{ 
			error("BUG at line %d: agent statement error",yylineno);
			if(static_agent != NULL){ 
				delete_all_subtree_from_agent(static_agent);
				delete_all_tables_for_agent(static_agent);
				if(static_agent->agentName.chars != NULL){
				  free(static_agent->agentName.chars);
				  static_agent->agentName.chars = NULL;
				}
				static_agent->agentName.len = 0;
				if(static_agent->name != NULL){
					free(static_agent->name);
					static_agent->name = NULL;
				}
				free(static_agent);
				static_agent = NULL;
			}
			/* clean up */
		}


name :		t_name t_equal t_quotedstring
		{
			DEBUG_YACC("name")

			if(static_agent->name != NULL)
			{
				error("BUG at line %d: static_agent->name not NULL in name", yylineno);
			}
			static_agent->name = strdup(quoted_string);
			(static_agent->agentName).chars = 
				(u_char*)strdup(static_agent->name);
			(static_agent->agentName).len = strlen(static_agent->name);

			if(static_agent->name == NULL)
			{
				error("malloc() failed");
				YYERROR;
			}
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


subtrees_list : /* empty */ | subtrees_list_comma_separated
		{
			DEBUG_YACC("subtrees_list")
		}


subtrees_list_comma_separated : subtree_item | subtrees_list_comma_separated t_comma subtree_item
		{
			DEBUG_YACC("subtrees_list_comma_separated")
		}


subtree_item : subids_list
		{
			Subtree *sp;


			DEBUG_YACC("subtree_item")

			if(parsing_oid != True)
			{
				error("BUG at line %d: parsing_oid is not True in subtree_item", yylineno);
			}

			if(subtree_add(static_agent, static_subids, static_len,NULL) == -1)
			{
				error("error at line %d", yylineno);
				YYERROR;
			}
	
			/* add the mirror table(mibpatch) */
			/* assume that the subtree is the first agent
			   subtree */
			sp = static_agent->first_agent_subtree;
			create_mirror_table_from_subtree(sp);

			free(static_subids);
			static_subids = NULL;
			static_len = 0;
			found_comma = FALSE;
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
			static_table->regTblStatus = SSA_OPER_STATUS_ACTIVE;
			static_table->next_table = NULL;
			static_table->agent = static_agent;
			static_table->regTblAgentID = static_agent->agentID;
			static_table->regTblIndex = ++static_agent->agentTblIndex;
			static_table->name.subids = NULL;
			static_table->name.len = 0;
			static_table->first_column_subid = 0;
			static_table->last_column_subid = 0;
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
				error("BUG at line %d: static_table is NULL in table_item", yylineno);
			}else{
			  /* check for the validation of the table,
		  	   * if insertion is ok, then put it into the 
			   * table lists
			   */
			
			  if(single_table_to_subtrees(TABLE_TO_OID_TRY,
			    static_table,error_label) == -1){
				/* may need more elaboration in error */
				error("Table %d insertion failed",
				(static_table->name.subids)?
				SSAOidString(&(static_table->name)):"");
				table_free(static_table);
			  }
			  if(single_table_to_subtrees(TABLE_TO_OID_GO,
			    static_table,error_label) != -1){

				if(first_table==NULL){
				  first_table =static_table;
				}else{
				  for(tmp_table=first_table;tmp_table;
				      tmp_table=tmp_table->next_table)
					last_table = tmp_table;
				  last_table->next_table = static_table;
				}
			  }
			}
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

			static_table->name.subids = static_subids;
			static_subids = NULL;
			static_table->name.len = static_len;
			static_len = 0;
		}


columns :	t_columns t_equal range
		{
			DEBUG_YACC("columns")

			if(static_table == NULL)
			{
				error_exit("BUG at line %d: static_table is NULL in columns", yylineno);
			}

			static_table->first_column_subid = static_inf_value;
			static_inf_value = -1;
			static_table->last_column_subid = static_sup_value;
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
			static_table->first_index_subid = static_inf_value;
			static_table->last_index_subid = static_sup_value;
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

			static_agent->agentTimeOut =static_agent->timeout = token_value;
		}

optional_watch_dog_time : /*empty*/ |	t_watch_dog_time t_equal NUMBER
		{
			DEBUG_YACC("optional_watch_dog_time")
			static_agent->agentWatchDogTime = token_value;
		}


optional_port : /*empty*/ | port
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

			static_agent->address.sin_port = (short) token_value;
			static_agent->agentPortNumber = 
				static_agent->address.sin_port;

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
                        found_dot = FALSE;
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
/*             
                        if(save_string == NULL)
                        {
                           error("malloc() failed");
                           YYERROR;
                        }
*/
                        save_string = strdup(yytext);


		}

t_communities : COMMUNITIES
                {
                        DEBUG_YACC("t_communities")
                }

t_hosts : HOSTS
        {
                DEBUG_YACC("t_hosts")
        }

t_acls	: ACL
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

t_trap :        TRAP
                {
                        DEBUG_YACC("t_trap")
                }
 
t_trap_num:     TRAPNUM
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

list_separator :  | t_comma
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
                        found_dot=TRUE;
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

t_environment:	ENVIRONMENT
		{
			DEBUG_YACC("t_environment")
		}

t_watch_dog_time :	WATCHDOGTIME
		{
			DEBUG_YACC("t_watch_dog_time")
		}

t_poll_interval: 	POLLINTERVAL
		{
			DEBUG_YACC("t_poll_interval")
		}

t_max_agent_time_out:	MAXAGENTTIMEOUT
		{
			DEBUG_YACC("t_max_agent_time_out")
		}


t_port :	PORT
		{
			DEBUG_YACC("t_port")
		}


t_quotedstring : QUOTEDSTRING
		{
			DEBUG_YACC("t_quotedstring\n")
		}


t_comma :	COMMA
		{
			DEBUG_YACC("t_comma")
                        found_comma=TRUE;
		}
%%

#include "config.lex.c"

/****************************************************************/

static int subids_cat(Subid *subids, int len)
{
	Subid *new_subids;
	int new_len;


	new_len = static_len + len;
	new_subids = (Subid *) malloc(new_len * sizeof(Subid));
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
	memcpy(new_subids, static_subids, static_len * sizeof(Subid));
	memcpy(&(new_subids[static_len]), subids, len * sizeof(Subid));


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
	new->name.subids = (Subid *) malloc(len * sizeof(Subid));
	if(new->name.subids == NULL)
	{
		error("malloc() failed");
		macro_free(new);
		return NULL;
	}
	memcpy(new->name.subids, subids, len * sizeof(Subid));
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

static void trace_macros()
{
	Macro *mp;


	trace("MACROS:\n");
	for(mp = first_macro; mp; mp = mp->next_macro)
	{
		trace("\t%-30s %-30s\n",
			mp->label,
			SSAOidString(&(mp->name)));
	}
	trace("\n");
}


/****************************************************************/

int yyerror(char *s)
{
	error("%s at line %d: %s", s, yylineno, yytext);
	return (0);
}


/****************************************************************/

/*
 * filename is the file to be read
 * file_time is the modified time of the file, this argument can be NULL
 */
int parsing_file(char* filename,time_t *file_time)
{
  struct stat statb;
  int fd;
  char *fileaddr;
  int error_free = TRUE;

  yylineno = 1;
  if((fd = open(filename, O_RDONLY)) < 0)
  {
	error(ERR_MSG_OPEN, filename, errno_string());
	error_free = FALSE;
	return (error_free);
  }

  /* 
   * get the size of the file
   */
  if(fstat(fd, &statb) < 0 )
  {
	error(ERR_MSG_FSTAT, filename, errno_string());
	error_free = FALSE;
	return(error_free);
   }

  if(S_ISREG(statb.st_mode)==0)
  {
	error(" parsing file error: %s is not a file\n",filename);
	error_free = FALSE;
	return(error_free);
   }

   /* file time stamp */
   if(file_time) *file_time = statb.st_mtime;

   /* 
    * and map it into my address space
    */
   if(statb.st_size)
   {
	if((fileaddr = (char *) mmap(0, statb.st_size, PROT_READ|PROT_WRITE,
				MAP_PRIVATE, fd, 0)) <= (char *) 0)
	{
		error(ERR_MSG_MMAP, filename, errno_string());
		error_free = FALSE;
		return(error_free);
	}

	/*
	 * set current lex focus on the file
	 */

	lexinput = fileaddr;

	/*
	 * and parse the file
	 */

	if(yyparse() == 1)
	{
		error("parsing %s failed", filename);
		error_free = FALSE;
	}

	/*
	 * Parsing is finished
	 *
	 * unmap the file and close it
	 */

	if(munmap(fileaddr, statb.st_size) == -1)
	{
		error(ERR_MSG_MUNMAP, errno_string());
	}
  } else {
	/* empty file, ignore it */
	error("empty configuration file %s", filename);
	error_free = FALSE;
  }

  if(close(fd) == -1)
  {
	error(ERR_MSG_CLOSE, errno_string());
  }

  return(error_free);
}


int personal_file_reading(char* dirname, char* filename, time_t *file_time)
{

  static char file[100];
  int error_free;

	file[0] = '\0';
	if(dirname != NULL)
		sprintf(file, "%s/%s", dirname, filename);
	else
		sprintf(file, "%s", filename);

        error_free = parsing_file(file,file_time);
	macro_list_delete();
	return(error_free);
}

/* If we have a serious problem, this function will	*/
/* terminate (<==> exit) the program			*/
/* now it won't call error_exit, call error only and
   return FALSE */

int config_init(char *dirname)
{
	DIR *dirp;
	struct dirent *direntp;
	int error_free = TRUE;
	struct stat statbuf;


	dirp = opendir(dirname);
	if(dirp == NULL)
	{
		error(ERR_MSG_OPENDIR,
			dirname, errno_string());
		error_free = FALSE;
		return error_free;
	}

	if(stat(dirname,&statbuf)>=0 &&
	   S_ISDIR(statbuf.st_mode)==0)
	{
		error(ERR_MSG_OPENDIR,
			dirname, errno_string());
		error_free = FALSE;
		return error_free;
	}

	while((direntp = readdir(dirp)) != NULL)
	{


		if(strcmp(direntp->d_name,SNMPRELAY_REG_FILE))
			continue;

		sprintf(config_file_4_res, "%s/%s", dirname, direntp->d_name);
	
		if(parsing_file(config_file_4_res,NULL) == FALSE){
		  error_free = FALSE;
		  continue;
		}

		macro_list_delete();

		config_file_4_res[0] = '\0';
	}

	if(closedir(dirp) == -1)
	{
		error(ERR_MSG_CLOSEDIR, dirname, errno_string());
	}

/*
	if(tables_to_subtrees(error_label))
	{
		error("tables_to_subtrees() failed: %s", error_label);
		error_free = FALSE;
	}
	table_list_delete();
*/


	if(first_agent == NULL)
	{
		error("No SNMP agent configured");
		error_free = FALSE;
	}

	if(trace_level > 0)
	{
		trace_subtrees();
		trace_agents();
	}
	return(error_free);
}



/****************************************************************/
/*
 * if pass is  TRY, see can we add all the subtrees of the table
 * if pass is GO, we really go ahead and add the subtrees
 */
int single_table_to_subtrees(int pass,Table *tp, char* error_label)
{
  /* update the columnar object for the table */
	Subtree *sp;
	Subid one = 1;
	Subid column;
	Subid index;
	TblTag *tbl_tag=NULL;


	error_label[0] = '\0';

	if(static_subids)
	{
		error("BUG: tables_to_subtrees(): static_subids not NULL");
		free(static_subids);
		static_subids = NULL;
	}
	if(static_len)
	{
		error("BUG: tables_to_subtrees(): static_len not 0");
		static_len = 0;
	}



		for(index = tp->first_index_subid; index <= tp->last_index_subid; index++)
		{
			for(column = tp->first_column_subid; column <= tp->last_column_subid; column++)
			{
				if(pass == TABLE_TO_OID_GO){
				  tbl_tag = (TblTag*)malloc(sizeof(TblTag));
				  if(tbl_tag != NULL){
				    tbl_tag->entry_index = tp->first_index_subid;
				    tbl_tag->type = TBL_TAG_TYPE_LEAF;
				    tbl_tag->table = tp;
				  }
				}
				if(subids_cat(tp->name.subids, tp->name.len))
				{
					return -1;
				}
				if(subids_cat(&one, 1) == -1)
				{
					return -1;
				}
				if(subids_cat(&column, 1) == -1)
				{
					return -1;
				}
				if(subids_cat(&index, 1) == -1)
				{
					return -1;
				}
		
				if(pass == TABLE_TO_OID_GO &&subtree_add(tp->agent, static_subids, static_len,tbl_tag) == -1)
				{
					sprintf(error_label, "subtree_add() failed for table %s for the agent %s",
						SSAOidString(&(tp->name)),
						tp->agent->name);
					if(static_subids)
					{
						free(static_subids);
					}
					if(tbl_tag)
						free(tbl_tag);
					tbl_tag = NULL;
					static_subids = NULL;
					static_len = 0;
					return -1;
				}
				if(pass == TABLE_TO_OID_TRY &&
				   (sp=subtree_find(static_subids,static_len))
				   != NULL){
					return -1;
				}

				if(static_subids)
				{
					free(static_subids);
				}
				static_subids = NULL;
				static_len = 0;
				tbl_tag = NULL;
			}
		}


	return 0;
}

/* This function translates the tables in subtrees	*/


	
/*********** SNMP security (5-13-96) ******/
/* If we have a serious problem, this function will	*/
/* terminate (<==> exit) the program			*/

int sec_config_init(char *filename)
{
	int error_free = TRUE;
	Manager *manager;


	delete_manager_list();
	delete_community_list();
	if(trap_community)
	{
		free(trap_community);
		trap_community = NULL;
	}
	delete_trap_destinator_list();

 	error_free = parsing_file(filename,NULL);

	if(trace_level > 0)
	{
		trace("\n");
		trace_managers();
		trace_filter();
		trace_trap_destinators();
	}

	return(error_free);
}

int res_file_init(char *dirname,SapResource *sp)
{
	DIR *dirp;
	struct dirent *direntp;
	int error_free = TRUE;
  	time_t file_time=0;


	dirp = opendir(dirname);
	if(dirp == NULL)
	{
		error(ERR_MSG_OPENDIR,
			dirname, errno_string());
		error_free = FALSE;
		return error_free;
	}

	while((direntp = readdir(dirp)) != NULL)
	{

		int pos;

		pos = strlen(direntp->d_name) - strlen(SNMPRESOURCE_SUFFIX);
		if( (pos<0) ||
		    strcmp(&(direntp->d_name[pos]),SNMPRESOURCE_SUFFIX))
			continue;

		sprintf(config_file_4_res, "%s/%s", dirname, direntp->d_name);
	
		if(parsing_file(config_file_4_res,&file_time) == FALSE){
		  error_free = FALSE;
		  continue;
		}
		if(sp!=NULL)
			sp->rsrc_file_time = file_time;

		config_file_4_res[0] = '\0';
	}

	if(closedir(dirp) == -1)
	{
		error(ERR_MSG_CLOSEDIR, dirname, errno_string());
	}

  return(error_free);
}
/*********** SNMP security (5-13-96) ******/

void res_config_init(char *dirname)
{
	int error_free;
   	SapResource *rp;

	/* delete_resource_list() */

	/* if recovery , delete all processes in the pid file */
	read_pid_file(pid_file);

	if(recovery_on == FALSE) kill_all_pid_rec_list();

	/* MRF */
	/* parsing the resource files in the default directory */
	/* last_res_modify_time should be the largest one */
	error_free = res_file_init(dirname,first_res);

   	for(rp=first_res; rp ; rp=rp->next_res){
		resource_handling(rp);
	}
	
	read_acl();

	if(recovery_on == TRUE) kill_part_pid_rec_list();

	recovery_on = FALSE; /* recovery is done */
	delete_pid_rec_list();

	/* should update pid file */

}

int resource_update(char *dirname)
{
  time_t file_time;
  int error_free = TRUE;

	/* MRF: find out the largest latest time stamp of resource files */

  /* mark the resouce element to be kept */
  mark_all_resources_not_visit();
  res_parsing_state = RES_PARSING_STATE_RE_READ;
  reconfig_first_res = NULL;

  delete_pid_rec_list();
  read_pid_file(pid_file);

	/* MRF: reading all resource file again */
  /* parsing the resource file */
  error_free = res_file_init(dirname,reconfig_first_res);

  if(error_free==FALSE){
	error("parsing error in reading the resouce file %s:%s",
		dirname,error_label);
	return FALSE;
  }

  merging_resource_list();

  read_acl();

  write_pid_file(pid_file);

  res_parsing_state = RES_PARSING_STATE_FROM_SCRATCH;
  
  return TRUE;
}

int read_acl()
{
	SapResource * sp, * nextsp;
	Agent *agent;
	int error_free=TRUE;

	sp = first_res;
	while (sp) {
		if (sp->agent && sp->agent->first_manager) {
			agent_manager_list_free (sp->agent->first_manager);
			sp->agent->first_manager = NULL;
		}
		sp = sp->next_res;
	}
	init_manager_set ();
	sp = first_res;
	while (sp) {
		if (sp->sec_file) {
 			error_free = parsing_file(sp->sec_file, NULL);

			if(trace_level > 0)
			{
				trace("\n");
				trace_agents();
				trace_managers();
				trace_filter();
				trace_trap_destinators();
			}

			if (error_free) {
				if (sp->agent)
					sp->agent->first_manager = get_curr_manager_set();
				init_manager_set ();
			}

		}
		sp = sp->next_res;
	}
	return TRUE;
}
int read_agent_acl(SapResource * sp)
{
	Agent *agent;
	int error_free=TRUE;

	if (sp) {
		if (sp->agent && sp->agent->first_manager) {
			agent_manager_list_free (sp->agent->first_manager);
			sp->agent->first_manager = NULL;
		}
	}
	init_manager_set ();
	if (sp) {
		if (sp->sec_file) {
 			error_free = parsing_file(sp->sec_file, NULL);

			if(trace_level > 0)
			{
				trace("\n");
				trace_agents();
				trace_managers();
				trace_filter();
				trace_trap_destinators();
			}

			if (error_free) {
				if (sp->agent)
					sp->agent->first_manager = get_curr_manager_set();
				init_manager_set ();
			}

		}
	}
	return TRUE;
}

int read_agent_files (Agent * ap)
{
	SapResource *sp, *firstguy, *next;
	time_t file_time;

	if (ap == NULL) {
		return 1;
	}
	if (trace_level > 0)
		trace ("read_agent_files() agent -%s- ipaddr %s timeout %d id %d status %d pid %d mgr %X\n",
			ap->name ? ap->name : "NO NAME",
			address_string (&(ap->address)),
			ap->timeout, ap->agentID, ap->agentStatus,
			ap->agentProcessID, ap->first_manager);
	
	if (ap->name == NULL || *(ap->name) == 0) {
		return 1;
	}
	
	/* find an existing SapResource - if found, update the acl
	** for this agent
	*/
	sp = resource_find_by_name (ap->name);
	if (sp) {
		read_agent_acl (sp);
		sp->agent = ap;
		return 0;
	}

	firstguy = first_res;
	first_res = NULL;
	if (static_res) {
		resource_free (static_res);
	}
	static_res = NULL;
	/* see if the agent has a personal resource file - if found,
	** create a new SapResource with this
	** agentPersonalFile is the .reg file
	** agentConfigFile is the .rsrc file
	*/
	res_parsing_state = RES_PARSING_STATE_FROM_SCRATCH;
	if (ap->agentConfigFile.len) {
		if (parsing_file((char *)(ap->agentConfigFile.chars),&file_time) == TRUE) {
			first_res->next_res = firstguy;
			first_res->agent = ap;
			static_res = NULL;
			return 0;
		}
	}

	/* else, parse all the resource files in the default directory
	** to find one whose agent name matches this one, and use it
	*/
	res_parsing_state = RES_PARSING_STATE_FROM_SCRATCH;
	res_file_init (config_dir, NULL);
	sp = first_res;
	while (sp) {
		if (sp->res_name && !strcmp (sp->res_name, ap->name))
			break;
		else if (sp->personal_file && ap->agentPersonalFile.chars && !strcmp (sp->personal_file, (char *) (ap->agentPersonalFile.chars)))
			break;
		else
			sp = sp->next_res;
	}
	if (sp) {
		resource_detach (sp);
		sp->next_res = firstguy;
		firstguy = sp;
		firstguy->agent = ap;
		if (firstguy->res_name == NULL)
			firstguy->res_name = strdup (ap->name);
	}

	sp = first_res;
	while (sp) {
		next = sp->next_res;
		resource_free (sp);
		sp = next;
	}
	first_res = firstguy;
	read_agent_acl (first_res);
	return 0;
}

