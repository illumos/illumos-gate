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
 */
/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "impl.h"
#include "asn1.h"
#include "error.h"
#include "snmp.h"
#include "trap.h"

#include "snmpdx_stub.h"
#include "agent.h"
#include "subtree.h"
#include "res.h"
#include "sh_table.h"

#include "dispatcher.h"


typedef void (*SapDelFunc)(char* t);
typedef char* (*SapAllocFunc)();
typedef char* (*SapFirstEntryFunc)();
typedef int (*SapChkEntryFunc)(char* t);
typedef int (*SapModifyEntryFunc)(int pass,char* t,int offset,Integer num,String *str, Oid *name);
typedef int (*SapAddEntryFunc)(char *t);
typedef int (*SapMatchIndexFunc)(Integer index, char* t);
typedef int (*SapMatchDoubleIndexFunc)(Integer index, Integer index2, char* t);
typedef int (*SapIndexOffsetFunc)();
typedef int (*SapIndexOffsetFunc2)();
typedef char* (*SapAdvanceFunc)(char *t);
typedef int (*SapIndexFunc)(char *t);
typedef int (*SapIndexFunc2)(char *t);
typedef char* (*SapCloneFunc)(char *t);

#define SAP_ST_INACTIVE 0
#define SAP_ST_ERR 1
#define SAP_ST_ACTIVE 2

#define DEFAULT_SAP_TBL_INC_SIZE 100
#define SAP_TBL_SUCCESS 1
#define SAP_TBL_FAIL 0
#define SAP_INVALID_INDEX -1
#define SAP_TBL_ENTRY_VALID 1

extern int read_agent_acl (SapResource *);
/** Table **/
/** Current impl, fix array size */
typedef struct _SapTable {
	int size;
	char *next;
	char *first;
	SapDelFunc del;
	SapAllocFunc alloc;
	SapCloneFunc clone;
	SapFirstEntryFunc first_entry;
	SapChkEntryFunc chk_entry;
	SapAddEntryFunc	add_entry;
	SapModifyEntryFunc modify_entry;
	SapMatchIndexFunc match_index;
	SapMatchDoubleIndexFunc match_double_index;
	SapIndexOffsetFunc index_offset;
	SapIndexOffsetFunc2 index_offset_2;
	SapAdvanceFunc advance_entry;
	SapIndexFunc index;
	SapIndexFunc2 index_2;
} SapTable;

/****** AgentTable private Info *****/
void free_Agent(char *t);
char* alloc_Agent();
char* clone_Agent();
int chk_Agent(char* t);
char* first_entry_Agent();
int modify_entry_Agent(int pass,char *t,int offset, Integer num, String *str,
				  Oid *name);
int match_index_Agent(Integer index, char* t);
int match_double_index_Agent(Integer index, Integer index2, char* t);
int index_offset_agent();
int index_offset_2_Agent();
int add_entry_Agent(char* t);
char* advance_entry_Agent(char* t);
int index_agent(char *t);
int index_2_Agent(char *t);
static SapTable agent_tbl = { 0, 0, 0, 
		free_Agent,alloc_Agent,clone_Agent,
		first_entry_Agent,
		chk_Agent,
		add_entry_Agent,
		modify_entry_Agent,
		match_index_Agent,
		match_double_index_Agent,
		index_offset_agent, 
		index_offset_2_Agent,
		advance_entry_Agent,
		index_agent, 
		index_2_Agent};

/***** AgentEntry Specific MACRO ****/
#define OFFSET_AGENT_ID 1
#define OFFSET_AGENT_STATUS 2
#define OFFSET_AGENT_TIME_OUT 3
#define OFFSET_AGENT_PORT_NUMBER 4
#define OFFSET_AGENT_PERSONAL_FILE 5
#define OFFSET_AGENT_CONFIG_FILE 6
#define OFFSET_AGENT_EXECUTABLE 7
#define OFFSET_AGENT_VERSION_NUM 8
#define OFFSET_AGENT_PROCESS_ID 9
#define OFFSET_AGENT_AGENT_NAME 10
#define OFFSET_AGENT_SYSTEM_UP_TIME 11
#define OFFSET_AGENT_WATCH_DOG_TIME 12
/***** AgentEntry Specific MACRO ****/

/****** AgentTable private Info *****/


/****** RegTreeTable private Info *****/
void free_Subtree(char *t);
char* alloc_Subtree();
char* clone_Subtree();
int chk_Subtree(char* t);
char* first_entry_Subtree();
int modify_entry_Subtree(int pass,char *t,int offset, Integer num, String *str,
				 Oid *name);
int match_index_Subtree(Integer index, char* t);
int match_double_index_Subtree(Integer index, Integer index2, char* t);
int index_offset_Subtree();
int index_offset_2_Subtree();
int add_entry_Subtree(char* t);
char* advance_entry_Subtree(char* t);
int index_Subtree(char *t);
int index_2_Subtree(char *t);
static SapTable reg_tree_tbl = { 0, 0, 0, 
		free_Subtree,alloc_Subtree,clone_Subtree,
		first_entry_Subtree,
		chk_Subtree,
		add_entry_Subtree,
		modify_entry_Subtree,
		match_index_Subtree,
		match_double_index_Subtree,
		index_offset_Subtree, 
		index_offset_2_Subtree,
		advance_entry_Subtree,
		index_Subtree, 
		index_2_Subtree};

/***** RegTreeTable Specific MACRO ****/
#define OFFSET_REGTREE_INDEX 1
#define OFFSET_REGTREE_ID	2
#define OFFSET_REGTREE_OID	3
#define OFFSET_REGTREE_STATUS	4
/***** RegTreeTable Specific MACRO ****/

/****** RegTblTable private Info *****/
void free_Table(char *t);
char* alloc_Table();
char* clone_Table();
int chk_Table(char* t);
char* first_entry_Table();
int modify_entry_Table(int pass,char *t,int offset, Integer num, String *str,
				 Oid *name);
int match_index_Table(Integer index, char* t);
int match_double_index_Table(Integer index, Integer index2, char* t);
int index_offset_Table();
int index_offset_2_Table();
int add_entry_Table(char* t);
char* advance_entry_Table(char* t);
int index_Table(char *t);
int index_2_Table(char *t);
static SapTable reg_tbl_tbl = { 0, 0, 0, 
		free_Table,alloc_Table,clone_Table,
		first_entry_Table,
		chk_Table,
		add_entry_Table,
		modify_entry_Table,
		match_index_Table,
		match_double_index_Table,
		index_offset_Table,
		index_offset_2_Table,
		advance_entry_Table,
		index_Table,
		index_2_Table};

/***** RegTblTbl Specific MACRO ****/
#define OFFSET_REG_TBL_INDEX	1
#define OFFSET_REG_TBL_AGENT_ID	2
#define OFFSET_REG_TBL_OID	3
#define OFFSET_REG_TBL_SCOL	4
#define OFFSET_REG_TBL_ECOL	5
#define OFFSET_REG_TBL_SROW	6
#define OFFSET_REG_TBL_EROW	7
#define OFFSET_REG_TBL_STATUS	8
/***** RegTblTbl Specific MACRO ****/



/****** RegTreeTable private Info *****/

/***********/

int sync_agent_acl (Agent * agent)
{
	SapResource * rp;
	if (agent == NULL) {
		return 0;
	}
	read_agent_files (agent);
	return 0;
}

/*** string equal ***/
int string_equal(String *string1, String *string2)
{
  int i;
  if(string1 == NULL && string2 == NULL) return 1;
  if(string1 == NULL || string2 == NULL) return 0;
  if(string1->len == string2->len){
	for(i=0;i<string1->len;i++){
		if(string1->chars[i] != string2->chars[i])
			return 0;
	}
	return 1;
  }
  return 0;
}

int cpy_2_char_and_string(String* dst1, String *src, char** dst2)
{
  if(dst1->chars) free(dst1->chars);
  dst1->chars = NULL;
  dst1->len = 0;
  if((*dst2)) free((*dst2));
  *dst2 = NULL;
  if(src->len !=0 && src->chars ){
	if( (dst1->chars = (u_char *)malloc(src->len)) == NULL)
		return 0;
  	memcpy(dst1->chars,src->chars,src->len);
	dst1->len = src->len;
  	if( ((*dst2) = (char*)malloc((src->len+1)* sizeof(char))) == NULL )
		return 0;
  	strncpy((*dst2),(char*)src->chars,src->len);
	(*dst2)[src->len]='\0';
  }
  return 1;	
}

int cpy_2_string(String* dst1, String *src)
{
  if(dst1->chars) free(dst1->chars);
  dst1->chars = NULL;
  dst1->len = 0;
  if(src->len !=0 || src->chars ){
	if( (dst1->chars = (u_char *)malloc(src->len)) == NULL)
		return 0;
  	memcpy(dst1->chars,src->chars,src->len);
	dst1->len = src->len;
  }
  return 1;	
}
/************************/

/***** AgentEntry Specific routines ****/

char* first_entry_Agent()
{
  return((char*)first_agent);
}

int add_entry_Agent(char* t)
{
  Agent *entry = (Agent*) t;

  if(first_agent == NULL){
	entry->next_agent = NULL;
  }else{
	entry->next_agent = first_agent;
  }
  first_agent = entry;
  return SAP_TBL_SUCCESS;
}

/* a hack: assume the index is integer */
int index_agent(char* t)
{
	Agent *entry = (Agent*) t;
	if(entry==NULL) return 0;
	return(entry->agentID);
}

int index_2_Agent(char *t)
{
	return 0;
}

int modify_entry_Agent(int pass,char *t, int offset, Integer num, String *str,
				  Oid *name)
{
	int res=1;
	Agent *entry = (Agent*) t;
 	Subtree *sp;

  	if(entry==NULL) return 0;

	switch(offset){
	  case OFFSET_AGENT_PORT_NUMBER: 
	        if(pass==FIRST_PASS) return(res);
		/* policy: once the port is bind, may not allow it
		   to bind to another port. If allow, need unbind and
		   rebind */
		entry->agentPortNumber = entry->address.sin_port = num; 
		/* Bug fix 4145620 - The subagents listen on the loopback driver */
  		entry->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		break;
	  case OFFSET_AGENT_AGENT_NAME:
	        if(pass==FIRST_PASS) return(res);
		res = cpy_2_char_and_string(&(entry->agentName),str,&(entry->name));
		/* TODO: sync the agent's ACL with the resource list here */
		sync_agent_acl (entry);
		break;
	  case OFFSET_AGENT_TIME_OUT: 
		/* for timeout > relay_agent_max_agent_time_out
	 	 * we reset it to relay_agent_max_agent_time_out
 		 */
	        if(pass==FIRST_PASS) return(res);
		if(num>relay_agent_max_agent_time_out){
			entry->agentTimeOut = entry->timeout = 
				relay_agent_max_agent_time_out;
		}else{
			entry->agentTimeOut = entry->timeout = num; 
		}
		break;

	  case OFFSET_AGENT_ID: 
		/* may not be allowd to change */
		entry->agentID = num; break;
	  case OFFSET_AGENT_STATUS: 
		/* valid state transistion for user:
		 * inactive-> any state except inactive
  		 * active-> inactive, destroy except active
		 */
		if(entry->agentStatus == num) break;
		if(pass==SECOND_PASS){
			entry->agentStatus = num; 
			sync_subtrees_with_agent(entry);
		}
		if(num==SSA_OPER_STATUS_ACTIVE){
		   	if(pass==SECOND_PASS)
		 	  activate_table_for_agent(entry);
		}else if(num==SSA_OPER_STATUS_NOT_IN_SERVICE){
		}else if(num==SSA_OPER_STATUS_DESTROY){
			/* destroy the table before the subtree */
			if(pass==FIRST_PASS &&
			   entry->agentStatus == SSA_OPER_STATUS_INIT)
				return(0);
		   	if(pass==SECOND_PASS)
			  agent_destroy(entry);
		}else return(0); 
		break;
	  case OFFSET_AGENT_PROCESS_ID: 
	        if(pass==FIRST_PASS) return(res);
		entry->agentProcessID = num; break;
	  case OFFSET_AGENT_PERSONAL_FILE: 
	        	if(pass==FIRST_PASS) return(res);
			res = cpy_2_string(&(entry->agentPersonalFile),str);
			break;
	  case OFFSET_AGENT_CONFIG_FILE:
	        	if(pass==FIRST_PASS) return(res);
			res = cpy_2_string(&(entry->agentConfigFile),str);
			break;
	  case OFFSET_AGENT_EXECUTABLE:
	        	if(pass==FIRST_PASS) return(res);
			res = cpy_2_string(&(entry->agentExecutable),str);
			break;
	  case OFFSET_AGENT_VERSION_NUM:
	        	if(pass==FIRST_PASS) return(res);
			res = cpy_2_string(&(entry->agentVersionNum),str);
			break;
	  case OFFSET_AGENT_SYSTEM_UP_TIME:
	        	if(pass==FIRST_PASS) return(res);
			entry->agentSystemUpTime = num; break;
	  case OFFSET_AGENT_WATCH_DOG_TIME:
	        	if(pass==FIRST_PASS) return(res);
			entry->agentWatchDogTime = num; break;
	}
	return res;
}

void free_Agent(char* t)
{
  Agent *tmp=(Agent *)t;
  if(tmp==NULL) return;
  free(tmp);
}

char* alloc_Agent()
{
  char* t;
  if(t = (char*)calloc(1,sizeof(Agent))){
	 ((Agent*)t)->agentStatus = SSA_OPER_STATUS_INIT;
	 return t;
  }
  return NULL;
}

char* clone_Agent(char* orig)
{
  /* image copy */
  char* t;
  if(t = (char*)calloc(1,sizeof(Agent))){
	 memcpy(t,orig,sizeof(Agent));
	 return t;
  }
  return NULL;
}

int chk_Agent(char* t)
{
  Agent *entry=(Agent *)t;
  if(entry == NULL) return SAP_TBL_FAIL;
  return SAP_TBL_SUCCESS;
}

int match_index_Agent(Integer index, char* t)
{
  Agent *entry = (Agent *)t;
  if(chk_Agent(t) == SAP_TBL_SUCCESS)
	if(entry->agentID == index)
		return SAP_TBL_SUCCESS;
  return SAP_TBL_FAIL;
}

int match_double_index_Agent(Integer index1, Integer index2, char* t)
{
  return SAP_TBL_FAIL;
}

int index_offset_agent()
{
	return(OFFSET_AGENT_ID);
}
int index_offset_2_Agent()
{
	return(-1);
}

char* advance_entry_Agent(char* t)
{
  Agent *entry = (Agent*) t, *i;
  if(entry==NULL) return (NULL);
  for(i=entry->next_agent;i;i=i->next_agent){
	if(chk_Agent((char*)i) == SAP_TBL_SUCCESS) return((char*)i);
  }
  return(NULL);
}


/***** AgentEntry Specific routines ****/

/***** RegTreeEntry Specific routines ***/
char* first_entry_Subtree()
{
  return((char*)first_subtree);
}

char* advance_entry_Subtree(char* t)
{
  Subtree *entry = (Subtree*) t, *i;
  if(entry==NULL) return (NULL);
  for(i=entry->next_subtree;i;i=i->next_subtree){
	if(chk_Subtree((char*)i) == SAP_TBL_SUCCESS) return((char*)i);
  }
  return(NULL);
}

int add_entry_Subtree(char* t)
{
  /* can't register a subtree with agent */
  Subtree *entry = (Subtree*) t, *sp, *last=NULL;
  int ret;

  if(entry == NULL ) return SAP_TBL_FAIL;
  if(entry->agent == NULL && entry->regTreeAgentID > 0){
	/* initialize the agent */
	if( (entry->agent = agent_find_by_id(entry->regTreeAgentID))==NULL)
		return SAP_TBL_FAIL;
  }

  /* if name not exist, insert is not allowed */

        for(sp = first_subtree; sp; sp = sp->next_subtree)
        {
                ret = SSAOidCmp(&(entry->name), &(sp->name));
                if(ret == 0)
                {
			/* for duplication registration of oid,
			   replace the current one */
			subtree_detach(sp);
			subtree_free(sp);
			break;
                }
                else
                if(ret < 0)
                {
                        break;
                }
 
                last = sp;
        }


  if(last == NULL){
	entry->next_subtree = first_subtree;
	first_subtree = entry;
  }else{
	entry->next_subtree = last->next_subtree;
	last->next_subtree = entry;
  }
  return SAP_TBL_SUCCESS;
}

int index_Subtree(char *t)
{
	Subtree *entry = (Subtree*) t;
	if(entry == NULL) return 0;
	return(entry->regTreeAgentID);
}

int index_2_Subtree(char *t)
{
/* no longer used */
	Subtree *entry = (Subtree*) t;
	if(entry == NULL) return 0;
	return(entry->regTreeIndex);
}


/*
 * If the pass is FIRST_PASS, this function is called when the entry
 * exits. It may not be allowed to overwrite some fields.
 */
int modify_entry_Subtree(int pass, char *t,int offset, Integer num, String *str,
				 Oid *name)
{
	int res = 1;
	Subtree *entry = (Subtree*) t;
	if(entry==NULL) return 0;
	switch(offset){
	  case OFFSET_REGTREE_ID: /* need to detach and reattach */
	    if(pass==SECOND_PASS){
		if(entry->agent && entry->agent->agentID != num){ /* detach */
			subtree_remove_from_agent_list(entry);
		}
		if(entry->agent == NULL){ /*attach a new one */
		  if( (entry->agent=agent_find_by_id(num)) != NULL){
			entry->next_agent_subtree = entry->agent->first_agent_subtree;
			entry->agent->first_agent_subtree = entry;
		  }
		}
	    }
	    entry->regTreeAgentID = num; break;
	  case OFFSET_REGTREE_STATUS: 
		if(pass==FIRST_PASS){ 
			/* don't allow user to destroy tree object which
			   belongs to table */
			if(entry->tbl_tag !=NULL  &&
			   entry->tbl_tag->table != NULL)
				return 0;
			if(entry->name.subids == NULL ||
			   entry->name.len == 0)
				return 0;
			entry->regTreeStatus = num; 
			break;
		}
		/* (mibpatch) if entry->mirrorTag == NULL
 		   create a new mirror_table */
		if(entry->mirror_tag==NULL)
			create_mirror_table_from_subtree((Subtree*)entry);

		/* if status is not-in-service, we may destroy
		   this entry */
		if(num==SSA_OPER_STATUS_NOT_IN_SERVICE){
		   if(entry->regTreeStatus == SSA_OPER_STATUS_ACTIVE){
			/* (mibpatch) delete the mirror_table, don't use
			   delete_table call */
			if(entry->mirror_tag!=NULL){
			  if(entry->mirror_tag->table){
				table_detach(entry->mirror_tag->table);
				table_free(entry->mirror_tag->table);
			  }
			}
			subtree_detach(entry);
			subtree_free(entry);
                        break;
		   }
		}
		entry->regTreeStatus = num; 
		/* (mibpatch) if there exists corresponding table,
		 if(entry->mirrorTag!=NULL) update the table status */
		if(entry->mirror_tag!=NULL && entry->mirror_tag->table!=NULL)
			entry->mirror_tag->table->regTblStatus = num;
		break;
	  case OFFSET_REGTREE_INDEX: 
	    if(pass==SECOND_PASS){
		/* this may not be changed */
		if(entry->agent != NULL) 
		  entry->agent->agentTreeIndex = 
			(num>entry->agent->agentTreeIndex? num :
			 entry->agent->agentTreeIndex);
	    }
	    entry->regTreeIndex = num; break;
	  case OFFSET_REGTREE_OID: 
		/* don't allow to change any established oid */
		if(entry->tbl_tag !=NULL  &&
		   entry->tbl_tag->table != NULL)
			return 0;
		if(entry->name.subids != NULL &&
		   entry->name.len != 0)
			return 0;
		SSAOidZero(&(entry->name));
		SSAOidCpy(&(entry->name),name,error_label);
		break;
	}
	return(res);
}

void free_Subtree(char* t)
{
  Subtree *tmp=(Subtree *)t;
  if(tmp==NULL) return;
  if(tmp->name.subids!=NULL && tmp->name.len!=0)
  	SSAOidZero(&(tmp->name));
  free(tmp);
}

char* alloc_Subtree()
{
  char* t;
  if(t = (char*)calloc(1,sizeof(Subtree))){ 
	((Subtree*)t)->regTreeStatus = SSA_OPER_STATUS_NOT_IN_SERVICE;
	return t;
  }
  return NULL;
}

char* clone_Subtree(Subtree *tree)
{
  Subtree *t;
  if(t = (Subtree *)calloc(1,sizeof(Subtree))){ 
	memcpy(t,tree,sizeof(Subtree));
	t->name.subids = NULL;
	t->name.len = 0;
	SSAOidCpy(&(t->name),&(tree->name),error_label);
	return ((char *)t);
  }
  return NULL;
}

int chk_Subtree(char* t)
{
  Subtree *entry=(Subtree *)t;
  if(entry == NULL) return SAP_TBL_FAIL;
  return SAP_TBL_SUCCESS;
}

int match_index_Subtree(Integer index, char* t)
{
  Subtree *entry = (Subtree *)t;
  if(chk_Subtree(t) == SAP_TBL_SUCCESS)
        if(entry->regTreeIndex == index)
                return SAP_TBL_SUCCESS;
  return SAP_TBL_FAIL;
}

int match_double_index_Subtree(Integer index1, Integer index2,  char* t)
{
  Subtree *entry = (Subtree *)t;
  if(chk_Subtree(t) == SAP_TBL_SUCCESS)
        if(entry->regTreeAgentID == index1 && entry->regTreeIndex == index2)
                return SAP_TBL_SUCCESS;
  return SAP_TBL_FAIL;
}

int index_offset_Subtree()
{
	return(OFFSET_REGTREE_ID);
}
int index_offset_2_Subtree()
{
/* no longer used */
	return(OFFSET_REGTREE_INDEX);
}
/***** RegTreeEntry Specific routines ***/


/***** RegTblEntry Specific routines ***/
char* first_entry_Table()
{
  return((char*)first_table);
}

char* advance_entry_Table(char* t)
{
  Table *entry = (Table*) t, *i;
  if(entry==NULL) return (NULL);
  for(i=entry->next_table;i;i=i->next_table){
	if(chk_Table((char*)i) == SAP_TBL_SUCCESS) return((char*)i);
  }
  return(NULL);
}

static int tblcmp(Table* t1,Table* t2)
{
  if( 	(t1->first_column_subid == t2->first_column_subid) &&
      	(t1->last_column_subid == t2->last_column_subid) &&
	(t1->first_index_subid == t2->first_index_subid) &&
	(t1->last_index_subid == t2->last_index_subid) )	      
		return 0;
  return 1;
     
}


int add_entry_Table(char* t)
{
  Table *entry = (Table*) t, *sp, *last=NULL;
  int ret;

  if(entry == NULL ) return SAP_TBL_FAIL;
  if(entry->agent == NULL && entry->regTblAgentID > 0){
	/* initialize the agent */
	if( (entry->agent = agent_find_by_id(entry->regTblAgentID))==NULL)
		return SAP_TBL_FAIL;
  }

        for(sp = first_table; sp; sp = sp->next_table)
        {
		ret = tblcmp(entry,sp);
                if(ret == 0)
                {
			/* for duplication registration of oid,
			   replace the current one */
			delete_table(sp);
			break;
                }
 
                last = sp;
        }


  if(last == NULL){
	entry->next_table = first_table;
	first_table = entry;
  }else{
	entry->next_table = last->next_table;
	last->next_table = entry;
  }

  return SAP_TBL_SUCCESS;
}

int index_Table(char *t)
{
	Table *entry = (Table*) t;
	if(entry == NULL) return 0;
	return(entry->regTblAgentID);
}

int index_2_Table(char *t)
{
	Table *entry = (Table*) t;
	if(entry == NULL) return 0;
	return(entry->regTblIndex);
}

static int table_is_incomplete(Table *t)
{
  /* (mibpatch) don't know what to do */
  if(t->mirror_flag==1) return FALSE;
  if(t->first_column_subid==0 || t->last_column_subid==0 ||
     t->first_index_subid==0 || t->last_index_subid==0)
	return TRUE;
  return FALSE;
}

/*
 * If the pass is FIRST_PASS, this function is called when the entry
 * exits. It may not be allowed to overwrite some fields.
 */
int modify_entry_Table(int pass, char *t,int offset, Integer num, String *str,
				 Oid *name)
{
	int res = 1;
	Table *entry = (Table*) t;
	if(entry==NULL) return 0;
	switch(offset){

	  case OFFSET_REG_TBL_INDEX: 
		/* this may not be changed */
		if(pass==SECOND_PASS){
		  if(entry->agent != NULL) 
		    entry->agent->agentTblIndex = 
			(num>entry->agent->agentTblIndex? num :
			 entry->agent->agentTblIndex);
		}
		entry->regTblIndex = num; break;

	  case OFFSET_REG_TBL_AGENT_ID: /* need to detach and reattach */
		if(pass==SECOND_PASS){ 
		  if(entry->agent == NULL){ /*attach a new one */
		    entry->agent=agent_find_by_id(num);
		  }
		}
		entry->regTblAgentID = num; break;

	  case OFFSET_REG_TBL_OID: 
		/* this oid can be set up once, no replacement */
		if(pass==FIRST_PASS){
		  /* if table is complete, user can't change the table */
		  if(entry->name.subids !=NULL &&
		     entry->name.len !=0) return 0;
		  if(table_is_incomplete(entry)==TRUE) return res;
		  return 0;
		}
		if(pass==SECOND_PASS){ 
		  SSAOidZero(&(entry->name));
		  SSAOidCpy(&(entry->name),name,error_label);
		}
		break;

	 case OFFSET_REG_TBL_SCOL:
		if(table_is_incomplete(entry)){
			entry->first_column_subid = num;
		}else
			return(0);
		break;

	 case OFFSET_REG_TBL_ECOL:
		if(table_is_incomplete(entry)){
			entry->last_column_subid = num;
		}else
			return(0);
		break;

	 case OFFSET_REG_TBL_SROW:
		if(table_is_incomplete(entry)){
			entry->first_index_subid = num;
		}else
			return(0);
		break;

	 case OFFSET_REG_TBL_EROW:
		if(table_is_incomplete(entry)){
			entry->last_index_subid = num;
		}else
			return(0);
		break;


	 case OFFSET_REG_TBL_STATUS: 
		/* destroy the table or add the table */
		if(pass==FIRST_PASS){
		  if(table_is_incomplete(entry) == TRUE) return 0;
		  if( entry->regTblStatus == SSA_OPER_STATUS_ACTIVE &&
		       num==SSA_OPER_STATUS_ACTIVE ) return 0;
		  if( (entry->regTblStatus == SSA_OPER_STATUS_ACTIVE &&
		       num==SSA_OPER_STATUS_NOT_IN_SERVICE) ||
		      (entry->regTblStatus==SSA_OPER_STATUS_NOT_IN_SERVICE &&
		       num==SSA_OPER_STATUS_ACTIVE) )
				return(res);
		  if(single_table_to_subtrees(
			TABLE_TO_OID_TRY,entry,error_label) != -1)
				return(res);
			return 0;
		}

		/* second pass */
		if(num==SSA_OPER_STATUS_ACTIVE){
		  if(entry->regTblStatus == SSA_OPER_STATUS_ACTIVE) return 0;
		  if(single_table_to_subtrees
		     (TABLE_TO_OID_TRY,entry,error_label) != -1 &&
		     single_table_to_subtrees
			(TABLE_TO_OID_GO,entry,error_label) != -1 &&
		     activate_table(entry) != -1)
		  {
			/* (mibpatch) if table is mirror, set the
			   subtree status to active */
		  }
		}else if(num==SSA_OPER_STATUS_NOT_IN_SERVICE){
		  /* destroy the table */
		  if(entry->regTblStatus == SSA_OPER_STATUS_ACTIVE)
		  	delete_table(entry);
		  else
		     single_table_to_subtrees(TABLE_TO_OID_GO,entry,error_label);
		}
		entry->regTblStatus = num; 
	}
	return(res);
}

void free_Table(char* t)
{
  Table *tmp=(Table *)t;
  if(tmp==NULL) return;
  free(tmp);
}

char* alloc_Table()
{
  char* t;
  if(t = (char*)calloc(1,sizeof(Table))){ 
	((Table*)t)->regTblStatus = SSA_OPER_STATUS_NOT_IN_SERVICE;
	return t;
  }
  return NULL;
}

char* clone_Table(char* table)
{
  char* t;
  if(t = (char*)calloc(1,sizeof(Table))){ 
	memcpy(t,table,sizeof(Table));
	return t;
  }
  return NULL;
}

int chk_Table(char* t)
{
  Table *entry=(Table *)t;
  if(entry == NULL) return SAP_TBL_FAIL;
  return SAP_TBL_SUCCESS;
}

int match_index_Table(Integer index, char* t)
{
  Table *entry = (Table *)t;
  if(chk_Table(t) == SAP_TBL_SUCCESS)
        if(entry->regTblIndex == index)
                return SAP_TBL_SUCCESS;
  return SAP_TBL_FAIL;
}

int match_double_index_Table(Integer index1, Integer index2,  char* t)
{
  Table *entry = (Table *)t;
  if(chk_Table(t) == SAP_TBL_SUCCESS)
        if(entry->regTblAgentID == index1 && entry->regTblIndex == index2)
                return SAP_TBL_SUCCESS;
  return SAP_TBL_FAIL;
}

int index_offset_Table()
{
	return(OFFSET_REG_TBL_AGENT_ID);
}
int index_offset_2_Table()
{
	return(OFFSET_REG_TBL_INDEX);
}


/***** RegTblEntry Specific routines ***/


/***********************************************************/
void tbl_init(SapTable *this)
{
  if(this) this->first = (*this->first_entry)();
  /* point to the first of the list */
}

void tbl_free(SapTable *this)
{
  if(this) (*this->del)((char*)this->first);
  /* free out the list */
}


int tbl_add_entry(SapTable *this, char *entry)
{
  if(this == NULL) return SAP_TBL_FAIL;
  if(this) tbl_init(this);
  return((*this->add_entry)(entry));
 /* add entry to the list */
}

char *tbl_search(SapTable *this, Integer AgentID)
{
  char* t; 
  if(this == NULL) return(NULL);
  if(this) tbl_init(this);
  for(t=this->first;t;){
	if((*this->match_index)(AgentID,t) ==
	   SAP_TBL_SUCCESS)
		return t;
	t = (*this->advance_entry)(t);
  }
  return(NULL);
  /* call the search */
}

char *tbl_search_2(SapTable *this, Integer AgentID, Integer index2)
{
  char* t; 
  if(this == NULL) return(NULL);
  if(this) tbl_init(this);
  for(t=this->first;t;){
    if((*this->match_double_index)(AgentID,index2,t) ==
	   SAP_TBL_SUCCESS)
		return t;
	t = (*this->advance_entry)(t);
  }
  return(NULL);
  /* call the search2 */
}

int tbl_avail_index(SapTable *this)
{
	return -1;
  /* not required */
}

char *tbl_next_entry(SapTable *this, Integer AgentID)
{
  char* t; 
  if(this == NULL) return(NULL);
  if(this) tbl_init(this);
  for(t=this->first;t;){
    if((*this->match_index)(AgentID,t) == SAP_TBL_SUCCESS){
	if( (*this->chk_entry)(t) != SAP_TBL_SUCCESS) return NULL;
	return((*this->advance_entry)(t));
    }
    t = (*this->advance_entry)(t);
  }
  return(NULL);
  /* call the next_entry */
}

char *tbl_next_entry_2(SapTable *this, Integer AgentID, Integer index2)
{
  char* t; 
  if(this == NULL) return(NULL);
  if(this) tbl_init(this);
  for(t=this->first;t;){
    if((*this->match_double_index)(AgentID,index2,t) == SAP_TBL_SUCCESS){
	if( (*this->chk_entry)(t) != SAP_TBL_SUCCESS) return NULL;
	return((*this->advance_entry)(t));
    }
    t = (*this->advance_entry)(t);
  }
  return(NULL);
  /* call the next_entry */
}

char *tbl_first_entry(SapTable *this)
{
  char *t;
  if(this == NULL ) return (NULL);
  if(this) tbl_init(this);
  t=this->first;
  if( (*this->chk_entry)(t) == SAP_TBL_SUCCESS ) return(this->first);
  return( (*this->advance_entry)(t) );
  /* head of the list */
}

char* get_tbl_entry(SapTable *this, int search_type, int *snmp_error, Integer *AgentID)
{
	char *entry=NULL;
	switch(search_type)
	{
		case FIRST_ENTRY:
			if((entry = tbl_first_entry(this))
			    == NULL)
				*snmp_error = END_OF_TABLE;
			/* update the index */
			*AgentID = (*this->index)(entry);
			break;
		
		case NEXT_ENTRY:
			if((entry =
		            tbl_next_entry(this,*AgentID))
			  == NULL)
				*snmp_error = END_OF_TABLE;
			/* update the index */
			*AgentID = (*this->index)(entry);
			break;

		case EXACT_ENTRY:
			if( (entry =
			     tbl_search(this,*AgentID)) 
			  == NULL)
				*snmp_error = SNMP_ERR_NOSUCHNAME;
			break;
	}
 	return entry;
}

char* get_tbl_entry_2(SapTable *this, int search_type, int *snmp_error, Integer *AgentID, Integer *index2)
{
	char *entry=NULL;
	switch(search_type)
	{
		case FIRST_ENTRY:
			if((entry = tbl_first_entry(this))
			    == NULL)
				*snmp_error = END_OF_TABLE;
			/* update the index */
			*AgentID = (*this->index)(entry);
			*index2 = (*this->index_2)(entry);
			break;
		
		case NEXT_ENTRY:
			if((entry =
		            tbl_next_entry_2(this,*AgentID,*index2))
			  == NULL)
				*snmp_error = END_OF_TABLE;
			/* update the index */
			*AgentID = (*this->index)(entry);
			*index2 = (*this->index_2)(entry);
			break;

		case EXACT_ENTRY:
			if( (entry =
			     tbl_search_2(this,*AgentID,*index2)) 
			  == NULL)
				*snmp_error = SNMP_ERR_NOSUCHNAME;
			break;
	}
 	return entry;
}

/* Assumption: second phase comes after successful first phase
   in second phase cleanup the clone created in first phase, 
   if first phase fails, the clone is cleanup before return */ 
/* side effect, if index doesn't exist, add a new row */
int set_table_entry_field(SapTable *this, Integer AgentID, int pass, 
		  	Integer *num, String *str, Oid *name, int offset)
{
	static char* entry=NULL;
	static char* first_pass_entry=NULL;

	if( (pass==FIRST_PASS && first_pass_entry!=NULL &&
	     (*this->match_index)(AgentID,first_pass_entry)==SAP_TBL_FAIL) ||
	    (pass==SECOND_PASS && first_pass_entry!=NULL) )
	{
		(*this->del)((char*)first_pass_entry);
		first_pass_entry = NULL;
	}
	/* here, if first_pass_entry is not NULL => it points to the desired
	   entry */

	if( first_pass_entry==NULL && (entry = tbl_search(this,AgentID))==NULL){
	  if((entry = (*this->alloc)())==NULL)
		  	return SNMP_ERR_NOSUCHNAME;
	  if(pass==FIRST_PASS)
		first_pass_entry = entry;
	  if((*this->modify_entry)(pass,
			(pass==FIRST_PASS)?first_pass_entry:entry,
			(*this->index_offset)(), AgentID,
			NULL,NULL) == 0 ||
	     (*this->modify_entry)(pass,
			(pass==FIRST_PASS)?first_pass_entry:entry,
			offset,
			num?*num:0,str,name)==0){
		  (*this->del)((char*)
			(pass==FIRST_PASS)?first_pass_entry:entry);
		  first_pass_entry = NULL;
		  return SNMP_ERR_GENERR;
	  }
	  if(pass==SECOND_PASS){
	    if(tbl_add_entry(this,entry) == SAP_TBL_FAIL){
		  	(*this->del)((char*)entry);
		 	return SNMP_ERR_GENERR;
	    }
	  }
	}else{
	  /* entry exists, may need to do some clean up */
	  /* made a duplication */
	  if(pass==FIRST_PASS){
		if(first_pass_entry == NULL){
		  if( (first_pass_entry = (*this->clone)(entry)) == NULL)
			return SNMP_ERR_GENERR;
		}
	  }
	  if((*this->modify_entry)(pass,
			(pass==FIRST_PASS)?first_pass_entry:entry,
			offset,num?*num:0,str,name)==0){
			if(pass==FIRST_PASS)
		  	  (*this->del)((char*)first_pass_entry);
			first_pass_entry = NULL;
		  	return SNMP_ERR_GENERR;
	  }
	}
	entry = NULL;
	return SNMP_ERR_NOERROR;
}

int set_table_entry_field_2(SapTable *this, Integer AgentID, Integer index2,
	 int pass, Integer *num, String *str, Oid *name, int offset)
{
	static char* entry=NULL;
        static char* first_pass_entry=NULL;

        if( (pass==FIRST_PASS && first_pass_entry!=NULL &&
             (*this->match_double_index)(AgentID,index2,first_pass_entry)==SAP_TBL_FAIL) ||
            (pass==SECOND_PASS && first_pass_entry!=NULL) )
        {
                (*this->del)((char*)first_pass_entry);
                first_pass_entry = NULL;
        }
        /* here, if first_pass_entry is not NULL => it points to the desired
           entry */

	if( first_pass_entry==NULL && 
	    (entry = tbl_search_2(this,AgentID,index2))==NULL){
  		if( (entry = (*this->alloc)())==NULL)
		  return SNMP_ERR_NOSUCHNAME;
		if(pass==FIRST_PASS)
			first_pass_entry = entry;
		if((*this->modify_entry)(pass,
			(pass==FIRST_PASS)?first_pass_entry:entry,
			(*this->index_offset)(), AgentID,
			NULL,NULL)==0 ||
		(*this->modify_entry)(pass,
			(pass==FIRST_PASS)?first_pass_entry:entry,
			(*this->index_offset_2)(),index2,NULL,
			NULL)==0 ||
		 (*this->modify_entry)(pass,
			(pass==FIRST_PASS)?first_pass_entry:entry,
			offset,num?*num:0,str,name)==0){
		  (*this->del)((char*)
                        (pass==FIRST_PASS)?first_pass_entry:entry);
		  return SNMP_ERR_GENERR;
		}
		if(pass==SECOND_PASS){
			if(tbl_add_entry(this,entry) == SAP_TBL_FAIL){
	  			(*this->del)((char*)entry);
				return SNMP_ERR_GENERR;
			}
		}
	}else{
	  /* entry exists, may need to do some clean up */
	  if(pass==FIRST_PASS){
		/* clone the entry */
	    if(first_pass_entry == NULL){
		if( (first_pass_entry = (*this->clone)(entry)) == NULL)
			return SNMP_ERR_GENERR;
		  }
	  }
	  if( (*this->modify_entry)(pass,
                        (pass==FIRST_PASS)?first_pass_entry:entry,
			offset,num?*num:0,str,name)==0){
			if(pass==FIRST_PASS)
		  	  (*this->del)((char*)first_pass_entry);
			first_pass_entry = NULL;
			return SNMP_ERR_GENERR;
	  }
	}
	entry = NULL;
	return SNMP_ERR_NOERROR;
}

/***********************************************************/

int get_agentEntry(int search_type, AgentEntry_t **agentEntry_data, IndexType *index)
{
	int snmp_error;
	Integer AgentID = index->value[0];
	SapTable *tbl = &agent_tbl;
	char* entry = get_tbl_entry(tbl,search_type,&snmp_error,&AgentID);
	index->value[0] = AgentID;

	*agentEntry_data = (AgentEntry_t *)entry;

	return(snmp_error);
}


/***** AgentStatus       ********************************/

int set_agentStatus(int pass, IndexType index, Integer *AgentStatus)
{
  /* set agent status, remember to set all the subtree belongs to it */
	SapTable *tbl = &agent_tbl;
	Integer AgentID = index.value[0];

        int offset = OFFSET_AGENT_STATUS;
	return(set_table_entry_field(tbl,AgentID,pass,AgentStatus,NULL,NULL,offset));
}


/***** AgentTimeOut      ********************************/

int set_agentTimeOut(int pass, IndexType index, Integer *AgentTimeOut)
{
	SapTable *tbl = &agent_tbl;
	Integer AgentID = index.value[0];

        int offset = OFFSET_AGENT_TIME_OUT;
	return(set_table_entry_field(tbl,AgentID,pass,AgentTimeOut,NULL,NULL,offset));
}


/***** AgentPortNumber   ********************************/

int set_agentPortNumber(int pass, IndexType index, Integer *AgentPortNumber)
{
	SapTable *tbl = &agent_tbl;
	Integer AgentID = index.value[0];

        int offset = OFFSET_AGENT_PORT_NUMBER;
	return(set_table_entry_field(tbl,AgentID,pass,AgentPortNumber,NULL,NULL,offset));
}


/***** AgentPersonalFile ********************************/

int set_agentPersonalFile(int pass, IndexType index, String *AgentPersonalFile)
{
	SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_PERSONAL_FILE;
	Integer AgentID = index.value[0];

	return(set_table_entry_field(tbl,AgentID,pass,0,AgentPersonalFile,NULL,offset));
}


/***** AgentConfigFile   ********************************/

int set_agentConfigFile(int pass, IndexType index, String *AgentConfigFile)
{
	SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_CONFIG_FILE;
	Integer AgentID = index.value[0];

	return(set_table_entry_field(tbl,AgentID,pass,0,AgentConfigFile,NULL,offset));
}


/***** AgentExecutable   ********************************/

int set_agentExecutable(int pass, IndexType index, String *AgentExecutable)
{
	SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_EXECUTABLE;
	Integer AgentID = index.value[0];

	return(set_table_entry_field(tbl,AgentID,pass,0,AgentExecutable,NULL,offset));
}


/***** AgentVersionNum   ********************************/

int set_agentVersionNum(int pass, IndexType index, String *AgentVersionNum)
{
	SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_VERSION_NUM;
	Integer AgentID = index.value[0];

	return(set_table_entry_field(tbl,AgentID,pass,0,AgentVersionNum,NULL,offset));
}



/***** AgentProcessID    ********************************/

int set_agentProcessID(int pass, IndexType index, Integer *AgentProcessID)
{
	int ret;
	SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_PROCESS_ID;
	Integer AgentID = index.value[0];

	ret = set_table_entry_field(tbl,AgentID,pass,AgentProcessID,NULL,NULL,offset);
	return ret;
}


/***** AgentName         ********************************/

int set_agentName(int pass, IndexType index, String *AgentName)
{
	SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_AGENT_NAME;
	Integer AgentID = index.value[0];

	return(set_table_entry_field(tbl,AgentID,pass,0,AgentName,NULL,offset));
}

/***** agentSystemUpTime    ********************************/ 
 
int set_agentSystemUpTime(int pass, IndexType index, Integer *agentSystemUpTime){        
        SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_SYSTEM_UP_TIME;
	Integer agentID = index.value[0];

        return(set_table_entry_field(tbl,agentID,pass,agentSystemUpTime,NULL,NULL,offset));
} 

int set_agentWatchDogTime(int pass, IndexType index, Integer *agentWatchDogTime){
        SapTable *tbl = &agent_tbl;
        int offset = OFFSET_AGENT_WATCH_DOG_TIME;
	Integer agentID = index.value[0];

        return(set_table_entry_field(tbl,agentID,pass,agentWatchDogTime,NULL,NULL,offset));
}

 
int get_agentTableIndex(Integer *AgentTableIndex)
{
	/* next available index to be used */
	*AgentTableIndex = sap_agent_id;
	return SNMP_ERR_NOERROR;
}

int set_agentTableIndex(int pass, Integer *AgentTableIndex)
{
  switch(pass)
  {
	case FIRST_PASS:
		if(*AgentTableIndex != sap_agent_id +1)
	  		return SNMP_ERR_GENERR;
		break;
	case SECOND_PASS:
		sap_agent_id++;
  }
  return SNMP_ERR_NOERROR;
}

/***** Subtree         ********************************/

/***** regTreeEntry         ********************************/

int get_regTreeEntry(int search_type, RegTreeEntry_t **regTreeEntry_data, IndexType *index)
{
	int snmp_error;
	Integer regTreeAgentID = index->value[0];
	Integer regTreeIndex = index->value[1];

        SapTable *tbl = &reg_tree_tbl;
        char* entry = get_tbl_entry_2(tbl,search_type,&snmp_error,&regTreeAgentID,&regTreeIndex);
	index->value[0] = regTreeAgentID;
	index->value[1] = regTreeIndex;
	*regTreeEntry_data = (RegTreeEntry_t *)entry;
	return(snmp_error);
}

/***** regTreeOID           ********************************/

int set_regTreeOID(int pass, IndexType index, Oid *regTreeOID)
{
        SapTable *tbl = &reg_tree_tbl;
        int offset = OFFSET_REGTREE_OID;
	Integer regTreeAgentID = index.value[0];
	Integer regTreeIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTreeAgentID,regTreeIndex,pass,NULL,NULL,regTreeOID,offset));
}



/***** regTreeStatus        ********************************/

int set_regTreeStatus(int pass, IndexType index, Integer *regTreeStatus)
{
        SapTable *tbl = &reg_tree_tbl;
        int offset = OFFSET_REGTREE_STATUS;
	Integer regTreeAgentID = index.value[0];
	Integer regTreeIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTreeAgentID,regTreeIndex,pass,regTreeStatus,NULL,NULL,offset));
}



int get_regTreeTableIndex(Integer *regTreeTableIndex)
{
	/* it may overflow */
        *regTreeTableIndex = sap_reg_tree_index;
        return SNMP_ERR_NOERROR;
}

/*********************************************************/

/***** relayProcessIDFile   ********************************/

int get_relayProcessIDFile(String *sunMasterAgentStatusFile)
{
	sunMasterAgentStatusFile->chars = (u_char*)pid_file;
	sunMasterAgentStatusFile->len = strlen(pid_file);
        return SNMP_ERR_NOERROR;
}

int set_relayProcessIDFile(int pass, String *sunMasterAgentStatusFile)
{
        return SNMP_ERR_NOERROR;
}

/***** regTblEntry          ********************************/

int get_regTblEntry(int search_type, RegTblEntry_t **regTblEntry_data, IndexType *index)
{
	int snmp_error;
        SapTable *tbl = &reg_tbl_tbl;
	Integer regTblAgentID = index->value[0];
	Integer regTblIndex = index->value[1];

        char* entry = get_tbl_entry_2(tbl,search_type,&snmp_error,&regTblAgentID,&regTblIndex);
	index->value[0] = regTblAgentID;
	index->value[1] = regTblIndex;
	*regTblEntry_data = (RegTblEntry_t *)entry;
	return(snmp_error);
}
 
 
/***** regTblOID            ********************************/
 
int set_regTblOID(int pass, IndexType index, Oid *regTblOID)
{
        SapTable *tbl = &reg_tbl_tbl;
        int offset = OFFSET_REG_TBL_OID;
	Integer regTblAgentID = index.value[0];
	Integer regTblIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTblAgentID,regTblIndex,pass,NULL,NULL,regTblOID,offset));
}
 
/***** regTblStartColumn    ********************************/
 
int set_regTblStartColumn(int pass, IndexType index,
Integer *regTblStartColumn)
{
        SapTable *tbl = &reg_tbl_tbl;
        int offset = OFFSET_REG_TBL_SCOL;
	Integer regTblAgentID = index.value[0];
	Integer regTblIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTblAgentID,regTblIndex,pass,regTblStartColumn,NULL,NULL,offset));
}
 
 
/***** regTblEndColumn      ********************************/
 
int set_regTblEndColumn(int pass, IndexType index, Integer *regTblEndColumn)
{
        SapTable *tbl = &reg_tbl_tbl;
        int offset = OFFSET_REG_TBL_ECOL;
	Integer regTblAgentID = index.value[0];
	Integer regTblIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTblAgentID,regTblIndex,pass,regTblEndColumn,NULL,NULL,offset));
}
 
/***** regTblStartRow       ********************************/
 
int set_regTblStartRow(int pass, IndexType index, Integer *regTblStartRow)
{
        SapTable *tbl = &reg_tbl_tbl;
        int offset = OFFSET_REG_TBL_SROW;
	Integer regTblAgentID = index.value[0];
	Integer regTblIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTblAgentID,regTblIndex,pass,regTblStartRow,NULL,NULL,offset));
}
 
 
/***** regTblEndRow         ********************************/
 
int set_regTblEndRow(int pass, IndexType index, Integer *regTblEndRow)
{
        SapTable *tbl = &reg_tbl_tbl;
        int offset = OFFSET_REG_TBL_EROW;
	Integer regTblAgentID = index.value[0];
	Integer regTblIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTblAgentID,regTblIndex,pass,regTblEndRow,NULL,NULL,offset));
}
 
 
/***** regTblStatus         ********************************/
 
int set_regTblStatus(int pass, IndexType index, Integer *regTblStatus)
{
        SapTable *tbl = &reg_tbl_tbl;
        int offset = OFFSET_REG_TBL_STATUS;
	Integer regTblAgentID = index.value[0];
	Integer regTblIndex = index.value[1];

        return(set_table_entry_field_2(tbl,regTblAgentID,regTblIndex,pass,regTblStatus,NULL,NULL,offset));
}

int get_regTblTableIndex(Integer *regTblTableIndex)
{
	*regTblTableIndex = 0;
        return SNMP_ERR_NOERROR;
}


/***** relayResourceFile    ********************************/

int get_relayResourceFile(String *sunMasterAgentResourceConfigFile)
{
	sunMasterAgentResourceConfigFile->chars = (u_char*)resource_file;
	sunMasterAgentResourceConfigFile->len = strlen(resource_file);
        return SNMP_ERR_NOERROR;
}

int set_relayResourceFile(int pass, String *sunMasterAgentResourceConfigFile)
{
        return SNMP_ERR_NOERROR;
}


/***** relayPersonalFileDir ********************************/

int get_relayPersonalFileDir(String *relayPersonalFileDir)
{
	relayPersonalFileDir->chars = (u_char*)config_dir;
	relayPersonalFileDir->len = strlen(config_dir);
	return SNMP_ERR_NOERROR;
}

int set_relayPersonalFileDir(int pass, String *relayPersonalFileDir)
{
	return SNMP_ERR_NOERROR;
}


/***** relayLogFile         ********************************/

int get_relayLogFile(String *relayLogFile)
{
	if (relayLogFile == NULL)
		return SNMP_ERR_BADVALUE;
	else
		relayLogFile->len=0;

	return SNMP_ERR_NOERROR;
}

int set_relayLogFile(int pass, String *relayLogFile)
{
	return SNMP_ERR_NOERROR;
}


/***** relayOperationStatus ********************************/

int get_relayOperationStatus(Integer *relayOperationStatus)
{
	if (relayOperationStatus == NULL)
		return SNMP_ERR_BADVALUE;
	else
		*relayOperationStatus=0;

	return SNMP_ERR_NOERROR;
}

int set_relayOperationStatus(int pass, Integer *relayOperationStatus)
{
	return SNMP_ERR_NOERROR;
}

int get_relayTrapPort(Integer *relayTrapPort)
{
	*relayTrapPort = relay_agent_trap_port;
	return SNMP_ERR_NOERROR;
}

/***** relayCheckPoint      ********************************/
 
int get_relayCheckPoint(String *relayCheckPoint)
{
	if (relayCheckPoint == NULL)
		return SNMP_ERR_BADVALUE;
	else
		relayCheckPoint->len=0;

	return SNMP_ERR_NOERROR;
}
 
int set_relayCheckPoint(int pass, String *relayCheckPoint)
{
	/* check for dup. agent name */
	char *buffer;
	Agent *agent;

	buffer = malloc(relayCheckPoint->len + 1);

	if (buffer == NULL)
		return SNMP_ERR_NOERROR;		/* No alternative */

	memcpy(buffer,relayCheckPoint->chars,relayCheckPoint->len);
	buffer[relayCheckPoint->len]='\0';
        switch(pass)
        {
                case FIRST_PASS:
                case SECOND_PASS:
			if((agent=agent_find_by_name(buffer))!=NULL)
			  agent_destroy(agent);
        }
	free(buffer);
	return SNMP_ERR_NOERROR;
}
 
int get_relayNSession(Integer *relayNSession)
{
        return NOT_IMPLEMENTED;
}
 
int get_relayNSessionDiscards(Integer *relayNSessionDiscards)
{
        return NOT_IMPLEMENTED;
}

int get_relayPollInterval(Integer *relayPollInterval)
{
	*relayPollInterval = relay_agent_poll_interval;
	return SNMP_ERR_NOERROR;
}
 
int get_relayMaxAgentTimeOut(Integer *relayMaxAgentTimeOut)
{
	*relayMaxAgentTimeOut = relay_agent_max_agent_time_out;
	return SNMP_ERR_NOERROR;
}


void free_agentEntry(AgentEntry_t *agentEntry)
{
}

void free_agentPersonalFile(String *agentPersonalFile)
{
}

void free_agentConfigFile(String *agentConfigFile)
{
}

void free_agentExecutable(String *agentExecutable)
{
}

void free_agentVersionNum(String *agentVersionNum)
{
}

void free_agentProtocol(String *agentProtocol)
{
}

void free_agentName(String *agentName)
{
}

void free_regTreeEntry(RegTreeEntry_t *regTreeEntry)
{
}

void free_regTreeOID(Oid *regTreeOID)
{
}

void free_regTreeView(String *regTreeView)
{
}

void free_relayProcessIDFile(String *relayProcessIDFile)
{
}

void free_relayResourceFile(String *sunMasterAgentResourceConfigFile)
{
}

void free_relayPersonalFileDir(String *relayPersonalFileDir)
{
}

void free_relayLogFile(String *relayLogFile)
{
}

void free_relayCheckPoint(String *relayCheckPoint)
{
}

void free_regTblEntry(RegTblEntry_t *regTblEntry)
{
}

void free_regTblOID(Oid *regTblOID)
{
}

void free_regTblView(String *regTblView)
{
}



