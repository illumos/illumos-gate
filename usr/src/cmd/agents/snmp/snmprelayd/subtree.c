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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * HISTORY
 * 5-21-96	Jerry Yeung	export first_subtree
 * 5-24-96	Jerry Yeung	skip invalid subtree
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "asn1.h"
#include "snmp.h"
#include "pdu.h"

#include "agent.h"
#include "subtree.h"
#include "session.h"


extern Session *first_session;
Subtree *first_subtree = NULL;
int sap_reg_tree_index=1;


void subtree_remove_from_agent_list(Subtree *subtree);


static int longest_subtree_match (Oid * one, Oid * two)
{
	int	i, min;

	if (one == NULL || two == NULL)
		return (-1);

	if (one->len > two->len)
		return two->len - one->len;

	for (i = 0;i < one->len;i ++) {
		if (one->subids[i] > two->subids[i])
			return (-1);
		if (one->subids[i] < two->subids[i])
			return (-1);
	}
	return two->len - one->len;
}

/****************************************************************/
Subtree*  subtree_find(Subid *subids, int len)
{
	Subtree *sp;
	int ret;
	Oid name;


	name.subids = (Subid *) malloc(len * sizeof(Subid));
	if(name.subids == NULL)
	{
		error("malloc() failed");
		return NULL;
	}
	memcpy(name.subids, subids, len * sizeof(Subid));
	name.len = len;

	for(sp = first_subtree; sp; sp = sp->next_subtree)
	{
		ret = SSAOidCmp(&(name), &(sp->name));
		if(ret == 0)
		{
			free(name.subids);
			name.subids=NULL;
			return sp;
		}
		else
		if(ret < 0)
		{
			break;
		}

	}

	free(name.subids);
	name.subids=NULL;
	return NULL;
}

int subtree_purge(Subid *subids, int len)
{
	Subtree *sp;
	int ret;
	Oid name;


	name.subids = (Subid *) malloc(len * sizeof(Subid));
	if(name.subids == NULL)
	{
		error("malloc() failed");
		return FALSE;
	}
	memcpy(name.subids, subids, len * sizeof(Subid));
	name.len = len;

	for(sp = first_subtree; sp; sp = sp->next_subtree)
	{
		ret = SSAOidCmp(&(name), &(sp->name));
		if(ret == 0)
		{
			free(name.subids);
			name.subids=NULL;
			subtree_detach(sp);
			subtree_free(sp);
			return TRUE;
		}
		else
		if(ret < 0)
		{
			break;
		}

	}
	free(name.subids);
	name.subids=NULL;

	return TRUE;
}


int subtree_add(Agent *agent, Subid *subids, int len, TblTag *tbl_tag)
{
	Subtree *sp;
	Subtree *new;
	Subtree *last = NULL;
	int ret;


	if(agent == NULL)
	{
		error("BUG: subtree_add(): agent is NULL");
		return -1;
	}

	new = (Subtree *) calloc(1,sizeof(Subtree));
	if(new == NULL)
	{
		error("malloc() failed");
		return -1;
	}
	new->next_subtree = NULL;
	new->agent = agent;
	new->next_agent_subtree = NULL;
	new->name.subids = (Subid *) malloc(len * sizeof(Subid));
	if(new->name.subids == NULL)
	{
		error("malloc() failed");
		subtree_free(new);
		return -1;
	}
	memcpy(new->name.subids, subids, len * sizeof(Subid));
	new->name.len = len;

  	new->regTreeAgentID = agent->agentID;
	new->regTreeIndex = ++agent->agentTreeIndex;
	new->regTreeStatus =  SSA_OPER_STATUS_ACTIVE;
	new->tbl_tag = tbl_tag;

	for(sp = first_subtree; sp; sp = sp->next_subtree)
	{
		ret = SSAOidCmp(&(new->name), &(sp->name));
		if(ret == 0)
		{
			error("The subtree %s already belongs to the agent %s",
				SSAOidString(&(sp->name)),
				sp->agent->name);
			subtree_free(new);
			return -1;
		}
		else
		if(ret < 0)
		{
			break;
		}

		last = sp;
	}

	if(last == NULL)
	{
		new->next_subtree = first_subtree;
		first_subtree = new;
	}
	else
	{
		new->next_subtree = last->next_subtree;
		last->next_subtree = new;
	}

	new->next_agent_subtree = agent->first_agent_subtree;
	agent->first_agent_subtree = new;
	

	return 0;
}


/****************************************************************/

Subtree *subtree_match(u_char type, Oid *name)
{
	Subtree *sp;
	Subtree *last, *good;
	Subtree *first_valid_subtree;
	int ret;


	if(name == NULL)
	{
		error("subtree_match(): name is NULL");
		return NULL;
	}

	if(first_subtree == NULL)
	{
		if(trace_level > 1)
		{
			trace("subtree_match() returned NULL\n\n");
		}

		return NULL;
	}


	if(type == GETNEXT_REQ_MSG)
	{
		/* grep the first valid subtree (vsb)*/
		if( (first_valid_subtree = subtree_next(first_subtree))
			== NULL) return NULL;
		if(SSAOidCmp(name, &(first_valid_subtree->name)) < 0)
		{
			if(trace_level > 1)
			{
				trace("subtree_match() returned %s supported by %s\n\n",
					SSAOidString(&(first_subtree->name)),
					first_subtree->agent->name);
			}

			return first_valid_subtree;
		}
	}

	last = NULL;
	good = NULL;
	for (sp = first_subtree; sp; sp = sp->next_subtree) {
	 	/* subtree is invalid skip (vsb)*/
		if(subtree_is_valid (sp) == FALSE)
			continue;
		ret = longest_subtree_match (&(sp->name), name);
		if (ret == 0) {
			if (trace_level > 1)
				trace("subtree_match() full match returned %s supported by %s\n\n",
					SSAOidString(&(sp->name)),
					sp->agent->name);
			return sp;
			
		}
		if (ret < 0)
			continue;
		if (good == NULL)
			good = sp;
		else if (good->name.len < sp->name.len)
			good = sp;
	}
	if(trace_level > 1) {
		if (good) {
			trace("subtree_match() returned %s supported by %s\n\n",
				SSAOidString(&(good->name)),
				good->agent->name);
		}
		else {
			trace("subtree_match() returned NULL\n\n");
		}
	}

	return good;
}


/****************************************************************/

void trace_subtrees()
{
	Subtree *sp;


	trace("SUBTREES:\n");
	for(sp = first_subtree; sp; sp = sp->next_subtree)
	{
		if(sp->agent)
		{
			trace("\t%-30s %d %d %-30s %d %d\n",
				SSAOidString(&(sp->name)),
				sp->regTreeIndex,
				sp->regTreeStatus,
				sp->agent->name,
				sp->agent->address.sin_port,
				sp->regTreeAgentID);
		}
		else
		{
			trace("\t%-30s %d %d %-30s\n",
				SSAOidString(&(sp->name)),
				sp->regTreeIndex,
				sp->regTreeStatus,
				"NO AGENT!");
		}
	}
	trace("\n");
}


/****************************************************************/

void subtree_free(Subtree *sp)
{
	if(sp == NULL)
	{
		return;
	}

	if(sp->name.subids)
	{
		free(sp->name.subids);
		sp->name.subids=NULL;
	}

	if(sp->regTreeView.chars != NULL &&
	   sp->regTreeView.len != 0 )
		free(sp->regTreeView.chars);

	if(sp->tbl_tag){
		free(sp->tbl_tag);
		sp->tbl_tag=NULL;
	}

	free(sp);
}


/****************************************************************/

void subtree_list_delete()
{
	Subtree *sp = first_subtree;
	Subtree *next;


	while(sp)
	{
		next = sp->next_subtree;

		subtree_remove_from_agent_list(sp);

		subtree_free(sp);

		sp = next;
	}

	first_subtree = NULL;

	return;
}


/****************************************************************/
/* the subtree  will be detached from both the agent_subtree list
 * and the main subtree list
 */
void delete_all_subtree_from_agent(Agent* agent) 
{
	Subtree *sp = first_subtree;
	Subtree *next, *last=NULL;
	Session *spp;
	Request *rp;

	while(sp)
	{
		next = sp->next_subtree;

		if(sp->agent != NULL && sp->agent == agent){
			if(last == NULL){
			  first_subtree = next;
			}else{
			  last->next_subtree = next;
			}

			for (spp = first_session; spp; spp = spp->next_session) {
				for (rp = spp->first_request; rp; rp = rp->next_request) {
					if (rp->subtree->agent == sp->agent)
						session_close(spp);
				}
			}

			subtree_remove_from_agent_list(sp);
			subtree_free(sp);
		}else{
		  last = sp;
		}

		sp = next;
	}

   
}

void subtree_remove_from_agent_list(Subtree *subtree)
{
	Agent *agent = subtree->agent;
	Subtree *sp;
	Subtree *osp;
	Table *table;


        if(agent == NULL) return;
	osp = NULL;
	for(sp = agent->first_agent_subtree; sp; sp = sp->next_agent_subtree)
	{
		if(sp == subtree)
		{
			break;
		}

		osp = sp;
	}

	if(sp == NULL)
	{
		error("subtree_remove_from_agent_list() : subtree (0x%x) not found", subtree);
		return;
	}

	if(osp == NULL)
	{
		agent->first_agent_subtree = sp->next_agent_subtree;
	}
	else
	{
		osp->next_agent_subtree = sp->next_agent_subtree;
	}

	subtree->agent = NULL;

	/*(mibpatch) */
	if(subtree->mirror_tag!=NULL){
/*
		table = subtree->mirror_tag->table;	
		if(table!=NULL){
			table_detach(table);
			table_free(table);
		}
*/
	}

	return;
}

void subtree_detach(Subtree *tgt)
{
  Subtree *sp, *last=NULL;

	if(tgt == NULL) return;
	for(sp = first_subtree; sp; sp = sp->next_subtree)
	{
		if(sp == tgt)
		{
			break;
		}

		last = sp;
	}
	if(sp==NULL) return;

	if(last == NULL)
	{
		first_subtree = tgt->next_subtree;
		tgt->next_subtree = NULL;
	}
	else
	{
		last->next_subtree = tgt->next_subtree;
		tgt->next_subtree = NULL;
	}

	subtree_remove_from_agent_list(tgt);

}


int subtree_is_valid(Subtree *t)
{
  if(t==NULL || t->agent==NULL || 
     t->agent->agentStatus != SSA_OPER_STATUS_ACTIVE ||
     t->regTreeStatus != SSA_OPER_STATUS_ACTIVE) return FALSE;
  return TRUE;
}

Subtree *subtree_next(Subtree *subtree)
{
  Subtree* sp;
  for(sp=subtree; sp; sp=sp->next_subtree){
	if(subtree_is_valid(sp)) return sp;
  }
  return NULL;
}

int sync_subtrees_with_agent(Agent *agent)
{
  Subtree *sp;
  if(agent == NULL) return -1;
  for(sp=agent->first_agent_subtree;sp;sp=sp->next_agent_subtree)
	sp->regTreeStatus = agent->agentStatus;

  return 0;
}

