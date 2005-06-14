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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include "pagent.h"
#include "subtree.h"

/***** STATIC VARIABLES *****/

static Subtree *first_subtree = NULL;


/***** STATIC FUNCTIONS *****/

static void subtree_remove_from_agent_list(Subtree *subtree);
static void subtree_free(Subtree *sp);
extern int SSARegSubtree(SSA_Subtree *);


/****************************************************************/
/* currently, the index are processid(agentid) and local index */

int subtree_add(Agent *agent, Subid *subids, int len)
{

	/* call reg. api */
	Subtree *sp;
	Subtree *new;
	Subtree *last = NULL;
	int ret;


	if(agent == NULL)
	{
		error("BUG: subtree_add(): agent is NULL");
		return -1;
	}

	new = (Subtree *) malloc(sizeof(Subtree));
	if(new == NULL)
	{
		error("malloc() failed");
		return -1;
	}
	new->next_subtree = NULL;
	new->agent = agent;
	new->next_agent_subtree = NULL;
	new->name.subids = (Subid *) malloc(len * (int32_t)sizeof(Subid));
	if(new->name.subids == NULL)
	{
		error("malloc() failed");
		subtree_free(new);
		return -1;
	}
	(void)memcpy(new->name.subids, subids, len * (int32_t)sizeof(Subid));
	new->name.len = len;

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

	new->regTreeIndex = ++new->agent->tree_index;
	new->regTreeAgentID = new->agent->agent_id;
	new->regTreeStatus = SSA_OPER_STATUS_ACTIVE;
	if(SSARegSubtree(new)==0)
	{
		return -1;
	}
	
	return 0;
}


/****************************************************************/

Subtree *subtree_match(u_char type, Oid *name)
{
	Subtree *sp;
	Subtree *last;


	if(name == NULL)
	{
		error("subtree_match(): name is NULL");
		return NULL;
	}

	if(first_subtree == NULL)
	{
/*
		if(trace_level > 1)
		{
			trace("subtree_match() returned NULL\n\n");
		}
*/

		return NULL;
	}


	if(type == GETNEXT_REQ_MSG)
	{
		if(SSAOidCmp(name, &(first_subtree->name)) < 0)
		{
/*
			if(trace_level > 1)
			{
				trace("subtree_match() returned %s supported by %s\n\n",
					SSAOidString(&(first_subtree->name)),
					first_subtree->agent->name);
			}
*/

			return first_subtree;
		}
	}

	last = NULL;
	for(sp = first_subtree; sp; sp = sp->next_subtree)
	{
		if(SSAOidCmp(name, &(sp->name)) < 0)
		{
			break;
		}

		if(sp->name.len <= name->len)
		{
			int i;


			for(i = 0; i < sp->name.len; i++)
			{
				if(sp->name.subids[i] == 0)
				{
					continue;
				}

				if(name->subids[i] != sp->name.subids[i])
				{
					break;
				}
			}

			if(i == sp->name.len)
			{
				last = sp;
			}
		}
	}


/*
	if(trace_level > 1)
	{
		if(last)
		{
			trace("subtree_match() returned %s supported by %s\n\n",
				SSAOidString(&(last->name)),
				last->agent->name);
		}
		else
		{
			trace("subtree_match() returned NULL\n\n");
		}
	}
*/


	return last;
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
			trace("\t%-30s %-30s %d\n",
				SSAOidString(&(sp->name)),
				sp->agent->name,
				sp->agent->address.sin_port);
		}
		else
		{
			trace("\t%-30s %-30s\n",
				SSAOidString(&(sp->name)),
				"NO AGENT!");
		}
	}
	trace("\n");
}


/****************************************************************/

static void subtree_free(Subtree *sp)
{
	if(sp == NULL)
	{
		return;
	}

	if(sp->name.subids)
	{
		free(sp->name.subids);
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

static void subtree_remove_from_agent_list(Subtree *subtree)
{
	Agent *agent = subtree->agent;
	Subtree *sp;
	Subtree *osp;


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

	return;
}



