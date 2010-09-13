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
 * Copyright 1997 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "impl.h"
#include "error.h"
#include "trace.h"
#include "pdu.h"

#include "access.h"
#include "agent.h"
#include "subtree.h"
#include "session.h"
#include "sh_table.h"


/***** STATIC VARIABLES *****/

int sap_agent_id = 1;

/* the agent list */
Agent *first_agent = NULL;


/****************************************************************/

void trace_agents()
{
	Agent *ap;


	trace("AGENTS:\n");
	for(ap = first_agent; ap; ap = ap->next_agent)
	{

                trace("\t%X %-30s %-30s %8d %8d %8d %8d %X\n",
			ap,
                        ap->name?ap->name:"NO NAME",
                        address_string(&(ap->address)),
                        ap->timeout,ap->agentID,ap->agentStatus,
                        ap->agentProcessID,
			ap->first_manager);

	}
	trace("\n");
}


/****************************************************************/

/* We must invoke subtree_list_delete() before invoking	*/
/* this function because the first_agent_subtree member	*/
/* of the agent structures should be NULL		*/

void agent_list_delete()
{
	Agent *ap = first_agent;
	Agent *next;


	while(ap)
	{
		next = ap->next_agent;

		agent_free(ap);

		ap = next;
	}

	first_agent = NULL;

	return;
}


/****************************************************************/

static void free_string_content(String str)
{
  if(str.chars != NULL && str.len != 0){
	free(str.chars);
	str.chars = NULL;
	str.len = 0;
  }
}

/* The fisrt_agent_subtree member of the agent		*/
/* structure should be NULL				*/

void agent_free(Agent *ap)
{
	if(ap == NULL)
	{
		return;
	}

	if(ap->first_agent_subtree)
	{
		error("BUG: agent_free(): first_agent_subtree not NULL");
	}

	/* free the extra element */

	free_string_content(ap->agentPersonalFile);
	free_string_content(ap->agentConfigFile);
	free_string_content(ap->agentExecutable);
	free_string_content(ap->agentVersionNum);
	free_string_content(ap->agentProtocol);
	free_string_content(ap->agentName);
	if(ap->name) free(ap->name);
	free(ap);
	ap =NULL;
	return;
}

/****************************************************************/
Agent *agent_find_by_id(int id)
{
	Agent *ap;


	for(ap = first_agent; ap; ap = ap->next_agent)
	{
		if(ap->agentID == id)
		{
			return ap;
		}
	}

	return NULL;
}


Agent *agent_find_by_name(char* name)
{
	Agent *ap;


	for(ap = first_agent; ap; ap = ap->next_agent)
	{
		if(!strcmp(ap->name,name))
		{
			return ap;
		}
	}

	return NULL;
}

/* agent_find() is used to check if we have not		*/
/* two SNMP agents registered on the same UDP port	*/

Agent *agent_find(Address *address)
{
	Agent *ap;


	for(ap = first_agent; ap; ap = ap->next_agent)
	{
		if(ap->address.sin_port == address->sin_port)
		{
			return ap;
		}
	}

	return NULL;
}

void agent_update_subtree(Agent* agent)
{
  Subtree *sp;
  if(agent == NULL) return ;
  sp = agent->first_agent_subtree;
  for(;sp;sp=sp->next_agent_subtree){
	sp->regTreeStatus = agent->agentStatus;
  }
}

void agent_detach_from_list(Agent* agent)
{
	Agent *ap, *last=NULL;

        if(agent == NULL) return;
	for(ap = first_agent; ap ; ap = ap->next_agent)
	{
		if(ap == agent)
			break;
		last = ap;
	}
	if(ap==NULL) return;
	if(last == NULL){
		first_agent = ap->next_agent;
	}else{
		last->next_agent = ap->next_agent;
	}
	ap->next_agent = NULL;
}


void agent_destroy(Agent* agent)
{
  if(agent!=NULL){
	if(agent->agentID==sap_agent_id-1)
		sap_agent_id--;
  }
  agent_detach_from_list(agent);
  agent_manager_list_free(agent->first_manager);
  delete_all_table_from_agent(agent);
  delete_all_subtree_from_agent(agent);
  delete_agent_from_resource_list(agent); 
  agent_free(agent);
}

/*
** Maximum number of consecutive timeouts before snmpdx will purge the
** subagent from the internal tables.
*/

static	int MaxFails	= 5 ; 

int	SetFailThreshold ( int v )
{
	MaxFails = v ; 
	return 0 ; 
}


	
/****************************************************************/

/* destroy hanging agent when no outstanding session which
   relates to the agent */
void destroy_hanging_agent()
{
	Agent *ap;
	int rslt ; 

	for (ap = first_agent; ap ; ap = ap->next_agent) {

		if (ap->numOfFailRequest <= 5)
			continue ; 

		/* Even if the subagent isn't responding, we need to let the
		** sessions timeout and rip-down thru the normal mechanism.
		*/
		if (!no_outstanding_session_for_the_agent (ap))
			continue ; 

		/* subagent is quiesced and not talking -- check proces */
		if ( ap->agentProcessID != 0 && kill (ap->agentProcessID, 0) < 0) { 
			error ("Subagent died: %s PID=%d -- deleted from the agent table",
				ap->name, ap->agentProcessID ) ;	
			agent_destroy (ap) ; 
			return ; 		/* only kill one at a time */
		}

		/* subagent appears to be alive but hung and not responding */

		if (MaxFails <= 0 || ap->numOfFailRequest < MaxFails)
			continue ; 

		/* If the subagent receives a request with a bad community string
		// it is obliged to discard the string and _not_ respond.  This
		// doesn't jive with our stateful relay model.  We timeout and
		// can't distinguish a hung agent from an agent that is dropping
		// packets because of the "bad" community strings.  Thus, before
		// putting the ax to an agent we see if it's still alive.
		// 
		// The ssa_subagent_is_alive() routine "pings" the subagent with
		// a valid but innocuous request packet.  Unfortunately the dummy
		// we build has the community string set to "public".  If the subagent
		// doesn't accept "public" requests it will ignore our ping attempt.
		//
		// Sunil indicated that snmpdx would pre-validate incoming community
		// strings and only pass requests that would be accepted by the subagent.
		// This doesn't appear to work as advertised.
	 	*/

		if (ssa_subagent_is_alive (ap)) {
			error ("Agent %s appeared dead but responded to ping", ap->name) ; 
			ap->numOfFailRequest = 0 ; 
			continue ; 
		}

		error ("Agent not responding: %s -- deleted from the agent table", ap->name ) ; 
		agent_destroy(ap);
		return;
	}
}

