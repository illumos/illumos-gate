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
 * Copyright 1996 Sun Microsystems, Inc.  All Rights Reserved.
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

#include "pagent.h"
#include "subtree.h"


/***** STATIC VARIABLES *****/

/* the agent list */
Agent *first_agent = NULL;


/***** STATIC FUNCTIONS *****/

static void agent_free(Agent *ap);


/****************************************************************/

void trace_agents()
{
	Agent *ap;


	trace("AGENTS:\n");
	for(ap = first_agent; ap; ap = ap->next_agent)
	{
		trace("\t%-30s %-30s %8d\n",
			ap->name,
			address_string(&(ap->address)),
			ap->timeout);
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

/* The fisrt_agent_subtree member of the agent		*/
/* structure should be NULL				*/

static void agent_free(Agent *ap)
{
	if(ap == NULL)
	{
		return;
	}

	if(ap->first_agent_subtree)
	{
		error("BUG: agent_free(): first_agent_subtree not NULL");
	}

	free(ap->name);
	free(ap);

	return;
}

/****************************************************************/

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

	
/****************************************************************/

