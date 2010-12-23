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

/* HISTORY
 * 5-20-96	Jerry Yeung	add mib-handling data structure
 * 9-20-96	Jerry Yeung	change agent structure
 */

#ifndef _AGENT_H_
#define _AGENT_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "snmpdx_stub.h"

#define SSA_OPER_STATUS_ACTIVE	1
#define SSA_OPER_STATUS_NOT_IN_SERVICE	2
#define SSA_OPER_STATUS_INIT 	3
#define SSA_OPER_STATUS_LOAD	4
#define SSA_OPER_STATUS_DESTROY	5

typedef struct _Agent {

	/* extra elements */
        Integer agentID;
        Integer agentStatus;
        Integer agentTimeOut;
        Integer agentPortNumber; /* same as address.sin_port */
        String agentPersonalFile;
        String agentConfigFile;
        String agentExecutable;
        String agentVersionNum;
        Integer agentProcessID;
        String agentName; /* it points to name */
	Integer agentSystemUpTime;
        Integer agentWatchDogTime;
        String agentProtocol;

	Integer	agentTreeIndex;
	Integer	agentTblIndex;

	struct _Manager	*first_manager;
	struct _Agent	*next_agent;
	Address		address;
	char		*name;
	u_long		timeout;
	struct _Subtree	*first_agent_subtree;
	int		numOfFailRequest;
} Agent;

extern int sap_agent_id;

/* the agent list */
extern Agent *first_agent;

/* the address is a unique key for an agent */
extern Agent *agent_find(Address *address);
extern Agent *agent_find_by_name(char* name);
extern Agent *agent_find_by_id(int id);

/* We must invoke subtree_list_delete() before invoking */
/* this function because the first_agent_subtree member */
/* of the agent structures should be NULL               */
extern void agent_list_delete();

extern void agent_update_subtree(Agent* agent);

extern void agent_detach_from_list(Agent* agent);

extern void agent_destroy(Agent* agent);

extern void trace_agents();
extern void agent_free(Agent *ap);

#endif

