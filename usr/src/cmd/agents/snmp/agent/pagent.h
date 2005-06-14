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
 * Copyright (c) 1998, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _PAGENT_H
#define	_PAGENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SSA_OPER_STATUS_ACTIVE			1
#define	SSA_OPER_STATUS_NOT_IN_SERVICE		2
#define	SSA_OPER_STATUS_NOT_READY		3
#define	SSA_OPER_STATUS_CREATE_AND_WAIT		4
#define	SSA_OPER_STATUS_DESTROY			5

/*
 * This macro depends on the AgentStatus field in MIB object in the
 * relay agent
 */

typedef struct _Agent {
	int		timeout;
	int		agent_id;
	int		agent_status;
	char		*personal_file;
	char		*config_file;
	char		*executable;
	char		*version_string;
	char		*protocol;
	int		process_id;
	char		*name;
	int		system_up_time;
	int		watch_dog_time;

	Address		address;
	struct _Agent	*next_agent;
	struct _Subtree	*first_agent_subtree;

	int 	tree_index;
	int	table_index;
} Agent;


/* the agent list */
extern Agent *first_agent;

/* the address is a unique key for an agent */
extern Agent *agent_find(Address *address);

/* We must invoke subtree_list_delete() before invoking */
/* this function because the first_agent_subtree member */
/* of the agent structures should be NULL */
extern void agent_list_delete(void);
extern void trace_agents(void);

#ifdef	__cplusplus
}
#endif

#endif /* _PAGENT_H */
