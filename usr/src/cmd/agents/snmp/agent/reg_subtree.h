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

#ifndef	_REG_SUBTREE_H
#define	_REG_SUBTREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int SSARegSubagent(Agent *agent);
extern int SSARegSubtree(SSA_Subtree *subtree);
extern int SSARegSubtable(SSA_Table *table);
extern int SSAGetTrapPort(void);
/*
 * it will request a resource handler(an agent id) from the relay agent,
 * it returns the agent id if successful, otherwise, return 0
 * if fails, it will retry "num_of_retry".
 */
extern int SSASubagentOpen(int num_of_retry, char *agent_name);
extern int SSAAgentIsAlive(IPAddress *agent_addr, int port, char *community,
	struct timeval *timeout);
/* if flag = 1, turn on the auto mode */
extern void SSAAutoMemFree(int flag);
extern void _SSASendTrap(char *name);
extern void _SSASendTrap2(char *name);
extern int _SSASendTrap3(char *name);
extern int SSASendTrap4(char *name, IndexType *index_obj);

#ifdef	__cplusplus
}
#endif

#endif	/* _REG_SUBTREE_H */
