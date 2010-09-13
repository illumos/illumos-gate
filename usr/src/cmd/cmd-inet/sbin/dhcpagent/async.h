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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	ASYNC_H
#define	ASYNC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <libinetutil.h>
#include <dhcpagent_ipc.h>

#include "common.h"

/*
 * async.[ch] comprise the interface used to handle asynchronous DHCP
 * commands.  see ipc_event() in agent.c for more documentation on
 * the treatment of asynchronous DHCP commands.  see async.c for
 * documentation on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct async_action {
	dhcp_ipc_type_t	as_cmd;		/* command/action in progress */
	boolean_t	as_user;	/* user-generated async cmd */
	boolean_t	as_present;	/* async operation present */
} async_action_t;

boolean_t	async_start(dhcp_smach_t *, dhcp_ipc_type_t, boolean_t);
void		async_finish(dhcp_smach_t *);
boolean_t	async_cancel(dhcp_smach_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* ASYNC_H */
