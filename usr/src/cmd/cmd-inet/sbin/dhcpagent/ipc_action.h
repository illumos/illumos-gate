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

#ifndef	IPC_ACTION_H
#define	IPC_ACTION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/dhcp.h>
#include <dhcpagent_ipc.h>
#include <libinetutil.h>

#include "common.h"

/*
 * ipc_action.[ch] make up the interface used to control the current
 * pending interprocess communication transaction taking place.  see
 * ipc_action.c for documentation on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ipc_action {
	dhcp_ipc_type_t		ia_cmd;		/* command/action requested  */
	int			ia_fd;		/* ipc channel descriptor */
	iu_timer_id_t		ia_tid;		/* ipc timer id */
	iu_event_id_t		ia_eid;		/* ipc event ID */
	dhcp_ipc_request_t	*ia_request;	/* ipc request pointer */
} ipc_action_t;

void		ipc_action_init(ipc_action_t *);
boolean_t	ipc_action_start(dhcp_smach_t *, ipc_action_t *);
void		ipc_action_finish(dhcp_smach_t *, int);
void		send_error_reply(ipc_action_t *, int);
void		send_ok_reply(ipc_action_t *);
void		send_data_reply(ipc_action_t *, int, dhcp_data_type_t,
		    const void *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* IPC_ACTION_H */
