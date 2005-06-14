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
 * Copyright (c) 1993,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* Taken from 4.1.3 ypserv resolver code. */

#ifndef _RPC_AS_H
#define	_RPC_AS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <poll.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rpc_as {
	char	*as_userptr;		/* anything you like */
	struct timeval   as_timeout_remain;
	int	as_fd;
	bool_t	as_timeout_flag;	/* set if timeouts wanted */
	void	(*as_timeout)();	/* routine to call if timeouts wanted */
	void	(*as_recv)();		/* routine to call if data is present */
};
typedef struct rpc_as rpc_as;

extern struct timeval rpc_as_get_timeout(void);
extern pollfd_t *rpc_as_get_pollset(void);
extern int rpc_as_get_max_pollfd(void);
extern void rpc_as_timeout(struct timeval);
extern void rpc_as_rcvreq_poll(pollfd_t *, int *);
extern int rpc_as_register(rpc_as *);
extern int rpc_as_unregister(rpc_as *);

#ifdef __cplusplus
}
#endif

#endif	/* _RPC_AS_H */
