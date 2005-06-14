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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BRPC_H
#define	_BRPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	RPC_ALLOWABLE_ERRORS	(10)	/* Threshold on receiving bad results */
#define	RPC_REXMIT_MSEC		(500)	/* default 1/2 second retransmissions */
#define	RPC_RCVWAIT_MSEC	(20000)	/* default response waittime */

extern enum clnt_stat brpc_call(rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t,
	caddr_t, xdrproc_t, caddr_t, int, int, struct sockaddr_in *,
	struct sockaddr_in *, uint_t);

extern void rpc_disperr(struct rpc_err *stat);

#ifdef	__cplusplus
}
#endif

#endif	/* _BRPC_H */
