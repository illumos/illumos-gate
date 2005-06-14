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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RPC_RAC_H
#define	_RPC_RAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/clnt.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __STDC__
void rac_drop(CLIENT *, void *);
enum clnt_stat	rac_poll(CLIENT *, void *);
enum clnt_stat	rac_recv(CLIENT *, void *);
void *rac_send(CLIENT *, rpcproc_t, xdrproc_t, void *, xdrproc_t,
		void *, struct timeval);
#else
void rac_drop();
enum clnt_stat	rac_poll();
enum clnt_stat	rac_recv();
void *rac_send();
#endif

/*
 *	If a rac_send fails, it returns (void *) 0.  The reason for failure
 *	is cached here.
 *	N.B.:  this is a global structure.
 */
extern struct rpc_err	rac_senderr;

#ifdef __cplusplus
}
#endif

#endif	/* _RPC_RAC_H */
