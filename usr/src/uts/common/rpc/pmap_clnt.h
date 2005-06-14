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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#ifndef _RPC_PMAP_CLNT_H
#define	_RPC_PMAP_CLNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * pmap_clnt.h
 * Supplies C routines to get to portmap services.
 */

#include <netinet/in.h>

#ifdef __STDC__
#include <rpc/clnt.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Usage:
 *	success = pmap_set(program, version, protocol, port);
 *	success = pmap_unset(program, version);
 *	port = pmap_getport(address, program, version, protocol);
 *	head = pmap_getmaps(address);
 *	clnt_stat = pmap_rmtcall(address, program, version, procedure,
 *		xdrargs, argsp, xdrres, resp, tout, port_ptr)
 *		(works for udp only.)
 * 	clnt_stat = clnt_broadcast(program, version, procedure,
 *		xdrargs, argsp,	xdrres, resp, eachresult)
 *		(like pmap_rmtcall, except the call is broadcasted to all
 *		locally connected nets.  For each valid response received,
 *		the procedure eachresult is called.  Its form is:
 *	done = eachresult(resp, raddr)
 *		bool_t done;
 *		caddr_t resp;
 *		struct sockaddr_in raddr;
 *		where resp points to the results of the call and raddr is the
 *		address if the responder to the broadcast.
 */

#ifdef __STDC__
extern bool_t pmap_set(rpcprog_t, rpcvers_t, rpcprot_t, unsigned short port);
extern bool_t pmap_unset(rpcprog_t, rpcvers_t);
extern struct pmaplist *pmap_getmaps(struct sockaddr_in *);
extern ushort_t pmap_getport(struct sockaddr_in *, rpcprog_t, rpcvers_t,
    rpcprot_t);
#ifndef _KERNEL
enum clnt_stat clnt_broadcast(rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t,
    char *, xdrproc_t, char *, resultproc_t);
enum clnt_stat pmap_rmtcall(struct sockaddr_in *, rpcprog_t, rpcvers_t,
    rpcproc_t, xdrproc_t, caddr_t, xdrproc_t, caddr_t, struct timeval,
    rpcport_t *);
#endif
#else
extern bool_t pmap_set();
extern bool_t pmap_unset();
extern struct pmaplist *pmap_getmaps();
extern ushort_t pmap_getport();
#ifndef _KERNEL
enum clnt_stat clnt_broadcast();
enum clnt_stat pmap_rmtcall();
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _RPC_PMAP_CLNT_H */
