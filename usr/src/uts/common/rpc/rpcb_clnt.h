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

/*
 * rpcb_clnt.h
 * Supplies C routines to get to rpcbind services.
 */

/*
 * Usage:
 *	success = rpcb_set(program, version, nconf, address);
 *	success = rpcb_unset(program, version, nconf);
 *	success = rpcb_getaddr(program, version, nconf, host);
 *	head = rpcb_getmaps(nconf, host);
 *	clnt_stat = rpcb_rmtcall(nconf, host, program, version, procedure,
 *		xdrargs, argsp, xdrres, resp, tout, addr_ptr)
 *	success = rpcb_gettime(host, timep)
 *	uaddr = rpcb_taddr2uaddr(nconf, taddr);
 *	taddr = rpcb_uaddr2uaddr(nconf, uaddr);
 */

#ifndef _RPC_RPCB_CLNT_H
#define	_RPC_RPCB_CLNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <rpc/rpcb_prot.h>
#include <sys/netconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __STDC__
extern bool_t		rpcb_set(const rpcprog_t, const rpcvers_t,
	const struct netconfig  *, const struct netbuf *);
extern bool_t		rpcb_unset(const rpcprog_t, const rpcvers_t,
	const struct netconfig *);
extern rpcblist	*rpcb_getmaps(const struct netconfig *, const char *);
extern enum clnt_stat	rpcb_rmtcall(const struct netconfig *, const char *,
const rpcprog_t, const rpcvers_t, const rpcproc_t, const xdrproc_t,
	const caddr_t, const xdrproc_t, const caddr_t,
	const struct timeval, struct netbuf *);
extern bool_t		rpcb_getaddr(const rpcprog_t, const rpcvers_t,
	const struct netconfig *, struct netbuf *, const  char *);
extern bool_t		rpcb_gettime(const char *, time_t *);
extern char		*rpcb_taddr2uaddr(struct netconfig *, struct netbuf *);
extern struct netbuf	*rpcb_uaddr2taddr(struct netconfig *, char *);
#else
extern bool_t		rpcb_set();
extern bool_t		rpcb_unset();
extern rpcblist	*rpcb_getmaps();
extern enum clnt_stat	rpcb_rmtcall();
extern bool_t		rpcb_getaddr();
extern bool_t		rpcb_gettime();
extern char		*rpcb_taddr2uaddr();
extern struct netbuf	*rpcb_uaddr2taddr();
#endif

#ifdef __cplusplus
}
#endif

#endif	/* !_RPC_RPCB_CLNT_H */
