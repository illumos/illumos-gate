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
 * clnt.h - Client side remote procedure call interface.
 */

#ifndef _RPC_CLNT_SOC_H
#define	_RPC_CLNT_SOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * All the following declarations are only for backward compatibility
 * with SUNOS 4.0.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/xdr.h>
#include <rpc/clnt.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	UDPMSGSIZE	8800	/* rpc imposed limit on udp msg size */

/*
 * callrpc(host, prognum, versnum, procnum, inproc, in, outproc, out)
 *	char *host;
 *	rpcprog_t prognum;
 *	rpcvers_t versnum;
 *	rpcproc_t procnum;
 *	xdrproc_t inproc, outproc;
 *	char *in, *out;
 */
#ifdef __STDC__
extern int callrpc(char *, rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t, char *,
    xdrproc_t, char *);
#else
extern int callrpc();
#endif


/*
 * TCP based rpc
 * CLIENT *
 * clnttcp_create(raddr, prog, vers, fdp, sendsz, recvsz)
 *	struct sockaddr_in *raddr;
 *	rpcprog_t prog;
 *	rpcvers_t version;
 *	int *fdp;
 *	uint_t sendsz;
 *	uint_t recvsz;
 */
#ifdef __STDC__
extern CLIENT *clnttcp_create(struct sockaddr_in *, rpcprog_t, rpcvers_t,
    int *, uint_t, uint_t);
#else
extern CLIENT *clnttcp_create();
#endif


/*
 * UDP based rpc.
 * CLIENT *
 * clntudp_create(raddr, program, version, wait, fdp)
 *	struct sockaddr_in *raddr;
 *	rpcprog_t program;
 *	rpcvers_t version;
 *	struct timeval wait;
 *	int *fdp;
 *
 * Same as above, but you specify max packet sizes.
 * CLIENT *
 * clntudp_bufcreate(raddr, program, version, wait, fdp, sendsz, recvsz)
 *	struct sockaddr_in *raddr;
 *	rpcprog_t program;
 *	rpcvers_t version;
 *	struct timeval wait;
 *	int *fdp;
 *	uint_t sendsz;
 *	uint_t recvsz;
 *
 */
#ifdef __STDC__
extern CLIENT *clntudp_create(struct sockaddr_in *, rpcprog_t, rpcvers_t,
    struct timeval, int *);
extern CLIENT *clntudp_bufcreate(struct sockaddr_in *, rpcprog_t, rpcvers_t,
    struct timeval, int *, uint_t, uint_t);
#else
extern CLIENT *clntudp_create();
extern CLIENT *clntudp_bufcreate();
#endif

/*
 * Memory based rpc (for speed check and testing)
 * CLIENT *
 * clntraw_create(prog, vers)
 *	rpcprog_t prog;
 *	rpcvers_t vers;
 */
#ifdef __STDC__
extern CLIENT *clntraw_create(rpcprog_t, rpcvers_t);
#else
extern CLIENT *clntraw_create();
#endif

/*
 * get the local host's IP address without consulting
 * name service library functions
 * void
 * get_myaddress(addr)
 * 	struct sockaddr_in  *addr;
 */
#ifdef __STDC__
extern void get_myaddress(struct sockaddr_in *);
#else
extern void get_myaddress();
#endif

/*
 * get the port number on the host for the rpc program, version and proto
 * void
 * getrpcport(host, prognum, versnum, proto)
 * 	char *host;
 *	rpcprog_t prognum;
 *	rpcvers_t versnum;
 *	rpcprot_t proto;
 */
#ifdef __STDC__
extern ushort_t getrpcport(char *, rpcprog_t, rpcvers_t, rpcprot_t);
#else
extern ushort_t getrpcport();
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _RPC_CLNT_SOC_H */
