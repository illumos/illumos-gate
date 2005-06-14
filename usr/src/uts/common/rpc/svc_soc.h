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
 * svc_soc.h, Server-side remote procedure call interface.
 *
 * All the following declarations are only for backward compatibility
 * with SUNOS 4.0.
 */

#ifndef _RPC_SVC_SOC_H
#define	_RPC_SVC_SOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _KERNEL

#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/svc.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  Approved way of getting address of caller
 */
#define	svc_getcaller(x)	((struct sockaddr_in *)(x)->xp_rtaddr.buf)

/*
 * Service registration and unregistration.
 *
 * svc_register(xprt, prog, vers, dispatch, protocol)
 * svc_unregister(prog, vers);
 */
#ifdef __STDC__
extern bool_t svc_register(SVCXPRT *, rpcprog_t, rpcvers_t,
    void (*)(struct svc_req *, SVCXPRT *), int);
extern void svc_unregister(rpcprog_t, rpcvers_t);

/*
 * Memory based rpc for testing and timing.
 */
extern SVCXPRT *svcraw_create(void);

/*
 * Udp based rpc. For compatibility reasons
 */
extern SVCXPRT *svcudp_create(int);
extern SVCXPRT *svcudp_bufcreate(int, uint_t, uint_t);

/*
 * Tcp based rpc.
 */
extern SVCXPRT *svctcp_create(int, uint_t, uint_t);
extern SVCXPRT *svcfd_create(int, uint_t, uint_t);

/*
 * For connectionless kind of transport. Obsoleted by rpc_reg()
 *
 * registerrpc(prognum, versnum, procnum, progname, inproc, outproc)
 *      rpcprog_t prognum;
 *      rpcvers_t versnum;
 *      rpcproc_t procnum;
 *      char *(*progname)();
 *      xdrproc_t inproc, outproc;
 */
extern int registerrpc(rpcprog_t, rpcvers_t, rpcproc_t, char *(*)(),
				xdrproc_t, xdrproc_t);
#else	/* __STDC__ */
extern bool_t svc_register();
extern void svc_unregister();
extern SVCXPRT *svcraw_create();
extern SVCXPRT *svcudp_create();
extern SVCXPRT *svcudp_bufcreate();
extern SVCXPRT *svctcp_create();
extern SVCXPRT *svcfd_create();
extern int registerrpc();
#endif	/* __STDC__ */

#ifdef __cplusplus
}
#endif
#endif	/* _KERNEL */

#endif /* !_RPC_SVC_SOC_H */
