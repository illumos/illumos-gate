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
 *
 * clnt.h - Client side remote procedure call interface.
 * Stripped down sockets based client for boot.
 */

#ifndef _RPC_CLNT_H
#define	_RPC_CLNT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <rpc/clnt_stat.h>
#include <rpc/auth.h>
#include <netinet/in.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Error info.
 */
struct rpc_err {
	enum clnt_stat re_status;
	union {
		int RE_errno;		/* realated system error */
		enum auth_stat RE_why;	/* why the auth error occurred */
	} ru;
#define	re_errno	ru.RE_errno
#define	re_why		ru.RE_why
};


/*
 * Client rpc handle.
 * Created by individual implementations, see e.g. rpc_udp.c.
 * Client is responsible for initializing auth, see e.g. auth_none.c.
 */
typedef struct __client {
	AUTH	*cl_auth;			/* authenticator */
	struct clnt_ops {
				/* call remote procedure */
		enum clnt_stat	(*cl_call)(struct __client *, rpcproc_t,
					xdrproc_t, caddr_t, xdrproc_t,
					caddr_t, struct timeval);
				/* abort a call */
		void		(*cl_abort)(/* various */);
				/* get specific error code */
		void		(*cl_geterr)(struct __client *,
					struct rpc_err *);
				/* frees results */
		bool_t		(*cl_freeres)(struct __client *, xdrproc_t,
					caddr_t);
				/* destroy this structure */
		void		(*cl_destroy)(struct __client *);
				/* the ioctl() of rpc */
		bool_t		(*cl_control)(struct __client *, int, char *);
	} *cl_ops;
	caddr_t			cl_private;	/* private stuff */
} CLIENT;


/*
 * client side rpc interface ops
 *
 * Parameter types are:
 *
 */

/*
 * enum clnt_stat
 * CLNT_CALL(rh, proc, xargs, argsp, xres, resp, timeout)
 * 	CLIENT *rh;
 *	ulong_t proc;
 *	xdrproc_t xargs;
 *	caddr_t argsp;
 *	xdrproc_t xres;
 *	caddr_t resp;
 *	struct timeval timeout;
 */
#define	CLNT_CALL(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))

/*
 * void
 * CLNT_ABORT(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_ABORT(rh)	((*(rh)->cl_ops->cl_abort)(rh))

/*
 * struct rpc_err
 * CLNT_GETERR(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_GETERR(rh, errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))

/*
 * bool_t
 * CLNT_FREERES(rh, xres, resp);
 * 	CLIENT *rh;
 *	xdrproc_t xres;
 *	caddr_t resp;
 */
#define	CLNT_FREERES(rh, xres, resp) ((*(rh)->cl_ops->cl_freeres)\
	(rh, xres, resp))

/*
 * bool_t
 * CLNT_CONTROL(cl, request, info)
 *	CLIENT *cl;
 *	uint_t request;
 *	char *info;
 */
#define	CLNT_CONTROL(cl, rq, in) ((*(cl)->cl_ops->cl_control)(cl, rq, in))

/*
 * control operations that apply to both udp and tcp transports
 */
#define	CLSET_TIMEOUT		1   /* set timeout (timeval) */
#define	CLGET_TIMEOUT		2   /* get timeout (timeval) */
#define	CLGET_SERVER_ADDR	3   /* get server's address (sockaddr) */
#define	CLGET_FD		6   /* get connections file descriptor */
#define	CLSET_FD_CLOSE		8   /* close fd while clnt_destroy */
#define	CLSET_FD_NCLOSE		9   /* Do not close fd while clnt_destroy */
/*
 * udp only control operations
 */
#define	CLSET_RETRY_TIMEOUT 4   /* set retry timeout (timeval) */
#define	CLGET_RETRY_TIMEOUT 5   /* get retry timeout (timeval) */

/*
 * void
 * CLNT_DESTROY(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))

/*
 * By convention, procedure 0 takes null arguments and returns them
 */

#define	NULLPROC ((ulong_t)0)

/*
 * Below are the client handle creation routines for the various
 * implementations of client side rpc.  They can return NULL if a
 * creation failure occurs.
 */

/*
 * UDP based rpc.
 * CLIENT *
 * clntbudp_create(raddr, program, version, wait, sockp)
 *	struct sockaddr_in *raddr;
 *	ulong_t program;
 *	ulong_t version;
 *	struct timeval wait;
 *	int *sockp;
 *
 * Same as above, but you specify max packet sizes.
 * CLIENT *
 * clntbudp_bufcreate(raddr, program, version, wait, sockp, sendsz, recvsz)
 *	struct sockaddr_in *raddr;
 *	ulong_t program;
 *	ulong_t version;
 *	struct timeval wait;
 *	int *sockp;
 *	uint_t sendsz;
 *	uint_t recvsz;
 */
extern CLIENT *clntbudp_create(struct sockaddr_in *raddr, rpcprog_t program,
				rpcvers_t version, struct timeval wait,
				int *sockp);
extern CLIENT *clntbudp_bufcreate(struct sockaddr_in *raddr, rpcprog_t program,
				rpcvers_t version, struct timeval wait,
				int *sockp, uint_t sendsz, uint_t recvsz);

/*
 * TCP based rpc.
 * CLIENT *
 * clntbtcp_create(raddr, program, version, wait, sockp, sendsz, recvsz)
 *	struct sockaddr_in *raddr;
 *	ulong_t program;
 *	ulong_t version;
 *	struct timeval wait;
 *	int *sockp;
 *	uint_t sendsz;
 *	uint_t recvsz;
 *
 */
extern CLIENT *clntbtcp_create(struct sockaddr_in *raddr, rpcprog_t program,
				rpcvers_t version, struct timeval wait,
				int *sockp, uint_t sendsz, uint_t recvsz);
/*
 * If a creation fails, the following allows the user to figure out why.
 */
struct rpc_createerr {
	enum clnt_stat cf_stat;
	struct rpc_err cf_error; /* useful when cf_stat == RPC_PMAPFAILURE */
};

extern struct rpc_createerr rpc_createerr;

#define	UDPMSGSIZE	8800	/* rpc imposed limit on udp msg size */
#define	RPCSMALLMSGSIZE	400	/* a more reasonable packet size */
#define	TCPMSGSIZE	(32 * 1024) /* reasonably sized RPC/TCP msg */
#ifdef	__cplusplus
}
#endif

#endif /* !_RPC_CLNT_H */
