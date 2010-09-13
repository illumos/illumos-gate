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

#ifndef _RPC_RPC_MSG_H
#define	_RPC_RPC_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/clnt.h>
/*
 * rpc_msg.h
 * rpc message definition
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	RPC_MSG_VERSION		((uint32_t)2)
#define	RPC_SERVICE_PORT	((ushort_t)2048)

/*
 * Bottom up definition of an rpc message.
 * NOTE: call and reply use the same overall stuct but
 * different parts of unions within it.
 */

enum msg_type {
	CALL = 0,
	REPLY = 1
};

enum reply_stat {
	MSG_ACCEPTED = 0,
	MSG_DENIED = 1
};

enum accept_stat {
	SUCCESS = 0,
	PROG_UNAVAIL = 1,
	PROG_MISMATCH = 2,
	PROC_UNAVAIL = 3,
	GARBAGE_ARGS = 4,
	SYSTEM_ERR = 5
};

enum reject_stat {
	RPC_MISMATCH = 0,
	AUTH_ERROR = 1
};

/*
 * Reply part of an rpc exchange
 */

/*
 * Reply to an rpc request that was accepted by the server.
 * Note: there could be an error even though the request was
 * accepted.
 */
struct accepted_reply {
	struct opaque_auth	ar_verf;
	enum accept_stat	ar_stat;
	union {
		struct {
			rpcvers_t low;
			rpcvers_t high;
		} AR_versions;
		struct {
			caddr_t	where;
			xdrproc_t proc;
		} AR_results;
		/* and many other null cases */
	} ru;
#define	ar_results	ru.AR_results
#define	ar_vers		ru.AR_versions
};

/*
 * Reply to an rpc request that was rejected by the server.
 */
struct rejected_reply {
	enum reject_stat rj_stat;
	union {
		struct {
			rpcvers_t low;
			rpcvers_t high;
		} RJ_versions;
		enum auth_stat RJ_why;  /* why authentication did not work */
	} ru;
#define	rj_vers	ru.RJ_versions
#define	rj_why	ru.RJ_why
};

/*
 * Body of a reply to an rpc request.
 */
struct reply_body {
	enum reply_stat rp_stat;
	union {
		struct accepted_reply RP_ar;
		struct rejected_reply RP_dr;
	} ru;
#define	rp_acpt	ru.RP_ar
#define	rp_rjct	ru.RP_dr
};

/*
 * Body of an rpc request call.
 */
struct call_body {
	rpcvers_t cb_rpcvers;	/* must be equal to two */
	rpcprog_t cb_prog;
	rpcvers_t cb_vers;
	rpcproc_t cb_proc;
	struct opaque_auth cb_cred;
	struct opaque_auth cb_verf; /* protocol specific - provided by client */
};

/*
 * The rpc message
 */
struct rpc_msg {
	uint32_t		rm_xid;
	enum msg_type		rm_direction;
	union {
		struct call_body RM_cmb;
		struct reply_body RM_rmb;
	} ru;
#define	rm_call		ru.RM_cmb
#define	rm_reply	ru.RM_rmb
};
#define	acpted_rply	ru.RM_rmb.ru.RP_ar
#define	rjcted_rply	ru.RM_rmb.ru.RP_dr


/*
 * XDR routine to handle a rpc message.
 * xdr_callmsg(xdrs, cmsg)
 * 	XDR *xdrs;
 * 	struct rpc_msg *cmsg;
 */
#ifdef __STDC__
extern bool_t	xdr_callmsg(XDR *, struct rpc_msg *);
#else
extern bool_t	xdr_callmsg();
#endif


/*
 * XDR routine to pre-serialize the static part of a rpc message.
 * xdr_callhdr(xdrs, cmsg)
 * 	XDR *xdrs;
 * 	struct rpc_msg *cmsg;
 */
#ifdef __STDC__
extern bool_t	xdr_callhdr(XDR *, struct rpc_msg *);
#else
extern bool_t	xdr_callhdr();
#endif


/*
 * XDR routine to handle a rpc reply.
 * xdr_replymsg(xdrs, rmsg)
 * 	XDR *xdrs;
 * 	struct rpc_msg *rmsg;
 *
 * xdr_accepted_reply(xdrs, ar)
 *	XDR *xdrs;
 *	const struct accepted_reply *ar;
 *
 * xdr_rejected_reply(xdrs, rr)
 *	XDR *xdrs;
 *	const struct rejected_reply *rr;
 */
#ifdef __STDC__
extern bool_t	xdr_replymsg(XDR *, struct rpc_msg *);
extern bool_t	xdr_accepted_reply(XDR *, struct accepted_reply *);
extern bool_t	xdr_rejected_reply(XDR *, struct rejected_reply *);
#else
extern bool_t	xdr_replymsg();
extern bool_t	xdr_accepted_reply();
extern bool_t	xdr_rejected_reply();
#endif


#ifdef _KERNEL
/*
 * Fills in the error part of a reply message.
 * _seterr_reply(msg, error)
 * 	struct rpc_msg *msg;
 * 	struct rpc_err *error;
 */
#ifdef __STDC__
extern void	_seterr_reply(struct rpc_msg *, struct rpc_err *);
#else
extern void	_seterr_reply();
#endif
#else
/*
 * Fills in the error part of a reply message.
 * __seterr_reply(msg, error)
 * 	struct rpc_msg *msg;
 * 	struct rpc_err *error;
 */
#ifdef __STDC__
extern void	__seterr_reply(struct rpc_msg *, struct rpc_err *);
#else
extern void	__seterr_reply();
#endif
#endif

#ifdef _KERNEL
/*
 * Frees any verifier that xdr_replymsg() (DECODE) allocated.
 */
bool_t xdr_rpc_free_verifier(register XDR *xdrs, register struct rpc_msg *msg);

#endif

#ifdef __cplusplus
}
#endif

#endif	/* _RPC_RPC_MSG_H */
