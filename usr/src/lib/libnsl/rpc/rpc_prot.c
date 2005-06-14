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
 *
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * rpc_prot.c
 *
 * This set of routines implements the rpc message definition,
 * its serializer and some common rpc utility routines.
 * The routines are meant for various implementations of rpc -
 * they are NOT for the rpc client or rpc service implementations!
 * Because authentication stuff is easy and is part of rpc, the opaque
 * routines are also in this program.
 */

#include <sys/param.h>
#include <rpc/trace.h>
#include <syslog.h>

#ifdef KERNEL
#include <rpc/types.h>		/* spell 'em out for make depend */
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#else
#include <rpc/rpc.h>
#include <malloc.h>
#endif

/* * * * * * * * * * * * * * XDR Authentication * * * * * * * * * * * */

struct opaque_auth _null_auth;

/*
 * XDR an opaque authentication struct
 * (see auth.h)
 */
bool_t
xdr_opaque_auth(xdrs, ap)
	register XDR *xdrs;
	register struct opaque_auth *ap;
{
	bool_t dummy;

	trace1(TR_xdr_opaque_auth, 0);
	if (xdr_enum(xdrs, &(ap->oa_flavor))) {
		dummy = xdr_bytes(xdrs, &ap->oa_base,
			&ap->oa_length, MAX_AUTH_BYTES);
		trace1(TR_xdr_opaque_auth, 1);
		return (dummy);
	}
	trace1(TR_xdr_opaque_auth, 1);
	return (FALSE);
}

/*
 * XDR a DES block
 */
bool_t
xdr_des_block(xdrs, blkp)
	register XDR *xdrs;
	register des_block *blkp;
{
	bool_t dummy;

	trace1(TR_xdr_des_block, 0);
	dummy = xdr_opaque(xdrs, (caddr_t)blkp, (u_int) sizeof (des_block));
	trace1(TR_xdr_des_block, 1);
	return (dummy);
}

/* * * * * * * * * * * * * * XDR RPC MESSAGE * * * * * * * * * * * * * * * */

/*
 * XDR the MSG_ACCEPTED part of a reply message union
 */
bool_t
xdr_accepted_reply(xdrs, ar)
	register XDR *xdrs;
	register struct accepted_reply *ar;
{
	bool_t dummy;

	/* personalized union, rather than calling xdr_union */
	trace1(TR_xdr_accepted_reply, 0);
	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf))) {
		trace1(TR_xdr_accepted_reply, 1);
		return (FALSE);
	}
	if (! xdr_enum(xdrs, (enum_t *)&(ar->ar_stat))) {
		trace1(TR_xdr_accepted_reply, 1);
		return (FALSE);
	}

	switch (ar->ar_stat) {
	case SUCCESS:
		dummy = (*(ar->ar_results.proc))(xdrs, ar->ar_results.where);
		trace1(TR_xdr_accepted_reply, 1);
		return (dummy);

	case PROG_MISMATCH:
		if (!xdr_u_int(xdrs, (u_int *)&(ar->ar_vers.low))) {
			trace1(TR_xdr_accepted_reply, 1);
			return (FALSE);
		}
		dummy = xdr_u_int(xdrs, (u_int *)&(ar->ar_vers.high));
		trace1(TR_xdr_accepted_reply, 1);
		return (dummy);
	}
	trace1(TR_xdr_accepted_reply, 1);
	return (TRUE);  /* TRUE => open ended set of problems */
}

/*
 * XDR the MSG_DENIED part of a reply message union
 */
bool_t
xdr_rejected_reply(xdrs, rr)
	register XDR *xdrs;
	register struct rejected_reply *rr;
{
	bool_t dummy;

	/* personalized union, rather than calling xdr_union */
	trace1(TR_xdr_rejected_reply, 0);
	if (! xdr_enum(xdrs, (enum_t *)&(rr->rj_stat))) {
		trace1(TR_xdr_rejected_reply, 1);
		return (FALSE);
	}
	switch (rr->rj_stat) {
	case RPC_MISMATCH:
		if (! xdr_u_int(xdrs, (u_int *)&(rr->rj_vers.low))) {
			trace1(TR_xdr_rejected_reply, 1);
			return (FALSE);
		}
		dummy = xdr_u_int(xdrs, (u_int *)&(rr->rj_vers.high));
		trace1(TR_xdr_rejected_reply, 1);
		return (dummy);

	case AUTH_ERROR:
		dummy = xdr_enum(xdrs, (enum_t *)&(rr->rj_why));
		trace1(TR_xdr_rejected_reply, 1);
		return (dummy);
	}
	trace1(TR_xdr_rejected_reply, 1);
	return (FALSE);
}

/*
 * XDR a reply message
 */
bool_t
xdr_replymsg(xdrs, rmsg)
	register XDR *xdrs;
	register struct rpc_msg *rmsg;
{
	struct xdr_discrim reply_dscrm[3];
	register rpc_inline_t *buf;
	register struct accepted_reply *ar;
	register struct opaque_auth *oa;
	register u_int rndup;
	bool_t	dummy;

	trace1(TR_xdr_replymsg, 0);
	if (xdrs->x_op == XDR_ENCODE &&
	    rmsg->rm_reply.rp_stat == MSG_ACCEPTED &&
	    rmsg->rm_direction == REPLY &&
	    (buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT + (rndup =
		RNDUP(rmsg->rm_reply.rp_acpt.ar_verf.oa_length)))) != NULL) {
		IXDR_PUT_INT32(buf, rmsg->rm_xid);
		IXDR_PUT_ENUM(buf, rmsg->rm_direction);
		IXDR_PUT_ENUM(buf, rmsg->rm_reply.rp_stat);
		ar = &rmsg->rm_reply.rp_acpt;
		oa = &ar->ar_verf;
		IXDR_PUT_ENUM(buf, oa->oa_flavor);
		IXDR_PUT_INT32(buf, oa->oa_length);
		if (oa->oa_length) {
			(void) memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
/* LINTED pointer alignment */
			buf = (rpc_inline_t *)(((caddr_t)buf) + oa->oa_length);
		}
		if ((rndup = (rndup - oa->oa_length)) > 0) {
			(void) memset((caddr_t)buf, 0, rndup);
/* LINTED pointer alignment */
			buf = (rpc_inline_t *)(((caddr_t)buf) + rndup);
		}
		/*
		 * stat and rest of reply, copied from xdr_accepted_reply
		 */
		IXDR_PUT_ENUM(buf, ar->ar_stat);
		switch (ar->ar_stat) {
		case SUCCESS:
			dummy = (*(ar->ar_results.proc))
				(xdrs, ar->ar_results.where);
			trace1(TR_xdr_replymsg, 1);
			return (dummy);

		case PROG_MISMATCH:
			if (! xdr_u_int(xdrs, (u_int *)&(ar->ar_vers.low))) {
				trace1(TR_xdr_replymsg, 1);
				return (FALSE);
			}
			dummy = xdr_u_int(xdrs, (u_int *)&(ar->ar_vers.high));
			trace1(TR_xdr_replymsg, 1);
			return (dummy);
		}
		trace1(TR_xdr_replymsg, 1);
		return (TRUE);
	}
	if (xdrs->x_op == XDR_DECODE &&
	    (buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT)) != NULL) {
		rmsg->rm_xid = IXDR_GET_INT32(buf);
		rmsg->rm_direction = IXDR_GET_ENUM(buf, enum msg_type);
		if (rmsg->rm_direction != REPLY) {
			trace1(TR_xdr_replymsg, 1);
			return (FALSE);
		}
		rmsg->rm_reply.rp_stat = IXDR_GET_ENUM(buf, enum reply_stat);
		if (rmsg->rm_reply.rp_stat != MSG_ACCEPTED) {
			if (rmsg->rm_reply.rp_stat == MSG_DENIED) {
				dummy = xdr_rejected_reply(xdrs,
					&rmsg->rm_reply.rp_rjct);
				trace1(TR_xdr_replymsg, 1);
				return (dummy);
			}
			trace1(TR_xdr_replymsg, 1);
			return (FALSE);
		}
		ar = &rmsg->rm_reply.rp_acpt;
		oa = &ar->ar_verf;
		buf = XDR_INLINE(xdrs, 2 * BYTES_PER_XDR_UNIT);
		if (buf != NULL) {
			oa->oa_flavor = IXDR_GET_ENUM(buf, enum_t);
			oa->oa_length = IXDR_GET_INT32(buf);
		} else {
			if (xdr_enum(xdrs, &oa->oa_flavor) == FALSE ||
			    xdr_u_int(xdrs, &oa->oa_length) == FALSE) {
				trace1(TR_xdr_replymsg, 1);
				return (FALSE);
			}
		}
		if (oa->oa_length) {
			if (oa->oa_length > MAX_AUTH_BYTES) {
				trace1(TR_xdr_replymsg, 1);
				return (FALSE);
			}
			if (oa->oa_base == NULL) {
				oa->oa_base = (caddr_t)
					mem_alloc(oa->oa_length);
				if (oa->oa_base == NULL) {
					syslog(LOG_ERR,
						"xdr_replymsg : "
						"out of memory.");
					rpc_callerr.re_status = RPC_SYSTEMERROR;
					trace1(TR_xdr_callmsg, 1);
					return (FALSE);
				}
			}
			buf = XDR_INLINE(xdrs, RNDUP(oa->oa_length));
			if (buf == NULL) {
				if (xdr_opaque(xdrs, oa->oa_base,
				    oa->oa_length) == FALSE) {
					trace1(TR_xdr_replymsg, 1);
					return (FALSE);
				}
			} else {
				(void) memcpy(oa->oa_base,
					(caddr_t)buf, oa->oa_length);
			}
		}
		/*
		 * stat and rest of reply, copied from
		 * xdr_accepted_reply
		 */
		if (! xdr_enum(xdrs, (enum_t *)&ar->ar_stat)) {
			trace1(TR_xdr_replymsg, 1);
			return (FALSE);
		}
		switch (ar->ar_stat) {
		case SUCCESS:
			dummy = (*(ar->ar_results.proc))
				(xdrs, ar->ar_results.where);
			trace1(TR_xdr_replymsg, 1);
			return (dummy);

		case PROG_MISMATCH:
			if (! xdr_u_int(xdrs, (u_int *)&(ar->ar_vers.low))) {
				trace1(TR_xdr_replymsg, 1);
				return (FALSE);
			}
			dummy = xdr_u_int(xdrs, (u_int *)&(ar->ar_vers.high));
			trace1(TR_xdr_replymsg, 1);
			return (dummy);
		}
		trace1(TR_xdr_replymsg, 1);
		return (TRUE);
	}

	reply_dscrm[0].value = (int)MSG_ACCEPTED;
	reply_dscrm[0].proc = (xdrproc_t) xdr_accepted_reply;
	reply_dscrm[1].value = (int)MSG_DENIED;
	reply_dscrm[1].proc =  (xdrproc_t) xdr_rejected_reply;
	reply_dscrm[2].value = __dontcare__;
	reply_dscrm[2].proc = NULL_xdrproc_t;
	if (xdr_u_int(xdrs, &(rmsg->rm_xid)) &&
	    xdr_enum(xdrs, (enum_t *)&(rmsg->rm_direction)) &&
	    (rmsg->rm_direction == REPLY)) {
		dummy = xdr_union(xdrs, (enum_t *)&(rmsg->rm_reply.rp_stat),
				(caddr_t)&(rmsg->rm_reply.ru),
				reply_dscrm, NULL_xdrproc_t);
		trace1(TR_xdr_replymsg, 1);
		return (dummy);
	}
	trace1(TR_xdr_replymsg, 1);
	return (FALSE);
}

/*
 * Serializes the "static part" of a call message header.
 * The fields include: rm_xid, rm_direction, rpcvers, prog, and vers.
 * The rm_xid is not really static, but the user can easily munge on the fly.
 */
bool_t
xdr_callhdr(xdrs, cmsg)
	register XDR *xdrs;
	register struct rpc_msg *cmsg;
{
	bool_t dummy;

	trace1(TR_xdr_callhdr, 0);
	cmsg->rm_direction = CALL;
	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
	if (xdrs->x_op == XDR_ENCODE &&
	    xdr_u_int(xdrs, &(cmsg->rm_xid)) &&
	    xdr_enum(xdrs, (enum_t *)&(cmsg->rm_direction)) &&
	    xdr_u_int(xdrs, (u_int *)&(cmsg->rm_call.cb_rpcvers)) &&
	    xdr_u_int(xdrs, (u_int *)&(cmsg->rm_call.cb_prog))) {
	    dummy = xdr_u_int(xdrs, (u_int *)&(cmsg->rm_call.cb_vers));
	    trace1(TR_xdr_callhdr, 1);
	    return (dummy);
	}
	trace1(TR_xdr_callhdr, 1);
	return (FALSE);
}

/* ************************** Client utility routine ************* */

static void
accepted(acpt_stat, error)
	register enum accept_stat acpt_stat;
	register struct rpc_err *error;
{
	trace1(TR_accepted, 0);
	switch (acpt_stat) {

	case PROG_UNAVAIL:
		error->re_status = RPC_PROGUNAVAIL;
		trace1(TR_accepted, 1);
		return;

	case PROG_MISMATCH:
		error->re_status = RPC_PROGVERSMISMATCH;
		trace1(TR_accepted, 1);
		return;

	case PROC_UNAVAIL:
		error->re_status = RPC_PROCUNAVAIL;
		trace1(TR_accepted, 1);
		return;

	case GARBAGE_ARGS:
		error->re_status = RPC_CANTDECODEARGS;
		trace1(TR_accepted, 1);
		return;

	case SYSTEM_ERR:
		error->re_status = RPC_SYSTEMERROR;
		trace1(TR_accepted, 1);
		return;

	case SUCCESS:
		error->re_status = RPC_SUCCESS;
		trace1(TR_accepted, 1);
		return;
	}
	/* something's wrong, but we don't know what ... */
	error->re_status = RPC_FAILED;
	error->re_lb.s1 = (int32_t)MSG_ACCEPTED;
	error->re_lb.s2 = (int32_t)acpt_stat;
	trace1(TR_accepted, 1);
}

static void
rejected(rjct_stat, error)
	register enum reject_stat rjct_stat;
	register struct rpc_err *error;
{

	trace1(TR_rejected, 0);
	switch (rjct_stat) {
	case RPC_MISMATCH:
		error->re_status = RPC_VERSMISMATCH;
		trace1(TR_rejected, 1);
		return;

	case AUTH_ERROR:
		error->re_status = RPC_AUTHERROR;
		trace1(TR_rejected, 1);
		return;
	}
	/* something's wrong, but we don't know what ... */
	error->re_status = RPC_FAILED;
	error->re_lb.s1 = (int32_t)MSG_DENIED;
	error->re_lb.s2 = (int32_t)rjct_stat;
	trace1(TR_rejected, 1);
}

/*
 * given a reply message, fills in the error
 */
void
__seterr_reply(msg, error)
	register struct rpc_msg *msg;
	register struct rpc_err *error;
{
	/* optimized for normal, SUCCESSful case */
	trace1(TR___seterr_reply, 0);
	switch (msg->rm_reply.rp_stat) {
	case MSG_ACCEPTED:
		if (msg->acpted_rply.ar_stat == SUCCESS) {
			error->re_status = RPC_SUCCESS;
			trace1(TR___seterr_reply, 1);
			return;
		};
		accepted(msg->acpted_rply.ar_stat, error);
		break;

	case MSG_DENIED:
		rejected(msg->rjcted_rply.rj_stat, error);
		break;

	default:
		error->re_status = RPC_FAILED;
		error->re_lb.s1 = (int32_t)(msg->rm_reply.rp_stat);
		break;
	}

	switch (error->re_status) {
	case RPC_VERSMISMATCH:
		error->re_vers.low = msg->rjcted_rply.rj_vers.low;
		error->re_vers.high = msg->rjcted_rply.rj_vers.high;
		break;

	case RPC_AUTHERROR:
		error->re_why = msg->rjcted_rply.rj_why;
		break;

	case RPC_PROGVERSMISMATCH:
		error->re_vers.low = msg->acpted_rply.ar_vers.low;
		error->re_vers.high = msg->acpted_rply.ar_vers.high;
		break;
	}
	trace1(TR___seterr_reply, 1);
}
