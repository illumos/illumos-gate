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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * clnt_vc.c
 *
 * Implements a connectionful client side RPC.
 *
 * Connectionful RPC supports 'batched calls'.
 * A sequence of calls may be batched-up in a send buffer. The rpc call
 * return immediately to the client even though the call was not necessarily
 * sent. The batching occurs if the results' xdr routine is NULL (0) AND
 * the rpc timeout value is zero (see clnt.h, rpc).
 *
 * Clients should NOT casually batch calls that in fact return results; that
 * is the server side should be aware that a call is batched and not produce
 * any return message. Batched calls that produce many result messages can
 * deadlock (netlock) the client and the server....
 */

#include <rpc/rpc.h>
#include <rpc/rac.h>
#include "rac_private.h"
#include <syslog.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <sys/mkdev.h>
#include <sys/poll.h>
#include <sys/syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <tiuser.h>

#define	MCALL_MSG_SIZE 24

extern bool_t		xdr_opaque_auth(XDR *, struct opaque_auth *ap);

enum vc_xdrin_status	{ XS_CALLAGAIN, XS_ERROR, XS_OK };

/*
 * Private data structure
 */
struct ct_data {
	/* per-CLIENT information */
	int		ct_fd;		/* connection's file descriptor */
	bool_t		ct_closeit;	/* should ct_fd be closed on destroy? */
	struct timeval	ct_wait;	/* total time to wait for reply */
	bool_t		ct_waitset;	/* was ct_wait set by clnt_control? */
	struct netbuf	ct_addr;	/* remote service address */
	char		ct_mcallproto[MCALL_MSG_SIZE];
	/* prototype marshalled callmsg */
	uint_t		ct_msize;	/* amount of data in ct_mcallproto */
	uint_t		ct_sendsz;	/* per-call send size */
	uint_t		ct_recvsz;	/* per-call receive size */
	uint32_t	ct_xidseed;	/* XID seed */
	struct t_info	ct_tinfo;	/* cache of results of t_getinfo() */
	void		*ct_pollinfo;	/* private data for pkt_vc_poll() */
	struct callinfo	*ct_calls;	/* per-call information chain */
};

struct callinfo {
	uint_t		ci_flags;	/* per-call flags */
#define	CI_ASYNC	1
#define	CI_SYNC		2
	struct rpc_err	ci_error;	/* call error information */
	uint_t		ci_nrefreshes;	/* number of times to refresh creds */
	uint32_t	ci_xid;		/* XID assigned to this call */
	rpcproc_t	ci_proc;	/* remote procedure */
	xdrproc_t	ci_xargs;	/* XDR routine for arguments */
	caddr_t		ci_argsp;	/* pointer to args buffer */
	xdrproc_t	ci_xresults;	/* XDR routine for results */
	caddr_t		ci_resultsp;	/* pointer to results buffer */
	char		ci_mcall[MCALL_MSG_SIZE]; /* marshalled callmsg */
	XDR		ci_xdrs;	/* XDR stream */
	void		*ci_readinfo;	/* private data for pkt_vc_read() */
	struct ct_data	*ci_ct;		/* pointer to per-CLIENT information */
	struct callinfo	*ci_next;	/* pointer to info on ``next'' call */
};

static enum vc_xdrin_status vc_xdrin(CLIENT *, struct callinfo *,
    struct rpc_msg *);
static enum clnt_stat	vc_send(CLIENT *, struct callinfo *, bool_t);
static enum clnt_stat	vc_recv(struct callinfo *, struct rpc_msg *);
static struct clnt_ops	*clnt_vc_ops(void);
static int		read_vc(struct callinfo *, caddr_t, int);
static int		write_vc(struct callinfo *, caddr_t, int);
static bool_t		time_not_ok(struct timeval *);
static struct callinfo	*xid_to_callinfo(struct ct_data *, uint32_t);
static bool_t		set_up_connection(int, struct netbuf *,
    struct ct_data *);

static void		rac_vc_drop(CLIENT *, struct callinfo *);
static enum clnt_stat	rac_vc_poll(CLIENT *, struct callinfo *);
static enum clnt_stat	rac_vc_recv(CLIENT *, struct callinfo *);
static void		*rac_vc_send(CLIENT *, struct rac_send_req *);
static bool_t		rachandle_is_valid(CLIENT *, struct callinfo *);

static struct callinfo *alloc_callinfo(struct ct_data *, uint_t);
static struct callinfo	*find_callinfo(struct ct_data *, uint_t);
static void		free_callinfo(struct callinfo *);
static void		dequeue_callinfo(struct ct_data *, struct callinfo *);

static const char	clnt_vc_errstr[] = "%s : %s";
static const char	clnt_vc_str[] = "clnt_vc_create";
static const char	__no_mem_str[] = "out of memory";


/*
 * Create a client handle for a connection.
 * Default options are set, which the user can change using clnt_control()'s.
 * The rpc/vc package does buffering similar to stdio, so the client
 * must pick send and receive buffer sizes, 0 => use the default.
 * NB: fd is copied into a private area.
 * NB: The rpch->cl_auth is set null authentication. Caller may wish to
 * set this something more useful.
 *
 * fd should be open and bound.
 */
CLIENT *
clnt_vc_create(const int fd, struct netbuf *svcaddr, const rpcprog_t prog,
    const rpcvers_t vers, const uint_t sendsz, const uint_t recvsz)
{
	CLIENT *cl;			/* client handle */
	register struct ct_data *ct;	/* private data */
	struct timeval now;
	struct rpc_msg call_msg;
	XDR tmpxdrs;

	cl = (CLIENT *)malloc(sizeof (*cl));
#ifdef	PRINTFS
	printf("clnt_vc_create:  malloc CLIENT struct returning 0x%p\n", cl);
#endif
	ct = (struct ct_data *)malloc(sizeof (*ct));
#ifdef	PRINTFS
	printf("clnt_vc_create:  malloc ct_data struct returning 0x%p\n", ct);
#endif
	if ((cl == (CLIENT *)NULL) || (ct == (struct ct_data *)NULL)) {
		(void) syslog(LOG_ERR, clnt_vc_errstr,
				clnt_vc_str, __no_mem_str);
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		rpc_createerr.cf_error.re_terrno = 0;
		goto err;
	}
	ct->ct_addr.len = 0;

	if (set_up_connection(fd, svcaddr, ct) == FALSE)
		goto err;
	/*
	 * Set up other members of private data struct
	 */

	ct->ct_fd = fd;

	ct->ct_calls = (struct callinfo *)0;
	ct->ct_fd = fd;
	ct->ct_pollinfo = (void *)0;
	/*
	 * The actual value will be set by clnt_call or clnt_control
	 */
	ct->ct_wait.tv_sec = 30;
	ct->ct_wait.tv_usec = 0;
	ct->ct_waitset = FALSE;
	/*
	 * By default, closeit is always FALSE. It is users responsibility
	 * to do a t_close on it, else the user may use clnt_control
	 * to let clnt_destroy do it for him/her.
	 */
	ct->ct_closeit = FALSE;

	/*
	 * Initialize call message
	 */
	(void) gettimeofday(&now, (struct timezone *)0);
	call_msg.rm_xid = ct->ct_xidseed = getpid() ^ now.tv_sec ^ now.tv_usec;
	call_msg.rm_call.cb_prog = prog;
	call_msg.rm_call.cb_vers = vers;

	/*
	 * pre-serialize the static part of the call msg and stash it away
	 */
	xdrmem_create(&tmpxdrs, ct->ct_mcallproto, MCALL_MSG_SIZE, XDR_ENCODE);
	if (! xdr_callhdr(&tmpxdrs, &call_msg)) {
		goto err;
	}
	ct->ct_msize = XDR_GETPOS(&tmpxdrs);
	XDR_DESTROY(&tmpxdrs);

	if (t_getinfo(fd, &ct->ct_tinfo) == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		rpc_createerr.cf_error.re_terrno = t_errno;
		rpc_createerr.cf_error.re_errno = 0;
		goto err;
	} else {
		/*
		 * Find the receive and the send size
		 */
		ct->ct_sendsz = __rpc_get_t_size((int)sendsz,
			ct->ct_tinfo.tsdu);
		ct->ct_recvsz = __rpc_get_t_size((int)recvsz,
			ct->ct_tinfo.tsdu);
	}
	cl->cl_ops = clnt_vc_ops();
	cl->cl_private = (caddr_t)ct;
	cl->cl_auth = authnone_create();
	cl->cl_tp = (char *)NULL;
	cl->cl_netid = (char *)NULL;
	return (cl);

err:
	if (cl) {
		if (ct) {
#ifdef	PRINTFS
			printf("clnt_vc_create:  free 0x%p\n", ct);
#endif
			if (ct->ct_addr.len)
				free(ct->ct_addr.buf);
			(void) free((caddr_t)ct);
		}

#ifdef	PRINTFS
		printf("clnt_vc_create:  free 0x%p\n", cl);
#endif
		(void) free((caddr_t)cl);
	}
	return ((CLIENT *)NULL);
}


static bool_t
set_up_connection(int fd, struct netbuf *svcaddr, struct ct_data *ct)
{
	int state;
	struct t_call sndcallstr, *rcvcall;

	ct->ct_addr.len = 0;
	state = t_getstate(fd);
	if (state == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		rpc_createerr.cf_error.re_errno = 0;
		rpc_createerr.cf_error.re_terrno = t_errno;
		return (FALSE);
	}

#ifdef PRINTFS
	fprintf(stderr, "set_up_connection: state = %d\n", state);
#endif
	switch (state) {
	case T_IDLE:
		if (svcaddr == (struct netbuf *)NULL) {
			rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
			return (FALSE);
		}
		/*
		 * Connect only if state is IDLE and svcaddr known
		 */
		rcvcall = (struct t_call *)t_alloc(fd, T_CALL, T_OPT|T_ADDR);
		if (rcvcall == NULL) {
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_terrno = t_errno;
			rpc_createerr.cf_error.re_errno = errno;
			return (FALSE);
		}
		rcvcall->udata.maxlen = 0;
		sndcallstr.addr = *svcaddr;
		sndcallstr.opt.len = 0;
		sndcallstr.udata.len = 0;
		/*
		 * Even NULL could have sufficed for rcvcall, because
		 * the address returned is same for all cases except
		 * for the gateway case, and hence required.
		 */
		if (t_connect(fd, &sndcallstr, rcvcall) == -1) {
			(void) t_free((char *)rcvcall, T_CALL);
			rpc_createerr.cf_stat = RPC_TLIERROR;
			if (t_errno == TLOOK) {
				int old, res;

				old = t_errno;
				if (res = t_look(fd))
					rpc_createerr.cf_error.re_terrno = res;
				else
					rpc_createerr.cf_error.re_terrno = old;
			} else {
				rpc_createerr.cf_error.re_terrno = t_errno;
			}
#ifdef PRINTFS
			fprintf(stderr, "clnt_vc: t_connect error %d\n",
				rpc_createerr.cf_error.re_terrno);
#endif
			rpc_createerr.cf_error.re_errno = 0;
			return (FALSE);
		}
		/* Free old area if allocated */
		if (ct->ct_addr.len != 0)
			free(ct->ct_addr.buf);
		ct->ct_addr = rcvcall->addr;	/* To get the new address */
		/* So that address buf does not get freed */
		rcvcall->addr.buf = NULL;
		(void) t_free((char *)rcvcall, T_CALL);
		break;
	case T_DATAXFER:
	case T_OUTCON:
		if (svcaddr == (struct netbuf *)NULL) {
			/*
			 * svcaddr could also be NULL in cases where the
			 * client is already bound and connected.
			 */
			ct->ct_addr.len = 0;
		} else {
			ct->ct_addr.buf = malloc(svcaddr->len);
			if (ct->ct_addr.buf == (char *)NULL) {
				(void) syslog(LOG_ERR, clnt_vc_errstr,
					clnt_vc_str, __no_mem_str);
				rpc_createerr.cf_stat = RPC_SYSTEMERROR;
				rpc_createerr.cf_error.re_errno = errno;
				rpc_createerr.cf_error.re_terrno = 0;
				return (FALSE);
			}
			(void) memcpy(ct->ct_addr.buf, svcaddr->buf,
					(int)svcaddr->len);
			ct->ct_addr.len = ct->ct_addr.maxlen = svcaddr->len;
		}
		break;
	default:
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		return (FALSE);
	}
	return (TRUE);

}


static int	readhack = 0;

typedef int (* recrw_fn_t)(void *, caddr_t, int);

static enum clnt_stat
clnt_vc_call(CLIENT *cl, rpcproc_t proc, xdrproc_t xdr_args, caddr_t args_ptr,
    xdrproc_t xdr_results, caddr_t results_ptr, struct timeval timeout)
{
	register struct ct_data *ct = (struct ct_data *)cl->cl_private;
	register struct callinfo *ci;
	struct rpc_msg reply_msg;
	register bool_t shipnow;

	if ((ci = find_callinfo(ct, CI_SYNC)) == (struct callinfo *)NULL) {
		if ((ci = alloc_callinfo(ct, CI_SYNC)) == (struct callinfo *)0)
			return (RPC_SYSTEMERROR);
		/*
		 * Create a client handle which uses xdrrec for serialization
		 * and authnone for authentication.
		 */
		ci->ci_xdrs.x_ops = NULL;
		xdrrec_create(&(ci->ci_xdrs), ct->ct_sendsz, ct->ct_recvsz,
				(caddr_t)ci, (recrw_fn_t)read_vc,
				(recrw_fn_t)write_vc);
		if (ci->ci_xdrs.x_ops == NULL) {
			free_callinfo(ci);
			return (RPC_SYSTEMERROR);
		}
	}
	ci->ci_nrefreshes = 2;
	ci->ci_proc = proc;
	ci->ci_xargs = xdr_args;
	ci->ci_argsp = args_ptr;
	ci->ci_xresults = xdr_results;
	ci->ci_resultsp = results_ptr;
	ci->ci_readinfo = (void *)0;
#ifdef	PRINTFS
	printf("clnt_vc_call:  ci_readinfo <- 0\n");
#endif
	ci->ci_xid = --ct->ct_xidseed;

	if (!ct->ct_waitset) {
		/* If time is not within limits, we ignore it. */
		if (time_not_ok(&timeout) == FALSE)
			ct->ct_wait = timeout;
	}

	shipnow = ((xdr_results == (xdrproc_t)0) && (timeout.tv_sec == 0) &&
			(timeout.tv_usec == 0)) ? FALSE : TRUE;

call_again:
#ifdef	PRINTFS
	printf("clnt_vc_call:  call_again\n");
#endif
	if (vc_send(cl, ci, shipnow) != RPC_SUCCESS) {
		dequeue_callinfo(ct, ci);
		free_callinfo(ci);
		XDR_DESTROY(&(ci->ci_xdrs));
#ifdef	PRINTFS
		printf("clnt_vc_call returning error %d\n",
			ci->ci_error.re_status);
#endif
		return (ci->ci_error.re_status);
	}
#ifdef	PRINTFS
	else
		printf("clnt_vc_call:  vc_send succeeded\n");
#endif
	if (! shipnow) {
#ifdef	PRINTFS
		printf("clnt_vc_call:  returning RPC_SUCCESS\n");
#endif
		return (RPC_SUCCESS);
	}
	/*
	 * Hack to provide rpc-based message passing
	 */
	if (!timerisset(&timeout)) {
#ifdef	PRINTFS
		printf("clnt_vc_call:  returning RPC_TIMEDOUT\n");
#endif
		return (ci->ci_error.re_status = RPC_TIMEDOUT);
	}

	if (vc_recv(ci, &reply_msg) != RPC_SUCCESS) {
#ifdef	PRINTFS
		printf("clnt_vc_call:  returning %d\n", ci->ci_error.re_status);
#endif
		if (ci->ci_readinfo) {
			free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
			printf("clnt_vc_call:  ci_readinfo <- 0\n");
#endif
			ci->ci_readinfo = (void *)0;
		}
#ifdef	PRINTFS
		else
			printf("clnt_vc_call:  ci_readinfo = 0\n");
#endif
		return (ci->ci_error.re_status);
	}
#ifdef	PRINTFS
	else
		printf("clnt_vc_call:  vc_recv returned OK\n");
#endif

	switch (vc_xdrin(cl, ci, &reply_msg)) {
	case (int)XS_CALLAGAIN:
#ifdef	PRINTFS
		printf("vc_xdrin returned XS_CALLAGAIN\n");
#endif
		if (ci->ci_readinfo) {
			free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
			printf("clnt_vc_call:  ci_readinfo <- 0\n");
#endif
			ci->ci_readinfo = (void *)0;
		}
#ifdef	PRINTFS
		else
			printf("clnt_vc_call:  ci_readinfo = 0\n");
#endif
		goto call_again;

	case (int)XS_ERROR:
	case (int)XS_OK:
	default:
#ifdef	PRINTFS
		printf("vc_xdrin returned %d\n", ci->ci_error.re_status);
#endif
		if (ci->ci_readinfo) {
			free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
			printf("clnt_vc_call:  ci_readinfo <- 0\n");
#endif
			ci->ci_readinfo = (void *)0;
		}
#ifdef	PRINTFS
		else
			printf("clnt_vc_call:  ci_readinfo = 0\n");
#endif
		return (ci->ci_error.re_status);
	}
	/* NOTREACHED */
}

static enum clnt_stat
vc_send(CLIENT *cl, struct callinfo *ci, bool_t shipnow)
{
	register struct ct_data *ct = ci->ci_ct;
	register XDR *xdrs = &(ci->ci_xdrs);

	xdrs->x_op = XDR_ENCODE;
	ci->ci_error.re_status = RPC_SUCCESS;
	(void) memcpy(ci->ci_mcall, ct->ct_mcallproto, (int)ct->ct_msize);
	*(uint32_t *)ci->ci_mcall = htonl(ci->ci_xid);
#ifdef	PRINTFS
	printf("vc_send:  xid %d\n", *(uint32_t *)ci->ci_mcall);
#endif
	if ((! XDR_PUTBYTES(xdrs, ci->ci_mcall, ct->ct_msize)) ||
	    (! XDR_PUTINT32(xdrs, (int *)&ci->ci_proc)) ||
	    (! AUTH_MARSHALL(cl->cl_auth, xdrs)) ||
	    (! (*ci->ci_xargs)(xdrs, ci->ci_argsp))) {
		if (ci->ci_error.re_status == RPC_SUCCESS)
			ci->ci_error.re_status = RPC_CANTENCODEARGS;
		(void) xdrrec_endofrecord(xdrs, TRUE);
		return (ci->ci_error.re_status);
	}
	if (! xdrrec_endofrecord(xdrs, shipnow))
		return (ci->ci_error.re_status = RPC_CANTSEND);
	return (RPC_SUCCESS);
}

static enum clnt_stat
vc_recv(struct callinfo *ci, struct rpc_msg *reply_msg)
{
	register XDR *xdrs = &(ci->ci_xdrs);

	/*
	 * Keep receiving until we get a valid transaction id
	 */
	xdrs->x_op = XDR_DECODE;
	/* CONSTCOND */
	while (TRUE) {
		reply_msg->acpted_rply.ar_verf = _null_auth;
		reply_msg->acpted_rply.ar_results.where = NULL;
		reply_msg->acpted_rply.ar_results.proc = xdr_void;
		if (! xdrrec_skiprecord(xdrs)) {
#ifdef	PRINTFS
	printf("vc_recv:  returning %d after xdrrec_skiprecord\n",
		ci->ci_error.re_status);
#endif
			if (ci->ci_readinfo) {
				free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
				printf("vc_recv:  ci_readinfo <- 0\n");
#endif
				ci->ci_readinfo = (void *)0;
			}
#ifdef	PRINTFS
			else
				printf("vc_recv:  ci_readinfo = 0\n");
#endif
			return (ci->ci_error.re_status);
		}
		else
			readhack = 0;
		/* now decode and validate the response header */
		if (! xdr_replymsg(xdrs, reply_msg)) {
			if (ci->ci_error.re_status == RPC_SUCCESS)
				continue;
#ifdef	PRINTFS
	printf("vc_recv:  returning %d after xdr_replymsg\n",
		ci->ci_error.re_status);
#endif
			if (ci->ci_readinfo) {
				free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
				printf("vc_recv:  ci_readinfo <- 0\n");
#endif
				ci->ci_readinfo = (void *)0;
			}
			return (ci->ci_error.re_status);
		}
		if (reply_msg->rm_xid == ci->ci_xid)
			return (RPC_SUCCESS);
#ifdef	PRINTFS
		else
	printf("vc_recv:  reply_msg->rm_xid %d, ci->ci_xid %d\n",
		reply_msg->rm_xid, ci->ci_xid);
#endif
	}
	/* NOTREACHED */
}

static enum vc_xdrin_status
vc_xdrin(CLIENT *cl, struct callinfo *ci, struct rpc_msg *reply_msg)
{
	register XDR *xdrs = &(ci->ci_xdrs);

	/*
	 * process header
	 */
	__seterr_reply(reply_msg, &(ci->ci_error));
	if (ci->ci_error.re_status == RPC_SUCCESS) {
		if (! AUTH_VALIDATE(cl->cl_auth,
				&reply_msg->acpted_rply.ar_verf)) {
			ci->ci_error.re_status = RPC_AUTHERROR;
			ci->ci_error.re_why = AUTH_INVALIDRESP;
		} else if (! (*ci->ci_xresults)(xdrs, ci->ci_resultsp)) {
			if (ci->ci_error.re_status == RPC_SUCCESS)
				ci->ci_error.re_status = RPC_CANTDECODERES;
		}
		/* free verifier ... */
		if (reply_msg->acpted_rply.ar_verf.oa_base != NULL) {
			xdrs->x_op = XDR_FREE;
			(void) xdr_opaque_auth(xdrs,
				&(reply_msg->acpted_rply.ar_verf));
		}
	} /* end successful completion */
	else {
		/* maybe our credentials need to be refreshed ... */
		if (ci->ci_nrefreshes-- &&
			AUTH_REFRESH(cl->cl_auth, reply_msg))
			return (XS_CALLAGAIN);
		else
			return (XS_ERROR);
	} /* end of unsuccessful completion */

	return (XS_OK);
}

/*
 *	The action of this function is not well-defined in the face of
 *	asynchronous calls.  We do the best we can by first trying to
 *	find a synchronous callinfo structure and if none is found,
 *	taking the first call in the chain.
 */
static void
clnt_vc_geterr(CLIENT *cl, struct rpc_err *errp)
{
	register struct ct_data *ct = (struct ct_data *)cl->cl_private;
	register struct callinfo *ci;

	for (ci = ct->ct_calls; ci; ci = ci->ci_next)
		if (ci->ci_flags & CI_SYNC) {
			*errp = ci->ci_error;
			return;
		}
	if (ci == (struct callinfo *)0 &&
		ct->ct_calls != (struct callinfo *)0)
		*errp = ct->ct_calls->ci_error;
}

/*
 *	The action of this function is not well-defined in the face of
 *	asynchronous calls.  We do the best we can by first trying to
 *	find a synchronous callinfo structure and if none is found,
 *	taking the first call in the chain.
 */
static bool_t
clnt_vc_freeres(CLIENT *cl, xdrproc_t xdr_res, caddr_t res_ptr)
{
	register struct ct_data *ct = (struct ct_data *)cl->cl_private;
	register struct callinfo *ci;
	register XDR *xdrs = (XDR *)0;

	for (ci = ct->ct_calls; ci; ci = ci->ci_next)
		if (ci->ci_flags & CI_SYNC) {
			xdrs = &ci->ci_xdrs;
			break;
		}
	if (xdrs == (XDR *)0 && ci == (struct callinfo *)0 &&
	    ct->ct_calls != (struct callinfo *)0)
		xdrs = &ct->ct_calls->ci_xdrs;

	if (xdrs) {
		xdrs->x_op = XDR_FREE;
		return ((*xdr_res)(xdrs, res_ptr));
	} else
		return (FALSE);
}

static void
clnt_vc_abort()
{
}

static bool_t
clnt_vc_control(CLIENT *cl, int request, char *info)
{
	register struct ct_data *ct = (struct ct_data *)cl->cl_private;

	switch (request) {
	case CLSET_FD_CLOSE:
		ct->ct_closeit = TRUE;
		return (TRUE);
	case CLSET_FD_NCLOSE:
		ct->ct_closeit = FALSE;
		return (TRUE);
	}

	/* for other requests which use info */
	if (info == NULL)
		return (FALSE);
	switch (request) {
	case CLSET_TIMEOUT:
		if (time_not_ok((struct timeval *)info))
			return (FALSE);
		ct->ct_wait = *(struct timeval *)info;
		ct->ct_waitset = TRUE;
		break;
	case CLGET_TIMEOUT:
		*(struct timeval *)info = ct->ct_wait;
		break;
	case CLGET_SERVER_ADDR:	/* For compatibility only */
		(void) memcpy(info, ct->ct_addr.buf, (int)ct->ct_addr.len);
		break;
	case CLGET_FD:
		*(int *)info = ct->ct_fd;
		break;
	case CLGET_SVC_ADDR:
		/* The caller should not free this memory area */
		*(struct netbuf *)info = ct->ct_addr;
		break;
	case CLSET_SVC_ADDR:		/* set to new address */
		return (FALSE);
	case CLGET_XID:
		/*
		 * use the knowledge that xid is the
		 * first element in the call structure
		 * This will get the xid of the PREVIOUS call
		 */
		*(uint32_t *)info = ct->ct_xidseed;
		break;
	case CLSET_XID:
		/* This will set the xid of the NEXT call */
		ct->ct_xidseed =  htonl(*(uint32_t *)info + 1);
		/* increment by 1 as clnt_vc_call() decrements once */
		break;
	case CLGET_VERS:
		/*
		 * This RELIES on the information that, in the call body,
		 * the version number field is the fifth field from the
		 * begining of the RPC header. MUST be changed if the
		 * call_struct is changed
		 */
		*(uint32_t *)info = ntohl(*(uint32_t *)(ct->ct_mcallproto +
						4 * BYTES_PER_XDR_UNIT));
		break;

	case CLSET_VERS:
		*(uint32_t *)(ct->ct_mcallproto + 4 * BYTES_PER_XDR_UNIT) =
			htonl(*(uint32_t *)info);
		break;

	case CLGET_PROG:
		/*
		 * This RELIES on the information that, in the call body,
		 * the program number field is the fourth field from the
		 * begining of the RPC header. MUST be changed if the
		 * call_struct is changed
		 */
		*(uint32_t *)info = ntohl(*(uint32_t *)(ct->ct_mcallproto +
						3 * BYTES_PER_XDR_UNIT));
		break;

	case CLSET_PROG:
		*(uint32_t *)(ct->ct_mcallproto + 3 * BYTES_PER_XDR_UNIT) =
			htonl(*(uint32_t *)info);
		break;

	case CLRAC_DROP:
		rac_vc_drop(cl, (struct callinfo *)info);
		break;
	case CLRAC_POLL:
		return ((bool_t)rac_vc_poll(cl, (struct callinfo *)info));
	case CLRAC_RECV:
		return ((bool_t)rac_vc_recv(cl, (struct callinfo *)info));
	case CLRAC_SEND:
		((struct rac_send_req *)info)->handle =
				rac_vc_send(cl, (struct rac_send_req *)info);
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

static void
clnt_vc_destroy(CLIENT *cl)
{

	register struct ct_data *ct = (struct ct_data *)cl->cl_private;
	register struct callinfo *ci, *nextci;

	if (ct->ct_closeit)
		(void) t_close(ct->ct_fd);
	for (ci = ct->ct_calls; ci; ci = nextci) {
		nextci = ci->ci_next;
		XDR_DESTROY(&(ci->ci_xdrs));
		free_callinfo(ci);
	}
	if (ct->ct_addr.buf) {
#ifdef	PRINTFS
		printf("clnt_vc_destroy:  free 0x%p\n", ct->ct_addr.buf);
#endif
		(void) free(ct->ct_addr.buf);
	}

#ifdef	PRINTFS
	printf("clnt_vc_destroy:  free 0x%p\n", ct);
#endif

	(void) free((caddr_t)ct);

	if (cl->cl_netid && cl->cl_netid[0]) {
#ifdef	PRINTFS
		printf("clnt_vc_destroy:  free 0x%p\n", cl->cl_netid);
#endif
		(void) free(cl->cl_netid);
	}

	if (cl->cl_tp && cl->cl_tp[0]) {
#ifdef	PRINTFS
		printf("clnt_vc_destroy:  free 0x%p\n", cl->cl_tp);
#endif
		(void) free(cl->cl_tp);
	}
#ifdef	PRINTFS
	printf("clnt_vc_destroy:  free 0x%p\n", cl);
#endif
	(void) free((caddr_t)cl);

}

/*
 * Interface between xdr serializer and vc connection.
 * Behaves like the system calls, read & write, but keeps some error state
 * around for the rpc level.
 */
static int
read_vc(struct callinfo *ci, caddr_t buf, int len)
{
	register uint32_t	xid;
	register void	*ri;
	register struct callinfo	*h;
	register struct ct_data *ct = ci->ci_ct;

	struct pollfd readfd;
	int ms = (int)((ct->ct_wait.tv_sec * 1000) +
		(ct->ct_wait.tv_usec / 1000) +
		(ct->ct_wait.tv_usec % 1000 ? 1 : 0));

#ifdef	PRINTFS
	printf("read_vc(0x%p, 0x%p, %d)\n", ci, buf, len);
#endif
	if (len == 0) {
		if (ci->ci_readinfo) {
			free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
			printf("read_vc:  ci_readinfo <- 0\n");
#endif
			ci->ci_readinfo = (void *)0;
		}
#ifdef	PRINTFS
		else
			printf("read_vc:  ci_readinfo = 0\n");
#endif
		return (0);
	}

	if (!ci->ci_readinfo) {
#ifdef	PRINTFS
		printf("read_vc:  ci->ci_readinfo == 0\np");
#endif

		while (!ci->ci_readinfo) {
#ifdef	PRINTFS
			printf("read_vc:  calling poll\n");
#endif
			readfd.fd = ct->ct_fd;
			readfd.events = POLLRDNORM;
			readfd.revents = 0;

			switch (poll(&readfd, 1, ms)) {
			case 0:
#ifdef	PRINTFS
				printf("read_vc:  poll returned 0\n");
#endif
				if (readhack == 0)
					xdrrec_resetinput(&ci->ci_xdrs);
				ci->ci_error.re_status = RPC_TIMEDOUT;
				return (-1);

			case -1:
#ifdef	PRINTFS
	printf("read_vc:  poll returned -1 (errno %d, fd %d)\n",
		errno, ct->ct_fd);
#endif
				if (!(readfd.revents & POLLNVAL))
					continue;
				ci->ci_error.re_status = RPC_CANTRECV;
				ci->ci_error.re_errno = errno;
				return (-1);

			default:
#ifdef	PRINTFS
		printf("read_vc:  poll returned > 0 - calling pkt_vc_poll()\n");
#endif
				assert(readfd.revents & POLLRDNORM);
				ri = pkt_vc_poll(ct->ct_fd, &ct->ct_pollinfo);
#ifdef	PRINTFS
	printf("read_vc:  pkt_vc_poll() returned 0x%p\n", ri);
#endif
				if (ri == (void *)0)
					continue;
				xid = ri_to_xid(ri);
				if (ci->ci_xid == xid) {
#ifdef	PRINTFS
	printf("read_vc:  got reply for me (xid %d)\n", xid);
#endif
					ci->ci_readinfo = ri;
#ifdef	PRINTFS
	printf("read_vc:  0x%p->ci_readinfo <- 0x%p\n", ci, ri);
#endif
				} else {
#ifdef	PRINTFS
	printf("read_vc:  got reply for xid %d\n", xid);
#endif
					h = xid_to_callinfo(ci->ci_ct, xid);
					if (h && (h->ci_readinfo
						== (void *)0)) {
						h->ci_readinfo = ri;
#ifdef	PRINTFS
	printf("read_vc:  0x%p->ci_readinfo <- 0x%p\n", h, ri);
#endif
					} else
						free_pkt(ri);
				}
				break;
			}
		}
	}

#ifdef	PRINTFS
	printf("read_vc:  calling pkt_vc_read()\n");
#endif
	switch (len = pkt_vc_read(&ci->ci_readinfo, buf, len)) {
	case 0:
#ifdef	PRINTFS
		printf("read_vc:  pkt_vc_read() returned 0\n");
#endif
		/* premature eof */
		ci->ci_error.re_errno = ENOLINK;
		ci->ci_error.re_terrno = 0;
		ci->ci_error.re_status = RPC_CANTRECV;
		len = -1;	/* it's really an error */
		if (ci->ci_readinfo) {
			free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
			printf("read_vc:  0x%p->ci_readinfo <- 0\n", ci);
#endif
			ci->ci_readinfo = (void *)0;
		}
#ifdef	PRINTFS
		else
			printf("read_vc:  ci_readinfo = 0\n");
#endif
		break;

	case -1:
#ifdef	PRINTFS
		printf("read_vc:  pkt_vc_read() returned -1\n");
#endif
		ci->ci_error.re_terrno = t_errno;
		ci->ci_error.re_errno = 0;
		ci->ci_error.re_status = RPC_CANTRECV;
		if (ci->ci_readinfo) {
			free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
			printf("read_vc:  0x%p->ci_readinfo <- 0\n", ci);
#endif
			ci->ci_readinfo = (void *)0;
		}
#ifdef	PRINTFS
		else
			printf("read_vc:  ci_readinfo = 0\n");
#endif
		break;
	default:
		readhack = len;

	}

#ifdef	PRINTFS
	printf("read_vc:  returning %d\n", len);
#endif
	return (len);
}

static int
write_vc(struct callinfo *ci, caddr_t buf, int len)
{
	register int i, cnt;
	register struct ct_data *ct = ci->ci_ct;
	int flag;
	int maxsz;

	maxsz = ct->ct_tinfo.tsdu;
	i = 0;
	if (maxsz == -2) {	/* Transfer of data unsupported */
		ci->ci_error.re_terrno = TNOTSUPPORT;
		ci->ci_error.re_errno = 0;
		ci->ci_error.re_status = RPC_CANTSEND;
		return (-1);
	}
	if ((maxsz == 0) || (maxsz == -1)) {
		if ((len = t_snd(ct->ct_fd, buf, (unsigned)len, 0)) == -1) {
			ci->ci_error.re_terrno = t_errno;
			ci->ci_error.re_errno = 0;
			ci->ci_error.re_status = RPC_CANTSEND;
		}
		return (len);
	}

	/*
	 * This for those transports which have a max size for data.
	 */
	for (cnt = len; cnt > 0; cnt -= i, buf += i) {
		flag = cnt > maxsz ? T_MORE : 0;
		if ((i = t_snd(ct->ct_fd, buf, (unsigned)MIN(cnt, maxsz),
				flag)) == -1) {
			ci->ci_error.re_terrno = t_errno;
			ci->ci_error.re_errno = 0;
			ci->ci_error.re_status = RPC_CANTSEND;
			return (-1);
		}
	}
	return (len);
}

static struct clnt_ops *
clnt_vc_ops()
{
	static struct clnt_ops ops;

	if (ops.cl_call == NULL) {
		ops.cl_call = clnt_vc_call;
		ops.cl_abort = clnt_vc_abort;
		ops.cl_geterr = clnt_vc_geterr;
		ops.cl_freeres = clnt_vc_freeres;
		ops.cl_destroy = clnt_vc_destroy;
		ops.cl_control = clnt_vc_control;
	}
	return (&ops);
}

/*
 * Make sure that the time is not garbage.   -1 value is disallowed.
 * Note this is different from time_not_ok in clnt_dg.c
 */
static bool_t
time_not_ok(struct timeval *t)
{
	return (t->tv_sec <= -1 || t->tv_sec > 100000000 ||
		t->tv_usec <= -1 || t->tv_usec > 1000000);
}

static struct callinfo *
alloc_callinfo(struct ct_data *ct, uint_t flags)
{
	register struct callinfo *ci;

	ci = (struct callinfo *)malloc(sizeof (struct callinfo));

	if (ci == ((struct callinfo *)NULL))
		return ((struct callinfo *)NULL);
#ifdef	PRINTFS
	printf("alloc_callinfo:  malloc callinfo struct returning 0x%p\n",
	ci);
#endif
	ci->ci_flags = flags;
	ci->ci_ct = ct;
	if (ct->ct_calls != (struct callinfo *)NULL) {
		ci->ci_next = ct->ct_calls;
		ct->ct_calls = ci;
	} else {
		ci->ci_next = (struct callinfo *)0;
		ct->ct_calls = ci;
	}

	return (ci);
}

static void
free_callinfo(struct callinfo *ci)
{
#ifdef	PRINTFS
	printf("free_callinfo:  free 0x%p\n", ci);
#endif
	(void) free((char *)ci);
}

static struct callinfo	*
find_callinfo(struct ct_data *ct, uint_t flags)
{
	register struct callinfo	*ci;

	for (ci = ct->ct_calls; ci; ci = ci->ci_next)
		if (ci->ci_flags & flags)
			return (ci);

	return ((struct callinfo *)0);
}

static void
dequeue_callinfo(struct ct_data *ct, struct callinfo *targetci)
{
	register struct callinfo	*ci, *prevci = (struct callinfo *)0;

	for (ci = ct->ct_calls; ci; ci = ci->ci_next) {
		if (ci == targetci)
			if (ct->ct_calls == ci)
				ct->ct_calls = ci->ci_next;
			else {
				assert(prevci != (struct callinfo *)0);
				prevci->ci_next = ci->ci_next;
			}
		prevci = ci;
	}
}

static void
rac_vc_drop(CLIENT *cl, struct callinfo *h)
{
	register struct ct_data *ct = (struct ct_data *)cl->cl_private;
	register struct callinfo *ci, *prevci;

	for (ci = ct->ct_calls, prevci = (struct callinfo *)NULL;
			ci; ci = ci->ci_next)
		if (ci == h && (ci->ci_flags & CI_ASYNC)) {
			if (ct->ct_calls == ci)
				ct->ct_calls = ci->ci_next;
			else {
				assert(prevci != (struct callinfo *)NULL);
				prevci->ci_next = ci->ci_next;
}
			if (ci->ci_readinfo) {
#ifdef	PRINTFS
	printf("rac_vc_drop:  calling free_pkt(0x%p)\n",
		ci->ci_readinfo);
#endif
				free_pkt(ci->ci_readinfo);
#ifdef	PRINTFS
	printf("rac_vc_drop:  0x%p->ci_readinfo <- 0\n", ci);
#endif
				ci->ci_readinfo = (void *)0;
			}
#ifdef	PRINTFS
			else
	printf("rac_vc_drop:  ci_readinfo == 0 for ci@0x%p\n", ci);
#endif
			if (ct->ct_pollinfo) {
#ifdef	PRINTFS
	printf("rac_vc_drop:  calling free_pollinfo(0x%p)\n", ct->ct_pollinfo);
#endif
				free_pollinfo(ct->ct_pollinfo);
#ifdef	PRINTFS
	printf("rac_v_drop:  0x%p->ct_pollinfo <- 0\n", ct);
#endif
				ct->ct_pollinfo = (void *)0;
			}
#ifdef	PRINTFS
			else
	printf("rac_vc_drop:  ci_pollinfo == 0 for ci@0x%p\n", ci);
#endif
			XDR_DESTROY(&(ci->ci_xdrs));
#ifdef	PRINTFS
	printf("rac_vc_drop:  calling free_callinfo(0x%p)\n", ci);
#endif
			free_callinfo(ci);
			return;
		} else
			prevci = ci;
#ifdef	PRINTFS
	printf("rac_vc_drop:  <cl 0x%p, h 0x%p> not found\n", cl, h);
#endif
}

static enum clnt_stat
rac_vc_poll(CLIENT *cl, struct callinfo *h)
{
	register void	*ri;
	register uint32_t	xid;
	register struct ct_data	*ct;
	register struct callinfo	*ci;

	if (rachandle_is_valid(cl, h)) {
		if (h->ci_readinfo) {
#ifdef	PRINTFS
	printf("rac_vc_poll:  0x%p->ci_readinfo 0x%p, returning RPC_SUCCESS\n",
		h, h->ci_readinfo);
#endif
			return (RPC_SUCCESS);
	}

		ct = h->ci_ct;
		if (ri = pkt_vc_poll(ct->ct_fd, &ct->ct_pollinfo)) {
			xid = ri_to_xid(ri);
			if (h->ci_xid == xid) {
#ifdef	PRINTFS
	printf("rac_vc_poll:  got my reply (xid %d), returning RPC_SUCCESS\n",
	xid);
	printf("rac_vc_poll:  0x%p->ci_readinfo <- 0x%p\n", h, ri);
#endif
				h->ci_readinfo = ri;
				return (RPC_SUCCESS);
			} else {
#ifdef	PRINTFS
	printf("rac_vc_poll:  got reply for xid %d, ", xid);
#endif
				ci = xid_to_callinfo(h->ci_ct, xid);
				if (ci && (ci->ci_readinfo == (void *)0)) {
#ifdef	PRINTFS
	printf("rac_vc_poll:  0x%p->ci_readinfo <- 0x%p\n", ci, ri);
#endif
					ci->ci_readinfo = ri;
				} else {
#ifdef	PRINTFS
	printf("rac_vc_poll:  no ci, or ci_readinfo already set for ci 0x%p\n",
	ci);
#endif
					free_pkt(ri);
				}
			}
		}
#ifdef	PRINTFS
		printf("returning RPC_INPROGRESS\n");
#endif
		return (RPC_INPROGRESS);
	} else
		return (RPC_STALERACHANDLE);
}

static enum clnt_stat
rac_vc_recv(CLIENT *cl, struct callinfo *h)
{
	enum clnt_stat	status;

	if (rachandle_is_valid(cl, h)) {
		struct rpc_msg	reply_msg;
		bool_t	hadri;

		hadri = h->ci_readinfo ?  TRUE : FALSE;
#ifdef	PRINTFS
		printf("rac_vc_recv(CLIENT 0x%p, callinfo 0x%p):  "
			"readinfo 0x%p\n", cl, h, h->ci_readinfo);
#endif
recv_again:
		if (vc_recv(h, &reply_msg) != RPC_SUCCESS) {
			status = h->ci_error.re_status;
			rac_vc_drop(cl, h);
			return (status);
		}

		switch (vc_xdrin(cl, h, &reply_msg)) {
		case (int)XS_CALLAGAIN:
			if (hadri == TRUE) {
				rac_vc_drop(cl, h);
				return (RPC_AUTHERROR);
			} else {
				if (vc_send(cl, h, TRUE) != RPC_SUCCESS) {
					status = h->ci_error.re_status;
					rac_vc_drop(cl, h);
					return (status);
				} else
					goto recv_again;
			}
		/* NOTREACHED */

		case (int)XS_ERROR:
		case (int)XS_OK:
		default:
			status = h->ci_error.re_status;
			rac_vc_drop(cl, h);
			return (status);
		}
		/* NOTREACHED */
	} else
		return (RPC_STALERACHANDLE);
}

static void *
rac_vc_send(CLIENT *cl, struct rac_send_req *h)
{
	register struct ct_data *ct = (struct ct_data *)cl->cl_private;
	register struct callinfo *ci;

	if ((ci = alloc_callinfo(ct, CI_ASYNC)) == (struct callinfo *)NULL) {
		rac_senderr.re_status = RPC_SYSTEMERROR;
		return ((void *)NULL);
	}
	ci->ci_nrefreshes = 2;
	ci->ci_proc = h->proc;
	ci->ci_xargs = h->xargs;
	ci->ci_argsp = (caddr_t)h->argsp;
	ci->ci_xresults = h->xresults;
	ci->ci_resultsp = (caddr_t)h->resultsp;
#ifdef	PRINTFS
	printf("rac_vc_send:  0x%p->ci_readinfo <- 0\n", ci);
#endif
	ci->ci_readinfo = (void *)0;

	ci->ci_xid = --ct->ct_xidseed;

	if (!ct->ct_waitset)
		ct->ct_wait = h->timeout;

	/*
	 * Create a client handle which uses xdrrec for serialization
	 * and authnone for authentication.
	 */
	ci->ci_xdrs.x_ops = NULL;
	xdrrec_create(&(ci->ci_xdrs), ct->ct_sendsz, ct->ct_recvsz,
				(caddr_t)ci, (recrw_fn_t)read_vc,
			(recrw_fn_t)write_vc);
	if (ci->ci_xdrs.x_ops == NULL) {
		free_callinfo(ci);
		return ((void *)NULL);
	}

	if (vc_send(cl, ci, TRUE) != RPC_SUCCESS) {
		dequeue_callinfo(ct, ci);
		free_callinfo(ci);
#ifdef	PRINTFS
		printf("rac_vc_send:  vc_send failed (error %d)\n",
	ci->ci_error.re_status);
#endif
		return ((void *)NULL);
	}
#ifdef	PRINTFS
	else
		printf("rac_vc_send:  vc_send succeeded\n");
#endif

	return ((void *)ci);
}

static bool_t
rachandle_is_valid(CLIENT *cl, struct callinfo *h)
{
	register struct callinfo *ci;

	for (ci = ((struct ct_data *)cl->cl_private)->ct_calls;
		ci; ci = ci->ci_next) {
		if (ci == h && (ci->ci_flags & CI_ASYNC))
			return (TRUE);
	}
	return (FALSE);
}

static struct callinfo *
xid_to_callinfo(struct ct_data *ct, uint32_t xid)
{
	register struct callinfo *ci;

	for (ci = ct->ct_calls; ci; ci = ci->ci_next)
		if (xid == ci->ci_xid)
			return (ci);

	return ((struct callinfo *)NULL);
}
