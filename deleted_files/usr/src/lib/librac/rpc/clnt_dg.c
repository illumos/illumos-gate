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
 * clnt_dg.c
 *
 * Implements a connectionless client side RPC.
 */

#include <rpc/rpc.h>
#include <rpc/rac.h>
#include "rac_private.h"
#ifndef	NDEBUG
#include <stdio.h>
#endif
#include <assert.h>
#include <errno.h>
#include <sys/poll.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/kstat.h>
#include <sys/time.h>
#include <tiuser.h>

#define	MCALL_MSG_SIZE		24

enum clnt_dg_receive_stat { RS_RESEND, RS_ERROR, RS_OK };
enum clnt_dg_xdrin_stat { XS_CALLAGAIN, XS_ERROR, XS_OK };

/*
 * Private data kept per client handle
 */
struct cu_data {
	/* per-CLIENT information */
	int			cu_fd;		/* connections fd */
	bool_t			cu_closeit;	/* opened by library */
	struct timeval		cu_wait;	/* retransmit interval */
	struct timeval		cu_total;	/* total time for the call */
	struct netbuf		cu_addr;	/* remote address */
	char			cu_mcallproto[MCALL_MSG_SIZE];
	/* prototype marshalled callmsg */
	uint_t			cu_msize;	/* #bytes in cu_mcallproto */
	uint_t			cu_sendsz;	/* per-call send size */
	uint_t			cu_recvsz;	/* per-call receive size */
	uint32_t		cu_xidseed;	/* XID seed */
	struct t_unitdata	*cu_tr_data;
	/* recv. buffer for sync calls */
	struct callinfo		*cu_calls;	/* per-call information chain */
};

struct callinfo {
	uint_t			ci_flags;	/* per-call flags */
#define	CI_ASYNC	1
#define	CI_SYNC		2
	struct rpc_err		ci_error;	/* call error information */
	int			ci_nrefreshes;	/* times to refresh cred */
	struct timeval		ci_timewaited;	/* time we've waited so far */
	struct timeval		ci_rexmittime;	/* time until rexmit due */
	struct timeval		ci_calltimeout;	/* total time for the call */
	struct timeval		ci_sendtime;	/* time of rac_dg_send call */
	uint_t			ci_firsttimeout;
	/* First timeout associated with this call */
	uint32_t		ci_xid;		/* transaction id */
	rpcproc_t		ci_proc;	/* remote procedure */
	xdrproc_t		ci_xargs;	/* XDR routine for arguments */
	caddr_t			ci_argsp;	/* pointer to args buffer */
	xdrproc_t		ci_xresults;	/* XDR routine for results */
	caddr_t			ci_resultsp;	/* pointer to results buffer */
	char			*ci_outbuf;	/* per-call output buffer */
	XDR			ci_outxdrs;
	uint_t			ci_xdrpos;	/* position in ci_outxdrs */
	struct t_unitdata	*ci_trdata;
	struct cu_data	*ci_cu;		/* per-CLIENT information */
	struct callinfo		*ci_next;	/* info on ``next'' call */
};

static struct clnt_ops *clnt_dg_ops(void);
static enum clnt_stat clnt_dg_marshall(CLIENT *, struct callinfo *);
static enum clnt_stat clnt_dg_send(struct callinfo *);
static enum clnt_dg_receive_stat clnt_dg_receive(struct callinfo *, int);
static enum clnt_dg_xdrin_stat clnt_dg_xdrin(CLIENT *cl, struct callinfo *,
									int);

static void		rac_dg_drop(CLIENT *, struct callinfo *);
static enum clnt_stat	rac_dg_poll(CLIENT *, struct callinfo *);
static enum clnt_stat	rac_dg_recv(CLIENT *, struct callinfo *);
static void		*rac_dg_send(CLIENT *, struct rac_send_req *);
static bool_t		rachandle_is_valid(CLIENT *, struct callinfo *);
static struct callinfo	*xid_to_callinfo(struct cu_data *, uint32_t);
static bool_t		time_not_ok(struct timeval *);
static int		netbuf_copy(struct netbuf *, struct netbuf *, int);
static struct callinfo	*alloc_callinfo(struct cu_data *, uint_t);
static struct callinfo	*find_callinfo(struct cu_data *, uint_t);
static void		free_callinfo(struct callinfo *);
static void		dequeue_callinfo(struct cu_data *, struct callinfo *);


extern int		__rpc_timeval_to_msec(struct timeval *);
extern bool_t		xdr_opaque_auth(XDR *, struct opaque_auth *ap);

/*
 * Connectionless client creation returns with client handle parameters.
 * Default options are set, which the user can change using clnt_control().
 * fd should be open and bound.
 * NB: The cl->cl_auth is initialized to null authentication.
 * 	Caller may wish to set this something more useful.
 *
 * sendsz and recvsz are the maximum allowable packet sizes that can be
 * sent and received. Normally they are the same, but they can be
 * changed to improve the program efficiency and buffer allocation.
 * If they are 0, use the transport default.
 *
 * If svcaddr is NULL, returns NULL.
 */
CLIENT *
clnt_dg_create(const int fd, struct netbuf *svcaddr,
    const rpcprog_t program, const rpcvers_t version, const uint_t sendsz,
    const uint_t recvsz)
{
	CLIENT *cl = NULL;			/* client handle */
	register struct cu_data *cu = NULL;	/* private data */
	struct t_unitdata *tr_data;
	struct t_info tinfo;
	struct rpc_msg call_msg;
	struct timeval now;
	uint_t ssz, rsz;
	XDR tmpxdrs;

	if (svcaddr == (struct netbuf *)NULL) {
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		return ((CLIENT *)NULL);
	}

	if ((cl = (CLIENT *)malloc(sizeof (CLIENT))) == (CLIENT *)NULL)
		goto err1;
	cu = (struct cu_data *)malloc(sizeof (*cu));
	if (cu == (struct cu_data *)NULL)
		goto err1;
	cu->cu_addr = *svcaddr;
	if ((cu->cu_addr.buf = malloc(svcaddr->len)) == NULL) {
		free((caddr_t)cu);
		cu = (struct cu_data *)NULL;
		goto err1;
	}
	(void) memcpy(cu->cu_addr.buf, svcaddr->buf, (int)svcaddr->len);
	/* Other values can also be set through clnt_control() */
	cu->cu_wait.tv_sec = 15;	/* heuristically chosen */
	cu->cu_wait.tv_usec = 0;
	cu->cu_total.tv_sec = -1;
	cu->cu_total.tv_usec = -1;

	/* XID is set in clnt_dg_marshall() */
	call_msg.rm_call.cb_prog = program;
	call_msg.rm_call.cb_vers = version;
	xdrmem_create(&tmpxdrs, cu->cu_mcallproto, MCALL_MSG_SIZE, XDR_ENCODE);
	if (! xdr_callhdr(&tmpxdrs, &call_msg)) {
		rpc_createerr.cf_stat = RPC_CANTENCODEARGS;  /* XXX */
		rpc_createerr.cf_error.re_errno = 0;
		rpc_createerr.cf_error.re_terrno = 0;
		goto err2;
	}
	cu->cu_msize = XDR_GETPOS(&tmpxdrs);
	XDR_DESTROY(&tmpxdrs);

	if (t_getinfo(fd, &tinfo) == -1) {
		if ((sendsz == 0) || (recvsz == 0)) {
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_errno = 0;
			rpc_createerr.cf_error.re_terrno = t_errno;
			goto err2;
		}
		ssz = sendsz;
		rsz = recvsz;
	} else {
		/*
		 * Find the receive and the send size
		 */
		ssz = __rpc_get_t_size((int)sendsz, tinfo.tsdu);
		rsz = __rpc_get_t_size((int)recvsz, tinfo.tsdu);
	}
	/*
	 * Should be multiple of 4 for XDR.
	 */
	cu->cu_sendsz = ((ssz + 3) / 4) * 4;
	cu->cu_recvsz = ((rsz + 3) / 4) * 4;

	(void) gettimeofday(&now, (struct timezone *)0);
	cu->cu_xidseed = getpid() ^ now.tv_sec ^ now.tv_usec;

	/*
	 * By default, closeit is always FALSE. It is users responsibility
	 * to do a t_close on it, else the user may use clnt_control
	 * to let clnt_destroy do it for him/her.
	 */
	cu->cu_closeit = FALSE;
	cu->cu_fd = fd;
	cu->cu_calls = (struct callinfo *)NULL;
	tr_data = (struct t_unitdata *)t_alloc(fd,
				T_UNITDATA, T_DATA | T_ADDR);

	if (tr_data == (struct t_unitdata *)NULL) {
		goto err1;
	}
	tr_data->udata.maxlen = cu->cu_recvsz;
	cu->cu_tr_data = tr_data;

	cl->cl_ops = clnt_dg_ops();
	cl->cl_private = (caddr_t)cu;
	cl->cl_auth = authnone_create();
	cl->cl_tp = (char *)NULL;
	cl->cl_netid = (char *)NULL;
	return (cl);
err1:
	(void) syslog(LOG_ERR, "clnt_dg_create: out of memory");
	rpc_createerr.cf_stat = RPC_SYSTEMERROR;
	rpc_createerr.cf_error.re_errno = errno;
	rpc_createerr.cf_error.re_terrno = 0;
err2:
	if (cl) {
		free((caddr_t)cl);
		if (cu) {
			free(cu->cu_addr.buf);
			free((caddr_t)cu);
		}
	}
	return ((CLIENT *)NULL);
}

static enum clnt_stat
clnt_dg_call(CLIENT *cl, rpcproc_t proc, xdrproc_t xargs, caddr_t argsp,
    xdrproc_t xresults, caddr_t resultsp, struct timeval utimeout)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register struct callinfo *ci;

	if ((ci = find_callinfo(cu, CI_SYNC)) == (struct callinfo *)NULL)
		if ((ci = alloc_callinfo(cu, CI_SYNC)) == (struct callinfo *)0)
		return (RPC_SYSTEMERROR);
	ci->ci_nrefreshes = 2;	/* number of times to refresh cred */
	ci->ci_proc = proc;
	ci->ci_xargs = xargs;
	ci->ci_argsp = argsp;
	ci->ci_xresults = xresults;
	ci->ci_resultsp = resultsp;
	xdrmem_create(&(ci->ci_outxdrs), ci->ci_outbuf,
			cu->cu_sendsz, XDR_ENCODE);
	ci->ci_xid = ++cu->cu_xidseed;

	if (cu->cu_total.tv_usec == -1) {
		ci->ci_calltimeout = utimeout;	/* use supplied timeout */
	} else {
		ci->ci_calltimeout = cu->cu_total; /* use default timeout */
	}
	ci->ci_trdata = NULL;

	timerclear(&ci->ci_timewaited);
	ci->ci_rexmittime = cu->cu_wait;

call_again:
#ifdef	PRINTFS
	printf("clnt_dg_call:  call_again\n");
#endif
	if (clnt_dg_marshall(cl, ci) != RPC_SUCCESS) {
		dequeue_callinfo(cu, ci);
		free_callinfo(ci);
		return (ci->ci_error.re_status);
	}
#ifdef	PRINTFS
	else
		printf("clnt_dg_call:  clnt_dg_marshall succeeded\n");
#endif

send_again:
	if (clnt_dg_send(ci) != RPC_SUCCESS) {
		dequeue_callinfo(cu, ci);
		free_callinfo(ci);
		return (ci->ci_error.re_status);
	}
#ifdef	PRINTFS
	else
		printf("clnt_dg_call:  clnt_dg_send succeeded\n");
#endif

	/*
	 * Hack to provide rpc-based message passing
	 */
	if (! timerisset(&ci->ci_calltimeout))
		return (ci->ci_error.re_status = RPC_TIMEDOUT);

	switch ((int)clnt_dg_receive(ci, CI_SYNC)) {
	case (int)RS_RESEND:
#ifdef	PRINTFS
		printf("clnt_dg_receive returned RS_RESEND\n");
#endif
		goto send_again;
		/* NOTREACHED */

	case (int)RS_ERROR:
#ifdef	PRINTFS
		printf("clnt_dg_receive returned error %d\n",
			ci->ci_error.re_status);
#endif
		return (ci->ci_error.re_status);
		/* NOTREACHED */

	case (int)RS_OK:
#ifdef	PRINTFS
		printf("clnt_dg_receive returned OK\n");
#endif
		break;
	}

	switch (clnt_dg_xdrin(cl, ci, CI_SYNC)) {
	case (int)XS_CALLAGAIN:
#ifdef	PRINTFS
		printf("clnt_dg_xdrin returned CALL_AGAIN\n");
#endif
		goto call_again;

	case (int)XS_ERROR:
	case (int)XS_OK:
	default:
#ifdef	PRINTFS
		printf("clnt_dg_xdrin returned %d\n", ci->ci_error.re_status);
#endif
		return (ci->ci_error.re_status);
	}
	/* NOTREACHED */
}

static enum clnt_stat
clnt_dg_marshall(CLIENT *cl, struct callinfo *ci)
{
	register XDR *xdrs = &(ci->ci_outxdrs);
	register struct cu_data	*cu = ci->ci_cu;

	assert(cl);
	assert(ci);
	assert(cu);
	assert(ci->ci_outbuf);
	assert(cu->cu_mcallproto);
	assert(cu->cu_msize);
	xdrs->x_op = XDR_ENCODE;
	XDR_SETPOS(xdrs, cu->cu_msize);
	(void) memcpy(ci->ci_outbuf, cu->cu_mcallproto, (int)cu->cu_msize);
	/*
	 * the transaction id is the first thing in the output buffer
	 */
	*(uint32_t *)ci->ci_outbuf = htonl(++ci->ci_xid);
#ifdef	PRINTFS
	printf("clnt_dg_marshall:  xid %d\n", ci->ci_xid);
#endif
	if ((! XDR_PUTINT32(xdrs, (int32_t *)&ci->ci_proc)) ||
	    (! AUTH_MARSHALL(cl->cl_auth, xdrs)) ||
	    (! (*ci->ci_xargs)(xdrs, ci->ci_argsp)))
		return (ci->ci_error.re_status = RPC_CANTENCODEARGS);
	else
		return (RPC_SUCCESS);
}

static enum clnt_stat
clnt_dg_send(struct callinfo *ci)
{
	register struct cu_data	*cu = ci->ci_cu;
	struct t_unitdata tu_data;

	assert(ci);
	assert(cu);
	assert(cu->cu_fd >= 0);
	assert(ci->ci_outbuf);
	tu_data.addr = cu->cu_addr;
	tu_data.udata.buf = ci->ci_outbuf;
	tu_data.udata.len = (int)XDR_GETPOS(&ci->ci_outxdrs);
	tu_data.opt.len = 0;
	if (t_sndudata(cu->cu_fd, &tu_data) == -1) {
		ci->ci_error.re_terrno = t_errno;
		ci->ci_error.re_errno = errno;
		return (ci->ci_error.re_status = RPC_CANTSEND);
	} else
		return (RPC_SUCCESS);
}


static enum clnt_dg_receive_stat
clnt_dg_receive(struct callinfo *ci, int flag)
{
	register struct cu_data	*cu = ci->ci_cu;
	struct t_unitdata *tmp_trdata = (struct t_unitdata *)NULL;
	uint32_t pktxid;
	int res;		/* result of operations */
	struct timeval startime, curtime;
	static struct pollfd *pfdp = NULL;
	static int nfds = 0;

	assert(ci);
	assert(cu);

	if (pfdp == (struct pollfd *)NULL) {
		pfdp = (struct pollfd *)
			malloc(sizeof (struct pollfd));
		if (pfdp == (struct pollfd *)NULL) {
			return (-1);
		}
		nfds = 1;
	}

	pfdp[0].fd = cu->cu_fd;
	pfdp[0].events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
	pfdp[0].revents = 0;

	for (;;) {
		extern void (*_svc_getreqset_proc)();
		int fds;

		if (tmp_trdata != (struct t_unitdata *)NULL &&
			flag == CI_ASYNC) {
			(void) t_free((char *)tmp_trdata, T_UNITDATA);
			tmp_trdata = (struct t_unitdata *)NULL;
		}

		/*
		 * This provides for callback support.  When a client
		 * recv's a call from another client on the server fd's,
		 * it calls _svc_getreqset(&readfds) which would return
		 * after serving all the server requests.  Also look under
		 * svc.c
		 */

		if (_svc_getreqset_proc) {
			/* ``+ 1'' because of pfdp[0] */
			if (nfds != (svc_max_pollfd + 1)) {
				pfdp = realloc(pfdp,
				    sizeof (pollfd_t) * (svc_max_pollfd + 1));
				nfds = svc_max_pollfd + 1;
			}
			(void) memcpy(&pfdp[1], svc_pollfd,
					sizeof (pollfd_t) * svc_max_pollfd);
		} else {
			nfds = 1; /* don't forget about pfdp[0] */
		}

		switch (fds = poll(pfdp, nfds,
		    __rpc_timeval_to_msec(&ci->ci_rexmittime))) {

		case 0:
			ci->ci_timewaited.tv_sec += ci->ci_rexmittime.tv_sec;
			ci->ci_timewaited.tv_usec += ci->ci_rexmittime.tv_usec;
			while (ci->ci_timewaited.tv_usec >= 1000000) {
				ci->ci_timewaited.tv_sec++;
				ci->ci_timewaited.tv_usec -= 1000000;
			}
			/* update the time to next retransmission */
			if (ci->ci_rexmittime.tv_sec < RPC_MAX_BACKOFF) {
				ci->ci_rexmittime.tv_usec *= 2;
				ci->ci_rexmittime.tv_sec *= 2;
				while (ci->ci_rexmittime.tv_usec >= 1000000) {
					ci->ci_rexmittime.tv_sec++;
					ci->ci_rexmittime.tv_usec -= 1000000;
				}
			}

			if (timercmp(&ci->ci_timewaited,
			    &ci->ci_calltimeout, < /* */))
				return (RS_RESEND);
			else {
				ci->ci_error.re_status = RPC_TIMEDOUT;
				return (RS_ERROR);
			}

		case -1:

			if (errno == EBADF) {
				ci->ci_error.re_errno = errno;
				ci->ci_error.re_terrno = 0;
				ci->ci_error.re_status = RPC_CANTRECV;
				return (RS_ERROR);
			}

			if (errno != EINTR) {
				errno = 0; /* reset it */
				continue;
			}
			if (ci->ci_firsttimeout) {
				/*
				 * Could have done gettimeofday before clnt_call
				 * but that means 1 more system call per each
				 * clnt_call, so do it after first time out
				 */
				if (gettimeofday(&startime,
					(struct timezone *)NULL) == -1) {
					errno = 0;
					continue;
				}
				ci->ci_firsttimeout = 0;
				errno = 0;
				continue;
			};
			if (gettimeofday(&curtime,
				(struct timezone *)NULL) == -1) {
				errno = 0;
				continue;
			};
			ci->ci_timewaited.tv_sec +=
				curtime.tv_sec - startime.tv_sec;
			ci->ci_timewaited.tv_usec += curtime.tv_usec -
				startime.tv_usec;
			while (ci->ci_timewaited.tv_usec < 0) {
				ci->ci_timewaited.tv_sec--;
				ci->ci_timewaited.tv_usec += 1000000;
			};
			while (ci->ci_timewaited.tv_usec >= 1000000) {
				ci->ci_timewaited.tv_sec++;
				ci->ci_timewaited.tv_usec -= 1000000;
			}
			startime.tv_sec = curtime.tv_sec;
			startime.tv_usec = curtime.tv_usec;
			if ((ci->ci_timewaited.tv_sec >
				ci->ci_calltimeout.tv_sec) ||
				(ci->ci_timewaited.tv_sec ==
				ci->ci_calltimeout.tv_sec) &&
				(ci->ci_timewaited.tv_usec >
				ci->ci_calltimeout.tv_usec)) {
			ci->ci_error.re_status = RPC_TIMEDOUT;
				return (RS_ERROR);
			}
			errno = 0; /* reset it */
			continue;

		}
		if (pfdp[0].revents == 0) {
			/* must be for server side of the house */
			(*_svc_getreqset_proc)(&pfdp[1], fds);
			continue; /* do poll again */
		} else if (pfdp[0].revents & POLLNVAL) {


			ci->ci_error.re_status = RPC_CANTRECV;
			/*
			 *	Note:  we're faking errno here because we
			 *	previously would have expected select() to
			 *	return -1 with errno EBADF.  Poll(BA_OS)
			 *	returns 0 and sets the POLLNVAL revents flag
			 *	instead.
			 */
			ci->ci_error.re_errno = errno = EBADF;
			return (RS_ERROR);

		}

		/* We have some data now */
		if (flag == CI_ASYNC) {
			tmp_trdata = (struct t_unitdata *)t_alloc(cu->cu_fd,
							T_UNITDATA,
							T_ALL);
			if (tmp_trdata == (struct t_unitdata *)NULL) {
				ci->ci_error.re_errno = errno;
				ci->ci_error.re_terrno = t_errno;
				ci->ci_error.re_status = RPC_SYSTEMERROR;
				return (RS_ERROR);
			}
		} else
			tmp_trdata = cu->cu_tr_data;

		do {
			int moreflag; /* flag indicating more data */

			moreflag = 0;

			res = t_rcvudata(cu->cu_fd, tmp_trdata, &moreflag);

			if ((moreflag & T_MORE) ||
			    (tmp_trdata->udata.len > cu->cu_recvsz)) {
#ifdef	PRINTFS
	printf("clnt_dg_receive:  moreflag %d, udata.len %d, recvsz %d\n",
		moreflag, tmp_trdata->udata.len, cu->cu_recvsz);
#endif
				/*
				 * Drop this packet. I ain't got any
				 * more space.
				 */
				res = -1;
				/* I should not really be doing this */
				errno = 0;
				/*
				 * XXX: Not really Buffer overflow in the
				 * sense of TLI.
				 */
				t_errno = TBUFOVFLW;
			}
		} while (res < 0 && (t_errno == TSYSERR && errno == EINTR));
		if (res < 0) {
#ifdef sun
			if (t_errno == TSYSERR && errno == EWOULDBLOCK)
#else
				if (t_errno == TSYSERR && errno == EAGAIN)
#endif
					continue;
			if (t_errno == TLOOK) {
				int old;

				old = t_errno;
				if (t_rcvuderr(cu->cu_fd,
					(struct t_uderr *)NULL) == 0)
					continue;
				else
					ci->ci_error.re_terrno = old;
			} else {
				ci->ci_error.re_terrno = t_errno;
			}
			(void) t_free((char *)tmp_trdata, T_UNITDATA);
			ci->ci_error.re_errno = errno;
			ci->ci_error.re_status = RPC_CANTRECV;
			return (RS_ERROR);
		}
		if (tmp_trdata->udata.len < sizeof (uint32_t))
			/* tmp_trdata is freed at the top of the for loop */
			continue;
		/*
		 *	If the returned XID happens to match ours, we're in
		 *	luck.  If not, we have to search for an in-progress
		 *	call to which the reply should be attached.
		 */
		pktxid = ntohl(*(uint32_t *)(tmp_trdata->udata.buf));
		if (pktxid != ci->ci_xid) {
			register struct callinfo *p;

#ifdef	PRINTFS
	printf("clnt_dg_receive:  pktxid (%x) != ci_xid (%x)\n",
		pktxid, ci->ci_xid);
#endif
			p = xid_to_callinfo(cu, pktxid);
			/* don't overwrite a previous reply */

			if (p && p->ci_trdata == (struct t_unitdata *)NULL) {
				if (flag == CI_ASYNC) {
					p->ci_trdata = tmp_trdata;
					/*
					 * Prevent a t_free on the
					 * packet we gave away
					 */
					tmp_trdata = (struct t_unitdata *)NULL;
				} else {
					/* copy t_unitdata structure */
					p->ci_trdata = (struct t_unitdata *)
						t_alloc(cu->cu_fd,
							T_UNITDATA,
							T_ADDR | T_OPT);

					if (!netbuf_copy(&tmp_trdata->addr,
							&p->ci_trdata->addr,
							T_ADDR)) {
						(void) t_free(
						    (char *)p->ci_trdata,
						    T_UNITDATA);
						p->ci_trdata = NULL;
						return (RS_ERROR);
					}
					if (!netbuf_copy(&tmp_trdata->opt,
							&p->ci_trdata->opt,
							T_OPT)) {
						(void) t_free(
						    (char *)p->ci_trdata,
						    T_UNITDATA);
						p->ci_trdata = NULL;
						return (RS_ERROR);
					}
					if (!netbuf_copy(&tmp_trdata->udata,
							&p->ci_trdata->udata,
							T_DATA)) {
						(void) t_free(
						    (char *)p->ci_trdata,
						    T_UNITDATA);
						p->ci_trdata = NULL;
						return (RS_ERROR);
					}

				}
			}

			/*
			 * Else, tmp_trdata is freed at the top of the
			 * for loop
			 */
			continue;
		}
#ifdef	PRINTFS
		else
			printf("clnt_dg_receive:  xid match\n");
#endif

		/* we now assume we have the proper reply */
		if (flag == CI_ASYNC)
			ci->ci_trdata = tmp_trdata;
		break;
	}
	return (RS_OK);
}

static enum clnt_dg_xdrin_stat
clnt_dg_xdrin(CLIENT *cl, struct callinfo *ci, int flag)
{
	struct rpc_msg reply_msg;
	register XDR *xdrs = &ci->ci_outxdrs;
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	XDR reply_xdrs;
	bool_t ok;

	assert(cl);
	assert(ci);
	if (flag == CI_ASYNC)
		assert(ci->ci_trdata);

	reply_msg.acpted_rply.ar_verf = _null_auth;
	reply_msg.acpted_rply.ar_results.where = ci->ci_resultsp;
	reply_msg.acpted_rply.ar_results.proc = ci->ci_xresults;

	/*
	 * now decode and validate the response
	 */
	if (flag == CI_SYNC)
		xdrmem_create(&reply_xdrs, cu->cu_tr_data->udata.buf,
			(uint_t)cu->cu_tr_data->udata.len, XDR_DECODE);
	else
		xdrmem_create(&reply_xdrs, ci->ci_trdata->udata.buf,
			(uint_t)ci->ci_trdata->udata.len, XDR_DECODE);

	ok = xdr_replymsg(&reply_xdrs, &reply_msg);
	if (flag == CI_ASYNC) {
		(void) t_free((char *)ci->ci_trdata, T_UNITDATA);
		ci->ci_trdata = (struct t_unitdata *)NULL;
	}
	/* XDR_DESTROY(&reply_xdrs);	save a few cycles on noop destroy */
	if (ok) {
		if ((reply_msg.rm_reply.rp_stat == MSG_ACCEPTED) &&
		    (reply_msg.acpted_rply.ar_stat == SUCCESS))
			ci->ci_error.re_status = RPC_SUCCESS;
		else
			__seterr_reply(&reply_msg, &(ci->ci_error));

		if (ci->ci_error.re_status == RPC_SUCCESS) {
			if (! AUTH_VALIDATE(cl->cl_auth,
					    &reply_msg.acpted_rply.ar_verf)) {
				ci->ci_error.re_status = RPC_AUTHERROR;
				ci->ci_error.re_why = AUTH_INVALIDRESP;
			}
			if (reply_msg.acpted_rply.ar_verf.oa_base != NULL) {
				xdrs->x_op = XDR_FREE;
				(void) xdr_opaque_auth(xdrs,
					&(reply_msg.acpted_rply.ar_verf));
			}
		}		/* end successful completion */
		/*
		 * If unsuccesful AND error is an authentication error
		 * then refresh credentials and try again, else break
		 */
		else if (ci->ci_error.re_status == RPC_AUTHERROR)
			/* maybe our credentials need to be refreshed ... */
			if (ci->ci_nrefreshes > 0 &&
				AUTH_REFRESH(cl->cl_auth, &reply_msg)) {
				ci->ci_nrefreshes--;
				return (XS_CALLAGAIN);
				}
		/* end of valid reply message */
	} else {
		ci->ci_error.re_status = RPC_CANTDECODERES;
		return (XS_ERROR);
	}
	return (XS_OK);
}

/*
 *	The action of this function is not well-defined in the face of
 *	asynchronous calls.  We do the best we can by first trying to
 *	find a synchronous callinfo structure and if none is found,
 *	taking the first call in the chain.  Finally, we assume that
 *	the error must have been from a rac_send() failure and look in
 *	the rac_senderr structure.
 */
static void
clnt_dg_geterr(CLIENT *cl, struct rpc_err *errp)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register struct callinfo *ci;

	for (ci = cu->cu_calls; ci; ci = ci->ci_next)
		if (ci->ci_flags & CI_SYNC) {
			*errp = ci->ci_error;
			return;
		}
	if (ci == (struct callinfo *)0 &&
		cu->cu_calls != (struct callinfo *)0)
		*errp = cu->cu_calls->ci_error;
	else
		/*
		 *	No calls in progress at all - assume this was a
		 *	rac_send failure.
		 */
		*errp = rac_senderr;
}

/*
 *	The action of this function is not well-defined in the face of
 *	asynchronous calls.  We do the best we can by first trying to
 *	find a synchronous callinfo structure and if none is found,
 *	taking the first call in the chain.
 */
static bool_t
clnt_dg_freeres(CLIENT *cl, xdrproc_t xdr_res, caddr_t res_ptr)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register struct callinfo *ci;
	register XDR *xdrs = (XDR *)0;

	for (ci = cu->cu_calls; ci; ci = ci->ci_next)
		if (ci->ci_flags & CI_SYNC) {
			xdrs = &ci->ci_outxdrs;
			break;
		}
	if (xdrs == (XDR *)0 && ci == (struct callinfo *)0 &&
	    cu->cu_calls != (struct callinfo *)0)
		xdrs = &cu->cu_calls->ci_outxdrs;

	if (xdrs) {
		xdrs->x_op = XDR_FREE;
		return ((*xdr_res)(xdrs, res_ptr));
	} else
		return (FALSE);
}

/* ARGSUSED */
static void
clnt_dg_abort(CLIENT *h)
{
}

static bool_t
clnt_dg_control(CLIENT *cl, int request, char *info)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	struct netbuf *addr;

	switch (request) {
	case CLSET_FD_CLOSE:
		cu->cu_closeit = TRUE;
		return (TRUE);
	case CLSET_FD_NCLOSE:
		cu->cu_closeit = FALSE;
		return (TRUE);
	}

	/* for other requests which use info */
	if (info == NULL)
		return (FALSE);
	switch (request) {
	case CLSET_TIMEOUT:
		if (time_not_ok((struct timeval *)info))
			return (FALSE);
		cu->cu_total = *(struct timeval *)info;
		break;
	case CLGET_TIMEOUT:
		*(struct timeval *)info = cu->cu_total;
		break;
	case CLGET_SERVER_ADDR:		/* Give him the fd address */
		/* Now obsolete. Only for backword compatibility */
		(void) memcpy(info, cu->cu_addr.buf, (int)cu->cu_addr.len);
		break;
	case CLSET_RETRY_TIMEOUT:
		if (time_not_ok((struct timeval *)info))
			return (FALSE);
		cu->cu_wait = *(struct timeval *)info;
		break;
	case CLGET_RETRY_TIMEOUT:
		*(struct timeval *)info = cu->cu_wait;
		break;
	case CLGET_FD:
		*(int *)info = cu->cu_fd;
		break;
	case CLGET_SVC_ADDR:
		*(struct netbuf *)info = cu->cu_addr;
		break;
	case CLSET_SVC_ADDR:		/* set to new address */
		addr = (struct netbuf *)info;
		if (cu->cu_addr.maxlen < addr->len) {
			free(cu->cu_addr.buf);
			if ((cu->cu_addr.buf = malloc(addr->len)) == NULL)
				return (FALSE);
			cu->cu_addr.maxlen = addr->len;
		}
		cu->cu_addr.len = addr->len;
		(void) memcpy(cu->cu_addr.buf, addr->buf, addr->len);
		break;
	case CLGET_XID:
		/*
		 * This will get the xid seed value
		 */

		*(uint32_t *)info = cu->cu_xidseed;
		break;

	case CLSET_XID:
		/* This will set the xid seed of the NEXT call */
		cu->cu_xidseed = *(uint32_t *)info - 1;
		/* decrement by 1 as clnt_dg_call() increments once */
		break;
	case CLGET_VERS:
		/*
		 * This RELIES on the information that, in the call body,
		 * the version number field is the fifth field from the
		 * begining of the RPC header. MUST be changed if the
		 * call_struct is changed
		 */
		*(uint32_t *)info = ntohl(*(uint32_t *)(cu->cu_mcallproto +
						    4 * BYTES_PER_XDR_UNIT));
		break;
	case CLSET_VERS:
		*(uint32_t *)(cu->cu_mcallproto + 4 * BYTES_PER_XDR_UNIT)
			= htonl(*(uint32_t *)info);
		break;

	case CLGET_PROG:
		/*
		 * This RELIES on the information that, in the call body,
		 * the program number field is the fourth field from the
		 * begining of the RPC header. MUST be changed if the
		 * call_struct is changed
		 */
		*(uint32_t *)info = ntohl(*(uint32_t *)(cu->cu_mcallproto +
						    3 * BYTES_PER_XDR_UNIT));
		break;

	case CLSET_PROG:
		*(uint32_t *)(cu->cu_mcallproto + 3 * BYTES_PER_XDR_UNIT)
			= htonl(*(uint32_t *)info);
		break;

	case CLRAC_DROP:
		rac_dg_drop(cl, (struct callinfo *)info);
		break;
	case CLRAC_POLL:
		return ((bool_t)rac_dg_poll(cl, (struct callinfo *)info));
	case CLRAC_RECV:
		return ((bool_t)rac_dg_recv(cl, (struct callinfo *)info));
	case CLRAC_SEND:
		((struct rac_send_req *)info)->handle =
				rac_dg_send(cl, (struct rac_send_req *)info);
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

static void
clnt_dg_destroy(CLIENT *cl)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register struct callinfo *ci, *nextci;

	if (cu->cu_closeit)
		(void) t_close(cu->cu_fd);
	for (ci = cu->cu_calls; ci; ci = nextci) {
		nextci = ci->ci_next;
		if (ci->ci_trdata)
			(void) t_free((char *)ci->ci_trdata, T_UNITDATA);
		XDR_DESTROY(&(ci->ci_outxdrs));
		/*
		 *	Don't destroy the one allocated synchronous callinfo
		 *	structure.
		 *
		 *	if ((ci->ci_flags & CI_SYNC) == 0)
		 */
		free_callinfo(ci);
	}
	if (cu->cu_addr.buf)
		(void) free(cu->cu_addr.buf);
	(void) t_free((char *)cu->cu_tr_data, T_UNITDATA);
	(void) free((caddr_t)cu);

	if (cl->cl_netid && cl->cl_netid[0])
		(void) free(cl->cl_netid);
	if (cl->cl_tp && cl->cl_tp[0])
		(void) free(cl->cl_tp);
	(void) free((caddr_t)cl);
}

static struct clnt_ops *
clnt_dg_ops()
{
	static struct clnt_ops ops;

	if (ops.cl_call == NULL) {
		ops.cl_call = clnt_dg_call;
		ops.cl_abort = clnt_dg_abort;
		ops.cl_geterr = clnt_dg_geterr;
		ops.cl_freeres = clnt_dg_freeres;
		ops.cl_destroy = clnt_dg_destroy;
		ops.cl_control = clnt_dg_control;
	}
	return (&ops);
}

/*
 * Make sure that the time is not garbage.  -1 value is allowed.
 */
static bool_t
time_not_ok(struct timeval *t)
{
	return (t->tv_sec < -1 || t->tv_sec > 100000000 ||
		t->tv_usec < -1 || t->tv_usec > 1000000);
}

static struct callinfo *
alloc_callinfo(struct cu_data *cu, uint_t flags)
{
	register struct callinfo *ci;

	/*
	 *	Memory is arranged as:
	 *
	 *	------------------------------------
	 *	| callinfo structure | send buffer |
	 *	------------------------------------
	 *
	 *	with the receive buffer allocated via t_alloc()
	 */
	ci = (struct callinfo *)malloc(sizeof (*ci) + cu->cu_sendsz);
	if (ci == (struct callinfo *)NULL)
		return ((struct callinfo *)NULL);
	ci->ci_trdata = (struct t_unitdata *)NULL;
	ci->ci_outbuf = ((char *)ci) + sizeof (*ci);

	ci->ci_flags = flags;
	ci->ci_cu = cu;
	if (cu->cu_calls != (struct callinfo *)0) {
		ci->ci_next = cu->cu_calls;
		cu->cu_calls = ci;
	} else {
		ci->ci_next = (struct callinfo *)0;
		cu->cu_calls = ci;
	}

	return (ci);
}

static void
free_callinfo(struct callinfo *ci)
{
	(void) free((char *)ci);
}

static struct callinfo	*
find_callinfo(struct cu_data *cu, uint_t flags)
{
	register struct callinfo	*ci;

	for (ci = cu->cu_calls; ci; ci = ci->ci_next)
		if (ci->ci_flags & flags)
			return (ci);

	return ((struct callinfo *)0);
}

static void
dequeue_callinfo(struct cu_data *cu, struct callinfo *targetci)
{
	register struct callinfo *ci, *prevci = (struct callinfo *)0;

	for (ci = cu->cu_calls; ci; ci = ci->ci_next) {
		if (ci == targetci)
			if (cu->cu_calls == ci)
				cu->cu_calls = ci->ci_next;
			else {
				assert(prevci != (struct callinfo *)0);
				prevci->ci_next = ci->ci_next;
			}
		prevci = ci;
	}
}
static void
rac_dg_drop(CLIENT *cl, struct callinfo *h)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register struct callinfo *ci, *prevci;

	for (ci = cu->cu_calls, prevci = (struct callinfo *)NULL;
		ci; ci = ci->ci_next)
		if (ci == h && (ci->ci_flags & CI_ASYNC)) {
			if (cu->cu_calls == ci)
				cu->cu_calls = ci->ci_next;
			else {
				assert(prevci != (struct callinfo *)NULL);
				prevci->ci_next = ci->ci_next;
			}
			if (ci->ci_trdata)
				(void) t_free((char *)ci->ci_trdata,
								T_UNITDATA);
			XDR_DESTROY(&(ci->ci_outxdrs));
			free_callinfo(ci);
			return;
		} else
			prevci = ci;
}

static enum clnt_stat
rac_dg_poll(CLIENT *cl, struct callinfo *h)
{
	register struct cu_data	*cu;
	struct pollfd pfdp;
	struct timeval now, delta1, delta2;
	int polltimeout = 0;
	struct t_unitdata	*tmp_trdata = (struct t_unitdata *)NULL;
	struct callinfo *ci;
	uint32_t pktxid;
	int res;		/* result of operations */

#ifdef	PRINTFS
	printf("rac_dg_poll(0x%p, 0x%p)\n", cl, h);
#endif
	if (rachandle_is_valid(cl, h))
		cu = h->ci_cu;
	else
		return (RPC_STALERACHANDLE);
	assert(cl);
	assert(h);
	assert(cu);
	assert(cu->cu_fd >= 0);

	/*
	 *	If a packet's already been received (possibly by someone else
	 *	doing a poll), return success immediately.
	 */
	if (h->ci_trdata != (struct t_unitdata *)NULL) {
#ifdef	PRINTFS
		printf("rac_dg_poll:  packet waiting for handle %p\n", h);
#endif
		return (RPC_SUCCESS);
	}

	pfdp.fd = cu->cu_fd;
	pfdp.events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
	pfdp.revents = 0;

	switch (poll(&pfdp, 1, polltimeout)) {
	case 0:
		/*
		 *	Compute the time difference between now and the time
		 *	we last called clnt_dg_send().
		 */
		(void) gettimeofday(&now, (struct timezone *)0);
		delta1.tv_sec = now.tv_sec - h->ci_sendtime.tv_sec;
		delta1.tv_usec = now.tv_usec - h->ci_sendtime.tv_usec;
		if (delta1.tv_usec < 0) {
			delta1.tv_sec--;	/* need to ``borrow'' */
			delta1.tv_usec += 1000000;
		}
		/*
		 *	``Delta1'' is the time we've waited since the last call
		 *	to clnt_dg_send();  ``h->ci_timewaited'' contains the
		 *	cumulative wait from the first send to the most recent.
		 *
		 *	``Delta2'' will contain the total waiting time.  If it
		 *	exceeds the total call timeout, give up.
		 */
		delta2.tv_sec = delta1.tv_sec + h->ci_timewaited.tv_sec;
		delta2.tv_usec = delta1.tv_usec + h->ci_timewaited.tv_usec;
		while (delta2.tv_usec >= 1000000) {
			delta2.tv_sec++;
			delta2.tv_usec -= 1000000;
		}
		if (timercmp(&delta2, &h->ci_calltimeout, > /* */)) {
			rac_dg_drop(cl, h);
			return (RPC_TIMEDOUT);
		}

		/*
		 *	Nothing there for us, but the call hasn't timed out.
		 *	If ``delta1'' is greater than the retransmit timeout,
		 *	retransmit the packet for the user and recompute the
		 *	retransmit time.
		 */
		if (timercmp(&delta1, &h->ci_rexmittime, > /* */)) {
			h->ci_sendtime = now;	/* lie by a few microseconds */
			h->ci_timewaited = delta1;
			/* remember time waited so far */
#ifdef	PRINTFS
			if (clnt_dg_send(h) != RPC_SUCCESS)
	printf("rac_dg_poll:  clnt_dg_send failed\n");
			else
	printf("rac_dg_poll:  clnt_dg_send succeeded\n");
#else
			(void) clnt_dg_send(h);
#endif
			if (h->ci_rexmittime.tv_sec < RPC_MAX_BACKOFF) {
				h->ci_rexmittime.tv_usec *= 2;
				h->ci_rexmittime.tv_sec *= 2;
				while (h->ci_rexmittime.tv_usec >= 1000000) {
					h->ci_rexmittime.tv_sec++;
					h->ci_rexmittime.tv_usec -= 1000000;
				}
			}
		}
		return (RPC_INPROGRESS);

	case -1:
		if (errno == EFAULT || errno == EINVAL) {
			h->ci_error.re_errno = errno;
			h->ci_error.re_terrno = t_errno;
			h->ci_error.re_status = RPC_CANTRECV;
			return (h->ci_error.re_status = RPC_CANTRECV);
		} else {
			errno = 0;	/* reset it */
			return (RPC_INPROGRESS);
		}
		/* NOTREACHED */
	}

	/*
	 *	poll says we have a packet.  Receive it.  If it`s for us,
	 *	great!  If it's for some other customer of this CLIENT handle,
	 *	figure out who and hang the packet off his callinfo structure.
	 */

	if (pfdp.revents == 0 || pfdp.revents & POLLNVAL) {
		/*
		 *	Note:  we're faking errno here because we
		 *	previously would have expected select() to
		 *	return -1 with errno EBADF.  Poll(BA_OS)
		 *	returns 0 and sets the POLLNVAL revents flag
		 *	instead.
		 */
		h->ci_error.re_errno = errno = EBADF;
		return (h->ci_error.re_status = RPC_CANTRECV);
	}

	tmp_trdata = (struct t_unitdata *)t_alloc(cu->cu_fd, T_UNITDATA, T_ALL);
	if (tmp_trdata == (struct t_unitdata *)NULL) {
		h->ci_error.re_errno = errno;
		h->ci_error.re_terrno = t_errno;
		return (h->ci_error.re_status = RPC_SYSTEMERROR);
	}

	do {
		int moreflag;	/* flag indicating more data */

		moreflag = 0;
		if (errno == EINTR) {
			/*
			 * Must make sure errno was not already
			 * EINTR in case t_rcvudata() returns -1.
			 * This way will only stay in the loop
			 * if getmsg() sets errno to EINTR.
			 */
			errno = 0;
		}
		res = t_rcvudata(cu->cu_fd, tmp_trdata, &moreflag);
		if ((moreflag & T_MORE) ||
		    (tmp_trdata->udata.len > cu->cu_recvsz)) {
#ifdef	PRINTFS
	printf("rac_dg_poll:  moreflag %d, udata.len %d, recvsz %d\n",
		moreflag, tmp_trdata->udata.len, cu->cu_recvsz);
#endif
			/*
			 * Drop this packet. I ain't got any
			 * more space.
			 */
			res = -1;
			/* I should not really be doing this */
			errno = 0;
			/*
			 * XXX: Not really Buffer overflow in the
			 * sense of TLI.
			 */
			t_errno = TBUFOVFLW;
		}
	} while (res < 0 && (t_errno == TSYSERR && errno == EINTR));
	if (res < 0) {
#ifdef sun
		if (t_errno == TSYSERR && errno == EWOULDBLOCK)
#else
		if (t_errno == TSYSERR && errno == EAGAIN)
#endif
			return (RPC_INPROGRESS);
		if (t_errno == TLOOK) {
			int old;

			old = t_errno;
			if (t_rcvuderr(cu->cu_fd, (struct t_uderr *)NULL) == 0)
				return (RPC_INPROGRESS);
			else
				h->ci_error.re_terrno = old;
		} else {
			h->ci_error.re_terrno = t_errno;
		}
		(void) t_free((char *)tmp_trdata, T_UNITDATA);

		h->ci_error.re_errno = errno;
		return (h->ci_error.re_status = RPC_CANTRECV);
	}
	if (tmp_trdata->udata.len < sizeof (uint32_t)) {
		(void) t_free((char *)tmp_trdata, T_UNITDATA);
		return (RPC_INPROGRESS);
	}
	/*
	 *	If the returned XID happens to match ours, we're in luck.
	 *	If not, we have to search for an in-progress call to which
	 *	the reply should be attached.
	 */
	pktxid = ntohl(*(uint32_t *)(tmp_trdata->udata.buf));
	if (pktxid == h->ci_xid) {
		assert(h->ci_trdata == (struct t_unitdata *)NULL);
#ifdef	PRINTFS
		printf("rac_dg_poll:  xid match\n");
#endif
		h->ci_trdata = tmp_trdata;
		return (RPC_SUCCESS);
	} else {
#ifdef	PRINTFS
	printf("rac_dg_poll:  pktxid (%x) != ci_xid (%x)\n",
		pktxid, h->ci_xid);
#endif
		ci = xid_to_callinfo(cu, pktxid);
		/* don't overwrite a previous reply */
		if (ci && ci->ci_trdata == (struct t_unitdata *)NULL) {
#ifdef	PRINTFS
	printf("rac_dg_poll:  found owner of xid %d:  handle %p\n",
		pktxid, ci);
#endif
			ci->ci_trdata = tmp_trdata;
		} else
			/* no owner found or reply already present - drop it */
			(void) t_free((char *)tmp_trdata, T_UNITDATA);
		return (RPC_INPROGRESS);
	}
	/* NOTREACHED */
}

static enum clnt_stat
rac_dg_recv(CLIENT *cl, struct callinfo *h)
{
	if (!rachandle_is_valid(cl, h))
		return (RPC_STALERACHANDLE);

	/*
	 *	If a packet has been received (indicated by a non-NULL
	 *	ci_trdata field), XDR it.  Otherwise, we act just like
	 *	normal, blocking, RPC.
	 */
	if (h->ci_trdata != (struct t_unitdata *)NULL) {
		switch (clnt_dg_xdrin(cl, h, CI_ASYNC)) {
		case (int)XS_CALLAGAIN:
#ifdef	PRINTFS
	printf("rac_dg_recv:  clnt_dg_xdrin returned CALL_AGAIN\n");
#endif
			rac_dg_drop(cl, h);
			return (RPC_AUTHERROR);
		case (int)XS_ERROR:
		case (int)XS_OK:
		default:
#ifdef	PRINTFS
	printf("rac_dg_recv:  clnt_dg_xdrin returned %d\n",
		h->ci_error.re_status);
#endif
			rac_dg_drop(cl, h);
			return (h->ci_error.re_status);
		}
		/* NOTREACHED */
	} else {
	receive_again:
		switch ((int)clnt_dg_receive(h, CI_ASYNC)) {
		case (int)RS_RESEND:
#ifdef	PRINTFS
	printf("rac_dg_recv:  clnt_dg_receive returned RS_RESEND\n");
#endif
			goto send_again;
			/* NOTREACHED */

		case (int)RS_ERROR:
#ifdef	PRINTFS
	printf("rac_dg_recv:  clnt_dg_receive returned error %d\n",
		h->ci_error.re_status);
#endif
			rac_dg_drop(cl, h);
			return (h->ci_error.re_status);
			/* NOTREACHED */

		case (int)RS_OK:
#ifdef	PRINTFS
	printf("rac_dg_recv:  clnt_dg_receive returned OK\n");
#endif
			break;
		}

		switch (clnt_dg_xdrin(cl, h, CI_ASYNC)) {
		case (int)XS_CALLAGAIN:
#ifdef	PRINTFS
	printf("rac_dg_recv:  clnt_dg_xdrin returned CALL_AGAIN\n");
#endif
			break;

		case (int)XS_ERROR:
		case (int)XS_OK:
#ifdef	PRINTFS
			printf("rac_dg_recv:  clnt_dg_xdrin returned %d\n",
				h->ci_error.re_status);
#endif
			rac_dg_drop(cl, h);
			return (h->ci_error.re_status);
		}

#ifdef	PRINTFS
		printf("rac_dg_recv:  call_again\n");
#endif
		if (clnt_dg_marshall(cl, h) != RPC_SUCCESS) {
			rac_dg_drop(cl, h);
			return (h->ci_error.re_status);
		}
#ifdef	PRINTFS
		else
			printf("rac_dg_recv:  clnt_dg_marshall succeeded\n");
#endif

	send_again:
		if (clnt_dg_send(h) != RPC_SUCCESS) {
			rac_dg_drop(cl, h);
			return (h->ci_error.re_status);
		}
#ifdef	PRINTFS
		else
			printf("rac_dg_recv:  clnt_dg_send succeeded\n");
#endif

		goto receive_again;
	}
	/* NOTREACHED */
}

static void *
rac_dg_send(CLIENT *cl, struct rac_send_req *h)
{
	register struct cu_data *cu = (struct cu_data *)cl->cl_private;
	register struct callinfo *ci;

	if ((ci = alloc_callinfo(cu, CI_ASYNC)) == (struct callinfo *)NULL) {
		rac_senderr.re_status = RPC_SYSTEMERROR;
		return ((void *)NULL);
	}
	ci->ci_nrefreshes = 2;	/* number of times to refresh cred */
	ci->ci_proc = h->proc;
	ci->ci_xargs = h->xargs;
	ci->ci_argsp = (caddr_t)h->argsp;
	ci->ci_xresults = h->xresults;
	ci->ci_resultsp = (caddr_t)h->resultsp;
	xdrmem_create(&(ci->ci_outxdrs), ci->ci_outbuf,
		cu->cu_sendsz, XDR_ENCODE);

	ci->ci_xid = ++cu->cu_xidseed;
	ci->ci_calltimeout = h->timeout;
	ci->ci_trdata = NULL;

	timerclear(&ci->ci_timewaited);
	ci->ci_rexmittime = cu->cu_wait;

	if (clnt_dg_marshall(cl, ci) != RPC_SUCCESS)
		return ((void *)NULL);

#ifdef	PRINTFS
	printf("rac_dg_send:  calling clnt_dg_send\n");
#endif
	(void) gettimeofday(&ci->ci_sendtime, (struct timezone *)0);
	if (clnt_dg_send(ci) != RPC_SUCCESS) {
		dequeue_callinfo(cu, ci);
		free_callinfo(ci);
		return ((void *)NULL);
	}
#ifdef	PRINTFS
	else
		printf("rac_dg_send:  clnt_dg_send succeeded 0x%p\n", ci);
#endif

	return ((void *)ci);
}

static bool_t
rachandle_is_valid(CLIENT *cl, struct callinfo *h)
{
	register struct callinfo *ci;

	for (ci = ((struct cu_data *)cl->cl_private)->cu_calls;
		ci; ci = ci->ci_next) {
		if (ci == h && (ci->ci_flags & CI_ASYNC))
			return (TRUE);
	}
	return (FALSE);
}

static struct callinfo *
xid_to_callinfo(struct cu_data *cu, uint32_t xid)
{
	register struct callinfo *ci;

	for (ci = cu->cu_calls; ci; ci = ci->ci_next)
		if (xid == ci->ci_xid)
			return (ci);

	return ((struct callinfo *)NULL);
}

static int
netbuf_copy(struct netbuf *from, struct netbuf *to, int type)
{

	if (!from)
		return (0);

	if (type != T_DATA) {
		if (to->maxlen < from->len)
			return (0);
		to->len = from->len;
	} else { /* for T_DATA, also allocate memory */
		to->buf = malloc(from->len);
		to->len = from->len;
		to->maxlen = from->len;
	}

	if (!to->buf)
		return (0);

	(void) memcpy(to->buf, from->buf, from->len);
	return (1);
}
