/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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


#include "mt.h"
#include "rpc_mt.h"
#include <assert.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <sys/mkdev.h>
#include <sys/poll.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <limits.h>

#define	MCALL_MSG_SIZE 24
#define	SECS_TO_NS(x)	((hrtime_t)(x) * 1000 * 1000 * 1000)
#define	MSECS_TO_NS(x)	((hrtime_t)(x) * 1000 * 1000)
#define	USECS_TO_NS(x)	((hrtime_t)(x) * 1000)
#define	NSECS_TO_MS(x)	((x) / 1000 / 1000)
#ifndef MIN
#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif

extern int __rpc_timeval_to_msec(struct timeval *);
extern int __rpc_compress_pollfd(int, pollfd_t *, pollfd_t *);
extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
extern bool_t __rpc_gss_wrap(AUTH *, char *, uint_t, XDR *, bool_t (*)(),
								caddr_t);
extern bool_t __rpc_gss_unwrap(AUTH *, XDR *, bool_t (*)(), caddr_t);
extern CLIENT *_clnt_vc_create_timed(int, struct netbuf *, rpcprog_t,
		rpcvers_t, uint_t, uint_t, const struct timeval *);

static struct clnt_ops	*clnt_vc_ops(void);
static int		read_vc(void *, caddr_t, int);
static int		write_vc(void *, caddr_t, int);
static int		t_rcvall(int, char *, int);
static bool_t		time_not_ok(struct timeval *);

struct ct_data;
static bool_t		set_up_connection(int, struct netbuf *,
				struct ct_data *, const struct timeval *);
static bool_t		set_io_mode(struct ct_data *, int);

/*
 * Lock table handle used by various MT sync. routines
 */
static mutex_t	vctbl_lock = DEFAULTMUTEX;
static void	*vctbl = NULL;

static const char clnt_vc_errstr[] = "%s : %s";
static const char clnt_vc_str[] = "clnt_vc_create";
static const char clnt_read_vc_str[] = "read_vc";
static const char __no_mem_str[] = "out of memory";
static const char no_fcntl_getfl_str[] = "could not get status flags and modes";
static const char no_nonblock_str[] = "could not set transport blocking mode";

/*
 * Private data structure
 */
struct ct_data {
	int		ct_fd;		/* connection's fd */
	bool_t		ct_closeit;	/* close it on destroy */
	int		ct_tsdu;	/* size of tsdu */
	int		ct_wait;	/* wait interval in milliseconds */
	bool_t		ct_waitset;	/* wait set by clnt_control? */
	struct netbuf	ct_addr;	/* remote addr */
	struct rpc_err	ct_error;
	char		ct_mcall[MCALL_MSG_SIZE]; /* marshalled callmsg */
	uint_t		ct_mpos;	/* pos after marshal */
	XDR		ct_xdrs;	/* XDR stream */

	/* NON STANDARD INFO - 00-08-31 */
	bool_t		ct_is_oneway; /* True if the current call is oneway. */
	bool_t		ct_is_blocking;
	ushort_t	ct_io_mode;
	ushort_t	ct_blocking_mode;
	uint_t		ct_bufferSize; /* Total size of the buffer. */
	uint_t		ct_bufferPendingSize; /* Size of unsent data. */
	char 		*ct_buffer; /* Pointer to the buffer. */
	char 		*ct_bufferWritePtr; /* Ptr to the first free byte. */
	char 		*ct_bufferReadPtr; /* Ptr to the first byte of data. */
};

struct nb_reg_node {
	struct nb_reg_node *next;
	struct ct_data *ct;
};

static struct nb_reg_node *nb_first = (struct nb_reg_node *)&nb_first;
static struct nb_reg_node *nb_free  = (struct nb_reg_node *)&nb_free;

static bool_t exit_handler_set = FALSE;

static mutex_t nb_list_mutex = DEFAULTMUTEX;


/* Define some macros to manage the linked list. */
#define	LIST_ISEMPTY(l) (l == (struct nb_reg_node *)&l)
#define	LIST_CLR(l) (l = (struct nb_reg_node *)&l)
#define	LIST_ADD(l, node) (node->next = l->next, l = node)
#define	LIST_EXTRACT(l, node) (node = l, l = l->next)
#define	LIST_FOR_EACH(l, node) \
	for (node = l; node != (struct nb_reg_node *)&l; node = node->next)


/* Default size of the IO buffer used in non blocking mode */
#define	DEFAULT_PENDING_ZONE_MAX_SIZE (16*1024)

static int nb_send(struct ct_data *, void *, unsigned int);
static int do_flush(struct ct_data *, uint_t);
static bool_t set_flush_mode(struct ct_data *, int);
static bool_t set_blocking_connection(struct ct_data *, bool_t);

static int register_nb(struct ct_data *);
static int unregister_nb(struct ct_data *);


/*
 * Change the mode of the underlying fd.
 */
static bool_t
set_blocking_connection(struct ct_data *ct, bool_t blocking)
{
	int flag;

	/*
	 * If the underlying fd is already in the required mode,
	 * avoid the syscall.
	 */
	if (ct->ct_is_blocking == blocking)
		return (TRUE);

	if ((flag = fcntl(ct->ct_fd, F_GETFL, 0)) < 0) {
		(void) syslog(LOG_ERR, "set_blocking_connection : %s",
		    no_fcntl_getfl_str);
		return (FALSE);
	}

	flag = blocking? flag&~O_NONBLOCK : flag|O_NONBLOCK;
	if (fcntl(ct->ct_fd, F_SETFL, flag) != 0) {
		(void) syslog(LOG_ERR, "set_blocking_connection : %s",
		    no_nonblock_str);
		return (FALSE);
	}
	ct->ct_is_blocking = blocking;
	return (TRUE);
}

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
	return (_clnt_vc_create_timed(fd, svcaddr, prog, vers, sendsz,
	    recvsz, NULL));
}

/*
 * This has the same definition as clnt_vc_create(), except it
 * takes an additional parameter - a pointer to a timeval structure.
 *
 * Not a public interface. This is for clnt_create_timed,
 * clnt_create_vers_timed, clnt_tp_create_timed to pass down the timeout
 * value to control a tcp connection attempt.
 * (for bug 4049792: clnt_create_timed does not time out)
 *
 * If tp is NULL, use default timeout to set up the connection.
 */
CLIENT *
_clnt_vc_create_timed(int fd, struct netbuf *svcaddr, rpcprog_t prog,
	rpcvers_t vers, uint_t sendsz, uint_t recvsz, const struct timeval *tp)
{
	CLIENT *cl;			/* client handle */
	struct ct_data *ct;		/* private data */
	struct timeval now;
	struct rpc_msg call_msg;
	struct t_info tinfo;
	int flag;

	cl = malloc(sizeof (*cl));
	if ((ct = malloc(sizeof (*ct))) != NULL)
		ct->ct_addr.buf = NULL;

	if ((cl == NULL) || (ct == NULL)) {
		(void) syslog(LOG_ERR, clnt_vc_errstr,
		    clnt_vc_str, __no_mem_str);
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		rpc_createerr.cf_error.re_terrno = 0;
		goto err;
	}

	/*
	 * The only use of vctbl_lock is for serializing the creation of
	 * vctbl. Once created the lock needs to be released so we don't
	 * hold it across the set_up_connection() call and end up with a
	 * bunch of threads stuck waiting for the mutex.
	 */
	sig_mutex_lock(&vctbl_lock);

	if ((vctbl == NULL) && ((vctbl = rpc_fd_init()) == NULL)) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_errno = errno;
		rpc_createerr.cf_error.re_terrno = 0;
		sig_mutex_unlock(&vctbl_lock);
		goto err;
	}

	sig_mutex_unlock(&vctbl_lock);

	ct->ct_io_mode = RPC_CL_BLOCKING;
	ct->ct_blocking_mode = RPC_CL_BLOCKING_FLUSH;

	ct->ct_buffer = NULL;	/* We allocate the buffer when needed. */
	ct->ct_bufferSize = DEFAULT_PENDING_ZONE_MAX_SIZE;
	ct->ct_bufferPendingSize = 0;
	ct->ct_bufferWritePtr = NULL;
	ct->ct_bufferReadPtr = NULL;

	/* Check the current state of the fd. */
	if ((flag = fcntl(fd, F_GETFL, 0)) < 0) {
		(void) syslog(LOG_ERR, "_clnt_vc_create_timed : %s",
		    no_fcntl_getfl_str);
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_terrno = errno;
		rpc_createerr.cf_error.re_errno = 0;
		goto err;
	}
	ct->ct_is_blocking = flag & O_NONBLOCK ? FALSE : TRUE;

	if (set_up_connection(fd, svcaddr, ct, tp) == FALSE) {
		goto err;
	}

	/*
	 * Set up other members of private data struct
	 */
	ct->ct_fd = fd;
	/*
	 * The actual value will be set by clnt_call or clnt_control
	 */
	ct->ct_wait = 30000;
	ct->ct_waitset = FALSE;
	/*
	 * By default, closeit is always FALSE. It is users responsibility
	 * to do a t_close on it, else the user may use clnt_control
	 * to let clnt_destroy do it for them.
	 */
	ct->ct_closeit = FALSE;

	/*
	 * Initialize call message
	 */
	(void) gettimeofday(&now, (struct timezone *)0);
	call_msg.rm_xid = getpid() ^ now.tv_sec ^ now.tv_usec;
	call_msg.rm_call.cb_prog = prog;
	call_msg.rm_call.cb_vers = vers;

	/*
	 * pre-serialize the static part of the call msg and stash it away
	 */
	xdrmem_create(&(ct->ct_xdrs), ct->ct_mcall, MCALL_MSG_SIZE, XDR_ENCODE);
	if (!xdr_callhdr(&(ct->ct_xdrs), &call_msg)) {
		goto err;
	}
	ct->ct_mpos = XDR_GETPOS(&(ct->ct_xdrs));
	XDR_DESTROY(&(ct->ct_xdrs));

	if (t_getinfo(fd, &tinfo) == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		rpc_createerr.cf_error.re_terrno = t_errno;
		rpc_createerr.cf_error.re_errno = 0;
		goto err;
	}
	/*
	 * Find the receive and the send size
	 */
	sendsz = __rpc_get_t_size((int)sendsz, tinfo.tsdu);
	recvsz = __rpc_get_t_size((int)recvsz, tinfo.tsdu);
	if ((sendsz == 0) || (recvsz == 0)) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		rpc_createerr.cf_error.re_terrno = 0;
		rpc_createerr.cf_error.re_errno = 0;
		goto err;
	}
	ct->ct_tsdu = tinfo.tsdu;
	/*
	 * Create a client handle which uses xdrrec for serialization
	 * and authnone for authentication.
	 */
	ct->ct_xdrs.x_ops = NULL;
	xdrrec_create(&(ct->ct_xdrs), sendsz, recvsz, (caddr_t)ct,
	    read_vc, write_vc);
	if (ct->ct_xdrs.x_ops == NULL) {
		rpc_createerr.cf_stat = RPC_SYSTEMERROR;
		rpc_createerr.cf_error.re_terrno = 0;
		rpc_createerr.cf_error.re_errno = ENOMEM;
		goto err;
	}
	cl->cl_ops = clnt_vc_ops();
	cl->cl_private = (caddr_t)ct;
	cl->cl_auth = authnone_create();
	cl->cl_tp = NULL;
	cl->cl_netid = NULL;
	return (cl);

err:
	if (ct) {
		free(ct->ct_addr.buf);
		free(ct);
	}
	free(cl);

	return (NULL);
}

#define	TCPOPT_BUFSIZE 128

/*
 * Set tcp connection timeout value.
 * Retun 0 for success, -1 for failure.
 */
static int
_set_tcp_conntime(int fd, int optval)
{
	struct t_optmgmt req, res;
	struct opthdr *opt;
	int *ip;
	char buf[TCPOPT_BUFSIZE];

	/* LINTED pointer cast */
	opt = (struct opthdr *)buf;
	opt->level =  IPPROTO_TCP;
	opt->name = TCP_CONN_ABORT_THRESHOLD;
	opt->len = sizeof (int);

	req.flags = T_NEGOTIATE;
	req.opt.len = sizeof (struct opthdr) + opt->len;
	req.opt.buf = (char *)opt;
	/* LINTED pointer cast */
	ip = (int *)((char *)buf + sizeof (struct opthdr));
	*ip = optval;

	res.flags = 0;
	res.opt.buf = (char *)buf;
	res.opt.maxlen = sizeof (buf);
	if (t_optmgmt(fd, &req, &res) < 0 || res.flags != T_SUCCESS) {
		return (-1);
	}
	return (0);
}

/*
 * Get current tcp connection timeout value.
 * Retun the timeout in milliseconds, or -1 for failure.
 */
static int
_get_tcp_conntime(int fd)
{
	struct t_optmgmt req, res;
	struct opthdr *opt;
	int *ip, retval;
	char buf[TCPOPT_BUFSIZE];

	/* LINTED pointer cast */
	opt = (struct opthdr *)buf;
	opt->level =  IPPROTO_TCP;
	opt->name = TCP_CONN_ABORT_THRESHOLD;
	opt->len = sizeof (int);

	req.flags = T_CURRENT;
	req.opt.len = sizeof (struct opthdr) + opt->len;
	req.opt.buf = (char *)opt;
	/* LINTED pointer cast */
	ip = (int *)((char *)buf + sizeof (struct opthdr));
	*ip = 0;

	res.flags = 0;
	res.opt.buf = (char *)buf;
	res.opt.maxlen = sizeof (buf);
	if (t_optmgmt(fd, &req, &res) < 0 || res.flags != T_SUCCESS) {
		return (-1);
	}

	/* LINTED pointer cast */
	ip = (int *)((char *)buf + sizeof (struct opthdr));
	retval = *ip;
	return (retval);
}

static bool_t
set_up_connection(int fd, struct netbuf *svcaddr, struct ct_data *ct,
    const struct timeval *tp)
{
	int state;
	struct t_call sndcallstr, *rcvcall;
	int nconnect;
	bool_t connected, do_rcv_connect;
	int curr_time = -1;
	hrtime_t start;
	hrtime_t tout;	/* timeout in nanoseconds (from tp) */

	ct->ct_addr.len = 0;
	state = t_getstate(fd);
	if (state == -1) {
		rpc_createerr.cf_stat = RPC_TLIERROR;
		rpc_createerr.cf_error.re_errno = 0;
		rpc_createerr.cf_error.re_terrno = t_errno;
		return (FALSE);
	}

	switch (state) {
	case T_IDLE:
		if (svcaddr == NULL) {
			rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
			return (FALSE);
		}
		/*
		 * Connect only if state is IDLE and svcaddr known
		 */
/* LINTED pointer alignment */
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
		connected = FALSE;
		do_rcv_connect = FALSE;

		/*
		 * If there is a timeout value specified, we will try to
		 * reset the tcp connection timeout. If the transport does
		 * not support the TCP_CONN_ABORT_THRESHOLD option or fails
		 * for other reason, default timeout will be used.
		 */
		if (tp != NULL) {
			start = gethrtime();

			/*
			 * Calculate the timeout in nanoseconds
			 */
			tout = SECS_TO_NS(tp->tv_sec) +
			    USECS_TO_NS(tp->tv_usec);
			curr_time = _get_tcp_conntime(fd);
		}

		for (nconnect = 0; nconnect < 3; nconnect++) {
			if (tp != NULL) {
				/*
				 * Calculate the elapsed time
				 */
				hrtime_t elapsed = gethrtime() - start;
				if (elapsed >= tout)
					break;

				if (curr_time != -1) {
					int ms;

					/*
					 * TCP_CONN_ABORT_THRESHOLD takes int
					 * value in milliseconds.  Make sure we
					 * do not overflow.
					 */
					if (NSECS_TO_MS(tout - elapsed) >=
					    INT_MAX) {
						ms = INT_MAX;
					} else {
						ms = (int)
						    NSECS_TO_MS(tout - elapsed);
						if (MSECS_TO_NS(ms) !=
						    tout - elapsed)
							ms++;
					}

					(void) _set_tcp_conntime(fd, ms);
				}
			}

			if (t_connect(fd, &sndcallstr, rcvcall) != -1) {
				connected = TRUE;
				break;
			}
			if (t_errno == TLOOK) {
				switch (t_look(fd)) {
				case T_DISCONNECT:
					(void) t_rcvdis(fd, (struct
					    t_discon *) NULL);
					break;
				default:
					break;
				}
			} else if (!(t_errno == TSYSERR && errno == EINTR)) {
				break;
			}
			if ((state = t_getstate(fd)) == T_OUTCON) {
				do_rcv_connect = TRUE;
				break;
			}
			if (state != T_IDLE) {
				break;
			}
		}
		if (do_rcv_connect) {
			do {
				if (t_rcvconnect(fd, rcvcall) != -1) {
					connected = TRUE;
					break;
				}
			} while (t_errno == TSYSERR && errno == EINTR);
		}

		/*
		 * Set the connection timeout back to its old value.
		 */
		if (curr_time != -1) {
			(void) _set_tcp_conntime(fd, curr_time);
		}

		if (!connected) {
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_terrno = t_errno;
			rpc_createerr.cf_error.re_errno = errno;
			(void) t_free((char *)rcvcall, T_CALL);
			return (FALSE);
		}

		/* Free old area if allocated */
		if (ct->ct_addr.buf)
			free(ct->ct_addr.buf);
		ct->ct_addr = rcvcall->addr;	/* To get the new address */
		/* So that address buf does not get freed */
		rcvcall->addr.buf = NULL;
		(void) t_free((char *)rcvcall, T_CALL);
		break;
	case T_DATAXFER:
	case T_OUTCON:
		if (svcaddr == NULL) {
			/*
			 * svcaddr could also be NULL in cases where the
			 * client is already bound and connected.
			 */
			ct->ct_addr.len = 0;
		} else {
			ct->ct_addr.buf = malloc(svcaddr->len);
			if (ct->ct_addr.buf == NULL) {
				(void) syslog(LOG_ERR, clnt_vc_errstr,
				    clnt_vc_str, __no_mem_str);
				rpc_createerr.cf_stat = RPC_SYSTEMERROR;
				rpc_createerr.cf_error.re_errno = errno;
				rpc_createerr.cf_error.re_terrno = 0;
				return (FALSE);
			}
			(void) memcpy(ct->ct_addr.buf, svcaddr->buf,
			    (size_t)svcaddr->len);
			ct->ct_addr.len = ct->ct_addr.maxlen = svcaddr->len;
		}
		break;
	default:
		rpc_createerr.cf_stat = RPC_UNKNOWNADDR;
		return (FALSE);
	}
	return (TRUE);
}

static enum clnt_stat
clnt_vc_call(CLIENT *cl, rpcproc_t proc, xdrproc_t xdr_args, caddr_t args_ptr,
	xdrproc_t xdr_results, caddr_t results_ptr, struct timeval timeout)
{
/* LINTED pointer alignment */
	struct ct_data *ct = (struct ct_data *)cl->cl_private;
	XDR *xdrs = &(ct->ct_xdrs);
	struct rpc_msg reply_msg;
	uint32_t x_id;
/* LINTED pointer alignment */
	uint32_t *msg_x_id = (uint32_t *)(ct->ct_mcall);	/* yuk */
	bool_t shipnow;
	int refreshes = 2;

	if (rpc_fd_lock(vctbl, ct->ct_fd)) {
		rpc_callerr.re_status = RPC_FAILED;
		rpc_callerr.re_errno = errno;
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (RPC_FAILED);
	}

	ct->ct_is_oneway = FALSE;
	if (ct->ct_io_mode == RPC_CL_NONBLOCKING) {
		if (do_flush(ct, RPC_CL_BLOCKING_FLUSH) != 0) {
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (RPC_FAILED);  /* XXX */
		}
	}

	if (!ct->ct_waitset) {
		/* If time is not within limits, we ignore it. */
		if (time_not_ok(&timeout) == FALSE)
			ct->ct_wait = __rpc_timeval_to_msec(&timeout);
	} else {
		timeout.tv_sec = (ct->ct_wait / 1000);
		timeout.tv_usec = (ct->ct_wait % 1000) * 1000;
	}

	shipnow = ((xdr_results == (xdrproc_t)0) && (timeout.tv_sec == 0) &&
	    (timeout.tv_usec == 0)) ? FALSE : TRUE;
call_again:
	xdrs->x_op = XDR_ENCODE;
	rpc_callerr.re_status = RPC_SUCCESS;
	/*
	 * Due to little endian byte order, it is necessary to convert to host
	 * format before decrementing xid.
	 */
	x_id = ntohl(*msg_x_id) - 1;
	*msg_x_id = htonl(x_id);

	if (cl->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
		if ((!XDR_PUTBYTES(xdrs, ct->ct_mcall, ct->ct_mpos)) ||
		    (!XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
		    (!AUTH_MARSHALL(cl->cl_auth, xdrs)) ||
		    (!xdr_args(xdrs, args_ptr))) {
			if (rpc_callerr.re_status == RPC_SUCCESS)
				rpc_callerr.re_status = RPC_CANTENCODEARGS;
			(void) xdrrec_endofrecord(xdrs, TRUE);
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (rpc_callerr.re_status);
		}
	} else {
/* LINTED pointer alignment */
		uint32_t *u = (uint32_t *)&ct->ct_mcall[ct->ct_mpos];
		IXDR_PUT_U_INT32(u, proc);
		if (!__rpc_gss_wrap(cl->cl_auth, ct->ct_mcall,
		    ((char *)u) - ct->ct_mcall, xdrs, xdr_args, args_ptr)) {
			if (rpc_callerr.re_status == RPC_SUCCESS)
				rpc_callerr.re_status = RPC_CANTENCODEARGS;
			(void) xdrrec_endofrecord(xdrs, TRUE);
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (rpc_callerr.re_status);
		}
	}
	if (!xdrrec_endofrecord(xdrs, shipnow)) {
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (rpc_callerr.re_status = RPC_CANTSEND);
	}
	if (!shipnow) {
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (RPC_SUCCESS);
	}
	/*
	 * Hack to provide rpc-based message passing
	 */
	if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (rpc_callerr.re_status = RPC_TIMEDOUT);
	}


	/*
	 * Keep receiving until we get a valid transaction id
	 */
	xdrs->x_op = XDR_DECODE;
	for (;;) {
		reply_msg.acpted_rply.ar_verf = _null_auth;
		reply_msg.acpted_rply.ar_results.where = NULL;
		reply_msg.acpted_rply.ar_results.proc = (xdrproc_t)xdr_void;
		if (!xdrrec_skiprecord(xdrs)) {
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (rpc_callerr.re_status);
		}
		/* now decode and validate the response header */
		if (!xdr_replymsg(xdrs, &reply_msg)) {
			if (rpc_callerr.re_status == RPC_SUCCESS)
				continue;
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (rpc_callerr.re_status);
		}
		if (reply_msg.rm_xid == x_id)
			break;
	}

	/*
	 * process header
	 */
	if ((reply_msg.rm_reply.rp_stat == MSG_ACCEPTED) &&
	    (reply_msg.acpted_rply.ar_stat == SUCCESS))
		rpc_callerr.re_status = RPC_SUCCESS;
	else
		__seterr_reply(&reply_msg, &(rpc_callerr));

	if (rpc_callerr.re_status == RPC_SUCCESS) {
		if (!AUTH_VALIDATE(cl->cl_auth,
		    &reply_msg.acpted_rply.ar_verf)) {
			rpc_callerr.re_status = RPC_AUTHERROR;
			rpc_callerr.re_why = AUTH_INVALIDRESP;
		} else if (cl->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
			if (!(*xdr_results)(xdrs, results_ptr)) {
				if (rpc_callerr.re_status == RPC_SUCCESS)
					rpc_callerr.re_status =
					    RPC_CANTDECODERES;
			}
		} else if (!__rpc_gss_unwrap(cl->cl_auth, xdrs, xdr_results,
		    results_ptr)) {
			if (rpc_callerr.re_status == RPC_SUCCESS)
				rpc_callerr.re_status = RPC_CANTDECODERES;
		}
	}	/* end successful completion */
	/*
	 * If unsuccesful AND error is an authentication error
	 * then refresh credentials and try again, else break
	 */
	else if (rpc_callerr.re_status == RPC_AUTHERROR) {
		/* maybe our credentials need to be refreshed ... */
		if (refreshes-- && AUTH_REFRESH(cl->cl_auth, &reply_msg))
			goto call_again;
		else
			/*
			 * We are setting rpc_callerr here given that libnsl
			 * is not reentrant thereby reinitializing the TSD.
			 * If not set here then success could be returned even
			 * though refresh failed.
			 */
			rpc_callerr.re_status = RPC_AUTHERROR;
	} /* end of unsuccessful completion */
	/* free verifier ... */
	if (reply_msg.rm_reply.rp_stat == MSG_ACCEPTED &&
	    reply_msg.acpted_rply.ar_verf.oa_base != NULL) {
		xdrs->x_op = XDR_FREE;
		(void) xdr_opaque_auth(xdrs, &(reply_msg.acpted_rply.ar_verf));
	}
	rpc_fd_unlock(vctbl, ct->ct_fd);
	return (rpc_callerr.re_status);
}

static enum clnt_stat
clnt_vc_send(CLIENT *cl, rpcproc_t proc, xdrproc_t xdr_args, caddr_t args_ptr)
{
/* LINTED pointer alignment */
	struct ct_data *ct = (struct ct_data *)cl->cl_private;
	XDR *xdrs = &(ct->ct_xdrs);
	uint32_t x_id;
/* LINTED pointer alignment */
	uint32_t *msg_x_id = (uint32_t *)(ct->ct_mcall);	/* yuk */

	if (rpc_fd_lock(vctbl, ct->ct_fd)) {
		rpc_callerr.re_status = RPC_FAILED;
		rpc_callerr.re_errno = errno;
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (RPC_FAILED);
	}

	ct->ct_is_oneway = TRUE;

	xdrs->x_op = XDR_ENCODE;
	rpc_callerr.re_status = RPC_SUCCESS;
	/*
	 * Due to little endian byte order, it is necessary to convert to host
	 * format before decrementing xid.
	 */
	x_id = ntohl(*msg_x_id) - 1;
	*msg_x_id = htonl(x_id);

	if (cl->cl_auth->ah_cred.oa_flavor != RPCSEC_GSS) {
		if ((!XDR_PUTBYTES(xdrs, ct->ct_mcall, ct->ct_mpos)) ||
		    (!XDR_PUTINT32(xdrs, (int32_t *)&proc)) ||
		    (!AUTH_MARSHALL(cl->cl_auth, xdrs)) ||
		    (!xdr_args(xdrs, args_ptr))) {
			if (rpc_callerr.re_status == RPC_SUCCESS)
				rpc_callerr.re_status = RPC_CANTENCODEARGS;
			(void) xdrrec_endofrecord(xdrs, TRUE);
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (rpc_callerr.re_status);
		}
	} else {
/* LINTED pointer alignment */
		uint32_t *u = (uint32_t *)&ct->ct_mcall[ct->ct_mpos];
		IXDR_PUT_U_INT32(u, proc);
		if (!__rpc_gss_wrap(cl->cl_auth, ct->ct_mcall,
		    ((char *)u) - ct->ct_mcall, xdrs, xdr_args, args_ptr)) {
			if (rpc_callerr.re_status == RPC_SUCCESS)
				rpc_callerr.re_status = RPC_CANTENCODEARGS;
			(void) xdrrec_endofrecord(xdrs, TRUE);
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (rpc_callerr.re_status);
		}
	}

	/*
	 * Do not need to check errors, as the following code does
	 * not depend on the successful completion of the call.
	 * An error, if any occurs, is reported through
	 * rpc_callerr.re_status.
	 */
	(void) xdrrec_endofrecord(xdrs, TRUE);

	rpc_fd_unlock(vctbl, ct->ct_fd);
	return (rpc_callerr.re_status);
}

/* ARGSUSED */
static void
clnt_vc_geterr(CLIENT *cl, struct rpc_err *errp)
{
	*errp = rpc_callerr;
}

static bool_t
clnt_vc_freeres(CLIENT *cl, xdrproc_t xdr_res, caddr_t res_ptr)
{
/* LINTED pointer alignment */
	struct ct_data *ct = (struct ct_data *)cl->cl_private;
	XDR *xdrs = &(ct->ct_xdrs);
	bool_t stat;

	(void) rpc_fd_lock(vctbl, ct->ct_fd);
	xdrs->x_op = XDR_FREE;
	stat = (*xdr_res)(xdrs, res_ptr);
	rpc_fd_unlock(vctbl, ct->ct_fd);
	return (stat);
}

static void
clnt_vc_abort(void)
{
}

/*ARGSUSED*/
static bool_t
clnt_vc_control(CLIENT *cl, int request, char *info)
{
	bool_t ret;
/* LINTED pointer alignment */
	struct ct_data *ct = (struct ct_data *)cl->cl_private;

	if (rpc_fd_lock(vctbl, ct->ct_fd)) {
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (FALSE);
	}

	switch (request) {
	case CLSET_FD_CLOSE:
		ct->ct_closeit = TRUE;
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (TRUE);
	case CLSET_FD_NCLOSE:
		ct->ct_closeit = FALSE;
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (TRUE);
	case CLFLUSH:
		if (ct->ct_io_mode == RPC_CL_NONBLOCKING) {
			int res;
			res = do_flush(ct, (info == NULL ||
			    /* LINTED pointer cast */
			    *(int *)info == RPC_CL_DEFAULT_FLUSH)?
			    /* LINTED pointer cast */
			    ct->ct_blocking_mode: *(int *)info);
			ret = (0 == res);
		} else {
			ret = FALSE;
		}
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (ret);
	}

	/* for other requests which use info */
	if (info == NULL) {
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (FALSE);
	}
	switch (request) {
	case CLSET_TIMEOUT:
/* LINTED pointer alignment */
		if (time_not_ok((struct timeval *)info)) {
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (FALSE);
		}
/* LINTED pointer alignment */
		ct->ct_wait = __rpc_timeval_to_msec((struct timeval *)info);
		ct->ct_waitset = TRUE;
		break;
	case CLGET_TIMEOUT:
/* LINTED pointer alignment */
		((struct timeval *)info)->tv_sec = ct->ct_wait / 1000;
/* LINTED pointer alignment */
		((struct timeval *)info)->tv_usec = (ct->ct_wait % 1000) * 1000;
		break;
	case CLGET_SERVER_ADDR:	/* For compatibility only */
		(void) memcpy(info, ct->ct_addr.buf, (size_t)ct->ct_addr.len);
		break;
	case CLGET_FD:
/* LINTED pointer alignment */
		*(int *)info = ct->ct_fd;
		break;
	case CLGET_SVC_ADDR:
		/* The caller should not free this memory area */
/* LINTED pointer alignment */
		*(struct netbuf *)info = ct->ct_addr;
		break;
	case CLSET_SVC_ADDR:		/* set to new address */
#ifdef undef
		/*
		 * XXX: once the t_snddis(), followed by t_connect() starts to
		 * work, this ifdef should be removed.  CLIENT handle reuse
		 * would then be possible for COTS as well.
		 */
		if (t_snddis(ct->ct_fd, NULL) == -1) {
			rpc_createerr.cf_stat = RPC_TLIERROR;
			rpc_createerr.cf_error.re_terrno = t_errno;
			rpc_createerr.cf_error.re_errno = errno;
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (FALSE);
		}
		ret = set_up_connection(ct->ct_fd, (struct netbuf *)info,
		    ct, NULL);
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (ret);
#else
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (FALSE);
#endif
	case CLGET_XID:
		/*
		 * use the knowledge that xid is the
		 * first element in the call structure
		 * This will get the xid of the PREVIOUS call
		 */
/* LINTED pointer alignment */
		*(uint32_t *)info = ntohl(*(uint32_t *)ct->ct_mcall);
		break;
	case CLSET_XID:
		/* This will set the xid of the NEXT call */
/* LINTED pointer alignment */
		*(uint32_t *)ct->ct_mcall =  htonl(*(uint32_t *)info + 1);
		/* increment by 1 as clnt_vc_call() decrements once */
		break;
	case CLGET_VERS:
		/*
		 * This RELIES on the information that, in the call body,
		 * the version number field is the fifth field from the
		 * begining of the RPC header. MUST be changed if the
		 * call_struct is changed
		 */
/* LINTED pointer alignment */
		*(uint32_t *)info = ntohl(*(uint32_t *)(ct->ct_mcall +
		    4 * BYTES_PER_XDR_UNIT));
		break;

	case CLSET_VERS:
/* LINTED pointer alignment */
		*(uint32_t *)(ct->ct_mcall + 4 * BYTES_PER_XDR_UNIT) =
/* LINTED pointer alignment */
		    htonl(*(uint32_t *)info);
		break;

	case CLGET_PROG:
		/*
		 * This RELIES on the information that, in the call body,
		 * the program number field is the fourth field from the
		 * begining of the RPC header. MUST be changed if the
		 * call_struct is changed
		 */
/* LINTED pointer alignment */
		*(uint32_t *)info = ntohl(*(uint32_t *)(ct->ct_mcall +
		    3 * BYTES_PER_XDR_UNIT));
		break;

	case CLSET_PROG:
/* LINTED pointer alignment */
		*(uint32_t *)(ct->ct_mcall + 3 * BYTES_PER_XDR_UNIT) =
/* LINTED pointer alignment */
		    htonl(*(uint32_t *)info);
		break;

	case CLSET_IO_MODE:
		/* LINTED pointer cast */
		if (!set_io_mode(ct, *(int *)info)) {
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (FALSE);
		}
		break;
	case CLSET_FLUSH_MODE:
		/* Set a specific FLUSH_MODE */
		/* LINTED pointer cast */
		if (!set_flush_mode(ct, *(int *)info)) {
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (FALSE);
		}
		break;
	case CLGET_FLUSH_MODE:
		/* LINTED pointer cast */
		*(rpcflushmode_t *)info = ct->ct_blocking_mode;
		break;

	case CLGET_IO_MODE:
		/* LINTED pointer cast */
		*(rpciomode_t *)info = ct->ct_io_mode;
		break;

	case CLGET_CURRENT_REC_SIZE:
		/*
		 * Returns the current amount of memory allocated
		 * to pending requests
		 */
		/* LINTED pointer cast */
		*(int *)info = ct->ct_bufferPendingSize;
		break;

	case CLSET_CONNMAXREC_SIZE:
		/* Cannot resize the buffer if it is used. */
		if (ct->ct_bufferPendingSize != 0) {
			rpc_fd_unlock(vctbl, ct->ct_fd);
			return (FALSE);
		}
		/*
		 * If the new size is equal to the current size,
		 * there is nothing to do.
		 */
		/* LINTED pointer cast */
		if (ct->ct_bufferSize == *(uint_t *)info)
			break;

		/* LINTED pointer cast */
		ct->ct_bufferSize = *(uint_t *)info;
		if (ct->ct_buffer) {
			free(ct->ct_buffer);
			ct->ct_buffer = NULL;
			ct->ct_bufferReadPtr = ct->ct_bufferWritePtr = NULL;
		}
		break;

	case CLGET_CONNMAXREC_SIZE:
		/*
		 * Returns the size of buffer allocated
		 * to pending requests
		 */
		/* LINTED pointer cast */
		*(uint_t *)info = ct->ct_bufferSize;
		break;

	default:
		rpc_fd_unlock(vctbl, ct->ct_fd);
		return (FALSE);
	}
	rpc_fd_unlock(vctbl, ct->ct_fd);
	return (TRUE);
}

static void
clnt_vc_destroy(CLIENT *cl)
{
/* LINTED pointer alignment */
	struct ct_data *ct = (struct ct_data *)cl->cl_private;
	int ct_fd = ct->ct_fd;

	(void) rpc_fd_lock(vctbl, ct_fd);

	if (ct->ct_io_mode == RPC_CL_NONBLOCKING) {
		(void) do_flush(ct, RPC_CL_BLOCKING_FLUSH);
		(void) unregister_nb(ct);
	}

	if (ct->ct_closeit)
		(void) t_close(ct_fd);
	XDR_DESTROY(&(ct->ct_xdrs));
	if (ct->ct_addr.buf)
		free(ct->ct_addr.buf);
	free(ct);
	if (cl->cl_netid && cl->cl_netid[0])
		free(cl->cl_netid);
	if (cl->cl_tp && cl->cl_tp[0])
		free(cl->cl_tp);
	free(cl);
	rpc_fd_unlock(vctbl, ct_fd);
}

/*
 * Interface between xdr serializer and vc connection.
 * Behaves like the system calls, read & write, but keeps some error state
 * around for the rpc level.
 */
static int
read_vc(void *ct_tmp, caddr_t buf, int len)
{
	static pthread_key_t pfdp_key = PTHREAD_ONCE_KEY_NP;
	struct pollfd *pfdp;
	int npfd;		/* total number of pfdp allocated */
	struct ct_data *ct = ct_tmp;
	struct timeval starttime;
	struct timeval curtime;
	int poll_time;
	int delta;

	if (len == 0)
		return (0);

	/*
	 * Allocate just one the first time.  thr_get_storage() may
	 * return a larger buffer, left over from the last time we were
	 * here, but that's OK.  realloc() will deal with it properly.
	 */
	npfd = 1;
	pfdp = thr_get_storage(&pfdp_key, sizeof (struct pollfd), free);
	if (pfdp == NULL) {
		(void) syslog(LOG_ERR, clnt_vc_errstr,
		    clnt_read_vc_str, __no_mem_str);
		rpc_callerr.re_status = RPC_SYSTEMERROR;
		rpc_callerr.re_errno = errno;
		rpc_callerr.re_terrno = 0;
		return (-1);
	}

	/*
	 *	N.B.:  slot 0 in the pollfd array is reserved for the file
	 *	descriptor we're really interested in (as opposed to the
	 *	callback descriptors).
	 */
	pfdp[0].fd = ct->ct_fd;
	pfdp[0].events = MASKVAL;
	pfdp[0].revents = 0;
	poll_time = ct->ct_wait;
	if (gettimeofday(&starttime, NULL) == -1) {
		syslog(LOG_ERR, "Unable to get time of day: %m");
		return (-1);
	}

	for (;;) {
		extern void (*_svc_getreqset_proc)();
		extern pollfd_t *svc_pollfd;
		extern int svc_max_pollfd;
		int fds;

		/* VARIABLES PROTECTED BY svc_fd_lock: svc_pollfd */

		if (_svc_getreqset_proc) {
			sig_rw_rdlock(&svc_fd_lock);

			/* reallocate pfdp to svc_max_pollfd +1 */
			if (npfd != (svc_max_pollfd + 1)) {
				struct pollfd *tmp_pfdp = realloc(pfdp,
				    sizeof (struct pollfd) *
				    (svc_max_pollfd + 1));
				if (tmp_pfdp == NULL) {
					sig_rw_unlock(&svc_fd_lock);
					(void) syslog(LOG_ERR, clnt_vc_errstr,
					    clnt_read_vc_str, __no_mem_str);
					rpc_callerr.re_status = RPC_SYSTEMERROR;
					rpc_callerr.re_errno = errno;
					rpc_callerr.re_terrno = 0;
					return (-1);
				}

				pfdp = tmp_pfdp;
				npfd = svc_max_pollfd + 1;
				(void) pthread_setspecific(pfdp_key, pfdp);
			}
			if (npfd > 1)
				(void) memcpy(&pfdp[1], svc_pollfd,
				    sizeof (struct pollfd) * (npfd - 1));

			sig_rw_unlock(&svc_fd_lock);
		} else {
			npfd = 1;	/* don't forget about pfdp[0] */
		}

		switch (fds = poll(pfdp, npfd, poll_time)) {
		case 0:
			rpc_callerr.re_status = RPC_TIMEDOUT;
			return (-1);

		case -1:
			if (errno != EINTR)
				continue;
			else {
				/*
				 * interrupted by another signal,
				 * update time_waited
				 */

				if (gettimeofday(&curtime, NULL) == -1) {
					syslog(LOG_ERR,
					    "Unable to get time of day:  %m");
					errno = 0;
					continue;
				};
				delta = (curtime.tv_sec -
				    starttime.tv_sec) * 1000 +
				    (curtime.tv_usec -
				    starttime.tv_usec) / 1000;
				poll_time -= delta;
				if (poll_time < 0) {
					rpc_callerr.re_status = RPC_TIMEDOUT;
					errno = 0;
					return (-1);
				} else {
					errno = 0; /* reset it */
					continue;
				}
			}
		}

		if (pfdp[0].revents == 0) {
			/* must be for server side of the house */
			(*_svc_getreqset_proc)(&pfdp[1], fds);
			continue;	/* do poll again */
		}

		if (pfdp[0].revents & POLLNVAL) {
			rpc_callerr.re_status = RPC_CANTRECV;
			/*
			 *	Note:  we're faking errno here because we
			 *	previously would have expected select() to
			 *	return -1 with errno EBADF.  Poll(BA_OS)
			 *	returns 0 and sets the POLLNVAL revents flag
			 *	instead.
			 */
			rpc_callerr.re_errno = errno = EBADF;
			return (-1);
		}

		if (pfdp[0].revents & (POLLERR | POLLHUP)) {
			rpc_callerr.re_status = RPC_CANTRECV;
			rpc_callerr.re_errno = errno = EPIPE;
			return (-1);
		}
		break;
	}

	switch (len = t_rcvall(ct->ct_fd, buf, len)) {
	case 0:
		/* premature eof */
		rpc_callerr.re_errno = ENOLINK;
		rpc_callerr.re_terrno = 0;
		rpc_callerr.re_status = RPC_CANTRECV;
		len = -1;	/* it's really an error */
		break;

	case -1:
		rpc_callerr.re_terrno = t_errno;
		rpc_callerr.re_errno = 0;
		rpc_callerr.re_status = RPC_CANTRECV;
		break;
	}
	return (len);
}

static int
write_vc(void *ct_tmp, caddr_t buf, int len)
{
	int i, cnt;
	struct ct_data *ct = ct_tmp;
	int flag;
	int maxsz;

	maxsz = ct->ct_tsdu;

	/* Handle the non-blocking mode */
	if (ct->ct_is_oneway && ct->ct_io_mode == RPC_CL_NONBLOCKING) {
		/*
		 * Test a special case here. If the length of the current
		 * write is greater than the transport data unit, and the
		 * mode is non blocking, we return RPC_CANTSEND.
		 * XXX  this is not very clean.
		 */
		if (maxsz > 0 && len > maxsz) {
			rpc_callerr.re_terrno = errno;
			rpc_callerr.re_errno = 0;
			rpc_callerr.re_status = RPC_CANTSEND;
			return (-1);
		}

		len = nb_send(ct, buf, (unsigned)len);
		if (len == -1) {
			rpc_callerr.re_terrno = errno;
			rpc_callerr.re_errno = 0;
			rpc_callerr.re_status = RPC_CANTSEND;
		} else if (len == -2) {
			rpc_callerr.re_terrno = 0;
			rpc_callerr.re_errno = 0;
			rpc_callerr.re_status = RPC_CANTSTORE;
		}
		return (len);
	}

	if ((maxsz == 0) || (maxsz == -1)) {
		/*
		 * T_snd may return -1 for error on connection (connection
		 * needs to be repaired/closed, and -2 for flow-control
		 * handling error (no operation to do, just wait and call
		 * T_Flush()).
		 */
		if ((len = t_snd(ct->ct_fd, buf, (unsigned)len, 0)) == -1) {
			rpc_callerr.re_terrno = t_errno;
			rpc_callerr.re_errno = 0;
			rpc_callerr.re_status = RPC_CANTSEND;
		}
		return (len);
	}

	/*
	 * This for those transports which have a max size for data.
	 */
	for (cnt = len, i = 0; cnt > 0; cnt -= i, buf += i) {
		flag = cnt > maxsz ? T_MORE : 0;
		if ((i = t_snd(ct->ct_fd, buf, (unsigned)MIN(cnt, maxsz),
		    flag)) == -1) {
			rpc_callerr.re_terrno = t_errno;
			rpc_callerr.re_errno = 0;
			rpc_callerr.re_status = RPC_CANTSEND;
			return (-1);
		}
	}
	return (len);
}

/*
 * Receive the required bytes of data, even if it is fragmented.
 */
static int
t_rcvall(int fd, char *buf, int len)
{
	int moreflag;
	int final = 0;
	int res;

	do {
		moreflag = 0;
		res = t_rcv(fd, buf, (unsigned)len, &moreflag);
		if (res == -1) {
			if (t_errno == TLOOK)
				switch (t_look(fd)) {
				case T_DISCONNECT:
					(void) t_rcvdis(fd, NULL);
					(void) t_snddis(fd, NULL);
					return (-1);
				case T_ORDREL:
				/* Received orderly release indication */
					(void) t_rcvrel(fd);
				/* Send orderly release indicator */
					(void) t_sndrel(fd);
					return (-1);
				default:
					return (-1);
				}
		} else if (res == 0) {
			return (0);
		}
		final += res;
		buf += res;
		len -= res;
	} while ((len > 0) && (moreflag & T_MORE));
	return (final);
}

static struct clnt_ops *
clnt_vc_ops(void)
{
	static struct clnt_ops ops;
	extern mutex_t	ops_lock;

	/* VARIABLES PROTECTED BY ops_lock: ops */

	sig_mutex_lock(&ops_lock);
	if (ops.cl_call == NULL) {
		ops.cl_call = clnt_vc_call;
		ops.cl_send = clnt_vc_send;
		ops.cl_abort = clnt_vc_abort;
		ops.cl_geterr = clnt_vc_geterr;
		ops.cl_freeres = clnt_vc_freeres;
		ops.cl_destroy = clnt_vc_destroy;
		ops.cl_control = clnt_vc_control;
	}
	sig_mutex_unlock(&ops_lock);
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


/* Compute the # of bytes that remains until the end of the buffer */
#define	REMAIN_BYTES(p) (ct->ct_bufferSize-(ct->ct_##p - ct->ct_buffer))

static int
addInBuffer(struct ct_data *ct, char *dataToAdd, unsigned int nBytes)
{
	if (NULL == ct->ct_buffer) {
		/* Buffer not allocated yet. */
		char *buffer;

		buffer = malloc(ct->ct_bufferSize);
		if (NULL == buffer) {
			errno = ENOMEM;
			return (-1);
		}
		(void) memcpy(buffer, dataToAdd, nBytes);

		ct->ct_buffer = buffer;
		ct->ct_bufferReadPtr = buffer;
		ct->ct_bufferWritePtr = buffer + nBytes;
		ct->ct_bufferPendingSize = nBytes;
	} else {
		/*
		 * For an already allocated buffer, two mem copies
		 * might be needed, depending on the current
		 * writing position.
		 */

		/* Compute the length of the first copy. */
		int len = MIN(nBytes, REMAIN_BYTES(bufferWritePtr));

		ct->ct_bufferPendingSize += nBytes;

		(void) memcpy(ct->ct_bufferWritePtr, dataToAdd, len);
		ct->ct_bufferWritePtr += len;
		nBytes -= len;
		if (0 == nBytes) {
			/* One memcopy needed. */

			/*
			 * If the write pointer is at the end of the buffer,
			 * wrap it now.
			 */
			if (ct->ct_bufferWritePtr ==
			    (ct->ct_buffer + ct->ct_bufferSize)) {
				ct->ct_bufferWritePtr = ct->ct_buffer;
			}
		} else {
			/* Two memcopy needed. */
			dataToAdd += len;

			/*
			 * Copy the remaining data to the beginning of the
			 * buffer
			 */
			(void) memcpy(ct->ct_buffer, dataToAdd, nBytes);
			ct->ct_bufferWritePtr = ct->ct_buffer + nBytes;
		}
	}
	return (0);
}

static void
consumeFromBuffer(struct ct_data *ct, unsigned int nBytes)
{
	ct->ct_bufferPendingSize -= nBytes;
	if (ct->ct_bufferPendingSize == 0) {
		/*
		 * If the buffer contains no data, we set the two pointers at
		 * the beginning of the buffer (to miminize buffer wraps).
		 */
		ct->ct_bufferReadPtr = ct->ct_bufferWritePtr = ct->ct_buffer;
	} else {
		ct->ct_bufferReadPtr += nBytes;
		if (ct->ct_bufferReadPtr >
		    ct->ct_buffer + ct->ct_bufferSize) {
			ct->ct_bufferReadPtr -= ct->ct_bufferSize;
		}
	}
}

static int
iovFromBuffer(struct ct_data *ct, struct iovec *iov)
{
	int l;

	if (ct->ct_bufferPendingSize == 0)
		return (0);

	l = REMAIN_BYTES(bufferReadPtr);
	if (l < ct->ct_bufferPendingSize) {
		/* Buffer in two fragments. */
		iov[0].iov_base = ct->ct_bufferReadPtr;
		iov[0].iov_len  = l;

		iov[1].iov_base = ct->ct_buffer;
		iov[1].iov_len  = ct->ct_bufferPendingSize - l;
		return (2);
	} else {
		/* Buffer in one fragment. */
		iov[0].iov_base = ct->ct_bufferReadPtr;
		iov[0].iov_len  = ct->ct_bufferPendingSize;
		return (1);
	}
}

static bool_t
set_flush_mode(struct ct_data *ct, int mode)
{
	switch (mode) {
	case RPC_CL_BLOCKING_FLUSH:
		/* flush as most as possible without blocking */
	case RPC_CL_BESTEFFORT_FLUSH:
		/* flush the buffer completely (possibly blocking) */
	case RPC_CL_DEFAULT_FLUSH:
		/* flush according to the currently defined policy */
		ct->ct_blocking_mode = mode;
		return (TRUE);
	default:
		return (FALSE);
	}
}

static bool_t
set_io_mode(struct ct_data *ct, int ioMode)
{
	switch (ioMode) {
	case RPC_CL_BLOCKING:
		if (ct->ct_io_mode == RPC_CL_NONBLOCKING) {
			if (NULL != ct->ct_buffer) {
				/*
				 * If a buffer was allocated for this
				 * connection, flush it now, and free it.
				 */
				(void) do_flush(ct, RPC_CL_BLOCKING_FLUSH);
				free(ct->ct_buffer);
				ct->ct_buffer = NULL;
			}
			(void) unregister_nb(ct);
			ct->ct_io_mode = ioMode;
		}
		break;
	case RPC_CL_NONBLOCKING:
		if (ct->ct_io_mode == RPC_CL_BLOCKING) {
			if (-1 == register_nb(ct)) {
				return (FALSE);
			}
			ct->ct_io_mode = ioMode;
		}
		break;
	default:
		return (FALSE);
	}
	return (TRUE);
}

static int
do_flush(struct ct_data *ct, uint_t flush_mode)
{
	int result;
	if (ct->ct_bufferPendingSize == 0) {
		return (0);
	}

	switch (flush_mode) {
	case RPC_CL_BLOCKING_FLUSH:
		if (!set_blocking_connection(ct, TRUE)) {
			return (-1);
		}
		while (ct->ct_bufferPendingSize > 0) {
			if (REMAIN_BYTES(bufferReadPtr) <
			    ct->ct_bufferPendingSize) {
				struct iovec iov[2];
				(void) iovFromBuffer(ct, iov);
				result = writev(ct->ct_fd, iov, 2);
			} else {
				result = t_snd(ct->ct_fd, ct->ct_bufferReadPtr,
				    ct->ct_bufferPendingSize, 0);
			}
			if (result < 0) {
				return (-1);
			}
			consumeFromBuffer(ct, result);
		}

		break;

	case RPC_CL_BESTEFFORT_FLUSH:
		(void) set_blocking_connection(ct, FALSE);
		if (REMAIN_BYTES(bufferReadPtr) < ct->ct_bufferPendingSize) {
			struct iovec iov[2];
			(void) iovFromBuffer(ct, iov);
			result = writev(ct->ct_fd, iov, 2);
		} else {
			result = t_snd(ct->ct_fd, ct->ct_bufferReadPtr,
			    ct->ct_bufferPendingSize, 0);
		}
		if (result < 0) {
			if (errno != EWOULDBLOCK) {
				perror("flush");
				return (-1);
			}
			return (0);
		}
		if (result > 0)
			consumeFromBuffer(ct, result);
		break;
	}
	return (0);
}

/*
 * Non blocking send.
 */

static int
nb_send(struct ct_data *ct, void *buff, unsigned int nBytes)
{
	int result;

	if (!(ntohl(*(uint32_t *)buff) & 2^31)) {
		return (-1);
	}

	/*
	 * Check to see if the current message can be stored fully in the
	 * buffer. We have to check this now because it may be impossible
	 * to send any data, so the message must be stored in the buffer.
	 */
	if (nBytes > (ct->ct_bufferSize - ct->ct_bufferPendingSize)) {
		/* Try to flush  (to free some space). */
		(void) do_flush(ct, RPC_CL_BESTEFFORT_FLUSH);

		/* Can we store the message now ? */
		if (nBytes > (ct->ct_bufferSize - ct->ct_bufferPendingSize))
			return (-2);
	}

	(void) set_blocking_connection(ct, FALSE);

	/*
	 * If there is no data pending, we can simply try
	 * to send our data.
	 */
	if (ct->ct_bufferPendingSize == 0) {
		result = t_snd(ct->ct_fd, buff, nBytes, 0);
		if (result == -1) {
			if (errno == EWOULDBLOCK) {
				result = 0;
			} else {
				perror("send");
				return (-1);
			}
		}
		/*
		 * If we have not sent all data, we must store them
		 * in the buffer.
		 */
		if (result != nBytes) {
			if (addInBuffer(ct, (char *)buff + result,
			    nBytes - result) == -1) {
				return (-1);
			}
		}
	} else {
		/*
		 * Some data pending in the buffer.  We try to send
		 * both buffer data and current message in one shot.
		 */
		struct iovec iov[3];
		int i = iovFromBuffer(ct, &iov[0]);

		iov[i].iov_base = buff;
		iov[i].iov_len  = nBytes;

		result = writev(ct->ct_fd, iov, i+1);
		if (result == -1) {
			if (errno == EWOULDBLOCK) {
				/* No bytes sent */
				result = 0;
			} else {
				return (-1);
			}
		}

		/*
		 * Add the bytes from the message
		 * that we have not sent.
		 */
		if (result <= ct->ct_bufferPendingSize) {
			/* No bytes from the message sent */
			consumeFromBuffer(ct, result);
			if (addInBuffer(ct, buff, nBytes) == -1) {
				return (-1);
			}
		} else {
			/*
			 * Some bytes of the message are sent.
			 * Compute the length of the message that has
			 * been sent.
			 */
			int len = result - ct->ct_bufferPendingSize;

			/* So, empty the buffer. */
			ct->ct_bufferReadPtr = ct->ct_buffer;
			ct->ct_bufferWritePtr = ct->ct_buffer;
			ct->ct_bufferPendingSize = 0;

			/* And add the remaining part of the message. */
			if (len != nBytes) {
				if (addInBuffer(ct, (char *)buff + len,
				    nBytes-len) == -1) {
					return (-1);
				}
			}
		}
	}
	return (nBytes);
}

static void
flush_registered_clients(void)
{
	struct nb_reg_node *node;

	if (LIST_ISEMPTY(nb_first)) {
		return;
	}

	LIST_FOR_EACH(nb_first, node) {
		(void) do_flush(node->ct, RPC_CL_BLOCKING_FLUSH);
	}
}

static int
allocate_chunk(void)
{
#define	CHUNK_SIZE 16
	struct nb_reg_node *chk =
	    malloc(sizeof (struct nb_reg_node) * CHUNK_SIZE);
	struct nb_reg_node *n;
	int i;

	if (NULL == chk) {
		return (-1);
	}

	n = chk;
	for (i = 0; i < CHUNK_SIZE-1; ++i) {
		n[i].next = &(n[i+1]);
	}
	n[CHUNK_SIZE-1].next = (struct nb_reg_node *)&nb_free;
	nb_free = chk;
	return (0);
}

static int
register_nb(struct ct_data *ct)
{
	struct nb_reg_node *node;

	(void) mutex_lock(&nb_list_mutex);

	if (LIST_ISEMPTY(nb_free) && (allocate_chunk() == -1)) {
		(void) mutex_unlock(&nb_list_mutex);
		errno = ENOMEM;
		return (-1);
	}

	if (!exit_handler_set) {
		(void) atexit(flush_registered_clients);
		exit_handler_set = TRUE;
	}
	/* Get the first free node */
	LIST_EXTRACT(nb_free, node);

	node->ct = ct;

	LIST_ADD(nb_first, node);
	(void) mutex_unlock(&nb_list_mutex);

	return (0);
}

static int
unregister_nb(struct ct_data *ct)
{
	struct nb_reg_node *node;

	(void) mutex_lock(&nb_list_mutex);
	assert(!LIST_ISEMPTY(nb_first));

	node = nb_first;
	LIST_FOR_EACH(nb_first, node) {
		if (node->next->ct == ct) {
			/* Get the node to unregister. */
			struct nb_reg_node *n = node->next;
			node->next = n->next;

			n->ct = NULL;
			LIST_ADD(nb_free, n);
			break;
		}
	}
	(void) mutex_unlock(&nb_list_mutex);
	return (0);
}
