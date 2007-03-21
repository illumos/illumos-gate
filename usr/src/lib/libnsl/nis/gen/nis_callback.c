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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	nis_callback.c
 *
 *	This module contains the functions that implement the callback
 *	facility. They are RPC library dependent.
 *
 * 	These callback functions set up and run the callback
 * 	facility of NIS+. The idea is simple, a psuedo service is created
 * 	by the client and registered with the portmapper. The program number
 * 	for that service is included in the request as is the principal
 * 	name of the _host_ where the request is being made. The server
 * 	then does rpc calls to that service to return results.
 */

#include "mt.h"
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <tiuser.h>
#include <netdir.h>
#include <sys/netconfig.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <rpc/types.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_callback.h>
#include "nis_clnt.h"
#include "nis_local.h"
#include <thread.h>

#ifndef TRUE
#define	TRUE 1
#define	FALSE 0
#endif

#define	CB_MAXENDPOINTS 16

/*
 * Multi-threaded and Reentrant callback support:
 *
 * Eventually we would like to support simultaneous callbacks from
 * multiple threads and callbacks within call backs.  At the moment we
 * don't/can't.  Much of the problem lies with the rpc system, which
 * does not support either multi-threaded or reentrant calls from rpc
 * servers.  Also note that the use of thread global data in this file
 * precludes reentrant callbacks.  Since these things cannot easily be
 * made to work, we use a mutex lock to ensure that only one use of
 * callbacks is taking place at a time.  The lock must be held around
 * all calls to __nis_core_lookup and nis_dump_r which do callbacks,
 * as those functions are the ones which call __nis_init_callback and
 * __nis_run_callback.  The lock is defined here.
 */
mutex_t __nis_callback_lock = DEFAULTMUTEX;


/*
 * __cbdata is the internal state which the callback routines maintain
 * for clients. It is stored as a structure so that multithreaded clients
 * may eventually keep a static copy of this on their Thread local storage.
 */
struct callback_data {
	nis_server 	cbhost;
	char		pkey_data[1024];
	endpoint	cbendp[CB_MAXENDPOINTS];
	SVCXPRT		*cbsvc[CB_MAXENDPOINTS];
	bool_t		complete;
	int		results;
	pid_t		cbpid;
	nis_error	cberror;
	void		*cbuser;
	int		(*cback)();
	void		(*dispatch)();
};

/*
 * Static function prototypes.
 */
static void
__do_callback(struct svc_req *, SVCXPRT *);

static void
__do_dump_callback(struct svc_req *, SVCXPRT *);

static bool_t
__callback_stub(cback_data *, struct svc_req *, struct callback_data *, int *);

static bool_t
__callback_finish(void *, struct svc_req *, struct callback_data *, int *);

static bool_t
__callback_error(nis_error *, struct svc_req *, struct callback_data *, int *);

static char *__get_clnt_uaddr(CLIENT *);

static void destroy_cbdata(void *);

static pthread_key_t cbdata_key = PTHREAD_ONCE_KEY_NP;
static struct callback_data __cbdata_main;

/*
 * In the MT rpc.nisd, the callback service is handled by one of the
 * RPC auto MT service threads. Since nis_dump() assumes that one and
 * the same thread both sets up the __cbdata and runs the callback
 * service, we must use a sleight-of-hand to maintain that illusion.
 * Hence the '__cbdata_dump', which points to the __cbdata of the
 * thread running nis_dump().
 *
 * Protected by '__nis_callback_lock'.
 */
static struct callback_data *__cbdata_dump = NULL;

/*
 * To synchronize the nis_dump() thread with its callback thread, we use
 * a mutex, a condition variable, and a count of the number of times the
 * dispatch function was invoked. We use the 'complete' field of the
 * (struct callback_data) to signal completion, so for the nis_dump()
 * case, 'complete' is protected by the '__nis_dump_mutex'.
 */
static mutex_t		__nis_dump_mutex = DEFAULTMUTEX;
static cond_t		__nis_dump_cv = DEFAULTCV;
static int		__nis_dump_cb_count = -1;
static struct timeval	__nis_dump_lastcb = {0, 0};

/*
 * Callback functions. These functions set up and run the callback
 * facility of NIS. The idea is simple, a psuedo service is created
 * by the client and registered with the portmapper. The program number
 * for that service is included in the request as is the principal
 * name of the _host_ where the request is being made. The server
 * then does rpc calls to that service to return results.
 */


static void destroy_cbdata(void * cbdata)
{
	if (cbdata)
		free(cbdata);
}

static struct callback_data *my_cbdata(void)
{
	struct callback_data *__cbdata;

	if (thr_main())
		return (&__cbdata_main);
	else
		__cbdata = thr_get_storage(&cbdata_key, sizeof (*__cbdata),
						destroy_cbdata);
	return (__cbdata);
}

static char *
__get_clnt_uaddr(CLIENT	*cl)
{
	struct netconfig	*nc;
	struct netbuf		addr;
	char			*uaddr;

	nc = getnetconfigent(cl->cl_netid);
	if (! nc)
		return (NULL);
	(void) clnt_control(cl, CLGET_SVC_ADDR, (char *)&addr);
	uaddr = taddr2uaddr(nc, &addr);
	freenetconfigent(nc);
	return (uaddr);
}

int
__nis_destroy_callback(void)
{
	struct callback_data *__cbdata;
	__cbdata = my_cbdata();

	if (!__cbdata)
		return (0);

	if (__cbdata->cbsvc[0]) {
		svc_destroy(__cbdata->cbsvc[0]);
		__cbdata->cbsvc[0] = NULL;
	}

	if (__cbdata->cbhost.name != NULL) {
		free(__cbdata->cbhost.name);
		__cbdata->cbhost.name = NULL;
	}

	/*
	 * Can only safely free __cbdata if:
	 *
	 * (a)	It's not a pointer to the static __cbdata_main, and
	 *
	 * (b)	We can set the TSD pointer to NULL first.
	 */

	if (__cbdata != &__cbdata_main &&
	    pthread_setspecific(cbdata_key, NULL) == 0) {
		free(__cbdata);
	}

	return (1);
}

/*
 * __nis_init_callback()
 * This function will initialize an RPC service handle for the
 * NIS client if one doesn't already exist. This handle uses a
 * "COTS" connection in a TIRPC.
 * The server will either fork, or generate a thread to send us
 * data and if the connection breaks we want to know (that means
 * the server died and we have to return an error). It returns
 * an endpoint if successful and NULL if it fails.
 *
 * NOTE : since we send the server the complete endpoint, including
 * universal address, transport, and family, it doesn't need to contact
 * our portmapper to find out what port we are using. Consequently we
 * don't bother registering with the portmapper, this saves us from having
 * to determine a unique program number.
 */

struct callback_data *
__nis_init_callback_cbdata(
	CLIENT	*svc_clnt,	/* Client handle pointing at the service */
	int	(*cbfunc)(),	/* Callback function			 */
	void	*userdata,	/* Userdata, stuffed away for later	 */
	void	(*dispatch)())	/* Dispatch function for callback	*/
{
	int			nep; 	/* number of endpoints */
	struct callback_data *__cbdata;
	struct netconfig	*nc;
	struct nd_mergearg	ma;
	void			*nch;

	if (cbfunc == NULL)
		return (NULL);

	if (thr_main())
		__cbdata = &__cbdata_main;
	else
		__cbdata = thr_get_storage(&cbdata_key, 0, destroy_cbdata);

	/* Check to see if we already have a service handle */
	if (__cbdata && (__cbdata->cbsvc[0] != NULL) &&
	    (__cbdata->cbpid == getpid()) &&
			(__cbdata->dispatch == dispatch))  {
		__cbdata->cback = cbfunc;
		__cbdata->cbuser = userdata;
		__cbdata->results = 0;
		__cbdata->complete = FALSE;
		return (__cbdata);
	}

	/* Nope, then let's create one... */

	if (__cbdata == NULL) {
		__cbdata = thr_get_storage(&cbdata_key, sizeof (*__cbdata),
						destroy_cbdata);
		ASSERT(my_cbdata() != NULL);
	}
	if (! __cbdata) {
		syslog(LOG_ERR, "__nis_init_callback: Client out of memory.");
		return (NULL);
	}

	__cbdata->cback = cbfunc;
	__cbdata->cbuser = userdata;
	__cbdata->cbpid = getpid();
	__cbdata->results = 0;
	__cbdata->complete = FALSE;
	__cbdata->cbhost.ep.ep_val = &(__cbdata->cbendp[0]);
	__cbdata->dispatch = dispatch;

	/* callbacks are not authenticated, so do minimal srv description. */
	__cbdata->cbhost.name = strdup((char *)nis_local_principal());
	__cbdata->cbhost.key_type = NIS_PK_NONE;
	__cbdata->cbhost.pkey.n_bytes = NULL;
	__cbdata->cbhost.pkey.n_len = 0;

	/* Create the service handle(s) */
	/*
	 * This gets a bit tricky. Because we don't know which transport
	 * the service will choose to call us back on, we have something
	 * of a delimma in picking the correct one here. Because of this
	 * we pick all of the likely ones and pass them on to the remote
	 * server and let it figure it out.
	 * XXX Use the same one as we have a client handle for XXX
	 */
	nch = (void *)setnetconfig();
	nep = 0;
	while (nch && ((nc = (struct netconfig *)getnetconfig(nch)) != NULL) &&
		    (nep == 0)) {

		/* Step 0. XXX see if it is the same netid */
		if (strcmp(nc->nc_netid, svc_clnt->cl_netid) != 0)
			continue;

		/* Step 1. Check to see if it is a virtual circuit transport. */
		if ((nc->nc_semantics != NC_TPI_COTS) &&
		    (nc->nc_semantics != NC_TPI_COTS_ORD))
			continue;

		/* Step 2. Try to create a service transport handle. */
		__cbdata->cbsvc[nep] = svc_tli_create(RPC_ANYFD, nc, NULL,
								128, 8192);
		if (! __cbdata->cbsvc[nep]) {
			syslog(LOG_WARNING,
				"__nis_init_callback: Can't create SVCXPRT.");
			continue;
		}

		/*
		 * When handling a callback, we don't want to impose
		 * any restrictions on request message size, and since
		 * we're not a general purpose server creating new
		 * connections, we don't need the non-blocking code
		 * either. Make sure those features are turned off
		 * for this connection.
		 */
		{
			int connmaxrec = 0;
			(void) svc_control(__cbdata->cbsvc[nep],
			    SVCSET_CONNMAXREC, &connmaxrec);
		}

		/*
		 * This merge code works because we know the netids match
		 * if we want to use a connectionless transport for the
		 * initial call and a connection oriented one for the
		 * callback this won't work. Argh.! XXX
		 */
		ma.s_uaddr = taddr2uaddr(nc,
					&(__cbdata->cbsvc[nep]->xp_ltaddr));
		if (!ma.s_uaddr) {
			syslog(LOG_WARNING,
		    "__nis_init_callback: Can't get uaddr for %s transport.",
				    nc->nc_netid);
			continue;
		}
		ma.c_uaddr = __get_clnt_uaddr(svc_clnt);
		ma.m_uaddr = NULL;
		(void) netdir_options(nc, ND_MERGEADDR, 0, (void *)&ma);
		free(ma.s_uaddr);
		free(ma.c_uaddr);

		/* Step 3. Register it */
		(void) svc_reg(__cbdata->cbsvc[nep], CB_PROG, 1,
		    __cbdata->dispatch, NULL);

		/* Step 4. Fill in the endpoint structure. */
		__cbdata->cbendp[nep].uaddr = ma.m_uaddr;
		__cbdata->cbendp[nep].family = strdup(nc->nc_protofmly);
		__cbdata->cbendp[nep].proto = strdup(nc->nc_proto);
		nep++;
	}
	(void) endnetconfig(nch);

	__cbdata->cbhost.ep.ep_len = nep;
	if (__cbdata->cbsvc[0] == NULL) {
		syslog(LOG_ERR,
			"__nis_init_callback: cannot create callback service.");
		return (NULL);
	}

	return (__cbdata);
}

nis_server *
__nis_init_callback(
	CLIENT	*svc_clnt,	/* Client handle pointing at the service */
	int	(*cbfunc)(),	/* Callback function			 */
	void	*userdata)	/* Userdata, stuffed away for later	 */
{
	struct callback_data	*__cbdata;

	__cbdata = __nis_init_callback_cbdata(svc_clnt, cbfunc, userdata,
						__do_callback);
	if (__cbdata != NULL)
		return (&(__cbdata->cbhost));
	else
		return (NULL);
}

nis_server *
__nis_init_dump_callback(
	CLIENT	*svc_clnt,	/* Client handle pointing at the service */
	int	(*cbfunc)(),	/* Callback function			 */
	void	*userdata)	/* Userdata, stuffed away for later	 */
{
	struct callback_data	*__cbdata;
	nis_server		*ret;

	__cbdata = __nis_init_callback_cbdata(svc_clnt, cbfunc, userdata,
						__do_dump_callback);

	(void) mutex_lock(&__nis_dump_mutex);

	__cbdata_dump = __cbdata;
	if (__cbdata != NULL) {
		__nis_dump_cb_count = -1;
		ret = &(__cbdata->cbhost);
	} else {
		ret = 0;
	}

	__nis_dump_lastcb.tv_sec = 0;
	__nis_dump_lastcb.tv_usec = 0;

	(void) mutex_unlock(&__nis_dump_mutex);
	return (ret);
}

/*
 * Stub to handle requests...
 * Note, as an optimization the server may return us more than one object.
 * This stub will feed them to the callback function one at a time.
 */
static bool_t
__callback_stub(
	cback_data	*argp,
	struct svc_req	*rqstp,
	struct callback_data  *__cbdata,
	int		*results_ptr)
{
	int		i;
	char		buf[1024];

#ifdef lint
	argp = argp;
	rqstp = rqstp;
#endif /* lint */
	*results_ptr = 0;
	for (i = 0; (i < argp->entries.entries_len) && (!(*results_ptr)); i++) {
		(void) strcpy(buf, argp->entries.entries_val[i]->zo_name);
		(void) strcat(buf, ".");
		(void) strcat(buf, argp->entries.entries_val[i]->zo_domain);
		*results_ptr = (*(__cbdata->cback))(buf,
				argp->entries.entries_val[i], __cbdata->cbuser);
	}
	return (1); /* please do reply */
}

static bool_t
__callback_finish(
	void		*argp,
	struct svc_req	*rqstp,
	struct callback_data  *__cbdata,
	int		*results_ptr) /* not used */
{
#ifdef lint
	argp = argp;
	rqstp = rqstp;
	results_ptr = results_ptr;
#endif /* lint */
	__cbdata->cberror = NIS_SUCCESS;
	__cbdata->complete = TRUE;

	return (0); /* don't attempt a reply */
}

static bool_t
__callback_error(argp, rqstp, __cbdata, results_ptr)
	nis_error	*argp;
	struct svc_req	*rqstp;
	struct callback_data  *__cbdata;
	int 	*results_ptr;
{
#ifdef lint
	rqstp = rqstp;
	results_ptr = results_ptr;
#endif /* lint */
	__cbdata->cberror = *argp;
	__cbdata->complete = TRUE;

	return (1);  /* non-zero => please do a reply */
}

/*
 * __nis_run_callback()
 *
 * This is the other function exported by this module. The function
 * duplicates the behaviour of svc_run() for regular rpc services,
 * however it has the additional benefit that it monitors
 * the state of the connection and if it goes away, it terminates
 * the service and returns. Finally, when it returns, it returns
 * the number of times the callback function was called for this
 * session, or -1 if the session ended erroneously.
 */
int
__nis_run_callback(
	netobj		*srvid,		/* Server's netobj		*/
	rpcproc_t	srvproc,	/* RPC to call to check up 	*/
	struct timeval	*timeout,	/* User's timeout		*/
	CLIENT		*myserv)	/* Server talking to us 	*/
{
	enum clnt_stat	cs;
	struct timeval	tv, cbtv;
	bool_t	is_up; /* is_up is TRUE if the server answers us */
	struct callback_data  *__cbdata;
	int nfds = 0;
	int pollret;
	struct pollfd *svc_pollset = 0;
	extern rwlock_t svc_fd_lock;	/* def'd in RPC lib (mt_misc.c) */

	__cbdata = my_cbdata();
	if (__cbdata == NULL)
		return (-1);

	cbtv.tv_sec = NIS_CBACK_TIMEOUT;
	cbtv.tv_usec = 0;
	if (timeout)
		tv = *timeout;
	else {
		/* Default timeout when timeout is null */
		tv.tv_sec = NIS_CBACK_TIMEOUT;
		tv.tv_usec = 0;
	}
	while (! __cbdata->complete) {
		(void) rw_rdlock(&svc_fd_lock);	/* acquire svc_fdset lock */
		if (nfds != svc_max_pollfd) {
			svc_pollset = realloc(svc_pollset,
					sizeof (pollfd_t) * svc_max_pollfd);
			nfds = svc_max_pollfd;
		}

		if (nfds == 0) {
			(void) rw_unlock(&svc_fd_lock);
			break;	/* None waiting, hence return */
		}

		(void) memcpy(svc_pollset, svc_pollfd,
			sizeof (pollfd_t) * svc_max_pollfd);
		(void) rw_unlock(&svc_fd_lock);

		switch (pollret = poll(svc_pollset, nfds,
		    __rpc_timeval_to_msec(&tv))) {
		case -1:
			/*
			 * We exit on any error other than EBADF.  For all
			 * other errors, we return a callback error.
			 */
			if (errno != EBADF) {
				continue;
			}
			syslog(LOG_ERR, "callback: - select failed: %m");
			if (svc_pollset != 0)
				free(svc_pollset);
			return (- NIS_CBERROR);
		case 0:
			/*
			 * possible data race condition
			 */
			if (__cbdata->complete) {
				syslog(LOG_INFO,
		"__run_callback: data race condition detected and avoided.");
				break;
			}

			/*
			 * Check to see if the thread servicing us is still
			 * alive
			 */

			cs = clnt_call(myserv, srvproc,
						xdr_netobj, (char *)srvid,
						xdr_bool, (char *)&is_up,
						cbtv);

			if (cs != RPC_SUCCESS || !is_up) {
				if (svc_pollset != 0)
					free(svc_pollset);
				return (- NIS_CBERROR);
			}
			break;
		default:
			svc_getreq_poll(svc_pollset, pollret);
		}
	}
	if (svc_pollset != 0)
		free(svc_pollset);
	if (__cbdata->cberror) {
		return (0 - __cbdata->cberror);	/* return error results */
	} else
		return (__cbdata->results);	/* Return success (>= 0) */
}

/*
 * When we're doing a nis_dump() in the MT rpc.nisd, '__nis_run_dump_callback'
 * isn't involved in the actual work. It just signals that the configuration
 * is done, waits for completion, and returns the number of times that the
 * dispatch function was invoked.
 */
/* ARGSUSED */
int
__nis_run_dump_callback(
	netobj		*srvid,		/* Server's netobj		*/
	rpcproc_t	srvproc,	/* RPC to call to check up 	*/
	struct timeval	*timeout,	/* User's timeout		*/
	CLIENT		*myserv)	/* Server talking to us 	*/
{
	int		count;
	struct timeval	cbtv = {NIS_CBACK_TIMEOUT, 0};

	if (timeout == 0 || (timeout->tv_sec == 0 && timeout->tv_usec == 0))
		timeout = &cbtv;

	(void) mutex_lock(&__nis_dump_mutex);
	if (__cbdata_dump == NULL) {
		syslog(LOG_ERR,
			"__nis_run_dump_callback: No dump callback structure");
		(void) mutex_unlock(&__nis_dump_mutex);
		return (-1);
	}

	/* Set '__nis_dump_cb_count' to zero so that the dispatch can start */
	if (__nis_dump_cb_count < 0) {
		__nis_dump_cb_count = 0;
		(void) cond_broadcast(&__nis_dump_cv);
	}

	/* Now it's our turn to wait (for completion) */
	for (;;) {
		timestruc_t	to;
		int		ret;

		to.tv_sec = timeout->tv_sec;
		to.tv_nsec = 1000 * timeout->tv_usec;

		ret = cond_reltimedwait(&__nis_dump_cv, &__nis_dump_mutex,
					&to);
		/*
		 * If we've completed, we don't care what cond_wait()
		 * returned,
		 */
		if (__cbdata_dump->complete)
			break;
		if (ret == ETIME) {
			/*
			 * Check when the most recent callback thread exited.
			 * We know there's none active now, because we're
			 * holding the lock. If the time stamp still is
			 * zero, no callback has arrived.
			 */
			if (__nis_dump_lastcb.tv_usec == 0 &&
					__nis_dump_lastcb.tv_sec == 0) {
				syslog(LOG_WARNING,
		"__nis_run_dump_callback: Timeout waiting for first callback");
				(void) mutex_unlock(&__nis_dump_mutex);
				return (-1);
			} else {
				struct timeval	now;

				(void) gettimeofday(&now, 0);
				now.tv_sec -= timeout->tv_sec;
				now.tv_usec -= timeout->tv_usec;
				if (now.tv_usec < 0) {
					now.tv_usec += 1000000;
					now.tv_sec -= 1;
				}
				if (now.tv_sec <= 0 && now.tv_usec <= 0) {
					syslog(LOG_WARNING,
		"__nis_run_dump_callback: Timeout waiting for callback");
					(void) mutex_unlock(&__nis_dump_mutex);
					return (-1);
				}
			}
		} else if (ret != 0) {
			syslog(LOG_WARNING,
		"__nis_run_dump_callback: Error %d from cond_reltimedwait()",
				ret);
			(void) mutex_unlock(&__nis_dump_mutex);
			return (-1);
		}
	}

	if (__cbdata_dump->cberror != 0) {
		count = -(__cbdata_dump->cberror);
	} else {
		count = __nis_dump_cb_count;
	}
	(void) mutex_unlock(&__nis_dump_mutex);

	return (count);
}

/*
 * __do_callback()
 *
 * This is the dispatcher routine for the callback service. It is
 * very simple as you can see.
 */
static void
__do_callback_cbdata(struct svc_req *rqstp, SVCXPRT *transp,
			struct callback_data *__cbdata)
{
	union {
		cback_data 	callback_recieve_1_arg;
		nis_error	callback_error_1_arg;
	} argument;
	int  	result;
	bool_t  do_reply;
	bool_t (*xdr_argument)(), (*xdr_result)();
	bool_t (*local)();

	if (__cbdata == NULL)
		return;

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void, (char *)NULL);
		return;

	case CBPROC_RECEIVE:
		xdr_argument = xdr_cback_data;
		xdr_result = xdr_bool;
		local = __callback_stub;
		(__cbdata->results)++; /* Count callback */
		break;

	case CBPROC_FINISH:
		xdr_argument = xdr_void;
		xdr_result = xdr_void;
		local = __callback_finish;
		break;

	case CBPROC_ERROR:
		xdr_argument = xdr_nis_error;
		xdr_result = xdr_void;
		local = __callback_error;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (char *)&argument)) {
		svcerr_decode(transp);
		return;
	}
	do_reply = (*local)(&argument, rqstp, __cbdata, &result);
	if (do_reply && !svc_sendreply(transp, xdr_result, (char *)&result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (char *)&argument)) {
		syslog(LOG_WARNING, "unable to free arguments");
	}
}

static void
__do_callback(struct svc_req *rqstp, SVCXPRT *transp) {
	__do_callback_cbdata(rqstp, transp, my_cbdata());
}

static void
__do_dump_callback(struct svc_req *rqstp, SVCXPRT *transp) {

	bool_t		complete;
	timestruc_t	timeout = {120, 0};	/* XXX Make configurable */
	int		waitstat = 0;

	/*
	 * Wait until initialization done by nis_dump(), which is
	 * signaled by '__nis_dump_cb_count' having a value >= 0.
	 */
	(void) mutex_lock(&__nis_dump_mutex);
	while (__nis_dump_cb_count < 0 && waitstat == 0) {
		waitstat = cond_reltimedwait(&__nis_dump_cv, &__nis_dump_mutex,
						&timeout);
	}

	/* Check if someone else has decided that we're done */
	if (__cbdata_dump->complete) {
		/*
		 * That "someone else" should have woken up
		 * __nis_run_dump_callback(), so no need to do
		 * anything about __nis_dump_cv.
		 */
		(void) mutex_unlock(&__nis_dump_mutex);
		return;
	} else if (waitstat != 0) {
		syslog(LOG_ERR,
"__do_dump_callback: cond error %d waiting for callback initialization",
			waitstat);
#ifdef	NIS_MT_DEBUG
		abort();
#endif	/* NIS_MT_DEBUG */
		/*
		 * Since our wait for initialization failed,
		 * __nis_run_dump_callback() probably isn't running,
		 * but in order to maximize the chances of recovery,
		 * set completion and wake it up anyway. In any case,
		 * we need to wake up any other instances of this routine
		 * that might be waiting to handle a request.
		 */
		__cbdata_dump->complete = TRUE;
		(void) mutex_unlock(&__nis_dump_mutex);
		(void) cond_broadcast(&__nis_dump_cv);
		return;
	}

	/* Increment the call counter */
	__nis_dump_cb_count++;

	/*
	 * Hold the lock so that we don't have to deal with multiple
	 * instances of the dispatch function.
	 */
	__do_callback_cbdata(rqstp, transp, __cbdata_dump);

	/*
	 * Note time when we ended our activity, so that
	 * __nis_run_dump_callback() knows when it's waited
	 * long enough.
	 */
	(void) gettimeofday(&__nis_dump_lastcb, 0);

	/*
	 * We always unlock the mutex. If the callback is complete, we then
	 * wake up __nis_run_dump_callback(). Since we need to release the
	 * mutex before signaling on the cv (otherwise, we open a window
	 * for dead-lock), we first save the 'complete' status.
	 */
	complete = __cbdata_dump->complete;
	(void) mutex_unlock(&__nis_dump_mutex);
	if (complete)
		(void) cond_broadcast(&__nis_dump_cv);
}
