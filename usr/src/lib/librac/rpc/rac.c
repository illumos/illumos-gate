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
 * rac.c
 */

#include	<sys/select.h>
#include	<sys/types.h>
#include	<rpc/trace.h>
#include	<sys/time.h>
#include	<sys/poll.h>
#include	<rpc/rpc.h>
#include	<rpc/rac.h>
#include	"rac_private.h"
#include 	<rpc/nettype.h>
#include 	<sys/param.h>
#include 	<sys/mkdev.h>
#include 	<sys/stat.h>
#include 	<ctype.h>
#include 	<sys/resource.h>
#include 	<netconfig.h>
#include 	<malloc.h>
#include 	<string.h>

struct rpc_err	rac_senderr;

void
rac_drop(CLIENT *cl, void *h)
{
	(void) clnt_control(cl, CLRAC_DROP, (char *)h);
}

enum clnt_stat
rac_poll(CLIENT *cl, void *h)
{
	return ((enum clnt_stat) clnt_control(cl, CLRAC_POLL, (char *)h));
}

enum clnt_stat
rac_recv(CLIENT *cl, void *h)
{
	return ((enum clnt_stat) clnt_control(cl, CLRAC_RECV, (char *)h));
}

void *
rac_send(CLIENT *cl, rpcproc_t proc, xdrproc_t xargs, void *argsp,
    xdrproc_t xresults, void *resultsp, struct timeval timeout)
{
	struct rac_send_req	req;

	req.proc = proc;
	req.xargs = xargs;
	req.argsp = argsp;
	req.xresults = xresults;
	req.resultsp = resultsp;
	req.timeout = timeout;
	req.handle = 0;

	(void) clnt_control(cl, CLRAC_SEND, (char *)&req);

	return (req.handle);
}

/* Some utility functions for use by rpc */

/*
 * Cache the result of getrlimit(), so we don't have to do an
 * expensive call every time.
 */
int
__rpc_dtbsize()
{
	static int tbsize = 0;
	struct rlimit rl;

	if (tbsize) {
		return (tbsize);
	}
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		return (tbsize = rl.rlim_max);
	}
	/*
	 * Something wrong.  I'll try to save face by returning a
	 * pessimistic number.
	 */
	return (32);
}

/*
 * Find the appropriate buffer size
 */
uint_t
__rpc_get_t_size(t_scalar_t size, t_scalar_t bufsize)
{
	if (bufsize == -2) {
		/* transfer of data unsupported */
		return ((uint_t)0);
	}
	if (size == 0) {
		if ((bufsize == -1) || (bufsize == 0)) {
			/*
			 * bufsize == -1 : No limit on the size
			 * bufsize == 0 : Concept of tsdu foreign. Choose
			 *			a value.
			 */
			return ((uint_t)RPC_MAXDATASIZE);
		} else {
			return ((uint_t)bufsize);
		}
	}
	if ((bufsize == -1) || (bufsize == 0)) {
		return ((uint_t)size);
	}
	/* Check whether the value is within the upper max limit */
	return (size > bufsize ? (uint_t)bufsize : (uint_t)size);
}

/*
 * Find the appropriate address buffer size
 */
uint_t
__rpc_get_a_size(t_scalar_t size)
{
	if (size >= 0) {
		return ((uint_t)size);
	}
	if (size <= -2) {
		return ((uint_t)0);
	}
	/*
	 * (size == -1) No limit on the size. we impose a limit here.
	 */
	return ((uint_t)RPC_MAXADDRSIZE);
}


/*
 * For the given nettype (tcp or udp only), return the first structure found.
 * This should be freed by calling freenetconfigent()
 */
struct netconfig *
__rpc_getconfip(char *nettype)
{
	char *netid;
	static char *netid_tcp;
	static char *netid_udp;
	struct netconfig *dummy;

	if (!netid_udp && !netid_tcp) {
		struct netconfig *nconf;
		void *confighandle;

		if (!(confighandle = setnetconfig())) {
			return (NULL);
		}
		while (nconf = getnetconfig(confighandle)) {
			if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
				if (strcmp(nconf->nc_proto, NC_TCP) == 0)
					netid_tcp = strdup(nconf->nc_netid);
				else if (strcmp(nconf->nc_proto, NC_UDP) == 0)
					netid_udp = strdup(nconf->nc_netid);
			}
		}
		(void) endnetconfig(confighandle);
	}
	if (strcmp(nettype, "udp") == 0)
		netid = netid_udp;
	else if (strcmp(nettype, "tcp") == 0)
		netid = netid_tcp;
	else {
		return ((struct netconfig *)NULL);
	}
	if ((netid == NULL) || (netid[0] == NULL)) {
		return ((struct netconfig *)NULL);
	}
	dummy = getnetconfigent(netid);
	return (dummy);
}

struct handle {
	NCONF_HANDLE *nhandle;
	int nflag;		/* Whether NETPATH or NETCONFIG */
	int nettype;
};

struct _rpcnettype {
	const char *name;
	const int type;
} _rpctypelist[] = {
	"netpath", _RPC_NETPATH,
	"visible", _RPC_VISIBLE,
	"circuit_v", _RPC_CIRCUIT_V,
	"datagram_v", _RPC_DATAGRAM_V,
	"circuit_n", _RPC_CIRCUIT_N,
	"datagram_n", _RPC_DATAGRAM_N,
	"tcp", _RPC_TCP,
	"udp", _RPC_UDP,
	0, _RPC_NONE
};

static char *
strlocase(char *p)
{
	char *t = p;

	for (; *p; p++)
		if (isupper(*p))
			*p = tolower(*p);
	return (t);
}

/*
 * Returns the type of the network as defined in <rpc/nettype.h>
 * If nettype is NULL, it defaults to NETPATH.
 */
static int
getnettype(char *nettype)
{
	int i;

	if ((nettype == NULL) || (nettype[0] == NULL)) {
		return (_RPC_NETPATH);	/* Default */
	}

	nettype = strlocase(nettype);
	for (i = 0; _rpctypelist[i].name; i++)
		if (strcmp(nettype, _rpctypelist[i].name) == 0) {
			return (_rpctypelist[i].type);
		}
	return (_rpctypelist[i].type);
}

/*
 * Returns the type of the nettype, which should then be used with
 * __rpc_getconf().
 */
void *
__rpc_setconf(char *nettype)
{
	struct handle *handle;

	handle = (struct handle *)malloc(sizeof (struct handle));
	if (handle == NULL) {
		return (NULL);
	}
	switch (handle->nettype = getnettype(nettype)) {
	case _RPC_NETPATH:
	case _RPC_CIRCUIT_N:
	case _RPC_DATAGRAM_N:
		if (!(handle->nhandle = setnetpath())) {
			free(handle);
			return (NULL);
		}
		handle->nflag = TRUE;
		break;
	case _RPC_VISIBLE:
	case _RPC_CIRCUIT_V:
	case _RPC_DATAGRAM_V:
	case _RPC_TCP:
	case _RPC_UDP:
		if (!(handle->nhandle = setnetconfig())) {
			free(handle);
			return (NULL);
		}
		handle->nflag = FALSE;
		break;
	default:
		return (NULL);
	}
	return (handle);
}

/*
 * Returns the next netconfig struct for the given "net" type.
 * __rpc_setconf() should have been called previously.
 */
struct netconfig *
__rpc_getconf(void *vhandle)
{
	struct handle *handle;
	struct netconfig *nconf;

	handle = (struct handle *)vhandle;
	if (handle == NULL) {
		return (NULL);
	}
	/* CONSTCOND */
	while (1) {
		if (handle->nflag)
			nconf = getnetpath(handle->nhandle);
		else
			nconf = getnetconfig(handle->nhandle);
		if (nconf == (struct netconfig *)NULL)
			break;
		if ((nconf->nc_semantics != NC_TPI_CLTS) &&
			(nconf->nc_semantics != NC_TPI_COTS) &&
			(nconf->nc_semantics != NC_TPI_COTS_ORD))
			continue;
		switch (handle->nettype) {
		case _RPC_VISIBLE:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			/* FALLTHRU */
		case _RPC_NETPATH:	/* Be happy */
			break;
		case _RPC_CIRCUIT_V:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			/* FALLTHRU */
		case _RPC_CIRCUIT_N:
			if ((nconf->nc_semantics != NC_TPI_COTS) &&
				(nconf->nc_semantics != NC_TPI_COTS_ORD))
				continue;
			break;
		case _RPC_DATAGRAM_V:
			if (!(nconf->nc_flag & NC_VISIBLE))
				continue;
			/* FALLTHRU */
		case _RPC_DATAGRAM_N:
			if (nconf->nc_semantics != NC_TPI_CLTS)
				continue;
			break;
		case _RPC_TCP:
			if (((nconf->nc_semantics != NC_TPI_COTS) &&
				(nconf->nc_semantics != NC_TPI_COTS_ORD)) ||
				strcmp(nconf->nc_protofmly, NC_INET) ||
				strcmp(nconf->nc_proto, NC_TCP))
				continue;
			break;
		case _RPC_UDP:
			if ((nconf->nc_semantics != NC_TPI_CLTS) ||
				strcmp(nconf->nc_protofmly, NC_INET) ||
				strcmp(nconf->nc_proto, NC_UDP))
				continue;
			break;
		}
		break;
	}
	return (nconf);
}

void
__rpc_endconf(void *vhandle)
{
	struct handle *handle;

	handle = (struct handle *)vhandle;
	if (handle == NULL) {
		return;
	}
	if (handle->nflag) {
		(void) endnetpath(handle->nhandle);
	} else {
		(void) endnetconfig(handle->nhandle);
	}
	free(handle);

}

#define	MASKVAL	(POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)

/*
 *	Given an fd_set pointer and the number of bits to check in it,
 *	initialize the supplied pollfd array for RPC's use (RPC only
 *	polls for input events).  We return the number of pollfd slots
 *	we initialized.
 */
int
__rpc_select_to_poll(int fdmax, fd_set *fdset, struct pollfd *p0)
{
	/* register declarations ordered by expected frequency of use */
	register long *in;
	register int j;		/* loop counter */
	register ulong_t b;	/* bits to test */
	register int n;
	register struct pollfd	*p = p0;

	/*
	 * For each fd, if the appropriate bit is set convert it into
	 * the appropriate pollfd struct.
	 */
	for (in = fdset->fds_bits, n = 0; n < fdmax; n += NFDBITS, in++)
		for (b = (uint_t)*in, j = 0; b; j++, b >>= 1)
			if (b & 1) {
				p->fd = n + j;
				if (p->fd >= fdmax) {
					return (p - p0);
				}
				p->events = MASKVAL;
				p++;
			}

	return (p - p0);
}

/*
 *	Convert from timevals (used by select) to milliseconds (used by poll).
 */
int
__rpc_timeval_to_msec(struct timeval *t)
{
	int	t1, tmp;

	/*
	 *	We're really returning t->tv_sec * 1000 + (t->tv_usec / 1000)
	 *	but try to do so efficiently.  Note:  1000 = 1024 - 16 - 8.
	 */
	tmp = ((int)t->tv_sec << 3);
	t1 = -tmp;
	t1 += t1 << 1;
	t1 += tmp << 7;
	if (t->tv_usec)
		t1 += t->tv_usec / 1000;

	return (t1);
}

/* ************************** Client utility routine ************* */

static void
accepted(enum accept_stat acpt_stat, struct rpc_err *error)
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
rejected(enum reject_stat rjct_stat, struct rpc_err *error)
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
__seterr_reply(struct rpc_msg *msg, struct rpc_err *error)
{
	/* optimized for normal, SUCCESSful case */
	switch (msg->rm_reply.rp_stat) {
	case MSG_ACCEPTED:
		if (msg->acpted_rply.ar_stat == SUCCESS) {
			error->re_status = RPC_SUCCESS;
			return;
		};
		accepted(msg->acpted_rply.ar_stat, error);
		break;

	case MSG_DENIED:
		rejected(msg->rjcted_rply.rj_stat, error);
		break;

	default:
		error->re_status = RPC_FAILED;
		error->re_lb.s1 = msg->rm_reply.rp_stat;
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
}
