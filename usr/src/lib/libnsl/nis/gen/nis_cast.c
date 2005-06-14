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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * nis_cast: multicast to a specific group of hosts.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <rpc/rpc.h>
#include <rpc/clnt_soc.h>
#include <rpc/nettype.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpc/pmap_prot.h>  /* for PMAP_CALLIT */

#include <locale.h>
#include <rpcsvc/nis.h>
#include "nis_clnt.h"
#include "nis_local.h"

/*
 *  This is an arbitrary number.  It limits the number of servers
 *  that we can send a request to.  This should be adequate though,
 *  because we only need to get a response from one of these servers.
 */
#define	MAXBCAST 1024

static void set_addresses(nis_bound_directory *, char *);

extern int __nis_debuglevel;

/* A list of connectionless transports */

struct transp {
	struct transp		*tr_next;
	int			tr_fd;
	char			*tr_device;
	char			*tr_protofmly;
	struct t_bind		*tr_taddr;
	char			*uaddr;
};

struct server_addr {
	struct netbuf *sa_taddr;
	struct transp *sa_transp;
};

static struct netbuf *translate_addr(struct netconfig *, endpoint *);
static void free_transports(struct transp *);
static void free_server_addrs(struct server_addr *, int);
extern bool_t xdr_rmtcallargs(XDR *, struct p_rmtcallargs *);

/*
 * __nis_cast_proc(): this provides a pseudo multicast feature where the list of
 * the servers is in the directory object.  Very similar to rpc_broadcast().
 */
enum clnt_stat
__nis_cast_proc(
	nis_bound_directory *binding,
	int base,
	int nbep,
	rpcproc_t procnum,	/* procedure number to call */
	xdrproc_t xdr_inproc,	/* XDR input functions */
	void *in,		/* input argument */
	xdrproc_t xdr_outproc,	/* XDR output functions */
	void *out,		/* output argument */
	int *fastest,		/* return endpoint that responded first */
	int mytimeout)		/* timeout (sec).  Can be 0 for messaging */
{
	enum clnt_stat stat = RPC_SUCCESS;
	AUTH *sys_auth = authsys_create_default();
	XDR xdr_stream, xdr_stream6;
	XDR *xdrs = &xdr_stream, *xdrs6 = &xdr_stream6;
	int outlen, outlen6;
	int flag;
	int sent, addr_cnt, rcvd;
	uint32_t xid;		/* xid - unique per addr */
	int i;
	struct rpc_msg msg, msg6;
	struct timeval tv;
	char outbuf[UDPMSGSIZE], outbuf6[UDPMSGSIZE], inbuf[UDPMSGSIZE];
	struct t_unitdata t_udata, t_rdata;
	struct transp *tr_head;
	struct transp *trans, *prev_trans = NULL;
	struct netconfig *nc;
	int curr, start;
	bool_t done = FALSE;
	int timeout = mytimeout;
	int fd;
	int pingable = 0;
	nis_bound_endpoint *bep;
	nis_server *srv;
	endpoint *ep;
	struct netbuf *taddr;
	struct server_addr *saddrs = 0;
	struct p_rmtcallargs rarg;	/* Remote arguments */
	struct p_rmtcallres rres;	/* Remote results */
	struct r_rpcb_rmtcallargs rarg6;
	struct r_rpcb_rmtcallres rres6;
	struct pollfd pfd[MAXBCAST];    /* list of fd's for poll */
	int fdlistno = 0;		/* number of entries in pfd */
	int pollretval;
	int fds_found;
	char uaddrbuf[INET6_ADDRSTRLEN + sizeof (".255.255")];
					/* large enough for an IPv6 uaddr */

	if (sys_auth == (AUTH *) NULL) {
		stat = RPC_SYSTEMERROR;
		goto done_broad;
	}

	saddrs = (struct server_addr *)calloc(nbep, sizeof (*saddrs));
	if (saddrs == 0) {
		syslog(LOG_ERR, "nis_cast: no memory");
		stat = RPC_CANTSEND;
		goto done_broad;
	}

	addr_cnt = sent = rcvd = 0;
	tr_head = NULL;

	srv = binding->dobj.do_servers.do_servers_val;
	for (i = 0, bep = binding->bep_val + base; i < nbep; i++, bep++) {
		if (bep->flags & NIS_BOUND)
			continue;
		ep = &srv[bep->hostnum].ep.ep_val[bep->epnum];
		nc = __nis_get_netconfig(ep);
		if (nc == 0 ||
		    (nc->nc_flag & NC_VISIBLE) == 0 ||
		    nc->nc_semantics != NC_TPI_CLTS ||
		    (strcmp(nc->nc_protofmly, NC_LOOPBACK) == 0))
			continue;

		if (fdlistno >= MAXBCAST)
			break;	/* no more slots available */

		pingable++;

		trans = (struct transp *)malloc(sizeof (*trans));
		if (trans == NULL) {
			syslog(LOG_ERR, "nis_cast: no memory");
			stat = RPC_CANTSEND;
			goto done_broad;
		}
		(void) memset(trans, 0, sizeof (*trans));
		if (tr_head == NULL)
			tr_head = trans;
		else
			prev_trans->tr_next = trans;
		prev_trans = trans;

		trans->tr_fd = t_open(nc->nc_device, O_RDWR, NULL);
		if (trans->tr_fd < 0) {
			syslog(LOG_ERR, "nis_cast: t_open: %s:%m",
			    nc->nc_device);
			stat = RPC_CANTSEND;
			goto done_broad;
		}
		if (t_bind(trans->tr_fd, (struct t_bind *)NULL,
		    (struct t_bind *)NULL) < 0) {
			syslog(LOG_ERR, "nis_cast: t_bind: %m");
			stat = RPC_CANTSEND;
			goto done_broad;
		}
		trans->tr_taddr =
		    (struct t_bind *)t_alloc(trans->tr_fd, T_BIND, T_ADDR);
		if (trans->tr_taddr == (struct t_bind *)NULL) {
			syslog(LOG_ERR, "nis_cast: t_alloc: %m");
			stat = RPC_SYSTEMERROR;
			goto done_broad;
		}

		trans->tr_device = nc->nc_device;
		trans->tr_protofmly = nc->nc_protofmly;

		pfd[fdlistno].events = POLLIN | POLLPRI | POLLRDNORM |
					POLLRDBAND;
		pfd[fdlistno++].fd = trans->tr_fd;

		trans->uaddr = ep->uaddr;

		taddr = translate_addr(nc, ep);
		if (taddr) {
			saddrs[i].sa_taddr = taddr;
			saddrs[i].sa_transp = trans;
			addr_cnt++;
		}
	}

	/*
	 *  If we didn't find any addresss to send to, then
	 *  syslog an error message.
	 */
	if (addr_cnt == 0) {
		/* only syslog if we actually had some addresses to ping */
		if (pingable)
			syslog(LOG_ERR, "nis_cast: couldn't find addresses");
		stat = RPC_CANTSEND;
		goto done_broad;
	}

	(void) gettimeofday(&tv, (struct timezone *)0);
	xid = (getpid() ^ (uint32_t)tv.tv_sec ^ (uint32_t)tv.tv_usec) & ~0xFF;
	tv.tv_usec = 0;

	/* serialize the RPC header */
	msg.rm_direction = msg6.rm_direction = CALL;
	msg.rm_call.cb_rpcvers = msg6.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	/*
	 * For NC_INET, we must use a portmap version (2) so that we can
	 * speak to 4.X machines and 5.X machines with a single ping packet.
	 */
	msg.rm_call.cb_prog = PMAPPROG;
	msg.rm_call.cb_vers = PMAPVERS;	/* version 2 */
	msg.rm_call.cb_proc = PMAPPROC_CALLIT;

	msg6.rm_call.cb_prog = RPCBPROG;
	msg6.rm_call.cb_vers = RPCBVERS;
	msg6.rm_call.cb_proc = RPCBPROC_CALLIT;

	rarg.prog = NIS_PROG;
	rarg.vers = NIS_VERSION;
	rarg.proc = procnum;
	rarg.args.args_val = in;
	rarg.xdr_args = (xdrproc_t)xdr_inproc;
	rres.res.res_val = out;
	rres.xdr_res = (xdrproc_t)xdr_outproc;

	rarg6.prog = NIS_PROG;
	rarg6.vers = NIS_VERSION;
	rarg6.proc = procnum;
	rarg6.args.args_val = in;
	rarg6.xdr_args = (xdrproc_t)xdr_inproc;
	rres6.results.results_val = out;
	rres6.xdr_res = (xdrproc_t)xdr_outproc;
	rres6.addr = uaddrbuf;

	msg.rm_call.cb_cred = msg6.rm_call.cb_cred = sys_auth->ah_cred;
	msg.rm_call.cb_verf = msg6.rm_call.cb_verf = sys_auth->ah_verf;
	xdrmem_create(xdrs, outbuf, sizeof (outbuf), XDR_ENCODE);
	xdrmem_create(xdrs6, outbuf6, sizeof (outbuf6), XDR_ENCODE);

	if ((! xdr_callmsg(xdrs, &msg)) ||
	    (! xdr_rmtcallargs(xdrs, &rarg))) {
		stat = RPC_CANTENCODEARGS;
		goto done_broad;
	}
	if ((! xdr_callmsg(xdrs6, &msg6)) ||
	    (! xdr_rpcb_rmtcallargs(xdrs6, &rarg6))) {
		stat = RPC_CANTENCODEARGS;
		goto done_broad;
	}

	outlen = (int)xdr_getpos(xdrs);
	xdr_destroy(xdrs);
	outlen6 = (int)xdr_getpos(xdrs6);
	xdr_destroy(xdrs6);

	t_udata.opt.len = 0;

	/*
	 * Basic loop: send packet to all hosts and wait for response(s).
	 * The response timeout grows larger per iteration.
	 * A unique xid is assigned to each address in order to
	 * correctly match the replies.  We allow a timeout of 0 as well to
	 * support one-way messages.
	 */
	for (tv.tv_sec = 3; timeout >= 0; tv.tv_sec += 2) {
		struct rpc_msg	*m;

		timeout -= (int)tv.tv_sec;
		if (timeout < 0)
			tv.tv_sec += timeout;
		sent = 0;
		start = __nis_librand() % nbep;
		for (i = 0; i < nbep; i++) {
			/*
			 *  We randomly choose to go either forward or
			 *  backward through the array so we get better
			 *  behavior on "clumps" of addresses.
			 */
			if (start & 0x1)
				curr = (start+i) % nbep;
			else
				curr = (start + nbep - i) % nbep;

			/*
			 *  We only have 8 bits for the endpoint number
			 *  in the xid, so  we have to stop before 256.
			 */
			if (curr >= 256 || saddrs[curr].sa_taddr == 0)
				continue;

			/*
			 * Put endpoint number in xid.
			 * xid is the first thing in
			 * preserialized buffer
			 */
			t_udata.addr = *(saddrs[curr].sa_taddr);
			fd = saddrs[curr].sa_transp->tr_fd;
			if (strcmp(NC_INET,
				saddrs[curr].sa_transp->tr_protofmly) == 0) {
				*((uint32_t *)outbuf) = htonl(xid + curr);
				t_udata.udata.buf = outbuf;
				t_udata.udata.len = outlen;
			} else {
				*((uint32_t *)outbuf6) = htonl(xid + curr);
				t_udata.udata.buf = outbuf6;
				t_udata.udata.len = outlen6;
			}
			if (t_sndudata(fd, &t_udata) == 0)
				sent++;
		}
		if (sent == 0) {		/* no packets sent ? */
			stat = RPC_CANTSEND;
			goto done_broad;
		}

		if (tv.tv_sec == 0) {
			if (mytimeout == 0)
				/* this could be set for message passing mode */
				stat = RPC_SUCCESS;
			else
				stat = RPC_TIMEDOUT;
			goto done_broad;
		}
		/*
		 * Have sent all the packets.  Now collect the responses...
		 */
		rcvd = 0;
	recv_again:
		msg.acpted_rply.ar_verf = msg6.acpted_rply.ar_verf = _null_auth;

		msg.acpted_rply.ar_results.where = (caddr_t)&rres;
		msg.acpted_rply.ar_results.proc = (xdrproc_t)xdr_rmtcallres;

		msg6.acpted_rply.ar_results.where = (caddr_t)&rres6;
		msg6.acpted_rply.ar_results.proc =
					(xdrproc_t)xdr_rpcb_rmtcallres;

		switch (pollretval = poll(pfd, fdlistno,
		    (int)tv.tv_sec * 1000)) {
		case 0:  /* timed out */
			if (rcvd == 0) {
				stat = RPC_TIMEDOUT;
				continue;
			} else
				goto done_broad;

		case -1:  /* some kind of error */
			if (errno == EINTR)
				goto recv_again;
			syslog(LOG_ERR, "nis_cast: poll: %m");
			if (rcvd == 0)
				stat = RPC_CANTRECV;
			goto done_broad;

		}  /* end of poll results switch */

		/*
		 * Find the trans that corresponds to the first fd
		 * which poll managed to read on.  We take advantage of
		 * the fact that the list of trans and the array pfd
		 * contain the same fd's in the same order.
		 */
		for (i = fds_found = 0, trans = tr_head;
		    i < fdlistno && fds_found < pollretval && trans;
		    i++, trans = trans->tr_next) {

			if (pfd[i].revents  == 0)
				continue; /* nothing on this fd */
			else if (pfd[i].revents & POLLNVAL) {
				/*
				 * Something bad has happened to this
				 * descriptor.  We can cause poll() to
				 * ignore it simply by using a negative
				 * fd.  We do that rather than
				 * compacting the pfd[] array and trans
				 * list.
				 */
				pfd[i].fd = -1;
				fds_found++;
				continue;
			} else
				break;
		}
		if (trans == NULL)
			goto recv_again;

	try_again:
		t_rdata.addr = trans->tr_taddr->addr;
		t_rdata.udata.buf = inbuf;
		t_rdata.udata.maxlen = sizeof (inbuf);
		t_rdata.udata.len = 0;
		t_rdata.opt.len = 0;
		if (t_rcvudata(trans->tr_fd, &t_rdata, &flag) < 0) {
			if (t_errno == TSYSERR && errno == EINTR)
				goto try_again;
			/*
			 * Ignore any T_UDERR look errors.  We should
			 * never see any ICMP port unreachables when
			 * broadcasting but it has been observed with
			 * broken IP implementations.
			 */
			if (t_errno == TLOOK &&
			    t_look(trans->tr_fd) == T_UDERR &&
			    t_rcvuderr(trans->tr_fd, NULL) == 0)
				goto recv_again;

			syslog(LOG_ERR, "nis_cast: t_rcvudata: %s:%m",
			    trans->tr_device);
			stat = RPC_CANTRECV;
			continue;
		}
		if (t_rdata.udata.len < sizeof (uint_t))
			goto recv_again;
		if (flag & T_MORE) {
			syslog(LOG_ERR,
			    "nis_cast: t_rcvudata: %s: buffer overflow",
			    trans->tr_device);
			goto recv_again;
		}
		/*
		 * see if reply transaction id matches sent id.
		 * If so, decode the results.
		 * Note: received addr is ignored, it could be different
		 * from the send addr if the host has more than one addr.
		 */
		xdrmem_create(xdrs, inbuf,
				(uint_t)t_rdata.udata.len, XDR_DECODE);

		m = (strcmp(NC_INET6, trans->tr_protofmly) == 0) ? &msg6 : &msg;
		if (xdr_replymsg(xdrs, m)) {
			if (m->rm_reply.rp_stat == MSG_ACCEPTED &&
			    (m->acpted_rply.ar_stat == SUCCESS)) {
				rcvd++;
				if (fastest) {
					*fastest = m->rm_xid & 0xFF;
					done = 1;
				}
				stat = RPC_SUCCESS;
			}
			/* otherwise, we just ignore the errors ... */
		}
		xdrs->x_op = XDR_FREE;
		m->acpted_rply.ar_results.proc = xdr_void;
		(void) (*xdr_outproc)(xdrs, out);
		(void) xdr_replymsg(xdrs, m);
		XDR_DESTROY(xdrs);
		if (done)
			goto done_broad;
		else
			goto recv_again;
	}
	if (!rcvd)
		stat = RPC_TIMEDOUT;

done_broad:
	free_transports(tr_head);
	free_server_addrs(saddrs, nbep);
	AUTH_DESTROY(sys_auth);
	return (stat);
}

static void
free_transports(struct transp *trans)
{
	struct transp *t, *tmpt;

	for (t = trans; t; t = tmpt) {
		if (t->tr_taddr)
			(void) t_free((char *)t->tr_taddr, T_BIND);
		if (t->tr_fd >= 0)
			(void) t_close(t->tr_fd);
		tmpt = t->tr_next;
		free(t);
	}
}


static void
free_server_addrs(struct server_addr *saddrs, int n)
{
	int i;

	if (saddrs == 0)
		return;

	for (i = 0; i < n; i++) {
		if (saddrs[i].sa_taddr)
			netdir_free((char *)saddrs[i].sa_taddr, ND_ADDR);
	}
	free(saddrs);
}

static
struct netbuf *
translate_addr(struct netconfig *nconf, endpoint *ep)
{
	struct netbuf *taddr = 0;

	taddr = uaddr2taddr(nconf, ep->uaddr);
	if (taddr == NULL) {
		syslog(LOG_ERR,
			"translate_addr: uaddr2taddr: %s (%d).",
			ep->uaddr, _nderror);
		return (0);
	}
	return (taddr);
}


int
__nis_server_is_local(endpoint *ep, void *local)
{
	int answer = 0;
	struct netconfig *nc;

	nc = __nis_get_netconfig(ep);
	if (__inet_uaddr_is_local(local, nc, ep->uaddr)) {
		answer = 1;
	}
	return (answer);
}

static
enum clnt_stat
ping_endpoints(nis_bound_directory *binding, int start, int end, int *fastest)
{
	int count;
	enum clnt_stat st;

	count = end - start;
	st = __nis_cast_proc(binding, start, count, NULLPROC,
			xdr_void, (void *)NULL,
			xdr_void, (void *)NULL,
			fastest, NIS_PING_TIMEOUT);
	if (st == RPC_SUCCESS)
		*fastest += start;
	return (st);
}

/*
 *  The MIN_ACTIVE define sets the minimum number of endpoints we
 *  want to have avaialable.  It is set to twice the number of
 *  servers because each server has a tcp endpoint and udp endpoint.
 *  This is really just a heuristic right now, because we don't
 *  even check that we have separate servers rather than different
 *  interfaces on a multi-homed server.
 */

#define	MIN_ACTIVE 4	/* minimum number of active servers we want */

nis_error
__nis_ping_servers(nis_bound_directory *binding, int max_rank, int quick)
{
	int i;
	int base;
	int scan;
	int nbep;
	int active_count = 0;
	int new_active;
	int min_active;
	int fastest;
	endpoint *ep;
	nis_bound_endpoint *bep;
	enum clnt_stat st = RPC_TIMEDOUT;
	nis_error err = NIS_SUCCESS;

	if (quick)
		min_active = 1;
	else
		min_active = MIN_ACTIVE;
	bep = binding->bep_val;
	nbep = binding->bep_len;
	for (base = scan = 0; base < nbep && bep[base].rank <= max_rank;
		base = scan) {
		new_active = 0;
		while (scan < nbep && bep[scan].rank == bep[base].rank) {
			if (bep[scan].flags & NIS_BOUND)
				new_active++;
			scan++;
		}
		/* see if we have enough active servers before pinging */
		if (active_count + new_active >= min_active)
			break;

		st = ping_endpoints(binding, base, scan, &fastest);
		if (st == RPC_SUCCESS) {
			ep = __get_bound_endpoint(binding, fastest);
			set_addresses(binding, ep->uaddr);
			break;
		}
		for (i = base; i < scan; i++)
			if (bep[i].flags & NIS_BOUND)
				active_count++;

		/* see if we have enough active servers now */
		if (active_count >= min_active)
			break;
	}
	if (base == nbep && st == RPC_TIMEDOUT)
		err = NIS_NAMEUNREACHABLE;
	return (err);
}

/*
 *  Call the portmapper for each bound endpoint and get the
 *  server's transport address.
 */
static
void
set_addresses(nis_bound_directory *binding, char *uaddr)
{
	int i;
	char *u;
	struct netconfig *nc;
	endpoint *ep;
	nis_bound_endpoint *bep;
	nis_server *srv = binding->dobj.do_servers.do_servers_val;

	for (i = 0; i < binding->bep_len; i++) {
		bep = &binding->bep_val[i];
		ep = &srv[bep->hostnum].ep.ep_val[bep->epnum];
		if (strcmp(ep->uaddr, uaddr) == 0) {
			nc = __nis_get_netconfig(ep);
			if (nc == 0 || (nc->nc_flag & NC_VISIBLE) == 0)
				continue;
			bep->flags = NIS_BOUND;
			u = __nis_get_server_address(nc, ep);
			if (u)
				bep->uaddr = u;
			else
				bep->flags &= ~NIS_BOUND;
		}
	}
}
