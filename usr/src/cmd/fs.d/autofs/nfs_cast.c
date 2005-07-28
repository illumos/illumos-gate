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
 *	nfs_cast.c : broadcast to a specific group of NFS servers
 *
 *      Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 *      Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/clnt_soc.h>
#include <rpc/nettype.h>
#include <rpc/pmap_prot.h>
#include <netconfig.h>
#include <netdir.h>
#include <nfs/nfs.h>
#define	NFSCLIENT
#include <locale.h>
#include "automount.h"

#define	PENALTY_WEIGHT    100000

struct tstamps {
	struct tstamps	*ts_next;
	int		ts_penalty;
	int		ts_inx;
	int		ts_rcvd;
	struct timeval	ts_timeval;
};

/* A list of addresses - all belonging to the same transport */

struct addrs {
	struct addrs		*addr_next;
	struct mapfs		*addr_mfs;
	struct nd_addrlist	*addr_addrs;
	struct tstamps		*addr_if_tstamps;
};

/* A list of connectionless transports */

struct transp {
	struct transp		*tr_next;
	int			tr_fd;
	char			*tr_device;
	struct t_bind		*tr_taddr;
	struct addrs		*tr_addrs;
};

/* A list of map entries and their roundtrip times, for sorting */

struct sm {
	struct mapfs *mfs;
	struct timeval timeval;
};

static void free_transports(struct transp *);
static void calc_resp_time(struct timeval *);
static struct mapfs *sort_responses(struct transp *);
static int host_sm(const void *, const void *b);
static int time_sm(const void *, const void *b);
extern struct mapfs *add_mfs(struct mapfs *, int, struct mapfs **,
	struct mapfs **);

/*
 * This routine is designed to be able to "ping"
 * a list of hosts and create a list of responding
 * hosts sorted by response time.
 * This must be done without any prior
 * contact with the host - therefore the "ping"
 * must be to a "well-known" address.  The outstanding
 * candidate here is the address of "rpcbind".
 *
 * A response to a ping is no guarantee that the host
 * is running NFS, has a mount daemon, or exports
 * the required filesystem.  If the subsequent
 * mount attempt fails then the host will be marked
 * "ignore" and the host list will be re-pinged
 * (sans the bad host). This process continues
 * until a successful mount is achieved or until
 * there are no hosts left to try.
 */
enum clnt_stat
nfs_cast(struct mapfs *mfs_in, struct mapfs **mfs_out, int timeout)
{
	enum clnt_stat stat;
	AUTH *sys_auth = authsys_create_default();
	XDR xdr_stream;
	register XDR *xdrs = &xdr_stream;
	int outlen;
	int if_inx;
	int tsec;
	int flag;
	int sent, addr_cnt, rcvd, if_cnt;
	fd_set readfds, mask;
	register ulong_t xid;		/* xid - unique per addr */
	register int i;
	struct rpc_msg msg;
	struct timeval t, rcv_timeout;
	char outbuf[UDPMSGSIZE], inbuf[UDPMSGSIZE];
	struct t_unitdata t_udata, t_rdata;
	struct nd_hostserv hs;
	struct nd_addrlist *retaddrs;
	struct transp *tr_head;
	struct transp *trans, *prev_trans;
	struct addrs *a, *prev_addr;
	struct tstamps *ts, *prev_ts;
	NCONF_HANDLE *nc = NULL;
	struct netconfig *nconf;
	struct rlimit rl;
	int dtbsize;
	struct mapfs *mfs;

	/*
	 * For each connectionless transport get a list of
	 * host addresses.  Any single host may have
	 * addresses on several transports.
	 */
	addr_cnt = sent = rcvd = 0;
	tr_head = NULL;
	FD_ZERO(&mask);

	/*
	 * Set the default select size to be the maximum FD_SETSIZE, unless
	 * the current rlimit is lower.
	 */
	dtbsize = FD_SETSIZE;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		if (rl.rlim_cur < FD_SETSIZE)
			dtbsize = rl.rlim_cur;
	}

	prev_trans = NULL;
	prev_addr = NULL;
	prev_ts = NULL;
	for (mfs = mfs_in; mfs; mfs = mfs->mfs_next) {

		if (trace > 2)
			trace_prt(1, "nfs_cast: host=%s\n", mfs->mfs_host);

		nc = setnetconfig();
		if (nc == NULL) {
			stat = RPC_CANTSEND;
			goto done_broad;
		}
		while (nconf = getnetconfig(nc)) {
			if (!(nconf->nc_flag & NC_VISIBLE) ||
			    nconf->nc_semantics != NC_TPI_CLTS ||
			    (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0))
				continue;
			trans = (struct transp *)malloc(sizeof (*trans));
			if (trans == NULL) {
				syslog(LOG_ERR, "no memory");
				stat = RPC_CANTSEND;
				goto done_broad;
			}
			(void) memset(trans, 0, sizeof (*trans));
			if (tr_head == NULL)
				tr_head = trans;
			else
				prev_trans->tr_next = trans;
			prev_trans = trans;

			trans->tr_fd = t_open(nconf->nc_device, O_RDWR, NULL);
			if (trans->tr_fd < 0) {
				syslog(LOG_ERR, "nfscast: t_open: %s:%m",
					nconf->nc_device);
				stat = RPC_CANTSEND;
				goto done_broad;
			}
			if (t_bind(trans->tr_fd, (struct t_bind *)NULL,
				(struct t_bind *)NULL) < 0) {
				syslog(LOG_ERR, "nfscast: t_bind: %m");
				stat = RPC_CANTSEND;
				goto done_broad;
			}
			trans->tr_taddr =
				/* LINTED pointer alignment */
			(struct t_bind *)t_alloc(trans->tr_fd, T_BIND, T_ADDR);
			if (trans->tr_taddr == (struct t_bind *)NULL) {
				syslog(LOG_ERR, "nfscast: t_alloc: %m");
				stat = RPC_SYSTEMERROR;
				goto done_broad;
			}

			trans->tr_device = nconf->nc_device;
			FD_SET(trans->tr_fd, &mask);

			if_inx = 0;
			hs.h_host = mfs->mfs_host;
			hs.h_serv = "rpcbind";
			if (netdir_getbyname(nconf, &hs, &retaddrs) == ND_OK) {

				/*
				 * If mfs->ignore is previously set for
				 * this map, clear it. Because a host can
				 * have either v6 or v4 address
				 */
				if (mfs->mfs_ignore == 1)
					mfs->mfs_ignore = 0;

				a = (struct addrs *)malloc(sizeof (*a));
				if (a == NULL) {
					syslog(LOG_ERR, "no memory");
					stat = RPC_CANTSEND;
					goto done_broad;
				}
				(void) memset(a, 0, sizeof (*a));
				if (trans->tr_addrs == NULL)
					trans->tr_addrs = a;
				else
					prev_addr->addr_next = a;
				prev_addr = a;
				a->addr_if_tstamps = NULL;
				a->addr_mfs = mfs;
				a->addr_addrs = retaddrs;
				if_cnt = retaddrs->n_cnt;
				while (if_cnt--) {
					ts = (struct tstamps *)
						malloc(sizeof (*ts));
					if (ts == NULL) {
						syslog(LOG_ERR, "no memory");
						stat = RPC_CANTSEND;
						goto done_broad;
					}
					(void) memset(ts, 0, sizeof (*ts));
					ts->ts_penalty = mfs->mfs_penalty;
					if (a->addr_if_tstamps == NULL)
						a->addr_if_tstamps = ts;
					else
						prev_ts->ts_next = ts;
					prev_ts = ts;
					ts->ts_inx = if_inx++;
					addr_cnt++;
				}
				break;
			} else {
				mfs->mfs_ignore = 1;
				if (verbose)
					syslog(LOG_ERR,
				"%s:%s address not known",
				mfs->mfs_host,
				strcmp(nconf->nc_proto, NC_INET)?"IPv6":"IPv4");
			}
		} /* while */

		endnetconfig(nc);
		nc = NULL;
	} /* for */
	if (addr_cnt == 0) {
		syslog(LOG_ERR, "nfscast: couldn't find addresses");
		stat = RPC_CANTSEND;
		goto done_broad;
	}

	(void) gettimeofday(&t, (struct timezone *)0);
	xid = (getpid() ^ t.tv_sec ^ t.tv_usec) & ~0xFF;
	t.tv_usec = 0;

	/* serialize the RPC header */

	msg.rm_direction = CALL;
	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	msg.rm_call.cb_prog = RPCBPROG;
	/*
	 * we can not use RPCBVERS here since it doesn't exist in 4.X,
	 * the fix to bug 1139883 has made the 4.X portmapper silent to
	 * version mismatches. This causes the RPC call to the remote
	 * portmapper to simply be ignored if it's not Version 2.
	 */
	msg.rm_call.cb_vers = PMAPVERS;
	msg.rm_call.cb_proc = NULLPROC;
	if (sys_auth == (AUTH *)NULL) {
		stat = RPC_SYSTEMERROR;
		goto done_broad;
	}
	msg.rm_call.cb_cred = sys_auth->ah_cred;
	msg.rm_call.cb_verf = sys_auth->ah_verf;
	xdrmem_create(xdrs, outbuf, sizeof (outbuf), XDR_ENCODE);
	if (! xdr_callmsg(xdrs, &msg)) {
		stat = RPC_CANTENCODEARGS;
		goto done_broad;
	}
	outlen = (int)xdr_getpos(xdrs);
	xdr_destroy(xdrs);

	t_udata.opt.len = 0;
	t_udata.udata.buf = outbuf;
	t_udata.udata.len = outlen;

	/*
	 * Basic loop: send packet to all hosts and wait for response(s).
	 * The response timeout grows larger per iteration.
	 * A unique xid is assigned to each address in order to
	 * correctly match the replies.
	 */
	for (tsec = 4; timeout > 0; tsec *= 2) {

		timeout -= tsec;
		if (timeout <= 0)
			tsec += timeout;

		rcv_timeout.tv_sec = tsec;
		rcv_timeout.tv_usec = 0;

		sent = 0;
		for (trans = tr_head; trans; trans = trans->tr_next) {
			for (a = trans->tr_addrs; a; a = a->addr_next) {
				struct netbuf *if_netbuf =
					a->addr_addrs->n_addrs;
				ts = a->addr_if_tstamps;
				if_cnt = a->addr_addrs->n_cnt;
				while (if_cnt--) {

					/*
					 * xid is the first thing in
					 * preserialized buffer
					 */
					/* LINTED pointer alignment */
					*((ulong_t *)outbuf) =
						htonl(xid + ts->ts_inx);
					(void) gettimeofday(&(ts->ts_timeval),
						(struct timezone *)0);
					/*
					 * Check if already received
					 * from a previous iteration.
					 */
					if (ts->ts_rcvd) {
						sent++;
						ts = ts->ts_next;
						continue;
					}

					t_udata.addr = *if_netbuf++;

					if (t_sndudata(trans->tr_fd,
							&t_udata) == 0) {
						sent++;
					}

					ts = ts->ts_next;
				}
			}
		}
		if (sent == 0) {		/* no packets sent ? */
			stat = RPC_CANTSEND;
			goto done_broad;
		}

		/*
		 * Have sent all the packets.  Now collect the responses...
		 */
		rcvd = 0;
	recv_again:
		msg.acpted_rply.ar_verf = _null_auth;
		msg.acpted_rply.ar_results.proc = xdr_void;
		readfds = mask;

		switch (select(dtbsize, &readfds,
			(fd_set *)NULL, (fd_set *)NULL, &rcv_timeout)) {

		case 0: /* Timed out */
			/*
			 * If we got at least one response in the
			 * last interval, then don't wait for any
			 * more.  In theory we should wait for
			 * the max weighting (penalty) value so
			 * that a very slow server has a chance to
			 * respond but this could take a long time
			 * if the admin has set a high weighting
			 * value.
			 */
			if (rcvd > 0)
				goto done_broad;

			stat = RPC_TIMEDOUT;
			continue;

		case -1:  /* some kind of error */
			if (errno == EINTR)
				goto recv_again;
			syslog(LOG_ERR, "nfscast: select: %m");
			if (rcvd == 0)
				stat = RPC_CANTRECV;
			goto done_broad;

		}  /* end of select results switch */

		for (trans = tr_head; trans; trans = trans->tr_next) {
			if (FD_ISSET(trans->tr_fd, &readfds))
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
			if (errno == EINTR)
				goto try_again;
			syslog(LOG_ERR, "nfscast: t_rcvudata: %s:%m",
				trans->tr_device);
			stat = RPC_CANTRECV;
			continue;
		}
		if (t_rdata.udata.len < sizeof (ulong_t))
			goto recv_again;
		if (flag & T_MORE) {
			syslog(LOG_ERR,
				"nfscast: t_rcvudata: %s: buffer overflow",
				trans->tr_device);
			goto recv_again;
		}

		/*
		 * see if reply transaction id matches sent id.
		 * If so, decode the results.
		 * Note: received addr is ignored, it could be
		 * different from the send addr if the host has
		 * more than one addr.
		 */
		xdrmem_create(xdrs, inbuf, (uint_t)t_rdata.udata.len,
								XDR_DECODE);
		if (xdr_replymsg(xdrs, &msg)) {
		    if (msg.rm_reply.rp_stat == MSG_ACCEPTED &&
			(msg.rm_xid & ~0xFF) == xid) {
			struct addrs *curr_addr;

			i = msg.rm_xid & 0xFF;
			for (curr_addr = trans->tr_addrs; curr_addr;
			    curr_addr = curr_addr->addr_next) {
			    for (ts = curr_addr->addr_if_tstamps; ts;
				ts = ts->ts_next)
				if (ts->ts_inx == i && !ts->ts_rcvd) {
					ts->ts_rcvd = 1;
					calc_resp_time(&ts->ts_timeval);
					stat = RPC_SUCCESS;
					rcvd++;
					break;
				}
			}
		    } /* otherwise, we just ignore the errors ... */
		}
		xdrs->x_op = XDR_FREE;
		msg.acpted_rply.ar_results.proc = xdr_void;
		(void) xdr_replymsg(xdrs, &msg);
		XDR_DESTROY(xdrs);
		if (rcvd == sent)
			goto done_broad;
		else
			goto recv_again;
	}
	if (!rcvd)
		stat = RPC_TIMEDOUT;

done_broad:
	if (rcvd) {
		*mfs_out = sort_responses(tr_head);
		stat = RPC_SUCCESS;
	}
	if (nc)
		endnetconfig(nc);
	free_transports(tr_head);
	AUTH_DESTROY(sys_auth);
	return (stat);
}

/*
 * Go through all the responses and sort fastest to slowest.
 * Note that any penalty is added to the response time - so the
 * fastest response isn't necessarily the one that arrived first.
 */
static struct mapfs *
sort_responses(trans)
	struct transp *trans;
{
	struct transp *t;
	struct addrs *a;
	struct tstamps *ti;
	int i, size = 0, allocsize = 10;
	struct mapfs *p, *mfs_head = NULL, *mfs_tail = NULL;
	struct sm *buffer;

	buffer = (struct sm *)malloc(allocsize * sizeof (struct sm));
	if (!buffer) {
		syslog(LOG_ERR, "sort_responses: malloc error.\n");
		return (NULL);
	}

	for (t = trans; t; t = t->tr_next) {
		for (a = t->tr_addrs; a; a = a->addr_next) {
			for (ti = a->addr_if_tstamps;
				ti; ti = ti->ts_next) {
				if (!ti->ts_rcvd)
					continue;
				ti->ts_timeval.tv_usec +=
					(ti->ts_penalty * PENALTY_WEIGHT);
				if (ti->ts_timeval.tv_usec >= 1000000) {
					ti->ts_timeval.tv_sec +=
					(ti->ts_timeval.tv_usec / 1000000);
					ti->ts_timeval.tv_usec =
					(ti->ts_timeval.tv_usec % 1000000);
				}

				if (size >= allocsize) {
					allocsize += 10;
					buffer = (struct sm *)realloc(buffer,
					    allocsize * sizeof (struct sm));
					if (!buffer) {
						syslog(LOG_ERR,
					    "sort_responses: malloc error.\n");
						return (NULL);
					}
				}
				buffer[size].timeval = ti->ts_timeval;
				buffer[size].mfs = a->addr_mfs;
				size++;
			}
		}
	}

#ifdef DEBUG
	if (trace > 3) {
		trace_prt(1, "  sort_responses: before host sort:\n");
		for (i = 0; i < size; i++)
			trace_prt(1, "    %s %d.%d\n", buffer[i].mfs->mfs_host,
			buffer[i].timeval.tv_sec, buffer[i].timeval.tv_usec);
		trace_prt(0, "\n");
	}
#endif

	qsort((void *)buffer, size, sizeof (struct sm), host_sm);

	/*
	 * Cope with multiply listed hosts  by choosing first time
	 */
	for (i = 1; i < size; i++) {
#ifdef DEBUG
		if (trace > 3) {
			trace_prt(1, "  sort_responses: comparing %s and %s\n",
				buffer[i-1].mfs->mfs_host,
				buffer[i].mfs->mfs_host);
		}
#endif
		if (strcmp(buffer[i-1].mfs->mfs_host,
		    buffer[i].mfs->mfs_host) == 0)
			memcpy(&buffer[i].timeval, &buffer[i-1].timeval,
				sizeof (struct timeval));
	}
	if (trace > 3)
		trace_prt(0, "\n");

#ifdef DEBUG
	if (trace > 3) {
		trace_prt(1, "  sort_responses: before time sort:\n");
		for (i = 0; i < size; i++)
			trace_prt(1, "    %s %d.%d\n", buffer[i].mfs->mfs_host,
			buffer[i].timeval.tv_sec, buffer[i].timeval.tv_usec);
		trace_prt(0, "\n");
	}
#endif

	qsort((void *)buffer, size, sizeof (struct sm), time_sm);

#ifdef DEBUG
	if (trace > 3) {
		trace_prt(1, "  sort_responses: after sort:\n");
		for (i = 0; i < size; i++)
			trace_prt(1, "    %s %d.%d\n", buffer[i].mfs->mfs_host,
			buffer[i].timeval.tv_sec, buffer[i].timeval.tv_usec);
		trace_prt(0, "\n");
	}
#endif

	for (i = 0; i < size; i++) {
#ifdef DEBUG
		if (trace > 3) {
			trace_prt(1, "  sort_responses: adding %s\n",
				buffer[i].mfs->mfs_host);
		}
#endif
		p = add_mfs(buffer[i].mfs, 0, &mfs_head, &mfs_tail);
		if (!p)
			return (NULL);
	}
	free(buffer);

	return (mfs_head);
}


/*
 * Comparison routines called by qsort(3).
 */
static int host_sm(const void *a, const void *b)
{
	return (strcmp(((struct sm *)a)->mfs->mfs_host,
			((struct sm *)b)->mfs->mfs_host));
}

static int time_sm(const void *a, const void *b)
{
	if (timercmp(&(((struct sm *)a)->timeval),
	    &(((struct sm *)b)->timeval), < /* cstyle */))
		return (-1);
	else if (timercmp(&(((struct sm *)a)->timeval),
	    &(((struct sm *)b)->timeval), > /* cstyle */))
		return (1);
	else
		return (0);
}

/*
 * Given send_time which is the time a request
 * was transmitted to a server, subtract it
 * from the time "now" thereby converting it
 * to an elapsed time.
 */
static void
calc_resp_time(send_time)
struct timeval *send_time;
{
	struct timeval time_now;

	(void) gettimeofday(&time_now, (struct timezone *)0);
	if (time_now.tv_usec <  send_time->tv_usec) {
		time_now.tv_sec--;
		time_now.tv_usec += 1000000;
	}
	send_time->tv_sec = time_now.tv_sec - send_time->tv_sec;
	send_time->tv_usec = time_now.tv_usec - send_time->tv_usec;
}

static void
free_transports(trans)
	struct transp *trans;
{
	struct transp *t, *tmpt = NULL;
	struct addrs *a, *tmpa = NULL;
	struct tstamps *ts, *tmpts = NULL;

	for (t = trans; t; t = tmpt) {
		if (t->tr_taddr)
			(void) t_free((char *)t->tr_taddr, T_BIND);
		if (t->tr_fd > 0)
			(void) t_close(t->tr_fd);
		for (a = t->tr_addrs; a; a = tmpa) {
			for (ts = a->addr_if_tstamps; ts; ts = tmpts) {
				tmpts = ts->ts_next;
				free(ts);
			}
			(void) netdir_free((char *)a->addr_addrs, ND_ADDRLIST);
			tmpa = a->addr_next;
			free(a);
		}
		tmpt = t->tr_next;
		free(t);
	}
}
