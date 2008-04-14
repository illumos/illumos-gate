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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains routines that deal with TLI/XTI endpoints and rpc services.
 */

#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <libintl.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <netconfig.h>
#include <errno.h>
#include <sys/sockio.h>
#include "inetd_impl.h"

uu_list_pool_t *conn_ind_pool = NULL;

/*
 * RPC functions.
 */

/*
 * Returns B_TRUE if the non-address components of the 2 rpc_info_t structures
 * are equivalent, else B_FALSE.
 */
boolean_t
rpc_info_equal(const rpc_info_t *ri, const rpc_info_t *ri2)
{
	return ((ri->prognum == ri2->prognum) &&
	    (ri->lowver == ri2->lowver) &&
	    (ri->highver == ri2->highver) &&
	    (strcmp(ri->netid, ri2->netid) == 0));
}

/*
 * Determine if we have a configured interface for the specified address
 * family. This code is a mirror of libnsl's __can_use_af(). We mirror
 * it because we need an exact duplicate of its behavior, yet the
 * function isn't exported by libnsl, and this fix is considered short-
 * term, so it's not worth exporting it.
 *
 * We need to duplicate __can_use_af() so we can accurately determine
 * when getnetconfigent() returns failure for a v6 netid due to no IPv6
 * interfaces being configured: getnetconfigent() returns failure
 * if a netid is either 'tcp6' or 'udp6' and __can_use_af() returns 0,
 * but it doesn't return a return code to uniquely determine this
 * failure. If we don't accurately determine these failures, we could
 * output error messages in a case when they weren't justified.
 */
static int
can_use_af(sa_family_t af)
{
	struct lifnum	lifn;
	int		fd;

	if ((fd =  open("/dev/udp", O_RDONLY)) < 0) {
		return (0);
	}
	lifn.lifn_family = af;
	/* LINTED ECONST_EXPR */
	lifn.lifn_flags = IFF_UP & !(IFF_NOXMIT | IFF_DEPRECATED);
	if (ioctl(fd, SIOCGLIFNUM, &lifn, sizeof (lifn)) < 0) {
		lifn.lifn_count = 0;
	}

	(void) close(fd);
	return (lifn.lifn_count);
}

static boolean_t
is_v6_netid(const char *netid)
{
	return ((strcmp(netid, SOCKET_PROTO_TCP6) == 0) ||
	    (strcmp(netid, SOCKET_PROTO_UDP6) == 0));
}

/*
 * Registers with rpcbind the program number with all versions, from low to
 * high, with the netid, all specified in 'rpc'. If registration fails,
 * returns -1, else 0.
 */
int
register_rpc_service(const char *fmri, const rpc_info_t *rpc)
{
	struct netconfig	*nconf;
	int			ver;

	if ((nconf = getnetconfigent(rpc->netid)) == NULL) {
		/*
		 * Check whether getnetconfigent() failed as a result of
		 * having no IPv6 interfaces configured for a v6 netid, or
		 * as a result of a 'real' error, and output an appropriate
		 * message with an appropriate severity.
		 */
		if (is_v6_netid(rpc->netid) && !can_use_af(AF_INET6)) {
			warn_msg(gettext(
			    "Couldn't register netid %s for RPC instance %s "
			    "because no IPv6 interfaces are plumbed"),
			    rpc->netid, fmri);
		} else {
			error_msg(gettext(
			    "Failed to lookup netid '%s' for instance %s: %s"),
			    rpc->netid, fmri, nc_sperror());
		}
		return (-1);
	}

	for (ver = rpc->lowver; ver <= rpc->highver; ver++) {
		if (!rpcb_set(rpc->prognum, ver, nconf, &(rpc->netbuf))) {
			error_msg(gettext("Failed to register version %d "
			    "of RPC service instance %s, netid %s"), ver,
			    fmri, rpc->netid);

			for (ver--; ver >= rpc->lowver; ver--)
				(void) rpcb_unset(rpc->prognum, ver, nconf);

			freenetconfigent(nconf);
			return (-1);
		}
	}

	freenetconfigent(nconf);
	return (0);
}

/* Unregister all the registrations done by register_rpc_service */
void
unregister_rpc_service(const char *fmri, const rpc_info_t *rpc)
{
	int			ver;
	struct netconfig	*nconf;

	if ((nconf = getnetconfigent(rpc->netid)) == NULL) {
		/*
		 * Don't output an error message if getnetconfigent() fails for
		 * a v6 netid when an IPv6 interface isn't configured.
		 */
		if (!(is_v6_netid(rpc->netid) && !can_use_af(AF_INET6))) {
			error_msg(gettext(
			    "Failed to lookup netid '%s' for instance %s: %s"),
			    rpc->netid, fmri, nc_sperror());
		}
		return;
	}

	for (ver = rpc->lowver; ver <= rpc->highver; ver++)
		(void) rpcb_unset(rpc->prognum, ver, nconf);

	freenetconfigent(nconf);
}

/*
 * TLI/XTI functions.
 */

int
tlx_init(void)
{
	if ((conn_ind_pool = uu_list_pool_create("conn_ind_pool",
	    sizeof (tlx_conn_ind_t), offsetof(tlx_conn_ind_t, link),
	    NULL, UU_LIST_POOL_DEBUG)) == NULL) {
		error_msg("%s: %s", gettext("Failed to create uu pool"),
		    uu_strerror(uu_error()));
		return (-1);
	}

	return (0);
}

void
tlx_fini(void)
{
	if (conn_ind_pool != NULL) {
		uu_list_pool_destroy(conn_ind_pool);
		conn_ind_pool = NULL;
	}
}

/*
 * Checks if the contents of the 2 tlx_info_t structures are equivalent.
 * If 'isrpc' is false, the address components of the two structures are
 * compared for equality as part of this. If the two structures are
 * equivalent B_TRUE is returned, else B_FALSE.
 */
boolean_t
tlx_info_equal(const tlx_info_t *ti, const tlx_info_t *ti2, boolean_t isrpc)
{
	return ((isrpc || (memcmp(ti->local_addr.buf, ti2->local_addr.buf,
	    sizeof (struct sockaddr_storage)) == 0)) &&
	    (strcmp(ti->dev_name, ti2->dev_name) == 0));
}

/*
 * Attempts to bind an address to the network fd 'fd'. If 'reqaddr' is non-NULL,
 * it attempts to bind to that requested address, else it binds to a kernel
 * selected address. In the former case, the function returning success
 * doesn't guarantee that the requested address was bound (the caller needs to
 * check). If 'retaddr' is non-NULL, the bound address is returned in it. The
 * 'qlen' parameter is used to set the connection backlog. If the bind
 * succeeds 0 is returned, else -1.
 */
static int
tlx_bind(int fd, const struct netbuf *reqaddr, struct netbuf *retaddr, int qlen)
{
	struct t_bind breq;
	struct t_bind bret;

	if (retaddr != NULL) {	/* caller requests bound address be returned */
		bret.addr.buf = retaddr->buf;
		bret.addr.maxlen = retaddr->maxlen;
	}

	if (reqaddr != NULL) {  /* caller requests specific address */
		breq.addr.buf = reqaddr->buf;
		breq.addr.len = reqaddr->len;
	} else {
		breq.addr.len = 0;
	}
	breq.qlen = qlen;

	if (t_bind(fd, &breq, retaddr != NULL ? &bret : NULL) < 0)
		return (-1);

	if (retaddr != NULL)
		retaddr->len = bret.addr.len;

	return (0);
}

static int
tlx_setsockopt(int fd, int level, int optname, const void *optval,
    socklen_t optlen)
{
	struct t_optmgmt request, reply;
	struct {
		struct opthdr sockopt;
		char data[256];
	} optbuf;

	if (optlen > sizeof (optbuf.data)) {
		error_msg(gettext("t_optmgmt request too long"));
		return (-1);
	}

	optbuf.sockopt.level = level;
	optbuf.sockopt.name = optname;
	optbuf.sockopt.len = optlen;
	(void) memcpy(optbuf.data, optval, optlen);

	request.opt.len = sizeof (struct opthdr) + optlen;
	request.opt.buf = (char *)&optbuf;
	request.flags = T_NEGOTIATE;

	reply.opt.maxlen = sizeof (struct opthdr) + optlen;
	reply.opt.buf = (char *)&optbuf;
	reply.flags = 0;

	if ((t_optmgmt(fd, &request, &reply) == -1) ||
	    (reply.flags != T_SUCCESS)) {
		error_msg("t_optmgmt: %s", t_strerror(t_errno));
		return (-1);
	}
	return (0);
}

/*
 * Compare contents of netbuf for equality. Return B_TRUE on a match and
 * B_FALSE for mismatch.
 */
static boolean_t
netbufs_equal(struct netbuf *n1, struct netbuf *n2)
{
	return ((n1->len == n2->len) &&
	    (memcmp(n1->buf, n2->buf, (size_t)n1->len) == 0));
}

/*
 * Create a tli/xti endpoint, either bound to the address specified in
 * 'instance' for non-RPC services, else a kernel chosen address.
 * Returns -1 on failure, else 0.
 */
int
create_bound_endpoint(const instance_t *inst, tlx_info_t *tlx_info)
{
	int			fd;
	int			qlen;
	const char		*fmri = inst->fmri;
	struct netbuf		*reqaddr;
	struct netbuf		*retaddr;
	struct netbuf		netbuf;
	struct sockaddr_storage	ss;
	rpc_info_t		*rpc = tlx_info->pr_info.ri;

	if ((fd = t_open(tlx_info->dev_name, O_RDWR, NULL)) == -1) {
		error_msg(gettext("Failed to open transport %s for "
		    "instance %s, proto %s: %s"), tlx_info->dev_name,
		    fmri, tlx_info->pr_info.proto, t_strerror(t_errno));
		return (-1);
	}

	if (tlx_info->pr_info.v6only) {
		int	on = 1;

		/* restrict to IPv6 communications only */
		if (tlx_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
		    sizeof (on)) == -1) {
			(void) t_close(fd);
			return (-1);
		}
	}

	/*
	 * Negotiate for the returning of the remote uid for loopback
	 * transports for RPC services. This needs to be done before the
	 * endpoint is bound using t_bind(), so that any requests to it
	 * contain the uid.
	 */
	if ((rpc != NULL) && (rpc->is_loopback))
		svc_fd_negotiate_ucred(fd);

	/*
	 * Bind the service's address to the endpoint and setup connection
	 * backlog. In the case of RPC services, we specify a NULL requested
	 * address and accept what we're given, storing the returned address
	 * for later RPC binding. In the case of non-RPC services we specify
	 * the service's associated address.
	 */
	if (rpc != NULL) {
		reqaddr = NULL;
		retaddr =  &(rpc->netbuf);
	} else {
		reqaddr = &(tlx_info->local_addr);
		netbuf.buf = (char *)&ss;
		netbuf.maxlen = sizeof (ss);
		retaddr = &netbuf;
	}

	/* ignored for conn/less services */
	qlen = inst->config->basic->conn_backlog;

	if ((tlx_bind(fd, reqaddr, retaddr, qlen) == -1) ||
	    ((reqaddr != NULL) && !netbufs_equal(reqaddr, retaddr))) {
		error_msg(gettext("Failed to bind to the requested address "
		    "for instance %s, proto %s"), fmri,
		    tlx_info->pr_info.proto);
		(void) t_close(fd);
		return (-1);
	}

	return (fd);
}

/*
 * Takes a connection request off 'fd' in the form of a t_call structure
 * and returns a pointer to it.
 * Returns NULL on failure, else pointer to t_call structure on success.
 */
static struct t_call *
get_new_conind(int fd)
{
	struct t_call *call;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	if ((call = (struct t_call *)t_alloc(fd, T_CALL, T_ALL)) == NULL) {
		error_msg("t_alloc: %s", t_strerror(t_errno));
		return (NULL);
	}
	if (t_listen(fd, call) < 0) {
		error_msg("t_listen: %s", t_strerror(t_errno));
		(void) t_free((char *)call, T_CALL);
		return (NULL);
	}

	return (call);
}

/* Add 'call' to the connection indication queue 'queue'. */
int
queue_conind(uu_list_t *queue, struct t_call *call)
{
	tlx_conn_ind_t *ci;

	if ((ci = malloc(sizeof (tlx_conn_ind_t))) == NULL) {
		error_msg(strerror(errno));
		return (-1);
	}

	ci->call = call;
	uu_list_node_init(ci, &ci->link, conn_ind_pool);
	(void) uu_list_insert_after(queue, NULL, ci);

	return (0);
}

/*
 * Remove and return a pointer to the first call on queue 'queue'. However,
 * if the queue is empty returns NULL.
 */
struct t_call *
dequeue_conind(uu_list_t *queue)
{
	struct t_call   *ret;
	tlx_conn_ind_t	*ci = uu_list_first(queue);

	if (ci == NULL)
		return (NULL);

	ret = ci->call;
	uu_list_remove(queue, ci);
	free(ci);

	return (ret);
}

/*
 * Handle a TLOOK notification received during a t_accept() call.
 * Returns -1 on failure, else 0.
 */
static int
process_tlook(const char *fmri, tlx_info_t *tlx_info)
{
	int	event;
	int	fd = tlx_info->pr_info.listen_fd;

	switch (event = t_look(fd)) {
	case T_LISTEN: {
		struct t_call *call;

		debug_msg("process_tlook: T_LISTEN event");
		if ((call = get_new_conind(fd)) == NULL)
			return (-1);
		if (queue_conind(tlx_info->conn_ind_queue, call) == -1) {
			error_msg(gettext("Failed to queue connection "
			    "indication for instance %s"), fmri);
			(void) t_free((char *)call, T_CALL);
			return (-1);
		}
		break;
	}
	case T_DISCONNECT: {
		/*
		 * Note: In Solaris 2.X (SunOS 5.X) bundled
		 * connection-oriented transport drivers
		 * [ e.g /dev/tcp and /dev/ticots and
		 * /dev/ticotsord (tl)] we do not send disconnect
		 * indications to listening endpoints.
		 * So this will not be seen with endpoints on Solaris
		 * bundled transport devices. However, Streams TPI
		 * allows for this (broken?) behavior and so we account
		 * for it here because of the possibility of unbundled
		 * transport drivers causing this.
		 */
		tlx_conn_ind_t	*cip;
		struct t_discon	*discon;

		debug_msg("process_tlook: T_DISCONNECT event");

		/* LINTED */
		if ((discon = (struct t_discon *)
		    t_alloc(fd, T_DIS, T_ALL)) == NULL) {
			error_msg("t_alloc: %s", t_strerror(t_errno));
			return (-1);
		}
		if (t_rcvdis(fd, discon) < 0) {
			error_msg("t_rcvdis: %s", t_strerror(t_errno));
			(void) t_free((char *)discon, T_DIS);
			return (-1);
		}

		/*
		 * Find any queued connection pending that matches this
		 * disconnect notice and remove from the pending queue.
		 */
		cip = uu_list_first(tlx_info->conn_ind_queue);
		while ((cip != NULL) &&
		    (cip->call->sequence != discon->sequence)) {
			cip = uu_list_next(tlx_info->conn_ind_queue, cip);
		}
		if (cip != NULL) {	/* match found */
			uu_list_remove(tlx_info->conn_ind_queue, cip);
			(void) t_free((char *)cip->call, T_CALL);
			free(cip);
		}

		(void) t_free((char *)discon, T_DIS);
		break;
	}
	case -1:
		error_msg("t_look: %s", t_errno);
		return (-1);
	default:
		error_msg(gettext("do_tlook: unexpected t_look event: %d"),
		    event);
		return (-1);
	}

	return (0);
}

/*
 * This call attempts to t_accept() an incoming/pending TLI connection.
 * If it is thwarted by a TLOOK, it is deferred and whatever is on the
 * file descriptor, removed after a t_look. (Incoming connect indications
 * get queued for later processing and disconnect indications remove a
 * a queued connection request if a match found).
 * Returns -1 on failure, else 0.
 */
int
tlx_accept(const char *fmri, tlx_info_t *tlx_info,
    struct sockaddr_storage *remote_addr)
{
	tlx_conn_ind_t	*conind;
	struct t_call	*call;
	int		fd;
	int		listen_fd = tlx_info->pr_info.listen_fd;

	if ((fd = t_open(tlx_info->dev_name, O_RDWR, NULL)) == -1) {
		error_msg("t_open: %s", t_strerror(t_errno));
		return (-1);
	}

	if (tlx_info->pr_info.v6only) {
		int	on = 1;

		/* restrict to IPv6 communications only */
		if (tlx_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on,
		    sizeof (on)) == -1) {
			(void) t_close(fd);
			return (-1);
		}
	}

	if (t_bind(fd, NULL, NULL) == -1) {
		error_msg("t_bind: %s", t_strerror(t_errno));
		(void) t_close(fd);
		return (-1);
	}

	/*
	 * Get the next connection indication - first try the pending
	 * queue, then, if none there, get a new one from the file descriptor.
	 */
	if ((conind = uu_list_first(tlx_info->conn_ind_queue)) != NULL) {
		debug_msg("taking con off queue");
		call = conind->call;
	} else if ((call = get_new_conind(listen_fd)) == NULL) {
		(void) t_close(fd);
		return (-1);
	}

	/*
	 * Accept the connection indication on the newly created endpoint.
	 * If we fail, and it's the result of a tlook, queue the indication
	 * if it isn't already, and go and process the t_look.
	 */
	if (t_accept(listen_fd, fd, call) == -1) {
		if (t_errno == TLOOK) {
			if (uu_list_first(tlx_info->conn_ind_queue) == NULL) {
				/*
				 * We are first one to have to defer accepting
				 * and start the pending connections list.
				 */
				if (queue_conind(tlx_info->conn_ind_queue,
				    call) == -1) {
					error_msg(gettext(
					    "Failed to queue connection "
					    "indication for instance %s"),
					    fmri);
					(void) t_free((char *)call, T_CALL);
					return (-1);
				}
			}
			(void) process_tlook(fmri, tlx_info);
		} else {		  /* non-TLOOK accept failure */
			error_msg("%s: %s", "t_accept failed",
			    t_strerror(t_errno));
			/*
			 * If we were accepting a queued connection, dequeue
			 * it.
			 */
			if (uu_list_first(tlx_info->conn_ind_queue) != NULL)
				(void) dequeue_conind(tlx_info->conn_ind_queue);
			(void) t_free((char *)call, T_CALL);
		}

		(void) t_close(fd);
		return (-1);
	}

	/* Copy remote address into address parameter */
	(void) memcpy(remote_addr, call->addr.buf,
	    MIN(call->addr.len, sizeof (*remote_addr)));

	/* If we were accepting a queued connection, dequeue it. */
	if (uu_list_first(tlx_info->conn_ind_queue) != NULL)
		(void) dequeue_conind(tlx_info->conn_ind_queue);
	(void) t_free((char *)call, T_CALL);

	return (fd);
}

/* protocol independent network fd close routine */
void
close_net_fd(instance_t *inst, int fd)
{
	if (inst->config->basic->istlx) {
		(void) t_close(fd);
	} else {
		(void) close(fd);
	}
}

/*
 * Consume some data from the given endpoint of the given wait-based instance.
 */
void
consume_wait_data(instance_t *inst, int fd)
{
	int	flag;
	char	buf[50];	/* same arbitrary size as old inetd */

	if (inst->config->basic->istlx) {
		(void) t_rcv(fd, buf, sizeof (buf), &flag);
	} else {
		(void) recv(fd, buf, sizeof (buf), 0);
	}
}
