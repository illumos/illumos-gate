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
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * rpcb_svc_com.c
 * The commom server procedure for the rpcbind.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <rpc/rpc.h>
#include <rpc/rpcb_prot.h>
#include <rpcsvc/svc_dg_priv.h>
#include <netconfig.h>
#include <sys/param.h>
#include <errno.h>
#include <zone.h>
#include <sys/poll.h>
#include <sys/stropts.h>
#ifdef PORTMAP
#include <netinet/in.h>
#include <rpc/pmap_prot.h>
#endif /* PORTMAP */
#include <syslog.h>
#include <netdir.h>
#include <ucred.h>
#include <alloca.h>
#include <rpcsvc/yp_prot.h>
#include <nfs/nfs.h>
#include <nfs/nfs_acl.h>
#include <rpcsvc/mount.h>
#include <nfs/nfs_acl.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nispasswd.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/rquota.h>
#include <rpcsvc/yppasswd.h>
#include <rpcsvc/ypupd.h>
#include "rpcbind.h"

static bool_t	xdr_opaque_parms();
char	*getowner();
static ulong_t	forward_register();
static void	handle_reply();
static int	netbufcmp();
static int	free_slot_by_xid();
static int	free_slot_by_index();
static int	check_rmtcalls();
static void	netbuffree();
static void	find_versions();
static struct netbuf	*netbufdup();
static rpcblist_ptr find_service();
static int	add_pmaplist(RPCB *);
int	del_pmaplist(RPCB *);
void	delete_rbl(rpcblist_ptr);

static char *nullstring = "";
static int rpcb_rmtcalls;

/*
 * Set a mapping of program, version, netid
 */
/* ARGSUSED */
bool_t *
rpcbproc_set_com(regp, rqstp, transp, rpcbversnum)
	RPCB *regp;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
	int rpcbversnum;
{
	static bool_t ans;
	char owner[64];

#ifdef RPCBIND_DEBUG
	fprintf(stderr, "RPCB_SET request for (%lu, %lu, %s, %s) : ",
		regp->r_prog, regp->r_vers, regp->r_netid, regp->r_addr);
#endif
	ans = map_set(regp, getowner(transp, owner));
#ifdef RPCBIND_DEBUG
	fprintf(stderr, "%s\n", ans == TRUE ? "succeeded" : "failed");
#endif
	/* XXX: should have used some defined constant here */
	rpcbs_set((ulong_t)(rpcbversnum - 2), ans);
	return (&ans);
}

bool_t
map_set(regp, owner)
	RPCB *regp;
	char *owner;
{
	RPCB reg, *a;
	rpcblist_ptr rbl, fnd;

	reg = *regp;
	/*
	 * check to see if already used
	 * find_service returns a hit even if
	 * the versions don't match, so check for it
	 */
	fnd = find_service(reg.r_prog, reg.r_vers, reg.r_netid);
	if (fnd && (fnd->rpcb_map.r_vers == reg.r_vers)) {
		if (strcmp(fnd->rpcb_map.r_addr, reg.r_addr) == 0)
			/*
			 * if these match then it is already
			 * registered so just say "OK".
			 */
			return (TRUE);
		else {
			/*
			 * Check if server is up.  If so, return FALSE.
			 * If not, cleanup old registrations for the
			 * program and register the new server.
			 */
			if (is_bound(fnd->rpcb_map.r_netid,
							fnd->rpcb_map.r_addr))
				return (FALSE);
			delete_prog(reg.r_prog);
			fnd = NULL;
		}
	}
	/*
	 * add to the end of the list
	 */
	rbl = (rpcblist_ptr) malloc((uint_t)sizeof (RPCBLIST));
	if (rbl == (rpcblist_ptr)NULL) {
		return (FALSE);
	}
	a = &(rbl->rpcb_map);
	a->r_prog = reg.r_prog;
	a->r_vers = reg.r_vers;
	a->r_netid = strdup(reg.r_netid);
	a->r_addr = strdup(reg.r_addr);
	a->r_owner = strdup(owner);
	if (a->r_addr == NULL || a->r_netid == NULL|| a->r_owner == NULL) {
		delete_rbl(rbl);
		return (FALSE);
	}
	rbl->rpcb_next = (rpcblist_ptr)NULL;
	if (list_rbl == NULL) {
		list_rbl = rbl;
	} else {
		for (fnd = list_rbl; fnd->rpcb_next;
			fnd = fnd->rpcb_next)
			;
		fnd->rpcb_next = rbl;
	}
#ifdef PORTMAP
	(void) add_pmaplist(regp);
#endif
	return (TRUE);
}

/*
 * Unset a mapping of program, version, netid
 */
/* ARGSUSED */
bool_t *
rpcbproc_unset_com(regp, rqstp, transp, rpcbversnum)
	RPCB *regp;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
	int rpcbversnum;
{
	static bool_t ans;
	char owner[64];

#ifdef RPCBIND_DEBUG
	fprintf(stderr, "RPCB_UNSET request for (%lu, %lu, %s) : ",
		regp->r_prog, regp->r_vers, regp->r_netid);
#endif
	ans = map_unset(regp, getowner(transp, owner));
#ifdef RPCBIND_DEBUG
	fprintf(stderr, "%s\n", ans == TRUE ? "succeeded" : "failed");
#endif
	/* XXX: should have used some defined constant here */
	rpcbs_unset((ulong_t)(rpcbversnum - 2), ans);
	return (&ans);
}

bool_t
map_unset(regp, owner)
	RPCB *regp;
	char *owner;
{
#ifdef PORTMAP
	int ans = 0;
#endif
	rpcblist_ptr rbl, next, prev = NULL;

	if (owner == NULL)
		return (0);

	for (rbl = list_rbl; rbl != NULL; rbl = next) {
		next = rbl->rpcb_next;

		if ((rbl->rpcb_map.r_prog != regp->r_prog) ||
		    (rbl->rpcb_map.r_vers != regp->r_vers) ||
		    (regp->r_netid[0] && strcasecmp(regp->r_netid,
			rbl->rpcb_map.r_netid))) {
			/* prev moves forwards */
			prev = rbl;
			continue;
		}
		/*
		 * Check whether appropriate uid. Unset only
		 * if superuser or the owner itself.
		 */
		if (strcmp(owner, "superuser") &&
		    strcmp(rbl->rpcb_map.r_owner, owner))
			return (0);
		/* prev stays */
#ifdef PORTMAP
		ans = 1;
#endif
		delete_rbl(rbl);

		if (prev == NULL)
			list_rbl = next;
		else
			prev->rpcb_next = next;
	}
#ifdef PORTMAP
	if (ans)
		(void) del_pmaplist(regp);
#endif
	/*
	 * We return 1 either when the entry was not there or it
	 * was able to unset it.  It can come to this point only if
	 * at least one of the conditions is true.
	 */
	return (1);
}

void
delete_rbl(rpcblist_ptr rbl)
{
	free(rbl->rpcb_map.r_addr);
	free(rbl->rpcb_map.r_netid);
	free(rbl->rpcb_map.r_owner);
	free(rbl);
}

void
delete_prog(prog)
	unsigned long prog;
{
	rpcblist_ptr rbl, next, prev = NULL;

	for (rbl = list_rbl; rbl != NULL; rbl = next) {
		next = rbl->rpcb_next;

		if (rbl->rpcb_map.r_prog != prog ||
		    is_bound(rbl->rpcb_map.r_netid, rbl->rpcb_map.r_addr)) {
			prev = rbl;
			continue;
		}

#ifdef PORTMAP
		(void) del_pmaplist(&rbl->rpcb_map);
#endif
		delete_rbl(rbl);

		if (prev == NULL)
			list_rbl = next;
		else
			prev->rpcb_next = next;
	}
}

/*ARGSUSED*/
char **
rpcbproc_getaddr_com(regp, rqstp, transp, rpcbversnum, verstype)
	RPCB *regp;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
	ulong_t rpcbversnum;
	ulong_t verstype;
{
	static char *uaddr;
	char *saddr = NULL;
	rpcblist_ptr fnd;
	struct netconfig *trans_conf;	/* transport netconfig */

	/*
	 * There is a potential window at startup during which rpcbind
	 * service has been established over IPv6 but not over IPv4.  If an
	 * IPv4 request comes in during that window, the IP code will map
	 * it into IPv6.  We could patch up the request so that it looks
	 * like IPv4 (so that rpcbind returns an IPv4 uaddr to the caller),
	 * but that requires some non-trivial code and it's hard to test.
	 * Instead, drop the request on the floor and force the caller to
	 * retransmit.  By the time rpcbind sees the retransmission, IPv4
	 * service should be in place and it should see the request as
	 * IPv4, as desired.
	 */
	trans_conf = rpcbind_get_conf(transp->xp_netid);
	if (strcmp(trans_conf->nc_protofmly, NC_INET6) == 0) {
		struct sockaddr_in6 *rmtaddr;

		rmtaddr = (struct sockaddr_in6 *)transp->xp_rtaddr.buf;
		if (IN6_IS_ADDR_V4MAPPED(&rmtaddr->sin6_addr)) {
			syslog(LOG_DEBUG,
			    "IPv4 GETADDR request mapped to IPv6: ignoring");
			return (NULL);
		}
	}

	if (uaddr && uaddr[0])
		free((void *) uaddr);
	fnd = find_service(regp->r_prog, regp->r_vers, transp->xp_netid);
	if (fnd && ((verstype == RPCB_ALLVERS) ||
		    (regp->r_vers == fnd->rpcb_map.r_vers))) {
		if (*(regp->r_addr) != '\0') {  /* may contain a hint about */
			saddr = regp->r_addr;   /* the interface that we    */
		}				/* should use */
		if (!(uaddr = mergeaddr(transp, transp->xp_netid,
				fnd->rpcb_map.r_addr, saddr))) {
			/* Try whatever we have */
			uaddr = strdup(fnd->rpcb_map.r_addr);
		} else if (!uaddr[0]) {
			/*
			 * The server died.  Unset all versions of this prog.
			 */
			delete_prog(regp->r_prog);
			uaddr = nullstring;
		}
	} else {
		uaddr = nullstring;
	}
#ifdef RPCBIND_DEBUG
	fprintf(stderr, "getaddr: %s\n", uaddr);
#endif
	/* XXX: should have used some defined constant here */
	rpcbs_getaddr(rpcbversnum - 2, regp->r_prog, regp->r_vers,
		transp->xp_netid, uaddr);
	return (&uaddr);
}

/* VARARGS */
ulong_t *
rpcbproc_gettime_com()
{
	static time_t curtime;

	(void) time(&curtime);
	return ((ulong_t *)&curtime);
}

/*
 * Convert uaddr to taddr. Should be used only by
 * local servers/clients. (kernel level stuff only)
 */
/* ARGSUSED */
struct netbuf *
rpcbproc_uaddr2taddr_com(uaddrp, rqstp, transp, rpcbversnum)
	char **uaddrp;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
	int rpcbversnum;	/* Not used here */
{
	struct netconfig *nconf;
	static struct netbuf nbuf;
	static struct netbuf *taddr;

	if (taddr) {
		free((void *) taddr->buf);
		free((void *) taddr);
	}
	if (((nconf = rpcbind_get_conf(transp->xp_netid)) == NULL) ||
	    ((taddr = uaddr2taddr(nconf, *uaddrp)) == NULL)) {
		(void) memset((char *)&nbuf, 0, sizeof (struct netbuf));
		return (&nbuf);
	}
	return (taddr);
}

/*
 * Convert taddr to uaddr. Should be used only by
 * local servers/clients. (kernel level stuff only)
 */
/* ARGSUSED */
char **
rpcbproc_taddr2uaddr_com(taddr, rqstp, transp, rpcbversnum)
	struct netbuf *taddr;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
	int rpcbversnum; /* unused */
{
	static char *uaddr;
	struct netconfig *nconf;

#ifdef CHEW_FDS
	int fd;

	if ((fd = open("/dev/null", O_RDONLY)) == -1) {
		uaddr = (char *)strerror(errno);
		return (&uaddr);
	}
#endif /* CHEW_FDS */
	if (uaddr && uaddr[0])
		free((void *) uaddr);
	if (((nconf = rpcbind_get_conf(transp->xp_netid)) == NULL) ||
		((uaddr = taddr2uaddr(nconf, taddr)) == NULL)) {
		uaddr = nullstring;
	}
	return (&uaddr);
}


/*
 * Stuff for the rmtcall service
 */
struct encap_parms {
	ulong_t arglen;
	char *args;
};

static bool_t
xdr_encap_parms(xdrs, epp)
	XDR *xdrs;
	struct encap_parms *epp;
{
	return (xdr_bytes(xdrs, &(epp->args), (uint_t *)&(epp->arglen), ~0));
}


struct r_rmtcall_args {
	ulong_t 	rmt_prog;
	ulong_t 	rmt_vers;
	ulong_t 	rmt_proc;
	int	rmt_localvers;	/* whether to send port # or uaddr */
	char 	*rmt_uaddr;
	struct encap_parms rmt_args;
};

/*
 * XDR remote call arguments.  It ignores the address part.
 * written for XDR_DECODE direction only
 */
static bool_t
xdr_rmtcall_args(xdrs, cap)
	register XDR *xdrs;
	register struct r_rmtcall_args *cap;
{
	/* does not get the address or the arguments */
	if (xdr_u_long(xdrs, &(cap->rmt_prog)) &&
	    xdr_u_long(xdrs, &(cap->rmt_vers)) &&
	    xdr_u_long(xdrs, &(cap->rmt_proc))) {
		return (xdr_encap_parms(xdrs, &(cap->rmt_args)));
	}
	return (FALSE);
}

/*
 * XDR remote call results along with the address.  Ignore
 * program number, version  number and proc number.
 * Written for XDR_ENCODE direction only.
 */
static bool_t
xdr_rmtcall_result(xdrs, cap)
	register XDR *xdrs;
	register struct r_rmtcall_args *cap;
{
	bool_t result;

#ifdef PORTMAP
	if (cap->rmt_localvers == PMAPVERS) {
		int h1, h2, h3, h4, p1, p2;
		ulong_t port;

		/* interpret the universal address for TCP/IP */
		if (sscanf(cap->rmt_uaddr, "%d.%d.%d.%d.%d.%d",
			&h1, &h2, &h3, &h4, &p1, &p2) != 6)
			return (FALSE);
		port = ((p1 & 0xff) << 8) + (p2 & 0xff);
		result = xdr_u_long(xdrs, &port);
	} else
#endif
		if ((cap->rmt_localvers == RPCBVERS) ||
		    (cap->rmt_localvers == RPCBVERS4)) {
		result = xdr_wrapstring(xdrs, &(cap->rmt_uaddr));
	} else {
		return (FALSE);
	}
	if (result == TRUE)
		return (xdr_encap_parms(xdrs, &(cap->rmt_args)));
	return (FALSE);
}

/*
 * only worries about the struct encap_parms part of struct r_rmtcall_args.
 * The arglen must already be set!!
 */
static bool_t
xdr_opaque_parms(xdrs, cap)
	XDR *xdrs;
	struct r_rmtcall_args *cap;
{
	return (xdr_opaque(xdrs, cap->rmt_args.args, cap->rmt_args.arglen));
}

struct rmtcallfd_list {
	int fd;
	SVCXPRT *xprt;
	char *netid;
	struct rmtcallfd_list *next;
};

static struct rmtcallfd_list *rmthead;
static struct rmtcallfd_list *rmttail;

int
create_rmtcall_fd(nconf)
struct netconfig *nconf;
{
	int fd;
	struct rmtcallfd_list *rmt;
	SVCXPRT *xprt;

	if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) == -1) {
		if (debugging)
			fprintf(stderr,
	"create_rmtcall_fd: couldn't open \"%s\" (errno %d, t_errno %d)\n",
			nconf->nc_device, errno, t_errno);
		return (-1);
	}
	if (t_bind(fd, (struct t_bind *)0,
		(struct t_bind *)0) == -1) {
		if (debugging)
			fprintf(stderr,
"create_rmtcall_fd: couldn't bind to fd for \"%s\" (errno %d, t_errno %d)\n",
				nconf->nc_device, errno, t_errno);
		return (-1);
	}
	xprt = svc_tli_create(fd, 0, (struct t_bind *)0, 0, 0);
	if (xprt == NULL) {
		if (debugging)
			fprintf(stderr,
				"create_rmtcall_fd: svc_tli_create failed\n");
		return (-1);
	}
	rmt = (struct rmtcallfd_list *)malloc((uint_t)
		sizeof (struct rmtcallfd_list));
	if (rmt == NULL) {
		syslog(LOG_ERR, "create_rmtcall_fd: no memory!");
		return (-1);
	}
	rmt->xprt = xprt;
	rmt->netid = strdup(nconf->nc_netid);
	xprt->xp_netid = rmt->netid;
	rmt->fd = fd;
	rmt->next = NULL;
	if (rmthead == NULL) {
		rmthead = rmt;
		rmttail = rmt;
	} else {
		rmttail->next = rmt;
		rmttail = rmt;
	}
#if defined(DEBUG_RMTCALL) && defined(PORTMAP)
	if (debugging) {
		struct sockaddr_in *sin;
		struct netbuf *nb;
		nb = &xprt->xp_ltaddr;
		sin = (struct sockaddr_in *)nb->buf;
		fprintf(stderr,
			"create_rmtcall_fd %d, port %d\n",
			fd, sin->sin_port);
	}
#endif
	return (fd);
}

static int
find_rmtcallfd_by_netid(netid)
char *netid;
{
	struct rmtcallfd_list *rmt;

	for (rmt = rmthead; rmt != NULL; rmt = rmt->next) {
		if (strcmp(netid, rmt->netid) == 0) {
			return (rmt->fd);
		}
	}
	return (-1);
}

static SVCXPRT *
find_rmtcallxprt_by_fd(fd)
int fd;
{
	struct rmtcallfd_list *rmt;

	for (rmt = rmthead; rmt != NULL; rmt = rmt->next) {
		if (fd == rmt->fd) {
			return (rmt->xprt);
		}
	}
	return (NULL);
}


/*
 * Call a remote procedure service.  This procedure is very quiet when things
 * go wrong.  The proc is written to support broadcast rpc.  In the broadcast
 * case, a machine should shut-up instead of complain, lest the requestor be
 * overrun with complaints at the expense of not hearing a valid reply.
 * When receiving a request and verifying that the service exists, we
 *
 *	receive the request
 *
 *	open a new TLI endpoint on the same transport on which we received
 *	the original request
 *
 *	remember the original request's XID (which requires knowing the format
 *	of the svc_dg_data structure)
 *
 *	forward the request, with a new XID, to the requested service,
 *	remembering the XID used to send this request (for later use in
 *	reassociating the answer with the original request), the requestor's
 *	address, the file descriptor on which the forwarded request is
 *	made and the service's address.
 *
 *	mark the file descriptor on which we anticipate receiving a reply from
 *	the service and one to select for in our private svc_run procedure
 *
 * At some time in the future, a reply will be received from the service to
 * which we forwarded the request.  At that time, we detect that the socket
 * used was for forwarding (by looking through the finfo structures to see
 * whether the fd corresponds to one of those) and call handle_reply() to
 *
 *	receive the reply
 *
 *	bundle the reply, along with the service's universal address
 *
 *	create a SVCXPRT structure and use a version of svc_sendreply
 *	that allows us to specify the reply XID and destination, send the reply
 *	to the original requestor.
 */

#define	RPC_BUF_MAX	65536	/* can be raised if required */

/*
 *  This is from ../ypcmd/yp_b.h
 *  It does not appear in <rpcsvc/yp_prot.h>
 */
#define	YPBINDPROG ((ulong_t)100007)
#define	YPBINDPROC_SETDOM ((ulong_t)2)

void
rpcbproc_callit_com(rqstp, transp, reply_type, versnum)
	struct svc_req *rqstp;
	SVCXPRT *transp;
	ulong_t reply_type;	/* which proc number */
	ulong_t versnum;	/* which vers was called */
{
	register rpcblist_ptr rbl;
	struct netconfig *nconf;
	struct netbuf *caller;
	struct r_rmtcall_args a;
	char *buf_alloc = NULL;
	char *outbuf_alloc = NULL;
	char buf[RPC_BUF_MAX], outbuf[RPC_BUF_MAX];
	struct netbuf *na = (struct netbuf *)NULL;
	struct t_info tinfo;
	struct t_unitdata tu_data;
	struct rpc_msg call_msg;
	struct svc_dg_data *bd;
	int outlen;
	uint_t sendsz;
	XDR outxdr;
	AUTH *auth;
	int fd = -1;
	char *uaddr;
	struct nd_mergearg ma;
	int stat;

	if (t_getinfo(transp->xp_fd, &tinfo) == -1) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		return;
	}
	if (tinfo.servtype != T_CLTS)
		return;	/* Only datagram type accepted */
	sendsz = __rpc_get_t_size(0, tinfo.tsdu);
	if (sendsz == 0) {	/* data transfer not supported */
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		return;
	}
	/*
	 * Should be multiple of 4 for XDR.
	 */
	sendsz = ((sendsz + 3) / 4) * 4;
	if (sendsz > RPC_BUF_MAX) {
#ifdef	notyet
		buf_alloc = alloca(sendsz);		/* not in IDR2? */
#else
		buf_alloc = malloc(sendsz);
#endif	/* notyet */
		if (buf_alloc == NULL) {
			if (debugging)
				fprintf(stderr,
					"rpcbproc_callit_com:  No Memory!\n");
			if (reply_type == RPCBPROC_INDIRECT)
				svcerr_systemerr(transp);
			return;
		}
		a.rmt_args.args = buf_alloc;
	} else {
		a.rmt_args.args = buf;
	}

	call_msg.rm_xid = 0;	/* For error checking purposes */
	ma.m_uaddr = NULL;
	if (!svc_getargs(transp, (xdrproc_t)xdr_rmtcall_args, (char *)&a)) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_decode(transp);
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  svc_getargs failed\n");
		goto error;
	}
	if (!allow_indirect)
		goto error;
	caller = svc_getrpccaller(transp);
#ifdef RPCBIND_DEBUG
	uaddr = taddr2uaddr(rpcbind_get_conf(transp->xp_netid), caller);
	fprintf(stderr, "%s %s request for (%lu, %lu, %lu, %s) from %s : ",
		versnum == PMAPVERS ? "pmap_rmtcall" :
		versnum == RPCBVERS ? "rpcb_rmtcall" :
		versnum == RPCBVERS4 ? "rpcb_indirect" : "unknown",
		reply_type == RPCBPROC_INDIRECT ? "indirect" : "callit",
		a.rmt_prog, a.rmt_vers, a.rmt_proc, transp->xp_netid,
		uaddr ? uaddr : "unknown");
	if (uaddr)
		free((void *) uaddr);
#endif

	/*
	 * Disallow calling rpcbind for certain procedures.
	 * Allow calling NULLPROC - per man page on rpcb_rmtcall().
	 * switch is in alphabetical order.
	 */
	if (a.rmt_proc != NULLPROC) {
		switch (a.rmt_prog) {
		case KEY_PROG:
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting KEY_PROG(%d)\n",
					a.rmt_proc);
			goto error;
		case MOUNTPROG:
			if (a.rmt_proc != MOUNTPROC_MNT)
				break;
			/*
			 * In Solaris 2.6, the host-based accesss control
			 * is done by the NFS server on each request.
			 * Prior to 2.6 we rely on mountd.
			 */
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting MOUNTPROG(%d)\n",
					a.rmt_proc);
			goto error;
		case NFS_ACL_PROGRAM:
			if (debugging)
				fprintf(stderr,
				"rpcbind: rejecting NFS_ACL_PROGRAM(%d)\n",
					a.rmt_proc);
			goto error;
		case NFS_PROGRAM:
			/* also NFS3_PROGRAM */
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting NFS_PROGRAM(%d)\n",
					a.rmt_proc);
			goto error;
		case RPCBPROG:
			/*
			 * Disallow calling rpcbind for certain procedures.
			 * Luckily Portmap set/unset/callit also have same
			 * procedure numbers.  So, will not check for those.
			 */
			switch (a.rmt_proc) {
			case RPCBPROC_SET:
			case RPCBPROC_UNSET:
			case RPCBPROC_CALLIT:
			case RPCBPROC_INDIRECT:
				if (reply_type == RPCBPROC_INDIRECT)
					svcerr_weakauth(transp); /* XXX */
				if (debugging)
					fprintf(stderr,
"rpcbproc_callit_com: calling RPCBPROG procs SET, UNSET, CALLIT, or INDIRECT \
not allowed	\n");
				goto error;
			default:
				/*
				 * Ideally, we should have called rpcb_service()
				 * or pmap_service() with appropriate parameters
				 * instead of going about in a roundabout
				 * manner.  Hopefully, this case should happen
				 * rarely.
				 */
				break;
			}
			break;
		case RQUOTAPROG:
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting RQUOTAPROG(%d)\n",
					a.rmt_proc);
			goto error;
		case YPPASSWDPROG:
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting YPPASSWDPROG(%d)\n",
					a.rmt_proc);
			goto error;
		case YPU_PROG:
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting YPU_PROG(%d)\n",
					a.rmt_proc);
			goto error;
		case YPBINDPROG:
			if (a.rmt_proc != YPBINDPROC_SETDOM)
				break;
			if (debugging)
				fprintf(stderr,
					"rpcbind: rejecting YPBINDPROG(%d)\n",
					a.rmt_proc);
			goto error;
		case YPPROG:
			switch (a.rmt_proc) {
			case YPPROC_FIRST:
			case YPPROC_NEXT:
			case YPPROC_MATCH:
			case YPPROC_ALL:
				if (debugging)
					fprintf(stderr,
					"rpcbind: rejecting YPPROG(%d)\n",
						a.rmt_proc);
				goto error;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}

	rbl = find_service(a.rmt_prog, a.rmt_vers, transp->xp_netid);

	rpcbs_rmtcall(versnum - 2, reply_type, a.rmt_prog, a.rmt_vers,
			a.rmt_proc, transp->xp_netid, rbl);

	if (rbl == (rpcblist_ptr)NULL) {
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "not found\n");
#endif
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_noprog(transp);
		goto error;
	}
	if (rbl->rpcb_map.r_vers != a.rmt_vers) {
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "version not found\n");
#endif
		if (reply_type == RPCBPROC_INDIRECT) {
			ulong_t vers_low, vers_high;

			find_versions(a.rmt_prog, transp->xp_netid,
				&vers_low, &vers_high);
			svcerr_progvers(transp, vers_low, vers_high);
		}
		goto error;
	}

#ifdef RPCBIND_DEBUG
	fprintf(stderr, "found at uaddr %s\n", rbl->rpcb_map.r_addr);
#endif
	/*
	 *	Check whether this entry is valid and a server is present
	 *	Mergeaddr() returns NULL if no such entry is present, and
	 *	returns "" if the entry was present but the server is not
	 *	present (i.e., it crashed).
	 */
	if (reply_type == RPCBPROC_INDIRECT) {
		uaddr = mergeaddr(transp, transp->xp_netid,
			rbl->rpcb_map.r_addr, NULL);
		if ((uaddr == (char *)NULL) || uaddr[0] == '\0') {
			svcerr_noprog(transp);
			goto error;
		} else {
			free((void *) uaddr);
		}
	}
	nconf = rpcbind_get_conf(transp->xp_netid);
	if (nconf == (struct netconfig *)NULL) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  rpcbind_get_conf failed\n");
		goto error;
	}
	ma.c_uaddr = taddr2uaddr(nconf, caller);
	ma.s_uaddr = rbl->rpcb_map.r_addr;
	/*
	 *	A mergeaddr operation allocates a string, which it stores in
	 *	ma.m_uaddr.  It's passed to forward_register() and is
	 *	eventually freed by free_slot_*().
	 */

	stat = netdir_options(nconf, ND_MERGEADDR, 0, (char *)&ma);
	free((void *) ma.c_uaddr);
	if (stat)
		(void) syslog(LOG_ERR, "netdir_merge failed for %s: %s",
			nconf->nc_netid, netdir_sperror());
#ifdef ND_DEBUG
fprintf(stderr,
"rpcbproc_callit_com: s_uaddr = %s, c_uaddr = %s, merged m_uaddr = %s\n",
				ma.s_uaddr, ma.c_uaddr, ma.m_uaddr);
#endif
	if ((fd = find_rmtcallfd_by_netid(nconf->nc_netid)) == -1) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		free((void *) ma.m_uaddr);
		ma.m_uaddr = NULL;
		goto error;
	}
	bd = get_svc_dg_data(transp);
	call_msg.rm_xid = forward_register(bd->su_xid,
			caller, fd, ma.m_uaddr, reply_type, versnum);
	if (call_msg.rm_xid == 0) {
		/*
		 * A duplicate request for the slow server.  Let's not
		 * beat on it any more.
		 */
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  duplicate request\n");
		free((void *) ma.m_uaddr);
		ma.m_uaddr = NULL;
		goto error;
	} else 	if (call_msg.rm_xid == (uint32_t)-1) {
		/*  forward_register failed.  Perhaps no memory. */
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  forward_register failed\n");
		free((void *) ma.m_uaddr);
		ma.m_uaddr = NULL;
		goto error;
	}

#ifdef DEBUG_RMTCALL
	fprintf(stderr,
		"rpcbproc_callit_com:  original XID %x, new XID %x\n",
			bd->su_xid, call_msg.rm_xid);
#endif
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = a.rmt_prog;
	call_msg.rm_call.cb_vers = a.rmt_vers;
	if (sendsz > RPC_BUF_MAX) {
#ifdef	notyet
		outbuf_alloc = alloca(sendsz);	/* not in IDR2? */
#else
		outbuf_alloc = malloc(sendsz);
#endif	/* notyet */
		if (outbuf_alloc == NULL) {
			if (reply_type == RPCBPROC_INDIRECT)
				svcerr_systemerr(transp);
			if (debugging)
				fprintf(stderr,
				"rpcbproc_callit_com:  No memory!\n");
			goto error;
		}
		xdrmem_create(&outxdr, outbuf_alloc, sendsz, XDR_ENCODE);
	} else {
		xdrmem_create(&outxdr, outbuf, sendsz, XDR_ENCODE);
	}
	if (!xdr_callhdr(&outxdr, &call_msg)) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  xdr_callhdr failed\n");
		goto error;
	}
	if (!xdr_u_long(&outxdr, &(a.rmt_proc))) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  xdr_u_long failed\n");
		goto error;
	}

	if (rqstp->rq_cred.oa_flavor == AUTH_NULL) {
		auth = authnone_create();
	} else if (rqstp->rq_cred.oa_flavor == AUTH_SYS) {
		struct authsys_parms *au;

		au = (struct authsys_parms *)rqstp->rq_clntcred;
		auth = authsys_create(au->aup_machname,
				au->aup_uid, au->aup_gid,
				au->aup_len, au->aup_gids);
		if (auth == NULL) /* fall back */
			auth = authnone_create();
	} else {
		/* we do not support any other authentication scheme */
		if (debugging)
			fprintf(stderr,
"rpcbproc_callit_com:  oa_flavor != AUTH_NONE and oa_flavor != AUTH_SYS\n");
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_weakauth(transp); /* XXX too strong.. */
		goto error;
	}
	if (auth == NULL) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
		"rpcbproc_callit_com:  authwhatever_create returned NULL\n");
		goto error;
	}
	if (!AUTH_MARSHALL(auth, &outxdr)) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		AUTH_DESTROY(auth);
		if (debugging)
			fprintf(stderr,
		"rpcbproc_callit_com:  AUTH_MARSHALL failed\n");
		goto error;
	}
	AUTH_DESTROY(auth);
	if (!xdr_opaque_parms(&outxdr, &a)) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
		"rpcbproc_callit_com:  xdr_opaque_parms failed\n");
		goto error;
	}
	outlen = (int)XDR_GETPOS(&outxdr);
	if (outbuf_alloc)
		tu_data.udata.buf = outbuf_alloc;
	else
		tu_data.udata.buf = outbuf;
	tu_data.udata.len = outlen;
	tu_data.opt.len = 0;

	na = uaddr2taddr(nconf, ma.m_uaddr);
	if (!na) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		goto error;
	}
	tu_data.addr = *na;

	if (t_sndudata(fd, &tu_data) == -1) {
		if (debugging)
			fprintf(stderr,
	"rpcbproc_callit_com:  t_sndudata failed:  t_errno %d, errno %d\n",
				t_errno, errno);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		goto error;
	}
	goto out;

error:
	if ((call_msg.rm_xid != 0) && (ma.m_uaddr != NULL))
		(void) free_slot_by_xid(call_msg.rm_xid, ma.m_uaddr);
out:
	if (buf_alloc)
		free((void *) buf_alloc);
	if (outbuf_alloc)
		free((void *) outbuf_alloc);
	if (na)
		netdir_free((char *)na, ND_ADDR);
}

#define	NFORWARD	64
#define	MAXTIME_OFF	300	/* 5 minutes */

struct finfo {
	int		flag;
#define	FINFO_ACTIVE	0x1
	ulong_t		caller_xid;
	struct netbuf	*caller_addr;
	ulong_t		forward_xid;
	int		forward_fd;
	char		*uaddr;
	ulong_t		reply_type;
	ulong_t		versnum;
	time_t		time;
};
static struct finfo	FINFO[NFORWARD];
/*
 * Makes an entry into the FIFO for the given request.
 * If duplicate request, returns a 0, else returns the xid of its call.
 */
static ulong_t
forward_register(caller_xid, caller_addr, forward_fd, uaddr,
	reply_type, versnum)
	ulong_t		caller_xid;
	struct netbuf	*caller_addr;
	int		forward_fd;
	char		*uaddr;
	ulong_t		reply_type;
	ulong_t		versnum;
{
	int		i;
	int		j = 0;
	time_t		min_time, time_now;
	static ulong_t	lastxid;
	int		entry = -1;

	min_time = FINFO[0].time;
	time_now = time((time_t *)0);
	/*
	 * initialization: once this has happened, lastxid will
	 * - always be a multiple of NFORWARD (which has to be a power of 2),
	 * - never be 0 again,
	 * - never be (ulong_t)(-NFORWARD)
	 * when entering or returning from this function.
	 */
	if (lastxid == 0) {
		lastxid = time_now * NFORWARD;
		/*
		 * avoid lastxid wraparound to 0,
		 *  and generating a forward_xid of -1
		 */
		if (lastxid >= (ulong_t)(-NFORWARD))
			lastxid = NFORWARD;
	}

	/*
	 * Check if it is an duplicate entry. Then,
	 * try to find an empty slot.  If not available, then
	 * use the slot with the earliest time.
	 */
	for (i = 0; i < NFORWARD; i++) {
		if (FINFO[i].flag & FINFO_ACTIVE) {
			if ((FINFO[i].caller_xid == caller_xid) &&
			    (FINFO[i].reply_type == reply_type) &&
			    (FINFO[i].versnum == versnum) &&
			    (!netbufcmp(FINFO[i].caller_addr,
					    caller_addr))) {
				FINFO[i].time = time((time_t *)0);
				return (0);	/* Duplicate entry */
			} else {
				/* Should we wait any longer */
				if ((time_now - FINFO[i].time) > MAXTIME_OFF)
					(void) free_slot_by_index(i);
			}
		}
		if (entry == -1) {
			if ((FINFO[i].flag & FINFO_ACTIVE) == 0) {
				entry = i;
			} else if (FINFO[i].time < min_time) {
				j = i;
				min_time = FINFO[i].time;
			}
		}
	}
	if (entry != -1) {
		/* use this empty slot */
		j = entry;
	} else {
		(void) free_slot_by_index(j);
	}
	if ((FINFO[j].caller_addr = netbufdup(caller_addr)) == NULL) {
		return ((ulong_t)-1);
	}
	rpcb_rmtcalls++;	/* no of pending calls */
	FINFO[j].flag = FINFO_ACTIVE;
	FINFO[j].reply_type = reply_type;
	FINFO[j].versnum = versnum;
	FINFO[j].time = time_now;
	FINFO[j].caller_xid = caller_xid;
	FINFO[j].forward_fd = forward_fd;
	/*
	 * Though uaddr is not allocated here, it will still be freed
	 * from free_slot_*().
	 */
	FINFO[j].uaddr = uaddr;
	lastxid = lastxid + NFORWARD;
	/* avoid lastxid wraparound to 0, and generating a forward_xid of -1 */
	if (lastxid >= (ulong_t)(-NFORWARD))
		lastxid = NFORWARD;

	FINFO[j].forward_xid = lastxid + j;	/* encode slot */
	return (FINFO[j].forward_xid);		/* forward on this xid */
}

static struct finfo *
forward_find(reply_xid, uaddr)
	ulong_t		reply_xid;
	char		*uaddr;
{
	int		i;

	i = reply_xid % NFORWARD;
	if (i < 0)
		i += NFORWARD;
	if ((FINFO[i].flag & FINFO_ACTIVE) &&
	    (strcmp(FINFO[i].uaddr, uaddr) == 0) &&
	    (FINFO[i].forward_xid == reply_xid)) {
		return (&FINFO[i]);
	}
	return (NULL);
}

static int
free_slot_by_xid(xid, uaddr)
	ulong_t xid;
	char   *uaddr;
{
	int entry;

	if (forward_find(xid, uaddr)) {
		entry = xid % NFORWARD;
		if (entry < 0)
			entry += NFORWARD;
		return (free_slot_by_index(entry));
	}
	return (0);
}

static int
free_slot_by_index(index)
	int index;
{
	struct finfo	*fi;

	fi = &FINFO[index];
	if (fi->flag & FINFO_ACTIVE) {
		netbuffree(fi->caller_addr);
		free((void *) fi->uaddr);
		fi->flag &= ~FINFO_ACTIVE;
		rpcb_rmtcalls--;
		return (1);
	}
	return (0);
}

static int
netbufcmp(n1, n2)
	struct netbuf	*n1, *n2;
{
	return ((n1->len != n2->len) || memcmp(n1->buf, n2->buf, n1->len));
}

static struct netbuf *
netbufdup(ap)
	register struct netbuf  *ap;
{
	register struct netbuf  *np;

	np = (struct netbuf *) malloc(sizeof (struct netbuf) + ap->len);
	if (np) {
		np->maxlen = np->len = ap->len;
		np->buf = ((char *)np) + sizeof (struct netbuf);
		(void) memcpy(np->buf, ap->buf, ap->len);
	}
	return (np);
}

static void
netbuffree(ap)
	register struct netbuf  *ap;
{
	free((void *) ap);
}

/*
 * active_fd is used to determine whether an entry in svc_pollfd is:
 *    1. not a forward fd (should be polled)
 *    2. an active forward fd (should be polled)
 *    3. an inactive forward fd (should not be polled)
 */
static bool_t
active_fd(fd)
	int fd;
{
	int i;
	time_t time_now;

	if (find_rmtcallxprt_by_fd(fd) == (SVCXPRT *)NULL)
		return (TRUE);
	if (rpcb_rmtcalls == 0)
		return (FALSE);
	time_now = time((time_t *)0);
	for (i = 0; i < NFORWARD; i++)
		if (FINFO[i].forward_fd == fd) {
			if (FINFO[i].flag & FINFO_ACTIVE) {
			/* Should we wait any longer */
				if ((time_now - FINFO[i].time) > MAXTIME_OFF)
					(void) free_slot_by_index(i);
				else
					return (TRUE);
			}
		}
	return (FALSE);
}

#define	MASKVAL	(POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)

void
my_svc_run()
{
	size_t nfds;
	struct pollfd pollfds[FD_SETSIZE];
	int poll_ret, check_ret;
#ifdef SVC_RUN_DEBUG
	int i;
#endif
	register struct pollfd	*p;

	for (;;) {
		{
			register pollfd_t *in;
			register int n;		/* loop counter */

			/*
			 * compress the sparse svc_pollfd strcutre
			 * into pollfds
			 */
			memset(pollfds, 0, sizeof (pollfds));
			p = pollfds;
			for (in = svc_pollfd, n = 0; n < svc_max_pollfd;
					n++, in++) {
				if ((in->fd >= 0) && active_fd(in->fd)) {
					p->fd = in->fd;
					p->events = MASKVAL;
					p->revents = 0;
					p++;
				}
			}
			nfds = p - pollfds;
		}
		poll_ret = 0;
#ifdef SVC_RUN_DEBUG
		if (debugging) {
			fprintf(stderr, "polling for read on fd < ");
			for (i = 0, p = pollfds; i < nfds; i++, p++)
				if (p->events)
					fprintf(stderr, "%d ", p->fd);
			fprintf(stderr, ">\n");
		}
#endif
		switch (poll_ret = poll(pollfds, nfds, INFTIM)) {
		case -1:
			/*
			 * We ignore all errors, continuing with the assumption
			 * that it was set by the signal handlers (or any
			 * other outside event) and not caused by poll().
			 * If it was our refresh signal, call the refresh
			 * function.
			 */
			if (sigrefresh) {
				sigrefresh = 0;
				rpcb_check_init();
			}
		case 0:
			continue;
		default:
#ifdef SVC_RUN_DEBUG
			if (debugging) {
				fprintf(stderr, "poll returned read fds < ");
				for (i = 0, p = pollfds; i < nfds; i++, p++)
					if (p->revents)
						fprintf(stderr, "%d ", p->fd);
				fprintf(stderr, ">\n");
			}
#endif
			/*
			 * If we found as many replies on callback fds
			 * as the number of descriptors selectable which
			 * poll() returned, there can be no more so we
			 * don't call svc_getreq_poll.  Otherwise, there
			 * must be another so we must call svc_getreq_poll.
			 */
			if ((check_ret = check_rmtcalls(pollfds, nfds)) ==
			    poll_ret)
				continue;
			svc_getreq_poll(pollfds, poll_ret-check_ret);
		}
	}
}

static int
check_rmtcalls(pfds, nfds)
	struct pollfd *pfds;
	int nfds;
{
	int j, ncallbacks_found = 0;
	SVCXPRT *xprt;

	/*
	 * This fd will not be polled if rpcb_rmtcalls == 0
	 */
	if (rpcb_rmtcalls == 0)
		return (0);

	for (j = 0; j < nfds; j++) {
		if ((xprt = find_rmtcallxprt_by_fd(pfds[j].fd)) != NULL) {
			if (pfds[j].revents) {
				ncallbacks_found++;
#ifdef DEBUG_RMTCALL
			if (debugging)
				fprintf(stderr,
"my_svc_run:  polled on forwarding fd %d, netid %s - calling handle_reply\n",
		pfds[j].fd, xprt->xp_netid);
#endif
				handle_reply(pfds[j].fd, xprt);
				pfds[j].revents = 0;
			}
		}
	}
	return (ncallbacks_found);
}

static void
xprt_set_caller(xprt, fi)
	SVCXPRT *xprt;
	struct finfo *fi;
{
	struct svc_dg_data *bd;

	*(svc_getrpccaller(xprt)) = *(fi->caller_addr);
	bd = get_svc_dg_data(xprt);
	bd->su_xid = fi->caller_xid;	/* set xid on reply */
}

/*
 * Call svcerr_systemerr() only if RPCBVERS4
 */
static void
send_svcsyserr(xprt, fi)
	SVCXPRT *xprt;
	struct finfo	*fi;
{
	if (fi->reply_type == RPCBPROC_INDIRECT) {
		xprt_set_caller(xprt, fi);
		svcerr_systemerr(xprt);
	}
}

static void
handle_reply(fd, xprt)
	int	fd;
	SVCXPRT *xprt;
{
	XDR		reply_xdrs;
	struct rpc_msg	reply_msg;
	struct rpc_err	reply_error;
	char		*buffer;
	struct finfo	*fi = NULL;
	int		inlen, pos, len, res, i;
	struct r_rmtcall_args a;
	struct t_unitdata	*tr_data = NULL, *tu_data;
	struct netconfig	*nconf = NULL;
	char *uaddr = NULL;

	nconf = rpcbind_get_conf(xprt->xp_netid);
	if (nconf == NULL) {
#ifdef SVC_RUN_DEBUG
		if (debugging)
			fprintf(stderr, "handle_reply:  null xp_netid\n");
#endif
		goto done;
	}
	/*
	 * If this fd is not active on the forward list, ignore it
	 * If the svc_pollfd structure has multiple settings
	 * of the same fd, then it will enter handle_reply() for the first one,
	 * set FINFO_ACTIVE false and then get another call to handle_reply()
	 * with the same, now inactive, fd.
	 */

	for (i = 0; i < NFORWARD; i++) {
		if ((FINFO[i].forward_fd == fd) &&
			(FINFO[i].flag & FINFO_ACTIVE))
				break;
	}

	if (i == NFORWARD) {
#ifdef  SVC_RUN_DEBUG
		if (debugging) {
			fprintf(stderr, "Unsolicited message on rmtcall fd\n");
		}
#endif
		return;
	}

	reply_msg.rm_xid = 0;  /* for easier error handling */
	tr_data = (struct t_unitdata *)t_alloc(fd, T_UNITDATA,
						T_ADDR | T_UDATA);
	if (tr_data == (struct t_unitdata *)NULL) {
		if (debugging)
			fprintf(stderr,
			"handle_reply:  t_alloc T_UNITDATA failed\n");
		goto done;
	}
	do {
		int	moreflag;

		moreflag = 0;
		if (errno == EINTR)
			errno = 0;
		res = t_rcvudata(fd, tr_data, &moreflag);
		if (moreflag & T_MORE) {
			/* Drop this packet - we have no more space. */
			if (debugging)
				fprintf(stderr,
			"handle_reply:  recvd packet with T_MORE flag set\n");
			goto done;
		}
	} while (res < 0 && (t_errno == TSYSERR && errno == EINTR));
	if (res < 0) {
		if (t_errno == TLOOK) {
			if (debugging)
				fprintf(stderr,
	"handle_reply:  t_rcvudata returned %d, t_errno TLOOK\n", res);
			(void) t_rcvuderr(fd, (struct t_uderr *)NULL);
		}

		if (debugging)
			fprintf(stderr,
	"handle_reply:  t_rcvudata returned %d, t_errno %d, errno %d\n",
				res, t_errno, errno);

		goto done;
	}

	inlen = tr_data->udata.len;
	uaddr = taddr2uaddr(nconf, &tr_data->addr);
	if (uaddr == NULL)
		goto done;

#ifdef	DEBUG_MORE
	if (debugging)
		fprintf(stderr,
		"handle_reply:  t_rcvudata received %d-byte packet from %s\n",
		inlen, uaddr);
#endif
	buffer = tr_data->udata.buf;
	if (buffer == (char *)NULL) {
		goto done;
	}
	reply_msg.acpted_rply.ar_verf = _null_auth;
	reply_msg.acpted_rply.ar_results.where = 0;
	reply_msg.acpted_rply.ar_results.proc = (xdrproc_t)xdr_void;

	xdrmem_create(&reply_xdrs, buffer, (uint_t)inlen, XDR_DECODE);
	if (!xdr_replymsg(&reply_xdrs, &reply_msg)) {
		if (debugging)
			(void) fprintf(stderr,
				"handle_reply:  xdr_replymsg failed\n");
		goto done;
	}
	fi = forward_find((ulong_t)reply_msg.rm_xid, uaddr);
	if (fi == NULL)
		goto done;
#ifdef	SVC_RUN_DEBUG
	if (debugging) {
		fprintf(stderr, "handle_reply:  reply xid: %d fi addr: %x\n",
			reply_msg.rm_xid, fi);
	}
#endif
	__seterr_reply(&reply_msg, &reply_error);
	if (reply_error.re_status != RPC_SUCCESS) {
		if (debugging)
			(void) fprintf(stderr, "handle_reply:  %s\n",
				clnt_sperrno(reply_error.re_status));
		send_svcsyserr(xprt, fi);
		goto done;
	}
	pos = XDR_GETPOS(&reply_xdrs);
	len = inlen - pos;
	a.rmt_args.args = &buffer[pos];
	a.rmt_args.arglen = len;
	a.rmt_uaddr = fi->uaddr;
	a.rmt_localvers = fi->versnum;

	xprt_set_caller(xprt, fi);
	/* XXX hack */
	tu_data =  &(get_svc_dg_data(xprt)->su_tudata);

	tu_data->addr = xprt->xp_rtaddr;
#ifdef	SVC_RUN_DEBUG
	if (uaddr)
		free((void *) uaddr);
	uaddr = taddr2uaddr(nconf, svc_getrpccaller(xprt));
	if (debugging) {
		fprintf(stderr, "handle_reply:  forwarding address %s to %s\n",
			a.rmt_uaddr, uaddr ? uaddr : "unknown");
	}
#endif
	svc_sendreply(xprt, (xdrproc_t)xdr_rmtcall_result, (char *)&a);
done:
	if (uaddr)
		free((void *) uaddr);
	if (tr_data)
		t_free((char *)tr_data, T_UNITDATA);
	if ((fi == NULL) || (reply_msg.rm_xid == 0)) {
#ifdef	SVC_RUN_DEBUG
	if (debugging) {
		fprintf(stderr, "handle_reply:  NULL xid on exit!\n");
	}
#endif
	} else
		(void) free_slot_by_xid((ulong_t)reply_msg.rm_xid, fi->uaddr);
}

static void
find_versions(prog, netid, lowvp, highvp)
	ulong_t prog;	/* Program Number */
	char *netid;	/* Transport Provider token */
	ulong_t *lowvp;  /* Low version number */
	ulong_t *highvp; /* High version number */
{
	register rpcblist_ptr rbl;
	int lowv = 0;
	int highv = 0;

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog) ||
		    ((rbl->rpcb_map.r_netid != NULL) &&
			(strcasecmp(rbl->rpcb_map.r_netid, netid) != 0)))
			continue;
		if (lowv == 0) {
			highv = rbl->rpcb_map.r_vers;
			lowv = highv;
		} else if (rbl->rpcb_map.r_vers < lowv) {
			lowv = rbl->rpcb_map.r_vers;
		} else if (rbl->rpcb_map.r_vers > highv) {
			highv = rbl->rpcb_map.r_vers;
		}
	}
	*lowvp = lowv;
	*highvp = highv;
}

/*
 * returns the item with the given program, version number and netid.
 * If that version number is not found, it returns the item with that
 * program number, so that address is now returned to the caller. The
 * caller when makes a call to this program, version number, the call
 * will fail and it will return with PROGVERS_MISMATCH. The user can
 * then determine the highest and the lowest version number for this
 * program using clnt_geterr() and use those program version numbers.
 *
 * Returns the RPCBLIST for the given prog, vers and netid
 */
static rpcblist_ptr
find_service(prog, vers, netid)
	ulong_t prog;	/* Program Number */
	ulong_t vers;	/* Version Number */
	char *netid;	/* Transport Provider token */
{
	register rpcblist_ptr hit = NULL;
	register rpcblist_ptr rbl;

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog) ||
		    ((rbl->rpcb_map.r_netid != NULL) &&
			(strcasecmp(rbl->rpcb_map.r_netid, netid) != 0)))
			continue;
		hit = rbl;
		if (rbl->rpcb_map.r_vers == vers)
			break;
	}
	return (hit);
}

/*
 * If the caller is from our zone and we know
 * who it is, we return the uid.
 */
uid_t
rpcb_caller_uid(SVCXPRT *transp)
{
	ucred_t *uc = alloca(ucred_size());
	static zoneid_t myzone = MIN_ZONEID - 1;
	uid_t uid;

	if (myzone == MIN_ZONEID - 1)
		myzone = getzoneid();

	if (svc_getcallerucred(transp, &uc) != 0 ||
	    (ucred_getzoneid(uc)) != myzone) {
		return (-1);
	} else {
		return (ucred_geteuid(uc));
	}
}

/*
 * Copies the name associated with the uid of the caller and returns
 * a pointer to it.  Similar to getwd().
 */
char *
getowner(transp, owner)
	SVCXPRT *transp;
	char *owner;
{
	uid_t uid = rpcb_caller_uid(transp);

	switch (uid) {
	case -1:
		return (strcpy(owner, "unknown"));
	case 0:
		return (strcpy(owner, "superuser"));
	default:
		(void) sprintf(owner, "%u", uid);
		return (owner);
	}
}

#ifdef PORTMAP
/*
 * Add this to the pmap list only if it is UDP or TCP.
 */
static int
add_pmaplist(arg)
	RPCB *arg;
{
	pmap pmap;
	pmaplist *pml;
	int h1, h2, h3, h4, p1, p2;

	if (strcmp(arg->r_netid, udptrans) == 0) {
		/* It is UDP! */
		pmap.pm_prot = IPPROTO_UDP;
	} else if (strcmp(arg->r_netid, tcptrans) == 0) {
		/* It is TCP */
		pmap.pm_prot = IPPROTO_TCP;
	} else
		/* Not a IP protocol */
		return (0);

	/* interpret the universal address for TCP/IP */
	if (sscanf(arg->r_addr, "%d.%d.%d.%d.%d.%d",
		&h1, &h2, &h3, &h4, &p1, &p2) != 6)
		return (0);
	pmap.pm_port = ((p1 & 0xff) << 8) + (p2 & 0xff);
	pmap.pm_prog = arg->r_prog;
	pmap.pm_vers = arg->r_vers;
	/*
	 * add to END of list
	 */
	pml = (pmaplist *) malloc((uint_t)sizeof (pmaplist));
	if (pml == NULL) {
		(void) syslog(LOG_ERR, "rpcbind: no memory!\n");
		return (1);
	}
	pml->pml_map = pmap;
	pml->pml_next = NULL;
	if (list_pml == NULL) {
		list_pml = pml;
	} else {
		pmaplist *fnd;

		/* Attach to the end of the list */
		for (fnd = list_pml; fnd->pml_next; fnd = fnd->pml_next)
			;
		fnd->pml_next = pml;
	}
	return (0);
}

/*
 * Delete this from the pmap list only if it is UDP or TCP.
 */
int
del_pmaplist(RPCB *arg)
{
	register pmaplist *pml;
	pmaplist *prevpml, *fnd;
	long prot;

	if (strcmp(arg->r_netid, udptrans) == 0) {
		/* It is UDP! */
		prot = IPPROTO_UDP;
	} else if (strcmp(arg->r_netid, tcptrans) == 0) {
		/* It is TCP */
		prot = IPPROTO_TCP;
	} else if (arg->r_netid[0] == NULL) {
		prot = 0;	/* Remove all occurrences */
	} else {
		/* Not a IP protocol */
		return (0);
	}
	for (prevpml = NULL, pml = list_pml; pml; /* cstyle */) {
		if ((pml->pml_map.pm_prog != arg->r_prog) ||
			(pml->pml_map.pm_vers != arg->r_vers) ||
			(prot && (pml->pml_map.pm_prot != prot))) {
			/* both pml & prevpml move forwards */
			prevpml = pml;
			pml = pml->pml_next;
			continue;
		}
		/* found it; pml moves forward, prevpml stays */
		fnd = pml;
		pml = pml->pml_next;
		if (prevpml == NULL)
			list_pml = pml;
		else
			prevpml->pml_next = pml;
		free((void *) fnd);
	}
	return (0);
}
#endif /* PORTMAP */
