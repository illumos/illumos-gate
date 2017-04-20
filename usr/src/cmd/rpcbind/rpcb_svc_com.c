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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 Joyent Inc
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
#else
#define	PMAPVERS	2
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
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/rquota.h>
#include <rpcsvc/yppasswd.h>
#include <rpcsvc/ypupd.h>
#include <assert.h>
#include <synch.h>
#include "rpcbind.h"
#include <sys/debug.h>

static struct finfo *forward_register(ulong_t, struct netbuf *, int, char *);
static void forward_destroy(struct finfo *);
static void handle_reply(svc_input_id_t, int, unsigned int, void *);
static int netbufcmp(struct netbuf *, struct netbuf *);
static void netbuffree(struct netbuf *);
static struct netbuf *netbufdup(struct netbuf *);
static void find_versions(rpcprog_t, char *, rpcvers_t *, rpcvers_t *);
static rpcblist_ptr find_service(ulong_t, ulong_t, char *);
#ifdef PORTMAP
static int add_pmaplist(RPCB *);
#endif

zoneid_t myzone;

/*
 * Set a mapping of program, version, netid
 */
bool_t
rpcbproc_set_com(RPCB *regp, bool_t *result, struct svc_req *rqstp,
    int rpcbversnum)
{
	char owner[64];

	*result = map_set(regp, getowner(rqstp->rq_xprt, owner));

	rpcbs_set(rpcbversnum - PMAPVERS, *result);

	return (TRUE);
}

bool_t
map_set(RPCB *regp, char *owner)
{
	RPCB *a;
	rpcblist_ptr rbl, fnd;

	/*
	 * check to see if already used
	 * find_service returns a hit even if
	 * the versions don't match, so check for it
	 */
	(void) rw_wrlock(&list_rbl_lock);
#ifdef PORTMAP
	(void) rw_wrlock(&list_pml_lock);
#endif /* PORTMAP */
	fnd = find_service(regp->r_prog, regp->r_vers, regp->r_netid);
	if (fnd && (fnd->rpcb_map.r_vers == regp->r_vers)) {
		if (strcmp(fnd->rpcb_map.r_addr, regp->r_addr) == 0) {
			/*
			 * if these match then it is already
			 * registered so just say "OK".
			 */
#ifdef PORTMAP
			(void) rw_unlock(&list_pml_lock);
#endif /* PORTMAP */
			(void) rw_unlock(&list_rbl_lock);
			return (TRUE);
		} else {
			/*
			 * Check if server is up.  If so, return FALSE.
			 * If not, cleanup old registrations for the
			 * program and register the new server.
			 */
			if (is_bound(fnd->rpcb_map.r_netid,
			    fnd->rpcb_map.r_addr)) {
#ifdef PORTMAP
				(void) rw_unlock(&list_pml_lock);
#endif /* PORTMAP */
				(void) rw_unlock(&list_rbl_lock);
				return (FALSE);
			}

			delete_prog(regp->r_prog);
			fnd = NULL;
		}
	}
#ifdef PORTMAP
	(void) rw_unlock(&list_pml_lock);
#endif /* PORTMAP */

	/*
	 * add to the end of the list
	 */
	rbl = malloc(sizeof (RPCBLIST));
	if (rbl == NULL) {
		(void) rw_unlock(&list_rbl_lock);
		return (FALSE);
	}
	a = &rbl->rpcb_map;
	a->r_prog = regp->r_prog;
	a->r_vers = regp->r_vers;
	a->r_netid = strdup(regp->r_netid);
	a->r_addr = strdup(regp->r_addr);
	a->r_owner = strdup(owner);
	if (a->r_addr == NULL || a->r_netid == NULL|| a->r_owner == NULL) {
		(void) rw_unlock(&list_rbl_lock);
		delete_rbl(rbl);
		return (FALSE);
	}
	rbl->rpcb_next = NULL;
	if (list_rbl == NULL) {
		list_rbl = rbl;
	} else {
		for (fnd = list_rbl; fnd->rpcb_next; fnd = fnd->rpcb_next)
			;
		fnd->rpcb_next = rbl;
	}

#ifdef PORTMAP
	(void) add_pmaplist(regp);
#endif
	(void) rw_unlock(&list_rbl_lock);
	return (TRUE);
}

/*
 * Unset a mapping of program, version, netid
 */
bool_t
rpcbproc_unset_com(RPCB *regp, bool_t *result, struct svc_req *rqstp,
    int rpcbversnum)
{
	char owner[64];

	*result = map_unset(regp, getowner(rqstp->rq_xprt, owner));

	rpcbs_unset(rpcbversnum - PMAPVERS, *result);

	return (TRUE);
}

bool_t
map_unset(RPCB *regp, char *owner)
{
#ifdef PORTMAP
	int ans = 0;
#endif
	rpcblist_ptr rbl, next, prev = NULL;

	if (owner == NULL)
		return (0);

	(void) rw_wrlock(&list_rbl_lock);
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
		    strcmp(rbl->rpcb_map.r_owner, owner)) {
			(void) rw_unlock(&list_rbl_lock);
			return (0);
		}

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
	if (ans != 0) {
		(void) rw_wrlock(&list_pml_lock);
		(void) del_pmaplist(regp);
		(void) rw_unlock(&list_pml_lock);
	}
#endif
	(void) rw_unlock(&list_rbl_lock);

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
delete_prog(rpcprog_t prog)
{
	rpcblist_ptr rbl, next, prev = NULL;

	assert(RW_WRITE_HELD(&list_rbl_lock));

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

/*
 * Lookup the mapping for a program, version and return its
 * address. Assuming that the caller wants the address of the
 * server running on the transport on which the request came.
 *
 * For RPCBPROC_GETVERSADDR it will return a service with the exact version
 * number only.
 *
 * Otherwise, even if a service with a different version number is available,
 * it will return that address.  The client should check with an
 * clnt_call to verify whether the service is the one that is desired.
 *
 * We also try to resolve the universal address in terms of
 * address of the caller.
 */
bool_t
rpcbproc_getaddr_com(RPCB *regp, char **result, struct svc_req *rqstp,
    ulong_t rpcbversnum)
{
	char *saddr = NULL;
	rpcblist_ptr fnd;
	struct netconfig *trans_conf;	/* transport netconfig */
	SVCXPRT *transp = rqstp->rq_xprt;
	int verstype = rqstp->rq_proc == RPCBPROC_GETVERSADDR ? RPCB_ONEVERS :
	    RPCB_ALLVERS;
	bool_t pml_locked = FALSE;

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
			*result = NULL;
			return (FALSE);
		}
	}

	(void) rw_rdlock(&list_rbl_lock);
retry:
	fnd = find_service(regp->r_prog, regp->r_vers, transp->xp_netid);
	if (fnd && ((verstype == RPCB_ALLVERS) ||
	    (regp->r_vers == fnd->rpcb_map.r_vers))) {
		if (*(regp->r_addr) != '\0') {  /* may contain a hint about */
			saddr = regp->r_addr;   /* the interface that we    */
		}				/* should use */
		if (!(*result = mergeaddr(transp, transp->xp_netid,
		    fnd->rpcb_map.r_addr, saddr))) {
			/* Try whatever we have */
			*result = strdup(fnd->rpcb_map.r_addr);
		} else if (!(*result)[0]) {
			if (!pml_locked) {
				(void) rw_unlock(&list_rbl_lock);
				(void) rw_wrlock(&list_rbl_lock);
#ifdef PORTMAP
				(void) rw_wrlock(&list_pml_lock);
#endif /* PORTMAP */
				pml_locked = TRUE;
				goto retry;
			}
			/*
			 * The server died.  Unset all versions of this prog.
			 */
			delete_prog(regp->r_prog);
			*result = NULL;
		}
	} else {
		*result = NULL;
	}
#ifdef PORTMAP
	if (pml_locked)
		(void) rw_unlock(&list_pml_lock);
#endif /* PORTMAP */
	(void) rw_unlock(&list_rbl_lock);

	rpcbs_getaddr(rpcbversnum - PMAPVERS, regp->r_prog, regp->r_vers,
	    transp->xp_netid, *result);
	return (TRUE);
}

/* ARGSUSED */
bool_t
rpcbproc_dump_com(void *argp, rpcblist_ptr **result)
{
	/*
	 * list_rbl_lock is unlocked in xdr_rpcblist_ptr_ptr()
	 */
	(void) rw_rdlock(&list_rbl_lock);
	*result = &list_rbl;
	return (TRUE);
}

bool_t
xdr_rpcblist_ptr_ptr(XDR *xdrs, rpcblist_ptr **objp)
{
	if (xdrs->x_op == XDR_FREE) {
		/*
		 * list_rbl_lock is locked in rpcbproc_dump_com()
		 */
		rw_unlock(&list_rbl_lock);
		return (TRUE);
	}

	return (xdr_rpcblist_ptr(xdrs, *objp));
}

/* ARGSUSED */
bool_t
rpcbproc_gettime_com(void *argp, ulong_t *result)
{
	(void) time((time_t *)result);

	return (TRUE);
}

/*
 * Convert uaddr to taddr. Should be used only by
 * local servers/clients. (kernel level stuff only)
 */
bool_t
rpcbproc_uaddr2taddr_com(char **uaddrp, struct netbuf *result,
    struct svc_req *rqstp)
{
	struct netconfig *nconf;
	struct netbuf *taddr;

	if (((nconf = rpcbind_get_conf(rqstp->rq_xprt->xp_netid)) == NULL) ||
	    ((taddr = uaddr2taddr(nconf, *uaddrp)) == NULL)) {
		(void) memset(result, 0, sizeof (*result));
		return (TRUE);
	}

	memcpy(result, taddr, sizeof (*result));
	free(taddr);

	return (TRUE);
}

/*
 * Convert taddr to uaddr. Should be used only by
 * local servers/clients. (kernel level stuff only)
 */
bool_t
rpcbproc_taddr2uaddr_com(struct netbuf *taddr, char **result,
    struct svc_req *rqstp)
{
	struct netconfig *nconf;

	if ((nconf = rpcbind_get_conf(rqstp->rq_xprt->xp_netid)) == NULL)
		*result = NULL;
	else
		*result = taddr2uaddr(nconf, taddr);

	return (TRUE);
}

/*
 * Stuff for the rmtcall service
 */
bool_t
xdr_rpcb_rmtcallargs(XDR *xdrs, rpcb_rmtcallargs *objp)
{
	if (!xdr_u_long(xdrs, &objp->prog))
		return (FALSE);
	if (!xdr_u_long(xdrs, &objp->vers))
		return (FALSE);
	if (!xdr_u_long(xdrs, &objp->proc))
		return (FALSE);
	if (!xdr_bytes(xdrs, (char **)&objp->args.args_val,
	    (uint_t *)&objp->args.args_len, ~0))
		return (FALSE);
	return (TRUE);
}

#ifdef PORTMAP
bool_t
xdr_rmtcallres(XDR *xdrs, rmtcallres *objp)
{
	if (!xdr_u_long(xdrs, &objp->port))
		return (FALSE);
	if (!xdr_bytes(xdrs, (char **)&objp->res.res_val,
	    (uint_t *)&objp->res.res_len, ~0))
		return (FALSE);
	return (TRUE);
}
#endif

bool_t
xdr_rpcb_rmtcallres(XDR *xdrs, rpcb_rmtcallres *objp)
{
	if (!xdr_string(xdrs, &objp->addr, ~0))
		return (FALSE);
	if (!xdr_bytes(xdrs, (char **)&objp->results.results_val,
	    (uint_t *)&objp->results.results_len, ~0))
		return (FALSE);
	return (TRUE);
}

struct rmtcallfd_list {
	int fd;
	char *netid;
	struct rmtcallfd_list *next;
};

static struct rmtcallfd_list *rmthead;
static struct rmtcallfd_list *rmttail;

#define	MASKVAL	(POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)

int
create_rmtcall_fd(struct netconfig *nconf)
{
	int fd;
	struct rmtcallfd_list *rmt;

	if ((fd = t_open(nconf->nc_device, O_RDWR, NULL)) == -1) {
		if (debugging)
			fprintf(stderr, "create_rmtcall_fd: couldn't open "
			    "\"%s\" (errno %d, t_errno %d)\n",
			    nconf->nc_device, errno, t_errno);
		return (-1);
	}

	if (t_bind(fd, NULL, NULL) == -1) {
		if (debugging)
			fprintf(stderr, "create_rmtcall_fd: couldn't bind to "
			    "fd for \"%s\" (errno %d, t_errno %d)\n",
			    nconf->nc_device, errno, t_errno);
		return (-1);
	}

	rmt = malloc(sizeof (struct rmtcallfd_list));
	if (rmt == NULL) {
		syslog(LOG_ERR, "create_rmtcall_fd: no memory!");
		return (-1);
	}

	rmt->netid = strdup(nconf->nc_netid);
	if (rmt->netid == NULL) {
		free(rmt);
		syslog(LOG_ERR, "create_rmtcall_fd: no memory!");
		return (-1);
	}

	if (svc_add_input(fd, MASKVAL, handle_reply, rmt->netid) == -1) {
		free(rmt->netid);
		free(rmt);
		syslog(LOG_ERR, "create_rmtcall_fd: svc_add_input() failed!");
		return (-1);
	}

	rmt->fd = fd;
	rmt->next = NULL;
	if (rmthead == NULL) {
		rmthead = rmt;
		rmttail = rmt;
	} else {
		rmttail->next = rmt;
		rmttail = rmt;
	}

	return (fd);
}

static int
find_rmtcallfd_by_netid(char *netid)
{
	struct rmtcallfd_list *rmt;

	for (rmt = rmthead; rmt != NULL; rmt = rmt->next) {
		if (strcmp(netid, rmt->netid) == 0) {
			return (rmt->fd);
		}
	}
	return (-1);
}

#define	MAXTIME_OFF	300	/* 5 minutes timeout for rmtcalls */

struct finfo {
	struct finfo	*prev;
	struct finfo	*next;
	int		flag;
#define	FINFO_ACTIVE	0x1
	ulong_t		caller_xid;
	struct netbuf	*caller_addr;
	ulong_t		forward_xid;
	int		forward_fd;
	char		*uaddr;
	struct t_unitdata *reply_data;
	struct rpc_err	reply_error;
	uint_t		res_len;
	void		*res_val;
	cond_t		cv;
};

/*
 * finfo_lock protects rpcb_rmtcalls, rpcb_rmtcalls_max, lastxid,
 * fihead, and fitail.
 */
static mutex_t finfo_lock = DEFAULTMUTEX;

static int rpcb_rmtcalls;
static int rpcb_rmtcalls_max;
static ulong_t lastxid;
static struct finfo *fihead;
static struct finfo *fitail;

void
set_rpcb_rmtcalls_max(int max)
{
	(void) mutex_lock(&finfo_lock);
	rpcb_rmtcalls_max = max;
	if (rpcb_rmtcalls > rpcb_rmtcalls_max) {
		assert(fitail != NULL);
		(void) cond_signal(&fitail->cv);
	}
	(void) mutex_unlock(&finfo_lock);
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
 *	made and the service's address
 *
 *	wait for either the timeout or the condition variable is signalled from
 *	handle_reply().
 *
 * At some time in the future, a reply will be received from the service to
 * which we forwarded the request.  At that time, svc_run() detect that the
 * socket used was for forwarding and call handle_reply() to
 *
 *	receive the reply
 *
 *	bundle the reply, along with the service's universal address
 *
 *	put the reply into the particular finfo
 *
 *	signal the condition variable.
 */

#define	RPC_BUF_MAX	65536	/* can be raised if required */

/*
 *  This is from ../ypcmd/yp_b.h
 *  It does not appear in <rpcsvc/yp_prot.h>
 */
#define	YPBINDPROG ((ulong_t)100007)
#define	YPBINDPROC_SETDOM ((ulong_t)2)

/*
 * reply_type - which proc number
 * versnum - which vers was called
 */
void
rpcbproc_callit_com(struct svc_req *rqstp, SVCXPRT *transp, ulong_t reply_type,
    int versnum)
{
	struct t_info tinfo;
	uint_t sendsz;

	rpcb_rmtcallargs arg;
	rpcblist_ptr rbl;

	struct netconfig *nconf;
	struct netbuf *caller;
	struct nd_mergearg ma;
	int stat;

	int fd;
	struct svc_dg_data *bd;
	struct finfo *fi;

	struct rpc_msg call_msg;
	char outbuf[RPC_BUF_MAX];
	char *outbuf_alloc = NULL;
	XDR outxdr;
	bool_t outxdr_created = FALSE;

	AUTH *auth;

	struct t_unitdata tu_data;
	struct netbuf *na;

	timestruc_t to;

	(void) mutex_lock(&finfo_lock);
	if (!allow_indirect || rpcb_rmtcalls_max == 0) {
		(void) mutex_unlock(&finfo_lock);
		return;
	}
	(void) mutex_unlock(&finfo_lock);

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

	(void) memset((char *)&arg, 0, sizeof (arg));
	if (!svc_getargs(transp, xdr_rpcb_rmtcallargs, (char *)&arg)) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_decode(transp);
		if (debugging)
			fprintf(stderr,
			"rpcbproc_callit_com:  svc_getargs failed\n");
		goto error;
	}

	/*
	 * Disallow calling rpcbind for certain procedures.
	 * Allow calling NULLPROC - per man page on rpcb_rmtcall().
	 * switch is in alphabetical order.
	 */
	if (arg.proc != NULLPROC) {
		switch (arg.prog) {
		case KEY_PROG:
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting KEY_PROG(%d)\n",
				    arg.proc);
			goto error;
		case MOUNTPROG:
			if (arg.proc != MOUNTPROC_MNT)
				break;
			/*
			 * In Solaris 2.6, the host-based accesss control
			 * is done by the NFS server on each request.
			 * Prior to 2.6 we rely on mountd.
			 */
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting MOUNTPROG(%d)\n",
				    arg.proc);
			goto error;
		case NFS_ACL_PROGRAM:
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting NFS_ACL_PROGRAM(%d)\n",
				    arg.proc);
			goto error;
		case NFS_PROGRAM:
			/* also NFS3_PROGRAM */
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting NFS_PROGRAM(%d)\n",
				    arg.proc);
			goto error;
		case RPCBPROG:
			/*
			 * Disallow calling rpcbind for certain procedures.
			 * Luckily Portmap set/unset/callit also have same
			 * procedure numbers.  So, will not check for those.
			 */
			switch (arg.proc) {
			case RPCBPROC_SET:
			case RPCBPROC_UNSET:
			case RPCBPROC_CALLIT:
			case RPCBPROC_INDIRECT:
				if (reply_type == RPCBPROC_INDIRECT)
					svcerr_weakauth(transp); /* XXX */
				if (debugging)
					fprintf(stderr, "rpcbproc_callit_com: "
					    "calling RPCBPROG procs SET, "
					    "UNSET, CALLIT, or INDIRECT not "
					    "allowed\n");
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
				    arg.proc);
			goto error;
		case YPPASSWDPROG:
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting YPPASSWDPROG(%d)\n",
				    arg.proc);
			goto error;
		case YPU_PROG:
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting YPU_PROG(%d)\n",
				    arg.proc);
			goto error;
		case YPBINDPROG:
			if (arg.proc != YPBINDPROC_SETDOM)
				break;
			if (debugging)
				fprintf(stderr,
				    "rpcbind: rejecting YPBINDPROG(%d)\n",
				    arg.proc);
			goto error;
		case YPPROG:
			switch (arg.proc) {
			case YPPROC_FIRST:
			case YPPROC_NEXT:
			case YPPROC_MATCH:
			case YPPROC_ALL:
				if (debugging)
					fprintf(stderr,
					    "rpcbind: rejecting YPPROG(%d)\n",
					    arg.proc);
				goto error;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}

	(void) rw_rdlock(&list_rbl_lock);
	rbl = find_service(arg.prog, arg.vers, transp->xp_netid);

	rpcbs_rmtcall(versnum - PMAPVERS, reply_type, arg.prog, arg.vers,
	    arg.proc, transp->xp_netid, rbl);

	if (rbl == NULL) {
		(void) rw_unlock(&list_rbl_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_noprog(transp);
		goto error;
	}
	if (rbl->rpcb_map.r_vers != arg.vers) {
		if (reply_type == RPCBPROC_INDIRECT) {
			ulong_t vers_low, vers_high;

			find_versions(arg.prog, transp->xp_netid,
			    &vers_low, &vers_high);
			(void) rw_unlock(&list_rbl_lock);
			svcerr_progvers(transp, vers_low, vers_high);
		} else {
			(void) rw_unlock(&list_rbl_lock);
		}
		goto error;
	}

	/*
	 * Check whether this entry is valid and a server is present
	 * Mergeaddr() returns NULL if no such entry is present, and
	 * returns "" if the entry was present but the server is not
	 * present (i.e., it crashed).
	 */
	if (reply_type == RPCBPROC_INDIRECT) {
		char *uaddr = mergeaddr(transp, transp->xp_netid,
		    rbl->rpcb_map.r_addr, NULL);
		if ((uaddr == (char *)NULL) || uaddr[0] == '\0') {
			(void) rw_unlock(&list_rbl_lock);
			svcerr_noprog(transp);
			goto error;
		} else {
			free(uaddr);
		}
	}

	nconf = rpcbind_get_conf(transp->xp_netid);
	if (nconf == NULL) {
		(void) rw_unlock(&list_rbl_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  rpcbind_get_conf failed\n");
		goto error;
	}

	caller = svc_getrpccaller(transp);
	ma.c_uaddr = taddr2uaddr(nconf, caller);
	ma.s_uaddr = rbl->rpcb_map.r_addr;

	/*
	 * A mergeaddr operation allocates a string, which it stores in
	 * ma.m_uaddr.  It's passed to forward_register() and is
	 * eventually freed by forward_destroy().
	 */
	stat = netdir_options(nconf, ND_MERGEADDR, 0, (char *)&ma);
	(void) rw_unlock(&list_rbl_lock);
	free(ma.c_uaddr);
	if (stat)
		(void) syslog(LOG_ERR, "netdir_merge failed for %s: %s",
		    nconf->nc_netid, netdir_sperror());

	if ((fd = find_rmtcallfd_by_netid(nconf->nc_netid)) == -1) {
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		free(ma.m_uaddr);
		goto error;
	}

	bd = get_svc_dg_data(transp);

	assert(!MUTEX_HELD(&finfo_lock));
	fi = forward_register(bd->su_xid, caller, fd, ma.m_uaddr);
	if (fi == NULL) {
		/*  forward_register failed.  Perhaps no memory. */
		free(ma.m_uaddr);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  forward_register failed\n");
		assert(!MUTEX_HELD(&finfo_lock));
		goto error;
	}
	/* forward_register() returns with finfo_lock held when successful */
	assert(MUTEX_HELD(&finfo_lock));

	if (fi->flag & FINFO_ACTIVE) {
		/*
		 * A duplicate request for the slow server.  Let's not
		 * beat on it any more.
		 */
		(void) mutex_unlock(&finfo_lock);
		free(ma.m_uaddr);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  duplicate request\n");
		goto error;
	}
	fi->flag |= FINFO_ACTIVE;

	call_msg.rm_xid = fi->forward_xid;
	call_msg.rm_direction = CALL;
	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	call_msg.rm_call.cb_prog = arg.prog;
	call_msg.rm_call.cb_vers = arg.vers;

	if (sendsz > RPC_BUF_MAX) {
		outbuf_alloc = malloc(sendsz);
		if (outbuf_alloc == NULL) {
			forward_destroy(fi);
			(void) mutex_unlock(&finfo_lock);
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
	outxdr_created = TRUE;

	if (!xdr_callhdr(&outxdr, &call_msg)) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  xdr_callhdr failed\n");
		goto error;
	}

	if (!xdr_u_long(&outxdr, &arg.proc)) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
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

		CTASSERT(sizeof (struct authsys_parms) <= RQCRED_SIZE);
		au = (struct authsys_parms *)rqstp->rq_clntcred;
		auth = authsys_create(au->aup_machname, au->aup_uid,
		    au->aup_gid, au->aup_len, au->aup_gids);
		if (auth == NULL) /* fall back */
			auth = authnone_create();
	} else {
		/* we do not support any other authentication scheme */
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_weakauth(transp); /* XXX too strong.. */
		if (debugging)
			fprintf(stderr, "rpcbproc_callit_com:  oa_flavor != "
			    "AUTH_NONE and oa_flavor != AUTH_SYS\n");
		goto error;
	}
	if (auth == NULL) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr, "rpcbproc_callit_com:  "
			    "authwhatever_create returned NULL\n");
		goto error;
	}
	if (!AUTH_MARSHALL(auth, &outxdr)) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		AUTH_DESTROY(auth);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  AUTH_MARSHALL failed\n");
		goto error;
	}
	AUTH_DESTROY(auth);

	if (!xdr_opaque(&outxdr, arg.args.args_val, arg.args.args_len)) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  xdr_opaque failed\n");
		goto error;
	}

	tu_data.udata.len = XDR_GETPOS(&outxdr);
	if (outbuf_alloc)
		tu_data.udata.buf = outbuf_alloc;
	else
		tu_data.udata.buf = outbuf;
	tu_data.opt.len = 0;

	na = uaddr2taddr(nconf, ma.m_uaddr);
	if (!na) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);
		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		goto error;
	}
	tu_data.addr = *na;

	if (t_sndudata(fd, &tu_data) == -1) {
		int err = errno;
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);

		netdir_free((char *)na, ND_ADDR);

		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			fprintf(stderr,
			    "rpcbproc_callit_com:  t_sndudata failed:  "
			    "t_errno %d, errno %d\n", t_errno, err);
		goto error;
	}

	netdir_free((char *)na, ND_ADDR);
	xdr_destroy(&outxdr);
	outxdr_created = FALSE;
	if (outbuf_alloc != NULL) {
		free(outbuf_alloc);
		outbuf_alloc = NULL;
	}
	svc_freeargs(transp, xdr_rpcb_rmtcallargs, (char *)&arg);

	to.tv_sec = time(NULL) + MAXTIME_OFF;
	to.tv_nsec = 0;

	while (fi->reply_data == NULL &&
	    cond_timedwait(&fi->cv, &finfo_lock, &to) != ETIME)
		;

	if (fi->reply_data == NULL) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);

		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			(void) fprintf(stderr,
			    "rpcbproc_callit_com:  timeout\n");
		return;
	}

	if (fi->reply_error.re_status != RPC_SUCCESS) {
		forward_destroy(fi);
		(void) mutex_unlock(&finfo_lock);

		if (reply_type == RPCBPROC_INDIRECT)
			svcerr_systemerr(transp);
		if (debugging)
			(void) fprintf(stderr,
			    "rpcbproc_callit_com:  error in reply:  %s\n",
			    clnt_sperrno(fi->reply_error.re_status));
		return;
	}

	switch (versnum) {
#ifdef PORTMAP
	case PMAPVERS:
		{
			rmtcallres result;
			int h1, h2, h3, h4, p1, p2;

			/* interpret the universal address for TCP/IP */
			if (sscanf(fi->uaddr, "%d.%d.%d.%d.%d.%d",
			    &h1, &h2, &h3, &h4, &p1, &p2) != 6)
				break;

			result.port = ((p1 & 0xff) << 8) + (p2 & 0xff);
			result.res.res_len = fi->res_len;
			result.res.res_val = fi->res_val;

			svc_sendreply(transp, xdr_rmtcallres, (char *)&result);
		}
		break;
#endif
	case RPCBVERS:
	case RPCBVERS4:
		{
			rpcb_rmtcallres result;

			result.addr = fi->uaddr;
			result.results.results_len = fi->res_len;
			result.results.results_val = fi->res_val;

			svc_sendreply(transp, xdr_rpcb_rmtcallres,
			    (char *)&result);
		}
		break;
	}

	forward_destroy(fi);
	(void) mutex_unlock(&finfo_lock);

	return;

error:
	if (outxdr_created)
		xdr_destroy(&outxdr);
	free(outbuf_alloc);
	svc_freeargs(transp, xdr_rpcb_rmtcallargs, (char *)&arg);
}

static struct finfo *forward_find(ulong_t, char *);

/*
 * Adds an entry into the finfo list for the given request. Returns the finfo
 * and finfo_lock is left held.  If duplicate request, returns finfo with
 * FINFO_ACTIVE, else returns finfo without FINFO_ACTIVE.
 * If failed, returns NULL and finfo_lock is left unheld.
 */
static struct finfo *
forward_register(ulong_t caller_xid, struct netbuf *caller_addr, int forward_fd,
    char *uaddr)
{
	struct finfo	*fi;

	(void) mutex_lock(&finfo_lock);
	if (rpcb_rmtcalls_max == 0) {
		(void) mutex_unlock(&finfo_lock);
		return (NULL);
	}

	/*
	 * initialization: once this has happened, lastxid will
	 * never be 0 again, when entering or returning from this function.
	 */
	if (lastxid == 0)
		lastxid = time(NULL);

	/*
	 * Check if it is an duplicate entry
	 */
	for (fi = fihead; fi != NULL; fi = fi->next) {
		if (fi->caller_xid == caller_xid &&
		    netbufcmp(fi->caller_addr, caller_addr)) {
			assert(fi->flag & FINFO_ACTIVE);
			return (fi);
		}
	}

	fi = malloc(sizeof (*fi));
	if (fi == NULL) {
		(void) mutex_unlock(&finfo_lock);
		return (NULL);
	}

	if ((fi->caller_addr = netbufdup(caller_addr)) == NULL) {
		(void) mutex_unlock(&finfo_lock);
		free(fi);
		return (NULL);
	}

	/*
	 * Generate new xid and make sure it is unique.
	 */
	do {
		lastxid++;
		/* avoid lastxid wraparound to 0 */
		if (lastxid == 0)
			lastxid = 1;
	} while (forward_find(lastxid, uaddr) != NULL);

	fi->prev = NULL;
	fi->next = fihead;
	if (fihead != NULL)
		fihead->prev = fi;
	fihead = fi;
	if (fitail == NULL)
		fitail = fi;

	fi->flag = 0;
	fi->caller_xid = caller_xid;

	fi->forward_xid = lastxid;
	fi->forward_fd = forward_fd;

	/*
	 * Though uaddr is not allocated here, it will still be freed
	 * from forward_destroy().
	 */
	fi->uaddr = uaddr;

	fi->reply_data = NULL;
	(void) cond_init(&fi->cv, USYNC_THREAD, NULL);

	rpcb_rmtcalls++;
	if (rpcb_rmtcalls > rpcb_rmtcalls_max) {
		assert(fitail != fi);
		(void) cond_signal(&fitail->cv);
	}

	return (fi);
}

static void
forward_destroy(struct finfo *fi)
{
	assert(MUTEX_HELD(&finfo_lock));
	assert(fi->flag & FINFO_ACTIVE);

	if (fihead == fi) {
		assert(fi->prev == NULL);
		fihead = fi->next;
	} else {
		fi->prev->next = fi->next;
	}

	if (fitail == fi) {
		assert(fi->next == NULL);
		fitail = fi->prev;
	} else {
		fi->next->prev = fi->prev;
	}

	netbuffree(fi->caller_addr);
	free(fi->uaddr);
	if (fi->reply_data != NULL)
		t_free((char *)fi->reply_data, T_UNITDATA);
	(void) cond_destroy(&fi->cv);

	free(fi);

	rpcb_rmtcalls--;
	if (rpcb_rmtcalls > rpcb_rmtcalls_max) {
		assert(fitail != NULL);
		(void) cond_signal(&fitail->cv);
	}
}

static struct finfo *
forward_find(ulong_t reply_xid, char *uaddr)
{
	struct finfo *fi;

	assert(MUTEX_HELD(&finfo_lock));

	for (fi = fihead; fi != NULL; fi = fi->next) {
		if (fi->forward_xid == reply_xid &&
		    strcmp(fi->uaddr, uaddr) == 0)
			return (fi);
	}

	return (NULL);
}

static int
netbufcmp(struct netbuf *n1, struct netbuf *n2)
{
	return ((n1->len != n2->len) || memcmp(n1->buf, n2->buf, n1->len));
}

static struct netbuf *
netbufdup(struct netbuf *ap)
{
	struct netbuf *np;

	np = malloc(sizeof (struct netbuf) + ap->len);
	if (np) {
		np->maxlen = np->len = ap->len;
		np->buf = ((char *)np) + sizeof (struct netbuf);
		(void) memcpy(np->buf, ap->buf, ap->len);
	}
	return (np);
}

static void
netbuffree(struct netbuf *ap)
{
	free(ap);
}

static void
handle_reply(svc_input_id_t id, int fd, unsigned int events, void *cookie)
{
	struct t_unitdata *tr_data;
	int res;

	unsigned int inlen;
	char *buffer;
	XDR reply_xdrs;

	struct rpc_msg reply_msg;
	unsigned int pos;
	unsigned int len;

	struct netconfig *nconf;
	char *uaddr = NULL;

	struct finfo *fi;

	tr_data = (struct t_unitdata *)t_alloc(fd, T_UNITDATA,
	    T_ADDR | T_UDATA);
	if (tr_data == NULL) {
		syslog(LOG_ERR, "handle_reply: t_alloc failed!");
		return;
	}

	do {
		int moreflag = 0;

		if (errno == EINTR)
			errno = 0;
		res = t_rcvudata(fd, tr_data, &moreflag);
		if (moreflag & T_MORE) {
			/* Drop this packet - we have no more space. */
			if (debugging)
				fprintf(stderr, "handle_reply:  recvd packet "
				    "with T_MORE flag set\n");
			goto done;
		}
	} while (res < 0 && t_errno == TSYSERR && errno == EINTR);

	if (res < 0) {
		if (debugging)
			fprintf(stderr, "handle_reply:  t_rcvudata returned "
			    "%d, t_errno %d, errno %d\n", res, t_errno, errno);

		if (t_errno == TLOOK)
			(void) t_rcvuderr(fd, NULL);

		goto done;
	}

	inlen = tr_data->udata.len;
	buffer = tr_data->udata.buf;
	assert(buffer != NULL);
	xdrmem_create(&reply_xdrs, buffer, inlen, XDR_DECODE);

	reply_msg.acpted_rply.ar_verf = _null_auth;
	reply_msg.acpted_rply.ar_results.where = 0;
	reply_msg.acpted_rply.ar_results.proc = (xdrproc_t)xdr_void;

	if (!xdr_replymsg(&reply_xdrs, &reply_msg)) {
		xdr_destroy(&reply_xdrs);
		if (debugging)
			(void) fprintf(stderr,
			    "handle_reply:  xdr_replymsg failed\n");
		goto done;
	}
	pos = XDR_GETPOS(&reply_xdrs);
	xdr_destroy(&reply_xdrs);

	len = inlen - pos;

	nconf = rpcbind_get_conf((char *)cookie);
	if (nconf == NULL) {
		syslog(LOG_ERR, "handle_reply: rpcbind_get_conf failed!");
		goto done;
	}
	uaddr = taddr2uaddr(nconf, &tr_data->addr);
	if (uaddr == NULL) {
		syslog(LOG_ERR, "handle_reply: taddr2uaddr failed!");
		goto done;
	}

	(void) mutex_lock(&finfo_lock);
	fi = forward_find(reply_msg.rm_xid, uaddr);
	if (fi == NULL) {
		(void) mutex_unlock(&finfo_lock);
		goto done;
	}

	fi->reply_data = tr_data;
	tr_data = NULL;

	__seterr_reply(&reply_msg, &fi->reply_error);

	fi->res_len = len;
	fi->res_val = &buffer[pos];

	(void) cond_signal(&fi->cv);
	(void) mutex_unlock(&finfo_lock);

done:
	free(uaddr);
	if (tr_data)
		t_free((char *)tr_data, T_UNITDATA);
}

/*
 * prog: Program Number
 * netid: Transport Provider token
 * lowvp: Low version number
 * highvp: High version number
 */
static void
find_versions(rpcprog_t prog, char *netid, rpcvers_t *lowvp, rpcvers_t *highvp)
{
	rpcblist_ptr rbl;
	rpcvers_t lowv = 0;
	rpcvers_t highv = 0;

	assert(RW_LOCK_HELD(&list_rbl_lock));

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog) ||
		    (strcasecmp(rbl->rpcb_map.r_netid, netid) != 0))
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
 *
 * prog: Program Number
 * vers: Version Number
 * netid: Transport Provider token
 */
static rpcblist_ptr
find_service(rpcprog_t prog, rpcvers_t vers, char *netid)
{
	rpcblist_ptr hit = NULL;
	rpcblist_ptr rbl;

	assert(RW_LOCK_HELD(&list_rbl_lock));

	for (rbl = list_rbl; rbl != NULL; rbl = rbl->rpcb_next) {
		if ((rbl->rpcb_map.r_prog != prog) ||
		    (strcasecmp(rbl->rpcb_map.r_netid, netid) != 0))
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
getowner(SVCXPRT *transp, char *owner)
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
add_pmaplist(RPCB *arg)
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

	(void) rw_wrlock(&list_pml_lock);
	if (list_pml == NULL) {
		list_pml = pml;
	} else {
		pmaplist *fnd;

		/* Attach to the end of the list */
		for (fnd = list_pml; fnd->pml_next; fnd = fnd->pml_next)
			;
		fnd->pml_next = pml;
	}
	(void) rw_unlock(&list_pml_lock);

	return (0);
}

/*
 * Delete this from the pmap list only if it is UDP or TCP.
 */
int
del_pmaplist(RPCB *arg)
{
	pmaplist *pml;
	pmaplist *prevpml, *fnd;
	rpcport_t prot;

	if (strcmp(arg->r_netid, udptrans) == 0) {
		/* It is UDP! */
		prot = IPPROTO_UDP;
	} else if (strcmp(arg->r_netid, tcptrans) == 0) {
		/* It is TCP */
		prot = IPPROTO_TCP;
	} else if (arg->r_netid[0] == '\0') {
		prot = 0;	/* Remove all occurrences */
	} else {
		/* Not a IP protocol */
		return (0);
	}

	assert(RW_WRITE_HELD(&list_pml_lock));

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
		free(fnd);
	}

	return (0);
}
#endif /* PORTMAP */
