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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * rpcb_svc_4.c
 * The server procedure for the version 4 rpcbind.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <netconfig.h>
#include <syslog.h>
#include <netdir.h>
#include <string.h>
#include <stdlib.h>
#include "rpcbind.h"

static void free_rpcb_entry_list(rpcb_entry_list_ptr);
static bool_t xdr_rpcb_entry_list_ptr_wrap(XDR *, rpcb_entry_list_ptr *);
static bool_t rpcbproc_getaddrlist(rpcb *, rpcb_entry_list_ptr *,
    struct svc_req *);

/*
 * Called by svc_getreqset. There is a separate server handle for
 * every transport that it waits on.
 */
void
rpcb_service_4(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		rpcb rpcbproc_set_4_arg;
		rpcb rpcbproc_unset_4_arg;
		rpcb rpcbproc_getaddr_4_arg;
		char *rpcbproc_uaddr2taddr_4_arg;
		struct netbuf rpcbproc_taddr2uaddr_4_arg;
		rpcb rpcbproc_getversaddr_4_arg;
		rpcb rpcbproc_getaddrlist_4_arg;
	} argument;
	union {
		bool_t rpcbproc_set_4_res;
		bool_t rpcbproc_unset_4_res;
		char *rpcbproc_getaddr_4_res;
		rpcblist_ptr *rpcbproc_dump_4_res;
		ulong_t rpcbproc_gettime_4_res;
		struct netbuf rpcbproc_uaddr2taddr_4_res;
		char *rpcbproc_taddr2uaddr_4_res;
		char *rpcbproc_getversaddr_4_res;
		rpcb_entry_list_ptr rpcbproc_getaddrlist_4_res;
		rpcb_stat_byvers *rpcbproc_getstat_4_res;
	} result;
	bool_t retval;
	xdrproc_t xdr_argument, xdr_result;
	bool_t (*local)();

	rpcbs_procinfo(RPCBVERS_4_STAT, rqstp->rq_proc);

	RPCB_CHECK(transp, rqstp->rq_proc);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		/*
		 * Null proc call
		 */
		(void) svc_sendreply(transp, (xdrproc_t)xdr_void, (char *)NULL);
		return;

	case RPCBPROC_SET:
		/*
		 * Check to see whether the message came from
		 * loopback transports (for security reasons)
		 */
		if (strcasecmp(transp->xp_netid, loopback_dg) &&
		    strcasecmp(transp->xp_netid, loopback_vc) &&
		    strcasecmp(transp->xp_netid, loopback_vc_ord)) {
			syslog(LOG_ERR, "non-local attempt to set");
			svcerr_weakauth(transp);
			return;
		}
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_bool;
		local = (bool_t (*)()) rpcbproc_set_com;
		break;

	case RPCBPROC_UNSET:
		/*
		 * Check to see whether the message came from
		 * loopback transports (for security reasons)
		 */
		if (strcasecmp(transp->xp_netid, loopback_dg) &&
		    strcasecmp(transp->xp_netid, loopback_vc) &&
		    strcasecmp(transp->xp_netid, loopback_vc_ord)) {
			syslog(LOG_ERR, "non-local attempt to unset");
			svcerr_weakauth(transp);
			return;
		}
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_bool;
		local = (bool_t (*)()) rpcbproc_unset_com;
		break;

	case RPCBPROC_GETADDR:
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_wrapstring;
		local = (bool_t (*)()) rpcbproc_getaddr_com;
		break;

	case RPCBPROC_DUMP:
		xdr_argument = xdr_void;
		xdr_result = xdr_rpcblist_ptr_ptr;
		local = (bool_t (*)()) rpcbproc_dump_com;
		break;

	case RPCBPROC_BCAST:
		rpcbproc_callit_com(rqstp, transp, rqstp->rq_proc, RPCBVERS4);
		return;

	case RPCBPROC_GETTIME:
		xdr_argument = xdr_void;
		xdr_result = xdr_u_long;
		local = (bool_t (*)()) rpcbproc_gettime_com;
		break;

	case RPCBPROC_UADDR2TADDR:
		xdr_argument = xdr_wrapstring;
		xdr_result = xdr_netbuf;
		local = (bool_t (*)()) rpcbproc_uaddr2taddr_com;
		break;

	case RPCBPROC_TADDR2UADDR:
		xdr_argument = xdr_netbuf;
		xdr_result = xdr_wrapstring;
		local = (bool_t (*)()) rpcbproc_taddr2uaddr_com;
		break;

	case RPCBPROC_GETVERSADDR:
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_wrapstring;
		local = (bool_t (*)()) rpcbproc_getaddr_com;
		break;

	case RPCBPROC_INDIRECT:
		rpcbproc_callit_com(rqstp, transp, rqstp->rq_proc, RPCBVERS4);
		return;

	case RPCBPROC_GETADDRLIST:
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_rpcb_entry_list_ptr_wrap;
		local = (bool_t (*)()) rpcbproc_getaddrlist;
		break;

	case RPCBPROC_GETSTAT:
		xdr_argument = xdr_void;
		xdr_result = xdr_rpcb_stat_byvers_ptr;
		local = (bool_t (*)()) rpcbproc_getstat;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (char *)&argument)) {
		svcerr_decode(transp);
		if (debugging)
			(void) fprintf(stderr, "rpcbind: could not decode\n");
		return;
	}
	retval = (*local)(&argument, &result, rqstp, RPCBVERS4);
	if (retval > 0 && !svc_sendreply(transp, xdr_result, (char *)&result)) {
		svcerr_systemerr(transp);
		if (debugging) {
			(void) fprintf(stderr, "rpcbind: svc_sendreply\n");
			if (doabort) {
				rpcbind_abort();
			}
		}
	}
	if (!svc_freeargs(transp, xdr_argument, (char *)&argument)) {
		if (debugging) {
			(void) fprintf(stderr, "unable to free arguments\n");
			if (doabort) {
				rpcbind_abort();
			}
		}
	}

	xdr_free(xdr_result, (char *)&result);
}

/*
 * Lookup the mapping for a program, version and return the
 * addresses for all transports in the current transport family.
 * We return a merged address.
 */
static bool_t
rpcbproc_getaddrlist(rpcb *regp, rpcb_entry_list_ptr *result,
    struct svc_req *rqstp)
{
	rpcb_entry_list_ptr rlist = *result = NULL;
	rpcblist_ptr rbl, next, prev;
	rpcb_entry_list_ptr rp, tail = NULL;
	ulong_t prog, vers;
	rpcb_entry *a;
	struct netconfig *nconf;
	struct netconfig *reg_nconf;
	char *saddr, *maddr = NULL;
	struct netconfig *trans_conf;	/* transport netconfig */
	SVCXPRT *transp = rqstp->rq_xprt;

	/*
	 * Deal with a possible window during which we could return an IPv6
	 * address when the caller wanted IPv4.  See the comments in
	 * rpcbproc_getaddr_com() for more details.
	 */
	trans_conf = rpcbind_get_conf(transp->xp_netid);
	if (strcmp(trans_conf->nc_protofmly, NC_INET6) == 0) {
		struct sockaddr_in6 *rmtaddr;

		rmtaddr = (struct sockaddr_in6 *)transp->xp_rtaddr.buf;
		if (IN6_IS_ADDR_V4MAPPED(&rmtaddr->sin6_addr)) {
			syslog(LOG_DEBUG,
			    "IPv4 GETADDRLIST request mapped "
			    "to IPv6: ignoring");
			return (FALSE);
		}
	}

	prog = regp->r_prog;
	vers = regp->r_vers;
	reg_nconf = rpcbind_get_conf(transp->xp_netid);
	if (reg_nconf == NULL)
		return (FALSE);
	if (*(regp->r_addr) != '\0') {
		saddr = regp->r_addr;
	} else {
		saddr = NULL;
	}

	prev = NULL;
	(void) rw_wrlock(&list_rbl_lock);
	for (rbl = list_rbl; rbl != NULL; rbl = next) {
		next = rbl->rpcb_next;
		if ((rbl->rpcb_map.r_prog == prog) &&
		    (rbl->rpcb_map.r_vers == vers)) {
			nconf = rpcbind_get_conf(rbl->rpcb_map.r_netid);
			if (nconf == NULL) {
				(void) rw_unlock(&list_rbl_lock);
				goto fail;
			}
			if (strcmp(nconf->nc_protofmly, reg_nconf->nc_protofmly)
			    != 0) {
				prev = rbl;
				continue;	/* not same proto family */
			}
			if ((maddr = mergeaddr(transp, rbl->rpcb_map.r_netid,
			    rbl->rpcb_map.r_addr, saddr)) == NULL) {
				prev = rbl;
				continue;
			} else if (!maddr[0]) {
				/*
				 * The server died, remove this rpcb_map element
				 * from the list and free it.
				 */
#ifdef PORTMAP
				(void) rw_wrlock(&list_pml_lock);
				(void) del_pmaplist(&rbl->rpcb_map);
				(void) rw_unlock(&list_pml_lock);
#endif
				(void) delete_rbl(rbl);

				if (prev == NULL)
					list_rbl = next;
				else
					prev->rpcb_next = next;
				continue;
			}
			/*
			 * Add it to rlist.
			 */
			rp = (rpcb_entry_list_ptr)
			    malloc((uint_t)sizeof (rpcb_entry_list));
			if (rp == NULL) {
				(void) rw_unlock(&list_rbl_lock);
				goto fail;
			}
			a = &rp->rpcb_entry_map;
			a->r_maddr = maddr;
			a->r_nc_netid = nconf->nc_netid;
			a->r_nc_semantics = nconf->nc_semantics;
			a->r_nc_protofmly = nconf->nc_protofmly;
			a->r_nc_proto = nconf->nc_proto;
			rp->rpcb_entry_next = NULL;
			if (rlist == NULL) {
				rlist = rp;
				tail = rp;
			} else {
				tail->rpcb_entry_next = rp;
				tail = rp;
			}
			rp = NULL;
		}
		prev = rbl;
	}
	(void) rw_unlock(&list_rbl_lock);

	/*
	 * XXX: getaddrlist info is also being stuffed into getaddr.
	 * Perhaps wrong, but better than it not getting counted at all.
	 */
	rpcbs_getaddr(RPCBVERS_4_STAT, prog, vers, transp->xp_netid, maddr);

	*result = rlist;
	return (TRUE);

fail:
	free_rpcb_entry_list(rlist);
	return (FALSE);
}

/*
 * Free only the allocated structure, rest is all a pointer to some
 * other data somewhere else.
 */
static void
free_rpcb_entry_list(rpcb_entry_list_ptr rlist)
{
	while (rlist != NULL) {
		rpcb_entry_list_ptr tmp = rlist;
		rlist = rlist->rpcb_entry_next;
		free(tmp->rpcb_entry_map.r_maddr);
		free(tmp);
	}
}

static bool_t
xdr_rpcb_entry_list_ptr_wrap(XDR *xdrs, rpcb_entry_list_ptr *rp)
{
	if (xdrs->x_op == XDR_FREE) {
		free_rpcb_entry_list(*rp);
		return (TRUE);
	}

	return (xdr_rpcb_entry_list_ptr(xdrs, rp));
}
