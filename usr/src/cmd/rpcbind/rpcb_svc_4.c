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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

static void free_rpcb_entry_list();

/*
 * Called by svc_getreqset. There is a separate server handle for
 * every transport that it waits on.
 */
void
rpcb_service_4(rqstp, transp)
	register struct svc_req *rqstp;
	register SVCXPRT *transp;
{
	union {
		rpcb rpcbproc_set_4_arg;
		rpcb rpcbproc_unset_4_arg;
		rpcb rpcbproc_getaddr_4_arg;
		char *rpcbproc_uaddr2taddr_4_arg;
		struct netbuf rpcbproc_taddr2uaddr_4_arg;
	} argument;
	char *result;
	bool_t (*xdr_argument)(), (*xdr_result)();
	char *(*local)();

	rpcbs_procinfo(RPCBVERS_4_STAT, rqstp->rq_proc);

	RPCB_CHECK(transp, rqstp->rq_proc);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		/*
		 * Null proc call
		 */
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_NULL\n");
#endif
		(void) svc_sendreply(transp, (xdrproc_t)xdr_void,
					(char *)NULL);
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
		local = (char *(*)()) rpcbproc_set_com;
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
		local = (char *(*)()) rpcbproc_unset_com;
		break;

	case RPCBPROC_GETADDR:
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_wrapstring;
		local = (char *(*)()) rpcbproc_getaddr_4;
		break;

	case RPCBPROC_GETVERSADDR:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_GETVERSADDR\n");
#endif
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_wrapstring;
		local = (char *(*)()) rpcbproc_getversaddr_4;
		break;

	case RPCBPROC_DUMP:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_DUMP\n");
#endif
		xdr_argument = xdr_void;
		xdr_result = xdr_rpcblist_ptr;
		local = (char *(*)()) rpcbproc_dump_4;
		break;

	case RPCBPROC_INDIRECT:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_INDIRECT\n");
#endif
		rpcbproc_callit_com(rqstp, transp, rqstp->rq_proc, RPCBVERS4);
		return;

/*	case RPCBPROC_CALLIT: */
	case RPCBPROC_BCAST:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_BCAST\n");
#endif
		rpcbproc_callit_com(rqstp, transp, rqstp->rq_proc, RPCBVERS4);
		return;

	case RPCBPROC_GETTIME:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_GETTIME\n");
#endif
		xdr_argument = xdr_void;
		xdr_result = xdr_u_long;
		local = (char *(*)()) rpcbproc_gettime_com;
		break;

	case RPCBPROC_UADDR2TADDR:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_UADDR2TADDR\n");
#endif
		xdr_argument = xdr_wrapstring;
		xdr_result = xdr_netbuf;
		local = (char *(*)()) rpcbproc_uaddr2taddr_com;
		break;

	case RPCBPROC_TADDR2UADDR:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_TADDR2UADDR\n");
#endif
		xdr_argument = xdr_netbuf;
		xdr_result = xdr_wrapstring;
		local = (char *(*)()) rpcbproc_taddr2uaddr_com;
		break;

	case RPCBPROC_GETADDRLIST:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_GETADDRLIST\n");
#endif
		xdr_argument = xdr_rpcb;
		xdr_result = xdr_rpcb_entry_list_ptr;
		local = (char *(*)()) rpcbproc_getaddrlist_4;
		break;

	case RPCBPROC_GETSTAT:
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "RPCBPROC_GETSTAT\n");
#endif
		xdr_argument = xdr_void;
		xdr_result = xdr_rpcb_stat_byvers;
		local = (char *(*)()) rpcbproc_getstat;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, (xdrproc_t)xdr_argument,
		(char *)&argument)) {
		svcerr_decode(transp);
		if (debugging)
			(void) fprintf(stderr, "rpcbind: could not decode\n");
		return;
	}
	result = (*local)(&argument, rqstp, transp, RPCBVERS4);
	if (result != NULL && !svc_sendreply(transp, (xdrproc_t)xdr_result,
						result)) {
		svcerr_systemerr(transp);
		if (debugging) {
			(void) fprintf(stderr, "rpcbind: svc_sendreply\n");
			if (doabort) {
				rpcbind_abort();
			}
		}
	}
	if (!svc_freeargs(transp, (xdrproc_t)xdr_argument,
				(char *)&argument)) {
		if (debugging) {
			(void) fprintf(stderr, "unable to free arguments\n");
			if (doabort) {
				rpcbind_abort();
			}
		}
	}
}

/*
 * Lookup the mapping for a program, version and return its
 * address. Assuming that the caller wants the address of the
 * server running on the transport on which the request came.
 * Even if a service with a different version number is available,
 * it will return that address.  The client should check with an
 * clnt_call to verify whether the service is the one that is desired.
 * We also try to resolve the universal address in terms of
 * address of the caller.
 */
/* ARGSUSED */
char **
rpcbproc_getaddr_4(regp, rqstp, transp, rpcbversnum)
	rpcb *regp;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
	int rpcbversnum; /* unused here */
{
#ifdef RPCBIND_DEBUG
	char *uaddr;

	uaddr =	taddr2uaddr(rpcbind_get_conf(transp->xp_netid),
			    svc_getrpccaller(transp));
	fprintf(stderr, "RPCB_GETADDR request for (%lu, %lu, %s) from %s : ",
		regp->r_prog, regp->r_vers, transp->xp_netid, uaddr);
	free(uaddr);
#endif
	return (rpcbproc_getaddr_com(regp, rqstp, transp, RPCBVERS4,
					(ulong_t)RPCB_ALLVERS));
}

/*
 * Lookup the mapping for a program, version and return its
 * address. Assuming that the caller wants the address of the
 * server running on the transport on which the request came.
 *
 * We also try to resolve the universal address in terms of
 * address of the caller.
 */
/* ARGSUSED */
char **
rpcbproc_getversaddr_4(regp, rqstp, transp)
	rpcb *regp;
	struct svc_req *rqstp;	/* Not used here */
	SVCXPRT *transp;
{
#ifdef RPCBIND_DEBUG
	char *uaddr;

	uaddr = taddr2uaddr(rpcbind_get_conf(transp->xp_netid),
			    svc_getrpccaller(transp));
	fprintf(stderr, "RPCB_GETVERSADDR rqst for (%lu, %lu, %s) from %s : ",
		regp->r_prog, regp->r_vers, transp->xp_netid, uaddr);
	free(uaddr);
#endif
	return (rpcbproc_getaddr_com(regp, rqstp, transp, RPCBVERS4,
					(ulong_t)RPCB_ONEVERS));
}

/*
 * Lookup the mapping for a program, version and return the
 * addresses for all transports in the current transport family.
 * We return a merged address.
 */
/* ARGSUSED */
rpcb_entry_list_ptr *
rpcbproc_getaddrlist_4(
	rpcb *regp,
	struct svc_req *rqstp,	/* Not used here */
	SVCXPRT *transp)
{
	static rpcb_entry_list_ptr rlist;
	rpcblist_ptr rbl, next, prev;
	rpcb_entry_list_ptr rp, tail;
	ulong_t prog, vers;
	rpcb_entry *a;
	struct netconfig *nconf;
	struct netconfig *reg_nconf;
	char *saddr, *maddr = NULL;
	struct netconfig *trans_conf;	/* transport netconfig */

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
			return (NULL);
		}
	}

	free_rpcb_entry_list(&rlist);
	prog = regp->r_prog;
	vers = regp->r_vers;
	reg_nconf = rpcbind_get_conf(transp->xp_netid);
	if (reg_nconf == NULL)
		return (NULL);
	if (*(regp->r_addr) != '\0') {
		saddr = regp->r_addr;
	} else {
		saddr = NULL;
	}
#ifdef RPCBIND_DEBUG
	fprintf(stderr, "r_addr: %s r_netid: %s nc_protofmly: %s\n",
		regp->r_addr, transp->xp_netid, reg_nconf->nc_protofmly);
#endif
	prev = NULL;
	for (rbl = list_rbl; rbl != NULL; rbl = next) {
	    next = rbl->rpcb_next;
	    if ((rbl->rpcb_map.r_prog == prog) &&
		(rbl->rpcb_map.r_vers == vers)) {
		nconf = rpcbind_get_conf(rbl->rpcb_map.r_netid);
		if (nconf == NULL)
			goto fail;
		if (strcmp(nconf->nc_protofmly, reg_nconf->nc_protofmly)
				!= 0) {
			prev = rbl;
			continue;	/* not same proto family */
		}
#ifdef RPCBIND_DEBUG
		fprintf(stderr, "\tmerge with: %s", rbl->rpcb_map.r_addr);
#endif
		if ((maddr = mergeaddr(transp, rbl->rpcb_map.r_netid,
				rbl->rpcb_map.r_addr, saddr)) == NULL) {
#ifdef RPCBIND_DEBUG
		fprintf(stderr, " FAILED\n");
#endif
			prev = rbl;
			continue;
		} else if (!maddr[0]) {
#ifdef RPCBIND_DEBUG
	fprintf(stderr, " SUCCEEDED, but port died -  maddr: nullstring\n");
#endif
			/*
			 * The server died, remove this rpcb_map element from
			 * the list and free it.
			 */
#ifdef PORTMAP
			(void) del_pmaplist(&rbl->rpcb_map);
#endif
			(void) delete_rbl(rbl);

			if (prev == NULL)
				list_rbl = next;
			else
				prev->rpcb_next = next;
			continue;
		}
#ifdef RPCBIND_DEBUG
		fprintf(stderr, " SUCCEEDED maddr: %s\n", maddr);
#endif
		/*
		 * Add it to rlist.
		 */
		rp = (rpcb_entry_list_ptr)
			malloc((uint_t)sizeof (rpcb_entry_list));
		if (rp == NULL)
			goto fail;
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
#ifdef RPCBIND_DEBUG
	for (rp = rlist; rp; rp = rp->rpcb_entry_next) {
		fprintf(stderr, "\t%s %s\n", rp->rpcb_entry_map.r_maddr,
			rp->rpcb_entry_map.r_nc_proto);
	}
#endif
	/*
	 * XXX: getaddrlist info is also being stuffed into getaddr.
	 * Perhaps wrong, but better than it not getting counted at all.
	 */
	rpcbs_getaddr(RPCBVERS4 - 2, prog, vers, transp->xp_netid, maddr);
	return (&rlist);

fail:	free_rpcb_entry_list(&rlist);
	return (NULL);
}

/*
 * Free only the allocated structure, rest is all a pointer to some
 * other data somewhere else.
 */
void
free_rpcb_entry_list(rlistp)
	rpcb_entry_list_ptr *rlistp;
{
	register rpcb_entry_list_ptr rbl, tmp;

	for (rbl = *rlistp; rbl != NULL; ) {
		tmp = rbl;
		rbl = rbl->rpcb_entry_next;
		free((char *)tmp->rpcb_entry_map.r_maddr);
		free((char *)tmp);
	}
	*rlistp = NULL;
}

/* VARARGS */
rpcblist_ptr *
rpcbproc_dump_4()
{
	return ((rpcblist_ptr *)&list_rbl);
}
