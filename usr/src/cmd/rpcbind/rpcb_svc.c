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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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
 * rpcb_svc.c
 * The server procedure for the version 3 rpcbind (TLI).
 *
 * It maintains a separate list of all the registered services with the
 * version 3 of rpcbind.
 */
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpc/rpcb_prot.h>
#include <netconfig.h>
#include <syslog.h>
#include <netdir.h>
#include <stdlib.h>
#include "rpcbind.h"

/*
 * Called by svc_getreqset. There is a separate server handle for
 * every transport that it waits on.
 */
void
rpcb_service_3(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		rpcb rpcbproc_set_3_arg;
		rpcb rpcbproc_unset_3_arg;
		rpcb rpcbproc_getaddr_3_arg;
		rpcb_rmtcallargs rpcbproc_callit_3_arg;
		char *rpcbproc_uaddr2taddr_3_arg;
		struct netbuf rpcbproc_taddr2uaddr_3_arg;
	} argument;
	union {
		bool_t rpcbproc_set_3_res;
		bool_t rpcbproc_unset_3_res;
		char *rpcbproc_getaddr_3_res;
		rpcblist_ptr *rpcbproc_dump_3_res;
		ulong_t rpcbproc_gettime_3_res;
		struct netbuf rpcbproc_uaddr2taddr_3_res;
		char *rpcbproc_taddr2uaddr_3_res;
	} result;
	bool_t retval;
	xdrproc_t xdr_argument, xdr_result;
	bool_t (*local)();

	rpcbs_procinfo(RPCBVERS_3_STAT, rqstp->rq_proc);

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
			char *uaddr;

			uaddr = taddr2uaddr(rpcbind_get_conf(transp->xp_netid),
			    svc_getrpccaller(transp));
			syslog(LOG_ERR, "non-local attempt to set from %s",
			    uaddr == NULL ? "<unknown>" : uaddr);
			free(uaddr);
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
			char *uaddr;

			uaddr = taddr2uaddr(rpcbind_get_conf(transp->xp_netid),
			    svc_getrpccaller(transp));
			syslog(LOG_ERR, "non-local attempt to unset from %s",
			    uaddr == NULL ? "<unknown>" : uaddr);
			free(uaddr);
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

	case RPCBPROC_CALLIT:
		rpcbproc_callit_com(rqstp, transp, rqstp->rq_proc, RPCBVERS);
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
	retval = (*local)(&argument, &result, rqstp, RPCBVERS);
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
