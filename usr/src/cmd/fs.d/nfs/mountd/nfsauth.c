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
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <locale.h>
#include <unistd.h>
#include <thread.h>
#include <netdir.h>
#include <nfs/auth.h>
#include <sharefs/share.h>
#include "../lib/sharetab.h"
#include "mountd.h"

static void
nfsauth_access(auth_req *argp, auth_res *result)
{
	struct netconfig *nconf;
	struct nd_hostservlist *clnames = NULL;
	struct netbuf nbuf;
	struct share *sh;
	char tmp[MAXIPADDRLEN];
	char *host = NULL;

	result->auth_perm = NFSAUTH_DENIED;

	/*
	 * Convert the client's address to a hostname
	 */
	nconf = getnetconfigent(argp->req_netid);
	if (nconf == NULL) {
		syslog(LOG_ERR, "No netconfig entry for %s", argp->req_netid);
		return;
	}

	nbuf.len = argp->req_client.n_len;
	nbuf.buf = argp->req_client.n_bytes;

	if (nbuf.len == 0 || nbuf.buf == NULL)
		goto done;

	if (netdir_getbyaddr(nconf, &clnames, &nbuf)) {
		host = &tmp[0];
		if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
			struct sockaddr_in *sa;

			/* LINTED pointer alignment */
			sa = (struct sockaddr_in *)nbuf.buf;
			(void) inet_ntoa_r(sa->sin_addr, tmp);
		} else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
			struct sockaddr_in6 *sa;
			/* LINTED pointer */
			sa = (struct sockaddr_in6 *)nbuf.buf;
			(void) inet_ntop(AF_INET6, sa->sin6_addr.s6_addr,
			    tmp, INET6_ADDRSTRLEN);
		}
		clnames = anon_client(host);
	}
	/*
	 * Both netdir_getbyaddr() and anon_client() can return a NULL
	 * clnames.  This has been seen when the DNS entry for the client
	 * name does not have the correct format or a reverse lookup DNS
	 * entry cannot be found for the client's IP address.
	 */
	if (clnames == NULL) {
		syslog(LOG_ERR, "Could not find DNS entry for %s",
		    argp->req_netid);
		goto done;
	}

	/*
	 * Now find the export
	 */
	sh = findentry(argp->req_path);
	if (sh == NULL) {
		syslog(LOG_ERR, "%s not exported", argp->req_path);
		goto done;
	}

	result->auth_perm = check_client(sh, &nbuf, clnames, argp->req_flavor,
	    argp->req_clnt_uid, argp->req_clnt_gid, &result->auth_srv_uid,
	    &result->auth_srv_gid);

	sharefree(sh);

	if (result->auth_perm == NFSAUTH_DENIED) {
		syslog(LOG_ERR, "%s denied access to %s",
		    clnames->h_hostservs[0].h_host, argp->req_path);
	}

done:
	freenetconfigent(nconf);
	if (clnames)
		netdir_free(clnames, ND_HOSTSERVLIST);
}

void
nfsauth_func(void *cookie, char *dataptr, size_t arg_size,
	door_desc_t *dp, uint_t n_desc)

{
	nfsauth_arg_t	*ap;
	nfsauth_res_t	 res = {0};
	nfsauth_res_t	*rp = &res;
	XDR		 xdrs_a;
	XDR		 xdrs_r;
	caddr_t		 abuf = dataptr;
	size_t		 absz = arg_size;
	size_t		 rbsz = (size_t)(BYTES_PER_XDR_UNIT * 4);
	char		 result[BYTES_PER_XDR_UNIT * 4];
	caddr_t		 rbuf = (caddr_t)&result;
	varg_t		 varg = {0};

	/*
	 * Decode the inbound door data, so we can look at the cmd.
	 */
	xdrmem_create(&xdrs_a, abuf, absz, XDR_DECODE);
	if (!xdr_varg(&xdrs_a, &varg)) {
		/*
		 * If the arguments can't be decoded, bail.
		 */
		if (varg.vers == V_ERROR)
			syslog(LOG_ERR, gettext("Arg version mismatch"));
		res.stat = NFSAUTH_DR_DECERR;
		goto encres;
	}

	/*
	 * Now set the args pointer to the proper version of the args
	 */
	switch (varg.vers) {
	case V_PROTO:
		ap = &varg.arg_u.arg;
		break;

		/* Additional arguments versions go here */

	default:
		syslog(LOG_ERR, gettext("Invalid args version"));
		goto encres;
	}

	/*
	 * Call the specified cmd
	 */
	switch (ap->cmd) {
		case NFSAUTH_ACCESS:
			nfsauth_access(&ap->areq, &rp->ares);
			rp->stat = NFSAUTH_DR_OKAY;
			break;
		default:
			rp->stat = NFSAUTH_DR_BADCMD;
			break;
	}

encres:
	/*
	 * Free space used to decode the args
	 */
	xdrs_a.x_op = XDR_FREE;
	(void) xdr_varg(&xdrs_a, &varg);
	xdr_destroy(&xdrs_a);

	/*
	 * Encode the results before passing thru door.
	 *
	 * The result (nfsauth_res_t) is always two int's, so we don't
	 * have to dynamically size (or allocate) the results buffer.
	 */
	xdrmem_create(&xdrs_r, rbuf, rbsz, XDR_ENCODE);
	if (!xdr_nfsauth_res(&xdrs_r, rp)) {
		/*
		 * return only the status code
		 */
		rp->stat = NFSAUTH_DR_EFAIL;
		rbsz = sizeof (uint_t);
		*rbuf = (uint_t)rp->stat;
	}
	xdr_destroy(&xdrs_r);

	(void) door_return((char *)rbuf, rbsz, NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */
}
