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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <alloca.h>
#include "../lib/sharetab.h"
#include "mountd.h"

static void
nfsauth_access(auth_req *argp, auth_res *result)
{
	struct netbuf nbuf;
	struct share *sh;

	struct cln cln;

	result->auth_perm = NFSAUTH_DENIED;

	nbuf.len = argp->req_client.n_len;
	nbuf.buf = argp->req_client.n_bytes;

	if (nbuf.len == 0 || nbuf.buf == NULL)
		return;

	/*
	 * Find the export
	 */
	sh = findentry(argp->req_path);
	if (sh == NULL) {
		syslog(LOG_ERR, "%s not exported", argp->req_path);
		return;
	}

	cln_init_lazy(&cln, argp->req_netid, &nbuf);

	result->auth_perm = check_client(sh, &cln, argp->req_flavor,
	    argp->req_clnt_uid, argp->req_clnt_gid, argp->req_clnt_gids.len,
	    argp->req_clnt_gids.val, &result->auth_srv_uid,
	    &result->auth_srv_gid, &result->auth_srv_gids.len,
	    &result->auth_srv_gids.val);

	sharefree(sh);

	if (result->auth_perm == NFSAUTH_DENIED) {
		char *host = cln_gethost(&cln);
		if (host != NULL)
			syslog(LOG_ERR, "%s denied access to %s", host,
			    argp->req_path);
	}

	cln_fini(&cln);
}

void
nfsauth_func(void *cookie, char *dataptr, size_t arg_size,
	door_desc_t *dp, uint_t n_desc)

{
	nfsauth_arg_t	*ap;
	nfsauth_res_t	 res = {0};
	XDR		 xdrs_a;
	XDR		 xdrs_r;
	size_t		 rbsz;
	caddr_t		 rbuf;
	varg_t		 varg = {0};

	/*
	 * Decode the inbound door data, so we can look at the cmd.
	 */
	xdrmem_create(&xdrs_a, dataptr, arg_size, XDR_DECODE);
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
		res.stat = NFSAUTH_DR_DECERR;
		goto encres;
	}

	/*
	 * Call the specified cmd
	 */
	switch (ap->cmd) {
	case NFSAUTH_ACCESS:
		nfsauth_access(&ap->areq, &res.ares);
		res.stat = NFSAUTH_DR_OKAY;
		break;
	default:
		res.stat = NFSAUTH_DR_BADCMD;
		break;
	}

encres:
	/*
	 * Free space used to decode the args
	 */
	xdr_free(xdr_varg, (char *)&varg);
	xdr_destroy(&xdrs_a);

	/*
	 * Encode the results before passing thru door.
	 */
	rbsz = xdr_sizeof(xdr_nfsauth_res, &res);
	if (rbsz == 0)
		goto failed;
	rbuf = alloca(rbsz);

	xdrmem_create(&xdrs_r, rbuf, rbsz, XDR_ENCODE);
	if (!xdr_nfsauth_res(&xdrs_r, &res)) {
		xdr_destroy(&xdrs_r);
failed:
		xdr_free(xdr_nfsauth_res, (char *)&res);
		/*
		 * return only the status code
		 */
		res.stat = NFSAUTH_DR_EFAIL;
		rbsz = sizeof (uint_t);
		rbuf = (caddr_t)&res.stat;

		goto out;
	}
	xdr_destroy(&xdrs_r);
	xdr_free(xdr_nfsauth_res, (char *)&res);

out:
	(void) door_return((char *)rbuf, rbsz, NULL, 0);
	(void) door_return(NULL, 0, NULL, 0);
	/* NOTREACHED */
}
