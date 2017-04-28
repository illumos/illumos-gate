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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2017 Joyent Inc
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * svc_auth_unix.c
 * Handles UNIX flavor authentication parameters on the service side of rpc.
 * There are two svc auth implementations here: AUTH_UNIX and AUTH_SHORT.
 * _svcauth_unix does full blown unix style uid, gid+gids auth,
 * _svcauth_short uses a shorthand auth to index into a cache of longhand auths.
 * Note: the shorthand has been gutted for efficiency.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tiuser.h>
#include <sys/tihdr.h>
#include <sys/t_kuser.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/svc.h>
#include <rpc/auth_unix.h>
#include <rpc/svc_auth.h>


/*
 * Unix longhand authenticator
 */
enum auth_stat
_svcauth_unix(struct svc_req *rqst, struct rpc_msg *msg)
{
	struct authunix_parms *aup;
	int32_t *buf;
	struct area {
		struct authunix_parms area_aup;
		char area_machname[MAX_MACHINE_NAME+1];
		gid_t area_gids[NGRPS];
	} *area;
	uint_t auth_len;
	uint_t str_len, gid_len;
	int i;

	CTASSERT(sizeof (struct area) <= RQCRED_SIZE);
	/* LINTED pointer alignment */
	area = (struct area *)rqst->rq_clntcred;
	aup = &area->area_aup;
	aup->aup_machname = area->area_machname;
	aup->aup_gids = area->area_gids;
	auth_len = msg->rm_call.cb_cred.oa_length;
	if (auth_len == 0)
		return (AUTH_BADCRED);

	/* LINTED pointer cast */
	buf = (int32_t *)msg->rm_call.cb_cred.oa_base;

	aup->aup_time = IXDR_GET_INT32(buf);
	str_len = IXDR_GET_U_INT32(buf);
	if (str_len > MAX_MACHINE_NAME)
		return (AUTH_BADCRED);
	bcopy((caddr_t)buf, aup->aup_machname, str_len);
	aup->aup_machname[str_len] = 0;
	str_len = RNDUP(str_len);
	buf += str_len / sizeof (int32_t);
	aup->aup_uid = IXDR_GET_INT32(buf);
	aup->aup_gid = IXDR_GET_INT32(buf);
	gid_len = IXDR_GET_U_INT32(buf);
	if (gid_len > NGRPS)
		return (AUTH_BADCRED);
	aup->aup_len = gid_len;
	for (i = 0; i < gid_len; i++) {
		aup->aup_gids[i] = IXDR_GET_INT32(buf);
	}
	/*
	 * five is the smallest unix credentials structure -
	 * timestamp, hostname len (0), uid, gid, and gids len (0).
	 */
	if ((5 + gid_len) * BYTES_PER_XDR_UNIT + str_len > auth_len)
		return (AUTH_BADCRED);

	rqst->rq_xprt->xp_verf.oa_flavor = AUTH_NULL;
	rqst->rq_xprt->xp_verf.oa_length = 0;

	return (AUTH_OK);
}


/*
 * Shorthand unix authenticator
 * Looks up longhand in a cache.
 */
/* ARGSUSED */
enum auth_stat
_svcauth_short(struct svc_req *rqst, struct rpc_msg *msg)
{
	return (AUTH_REJECTEDCRED);
}
