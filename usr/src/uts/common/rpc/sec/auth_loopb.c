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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * auth_loopb.c, implements UNIX style authentication parameters in the
 * kernel.  Interfaces with svc_auth_loopback on the server.  See
 * auth_loopb.c for the user level implementation of the loopback auth.
 *
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/utsname.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>

/*
 * Unix authenticator operations vector
 */
static void	authloopback_nextverf(AUTH *);
static bool_t	authloopback_marshal(AUTH *, XDR *, struct cred *);
static bool_t	authloopback_validate(AUTH *, struct opaque_auth *);
static bool_t	authloopback_refresh(AUTH *, struct rpc_msg *, cred_t *);
static void	authloopback_destroy(AUTH *);

static struct auth_ops authloopback_ops = {
	authloopback_nextverf,
	authloopback_marshal,
	authloopback_validate,
	authloopback_refresh,
	authloopback_destroy,
	authany_wrap,
	authany_unwrap
};

/*
 * Create a kernel unix style authenticator.
 * Returns an auth handle.
 */
AUTH *
authloopback_create(void)
{
	/*
	 * Allocate and set up auth handle
	 */
	return (kmem_cache_alloc(authloopback_cache, KM_SLEEP));
}

/*
 *  The constructor of the authloopback_cache.
 */
/* ARGSUSED */
int
authloopback_init(void *buf, void *cdrarg, int kmflags)
{
	AUTH *auth = (AUTH *)buf;

	auth->ah_ops = &authloopback_ops;
	auth->ah_cred.oa_flavor = AUTH_LOOPBACK;
	auth->ah_verf = _null_auth;

	return (0);
}

/*
 * authloopback operations
 */
/* ARGSUSED */
static void
authloopback_nextverf(AUTH *auth)
{

	/* no action necessary */
}

static bool_t
authloopback_marshal(AUTH *auth, XDR *xdrs, struct cred *cr)
{
	char *sercred;
	XDR xdrm;
	bool_t ret;
	uint32_t gidlen, credsize, namelen, rounded_namelen;
	int32_t *ptr;
	char *nodename = uts_nodename();
	uint32_t maxgidlen;
	uint_t startpos;

	ASSERT(xdrs->x_op == XDR_ENCODE);
	ASSERT(auth->ah_cred.oa_flavor == AUTH_LOOPBACK);
	ASSERT(auth->ah_verf.oa_flavor == AUTH_NONE);
	ASSERT(auth->ah_verf.oa_length == 0);

	/*
	 * First we try a fast path to get through
	 * this very common operation.
	 */
	namelen = (uint32_t)strlen(nodename);
	if (namelen > MAX_MACHINE_NAME)
		return (FALSE);
	rounded_namelen = RNDUP(namelen);

	/*
	 * NFIELDS is a number of the following fields we are going to encode:
	 *   - stamp
	 *   - strlen(machinename)
	 *   - uid
	 *   - gid
	 *   - the number of gids
	 */
#define	NFIELDS	5
	CTASSERT(NFIELDS * BYTES_PER_XDR_UNIT + RNDUP(MAX_MACHINE_NAME) <=
	    MAX_AUTH_BYTES);
	maxgidlen = (MAX_AUTH_BYTES - NFIELDS * BYTES_PER_XDR_UNIT -
	    rounded_namelen) / BYTES_PER_XDR_UNIT;

	gidlen = crgetngroups(cr);
	if (gidlen > maxgidlen)
		return (FALSE);

	credsize = NFIELDS * BYTES_PER_XDR_UNIT + rounded_namelen +
	    gidlen * BYTES_PER_XDR_UNIT;
	ASSERT(credsize <= MAX_AUTH_BYTES);
#undef	NFIELDS

	/*
	 * We need to marshal both cred and verf parts of the rpc_msg body
	 * (call_body).  For the cred part we need to inline the auth_flavor
	 * and the opaque auth body size.  Then we inline the credsize bytes of
	 * the opaque auth body for the cred part.  Finally we add the
	 * AUTH_NONE verifier (its auth_flavor and the opaque auth body size).
	 */
	ptr = XDR_INLINE(xdrs, 2 * BYTES_PER_XDR_UNIT + credsize +
	    2 * BYTES_PER_XDR_UNIT);
	if (ptr != NULL) {
		/*
		 * We can do the fast path.
		 */
		const gid_t *gp = crgetgroups(cr);

		IXDR_PUT_U_INT32(ptr, AUTH_LOOPBACK);	/* cred flavor */
		IXDR_PUT_U_INT32(ptr, credsize);	/* cred len */

		IXDR_PUT_INT32(ptr, gethrestime_sec());
		IXDR_PUT_U_INT32(ptr, namelen);
		bcopy(nodename, ptr, namelen);
		if ((rounded_namelen - namelen) > 0)
			bzero((char *)ptr + namelen, rounded_namelen - namelen);
		ptr += rounded_namelen / BYTES_PER_XDR_UNIT;
		IXDR_PUT_U_INT32(ptr, crgetuid(cr));
		IXDR_PUT_U_INT32(ptr, crgetgid(cr));
		IXDR_PUT_U_INT32(ptr, gidlen);
		while (gidlen-- > 0)
			IXDR_PUT_U_INT32(ptr, *gp++);

		IXDR_PUT_U_INT32(ptr, AUTH_NONE);	/* verf flavor */
		IXDR_PUT_U_INT32(ptr, 0);		/* verf len */

		return (TRUE);
	}

	sercred = kmem_alloc(MAX_AUTH_BYTES, KM_SLEEP);

	/*
	 * Serialize the auth body data into sercred.
	 */
	xdrmem_create(&xdrm, sercred, MAX_AUTH_BYTES, XDR_ENCODE);
	startpos = XDR_GETPOS(&xdrm);
	if (!xdr_authloopback(&xdrm, cr)) {
		printf("authloopback_marshal: xdr_authloopback failed\n");
		ret = FALSE;
		goto done;
	}

	/*
	 * Make opaque auth credentials to point at the serialized auth body
	 * data.
	 */
	auth->ah_cred.oa_base = sercred;
	auth->ah_cred.oa_length = XDR_GETPOS(&xdrm) - startpos;
	ASSERT(auth->ah_cred.oa_length <= MAX_AUTH_BYTES);

	/*
	 * serialize credentials and verifier (null)
	 */
	if ((xdr_opaque_auth(xdrs, &(auth->ah_cred))) &&
	    (xdr_opaque_auth(xdrs, &(auth->ah_verf))))
		ret = TRUE;
	else
		ret = FALSE;

done:
	XDR_DESTROY(&xdrm);
	kmem_free(sercred, MAX_AUTH_BYTES);

	return (ret);
}

/* ARGSUSED */
static bool_t
authloopback_validate(AUTH *auth, struct opaque_auth *verf)
{
	return (TRUE);
}

/* ARGSUSED */
static bool_t
authloopback_refresh(AUTH *auth, struct rpc_msg *msg, cred_t *cr)
{
	return (FALSE);
}

static void
authloopback_destroy(register AUTH *auth)
{
	kmem_cache_free(authloopback_cache, auth);
}
