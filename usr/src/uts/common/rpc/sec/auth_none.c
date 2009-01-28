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
 * auth_none.c implements routines used to pass "null" credentials
 * and "null" verifiers in kernel RPC.
 */

#include <rpc/auth.h>

/*
 * Null authenticator operations vector
 */
static void	authnone_nextverf(AUTH *);
static bool_t	authnone_marshal(AUTH *, XDR *, struct cred *);
static bool_t	authnone_validate(AUTH *, struct opaque_auth *);
static bool_t	authnone_refresh(AUTH *, struct rpc_msg *, cred_t *);
static void	authnone_destroy(AUTH *);

static struct auth_ops auth_none_ops = {
	authnone_nextverf,
	authnone_marshal,
	authnone_validate,
	authnone_refresh,
	authnone_destroy,
	authany_wrap,
	authany_unwrap
};

/*
 * Create a kernel null style authenticator.
 * Returns an auth handle.
 */
AUTH *
authnone_create(void)
{
	/*
	 * Allocate and set up auth handle
	 */
	return (kmem_cache_alloc(authnone_cache, KM_SLEEP));
}

/*
 *  The constructor of the authnone_cache.
 */
/* ARGSUSED */
int
authnone_init(void *buf, void *cdrarg, int kmflags)
{
	AUTH *auth = (AUTH *)buf;

	auth->ah_ops = &auth_none_ops;

	/*
	 * Flavor of RPC message's credential and verifier should be set to
	 * AUTH_NONE. Opaque data associated with AUTH_NONE is undefined.
	 * The length of the opaque data should be zero.
	 *	oa_flavor = AUTH_NONE
	 *	oa_base = NULL
	 *	oa_length = 0
	 */
	auth->ah_cred = auth->ah_verf = _null_auth;

	return (0);
}

/*
 * authnone operations
 */
/* ARGSUSED */
static void
authnone_nextverf(AUTH *auth)
{
	/* no action necessary */
}

/* ARGSUSED */
static bool_t
authnone_marshal(AUTH *auth, XDR *xdrs, struct cred *cr)
{
	int32_t	*ptr;

	/*
	 * auth_none has no opaque data. Encode auth_none
	 * value with 0 len data for both cred and verf.
	 * We first try a fast path to complete this operation.
	 */
	ptr = XDR_INLINE(xdrs, 4 + 4 + 4 + 4);
	if (ptr) {
		IXDR_PUT_INT32(ptr, AUTH_NONE);
		IXDR_PUT_INT32(ptr, 0);
		IXDR_PUT_INT32(ptr, AUTH_NONE);
		IXDR_PUT_INT32(ptr, 0);
		return (TRUE);
	}

	/*
	 * serialize AUTH_NONE credential and AUTH_NONE verifier
	 */
	if ((xdr_opaque_auth(xdrs, &(auth->ah_cred))) &&
	    (xdr_opaque_auth(xdrs, &(auth->ah_verf))))
		return (TRUE);
	else
		return (FALSE);
}

/* ARGSUSED */
static bool_t
authnone_validate(AUTH *auth, struct opaque_auth *verf)
{
	return (TRUE);
}

/* ARGSUSED */
static bool_t
authnone_refresh(AUTH *auth, struct rpc_msg *msg, cred_t *cr)
{
	return (FALSE);
}

static void
authnone_destroy(AUTH *auth)
{
	kmem_cache_free(authnone_cache, auth);
}
