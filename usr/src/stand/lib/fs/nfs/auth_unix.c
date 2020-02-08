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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Adapted for use by the boot program.
 *
 * auth_unix.c, Implements UNIX style authentication parameters.
 *
 * The system is very weak.  The client uses no encryption for its
 * credentials and only sends null verifiers.  The server sends backs
 * null verifiers or optionally a verifier that suggests a new short hand
 * for the credentials.
 */

#include <stdlib.h>
#include <sys/sysmacros.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include "clnt.h"
#include <rpc/auth_unix.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/bootdebug.h>
#include "nfs_inet.h"

static struct auth_ops *authunix_ops();
/*
 * This struct is pointed to by the ah_private field of an auth_handle.
 */
struct audata {
	struct opaque_auth	au_origcred;	/* original credentials */
	struct opaque_auth	au_shcred;	/* short hand cred */
	uint_t			au_shfaults;	/* short hand cache faults */
	char			au_marshed[MAX_AUTH_BYTES];
	uint_t			au_mpos;	/* xdr pos at end of marshed */
};
#define	AUTH_PRIVATE(auth)	((struct audata *)auth->ah_private)

static void marshal_new_auth(AUTH *);

#define	dprintf	if (boothowto & RB_DEBUG) printf

/*
 * Create a unix style authenticator.
 * Returns an auth handle with the given stuff in it.
 */
AUTH *
authunix_create(char *machname, uid_t uid, gid_t gid, int len, gid_t *aup_gids)
{
	struct authunix_parms aup;
	char mymem[MAX_AUTH_BYTES];
	XDR xdrs;
	AUTH *auth;
	struct audata *au;

	/*
	 * Allocate and set up auth handle
	 */
	auth = (AUTH *) bkmem_alloc(sizeof (*auth));
	if (auth == NULL) {
		prom_panic("authunix_create: Cannot allocate memory.");
	}

	au = (struct audata *)bkmem_alloc(sizeof (*au));
	if (au == NULL) {
		prom_panic("authunix_create: Cannot allocate memory.");
	}

	/* setup authenticator. */
	auth->ah_ops = authunix_ops();
	auth->ah_private = (caddr_t)au;

	/* structure copies */
	auth->ah_verf = au->au_shcred = _null_auth;

	au->au_shfaults = 0;

	/*
	 * fill in param struct from the given params
	 */
	aup.aup_time = prom_gettime() / 1000;
	aup.aup_machname = machname;
	aup.aup_uid = uid;
	aup.aup_gid = gid;
	aup.aup_len = (uint_t)len;
	aup.aup_gids = (gid_t *)aup_gids;

	/*
	 * Serialize the parameters into origcred
	 */
	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
	if (!xdr_authunix_parms(&xdrs, &aup)) {
		prom_panic("authunix_create:  xdr_authunix_parms failed");
	}
	au->au_origcred.oa_length = len = XDR_GETPOS(&xdrs);
	au->au_origcred.oa_flavor = (uint_t)AUTH_UNIX;
	if ((au->au_origcred.oa_base = bkmem_alloc((uint_t)len)) == NULL) {
		prom_panic("authunix_create: memory alloc failed");
	}
	(void) bcopy(mymem, au->au_origcred.oa_base, (uint_t)len);

	/*
	 * set auth handle to reflect new cred.
	 */
	auth->ah_cred = au->au_origcred;
	marshal_new_auth(auth);
	return (auth);
}

/*
 * authunix operations
 */

/* ARGSUSED */
static void
authunix_nextverf(AUTH *auth)
{
}

/* ARGSUSED */
static bool_t
authunix_marshal(AUTH *auth, XDR *xdrs, cred_t *cr)
{
	struct audata *au = AUTH_PRIVATE(auth);

	return (XDR_PUTBYTES(xdrs, au->au_marshed, au->au_mpos));
}

static bool_t
authunix_validate(AUTH *auth, struct opaque_auth *verf)
{
	struct audata *au;
	XDR xdrs;

	if (verf->oa_flavor == AUTH_SHORT) {
		au = AUTH_PRIVATE(auth);


		xdrmem_create(&xdrs, verf->oa_base, verf->oa_length,
		    XDR_DECODE);

		if (xdr_opaque_auth(&xdrs, &au->au_shcred)) {
			auth->ah_cred = au->au_shcred;
		} else {
			xdrs.x_op = XDR_FREE;
			(void) xdr_opaque_auth(&xdrs, &au->au_shcred);
			au->au_shcred.oa_base = 0;
			auth->ah_cred = au->au_origcred;
		}
		marshal_new_auth(auth);
	}

	return (TRUE);
}

/*ARGSUSED*/
static bool_t
authunix_refresh(AUTH *auth, struct rpc_msg *msg, cred_t *cr)
{
	struct audata *au = AUTH_PRIVATE(auth);
	struct authunix_parms aup;
	XDR xdrs;
	int stat;

	if (auth->ah_cred.oa_base == au->au_origcred.oa_base) {
		/* there is no hope.  Punt */
		return (FALSE);
	}
	au->au_shfaults ++;

	/* first deserialize the creds back into a struct authunix_parms */
	aup.aup_machname = (char *)0;
	aup.aup_gids = (gid_t *)0;
	xdrmem_create(&xdrs, au->au_origcred.oa_base,
			au->au_origcred.oa_length, XDR_DECODE);
	stat = xdr_authunix_parms(&xdrs, &aup);
	if (!stat)
		goto done;

	/* update the time and serialize in place */
	aup.aup_time = (prom_gettime() / 1000);
	xdrs.x_op = XDR_ENCODE;
	(void) XDR_SETPOS(&xdrs, 0);
	stat = xdr_authunix_parms(&xdrs, &aup);
	if (!stat)
		goto done;
	auth->ah_cred = au->au_origcred;
	marshal_new_auth(auth);
done:
	/* free the struct authunix_parms created by deserializing */
	xdrs.x_op = XDR_FREE;
	(void) xdr_authunix_parms(&xdrs, &aup);
	XDR_DESTROY(&xdrs);
	return (stat);
}

static void
authunix_destroy(AUTH *auth)
{
	struct audata *au = AUTH_PRIVATE(auth);

	if (au->au_shcred.oa_base != NULL)
		bkmem_free(au->au_shcred.oa_base, au->au_shcred.oa_length);
	bkmem_free(auth->ah_private, sizeof (struct audata));
	if (auth->ah_verf.oa_base != NULL)
		bkmem_free(auth->ah_verf.oa_base, auth->ah_verf.oa_length);
	bkmem_free((caddr_t)auth, sizeof (*auth));
}

/*
 * Marshals (pre-serializes) an auth struct.
 * sets private data, au_marshed and au_mpos
 */
static void
marshal_new_auth(AUTH *auth)
{
	XDR xdr_stream;
	XDR *xdrs = &xdr_stream;
	struct audata *au = AUTH_PRIVATE(auth);

	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
	if ((!xdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
	    (!xdr_opaque_auth(xdrs, &(auth->ah_verf)))) {
		dprintf("marshal_new_auth - Fatal marshalling problem");
	} else {
		au->au_mpos = XDR_GETPOS(xdrs);
	}
	XDR_DESTROY(xdrs);
}


static struct auth_ops *
authunix_ops(void)
{
	static struct auth_ops ops;

	if (ops.ah_nextverf == 0) {
		ops.ah_nextverf = authunix_nextverf;
		ops.ah_marshal = authunix_marshal;
		ops.ah_validate = authunix_validate;
		ops.ah_refresh = authunix_refresh;
		ops.ah_destroy = authunix_destroy;
	}
	return (&ops);
}

/*
 * XDR for unix authentication parameters.
 */
bool_t
xdr_authunix_parms(XDR *xdrs, struct authunix_parms *p)
{
	if (xdr_u_int(xdrs, &(p->aup_time)) &&
	    xdr_string(xdrs, &(p->aup_machname), MAX_MACHINE_NAME) &&
	    xdr_int(xdrs, (int *)&(p->aup_uid)) &&
	    xdr_int(xdrs, (int *)&(p->aup_gid)) &&
	    xdr_array(xdrs, (caddr_t *)&(p->aup_gids),
		    &(p->aup_len), NGRPS, sizeof (int), xdr_int)) {
		return (TRUE);
	}
	return (FALSE);
}
