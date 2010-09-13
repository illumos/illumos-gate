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

/* from SunOS 4.1 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * modified for use by the boot program.
 *
 * auth_none.c
 * Creates a client authentication handle for passing "null"
 * credentials and verifiers to remote systems.
 */

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include "clnt.h"

#define	MAX_MARSHEL_SIZE 20

static struct auth_ops *authnone_ops();

static struct authnone_private {
	AUTH	no_client;
	char	marshalled_client[MAX_MARSHEL_SIZE];
	uint_t	mcnt;
} *authnone_private;

static struct authnone_private authnone_local;

AUTH *
authnone_create(void)
{
	struct authnone_private *ap = authnone_private;
	XDR xdr_stream;
	XDR *xdrs;

	if (ap == 0) {
		ap = &authnone_local;
		authnone_private = ap;
	}
	if (!ap->mcnt) {
		ap->no_client.ah_cred = ap->no_client.ah_verf = _null_auth;
		ap->no_client.ah_ops = authnone_ops();
		xdrs = &xdr_stream;
		xdrmem_create(xdrs, ap->marshalled_client,
			(uint_t)MAX_MARSHEL_SIZE, XDR_ENCODE);
		(void) xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
		(void) xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
		ap->mcnt = XDR_GETPOS(xdrs);
		XDR_DESTROY(xdrs);
	}
	return (&ap->no_client);
}

/*ARGSUSED*/
static bool_t
authnone_marshal(AUTH *client, XDR *xdrs, struct cred *cr)
{
	struct authnone_private *ap = authnone_private;

	if (ap == 0)
		return (0);
	return ((*xdrs->x_ops->x_putbytes)(xdrs,
	    ap->marshalled_client, ap->mcnt));
}

/* ARGSUSED */
static void
authnone_verf(AUTH *foo)
{
}

/* ARGSUSED */
static bool_t
authnone_validate(AUTH *foo, struct opaque_auth *bar)
{
	return (TRUE);
}

/* ARGSUSED */
static bool_t
authnone_refresh(AUTH *foo, struct rpc_msg *bar, cred_t *cr)
{
	return (FALSE);
}

/* ARGSUSED */
static void
authnone_destroy(AUTH *foo)
{
}

static struct auth_ops *
authnone_ops(void)
{
	static struct auth_ops ops;

	if (ops.ah_nextverf == NULL) {
		ops.ah_nextverf = authnone_verf;
		ops.ah_marshal = authnone_marshal;
		ops.ah_validate = authnone_validate;
		ops.ah_refresh = authnone_refresh;
		ops.ah_destroy = authnone_destroy;
	}
	return (&ops);
}
