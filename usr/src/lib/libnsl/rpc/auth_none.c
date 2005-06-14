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
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * auth_none.c
 * Creates a client authentication handle for passing "null"
 * credentials and verifiers to remote systems.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <rpc/types.h>
#include <rpc/trace.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#define	MAX_MARSHEL_SIZE 20


extern bool_t xdr_opaque_auth();

static struct auth_ops *authnone_ops();

static struct authnone_private {
	AUTH	no_client;
	char	marshalled_client[MAX_MARSHEL_SIZE];
	uint_t	mcnt;
} *authnone_private;

char *calloc();

AUTH *
authnone_create()
{
	struct authnone_private *ap;
	XDR xdr_stream;
	XDR *xdrs;
	extern mutex_t authnone_lock;

	/* VARIABLES PROTECTED BY authnone_lock: ap */

	trace1(TR_authnone_create, 0);
	mutex_lock(&authnone_lock);
	ap = authnone_private;
	if (ap == NULL) {
/* LINTED pointer alignment */
		ap = (struct authnone_private *)calloc(1, sizeof (*ap));
		if (ap == NULL) {
			mutex_unlock(&authnone_lock);
			trace1(TR_authnone_create, 1);
			return ((AUTH *)NULL);
		}
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
	mutex_unlock(&authnone_lock);
	trace1(TR_authnone_create, 1);
	return (&ap->no_client);
}

/*ARGSUSED*/
static bool_t
authnone_marshal(AUTH *client, XDR *xdrs)
{
	struct authnone_private *ap;
	bool_t dummy;
	extern mutex_t authnone_lock;

	trace1(TR_authnone_marshal, 0);
	mutex_lock(&authnone_lock);
	ap = authnone_private;
	if (ap == NULL) {
		mutex_unlock(&authnone_lock);
		trace1(TR_authnone_marshal, 1);
		return (FALSE);
	}
	dummy = (*xdrs->x_ops->x_putbytes)(xdrs,
			ap->marshalled_client, ap->mcnt);
	mutex_unlock(&authnone_lock);
	trace1(TR_authnone_marshal, 1);
	return (dummy);
}

/* All these unused parameters are required to keep ANSI-C from grumbling */
/*ARGSUSED*/
static void
authnone_verf(AUTH *client)
{
	trace1(TR_authnone_verf, 0);
	trace1(TR_authnone_verf, 1);
}

/*ARGSUSED*/
static bool_t
authnone_validate(AUTH *client, struct opaque_auth *opaque)
{
	trace1(TR_authnone_validate, 0);
	trace1(TR_authnone_validate, 1);
	return (TRUE);
}

/*ARGSUSED*/
static bool_t
authnone_refresh(AUTH *client, void *dummy)
{
	trace1(TR_authnone_refresh, 0);
	trace1(TR_authnone_refresh, 1);
	return (FALSE);
}

/*ARGSUSED*/
static void
authnone_destroy(AUTH *client)
{
	trace1(TR_authnone_destroy, 0);
	trace1(TR_authnone_destroy, 1);
}

static struct auth_ops *
authnone_ops()
{
	static struct auth_ops ops;
	extern mutex_t ops_lock;

/* VARIABLES PROTECTED BY ops_lock: ops */

	trace1(TR_authnone_ops, 0);
	mutex_lock(&ops_lock);
	if (ops.ah_nextverf == NULL) {
		ops.ah_nextverf = authnone_verf;
		ops.ah_marshal = authnone_marshal;
		ops.ah_validate = authnone_validate;
		ops.ah_refresh = authnone_refresh;
		ops.ah_destroy = authnone_destroy;
	}
	mutex_unlock(&ops_lock);
	trace1(TR_authnone_ops, 1);
	return (&ops);
}
