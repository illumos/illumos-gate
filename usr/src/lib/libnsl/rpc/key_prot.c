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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <rpc/rpc.h>
#include <rpc/key_prot.h>

/*
 * Originally ompiled from key_prot.x using rpcgen.
 */

bool_t
xdr_keystatus(XDR *xdrs, keystatus *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_keybuf(XDR *xdrs, keybuf objp)
{
	return (xdr_opaque(xdrs, objp, HEXKEYBYTES));
}

bool_t
xdr_keybuf3(XDR *xdrs, keybuf3 *objp)
{
	return (xdr_bytes(xdrs, (char **)&objp->keybuf3_val,
					(uint_t *)&objp->keybuf3_len, ~0));
}

bool_t
xdr_netnamestr(XDR *xdrs, netnamestr *objp)
{
	return (xdr_string(xdrs, objp, MAXNETNAMELEN));
}

bool_t
xdr_keylen_t(XDR *xdrs, keylen_t *objp)
{
	return (xdr_int(xdrs, objp));
}

bool_t
xdr_algtype_t(XDR *xdrs, algtype_t *objp)
{
	return (xdr_int(xdrs, objp));
}

bool_t
xdr_mechtype(XDR *xdrs, mechtype *objp)
{
	if (!xdr_keylen_t(xdrs, &objp->keylen))
		return (FALSE);
	return (xdr_algtype_t(xdrs, &objp->algtype));
}

bool_t
xdr_keynum_t(XDR *xdrs, keynum_t *objp)
{
	return (xdr_int(xdrs, objp));
}

bool_t
xdr_deskeyarray(XDR *xdrs, deskeyarray *objp)
{
	return (xdr_array(xdrs, (char **)&objp->deskeyarray_val,
		(uint_t *)&objp->deskeyarray_len, ~0,
		sizeof (des_block), (xdrproc_t)xdr_des_block));
}

bool_t
xdr_cryptkeyarg(XDR *xdrs, cryptkeyarg *objp)
{
	if (!xdr_netnamestr(xdrs, &objp->remotename))
		return (FALSE);
	return (xdr_des_block(xdrs, &objp->deskey));
}

bool_t
xdr_cryptkeyarg2(XDR *xdrs, cryptkeyarg2 *objp)
{
	if (!xdr_netnamestr(xdrs, &objp->remotename))
		return (FALSE);
	if (!xdr_netobj(xdrs, &objp->remotekey))
		return (FALSE);
	return (xdr_des_block(xdrs, &objp->deskey));
}

bool_t
xdr_cryptkeyarg3(XDR *xdrs, cryptkeyarg3 *objp)
{
	if (!xdr_netnamestr(xdrs, &objp->remotename))
		return (FALSE);
	if (!xdr_keybuf3(xdrs, &objp->remotekey))
		return (FALSE);
	if (!xdr_deskeyarray(xdrs, &objp->deskey))
		return (FALSE);
	if (!xdr_algtype_t(xdrs, &objp->algtype))
		return (FALSE);
	return (xdr_keylen_t(xdrs, &objp->keylen));
}

bool_t
xdr_cryptkeyres(XDR *xdrs, cryptkeyres *objp)
{
	if (!xdr_keystatus(xdrs, &objp->status))
		return (FALSE);
	if (objp->status != KEY_SUCCESS)
		return (TRUE);
	return (xdr_des_block(xdrs, &objp->cryptkeyres_u.deskey));
}

bool_t
xdr_cryptkeyres3(XDR *xdrs, cryptkeyres3 *objp)
{
	if (!xdr_keystatus(xdrs, &objp->status))
		return (FALSE);
	if (objp->status != KEY_SUCCESS)
		return (TRUE);
	return (xdr_deskeyarray(xdrs, &objp->cryptkeyres3_u.deskey));
}

bool_t
xdr_unixcred(XDR *xdrs, unixcred *objp)
{
	if (!xdr_u_int(xdrs, &objp->uid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->gid))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->gids.gids_val,
		(uint_t *)&objp->gids.gids_len, MAXGIDS,
		sizeof (uint_t), (xdrproc_t)xdr_u_int));
}

bool_t
xdr_unixcred3(XDR *xdrs, unixcred3 *objp)
{
	if (!xdr_u_int(xdrs, &objp->uid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->gid))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->gids.gids_val,
		(uint_t *)&objp->gids.gids_len, ~0,
		sizeof (uint_t), (xdrproc_t)xdr_u_int));
}

bool_t
xdr_getcredres(XDR *xdrs, getcredres *objp)
{
	if (!xdr_keystatus(xdrs, &objp->status))
		return (FALSE);
	if (objp->status != KEY_SUCCESS)
		return (TRUE);
	return (xdr_unixcred(xdrs, &objp->getcredres_u.cred));
}

bool_t
xdr_getcredres3(XDR *xdrs, getcredres3 *objp)
{
	if (!xdr_keystatus(xdrs, &objp->status))
		return (FALSE);
	if (objp->status != KEY_SUCCESS)
		return (TRUE);
	return (xdr_unixcred3(xdrs, &objp->getcredres3_u.cred));
}

bool_t
xdr_key_netstarg(XDR *xdrs, key_netstarg *objp)
{
	if (!xdr_keybuf(xdrs, objp->st_priv_key))
		return (FALSE);
	if (!xdr_keybuf(xdrs, objp->st_pub_key))
		return (FALSE);
	return (xdr_netnamestr(xdrs, &objp->st_netname));
}

bool_t
xdr_key_netstarg3(XDR *xdrs, key_netstarg3 *objp)
{
	if (!xdr_keybuf3(xdrs, &objp->st_priv_key))
		return (FALSE);
	if (!xdr_keybuf3(xdrs, &objp->st_pub_key))
		return (FALSE);
	if (!xdr_netnamestr(xdrs, &objp->st_netname))
		return (FALSE);
	if (!xdr_algtype_t(xdrs, &objp->algtype))
		return (FALSE);
	if (!xdr_keylen_t(xdrs, &objp->keylen))
		return (FALSE);
	return (xdr_des_block(xdrs, &objp->userkey));
}

bool_t
xdr_key_netstres(XDR *xdrs, key_netstres *objp)
{
	if (!xdr_keystatus(xdrs, &objp->status))
		return (FALSE);
	switch (objp->status) {
	case KEY_SUCCESS:
		if (!xdr_key_netstarg(xdrs, &objp->key_netstres_u.knet))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_key_netstres3(XDR *xdrs, key_netstres3 *objp)
{
	if (!xdr_keystatus(xdrs, &objp->status))
		return (FALSE);
	if (objp->status != KEY_SUCCESS)
		return (TRUE);
	return (xdr_key_netstarg3(xdrs, &objp->key_netstres3_u.knet));
}

bool_t
xdr_deskeyarg3(XDR *xdrs, deskeyarg3 *objp)
{
	if (!xdr_keybuf3(xdrs, &objp->pub_key))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->nkeys))
		return (FALSE);
	if (!xdr_algtype_t(xdrs, &objp->algtype))
		return (FALSE);
	return (xdr_keylen_t(xdrs, &objp->keylen));
}

bool_t
xdr_setkeyarg3(XDR *xdrs, setkeyarg3 *objp)
{
	if (!xdr_keybuf3(xdrs, &objp->key))
		return (FALSE);
	if (!xdr_des_block(xdrs, &objp->userkey))
		return (FALSE);
	if (!xdr_algtype_t(xdrs, &objp->algtype))
		return (FALSE);
	return (xdr_keylen_t(xdrs, &objp->keylen));
}
