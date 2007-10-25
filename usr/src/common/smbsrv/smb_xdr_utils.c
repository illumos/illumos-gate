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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _KERNEL
#include <string.h>
#endif /* _KERNEL */
#include <smbsrv/smb_xdr.h>

#ifdef _KERNEL
/*
 * xdr_vector():
 *
 * XDR a fixed length array. Unlike variable-length arrays,
 * the storage of fixed length arrays is static and unfreeable.
 * > basep: base of the array
 * > size: size of the array
 * > elemsize: size of each element
 * > xdr_elem: routine to XDR each element
 */
#define	LASTUNSIGNED ((uint_t)0-1)
bool_t
xdr_vector(XDR *xdrs, char *basep, uint_t nelem,
	uint_t elemsize, xdrproc_t xdr_elem)
{
	uint_t i;
	char *elptr;

	elptr = basep;
	for (i = 0; i < nelem; i++) {
		if (!(*xdr_elem)(xdrs, elptr, LASTUNSIGNED))
			return (FALSE);
		elptr += elemsize;
	}
	return (TRUE);
}

/*
 * XDR an unsigned char
 */
bool_t
xdr_u_char(XDR *xdrs, uchar_t *cp)
{
	int i;

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		i = (*cp);
		return (XDR_PUTINT32(xdrs, &i));
	case XDR_DECODE:
		if (!XDR_GETINT32(xdrs, &i))
			return (FALSE);
		*cp = (uchar_t)i;
		return (TRUE);
	case XDR_FREE:
		return (TRUE);
	}
	return (FALSE);
}
#endif /* _KERNEL */

bool_t
xdr_smb_dr_string_t(xdrs, objp)
	XDR *xdrs;
	smb_dr_string_t *objp;
{
	if (!xdr_string(xdrs, &objp->buf, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_smb_dr_bytes_t(xdrs, objp)
	XDR *xdrs;
	smb_dr_bytes_t *objp;
{
	if (!xdr_array(xdrs, (char **)&objp->bytes_val,
	    (uint32_t *)&objp->bytes_len, ~0, sizeof (uint8_t),
	    (xdrproc_t)xdr_uint8_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_smb_dr_user_ctx_t(xdrs, objp)
	XDR *xdrs;
	smb_dr_user_ctx_t *objp;
{
	if (!xdr_uint64_t(xdrs, &objp->du_session_id))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->du_uid))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->du_domain_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->du_domain, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->du_account_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->du_account, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->du_workstation_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->du_workstation, ~0))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->du_ipaddr))
		return (FALSE);
	if (!xdr_int32_t(xdrs, &objp->du_native_os))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->du_logon_time))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->du_flags))
		return (FALSE);
	return (TRUE);
}


bool_t
xdr_smb_dr_ulist_t(xdrs, objp)
	XDR *xdrs;
	smb_dr_ulist_t *objp;
{
	if (!xdr_uint32_t(xdrs, &objp->dul_cnt))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->dul_users, SMB_DR_MAX_USERS,
		sizeof (smb_dr_user_ctx_t), (xdrproc_t)xdr_smb_dr_user_ctx_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_smb_dr_kshare_t(xdrs, objp)
	XDR *xdrs;
	smb_dr_kshare_t *objp;
{
	if (!xdr_int32_t(xdrs, &objp->k_op))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->k_path, MAXPATHLEN))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->k_sharename, MAXNAMELEN))
		return (FALSE);
	return (TRUE);
}
