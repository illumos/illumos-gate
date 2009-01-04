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

#include <sys/sunddi.h>
#ifndef _KERNEL
#include <string.h>
#include <strings.h>
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

/*
 * Encode an opipe header structure into a buffer.
 */
int
smb_opipe_hdr_encode(smb_opipe_hdr_t *hdr, uint8_t *buf, uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!smb_opipe_hdr_xdr(&xdrs, hdr))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into an opipe header structure.
 */
int
smb_opipe_hdr_decode(smb_opipe_hdr_t *hdr, uint8_t *buf, uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	bzero(hdr, sizeof (smb_opipe_hdr_t));
	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	if (!smb_opipe_hdr_xdr(&xdrs, hdr))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

bool_t
smb_opipe_hdr_xdr(XDR *xdrs, smb_opipe_hdr_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->oh_magic))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oh_fid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oh_op))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oh_datalen))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oh_resid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oh_status))
		return (FALSE);
	return (TRUE);
}

/*
 * Encode an opipe context structure into a buffer.
 */
int
smb_opipe_context_encode(smb_opipe_context_t *ctx, uint8_t *buf,
    uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!smb_opipe_context_xdr(&xdrs, ctx))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into an opipe context structure.
 */
int
smb_opipe_context_decode(smb_opipe_context_t *ctx, uint8_t *buf,
    uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	bzero(ctx, sizeof (smb_opipe_context_t));
	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	if (!smb_opipe_context_xdr(&xdrs, ctx))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

bool_t
smb_opipe_context_xdr(XDR *xdrs, smb_opipe_context_t *objp)
{
	if (!xdr_uint64_t(xdrs, &objp->oc_session_id))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->oc_uid))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->oc_domain_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->oc_domain, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->oc_account_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->oc_account, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->oc_workstation_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->oc_workstation, ~0))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oc_ipaddr))
		return (FALSE);
	if (!xdr_int32_t(xdrs, &objp->oc_native_os))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->oc_logon_time))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->oc_flags))
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
		sizeof (smb_opipe_context_t), (xdrproc_t)smb_opipe_context_xdr))
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

bool_t
xdr_smb_dr_get_gmttokens_t(XDR *xdrs, smb_dr_get_gmttokens_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->gg_count)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->gg_path, ~0)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_gmttoken(XDR *xdrs, gmttoken *objp)
{
	if (!xdr_string(xdrs, objp, SMB_VSS_GMT_SIZE)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_smb_dr_return_gmttokens_t(XDR *xdrs, smb_dr_return_gmttokens_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->rg_count)) {
		return (FALSE);
	}
	if (!xdr_array(xdrs, (char **)&objp->rg_gmttokens.rg_gmttokens_val,
	    (uint_t *)&objp->rg_gmttokens.rg_gmttokens_len, ~0,
	    sizeof (gmttoken), (xdrproc_t)xdr_gmttoken)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_smb_dr_map_gmttoken_t(XDR *xdrs, smb_dr_map_gmttoken_t *objp)
{
	if (!xdr_string(xdrs, &objp->mg_path, MAXPATHLEN)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->mg_gmttoken, SMB_VSS_GMT_SIZE)) {
		return (FALSE);
	}
	return (TRUE);
}
