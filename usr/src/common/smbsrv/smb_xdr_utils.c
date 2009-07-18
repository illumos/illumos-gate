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
#include <sys/socket.h>

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
 * Encode an smb_netuserinfo_t into a buffer.
 */
int
smb_netuserinfo_encode(smb_netuserinfo_t *info, uint8_t *buf,
    uint32_t buflen, uint_t *nbytes)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!smb_netuserinfo_xdr(&xdrs, info))
		rc = -1;

	if (nbytes != NULL)
		*nbytes = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into an smb_netuserinfo_t.
 */
int
smb_netuserinfo_decode(smb_netuserinfo_t *info, uint8_t *buf,
    uint32_t buflen, uint_t *nbytes)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	bzero(info, sizeof (smb_netuserinfo_t));
	if (!smb_netuserinfo_xdr(&xdrs, info))
		rc = -1;

	if (nbytes != NULL)
		*nbytes = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	return (rc);
}

bool_t
xdr_smb_inaddr_t(XDR *xdrs, smb_inaddr_t *objp)
{
	if (!xdr_int32_t(xdrs, &objp->a_family))
		return (FALSE);
	if (objp->a_family == AF_INET) {
		if (!xdr_uint32_t(xdrs, (in_addr_t *)&objp->a_ipv4))
			return (FALSE);
	} else {
		if (!xdr_vector(xdrs, (char *)&objp->a_ipv6,
		    sizeof (objp->a_ipv6), sizeof (char), (xdrproc_t)xdr_char))
			return (FALSE);
	}
	return (TRUE);
}

/*
 * XDR encode/decode for smb_netuserinfo_t.
 */
bool_t
smb_netuserinfo_xdr(XDR *xdrs, smb_netuserinfo_t *objp)
{
	if (!xdr_uint64_t(xdrs, &objp->ui_session_id))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_uid))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_domain_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ui_domain, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_account_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ui_account, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_workstation_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ui_workstation, ~0))
		return (FALSE);
	if (!xdr_smb_inaddr_t(xdrs, &objp->ui_ipaddr))
		return (FALSE);
	if (!xdr_int32_t(xdrs, &objp->ui_native_os))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->ui_logon_time))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ui_numopens))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ui_flags))
		return (FALSE);
	return (TRUE);
}

/*
 * Encode an smb_netconnectinfo_t into a buffer.
 */
int
smb_netconnectinfo_encode(smb_netconnectinfo_t *info, uint8_t *buf,
    uint32_t buflen, uint_t *nbytes)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!smb_netconnectinfo_xdr(&xdrs, info))
		rc = -1;

	if (nbytes != NULL)
		*nbytes = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into an smb_netconnectinfo_t.
 */
int
smb_netconnectinfo_decode(smb_netconnectinfo_t *info, uint8_t *buf,
    uint32_t buflen, uint_t *nbytes)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	bzero(info, sizeof (smb_netconnectinfo_t));
	if (!smb_netconnectinfo_xdr(&xdrs, info))
		rc = -1;

	if (nbytes != NULL)
		*nbytes = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * XDR encode/decode for smb_netconnectinfo_t.
 */
bool_t
smb_netconnectinfo_xdr(XDR *xdrs, smb_netconnectinfo_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->ci_id))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ci_type))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ci_numopens))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ci_numusers))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ci_time))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ci_namelen))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ci_sharelen))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ci_username, MAXNAMELEN))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ci_share, MAXNAMELEN))
		return (FALSE);
	return (TRUE);
}

/*
 * Encode an smb_netfileinfo_t into a buffer.
 */
int
smb_netfileinfo_encode(smb_netfileinfo_t *info, uint8_t *buf,
    uint32_t buflen, uint_t *nbytes)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!smb_netfileinfo_xdr(&xdrs, info))
		rc = -1;

	if (nbytes != NULL)
		*nbytes = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into an smb_netfileinfo_t.
 */
int
smb_netfileinfo_decode(smb_netfileinfo_t *info, uint8_t *buf,
    uint32_t buflen, uint_t *nbytes)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	bzero(info, sizeof (smb_netfileinfo_t));
	if (!smb_netfileinfo_xdr(&xdrs, info))
		rc = -1;

	if (nbytes != NULL)
		*nbytes = xdr_getpos(&xdrs);
	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * XDR encode/decode for smb_netfileinfo_t.
 */
bool_t
smb_netfileinfo_xdr(XDR *xdrs, smb_netfileinfo_t *objp)
{
	if (!xdr_uint16_t(xdrs, &objp->fi_fid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->fi_uniqid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->fi_permissions))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->fi_numlocks))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->fi_pathlen))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->fi_namelen))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->fi_path, MAXPATHLEN))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->fi_username, MAXNAMELEN))
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
