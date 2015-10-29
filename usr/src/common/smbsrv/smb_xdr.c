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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/sunddi.h>
#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <string.h>
#include <strings.h>
#include <stddef.h>
#endif /* _KERNEL */
#include <smbsrv/smb_door.h>
#include <smbsrv/alloc.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>

#define	SMB_XDRMAX32_SZ		0xFFFFFFFF

bool_t smb_list_xdr(XDR *, list_t *,  const size_t, const size_t,
    const xdrproc_t);

bool_t
smb_buf32_xdr(XDR *xdrs, smb_buf32_t *objp)
{
	uint_t	maxsize = SMB_XDRMAX32_SZ;
	uint_t	size;

	if (xdrs->x_op != XDR_DECODE)
		maxsize = size = (uint_t)objp->len;

	if (xdr_bytes(xdrs, (char **)&objp->val, &size, maxsize)) {
		if (xdrs->x_op == XDR_DECODE)
			objp->len = (uint32_t)size;
		return (TRUE);
	}

	return (FALSE);
}

/*
 * When decoding into a string, ensure that objp->buf is NULL or
 * is pointing at a buffer large enough to receive the string.
 * Don't leave it as an uninitialized pointer.
 *
 * If objp->buf is NULL, xdr_string will allocate memory for the
 * string.  Otherwise it will copy into the available buffer.
 */
bool_t
smb_string_xdr(XDR *xdrs, smb_string_t *objp)
{
	if (!xdr_string(xdrs, &objp->buf, ~0))
		return (FALSE);
	return (TRUE);
}

const char *
smb_doorhdr_opname(uint32_t op)
{
	struct {
		uint32_t	op;
		const char	*name;
	} ops[] = {
		{ SMB_DR_NULL,			"null" },
		{ SMB_DR_ASYNC_RESPONSE,	"async_response" },
		{ SMB_DR_USER_AUTH_LOGON,	"user_auth_logon" },
		{ SMB_DR_USER_NONAUTH_LOGON,	"user_nonauth_logon" },
		{ SMB_DR_USER_AUTH_LOGOFF,	"user_auth_logoff" },
		{ SMB_DR_LOOKUP_SID,		"lookup_sid" },
		{ SMB_DR_LOOKUP_NAME,		"lookup_name" },
		{ SMB_DR_JOIN,			"join" },
		{ SMB_DR_GET_DCINFO,		"get_dcinfo" },
		{ SMB_DR_VSS_GET_COUNT,		"vss_get_count" },
		{ SMB_DR_VSS_GET_SNAPSHOTS,	"vss_get_snapshots" },
		{ SMB_DR_VSS_MAP_GMTTOKEN,	"vss_map_gmttoken" },
		{ SMB_DR_ADS_FIND_HOST,		"ads_find_host" },
		{ SMB_DR_QUOTA_QUERY,		"quota_query" },
		{ SMB_DR_QUOTA_SET,		"quota_set" },
		{ SMB_DR_DFS_GET_REFERRALS,	"dfs_get_referrals" },
		{ SMB_DR_SHR_HOSTACCESS,	"share_hostaccess" },
		{ SMB_DR_SHR_EXEC,		"share_exec" },
		{ SMB_DR_NOTIFY_DC_CHANGED,	"notify_dc_changed" }
	};
	int	i;

	for (i = 0; i < (sizeof (ops) / sizeof (ops[0])); ++i) {
		if (ops[i].op == op)
			return (ops[i].name);
	}

	return ("unknown");
}

/*
 * Encode a door header structure into an XDR buffer.
 */
int
smb_doorhdr_encode(smb_doorhdr_t *hdr, uint8_t *buf, uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!smb_doorhdr_xdr(&xdrs, hdr))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into a door header structure.
 */
int
smb_doorhdr_decode(smb_doorhdr_t *hdr, uint8_t *buf, uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	bzero(hdr, sizeof (smb_doorhdr_t));
	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	if (!smb_doorhdr_xdr(&xdrs, hdr))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

bool_t
smb_doorhdr_xdr(XDR *xdrs, smb_doorhdr_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->dh_magic))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_flags))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_fid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_op))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_txid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_datalen))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_resid))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_door_rc))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dh_status))
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
smb_inaddr_xdr(XDR *xdrs, smb_inaddr_t *objp)
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
	if (!xdr_uint16_t(xdrs, &objp->ui_smb_uid))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_domain_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ui_domain, ~0))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_account_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ui_account, ~0))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->ui_posix_uid))
		return (FALSE);
	if (!xdr_uint16_t(xdrs, &objp->ui_workstation_len))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->ui_workstation, ~0))
		return (FALSE);
	if (!smb_inaddr_xdr(xdrs, &objp->ui_ipaddr))
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
smb_gmttoken_query_xdr(XDR *xdrs, smb_gmttoken_query_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->gtq_count)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->gtq_path, ~0)) {
		return (FALSE);
	}
	return (TRUE);
}

static bool_t
smb_gmttoken_xdr(XDR *xdrs, smb_gmttoken_t *objp)
{
	if (!xdr_string(xdrs, objp, SMB_VSS_GMT_SIZE)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
smb_gmttoken_response_xdr(XDR *xdrs, smb_gmttoken_response_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->gtr_count)) {
		return (FALSE);
	}
	if (!xdr_array(xdrs, (char **)&objp->gtr_gmttokens.gtr_gmttokens_val,
	    (uint_t *)&objp->gtr_gmttokens.gtr_gmttokens_len, ~0,
	    sizeof (smb_gmttoken_t), (xdrproc_t)smb_gmttoken_xdr)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
smb_gmttoken_snapname_xdr(XDR *xdrs, smb_gmttoken_snapname_t *objp)
{
	if (!xdr_string(xdrs, &objp->gts_path, MAXPATHLEN)) {
		return (FALSE);
	}
	if (!xdr_string(xdrs, &objp->gts_gmttoken, SMB_VSS_GMT_SIZE)) {
		return (FALSE);
	}
	return (TRUE);
}

bool_t
smb_quota_xdr(XDR *xdrs, smb_quota_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->q_sidstr, SMB_SID_STRSZ,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->q_sidtype))
		return (FALSE);
	if (!xdr_uint64_t(xdrs, &objp->q_used))
		return (FALSE);
	if (!xdr_uint64_t(xdrs, &objp->q_thresh))
		return (FALSE);
	if (!xdr_uint64_t(xdrs, &objp->q_limit))
		return (FALSE);

	return (TRUE);
}

bool_t
smb_quota_sid_xdr(XDR *xdrs, smb_quota_sid_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->qs_sidstr, SMB_SID_STRSZ,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	return (TRUE);
}

bool_t
smb_quota_query_xdr(XDR *xdrs, smb_quota_query_t *objp)
{
	if (!xdr_string(xdrs, &objp->qq_root_path, ~0))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->qq_query_op))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->qq_single))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->qq_restart))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->qq_max_quota))
		return (FALSE);
	if (!smb_list_xdr(xdrs, &objp->qq_sid_list,
	    offsetof(smb_quota_sid_t, qs_list_node),
	    sizeof (smb_quota_sid_t), (xdrproc_t)smb_quota_sid_xdr))
		return (FALSE);

	return (TRUE);
}

bool_t
smb_quota_response_xdr(XDR *xdrs, smb_quota_response_t *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->qr_status))
		return (FALSE);
	if (!smb_list_xdr(xdrs, &objp->qr_quota_list,
	    offsetof(smb_quota_t, q_list_node),
	    sizeof (smb_quota_t), (xdrproc_t)smb_quota_xdr))
		return (FALSE);
	return (TRUE);
}

bool_t
smb_quota_set_xdr(XDR *xdrs, smb_quota_set_t *objp)
{
	if (!xdr_string(xdrs, &objp->qs_root_path, ~0))
		return (FALSE);
	if (!smb_list_xdr(xdrs, &objp->qs_quota_list,
	    offsetof(smb_quota_t, q_list_node),
	    sizeof (smb_quota_t), (xdrproc_t)smb_quota_xdr))
		return (FALSE);
	return (TRUE);
}

/*
 * XDR a list_t list of elements
 * offset - offset of list_node_t in list element
 * elsize - size of list element
 * elproc - XDR function for the list element
 */
bool_t
smb_list_xdr(XDR *xdrs, list_t *list,  const size_t offset,
    const size_t elsize, const xdrproc_t elproc)
{
	void *node;
	uint32_t count = 0;

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		node = list_head(list);
		while (node) {
			++count;
			node = list_next(list, node);
		}
		if (!xdr_uint32_t(xdrs, &count))
			return (FALSE);

		node = list_head(list);
		while (node) {
			if (!elproc(xdrs, node))
				return (FALSE);
			node = list_next(list, node);
		}
		return (TRUE);

	case XDR_DECODE:
		if (!xdr_uint32_t(xdrs, &count))
			return (FALSE);
		list_create(list, elsize, offset);
		while (count) {
			node = MEM_MALLOC("xdr", elsize);
			if (node == NULL)
				return (FALSE);
			if (!elproc(xdrs, node))
				return (FALSE);
			list_insert_tail(list, node);
			--count;
		}
		return (TRUE);

	case XDR_FREE:
		while ((node = list_head(list)) != NULL) {
			list_remove(list, node);
			(void) elproc(xdrs, node);
			MEM_FREE("xdr", node);
		}
		list_destroy(list);
		return (TRUE);
	}

	return (FALSE);
}

bool_t
dfs_target_pclass_xdr(XDR *xdrs, dfs_target_pclass_t *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
dfs_target_priority_xdr(XDR *xdrs, dfs_target_priority_t *objp)
{
	if (!dfs_target_pclass_xdr(xdrs, &objp->p_class))
		return (FALSE);

	if (!xdr_uint16_t(xdrs, &objp->p_rank))
		return (FALSE);

	return (TRUE);
}

bool_t
dfs_target_xdr(XDR *xdrs, dfs_target_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->t_server, DFS_SRVNAME_MAX,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->t_share, DFS_NAME_MAX,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->t_state))
		return (FALSE);

	if (!dfs_target_priority_xdr(xdrs, &objp->t_priority))
		return (FALSE);

	return (TRUE);
}

bool_t
dfs_reftype_xdr(XDR *xdrs, dfs_reftype_t *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
dfs_info_xdr(XDR *xdrs, dfs_info_t *objp)
{
	if (!xdr_vector(xdrs, (char *)objp->i_uncpath, DFS_PATH_MAX,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->i_comment, DFS_COMMENT_MAX,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_vector(xdrs, (char *)objp->i_guid,
	    UUID_PRINTABLE_STRING_LENGTH, sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->i_state))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->i_timeout))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->i_propflags))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->i_type))
		return (FALSE);

	if (!xdr_array(xdrs, (char **)&objp->i_targets,
	    (uint32_t *)&objp->i_ntargets, ~0, sizeof (dfs_target_t),
	    (xdrproc_t)dfs_target_xdr))
		return (FALSE);

	return (TRUE);
}

bool_t
dfs_referral_query_xdr(XDR *xdrs, dfs_referral_query_t *objp)
{
	if (!dfs_reftype_xdr(xdrs, &objp->rq_type))
		return (FALSE);

	if (!xdr_string(xdrs, &objp->rq_path, ~0))
		return (FALSE);

	return (TRUE);
}

bool_t
dfs_referral_response_xdr(XDR *xdrs, dfs_referral_response_t *objp)
{
	if (!dfs_info_xdr(xdrs, &objp->rp_referrals))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->rp_status))
		return (FALSE);

	return (TRUE);
}

bool_t
smb_shr_hostaccess_query_xdr(XDR *xdrs, smb_shr_hostaccess_query_t *objp)
{
	if (!xdr_string(xdrs, &objp->shq_none, ~0))
		return (FALSE);

	if (!xdr_string(xdrs, &objp->shq_ro, ~0))
		return (FALSE);

	if (!xdr_string(xdrs, &objp->shq_rw, ~0))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->shq_flag))
		return (FALSE);

	if (!smb_inaddr_xdr(xdrs, &objp->shq_ipaddr))
		return (FALSE);

	return (TRUE);
}

bool_t
smb_shr_execinfo_xdr(XDR *xdrs, smb_shr_execinfo_t *objp)
{
	if (!xdr_string(xdrs, &objp->e_sharename, ~0))
		return (FALSE);

	if (!xdr_string(xdrs, &objp->e_winname, ~0))
		return (FALSE);

	if (!xdr_string(xdrs, &objp->e_userdom, ~0))
		return (FALSE);

	if (!smb_inaddr_xdr(xdrs, &objp->e_srv_ipaddr))
		return (FALSE);

	if (!smb_inaddr_xdr(xdrs, &objp->e_cli_ipaddr))
		return (FALSE);

	if (!xdr_string(xdrs, &objp->e_cli_netbiosname, ~0))
		return (FALSE);

	if (!xdr_u_int(xdrs, &objp->e_uid))
		return (FALSE);

	if (!xdr_int(xdrs, &objp->e_type))
		return (FALSE);

	return (TRUE);
}

/*
 * The smbsrv ioctl callers include a CRC of the XDR encoded data,
 * and kmod ioctl handler checks it.  Both use this function.  This
 * is not really XDR related, but this is as good a place as any.
 */
#define	SMB_CRC_POLYNOMIAL	0xD8B5D8B5
uint32_t
smb_crc_gen(uint8_t *buf, size_t len)
{
	uint32_t crc = SMB_CRC_POLYNOMIAL;
	uint8_t *p;
	int i;

	for (p = buf, i = 0; i < len; ++i, ++p) {
		crc = (crc ^ (uint32_t)*p) + (crc << 12);

		if (crc == 0 || crc == 0xFFFFFFFF)
			crc = SMB_CRC_POLYNOMIAL;
	}

	return (crc);
}
