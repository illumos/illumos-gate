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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_dfs.h>
#include <smbsrv/smb_door.h>

/*
 * Get Referral response header flags
 * For exact meaning refer to MS-DFSC spec.
 *
 * R: ReferralServers
 * S: StorageServers
 * T: TargetFailback
 */
#define	DFS_HDRFLG_R		0x00000001
#define	DFS_HDRFLG_S		0x00000002
#define	DFS_HDRFLG_T		0x00000004

/*
 * Entry flags
 */
#define	DFS_ENTFLG_T		0x0004

/*
 * Referral entry types/versions
 */
#define	DFS_REFERRAL_V1		0x0001
#define	DFS_REFERRAL_V2		0x0002
#define	DFS_REFERRAL_V3		0x0003
#define	DFS_REFERRAL_V4		0x0004

/*
 * Valid values for ServerType field in referral entries
 */
#define	DFS_SRVTYPE_NONROOT	0x0000
#define	DFS_SRVTYPE_ROOT	0x0001

/*
 * Size of the fix part for each referral entry type
 */
#define	DFS_REFV1_ENTSZ		8
#define	DFS_REFV2_ENTSZ		22
#define	DFS_REFV3_ENTSZ		34
#define	DFS_REFV4_ENTSZ		34

static dfs_reftype_t smb_dfs_get_reftype(const char *);
static void smb_dfs_encode_hdr(smb_xa_t *, dfs_info_t *);
static uint32_t smb_dfs_encode_refv1(smb_request_t *, smb_xa_t *, dfs_info_t *);
static uint32_t smb_dfs_encode_refv2(smb_request_t *, smb_xa_t *, dfs_info_t *);
static uint32_t smb_dfs_encode_refv3_v4(smb_request_t *, smb_xa_t *,
    dfs_info_t *, uint16_t);
static void smb_dfs_encode_targets(smb_xa_t *, dfs_info_t *);
static uint32_t smb_dfs_referrals_get(smb_request_t *, char *, dfs_reftype_t,
    dfs_referral_response_t *);
static void smb_dfs_referrals_free(dfs_referral_response_t *);
static uint16_t smb_dfs_referrals_unclen(dfs_info_t *, uint16_t);

/*
 * [MS-CIFS]
 *
 * 2.2.6.17    TRANS2_REPORT_DFS_INCONSISTENCY (0x0011)
 *
 *  This Transaction2 subcommand was introduced in the NT LAN Manager dialect.
 *  This subcommand is reserved but not implemented.
 *
 *  Clients SHOULD NOT send requests using this command code. Servers receiving
 *  requests with this command code SHOULD return STATUS_NOT_IMPLEMENTED
 *  (ERRDOS/ERRbadfunc).
 */
smb_sdrc_t /*ARGSUSED*/
smb_com_trans2_report_dfs_inconsistency(smb_request_t *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}

/*
 * See [MS-DFSC] for details about this command
 */
smb_sdrc_t
smb_com_trans2_get_dfs_referral(smb_request_t *sr, smb_xa_t *xa)
{
	dfs_info_t *referrals;
	dfs_referral_response_t refrsp;
	dfs_reftype_t reftype;
	uint16_t maxreflvl;
	uint32_t status;
	char *path;

	/* This request is only valid over IPC connections */
	if (!STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%wu", sr, &maxreflvl, &path)
	    != 0) {
		return (SDRC_ERROR);
	}

	reftype = smb_dfs_get_reftype((const char *)path);

	switch (reftype) {
	case DFS_REFERRAL_INVALID:
		/* Need to check the error for this case */
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, ERRDOS,
		    ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);

	case DFS_REFERRAL_DOMAIN:
	case DFS_REFERRAL_DC:
		/* MS-DFSC: this error is returned by non-DC root */
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, ERRDOS,
		    ERROR_INVALID_PARAMETER);
		return (SDRC_ERROR);

	case DFS_REFERRAL_SYSVOL:
		/* MS-DFSC: this error is returned by non-DC root */
		smbsr_error(sr, NT_STATUS_NO_SUCH_DEVICE, ERRDOS,
		    ERROR_BAD_DEVICE);
		return (SDRC_ERROR);

	default:
		break;
	}

	status = smb_dfs_referrals_get(sr, path, reftype, &refrsp);
	if (status != NT_STATUS_SUCCESS)
		return (SDRC_ERROR);

	referrals = &refrsp.rp_referrals;
	smb_dfs_encode_hdr(xa, referrals);

	/*
	 * Server can respond with a referral version which is not
	 * bigger than but could be less than the maximum specified
	 * in the request.
	 */
	switch (maxreflvl) {
	case DFS_REFERRAL_V1:
		status = smb_dfs_encode_refv1(sr, xa, referrals);
		break;

	case DFS_REFERRAL_V2:
		status = smb_dfs_encode_refv2(sr, xa, referrals);
		break;

	case DFS_REFERRAL_V3:
		status = smb_dfs_encode_refv3_v4(sr, xa, referrals, maxreflvl);
		break;

	default:
		status = smb_dfs_encode_refv3_v4(sr, xa, referrals,
		    DFS_REFERRAL_V4);
		break;
	}

	smb_dfs_referrals_free(&refrsp);

	return ((status == NT_STATUS_SUCCESS) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * [MS-DFSC]: REQ_GET_DFS_REFERRAL
 *
 * Determines the referral type based on the specified path:
 *
 * Domain referral:
 *    ""
 *
 * DC referral:
 *    \<domain>
 *
 * Sysvol referral:
 *    \<domain>\SYSVOL
 *    \<domain>\NETLOGON
 *
 * Root referral:
 *    \<domain>\<dfsname>
 *    \<server>\<dfsname>
 *
 * Link referral:
 *    \<domain>\<dfsname>\<linkpath>
 *    \<server>\<dfsname>\<linkpath>
 */
static dfs_reftype_t
smb_dfs_get_reftype(const char *path)
{
	smb_unc_t unc;
	dfs_reftype_t reftype = 0;

	if (*path == '\0')
		return (DFS_REFERRAL_DOMAIN);

	if (smb_unc_init(path, &unc) != 0)
		return (DFS_REFERRAL_INVALID);

	if (unc.unc_path != NULL) {
		reftype = DFS_REFERRAL_LINK;
	} else if (unc.unc_share != NULL) {
		if ((smb_strcasecmp(unc.unc_share, "SYSVOL", 0) == 0) ||
		    (smb_strcasecmp(unc.unc_share, "NETLOGON", 0) == 0)) {
			reftype = DFS_REFERRAL_SYSVOL;
		} else {
			reftype = DFS_REFERRAL_ROOT;
		}
	} else if (unc.unc_server != NULL) {
		reftype = DFS_REFERRAL_DC;
	}

	smb_unc_free(&unc);
	return (reftype);
}

static void
smb_dfs_encode_hdr(smb_xa_t *xa, dfs_info_t *referrals)
{
	uint16_t path_consumed;
	uint32_t flags;

	path_consumed = smb_wcequiv_strlen(referrals->i_uncpath);
	flags = DFS_HDRFLG_S;
	if (referrals->i_type == DFS_OBJECT_ROOT)
		flags |= DFS_HDRFLG_R;

	(void) smb_mbc_encodef(&xa->rep_param_mb, "w", 0);
	(void) smb_mbc_encodef(&xa->rep_data_mb, "wwl", path_consumed,
	    referrals->i_ntargets, flags);
}

static uint32_t
smb_dfs_encode_refv1(smb_request_t *sr, smb_xa_t *xa, dfs_info_t *referrals)
{
	uint16_t entsize, rep_bufsize;
	uint16_t server_type;
	uint16_t flags = 0;
	uint16_t r;
	char *target;

	rep_bufsize = MBC_MAXBYTES(&xa->rep_data_mb);

	server_type = (referrals->i_type == DFS_OBJECT_ROOT) ?
	    DFS_SRVTYPE_ROOT : DFS_SRVTYPE_NONROOT;

	target = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	for (r = 0; r < referrals->i_ntargets; r++) {
		(void) snprintf(target, MAXPATHLEN, "\\%s\\%s",
		    referrals->i_targets[r].t_server,
		    referrals->i_targets[r].t_share);

		entsize = DFS_REFV1_ENTSZ + smb_wcequiv_strlen(target) + 2;
		if (entsize > rep_bufsize)
			break;

		(void) smb_mbc_encodef(&xa->rep_data_mb, "wwwwU",
		    DFS_REFERRAL_V1, entsize, server_type, flags, target);
		rep_bufsize -= entsize;
	}

	kmem_free(target, MAXPATHLEN);

	/*
	 * Need room for at least one entry.
	 * Windows will silently drop targets that do not fit in
	 * the response buffer.
	 */
	if (r == 0) {
		smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
		    ERRDOS, ERROR_MORE_DATA);
		return (NT_STATUS_BUFFER_OVERFLOW);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * Prepare a response with V2 referral format.
 *
 * Here is the response packet format.
 * All the strings come after all the fixed size entry headers.
 * These headers contain offsets to the strings at the end. Note
 * that the two "dfs_path" after the last entry is shared between
 * all the entries.
 *
 * ent1-hdr
 * ent2-hdr
 * ...
 * entN-hdr
 *   dfs_path
 *   dfs_path
 *   target1
 *   target2
 *   ...
 *   targetN
 *
 * MS-DFSC mentions that strings can come after each entry header or all after
 * the last entry header. Windows responses are in the format above.
 */
static uint32_t
smb_dfs_encode_refv2(smb_request_t *sr, smb_xa_t *xa, dfs_info_t *referrals)
{
	uint16_t entsize, rep_bufsize;
	uint16_t server_type;
	uint16_t flags = 0;
	uint32_t proximity = 0;
	uint16_t path_offs, altpath_offs, netpath_offs;
	uint16_t targetsz, total_targetsz = 0;
	uint16_t dfs_pathsz;
	uint16_t r;

	rep_bufsize = MBC_MAXBYTES(&xa->rep_data_mb);
	dfs_pathsz = smb_wcequiv_strlen(referrals->i_uncpath) + 2;
	entsize = DFS_REFV2_ENTSZ + dfs_pathsz + dfs_pathsz +
	    smb_dfs_referrals_unclen(referrals, 0);

	if (entsize > rep_bufsize) {
		/* need room for at least one referral */
		smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
		    ERRDOS, ERROR_MORE_DATA);
		return (NT_STATUS_BUFFER_OVERFLOW);
	}

	server_type = (referrals->i_type == DFS_OBJECT_ROOT) ?
	    DFS_SRVTYPE_ROOT : DFS_SRVTYPE_NONROOT;

	rep_bufsize -= entsize;
	entsize = DFS_REFV2_ENTSZ;

	for (r = 0; r < referrals->i_ntargets; r++) {
		path_offs = (referrals->i_ntargets - r) * DFS_REFV2_ENTSZ;
		altpath_offs = path_offs + dfs_pathsz;
		netpath_offs = altpath_offs + dfs_pathsz + total_targetsz;
		targetsz = smb_dfs_referrals_unclen(referrals, r);

		if (r != 0) {
			entsize = DFS_REFV2_ENTSZ + targetsz;
			if (entsize > rep_bufsize)
				/* silently drop targets that do not fit */
				break;
			rep_bufsize -= entsize;
		}

		(void) smb_mbc_encodef(&xa->rep_data_mb, "wwwwllwww",
		    DFS_REFERRAL_V2, DFS_REFV2_ENTSZ, server_type, flags,
		    proximity, referrals->i_timeout, path_offs, altpath_offs,
		    netpath_offs);

		total_targetsz += targetsz;
	}

	smb_dfs_encode_targets(xa, referrals);

	return (NT_STATUS_SUCCESS);
}

/*
 * Prepare a response with V3/V4 referral format.
 *
 * For more details, see comments for smb_dfs_encode_refv2() or see
 * MS-DFSC specification.
 */
static uint32_t
smb_dfs_encode_refv3_v4(smb_request_t *sr, smb_xa_t *xa, dfs_info_t *referrals,
    uint16_t ver)
{
	uint16_t entsize, rep_bufsize, hdrsize;
	uint16_t server_type;
	uint16_t flags = 0;
	uint16_t path_offs, altpath_offs, netpath_offs;
	uint16_t targetsz, total_targetsz = 0;
	uint16_t dfs_pathsz;
	uint16_t r;

	hdrsize = (ver == DFS_REFERRAL_V3) ? DFS_REFV3_ENTSZ : DFS_REFV4_ENTSZ;
	rep_bufsize = MBC_MAXBYTES(&xa->rep_data_mb);
	dfs_pathsz = smb_wcequiv_strlen(referrals->i_uncpath) + 2;
	entsize = hdrsize + dfs_pathsz + dfs_pathsz +
	    smb_dfs_referrals_unclen(referrals, 0);

	if (entsize > rep_bufsize) {
		/* need room for at least one referral */
		smbsr_warn(sr, NT_STATUS_BUFFER_OVERFLOW,
		    ERRDOS, ERROR_MORE_DATA);
		return (NT_STATUS_BUFFER_OVERFLOW);
	}

	server_type = (referrals->i_type == DFS_OBJECT_ROOT) ?
	    DFS_SRVTYPE_ROOT : DFS_SRVTYPE_NONROOT;

	rep_bufsize -= entsize;

	for (r = 0; r < referrals->i_ntargets; r++) {
		path_offs = (referrals->i_ntargets - r) * hdrsize;
		altpath_offs = path_offs + dfs_pathsz;
		netpath_offs = altpath_offs + dfs_pathsz + total_targetsz;
		targetsz = smb_dfs_referrals_unclen(referrals, r);

		if (r != 0) {
			entsize = hdrsize + targetsz;
			if (entsize > rep_bufsize)
				/* silently drop targets that do not fit */
				break;
			rep_bufsize -= entsize;
			flags = 0;
		} else if (ver == DFS_REFERRAL_V4) {
			flags = DFS_ENTFLG_T;
		}

		(void) smb_mbc_encodef(&xa->rep_data_mb, "wwwwlwww16.",
		    ver, hdrsize, server_type, flags,
		    referrals->i_timeout, path_offs, altpath_offs,
		    netpath_offs);

		total_targetsz += targetsz;
	}

	smb_dfs_encode_targets(xa, referrals);

	return (NT_STATUS_SUCCESS);
}

/*
 * Encodes DFS path, and target strings which come after fixed header
 * entries.
 *
 * Windows 2000 and earlier set the DFSAlternatePathOffset to point to
 * an 8.3 string representation of the string pointed to by
 * DFSPathOffset if it is not a legal 8.3 string. Otherwise, if
 * DFSPathOffset points to a legal 8.3 string, DFSAlternatePathOffset
 * points to a separate copy of the same string. Windows Server 2003,
 * Windows Server 2008 and Windows Server 2008 R2 set the
 * DFSPathOffset and DFSAlternatePathOffset fields to point to separate
 * copies of the identical string.
 *
 * Following Windows 2003 and later here.
 */
static void
smb_dfs_encode_targets(smb_xa_t *xa, dfs_info_t *referrals)
{
	char *target;
	int r;

	(void) smb_mbc_encodef(&xa->rep_data_mb, "UU", referrals->i_uncpath,
	    referrals->i_uncpath);

	target = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	for (r = 0; r < referrals->i_ntargets; r++) {
		(void) snprintf(target, MAXPATHLEN, "\\%s\\%s",
		    referrals->i_targets[r].t_server,
		    referrals->i_targets[r].t_share);
		(void) smb_mbc_encodef(&xa->rep_data_mb, "U", target);
	}
	kmem_free(target, MAXPATHLEN);
}

/*
 * Get referral information for the specified path from user space
 * using a door call.
 */
static uint32_t
smb_dfs_referrals_get(smb_request_t *sr, char *dfs_path, dfs_reftype_t reftype,
    dfs_referral_response_t *refrsp)
{
	dfs_referral_query_t	req;
	int			rc;

	req.rq_type = reftype;
	req.rq_path = dfs_path;

	bzero(refrsp, sizeof (dfs_referral_response_t));
	refrsp->rp_status = NT_STATUS_NOT_FOUND;

	rc = smb_kdoor_upcall(sr->sr_server, SMB_DR_DFS_GET_REFERRALS,
	    &req, dfs_referral_query_xdr, refrsp, dfs_referral_response_xdr);

	if (rc != 0 || refrsp->rp_status != ERROR_SUCCESS) {
		smbsr_error(sr, NT_STATUS_NO_SUCH_DEVICE, ERRDOS,
		    ERROR_BAD_DEVICE);
		return (NT_STATUS_NO_SUCH_DEVICE);
	}

	(void) strsubst(refrsp->rp_referrals.i_uncpath, '/', '\\');
	return (NT_STATUS_SUCCESS);
}

static void
smb_dfs_referrals_free(dfs_referral_response_t *refrsp)
{
	xdr_free(dfs_referral_response_xdr, (char *)refrsp);
}

/*
 * Returns the Unicode string length for the target UNC of
 * the specified entry by 'refno'
 *
 * Note that the UNC path should be encoded with ONE leading
 * slash not two as is common to user-visible UNC paths.
 */
static uint16_t
smb_dfs_referrals_unclen(dfs_info_t *referrals, uint16_t refno)
{
	uint16_t len;

	if (refno >= referrals->i_ntargets)
		return (0);

	/* Encoded target UNC \server\share */
	len = smb_wcequiv_strlen(referrals->i_targets[refno].t_server) +
	    smb_wcequiv_strlen(referrals->i_targets[refno].t_share) +
	    smb_wcequiv_strlen("\\\\") + 2; /* two '\' + NULL */

	return (len);
}
