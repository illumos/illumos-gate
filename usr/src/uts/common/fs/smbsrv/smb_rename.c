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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/synch.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/nbmlock.h>

/*
 * NT_RENAME InformationLevels:
 *
 * SMB_NT_RENAME_MOVE_CLUSTER_INFO	Server returns invalid parameter.
 * SMB_NT_RENAME_SET_LINK_INFO		Create a hard link to a file.
 * SMB_NT_RENAME_RENAME_FILE		In-place rename of a file.
 * SMB_NT_RENAME_MOVE_FILE		Move (rename) a file.
 */
#define	SMB_NT_RENAME_MOVE_CLUSTER_INFO	0x0102
#define	SMB_NT_RENAME_SET_LINK_INFO	0x0103
#define	SMB_NT_RENAME_RENAME_FILE	0x0104
#define	SMB_NT_RENAME_MOVE_FILE		0x0105

/*
 * smb_com_rename
 *
 * Rename a file. Files OldFileName must exist and NewFileName must not.
 * Both pathnames must be relative to the Tid specified in the request.
 * Open files may be renamed.
 *
 * Multiple files may be renamed in response to a single request as Rename
 * File supports wildcards in the file name (last component of the path).
 * NOTE: we don't support rename with wildcards.
 *
 * SearchAttributes indicates the attributes that the target file(s) must
 * have. If SearchAttributes is zero then only normal files are renamed.
 * If the system file or hidden attributes are specified then the rename
 * is inclusive - both the specified type(s) of files and normal files are
 * renamed.
 */
smb_sdrc_t
smb_pre_rename(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	int rc;

	if ((rc = smbsr_decode_vwv(sr, "w", &src_fqi->fq_sattr)) == 0) {
		rc = smbsr_decode_data(sr, "%SS", sr, &src_fqi->fq_path.pn_path,
		    &dst_fqi->fq_path.pn_path);

		dst_fqi->fq_sattr = 0;
	}

	DTRACE_SMB_2(op__Rename__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_rename(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Rename__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_rename(smb_request_t *sr)
{
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*src_pn = &src_fqi->fq_path;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;
	uint32_t	status;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_pathname_init(sr, src_pn, src_pn->pn_path);
	smb_pathname_init(sr, dst_pn, dst_pn->pn_path);
	if (!smb_pathname_validate(sr, src_pn) ||
	    !smb_pathname_validate(sr, dst_pn)) {
		return (SDRC_ERROR);
	}

	status = smb_common_rename(sr, src_fqi, dst_fqi);
	if (status != 0) {
		smbsr_error(sr, status, 0, 0);
		return (SDRC_ERROR);
	}

	(void) smbsr_encode_empty_result(sr);
	return (SDRC_SUCCESS);
}

/*
 * smb_com_nt_rename
 *
 * Rename a file. Files OldFileName must exist and NewFileName must not.
 * Both pathnames must be relative to the Tid specified in the request.
 * Open files may be renamed.
 *
 * SearchAttributes indicates the attributes that the target file(s) must
 * have. If SearchAttributes is zero then only normal files are renamed.
 * If the system file or hidden attributes are specified then the rename
 * is inclusive - both the specified type(s) of files and normal files are
 * renamed.
 */
smb_sdrc_t
smb_pre_nt_rename(smb_request_t *sr)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	uint32_t clusters;
	int rc;

	rc = smbsr_decode_vwv(sr, "wwl", &src_fqi->fq_sattr,
	    &sr->arg.dirop.info_level, &clusters);
	if (rc == 0) {
		rc = smbsr_decode_data(sr, "%SS", sr,
		    &src_fqi->fq_path.pn_path, &dst_fqi->fq_path.pn_path);

		dst_fqi->fq_sattr = 0;
	}

	DTRACE_SMB_2(op__NtRename__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_nt_rename(smb_request_t *sr)
{
	DTRACE_SMB_1(op__NtRename__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_nt_rename(smb_request_t *sr)
{
	smb_fqi_t	*src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t	*dst_fqi = &sr->arg.dirop.dst_fqi;
	smb_pathname_t	*src_pn = &src_fqi->fq_path;
	smb_pathname_t	*dst_pn = &dst_fqi->fq_path;
	uint32_t	status;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_pathname_init(sr, src_pn, src_pn->pn_path);
	smb_pathname_init(sr, dst_pn, dst_pn->pn_path);
	if (!smb_pathname_validate(sr, src_pn) ||
	    !smb_pathname_validate(sr, dst_pn)) {
		return (SDRC_ERROR);
	}

	if (smb_contains_wildcards(src_pn->pn_path)) {
		smbsr_error(sr, NT_STATUS_OBJECT_PATH_SYNTAX_BAD,
		    ERRDOS, ERROR_BAD_PATHNAME);
		return (SDRC_ERROR);
	}

	switch (sr->arg.dirop.info_level) {
	case SMB_NT_RENAME_SET_LINK_INFO:
		status = smb_make_link(sr, src_fqi, dst_fqi);
		break;
	case SMB_NT_RENAME_RENAME_FILE:
	case SMB_NT_RENAME_MOVE_FILE:
		status = smb_common_rename(sr, src_fqi, dst_fqi);
		break;
	case SMB_NT_RENAME_MOVE_CLUSTER_INFO:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	default:
		status = NT_STATUS_ACCESS_DENIED;
		break;
	}

	if (status != 0) {
		smbsr_error(sr, status, 0, 0);
		return (SDRC_ERROR);
	}

	(void) smbsr_encode_empty_result(sr);
	return (SDRC_SUCCESS);
}

/*
 * smb_nt_transact_rename
 *
 * Windows servers return SUCCESS without renaming file.
 * The only check required is to check that the handle (fid) is valid.
 */
smb_sdrc_t
smb_nt_transact_rename(smb_request_t *sr, smb_xa_t *xa)
{
	if (smb_mbc_decodef(&xa->req_param_mb, "w", &sr->smb_fid) != 0)
		return (SDRC_ERROR);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}
	smbsr_release_file(sr);

	return (SDRC_SUCCESS);
}
