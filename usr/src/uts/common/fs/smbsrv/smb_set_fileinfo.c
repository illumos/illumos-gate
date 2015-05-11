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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Trans2 Set File/Path Information Levels:
 *
 * SMB_INFO_STANDARD
 * SMB_INFO_SET_EAS
 * SMB_SET_FILE_BASIC_INFO
 * SMB_SET_FILE_DISPOSITION_INFO
 * SMB_SET_FILE_END_OF_FILE_INFO
 * SMB_SET_FILE_ALLOCATION_INFO
 *
 * Handled Passthrough levels:
 * SMB_FILE_BASIC_INFORMATION
 * SMB_FILE_RENAME_INFORMATION
 * SMB_FILE_LINK_INFORMATION
 * SMB_FILE_DISPOSITION_INFORMATION
 * SMB_FILE_END_OF_FILE_INFORMATION
 * SMB_FILE_ALLOCATION_INFORMATION
 *
 * Internal levels representing non trans2 requests
 * SMB_SET_INFORMATION
 * SMB_SET_INFORMATION2
 */

/*
 * Setting timestamps:
 * The behaviour when the time field is set to -1 is not documented
 * but is generally treated like 0, meaning that that server file
 * system assigned value need not be changed.
 *
 * Setting attributes - FILE_ATTRIBUTE_NORMAL:
 * SMB_SET_INFORMATION -
 * - if the specified attributes have ONLY FILE_ATTRIBUTE_NORMAL set
 *   do NOT change the file's attributes.
 * SMB_SET_BASIC_INFO -
 * - if the specified attributes have ONLY FILE_ATTRIBUTE_NORMAL set
 *   clear (0) the file's attributes.
 * - if the specified attributes are 0 do NOT change the file's
 *   attributes.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

typedef struct smb_setinfo {
	uint16_t si_infolev;
	smb_xa_t *si_xa;
	smb_node_t *si_node;
} smb_setinfo_t;

/*
 * These functions all return 0 (success)  or -1 (error).
 * They set error details in the sr when appropriate.
 */
static int smb_set_by_fid(smb_request_t *, smb_xa_t *, uint16_t);
static int smb_set_by_path(smb_request_t *, smb_xa_t *, uint16_t);
static int smb_set_fileinfo(smb_request_t *, smb_setinfo_t *);
static int smb_set_information(smb_request_t *, smb_setinfo_t *);
static int smb_set_information2(smb_request_t *, smb_setinfo_t *);
static int smb_set_standard_info(smb_request_t *, smb_setinfo_t *);
static int smb_set_basic_info(smb_request_t *, smb_setinfo_t *);
static int smb_set_disposition_info(smb_request_t *, smb_setinfo_t *);
static int smb_set_eof_info(smb_request_t *sr, smb_setinfo_t *);
static int smb_set_alloc_info(smb_request_t *sr, smb_setinfo_t *);
static int smb_set_rename_info(smb_request_t *sr, smb_setinfo_t *);

/*
 * smb_com_trans2_set_file_information
 */
smb_sdrc_t
smb_com_trans2_set_file_information(smb_request_t *sr, smb_xa_t *xa)
{
	uint16_t infolev;

	if (smb_mbc_decodef(&xa->req_param_mb, "ww",
	    &sr->smb_fid, &infolev) != 0)
		return (SDRC_ERROR);

	if (smb_set_by_fid(sr, xa, infolev) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_com_trans2_set_path_information
 */
smb_sdrc_t
smb_com_trans2_set_path_information(smb_request_t *sr, smb_xa_t *xa)
{
	uint16_t	infolev;
	smb_fqi_t	*fqi = &sr->arg.dirop.fqi;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_INVALID_DEVICE_REQUEST,
		    ERRDOS, ERROR_INVALID_FUNCTION);
		return (SDRC_ERROR);
	}

	if (smb_mbc_decodef(&xa->req_param_mb, "%w4.u",
	    sr, &infolev, &fqi->fq_path.pn_path) != 0)
		return (SDRC_ERROR);

	if (smb_set_by_path(sr, xa, infolev) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_com_set_information (aka setattr)
 */
smb_sdrc_t
smb_pre_set_information(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SetInformation__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_set_information(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SetInformation__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_set_information(smb_request_t *sr)
{
	uint16_t	infolev = SMB_SET_INFORMATION;
	smb_fqi_t	*fqi = &sr->arg.dirop.fqi;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smbsr_decode_data(sr, "%S", sr, &fqi->fq_path.pn_path) != 0)
		return (SDRC_ERROR);

	if (smb_set_by_path(sr, NULL, infolev) != 0)
		return (SDRC_ERROR);

	if (smbsr_encode_empty_result(sr) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_com_set_information2 (aka setattre)
 */
smb_sdrc_t
smb_pre_set_information2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SetInformation2__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_set_information2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__SetInformation2__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_set_information2(smb_request_t *sr)
{
	uint16_t infolev = SMB_SET_INFORMATION2;

	if (smbsr_decode_vwv(sr, "w", &sr->smb_fid) != 0)
		return (SDRC_ERROR);

	if (smb_set_by_fid(sr, NULL, infolev) != 0)
		return (SDRC_ERROR);

	if (smbsr_encode_empty_result(sr) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * smb_set_by_fid
 *
 * Common code for setting file information by open file id.
 * Use the id to identify the node object and invoke smb_set_fileinfo
 * for that node.
 *
 * Setting attributes on a named pipe by id is handled by simply
 * returning success.
 */
static int
smb_set_by_fid(smb_request_t *sr, smb_xa_t *xa, uint16_t infolev)
{
	int rc;
	smb_setinfo_t sinfo;

	if (SMB_TREE_IS_READONLY(sr)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (-1);
	}

	if (STYPE_ISIPC(sr->tid_tree->t_res_type))
		return (0);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (-1);
	}

	if (!SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
		smbsr_release_file(sr);
		return (0);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	sinfo.si_xa = xa;
	sinfo.si_infolev = infolev;
	sinfo.si_node = sr->fid_ofile->f_node;
	rc = smb_set_fileinfo(sr, &sinfo);

	smbsr_release_file(sr);
	return (rc);
}

/*
 * smb_set_by_path
 *
 * Common code for setting file information by file name.
 * Use the file name to identify the node object and invoke
 * smb_set_fileinfo for that node.
 *
 * Path should be set in sr->arg.dirop.fqi.fq_path prior to
 * calling smb_set_by_path.
 *
 * Setting attributes on a named pipe by name is an error and
 * is handled in the calling functions so that they can return
 * the appropriate error status code (which differs by caller).
 */
static int
smb_set_by_path(smb_request_t *sr, smb_xa_t *xa, uint16_t infolev)
{
	int rc;
	smb_setinfo_t sinfo;
	smb_node_t *node, *dnode;
	char *name;
	smb_pathname_t	*pn;

	if (SMB_TREE_IS_READONLY(sr)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (-1);
	}

	pn = &sr->arg.dirop.fqi.fq_path;
	smb_pathname_init(sr, pn, pn->pn_path);
	if (!smb_pathname_validate(sr, pn))
		return (-1);

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	rc = smb_pathname_reduce(sr, sr->user_cr, pn->pn_path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dnode, name);
	if (rc == 0) {
		rc = smb_fsop_lookup_name(sr, sr->user_cr, SMB_FOLLOW_LINKS,
		    sr->tid_tree->t_snode, dnode, name, &node);
		smb_node_release(dnode);
	}
	kmem_free(name, MAXNAMELEN);

	if (rc != 0) {
		if (rc == ENOENT) {
			smbsr_error(sr, NT_STATUS_OBJECT_NAME_NOT_FOUND,
			    ERRDOS, ERROR_FILE_NOT_FOUND);
		} else {
			smbsr_errno(sr, rc);
		}
		return (-1);
	}

	sinfo.si_xa = xa;
	sinfo.si_infolev = infolev;
	sinfo.si_node = node;
	rc = smb_set_fileinfo(sr, &sinfo);

	smb_node_release(node);
	return (rc);
}

/*
 * smb_set_fileinfo
 *
 * For compatibility with windows servers, SMB_FILE_LINK_INFORMATION
 * is handled by returning NT_STATUS_NOT_SUPPORTED.
 */
static int
smb_set_fileinfo(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	switch (sinfo->si_infolev) {
	case SMB_SET_INFORMATION:
		return (smb_set_information(sr, sinfo));

	case SMB_SET_INFORMATION2:
		return (smb_set_information2(sr, sinfo));

	case SMB_INFO_STANDARD:
		return (smb_set_standard_info(sr, sinfo));

	case SMB_INFO_SET_EAS:
		/* EAs not supported */
		return (0);

	case SMB_SET_FILE_BASIC_INFO:
	case SMB_FILE_BASIC_INFORMATION:
		return (smb_set_basic_info(sr, sinfo));

	case SMB_SET_FILE_DISPOSITION_INFO:
	case SMB_FILE_DISPOSITION_INFORMATION:
		return (smb_set_disposition_info(sr, sinfo));

	case SMB_SET_FILE_END_OF_FILE_INFO:
	case SMB_FILE_END_OF_FILE_INFORMATION:
		return (smb_set_eof_info(sr, sinfo));

	case SMB_SET_FILE_ALLOCATION_INFO:
	case SMB_FILE_ALLOCATION_INFORMATION:
		return (smb_set_alloc_info(sr, sinfo));

	case SMB_FILE_RENAME_INFORMATION:
		return (smb_set_rename_info(sr, sinfo));

	case SMB_FILE_LINK_INFORMATION:
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
		    ERRDOS, ERROR_NOT_SUPPORTED);
		return (-1);
	default:
		break;
	}

	smbsr_error(sr, NT_STATUS_INVALID_INFO_CLASS,
	    ERRDOS, ERROR_INVALID_PARAMETER);
	return (-1);
}

/*
 * smb_set_information
 *
 * It is not valid to set FILE_ATTRIBUTE_DIRECTORY if the
 * target is not a directory.
 *
 * For compatibility with Windows Servers, if the specified
 * attributes have ONLY FILE_ATTRIBUTE_NORMAL set do NOT change
 * the file's attributes.
 */
static int
smb_set_information(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	int rc;
	uint16_t attributes;
	smb_node_t *node = sinfo->si_node;
	smb_attr_t attr;
	uint32_t mtime;

	if (smbsr_decode_vwv(sr, "wl10.", &attributes, &mtime) != 0)
		return (-1);

	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) &&
	    (!smb_node_is_dir(node))) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (-1);
	}

	bzero(&attr, sizeof (smb_attr_t));
	if (attributes != FILE_ATTRIBUTE_NORMAL) {
		attr.sa_dosattr = attributes;
		attr.sa_mask |= SMB_AT_DOSATTR;
	}

	if (mtime != 0 && mtime != UINT_MAX) {
		attr.sa_vattr.va_mtime.tv_sec =
		    smb_time_local_to_gmt(sr, mtime);
		attr.sa_mask |= SMB_AT_MTIME;
	}

	rc = smb_node_setattr(sr, node, sr->user_cr, NULL, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}

	return (0);
}

/*
 * smb_set_information2
 */
static int
smb_set_information2(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	int rc;
	uint32_t crtime, atime, mtime;
	smb_attr_t attr;

	if (smbsr_decode_vwv(sr, "yyy", &crtime, &atime, &mtime) != 0)
		return (-1);

	bzero(&attr, sizeof (smb_attr_t));
	if (mtime != 0 && mtime != UINT_MAX) {
		attr.sa_vattr.va_mtime.tv_sec =
		    smb_time_local_to_gmt(sr, mtime);
		attr.sa_mask |= SMB_AT_MTIME;
	}

	if (crtime != 0 && crtime != UINT_MAX) {
		attr.sa_crtime.tv_sec = smb_time_local_to_gmt(sr, crtime);
		attr.sa_mask |= SMB_AT_CRTIME;
	}

	if (atime != 0 && atime != UINT_MAX) {
		attr.sa_vattr.va_atime.tv_sec =
		    smb_time_local_to_gmt(sr, atime);
		attr.sa_mask |= SMB_AT_ATIME;
	}

	rc = smb_node_setattr(sr, sinfo->si_node, sr->user_cr,
	    sr->fid_ofile, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}

	return (0);
}

/*
 * smb_set_standard_info
 *
 * Sets standard file/path information.
 */
static int
smb_set_standard_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	smb_attr_t attr;
	uint32_t crtime, atime, mtime;
	smb_node_t *node = sinfo->si_node;
	int rc;

	if (smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "yyy",
	    &crtime, &atime, &mtime) != 0) {
		return (-1);
	}

	bzero(&attr, sizeof (smb_attr_t));
	if (mtime != 0 && mtime != (uint32_t)-1) {
		attr.sa_vattr.va_mtime.tv_sec =
		    smb_time_local_to_gmt(sr, mtime);
		attr.sa_mask |= SMB_AT_MTIME;
	}

	if (crtime != 0 && crtime != (uint32_t)-1) {
		attr.sa_crtime.tv_sec = smb_time_local_to_gmt(sr, crtime);
		attr.sa_mask |= SMB_AT_CRTIME;
	}

	if (atime != 0 && atime != (uint32_t)-1) {
		attr.sa_vattr.va_atime.tv_sec =
		    smb_time_local_to_gmt(sr, atime);
		attr.sa_mask |= SMB_AT_ATIME;
	}

	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}

	return (0);
}

/*
 * smb_set_basic_info
 *
 * Sets basic file/path information.
 *
 * It is not valid to set FILE_ATTRIBUTE_DIRECTORY if the
 * target is not a directory.
 *
 * For compatibility with windows servers:
 * - if the specified attributes have ONLY FILE_ATTRIBUTE_NORMAL set
 *   clear (0) the file's attributes.
 * - if the specified attributes are 0 do NOT change the file's attributes.
 */
static int
smb_set_basic_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	int rc;
	uint64_t crtime, atime, mtime, ctime;
	uint16_t attributes;
	smb_attr_t attr;
	smb_node_t *node = sinfo->si_node;

	if (smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "qqqqw",
	    &crtime, &atime, &mtime, &ctime, &attributes) != 0) {
		return (-1);
	}

	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) &&
	    (!smb_node_is_dir(node))) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (-1);
	}

	bzero(&attr, sizeof (smb_attr_t));
	if (ctime != 0 && ctime != (uint64_t)-1) {
		smb_time_nt_to_unix(ctime, &attr.sa_vattr.va_ctime);
		attr.sa_mask |= SMB_AT_CTIME;
	}

	if (crtime != 0 && crtime != (uint64_t)-1) {
		smb_time_nt_to_unix(crtime, &attr.sa_crtime);
		attr.sa_mask |= SMB_AT_CRTIME;
	}

	if (mtime != 0 && mtime != (uint64_t)-1) {
		smb_time_nt_to_unix(mtime, &attr.sa_vattr.va_mtime);
		attr.sa_mask |= SMB_AT_MTIME;
	}

	if (atime != 0 && atime != (uint64_t)-1) {
		smb_time_nt_to_unix(atime, &attr.sa_vattr.va_atime);
		attr.sa_mask |= SMB_AT_ATIME;
	}

	if (attributes != 0) {
		attr.sa_dosattr = attributes;
		attr.sa_mask |= SMB_AT_DOSATTR;
	}

	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}

	return (0);
}

/*
 * smb_set_eof_info
 */
static int
smb_set_eof_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	int rc;
	smb_attr_t attr;
	uint64_t eof;
	smb_node_t *node = sinfo->si_node;

	if (smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "q", &eof) != 0)
		return (-1);

	if (smb_node_is_dir(node)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (-1);
	}

	/* If opened by path, break exclusive oplock */
	if (sr->fid_ofile == NULL)
		(void) smb_oplock_break(sr, node,
		    SMB_OPLOCK_BREAK_EXCLUSIVE | SMB_OPLOCK_BREAK_TO_NONE);

	bzero(&attr, sizeof (smb_attr_t));
	attr.sa_mask = SMB_AT_SIZE;
	attr.sa_vattr.va_size = (u_offset_t)eof;
	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}

	smb_oplock_break_levelII(node);
	return (0);
}

/*
 * smb_set_alloc_info
 */
static int
smb_set_alloc_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	int rc;
	smb_attr_t attr;
	uint64_t allocsz;
	smb_node_t *node = sinfo->si_node;

	if (smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "q", &allocsz) != 0)
		return (-1);

	if (smb_node_is_dir(node)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (-1);
	}

	/* If opened by path, break exclusive oplock */
	if (sr->fid_ofile == NULL)
		(void) smb_oplock_break(sr, node,
		    SMB_OPLOCK_BREAK_EXCLUSIVE | SMB_OPLOCK_BREAK_TO_NONE);

	bzero(&attr, sizeof (smb_attr_t));
	attr.sa_mask = SMB_AT_ALLOCSZ;
	attr.sa_allocsz = (u_offset_t)allocsz;
	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (-1);
	}

	smb_oplock_break_levelII(node);
	return (0);
}

/*
 * smb_set_disposition_info
 *
 * Set/Clear DELETE_ON_CLOSE flag for an open file.
 * File should have been opened with DELETE access otherwise
 * the operation is not permitted.
 *
 * NOTE: The node should be marked delete-on-close upon the receipt
 * of the Trans2SetFileInfo(SetDispositionInfo) if mark_delete is set.
 * It is different than both SmbNtCreateAndX and SmbNtTransact, which
 * set delete-on-close on the ofile and defer setting the flag on the
 * node until the file is closed.
 *
 * Observation of Windows 2000 indicates the following:
 *
 * 1) If a file is not opened with delete-on-close create options and
 * the delete-on-close is set via Trans2SetFileInfo(SetDispositionInfo)
 * using that open file handle, any subsequent open requests will fail
 * with DELETE_PENDING.
 *
 * 2) If a file is opened with delete-on-close create options and the
 * client attempts to unset delete-on-close via Trans2SetFileInfo
 * (SetDispositionInfo) prior to the file close, any subsequent open
 * requests will still fail with DELETE_PENDING after the file is closed.
 *
 * 3) If a file is opened with delete-on-close create options and that
 * file handle (not the last open handle and the only file handle
 * with delete-on-close set) is closed. Any subsequent open requests
 * will fail with DELETE_PENDING. Unsetting delete-on-close via
 * Trans2SetFileInfo(SetDispositionInfo) at this time will unset the
 * node delete-on-close flag, which will result in the file not being
 * removed even after the last file handle is closed.
 */
static int
smb_set_disposition_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	unsigned char	mark_delete;
	uint32_t	flags = 0;
	int		doserr;
	uint32_t	status;

	if (smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "b", &mark_delete) != 0)
		return (-1);

	if ((sr->fid_ofile == NULL) ||
	    !(smb_ofile_granted_access(sr->fid_ofile) & DELETE)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (-1);
	}

	if (mark_delete) {
		if (SMB_TREE_SUPPORTS_CATIA(sr))
			flags |= SMB_CATIA;

		status = smb_node_set_delete_on_close(sinfo->si_node,
		    sr->user_cr, flags);
		if (status != NT_STATUS_SUCCESS) {
			switch (status) {
			case NT_STATUS_CANNOT_DELETE:
				doserr = ERROR_ACCESS_DENIED;
				break;
			case NT_STATUS_DIRECTORY_NOT_EMPTY:
				doserr = ERROR_DIR_NOT_EMPTY;
				break;
			default:
				doserr = ERROR_GEN_FAILURE;
				break;
			}
			smbsr_error(sr, status, ERRDOS, doserr);
			return (-1);
		}
	} else {
		smb_node_reset_delete_on_close(sinfo->si_node);
	}
	return (0);
}

/*
 * smb_set_rename_info
 *
 * Explicitly specified parameter validation rules:
 * - If rootdir is not NULL respond with NT_STATUS_INVALID_PARAMETER.
 * - If the filename contains a separator character respond with
 *   NT_STATUS_INVALID_PARAMETER.
 *
 * Oplock break:
 * Some Windows servers break BATCH oplocks prior to the rename.
 * W2K3 does not. We behave as W2K3; we do not send an oplock break.
 */
static int
smb_set_rename_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	int rc;
	uint32_t flags, rootdir, namelen;
	char *fname;

	rc = smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "lll",
	    &flags, &rootdir, &namelen);
	if (rc == 0) {
		rc = smb_mbc_decodef(&sinfo->si_xa->req_data_mb, "%#U",
		    sr, namelen, &fname);
	}
	if (rc != 0)
		return (-1);

	if ((rootdir != 0) || (namelen == 0) || (namelen >= MAXNAMELEN)) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER,
		    ERRDOS, ERROR_INVALID_PARAMETER);
		return (-1);
	}

	if (strchr(fname, '\\') != NULL) {
		smbsr_error(sr, NT_STATUS_NOT_SUPPORTED,
		    ERRDOS, ERROR_NOT_SUPPORTED);
		return (-1);
	}

	rc = smb_trans2_rename(sr, sinfo->si_node, fname, flags);

	return ((rc == 0) ? 0 : -1);
}
