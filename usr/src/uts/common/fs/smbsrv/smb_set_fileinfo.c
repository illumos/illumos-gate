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

static int smb_set_by_fid(smb_request_t *, smb_xa_t *, uint16_t);
static int smb_set_by_path(smb_request_t *, smb_xa_t *, uint16_t);

/*
 * These functions all return and NT status code.
 */
static uint32_t smb_set_fileinfo(smb_request_t *, smb_setinfo_t *, int);
static uint32_t smb_set_information(smb_request_t *, smb_setinfo_t *);
static uint32_t smb_set_information2(smb_request_t *, smb_setinfo_t *);
static uint32_t smb_set_standard_info(smb_request_t *, smb_setinfo_t *);
static uint32_t smb_set_rename_info(smb_request_t *sr, smb_setinfo_t *);

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
	smb_setinfo_t sinfo;
	uint32_t status;
	int rc = 0;

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

	bzero(&sinfo, sizeof (sinfo));
	sinfo.si_node = sr->fid_ofile->f_node;
	if (xa != NULL)
		sinfo.si_data = xa->req_data_mb;
	status = smb_set_fileinfo(sr, &sinfo, infolev);
	if (status != 0) {
		smbsr_error(sr, status, 0, 0);
		rc = -1;
	}

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
	uint32_t status;
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

	bzero(&sinfo, sizeof (sinfo));
	sinfo.si_node = node;
	if (xa != NULL)
		sinfo.si_data = xa->req_data_mb;
	status = smb_set_fileinfo(sr, &sinfo, infolev);
	if (status != 0) {
		smbsr_error(sr, status, 0, 0);
		rc = -1;
	}

	smb_node_release(node);
	return (rc);
}

/*
 * smb_set_fileinfo
 *
 * For compatibility with windows servers, SMB_FILE_LINK_INFORMATION
 * is handled by returning NT_STATUS_NOT_SUPPORTED.
 */
static uint32_t
smb_set_fileinfo(smb_request_t *sr, smb_setinfo_t *sinfo, int infolev)
{
	uint32_t status;

	switch (infolev) {
	case SMB_SET_INFORMATION:
		status = smb_set_information(sr, sinfo);
		break;

	case SMB_SET_INFORMATION2:
		status = smb_set_information2(sr, sinfo);
		break;

	case SMB_INFO_STANDARD:
		status = smb_set_standard_info(sr, sinfo);
		break;

	case SMB_INFO_SET_EAS:
		/* EAs not supported */
		status = 0;
		break;

	case SMB_SET_FILE_BASIC_INFO:
	case SMB_FILE_BASIC_INFORMATION:
		status = smb_set_basic_info(sr, sinfo);
		break;

	case SMB_SET_FILE_DISPOSITION_INFO:
	case SMB_FILE_DISPOSITION_INFORMATION:
		status = smb_set_disposition_info(sr, sinfo);
		break;

	case SMB_SET_FILE_END_OF_FILE_INFO:
	case SMB_FILE_END_OF_FILE_INFORMATION:
		status = smb_set_eof_info(sr, sinfo);
		break;

	case SMB_SET_FILE_ALLOCATION_INFO:
	case SMB_FILE_ALLOCATION_INFORMATION:
		status = smb_set_alloc_info(sr, sinfo);
		break;

	case SMB_FILE_RENAME_INFORMATION:
		status = smb_set_rename_info(sr, sinfo);
		break;

	case SMB_FILE_LINK_INFORMATION:
		status = NT_STATUS_NOT_SUPPORTED;
		break;

	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	return (status);
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
static uint32_t
smb_set_information(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	smb_attr_t attr;
	smb_node_t *node = sinfo->si_node;
	uint32_t status = 0;
	uint32_t mtime;
	uint16_t attributes;
	int rc;

	if (smbsr_decode_vwv(sr, "wl10.", &attributes, &mtime) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) &&
	    (!smb_node_is_dir(node))) {
		return (NT_STATUS_INVALID_PARAMETER);
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
	if (rc != 0)
		status = smb_errno2status(rc);

	return (status);
}

/*
 * smb_set_information2
 */
static uint32_t
smb_set_information2(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	smb_attr_t attr;
	uint32_t crtime, atime, mtime;
	uint32_t status = 0;
	int rc;

	if (smbsr_decode_vwv(sr, "yyy", &crtime, &atime, &mtime) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

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
	if (rc != 0)
		status = smb_errno2status(rc);

	return (status);
}

/*
 * smb_set_standard_info
 *
 * Sets standard file/path information.
 */
static uint32_t
smb_set_standard_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	smb_attr_t attr;
	smb_node_t *node = sinfo->si_node;
	uint32_t crtime, atime, mtime;
	uint32_t status = 0;
	int rc;

	if (smb_mbc_decodef(&sinfo->si_data, "yyy",
	    &crtime, &atime, &mtime) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

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
	if (rc != 0)
		status = smb_errno2status(rc);

	return (status);
}

/*
 * smb_set_rename_info
 *
 * This call only allows a rename in the same directory, and the
 * directory name is not part of the new name provided.
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
static uint32_t
smb_set_rename_info(smb_request_t *sr, smb_setinfo_t *sinfo)
{
	smb_fqi_t *src_fqi = &sr->arg.dirop.fqi;
	smb_fqi_t *dst_fqi = &sr->arg.dirop.dst_fqi;
	char *fname;
	char *path;
	uint8_t flags;
	uint32_t rootdir, namelen;
	uint32_t status = 0;
	int rc;

	rc = smb_mbc_decodef(&sinfo->si_data, "b...ll",
	    &flags, &rootdir, &namelen);
	if (rc == 0) {
		rc = smb_mbc_decodef(&sinfo->si_data, "%#U",
		    sr, namelen, &fname);
	}
	if (rc != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if ((rootdir != 0) || (namelen == 0) || (namelen >= MAXNAMELEN)) {
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (strchr(fname, '\\') != NULL) {
		return (NT_STATUS_NOT_SUPPORTED);
	}

	/*
	 * Construct the full dst. path relative to the share root.
	 * Allocated path is free'd in smb_request_free.
	 */
	path = smb_srm_zalloc(sr, SMB_MAXPATHLEN);
	if (src_fqi->fq_path.pn_pname) {
		/* Got here via: smb_set_by_path */
		(void) snprintf(path, SMB_MAXPATHLEN, "%s\\%s",
		    src_fqi->fq_path.pn_pname, fname);
	} else {
		/* Got here via: smb_set_by_fid */
		rc = smb_node_getshrpath(sinfo->si_node->n_dnode,
		    sr->tid_tree, path, SMB_MAXPATHLEN);
		if (rc != 0) {
			status = smb_errno2status(rc);
			return (status);
		}
		(void) strlcat(path, "\\", SMB_MAXPATHLEN);
		(void) strlcat(path, fname, SMB_MAXPATHLEN);
	}

	/*
	 * The common rename code can slightly optimize a
	 * rename in the same directory when we set the
	 * dst_fqi->fq_dnode, dst_fqi->fq_last_comp
	 */
	dst_fqi->fq_dnode = sinfo->si_node->n_dnode;
	(void) strlcpy(dst_fqi->fq_last_comp, fname, MAXNAMELEN);

	status = smb_setinfo_rename(sr, sinfo->si_node, path, flags);
	return (status);
}
