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

/*
 * This file contains the common code used by
 * Trans2SetFileInfo and Trans2SetPathInfo SMBs.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

static uint32_t smb_set_standard_info(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

static uint32_t smb_set_basic_info(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

static uint32_t smb_set_disposition_info(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

static uint32_t smb_set_alloc_info(smb_request_t *sr,
    smb_trans2_setinfo_t *, smb_error_t *);

/*LINTED E_STATIC_UNUSED*/
static uint32_t smb_set_mac_info(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

/*LINTED E_STATIC_UNUSED*/
static uint32_t smb_set_mac_addappl(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

/*LINTED E_STATIC_UNUSED*/
static uint32_t smb_set_mac_rmvappl(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

/*LINTED E_STATIC_UNUSED*/
static uint32_t smb_set_mac_addicon(smb_request_t *,
    smb_trans2_setinfo_t *, smb_error_t *);

static unsigned short smb_info_passthru(unsigned short infolevel);

/*
 * smb_trans2_set_information
 *
 * This is a common function called by both Trans2SetFileInfo
 * and Trans2SetPathInfo.
 */
uint32_t
smb_trans2_set_information(smb_request_t *sr, smb_trans2_setinfo_t *info,
    smb_error_t *smberr)
{
	info->level = smb_info_passthru(info->level);

	switch (info->level) {
	case SMB_INFO_STANDARD:
		return (smb_set_standard_info(sr, info, smberr));

	case SMB_INFO_SET_EAS:
		/* EAs not supported */
		return (NT_STATUS_SUCCESS);

	case SMB_SET_FILE_BASIC_INFO:
		return (smb_set_basic_info(sr, info, smberr));

	case SMB_SET_FILE_DISPOSITION_INFO:
		return (smb_set_disposition_info(sr, info, smberr));

	case SMB_SET_FILE_END_OF_FILE_INFO:
	case SMB_SET_FILE_ALLOCATION_INFO:
		return (smb_set_alloc_info(sr, info, smberr));

	default:
		break;
	}

	smberr->status = NT_STATUS_INVALID_INFO_CLASS;
	smberr->errcls = ERRDOS;
	smberr->errcode = ERROR_INVALID_PARAMETER;
	return (NT_STATUS_UNSUCCESSFUL);
}

/*
 * smb_info_passthru
 *
 * SMB_INFO_PASSTHROUGH
 * If the server supports information level request passing through,
 * the client may add the information level with SMB_INFO_PASSTHROUGH
 * and submit the file information in NT data format instead of SMB
 * data format. Please refer to MSDN for related NT file information
 * data structure.
 *
 * SMB_INFO_PASSTHROUGH (1000) is defined in win32/cifs.h and the file
 * information class values are defined in win32/ntifs.h. we have
 * observed:
 * 0x3EC = SMB_INFO_PASSTHROUGH + FileBasicInformation (4)
 * 0x3F5 = SMB_INFO_PASSTHROUGH + FileDispositionInformation (13)
 * 0x3FC = SMB_INFO_PASSTHROUGH + FileEndOfFileInformation (20)
 *
 * Based on network traces between two Win2K systems:
 *	FileBasicInformation <=> SMB_SET_FILE_BASIC_INFO
 *  FileDispositionInformation <=> SMB_SET_FILE_DISPOSITION_INFO
 *	FileEndOfFileInformation <=> SMB_SET_FILE_END_OF_FILE_INFO
 */
static unsigned short
smb_info_passthru(unsigned short infolevel)
{
	if (infolevel <= SMB_INFO_PASSTHROUGH)
		return (infolevel);

	infolevel -= SMB_INFO_PASSTHROUGH;

	switch (infolevel) {
	case FileBasicInformation:
		return (SMB_SET_FILE_BASIC_INFO);

	case FileDispositionInformation:
		return (SMB_SET_FILE_DISPOSITION_INFO);

	case FileEndOfFileInformation:
		return (SMB_SET_FILE_END_OF_FILE_INFO);

	case FileAllocationInformation:
		return (SMB_SET_FILE_ALLOCATION_INFO);
	}

	return (infolevel);
}

/*
 * smb_set_standard_info
 *
 * Sets standard file/path information.
 */
static uint32_t
smb_set_standard_info(smb_request_t *sr, smb_trans2_setinfo_t *info,
    smb_error_t *smberr)
{
	smb_attr_t attr;
	uint32_t Creation, LastAccess, LastWrite;  /* times */
	uint32_t status = NT_STATUS_SUCCESS;
	smb_node_t *node = info->node;
	int rc;

	if (smb_mbc_decodef(&info->ts_xa->req_data_mb, "yyy",
	    &Creation,		/* CreationDate/Time */
	    &LastAccess,	/* LastAccessDate/Time */
	    &LastWrite) != 0) {	/* LastWriteDate/Time */
		return (NT_STATUS_DATA_ERROR);
	}

	bzero(&attr, sizeof (smb_attr_t));

	/*
	 * The behaviour when the time field is set to -1
	 * is not documented but is generally treated like 0,
	 * meaning that that server file system assigned value
	 * need not be changed.
	 */
	if (LastWrite != 0 && LastWrite != (uint32_t)-1) {
		attr.sa_vattr.va_mtime.tv_sec = smb_local2gmt(sr, LastWrite);
		attr.sa_mask |= SMB_AT_MTIME;
	}

	if (Creation != 0 && Creation != (uint32_t)-1) {
		attr.sa_crtime.tv_sec = smb_local2gmt(sr, Creation);
		attr.sa_mask |= SMB_AT_CRTIME;
	}

	if (LastAccess != 0 && LastAccess != (uint32_t)-1) {
		attr.sa_vattr.va_atime.tv_sec = smb_local2gmt(sr, LastAccess);
		attr.sa_mask |= SMB_AT_ATIME;
	}

	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc) {
		smbsr_map_errno(rc, smberr);
		status = NT_STATUS_UNSUCCESSFUL;
	}

	return (status);
}

/*
 * smb_set_basic_info
 *
 * Sets basic file/path information.
 */
static uint32_t
smb_set_basic_info(smb_request_t *sr, smb_trans2_setinfo_t *info,
    smb_error_t *smberr)
{
	smb_attr_t attr;
	uint64_t NT_Creation, NT_LastAccess, NT_LastWrite, NT_Change;
	unsigned short Attributes;
	smb_node_t *node = info->node;
	uint32_t status = NT_STATUS_SUCCESS;
	int rc;

	if (smb_mbc_decodef(&info->ts_xa->req_data_mb, "qqqqw",
	    &NT_Creation,		/* CreationDate/Time */
	    &NT_LastAccess,		/* LastAccessDate/Time */
	    &NT_LastWrite,		/* LastWriteDate/Time */
	    &NT_Change,			/* LastWriteDate/Time */
	    &Attributes) != 0) {	/* File Attributes */
		return (NT_STATUS_DATA_ERROR);
	}

	bzero(&attr, sizeof (smb_attr_t));

	/*
	 * The behaviour when the time field is set to -1
	 * is not documented but is generally treated like 0,
	 * meaning that that server file system assigned value
	 * need not be changed.
	 */
	if (NT_Change != 0 && NT_Change != (uint64_t)-1) {
		(void) nt_to_unix_time(NT_Change, &attr.sa_vattr.va_ctime);
		attr.sa_mask |= SMB_AT_CTIME;
	}

	if (NT_Creation != 0 && NT_Creation != (uint64_t)-1) {
		(void) nt_to_unix_time(NT_Creation, &attr.sa_crtime);
		attr.sa_mask |= SMB_AT_CRTIME;
	}

	if (NT_LastWrite != 0 && NT_LastWrite != (uint64_t)-1) {
		(void) nt_to_unix_time(NT_LastWrite, &attr.sa_vattr.va_mtime);
		attr.sa_mask |= SMB_AT_MTIME;
	}

	if (NT_LastAccess != 0 && NT_LastAccess != (uint64_t)-1) {
		(void) nt_to_unix_time(NT_LastAccess, &attr.sa_vattr.va_atime);
		attr.sa_mask |= SMB_AT_ATIME;
	}

	/*
	 * If Attributes are 0 this means that the file's attributes
	 * should be left unchanged. If the client wanted to 0 (clear)
	 * all of the attributes Attributes would be FILE_ATTRIBUTE_NORMAL.
	 * Note - this is different from SMBsetatr (SMBSetInformation).
	 *
	 * It is not valid to set FILE_ATTRIBUTE_DIRECTORY if the
	 * target is not a directory.
	 */
	if (Attributes != 0) {
		if ((Attributes & FILE_ATTRIBUTE_DIRECTORY) &&
		    (!smb_node_is_dir(node))) {
			smberr->status = NT_STATUS_INVALID_PARAMETER;
			smberr->errcls = ERRDOS;
			smberr->errcode = ERROR_INVALID_PARAMETER;
			return (NT_STATUS_UNSUCCESSFUL);
		}

		attr.sa_dosattr = Attributes;
		attr.sa_mask |= SMB_AT_DOSATTR;
	}

	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc) {
		smbsr_map_errno(rc, smberr);
		status = NT_STATUS_UNSUCCESSFUL;
	}

	return (status);
}


/*
 * smb_set_alloc_info
 *
 * Sets file allocation/end_of_file info
 */
static uint32_t
smb_set_alloc_info(smb_request_t *sr, smb_trans2_setinfo_t *info,
    smb_error_t *smberr)
{
	smb_attr_t attr;
	uint64_t DataSize;
	uint32_t status = NT_STATUS_SUCCESS;
	smb_node_t *node = info->node;
	int rc;

	if (smb_mbc_decodef(&info->ts_xa->req_data_mb, "q", &DataSize) != 0)
		return (NT_STATUS_DATA_ERROR);

	bzero(&attr, sizeof (smb_attr_t));
	attr.sa_mask = SMB_AT_SIZE;
	attr.sa_vattr.va_size = (u_offset_t)DataSize;
	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, &attr);
	if (rc) {
		smbsr_map_errno(rc, smberr);
		status = NT_STATUS_UNSUCCESSFUL;
	}

	return (status);
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
static uint32_t
smb_set_disposition_info(smb_request_t *sr, smb_trans2_setinfo_t *info,
    smb_error_t *smberr)
{
	unsigned char	mark_delete;
	uint32_t	flags = 0;

	if (smb_mbc_decodef(&info->ts_xa->req_data_mb, "b", &mark_delete) != 0)
		return (NT_STATUS_DATA_ERROR);

	if ((sr->fid_ofile == NULL) ||
	    !(smb_ofile_granted_access(sr->fid_ofile) & DELETE)) {
		smberr->status = NT_STATUS_ACCESS_DENIED;
		smberr->errcls = ERRDOS;
		smberr->errcode = ERROR_ACCESS_DENIED;
		return (NT_STATUS_UNSUCCESSFUL);
	}

	if (mark_delete) {
		if (SMB_TREE_SUPPORTS_CATIA(sr))
			flags |= SMB_CATIA;

		if (smb_node_set_delete_on_close(info->node,
		    sr->user_cr, flags)) {
			smberr->status = NT_STATUS_CANNOT_DELETE;
			smberr->errcls = ERRDOS;
			smberr->errcode = ERROR_ACCESS_DENIED;
			return (NT_STATUS_UNSUCCESSFUL);
		}
	} else {
		smb_node_reset_delete_on_close(info->node);
	}
	return (NT_STATUS_SUCCESS);
}
