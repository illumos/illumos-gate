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
 * Common functions supporting both:
 * SMB1 Trans2 Set File/Path Info,
 * SMB2 Set File Info
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>

/*
 * smb_set_basic_info
 * [MS-FSCC] 2.4.7
 *	FileBasicInformation
 *	SMB_SET_FILE_BASIC_INFO
 *	SMB_FILE_BASIC_INFORMATION
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
uint32_t
smb_set_basic_info(smb_request_t *sr, smb_setinfo_t *si)
{
	smb_attr_t *attr = &si->si_attr;
	smb_node_t *node = si->si_node;
	uint64_t crtime, atime, mtime, ctime;
	uint32_t attributes;
	int rc;

	if (smb_mbc_decodef(&si->si_data, "qqqql",
	    &crtime, &atime, &mtime, &ctime, &attributes) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if ((attributes & FILE_ATTRIBUTE_DIRECTORY) &&
	    (!smb_node_is_dir(node)))
		return (NT_STATUS_INVALID_PARAMETER);

	bzero(attr, sizeof (*attr));
	if (atime != 0 && atime != (uint64_t)-1) {
		smb_time_nt_to_unix(atime, &attr->sa_vattr.va_atime);
		attr->sa_mask |= SMB_AT_ATIME;
	}
	if (mtime != 0 && mtime != (uint64_t)-1) {
		smb_time_nt_to_unix(mtime, &attr->sa_vattr.va_mtime);
		attr->sa_mask |= SMB_AT_MTIME;
	}
	if (ctime != 0 && ctime != (uint64_t)-1) {
		smb_time_nt_to_unix(ctime, &attr->sa_vattr.va_ctime);
		attr->sa_mask |= SMB_AT_CTIME;
	}
	if (crtime != 0 && crtime != (uint64_t)-1) {
		smb_time_nt_to_unix(crtime, &attr->sa_crtime);
		attr->sa_mask |= SMB_AT_CRTIME;
	}

	if (attributes != 0) {
		attr->sa_dosattr = attributes;
		attr->sa_mask |= SMB_AT_DOSATTR;
	}

	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, attr);
	if (rc != 0)
		return (smb_errno2status(rc));

	return (0);
}

/*
 * smb_set_eof_info
 *	FileEndOfFileInformation
 *	SMB_SET_FILE_END_OF_FILE_INFO
 *	SMB_FILE_END_OF_FILE_INFORMATION
 */
uint32_t
smb_set_eof_info(smb_request_t *sr, smb_setinfo_t *si)
{
	smb_attr_t *attr = &si->si_attr;
	smb_node_t *node = si->si_node;
	uint64_t eof;
	int rc;

	if (smb_mbc_decodef(&si->si_data, "q", &eof) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if (smb_node_is_dir(node))
		return (NT_STATUS_INVALID_PARAMETER);

	/* If opened by path, break exclusive oplock */
	if (sr->fid_ofile == NULL)
		(void) smb_oplock_break(sr, node,
		    SMB_OPLOCK_BREAK_EXCLUSIVE | SMB_OPLOCK_BREAK_TO_NONE);

	bzero(attr, sizeof (*attr));
	attr->sa_mask = SMB_AT_SIZE;
	attr->sa_vattr.va_size = (u_offset_t)eof;
	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, attr);
	if (rc != 0)
		return (smb_errno2status(rc));

	smb_oplock_break_levelII(node);
	return (0);
}

/*
 * smb_set_alloc_info
 *	FileAllocationInformation
 *	SMB_SET_FILE_ALLOCATION_INFO
 *	SMB_FILE_ALLOCATION_INFORMATION
 */
uint32_t
smb_set_alloc_info(smb_request_t *sr, smb_setinfo_t *si)
{
	smb_attr_t *attr = &si->si_attr;
	smb_node_t *node = si->si_node;
	uint64_t allocsz;
	int rc;

	if (smb_mbc_decodef(&si->si_data, "q", &allocsz) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if (smb_node_is_dir(node))
		return (NT_STATUS_INVALID_PARAMETER);

	/* If opened by path, break exclusive oplock */
	if (sr->fid_ofile == NULL)
		(void) smb_oplock_break(sr, node,
		    SMB_OPLOCK_BREAK_EXCLUSIVE | SMB_OPLOCK_BREAK_TO_NONE);

	bzero(attr, sizeof (*attr));
	attr->sa_mask = SMB_AT_ALLOCSZ;
	attr->sa_allocsz = (u_offset_t)allocsz;
	rc = smb_node_setattr(sr, node, sr->user_cr, sr->fid_ofile, attr);
	if (rc != 0)
		return (smb_errno2status(rc));

	smb_oplock_break_levelII(node);
	return (0);
}

/*
 * smb_set_disposition_info
 * See:
 *	FileDispositionInformation
 *	SMB_SET_FILE_DISPOSITION_INFO
 *	SMB_FILE_DISPOSITION_INFORMATION
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
uint32_t
smb_set_disposition_info(smb_request_t *sr, smb_setinfo_t *si)
{
	smb_node_t *node = si->si_node;
	smb_ofile_t *of = sr->fid_ofile;
	uint8_t		mark_delete;
	uint32_t	flags = 0;

	if (smb_mbc_decodef(&si->si_data, "b", &mark_delete) != 0)
		return (NT_STATUS_INFO_LENGTH_MISMATCH);

	if ((of == NULL) || !(smb_ofile_granted_access(of) & DELETE))
		return (NT_STATUS_ACCESS_DENIED);

	if (mark_delete) {
		if (SMB_TREE_SUPPORTS_CATIA(sr))
			flags |= SMB_CATIA;
		return (smb_node_set_delete_on_close(node, of->f_cr, flags));
	} else {
		smb_node_reset_delete_on_close(node);
	}

	return (NT_STATUS_SUCCESS);
}
