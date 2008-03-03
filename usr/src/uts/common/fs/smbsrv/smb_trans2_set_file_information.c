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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SMB: trans2_set_file_information
 *
 * This request is used to set information about a specific file or
 * subdirectory given a handle to the file or subdirectory.
 *
 *  Client Request             Value
 *  ========================== ==========================================
 *
 *  WordCount                  15
 *  MaxSetupCount              0
 *  SetupCount                 1
 *  Setup[0]                   TRANS2_SET_FILE_INFORMATION
 *
 *  Parameter Block Encoding   Description
 *  ========================== ==========================================
 *
 *  USHORT Fid;                Handle of file for request
 *  USHORT InformationLevel;   Level of information requested
 *  USHORT Reserved;           Ignored by the server
 *
 * The following InformationLevels may be set:
 *
 *  Information Level                Value
 *  ================================ =====
 *
 *  SMB_INFO_STANDARD                1
 *  SMB_INFO_QUERY_EA_SIZE           2
 *  SMB_SET_FILE_BASIC_INFO          0x101
 *  SMB_SET_FILE_DISPOSITION_INFO    0x102
 *  SMB_SET_FILE_ALLOCATION_INFO     0x103
 *  SMB_SET_FILE_END_OF_FILE_INFO    0x104
 *
 * The two levels below 0x101 are as described in the
 * NT_SET_PATH_INFORMATION transaction.  The requested information is
 * placed in the Data portion of the transaction response. For the
 * information levels greater than 0x100, the transaction response has 1
 * parameter word which should be ignored by the client.
 *
 * 4.2.17.1  SMB_FILE_DISPOSITION_INFO
 *
 *  Response Field       Value
 *  ==================== ===============================================
 *
 *  BOOLEAN              A boolean which is TRUE if the file is marked
 *  FileIsDeleted        for deletion
 *
 * 4.2.17.2  SMB_FILE_ALLOCATION_INFO
 *
 *  Response Field       Value
 *  ==================== ===============================================
 *
 *  LARGE_INTEGER        File Allocation size in number of bytes
 *
 * 4.2.17.3  SMB_FILE_END_OF_FILE_INFO
 *
 *  Response Field       Value
 *  ==================== ===============================================
 *
 *  LARGE_INTEGER        The total number of bytes that need to be
 *                        traversed from the beginning of the file in
 *                        order to locate the end of the file
 *
 * Undocumented things:
 *	Poorly documented information levels.  Information must be infered
 *	from other commands.
 *
 *	NULL Attributes means don't set them.  NT sets the high bit to
 *	set attributes to 0.
 */

#include <smbsrv/smb_incl.h>

/*
 * smb_com_trans2_set_file_information
 */
smb_sdrc_t
smb_com_trans2_set_file_information(struct smb_request *sr, struct smb_xa *xa)
{
	smb_trans2_setinfo_t *info;
	smb_error_t smberr;
	DWORD status;
	int rc;

	info = kmem_zalloc(sizeof (smb_trans2_setinfo_t), KM_SLEEP);
	info->ts_xa = xa;

	rc = smb_decode_mbc(&xa->req_param_mb, "ww", &sr->smb_fid,
	    &info->level);
	if (rc != 0) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		return (SDRC_ERROR);
	}

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type) ||
	    SMB_TREE_IS_READ_ONLY(sr)) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	info->node = sr->fid_ofile->f_node;

	if (info->node == 0 ||
	    !SMB_FTYPE_IS_DISK(sr->fid_ofile->f_ftype)) {
		cmn_err(CE_NOTE, "SmbT2SetFileInfo: access denied");
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	status = smb_trans2_set_information(sr, info, &smberr);
	kmem_free(info, sizeof (smb_trans2_setinfo_t));

	if (status == NT_STATUS_DATA_ERROR)
		return (SDRC_ERROR);

	if (status == NT_STATUS_UNSUCCESSFUL) {
		smbsr_error(sr, smberr.status, smberr.errcls, smberr.errcode);
		return (SDRC_ERROR);
	}

	return (SDRC_SUCCESS);
}
