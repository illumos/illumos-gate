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

#pragma ident	"@(#)smb_trans2_set_path_information.c	1.9	08/08/08 SMI"

/*
 * SMB: trans2_set_path_information
 *
 * This request is used to set information about a specific file or
 * subdirectory.
 *
 *  Client Request             Value
 *  ========================== =========================================
 *
 *  WordCount                  15
 *  MaxSetupCount              0
 *  SetupCount                 1
 *  Setup[0]                   TRANS2_SET_PATH_INFORMATION
 *
 *  Parameter Block Encoding   Description
 *  ========================== =========================================
 *
 *  USHORT InformationLevel;   Level of information to set
 *  ULONG Reserved;            Must be zero
 *  STRING FileName;           File or directory name
 *
 * The following InformationLevels may be set:
 *
 *  Information Level           Value
 *  ==========================  =========================================
 *
 *  SMB_INFO_STANDARD           1
 *  SMB_INFO_QUERY_EA_SIZE      2
 *  SMB_INFO_QUERY_ALL_EAS      4
 *
 * The response formats are:
 *
 * 4.2.16.1  SMB_INFO_STANDARD & SMB_INFO_QUERY_EA_SIZE
 *
 *  Parameter Block Encoding           Description
 *  ================================== =================================
 *
 *  USHORT Reserved                    0
 *
 *  Data Block Encoding                Description
 *  ================================== =================================
 *
 *  SMB_DATE CreationDate;             Date when file was created
 *  SMB_TIME CreationTime;             Time when file was created
 *  SMB_DATE LastAccessDate;           Date of last file access
 *  SMB_TIME LastAccessTime;           Time of last file access
 *  SMB_DATE LastWriteDate;            Date of last write to the file
 *  SMB_TIME LastWriteTime;            Time of last write to the file
 *  ULONG  DataSize;                   File Size
 *  ULONG AllocationSize;              Size of filesystem allocation
 *                                      unit
 *  USHORT Attributes;                 File Attributes
 *  ULONG EaSize;                      Size of file's EA information
 *                                      (SMB_INFO_QUERY_EA_SIZE)
 *
 * 4.2.16.2  SMB_INFO_QUERY_ALL_EAS
 *
 *  Response Field       Value
 *  ==================== ===============================================
 *
 *  MaxDataCount         Length of FEAlist found (minimum value is 4)
 *
 *  Parameter Block      Description
 *  Encoding             ===============================================
 *  ====================
 *
 *  USHORT EaErrorOffset Offset into EAList of EA error
 *
 *  Data Block Encoding  Description
 *  ==================== ===============================================
 *
 *  ULONG ListLength;    Length of the remaining data
 *  UCHAR EaList[]       The extended attributes list
 *
 * Undocumented things:
 *	Poorly documented information levels.  Information must be infered
 *	from other commands.
 *
 *	NULL Attributes means don't set them.  NT sets the high bit to
 *	set attributes to 0.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb_com_trans2_set_path_information(struct smb_request *sr, struct smb_xa *xa)
{
	smb_trans2_setinfo_t *info;
	smb_attr_t ret_attr;
	struct smb_node *dir_node;
	struct smb_node *ret_snode;
	smb_error_t smberr;
	DWORD status;
	int rc = 0;

	info = kmem_zalloc(sizeof (smb_trans2_setinfo_t), KM_SLEEP);
	info->ts_xa = xa;

	if (smb_mbc_decodef(&xa->req_param_mb, "%w4.u", sr, &info->level,
	    &info->path) != 0) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		return (SDRC_ERROR);
	}

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type) ||
	    SMB_TREE_IS_READONLY(sr)) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	rc = smb_pathname_reduce(sr, sr->user_cr, info->path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode,
	    &dir_node, info->name);

	if (rc != 0) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, info->name, &ret_snode, &ret_attr,
	    0, 0);

	smb_node_release(dir_node);

	if (rc != 0) {
		kmem_free(info, sizeof (smb_trans2_setinfo_t));
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	if (smb_oplock_conflict(ret_snode, sr->session, NULL)) {
		/*
		 * for the benefit of attribute setting later on
		 */
		smb_oplock_break(ret_snode);
	}

	info->node = ret_snode;
	status = smb_trans2_set_information(sr, info, &smberr);
	info->node = NULL;
	smb_node_release(ret_snode);
	kmem_free(info, sizeof (smb_trans2_setinfo_t));

	if (status == NT_STATUS_DATA_ERROR)
		return (SDRC_ERROR);

	if (status != NT_STATUS_SUCCESS) {
		smbsr_error(sr, smberr.status, smberr.errcls, smberr.errcode);
		return (SDRC_ERROR);
	}

	return (SDRC_SUCCESS);
}
