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

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>

/*
 * smb_com_delete_directory
 *
 * The delete directory message is sent to delete an empty directory. The
 * appropriate Tid and additional pathname are passed. The directory must
 * be empty for it to be deleted.
 *
 * NT supports a hidden permission known as File Delete Child (FDC). If
 * the user has FullControl access to a directory, the user is permitted
 * to delete any object in the directory regardless of the permissions
 * on the object.
 *
 * Client Request                     Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes; min = 2
 * UCHAR BufferFormat;                0x04
 * STRING DirectoryName[];            Directory name
 *
 * The directory to be deleted cannot be the root of the share specified
 * by Tid.
 *
 * Server Response                    Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 */
smb_sdrc_t
smb_pre_delete_directory(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_data(sr, "%S", sr, &sr->arg.dirop.fqi.path);

	DTRACE_SMB_2(op__DeleteDirectory__start, smb_request_t *, sr,
	    struct dirop *, &sr->arg.dirop);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_delete_directory(smb_request_t *sr)
{
	DTRACE_SMB_1(op__DeleteDirectory__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_delete_directory(smb_request_t *sr)
{
	smb_node_t *dnode;
	int rc;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	sr->arg.dirop.fqi.srch_attr = 0;

	rc = smbd_fs_query(sr, &sr->arg.dirop.fqi, FQM_PATH_MUST_EXIST);
	if (rc) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	dnode = sr->arg.dirop.fqi.last_snode;

	if (dnode->attr.sa_dosattr & FILE_ATTRIBUTE_READONLY) {
		smb_node_release(dnode);
		smb_node_release(sr->arg.dirop.fqi.dir_snode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);

		smbsr_error(sr, NT_STATUS_CANNOT_DELETE,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	smb_node_release(dnode);

	dnode = sr->arg.dirop.fqi.dir_snode;

	rc = smb_fsop_rmdir(sr, sr->user_cr, dnode,
	    sr->arg.dirop.fqi.last_comp_od, 1);
	if (rc != 0) {
		smb_node_release(dnode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_node_release(dnode);
	SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
