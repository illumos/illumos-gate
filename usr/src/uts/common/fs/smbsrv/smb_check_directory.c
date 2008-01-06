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
 * SMB: check_directory
 *
 * This SMB is used to verify that a path exists and is a directory.  No
 * error is returned if the given path exists and the client has read
 * access to it.  Client machines which maintain a concept of a "working
 * directory" will find this useful to verify the validity of a "change
 * working directory" command.  Note that the servers do NOT have a concept
 * of working directory for a particular client.  The client must always
 * supply full pathnames relative to the Tid in the SMB header.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes;    min = 2
 * UCHAR BufferFormat;                0x04
 * STRING DirectoryPath[];            Directory path
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * DOS clients, in particular, depend on the SMB_ERR_BAD_PATH return code
 * if the directory is not found.
 *
 * 4.3.3.1   Errors
 *
 * ERRDOS/ERRbadfile
 * ERRDOS/ERRbadpath
 * ERRDOS/ERRnoaccess
 * ERRHRD/ERRdata
 * ERRSRV/ERRinvid
 * ERRSRV/ERRbaduid
 * ERRSRV/ERRaccess
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

int
smb_com_check_directory(struct smb_request *sr)
{
	int rc;
	struct smb_node *dnode;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		/* NOTREACHED */
	}

	if (smbsr_decode_data(sr, "%S", sr, &sr->arg.dirop.fqi.path) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	sr->arg.dirop.fqi.srch_attr = 0;

	rc = smbd_fs_query(sr, &sr->arg.dirop.fqi, FQM_PATH_MUST_EXIST);
	if (rc) {
		smbsr_errno(sr, rc);
		/* NOTREACHED */
	}

	/*
	 * Release hold on dir_snode taken in smbd_fs_query()
	 */

	smb_node_release(sr->arg.dirop.fqi.dir_snode);

	dnode = sr->arg.dirop.fqi.last_snode;

	if (sr->arg.dirop.fqi.last_attr.sa_vattr.va_type != VDIR) {
		smb_node_release(dnode);
		SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);

		smbsr_errno(sr, ENOTDIR);
		/* NOTREACHED */
	}

	rc = smb_fsop_access(sr, sr->user_cr, dnode, FILE_TRAVERSE);

	smb_node_release(dnode);
	SMB_NULL_FQI_NODES(sr->arg.dirop.fqi);

	if (rc != 0) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		/* NOTREACHED */
	}

	smbsr_encode_empty_result(sr);

	return (SDRC_NORMAL_REPLY);
}
