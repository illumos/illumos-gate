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
 * SMB: set_information2
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 7
 *  USHORT Fid;                        File handle
 *  SMB_DATE CreationDate;
 *  SMB_TIME CreationTime;
 *  SMB_DATE LastAccessDate;
 *  SMB_TIME LastAccessTime;
 *  SMB_DATE LastWriteDate;
 *  SMB_TIME LastWriteTime;
 *  USHORT ByteCount;                  Count of data bytes = 0
 *
 * SMB_COM_SET_INFORMATION2 sets information about the file represented by
 * Fid.  The target file is updated from the values specified.  A date or
 * time value or zero indicates to leave that specific date and time
 * unchanged.
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 0
 *  USHORT ByteCount;                  Count of data bytes = 0
 *
 * Fid must be open with (at least) write permission.
 */

#include <smbsrv/smb_incl.h>

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
	unsigned short		la_ddate, la_dtime;
	unsigned short		lw_ddate, lw_dtime;
	unsigned short		cr_ddate, cr_dtime;
	timestruc_t		crtime, mtime, atime;
	unsigned int 		what = 0;
	struct smb_node		*node;
	int			rc;

	rc = smbsr_decode_vwv(sr, "wwwwwww", &sr->smb_fid, &cr_ddate, &cr_dtime,
	    &la_ddate, &la_dtime, &lw_ddate, &lw_dtime);
	if (rc != 0)
		return (SDRC_ERROR);

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	node = sr->fid_ofile->f_node;

	if (node == 0 || sr->fid_ofile->f_ftype != SMB_FTYPE_DISK) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		return (SDRC_ERROR);
	}

	crtime.tv_nsec = mtime.tv_nsec = atime.tv_nsec = 0;

	if (cr_ddate || cr_dtime) {
		crtime.tv_sec = smb_local2gmt(sr,
		    dosfs_dos_to_ux_time(cr_ddate, cr_dtime));
		what |= SMB_AT_CRTIME;
	}

	if (lw_ddate || lw_dtime) {
		mtime.tv_sec = smb_local2gmt(sr,
		    dosfs_dos_to_ux_time(lw_ddate, lw_dtime));
		what |= SMB_AT_MTIME;
	}

	if (la_ddate || la_dtime) {
		atime.tv_sec = smb_local2gmt(sr,
		    dosfs_dos_to_ux_time(la_ddate, la_dtime));
		what |= SMB_AT_ATIME;
	}

	smb_node_set_time(node, &crtime, &mtime, &atime, 0, what);
	rc = smb_sync_fsattr(sr, sr->user_cr, node);
	if (rc) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
