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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>

/*
 * Close a file by fid.  All locks or other resources held by the
 * requesting process on the file should be released by the server.
 * The requesting process can no longer use the fid for further
 * file access requests.
 *
 * If LastWriteTime is non-zero, it should be used to set the file
 * timestamp.  Otherwise, file system should set the timestamp.
 * Failure to set the timestamp, even if requested by the client,
 * should not result in an error response from the server.
 */
smb_sdrc_t
smb_pre_close(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_vwv(sr, "wl", &sr->smb_fid, &sr->arg.timestamp);

	DTRACE_SMB_1(op__Close__start, smb_request_t *, sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_close(smb_request_t *sr)
{
	DTRACE_SMB_1(op__Close__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_close(smb_request_t *sr)
{
	int32_t mtime;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	mtime = smb_time_local_to_gmt(sr, sr->arg.timestamp);
	smb_ofile_close(sr->fid_ofile, mtime);

	if (smbsr_encode_empty_result(sr) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}

/*
 * Close the file represented by fid and then disconnect the
 * associated tree.
 */
smb_sdrc_t
smb_pre_close_and_tree_disconnect(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_vwv(sr, "wl", &sr->smb_fid, &sr->arg.timestamp);

	DTRACE_SMB_1(op__CloseAndTreeDisconnect__start, smb_request_t *, sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_close_and_tree_disconnect(smb_request_t *sr)
{
	DTRACE_SMB_1(op__CloseAndTreeDisconnect__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_close_and_tree_disconnect(smb_request_t *sr)
{
	int32_t mtime;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	mtime = smb_time_local_to_gmt(sr, sr->arg.timestamp);
	smb_ofile_close(sr->fid_ofile, mtime);
	smb_session_cancel_requests(sr->session, sr->tid_tree, sr);
	smb_tree_disconnect(sr->tid_tree, B_TRUE);

	if (smbsr_encode_empty_result(sr) != 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
