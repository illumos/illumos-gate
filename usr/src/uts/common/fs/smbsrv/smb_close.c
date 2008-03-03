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
	int rc;

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	rc = smb_common_close(sr, sr->arg.timestamp);
	if (rc) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
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
	int rc;

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	rc = smb_common_close(sr, sr->arg.timestamp);
	smbsr_rq_notify(sr, sr->session, sr->tid_tree);
	smb_tree_disconnect(sr->tid_tree);

	if (rc) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

/*
 * smb_common_close
 *
 * Common close function called by SmbClose, SmbWriteAndClose,
 * and SMBCloseAndTreeDisconnect.
 */
int
smb_common_close(smb_request_t *sr, uint32_t last_wtime)
{
	return (smb_ofile_close(sr->fid_ofile, last_wtime));
}

/*
 * smb_commit_delete_on_close()
 *
 * Check for the DeleteOnClose flag on the smb file and set it on the
 * smb node if it is not already set. This will inhibit subsequent
 * open requests. The delete-on-close credentials should be set to the
 * user credentials of the current open file instance.
 *
 * When DeleteOnClose is set on an smb_node, the common open code will
 * reject subsequent open requests for the file. Observation of Windows
 * 2000 indicates that subsequent opens should be allowed (assuming
 * there would be no sharing violation) until the file is closed using
 * the fid on which the DeleteOnClose was requested.
 *
 * If there are multiple opens with delete-on-close create options,
 * whichever the first file handle is closed will trigger the node to be
 * marked as delete-on-close. The credentials of that ofile will be used
 * as the delete-on-close credentials of the node.
 */
void
smb_commit_delete_on_close(struct smb_ofile *ofile)
{
	struct smb_node *node = ofile->f_node;

	if (!(node->flags & NODE_FLAGS_DELETE_ON_CLOSE) &&
	    (ofile->f_flags & SMB_OFLAGS_SET_DELETE_ON_CLOSE))	{
		node->flags |= NODE_FLAGS_DELETE_ON_CLOSE;
		crhold(node->delete_on_close_cred = ofile->f_cr);
	}
}
