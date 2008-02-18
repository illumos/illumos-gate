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
 * SMB: process_exit
 *
 * This command informs the server that a client process has terminated.
 * The server must close all files opened by Pid in the SMB header.  This
 * must automatically release all locks the process holds.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 *  USHORT ByteCount;                 Count of data bytes = 0
 *
 * This SMB should not generate any errors from the server, unless the
 * server is a user mode server and Uid in the SMB header is invalid.
 *
 * Clients are not required to send this SMB, they can do all cleanup
 * necessary by sending close SMBs to the server to release resources.  In
 * fact, clients who have negotiated LANMAN 1.0 and later probably do not
 * send this message at all.
 */

#include <smbsrv/smb_incl.h>

smb_sdrc_t
smb_com_process_exit(struct smb_request *sr)
{
	int rc;

	sr->uid_user = smb_user_lookup_by_uid(sr->session, &sr->user_cr,
	    sr->smb_uid);
	if (sr->uid_user == NULL) {
		rc = smbsr_encode_empty_result(sr);
		return ((rc == 0) ? SDRC_NORMAL_REPLY : SDRC_ERROR_REPLY);
	}

	/*
	 * If request has a valid tree ID, only look for the PID within
	 * that tree.  Otherwise look in all the trees.  smbtorture seems
	 * to be the only thing that sends this request these days and
	 * it doesn't provide a TID.
	 */
	sr->tid_tree = smb_tree_lookup_by_tid(sr->uid_user, sr->smb_tid);
	if (sr->tid_tree != NULL) {
		smb_ofile_close_all_by_pid(sr->tid_tree, sr->smb_pid);
		smb_odir_close_all_by_pid(sr->tid_tree, sr->smb_pid);
	} else {
		smb_tree_close_all_by_pid(sr->uid_user, sr->smb_pid);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_NORMAL_REPLY : SDRC_ERROR_REPLY);
}
