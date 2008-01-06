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
 * SMB: tree_disconnect
 *
 * This message informs the server that the client no longer wishes to
 * access the resource connected to with a prior SMB_COM_TREE_CONNECT or
 * SMB_COM_TREE_CONNECT_ANDX.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * The resource sharing connection identified by Tid in the SMB header is
 * logically disconnected from the server. Tid is invalidated; it will not
 * be recognized if used by the client for subsequent requests. All locks,
 * open files, etc. created on behalf of Tid are released.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * 4.1.5.1   Errors
 *
 * ERRSRV/ERRinvnid
 * ERRSRV/ERRbaduid
 */

#include <smbsrv/smb_incl.h>

/*
 * Function: int smb_com_tree_disconnect(struct smb_request *)
 *
 * Please note the SDDF_SUPPRESS_UID is set for this operation;
 * therefore, the uid_user field in sr is invalid. Do not use it
 * or the system would panic.
 *
 * Please also note that in some cases, the client would not send
 * tree disconnect call. An example of that is, the return of invalid
 * uid for a client request i.e. read_andx, when the used has logged
 * off. This will cause a minor memory leak for the share and some
 * files would remain open. When the session is destroyed, the leaked
 * and remained open files will be freed/closed. We will need to
 * address this problem by re-architecting user/tree structures.
 * For the time being, we will leave it till we have time.
 */

int
smb_com_tree_disconnect(struct smb_request *sr)
{
	/*
	 * A Tree Disconnect request requires a valid user ID as well as a
	 * valid tree ID. However, some clients logoff a user and then try to
	 * disconnect the trees connected using the user they just logged off.
	 * There's a problem with that behavior and the tree representation
	 * of the different contexts (session, user, tree, file...). In order
	 * to find a tree a valid user has to be provided. This means, with
	 * the behavior described above, a client would receive a negative
	 * response to the TreeDisconnect request with an error code saying
	 * ERRbaduid. That response breaks some clients. To prevent that
	 * from happening, the dispatch table indicates that, for the
	 * TreeDisconnect request, the UID and the TID shouldn't be looked up
	 * in the dispatch routine. The lookup is done here. If the user or
	 * the tree cannot be identified a negative response is sent back with
	 * the error code ERRinvnid.
	 */
	sr->uid_user = smb_user_lookup_by_uid(sr->session, &sr->user_cr,
	    sr->smb_uid);
	if (sr->uid_user != NULL)
		sr->tid_tree = smb_tree_lookup_by_tid(sr->uid_user,
		    sr->smb_tid);

	if (sr->uid_user == NULL || sr->tid_tree == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRinvnid);
		/* NOTREACHED */
	}

	smbsr_rq_notify(sr, sr->session, sr->tid_tree);
	smb_tree_disconnect(sr->tid_tree);
	smbsr_encode_empty_result(sr);
	return (SDRC_NORMAL_REPLY);
}
