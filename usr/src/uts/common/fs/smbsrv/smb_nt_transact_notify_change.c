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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * File Change Notification (FCN)
 * SMB1 specific part.
 */

/*
 * SMB: nt_transact_notify_change
 *
 *  Client Setup Words                 Description
 *  ================================== =================================
 *
 *  ULONG CompletionFilter;            Specifies operation to monitor
 *  USHORT Fid;                        Fid of directory to monitor
 *  BOOLEAN WatchTree;                 TRUE = watch all subdirectories too
 *  UCHAR Reserved;                    MBZ
 *
 * This command notifies the client when the directory specified by Fid is
 * modified.  See smb_notify.c for details.
 *
 * The MaxParameterCount field in the NT transact header determines
 * the size of the buffer used to return change information:
 *
 *  Server Response                    Description
 *  ================================== ================================
 *  ParameterCount                     # of bytes of change data
 *  Parameters[ ParameterCount ]       FILE_NOTIFY_INFORMATION
 *                                      structures
 *
 * See smb_notify.c for details of FILE_NOTIFY_INFORMATION
 */

#include <smbsrv/smb_kproto.h>

/*
 * We add this flag to the CompletionFilter (see above) when the
 * client sets WatchTree.  Must not overlap FILE_NOTIFY_VALID_MASK.
 */
#define	NODE_FLAGS_WATCH_TREE		0x10000000
#if (NODE_FLAGS_WATCH_TREE & FILE_NOTIFY_VALID_MASK)
#error "NODE_FLAGS_WATCH_TREE"
#endif

/*
 * smb_nt_transact_notify_change
 *
 * Handle and SMB NT transact NOTIFY CHANGE request.
 * Basically, wait until "something has changed", and either
 * return information about what changed, or return a special
 * error telling the client "many things changed".
 *
 * The implementation uses a per-node list of waiting notify
 * requests like this one, each with a blocked worker thead.
 * Later, FEM and/or smbsrv events wake these threads, which
 * then send the reply to the client.
 */
smb_sdrc_t
smb_nt_transact_notify_change(smb_request_t *sr, struct smb_xa *xa)
{
	uint32_t		CompletionFilter;
	unsigned char		WatchTree;
	uint32_t		status;
	hrtime_t		t1, t2;

	if (smb_mbc_decodef(&xa->req_setup_mb, "lwb",
	    &CompletionFilter, &sr->smb_fid, &WatchTree) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}
	CompletionFilter &= FILE_NOTIFY_VALID_MASK;
	if (WatchTree)
		CompletionFilter |= NODE_FLAGS_WATCH_TREE;

	smbsr_lookup_file(sr);

	t1 = gethrtime();
	status = smb_notify_common(sr, &xa->rep_data_mb, CompletionFilter);
	t2 = gethrtime();

	/*
	 * We don't want to include the (indefinite) wait time of the
	 * smb_notify_common() call in the SMB1 transact latency.
	 * The easiest way to do that, without adding special case
	 * logic to the common SMB1 dispatch handler is to adjust the
	 * start time of this request to effectively subtract out the
	 * time we were blocked in smb_notify_common().
	 */
	sr->sr_time_start += (t2 - t1);

	if (status != 0)
		smbsr_error(sr, status, 0, 0);

	return (SDRC_SUCCESS);
}
