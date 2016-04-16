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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB: unlock_byte_range
 *
 * This message is sent to unlock the given byte range.  Offset, Count, and
 * Pid must be identical to that specified in a prior successful lock.  If
 *
 * an unlock references an address range that is not locked, no error is
 * generated.
 *
 * Since Offset is a 32 bit quantity, this request is inappropriate for
 * general locking within a very large file.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 5
 * USHORT Fid;                        File handle
 * ULONG Count;                       Count of bytes to unlock
 * ULONG Offset;                      Offset from start of file
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 */

#include <smbsrv/smb_kproto.h>

smb_sdrc_t
smb_pre_unlock_byte_range(smb_request_t *sr)
{
	DTRACE_SMB_1(op__UnlockByteRange__start, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_unlock_byte_range(smb_request_t *sr)
{
	DTRACE_SMB_1(op__UnlockByteRange__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_unlock_byte_range(smb_request_t *sr)
{
	uint32_t	Length;
	uint32_t	Offset;
	uint32_t	lk_pid;
	DWORD		result;

	if (smbsr_decode_vwv(sr, "wll", &sr->smb_fid, &Length, &Offset) != 0)
		return (SDRC_ERROR);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	/* Note: SMB1 locking uses 16-bit PIDs. */
	lk_pid = sr->smb_pid & 0xFFFF;

	result = smb_unlock_range(sr, (uint64_t)Offset, (uint64_t)Length,
	    lk_pid);
	if (result != NT_STATUS_SUCCESS) {
		smbsr_error(sr, NT_STATUS_RANGE_NOT_LOCKED,
		    ERRDOS, ERROR_NOT_LOCKED);
		return (SDRC_ERROR);
	}

	if (smbsr_encode_empty_result(sr))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
