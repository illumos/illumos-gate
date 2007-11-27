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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <smbsrv/smb_incl.h>

int
smb_com_unlock_byte_range(struct smb_request *sr)
{
	uint32_t	Length;
	uint32_t	Offset;
	DWORD		result;

	if (smbsr_decode_vwv(sr, "wll", &sr->smb_fid, &Length, &Offset) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_raise_cifs_error(sr, NT_STATUS_INVALID_HANDLE,
		    ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}

	result = smb_unlock_range(sr, sr->fid_ofile->f_node,
	    (u_offset_t)Offset, (uint64_t)Length);
	if (result != NT_STATUS_SUCCESS) {
		smb_unlock_range_raise_error(sr, result);
		/* NOT REACHED */
	}

	smbsr_encode_empty_result(sr);

	return (SDRC_NORMAL_REPLY);
}
