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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * The seek message is sent to set the current file pointer for FID.
 * This request should generally only be used by clients wishing to
 * find the size of a file, since all read and write requests include
 * the read or write file position as part of the SMB. This request
 * is inappropriate for large files, as the offsets specified are only
 * 32 bits.
 *
 * The CIFS/1.0 (1996) spec contains the following incomplete statement:
 *
 * "A seek which results in an Offset which can not be expressed
 *  in 32 bits returns the least significant."
 *
 * It would probably be a mistake to make an assumption about what this
 * statement means. So, for now, we return an error if the resultant
 * file offset is beyond the 32-bit limit.
 */

#include <smbsrv/smb_kproto.h>


/*
 * smb_com_seek
 *
 * Client Request                     Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 4
 * USHORT Fid;                        File handle
 * USHORT Mode;                       Seek mode: 0, 1 or 2
 * LONG Offset;                       Relative offset
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * The starting point of the seek is set by Mode:
 *
 *      0  seek from start of file
 *      1  seek from current current position
 *      2  seek from end of file
 *
 * The "current position" reflects the offset plus data length specified in
 * the previous read, write or seek request, and the pointer set by this
 * command will be replaced by the offset specified in the next read, write
 * or seek command.
 *
 * Server Response                    Description
 * ================================== =================================
 * UCHAR WordCount;                   Count of parameter words = 2
 * ULONG Offset;                      Offset from start of file
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * The response returns the new file pointer in Offset, which is expressed
 * as the offset from the start of the file, and may be beyond the current
 * end of file. An attempt to seek before the start of the file sets the
 * current file pointer to the start of the file.
 */
smb_sdrc_t
smb_pre_seek(smb_request_t *sr)
{
	DTRACE_SMB_START(op__Seek, smb_request_t *, sr);
	return (SDRC_SUCCESS);
}

void
smb_post_seek(smb_request_t *sr)
{
	DTRACE_SMB_DONE(op__Seek, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_seek(smb_request_t *sr)
{
	ushort_t	mode;
	int32_t		off;
	uint32_t	off_ret;
	int		rc;

	if (smbsr_decode_vwv(sr, "wwl", &sr->smb_fid, &mode, &off) != 0)
		return (SDRC_ERROR);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	if ((rc = smb_ofile_seek(sr->fid_ofile, mode, off, &off_ret)) != 0) {
		if (rc == EINVAL) {
			smbsr_error(sr, 0, ERRDOS, ERRbadfunc);
			return (SDRC_ERROR);
		} else {
			smbsr_error(sr, 0, ERRSRV, ERRerror);
			return (SDRC_ERROR);
		}
	}

	if (smbsr_encode_result(sr, 2, 0, "blw", 2, off_ret, 0))
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
