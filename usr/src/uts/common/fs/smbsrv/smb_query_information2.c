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
 * SMB: query_information2
 *
 * This SMB is gets information about the file represented by Fid.
 *
 *  Client Request                     Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 2
 *  USHORT Fid;                        File handle
 *  USHORT ByteCount;                  Count of data bytes = 0
 *
 *  Server Response                    Description
 *  ================================== =================================
 *
 *  UCHAR WordCount;                   Count of parameter words = 11
 *  SMB_DATE CreationDate;
 *  SMB_TIME CreationTime;
 *  SMB_DATE LastAccessDate;
 *  SMB_TIME LastAccessTime;
 *  SMB_DATE LastWriteDate;
 *  SMB_TIME LastWriteTime;
 *  ULONG FileDataSize;                File end of data
 *  ULONG FileAllocationSize;          File allocation size
 *  USHORT FileAttributes;
 *  USHORT ByteCount;                  Count of data bytes;  min = 0
 *
 * The file being interrogated is specified by Fid, which must possess at
 * least read permission.
 *
 * FileAttributes are described in the "File Attribute Encoding" section
 * elsewhere in this document.
 */

#include <smbsrv/smb_incl.h>

smb_sdrc_t
smb_pre_query_information2(smb_request_t *sr)
{
	int rc;

	rc = smbsr_decode_vwv(sr, "w", &sr->smb_fid);

	DTRACE_SMB_1(op__QueryInformation2__start, smb_request_t *, sr);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_query_information2(smb_request_t *sr)
{
	DTRACE_SMB_1(op__QueryInformation2__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_query_information2(smb_request_t *sr)
{
	smb_node_t *node;
	smb_attr_t *attr;
	uint32_t	dsize, dasize;
	unsigned short	dattr;
	int rc;


	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	if (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		return (SDRC_ERROR);
	}

	node = sr->fid_ofile->f_node;
	attr = &node->attr;

	dattr = smb_node_get_dosattr(node);
	dasize = attr->sa_vattr.va_blksize * attr->sa_vattr.va_nblocks;
	dsize = (dattr & SMB_FA_DIRECTORY) ? 0 : attr->sa_vattr.va_size;

	rc = smbsr_encode_result(sr, 11, 0, "byyyllww",
	    11,						/* wct */
	    smb_gmt2local(sr, attr->sa_crtime.tv_sec),
	    /* LastAccessTime */
	    smb_gmt2local(sr, attr->sa_vattr.va_atime.tv_sec),
	    /* LastWriteTime */
	    smb_gmt2local(sr, attr->sa_vattr.va_mtime.tv_sec),
	    dsize,
	    dasize,
	    dattr,					/* FileAttributes */
	    0);						/* bcc */

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
