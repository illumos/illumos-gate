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

int
smb_com_query_information2(struct smb_request *sr)
{
	smb_node_t *node;
	smb_attr_t *attr;
	uint32_t	dsize, dasize;
	unsigned short	dattr;

	if (smbsr_decode_vwv(sr, "w", &sr->smb_fid) != 0) {
		smbsr_decode_error(sr);
		/* NOTREACHED */
	}

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		/* NOTREACHED */
	}


	if (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS, ERRnoaccess);
		/* NOTREACHED */
	}

	node = sr->fid_ofile->f_node;
	attr = &node->attr;

	dattr = smb_node_get_dosattr(node);
	dasize = attr->sa_vattr.va_blksize * attr->sa_vattr.va_nblocks;
	dsize = (dattr & SMB_FA_DIRECTORY) ? 0 : attr->sa_vattr.va_size;

	smbsr_encode_result(sr, 11, 0, "byyyllww",
	    11,						/* wct */
	    smb_gmt_to_local_time(attr->sa_crtime.tv_sec),
	    /* LastAccessTime */
	    smb_gmt_to_local_time(attr->sa_vattr.va_atime.tv_sec),
	    /* LastWriteTime */
	    smb_gmt_to_local_time(attr->sa_vattr.va_mtime.tv_sec),
	    dsize,
	    dasize,
	    dattr,					/* FileAttributes */
	    0);						/* bcc */

	return (SDRC_NORMAL_REPLY);
}
