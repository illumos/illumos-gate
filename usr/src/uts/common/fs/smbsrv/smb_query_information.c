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
 * SMB: query_information
 *
 * This request is sent to obtain information about a file.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes;    min = 2
 * UCHAR BufferFormat;                0x04
 * STRING FileName[];                 File name
 *
 * FileName is the fully qualified name of the file relative to the Tid in
 * the header.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 10
 * USHORT FileAttributes;
 * UTIME LastWriteTime;               Time of last write
 * ULONG FileSize;                    File size
 * USHORT Reserved [5];               Reserved - client should ignore
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 * FileAttributes are as described in the "Attributes Encoding" section of
 * this document.
 *
 * Note that FileSize is limited to 32 bits, this request is inappropriate
 * for files whose size is too large.
 *
 * NOTES:
 *	Some clients send a NULL file name.  Right now we return ERRbadfile
 *	until we find out what a MS client would send...
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb_pre_query_information(smb_request_t *sr)
{
	struct smb_fqi *fqi = &sr->arg.dirop.fqi;
	int rc;

	if ((rc = smbsr_decode_data(sr, "%S", sr, &fqi->path)) == 0) {
		if (strlen(fqi->path) == 0)
			fqi->path = "\\";
	}

	DTRACE_SMB_2(op__QueryInformation__start, smb_request_t *, sr,
	    struct smb_fqi *, fqi);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_query_information(smb_request_t *sr)
{
	DTRACE_SMB_1(op__QueryInformation__done, smb_request_t *, sr);
}

smb_sdrc_t
smb_com_query_information(smb_request_t *sr)
{
	char		*path = sr->arg.dirop.fqi.path;
	char		*name = sr->arg.dirop.fqi.last_comp;
	int		rc;
	uint16_t	dattr;
	uint32_t	write_time;
	u_offset_t	datasz;
	smb_node_t	*dir_node;
	smb_node_t	*node;
	smb_attr_t	attr;
	timestruc_t	*mtime;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		rc = smbsr_encode_result(sr, 10, 0, "bwll10.w",
		    10, FILE_ATTRIBUTE_NORMAL, 0, 0, 0);
		return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
	}

	if ((rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dir_node, name))
	    != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	if ((rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, name, &node, &attr, 0, 0)) != 0) {
		smb_node_release(dir_node);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_node_release(dir_node);

	dattr = smb_node_get_dosattr(node);
	mtime = smb_node_get_mtime(node);
	write_time = smb_gmt2local(sr, mtime->tv_sec);
	datasz = smb_node_get_size(node, &node->attr);
	if (datasz > UINT_MAX)
		datasz = UINT_MAX;

	smb_node_release(node);

	rc = smbsr_encode_result(sr, 10, 0, "bwll10.w",
	    10, dattr, write_time, (uint32_t)datasz, 0);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
