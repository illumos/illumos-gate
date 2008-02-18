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
smb_com_query_information(struct smb_request *sr)
{
	int			rc;
	unsigned short		dattr;
	uint32_t		write_time, file_size;
	char			*path;
	struct smb_node		*dir_node;
	struct smb_node		*node;
	smb_attr_t		attr;
	char			*name;
	timestruc_t		*mtime;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		dattr = SMB_FA_NORMAL;
		write_time = file_size = 0;
		rc = smbsr_encode_result(sr, 10, 0, "bwll10.w",
		    10, dattr, write_time, file_size, 0);
		return ((rc == 0) ? SDRC_NORMAL_REPLY : SDRC_ERROR_REPLY);
	}

	if (smbsr_decode_data(sr, "%S", sr, &path) != 0)
		return (SDRC_ERROR_REPLY);

	/*
	 * Interpret NULL file names as "\".
	 */
	if (strlen(path) == 0)
		path = "\\";

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	if ((rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dir_node, name))
	    != 0) {
		kmem_free(name, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR_REPLY);
	}

	if ((rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, name, &node, &attr, 0, 0)) != 0) {
		smb_node_release(dir_node);
		kmem_free(name, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR_REPLY);
	}

	smb_node_release(dir_node);

	dattr = smb_node_get_dosattr(node);
	mtime = smb_node_get_mtime(node);
	write_time = smb_gmt_to_local_time(mtime->tv_sec);
	file_size = (uint32_t)smb_node_get_size(node, &node->attr);

	smb_node_release(node);
	kmem_free(name, MAXNAMELEN);

	rc = smbsr_encode_result(sr, 10, 0, "bwll10.w",
	    10,			/* wct */
	    dattr,
	    write_time,		/* Last write time */
	    file_size,		/* FileSize */
	    0);			/* bcc */

	return ((rc == 0) ? SDRC_NORMAL_REPLY : SDRC_ERROR_REPLY);
}
