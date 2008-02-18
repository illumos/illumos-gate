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
 * SMB: set_information
 *
 * This message is sent to change the information about a file.
 *
 * Client Request                     Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 8
 * USHORT FileAttributes;             Attributes of the file
 * UTIME LastWriteTime;               Time of last write
 * USHORT Reserved [5];               Reserved (must be 0)
 * USHORT ByteCount;                  Count of data bytes;    min = 2
 * UCHAR BufferFormat;                0x04
 * STRING FileName[];                 File name
 *
 * FileName is the fully qualified name of the file relative to the Tid.
 *
 * Support of all parameters is optional.  A server which does not
 * implement one of the parameters will ignore that field.  If the
 * LastWriteTime field contain zero then the file's time is not changed.
 *
 * Server Response                    Description
 * ================================== =================================
 *
 * UCHAR WordCount;                   Count of parameter words = 0
 * USHORT ByteCount;                  Count of data bytes = 0
 *
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>

smb_sdrc_t
smb_com_set_information(struct smb_request *sr)
{
	int			rc;
	unsigned short		dattr;
	timestruc_t		utime;
	char			*path;
	struct smb_node		*dir_node;
	smb_attr_t		attr;
	struct smb_node		*node;
	char			*name;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		(void) smbsr_encode_empty_result(sr);
		return (SDRC_NORMAL_REPLY);
	}

	name = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	if (smbsr_decode_vwv(sr, "wl10.", &dattr, &utime.tv_sec) != 0) {
		kmem_free(name, MAXNAMELEN);
		return (SDRC_ERROR_REPLY);
	}

	if (smbsr_decode_data(sr, "%S", sr, &path) != 0) {
		kmem_free(name, MAXNAMELEN);
		return (SDRC_ERROR_REPLY);
	}
	utime.tv_nsec = 0;

	rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dir_node, name);
	if (rc != 0) {
		kmem_free(name, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR_REPLY);
	}

	rc = smb_fsop_lookup(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, name, &node, &attr, 0, 0);
	if (rc != 0) {
		smb_node_release(dir_node);
		kmem_free(name, MAXNAMELEN);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR_REPLY);
	}

	smb_node_release(dir_node);

	smb_node_set_dosattr(node, dattr);

	/*
	 * IR101794 The behaviour when the time field is set to -1
	 * is not documented, so we'll assume it should be treated
	 * like 0. We ignore utime.tv_nsec is assumed to be 0 here.
	 */
	if (utime.tv_sec != 0 && utime.tv_sec != -1) {
		utime.tv_sec = smb_local_time_to_gmt(utime.tv_sec);
		smb_node_set_time(node, 0, &utime, 0, 0, SMB_AT_MTIME);
	}

	rc = smb_sync_fsattr(sr, sr->user_cr, node);
	smb_node_release(node);
	kmem_free(name, MAXNAMELEN);

	if (rc) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR_REPLY);
	}

	rc = smbsr_encode_empty_result(sr);
	return ((rc == 0) ? SDRC_NORMAL_REPLY : SDRC_ERROR_REPLY);
}
