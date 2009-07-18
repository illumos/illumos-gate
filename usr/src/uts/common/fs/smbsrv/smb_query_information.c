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
 */

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
	smb_fqi_t *fqi = &sr->arg.dirop.fqi;
	int rc;

	rc = smbsr_decode_data(sr, "%S", sr, &fqi->fq_path.pn_path);
	if (rc == 0) {
		if (strlen(fqi->fq_path.pn_path) == 0)
			fqi->fq_path.pn_path = "\\";
	}

	DTRACE_SMB_2(op__QueryInformation__start, smb_request_t *, sr,
	    smb_fqi_t *, fqi);

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
	char		*path = sr->arg.dirop.fqi.fq_path.pn_path;
	char		*name = sr->arg.dirop.fqi.fq_last_comp;
	int		rc;
	uint16_t	dattr;
	uint32_t	write_time;
	u_offset_t	datasz;
	smb_node_t	*dir_node;
	smb_node_t	*node;
	smb_attr_t	attr;
	timestruc_t	*mtime;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if ((rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    sr->tid_tree->t_snode, sr->tid_tree->t_snode, &dir_node, name))
	    != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	if ((rc = smb_fsop_lookup_name(sr, sr->user_cr, SMB_FOLLOW_LINKS,
	    sr->tid_tree->t_snode, dir_node, name, &node)) != 0) {
		smb_node_release(dir_node);
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	smb_node_release(dir_node);
	rc = smb_node_getattr(sr, node, &attr);
	smb_node_release(node);

	if (rc != 0) {
		smbsr_error(sr, NT_STATUS_INTERNAL_ERROR,
		    ERRDOS, ERROR_INTERNAL_ERROR);
		return (SDRC_ERROR);
	}

	dattr = attr.sa_dosattr & FILE_ATTRIBUTE_MASK;
	mtime = &attr.sa_vattr.va_mtime;
	write_time = smb_gmt2local(sr, mtime->tv_sec);
	datasz = attr.sa_vattr.va_size;
	if (datasz > UINT_MAX)
		datasz = UINT_MAX;

	rc = smbsr_encode_result(sr, 10, 0, "bwll10.w",
	    10, dattr, write_time, (uint32_t)datasz, 0);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}
