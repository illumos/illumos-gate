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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_QUERY_INFO
 * Similar to smb_nt_transact_security.c
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

uint32_t
smb2_qinfo_sec(smb_request_t *sr, smb_queryinfo_t *qi)
{
	smb_sd_t sd;
	uint32_t secinfo = qi->qi_AddlInfo;
	uint32_t sdlen;
	uint32_t status;

	/*
	 * secinfo & ...
	 * OWNER_SECURITY_INFORMATION,
	 * GROUP_SECURITY_INFORMATION,
	 * DACL_SECURITY_INFORMATION, ...
	 */

	if ((sr->fid_ofile->f_node == NULL) ||
	    (sr->fid_ofile->f_ftype != SMB_FTYPE_DISK))
		return (NT_STATUS_INVALID_PARAMETER);

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * If target filesystem doesn't support ACE_T acls then
		 * don't process SACL
		 */
		secinfo &= ~SMB_SACL_SECINFO;
	}

	status = smb_sd_read(sr, &sd, secinfo);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	sdlen = smb_sd_len(&sd, secinfo);
	if (sdlen == 0) {
		status = NT_STATUS_INVALID_SECURITY_DESCR;
		goto out;
	}

	if (sdlen > sr->raw_data.max_bytes) {
		/*
		 * The maximum data return count specified by the
		 * client is not big enough to hold the security
		 * descriptor.  Return the special error that
		 * tells the client how much room they need.
		 * Error data is the required size.
		 */
		MBC_FLUSH(&sr->raw_data);
		sr->raw_data.max_bytes = 4;
		(void) smb_mbc_encodef(&sr->raw_data, "l", sdlen);
		status = NT_STATUS_BUFFER_TOO_SMALL;
		goto out;
	}

	smb_encode_sd(&sr->raw_data, &sd, secinfo);
	status = 0;

out:
	smb_sd_term(&sd);
	return (status);
}
