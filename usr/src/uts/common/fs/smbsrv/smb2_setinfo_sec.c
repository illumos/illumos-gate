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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Dispatch function for SMB2_SET_INFO
 * Similar to smb_nt_transact_security.c
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

uint32_t
smb2_setinfo_sec(smb_request_t *sr, smb_setinfo_t *si, uint32_t secinfo)
{
	smb_sd_t sd;
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

	if (SMB_TREE_IS_READONLY(sr))
		return (NT_STATUS_MEDIA_WRITE_PROTECTED);

	if (sr->tid_tree->t_acltype != ACE_T) {
		/*
		 * If target filesystem doesn't support ACE_T acls then
		 * don't process SACL
		 */
		secinfo &= ~SMB_SACL_SECINFO;
	}

	if ((secinfo & SMB_ALL_SECINFO) == 0)
		return (NT_STATUS_SUCCESS);

	status = smb_decode_sd(&si->si_data, &sd);
	if (status != NT_STATUS_SUCCESS)
		return (status);

	if (((secinfo & SMB_OWNER_SECINFO) && (sd.sd_owner == NULL)) ||
	    ((secinfo & SMB_GROUP_SECINFO) && (sd.sd_group == NULL)))
		return (NT_STATUS_INVALID_PARAMETER);

	if (!smb_node_is_system(sr->fid_ofile->f_node))
		status = smb_sd_write(sr, &sd, secinfo);

	smb_sd_term(&sd);
	return (status);
}
