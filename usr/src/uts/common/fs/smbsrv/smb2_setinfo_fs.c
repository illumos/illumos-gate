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
 *
 * [MS-FSCC 2.5] If a file system does not implement ...
 * an Information Classs, NT_STATUS_INVALID_PARAMETER...
 */

#include <smbsrv/smb2_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/ntifs.h>

uint32_t smb2_setfs_control(smb_request_t *, smb_setinfo_t *);
uint32_t smb2_setfs_obj_id(smb_request_t *, smb_setinfo_t *);

uint32_t
smb2_setinfo_fs(smb_request_t *sr, smb_setinfo_t *si, int InfoClass)
{
	uint32_t status;

	switch (InfoClass) {

	/* pg 153 */

	case FileFsControlInformation:	/* 6 */
		status = smb2_setfs_control(sr, si);
		break;
	case FileFsObjectIdInformation:	/* 8 */
		status = smb2_setfs_obj_id(sr, si);
		break;

	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	return (status);
}

/*
 * FileFsControlInformation
 */
uint32_t
smb2_setfs_control(smb_request_t *sr, smb_setinfo_t *si)
{
	_NOTE(ARGUNUSED(si))
	smb_tree_t *tree = sr->tid_tree;

	if (!STYPE_ISDSK(tree->t_res_type))
		return (NT_STATUS_INVALID_PARAMETER);

	return (0);
}

/*
 * FileFsObjectIdInformation
 */
/* ARGSUSED */
uint32_t
smb2_setfs_obj_id(smb_request_t *sr, smb_setinfo_t *si)
{
	/*
	 * Return an error per. [MS-FSCC 2.5.7]
	 * which means we can't change object IDs.
	 */
	return (NT_STATUS_INVALID_PARAMETER);
}
