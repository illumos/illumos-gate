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
 * SMB: trans2_create_directory
 *
 * This requests the server to create a directory relative to Tid in the
 * SMB header, optionally assigning extended attributes to it.
 *
 *  Client Request             Value
 *  ========================== =========================================
 *
 *  WordCount                  15
 *  MaxSetupCount              0
 *  SetupCount                 1
 *  Setup[0]                   TRANS2_CREATE_DIRECTORY
 *
 *  Parameter Block Encoding   Description
 *  ========================== =========================================
 *
 *  ULONG Reserved;            Reserved--must be zero
 *  STRING Name[];             Directory name to create
 *  UCHAR Data[];              Optional FEAList for the new directory
 *
 *  Response Parameter Block   Description
 *  ========================== =========================================
 *
 *  USHORT EaErrorOffset       Offset into FEAList of first error which
 *                             occurred while setting EAs
 */

#include <smbsrv/nterror.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/smb_incl.h>


/*
 * smb_com_trans2_create_directory
 */
smb_sdrc_t
smb_com_trans2_create_directory(struct smb_request *sr, struct smb_xa *xa)
{
	int	rc;
	DWORD	status;

	if (!STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	if (smb_decode_mbc(&xa->req_param_mb, "%4.s",
	    sr, &sr->arg.dirop.fqi.path) != 0) {
		return (SDRC_ERROR);
	}

	if ((status = smb_validate_dirname(sr->arg.dirop.fqi.path)) != 0) {
		smbsr_error(sr, status, ERRDOS, ERROR_INVALID_NAME);
		return (SDRC_ERROR);
	}

	if ((rc = smb_common_create_directory(sr)) != 0) {
		smbsr_errno(sr, rc);
		return (SDRC_ERROR);
	}

	if (smb_encode_mbc(&xa->rep_param_mb, "w", 0) < 0)
		return (SDRC_ERROR);

	return (SDRC_SUCCESS);
}
