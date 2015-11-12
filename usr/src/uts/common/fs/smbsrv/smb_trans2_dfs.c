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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_kproto.h>
#include <smbsrv/winioctl.h>

/*
 * [MS-CIFS]
 *
 * 2.2.6.17    TRANS2_REPORT_DFS_INCONSISTENCY (0x0011)
 *
 *  This Transaction2 subcommand was introduced in the NT LAN Manager dialect.
 *  This subcommand is reserved but not implemented.
 *
 *  Clients SHOULD NOT send requests using this command code. Servers receiving
 *  requests with this command code SHOULD return STATUS_NOT_IMPLEMENTED
 *  (ERRDOS/ERRbadfunc).
 */
smb_sdrc_t /*ARGSUSED*/
smb_com_trans2_report_dfs_inconsistency(smb_request_t *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}

/*
 * See [MS-DFSC] for details about this command
 */
smb_sdrc_t
smb_com_trans2_get_dfs_referral(smb_request_t *sr, smb_xa_t *xa)
{
	smb_fsctl_t fsctl;
	uint32_t status;
	uint16_t doserr;

	/* This request is only valid over IPC connections */
	if (!STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRDOS,
		    ERROR_ACCESS_DENIED);
		return (SDRC_ERROR);
	}

	fsctl.CtlCode = FSCTL_DFS_GET_REFERRALS;
	fsctl.InputCount = xa->smb_tpscnt;
	fsctl.OutputCount = 0;
	fsctl.MaxOutputResp = xa->smb_mdrcnt;
	fsctl.in_mbc = &xa->req_param_mb;
	fsctl.out_mbc = &xa->rep_data_mb;

	status = smb_dfs_get_referrals(sr, &fsctl);

	/* Out param is the API-level return code. */
	doserr = smb_status2doserr(status);
	(void) smb_mbc_encodef(&xa->rep_param_mb, "w", doserr);

#if 0	/* XXX - Is API-level return code enough? */
	if (status) {
		smbsr_error(sr, NT_STATUS_NO_SUCH_DEVICE, 0, 0);
		return (SDRC_ERROR);
	}
#endif

	return (SDRC_SUCCESS);
}
