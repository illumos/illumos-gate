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

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smb_vops.h>
#include <sys/stat.h>


void
smb_user_nonauth_logon(uint32_t audit_sid)
{
	char *arg, *rsp;
	size_t arg_size, rsp_size;

	arg = smb_kdr_encode_common(SMB_DR_USER_NONAUTH_LOGON,
	    &audit_sid, xdr_uint32_t, &arg_size);

	if (arg != NULL) {
		rsp = smb_kdoor_clnt_upcall(arg, arg_size, NULL, 0, &rsp_size);
		smb_kdoor_clnt_free(arg, arg_size, rsp, rsp_size);
	}
}

void
smb_user_auth_logoff(uint32_t audit_sid)
{
	char *arg, *rsp;
	size_t arg_size, rsp_size;

	arg = smb_kdr_encode_common(SMB_DR_USER_AUTH_LOGOFF,
	    &audit_sid, xdr_uint32_t, &arg_size);

	if (arg != NULL) {
		rsp = smb_kdoor_clnt_upcall(arg, arg_size, NULL, 0, &rsp_size);
		smb_kdoor_clnt_free(arg, arg_size, rsp, rsp_size);
	}
}

smb_token_t *
smb_upcall_get_token(netr_client_t *clnt_info)
{
	char *arg, *rsp;
	size_t arg_size, rsp_size;
	smb_token_t *token = NULL;

	if ((arg = smb_dr_encode_arg_get_token(clnt_info, &arg_size)) == NULL)
		return (NULL);

	rsp = smb_kdoor_clnt_upcall(arg, arg_size, NULL, 0, &rsp_size);
	if (rsp) {
		token = smb_dr_decode_res_token(rsp + SMB_DR_DATA_OFFSET,
		    rsp_size - SMB_DR_DATA_OFFSET);
	}

	smb_kdoor_clnt_free(arg, arg_size, rsp, rsp_size);
	return (token);

}

int
smb_set_downcall_desc(door_desc_t *dp, uint_t n_desc)
{
	char *arg, *rsp;
	size_t arg_size, rsp_size;

	arg = smb_dr_set_opcode(SMB_DR_SET_DWNCALL_DESC, &arg_size);
	if (arg == NULL)
		return (-1);

	rsp = smb_kdoor_clnt_upcall(arg, arg_size, dp, n_desc, &rsp_size);

	smb_kdoor_clnt_free(arg, arg_size, rsp, rsp_size);
	return ((rsp == NULL) ? -1 : 0);
}
