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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	char *argp, *rbufp;
	size_t arg_size, rbuf_size;
	smb_token_t *token = NULL;

	argp = smb_dr_encode_arg_get_token(clnt_info, &arg_size);
	rbufp = smb_kdoor_clnt_upcall(argp, arg_size, NULL, 0, &rbuf_size);
	if (rbufp)
		token = smb_dr_decode_res_token(rbufp + SMB_DR_DATA_OFFSET,
		    rbuf_size - SMB_DR_DATA_OFFSET);

	smb_kdoor_clnt_free(argp, arg_size, rbufp, rbuf_size);
	return (token);

}

int
smb_upcall_set_dwncall_desc(uint32_t opcode, door_desc_t *dp, uint_t n_desc)
{
	char *argp, *rbufp;
	size_t arg_size, rbuf_size;

	argp = smb_dr_set_opcode(opcode, &arg_size);
	if (argp == NULL) {
		return (SMB_DR_OP_ERR_ENCODE);
	}

	rbufp = smb_kdoor_clnt_upcall(argp, arg_size, dp, n_desc, &rbuf_size);
	if (rbufp == NULL) {
		return (SMB_DR_OP_ERR);
	}

	smb_kdoor_clnt_free(argp, arg_size, rbufp, rbuf_size);

	return (SMB_DR_OP_SUCCESS);
}
