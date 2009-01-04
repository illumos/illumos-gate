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

/*
 * This returns the number of snapshots for the dataset
 * of the path provided.
 */
uint32_t
smb_upcall_vss_get_count(char *resource_path)
{
	char *argp, *rsp;
	size_t arg_size, rsp_size;
	uint32_t count = 0;

	arg_size = strlen(resource_path);

	argp = smb_dr_encode_string(SMB_DR_VSS_GET_COUNT, resource_path,
	    &arg_size);

	rsp = smb_kdoor_clnt_upcall(argp, arg_size, NULL, 0, &rsp_size);

	if (rsp) {
		if (smb_kdr_decode_common((rsp + SMB_DR_DATA_OFFSET),
		    (rsp_size - SMB_DR_DATA_OFFSET), xdr_uint32_t, &count)
		    != 0) {
			count = 0;
		}
	}

	smb_kdoor_clnt_free(argp, arg_size, rsp, rsp_size);
	return (count);
}

/*
 * This take a path for the root of the dataset and
 * gets the counts of snapshots for that dataset and the
 * list of @GMT tokens(one for each snapshot) up to the
 * count provided.
 * Need to call smb_upcall_vss_get_snapshots_free after
 * to free up the data
 */
void
smb_upcall_vss_get_snapshots(char *resource_path, uint32_t count,
    smb_dr_return_gmttokens_t *gmttokens)
{
	char *argp, *rbufp;
	size_t  rbuf_size;
	size_t arg_size;
	smb_dr_get_gmttokens_t request;

	request.gg_count = count;
	request.gg_path = resource_path;
	bzero(gmttokens, sizeof (smb_dr_return_gmttokens_t));

	argp = smb_kdr_encode_common(SMB_DR_VSS_GET_SNAPSHOTS, &request,
	    xdr_smb_dr_get_gmttokens_t, &arg_size);

	rbufp = smb_kdoor_clnt_upcall(argp, arg_size, NULL, 0, &rbuf_size);

	if (rbufp != NULL) {
		(void) smb_kdr_decode_common((rbufp + SMB_DR_DATA_OFFSET),
		    (rbuf_size - SMB_DR_DATA_OFFSET),
		    xdr_smb_dr_return_gmttokens_t, gmttokens);
	}

	smb_kdoor_clnt_free(argp, arg_size, rbufp, rbuf_size);
}

void
smb_upcall_vss_get_snapshots_free(smb_dr_return_gmttokens_t *reply)
{
	xdr_free(xdr_smb_dr_return_gmttokens_t, (char *)reply);
}


/*
 * Returns the snapshot name for the @GMT token provided
 * for the dataset of the path.
 * If the snapshot can not be found, a string with a NULL
 * is returned.
 */
void
smb_upcall_vss_map_gmttoken(char *path, char *gmttoken,
    char *snapname)
{
	char *argp, *rbufp;
	size_t arg_size, rbuf_size;
	smb_dr_string_t res;
	smb_dr_map_gmttoken_t request;

	bzero(&res, sizeof (smb_dr_string_t));

	request.mg_path = path;
	request.mg_gmttoken = gmttoken;

	argp = smb_kdr_encode_common(SMB_DR_VSS_MAP_GMTTOKEN, &request,
	    xdr_smb_dr_map_gmttoken_t, &arg_size);

	if (argp == NULL) {
		return;
	}

	rbufp = smb_kdoor_clnt_upcall(argp, arg_size, NULL, 0, &rbuf_size);

	if (rbufp != NULL) {
		res.buf = snapname;

		/* a snapname set to '\0' means that there was no match */
		(void) smb_kdr_decode_common((rbufp + SMB_DR_DATA_OFFSET),
		    (rbuf_size - SMB_DR_DATA_OFFSET), xdr_smb_dr_string_t,
		    &res);
	}

	smb_kdoor_clnt_free(argp, arg_size, rbufp, rbuf_size);
}
