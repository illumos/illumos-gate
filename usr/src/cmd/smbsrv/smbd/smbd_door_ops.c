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
 * SMBd door operations
 */
#include <stdlib.h>
#include <synch.h>
#include <strings.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/libmlsvc.h>
#include "smbd.h"

static int smb_set_downcall_desc(int desc);
static int smb_get_downcall_desc(void);

static char *smb_dop_set_dwncall_desc(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_user_auth_logon(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_user_nonauth_logon(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_user_auth_logoff(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

static char *smb_dop_user_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

static char *smb_dop_lookup_sid(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_lookup_name(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_join(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

/* SMB daemon's door operation table */
smb_dr_op_t smb_doorsrv_optab[] =
{
	smb_dop_user_auth_logon,
	smb_dop_set_dwncall_desc,
	smb_dop_user_nonauth_logon,
	smb_dop_user_auth_logoff,
	smb_dop_user_list,
	smb_dop_lookup_sid,
	smb_dop_lookup_name,
	smb_dop_join,
};

/*ARGSUSED*/
static char *
smb_dop_user_nonauth_logon(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc, size_t *rbufsize, int *err)
{
	char *buf;
	uint32_t sid;

	if (smb_dr_decode_common(argp, arg_size, xdr_uint32_t, &sid) != 0) {
		*rbufsize = 0;
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	smbd_user_nonauth_logon(sid);

	if ((buf = smb_dr_set_res_stat(SMB_DR_OP_SUCCESS, rbufsize)) == NULL) {
		*rbufsize = 0;
		*err = SMB_DR_OP_ERR_ENCODE;
		return (NULL);
	}

	*err = SMB_DR_OP_SUCCESS;
	return (buf);
}

/*ARGSUSED*/
static char *
smb_dop_user_auth_logoff(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc, size_t *rbufsize, int *err)
{
	char *buf;
	uint32_t sid;

	if (smb_dr_decode_common(argp, arg_size, xdr_uint32_t, &sid) != 0) {
		*rbufsize = 0;
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	smbd_user_auth_logoff(sid);

	if ((buf = smb_dr_set_res_stat(SMB_DR_OP_SUCCESS, rbufsize)) == NULL) {
		*rbufsize = 0;
		*err = SMB_DR_OP_ERR_ENCODE;
		return (NULL);
	}

	*err = SMB_DR_OP_SUCCESS;
	return (buf);
}

/*
 * smb_downcall_desc
 *
 * This downcall descriptor will be initialized when the SMB Kmod
 * makes a upcall for the SMBD_DOOR_SET_DOWNCALL_DESC.
 * This descriptor should be passed as the 1st argument to the
 * door_call() whenever the SMBD is making a downcall to SMB Kmod.
 */
static int smb_downcall_desc = -1;
static mutex_t smb_downcall_mutex;

/*
 * Get and set the smb downcall descriptor.
 */
static int
smb_set_downcall_desc(int desc)
{
	(void) mutex_lock(&smb_downcall_mutex);
	smb_downcall_desc = desc;
	(void) mutex_unlock(&smb_downcall_mutex);
	return (0);
}

/*
 * smb_get_downcall_desc
 *
 * Returns the downcall descriptor.
 */
static int
smb_get_downcall_desc(void)
{
	int rc;

	(void) mutex_lock(&smb_downcall_mutex);
	rc = smb_downcall_desc;
	(void) mutex_unlock(&smb_downcall_mutex);
	return (rc);
}

/*
 * smb_dr_is_valid_opcode
 *
 * Validates the given door opcode.
 */
int
smb_dr_is_valid_opcode(int opcode)
{
	if (opcode < 0 ||
	    opcode > (sizeof (smb_doorsrv_optab) / sizeof (smb_dr_op_t)))
		return (-1);
	else
		return (0);
}

/*
 * Obtains an access token on successful user authentication.
 */
/*ARGSUSED*/
static char *
smb_dop_user_auth_logon(char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc, size_t *rbufsize, int *err)
{
	netr_client_t *clnt_info;
	smb_token_t *token;
	char *buf;

	*rbufsize = 0;
	*err = 0;
	clnt_info = smb_dr_decode_arg_get_token(argp, arg_size);
	if (clnt_info == NULL) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	token = smbd_user_auth_logon(clnt_info);

	netr_client_xfree(clnt_info);

	if (!token) {
		*err = SMB_DR_OP_ERR_EMPTYBUF;
		return (NULL);
	}

	if ((buf = smb_dr_encode_res_token(token, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
	}

	smb_token_destroy(token);
	return (buf);
}

/*
 * smb_dop_set_dwncall_desc
 *
 * Set the downcall descriptor.
 */
/*ARGSUSED*/
static char *
smb_dop_set_dwncall_desc(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *buf = NULL;
	uint32_t stat;

	*rbufsize = 0;
	*err = 0;

	if (n_desc != 1 ||
	    smb_set_downcall_desc(dp->d_data.d_desc.d_descriptor) != 0) {
		stat = SMB_DR_OP_ERR;
	} else {
		/* install get downcall descriptor callback */
		(void) smb_dwncall_install_callback(smb_get_downcall_desc);
		stat = SMB_DR_OP_SUCCESS;
	}
	if ((buf = smb_dr_set_res_stat(stat, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	return (buf);
}

/*
 * smb_dr_op_users
 *
 * This function will obtain information on the connected users
 * starting at the given offset by making a door down-call. The
 * information will then be returned to the user-space door client.
 *
 * At most 50 users (i.e. SMB_DR_MAX_USER) will be returned via this
 * function. The user-space door client might need to make multiple
 * calls to retrieve information on all connected users.
 */
/*ARGSUSED*/
char *
smb_dop_user_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	smb_dr_ulist_t *ulist;
	uint32_t offset;
	char *rbuf = NULL;
	int cnt = 0;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;
	if (smb_dr_decode_common(argp, arg_size, xdr_uint32_t, &offset) != 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	ulist = malloc(sizeof (smb_dr_ulist_t));
	if (!ulist) {
		*err = SMB_DR_OP_ERR_EMPTYBUF;
		return (NULL);
	}

	cnt = smb_dwncall_get_users(offset, ulist);
	if (cnt < 0) {
		*err = SMB_DR_OP_ERR_EMPTYBUF;
		free(ulist);
		return (NULL);
	}

	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, ulist,
	    xdr_smb_dr_ulist_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	smb_dr_ulist_free(ulist);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_lookup_name(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	char *name = NULL;
	uint32_t status;
	smb_sid_t *sid;
	uint16_t sid_type;
	char strsid[SMB_SID_STRSZ];
	char strres[SMB_SID_STRSZ];

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((name = smb_dr_decode_string(argp, arg_size)) == 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	*strres = '\0';
	sid_type = SidTypeUnknown;
	status = mlsvc_lookup_name(name, &sid, &sid_type);
	xdr_free(xdr_string, (char *)&name);
	if (status == NT_STATUS_SUCCESS) {
		/* pack the SID and its type in a string */
		smb_sid_tostr(sid, strsid);
		(void) snprintf(strres, sizeof (strres), "%d-%s",
		    sid_type, strsid);
		free(sid);
	}

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_string(SMB_DR_OP_SUCCESS, strres,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_lookup_sid(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	char *name = NULL;
	uint32_t status;
	smb_sid_t *sid;
	char *strsid;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((strsid = smb_dr_decode_string(argp, arg_size)) == 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	sid = smb_sid_fromstr(strsid);
	status = mlsvc_lookup_sid(sid, &name);
	free(sid);
	if (status != NT_STATUS_SUCCESS)
		name = strsid;

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_string(SMB_DR_OP_SUCCESS, name,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	if (status == NT_STATUS_SUCCESS)
		free(name);

	xdr_free(xdr_string, (char *)&strsid);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_join(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	smb_joininfo_t jdi;
	uint32_t status;
	char *rbuf = NULL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	if (smb_dr_decode_common(argp, arg_size, xdr_smb_dr_joininfo_t, &jdi)
	    != 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	status = smbd_join(&jdi);

	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &status,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	return (rbuf);
}
