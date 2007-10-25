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

/*
 * SMBd door operations
 */
#include <stdlib.h>
#include <synch.h>
#include <strings.h>
#include <smbsrv/smb_common_door.h>
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

static char *smb_dop_group_add(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_delete(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_member_add(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_member_remove(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_count(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_cachesize(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_modify(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_priv_num(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_priv_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_priv_get(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_priv_set(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_member_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_group_member_count(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

/* SMB daemon's door operation table */
smb_dr_op_t smb_doorsrv_optab[] =
{
	smb_dop_user_auth_logon,
	smb_dop_set_dwncall_desc,
	smb_dop_user_nonauth_logon,
	smb_dop_user_auth_logoff,
	smb_dop_user_list,
	smb_dop_group_add,
	smb_dop_group_delete,
	smb_dop_group_member_add,
	smb_dop_group_member_remove,
	smb_dop_group_count,
	smb_dop_group_cachesize,
	smb_dop_group_modify,
	smb_dop_group_priv_num,
	smb_dop_group_priv_list,
	smb_dop_group_priv_get,
	smb_dop_group_priv_set,
	smb_dop_group_list,
	smb_dop_group_member_list,
	smb_dop_group_member_count
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
		syslog(LOG_ERR, "smbd: clnt_info is NULL");
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	token = smbd_user_auth_logon(clnt_info);

	free(clnt_info);

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

/* NT Group door operations start from here */
/*ARGSUSED*/
static char *
smb_dop_group_add(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_add: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	ntstatus = nt_group_add(args->gname, args->desc);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &ntstatus,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_delete(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *gname = NULL;
	char *rbuf = NULL;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((gname = smb_dr_decode_string(argp, arg_size)) == 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	ntstatus = nt_group_delete(gname);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &ntstatus,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_member_add(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	nt_group_t *grp = NULL;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_member_add: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	grp = nt_group_getinfo(args->gname, RWLOCK_WRITER);
	if (grp) {
		ntstatus = nt_group_add_member_byname(args->gname,
		    args->member);
	} else {
		ntstatus = NT_STATUS_NO_SUCH_GROUP;
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &ntstatus,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_member_remove(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	nt_group_t *grp = NULL;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_member_add: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	grp = nt_group_getinfo(args->gname, RWLOCK_WRITER);
	if (grp) {
		ntstatus = nt_group_del_member_byname(grp, args->member);
	} else {
		ntstatus = NT_STATUS_NO_SUCH_GROUP;
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &ntstatus,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_count(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	int num = 0;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	num = nt_group_num_groups();

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &num,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_cachesize(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	int num = 0;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	num = nt_group_cache_size();

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &num,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_modify(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	nt_group_t *grp = NULL;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_modify: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	grp = nt_group_getinfo(args->gname, RWLOCK_WRITER);
	if (grp) {
		if (!args->desc)
			args->desc = grp->comment;
		ntstatus = nt_group_modify(args->gname,
		    args->newgname, args->desc);
	} else {
		ntstatus = NT_STATUS_NO_SUCH_GROUP;
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &ntstatus,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_priv_num(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	int num = 0;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	num = smb_priv_presentable_num();

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &num,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_priv_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	int num = 0, i, len = 0;
	uint32_t *ids = NULL;
	smb_privinfo_t *priv = NULL;
	ntpriv_list_t *list;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	num = smb_priv_presentable_num();
	if (num > 0) {
		len = sizeof (int) + (num * sizeof (privs_t *));
		if ((ids = malloc(num * sizeof (uint32_t))) == 0) {
			syslog(LOG_ERR, "smb_dop_group_priv_list:"
			    "cannot allocate memory");
			*err = SMB_DR_OP_ERR;
			return (NULL);
		}

		if ((list = (ntpriv_list_t *)malloc(len)) == 0) {
			syslog(LOG_ERR, "smb_dop_group_priv_list:"
			    "cannot allocate memory");
			*err = SMB_DR_OP_ERR;
			free(ids);
			return (NULL);
		}

		list->cnt = num;
		(void) smb_priv_presentable_ids(ids, num);
		for (i = 0; i < num; i++) {
			if ((list->privs[i] = malloc(sizeof (ntpriv_t))) == 0) {
				*err = SMB_DR_OP_ERR;
				free(ids);
				smb_group_free_privlist(list, 1);
				return (NULL);
			}
			bzero(list->privs[i], sizeof (ntpriv_t));
			priv = smb_priv_getbyvalue(ids[i]);
			list->privs[i]->id = priv->id;
			list->privs[i]->name = strdup(priv->name);
		}
		free(ids);
	}

	if ((rbuf = smb_dr_encode_grp_privlist(SMB_DR_OP_SUCCESS, list,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	smb_group_free_privlist(list, 1);

	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_priv_get(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	uint32_t priv_attr;
	nt_group_t *grp;
	uint32_t retval;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_priv_get: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	grp = nt_group_getinfo(args->gname, RWLOCK_READER);
	if (grp) {
		priv_attr = nt_group_getpriv(grp, args->privid);
		retval = priv_attr;
	} else {
		retval = NT_STATUS_NO_SUCH_GROUP;
		*err = SMB_DR_OP_ERR;
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &retval,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_priv_set(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;
	nt_group_t *grp;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_priv_set: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	grp = nt_group_getinfo(args->gname, RWLOCK_WRITER);
	if (grp) {
		ntstatus = nt_group_setpriv(grp,
		    args->privid, args->priv_attr);
	} else {
		ntstatus = NT_STATUS_NO_SUCH_GROUP;
		*err = SMB_DR_OP_ERR;
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &ntstatus,
	    xdr_uint32_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL, *scope = NULL;
	ntgrp_dr_arg_t *args;
	ntgrp_list_t list;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_list: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	bzero(&list, sizeof (ntgrp_list_t));
	scope = args->scope;
	if (scope == NULL)
		scope = "*";
	nt_group_list(args->offset, scope, &list);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_grp_list(SMB_DR_OP_SUCCESS, &list,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	smb_group_free_list(&list, 1);
	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_member_list(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	ntgrp_dr_arg_t *args;
	nt_group_t *grp = NULL;
	ntgrp_member_list_t members;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((args = (ntgrp_dr_arg_t *)malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_group_dr_listmember: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(args, sizeof (ntgrp_dr_arg_t));
	if (smb_dr_decode_common(argp, arg_size,
	    xdr_ntgrp_dr_arg_t, args) != 0) {
		free(args);
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	bzero(&members, sizeof (ntgrp_member_list_t));
	bzero(&members.members, SMB_GROUP_PER_LIST * sizeof (members_list));
	if ((!args->gname) || (strlen(args->gname) == 0)) {
		free(args);
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	grp = nt_group_getinfo(args->gname, RWLOCK_READER);
	if (grp) {
		(void) nt_group_member_list(args->offset, grp, &members);
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_grp_memberlist(SMB_DR_OP_SUCCESS, &members,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	smb_group_free_memberlist(&members, 1);
	free(args);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_group_member_count(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL, *gname = NULL;
	ntgrp_dr_arg_t *enc_args;
	nt_group_t *grp = NULL;
	int num = 0;
	uint32_t ntstatus = NT_STATUS_UNSUCCESSFUL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((gname = smb_dr_decode_string(argp, arg_size)) == 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	grp = nt_group_getinfo(gname, RWLOCK_READER);
	if (grp) {
		num = nt_group_num_members(grp);
		ntstatus = NT_STATUS_SUCCESS;
	} else {
		ntstatus = NT_STATUS_NO_SUCH_GROUP;
	}
	nt_group_putinfo(grp);

	/* Encode the result and return */
	if ((enc_args = (ntgrp_dr_arg_t *)
	    malloc(sizeof (ntgrp_dr_arg_t))) == 0) {
		syslog(LOG_ERR,
		    "smb_dop_group_member_count: cannot allocate memory");
		*err = SMB_DR_OP_ERR;
		return (NULL);
	}
	bzero(enc_args, sizeof (ntgrp_dr_arg_t));
	enc_args->count = num;
	enc_args->ntstatus = ntstatus;
	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, enc_args,
	    xdr_ntgrp_dr_arg_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	free(enc_args);
	return (rbuf);
}
