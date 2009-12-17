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

/*
 * SMBd door operations
 */
#include <stdlib.h>
#include <synch.h>
#include <strings.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/libsmbns.h>
#include "smbd.h"

static char *smb_dop_user_auth_logon(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_user_nonauth_logon(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_user_auth_logoff(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

static char *smb_dop_lookup_sid(char *, size_t, door_desc_t *, uint_t,
    size_t *, int *);
static char *smb_dop_lookup_name(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_join(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_get_dcinfo(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

static char *smb_dop_vss_get_count(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_vss_get_snapshots(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_vss_map_gmttoken(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);
static char *smb_dop_ads_find_host(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err);

/* SMB daemon's door operation table */
smb_dr_op_t smb_doorsrv_optab[] =
{
	smb_dop_user_auth_logon,	/* SMB_DR_USER_AUTH_LOGON */
	smb_dop_user_nonauth_logon,	/* SMB_DR_USER_NONAUTH_LOGON */
	smb_dop_user_auth_logoff,	/* SMB_DR_USER_AUTH_LOGOFF */
	smb_dop_lookup_sid,		/* SMB_DR_LOOKUP_SID */
	smb_dop_lookup_name,		/* SMB_DR_LOOKUP_NAME */
	smb_dop_join,			/* SMB_DR_JOIN */
	smb_dop_get_dcinfo,		/* SMB_DR_GET_DCINFO */
	smb_dop_vss_get_count,		/* SMB_DR_VSS_GET_COUNT */
	smb_dop_vss_get_snapshots,	/* SMB_DR_VSS_GET_SNAPSHOTS */
	smb_dop_vss_map_gmttoken,	/* SMB_DR_VSS_MAP_GMTTOKEN */
	smb_dop_ads_find_host		/* SMB_DR_ADS_FIND_HOST */
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

/*ARGSUSED*/
static char *
smb_dop_lookup_name(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	smb_domain_t	dinfo;
	smb_account_t	ainfo;
	lsa_account_t	acct;
	char		buf[MAXNAMELEN];
	char		*rbuf = NULL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	if (smb_dr_decode_common(argp, arg_size, lsa_account_xdr, &acct) != 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	if (*acct.a_domain == '\0')
		(void) snprintf(buf, MAXNAMELEN, "%s", acct.a_name);
	else if (strchr(acct.a_domain, '.') != NULL)
		(void) snprintf(buf, MAXNAMELEN, "%s@%s", acct.a_name,
		    acct.a_domain);
	else
		(void) snprintf(buf, MAXNAMELEN, "%s\\%s", acct.a_domain,
		    acct.a_name);

	acct.a_status = lsa_lookup_name(buf, acct.a_sidtype, &ainfo);
	if (acct.a_status == NT_STATUS_SUCCESS) {
		acct.a_sidtype = ainfo.a_type;
		smb_sid_tostr(ainfo.a_sid, acct.a_sid);
		(void) strlcpy(acct.a_name, ainfo.a_name, MAXNAMELEN);

		if (smb_domain_lookup_name(ainfo.a_domain, &dinfo))
			(void) strlcpy(acct.a_domain, dinfo.di_fqname,
			    MAXNAMELEN);
		else
			(void) strlcpy(acct.a_domain, ainfo.a_domain,
			    MAXNAMELEN);
		smb_account_free(&ainfo);
	}

	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &acct,
	    lsa_account_xdr, rbufsize)) == NULL) {
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
	smb_domain_t	dinfo;
	smb_account_t	ainfo;
	lsa_account_t	acct;
	smb_sid_t	*sid;
	char		*rbuf = NULL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	if (smb_dr_decode_common(argp, arg_size, lsa_account_xdr, &acct) != 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	sid = smb_sid_fromstr(acct.a_sid);
	acct.a_status = lsa_lookup_sid(sid, &ainfo);
	smb_sid_free(sid);

	if (acct.a_status == NT_STATUS_SUCCESS) {
		acct.a_sidtype = ainfo.a_type;
		smb_sid_tostr(ainfo.a_sid, acct.a_sid);
		(void) strlcpy(acct.a_name, ainfo.a_name, MAXNAMELEN);

		if (smb_domain_lookup_name(ainfo.a_domain, &dinfo))
			(void) strlcpy(acct.a_domain, dinfo.di_fqname,
			    MAXNAMELEN);
		else
			(void) strlcpy(acct.a_domain, ainfo.a_domain,
			    MAXNAMELEN);

		smb_account_free(&ainfo);
	}

	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &acct,
	    lsa_account_xdr, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

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

/*ARGSUSED*/
static char *
smb_dop_get_dcinfo(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	smb_domainex_t dxi;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	if (!smb_domain_getinfo(&dxi)) {
		*err = SMB_DR_OP_ERR_EMPTYBUF;
		return (NULL);
	}

	if ((rbuf = smb_dr_encode_string(SMB_DR_OP_SUCCESS, dxi.d_dc,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}
	return (rbuf);
}

/*
 * This routine returns the number of snapshots for a dataset
 */

/*ARGSUSED*/
static char *
smb_dop_vss_get_count(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	uint32_t count;
	char *path;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	if ((path = smb_dr_decode_string(argp, arg_size)) == NULL) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	if (smbd_vss_get_count(path, &count) == 0) {
		if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &count,
		    xdr_uint32_t, rbufsize)) == NULL) {
			*err = SMB_DR_OP_ERR_ENCODE;
		}
	}

	xdr_free(xdr_string, (char *)&path);

	return (rbuf);
}

/*
 * This routine returns the count and list of snapshots.
 * The list is in the Microsoft @GMT token format.
 */
/*ARGSUSED*/
static char *
smb_dop_vss_get_snapshots(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL, **gmtp;
	smb_dr_get_gmttokens_t request;
	smb_dr_return_gmttokens_t reply;
	uint_t i;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;
	bzero(&request, sizeof (smb_dr_get_gmttokens_t));
	bzero(&reply, sizeof (smb_dr_return_gmttokens_t));

	if (smb_dr_decode_common(argp, arg_size,
	    xdr_smb_dr_get_gmttokens_t, &request) != 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	reply.rg_gmttokens.rg_gmttokens_val = malloc(request.gg_count *
	    sizeof (char *));
	bzero(reply.rg_gmttokens.rg_gmttokens_val, request.gg_count *
	    sizeof (char *));

	if (reply.rg_gmttokens.rg_gmttokens_val == NULL) {
		xdr_free(xdr_smb_dr_get_gmttokens_t, (char *)&request);
		return (NULL);
	}

	smbd_vss_get_snapshots(request.gg_path, request.gg_count,
	    &reply.rg_count,
	    &reply.rg_gmttokens.rg_gmttokens_len,
	    reply.rg_gmttokens.rg_gmttokens_val);

	if ((rbuf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &reply,
	    xdr_smb_dr_return_gmttokens_t, rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
	}

	for (i = 0, gmtp = reply.rg_gmttokens.rg_gmttokens_val;
	    (i < request.gg_count); i++) {
		if (*gmtp)
			free(*gmtp);
		gmtp++;
	}
	free(reply.rg_gmttokens.rg_gmttokens_val);
	xdr_free(xdr_smb_dr_get_gmttokens_t, (char *)&request);
	return (rbuf);
}

/*
 * This routine returns the snapshot name of the snapshot
 * that matches path of the pathname of the dataset and
 * the @GMT token.
 */

/*ARGSUSED*/
static char *
smb_dop_vss_map_gmttoken(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	char *rbuf = NULL;
	char *snapname;
	smb_dr_map_gmttoken_t request;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;
	bzero(&request, sizeof (smb_dr_map_gmttoken_t));

	if (smb_dr_decode_common(argp, arg_size, xdr_smb_dr_map_gmttoken_t,
	    &request) != 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		xdr_free(xdr_smb_dr_map_gmttoken_t, (char *)&request);
		return (NULL);
	}

	snapname = (char *)malloc(MAXPATHLEN);

	if (snapname == NULL) {
		xdr_free(xdr_smb_dr_map_gmttoken_t, (char *)&request);
		return (NULL);
	}

	if ((smbd_vss_map_gmttoken(request.mg_path, request.mg_gmttoken,
	    snapname) != 0)) {
		*snapname = '\0';
	}

	rbuf = smb_dr_encode_string(SMB_DR_OP_SUCCESS, snapname, rbufsize);

	if (rbuf == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	xdr_free(xdr_smb_dr_map_gmttoken_t, (char *)&request);
	free(snapname);
	return (rbuf);
}

/*ARGSUSED*/
static char *
smb_dop_ads_find_host(char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_desc, size_t *rbufsize, int *err)
{
	smb_ads_host_info_t *hinfo = NULL;
	char *hostname;
	char *fqdn = NULL;
	char *rbuf = NULL;

	*err = SMB_DR_OP_SUCCESS;
	*rbufsize = 0;

	/* Decode */
	if ((fqdn = smb_dr_decode_string(argp, arg_size)) == 0) {
		*err = SMB_DR_OP_ERR_DECODE;
		return (NULL);
	}

	if ((hinfo = smb_ads_find_host(fqdn, NULL)) == NULL)
		hostname = "";
	else
		hostname = hinfo->name;

	xdr_free(xdr_string, (char *)&fqdn);

	/* Encode the result and return */
	if ((rbuf = smb_dr_encode_string(SMB_DR_OP_SUCCESS, hostname,
	    rbufsize)) == NULL) {
		*err = SMB_DR_OP_ERR_ENCODE;
		*rbufsize = 0;
	}

	free(hinfo);
	return (rbuf);
}
