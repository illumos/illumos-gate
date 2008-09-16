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

#pragma ident	"@(#)secdb.c	1.5	08/07/08 SMI"

/*
 * Security database interface.
 */
#include <unistd.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <syslog.h>
#include <assert.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/lsalib.h>

extern uint32_t netlogon_logon(netr_client_t *clnt, smb_userinfo_t *uinfo);
static uint32_t smb_logon_domain(netr_client_t *clnt, smb_userinfo_t *uinfo);
static uint32_t smb_logon_local(netr_client_t *clnt, smb_userinfo_t *uinfo);
static uint32_t smb_logon_none(netr_client_t *clnt, smb_userinfo_t *uinfo);

static uint32_t smb_setup_luinfo(smb_userinfo_t *, netr_client_t *, uid_t);

static int smb_token_is_member(smb_token_t *token, smb_sid_t *sid);
static int smb_token_is_valid(smb_token_t *token);
static smb_win_grps_t *smb_token_create_wingrps(smb_userinfo_t *user_info);

static smb_posix_grps_t *smb_token_create_pxgrps(uid_t uid);

/* Consolidation private function from Network Repository */
extern int _getgroupsbymember(const char *, gid_t[], int, int);

static idmap_stat
smb_token_idmap(smb_token_t *token, smb_idmap_batch_t *sib)
{
	idmap_stat stat;
	smb_idmap_t *sim;
	smb_id_t *id;
	int i;

	if (!token || !sib)
		return (IDMAP_ERR_ARG);

	sim = sib->sib_maps;

	if (token->tkn_flags & SMB_ATF_ANON) {
		token->tkn_user->i_id = UID_NOBODY;
		token->tkn_owner->i_id = UID_NOBODY;
	} else {
		/* User SID */
		id = token->tkn_user;
		sim->sim_id = &id->i_id;
		stat = smb_idmap_batch_getid(sib->sib_idmaph, sim++,
		    id->i_sidattr.sid, SMB_IDMAP_USER);

		if (stat != IDMAP_SUCCESS)
			return (stat);

		/* Owner SID */
		id = token->tkn_owner;
		sim->sim_id = &id->i_id;
		stat = smb_idmap_batch_getid(sib->sib_idmaph, sim++,
		    id->i_sidattr.sid, SMB_IDMAP_USER);

		if (stat != IDMAP_SUCCESS)
			return (stat);
	}

	/* Primary Group SID */
	id = token->tkn_primary_grp;
	sim->sim_id = &id->i_id;
	stat = smb_idmap_batch_getid(sib->sib_idmaph, sim++,
	    id->i_sidattr.sid, SMB_IDMAP_GROUP);

	if (stat != IDMAP_SUCCESS)
		return (stat);

	/* Other Windows Group SIDs */
	for (i = 0; i < token->tkn_win_grps->wg_count; i++, sim++) {
		id = &token->tkn_win_grps->wg_groups[i];
		sim->sim_id = &id->i_id;
		stat = smb_idmap_batch_getid(sib->sib_idmaph, sim,
		    id->i_sidattr.sid, SMB_IDMAP_GROUP);

		if (stat != IDMAP_SUCCESS)
			break;
	}

	return (stat);
}

/*
 * smb_token_sids2ids
 *
 * This will map all the SIDs of the access token to UIDs/GIDs.
 *
 * Returns 0 upon success.  Otherwise, returns -1.
 */
static int
smb_token_sids2ids(smb_token_t *token)
{
	idmap_stat stat;
	int nmaps, retries = 0;
	smb_idmap_batch_t sib;

	/*
	 * Number of idmap lookups: user SID, owner SID, primary group SID,
	 * and all Windows group SIDs
	 */
	if (token->tkn_flags & SMB_ATF_ANON)
		/*
		 * Don't include user and owner SID, they're Anonymous
		 */
		nmaps = 1;
	else
		nmaps = 3;

	nmaps += token->tkn_win_grps->wg_count;

	do {
		stat = smb_idmap_batch_create(&sib, nmaps, SMB_IDMAP_SID2ID);
		if (stat != IDMAP_SUCCESS)
			return (-1);

		stat = smb_token_idmap(token, &sib);
		if (stat != IDMAP_SUCCESS) {
			smb_idmap_batch_destroy(&sib);
			return (-1);
		}

		stat = smb_idmap_batch_getmappings(&sib);
		smb_idmap_batch_destroy(&sib);
		if (stat == IDMAP_ERR_RPC_HANDLE)
			if (smb_idmap_restart() < 0)
				break;
	} while (stat == IDMAP_ERR_RPC_HANDLE && retries++ < 3);

	return (stat == IDMAP_SUCCESS ? 0 : -1);
}

/*
 * smb_token_create_pxgrps
 *
 * Setup the POSIX group membership of the access token if the given UID is
 * a POSIX UID (non-ephemeral). Both the user's primary group and
 * supplementary groups will be added to the POSIX group array of the access
 * token.
 */
static smb_posix_grps_t *
smb_token_create_pxgrps(uid_t uid)
{
	struct passwd *pwd;
	smb_posix_grps_t *pgrps;
	int ngroups_max, num;
	gid_t *gids;

	if ((ngroups_max = sysconf(_SC_NGROUPS_MAX)) < 0) {
		syslog(LOG_ERR, "smb_logon: failed to get _SC_NGROUPS_MAX");
		return (NULL);
	}

	pwd = getpwuid(uid);
	if (pwd == NULL) {
		pgrps = malloc(sizeof (smb_posix_grps_t));
		if (pgrps == NULL)
			return (NULL);

		pgrps->pg_ngrps = 0;
		return (pgrps);
	}

	if (pwd->pw_name == NULL) {
		pgrps = malloc(sizeof (smb_posix_grps_t));
		if (pgrps == NULL)
			return (NULL);

		pgrps->pg_ngrps = 1;
		pgrps->pg_grps[0] = pwd->pw_gid;
		return (pgrps);
	}

	gids = (gid_t *)malloc(ngroups_max * sizeof (gid_t));
	if (gids == NULL) {
		return (NULL);
	}
	bzero(gids, ngroups_max * sizeof (gid_t));

	gids[0] = pwd->pw_gid;

	/*
	 * Setup the groups starting at index 1 (the last arg)
	 * of gids array.
	 */
	num = _getgroupsbymember(pwd->pw_name, gids, ngroups_max, 1);

	if (num == -1) {
		syslog(LOG_ERR, "smb_logon: unable "
		    "to get user's supplementary groups");
		num = 1;
	}

	pgrps = (smb_posix_grps_t *)malloc(SMB_POSIX_GRPS_SIZE(num));
	if (pgrps) {
		pgrps->pg_ngrps = num;
		bcopy(gids, pgrps->pg_grps, num * sizeof (gid_t));
	}

	free(gids);
	return (pgrps);
}

/*
 * smb_token_destroy
 *
 * Release all of the memory associated with a token structure. Ensure
 * that the token has been unlinked before calling.
 */
void
smb_token_destroy(smb_token_t *token)
{
	smb_win_grps_t *groups;
	int i;

	if (token == NULL)
		return;

	if (token->tkn_user) {
		free(token->tkn_user->i_sidattr.sid);
		free(token->tkn_user);
	}

	if (token->tkn_owner) {
		free(token->tkn_owner->i_sidattr.sid);
		free(token->tkn_owner);
	}

	if (token->tkn_primary_grp) {
		free(token->tkn_primary_grp->i_sidattr.sid);
		free(token->tkn_primary_grp);
	}

	if ((groups = token->tkn_win_grps) != NULL) {
		for (i = 0; i < groups->wg_count; ++i)
			free(groups->wg_groups[i].i_sidattr.sid);
		free(groups);
	}

	smb_privset_free(token->tkn_privileges);

	free(token->tkn_posix_grps);
	free(token->tkn_account_name);
	free(token->tkn_domain_name);
	free(token->tkn_session_key);

	free(token);
}

static smb_id_t *
smb_token_create_id(smb_sid_t *sid)
{
	smb_id_t *id;

	if ((id = malloc(sizeof (smb_id_t))) == NULL)
		return (NULL);

	id->i_id = (uid_t)-1;
	id->i_sidattr.attrs = 7;
	id->i_sidattr.sid = smb_sid_dup(sid);

	if (id->i_sidattr.sid == NULL) {
		free(id);
		id = NULL;
	}

	return (id);
}

/*
 * Token owner should be set to local Administrators group
 * in two cases:
 *   1. The logged on user is a member of Domain Admins group
 *   2. he/she is a member of local Administrators group
 */
static smb_id_t *
smb_token_create_owner(smb_userinfo_t *user_info)
{
	smb_sid_t *owner_sid;
	smb_wka_t *wka;

	if (user_info->flags & SMB_UINFO_FLAG_ADMIN) {
		wka = smb_wka_lookup("Administrators");
		assert(wka);
		owner_sid = wka->wka_binsid;
	} else {
		owner_sid = user_info->user_sid;
	}

	return (smb_token_create_id(owner_sid));
}

static smb_privset_t *
smb_token_create_privs(smb_userinfo_t *user_info)
{
	smb_privset_t *privs;
	smb_giter_t gi;
	smb_group_t grp;
	int rc;

	privs = smb_privset_new();
	if (privs == NULL)
		return (NULL);

	if (smb_lgrp_iteropen(&gi) != SMB_LGRP_SUCCESS) {
		smb_privset_free(privs);
		return (NULL);
	}

	while (smb_lgrp_iterate(&gi, &grp) == SMB_LGRP_SUCCESS) {
		if (smb_lgrp_is_member(&grp, user_info->user_sid)) {
			smb_privset_merge(privs, grp.sg_privs);
		}
		smb_lgrp_free(&grp);
	}
	smb_lgrp_iterclose(&gi);

	if (user_info->flags & SMB_UINFO_FLAG_ADMIN) {
		rc = smb_lgrp_getbyname("Administrators", &grp);
		if (rc == SMB_LGRP_SUCCESS) {
			smb_privset_merge(privs, grp.sg_privs);
			smb_lgrp_free(&grp);
		}

		/*
		 * This privilege is required to view/edit SACL
		 */
		smb_privset_enable(privs, SE_SECURITY_LUID);
	}

	return (privs);
}

static void
smb_token_set_flags(smb_token_t *token, smb_userinfo_t *user_info)
{
	smb_wka_t *wka;

	if (user_info->flags & SMB_UINFO_FLAG_ANON) {
		token->tkn_flags |= SMB_ATF_ANON;
		return;
	}

	if (user_info->rid == DOMAIN_USER_RID_GUEST) {
		token->tkn_flags |= SMB_ATF_GUEST;
		return;
	}

	wka = smb_wka_lookup("Administrators");
	if (wka->wka_binsid && smb_token_is_member(token, wka->wka_binsid))
		token->tkn_flags |= SMB_ATF_ADMIN;

	wka = smb_wka_lookup("Power Users");
	if (wka->wka_binsid && smb_token_is_member(token, wka->wka_binsid))
		token->tkn_flags |= SMB_ATF_POWERUSER;

	wka = smb_wka_lookup("Backup Operators");
	if (wka->wka_binsid && smb_token_is_member(token, wka->wka_binsid))
		token->tkn_flags |= SMB_ATF_BACKUPOP;

}

/*
 * smb_token_create
 *
 * Build an access token based on the given user information (user_info).
 *
 * If everything is successful, a pointer to an access token is
 * returned. Otherwise a null pointer is returned.
 */
static smb_token_t *
smb_token_create(smb_userinfo_t *user_info)
{
	smb_token_t *token;

	if (user_info->sid_name_use != SidTypeUser)
		return (NULL);

	token = (smb_token_t *)malloc(sizeof (smb_token_t));
	if (token == NULL) {
		syslog(LOG_ERR, "smb_token_create: resource shortage");
		return (NULL);
	}
	bzero(token, sizeof (smb_token_t));

	/* User */
	token->tkn_user = smb_token_create_id(user_info->user_sid);
	if (token->tkn_user == NULL) {
		smb_token_destroy(token);
		return (NULL);
	}

	/* Owner */
	token->tkn_owner = smb_token_create_owner(user_info);
	if (token->tkn_owner == NULL) {
		smb_token_destroy(token);
		return (NULL);
	}

	/* Primary Group */
	token->tkn_primary_grp = smb_token_create_id(user_info->pgrp_sid);
	if (token->tkn_primary_grp == NULL) {
		smb_token_destroy(token);
		return (NULL);
	}

	/* Privileges */
	token->tkn_privileges = smb_token_create_privs(user_info);
	if (token->tkn_privileges == NULL) {
		smb_token_destroy(token);
		return (NULL);
	}

	/* Windows Groups */
	token->tkn_win_grps = smb_token_create_wingrps(user_info);

	smb_token_set_flags(token, user_info);

	/*
	 * IMPORTANT
	 *
	 * This function has to be called after all the SIDs in the
	 * token are setup (i.e. user, owner, primary and supplementary
	 * groups) and before setting up Solaris groups.
	 */
	if (smb_token_sids2ids(token) != 0) {
		syslog(LOG_ERR, "%s\\%s: idmap failed",
		    (user_info->domain_name) ? user_info->domain_name : "",
		    (user_info->name) ? user_info->name : "");
		smb_token_destroy(token);
		return (NULL);
	}

	/* Solaris Groups */
	token->tkn_posix_grps = smb_token_create_pxgrps(token->tkn_user->i_id);

	if (user_info->session_key) {
		token->tkn_session_key = malloc(sizeof (smb_session_key_t));
		if (token->tkn_session_key == NULL) {
			smb_token_destroy(token);
			return (NULL);
		}

		(void) memcpy(token->tkn_session_key,
		    user_info->session_key, sizeof (smb_session_key_t));
	}

	token->tkn_account_name = strdup(user_info->name);
	token->tkn_domain_name = strdup(user_info->domain_name);

	if (!smb_token_is_valid(token)) {
		smb_token_destroy(token);
		return (NULL);
	}

	return (token);
}

/*
 * smb_token_create_wingrps
 *
 * This private function supports smb_token_create() by mapping the group
 * information in the user_info structure to the form required in an
 * access token. The main difference is that the user_info contains
 * RIDs while and access token contains full SIDs. Memory allocated
 * here will be deallocated as part of smb_token_destroy().
 *
 * If everything is successful, a pointer to a smb_win_grps_t
 * structure is returned. Otherwise a null pointer is returned.
 */
static smb_win_grps_t *
smb_token_create_wingrps(smb_userinfo_t *user_info)
{
	static char *wk_grps[] =
		{"Authenticated Users", "NETWORK", "Administrators"};
	smb_win_grps_t *tkn_grps;
	smb_sid_attrs_t *dlg_grps;
	smb_rid_attrs_t *g_grps;
	smb_sid_attrs_t *grp;
	smb_sid_t *builtin_sid;
	smb_giter_t gi;
	smb_group_t lgrp;
	uint32_t n_gg, n_lg, n_dlg, n_wg;
	uint32_t i, j;
	int size, count;

	if (user_info == NULL)
		return (NULL);

	n_gg = user_info->n_groups;		/* Global Groups */
	n_dlg = user_info->n_other_grps;	/* Domain Local Groups */

	/* Local Groups */
	(void) smb_lgrp_numbymember(user_info->user_sid, (int *)&n_lg);

	/* Well known Groups */
	if ((user_info->flags & SMB_UINFO_FLAG_ADMIN) == SMB_UINFO_FLAG_DADMIN)
		/* if user is a domain admin but not a local admin */
		n_wg = 3;
	else if (user_info->flags & SMB_UINFO_FLAG_ANON)
		n_wg = 0;
	else
		n_wg = 2;

	count = n_gg + n_dlg + n_lg + n_wg;
	size = sizeof (smb_win_grps_t) + (count * sizeof (smb_id_t));

	if ((tkn_grps = malloc(size)) == NULL)
		return (NULL);
	bzero(tkn_grps, size);

	/* Add global groups */
	g_grps = user_info->groups;
	for (i = 0; i < n_gg; i++) {
		grp = &tkn_grps->wg_groups[i].i_sidattr;
		grp->sid = smb_sid_splice(user_info->domain_sid, g_grps[i].rid);
		if (grp->sid == NULL)
			break;
		grp->attrs = g_grps[i].attributes;
	}

	if (n_gg == 0) {
		/*
		 * if there's no global group should add the
		 * primary group.
		 */
		grp = &tkn_grps->wg_groups[i].i_sidattr;
		grp->sid = smb_sid_dup(user_info->pgrp_sid);
		if (grp->sid != NULL) {
			grp->attrs = 0x7;
			i++;
		}
	}

	/* Add domain local groups */
	dlg_grps = user_info->other_grps;
	for (j = 0; j < n_dlg; j++, i++) {
		grp = &tkn_grps->wg_groups[i].i_sidattr;
		grp->sid = smb_sid_dup(dlg_grps[j].sid);
		if (grp->sid == NULL)
			break;
		grp->attrs = dlg_grps[j].attrs;
	}

	/* Add local groups */
	if (n_lg && (smb_lgrp_iteropen(&gi) == SMB_LGRP_SUCCESS)) {
		j = 0;
		while (smb_lgrp_iterate(&gi, &lgrp) == SMB_LGRP_SUCCESS) {
			if ((j < n_lg) &&
			    smb_lgrp_is_member(&lgrp, user_info->user_sid)) {
				grp = &tkn_grps->wg_groups[i].i_sidattr;
				grp->sid = smb_sid_dup(lgrp.sg_id.gs_sid);
				if (grp->sid == NULL) {
					smb_lgrp_free(&lgrp);
					break;
				}
				grp->attrs = lgrp.sg_attr;
				i++;
				j++;
			}
			smb_lgrp_free(&lgrp);
		}
		smb_lgrp_iterclose(&gi);
	}

	/* Add well known groups */
	for (j = 0; j < n_wg; j++, i++) {
		builtin_sid = smb_wka_lookup_name(wk_grps[j], NULL);
		if (builtin_sid == NULL)
			break;
		tkn_grps->wg_groups[i].i_sidattr.sid = builtin_sid;
		tkn_grps->wg_groups[i].i_sidattr.attrs = 0x7;
	}

	tkn_grps->wg_count = i;
	return (tkn_grps);
}

/*
 * smb_logon
 *
 * Performs user authentication and creates a token if the
 * authentication is successful.
 *
 * Returns pointer to the created token.
 */
smb_token_t *
smb_logon(netr_client_t *clnt)
{
	smb_token_t *token = NULL;
	smb_userinfo_t *uinfo;
	uint32_t status;

	if ((uinfo = mlsvc_alloc_user_info()) == 0)
		return (NULL);

	switch (clnt->flags) {
	case NETR_CFLG_DOMAIN:
		/* Pass through authentication with DC */
		status = smb_logon_domain(clnt, uinfo);
		break;

	case NETR_CFLG_LOCAL:
		/* Local authentication */
		status = smb_logon_local(clnt, uinfo);
		break;

	case NETR_CFLG_ANON:
		/* Anonymous user; no authentication */
		status = smb_logon_none(clnt, uinfo);
		break;

	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	if (status == NT_STATUS_SUCCESS)
		token = smb_token_create(uinfo);

	mlsvc_free_user_info(uinfo);
	return (token);
}

/*
 * smb_logon_domain
 *
 * Performs pass through authentication with PDC.
 */
static uint32_t
smb_logon_domain(netr_client_t *clnt, smb_userinfo_t *uinfo)
{
	uint32_t status;

	if ((status = netlogon_logon(clnt, uinfo)) != 0) {
		if (status == NT_STATUS_CANT_ACCESS_DOMAIN_INFO) {
			if ((status = netlogon_logon(clnt, uinfo)) != 0) {
				syslog(LOG_INFO, "SmbLogon[%s\\%s]: %s",
				    clnt->domain, clnt->username,
				    xlate_nt_status(status));
				return (status);
			}
		}
	}

	return (status);
}

/*
 * smb_logon_local
 *
 * Check to see if connected user has an entry in the local
 * smbpasswd database. If it has, tries both LM hash and NT
 * hash with user's password(s) to authenticate the user.
 */
static uint32_t
smb_logon_local(netr_client_t *clnt, smb_userinfo_t *uinfo)
{
	smb_passwd_t smbpw;
	boolean_t lm_ok, nt_ok;
	uint32_t status;

	if (smb_pwd_getpasswd(clnt->username, &smbpw) == NULL) {
		/*
		 * If user doesn't have entry either in smbpasswd
		 * or passwd it's considered as an invalid user.
		 */
		status = NT_STATUS_NO_SUCH_USER;
		syslog(LOG_NOTICE, "SmbLogon[%s\\%s]: %s",
		    clnt->domain, clnt->username,
		    xlate_nt_status(status));
		return (status);
	}
	if (smbpw.pw_flags & SMB_PWF_DISABLE)
		return (NT_STATUS_ACCOUNT_DISABLED);

	nt_ok = lm_ok = B_FALSE;
	if ((smbpw.pw_flags & SMB_PWF_LM) &&
	    (clnt->lm_password.lm_password_len != 0)) {
		lm_ok = smb_auth_validate_lm(
		    clnt->challenge_key.challenge_key_val,
		    clnt->challenge_key.challenge_key_len,
		    &smbpw,
		    clnt->lm_password.lm_password_val,
		    clnt->lm_password.lm_password_len,
		    clnt->domain,
		    clnt->username);
		uinfo->session_key = NULL;
	}

	if (!lm_ok && (clnt->nt_password.nt_password_len != 0)) {
		if ((uinfo->session_key =
		    malloc(SMBAUTH_SESSION_KEY_SZ)) == NULL)
			return (NT_STATUS_NO_MEMORY);
		nt_ok = smb_auth_validate_nt(
		    clnt->challenge_key.challenge_key_val,
		    clnt->challenge_key.challenge_key_len,
		    &smbpw,
		    clnt->nt_password.nt_password_val,
		    clnt->nt_password.nt_password_len,
		    clnt->domain,
		    clnt->username,
		    (uchar_t *)uinfo->session_key);
	}

	if (!nt_ok && !lm_ok) {
		status = NT_STATUS_WRONG_PASSWORD;
		syslog(LOG_NOTICE, "SmbLogon[%s\\%s]: %s",
		    clnt->domain, clnt->username,
		    xlate_nt_status(status));
		return (status);
	}

	status = smb_setup_luinfo(uinfo, clnt, smbpw.pw_uid);
	return (status);
}

/*
 * smb_logon_none
 *
 * Setup user information for anonymous user.
 * No authentication is required.
 */
static uint32_t
smb_logon_none(netr_client_t *clnt, smb_userinfo_t *uinfo)
{
	return (smb_setup_luinfo(uinfo, clnt, (uid_t)-1));
}

/*
 * smb_setup_luinfo
 *
 * Setup local user information based on the client information and
 * user's record in the local password file.
 */
static uint32_t
smb_setup_luinfo(smb_userinfo_t *lui, netr_client_t *clnt, uid_t uid)
{
	idmap_stat stat;
	smb_idmap_batch_t sib;
	smb_idmap_t *umap, *gmap;
	smb_group_t grp;
	struct passwd pw;
	char pwbuf[1024];

	lui->sid_name_use = SidTypeUser;
	lui->domain_sid = smb_sid_dup(nt_domain_local_sid());
	lui->name = strdup(clnt->username);
	lui->domain_name = strdup(clnt->domain);
	lui->n_groups = 0;
	lui->groups = NULL;
	lui->n_other_grps = 0;
	lui->other_grps = NULL;
	lui->flags = 0;

	if (lui->name == NULL || lui->domain_name == NULL ||
	    lui->domain_sid == NULL)
		return (NT_STATUS_INVALID_PARAMETER);

	if (clnt->flags & NETR_CFLG_ANON) {
		lui->user_sid = smb_wka_lookup_name("Anonymous", NULL);
		lui->pgrp_sid = smb_wka_lookup_name("Anonymous", NULL);
		lui->flags = SMB_UINFO_FLAG_ANON;

		if (lui->user_sid == NULL || lui->pgrp_sid == NULL)
			return (NT_STATUS_NO_MEMORY);

		return (NT_STATUS_SUCCESS);
	}

	if (getpwuid_r(uid, &pw, pwbuf, sizeof (pwbuf)) == NULL)
		return (NT_STATUS_NO_SUCH_USER);

	/* Get the SID for user's uid & gid */
	stat = smb_idmap_batch_create(&sib, 2, SMB_IDMAP_ID2SID);
	if (stat != IDMAP_SUCCESS) {
		return (NT_STATUS_INTERNAL_ERROR);
	}

	umap = &sib.sib_maps[0];
	stat = smb_idmap_batch_getsid(sib.sib_idmaph, umap, pw.pw_uid,
	    SMB_IDMAP_USER);

	if (stat != IDMAP_SUCCESS) {
		smb_idmap_batch_destroy(&sib);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	gmap = &sib.sib_maps[1];
	stat = smb_idmap_batch_getsid(sib.sib_idmaph, gmap, pw.pw_gid,
	    SMB_IDMAP_GROUP);

	if (stat != IDMAP_SUCCESS) {
		smb_idmap_batch_destroy(&sib);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	stat = smb_idmap_batch_getmappings(&sib);

	if (stat != IDMAP_SUCCESS) {
		return (NT_STATUS_INTERNAL_ERROR);
	}

	lui->rid = umap->sim_rid;
	lui->user_sid = smb_sid_dup(umap->sim_sid);

	lui->primary_group_rid = gmap->sim_rid;
	lui->pgrp_sid = smb_sid_dup(gmap->sim_sid);

	smb_idmap_batch_destroy(&sib);

	if ((lui->user_sid == NULL) || (lui->pgrp_sid == NULL))
		return (NT_STATUS_NO_MEMORY);

	if (smb_lgrp_getbyname("Administrators", &grp) == SMB_LGRP_SUCCESS) {
		if (smb_lgrp_is_member(&grp, lui->user_sid))
			lui->flags = SMB_UINFO_FLAG_LADMIN;
		smb_lgrp_free(&grp);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * smb_token_is_valid
 *
 * check to see if specified fields of the given access
 * token are valid.
 * Returns 1 if all of them are valid; otherwise 0.
 */
static int
smb_token_is_valid(smb_token_t *token)
{
	int valid;

	valid = (token->tkn_user != 0) &&
	    (token->tkn_user->i_sidattr.sid != 0) &&
	    (token->tkn_privileges != 0) &&
	    (token->tkn_win_grps != 0) &&
	    (token->tkn_owner != 0) &&
	    (token->tkn_owner->i_sidattr.sid != 0) &&
	    (token->tkn_primary_grp != 0) &&
	    (token->tkn_primary_grp->i_sidattr.sid != 0);

	return (valid);
}

/*
 * smb_token_user_sid
 *
 * Return a pointer to the user SID in the specified token. A null
 * pointer indicates an error.
 */
static smb_sid_t *
smb_token_user_sid(smb_token_t *token)
{
	if (token && token->tkn_user)
		return ((token)->tkn_user->i_sidattr.sid);

	return (NULL);
}

/*
 * smb_token_group_sid
 *
 * Return a pointer to the group SID as indicated by the iterator.
 * Setting the iterator to 0 before calling this function will return
 * the first group, which will always be the primary group. The
 * iterator will be incremented before returning the SID so that this
 * function can be used to cycle through the groups. The caller can
 * adjust the iterator as required between calls to obtain any specific
 * group.
 *
 * On success a pointer to the appropriate group SID will be returned.
 * Otherwise a null pointer will be returned.
 */
static smb_sid_t *
smb_token_group_sid(smb_token_t *token, int *iterator)
{
	smb_win_grps_t *groups;
	int index;

	if (token == NULL || iterator == NULL) {
		return (NULL);
	}

	if ((groups = token->tkn_win_grps) == NULL) {
		return (NULL);
	}

	index = *iterator;

	if (index < 0 || index >= groups->wg_count) {
		return (NULL);
	}

	++(*iterator);
	return (groups->wg_groups[index].i_sidattr.sid);
}

/*
 * smb_token_is_member
 *
 * This function will determine whether or not the specified SID is a
 * member of a token. The user SID and all group SIDs are tested.
 * Returns 1 if the SID is a member of the token. Otherwise returns 0.
 */
static int
smb_token_is_member(smb_token_t *token, smb_sid_t *sid)
{
	smb_sid_t *tsid;
	int iterator = 0;

	tsid = smb_token_user_sid(token);
	while (tsid) {
		if (smb_sid_cmp(tsid, sid))
			return (1);

		tsid = smb_token_group_sid(token, &iterator);
	}

	return (0);
}

/*
 * smb_token_log
 *
 * Diagnostic routine to write the contents of a token to the log.
 */
void
smb_token_log(smb_token_t *token)
{
	smb_win_grps_t *w_grps;
	smb_posix_grps_t *x_grps;
	smb_sid_attrs_t *grp;
	char sidstr[SMB_SID_STRSZ];
	int i;

	if (token == NULL)
		return;

	syslog(LOG_DEBUG, "Token for %s\\%s",
	    (token->tkn_domain_name) ? token->tkn_domain_name : "-NULL-",
	    (token->tkn_account_name) ? token->tkn_account_name : "-NULL-");

	syslog(LOG_DEBUG, "   User->Attr: %d",
	    token->tkn_user->i_sidattr.attrs);
	smb_sid_tostr((smb_sid_t *)token->tkn_user->i_sidattr.sid, sidstr);
	syslog(LOG_DEBUG, "   User->Sid: %s (id=%u)",
	    sidstr, token->tkn_user->i_id);

	smb_sid_tostr((smb_sid_t *)token->tkn_owner->i_sidattr.sid, sidstr);
	syslog(LOG_DEBUG, "   Ownr->Sid: %s (id=%u)",
	    sidstr, token->tkn_owner->i_id);

	smb_sid_tostr((smb_sid_t *)token->tkn_primary_grp->i_sidattr.sid,
	    sidstr);
	syslog(LOG_DEBUG, "   PGrp->Sid: %s (id=%u)",
	    sidstr, token->tkn_primary_grp->i_id);

	w_grps = token->tkn_win_grps;
	if (w_grps) {
		syslog(LOG_DEBUG, "   Windows groups: %d",
		    w_grps->wg_count);

		for (i = 0; i < w_grps->wg_count; ++i) {
			grp = &w_grps->wg_groups[i].i_sidattr;
			syslog(LOG_DEBUG,
			    "    Grp[%d].Attr:%d", i, grp->attrs);
			if (w_grps->wg_groups[i].i_sidattr.sid) {
				smb_sid_tostr((smb_sid_t *)grp->sid, sidstr);
				syslog(LOG_DEBUG,
				    "    Grp[%d].Sid: %s (id=%u)", i, sidstr,
				    w_grps->wg_groups[i].i_id);
			}
		}
	}
	else
		syslog(LOG_DEBUG, "   No Windows groups");

	x_grps = token->tkn_posix_grps;
	if (x_grps) {
		syslog(LOG_DEBUG, "   Solaris groups: %d",
		    x_grps->pg_ngrps);
		for (i = 0; i < x_grps->pg_ngrps; i++)
			syslog(LOG_DEBUG, "    %u",
			    x_grps->pg_grps[i]);
	}
	else
		syslog(LOG_DEBUG, "   No Solaris groups");

	if (token->tkn_privileges)
		smb_privset_log(token->tkn_privileges);
	else
		syslog(LOG_DEBUG, "   No privileges");
}
