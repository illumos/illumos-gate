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
#include <lsalib.h>

extern uint32_t netlogon_logon(netr_client_t *, smb_token_t *);
static uint32_t smb_logon_domain(netr_client_t *, smb_token_t *);
static uint32_t smb_logon_local(netr_client_t *, smb_token_t *);
static uint32_t smb_logon_anon(netr_client_t *, smb_token_t *);

static uint32_t smb_token_setup_local(smb_passwd_t *, smb_token_t *);
static uint32_t smb_token_setup_anon(smb_token_t *token);

static boolean_t smb_token_is_member(smb_token_t *, smb_sid_t *);
static uint32_t smb_token_setup_wingrps(smb_token_t *);
static smb_posix_grps_t *smb_token_create_pxgrps(uid_t);

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
		token->tkn_user.i_id = UID_NOBODY;
		token->tkn_owner.i_id = UID_NOBODY;
	} else {
		/* User SID */
		id = &token->tkn_user;
		sim->sim_id = &id->i_id;
		stat = smb_idmap_batch_getid(sib->sib_idmaph, sim++,
		    id->i_sid, SMB_IDMAP_USER);

		if (stat != IDMAP_SUCCESS)
			return (stat);

		/* Owner SID */
		id = &token->tkn_owner;
		sim->sim_id = &id->i_id;
		stat = smb_idmap_batch_getid(sib->sib_idmaph, sim++,
		    id->i_sid, SMB_IDMAP_USER);

		if (stat != IDMAP_SUCCESS)
			return (stat);
	}

	/* Primary Group SID */
	id = &token->tkn_primary_grp;
	sim->sim_id = &id->i_id;
	stat = smb_idmap_batch_getid(sib->sib_idmaph, sim++, id->i_sid,
	    SMB_IDMAP_GROUP);

	if (stat != IDMAP_SUCCESS)
		return (stat);

	/* Other Windows Group SIDs */
	for (i = 0; i < token->tkn_win_grps.i_cnt; i++, sim++) {
		id = &token->tkn_win_grps.i_ids[i];
		sim->sim_id = &id->i_id;
		stat = smb_idmap_batch_getid(sib->sib_idmaph, sim,
		    id->i_sid, SMB_IDMAP_GROUP);

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
	 * and all Windows group SIDs. Skip user/owner SID for Anonymous.
	 */
	if (token->tkn_flags & SMB_ATF_ANON)
		nmaps = token->tkn_win_grps.i_cnt + 1;
	else
		nmaps = token->tkn_win_grps.i_cnt + 3;

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
	if (token != NULL) {
		smb_sid_free(token->tkn_user.i_sid);
		smb_sid_free(token->tkn_owner.i_sid);
		smb_sid_free(token->tkn_primary_grp.i_sid);
		smb_ids_free(&token->tkn_win_grps);
		smb_privset_free(token->tkn_privileges);
		free(token->tkn_posix_grps);
		free(token->tkn_account_name);
		free(token->tkn_domain_name);
		free(token->tkn_session_key);
		free(token);
	}
}

/*
 * Token owner should be set to local Administrators group
 * in two cases:
 *   1. The logged on user is a member of Domain Admins group
 *   2. he/she is a member of local Administrators group
 */
static void
smb_token_set_owner(smb_token_t *token)
{
#ifdef SMB_SUPPORT_GROUP_OWNER
	smb_sid_t *owner_sid;

	if (token->tkn_flags & SMB_ATF_ADMIN) {
		owner_sid = smb_wka_get_sid("Administrators");
		assert(owner_sid);
	} else {
		owner_sid = token->tkn_user->i_sid;
	}

	token->tkn_owner.i_sid = smb_sid_dup(owner_sid);
#endif
	token->tkn_owner.i_sid = smb_sid_dup(token->tkn_user.i_sid);
}

static smb_privset_t *
smb_token_create_privs(smb_token_t *token)
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
		if (smb_lgrp_is_member(&grp, token->tkn_user.i_sid))
			smb_privset_merge(privs, grp.sg_privs);
		smb_lgrp_free(&grp);
	}
	smb_lgrp_iterclose(&gi);

	if (token->tkn_flags & SMB_ATF_ADMIN) {
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
smb_token_set_flags(smb_token_t *token)
{
	uint32_t rid;

	(void) smb_sid_getrid(token->tkn_user.i_sid, &rid);
	if (rid == DOMAIN_USER_RID_GUEST) {
		token->tkn_flags |= SMB_ATF_GUEST;
		return;
	}

	if (smb_token_is_member(token, smb_wka_get_sid("Administrators")))
		token->tkn_flags |= SMB_ATF_ADMIN;

	if (smb_token_is_member(token, smb_wka_get_sid("Power Users")))
		token->tkn_flags |= SMB_ATF_POWERUSER;

	if (smb_token_is_member(token, smb_wka_get_sid("Backup Operators")))
		token->tkn_flags |= SMB_ATF_BACKUPOP;
}

/*
 * Common token setup for both local and domain users.
 * This function must be called after the initial setup
 * has been done.
 *
 * Note that the order of calls in this function are important.
 */
static uint32_t
smb_token_setup_common(smb_token_t *token)
{
	smb_token_set_flags(token);

	smb_token_set_owner(token);
	if (token->tkn_owner.i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	/* Privileges */
	token->tkn_privileges = smb_token_create_privs(token);
	if (token->tkn_privileges == NULL)
		return (NT_STATUS_NO_MEMORY);

	if (smb_token_sids2ids(token) != 0) {
		syslog(LOG_ERR, "%s\\%s: idmap failed",
		    token->tkn_domain_name, token->tkn_account_name);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	/* Solaris Groups */
	token->tkn_posix_grps = smb_token_create_pxgrps(token->tkn_user.i_id);

	return (NT_STATUS_SUCCESS);
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
	uint32_t status;

	if ((token = malloc(sizeof (smb_token_t))) == NULL) {
		syslog(LOG_ERR, "smb_logon: resource shortage");
		return (NULL);
	}
	bzero(token, sizeof (smb_token_t));

	status = smb_logon_anon(clnt, token);
	if (status == NT_STATUS_INVALID_LOGON_TYPE) {
		status = smb_logon_local(clnt, token);
		if (status != NT_STATUS_SUCCESS) {
			if ((status == NT_STATUS_INVALID_LOGON_TYPE) ||
			    (*clnt->real_domain == '\0'))
				status = smb_logon_domain(clnt, token);
		}
	}

	if (status == NT_STATUS_SUCCESS) {
		if (smb_token_setup_common(token) == NT_STATUS_SUCCESS)
			return (token);
	}

	smb_token_destroy(token);
	return (NULL);
}

/*
 * smb_logon_domain
 *
 * Performs pass through authentication with PDC.
 */
static uint32_t
smb_logon_domain(netr_client_t *clnt, smb_token_t *token)
{
	uint32_t status;

	if ((status = netlogon_logon(clnt, token)) != 0) {
		if (status == NT_STATUS_CANT_ACCESS_DOMAIN_INFO) {
			if ((status = netlogon_logon(clnt, token)) != 0) {
				syslog(LOG_INFO, "SmbLogon[%s\\%s]: %s",
				    clnt->real_domain, clnt->real_username,
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
smb_logon_local(netr_client_t *clnt, smb_token_t *token)
{
	smb_passwd_t smbpw;
	boolean_t lm_ok, nt_ok;
	uint32_t status;
	nt_domain_t *domain;

	/* Make sure this is not a domain user */
	if (smb_config_get_secmode() == SMB_SECMODE_DOMAIN) {
		domain = nt_domain_lookup_name(clnt->real_domain);
		if (domain && (domain->type != NT_DOMAIN_LOCAL))
			return (NT_STATUS_INVALID_LOGON_TYPE);
	}

	if (smb_pwd_getpwnam(clnt->real_username, &smbpw) == NULL) {
		/*
		 * If user doesn't have entry either in smbpasswd
		 * or passwd it's considered as an invalid user.
		 */
		status = NT_STATUS_NO_SUCH_USER;
		syslog(LOG_NOTICE, "SmbLogon[%s\\%s]: %s",
		    clnt->real_domain, clnt->real_username,
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
		token->tkn_session_key = NULL;
	}

	if (!lm_ok && (clnt->nt_password.nt_password_len != 0)) {
		token->tkn_session_key = malloc(SMBAUTH_SESSION_KEY_SZ);
		if (token->tkn_session_key == NULL)
			return (NT_STATUS_NO_MEMORY);
		nt_ok = smb_auth_validate_nt(
		    clnt->challenge_key.challenge_key_val,
		    clnt->challenge_key.challenge_key_len,
		    &smbpw,
		    clnt->nt_password.nt_password_val,
		    clnt->nt_password.nt_password_len,
		    clnt->domain,
		    clnt->username,
		    (uchar_t *)token->tkn_session_key);
	}

	if (!nt_ok && !lm_ok) {
		status = NT_STATUS_WRONG_PASSWORD;
		syslog(LOG_NOTICE, "SmbLogon[%s\\%s]: %s",
		    clnt->real_domain, clnt->real_username,
		    xlate_nt_status(status));
		return (status);
	}

	status = smb_token_setup_local(&smbpw, token);
	return (status);
}

/*
 * If 'clnt' represents an anonymous user (no password)
 * then setup the token accordingly, otherwise return
 * NT_STATUS_INVALID_LOGON_TYPE
 */
static uint32_t
smb_logon_anon(netr_client_t *clnt, smb_token_t *token)
{
	if ((clnt->nt_password.nt_password_len == 0) &&
	    (clnt->lm_password.lm_password_len == 0 ||
	    (clnt->lm_password.lm_password_len == 1 &&
	    *clnt->lm_password.lm_password_val == '\0'))) {
		return (smb_token_setup_anon(token));
	}

	return (NT_STATUS_INVALID_LOGON_TYPE);
}

/*
 * Setup an access token for the specified local user.
 */
static uint32_t
smb_token_setup_local(smb_passwd_t *smbpw, smb_token_t *token)
{
	idmap_stat stat;
	smb_idmap_batch_t sib;
	smb_idmap_t *umap, *gmap;
	struct passwd pw;
	char pwbuf[1024];
	char nbname[NETBIOS_NAME_SZ];

	(void) smb_getnetbiosname(nbname, sizeof (nbname));
	token->tkn_account_name = strdup(smbpw->pw_name);
	token->tkn_domain_name = strdup(nbname);

	if (token->tkn_account_name == NULL ||
	    token->tkn_domain_name == NULL)
		return (NT_STATUS_NO_MEMORY);

	if (getpwuid_r(smbpw->pw_uid, &pw, pwbuf, sizeof (pwbuf)) == NULL)
		return (NT_STATUS_NO_SUCH_USER);

	/* Get the SID for user's uid & gid */
	stat = smb_idmap_batch_create(&sib, 2, SMB_IDMAP_ID2SID);
	if (stat != IDMAP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

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

	if (smb_idmap_batch_getmappings(&sib) != IDMAP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	token->tkn_user.i_sid = smb_sid_dup(umap->sim_sid);
	token->tkn_primary_grp.i_sid = smb_sid_dup(gmap->sim_sid);

	smb_idmap_batch_destroy(&sib);

	if (token->tkn_user.i_sid == NULL ||
	    token->tkn_primary_grp.i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	return (smb_token_setup_wingrps(token));
}

/*
 * Setup access token for an anonymous connection
 */
static uint32_t
smb_token_setup_anon(smb_token_t *token)
{
	char nbname[NETBIOS_NAME_SZ];
	smb_sid_t *user_sid;

	(void) smb_getnetbiosname(nbname, sizeof (nbname));
	token->tkn_account_name = strdup("Anonymous");
	token->tkn_domain_name = strdup("NT Authority");
	user_sid = smb_wka_get_sid("Anonymous");
	token->tkn_user.i_sid = smb_sid_dup(user_sid);
	token->tkn_primary_grp.i_sid = smb_sid_dup(user_sid);
	token->tkn_flags = SMB_ATF_ANON;

	if (token->tkn_account_name == NULL ||
	    token->tkn_domain_name == NULL ||
	    token->tkn_user.i_sid == NULL ||
	    token->tkn_primary_grp.i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	return (smb_token_setup_wingrps(token));
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
	return ((token) ? token->tkn_user.i_sid : NULL);
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
	int index;

	if (token == NULL || iterator == NULL)
		return (NULL);

	if (token->tkn_win_grps.i_ids == NULL)
		return (NULL);

	index = *iterator;

	if (index < 0 || index >= token->tkn_win_grps.i_cnt)
		return (NULL);

	++(*iterator);
	return (token->tkn_win_grps.i_ids[index].i_sid);
}

/*
 * smb_token_is_member
 *
 * This function will determine whether or not the specified SID is a
 * member of a token. The user SID and all group SIDs are tested.
 * Returns 1 if the SID is a member of the token. Otherwise returns 0.
 */
static boolean_t
smb_token_is_member(smb_token_t *token, smb_sid_t *sid)
{
	smb_sid_t *tsid;
	int iterator = 0;

	if (token == NULL || sid == NULL)
		return (B_FALSE);

	tsid = smb_token_user_sid(token);
	while (tsid) {
		if (smb_sid_cmp(tsid, sid))
			return (B_TRUE);

		tsid = smb_token_group_sid(token, &iterator);
	}

	return (B_FALSE);
}

/*
 * smb_token_log
 *
 * Diagnostic routine to write the contents of a token to the log.
 */
void
smb_token_log(smb_token_t *token)
{
	smb_ids_t *w_grps;
	smb_id_t *grp;
	smb_posix_grps_t *x_grps;
	char sidstr[SMB_SID_STRSZ];
	int i;

	if (token == NULL)
		return;

	syslog(LOG_DEBUG, "Token for %s\\%s",
	    (token->tkn_domain_name) ? token->tkn_domain_name : "-NULL-",
	    (token->tkn_account_name) ? token->tkn_account_name : "-NULL-");

	syslog(LOG_DEBUG, "   User->Attr: %d", token->tkn_user.i_attrs);
	smb_sid_tostr((smb_sid_t *)token->tkn_user.i_sid, sidstr);
	syslog(LOG_DEBUG, "   User->Sid: %s (id=%u)", sidstr,
	    token->tkn_user.i_id);

	smb_sid_tostr((smb_sid_t *)token->tkn_owner.i_sid, sidstr);
	syslog(LOG_DEBUG, "   Ownr->Sid: %s (id=%u)",
	    sidstr, token->tkn_owner.i_id);

	smb_sid_tostr((smb_sid_t *)token->tkn_primary_grp.i_sid, sidstr);
	syslog(LOG_DEBUG, "   PGrp->Sid: %s (id=%u)",
	    sidstr, token->tkn_primary_grp.i_id);

	w_grps = &token->tkn_win_grps;
	if (w_grps->i_ids) {
		syslog(LOG_DEBUG, "   Windows groups: %d", w_grps->i_cnt);
		grp = w_grps->i_ids;
		for (i = 0; i < w_grps->i_cnt; ++i, grp++) {
			syslog(LOG_DEBUG,
			    "    Grp[%d].Attr:%d", i, grp->i_attrs);
			if (grp->i_sid != NULL) {
				smb_sid_tostr((smb_sid_t *)grp->i_sid, sidstr);
				syslog(LOG_DEBUG,
				    "    Grp[%d].Sid: %s (id=%u)", i, sidstr,
				    grp->i_id);
			}
		}
	} else {
		syslog(LOG_DEBUG, "   No Windows groups");
	}

	x_grps = token->tkn_posix_grps;
	if (x_grps) {
		syslog(LOG_DEBUG, "   Solaris groups: %d", x_grps->pg_ngrps);
		for (i = 0; i < x_grps->pg_ngrps; i++)
			syslog(LOG_DEBUG, "    %u", x_grps->pg_grps[i]);
	} else {
		syslog(LOG_DEBUG, "   No Solaris groups");
	}

	if (token->tkn_privileges)
		smb_privset_log(token->tkn_privileges);
	else
		syslog(LOG_DEBUG, "   No privileges");
}

/*
 * Sets up local and well-known group membership for the given
 * token. Two assumptions have been made here:
 *
 *   a) token already contains a valid user SID so that group
 *      memberships can be established
 *
 *   b) token belongs to a local or anonymous user
 */
static uint32_t
smb_token_setup_wingrps(smb_token_t *token)
{
	smb_ids_t tkn_grps;
	uint32_t status;


	/*
	 * We always want the user's primary group in the list
	 * of groups.
	 */
	tkn_grps.i_cnt = 1;
	if ((tkn_grps.i_ids = malloc(sizeof (smb_id_t))) == NULL)
		return (NT_STATUS_NO_MEMORY);

	tkn_grps.i_ids->i_sid = smb_sid_dup(token->tkn_primary_grp.i_sid);
	tkn_grps.i_ids->i_attrs = token->tkn_primary_grp.i_attrs;
	if (tkn_grps.i_ids->i_sid == NULL) {
		smb_ids_free(&tkn_grps);
		return (NT_STATUS_NO_MEMORY);
	}

	status = smb_sam_usr_groups(token->tkn_user.i_sid, &tkn_grps);
	if (status != NT_STATUS_SUCCESS) {
		smb_ids_free(&tkn_grps);
		return (status);
	}

	if ((token->tkn_flags & SMB_ATF_ANON) == 0) {
		status = smb_wka_token_groups(B_FALSE, &tkn_grps);
		if (status != NT_STATUS_SUCCESS) {
			smb_ids_free(&tkn_grps);
			return (status);
		}
	}

	token->tkn_win_grps = tkn_grps;
	return (status);
}
