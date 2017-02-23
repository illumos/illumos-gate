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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <unistd.h>
#include <strings.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <syslog.h>
#include <assert.h>
#include <synch.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_token.h>
#include <lsalib.h>

static smb_account_t smb_guest;
static smb_account_t smb_domusers;
static rwlock_t smb_logoninit_rwl;

typedef void (*smb_logonop_t)(smb_logon_t *, smb_token_t *);

static void smb_logon_local(smb_logon_t *, smb_token_t *);
static void smb_logon_guest(smb_logon_t *, smb_token_t *);
static void smb_logon_anon(smb_logon_t *, smb_token_t *);

static uint32_t smb_token_auth_local(smb_logon_t *, smb_token_t *,
    smb_passwd_t *);

static uint32_t smb_token_setup_local(smb_passwd_t *, smb_token_t *);
static uint32_t smb_token_setup_guest(smb_logon_t *, smb_token_t *);
static uint32_t smb_token_setup_anon(smb_token_t *token);

static boolean_t smb_token_is_member(smb_token_t *, smb_sid_t *);
static uint32_t smb_token_setup_wingrps(smb_token_t *);
static smb_posix_grps_t *smb_token_create_pxgrps(uid_t);

static void smb_guest_account(char *, size_t);

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
	int nmaps;
	smb_idmap_batch_t sib;

	/*
	 * Number of idmap lookups: user SID, owner SID, primary group SID,
	 * and all Windows group SIDs. Skip user/owner SID for Anonymous.
	 */
	if (token->tkn_flags & SMB_ATF_ANON)
		nmaps = token->tkn_win_grps.i_cnt + 1;
	else
		nmaps = token->tkn_win_grps.i_cnt + 3;

	stat = smb_idmap_batch_create(&sib, nmaps, SMB_IDMAP_SID2ID);
	if (stat != IDMAP_SUCCESS)
		return (-1);

	stat = smb_token_idmap(token, &sib);
	if (stat != IDMAP_SUCCESS) {
		smb_idmap_batch_destroy(&sib);
		return (-1);
	}

	stat = smb_idmap_batch_getmappings(&sib);
	smb_idmap_check("smb_idmap_batch_getmappings", stat);
	smb_idmap_batch_destroy(&sib);

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
		free(token->tkn_ssnkey.val);
		bzero(token, sizeof (smb_token_t));
		free(token);
	}
}

/*
 * Token owner should be set to local Administrators group
 * in two cases:
 *   1. The logged on user is a member of Domain Admins group
 *   2. They are a member of local Administrators group
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
		char admgrp[] = "Administrators";

		rc = smb_lgrp_getbyname(admgrp, &grp);
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
 *
 * Returns B_TRUE for success.
 */
boolean_t
smb_token_setup_common(smb_token_t *token)
{
	smb_token_set_flags(token);

	smb_token_set_owner(token);
	if (token->tkn_owner.i_sid == NULL)
		return (B_FALSE);

	/* Privileges */
	token->tkn_privileges = smb_token_create_privs(token);
	if (token->tkn_privileges == NULL)
		return (B_FALSE);

	if (smb_token_sids2ids(token) != 0) {
		syslog(LOG_ERR, "%s\\%s: idmap failed",
		    token->tkn_domain_name, token->tkn_account_name);
		return (B_FALSE);
	}

	/* Solaris Groups */
	token->tkn_posix_grps = smb_token_create_pxgrps(token->tkn_user.i_id);

	return (smb_token_valid(token));
}

uint32_t
smb_logon_init(void)
{
	uint32_t status;

	(void) rw_wrlock(&smb_logoninit_rwl);
	status = smb_sam_lookup_name(NULL, "guest", SidTypeUser, &smb_guest);
	if (status != NT_STATUS_SUCCESS) {
		(void) rw_unlock(&smb_logoninit_rwl);
		return (status);
	}

	status = smb_sam_lookup_name(NULL, "domain users", SidTypeGroup,
	    &smb_domusers);
	if (status != NT_STATUS_SUCCESS) {
		smb_account_free(&smb_guest);
		bzero(&smb_guest, sizeof (smb_account_t));
		(void) rw_unlock(&smb_logoninit_rwl);
		return (status);
	}

	(void) rw_unlock(&smb_logoninit_rwl);
	return (status);
}

void
smb_logon_fini(void)
{
	(void) rw_wrlock(&smb_logoninit_rwl);
	smb_account_free(&smb_guest);
	smb_account_free(&smb_domusers);
	bzero(&smb_guest, sizeof (smb_account_t));
	bzero(&smb_domusers, sizeof (smb_account_t));
	(void) rw_unlock(&smb_logoninit_rwl);
}

/*
 * Perform user authentication.
 *
 * The dispatched functions must only update the user_info status if they
 * attempt to authenticate the user.
 *
 * On success, a pointer to a new access token is returned.
 */
smb_token_t *
smb_logon(smb_logon_t *user_info)
{
	static smb_logonop_t	ops[] = {
		smb_logon_anon,
		smb_logon_local,
		smb_logon_domain,
		smb_logon_guest
	};
	smb_token_t		*token = NULL;
	smb_domain_t		domain;
	int			n_op = (sizeof (ops) / sizeof (ops[0]));
	int			i;

	user_info->lg_secmode = smb_config_get_secmode();
	user_info->lg_status = NT_STATUS_NO_SUCH_USER;

	if (smb_domain_lookup_name(user_info->lg_e_domain, &domain))
		user_info->lg_domain_type = domain.di_type;
	else
		user_info->lg_domain_type = SMB_DOMAIN_NULL;

	if ((token = calloc(1, sizeof (smb_token_t))) == NULL) {
		syslog(LOG_ERR, "logon[%s\\%s]: %m",
		    user_info->lg_e_domain, user_info->lg_e_username);
		return (NULL);
	}

	for (i = 0; i < n_op; ++i) {
		(*ops[i])(user_info, token);

		if (user_info->lg_status == NT_STATUS_SUCCESS)
			break;
	}

	if (user_info->lg_status == NT_STATUS_SUCCESS) {
		if (smb_token_setup_common(token))
			return (token);
	}

	smb_token_destroy(token);
	return (NULL);
}

/*
 * If the user has an entry in the local database, attempt local authentication.
 *
 * In domain mode, we try to exclude domain accounts, which we do by only
 * accepting local or null (blank) domain names here.  Some clients (Mac OS)
 * don't always send the domain name.
 *
 * If we are not going to attempt authentication, this function must return
 * without updating the status.
 */
static void
smb_logon_local(smb_logon_t *user_info, smb_token_t *token)
{
	char guest[SMB_USERNAME_MAXLEN];
	smb_passwd_t smbpw;
	uint32_t status;

	if (user_info->lg_secmode == SMB_SECMODE_DOMAIN) {
		if ((user_info->lg_domain_type != SMB_DOMAIN_LOCAL) &&
		    (user_info->lg_domain_type != SMB_DOMAIN_NULL))
			return;
	}

	/*
	 * If the requested account name is "guest" (or whatever
	 * our guest account is named) then don't handle it here.
	 * Let this request fall through to smb_logon_guest().
	 */
	smb_guest_account(guest, SMB_USERNAME_MAXLEN);
	if (smb_strcasecmp(guest, user_info->lg_e_username, 0) == 0)
		return;

	status = smb_token_auth_local(user_info, token, &smbpw);
	if (status == NT_STATUS_SUCCESS)
		status = smb_token_setup_local(&smbpw, token);

	user_info->lg_status = status;
}

/*
 * Guest authentication.  This may be a local guest account or the guest
 * account may be mapped to a local account.  These accounts are regular
 * accounts with normal password protection.
 *
 * Only proceed with a guest logon if previous logon options have resulted
 * in NO_SUCH_USER.
 *
 * If we are not going to attempt authentication, this function must return
 * without updating the status.
 */
static void
smb_logon_guest(smb_logon_t *user_info, smb_token_t *token)
{
	char guest[SMB_USERNAME_MAXLEN];
	smb_passwd_t smbpw;
	char *temp;

	if (user_info->lg_status != NT_STATUS_NO_SUCH_USER)
		return;

	/* Get the name of the guest account. */
	smb_guest_account(guest, SMB_USERNAME_MAXLEN);

	/* Does the guest account exist? */
	if (smb_pwd_getpwnam(guest, &smbpw) == NULL)
		return;

	/* Is it enabled? (empty p/w is OK) */
	if (smbpw.pw_flags & SMB_PWF_DISABLE)
		return;

	/*
	 * OK, give the client a guest logon.  Note that on entry,
	 * lg_e_username is typically something other than "guest"
	 * so we need to set the effective username when createing
	 * the guest token.
	 */
	temp = user_info->lg_e_username;
	user_info->lg_e_username = guest;
	user_info->lg_status = smb_token_setup_guest(user_info, token);
	user_info->lg_e_username = temp;
}

/*
 * If user_info represents an anonymous user then setup the token.
 * Otherwise return without updating the status.
 */
static void
smb_logon_anon(smb_logon_t *user_info, smb_token_t *token)
{
	if (user_info->lg_flags & SMB_ATF_ANON)
		user_info->lg_status = smb_token_setup_anon(token);
}

/*
 * Try both LM hash and NT hashes with user's password(s) to authenticate
 * the user.
 */
static uint32_t
smb_token_auth_local(smb_logon_t *user_info, smb_token_t *token,
    smb_passwd_t *smbpw)
{
	boolean_t ok;
	uint32_t status = NT_STATUS_SUCCESS;

	if (smb_pwd_getpwnam(user_info->lg_e_username, smbpw) == NULL)
		return (NT_STATUS_NO_SUCH_USER);

	if (smbpw->pw_flags & SMB_PWF_DISABLE)
		return (NT_STATUS_ACCOUNT_DISABLED);

	if ((smbpw->pw_flags & (SMB_PWF_LM | SMB_PWF_NT)) == 0) {
		/*
		 * The SMB passwords have not been set.
		 * Return an error that suggests the
		 * password needs to be set.
		 */
		return (NT_STATUS_PASSWORD_EXPIRED);
	}

	token->tkn_ssnkey.val = malloc(SMBAUTH_SESSION_KEY_SZ);
	if (token->tkn_ssnkey.val == NULL)
		return (NT_STATUS_NO_MEMORY);
	token->tkn_ssnkey.len = SMBAUTH_SESSION_KEY_SZ;

	ok = smb_auth_validate(
	    smbpw,
	    user_info->lg_domain,
	    user_info->lg_username,
	    user_info->lg_challenge_key.val,
	    user_info->lg_challenge_key.len,
	    user_info->lg_nt_password.val,
	    user_info->lg_nt_password.len,
	    user_info->lg_lm_password.val,
	    user_info->lg_lm_password.len,
	    token->tkn_ssnkey.val);
	if (ok)
		return (NT_STATUS_SUCCESS);

	free(token->tkn_ssnkey.val);
	token->tkn_ssnkey.val = NULL;
	token->tkn_ssnkey.len = 0;

	status = NT_STATUS_WRONG_PASSWORD;
	syslog(LOG_NOTICE, "logon[%s\\%s]: %s",
	    user_info->lg_e_domain, user_info->lg_e_username,
	    xlate_nt_status(status));

	return (status);
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
 * Setup access token for guest connections
 */
static uint32_t
smb_token_setup_guest(smb_logon_t *user_info, smb_token_t *token)
{
	token->tkn_account_name = strdup(user_info->lg_e_username);

	(void) rw_rdlock(&smb_logoninit_rwl);
	token->tkn_domain_name = strdup(smb_guest.a_domain);
	token->tkn_user.i_sid = smb_sid_dup(smb_guest.a_sid);
	token->tkn_primary_grp.i_sid = smb_sid_dup(smb_domusers.a_sid);
	(void) rw_unlock(&smb_logoninit_rwl);
	token->tkn_flags = SMB_ATF_GUEST;

	if (token->tkn_account_name == NULL ||
	    token->tkn_domain_name == NULL ||
	    token->tkn_user.i_sid == NULL ||
	    token->tkn_primary_grp.i_sid == NULL)
		return (NT_STATUS_NO_MEMORY);

	return (smb_token_setup_wingrps(token));
}

/*
 * Setup access token for anonymous connections
 */
static uint32_t
smb_token_setup_anon(smb_token_t *token)
{
	smb_sid_t *user_sid;

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

	status = smb_wka_token_groups(token->tkn_flags, &tkn_grps);
	if (status != NT_STATUS_SUCCESS) {
		smb_ids_free(&tkn_grps);
		return (status);
	}

	token->tkn_win_grps = tkn_grps;
	return (status);
}

/*
 * Returns the guest account name in the provided buffer.
 *
 * By default the name would be "guest" unless there's
 * a idmap name-based rule which maps the guest to a local
 * Solaris user in which case the name of that user is
 * returned.
 */
static void
smb_guest_account(char *guest, size_t buflen)
{
	idmap_stat stat;
	uid_t guest_uid;
	struct passwd pw;
	char pwbuf[1024];
	int idtype;

	/* default Guest account name */
	(void) rw_rdlock(&smb_logoninit_rwl);
	(void) strlcpy(guest, smb_guest.a_name, buflen);

	idtype = SMB_IDMAP_USER;
	stat = smb_idmap_getid(smb_guest.a_sid, &guest_uid, &idtype);
	(void) rw_unlock(&smb_logoninit_rwl);

	if (stat != IDMAP_SUCCESS)
		return;

	/* If Ephemeral ID return the default name */
	if (IDMAP_ID_IS_EPHEMERAL(guest_uid))
		return;

	if (getpwuid_r(guest_uid, &pw, pwbuf, sizeof (pwbuf)) == NULL)
		return;

	(void) strlcpy(guest, pw.pw_name, buflen);
}
