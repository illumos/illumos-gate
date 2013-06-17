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

#include <strings.h>
#include <smbsrv/libsmb.h>

extern int smb_pwd_num(void);
extern int smb_lgrp_numbydomain(smb_domain_type_t, int *);

static uint32_t smb_sam_lookup_user(char *, smb_sid_t **);
static uint32_t smb_sam_lookup_group(char *, smb_sid_t **);

/*
 * Local well-known accounts data structure table and prototypes
 */
typedef struct smb_lwka {
	uint32_t	lwka_rid;
	char		*lwka_name;
	uint16_t	lwka_type;
} smb_lwka_t;

static smb_lwka_t lwka_tbl[] = {
	{ 500, "Administrator", SidTypeUser },
	{ 501, "Guest", SidTypeUser },
	{ 502, "KRBTGT", SidTypeUser },
	{ 512, "Domain Admins", SidTypeGroup },
	{ 513, "Domain Users", SidTypeGroup },
	{ 514, "Domain Guests", SidTypeGroup },
	{ 516, "Domain Controllers", SidTypeGroup },
	{ 517, "Cert Publishers", SidTypeGroup },
	{ 518, "Schema Admins", SidTypeGroup },
	{ 519, "Enterprise Admins", SidTypeGroup },
	{ 520, "Global Policy Creator Owners", SidTypeGroup },
	{ 533, "RAS and IAS Servers", SidTypeGroup }
};

#define	SMB_LWKA_NUM	(sizeof (lwka_tbl)/sizeof (lwka_tbl[0]))

static smb_lwka_t *smb_lwka_lookup_name(char *);
static smb_lwka_t *smb_lwka_lookup_sid(smb_sid_t *);

/*
 * Looks up the given name in local account databases:
 *
 * SMB Local users are looked up in /var/smb/smbpasswd
 * SMB Local groups are looked up in /var/smb/smbgroup.db
 *
 * If the account is found, its information is populated
 * in the passed smb_account_t structure. Caller must free
 * allocated memories by calling smb_account_free() upon
 * successful return.
 *
 * The type of account is specified by 'type', which can be user,
 * alias (local group) or unknown. If the caller doesn't know
 * whether the name is a user or group name then SidTypeUnknown
 * should be passed.
 *
 * If a local user and group have the same name, the user will
 * always be picked. Note that this situation cannot happen on
 * Windows systems.
 *
 * If a SMB local user/group is found but it turns out that
 * it'll be mapped to a domain user/group the lookup is considered
 * failed and NT_STATUS_NONE_MAPPED is returned.
 *
 * Return status:
 *
 *   NT_STATUS_NOT_FOUND	This is not a local account
 *   NT_STATUS_NONE_MAPPED	It's a local account but cannot be
 *   				translated.
 *   other error status codes.
 */
uint32_t
smb_sam_lookup_name(char *domain, char *name, uint16_t type,
    smb_account_t *account)
{
	smb_domain_t di;
	smb_sid_t *sid;
	uint32_t status;
	smb_lwka_t *lwka;

	bzero(account, sizeof (smb_account_t));

	if (domain != NULL) {
		if (!smb_domain_lookup_name(domain, &di) ||
		    (di.di_type != SMB_DOMAIN_LOCAL))
			return (NT_STATUS_NOT_FOUND);

		/* Only Netbios hostname is accepted */
		if (smb_strcasecmp(domain, di.di_nbname, 0) != 0)
			return (NT_STATUS_NONE_MAPPED);
	} else {
		if (!smb_domain_lookup_type(SMB_DOMAIN_LOCAL, &di))
			return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	if (smb_strcasecmp(name, di.di_nbname, 0) == 0) {
		/* This is the local domain name */
		account->a_type = SidTypeDomain;
		account->a_name = strdup("");
		account->a_domain = strdup(di.di_nbname);
		account->a_sid = smb_sid_dup(di.di_binsid);
		account->a_domsid = smb_sid_dup(di.di_binsid);
		account->a_rid = (uint32_t)-1;

		if (!smb_account_validate(account)) {
			smb_account_free(account);
			return (NT_STATUS_NO_MEMORY);
		}

		return (NT_STATUS_SUCCESS);
	}

	if ((lwka = smb_lwka_lookup_name(name)) != NULL) {
		sid = smb_sid_splice(di.di_binsid, lwka->lwka_rid);
		type = lwka->lwka_type;
	} else {
		switch (type) {
		case SidTypeUser:
			status = smb_sam_lookup_user(name, &sid);
			if (status != NT_STATUS_SUCCESS)
				return (status);
			break;

		case SidTypeAlias:
			status = smb_sam_lookup_group(name, &sid);
			if (status != NT_STATUS_SUCCESS)
				return (status);
			break;

		case SidTypeUnknown:
			type = SidTypeUser;
			status = smb_sam_lookup_user(name, &sid);
			if (status == NT_STATUS_SUCCESS)
				break;

			if (status == NT_STATUS_NONE_MAPPED)
				return (status);

			type = SidTypeAlias;
			status = smb_sam_lookup_group(name, &sid);
			if (status != NT_STATUS_SUCCESS)
				return (status);
			break;

		default:
			return (NT_STATUS_INVALID_PARAMETER);
		}
	}

	account->a_name = strdup(name);
	account->a_sid = sid;
	account->a_domain = strdup(di.di_nbname);
	account->a_domsid = smb_sid_split(sid, &account->a_rid);
	account->a_type = type;

	if (!smb_account_validate(account)) {
		smb_account_free(account);
		return (NT_STATUS_NO_MEMORY);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * Looks up the given SID in local account databases:
 *
 * SMB Local users are looked up in /var/smb/smbpasswd
 * SMB Local groups are looked up in /var/smb/smbgroup.db
 *
 * If the account is found, its information is populated
 * in the passed smb_account_t structure. Caller must free
 * allocated memories by calling smb_account_free() upon
 * successful return.
 *
 * Return status:
 *
 *   NT_STATUS_NOT_FOUND	This is not a local account
 *   NT_STATUS_NONE_MAPPED	It's a local account but cannot be
 *   				translated.
 *   other error status codes.
 */
uint32_t
smb_sam_lookup_sid(smb_sid_t *sid, smb_account_t *account)
{
	char hostname[MAXHOSTNAMELEN];
	smb_passwd_t smbpw;
	smb_group_t grp;
	smb_lwka_t *lwka;
	smb_domain_t di;
	uint32_t rid;
	uid_t id;
	int id_type;
	int rc;

	bzero(account, sizeof (smb_account_t));

	if (!smb_domain_lookup_type(SMB_DOMAIN_LOCAL, &di))
		return (NT_STATUS_CANT_ACCESS_DOMAIN_INFO);

	if (smb_sid_cmp(sid, di.di_binsid)) {
		/* This is the local domain SID */
		account->a_type = SidTypeDomain;
		account->a_name = strdup("");
		account->a_domain = strdup(di.di_nbname);
		account->a_sid = smb_sid_dup(sid);
		account->a_domsid = smb_sid_dup(sid);
		account->a_rid = (uint32_t)-1;

		if (!smb_account_validate(account)) {
			smb_account_free(account);
			return (NT_STATUS_NO_MEMORY);
		}

		return (NT_STATUS_SUCCESS);
	}

	if (!smb_sid_indomain(di.di_binsid, sid)) {
		/* This is not a local SID */
		return (NT_STATUS_NOT_FOUND);
	}

	if ((lwka = smb_lwka_lookup_sid(sid)) != NULL) {
		account->a_type = lwka->lwka_type;
		account->a_name = strdup(lwka->lwka_name);
	} else {
		id_type = SMB_IDMAP_UNKNOWN;
		if (smb_idmap_getid(sid, &id, &id_type) != IDMAP_SUCCESS)
			return (NT_STATUS_NONE_MAPPED);

		switch (id_type) {
		case SMB_IDMAP_USER:
			account->a_type = SidTypeUser;
			if (smb_pwd_getpwuid(id, &smbpw) == NULL)
				return (NT_STATUS_NO_SUCH_USER);

			account->a_name = strdup(smbpw.pw_name);
			break;

		case SMB_IDMAP_GROUP:
			account->a_type = SidTypeAlias;
			(void) smb_sid_getrid(sid, &rid);
			rc = smb_lgrp_getbyrid(rid, SMB_DOMAIN_LOCAL, &grp);
			if (rc != SMB_LGRP_SUCCESS)
				return (NT_STATUS_NO_SUCH_ALIAS);

			account->a_name = strdup(grp.sg_name);
			smb_lgrp_free(&grp);
			break;

		default:
			return (NT_STATUS_NONE_MAPPED);
		}
	}

	if (smb_getnetbiosname(hostname, MAXHOSTNAMELEN) == 0)
		account->a_domain = strdup(hostname);
	account->a_sid = smb_sid_dup(sid);
	account->a_domsid = smb_sid_split(sid, &account->a_rid);

	if (!smb_account_validate(account)) {
		smb_account_free(account);
		return (NT_STATUS_NO_MEMORY);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * Returns number of SMB users, i.e. users who have entry
 * in /var/smb/smbpasswd
 */
int
smb_sam_usr_cnt(void)
{
	return (smb_pwd_num());
}

/*
 * Updates a list of groups in which the given user is a member
 * by adding any local (SAM) groups.
 *
 * We are a member of local groups where the local group
 * contains either the user's primary SID, or any of their
 * other SIDs such as from domain groups, SID history, etc.
 * We can have indirect membership via domain groups.
 */
uint32_t
smb_sam_usr_groups(smb_sid_t *user_sid, smb_ids_t *gids)
{
	smb_ids_t new_gids;
	smb_id_t *ids, *new_ids;
	smb_giter_t gi;
	smb_group_t lgrp;
	int i, gcnt, total_cnt;
	uint32_t ret;
	boolean_t member;

	/*
	 * First pass: count groups to be added (gcnt)
	 */
	gcnt = 0;
	if (smb_lgrp_iteropen(&gi) != SMB_LGRP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	while (smb_lgrp_iterate(&gi, &lgrp) == SMB_LGRP_SUCCESS) {
		member = B_FALSE;
		if (smb_lgrp_is_member(&lgrp, user_sid))
			member = B_TRUE;
		else for (i = 0, ids = gids->i_ids;
		    i < gids->i_cnt; i++, ids++) {
			if (smb_lgrp_is_member(&lgrp, ids->i_sid)) {
				member = B_TRUE;
				break;
			}
		}
		/* Careful: only count lgrp once */
		if (member)
			gcnt++;
		smb_lgrp_free(&lgrp);
	}
	smb_lgrp_iterclose(&gi);

	if (gcnt == 0)
		return (NT_STATUS_SUCCESS);

	/*
	 * Second pass: add to groups list.
	 * Do not modify gcnt after here.
	 */
	if (smb_lgrp_iteropen(&gi) != SMB_LGRP_SUCCESS)
		return (NT_STATUS_INTERNAL_ERROR);

	/*
	 * Expand the list (copy to a new, larger one)
	 * Note: were're copying pointers from the old
	 * array to the new (larger) array, and then
	 * adding new pointers after what we copied.
	 */
	ret = 0;
	new_gids.i_cnt = gids->i_cnt;
	total_cnt = gids->i_cnt + gcnt;
	new_gids.i_ids = malloc(total_cnt * sizeof (smb_id_t));
	if (new_gids.i_ids == NULL) {
		ret = NT_STATUS_NO_MEMORY;
		goto out;
	}
	(void) memcpy(new_gids.i_ids, gids->i_ids,
	    gids->i_cnt * sizeof (smb_id_t));
	new_ids = new_gids.i_ids + gids->i_cnt;
	(void) memset(new_ids, 0, gcnt * sizeof (smb_id_t));

	/*
	 * Add group SIDs starting at the end of the
	 * previous list.  (new_ids)
	 */
	while (smb_lgrp_iterate(&gi, &lgrp) == SMB_LGRP_SUCCESS) {
		member = B_FALSE;
		if (smb_lgrp_is_member(&lgrp, user_sid))
			member = B_TRUE;
		else for (i = 0, ids = gids->i_ids;
		    i < gids->i_cnt; i++, ids++) {
			if (smb_lgrp_is_member(&lgrp, ids->i_sid)) {
				member = B_TRUE;
				break;
			}
		}
		if (member && (new_gids.i_cnt < (gids->i_cnt + gcnt))) {
			new_ids->i_sid = smb_sid_dup(lgrp.sg_id.gs_sid);
			if (new_ids->i_sid == NULL) {
				smb_lgrp_free(&lgrp);
				ret = NT_STATUS_NO_MEMORY;
				goto out;
			}
			new_ids->i_attrs = lgrp.sg_attr;
			new_ids++;
			new_gids.i_cnt++;
		}
		smb_lgrp_free(&lgrp);
	}

out:
	smb_lgrp_iterclose(&gi);

	if (ret != 0) {
		if (new_gids.i_ids != NULL) {
			/*
			 * Free only the new sids we added.
			 * The old ones were copied ptrs.
			 */
			ids = new_gids.i_ids + gids->i_cnt;
			for (i = 0; i < gcnt; i++, ids++) {
				smb_sid_free(ids->i_sid);
			}
			free(new_gids.i_ids);
		}
		return (ret);
	}

	/*
	 * Success! Update passed gids and
	 * free the old array.
	 */
	free(gids->i_ids);
	*gids = new_gids;

	return (NT_STATUS_SUCCESS);
}

/*
 * Returns the number of built-in or local groups stored
 * in /var/smb/smbgroup.db
 */
int
smb_sam_grp_cnt(smb_domain_type_t dtype)
{
	int grpcnt;
	int rc;

	switch (dtype) {
	case SMB_DOMAIN_BUILTIN:
		rc = smb_lgrp_numbydomain(SMB_DOMAIN_BUILTIN, &grpcnt);
		break;

	case SMB_DOMAIN_LOCAL:
		rc = smb_lgrp_numbydomain(SMB_DOMAIN_LOCAL, &grpcnt);
		break;

	default:
		rc = SMB_LGRP_INVALID_ARG;
	}

	return ((rc == SMB_LGRP_SUCCESS) ? grpcnt : 0);
}

/*
 * Determines whether the given SID is a member of the group
 * specified by gname.
 */
boolean_t
smb_sam_grp_ismember(const char *gname, smb_sid_t *sid)
{
	smb_group_t grp;
	boolean_t ismember = B_FALSE;

	if (smb_lgrp_getbyname((char *)gname, &grp) == SMB_LGRP_SUCCESS) {
		ismember = smb_lgrp_is_member(&grp, sid);
		smb_lgrp_free(&grp);
	}

	return (ismember);
}

/*
 * Frees memories allocated for the passed account fields.
 */
void
smb_account_free(smb_account_t *account)
{
	free(account->a_name);
	free(account->a_domain);
	smb_sid_free(account->a_sid);
	smb_sid_free(account->a_domsid);
}

/*
 * Validates the given account.
 */
boolean_t
smb_account_validate(smb_account_t *account)
{
	return ((account->a_name != NULL) && (account->a_sid != NULL) &&
	    (account->a_domain != NULL) && (account->a_domsid != NULL));
}

/*
 * Lookup local SMB user account database (/var/smb/smbpasswd)
 * if there's a match query its SID from idmap service and make
 * sure the SID is a local SID.
 *
 * The memory for the returned SID must be freed by the caller.
 */
static uint32_t
smb_sam_lookup_user(char *name, smb_sid_t **sid)
{
	smb_passwd_t smbpw;

	if (smb_pwd_getpwnam(name, &smbpw) == NULL)
		return (NT_STATUS_NO_SUCH_USER);

	if (smb_idmap_getsid(smbpw.pw_uid, SMB_IDMAP_USER, sid)
	    != IDMAP_SUCCESS)
		return (NT_STATUS_NONE_MAPPED);

	if (!smb_sid_islocal(*sid)) {
		smb_sid_free(*sid);
		return (NT_STATUS_NONE_MAPPED);
	}

	return (NT_STATUS_SUCCESS);
}

/*
 * Lookup local SMB group account database (/var/smb/smbgroup.db)
 * The memory for the returned SID must be freed by the caller.
 */
static uint32_t
smb_sam_lookup_group(char *name, smb_sid_t **sid)
{
	smb_group_t grp;

	if (smb_lgrp_getbyname(name, &grp) != SMB_LGRP_SUCCESS)
		return (NT_STATUS_NO_SUCH_ALIAS);

	*sid = smb_sid_dup(grp.sg_id.gs_sid);
	smb_lgrp_free(&grp);

	return ((*sid == NULL) ? NT_STATUS_NO_MEMORY : NT_STATUS_SUCCESS);
}

static smb_lwka_t *
smb_lwka_lookup_name(char *name)
{
	int i;

	for (i = 0; i < SMB_LWKA_NUM; i++) {
		if (smb_strcasecmp(name, lwka_tbl[i].lwka_name, 0) == 0)
			return (&lwka_tbl[i]);
	}

	return (NULL);
}

static smb_lwka_t *
smb_lwka_lookup_sid(smb_sid_t *sid)
{
	uint32_t rid;
	int i;

	(void) smb_sid_getrid(sid, &rid);
	if (rid > 999)
		return (NULL);

	for (i = 0; i < SMB_LWKA_NUM; i++) {
		if (rid == lwka_tbl[i].lwka_rid)
			return (&lwka_tbl[i]);
	}

	return (NULL);
}

/*
 * smb_sid_islocal
 *
 * Check a SID to see if it belongs to the local domain.
 */
boolean_t
smb_sid_islocal(smb_sid_t *sid)
{
	smb_domain_t di;
	boolean_t islocal = B_FALSE;

	if (smb_domain_lookup_type(SMB_DOMAIN_LOCAL, &di))
		islocal = smb_sid_indomain(di.di_binsid, sid);

	return (islocal);
}

void
smb_ids_free(smb_ids_t *ids)
{
	smb_id_t *id;
	int i;

	if ((ids != NULL) && (ids->i_ids != NULL)) {
		id = ids->i_ids;
		for (i = 0; i < ids->i_cnt; i++, id++)
			smb_sid_free(id->i_sid);

		free(ids->i_ids);
	}
}
