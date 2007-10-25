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
 * Utility functions to support the RPC interface library.
 */

#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include <sys/time.h>
#include <sys/systm.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/lsalib.h>
#include <smbsrv/samlib.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/mlsvc.h>

extern int netr_open(char *, char *, mlsvc_handle_t *);
extern int netr_close(mlsvc_handle_t *);
extern DWORD netlogon_auth(char *, mlsvc_handle_t *, DWORD);
extern int mlsvc_user_getauth(char *, char *, smb_auth_info_t *);

static int mlsvc_lookup_local_name(char *name, nt_sid_t **sid);
static int mlsvc_lookup_nt_name(char *name, nt_sid_t **sid);
static int mlsvc_lookup_nt_sid(nt_sid_t *sid, char *buf, int bufsize);

/*
 * Compare the supplied domain name with the local hostname.
 * We need to deal with both server names and fully-qualified
 * domain names.
 *
 * Returns:
 *	0	The specified domain is not the local domain,
 *	1	The Specified domain is the local domain.
 *	-1	Invalid parameter or unable to get the local
 *		system information.
 */
int
mlsvc_is_local_domain(const char *domain)
{
	char hostname[MAXHOSTNAMELEN];
	uint32_t mode;
	int rc;

	if (strchr(domain, '.') != NULL)
		rc = smb_getfqhostname(hostname, MAXHOSTNAMELEN);
	else
		rc = smb_gethostname(hostname, MAXHOSTNAMELEN, 1);

	if (rc != 0)
		return (-1);

	rc = strcasecmp(domain, hostname);
	mode = smb_get_security_mode();

	if ((rc == 0) || (mode == SMB_SECMODE_WORKGRP))
		return (1);

	return (0);
}

/*
 * mlsvc_lookup_name
 *
 * Lookup a name in the specified domain and translate it to a SID.
 * If the name is in the NT domain, it may refer to a user, group or
 * alias. Otherwise it must refer to a UNIX username. The memory for
 * the sid is allocated using malloc so the caller should call free
 * when it is no longer required.
 *
 * On success, 0 will be returned and sid will point to a local domain
 * user SID. Otherwise -1 will be returned.
 */
int
mlsvc_lookup_name(char *domain, char *name, nt_sid_t **sid)
{
	if (domain == NULL || name == NULL || sid == NULL)
		return (-1);

	if (mlsvc_is_local_domain(domain) == 1)
		return (mlsvc_lookup_local_name(name, sid));
	else
		return (mlsvc_lookup_nt_name(name, sid));
}

/*
 * mlsvc_lookup_local_name
 *
 * Lookup a name in the local password file and translate it to a SID.
 * The name must refer to a user. This is a private function intended
 * to support mlsvc_lookup_name so it doesn't perform any parameter
 * validation. The memory for the sid is allocated using malloc so the
 * caller must call free when it is no longer required.
 *
 * On success, 0 will be returned and sid will point to a local domain
 * user SID. Otherwise -1 will be returned.
 */
static int
mlsvc_lookup_local_name(char *name, nt_sid_t **sid)
{
	struct passwd *pw;
	nt_sid_t *domain_sid;

	if ((pw = getpwnam(name)) == NULL)
		return (-1);

	if ((domain_sid = nt_domain_local_sid()) == NULL)
		return (-1);

	*sid = nt_sid_splice(domain_sid, pw->pw_uid);
	return (0);
}

/*
 * mlsvc_lookup_nt_name
 *
 * Lookup a name in the specified NT domain and translate it to a SID.
 * The name may refer to a user, group or alias. This is a private
 * function intended to support mlsvc_lookup_name so it doesn't do any
 * parameter validation. The memory for the sid is allocated using
 * malloc so the caller should call free when it is no longer required.
 *
 * On success, 0 will be returned and sid will point to an NT domain
 * user SID. Otherwise -1 will be returned.
 */
static int
mlsvc_lookup_nt_name(char *name, nt_sid_t **sid)
{
	smb_userinfo_t *user_info;

	if ((user_info = mlsvc_alloc_user_info()) == NULL)
		return (-1);

	if (lsa_lookup_name(0, 0, name, user_info) != 0)
		return (-1);

	*sid = nt_sid_splice(user_info->domain_sid, user_info->rid);
	mlsvc_free_user_info(user_info);
	return (0);
}

/*
 * mlsvc_lookup_sid
 *
 * Lookup a SID and translate it to a name. The name returned may refer
 * to a domain, user, group or alias dependent on the SID. On success 0
 * will be returned. Otherwise -1 will be returned.
 */
int
mlsvc_lookup_sid(nt_sid_t *sid, char *buf, int bufsize)
{
	struct passwd *pw;
	struct group *gr;
	nt_group_t *grp;
	DWORD rid;

	if (sid == NULL || buf == NULL)
		return (-1);

	if (nt_sid_is_local(sid)) {
		(void) nt_sid_get_rid(sid, &rid);

		switch (SAM_RID_TYPE(rid)) {
		case SAM_RT_NT_UID:
			break;

		case SAM_RT_NT_GID:
			if ((grp = nt_groups_lookup_rid(rid)) == NULL)
				return (-1);

			(void) strlcpy(buf, grp->name, bufsize);
			break;

		case SAM_RT_UNIX_UID:
			if ((pw = getpwuid(SAM_DECODE_RID(rid))) == NULL)
				return (-1);

			(void) strlcpy(buf, pw->pw_name, bufsize);
			break;

		case SAM_RT_UNIX_GID:
			if ((gr = getgrgid(SAM_DECODE_RID(rid))) == NULL)
				return (-1);

			(void) strlcpy(buf, gr->gr_name, bufsize);
			break;
		}

		return (0);
	}

	return (mlsvc_lookup_nt_sid(sid, buf, bufsize));
}

/*
 * mlsvc_lookup_nt_sid
 *
 * Lookup an NT SID and translate it to a name. This is a private
 * function intended to support mlsvc_lookup_sid so it doesn't do any
 * parameter validation. The input account_name specifies the logon/
 * session to be used for the lookup. It doesn't need to have any
 * association with the SID being looked up. The name returned may
 * refer to a domain, user, group or alias dependent on the SID.
 *
 * On success the name will be copied into buf and 0 will be returned.
 * Otherwise -1 will be returned.
 */
static int
mlsvc_lookup_nt_sid(nt_sid_t *sid, char *buf, int bufsize)
{
	smb_userinfo_t *user_info;
	int rc;

	if ((user_info = mlsvc_alloc_user_info()) == NULL)
		return (-1);

	if ((rc = lsa_lookup_sid(sid, user_info)) == 0)
		(void) strlcpy(buf, user_info->name, bufsize);

	mlsvc_free_user_info(user_info);
	return (rc);
}

/*
 * mlsvc_alloc_user_info
 *
 * Allocate a user_info structure and set the contents to zero. A
 * pointer to the user_info structure is returned.
 */
smb_userinfo_t *
mlsvc_alloc_user_info(void)
{
	smb_userinfo_t *user_info;

	user_info = (smb_userinfo_t *)malloc(sizeof (smb_userinfo_t));
	if (user_info == NULL)
		return (NULL);

	bzero(user_info, sizeof (smb_userinfo_t));
	return (user_info);
}

/*
 * mlsvc_free_user_info
 *
 * Free a user_info structure. This function ensures that the contents
 * of the user_info are freed as well as the user_info itself.
 */
void
mlsvc_free_user_info(smb_userinfo_t *user_info)
{
	if (user_info) {
		mlsvc_release_user_info(user_info);
		free(user_info);
	}
}

/*
 * mlsvc_release_user_info
 *
 * Release the contents of a user_info structure and zero out the
 * elements but do not free the user_info structure itself. This
 * function cleans out the structure so that it can be reused without
 * worrying about stale contents.
 */
void
mlsvc_release_user_info(smb_userinfo_t *user_info)
{
	int i;

	if (user_info == NULL)
		return;

	free(user_info->name);
	free(user_info->domain_sid);
	free(user_info->domain_name);
	free(user_info->groups);

	if (user_info->n_other_grps) {
		for (i = 0; i < user_info->n_other_grps; i++)
			free(user_info->other_grps[i].sid);

		free(user_info->other_grps);
	}

	free(user_info->user_sid);
	free(user_info->pgrp_sid);
	bzero(user_info, sizeof (smb_userinfo_t));
}

/*
 * mlsvc_setadmin_user_info
 *
 * Determines if the given user is the domain Administrator or a
 * member of Domain Admins or Administrators group and set the
 * user_info->flags accordingly.
 */
void
mlsvc_setadmin_user_info(smb_userinfo_t *user_info)
{
	nt_domain_t *domain;
	nt_group_t *grp;
	int i;

	if ((domain = nt_domain_lookupbytype(NT_DOMAIN_PRIMARY)) == NULL)
		return;

	if (!nt_sid_is_equal((nt_sid_t *)user_info->domain_sid, domain->sid))
		return;

	if (user_info->rid == DOMAIN_USER_RID_ADMIN)
		user_info->flags |= SMB_UINFO_FLAG_DADMIN;
	else if (user_info->primary_group_rid == DOMAIN_GROUP_RID_ADMINS)
		user_info->flags |= SMB_UINFO_FLAG_DADMIN;
	else {
		for (i = 0; i < user_info->n_groups; i++)
			if (user_info->groups[i].rid == DOMAIN_GROUP_RID_ADMINS)
				user_info->flags |= SMB_UINFO_FLAG_DADMIN;
	}

	grp = nt_group_getinfo("Administrators", RWLOCK_READER);
	if (grp) {
		i = nt_group_is_member(grp, user_info->user_sid);
		nt_group_putinfo(grp);
		if (i)
			user_info->flags |= SMB_UINFO_FLAG_LADMIN;
	}
}

/*
 * mlsvc_string_save
 *
 * This is a convenience function to prepare strings for an RPC call.
 * An ms_string_t is set up with the appropriate lengths and str is
 * set up to point to a copy of the original string on the heap. The
 * macro MLRPC_HEAP_STRSAVE is an alias for mlrpc_heap_strsave, which
 * extends the heap and copies the string into the new area.
 */
int
mlsvc_string_save(ms_string_t *ms, char *str, struct mlrpc_xaction *mxa)
{
	int length;
	char *p;

	if (ms == NULL || str == NULL || mxa == NULL)
		return (0);

	/*
	 * Windows NT expects the name length to exclude the
	 * terminating wchar null but doesn't care whether or
	 * not the allosize includes it. Windows 2000 insists
	 * that both the length and the allosize include the
	 * wchar null.
	 */
	length = mts_wcequiv_strlen(str);
	ms->allosize = length + sizeof (mts_wchar_t);

	if (mxa->context->user_ctx->du_native_os == NATIVE_OS_WIN2000)
		ms->length = ms->allosize;
	else
		ms->length = length;

	if ((p = MLRPC_HEAP_STRSAVE(mxa, str)) == NULL) {
		return (0);
	}

	ms->str = (LPTSTR)p;
	return (1);
}

/*
 * mlsvc_sid_save
 *
 * Expand the heap and copy the sid into the new area.
 * Returns a pointer to the copy of the sid on the heap.
 */
nt_sid_t *
mlsvc_sid_save(nt_sid_t *sid, struct mlrpc_xaction *mxa)
{
	nt_sid_t *heap_sid;
	unsigned size;

	if (sid == NULL)
		return (NULL);

	size = nt_sid_length(sid);

	if ((heap_sid = (nt_sid_t *)MLRPC_HEAP_MALLOC(mxa, size)) == NULL)
		return (0);

	bcopy(sid, heap_sid, size);
	return (heap_sid);
}

/*
 * mlsvc_is_null_handle
 *
 * Check a handle against a null handle. Returns 1 if the handle is
 * null. Otherwise returns 0.
 */
int
mlsvc_is_null_handle(mlsvc_handle_t *handle)
{
	static ms_handle_t zero_handle;

	if (handle == NULL || handle->context == NULL)
		return (1);

	if (!memcmp(&handle->handle, &zero_handle, sizeof (ms_handle_t)))
		return (1);

	return (0);
}

/*
 * mlsvc_validate_user
 *
 * Returns NT status codes.
 */
DWORD
mlsvc_validate_user(char *server, char *domain, char *plain_user,
    char *plain_text)
{
	smb_auth_info_t auth;
	smb_ntdomain_t *di;
	int erc;
	DWORD status;
	mlsvc_handle_t netr_handle;
	char machine_passwd[MLSVC_MACHINE_ACCT_PASSWD_MAX];

	machine_passwd[0] = '\0';

	/*
	 * Ensure that the domain name is uppercase.
	 */
	(void) utf8_strupr(domain);

	/*
	 * There is no point continuing if the domain information is
	 * not available. Wait for up to 10 seconds and then give up.
	 */
	if ((di = smb_getdomaininfo(10)) == 0) {
		status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		return (status);
	}

	if (strcasecmp(domain, di->domain) != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		return (status);
	}

	erc = mlsvc_user_logon(server, domain, plain_user, plain_text);

	if (erc == AUTH_USER_GRANT) {
		int isenabled;

		smb_config_rdlock();
		isenabled = smb_config_getyorn(SMB_CI_ADS_ENABLE);
		smb_config_unlock();
		if (isenabled) {
			if (adjoin(machine_passwd,
			    sizeof (machine_passwd)) == ADJOIN_SUCCESS) {
				status = NT_STATUS_SUCCESS;
			} else {
				status = NT_STATUS_UNSUCCESSFUL;
			}
		} else {
			/*
			 * Ensure that we don't have an old account in
			 * this domain. There's no need to check the
			 * return status.
			 */
			(void) sam_remove_trust_account(server, domain);

			if (mlsvc_user_getauth(server, plain_user, &auth)
			    != 0) {
				status = NT_STATUS_INVALID_PARAMETER;
				return (status);
			}

			status = sam_create_trust_account(server, domain,
			    &auth);
			if (status == NT_STATUS_SUCCESS) {
				(void) smb_gethostname(machine_passwd,
				    sizeof (machine_passwd), 0);
				(void) utf8_strlwr(machine_passwd);
			}
		}

		if (status == NT_STATUS_SUCCESS) {
			smb_config_wrlock();
			if (smb_config_set(SMB_CI_MACHINE_PASSWD,
			    machine_passwd) != 0) {
				smb_config_unlock();
				return (NT_STATUS_UNSUCCESSFUL);
			}
			smb_config_unlock();

			/*
			 * If we successfully create a trust account, we mark
			 * ourselves as a domain member in the environment so
			 * that we use the SAMLOGON version of the NETLOGON
			 * PDC location protocol.
			 */
			smb_set_domain_member(1);

			if (netr_open(server, domain, &netr_handle) == 0) {
				status = netlogon_auth(server, &netr_handle,
				    NETR_FLG_INIT);
				(void) netr_close(&netr_handle);
			} else {
				status = NT_STATUS_OPEN_FAILED;
			}
		}
	} else {
		status = NT_STATUS_LOGON_FAILURE;
	}

	return (status);
}

/*ARGSUSED*/
void
nt_group_ht_lock(krwmode_t locktype)
{
}

void
nt_group_ht_unlock(void)
{
}

int
nt_group_num_groups(void)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
nt_group_add(char *gname, char *comment)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
uint32_t
nt_group_modify(char *gname, char *new_gname, char *comment)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
uint32_t
nt_group_delete(char *gname)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
nt_group_t *
nt_group_getinfo(char *gname, krwmode_t locktype)
{
	return (NULL);
}

/*ARGSUSED*/
void
nt_group_putinfo(nt_group_t *grp)
{
}

/*ARGSUSED*/
int
nt_group_getpriv(nt_group_t *grp, uint32_t priv_id)
{
	return (SE_PRIVILEGE_DISABLED);
}

/*ARGSUSED*/
uint32_t
nt_group_setpriv(nt_group_t *grp, uint32_t priv_id, uint32_t new_attr)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
int
nt_group_is_member(nt_group_t *grp, nt_sid_t *sid)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
nt_group_add_member(nt_group_t *grp, nt_sid_t *msid, uint16_t sid_name_use,
    char *account)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
uint32_t
nt_group_del_member(nt_group_t *grp, void *key, int keytype)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
int
nt_group_num_members(nt_group_t *grp)
{
	return (0);
}

nt_group_iterator_t *
nt_group_open_iterator(void)
{
	return (NULL);
}

/*ARGSUSED*/
void
nt_group_close_iterator(nt_group_iterator_t *gi)
{
}

/*ARGSUSED*/
nt_group_t *
nt_group_iterate(nt_group_iterator_t *gi)
{
	return (NULL);
}

int
nt_group_cache_size(void)
{
	return (0);
}

uint32_t
sam_init(void)
{
	return (NT_STATUS_SUCCESS);
}

/*ARGSUSED*/
uint32_t
nt_group_add_member_byname(char *gname, char *account)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
uint32_t
nt_group_del_member_byname(nt_group_t *grp, char *member_name)
{
	return (NT_STATUS_NOT_SUPPORTED);
}

/*ARGSUSED*/
void
nt_group_add_groupprivs(nt_group_t *grp, smb_privset_t *priv)
{
}

/*ARGSUSED*/
uint32_t
nt_groups_member_privs(nt_sid_t *sid, smb_privset_t *priv)
{
	return (NT_STATUS_SUCCESS);
}

/*ARGSUSED*/
int
nt_groups_member_ngroups(nt_sid_t *sid)
{
	return (0);
}

/*ARGSUSED*/
uint32_t
nt_groups_member_groups(nt_sid_t *sid, smb_id_t *grps, int ngrps)
{
	return (NT_STATUS_SUCCESS);
}

/*ARGSUSED*/
nt_group_t *
nt_groups_lookup_rid(uint32_t rid)
{
	return (NULL);
}

/*ARGSUSED*/
int
nt_groups_count(int cnt_opt)
{
	return (0);
}

/*ARGSUSED*/
int
nt_group_member_list(int offset, nt_group_t *grp,
    ntgrp_member_list_t *rmembers)
{
	return (0);
}

/*ARGSUSED*/
void
nt_group_list(int offset, char *pattern, ntgrp_list_t *list)
{
}
