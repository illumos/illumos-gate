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
 * Security Accounts Manager RPC (SAMR) interface definition.
 */

#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/ntsid.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/samrpc.ndl>
#include <smbsrv/samlib.h>

/*
 * The keys associated with the various handles dispensed
 * by the SAMR server. These keys can be used to validate
 * client activity. These values are never passed over
 * the network so security shouldn't be an issue.
 */
#define	SAMR_CONNECT_KEY	"SamrConnect"
#define	SAMR_DOMAIN_KEY		"SamrDomain"
#define	SAMR_USER_KEY		"SamrUser"
#define	SAMR_GROUP_KEY		"SamrGroup"
#define	SAMR_ALIAS_KEY		"SamrAlias"

/*
 * Domain discriminator values. Set the top bit to try
 * to distinguish these values from user and group ids.
 */
#define	SAMR_DATABASE_DOMAIN	0x80000001
#define	SAMR_LOCAL_DOMAIN	0x80000002
#define	SAMR_BUILTIN_DOMAIN	0x80000003
#define	SAMR_PRIMARY_DOMAIN	0x80000004

static DWORD samr_s_enum_local_domains(struct samr_EnumLocalDomain *,
    struct mlrpc_xaction *);

static mlrpc_stub_table_t samr_stub_table[];

static mlrpc_service_t samr_service = {
	"SAMR",				/* name */
	"Security Accounts Manager",	/* desc */
	"\\samr",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"12345778-1234-abcd-ef000123456789ac", 1,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(samr_interface),	/* interface ti */
	samr_stub_table			/* stub_table */
};

/*
 * samr_initialize
 *
 * This function registers the SAM RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
samr_initialize(void)
{
	(void) mlrpc_register_service(&samr_service);
}

/*
 * samr_s_ConnectAnon
 *
 * This is a request to connect to the local SAM database. We don't
 * support any form of update request and our database doesn't
 * contain any private information, so there is little point in
 * doing any access access checking here.
 *
 * Return a handle for use with subsequent SAM requests.
 */
/*ARGSUSED*/
static int
samr_s_ConnectAnon(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_ConnectAnon *param = arg;
	ms_handle_t *handle;

	handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR, SAMR_CONNECT_KEY,
	    SAMR_DATABASE_DOMAIN);
	bcopy(handle, &param->handle, sizeof (samr_handle_t));

	param->status = 0;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_CloseHandle
 *
 * This is a request to close the SAM interface specified by the handle.
 * Free the handle and zero out the result handle for the client.
 *
 * We could do some checking here but it probably doesn't matter.
 */
/*ARGSUSED*/
static int
samr_s_CloseHandle(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_CloseHandle *param = arg;

#ifdef SAMR_S_DEBUG
	if (mlsvc_lookup_handle((ms_handle_t *)&param->handle) == 0) {
		bzero(&param->result_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (MLRPC_DRC_OK);
	}
#endif /* SAMR_S_DEBUG */

	(void) mlsvc_put_handle((ms_handle_t *)&param->handle);
	bzero(&param->result_handle, sizeof (samr_handle_t));
	param->status = 0;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_LookupDomain
 *
 * This is a request to map a domain name to a domain SID. We can map
 * the primary domain name, our local domain name (hostname) and the
 * builtin domain names to the appropriate SID. Anything else will be
 * rejected.
 */
static int
samr_s_LookupDomain(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_LookupDomain *param = arg;
	char resource_domain[MAXHOSTNAMELEN];
	char *domain_name;
	char *p;
	nt_sid_t *sid = NULL;

	if ((domain_name = (char *)param->domain_name.str) == NULL) {
		bzero(param, sizeof (struct samr_LookupDomain));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (MLRPC_DRC_OK);
	}

	smb_config_rdlock();
	p = smb_config_getstr(SMB_CI_DOMAIN_NAME);
	(void) strlcpy(resource_domain, p, MAXHOSTNAMELEN);
	smb_config_unlock();

	if (mlsvc_is_local_domain(domain_name) == 1) {
		sid = nt_sid_dup(nt_domain_local_sid());
	} else if (strcasecmp(resource_domain, domain_name) == 0) {
		/*
		 * We should not be asked to provide
		 * the domain SID for the primary domain.
		 */
		sid = NULL;
	} else {
		sid = nt_builtin_lookup_name(domain_name, 0);
	}

	if (sid) {
		param->sid = (struct samr_sid *)mlsvc_sid_save(sid, mxa);
		free(sid);

		if (param->sid == NULL) {
			bzero(param, sizeof (struct samr_LookupDomain));
			param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
			return (MLRPC_DRC_OK);
		}

		param->status = NT_STATUS_SUCCESS;
	} else {
		param->sid = NULL;
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_DOMAIN);
	}

	return (MLRPC_DRC_OK);
}

/*
 * samr_s_EnumLocalDomains
 *
 * This is a request for the local domains supported by this server.
 * All we do here is validate the handle and set the status. The real
 * work is done in samr_s_enum_local_domains.
 */
static int
samr_s_EnumLocalDomains(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_EnumLocalDomain *param = arg;
	ms_handle_t *handle;
	DWORD status;

	handle = (ms_handle_t *)&param->handle;

	if (mlsvc_validate_handle(handle, SAMR_CONNECT_KEY) == 0)
		status = NT_STATUS_ACCESS_DENIED;
	else
		status = samr_s_enum_local_domains(param, mxa);

	if (status == NT_STATUS_SUCCESS) {
		param->enum_context = param->info->entries_read;
		param->total_entries = param->info->entries_read;
		param->status = NT_STATUS_SUCCESS;
	} else {
		bzero(param, sizeof (struct samr_EnumLocalDomain));
		param->status = NT_SC_ERROR(status);
	}

	return (MLRPC_DRC_OK);
}


/*
 * samr_s_enum_local_domains
 *
 * This function should only be called via samr_s_EnumLocalDomains to
 * ensure that the appropriate validation is performed. We will answer
 * queries about two domains: the local domain, synonymous with the
 * local hostname, and the BUILTIN domain. So we return these two
 * strings.
 *
 * Returns NT status values.
 */
static DWORD
samr_s_enum_local_domains(struct samr_EnumLocalDomain *param,
    struct mlrpc_xaction *mxa)
{
	struct samr_LocalDomainInfo *info;
	struct samr_LocalDomainEntry *entry;
	char *hostname;

	hostname = MLRPC_HEAP_MALLOC(mxa, MAXHOSTNAMELEN);
	if (hostname == NULL)
		return (NT_STATUS_NO_MEMORY);

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 1) != 0)
		return (NT_STATUS_NO_MEMORY);

	entry = MLRPC_HEAP_NEWN(mxa, struct samr_LocalDomainEntry, 2);
	if (entry == NULL)
		return (NT_STATUS_NO_MEMORY);

	bzero(entry, (sizeof (struct samr_LocalDomainEntry) * 2));
	(void) mlsvc_string_save((ms_string_t *)&entry[0].name, hostname, mxa);
	(void) mlsvc_string_save((ms_string_t *)&entry[1].name, "Builtin", mxa);

	info = MLRPC_HEAP_NEW(mxa, struct samr_LocalDomainInfo);
	if (info == NULL)
		return (NT_STATUS_NO_MEMORY);

	info->entries_read = 2;
	info->entry = entry;
	param->info = info;
	return (NT_STATUS_SUCCESS);
}

/*
 * samr_s_OpenDomain
 *
 * This is a request to open a domain within the local SAM database.
 * The caller must supply a valid handle obtained via a successful
 * connect. We return a handle to be used to access objects within
 * this domain.
 */
/*ARGSUSED*/
static int
samr_s_OpenDomain(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_OpenDomain *param = arg;
	ms_handle_t *handle = 0;
	nt_domain_t *domain;

	if (!mlsvc_validate_handle(
	    (ms_handle_t *)&param->handle, SAMR_CONNECT_KEY)) {
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (MLRPC_DRC_OK);
	}

	domain = nt_domain_lookup_sid((nt_sid_t *)param->sid);
	if (domain == NULL) {
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		return (MLRPC_DRC_OK);
	}

	switch (domain->type) {
	case NT_DOMAIN_BUILTIN:
		handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR,
		    SAMR_DOMAIN_KEY, SAMR_BUILTIN_DOMAIN);

		bcopy(handle, &param->domain_handle, sizeof (samr_handle_t));
		param->status = 0;
		break;

	case NT_DOMAIN_LOCAL:
		handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR,
		    SAMR_DOMAIN_KEY, SAMR_LOCAL_DOMAIN);

		bcopy(handle, &param->domain_handle, sizeof (samr_handle_t));
		param->status = 0;
		break;

	default:
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
	}

	return (MLRPC_DRC_OK);
}

/*
 * samr_s_QueryDomainInfo
 *
 * The caller should pass a domain handle.
 *
 * Windows 95 Server Manager sends requests for levels 6 and 7 when
 * the services menu item is selected. Level 2 is basically for getting
 * number of users, groups, and aliases in a domain.
 * We have no information on what the various information levels mean.
 */
static int
samr_s_QueryDomainInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_QueryDomainInfo *param = arg;
	ms_handle_desc_t *desc;
	char *hostname;
	char *domain_str = "";
	int rc;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->domain_handle);
	if (desc == NULL || (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0)) {
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (MLRPC_DRC_OK);
	}

	switch (param->info_level) {
	case SAMR_QUERY_DOMAIN_INFO_6:
		param->ru.info6.unknown1 = 0x00000000;
		param->ru.info6.unknown2 = 0x00147FB0;
		param->ru.info6.unknown3 = 0x00000000;
		param->ru.info6.unknown4 = 0x00000000;
		param->ru.info6.unknown5 = 0x00000000;
		param->status = NT_STATUS_SUCCESS;
		break;

	case SAMR_QUERY_DOMAIN_INFO_7:
		param->ru.info7.unknown1 = 0x00000003;
		param->status = NT_STATUS_SUCCESS;
		break;

	case SAMR_QUERY_DOMAIN_INFO_2:
		if (desc->discrim == SAMR_LOCAL_DOMAIN) {
			hostname = MLRPC_HEAP_MALLOC(mxa, MAXHOSTNAMELEN);
			rc = smb_gethostname(hostname, MAXHOSTNAMELEN, 1);
			if (rc != 0 || hostname == NULL) {
				bzero(param,
				    sizeof (struct samr_QueryDomainInfo));
				param->status =
				    NT_SC_ERROR(NT_STATUS_NO_MEMORY);
				return (MLRPC_DRC_OK);
			}

			domain_str = hostname;
		} else {
			if (desc->discrim == SAMR_BUILTIN_DOMAIN)
				domain_str = "Builtin";
		}

		param->ru.info2.unknown1 = 0x00000000;
		param->ru.info2.unknown2 = 0x80000000;

		(void) mlsvc_string_save((ms_string_t *)&(param->ru.info2.s1),
		    "", mxa);

		(void) mlsvc_string_save(
		    (ms_string_t *)&(param->ru.info2.domain), domain_str, mxa);

		(void) mlsvc_string_save((ms_string_t *)&(param->ru.info2.s2),
		    "", mxa);

		param->ru.info2.sequence_num = 0x0000002B;
		param->ru.info2.unknown3 = 0x00000000;
		param->ru.info2.unknown4 = 0x00000001;
		param->ru.info2.unknown5 = 0x00000003;
		param->ru.info2.unknown6 = 0x00000001;
		param->ru.info2.num_users = 0;
		param->ru.info2.num_groups = 0;
		param->ru.info2.num_aliases =
		    (desc->discrim == SAMR_BUILTIN_DOMAIN) ?
		    nt_groups_count(NT_GROUP_CNT_BUILTIN) :
		    nt_groups_count(NT_GROUP_CNT_LOCAL);

		param->status = NT_STATUS_SUCCESS;
		break;

	default:
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		return (MLRPC_DRC_FAULT_REQUEST_OPNUM_INVALID);
	};

	param->address = (DWORD)&param->ru;
	param->switch_value = param->info_level;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_LookupNames
 *
 * The definition for this interface is obviously wrong but I can't
 * seem to get it to work the way I think it should. It should
 * support multiple name lookup but I can only get one working for now.
 */
static int
samr_s_LookupNames(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_LookupNames *param = arg;
	ms_handle_desc_t *desc;
	struct passwd *pw;
	struct group *gr;
	nt_sid_t *sid;
	nt_group_t *grp;
	WORD rid_type;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->handle);
	if (desc == 0 || (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0)) {
		bzero(param, sizeof (struct samr_LookupNames));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (MLRPC_DRC_OK);
	}

	if (param->n_entry != 1) {
		bzero(param, sizeof (struct samr_LookupNames));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (MLRPC_DRC_OK);
	}

	if (param->name.str == NULL) {
		bzero(param, sizeof (struct samr_LookupNames));
		/*
		 * Windows NT returns NT_STATUS_NONE_MAPPED when the
		 * name is NULL.
		 * Windows 2000 returns STATUS_INVALID_ACCOUNT_NAME.
		 */
		param->status = NT_SC_ERROR(NT_STATUS_NONE_MAPPED);
		return (MLRPC_DRC_OK);
	}

	param->rids.rid = MLRPC_HEAP_NEW(mxa, DWORD);
	param->rid_types.rid_type = MLRPC_HEAP_NEW(mxa, DWORD);

	if (desc->discrim == SAMR_BUILTIN_DOMAIN) {
		sid = nt_builtin_lookup_name((char *)param->name.str,
		    &rid_type);

		if (sid != 0) {
			param->rids.n_entry = 1;
			(void) nt_sid_get_rid(sid, &param->rids.rid[0]);
			param->rid_types.n_entry = 1;
			param->rid_types.rid_type[0] = rid_type;
			param->status = NT_STATUS_SUCCESS;
			free(sid);
			return (MLRPC_DRC_OK);
		}
	} else if (desc->discrim == SAMR_LOCAL_DOMAIN) {
		grp = nt_group_getinfo((char *)param->name.str, RWLOCK_READER);

		if (grp != NULL) {
			param->rids.n_entry = 1;
			(void) nt_sid_get_rid(grp->sid, &param->rids.rid[0]);
			param->rid_types.n_entry = 1;
			param->rid_types.rid_type[0] = *grp->sid_name_use;
			param->status = NT_STATUS_SUCCESS;
			nt_group_putinfo(grp);
			return (MLRPC_DRC_OK);
		}

		if ((pw = getpwnam((const char *)param->name.str)) != NULL) {
			param->rids.n_entry = 1;
			param->rids.rid[0] = SAM_ENCODE_UXUID(pw->pw_uid);
			param->rid_types.n_entry = 1;
			param->rid_types.rid_type[0] = SidTypeUser;
			param->status = NT_STATUS_SUCCESS;
			return (MLRPC_DRC_OK);
		}

		if ((gr = getgrnam((const char *)param->name.str)) != NULL) {
			param->rids.n_entry = 1;
			param->rids.rid[0] = SAM_ENCODE_UXGID(gr->gr_gid);
			param->rid_types.n_entry = 1;
			param->rid_types.rid_type[0] = SidTypeAlias;
			param->status = NT_STATUS_SUCCESS;
			return (MLRPC_DRC_OK);
		}
	}

	param->rids.n_entry = 0;
	param->rid_types.n_entry = 0;
	param->status = NT_SC_ERROR(NT_STATUS_NONE_MAPPED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_OpenUser
 *
 * This is a request to open a user within a specified domain in the
 * local SAM database. The caller must supply a valid domain handle,
 * obtained via a successful domain open request. The user is
 * specified by the rid in the request.
 */
/*ARGSUSED*/
static int
samr_s_OpenUser(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_OpenUser *param = arg;
	ms_handle_t *handle;

	if (!mlsvc_validate_handle(
	    (ms_handle_t *)&param->handle, SAMR_DOMAIN_KEY)) {
		bzero(&param->user_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (MLRPC_DRC_OK);
	}

	handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR, SAMR_USER_KEY,
	    param->rid);
	bcopy(handle, &param->user_handle, sizeof (samr_handle_t));

	/*
	 * Need QueryUserInfo(level 21).
	 */
	bzero(&param->user_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_DeleteUser
 *
 * This is a request to delete a user within a specified domain in the
 * local SAM database. The caller should supply a valid user handle but
 * we deny access regardless.
 */
/*ARGSUSED*/
static int
samr_s_DeleteUser(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_DeleteUser *param = arg;

	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_QueryUserInfo
 *
 * Returns:
 * NT_STATUS_SUCCESS
 * NT_STATUS_ACCESS_DENIED
 * NT_STATUS_INVALID_INFO_CLASS
 */
/*ARGSUSED*/
static int
samr_s_QueryUserInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_QueryUserInfo *param = arg;

	if (!mlsvc_validate_handle(
	    (ms_handle_t *)&param->user_handle, SAMR_USER_KEY)) {
		bzero(param, sizeof (struct samr_QueryUserInfo));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (MLRPC_DRC_OK);
	}

	bzero(param, sizeof (struct samr_QueryUserInfo));
	param->status = 0;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_QueryUserGroups
 *
 * This is a request to obtain a list of groups of which a user is a
 * member. The user is identified from the handle, which contains an
 * encoded uid in the discriminator field.
 *
 * Get complete list of groups and check for builtin domain.
 */
static int
samr_s_QueryUserGroups(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_QueryUserGroups *param = arg;
	struct samr_UserGroupInfo *info;
	ms_handle_desc_t *desc;
	struct passwd *pw;
	DWORD uid;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->user_handle);
	if (desc == 0 || strcmp(desc->key, SAMR_USER_KEY)) {
		bzero(param, sizeof (struct samr_QueryUserGroups));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (MLRPC_DRC_OK);
	}

	info = MLRPC_HEAP_NEW(mxa, struct samr_UserGroupInfo);
	info->groups = MLRPC_HEAP_NEW(mxa, struct samr_UserGroups);

	uid = SAM_DECODE_RID(desc->discrim);

	if ((pw = getpwuid(uid)) != 0) {
		info->n_entry = 1;
		info->groups->rid = SAM_ENCODE_UXGID(pw->pw_gid);
		info->groups->attr = SE_GROUP_MANDATORY
		    | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
		param->info = info;
		param->status = 0;
	} else {
		bzero(param, sizeof (struct samr_QueryUserGroups));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	}

	return (MLRPC_DRC_OK);
}

/*
 * samr_s_OpenGroup
 *
 * This is a request to open a group within the specified domain in the
 * local SAM database. The caller must supply a valid domain handle,
 * obtained via a successful domain open request. The group is
 * specified by the rid in the request. If this is a local RID it
 * should already be encoded with type information.
 *
 * We return a handle to be used to access information about this group.
 */
/*ARGSUSED*/
static int
samr_s_OpenGroup(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_OpenGroup *param = arg;
	ms_handle_t *handle;

	if (!mlsvc_validate_handle(
	    (ms_handle_t *)&param->handle, SAMR_DOMAIN_KEY)) {
		bzero(&param->group_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (MLRPC_DRC_OK);
	}

	handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR, SAMR_GROUP_KEY,
	    param->rid);
	bcopy(handle, &param->group_handle, sizeof (samr_handle_t));

	param->status = 0;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_Connect
 *
 * This is a request to connect to the local SAM database. We don't
 * support any form of update request and our database doesn't
 * contain any private information, so there is little point in
 * doing any access access checking here.
 *
 * Return a handle for use with subsequent SAM requests.
 */
/*ARGSUSED*/
static int
samr_s_Connect(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_Connect *param = arg;
	ms_handle_t *handle;

	handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR,
	    SAMR_CONNECT_KEY, SAMR_DATABASE_DOMAIN);
	bcopy(handle, &param->handle, sizeof (samr_handle_t));

	param->status = 0;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_GetUserPwInfo
 *
 * This is a request to get a user's password.
 */
/*ARGSUSED*/
static int
samr_s_GetUserPwInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_GetUserPwInfo *param = arg;
	ms_handle_t *handle;
	DWORD status = 0;

	handle = (ms_handle_t *)&param->user_handle;

	if (!mlsvc_validate_handle(handle, SAMR_USER_KEY))
		status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);

	bzero(param, sizeof (struct samr_GetUserPwInfo));
	param->status = status;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_CreateUser
 *
 * This is a request to create a user within a specified domain in the
 * local SAM database.  We always deny access.
 */
/*ARGSUSED*/
static int
samr_s_CreateUser(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_CreateUser *param = arg;

	bzero(&param->user_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_ChangeUserPasswd
 */
/*ARGSUSED*/
static int
samr_s_ChangeUserPasswd(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_ChangeUserPasswd *param = arg;

	bzero(param, sizeof (struct samr_ChangeUserPasswd));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_GetDomainPwInfo
 */
/*ARGSUSED*/
static int
samr_s_GetDomainPwInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_GetDomainPwInfo *param = arg;

	bzero(param, sizeof (struct samr_GetDomainPwInfo));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_SetUserInfo
 */
/*ARGSUSED*/
static int
samr_s_SetUserInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_SetUserInfo *param = arg;

	bzero(param, sizeof (struct samr_SetUserInfo));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_QueryDispInfo
 *
 * This function is supposed to return local users' information.
 * As we don't support local users, this function dosen't send
 * back any information.
 *
 * I added a peice of code that returns information for Administrator
 * and Guest builtin users. All information are hard-coded which I get
 * from packet captures. Currently, this peice of code is opt-out.
 */
/*ARGSUSED*/
static int
samr_s_QueryDispInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_QueryDispInfo *param = arg;
	ms_handle_desc_t *desc;
	DWORD status = 0;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->domain_handle);
	if (desc == NULL || (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0))
		status = NT_STATUS_INVALID_HANDLE;

#ifdef SAMR_SUPPORT_USER
	if ((desc->discrim != SAMR_LOCAL_DOMAIN) || (param->start_idx != 0)) {
		param->total_size = 0;
		param->returned_size = 0;
		param->switch_value = 1;
		param->count = 0;
		param->users = 0;
	} else {
		param->total_size = 328;
		param->returned_size = 328;
		param->switch_value = 1;
		param->count = 2;
		param->users = (struct user_disp_info *)MLRPC_HEAP_MALLOC(mxa,
		    sizeof (struct user_disp_info));

		param->users->count = 2;
		param->users->acct[0].index = 1;
		param->users->acct[0].rid = 500;
		param->users->acct[0].ctrl = 0x210;

		(void) mlsvc_string_save(
		    (ms_string_t *)&param->users->acct[0].name,
		    "Administrator", mxa);

		(void) mlsvc_string_save(
		    (ms_string_t *)&param->users->acct[0].fullname,
		    "Built-in account for administering the computer/domain",
		    mxa);

		bzero(&param->users->acct[0].desc, sizeof (samr_string_t));

		param->users->acct[1].index = 2;
		param->users->acct[1].rid = 501;
		param->users->acct[1].ctrl = 0x211;

		(void) mlsvc_string_save(
		    (ms_string_t *)&param->users->acct[1].name,
		    "Guest", mxa);

		(void) mlsvc_string_save(
		    (ms_string_t *)&param->users->acct[1].fullname,
		    "Built-in account for guest access to the computer/domain",
		    mxa);

		bzero(&param->users->acct[1].desc, sizeof (samr_string_t));
	}
#else
	param->total_size = 0;
	param->returned_size = 0;
	param->switch_value = 1;
	param->count = 0;
	param->users = 0;
#endif
	param->status = status;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_EnumDomainGroups
 *
 *
 * This function is supposed to return local users' information.
 * As we don't support local users, this function dosen't send
 * back any information.
 *
 * I added a peice of code that returns information for a
 * domain group as None. All information are hard-coded which I get
 * from packet captures. Currently, this peice of code is opt-out.
 */
/*ARGSUSED*/
static int
samr_s_EnumDomainGroups(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_EnumDomainGroups *param = arg;
	ms_handle_desc_t *desc;
	DWORD status = NT_STATUS_SUCCESS;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->domain_handle);
	if (desc == NULL || (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0))
		status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);

	param->total_size = 0;
	param->returned_size = 0;
	param->switch_value = 3;
	param->count = 0;
	param->groups = 0;
	param->status = status;
	return (MLRPC_DRC_OK);

#ifdef SAMR_SUPPORT_GROUPS
	if ((desc->discrim != SAMR_LOCAL_DOMAIN) || (param->start_idx != 0)) {
		param->total_size = 0;
		param->returned_size = 0;
		param->switch_value = 3;
		param->count = 0;
		param->groups = 0;
	} else {
		param->total_size = 64;
		param->returned_size = 64;
		param->switch_value = 3;
		param->count = 1;
		param->groups = (struct group_disp_info *)MLRPC_HEAP_MALLOC(
		    mxa, sizeof (struct group_disp_info));

		param->groups->count = 1;
		param->groups->acct[0].index = 1;
		param->groups->acct[0].rid = 513;
		param->groups->acct[0].ctrl = 0x7;
		(void) mlsvc_string_save(
		    (ms_string_t *)&param->groups->acct[0].name, "None", mxa);

		(void) mlsvc_string_save(
		    (ms_string_t *)&param->groups->acct[0].desc,
		    "Ordinary users", mxa);
	}

	param->status = NT_STATUS_SUCCESS;
	return (MLRPC_DRC_OK);
#endif
}

/*
 * samr_s_OpenAlias
 *
 * Lookup for requested alias, if it exists return a handle
 * for that alias. The alias domain sid should match with
 * the passed domain handle.
 */
/*ARGSUSED*/
static int
samr_s_OpenAlias(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_OpenAlias *param = arg;
	ms_handle_desc_t *desc = 0;
	ms_handle_t *handle;
	nt_group_t *grp;
	DWORD status = NT_STATUS_SUCCESS;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->domain_handle);
	if (desc == 0 || (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0)) {
		status = NT_STATUS_INVALID_HANDLE;
		goto open_alias_err;
	}

	if (param->access_mask != SAMR_ALIAS_ACCESS_GET_INFO) {
		status = NT_STATUS_ACCESS_DENIED;
		goto open_alias_err;
	}

	grp = nt_groups_lookup_rid(param->rid);
	if (grp == 0) {
		status = NT_STATUS_NO_SUCH_ALIAS;
		goto open_alias_err;
	}

	if (((desc->discrim == SAMR_LOCAL_DOMAIN) &&
	    !nt_sid_is_local(grp->sid)) ||
	    ((desc->discrim == SAMR_BUILTIN_DOMAIN) &&
	    !nt_sid_is_builtin(grp->sid))) {
		status = NT_STATUS_NO_SUCH_ALIAS;
		goto open_alias_err;
	}

	handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR, SAMR_ALIAS_KEY,
	    param->rid);
	bcopy(handle, &param->alias_handle, sizeof (samr_handle_t));
	param->status = 0;
	return (MLRPC_DRC_OK);

open_alias_err:
	bzero(&param->alias_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_CreateDomainAlias
 *
 * Creates a local group in the security database, which is the
 * security accounts manager (SAM)
 * For more information you can look at MSDN page for NetLocalGroupAdd.
 * This RPC is used by CMC and right now it returns access denied.
 * The peice of code that creates a local group doesn't get compiled.
 */
/*ARGSUSED*/
static int
samr_s_CreateDomainAlias(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_CreateDomainAlias *param = arg;

#ifdef SAMR_SUPPORT_ADD_ALIAS
	DWORD status = NT_STATUS_SUCCESS;
	ms_handle_desc_t *desc = 0;
	ms_handle_t *handle;
	nt_group_t *grp;
	char *alias_name;
#endif
	bzero(&param->alias_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);

#ifdef SAMR_SUPPORT_ADD_ALIAS
	alias_name = param->alias_name.str;
	if (alias_name == 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto create_alias_err;
	}

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->domain_handle);
	if (desc == 0 ||
	    (desc->discrim != SAMR_LOCAL_DOMAIN) ||
	    (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0)) {
		status = NT_STATUS_INVALID_HANDLE;
		goto create_alias_err;
	}

	/*
	 * Check access mask.  User should be member of
	 * Administrators or Account Operators local group.
	 */
	status = nt_group_add(alias_name, 0,
	    NT_GROUP_AF_ADD | NT_GROUP_AF_LOCAL);

	if (status != NT_STATUS_SUCCESS)
		goto create_alias_err;

	grp = nt_group_getinfo(alias_name, RWLOCK_READER);
	if (grp == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto create_alias_err;
	}

	(void) nt_sid_get_rid(grp->sid, &param->rid);
	nt_group_putinfo(grp);
	handle = mlsvc_get_handle(MLSVC_IFSPEC_SAMR, SAMR_ALIAS_KEY,
	    param->rid);
	bcopy(handle, &param->alias_handle, sizeof (samr_handle_t));

	param->status = 0;
	return (MLRPC_DRC_OK);

create_alias_err:
	bzero(&param->alias_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
#endif
}

/*
 * samr_s_SetAliasInfo
 *
 * For more information you can look at MSDN page for NetLocalGroupSetInfo.
 */
/*ARGSUSED*/
static int
samr_s_SetAliasInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_SetAliasInfo *param = arg;
	DWORD status = NT_STATUS_SUCCESS;

	if (!mlsvc_validate_handle(
	    (ms_handle_t *)&param->alias_handle, SAMR_ALIAS_KEY)) {
		status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
	}

	param->status = status;
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_QueryAliasInfo
 *
 * Retrieves information about the specified local group account
 * by given handle.
 */
static int
samr_s_QueryAliasInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_QueryAliasInfo *param = arg;
	ms_handle_desc_t *desc;
	nt_group_t *grp;
	DWORD status;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->alias_handle);
	if (desc == NULL || (strcmp(desc->key, SAMR_ALIAS_KEY) != 0)) {
		status = NT_STATUS_INVALID_HANDLE;
		goto query_alias_err;
	}

	grp = nt_groups_lookup_rid(desc->discrim);
	if (grp == NULL) {
		status = NT_STATUS_NO_SUCH_ALIAS;
		goto query_alias_err;
	}

	switch (param->level) {
	case SAMR_QUERY_ALIAS_INFO_1:
		param->ru.info1.level = param->level;
		(void) mlsvc_string_save(
		    (ms_string_t *)&param->ru.info1.name, grp->name, mxa);

		(void) mlsvc_string_save(
		    (ms_string_t *)&param->ru.info1.desc, grp->comment, mxa);

		param->ru.info1.unknown = 1;
		break;

	case SAMR_QUERY_ALIAS_INFO_3:
		param->ru.info3.level = param->level;
		(void) mlsvc_string_save(
		    (ms_string_t *)&param->ru.info3.desc, grp->comment, mxa);

		break;

	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		goto query_alias_err;
	};

	param->address = (DWORD)&param->ru;
	param->status = 0;
	return (MLRPC_DRC_OK);

query_alias_err:
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_DeleteDomainAlias
 *
 * Deletes a local group account and all its members from the
 * security database, which is the security accounts manager (SAM) database.
 * Only members of the Administrators or Account Operators local group can
 * execute this function.
 * For more information you can look at MSDN page for NetLocalGroupSetInfo.
 *
 * This RPC is used by CMC and right now it returns access denied.
 * The peice of code that removes a local group doesn't get compiled.
 */
/*ARGSUSED*/
static int
samr_s_DeleteDomainAlias(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_DeleteDomainAlias *param = arg;

#ifdef SAMR_SUPPORT_DEL_ALIAS
	ms_handle_desc_t *desc = 0;
	nt_group_t *grp;
	char *alias_name;
	DWORD status;
#endif

	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (MLRPC_DRC_OK);

#ifdef SAMR_SUPPORT_DEL_ALIAS
	desc = mlsvc_lookup_handle((ms_handle_t *)&param->alias_handle);
	if (desc == 0 || (strcmp(desc->key, SAMR_ALIAS_KEY) != 0)) {
		status = NT_STATUS_INVALID_HANDLE;
		goto delete_alias_err;
	}

	grp = nt_groups_lookup_rid(desc->discrim);
	if (grp == 0) {
		status = NT_STATUS_NO_SUCH_ALIAS;
		goto delete_alias_err;
	}

	alias_name = strdup(grp->name);
	if (alias_name == 0) {
		status = NT_STATUS_NO_MEMORY;
		goto delete_alias_err;
	}

	status = nt_group_delete(alias_name);
	free(alias_name);
	if (status != NT_STATUS_SUCCESS)
		goto delete_alias_err;

	param->status = 0;
	return (MLRPC_DRC_OK);

delete_alias_err:
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
#endif
}

/*
 * samr_s_EnumDomainAliases
 *
 * This function sends back a list which contains all local groups' name.
 */
static int
samr_s_EnumDomainAliases(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_EnumDomainAliases *param = arg;
	ms_handle_desc_t *desc;
	nt_group_t *grp = NULL;
	DWORD status;
	nt_group_iterator_t *gi;
	nt_sid_t *local_sid;
	nt_sid_t *builtin_sid;
	nt_sid_t *sid;
	DWORD cnt, skip;
	struct name_rid *info;

	desc = mlsvc_lookup_handle((ms_handle_t *)&param->domain_handle);
	if (desc == NULL || (strcmp(desc->key, SAMR_DOMAIN_KEY) != 0)) {
		status = NT_STATUS_INVALID_HANDLE;
		goto enum_alias_err;
	}

	local_sid = nt_domain_local_sid();
	builtin_sid = nt_builtin_lookup_name("BUILTIN", 0);

	if (desc->discrim == SAMR_LOCAL_DOMAIN) {
		sid = local_sid;
	} else if (desc->discrim == SAMR_BUILTIN_DOMAIN) {
		sid = builtin_sid;
	} else {
		status = NT_STATUS_INVALID_HANDLE;
		goto enum_alias_err;
	}

	cnt = skip = 0;
	gi = nt_group_open_iterator();
	nt_group_ht_lock(RWLOCK_READER);
	while ((grp = nt_group_iterate(gi)) != 0) {
		if (skip++ < param->resume_handle)
			continue;
		if (nt_sid_is_indomain(sid, grp->sid))
			cnt++;
	}
	nt_group_ht_unlock();
	nt_group_close_iterator(gi);

	param->aliases = (struct aliases_info *)MLRPC_HEAP_MALLOC(mxa,
	    sizeof (struct aliases_info) + (cnt-1) * sizeof (struct name_rid));

	param->aliases->count = cnt;
	param->aliases->address = cnt;
	info = param->aliases->info;

	skip = 0;
	gi = nt_group_open_iterator();
	nt_group_ht_lock(RWLOCK_READER);
	while ((grp = nt_group_iterate(gi)) != NULL) {
		if (skip++ < param->resume_handle)
			continue;
		if (nt_sid_is_indomain(sid, grp->sid)) {
			(void) nt_sid_get_rid(grp->sid, &info->rid);
			(void) mlsvc_string_save((ms_string_t *)&info->name,
			    grp->name, mxa);

			info++;
		}
	}
	nt_group_ht_unlock();
	nt_group_close_iterator(gi);

	param->out_resume = cnt;
	param->entries = cnt;
	param->status = 0;
	return (MLRPC_DRC_OK);

enum_alias_err:
	param->status = NT_SC_ERROR(status);
	return (MLRPC_DRC_OK);
}

/*
 * samr_s_Connect3
 *
 * This is the connect3 form of the  connect request. It contains an
 * extra parameter over samr_Connect. See samr_s_Connect for other
 * details. NT returns an RPC fault - so we can do the same for now.
 * Doing it this way should avoid the unsupported opnum error message
 * appearing in the log.
 */
/*ARGSUSED*/
static int
samr_s_Connect3(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_Connect3 *param = arg;

	bzero(param, sizeof (struct samr_Connect3));
	return (MLRPC_DRC_FAULT_REQUEST_OPNUM_INVALID);
}


/*
 * samr_s_Connect4
 *
 * This is the connect4 form of the connect request used by Windows XP.
 * Returns an RPC fault for now.
 */
/*ARGSUSED*/
static int
samr_s_Connect4(void *arg, struct mlrpc_xaction *mxa)
{
	struct samr_Connect4 *param = arg;

	bzero(param, sizeof (struct samr_Connect4));
	return (MLRPC_DRC_FAULT_REQUEST_OPNUM_INVALID);
}

static mlrpc_stub_table_t samr_stub_table[] = {
	{ samr_s_ConnectAnon,		SAMR_OPNUM_ConnectAnon },
	{ samr_s_CloseHandle,		SAMR_OPNUM_CloseHandle },
	{ samr_s_LookupDomain,		SAMR_OPNUM_LookupDomain },
	{ samr_s_EnumLocalDomains,	SAMR_OPNUM_EnumLocalDomains },
	{ samr_s_OpenDomain,		SAMR_OPNUM_OpenDomain },
	{ samr_s_QueryDomainInfo,	SAMR_OPNUM_QueryDomainInfo },
	{ samr_s_LookupNames,		SAMR_OPNUM_LookupNames },
	{ samr_s_OpenUser,		SAMR_OPNUM_OpenUser },
	{ samr_s_DeleteUser,		SAMR_OPNUM_DeleteUser },
	{ samr_s_QueryUserInfo,		SAMR_OPNUM_QueryUserInfo },
	{ samr_s_QueryUserGroups,	SAMR_OPNUM_QueryUserGroups },
	{ samr_s_OpenGroup,		SAMR_OPNUM_OpenGroup },
	{ samr_s_Connect,		SAMR_OPNUM_Connect },
	{ samr_s_GetUserPwInfo,		SAMR_OPNUM_GetUserPwInfo },
	{ samr_s_CreateUser,		SAMR_OPNUM_CreateUser },
	{ samr_s_ChangeUserPasswd,	SAMR_OPNUM_ChangeUserPasswd },
	{ samr_s_GetDomainPwInfo,	SAMR_OPNUM_GetDomainPwInfo },
	{ samr_s_SetUserInfo,		SAMR_OPNUM_SetUserInfo },
	{ samr_s_Connect3,		SAMR_OPNUM_Connect3 },
	{ samr_s_Connect4,		SAMR_OPNUM_Connect4 },
	{ samr_s_QueryDispInfo,		SAMR_OPNUM_QueryDispInfo },
	{ samr_s_OpenAlias,		SAMR_OPNUM_OpenAlias },
	{ samr_s_CreateDomainAlias,	SAMR_OPNUM_CreateDomainAlias },
	{ samr_s_SetAliasInfo,		SAMR_OPNUM_SetAliasInfo },
	{ samr_s_QueryAliasInfo,	SAMR_OPNUM_QueryAliasInfo },
	{ samr_s_DeleteDomainAlias,	SAMR_OPNUM_DeleteDomainAlias },
	{ samr_s_EnumDomainAliases,	SAMR_OPNUM_EnumDomainAliases },
	{ samr_s_EnumDomainGroups,	SAMR_OPNUM_EnumDomainGroups },
	{0}
};

/*
 * There is a bug in the way that midl and the marshalling code handles
 * unions so we need to fix some of the data offsets at runtime. The
 * following macros and the fixup functions handle the corrections.
 */
DECL_FIXUP_STRUCT(samr_QueryDomainInfo_ru);
DECL_FIXUP_STRUCT(samr_QueryDomainInfoRes);
DECL_FIXUP_STRUCT(samr_QueryDomainInfo);

DECL_FIXUP_STRUCT(samr_QueryAliasInfo_ru);
DECL_FIXUP_STRUCT(samr_QueryAliasInfoRes);
DECL_FIXUP_STRUCT(samr_QueryAliasInfo);

DECL_FIXUP_STRUCT(QueryUserInfo_result_u);
DECL_FIXUP_STRUCT(QueryUserInfo_result);
DECL_FIXUP_STRUCT(samr_QueryUserInfo);

void
fixup_samr_QueryDomainInfo(struct samr_QueryDomainInfo *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	switch (val->switch_value) {
		CASE_INFO_ENT(samr_QueryDomainInfo, 2);
		CASE_INFO_ENT(samr_QueryDomainInfo, 6);
		CASE_INFO_ENT(samr_QueryDomainInfo, 7);

		default:
			return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (mlrpcconn_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(samr_QueryDomainInfo_ru, size1);
	FIXUP_PDU_SIZE(samr_QueryDomainInfoRes, size2);
	FIXUP_PDU_SIZE(samr_QueryDomainInfo, size3);
}

void
fixup_samr_QueryAliasInfo(struct samr_QueryAliasInfo *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	switch (val->level) {
		CASE_INFO_ENT(samr_QueryAliasInfo, 1);
		CASE_INFO_ENT(samr_QueryAliasInfo, 3);

		default:
			return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (mlrpcconn_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(samr_QueryAliasInfo_ru, size1);
	FIXUP_PDU_SIZE(samr_QueryAliasInfoRes, size2);
	FIXUP_PDU_SIZE(samr_QueryAliasInfo, size3);
}

void
fixup_samr_QueryUserInfo(struct samr_QueryUserInfo *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	switch (val->switch_index) {
		CASE_INFO_ENT(samr_QueryUserInfo, 1);
		CASE_INFO_ENT(samr_QueryUserInfo, 6);
		CASE_INFO_ENT(samr_QueryUserInfo, 7);
		CASE_INFO_ENT(samr_QueryUserInfo, 8);
		CASE_INFO_ENT(samr_QueryUserInfo, 9);
		CASE_INFO_ENT(samr_QueryUserInfo, 16);

		default:
			return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (mlrpcconn_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(QueryUserInfo_result_u, size1);
	FIXUP_PDU_SIZE(QueryUserInfo_result, size2);
	FIXUP_PDU_SIZE(samr_QueryUserInfo, size3);
}

/*
 * As long as there is only one entry in the union, there is no need
 * to patch anything.
 */
/*ARGSUSED*/
void
fixup_samr_QueryGroupInfo(struct samr_QueryGroupInfo *val)
{
}
