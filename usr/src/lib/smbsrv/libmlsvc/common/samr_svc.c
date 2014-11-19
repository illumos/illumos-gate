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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Security Accounts Manager RPC (SAMR) server-side interface.
 *
 * The SAM is a hierarchical database:
 * - If you want to talk to the SAM you need a SAM handle.
 * - If you want to work with a domain, use the SAM handle.
 *   to obtain a domain handle.
 * - Use domain handles to obtain user handles etc.
 */

#include <strings.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <grp.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/ndl/samrpc.ndl>
#include <samlib.h>

/*
 * The keys associated with the various handles dispensed by the SAMR
 * server.  These keys can be used to validate client activity.
 * These values are never passed over the wire so security shouldn't
 * be an issue.
 */
typedef enum {
	SAMR_KEY_NULL = 0,
	SAMR_KEY_CONNECT,
	SAMR_KEY_DOMAIN,
	SAMR_KEY_USER,
	SAMR_KEY_GROUP,
	SAMR_KEY_ALIAS
} samr_key_t;

typedef struct samr_keydata {
	samr_key_t kd_key;
	smb_domain_type_t kd_type;
	DWORD kd_rid;
} samr_keydata_t;

/*
 * DomainDisplayUser	All user objects (or those derived from user) with
 * 			userAccountControl containing the UF_NORMAL_ACCOUNT bit.
 *
 * DomainDisplayMachine	All user objects (or those derived from user) with
 * 			userAccountControl containing the
 * 			UF_WORKSTATION_TRUST_ACCOUNT or UF_SERVER_TRUST_ACCOUNT
 * 			bit.
 *
 * DomainDisplayGroup	All group objects (or those derived from group) with
 * 			groupType equal to GROUP_TYPE_SECURITY_UNIVERSAL or
 * 			GROUP_TYPE_SECURITY_ACCOUNT.
 *
 * DomainDisplayOemUser	Same as DomainDisplayUser with OEM strings
 *
 * DomainDisplayOemGroup Same as DomainDisplayGroup with OEM strings
 */
typedef enum {
	DomainDisplayUser = 1,
	DomainDisplayMachine,
	DomainDispalyGroup,
	DomainDisplayOemUser,
	DomainDisplayOemGroup
} samr_displvl_t;

#define	SAMR_VALID_DISPLEVEL(lvl) \
	(((lvl) >= DomainDisplayUser) && ((lvl) <= DomainDisplayOemGroup))

#define	SAMR_SUPPORTED_DISPLEVEL(lvl) (lvl == DomainDisplayUser)

static ndr_hdid_t *samr_hdalloc(ndr_xa_t *, samr_key_t, smb_domain_type_t,
    DWORD);
static void samr_hdfree(ndr_xa_t *, ndr_hdid_t *);
static ndr_handle_t *samr_hdlookup(ndr_xa_t *, ndr_hdid_t *, samr_key_t);
static int samr_call_stub(ndr_xa_t *mxa);
static DWORD samr_s_enum_local_domains(struct samr_EnumLocalDomain *,
    ndr_xa_t *);

static ndr_stub_table_t samr_stub_table[];

static ndr_service_t samr_service = {
	"SAMR",				/* name */
	"Security Accounts Manager",	/* desc */
	"\\samr",			/* endpoint */
	PIPE_LSASS,			/* sec_addr_port */
	"12345778-1234-abcd-ef00-0123456789ac", 1,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	NULL,				/* no bind_req() */
	NULL,				/* no unbind_and_close() */
	samr_call_stub,			/* call_stub() */
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
	(void) ndr_svc_register(&samr_service);
}

/*
 * Custom call_stub to set the stream string policy.
 */
static int
samr_call_stub(ndr_xa_t *mxa)
{
	NDS_SETF(&mxa->send_nds, NDS_F_NOTERM);
	NDS_SETF(&mxa->recv_nds, NDS_F_NOTERM);

	return (ndr_generic_call_stub(mxa));
}

/*
 * Handle allocation wrapper to setup the local context.
 */
static ndr_hdid_t *
samr_hdalloc(ndr_xa_t *mxa, samr_key_t key, smb_domain_type_t domain_type,
    DWORD rid)
{
	ndr_handle_t	*hd;
	ndr_hdid_t	*id;
	samr_keydata_t	*data;

	if ((data = malloc(sizeof (samr_keydata_t))) == NULL)
		return (NULL);

	data->kd_key = key;
	data->kd_type = domain_type;
	data->kd_rid = rid;

	if ((id = ndr_hdalloc(mxa, data)) == NULL) {
		free(data);
		return (NULL);
	}

	if ((hd = ndr_hdlookup(mxa, id)) != NULL)
		hd->nh_data_free = free;

	return (id);
}

/*
 * Handle deallocation wrapper to free the local context.
 */
static void
samr_hdfree(ndr_xa_t *mxa, ndr_hdid_t *id)
{
	ndr_handle_t *hd;

	if ((hd = ndr_hdlookup(mxa, id)) != NULL) {
		free(hd->nh_data);
		hd->nh_data = NULL;
		ndr_hdfree(mxa, id);
	}
}

/*
 * Handle lookup wrapper to validate the local context.
 */
static ndr_handle_t *
samr_hdlookup(ndr_xa_t *mxa, ndr_hdid_t *id, samr_key_t key)
{
	ndr_handle_t *hd;
	samr_keydata_t *data;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL)
		return (NULL);

	if ((data = (samr_keydata_t *)hd->nh_data) == NULL)
		return (NULL);

	if (data->kd_key != key)
		return (NULL);

	return (hd);
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
static int
samr_s_Connect(void *arg, ndr_xa_t *mxa)
{
	struct samr_Connect *param = arg;
	ndr_hdid_t *id;

	id = samr_hdalloc(mxa, SAMR_KEY_CONNECT, SMB_DOMAIN_NULL, 0);
	if (id) {
		bcopy(id, &param->handle, sizeof (samr_handle_t));
		param->status = 0;
	} else {
		bzero(&param->handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}

/*
 * samr_s_CloseHandle
 *
 * Close the SAM interface specified by the handle.
 * Free the handle and zero out the result handle for the client.
 */
static int
samr_s_CloseHandle(void *arg, ndr_xa_t *mxa)
{
	struct samr_CloseHandle *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	samr_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (samr_handle_t));
	param->status = 0;
	return (NDR_DRC_OK);
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
samr_s_LookupDomain(void *arg, ndr_xa_t *mxa)
{
	struct samr_LookupDomain *param = arg;
	char *domain_name;
	smb_domain_t di;

	if ((domain_name = (char *)param->domain_name.str) == NULL) {
		bzero(param, sizeof (struct samr_LookupDomain));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (NDR_DRC_OK);
	}

	if (!smb_domain_lookup_name(domain_name, &di)) {
		bzero(param, sizeof (struct samr_LookupDomain));
		param->status = NT_SC_ERROR(NT_STATUS_NO_SUCH_DOMAIN);
		return (NDR_DRC_OK);
	}

	param->sid = (struct samr_sid *)NDR_SIDDUP(mxa, di.di_binsid);
	if (param->sid == NULL) {
		bzero(param, sizeof (struct samr_LookupDomain));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * samr_s_EnumLocalDomains
 *
 * This is a request for the local domains supported by this server.
 * All we do here is validate the handle and set the status. The real
 * work is done in samr_s_enum_local_domains.
 */
static int
samr_s_EnumLocalDomains(void *arg, ndr_xa_t *mxa)
{
	struct samr_EnumLocalDomain *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	DWORD status;

	if (samr_hdlookup(mxa, id, SAMR_KEY_CONNECT) == NULL)
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

	return (NDR_DRC_OK);
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
    ndr_xa_t *mxa)
{
	struct samr_LocalDomainInfo *info;
	struct samr_LocalDomainEntry *entry;
	char *hostname;

	hostname = NDR_MALLOC(mxa, NETBIOS_NAME_SZ);
	if (hostname == NULL)
		return (NT_STATUS_NO_MEMORY);

	if (smb_getnetbiosname(hostname, NETBIOS_NAME_SZ) != 0)
		return (NT_STATUS_NO_MEMORY);

	entry = NDR_NEWN(mxa, struct samr_LocalDomainEntry, 2);
	if (entry == NULL)
		return (NT_STATUS_NO_MEMORY);

	bzero(entry, (sizeof (struct samr_LocalDomainEntry) * 2));
	(void) NDR_MSTRING(mxa, hostname, (ndr_mstring_t *)&entry[0].name);
	(void) NDR_MSTRING(mxa, "Builtin", (ndr_mstring_t *)&entry[1].name);

	info = NDR_NEW(mxa, struct samr_LocalDomainInfo);
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
 * The caller must supply a valid connect handle.
 * We return a handle to be used to access objects within this domain.
 */
static int
samr_s_OpenDomain(void *arg, ndr_xa_t *mxa)
{
	struct samr_OpenDomain *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	smb_domain_t domain;

	if (samr_hdlookup(mxa, id, SAMR_KEY_CONNECT) == NULL) {
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}

	if (!smb_domain_lookup_sid((smb_sid_t *)param->sid, &domain)) {
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		return (NDR_DRC_OK);
	}

	if ((domain.di_type != SMB_DOMAIN_BUILTIN) &&
	    (domain.di_type != SMB_DOMAIN_LOCAL)) {
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_CANT_ACCESS_DOMAIN_INFO);
		return (NDR_DRC_OK);
	}

	id = samr_hdalloc(mxa, SAMR_KEY_DOMAIN, domain.di_type, 0);
	if (id) {
		bcopy(id, &param->domain_handle, sizeof (samr_handle_t));
		param->status = 0;
	} else {
		bzero(&param->domain_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
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
samr_s_QueryDomainInfo(void *arg, ndr_xa_t *mxa)
{
	struct samr_QueryDomainInfo *param = arg;
	struct samr_QueryDomainInfoRes *info;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->domain_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	char *domain;
	char hostname[NETBIOS_NAME_SZ];
	int alias_cnt, user_cnt;
	int rc = 0;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL) {
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	info = NDR_NEW(mxa, struct samr_QueryDomainInfoRes);
	if (info == NULL) {
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}
	info->switch_value = param->info_level;
	param->info = info;

	data = (samr_keydata_t *)hd->nh_data;

	switch (data->kd_type) {
	case SMB_DOMAIN_BUILTIN:
		domain = "BUILTIN";
		user_cnt = 0;
		alias_cnt = smb_sam_grp_cnt(data->kd_type);
		break;

	case SMB_DOMAIN_LOCAL:
		rc = smb_getnetbiosname(hostname, sizeof (hostname));
		if (rc == 0) {
			domain = hostname;
			user_cnt = smb_sam_usr_cnt();
			alias_cnt = smb_sam_grp_cnt(data->kd_type);
		}
		break;

	default:
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	if (rc != 0) {
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		param->status = NT_SC_ERROR(NT_STATUS_INTERNAL_ERROR);
		return (NDR_DRC_OK);
	}

	switch (param->info_level) {
	case SAMR_QUERY_DOMAIN_INFO_6:
		info->ru.info6.unknown1 = 0x00000000;
		info->ru.info6.unknown2 = 0x00147FB0;
		info->ru.info6.unknown3 = 0x00000000;
		info->ru.info6.unknown4 = 0x00000000;
		info->ru.info6.unknown5 = 0x00000000;
		param->status = NT_STATUS_SUCCESS;
		break;

	case SAMR_QUERY_DOMAIN_INFO_7:
		info->ru.info7.unknown1 = 0x00000003;
		param->status = NT_STATUS_SUCCESS;
		break;

	case SAMR_QUERY_DOMAIN_INFO_2:
		info->ru.info2.unknown1 = 0x00000000;
		info->ru.info2.unknown2 = 0x80000000;

		(void) NDR_MSTRING(mxa, "",
		    (ndr_mstring_t *)&(info->ru.info2.s1));
		(void) NDR_MSTRING(mxa, domain,
		    (ndr_mstring_t *)&(info->ru.info2.domain));
		(void) NDR_MSTRING(mxa, "",
		    (ndr_mstring_t *)&(info->ru.info2.s2));

		info->ru.info2.sequence_num = 0x0000002B;
		info->ru.info2.unknown3 = 0x00000000;
		info->ru.info2.unknown4 = 0x00000001;
		info->ru.info2.unknown5 = 0x00000003;
		info->ru.info2.unknown6 = 0x00000001;
		info->ru.info2.num_users = user_cnt;
		info->ru.info2.num_groups = 0;
		info->ru.info2.num_aliases = alias_cnt;
		param->status = NT_STATUS_SUCCESS;
		break;

	default:
		bzero(param, sizeof (struct samr_QueryDomainInfo));
		return (NDR_DRC_FAULT_REQUEST_OPNUM_INVALID);
	};

	return (NDR_DRC_OK);
}

/*
 * QueryInfoDomain2: Identical to QueryDomainInfo.
 */
static int
samr_s_QueryInfoDomain2(void *arg, ndr_xa_t *mxa)
{
	return (samr_s_QueryDomainInfo(arg, mxa));
}

/*
 * Looks up the given name in the specified domain which could
 * be either the built-in or local domain.
 *
 * CAVEAT: this function should be able to handle a list of
 * names but currently it can only handle one name at a time.
 */
static int
samr_s_LookupNames(void *arg, ndr_xa_t *mxa)
{
	struct samr_LookupNames *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	smb_account_t account;
	smb_wka_t *wka;
	uint32_t status = NT_STATUS_SUCCESS;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL)
		status = NT_STATUS_INVALID_HANDLE;

	if (param->n_entry != 1)
		status = NT_STATUS_ACCESS_DENIED;

	if (param->name.str == NULL) {
		/*
		 * Windows NT returns NT_STATUS_NONE_MAPPED.
		 * Windows 2000 returns STATUS_INVALID_ACCOUNT_NAME.
		 */
		status = NT_STATUS_NONE_MAPPED;
	}

	if (status != NT_STATUS_SUCCESS) {
		bzero(param, sizeof (struct samr_LookupNames));
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	param->rids.rid = NDR_NEW(mxa, DWORD);
	param->rid_types.rid_type = NDR_NEW(mxa, DWORD);

	data = (samr_keydata_t *)hd->nh_data;

	switch (data->kd_type) {
	case SMB_DOMAIN_BUILTIN:
		wka = smb_wka_lookup_builtin((char *)param->name.str);
		if (wka != NULL) {
			param->rids.n_entry = 1;
			(void) smb_sid_getrid(wka->wka_binsid,
			    &param->rids.rid[0]);
			param->rid_types.n_entry = 1;
			param->rid_types.rid_type[0] = wka->wka_type;
			param->status = NT_STATUS_SUCCESS;
			return (NDR_DRC_OK);
		}
		break;

	case SMB_DOMAIN_LOCAL:
		status = smb_sam_lookup_name(NULL, (char *)param->name.str,
		    SidTypeUnknown, &account);
		if (status == NT_STATUS_SUCCESS) {
			param->rids.n_entry = 1;
			param->rids.rid[0] = account.a_rid;
			param->rid_types.n_entry = 1;
			param->rid_types.rid_type[0] = account.a_type;
			param->status = NT_STATUS_SUCCESS;
			smb_account_free(&account);
			return (NDR_DRC_OK);
		}
		break;

	default:
		bzero(param, sizeof (struct samr_LookupNames));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	param->rids.n_entry = 0;
	param->rid_types.n_entry = 0;
	param->status = NT_SC_ERROR(NT_STATUS_NONE_MAPPED);
	return (NDR_DRC_OK);
}

/*
 * samr_s_OpenUser
 *
 * This is a request to open a user within a specified domain in the
 * local SAM database. The caller must supply a valid domain handle,
 * obtained via a successful domain open request. The user is
 * specified by the rid in the request.
 */
static int
samr_s_OpenUser(void *arg, ndr_xa_t *mxa)
{
	struct samr_OpenUser *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL) {
		bzero(&param->user_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (samr_keydata_t *)hd->nh_data;

	id = samr_hdalloc(mxa, SAMR_KEY_USER, data->kd_type, param->rid);
	if (id == NULL) {
		bzero(&param->user_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	} else {
		bcopy(id, &param->user_handle, sizeof (samr_handle_t));
		param->status = NT_STATUS_SUCCESS;
	}

	return (NDR_DRC_OK);
}

/*
 * samr_s_DeleteUser
 *
 * Request to delete a user within a specified domain in the local
 * SAM database.  The caller should supply a valid user handle.
 */
/*ARGSUSED*/
static int
samr_s_DeleteUser(void *arg, ndr_xa_t *mxa)
{
	struct samr_DeleteUser *param = arg;

	bzero(param, sizeof (struct samr_DeleteUser));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
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
samr_s_QueryUserInfo(void *arg, ndr_xa_t *mxa)
{
	static uint16_t			owf_buf[8];
	static uint8_t			hour_buf[SAMR_SET_USER_HOURS_SZ];
	struct samr_QueryUserInfo	*param = arg;
	struct samr_QueryUserInfo21	*all_info;
	ndr_hdid_t			*id;
	ndr_handle_t			*hd;
	samr_keydata_t			*data;
	smb_domain_t			di;
	smb_account_t			account;
	smb_sid_t			*sid;
	uint32_t			status;

	id = (ndr_hdid_t *)&param->user_handle;
	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_USER)) == NULL) {
		status = NT_STATUS_INVALID_HANDLE;
		goto QueryUserInfoError;
	}

	data = (samr_keydata_t *)hd->nh_data;

	if (param->switch_value != SAMR_QUERY_USER_ALL_INFO) {
		status = NT_STATUS_ACCESS_DENIED;
		goto QueryUserInfoError;
	}

	if (!smb_domain_lookup_type(SMB_DOMAIN_LOCAL, &di)) {
		status = NT_STATUS_ACCESS_DENIED;
		goto QueryUserInfoError;
	}

	if ((sid = smb_sid_splice(di.di_binsid, data->kd_rid)) == NULL) {
		status = NT_STATUS_ACCESS_DENIED;
		goto QueryUserInfoError;
	}

	if (smb_sam_lookup_sid(sid, &account) != NT_STATUS_SUCCESS) {
		status = NT_STATUS_ACCESS_DENIED;
		goto QueryUserInfoError;
	}

	all_info = &param->ru.info21;
	bzero(all_info, sizeof (struct samr_QueryUserInfo21));

	all_info->WhichFields = SAMR_USER_ALL_USERNAME | SAMR_USER_ALL_USERID;

	(void) NDR_MSTRING(mxa, account.a_name,
	    (ndr_mstring_t *)&all_info->UserName);
	all_info->UserId = data->kd_rid;

	all_info->LmOwfPassword.length = 16;
	all_info->LmOwfPassword.maxlen = 16;
	all_info->LmOwfPassword.buf = owf_buf;
	all_info->NtOwfPassword.length = 16;
	all_info->NtOwfPassword.maxlen = 16;
	all_info->NtOwfPassword.buf = owf_buf;
	all_info->LogonHours.units_per_week = SAMR_HOURS_PER_WEEK;
	all_info->LogonHours.hours = hour_buf;

	param->address = 1;
	param->switch_index = SAMR_QUERY_USER_ALL_INFO;
	param->status = NT_STATUS_SUCCESS;
	smb_account_free(&account);
	smb_sid_free(sid);
	return (NDR_DRC_OK);

QueryUserInfoError:
	smb_sid_free(sid);
	bzero(param, sizeof (struct samr_QueryUserInfo));
	param->status = NT_SC_ERROR(status);
	return (NDR_DRC_OK);
}

/*
 * samr_s_QueryUserGroups
 *
 * Request the list of groups of which a user is a member.
 * The user is identified from the handle, which contains an
 * rid in the discriminator field. Note that this is a local user.
 */
static int
samr_s_QueryUserGroups(void *arg, ndr_xa_t *mxa)
{
	struct samr_QueryUserGroups *param = arg;
	struct samr_UserGroupInfo *info;
	struct samr_UserGroups *group;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->user_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	smb_sid_t *user_sid = NULL;
	smb_group_t grp;
	smb_giter_t gi;
	smb_domain_t di;
	uint32_t status;
	int size;
	int ngrp_max;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_USER)) == NULL) {
		status = NT_STATUS_ACCESS_DENIED;
		goto query_error;
	}

	data = (samr_keydata_t *)hd->nh_data;
	switch (data->kd_type) {
	case SMB_DOMAIN_BUILTIN:
	case SMB_DOMAIN_LOCAL:
		if (!smb_domain_lookup_type(data->kd_type, &di)) {
			status = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
			goto query_error;
		}
		break;
	default:
		status = NT_STATUS_INVALID_HANDLE;
		goto query_error;
	}

	user_sid = smb_sid_splice(di.di_binsid, data->kd_rid);
	if (user_sid == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto query_error;
	}

	info = NDR_NEW(mxa, struct samr_UserGroupInfo);
	if (info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto query_error;
	}
	bzero(info, sizeof (struct samr_UserGroupInfo));

	size = 32 * 1024;
	info->groups = NDR_MALLOC(mxa, size);
	if (info->groups == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto query_error;
	}
	ngrp_max = size / sizeof (struct samr_UserGroups);

	if (smb_lgrp_iteropen(&gi) != SMB_LGRP_SUCCESS) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto query_error;
	}

	info->n_entry = 0;
	group = info->groups;
	while ((info->n_entry < ngrp_max) &&
	    (smb_lgrp_iterate(&gi, &grp) == SMB_LGRP_SUCCESS)) {
		if (smb_lgrp_is_member(&grp, user_sid)) {
			group->rid = grp.sg_rid;
			group->attr = grp.sg_attr;
			group++;
			info->n_entry++;
		}
		smb_lgrp_free(&grp);
	}
	smb_lgrp_iterclose(&gi);

	free(user_sid);
	param->info = info;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);

query_error:
	free(user_sid);
	bzero(param, sizeof (struct samr_QueryUserGroups));
	param->status = NT_SC_ERROR(status);
	return (NDR_DRC_OK);
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
static int
samr_s_OpenGroup(void *arg, ndr_xa_t *mxa)
{
	struct samr_OpenGroup *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL) {
		bzero(&param->group_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (samr_keydata_t *)hd->nh_data;
	id = samr_hdalloc(mxa, SAMR_KEY_GROUP, data->kd_type, param->rid);

	if (id) {
		bcopy(id, &param->group_handle, sizeof (samr_handle_t));
		param->status = 0;
	} else {
		bzero(&param->group_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}

/*
 * samr_s_AddAliasMember
 *
 * Add a member to a local SAM group.
 * The caller must supply a valid group handle.
 * The member is specified by the sid in the request.
 */
static int
samr_s_AddAliasMember(void *arg, ndr_xa_t *mxa)
{
	struct samr_AddAliasMember *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->alias_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	smb_group_t grp;
	uint32_t rc;
	uint32_t status = NT_STATUS_SUCCESS;

	if (param->sid == NULL) {
		bzero(param, sizeof (struct samr_AddAliasMember));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (NDR_DRC_OK);
	}

	if (!ndr_is_admin(mxa)) {
		bzero(param, sizeof (struct samr_AddAliasMember));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}


	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_ALIAS)) == NULL) {
		bzero(param, sizeof (struct samr_AddAliasMember));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (samr_keydata_t *)hd->nh_data;
	rc = smb_lgrp_getbyrid(data->kd_rid, data->kd_type, &grp);
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(param, sizeof (struct samr_AddAliasMember));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	rc = smb_lgrp_add_member(grp.sg_name,
	    (smb_sid_t *)param->sid, SidTypeUser);
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(param, sizeof (struct samr_AddAliasMember));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
	}
	smb_lgrp_free(&grp);

	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * samr_s_DeleteAliasMember
 *
 * Delete a member from a local SAM group.
 * The caller must supply a valid group handle.
 * The member is specified by the sid in the request.
 */
static int
samr_s_DeleteAliasMember(void *arg, ndr_xa_t *mxa)
{
	struct samr_DeleteAliasMember *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->alias_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	smb_group_t grp;
	uint32_t rc;
	uint32_t status = NT_STATUS_SUCCESS;

	if (param->sid == NULL) {
		bzero(param, sizeof (struct samr_DeleteAliasMember));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (NDR_DRC_OK);
	}

	if (!ndr_is_admin(mxa)) {
		bzero(param, sizeof (struct samr_DeleteAliasMember));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_ALIAS)) == NULL) {
		bzero(param, sizeof (struct samr_DeleteAliasMember));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (samr_keydata_t *)hd->nh_data;
	rc = smb_lgrp_getbyrid(data->kd_rid, data->kd_type, &grp);
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(param, sizeof (struct samr_DeleteAliasMember));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	rc = smb_lgrp_del_member(grp.sg_name,
	    (smb_sid_t *)param->sid, SidTypeUser);
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(param, sizeof (struct samr_DeleteAliasMember));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
	}
	smb_lgrp_free(&grp);

	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * samr_s_ListAliasMembers
 *
 * List members from a local SAM group.
 * The caller must supply a valid group handle.
 * A list of user SIDs in the specified group is returned to the caller.
 */
static int
samr_s_ListAliasMembers(void *arg, ndr_xa_t *mxa)
{
	struct samr_ListAliasMembers *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->alias_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	smb_group_t grp;
	smb_gsid_t *members;
	struct samr_SidInfo info;
	struct samr_SidList *user;
	uint32_t num = 0, size;
	int i;
	uint32_t rc;
	uint32_t status = NT_STATUS_SUCCESS;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_ALIAS)) == NULL) {
		bzero(param, sizeof (struct samr_ListAliasMembers));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	bzero(&info, sizeof (struct samr_SidInfo));
	data = (samr_keydata_t *)hd->nh_data;
	rc = smb_lgrp_getbyrid(data->kd_rid, data->kd_type, &grp);
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(param, sizeof (struct samr_ListAliasMembers));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	num = grp.sg_nmembers;
	members = grp.sg_members;
	size = num * sizeof (struct samr_SidList);
	info.sidlist = NDR_MALLOC(mxa, size);
	if (info.sidlist == NULL) {
		bzero(param, sizeof (struct samr_ListAliasMembers));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		smb_lgrp_free(&grp);
		return (NDR_DRC_OK);
	}

	info.n_entry = num;
	user = info.sidlist;
	for (i = 0; i < num; i++) {
		user->sid = (struct samr_sid *)NDR_SIDDUP(mxa,
		    members[i].gs_sid);
		if (user->sid == NULL) {
			bzero(param, sizeof (struct samr_ListAliasMembers));
			param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
			smb_lgrp_free(&grp);
			return (NDR_DRC_OK);
		}
		user++;
	}
	smb_lgrp_free(&grp);

	param->info = info;
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * samr_s_Connect2
 *
 * This is a request to connect to the local SAM database.
 * We don't support any form of update request and our database doesn't
 * contain any private information, so there is little point in doing
 * any access access checking here.
 *
 * Return a handle for use with subsequent SAM requests.
 */
static int
samr_s_Connect2(void *arg, ndr_xa_t *mxa)
{
	struct samr_Connect2 *param = arg;
	ndr_hdid_t *id;

	id = samr_hdalloc(mxa, SAMR_KEY_CONNECT, SMB_DOMAIN_NULL, 0);
	if (id) {
		bcopy(id, &param->handle, sizeof (samr_handle_t));
		param->status = 0;
	} else {
		bzero(&param->handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}

/*
 * samr_s_GetUserPwInfo
 *
 * Request for a user's password policy information.
 */
/*ARGSUSED*/
static int
samr_s_GetUserPwInfo(void *arg, ndr_xa_t *mxa)
{
	static samr_password_info_t	pwinfo;
	struct samr_GetUserPwInfo	*param = arg;

	param->pwinfo = &pwinfo;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * samr_s_CreateUser
 */
/*ARGSUSED*/
static int
samr_s_CreateUser(void *arg, ndr_xa_t *mxa)
{
	struct samr_CreateUser *param = arg;

	bzero(&param->user_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * samr_s_ChangePasswordUser2
 */
/*ARGSUSED*/
static int
samr_s_ChangePasswordUser2(void *arg, ndr_xa_t *mxa)
{
	struct samr_ChangePasswordUser2 *param = arg;

	bzero(param, sizeof (*param));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * samr_s_GetDomainPwInfo
 *
 * Request for the domain password policy information.
 */
/*ARGSUSED*/
static int
samr_s_GetDomainPwInfo(void *arg, ndr_xa_t *mxa)
{
	static samr_password_info_t	pwinfo;
	struct samr_GetDomainPwInfo	*param = arg;

	param->pwinfo = &pwinfo;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * samr_s_SetUserInfo
 */
/*ARGSUSED*/
static int
samr_s_SetUserInfo(void *arg, ndr_xa_t *mxa)
{
	struct samr_SetUserInfo *param = arg;

	bzero(param, sizeof (struct samr_SetUserInfo));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * samr_s_QueryDispInfo
 *
 * This function currently return local users' information only.
 * This RPC is called repeatedly until all the users info are
 * retrieved.
 *
 * The total count and the returned count are returned as total size
 * and returned size.  The client doesn't seem to care.
 */
static int
samr_s_QueryDispInfo(void *arg, ndr_xa_t *mxa)
{
	struct samr_QueryDispInfo *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->domain_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	DWORD status = NT_STATUS_SUCCESS;
	struct user_acct_info *user;
	smb_pwditer_t pwi;
	smb_luser_t *uinfo;
	int num_users;
	int start_idx;
	int max_retcnt, retcnt;
	int skip;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL) {
		status = NT_STATUS_INVALID_HANDLE;
		goto error;
	}

	if (!SAMR_VALID_DISPLEVEL(param->level)) {
		status = NT_STATUS_INVALID_INFO_CLASS;
		goto error;
	}

	if (!SAMR_SUPPORTED_DISPLEVEL(param->level)) {
		status = NT_STATUS_NOT_IMPLEMENTED;
		goto error;
	}

	data = (samr_keydata_t *)hd->nh_data;

	switch (data->kd_type) {
	case SMB_DOMAIN_BUILTIN:
		goto no_info;

	case SMB_DOMAIN_LOCAL:
		num_users = smb_sam_usr_cnt();
		start_idx = param->start_idx;
		if ((num_users == 0) || (start_idx >= num_users))
			goto no_info;

		max_retcnt = num_users - start_idx;
		if (max_retcnt > param->max_entries)
			max_retcnt = param->max_entries;
		param->users.acct = NDR_MALLOC(mxa,
		    max_retcnt * sizeof (struct user_acct_info));
		user = param->users.acct;
		if (user == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}
		bzero(user, max_retcnt * sizeof (struct user_acct_info));

		if (smb_pwd_iteropen(&pwi) != SMB_PWE_SUCCESS)
			goto no_info;

		skip = retcnt = 0;
		while ((uinfo = smb_pwd_iterate(&pwi)) != NULL) {
			if (skip++ < start_idx)
				continue;

			if (retcnt++ >= max_retcnt)
				break;

			assert(uinfo->su_name != NULL);

			user->index = start_idx + retcnt;
			user->rid = uinfo->su_rid;
			user->ctrl = ACF_NORMUSER | ACF_PWDNOEXP;
			if (uinfo->su_ctrl & SMB_PWF_DISABLE)
				user->ctrl |= ACF_DISABLED;
			if (NDR_MSTRING(mxa, uinfo->su_name,
			    (ndr_mstring_t *)&user->name) == -1) {
				smb_pwd_iterclose(&pwi);
				status = NT_STATUS_NO_MEMORY;
				goto error;
			}
			(void) NDR_MSTRING(mxa, uinfo->su_fullname,
			    (ndr_mstring_t *)&user->fullname);
			(void) NDR_MSTRING(mxa, uinfo->su_desc,
			    (ndr_mstring_t *)&user->desc);
			user++;
		}
		smb_pwd_iterclose(&pwi);

		if (retcnt >= max_retcnt) {
			retcnt = max_retcnt;
			param->status = status;
		} else {
			param->status = NT_STATUS_MORE_ENTRIES;
		}

		param->users.total_size = num_users;
		param->users.returned_size = retcnt;
		param->users.switch_value = param->level;
		param->users.count = retcnt;

		break;

	default:
		status = NT_STATUS_INVALID_HANDLE;
		goto error;
	}

	return (NDR_DRC_OK);

no_info:
	param->users.total_size = 0;
	param->users.returned_size = 0;
	param->users.switch_value = param->level;
	param->users.count = 0;
	param->users.acct = NULL;
	param->status = status;
	return (NDR_DRC_OK);

error:
	bzero(param, sizeof (struct samr_QueryDispInfo));
	param->status = NT_SC_ERROR(status);
	return (NDR_DRC_OK);
}

/*
 * samr_s_EnumDomainGroups
 *
 *
 * This function is supposed to return local group information.
 * As we don't support local users, this function dosen't send
 * back any information.
 *
 * Added template that returns information for a domain group as None.
 * All information is hard-coded from packet captures.
 */
static int
samr_s_EnumDomainGroups(void *arg, ndr_xa_t *mxa)
{
	struct samr_EnumDomainGroups *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->domain_handle;
	DWORD status = NT_STATUS_SUCCESS;

	if (samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN) == NULL)
		status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);

	param->total_size = 0;
	param->returned_size = 0;
	param->switch_value = 3;
	param->count = 0;
	param->groups = 0;
	param->status = status;
	return (NDR_DRC_OK);

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
		param->groups = (struct group_disp_info *)NDR_MALLOC(
		    mxa, sizeof (struct group_disp_info));

		param->groups->count = 1;
		param->groups->acct[0].index = 1;
		param->groups->acct[0].rid = 513;
		param->groups->acct[0].ctrl = 0x7;
		(void) NDR_MSTRING(mxa, "None",
		    (ndr_mstring_t *)&param->groups->acct[0].name);

		(void) NDR_MSTRING(mxa, "Ordinary users",
		    (ndr_mstring_t *)&param->groups->acct[0].desc);
	}

	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
#endif
}

/*
 * samr_s_OpenAlias
 *
 * Lookup for requested alias, if it exists return a handle
 * for that alias. The alias domain sid should match with
 * the passed domain handle.
 */
static int
samr_s_OpenAlias(void *arg, ndr_xa_t *mxa)
{
	struct samr_OpenAlias *param = arg;
	ndr_hdid_t	*id = (ndr_hdid_t *)&param->domain_handle;
	ndr_handle_t	*hd;
	samr_keydata_t	*data;
	smb_domain_type_t gd_type;
	smb_sid_t	*sid;
	smb_wka_t	*wka;
	char		sidstr[SMB_SID_STRSZ];
	uint32_t	rid;
	uint32_t	status;
	int		rc;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL) {
		status = NT_STATUS_INVALID_HANDLE;
		goto open_alias_err;
	}

	if ((param->access_mask & SAMR_ALIAS_ACCESS_ALL_ACCESS) == 0) {
		status = NT_STATUS_ACCESS_DENIED;
		goto open_alias_err;
	}

	data = (samr_keydata_t *)hd->nh_data;
	gd_type = (smb_domain_type_t)data->kd_type;
	rid = param->rid;

	switch (gd_type) {
	case SMB_DOMAIN_BUILTIN:
		(void) snprintf(sidstr, SMB_SID_STRSZ, "%s-%d",
		    NT_BUILTIN_DOMAIN_SIDSTR, rid);
		if ((sid = smb_sid_fromstr(sidstr)) == NULL) {
			status = NT_STATUS_NO_SUCH_ALIAS;
			goto open_alias_err;
		}

		wka = smb_wka_lookup_sid(sid);
		smb_sid_free(sid);

		if (wka == NULL) {
			status = NT_STATUS_NO_SUCH_ALIAS;
			goto open_alias_err;
		}
		break;

	case SMB_DOMAIN_LOCAL:
		rc = smb_lgrp_getbyrid(rid, gd_type, NULL);
		if (rc != SMB_LGRP_SUCCESS) {
			status = NT_STATUS_NO_SUCH_ALIAS;
			goto open_alias_err;
		}
		break;

	default:
		status = NT_STATUS_NO_SUCH_ALIAS;
		goto open_alias_err;
	}

	id = samr_hdalloc(mxa, SAMR_KEY_ALIAS, data->kd_type, param->rid);
	if (id) {
		bcopy(id, &param->alias_handle, sizeof (samr_handle_t));
		param->status = NT_STATUS_SUCCESS;
		return (NDR_DRC_OK);
	}

	status = NT_STATUS_NO_MEMORY;

open_alias_err:
	bzero(&param->alias_handle, sizeof (samr_handle_t));
	param->status = NT_SC_ERROR(status);
	return (NDR_DRC_OK);
}

/*
 * samr_s_CreateDomainAlias
 *
 * Create a local group in the security accounts manager (SAM) database.
 * A local SAM group can only be added if a Solaris group already exists
 * with the same name.  On success, a valid group handle is returned.
 *
 * The caller must have administrator rights to execute this function.
 */
static int
samr_s_CreateDomainAlias(void *arg, ndr_xa_t *mxa)
{
	struct samr_CreateDomainAlias *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->alias_handle;
	uint32_t status = NT_STATUS_SUCCESS;
	smb_group_t grp;
	uint32_t rc;
	char *gname;

	if (samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN) != NULL) {
		bzero(param, sizeof (struct samr_CreateDomainAlias));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	gname = (char *)param->alias_name.str;
	if (gname == NULL) {
		bzero(&param->alias_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_PARAMETER);
		return (NDR_DRC_OK);
	}

	if ((!ndr_is_admin(mxa)) ||
	    ((param->access_mask & SAMR_ALIAS_ACCESS_WRITE_ACCOUNT) == 0)) {
		bzero(&param->alias_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}

	rc = smb_lgrp_add(gname, "");
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(&param->alias_handle, sizeof (samr_handle_t));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	rc = smb_lgrp_getbyname((char *)gname, &grp);
	if (rc != SMB_LGRP_SUCCESS) {
		bzero(&param->alias_handle, sizeof (samr_handle_t));
		status = smb_lgrp_err_to_ntstatus(rc);
		param->status = NT_SC_ERROR(status);
		return (NDR_DRC_OK);
	}

	id = samr_hdalloc(mxa, SAMR_KEY_ALIAS, SMB_DOMAIN_LOCAL, grp.sg_rid);
	smb_lgrp_free(&grp);
	if (id) {
		bcopy(id, &param->alias_handle, sizeof (samr_handle_t));
		param->status = status;
	} else {
		bzero(&param->alias_handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}

/*
 * samr_s_SetAliasInfo
 *
 * Similar to NetLocalGroupSetInfo.
 */
static int
samr_s_SetAliasInfo(void *arg, ndr_xa_t *mxa)
{
	struct samr_SetAliasInfo *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->alias_handle;
	DWORD status = NT_STATUS_SUCCESS;

	if (samr_hdlookup(mxa, id, SAMR_KEY_ALIAS) == NULL)
		status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);

	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * samr_s_QueryAliasInfo
 *
 * Retrieves information about the specified local group account
 * by given handle.
 */
static int
samr_s_QueryAliasInfo(void *arg, ndr_xa_t *mxa)
{
	struct samr_QueryAliasInfo *param = arg;
	ndr_hdid_t	*id = (ndr_hdid_t *)&param->alias_handle;
	ndr_handle_t	*hd;
	samr_keydata_t	*data;
	smb_group_t	grp;
	smb_domain_type_t gd_type;
	smb_sid_t	*sid;
	smb_wka_t	*wka;
	char		sidstr[SMB_SID_STRSZ];
	char		*name;
	char		*desc;
	uint32_t	rid;
	uint32_t	status;
	int		rc;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_ALIAS)) == NULL) {
		status = NT_STATUS_INVALID_HANDLE;
		goto query_alias_err;
	}

	data = (samr_keydata_t *)hd->nh_data;
	gd_type = (smb_domain_type_t)data->kd_type;
	rid = data->kd_rid;

	switch (gd_type) {
	case SMB_DOMAIN_BUILTIN:
		(void) snprintf(sidstr, SMB_SID_STRSZ, "%s-%d",
		    NT_BUILTIN_DOMAIN_SIDSTR, rid);
		if ((sid = smb_sid_fromstr(sidstr)) == NULL) {
			status = NT_STATUS_NO_SUCH_ALIAS;
			goto query_alias_err;
		}

		wka = smb_wka_lookup_sid(sid);
		smb_sid_free(sid);

		if (wka == NULL) {
			status = NT_STATUS_NO_SUCH_ALIAS;
			goto query_alias_err;
		}

		name = wka->wka_name;
		desc = (wka->wka_desc != NULL) ? wka->wka_desc : "";
		break;

	case SMB_DOMAIN_LOCAL:
		rc = smb_lgrp_getbyrid(rid, gd_type, &grp);
		if (rc != SMB_LGRP_SUCCESS) {
			status = NT_STATUS_NO_SUCH_ALIAS;
			goto query_alias_err;
		}
		name = grp.sg_name;
		desc = grp.sg_cmnt;
		break;

	default:
		status = NT_STATUS_NO_SUCH_ALIAS;
		goto query_alias_err;
	}

	switch (param->level) {
	case SAMR_QUERY_ALIAS_INFO_1:
		param->ru.info1.level = param->level;
		(void) NDR_MSTRING(mxa, name,
		    (ndr_mstring_t *)&param->ru.info1.name);

		(void) NDR_MSTRING(mxa, desc,
		    (ndr_mstring_t *)&param->ru.info1.desc);

		param->ru.info1.unknown = 1;
		break;

	case SAMR_QUERY_ALIAS_INFO_3:
		param->ru.info3.level = param->level;
		(void) NDR_MSTRING(mxa, desc,
		    (ndr_mstring_t *)&param->ru.info3.desc);
		break;

	default:
		if (gd_type == SMB_DOMAIN_LOCAL)
			smb_lgrp_free(&grp);
		status = NT_STATUS_INVALID_INFO_CLASS;
		goto query_alias_err;
	};

	if (gd_type == SMB_DOMAIN_LOCAL)
		smb_lgrp_free(&grp);
	param->address = (DWORD)(uintptr_t)&param->ru;
	param->status = 0;
	return (NDR_DRC_OK);

query_alias_err:
	param->status = NT_SC_ERROR(status);
	return (NDR_DRC_OK);
}

/*
 * samr_s_DeleteDomainAlias
 *
 * Deletes a local group in the security database, which is the
 * security accounts manager (SAM). A valid group handle is returned
 * to the caller upon success.
 *
 * The caller must have administrator rights to execute this function.
 */
static int
samr_s_DeleteDomainAlias(void *arg, ndr_xa_t *mxa)
{
	struct samr_DeleteDomainAlias *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->alias_handle;
	ndr_handle_t	*hd;
	smb_group_t grp;
	samr_keydata_t	*data;
	smb_domain_type_t	gd_type;
	uint32_t	rid;
	uint32_t	rc;
	uint32_t	status = NT_STATUS_SUCCESS;

	if (!ndr_is_admin(mxa)) {
		bzero(param, sizeof (struct samr_DeleteDomainAlias));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_ALIAS)) == NULL) {
		bzero(param, sizeof (struct samr_DeleteDomainAlias));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (samr_keydata_t *)hd->nh_data;
	gd_type = (smb_domain_type_t)data->kd_type;
	rid = data->kd_rid;

	switch (gd_type) {
	case SMB_DOMAIN_BUILTIN:
		bzero(param, sizeof (struct samr_DeleteDomainAlias));
		status = NT_SC_ERROR(NT_STATUS_NOT_SUPPORTED);
		break;

	case SMB_DOMAIN_LOCAL:
		rc = smb_lgrp_getbyrid(rid, gd_type, &grp);
		if (rc != SMB_LGRP_SUCCESS) {
			bzero(param, sizeof (struct samr_DeleteDomainAlias));
			status = smb_lgrp_err_to_ntstatus(rc);
			status = NT_SC_ERROR(status);
			break;
		}

		rc = smb_lgrp_delete(grp.sg_name);
		if (rc != SMB_LGRP_SUCCESS) {
			bzero(param, sizeof (struct samr_DeleteDomainAlias));
			status = smb_lgrp_err_to_ntstatus(rc);
			status = NT_SC_ERROR(status);
		}
		smb_lgrp_free(&grp);
		break;

	default:
		bzero(param, sizeof (struct samr_DeleteDomainAlias));
		status = NT_SC_ERROR(NT_STATUS_NO_SUCH_ALIAS);
	}

	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * samr_s_EnumDomainAliases
 *
 * This function sends back a list which contains all local groups' name.
 */
static int
samr_s_EnumDomainAliases(void *arg, ndr_xa_t *mxa)
{
	struct samr_EnumDomainAliases *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->domain_handle;
	ndr_handle_t *hd;
	samr_keydata_t *data;
	smb_group_t grp;
	smb_giter_t gi;
	int cnt, skip, i;
	struct name_rid *info;

	if ((hd = samr_hdlookup(mxa, id, SAMR_KEY_DOMAIN)) == NULL) {
		bzero(param, sizeof (struct samr_EnumDomainAliases));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (samr_keydata_t *)hd->nh_data;

	cnt = smb_sam_grp_cnt(data->kd_type);
	if (cnt <= param->resume_handle) {
		param->aliases = (struct aliases_info *)NDR_MALLOC(mxa,
		    sizeof (struct aliases_info));

		if (param->aliases == NULL) {
			bzero(param, sizeof (struct samr_EnumDomainAliases));
			param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
			return (NDR_DRC_OK);
		}

		bzero(param->aliases, sizeof (struct aliases_info));
		param->out_resume = 0;
		param->entries = 0;
		param->status = NT_STATUS_SUCCESS;
		return (NDR_DRC_OK);
	}

	cnt -= param->resume_handle;
	param->aliases = (struct aliases_info *)NDR_MALLOC(mxa,
	    sizeof (struct aliases_info) + (cnt-1) * sizeof (struct name_rid));

	if (param->aliases == NULL) {
		bzero(param, sizeof (struct samr_EnumDomainAliases));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	if (smb_lgrp_iteropen(&gi) != SMB_LGRP_SUCCESS) {
		bzero(param, sizeof (struct samr_EnumDomainAliases));
		param->status = NT_SC_ERROR(NT_STATUS_INTERNAL_ERROR);
		return (NDR_DRC_OK);
	}

	skip = i = 0;
	info = param->aliases->info;
	while (smb_lgrp_iterate(&gi, &grp) == SMB_LGRP_SUCCESS) {
		if ((skip++ >= param->resume_handle) &&
		    (grp.sg_domain == data->kd_type) && (i++ < cnt)) {
			info->rid = grp.sg_rid;
			(void) NDR_MSTRING(mxa, grp.sg_name,
			    (ndr_mstring_t *)&info->name);

			info++;
		}
		smb_lgrp_free(&grp);
	}
	smb_lgrp_iterclose(&gi);

	param->aliases->count = i;
	param->aliases->address = i;

	param->out_resume = i;
	param->entries = i;
	param->status = 0;
	return (NDR_DRC_OK);
}

/*
 * samr_s_Connect4
 */
static int
samr_s_Connect4(void *arg, ndr_xa_t *mxa)
{
	struct samr_Connect4	*param = arg;
	ndr_hdid_t		*id;

	id = samr_hdalloc(mxa, SAMR_KEY_CONNECT, SMB_DOMAIN_NULL, 0);
	if (id) {
		bcopy(id, &param->handle, sizeof (samr_handle_t));
		param->status = 0;
	} else {
		bzero(&param->handle, sizeof (samr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
	}

	return (NDR_DRC_OK);
}

/*
 * samr_s_Connect5
 *
 * This is the connect5 form of the connect request used by Windows XP.
 * Returns an RPC fault for now.
 */
/*ARGSUSED*/
static int
samr_s_Connect5(void *arg, ndr_xa_t *mxa)
{
	struct samr_Connect5 *param = arg;

	bzero(param, sizeof (struct samr_Connect5));
	return (NDR_DRC_FAULT_REQUEST_OPNUM_INVALID);
}

static ndr_stub_table_t samr_stub_table[] = {
	{ samr_s_Connect,		SAMR_OPNUM_Connect },
	{ samr_s_CloseHandle,		SAMR_OPNUM_CloseHandle },
	{ samr_s_LookupDomain,		SAMR_OPNUM_LookupDomain },
	{ samr_s_EnumLocalDomains,	SAMR_OPNUM_EnumLocalDomains },
	{ samr_s_OpenDomain,		SAMR_OPNUM_OpenDomain },
	{ samr_s_QueryDomainInfo,	SAMR_OPNUM_QueryDomainInfo },
	{ samr_s_QueryInfoDomain2,	SAMR_OPNUM_QueryInfoDomain2 },
	{ samr_s_LookupNames,		SAMR_OPNUM_LookupNames },
	{ samr_s_OpenUser,		SAMR_OPNUM_OpenUser },
	{ samr_s_DeleteUser,		SAMR_OPNUM_DeleteUser },
	{ samr_s_QueryUserInfo,		SAMR_OPNUM_QueryUserInfo },
	{ samr_s_QueryUserGroups,	SAMR_OPNUM_QueryUserGroups },
	{ samr_s_OpenGroup,		SAMR_OPNUM_OpenGroup },
	{ samr_s_Connect2,		SAMR_OPNUM_Connect2 },
	{ samr_s_GetUserPwInfo,		SAMR_OPNUM_GetUserPwInfo },
	{ samr_s_CreateUser,		SAMR_OPNUM_CreateUser },
	{ samr_s_ChangePasswordUser2,	SAMR_OPNUM_ChangePasswordUser2 },
	{ samr_s_GetDomainPwInfo,	SAMR_OPNUM_GetDomainPwInfo },
	{ samr_s_SetUserInfo,		SAMR_OPNUM_SetUserInfo },
	{ samr_s_Connect4,		SAMR_OPNUM_Connect4 },
	{ samr_s_Connect5,		SAMR_OPNUM_Connect5 },
	{ samr_s_QueryDispInfo,		SAMR_OPNUM_QueryDispInfo },
	{ samr_s_OpenAlias,		SAMR_OPNUM_OpenAlias },
	{ samr_s_CreateDomainAlias,	SAMR_OPNUM_CreateDomainAlias },
	{ samr_s_SetAliasInfo,		SAMR_OPNUM_SetAliasInfo },
	{ samr_s_QueryAliasInfo,	SAMR_OPNUM_QueryAliasInfo },
	{ samr_s_DeleteDomainAlias,	SAMR_OPNUM_DeleteDomainAlias },
	{ samr_s_EnumDomainAliases,	SAMR_OPNUM_EnumDomainAliases },
	{ samr_s_EnumDomainGroups,	SAMR_OPNUM_EnumDomainGroups },
	{ samr_s_AddAliasMember,	SAMR_OPNUM_AddAliasMember },
	{ samr_s_DeleteAliasMember,	SAMR_OPNUM_DeleteAliasMember },
	{ samr_s_ListAliasMembers,	SAMR_OPNUM_ListAliasMembers },
	{0}
};

/*
 * There is a bug in the way that midl and the marshalling code handles
 * unions so we need to fix some of the data offsets at runtime. The
 * following macros and the fixup functions handle the corrections.
 */

DECL_FIXUP_STRUCT(samr_QueryAliasInfo_ru);
DECL_FIXUP_STRUCT(samr_QueryAliasInfoRes);
DECL_FIXUP_STRUCT(samr_QueryAliasInfo);

DECL_FIXUP_STRUCT(QueryUserInfo_result_u);
DECL_FIXUP_STRUCT(QueryUserInfo_result);
DECL_FIXUP_STRUCT(samr_QueryUserInfo);

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
	size3 = size2 + sizeof (ndr_request_hdr_t) + sizeof (DWORD);

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
		CASE_INFO_ENT(samr_QueryUserInfo, 21);

		default:
			return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (ndr_request_hdr_t) + sizeof (DWORD);

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
