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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Windows Registry RPC (WINREG) server-side interface.
 *
 * The registry is a database with a hierarchical structure similar to
 * a file system, with keys in place of directories and values in place
 * of files.  The top level keys are known as root keys and each key can
 * contain subkeys and values.  As with directories and sub-directories,
 * the terms key and subkey are used interchangeably.  Values, analogous
 * to files, contain data.
 *
 * A specific subkey can be identifies by its fully qualified name (FQN),
 * which is analogous to a file system path.  In the registry, the key
 * separator is the '\' character, which is reserved and cannot appear
 * in key or value names.  Registry names are case-insensitive.
 *
 * For example:  HKEY_LOCAL_MACHINE\System\CurrentControlSet
 *
 * The HKEY_LOCAL_MACHINE root key contains a subkey called System, and
 * System contains a subkey called CurrentControlSet.
 *
 * The WINREG RPC interface returns Win32 error codes.
 */

#include <sys/utsname.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/winreg.ndl>

/*
 * List of supported registry keys (case-insensitive).
 */
static char *winreg_keys[] = {
	"HKLM",
	"HKU",
	"HKLM\\SOFTWARE",
	"HKLM\\SYSTEM",
	"System",
	"CurrentControlSet",
	"SunOS",
	"Solaris",
	"System\\CurrentControlSet\\Services\\Eventlog",
	"System\\CurrentControlSet\\Control\\ProductOptions",
	"SOFTWARE",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
};

static char *winreg_eventlog = "System\\CurrentControlSet\\Services\\Eventlog";

static char *winreg_log[] = {
	"Application",
	"Security",
	"System",
	"smbd",
	"smbrdr"
};

typedef struct winreg_subkey {
	list_node_t sk_lnd;
	ndr_hdid_t sk_handle;
	char sk_name[MAXPATHLEN];
	boolean_t sk_predefined;
} winreg_subkey_t;

typedef struct winreg_keylist {
	list_t kl_list;
	int kl_count;
} winreg_keylist_t;

static winreg_keylist_t winreg_keylist;
static mutex_t winreg_mutex;

static void winreg_add_predefined(const char *);
static ndr_hdid_t *winreg_alloc_id(ndr_xa_t *, const char *);
static void winreg_dealloc_id(ndr_xa_t *, ndr_hdid_t *);
static boolean_t winreg_key_has_subkey(const char *);
static char *winreg_enum_subkey(ndr_xa_t *, const char *, uint32_t);
static char *winreg_lookup_value(const char *);
static uint32_t winreg_sd_format(smb_sd_t *);
uint32_t srvsvc_sd_set_relative(smb_sd_t *, uint8_t *);

static int winreg_s_OpenHKCR(void *, ndr_xa_t *);
static int winreg_s_OpenHKCU(void *, ndr_xa_t *);
static int winreg_s_OpenHKLM(void *, ndr_xa_t *);
static int winreg_s_OpenHKPD(void *, ndr_xa_t *);
static int winreg_s_OpenHKU(void *, ndr_xa_t *);
static int winreg_s_OpenHKCC(void *, ndr_xa_t *);
static int winreg_s_OpenHKDD(void *, ndr_xa_t *);
static int winreg_s_OpenHKPT(void *, ndr_xa_t *);
static int winreg_s_OpenHKPN(void *, ndr_xa_t *);
static int winreg_s_OpenHK(void *, ndr_xa_t *, const char *);
static int winreg_s_Close(void *, ndr_xa_t *);
static int winreg_s_CreateKey(void *, ndr_xa_t *);
static int winreg_s_DeleteKey(void *, ndr_xa_t *);
static int winreg_s_DeleteValue(void *, ndr_xa_t *);
static int winreg_s_EnumKey(void *, ndr_xa_t *);
static int winreg_s_EnumValue(void *, ndr_xa_t *);
static int winreg_s_FlushKey(void *, ndr_xa_t *);
static int winreg_s_GetKeySec(void *, ndr_xa_t *);
static int winreg_s_NotifyChange(void *, ndr_xa_t *);
static int winreg_s_OpenKey(void *, ndr_xa_t *);
static int winreg_s_QueryKey(void *, ndr_xa_t *);
static int winreg_s_QueryValue(void *, ndr_xa_t *);
static int winreg_s_SetKeySec(void *, ndr_xa_t *);
static int winreg_s_CreateValue(void *, ndr_xa_t *);
static int winreg_s_Shutdown(void *, ndr_xa_t *);
static int winreg_s_AbortShutdown(void *, ndr_xa_t *);
static int winreg_s_GetVersion(void *, ndr_xa_t *);

static ndr_stub_table_t winreg_stub_table[] = {
	{ winreg_s_OpenHKCR,	WINREG_OPNUM_OpenHKCR },
	{ winreg_s_OpenHKCU,	WINREG_OPNUM_OpenHKCU },
	{ winreg_s_OpenHKLM,	WINREG_OPNUM_OpenHKLM },
	{ winreg_s_OpenHKPD,	WINREG_OPNUM_OpenHKPD },
	{ winreg_s_OpenHKU,	WINREG_OPNUM_OpenHKUsers },
	{ winreg_s_Close,	WINREG_OPNUM_Close },
	{ winreg_s_CreateKey,	WINREG_OPNUM_CreateKey },
	{ winreg_s_DeleteKey,	WINREG_OPNUM_DeleteKey },
	{ winreg_s_DeleteValue,	WINREG_OPNUM_DeleteValue },
	{ winreg_s_EnumKey,	WINREG_OPNUM_EnumKey },
	{ winreg_s_EnumValue,	WINREG_OPNUM_EnumValue },
	{ winreg_s_FlushKey,	WINREG_OPNUM_FlushKey },
	{ winreg_s_GetKeySec,	WINREG_OPNUM_GetKeySec },
	{ winreg_s_NotifyChange,	WINREG_OPNUM_NotifyChange },
	{ winreg_s_OpenKey,	WINREG_OPNUM_OpenKey },
	{ winreg_s_QueryKey,	WINREG_OPNUM_QueryKey },
	{ winreg_s_QueryValue,	WINREG_OPNUM_QueryValue },
	{ winreg_s_SetKeySec,	WINREG_OPNUM_SetKeySec },
	{ winreg_s_CreateValue,	WINREG_OPNUM_CreateValue },
	{ winreg_s_Shutdown,	WINREG_OPNUM_Shutdown },
	{ winreg_s_AbortShutdown,	WINREG_OPNUM_AbortShutdown },
	{ winreg_s_GetVersion,	WINREG_OPNUM_GetVersion },
	{ winreg_s_OpenHKCC,	WINREG_OPNUM_OpenHKCC },
	{ winreg_s_OpenHKDD,	WINREG_OPNUM_OpenHKDD },
	{ winreg_s_OpenHKPT,	WINREG_OPNUM_OpenHKPT },
	{ winreg_s_OpenHKPN,	WINREG_OPNUM_OpenHKPN },
	{0}
};

static ndr_service_t winreg_service = {
	"Winreg",			/* name */
	"Windows Registry",		/* desc */
	"\\winreg",			/* endpoint */
	PIPE_WINREG,			/* sec_addr_port */
	"338cd001-2244-31f1-aaaa-900038001003", 1,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(winreg_interface),	/* interface ti */
	winreg_stub_table		/* stub_table */
};

static char winreg_sysname[SYS_NMLN];
static char winreg_sysver[SMB_VERSTR_LEN];

/*
 * winreg_initialize
 *
 * Initialize and register the WINREG RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
winreg_initialize(void)
{
	smb_version_t version;
	struct utsname name;
	char subkey[MAXPATHLEN];
	char *sysname;
	int i;

	(void) mutex_lock(&winreg_mutex);

	list_create(&winreg_keylist.kl_list, sizeof (winreg_subkey_t),
	    offsetof(winreg_subkey_t, sk_lnd));
	winreg_keylist.kl_count = 0;

	for (i = 0; i < sizeof (winreg_keys)/sizeof (winreg_keys[0]); ++i)
		winreg_add_predefined(winreg_keys[i]);

	for (i = 0; i < sizeof (winreg_log)/sizeof (winreg_log[0]); ++i) {
		(void) snprintf(subkey, MAXPATHLEN, "%s", winreg_log[i]);
		winreg_add_predefined(subkey);

		(void) snprintf(subkey, MAXPATHLEN, "%s\\%s",
		    winreg_eventlog, winreg_log[i]);
		winreg_add_predefined(subkey);

		(void) snprintf(subkey, MAXPATHLEN, "%s\\%s\\%s",
		    winreg_eventlog, winreg_log[i], winreg_log[i]);
		winreg_add_predefined(subkey);
	}

	(void) mutex_unlock(&winreg_mutex);

	if (uname(&name) < 0)
		sysname = "Solaris";
	else
		sysname = name.sysname;

	(void) strlcpy(winreg_sysname, sysname, SYS_NMLN);

	smb_config_get_version(&version);
	(void) snprintf(winreg_sysver, SMB_VERSTR_LEN, "%d.%d",
	    version.sv_major, version.sv_minor);

	(void) ndr_svc_register(&winreg_service);
}

static void
winreg_add_predefined(const char *subkey)
{
	winreg_subkey_t *key;

	if ((key = malloc(sizeof (winreg_subkey_t))) != NULL) {
		bzero(key, sizeof (winreg_subkey_t));
		(void) strlcpy(key->sk_name, subkey, MAXPATHLEN);
		key->sk_predefined = B_TRUE;

		list_insert_tail(&winreg_keylist.kl_list, key);
		++winreg_keylist.kl_count;
	}
}

static int
winreg_s_OpenHKCR(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKCR"));
}

static int
winreg_s_OpenHKCU(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKCU"));
}

static int
winreg_s_OpenHKLM(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKLM"));
}

static int
winreg_s_OpenHKPD(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKPD"));
}

static int
winreg_s_OpenHKU(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKU"));
}

static int
winreg_s_OpenHKCC(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKCC"));
}

static int
winreg_s_OpenHKDD(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKDD"));
}

static int
winreg_s_OpenHKPT(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKPT"));
}

static int
winreg_s_OpenHKPN(void *arg, ndr_xa_t *mxa)
{
	return (winreg_s_OpenHK(arg, mxa, "HKPN"));
}

/*
 * winreg_s_OpenHK
 *
 * Common code to open root HKEYs.
 */
static int
winreg_s_OpenHK(void *arg, ndr_xa_t *mxa, const char *hkey)
{
	struct winreg_OpenHKCR *param = arg;
	ndr_hdid_t *id;

	(void) mutex_lock(&winreg_mutex);

	if ((id = winreg_alloc_id(mxa, hkey)) == NULL) {
		bzero(&param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	} else {
		bcopy(id, &param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_SUCCESS;
	}

	(void) mutex_unlock(&winreg_mutex);
	return (NDR_DRC_OK);
}

/*
 * winreg_s_Close
 *
 * This is a request to close the WINREG interface specified by the
 * handle. We don't track handles (yet), so just zero out the handle
 * and return NDR_DRC_OK. Setting the handle to zero appears to be
 * standard behaviour.
 */
static int
winreg_s_Close(void *arg, ndr_xa_t *mxa)
{
	struct winreg_Close *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	(void) mutex_lock(&winreg_mutex);
	winreg_dealloc_id(mxa, id);
	(void) mutex_unlock(&winreg_mutex);

	bzero(&param->result_handle, sizeof (winreg_handle_t));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

static ndr_hdid_t *
winreg_alloc_id(ndr_xa_t *mxa, const char *key)
{
	ndr_handle_t	*hd;
	ndr_hdid_t	*id;
	char		*data;

	if ((data = strdup(key)) == NULL)
		return (NULL);

	if ((id = ndr_hdalloc(mxa, data)) == NULL) {
		free(data);
		return (NULL);
	}

	if ((hd = ndr_hdlookup(mxa, id)) != NULL)
		hd->nh_data_free = free;

	return (id);
}

static void
winreg_dealloc_id(ndr_xa_t *mxa, ndr_hdid_t *id)
{
	ndr_handle_t *hd;

	if ((hd = ndr_hdlookup(mxa, id)) != NULL) {
		free(hd->nh_data);
		hd->nh_data = NULL;
	}

	ndr_hdfree(mxa, id);
}

/*
 * winreg_s_CreateKey
 */
static int
winreg_s_CreateKey(void *arg, ndr_xa_t *mxa)
{
	struct winreg_CreateKey *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	winreg_subkey_t *key;
	char *subkey;
	DWORD *action;

	subkey = (char *)param->subkey.str;

	if (!ndr_is_admin(mxa) || (subkey == NULL)) {
		bzero(param, sizeof (struct winreg_CreateKey));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	(void) mutex_lock(&winreg_mutex);

	hd = ndr_hdlookup(mxa, id);
	if (hd == NULL) {
		(void) mutex_unlock(&winreg_mutex);
		bzero(param, sizeof (struct winreg_CreateKey));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	if ((action = NDR_NEW(mxa, DWORD)) == NULL) {
		(void) mutex_unlock(&winreg_mutex);
		bzero(param, sizeof (struct winreg_CreateKey));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	if (list_is_empty(&winreg_keylist.kl_list))
		goto new_key;

	/*
	 * Check for an existing key.
	 */
	key = list_head(&winreg_keylist.kl_list);
	do {
		if (strcasecmp(subkey, key->sk_name) == 0) {
			bcopy(&key->sk_handle, &param->result_handle,
			    sizeof (winreg_handle_t));

			(void) mutex_unlock(&winreg_mutex);
			*action = WINREG_ACTION_EXISTING_KEY;
			param->action = action;
			param->status = ERROR_SUCCESS;
			return (NDR_DRC_OK);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

new_key:
	/*
	 * Create a new key.
	 */
	if ((id = winreg_alloc_id(mxa, subkey)) == NULL)
		goto no_memory;

	if ((key = malloc(sizeof (winreg_subkey_t))) == NULL) {
		winreg_dealloc_id(mxa, id);
		goto no_memory;
	}

	bcopy(id, &key->sk_handle, sizeof (ndr_hdid_t));
	(void) strlcpy(key->sk_name, subkey, MAXPATHLEN);
	key->sk_predefined = B_FALSE;
	list_insert_tail(&winreg_keylist.kl_list, key);
	++winreg_keylist.kl_count;

	bcopy(id, &param->result_handle, sizeof (winreg_handle_t));

	(void) mutex_unlock(&winreg_mutex);
	*action = WINREG_ACTION_NEW_KEY;
	param->action = action;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);

no_memory:
	(void) mutex_unlock(&winreg_mutex);
	bzero(param, sizeof (struct winreg_CreateKey));
	param->status = ERROR_NOT_ENOUGH_MEMORY;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_DeleteKey
 */
static int
winreg_s_DeleteKey(void *arg, ndr_xa_t *mxa)
{
	struct winreg_DeleteKey *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	winreg_subkey_t *key;
	char *subkey;

	subkey = (char *)param->subkey.str;

	if (!ndr_is_admin(mxa) || (subkey == NULL)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	(void) mutex_lock(&winreg_mutex);

	if ((ndr_hdlookup(mxa, id) == NULL) ||
	    list_is_empty(&winreg_keylist.kl_list) ||
	    winreg_key_has_subkey(subkey)) {
		(void) mutex_unlock(&winreg_mutex);
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	key = list_head(&winreg_keylist.kl_list);
	do {
		if (strcasecmp(subkey, key->sk_name) == 0) {
			if (key->sk_predefined == B_TRUE) {
				/* Predefined keys cannot be deleted */
				break;
			}

			list_remove(&winreg_keylist.kl_list, key);
			--winreg_keylist.kl_count;
			winreg_dealloc_id(mxa, &key->sk_handle);
			free(key);

			(void) mutex_unlock(&winreg_mutex);
			param->status = ERROR_SUCCESS;
			return (NDR_DRC_OK);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

	(void) mutex_unlock(&winreg_mutex);
	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * Call with the winreg_mutex held.
 */
static boolean_t
winreg_key_has_subkey(const char *subkey)
{
	winreg_subkey_t *key;
	int keylen;

	if (list_is_empty(&winreg_keylist.kl_list))
		return (B_FALSE);

	keylen = strlen(subkey);

	key = list_head(&winreg_keylist.kl_list);
	do {
		if (strncasecmp(subkey, key->sk_name, keylen) == 0) {
			/*
			 * Potential match.  If sk_name is longer than
			 * subkey, then sk_name is a subkey of our key.
			 */
			if (keylen < strlen(key->sk_name))
				return (B_TRUE);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

	return (B_FALSE);
}

/*
 * Call with the winreg_mutex held.
 */
static char *
winreg_enum_subkey(ndr_xa_t *mxa, const char *subkey, uint32_t index)
{
	winreg_subkey_t *key;
	char *entry;
	char *p;
	int subkeylen;
	int count = 0;

	if (subkey == NULL)
		return (NULL);

	if (list_is_empty(&winreg_keylist.kl_list))
		return (NULL);

	subkeylen = strlen(subkey);

	for (key = list_head(&winreg_keylist.kl_list);
	    key != NULL; key = list_next(&winreg_keylist.kl_list, key)) {
		if (strncasecmp(subkey, key->sk_name, subkeylen) == 0) {
			p = key->sk_name + subkeylen;

			if ((*p != '\\') || (*p == '\0')) {
				/*
				 * Not the same subkey or an exact match.
				 * We're looking for children of subkey.
				 */
				continue;
			}

			++p;

			if (count < index) {
				++count;
				continue;
			}

			if ((entry = NDR_STRDUP(mxa, p)) == NULL)
				return (NULL);

			if ((p = strchr(entry, '\\')) != NULL)
				*p = '\0';

			return (entry);
		}
	}

	return (NULL);
}

/*
 * winreg_s_DeleteValue
 */
/*ARGSUSED*/
static int
winreg_s_DeleteValue(void *arg, ndr_xa_t *mxa)
{
	struct winreg_DeleteValue *param = arg;

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_EnumKey
 */
static int
winreg_s_EnumKey(void *arg, ndr_xa_t *mxa)
{
	struct winreg_EnumKey *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	char *subkey;
	char *name = NULL;

	(void) mutex_lock(&winreg_mutex);

	if ((hd = ndr_hdlookup(mxa, id)) != NULL)
		name = hd->nh_data;

	if (hd == NULL || name == NULL) {
		(void) mutex_unlock(&winreg_mutex);
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_NO_MORE_ITEMS;
		return (NDR_DRC_OK);
	}

	subkey = winreg_enum_subkey(mxa, name, param->index);
	if (subkey == NULL) {
		(void) mutex_unlock(&winreg_mutex);
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_NO_MORE_ITEMS;
		return (NDR_DRC_OK);
	}

	if (NDR_MSTRING(mxa, subkey, (ndr_mstring_t *)&param->name_out) == -1) {
		(void) mutex_unlock(&winreg_mutex);
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	(void) mutex_unlock(&winreg_mutex);

	/*
	 * This request requires that the length includes the null.
	 */
	param->name_out.length = param->name_out.allosize;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_EnumValue
 */
static int
winreg_s_EnumValue(void *arg, ndr_xa_t *mxa)
{
	struct winreg_EnumValue *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	if (ndr_hdlookup(mxa, id) == NULL) {
		bzero(param, sizeof (struct winreg_EnumValue));
		param->status = ERROR_NO_MORE_ITEMS;
		return (NDR_DRC_OK);
	}

	bzero(param, sizeof (struct winreg_EnumValue));
	param->status = ERROR_NO_MORE_ITEMS;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_FlushKey
 *
 * Flush the attributes associated with the specified open key to disk.
 */
static int
winreg_s_FlushKey(void *arg, ndr_xa_t *mxa)
{
	struct winreg_FlushKey *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	if (ndr_hdlookup(mxa, id) == NULL)
		param->status = ERROR_INVALID_HANDLE;
	else
		param->status = ERROR_SUCCESS;

	return (NDR_DRC_OK);
}

/*
 * winreg_s_GetKeySec
 */
static int
winreg_s_GetKeySec(void *arg, ndr_xa_t *mxa)
{
	static struct winreg_secdesc	error_sd;
	struct winreg_GetKeySec		*param = arg;
	struct winreg_value		*sd_buf;
	smb_sd_t			sd;
	uint32_t			sd_len;
	uint32_t			status;

	bzero(&sd, sizeof (smb_sd_t));

	if ((status = winreg_sd_format(&sd)) != ERROR_SUCCESS)
		goto winreg_getkeysec_error;

	sd_len = smb_sd_len(&sd, SMB_ALL_SECINFO);
	sd_buf = NDR_MALLOC(mxa, sd_len + sizeof (struct winreg_value));

	param->sd = NDR_MALLOC(mxa, sizeof (struct winreg_secdesc));
	if ((param->sd == NULL) || (sd_buf == NULL)) {
		status = ERROR_NOT_ENOUGH_MEMORY;
		goto winreg_getkeysec_error;
	}

	param->sd->sd_len = sd_len;
	param->sd->sd_size = sd_len;
	param->sd->sd_buf = sd_buf;

	sd_buf->vc_first_is = 0;
	sd_buf->vc_length_is = sd_len;
	param->status = srvsvc_sd_set_relative(&sd, sd_buf->value);

	smb_sd_term(&sd);
	return (NDR_DRC_OK);

winreg_getkeysec_error:
	smb_sd_term(&sd);
	bzero(param, sizeof (struct winreg_GetKeySec));
	param->sd = &error_sd;
	param->status = status;
	return (NDR_DRC_OK);
}

static uint32_t
winreg_sd_format(smb_sd_t *sd)
{
	smb_fssd_t	fs_sd;
	acl_t		*acl;
	uint32_t	status = ERROR_SUCCESS;

	if (acl_fromtext("owner@:rwxpdDaARWcCos::allow", &acl) != 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_fssd_init(&fs_sd, SMB_ALL_SECINFO, SMB_FSSD_FLAGS_DIR);
	fs_sd.sd_uid = 0;
	fs_sd.sd_gid = 0;
	fs_sd.sd_zdacl = acl;
	fs_sd.sd_zsacl = NULL;

	if (smb_sd_fromfs(&fs_sd, sd) != NT_STATUS_SUCCESS)
		status = ERROR_ACCESS_DENIED;
	smb_fssd_term(&fs_sd);
	return (status);
}

/*
 * winreg_s_NotifyChange
 */
static int
winreg_s_NotifyChange(void *arg, ndr_xa_t *mxa)
{
	struct winreg_NotifyChange *param = arg;

	if (ndr_is_admin(mxa))
		param->status = ERROR_SUCCESS;
	else
		param->status = ERROR_ACCESS_DENIED;

	return (NDR_DRC_OK);
}

/*
 * winreg_s_OpenKey
 *
 * This is a request to open a windows registry key.
 * If we recognize the key, we return a handle.
 *
 * Returns:
 *	ERROR_SUCCESS		Valid handle returned.
 *	ERROR_FILE_NOT_FOUND	No key or unable to allocate a handle.
 */
static int
winreg_s_OpenKey(void *arg, ndr_xa_t *mxa)
{
	struct winreg_OpenKey *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	char *subkey = (char *)param->name.str;
	winreg_subkey_t *key;

	(void) mutex_lock(&winreg_mutex);

	if (subkey == NULL || *subkey == '\0') {
		if ((hd = ndr_hdlookup(mxa, id)) != NULL)
			subkey = hd->nh_data;
	}

	id = NULL;

	if (subkey == NULL || list_is_empty(&winreg_keylist.kl_list)) {
		(void) mutex_unlock(&winreg_mutex);
		bzero(&param->result_handle, sizeof (winreg_handle_t));
		param->status = ERROR_FILE_NOT_FOUND;
		return (NDR_DRC_OK);
	}

	key = list_head(&winreg_keylist.kl_list);
	do {
		if (strcasecmp(subkey, key->sk_name) == 0) {
			if (key->sk_predefined == B_TRUE)
				id = winreg_alloc_id(mxa, subkey);
			else
				id = &key->sk_handle;

			if (id == NULL)
				break;

			bcopy(id, &param->result_handle,
			    sizeof (winreg_handle_t));

			(void) mutex_unlock(&winreg_mutex);
			param->status = ERROR_SUCCESS;
			return (NDR_DRC_OK);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

	(void) mutex_unlock(&winreg_mutex);
	bzero(&param->result_handle, sizeof (winreg_handle_t));
	param->status = ERROR_FILE_NOT_FOUND;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_QueryKey
 */
/*ARGSUSED*/
static int
winreg_s_QueryKey(void *arg, ndr_xa_t *mxa)
{
	struct winreg_QueryKey *param = arg;
	int rc;
	winreg_string_t	*name;

	name = (winreg_string_t	*)&param->name;
	bzero(param, sizeof (struct winreg_QueryKey));

	if ((name = NDR_NEW(mxa, winreg_string_t)) != NULL)
		rc = NDR_MSTRING(mxa, "", (ndr_mstring_t *)name);

	if ((name == NULL) || (rc != 0)) {
		bzero(param, sizeof (struct winreg_QueryKey));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_QueryValue
 *
 * This is a request to get the value associated with a specified name.
 *
 * Returns:
 *	ERROR_SUCCESS		Value returned.
 *	ERROR_FILE_NOT_FOUND	PrimaryModule is not supported.
 *	ERROR_CANTREAD          No such name or memory problem.
 */
static int
winreg_s_QueryValue(void *arg, ndr_xa_t *mxa)
{
	struct winreg_QueryValue *param = arg;
	struct winreg_value *pv;
	char *name;
	char *value;
	DWORD slen;
	DWORD msize;

	name = (char *)param->value_name.str;

	if (name == NULL ||
	    strcasecmp(name, "PrimaryModule") == 0) {
		param->status = ERROR_FILE_NOT_FOUND;
		return (NDR_DRC_OK);
	}

	if ((value = winreg_lookup_value(name)) == NULL) {
		param->status = ERROR_CANTREAD;
		return (NDR_DRC_OK);
	}

	slen = smb_wcequiv_strlen(value) + sizeof (smb_wchar_t);
	msize = sizeof (struct winreg_value) + slen;

	param->value = (struct winreg_value *)NDR_MALLOC(mxa, msize);
	param->type = NDR_NEW(mxa, DWORD);
	param->value_size = NDR_NEW(mxa, DWORD);
	param->value_size_total = NDR_NEW(mxa, DWORD);

	if (param->value == NULL || param->type == NULL ||
	    param->value_size == NULL || param->value_size_total == NULL) {
		param->status = ERROR_CANTREAD;
		return (NDR_DRC_OK);
	}

	bzero(param->value, msize);
	pv = param->value;
	pv->vc_first_is = 0;
	pv->vc_length_is = slen;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	(void) ndr_mbstowcs(NULL, (smb_wchar_t *)pv->value, value, slen);

	*param->type = 1;
	*param->value_size = slen;
	*param->value_size_total = slen;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * Lookup a name in the registry and return the associated value.
 * Our registry is a case-insensitive, name-value pair table.
 *
 * Windows ProductType: WinNT, ServerNT, LanmanNT.
 *	Windows NT4.0 workstation: WinNT
 *	Windows NT4.0 server:      ServerNT
 *
 * If LanmanNT is used here, Windows 2000 sends LsarQueryInfoPolicy
 * with info level 6, which we don't support.  If we use ServerNT
 * (as reported by NT4.0 Server) Windows 2000 send requests for
 * levels 3 and 5, which are support.
 *
 * On success, returns a pointer to the value.  Otherwise returns
 * a null pointer.
 */
static char *
winreg_lookup_value(const char *name)
{
	static struct registry {
		char *name;
		char *value;
	} registry[] = {
		{ "SystemRoot",		"C:\\" },
		{ "CurrentVersion",	winreg_sysver },
		{ "ProductType",	"ServerNT" },
		{ "Sources",		winreg_sysname }, /* product name */
		{ "EventMessageFile",	"C:\\windows\\system32\\eventlog.dll" }
	};

	int i;

	for (i = 0; i < sizeof (registry)/sizeof (registry[0]); ++i) {
		if (strcasecmp(registry[i].name, name) == 0)
			return (registry[i].value);
	}

	return (NULL);
}

/*
 * winreg_s_SetKeySec
 */
/*ARGSUSED*/
static int
winreg_s_SetKeySec(void *arg, ndr_xa_t *mxa)
{
	struct winreg_SetKeySec *param = arg;

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_CreateValue
 */
/*ARGSUSED*/
static int
winreg_s_CreateValue(void *arg, ndr_xa_t *mxa)
{
	struct winreg_CreateValue *param = arg;

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_Shutdown
 *
 * Attempt to shutdown or reboot the system: access denied.
 */
/*ARGSUSED*/
static int
winreg_s_Shutdown(void *arg, ndr_xa_t *mxa)
{
	struct winreg_Shutdown *param = arg;

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * winreg_s_AbortShutdown
 *
 * Abort a shutdown request.
 */
static int
winreg_s_AbortShutdown(void *arg, ndr_xa_t *mxa)
{
	struct winreg_AbortShutdown *param = arg;

	if (ndr_is_admin(mxa))
		param->status = ERROR_SUCCESS;
	else
		param->status = ERROR_ACCESS_DENIED;

	return (NDR_DRC_OK);
}

/*
 * winreg_s_GetVersion
 *
 * Return the windows registry version.  The current version is 5.
 * This call is usually made prior to enumerating or querying registry
 * keys or values.
 */
/*ARGSUSED*/
static int
winreg_s_GetVersion(void *arg, ndr_xa_t *mxa)
{
	struct winreg_GetVersion *param = arg;

	param->version = 5;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}
