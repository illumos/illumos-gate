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
 * Windows Registry RPC (WINREG) server-side interface.
 *
 * The WINREG RPC interface returns Win32 error codes.
 *
 * HKLM		Hive Key Local Machine
 * HKU		Hive Key Users
 */

#include <sys/utsname.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nterror.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/winreg.ndl>

#define	WINREG_LOGR_SYSTEMKEY	\
	"System\\CurrentControlSet\\Services\\Eventlog\\System"

/*
 * Local handle management keys.
 */
static int winreg_hk;
static int winreg_hklm;
static int winreg_hkuser;
static int winreg_hkkey;

/*
 * List of supported registry keys (case-insensitive).
 */
static char *winreg_keys[] = {
	"System\\CurrentControlSet\\Services\\Eventlog",
	"System\\CurrentControlSet\\Services\\Eventlog\\System",
	"System\\CurrentControlSet\\Control\\ProductOptions",
	"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
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

static boolean_t winreg_key_has_subkey(const char *);
static char *winreg_lookup_value(const char *);
static char *winreg_lookup_eventlog_registry(char *, char *);

static int winreg_s_OpenHK(void *, ndr_xa_t *);
static int winreg_s_OpenHKLM(void *, ndr_xa_t *);
static int winreg_s_OpenHKUsers(void *, ndr_xa_t *);
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
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKCR },
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKCU },
	{ winreg_s_OpenHKLM,	WINREG_OPNUM_OpenHKLM },
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKPD },
	{ winreg_s_OpenHKUsers,	WINREG_OPNUM_OpenHKUsers },
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
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKCC },
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKDD },
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKPT },
	{ winreg_s_OpenHK,	WINREG_OPNUM_OpenHKPN },
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
	winreg_subkey_t *key;
	struct utsname name;
	char *sysname;
	int i;

	list_create(&winreg_keylist.kl_list, sizeof (winreg_subkey_t),
	    offsetof(winreg_subkey_t, sk_lnd));
	winreg_keylist.kl_count = 0;

	for (i = 0; i < sizeof (winreg_keys)/sizeof (winreg_keys[0]); ++i) {
		if ((key = malloc(sizeof (winreg_subkey_t))) != NULL) {
			bzero(key, sizeof (winreg_subkey_t));
			(void) strlcpy(key->sk_name, winreg_keys[i],
			    MAXPATHLEN);
			key->sk_predefined = B_TRUE;
			list_insert_tail(&winreg_keylist.kl_list, key);
			++winreg_keylist.kl_count;
		}
	}

	if (uname(&name) < 0)
		sysname = "Solaris";
	else
		sysname = name.sysname;

	(void) strlcpy(winreg_sysname, sysname, SYS_NMLN);
	(void) ndr_svc_register(&winreg_service);
}

/*
 * winreg_s_OpenHK
 *
 * Stub.
 */
static int
winreg_s_OpenHK(void *arg, ndr_xa_t *mxa)
{
	struct winreg_OpenHKCR *param = arg;
	ndr_hdid_t *id;

	if ((id = ndr_hdalloc(mxa, &winreg_hk)) == NULL) {
		bzero(&param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	} else {
		bcopy(id, &param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_SUCCESS;
	}

	return (NDR_DRC_OK);
}

/*
 * winreg_s_OpenHKLM
 *
 * This is a request to open the HKLM and get a handle.
 * The client should treat the handle as an opaque object.
 *
 * Status:
 *	ERROR_SUCCESS		Valid handle returned.
 *	ERROR_ACCESS_DENIED	Unable to allocate a handle.
 */
static int
winreg_s_OpenHKLM(void *arg, ndr_xa_t *mxa)
{
	struct winreg_OpenHKLM *param = arg;
	ndr_hdid_t *id;

	if ((id = ndr_hdalloc(mxa, &winreg_hklm)) == NULL) {
		bzero(&param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	} else {
		bcopy(id, &param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_SUCCESS;
	}

	return (NDR_DRC_OK);
}

/*
 * winreg_s_OpenHKUsers
 *
 * This is a request to get a HKUsers handle. I'm not sure we are
 * ready to fully support this interface yet, mostly due to the need
 * to support subsequent requests, but we may support enough now. It
 * seems okay with regedt32.
 */
static int
winreg_s_OpenHKUsers(void *arg, ndr_xa_t *mxa)
{
	struct winreg_OpenHKUsers *param = arg;
	ndr_hdid_t *id;

	if ((id = ndr_hdalloc(mxa, &winreg_hkuser)) == NULL) {
		bzero(&param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_ACCESS_DENIED;
	} else {
		bcopy(id, &param->handle, sizeof (winreg_handle_t));
		param->status = ERROR_SUCCESS;
	}

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

	ndr_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (winreg_handle_t));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
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

	hd = ndr_hdlookup(mxa, id);
	if (hd == NULL) {
		bzero(param, sizeof (struct winreg_CreateKey));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	if ((action = NDR_NEW(mxa, DWORD)) == NULL) {
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
	id = ndr_hdalloc(mxa, &winreg_hkkey);
	key = malloc(sizeof (winreg_subkey_t));

	if ((id == NULL) || (key == NULL)) {
		bzero(param, sizeof (struct winreg_CreateKey));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	bcopy(id, &key->sk_handle, sizeof (ndr_hdid_t));
	(void) strlcpy(key->sk_name, subkey, MAXPATHLEN);
	key->sk_predefined = B_FALSE;
	list_insert_tail(&winreg_keylist.kl_list, key);
	++winreg_keylist.kl_count;

	bcopy(id, &param->result_handle, sizeof (winreg_handle_t));
	*action = WINREG_ACTION_NEW_KEY;
	param->action = action;
	param->status = ERROR_SUCCESS;
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

	if ((ndr_hdlookup(mxa, id) == NULL) ||
	    list_is_empty(&winreg_keylist.kl_list) ||
	    winreg_key_has_subkey(subkey)) {
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
			ndr_hdfree(mxa, &key->sk_handle);
			free(key);
			param->status = ERROR_SUCCESS;
			return (NDR_DRC_OK);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

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
 * winreg_subkey_get_relative_name
 *
 * Each key contains one or more child keys, each called a subkey.
 * For any specified key, its name MUST be unique for any other subkeys that
 * have the same parent key.
 *
 * To accurately identify a given subkey within the key namespace, its fully
 * qualified name (FQN) is used. The FQN MUST consist of the name of the subkey
 * and the name of all of its parent keys all the way to the root of the tree.
 *
 * The "\" character MUST be used as a hierarchy separator to identify each key
 * in the FQN and therefore MUST not be used in the name of a single key.
 * For example, the subkey "MountedDevices" belongs to the subtree
 * HKEY_LOCAL_MACHINE, as shown in the following example.
 *
 *	HKEY_LOCAL_MACHINE -> SYSTEM -> MountedDevices
 *
 * The FQN for MountedDevices is HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices.
 * The relative name of the subkey is "MountedDevices". The relative name
 * MUST be used only for operations that are performed on its immediate parent
 * key (SYSTEM in the previous example).
 */
static char *
winreg_subkey_get_relative_name(const char *subkey)
{
	winreg_subkey_t *key;
	char *value;

	if (subkey == NULL)
		return (NULL);

	if (list_is_empty(&winreg_keylist.kl_list))
		return (NULL);

	key = list_head(&winreg_keylist.kl_list);
	do {
		if (strcasecmp(subkey, key->sk_name) == 0) {
			value = strrchr(key->sk_name, '\\');
			if (value != NULL)
				return (++value);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

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
	winreg_string_t	*name, *class;
	char *value, *namep = NULL, *classp = NULL;
	int slen = 0;

	if (ndr_hdlookup(mxa, id) == NULL) {
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_NO_MORE_ITEMS;
		return (NDR_DRC_OK);
	}

	if (param->index > 0) {
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_NO_MORE_ITEMS;
		return (NDR_DRC_OK);
	}

	name = (winreg_string_t	*)&param->name_in;
	class = (winreg_string_t *)&param->class_in;
	if (name->length != 0)
		namep = (char *)name->str;

	if (class->length != 0)
		classp = (char *)class->str;

	value = winreg_lookup_eventlog_registry(namep, classp);
	if (value == NULL) {
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_CANTREAD;
		return (NDR_DRC_OK);
	}

	slen = mts_wcequiv_strlen(value) + sizeof (mts_wchar_t);
	param->name_out.length = slen;
	param->name_out.allosize = slen;
	if ((param->name_out.str = NDR_STRDUP(mxa, value)) == NULL) {
		bzero(param, sizeof (struct winreg_EnumKey));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

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
/*ARGSUSED*/
static int
winreg_s_GetKeySec(void *arg, ndr_xa_t *mxa)
{
	struct winreg_GetKeySec *param = arg;

	bzero(param, sizeof (struct winreg_GetKeySec));
	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
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
	char *subkey = (char *)param->name.str;
	ndr_hdid_t *id = NULL;
	winreg_subkey_t *key;

	if (list_is_empty(&winreg_keylist.kl_list)) {
		bzero(&param->result_handle, sizeof (winreg_handle_t));
		param->status = ERROR_FILE_NOT_FOUND;
		return (NDR_DRC_OK);
	}

	key = list_head(&winreg_keylist.kl_list);
	do {
		if (strcasecmp(subkey, key->sk_name) == 0) {
			if (key->sk_predefined == B_TRUE)
				id = ndr_hdalloc(mxa, &winreg_hkkey);
			else
				id = &key->sk_handle;

			if (id == NULL)
				break;

			bcopy(id, &param->result_handle,
			    sizeof (winreg_handle_t));
			param->status = ERROR_SUCCESS;
			return (NDR_DRC_OK);
		}
	} while ((key = list_next(&winreg_keylist.kl_list, key)) != NULL);

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

	if (strcasecmp(name, "PrimaryModule") == 0) {
		param->status = ERROR_FILE_NOT_FOUND;
		return (NDR_DRC_OK);
	}

	if ((value = winreg_lookup_value(name)) == NULL) {
		param->status = ERROR_CANTREAD;
		return (NDR_DRC_OK);
	}

	slen = mts_wcequiv_strlen(value) + sizeof (mts_wchar_t);
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
	(void) ndr_mbstowcs(NULL, (mts_wchar_t *)pv->value, value, slen);

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
		{ "ProductType", "ServerNT" },
		{ "Sources",	 NULL }	/* product name */
	};

	int i;

	for (i = 0; i < sizeof (registry)/sizeof (registry[0]); ++i) {
		if (strcasecmp(registry[i].name, name) == 0) {
			if (registry[i].value == NULL)
				return (winreg_sysname);
			else
				return (registry[i].value);
		}
	}

	return (NULL);
}

/*
 * winreg_lookup_eventlog_registry
 *
 * Return the subkey of the specified EventLog key. Decoding of
 * class paramater not yet supported.
 */
/*ARGSUSED*/
static char *
winreg_lookup_eventlog_registry(char *name, char *class)
{
	if (name == NULL)
		return (winreg_subkey_get_relative_name(WINREG_LOGR_SYSTEMKEY));

	return (winreg_subkey_get_relative_name(name));
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
