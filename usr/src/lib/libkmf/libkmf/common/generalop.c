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
 *
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread.h>

#include <ber_der.h>
#include <kmfapiP.h>

#include <pem_encode.h>
#include <rdn_parser.h>
#include <libxml2/libxml/uri.h>
#include <libgen.h>
#include <cryptoutil.h>

static uchar_t pkcs11_initialized = 0;
mutex_t init_lock = DEFAULTMUTEX;
extern int errno;

typedef struct {
	KMF_RETURN code;
	char	*message;
} kmf_error_map;

static kmf_error_map kmf_errcodes[] = {
	{KMF_OK,	"KMF_OK"},
	{KMF_ERR_BAD_PARAMETER,	"KMF_ERR_BAD_PARAMETER"},
	{KMF_ERR_BAD_KEY_FORMAT,	"KMF_ERR_BAD_KEY_FORMAT"},
	{KMF_ERR_BAD_ALGORITHM,	"KMF_ERR_BAD_ALGORITHM"},
	{KMF_ERR_MEMORY,	"KMF_ERR_MEMORY"},
	{KMF_ERR_ENCODING,	"KMF_ERR_ENCODING"},
	{KMF_ERR_PLUGIN_INIT,	"KMF_ERR_PLUGIN_INIT"},
	{KMF_ERR_PLUGIN_NOTFOUND,	"KMF_ERR_PLUGIN_NOTFOUND"},
	{KMF_ERR_INTERNAL,	"KMF_ERR_INTERNAL"},
	{KMF_ERR_BAD_CERT_FORMAT,	"KMF_ERR_BAD_CERT_FORMAT"},
	{KMF_ERR_KEYGEN_FAILED,	"KMF_ERR_KEYGEN_FAILED"},
	{KMF_ERR_UNINITIALIZED,	"KMF_ERR_UNINITIALIZED"},
	{KMF_ERR_ISSUER,	"KMF_ERR_ISSUER"},
	{KMF_ERR_NOT_REVOKED,	"KMF_ERR_NOT_REVOKED"},
	{KMF_ERR_CERT_NOT_FOUND,	"KMF_ERR_CERT_NOT_FOUND"},
	{KMF_ERR_CRL_NOT_FOUND,	"KMF_ERR_CRL_NOT_FOUND"},
	{KMF_ERR_RDN_PARSER,	"KMF_ERR_RDN_PARSER"},
	{KMF_ERR_RDN_ATTR,	"KMF_ERR_RDN_ATTR"},
	{KMF_ERR_SLOTNAME,	"KMF_ERR_SLOTNAME"},
	{KMF_ERR_EMPTY_CRL,	"KMF_ERR_EMPTY_CRL"},
	{KMF_ERR_BUFFER_SIZE,	"KMF_ERR_BUFFER_SIZE"},
	{KMF_ERR_AUTH_FAILED,	"KMF_ERR_AUTH_FAILED"},
	{KMF_ERR_TOKEN_SELECTED,	"KMF_ERR_TOKEN_SELECTED"},
	{KMF_ERR_NO_TOKEN_SELECTED,	"KMF_ERR_NO_TOKEN_SELECTED"},
	{KMF_ERR_TOKEN_NOT_PRESENT,	"KMF_ERR_TOKEN_NOT_PRESENT"},
	{KMF_ERR_EXTENSION_NOT_FOUND,	"KMF_ERR_EXTENSION_NOT_FOUND"},
	{KMF_ERR_POLICY_ENGINE,	"KMF_ERR_POLICY_ENGINE"},
	{KMF_ERR_POLICY_DB_FORMAT,	"KMF_ERR_POLICY_DB_FORMAT"},
	{KMF_ERR_POLICY_NOT_FOUND,	"KMF_ERR_POLICY_NOT_FOUND"},
	{KMF_ERR_POLICY_DB_FILE,	"KMF_ERR_POLICY_DB_FILE"},
	{KMF_ERR_POLICY_NAME,	"KMF_ERR_POLICY_NAME"},
	{KMF_ERR_OCSP_POLICY,	"KMF_ERR_OCSP_POLICY"},
	{KMF_ERR_TA_POLICY,	"KMF_ERR_TA_POLICY"},
	{KMF_ERR_KEY_NOT_FOUND,	"KMF_ERR_KEY_NOT_FOUND"},
	{KMF_ERR_OPEN_FILE,	"KMF_ERR_OPEN_FILE"},
	{KMF_ERR_OCSP_BAD_ISSUER,	"KMF_ERR_OCSP_BAD_ISSUER"},
	{KMF_ERR_OCSP_BAD_CERT,	"KMF_ERR_OCSP_BAD_CERT"},
	{KMF_ERR_OCSP_CREATE_REQUEST,	"KMF_ERR_OCSP_CREATE_REQUEST"},
	{KMF_ERR_CONNECT_SERVER,	"KMF_ERR_CONNECT_SERVER"},
	{KMF_ERR_SEND_REQUEST,	"KMF_ERR_SEND_REQUEST"},
	{KMF_ERR_OCSP_CERTID,	"KMF_ERR_OCSP_CERTID"},
	{KMF_ERR_OCSP_MALFORMED_RESPONSE, "KMF_ERR_OCSP_MALFORMED_RESPONSE"},
	{KMF_ERR_OCSP_RESPONSE_STATUS,	"KMF_ERR_OCSP_RESPONSE_STATUS"},
	{KMF_ERR_OCSP_NO_BASIC_RESPONSE, "KMF_ERR_OCSP_NO_BASIC_RESPONSE"},
	{KMF_ERR_OCSP_BAD_SIGNER,	"KMF_ERR_OCSP_BAD_SIGNER"},
	{KMF_ERR_OCSP_RESPONSE_SIGNATURE, "KMF_ERR_OCSP_RESPONSE_SIGNATURE"},
	{KMF_ERR_OCSP_UNKNOWN_CERT,	"KMF_ERR_OCSP_UNKNOWN_CERT"},
	{KMF_ERR_OCSP_STATUS_TIME_INVALID, "KMF_ERR_OCSP_STATUS_TIME_INVALID"},
	{KMF_ERR_BAD_HTTP_RESPONSE,	"KMF_ERR_BAD_HTTP_RESPONSE"},
	{KMF_ERR_RECV_RESPONSE,	"KMF_ERR_RECV_RESPONSE"},
	{KMF_ERR_RECV_TIMEOUT,	"KMF_ERR_RECV_TIMEOUT"},
	{KMF_ERR_DUPLICATE_KEYFILE,	"KMF_ERR_DUPLICATE_KEYFILE"},
	{KMF_ERR_AMBIGUOUS_PATHNAME,	"KMF_ERR_AMBIGUOUS_PATHNAME"},
	{KMF_ERR_FUNCTION_NOT_FOUND,	"KMF_ERR_FUNCTION_NOT_FOUND"},
	{KMF_ERR_PKCS12_FORMAT,	"KMF_ERR_PKCS12_FORMAT"},
	{KMF_ERR_BAD_KEY_TYPE,	"KMF_ERR_BAD_KEY_TYPE"},
	{KMF_ERR_BAD_KEY_CLASS,	"KMF_ERR_BAD_KEY_CLASS"},
	{KMF_ERR_BAD_KEY_SIZE,	"KMF_ERR_BAD_KEY_SIZE"},
	{KMF_ERR_BAD_HEX_STRING,	"KMF_ERR_BAD_HEX_STRING"},
	{KMF_ERR_KEYUSAGE,	"KMF_ERR_KEYUSAGE"},
	{KMF_ERR_VALIDITY_PERIOD,	"KMF_ERR_VALIDITY_PERIOD"},
	{KMF_ERR_OCSP_REVOKED,	"KMF_ERR_OCSP_REVOKED"},
	{KMF_ERR_CERT_MULTIPLE_FOUND,	"KMF_ERR_CERT_MULTIPLE_FOUND"},
	{KMF_ERR_WRITE_FILE,	"KMF_ERR_WRITE_FILE"},
	{KMF_ERR_BAD_URI,	"KMF_ERR_BAD_URI"},
	{KMF_ERR_BAD_CRLFILE,	"KMF_ERR_BAD_CRLFILE"},
	{KMF_ERR_BAD_CERTFILE,	"KMF_ERR_BAD_CERTFILE"},
	{KMF_ERR_GETKEYVALUE_FAILED,	"KMF_ERR_GETKEYVALUE_FAILED"},
	{KMF_ERR_BAD_KEYHANDLE,	"KMF_ERR_BAD_KEYHANDLE"},
	{KMF_ERR_BAD_OBJECT_TYPE,	"KMF_ERR_BAD_OBJECT_TYPE"},
	{KMF_ERR_OCSP_RESPONSE_LIFETIME, "KMF_ERR_OCSP_RESPONSE_LIFETIME"},
	{KMF_ERR_UNKNOWN_CSR_ATTRIBUTE,	"KMF_ERR_UNKNOWN_CSR_ATTRIBUTE"},
	{KMF_ERR_UNINITIALIZED_TOKEN,	"KMF_ERR_UNINITIALIZED_TOKEN"},
	{KMF_ERR_INCOMPLETE_TBS_CERT,	"KMF_ERR_INCOMPLETE_TBS_CERT"},
	{KMF_ERR_MISSING_ERRCODE,	"KMF_ERR_MISSING_ERRCODE"},
	{KMF_KEYSTORE_ALREADY_INITIALIZED, "KMF_KEYSTORE_ALREADY_INITIALIZED"},
	{KMF_ERR_SENSITIVE_KEY,		"KMF_ERR_SENSITIVE_KEY"},
	{KMF_ERR_UNEXTRACTABLE_KEY,	"KMF_ERR_UNEXTRACTABLE_KEY"},
	{KMF_ERR_KEY_MISMATCH,		"KMF_ERR_KEY_MISMATCH"},
	{KMF_ERR_ATTR_NOT_FOUND,	"KMF_ERR_ATTR_NOT_FOUND"},
	{KMF_ERR_KMF_CONF,		"KMF_ERR_KMF_CONF"},
	{KMF_ERR_NAME_NOT_MATCHED,	"KMF_ERR_NAME_NOT_MATCHED"},
	{KMF_ERR_MAPPER_OPEN,		"KMF_ERR_MAPPER_OPEN"},
	{KMF_ERR_MAPPER_NOT_FOUND,	"KMF_ERR_MAPPER_NOT_FOUND"},
	{KMF_ERR_MAPPING_FAILED,	"KMF_ERR_MAPPING_FAILED"},
	{KMF_ERR_CERT_VALIDATION,	"KMF_ERR_CERT_VALIDATION"}
};

typedef struct {
	KMF_KEYSTORE_TYPE	kstype;
	char			*path;
	boolean_t		critical;
} KMF_PLUGIN_ITEM;

KMF_PLUGIN_ITEM plugin_list[] = {
	{KMF_KEYSTORE_OPENSSL,	KMF_PLUGIN_PATH "kmf_openssl.so.1",  TRUE},
	{KMF_KEYSTORE_PK11TOKEN, KMF_PLUGIN_PATH "kmf_pkcs11.so.1",  TRUE},
	{KMF_KEYSTORE_NSS,	KMF_PLUGIN_PATH "kmf_nss.so.1",  FALSE}
};



static KMF_RETURN InitializePlugin(KMF_KEYSTORE_TYPE, char *, KMF_PLUGIN **);
static KMF_RETURN AddPlugin(KMF_HANDLE_T, KMF_PLUGIN *);
static void free_extensions(KMF_X509_EXTENSIONS *extns);
static void DestroyPlugin(KMF_PLUGIN *);

#if defined(__sparcv9)
#define	ISA_PATH	"/sparcv9"
#elif defined(__sparc)
#define	ISA_PATH	"/"
#elif defined(__i386)
#define	ISA_PATH	"/"
#elif defined(__amd64)
#define	ISA_PATH	"/amd64"
#endif

#define	DEFAULT_KEYSTORE_NUM	3
static int kstore_num = DEFAULT_KEYSTORE_NUM;
conf_entrylist_t *extra_plugin_list = NULL;
static boolean_t check_extra_plugin = B_FALSE;
mutex_t extra_plugin_lock = DEFAULTMUTEX;

KMF_RETURN
init_pk11()
{
	(void) mutex_lock(&init_lock);
	if (!pkcs11_initialized) {
		CK_RV rv = C_Initialize(NULL);
		if ((rv != CKR_OK) &&
		    (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			(void) mutex_unlock(&init_lock);
			return (KMF_ERR_UNINITIALIZED);
		} else {
			pkcs11_initialized = 1;
		}
	}
	(void) mutex_unlock(&init_lock);
	return (KMF_OK);
}

/*
 * Private method for searching the plugin list for the correct
 * Plugin to use.
 */
KMF_PLUGIN *
FindPlugin(KMF_HANDLE_T handle, KMF_KEYSTORE_TYPE kstype)
{
	KMF_PLUGIN_LIST *node;
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *pluginrec = NULL;

	if (handle == NULL)
		return (NULL);

	node = handle->plugins;

	/* See if the desired plugin was already initialized. */
	while (node != NULL && node->plugin->type != kstype)
		node = node->next;

	if (node != NULL)
		return (node->plugin);

	/* The plugin was not found, try to initialize it here. */
	if (VALID_DEFAULT_KEYSTORE_TYPE(kstype)) {
		int i;
		int numitems = sizeof (plugin_list)/sizeof (KMF_PLUGIN_ITEM);
		for (i = 0; i < numitems; i++) {
			if (plugin_list[i].kstype == kstype) {
				ret = InitializePlugin(plugin_list[i].kstype,
				    plugin_list[i].path, &pluginrec);
				break;
			}
		}

		goto out;

	} else {
		/*
		 * Not a built-in plugin. Check if it is in the
		 * extra_plugin_list.  If it is, try to initialize it here.
		 */
		conf_entrylist_t *phead = extra_plugin_list;
		char realpath[MAXPATHLEN];

		while (phead != NULL) {
			if (phead->entry->kstype == kstype)
				break;
			else
				phead = phead->next;
		}

		if (phead == NULL)
			return (NULL);

		/*
		 * Get the absolute path of the module.
		 * - If modulepath is not a full path, then prepend it
		 *   with KMF_PLUGIN_PATH.
		 * - If modulepath is a full path and contain $ISA, then
		 *   subsitute the architecture dependent path.
		 */
		(void) memset(realpath, 0, sizeof (realpath));
		if (strncmp(phead->entry->modulepath, "/", 1) != 0) {
			(void) snprintf(realpath, MAXPATHLEN, "%s%s",
			    KMF_PLUGIN_PATH, phead->entry->modulepath);
		} else {
			char *buf = phead->entry->modulepath;
			char *isa;

			if ((isa = strstr(buf, PKCS11_ISA)) != NULL) {
				char *isa_str;

				(void) strncpy(realpath, buf, isa - buf);
				isa_str = strdup(ISA_PATH);
				if (isa_str == NULL) /* not enough memory */
					return (NULL);

				(void) strncat(realpath, isa_str,
				    strlen(isa_str));
				free(isa_str);

				isa += strlen(PKCS11_ISA);
				(void) strlcat(realpath, isa, MAXPATHLEN);
			} else {
				(void) snprintf(realpath, MAXPATHLEN, "%s",
				    phead->entry->modulepath);
			}
		}

		ret = InitializePlugin(phead->entry->kstype, realpath,
		    &pluginrec);
		goto out;
	}

out:
	if (ret != KMF_OK || pluginrec == NULL)
		/* No matching plugins found in the built-in list */
		return (NULL);

	ret = AddPlugin(handle, pluginrec);
	if (ret != KMF_OK) {
		DestroyPlugin(pluginrec);
		pluginrec = NULL;
	}
	return (pluginrec);
}


static KMF_RETURN
InitializePlugin(KMF_KEYSTORE_TYPE kstype, char *path, KMF_PLUGIN **plugin)
{
	KMF_PLUGIN *p = NULL;
	KMF_PLUGIN_FUNCLIST *(*sym)();

	if (path == NULL || plugin == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*plugin = NULL;

	p = (KMF_PLUGIN *)malloc(sizeof (KMF_PLUGIN));
	if (p == NULL)
		return (KMF_ERR_MEMORY);

	p->type = kstype;
	p->path = strdup(path);
	if (p->path == NULL) {
		free(p);
		return (KMF_ERR_MEMORY);
	}
	/*
	 * Do not use RTLD_GROUP here, or this will cause a circular
	 * dependency when kmf_pkcs11.so.1 gets its PKCS#11 functions
	 * from libpkcs11.so.1 when kmf is used via libelfsign.so.1
	 * called from kcfd.
	 */
	p->dldesc = dlopen(path, RTLD_LAZY | RTLD_PARENT);
	if (p->dldesc == NULL) {
		free(p->path);
		free(p);
		return (KMF_ERR_PLUGIN_INIT);
	}

	sym = (KMF_PLUGIN_FUNCLIST *(*)())dlsym(p->dldesc,
	    KMF_PLUGIN_INIT_SYMBOL);
	if (sym == NULL) {
		(void) dlclose(p->dldesc);
		free(p->path);
		free(p);
		return (KMF_ERR_PLUGIN_INIT);
	}

	/* Get the function list */
	if ((p->funclist = (*sym)()) == NULL) {
		(void) dlclose(p->dldesc);
		free(p->path);
		free(p);
		return (KMF_ERR_PLUGIN_INIT);
	}

	*plugin = p;

	return (KMF_OK);
}

static KMF_RETURN
AddPlugin(KMF_HANDLE_T handle, KMF_PLUGIN *plugin)
{
	KMF_PLUGIN_LIST *n;

	if (handle == NULL || plugin == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the head is NULL, create it */
	if (handle->plugins == NULL) {
		handle->plugins = (KMF_PLUGIN_LIST *)malloc(
		    sizeof (KMF_PLUGIN_LIST));
		if (handle->plugins == NULL)
			return (KMF_ERR_MEMORY);
		handle->plugins->plugin = plugin;
		handle->plugins->next = NULL;
	} else {
		/* walk the list to find the tail */
		n = handle->plugins;
		while (n->next != NULL)
			n = n->next;
		n->next = (KMF_PLUGIN_LIST *)malloc(sizeof (KMF_PLUGIN_LIST));
		if (n->next == NULL)
			return (KMF_ERR_MEMORY);

		n->next->plugin = plugin;
		n->next->next = NULL;
	}
	return (0);
}

static void
DestroyPlugin(KMF_PLUGIN *plugin)
{
	if (plugin) {
		if (plugin->path)
			free(plugin->path);
		free(plugin);
	}
}

static void
Cleanup_KMF_Handle(KMF_HANDLE_T handle)
{
	if (handle != NULL) {
		while (handle->plugins != NULL) {
			KMF_PLUGIN_LIST *next = handle->plugins->next;

			DestroyPlugin(handle->plugins->plugin);
			free(handle->plugins);
			handle->plugins = next;
		}
		kmf_free_policy_record(handle->policy);
		free(handle->policy);
	}
	free(handle);
}

void
Cleanup_PK11_Session(KMF_HANDLE_T handle)
{
	if (handle != NULL) {
		/* Close active session on a pkcs11 token */
		if (handle->pk11handle != NULL) {
			(void) C_CloseSession(handle->pk11handle);
			handle->pk11handle = NULL;
		}
	}
}

KMF_RETURN
kmf_initialize(KMF_HANDLE_T *outhandle, char *policyfile, char *policyname)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *handle = NULL;

	if (outhandle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*outhandle = NULL;
	handle = (KMF_HANDLE *)malloc(sizeof (KMF_HANDLE));
	if (handle == NULL)
		return (KMF_ERR_MEMORY);

	(void) memset(handle, 0, sizeof (KMF_HANDLE));
	handle->plugins = NULL;

	/*
	 * When this function is called the first time, get the additional
	 * plugins from the config file.
	 */
	(void) mutex_lock(&extra_plugin_lock);
	if (!check_extra_plugin) {

		ret = get_entrylist(&extra_plugin_list);
		check_extra_plugin = B_TRUE;

		/*
		 * Assign the kstype number to the additional plugins here.
		 * The global kstore_num will be protected by the mutex lock.
		 */
		if (ret == KMF_OK) {
			conf_entrylist_t *phead = extra_plugin_list;
			while (phead != NULL) {
				phead->entry->kstype = ++kstore_num;
				phead = phead->next;
			}
		}

		/*
		 * If the KMF configuration file does not exist or cannot be
		 * parsed correctly, we will give a warning in syslog and
		 * continue on as there is no extra plugins in the system.
		 */
		if (ret == KMF_ERR_KMF_CONF) {
			cryptoerror(LOG_WARNING, "KMF was unable to parse "
			    "the private KMF config file.\n");
			ret = KMF_OK;
		}

		if (ret != KMF_OK) {
			(void) mutex_unlock(&extra_plugin_lock);
			goto errout;
		}
	}
	(void) mutex_unlock(&extra_plugin_lock);

	/* Initialize the handle with the policy */
	ret = kmf_set_policy((void *)handle,
	    policyfile == NULL ? KMF_DEFAULT_POLICY_FILE : policyfile,
	    policyname == NULL ? KMF_DEFAULT_POLICY_NAME : policyname);
	if (ret != KMF_OK)
		goto errout;

	/*
	 * Let's have the mapper status structure even if no cert-to-name
	 * mapping is initialized. It's better not to coredump in the
	 * kmf_get_mapper_lasterror function, for example, when there is no
	 * mapping initialized.
	 */
	handle->mapstate = malloc(sizeof (KMF_MAPPER_STATE));
	if (handle->mapstate == NULL) {
		ret = KMF_ERR_MEMORY;
		goto errout;
	}
	handle->mapstate->lastmappererr = KMF_OK;
	handle->mapstate->options = NULL;

	/*
	 * Initialize the mapping scheme according to the policy. If no mapping
	 * is set in the policy database we silently ignore the error.
	 */
	(void) kmf_cert_to_name_mapping_initialize(handle, 0, NULL);

	CLEAR_ERROR(handle, ret);
errout:
	if (ret != KMF_OK) {
		Cleanup_KMF_Handle(handle);
		handle = NULL;
	}

	*outhandle = (KMF_HANDLE_T)handle;
	return (ret);
}

KMF_RETURN
kmf_configure_keystore(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, num_args, attrlist);

	if (ret != KMF_OK)
		return (ret);

	len = sizeof (kstype);
	ret = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, num_args,
	    &kstype, &len);
	if (ret != KMF_OK)
		return (ret);

	plugin = FindPlugin(handle, kstype);
	if (plugin != NULL && plugin->funclist->ConfigureKeystore != NULL) {
		return (plugin->funclist->ConfigureKeystore(handle, num_args,
		    attrlist));
	} else {
		/* return KMF_OK, if the plugin does not have an entry */
		return (KMF_OK);
	}
}

KMF_RETURN
kmf_finalize(KMF_HANDLE_T handle)
{
	KMF_RETURN ret = KMF_OK;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (pkcs11_initialized) {
		Cleanup_PK11_Session(handle);
	}
	Cleanup_KMF_Handle(handle);

	return (ret);
}

KMF_RETURN
kmf_get_kmf_error_str(KMF_RETURN errcode, char **errmsg)
{
	KMF_RETURN ret = KMF_OK;
	int i, maxerr;

	if (errmsg == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*errmsg = NULL;
	maxerr = sizeof (kmf_errcodes) / sizeof (kmf_error_map);

	for (i = 0; i < maxerr && errcode != kmf_errcodes[i].code; i++)
		/* empty body */
		;

	if (i == maxerr)
		return (KMF_ERR_MISSING_ERRCODE);
	else {
		*errmsg = strdup(kmf_errcodes[i].message);
		if ((*errmsg) == NULL)
			return (KMF_ERR_MEMORY);
	}
	return (ret);
}

KMF_RETURN
kmf_get_plugin_error_str(KMF_HANDLE_T handle, char **msgstr)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;

	if (handle == NULL || msgstr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*msgstr = NULL;

	if (handle->lasterr.errcode == 0) {
		return (KMF_ERR_MISSING_ERRCODE);
	}

	if (handle->lasterr.kstype == -1) { /* System error */
		char *str = strerror(handle->lasterr.errcode);
		if (str != NULL) {
			*msgstr = strdup(str);
			if ((*msgstr) == NULL)
				return (KMF_ERR_MEMORY);
		}
		return (KMF_OK);
	}

	plugin = FindPlugin(handle, handle->lasterr.kstype);
	if (plugin == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	if (plugin->funclist->GetErrorString != NULL) {
		ret = plugin->funclist->GetErrorString(handle, msgstr);
	} else {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	return (ret);
}


#define	SET_SYS_ERROR(h, c) if (h) {\
	h->lasterr.kstype = -1;\
	h->lasterr.errcode = c;\
}

KMF_RETURN
kmf_read_input_file(KMF_HANDLE_T handle, char *filename,  KMF_DATA *pdata)
{
	struct stat s;
	long nread, total = 0;
	int fd;
	unsigned char *buf = NULL;
	KMF_RETURN ret;

	if (handle) {
		CLEAR_ERROR(handle, ret);
		if (ret != KMF_OK)
			return (ret);
	}

	if (filename == NULL || pdata == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if ((fd = open(filename, O_RDONLY)) < 0) {
		SET_SYS_ERROR(handle, errno);
		return (KMF_ERR_OPEN_FILE);
	}

	if (fstat(fd, &s) < 0) {
		SET_SYS_ERROR(handle, errno);
		(void) close(fd);
		return (KMF_ERR_OPEN_FILE);
	}

	if ((buf = (unsigned char *) malloc(s.st_size)) == NULL) {
		(void) close(fd);
		return (KMF_ERR_MEMORY);
	}

	do {
		nread = read(fd, buf+total, s.st_size-total);
		if (nread < 0) {
			SET_SYS_ERROR(handle, errno);
			(void) close(fd);
			free(buf);
			return (KMF_ERR_INTERNAL);
		}
		total += nread;
	} while (total < s.st_size);

	pdata->Data = buf;
	pdata->Length = s.st_size;
	(void) close(fd);
	return (KMF_OK);
}

/*
 *
 * Name: kmf_der_to_pem
 *
 * Description:
 *   Function for converting DER encoded format to PEM encoded format
 *
 * Parameters:
 *   type(input) - CERTIFICATE or CSR
 *   data(input) - pointer to the DER encoded data
 *   len(input)  - length of input data
 *   out(output) - contains the output buffer address to be returned
 *   outlen(output) - pointer to the returned output length
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
kmf_der_to_pem(KMF_OBJECT_TYPE type, unsigned char *data,
	int len, unsigned char **out, int *outlen)
{

	KMF_RETURN err;
	if (data == NULL || out == NULL || outlen == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	err = Der2Pem(type, data, len, out, outlen);
	return (err);

}

/*
 *
 * Name: kmf_pem_to_der
 *
 * Description:
 *   Function for converting PEM encoded format to DER encoded format
 *
 * Parameters:
 *   in(input) - pointer to the PEM encoded data
 *   inlen(input)  - length of input data
 *   out(output) - contains the output buffer address to be returned
 *   outlen(output) - pointer to the returned output length
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 *   error condition.
 *   The value KMF_OK indicates success. All other values represent
 *   an error condition.
 *
 */
KMF_RETURN
kmf_pem_to_der(unsigned char *in, int inlen,
	unsigned char **out, int *outlen)
{
	KMF_RETURN err;
	if (in == NULL || out == NULL || outlen == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	err = Pem2Der(in, inlen, out, outlen);
	return (err);
}

char *
kmf_oid_to_string(KMF_OID *oid)
{
	char numstr[128];
	uint32_t number;
	int numshift;
	uint32_t i, string_length;
	uchar_t *cp;
	char *bp;

	/* First determine the size of the string */
	string_length = 0;
	number = 0;
	numshift = 0;
	cp = (unsigned char *)oid->Data;

	number = (uint32_t)cp[0];
	(void) sprintf(numstr, "%d ", number/40);

	string_length += strlen(numstr);
	(void) sprintf(numstr, "%d ", number%40);

	string_length += strlen(numstr);

	for (i = 1; i < oid->Length; i++) {
		if ((uint32_t)(numshift+7) < (sizeof (uint32_t)*8)) {
			number = (number << 7) | (cp[i] & 0x7f);
			numshift += 7;
		} else {
			return (NULL);
		}

		if ((cp[i] & 0x80) == 0) {
			(void) sprintf(numstr, "%d ", number);
			string_length += strlen(numstr);
			number = 0;
			numshift = 0;
		}
	}
	/*
	 * If we get here, we've calculated the length of "n n n ... n ".  Add 4
	 * here for "{ " and "}\0".
	 */
	string_length += 4;
	if ((bp = (char *)malloc(string_length))) {
		number = (uint32_t)cp[0];

		(void) sprintf(numstr, "%d.", number/40);
		(void) strcpy(bp, numstr);

		(void) sprintf(numstr, "%d.", number%40);
		(void) strcat(bp, numstr);

		number = 0;
		cp = (unsigned char *) oid->Data;
		for (i = 1; i < oid->Length; i++) {
			number = (number << 7) | (cp[i] & 0x7f);
			if ((cp[i] & 0x80) == 0) {
				(void) sprintf(numstr, "%d", number);
				(void) strcat(bp, numstr);
				number = 0;
				if (i+1 < oid->Length)
					(void) strcat(bp, ".");
			}
		}
	}
	return (bp);
}

static boolean_t
check_for_pem(uchar_t *buf, KMF_ENCODE_FORMAT *fmt)
{
	char *p;
	int i;

	if (buf == NULL)
		return (FALSE);

	for (i = 0; i < 8 && isascii(buf[i]); i++)
		/* loop to make sure this is ascii */;
	if (i != 8)
		return (FALSE);

	if (memcmp(buf, "Bag Attr", 8) == 0) {
		*fmt = KMF_FORMAT_PEM_KEYPAIR;
		return (TRUE);
	}

	/* Look for "-----BEGIN" right after a newline */
	p = strtok((char *)buf, "\n");
	while (p != NULL) {
		if (strstr(p, "-----BEGIN") != NULL) {
			*fmt = KMF_FORMAT_PEM;
			/* Restore the buffer */
			buf[strlen(p)] = '\n';
			return (TRUE);
		}
		buf[strlen(p)] = '\n';
		p = strtok(NULL, "\n");
	}
	return (FALSE);
}


static unsigned char pkcs12_version[3] = {0x02, 0x01, 0x03};
static unsigned char pkcs12_oid[11] =
{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01};

/*
 * This function takes a BER encoded string as input and checks the version
 * and the oid in the the top-level ASN.1 structure to see if it complies to
 * the PKCS#12 Syntax.
 */
static boolean_t
check_for_pkcs12(uchar_t *buf, int buf_len)
{
	int index = 0;
	int length_octets;

	if (buf == NULL || buf_len <= 0)
		return (FALSE);

	/*
	 * The top level structure for a PKCS12 string:
	 *
	 * PFX ::= SEQUENCE {
	 *	version		INTEGER {v3(3)}(v3,...)
	 *	authSafe	ContentInfo
	 *	macData		MacData OPTIONAL
	 * }
	 *
	 * ContentInfo
	 *	FROM PKCS-7 {iso(1) member-body(2) us(840) rsadsi(113549)
	 *		pkcs(1) pkcs-7(7) modules(0) pkcs-7(1)}
	 *
	 * Therefore, the BER/DER dump of a PKCS#12 file for the first 2
	 * sequences up to the oid part is as following:
	 *
	 *	SEQUENCE {
	 *	    INTEGER 3
	 *	    SEQUENCE {
	 *		OBJECT IDENTIFIER data (1 2 840 113549 1 7 1)
	 */

	/*
	 * Check the first sequence and calculate the number of bytes used
	 * to store the length.
	 */
	if (buf[index++] != 0x30)
		return (FALSE);

	if (buf[index] & 0x80) {
		length_octets = buf[index++] & 0x0F;  /* long form */
	} else {
		length_octets = 1; /* short form */
	}

	index += length_octets;
	if (index  >= buf_len)
		return (FALSE);

	/* Skip the length octets and check the pkcs12 version */
	if (memcmp(buf + index, pkcs12_version, sizeof (pkcs12_version)) != 0)
		return (FALSE);

	index += sizeof (pkcs12_version);
	if (index  >= buf_len)
		return (FALSE);

	/*
	 * Check the 2nd sequence and calculate the number of bytes used
	 * to store the length.
	 */
	if ((buf[index++] & 0xFF) != 0x30)
		return (FALSE);

	if (buf[index] & 0x80) {
		length_octets = buf[index++] & 0x0F;
	} else {
		length_octets = 1;
	}

	index += length_octets;
	if (index + sizeof (pkcs12_oid) >= buf_len)
		return (FALSE);

	/* Skip the length octets and check the oid */
	if (memcmp(buf + index, pkcs12_oid, sizeof (pkcs12_oid)) != 0)
		return (FALSE);
	else
		return (TRUE);
}

KMF_RETURN
kmf_get_data_format(KMF_DATA *data, KMF_ENCODE_FORMAT *fmt)
{
	uchar_t *buf = data->Data;

	if (check_for_pkcs12(buf, data->Length) == TRUE) {
		*fmt = KMF_FORMAT_PKCS12;
	} else if (buf[0] == 0x30 && (buf[1] & 0x80)) {
		/* It is most likely a generic ASN.1 encoded file */
		*fmt = KMF_FORMAT_ASN1;
	} else if (check_for_pem(buf, fmt) != TRUE) {
		/* Cannot determine this file format */
		*fmt = KMF_FORMAT_UNDEF;
		return (KMF_ERR_ENCODING);
	}
	return (KMF_OK);
}

KMF_RETURN
kmf_get_file_format(char *filename, KMF_ENCODE_FORMAT *fmt)
{
	KMF_RETURN ret = KMF_OK;
	KMF_DATA filebuf = { 0, NULL };

	if (filename == NULL || !strlen(filename) || fmt == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*fmt = 0;
	ret = kmf_read_input_file(NULL, filename, &filebuf);
	if (ret != KMF_OK)
		return (ret);

	if (filebuf.Length < 8) {
		ret = KMF_ERR_ENCODING; /* too small */
		goto end;
	}

	ret = kmf_get_data_format(&filebuf, fmt);
end:
	kmf_free_data(&filebuf);
	return (ret);
}

KMF_RETURN
kmf_hexstr_to_bytes(unsigned char *hexstr, unsigned char **bytes,
	size_t *outlen)
{
	KMF_RETURN ret = KMF_OK;
	unsigned char *buf = NULL;
	int len, stringlen;
	int i;
	unsigned char ch;

	if (hexstr == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (hexstr[0] == '0' && ((hexstr[1] == 'x') || (hexstr[1] == 'X')))
		hexstr += 2;

	for (i = 0; i < strlen((char *)hexstr) && isxdigit(hexstr[i]); i++)
		/* empty body */
		;
	/*
	 * If all the characters are not legitimate hex chars,
	 * return an error.
	 */
	if (i != strlen((char *)hexstr))
		return (KMF_ERR_BAD_HEX_STRING);
	stringlen = i;
	len = (i / 2) + (i % 2);

	buf = malloc(len);
	if (buf == NULL) {
		return (KMF_ERR_MEMORY);
	}
	(void) memset(buf, 0, len);

	for (i = 0; i < stringlen; i++) {
		ch = (unsigned char) *hexstr;
		hexstr++;
		if ((ch >= '0') && (ch <= '9'))
			ch -= '0';
		else if ((ch >= 'A') && (ch <= 'F'))
			ch = ch - 'A' + 10;
		else if ((ch >= 'a') && (ch <= 'f'))
			ch = ch - 'a' + 10;
		else {
			ret = KMF_ERR_BAD_HEX_STRING;
			goto out;
		}

		if (i & 1) {
			buf[i/2] |= ch;
		} else {
			buf[i/2] = (ch << 4);
		}
	}

	*bytes = buf;
	*outlen = len;
out:
	if (buf != NULL && ret != KMF_OK) {
		free(buf);
	}
	return (ret);
}

void
kmf_free_dn(KMF_X509_NAME *name)
{
	KMF_X509_RDN 		*newrdn = NULL;
	KMF_X509_TYPE_VALUE_PAIR *av = NULL;
	int i, j;

	if (name && name->numberOfRDNs) {
		for (i = 0; i < name->numberOfRDNs; i++) {
			newrdn = &name->RelativeDistinguishedName[i];
			for (j = 0; j < newrdn->numberOfPairs; j++) {
				av = &newrdn->AttributeTypeAndValue[j];
				kmf_free_data(&av->type);
				kmf_free_data(&av->value);
			}
			free(newrdn->AttributeTypeAndValue);
			newrdn->numberOfPairs = 0;
			newrdn->AttributeTypeAndValue = NULL;
		}
		free(name->RelativeDistinguishedName);
		name->numberOfRDNs = 0;
		name->RelativeDistinguishedName = NULL;
	}
}

void
kmf_free_kmf_cert(KMF_HANDLE_T handle, KMF_X509_DER_CERT *kmf_cert)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return;

	if (kmf_cert == NULL)
		return;

	plugin = FindPlugin(handle, kmf_cert->kmf_private.keystore_type);

	if (plugin != NULL && plugin->funclist->FreeKMFCert != NULL) {
		plugin->funclist->FreeKMFCert(handle, kmf_cert);
	}
}

void
kmf_free_data(KMF_DATA *datablock)
{
	if (datablock != NULL && datablock->Data != NULL) {
		free(datablock->Data);
		datablock->Data = NULL;
		datablock->Length = 0;
	}
}

void
kmf_free_algoid(KMF_X509_ALGORITHM_IDENTIFIER *algoid)
{
	if (algoid == NULL)
		return;
	kmf_free_data(&algoid->algorithm);
	kmf_free_data(&algoid->parameters);
}

void
kmf_free_extn(KMF_X509_EXTENSION *exptr)
{
	if (exptr == NULL)
		return;

	kmf_free_data((KMF_DATA *)&exptr->extnId);
	kmf_free_data(&exptr->BERvalue);

	if (exptr->value.tagAndValue) {
		kmf_free_data(&exptr->value.tagAndValue->value);
		free(exptr->value.tagAndValue);
	}
}

void
kmf_free_tbs_csr(KMF_TBS_CSR *tbscsr)
{
	if (tbscsr) {
		kmf_free_data(&tbscsr->version);

		kmf_free_dn(&tbscsr->subject);

		kmf_free_algoid(&tbscsr->subjectPublicKeyInfo.algorithm);
		kmf_free_data(&tbscsr->subjectPublicKeyInfo.subjectPublicKey);

		free_extensions(&tbscsr->extensions);
	}
}

void
kmf_free_signed_csr(KMF_CSR_DATA *csr)
{
	if (csr) {
		kmf_free_tbs_csr(&csr->csr);

		kmf_free_algoid(&csr->signature.algorithmIdentifier);
		kmf_free_data(&csr->signature.encrypted);
	}
}

static void
free_validity(KMF_X509_VALIDITY *validity)
{
	if (validity == NULL)
		return;
	kmf_free_data(&validity->notBefore.time);
	kmf_free_data(&validity->notAfter.time);
}

static void
free_extensions(KMF_X509_EXTENSIONS *extns)
{
	int i;
	KMF_X509_EXTENSION *exptr;

	if (extns && extns->numberOfExtensions > 0) {
		for (i = 0; i < extns->numberOfExtensions; i++) {
			exptr = &extns->extensions[i];
			kmf_free_extn(exptr);
		}
		free(extns->extensions);
		extns->numberOfExtensions = 0;
		extns->extensions = NULL;
	}
}

void
kmf_free_tbs_cert(KMF_X509_TBS_CERT *tbscert)
{
	if (tbscert) {
		kmf_free_data(&tbscert->version);
		kmf_free_bigint(&tbscert->serialNumber);
		kmf_free_algoid(&tbscert->signature);

		kmf_free_dn(&tbscert->issuer);
		kmf_free_dn(&tbscert->subject);

		free_validity(&tbscert->validity);

		kmf_free_data(&tbscert->issuerUniqueIdentifier);
		kmf_free_data(&tbscert->subjectUniqueIdentifier);

		kmf_free_algoid(&tbscert->subjectPublicKeyInfo.algorithm);
		kmf_free_data(&tbscert->subjectPublicKeyInfo.subjectPublicKey);

		free_extensions(&tbscert->extensions);

		kmf_free_data(&tbscert->issuerUniqueIdentifier);
		kmf_free_data(&tbscert->subjectUniqueIdentifier);
	}
}

void
kmf_free_signed_cert(KMF_X509_CERTIFICATE *certptr)
{
	if (!certptr)
		return;

	kmf_free_tbs_cert(&certptr->certificate);

	kmf_free_algoid(&certptr->signature.algorithmIdentifier);
	kmf_free_data(&certptr->signature.encrypted);
}

void
kmf_free_str(char *pstr)
{
	if (pstr != NULL)
		free(pstr);
}

void
free_keyidlist(KMF_OID *oidlist, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		kmf_free_data((KMF_DATA *)&oidlist[i]);
	}
	free(oidlist);
}

void
kmf_free_eku(KMF_X509EXT_EKU *eptr)
{
	if (eptr && eptr->nEKUs > 0 && eptr->keyPurposeIdList != NULL)
		free_keyidlist(eptr->keyPurposeIdList, eptr->nEKUs);
}

void
kmf_free_spki(KMF_X509_SPKI *spki)
{
	if (spki != NULL) {
		kmf_free_algoid(&spki->algorithm);
		kmf_free_data(&spki->subjectPublicKey);
	}
}

void
kmf_free_kmf_key(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;
	KMF_ATTRIBUTE attlist[2]; /* only 2 attributes for DeleteKey op */
	int i = 0;
	boolean_t token_destroy = B_FALSE;

	if (key == NULL)
		return;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEY_HANDLE_ATTR, key, sizeof (KMF_KEY_HANDLE));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_DESTROY_BOOL_ATTR, &token_destroy, sizeof (boolean_t));
	i++;

	plugin = FindPlugin(handle, key->kstype);
	if (plugin != NULL && plugin->funclist->DeleteKey != NULL) {
		(void) plugin->funclist->DeleteKey(handle, i, attlist);
	}

	if (key->keylabel)
		free(key->keylabel);

	if (key->israw) {
		kmf_free_raw_key(key->keyp);
		free(key->keyp);
	}

	(void) memset(key, 0, sizeof (KMF_KEY_HANDLE));
}

void
kmf_free_bigint(KMF_BIGINT *big)
{
	if (big != NULL && big->val != NULL) {
		/* Clear it out before returning it to the pool */
		(void) memset(big->val, 0x00, big->len);
		free(big->val);
		big->val = NULL;
		big->len = 0;
	}
}

static void
free_raw_rsa(KMF_RAW_RSA_KEY *key)
{
	if (key == NULL)
		return;
	kmf_free_bigint(&key->mod);
	kmf_free_bigint(&key->pubexp);
	kmf_free_bigint(&key->priexp);
	kmf_free_bigint(&key->prime1);
	kmf_free_bigint(&key->prime2);
	kmf_free_bigint(&key->exp1);
	kmf_free_bigint(&key->exp2);
	kmf_free_bigint(&key->coef);
}

static void
free_raw_dsa(KMF_RAW_DSA_KEY *key)
{
	if (key == NULL)
		return;
	kmf_free_bigint(&key->prime);
	kmf_free_bigint(&key->subprime);
	kmf_free_bigint(&key->base);
	kmf_free_bigint(&key->value);
}

static void
free_raw_sym(KMF_RAW_SYM_KEY *key)
{
	if (key == NULL)
		return;
	kmf_free_bigint(&key->keydata);
}

void
kmf_free_raw_key(KMF_RAW_KEY_DATA *key)
{
	if (key == NULL)
		return;

	switch (key->keytype) {
	case KMF_RSA:
		free_raw_rsa(&key->rawdata.rsa);
		break;
	case KMF_DSA:
		free_raw_dsa(&key->rawdata.dsa);
		break;
	case KMF_AES:
	case KMF_RC4:
	case KMF_DES:
	case KMF_DES3:
		free_raw_sym(&key->rawdata.sym);
		break;
	}
	if (key->label) {
		free(key->label);
		key->label = NULL;
	}
	kmf_free_data(&key->id);
}

void
kmf_free_raw_sym_key(KMF_RAW_SYM_KEY *key)
{
	if (key == NULL)
		return;
	kmf_free_bigint(&key->keydata);
	free(key);
}

/*
 * This function frees the space allocated for the name portion of a
 * KMF_CRL_DIST_POINT.
 */
void
free_dp_name(KMF_CRL_DIST_POINT *dp)
{
	KMF_GENERALNAMES *fullname;
	KMF_DATA *urldata;
	int i;

	if (dp == NULL)
		return;

	/* For phase 1, we only need to free the fullname space. */
	fullname = &(dp->name.full_name);
	if (fullname->number == 0)
		return;

	for (i = 0; i < fullname->number; i++) {
		urldata = &(fullname->namelist[fullname->number - 1].name);
		kmf_free_data(urldata);
	}

	free(fullname->namelist);
}

/*
 * This function frees the space allocated for a KMF_CRL_DIST_POINT.
 */
void
free_dp(KMF_CRL_DIST_POINT *dp)
{
	if (dp == NULL)
		return;

	free_dp_name(dp);
	kmf_free_data(&(dp->reasons));
	/* Need not to free crl_issuer space at phase 1 */
}

/*
 * This function frees space for a KMF_X509EXT_CRLDISTPOINTS internally.
 */
void
kmf_free_crl_dist_pts(KMF_X509EXT_CRLDISTPOINTS *crl_dps)
{
	int i;

	if (crl_dps == NULL)
		return;

	for (i = 0; i < crl_dps->number; i++)
		free_dp(&(crl_dps->dplist[i]));

	free(crl_dps->dplist);
}

KMF_RETURN
kmf_create_ocsp_request(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_RETURN (*createReqFn)(void *, int num_args,
	    KMF_ATTRIBUTE *attrlist);

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_OCSP_REQUEST_FILENAME_ATTR, FALSE, 1, 0},
		{KMF_USER_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)},
		{KMF_ISSUER_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, num_args, attrlist);

	if (ret != KMF_OK)
		return (ret);

	/*
	 * This framework function is actually implemented in the openssl
	 * plugin library, so we find the function address and call it.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	createReqFn = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "OpenSSL_CreateOCSPRequest");
	if (createReqFn == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	return (createReqFn(handle, num_args, attrlist));

}

KMF_RETURN
kmf_get_ocsp_status_for_cert(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_RETURN (*getCertStatusFn)(void *, int num_args,
	    KMF_ATTRIBUTE *attrlist);

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_USER_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)},
		{KMF_ISSUER_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)},
		{KMF_OCSP_RESPONSE_DATA_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)},
		{KMF_OCSP_RESPONSE_STATUS_ATTR, FALSE, sizeof (int),
			sizeof (uint32_t)},
		{KMF_OCSP_RESPONSE_REASON_ATTR, FALSE, sizeof (int),
			sizeof (uint32_t)},
		{KMF_OCSP_RESPONSE_CERT_STATUS_ATTR, FALSE, sizeof (int),
			sizeof (uint32_t)},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, num_args, attrlist);

	if (ret != KMF_OK)
		return (ret);

	/*
	 * This framework function is actually implemented in the openssl
	 * plugin library, so we find the function address and call it.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_INTERNAL);
	}

	getCertStatusFn = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "OpenSSL_GetOCSPStatusForCert");
	if (getCertStatusFn == NULL) {
		return (KMF_ERR_INTERNAL);
	}

	return (getCertStatusFn(handle, num_args, attrlist));

}

KMF_RETURN
kmf_string_to_oid(char *oidstring, KMF_OID *oid)
{
	KMF_RETURN rv = KMF_OK;
	char *cp, *bp, *startp;
	int numbuf;
	int onumbuf;
	int nbytes, index;
	int len;
	unsigned char *op;

	if (oidstring == NULL || oid == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	len = strlen(oidstring);

	bp = oidstring;
	cp = bp;
	/* Skip over leading space */
	while ((bp < &cp[len]) && isspace(*bp))
		bp++;

	startp = bp;
	nbytes = 0;

	/*
	 * The first two numbers are chewed up by the first octet.
	 */
	if (sscanf(bp, "%d", &numbuf) != 1)
		return (KMF_ERR_BAD_PARAMETER);
	while ((bp < &cp[len]) && isdigit(*bp))
		bp++;
	while ((bp < &cp[len]) && (isspace(*bp) || *bp == '.'))
		bp++;
	if (sscanf(bp, "%d", &numbuf) != 1)
		return (KMF_ERR_BAD_PARAMETER);
	while ((bp < &cp[len]) && isdigit(*bp))
		bp++;
	while ((bp < &cp[len]) && (isspace(*bp) || *bp == '.'))
		bp++;
	nbytes++;

	while (isdigit(*bp)) {
		if (sscanf(bp, "%d", &numbuf) != 1)
			return (KMF_ERR_BAD_PARAMETER);
		while (numbuf) {
			nbytes++;
			numbuf >>= 7;
		}
		while ((bp < &cp[len]) && isdigit(*bp))
			bp++;
		while ((bp < &cp[len]) && (isspace(*bp) || *bp == '.'))
			bp++;
	}

	oid->Length = nbytes;
	oid->Data = malloc(oid->Length);
	if (oid->Data == NULL) {
		return (KMF_ERR_MEMORY);
	}
	(void) memset(oid->Data, 0, oid->Length);

	op = oid->Data;

	bp = startp;
	(void) sscanf(bp, "%d", &numbuf);

	while (isdigit(*bp)) bp++;
	while (isspace(*bp) || *bp == '.') bp++;

	onumbuf = 40 * numbuf;
	(void) sscanf(bp, "%d", &numbuf);
	onumbuf += numbuf;
	*op = (unsigned char) onumbuf;
	op++;

	while (isdigit(*bp)) bp++;
	while (isspace(*bp) || *bp == '.') bp++;
	while (isdigit(*bp)) {
		(void) sscanf(bp, "%d", &numbuf);
		nbytes = 0;
		/* Have to fill in the bytes msb-first */
		onumbuf = numbuf;
		while (numbuf) {
			nbytes++;
			numbuf >>= 7;
		}
		numbuf = onumbuf;
		op += nbytes;
		index = -1;
		while (numbuf) {
			op[index] = (unsigned char)numbuf & 0x7f;
			if (index != -1)
				op[index] |= 0x80;
			index--;
			numbuf >>= 7;
		}
		while (isdigit(*bp)) bp++;
		while (isspace(*bp) || *bp == '.') bp++;
	}

	return (rv);
}

static KMF_RETURN
encode_rid(char *name, KMF_DATA *derdata)
{
	KMF_RETURN rv = KMF_OK;

	if (name == NULL || derdata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_string_to_oid(name, (KMF_OID *)derdata);

	return (rv);
}

static KMF_RETURN
encode_ipaddr(char *name, KMF_DATA *derdata)
{
	KMF_RETURN rv = KMF_OK;
	size_t len;
	in_addr_t v4;
	in6_addr_t v6;
	uint8_t *ptr;

	if (name == NULL || derdata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	v4 = inet_addr(name);
	if (v4 == (in_addr_t)-1) {
		ptr = (uint8_t *)&v6;
		if (inet_pton(AF_INET6, name, ptr) != 1)
			return (KMF_ERR_ENCODING);
		len = sizeof (v6);
	} else {
		ptr = (uint8_t *)&v4;
		len = sizeof (v4);
	}

	derdata->Data = malloc(len);
	if (derdata->Data == NULL)
		return (KMF_ERR_MEMORY);
	(void) memcpy(derdata->Data, ptr, len);
	derdata->Length = len;

	return (rv);
}

static KMF_RETURN
encode_krb5(char *name, KMF_DATA *derdata)
{
	KMF_RETURN rv = KMF_OK;
	char *at, *realm;
	char *slash, *inst = NULL;
	BerElement *asn1 = NULL;
	BerValue *extdata = NULL;

	at = strchr(name, '@');
	if (at == NULL)
		return (KMF_ERR_ENCODING);

	realm = at + 1;
	*at = 0;

	/*
	 * KRB5PrincipalName ::= SEQUENCE {
	 *	realm		[0] Realm,
	 *	principalName	[1] PrincipalName
	 * }
	 *
	 * KerberosString	::= GeneralString (IA5String)
	 * Realm	::= KerberosString
	 * PrincipalName	::= SEQUENCE {
	 *	name-type	[0] Int32,
	 *	name-string	[1] SEQUENCE OF KerberosString
	 * }
	 */

	/*
	 * Construct the "principalName" first.
	 *
	 * The name may be split with a "/" to indicate a new instance.
	 * This must be separated in the ASN.1
	 */
	slash = strchr(name, '/');
	if (slash != NULL) {
		inst = name;
		name = slash + 1;
		*slash = 0;
	}
	if ((asn1 = kmfder_alloc()) == NULL) {
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}
	if (kmfber_printf(asn1, "{Tli", 0xa0, 3, 0x01) == -1)
		goto cleanup;

	if (inst != NULL) {
		if (kmfber_printf(asn1, "Tl{Tl", 0xA1,
		    strlen(inst) + strlen(name) + 6,
		    BER_GENERALSTRING, strlen(inst)) == -1)
			goto cleanup;
		if (kmfber_write(asn1, inst, strlen(inst), 0) != strlen(inst))
			goto cleanup;
		if (kmfber_printf(asn1, "Tl", BER_GENERALSTRING,
		    strlen(name)) == -1)
			goto cleanup;
		if (kmfber_write(asn1, name, strlen(name), 0) != strlen(name))
			goto cleanup;
	} else {
		if (kmfber_printf(asn1, "Tl{Tl", 0xA1,
		    strlen(name) + 4, BER_GENERALSTRING, strlen(name)) == -1)
			goto cleanup;
		if (kmfber_write(asn1, name, strlen(name), 0) != strlen(name))
			goto cleanup;
	}

	if (kmfber_printf(asn1, "}}") == -1)
		goto cleanup;
	if (kmfber_flatten(asn1, &extdata) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	kmfber_free(asn1, 1);
	asn1 = NULL;

	/* Next construct the KRB5PrincipalNameSeq */
	if ((asn1 = kmfder_alloc()) == NULL) {
		kmfber_bvfree(extdata);
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}
	if (kmfber_printf(asn1, "{TlTl", 0xA0, strlen(realm) + 2,
	    BER_GENERALSTRING, strlen(realm)) == -1)
		goto cleanup;
	if (kmfber_write(asn1, realm, strlen(realm), 0) != strlen(realm))
		goto cleanup;
	if (kmfber_printf(asn1, "Tl", 0xA1, extdata->bv_len) == -1)
		goto cleanup;
	if (kmfber_write(asn1, extdata->bv_val,
	    extdata->bv_len, 0) != extdata->bv_len)
		goto cleanup;
	if (kmfber_printf(asn1, "}") == -1)
		goto cleanup;
	kmfber_bvfree(extdata);
	extdata = NULL;
	if (kmfber_flatten(asn1, &extdata) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	kmfber_free(asn1, 1);
	asn1 = NULL;

	/*
	 * GeneralName ::= CHOICE {
	 *	otherName	[0]	OtherName,
	 *	...
	 * }
	 *
	 * OtherName ::= SEQUENCE {
	 *	type-id	OBJECT IDENTIFIER,
	 *	value	[0] EXPLICIT ANY DEFINED BY type-id
	 * }
	 */

	/* Now construct the SAN: OID + typed data. */
	if ((asn1 = kmfder_alloc()) == NULL) {
		kmfber_bvfree(extdata);
		rv = KMF_ERR_MEMORY;
		goto cleanup;
	}
	if (kmfber_printf(asn1, "D", &KMFOID_PKINIT_san) == -1)
		goto cleanup;
	if (kmfber_printf(asn1, "Tl", 0xA0, extdata->bv_len) == -1)
		goto cleanup;
	if (kmfber_write(asn1, extdata->bv_val,
	    extdata->bv_len, 0) != extdata->bv_len)
		goto cleanup;
	kmfber_bvfree(extdata);
	extdata = NULL;
	if (kmfber_flatten(asn1, &extdata) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}
	kmfber_free(asn1, 1);
	asn1 = NULL;

	derdata->Data = (uchar_t *)extdata->bv_val;
	extdata->bv_val = NULL; /* clear it so it is not freed later */
	derdata->Length = extdata->bv_len;

cleanup:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	if (extdata != NULL)
		kmfber_bvfree(extdata);

	if (*at == 0)
		*at = '@';

	if (inst != NULL)
		*slash = '/';

	return (rv);
}

static KMF_RETURN
encode_sclogon(char *name, KMF_DATA *derdata)
{
	KMF_RETURN rv = KMF_OK;
	BerElement *asn1 = NULL;
	BerValue *extdata = NULL;

	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	/* The name is encoded as a KerberosString (IA5STRING) */
	if (kmfber_printf(asn1, "{Ds}",
	    &KMFOID_MS_KP_SCLogon, name) == -1)
		goto cleanup;

	if (kmfber_flatten(asn1, &extdata) == -1) {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}

	derdata->Data = (uchar_t *)extdata->bv_val;
	derdata->Length = extdata->bv_len;

	free(extdata);
cleanup:
	if (asn1 != NULL)
		kmfber_free(asn1, 1);

	return (rv);
}

static KMF_RETURN
verify_uri_format(char *uristring)
{
	KMF_RETURN ret = KMF_OK;
	xmlURIPtr   uriptr = NULL;

	/* Parse the URI string; get the hostname and port */
	uriptr = xmlParseURI(uristring);
	if (uriptr == NULL) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	if (uriptr->scheme == NULL || !strlen(uriptr->scheme)) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}

	if (uriptr->server == NULL || !strlen(uriptr->server)) {
		ret = KMF_ERR_BAD_URI;
		goto out;
	}
out:
	if (uriptr != NULL)
		xmlFreeURI(uriptr);
	return (ret);
}

static KMF_RETURN
encode_altname(char *namedata,
	KMF_GENERALNAMECHOICES nametype, KMF_DATA *encodedname)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_NAME dnname;
	uchar_t tagval;
	BerElement *asn1 = NULL;
	BerValue *extdata;

	if (namedata == NULL || encodedname == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Encode the namedata according to rules in RFC 3280 for GeneralName.
	 * The input "namedata" is assumed to be an ASCII string representation
	 * of the AltName, we need to convert it to correct ASN.1 here before
	 * adding it to the cert.
	 */
	switch (nametype) {
		case GENNAME_RFC822NAME: /* rfc 822 */
			/* IA5String, no encoding needed */
			encodedname->Data = (uchar_t *)strdup(namedata);
			if (encodedname->Data == NULL)
				return (KMF_ERR_MEMORY);
			encodedname->Length = strlen(namedata);
			tagval = (0x80 | nametype);
			break;
		case GENNAME_DNSNAME: /* rfc 1034 */
			encodedname->Data = (uchar_t *)strdup(namedata);
			if (encodedname->Data == NULL)
				return (KMF_ERR_MEMORY);
			encodedname->Length = strlen(namedata);
			tagval = (0x80 | nametype);
			break;
		case GENNAME_URI: /* rfc 1738 */
			ret = verify_uri_format(namedata);
			if (ret != KMF_OK)
				return (ret);
			/* IA5String, no encoding needed */
			encodedname->Data = (uchar_t *)strdup(namedata);
			if (encodedname->Data == NULL)
				return (KMF_ERR_MEMORY);
			encodedname->Length = strlen(namedata);
			tagval = (0x80 | nametype);
			break;
		case GENNAME_IPADDRESS:
			ret =  encode_ipaddr(namedata, encodedname);
			tagval = (0x80 | nametype);
			break;
		case GENNAME_REGISTEREDID:
			ret = encode_rid(namedata, encodedname);
			tagval = (0x80 | nametype);
			break;
		case GENNAME_DIRECTORYNAME:
			ret = kmf_dn_parser(namedata, &dnname);
			if (ret == KMF_OK) {
				ret = DerEncodeName(&dnname, encodedname);
			}
			(void) kmf_free_dn(&dnname);
			tagval = (0x80 | nametype);
			break;
		case GENNAME_KRB5PRINC:
			tagval = (0xA0 | GENNAME_OTHERNAME);
			ret = encode_krb5(namedata, encodedname);
			break;
		case GENNAME_SCLOGON_UPN:
			tagval = (0xA0 | GENNAME_OTHERNAME);
			ret = encode_sclogon(namedata, encodedname);
			break;
		default:
			/* unsupported */
			return (KMF_ERR_BAD_PARAMETER);

	}
	if (ret != KMF_OK) {
		kmf_free_data(encodedname);
		return (ret);
	}

	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "Tl", tagval, encodedname->Length) == -1)
		goto cleanup;

	if (kmfber_write(asn1, (char *)encodedname->Data,
	    encodedname->Length, 0) == -1) {
		ret = KMF_ERR_ENCODING;
		goto cleanup;
	}
	if (kmfber_flatten(asn1, &extdata) == -1) {
		ret = KMF_ERR_ENCODING;
		goto cleanup;
	}

	kmf_free_data(encodedname);
	encodedname->Data = (uchar_t *)extdata->bv_val;
	encodedname->Length = extdata->bv_len;

	free(extdata);

cleanup:
	if (asn1)
		kmfber_free(asn1, 1);

	if (ret != KMF_OK)
		kmf_free_data(encodedname);

	return (ret);
}

KMF_X509_EXTENSION *
FindExtn(KMF_X509_EXTENSIONS *exts, KMF_OID *oid)
{
	KMF_X509_EXTENSION *foundextn = NULL;
	int i;

	if (exts == NULL || oid == NULL)
		return (NULL);

	for (i = 0; i < exts->numberOfExtensions; i++) {
		if (IsEqualOid(oid, &exts->extensions[i].extnId))  {
			foundextn = &exts->extensions[i];
			break;
		}
	}
	return (foundextn);
}

KMF_RETURN
GetSequenceContents(char *data, size_t len,
	char **contents, size_t *outlen)
{
	KMF_RETURN ret = KMF_OK;
	BerElement *exasn1 = NULL;
	BerValue oldextn;
	int tag;
	size_t oldsize;
	char *olddata = NULL;

	if (data == NULL || contents == NULL || outlen == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Decode the sequence of general names
	 */
	oldextn.bv_val = data;
	oldextn.bv_len = len;

	if ((exasn1 = kmfder_init(&oldextn)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}

	/*
	 * Unwrap the sequence to find the size of the block
	 * of GeneralName items in the set.
	 *
	 * Peek at the tag and length ("tl"),
	 * then consume them ("{").
	 */
	if (kmfber_scanf(exasn1, "tl{", &tag, &oldsize) == KMFBER_DEFAULT ||
	    oldsize == 0) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	olddata = malloc(oldsize);
	if (olddata == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}
	(void) memset(olddata, 0, oldsize);
	/*
	 * Read the entire blob of GeneralNames, we don't
	 * need to interpret them now.
	 */
	if (kmfber_read(exasn1, olddata, oldsize) != oldsize) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}
out:
	if (exasn1 != NULL)
		kmfber_free(exasn1, 1);

	if (ret != KMF_OK) {
		*contents = NULL;
		*outlen = 0;
		if (olddata != NULL)
			free(olddata);
	} else {
		*contents = olddata;
		*outlen = oldsize;
	}
	return (ret);
}

KMF_RETURN
add_an_extension(KMF_X509_EXTENSIONS *exts, KMF_X509_EXTENSION *newextn)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION *extlist;

	if (exts == NULL || newextn == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	extlist = malloc(sizeof (KMF_X509_EXTENSION) *
	    (exts->numberOfExtensions + 1));
	if (extlist == NULL)
		return (KMF_ERR_MEMORY);

	(void) memcpy(extlist, exts->extensions,
	    exts->numberOfExtensions * sizeof (KMF_X509_EXTENSION));

	(void) memcpy(&extlist[exts->numberOfExtensions], newextn,
	    sizeof (KMF_X509_EXTENSION));

	free(exts->extensions);
	exts->numberOfExtensions++;
	exts->extensions = extlist;

	return (ret);
}

KMF_RETURN
kmf_set_altname(KMF_X509_EXTENSIONS *extensions,
	KMF_OID *oid,
	int critical,
	KMF_GENERALNAMECHOICES nametype,
	char *namedata)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION subjAltName;
	KMF_DATA dername = { 0, NULL };
	BerElement *asn1 = NULL;
	BerValue *extdata;
	char *olddata = NULL;
	KMF_X509_EXTENSION *foundextn = NULL;
	size_t	oldsize = 0;

	if (extensions == NULL || oid == NULL || namedata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = encode_altname(namedata, nametype, &dername);

	if (ret != KMF_OK)
		return (ret);

	(void) memset(&subjAltName, 0, sizeof (subjAltName));

	ret = copy_data(&subjAltName.extnId, oid);
	if (ret != KMF_OK)
		goto out;
	/*
	 * Check to see if this cert already has a subjectAltName.
	 */
	foundextn = FindExtn(extensions, oid);

	if (foundextn != NULL) {
		ret = GetSequenceContents(
		    (char *)foundextn->BERvalue.Data,
		    foundextn->BERvalue.Length,
		    &olddata, &oldsize);
		if (ret != KMF_OK)
			goto out;
	}

	/*
	 * Assume (!!) that the namedata given is already properly encoded.
	 */
	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "{") == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	/* Write the old extension data first */
	if (olddata != NULL && oldsize > 0) {
		if (kmfber_write(asn1, olddata, oldsize, 0) == -1) {
			ret = KMF_ERR_ENCODING;
			goto out;
		}
	}

	/* Now add the new name to the list */
	if (kmfber_write(asn1, (char *)dername.Data, dername.Length, 0) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	/* Now close the sequence */
	if (kmfber_printf(asn1, "}") == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}
	if (kmfber_flatten(asn1, &extdata) == -1) {
		ret = KMF_ERR_ENCODING;
		goto out;
	}

	/*
	 * If we are just adding to an existing list of altNames,
	 * just replace the BER data associated with the found extension.
	 */
	if (foundextn != NULL) {
		free(foundextn->BERvalue.Data);
		foundextn->critical = critical;
		foundextn->BERvalue.Data = (uchar_t *)extdata->bv_val;
		foundextn->BERvalue.Length = extdata->bv_len;
	} else {
		subjAltName.critical = critical;
		subjAltName.format = KMF_X509_DATAFORMAT_ENCODED;
		subjAltName.BERvalue.Data = (uchar_t *)extdata->bv_val;
		subjAltName.BERvalue.Length = extdata->bv_len;
		ret = add_an_extension(extensions, &subjAltName);
		if (ret != KMF_OK)
			free(subjAltName.BERvalue.Data);
	}

	free(extdata);
out:
	if (olddata != NULL)
		free(olddata);

	kmf_free_data(&dername);
	if (ret != KMF_OK)
		kmf_free_data(&subjAltName.extnId);
	if (asn1 != NULL)
		kmfber_free(asn1, 1);
	return (ret);
}

/*
 * Search a list of attributes for one that matches the given type.
 * Return a pointer into the attribute list.  This does not
 * return a copy of the value, it returns a reference into the
 * given list.
 */
int
kmf_find_attr(KMF_ATTR_TYPE type, KMF_ATTRIBUTE *attlist, int numattrs)
{
	int i;
	for (i = 0; i < numattrs; i++) {
		if (attlist[i].type == type)
			return (i);
	}
	return (-1);
}

/*
 * Verify that a given attribute is consistent with the
 * "test" attribute.
 */
static KMF_RETURN
verify_attribute(KMF_ATTRIBUTE *givenattr,
	KMF_ATTRIBUTE_TESTER *testattr)
{
	/* A NULL pValue was found where one is required */
	if (testattr->null_value_ok == FALSE &&
	    givenattr->pValue == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the given valueLen is too small, return error */
	if (givenattr->pValue != NULL &&
	    testattr->minlen > 0 &&
	    (givenattr->valueLen < testattr->minlen))
		return (KMF_ERR_BAD_PARAMETER);

	/* If the given valueLen is too big, return error */
	if (givenattr->pValue != NULL &&
	    testattr->maxlen > 0 &&
	    (givenattr->valueLen > testattr->maxlen))
		return (KMF_ERR_BAD_PARAMETER);

	return (KMF_OK);
}

/*
 * Given a set of required attribute tests and optional
 * attributes, make sure that the actual attributes
 * being tested (attrlist below) are allowed and are
 * properly specified.
 */
KMF_RETURN
test_attributes(int reqnum, KMF_ATTRIBUTE_TESTER *reqattrs,
	int optnum, KMF_ATTRIBUTE_TESTER *optattrs,
	int numattrs, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	int i, idx;

	/*
	 * If the caller didn't supply enough attributes,
	 * return an error.
	 */
	if (numattrs < reqnum || attrlist == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Make sure all required attrs are present and
	 * correct.
	 */
	for (i = 0; i < reqnum && ret == KMF_OK; i++) {
		idx = kmf_find_attr(reqattrs[i].type, attrlist, numattrs);
		/* If a required attr is not found, return error */
		if (idx == -1) {
			return (KMF_ERR_BAD_PARAMETER);
		}

		ret = verify_attribute(&attrlist[idx], &reqattrs[i]);
	}
	/*
	 * Now test the optional parameters.
	 */
	for (i = 0; i < optnum && ret == KMF_OK; i++) {
		idx = kmf_find_attr(optattrs[i].type, attrlist, numattrs);
		/* If a optional attr is not found, continue. */
		if (idx == -1) {
			continue;
		}

		ret = verify_attribute(&attrlist[idx], &optattrs[i]);
	}

	return (ret);
}

/*
 * Given an already allocated attribute list, insert
 * the given attribute information at a specific index
 * in the list.
 */
void
kmf_set_attr_at_index(KMF_ATTRIBUTE *attlist, int index,
	KMF_ATTR_TYPE type,  void *pValue, uint32_t len)
{
	if (attlist == NULL)
		return;

	attlist[index].type = type;
	attlist[index].pValue = pValue;
	attlist[index].valueLen = len;
}

/*
 * Find an attribute matching a particular type and set
 * the pValue and length fields to the given values.
 */
KMF_RETURN
kmf_set_attr(KMF_ATTRIBUTE *attlist, int numattr,
	KMF_ATTR_TYPE type,  void *pValue, uint32_t len)
{
	int idx;
	if (attlist == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	idx = kmf_find_attr(type, attlist, numattr);
	if (idx == -1)
		return (KMF_ERR_ATTR_NOT_FOUND);

	attlist[idx].type = type;
	/* Assumes the attribute pValue can hold the result */
	if (attlist[idx].pValue != NULL) {
		if (attlist[idx].valueLen >= len)
			(void) memcpy(attlist[idx].pValue, pValue, len);
		else
			return (KMF_ERR_BUFFER_SIZE);
	}
	attlist[idx].valueLen = len;
	return (KMF_OK);
}

/*
 * Find a particular attribute in a list and return
 * a pointer to its value.
 */
void *
kmf_get_attr_ptr(KMF_ATTR_TYPE type, KMF_ATTRIBUTE *attlist,
	int numattrs)
{
	int i;

	i = kmf_find_attr(type, attlist, numattrs);
	if (i == -1)
		return (NULL);

	return (attlist[i].pValue);
}

/*
 * Find a particular attribute in a list and return
 * the value and length values.  Value and length
 * may be NULL if the caller doesn't want their values
 * to be filled in.
 */
KMF_RETURN
kmf_get_attr(KMF_ATTR_TYPE type, KMF_ATTRIBUTE *attlist,
	int numattrs, void *outValue, uint32_t *outlen)
{
	int i;
	uint32_t len = 0;
	uint32_t *lenptr = outlen;

	if (lenptr == NULL)
		lenptr = &len;

	i = kmf_find_attr(type, attlist, numattrs);
	if (i == -1)
		return (KMF_ERR_ATTR_NOT_FOUND);

	/* This assumes that the ptr passed in is pre-allocated space */
	if (attlist[i].pValue != NULL && outValue != NULL) {
		/*
		 * If the caller did not specify a length,
		 * assume "outValue" is big enough.
		 */
		if (outlen != NULL) {
			if (*outlen >= attlist[i].valueLen)
				(void) memcpy(outValue, attlist[i].pValue,
				    attlist[i].valueLen);
			else
				return (KMF_ERR_BUFFER_SIZE);
		} else {
			(void) memcpy(outValue, attlist[i].pValue,
			    attlist[i].valueLen);
		}
	}

	if (outlen != NULL)
		*outlen = attlist[i].valueLen;
	return (KMF_OK);
}

/*
 * Utility routine to find a string type attribute, allocate it
 * and return the value to the caller.  This simplifies the
 * operation by doing both "kmf_get_attr" calls and avoids
 * duplicating this block of code in lots of places.
 */
KMF_RETURN
kmf_get_string_attr(KMF_ATTR_TYPE type, KMF_ATTRIBUTE *attrlist,
	int numattrs, char **outstr)
{
	KMF_RETURN rv;
	uint32_t len;

	if (outstr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if ((rv = kmf_get_attr(type, attrlist, numattrs, NULL, &len)) ==
	    KMF_OK) {
		*outstr = malloc(len + 1);
		if ((*outstr) == NULL)
			return (KMF_ERR_MEMORY);
		(void) memset((*outstr), 0, len + 1);
		rv = kmf_get_attr(type, attrlist, numattrs, (*outstr), &len);
		if (rv != KMF_OK) {
			free(*outstr);
			*outstr = NULL;
		}
	}

	return (rv);
}


void
free_entry(conf_entry_t *entry)
{
	if (entry == NULL)
		return;
	free(entry->keystore);
	free(entry->modulepath);
	free(entry->option);
}

void
free_entrylist(conf_entrylist_t *list)
{
	conf_entrylist_t *next;

	while (list != NULL) {
		next = list->next;
		free_entry(list->entry);
		free(list);
		list = next;
	}
}

static KMF_RETURN
parse_entry(char *buf, conf_entry_t **entry)
{
	KMF_RETURN ret = KMF_OK;
	conf_entry_t *tmp = NULL;
	char *token1;
	char *token2;
	char *token3;
	char *lasts;
	char *value;

	if ((token1 = strtok_r(buf, SEP_COLON, &lasts)) == NULL)
		return (KMF_ERR_KMF_CONF);

	if ((tmp = calloc(sizeof (conf_entry_t), 1)) == NULL)
		return (KMF_ERR_MEMORY);

	if ((tmp->keystore = strdup(token1)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	if ((token2 = strtok_r(NULL, SEP_SEMICOLON, &lasts)) == NULL) {
		ret = KMF_ERR_KMF_CONF;
		goto end;
	}

	/* need to get token3 first to satisfy nested strtok invocations */
	token3 = strtok_r(NULL, SEP_SEMICOLON, &lasts);

	/* parse token2 */
	if (strncmp(token2, CONF_MODULEPATH, strlen(CONF_MODULEPATH)) != 0) {
		ret = KMF_ERR_KMF_CONF;
		goto end;
	}

	if (value = strpbrk(token2, SEP_EQUAL)) {
		value++; /* get rid of = */
	} else {
		ret = KMF_ERR_KMF_CONF;
		goto end;
	}

	if ((tmp->modulepath = strdup(value)) == NULL) {
		ret = KMF_ERR_MEMORY;
		goto end;
	}

	/* parse token3, if it exists */
	if (token3 != NULL) {
		if (strncmp(token3, CONF_OPTION, strlen(CONF_OPTION))
		    != 0) {
			ret = KMF_ERR_KMF_CONF;
			goto end;
		}

		if (value = strpbrk(token3, SEP_EQUAL)) {
			value++; /* get rid of = */
		} else {
			ret = KMF_ERR_KMF_CONF;
			goto end;
		}

		if ((tmp->option = strdup(value)) == NULL) {
			ret = KMF_ERR_MEMORY;
			goto end;
		}
	}

	*entry = tmp;

end:
	if (ret != KMF_OK) {
		free_entry(tmp);
		free(tmp);
	}
	return (ret);
}


conf_entry_t *
dup_entry(conf_entry_t *entry)
{
	conf_entry_t *rtn_entry;

	if (entry == NULL)
		return (NULL);

	rtn_entry = malloc(sizeof (conf_entry_t));
	if (rtn_entry == NULL)
		return (NULL);

	if ((rtn_entry->keystore = strdup(entry->keystore)) == NULL)
		goto out;

	if ((rtn_entry->modulepath = strdup(entry->modulepath)) == NULL)
		goto out;

	if (entry->option != NULL &&
	    (rtn_entry->option = strdup(entry->modulepath)) == NULL)
		goto out;

	return (rtn_entry);

out:
	free_entry(rtn_entry);
	return (NULL);
}


/*
 * This function takes a keystore_name as input and returns
 * the KMF_KEYSTORE_TYPE value assigned to it.  If the "option"
 * argument is not NULL, this function also returns the option string
 * if there is an option string for the plugin module.
 */
KMF_RETURN
kmf_get_plugin_info(KMF_HANDLE_T handle, char *keystore_name,
    KMF_KEYSTORE_TYPE *kstype, char **option)
{
	KMF_RETURN ret = KMF_OK;
	conf_entrylist_t  *phead = extra_plugin_list;
	boolean_t is_default = B_TRUE;

	/*
	 * Although handle is not really used in the function, we will
	 * check the handle to make sure that kmf_intialize() is called
	 * before this function.
	 */
	if (handle == NULL || keystore_name == NULL || kstype == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (strcmp(keystore_name, "pkcs11") == 0) {
		*kstype = KMF_KEYSTORE_PK11TOKEN;
	} else if (strcmp(keystore_name, "file") == 0) {
		*kstype = KMF_KEYSTORE_OPENSSL;
	} else if (strcmp(keystore_name, "nss") == 0) {
		*kstype = KMF_KEYSTORE_NSS;
	} else {
		is_default = B_FALSE;
	}

	if (is_default) {
		if (option != NULL)
			*option = NULL;
		goto out;
	}

	/* Not a built-in plugin; check if it is in extra_plugin_list. */
	while (phead != NULL) {
		if (strcmp(phead->entry->keystore, keystore_name) == 0)
			break;
		phead = phead->next;
	}

	if (phead == NULL) {
		ret = KMF_ERR_PLUGIN_NOTFOUND;
		goto out;
	}

	/* found it */
	*kstype = phead->entry->kstype;
	if (option != NULL) {
		if (phead->entry->option == NULL)
			*option = NULL;
		else {
			*option = strdup(phead->entry->option);
			if (*option == NULL) {
				ret = KMF_ERR_MEMORY;
				goto out;
			}
		}
	}

out:
	return (ret);
}

/*
 * Retrieve the non-default plugin list from the kmf.conf file.
 */
KMF_RETURN
get_entrylist(conf_entrylist_t **entlist)
{
	KMF_RETURN rv = KMF_OK;
	FILE *pfile;
	conf_entry_t *entry;
	conf_entrylist_t *rtnlist = NULL;
	conf_entrylist_t *ptmp;
	conf_entrylist_t *pcur;
	char buffer[MAXPATHLEN];
	size_t len;

	if ((pfile = fopen(_PATH_KMF_CONF, "rF")) == NULL) {
		cryptoerror(LOG_ERR, "failed to open %s.\n", _PATH_KMF_CONF);
		return (KMF_ERR_KMF_CONF);
	}

	while (fgets(buffer, MAXPATHLEN, pfile) != NULL) {
		if (buffer[0] == '#' || buffer[0] == ' ' ||
		    buffer[0] == '\n'|| buffer[0] == '\t') {
			continue;   /* ignore comment lines */
		}

		len = strlen(buffer);
		if (buffer[len-1] == '\n') { /* get rid of trailing '\n' */
			len--;
		}
		buffer[len] = '\0';

		rv = parse_entry(buffer, &entry);
		if (rv != KMF_OK) {
			goto end;
		}

		if ((ptmp = malloc(sizeof (conf_entrylist_t))) == NULL) {
			rv = KMF_ERR_MEMORY;
			goto end;
		}
		ptmp->entry = entry;
		ptmp->next = NULL;

		if (rtnlist == NULL) {
			rtnlist = pcur = ptmp;
		} else {
			pcur->next = ptmp;
			pcur = ptmp;
		}
	}

end:
	(void) fclose(pfile);

	if (rv == KMF_OK) {
		*entlist = rtnlist;
	} else if (rtnlist != NULL) {
		free_entrylist(rtnlist);
		*entlist = NULL;
		kstore_num = DEFAULT_KEYSTORE_NUM;
	}

	return (rv);
}


boolean_t
is_valid_keystore_type(KMF_KEYSTORE_TYPE kstype)
{

	if (kstype > 0 && kstype <= kstore_num)
		return (B_TRUE);
	else
		return (B_FALSE);
}
