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
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	{KMF_ERR_KEY_MISMATCH,		"KMF_ERR_KEY_MISMATCH"}
};


static void free_extensions(KMF_X509_EXTENSIONS *extns);

int
is_pk11_ready()
{
	return (pkcs11_initialized);
}

/*
 * Private method for searching the plugin list for the correct
 * Plugin to use.
 */
KMF_PLUGIN *
FindPlugin(KMF_HANDLE_T handle, KMF_KEYSTORE_TYPE kstype)
{
	KMF_PLUGIN_LIST *node;

	if (handle == NULL)
		return (NULL);

	node = handle->plugins;

	while (node != NULL && node->plugin->type != kstype)
		node = node->next;

	/* If it is NULL, that is indication enough of an error */
	return (node ? node->plugin : NULL);
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
	p->dldesc = dlopen(path, RTLD_NOW | RTLD_GROUP | RTLD_PARENT);
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

		KMF_FreePolicyRecord(handle->policy);
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
KMF_Initialize(KMF_HANDLE_T *outhandle, char *policyfile, char *policyname)
{
	KMF_RETURN ret = KMF_OK;
	KMF_HANDLE *handle = NULL;
	KMF_PLUGIN *pluginrec = NULL;

	if (outhandle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*outhandle = NULL;
	handle = (KMF_HANDLE *)malloc(sizeof (KMF_HANDLE));
	if (handle == NULL)
		return (KMF_ERR_MEMORY);

	(void) memset(handle, 0, sizeof (KMF_HANDLE));
	handle->plugins = NULL;

	(void) mutex_lock(&init_lock);
	if (!pkcs11_initialized) {
		CK_RV rv = C_Initialize(NULL);
		if ((rv != CKR_OK) &&
		    (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
			ret = KMF_ERR_UNINITIALIZED;
			(void) mutex_unlock(&init_lock);
			goto errout;
		} else {
			pkcs11_initialized = 1;
		}
	}
	(void) mutex_unlock(&init_lock);

	/* Initialize the handle with the policy */
	ret = KMF_SetPolicy((void *)handle,
	    policyfile == NULL ? KMF_DEFAULT_POLICY_FILE : policyfile,
	    policyname == NULL ? KMF_DEFAULT_POLICY_NAME : policyname);
	if (ret != KMF_OK)
		goto errout;

	/* Create a record for the plugin */
	if ((ret = InitializePlugin(KMF_KEYSTORE_NSS,
		KMF_PLUGIN_PATH "kmf_nss.so.1", &pluginrec)) != KMF_OK)
		goto errout;

	/* Add it to the handle */
	if (pluginrec != NULL) {
		if ((ret = AddPlugin(handle, pluginrec)))
			goto errout;
	}
	if ((ret = InitializePlugin(KMF_KEYSTORE_OPENSSL,
		KMF_PLUGIN_PATH "kmf_openssl.so.1", &pluginrec)) != KMF_OK)
		goto errout;

	/* Add it to the handle */
	if (pluginrec != NULL)
		if ((ret = AddPlugin(handle, pluginrec)))
			goto errout;

	if ((ret = InitializePlugin(KMF_KEYSTORE_PK11TOKEN,
		KMF_PLUGIN_PATH "kmf_pkcs11.so.1", &pluginrec)) != KMF_OK)
		goto errout;

	/* Add it to the handle */
	if (pluginrec != NULL)
		if ((ret = AddPlugin(handle, pluginrec)))
			goto errout;

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
KMF_ConfigureKeystore(KMF_HANDLE_T handle, KMF_CONFIG_PARAMS *params)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, params->kstype);
	if (plugin == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	if (plugin->funclist->ConfigureKeystore != NULL)
		return (plugin->funclist->ConfigureKeystore(handle, params));
	else
		/* return KMF_OK, if the plugin does not have an entry */
		return (KMF_OK);
}

KMF_RETURN
KMF_Finalize(KMF_HANDLE_T handle)
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
KMF_GetKMFErrorString(KMF_RETURN errcode, char **errmsg)
{
	KMF_RETURN ret = KMF_OK;
	int i, maxerr;

	if (errmsg == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*errmsg = NULL;
	maxerr = sizeof (kmf_errcodes) / sizeof (kmf_error_map);

	for (i = 0; i < maxerr && errcode != kmf_errcodes[i].code; i++);

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
KMF_GetPluginErrorString(KMF_HANDLE_T handle, char **msgstr)
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

KMF_RETURN
KMF_DNParser(char *string, KMF_X509_NAME *name)
{
	KMF_RETURN err;

	if (string == NULL || name == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	err = ParseDistinguishedName(string, (int)strlen(string), name);
	return (err);
}

KMF_RETURN
KMF_DN2Der(KMF_X509_NAME *dn, KMF_DATA *der)
{
	KMF_RETURN rv;

	if (dn == NULL || der == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = DerEncodeName(dn, der);
	return (rv);
}

#define	SET_SYS_ERROR(h, c) h->lasterr.kstype = -1; h->lasterr.errcode = c;

KMF_RETURN
KMF_ReadInputFile(KMF_HANDLE_T handle, char *filename,  KMF_DATA *pdata)
{
	struct stat s;
	long nread, total = 0;
	int fd;
	unsigned char *buf = NULL;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);


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
 * Name: KMF_Der2Pem
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
KMF_Der2Pem(KMF_OBJECT_TYPE type, unsigned char *data,
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
 * Name: KMF_Pem2Der
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
KMF_Pem2Der(unsigned char *in, int inlen,
	unsigned char **out, int *outlen)
{
	KMF_RETURN err;
	if (in == NULL || out == NULL || outlen == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	err = Pem2Der(in, inlen, out, outlen);
	return (err);
}

char *
KMF_OID2String(KMF_OID *oid)
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
check_for_pem(char *filename)
{
	char buf[BUFSIZ];
	int len, f;

	if ((f = open(filename, O_RDONLY | O_NONBLOCK)) < 0)
		return (FALSE);

	while ((len = read(f, buf, sizeof (buf))) > 0) {
		/* Look for "-----BEGIN" right after a newline */
		char *p;

		p = strtok(buf, "\n");
		while (p != NULL) {
			if (p < (buf + len)) {
				if (strstr(p, "-----BEGIN") != NULL) {
					(void) close(f);
					return (TRUE);
				}
			}
			p = strtok(NULL, "\n");
		}
	}
	(void) close(f);
	return (FALSE);
}

KMF_RETURN
KMF_GetFileFormat(char *filename, KMF_ENCODE_FORMAT *fmt)
{
	int f;
	KMF_RETURN ret = KMF_OK;
	uchar_t buf[16];

	if (filename == NULL || !strlen(filename) || fmt == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	*fmt = 0;
	if ((f = open(filename, O_RDONLY)) == -1) {
		return (KMF_ERR_OPEN_FILE);
	}

	if (read(f, buf, 8) != 8) {
		ret = KMF_ERR_OPEN_FILE;
		goto end;
	}

	(void) close(f);
	if (buf[0] == 0x30 && (buf[1] & 0x80)) {
		if ((buf[1] & 0xFF) == 0x80 &&
		    (buf[2] & 0xFF) == 0x02 &&
		    (buf[5] & 0xFF) == 0x30) {
			*fmt = KMF_FORMAT_PKCS12;
		} else if ((buf[1] & 0xFF) == 0x82 &&
			(buf[4] & 0xFF) == 0x02 &&
			(buf[7] & 0xFF) == 0x30) {
			*fmt = KMF_FORMAT_PKCS12;
		/* It is most likely a generic ASN.1 encoded file */
		} else {
			*fmt = KMF_FORMAT_ASN1;
		}
	} else if (memcmp(buf, "Bag Attr", 8) == 0) {
		*fmt = KMF_FORMAT_PEM_KEYPAIR;
	} else {
		/* Try PEM */
		if (check_for_pem(filename) == TRUE) {
			*fmt = KMF_FORMAT_PEM;
		} else {
			/* Cannot determine this file format */
			*fmt = 0;
			ret = KMF_ERR_ENCODING;
		}
	}
end:
	return (ret);
}

KMF_RETURN
KMF_HexString2Bytes(unsigned char *hexstr, unsigned char **bytes,
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

	if (hexstr[0] == '0' &&
		((hexstr[1] == 'x') || (hexstr[1] == 'X')))
		hexstr += 2;

	for (i = 0; i < strlen((char *)hexstr) && isxdigit(hexstr[i]); i++);
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
KMF_FreeDN(KMF_X509_NAME *name)
{
	KMF_X509_RDN 		*newrdn = NULL;
	KMF_X509_TYPE_VALUE_PAIR *av = NULL;
	int i, j;

	if (name && name->numberOfRDNs) {
		for (i = 0; i < name->numberOfRDNs; i++) {
			newrdn = &name->RelativeDistinguishedName[i];
			for (j = 0; j < newrdn->numberOfPairs; j++) {
				av = &newrdn->AttributeTypeAndValue[j];
				KMF_FreeData(&av->type);
				KMF_FreeData(&av->value);
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
KMF_FreeKMFCert(KMF_HANDLE_T handle, KMF_X509_DER_CERT *kmf_cert)
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
KMF_FreeData(KMF_DATA *datablock)
{
	if (datablock != NULL && datablock->Data != NULL) {
		free(datablock->Data);
		datablock->Data = NULL;
		datablock->Length = 0;
	}
}

void
KMF_FreeAlgOID(KMF_X509_ALGORITHM_IDENTIFIER *algoid)
{
	if (algoid == NULL)
		return;
	KMF_FreeData(&algoid->algorithm);
	KMF_FreeData(&algoid->parameters);
}

void
KMF_FreeExtension(KMF_X509_EXTENSION *exptr)
{
	if (exptr == NULL)
		return;

	KMF_FreeData((KMF_DATA *)&exptr->extnId);
	KMF_FreeData(&exptr->BERvalue);

	if (exptr->value.tagAndValue) {
		KMF_FreeData(&exptr->value.tagAndValue->value);
		free(exptr->value.tagAndValue);
	}
}

void
KMF_FreeTBSCSR(KMF_TBS_CSR *tbscsr)
{
	if (tbscsr) {
		KMF_FreeData(&tbscsr->version);

		KMF_FreeDN(&tbscsr->subject);

		KMF_FreeAlgOID(&tbscsr->subjectPublicKeyInfo.algorithm);
		KMF_FreeData(&tbscsr->subjectPublicKeyInfo.subjectPublicKey);

		free_extensions(&tbscsr->extensions);
	}
}

void
KMF_FreeSignedCSR(KMF_CSR_DATA *csr)
{
	if (csr) {
		KMF_FreeTBSCSR(&csr->csr);

		KMF_FreeAlgOID(&csr->signature.algorithmIdentifier);
		KMF_FreeData(&csr->signature.encrypted);
	}
}

static void
free_validity(KMF_X509_VALIDITY *validity)
{
	if (validity == NULL)
		return;
	KMF_FreeData(&validity->notBefore.time);
	KMF_FreeData(&validity->notAfter.time);
}

static void
free_extensions(KMF_X509_EXTENSIONS *extns)
{
	int i;
	KMF_X509_EXTENSION *exptr;

	if (extns && extns->numberOfExtensions > 0) {
		for (i = 0; i < extns->numberOfExtensions; i++) {
			exptr = &extns->extensions[i];
			KMF_FreeExtension(exptr);
		}
		free(extns->extensions);
		extns->numberOfExtensions = 0;
		extns->extensions = NULL;
	}
}

void
KMF_FreeTBSCert(KMF_X509_TBS_CERT *tbscert)
{
	if (tbscert) {
		KMF_FreeData(&tbscert->version);
		KMF_FreeBigint(&tbscert->serialNumber);
		KMF_FreeAlgOID(&tbscert->signature);

		KMF_FreeDN(&tbscert->issuer);
		KMF_FreeDN(&tbscert->subject);

		free_validity(&tbscert->validity);

		KMF_FreeData(&tbscert->issuerUniqueIdentifier);
		KMF_FreeData(&tbscert->subjectUniqueIdentifier);

		KMF_FreeAlgOID(&tbscert->subjectPublicKeyInfo.algorithm);
		KMF_FreeData(&tbscert->subjectPublicKeyInfo.subjectPublicKey);

		free_extensions(&tbscert->extensions);

		KMF_FreeData(&tbscert->issuerUniqueIdentifier);
		KMF_FreeData(&tbscert->subjectUniqueIdentifier);
	}
}

void
KMF_FreeSignedCert(KMF_X509_CERTIFICATE *certptr)
{
	if (!certptr)
		return;

	KMF_FreeTBSCert(&certptr->certificate);

	KMF_FreeAlgOID(&certptr->signature.algorithmIdentifier);
	KMF_FreeData(&certptr->signature.encrypted);
}

void
KMF_FreeString(char *pstr)
{
	if (pstr != NULL)
		free(pstr);
}

void
free_keyidlist(KMF_OID *oidlist, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		KMF_FreeData((KMF_DATA *)&oidlist[i]);
	}
	free(oidlist);
}

void
KMF_FreeEKU(KMF_X509EXT_EKU *eptr)
{
	if (eptr && eptr->nEKUs > 0 &&
		eptr->keyPurposeIdList != NULL)
		free_keyidlist(eptr->keyPurposeIdList, eptr->nEKUs);
}

void
KMF_FreeSPKI(KMF_X509_SPKI *spki)
{
	if (spki != NULL) {
		KMF_FreeAlgOID(&spki->algorithm);
		KMF_FreeData(&spki->subjectPublicKey);
	}
}

void
KMF_FreeKMFKey(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return;

	if (key == NULL)
		return;

	plugin = FindPlugin(handle, key->kstype);
	if (plugin != NULL && plugin->funclist->DeleteKey != NULL) {
		(void) plugin->funclist->DeleteKey(handle, NULL, key, FALSE);
	}

	if (key == NULL)
		return;

	if (key->keylabel)
		free(key->keylabel);

	if (key->israw) {
		KMF_FreeRawKey(key->keyp);
		free(key->keyp);
	}

	(void) memset(key, 0, sizeof (KMF_KEY_HANDLE));
}

void
KMF_FreeBigint(KMF_BIGINT *big)
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
	KMF_FreeBigint(&key->mod);
	KMF_FreeBigint(&key->pubexp);
	KMF_FreeBigint(&key->priexp);
	KMF_FreeBigint(&key->prime1);
	KMF_FreeBigint(&key->prime2);
	KMF_FreeBigint(&key->exp1);
	KMF_FreeBigint(&key->exp2);
	KMF_FreeBigint(&key->coef);
}

static void
free_raw_dsa(KMF_RAW_DSA_KEY *key)
{
	if (key == NULL)
		return;
	KMF_FreeBigint(&key->prime);
	KMF_FreeBigint(&key->subprime);
	KMF_FreeBigint(&key->base);
	KMF_FreeBigint(&key->value);
}

static void
free_raw_sym(KMF_RAW_SYM_KEY *key)
{
	if (key == NULL)
		return;
	KMF_FreeBigint(&key->keydata);
}

void
KMF_FreeRawKey(KMF_RAW_KEY_DATA *key)
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
}

void
KMF_FreeRawSymKey(KMF_RAW_SYM_KEY *key)
{
	if (key == NULL)
		return;
	KMF_FreeBigint(&key->keydata);
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
		KMF_FreeData(urldata);
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
	KMF_FreeData(&(dp->reasons));
	/* Need not to free crl_issuer space at phase 1 */
}

/*
 * This function frees space for a KMF_X509EXT_CRLDISTPOINTS internally.
 */
void
KMF_FreeCRLDistributionPoints(KMF_X509EXT_CRLDISTPOINTS *crl_dps)
{
	int i;

	if (crl_dps == NULL)
		return;

	for (i = 0; i < crl_dps->number; i++)
		free_dp(&(crl_dps->dplist[i]));

	free(crl_dps->dplist);
}

KMF_RETURN
KMF_CreateOCSPRequest(KMF_HANDLE_T handle,  KMF_OCSPREQUEST_PARAMS *params,
    char *reqfile)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN (*createReqFn)(void *, KMF_OCSPREQUEST_PARAMS *params,
	    char *reqfile);
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);


	if (params == NULL ||
		reqfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

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

	return (createReqFn(handle, params, reqfile));
}

KMF_RETURN
KMF_GetOCSPStatusForCert(KMF_HANDLE_T handle,
    KMF_OCSPRESPONSE_PARAMS_INPUT *params_in,
    KMF_OCSPRESPONSE_PARAMS_OUTPUT *params_out)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN (*getCertStatusFn)(void *,
	    KMF_OCSPRESPONSE_PARAMS_INPUT *params_in,
	    KMF_OCSPRESPONSE_PARAMS_OUTPUT *params_out);
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);


	if (params_in == NULL ||
		params_out == NULL)
		return (KMF_ERR_BAD_PARAMETER);

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

	return (getCertStatusFn(handle, params_in, params_out));
}

KMF_RETURN
KMF_String2OID(char *oidstring, KMF_OID *oid)
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

	rv = KMF_String2OID(name, (KMF_OID *)derdata);

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
			ret = KMF_DNParser(namedata, &dnname);
			if (ret == KMF_OK) {
				ret = KMF_DN2Der(&dnname, encodedname);
			}
			(void) KMF_FreeDN(&dnname);
			tagval = (0xA0 | nametype);
			break;
		default:
			/* unsupported */
			return (KMF_ERR_BAD_PARAMETER);

	}
	if (ret != KMF_OK) {
		KMF_FreeData(encodedname);
		return (ret);
	}

	if ((asn1 = kmfder_alloc()) == NULL)
		return (KMF_ERR_MEMORY);

	if (kmfber_printf(asn1, "Tl",
		tagval, encodedname->Length) == -1)
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

	KMF_FreeData(encodedname);
	encodedname->Data = (uchar_t *)extdata->bv_val;
	encodedname->Length = extdata->bv_len;

	free(extdata);

cleanup:
	if (asn1)
		kmfber_free(asn1, 1);

	if (ret != KMF_OK)
		KMF_FreeData(encodedname);

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
KMF_SetAltName(KMF_X509_EXTENSIONS *extensions,
	KMF_OID *oid,
	int critical,
	KMF_GENERALNAMECHOICES nametype,
	char *namedata)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_EXTENSION subjAltName;
	KMF_DATA dername = { NULL, 0 };
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

	KMF_FreeData(&dername);
	if (ret != KMF_OK)
		KMF_FreeData(&subjAltName.extnId);
	if (asn1 != NULL)
		kmfber_free(asn1, 1);
	return (ret);
}
