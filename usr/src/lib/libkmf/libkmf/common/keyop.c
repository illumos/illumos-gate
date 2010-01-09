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
 */

#include <stdio.h>
#include <link.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ber_der.h>
#include <kmfapiP.h>
#include <libgen.h>
#include <cryptoutil.h>

KMF_RETURN
kmf_create_keypair(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
		{KMF_PRIVKEY_HANDLE_ATTR, FALSE, sizeof (KMF_KEY_HANDLE),
			sizeof (KMF_KEY_HANDLE)},
		{KMF_PUBKEY_HANDLE_ATTR, FALSE, sizeof (KMF_KEY_HANDLE),
			sizeof (KMF_KEY_HANDLE)},
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
	if (plugin != NULL && plugin->funclist->CreateKeypair != NULL) {
		return (plugin->funclist->CreateKeypair(handle, num_args,
		    attrlist));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
kmf_delete_key_from_keystore(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;
	KMF_KEY_HANDLE *key;


	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
		{KMF_KEY_HANDLE_ATTR, FALSE, sizeof (KMF_KEY_HANDLE),
			sizeof (KMF_KEY_HANDLE)},
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
	if (plugin != NULL && plugin->funclist->DeleteKey != NULL) {
		ret = plugin->funclist->DeleteKey(handle, num_args, attrlist);
	} else {
		ret = KMF_ERR_PLUGIN_NOTFOUND;
	}

	if (ret == KMF_OK) {
		key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, num_args);
		if (key == NULL)
			return (KMF_ERR_BAD_PARAMETER);
		if (key->keylabel != NULL)
			free(key->keylabel);

		if (key->israw && key->keyp != NULL) {
			if (key->keyclass ==  KMF_ASYM_PUB ||
			    key->keyclass == KMF_ASYM_PRI) {
				kmf_free_raw_key(key->keyp);
				free(key->keyp);
			} else if (key->keyclass == KMF_SYMMETRIC) {
				kmf_free_raw_sym_key(key->keyp);
			}
			/* Else we don't know how to free the memory. */
		}

		(void) memset(key, 0, sizeof (KMF_KEY_HANDLE));
	}

	return (ret);
}

KMF_RETURN
kmf_find_key(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
		{KMF_COUNT_ATTR, FALSE, sizeof (uint32_t),
			sizeof (uint32_t)}
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
	if (plugin != NULL && plugin->funclist->FindKey != NULL) {
		return (plugin->funclist->FindKey(handle, num_args, attrlist));
	}

	return (KMF_ERR_PLUGIN_NOTFOUND);
}

KMF_RETURN
kmf_create_sym_key(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
		{KMF_KEY_HANDLE_ATTR, FALSE, sizeof (KMF_KEY_HANDLE),
			sizeof (KMF_KEY_HANDLE)},
		{KMF_KEYALG_ATTR, FALSE, 1, sizeof (KMF_KEY_ALG)},
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
	if (plugin != NULL && plugin->funclist->CreateSymKey != NULL) {
		return (plugin->funclist->CreateSymKey(handle, num_args,
		    attrlist));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
kmf_get_sym_key_value(KMF_HANDLE_T handle, KMF_KEY_HANDLE *symkey,
	KMF_RAW_SYM_KEY *rkey)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (symkey == NULL || rkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, symkey->kstype);
	if (plugin != NULL &&
	    plugin->funclist->GetSymKeyValue != NULL) {
		return (plugin->funclist->GetSymKeyValue(handle,
		    symkey, rkey));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
kmf_store_key(KMF_HANDLE_T handle,
	int	numattr,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, numattr, attrlist);

	if (ret != KMF_OK)
		return (ret);

	ret = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, NULL);
	if (ret != KMF_OK)
		return (ret);

	plugin = FindPlugin(handle, kstype);
	if (plugin != NULL) {
		if (plugin->funclist->StoreKey != NULL)
			return (plugin->funclist->StoreKey(handle,
			    numattr, attrlist));
		else
			return (KMF_ERR_FUNCTION_NOT_FOUND);
	}
	return (KMF_ERR_PLUGIN_NOTFOUND);
}
