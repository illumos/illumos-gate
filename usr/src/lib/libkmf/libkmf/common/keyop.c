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

/*
 * The following are Phase 1 APIs still needed to maintain compat with elfsign.
 */

/*
 * Name: KMF_SignDataWithKey
 *
 * Description:
 *   This function signs a block of data using the private key
 * and returns the signature in output
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   key(input) - contains private key handle needed for signing
 *   AlgOID(input) - contains algorithm to be used for signing
 *   tobesigned(input) - pointer to a KMF_DATA structure containing
 *		the data to be signed
 *   output(output) - pointer to the KMF_DATA structure containing the
 *		signed data
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_SignDataWithKey(KMF_HANDLE_T handle,
	KMF_KEY_HANDLE *key,
	KMF_OID *AlgOID,
	KMF_DATA *tobesigned,
	KMF_DATA *output)
{
	KMF_ATTRIBUTE attlist[5]; /* only 5 attrs for SignData */
	int i = 0;

	if (key == NULL || AlgOID == NULL ||
	    tobesigned == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &key->kstype, sizeof (key->kstype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEY_HANDLE_ATTR, key, sizeof (KMF_KEY_HANDLE));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_OID_ATTR, AlgOID, sizeof (KMF_OID));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_DATA_ATTR, tobesigned, sizeof (KMF_DATA));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_OUT_DATA_ATTR, output, sizeof (KMF_DATA));
	i++;

	return (kmf_sign_data(handle, i, attlist));
}


KMF_RETURN
KMF_FindKey(KMF_HANDLE_T handle, KMF_FINDKEY_PARAMS *params,
	KMF_KEY_HANDLE *keys, uint32_t *numkeys)
{
	KMF_ATTRIBUTE attlist[16]; /* Max 16 attributes used here */
	int i = 0;

	if (params == NULL || numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &params->kstype, sizeof (params->kstype));
	i++;

	if (keys) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_KEY_HANDLE_ATTR, keys, sizeof (KMF_KEY_HANDLE));
		i++;
	}

	kmf_set_attr_at_index(attlist, i,
	    KMF_COUNT_ATTR, numkeys, sizeof (uint32_t));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYALG_ATTR, &params->keytype, sizeof (params->keytype));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYCLASS_ATTR, &params->keyclass, sizeof (params->keyclass));
	i++;

	kmf_set_attr_at_index(attlist, i,
	    KMF_ENCODE_FORMAT_ATTR, &params->format, sizeof (params->format));
	i++;

	if (params->findLabel != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_KEYLABEL_ATTR, params->findLabel,
		    strlen(params->findLabel));
		i++;
	}

	if (params->idstr != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_IDSTR_ATTR, params->idstr,
		    strlen(params->idstr));
		i++;
	}

	if (params->cred.credlen > 0) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_CREDENTIAL_ATTR, &params->cred,
		    sizeof (KMF_CREDENTIAL));
		i++;
	}

	if (params->kstype == KMF_KEYSTORE_NSS) {
		if (params->nssparms.slotlabel != NULL) {
			kmf_set_attr_at_index(attlist, i,
			    KMF_TOKEN_LABEL_ATTR,
			    params->nssparms.slotlabel,
			    strlen(params->nssparms.slotlabel));
			i++;
		}
	} else if (params->kstype == KMF_KEYSTORE_OPENSSL) {
		if (params->sslparms.dirpath != NULL) {
			kmf_set_attr_at_index(attlist, i,
			    KMF_DIRPATH_ATTR,
			    params->sslparms.dirpath,
			    strlen(params->sslparms.dirpath));
			i++;
		}
		if (params->sslparms.keyfile != NULL) {
			kmf_set_attr_at_index(attlist, i,
			    KMF_KEY_FILENAME_ATTR,
			    params->sslparms.keyfile,
			    strlen(params->sslparms.keyfile));
			i++;
		}
		kmf_set_attr_at_index(attlist, i,
		    KMF_ENCODE_FORMAT_ATTR,
		    &params->sslparms.format,
		    sizeof (params->sslparms.format));
		i++;
	} else if (params->kstype == KMF_KEYSTORE_PK11TOKEN) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_TOKEN_BOOL_ATTR,
		    &params->pkcs11parms.token,
		    sizeof (params->pkcs11parms.token));
		i++;
		kmf_set_attr_at_index(attlist, i,
		    KMF_PRIVATE_BOOL_ATTR,
		    &params->pkcs11parms.private,
		    sizeof (params->pkcs11parms.private));
		i++;
	}
	return (kmf_find_key(handle, i, attlist));
}

KMF_RETURN
KMF_CreateKeypair(KMF_HANDLE_T handle,
	KMF_CREATEKEYPAIR_PARAMS *params,
	KMF_KEY_HANDLE *privKey,
	KMF_KEY_HANDLE *pubKey)
{
	KMF_ATTRIBUTE attlist[12]; /* max 12 attrs used here */
	int i = 0;

	if (handle == NULL || params == NULL ||
	    privKey == NULL || pubKey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(privKey, 0, sizeof (KMF_KEY_HANDLE));
	(void) memset(pubKey, 0, sizeof (KMF_KEY_HANDLE));

	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYSTORE_TYPE_ATTR, &params->kstype, sizeof (params->kstype));
	i++;
	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYALG_ATTR, &params->keytype, sizeof (params->keytype));
	i++;
	kmf_set_attr_at_index(attlist, i,
	    KMF_KEYLENGTH_ATTR, &params->keylength, sizeof (params->keylength));
	i++;
	if (params->keylabel != NULL) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_KEYLABEL_ATTR, params->keylabel,
		    strlen(params->keylabel));
		i++;
	}
	if (params->cred.credlen > 0) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_CREDENTIAL_ATTR, &params->cred,
		    sizeof (KMF_CREDENTIAL));
		i++;
	}

	if (params->rsa_exponent.len > 0) {
		kmf_set_attr_at_index(attlist, i,
		    KMF_RSAEXP_ATTR, &params->cred,
		    sizeof (KMF_BIGINT));
		i++;
	}
	kmf_set_attr_at_index(attlist, i, KMF_PRIVKEY_HANDLE_ATTR, privKey,
	    sizeof (KMF_KEY_HANDLE));
	i++;
	kmf_set_attr_at_index(attlist, i, KMF_PUBKEY_HANDLE_ATTR, pubKey,
	    sizeof (KMF_KEY_HANDLE));
	i++;

	if (params->kstype == KMF_KEYSTORE_NSS) {
		if (params->nssparms.slotlabel != NULL) {
			kmf_set_attr_at_index(attlist, i,
			    KMF_TOKEN_LABEL_ATTR,
			    params->nssparms.slotlabel,
			    strlen(params->nssparms.slotlabel));
			i++;
		}
	} else if (params->kstype == KMF_KEYSTORE_OPENSSL) {
		if (params->sslparms.dirpath != NULL) {
			kmf_set_attr_at_index(attlist, i,
			    KMF_DIRPATH_ATTR,
			    params->sslparms.dirpath,
			    strlen(params->sslparms.dirpath));
			i++;
		}
		if (params->sslparms.keyfile != NULL) {
			kmf_set_attr_at_index(attlist, i,
			    KMF_KEY_FILENAME_ATTR,
			    params->sslparms.keyfile,
			    strlen(params->sslparms.keyfile));
			i++;
		}
		kmf_set_attr_at_index(attlist, i,
		    KMF_ENCODE_FORMAT_ATTR,
		    &params->sslparms.format,
		    sizeof (params->sslparms.format));
		i++;
	}
	return (kmf_create_keypair(handle, i, attlist));
}
