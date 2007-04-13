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

/*
 *
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
	KMF_RETURN ret;
	KMF_PLUGIN *plugin;
	KMF_ALGORITHM_INDEX AlgId;
	KMF_DATA	signature = {0, NULL};

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (key == NULL || AlgOID == NULL ||
		tobesigned == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * The plugin must be based on the key since private keys
	 * cannot be extracted.
	 */
	plugin = FindPlugin(handle, key->kstype);
	if (plugin != NULL && plugin->funclist->SignData != NULL) {
		ret = plugin->funclist->SignData(handle, key,
		    AlgOID, tobesigned, output);
		if (ret != KMF_OK)
			goto cleanup;

		AlgId = X509_AlgorithmOidToAlgId(AlgOID);

		/*
		 * For DSA, NSS returns an encoded signature. Decode the
		 * signature as DSA signature should be 40-byte long.
		 */
		if ((AlgId == KMF_ALGID_SHA1WithDSA) &&
		    (plugin->type == KMF_KEYSTORE_NSS)) {
			ret = DerDecodeDSASignature(output, &signature);
			if (ret != KMF_OK) {
				goto cleanup;
			} else {
				output->Length = signature.Length;
				(void) memcpy(output->Data, signature.Data,
				    signature.Length);
			}
		} else if (AlgId == KMF_ALGID_NONE) {
			ret = KMF_ERR_BAD_ALGORITHM;
		}
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

cleanup:
	if (signature.Data)
		free(signature.Data);
	return (ret);
}

/*
 *
 * Name: KMF_VerifyDataWithKey
 *
 * Description:
 *   This function verifies the signature of a block of data
 * using the input public key
 *
 * Parameters:
 *	handle(input) - opaque handle for KMF session
 *	KMFKey(input) - holds public key information for verification
 *	sigAlg(input) - algorithm to verify
 *	indata(input) - pointer to the block of data whose signature
 *		is to be verified
 *	insig(input) - pointer to the signature to be verified
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_VerifyDataWithKey(KMF_HANDLE_T handle,
		KMF_KEY_HANDLE *KMFKey,
		KMF_ALGORITHM_INDEX sigAlg,
		KMF_DATA *indata,
		KMF_DATA *insig)
{
	KMF_RETURN err;
	KMF_DATA	derkey = {0, NULL};
	KMF_PLUGIN	*plugin;

	CLEAR_ERROR(handle, err);
	if (err != KMF_OK)
		return (err);

	if (KMFKey == NULL ||
		indata == NULL || insig == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, KMFKey->kstype);

	/* Retrieve public key data from keystore */
	if (plugin != NULL && plugin->funclist->EncodePubkeyData != NULL) {
		err = plugin->funclist->EncodePubkeyData(handle,
		    KMFKey, &derkey);
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	err = VerifyDataWithKey(handle, &derkey, sigAlg, indata, insig);

	if (derkey.Data != NULL)
		free(derkey.Data);

	return (err);
}

KMF_RETURN
KMF_CreateKeypair(KMF_HANDLE_T handle,
	KMF_CREATEKEYPAIR_PARAMS *params,
	KMF_KEY_HANDLE *privKey,
	KMF_KEY_HANDLE *pubKey)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (params == NULL ||
		privKey == NULL || pubKey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(privKey, 0, sizeof (KMF_KEY_HANDLE));
	(void) memset(pubKey, 0, sizeof (KMF_KEY_HANDLE));
	plugin = FindPlugin(handle, params->kstype);

	if (plugin != NULL && plugin->funclist->CreateKeypair != NULL) {
		return (plugin->funclist->CreateKeypair(handle, params,
			privKey, pubKey));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
KMF_DeleteKeyFromKeystore(KMF_HANDLE_T handle, KMF_DELETEKEY_PARAMS *params,
	KMF_KEY_HANDLE *key)
{
	KMF_RETURN rv = KMF_OK;
	KMF_PLUGIN *plugin;

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (key == NULL || params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, params->kstype);
	if (plugin != NULL && plugin->funclist->DeleteKey != NULL) {
		rv = plugin->funclist->DeleteKey(handle, params, key, TRUE);
	} else {
		rv = KMF_ERR_PLUGIN_NOTFOUND;
	}

	if (rv == KMF_OK) {
		if (key->keylabel != NULL)
			free(key->keylabel);

		if (key->israw && key->keyp != NULL) {
			if (key->keyclass ==  KMF_ASYM_PUB ||
			    key->keyclass == KMF_ASYM_PRI) {
				KMF_FreeRawKey(key->keyp);
				free(key->keyp);
			} else if (key->keyclass == KMF_SYMMETRIC) {
				KMF_FreeRawSymKey(key->keyp);
			}
			/* Else we don't know how to free the memory. */
		}

		(void) memset(key, 0, sizeof (KMF_KEY_HANDLE));
	}

	return (rv);
}

KMF_RETURN
KMF_SignCertRecord(KMF_HANDLE_T handle, KMF_KEY_HANDLE *kmfprikey,
	KMF_X509_CERTIFICATE *CertData, KMF_DATA *signedCert)
{
	KMF_RETURN ret;
	KMF_DATA unsignedCert;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (kmfprikey == NULL ||
		CertData == NULL || signedCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = KMF_EncodeCertRecord(CertData, &unsignedCert);
	if (ret == KMF_OK)
		ret = KMF_SignCertWithKey(handle, &unsignedCert, kmfprikey,
			signedCert);

	KMF_FreeData(&unsignedCert);
	return (ret);
}

KMF_RETURN
KMF_FindKey(KMF_HANDLE_T handle, KMF_FINDKEY_PARAMS *parms,
	KMF_KEY_HANDLE *keys, uint32_t *numkeys)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (parms == NULL || numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (keys != NULL && *numkeys == 0)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, parms->kstype);

	if (plugin != NULL && plugin->funclist->FindKey != NULL) {
		return (plugin->funclist->FindKey(handle, parms,
			keys, numkeys));
	}

	return (KMF_ERR_PLUGIN_NOTFOUND);
}

KMF_RETURN
KMF_StorePrivateKey(KMF_HANDLE_T handle, KMF_STOREKEY_PARAMS *params,
	KMF_RAW_KEY_DATA *rawkey)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (params == NULL || rawkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Find the private key from the keystore */
	plugin = FindPlugin(handle, params->kstype);

	if (plugin != NULL && plugin->funclist->StorePrivateKey != NULL) {
		return (plugin->funclist->StorePrivateKey(handle,
		    params, rawkey));
	}
	return (KMF_ERR_PLUGIN_NOTFOUND);
}

KMF_RETURN
KMF_CreateSymKey(KMF_HANDLE_T handle, KMF_CREATESYMKEY_PARAMS *params,
	KMF_KEY_HANDLE *symkey)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (params == NULL ||
		symkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, params->kstype);
	if (plugin != NULL && plugin->funclist->CreateSymKey != NULL) {
		return (plugin->funclist->CreateSymKey(handle, params,
		    symkey));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
KMF_GetSymKeyValue(KMF_HANDLE_T handle, KMF_KEY_HANDLE *symkey,
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
