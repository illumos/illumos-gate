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
#include <link.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <ber_der.h>
#include <kmfapiP.h>
#include <pem_encode.h>
#include <libgen.h>
#include <cryptoutil.h>

#define	CERTFILE_TEMPNAME	"/tmp/user.certXXXXXX"
#define	CRLFILE_TEMPNAME	"/tmp/crlXXXXXX"
#define	X509_FORMAT_VERSION 2

static KMF_RETURN
sign_cert(KMF_HANDLE_T, const KMF_DATA *, KMF_KEY_HANDLE *,
    KMF_OID *, KMF_DATA *);

static KMF_RETURN
verify_cert_with_key(KMF_HANDLE_T, KMF_DATA *, const KMF_DATA *);

static KMF_RETURN
verify_cert_with_cert(KMF_HANDLE_T, const KMF_DATA *, const KMF_DATA *);

static KMF_RETURN
get_keyalg_from_cert(KMF_DATA *cert, KMF_KEY_ALG *keyalg)
{
	KMF_RETURN rv;
	KMF_X509_CERTIFICATE *SignerCert = NULL;
	KMF_ALGORITHM_INDEX AlgorithmId;

	rv = DerDecodeSignedCertificate(cert, &SignerCert);

	if (rv != KMF_OK)
		return (rv);

	/* Get the algorithm info from the signer certificate */
	AlgorithmId = x509_algoid_to_algid(
	    &SignerCert->signature.algorithmIdentifier.algorithm);

	switch (AlgorithmId) {
		case KMF_ALGID_MD5WithRSA:
		case KMF_ALGID_SHA1WithRSA:
		case KMF_ALGID_SHA256WithRSA:
		case KMF_ALGID_SHA384WithRSA:
		case KMF_ALGID_SHA512WithRSA:
			*keyalg = KMF_RSA;
			break;
		case KMF_ALGID_SHA1WithDSA:
		case KMF_ALGID_SHA256WithDSA:
			*keyalg = KMF_DSA;
			break;
		case KMF_ALGID_SHA1WithECDSA:
		case KMF_ALGID_SHA256WithECDSA:
		case KMF_ALGID_SHA384WithECDSA:
		case KMF_ALGID_SHA512WithECDSA:
		case KMF_ALGID_ECDSA:
			*keyalg = KMF_ECDSA;
			break;
		default:
			rv = KMF_ERR_BAD_ALGORITHM;
	}

	kmf_free_signed_cert(SignerCert);
	free(SignerCert);
	return (rv);
}

/*
 * Name: kmf_find_prikey_by_cert
 *
 * Description:
 *   This function finds the corresponding private key in keystore
 *   for a certificate
 */
KMF_RETURN
kmf_find_prikey_by_cert(KMF_HANDLE_T handle, int numattr,
    KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;
	KMF_KEY_ALG keyalg;
	KMF_KEY_HANDLE *key = NULL;
	KMF_DATA *cert = NULL;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)},
	    {KMF_KEY_HANDLE_ATTR, TRUE, sizeof (KMF_KEY_HANDLE),
	    sizeof (KMF_KEY_HANDLE)}
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

	/*
	 * First, get the key algorithm info from the certificate and saves it
	 * in the returned key handle.
	 */
	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	if (cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = get_keyalg_from_cert(cert, &keyalg);
	if (ret != KMF_OK)
		return (ret);

	key = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	if (key == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	key->keyalg = keyalg;

	/* Call the plugin to do the work. */
	ret = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, NULL);
	if (ret != KMF_OK)
		return (ret);

	plugin = FindPlugin(handle, kstype);
	if (plugin == NULL || plugin->funclist->FindPrikeyByCert == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	return (plugin->funclist->FindPrikeyByCert(handle, numattr, attrlist));
}


KMF_RETURN
check_key_usage(void *handle,
	const KMF_DATA *cert,
	const KMF_KU_PURPOSE purpose)
{
	KMF_X509EXT_BASICCONSTRAINTS constraint;
	KMF_BOOL	critical = B_FALSE;
	KMF_X509EXT_KEY_USAGE keyusage;
	KMF_RETURN ret = KMF_OK;

	if (handle == NULL || cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&constraint, 0, sizeof (KMF_X509EXT_BASICCONSTRAINTS));
	(void) memset(&keyusage, 0, sizeof (KMF_X509EXT_KEY_USAGE));

	ret = kmf_get_cert_ku(cert, &keyusage);
	if (ret != KMF_OK)
		/*
		 * If absent or error, the cert is assumed to be invalid
		 * for all key usage checking.
		 */
		return (ret);

	switch (purpose) {
	case KMF_KU_SIGN_CERT:
		/*
		 * RFC 3280:
		 * The keyCertSign bit is asserted when the subject
		 * public key is used for verifying a signature on
		 * public key certificates.  If the keyCertSign bit
		 * is asserted, then the cA bit in the basic constraints
		 * extension (section 4.2.1.10) MUST also be asserted.
		 * The basic constraints extension MUST appear as a
		 * critical extension in all CA certificates that
		 * contain public keys used to validate digital
		 * signatures on certificates.
		 */
		if (keyusage.KeyUsageBits & KMF_keyCertSign) {
			ret = kmf_get_cert_basic_constraint(cert,
			    &critical, &constraint);

			if (ret != KMF_OK)
				return (ret);

			if ((!critical) || (!constraint.cA))
				return (KMF_ERR_KEYUSAGE);
		} else {
			return (KMF_ERR_KEYUSAGE);
		}
		break;
	case KMF_KU_SIGN_DATA:
		/*
		 * RFC 3280:
		 * The digitalSignature bit is asserted when the subject
		 * public key is used with a digital signature mechanism
		 * to support security services other than certificate
		 * signing(bit 5), or CRL signing(bit 6).
		 */
		if (!(keyusage.KeyUsageBits & KMF_digitalSignature))
			return (KMF_ERR_KEYUSAGE);
		break;
	case KMF_KU_ENCRYPT_DATA:
		/*
		 * RFC 3280:
		 * The dataEncipherment bit is asserted when the subject
		 * public key is used for enciphering user data, other than
		 * cryptographic keys.
		 */
		if (!(keyusage.KeyUsageBits & KMF_dataEncipherment))
			return (KMF_ERR_KEYUSAGE);
		break;
	default:
		return (KMF_ERR_BAD_PARAMETER);
	}

	return (KMF_OK);
}

KMF_RETURN
kmf_find_cert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_COUNT_ATTR, FALSE, sizeof (uint32_t), sizeof (uint32_t)}
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
	if (plugin == NULL || plugin->funclist->FindCert == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	return (plugin->funclist->FindCert(handle, numattr, attrlist));
}

#define	NODATA(d) (d.Data == NULL || d.Length == NULL)

KMF_RETURN
kmf_encode_cert_record(KMF_X509_CERTIFICATE *CertData, KMF_DATA *encodedCert)
{
	KMF_RETURN ret;
	KMF_X509_TBS_CERT *tbs_cert;

	if (CertData == NULL || encodedCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Validate that all required fields are present.
	 */
	tbs_cert = &(CertData->certificate);
	if (NODATA(tbs_cert->version) ||
	    NODATA(tbs_cert->signature.algorithm) ||
	    NODATA(tbs_cert->subjectPublicKeyInfo.subjectPublicKey) ||
	    tbs_cert->serialNumber.val == NULL ||
	    tbs_cert->serialNumber.len == 0 ||
	    tbs_cert->subject.numberOfRDNs == 0 ||
	    tbs_cert->issuer.numberOfRDNs == 0) {
		return (KMF_ERR_INCOMPLETE_TBS_CERT);
	}

	encodedCert->Length = 0;
	encodedCert->Data = NULL;

	/* Pack the new certificate */
	ret = DerEncodeSignedCertificate(CertData, encodedCert);

	return (ret);
}

/*
 * This function is used to setup the attribute list before calling
 * kmf_find_prikey_by_cert().  This function is used by
 *	kmf_decrypt_with_cert
 *	kmf_sign_cert
 *	kmf_sign_data
 *
 * The attribute list in these callers contain all the attributes
 * needed by kmf_find_prikey_by_cert(), except the
 * KMF_KEY_HANDLE attribute and the KMF_CERT_DATA_ATTR attribute.
 * These 2 attributes need to be added or reset.
 *
 * The caller should free the new_attrlist after use it.
 */
static KMF_RETURN
setup_findprikey_attrlist(KMF_ATTRIBUTE *src_attrlist, int src_num,
    KMF_ATTRIBUTE **new_attrlist, int *new_num, KMF_KEY_HANDLE *key,
    KMF_DATA *cert)
{
	KMF_ATTRIBUTE *attrlist = NULL;
	int cur_num = src_num;
	int index;
	int i;

	if (src_attrlist == NULL || new_num == NULL || key == NULL ||
	    cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Create a new attribute list with 2 more elements */
	attrlist = (KMF_ATTRIBUTE *) malloc(
	    (src_num + 2) * sizeof (KMF_ATTRIBUTE));
	if (attrlist == NULL)
		return (KMF_ERR_MEMORY);

	/* Copy the src_attrlist to the new list */
	for (i = 0; i < src_num; i++) {
		attrlist[i].type = src_attrlist[i].type;
		attrlist[i].pValue = src_attrlist[i].pValue;
		attrlist[i].valueLen = src_attrlist[i].valueLen;
	}

	/* Add or reset the key handle attribute */
	index = kmf_find_attr(KMF_KEY_HANDLE_ATTR, attrlist, cur_num);
	if (index == -1) {
		/* not found; add it */
		kmf_set_attr_at_index(attrlist, cur_num,
		    KMF_KEY_HANDLE_ATTR, key, sizeof (KMF_KEY_HANDLE));
		cur_num++;
	} else {
		/* found; just reset it */
		kmf_set_attr_at_index(attrlist, index,
		    KMF_KEY_HANDLE_ATTR, key, sizeof (KMF_KEY_HANDLE));
	}

	/* add or reset the cert data attribute */
	index = kmf_find_attr(KMF_CERT_DATA_ATTR, attrlist, cur_num);
	if (index == -1) {
		/* not found; add it */
		kmf_set_attr_at_index(attrlist, cur_num,
		    KMF_CERT_DATA_ATTR, cert, sizeof (KMF_DATA));
		cur_num++;
	} else {
		/* found; just reset it */
		kmf_set_attr_at_index(attrlist, index,
		    KMF_CERT_DATA_ATTR, cert, sizeof (KMF_DATA));
	}

	*new_attrlist = attrlist;
	*new_num = cur_num;
	return (KMF_OK);
}

/*
 * Determine a default signature type to use based on
 * the key algorithm.
 */
static KMF_OID *
get_default_signoid(KMF_KEY_HANDLE *key)
{
	KMF_OID *oid;

	switch (key->keyalg) {
		case KMF_RSA:
			oid = (KMF_OID *)&KMFOID_SHA256WithRSA;
			break;
		case KMF_DSA:
			/* NSS doesnt support DSA-SHA2 hashes yet */
			if (key->kstype == KMF_KEYSTORE_NSS)
				oid = (KMF_OID *)&KMFOID_X9CM_DSAWithSHA1;
			else
				oid = (KMF_OID *)&KMFOID_SHA256WithDSA;
			break;
		case KMF_ECDSA:
			oid = (KMF_OID *)&KMFOID_SHA256WithECDSA;
			break;
		default:
			oid = NULL;
			break;
	}
	return (oid);
}

/*
 * This is to check to see if a certificate being signed has
 * the keyCertSign KeyUsage bit set, and if so, make sure the
 * "BasicConstraints" extension is also set accordingly.
 */
static KMF_RETURN
check_for_basic_constraint(KMF_DATA *cert)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509EXT_KEY_USAGE  keyUsage;
	KMF_X509_CERTIFICATE *x509cert = NULL;

	rv = kmf_get_cert_ku((const KMF_DATA *)cert, &keyUsage);
	if (rv == KMF_OK) {
		KMF_X509EXT_BASICCONSTRAINTS basicConstraint;
		KMF_BOOL critical;
		/* If keyCertSign is set, look for basicConstraints */
		if (keyUsage.KeyUsageBits & KMF_keyCertSign)
			rv = kmf_get_cert_basic_constraint(
			    (const KMF_DATA *)cert,
			    &critical, &basicConstraint);

		/*
		 * If we got KMF_OK (or an error), then return
		 * because the extension is already present.  We
		 * only want to continue with this function if
		 * the extension is NOT found.
		 */
		if (rv != KMF_ERR_EXTENSION_NOT_FOUND)
			return (rv);

		/*
		 * Don't limit the pathLen (for now).
		 * This should probably be a policy setting in the
		 * future.
		 */
		basicConstraint.cA = TRUE;
		basicConstraint.pathLenConstraintPresent = FALSE;

		/*
		 * Decode the DER cert data into the internal
		 * X.509 structure we need to set extensions.
		 */
		rv = DerDecodeSignedCertificate(cert, &x509cert);
		if (rv != KMF_OK)
			return (rv);
		/*
		 * Add the missing basic constraint.
		 */
		rv = kmf_set_cert_basic_constraint(x509cert,
		    TRUE, &basicConstraint);
		if (rv != KMF_OK) {
			kmf_free_signed_cert(x509cert);
			free(x509cert);
			return (rv);
		}
		/* Free the old cert data record */
		kmf_free_data(cert);

		/* Re-encode the cert with the extension */
		rv = kmf_encode_cert_record(x509cert, cert);

		/* cleanup */
		kmf_free_signed_cert(x509cert);
		free(x509cert);
	}
	if (rv == KMF_ERR_EXTENSION_NOT_FOUND)
		rv = KMF_OK;

	return (rv);
}

/*
 * Name: kmf_sign_cert
 *
 * Description:
 *   This function signs a certificate using the signer cert and
 *   returns a signed and DER-encoded certificate.
 *
 * The following types of certificate data can be submitted to be signed:
 *	KMF_TBS_CERT_DATA_ATTR - a KMF_DATA ptr is provided in the attrlist
 *		and is signed directly.
 *	KMF_X509_CERTIFICATE_ATTR - a KMF_X509_CERTIFICATE record is provided
 *		in the attribute list.  This is converted to raw KMF_DATA
 *		prior to signing.
 *
 * The key for the signing operation can be provided as a KMF_KEY_HANDLE_ATTR
 * or the caller may choose to provide a KMF_SIGNER_CERT_ATTR (KMF_DATA *).
 * If the latter, this function will then attempt to find the private key
 * associated with the certificate.  The private key must be stored in
 * the same keystore as the signer certificate.
 */
KMF_RETURN
kmf_sign_cert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret;
	int new_numattr = numattr + 1;
	KMF_ATTRIBUTE *new_attrlist = NULL;
	KMF_DATA *signer_cert = NULL;
	KMF_DATA *tbs_cert = NULL;  /* to be signed cert */
	KMF_DATA *signed_cert = NULL;
	KMF_DATA unsignedCert = { 0, NULL };
	KMF_KEY_HANDLE sign_key, *sign_key_ptr;
	int freethekey = 0;
	KMF_POLICY_RECORD *policy;
	KMF_OID *oid = NULL;
	KMF_X509_CERTIFICATE *x509cert;
	KMF_X509_TBS_CERT *decodedTbsCert = NULL;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)}
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

	/* Get the signer cert and check its keyUsage */
	signer_cert = kmf_get_attr_ptr(KMF_SIGNER_CERT_DATA_ATTR, attrlist,
	    numattr);
	sign_key_ptr = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist,
	    numattr);
	/*
	 * Only accept 1 or the other, not both.
	 */
	if (signer_cert == NULL && sign_key_ptr == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	if (signer_cert != NULL && sign_key_ptr != NULL)
		return (KMF_ERR_BAD_PARAMETER);

	oid = kmf_get_attr_ptr(KMF_OID_ATTR, attrlist, numattr);
	if (oid == NULL) {
		/*
		 * If the signature OID was not given, check
		 * for an algorithm index identifier instead.
		 */
		KMF_ALGORITHM_INDEX AlgId;
		ret = kmf_get_attr(KMF_ALGORITHM_INDEX_ATTR, attrlist, numattr,
		    &AlgId, NULL);
		if (ret == KMF_OK)
			oid = x509_algid_to_algoid(AlgId);
	}

	if (signer_cert != NULL) {
		policy = handle->policy;
		ret = check_key_usage(handle, signer_cert, KMF_KU_SIGN_CERT);
		if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
			ret = KMF_OK;
		if (ret != KMF_OK)
			return (ret);

		/*
		 * Find the private key from the signer certificate by calling
		 * kmf_find_prikey_by_cert().
		 */
		ret = setup_findprikey_attrlist(attrlist, numattr,
		    &new_attrlist, &new_numattr, &sign_key, signer_cert);
		if (ret != KMF_OK)
			goto out;

		ret = kmf_find_prikey_by_cert(handle, new_numattr,
		    new_attrlist);
		if (ret != KMF_OK) {
			goto out;
		}
		sign_key_ptr = &sign_key;
		freethekey = 1;
	}

	tbs_cert = kmf_get_attr_ptr(KMF_TBS_CERT_DATA_ATTR, attrlist,
	    numattr);
	if (tbs_cert == NULL) {
		x509cert = kmf_get_attr_ptr(KMF_X509_CERTIFICATE_ATTR, attrlist,
		    numattr);
		if (x509cert == NULL) {
			ret = KMF_ERR_BAD_PARAMETER;
			goto out;
		}

		ret = kmf_encode_cert_record(x509cert, &unsignedCert);
		if (ret != KMF_OK)
			goto out;

		tbs_cert = &unsignedCert;
	}
	/*
	 * Check for the keyCertSign bit in the KeyUsage extn.  If it is set,
	 * then the basicConstraints must also be present and be
	 * marked critical.
	 */
	ret = check_for_basic_constraint(tbs_cert);
	if (ret)
		goto out;

	if (oid == NULL) {
		/*
		 * If OID is not known yet, use a default value
		 * based on the signers key type.
		 */
		oid = get_default_signoid(sign_key_ptr);
	}

	signed_cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist,
	    numattr);
	if (signed_cert == NULL) {
		ret = KMF_ERR_BAD_PARAMETER;
		goto out;
	}

	ret = sign_cert(handle, tbs_cert, sign_key_ptr, oid, signed_cert);
out:
	if (new_attrlist)
		(void) free(new_attrlist);

	/* If we had to find the key, free it here. */
	if (freethekey)
		kmf_free_kmf_key(handle, &sign_key);

	kmf_free_data(&unsignedCert);
	if (decodedTbsCert != NULL) {
		kmf_free_tbs_cert(decodedTbsCert);
		free(decodedTbsCert);
	}
	return (ret);
}

/*
 * Name: kmf_sign_data
 *
 * Description:
 *   This function signs a block of data using the signer cert and
 *   returns the the signature in output
 */
KMF_RETURN
kmf_sign_data(KMF_HANDLE_T handle, int numattr,
    KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_ATTRIBUTE *new_attrlist = NULL;
	int new_numattr = numattr;
	KMF_DATA *signer_cert = NULL;
	KMF_DATA *tbs_data = NULL;  /* to be signed data */
	KMF_DATA *output = NULL;
	KMF_KEY_HANDLE sign_key, *sign_key_ptr;
	KMF_ALGORITHM_INDEX AlgId = KMF_ALGID_NONE;
	KMF_DATA	signature = { 0, NULL };
	KMF_OID *oid;
	KMF_POLICY_RECORD *policy;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)},
	    {KMF_OUT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)}
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

	/* Get the signer cert and check its keyUsage. */
	signer_cert = kmf_get_attr_ptr(KMF_SIGNER_CERT_DATA_ATTR, attrlist,
	    numattr);
	sign_key_ptr = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist,
	    numattr);

	if (signer_cert == NULL && sign_key_ptr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * If a signer cert was given, use it to find the private key
	 * to use for signing the data.
	 */
	if (signer_cert != NULL) {
		ret = check_key_usage(handle, signer_cert, KMF_KU_SIGN_DATA);

		/*
		 * Signing generic data does not require the
		 * KeyUsage extension.
		 */
		policy = handle->policy;
		if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
			ret = KMF_OK;
		if (ret != KMF_OK)
			return (ret);

		/*
		 * Find the private key from the signer certificate.
		 */
		ret = setup_findprikey_attrlist(attrlist, numattr,
		    &new_attrlist, &new_numattr, &sign_key, signer_cert);
		if (ret != KMF_OK) {
			goto cleanup;
		}

		ret = kmf_find_prikey_by_cert(handle, new_numattr,
		    new_attrlist);
		if (ret != KMF_OK) {
			goto cleanup;
		}
		sign_key_ptr = &sign_key;
	}

	/* Get the tbs_data and signed_data attributes now */
	tbs_data = kmf_get_attr_ptr(KMF_DATA_ATTR, attrlist, numattr);
	if (tbs_data == NULL) {
		ret = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	output = kmf_get_attr_ptr(KMF_OUT_DATA_ATTR, attrlist, numattr);
	if (output == NULL) {
		ret = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	/*
	 * Get the algorithm index attribute and its oid. If this attribute
	 * is not provided, then we use a default value.
	 */
	oid = kmf_get_attr_ptr(KMF_OID_ATTR, attrlist, numattr);
	if (oid == NULL) {
		ret = kmf_get_attr(KMF_ALGORITHM_INDEX_ATTR, attrlist,
		    numattr, &AlgId, NULL);
		/* If there was no Algorithm ID, use default based on key */
		if (ret != KMF_OK)
			oid = get_default_signoid(sign_key_ptr);
		else
			oid = x509_algid_to_algoid(AlgId);
	}
	if (sign_key_ptr->keyp == NULL) {
		ret = KMF_ERR_BAD_PARAMETER;
		goto cleanup;
	}

	/* Now call the plugin function to sign it */
	plugin = FindPlugin(handle, sign_key_ptr->kstype);
	if (plugin == NULL || plugin->funclist->SignData == NULL) {
		ret = KMF_ERR_PLUGIN_NOTFOUND;
		goto cleanup;
	}

	ret = plugin->funclist->SignData(handle, sign_key_ptr, oid, tbs_data,
	    output);
	if (ret != KMF_OK)
		goto cleanup;

	/*
	 * For DSA, NSS returns an encoded signature. Decode the
	 * signature and expect a 40-byte DSA signature.
	 */
	if (plugin->type == KMF_KEYSTORE_NSS &&
	    (IsEqualOid(oid, (KMF_OID *)&KMFOID_X9CM_DSAWithSHA1) ||
	    IsEqualOid(oid, (KMF_OID *)&KMFOID_SHA256WithDSA))) {
		ret = DerDecodeDSASignature(output, &signature);
		if (ret != KMF_OK)
			goto cleanup;

		output->Length = signature.Length;
		(void) memcpy(output->Data, signature.Data, signature.Length);
	}

cleanup:
	if (new_attrlist != NULL)
		free(new_attrlist);

	if (signature.Data)
		free(signature.Data);

	if (signer_cert != NULL && sign_key_ptr != NULL)
		kmf_free_kmf_key(handle, sign_key_ptr);

	return (ret);
}

/*
 * kmf_verify_data
 *
 * This routine will try to verify a block of data using
 * either a public key or a certificate as the source
 * of the verification (the key).
 *
 * The caller may provider either a KMF_KEY_HANDLE_ATTR or
 * a KMF_SIGNER_CERT_DATA_ATTR (with a KMF_DATA record) to
 * use for the key to the verification step.  If a certificate
 * is used and that certificate has the KeyUsage extension,
 * the SIGN-DATA bit must be set.  Also, if a certificate
 * is used, the verification will be done in a specific
 * keystore mechanism.
 *
 * If a KMF_KEY_HANDLE is given in the attribute list, the
 * verification will occur in the framework itself using
 * PKCS#11 C_Verify functions.
 */
KMF_RETURN
kmf_verify_data(KMF_HANDLE_T handle,
	int	num_args,
	KMF_ATTRIBUTE	*attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	uint32_t len;
	KMF_DATA	derkey = { 0, NULL };
	KMF_KEY_HANDLE *KMFKey;
	KMF_ALGORITHM_INDEX sigAlg = KMF_ALGID_NONE;
	KMF_DATA *indata;
	KMF_DATA *insig;
	KMF_DATA *signer_cert;
	KMF_X509_SPKI spki;
	KMF_POLICY_RECORD *policy;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
		{KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
		{KMF_DATA_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)},
		{KMF_IN_SIGN_ATTR, FALSE, sizeof (KMF_DATA),
			sizeof (KMF_DATA)}
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

	KMFKey = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, num_args);
	signer_cert = kmf_get_attr_ptr(KMF_SIGNER_CERT_DATA_ATTR, attrlist,
	    num_args);
	if (KMFKey == NULL && signer_cert == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	len = sizeof (sigAlg);
	ret = kmf_get_attr(KMF_ALGORITHM_INDEX_ATTR, attrlist, num_args,
	    &sigAlg, &len);

	/* We only need the algorithm index if we don't have a signer cert. */
	if (ret != KMF_OK && signer_cert == NULL)
		return (ret);

	indata = kmf_get_attr_ptr(KMF_DATA_ATTR, attrlist, num_args);
	if (indata == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	insig = kmf_get_attr_ptr(KMF_IN_SIGN_ATTR, attrlist, num_args);
	if (insig == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* If the caller passed a signer cert instead of a key use it. */
	if (signer_cert != NULL) {
		KMF_X509_CERTIFICATE *SignerCert = NULL;

		policy = handle->policy;
		ret = check_key_usage(handle, signer_cert, KMF_KU_SIGN_DATA);
		if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
			ret = KMF_OK;
		if (ret != KMF_OK)
			return (ret);

		/* Decode the signer cert so we can get the SPKI data */
		ret = DerDecodeSignedCertificate(signer_cert, &SignerCert);
		if (ret != KMF_OK)
			return (ret);

		/* If no algorithm specified, use the certs signature alg */
		if (sigAlg == KMF_ALGID_NONE)
			sigAlg = x509_algoid_to_algid(CERT_ALG_OID(SignerCert));

		if (sigAlg == KMF_ALGID_NONE) {
			kmf_free_signed_cert(SignerCert);
			free(SignerCert);
			return (KMF_ERR_BAD_ALGORITHM);
		}

		/*
		 * Verify the data locally (i.e. using PKCS#11).
		 * The verify operation uses a public key and does not
		 * require access to a specific keystore. Save time
		 * (and code) by just using the frameworks implementation
		 * of the verify operation using crypto framework
		 * APIs.
		 */
		ret = PKCS_VerifyData(handle, sigAlg,
		    &SignerCert->certificate.subjectPublicKeyInfo,
		    indata, insig);

		kmf_free_signed_cert(SignerCert);
		free(SignerCert);
	} else {
		/* Retrieve public key data from keystore */
		plugin = FindPlugin(handle, kstype);
		if (plugin != NULL &&
		    plugin->funclist->EncodePubkeyData != NULL) {
			ret = plugin->funclist->EncodePubkeyData(handle,
			    KMFKey, &derkey);
		} else {
			return (KMF_ERR_PLUGIN_NOTFOUND);
		}

		ret = DerDecodeSPKI(&derkey, &spki);
		if (ret == KMF_OK)
			ret = PKCS_VerifyData(handle, sigAlg, &spki,
			    indata, insig);

		if (derkey.Data != NULL)
			free(derkey.Data);

		kmf_free_algoid(&spki.algorithm);
		kmf_free_data(&spki.subjectPublicKey);
	}

	return (ret);
}
/*
 * Name: kmf_verify_cert
 *
 * Description:
 *   This function verifies that the a certificate was signed
 * using a specific private key and that the certificate has not
 * been altered since it was signed using that private key
 * The public key used for verification may be given in the
 * attribute list as a KMF_KEY_HANDLE or the caller may give
 * just the signing certificate (as KMF_SIGNER_CERT_DATA_ATTR)
 * from which the public key needed for verification can be
 * derived.
 *
 * Parameters:
 *	handle(input) - opaque handle for KMF session
 *	numattr  - number of attributes in the list
 *	attrlist - KMF_ATTRIBUTES
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.  The value KMF_OK indicates success. All other
 * values represent an error condition.
 */
KMF_RETURN
kmf_verify_cert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN	ret;
	KMF_DATA	derkey = { 0, NULL };
	KMF_PLUGIN	*plugin;
	KMF_KEY_HANDLE *KMFKey;
	KMF_DATA *CertToBeVerified;
	KMF_DATA *SignerCert;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)}
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, numattr, attrlist);
	if (ret != KMF_OK)
		return (ret);

	KMFKey = kmf_get_attr_ptr(KMF_KEY_HANDLE_ATTR, attrlist, numattr);
	SignerCert = kmf_get_attr_ptr(KMF_SIGNER_CERT_DATA_ATTR, attrlist,
	    numattr);

	/*
	 * Caller must provide at least a key handle or a cert to use
	 * as the "key" for verification.
	 */
	if (KMFKey == NULL && SignerCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CertToBeVerified = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist,
	    numattr);
	if (CertToBeVerified == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (SignerCert != NULL) {
		ret = verify_cert_with_cert(handle, CertToBeVerified,
		    SignerCert);
	} else {
		/*
		 * The keystore must extract the pubkey data because
		 * the framework doesn't have access to the raw key bytes
		 * that are needed to construct the DER encoded public
		 * key information needed for the verify operation.
		 */
		plugin = FindPlugin(handle, KMFKey->kstype);
		if (plugin != NULL && plugin->funclist->EncodePubkeyData !=
		    NULL) {
			ret = plugin->funclist->EncodePubkeyData(handle,
			    KMFKey, &derkey);
		} else {
			return (KMF_ERR_PLUGIN_NOTFOUND);
		}

		if (ret == KMF_OK && derkey.Length > 0) {
			ret = verify_cert_with_key(handle, &derkey,
			    CertToBeVerified);

			if (derkey.Data != NULL)
				free(derkey.Data);
		}
	}

	return (ret);
}

/*
 * Name: kmf_encrypt
 *
 * Description:
 *   Uses the public key from the cert to encrypt the plaintext
 *   into the ciphertext.
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   cert(input) - pointer to a DER encoded certificate for encryption
 *		by using its public key
 *   plaintext(input) - pointer to the plaintext to be encrypted
 *   ciphertext(output) - pointer to the ciphertext contains
 *		encrypted data
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
kmf_encrypt(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret;
	KMF_X509_CERTIFICATE *x509cert = NULL;
	KMF_X509_SPKI *pubkey;
	KMF_OID *alg;
	KMF_ALGORITHM_INDEX algid;
	KMF_DATA *cert;
	KMF_DATA *plaintext;
	KMF_DATA *ciphertext;
	KMF_POLICY_RECORD *policy;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
		sizeof (KMF_DATA)},
	    {KMF_PLAINTEXT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
		sizeof (KMF_DATA)},
	    {KMF_CIPHERTEXT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
		sizeof (KMF_DATA)}
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	ret = test_attributes(num_req_attrs, required_attrs,
	    0, NULL, numattr, attrlist);
	if (ret != KMF_OK)
		return (ret);

	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist,
	    numattr);
	plaintext = kmf_get_attr_ptr(KMF_PLAINTEXT_DATA_ATTR, attrlist,
	    numattr);
	ciphertext = kmf_get_attr_ptr(KMF_CIPHERTEXT_DATA_ATTR, attrlist,
	    numattr);

	if (cert == NULL || plaintext == NULL || ciphertext == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of the certificate */
	policy = handle->policy;
	ret = check_key_usage(handle, cert, KMF_KU_ENCRYPT_DATA);
	if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
		ret = KMF_OK;
	if (ret != KMF_OK)
		return (ret);

	/* Decode the cert so we can get the SPKI data */
	if ((ret = DerDecodeSignedCertificate(cert, &x509cert)) != KMF_OK)
		return (ret);

	/* Get the public key info from the certificate */
	pubkey = &x509cert->certificate.subjectPublicKeyInfo;

	/* Use the algorithm in SPKI to encrypt data */
	alg = &pubkey->algorithm.algorithm;

	algid = x509_algoid_to_algid(alg);

	/* [EC]DSA does not support encrypt */
	if (algid == KMF_ALGID_DSA ||
	    algid == KMF_ALGID_SHA1WithDSA ||
	    algid == KMF_ALGID_SHA256WithDSA ||
	    algid == KMF_ALGID_SHA1WithECDSA ||
	    algid == KMF_ALGID_SHA256WithECDSA ||
	    algid == KMF_ALGID_SHA384WithECDSA ||
	    algid == KMF_ALGID_SHA512WithECDSA ||
	    algid == KMF_ALGID_NONE) {
		kmf_free_signed_cert(x509cert);
		free(x509cert);
		return (KMF_ERR_BAD_ALGORITHM);
	}

	/*
	 * Encrypt using the crypto framework (not the KMF plugin mechanism).
	 */
	ret = PKCS_EncryptData(handle, algid, pubkey, plaintext, ciphertext);

	kmf_free_signed_cert(x509cert);
	free(x509cert);

	return (ret);
}

/*
 * Name: kmf_decrypt
 *
 * Description:
 *   Uses the private key associated with the cert to decrypt
 *   the ciphertext into the plaintext.
 */
KMF_RETURN
kmf_decrypt(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret;
	KMF_X509_CERTIFICATE *x509cert = NULL;
	KMF_X509_SPKI *spki_ptr;
	KMF_PLUGIN *plugin;
	KMF_ALGORITHM_INDEX AlgorithmId;
	KMF_ATTRIBUTE *new_attrlist = NULL;
	int new_numattr;
	KMF_DATA *cert = NULL;
	KMF_DATA *ciphertext = NULL;
	KMF_DATA *plaintext = NULL;
	KMF_KEY_HANDLE prikey;
	KMF_POLICY_RECORD *policy;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)},
	    {KMF_PLAINTEXT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
		sizeof (KMF_DATA)},
	    {KMF_CIPHERTEXT_DATA_ATTR, FALSE, sizeof (KMF_DATA),
		sizeof (KMF_DATA)},
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


	/* Get the cert and check its keyUsage */
	cert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist,
	    numattr);
	if (cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of the certificate */
	policy = handle->policy;
	ret = check_key_usage(handle, cert, KMF_KU_ENCRYPT_DATA);
	if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
		ret = KMF_OK;
	if (ret != KMF_OK)
		return (ret);

	/* Get the ciphertext and plaintext attributes */
	ciphertext = kmf_get_attr_ptr(KMF_CIPHERTEXT_DATA_ATTR, attrlist,
	    numattr);
	if (ciphertext == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plaintext = kmf_get_attr_ptr(KMF_PLAINTEXT_DATA_ATTR, attrlist,
	    numattr);
	if (plaintext == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Retrieve the private key from the keystore based on
	 * the certificate.
	 */
	ret = setup_findprikey_attrlist(attrlist, numattr, &new_attrlist,
	    &new_numattr, &prikey, cert);
	if (ret != KMF_OK)
		goto cleanup;

	ret = kmf_find_prikey_by_cert(handle, new_numattr, new_attrlist);
	if (ret != KMF_OK)
		goto cleanup;

	/* Decode the cert so we can get the alogorithm */
	ret = DerDecodeSignedCertificate(cert, &x509cert);
	if (ret != KMF_OK)
		goto cleanup;

	spki_ptr = &x509cert->certificate.subjectPublicKeyInfo;
	AlgorithmId = x509_algoid_to_algid((KMF_OID *)
	    &spki_ptr->algorithm.algorithm);

	/* [EC]DSA does not support decrypt */
	if (AlgorithmId == KMF_ALGID_DSA ||
	    AlgorithmId == KMF_ALGID_ECDSA) {
		ret = KMF_ERR_BAD_ALGORITHM;
		goto cleanup;
	}

	plugin = FindPlugin(handle, prikey.kstype);

	if (plugin != NULL && plugin->funclist->DecryptData != NULL) {
		ret = plugin->funclist->DecryptData(handle,
		    &prikey, &spki_ptr->algorithm.algorithm,
		    ciphertext, plaintext);
	} else {
		ret = KMF_ERR_PLUGIN_NOTFOUND;
	}

cleanup:
	if (new_attrlist != NULL)
		free(new_attrlist);

	kmf_free_kmf_key(handle, &prikey);
	kmf_free_signed_cert(x509cert);
	free(x509cert);

	return (ret);
}

KMF_RETURN
kmf_store_cert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)},
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
	if (plugin == NULL || plugin->funclist->StoreCert == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	return (plugin->funclist->StoreCert(handle, numattr, attrlist));
}

KMF_RETURN
kmf_import_cert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_CERT_FILENAME_ATTR, TRUE, 1, 0},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);

	ret = test_attributes(num_req_attrs, required_attrs, 0, NULL,
	    numattr, attrlist);
	if (ret != KMF_OK)
		return (ret);

	ret = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, NULL);
	if (ret != KMF_OK)
		return (ret);

	plugin = FindPlugin(handle, kstype);
	if (plugin == NULL || plugin->funclist->ImportCert == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	return (plugin->funclist->ImportCert(handle, numattr, attrlist));
}

KMF_RETURN
kmf_delete_cert_from_keystore(KMF_HANDLE_T handle, int numattr,
    KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;
	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)}
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
	if (plugin == NULL || plugin->funclist->DeleteCert == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	return (plugin->funclist->DeleteCert(handle, numattr, attrlist));
}


/*
 * This function gets the CRL URI entries from the certificate's Distribution
 * points extension, and downloads the CRL file.  The function also returns
 * the URI string and the format of the CRL file.   The caller should free
 * the space allocated for the returned URI string.
 */
static KMF_RETURN
cert_get_crl(KMF_HANDLE_T handle, const KMF_DATA *cert, char *proxy,
    char *filename, char **retn_uri, KMF_ENCODE_FORMAT *format)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509EXT_CRLDISTPOINTS crl_dps;
	boolean_t done = B_FALSE;
	char uri[1024];
	char *proxyname = NULL;
	char *proxy_port_s = NULL;
	int proxy_port = 0;
	int i, j;
	char *path = NULL;

	if (handle == NULL || cert == NULL || filename == NULL ||
	    retn_uri == NULL || format == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* Get the proxy info */
	if (proxy != NULL) {
		proxyname = strtok(proxy, ":");
		proxy_port_s = strtok(NULL, "\0");
		if (proxy_port_s != NULL) {
			proxy_port = strtol(proxy_port_s, NULL, 0);
		} else {
			proxy_port = 8080; /* default */
		}
	}

	/*
	 * Get the CRL URI from the certificate's CRL Distribution
	 * Points extension and download the CRL file.  There maybe more than
	 * one CRL URI entries in the DP extension, so we will continue
	 * the process until a CRL file is sucessfully downloaded or we
	 * are running out the CRL URI's.
	 */
	ret = kmf_get_cert_crl_dist_pts((const KMF_DATA *)cert,
	    &crl_dps);
	if (ret != KMF_OK)
		goto out;

	for (i = 0; i < crl_dps.number; i++) {
		KMF_CRL_DIST_POINT *dp = &(crl_dps.dplist[i]);
		KMF_GENERALNAMES *fullname = &(dp->name.full_name);
		KMF_DATA *data;

		if (done)
			break;
		for (j = 0; j < fullname->number; j++) {
			data = &(fullname->namelist[j].name);
			(void) memcpy(uri, data->Data, data->Length);
			uri[data->Length] = '\0';
			ret = kmf_download_crl(handle, uri, proxyname,
			    proxy_port, 30, filename, format);
			if (ret == KMF_OK) {
				done = B_TRUE;
				path = malloc(data->Length + 1);
				if (path == NULL) {
					ret = KMF_ERR_MEMORY;
					goto out;
				}
				(void) strncpy(path, uri, data->Length);
				*retn_uri = path;
				break;
			}
		}
	}

out:
	kmf_free_crl_dist_pts(&crl_dps);
	return (ret);
}

static KMF_RETURN
check_crl_validity(KMF_HANDLE_T handle, KMF_KEYSTORE_TYPE kstype,
	char *crlfilename, KMF_DATA *issuer_cert)
{
	KMF_RETURN ret = KMF_OK;
	KMF_POLICY_RECORD *policy;

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;

	/*
	 * NSS CRL is not file based, and its signature
	 * has been verified during CRL import.
	 * We only check CRL validity for file-based CRLs,
	 * NSS handles these checks internally.
	 */
	if (kstype == KMF_KEYSTORE_NSS)
		return (KMF_OK);

	/*
	 * Check the CRL signature if needed.
	 */
	if (!policy->validation_info.crl_info.ignore_crl_sign) {
		ret = kmf_verify_crl_file(handle, crlfilename,
		    issuer_cert);
		if (ret != KMF_OK)
			return (ret);
	}
	/*
	 * Check the CRL validity if needed.
	 */
	if (!policy->validation_info.crl_info.ignore_crl_date) {
		ret = kmf_check_crl_date(handle, crlfilename);
		if (ret != KMF_OK)
			return (ret);
	}

	return (ret);
}

static KMF_RETURN
cert_crl_check(KMF_HANDLE_T handle,  KMF_KEYSTORE_TYPE *kstype,
	KMF_DATA *user_cert, KMF_DATA *issuer_cert)
{
	KMF_POLICY_RECORD *policy;
	KMF_RETURN ret = KMF_OK;
	KMF_ATTRIBUTE attrlist[16];
	int numattr = 0;
	int fd;
	boolean_t crlchk;
	char user_certfile[MAXPATHLEN];
	char crlfile_tmp[MAXPATHLEN];
	char *basefilename = NULL;
	char *dir = NULL;
	char *crlfilename = NULL;
	char *proxy = NULL;
	char *uri = NULL;
	KMF_ENCODE_FORMAT format;

	if (handle == NULL || kstype == NULL || user_cert == NULL ||
	    issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (!is_valid_keystore_type(*kstype))
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;

	/*
	 * If the get-crl-uri policy is TRUE, then download the CRL
	 * file first.   The newly downloaded file will be stored in the
	 * NSS internal database for NSS keystore, and stored in a file for
	 * the File-based CRL plugins (OpenSSL and PKCS11).
	 *
	 * For file-based plugins, if the get-crl-uri policy is FALSE,
	 * then the caller should provide a CRL file in the policy.
	 * Also, after this step is done, the "crlfilename" variable should
	 * contain the proper CRL file to be used for the rest of CRL
	 * validation process.
	 */
	basefilename = policy->validation_info.crl_info.basefilename;
	dir = policy->validation_info.crl_info.directory;
	if (policy->validation_info.crl_info.get_crl_uri) {
		/*
		 * Check to see if we already have this CRL.
		 */
		if (basefilename == NULL)
			basefilename = basename(uri);

		crlfilename = get_fullpath(dir == NULL ? "./" : dir,
		    basefilename);
		if (crlfilename == NULL) {
			ret = KMF_ERR_BAD_CRLFILE;
			goto cleanup;
		}

		/*
		 * If this file already exists and is valid, we don't need to
		 * download a new one.
		 */
		if ((fd = open(crlfilename, O_RDONLY)) != -1) {
			(void) close(fd);
			if ((ret = check_crl_validity(handle, *kstype,
			    crlfilename, issuer_cert)) == KMF_OK) {
				goto checkcrl;
			}
		}

		/*
		 * Create a temporary file to hold the new CRL file initially.
		 */
		(void) strlcpy(crlfile_tmp, CRLFILE_TEMPNAME,
		    sizeof (crlfile_tmp));
		if (mkstemp(crlfile_tmp) == -1) {
			ret = KMF_ERR_INTERNAL;
			goto cleanup;
		}

		/*
		 * Get the URI entry from the certificate's CRL distribution
		 * points extension and download the CRL file.
		 */
		proxy = policy->validation_info.crl_info.proxy;
		ret = cert_get_crl(handle, user_cert, proxy, crlfile_tmp,
		    &uri, &format);
		if (ret != KMF_OK) {
			(void) unlink(crlfile_tmp);
			goto cleanup;
		}
		/*
		 * If we just downloaded one, make sure it is OK.
		 */
		if ((ret = check_crl_validity(handle, *kstype, crlfile_tmp,
		    issuer_cert)) != KMF_OK)
			return (ret);

		/* Cache the CRL file. */
		if (*kstype == KMF_KEYSTORE_NSS) {
			/*
			 * For NSS keystore, import this CRL file into th
			 * internal database.
			 */
			numattr = 0;
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_KEYSTORE_TYPE_ATTR, kstype, sizeof (kstype));
			numattr++;

			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CRL_FILENAME_ATTR, crlfile_tmp,
			    strlen(crlfile_tmp));
			numattr++;

			crlchk = B_FALSE;
			kmf_set_attr_at_index(attrlist, numattr,
			    KMF_CRL_CHECK_ATTR,	&crlchk, sizeof (boolean_t));
			numattr++;

			ret = kmf_import_crl(handle, numattr, attrlist);
			(void) unlink(crlfile_tmp);
			if (ret != KMF_OK)
				goto cleanup;
		} else {
			if (rename(crlfile_tmp, crlfilename) == -1) {
				(void) unlink(crlfile_tmp);
				ret = KMF_ERR_WRITE_FILE;
				goto cleanup;
			}
		}
	} else {
		/*
		 * If the get_crl_uri policy is FALSE, for File-based CRL
		 * plugins, get the input CRL file from the policy.
		 */
		if (*kstype != KMF_KEYSTORE_NSS) {
			if (basefilename == NULL) {
				ret = KMF_ERR_BAD_PARAMETER;
				goto cleanup;
			}

			crlfilename = get_fullpath(dir == NULL ? "./" : dir,
			    basefilename);
			if (crlfilename == NULL) {
				ret = KMF_ERR_BAD_CRLFILE;
				goto cleanup;
			}
			/*
			 * Make sure this CRL is still valid.
			 */
			if ((ret = check_crl_validity(handle, *kstype,
			    crlfilename, issuer_cert)) != KMF_OK)
				return (ret);
			}
	}

checkcrl:
	/*
	 * Check the CRL revocation for the certificate.
	 */
	numattr = 0;

	kmf_set_attr_at_index(attrlist, numattr, KMF_KEYSTORE_TYPE_ATTR,
	    kstype, sizeof (kstype));
	numattr++;

	switch (*kstype) {
	case KMF_KEYSTORE_NSS:
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_CERT_DATA_ATTR, user_cert, sizeof (KMF_DATA));
		numattr++;
		break;
	case KMF_KEYSTORE_PK11TOKEN:
	case KMF_KEYSTORE_OPENSSL:
		/*
		 * Create temporary file to hold the user certificate.
		 */
		(void) strlcpy(user_certfile, CERTFILE_TEMPNAME,
		    sizeof (user_certfile));
		if (mkstemp(user_certfile) == -1) {
			ret = KMF_ERR_INTERNAL;
			goto cleanup;
		}

		ret = kmf_create_cert_file(user_cert, KMF_FORMAT_ASN1,
		    user_certfile);
		if (ret != KMF_OK)  {
			goto cleanup;
		}

		kmf_set_attr_at_index(attrlist,  numattr,
		    KMF_CERT_FILENAME_ATTR,
		    user_certfile, strlen(user_certfile));
		numattr++;

		kmf_set_attr_at_index(attrlist,  numattr,
		    KMF_CRL_FILENAME_ATTR,
		    crlfilename, strlen(crlfilename));
		numattr++;
		break;
	default:
		ret = KMF_ERR_PLUGIN_NOTFOUND;
		goto cleanup;
	}

	ret = kmf_find_cert_in_crl(handle, numattr, attrlist);
	if (ret == KMF_ERR_NOT_REVOKED)  {
		ret = KMF_OK;
	}

cleanup:
	(void) unlink(user_certfile);

	if (crlfilename != NULL)
		free(crlfilename);

	if (uri != NULL)
		free(uri);

	return (ret);
}

static KMF_RETURN
cert_ocsp_check(KMF_HANDLE_T handle, KMF_KEYSTORE_TYPE *kstype,
	KMF_DATA *user_cert, KMF_DATA *issuer_cert, KMF_DATA *response,
	char *slotlabel, char *dirpath)
{
	KMF_RETURN ret = KMF_OK;
	KMF_POLICY_RECORD *policy;
	KMF_DATA *new_response = NULL;
	boolean_t ignore_response_sign = B_FALSE;
	uint32_t ltime = 0;
	KMF_DATA *signer_cert = NULL;
	KMF_BIGINT sernum = { NULL, 0 };
	int response_status;
	int reason;
	int cert_status;
	KMF_ATTRIBUTE attrlist[32];
	int numattr;

	if (handle == NULL || kstype == NULL || user_cert == NULL ||
	    issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;

	/*
	 * Get the response lifetime from policy.
	 */
	if (policy->VAL_OCSP_BASIC.response_lifetime != NULL &&
	    (str2lifetime(policy->VAL_OCSP_BASIC.response_lifetime, &ltime)
	    < 0))
		return (KMF_ERR_OCSP_RESPONSE_LIFETIME);

	/*
	 * Get the ignore_response_sign policy.
	 *
	 * If ignore_response_sign is FALSE, we need to verify the response.
	 * Find the OCSP Responder certificate if it is specified in the OCSP
	 * policy.
	 */
	ignore_response_sign = policy->VAL_OCSP_BASIC.ignore_response_sign;

	if (ignore_response_sign == B_FALSE &&
	    policy->VAL_OCSP.has_resp_cert == B_TRUE) {
		char *signer_name;
		KMF_X509_DER_CERT signer_retrcert;
		uchar_t *bytes = NULL;
		size_t bytelen;
		uint32_t num = 0;
		KMF_ATTRIBUTE fc_attrlist[16];
		int fc_numattr = 0;
		char *dir = "./";

		if (policy->VAL_OCSP_RESP_CERT.name == NULL ||
		    policy->VAL_OCSP_RESP_CERT.serial == NULL)
			return (KMF_ERR_POLICY_NOT_FOUND);

		signer_cert = malloc(sizeof (KMF_DATA));
		if (signer_cert == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}
		(void) memset(signer_cert, 0, sizeof (KMF_DATA));

		signer_name = policy->VAL_OCSP_RESP_CERT.name;
		ret = kmf_hexstr_to_bytes(
		    (uchar_t *)policy->VAL_OCSP_RESP_CERT.serial,
		    &bytes, &bytelen);
		if (ret != KMF_OK || bytes == NULL) {
			ret = KMF_ERR_OCSP_POLICY;
			goto out;
		}
		sernum.val = bytes;
		sernum.len = bytelen;

		kmf_set_attr_at_index(fc_attrlist, fc_numattr,
		    KMF_KEYSTORE_TYPE_ATTR, kstype,
		    sizeof (KMF_KEYSTORE_TYPE));
		fc_numattr++;

		kmf_set_attr_at_index(fc_attrlist, fc_numattr,
		    KMF_SUBJECT_NAME_ATTR, signer_name, strlen(signer_name));
		fc_numattr++;

		kmf_set_attr_at_index(fc_attrlist, fc_numattr, KMF_BIGINT_ATTR,
		    &sernum, sizeof (KMF_BIGINT));
		fc_numattr++;

		if (*kstype == KMF_KEYSTORE_NSS && slotlabel != NULL) {
			kmf_set_attr_at_index(fc_attrlist, fc_numattr,
			    KMF_TOKEN_LABEL_ATTR, slotlabel,
			    strlen(slotlabel));
			fc_numattr++;
		}

		if (*kstype == KMF_KEYSTORE_OPENSSL) {
			if (dirpath == NULL) {
				kmf_set_attr_at_index(fc_attrlist, fc_numattr,
				    KMF_DIRPATH_ATTR, dir, strlen(dir));
				fc_numattr++;
			} else {
				kmf_set_attr_at_index(fc_attrlist, fc_numattr,
				    KMF_DIRPATH_ATTR, dirpath,
				    strlen(dirpath));
				fc_numattr++;
			}
		}

		num = 0;
		kmf_set_attr_at_index(fc_attrlist, fc_numattr,
		    KMF_COUNT_ATTR, &num, sizeof (uint32_t));
		fc_numattr++;

		ret = kmf_find_cert(handle, fc_numattr, fc_attrlist);
		if (ret != KMF_OK || num != 1) {
			if (num == 0)
				ret = KMF_ERR_CERT_NOT_FOUND;
			if (num > 0)
				ret = KMF_ERR_CERT_MULTIPLE_FOUND;
			goto out;
		}

		(void) memset(&signer_retrcert, 0, sizeof (KMF_X509_DER_CERT));
		kmf_set_attr_at_index(fc_attrlist, fc_numattr,
		    KMF_X509_DER_CERT_ATTR, &signer_retrcert,
		    sizeof (KMF_X509_DER_CERT));
		fc_numattr++;

		ret = kmf_find_cert(handle, fc_numattr, fc_attrlist);
		if (ret == KMF_OK) {
			signer_cert->Length =
			    signer_retrcert.certificate.Length;
			signer_cert->Data = signer_retrcert.certificate.Data;
		} else {
			goto out;
		}
	}

	/*
	 * If the caller provides an OCSP response, we will use it directly.
	 * Otherwise, we will try to fetch an OCSP response for the given
	 * certificate now.
	 */
	if (response == NULL) {
		new_response = (KMF_DATA *) malloc(sizeof (KMF_DATA));
		if (new_response == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}
		new_response->Data = NULL;
		new_response->Length = 0;

		ret = kmf_get_ocsp_for_cert(handle, user_cert, issuer_cert,
		    new_response);
		if (ret != KMF_OK)
			goto out;
	}

	/*
	 * Process the OCSP response and retrieve the certificate status.
	 */
	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr, KMF_ISSUER_CERT_DATA_ATTR,
	    issuer_cert, sizeof (KMF_DATA));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_USER_CERT_DATA_ATTR,
	    user_cert, sizeof (KMF_DATA));
	numattr++;

	if (signer_cert != NULL) {
		kmf_set_attr_at_index(attrlist, numattr,
		    KMF_SIGNER_CERT_DATA_ATTR, user_cert, sizeof (KMF_DATA));
		numattr++;
	}

	kmf_set_attr_at_index(attrlist, numattr, KMF_OCSP_RESPONSE_DATA_ATTR,
	    response == NULL ? new_response : response, sizeof (KMF_DATA));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr, KMF_RESPONSE_LIFETIME_ATTR,
	    &ltime, sizeof (uint32_t));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_IGNORE_RESPONSE_SIGN_ATTR, &ignore_response_sign,
	    sizeof (boolean_t));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OCSP_RESPONSE_STATUS_ATTR, &response_status, sizeof (int));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OCSP_RESPONSE_REASON_ATTR, &reason, sizeof (int));
	numattr++;

	kmf_set_attr_at_index(attrlist, numattr,
	    KMF_OCSP_RESPONSE_CERT_STATUS_ATTR, &cert_status, sizeof (int));
	numattr++;

	ret = kmf_get_ocsp_status_for_cert(handle, numattr, attrlist);
	if (ret == KMF_OK) {
		switch (cert_status) {
		case OCSP_GOOD:
			break;
		case OCSP_UNKNOWN:
			ret = KMF_ERR_OCSP_UNKNOWN_CERT;
			break;
		case OCSP_REVOKED:
			ret = KMF_ERR_OCSP_REVOKED;
			break;
		}
	}

out:
	if (new_response) {
		kmf_free_data(new_response);
		free(new_response);
	}

	if (signer_cert) {
		kmf_free_data(signer_cert);
		free(signer_cert);
	}

	if (sernum.val != NULL)
		free(sernum.val);

	return (ret);
}

static KMF_RETURN
cert_ku_check(KMF_HANDLE_T handle, KMF_DATA *cert)
{
	KMF_POLICY_RECORD *policy;
	KMF_X509EXT_KEY_USAGE keyusage;
	KMF_RETURN ret = KMF_OK;
	KMF_X509EXT_BASICCONSTRAINTS constraint;
	KMF_BOOL	critical = B_FALSE;

	if (handle == NULL || cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;
	(void) memset(&keyusage, 0, sizeof (keyusage));
	ret = kmf_get_cert_ku(cert, &keyusage);

	if (ret == KMF_ERR_EXTENSION_NOT_FOUND) {
		if (policy->ku_bits) {
			/* keyusage is not set in cert but is set in policy */
			return (KMF_ERR_KEYUSAGE);
		} else {
			/* no keyusage set in both cert and policy */
			return (KMF_OK);
		}
	}

	if (ret != KMF_OK) {
		/* real error */
		return (ret);
	}

	/*
	 * If KeyCertSign is set, then constraints.cA must be TRUE and
	 * marked critical.
	 */
	if ((keyusage.KeyUsageBits & KMF_keyCertSign)) {
		(void) memset(&constraint, 0, sizeof (constraint));
		ret = kmf_get_cert_basic_constraint(cert,
		    &critical, &constraint);

		if (ret != KMF_OK) {
			/* real error */
			return (ret);
		}
		if (!constraint.cA || !critical)
			return (KMF_ERR_KEYUSAGE);
	}

	/*
	 * Rule: if the KU bit is set in policy, the corresponding KU bit
	 * must be set in the certificate (but not vice versa).
	 */
	if ((policy->ku_bits & keyusage.KeyUsageBits) == policy->ku_bits) {
		return (KMF_OK);
	} else {
		return (KMF_ERR_KEYUSAGE);
	}

}

static KMF_RETURN
cert_eku_check(KMF_HANDLE_T handle, KMF_DATA *cert)
{
	KMF_POLICY_RECORD *policy;
	KMF_RETURN ret = KMF_OK;
	KMF_X509EXT_EKU eku;
	uint16_t cert_eku = 0, policy_eku = 0;
	int i;

	if (handle == NULL || cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	policy = handle->policy;

	/*
	 * If the policy does not have any EKU, then there is
	 * nothing further to check.
	 */
	if (policy->eku_set.eku_count == 0)
		return (KMF_OK);

	ret = kmf_get_cert_eku(cert, &eku);
	if ((ret != KMF_ERR_EXTENSION_NOT_FOUND) && (ret != KMF_OK)) {
		/* real error */
		return (ret);
	}

	if (ret == KMF_ERR_EXTENSION_NOT_FOUND) {
		cert_eku = 0;
	} else {
		/*
		 * Build the EKU bitmap based on the certificate
		 */
		for (i = 0; i < eku.nEKUs; i++) {
			if (IsEqualOid(&eku.keyPurposeIdList[i],
			    (KMF_OID *)&KMFOID_PKIX_KP_ServerAuth)) {
				cert_eku |= KMF_EKU_SERVERAUTH;
			} else if (IsEqualOid(&eku.keyPurposeIdList[i],
			    (KMF_OID *)&KMFOID_PKIX_KP_ClientAuth)) {
				cert_eku |= KMF_EKU_CLIENTAUTH;
			} else if (IsEqualOid(&eku.keyPurposeIdList[i],
			    (KMF_OID *)&KMFOID_PKIX_KP_CodeSigning)) {
				cert_eku |= KMF_EKU_CODESIGNING;
			} else if (IsEqualOid(&eku.keyPurposeIdList[i],
			    (KMF_OID *)&KMFOID_PKIX_KP_EmailProtection)) {
				cert_eku |= KMF_EKU_EMAIL;
			} else if (IsEqualOid(&eku.keyPurposeIdList[i],
			    (KMF_OID *)&KMFOID_PKIX_KP_TimeStamping)) {
				cert_eku |= KMF_EKU_TIMESTAMP;
			} else if (IsEqualOid(&eku.keyPurposeIdList[i],
			    (KMF_OID *)&KMFOID_PKIX_KP_OCSPSigning)) {
				cert_eku |= KMF_EKU_OCSPSIGNING;
			} else if (!policy->ignore_unknown_ekus) {
				return (KMF_ERR_KEYUSAGE);
			}
		} /* for */
	}


	/*
	 * Build the EKU bitmap based on the policy
	 */
	for (i = 0; i < policy->eku_set.eku_count; i++) {
		if (IsEqualOid(&policy->eku_set.ekulist[i],
		    (KMF_OID *)&KMFOID_PKIX_KP_ServerAuth)) {
			policy_eku |= KMF_EKU_SERVERAUTH;
		} else if (IsEqualOid(&policy->eku_set.ekulist[i],
		    (KMF_OID *)&KMFOID_PKIX_KP_ClientAuth)) {
			policy_eku |= KMF_EKU_CLIENTAUTH;
		} else if (IsEqualOid(&policy->eku_set.ekulist[i],
		    (KMF_OID *)&KMFOID_PKIX_KP_CodeSigning)) {
			policy_eku |= KMF_EKU_CODESIGNING;
		} else if (IsEqualOid(&policy->eku_set.ekulist[i],
		    (KMF_OID *)&KMFOID_PKIX_KP_EmailProtection)) {
			policy_eku |= KMF_EKU_EMAIL;
		} else if (IsEqualOid(&policy->eku_set.ekulist[i],
		    (KMF_OID *)&KMFOID_PKIX_KP_TimeStamping)) {
			policy_eku |= KMF_EKU_TIMESTAMP;
		} else if (IsEqualOid(&policy->eku_set.ekulist[i],
		    (KMF_OID *)&KMFOID_PKIX_KP_OCSPSigning)) {
			policy_eku |= KMF_EKU_OCSPSIGNING;
		} else if (!policy->ignore_unknown_ekus) {
			return (KMF_ERR_KEYUSAGE);
		}
	} /* for */

	/*
	 * Rule: if the EKU OID is set in policy, the corresponding EKU OID
	 * must be set in the certificate (but not vice versa).
	 */
	if ((policy_eku & cert_eku) == policy_eku) {
		return (KMF_OK);
	} else {
		return (KMF_ERR_KEYUSAGE);
	}
}

static KMF_RETURN
find_issuer_cert(KMF_HANDLE_T handle, KMF_KEYSTORE_TYPE *kstype,
    char *user_issuer, KMF_DATA *issuer_cert,
    char *slotlabel, char *dirpath)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_DER_CERT *certlist = NULL;
	uint32_t i, num = 0;
	time_t t_notbefore;
	time_t t_notafter;
	time_t latest;
	KMF_DATA tmp_cert = { 0, NULL };
	KMF_ATTRIBUTE fc_attrlist[16];
	int fc_numattr = 0;
	char *dir = "./";

	if (handle == NULL || kstype == NULL || user_issuer == NULL ||
	    issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (!is_valid_keystore_type(*kstype))
		return (KMF_ERR_BAD_PARAMETER);

	kmf_set_attr_at_index(fc_attrlist, fc_numattr, KMF_KEYSTORE_TYPE_ATTR,
	    kstype, sizeof (KMF_KEYSTORE_TYPE));
	fc_numattr++;

	kmf_set_attr_at_index(fc_attrlist, fc_numattr, KMF_SUBJECT_NAME_ATTR,
	    user_issuer, strlen(user_issuer));
	fc_numattr++;

	if (*kstype == KMF_KEYSTORE_NSS && slotlabel != NULL) {
		kmf_set_attr_at_index(fc_attrlist, fc_numattr,
		    KMF_TOKEN_LABEL_ATTR, slotlabel, strlen(slotlabel));
		fc_numattr++;
	}

	if (*kstype == KMF_KEYSTORE_OPENSSL) {
		if (dirpath == NULL) {
			kmf_set_attr_at_index(fc_attrlist, fc_numattr,
			    KMF_DIRPATH_ATTR, dir, strlen(dir));
			fc_numattr++;
		} else {
			kmf_set_attr_at_index(fc_attrlist, fc_numattr,
			    KMF_DIRPATH_ATTR, dirpath, strlen(dirpath));
			fc_numattr++;
		}
	}

	num = 0;
	kmf_set_attr_at_index(fc_attrlist, fc_numattr,
	    KMF_COUNT_ATTR, &num, sizeof (uint32_t));
	fc_numattr++;

	ret = kmf_find_cert(handle, fc_numattr, fc_attrlist);

	if (ret == KMF_OK && num > 0) {
		certlist = (KMF_X509_DER_CERT *)malloc(num *
		    sizeof (KMF_X509_DER_CERT));

		if (certlist == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}

		kmf_set_attr_at_index(fc_attrlist, fc_numattr,
		    KMF_X509_DER_CERT_ATTR, certlist,
		    sizeof (KMF_X509_DER_CERT));
		fc_numattr++;

		ret = kmf_find_cert(handle, fc_numattr, fc_attrlist);
		if (ret != KMF_OK) {
			free(certlist);
			certlist = NULL;
			goto out;
		}
	} else {
		goto out;
	}

	if (num == 1) {
		/* only one issuer cert is found */
		tmp_cert.Length = certlist[0].certificate.Length;
		tmp_cert.Data = certlist[0].certificate.Data;
	} else {
		/*
		 * More than one issuer certs are found. We will
		 * pick the latest one.
		 */
		latest = 0;
		for (i = 0; i < num; i++) {
			ret = kmf_get_cert_validity(&certlist[i].certificate,
			    &t_notbefore, &t_notafter);
			if (ret != KMF_OK) {
				ret = KMF_ERR_VALIDITY_PERIOD;
				goto out;
			}

			if (t_notbefore > latest) {
				tmp_cert.Length =
				    certlist[i].certificate.Length;
				tmp_cert.Data =
				    certlist[i].certificate.Data;
				latest = t_notbefore;
			}

		}
	}

	issuer_cert->Length = tmp_cert.Length;
	issuer_cert->Data = malloc(tmp_cert.Length);
	if (issuer_cert->Data == NULL) {
		ret = KMF_ERR_MEMORY;
		goto out;
	}
	(void) memcpy(issuer_cert->Data, tmp_cert.Data,
	    tmp_cert.Length);

out:
	if (certlist != NULL) {
		for (i = 0; i < num; i++)
			kmf_free_kmf_cert(handle, &certlist[i]);
		free(certlist);
	}

	return (ret);

}

static KMF_RETURN
find_ta_cert(KMF_HANDLE_T handle, KMF_KEYSTORE_TYPE *kstype,
	KMF_DATA *ta_cert, KMF_X509_NAME *user_issuerDN,
	char *slotlabel, char *dirpath)
{
	KMF_POLICY_RECORD *policy;
	KMF_RETURN ret = KMF_OK;
	uint32_t num = 0;
	char *ta_name;
	KMF_BIGINT serial = { NULL, 0 };
	uchar_t *bytes = NULL;
	size_t bytelen;
	KMF_X509_DER_CERT ta_retrCert;
	char *ta_subject = NULL;
	KMF_X509_NAME ta_subjectDN;
	KMF_ATTRIBUTE fc_attrlist[16];
	int fc_numattr = 0;
	char *dir = "./";

	if (handle == NULL || kstype == NULL || ta_cert == NULL ||
	    user_issuerDN == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (!is_valid_keystore_type(*kstype))
		return (KMF_ERR_BAD_PARAMETER);

	/* Get the TA name and serial number from the policy */
	policy = handle->policy;
	ta_name = policy->ta_name;

	/*
	 * Use name and serial from policy.
	 */
	ret = kmf_hexstr_to_bytes((uchar_t *)policy->ta_serial,
	    &bytes, &bytelen);
	if (ret != KMF_OK || bytes == NULL) {
		ret = KMF_ERR_TA_POLICY;
		goto out;
	}
	serial.val = bytes;
	serial.len = bytelen;

	/* set up fc_attrlist for kmf_find_cert */
	kmf_set_attr_at_index(fc_attrlist,
	    fc_numattr++, KMF_BIGINT_ATTR,
	    &serial, sizeof (KMF_BIGINT));

	kmf_set_attr_at_index(fc_attrlist,
	    fc_numattr++, KMF_SUBJECT_NAME_ATTR,
	    ta_name, strlen(ta_name));

	kmf_set_attr_at_index(fc_attrlist, fc_numattr++, KMF_KEYSTORE_TYPE_ATTR,
	    kstype, sizeof (KMF_KEYSTORE_TYPE));

	if (*kstype == KMF_KEYSTORE_NSS && slotlabel != NULL) {
		kmf_set_attr_at_index(fc_attrlist, fc_numattr++,
		    KMF_TOKEN_LABEL_ATTR, slotlabel, strlen(slotlabel));
	}

	if (*kstype == KMF_KEYSTORE_OPENSSL) {
		if (dirpath == NULL) {
			kmf_set_attr_at_index(fc_attrlist, fc_numattr++,
			    KMF_DIRPATH_ATTR, dir, strlen(dir));
		} else {
			kmf_set_attr_at_index(fc_attrlist, fc_numattr++,
			    KMF_DIRPATH_ATTR, dirpath, strlen(dirpath));
		}
	}

	num = 0;
	kmf_set_attr_at_index(fc_attrlist, fc_numattr++,
	    KMF_COUNT_ATTR, &num, sizeof (uint32_t));

	ret = kmf_find_cert(handle, fc_numattr, fc_attrlist);
	if (ret != KMF_OK || num != 1)  {
		if (num == 0)
			ret = KMF_ERR_CERT_NOT_FOUND;
		if (num > 1)
			ret = KMF_ERR_CERT_MULTIPLE_FOUND;
		goto out;
	}

	kmf_set_attr_at_index(fc_attrlist, fc_numattr,
	    KMF_X509_DER_CERT_ATTR, &ta_retrCert, sizeof (KMF_X509_DER_CERT));
	fc_numattr++;

	ret = kmf_find_cert(handle, fc_numattr, fc_attrlist);
	if (ret == KMF_OK)  {
		ta_cert->Length = ta_retrCert.certificate.Length;
		ta_cert->Data = malloc(ta_retrCert.certificate.Length);
		if (ta_cert->Data == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}
		(void) memcpy(ta_cert->Data, ta_retrCert.certificate.Data,
		    ta_retrCert.certificate.Length);
	} else {
		goto out;
	}

	/*
	 * The found TA's name must be matching with issuer name in
	 * subscriber's certificate.
	 */
	(void) memset(&ta_subjectDN, 0, sizeof (ta_subjectDN));

	ret = kmf_get_cert_subject_str(handle, ta_cert, &ta_subject);
	if (ret != KMF_OK)
		goto out;

	ret = kmf_dn_parser(ta_subject,  &ta_subjectDN);
	if (ret != KMF_OK)
		goto out;

	if (kmf_compare_rdns(user_issuerDN, &ta_subjectDN) != 0)
		ret = KMF_ERR_CERT_NOT_FOUND;

	kmf_free_dn(&ta_subjectDN);

	/* Make sure the TA cert has the correct extensions */
	if (ret == KMF_OK) {
		ret = check_key_usage(handle, ta_cert, KMF_KU_SIGN_CERT);
		if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
			ret = KMF_OK;
	}
out:
	if (ta_retrCert.certificate.Data)
		kmf_free_kmf_cert(handle, &ta_retrCert);

	if ((ret != KMF_OK))
		kmf_free_data(ta_cert);

	if (ta_subject != NULL)
		free(ta_subject);

	if (serial.val != NULL)
		free(serial.val);

	return (ret);
}

KMF_RETURN
kmf_validate_cert(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE *kstype = NULL;
	KMF_DATA *pcert = NULL;
	int *result = NULL;
	char *slotlabel = NULL;
	char *dirpath = NULL;
	KMF_DATA *ocsp_response = NULL;
	KMF_DATA ta_cert = { 0, NULL };
	KMF_DATA issuer_cert = { 0, NULL };
	char *user_issuer = NULL, *user_subject = NULL;
	KMF_X509_NAME user_issuerDN, user_subjectDN;
	boolean_t	self_signed = B_FALSE;
	KMF_POLICY_RECORD *policy;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_CERT_DATA_ATTR, FALSE, sizeof (KMF_DATA), sizeof (KMF_DATA)},
	    {KMF_VALIDATE_RESULT_ATTR, FALSE, 1, sizeof (int)}
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

	policy = handle->policy;

	/* Get the attribute values */
	kstype = kmf_get_attr_ptr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr);
	pcert = kmf_get_attr_ptr(KMF_CERT_DATA_ATTR, attrlist, numattr);
	result = kmf_get_attr_ptr(KMF_VALIDATE_RESULT_ATTR, attrlist, numattr);
	if (kstype == NULL || pcert == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	slotlabel = kmf_get_attr_ptr(KMF_TOKEN_LABEL_ATTR, attrlist, numattr);
	dirpath = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	ocsp_response = kmf_get_attr_ptr(KMF_OCSP_RESPONSE_DATA_ATTR, attrlist,
	    numattr);

	/* Initialize the returned result */
	*result = KMF_CERT_VALIDATE_OK;

	/*
	 * Get the issuer information from the input certficate first.
	 */
	if ((ret = kmf_get_cert_issuer_str(handle, pcert,
	    &user_issuer)) != KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
	} else if ((ret = kmf_dn_parser(user_issuer,  &user_issuerDN)) !=
	    KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
	}

	/*
	 * Check if the certificate is a self-signed cert.
	 */
	if ((ret = kmf_get_cert_subject_str(handle, pcert,
	    &user_subject)) != KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
	} else if ((ret = kmf_dn_parser(user_subject,  &user_subjectDN)) !=
	    KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
	}

	if ((*result & KMF_CERT_VALIDATE_ERR_USER) == 0 &&
	    (kmf_compare_rdns(&user_issuerDN, &user_subjectDN)) == 0) {
		/*
		 * this is a self-signed cert
		 */
		self_signed = B_TRUE;
	}

	kmf_free_dn(&user_subjectDN);

	/*
	 * Check KeyUsage extension of the subscriber's certificate
	 */
	ret = cert_ku_check(handle, pcert);
	if (ret != KMF_OK)  {
		*result |= KMF_CERT_VALIDATE_ERR_KEYUSAGE;
	}

	/*
	 * Validate Extended KeyUsage extension
	 */
	ret = cert_eku_check(handle, pcert);
	if (ret != KMF_OK)  {
		*result |= KMF_CERT_VALIDATE_ERR_EXT_KEYUSAGE;
	}

	/*
	 * Check the certificate's validity period
	 *
	 * This step is needed when "ignore_date" in policy is set
	 * to false.
	 */
	if (!policy->ignore_date) {
		/*
		 * Validate expiration date
		 */
		ret = kmf_check_cert_date(handle, pcert);
		if (ret != KMF_OK)
			*result |= KMF_CERT_VALIDATE_ERR_TIME;
	}

	/*
	 * When "ignore_trust_anchor" in policy is set to FALSE,
	 * we will try to find the TA cert based on the TA policy
	 * attributes.
	 *
	 * TA's subject name (ta_name) and serial number (ta_serial)
	 * are defined as optional attributes in policy dtd, but they
	 * should exist in policy when "ignore_trust_anchor" is set
	 * to FALSE. The policy verification code has enforced that.
	 *
	 * The serial number may be NULL if the ta_name == "search"
	 * which indicates that KMF should try to locate the issuer
	 * of the subject cert instead of using a specific TA name.
	 */
	if (policy->ignore_trust_anchor) {
		goto check_revocation;
	}

	/*
	 * Verify the signature of subscriber's certificate using
	 * TA certificate.
	 */
	if (self_signed) {
		ret = verify_cert_with_cert(handle, pcert, pcert);
		if (ret != KMF_OK)
			*result |= KMF_CERT_VALIDATE_ERR_SIGNATURE;
	} else if (user_issuer != NULL) {
		if (policy->ta_name != NULL &&
		    strcasecmp(policy->ta_name, "search") == 0) {
			ret = find_issuer_cert(handle, kstype, user_issuer,
			    &issuer_cert, slotlabel, dirpath);
			if (ret != KMF_OK)  {
				*result |= KMF_CERT_VALIDATE_ERR_TA;
			} else {
				ta_cert = issuer_cert; /* used later */
			}
		} else {
			/*
			 * If we didnt find the user_issuer string, we
			 * won't have a "user_issuerDN" either.
			 */
			ret = find_ta_cert(handle, kstype, &ta_cert,
			    &user_issuerDN, slotlabel, dirpath);
		}
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_TA;
		}

		/* Only verify if we got the TA without an error. */
		if ((*result & KMF_CERT_VALIDATE_ERR_TA) == 0) {
			ret = verify_cert_with_cert(handle, pcert,
			    &ta_cert);
			if (ret != KMF_OK)
				*result |= KMF_CERT_VALIDATE_ERR_SIGNATURE;
		}
	} else {
		/* No issuer was found, so we cannot find a trust anchor */
		*result |= KMF_CERT_VALIDATE_ERR_TA;
	}

check_revocation:
	/*
	 * Check certificate revocation
	 */
	if (self_signed) {
		/* skip revocation checking */
		goto out;
	}

	/*
	 * When CRL or OCSP revocation method is set in the policy,
	 * we will try to find the issuer of the subscriber certificate
	 * using the issuer name of the subscriber certificate. The
	 * issuer certificate will be used to do the CRL checking
	 * and OCSP checking.
	 */
	if (!(policy->revocation & KMF_REVOCATION_METHOD_CRL) &&
	    !(policy->revocation & KMF_REVOCATION_METHOD_OCSP)) {
		goto out;
	}

	/*
	 * If we did not find the issuer cert earlier
	 * (when policy->ta_name == "search"), get it here.
	 * We need the issuer cert if the revocation method is
	 * CRL or OCSP.
	 */
	if (issuer_cert.Length == 0 &&
	    policy->revocation & KMF_REVOCATION_METHOD_CRL ||
	    policy->revocation & KMF_REVOCATION_METHOD_OCSP) {
		ret = find_issuer_cert(handle, kstype, user_issuer,
		    &issuer_cert, slotlabel, dirpath);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_ISSUER;
		}
	}

	if (policy->revocation & KMF_REVOCATION_METHOD_CRL &&
	    (*result & KMF_CERT_VALIDATE_ERR_ISSUER) == 0) {
		ret = cert_crl_check(handle, kstype, pcert, &issuer_cert);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_CRL;
		}
	}

	if (policy->revocation & KMF_REVOCATION_METHOD_OCSP &&
	    (*result & KMF_CERT_VALIDATE_ERR_ISSUER) == 0) {
		ret = cert_ocsp_check(handle, kstype, pcert, &issuer_cert,
		    ocsp_response, slotlabel, dirpath);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_OCSP;
		}
	}
out:
	if (user_issuer) {
		kmf_free_dn(&user_issuerDN);
		free(user_issuer);
	}

	if (user_subject)
		free(user_subject);

	/*
	 * If we did not copy ta_cert to issuer_cert, free it.
	 */
	if (issuer_cert.Data &&
	    issuer_cert.Data != ta_cert.Data)
		kmf_free_data(&issuer_cert);

	kmf_free_data(&ta_cert);

	/*
	 * If we got an error flag from any of the checks,
	 * remap the return code to a generic "CERT_VALIDATION"
	 * error so the caller knows to check the individual flags.
	 */
	if (*result != 0)
		ret = KMF_ERR_CERT_VALIDATION;

	return (ret);
}

KMF_RETURN
kmf_create_cert_file(const KMF_DATA *certdata, KMF_ENCODE_FORMAT format,
	char *certfile)
{
	KMF_RETURN rv = KMF_OK;
	int fd = -1;
	KMF_DATA pemdata = { 0, NULL };

	if (certdata == NULL || certfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (format != KMF_FORMAT_PEM && format != KMF_FORMAT_ASN1)
		return (KMF_ERR_BAD_PARAMETER);

	if (format == KMF_FORMAT_PEM) {
		int len;
		rv = kmf_der_to_pem(KMF_CERT,
		    certdata->Data, certdata->Length,
		    &pemdata.Data, &len);
		if (rv != KMF_OK)
			goto cleanup;
		pemdata.Length = (size_t)len;
	}

	if ((fd = open(certfile, O_CREAT | O_RDWR | O_TRUNC, 0644)) == -1) {
		rv = KMF_ERR_OPEN_FILE;
		goto cleanup;
	}

	if (format == KMF_FORMAT_PEM) {
		if (write(fd, pemdata.Data, pemdata.Length) !=
		    pemdata.Length) {
			rv = KMF_ERR_WRITE_FILE;
		}
	} else {
		if (write(fd, certdata->Data, certdata->Length) !=
		    certdata->Length) {
			rv = KMF_ERR_WRITE_FILE;
		}
	}

cleanup:
	if (fd != -1)
		(void) close(fd);

	kmf_free_data(&pemdata);

	return (rv);
}

/*
 * kmf_is_cert_data
 *
 * Determine if a KMF_DATA buffer contains an encoded X.509 certificate.
 *
 * Return:
 *   KMF_OK if it is a certificate
 *   KMF_ERR_ENCODING (or other error) if not.
 */
KMF_RETURN
kmf_is_cert_data(KMF_DATA *data, KMF_ENCODE_FORMAT *fmt)
{
	KMF_RETURN rv = KMF_OK;
	KMF_X509_CERTIFICATE *x509 = NULL;
	KMF_DATA oldpem = { 0, NULL };
	uchar_t *d = NULL;
	int len = 0;

	if (data == NULL || fmt == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = kmf_get_data_format(data, fmt);
	if (rv != KMF_OK)
		return (rv);
	switch (*fmt) {
		case KMF_FORMAT_ASN1:
			rv = DerDecodeSignedCertificate(data, &x509);
			break;
		case KMF_FORMAT_PEM:
			/* Convert to ASN.1 DER first */
			rv = kmf_pem_to_der(data->Data, data->Length,
			    &d, &len);
			if (rv != KMF_OK)
				return (rv);
			oldpem.Data = d;
			oldpem.Length = len;
			rv = DerDecodeSignedCertificate(&oldpem, &x509);
			kmf_free_data(&oldpem);
			break;
		case KMF_FORMAT_PKCS12:
		case KMF_FORMAT_UNDEF:
		default:
			return (KMF_ERR_ENCODING);
	}

	if (x509 != NULL) {
		kmf_free_signed_cert(x509);
		free(x509);
	}
	return (rv);
}

KMF_RETURN
kmf_is_cert_file(KMF_HANDLE_T handle, char *filename,
	KMF_ENCODE_FORMAT *pformat)
{
	KMF_RETURN ret;
	KMF_DATA filedata;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (filename  == NULL || pformat == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = kmf_read_input_file(handle, filename, &filedata);
	if (ret != KMF_OK)
		return (ret);

	ret = kmf_is_cert_data(&filedata, pformat);
	if (ret == KMF_ERR_BAD_CERT_FORMAT)
		ret = KMF_ERR_BAD_CERTFILE;

	kmf_free_data(&filedata);
	return (ret);
}

/*
 * This function checks the validity period of a der-encoded certificate.
 */
KMF_RETURN
kmf_check_cert_date(KMF_HANDLE_T handle, const KMF_DATA *cert)
{
	KMF_RETURN rv;
	struct tm *gmt;
	time_t t_now;
	time_t t_notbefore;
	time_t t_notafter;
	KMF_POLICY_RECORD *policy;
	uint32_t adj;

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (cert == NULL || cert->Data == NULL || cert->Length == 0)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;
	rv = kmf_get_cert_validity(cert, &t_notbefore, &t_notafter);
	if (rv != KMF_OK)
		return (rv);

	/*
	 * Get the current time. The time returned from time() is local which
	 * cannot be used directly. It must be converted to UTC/GMT first.
	 */
	t_now = time(NULL);
	gmt = gmtime(&t_now);
	t_now = mktime(gmt);

	/*
	 * Adjust the validity time
	 */
	if (policy->validity_adjusttime != NULL) {
		if (str2lifetime(policy->validity_adjusttime, &adj) < 0)
			return (KMF_ERR_VALIDITY_PERIOD);
	} else {
		adj = 0;
	}

	t_notafter += adj;
	t_notbefore -= adj;

	if (t_now <= t_notafter && t_now >= t_notbefore) {
		rv = KMF_OK;
	} else {
		rv = KMF_ERR_VALIDITY_PERIOD;
	}

	return (rv);
}

KMF_RETURN
kmf_export_pk12(KMF_HANDLE_T handle, int numattr, KMF_ATTRIBUTE *attrlist)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret = KMF_OK;
	KMF_KEYSTORE_TYPE kstype;

	KMF_ATTRIBUTE_TESTER required_attrs[] = {
	    {KMF_KEYSTORE_TYPE_ATTR, FALSE, 1, sizeof (KMF_KEYSTORE_TYPE)},
	    {KMF_OUTPUT_FILENAME_ATTR, TRUE, 1, 0},
	};

	int num_req_attrs = sizeof (required_attrs) /
	    sizeof (KMF_ATTRIBUTE_TESTER);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	CLEAR_ERROR(handle, ret);

	ret = test_attributes(num_req_attrs, required_attrs, 0, NULL,
	    numattr, attrlist);
	if (ret != KMF_OK)
		return (ret);

	ret = kmf_get_attr(KMF_KEYSTORE_TYPE_ATTR, attrlist, numattr,
	    &kstype, NULL);
	if (ret != KMF_OK)
		return (ret);

	plugin = FindPlugin(handle, kstype);
	if (plugin == NULL || plugin->funclist->ExportPK12 == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	return (plugin->funclist->ExportPK12(handle, numattr, attrlist));
}


KMF_RETURN
kmf_build_pk12(KMF_HANDLE_T handle, int numcerts,
    KMF_X509_DER_CERT *certlist, int numkeys, KMF_KEY_HANDLE *keylist,
    KMF_CREDENTIAL *p12cred, char *filename)
{
	KMF_RETURN rv;
	KMF_PLUGIN *plugin;
	KMF_RETURN (*buildpk12)(KMF_HANDLE *, int, KMF_X509_DER_CERT *,
	    int, KMF_KEY_HANDLE *, KMF_CREDENTIAL *, char *);

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (filename == NULL ||	p12cred == NULL ||
	    (certlist == NULL && keylist == NULL))
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	buildpk12 = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "openssl_build_pk12");
	if (buildpk12 == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	rv = buildpk12(handle, numcerts, certlist, numkeys, keylist, p12cred,
	    filename);

	return (rv);
}


KMF_RETURN
kmf_import_objects(KMF_HANDLE_T handle, char *filename,
	KMF_CREDENTIAL *cred,
	KMF_X509_DER_CERT **certs, int *ncerts,
	KMF_RAW_KEY_DATA **rawkeys, int *nkeys)
{
	KMF_RETURN rv;
	KMF_PLUGIN *plugin;
	KMF_RETURN (*import_objects)(KMF_HANDLE *, char *, KMF_CREDENTIAL *,
	    KMF_X509_DER_CERT **, int *, KMF_RAW_KEY_DATA **, int *);

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (filename == NULL ||	cred == NULL ||	certs == NULL ||
	    ncerts == NULL ||rawkeys == NULL || nkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Use the Keypair reader from the OpenSSL plugin.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	import_objects = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "openssl_import_objects");
	if (import_objects == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	/* Use OpenSSL interfaces to get raw key and cert data */
	rv = import_objects(handle, filename, cred, certs, ncerts,
	    rawkeys, nkeys);

	return (rv);
}

KMF_BOOL
IsEqualOid(KMF_OID *Oid1, KMF_OID *Oid2)
{
	return ((Oid1->Length == Oid2->Length) &&
	    !memcmp(Oid1->Data, Oid2->Data, Oid1->Length));
}

static KMF_RETURN
set_algoid(KMF_X509_ALGORITHM_IDENTIFIER *destid,
	KMF_OID *newoid)
{
	if (destid == NULL || newoid == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	destid->algorithm.Length = newoid->Length;
	destid->algorithm.Data = malloc(destid->algorithm.Length);
	if (destid->algorithm.Data == NULL)
		return (KMF_ERR_MEMORY);

	(void) memcpy(destid->algorithm.Data, newoid->Data,
	    destid->algorithm.Length);

	return (KMF_OK);
}

KMF_RETURN
copy_algoid(KMF_X509_ALGORITHM_IDENTIFIER *destid,
	KMF_X509_ALGORITHM_IDENTIFIER *srcid)
{
	KMF_RETURN ret = KMF_OK;
	if (!destid || !srcid)
		return (KMF_ERR_BAD_PARAMETER);

	destid->algorithm.Length = srcid->algorithm.Length;
	destid->algorithm.Data = malloc(destid->algorithm.Length);
	if (destid->algorithm.Data == NULL)
		return (KMF_ERR_MEMORY);

	(void) memcpy(destid->algorithm.Data, srcid->algorithm.Data,
	    destid->algorithm.Length);

	destid->parameters.Length = srcid->parameters.Length;
	if (destid->parameters.Length > 0) {
		destid->parameters.Data = malloc(destid->parameters.Length);
		if (destid->parameters.Data == NULL)
			return (KMF_ERR_MEMORY);

		(void) memcpy(destid->parameters.Data, srcid->parameters.Data,
		    destid->parameters.Length);
	} else {
		destid->parameters.Data = NULL;
	}
	return (ret);
}

static KMF_RETURN
sign_cert(KMF_HANDLE_T handle,
	const KMF_DATA *SubjectCert,
	KMF_KEY_HANDLE	*Signkey,
	KMF_OID		*signature_oid,
	KMF_DATA	*SignedCert)
{
	KMF_X509_CERTIFICATE	*subj_cert = NULL;
	KMF_DATA		data_to_sign = { 0, NULL };
	KMF_DATA		signed_data = { 0, NULL };
	KMF_RETURN		ret = KMF_OK;
	KMF_ALGORITHM_INDEX	algid;
	int i = 0;
	KMF_ATTRIBUTE attrlist[8];

	if (!SignedCert)
		return (KMF_ERR_BAD_PARAMETER);

	SignedCert->Length = 0;
	SignedCert->Data = NULL;

	if (!SubjectCert)
		return (KMF_ERR_BAD_PARAMETER);

	if (!SubjectCert->Data || !SubjectCert->Length)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Shortcut - just extract the already encoded TBS cert data from
	 * the original data buffer.  Since we haven't changed anything,
	 * there is no need to re-encode it.
	 */
	ret = ExtractX509CertParts((KMF_DATA *)SubjectCert,
	    &data_to_sign, NULL);
	if (ret != KMF_OK) {
		goto cleanup;
	}

	/* Estimate the signed data length generously */
	signed_data.Length = data_to_sign.Length*2;
	signed_data.Data = calloc(1, signed_data.Length);
	if (!signed_data.Data) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	/*
	 * If we got here OK, decode into a structure and then re-encode
	 * the complete certificate.
	 */
	ret = DerDecodeSignedCertificate(SubjectCert, &subj_cert);
	if (ret != KMF_OK) {
		goto cleanup;
	}

	/* We are re-signing this cert, so clear out old signature data */
	if (!IsEqualOid(&subj_cert->signature.algorithmIdentifier.algorithm,
	    signature_oid)) {
		kmf_free_algoid(&subj_cert->signature.algorithmIdentifier);
		ret = set_algoid(&subj_cert->signature.algorithmIdentifier,
		    signature_oid);
		if (ret != KMF_OK)
			goto cleanup;
		ret = set_algoid(&subj_cert->certificate.signature,
		    signature_oid);
		if (ret)
			goto cleanup;

		/* Free the previous "data to be signed" block */
		kmf_free_data(&data_to_sign);

		/*
		 * We changed the cert (updated the signature OID), so we
		 * need to re-encode it so the correct data gets signed.
		 */
		ret = DerEncodeTbsCertificate(&subj_cert->certificate,
		    &data_to_sign);
		if (ret != KMF_OK)
			goto cleanup;
	}
	kmf_set_attr_at_index(attrlist, i, KMF_KEYSTORE_TYPE_ATTR,
	    &Signkey->kstype, sizeof (KMF_KEYSTORE_TYPE));
	i++;
	kmf_set_attr_at_index(attrlist, i, KMF_KEY_HANDLE_ATTR,
	    Signkey, sizeof (KMF_KEY_HANDLE));
	i++;
	kmf_set_attr_at_index(attrlist, i, KMF_DATA_ATTR,
	    &data_to_sign, sizeof (KMF_DATA));
	i++;
	kmf_set_attr_at_index(attrlist, i, KMF_OUT_DATA_ATTR,
	    &signed_data, sizeof (KMF_DATA));
	i++;
	kmf_set_attr_at_index(attrlist, i, KMF_OID_ATTR,
	    signature_oid, sizeof (KMF_OID));
	i++;

	/* Sign the data */
	ret = kmf_sign_data(handle, i, attrlist);

	if (ret != KMF_OK)
		goto cleanup;

	algid = x509_algoid_to_algid(signature_oid);

	if (algid == KMF_ALGID_SHA1WithECDSA ||
	    algid == KMF_ALGID_SHA256WithECDSA ||
	    algid == KMF_ALGID_SHA384WithECDSA ||
	    algid == KMF_ALGID_SHA512WithECDSA) {
		/* ASN.1 encode ECDSA signature */
		KMF_DATA signature;

		ret = DerEncodeECDSASignature(&signed_data, &signature);
		kmf_free_data(&signed_data);

		if (ret != KMF_OK)
			goto cleanup;

		subj_cert->signature.encrypted = signature;
	} else if (algid == KMF_ALGID_SHA1WithDSA ||
	    algid == KMF_ALGID_SHA256WithDSA) {
		/*
		 * For DSA, kmf_sign_data() returns a 40-byte
		 * signature. We must encode the signature correctly.
		 */
		KMF_DATA signature;

		ret = DerEncodeDSASignature(&signed_data, &signature);
		kmf_free_data(&signed_data);

		if (ret != KMF_OK)
			goto cleanup;

		subj_cert->signature.encrypted = signature;
	} else {
		ret = copy_data(&subj_cert->signature.encrypted, &signed_data);
		kmf_free_data(&signed_data);

		if (ret != KMF_OK)
			goto cleanup;
	}

	/* Now, re-encode the cert with the new signature */
	ret = DerEncodeSignedCertificate(subj_cert, SignedCert);

cleanup:
	/* Cleanup & return */
	if (ret != KMF_OK)
		kmf_free_data(SignedCert);

	kmf_free_data(&data_to_sign);

	if (subj_cert != NULL) {
		kmf_free_signed_cert(subj_cert);
		free(subj_cert);
	}

	return (ret);
}

static KMF_RETURN
verify_cert_with_key(KMF_HANDLE_T handle,
	KMF_DATA *derkey,
	const KMF_DATA *CertToBeVerified)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_CERTIFICATE *signed_cert = NULL;
	KMF_X509_SPKI	spki;
	KMF_DATA	data_to_verify = { 0, NULL };
	KMF_DATA	signed_data = { 0, NULL };
	KMF_DATA	signature = { 0, NULL };
	KMF_ALGORITHM_INDEX	algid;

	/* check the caller and do other setup for this SPI call */
	if (handle == NULL || CertToBeVerified == NULL ||
	    derkey == NULL || derkey->Data == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&spki, 0, sizeof (KMF_X509_SPKI));

	ret = ExtractX509CertParts((KMF_DATA *)CertToBeVerified,
	    &data_to_verify, &signed_data);

	if (ret != KMF_OK)
		goto cleanup;

	ret = DerDecodeSPKI(derkey, &spki);
	if (ret != KMF_OK)
		goto cleanup;

	/* Decode the signer cert so we can get the Algorithm data */
	ret = DerDecodeSignedCertificate(CertToBeVerified, &signed_cert);
	if (ret != KMF_OK)
		return (ret);

	algid = x509_algoid_to_algid(CERT_SIG_OID(signed_cert));

	if (algid == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	if (algid == KMF_ALGID_SHA1WithDSA ||
	    algid == KMF_ALGID_SHA256WithDSA) {
		ret = DerDecodeDSASignature(&signed_data, &signature);
		if (ret != KMF_OK)
			goto cleanup;
	} else if (algid == KMF_ALGID_SHA1WithECDSA ||
	    algid == KMF_ALGID_SHA256WithECDSA ||
	    algid == KMF_ALGID_SHA384WithECDSA ||
	    algid == KMF_ALGID_SHA512WithECDSA) {
		ret = DerDecodeECDSASignature(&signed_data, &signature);
		if (ret != KMF_OK)
			goto cleanup;
	} else {
		signature.Data = signed_data.Data;
		signature.Length = signed_data.Length;
	}

	ret = PKCS_VerifyData(handle, algid, &spki,
	    &data_to_verify, &signature);

cleanup:
	if (data_to_verify.Data != NULL)
		free(data_to_verify.Data);

	if (signed_data.Data != NULL)
		free(signed_data.Data);

	if (signed_cert) {
		kmf_free_signed_cert(signed_cert);
		free(signed_cert);
	}
	if (algid == KMF_ALGID_SHA1WithDSA ||
	    algid == KMF_ALGID_SHA256WithDSA ||
	    algid == KMF_ALGID_SHA1WithECDSA ||
	    algid == KMF_ALGID_SHA256WithECDSA ||
	    algid == KMF_ALGID_SHA384WithECDSA ||
	    algid == KMF_ALGID_SHA512WithECDSA) {
		free(signature.Data);
	}

	kmf_free_algoid(&spki.algorithm);
	kmf_free_data(&spki.subjectPublicKey);

	return (ret);
}

/*
 * Use a signer cert to verify another certificate's signature.
 * This code forces the use of the PKCS11 mechanism for the verify
 * operation for the Cryptographic Framework's FIPS-140 boundary.
 */
static KMF_RETURN
verify_cert_with_cert(KMF_HANDLE_T handle,
	const KMF_DATA *CertToBeVerifiedData,
	const KMF_DATA *SignerCertData)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_CERTIFICATE *SignerCert = NULL;
	KMF_X509_CERTIFICATE *ToBeVerifiedCert = NULL;
	KMF_DATA	data_to_verify = { 0, NULL };
	KMF_DATA	signed_data = { 0, NULL };
	KMF_DATA	signature;
	KMF_ALGORITHM_INDEX	algid;
	KMF_POLICY_RECORD	*policy;

	if (handle == NULL ||
	    !CertToBeVerifiedData ||
	    !CertToBeVerifiedData->Data ||
	    !CertToBeVerifiedData->Length)
		return (KMF_ERR_BAD_PARAMETER);

	if (!SignerCertData ||
	    !SignerCertData->Data ||
	    !SignerCertData->Length)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;

	/* Make sure the signer has proper key usage bits */
	ret = check_key_usage(handle, SignerCertData, KMF_KU_SIGN_CERT);
	if (ret == KMF_ERR_EXTENSION_NOT_FOUND && policy->ku_bits == 0)
		ret = KMF_OK;
	if (ret != KMF_OK)
		return (ret);

	/* Decode the cert into parts for verification */
	ret = ExtractX509CertParts((KMF_DATA *)CertToBeVerifiedData,
	    &data_to_verify, &signed_data);
	if (ret != KMF_OK)
		goto cleanup;

	/* Decode the to-be-verified cert so we know what algorithm to use */
	ret = DerDecodeSignedCertificate(CertToBeVerifiedData,
	    &ToBeVerifiedCert);
	if (ret != KMF_OK)
		goto cleanup;

	algid = x509_algoid_to_algid(CERT_SIG_OID(ToBeVerifiedCert));

	if (algid == KMF_ALGID_SHA1WithDSA ||
	    algid == KMF_ALGID_SHA256WithDSA) {
		ret = DerDecodeDSASignature(&signed_data, &signature);
		if (ret != KMF_OK)
			goto cleanup;
	} else if (algid == KMF_ALGID_SHA1WithECDSA ||
	    algid == KMF_ALGID_SHA256WithECDSA ||
	    algid == KMF_ALGID_SHA384WithECDSA ||
	    algid == KMF_ALGID_SHA512WithECDSA) {
		ret = DerDecodeECDSASignature(&signed_data, &signature);
		if (ret != KMF_OK)
			goto cleanup;
	} else {
		signature.Data = signed_data.Data;
		signature.Length = signed_data.Length;
	}

	ret = DerDecodeSignedCertificate(SignerCertData, &SignerCert);
	if (ret != KMF_OK)
		goto cleanup;

	/*
	 * Force use of PKCS11 API for kcfd/libelfsign.  This is
	 * required for the Cryptographic Framework's FIPS-140 boundary.
	 */
	ret = PKCS_VerifyData(handle, algid,
	    &SignerCert->certificate.subjectPublicKeyInfo,
	    &data_to_verify, &signature);

cleanup:
	kmf_free_data(&data_to_verify);
	kmf_free_data(&signed_data);

	if (SignerCert) {
		kmf_free_signed_cert(SignerCert);
		free(SignerCert);
	}

	if (ToBeVerifiedCert) {
		kmf_free_signed_cert(ToBeVerifiedCert);
		free(ToBeVerifiedCert);
	}

	if (algid == KMF_ALGID_SHA1WithDSA ||
	    algid == KMF_ALGID_SHA256WithDSA ||
	    algid == KMF_ALGID_SHA1WithECDSA ||
	    algid == KMF_ALGID_SHA256WithECDSA ||
	    algid == KMF_ALGID_SHA384WithECDSA ||
	    algid == KMF_ALGID_SHA512WithECDSA) {
		free(signature.Data);
	}

	return (ret);
}
