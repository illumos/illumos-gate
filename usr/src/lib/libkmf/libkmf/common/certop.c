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
SignCert(KMF_HANDLE_T, const KMF_DATA *, KMF_KEY_HANDLE	*, KMF_DATA *);

static KMF_RETURN
VerifyCertWithKey(KMF_HANDLE_T, KMF_DATA *, const KMF_DATA *);

static KMF_RETURN
VerifyCertWithCert(KMF_HANDLE_T, const KMF_DATA *, const KMF_DATA *);

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
	AlgorithmId = X509_AlgorithmOidToAlgId(
	    &SignerCert->signature.algorithmIdentifier.algorithm);

	switch (AlgorithmId) {
		case KMF_ALGID_MD5WithRSA:
		case KMF_ALGID_MD2WithRSA:
		case KMF_ALGID_SHA1WithRSA:
			*keyalg = KMF_RSA;
			break;
		case KMF_ALGID_SHA1WithDSA:
			*keyalg = KMF_DSA;
			break;
		default:
			rv = KMF_ERR_BAD_ALGORITHM;
	}

	KMF_FreeSignedCert(SignerCert);
	free(SignerCert);
	return (rv);
}

/*
 *
 * Name: find_private_key_by_cert
 *
 * Description:
 *   This function finds the corresponding private key in keystore
 * for a certificate
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   params(input) - contains parameters used to find the private key
 *   SignerCertData(input) - pointer to a KMF_DATA structure containing a
 *		signer certificate
 *   key(output) - contains the found private key handle
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
static KMF_RETURN
find_private_key_by_cert(KMF_HANDLE_T handle,
	KMF_CRYPTOWITHCERT_PARAMS *params,
	KMF_DATA	*SignerCertData,
	KMF_KEY_HANDLE	*key)
{

	KMF_RETURN ret;
	KMF_KEY_ALG keytype;
	KMF_PLUGIN *plugin;

	if (handle == NULL || params == NULL ||
		SignerCertData == NULL || key == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(key, 0, sizeof (KMF_KEY_HANDLE));
	ret = get_keyalg_from_cert(SignerCertData, &keytype);
	if (ret != KMF_OK)
		return (ret);

	/* Find the private key from the keystore */
	plugin = FindPlugin(handle, params->kstype);

	if (plugin != NULL && plugin->funclist->GetPrikeyByCert != NULL) {
		CLEAR_ERROR(handle, ret);
		return (plugin->funclist->GetPrikeyByCert(handle,
		    params, SignerCertData, key, keytype));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

}

static KMF_RETURN
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

	ret = KMF_GetCertKeyUsageExt(cert, &keyusage);
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
		ret = KMF_GetCertBasicConstraintExt(cert, &critical,
		    &constraint);

		if ((ret != KMF_ERR_EXTENSION_NOT_FOUND) && (ret != KMF_OK)) {
			/* real error */
			return (ret);
		}

		if ((!critical) || (!constraint.cA) ||
		    (!(keyusage.KeyUsageBits & KMF_keyCertSign)))
			return (KMF_ERR_KEYUSAGE);
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
KMF_FindCert(KMF_HANDLE_T handle, KMF_FINDCERT_PARAMS *target,
		KMF_X509_DER_CERT *kmf_cert,
		uint32_t *num_certs)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN rv = KMF_OK;


	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (target == NULL || num_certs == NULL)
		return (KMF_ERR_BAD_PARAMETER); /* ILLEGAL ARGS ERROR */

	if ((target->find_cert_validity < KMF_ALL_CERTS) ||
	    (target->find_cert_validity > KMF_EXPIRED_CERTS))
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, target->kstype);

	if (plugin != NULL && plugin->funclist->FindCert != NULL) {
		return (plugin->funclist->FindCert(handle, target,
			kmf_cert, num_certs));
	}

	return (KMF_ERR_PLUGIN_NOTFOUND);
}

#define	NODATA(d) (d.Data == NULL || d.Length == NULL)

KMF_RETURN
KMF_EncodeCertRecord(KMF_X509_CERTIFICATE *CertData, KMF_DATA *encodedCert)
{
	KMF_RETURN ret;

	if (CertData == NULL || encodedCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Validate that all required fields are present.
	 */
	if (NODATA(CertData->certificate.version) ||
	    NODATA(CertData->certificate.signature.algorithm) ||
	NODATA(CertData->certificate.subjectPublicKeyInfo.subjectPublicKey) ||
	    CertData->certificate.serialNumber.val == NULL ||
	    CertData->certificate.serialNumber.len == 0 ||
	    CertData->certificate.subject.numberOfRDNs == 0 ||
	    CertData->certificate.issuer.numberOfRDNs == 0) {
		return (KMF_ERR_INCOMPLETE_TBS_CERT);
	}

	encodedCert->Length = 0;
	encodedCert->Data = NULL;

	/* Pack the new certificate */
	ret = DerEncodeSignedCertificate(CertData, encodedCert);

	return (ret);
}

KMF_RETURN
KMF_DecodeCertData(KMF_DATA *rawcert, KMF_X509_CERTIFICATE **certrec)
{
	KMF_RETURN ret = KMF_OK;

	if (rawcert == NULL || rawcert->Data == NULL ||
		rawcert->Length == 0 || certrec == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	ret = DerDecodeSignedCertificate(rawcert, certrec);

	return (ret);
}

/*
 *
 * Name: KMF_SignCertWithKey
 *
 * Description:
 *   This function signs a certificate using the private key and
 * returns the result as a signed, encoded certificate in SignedCert
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   CertToBeSigned(input) - pointer to a KMF_DATA structure containing a
 *		DER encoded certificate to be signed
 *   Signkey(input) - pointer to private key handle needed for signing
 *   SignedCert(output) - pointer to the KMF_DATA structure containing the
 *		signed certificate
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_SignCertWithKey(KMF_HANDLE_T handle,
		const KMF_DATA	*CertToBeSigned,
		KMF_KEY_HANDLE	*Signkey,
		KMF_DATA	*SignedCert)
{
	KMF_RETURN err;

	CLEAR_ERROR(handle, err);
	if (err != KMF_OK)
		return (err);

	if (CertToBeSigned == NULL ||
		Signkey == NULL || SignedCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	err = SignCert(handle, CertToBeSigned, Signkey, SignedCert);

	return (err);
}

/*
 *
 * Name: KMF_SignCertWithCert
 *
 * Description:
 *   This function signs a certificate using the signer cert and
 * returns the result as a signed, encoded certificate in SignedCert
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   params(input) - contains parameters to be used for signing
 *   CertToBeSigned(input) - pointer to a KMF_DATA structure containing a
 *		DER encoded certificate to be signed
 *   SignerCert(input) - pointer to a KMF_DATA structure containing a
 *		signer certificate
 *   SignedCert(output) - pointer to the KMF_DATA structure containing the
 *		DER encoded signed certificate
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_SignCertWithCert(KMF_HANDLE_T handle,
		KMF_CRYPTOWITHCERT_PARAMS *params,
		const KMF_DATA	*CertToBeSigned,
		KMF_DATA	*SignerCert,
		KMF_DATA	*SignedCert)
{
	KMF_RETURN ret;
	KMF_KEY_HANDLE Signkey;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (CertToBeSigned == NULL ||
		SignerCert == NULL || SignedCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of signer's certificate */
	ret = check_key_usage(handle, SignerCert, KMF_KU_SIGN_CERT);
	if (ret != KMF_OK)
		return (ret);

	/*
	 * Retrieve the private key from the keystore for the
	 * signer certificate.
	 */
	ret = find_private_key_by_cert(handle, params, SignerCert, &Signkey);
	if (ret != KMF_OK)
		return (ret);

	ret = SignCert(handle, CertToBeSigned, &Signkey, SignedCert);

	KMF_FreeKMFKey(handle, &Signkey);

	return (ret);
}

/*
 *
 * Name: KMF_SignDataWithCert
 *
 * Description:
 *   This function signs a block of data using the signer cert and
 * returns the the signature in output
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   params(input) - contains parameters to be used for signing
 *   tobesigned(input) - pointer to a KMF_DATA structure containing a
 *		the data to be signed
 *   output(output) - pointer to the KMF_DATA structure containing the
 *		signed data
 *   SignerCertData(input) - pointer to a KMF_DATA structure containing a
 *		signer certificate
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_SignDataWithCert(KMF_HANDLE_T handle,
	KMF_CRYPTOWITHCERT_PARAMS *params,
	KMF_DATA *tobesigned,
	KMF_DATA *output,
	KMF_DATA *SignerCertData)
{

	KMF_RETURN ret;
	KMF_KEY_HANDLE Signkey;
	KMF_X509_CERTIFICATE *SignerCert = NULL;
	KMF_PLUGIN *plugin;
	KMF_ALGORITHM_INDEX AlgId;
	KMF_DATA	signature = {0, NULL};

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (tobesigned == NULL ||
		SignerCertData == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of signer's certificate */
	ret = check_key_usage(handle, SignerCertData, KMF_KU_SIGN_DATA);
	if (ret != KMF_OK)
		return (ret);

	/*
	 * Retrieve the private key from the keystore based on
	 * the signer certificate.
	 */
	ret = find_private_key_by_cert(handle, params, SignerCertData,
	    &Signkey);
	if (ret != KMF_OK) {
		goto cleanup;
	}

	ret = DerDecodeSignedCertificate(SignerCertData, &SignerCert);
	if (ret != KMF_OK)
		goto cleanup;

	plugin = FindPlugin(handle, Signkey.kstype);
	if (plugin != NULL && plugin->funclist->SignData != NULL) {
		KMF_OID *oid;

		if (params->algid != KMF_ALGID_NONE)
			oid = X509_AlgIdToAlgorithmOid(params->algid);
		else
			oid = CERT_ALG_OID(SignerCert);

		ret = plugin->funclist->SignData(handle, &Signkey,
			oid, tobesigned, output);
		if (ret != KMF_OK)
			goto cleanup;

		AlgId = X509_AlgorithmOidToAlgId(CERT_ALG_OID(SignerCert));

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
		ret = KMF_ERR_PLUGIN_NOTFOUND;
	}

cleanup:
	if (signature.Data)
		free(signature.Data);

	KMF_FreeKMFKey(handle, &Signkey);
	if (SignerCert != NULL) {
		KMF_FreeSignedCert(SignerCert);
		free(SignerCert);
	}

	return (ret);
}

/*
 *
 * Name: KMF_VerifyCertWithKey
 *
 * Description:
 *   This function verifies that the CertToBeVerified was signed
 * using a specific private key and that the certificate has not
 * been altered since it was signed using that private key
 *
 * Parameters:
 *	handle(input) - opaque handle for KMF session
 *	KMFKey(input) - holds public key information for verification
 *	CertToBeVerified(input) - A signed certificate whose signature
 *	is to be verified
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.  The value KMF_OK indicates success. All other
 * values represent an error condition.
 */
KMF_RETURN
KMF_VerifyCertWithKey(KMF_HANDLE_T handle,
		KMF_KEY_HANDLE *KMFKey,
		const KMF_DATA *CertToBeVerified)
{
	KMF_RETURN err;
	KMF_DATA	derkey = {0, NULL};
	KMF_PLUGIN	*plugin;

	CLEAR_ERROR(handle, err);
	if (err != KMF_OK)
		return (err);

	if (KMFKey == NULL ||
		CertToBeVerified == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* The keystore must extract the pubkey data */
	plugin = FindPlugin(handle, KMFKey->kstype);
	if (plugin != NULL && plugin->funclist->EncodePubkeyData != NULL) {
		err = plugin->funclist->EncodePubkeyData(handle,
			KMFKey, &derkey);
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	if (err == KMF_OK && derkey.Length > 0) {
		/* check the caller and do other setup for this SPI call */
		err = VerifyCertWithKey(handle, &derkey, CertToBeVerified);

		if (derkey.Data != NULL)
			free(derkey.Data);
	}

	return (err);
}

/*
 *
 * Name: KMF_VerifyCertWithCert
 *
 * Description:
 *   Function to verify the signature of a signed certificate
 *
 * Parameters:
 *   handle	- pointer to KMF handle
 *   CertToBeVerified(input) - pointer to the signed certificate
 *   SignerCert(input) - pointer to certificate used in signing
 *
 * Returns:
 *   A KMF_RETURN value.
 *   The value KMF_OK indicates success.
 *   All other values represent an error condition.
 */
KMF_RETURN
KMF_VerifyCertWithCert(KMF_HANDLE_T handle,
	const KMF_DATA *CertToBeVerified,
	const KMF_DATA *SignerCert)
{
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (CertToBeVerified == NULL ||
		SignerCert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of signer's certificate */
	ret = check_key_usage(handle, SignerCert, KMF_KU_SIGN_CERT);
	if (ret != KMF_OK)
		return (ret);

	ret = VerifyCertWithCert(handle, CertToBeVerified, SignerCert);
	return (ret);
}

/*
 *
 * Name: KMF_VerifyDataWithCert
 *
 * Description:
 *   This function verifies the signature of a block of data using a signer
 *   certificate.
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   indata(input) - pointer to the block of data whose signature
 *		is to be verified
 *   insig(input) - pointer to the signature to be verified
 *   SignerCert(input) - pointer to signer cert for verification
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_VerifyDataWithCert(KMF_HANDLE_T handle,
	KMF_KEYSTORE_TYPE kstype,
	KMF_ALGORITHM_INDEX algid,
	KMF_DATA *indata,
	KMF_DATA *insig,
	const KMF_DATA *SignerCert)
{
	KMF_RETURN ret;
	KMF_PLUGIN *plugin;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (SignerCert == NULL ||
		indata == NULL || insig == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of signer's certificate */
	ret = check_key_usage(handle, SignerCert, KMF_KU_SIGN_DATA);
	if (ret != KMF_OK)
		return (ret);

	/*
	 * If NSS, use PKCS#11, we are not accessing the database(s),
	 * we just prefer the "verify" operation from the crypto framework.
	 * The OpenSSL version is unique in order to avoid a dependency loop
	 * with the kcfd(1M) process.
	 */
	if (kstype == KMF_KEYSTORE_NSS)
		kstype = KMF_KEYSTORE_PK11TOKEN;

	plugin = FindPlugin(handle, kstype);
	if (plugin == NULL)
		return (KMF_ERR_PLUGIN_NOTFOUND);

	if (plugin->funclist->VerifyDataWithCert == NULL)
		return (KMF_ERR_FUNCTION_NOT_FOUND);

	CLEAR_ERROR(handle, ret);
	ret = (plugin->funclist->VerifyDataWithCert(handle,
		algid, indata, insig, (KMF_DATA *)SignerCert));

	return (ret);
}

/*
 * Name: KMF_EncryptWithCert
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
KMF_EncryptWithCert(KMF_HANDLE_T handle,
	KMF_DATA *cert,
	KMF_DATA *plaintext,
	KMF_DATA *ciphertext)
{
	KMF_RETURN ret;
	KMF_X509_CERTIFICATE *x509cert = NULL;
	KMF_X509_SPKI *pubkey;
	KMF_OID *alg;
	KMF_ALGORITHM_INDEX algid;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (cert == NULL ||
		plaintext == NULL || ciphertext == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of the certificate */
	ret = check_key_usage(handle, cert, KMF_KU_ENCRYPT_DATA);
	if (ret != KMF_OK)
		return (ret);

	/* Decode the cert so we can get the SPKI data */
	if ((ret = DerDecodeSignedCertificate(cert, &x509cert)) != KMF_OK)
		return (ret);

	/* Get the public key info from the certificate */
	pubkey = &x509cert->certificate.subjectPublicKeyInfo;

	/* Use the algorithm in SPKI to encrypt data */
	alg = &pubkey->algorithm.algorithm;

	algid = X509_AlgorithmOidToAlgId(alg);

	/* DSA does not support encrypt */
	if (algid == KMF_ALGID_DSA || algid == KMF_ALGID_NONE) {
		KMF_FreeSignedCert(x509cert);
		free(x509cert);
		return (KMF_ERR_BAD_ALGORITHM);
	}

	ret = PKCS_EncryptData(handle, algid, pubkey, plaintext, ciphertext);

	KMF_FreeSignedCert(x509cert);
	free(x509cert);

	return (ret);
}

/*
 * Name: KMF_DecryptWithCert
 *
 * Description:
 *   Uses the private key associated with the cert to decrypt
 *   the ciphertext into the plaintext.
 *
 * Parameters:
 *   handle(input) - opaque handle for KMF session
 *   params(input) - contains parameters to be used to find the private
 *		key for decryption
 *   cert(input) - pointer to a DER encoded certificate for decryption
 *		by using its private key
 *   ciphertext(input) - pointer to the ciphertext contains to be
 *		decrypted data
 *   plaintext(output) - pointer to the plaintext after decryption
 *
 * Returns:
 *   A KMF_RETURN value indicating success or specifying a particular
 * error condition.
 *   The value KMF_OK indicates success. All other values represent
 * an error condition.
 *
 */
KMF_RETURN
KMF_DecryptWithCert(KMF_HANDLE_T handle,
	KMF_CRYPTOWITHCERT_PARAMS *params,
	KMF_DATA *cert,
	KMF_DATA *ciphertext,
	KMF_DATA *plaintext)
{
	KMF_RETURN ret;
	KMF_KEY_HANDLE Signkey;
	KMF_X509_CERTIFICATE *x509cert = NULL;
	KMF_X509_SPKI *spki_ptr;
	KMF_PLUGIN *plugin;
	KMF_ALGORITHM_INDEX AlgorithmId;


	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (cert == NULL ||
		plaintext == NULL || ciphertext == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* check the keyUsage of the certificate */
	ret = check_key_usage(handle, cert, KMF_KU_ENCRYPT_DATA);
	if (ret != KMF_OK)
		return (ret);

	/*
	 * Retrieve the private key from the keystore based on
	 * the certificate.
	 */
	ret = find_private_key_by_cert(handle, params, cert, &Signkey);
	if (ret != KMF_OK) {
		return (ret);
	}

	/* Decode the cert so we can get the alogorithm */
	ret = DerDecodeSignedCertificate(cert, &x509cert);
	if (ret != KMF_OK)
		goto cleanup;

	spki_ptr = &x509cert->certificate.subjectPublicKeyInfo;
	AlgorithmId = X509_AlgorithmOidToAlgId((KMF_OID *)
	    &spki_ptr->algorithm.algorithm);

	/* DSA does not support decrypt */
	if (AlgorithmId == KMF_ALGID_DSA) {
		ret = KMF_ERR_BAD_ALGORITHM;
		goto cleanup;
	}

	plugin = FindPlugin(handle, Signkey.kstype);

	if (plugin != NULL && plugin->funclist->DecryptData != NULL) {
		ret = plugin->funclist->DecryptData(handle,
		    &Signkey, &spki_ptr->algorithm.algorithm,
		    ciphertext, plaintext);
	} else {
		ret = KMF_ERR_PLUGIN_NOTFOUND;
	}

cleanup:
	KMF_FreeKMFKey(handle, &Signkey);
	KMF_FreeSignedCert(x509cert);
	free(x509cert);

	return (ret);
}

KMF_RETURN
KMF_StoreCert(KMF_HANDLE_T handle, KMF_STORECERT_PARAMS *target,
	KMF_DATA *pcert)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (target == NULL || pcert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, target->kstype);

	if (plugin != NULL && plugin->funclist->StoreCert != NULL) {
		return (plugin->funclist->StoreCert(handle, target, pcert));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
KMF_ImportCert(KMF_HANDLE_T handle, KMF_IMPORTCERT_PARAMS *target)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (target == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, target->kstype);

	if (plugin != NULL && plugin->funclist->ImportCert != NULL) {
		return (plugin->funclist->ImportCert(handle, target));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
}

KMF_RETURN
KMF_DeleteCertFromKeystore(KMF_HANDLE_T handle, KMF_DELETECERT_PARAMS *target)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (target == NULL ||
		(target->find_cert_validity < KMF_ALL_CERTS) ||
		(target->find_cert_validity > KMF_EXPIRED_CERTS))
		return (KMF_ERR_BAD_PARAMETER);

	plugin = FindPlugin(handle, target->kstype);

	if (plugin != NULL && plugin->funclist->DeleteCert != NULL) {
		return (plugin->funclist->DeleteCert(handle, target));
	} else {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}
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
	ret = KMF_GetCertCRLDistributionPointsExt((const KMF_DATA *)cert,
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
			ret = KMF_DownloadCRL(handle, uri, proxyname,
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
	KMF_FreeCRLDistributionPoints(&crl_dps);
	return (ret);
}

static KMF_RETURN
cert_crl_check(KMF_HANDLE_T handle,
	KMF_VALIDATECERT_PARAMS *params,
	KMF_DATA *user_cert,
	KMF_DATA *issuer_cert)
{
	KMF_POLICY_RECORD *policy;
	KMF_RETURN ret = KMF_OK;
	KMF_IMPORTCRL_PARAMS 	icrl_params;
	KMF_FINDCERTINCRL_PARAMS fcrl_params;
	KMF_OPENSSL_PARAMS ssl_params;
	KMF_VERIFYCRL_PARAMS vcrl_params;
	char user_certfile[MAXPATHLEN];
	char crlfile_tmp[MAXPATHLEN];
	KMF_CHECKCRLDATE_PARAMS ccrldate_params;
	char *basefilename = NULL;
	char *dir = NULL;
	char *crlfilename = NULL;
	char *proxy = NULL;
	char *uri = NULL;
	KMF_ENCODE_FORMAT format;

	if (handle == NULL || params == NULL ||
		user_cert == NULL || issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;

	(void) memset(&icrl_params, 0, sizeof (icrl_params));
	(void) memset(&vcrl_params, 0, sizeof (vcrl_params));
	(void) memset(&ccrldate_params, 0, sizeof (ccrldate_params));
	(void) memset(&fcrl_params, 0, sizeof (fcrl_params));
	(void) memset(&ssl_params, 0, sizeof (ssl_params));

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

		/* Cache the CRL file. */
		if (params->kstype == KMF_KEYSTORE_NSS) {
			/*
			 * For NSS keystore, import this CRL file into th
			 * internal database.
			 */
			icrl_params.kstype = KMF_KEYSTORE_NSS;
			icrl_params.nssparms.slotlabel = NULL;
			icrl_params.nssparms.crlfile = crlfile_tmp;
			icrl_params.nssparms.crl_check = B_FALSE;
			ret = KMF_ImportCRL(handle, &icrl_params);
			(void) unlink(crlfile_tmp);
			if (ret != KMF_OK)
				goto cleanup;
		} else {
			/*
			 * For File-based CRL plugin's, find the cache
			 * location from the CRL policy's attributes and
			 * cache it.
			 */
			if (basefilename == NULL)
				basefilename = basename(uri);

			crlfilename = get_fullpath(dir == NULL ? "./" : dir,
			    basefilename);
			if (crlfilename == NULL) {
				(void) unlink(crlfile_tmp);
				ret = KMF_ERR_BAD_CRLFILE;
				goto cleanup;
			}

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
		if (params->kstype != KMF_KEYSTORE_NSS) {
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
		}
	}

	/*
	 * Check the CRL signature if needed.
	 */
	if (!policy->validation_info.crl_info.ignore_crl_sign) {
		/*
		 * NSS CRL is not file based, and its signature
		 * has been verified during CRL import.
		 */
		if (params->kstype != KMF_KEYSTORE_NSS) {
			vcrl_params.crl_name = crlfilename;
			vcrl_params.tacert = issuer_cert;

			ret = KMF_VerifyCRLFile(handle, &vcrl_params);
			if (ret != KMF_OK)  {
				goto cleanup;
			}
		}
	}

	/*
	 * Check the CRL validity if needed.
	 */
	if (!policy->validation_info.crl_info.ignore_crl_date) {
		/*
		 * This is for file-based CRL, but not for NSS CRL.
		 */
		if (params->kstype != KMF_KEYSTORE_NSS) {
			ccrldate_params.crl_name = crlfilename;

			ret = KMF_CheckCRLDate(handle, &ccrldate_params);
			if (ret != KMF_OK)  {
				goto cleanup;
			}
		}
	}

	/*
	 * Check the CRL revocation for the certificate.
	 */
	fcrl_params.kstype = params->kstype;
	switch (params->kstype) {
	case KMF_KEYSTORE_NSS:
		fcrl_params.nssparms.certificate = params->certificate;
		break;
	case KMF_KEYSTORE_PK11TOKEN:
		/*
		 * Create temporary file to hold the user certificate.
		 */
		(void) strlcpy(user_certfile, CERTFILE_TEMPNAME,
		    sizeof (user_certfile));
		if (mkstemp(user_certfile) == -1) {
			ret = KMF_ERR_INTERNAL;
			goto cleanup;
		}

		ret = KMF_CreateCertFile(user_cert, KMF_FORMAT_ASN1,
		    user_certfile);
		if (ret != KMF_OK)  {
			goto cleanup;
		}

		ssl_params.certfile = user_certfile;
		ssl_params.crlfile = crlfilename;
		fcrl_params.sslparms = ssl_params;
		break;
	case KMF_KEYSTORE_OPENSSL:
		ssl_params.certfile = params->ks_opt_u.openssl_opts.certfile;
		ssl_params.crlfile = crlfilename;
		fcrl_params.sslparms = ssl_params;
		break;
	default:
		ret = KMF_ERR_PLUGIN_NOTFOUND;
		goto cleanup;
	}

	ret = KMF_FindCertInCRL(handle, &fcrl_params);
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
cert_ocsp_check(KMF_HANDLE_T handle,
	KMF_VALIDATECERT_PARAMS *params,
	KMF_DATA *user_cert,
	KMF_DATA *issuer_cert,
	KMF_DATA *response)
{
	KMF_RETURN ret = KMF_OK;
	KMF_POLICY_RECORD *policy;
	KMF_FINDCERT_PARAMS fc_target;
	KMF_OCSPRESPONSE_PARAMS_INPUT resp_params_in;
	KMF_OCSPRESPONSE_PARAMS_OUTPUT resp_params_out;
	KMF_DATA *new_response = NULL;
	boolean_t ignore_response_sign = B_FALSE;
	uint32_t ltime;
	KMF_DATA *signer_cert = NULL;
	KMF_BIGINT sernum = { NULL, 0 };

	if (handle == NULL || params == NULL || user_cert == NULL ||
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
		KMF_OPENSSL_PARAMS ssl_params;
		KMF_X509_DER_CERT signer_retrcert;
		uchar_t *bytes = NULL;
		size_t bytelen;
		uint32_t num = 0;

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
		ret = KMF_HexString2Bytes(
		    (uchar_t *)policy->VAL_OCSP_RESP_CERT.serial,
		    &bytes, &bytelen);
		if (ret != KMF_OK || bytes == NULL) {
			ret = KMF_ERR_OCSP_POLICY;
			goto out;
		}

		sernum.val = bytes;
		sernum.len = bytelen;

		(void) memset(&fc_target, 0, sizeof (fc_target));
		(void) memset(&ssl_params, 0, sizeof (ssl_params));

		fc_target.subject = signer_name;
		fc_target.serial = &sernum;

		switch (params->kstype) {
		case KMF_KEYSTORE_NSS:
			fc_target.kstype = KMF_KEYSTORE_NSS;
			params->nssparms.slotlabel =
			    params->nssparms.slotlabel;
			break;

		case KMF_KEYSTORE_OPENSSL:
			fc_target.kstype = KMF_KEYSTORE_OPENSSL;
			ssl_params.dirpath =
			    params->sslparms.dirpath == NULL ?
			    "./" : params->sslparms.dirpath;
			fc_target.sslparms = ssl_params;
			break;

		case KMF_KEYSTORE_PK11TOKEN:
			fc_target.kstype = KMF_KEYSTORE_PK11TOKEN;
			break;
		default:
			ret = KMF_ERR_BAD_PARAMETER;
			goto out;
			break;
		}

		num = 0;
		ret = KMF_FindCert(handle, &fc_target, NULL, &num);
		if (ret != KMF_OK || num != 1) {
			if (num == 0)
				ret = KMF_ERR_CERT_NOT_FOUND;
			if (num > 0)
				ret = KMF_ERR_CERT_MULTIPLE_FOUND;
			goto out;
		}

		(void) memset(&signer_retrcert, 0, sizeof (KMF_X509_DER_CERT));
		ret = KMF_FindCert(handle, &fc_target, &signer_retrcert, &num);
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

		ret = KMF_GetOCSPForCert(handle, user_cert, issuer_cert,
		    new_response);
		if (ret != KMF_OK)
			goto out;
	}

	/*
	 * Process the OCSP response and retrieve the certificate status.
	 */
	resp_params_in.issuer_cert = issuer_cert;
	resp_params_in.user_cert = user_cert;
	resp_params_in.signer_cert = signer_cert;
	resp_params_in.response =
		response == NULL ? new_response : response;
	resp_params_in.response_lifetime = ltime;
	resp_params_in.ignore_response_sign = ignore_response_sign;

	ret = KMF_GetOCSPStatusForCert(handle, &resp_params_in,
	    &resp_params_out);
	if (ret == KMF_OK) {
		switch (resp_params_out.cert_status) {
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
		KMF_FreeData(new_response);
		free(new_response);
	}

	if (signer_cert) {
		KMF_FreeData(signer_cert);
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
	ret = KMF_GetCertKeyUsageExt(cert, &keyusage);

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
		ret = KMF_GetCertBasicConstraintExt(cert,
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

	ret = KMF_GetCertEKU(cert, &eku);
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
kmf_find_issuer_cert(KMF_HANDLE_T handle,
	KMF_VALIDATECERT_PARAMS *params,
	char *user_issuer,
	KMF_DATA *issuer_cert)
{

	KMF_RETURN ret = KMF_OK;
	KMF_FINDCERT_PARAMS fc_target;
	KMF_OPENSSL_PARAMS ssl_params;
	KMF_X509_DER_CERT *certlist = NULL;
	uint32_t i, num = 0;
	time_t t_notbefore;
	time_t t_notafter;
	time_t latest;
	KMF_DATA tmp_cert = {0, NULL};

	if (handle == NULL || params == NULL ||
		user_issuer == NULL || issuer_cert == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&fc_target, 0, sizeof (fc_target));
	(void) memset(&ssl_params, 0, sizeof (ssl_params));

	fc_target.subject = user_issuer;

	switch (params->kstype) {
	case KMF_KEYSTORE_NSS:
		fc_target.kstype = KMF_KEYSTORE_NSS;
		fc_target.nssparms.slotlabel = params->nssparms.slotlabel;
		break;

	case KMF_KEYSTORE_OPENSSL:
		fc_target.kstype = KMF_KEYSTORE_OPENSSL;
		/* setup dirpath to search for TA in a directory */
		if (params->sslparms.dirpath == NULL) {
			ssl_params.dirpath = "./";
		} else {
			ssl_params.dirpath = params->sslparms.dirpath;
		}
		ssl_params.certfile = NULL;
		fc_target.sslparms = ssl_params;
		break;

	case KMF_KEYSTORE_PK11TOKEN:
		fc_target.kstype = KMF_KEYSTORE_PK11TOKEN;
		break;
	default:
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	num = 0;
	ret = KMF_FindCert(handle, &fc_target, NULL, &num);
	if (ret == KMF_OK && num > 0) {
		certlist = (KMF_X509_DER_CERT *)malloc(num *
		    sizeof (KMF_X509_DER_CERT));

		if (certlist == NULL) {
			ret = KMF_ERR_MEMORY;
			goto out;
		}

		(void) memset(certlist, 0, num *
		    sizeof (KMF_X509_DER_CERT));

		ret = KMF_FindCert(handle, &fc_target, certlist, &num);
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
			ret = KMF_GetCertValidity(&certlist[i].certificate,
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
			KMF_FreeKMFCert(handle, &certlist[i]);
		free(certlist);
	}

	return (ret);

}

static KMF_RETURN
kmf_find_ta_cert(KMF_HANDLE_T handle,
	KMF_VALIDATECERT_PARAMS *params,
	KMF_DATA *ta_cert,
	KMF_X509_NAME *user_issuerDN)
{

	KMF_POLICY_RECORD *policy;
	KMF_RETURN ret = KMF_OK;
	KMF_FINDCERT_PARAMS fc_target;
	KMF_OPENSSL_PARAMS ssl_params;
	uint32_t num = 0;
	char *ta_name;
	KMF_BIGINT serial = { NULL, 0 };
	uchar_t *bytes = NULL;
	size_t bytelen;
	KMF_X509_DER_CERT ta_retrCert;
	char *ta_subject = NULL;
	KMF_X509_NAME ta_subjectDN;

	if (handle == NULL || params == NULL ||
		ta_cert == NULL || user_issuerDN == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;
	ta_name = policy->ta_name;

	ret = KMF_HexString2Bytes((uchar_t *)policy->ta_serial,
	    &bytes, &bytelen);
	if (ret != KMF_OK || bytes == NULL) {
		ret = KMF_ERR_TA_POLICY;
		goto out;
	}

	(void) memset(&fc_target, 0, sizeof (fc_target));
	(void) memset(&ssl_params, 0, sizeof (ssl_params));

	serial.val = bytes;
	serial.len = bytelen;
	fc_target.serial = &serial;
	fc_target.subject = ta_name;

	switch (params->kstype) {
	case KMF_KEYSTORE_NSS:
		fc_target.kstype = KMF_KEYSTORE_NSS;
		fc_target.nssparms.slotlabel = params->nssparms.slotlabel;
		break;

	case KMF_KEYSTORE_OPENSSL:
		fc_target.kstype = KMF_KEYSTORE_OPENSSL;
		/* setup dirpath to search for TA in a directory */
		if (params->sslparms.dirpath == NULL) {
			ssl_params.dirpath = "./";
		} else {
			ssl_params.dirpath = params->sslparms.dirpath;
		}
		ssl_params.certfile = NULL;
		fc_target.sslparms = ssl_params;
		break;

	case KMF_KEYSTORE_PK11TOKEN:
		fc_target.kstype = KMF_KEYSTORE_PK11TOKEN;
		break;
	default:
		ret = KMF_ERR_PLUGIN_NOTFOUND;
		goto out;
	}

	num = 0;
	ret = KMF_FindCert(handle, &fc_target, NULL, &num);
	if (ret != KMF_OK || num != 1)  {
		if (num == 0)
			ret = KMF_ERR_CERT_NOT_FOUND;
		if (num > 1)
			ret = KMF_ERR_CERT_MULTIPLE_FOUND;
		goto out;
	}

	(void) memset(&ta_retrCert, 0, sizeof (KMF_X509_DER_CERT));

	ret = KMF_FindCert(handle, &fc_target, &ta_retrCert, &num);
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

	ret = KMF_GetCertSubjectNameString(handle, ta_cert, &ta_subject);
	if (ret != KMF_OK)
		goto out;

	ret = KMF_DNParser(ta_subject,  &ta_subjectDN);
	if (ret != KMF_OK)
		goto out;

	if (KMF_CompareRDNs(user_issuerDN, &ta_subjectDN) != 0)
		ret = KMF_ERR_CERT_NOT_FOUND;

	KMF_FreeDN(&ta_subjectDN);

	/* Make sure the TA cert has the correct extensions */
	if (ret == KMF_OK)
		ret = check_key_usage(handle, ta_cert, KMF_KU_SIGN_CERT);
out:
	if (ta_retrCert.certificate.Data)
		KMF_FreeKMFCert(handle, &ta_retrCert);

	if ((ret != KMF_OK) && (ta_cert->Data != NULL))
		free(ta_cert->Data);

	if (serial.val != NULL)
		free(serial.val);

	if (ta_subject)
		free(ta_subject);

	return (ret);
}

KMF_RETURN
KMF_ValidateCert(KMF_HANDLE_T handle,
	KMF_VALIDATECERT_PARAMS *params,
	int  *result)
{
	KMF_RETURN ret = KMF_OK;
	KMF_DATA *pcert = NULL;
	KMF_DATA ta_cert = {0, NULL};
	KMF_DATA issuer_cert = {0, NULL};
	char *user_issuer = NULL, *user_subject = NULL;
	KMF_X509_NAME user_issuerDN, user_subjectDN;
	boolean_t	self_signed = B_FALSE;
	KMF_POLICY_RECORD *policy;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (params == NULL || params->certificate == NULL || result == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;
	*result = KMF_CERT_VALIDATE_OK;
	pcert = params->certificate;

	/*
	 * Get the issuer information from the input certficate first.
	 */
	if ((ret = KMF_GetCertIssuerNameString(handle, pcert,
	    &user_issuer)) != KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
		goto out;
	}

	if ((ret = KMF_DNParser(user_issuer,  &user_issuerDN)) != KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
		goto out;
	}

	/*
	 * Check if the certificate is a self-signed cert.
	 */
	if ((ret = KMF_GetCertSubjectNameString(handle, pcert,
	    &user_subject)) != KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
		KMF_FreeDN(&user_issuerDN);
		goto out;
	}

	if ((ret = KMF_DNParser(user_subject,  &user_subjectDN)) != KMF_OK) {
		*result |= KMF_CERT_VALIDATE_ERR_USER;
		KMF_FreeDN(&user_issuerDN);
		goto out;
	}

	if ((KMF_CompareRDNs(&user_issuerDN, &user_subjectDN)) == 0) {
		/*
		 * this is a self-signed cert
		 */
		self_signed = B_TRUE;
	}

	KMF_FreeDN(&user_subjectDN);

	/*
	 * Check KeyUsage extension of the subscriber's certificate
	 */
	ret = cert_ku_check(handle, pcert);
	if (ret != KMF_OK)  {
		*result |= KMF_CERT_VALIDATE_ERR_KEYUSAGE;
		goto out;
	}

	/*
	 * Validate Extended KeyUsage extension
	 */
	ret = cert_eku_check(handle, pcert);
	if (ret != KMF_OK)  {
		*result |= KMF_CERT_VALIDATE_ERR_EXT_KEYUSAGE;
		goto out;
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
		ret = KMF_CheckCertDate(handle, pcert);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_TIME;
			goto out;
		}
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
	 */
	if (policy->ignore_trust_anchor) {
		goto check_revocation;
	}

	/*
	 * Verify the signature of subscriber's certificate using
	 * TA certificate.
	 */
	if (self_signed) {
		ret = KMF_VerifyCertWithCert(handle, pcert, pcert);
	} else {
		ret = kmf_find_ta_cert(handle, params, &ta_cert,
			&user_issuerDN);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_TA;
			goto out;
		}

		ret = KMF_VerifyCertWithCert(handle, pcert, &ta_cert);
	}
	if (ret != KMF_OK)  {
		*result |= KMF_CERT_VALIDATE_ERR_SIGNATURE;
		goto out;
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

	ret = kmf_find_issuer_cert(handle, params, user_issuer,
	    &issuer_cert);
	if (ret != KMF_OK)  {
		*result |= KMF_CERT_VALIDATE_ERR_ISSUER;
		goto out;
	}

	if (policy->revocation & KMF_REVOCATION_METHOD_CRL) {
		ret = cert_crl_check(handle, params,
		    pcert, &issuer_cert);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_CRL;
			goto out;
		}
	}

	if (policy->revocation & KMF_REVOCATION_METHOD_OCSP) {
		ret = cert_ocsp_check(handle, params,
			pcert, &issuer_cert, params->ocsp_response);
		if (ret != KMF_OK)  {
			*result |= KMF_CERT_VALIDATE_ERR_OCSP;
			goto out;
		}
	}
out:
	if (user_issuer) {
		KMF_FreeDN(&user_issuerDN);
		free(user_issuer);
	}

	if (user_subject)
		free(user_subject);

	if (ta_cert.Data)
		free(ta_cert.Data);

	if (issuer_cert.Data)
		free(issuer_cert.Data);

	return (ret);

}

KMF_RETURN
KMF_CreateCertFile(KMF_DATA *certdata, KMF_ENCODE_FORMAT format,
	char *certfile)
{
	KMF_RETURN rv = KMF_OK;
	int fd = -1;
	KMF_DATA pemdata = {NULL, 0};

	if (certdata == NULL || certfile == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (format != KMF_FORMAT_PEM && format != KMF_FORMAT_ASN1)
		return (KMF_ERR_BAD_PARAMETER);

	if (format == KMF_FORMAT_PEM) {
		int len;
		rv = KMF_Der2Pem(KMF_CERT,
			certdata->Data, certdata->Length,
			&pemdata.Data, &len);
		if (rv != KMF_OK)
			goto cleanup;
		pemdata.Length = (size_t)len;
	}

	if ((fd = open(certfile, O_CREAT |O_RDWR, 0644)) == -1) {
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

	KMF_FreeData(&pemdata);

	return (rv);
}

KMF_RETURN
KMF_IsCertFile(KMF_HANDLE_T handle, char *filename, KMF_ENCODE_FORMAT *pformat)
{
	KMF_PLUGIN *plugin;
	KMF_RETURN (*IsCertFileFn)(void *, char *, KMF_ENCODE_FORMAT *);

	KMF_RETURN ret;

	CLEAR_ERROR(handle, ret);
	if (ret != KMF_OK)
		return (ret);

	if (filename  == NULL || pformat == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/*
	 * This framework function is actually implemented in the openssl
	 * plugin library, so we find the function address and call it.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	IsCertFileFn = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "OpenSSL_IsCertFile");
	if (IsCertFileFn == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	return (IsCertFileFn(handle, filename, pformat));
}

/*
 * This function checks the validity period of a der-encoded certificate.
 */
KMF_RETURN
KMF_CheckCertDate(KMF_HANDLE_T handle, KMF_DATA *cert)
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

	if (cert == NULL || cert->Data == NULL ||
		cert->Length == 0)
		return (KMF_ERR_BAD_PARAMETER);

	policy = handle->policy;
	rv = KMF_GetCertValidity(cert, &t_notbefore, &t_notafter);
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
KMF_ExportPK12(KMF_HANDLE_T handle,
	KMF_EXPORTP12_PARAMS *params,
	char *filename)
{
	KMF_RETURN rv;
	KMF_PLUGIN *plugin;
	KMF_KEYSTORE_TYPE kstype;
	KMF_X509_DER_CERT *certlist = NULL;
	KMF_KEY_HANDLE *keys = NULL;
	uint32_t numkeys;
	uint32_t numcerts;
	int i;

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (params == NULL || filename == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	kstype = params->kstype;
	if (kstype == KMF_KEYSTORE_PK11TOKEN) {
		KMF_FINDCERT_PARAMS fcargs;

		(void) memset(&fcargs, 0, sizeof (fcargs));

		fcargs.kstype = kstype;
		fcargs.certLabel = params->certLabel;
		fcargs.issuer = params->issuer;
		fcargs.subject = params->subject;
		fcargs.serial = params->serial;
		fcargs.idstr = params->idstr;

		/*
		 * Special processing because PKCS11 doesn't have
		 * a native PKCS12 operation.
		 */
		rv = KMF_FindCert(handle, &fcargs,  NULL, &numcerts);
		if (rv == KMF_OK && numcerts > 0) {
			certlist = (KMF_X509_DER_CERT *)malloc(numcerts *
				sizeof (KMF_X509_DER_CERT));
			if (certlist == NULL)
				return (KMF_ERR_MEMORY);
			(void) memset(certlist, 0, numcerts *
				sizeof (KMF_X509_DER_CERT));
			rv = KMF_FindCert(handle, &fcargs,
				certlist, &numcerts);
			if (rv != KMF_OK) {
				free(certlist);
				return (rv);
			}
		} else {
			return (rv);
		}

		numkeys = 0;
		for (i = 0; i < numcerts; i++) {
			KMF_CRYPTOWITHCERT_PARAMS fkparms;
			KMF_KEY_HANDLE newkey;

			fkparms.kstype = kstype;
			fkparms.format = KMF_FORMAT_RAWKEY;
			fkparms.cred = params->cred;
			fkparms.certLabel = certlist[i].kmf_private.label;

			rv = find_private_key_by_cert(handle, &fkparms,
				&certlist[i].certificate, &newkey);
			if (rv == KMF_OK) {
				numkeys++;
				keys = realloc(keys,
					numkeys * sizeof (KMF_KEY_HANDLE));
				if (keys == NULL) {
					free(certlist);
					rv = KMF_ERR_MEMORY;
					goto out;
				}
				keys[numkeys - 1] = newkey;
			} else if (rv == KMF_ERR_KEY_NOT_FOUND) {
				/* it is OK if a key is not found */
				rv = KMF_OK;
			}
		}
		if (rv == KMF_OK) {
			/*
			 * Switch the keystore type to use OpenSSL for
			 * exporting the raw cert and key data as PKCS12.
			 */
			kstype = KMF_KEYSTORE_OPENSSL;
		} else {
			rv = KMF_ERR_KEY_NOT_FOUND;
			goto out;
		}
	}
	plugin = FindPlugin(handle, kstype);
	if (plugin != NULL && plugin->funclist->ExportP12 != NULL) {
		rv = plugin->funclist->ExportP12(handle,
			params, numcerts, certlist,
			numkeys, keys, filename);
	} else {
		rv = KMF_ERR_PLUGIN_NOTFOUND;
	}

out:
	if (certlist != NULL) {
		for (i = 0; i < numcerts; i++)
			KMF_FreeKMFCert(handle, &certlist[i]);
		free(certlist);
	}
	if (keys != NULL) {
		for (i = 0; i < numkeys; i++)
			KMF_FreeKMFKey(handle, &keys[i]);
		free(keys);
	}

	return (rv);
}

KMF_RETURN
KMF_ImportPK12(KMF_HANDLE_T handle, char *filename,
	KMF_CREDENTIAL *cred,
	KMF_DATA **certs, int *ncerts,
	KMF_RAW_KEY_DATA **rawkeys, int *nkeys)
{
	KMF_RETURN rv;
	KMF_PLUGIN *plugin;
	KMF_RETURN (*openpkcs12)(KMF_HANDLE *,
		char *, KMF_CREDENTIAL *,
		KMF_DATA **, int *,
		KMF_RAW_KEY_DATA **, int *);

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (filename == NULL ||
		cred == NULL ||
		certs == NULL || ncerts == NULL ||
		rawkeys == NULL || nkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Use the pkcs12 reader from the OpenSSL plugin.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	openpkcs12 = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "openssl_read_pkcs12");
	if (openpkcs12 == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	/* Use OpenSSL interfaces to get raw key and cert data */
	rv = openpkcs12(handle, filename, cred, certs, ncerts,
		rawkeys, nkeys);

	return (rv);
}

KMF_RETURN
KMF_ImportKeypair(KMF_HANDLE_T handle, char *filename,
	KMF_CREDENTIAL *cred,
	KMF_DATA **certs, int *ncerts,
	KMF_RAW_KEY_DATA **rawkeys, int *nkeys)
{
	KMF_RETURN rv;
	KMF_PLUGIN *plugin;
	KMF_RETURN (*import_keypair)(KMF_HANDLE *,
		char *, KMF_CREDENTIAL *,
		KMF_DATA **, int *,
		KMF_RAW_KEY_DATA **, int *);

	CLEAR_ERROR(handle, rv);
	if (rv != KMF_OK)
		return (rv);

	if (filename == NULL ||
		cred == NULL ||
		certs == NULL || ncerts == NULL ||
		rawkeys == NULL || nkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Use the Keypair reader from the OpenSSL plugin.
	 */
	plugin = FindPlugin(handle, KMF_KEYSTORE_OPENSSL);
	if (plugin == NULL || plugin->dldesc == NULL) {
		return (KMF_ERR_PLUGIN_NOTFOUND);
	}

	import_keypair = (KMF_RETURN(*)())dlsym(plugin->dldesc,
	    "openssl_import_keypair");
	if (import_keypair == NULL) {
		return (KMF_ERR_FUNCTION_NOT_FOUND);
	}

	/* Use OpenSSL interfaces to get raw key and cert data */
	rv = import_keypair(handle, filename, cred, certs, ncerts,
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
SignCert(KMF_HANDLE_T handle,
	const KMF_DATA *SubjectCert,
	KMF_KEY_HANDLE	*Signkey,
	KMF_DATA	*SignedCert)
{
	KMF_X509_CERTIFICATE	*subj_cert = NULL;
	KMF_DATA		data_to_sign = {0, NULL};
	KMF_DATA		signed_data = {0, NULL};
	KMF_RETURN		ret = KMF_OK;
	KMF_ALGORITHM_INDEX	algid;

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
	if (subj_cert->signature.algorithmIdentifier.algorithm.Length == 0) {
		KMF_FreeAlgOID(&subj_cert->signature.algorithmIdentifier);
		ret = copy_algoid(&subj_cert->signature.algorithmIdentifier,
			&subj_cert->certificate.signature);
	}

	if (ret)
		goto cleanup;

	/* Sign the data */
	ret = KMF_SignDataWithKey(handle, Signkey,
		CERT_ALG_OID(subj_cert),
		&data_to_sign, &signed_data);

	if (ret != KMF_OK)
		goto cleanup;

	algid = X509_AlgorithmOidToAlgId(CERT_SIG_OID(subj_cert));

	/*
	 * For DSA, KMF_SignDataWithKey() returns a 40-bytes decoded
	 * signature. So we must encode the signature correctly.
	 */
	if (algid == KMF_ALGID_SHA1WithDSA) {

		KMF_DATA signature;

		ret = DerEncodeDSASignature(&signed_data, &signature);
		KMF_FreeData(&signed_data);

		if (ret != KMF_OK)
			goto cleanup;

		subj_cert->signature.encrypted = signature;
	} else {
		subj_cert->signature.encrypted = signed_data;
	}

	/* Now, re-encode the cert with the new signature */
	ret = DerEncodeSignedCertificate(subj_cert, SignedCert);

cleanup:
	/* Cleanup & return */
	if (ret != KMF_OK)
		KMF_FreeData(SignedCert);

	KMF_FreeData(&data_to_sign);

	if (subj_cert != NULL) {
		KMF_FreeSignedCert(subj_cert);
		free(subj_cert);
	}

	return (ret);
}

static KMF_RETURN
VerifyCertWithKey(KMF_HANDLE_T handle,
	KMF_DATA *derkey,
	const KMF_DATA *CertToBeVerified)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_CERTIFICATE *signed_cert = NULL;
	KMF_X509_SPKI	spki;
	KMF_DATA	data_to_verify = {0, NULL};
	KMF_DATA	signed_data = {0, NULL};
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

	algid = X509_AlgorithmOidToAlgId(CERT_SIG_OID(signed_cert));

	if (algid == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_ALGORITHM);

	if (algid == KMF_ALGID_SHA1WithDSA) {
		ret = DerDecodeDSASignature(&signed_data, &signature);
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
		KMF_FreeSignedCert(signed_cert);
		free(signed_cert);
	}
	if (algid == KMF_ALGID_SHA1WithDSA) {
		free(signature.Data);
	}

	KMF_FreeAlgOID(&spki.algorithm);
	KMF_FreeData(&spki.subjectPublicKey);

	return (ret);
}

/*
 * The key must be an ASN.1/DER encoded PKCS#1 key.
 */
KMF_RETURN
VerifyDataWithKey(KMF_HANDLE_T handle,
	KMF_DATA *derkey,
	KMF_ALGORITHM_INDEX sigAlg,
	KMF_DATA *indata,
	KMF_DATA *insig)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_SPKI spki;

	if (!indata || !insig || !derkey || !derkey->Data)
		return (KMF_ERR_BAD_PARAMETER);

	ret = DerDecodeSPKI(derkey, &spki);
	if (ret != KMF_OK)
		goto cleanup;

	ret = PKCS_VerifyData(handle, sigAlg, &spki, indata, insig);

cleanup:
	KMF_FreeAlgOID(&spki.algorithm);
	KMF_FreeData(&spki.subjectPublicKey);

	return (ret);
}

static KMF_RETURN
VerifyCertWithCert(KMF_HANDLE_T handle,
	const KMF_DATA *CertToBeVerifiedData,
	const KMF_DATA *SignerCertData)
{
	KMF_RETURN ret = KMF_OK;
	KMF_X509_CERTIFICATE *SignerCert = NULL;
	KMF_X509_CERTIFICATE *ToBeVerifiedCert = NULL;
	KMF_X509_SPKI *pubkey;
	KMF_DATA	data_to_verify = {0, NULL};
	KMF_DATA	signed_data = {0, NULL};
	KMF_DATA	signature;
	KMF_ALGORITHM_INDEX	algid;

	if (!CertToBeVerifiedData ||
	    !CertToBeVerifiedData->Data ||
	    !CertToBeVerifiedData->Length)
		return (KMF_ERR_BAD_PARAMETER);

	if (!SignerCertData ||
	    !SignerCertData->Data ||
	    !SignerCertData->Length)
		return (KMF_ERR_BAD_PARAMETER);

	/* Decode the cert into parts for verification */
	ret = ExtractX509CertParts((KMF_DATA *)CertToBeVerifiedData,
		&data_to_verify, &signed_data);
	if (ret != KMF_OK)
		goto cleanup;

	/* Decode the signer cert so we can get the SPKI data */
	ret = DerDecodeSignedCertificate(SignerCertData, &SignerCert);
	if (ret != KMF_OK)
		goto cleanup;

	/*
	 * TODO !  Validate the SignerCert to make sure it is OK to be
	 * used to verify other certs. Or - should this be done the calling
	 * application?
	 */
	/* ValidateCert(SignerCert); */

	/* Get the public key info from the signer certificate */
	pubkey = &SignerCert->certificate.subjectPublicKeyInfo;

	/* Decode the to-be-verified cert so we know what algorithm to use */
	ret = DerDecodeSignedCertificate(CertToBeVerifiedData,
	    &ToBeVerifiedCert);

	if (ret != KMF_OK)
		goto cleanup;

	algid = X509_AlgorithmOidToAlgId(CERT_SIG_OID(ToBeVerifiedCert));

	if (algid == KMF_ALGID_SHA1WithDSA) {
		ret = DerDecodeDSASignature(&signed_data, &signature);
		if (ret != KMF_OK)
			goto cleanup;
	} else {
		signature.Data = signed_data.Data;
		signature.Length = signed_data.Length;
	}

	ret = PKCS_VerifyData(handle, algid, pubkey,
		&data_to_verify, &signature);

cleanup:
	KMF_FreeData(&data_to_verify);
	KMF_FreeData(&signed_data);

	if (SignerCert) {
		KMF_FreeSignedCert(SignerCert);
		free(SignerCert);
	}

	if (ToBeVerifiedCert) {
		KMF_FreeSignedCert(ToBeVerifiedCert);
		free(ToBeVerifiedCert);
	}

	if (algid == KMF_ALGID_SHA1WithDSA) {
		free(signature.Data);
	}

	return (ret);
}

KMF_RETURN
SignCsr(KMF_HANDLE_T handle,
	const KMF_DATA *SubjectCsr,
	KMF_KEY_HANDLE	*Signkey,
	KMF_X509_ALGORITHM_IDENTIFIER *algo,
	KMF_DATA	*SignedCsr)
{

	KMF_CSR_DATA	subj_csr;
	KMF_TBS_CSR	*tbs_csr = NULL;
	KMF_DATA	signed_data = {0, NULL};
	KMF_RETURN	ret = KMF_OK;

	if (!SignedCsr)
		return (KMF_ERR_BAD_PARAMETER);

	SignedCsr->Length = 0;
	SignedCsr->Data = NULL;

	if (!SubjectCsr)
	    return (KMF_ERR_BAD_PARAMETER);

	if (!SubjectCsr->Data || !SubjectCsr->Length)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&subj_csr, 0, sizeof (subj_csr));
	/* Estimate the signed data length generously */
	signed_data.Length = SubjectCsr->Length*2;
	signed_data.Data = calloc(1, signed_data.Length);
	if (!signed_data.Data) {
		ret = KMF_ERR_MEMORY;
		goto cleanup;
	}

	/* Sign the data */
	ret = KMF_SignDataWithKey(handle, Signkey, &algo->algorithm,
			(KMF_DATA *)SubjectCsr, &signed_data);

	if (KMF_OK != ret)
		goto cleanup;

	/*
	 * If we got here OK, decode into a structure and then re-encode
	 * the complete CSR.
	 */
	ret = DerDecodeTbsCsr(SubjectCsr, &tbs_csr);
	if (ret)
		goto cleanup;

	(void) memcpy(&subj_csr.csr, tbs_csr, sizeof (KMF_TBS_CSR));

	ret = copy_algoid(&subj_csr.signature.algorithmIdentifier, algo);
	if (ret)
		goto cleanup;

	subj_csr.signature.encrypted = signed_data;

	/* Now, re-encode the CSR with the new signature */
	ret = DerEncodeSignedCsr(&subj_csr, SignedCsr);
	if (ret != KMF_OK) {
		KMF_FreeData(SignedCsr);
		goto cleanup;
	}

	/* Cleanup & return */
cleanup:
	free(tbs_csr);

	KMF_FreeTBSCSR(&subj_csr.csr);

	KMF_FreeAlgOID(&subj_csr.signature.algorithmIdentifier);
	KMF_FreeData(&signed_data);

	return (ret);
}
