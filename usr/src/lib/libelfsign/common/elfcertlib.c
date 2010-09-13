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

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <md5.h>
#include <pthread.h>

#include <cryptoutil.h>

#include <kmfapi.h>
#include <sys/crypto/elfsign.h>
#include <libelfsign.h>

#include <synch.h>

const char _PATH_ELFSIGN_CRYPTO_CERTS[] = CRYPTO_CERTS_DIR;
const char _PATH_ELFSIGN_ETC_CERTS[] = ETC_CERTS_DIR;

/*
 * The CACERT and OBJCACERT are the Cryptographic Trust Anchors
 * for the Solaris Cryptographic Framework.
 *
 * The SECACERT is the Signed Execution Trust Anchor that the
 * Cryptographic Framework uses for FIPS-140 validation of non-crypto
 * binaries
 */
static const char _PATH_CRYPTO_CACERT[] = CRYPTO_CERTS_DIR "/CA";
static const char _PATH_CRYPTO_OBJCACERT[] = CRYPTO_CERTS_DIR "/SUNWObjectCA";
static const char _PATH_CRYPTO_SECACERT[] = ETC_CERTS_DIR "/SUNWSolarisCA";
static ELFCert_t CACERT = NULL;
static ELFCert_t OBJCACERT = NULL;
static ELFCert_t SECACERT = NULL;
static pthread_mutex_t ca_mutex = PTHREAD_MUTEX_INITIALIZER;

static void elfcertlib_freecert(ELFsign_t, ELFCert_t);
static ELFCert_t elfcertlib_allocatecert(void);

/*
 * elfcertlib_verifycert - Verify the Cert with a Trust Anchor
 *
 * IN	ess		- elfsign context structure
 *	cert
 * OUT	NONE
 * RETURN	TRUE/FALSE
 *
 * We first setup the Trust Anchor (CA and SUNWObjectCA) certs
 * if it hasn't been done already.  We verify that the files on disk
 * are those we expected.
 *
 * We then verify the given cert using the publickey of a TA.
 * If the passed in cert is a TA or it has been verified already we
 * short cut and return TRUE without futher validation.
 */
/*ARGSUSED*/
boolean_t
elfcertlib_verifycert(ELFsign_t ess, ELFCert_t cert)
{
	KMF_ATTRIBUTE	attrlist[8];
	int		numattr;

	KMF_RETURN rv;
	if ((cert->c_verified == E_OK) || (cert->c_verified == E_IS_TA)) {
		return (B_TRUE);
	}

	(void) pthread_mutex_lock(&ca_mutex);
	if (CACERT == NULL) {
		(void) elfcertlib_getcert(ess, (char *)_PATH_CRYPTO_CACERT,
		    NULL, &CACERT, ES_GET);
	}

	if (OBJCACERT == NULL) {
		(void) elfcertlib_getcert(ess, (char *)_PATH_CRYPTO_OBJCACERT,
		    NULL, &OBJCACERT, ES_GET);
	}

	if (SECACERT == NULL) {
		(void) elfcertlib_getcert(ess,
		    (char *)_PATH_CRYPTO_SECACERT, NULL, &SECACERT,
		    ES_GET_FIPS140);
	}

	(void) pthread_mutex_unlock(&ca_mutex);

	if (CACERT != NULL) {
		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_CERT_DATA_ATTR, &cert->c_cert.certificate,
		    sizeof (KMF_DATA));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_SIGNER_CERT_DATA_ATTR, &CACERT->c_cert.certificate,
		    sizeof (KMF_DATA));

		rv = kmf_verify_cert(ess->es_kmfhandle, numattr, attrlist);
		if (rv == KMF_OK) {
			if (ess->es_certCAcallback != NULL)
				(ess->es_certvercallback)(ess->es_callbackctx,
				    cert, CACERT);
			cert->c_verified = E_OK;
			return (B_TRUE);
		}
	}

	if (OBJCACERT != NULL) {
		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_CERT_DATA_ATTR, &cert->c_cert.certificate,
		    sizeof (KMF_DATA));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_SIGNER_CERT_DATA_ATTR, &OBJCACERT->c_cert.certificate,
		    sizeof (KMF_DATA));

		rv = kmf_verify_cert(ess->es_kmfhandle, numattr, attrlist);
		if (rv == KMF_OK) {
			if (ess->es_certCAcallback != NULL)
				(ess->es_certvercallback)(ess->es_callbackctx,
				    cert, OBJCACERT);
			cert->c_verified = E_OK;
			return (B_TRUE);
		}
	}

	if (SECACERT != NULL) {
		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_CERT_DATA_ATTR, &cert->c_cert.certificate,
		    sizeof (KMF_DATA));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_SIGNER_CERT_DATA_ATTR, &SECACERT->c_cert.certificate,
		    sizeof (KMF_DATA));

		rv = kmf_verify_cert(ess->es_kmfhandle, numattr, attrlist);
		if (rv == KMF_OK) {
			if (ess->es_certCAcallback != NULL)
				(ess->es_certvercallback)(ess->es_callbackctx,
				    cert, SECACERT);
			cert->c_verified = E_OK;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * elfcertlib_getcert - Get the certificate for signer_DN
 *
 * IN	ess		- elfsign context structure
 *	cert_pathname	- path to cert (May be NULL)
 *	signer_DN	- The DN we are looking for (May be NULL)
 *      action		- indicates crypto verification call
 * OUT  certp		- allocated/loaded ELFCert_t
 *
 * If the cert_pathname is passed use it and don't search.
 * Otherwise, go looking in certificate directories
 */
boolean_t
elfcertlib_getcert(ELFsign_t ess, char *cert_pathname,
    char *signer_DN, ELFCert_t *certp, enum ES_ACTION action)
{
	KMF_RETURN rv;
	ELFCert_t	cert = NULL;
	KMF_X509_DER_CERT certbuf[2];
	uint32_t ncerts;
	boolean_t ret = B_FALSE;
	char	*pathlist[3], **plp;

	cryptodebug("elfcertlib_getcert: path=%s, DN=%s",
	    cert_pathname ? cert_pathname : "-none-",
	    signer_DN ? signer_DN : "-none-");
	*certp = NULL;
	if (cert_pathname == NULL && signer_DN == NULL) {
		cryptodebug("elfcertlib_getcert: lack of specificity");
		return (ret);
	}

	plp = pathlist;
	if (cert_pathname != NULL) {
		/* look in the specified object */
		*plp++ = cert_pathname;
	} else {
		/* look in the certificate directories */
		*plp++ = (char *)_PATH_ELFSIGN_CRYPTO_CERTS;
		/*
		 * crypto verifications don't search beyond
		 * _PATH_ELFSIGN_CRYPTO_CERTS
		 */
		if (action != ES_GET_CRYPTO)
			*plp++ = (char *)_PATH_ELFSIGN_ETC_CERTS;
	}
	*plp = NULL;

	if ((cert = elfcertlib_allocatecert()) == NULL) {
		return (ret);
	}

	for (plp = pathlist; *plp; plp++) {
		KMF_ATTRIBUTE	attrlist[8];
		KMF_KEYSTORE_TYPE	kstype;
		KMF_CERT_VALIDITY	certvalidity;
		int		numattr;

		kstype = KMF_KEYSTORE_OPENSSL;
		certvalidity = KMF_ALL_CERTS;
		ncerts = 2;

		numattr = 0;
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_X509_DER_CERT_ATTR, certbuf,
		    sizeof (KMF_X509_DER_CERT));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_COUNT_ATTR, &ncerts, sizeof (uint32_t));
		if (signer_DN != NULL) {
			kmf_set_attr_at_index(attrlist, numattr++,
			    KMF_SUBJECT_NAME_ATTR, signer_DN,
			    strlen(signer_DN));
		}
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_CERT_VALIDITY_ATTR, &certvalidity,
		    sizeof (KMF_CERT_VALIDITY));
		kmf_set_attr_at_index(attrlist, numattr++,
		    KMF_CERT_FILENAME_ATTR, *plp, strlen (*plp));

		rv = kmf_find_cert(ess->es_kmfhandle, numattr, attrlist);

		if (rv != KMF_OK)
			continue;
		/* found one */
		cert->c_cert = certbuf[0];
		if (ncerts > 1) {
			/* release any extras */
			kmf_free_kmf_cert(ess->es_kmfhandle, &certbuf[1]);
			if (signer_DN == NULL) {
				/* There can be only one */
				cryptodebug("elfcertlib_getcert: "
				    "too many certificates found in %s",
				    cert_pathname);
				goto cleanup;
			}
		}
		/* cache subject and issuer */
		rv = kmf_get_cert_subject_str(ess->es_kmfhandle,
		    &cert->c_cert.certificate, &cert->c_subject);
		if (rv != KMF_OK)
			goto cleanup;

		rv = kmf_get_cert_issuer_str(ess->es_kmfhandle,
		    &cert->c_cert.certificate, &cert->c_issuer);
		if (rv != KMF_OK)
			goto cleanup;
		break;
	}
	if (*plp == NULL) {
		cryptodebug("elfcertlib_getcert: no certificate found");
		goto cleanup;
	}

	cert->c_verified = E_UNCHECKED;

	/*
	 * If the cert we are loading is the trust anchor (ie the CA) then
	 * we mark it as such in cert.  This is so that we don't attempt
	 * to verify it later.  The CA is always implicitly verified.
	 */
	if (cert_pathname != NULL && (
	    strcmp(cert_pathname, _PATH_CRYPTO_CACERT) == 0 ||
	    strcmp(cert_pathname, _PATH_CRYPTO_OBJCACERT) == 0 ||
	    strcmp(cert_pathname, _PATH_CRYPTO_SECACERT) == 0)) {
		if (ess->es_certCAcallback != NULL)
			(ess->es_certCAcallback)(ess->es_callbackctx, cert,
			    cert_pathname);
		cert->c_verified = E_IS_TA;
	}

	ret = B_TRUE;

cleanup:
	if (ret) {
		*certp = cert;
	} else {
		if (cert != NULL)
			elfcertlib_freecert(ess, cert);
		if (signer_DN != NULL)
			cryptoerror(LOG_ERR, "unable to find a certificate "
			    "for DN: %s", signer_DN);
		else
			cryptoerror(LOG_ERR, "unable to load certificate "
			    "from %s", cert_pathname);
	}
	return (ret);
}

/*
 * elfcertlib_loadprivatekey - Load the private key from path
 *
 * IN	ess		- elfsign context structure
 *	cert
 *	pathname
 * OUT	cert
 * RETURNS	TRUE/FALSE
 */
boolean_t
elfcertlib_loadprivatekey(ELFsign_t ess, ELFCert_t cert, const char *pathname)
{
	KMF_RETURN	rv = KMF_OK;
	KMF_KEY_HANDLE	keybuf[2];
	KMF_ATTRIBUTE	attrlist[16];
	uint32_t	nkeys;
	KMF_KEYSTORE_TYPE	kstype;
	KMF_KEY_ALG	keytype;
	KMF_KEY_CLASS	keyclass;
	KMF_ENCODE_FORMAT	format;
	int		numattr;

	kstype = KMF_KEYSTORE_OPENSSL;
	nkeys = 2;
	keytype = KMF_KEYALG_NONE;
	keyclass = KMF_ASYM_PRI;
	format = KMF_FORMAT_UNDEF;

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEY_HANDLE_ATTR,
	    keybuf, sizeof (KMF_KEY_HANDLE));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_COUNT_ATTR,
	    &nkeys, sizeof (uint32_t));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYALG_ATTR,
	    &keytype, sizeof (keytype));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYCLASS_ATTR,
	    &keyclass, sizeof (keyclass));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_ENCODE_FORMAT_ATTR,
	    &format, sizeof (format));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEY_FILENAME_ATTR,
	    (char *)pathname, strlen(pathname));

	rv = kmf_find_key(ess->es_kmfhandle, numattr, attrlist);
	if (rv != KMF_OK)
		return (B_FALSE);
	if (nkeys != 1) {
		/* lack of specificity */
		cryptodebug("found %d keys at %s", nkeys, pathname);
		return (B_FALSE);
	}
	cert->c_privatekey = keybuf[0];
	cryptodebug("key %s loaded", pathname);
	return (B_TRUE);
}

/*
 * elfcertlib_loadtokenkey - Load the private key from token
 *
 * IN	ess		- elfsign context structure
 *	cert
 *	token_label
 *	pin
 * OUT	cert
 * RETURNS	TRUE/FALSE
 */
boolean_t
elfcertlib_loadtokenkey(ELFsign_t ess, ELFCert_t cert,
    const char *token_label, const char *pin)
{
	KMF_RETURN	rv;
	char		*idstr = NULL;
	char		*kmferr;
	KMF_ATTRIBUTE	attrlist[16];
	uint32_t	nkeys;
	KMF_KEYSTORE_TYPE	kstype;
	KMF_KEY_ALG	keytype;
	KMF_KEY_CLASS	keyclass;
	KMF_ENCODE_FORMAT	format;
	KMF_CREDENTIAL	pincred;
	boolean_t	tokenbool, privatebool;
	int		numattr;

	/*
	 * We will search for the key based on the ID attribute
	 * which was added when the key was created.  ID is
	 * a SHA-1 hash of the public modulus shared by the
	 * key and the certificate.
	 */
	rv = kmf_get_cert_id_str(&cert->c_cert.certificate, &idstr);
	if (rv != KMF_OK) {
		(void) kmf_get_kmf_error_str(rv, &kmferr);
		cryptodebug("Error getting ID from cert: %s\n",
		    (kmferr ? kmferr : "Unrecognized KMF error"));
		free(kmferr);
		return (B_FALSE);
	}

	kstype = KMF_KEYSTORE_PK11TOKEN;
	nkeys = 1;
	keytype = KMF_KEYALG_NONE;
	keyclass = KMF_ASYM_PRI;
	format = KMF_FORMAT_UNDEF;
	pincred.cred = (char *)pin;
	pincred.credlen = strlen(pin);
	tokenbool = B_FALSE;
	privatebool = B_TRUE;

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype, sizeof (kstype));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEY_HANDLE_ATTR,
	    &cert->c_privatekey, sizeof (KMF_KEY_HANDLE));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_COUNT_ATTR,
	    &nkeys, sizeof (uint32_t));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYALG_ATTR,
	    &keytype, sizeof (keytype));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYCLASS_ATTR,
	    &keyclass, sizeof (keyclass));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_ENCODE_FORMAT_ATTR,
	    &format, sizeof (format));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_IDSTR_ATTR,
	    idstr, strlen(idstr));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_CREDENTIAL_ATTR,
	    &pincred, sizeof (KMF_CREDENTIAL));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_TOKEN_BOOL_ATTR,
	    &tokenbool, sizeof (tokenbool));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_PRIVATE_BOOL_ATTR,
	    &privatebool, sizeof (privatebool));

	rv = kmf_find_key(ess->es_kmfhandle, numattr, attrlist);
	free(idstr);
	if (rv != KMF_OK) {
		(void) kmf_get_kmf_error_str(rv, &kmferr);
		cryptodebug("Error finding private key: %s\n",
		    (kmferr ? kmferr : "Unrecognized KMF error"));
		free(kmferr);
		return (B_FALSE);
	}
	if (nkeys != 1) {
		cryptodebug("Error finding private key: No key found\n");
		return (B_FALSE);
	}
	cryptodebug("key found in %s", token_label);
	cryptodebug("elfcertlib_loadprivatekey = 0x%.8X",
	    &cert->c_privatekey);

	return (B_TRUE);
}

static const CK_BYTE MD5_DER_PREFIX[] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};

/*
 * elfcertlib_sign - sign the given DATA using the privatekey in cert
 *
 * IN	ess		- elfsign context structure
 *	cert
 *	data
 *	data_len
 * OUT	sig	- must be big enough to hold the signature of data
 *		  Caller must allocate
 *	sig_len	- actual length used; 0 on failure.
 * RETURNS	TRUE/FALSE
 */
/*ARGSUSED*/
boolean_t
elfcertlib_sign(ELFsign_t ess, ELFCert_t cert,
	const uchar_t *data, size_t data_len,
	uchar_t *sig, size_t *sig_len)
{
	KMF_RETURN	ret;
	KMF_DATA	tobesigned;
	KMF_DATA	signature;
	uchar_t		der_data[sizeof (MD5_DER_PREFIX) + MD5_DIGEST_LENGTH];
	KMF_ATTRIBUTE	attrlist[8];
	int		numattr;

	if (ess->es_version <= FILESIG_VERSION2) {
		/* compatibility: take MD5 hash of SHA1 hash */
		size_t	derlen = MD5_DIGEST_LENGTH;
		MD5_CTX ctx;

		/*
		 * first: digest using software-based methods, don't
		 * rely on the token for hashing.
		 */
		MD5Init(&ctx);
		MD5Update(&ctx, data, data_len);
		MD5Final(&der_data[sizeof (MD5_DER_PREFIX)], &ctx);

		/*
		 * second: insert prefix
		 */
		(void) memcpy(der_data, MD5_DER_PREFIX,
		    sizeof (MD5_DER_PREFIX));
		/*
		 * prepare to sign the local buffer
		 */
		tobesigned.Data = (uchar_t *)der_data;
		tobesigned.Length = sizeof (MD5_DER_PREFIX) + derlen;
	} else {
		tobesigned.Data = (uchar_t *)data;
		tobesigned.Length = data_len;
	}

	signature.Data = (uchar_t *)sig;
	signature.Length = *sig_len;

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEYSTORE_TYPE_ATTR, &(cert->c_privatekey.kstype),
	    sizeof (KMF_KEYSTORE_TYPE));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEY_HANDLE_ATTR, &cert->c_privatekey, sizeof (KMF_KEY_HANDLE));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_OID_ATTR, (KMF_OID *)&KMFOID_RSA, sizeof (KMF_OID));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_DATA_ATTR, &tobesigned, sizeof (KMF_DATA));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_OUT_DATA_ATTR, &signature, sizeof (KMF_DATA));

	ret = kmf_sign_data(ess->es_kmfhandle, numattr, attrlist);

	if (ret != KMF_OK) {
		char	*kmferr;

		(void) kmf_get_kmf_error_str(ret, &kmferr);
		cryptodebug("Error signing data: %s\n",
		    (kmferr ? kmferr : "Unrecognized KMF error"));
		free(kmferr);
		*sig_len = 0;
		return (B_FALSE);
	}
	*sig_len = signature.Length;
	return (B_TRUE);
}

/*
 * elfcertlib_verifysig - verify the given DATA using the public key in cert
 *
 * IN	ess		- elfsign context structure
 *	cert
 *	signature
 *	sig_len
 *	data
 *	data_len
 * OUT	N/A
 * RETURNS	TRUE/FALSE
 */
boolean_t
elfcertlib_verifysig(ELFsign_t ess, ELFCert_t cert,
	const uchar_t *signature, size_t sig_len,
	const uchar_t *data, size_t data_len)
{
	KMF_RETURN	rv;
	KMF_DATA	indata;
	KMF_DATA	insig;
	KMF_ALGORITHM_INDEX algid;
	KMF_ATTRIBUTE	attrlist[8];
	KMF_KEYSTORE_TYPE	kstype;
	int		numattr;

	indata.Data = (uchar_t *)data;
	indata.Length = data_len;
	insig.Data = (uchar_t *)signature;
	insig.Length = sig_len;

	if (ess->es_version <= FILESIG_VERSION2)
		algid = KMF_ALGID_MD5WithRSA;
	else
		algid = KMF_ALGID_RSA;

	/*
	 * We tell KMF to use the PKCS11 verification APIs
	 * here to prevent the use of OpenSSL and to keep
	 * all validation within the FIPS-140 boundary for
	 * the Cryptographic Framework.
	 */
	kstype = KMF_KEYSTORE_PK11TOKEN;

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++, KMF_KEYSTORE_TYPE_ATTR,
	    &kstype,  sizeof (kstype));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_DATA_ATTR,
	    &indata, sizeof (KMF_DATA));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_IN_SIGN_ATTR,
	    &insig, sizeof (KMF_DATA));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_SIGNER_CERT_DATA_ATTR,
	    (KMF_DATA *)(&cert->c_cert.certificate), sizeof (KMF_DATA));
	kmf_set_attr_at_index(attrlist, numattr++, KMF_ALGORITHM_INDEX_ATTR,
	    &algid, sizeof (algid));

	rv = kmf_verify_data(ess->es_kmfhandle, numattr, attrlist);

	return ((rv == KMF_OK));
}

/*
 * elfcertlib_getdn
 *
 * IN	cert
 * OUT	NONE
 * RETURN 	dn or NULL
 */
char *
elfcertlib_getdn(ELFCert_t cert)
{
	cryptodebug("elfcertlib_getdn");

	return (cert->c_subject);
}

/*
 * elfcertlib_getissuer
 *
 * IN	cert
 * OUT	NONE
 * RETURN 	dn or NULL
 */
char *
elfcertlib_getissuer(ELFCert_t cert)
{
	cryptodebug("elfcertlib_issuer");

	return (cert->c_issuer);
}

boolean_t
elfcertlib_init(ELFsign_t ess)
{
	boolean_t rc = B_TRUE;
	KMF_RETURN rv;
	if (ess->es_kmfhandle == NULL) {
		rv = kmf_initialize(&ess->es_kmfhandle, NULL, NULL);
		if (rv != KMF_OK) {
			cryptoerror(LOG_ERR,
			    "unable to initialize KMF library");
			rc = B_FALSE;
		}
	}
	return (rc);
}

void
elfcertlib_fini(ELFsign_t ess)
{
	(void) kmf_finalize(ess->es_kmfhandle);
}

/*
 * set the token device
 */
boolean_t
elfcertlib_settoken(ELFsign_t ess, char *token)
{
	boolean_t	rc = B_TRUE;
	KMF_RETURN	rv;
	KMF_ATTRIBUTE	attrlist[8];
	KMF_KEYSTORE_TYPE	kstype;
	boolean_t	readonly;
	int	numattr;

	kstype = KMF_KEYSTORE_PK11TOKEN;
	readonly = B_TRUE;

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_TOKEN_LABEL_ATTR, token, strlen(token));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_READONLY_ATTR, &readonly, sizeof (readonly));

	rv = kmf_configure_keystore(ess->es_kmfhandle, numattr, attrlist);
	if (rv != KMF_OK) {
		cryptoerror(LOG_ERR, "unable to select token\n");
		rc = B_FALSE;
	}

	return (rc);
}

/*
 * set the certificate CA identification callback
 */
void
elfcertlib_setcertCAcallback(ELFsign_t ess,
    void (*cb)(void *, ELFCert_t, char *))
{
	ess->es_certCAcallback = cb;
}

/*
 * set the certificate verification callback
 */
void
elfcertlib_setcertvercallback(ELFsign_t ess,
    void (*cb)(void *, ELFCert_t, ELFCert_t))
{
	ess->es_certvercallback = cb;
}


/*
 * elfcertlib_releasecert - release a cert
 *
 * IN cert
 * OUT cert
 * RETURN	N/A
 *
 */
void
elfcertlib_releasecert(ELFsign_t ess, ELFCert_t cert)
{
	elfcertlib_freecert(ess, cert);
}

/*
 * elfcertlib_allocatecert - create a new ELFCert_t
 *
 * IN N/A
 * OUT	N/A
 * RETURN 	ELFCert_t, NULL on failure.
 */
static ELFCert_t
elfcertlib_allocatecert(void)
{
	ELFCert_t cert = NULL;

	cert = malloc(sizeof (struct ELFCert_s));
	if (cert == NULL) {
		cryptoerror(LOG_ERR,
		    "elfcertlib_allocatecert: malloc failed %s",
		    strerror(errno));
		return (NULL);
	}
	(void) memset(cert, 0, sizeof (struct ELFCert_s));
	cert->c_verified = E_UNCHECKED;
	cert->c_subject = NULL;
	cert->c_issuer = NULL;
	return (cert);
}

/*
 * elfcertlib_freecert - freeup the memory of a cert
 *
 * IN cert
 * OUT cert
 * RETURN	N/A
 *
 */
static void
elfcertlib_freecert(ELFsign_t ess, ELFCert_t cert)
{
	if (cert == NULL)
		return;

	free(cert->c_subject);
	free(cert->c_issuer);

	kmf_free_kmf_cert(ess->es_kmfhandle, &cert->c_cert);
	kmf_free_kmf_key(ess->es_kmfhandle, &cert->c_privatekey);

	free(cert);
}
