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
 */
static const char _PATH_CRYPTO_CACERT[] = CRYPTO_CERTS_DIR "/CA";
static const char _PATH_CRYPTO_OBJCACERT[] = CRYPTO_CERTS_DIR "/SUNWObjectCA";
static ELFCert_t CACERT = NULL;
static ELFCert_t OBJCACERT = NULL;
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
	(void) pthread_mutex_unlock(&ca_mutex);

	if (CACERT != NULL) {
		rv = KMF_VerifyCertWithCert(ess->es_kmfhandle,
		    (const KMF_DATA *)&cert->c_cert,
		    (const KMF_DATA *)&CACERT->c_cert.certificate);
		if (rv == KMF_OK) {
			if (ess->es_certCAcallback != NULL)
				(ess->es_certvercallback)(ess->es_callbackctx,
				    cert, CACERT);
			cert->c_verified = E_OK;
			return (B_TRUE);
		}
	}

	if (OBJCACERT != NULL) {
		rv = KMF_VerifyCertWithCert(ess->es_kmfhandle,
		    (const KMF_DATA *)&cert->c_cert,
		    (const KMF_DATA *)&OBJCACERT->c_cert.certificate);
		if (rv == KMF_OK) {
			if (ess->es_certCAcallback != NULL)
				(ess->es_certvercallback)(ess->es_callbackctx,
				    cert, OBJCACERT);
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
	KMF_FINDCERT_PARAMS fcparams;
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
		(void) memset(&fcparams, 0, sizeof (fcparams));
		fcparams.kstype = KMF_KEYSTORE_OPENSSL;
		fcparams.sslparms.certfile = *plp;
		fcparams.subject = signer_DN;
		ncerts = 2;

		rv = KMF_FindCert(ess->es_kmfhandle, &fcparams, certbuf,
		    &ncerts);
		if (rv != KMF_OK)
			continue;
		if (ncerts > 1 && signer_DN == NULL) {
			/* There can be only one */
			cryptodebug("elfcertlib_getcert: "
			    "too many certificates found in %s",
			    cert_pathname);
			goto cleanup;
		}
		/* found it, cache subject and issuer */
		cert->c_cert = certbuf[0];
		rv = KMF_GetCertSubjectNameString(ess->es_kmfhandle,
		    &cert->c_cert.certificate, &cert->c_subject);
		if (rv != KMF_OK)
			goto cleanup;

		rv = KMF_GetCertIssuerNameString(ess->es_kmfhandle,
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
	 * If the cert we are loading it the trust anchor (ie the CA) then
	 * we mark it as such in cert.  This is so that we don't attempt
	 * to verify it later.  The CA is always implicitly verified.
	 */
	if (cert_pathname != NULL && (
	    strcmp(cert_pathname, _PATH_CRYPTO_CACERT) == 0 ||
	    strcmp(cert_pathname, _PATH_CRYPTO_OBJCACERT) == 0)) {
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
	KMF_RETURN rv = KMF_OK;
	uint32_t nkeys = 2;
	KMF_FINDKEY_PARAMS fkparams;
	KMF_KEY_HANDLE	keybuf[2];

	(void) memset(&fkparams, 0, sizeof (fkparams));
	fkparams.keyclass = KMF_ASYM_PRI;
	fkparams.kstype = KMF_KEYSTORE_OPENSSL;
	fkparams.sslparms.keyfile = (char *)pathname;

	rv = KMF_FindKey(ess->es_kmfhandle, &fkparams, keybuf, &nkeys);
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
	KMF_RETURN rv = KMF_OK;
	KMF_FINDKEY_PARAMS fkparams;
	KMF_CONFIG_PARAMS cfgparams;
	uint32_t nkeys = 1;
	char *idstr = NULL;
	char *err = NULL;

	(void) memset(&fkparams, 0, sizeof (fkparams));
	(void) memset(&cfgparams, 0, sizeof (cfgparams));

	cfgparams.kstype = KMF_KEYSTORE_PK11TOKEN;
	cfgparams.pkcs11config.label = (char *)token_label;
	cfgparams.pkcs11config.readonly = B_TRUE;
	rv = KMF_ConfigureKeystore(ess->es_kmfhandle, &cfgparams);
	if (rv != KMF_OK) {
		if (KMF_GetKMFErrorString(rv, &err) == KMF_OK) {
			cryptodebug("Error configuring token access:"
			    " %s\n", err);
			free(err);
		}
		return (B_FALSE);
	}

	fkparams.idstr = idstr;
	fkparams.kstype = KMF_KEYSTORE_PK11TOKEN;
	fkparams.keyclass = KMF_ASYM_PRI;
	fkparams.cred.cred = (char *)pin;
	fkparams.cred.credlen = (pin != NULL ? strlen(pin) : 0);
	fkparams.pkcs11parms.private = B_TRUE;

	/*
	 * We will search for the key based on the ID attribute
	 * which was added when the key was created.  ID is
	 * a SHA-1 hash of the public modulus shared by the
	 * key and the certificate.
	 */
	rv = KMF_GetCertIDString(&cert->c_cert.certificate, &idstr);
	if (rv != KMF_OK) {
		if (KMF_GetKMFErrorString(rv, &err) == KMF_OK) {
			cryptodebug("Error getting ID from cert: %s\n", err);
			free(err);
		}
		return (B_FALSE);
	}
	fkparams.idstr = idstr;

	rv = KMF_FindKey(ess->es_kmfhandle, &fkparams,
	    &cert->c_privatekey, &nkeys);
	if (rv != KMF_OK || nkeys != 1) {
		if (KMF_GetKMFErrorString(rv, &err) == KMF_OK) {
			cryptodebug("Error finding private key: %s\n", err);
			free(err);
		}
		free(idstr);
		return (B_FALSE);
	}
	cryptodebug("key found in %s", token_label);
	cryptodebug("elfcertlib_loadprivatekey = 0x%.8X",
	    &cert->c_privatekey);

	free(idstr);
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
	KMF_RETURN ret = KMF_OK;
	KMF_DATA tobesigned;
	KMF_DATA signature;
	uchar_t	 der_data[sizeof (MD5_DER_PREFIX) + MD5_DIGEST_LENGTH];

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

	ret = KMF_SignDataWithKey(ess->es_kmfhandle,
	    &cert->c_privatekey, (KMF_OID *)&KMFOID_RSA,
	    &tobesigned, &signature);

	if (ret != KMF_OK) {
		char *err;
		if (KMF_GetKMFErrorString(ret, &err) == KMF_OK &&
		    err != NULL) {
			cryptodebug("Error signing data: %s\n", err);
			free(err);
		}
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

	indata.Data = (uchar_t *)data;
	indata.Length = data_len;
	insig.Data = (uchar_t *)signature;
	insig.Length = sig_len;

	if (ess->es_version <= FILESIG_VERSION2)
		algid = KMF_ALGID_MD5WithRSA;
	else
		algid = KMF_ALGID_RSA;

	/*
	 * We tell KMF to use the OpenSSL verification
	 * APIs here to avoid a circular dependency with
	 * kcfd and libpkcs11.
	 */
	rv = KMF_VerifyDataWithCert(ess->es_kmfhandle,
	    KMF_KEYSTORE_OPENSSL, algid,
	    &indata, &insig, &cert->c_cert.certificate);

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
		rv = KMF_Initialize(&ess->es_kmfhandle, NULL, NULL);
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
	(void) KMF_Finalize(ess->es_kmfhandle);
}

/*
 * set the token device
 */
boolean_t
elfcertlib_settoken(ELFsign_t ess, char *token)
{
	boolean_t rc = B_TRUE;
	KMF_RETURN rv;
	KMF_CONFIG_PARAMS cfgparams;

	(void) memset(&cfgparams, 0, sizeof (cfgparams));
	cfgparams.kstype = KMF_KEYSTORE_PK11TOKEN;
	cfgparams.pkcs11config.label = token;
	cfgparams.pkcs11config.readonly = B_TRUE;
	rv = KMF_ConfigureKeystore(ess->es_kmfhandle, &cfgparams);
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

	KMF_FreeKMFCert(ess->es_kmfhandle, &cert->c_cert);
	KMF_FreeKMFKey(ess->es_kmfhandle, &cert->c_privatekey);

	free(cert);
}
