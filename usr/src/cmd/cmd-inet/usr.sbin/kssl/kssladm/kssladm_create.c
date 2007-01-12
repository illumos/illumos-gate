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

#include <errno.h>
#include <sys/sysmacros.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <inet/kssl/kssl.h>
#include <cryptoutil.h>
#include <libscf.h>
#include "kssladm.h"

#include <kmfapi.h>

void
usage_create(boolean_t do_print)
{
	if (do_print)
		(void) fprintf(stderr, "Usage:\n");
	(void) fprintf(stderr, "kssladm create"
		" -f pkcs11 [-d softtoken_directory] -T <token_label>"
		" -C <certificate_label> -x <proxy_port>"
		" [-h <ca_certchain_file>]"
		" [options] [<server_address>] [<server_port>]\n");

	(void) fprintf(stderr, "kssladm create"
		" -f pkcs12 -i <cert_and_key_pk12file> -x <proxy_port>"
		" [options] [<server_address>] [<server_port>]\n");

	(void) fprintf(stderr, "kssladm create"
		" -f pem -i <cert_and_key_pemfile> -x <proxy_port>"
		" [options] [<server_address>] [<server_port>]\n");

	(void) fprintf(stderr, "options are:\n"
		"\t[-c <ciphersuites>]\n"
		"\t[-p <password_file>]\n"
		"\t[-t <ssl_session_cache_timeout>]\n"
		"\t[-z <ssl_session_cache_size>]\n"
		"\t[-v]\n");
}

/*
 * Everything is allocated in one single contiguous buffer.
 * The layout is the following:
 * . the kssl_params_t structure
 * . optional buffer containing pin (if key is non extractable)
 * . the array of key attribute structs, (value of ck_attrs)
 * . the key attributes values (values of ck_attrs[i].ck_value);
 * . the array of sizes of the certificates, (referred to as sc_sizes[])
 * . the certificates values (referred to as sc_certs[])
 *
 * The address of the certs and key attributes values are offsets
 * from the beginning of the big buffer. sc_sizes_offset points
 * to sc_sizes[0] and sc_certs_offset points to sc_certs[0].
 */
static kssl_params_t *
kmf_to_kssl(int nxkey, KMF_RAW_KEY_DATA *rsa, int ncerts,
	KMF_DATA *certs, int *paramsize, char *token_label, KMF_DATA *idstr,
	KMF_CREDENTIAL *creds)
{
	int i, tcsize;
	kssl_params_t *kssl_params;
	kssl_key_t *key;
	char *buf;
	uint32_t bufsize;
	static CK_BBOOL true = TRUE;
	static CK_BBOOL false = FALSE;
	static CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE keytype = CKK_RSA;
	kssl_object_attribute_t kssl_attrs[MAX_ATTR_CNT];
	CK_ATTRIBUTE exkey_attrs[MAX_ATTR_CNT] = {
		{CKA_TOKEN, &true, sizeof (true)},
		{CKA_EXTRACTABLE, &false, sizeof (false)},
		{CKA_CLASS,	&class, sizeof (class) },
		{CKA_KEY_TYPE,	&keytype, sizeof (keytype) },
		{CKA_ID,	NULL, 0}
	};
	kssl_object_attribute_t kssl_tmpl_attrs[MAX_ATTR_CNT] = {
		{SUN_CKA_MODULUS, NULL, 0},
		{SUN_CKA_PUBLIC_EXPONENT, NULL, 0},
		{SUN_CKA_PRIVATE_EXPONENT, NULL, 0},
		{SUN_CKA_PRIME_1, NULL, 0},
		{SUN_CKA_PRIME_2, NULL, 0},
		{SUN_CKA_EXPONENT_1, NULL, 0},
		{SUN_CKA_EXPONENT_2, NULL, 0},
		{SUN_CKA_COEFFICIENT, NULL, 0}
	};
	KMF_BIGINT priv_key_bignums[MAX_ATTR_CNT];
	int attr_cnt;

	if (nxkey && idstr != NULL) {
		exkey_attrs[4].pValue = idstr->Data;
		exkey_attrs[4].ulValueLen = idstr->Length;
	}
	tcsize = 0;
	for (i = 0; i < ncerts; i++)
		tcsize += certs[i].Length;

	bufsize = sizeof (kssl_params_t);
	bufsize += (tcsize + (MAX_CHAIN_LENGTH * sizeof (uint32_t)));

	if (!nxkey) {
		bzero(priv_key_bignums, sizeof (KMF_BIGINT) *
			MAX_ATTR_CNT);
		/* and the key attributes */
		priv_key_bignums[0] = rsa->rawdata.rsa.mod;
		priv_key_bignums[1] = rsa->rawdata.rsa.pubexp;
		priv_key_bignums[2] = rsa->rawdata.rsa.priexp;
		priv_key_bignums[3] = rsa->rawdata.rsa.prime1;
		priv_key_bignums[4] = rsa->rawdata.rsa.prime2;
		priv_key_bignums[5] = rsa->rawdata.rsa.exp1;
		priv_key_bignums[6] = rsa->rawdata.rsa.exp2;
		priv_key_bignums[7] = rsa->rawdata.rsa.coef;

		if (rsa->rawdata.rsa.mod.val == NULL ||
			rsa->rawdata.rsa.priexp.val == NULL) {
			(void) fprintf(stderr,
			    "missing required attributes in private key.\n");
			return (NULL);
		}

		attr_cnt = 0;
		for (i = 0; i < MAX_ATTR_CNT; i++) {
			if (priv_key_bignums[i].val == NULL)
				continue;
			kssl_attrs[attr_cnt].ka_type =
				kssl_tmpl_attrs[i].ka_type;
			kssl_attrs[attr_cnt].ka_value_len =
				priv_key_bignums[i].len;
			bufsize += sizeof (crypto_object_attribute_t) +
			    kssl_attrs[attr_cnt].ka_value_len;
			attr_cnt++;
		}
	} else {
		/*
		 * Compute space for the attributes and values that the
		 * kssl kernel module will need in order to search for
		 * the private key.
		 */
		for (attr_cnt = 0; attr_cnt < 5; attr_cnt++) {
			bufsize += sizeof (crypto_object_attribute_t) +
				exkey_attrs[attr_cnt].ulValueLen;
		}
		if (creds)
			bufsize += creds->credlen;
	}

	/* Add 4-byte cushion as sc_sizes[0] needs 32-bit alignment */
	bufsize += sizeof (uint32_t);

	/* Now the big memory allocation */
	if ((buf = calloc(bufsize, 1)) == NULL) {
		(void) fprintf(stderr,
		    "Cannot allocate memory for the kssl_params "
		    "and values\n");
		return (NULL);
	}

	/* LINTED */
	kssl_params = (kssl_params_t *)buf;

	buf = (char *)(kssl_params + 1);

	if (!nxkey) {
		/* the keys attributes structs array */
		key = &kssl_params->kssl_privkey;
		key->ks_format = CRYPTO_KEY_ATTR_LIST;
		key->ks_count = attr_cnt;
		key->ks_attrs_offset = buf - (char *)kssl_params;
		buf += attr_cnt * sizeof (kssl_object_attribute_t);

		attr_cnt = 0;
		/* then the key attributes values */
		for (i = 0; i < MAX_ATTR_CNT; i++) {
			if (priv_key_bignums[i].val == NULL)
				continue;
			(void) memcpy(buf, priv_key_bignums[i].val,
				priv_key_bignums[i].len);
			kssl_attrs[attr_cnt].ka_value_offset =
			    buf - (char *)kssl_params;
			buf += kssl_attrs[attr_cnt].ka_value_len;
			attr_cnt++;
		}
	} else {
		char tlabel[CRYPTO_EXT_SIZE_LABEL];
		bzero(tlabel, sizeof (tlabel));
		(void) strlcpy(tlabel, token_label, sizeof (tlabel));

		/*
		 * For a non-extractable key, we must provide the PIN
		 * so the kssl module can access the token to find
		 * the key handle.
		 */
		kssl_params->kssl_is_nxkey = 1;
		bcopy(tlabel, kssl_params->kssl_token.toklabel,
			CRYPTO_EXT_SIZE_LABEL);
		kssl_params->kssl_token.pinlen = creds->credlen;
		kssl_params->kssl_token.tokpin_offset =
			buf - (char *)kssl_params;
		kssl_params->kssl_token.ck_rv = 0;
		bcopy(creds->cred, buf, creds->credlen);
		buf += creds->credlen;

		/*
		 * Next in the buffer, we must provide the attributes
		 * that the kssl module will use to search in the
		 * token to find the protected key handle.
		 */
		key = &kssl_params->kssl_privkey;
		key->ks_format = CRYPTO_KEY_ATTR_LIST;
		key->ks_count = attr_cnt;
		key->ks_attrs_offset = buf - (char *)kssl_params;

		buf += attr_cnt * sizeof (kssl_object_attribute_t);
		for (i = 0; i < attr_cnt; i++) {
			bcopy(exkey_attrs[i].pValue, buf,
				exkey_attrs[i].ulValueLen);

			kssl_attrs[i].ka_type = exkey_attrs[i].type;
			kssl_attrs[i].ka_value_offset =
				buf - (char *)kssl_params;
			kssl_attrs[i].ka_value_len = exkey_attrs[i].ulValueLen;

			buf += exkey_attrs[i].ulValueLen;
		}
	}
	/* Copy the key attributes array here */
	bcopy(kssl_attrs, ((char *)kssl_params) + key->ks_attrs_offset,
		attr_cnt * sizeof (kssl_object_attribute_t));

	buf = (char *)P2ROUNDUP((uintptr_t)buf, sizeof (uint32_t));

	/*
	 * Finally, add the certificate chain to the buffer.
	 */
	kssl_params->kssl_certs.sc_count = ncerts;

	/* First, an array of certificate sizes */
	for (i = 0; i < ncerts; i++) {
		uint32_t certsz = (uint32_t)certs[i].Length;
		char *p = buf + (i * sizeof (uint32_t));
		bcopy(&certsz, p, sizeof (uint32_t));
	}

	kssl_params->kssl_certs.sc_sizes_offset = buf - (char *)kssl_params;
	buf += MAX_CHAIN_LENGTH * sizeof (uint32_t);

	kssl_params->kssl_certs.sc_certs_offset = buf - (char *)kssl_params;

	/* Now add the certificate data (ASN.1 DER encoded) */
	for (i = 0; i < ncerts; i++) {
		bcopy(certs[i].Data, buf, certs[i].Length);
		buf += certs[i].Length;
	}

	*paramsize = bufsize;
	return (kssl_params);
}

/*
 * Extract a sensitive key via wrap/unwrap operations.
 *
 * This function requires that we call PKCS#11 API directly since
 * KMF does not yet support wrapping/unwrapping of keys.   By extracting
 * a sensitive key in wrapped form, we then unwrap it into a session key
 * object.  KMF is then used to find the session key and return it in
 * KMF_RAW_KEY format which is then passed along to KSSL by the caller.
 */
static KMF_RETURN
get_sensitive_key_data(KMF_HANDLE_T kmfh, KMF_FINDKEY_PARAMS *fkparams,
	KMF_KEY_HANDLE *key, KMF_KEY_HANDLE *rawkey)
{
	KMF_RETURN rv = KMF_OK;
	static CK_BYTE aes_param[16];
	static CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE privkey_type = CKK_RSA;
	static CK_BBOOL true = TRUE;
	static CK_BBOOL false = FALSE;
	char *err = NULL;
	char wrapkey_label[BUFSIZ];
	int fd;
	uint32_t nkeys = 0;
	CK_RV ckrv;
	CK_SESSION_HANDLE pk11session;
	CK_BYTE aes_key_val[16];

	CK_MECHANISM aes_cbc_pad_mech = {CKM_AES_CBC_PAD, aes_param,
		sizeof (aes_param)};
	CK_OBJECT_HANDLE aes_key_obj = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE sess_privkey_obj = CK_INVALID_HANDLE;
	CK_BYTE *wrapped_privkey = NULL;
	CK_ULONG wrapped_privkey_len = 0;

	CK_ATTRIBUTE unwrap_tmpl[] = {
		/* code below depends on the following attribute order */
		{CKA_TOKEN, &false, sizeof (false)},
		{CKA_CLASS, &privkey_class, sizeof (privkey_class)},
		{CKA_KEY_TYPE, &privkey_type, sizeof (privkey_type)},
		{CKA_SENSITIVE, &false, sizeof (false)},
		{CKA_PRIVATE, &false, sizeof (false)},
		{CKA_LABEL, NULL, 0}
	};

	/*
	 * Create a wrap key with random data.
	 */
	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		perror("Error reading /dev/urandom");
		return (KMF_ERR_INTERNAL);
	}
	if (read(fd, aes_key_val, sizeof (aes_key_val)) !=
		sizeof (aes_key_val)) {
		perror("Error reading from /dev/urandom");
		(void) close(fd);
		return (KMF_ERR_INTERNAL);
	}
	(void) close(fd);

	pk11session = KMF_GetPK11Handle(kmfh);

	/*
	 * Login to create the wrap key stuff.
	 */
	ckrv = C_Login(pk11session, CKU_USER,
		(CK_UTF8CHAR_PTR)fkparams->cred.cred,
		fkparams->cred.credlen);
	if (ckrv != CKR_OK && ckrv != CKR_USER_ALREADY_LOGGED_IN) {
		(void) fprintf(stderr,
			"Cannot login to the token. error = %s\n",
			pkcs11_strerror(ckrv));
		return (KMF_ERR_INTERNAL);
	}

	/*
	 * Turn the random key into a PKCS#11 session object.
	 */
	ckrv = SUNW_C_KeyToObject(pk11session, CKM_AES_CBC_PAD, aes_key_val,
		sizeof (aes_key_val), &aes_key_obj);
	if (ckrv != CKR_OK) {
		(void) fprintf(stderr,
			"Cannot create wrapping key. error = %s\n",
			pkcs11_strerror(ckrv));
		return (KMF_ERR_INTERNAL);
	}

	/*
	 * Find the original private key that we are going to wrap.
	 */
	rv = KMF_FindKey(kmfh, fkparams, key, &nkeys);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error finding private key", err);
		goto out;
	}

	/*
	 * Get the size of the wrapped private key.
	 */
	bzero(aes_param, sizeof (aes_param));
	ckrv = C_WrapKey(pk11session, &aes_cbc_pad_mech,
		aes_key_obj, (CK_OBJECT_HANDLE)key->keyp,
		NULL, &wrapped_privkey_len);
	if (ckrv != CKR_OK) {
		/*
		 * Most common error here is that the token doesn't
		 * support the wrapping mechanism or the key is
		 * marked non-extractable.  Return an error and let
		 * the caller deal with it gracefully.
		 */
		(void) fprintf(stderr,
			"Cannot get wrap key size. error = %s\n",
			pkcs11_strerror(ckrv));
		rv = KMF_ERR_INTERNAL;
		goto out;
	}
	wrapped_privkey = malloc(wrapped_privkey_len);
	if (wrapped_privkey == NULL) {
		rv = KMF_ERR_MEMORY;
		goto out;
	}
	/*
	 * Now get the actual wrapped key data.
	 */
	ckrv = C_WrapKey(pk11session, &aes_cbc_pad_mech,
		aes_key_obj, (CK_OBJECT_HANDLE)key->keyp,
		wrapped_privkey, &wrapped_privkey_len);
	if (ckrv != CKR_OK) {
		(void) fprintf(stderr,
			"Cannot wrap private key. error = %s\n",
			pkcs11_strerror(ckrv));
		rv = KMF_ERR_INTERNAL;
		goto out;
	}
	/*
	 * Create a label for the wrapped session key so we can find
	 * it easier later.
	 */
	snprintf(wrapkey_label, sizeof (wrapkey_label), "ksslprikey_%d",
		getpid());

	unwrap_tmpl[5].pValue = wrapkey_label;
	unwrap_tmpl[5].ulValueLen = strlen(wrapkey_label);

	/*
	 * Unwrap the key into the template and create a temporary
	 * session private key.
	 */
	ckrv = C_UnwrapKey(pk11session, &aes_cbc_pad_mech, aes_key_obj,
		wrapped_privkey, wrapped_privkey_len,
		unwrap_tmpl, 6, &sess_privkey_obj);
	if (ckrv != CKR_OK) {
		(void) fprintf(stderr,
			"Cannot unwrap private key. error = %s\n",
			pkcs11_strerror(ckrv));
		rv = KMF_ERR_INTERNAL;
		goto out;
	}

	/*
	 * Use KMF to find the session key and return it as RAW data
	 * so we can pass it along to KSSL.
	 */
	fkparams->kstype = KMF_KEYSTORE_PK11TOKEN;
	fkparams->keyclass = KMF_ASYM_PRI;
	fkparams->format = KMF_FORMAT_RAWKEY;
	fkparams->findLabel = wrapkey_label;
	fkparams->pkcs11parms.sensitive = FALSE;
	fkparams->pkcs11parms.private = FALSE;
	fkparams->pkcs11parms.token = FALSE; /* <-- very important! */

	rv = KMF_FindKey(kmfh, fkparams, rawkey, &nkeys);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error finding raw private key", err);
		goto out;
	}
out:
	if (wrapped_privkey)
		free(wrapped_privkey);

	if (aes_key_obj != CK_INVALID_HANDLE)
		C_DestroyObject(pk11session, aes_key_obj);

	if (sess_privkey_obj != CK_INVALID_HANDLE)
		C_DestroyObject(pk11session, sess_privkey_obj);

	return (rv);
}

static kssl_params_t *
load_from_pkcs11(const char *token_label, const char *password_file,
    const char *certname, int *bufsize)
{
	KMF_RETURN rv;
	KMF_HANDLE_T kmfh;
	KMF_X509_DER_CERT cert;
	KMF_KEY_HANDLE key, rawkey;
	KMF_CREDENTIAL creds;
	KMF_FINDCERT_PARAMS fcparams;
	KMF_FINDKEY_PARAMS fkparams;
	KMF_CONFIG_PARAMS cfgparams;
	KMF_DATA iddata = { NULL, 0 };
	kssl_params_t *kssl_params = NULL;
	uint32_t ncerts, nkeys;
	char *err, *idstr = NULL;
	char password_buf[1024];
	int nxkey = 0;

	rv = KMF_Initialize(&kmfh, NULL, NULL);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error initializing KMF", err);
		return (0);
	}
	if (get_passphrase(password_file, password_buf,
		sizeof (password_buf)) <= 0) {
		perror("Unable to read passphrase");
		goto done;
	}
	creds.cred = password_buf;
	creds.credlen = strlen(password_buf);

	bzero(&cfgparams, sizeof (cfgparams));
	bzero(&fcparams, sizeof (fcparams));
	bzero(&fkparams, sizeof (fkparams));

	cfgparams.kstype = KMF_KEYSTORE_PK11TOKEN;
	cfgparams.pkcs11config.label = (char *)token_label;
	cfgparams.pkcs11config.readonly = B_FALSE;

	rv = KMF_ConfigureKeystore(kmfh, &cfgparams);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error configuring KMF keystore", err);
		goto done;
	}

	/*
	 * Find the certificate matching the given label.
	 */
	fcparams.kstype = KMF_KEYSTORE_PK11TOKEN;
	fcparams.certLabel = (char *)certname;
	rv = KMF_FindCert(kmfh, &fcparams, &cert, &ncerts);
	if (rv != KMF_OK || ncerts == 0)
		goto done;

	/*
	 * Find the associated private key for this cert by
	 * keying off of the label and the ASCII ID string.
	 */
	rv = KMF_GetCertIDString(&cert.certificate, &idstr);
	if (rv != KMF_OK)
		goto done;

	fkparams.kstype = KMF_KEYSTORE_PK11TOKEN;
	fkparams.keyclass = KMF_ASYM_PRI;
	fkparams.cred = creds;
	fkparams.format = KMF_FORMAT_RAWKEY;
	fkparams.findLabel = (char *)certname;
	fkparams.idstr = idstr;
	fkparams.pkcs11parms.private = TRUE;
	fkparams.pkcs11parms.token = TRUE;

	rv = KMF_FindKey(kmfh, &fkparams, &key, &nkeys);
	if (rv == KMF_ERR_SENSITIVE_KEY) {
		KMF_FreeKMFKey(kmfh, &key);
		/*
		 * Get a normal key handle and then do a wrap/unwrap
		 * in order to get the necessary raw data fields needed
		 * to send to KSSL.
		 */
		fkparams.format = KMF_FORMAT_NATIVE;
		rv = get_sensitive_key_data(kmfh, &fkparams, &key, &rawkey);
		if (rv == KMF_OK) {
			/* Swap "key" for "rawkey" */
			KMF_FreeKMFKey(kmfh, &key);

			key = rawkey;
		} else {
			KMF_FreeKMFKey(kmfh, &key);

			/* Let kssl try to find the key. */
			nxkey = 1;
			rv = KMF_GetCertIDData(&cert.certificate, &iddata);
		}
	} else if (rv == KMF_ERR_UNEXTRACTABLE_KEY) {
			KMF_FreeKMFKey(kmfh, &key);

			/* Let kssl try to find the key. */
			nxkey = 1;
			rv = KMF_GetCertIDData(&cert.certificate, &iddata);
	} else if (rv != KMF_OK || nkeys == 0)
		goto done;

	if (rv == KMF_OK)
		kssl_params = kmf_to_kssl(nxkey, (KMF_RAW_KEY_DATA *)key.keyp,
			1, &cert.certificate, bufsize,
			(char *)token_label, &iddata, &creds);
done:
	if (ncerts != 0)
		KMF_FreeKMFCert(kmfh, &cert);
	if (nkeys != 0)
		KMF_FreeKMFKey(kmfh, &key);
	if (idstr)
		free(idstr);

	if (kmfh != NULL)
		(void) KMF_Finalize(kmfh);

	return (kssl_params);
}

/*
 * add_cacerts
 *
 * Load a chain of certificates from a PEM file.
 */
static kssl_params_t *
add_cacerts(kssl_params_t *old_params, const char *cacert_chain_file)
{
	int i, newlen;
	uint32_t certlen = 0, ncerts;
	char *buf;
	KMF_RETURN rv;
	KMF_X509_DER_CERT *certs = NULL;
	KMF_FINDCERT_PARAMS fcparms;
	kssl_params_t *kssl_params;
	KMF_HANDLE_T kmfh;
	char *err = NULL;

	bzero(&fcparms, sizeof (fcparms));
	fcparms.kstype = KMF_KEYSTORE_OPENSSL;
	fcparms.sslparms.certfile = (char *)cacert_chain_file;

	rv = KMF_Initialize(&kmfh, NULL, NULL);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error initializing KMF", err);
		return (0);
	}
	rv = KMF_FindCert(kmfh, &fcparms, NULL, &ncerts);
	if (rv != KMF_OK) {
		REPORT_KMF_ERROR(rv, "Error finding CA certificates", err);
		(void) KMF_Finalize(kmfh);
		return (0);
	}
	certs = (KMF_X509_DER_CERT *)malloc(ncerts *
		sizeof (KMF_X509_DER_CERT));
	if (certs == NULL) {
		(void) fprintf(stderr, "memory allocation error.\n");
		(void) KMF_Finalize(kmfh);
		return (NULL);
	}
	bzero(certs, ncerts * sizeof (KMF_X509_DER_CERT));
	rv = KMF_FindCert(kmfh, &fcparms, certs, &ncerts);

	(void) KMF_Finalize(kmfh);

	if (rv != KMF_OK || ncerts == 0) {
		bzero(old_params, old_params->kssl_params_size);
		free(old_params);
		return (NULL);
	}

	if (verbose) {
		(void) printf("%d certificates read successfully\n", ncerts);
	}

	newlen = old_params->kssl_params_size;
	for (i = 0; i < ncerts; i++)
		newlen += certs[i].certificate.Length;

	/*
	 * Get a bigger structure and update the
	 * fields to account for the additional certs.
	 */
	kssl_params = realloc(old_params, newlen);

	kssl_params->kssl_params_size = newlen;
	kssl_params->kssl_certs.sc_count += ncerts;

	/* Put the cert size info starting from sc_sizes[1] */
	buf = (char *)kssl_params;
	buf += kssl_params->kssl_certs.sc_sizes_offset;
	bcopy(buf, &certlen, sizeof (uint32_t));
	buf += sizeof (uint32_t);
	for (i = 0; i < ncerts; i++) {
		uint32_t size = (uint32_t)certs[i].certificate.Length;
		bcopy(&size, buf, sizeof (uint32_t));
		buf += sizeof (uint32_t);
	}

	/* Put the cert_bufs starting from sc_certs[1] */
	buf = (char *)kssl_params;
	buf += kssl_params->kssl_certs.sc_certs_offset;
	buf += certlen;

	/* now the certs values */
	for (i = 0; i < ncerts; i++) {
		bcopy(certs[i].certificate.Data, buf,
			certs[i].certificate.Length);
		buf += certs[i].certificate.Length;
	}

	for (i = 0; i < ncerts; i++)
		KMF_FreeKMFCert(kmfh, &certs[i]);
	free(certs);

	return (kssl_params);
}

/*
 * Find a key and certificate(s) from a single PEM file.
 */
static kssl_params_t *
load_from_pem(const char *filename, const char *password_file, int *paramsize)
{
	int ncerts = 0, i;
	kssl_params_t *kssl_params;
	KMF_RAW_KEY_DATA *rsa = NULL;
	KMF_DATA *certs = NULL;

	ncerts = PEM_get_rsa_key_certs(filename, (char *)password_file,
		&rsa, &certs);
	if (rsa == NULL || certs == NULL || ncerts == 0) {
		return (NULL);
	}

	if (verbose)
		(void) printf("%d certificates read successfully\n", ncerts);

	kssl_params = kmf_to_kssl(0, rsa, ncerts, certs, paramsize, NULL,
		NULL, NULL);

	for (i = 0; i < ncerts; i++)
		KMF_FreeData(&certs[i]);
	free(certs);
	KMF_FreeRawKey(rsa);

	return (kssl_params);
}

/*
 * Load a raw key and certificate(s) from a PKCS#12 file.
 */
static kssl_params_t *
load_from_pkcs12(const char *filename, const char *password_file,
    int *paramsize)
{
	KMF_RAW_KEY_DATA *rsa = NULL;
	kssl_params_t *kssl_params;
	KMF_DATA *certs = NULL;
	int ncerts = 0, i;

	ncerts = PKCS12_get_rsa_key_certs(filename,
		password_file, &rsa, &certs);

	if (certs == NULL || ncerts == 0) {
		(void) fprintf(stderr,
		    "Unable to read cert and/or key from %s\n", filename);
		return (NULL);
	}

	if (verbose)
		(void) printf("%d certificates read successfully\n", ncerts);

	kssl_params = kmf_to_kssl(0, rsa, ncerts, certs, paramsize, NULL,
		NULL, NULL);

	for (i = 0; i < ncerts; i++)
		KMF_FreeData(&certs[i]);
	free(certs);

	KMF_FreeRawKey(rsa);
	return (kssl_params);
}

int
parse_and_set_addr(char *server_address, char *server_port,
    struct sockaddr_in *addr)
{
	if (server_port == NULL) {
		return (-1);
	}

	if (server_address == NULL) {
		addr->sin_addr.s_addr = INADDR_ANY;
	} else {
		addr->sin_addr.s_addr = inet_addr(server_address);
		if ((int)addr->sin_addr.s_addr == -1) {
			struct hostent *hp;

			if ((hp = gethostbyname(server_address)) == NULL) {
				(void) fprintf(stderr,
				    "Error: Unknown host: %s\n",
				    server_address);
				return (-1);
			}

			(void) memcpy(&addr->sin_addr.s_addr,
			    hp->h_addr_list[0],
			    sizeof (addr->sin_addr.s_addr));
		}
	}

	errno = 0;
	addr->sin_port = strtol(server_port, NULL, 10);
	if (addr->sin_port == 0 || errno != 0) {
		(void) fprintf(stderr, "Error: Invalid Port value: %s\n",
		    server_port);
		return (-1);
	}

	return (0);
}

/*
 * The order of the ciphers is important. It is used as the
 * default order (when -c is not specified).
 */
struct csuite {
	const char *suite;
	uint16_t val;
	boolean_t seen;
} cipher_suites[CIPHER_SUITE_COUNT - 1] = {
	{"rsa_rc4_128_sha", SSL_RSA_WITH_RC4_128_SHA, B_FALSE},
	{"rsa_rc4_128_md5", SSL_RSA_WITH_RC4_128_MD5, B_FALSE},
	{"rsa_3des_ede_cbc_sha", SSL_RSA_WITH_3DES_EDE_CBC_SHA, B_FALSE},
	{"rsa_des_cbc_sha", SSL_RSA_WITH_DES_CBC_SHA, B_FALSE},
};

static int
check_suites(char *suites, uint16_t *sarray)
{
	int i;
	int err = 0;
	char *suite;
	int sindx = 0;

	if (suites != NULL) {
		for (i = 0; i < CIPHER_SUITE_COUNT - 1; i++)
			sarray[i] = CIPHER_NOTSET;
	} else {
		for (i = 0; i < CIPHER_SUITE_COUNT - 1; i++)
			sarray[i] = cipher_suites[i].val;
		return (err);
	}

	suite = strtok(suites, ",");
	do {
		for (i = 0; i < CIPHER_SUITE_COUNT - 1; i++) {
			if (strcasecmp(suite, cipher_suites[i].suite) == 0) {
				if (!cipher_suites[i].seen) {
					sarray[sindx++] = cipher_suites[i].val;
					cipher_suites[i].seen = B_TRUE;
				}
				break;
			}
		}

		if (i == (CIPHER_SUITE_COUNT - 1)) {
			(void) fprintf(stderr,
			    "Unknown Cipher suite name: %s\n", suite);
			err++;
		}
	} while ((suite = strtok(NULL, ",")) != NULL);

	return (err);
}

int
do_create(int argc, char *argv[])
{
	const char *softtoken_dir = NULL;
	const char *token_label = NULL;
	const char *password_file = NULL;
	const char *cert_key_file = NULL;
	const char *cacert_chain_file = NULL;
	const char *certname = NULL;
	char *suites = NULL;
	uint32_t timeout = DEFAULT_SID_TIMEOUT;
	uint32_t scache_size = DEFAULT_SID_CACHE_NENTRIES;
	uint16_t kssl_suites[CIPHER_SUITE_COUNT - 1];
	int proxy_port = -1;
	struct sockaddr_in server_addr;
	char *format = NULL;
	char *port, *addr;
	char c;
	int pcnt;
	kssl_params_t *kssl_params;
	int bufsize;

	argc -= 1;
	argv += 1;

	while ((c = getopt(argc, argv, "vT:d:f:h:i:p:c:C:t:x:z:")) != -1) {
		switch (c) {
		case 'd':
			softtoken_dir = optarg;
			break;
		case 'c':
			suites = optarg;
			break;
		case 'C':
			certname = optarg;
			break;
		case 'f':
			format = optarg;
			break;
		case 'h':
			cacert_chain_file = optarg;
			break;
		case 'i':
			cert_key_file = optarg;
			break;
		case 'T':
			token_label = optarg;
			break;
		case 'p':
			password_file = optarg;
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'x':
			proxy_port = atoi(optarg);
			break;
		case 'v':
			verbose = B_TRUE;
			break;
		case 'z':
			scache_size = atoi(optarg);
			break;
		default:
			goto err;
		}
	}

	pcnt = argc - optind;
	if (pcnt == 0) {
		port = "443";	/* default SSL port */
		addr = NULL;
	} else if (pcnt == 1) {
		port = argv[optind];
		addr = NULL;
	} else if (pcnt == 2) {
		addr = argv[optind];
		port = argv[optind + 1];
	} else {
		goto err;
	}

	if (parse_and_set_addr(addr, port, &server_addr) < 0) {
		goto err;
	}

	if (verbose) {
		(void) printf("addr=%s, port = %d\n",
		    inet_ntoa(server_addr.sin_addr), server_addr.sin_port);
	}

	if (format == NULL || proxy_port == -1) {
		goto err;
	}

	if (check_suites(suites, kssl_suites) != 0) {
		goto err;
	}

	if (strcmp(format, "pkcs11") == 0) {
		if (token_label == NULL || certname == NULL) {
			goto err;
		}
		if (softtoken_dir != NULL) {
			(void) setenv("SOFTTOKEN_DIR", softtoken_dir, 1);
			if (verbose) {
				(void) printf(
				    "SOFTTOKEN_DIR=%s\n",
				    getenv("SOFTTOKEN_DIR"));
			}
		}
		kssl_params = load_from_pkcs11(
		    token_label, password_file, certname, &bufsize);
	} else if (strcmp(format, "pkcs12") == 0) {
		if (cert_key_file == NULL) {
			goto err;
		}
		kssl_params = load_from_pkcs12(
		    cert_key_file, password_file, &bufsize);
	} else if (strcmp(format, "pem") == 0) {
		if (cert_key_file == NULL) {
			goto err;
		}
		kssl_params = load_from_pem(
		    cert_key_file, password_file, &bufsize);
	} else {
		(void) fprintf(stderr, "Unsupported cert format: %s\n", format);
		goto err;
	}

	if (kssl_params == NULL) {
		return (FAILURE);
	}

	/*
	 * Add the list of supported ciphers to the buffer.
	 */
	bcopy(kssl_suites, kssl_params->kssl_suites,
	    sizeof (kssl_params->kssl_suites));
	kssl_params->kssl_params_size = bufsize;
	kssl_params->kssl_addr = server_addr;
	kssl_params->kssl_session_cache_timeout = timeout;
	kssl_params->kssl_proxy_port = proxy_port;
	kssl_params->kssl_session_cache_size = scache_size;

	if (cacert_chain_file != NULL) {
		kssl_params = add_cacerts(kssl_params, cacert_chain_file);
		if (kssl_params == NULL) {
			return (FAILURE);
		}
	}

	if (kssl_send_command((char *)kssl_params, KSSL_ADD_ENTRY) < 0) {
		int err = CRYPTO_FAILED;

		if (kssl_params->kssl_is_nxkey)
			err = kssl_params->kssl_token.ck_rv;
		(void) fprintf(stderr,
		    "Error loading cert and key: 0x%x\n", err);
		return (FAILURE);
	}

	if (verbose)
		(void) printf("Successfully loaded cert and key\n");

	bzero(kssl_params, bufsize);
	free(kssl_params);
	return (SUCCESS);

err:
	usage_create(B_TRUE);
	return (SMF_EXIT_ERR_CONFIG);
}
