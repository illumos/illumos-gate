/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h> /* hostent */
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>
#include <cryptoutil.h>
#include <stdio.h>
#include <strings.h>
#include <sys/socket.h>
#include <libscf.h>
#include <inet/kssl/kssl.h>
#include "kssladm.h"

void
usage_create(boolean_t do_print)
{
	if (do_print)
		(void) fprintf(stderr, "Usage:\n");
	(void) fprintf(stderr, "kssladm create"
		" -f pkcs11 [-d softtoken_directory] -T <token_label>"
		" -C <certificate_label> -x <proxy_port>"
		" [options] [<server_address>] [<server_port>]\n");

	(void) fprintf(stderr, "kssladm create"
		" -f pkcs12 -i <certificate_file> -x <proxy_port>"
		" [options] [<server_address>] [<server_port>]\n");

	(void) fprintf(stderr, "kssladm create"
		" -f pem -i <certificate_file> -x <proxy_port>"
		" [options] [<server_address>] [<server_port>]\n");

	(void) fprintf(stderr, "options are:\n"
		"\t[-c <ciphersuites>]\n"
		"\t[-p <password_file>]\n"
		"\t[-t <ssl_session_cache_timeout>]\n"
		"\t[-z <ssl_session_cache_size>]\n"
		"\t[-v]\n");
}

static uchar_t *
get_cert_val(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE cert_obj, int *len)
{
	CK_RV rv;
	uchar_t *buf;
	CK_ATTRIBUTE cert_attrs[] = {{CKA_VALUE, NULL, 0}};

	/* the certs ... */
	rv = C_GetAttributeValue(sess, cert_obj, cert_attrs, 1);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot get cert size."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	buf = malloc(cert_attrs[0].ulValueLen);
	if (buf == NULL)
		return (NULL);
	cert_attrs[0].pValue = buf;

	rv = C_GetAttributeValue(sess, cert_obj, cert_attrs, 1);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot get cert value."
		    " error = %s\n", pkcs11_strerror(rv));
		free(buf);
		return (NULL);
	}

	*len = cert_attrs[0].ulValueLen;
	return (buf);
}

#define	REQ_ATTR_CNT	2
#define	OPT_ATTR_CNT	6
#define	MAX_ATTR_CNT	(REQ_ATTR_CNT + OPT_ATTR_CNT)

/*
 * Everything is allocated in one single contiguous buffer.
 * The layout is the following:
 * . the kssl_params_t structure
 * . the array of sizes of the certificates, (value of sc_sizes_offset)
 * . the array of key attribute structs, (value of ck_attrs)
 * . the certificates values (values of sc_certs[i])
 * . the key attributes values (values of ck_attrs[i].ck_value);
 *
 * The address of the certs and key attributes values are offsets
 * from the beginning of the big buffer.
 */
static kssl_params_t *
pkcs11_to_kssl(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE privkey_obj,
    CK_OBJECT_HANDLE cert_obj, int *paramsize)
{
	int i;
	CK_RV rv;
	CK_ATTRIBUTE privkey_attrs[MAX_ATTR_CNT] = {
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PRIVATE_EXPONENT, NULL_PTR, 0}
	};
	CK_ATTRIBUTE privkey_opt_attrs[OPT_ATTR_CNT] = {
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_PRIME_1, NULL_PTR, 0},
		{CKA_PRIME_2, NULL_PTR, 0},
		{CKA_EXPONENT_1, NULL_PTR, 0},
		{CKA_EXPONENT_2, NULL_PTR, 0},
		{CKA_COEFFICIENT, NULL_PTR, 0}
	};
	CK_ATTRIBUTE cert_attrs[] = { {CKA_VALUE, NULL, 0} };
	kssl_object_attribute_t kssl_attrs[MAX_ATTR_CNT];
	kssl_params_t *kssl_params;
	kssl_key_t *key;
	char *buf;
	uint32_t cert_size, bufsize;
	int attr_cnt;

	/* the certs ... */
	rv = C_GetAttributeValue(sess, cert_obj, cert_attrs, 1);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot get cert size."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	/* Get the sizes */
	bufsize = sizeof (kssl_params_t);
	cert_size = (uint32_t)cert_attrs[0].ulValueLen;
	bufsize += cert_size + sizeof (uint32_t);

	/* and the required key attributes */
	rv = C_GetAttributeValue(sess, privkey_obj, privkey_attrs,
	    REQ_ATTR_CNT);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot get private key object attributes. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}
	for (i = 0; i < REQ_ATTR_CNT; i++) {
		bufsize += sizeof (crypto_object_attribute_t) +
		    privkey_attrs[i].ulValueLen;
	}
	attr_cnt = REQ_ATTR_CNT;

	/*
	 * Get the optional key attributes. The return values could be
	 * CKR_ATTRIBUTE_TYPE_INVALID with ulValueLen set to -1 OR
	 * CKR_OK with ulValueLen set to 0. The latter is done by
	 * soft token and seems dubious.
	 */
	rv = C_GetAttributeValue(sess, privkey_obj, privkey_opt_attrs,
	    OPT_ATTR_CNT);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		(void) fprintf(stderr,
		    "Cannot get private key object attributes. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}
	for (i = 0; i < OPT_ATTR_CNT; i++) {
		if (privkey_opt_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    privkey_opt_attrs[i].ulValueLen == 0)
			continue;
		/* Structure copy */
		privkey_attrs[attr_cnt] = privkey_opt_attrs[i];
		bufsize += sizeof (crypto_object_attribute_t) +
		    privkey_opt_attrs[i].ulValueLen;
		attr_cnt++;
	}

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

	kssl_params->kssl_certs.sc_count = 1;
	bcopy(&cert_size, buf, sizeof (uint32_t));
	kssl_params->kssl_certs.sc_sizes_offset = buf - (char *)kssl_params;
	buf += sizeof (uint32_t);

	/* the keys attributes structs array */
	key = &kssl_params->kssl_privkey;
	key->ks_format = CRYPTO_KEY_ATTR_LIST;
	key->ks_count = attr_cnt;
	key->ks_attrs_offset = buf - (char *)kssl_params;
	buf += attr_cnt * sizeof (kssl_object_attribute_t);

	/* now the certs values */
	cert_attrs[0].pValue = buf;
	kssl_params->kssl_certs.sc_certs_offset = buf - (char *)kssl_params;
	buf += cert_attrs[0].ulValueLen;

	rv = C_GetAttributeValue(sess, cert_obj, cert_attrs, 1);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot get cert value."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	/* then the attributes values */
	for (i = 0; i < attr_cnt; i++) {
		privkey_attrs[i].pValue = buf;
		/*
		 * We assume the attribute types in the kernel are
		 * the same as the PKCS #11 values.
		 */
		kssl_attrs[i].ka_type = privkey_attrs[i].type;
		kssl_attrs[i].ka_value_offset = buf - (char *)kssl_params;

		kssl_attrs[i].ka_value_len = privkey_attrs[i].ulValueLen;

		buf += privkey_attrs[i].ulValueLen;
	}
	/* then the key attributes values */
	rv = C_GetAttributeValue(sess, privkey_obj, privkey_attrs, attr_cnt);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot get private key object attributes."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	bcopy(kssl_attrs, ((char *)kssl_params) + key->ks_attrs_offset,
	    attr_cnt * sizeof (kssl_object_attribute_t));

	*paramsize = bufsize;
	return (kssl_params);
}

#define	max_num_cert 32

kssl_params_t *
load_from_pkcs11(const char *token_label, const char *password_file,
	const char *certname, int *bufsize)
{
	static CK_BBOOL true = TRUE;
	static CK_BBOOL false = FALSE;

	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SLOT_ID_PTR	pk11_slots;
	CK_ULONG slotcnt = 10;
	CK_TOKEN_INFO	token_info;
	CK_SESSION_HANDLE sess;
	static CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	static CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_ATTRIBUTE cert_tmpl[4] = {
		{CKA_TOKEN, &true, sizeof (true)},
		{CKA_LABEL, NULL, 0},
		{CKA_CLASS, &cert_class, sizeof (cert_class)},
		{CKA_CERTIFICATE_TYPE, &cert_type, sizeof (cert_type)}
	};
	CK_ULONG cert_tmpl_count = 4, cert_obj_count = 1;
	CK_OBJECT_HANDLE cert_obj, privkey_obj;
	CK_OBJECT_HANDLE cert_objs[max_num_cert];
	static CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE privkey_type = CKK_RSA;
	CK_ATTRIBUTE privkey_tmpl[] = {
		{CKA_MODULUS, NULL, 0},
		{CKA_TOKEN, &true, sizeof (true)},
		{CKA_CLASS, &privkey_class, sizeof (privkey_class)},
		{CKA_KEY_TYPE, &privkey_type, sizeof (privkey_type)}
	};
	CK_ULONG privkey_tmpl_count = 4, privkey_obj_count = 1;
	static CK_BYTE modulus[1024];
	CK_ATTRIBUTE privkey_attrs[1] = {
		{CKA_MODULUS, modulus, sizeof (modulus)},
	};
	boolean_t bingo = B_FALSE;
	int blen, mlen;
	uchar_t *mval, *ber_buf;
	char token_label_padded[sizeof (token_info.label) + 1];

	(void) snprintf(token_label_padded, sizeof (token_label_padded),
		"%-32s", token_label);

	rv = C_Initialize(NULL_PTR);

	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		(void) fprintf(stderr,
		    "Cannot initialize PKCS#11. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	/* Get slot count */
	rv = C_GetSlotList(1, NULL_PTR, &slotcnt);
	if (rv != CKR_OK || slotcnt == 0) {
		(void) fprintf(stderr,
		    "Cannot get PKCS#11 slot list. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	pk11_slots = calloc(slotcnt, sizeof (CK_SLOT_ID));
	if (pk11_slots == NULL) {
		(void) fprintf(stderr,
		    "Cannot get memory for %ld slots\n", slotcnt);
		return (NULL);
	}

	rv = C_GetSlotList(1, pk11_slots, &slotcnt);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot get PKCS#11 slot list. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	if (verbose)
		(void) printf("Found %ld slots\n", slotcnt);

	/* Search the token that matches the label */
	while (slotcnt > 0) {
		rv = C_GetTokenInfo(pk11_slots[--slotcnt], &token_info);
		if (rv != CKR_OK)
			continue;

		if (verbose)
			(void) printf("slot [%ld] = %s\n",
			    slotcnt, token_info.label);
		if (memcmp(token_label_padded, token_info.label,
		    sizeof (token_info.label)) == 0) {
			bingo = B_TRUE;
			slot = pk11_slots[slotcnt];
			break;
		}
		if (verbose) {
			token_info.label[31] = '\0';
			(void) printf("found slot [%s]\n", token_info.label);
		}
	}

	if (!bingo) {
		(void) fprintf(stderr, "no matching PKCS#11 token found\n");
		return (NULL);
	}

	rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR,
		&sess);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot open session. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	cert_tmpl[1].pValue = (CK_VOID_PTR) certname;
	cert_tmpl[1].ulValueLen = strlen(certname);

	rv = C_FindObjectsInit(sess, cert_tmpl, cert_tmpl_count);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot intialize cert search."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	rv = C_FindObjects(sess, cert_objs,
		(certname == NULL ? 1 : max_num_cert), &cert_obj_count);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot retrieve cert object. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	/* Who cares if this fails! */
	(void) C_FindObjectsFinal(sess);
	if (verbose)
		(void) printf("found %ld certificates\n", cert_obj_count);

	if (cert_obj_count == 0) {
		(void) fprintf(stderr, "\"%s\" not found.\n", certname);
		(void) fprintf(stderr, "no certs. bye.\n");
		return (NULL);
	}

	cert_obj = cert_objs[0];

	/* Get the modulus value from the certificate */
	ber_buf = get_cert_val(sess, cert_obj, &blen);
	if (ber_buf == NULL) {
		(void) fprintf(stderr,
		    "Cannot get certificate data for \"%s\".\n", certname);
		return (NULL);
	}

	mval = get_modulus(ber_buf, blen, &mlen);
	if (mval == NULL) {
		(void) fprintf(stderr,
		    "Cannot get Modulus in certificate \"%s\".\n", certname);
		return (NULL);
	}

	/* Now get the private key */

	/* Gotta authenticate first if login is required. */
	if (token_info.flags & CKF_LOGIN_REQUIRED) {
		char passphrase[1024];
		CK_ULONG ulPinLen;

		ulPinLen = get_passphrase(
		    password_file, passphrase, sizeof (passphrase));
		if (ulPinLen == 0) {
			(void) fprintf(stderr, "Unable to read passphrase");
			return (NULL);
		}

		rv = C_Login(sess, CKU_USER, (CK_UTF8CHAR_PTR)passphrase,
		    ulPinLen);
		if (rv != CKR_OK) {
			(void) fprintf(stderr, "Cannot login to the token."
			    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
		}
	}

	privkey_tmpl[0].pValue = mval;
	privkey_tmpl[0].ulValueLen = mlen;

	rv = C_FindObjectsInit(sess, privkey_tmpl, privkey_tmpl_count);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot intialize private key search."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	rv = C_FindObjects(sess, &privkey_obj, 1,  &privkey_obj_count);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot retrieve private key object "
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}
	/* Who cares if this fails! */
	(void) C_FindObjectsFinal(sess);


	(void) printf("found %ld private keys\n", privkey_obj_count);

	if (privkey_obj_count == 0) {
		(void) fprintf(stderr, "no private keys. bye.\n");
		return (NULL);
	}

	rv = C_GetAttributeValue(sess, privkey_obj, privkey_attrs, 1);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot get private key object attributes."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	if (verbose) {
		(void) printf("private key attributes:    \n");
		(void) printf("\tmodulus: size %ld value:",
		    privkey_attrs[0].ulValueLen);
	}

	/* Now wrap the key, then unwrap it */

	{
	CK_BYTE	aes_key_val[16] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	static CK_BYTE aes_param[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	CK_MECHANISM aes_cbc_pad_mech = {CKM_AES_CBC_PAD, aes_param, 16};
	CK_OBJECT_HANDLE aes_key_obj, sess_privkey_obj;
	CK_BYTE *wrapped_privkey;
	CK_ULONG wrapped_privkey_len;

	CK_ATTRIBUTE unwrap_tmpl[] = {
		{CKA_TOKEN, &false, sizeof (false)},
		{CKA_CLASS, &privkey_class, sizeof (privkey_class)},
		{CKA_KEY_TYPE, &privkey_type, sizeof (privkey_type)},
		{CKA_SENSITIVE, &false, sizeof (false)},
		{CKA_PRIVATE, &false, sizeof (false)}
	};

	rv = SUNW_C_KeyToObject(sess, CKM_AES_CBC_PAD, aes_key_val, 16,
	    &aes_key_obj);

	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot create wrapping key. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	/* get the size of the wrapped key */
	rv = C_WrapKey(sess, &aes_cbc_pad_mech, aes_key_obj, privkey_obj,
	    NULL, &wrapped_privkey_len);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot get key size. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	wrapped_privkey = malloc(wrapped_privkey_len * sizeof (CK_BYTE));
	if (wrapped_privkey == NULL) {
		return (NULL);
	}

	/* do the actual key wrapping */
	rv = C_WrapKey(sess, &aes_cbc_pad_mech, aes_key_obj, privkey_obj,
	    wrapped_privkey, &wrapped_privkey_len);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot wrap private key. error = %s\n",
		    pkcs11_strerror(rv));
		return (NULL);
	}

	(void) C_Logout(sess);
	(void) printf("private key successfully wrapped, "
		"wrapped blob length: %ld\n",
		wrapped_privkey_len);

	rv = C_UnwrapKey(sess, &aes_cbc_pad_mech, aes_key_obj,
	    wrapped_privkey, wrapped_privkey_len,
	    unwrap_tmpl, 5, &sess_privkey_obj);
	if (rv != CKR_OK) {
		(void) fprintf(stderr, "Cannot unwrap private key."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}
	(void) printf("session private key successfully unwrapped\n");

	return (pkcs11_to_kssl(sess, sess_privkey_obj, cert_obj, bufsize));
	}
}


static kssl_params_t *
openssl_to_kssl(RSA *rsa, uchar_t *cert_buf, int cert_size, int *paramsize)
{
	int i;
	kssl_params_t *kssl_params;
	kssl_key_t *key;
	char *buf;
	uint32_t bufsize;
	kssl_object_attribute_t kssl_attrs[MAX_ATTR_CNT];
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
	BIGNUM *priv_key_bignums[MAX_ATTR_CNT];
	int attr_cnt;

	bufsize = sizeof (kssl_params_t);
	bufsize += cert_size + sizeof (uint32_t);

	/* and the key attributes */
	priv_key_bignums[0] = rsa->n;		/* MODULUS */
	priv_key_bignums[1] = rsa->e; 		/* PUBLIC_EXPONENT */
	priv_key_bignums[2] = rsa->d; 		/* PRIVATE_EXPONENT */
	priv_key_bignums[3] = rsa->p;		/* PRIME_1 */
	priv_key_bignums[4] = rsa->q;		/* PRIME_2 */
	priv_key_bignums[5] = rsa->dmp1;	/* EXPONENT_1 */
	priv_key_bignums[6] = rsa->dmq1;	/* EXPONENT_2 */
	priv_key_bignums[7] = rsa->iqmp;	/* COEFFICIENT */

	if (rsa->n == NULL || rsa->d == NULL) {
		(void) fprintf(stderr,
		    "missing required attributes in private key.\n");
		return (NULL);
	}

	attr_cnt = 0;
	for (i = 0; i < MAX_ATTR_CNT; i++) {
		if (priv_key_bignums[i] == NULL)
			continue;
		kssl_attrs[attr_cnt].ka_type = kssl_tmpl_attrs[i].ka_type;
		kssl_attrs[attr_cnt].ka_value_len =
		    BN_num_bytes(priv_key_bignums[i]);
		bufsize += sizeof (crypto_object_attribute_t) +
		    kssl_attrs[attr_cnt].ka_value_len;
		attr_cnt++;
	}

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

	kssl_params->kssl_certs.sc_count = 1;
	bcopy(&cert_size, buf, sizeof (uint32_t));
	kssl_params->kssl_certs.sc_sizes_offset = buf - (char *)kssl_params;
	buf += sizeof (uint32_t);

	/* the keys attributes structs array */
	key = &kssl_params->kssl_privkey;
	key->ks_format = CRYPTO_KEY_ATTR_LIST;
	key->ks_count = attr_cnt;
	key->ks_attrs_offset = buf - (char *)kssl_params;
	buf += attr_cnt * sizeof (kssl_object_attribute_t);

	/* now the certs values */
	bcopy(cert_buf, buf, cert_size);
	kssl_params->kssl_certs.sc_certs_offset = buf - (char *)kssl_params;
	buf += cert_size;

	attr_cnt = 0;
	/* then the key attributes values */
	for (i = 0; i < MAX_ATTR_CNT; i++) {
		if (priv_key_bignums[i] == NULL)
			continue;
		(void) BN_bn2bin(priv_key_bignums[i], (unsigned char *)buf);
		kssl_attrs[attr_cnt].ka_value_offset =
		    buf - (char *)kssl_params;
		buf += kssl_attrs[attr_cnt].ka_value_len;
		attr_cnt++;
	}

	bcopy(kssl_attrs, ((char *)kssl_params) + key->ks_attrs_offset,
	    attr_cnt * sizeof (kssl_object_attribute_t));

	*paramsize = bufsize;
	return (kssl_params);
}

kssl_params_t *
load_from_pem(const char *filename, const char *password_file, int *paramsize)
{
	uchar_t *cert_buf;
	int cert_size;
	RSA *rsa;
	kssl_params_t *kssl_params;

	rsa = PEM_get_rsa_key(filename, (char *)password_file);
	if (rsa == NULL) {
		(void) fprintf(stderr, "cannot read the private key\n");
		return (NULL);
	}

	if (verbose)
		(void) printf("private key read successfully\n");

	cert_buf = PEM_get_cert(filename, (char *)password_file, &cert_size);
	if (cert_buf == NULL) {
		RSA_free(rsa);
		return (NULL);
	}

	if (verbose)
		(void) printf("certificate read successfully size=%d\n",
		    cert_size);

	kssl_params = openssl_to_kssl(rsa, cert_buf, cert_size, paramsize);

	free(cert_buf);
	RSA_free(rsa);
	return (kssl_params);
}

kssl_params_t *
load_from_pkcs12(const char *filename, const char *password_file,
    int *paramsize)
{
	uchar_t *cert_buf;
	int cert_size;
	RSA *rsa;
	kssl_params_t *kssl_params;

	if (PKCS12_get_rsa_key_cert(filename, password_file, &rsa, &cert_buf,
	    &cert_size) < 0) {
		(void) fprintf(stderr,
		    "Unable to read cert and/or key from %s\n", filename);
		return (NULL);
	}

	if (verbose)
		(void) printf(
		    "key/certificate read successfully cert_size=%d\n",
		    cert_size);

	kssl_params = openssl_to_kssl(rsa, cert_buf, cert_size, paramsize);

	free(cert_buf);
	RSA_free(rsa);
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

int
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
	const char *filename = NULL;
	const char *certname = NULL;
	char *suites = NULL;
	uint32_t timeout = DEFAULT_SID_TIMEOUT;
	uint32_t scache_size = DEFAULT_SID_CACHE_NENTRIES;
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

	while ((c = getopt(argc, argv, "vT:d:f:i:p:c:C:t:x:z:")) != -1) {
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
		case 'i':
			filename = optarg;
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
		if (filename == NULL) {
			goto err;
		}
		kssl_params = load_from_pkcs12(
		    filename, password_file, &bufsize);
	} else if (strcmp(format, "pem") == 0) {
		if (filename == NULL) {
			goto err;
		}
		kssl_params = load_from_pem(
		    filename, password_file, &bufsize);
	} else {
		(void) fprintf(stderr, "Unsupported cert format: %s\n", format);
		goto err;
	}

	if (kssl_params == NULL) {
		return (FAILURE);
	}

	if (check_suites(suites, kssl_params->kssl_suites) != 0)
		goto err;

	kssl_params->kssl_params_size = bufsize;
	kssl_params->kssl_addr = server_addr;
	kssl_params->kssl_session_cache_timeout = timeout;
	kssl_params->kssl_proxy_port = proxy_port;
	kssl_params->kssl_session_cache_size = scache_size;

	if (kssl_send_command((char *)kssl_params, KSSL_ADD_ENTRY) < 0) {
		(void) fprintf(stderr, "Error loading cert and key");
		return (FAILURE);
	}

	if (verbose)
		(void) printf("Successfully loaded cert and key\n");

	free(kssl_params);
	return (SUCCESS);

err:
	usage_create(B_TRUE);
	return (SMF_EXIT_ERR_CONFIG);
}
