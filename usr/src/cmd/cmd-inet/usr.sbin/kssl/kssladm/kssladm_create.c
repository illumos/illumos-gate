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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <arpa/inet.h>
#include <errno.h>
#include <sys/sysmacros.h>
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

static uchar_t *
get_cert_val(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE cert_obj, int *len)
{
	CK_RV rv;
	uchar_t *buf;
	CK_ATTRIBUTE cert_attrs[] = {{CKA_VALUE, NULL_PTR, 0}};

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

#define	OPT_ATTR_CNT	6
#define	MAX_ATTR_CNT	16

int known_attr_cnt = 0;

#define	CKA_TOKEN_INDEX	1
/*
 * The order of the attributes must stay in the same order
 * as in the attribute template, privkey_tmpl, in load_from_pkcs11().
 */
CK_ATTRIBUTE key_gattrs[MAX_ATTR_CNT] = {
	{CKA_MODULUS, NULL_PTR, 0},
	{CKA_TOKEN, NULL_PTR, 0},
	{CKA_CLASS, NULL_PTR, 0},
	{CKA_KEY_TYPE, NULL_PTR, 0},
};
CK_ATTRIBUTE known_cert_attrs[1];

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
pkcs11_to_kssl(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE privkey_obj,
    boolean_t is_nxkey, int *paramsize, char *label, char *pin, int pinlen)
{
	int i;
	CK_RV rv;
	int total_attr_cnt;
	uint32_t cert_size, bufsize;
	char *buf;
	kssl_key_t *key;
	kssl_params_t *kssl_params;
	CK_ATTRIBUTE privkey_opt_attrs[OPT_ATTR_CNT] = {
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0},
		{CKA_PRIME_1, NULL_PTR, 0},
		{CKA_PRIME_2, NULL_PTR, 0},
		{CKA_EXPONENT_1, NULL_PTR, 0},
		{CKA_EXPONENT_2, NULL_PTR, 0},
		{CKA_COEFFICIENT, NULL_PTR, 0}
	};
	kssl_object_attribute_t kssl_attrs[MAX_ATTR_CNT];

	/* Get the certificate size */
	bufsize = sizeof (kssl_params_t);
	cert_size = (uint32_t)known_cert_attrs[0].ulValueLen;
	bufsize += cert_size + MAX_CHAIN_LENGTH * sizeof (uint32_t);

	/* These are attributes for which we have the value and length */
	for (i = 0; i < known_attr_cnt; i++) {
		bufsize += sizeof (crypto_object_attribute_t) +
		    key_gattrs[i].ulValueLen;
	}
	total_attr_cnt = known_attr_cnt;

	if (!is_nxkey) {
		/* Add CKA_PRIVATE_EXPONENT for extractable key */
		key_gattrs[total_attr_cnt].type = CKA_PRIVATE_EXPONENT;
		key_gattrs[total_attr_cnt].pValue  = NULL_PTR;
		key_gattrs[total_attr_cnt].ulValueLen = 0;

		rv = C_GetAttributeValue(sess, privkey_obj,
		    &key_gattrs[total_attr_cnt], 1);
		if (rv != CKR_OK) {
			(void) fprintf(stderr,
			    "Cannot get private key object attribute."
			    " error = %s\n", pkcs11_strerror(rv));
			return (NULL);
		}

		bufsize += sizeof (crypto_object_attribute_t) +
		    key_gattrs[total_attr_cnt].ulValueLen;
		total_attr_cnt++;
	}

	/*
	 * Get the optional key attributes. The return values could be
	 * CKR_ATTRIBUTE_TYPE_INVALID with ulValueLen set to -1 OR
	 * CKR_OK with ulValueLen set to 0. The latter is done by
	 * soft token and seems dubious.
	 */
	if (!is_nxkey) {
		rv = C_GetAttributeValue(sess, privkey_obj, privkey_opt_attrs,
		    OPT_ATTR_CNT);
		if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
			(void) fprintf(stderr,
			    "Cannot get private key object attributes."
			    " error = %s\n", pkcs11_strerror(rv));
			return (NULL);
		}

		for (i = 0; i < OPT_ATTR_CNT; i++) {
			if (privkey_opt_attrs[i].ulValueLen == (CK_ULONG)-1 ||
			    privkey_opt_attrs[i].ulValueLen == 0)
				continue;
			/* Structure copy */
			key_gattrs[total_attr_cnt] = privkey_opt_attrs[i];
			bufsize += sizeof (crypto_object_attribute_t) +
			    privkey_opt_attrs[i].ulValueLen;
			total_attr_cnt++;
		}
	} else
		bufsize += pinlen;

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

	if (is_nxkey) {
		kssl_params->kssl_is_nxkey = 1;
		bcopy(label, kssl_params->kssl_token.toklabel,
		    CRYPTO_EXT_SIZE_LABEL);
		kssl_params->kssl_token.pinlen = pinlen;
		kssl_params->kssl_token.tokpin_offset =
		    buf - (char *)kssl_params;
		kssl_params->kssl_token.ck_rv = 0;
		bcopy(pin, buf, pinlen);
		buf += pinlen;
	}

	/* the keys attributes structs array */
	key = &kssl_params->kssl_privkey;
	key->ks_format = CRYPTO_KEY_ATTR_LIST;
	key->ks_count = total_attr_cnt;
	key->ks_attrs_offset = buf - (char *)kssl_params;
	buf += total_attr_cnt * sizeof (kssl_object_attribute_t);

	/* These are attributes for which we already have the value */
	for (i = 0; i < known_attr_cnt; i++) {
		bcopy(key_gattrs[i].pValue, buf, key_gattrs[i].ulValueLen);
		kssl_attrs[i].ka_type = key_gattrs[i].type;
		kssl_attrs[i].ka_value_offset = buf - (char *)kssl_params;
		kssl_attrs[i].ka_value_len = key_gattrs[i].ulValueLen;
		buf += key_gattrs[i].ulValueLen;
	}

	if (total_attr_cnt > known_attr_cnt) {
		/* These are attributes for which we need to get the value */
		for (i = known_attr_cnt; i < total_attr_cnt; i++) {
			key_gattrs[i].pValue = buf;
			kssl_attrs[i].ka_type = key_gattrs[i].type;
			kssl_attrs[i].ka_value_offset =
			    buf - (char *)kssl_params;
			kssl_attrs[i].ka_value_len = key_gattrs[i].ulValueLen;
			buf += key_gattrs[i].ulValueLen;
		}

		rv = C_GetAttributeValue(sess, privkey_obj,
		    &key_gattrs[known_attr_cnt],
		    total_attr_cnt - known_attr_cnt);
		if (rv != CKR_OK) {
			(void) fprintf(stderr,
			    "Cannot get private key object attributes."
			    " error = %s\n", pkcs11_strerror(rv));
			return (NULL);
		}
	}

	bcopy(kssl_attrs, ((char *)kssl_params) + key->ks_attrs_offset,
	    total_attr_cnt * sizeof (kssl_object_attribute_t));

	buf = (char *)P2ROUNDUP((uintptr_t)buf, sizeof (uint32_t));
	kssl_params->kssl_certs.sc_count = 1;
	bcopy(&cert_size, buf, sizeof (uint32_t));
	kssl_params->kssl_certs.sc_sizes_offset = buf - (char *)kssl_params;
	buf += MAX_CHAIN_LENGTH * sizeof (uint32_t);

	/* now the certs values */
	bcopy(known_cert_attrs[0].pValue, buf, known_cert_attrs[0].ulValueLen);
	free(known_cert_attrs[0].pValue);
	kssl_params->kssl_certs.sc_certs_offset = buf - (char *)kssl_params;

	*paramsize = bufsize;
	bzero(pin, pinlen);
	(void) C_Logout(sess);
	(void) C_CloseSession(sess);
	return (kssl_params);
}

#define	max_num_cert 32

static kssl_params_t *
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
		{CKA_LABEL, NULL_PTR, 0},
		{CKA_CLASS, &cert_class, sizeof (cert_class)},
		{CKA_CERTIFICATE_TYPE, &cert_type, sizeof (cert_type)}
	};
	CK_ULONG cert_tmpl_count = 4, cert_obj_count = 1;
	CK_OBJECT_HANDLE cert_obj, privkey_obj;
	CK_OBJECT_HANDLE cert_objs[max_num_cert];
	static CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	static CK_KEY_TYPE privkey_type = CKK_RSA;
	CK_ATTRIBUTE privkey_tmpl[] = {
		/*
		 * The order of attributes must stay in the same order
		 * as in the global attribute array, key_gattrs.
		 */
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_TOKEN, &true, sizeof (true)},
		{CKA_CLASS, &privkey_class, sizeof (privkey_class)},
		{CKA_KEY_TYPE, &privkey_type, sizeof (privkey_type)}
	};
	CK_ULONG privkey_tmpl_count = 4, privkey_obj_count = 1;
	CK_BBOOL is_extractable;
	CK_ATTRIBUTE privkey_attrs[1] = {
		{CKA_EXTRACTABLE, NULL_PTR, 0},
	};
	boolean_t bingo = B_FALSE;
	int i, blen, mlen;
	uchar_t *mval, *ber_buf;
	char token_label_padded[sizeof (token_info.label) + 1];
	char passphrase[MAX_PIN_LENGTH];
	CK_ULONG ulPinLen;

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

	/*
	 * Some tokens may not be setting CKF_LOGIN_REQUIRED. So, we do
	 * not check for this flag and always login to be safe.
	 */
	ulPinLen = get_passphrase(password_file, passphrase,
	    sizeof (passphrase));
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

	cert_tmpl[1].pValue = (CK_VOID_PTR) certname;
	cert_tmpl[1].ulValueLen = strlen(certname);

	rv = C_FindObjectsInit(sess, cert_tmpl, cert_tmpl_count);
	if (rv != CKR_OK) {
		(void) fprintf(stderr,
		    "Cannot initialize cert search."
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

	/* Store it for later use. We free the buffer at that time. */
	known_cert_attrs[0].type = CKA_VALUE;
	known_cert_attrs[0].pValue = ber_buf;
	known_cert_attrs[0].ulValueLen = blen;

	mval = get_modulus(ber_buf, blen, &mlen);
	if (mval == NULL) {
		(void) fprintf(stderr,
		    "Cannot get Modulus in certificate \"%s\".\n", certname);
		return (NULL);
	}

	/* Now get the private key */
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

	if (privkey_obj_count == 0) {
		(void) fprintf(stderr, "no private keys. bye.\n");
		return (NULL);
	}

	(void) printf("found %ld private keys\n", privkey_obj_count);
	if (verbose) {
		(void) printf("private key attributes:    \n");
		(void) printf("\tmodulus: size %d \n", mlen);
	}

	/*
	 * Store it for later use. The index of the attributes
	 * is the same in both the structures.
	 */
	known_attr_cnt = privkey_tmpl_count;
	for (i = 0; i < privkey_tmpl_count; i++)
		key_gattrs[i] = privkey_tmpl[i];

	/*
	 * Get CKA_EXTRACTABLE value. We set the default value
	 * TRUE if the token returns CKR_ATTRIBUTE_TYPE_INVALID.
	 * The token would supply this attribute if the key
	 * is not extractable.
	 */
	privkey_attrs[0].pValue = &is_extractable;
	privkey_attrs[0].ulValueLen = sizeof (is_extractable);
	rv = C_GetAttributeValue(sess, privkey_obj, privkey_attrs, 1);
	if (rv != CKR_OK && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
		(void) fprintf(stderr,
		    "Cannot get CKA_EXTRACTABLE attribute."
		    " error = %s\n", pkcs11_strerror(rv));
		return (NULL);
	}

	if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
		is_extractable = TRUE;
	key_gattrs[known_attr_cnt++] = privkey_attrs[0];

	if (is_extractable) {
	/* Now wrap the key, then unwrap it */
	CK_BYTE	aes_key_val[16] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	static CK_BYTE aes_param[16] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	CK_MECHANISM aes_cbc_pad_mech = {CKM_AES_CBC_PAD, aes_param, 16};
	CK_OBJECT_HANDLE aes_key_obj, sess_privkey_obj;
	CK_BYTE *wrapped_privkey;
	CK_ULONG wrapped_privkey_len;

	CK_ATTRIBUTE unwrap_tmpl[] = {
		/* code below depends on the following attribute order */
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

	privkey_obj = sess_privkey_obj;
	/* Store the one modified attribute and the two new attributes. */
	key_gattrs[CKA_TOKEN_INDEX] = unwrap_tmpl[0];
	key_gattrs[known_attr_cnt++] = unwrap_tmpl[3];
	key_gattrs[known_attr_cnt++] = unwrap_tmpl[4];
	}

	return (pkcs11_to_kssl(sess, privkey_obj, !is_extractable, bufsize,
	    token_label_padded, passphrase, ulPinLen));
}

#define	MAX_OPENSSL_ATTR_CNT	8

/*
 * See the comments for pkcs11_to_kssl() for the layout of the
 * returned buffer.
 */
static kssl_params_t *
openssl_to_kssl(RSA *rsa, int ncerts, uchar_t *cert_bufs[], int *cert_sizes,
    int *paramsize)
{
	int i, tcsize;
	kssl_params_t *kssl_params;
	kssl_key_t *key;
	char *buf;
	uint32_t bufsize;
	kssl_object_attribute_t kssl_attrs[MAX_OPENSSL_ATTR_CNT];
	kssl_object_attribute_t kssl_tmpl_attrs[MAX_OPENSSL_ATTR_CNT] = {
		{SUN_CKA_MODULUS, NULL, 0},
		{SUN_CKA_PUBLIC_EXPONENT, NULL, 0},
		{SUN_CKA_PRIVATE_EXPONENT, NULL, 0},
		{SUN_CKA_PRIME_1, NULL, 0},
		{SUN_CKA_PRIME_2, NULL, 0},
		{SUN_CKA_EXPONENT_1, NULL, 0},
		{SUN_CKA_EXPONENT_2, NULL, 0},
		{SUN_CKA_COEFFICIENT, NULL, 0}
	};
	BIGNUM *priv_key_bignums[MAX_OPENSSL_ATTR_CNT];
	int attr_cnt;

	tcsize = 0;
	for (i = 0; i < ncerts; i++)
		tcsize += cert_sizes[i];

	bufsize = sizeof (kssl_params_t);
	bufsize += (tcsize + MAX_CHAIN_LENGTH * sizeof (uint32_t));

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
	for (i = 0; i < MAX_OPENSSL_ATTR_CNT; i++) {
		if (priv_key_bignums[i] == NULL)
			continue;
		kssl_attrs[attr_cnt].ka_type = kssl_tmpl_attrs[i].ka_type;
		kssl_attrs[attr_cnt].ka_value_len =
		    BN_num_bytes(priv_key_bignums[i]);
		bufsize += sizeof (crypto_object_attribute_t) +
		    kssl_attrs[attr_cnt].ka_value_len;
		attr_cnt++;
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

	/* the keys attributes structs array */
	key = &kssl_params->kssl_privkey;
	key->ks_format = CRYPTO_KEY_ATTR_LIST;
	key->ks_count = attr_cnt;
	key->ks_attrs_offset = buf - (char *)kssl_params;
	buf += attr_cnt * sizeof (kssl_object_attribute_t);

	attr_cnt = 0;
	/* then the key attributes values */
	for (i = 0; i < MAX_OPENSSL_ATTR_CNT; i++) {
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

	buf = (char *)P2ROUNDUP((uintptr_t)buf, sizeof (uint32_t));
	kssl_params->kssl_certs.sc_count = ncerts;
	bcopy(cert_sizes, buf, ncerts * sizeof (uint32_t));
	kssl_params->kssl_certs.sc_sizes_offset = buf - (char *)kssl_params;
	buf += MAX_CHAIN_LENGTH * sizeof (uint32_t);

	kssl_params->kssl_certs.sc_certs_offset = buf - (char *)kssl_params;
	/* now the certs values */
	for (i = 0; i < ncerts; i++) {
		bcopy(cert_bufs[i], buf, cert_sizes[i]);
		buf += cert_sizes[i];
	}

	*paramsize = bufsize;
	return (kssl_params);
}

static kssl_params_t *
add_cacerts(kssl_params_t *old_params, const char *cacert_chain_file,
    const char *password_file)
{
	int i, ncerts, newlen;
	int *cert_sizes;
	uint32_t certlen = 0;
	char *buf;
	uchar_t **cert_bufs;
	kssl_params_t *kssl_params;

	ncerts = 0;
	cert_bufs = PEM_get_rsa_key_certs(cacert_chain_file,
	    (char *)password_file, NULL, &cert_sizes, &ncerts);
	if (cert_bufs == NULL || ncerts == 0) {
		bzero(old_params, old_params->kssl_params_size);
		free(old_params);
		return (NULL);
	}

	if (verbose) {
		(void) printf("%d certificates read successfully\n", ncerts);
	}

	newlen = old_params->kssl_params_size;
	for (i = 0; i < ncerts; i++)
		newlen += cert_sizes[i];

	/*
	 * Get a bigger structure and update the
	 * fields to account for the additional certs.
	 */
	kssl_params = realloc(old_params, newlen);

	kssl_params->kssl_params_size = newlen;
	kssl_params->kssl_certs.sc_count += ncerts;

	/* Put the cert_sizes starting from sc_sizes[1] */
	buf = (char *)kssl_params;
	buf += kssl_params->kssl_certs.sc_sizes_offset;
	bcopy(buf, &certlen, sizeof (uint32_t));
	buf += sizeof (uint32_t);
	bcopy(cert_sizes, buf, ncerts * sizeof (uint32_t));

	/* Put the cert_bufs starting from sc_certs[1] */
	buf = (char *)kssl_params;
	buf += kssl_params->kssl_certs.sc_certs_offset;
	buf += certlen;

	/* now the certs values */
	for (i = 0; i < ncerts; i++) {
		bcopy(cert_bufs[i], buf, cert_sizes[i]);
		buf += cert_sizes[i];
	}

	for (i = 0; i < ncerts; i++)
		free(cert_bufs[i]);
	free(cert_bufs);
	free(cert_sizes);

	return (kssl_params);
}

static kssl_params_t *
load_from_pem(const char *filename, const char *password_file, int *paramsize)
{
	uchar_t **cert_bufs;
	int *cert_sizes, ncerts, i;
	RSA *rsa;
	kssl_params_t *kssl_params;

	ncerts = 0;
	cert_bufs = PEM_get_rsa_key_certs(filename, (char *)password_file,
	    &rsa, &cert_sizes, &ncerts);
	if (rsa == NULL || cert_bufs == NULL || ncerts == 0) {
		return (NULL);
	}

	if (verbose)
		(void) printf("%d certificates read successfully\n", ncerts);

	kssl_params = openssl_to_kssl(rsa, ncerts, cert_bufs,
	    cert_sizes, paramsize);

	for (i = 0; i < ncerts; i++)
		free(cert_bufs[i]);
	free(cert_bufs);
	free(cert_sizes);
	RSA_free(rsa);
	return (kssl_params);
}

static kssl_params_t *
load_from_pkcs12(const char *filename, const char *password_file,
    int *paramsize)
{
	RSA *rsa;
	kssl_params_t *kssl_params;
	uchar_t **cert_bufs;
	int *cert_sizes, ncerts, i;

	ncerts = 0;
	cert_bufs = PKCS12_get_rsa_key_certs(filename, password_file, &rsa,
	    &cert_sizes, &ncerts);
	if (cert_bufs == NULL || ncerts == 0) {
		(void) fprintf(stderr,
		    "Unable to read cert and/or key from %s\n", filename);
		return (NULL);
	}

	if (verbose)
		(void) printf("%d certificates read successfully\n", ncerts);

	kssl_params = openssl_to_kssl(rsa, ncerts, cert_bufs,
	    cert_sizes, paramsize);

	for (i = 0; i < ncerts; i++)
		free(cert_bufs[i]);
	free(cert_bufs);
	free(cert_sizes);

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

	bcopy(kssl_suites, kssl_params->kssl_suites,
	    sizeof (kssl_params->kssl_suites));
	kssl_params->kssl_params_size = bufsize;
	kssl_params->kssl_addr = server_addr;
	kssl_params->kssl_session_cache_timeout = timeout;
	kssl_params->kssl_proxy_port = proxy_port;
	kssl_params->kssl_session_cache_size = scache_size;

	if (cacert_chain_file != NULL) {
		kssl_params = add_cacerts(kssl_params, cacert_chain_file,
		    password_file);
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
