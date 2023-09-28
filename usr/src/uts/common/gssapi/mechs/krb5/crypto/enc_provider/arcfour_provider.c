/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2000 by Computer Science Laboratory,
 *                       Rensselaer Polytechnic Institute
 * #include STD_DISCLAIMER
 */

#include <k5-int.h>
#include <arcfour.h>

/* from a random bitstrem, construct a key */
static krb5_error_code
k5_arcfour_make_key(krb5_context, const krb5_data *, krb5_keyblock *);

#ifndef _KERNEL
static krb5_error_code
setup_arcfour_crypto(CK_SESSION_HANDLE session,
		const krb5_keyblock *key,
		KRB5_MECH_TO_PKCS *algos,
		CK_OBJECT_HANDLE *hKey)
{
	krb5_error_code ret = 0;
	CK_RV rv;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_RC4;
	CK_BBOOL true = TRUE, false =  FALSE;
	CK_ATTRIBUTE template[5];

	if ((rv = get_algo(key->enctype, algos)) != CKR_OK) {
		KRB5_LOG0(KRB5_ERR, "failure to get algo id in function "
		"k5_arcfour_decrypt.");
		return (PKCS_ERR);
	}

	template[0].type = CKA_CLASS;
	template[0].pValue = &class;
	template[0].ulValueLen = sizeof (class);
	template[1].type = CKA_KEY_TYPE;
	template[1].pValue = &keyType;
	template[1].ulValueLen = sizeof (keyType);
	template[2].type = CKA_TOKEN;
	template[2].pValue = &false;
	template[2].ulValueLen = sizeof (false);
	template[3].type = CKA_ENCRYPT;
	template[3].pValue = &true;
	template[3].ulValueLen = sizeof (true);
	template[4].type = CKA_VALUE;
	template[4].pValue = key->contents;
	template[4].ulValueLen = key->length;

	/* Create an object handle for the key */
	if ((rv = C_CreateObject(session, template,
		sizeof(template)/sizeof(CK_ATTRIBUTE),
		hKey)) != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "C_CreateObject failed in "
		"k5_arcfour_decrypt: rv = 0x%x.", rv);
		ret = PKCS_ERR;
	}

	return (ret);
}
#endif /* !_KERNEL */


/* The workhorse of the arcfour system, this impliments the cipher */
/* ARGSUSED */
static krb5_error_code
k5_arcfour_decrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *state,
	const krb5_data *input, krb5_data *output)
{
  krb5_error_code ret = 0;

#ifndef _KERNEL
  CK_RV rv;
  KRB5_MECH_TO_PKCS algos;
  CK_OBJECT_HANDLE *kptr = NULL, hKey = CK_INVALID_HANDLE;
  CK_MECHANISM mechanism;
  CK_SESSION_HANDLE session = 0;
  CK_ULONG outlen;
  int need_init = 0;
#endif

  KRB5_LOG0(KRB5_INFO, "k5_arcfour_decrypt start");
  if (key->length != 16)
    return(KRB5_BAD_KEYSIZE);
  if (input->length != output->length)
    return(KRB5_BAD_MSIZE);

#ifndef _KERNEL
   /*
    * If RC4 is being used to encrypt a stream of data blocks,
    * the keys for encrypt and decrypt must be kept separate
    * so that their associated state data doesn't get mixed up
    * between operations.    The r-cmds (rlogin, rsh, rcp) use
    * the  "init_state" function (see bottom of this module)
    * to set up and prepare for stream encryption.
    *
    * Normally, the RC4 key is used as a single operation
    * (i.e. call C_Encrypt) instead of a constantly updating
    * stream cipher (C_EncryptUpdate).  In those cases, we just
    * use a short-term key object defined locally. We don't
    * have to save state between operations.
    *
    * This logic here is to make sure that the keys are tracked
    * correctly depending on how they are used and that the RC4
    * context record is properly initialized.
    */
   if (!context->arcfour_ctx.initialized) {
	session = krb_ctx_hSession(context);
	/* Just use a local, 1-time only key object */
	kptr = (CK_OBJECT_HANDLE *)&hKey;
	need_init = 1;
   } else {
	session = context->arcfour_ctx.dSession;
	/* If the dKey handle was not defined, we need to initialize one */
	if (context->arcfour_ctx.dKey == CK_INVALID_HANDLE) {
		need_init = 1;
		/* Use the long-term key object in the RC4 context area */
		kptr =  &context->arcfour_ctx.dKey;
	}
   }

   if (need_init) {
	ret = setup_arcfour_crypto(session, key, &algos, kptr);
	if (ret)
                goto cleanup;

	mechanism.mechanism = algos.enc_algo;
	mechanism.pParameter =  NULL;
	mechanism.ulParameterLen = 0;

	rv = C_DecryptInit(session, &mechanism, *kptr);

	if (rv != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "C_DecryptInit failed in "
			"k5_arcfour_decrypt: rv = 0x%x", rv);
		ret = PKCS_ERR;
		goto cleanup;
	}
    }

    outlen = (CK_ULONG)output->length;
    if (context->arcfour_ctx.initialized)
	rv = C_DecryptUpdate(session,
		(CK_BYTE_PTR)input->data,
		(CK_ULONG)input->length,
		(CK_BYTE_PTR)output->data,
		(CK_ULONG_PTR)&outlen);
    else {
	rv = C_Decrypt(session,
		(CK_BYTE_PTR)input->data,
		(CK_ULONG)input->length,
		(CK_BYTE_PTR)output->data,
		(CK_ULONG_PTR)&outlen);
    }
    output->length = (uint32_t)outlen;

    if (rv != CKR_OK) {
            KRB5_LOG(KRB5_ERR,
		"C_DecryptUpdate failed in k5_arcfour_decrypt: "
		"rv = 0x%x", rv);
            ret = PKCS_ERR;
    }
cleanup:
    if (ret)
	bzero(output->data, input->length);

    /* If we used a 1-time only key object, destroy it now */
    if (hKey != CK_INVALID_HANDLE)
	(void)C_DestroyObject(session, hKey);

#else /* !_KERNEL */
    KRB5_LOG(KRB5_INFO, "key->kef_mt = %ld", (ulong_t) key->kef_mt);
    ret = k5_ef_crypto((const char *)input->data, (char *)output->data,
		input->length, (krb5_keyblock *)key, NULL, 0);
#endif /* !_KERNEL */

  KRB5_LOG0(KRB5_INFO, "k5_arcfour_docrypt end");
  return (ret);
}

/* ARGSUSED */
static krb5_error_code
k5_arcfour_encrypt(krb5_context context,
	const krb5_keyblock *key, const krb5_data *state,
	const krb5_data *input, krb5_data *output)
{
  krb5_error_code ret = 0;

#ifndef _KERNEL
  CK_RV rv;
  KRB5_MECH_TO_PKCS algos;
  CK_MECHANISM mechanism;
  CK_OBJECT_HANDLE *kptr = NULL, hKey = CK_INVALID_HANDLE;
  CK_SESSION_HANDLE session;
  int need_init = 0;
  CK_ULONG outlen;
#endif

  KRB5_LOG0(KRB5_INFO, "k5_arcfour_encrypt start");
  if (key->length != 16)
	return(KRB5_BAD_KEYSIZE);
  if (input->length != output->length)
	return(KRB5_BAD_MSIZE);

#ifndef _KERNEL

   /*
    * See the comments in the k5_arcfour_decrypt routine (above)
    * for an explanation of why the key handles are initialized
    * and used as they are here.
    */
   if (!context->arcfour_ctx.initialized) {
	session = krb_ctx_hSession(context);
	kptr = (CK_OBJECT_HANDLE *)&hKey;
	need_init = 1;
   } else {
	session = context->arcfour_ctx.eSession;
	if (context->arcfour_ctx.eKey == 0) {
		kptr = &context->arcfour_ctx.eKey;
		need_init = 1;
	}
   }

   if (need_init)  {
	ret = setup_arcfour_crypto(session, key, &algos, kptr);
	if (ret)
                goto cleanup;

	mechanism.mechanism = algos.enc_algo;
	mechanism.pParameter =  NULL;
	mechanism.ulParameterLen = 0;

	rv = C_EncryptInit(session, &mechanism, *kptr);

	if (rv != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "C_EncryptInit failed in "
			"k5_arcfour_encrypt: rv = 0x%x", rv);
		ret = PKCS_ERR;
		goto cleanup;
	}
    }

    /*
     * If we've initialize the stream for use with r-commands,
     * use the open-ended session handle and call.
     */
    outlen = (CK_ULONG)output->length;
    if (context->arcfour_ctx.initialized)
	rv = C_EncryptUpdate(session,
		(CK_BYTE_PTR)input->data,
		(CK_ULONG)input->length,
		(CK_BYTE_PTR)output->data,
		(CK_ULONG_PTR)&outlen);
    else {
	rv = C_Encrypt(session,
		(CK_BYTE_PTR)input->data,
		(CK_ULONG)input->length,
		(CK_BYTE_PTR)output->data,
		(CK_ULONG_PTR)&outlen);
    }
    output->length = (uint32_t)outlen;

    if (rv != CKR_OK) {
            KRB5_LOG(KRB5_ERR,
		"C_EncryptUpdate failed in k5_arcfour_encrypt: "
		"rv = 0x%x", rv);
            ret = PKCS_ERR;
    }
cleanup:
    if (ret)
	bzero(output->data, input->length);

    if (hKey != CK_INVALID_HANDLE)
	(void)C_DestroyObject(session, hKey);

#else /* !_KERNEL */
    KRB5_LOG1(KRB5_INFO, "key->kef_mt = %ld key->key_tmpl = %ld",
		(ulong_t) key->kef_mt, (ulong_t) key->key_tmpl);
    ret = k5_ef_crypto((const char *)input->data, (char *)output->data,
			input->length, (krb5_keyblock *)key, NULL, 1);
#endif /* !_KERNEL */

  KRB5_LOG0(KRB5_INFO, "k5_arcfour_docrypt end");
  return (ret);
}

/* ARGSUSED */
static krb5_error_code
k5_arcfour_make_key(krb5_context context,
	const krb5_data *randombits, krb5_keyblock *key)
{
    krb5_error_code ret = 0;
    KRB5_LOG0(KRB5_INFO, "k5_arcfour_make_key() start\n");

    if (key->length != 16)
	return(KRB5_BAD_KEYSIZE);
    if (randombits->length != 16)
	return(KRB5_CRYPTO_INTERNAL);

    key->magic = KV5M_KEYBLOCK;
    key->length = 16;
    key->dk_list = NULL;
#ifdef _KERNEL
    key->kef_key.ck_data = NULL;
    key->key_tmpl = NULL;
    ret = init_key_kef(context->kef_cipher_mt, key);
#else
    key->hKey = CK_INVALID_HANDLE;
    ret = init_key_uef(krb_ctx_hSession(context), key);
#endif /* _KERNEL */

    bcopy(randombits->data, key->contents, randombits->length);

    KRB5_LOG0(KRB5_INFO, "k5_arcfour_make_key() end\n");
    return (ret);
}

/*ARGSUSED*/
static krb5_error_code
k5_arcfour_init_state (krb5_context context,
		const krb5_keyblock *key,
		krb5_keyusage keyusage, krb5_data *new_state)
{
   krb5_error_code retval = 0;
#ifndef _KERNEL
   if (!context->arcfour_ctx.initialized) {
	retval = krb5_open_pkcs11_session(&context->arcfour_ctx.eSession);
	if (retval)
		return (retval);
	retval = krb5_open_pkcs11_session(&context->arcfour_ctx.dSession);
	if (retval)
		return (retval);
	context->arcfour_ctx.initialized = 1;
	context->arcfour_ctx.eKey = CK_INVALID_HANDLE;
	context->arcfour_ctx.dKey = CK_INVALID_HANDLE;
   }
#endif
  return (retval);
}

/* Since the arcfour cipher is identical going forwards and backwards,
   we just call "docrypt" directly
*/
const struct krb5_enc_provider krb5int_enc_arcfour = {
    1,
    16, 16,
    k5_arcfour_encrypt,
    k5_arcfour_decrypt,
    k5_arcfour_make_key,
    k5_arcfour_init_state,
    krb5int_default_free_state
};
