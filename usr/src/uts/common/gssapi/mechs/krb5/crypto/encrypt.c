/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "k5-int.h"
#include "etypes.h"


#ifdef _KERNEL
krb5_error_code
update_key_template(krb5_keyblock *key)
{
	crypto_mechanism_t kef_mech;
	int rv = 0;
	krb5_error_code ret = 0;

	KRB5_LOG0(KRB5_INFO, "update_key_template()");
	if (key == NULL)
		return (ret);

	/*
	 * Preallocate the crypto_key_t records
	 * needed by the kernel crypto calls later.
	 */
	kef_mech.cm_type = key->kef_mt;
	kef_mech.cm_param = NULL;
	kef_mech.cm_param_len = 0;
	/*
	 * Create an template to improve HMAC performance later.
	 */
	rv = crypto_create_ctx_template(&kef_mech,
					&key->kef_key,
					&key->key_tmpl,
					KM_SLEEP);
	if (rv != CRYPTO_SUCCESS) {
		/*
                 * Some mechs don't support context templates
		 */
                if (rv == CRYPTO_NOT_SUPPORTED) {
			ret = 0;
			key->key_tmpl = NULL;
		} else {
			KRB5_LOG(KRB5_ERR,"crypto_create_ctx_template "
				"error: %0x", rv);
			ret = KRB5_KEF_ERROR;
		}
	}
	return (ret);
}
/*
 * initialize the KEF components of the krb5_keyblock record.
 */
krb5_error_code
init_key_kef(crypto_mech_type_t mech_type, krb5_keyblock *key)
{
	krb5_error_code rv = 0;

	KRB5_LOG0(KRB5_INFO, "init_key_kef()");
	if (key == NULL)
		return (rv);

	if (key->kef_key.ck_data == NULL) {
		key->kef_key.ck_data = key->contents;
	}

	/* kef keys are measured in bits */
	key->kef_key.ck_length = key->length * 8;
	key->kef_key.ck_format = CRYPTO_KEY_RAW;
	key->kef_mt = mech_type;

	if (key->key_tmpl == NULL && mech_type != CRYPTO_MECH_INVALID) {
		rv = update_key_template(key);
	}
	return(rv);
}
#else

/*
 * init_key_uef
 *  Initialize the Userland Encryption Framework fields of the
 *  key block.
 */
krb5_error_code
init_key_uef(CK_SESSION_HANDLE hSession, krb5_keyblock *key)
{
        CK_RV rv = CKR_OK;
        CK_MECHANISM mechanism;
        CK_OBJECT_CLASS class = CKO_SECRET_KEY;
        CK_KEY_TYPE keyType;
        CK_BBOOL true = TRUE, false =  FALSE;
        CK_ATTRIBUTE template[6];

	/* If its already initialized, return OK */
	/*
	 * fork safety: if the key->pid != __krb5_current_pid then a fork has
	 * taken place and the pkcs11 key handle must be re-acquired.
	 */
	if ((key->hKey != CK_INVALID_HANDLE) &&
	    (key->pid == __krb5_current_pid))
		return (rv);

	/* fork safety */
	key->pid = __krb5_current_pid;

	if ((rv = get_key_type(key->enctype, &keyType)) != CKR_OK) {
                KRB5_LOG0(KRB5_ERR, "failure to get key type in function "
                "init_key_uef.");
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
        template[4].type = CKA_DECRYPT;
        template[4].pValue = &true;
        template[4].ulValueLen = sizeof (true);
        template[5].type = CKA_VALUE;
        template[5].pValue = key->contents;
        template[5].ulValueLen = key->length;

        /* Create an object handle for the key */
        if ((rv = C_CreateObject(hSession, template,
                sizeof(template)/sizeof(CK_ATTRIBUTE),
                &key->hKey)) != CKR_OK) {

                KRB5_LOG(KRB5_ERR, "C_CreateObject failed in "
                	"init_key_uef: rv = 0x%x.", rv);
		rv = PKCS_ERR;
        }

        return (rv);

}

#endif /* _KERNEL */

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_c_encrypt(krb5_context context, const krb5_keyblock *key,
	       krb5_keyusage usage, const krb5_data *ivec,
	       const krb5_data *input, krb5_enc_data *output)
{
    krb5_error_code ret;
    int i;

    KRB5_LOG(KRB5_INFO, "krb5_c_encrypt start etype = %d", key->enctype);
    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    output->magic = KV5M_ENC_DATA;
    output->kvno = 0;
    output->enctype = key->enctype;

#ifdef _KERNEL
    context->kef_cipher_mt = krb5_enctypes_list[i].kef_cipher_mt;
    context->kef_hash_mt = krb5_enctypes_list[i].kef_hash_mt;
    if (key->kef_key.ck_data == NULL) {
	if ((ret = init_key_kef(context->kef_cipher_mt,
			    (krb5_keyblock *)key)))
	    	return(ret);
    }
#else
    if ((ret = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key)))
	return (ret);

#endif /* _KERNEL */

    KRB5_LOG0(KRB5_INFO, "krb5_c_encrypt calling encrypt.");
    return((*(krb5_enctypes_list[i].encrypt))
	   (context, krb5_enctypes_list[i].enc, krb5_enctypes_list[i].hash,
	    key, usage, ivec, input, &output->ciphertext));
}
