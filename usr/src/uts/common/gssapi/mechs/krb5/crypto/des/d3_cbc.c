/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1995 by Richard P. Basch.  All Rights Reserved.
 * Copyright 1995 by Lehman Brothers, Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Richard P. Basch, Lehman Brothers and M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.  Richard P. Basch,
 * Lehman Brothers and M.I.T. make no representations about the suitability
 * of this software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

#include "des_int.h"

/*
 * Triple-DES CBC encryption mode.
 */
#ifndef _KERNEL
int
mit_des3_cbc_encrypt(krb5_context context, const mit_des_cblock *in, mit_des_cblock *out,
		     unsigned long length, krb5_keyblock *key,
		     const mit_des_cblock ivec, int encrypt)
{
    int ret = KRB5_PROG_ETYPE_NOSUPP;
    KRB5_MECH_TO_PKCS algos;
    CK_MECHANISM mechanism;
    CK_RV rv;
    /* For the Key Object */
    ret = 0;

    if ((rv = get_algo(key->enctype, &algos)) != CKR_OK) {
        KRB5_LOG0(KRB5_ERR, "failure to get algo id in function "
            "mit_des3_cbc_encrypt.");
        ret = PKCS_ERR;
        goto cleanup;
    }

    rv = init_key_uef(krb_ctx_hSession(context), key);
    if (rv != CKR_OK) {
        KRB5_LOG(KRB5_ERR, "init_key_uef failed in "
            "mit_des3_cbc_encrypt: rv = 0x%0x", rv);
        ret = PKCS_ERR;
        goto cleanup;
    }

    mechanism.mechanism = algos.enc_algo;
    mechanism.pParameter = (void*)ivec;
    if (ivec != NULL)
    	mechanism.ulParameterLen = sizeof(mit_des_cblock);
    else
	mechanism.ulParameterLen = 0;

    if (encrypt)
        rv = C_EncryptInit(krb_ctx_hSession(context), &mechanism, key->hKey);
    else
        rv = C_DecryptInit(krb_ctx_hSession(context), &mechanism, key->hKey);

    if (rv != CKR_OK) {
        KRB5_LOG(KRB5_ERR, "C_EncryptInit/C_DecryptInit failed in "
		"mit_des3_cbc_encrypt: rv = 0x%x", rv);
        ret = PKCS_ERR;
        goto cleanup;
    }

    if (encrypt)
        rv = C_Encrypt(krb_ctx_hSession(context), (CK_BYTE_PTR)in,
            (CK_ULONG)length, (CK_BYTE_PTR)out,
            (CK_ULONG_PTR)&length);
    else
        rv = C_Decrypt(krb_ctx_hSession(context), (CK_BYTE_PTR)in,
            (CK_ULONG)length, (CK_BYTE_PTR)out,
            (CK_ULONG_PTR)&length);

    if (rv != CKR_OK) {
            KRB5_LOG(KRB5_ERR,
                "C_Encrypt/C_Decrypt failed in mit_des3_cbc_encrypt: "
                "rv = 0x%x", rv);
            ret = PKCS_ERR;
    }
cleanup:

final_cleanup:
    if (ret)
        (void) memset(out, 0, length);

    KRB5_LOG(KRB5_INFO, "mit_des3_cbc_encrypt() end ret=%d\n", ret); 
    return(ret);
}

#else
#include <sys/crypto/api.h>

/* ARGSUSED */
int
mit_des3_cbc_encrypt(krb5_context context,
	const mit_des_cblock *in,
	mit_des_cblock *out,
        unsigned long length, krb5_keyblock *key,
        const mit_des_cblock ivec, int encrypt)
{
	int ret = KRB5_PROG_ETYPE_NOSUPP;
	krb5_data ivdata;

        KRB5_LOG(KRB5_INFO, "mit_des3_cbc_encrypt() start encrypt=%d", encrypt);

	ivdata.data = (char *)ivec;
	ivdata.length = sizeof(mit_des_cblock);

        ret = k5_ef_crypto((const char *)in, (char *)out,
			length, key, &ivdata, encrypt);

        KRB5_LOG(KRB5_INFO, "mit_des3_cbc_encrypt() end retval=%d", ret);
        return(ret);
}
#endif /* !_KERNEL */
