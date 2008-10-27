/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/crypto/pbkdf2.c
 *
 * Copyright 2002 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Implementation of PBKDF2 from RFC 2898.
 * Not currently used; likely to be used when we get around to AES support.
 */

#ifndef _KERNEL

#include <ctype.h>
#include "k5-int.h"
#include "hash_provider.h"

/*
 * Solaris Kerberos:
 * MIT code ripped out, use PBKDF2 algorithm from PKCS#11
 * provider.
 */
krb5_error_code
krb5int_pbkdf2_hmac_sha1(
	krb5_context context,
	const krb5_data *out,
	unsigned long count,
	krb5_enctype enctype,
	const krb5_data *pass, const krb5_data *salt)
{
	krb5_error_code ret = 0;
	CK_RV rv;
	CK_PKCS5_PBKD2_PARAMS params;
	CK_MECHANISM mechanism;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_ATTRIBUTE tmpl[3];
	CK_KEY_TYPE	keytype;
	CK_OBJECT_HANDLE hKey;
	int attrs = 0;
	CK_ULONG outlen, passlen;

	mechanism.mechanism = CKM_PKCS5_PBKD2;
	mechanism.pParameter = &params;
	mechanism.ulParameterLen = sizeof (params);

	tmpl[attrs].type = CKA_CLASS;
	tmpl[attrs].pValue = &class;
	tmpl[attrs].ulValueLen = sizeof (class);
	attrs++;

	rv = get_key_type(enctype, &keytype);
	if (rv != CKR_OK)
		return (PKCS_ERR);

	tmpl[attrs].type = CKA_KEY_TYPE;
	tmpl[attrs].pValue = &keytype;
	tmpl[attrs].ulValueLen = sizeof (keytype);
	attrs++;

	/*
	 * For DES key types, do not include the value len attr.
	 */
	if (out->length > 0 &&
	    enctype != ENCTYPE_DES_CBC_CRC &&
	    enctype != ENCTYPE_DES_CBC_MD5 &&
	    enctype != ENCTYPE_DES_CBC_RAW &&
	    enctype != ENCTYPE_DES_HMAC_SHA1 &&
	    enctype != ENCTYPE_DES3_CBC_SHA1 &&
	    enctype != ENCTYPE_DES3_CBC_RAW) {
		tmpl[attrs].type = CKA_VALUE_LEN;
		/* using outlen to avoid 64bit alignment issues */
		outlen = (CK_ULONG)out->length;
		tmpl[attrs].pValue = &outlen;
		tmpl[attrs].ulValueLen = sizeof (outlen);
		attrs++;
	}

	params.saltSource = CKZ_SALT_SPECIFIED;
	params.pSaltSourceData = (void *)salt->data;
	params.ulSaltSourceDataLen = salt->length;
	params.iterations = count;
	params.prf = CKP_PKCS5_PBKD2_HMAC_SHA1;
	params.pPrfData = NULL;
	params.ulPrfDataLen = 0;
	params.pPassword = (CK_UTF8CHAR_PTR)pass->data;
	/* using passlen to avoid 64bit alignment issues */
	passlen = (CK_ULONG)pass->length;
	params.ulPasswordLen = &passlen;

	rv = C_GenerateKey(krb_ctx_hSession(context), &mechanism, tmpl,
	    attrs, &hKey);

	if (rv != CKR_OK)
		ret = PKCS_ERR;
	else {
		/* Get the value from the key object. */
		tmpl[0].type = CKA_VALUE;
		tmpl[0].pValue = out->data;
		tmpl[0].ulValueLen = out->length;
		rv = C_GetAttributeValue(krb_ctx_hSession(context), hKey,
		    tmpl, 1);
		if (rv != CKR_OK)
			ret = PKCS_ERR;
		(void) C_DestroyObject(krb_ctx_hSession(context), hKey);
	}

	return (ret);
}
#endif /* !_KERNEL */
