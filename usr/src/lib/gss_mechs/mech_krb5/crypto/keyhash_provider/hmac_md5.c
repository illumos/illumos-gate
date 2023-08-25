/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/crypto/keyhash_provider/hmac_md5.c
 *
(I don't know)
.
 * Copyright2001 by the Massachusetts Institute of Technology.
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
* Implementation of the Microsoft hmac-md5 checksum type.
* Implemented based on draft-brezak-win2k-krb-rc4-hmac-03
 */

#include "k5-int.h"
#include "keyhash_provider.h"
#include "arcfour.h"
#include "hash_provider.h"

static  krb5_error_code
k5_hmac_md5_hash (krb5_context context,
	const krb5_keyblock *key, krb5_keyusage usage,
	const krb5_data *iv,
	const krb5_data *input, krb5_data *output)
{
  krb5_keyusage ms_usage;
  krb5_error_code ret;
  krb5_keyblock ks;
  krb5_data ds, ks_constant, md5tmp;
  krb5_data hash_input[2];
  char digest[MD5_CKSUM_LENGTH];
  char t[4];
  CK_MECHANISM mechanism;
  CK_RV rv;
  CK_ULONG hashlen;

  bzero(&ks, sizeof(krb5_keyblock));

  /*
   * Solaris Kerberos: The digest length is that of MD5_CKSUM_LENGTH not the key
   * length, as keys can be of varying lengths but should not affect the digest
   * length.  The signing key is the digest and therefore is also the same
   * length, MD5_CKSUM_LENGTH.
   */
  ds.length = MD5_CKSUM_LENGTH;
  ks.length = MD5_CKSUM_LENGTH;
  ds.data = malloc(ds.length);
  if (ds.data == NULL)
    return ENOMEM;
  ks.contents = (void *) ds.data;

  ks_constant.data = "signaturekey";
  ks_constant.length = strlen(ks_constant.data)+1; /* Including null*/

  /* Solaris Kerberos */
  ret = krb5_hmac(context, &krb5int_hash_md5, key, 1,
		   &ks_constant, &ds);
  if (ret)
    goto cleanup;

  ms_usage = krb5int_arcfour_translate_usage (usage);
  t[0] = (ms_usage) & 0xff;
  t[1] = (ms_usage>>8) & 0xff;
  t[2] = (ms_usage >>16) & 0xff;
  t[3] = (ms_usage>>24) & 0XFF;

  /* Solaris Kerberos */
  mechanism.mechanism = CKM_MD5;
  mechanism.pParameter = NULL_PTR;
  mechanism.ulParameterLen = 0;

  if ((rv = C_DigestInit(krb_ctx_hSession(context), &mechanism)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestInit failed in k5_md5_hmac_hash: "
	"rv = 0x%x.", rv);
	ret = PKCS_ERR;
	goto cleanup;
  }
  if ((rv = C_DigestUpdate(krb_ctx_hSession(context),
	(CK_BYTE_PTR)t, (CK_ULONG)sizeof(t))) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestUpdate failed in k5_md5_hmac_hash: "
            "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
  }
  if ((rv = C_DigestUpdate(krb_ctx_hSession(context),
	(CK_BYTE_PTR)input->data, (CK_ULONG)input->length)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestUpdate failed in k5_md5_hmac_hash: "
            "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
  }
  hashlen = MD5_CKSUM_LENGTH;
  if ((rv = C_DigestFinal(krb_ctx_hSession(context),
	(CK_BYTE_PTR)digest, (CK_ULONG_PTR)&hashlen)) != CKR_OK) {
	KRB5_LOG(KRB5_ERR, "C_DigestFinal failed in k5_md5_hmac_hash: "
            "rv = 0x%x", rv);
	ret = PKCS_ERR;
	goto cleanup;
  }

  md5tmp.data = digest;
  md5tmp.length = hashlen;

  ret = krb5_hmac (context, &krb5int_hash_md5, &ks, 1, &md5tmp, output);

cleanup:
  bzero(ks.contents, ks.length);
  bzero(md5tmp.data, md5tmp.length);
  FREE (ks.contents, ks.length);
  return (ret);
}



const struct krb5_keyhash_provider krb5int_keyhash_hmac_md5 = {
  16,
  k5_hmac_md5_hash,
  NULL /*checksum  again*/
};

