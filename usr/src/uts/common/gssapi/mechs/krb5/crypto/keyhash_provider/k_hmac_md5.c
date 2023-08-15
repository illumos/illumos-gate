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

#include <k5-int.h>
#include <etypes.h>
#include <keyhash_provider.h>
#include <arcfour.h>
#include <hash_provider.h>

/*ARGSUSED*/
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
  int i;
  char t[4], outbuf[MD5_CKSUM_LENGTH];

#ifdef _KERNEL
  KRB5_LOG1(KRB5_INFO, "k5_hmac_md5_hash() hash_mt = %ld cipher_mt = %ld",
	(ulong_t) context->kef_hash_mt,
	(ulong_t) context->kef_cipher_mt);
#endif

  for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
            break;
  }
  if (i == krb5_enctypes_length) {
	KRB5_LOG(KRB5_ERR, "krb5_ck_make_checksum bad enctype: %d",
		key->enctype);
	return(KRB5_BAD_ENCTYPE);
  }

  bzero(&ks, sizeof(krb5_keyblock));
  /*
   * Solaris Kerberos: The digest length is that of MD5_CKSUM_LENGTH not the key
   * length, as keys can be of varying lengths but should not affect the digest
   * length.  The signing key is the digest and therefore is also the same
   * length, MD5_CKSUM_LENGTH.
   */
  ds.length = MD5_CKSUM_LENGTH;
  ds.data = MALLOC(ds.length);
  if (ds.data == NULL)
    return (ENOMEM);
  ks.contents = (void *) ds.data;
  ks.length = MD5_CKSUM_LENGTH;

#ifdef _KERNEL
  if (key->kef_key.ck_data == NULL) {
	ret = init_key_kef(krb5_enctypes_list[i].kef_cipher_mt,
			(krb5_keyblock *)key);
	if (ret)
		goto cleanup;
  }

  ret = init_key_kef(krb5_enctypes_list[i].kef_cipher_mt, &ks);
  if (ret)
	goto cleanup;
#endif /* _KERNEL */

  ks_constant.data = "signaturekey";
  ks_constant.length = strlen(ks_constant.data)+1; /* Including null*/

#ifdef _KERNEL
  ret = krb5_hmac(context, (krb5_keyblock *)key, &ks_constant, &ds);
#else
  ret = krb5_hmac(context, &krb5int_hash_md5, key, 1, &ks_constant, &ds);
#endif /* _KERNEL */
  if (ret)
    goto cleanup;

  ms_usage = krb5int_arcfour_translate_usage (usage);
  t[0] = (ms_usage) & 0xff;
  t[1] = (ms_usage>>8) & 0xff;
  t[2] = (ms_usage >>16) & 0xff;
  t[3] = (ms_usage>>24) & 0XFF;

  hash_input[0].data = (char *)&t;
  hash_input[0].length = 4;
  hash_input[1].data = input->data;
  hash_input[1].length = input->length;

  md5tmp.data = (void *)outbuf;
  md5tmp.length = sizeof(outbuf);

  /* Use generic hash function that calls to kEF */
  if (k5_ef_hash(context, 2, hash_input, &md5tmp)) {
	return (KRB5_KEF_ERROR);
  }

#ifdef _KERNEL
  ret = krb5_hmac (context, &ks, &md5tmp, output);
#else
  ret = krb5_hmac (context, &krb5int_hash_md5, &ks, 1, &md5tmp, output);
#endif /* _KERNEL */

cleanup:
  bzero(md5tmp.data, md5tmp.length);
  bzero(ks.contents, ks.length);
  FREE (ks.contents, ks.length);
  return (ret);
}

 const struct krb5_keyhash_provider
krb5int_keyhash_hmac_md5 = {
                	MD5_CKSUM_LENGTH,
			k5_hmac_md5_hash,
			NULL /*checksum  again*/
			};

