/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
  * Copyright2001 by the Massachusetts Institute of Technology.
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
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

/* Solaris Kerberos:  order is important here.  include gssapiP_krb5.h
 * before all others, otherwise we get a LINT error from MALLOC macro
 * being redefined in mechglueP.h */
#include <gssapiP_krb5.h>
#include <k5-int.h>

/* Solaris Kerberos defines memory management macros in <krb5.h> */
/* #include <memory.h> */

/*
 * $Id: util_crypt.c,v 1.11.6.3 2000/06/03 06:09:45 tlyu Exp $
 */

int
kg_confounder_size(context, key)
     krb5_context context;
     krb5_keyblock *key;
{
   krb5_error_code code;
   size_t blocksize;
   /* We special case rc4*/
   if (key->enctype == ENCTYPE_ARCFOUR_HMAC)
     return 8;
   code = krb5_c_block_size(context, key->enctype, &blocksize);
   if (code)
      return(-1); /* XXX */

   return(blocksize);
}

krb5_error_code
kg_make_confounder(context, key, buf)
     krb5_context context;
     krb5_keyblock *key;
     unsigned char *buf;
{
   krb5_error_code code;
   size_t blocksize;
   krb5_data lrandom;

   code = krb5_c_block_size(context, key->enctype, &blocksize);
   if (code)
       return(code);

   lrandom.length = blocksize;
   lrandom.data = (char *) buf;

   return(krb5_c_random_make_octets(context, &lrandom));
}

int
kg_encrypt_size(context, key, n)
     krb5_context context;
     krb5_keyblock *key;
     int n;
{
   size_t enclen;

   if (krb5_c_encrypt_length(context, key->enctype, n, &enclen) != 0)
      return(-1); /* XXX */

   return(enclen);
}

krb5_error_code
kg_encrypt(context, key, usage, iv, in, out, length)
     krb5_context context;
     krb5_keyblock *key;
     int usage;
     krb5_pointer iv;
     krb5_const_pointer in;
     krb5_pointer out;
     unsigned int length;
{
   krb5_error_code code;
   size_t blocksize;
   krb5_data ivd, *pivd, inputd;
   krb5_enc_data outputd;

   KRB5_LOG0(KRB5_INFO, "kg_encrypt() start.");

   if (iv) {
       code = krb5_c_block_size(context, key->enctype, &blocksize);
       if (code)
	   return(code);

       ivd.length = blocksize;
       ivd.data = MALLOC(ivd.length);
       if (ivd.data == NULL)
	   return ENOMEM;
       (void) memcpy(ivd.data, iv, ivd.length);
       pivd = &ivd;
   } else {
       pivd = NULL;
   }

   inputd.length = length;
   inputd.data = (char *)in; /* Solaris Kerberos */

   outputd.ciphertext.length = length;
   outputd.ciphertext.data = out;

   code = krb5_c_encrypt(context, key, usage, pivd, &inputd, &outputd);
   if (pivd != NULL)
       krb5_free_data_contents(context, pivd);

   KRB5_LOG(KRB5_INFO, "kg_encrypt() end. code = %d", code);
   return code;
}

/* length is the length of the cleartext. */

krb5_error_code
kg_decrypt(context, key, usage, iv, in, out, length)
     krb5_context context;
     krb5_keyblock *key;
     int usage;
     krb5_pointer iv;
     krb5_const_pointer in;
     krb5_pointer out;
     unsigned int length;
{
   krb5_error_code code;
   size_t blocksize;
   krb5_data ivd, *pivd, outputd;
   krb5_enc_data inputd;
   KRB5_LOG0(KRB5_INFO, "kg_decrypt() start.");

   if (iv) {
       code = krb5_c_block_size(context, key->enctype, &blocksize);
       if (code)
	   return(code);

       ivd.length = blocksize;
       ivd.data = MALLOC(ivd.length);
       if (ivd.data == NULL)
	   return ENOMEM;
       (void) memcpy(ivd.data, iv, ivd.length);
       pivd = &ivd;
   } else {
       pivd = NULL;
   }

   inputd.enctype = ENCTYPE_UNKNOWN;
   inputd.ciphertext.length = length;
   inputd.ciphertext.data = (char *)in; /* Solaris Kerberos */

   outputd.length = length;
   outputd.data = out;

   code = krb5_c_decrypt(context, key, usage, pivd, &inputd, &outputd);
   if (pivd != NULL)
       krb5_free_data_contents(context, pivd);

   KRB5_LOG(KRB5_INFO, "kg_decrypt() end. code = %d", code);
   return code;
}

krb5_error_code
kg_arcfour_docrypt (krb5_context context,
		const krb5_keyblock *longterm_key , int ms_usage,
		const unsigned char *kd_data, size_t kd_data_len,
		const unsigned char *input_buf, size_t input_len,
		unsigned char *output_buf)
{
  krb5_error_code code;
  krb5_data input, output;
  krb5_keyblock seq_enc_key, usage_key;
  unsigned char t[4];

  KRB5_LOG0(KRB5_INFO, "kg_arcfour_docrypt() start");

  bzero(&usage_key, sizeof(krb5_keyblock));
  bzero(&seq_enc_key, sizeof(krb5_keyblock));

  usage_key.length = longterm_key->length;
  usage_key.contents = MALLOC(usage_key.length);
  usage_key.enctype = longterm_key->enctype;
  usage_key.dk_list = NULL;
#ifdef _KERNEL

  usage_key.kef_mt  = longterm_key->kef_mt;
  code = init_key_kef(longterm_key->kef_mt, &usage_key);
  if (code)
	return (code);
#endif /* _KERNEL */
  if (usage_key.contents == NULL)
    return (ENOMEM);
  seq_enc_key.length = longterm_key->length;
  seq_enc_key.contents = MALLOC(seq_enc_key.length);
  seq_enc_key.enctype = longterm_key->enctype;
  seq_enc_key.dk_list = NULL;
#ifdef _KERNEL
  seq_enc_key.kef_mt  = longterm_key->kef_mt;
  code = init_key_kef(longterm_key->kef_mt, &seq_enc_key);
  if (code)
	return (code);
#endif /* _KERNEL */
  if (seq_enc_key.contents == NULL) {
    FREE ((void *) usage_key.contents, usage_key.length);
    return (ENOMEM);
  }

  t[0] = ms_usage &0xff;
  t[1] = (ms_usage>>8) & 0xff;
  t[2] = (ms_usage>>16) & 0xff;
  t[3] = (ms_usage>>24) & 0xff;
  input.data = (void *) &t;
  input.length = 4;
  output.data = (void *) usage_key.contents;
  output.length = usage_key.length;
#ifdef _KERNEL
  code = krb5_hmac(context, longterm_key, &input, &output);
#else
  code = krb5_hmac(context, &krb5int_hash_md5,
		longterm_key, 1, &input, &output);
#endif /* _KERNEL */
  if (code)
    goto cleanup_arcfour;

  input.data = ( void *) kd_data;
  input.length = kd_data_len;
  output.data = (void *) seq_enc_key.contents;
#ifdef _KERNEL
  code = krb5_hmac(context, &usage_key, &input, &output);
#else
  code = krb5_hmac(context, &krb5int_hash_md5,
		&usage_key, 1, &input, &output);
#endif /* _KERNEL */

  if (code)
    goto cleanup_arcfour;
  input.data = ( void * ) input_buf;
  input.length = input_len;
  output.data = (void * ) output_buf;
  output.length = input_len;

  /*
   * Call the arcfour encryption method directly here, we cannot
   * use the standard "krb5_c_encrypt" interface because we just
   * want the arcfour algorithm applied and not the additional MD5-HMAC
   * which are applied when using the standard interface.
   */
  code = krb5int_enc_arcfour.encrypt(context, &seq_enc_key, 0, &input, &output);

 cleanup_arcfour:
  bzero ((void *) seq_enc_key.contents, seq_enc_key.length);
  bzero ((void *) usage_key.contents, usage_key.length);
  FREE ((void *) usage_key.contents, usage_key.length);
  FREE ((void *) seq_enc_key.contents, seq_enc_key.length);

  KRB5_LOG(KRB5_INFO, "kg_arcfour_docrypt() end code = %d", code);
  return (code);
}

