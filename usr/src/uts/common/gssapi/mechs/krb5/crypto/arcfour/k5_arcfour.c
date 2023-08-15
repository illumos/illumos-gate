/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*

ARCFOUR cipher (based on a cipher posted on the Usenet in Spring-95).
This cipher is widely believed and has been tested to be equivalent
with the RC4 cipher from RSA Data Security, Inc.  (RC4 is a trademark
of RSA Data Security)

*/
#include <k5-int.h>
#include <arcfour.h>

/* salt string used  for exportable ARCFOUR */
static const  char *l40 = "fortybits";

void
krb5_arcfour_encrypt_length(enc, hash, inputlen, length)
     const struct krb5_enc_provider *enc;
     const struct krb5_hash_provider *hash;
     size_t inputlen;
     size_t *length;
{
  size_t blocksize, hashsize;

  blocksize = enc->block_size;
  hashsize = hash->hashsize;

  /* checksum + (confounder + inputlen, in even blocksize) */
  *length = hashsize + krb5_roundup(8 + inputlen, blocksize);
}

krb5_keyusage
krb5int_arcfour_translate_usage(krb5_keyusage usage)
{
  switch (usage) {
  case 1:			/* AS-REQ PA-ENC-TIMESTAMP padata timestamp,  */
    return 1;
  case 2:			/* ticket from kdc */
    return 2;
  case 3:			/* as-rep encrypted part */
    return 8;
  case 4:			/* tgs-req authz data */
    return 4;
  case 5:			/* tgs-req authz data in subkey */
    return 5;
  case 6:			/* tgs-req authenticator cksum */
    return 6;
  case 7:			/* tgs-req authenticator */
    return 7;
  case 8:
    return 8;
  case 9:			/* tgs-rep encrypted with subkey */
    return 8;
  case 10:			/* ap-rep authentication cksum */
    return 10;			/* xxx  Microsoft never uses this*/
  case 11:			/* app-req authenticator */
    return 11;
  case 12:			/* app-rep encrypted part */
    return 12;
  case 23: /* sign wrap token*/
    return 13;
  default:
      return usage;
}
}

krb5_error_code
krb5_arcfour_encrypt(context, enc, hash, key, usage, ivec, input, output)
     krb5_context context;
     const struct krb5_enc_provider *enc;
     const struct krb5_hash_provider *hash;
     const krb5_keyblock *key;
     krb5_keyusage usage;
     const krb5_data *ivec;
     const krb5_data *input;
     krb5_data *output;
{
  krb5_keyblock k1, k2, k3;
  krb5_keyblock *kptr;
  krb5_data d1, d2, d3, salt, plaintext, checksum, ciphertext, confounder;
  krb5_keyusage ms_usage;
  size_t keybytes, blocksize, hashsize;
  krb5_error_code ret = 0;

  blocksize = enc->block_size;
  keybytes = enc->keybytes;
  hashsize = hash->hashsize;

  bzero(&d2, sizeof(krb5_data));
  bzero(&k2, sizeof(krb5_keyblock));
  /*
   * d1 is the contents buffer for key k1.
   * k1  = HMAC(input_key, salt)
   */
  d1.length=keybytes;
  d1.data=MALLOC(d1.length);
  if (d1.data == NULL)
    return (ENOMEM);
  bcopy(key, &k1, sizeof (krb5_keyblock));
  k1.length=d1.length;
  k1.contents= (void *) d1.data;

  /*
   * d2 is the contents of key 'k2', which is used to generate the
   * checksum field.  'd2' == 'd1' when not using the exportable
   * enctype.  This is only needed when using the exportable
   * enctype.
   */
  if (key->enctype==ENCTYPE_ARCFOUR_HMAC_EXP) {
	d2.length=keybytes;
	d2.data=MALLOC(d2.length);
	if (d2.data == NULL) {
		FREE(d1.data, d1.length);
		return (ENOMEM);
	}
	bcopy(key, &k2, sizeof (krb5_keyblock));
	k2.length=d2.length;
	k2.contents=(void *) d2.data;
  }

  /*
   * d3 will hold the contents of the final key used for the
   * encryption step.  'k3' is the key structure that has 'd3'
   * as its 'contents' field.
   * k3 = HMAC(k1, checksum)
   */
  d3.length=keybytes;
  d3.data=MALLOC(d3.length);
  if (d3.data == NULL) {
    FREE(d1.data, d1.length);
    if (d2.data)
	FREE(d2.data, d2.length);
    return (ENOMEM);
  }
  bcopy(key, &k3, sizeof (krb5_keyblock));
  k3.length=d3.length;
  k3.contents= (void *) d3.data;

  salt.length=14;
  salt.data=MALLOC(salt.length);

  if (salt.data == NULL) {
    FREE(d1.data, d1.length);
    if (d2.data)
	FREE(d2.data, d2.length);
    FREE(d3.data, d3.length);
    return (ENOMEM);
  }

  /* is "input" already blocksize aligned?  if it is, then we need this
     step, otherwise we do not */
  plaintext.length=krb5_roundup(input->length+CONFOUNDERLENGTH,blocksize);
  plaintext.data=MALLOC(plaintext.length);

  if (plaintext.data == NULL) {
    FREE(d1.data, d1.length);
    if (d2.data)
	FREE(d2.data, d2.length);
    FREE(d3.data, d3.length);
    FREE(salt.data, salt.length);
    return(ENOMEM);
  }
  bzero(plaintext.data, plaintext.length);

  /* setup convienient pointers into the allocated data */
  checksum.length=hashsize;
  checksum.data=output->data;

  ciphertext.length=krb5_roundup(input->length+CONFOUNDERLENGTH,blocksize);
  ciphertext.data=output->data+hashsize;

  confounder.length=CONFOUNDERLENGTH;
  confounder.data=plaintext.data;

  output->length = plaintext.length+hashsize;

  /* begin the encryption, computer K1 */
  ms_usage=krb5int_arcfour_translate_usage(usage);
  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
    (void) strncpy(salt.data, l40, salt.length);
    salt.data[10]=ms_usage & 0xff;
    salt.data[11]=(ms_usage >> 8) & 0xff;
    salt.data[12]=(ms_usage >> 16) & 0xff;
    salt.data[13]=(ms_usage >> 24) & 0xff;
  } else {
    salt.length=4;
    salt.data[0]=ms_usage & 0xff;
    salt.data[1]=(ms_usage >> 8) & 0xff;
    salt.data[2]=(ms_usage >> 16) & 0xff;
    salt.data[3]=(ms_usage >> 24) & 0xff;
  }

#ifdef _KERNEL
  ret = krb5_hmac(context, key, &salt, &d1);
#else
  ret = krb5_hmac(context, hash, key, 1, &salt, &d1);
#endif /* _KERNEL */
  if (ret != 0)
	goto cleanup;

  if (key->enctype==ENCTYPE_ARCFOUR_HMAC_EXP) {
    bcopy(k1.contents, k2.contents, k2.length);
    (void) memset(k1.contents+7, 0xab, 9);
    kptr = &k2;
  } else {
    kptr = &k1;
  }

  /* create a confounder block */
  ret=krb5_c_random_make_octets(context, &confounder);
  bcopy(input->data, plaintext.data+confounder.length, input->length);
  if (ret)
    goto cleanup;

  /*
   * Compute the HMAC checksum field.
   * checksum = HMAC(k1/k2, plaintext);
   *    k2 used when key->enctype==ENCTYPE_ARCFOUR_HMAC_EXP
   */
#ifdef _KERNEL
  ret = krb5_hmac(context, kptr, &plaintext, &checksum);
#else
  ret = krb5_hmac(context, hash, kptr, 1, &plaintext, &checksum);
#endif /* _KERNEL */
  if (ret)
    goto cleanup;

  /*
   * The final encryption key is the HMAC of the checksum
   * using k1
   *
   * k3 = HMAC(k1, checksum);
   *  == or (in other terms) ==
   * k3 = HMAC((HMAC(input_key,salt), HMAC(k1, plaintext));
   */
#ifdef _KERNEL
  ret = krb5_hmac(context, &k1, &checksum, &d3);
#else
  ret = krb5_hmac(context, hash, &k1, 1,  &checksum, &d3);
#endif /* _KERNEL */
  if (ret)
    goto cleanup;

  ret = (*(enc->encrypt))(context, &k3, ivec, &plaintext, &ciphertext);

 cleanup:
  bzero(d1.data, d1.length);
  if (d2.data) {
	bzero(d2.data, d2.length);
	FREE(d2.data, d2.length);
  }
  bzero(d3.data, d3.length);
  bzero(salt.data, salt.length);
  bzero(plaintext.data, plaintext.length);

  FREE(d1.data, d1.length);
  FREE(d3.data, d3.length);
  FREE(salt.data, salt.length);
  FREE(plaintext.data, plaintext.length);
  return (ret);
}

/* This is the arcfour-hmac decryption routine */
krb5_error_code
krb5_arcfour_decrypt(context, enc, hash, key, usage, ivec, input, output)
     krb5_context context;
     const struct krb5_enc_provider *enc;
     const struct krb5_hash_provider *hash;
     const krb5_keyblock *key;
     krb5_keyusage usage;
     const krb5_data *ivec;
     const krb5_data *input;
     krb5_data *output;
{
  krb5_keyblock k1,k2,k3, *kptr;
  krb5_data d1,d2,d3,salt,ciphertext,plaintext,checksum;
  krb5_keyusage ms_usage;
  size_t keybytes, hashsize;
  krb5_error_code ret;

  keybytes = enc->keybytes;
  hashsize = hash->hashsize;

  /* Verify input and output lengths. */
  if (input->length < hashsize + CONFOUNDERLENGTH)
	return KRB5_BAD_MSIZE;
  if (output->length < input->length - hashsize - CONFOUNDERLENGTH)
	return KRB5_BAD_MSIZE;

  bzero(&d2, sizeof(krb5_data));
  bzero(&k2, sizeof(krb5_keyblock));
  /*
   * d1 is the contents buffer for key k1.
   * k1  = HMAC(input_key, salt)
   */
  d1.length=keybytes;
  d1.data=MALLOC(d1.length);
  if (d1.data == NULL)
    return (ENOMEM);
  (void) bcopy(key, &k1, sizeof (krb5_keyblock));
  k1.length=d1.length;
  k1.contents= (void *) d1.data;

  /*
   * d2 is the contents of key 'k2', which is used to generate the
   * checksum field.  'd2' == 'd1' when not using the exportable
   * enctype.  This is only needed when using the exportable
   * enctype.
   */
  if (key->enctype==ENCTYPE_ARCFOUR_HMAC_EXP) {
	d2.length=keybytes;
	d2.data=MALLOC(d2.length);
	if (d2.data == NULL) {
		FREE(d1.data, d1.length);
		return (ENOMEM);
	}
	(void) bcopy(key, &k2, sizeof(krb5_keyblock));
	k2.length=d2.length;
	k2.contents= (void *) d2.data;
  }

  /*
   * d3 will hold the contents of the final key used for the
   * encryption step.  'k3' is the key structure that has 'd3'
   * as its 'contents' field.
   * k3 = HMAC(k1, checksum)
   */
  d3.length=keybytes;
  d3.data=MALLOC(d3.length);
  if  (d3.data == NULL) {
    FREE(d1.data, d1.length);
    if (d2.data)
	FREE(d2.data, d2.length);
    return (ENOMEM);
  }
  bcopy(key, &k3, sizeof(krb5_keyblock));
  k3.length=d3.length;
  k3.contents= (void *) d3.data;

  salt.length=14;
  salt.data=MALLOC(salt.length);
  if(salt.data==NULL) {
    FREE(d1.data, d1.length);
    if (d2.data)
	FREE(d2.data, d2.length);
    FREE(d3.data, d3.length);
    return (ENOMEM);
  }

  ciphertext.length=input->length-hashsize;
  ciphertext.data=input->data+hashsize;

  plaintext.length=ciphertext.length;
  plaintext.data=MALLOC(plaintext.length);
  if (plaintext.data == NULL) {
    FREE(d1.data, d1.length);
    if (d2.data)
	FREE(d2.data, d2.length);
    FREE(d3.data, d3.length);
    FREE(salt.data, salt.length);
    return (ENOMEM);
  }

  checksum.length=hashsize;
  checksum.data=input->data;

  /* compute the salt */
  ms_usage=krb5int_arcfour_translate_usage(usage);
  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
    (void) strncpy(salt.data, l40, salt.length);
    salt.data[10]=ms_usage & 0xff;
    salt.data[11]=(ms_usage>>8) & 0xff;
    salt.data[12]=(ms_usage>>16) & 0xff;
    salt.data[13]=(ms_usage>>24) & 0xff;
  } else {
    salt.length=4;
    salt.data[0]=ms_usage & 0xff;
    salt.data[1]=(ms_usage>>8) & 0xff;
    salt.data[2]=(ms_usage>>16) & 0xff;
    salt.data[3]=(ms_usage>>24) & 0xff;
  }

#ifdef _KERNEL
  ret=krb5_hmac(context, key, &salt, &d1);
#else
  ret=krb5_hmac(context, hash, key, 1, &salt, &d1);
#endif /* _KERNEL */
  if (ret)
    goto cleanup;

  if (key->enctype == ENCTYPE_ARCFOUR_HMAC_EXP) {
    bcopy(k1.contents, k2.contents, d1.length);
    (void) memset(k1.contents+7, 0xab, 9);
    kptr = &k2;
  } else {
    kptr = &k1;
  }

#ifdef _KERNEL
  ret = krb5_hmac(context, &k1, &checksum, &d3);
#else
  ret = krb5_hmac(context, hash, &k1, 1, &checksum, &d3);
#endif /* _KERNEL */

  if (ret)
    goto cleanup;

  ret=(*(enc->decrypt))(context, &k3, ivec, &ciphertext, &plaintext);
  if (ret)
    goto cleanup;

#ifdef _KERNEL
  ret = krb5_hmac(context, kptr, &plaintext, &d1);
#else
  ret = krb5_hmac(context, hash, kptr, 1, &plaintext, &d1);
#endif /* _KERNEL */

  if (ret)
    goto cleanup;

  if (bcmp(checksum.data, d1.data, hashsize) != 0) {
    ret=KRB5KRB_AP_ERR_BAD_INTEGRITY;
    goto cleanup;
  }

  bcopy(plaintext.data+CONFOUNDERLENGTH, output->data,
	 (plaintext.length-CONFOUNDERLENGTH));
  output->length=plaintext.length-CONFOUNDERLENGTH;

 cleanup:
  bzero(d1.data, d1.length);
  if (d2.data) {
	bzero(d2.data, d2.length);
	FREE(d2.data, d2.length);
  }
  bzero(d3.data, d2.length);
  bzero(salt.data, salt.length);
  bzero(plaintext.data, plaintext.length);

  FREE(d1.data, d1.length);
  FREE(d3.data, d3.length);
  FREE(salt.data, salt.length);
  FREE(plaintext.data, plaintext.length);

  return (ret);
}

