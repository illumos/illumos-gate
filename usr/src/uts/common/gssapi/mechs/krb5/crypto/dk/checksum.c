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
#include "dk.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

/*
 * Derive the key for checksum calculation.
 * This is only called (currently) for SHA1-DES3
 * checksum types.
 *
 * The primary benefit here is that a KEF template
 * is created for use when doing the HMAC operation which
 * saves ALOT of computation cycles and improves performance.
 */
static krb5_error_code
derive_cksum_key(krb5_context context,
		struct krb5_enc_provider *enc,
		const krb5_keyblock *key,
		krb5_keyusage usage,
		krb5_keyblock **outkey)
{
	krb5_error_code ret = 0;
	krb5_keyblock *cached_key = NULL;
	krb5_data d1;
	unsigned char constantdata[K5CLENGTH];

	cached_key = find_derived_key(usage, DK_CKSUM_KEY_BYTE,
				    (krb5_keyblock *)key);
	if (cached_key)
		*outkey = cached_key;
	else {
		*outkey = krb5_create_derived_keyblock(key->length);
		if (*outkey == NULL)
			return (ENOMEM);

		constantdata[0] = (usage>>24)&0xff;
		constantdata[1] = (usage>>16)&0xff;
		constantdata[2] = (usage>>8)&0xff;
		constantdata[3] = usage&0xff;
		constantdata[4] = DK_CKSUM_KEY_BYTE;

		d1.data = (char *)constantdata;
		d1.length = sizeof(constantdata);

		ret = krb5_derive_key(context, enc, key,
				    *outkey, &d1);
		if (ret) {
			krb5_free_keyblock(context, *outkey);
			*outkey = NULL;
			return (ret);
		}
#ifdef _KERNEL
		/*
		 * By default, derived keys get the "mech_type"
		 * that was associated with their parent.
		 * we need to switch the mech_type to correspond
		 * to the checksum mech type.
		 */
		if (ret == 0 &&
		    (*outkey)->kef_mt != context->kef_cksum_mt) {
			(*outkey)->kef_mt = context->kef_cksum_mt;
			if ((*outkey)->key_tmpl != NULL) {
				crypto_destroy_ctx_template((*outkey)->key_tmpl);
				(*outkey)->key_tmpl = NULL;
			}
			ret = update_key_template(*outkey);
		}
#endif /* _KERNEL */
		if (ret == 0)
			ret = add_derived_key((krb5_keyblock *)key, usage,
			    DK_CKSUM_KEY_BYTE,
			    *outkey);
	}

	KRB5_LOG0(KRB5_INFO, "derive_cksum_key() end.");
	return (ret);
}

/* ARGSUSED */
krb5_error_code
krb5_dk_make_checksum(context, hash, key, usage, input, output)
     krb5_context context;
     krb5_const struct krb5_hash_provider *hash;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *input;
     krb5_data *output;
{
    int i;
    krb5_error_code ret;
    krb5_keyblock *cksum_key = NULL;
    struct krb5_enc_provider *enc = NULL;

    KRB5_LOG0(KRB5_INFO, "krb5_dk_make_checksum() start");

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
	    break;
    }

    if (i == krb5_enctypes_length) {
	KRB5_LOG(KRB5_ERR, "krb5_ck_make_checksum bad enctype: %d",
		key->enctype);
	return(KRB5_BAD_ENCTYPE);
    }
    enc = (struct krb5_enc_provider *)krb5_enctypes_list[i].enc;

#ifdef _KERNEL
    if (key->kef_key.ck_data == NULL &&
	(ret = init_key_kef(krb5_enctypes_list[i].kef_cipher_mt,
			    (krb5_keyblock *)key)))
	    goto cleanup;
#endif
    ret = derive_cksum_key(context, enc, key, usage, &cksum_key);
    if (ret != 0)
	    goto cleanup;

#ifdef _KERNEL
    if ((ret = krb5_hmac(context, (krb5_keyblock *)cksum_key,
			input, output))) {
	KRB5_LOG(KRB5_ERR, "krb5_hmac error: %0x", ret);
	(void) memset(output->data, 0, output->length);
    }
#else
    if ((ret = krb5_hmac(context, hash, cksum_key, 1, input, output)) != 0) {
	KRB5_LOG(KRB5_ERR, "krb5_hmac error: %0x", ret);
	(void) memset(output->data, 0, output->length);
    }
#endif /* _KERNEL */
cleanup:

    KRB5_LOG0(KRB5_INFO, "krb5_dk_make_checksum() end");
    return(ret);
}

