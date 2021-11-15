/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2025 RackTop Systems, Inc.
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
#include "cksumtypes.h"
#include "etypes.h"
#include "dk.h"

krb5_error_code KRB5_CALLCONV
krb5_c_make_checksum(krb5_context context, krb5_cksumtype cksumtype,
		     const krb5_keyblock *key, krb5_keyusage usage,
		     const krb5_data *input, krb5_checksum *cksum)
{
    int i, e1, e2;
    krb5_data data;
    krb5_error_code ret = 0;
    size_t cksumlen;

    KRB5_LOG0(KRB5_INFO, "krb5_c_make_checksum() start.");

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    if (krb5_cksumtypes_list[i].keyhash)
	cksumlen = krb5_cksumtypes_list[i].keyhash->hashsize;
    else
	cksumlen = krb5_cksumtypes_list[i].hash->hashsize;

#ifdef _KERNEL
    context->kef_cksum_mt = krb5_cksumtypes_list[i].kef_cksum_mt;
#endif
    cksum->length = cksumlen;

    if ((cksum->contents = (krb5_octet *) MALLOC(cksum->length)) == NULL) {
	cksum->length = 0;
	return(ENOMEM);
    }

    data.length = cksum->length;
    data.data = (char *) cksum->contents;

    if (krb5_cksumtypes_list[i].keyhash) {
	/* check if key is compatible */

	if (krb5_cksumtypes_list[i].keyed_etype) {
	    for (e1=0; e1<krb5_enctypes_length; e1++)
		if (krb5_enctypes_list[e1].etype ==
		    krb5_cksumtypes_list[i].keyed_etype)
		    break;

	    for (e2=0; e2<krb5_enctypes_length; e2++)
		if (krb5_enctypes_list[e2].etype == key->enctype)
		    break;

	    /*
	     * Solaris Kerberos: The actual key encryption type could be
	     * arbitrary, so the checksum enc type doesn't need to be the same.
	     */
	    if ((e1 == krb5_enctypes_length) || (e2 == krb5_enctypes_length)) {
		ret = KRB5_BAD_ENCTYPE;
		goto cleanup;
	    }
	}
#ifdef _KERNEL
	context->kef_cipher_mt = krb5_enctypes_list[e1].kef_cipher_mt;
	context->kef_hash_mt = krb5_enctypes_list[e1].kef_hash_mt;
	if (key->kef_key.ck_data == NULL) {
		if ((ret = init_key_kef(context->kef_cipher_mt,
				(krb5_keyblock *)key)))
			goto cleanup;
	}
#else
	if ((ret = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key)))
		goto cleanup;
#endif /* _KERNEL */

	ret = (*(krb5_cksumtypes_list[i].keyhash->hash))(context, key,
						usage, 0, input, &data);
    } else if (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE) {
#ifdef _KERNEL
    	context->kef_cipher_mt = get_cipher_mech_type(context,
					(krb5_keyblock *)key);
    	context->kef_hash_mt = get_hash_mech_type(context,
					(krb5_keyblock *)key);
	/*
	 * If the hash_mt is invalid, try using the cksum_mt
	 * because "hash" and "checksum" are overloaded terms
	 * in some places.
	 */
	if (context->kef_hash_mt == CRYPTO_MECH_INVALID)
		context->kef_hash_mt = context->kef_cksum_mt;
#else
	ret = init_key_uef(krb_ctx_hSession(context), (krb5_keyblock *)key);
	if (ret)
		goto cleanup;
#endif /* _KERNEL */
	ret = krb5_dk_make_checksum(context,
				krb5_cksumtypes_list[i].hash,
				key, usage, input, &data);
    } else {
	    /*
	     * No key is used, hash and cksum are synonymous
	     * in this case
	     */
#ifdef _KERNEL
	    context->kef_hash_mt = context->kef_cksum_mt;
#endif /* _KERNEL */
	    ret = (*(krb5_cksumtypes_list[i].hash->hash))(context, 1,
							input, &data);
    }

    if (!ret) {
	cksum->magic = KV5M_CHECKSUM;
	cksum->checksum_type = cksumtype;
	if (krb5_cksumtypes_list[i].trunc_size) {
	    krb5_octet *trunc;
            size_t old_len = cksum->length;

            /*
             * Solaris Kerberos:
             * The Kernel does not like 'realloc' (which is what
             * MIT code does here), so we do our own "realloc".
             */
            cksum->length = krb5_cksumtypes_list[i].trunc_size;
            trunc = (krb5_octet *) MALLOC(cksum->length);
            if (trunc) {
                (void) memcpy(trunc, cksum->contents, cksum->length);
                FREE(cksum->contents, old_len);
                cksum->contents = trunc;
            } else {
                ret = ENOMEM;
            }
        }
    }

cleanup:
    if (ret) {
	(void) memset(cksum->contents, 0, cksum->length);
	FREE(cksum->contents, cksum->length);
	cksum->length = 0;
	cksum->contents = NULL;
    }

    KRB5_LOG(KRB5_INFO, "krb5_c_make_checksum() end ret = %d\n", ret);
    return(ret);
}
