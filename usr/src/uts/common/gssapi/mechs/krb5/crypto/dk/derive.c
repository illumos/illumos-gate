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
#include "dk.h"

#define K5CLENGTH 5 /* 32 bit net byte order integer + one byte seed */

/*
 * Search for a derived key based on the input key,
 * the  usage constant and the dkid byte.
 *
 * Return *derived key on success, NULL on failure.
 */
krb5_keyblock *
find_derived_key(krb5_keyusage usage, uchar_t dkid,
		krb5_keyblock *key)
{
	krb5_dk_node *dknode = key->dk_list;

	while (dknode != NULL) {
		if (usage == dknode->usage &&
		    dkid == dknode->dkid) {
			KRB5_LOG1(KRB5_INFO,
				"find_derived_key - MATCH FOUND %d 0x%0x",
				usage, dkid);
			return(dknode->derived_key);
		}
		dknode = dknode->next;
	}
	KRB5_LOG0(KRB5_INFO, "find_derived_key - no match");
	return(NULL);
}

/*
 * Add a derived key to the dk_list for the indicated key.
 */
krb5_error_code
add_derived_key(krb5_keyblock *key,
		krb5_keyusage usage, uchar_t dkid,
		krb5_keyblock *derived_key)
{
	krb5_dk_node *dknode;
	KRB5_LOG1(KRB5_INFO, "add_derived_key: %d 0x%0x",
		usage, dkid);

	if (key->dk_list == NULL) {
		key->dk_list = MALLOC(sizeof(krb5_dk_node));
		if (key->dk_list == NULL)
			return (ENOMEM);
		dknode = key->dk_list;
	} else {
		dknode = key->dk_list;
		/*
		 * Find last derived key in list
		 */
		while (dknode->next != NULL)
			dknode = dknode->next;
		dknode->next = MALLOC(sizeof(krb5_dk_node));
		if (dknode->next == NULL)
			return (ENOMEM);
		dknode = dknode->next;
	}
	dknode->usage = usage;
	dknode->dkid = dkid;
	dknode->derived_key = derived_key;
	dknode->next = NULL;

	return (0);
}

/*
 * Utility function to create a new keyblock
 * Return NULL on failure.
 */
krb5_keyblock *
krb5_create_derived_keyblock(int keysize)
{
	krb5_keyblock *key = MALLOC(sizeof(krb5_keyblock));

	KRB5_LOG0(KRB5_INFO, "krb5_create_derived_keyblock()");
	if (key == NULL)
		return (NULL);

	bzero(key, sizeof(krb5_keyblock));

	key->length = keysize;
	key->contents = (uchar_t *)MALLOC(key->length);
	if (key->contents == NULL) {
		FREE(key, sizeof(krb5_keyblock));
		return (NULL);
	}

	bzero(key->contents, key->length);
#ifdef _KERNEL
	key->kef_mt = CRYPTO_MECH_INVALID;
	key->key_tmpl = NULL;
#else
	key->hKey = CK_INVALID_HANDLE;
#endif /* _KERNEL */
	return(key);
}

/*
 * initialize the derived key values in the context.
 */
krb5_error_code
init_derived_keydata(krb5_context context,
		    const struct krb5_enc_provider *enc,
		    krb5_keyblock *key,
		    krb5_keyusage usage,
		    krb5_keyblock **d_encr_key,
		    krb5_keyblock **d_hmac_key)
{
	krb5_error_code rv = 0;
	unsigned char constantdata[K5CLENGTH];
	krb5_keyblock *cached_key;
	krb5_data d1;

	KRB5_LOG0(KRB5_INFO,"init_ef_derived_keydata().");

	/*
	 * Get a derived encryption key, either from the cache
	 * or by calculation.
	 */
	cached_key = find_derived_key(usage, DK_ENCR_KEY_BYTE, key);
	if (cached_key != NULL)
		*d_encr_key = cached_key;
	else {
		*d_encr_key = krb5_create_derived_keyblock(key->length);
		if (*d_encr_key == NULL) {
			return (ENOMEM);
		}

		(*d_encr_key)->enctype = key->enctype;

		constantdata[0] = (usage>>24)&0xff;
		constantdata[1] = (usage>>16)&0xff;
		constantdata[2] = (usage>>8)&0xff;
		constantdata[3] = usage&0xff;
		constantdata[4] = DK_ENCR_KEY_BYTE;

		d1.data = (char *)constantdata;
		d1.length = sizeof(constantdata);
		rv = krb5_derive_key(context, enc, key,
				    *d_encr_key, &d1);
		if (rv != 0) {
			krb5_free_keyblock(context, *d_encr_key);
			*d_encr_key = NULL;
			return (rv);
		}
		rv = add_derived_key(key, usage, DK_ENCR_KEY_BYTE,
			    *d_encr_key);

		if (rv != 0) {
			krb5_free_keyblock(context, *d_encr_key);
			*d_encr_key = NULL;
			return (rv);
		}
	}

	/*
	 * Get a derived HMAC key, either from the cache
	 * or by calculation.
	 */
	cached_key = find_derived_key(usage, DK_HASH_KEY_BYTE, key);
	if (cached_key != NULL)
		*d_hmac_key = cached_key;
	else {
		*d_hmac_key = krb5_create_derived_keyblock(key->length);
		if (*d_hmac_key == NULL) {
			return (ENOMEM);
		}
		(*d_hmac_key)->enctype = key->enctype;

		constantdata[0] = (usage>>24)&0xff;
		constantdata[1] = (usage>>16)&0xff;
		constantdata[2] = (usage>>8)&0xff;
		constantdata[3] = usage&0xff;
		constantdata[4] = DK_HASH_KEY_BYTE;

		d1.data = (char *)constantdata;
		d1.length = sizeof(constantdata);
		rv = krb5_derive_key(context, enc, key, *d_hmac_key, &d1);
		if (rv != 0) {
			krb5_free_keyblock(context, *d_hmac_key);
			*d_hmac_key = NULL;
			return (rv);
		}
#ifdef _KERNEL
		/*
		 * By default, derived keys get the "mech_type"
		 * that was associated with their parent.
		 * we need to switch the mech type of the derived HMAC key
		 * to correspond to the mech type for the hmac key.
		 */
		if ((*d_hmac_key)->kef_mt != context->kef_hash_mt) {
			(*d_hmac_key)->kef_mt = context->kef_hash_mt;

			if ((*d_hmac_key)->key_tmpl != NULL) {
				crypto_destroy_ctx_template((*d_hmac_key)->key_tmpl);
				(*d_hmac_key)->key_tmpl = NULL;
			}
			rv = update_key_template(*d_hmac_key);

			if (rv != 0) {
				krb5_free_keyblock(context, *d_hmac_key);
				*d_hmac_key = NULL;
				return (rv);
			}
		}
#endif /* _KERNEL */
		if (rv == 0) {
			rv = add_derived_key(key, usage, DK_HASH_KEY_BYTE,
				    *d_hmac_key);
			if (rv != 0) {
				krb5_free_keyblock(context, *d_hmac_key);
				*d_hmac_key = NULL;
				return (rv);
			}
		}
	}
	KRB5_LOG0(KRB5_INFO,"init_ef_derived_keydata() end.");
	return (rv);
}


krb5_error_code
krb5_derive_key(context, enc, inkey, outkey, in_constant)
     krb5_context context;
     krb5_const struct krb5_enc_provider *enc;
     krb5_const krb5_keyblock *inkey;
     krb5_keyblock *outkey;
     krb5_const krb5_data *in_constant;
{
    size_t blocksize, keybytes, keylength, n;
    unsigned char *inblockdata, *outblockdata, *rawkey;
    krb5_data inblock, outblock;
    krb5_error_code ret = 0;

    KRB5_LOG0(KRB5_INFO, "krb5_derive_key() start");

    blocksize = enc->block_size;
    keybytes = enc->keybytes;
    keylength = enc->keylength;


    if ((inkey->length != keylength) ||
	(outkey->length != keylength))
	return(KRB5_CRYPTO_INTERNAL);

    /* allocate and set up buffers */
    if ((inblockdata = (unsigned char *) MALLOC(blocksize)) == NULL)
	return(ENOMEM);

    if ((outblockdata = (unsigned char *) MALLOC(blocksize)) == NULL) {
	FREE(inblockdata, blocksize);
	return(ENOMEM);
    }

    if ((rawkey = (unsigned char *) MALLOC(keybytes)) == NULL) {
	FREE(outblockdata, blocksize);
	FREE(inblockdata, blocksize);
	return(ENOMEM);
    }

    inblock.data = (char *) inblockdata;
    inblock.length = blocksize;

    outblock.data = (char *) outblockdata;
    outblock.length = blocksize;

    /* initialize the input block */
    if (in_constant->length == inblock.length) {
	(void) memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
	krb5_nfold(in_constant->length*8,
		(krb5_const unsigned char *) in_constant->data,
		   inblock.length*8, (unsigned char *) inblock.data);
    }

    /* loop encrypting the blocks until enough key bytes are generated */
    n = 0;
    while (n < keybytes) {
      ret = (*(enc->encrypt))(context, inkey, 0, &inblock, &outblock);

      if (ret) {
	KRB5_LOG(KRB5_INFO, "krb5_derive_key() encrypt error: %d", ret);
	goto cleanup;
      }

	if ((keybytes - n) <= outblock.length) {
	    (void) memcpy(rawkey+n, outblock.data, (keybytes - n));
	    break;
	}

	(void) memcpy(rawkey+n, outblock.data, outblock.length);
	(void) memcpy(inblock.data, outblock.data, outblock.length);
	n += outblock.length;
    }

    /* postprocess the key */
    inblock.data = (char *) rawkey;
    inblock.length = keybytes;

    outkey->enctype = inkey->enctype;
    ret = (*(enc->make_key))(context, &inblock, outkey);

    /* clean memory, free resources and exit */
cleanup:
    (void) memset(inblockdata, 0, blocksize);
    (void) memset(outblockdata, 0, blocksize);
    (void) memset(rawkey, 0, keybytes);

    FREE(rawkey, keybytes);
    FREE(outblockdata, blocksize);
    FREE(inblockdata, blocksize);

    KRB5_LOG0(KRB5_INFO, "krb5_derive_key() end");
    return(ret);
}
