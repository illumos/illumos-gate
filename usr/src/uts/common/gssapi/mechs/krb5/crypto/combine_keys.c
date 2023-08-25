/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright (c) 2002 Naval Research Laboratory (NRL/CCS)
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof.
 *
 * NRL ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION AND
 * DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES WHATSOEVER
 * RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Key combination function.
 *
 * If Key1 and Key2 are two keys to be combined, the algorithm to combine
 * them is as follows.
 *
 * Definitions:
 *
 * k-truncate is defined as truncating to the key size the input.
 *
 * DR is defined as the generate "random" data from a key
 * (defined in crypto draft)
 *
 * DK is defined as the key derivation function (krb5_derive_key())
 *
 * (note: | means "concatenate")
 *
 * Combine key algorithm:
 *
 * R1 = DR(Key1, n-fold(Key2)) [ Output is length of Key1 ]
 * R2 = DR(Key2, n-fold(Key1)) [ Output is length of Key2 ]
 *
 * rnd = n-fold(R1 | R2) [ Note: output size of nfold must be appropriately
 *			   sized for random-to-key function ]
 * tkey = random-to-key(rnd)
 * Combine-Key(Key1, Key2) = DK(tkey, CombineConstant)
 *
 * CombineConstant is defined as the byte string:
 *
 * { 0x63 0x6f 0x6d 0x62 0x69 0x6e 0x65 }, which corresponds to the
 * ASCII encoding of the string "combine"
 */

#include "k5-int.h"
#include "etypes.h"
#include "dk.h"

/* Solaris Kerberos */
static krb5_error_code dr
(krb5_context context,
const struct krb5_enc_provider *enc, const krb5_keyblock *inkey,
unsigned char *outdata, const krb5_data *in_constant);

/*
 * We only support this combine_keys algorithm for des and 3des keys.
 * Everything else should use the PRF defined in the crypto framework.
 * We don't implement that yet.
 */

static krb5_boolean  enctype_ok (krb5_enctype e)
{
    switch (e) {
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_MD5:
    case ENCTYPE_DES3_CBC_SHA1:
	return 1;
    default:
	return 0;
    }
}

krb5_error_code krb5int_c_combine_keys
(krb5_context context, krb5_keyblock *key1, krb5_keyblock *key2, krb5_keyblock *outkey)
{
    unsigned char *r1, *r2, *combined, *rnd, *output;
    size_t keybytes, keylength;
    const struct krb5_enc_provider *enc;
    krb5_data input, randbits;
    krb5_keyblock tkey;
    krb5_error_code ret;
    int i, myalloc = 0;
    if (!(enctype_ok(key1->enctype)&&enctype_ok(key2->enctype)))
	return (KRB5_CRYPTO_INTERNAL);


    if (key1->length != key2->length || key1->enctype != key2->enctype)
	return (KRB5_CRYPTO_INTERNAL);

    /*
     * Find our encryption algorithm
     */

    for (i = 0; i < krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key1->enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return (KRB5_BAD_ENCTYPE);

    enc = krb5_enctypes_list[i].enc;

    keybytes = enc->keybytes;
    keylength = enc->keylength;

    /*
     * Allocate and set up buffers
     */

    if ((r1 = (unsigned char *) malloc(keybytes)) == NULL)
	return (ENOMEM);

    if ((r2 = (unsigned char *) malloc(keybytes)) == NULL) {
	free(r1);
	return (ENOMEM);
    }

    if ((rnd = (unsigned char *) malloc(keybytes)) == NULL) {
	free(r1);
	free(r2);
	return (ENOMEM);
    }

    if ((combined = (unsigned char *) malloc(keybytes * 2)) == NULL) {
	free(r1);
	free(r2);
	free(rnd);
	return (ENOMEM);
    }

    if ((output = (unsigned char *) malloc(keylength)) == NULL) {
	free(r1);
	free(r2);
	free(rnd);
	free(combined);
	return (ENOMEM);
    }

    /*
     * Get R1 and R2 (by running the input keys through the DR algorithm.
     * Note this is most of derive-key, but not all.
     */

    input.length = key2->length;
    input.data = (char *) key2->contents;
    /* Solaris Kerberos */
    if ((ret = dr(context, enc, key1, r1, &input)))
	goto cleanup;

#if 0
    {
	int i;
	printf("R1 =");
	for (i = 0; i < keybytes; i++)
	    printf(" %02x", (unsigned char) r1[i]);
	printf("\n");
    }
#endif

    input.length = key1->length;
    input.data = (char *) key1->contents;
    /* Solaris Kerberos */
    if ((ret = dr(context, enc, key2, r2, &input)))
	goto cleanup;

#if 0
    {
	int i;
	printf("R2 =");
	for (i = 0; i < keybytes; i++)
	    printf(" %02x", (unsigned char) r2[i]);
	printf("\n");
    }
#endif

    /*
     * Concatenate the two keys together, and then run them through
     * n-fold to reduce them to a length appropriate for the random-to-key
     * operation.  Note here that krb5_nfold() takes sizes in bits, hence
     * the multiply by 8.
     */

    memcpy(combined, r1, keybytes);
    memcpy(combined + keybytes, r2, keybytes);

    krb5_nfold((keybytes * 2) * 8, combined, keybytes * 8, rnd);

#if 0
    {
	int i;
	printf("rnd =");
	for (i = 0; i < keybytes; i++)
	    printf(" %02x", (unsigned char) rnd[i]);
	printf("\n");
    }
#endif

    /*
     * Run the "random" bits through random-to-key to produce a encryption
     * key.
     */

    randbits.length = keybytes;
    randbits.data = (char *) rnd;
    tkey.length = keylength;
    tkey.contents = output;

    /* Solaris Kerberos */
    if ((ret = (*(enc->make_key))(context, &randbits, &tkey)))
	goto cleanup;

#if 0
    {
	int i;
	printf("tkey =");
	for (i = 0; i < tkey.length; i++)
	    printf(" %02x", (unsigned char) tkey.contents[i]);
	printf("\n");
    }
#endif

    /*
     * Run through derive-key one more time to produce the final key.
     * Note that the input to derive-key is the ASCII string "combine".
     */

    input.length = 7; /* Note; change this if string length changes */
    input.data = "combine";

    /*
     * Just FYI: _if_ we have space here in the key, then simply use it
     * without modification.  But if the key is blank (no allocated storage)
     * then allocate some memory for it.  This allows programs to use one of
     * the existing keys as the output key, _or_ pass in a blank keyblock
     * for us to allocate.  It's easier for us to allocate it since we already
     * know the crypto library internals
     */

    if (outkey->length == 0 || outkey->contents == NULL) {
	outkey->contents = (krb5_octet *) malloc(keylength);
	if (!outkey->contents) {
	    ret = ENOMEM;
	    goto cleanup;
	}
	outkey->length = keylength;
	outkey->enctype = key1->enctype;
	myalloc = 1;
    }

    /* Solaris Kerberos */
    if ((ret = krb5_derive_key(context, enc, &tkey, outkey, &input))) {
	if (myalloc) {
	    free(outkey->contents);
	    outkey->contents = NULL;
	}
	goto cleanup;
    }

#if 0
    {
	int i;
	printf("output =");
	for (i = 0; i < outkey->length; i++)
	    printf(" %02x", (unsigned char) outkey->contents[i]);
	printf("\n");
    }
#endif

    ret = 0;

cleanup:
    memset(r1, 0, keybytes);
    memset(r2, 0, keybytes);
    memset(rnd, 0, keybytes);
    memset(combined, 0, keybytes * 2);
    memset(output, 0, keylength);

    free(r1);
    free(r2);
    free(rnd);
    free(combined);
    free(output);

    return (ret);
}

/*
 * Our DR function; mostly taken from derive.c
 */

    /* Solaris Kerberos */
static krb5_error_code dr
(	krb5_context context,
	const struct krb5_enc_provider *enc,
	const krb5_keyblock *inkey,
	unsigned char *out,
	const krb5_data *in_constant)
{
    size_t blocksize, keybytes, keylength, n;
    unsigned char *inblockdata, *outblockdata;
    krb5_data inblock, outblock;

    blocksize = enc->block_size;
    keybytes = enc->keybytes;
    keylength = enc->keylength;

    /* allocate and set up buffers */

    if ((inblockdata = (unsigned char *) malloc(blocksize)) == NULL)
	return(ENOMEM);

    if ((outblockdata = (unsigned char *) malloc(blocksize)) == NULL) {
	free(inblockdata);
	return(ENOMEM);
    }

    inblock.data = (char *) inblockdata;
    inblock.length = blocksize;

    outblock.data = (char *) outblockdata;
    outblock.length = blocksize;

    /* initialize the input block */

    if (in_constant->length == inblock.length) {
	memcpy(inblock.data, in_constant->data, inblock.length);
    } else {
	krb5_nfold(in_constant->length*8, (unsigned char *) in_constant->data,
		   inblock.length*8, (unsigned char *) inblock.data);
    }

    /* loop encrypting the blocks until enough key bytes are generated */

    n = 0;
    while (n < keybytes) {
	/* Solaris Kerberos */
	(*(enc->encrypt))(context, inkey, 0, &inblock, &outblock);

	if ((keybytes - n) <= outblock.length) {
	    memcpy(out+n, outblock.data, (keybytes - n));
	    break;
	}

	memcpy(out+n, outblock.data, outblock.length);
	memcpy(inblock.data, outblock.data, outblock.length);
	n += outblock.length;
    }

    /* clean memory, free resources and exit */

    memset(inblockdata, 0, blocksize);
    memset(outblockdata, 0, blocksize);

    free(outblockdata);
    free(inblockdata);

    return(0);
}

