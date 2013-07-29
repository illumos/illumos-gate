/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * des_cbc_cksum.c - compute an 8 byte checksum using DES in CBC mode
 */
#include "des_int.h"

/*
 * This routine performs DES cipher-block-chaining checksum operation,
 * a.k.a.  Message Authentication Code.  It ALWAYS encrypts from input
 * to a single 64 bit output MAC checksum.
 *
 * The key schedule is passed as an arg, as well as the cleartext or
 * ciphertext. The cleartext and ciphertext should be in host order.
 *
 * NOTE-- the output is ALWAYS 8 bytes long.  If not enough space was
 * provided, your program will get trashed.
 *
 * The input is null padded, at the end (highest addr), to an integral
 * multiple of eight bytes.
 */
unsigned long
mit_des_cbc_cksum(krb5_context context,
	const krb5_octet *in, krb5_octet *out,
	unsigned long length, krb5_keyblock *key,
	const krb5_octet  *ivec)
{
	krb5_error_code ret = 0;
	krb5_data input;
	krb5_data output;
	krb5_data ivecdata;

	input.data = (char *)in;
	input.length = length;
	output.data = (char *)out;
	output.length = MIT_DES_BLOCK_LENGTH;
	ivecdata.data = (char *)ivec;
	ivecdata.length = MIT_DES_BLOCK_LENGTH;

	ret = k5_ef_mac(context, key, &ivecdata,
		(const krb5_data *)&input, &output);

	return (ret);
}
