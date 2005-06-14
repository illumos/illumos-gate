#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/krb/gen_seqnum.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Routine to automatically generate a starting sequence number.
 * We do this by getting a random key and encrypting something with it,
 * then taking the output and slicing it up.
 */

#include <k5-int.h>

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

krb5_error_code
krb5_generate_seq_number(context, key, seqno)
    krb5_context context;
    krb5_const krb5_keyblock *key;
    krb5_int32 *seqno;
{
    krb5_data seed;
    krb5_error_code retval;

    seed.length = key->length;
    seed.data = (char *)key->contents;
    if ((retval = krb5_c_random_seed(context, &seed)))
	return(retval);

    seed.length = sizeof(*seqno);
    seed.data = (char *) seqno;
    return(krb5_c_random_make_octets(context, &seed));
}
