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

/* Solaris Kerberos:
 * this code is based on the
 * usr/src/lib/gss_mechs/mech_krb5/crypto/hash_provider/hash_sha1.c
 * file, but has been modified to use the Solaris resident sha1.o kernel
 * module and associated header /usr/include/sys/sha1.h.
 * This means that the SHA1* functions are called instead of shs*.
 */

#include <k5-int.h>
#include <hash_provider.h>
#include <sys/crypto/api.h>

static krb5_error_code
k5_sha1_hash(krb5_context context,
	unsigned int icount, krb5_const krb5_data *input,
	krb5_data *output)
{
    krb5_error_code ret = 0;

    KRB5_LOG0(KRB5_INFO, "k5_sha1_hash() start");

    if (output->length != SHS_DIGESTSIZE) {
	KRB5_LOG1(KRB5_ERR, "k5_sha1_hash() end error "
		"output->length(%d) != SHS_DIGESTSIZE(%d)",
		output->length, SHS_DIGESTSIZE);
	return(KRB5_CRYPTO_INTERNAL);
    }

    if (k5_ef_hash(context, icount, input, output))
	ret = KRB5_KEF_ERROR;

    KRB5_LOG0(KRB5_INFO, "k5_sha1_hash() end");
    return(ret);
}

const struct krb5_hash_provider krb5int_hash_sha1 = {
    SHS_DIGESTSIZE,
    SHS_DATASIZE,
    k5_sha1_hash
};
