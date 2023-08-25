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
/* Solaris Kerberos */
#if 0
#include "rsa-md5.h"
#endif
#include "hash_provider.h"

static krb5_error_code
k5_md5_hash(krb5_context context,
	    unsigned int icount, krb5_const krb5_data *input,
	    krb5_data *output)
{
	/* Solaris Kerberos */
	CK_MECHANISM mechanism;

	mechanism.mechanism = CKM_MD5;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;

	return(k5_ef_hash(context, &mechanism, icount, input, output));
}

/* Solaris Kerberos */
const struct krb5_hash_provider krb5int_hash_md5 = {
    MD5_CKSUM_LENGTH,
    MD5_BLOCKSIZE,
    k5_md5_hash
};
