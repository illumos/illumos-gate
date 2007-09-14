/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/*
 * Solaris Kerberos
 * krb5_string_to_key/krb5_use_enctype are needed by Samba
 */

krb5_error_code KRB5_CALLCONV
krb5_string_to_key(krb5_context context, const krb5_encrypt_block *eblock,
		   krb5_keyblock *keyblock, const krb5_data *data,
		   const krb5_data *salt)
{
    return(krb5_c_string_to_key(context, eblock->crypto_entry, data, salt,
				keyblock));
}

krb5_error_code KRB5_CALLCONV
krb5_use_enctype(krb5_context context, krb5_encrypt_block *eblock,
                 krb5_enctype enctype)
{
    eblock->crypto_entry = enctype;

    return(0);
}

size_t KRB5_CALLCONV
krb5_checksum_size(krb5_context context, krb5_cksumtype ctype)
{
  size_t ret;

  if (krb5_c_checksum_length(context, ctype, &ret))
    return(-1); /* XXX */

  return(ret);
}

size_t KRB5_CALLCONV
krb5_encrypt_size(size_t length, krb5_enctype crypto)
{
    size_t ret;

    if (krb5_c_encrypt_length(/* XXX */ 0, crypto, length, &ret))
        return(-1); /* XXX */

    return(ret);
}
