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
#include "old.h"
#include <des_int.h>

/* XXX */
extern krb5_error_code mit_des_string_to_key_int
(krb5_context context,
		 krb5_keyblock * keyblock,
		 const krb5_data * data,
		 const krb5_data * salt);

/*ARGSUSED*/
krb5_error_code
krb5int_des_string_to_key(krb5_context context,
			  const struct krb5_enc_provider *enc,
			  const krb5_data *string,
			  const krb5_data *salt, const krb5_data *parm,
			  krb5_keyblock *key)
{
    int type;
    if (parm ) {
	if (parm->length != 1)
	    return KRB5_ERR_BAD_S2K_PARAMS;
	type = parm->data[0];
    }
    else type = 0;
    switch(type) {
    case 0:
    /* Solaris Kerberos */
    return(mit_des_string_to_key_int(context, key, string, salt));
    case 1:
	/* Solaris Kerberos */
	return mit_afs_string_to_key(context, key, string, salt);
    default:
	return KRB5_ERR_BAD_S2K_PARAMS;
    }
}
