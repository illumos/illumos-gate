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

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_c_checksum_length(krb5_context context, krb5_cksumtype cksumtype,
		       size_t *length)
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    if (krb5_cksumtypes_list[i].keyhash)
	*length = krb5_cksumtypes_list[i].keyhash->hashsize;
    else if (krb5_cksumtypes_list[i].trunc_size)
	*length = krb5_cksumtypes_list[i].trunc_size;
    else
	*length = krb5_cksumtypes_list[i].hash->hashsize;

    return(0);
}

