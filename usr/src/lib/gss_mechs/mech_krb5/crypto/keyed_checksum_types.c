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
#include "etypes.h"
#include "cksumtypes.h"

static int etype_match(krb5_enctype e1, krb5_enctype e2)
{
    int i1, i2;

    for (i1=0; i1<krb5_enctypes_length; i1++)
	if (krb5_enctypes_list[i1].etype == e1)
	    break;

    for (i2=0; i2<krb5_enctypes_length; i2++)
	if (krb5_enctypes_list[i2].etype == e2)
	    break;

    return((i1 < krb5_enctypes_length) &&
	   (i2 < krb5_enctypes_length) &&
	   (krb5_enctypes_list[i1].enc == krb5_enctypes_list[i2].enc));
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_c_keyed_checksum_types(krb5_context context, krb5_enctype enctype,
			    unsigned int *count, krb5_cksumtype **cksumtypes)
{
    unsigned int i, c;

    c = 0;
    for (i=0; i<krb5_cksumtypes_length; i++) {
	if ((krb5_cksumtypes_list[i].keyhash &&
	     etype_match(krb5_cksumtypes_list[i].keyed_etype, enctype)) ||
	    (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE)) {
	    c++;
	}
    }

    *count = c;

    if ((*cksumtypes = (krb5_cksumtype *) malloc(c*sizeof(krb5_cksumtype)))
	== NULL)
	return(ENOMEM);

    c = 0;
    for (i=0; i<krb5_cksumtypes_length; i++) {
	if ((krb5_cksumtypes_list[i].keyhash &&
	     etype_match(krb5_cksumtypes_list[i].keyed_etype, enctype)) ||
	    (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE)) {
	    (*cksumtypes)[c] = krb5_cksumtypes_list[i].ctype;
	    c++;
	}
    }

    return(0);
}

/*ARGSUSED*/
void KRB5_CALLCONV
krb5_free_cksumtypes(krb5_context context, krb5_cksumtype *val)
{
    if (val)
	krb5_xfree(val);
    return;
}

