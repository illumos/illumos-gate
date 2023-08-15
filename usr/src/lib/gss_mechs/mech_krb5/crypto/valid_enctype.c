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
#include "etypes.h"

krb5_boolean KRB5_CALLCONV
krb5_c_valid_enctype(krb5_enctype etype)
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == etype)
	    return(1);
    }

    return(0);
}

krb5_boolean KRB5_CALLCONV
valid_enctype(krb5_enctype etype)
{
    return krb5_c_valid_enctype (etype);
}

/* Solaris kerberos:
 *
 * is_in_keytype(): returns 1 if enctype == one of the enctypes in keytype
 * otherwise 0 is returned.
 */
krb5_boolean KRB5_CALLCONV
is_in_keytype(keytype, numkeytypes, enctype)
    krb5_const krb5_enctype	*keytype;
    int			numkeytypes;
    krb5_enctype	enctype;
{
    int i;

    KRB5_LOG(KRB5_INFO, "is_in_keytype() enctype = %d", enctype);
    KRB5_LOG(KRB5_INFO, "is_in_keytype() numkeytypes = %d", numkeytypes);

    if (keytype == NULL || numkeytypes <= 0) {
	return(0);
    }

    for (i = 0; i < numkeytypes; i++) {

	KRB5_LOG1(KRB5_INFO, "is_in_keytype() keytype[%d] = %d",
		i, keytype[i]);

	if (keytype[i] == enctype) {
	    KRB5_LOG0(KRB5_INFO, "is_in_keytype() end true");
	    return(1);
	}
    }

    KRB5_LOG0(KRB5_INFO, "is_in_keytype() end false");
    return(0);
}
