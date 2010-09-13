/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

#include <k5-int.h>
#include <etypes.h>
krb5_error_code KRB5_CALLCONV
krb5_enctype_to_string(krb5_enctype enctype, char *buffer, size_t buflen)
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype) {
	    if ((strlen(krb5_enctypes_list[i].out_string)+1) > buflen)
		return(ENOMEM);

	    strcpy(buffer, krb5_enctypes_list[i].out_string);
	    return(0);
	}
    }

    return(EINVAL);
}

/* Solaris Kerberos */
krb5_error_code KRB5_CALLCONV
krb5_enctype_to_istring(krb5_enctype enctype, char *buffer, size_t buflen)
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype) {
	    if ((strlen(krb5_enctypes_list[i].in_string)+1) > buflen)
		return(ENOMEM);

	    strlcpy(buffer, krb5_enctypes_list[i].in_string, buflen);
	    return(0);
	}
    }

    return(EINVAL);
}
