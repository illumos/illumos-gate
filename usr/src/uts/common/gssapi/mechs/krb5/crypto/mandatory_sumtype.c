/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (C) 2003 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 */

#include "k5-int.h"
#include "etypes.h"

/*ARGSUSED*/
krb5_error_code
krb5int_c_mandatory_cksumtype (krb5_context ctx, krb5_enctype etype,
			       krb5_cksumtype *cksumtype)
{
    int i;

    for (i = 0; i < krb5_enctypes_length; i++)
	if (krb5_enctypes_list[i].etype == etype) {
	    *cksumtype = krb5_enctypes_list[i].required_ctype;
	    return 0;
	}

    return KRB5_BAD_ENCTYPE;
}
