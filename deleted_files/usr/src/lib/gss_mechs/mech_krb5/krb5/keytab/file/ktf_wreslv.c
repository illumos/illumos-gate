/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/keytab/file/ktf_wreslv.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This is an implementation specific resolver.  It returns a keytab id
 * initialized with file keytab routines.
 */

#include <k5-int.h>
#include "ktfile.h"

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_ktfile_wresolve(context, name, id)
    krb5_context context;
  const char *name;
  krb5_keytab *id;
{
    krb5_ktfile_data *data;

    if ((*id = (krb5_keytab) malloc(sizeof(**id))) == NULL)
	return(ENOMEM);

    (*id)->ops = &krb5_ktf_writable_ops;
    if ((data = (krb5_ktfile_data *)malloc(sizeof(krb5_ktfile_data))) == NULL) {
	krb5_xfree(*id);
	return(ENOMEM);
    }
    bzero(data, sizeof(krb5_ktfile_data));

    if ((data->name = (char *)calloc(strlen(name) + 1, sizeof(char))) == NULL) {
	krb5_xfree(data);
	krb5_xfree(*id);
	return(ENOMEM);
    }

    (void) strcpy(data->name, name);

    (*id)->data = (krb5_pointer)data;
    (*id)->magic = KV5M_KEYTAB;
    return(0);
}
