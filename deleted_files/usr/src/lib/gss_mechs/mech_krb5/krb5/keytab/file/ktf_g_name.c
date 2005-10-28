/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/keytab/file/ktf_get_na.c
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
 * Get the name of the file containing a file-based keytab.
 */

#include <k5-int.h>
#include "ktfile.h"

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_ktfile_get_name(context, id, name, len)
    krb5_context context;
  krb5_keytab id;
  char *name;
  int len;
  /*
   * This routine returns the name of the name of the file associated with
   * this file-based keytab.  name is zeroed and the filename is truncated
   * to fit in name if necessary.  The name is prefixed with PREFIX:, so that
   * trt will happen if the name is passed back to resolve.
   */
{
    memset(name, 0, len);

    if (len < strlen(id->ops->prefix)+2)
	return(KRB5_KT_NAME_TOOLONG);
    strcpy(name, id->ops->prefix);
    name += strlen(id->ops->prefix);
    name[0] = ':';
    name++;
    len -= strlen(id->ops->prefix)+1;

    if (len < strlen(KTFILENAME(id)+1))
	return(KRB5_KT_NAME_TOOLONG);
    strcpy(name, KTFILENAME(id));
    /* strcpy will NUL-terminate the destination */

    return(0);
}
