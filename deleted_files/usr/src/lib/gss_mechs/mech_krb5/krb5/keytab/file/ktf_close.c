/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/keytab/file/ktf_close.c
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
 * "Close" a file-based keytab and invalidate the id.  This means
 * free memory hidden in the structures.
 */

#include <k5-int.h>
#include "ktfile.h"

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_ktfile_close(context, id)
    krb5_context context;
  krb5_keytab id;
  /*
   * This routine is responsible for freeing all memory allocated
   * for this keytab.  There are no system resources that need
   * to be freed nor are there any open files.
   *
   * This routine should undo anything done by krb5_ktfile_resolve().
   */
{
    krb5_xfree(KTFILENAME(id));
    krb5_xfree(id->data);
    id->ops = 0;
    krb5_xfree(id);
    return (0);
}
