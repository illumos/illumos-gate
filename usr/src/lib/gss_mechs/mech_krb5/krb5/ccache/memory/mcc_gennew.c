/*
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/memory/mcc_gennew.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_mcc_generate_new.
 */

#include "mcc.h"
#include "k5-int.h"

extern krb5_cc_ops krb5_mcc_ops;

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from mcc.h).
 * The cache is not opened, but the new filename is reserved.
 *  
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 *              krb5_ccache.  id is undefined.
 * system errors (from open)
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_generate_new (context, id)
   krb5_context context;
   krb5_ccache *id;
{
     krb5_ccache lid;
     char scratch[6+1]; /* 6 for the scratch part, +1 for NUL */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_mcc_ops;

     (void) strcpy(scratch, "XXXXXX");
     (void) mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_mcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_mcc_data *) lid->data)->name = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_mcc_data *) lid->data)->name == NULL) {
	  krb5_xfree(((krb5_mcc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }
     ((krb5_mcc_data *) lid->data)->link = NULL;
     ((krb5_mcc_data *) lid->data)->prin = NULL;

     /* Set up the filename */
     (void) strcpy(((krb5_mcc_data *) lid->data)->name, scratch);

     *id = lid;
#if 0
     ++krb5_cache_sessions;
#endif
     ((krb5_mcc_data *)lid->data)->next = mcc_head;
     mcc_head = (krb5_mcc_data *)lid->data;

     krb5_change_cache ();
     return KRB5_OK;
}
