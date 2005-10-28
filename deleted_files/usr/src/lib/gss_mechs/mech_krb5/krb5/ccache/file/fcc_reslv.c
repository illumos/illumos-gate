#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_reslv.c
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
 * This file contains the source code for krb5_fcc_resolve.
 */



#include "fcc.h"

extern krb5_cc_ops krb5_fcc_ops;

/*
 * Requires:
 * residual is a legal path name, and a null-terminated string
 *
 * Modifies:
 * id
 * 
 * Effects:
 * creates a file-based cred cache that will reside in the file
 * residual.  The cache is not opened, but the filename is reserved.
 * 
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * permission errors
 */
/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_fcc_resolve (context, id, residual)
   krb5_context context;
   krb5_ccache *id;
   const char *residual;
{
     krb5_ccache lid;
     
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_fcc_ops;
     
     lid->data = (krb5_pointer) malloc(sizeof(krb5_fcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_fcc_data *) lid->data)->filename = (char *)
	  malloc(strlen(residual) + 1);

     if (((krb5_fcc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_fcc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /* default to open/close on every trn */
     ((krb5_fcc_data *) lid->data)->flags = KRB5_TC_OPENCLOSE;
     ((krb5_fcc_data *) lid->data)->fd = -1;
     
     /* Set up the filename */
     strcpy(((krb5_fcc_data *) lid->data)->filename, residual);

     lid->magic = KV5M_CCACHE;

     /* other routines will get errors on open, and callers must expect them,
	if cache is non-existent/unusable */
     *id = lid;
     return KRB5_OK;
}
