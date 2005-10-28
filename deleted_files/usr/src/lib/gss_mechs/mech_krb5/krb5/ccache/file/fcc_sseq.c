#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_sseq.c
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
 * This file contains the source code for krb5_fcc_start_seq_get.
 */


#include "fcc.h"

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns and krb5_cc_cursor to be used with krb5_fcc_next_cred and
 * krb5_fcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_fcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_start_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_fcc_cursor *fcursor;
     krb5_error_code kret = KRB5_OK;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     
     fcursor = (krb5_fcc_cursor *) malloc(sizeof(krb5_fcc_cursor));
     if (fcursor == NULL)
	  return KRB5_CC_NOMEM;
     if (OPENCLOSE(id)) {
	  kret = krb5_fcc_open_file(context, id, FCC_OPEN_RDONLY);
	  if (kret) {
	      krb5_xfree(fcursor);
	      return kret;
	  }
     }

     /* Make sure we start reading right after the primary principal */
     kret = krb5_fcc_skip_header(context, id);
     if (kret) goto done;
     kret = krb5_fcc_skip_principal(context, id);
     if (kret) goto done;

     fcursor->pos = lseek(data->fd, 0, SEEK_CUR);
     *cursor = (krb5_cc_cursor) fcursor;

done:
     MAYBE_CLOSE(context, id, kret);
     return kret;
}
