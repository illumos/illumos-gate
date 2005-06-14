#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/stdio/scc_sseq.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_start_seq_get.
 */



#include "scc.h"

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns and krb5_cc_cursor to be used with krb5_scc_next_cred and
 * krb5_scc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_scc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
krb5_error_code
krb5_scc_start_seq_get(context, id, cursor)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_scc_cursor *fcursor;
     int ret = 0;
     
     fcursor = (krb5_scc_cursor *) malloc(sizeof(krb5_scc_cursor));
     if (fcursor == NULL)
	  return KRB5_CC_NOMEM;

     /* Make sure we start reading right after the primary principal */
     MAYBE_OPEN (context, id, SCC_OPEN_RDONLY);

     ret = krb5_scc_skip_header(context, id);
     if (ret) goto done;
     ret = krb5_scc_skip_principal(context, id);
     if (ret) goto done;
     
     fcursor->pos = ftell(((krb5_scc_data *) id->data)->file);
     *cursor = (krb5_cc_cursor) fcursor;

done:
     MAYBE_CLOSE (context, id, ret);
     return(ret);
}
