#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/stdio/scc_gennew.c
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
 * This file contains the source code for krb5_scc_generate_new.
 */

#include "scc.h"
#include "k5-int.h"

extern krb5_cc_ops krb5_scc_ops;

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from scc.h).
 * The cache is not opened, but the new filename is reserved.
 *  
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * system errors (from open)
 */
krb5_error_code
krb5_scc_generate_new (context, id)
   krb5_context context;
   krb5_ccache *id;
{
     krb5_ccache lid;
     FILE *f;
     krb5_error_code	retcode = 0;
     char scratch[sizeof(TKT_ROOT)+6+1]; /* +6 for the scratch part, +1 for
					    NUL */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_scc_ops;

     (void) strcpy(scratch, TKT_ROOT);
     (void) strcat(scratch, "XXXXXX");
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_scc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_scc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_scc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->flags = 0;
     ((krb5_scc_data *) lid->data)->file = 0;
     
     /* Set up the filename */
     strcpy(((krb5_scc_data *) lid->data)->filename, scratch);

     /* Make sure the file name is useable */
#if defined(__STDC__) || defined(_MSDOS) || defined(_WIN32)
     f = fopen (((krb5_scc_data *) lid->data)->filename, "wb+");
#else
     f = fopen (((krb5_scc_data *) lid->data)->filename, "w+");
#endif
     if (!f) {
	     retcode = krb5_scc_interpret (context, errno);
	     goto err_out;
     } else {
	 unsigned char scc_fvno[2];

	 scc_fvno[0] = (unsigned char) ((context->scc_default_format >> 8) & 0xFF);
	 scc_fvno[1] = (unsigned char) (context->scc_default_format & 0xFF);

	 if (!fwrite((char *)scc_fvno, sizeof(scc_fvno), 1, f)) {
	     retcode = krb5_scc_interpret(context, errno);
	     (void) fclose(f);
	     (void) remove(((krb5_scc_data *) lid->data)->filename);
	     goto err_out;
	 }
 	 /* For version 4 we save a length for the rest of the header */
          if (context->scc_default_format == KRB5_SCC_FVNO_4) {
	     unsigned char scc_flen[2];
	     scc_flen[0] = 0;
	     scc_flen[1] = 0;
	     if (!fwrite((char *)scc_flen, sizeof(scc_flen), 1, f)) {
	        retcode = krb5_scc_interpret(context, errno);
	        (void) fclose(f);
	        (void) remove(((krb5_scc_data *) lid->data)->filename);
                goto err_out;
            }
	 }
	 if (fclose(f) == EOF) {
	     retcode = krb5_scc_interpret(context, errno);
	     (void) remove(((krb5_scc_data *) lid->data)->filename);
	     goto err_out;
	 }
	 *id = lid;
	 return KRB5_OK;
     }
err_out:
     krb5_xfree(((krb5_scc_data *) lid->data)->filename);
     krb5_xfree(((krb5_scc_data *) lid->data));
     krb5_xfree(lid);
     return retcode;
}
