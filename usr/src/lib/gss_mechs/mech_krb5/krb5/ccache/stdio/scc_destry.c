#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/stdio/scc_destry.c
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_scc_destroy.
 */



#include "scc.h"

#ifndef SEEK_SET
#define SEEK_SET 0
#endif

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error_code krb5_scc_destroy(context, id)
   krb5_context context;
   krb5_ccache id;
{
#if 0
     unsigned long size;
     char zeros[BUFSIZ];
#endif
     krb5_scc_data *data = (krb5_scc_data *) id->data;
     register int ret;
     
     if (!OPENCLOSE(id)) {
	 (void) fclose(data->file);
	 data->file = 0;
     }

     ret = remove (data->filename);
     if (ret < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 goto cleanup;
     }

#if 0
     /*
      * Possible future extension: Read entire file to determine
      * length, then write nulls all over it.  This was the UNIX
      * version...
      */
     ret = fstat(fileno(data->file), &buf);
     if (ret < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 goto cleanup;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;

     memset (zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (fwrite(data->file, zeros, BUFSIZ) < 0) {
	      ret = krb5_scc_interpret(context, errno);
	      if (OPENCLOSE(id)) {
		  (void) fclose(data->file);
		  data->file = 0;
	      }
	      goto cleanup;
	  }

     if (fwrite(data->file, zeros, size % BUFSIZ) < 0) {
	 ret = krb5_scc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) fclose(data->file);
	     data->file = 0;
	 }
	 goto cleanup;
     }
     
     ret = fclose(data->file);
     data->file = 0;
#endif

     if (ret)
	 ret = krb5_scc_interpret(context, errno);

  cleanup:
     krb5_xfree(data->filename);
     krb5_xfree(data);
     krb5_xfree(id);

     return ret;
}
