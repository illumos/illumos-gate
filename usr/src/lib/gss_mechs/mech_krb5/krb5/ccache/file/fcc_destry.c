#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_destry.c
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
 * This file contains the source code for krb5_fcc_destroy.
 */

#include <errno.h>
#include "fcc.h"

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_destroy(context, id)
   krb5_context context;
   krb5_ccache id;
{
     struct stat buf;
     unsigned long i, size;
     unsigned int wlen;
     char zeros[BUFSIZ];
     register int ret;
     krb5_error_code kret = 0;
      
     
     if (OPENCLOSE(id)) {
	  ret = THREEPARAMOPEN(((krb5_fcc_data *) id->data)->filename, O_RDWR | O_BINARY, 0);
	  if (ret < 0) {
	      kret = krb5_fcc_interpret(context, errno);
	      goto cleanup;
	  }
	  ((krb5_fcc_data *) id->data)->fd = ret;
     }
     else
	  lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_SET);

#ifdef MSDOS_FILESYSTEM
/* "disgusting bit of UNIX trivia" - that's how the writers of NFS describe
** the ability of UNIX to still write to a file which has been unlinked.
** Naturally, the PC can't do this. As a result, we have to delete the file
** after we wipe it clean but that throws off all the error handling code.
** So we have do the work ourselves.
*/
    ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
    if (ret == -1) {
        kret = krb5_fcc_interpret(context, errno);
        size = 0;                               /* Nothing to wipe clean */
    } else
        size = (unsigned long) buf.st_size;

    memset(zeros, 0, BUFSIZ);
    while (size > 0) {
        wlen = (int) ((size > BUFSIZ) ? BUFSIZ : size); /* How much to write */
        i = write(((krb5_fcc_data *) id->data)->fd, zeros, wlen);
        if (i < 0) {
            kret = krb5_fcc_interpret(context, errno);
            /* Don't jump to cleanup--we still want to delete the file. */
            break;
        }
        size -= i;                              /* We've read this much */
    }

    if (OPENCLOSE(id)) {
        (void) close(((krb5_fcc_data *)id->data)->fd);
        ((krb5_fcc_data *) id->data)->fd = -1;
    }

    ret = unlink(((krb5_fcc_data *) id->data)->filename);
    if (ret < 0) {
        kret = krb5_fcc_interpret(context, errno);
        goto cleanup;
    }

#else /* MSDOS_FILESYSTEM */

     ret = unlink(((krb5_fcc_data *) id->data)->filename);
     if (ret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
             kret = ret;
	 }
	 goto cleanup;
     }
     
     ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
     if (ret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;
     memset(zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (write(((krb5_fcc_data *) id->data)->fd, zeros, BUFSIZ) < 0) {
	      kret = krb5_fcc_interpret(context, errno);
	      if (OPENCLOSE(id)) {
		  (void) close(((krb5_fcc_data *)id->data)->fd);
		  ((krb5_fcc_data *) id->data)->fd = -1;
	      }
	      goto cleanup;
	  }

     wlen = (unsigned int) (size % BUFSIZ);
     if (write(((krb5_fcc_data *) id->data)->fd, zeros, wlen) < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }

     ret = close(((krb5_fcc_data *) id->data)->fd);
     ((krb5_fcc_data *) id->data)->fd = -1;

     if (ret)
	 kret = krb5_fcc_interpret(context, errno);

#endif /* MSDOS_FILESYSTEM */

  cleanup:
     krb5_xfree(((krb5_fcc_data *) id->data)->filename);
     krb5_xfree(id->data);
     krb5_xfree(id);

     krb5_change_cache ();
     return kret;
}
