/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/file/fcc_gennew.c
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
 * This file contains the source code for krb5_fcc_generate_new.
 */

#define NEED_SOCKETS
#include <errno.h>
#include "fcc.h"
#include <k5-int.h>

#ifdef HAVE_NETINET_IN_H
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 /*error find some way to use net-byte-order file version numbers.*/
#endif

extern krb5_cc_ops krb5_fcc_ops;

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from fcc.h).
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
krb5_error_code KRB5_CALLCONV
krb5_fcc_generate_new (context, id)
   krb5_context context;
   krb5_ccache *id;
{
     krb5_ccache lid;
     int ret;
     krb5_error_code    retcode = 0;
     char scratch[sizeof(TKT_ROOT)+6+1]; /* +6 for the scratch part, +1 for
					    NUL */

     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_fcc_ops;

     (void) strcpy(scratch, TKT_ROOT);
     (void) strcat(scratch, "XXXXXX");
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_fcc_data));
     if (lid->data == NULL) {
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /*
      * The file is initially closed at the end of this call...
      */
     ((krb5_fcc_data *) lid->data)->fd = -1;

     ((krb5_fcc_data *) lid->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_fcc_data *) lid->data)->filename == NULL) {
	  krb5_xfree(((krb5_fcc_data *) lid->data));
	  krb5_xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /* Solaris kerberos: I believe the KRB5_TC_OPENCLOSE should be set because
      * this is a file based cred cache and it needs an open/close to be used
      * properly.
      */
     ((krb5_fcc_data *) lid->data)->flags = KRB5_TC_OPENCLOSE;

     /* Set up the filename */
     strcpy(((krb5_fcc_data *) lid->data)->filename, scratch);

     /* Make sure the file name is reserved */
     ret = THREEPARAMOPEN(((krb5_fcc_data *) lid->data)->filename,
		O_CREAT | O_EXCL | O_WRONLY | O_BINARY, 0);
     if (ret == -1) {
	  retcode = krb5_fcc_interpret(context, errno);
          goto err_out;
     } else {
	  krb5_int16 fcc_fvno = htons(context->fcc_default_format);
	  krb5_int16 fcc_flen = 0;
	  int errsave, cnt;

	  /* Ignore user's umask, set mode = 0600 */
#ifndef HAVE_FCHMOD
#ifdef HAVE_CHMOD
	  chmod(((krb5_fcc_data *) lid->data)->filename, S_IRUSR | S_IWUSR);
#endif
#else
	  fchmod(ret, S_IRUSR | S_IWUSR);
#endif
	  if ((cnt = write(ret, (char *)&fcc_fvno, sizeof(fcc_fvno)))
	      != sizeof(fcc_fvno)) {
	      errsave = errno;
	      (void) close(ret);
	      (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	      retcode = (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
              goto err_out;
	  }
	  /* For version 4 we save a length for the rest of the header */
	  if (context->fcc_default_format == KRB5_FCC_FVNO_4) {
	    if ((cnt = write(ret, (char *)&fcc_flen, sizeof(fcc_flen)))
	        != sizeof(fcc_flen)) {
	        errsave = errno;
	        (void) close(ret);
	        (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	        retcode = (cnt == -1) ? krb5_fcc_interpret(context, errsave) : KRB5_CC_IO;
                goto err_out;
	    }
	  }
	  if (close(ret) == -1) {
	      errsave = errno;
	      (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	      retcode = krb5_fcc_interpret(context, errsave);
              goto err_out;
	  }

	  *id = lid;

      krb5_change_cache ();
	  return KRB5_OK;
     }

err_out:
     krb5_xfree(((krb5_fcc_data *) lid->data)->filename);
     krb5_xfree(((krb5_fcc_data *) lid->data));
     krb5_xfree(lid);
     return retcode;
}
