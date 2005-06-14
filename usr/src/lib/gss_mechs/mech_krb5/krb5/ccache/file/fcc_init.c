#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_init.c
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
 * This file contains the source code for krb5_fcc_initialize.
 */


#include <errno.h>
#include "fcc.h"

/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents are destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_initialize(context, id, princ)
   krb5_context context;
   krb5_ccache id;
   krb5_principal princ;
{
     krb5_error_code kret = 0;
     int reti = 0;

     MAYBE_OPEN(context, id, FCC_OPEN_AND_ERASE_NOUNLINK); /* SUNW */

#ifndef HAVE_FCHMOD
#ifdef HAVE_CHMOD
     reti = chmod(((krb5_fcc_data *) id->data)->filename, S_IREAD | S_IWRITE);
#endif
#else
     reti = fchmod(((krb5_fcc_data *) id->data)->fd, S_IREAD | S_IWRITE);
#endif
     if (reti == -1) {
	 kret = krb5_fcc_interpret(context, errno);
	 MAYBE_CLOSE(context, id, kret);
	 return kret;
     }
     kret = krb5_fcc_store_principal(context, id, princ);

     MAYBE_CLOSE(context, id, kret);
     krb5_change_cache ();
     return kret;
}


