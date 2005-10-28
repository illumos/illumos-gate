#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_skip.c
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
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */


#include "fcc.h"

krb5_error_code
krb5_fcc_skip_header(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code kret;
     krb5_ui_2 fcc_flen;

     lseek(data->fd, sizeof(krb5_ui_2), SEEK_SET);
     if (data->version == KRB5_FCC_FVNO_4) {
	 kret = krb5_fcc_read_ui_2(context, id, &fcc_flen);
	 if (kret) return kret;
	 if(lseek(data->fd, fcc_flen, SEEK_CUR) < 0)
		 return errno;
     }
     return KRB5_OK;
}

krb5_error_code
krb5_fcc_skip_principal(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_principal princ;

     kret = krb5_fcc_read_principal(context, id, &princ);
     if (kret != KRB5_OK)
	  return kret;

     krb5_free_principal(context, princ);
     return KRB5_OK;
}
