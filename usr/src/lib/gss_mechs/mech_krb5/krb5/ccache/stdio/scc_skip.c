#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/stdio/scc_skip.c
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
 * This file contains the source code for reading variables from a
 * credentials cache.  These are not library-exported functions.
 */


#include "scc.h"

krb5_error_code
krb5_scc_skip_header(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_scc_data *data = (krb5_scc_data *) id->data;
     krb5_ui_2 scc_flen;

     if (fseek(data->file, sizeof(krb5_ui_2), SEEK_SET))
	 return errno;
     if (data->version == KRB5_SCC_FVNO_4) {
	 kret = krb5_scc_read_ui_2(context, id, &scc_flen);
	 if (kret) return kret;
	 if (fseek(data->file, scc_flen, SEEK_CUR))
	     return errno;
     }
     return KRB5_OK;
}

krb5_error_code
krb5_scc_skip_principal(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_error_code kret;
     krb5_principal princ;

     kret = krb5_scc_read_principal(context, id, &princ);
     if (kret != KRB5_OK)
	  return kret;

     krb5_free_principal(context, princ);
     return KRB5_OK;
}
