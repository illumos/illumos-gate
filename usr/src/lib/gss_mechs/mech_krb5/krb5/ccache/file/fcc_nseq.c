#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/krb5/ccache/file/fcc_nseq.c
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
 * This file contains the source code for krb5_fcc_next_cred.
 */


#include <errno.h>
#include "fcc.h"

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifes:
 * cursor, creds
 * 
 * Effects:
 * Fills in creds with the "next" credentals structure from the cache
 * id.  The actual order the creds are returned in is arbitrary.
 * Space is allocated for the variable length fields in the
 * credentials structure, so the object returned must be passed to
 * krb5_destroy_credential.
 *
 * The cursor is updated for the next call to krb5_fcc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_fcc_next_cred(context, id, cursor, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     krb5_error_code kret;
     krb5_fcc_cursor *fcursor;
     krb5_int32 int32;
     krb5_octet octet;

     memset((char *)creds, 0, sizeof(*creds));

     MAYBE_OPEN(context, id, FCC_OPEN_RDONLY);

     fcursor = (krb5_fcc_cursor *) *cursor;

     kret = lseek(((krb5_fcc_data *) id->data)->fd, fcursor->pos, SEEK_SET);
     if (kret < 0) {
	 kret = krb5_fcc_interpret(context, errno);
	 MAYBE_CLOSE(context, id, kret);
	 return kret;
     }

     kret = krb5_fcc_read_principal(context, id, &creds->client);
     TCHECK(kret);
     kret = krb5_fcc_read_principal(context, id, &creds->server);
     TCHECK(kret);
     kret = krb5_fcc_read_keyblock(context, id, &creds->keyblock);
     TCHECK(kret);
     kret = krb5_fcc_read_times(context, id, &creds->times);
     TCHECK(kret);
     kret = krb5_fcc_read_octet(context, id, &octet);
     TCHECK(kret);
     creds->is_skey = octet;
     kret = krb5_fcc_read_int32(context, id, &int32);
     TCHECK(kret);
     creds->ticket_flags = int32;
     kret = krb5_fcc_read_addrs(context, id, &creds->addresses);
     TCHECK(kret);
     kret = krb5_fcc_read_authdata(context, id, &creds->authdata);
     TCHECK(kret);
     kret = krb5_fcc_read_data(context, id, &creds->ticket);
     TCHECK(kret);
     kret = krb5_fcc_read_data(context, id, &creds->second_ticket);
     TCHECK(kret);
     
     fcursor->pos = lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_CUR);
     cursor = (krb5_cc_cursor *) fcursor;

lose:
     MAYBE_CLOSE(context, id, kret);		/* won't overwrite kret
					   if already set */
     if (kret != KRB5_OK)
	 krb5_free_cred_contents(context, creds);
     return kret;
}
