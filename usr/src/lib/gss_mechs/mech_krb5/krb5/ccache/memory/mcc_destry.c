#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/memory/mcc_destry.c
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
 * This file contains the source code for krb5_mcc_destroy.
 */

#include <errno.h>
#include "mcc.h"

void
krb5_mcc_free(context, id)
	krb5_context context;
	krb5_ccache id;
{
	krb5_mcc_cursor curr,next;
     
     for (curr = ((krb5_mcc_data *)id->data)->link; curr;)
     {
	krb5_free_creds(context, curr->creds);
	next = curr->next;
	krb5_xfree(curr);
	curr = next;
     }
     ((krb5_mcc_data *)id->data)->link = NULL;
     krb5_free_principal(context, ((krb5_mcc_data *)id->data)->prin);
}

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * none
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_destroy(context, id)
   krb5_context context;
   krb5_ccache id;
{
     krb5_mcc_data *curr;

     if (mcc_head && ((krb5_mcc_data *)id->data) == mcc_head)
	mcc_head = mcc_head->next;
     else {
	for (curr=mcc_head; curr; curr=curr->next)
		if (curr->next == ((krb5_mcc_data *)id->data)) {
			curr->next = curr->next->next;
			break;
		}
     }
     
     krb5_mcc_free(context, id);

     krb5_xfree(((krb5_mcc_data *)id->data)->name);
     krb5_xfree(id->data); 
     krb5_xfree(id);
#if 0
     --krb5_cache_sessions;
#endif

     krb5_change_cache ();
     return KRB5_OK;
}
