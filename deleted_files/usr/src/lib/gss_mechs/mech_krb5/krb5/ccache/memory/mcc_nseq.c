#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/file/mcc_nseq.c
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
 * This file contains the source code for krb5_mcc_next_cred.
 */

#include "mcc.h"

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_mcc_start_seq_get.
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
 * The cursor is updated for the next call to krb5_mcc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code KRB5_CALLCONV
krb5_mcc_next_cred(context, id, cursor, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_cc_cursor *cursor;
   krb5_creds *creds;
{
     krb5_mcc_cursor mcursor;
     krb5_error_code retval;
     krb5_data *scratch;

     mcursor = (krb5_mcc_cursor) *cursor;
     if (mcursor == NULL)
	return KRB5_CC_END;
     memset(creds, 0, sizeof(krb5_creds));     
     if (mcursor->creds) {
	*creds = *mcursor->creds;
	retval = krb5_copy_principal(context, mcursor->creds->client, &creds->client);
	if (retval)
		return retval;
	retval = krb5_copy_principal(context, mcursor->creds->server,
		&creds->server);
	if (retval)
		goto cleanclient;
	retval = krb5_copy_keyblock_contents(context, &mcursor->creds->keyblock,
		&creds->keyblock);
	if (retval)
		goto cleanserver;
	retval = krb5_copy_addresses(context, mcursor->creds->addresses,
		&creds->addresses);
	if (retval)
		goto cleanblock;
	retval = krb5_copy_data(context, &mcursor->creds->ticket, &scratch);
	if (retval)
		goto cleanaddrs;
	creds->ticket = *scratch;
	krb5_xfree(scratch);
	retval = krb5_copy_data(context, &mcursor->creds->second_ticket, &scratch);
	if (retval)
		goto cleanticket;
	creds->second_ticket = *scratch;
	krb5_xfree(scratch);
	retval = krb5_copy_authdata(context, mcursor->creds->authdata,
		&creds->authdata);
	if (retval)
		goto clearticket;
     }
     *cursor = (krb5_cc_cursor)mcursor->next;
     return KRB5_OK;

clearticket:
	memset(creds->ticket.data,0,creds->ticket.length);
cleanticket:
	krb5_xfree(creds->ticket.data);
cleanaddrs:
	krb5_free_addresses(context, creds->addresses);
cleanblock:
	krb5_xfree(creds->keyblock.contents);
cleanserver:
	krb5_free_principal(context, creds->server);
cleanclient:
	krb5_free_principal(context, creds->client);
	return retval;
}
