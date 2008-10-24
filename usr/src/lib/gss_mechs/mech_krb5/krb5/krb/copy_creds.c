/*
 * lib/krb5/krb/copy_creds.c
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
 * krb5_copy_cred()
 */

#include "k5-int.h"

/*
 * Copy credentials, allocating fresh storage where needed.
 */

krb5_error_code KRB5_CALLCONV
krb5_copy_creds(krb5_context context, const krb5_creds *incred, krb5_creds **outcred)
{
    krb5_creds *tempcred;
    krb5_error_code retval;
    krb5_data *scratch;

    if (!(tempcred = (krb5_creds *)malloc(sizeof(*tempcred))))
	return ENOMEM;

    *tempcred = *incred;
    retval = krb5_copy_principal(context, incred->client, &tempcred->client);
    if (retval)
	goto cleanlast;
    retval = krb5_copy_principal(context, incred->server, &tempcred->server);
    if (retval)
	goto cleanclient;
    retval = krb5_copy_keyblock_contents(context, &incred->keyblock,
					 &tempcred->keyblock);
    if (retval)
	goto cleanserver;
    retval = krb5_copy_addresses(context, incred->addresses, &tempcred->addresses);
    if (retval)
	goto cleanblock;
    retval = krb5_copy_data(context, &incred->ticket, &scratch);
    if (retval)
	goto cleanaddrs;
    tempcred->ticket = *scratch;
    krb5_xfree(scratch);
    retval = krb5_copy_data(context, &incred->second_ticket, &scratch);
    if (retval)
	goto cleanticket;

    tempcred->second_ticket = *scratch;
    krb5_xfree(scratch);

    retval = krb5_copy_authdata(context, incred->authdata,&tempcred->authdata);
    if (retval)
        goto clearticket;

    *outcred = tempcred;
    return 0;

 clearticket:    
    memset(tempcred->ticket.data,0,tempcred->ticket.length);
 cleanticket:
    free(tempcred->ticket.data);
 cleanaddrs:
    krb5_free_addresses(context, tempcred->addresses);
 cleanblock:
    krb5_xfree(tempcred->keyblock.contents);
 cleanserver:
    krb5_free_principal(context, tempcred->server);
 cleanclient:
    krb5_free_principal(context, tempcred->client);
 cleanlast:
    krb5_xfree(tempcred);
    return retval;
}
