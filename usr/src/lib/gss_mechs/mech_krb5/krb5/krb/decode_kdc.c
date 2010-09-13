/*
 * lib/krb5/krb/decode_kdc.c
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
 * krb5_decode_kdc_rep() function.
 */

#include "k5-int.h"

/*
 Takes a KDC_REP message and decrypts encrypted part using etype and
 *key, putting result in *rep.
 dec_rep->client,ticket,session,last_req,server,caddrs
 are all set to allocated storage which should be freed by the caller
 when finished with the response.

 If the response isn't a KDC_REP (tgs or as), it returns an error from
 the decoding routines.

 returns errors from encryption routines, system errors
 */

krb5_error_code
krb5_decode_kdc_rep(krb5_context context, krb5_data *enc_rep, const krb5_keyblock *key, krb5_kdc_rep **dec_rep)
{
    krb5_error_code retval;
    krb5_kdc_rep *local_dec_rep;
    krb5_keyusage usage;

    if (krb5_is_as_rep(enc_rep)) {
	usage = KRB5_KEYUSAGE_AS_REP_ENCPART;
	retval = decode_krb5_as_rep(enc_rep, &local_dec_rep);
    } else if (krb5_is_tgs_rep(enc_rep)) {
	usage = KRB5_KEYUSAGE_TGS_REP_ENCPART_SESSKEY;
	/* KRB5_KEYUSAGE_TGS_REP_ENCPART_SUBKEY would go here, except
	   that this client code base doesn't ever put a subkey in the
	   tgs_req authenticator, so the tgs_rep is never encrypted in
	   one.  (Check send_tgs.c:krb5_send_tgs_basic(), near the top
	   where authent.subkey is set to 0) */
	retval = decode_krb5_tgs_rep(enc_rep, &local_dec_rep);
    } else {
	return KRB5KRB_AP_ERR_MSG_TYPE;
    }

    if (retval)
	return retval;

    if ((retval = krb5_kdc_rep_decrypt_proc(context, key, &usage,
					    local_dec_rep))) 
	krb5_free_kdc_rep(context, local_dec_rep);
    else
    	*dec_rep = local_dec_rep;
    return(retval);
}

