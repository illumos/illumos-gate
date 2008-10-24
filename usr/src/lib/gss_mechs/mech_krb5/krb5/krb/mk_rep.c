/*
 * lib/krb5/krb/mk_rep.c
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
 * krb5_mk_rep()
 */

#include "k5-int.h"
#include "auth_con.h"

/*
 Formats a KRB_AP_REP message into outbuf.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 returns system errors
*/

krb5_error_code KRB5_CALLCONV
krb5_mk_rep(krb5_context context, krb5_auth_context auth_context, krb5_data *outbuf)
{
    krb5_error_code 	  retval;
    krb5_ap_rep_enc_part  repl;
    krb5_ap_rep 	  reply;
    krb5_data 		* scratch;
    krb5_data 		* toutbuf;

    /* Make the reply */
    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) ||
	(auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
	(auth_context->local_seq_number == 0)) {
	if ((retval = krb5_generate_seq_number(context, auth_context->keyblock,
					       &auth_context->local_seq_number)))
            return(retval);
    }

    repl.ctime = auth_context->authentp->ctime;    
    repl.cusec = auth_context->authentp->cusec;    
    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_USE_SUBKEY) {
	retval = krb5int_generate_and_save_subkey (context, auth_context,
						   auth_context->keyblock);
	if (retval)
	    return retval;
	repl.subkey = auth_context->send_subkey;
    } else
	repl.subkey = auth_context->authentp->subkey;
    repl.seq_number = auth_context->local_seq_number;

    /* encode it before encrypting */
    if ((retval = encode_krb5_ap_rep_enc_part(&repl, &scratch)))
	return retval;

    if ((retval = krb5_encrypt_helper(context, auth_context->keyblock,
				      KRB5_KEYUSAGE_AP_REP_ENCPART,
				      scratch, &reply.enc_part)))
	goto cleanup_scratch;

    if (!(retval = encode_krb5_ap_rep(&reply, &toutbuf))) {
	*outbuf = *toutbuf;
	krb5_xfree(toutbuf);
    }

    memset(reply.enc_part.ciphertext.data, 0, reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data); 
    reply.enc_part.ciphertext.length = 0; 
    reply.enc_part.ciphertext.data = 0;

cleanup_scratch:
    memset(scratch->data, 0, scratch->length); 
    krb5_free_data(context, scratch);

    return retval;
}
