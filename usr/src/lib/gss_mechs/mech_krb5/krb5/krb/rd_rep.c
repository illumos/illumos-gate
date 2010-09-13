/*
 * lib/krb5/krb/rd_rep.c
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
 * krb5_rd_rep()
 */

#include "k5-int.h"
#include "auth_con.h"

/*
 *  Parses a KRB_AP_REP message, returning its contents.
 * 
 *  repl is filled in with with a pointer to allocated memory containing
 * the fields from the encrypted response. 
 * 
 *  the key in kblock is used to decrypt the message.
 * 
 *  returns system errors, encryption errors, replay errors
 */

krb5_error_code KRB5_CALLCONV
krb5_rd_rep(krb5_context context, krb5_auth_context auth_context, const krb5_data *inbuf, krb5_ap_rep_enc_part **repl)
{
    krb5_error_code 	  retval;
    krb5_ap_rep 	* reply;
    krb5_data 	 	  scratch;

    if (!krb5_is_ap_rep(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;

    /* decode it */

    if ((retval = decode_krb5_ap_rep(inbuf, &reply)))
	return retval;

    /* put together an eblock for this encryption */

    scratch.length = reply->enc_part.ciphertext.length;
    if (!(scratch.data = malloc(scratch.length))) {
	krb5_free_ap_rep(context, reply);
	return(ENOMEM);
    }

    if ((retval = krb5_c_decrypt(context, auth_context->keyblock,
				 KRB5_KEYUSAGE_AP_REP_ENCPART, 0,
				 &reply->enc_part, &scratch)))
	goto clean_scratch;

    /* now decode the decrypted stuff */
    retval = decode_krb5_ap_rep_enc_part(&scratch, repl);
    if (retval)
	goto clean_scratch;

    /* Check reply fields */
    if (((*repl)->ctime != auth_context->authentp->ctime) ||
      ((*repl)->cusec != auth_context->authentp->cusec)) {
	retval = KRB5_MUTUAL_FAILED;
	goto clean_scratch;
    }

    /* Set auth subkey */
    if ((*repl)->subkey) {
	if (auth_context->recv_subkey) {
	    krb5_free_keyblock(context, auth_context->recv_subkey);
	    auth_context->recv_subkey = NULL;
	}
	retval = krb5_copy_keyblock(context, (*repl)->subkey,
				    &auth_context->recv_subkey);
	if (retval)
	    goto clean_scratch;
	if (auth_context->send_subkey) {
	    krb5_free_keyblock(context, auth_context->send_subkey);
	    auth_context->send_subkey = NULL;
	}
	retval = krb5_copy_keyblock(context, (*repl)->subkey,
				    &auth_context->send_subkey);
	if (retval) {
	    krb5_free_keyblock(context, auth_context->send_subkey);
	    auth_context->send_subkey = NULL;
	}
    }

    /* Get remote sequence number */
    auth_context->remote_seq_number = (*repl)->seq_number;

clean_scratch:
    memset(scratch.data, 0, scratch.length); 

    krb5_free_ap_rep(context, reply);
    free(scratch.data);
    return retval;
}
