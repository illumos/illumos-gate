/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/krb/mk_req_ext.c
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
 * krb5_mk_req_extended()
 */


#include "k5-int.h"
#include "auth_con.h"

/*
 Formats a KRB_AP_REQ message into outbuf, with more complete options than
 krb_mk_req.

 outbuf, ap_req_options, checksum, and ccache are used in the
 same fashion as for krb5_mk_req.

 creds is used to supply the credentials (ticket and session key) needed
 to form the request.

 if creds->ticket has no data (length == 0), then a ticket is obtained
 from either the cache or the TGS, passing creds to krb5_get_credentials().
 kdc_options specifies the options requested for the ticket to be used.
 If a ticket with appropriate flags is not found in the cache, then these
 options are passed on in a request to an appropriate KDC.

 ap_req_options specifies the KRB_AP_REQ options desired.

 if ap_req_options specifies AP_OPTS_USE_SESSION_KEY, then creds->ticket
 must contain the appropriate ENC-TKT-IN-SKEY ticket.

 checksum specifies the checksum to be used in the authenticator.

 The outbuf buffer storage is allocated, and should be freed by the
 caller when finished.

 On an error return, the credentials pointed to by creds might have been
 augmented with additional fields from the obtained credentials; the entire
 credentials should be released by calling krb5_free_creds().

 returns system errors
*/

static krb5_error_code
krb5_generate_authenticator (krb5_context,
				       krb5_authenticator *, krb5_principal,
				       krb5_checksum *, krb5_keyblock *,
				       krb5_ui_4, krb5_authdata ** );

krb5_error_code
krb5int_generate_and_save_subkey (krb5_context context,
				  krb5_auth_context auth_context,
				  krb5_keyblock *keyblock)
{
#if 0
    /*
     * Solaris Kerberos:  Don't bother with this PRNG stuff,
     * we have /dev/random and PKCS#11 to handle Random Numbers.
     */
    /* Provide some more fodder for random number code.
       This isn't strong cryptographically; the point here is not
       to guarantee randomness, but to make it less likely that multiple
       sessions could pick the same subkey.  */
    struct {
	krb5_int32 sec, usec;
    } rnd_data;
    krb5_data d;

    krb5_crypto_us_timeofday (&rnd_data.sec, &rnd_data.usec);
    d.length = sizeof (rnd_data);
    d.data = (char *) &rnd_data;
    (void) krb5_c_random_add_entropy (context, KRB5_C_RANDSOURCE_TIMING, &d);
#endif
    krb5_error_code retval;

    /* Solaris Kerberos */
    if (auth_context->send_subkey != NULL) {
	krb5_free_keyblock(context, auth_context->send_subkey);
	auth_context->send_subkey = NULL;
    }

    if ((retval = krb5_generate_subkey(context, keyblock, &auth_context->send_subkey)))
	return retval;

    /* Solaris Kerberos */
    if (auth_context->recv_subkey != NULL) {
	krb5_free_keyblock(context, auth_context->recv_subkey);
	auth_context->recv_subkey = NULL;
    }
    retval = krb5_copy_keyblock(context, auth_context->send_subkey,
				&auth_context->recv_subkey);
    if (retval) {
	krb5_free_keyblock(context, auth_context->send_subkey);
	auth_context->send_subkey = NULL;
	return retval;
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_mk_req_extended(krb5_context context, krb5_auth_context *auth_context,
		     krb5_flags ap_req_options, krb5_data *in_data,
		     krb5_creds *in_creds, krb5_data *outbuf)
{
    krb5_error_code 	  retval;
    krb5_checksum	  checksum;
    krb5_checksum	  *checksump = 0;
    krb5_auth_context	  new_auth_context;

    krb5_ap_req request;
    krb5_data *scratch = 0;
    krb5_data *toutbuf;

    request.ap_options = ap_req_options & AP_OPTS_WIRE_MASK;
    request.authenticator.ciphertext.data = 0;
    request.ticket = 0;

    if (!in_creds->ticket.length)
	return(KRB5_NO_TKT_SUPPLIED);

    /* we need a native ticket */
    if ((retval = decode_krb5_ticket(&(in_creds)->ticket, &request.ticket)))
	return(retval);

    /* verify that the ticket is not expired */
    if ((retval = krb5_validate_times(context, &in_creds->times)) != 0)
	goto cleanup;

    /* generate auth_context if needed */
    if (*auth_context == NULL) {
	if ((retval = krb5_auth_con_init(context, &new_auth_context)))
	    goto cleanup;
	*auth_context = new_auth_context;
    }

    if ((*auth_context)->keyblock != NULL) {
	krb5_free_keyblock(context, (*auth_context)->keyblock);
	(*auth_context)->keyblock = NULL;
    }

    /* set auth context keyblock */
    if ((retval = krb5_copy_keyblock(context, &in_creds->keyblock,
				     &((*auth_context)->keyblock))))
	goto cleanup;

    /* generate seq number if needed */
    if ((((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE)
     || ((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE))
      && ((*auth_context)->local_seq_number == 0))
	if ((retval = krb5_generate_seq_number(context, &in_creds->keyblock,
				     &(*auth_context)->local_seq_number)))
	    goto cleanup;


    /* generate subkey if needed */
    if (!in_data &&(*auth_context)->checksum_func) {
	retval = (*auth_context)->checksum_func( context,
						 *auth_context,
						 (*auth_context)->checksum_func_data,
						 &in_data);
	if (retval)
	    goto cleanup;
    }

    if ((ap_req_options & AP_OPTS_USE_SUBKEY)&&(!(*auth_context)->send_subkey)) {
	retval = krb5int_generate_and_save_subkey (context, *auth_context,
						   &in_creds->keyblock);
	if (retval)
	    goto cleanup;
    }


    if (in_data) {

      if ((*auth_context)->req_cksumtype == 0x8003) {
	    /* XXX Special hack for GSSAPI */
	    checksum.checksum_type = 0x8003;
	    checksum.length = in_data->length;
	    checksum.contents = (krb5_octet *) in_data->data;
	} else {
	    if ((retval = krb5_c_make_checksum(context,
					       (*auth_context)->req_cksumtype,
					       (*auth_context)->keyblock,
					       KRB5_KEYUSAGE_AP_REQ_AUTH_CKSUM,
					       in_data, &checksum)))
		goto cleanup_cksum;
	}
	checksump = &checksum;
    }

    /* Generate authenticator */
    if (((*auth_context)->authentp = (krb5_authenticator *)malloc(sizeof(
					krb5_authenticator))) == NULL) {
	retval = ENOMEM;
	goto cleanup_cksum;
    }

    if ((retval = krb5_generate_authenticator(context,
					      (*auth_context)->authentp,
					      (in_creds)->client, checksump,
					      (*auth_context)->send_subkey,
					      (*auth_context)->local_seq_number,
					      (in_creds)->authdata)))
	goto cleanup_cksum;

    /* encode the authenticator */
    if ((retval = encode_krb5_authenticator((*auth_context)->authentp,
					    &scratch)))
	goto cleanup_cksum;

    /* Null out these fields, to prevent pointer sharing problems;
     * they were supplied by the caller
     */
    (*auth_context)->authentp->client = NULL;
    (*auth_context)->authentp->checksum = NULL;
    (*auth_context)->authentp->authorization_data = NULL;

    /* call the encryption routine */
    if ((retval = krb5_encrypt_helper(context, &in_creds->keyblock,
				      KRB5_KEYUSAGE_AP_REQ_AUTH,
				      scratch, &request.authenticator)))
	goto cleanup_cksum;

    if ((retval = encode_krb5_ap_req(&request, &toutbuf)))
	goto cleanup_cksum;
    *outbuf = *toutbuf;

    krb5_xfree(toutbuf);

cleanup_cksum:
    if (checksump && checksump->checksum_type != 0x8003)
      free(checksump->contents);

cleanup:
    if (request.ticket)
	krb5_free_ticket(context, request.ticket);
    if (request.authenticator.ciphertext.data) {
    	(void) memset(request.authenticator.ciphertext.data, 0,
		      request.authenticator.ciphertext.length);
	free(request.authenticator.ciphertext.data);
    }
    if (scratch) {
	memset(scratch->data, 0, scratch->length);
        krb5_xfree(scratch->data);
	krb5_xfree(scratch);
    }
    return retval;
}

static krb5_error_code
krb5_generate_authenticator(krb5_context context, krb5_authenticator *authent, krb5_principal client, krb5_checksum *cksum, krb5_keyblock *key, krb5_ui_4 seq_number, krb5_authdata **authorization)
{
    krb5_error_code retval;

    authent->client = client;
    authent->checksum = cksum;
    if (key) {
	retval = krb5_copy_keyblock(context, key, &authent->subkey);
	if (retval)
	    return retval;
    } else
	authent->subkey = 0;
    authent->seq_number = seq_number;
    authent->authorization_data = authorization;

    return(krb5_us_timeofday(context, &authent->ctime, &authent->cusec));
}
