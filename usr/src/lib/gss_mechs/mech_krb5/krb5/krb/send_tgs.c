/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * lib/krb5/krb/send_tgs.c
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
 * krb5_send_tgs()
 */

#include "k5-int.h"

/*
 Sends a request to the TGS and waits for a response.
 options is used for the options in the KRB_TGS_REQ.
 timestruct values are used for from, till, rtime " " "
 enctype is used for enctype " " ", and to encrypt the authorization data, 
 sname is used for sname " " "
 addrs, if non-NULL, is used for addresses " " "
 authorization_dat, if non-NULL, is used for authorization_dat " " "
 second_ticket, if required by options, is used for the 2nd ticket in the req.
 in_cred is used for the ticket & session key in the KRB_AP_REQ header " " "
 (the KDC realm is extracted from in_cred->server's realm)
 
 The response is placed into *rep.
 rep->response.data is set to point at allocated storage which should be
 freed by the caller when finished.

 returns system errors
 */
static krb5_error_code 
krb5_send_tgs_basic(krb5_context context, krb5_data *in_data, krb5_creds *in_cred, krb5_data *outbuf)
{   
    krb5_error_code       retval;
    krb5_checksum         checksum;
    krb5_authenticator 	  authent;
    krb5_ap_req 	  request;
    krb5_data		* scratch;
    krb5_data           * toutbuf;

    /* Generate checksum */
    if ((retval = krb5_c_make_checksum(context, context->kdc_req_sumtype,
				       &in_cred->keyblock,
				       KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
				       in_data, &checksum))) {
	free(checksum.contents);
	return(retval);
    }

    /* gen authenticator */
    authent.subkey = 0;
    authent.seq_number = 0;
    authent.checksum = &checksum;
    authent.client = in_cred->client;
    authent.authorization_data = in_cred->authdata;
    if ((retval = krb5_us_timeofday(context, &authent.ctime,
				    &authent.cusec))) {
        free(checksum.contents);
	return(retval);
    }

    /* encode the authenticator */
    if ((retval = encode_krb5_authenticator(&authent, &scratch))) {
        free(checksum.contents);
	return(retval);
    }

    free(checksum.contents);

    request.authenticator.ciphertext.data = 0;
    request.authenticator.kvno = 0;
    request.ap_options = 0;
    request.ticket = 0;

    if ((retval = decode_krb5_ticket(&(in_cred)->ticket, &request.ticket)))
	/* Cleanup scratch and scratch data */
        goto cleanup_data;

    /* call the encryption routine */ 
    if ((retval = krb5_encrypt_helper(context, &in_cred->keyblock,
				      KRB5_KEYUSAGE_TGS_REQ_AUTH,
				      scratch, &request.authenticator)))
	goto cleanup_ticket;

    retval = encode_krb5_ap_req(&request, &toutbuf);
    /* Solaris Kerberos */
    if (retval == 0) {
	*outbuf = *toutbuf;
	krb5_xfree(toutbuf);
    }


    memset(request.authenticator.ciphertext.data, 0,
           request.authenticator.ciphertext.length);
    free(request.authenticator.ciphertext.data);

cleanup_ticket:
    krb5_free_ticket(context, request.ticket);

cleanup_data:
    memset(scratch->data, 0, scratch->length);
    free(scratch->data);

    free(scratch);

    return retval;
}

krb5_error_code
krb5_send_tgs(krb5_context context, krb5_flags kdcoptions,
	      const krb5_ticket_times *timestruct, const krb5_enctype *ktypes,
	      krb5_const_principal sname, krb5_address *const *addrs,
	      krb5_authdata *const *authorization_data,
	      krb5_pa_data *const *padata, const krb5_data *second_ticket,
	      krb5_creds *in_cred, krb5_response *rep)
{
	return (krb5_send_tgs2(context, kdcoptions,
			    timestruct, ktypes,
			    sname, addrs,
			    authorization_data,
			    padata, second_ticket,
			    in_cred, rep,
			    NULL));
}

/*
 * Solaris Kerberos
 * Same as krb5_send_tgs plus an extra arg to return the FQDN
 * of the KDC sent the request.
 */
krb5_error_code
krb5_send_tgs2(krb5_context context, krb5_flags kdcoptions,
	      const krb5_ticket_times *timestruct, const krb5_enctype *ktypes,
	      krb5_const_principal sname, krb5_address *const *addrs,
	      krb5_authdata *const *authorization_data,
	      krb5_pa_data *const *padata, const krb5_data *second_ticket,
	    krb5_creds *in_cred, krb5_response *rep, char **hostname_used)
{
    krb5_error_code retval;
    krb5_kdc_req tgsreq;
    krb5_data *scratch, scratch2;
    krb5_ticket *sec_ticket = 0;
    krb5_ticket *sec_ticket_arr[2];
    krb5_timestamp time_now;
    krb5_pa_data **combined_padata;
    krb5_pa_data ap_req_padata;
    int tcp_only = 0, use_master;

    /* 
     * in_creds MUST be a valid credential NOT just a partially filled in
     * place holder for us to get credentials for the caller.
     */
    if (!in_cred->ticket.length)
        return(KRB5_NO_TKT_SUPPLIED);

    /* Solaris Kerberos (illumos) */
    if (krb5_getenv("MS_INTEROP")) {
        /* Don't bother with UDP. */
        tcp_only = 1;
    }

    memset((char *)&tgsreq, 0, sizeof(tgsreq));

    tgsreq.kdc_options = kdcoptions;
    tgsreq.server = (krb5_principal) sname;

    tgsreq.from = timestruct->starttime;
    tgsreq.till = timestruct->endtime ? timestruct->endtime :
	    in_cred->times.endtime;
    tgsreq.rtime = timestruct->renew_till;
    if ((retval = krb5_timeofday(context, &time_now)))
	return(retval);
    /* XXX we know they are the same size... */
    rep->expected_nonce = tgsreq.nonce = (krb5_int32) time_now;
    rep->request_time = time_now;

    tgsreq.addresses = (krb5_address **) addrs;

    if (authorization_data) {
	/* need to encrypt it in the request */

	if ((retval = encode_krb5_authdata(authorization_data,
					   &scratch)))
	    return(retval);

	if ((retval = krb5_encrypt_helper(context, &in_cred->keyblock,
					  KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY,
					  scratch,
					  &tgsreq.authorization_data))) {
	    krb5_xfree(tgsreq.authorization_data.ciphertext.data);
	    krb5_free_data(context, scratch);
	    return retval;
	}

	krb5_free_data(context, scratch);
    }

    /* Get the encryption types list */
    if (ktypes) {
	/* Check passed ktypes and make sure they're valid. */
   	for (tgsreq.nktypes = 0; ktypes[tgsreq.nktypes]; tgsreq.nktypes++) {
    	    if (!krb5_c_valid_enctype(ktypes[tgsreq.nktypes]))
		return KRB5_PROG_ETYPE_NOSUPP;
	}
    	tgsreq.ktype = (krb5_enctype *)ktypes;
    } else {
        /* Get the default ktypes */
	/* Solaris Kerberos */
	if ((retval = krb5_get_tgs_ktypes(context, sname, &(tgsreq.ktype))))
		goto send_tgs_error_2;
	for(tgsreq.nktypes = 0; tgsreq.ktype[tgsreq.nktypes]; tgsreq.nktypes++);
    }

    if (second_ticket) {
	if ((retval = decode_krb5_ticket(second_ticket, &sec_ticket)))
	    goto send_tgs_error_1;
	sec_ticket_arr[0] = sec_ticket;
	sec_ticket_arr[1] = 0;
	tgsreq.second_ticket = sec_ticket_arr;
    } else
	tgsreq.second_ticket = 0;

    /* encode the body; then checksum it */
    if ((retval = encode_krb5_kdc_req_body(&tgsreq, &scratch)))
	goto send_tgs_error_2;

    /*
     * Get an ap_req.
     */
    if ((retval = krb5_send_tgs_basic(context, scratch, in_cred, &scratch2))) {
        krb5_free_data(context, scratch);
	goto send_tgs_error_2;
    }
    krb5_free_data(context, scratch);

    ap_req_padata.pa_type = KRB5_PADATA_AP_REQ;
    ap_req_padata.length = scratch2.length;
    ap_req_padata.contents = (krb5_octet *)scratch2.data;

    /* combine in any other supplied padata */
    if (padata) {
	krb5_pa_data * const * counter;
	register unsigned int i = 0;
	for (counter = padata; *counter; counter++, i++);
	combined_padata = malloc((i+2) * sizeof(*combined_padata));
	if (!combined_padata) {
	    krb5_xfree(ap_req_padata.contents);
	    retval = ENOMEM;
	    goto send_tgs_error_2;
	}
	combined_padata[0] = &ap_req_padata;
	for (i = 1, counter = padata; *counter; counter++, i++)
	    combined_padata[i] = (krb5_pa_data *) *counter;
	combined_padata[i] = 0;
    } else {
	combined_padata = (krb5_pa_data **)malloc(2*sizeof(*combined_padata));
	if (!combined_padata) {
	    krb5_xfree(ap_req_padata.contents);
	    retval = ENOMEM;
	    goto send_tgs_error_2;
	}
	combined_padata[0] = &ap_req_padata;
	combined_padata[1] = 0;
    }
    tgsreq.padata = combined_padata;

    /* the TGS_REQ is assembled in tgsreq, so encode it */
    if ((retval = encode_krb5_tgs_req(&tgsreq, &scratch))) {
	krb5_xfree(ap_req_padata.contents);
	krb5_xfree(combined_padata);
	goto send_tgs_error_2;
    }
    krb5_xfree(ap_req_padata.contents);
    krb5_xfree(combined_padata);

    /* now send request & get response from KDC */
send_again:
    use_master = 0;
    retval = krb5_sendto_kdc2(context, scratch, 
			    krb5_princ_realm(context, sname),
			    &rep->response, &use_master, tcp_only,
			    hostname_used);
    if (retval == 0) {
	if (krb5_is_krb_error(&rep->response)) {
	    if (!tcp_only) {
		krb5_error *err_reply;
		retval = decode_krb5_error(&rep->response, &err_reply);
		/* Solaris Kerberos */
		if (retval == 0) {
		    if (err_reply->error == KRB_ERR_RESPONSE_TOO_BIG) {
			tcp_only = 1;
			krb5_free_error(context, err_reply);
			free(rep->response.data);
			rep->response.data = 0;
			goto send_again;
		    }
		    krb5_free_error(context, err_reply);
		}
	    }
	} else if (krb5_is_tgs_rep(&rep->response))
	    rep->message_type = KRB5_TGS_REP;
        else /* XXX: assume it's an error */
	    rep->message_type = KRB5_ERROR;
    }

    krb5_free_data(context, scratch);
    
send_tgs_error_2:;
    if (sec_ticket) 
	krb5_free_ticket(context, sec_ticket);

send_tgs_error_1:;
    if (ktypes == NULL)
	krb5_xfree(tgsreq.ktype);
    if (tgsreq.authorization_data.ciphertext.data) {
	memset(tgsreq.authorization_data.ciphertext.data, 0,
               tgsreq.authorization_data.ciphertext.length); 
	krb5_xfree(tgsreq.authorization_data.ciphertext.data);
    }

    return retval;
}
