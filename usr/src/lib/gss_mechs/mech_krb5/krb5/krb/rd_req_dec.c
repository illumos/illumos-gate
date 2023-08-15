/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/krb/rd_req_dec.c
 *
 * Copyright (c) 1994 CyberSAFE Corporation.
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
 * Neither M.I.T., the Open Computing Security Group, nor
 * CyberSAFE Corporation make any representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * krb5_rd_req_decoded()
 */

#include "k5-int.h"
#include "auth_con.h"
#include <locale.h>
#include <syslog.h>

/*
 * essentially the same as krb_rd_req, but uses a decoded AP_REQ as
 * the input rather than an encoded input.
 */
/*
 *  Parses a KRB_AP_REQ message, returning its contents.
 *
 *  server specifies the expected server's name for the ticket; if NULL, then
 *  any server will be accepted if the key can be found, and the caller should
 *  verify that the principal is something it trusts.
 *
 *  rcache specifies a replay detection cache used to store authenticators and
 *  server names
 *
 *  keyproc specifies a procedure to generate a decryption key for the
 *  ticket.  If keyproc is non-NULL, keyprocarg is passed to it, and the result
 *  used as a decryption key. If keyproc is NULL, then fetchfrom is checked;
 *  if it is non-NULL, it specifies a parameter name from which to retrieve the
 *  decryption key.  If fetchfrom is NULL, then the default key store is
 *  consulted.
 *
 *  authdat is set to point at allocated storage structures; the caller
 *  should free them when finished.
 *
 *  returns system errors, encryption errors, replay errors
 */

static krb5_error_code decrypt_authenticator
	(krb5_context, const krb5_ap_req *, krb5_authenticator **,
		   int);


static krb5_error_code
krb5_rd_req_decrypt_tkt_part(krb5_context context, const krb5_ap_req *req, krb5_keytab keytab)
{
    krb5_error_code 	  retval;
    krb5_enctype 	  enctype;
    krb5_keytab_entry 	  ktent;

    enctype = req->ticket->enc_part.enctype;

    /* Solaris Kerberos: */
    memset(&ktent, 0, sizeof(krb5_keytab_entry));
    if ((retval = krb5_kt_get_entry(context, keytab, req->ticket->server,
				    req->ticket->enc_part.kvno,
				    enctype, &ktent)))
	return retval;


    /*
     * Solaris Kerberos:
     * If we get this far then we know that the enc types are similar,
     * therefore we should change the enc type to match that of what
     * we are decrypting.
     */
    ktent.key.enctype = enctype;

    retval = krb5_decrypt_tkt_part(context, &ktent.key, req->ticket);
    /* Upon error, Free keytab entry first, then return */

    if (retval == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
        /* Solaris Kerberos: spruce-up the err msg */
        krb5_principal princ = (krb5_principal) req->ticket->server;
	char *s_name = NULL;
	int kret = krb5_unparse_name(context, princ, &s_name);
	if (kret == 0) {
	    krb5_set_error_message(context, retval,
				dgettext(TEXT_DOMAIN,
					"AP Request ticket decrypt fail for principal '%s' (kvno=%d, enctype=%d)"),
				s_name,
				req->ticket->enc_part.kvno,
				enctype);
	   krb5_free_unparsed_name(context, s_name);
	}
    }

    (void) krb5_kt_free_entry(context, &ktent);
    return retval;
}

/*
 * Solaris Kerberos
 * Same as krb5int_check_clockskew() plus return the skew in seconds.
 */
static krb5_error_code
krb5int_check_clockskew2(krb5_context context,
			krb5_timestamp date,
			krb5_timestamp *ret_skew)
{
    krb5_timestamp currenttime, skew;
    krb5_error_code retval;

    retval = krb5_timeofday(context, &currenttime);
    if (retval)
        return retval;

    skew = labs((date)-currenttime);
    if (!(skew < context->clockskew)) {
        *ret_skew = skew;
        return KRB5KRB_AP_ERR_SKEW;
    }

    return 0;
}

static krb5_error_code
krb5_rd_req_decoded_opt(krb5_context context, krb5_auth_context *auth_context,
			const krb5_ap_req *req, krb5_const_principal server,
			krb5_keytab keytab, krb5_flags *ap_req_options,
			krb5_ticket **ticket, int check_valid_flag)
{
    krb5_error_code 	  retval = 0;
    krb5_principal_data princ_data;
    krb5_timestamp	  skew = 0; /* Solaris Kerberos */

    req->ticket->enc_part2 == NULL;
    if (server && krb5_is_referral_realm(&server->realm)) {
	char *realm;
	princ_data = *server;
	server = &princ_data;
	retval = krb5_get_default_realm(context, &realm);
	if (retval)
	    return retval;
	princ_data.realm.data = realm;
	princ_data.realm.length = strlen(realm);
    }
    if (server && !krb5_principal_compare(context, server, req->ticket->server)) {
	char *found_name = 0, *wanted_name = 0;
	if (krb5_unparse_name(context, server, &wanted_name) == 0
	    && krb5_unparse_name(context, req->ticket->server, &found_name) == 0)
	    krb5_set_error_message(context, KRB5KRB_AP_WRONG_PRINC,
				dgettext(TEXT_DOMAIN,
					"Wrong principal in request (found %s, wanted %s)"),
				   found_name, wanted_name);
	krb5_free_unparsed_name(context, wanted_name);
	krb5_free_unparsed_name(context, found_name);
	retval =  KRB5KRB_AP_WRONG_PRINC;
	goto cleanup;
    }

    /* if (req->ap_options & AP_OPTS_USE_SESSION_KEY)
       do we need special processing here ?	*/

    /* decrypt the ticket */
    if ((*auth_context)->keyblock) { /* User to User authentication */
    	if ((retval = krb5_decrypt_tkt_part(context, (*auth_context)->keyblock,
					    req->ticket)))
goto cleanup;
	krb5_free_keyblock(context, (*auth_context)->keyblock);
	(*auth_context)->keyblock = NULL;
    } else {
    	if ((retval = krb5_rd_req_decrypt_tkt_part(context, req, keytab)))
	    goto cleanup;
    }

    /* XXX this is an evil hack.  check_valid_flag is set iff the call
       is not from inside the kdc.  we can use this to determine which
       key usage to use */
    if ((retval = decrypt_authenticator(context, req,
					&((*auth_context)->authentp),
					check_valid_flag)))
	goto cleanup;

    if (!krb5_principal_compare(context, (*auth_context)->authentp->client,
				req->ticket->enc_part2->client)) {
	retval = KRB5KRB_AP_ERR_BADMATCH;
	goto cleanup;
    }

    if ((*auth_context)->remote_addr &&
      !krb5_address_search(context, (*auth_context)->remote_addr,
			   req->ticket->enc_part2->caddrs)) {
	retval = KRB5KRB_AP_ERR_BADADDR;
	goto cleanup;
    }

    /* okay, now check cross-realm policy */

#if defined(_SINGLE_HOP_ONLY)

    /* Single hop cross-realm tickets only */

    {
	krb5_transited *trans = &(req->ticket->enc_part2->transited);

      	/* If the transited list is empty, then we have at most one hop */
      	if (trans->tr_contents.data && trans->tr_contents.data[0])
            retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
    }

#elif defined(_NO_CROSS_REALM)

    /* No cross-realm tickets */

    {
	char		* lrealm;
      	krb5_data      	* realm;
      	krb5_transited 	* trans;

	realm = krb5_princ_realm(context, req->ticket->enc_part2->client);
	trans = &(req->ticket->enc_part2->transited);

	/*
      	 * If the transited list is empty, then we have at most one hop
      	 * So we also have to check that the client's realm is the local one
	 */
      	krb5_get_default_realm(context, &lrealm);
      	if ((trans->tr_contents.data && trans->tr_contents.data[0]) ||
          strlen(lrealm) != realm->length ||
          memcmp(lrealm, realm->data, strlen(lrealm))) {
            retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
      	}
      	free(lrealm);
    }

#else

    /* Hierarchical Cross-Realm */

    {
      	krb5_data      * realm;
      	krb5_transited * trans;

	realm = krb5_princ_realm(context, req->ticket->enc_part2->client);
	trans = &(req->ticket->enc_part2->transited);

	/*
      	 * If the transited list is not empty, then check that all realms
      	 * transited are within the hierarchy between the client's realm
      	 * and the local realm.
  	 */
	if (trans->tr_contents.data && trans->tr_contents.data[0]) {
	    retval = krb5_check_transited_list(context, &(trans->tr_contents),
					       realm,
					       krb5_princ_realm (context,
								 server));
      	}
    }

#endif

    if (retval)  goto cleanup;

    /* only check rcache if sender has provided one---some services
       may not be able to use replay caches (such as datagram servers) */

    if ((*auth_context)->rcache) {
	krb5_donot_replay  rep;
        krb5_tkt_authent   tktauthent;

	tktauthent.ticket = req->ticket;
	tktauthent.authenticator = (*auth_context)->authentp;
	if (!(retval = krb5_auth_to_rep(context, &tktauthent, &rep))) {
	    retval = krb5_rc_store(context, (*auth_context)->rcache, &rep);
	    krb5_xfree(rep.server);
	    krb5_xfree(rep.client);
	}

	if (retval == KRB5KRB_AP_ERR_SKEW)
	    goto err_skew;

	if (retval)
	    goto cleanup;
    }

    retval = krb5_validate_times(context, &req->ticket->enc_part2->times);
    if (retval != 0)
	    goto cleanup;

err_skew:
    if ((retval = krb5int_check_clockskew2(context,
					(*auth_context)->authentp->ctime,
					&skew))) {
        /* Solaris Kerberos */
        char *s_name = NULL;
        char *c_name = NULL;
	krb5_error_code serr, cerr;
	serr = krb5_unparse_name(context, req->ticket->server, &s_name);
	cerr = krb5_unparse_name(context, req->ticket->enc_part2->client,
				&c_name);
	krb5_set_error_message(context, retval,
			    dgettext(TEXT_DOMAIN,
				    "Clock skew too great: client '%s' AP request with ticket for '%s'. Skew is %dm (allowable %dm)."),
			    cerr == 0 ? c_name : "unknown",
			    serr == 0 ? s_name : "unknown",
			    skew > 0 ? skew/60 : 0,
			    context->clockskew > 0 ? context->clockskew/60 : 0);
	if (s_name)
	    krb5_free_unparsed_name(context, s_name);
	if (c_name)
	    krb5_free_unparsed_name(context, c_name);
        goto cleanup;
    }

    if (check_valid_flag) {
        if (req->ticket->enc_part2->flags & TKT_FLG_INVALID) {
	    /* Solaris Kerberos */
	    char *s_name = NULL;
	    int err = krb5_unparse_name(context, req->ticket->server, &s_name);
	    retval = KRB5KRB_AP_ERR_TKT_INVALID;
	    if (!err) {
	        krb5_set_error_message(context, retval,
				    dgettext(TEXT_DOMAIN,
				    "Ticket has invalid flag set for server '%s'"),
				    s_name);
	        krb5_free_unparsed_name(context, s_name);
	    }
	    goto cleanup;
	}
    }

    /* check if the various etypes are permitted */

    if ((*auth_context)->auth_context_flags & KRB5_AUTH_CONTEXT_PERMIT_ALL) {
	/* no etype check needed */
	/*EMPTY*/
	;
    } else if ((*auth_context)->permitted_etypes == NULL) {
	int etype;
	/* check against the default set */
	if ((!krb5_is_permitted_enctype(context,
					etype = req->ticket->enc_part.enctype)) ||
	    (!krb5_is_permitted_enctype(context,
					etype = req->ticket->enc_part2->session->enctype)) ||
	    (((*auth_context)->authentp->subkey) &&
	     !krb5_is_permitted_enctype(context,
					etype = (*auth_context)->authentp->subkey->enctype))) {
	    char enctype_name[30];
	    retval = KRB5_NOPERM_ETYPE;
	    if (krb5_enctype_to_string(etype, enctype_name, sizeof(enctype_name)) == 0)
		krb5_set_error_message(context, retval,
				    dgettext(TEXT_DOMAIN,
					    "Encryption type %s not permitted"),
				    enctype_name);
	    goto cleanup;
	}
    } else {
	/* check against the set in the auth_context */
	int i;

	for (i=0; (*auth_context)->permitted_etypes[i]; i++)
	    if ((*auth_context)->permitted_etypes[i] ==
		req->ticket->enc_part.enctype)
		break;
	if (!(*auth_context)->permitted_etypes[i]) {
	    char enctype_name[30];
	    retval = KRB5_NOPERM_ETYPE;
	    if (krb5_enctype_to_string(req->ticket->enc_part.enctype,
				       enctype_name, sizeof(enctype_name)) == 0)
		krb5_set_error_message(context, retval,
				    dgettext(TEXT_DOMAIN,
					    "Encryption type %s not permitted"),
				    enctype_name);
	    goto cleanup;
	}

	for (i=0; (*auth_context)->permitted_etypes[i]; i++)
	    if ((*auth_context)->permitted_etypes[i] ==
		req->ticket->enc_part2->session->enctype)
		break;
	if (!(*auth_context)->permitted_etypes[i]) {
	    char enctype_name[30];
	    retval = KRB5_NOPERM_ETYPE;
	    if (krb5_enctype_to_string(req->ticket->enc_part2->session->enctype,
				       enctype_name, sizeof(enctype_name)) == 0)
		krb5_set_error_message(context, retval,
				    dgettext(TEXT_DOMAIN,
					    "Encryption type %s not permitted"),
				    enctype_name);
	    goto cleanup;
	}

	if ((*auth_context)->authentp->subkey) {
	    for (i=0; (*auth_context)->permitted_etypes[i]; i++)
		if ((*auth_context)->permitted_etypes[i] ==
		    (*auth_context)->authentp->subkey->enctype)
		    break;
	    if (!(*auth_context)->permitted_etypes[i]) {
		char enctype_name[30];
		retval = KRB5_NOPERM_ETYPE;
		if (krb5_enctype_to_string((*auth_context)->authentp->subkey->enctype,
					   enctype_name,
					   sizeof(enctype_name)) == 0)
		    krb5_set_error_message(context, retval,
					dgettext(TEXT_DOMAIN,
					    "Encryption type %s not permitted"),
					enctype_name);
		goto cleanup;
	    }
	}
    }

    (*auth_context)->remote_seq_number = (*auth_context)->authentp->seq_number;
    if ((*auth_context)->authentp->subkey) {
	/* Solaris Kerberos */
	if ((*auth_context)->recv_subkey != NULL) {
	    krb5_free_keyblock(context, (*auth_context)->recv_subkey);
	    (*auth_context)->recv_subkey = NULL;
	}

	if ((retval = krb5_copy_keyblock(context,
					 (*auth_context)->authentp->subkey,
					 &((*auth_context)->recv_subkey))))
	    goto cleanup;
	/* Solaris Kerberos */
	if ((*auth_context)->send_subkey != NULL) {
	    krb5_free_keyblock(context, (*auth_context)->send_subkey);
	    (*auth_context)->send_subkey = NULL;
	}

	retval = krb5_copy_keyblock(context, (*auth_context)->authentp->subkey,
				    &((*auth_context)->send_subkey));
	if (retval) {
	    krb5_free_keyblock(context, (*auth_context)->recv_subkey);
	    (*auth_context)->recv_subkey = NULL;
	    goto cleanup;
	}
    } else {
	(*auth_context)->recv_subkey = 0;
	(*auth_context)->send_subkey = 0;
    }
    /* Solaris Kerberos */
    if ((*auth_context)->keyblock != NULL) {
	krb5_free_keyblock(context, (*auth_context)->keyblock);
	(*auth_context)->keyblock = NULL;
    }
    if ((retval = krb5_copy_keyblock(context, req->ticket->enc_part2->session,
				     &((*auth_context)->keyblock))))
	goto cleanup;

    /*
     * If not AP_OPTS_MUTUAL_REQUIRED then and sequence numbers are used
     * then the default sequence number is the one's complement of the
     * sequence number sent ot us.
     */
    if ((!(req->ap_options & AP_OPTS_MUTUAL_REQUIRED)) &&
      (*auth_context)->remote_seq_number) {
	(*auth_context)->local_seq_number ^=
	  (*auth_context)->remote_seq_number;
    }

    if (ticket)
   	if ((retval = krb5_copy_ticket(context, req->ticket, ticket)))
	    goto cleanup;
    if (ap_req_options)
    	*ap_req_options = req->ap_options;
    retval = 0;

cleanup:
    if (server == &princ_data)
	krb5_free_default_realm(context, princ_data.realm.data);
    if (retval) {
	/* only free if we're erroring out...otherwise some
	   applications will need the output. */
	if (req->ticket->enc_part2)
	    krb5_free_enc_tkt_part(context, req->ticket->enc_part2);
	req->ticket->enc_part2 = NULL;
    }
    return retval;
}

krb5_error_code
krb5_rd_req_decoded(krb5_context context, krb5_auth_context *auth_context,
		    const krb5_ap_req *req, krb5_const_principal server,
		    krb5_keytab keytab, krb5_flags *ap_req_options,
		    krb5_ticket **ticket)
{
  krb5_error_code retval;
  retval = krb5_rd_req_decoded_opt(context, auth_context,
				   req, server, keytab,
				   ap_req_options, ticket,
				   1); /* check_valid_flag */
  return retval;
}

krb5_error_code
krb5_rd_req_decoded_anyflag(krb5_context context,
			    krb5_auth_context *auth_context,
			    const krb5_ap_req *req,
			    krb5_const_principal server, krb5_keytab keytab,
			    krb5_flags *ap_req_options, krb5_ticket **ticket)
{
  krb5_error_code retval;
  retval = krb5_rd_req_decoded_opt(context, auth_context,
				   req, server, keytab,
				   ap_req_options, ticket,
				   0); /* don't check_valid_flag */
  return retval;
}

/*ARGSUSED*/
static krb5_error_code
decrypt_authenticator(krb5_context context, const krb5_ap_req *request,
		      krb5_authenticator **authpp, int is_ap_req)
{
    krb5_authenticator *local_auth;
    krb5_error_code retval;
    krb5_data scratch;
    krb5_keyblock *sesskey;

    sesskey = request->ticket->enc_part2->session;

    scratch.length = request->authenticator.ciphertext.length;
    if (!(scratch.data = malloc(scratch.length)))
	return(ENOMEM);

    if ((retval = krb5_c_decrypt(context, sesskey,
				 is_ap_req?KRB5_KEYUSAGE_AP_REQ_AUTH:
				 KRB5_KEYUSAGE_TGS_REQ_AUTH, 0,
				 &request->authenticator, &scratch))) {
	free(scratch.data);
	return(retval);
    }

#define clean_scratch() {memset(scratch.data, 0, scratch.length); \
free(scratch.data);}

    /*  now decode the decrypted stuff */
    if (!(retval = decode_krb5_authenticator(&scratch, &local_auth))) {
	*authpp = local_auth;
    }
    clean_scratch();
    return retval;
}

krb5_error_code
krb5int_check_clockskew(krb5_context context, krb5_timestamp date)
{
    krb5_timestamp currenttime;
    krb5_error_code retval;

    retval = krb5_timeofday(context, &currenttime);
    if (retval)
        return retval;
    if (!(labs((date)-currenttime) < context->clockskew))
        return KRB5KRB_AP_ERR_SKEW;
    return 0;
}
