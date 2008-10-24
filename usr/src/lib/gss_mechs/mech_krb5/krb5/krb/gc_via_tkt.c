/*
 * lib/krb5/krb/gc_via_tgt.c
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
 * Given a tkt, and a target cred, get it.
 * Assumes that the kdc_rep has been decrypted.
 */

#include "k5-int.h"
#include "int-proto.h"

#define in_clock_skew(date, now) (labs((date)-(now)) < context->clockskew)

#define IS_TGS_PRINC(c, p)				\
    ((krb5_princ_size((c), (p)) == 2) &&		\
     (krb5_princ_component((c), (p), 0)->length ==	\
      KRB5_TGS_NAME_SIZE) &&				\
     (!memcmp(krb5_princ_component((c), (p), 0)->data,	\
	      KRB5_TGS_NAME, KRB5_TGS_NAME_SIZE)))

static krb5_error_code
krb5_kdcrep2creds(krb5_context context, krb5_kdc_rep *pkdcrep, krb5_address *const *address, krb5_data *psectkt, krb5_creds **ppcreds)
{
    krb5_error_code retval;  
    krb5_data *pdata;
  
    if ((*ppcreds = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL) {
        return ENOMEM;
    }

    memset(*ppcreds, 0, sizeof(krb5_creds));

    if ((retval = krb5_copy_principal(context, pkdcrep->client,
                                     &(*ppcreds)->client)))
        goto cleanup;

    if ((retval = krb5_copy_principal(context, pkdcrep->enc_part2->server,
				      &(*ppcreds)->server)))
        goto cleanup;

    if ((retval = krb5_copy_keyblock_contents(context, 
					      pkdcrep->enc_part2->session,
					      &(*ppcreds)->keyblock)))
        goto cleanup;

    if ((retval = krb5_copy_data(context, psectkt, &pdata)))
	goto cleanup;
    (*ppcreds)->second_ticket = *pdata;
    krb5_xfree(pdata);

    (*ppcreds)->ticket_flags = pkdcrep->enc_part2->flags;
    (*ppcreds)->times = pkdcrep->enc_part2->times;
    (*ppcreds)->magic = KV5M_CREDS;

    (*ppcreds)->authdata = NULL;   			/* not used */
    (*ppcreds)->is_skey = psectkt->length != 0;

    if (pkdcrep->enc_part2->caddrs) {
	if ((retval = krb5_copy_addresses(context, pkdcrep->enc_part2->caddrs,
					  &(*ppcreds)->addresses)))
	    goto cleanup_keyblock;
    } else {
	/* no addresses in the list means we got what we had */
	if ((retval = krb5_copy_addresses(context, address,
					  &(*ppcreds)->addresses)))
	    goto cleanup_keyblock;
    }

    if ((retval = encode_krb5_ticket(pkdcrep->ticket, &pdata)))
	goto cleanup_keyblock;

    (*ppcreds)->ticket = *pdata;
    free(pdata);
    return 0;

cleanup_keyblock:
    krb5_free_keyblock(context, &(*ppcreds)->keyblock);

cleanup:
    free (*ppcreds);
    return retval;
}
 
static krb5_error_code
check_reply_server(krb5_context context, krb5_flags kdcoptions,
		   krb5_creds *in_cred, krb5_kdc_rep *dec_rep)
{

    if (!krb5_principal_compare(context, dec_rep->ticket->server,
				dec_rep->enc_part2->server))
	return KRB5_KDCREP_MODIFIED;

    /* Reply is self-consistent. */

    if (krb5_principal_compare(context, dec_rep->ticket->server,
			       in_cred->server))
	return 0;

    /* Server in reply differs from what we requested. */

    if (kdcoptions & KDC_OPT_CANONICALIZE) {
	/* in_cred server differs from ticket returned, but ticket
	   returned is consistent and we requested canonicalization. */
#if 0
#ifdef DEBUG_REFERRALS
	printf("gc_via_tkt: in_cred and encoding don't match but referrals requested\n");
	krb5int_dbgref_dump_principal("gc_via_tkt: in_cred",in_cred->server);
	krb5int_dbgref_dump_principal("gc_via_tkt: encoded server",dec_rep->enc_part2->server);
#endif
#endif
	return 0;
    }

    /* We didn't request canonicalization. */

    if (!IS_TGS_PRINC(context, in_cred->server) ||
	!IS_TGS_PRINC(context, dec_rep->ticket->server)) {
	/* Canonicalization not requested, and not a TGS referral. */
	return KRB5_KDCREP_MODIFIED;
    }
#if 0
    /*
     * Is this check needed?  find_nxt_kdc() in gc_frm_kdc.c already
     * effectively checks this.
     */
    if (krb5_realm_compare(context, in_cred->client, in_cred->server) &&
	in_cred->server->data[1].length == in_cred->client->realm.length &&
	!memcmp(in_cred->client->realm.data, in_cred->server->data[1].data,
		in_cred->client->realm.length)) {
	/* Attempted to rewrite local TGS. */
	return KRB5_KDCREP_MODIFIED;
    }
#endif
    return 0;
}

krb5_error_code
krb5_get_cred_via_tkt (krb5_context context, krb5_creds *tkt,
		       krb5_flags kdcoptions, krb5_address *const *address,
		       krb5_creds *in_cred, krb5_creds **out_cred)
{
    krb5_error_code retval;
    krb5_kdc_rep *dec_rep;
    krb5_error *err_reply;
    krb5_response tgsrep;
    krb5_enctype *enctypes = 0;

#ifdef DEBUG_REFERRALS
    printf("krb5_get_cred_via_tkt starting; referral flag is %s\n", kdcoptions&KDC_OPT_CANONICALIZE?"on":"off");
    krb5int_dbgref_dump_principal("krb5_get_cred_via_tkt requested ticket", in_cred->server);
    krb5int_dbgref_dump_principal("krb5_get_cred_via_tkt TGT in use", tkt->server);
#endif

    /* tkt->client must be equal to in_cred->client */
    if (!krb5_principal_compare(context, tkt->client, in_cred->client))
	return KRB5_PRINC_NOMATCH;

    if (!tkt->ticket.length)
	return KRB5_NO_TKT_SUPPLIED;

    if ((kdcoptions & KDC_OPT_ENC_TKT_IN_SKEY) && 
	(!in_cred->second_ticket.length))
        return(KRB5_NO_2ND_TKT);


    /* check if we have the right TGT                    */
    /* tkt->server must be equal to                      */
    /* krbtgt/realmof(cred->server)@realmof(tgt->server) */
/*
    {
    krb5_principal tempprinc;
        if (retval = krb5_tgtname(context, 
		     krb5_princ_realm(context, in_cred->server),
		     krb5_princ_realm(context, tkt->server), &tempprinc))
    	    return(retval);

        if (!krb5_principal_compare(context, tempprinc, tkt->server)) {
            krb5_free_principal(context, tempprinc);
	    return (KRB5_PRINC_NOMATCH);
        }
    krb5_free_principal(context, tempprinc);
    }
*/

    if (in_cred->keyblock.enctype) {
	enctypes = (krb5_enctype *) malloc(sizeof(krb5_enctype)*2);
	if (!enctypes)
	    return ENOMEM;
	enctypes[0] = in_cred->keyblock.enctype;
	enctypes[1] = 0;
    }
    
    retval = krb5_send_tgs(context, kdcoptions, &in_cred->times, enctypes, 
			   in_cred->server, address, in_cred->authdata,
			   0,		/* no padata */
			   (kdcoptions & KDC_OPT_ENC_TKT_IN_SKEY) ? 
			   &in_cred->second_ticket : NULL,
			   tkt, &tgsrep);
    if (enctypes)
	free(enctypes);
    if (retval) {
#ifdef DEBUG_REFERRALS
        printf("krb5_get_cred_via_tkt ending early after send_tgs with: %s\n",
	       error_message(retval));
#endif
	return retval;
    }

    switch (tgsrep.message_type) {
    case KRB5_TGS_REP:
	break;
    case KRB5_ERROR:
    default:
	if (krb5_is_krb_error(&tgsrep.response))
	    retval = decode_krb5_error(&tgsrep.response, &err_reply);
	else
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;

	if (retval)			/* neither proper reply nor error! */
	    goto error_4;

	retval = (krb5_error_code) err_reply->error + ERROR_TABLE_BASE_krb5;
	if (err_reply->text.length > 0) {
#if 0
	    const char *m;
#endif
	    switch (err_reply->error) {
	    case KRB_ERR_GENERIC:
		krb5_set_error_message(context, retval,
				       "KDC returned error string: %s",
				       err_reply->text.data);
		break;
	    default:
#if 0 /* We should stop the KDC from sending back this text, because
	 if the local language doesn't match the KDC's language, we'd
	 just wind up printing out the error message in two languages.
	 Well, when we get some localization.  Which is already
	 happening in KfM.  */
		m = error_message(retval);
		/* Special case: MIT KDC may return this same string
		   in the e-text field.  */
		if (strlen (m) == err_reply->text.length-1
		    && !strcmp(m, err_reply->text.data))
		    break;
		krb5_set_error_message(context, retval,
				       "%s (KDC supplied additional data: %s)",
				       m, err_reply->text.data);
#endif
		break;
	    }
	}

	krb5_free_error(context, err_reply);
	goto error_4;
    }

    if ((retval = krb5_decode_kdc_rep(context, &tgsrep.response,
				      &tkt->keyblock, &dec_rep)))
	goto error_4;

    if (dec_rep->msg_type != KRB5_TGS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	goto error_3;
    }
   
    /* make sure the response hasn't been tampered with..... */
    retval = 0;

    if (!krb5_principal_compare(context, dec_rep->client, tkt->client))
	retval = KRB5_KDCREP_MODIFIED;

    if (retval == 0)
	retval = check_reply_server(context, kdcoptions, in_cred, dec_rep);

    if (dec_rep->enc_part2->nonce != tgsrep.expected_nonce)
	retval = KRB5_KDCREP_MODIFIED;

    if ((kdcoptions & KDC_OPT_POSTDATED) &&
	(in_cred->times.starttime != 0) &&
    	(in_cred->times.starttime != dec_rep->enc_part2->times.starttime))
	retval = KRB5_KDCREP_MODIFIED;

    if ((in_cred->times.endtime != 0) &&
	(dec_rep->enc_part2->times.endtime > in_cred->times.endtime))
	retval = KRB5_KDCREP_MODIFIED;

    if ((kdcoptions & KDC_OPT_RENEWABLE) &&
	(in_cred->times.renew_till != 0) &&
	(dec_rep->enc_part2->times.renew_till > in_cred->times.renew_till))
	retval = KRB5_KDCREP_MODIFIED;

    if ((kdcoptions & KDC_OPT_RENEWABLE_OK) &&
	(dec_rep->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	(in_cred->times.endtime != 0) &&
	(dec_rep->enc_part2->times.renew_till > in_cred->times.endtime))
 	retval = KRB5_KDCREP_MODIFIED;

    if (retval != 0)
    	goto error_3;

    if (!in_cred->times.starttime &&
	!in_clock_skew(dec_rep->enc_part2->times.starttime,
		       tgsrep.request_time)) {
	retval = KRB5_KDCREP_SKEW;
	goto error_3;
    }
    
    retval = krb5_kdcrep2creds(context, dec_rep, address, 
			       &in_cred->second_ticket,  out_cred);

error_3:;
    memset(dec_rep->enc_part2->session->contents, 0,
	   dec_rep->enc_part2->session->length);
    krb5_free_kdc_rep(context, dec_rep);

error_4:;
    free(tgsrep.response.data);
#ifdef DEBUG_REFERRALS
    printf("krb5_get_cred_via_tkt ending; %s\n", retval?error_message(retval):"no error");
#endif
    return retval;
}
