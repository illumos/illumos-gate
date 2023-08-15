/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * kdc/do_tgs_req.c
 *
 * Copyright 1990,1991,2001 by the Massachusetts Institute of Technology.
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
 * KDC Routines to deal with TGS_REQ's
 */

#include "k5-int.h"
#include "com_err.h"

#include <syslog.h>
#ifdef HAVE_NETINET_IN_H
#include <sys/types.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif
#endif

#include "kdc_util.h"
#include "policy.h"
#include "extern.h"
#include "adm_proto.h"

extern krb5_error_code setup_server_realm(krb5_principal);

static void find_alternate_tgs (krb5_kdc_req *, krb5_db_entry *,
				krb5_boolean *, int *,
		   		const krb5_fulladdr *from, char *cname);

static krb5_error_code prepare_error_tgs (krb5_kdc_req *, krb5_ticket *,
					  int, const char *, krb5_data **,
					  const char *);

/*ARGSUSED*/
krb5_error_code
process_tgs_req(krb5_data *pkt, const krb5_fulladdr *from,
		krb5_data **response)
{
    krb5_keyblock * subkey;
    krb5_kdc_req *request = 0;
    krb5_db_entry server;
    krb5_kdc_rep reply;
    krb5_enc_kdc_rep_part reply_encpart;
    krb5_ticket ticket_reply, *header_ticket = 0;
    int st_idx = 0;
    krb5_enc_tkt_part enc_tkt_reply;
    krb5_transited enc_tkt_transited;
    int newtransited = 0;
    krb5_error_code retval = 0;
    int nprincs = 0;
    krb5_boolean more;
    krb5_timestamp kdc_time, authtime=0;
    krb5_keyblock session_key;
    krb5_timestamp until, rtime;
    krb5_keyblock encrypting_key;
    krb5_key_data  *server_key;
    char *cname = 0, *sname = 0, *tmp = 0;
    const char *fromstring = 0;
    krb5_last_req_entry *nolrarray[2], nolrentry;
/*    krb5_address *noaddrarray[1]; */
    krb5_enctype useenctype;
    int	errcode, errcode2;
    register int i;
    int firstpass = 1;
    const char	*status = 0;
    char ktypestr[128];
    char rep_etypestr[128];
    char fromstringbuf[70];
    long long tmp_server_times, tmp_realm_times;

    (void) memset(&encrypting_key, 0, sizeof(krb5_keyblock));
    (void) memset(&session_key, 0, sizeof(krb5_keyblock));

    retval = decode_krb5_tgs_req(pkt, &request);
    if (retval)
	return retval;

    ktypes2str(ktypestr, sizeof(ktypestr),
	       request->nktypes, request->ktype);
    /*
     * setup_server_realm() sets up the global realm-specific data pointer.
     */
    if ((retval = setup_server_realm(request->server)))
	return retval;

    fromstring = inet_ntop(ADDRTYPE2FAMILY(from->address->addrtype),
			   from->address->contents,
			   fromstringbuf, sizeof(fromstringbuf));
    if (!fromstring)
	fromstring = "<unknown>";

    if ((errcode = krb5_unparse_name(kdc_context, request->server, &sname))) {
	status = "UNPARSING SERVER";
	goto cleanup;
    }
    limit_string(sname);

   /* errcode = kdc_process_tgs_req(request, from, pkt, &req_authdat); */
    errcode = kdc_process_tgs_req(request, from, pkt, &header_ticket, &subkey);

    if (header_ticket && header_ticket->enc_part2 &&
	(errcode2 = krb5_unparse_name(kdc_context,
				      header_ticket->enc_part2->client,
				      &cname))) {
	status = "UNPARSING CLIENT";
	errcode = errcode2;
	goto cleanup;
    }
    limit_string(cname);

    if (errcode) {
	status = "PROCESS_TGS";
	goto cleanup;
    }

    if (!header_ticket) {
	errcode = KRB5_NO_TKT_SUPPLIED;	/* XXX? */
	status="UNEXPECTED NULL in header_ticket";
	goto cleanup;
    }

    /*
     * We've already dealt with the AP_REQ authentication, so we can
     * use header_ticket freely.  The encrypted part (if any) has been
     * decrypted with the session key.
     */

    authtime = header_ticket->enc_part2->times.authtime;

    /* XXX make sure server here has the proper realm...taken from AP_REQ
       header? */

    nprincs = 1;
    if ((errcode = krb5_db_get_principal(kdc_context, request->server, &server,
					&nprincs, &more))) {
	status = "LOOKING_UP_SERVER";
	nprincs = 0;
	goto cleanup;
    }
tgt_again:
    if (more) {
	status = "NON_UNIQUE_PRINCIPAL";
	errcode = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
	goto cleanup;
    } else if (nprincs != 1) {
	/*
	 * might be a request for a TGT for some other realm; we
	 * should do our best to find such a TGS in this db
	 */
	if (firstpass && krb5_is_tgs_principal(request->server) == TRUE) {
	    if (krb5_princ_size(kdc_context, request->server) == 2) {
		krb5_data *server_1 =
		    krb5_princ_component(kdc_context, request->server, 1);
		krb5_data *tgs_1 =
		    krb5_princ_component(kdc_context, tgs_server, 1);

		if (!tgs_1 || server_1->length != tgs_1->length ||
		    memcmp(server_1->data, tgs_1->data, tgs_1->length)) {
		    krb5_db_free_principal(kdc_context, &server, nprincs);
		    find_alternate_tgs(request, &server, &more, &nprincs,
				      from, cname);
		    firstpass = 0;
		    goto tgt_again;
		}
	    }
	}
	krb5_db_free_principal(kdc_context, &server, nprincs);
	status = "UNKNOWN_SERVER";
	errcode = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto cleanup;
    }

    if ((errcode = krb5_timeofday(kdc_context, &kdc_time))) {
	status = "TIME_OF_DAY";
	goto cleanup;
    }

    if ((retval = validate_tgs_request(request, server, header_ticket,
				      kdc_time, &status))) {
	if (!status)
	    status = "UNKNOWN_REASON";
	errcode = retval + ERROR_TABLE_BASE_krb5;
	goto cleanup;
    }

    /*
     * We pick the session keytype here....
     *
     * Some special care needs to be taken in the user-to-user
     * case, since we don't know what keytypes the application server
     * which is doing user-to-user authentication can support.  We
     * know that it at least must be able to support the encryption
     * type of the session key in the TGT, since otherwise it won't be
     * able to decrypt the U2U ticket!  So we use that in preference
     * to anything else.
     */
    useenctype = 0;
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	krb5_keyblock *	st_sealing_key;
	krb5_kvno 	st_srv_kvno;
	krb5_enctype	etype;

	/*
	 * Get the key for the second ticket, and decrypt it.
	 */
	if ((errcode = kdc_get_server_key(request->second_ticket[st_idx],
					 &st_sealing_key,
					 &st_srv_kvno))) {
	    status = "2ND_TKT_SERVER";
	    goto cleanup;
	}
	errcode = krb5_decrypt_tkt_part(kdc_context, st_sealing_key,
				       request->second_ticket[st_idx]);
	krb5_free_keyblock(kdc_context, st_sealing_key);
	if (errcode) {
	    status = "2ND_TKT_DECRYPT";
	    goto cleanup;
	}

	etype = request->second_ticket[st_idx]->enc_part2->session->enctype;
	if (!krb5_c_valid_enctype(etype)) {
	    status = "BAD_ETYPE_IN_2ND_TKT";
	    errcode = KRB5KDC_ERR_ETYPE_NOSUPP;
	    goto cleanup;
	}

	for (i = 0; i < request->nktypes; i++) {
	    if (request->ktype[i] == etype) {
		useenctype = etype;
		break;
	    }
	}
    }

    /*
     * Select the keytype for the ticket session key.
     */
    if ((useenctype == 0) &&
	(useenctype = select_session_keytype(kdc_context, &server,
					     request->nktypes,
					     request->ktype)) == 0) {
	/* unsupported ktype */
	status = "BAD_ENCRYPTION_TYPE";
	errcode = KRB5KDC_ERR_ETYPE_NOSUPP;
	goto cleanup;
    }

    errcode = krb5_c_make_random_key(kdc_context, useenctype, &session_key);

    if (errcode) {
	/* random key failed */
	status = "RANDOM_KEY_FAILED";
	goto cleanup;
    }

    ticket_reply.server = request->server; /* XXX careful for realm... */

    enc_tkt_reply.flags = 0;
    enc_tkt_reply.times.starttime = 0;

    /*
     * Fix header_ticket's starttime; if it's zero, fill in the
     * authtime's value.
     */
    if (!(header_ticket->enc_part2->times.starttime))
	header_ticket->enc_part2->times.starttime =
	    header_ticket->enc_part2->times.authtime;

    /* don't use new addresses unless forwarded, see below */

    enc_tkt_reply.caddrs = header_ticket->enc_part2->caddrs;
    /* noaddrarray[0] = 0; */
    reply_encpart.caddrs = 0;		/* optional...don't put it in */

    /* It should be noted that local policy may affect the  */
    /* processing of any of these flags.  For example, some */
    /* realms may refuse to issue renewable tickets         */

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDABLE);

    if (isflagset(request->kdc_options, KDC_OPT_FORWARDED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

	/* include new addresses in ticket & reply */

	enc_tkt_reply.caddrs = request->addresses;
	reply_encpart.caddrs = request->addresses;
    }
    if (isflagset(header_ticket->enc_part2->flags, TKT_FLG_FORWARDED))
	setflag(enc_tkt_reply.flags, TKT_FLG_FORWARDED);

    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE))
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXIABLE);

    if (isflagset(request->kdc_options, KDC_OPT_PROXY)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_PROXY);

	/* include new addresses in ticket & reply */

	enc_tkt_reply.caddrs = request->addresses;
	reply_encpart.caddrs = request->addresses;
    }

    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE))
	setflag(enc_tkt_reply.flags, TKT_FLG_MAY_POSTDATE);

    if (isflagset(request->kdc_options, KDC_OPT_POSTDATED)) {
	setflag(enc_tkt_reply.flags, TKT_FLG_POSTDATED);
	setflag(enc_tkt_reply.flags, TKT_FLG_INVALID);
	enc_tkt_reply.times.starttime = request->from;
    } else
	enc_tkt_reply.times.starttime = kdc_time;

    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE)) {
	/* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
	   to the caller */
	ticket_reply = *(header_ticket);
	enc_tkt_reply = *(header_ticket->enc_part2);
	clear(enc_tkt_reply.flags, TKT_FLG_INVALID);
    }

    if (isflagset(request->kdc_options, KDC_OPT_RENEW)) {
	krb5_deltat old_life;

	/* BEWARE of allocation hanging off of ticket & enc_part2, it belongs
	   to the caller */
	ticket_reply = *(header_ticket);
	enc_tkt_reply = *(header_ticket->enc_part2);

	old_life = enc_tkt_reply.times.endtime - enc_tkt_reply.times.starttime;

	enc_tkt_reply.times.starttime = kdc_time;
	enc_tkt_reply.times.endtime =
	    min(header_ticket->enc_part2->times.renew_till,
		kdc_time + old_life);
    } else {
	/* not a renew request */
	enc_tkt_reply.times.starttime = kdc_time;
	until = (request->till == 0) ? kdc_infinity : request->till;

	/* SUNW */
        tmp_server_times = (long long) enc_tkt_reply.times.starttime
	  + server.max_life;

        tmp_realm_times = (long long) enc_tkt_reply.times.starttime
	  + max_life_for_realm;

        enc_tkt_reply.times.endtime =
  	  min(until,
	    min(tmp_server_times,
		min(tmp_realm_times,
			min(header_ticket->enc_part2->times.endtime,
			    KRB5_KDB_EXPIRATION)))); /* SUNW */
/*
	enc_tkt_reply.times.endtime =
	    min(until, min(enc_tkt_reply.times.starttime + server.max_life,
			   min(enc_tkt_reply.times.starttime + max_life_for_realm,
			       min(header_ticket->enc_part2->times.endtime)));
*/
	if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE_OK) &&
	    (enc_tkt_reply.times.endtime < request->till) &&
	    isflagset(header_ticket->enc_part2->flags,
		  TKT_FLG_RENEWABLE)) {
	    setflag(request->kdc_options, KDC_OPT_RENEWABLE);
	    request->rtime =
		min(request->till,
		    min(KRB5_KDB_EXPIRATION,
		    header_ticket->enc_part2->times.renew_till));
	}
    }
    rtime = (request->rtime == 0) ? kdc_infinity : request->rtime;

    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) {
	/* already checked above in policy check to reject request for a
	   renewable ticket using a non-renewable ticket */
	setflag(enc_tkt_reply.flags, TKT_FLG_RENEWABLE);
	tmp_realm_times =  (long long) enc_tkt_reply.times.starttime +
		min(server.max_renewable_life,max_renewable_life_for_realm);
	enc_tkt_reply.times.renew_till =
	    min(rtime,
		min(header_ticket->enc_part2->times.renew_till,
				min (tmp_realm_times, KRB5_KDB_EXPIRATION)));
    } else {
	enc_tkt_reply.times.renew_till = 0;
    }

    /*
     * Set authtime to be the same as header_ticket's
     */
    enc_tkt_reply.times.authtime = header_ticket->enc_part2->times.authtime;

    /*
     * Propagate the preauthentication flags through to the returned ticket.
     */
    if (isflagset(header_ticket->enc_part2->flags, TKT_FLG_PRE_AUTH))
	setflag(enc_tkt_reply.flags, TKT_FLG_PRE_AUTH);

    if (isflagset(header_ticket->enc_part2->flags, TKT_FLG_HW_AUTH))
	setflag(enc_tkt_reply.flags, TKT_FLG_HW_AUTH);

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
	enc_tkt_reply.times.starttime = 0;

    /* assemble any authorization data */
    if (request->authorization_data.ciphertext.data) {
	krb5_data scratch;

	scratch.length = request->authorization_data.ciphertext.length;
	if (!(scratch.data =
	      malloc(request->authorization_data.ciphertext.length))) {
	    status = "AUTH_NOMEM";
	    errcode = ENOMEM;
	    goto cleanup;
	}

	if ((errcode = krb5_c_decrypt(kdc_context,
				      header_ticket->enc_part2->session,
				      KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY,
				      0, &request->authorization_data,
				      &scratch))) {
	    status = "AUTH_ENCRYPT_FAIL";
	    free(scratch.data);
	    goto cleanup;
	}

	/* scratch now has the authorization data, so we decode it */
	errcode = decode_krb5_authdata(&scratch, &(request->unenc_authdata));
	free(scratch.data);
	if (errcode) {
	    status = "AUTH_DECODE";
	    goto cleanup;
	}

	if ((errcode =
	     concat_authorization_data(request->unenc_authdata,
				       header_ticket->enc_part2->authorization_data,
				       &enc_tkt_reply.authorization_data))) {
	    status = "CONCAT_AUTH";
	    goto cleanup;
	}
    } else
	enc_tkt_reply.authorization_data =
	    header_ticket->enc_part2->authorization_data;

    enc_tkt_reply.session = &session_key;
    enc_tkt_reply.client = header_ticket->enc_part2->client;
    enc_tkt_reply.transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
    enc_tkt_reply.transited.tr_contents = empty_string; /* equivalent of "" */

    /*
     * Only add the realm of the presented tgt to the transited list if
     * it is different than the local realm (cross-realm) and it is different
     * than the realm of the client (since the realm of the client is already
     * implicitly part of the transited list and should not be explicitly
     * listed).
     */

    /* realm compare is like strcmp, but knows how to deal with these args */
    if (realm_compare(header_ticket->server, tgs_server) ||
	realm_compare(header_ticket->server, enc_tkt_reply.client)) {
	/* tgt issued by local realm or issued by realm of client */
	enc_tkt_reply.transited = header_ticket->enc_part2->transited;
    } else {
	/* tgt issued by some other realm and not the realm of the client */
	/* assemble new transited field into allocated storage */
	if (header_ticket->enc_part2->transited.tr_type !=
	    KRB5_DOMAIN_X500_COMPRESS) {
	    status = "BAD_TRTYPE";
	    errcode = KRB5KDC_ERR_TRTYPE_NOSUPP;
	    goto cleanup;
	}
	enc_tkt_transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
	enc_tkt_transited.magic = 0;
	enc_tkt_transited.tr_contents.magic = 0;
	enc_tkt_transited.tr_contents.data = 0;
	enc_tkt_transited.tr_contents.length = 0;
	enc_tkt_reply.transited = enc_tkt_transited;
	if ((errcode =
	     add_to_transited(&header_ticket->enc_part2->transited.tr_contents,
			      &enc_tkt_reply.transited.tr_contents,
			      header_ticket->server,
			      enc_tkt_reply.client,
			      request->server))) {
	    status = "ADD_TR_FAIL";
	    goto cleanup;
	}
	newtransited = 1;
    }
    if (!isflagset (request->kdc_options, KDC_OPT_DISABLE_TRANSITED_CHECK)) {
	unsigned int tlen;
	char *tdots;

	errcode = krb5_check_transited_list (kdc_context,
					     &enc_tkt_reply.transited.tr_contents,
					     krb5_princ_realm (kdc_context, header_ticket->enc_part2->client),
					     krb5_princ_realm (kdc_context, request->server));
	tlen = enc_tkt_reply.transited.tr_contents.length;
	tdots = tlen > 125 ? "..." : "";
	tlen = tlen > 125 ? 125 : tlen;

	if (errcode == 0) {
	    setflag (enc_tkt_reply.flags, TKT_FLG_TRANSIT_POLICY_CHECKED);
	} else if (errcode == KRB5KRB_AP_ERR_ILL_CR_TKT)
	    krb5_klog_syslog (LOG_INFO,
			      "bad realm transit path from '%s' to '%s' "
			      "via '%.*s%s'",
			      cname ? cname : "<unknown client>",
			      sname ? sname : "<unknown server>",
			      tlen,
			      enc_tkt_reply.transited.tr_contents.data,
			      tdots);
	else {
	    const char *emsg = krb5_get_error_message(kdc_context, errcode);
	    krb5_klog_syslog (LOG_ERR,
			      "unexpected error checking transit from "
			      "'%s' to '%s' via '%.*s%s': %s",
			      cname ? cname : "<unknown client>",
			      sname ? sname : "<unknown server>",
			      tlen,
			      enc_tkt_reply.transited.tr_contents.data,
			      tdots, emsg);
	    krb5_free_error_message(kdc_context, emsg);
	}
    } else
	krb5_klog_syslog (LOG_INFO, "not checking transit path");
    if (reject_bad_transit
	&& !isflagset (enc_tkt_reply.flags, TKT_FLG_TRANSIT_POLICY_CHECKED)) {
	errcode = KRB5KDC_ERR_POLICY;
	status = "BAD_TRANSIT";
	goto cleanup;
    }

    ticket_reply.enc_part2 = &enc_tkt_reply;

    /*
     * If we are doing user-to-user authentication, then make sure
     * that the client for the second ticket matches the request
     * server, and then encrypt the ticket using the session key of
     * the second ticket.
     */
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	/*
	 * Make sure the client for the second ticket matches
	 * requested server.
	 */
	krb5_enc_tkt_part *t2enc = request->second_ticket[st_idx]->enc_part2;
	krb5_principal client2 = t2enc->client;
	if (!krb5_principal_compare(kdc_context, request->server, client2)) {
		if ((errcode = krb5_unparse_name(kdc_context, client2, &tmp)))
			tmp = 0;
		if (tmp != NULL)
		    limit_string(tmp);
		audit_krb5kdc_tgs_req_2ndtktmm(
			(struct in_addr *)from->address->contents,
			(in_port_t)from->port,
			0, cname, sname);
		krb5_klog_syslog(LOG_INFO,
				 "TGS_REQ %s: 2ND_TKT_MISMATCH: "
				 "authtime %d, %s for %s, 2nd tkt client %s",
				 fromstring, authtime,
				 cname ? cname : "<unknown client>",
				 sname ? sname : "<unknown server>",
				 tmp ? tmp : "<unknown>");
		errcode = KRB5KDC_ERR_SERVER_NOMATCH;
		goto cleanup;
	}

	ticket_reply.enc_part.kvno = 0;
	ticket_reply.enc_part.enctype = t2enc->session->enctype;
	if ((errcode = krb5_encrypt_tkt_part(kdc_context, t2enc->session,
					     &ticket_reply))) {
	    status = "2ND_TKT_ENCRYPT";
	    goto cleanup;
	}
	st_idx++;
    } else {
	/*
	 * Find the server key
	 */
	if ((errcode = krb5_dbe_find_enctype(kdc_context, &server,
					     -1, /* ignore keytype */
					     -1, /* Ignore salttype */
					     0,		/* Get highest kvno */
					     &server_key))) {
	    status = "FINDING_SERVER_KEY";
	    goto cleanup;
	}
	/* convert server.key into a real key (it may be encrypted
	 *        in the database) */
	if ((errcode = krb5_dbekd_decrypt_key_data(kdc_context,
						   &master_keyblock,
						   server_key, &encrypting_key,
						   NULL))) {
	    status = "DECRYPT_SERVER_KEY";
	    goto cleanup;
	}
	errcode = krb5_encrypt_tkt_part(kdc_context, &encrypting_key,
					&ticket_reply);
	krb5_free_keyblock_contents(kdc_context, &encrypting_key);
	if (errcode) {
	    status = "TKT_ENCRYPT";
	    goto cleanup;
	}
	ticket_reply.enc_part.kvno = server_key->key_data_kvno;
    }

    /* Start assembling the response */
    reply.msg_type = KRB5_TGS_REP;
    reply.padata = 0;		/* always */
    reply.client = header_ticket->enc_part2->client;
    reply.enc_part.kvno = 0;		/* We are using the session key */
    reply.ticket = &ticket_reply;

    reply_encpart.session = &session_key;
    reply_encpart.nonce = request->nonce;

    /* copy the time fields EXCEPT for authtime; its location
       is used for ktime */
    reply_encpart.times = enc_tkt_reply.times;
    reply_encpart.times.authtime = header_ticket->enc_part2->times.authtime;

    /* starttime is optional, and treated as authtime if not present.
       so we can nuke it if it matches */
    if (enc_tkt_reply.times.starttime == enc_tkt_reply.times.authtime)
	enc_tkt_reply.times.starttime = 0;

    nolrentry.lr_type = KRB5_LRQ_NONE;
    nolrentry.value = 0;
    nolrarray[0] = &nolrentry;
    nolrarray[1] = 0;
    reply_encpart.last_req = nolrarray;	/* not available for TGS reqs */
    reply_encpart.key_exp = 0;		/* ditto */
    reply_encpart.flags = enc_tkt_reply.flags;
    reply_encpart.server = ticket_reply.server;

    /* use the session key in the ticket, unless there's a subsession key
       in the AP_REQ */

    reply.enc_part.enctype = subkey ? subkey->enctype :
		    header_ticket->enc_part2->session->enctype;
    errcode = krb5_encode_kdc_rep(kdc_context, KRB5_TGS_REP, &reply_encpart,
				  subkey ? 1 : 0,
				  subkey ? subkey :
				  header_ticket->enc_part2->session,
				  &reply, response);
    if (errcode) {
	status = "ENCODE_KDC_REP";
    } else {
	status = "ISSUE";
    }

    if (ticket_reply.enc_part.ciphertext.data) {
     memset(ticket_reply.enc_part.ciphertext.data, 0,
	   ticket_reply.enc_part.ciphertext.length);
    free(ticket_reply.enc_part.ciphertext.data);
	ticket_reply.enc_part.ciphertext.data = NULL;
    }
    /* these parts are left on as a courtesy from krb5_encode_kdc_rep so we
       can use them in raw form if needed.  But, we don't... */
    if (reply.enc_part.ciphertext.data) {
     memset(reply.enc_part.ciphertext.data, 0,
	   reply.enc_part.ciphertext.length);
    free(reply.enc_part.ciphertext.data);
	reply.enc_part.ciphertext.data = NULL;
    }

cleanup:
    if (status) {
	const char * emsg = NULL;
	    audit_krb5kdc_tgs_req((struct in_addr *)from->address->contents,
				(in_port_t)from->port, 0,
				cname ? cname : "<unknown client>",
				sname ? sname : "<unknown client>",
				errcode);
	if (!errcode)
	    rep_etypes2str(rep_etypestr, sizeof(rep_etypestr), &reply);
	if (errcode)
	    emsg = krb5_get_error_message (kdc_context, errcode);
	krb5_klog_syslog(LOG_INFO,
			 "TGS_REQ (%s) %s: %s: authtime %d, "
			 "%s%s %s for %s%s%s",
			 ktypestr,
			 fromstring, status, authtime,
			 !errcode ? rep_etypestr : "",
			 !errcode ? "," : "",
			 cname ? cname : "<unknown client>",
			 sname ? sname : "<unknown server>",
			 errcode ? ", " : "",
			 errcode ? emsg : "");
	if (errcode)
	    krb5_free_error_message (kdc_context, emsg);
    }

    if (errcode) {
        int got_err = 0;
	if (status == 0) {
	    status = krb5_get_error_message (kdc_context, errcode);
	    got_err = 1;
	}
	errcode -= ERROR_TABLE_BASE_krb5;
	if (errcode < 0 || errcode > 128)
	    errcode = KRB_ERR_GENERIC;

	retval = prepare_error_tgs(request, header_ticket, errcode,
				   fromstring, response, status);
	if (got_err) {
	    krb5_free_error_message (kdc_context, status);
	    status = 0;
	}
    }

    if (header_ticket)
	krb5_free_ticket(kdc_context, header_ticket);
    if (request)
	krb5_free_kdc_req(kdc_context, request);
    if (cname)
	free(cname);
    if (sname)
	free(sname);
    if (nprincs)
	krb5_db_free_principal(kdc_context, &server, 1);
    if (session_key.contents)
	krb5_free_keyblock_contents(kdc_context, &session_key);
    if (newtransited)
	free(enc_tkt_reply.transited.tr_contents.data);

    return retval;
}

static krb5_error_code
prepare_error_tgs (krb5_kdc_req *request, krb5_ticket *ticket, int error,
		   const char *ident, krb5_data **response, const char *status)
{
    krb5_error errpkt;
    krb5_error_code retval;
    krb5_data *scratch;

    errpkt.ctime = request->nonce;
    errpkt.cusec = 0;

    if ((retval = krb5_us_timeofday(kdc_context, &errpkt.stime,
				    &errpkt.susec)))
	return(retval);
    errpkt.error = error;
    errpkt.server = request->server;
    if (ticket && ticket->enc_part2)
	errpkt.client = ticket->enc_part2->client;
    else
	errpkt.client = 0;
    errpkt.text.length = strlen(status) + 1;
    if (!(errpkt.text.data = malloc(errpkt.text.length)))
	return ENOMEM;
    (void) strcpy(errpkt.text.data, status);

    if (!(scratch = (krb5_data *)malloc(sizeof(*scratch)))) {
	free(errpkt.text.data);
	return ENOMEM;
    }
    errpkt.e_data.length = 0;
    errpkt.e_data.data = 0;

    retval = krb5_mk_error(kdc_context, &errpkt, scratch);
    free(errpkt.text.data);
    if (retval)
	free(scratch);
    else
	*response = scratch;

    return retval;
}

/*
 * The request seems to be for a ticket-granting service somewhere else,
 * but we don't have a ticket for the final TGS.  Try to give the requestor
 * some intermediate realm.
 */
static void
find_alternate_tgs(krb5_kdc_req *request, krb5_db_entry *server,
		   krb5_boolean *more, int *nprincs,
		   const krb5_fulladdr *from, char *cname)
{
    krb5_error_code retval;
    krb5_principal *plist, *pl2;
    krb5_data tmp;

    *nprincs = 0;
    *more = FALSE;

    /*
     * Call to krb5_princ_component is normally not safe but is so
     * here only because find_alternate_tgs() is only called from
     * somewhere that has already checked the number of components in
     * the principal.
     */
    if ((retval = krb5_walk_realm_tree(kdc_context,
		      krb5_princ_realm(kdc_context, request->server),
		      krb5_princ_component(kdc_context, request->server, 1),
				      &plist, KRB5_REALM_BRANCH_CHAR)))
	return;

    /* move to the end */
    for (pl2 = plist; *pl2; pl2++);

    /* the first entry in this array is for krbtgt/local@local, so we
       ignore it */
    while (--pl2 > plist) {
	*nprincs = 1;
	tmp = *krb5_princ_realm(kdc_context, *pl2);
	krb5_princ_set_realm(kdc_context, *pl2,
			     krb5_princ_realm(kdc_context, tgs_server));
	retval = krb5_db_get_principal(kdc_context, *pl2, server, nprincs, more);
	krb5_princ_set_realm(kdc_context, *pl2, &tmp);
	if (retval) {
	    *nprincs = 0;
	    *more = FALSE;
	    krb5_free_realm_tree(kdc_context, plist);
	    return;
	}
	if (*more) {
	    krb5_db_free_principal(kdc_context, server, *nprincs);
	    continue;
	} else if (*nprincs == 1) {
	    /* Found it! */
	    krb5_principal tmpprinc;
	    char *sname;

	    tmp = *krb5_princ_realm(kdc_context, *pl2);
	    krb5_princ_set_realm(kdc_context, *pl2,
				 krb5_princ_realm(kdc_context, tgs_server));
	    if ((retval = krb5_copy_principal(kdc_context, *pl2, &tmpprinc))) {
		krb5_db_free_principal(kdc_context, server, *nprincs);
		krb5_princ_set_realm(kdc_context, *pl2, &tmp);
		continue;
	    }
	    krb5_princ_set_realm(kdc_context, *pl2, &tmp);

	    krb5_free_principal(kdc_context, request->server);
	    request->server = tmpprinc;
	    if (krb5_unparse_name(kdc_context, request->server, &sname)) {

		audit_krb5kdc_tgs_req_alt_tgt(
			(struct in_addr *)from->address->contents,
			(in_port_t)from->port,
			0, cname, "<unparseable>", 0);
		krb5_klog_syslog(LOG_INFO,
		       "TGS_REQ: issuing alternate <un-unparseable> TGT");
	    } else {
		limit_string(sname);
		audit_krb5kdc_tgs_req_alt_tgt(
			(struct in_addr *)from->address->contents,
			(in_port_t)from->port,
			0, cname, sname, 0);
		krb5_klog_syslog(LOG_INFO,
		       "TGS_REQ: issuing TGT %s", sname);
		free(sname);
	    }
	    return;
	}
	krb5_db_free_principal(kdc_context, server, *nprincs);
	continue;
    }

    *nprincs = 0;
    *more = FALSE;
    krb5_free_realm_tree(kdc_context, plist);
    return;
}
