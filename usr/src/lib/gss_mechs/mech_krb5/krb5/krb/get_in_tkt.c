/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * lib/krb5/krb/get_in_tkt.c
 *
 * Copyright 1990,1991, 2003 by the Massachusetts Institute of Technology.
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
 * krb5_get_in_tkt()
 */

#include <string.h>
#include <ctype.h>
#include "k5-int.h"
#include "int-proto.h"
#include "os-proto.h"
#include <locale.h>
#include <syslog.h>

/*
 All-purpose initial ticket routine, usually called via
 krb5_get_in_tkt_with_password or krb5_get_in_tkt_with_skey.

 Attempts to get an initial ticket for creds->client to use server
 creds->server, (realm is taken from creds->client), with options
 options, and using creds->times.starttime, creds->times.endtime,
 creds->times.renew_till as from, till, and rtime.  
 creds->times.renew_till is ignored unless the RENEWABLE option is requested.

 key_proc is called to fill in the key to be used for decryption.
 keyseed is passed on to key_proc.

 decrypt_proc is called to perform the decryption of the response (the
 encrypted part is in dec_rep->enc_part; the decrypted part should be
 allocated and filled into dec_rep->enc_part2
 arg is passed on to decrypt_proc.

 If addrs is non-NULL, it is used for the addresses requested.  If it is
 null, the system standard addresses are used.

 A succesful call will place the ticket in the credentials cache ccache
 and fill in creds with the ticket information used/returned..

 returns system errors, encryption errors

 */

/* Solaris Kerberos */
#define	max(a, b)	((a) > (b) ? (a) : (b))

/* some typedef's for the function args to make things look a bit cleaner */

typedef krb5_error_code (*git_key_proc) (krb5_context,
						   const krb5_enctype,
						   krb5_data *,
						   krb5_const_pointer,
						   krb5_keyblock **);

typedef krb5_error_code (*git_decrypt_proc) (krb5_context,
						       const krb5_keyblock *,
						       krb5_const_pointer,
						       krb5_kdc_rep * );

static krb5_error_code make_preauth_list (krb5_context, 
						    krb5_preauthtype *,
						    int, krb5_pa_data ***);
static krb5_error_code sort_krb5_padata_sequence(krb5_context context,
						 krb5_data *realm,
						 krb5_pa_data **padata);

/*
 * This function performs 32 bit bounded addition so we can generate
 * lifetimes without overflowing krb5_int32
 */
static krb5_int32 krb5int_addint32 (krb5_int32 x, krb5_int32 y)
{
    if ((x > 0) && (y > (KRB5_INT32_MAX - x))) {
        /* sum will be be greater than KRB5_INT32_MAX */
        return KRB5_INT32_MAX;
    } else if ((x < 0) && (y < (KRB5_INT32_MIN - x))) {
        /* sum will be less than KRB5_INT32_MIN */
        return KRB5_INT32_MIN;
    }
    
    return x + y;
}

/*
 * This function sends a request to the KDC, and gets back a response;
 * the response is parsed into ret_err_reply or ret_as_reply if the
 * reponse is a KRB_ERROR or a KRB_AS_REP packet.  If it is some other
 * unexpected response, an error is returned.
 */
static krb5_error_code
send_as_request2(krb5_context 		context,
		krb5_kdc_req		*request,
		krb5_error ** 		ret_err_reply,
		krb5_kdc_rep ** 	ret_as_reply,
		int 			*use_master,
		char			**hostname_used)

{
    krb5_kdc_rep *as_reply = 0;
    krb5_error_code retval;
    krb5_data *packet = 0;
    krb5_data reply;
    char k4_version;		/* same type as *(krb5_data::data) */
    int tcp_only = 0;
    krb5_timestamp time_now;

    reply.data = 0;

    /* Solaris Kerberos (illumos) */
    if (krb5_getenv("MS_INTEROP")) {
        /* Don't bother with UDP. */
        tcp_only = 1;
    }

    /* set the nonce if the caller expects us to do it */
    if (request->nonce == 0) {
        if ((retval = krb5_timeofday(context, &time_now)))
	    goto cleanup;
        request->nonce = (krb5_int32) time_now;
    }

    /* encode & send to KDC */
    if ((retval = encode_krb5_as_req(request, &packet)) != 0)
	goto cleanup;

    k4_version = packet->data[0];
send_again:
    retval = krb5_sendto_kdc2(context, packet, 
			    krb5_princ_realm(context, request->client),
			    &reply, use_master, tcp_only, hostname_used);
    if (retval)
	goto cleanup;

    /* now decode the reply...could be error or as_rep */
    if (krb5_is_krb_error(&reply)) {
	krb5_error *err_reply;

	if ((retval = decode_krb5_error(&reply, &err_reply)))
	    /* some other error code--??? */	    
	    goto cleanup;
    
	if (ret_err_reply) {
	    if (err_reply->error == KRB_ERR_RESPONSE_TOO_BIG
		&& tcp_only == 0) {
		tcp_only = 1;
		krb5_free_error(context, err_reply);
		free(reply.data);
		reply.data = 0;
		goto send_again;
	    }
	    *ret_err_reply = err_reply;
	} else {
	    krb5_free_error(context, err_reply);
	    err_reply = NULL;
	}
	goto cleanup;
    }

    /*
     * Check to make sure it isn't a V4 reply.
     */
    if (!krb5_is_as_rep(&reply)) {
/* these are in <kerberosIV/prot.h> as well but it isn't worth including. */
#define V4_KRB_PROT_VERSION	4
#define V4_AUTH_MSG_ERR_REPLY	(5<<1)
	/* check here for V4 reply */
	unsigned int t_switch;

	/* From v4 g_in_tkt.c: This used to be
	   switch (pkt_msg_type(rpkt) & ~1) {
	   but SCO 3.2v4 cc compiled that incorrectly.  */
	t_switch = reply.data[1];
	t_switch &= ~1;

	if (t_switch == V4_AUTH_MSG_ERR_REPLY
	    && (reply.data[0] == V4_KRB_PROT_VERSION
		|| reply.data[0] == k4_version)) {
	    retval = KRB5KRB_AP_ERR_V4_REPLY;
	} else {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	}
	goto cleanup;
    }

    /* It must be a KRB_AS_REP message, or an bad returned packet */
    if ((retval = decode_krb5_as_rep(&reply, &as_reply)))
	/* some other error code ??? */
	goto cleanup;

    if (as_reply->msg_type != KRB5_AS_REP) {
	retval = KRB5KRB_AP_ERR_MSG_TYPE;
	krb5_free_kdc_rep(context, as_reply);
	goto cleanup;
    }

    if (ret_as_reply)
	*ret_as_reply = as_reply;
    else
	krb5_free_kdc_rep(context, as_reply);

cleanup:
    if (packet)
	krb5_free_data(context, packet);
    if (reply.data)
	free(reply.data);
    return retval;
}

static krb5_error_code
send_as_request(krb5_context 		context,
		krb5_kdc_req		*request,
		krb5_error ** 		ret_err_reply,
		krb5_kdc_rep ** 	ret_as_reply,
		int 			    *use_master)
{
	return send_as_request2(context,
			    request,
			    ret_err_reply,
			    ret_as_reply,
			    use_master,
			    NULL);
}

static krb5_error_code
decrypt_as_reply(krb5_context 		context,
		 krb5_kdc_req		*request,
		 krb5_kdc_rep		*as_reply,
		 git_key_proc 		key_proc,
		 krb5_const_pointer 	keyseed,
		 krb5_keyblock *	key,
		 git_decrypt_proc 	decrypt_proc,
		 krb5_const_pointer 	decryptarg)
{
    krb5_error_code		retval;
    krb5_keyblock *		decrypt_key = 0;
    krb5_data 			salt;
    
    if (as_reply->enc_part2)
	return 0;

    if (key)
	    decrypt_key = key;
    /* Solaris Kerberos */
    else if (request != NULL) {
	if ((retval = krb5_principal2salt(context, request->client, &salt)))
	    return(retval);
    
	retval = (*key_proc)(context, as_reply->enc_part.enctype,
			     &salt, keyseed, &decrypt_key);
	krb5_xfree(salt.data);
	if (retval)
	    goto cleanup;
    } else {
	KRB5_LOG0(KRB5_ERR, "decrypt_as_reply() end, "
		"error key == NULL and request == NULL");
	return (EINVAL);
    }

    /*
     * Solaris kerberos: Overwriting the decrypt_key->enctype because the
     * decrypt key's enctype may not be an exact match with the enctype that the
     * KDC used to encrypt this part of the AS reply.  This assumes the
     * as_reply->enc_part.enctype has been validated which is done by checking
     * to see if the enctype that the KDC sent back in the as_reply is one of
     * the enctypes originally requested.  Note, if request is NULL then the
     * as_reply->enc_part.enctype could not be validated.
     */

    if (request != NULL) {
        if (is_in_keytype(request->ktype, request->nktypes,
                as_reply->enc_part.enctype)) {

	    decrypt_key->enctype = as_reply->enc_part.enctype;

	} else {
	    KRB5_LOG0(KRB5_ERR, "decrypt_as_reply() end, "
		    "error is_in_keytype() returned false");
	    retval = KRB5_BAD_ENCTYPE;
	    goto cleanup;
	}
    }

    if ((retval = (*decrypt_proc)(context, decrypt_key, decryptarg, as_reply))){
	KRB5_LOG(KRB5_ERR, "decrypt_as_reply() error (*decrypt_proc)() retval "
			    "= %d", retval);
	goto cleanup;
    }

cleanup:
    if (!key && decrypt_key)
	krb5_free_keyblock(context, decrypt_key);
    return (retval);
}

static krb5_error_code
verify_as_reply(krb5_context 		context,
		krb5_timestamp 		time_now,
		krb5_kdc_req		*request,
		krb5_kdc_rep		*as_reply)
{
    krb5_error_code		retval;
    
    /* check the contents for sanity: */
    if (!as_reply->enc_part2->times.starttime)
	as_reply->enc_part2->times.starttime =
	    as_reply->enc_part2->times.authtime;
    
    if (!krb5_principal_compare(context, as_reply->client, request->client)
	|| !krb5_principal_compare(context, as_reply->enc_part2->server, request->server)
	|| !krb5_principal_compare(context, as_reply->ticket->server, request->server)
	|| (request->nonce != as_reply->enc_part2->nonce)
	/* XXX check for extraneous flags */
	/* XXX || (!krb5_addresses_compare(context, addrs, as_reply->enc_part2->caddrs)) */
	|| ((request->kdc_options & KDC_OPT_POSTDATED) &&
	    (request->from != 0) &&
	    (request->from != as_reply->enc_part2->times.starttime))
	|| ((request->till != 0) &&
	    (as_reply->enc_part2->times.endtime > request->till))
	|| ((request->kdc_options & KDC_OPT_RENEWABLE) &&
	    /*
	     * Solaris Kerberos: Here we error only if renewable_ok was not set.
	     */
	    !(request->kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    (as_reply->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request->rtime != 0) &&
	    (as_reply->enc_part2->times.renew_till > request->rtime))
	|| ((request->kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    !(request->kdc_options & KDC_OPT_RENEWABLE) &&
	    (as_reply->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request->till != 0) &&
	    (as_reply->enc_part2->times.renew_till > request->till))
	    /*
	     * Solaris Kerberos: renew_till should never be greater than till or
	     * rtime.
	     */
	|| ((request->kdc_options & KDC_OPT_RENEWABLE_OK) &&
	    (as_reply->enc_part2->flags & KDC_OPT_RENEWABLE) &&
	    (request->till != 0) &&
	    (request->rtime != 0) &&
	    (as_reply->enc_part2->times.renew_till > max(request->till,
	     request->rtime)))
	)
	return KRB5_KDCREP_MODIFIED;

    if (context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) {
	retval = krb5_set_real_time(context,
				    as_reply->enc_part2->times.authtime, 0);
	if (retval)
	    return retval;
    } else {
	if ((request->from == 0) &&
	    (labs(as_reply->enc_part2->times.starttime - time_now)
	     > context->clockskew))
	    return (KRB5_KDCREP_SKEW);
    }
    return 0;
}

/*ARGSUSED*/
static krb5_error_code
stash_as_reply(krb5_context 		context,
	       krb5_timestamp 		time_now,
	       krb5_kdc_req		*request,
	       krb5_kdc_rep		*as_reply,
	       krb5_creds * 		creds,
	       krb5_ccache 		ccache)
{
    krb5_error_code 		retval;
    krb5_data *			packet;
    krb5_principal		client;
    krb5_principal		server;

    client = NULL;
    server = NULL;

    if (!creds->client)
        if ((retval = krb5_copy_principal(context, as_reply->client, &client)))
	    goto cleanup;

    if (!creds->server)
	if ((retval = krb5_copy_principal(context, as_reply->enc_part2->server,
					  &server)))
	    goto cleanup;

    /* fill in the credentials */
    if ((retval = krb5_copy_keyblock_contents(context, 
					      as_reply->enc_part2->session,
					      &creds->keyblock)))
	goto cleanup;

    creds->times = as_reply->enc_part2->times;
    creds->is_skey = FALSE;		/* this is an AS_REQ, so cannot
					   be encrypted in skey */
    creds->ticket_flags = as_reply->enc_part2->flags;
    if ((retval = krb5_copy_addresses(context, as_reply->enc_part2->caddrs,
				      &creds->addresses)))
	goto cleanup;

    creds->second_ticket.length = 0;
    creds->second_ticket.data = 0;

    if ((retval = encode_krb5_ticket(as_reply->ticket, &packet)))
	goto cleanup;

    creds->ticket = *packet;
    krb5_xfree(packet);

    /* store it in the ccache! */
    if (ccache) /* Solaris Kerberos */
	if ((retval = krb5_cc_store_cred(context, ccache, creds)) !=0)
	    goto cleanup;

    if (!creds->client)
	creds->client = client;
    if (!creds->server)
	creds->server = server;

cleanup:
    if (retval) {
	if (client)
	    krb5_free_principal(context, client);
	if (server)
	    krb5_free_principal(context, server);
	if (creds->keyblock.contents) {
	    memset((char *)creds->keyblock.contents, 0,
		   creds->keyblock.length);
	    krb5_xfree(creds->keyblock.contents);
	    creds->keyblock.contents = 0;
	    creds->keyblock.length = 0;
	}
	if (creds->ticket.data) {
	    krb5_xfree(creds->ticket.data);
	    creds->ticket.data = 0;
	}
	if (creds->addresses) {
	    krb5_free_addresses(context, creds->addresses);
	    creds->addresses = 0;
	}
    }
    return (retval);
}

/*ARGSUSED*/
static krb5_error_code
make_preauth_list(krb5_context	context,
		  krb5_preauthtype *	ptypes,
		  int			nptypes,
		  krb5_pa_data ***	ret_list)
{
    krb5_preauthtype *		ptypep;
    krb5_pa_data **		preauthp;
    int				i;

    if (nptypes < 0) {
 	for (nptypes=0, ptypep = ptypes; *ptypep; ptypep++, nptypes++)
 	    ;
    }
 
    /* allocate space for a NULL to terminate the list */
 
    if ((preauthp =
 	 (krb5_pa_data **) malloc((nptypes+1)*sizeof(krb5_pa_data *))) == NULL)
 	return(ENOMEM);
 
    for (i=0; i<nptypes; i++) {
 	if ((preauthp[i] =
 	     (krb5_pa_data *) malloc(sizeof(krb5_pa_data))) == NULL) {
 	    for (; i>=0; i++)
 		free(preauthp[i]);
 	    free(preauthp);
	    return (ENOMEM);
	}
 	preauthp[i]->magic = KV5M_PA_DATA;
 	preauthp[i]->pa_type = ptypes[i];
 	preauthp[i]->length = 0;
 	preauthp[i]->contents = 0;
    }
     
    /* fill in the terminating NULL */
 
    preauthp[nptypes] = NULL;
 
    *ret_list = preauthp;
    return 0;
}

#define MAX_IN_TKT_LOOPS 16
static const krb5_enctype get_in_tkt_enctypes[] = {
    ENCTYPE_DES3_CBC_SHA1,
    ENCTYPE_ARCFOUR_HMAC,
    ENCTYPE_DES_CBC_MD5,
    ENCTYPE_DES_CBC_MD4,
    ENCTYPE_DES_CBC_CRC,
    0
};

krb5_error_code KRB5_CALLCONV
krb5_get_in_tkt(krb5_context context,
		const krb5_flags options,
		krb5_address * const * addrs,
		krb5_enctype * ktypes,
		krb5_preauthtype * ptypes,
		git_key_proc key_proc,
		krb5_const_pointer keyseed,
		git_decrypt_proc decrypt_proc,
		krb5_const_pointer decryptarg,
		krb5_creds * creds,
		krb5_ccache ccache,
		krb5_kdc_rep ** ret_as_reply)
{
    krb5_error_code	retval;
    krb5_timestamp	time_now;
    krb5_keyblock *	decrypt_key = 0;
    krb5_kdc_req	request;
    krb5_pa_data	**padata = 0;
    krb5_error *	err_reply;
    krb5_kdc_rep *	as_reply = 0;
    krb5_pa_data  **	preauth_to_use = 0;
    int			loopcount = 0;
    krb5_int32		do_more = 0;
    int             use_master = 0;
    char *hostname_used = NULL;

    if (! krb5_realm_compare(context, creds->client, creds->server)) {
	/* Solaris Kerberos */
	char *s_name = NULL;
	char *c_name = NULL;
	krb5_error_code serr, cerr;
	serr = krb5_unparse_name(context, creds->server, &s_name);
	cerr = krb5_unparse_name(context, creds->client, &c_name);
	krb5_set_error_message(context, KRB5_IN_TKT_REALM_MISMATCH,
			    dgettext(TEXT_DOMAIN,
				    "Client/server realm mismatch in initial ticket request: '%s' requesting ticket '%s'"),
			    cerr ? "unknown" : c_name,
			    serr ? "unknown" : s_name);
	if (s_name)
	    krb5_free_unparsed_name(context, s_name);
	if (c_name)
	    krb5_free_unparsed_name(context, c_name);
	return KRB5_IN_TKT_REALM_MISMATCH;
    }

    if (ret_as_reply)
	*ret_as_reply = 0;
    
    /*
     * Set up the basic request structure
     */
    request.magic = KV5M_KDC_REQ;
    request.msg_type = KRB5_AS_REQ;
    request.addresses = 0;
    request.ktype = 0;
    request.padata = 0;
    if (addrs)
	request.addresses = (krb5_address **) addrs;
    else
	if ((retval = krb5_os_localaddr(context, &request.addresses)))
	    goto cleanup;
    request.kdc_options = options;
    request.client = creds->client;
    request.server = creds->server;
    request.nonce = 0;
    request.from = creds->times.starttime;
    request.till = creds->times.endtime;
    request.rtime = creds->times.renew_till;

    request.ktype = malloc (sizeof(get_in_tkt_enctypes));
    if (request.ktype == NULL) {
	retval = ENOMEM;
	goto cleanup;
    }
    memcpy(request.ktype, get_in_tkt_enctypes, sizeof(get_in_tkt_enctypes));
    for (request.nktypes = 0;request.ktype[request.nktypes];request.nktypes++);
    if (ktypes) {
	int i, req, next = 0;
	for (req = 0; ktypes[req]; req++) {
	    if (ktypes[req] == request.ktype[next]) {
		next++;
		continue;
	    }
	    for (i = next + 1; i < request.nktypes; i++)
		if (ktypes[req] == request.ktype[i]) {
		    /* Found the enctype we want, but not in the
		       position we want.  Move it, but keep the old
		       one from the desired slot around in case it's
		       later in our requested-ktypes list.  */
		    krb5_enctype t;
		    t = request.ktype[next];
		    request.ktype[next] = request.ktype[i];
		    request.ktype[i] = t;
		    next++;
		    break;
		}
	    /* If we didn't find it, don't do anything special, just
	       drop it.  */
	}
	request.ktype[next] = 0;
	request.nktypes = next;
    }
    request.authorization_data.ciphertext.length = 0;
    request.authorization_data.ciphertext.data = 0;
    request.unenc_authdata = 0;
    request.second_ticket = 0;

    /*
     * If a list of preauth types are passed in, convert it to a
     * preauth_to_use list.
     */
    if (ptypes) {
	retval = make_preauth_list(context, ptypes, -1, &preauth_to_use);
	if (retval)
	    goto cleanup;
    }
	    
    while (1) {
	if (loopcount++ > MAX_IN_TKT_LOOPS) {
	    retval = KRB5_GET_IN_TKT_LOOP;
	    /* Solaris Kerberos */
	    {
                char *s_name = NULL;
		char *c_name = NULL;
		krb5_error_code serr, cerr;
		serr = krb5_unparse_name(context, creds->server, &s_name);
		cerr = krb5_unparse_name(context, creds->client, &c_name);
		krb5_set_error_message(context, retval,
				    dgettext(TEXT_DOMAIN,
					    "Looping detected getting ticket: '%s' requesting ticket '%s'. Max loops is %d.  Make sure a KDC is available"),
				    cerr ? "unknown" : c_name,
				    serr ? "unknown" : s_name,
				    MAX_IN_TKT_LOOPS);
		if (s_name)
		    krb5_free_unparsed_name(context, s_name);
		if (c_name)
		    krb5_free_unparsed_name(context, c_name);
	    }
	    goto cleanup;
	}

	if ((retval = krb5_obtain_padata(context, preauth_to_use, key_proc,
					 keyseed, creds, &request)) != 0)
	    goto cleanup;
	if (preauth_to_use)
	    krb5_free_pa_data(context, preauth_to_use);
	preauth_to_use = 0;
	
	err_reply = 0;
	as_reply = 0;

        if ((retval = krb5_timeofday(context, &time_now)))
	    goto cleanup;

        /*
         * XXX we know they are the same size... and we should do
         * something better than just the current time
         */
	request.nonce = (krb5_int32) time_now;

	if ((retval = send_as_request2(context, &request, &err_reply,
				    &as_reply, &use_master,
				    &hostname_used)))
	    goto cleanup;

	if (err_reply) {
	    if (err_reply->error == KDC_ERR_PREAUTH_REQUIRED &&
		err_reply->e_data.length > 0) {
		retval = decode_krb5_padata_sequence(&err_reply->e_data,
						     &preauth_to_use);
		krb5_free_error(context, err_reply);
                err_reply = NULL;
		if (retval)
		    goto cleanup;
                retval = sort_krb5_padata_sequence(context,
						   &request.server->realm,
						   padata);
		if (retval)
		    goto cleanup;
		continue;
	    } else {
		retval = (krb5_error_code) err_reply->error 
		    + ERROR_TABLE_BASE_krb5;
		krb5_free_error(context, err_reply);
                err_reply = NULL;
		goto cleanup;
	    }
	} else if (!as_reply) {
	    retval = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto cleanup;
	}
	if ((retval = krb5_process_padata(context, &request, as_reply,
					  key_proc, keyseed, decrypt_proc, 
					  &decrypt_key, creds,
					  &do_more)) != 0)
	    goto cleanup;

	if (!do_more)
	    break;
    }
    
    if ((retval = decrypt_as_reply(context, &request, as_reply, key_proc,
				   keyseed, decrypt_key, decrypt_proc,
				   decryptarg)))
	goto cleanup;

    if ((retval = verify_as_reply(context, time_now, &request, as_reply)))
	goto cleanup;

    if ((retval = stash_as_reply(context, time_now, &request, as_reply,
				 creds, ccache)))
	goto cleanup;

cleanup:
    if (request.ktype)
	free(request.ktype);
    if (!addrs && request.addresses)
	krb5_free_addresses(context, request.addresses);
    if (request.padata)
	krb5_free_pa_data(context, request.padata);
    if (padata)
	krb5_free_pa_data(context, padata);
    if (preauth_to_use)
	krb5_free_pa_data(context, preauth_to_use);
    if (decrypt_key)
    	krb5_free_keyblock(context, decrypt_key);
    if (as_reply) {
	if (ret_as_reply)
	    *ret_as_reply = as_reply;
	else
	    krb5_free_kdc_rep(context, as_reply);
    }
    if (hostname_used)
        free(hostname_used);

    return (retval);
}

/* begin libdefaults parsing code.  This should almost certainly move
   somewhere else, but I don't know where the correct somewhere else
   is yet. */

/* XXX Duplicating this is annoying; try to work on a better way.*/
static const char *const conf_yes[] = {
    "y", "yes", "true", "t", "1", "on",
    0,
};

static const char *const conf_no[] = {
    "n", "no", "false", "nil", "0", "off",
    0,
};

int
_krb5_conf_boolean(const char *s)
{
    const char *const *p;

    for(p=conf_yes; *p; p++) {
	if (!strcasecmp(*p,s))
	    return 1;
    }

    for(p=conf_no; *p; p++) {
	if (!strcasecmp(*p,s))
	    return 0;
    }

    /* Default to "no" */
    return 0;
}

static krb5_error_code
krb5_libdefault_string(krb5_context context, const krb5_data *realm,
		       const char *option, char **ret_value)
{
    profile_t profile;
    const char *names[5];
    char **nameval = NULL;
    krb5_error_code retval;
    char realmstr[1024];

    if (realm->length > sizeof(realmstr)-1)
	return(EINVAL);

    strncpy(realmstr, realm->data, realm->length);
    realmstr[realm->length] = '\0';

    if (!context || (context->magic != KV5M_CONTEXT)) 
	return KV5M_CONTEXT;

    profile = context->profile;
	    
    /* Solaris Kerberos */
    names[0] = "realms";

    /*
     * Try number one:
     *
     * [realms]
     *		REALM = {
     *			option = <boolean>
     *		}
     */

    names[1] = realmstr;
    names[2] = option;
    names[3] = 0;
    retval = profile_get_values(profile, names, &nameval);
    if (retval == 0 && nameval && nameval[0])
	goto goodbye;

    /*
     * Try number two:
     *
     * [libdefaults]
     *		option = <boolean>
     */
    
    names[0] = "libdefaults";
    names[1] = option;
    names[2] = 0;
    retval = profile_get_values(profile, names, &nameval);
    if (retval == 0 && nameval && nameval[0])
	goto goodbye;

goodbye:
    if (!nameval) 
	return(ENOENT);

    if (!nameval[0]) {
        retval = ENOENT;
    } else {
        *ret_value = malloc(strlen(nameval[0]) + 1);
        if (!*ret_value)
            retval = ENOMEM;
        else
            strcpy(*ret_value, nameval[0]);
    }

    profile_free_list(nameval);

    return retval;
}

/* not static so verify_init_creds() can call it */
/* as well as the DNS code */

krb5_error_code
krb5_libdefault_boolean(krb5_context context, const krb5_data *realm,
			const char *option, int *ret_value)
{
    char *string = NULL;
    krb5_error_code retval;

    retval = krb5_libdefault_string(context, realm, option, &string);

    if (retval)
	return(retval);

    *ret_value = _krb5_conf_boolean(string);
    free(string);

    return(0);
}

/* Sort a pa_data sequence so that types named in the "preferred_preauth_types"
 * libdefaults entry are listed before any others. */
static krb5_error_code
sort_krb5_padata_sequence(krb5_context context, krb5_data *realm,
			  krb5_pa_data **padata)
{
    int i, j, base;
    krb5_error_code ret;
    const char *p;
    long l;
    char *q, *preauth_types = NULL;
    krb5_pa_data *tmp;
    int need_free_string = 1;

    if ((padata == NULL) || (padata[0] == NULL)) {
	return 0;
    }

    ret = krb5_libdefault_string(context, realm, "preferred_preauth_types",
				 &preauth_types);
    if ((ret != 0) || (preauth_types == NULL)) {
	/* Try to use PKINIT first. */
	preauth_types = "17, 16, 15, 14";
	need_free_string = 0;
    }

#ifdef DEBUG
    fprintf (stderr, "preauth data types before sorting:");
    for (i = 0; padata[i]; i++) {
	fprintf (stderr, " %d", padata[i]->pa_type);
    }
    fprintf (stderr, "\n");
#endif

    base = 0;
    for (p = preauth_types; *p != '\0';) {
	/* skip whitespace to find an entry */
	p += strspn(p, ", ");
	if (*p != '\0') {
	    /* see if we can extract a number */
	    l = strtol(p, &q, 10);
	    if ((q != NULL) && (q > p)) {
		/* got a valid number; search for a matchin entry */
		for (i = base; padata[i] != NULL; i++) {
		    /* bubble the matching entry to the front of the list */
		    if (padata[i]->pa_type == l) {
			tmp = padata[i];
			for (j = i; j > base; j--)
			    padata[j] = padata[j - 1];
			padata[base] = tmp;
			base++;
			break;
		    }
		}
		p = q;
	    } else {
		break;
	    }
	}
    }
    if (need_free_string)
	free(preauth_types);

#ifdef DEBUG
    fprintf (stderr, "preauth data types after sorting:");
    for (i = 0; padata[i]; i++)
	fprintf (stderr, " %d", padata[i]->pa_type);
    fprintf (stderr, "\n");
#endif

    return 0;
}

/*
 * Solaris Kerberos
 * Return 1 if any char in string is lower-case.
 */
static int
is_lower_case(char *s)
{
    if (!s)
	return 0;

    while (*s) {
	if (islower((int)*s))
	    return 1;
	s++;
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds(krb5_context context,
		    krb5_creds *creds,
		    krb5_principal client,
		    krb5_prompter_fct prompter,
		    void *prompter_data,
		    krb5_deltat start_time,
		    char *in_tkt_service,
		    krb5_gic_opt_ext *options,
		    krb5_gic_get_as_key_fct gak_fct,
		    void *gak_data,
		    int  *use_master,
		    krb5_kdc_rep **as_reply)
{
    krb5_error_code ret;
    krb5_kdc_req request;
    krb5_data *encoded_request_body, *encoded_previous_request;
    krb5_pa_data **preauth_to_use, **kdc_padata;
    int tempint;
    char *tempstr = NULL;
    krb5_deltat tkt_life;
    krb5_deltat renew_life;
    int loopcount;
    krb5_data salt;
    krb5_data s2kparams;
    krb5_keyblock as_key;
    krb5_error *err_reply = NULL;
    krb5_kdc_rep *local_as_reply;
    krb5_timestamp time_now;
    krb5_enctype etype = 0;
    krb5_preauth_client_rock get_data_rock;
    char *hostname_used = NULL;

    /* initialize everything which will be freed at cleanup */

    s2kparams.data = NULL;
    s2kparams.length = 0;
    request.server = NULL;
    request.ktype = NULL;
    request.addresses = NULL;
    request.padata = NULL;
    encoded_request_body = NULL;
    encoded_previous_request = NULL;
    preauth_to_use = NULL;
    kdc_padata = NULL;
    as_key.length = 0;
    salt.length = 0;
    salt.data = NULL;

    (void) memset(&as_key, 0, sizeof(as_key));

    local_as_reply = 0;

    /*
     * Set up the basic request structure
     */
    request.magic = KV5M_KDC_REQ;
    request.msg_type = KRB5_AS_REQ;

    /* request.nonce is filled in when we send a request to the kdc */
    request.nonce = 0;

    /* request.padata is filled in later */

    request.kdc_options = context->kdc_default_options;

    /* forwardable */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_FORWARDABLE))
	tempint = options->forwardable;
    else if ((ret = krb5_libdefault_boolean(context, &client->realm,
					    "forwardable", &tempint)) == 0)
	/*EMPTY*/
	;
    else
	tempint = 0;
    if (tempint)
	request.kdc_options |= KDC_OPT_FORWARDABLE;

    /* proxiable */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_PROXIABLE))
	tempint = options->proxiable;
    else if ((ret = krb5_libdefault_boolean(context, &client->realm,
					    "proxiable", &tempint)) == 0)
	/*EMPTY*/
	;
    else
	tempint = 0;
    if (tempint)
	request.kdc_options |= KDC_OPT_PROXIABLE;

    /* allow_postdate */
    
    if (start_time > 0)
	request.kdc_options |= (KDC_OPT_ALLOW_POSTDATE|KDC_OPT_POSTDATED);
    
    /* ticket lifetime */
    
    if ((ret = krb5_timeofday(context, &request.from)))
	goto cleanup;
    request.from = krb5int_addint32(request.from, start_time);
    
    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_TKT_LIFE)) {
        tkt_life = options->tkt_life;
    } else if ((ret = krb5_libdefault_string(context, &client->realm,
					     "ticket_lifetime", &tempstr))
	       == 0) {
	ret = krb5_string_to_deltat(tempstr, &tkt_life);
	free(tempstr);
	if (ret) {
	    goto cleanup;
	}
    } else {
	/* this used to be hardcoded in kinit.c */
	tkt_life = 24*60*60;
    }
    request.till = krb5int_addint32(request.from, tkt_life);
    
    /* renewable lifetime */
    
    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE)) {
	renew_life = options->renew_life;
    } else if ((ret = krb5_libdefault_string(context, &client->realm,
					     "renew_lifetime", &tempstr))
	       == 0) {
	ret = krb5_string_to_deltat(tempstr, &renew_life);
	free(tempstr);
	if (ret) {
	    goto cleanup;
	}
    } else {
	renew_life = 0;
    }
    if (renew_life > 0)
	request.kdc_options |= KDC_OPT_RENEWABLE;
    
    if (renew_life > 0) {
	request.rtime = krb5int_addint32(request.from, renew_life);
        if (request.rtime < request.till) {
            /* don't ask for a smaller renewable time than the lifetime */
            request.rtime = request.till;
        }
        /* we are already asking for renewable tickets so strip this option */
	request.kdc_options &= ~(KDC_OPT_RENEWABLE_OK);
    } else {
	request.rtime = 0;
    }
    
    /* client */

    request.client = client;

    /* service */
    
    if (in_tkt_service) {
	/* this is ugly, because so are the data structures involved.  I'm
	   in the library, so I'm going to manipulate the data structures
	   directly, otherwise, it will be worse. */

        if ((ret = krb5_parse_name(context, in_tkt_service, &request.server)))
	    goto cleanup;

	/* stuff the client realm into the server principal.
	   realloc if necessary */
	if (request.server->realm.length < request.client->realm.length)
	    if ((request.server->realm.data =
		 (char *) realloc(request.server->realm.data,
				  request.client->realm.length)) == NULL) {
		ret = ENOMEM;
		goto cleanup;
	    }

	request.server->realm.length = request.client->realm.length;
	memcpy(request.server->realm.data, request.client->realm.data,
	       request.client->realm.length);
    } else {
	if ((ret = krb5_build_principal_ext(context, &request.server,
					   request.client->realm.length,
					   request.client->realm.data,
					   KRB5_TGS_NAME_SIZE,
					   KRB5_TGS_NAME,
					   request.client->realm.length,
					   request.client->realm.data,
					   0)))
	    goto cleanup;
    }

    krb5_preauth_request_context_init(context);

    /* nonce is filled in by send_as_request if we don't take care of it */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST)) {
	request.ktype = options->etype_list;
	request.nktypes = options->etype_list_length;
    } else if ((ret = krb5_get_default_in_tkt_ktypes(context,
						     &request.ktype)) == 0) {
	for (request.nktypes = 0;
	     request.ktype[request.nktypes];
	     request.nktypes++)
	    ;
    } else {
	/* there isn't any useful default here.  ret is set from above */
	goto cleanup;
    }

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST)) {
	request.addresses = options->address_list;
    }
    /* it would be nice if this parsed out an address list, but
       that would be work. */
    else if (((ret = krb5_libdefault_boolean(context, &client->realm,
					    "no_addresses", &tempint)) == 0)
	     || (tempint == 1)) {
	    /*EMPTY*/
	    ;
    } else if (((ret = krb5_libdefault_boolean(context, &client->realm,
					    "noaddresses", &tempint)) == 0)
	     || (tempint == 1)) {
	    /*EMPTY*/
	    ;
    } else {
	if ((ret = krb5_os_localaddr(context, &request.addresses)))
	    goto cleanup;
    }

    request.authorization_data.ciphertext.length = 0;
    request.authorization_data.ciphertext.data = 0;
    request.unenc_authdata = 0;
    request.second_ticket = 0;

    /* set up the other state.  */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST)) {
	if ((ret = make_preauth_list(context, options->preauth_list,
				     options->preauth_list_length,
				     &preauth_to_use)))
	    goto cleanup;
    }

    /* the salt is allocated from somewhere, unless it is from the caller,
       then it is a reference */

    if (options && (options->flags & KRB5_GET_INIT_CREDS_OPT_SALT)) {
	salt = *options->salt;
    } else {
	salt.length = SALT_TYPE_AFS_LENGTH;
	salt.data = NULL;
    }


    /* set the request nonce */
    if ((ret = krb5_timeofday(context, &time_now)))
	goto cleanup;
    /*
     * XXX we know they are the same size... and we should do
     * something better than just the current time
     */
    request.nonce = (krb5_int32) time_now;

    /* give the preauth plugins a chance to prep the request body */
    krb5_preauth_prepare_request(context, options, &request);
    ret = encode_krb5_kdc_req_body(&request, &encoded_request_body);
    if (ret)
        goto cleanup;

    get_data_rock.magic = CLIENT_ROCK_MAGIC;
    get_data_rock.as_reply = NULL;

    /* now, loop processing preauth data and talking to the kdc */
    for (loopcount = 0; loopcount < MAX_IN_TKT_LOOPS; loopcount++) {
	if (request.padata) {
	    krb5_free_pa_data(context, request.padata);
	    request.padata = NULL;
	}
	if (!err_reply) {
            /* either our first attempt, or retrying after PREAUTH_NEEDED */
	    if ((ret = krb5_do_preauth(context,
				       &request,
				       encoded_request_body,
				       encoded_previous_request,
				       preauth_to_use, &request.padata,
				       &salt, &s2kparams, &etype, &as_key,
				       prompter, prompter_data,
				       gak_fct, gak_data,
				       &get_data_rock, options)))
	        goto cleanup;
	} else {
	    if (preauth_to_use != NULL) {
		/*
		 * Retry after an error other than PREAUTH_NEEDED,
		 * using e-data to figure out what to change.
		 */
		ret = krb5_do_preauth_tryagain(context,
					       &request,
					       encoded_request_body,
					       encoded_previous_request,
					       preauth_to_use, &request.padata,
					       err_reply,
					       &salt, &s2kparams, &etype,
					       &as_key,
					       prompter, prompter_data,
					       gak_fct, gak_data,
					       &get_data_rock, options);
	    } else {
		/* No preauth supplied, so can't query the plug-ins. */
		ret = KRB5KRB_ERR_GENERIC;
	    }
	    if (ret) {
		/* couldn't come up with anything better */
		ret = err_reply->error + ERROR_TABLE_BASE_krb5;
	    }
	    krb5_free_error(context, err_reply);
	    err_reply = NULL;
	    if (ret)
		goto cleanup;
	}

        if (encoded_previous_request != NULL) {
	    krb5_free_data(context, encoded_previous_request);
	    encoded_previous_request = NULL;
        }
        ret = encode_krb5_as_req(&request, &encoded_previous_request);
	if (ret)
	    goto cleanup;

	err_reply = NULL;
	local_as_reply = 0;
	if ((ret = send_as_request2(context, &request, &err_reply,
				    &local_as_reply, use_master,
				    &hostname_used)))
	    goto cleanup;

	if (err_reply) {
	    if (err_reply->error == KDC_ERR_PREAUTH_REQUIRED &&
		err_reply->e_data.length > 0) {
		/* reset the list of preauth types to try */
		if (preauth_to_use) {
		    krb5_free_pa_data(context, preauth_to_use);
		    preauth_to_use = NULL;
		}
		ret = decode_krb5_padata_sequence(&err_reply->e_data,
						  &preauth_to_use);
 		krb5_free_error(context, err_reply);
 		err_reply = NULL;
		if (ret)
		    goto cleanup;
		ret = sort_krb5_padata_sequence(context,
						&request.server->realm,
						preauth_to_use);
		if (ret)
		    goto cleanup;
		/* continue to next iteration */
	    } else {
		if (err_reply->e_data.length > 0) {
		    /* continue to next iteration */
		} else {
		    /* error + no hints = give up */
		    ret = (krb5_error_code) err_reply->error
		          + ERROR_TABLE_BASE_krb5;
		    goto cleanup;
		}
	    }
	} else if (local_as_reply) {
	    break;
	} else {
	    ret = KRB5KRB_AP_ERR_MSG_TYPE;
	    goto cleanup;
	}
    }

    if (loopcount == MAX_IN_TKT_LOOPS) {
	ret = KRB5_GET_IN_TKT_LOOP;
	/* Solaris Kerberos */
	{
            char *s_name = NULL;
	    char *c_name = NULL;
	    krb5_error_code serr, cerr;
	    serr = krb5_unparse_name(context, creds->server, &s_name);
	    cerr = krb5_unparse_name(context, creds->client, &c_name);
	    krb5_set_error_message(context, ret,
				dgettext(TEXT_DOMAIN,
					"Looping detected getting initial creds: '%s' requesting ticket '%s'. Max loops is %d.  Make sure a KDC is available"),
				cerr ? "unknown" : c_name,
				serr ? "unknown" : s_name,
				MAX_IN_TKT_LOOPS);
	    if (s_name)
		krb5_free_unparsed_name(context, s_name);
	    if (c_name)
		krb5_free_unparsed_name(context, c_name);
	}
	goto cleanup;
    }

    /* process any preauth data in the as_reply */
    krb5_clear_preauth_context_use_counts(context);
    if ((ret = sort_krb5_padata_sequence(context, &request.server->realm,
					 local_as_reply->padata)))
	goto cleanup;
    get_data_rock.as_reply = local_as_reply;
    if ((ret = krb5_do_preauth(context,
			       &request,
			       encoded_request_body, encoded_previous_request,
			       local_as_reply->padata, &kdc_padata,
			       &salt, &s2kparams, &etype, &as_key, prompter,
			       prompter_data, gak_fct, gak_data,
			       &get_data_rock, options)))
	goto cleanup;

    /* XXX For 1.1.1 and prior KDC's, when SAM is used w/ USE_SAD_AS_KEY,
       the AS_REP comes back encrypted in the user's longterm key
       instead of in the SAD. If there was a SAM preauth, there
       will be an as_key here which will be the SAD. If that fails,
       use the gak_fct to get the password, and try again. */
      
    /* XXX because etypes are handled poorly (particularly wrt SAM,
       where the etype is fixed by the kdc), we may want to try
       decrypt_as_reply twice.  If there's an as_key available, try
       it.  If decrypting the as_rep fails, or if there isn't an
       as_key at all yet, then use the gak_fct to get one, and try
       again.  */

    if (as_key.length)
	ret = decrypt_as_reply(context, NULL, local_as_reply, NULL,
			       NULL, &as_key, krb5_kdc_rep_decrypt_proc,
			       NULL);
    else
	ret = -1;
	   
    if (ret) {
	/* if we haven't get gotten a key, get it now */

	if ((ret = ((*gak_fct)(context, request.client,
			       local_as_reply->enc_part.enctype,
			       prompter, prompter_data, &salt, &s2kparams,
			       &as_key, gak_data))))
	    goto cleanup;

	if ((ret = decrypt_as_reply(context, NULL, local_as_reply, NULL,
				    NULL, &as_key, krb5_kdc_rep_decrypt_proc,
				    NULL)))
	    goto cleanup;
    }

    if ((ret = verify_as_reply(context, time_now, &request, local_as_reply)))
	goto cleanup;

    /* XXX this should be inside stash_as_reply, but as long as
       get_in_tkt is still around using that arg as an in/out, I can't
       do that */
	/* Solaris Kerberos */
	(void) memset(creds, 0, sizeof(*creds));

    /* Solaris Kerberos */
    if ((ret = stash_as_reply(context, time_now, &request, local_as_reply,
			      creds, (krb5_ccache)NULL)))
	goto cleanup;

    /* success */

    ret = 0;

cleanup:
    if (ret != 0) {
        char *client_name = NULL;
        /* See if we can produce a more detailed error message.  */
        switch (ret) {
        case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
            if (krb5_unparse_name(context, client, &client_name) == 0) {
                krb5_set_error_message(context, ret,
                                       dgettext(TEXT_DOMAIN,
						"Client '%s' not found in Kerberos database"),
                                       client_name);
                free(client_name);
            }
            break;
        /* Solaris Kerberos: spruce-up the err msg */
	case KRB5_PREAUTH_FAILED:
	case KRB5KDC_ERR_PREAUTH_FAILED:
            if (krb5_unparse_name(context, client, &client_name) == 0) {
                krb5_set_error_message(context, ret,
				    dgettext(TEXT_DOMAIN,
				      "Client '%s' pre-authentication failed"),
                                       client_name);
                free(client_name);
            }
            break;
	/* Solaris Kerberos: spruce-up the err msg */
	case KRB5KRB_AP_ERR_SKEW: /* KRB_AP_ERR_SKEW + ERROR_TABLE_BASE_krb5 */
	    {
                char *s_name = NULL;
		char *c_name = NULL;
		char stimestring[17];
		char fill = ' ';
		krb5_error_code c_err, s_err, s_time;

		s_err = krb5_unparse_name(context,
					err_reply->server, &s_name);
		s_time = krb5_timestamp_to_sfstring(err_reply->stime,
						    stimestring,
						    sizeof (stimestring),
						    &fill);
		c_err = krb5_unparse_name(context, client, &c_name);
		krb5_set_error_message(context, ret,
				    dgettext(TEXT_DOMAIN,
					    "Clock skew too great: '%s' requesting ticket '%s' from KDC '%s' (%s). Skew is %dm"),
				    c_err == 0 ? c_name : "unknown",
				    s_err == 0 ? s_name : "unknown",
				    hostname_used ? hostname_used : "unknown",
				    s_time == 0 ? stimestring : "unknown",
				    (s_time != 0) ? 0 :
				      (abs(err_reply->stime - time_now) / 60));
		if (s_name)
			krb5_free_unparsed_name(context, s_name);
		if (c_name)
			krb5_free_unparsed_name(context, c_name);
	    }
	    break;
	case KRB5_KDCREP_MODIFIED:
            if (krb5_unparse_name(context, client, &client_name) == 0) {
		/*
		 * Solaris Kerberos
		 * Extra err msg for common(?) case of 
		 * 'kinit user@lower-case-def-realm'.
		 * DNS SRV recs will match (case insensitive) and trigger sendto
		 * KDC and result in this error (at least w/MSFT AD KDC).
		 */
		char *realm = strpbrk(client_name, "@");
		int set = 0;
		if (realm++) {
		    if (realm && realm[0] && is_lower_case(realm)) {
			krb5_set_error_message(context, ret,
					    dgettext(TEXT_DOMAIN,
						    "KDC reply did not match expectations for client '%s': lower-case detected in realm '%s'"),
					    client_name, realm);
			set = 1;
		    }
		}
		if (!set)
		    krb5_set_error_message(context, ret,
					dgettext(TEXT_DOMAIN,
						"KDC reply did not match expectations for client '%s'"),                                 
					client_name);
                free(client_name);
            }
	    break;
        default:
            break;
        }
    }
    if (err_reply)
	    krb5_free_error(context, err_reply);
    krb5_preauth_request_context_fini(context);
    if (encoded_previous_request != NULL) {
	krb5_free_data(context, encoded_previous_request);
	encoded_previous_request = NULL;
    }
    if (encoded_request_body != NULL) {
	krb5_free_data(context, encoded_request_body);
	encoded_request_body = NULL;
    }
    if (request.server)
	krb5_free_principal(context, request.server);
    if (request.ktype &&
	(!(options && (options->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST))))
	free(request.ktype);
    if (request.addresses &&
	(!(options &&
	   (options->flags & KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST))))
	krb5_free_addresses(context, request.addresses);
    if (preauth_to_use)
	krb5_free_pa_data(context, preauth_to_use);
    if (kdc_padata)
	krb5_free_pa_data(context, kdc_padata);
    if (request.padata)
	krb5_free_pa_data(context, request.padata);
    if (as_key.length)
	krb5_free_keyblock_contents(context, &as_key);
    if (salt.data &&
	(!(options && (options->flags & KRB5_GET_INIT_CREDS_OPT_SALT))))
	krb5_xfree(salt.data);
    krb5_free_data_contents(context, &s2kparams);
    if (as_reply)
	*as_reply = local_as_reply;
    else if (local_as_reply)
	krb5_free_kdc_rep(context, local_as_reply);
    if (hostname_used)
        free(hostname_used);
    return(ret);
}
