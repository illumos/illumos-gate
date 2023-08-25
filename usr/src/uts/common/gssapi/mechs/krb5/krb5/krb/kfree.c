/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Copyright 1990-1998 by the Massachusetts Institute of Technology.
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
 * krb5_free_address()
 */

#include "k5-int.h"

static void cleanup_dk_list(krb5_context, krb5_keyblock *);

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_address(krb5_context context, krb5_address *val)
{
    if (val->contents)
	krb5_xfree_wrap(val->contents, val->length);
    krb5_xfree_wrap(val, sizeof(krb5_address));
}

#ifndef _KERNEL
void KRB5_CALLCONV
krb5_free_addresses(krb5_context context, krb5_address **val)
{
    register krb5_address **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    krb5_xfree((*temp)->contents);
	krb5_xfree(*temp);
    }
    krb5_xfree(val);
}


void KRB5_CALLCONV
krb5_free_ap_rep(krb5_context context, register krb5_ap_rep *val)
{
    if (val->enc_part.ciphertext.data) {
	krb5_xfree(val->enc_part.ciphertext.data);
	val->enc_part.ciphertext.data = 0;
    }
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_ap_req(krb5_context context, register krb5_ap_req *val)
{
    if (val->ticket) {
	krb5_free_ticket(context, val->ticket);
	val->ticket = 0;
    }
    if (val->authenticator.ciphertext.data) {
	krb5_xfree(val->authenticator.ciphertext.data);
	val->authenticator.ciphertext.data = 0;
    }
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_ap_rep_enc_part(krb5_context context, krb5_ap_rep_enc_part *val)
{
    if (val->subkey)
	krb5_free_keyblock(context, val->subkey);
    krb5_xfree(val);
}
#endif	/* !_KERNEL */

void KRB5_CALLCONV
krb5_free_authenticator_contents(krb5_context context, krb5_authenticator *val)
{
    if (val->checksum) {
	krb5_free_checksum(context, val->checksum);
	val->checksum = 0;
    }
    if (val->client) {
	krb5_free_principal(context, val->client);
	val->client = 0;
    }
    if (val->subkey) {
	krb5_free_keyblock(context, val->subkey);
	val->subkey = 0;
    }
    if (val->authorization_data) {
	krb5_free_authdata(context, val->authorization_data);
	val->authorization_data = 0;
    }
}

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_authdata(krb5_context context, krb5_authdata **val)
{
    register krb5_authdata **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    krb5_xfree_wrap((*temp)->contents, (*temp)->length);
	krb5_xfree_wrap(*temp, sizeof(krb5_authdata));
    }
    /* Note val points to an array of pointers and (++temp - val) is # of bytes
     * in that array.
     */
    krb5_xfree_wrap(val, (++temp - val));
}

void KRB5_CALLCONV
krb5_free_authenticator(krb5_context context, krb5_authenticator *val)
{
    krb5_free_authenticator_contents(context, val);
    krb5_xfree_wrap(val, sizeof(krb5_authenticator));
}

void KRB5_CALLCONV
krb5_free_checksum(krb5_context context, register krb5_checksum *val)
{
    krb5_free_checksum_contents(context, val);
    krb5_xfree_wrap(val, sizeof(krb5_checksum));
}

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_checksum_contents(krb5_context context, register krb5_checksum *val)
{
    if (val->contents) {
	krb5_xfree_wrap(val->contents, val->length);
	val->length = 0;
	val->contents = 0;
    }
}

#ifndef _KERNEL
void KRB5_CALLCONV
krb5_free_cred(krb5_context context, register krb5_cred *val)
{
    if (val->tickets) {
        krb5_free_tickets(context, val->tickets);
	val->tickets = 0;
    }
    if (val->enc_part.ciphertext.data) {
	krb5_xfree(val->enc_part.ciphertext.data);
	val->enc_part.ciphertext.data = 0;
    }
    krb5_xfree(val);
}

/*
 * krb5_free_cred_contents zeros out the session key, and then frees
 * the credentials structures
 */

void KRB5_CALLCONV
krb5_free_cred_contents(krb5_context context, krb5_creds *val)
{
    if (val->client) {
	krb5_free_principal(context, val->client);
	val->client = 0;
    }
    if (val->server) {
	krb5_free_principal(context, val->server);
	val->server = 0;
    }

    krb5_free_keyblock_contents(context, &val->keyblock);

    if (val->ticket.data) {
	krb5_xfree(val->ticket.data);
	val->ticket.data = 0;
    }
    if (val->second_ticket.data) {
	krb5_xfree(val->second_ticket.data);
	val->second_ticket.data = 0;
    }
    if (val->addresses) {
	krb5_free_addresses(context, val->addresses);
	val->addresses = 0;
    }
    if (val->authdata) {
	krb5_free_authdata(context, val->authdata);
	val->authdata = 0;
    }
}

void KRB5_CALLCONV
krb5_free_cred_enc_part(krb5_context context, register krb5_cred_enc_part *val)
{
    register krb5_cred_info **temp;

    if (val->r_address) {
	krb5_free_address(context, val->r_address);
	val->r_address = 0;
    }
    if (val->s_address) {
	krb5_free_address(context, val->s_address);
	val->s_address = 0;
    }

    if (val->ticket_info) {
	for (temp = val->ticket_info; *temp; temp++) {
	    if ((*temp)->session)
		krb5_free_keyblock(context, (*temp)->session);
	    if ((*temp)->client)
		krb5_free_principal(context, (*temp)->client);
	    if ((*temp)->server)
		krb5_free_principal(context, (*temp)->server);
	    if ((*temp)->caddrs)
		krb5_free_addresses(context, (*temp)->caddrs);
	    krb5_xfree((*temp));
	}
	krb5_xfree(val->ticket_info);
	val->ticket_info = 0;
    }
}


void KRB5_CALLCONV
krb5_free_creds(krb5_context context, krb5_creds *val)
{
    krb5_free_cred_contents(context, val);
    krb5_xfree(val);
}

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_data(krb5_context context, krb5_data *val)
{
    if (val->data) {
	krb5_xfree(val->data);
	val->data = 0;
    }
    krb5_xfree(val);
}
#endif	/* !_KERNEL */

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_data_contents(krb5_context context, krb5_data *val)
{
    if (val->data) {
	krb5_xfree_wrap(val->data, val->length);
	val->length = 0;
        val->data = 0;
    }
}

#ifndef _KERNEL
void krb5_free_etype_info(krb5_context context, krb5_etype_info info)
{
  int i;

  for(i=0; info[i] != NULL; i++) {
      if (info[i]->salt)
	  free(info[i]->salt);
      krb5_free_data_contents(context, &info[i]->s2kparams);
      free(info[i]);
  }
  free(info);
}


void KRB5_CALLCONV
krb5_free_enc_kdc_rep_part(krb5_context context, register krb5_enc_kdc_rep_part *val)
{
    if (val->session)
	krb5_free_keyblock(context, val->session);
    if (val->last_req)
	krb5_free_last_req(context, val->last_req);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->caddrs)
	krb5_free_addresses(context, val->caddrs);
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_enc_tkt_part(krb5_context context, krb5_enc_tkt_part *val)
{
    if (val->session) {
	krb5_free_keyblock(context, val->session);
	val->session = 0;
    }
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->transited.tr_contents.data) {
	krb5_xfree(val->transited.tr_contents.data);
	val->transited.tr_contents.data = 0;
    }
    if (val->caddrs)
	krb5_free_addresses(context, val->caddrs);
    if (val->authorization_data) {
	krb5_free_authdata(context, val->authorization_data);
	val->authorization_data = 0;
    }
    krb5_xfree(val);
}
#endif	/* !_KERNEL */

void KRB5_CALLCONV
krb5_free_error(krb5_context context, register krb5_error *val)
{
    if (val->client)
	krb5_free_principal(context, val->client);
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->text.data)
	krb5_xfree_wrap(val->text.data, val->text.length);
    if (val->e_data.data)
	krb5_xfree_wrap(val->e_data.data, val->e_data.length);
    krb5_xfree_wrap(val, sizeof (krb5_error));
}

#ifndef _KERNEL
void KRB5_CALLCONV
krb5_free_kdc_rep(krb5_context context, krb5_kdc_rep *val)
{
    if (val->padata) {
	krb5_free_pa_data(context, val->padata);
	val->padata = 0;
    }
    if (val->client) {
	krb5_free_principal(context, val->client);
	val->client = 0;
    }
    if (val->ticket) {
	krb5_free_ticket(context, val->ticket);
	val->ticket = 0;
    }
    if (val->enc_part.ciphertext.data) {
	krb5_xfree(val->enc_part.ciphertext.data);
	val->enc_part.ciphertext.data = 0;
    }
    if (val->enc_part2) {
	krb5_free_enc_kdc_rep_part(context, val->enc_part2);
	val->enc_part2 = 0;
    }
    krb5_xfree(val);
}


void KRB5_CALLCONV
krb5_free_kdc_req(krb5_context context, krb5_kdc_req *val)
{
    if (val->padata) {
	krb5_free_pa_data(context, val->padata);
	val->padata = 0;
    }
    if (val->client) {
	krb5_free_principal(context, val->client);
	val->client = 0;
    }
    if (val->server) {
	krb5_free_principal(context, val->server);
	val->server = 0;
    }
    if (val->ktype) {
	krb5_xfree(val->ktype);
	val->ktype = 0;
    }
    if (val->addresses) {
	krb5_free_addresses(context, val->addresses);
	val->addresses = 0;
    }
    if (val->authorization_data.ciphertext.data) {
	krb5_xfree(val->authorization_data.ciphertext.data);
	val->authorization_data.ciphertext.data = 0;
    }
    if (val->unenc_authdata) {
	krb5_free_authdata(context, val->unenc_authdata);
	val->unenc_authdata = 0;
    }
    if (val->second_ticket) {
	krb5_free_tickets(context, val->second_ticket);
	val->second_ticket = 0;
    }
    krb5_xfree(val);
}
#endif	/* !_KERNEL */

/*
 * Delete a key's derived key list
 */
static void
cleanup_dk_list(krb5_context context, krb5_keyblock *key)
{
	krb5_dk_node *dn = key->dk_list;
	krb5_dk_node *nxt;

	while (dn != NULL) {
		nxt = dn->next;

		if (dn->derived_key != NULL) {
			/*
			 * Some recursion here but its OK,
			 * it stops when a NULL dk_list
			 * is encountered.
			 */
			krb5_free_keyblock(context, dn->derived_key);
			dn->derived_key = NULL;
		}

		FREE(dn, sizeof(krb5_dk_node));

		dn = nxt;
	}
	key->dk_list = NULL;
}

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_keyblock_contents(krb5_context context, register krb5_keyblock *key)
{
     if (key->contents) {
	  (void) memset(key->contents, 0, key->length);
	  krb5_xfree_wrap(key->contents, key->length);
	  key->length = 0;
	  key->contents = 0;
     }
#ifdef _KERNEL
     if (key->key_tmpl != NULL)
	(void) crypto_destroy_ctx_template(key->key_tmpl);
#else
     if (key->hKey != CK_INVALID_HANDLE) {
	CK_RV rv;
	rv = C_DestroyObject(krb_ctx_hSession(context), key->hKey);
	if (rv != CKR_OK) {
		KRB5_LOG(KRB5_ERR, "krb5_free_keyblock_contents: "
			"C_DestroyObject = %0x", rv);
	}
	key->hKey = CK_INVALID_HANDLE;
     }
#endif /* _KERNEL */
     /*
      * If the original key data is freed, we should also free
      * any keys derived from that data.
      * This saves us from making additional calls to "cleanup_dk_list"
      * in all of the many function which have keyblock structures
      * declared on the stack that re-use the keyblock data contents
      * without freeing the entire keyblock record.
      */
     cleanup_dk_list(context, key);
}

void KRB5_CALLCONV
krb5_free_keyblock(krb5_context context, register krb5_keyblock *val)
{
    if (!val)
        return;

    krb5_free_keyblock_contents(context, val);

    krb5_xfree_wrap(val, sizeof(krb5_keyblock));
}

#ifndef _KERNEL
void KRB5_CALLCONV
krb5_free_last_req(krb5_context context, krb5_last_req_entry **val)
{
    register krb5_last_req_entry **temp;

    for (temp = val; *temp; temp++)
	krb5_xfree(*temp);
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_pa_data(krb5_context context, krb5_pa_data **val)
{
    register krb5_pa_data **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->contents)
	    krb5_xfree((*temp)->contents);
	krb5_xfree(*temp);
    }
    krb5_xfree(val);
}
#endif	/* !_KERNEL */

/* ARGSUSED */
void KRB5_CALLCONV
krb5_free_principal(krb5_context context, krb5_principal val)
{
    register krb5_int32 i;

    if (!val)
	return;

    if (val->data) {
	i = krb5_princ_size(context, val);
	while(--i >= 0)
            FREE(krb5_princ_component(context, val, i)->data,
                krb5_princ_component(context, val, i)->length+1);
	krb5_xfree_wrap(val->data,
		sizeof(krb5_data) * krb5_princ_size(context, val));
    }
    if (val->realm.data)
	krb5_xfree_wrap(val->realm.data, val->realm.length+1);
    krb5_xfree_wrap(val, sizeof (krb5_principal_data));
}

#ifndef _KERNEL
void KRB5_CALLCONV
krb5_free_priv(krb5_context context, register krb5_priv *val)
{
    if (val->enc_part.ciphertext.data) {
	krb5_xfree(val->enc_part.ciphertext.data);
	val->enc_part.ciphertext.data = 0;
    }
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_priv_enc_part(krb5_context context, register krb5_priv_enc_part *val)
{
    if (val->user_data.data) {
	krb5_xfree(val->user_data.data);
	val->user_data.data = 0;
    }
    if (val->r_address) {
	krb5_free_address(context, val->r_address);
	val->r_address = 0;
    }
    if (val->s_address) {
	krb5_free_address(context, val->s_address);
	val->s_address = 0;
    }
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_pwd_data(krb5_context context, krb5_pwd_data *val)
{
    if (val->element)
	krb5_free_pwd_sequences(context, val->element);
    krb5_xfree(val);
}


void KRB5_CALLCONV
krb5_free_pwd_sequences(krb5_context context, passwd_phrase_element **val)
{
    register passwd_phrase_element **temp;

    for (temp = val; *temp; temp++) {
	if ((*temp)->passwd) {
	   krb5_free_data(context, (*temp)->passwd);
	   (*temp)->passwd = 0;
	}
	if ((*temp)->phrase) {
	   krb5_free_data(context, (*temp)->phrase);
	   (*temp)->phrase = 0;
	}
	krb5_xfree(*temp);
    }
    krb5_xfree(val);
}


void KRB5_CALLCONV
krb5_free_safe(krb5_context context, register krb5_safe *val)
{
    if (val->user_data.data) {
	krb5_xfree(val->user_data.data);
	val->user_data.data = 0;
    }
    if (val->r_address) {
	krb5_free_address(context, val->r_address);
	val->r_address = 0;
    }
    if (val->s_address) {
	krb5_free_address(context, val->s_address);
	val->s_address = 0;
    }
    if (val->checksum) {
	krb5_free_checksum(context, val->checksum);
	val->checksum = 0;
    }
    krb5_xfree(val);
}


void KRB5_CALLCONV
krb5_free_ticket(krb5_context context, krb5_ticket *val)
{
    if (val->server)
	krb5_free_principal(context, val->server);
    if (val->enc_part.ciphertext.data) {
	krb5_xfree(val->enc_part.ciphertext.data);
	val->enc_part.ciphertext.data = 0;
    }
    if (val->enc_part2)
	krb5_free_enc_tkt_part(context, val->enc_part2);
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_tickets(krb5_context context, krb5_ticket **val)
{
    register krb5_ticket **temp;

    for (temp = val; *temp; temp++)
        krb5_free_ticket(context, *temp);
    krb5_xfree(val);
}


void KRB5_CALLCONV
krb5_free_tgt_creds(krb5_context context, krb5_creds **tgts)
{
    register krb5_creds **tgtpp;
    for (tgtpp = tgts; *tgtpp; tgtpp++)
	krb5_free_creds(context, *tgtpp);
    krb5_xfree(tgts);
}

void KRB5_CALLCONV
krb5_free_tkt_authent(krb5_context context, krb5_tkt_authent *val)
{
    if (val->ticket) {
	krb5_free_ticket(context, val->ticket);
	val->ticket = 0;
    }
    if (val->authenticator) {
	krb5_free_authenticator(context, val->authenticator);
	val->authenticator = 0;
    }
    krb5_xfree(val);
}

void KRB5_CALLCONV
krb5_free_unparsed_name(krb5_context context, char *val)
{
    if (val) {
	krb5_xfree(val);
    }
}

void KRB5_CALLCONV
krb5_free_sam_challenge(krb5_context ctx, krb5_sam_challenge *sc)
{
    if (!sc)
	return;
    krb5_free_sam_challenge_contents(ctx, sc);
    krb5_xfree(sc);
}

void KRB5_CALLCONV
krb5_free_sam_challenge_2(krb5_context ctx, krb5_sam_challenge_2 *sc2)
{
    if (!sc2)
	return;
    krb5_free_sam_challenge_2_contents(ctx, sc2);
    krb5_xfree(sc2);
}

void KRB5_CALLCONV
krb5_free_sam_challenge_contents(krb5_context ctx, krb5_sam_challenge *sc)
{
    if (!sc)
	return;
    if (sc->sam_type_name.data)
	krb5_free_data_contents(ctx, &sc->sam_type_name);
    if (sc->sam_track_id.data)
	krb5_free_data_contents(ctx, &sc->sam_track_id);
    if (sc->sam_challenge_label.data)
	krb5_free_data_contents(ctx, &sc->sam_challenge_label);
    if (sc->sam_challenge.data)
	krb5_free_data_contents(ctx, &sc->sam_challenge);
    if (sc->sam_response_prompt.data)
	krb5_free_data_contents(ctx, &sc->sam_response_prompt);
    if (sc->sam_pk_for_sad.data)
	krb5_free_data_contents(ctx, &sc->sam_pk_for_sad);
    if (sc->sam_cksum.contents) {
	krb5_xfree(sc->sam_cksum.contents);
	sc->sam_cksum.contents = 0;
    }
}

void KRB5_CALLCONV
krb5_free_sam_challenge_2_contents(krb5_context ctx,
				   krb5_sam_challenge_2 *sc2)
{
    krb5_checksum **cksump;

    if (!sc2)
	return;
    if (sc2->sam_challenge_2_body.data)
	krb5_free_data_contents(ctx, &sc2->sam_challenge_2_body);
    if (sc2->sam_cksum) {
	cksump = sc2->sam_cksum;
	while (*cksump) {
            krb5_free_checksum(ctx, *cksump);
            cksump++;
	}
	krb5_xfree(sc2->sam_cksum);
	sc2->sam_cksum = 0;
    }
}

void KRB5_CALLCONV
krb5_free_sam_challenge_2_body(krb5_context ctx,
			       krb5_sam_challenge_2_body *sc2)
{
    if (!sc2)
	return;
    krb5_free_sam_challenge_2_body_contents(ctx, sc2);
    krb5_xfree(sc2);
}

void KRB5_CALLCONV
krb5_free_sam_challenge_2_body_contents(krb5_context ctx,
					krb5_sam_challenge_2_body *sc2)
{
    if (!sc2)
	return;
    if (sc2->sam_type_name.data)
	krb5_free_data_contents(ctx, &sc2->sam_type_name);
    if (sc2->sam_track_id.data)
	krb5_free_data_contents(ctx, &sc2->sam_track_id);
    if (sc2->sam_challenge_label.data)
	krb5_free_data_contents(ctx, &sc2->sam_challenge_label);
    if (sc2->sam_challenge.data)
	krb5_free_data_contents(ctx, &sc2->sam_challenge);
    if (sc2->sam_response_prompt.data)
	krb5_free_data_contents(ctx, &sc2->sam_response_prompt);
    if (sc2->sam_pk_for_sad.data)
	krb5_free_data_contents(ctx, &sc2->sam_pk_for_sad);
}

void KRB5_CALLCONV
krb5_free_sam_response(krb5_context ctx, krb5_sam_response *sr)
{
    if (!sr)
	return;
    krb5_free_sam_response_contents(ctx, sr);
    krb5_xfree(sr);
}

void KRB5_CALLCONV
krb5_free_sam_response_2(krb5_context ctx, krb5_sam_response_2 *sr2)
{
    if (!sr2)
	return;
    krb5_free_sam_response_2_contents(ctx, sr2);
    krb5_xfree(sr2);
}

void KRB5_CALLCONV
krb5_free_sam_response_contents(krb5_context ctx, krb5_sam_response *sr)
{
    if (!sr)
	return;
    if (sr->sam_track_id.data)
	krb5_free_data_contents(ctx, &sr->sam_track_id);
    if (sr->sam_enc_key.ciphertext.data)
	krb5_free_data_contents(ctx, &sr->sam_enc_key.ciphertext);
    if (sr->sam_enc_nonce_or_ts.ciphertext.data)
	krb5_free_data_contents(ctx, &sr->sam_enc_nonce_or_ts.ciphertext);
}

void KRB5_CALLCONV
krb5_free_sam_response_2_contents(krb5_context ctx, krb5_sam_response_2 *sr2)
{
    if (!sr2)
	return;
    if (sr2->sam_track_id.data)
	krb5_free_data_contents(ctx, &sr2->sam_track_id);
    if (sr2->sam_enc_nonce_or_sad.ciphertext.data)
	krb5_free_data_contents(ctx, &sr2->sam_enc_nonce_or_sad.ciphertext);
}

void KRB5_CALLCONV
krb5_free_predicted_sam_response(krb5_context ctx,
				 krb5_predicted_sam_response *psr)
{
    if (!psr)
	return;
    krb5_free_predicted_sam_response_contents(ctx, psr);
    krb5_xfree(psr);
}

void KRB5_CALLCONV
krb5_free_predicted_sam_response_contents(krb5_context ctx,
				 krb5_predicted_sam_response *psr)
{
    if (!psr)
	return;
    if (psr->sam_key.contents)
	krb5_free_keyblock_contents(ctx, &psr->sam_key);
    if (psr->client) {
	krb5_free_principal(ctx, psr->client);
	psr->client = 0;
    }
    if (psr->msd.data)
	krb5_free_data_contents(ctx, &psr->msd);
}

void KRB5_CALLCONV
krb5_free_enc_sam_response_enc(krb5_context ctx,
			       krb5_enc_sam_response_enc *esre)
{
    if (!esre)
	return;
    krb5_free_enc_sam_response_enc_contents(ctx, esre);
    krb5_xfree(esre);
}

void KRB5_CALLCONV
krb5_free_enc_sam_response_enc_2(krb5_context ctx,
				 krb5_enc_sam_response_enc_2 *esre2)
{
    if (!esre2)
	return;
    krb5_free_enc_sam_response_enc_2_contents(ctx, esre2);
    krb5_xfree(esre2);
}

void KRB5_CALLCONV
krb5_free_enc_sam_response_enc_contents(krb5_context ctx,
			       krb5_enc_sam_response_enc *esre)
{
    if (!esre)
	return;
    if (esre->sam_sad.data)
	krb5_free_data_contents(ctx, &esre->sam_sad);
}

void KRB5_CALLCONV
krb5_free_enc_sam_response_enc_2_contents(krb5_context ctx,
					  krb5_enc_sam_response_enc_2 *esre2)
{
    if (!esre2)
	return;
    if (esre2->sam_sad.data)
	krb5_free_data_contents(ctx, &esre2->sam_sad);
}

void KRB5_CALLCONV
krb5_free_pa_enc_ts(krb5_context ctx, krb5_pa_enc_ts *pa_enc_ts)
{
    if (!pa_enc_ts)
	return;
    krb5_xfree(pa_enc_ts);
}
#endif	/* !_KERNEL */
