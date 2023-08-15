/*
 * kdc/kdc_util.c
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
 * Utility functions for the KDC implementation.
 */



#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include "adm.h"
#include "adm_proto.h"
#include <limits.h>

#ifdef USE_RCACHE
static char *kdc_current_rcname = (char *) NULL;
krb5_deltat rc_lifetime; /* See kdc_initialize_rcache() */
#endif

#ifdef USE_RCACHE
/*
 * initialize the replay cache.
 */
krb5_error_code
kdc_initialize_rcache(krb5_context kcontext, char *rcache_name)
{
    krb5_error_code	retval;
    char		*rcname;
    char		*sname;

    rcname = (rcache_name) ? rcache_name : kdc_current_rcname;

    /* rc_lifetime used elsewhere to verify we're not */
    /*  replaying really old data                     */
    rc_lifetime = kcontext->clockskew;

    if (!rcname)
	rcname = KDCRCACHE;
    if (!(retval = krb5_rc_resolve_full(kcontext, &kdc_rcache, rcname))) {
	/* Recover or initialize the replay cache */
	if (!(retval = krb5_rc_recover(kcontext, kdc_rcache)) ||
	    !(retval = krb5_rc_initialize(kcontext,
					  kdc_rcache,
					  kcontext->clockskew))
	    ) {
	    /* Expunge the replay cache */
	    if (!(retval = krb5_rc_expunge(kcontext, kdc_rcache))) {
		sname = kdc_current_rcname;
		kdc_current_rcname = strdup(rcname);
		if (sname)
		    free(sname);
	    }
	}
	if (retval)
	    krb5_rc_close(kcontext, kdc_rcache);
    }
    return(retval);
}
#endif

/*
 * concatenate first two authdata arrays, returning an allocated replacement.
 * The replacement should be freed with krb5_free_authdata().
 */
krb5_error_code
concat_authorization_data(krb5_authdata **first, krb5_authdata **second,
			  krb5_authdata ***output)
{
    register int i, j;
    register krb5_authdata **ptr, **retdata;

    /* count up the entries */
    i = 0;
    if (first)
	for (ptr = first; *ptr; ptr++)
	    i++;
    if (second)
	for (ptr = second; *ptr; ptr++)
	    i++;

    retdata = (krb5_authdata **)malloc((i+1)*sizeof(*retdata));
    if (!retdata)
	return ENOMEM;
    retdata[i] = 0;			/* null-terminated array */
    for (i = 0, j = 0, ptr = first; j < 2 ; ptr = second, j++)
	while (ptr && *ptr) {
	    /* now walk & copy */
	    retdata[i] = (krb5_authdata *)malloc(sizeof(*retdata[i]));
	    if (!retdata[i]) {
		krb5_free_authdata(kdc_context, retdata);
		return ENOMEM;
	    }
	    *retdata[i] = **ptr;
	    if (!(retdata[i]->contents =
		  (krb5_octet *)malloc(retdata[i]->length))) {
		free((char *)retdata[i]);
		retdata[i] = 0;
		krb5_free_authdata(kdc_context, retdata);
		return ENOMEM;
	    }
	    memcpy((char *) retdata[i]->contents,
		   (char *)(*ptr)->contents,
		   retdata[i]->length);

	    ptr++;
	    i++;
	}
    *output = retdata;
    return 0;
}

krb5_boolean
realm_compare(krb5_principal princ1, krb5_principal princ2)
{
  krb5_data *realm1 = krb5_princ_realm(kdc_context, princ1);
  krb5_data *realm2 = krb5_princ_realm(kdc_context, princ2);

  return((realm1->length == realm2->length) &&
         !memcmp(realm1->data, realm2->data, realm1->length));
}

/*
 * Returns TRUE if the kerberos principal is the name of a Kerberos ticket
 * service.
 */
krb5_boolean krb5_is_tgs_principal(krb5_principal principal)
{
	if ((krb5_princ_size(kdc_context, principal) > 0) &&
	    (krb5_princ_component(kdc_context, principal, 0)->length ==
	     KRB5_TGS_NAME_SIZE) &&
	    (!memcmp(krb5_princ_component(kdc_context, principal, 0)->data,
		     KRB5_TGS_NAME, KRB5_TGS_NAME_SIZE)))
		return TRUE;
	return FALSE;
}

/*
 * given authentication data (provides seed for checksum), verify checksum
 * for source data.
 */
static krb5_error_code
comp_cksum(krb5_context kcontext, krb5_data *source, krb5_ticket *ticket,
	   krb5_checksum *his_cksum)
{
    krb5_error_code 	  retval;
    krb5_boolean	  valid;

    if (!krb5_c_valid_cksumtype(his_cksum->checksum_type))
	return KRB5KDC_ERR_SUMTYPE_NOSUPP;

    /* must be collision proof */
    if (!krb5_c_is_coll_proof_cksum(his_cksum->checksum_type))
	return KRB5KRB_AP_ERR_INAPP_CKSUM;

    /* verify checksum */
    if ((retval = krb5_c_verify_checksum(kcontext, ticket->enc_part2->session,
					 KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
					 source, his_cksum, &valid)))
	return(retval);

    if (!valid)
	return(KRB5KRB_AP_ERR_BAD_INTEGRITY);

    return(0);
}

krb5_error_code
kdc_process_tgs_req(krb5_kdc_req *request, const krb5_fulladdr *from,
		    krb5_data *pkt, krb5_ticket **ticket,
		    krb5_keyblock **subkey)
{
    krb5_pa_data       ** tmppa;
    krb5_ap_req 	* apreq;
    krb5_error_code 	  retval;
    krb5_data		  scratch1;
    krb5_data 		* scratch = NULL;
    krb5_boolean 	  foreign_server = FALSE;
    krb5_auth_context 	  auth_context = NULL;
    krb5_authenticator	* authenticator = NULL;
    krb5_checksum 	* his_cksum = NULL;
/*    krb5_keyblock 	* key = NULL;*/
/*    krb5_kvno 		  kvno = 0;*/

    if (!request->padata)
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
    for (tmppa = request->padata; *tmppa; tmppa++) {
	if ((*tmppa)->pa_type == KRB5_PADATA_AP_REQ)
	    break;
    }
    if (!*tmppa)			/* cannot find any AP_REQ */
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;

    scratch1.length = (*tmppa)->length;
    scratch1.data = (char *)(*tmppa)->contents;
    if ((retval = decode_krb5_ap_req(&scratch1, &apreq)))
	return retval;

    if (isflagset(apreq->ap_options, AP_OPTS_USE_SESSION_KEY) ||
	isflagset(apreq->ap_options, AP_OPTS_MUTUAL_REQUIRED)) {
	krb5_klog_syslog(LOG_INFO, "TGS_REQ: SESSION KEY or MUTUAL");
	retval = KRB5KDC_ERR_POLICY;
	goto cleanup;
    }

    /* If the "server" principal in the ticket is not something
       in the local realm, then we must refuse to service the request
       if the client claims to be from the local realm.

       If we don't do this, then some other realm's nasty KDC can
       claim to be authenticating a client from our realm, and we'll
       give out tickets concurring with it!

       we set a flag here for checking below.
       */
    if ((krb5_princ_realm(kdc_context, apreq->ticket->server)->length !=
	 krb5_princ_realm(kdc_context, tgs_server)->length) ||
	memcmp(krb5_princ_realm(kdc_context, apreq->ticket->server)->data,
	       krb5_princ_realm(kdc_context, tgs_server)->data,
	       krb5_princ_realm(kdc_context, tgs_server)->length))
	foreign_server = TRUE;

    if ((retval = krb5_auth_con_init(kdc_context, &auth_context)))
	goto cleanup;

    if ((retval = krb5_auth_con_setaddrs(kdc_context, auth_context, NULL,
					 from->address)) )
	goto cleanup_auth_context;
#ifdef USE_RCACHE
    if ((retval = krb5_auth_con_setrcache(kdc_context, auth_context,
					  kdc_rcache)))
	goto cleanup_auth_context;
#endif

/*
    if ((retval = kdc_get_server_key(apreq->ticket, &key, &kvno)))
	goto cleanup_auth_context;
*/

    /*
     * XXX This is currently wrong but to fix it will require making a
     * new keytab for groveling over the kdb.
     */
/*
    retval = krb5_auth_con_setuseruserkey(kdc_context, auth_context, key);
    krb5_free_keyblock(kdc_context, key);
    if (retval)
	goto cleanup_auth_context;
*/

    if ((retval = krb5_rd_req_decoded_anyflag(kdc_context, &auth_context, apreq,
				      apreq->ticket->server,
				      kdc_active_realm->realm_keytab,
				      NULL, ticket))) {
#ifdef USE_RCACHE
	/*
	 * I'm not so sure that this is right, but it's better than nothing
	 * at all.
	 *
	 * If we choke in the rd_req because of the replay cache, then attempt
	 * to reinitialize the replay cache because somebody could have deleted
	 * it from underneath us (e.g. a cron job)
	 */
	if ((retval == KRB5_RC_IO_IO) ||
	    (retval == KRB5_RC_IO_UNKNOWN)) {
	    (void) krb5_rc_close(kdc_context, kdc_rcache);
	    kdc_rcache = (krb5_rcache) NULL;
	    if (!(retval = kdc_initialize_rcache(kdc_context, (char *) NULL))) {
		if ((retval = krb5_auth_con_setrcache(kdc_context, auth_context,
						      kdc_rcache)) ||
		    (retval = krb5_rd_req_decoded_anyflag(kdc_context, &auth_context,
						  apreq, apreq->ticket->server,
				      		 kdc_active_realm->realm_keytab,
						  NULL, ticket))
		    )
		    goto cleanup_auth_context;
	    }
	} else
	    goto cleanup_auth_context;
#else
	goto cleanup_auth_context;
#endif
    }

    /* "invalid flag" tickets can must be used to validate */
    if (isflagset((*ticket)->enc_part2->flags, TKT_FLG_INVALID)
	&& !isflagset(request->kdc_options, KDC_OPT_VALIDATE)) {
        retval = KRB5KRB_AP_ERR_TKT_INVALID;
	goto cleanup_auth_context;
    }

    if ((retval = krb5_auth_con_getrecvsubkey(kdc_context,
					      auth_context, subkey)))
	goto cleanup_auth_context;

    if ((retval = krb5_auth_con_getauthenticator(kdc_context, auth_context,
						 &authenticator)))
	goto cleanup_auth_context;

    /* Check for a checksum */
    if (!(his_cksum = authenticator->checksum)) {
	retval = KRB5KRB_AP_ERR_INAPP_CKSUM;
	goto cleanup_authenticator;
    }

    /* make sure the client is of proper lineage (see above) */
    if (foreign_server) {
	krb5_data *tkt_realm = krb5_princ_realm(kdc_context,
						(*ticket)->enc_part2->client);
	krb5_data *tgs_realm = krb5_princ_realm(kdc_context, tgs_server);
	if (tkt_realm->length == tgs_realm->length &&
	    !memcmp(tkt_realm->data, tgs_realm->data, tgs_realm->length)) {
	    /* someone in a foreign realm claiming to be local */
	    krb5_klog_syslog(LOG_INFO, "PROCESS_TGS: failed lineage check");
	    retval = KRB5KDC_ERR_POLICY;
	    goto cleanup_authenticator;
	}
    }

    /*
     * Check application checksum vs. tgs request
     *
     * We try checksumming the req-body two different ways: first we
     * try reaching into the raw asn.1 stream (if available), and
     * checksum that directly; if that fails, then we try encoding
     * using our local asn.1 library.
     */
    if (pkt && (fetch_asn1_field((unsigned char *) pkt->data,
				 1, 4, &scratch1) >= 0)) {
	if (comp_cksum(kdc_context, &scratch1, *ticket, his_cksum)) {
	    if (!(retval = encode_krb5_kdc_req_body(request, &scratch)))
	        retval = comp_cksum(kdc_context, scratch, *ticket, his_cksum);
	    krb5_free_data(kdc_context, scratch);
	}
    }

cleanup_authenticator:
    krb5_free_authenticator(kdc_context, authenticator);

cleanup_auth_context:
    /* We do not want the free of the auth_context to close the rcache */
#ifdef USE_RCACHE
    (void)  krb5_auth_con_setrcache(kdc_context, auth_context, 0);
#endif
    krb5_auth_con_free(kdc_context, auth_context);

cleanup:
    krb5_free_ap_req(kdc_context, apreq);
    return retval;
}

/* XXX This function should no longer be necessary.
 * The KDC should take the keytab associated with the realm and pass that to
 * the krb5_rd_req_decode(). --proven
 *
 * It's actually still used by do_tgs_req() for u2u auth, and not too
 * much else. -- tlyu
 */
krb5_error_code
kdc_get_server_key(krb5_ticket *ticket, krb5_keyblock **key, krb5_kvno *kvno)
{
    krb5_error_code 	  retval;
    krb5_db_entry 	  server;
    krb5_boolean 	  more;
    int	nprincs;
    krb5_key_data	* server_key;

    nprincs = 1;

    if ((retval = krb5_db_get_principal(kdc_context, ticket->server,
					&server, &nprincs,
					&more))) {
	return(retval);
    }
    if (more) {
	krb5_db_free_principal(kdc_context, &server, nprincs);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    } else if (nprincs != 1) {
	char *sname;

	krb5_db_free_principal(kdc_context, &server, nprincs);
	if (!krb5_unparse_name(kdc_context, ticket->server, &sname)) {
	    limit_string(sname);
	    krb5_klog_syslog(LOG_ERR,"TGS_REQ: UNKNOWN SERVER: server='%s'",
			     sname);
	    free(sname);
	}
	return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
    retval = krb5_dbe_find_enctype(kdc_context, &server,
				   ticket->enc_part.enctype, -1,
				   ticket->enc_part.kvno, &server_key);
    if (retval)
	goto errout;
    if (!server_key) {
	retval = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto errout;
    }
    *kvno = server_key->key_data_kvno;
    if ((*key = (krb5_keyblock *)malloc(sizeof **key))) {
	retval = krb5_dbekd_decrypt_key_data(kdc_context, &master_keyblock,
					     server_key,
					     *key, NULL);
    } else
	retval = ENOMEM;
errout:
    krb5_db_free_principal(kdc_context, &server, nprincs);
    return retval;
}

/* This probably wants to be updated if you support last_req stuff */

static krb5_last_req_entry nolrentry = { KV5M_LAST_REQ_ENTRY, KRB5_LRQ_NONE, 0 };
static krb5_last_req_entry *nolrarray[] = { &nolrentry, 0 };

krb5_error_code
fetch_last_req_info(krb5_db_entry *dbentry, krb5_last_req_entry ***lrentry)
{
    *lrentry = nolrarray;
    return 0;
}


/* XXX!  This is a temporary place-holder */

krb5_error_code
check_hot_list(krb5_ticket *ticket)
{
    return 0;
}


#define MAX_REALM_LN 500


/*
 * subrealm - determine if r2 is a subrealm of r1
 *
 *            SUBREALM takes two realms, r1 and r2, and
 *            determines if r2 is a subrealm of r1.
 *            r2 is a subrealm of r1 if (r1 is a prefix
 *            of r2 AND r1 and r2 begin with a /) or if
 *            (r1 is a suffix of r2 and neither r1 nor r2
 *            begin with a /).
 *
 * RETURNS:   If r2 is a subrealm, and r1 is a prefix, the number
 *            of characters in the suffix of r2 is returned as a
 *            negative number.
 *
 *            If r2 is a subrealm, and r1 is a suffix, the number
 *            of characters in the prefix of r2 is returned as a
 *            positive number.
 *
 *            If r2 is not a subrealm, SUBREALM returns 0.
 */
static  int
subrealm(char *r1, char *r2)
{
    size_t l1,l2;
    l1 = strlen(r1);
    l2 = strlen(r2);
    if(l2 <= l1) return(0);
    if((*r1 == '/') && (*r2 == '/') && (strncmp(r1,r2,l1) == 0)) return(l1-l2);
    if((*r1 != '/') && (*r2 != '/') && (strncmp(r1,r2+l2-l1,l1) == 0))
	return(l2-l1);
    return(0);
}

/*
 * add_to_transited  Adds the name of the realm which issued the
 *                   ticket granting ticket on which the new ticket to
 *                   be issued is based (note that this is the same as
 *                   the realm of the server listed in the ticket
 *                   granting ticket.
 *
 * ASSUMPTIONS:  This procedure assumes that the transited field from
 *               the existing ticket granting ticket already appears
 *               in compressed form.  It will add the new realm while
 *               maintaining that form.   As long as each successive
 *               realm is added using this (or a similar) routine, the
 *               transited field will be in compressed form.  The
 *               basis step is an empty transited field which is, by
 *               its nature, in its most compressed form.
 *
 * ARGUMENTS: krb5_data *tgt_trans  Transited field from TGT
 *            krb5_data *new_trans  The transited field for the new ticket
 *            krb5_principal tgs    Name of ticket granting server
 *                                  This includes the realm of the KDC
 *                                  that issued the ticket granting
 *                                  ticket.  This is the realm that is
 *                                  to be added to the transited field.
 *            krb5_principal client Name of the client
 *            krb5_principal server The name of the requested server.
 *                                  This may be the an intermediate
 *                                  ticket granting server.
 *
 *            The last two argument are needed since they are
 *            implicitly part of the transited field of the new ticket
 *            even though they are not explicitly listed.
 *
 * RETURNS:   krb5_error_code - Success, or out of memory
 *
 * MODIFIES:  new_trans:  ->length will contain the length of the new
 *                        transited field.
 *
 *                        If ->data was not null when this procedure
 *                        is called, the memory referenced by ->data
 *                        will be deallocated.
 *
 *                        Memory will be allocated for the new transited field
 *                        ->data will be updated to point to the newly
 *                        allocated memory.
 *
 * BUGS:  The space allocated for the new transited field is the
 *        maximum that might be needed given the old transited field,
 *        and the realm to be added.  This length is calculated
 *        assuming that no compression of the new realm is possible.
 *        This has no adverse consequences other than the allocation
 *        of more space than required.
 *
 *        This procedure will not yet use the null subfield notation,
 *        and it will get confused if it sees it.
 *
 *        This procedure does not check for quoted commas in realm
 *        names.
 */

static char *
data2string (krb5_data *d)
{
    char *s;
    s = malloc(d->length + 1);
    if (s) {
	memcpy(s, d->data, d->length);
	s[d->length] = 0;
    }
    return s;
}

krb5_error_code
add_to_transited(krb5_data *tgt_trans, krb5_data *new_trans,
		 krb5_principal tgs, krb5_principal client,
		 krb5_principal server)
{
  krb5_error_code retval;
  char        *realm;
  char        *trans;
  char        *otrans, *otrans_ptr;

  /* The following are for stepping through the transited field     */

  char        prev[MAX_REALM_LN];
  char        next[MAX_REALM_LN];
  char        current[MAX_REALM_LN];
  char        exp[MAX_REALM_LN];      /* Expanded current realm name     */

  int	      i;
  int         clst, nlst;    /* count of last character in current and next */
  int         pl, pl1;       /* prefix length                               */
  int         added;         /* TRUE = new realm has been added             */

  realm = data2string(krb5_princ_realm(kdc_context, tgs));
  if (realm == NULL)
      return(ENOMEM);

  otrans = data2string(tgt_trans);
  if (otrans == NULL) {
      free(realm);
      return(ENOMEM);
  }
  /* Keep track of start so we can free */
  otrans_ptr = otrans;

  /* +1 for null,
     +1 for extra comma which may be added between
     +1 for potential space when leading slash in realm */
  if (!(trans = (char *) malloc(strlen(realm) + strlen(otrans) + 3))) {
    retval = ENOMEM;
    goto fail;
  }

  if (new_trans->data)  free(new_trans->data);
  new_trans->data = trans;
  new_trans->length = 0;

  trans[0] = '\0';

  /* For the purpose of appending, the realm preceding the first */
  /* realm in the transited field is considered the null realm   */

  prev[0] = '\0';

  /* read field into current */
  for (i = 0; *otrans != '\0';) {
      if (*otrans == '\\') {
	  if (*(++otrans) == '\0')
	      break;
	  else
	      continue;
      }
      if (*otrans == ',') {
	  otrans++;
	  break;
      }
      current[i++] = *otrans++;
      if (i >= MAX_REALM_LN) {
	  retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	  goto fail;
      }
  }
  current[i] = '\0';

  added = (krb5_princ_realm(kdc_context, client)->length == strlen(realm) &&
           !strncmp(krb5_princ_realm(kdc_context, client)->data, realm, strlen(realm))) ||
          (krb5_princ_realm(kdc_context, server)->length == strlen(realm) &&
           !strncmp(krb5_princ_realm(kdc_context, server)->data, realm, strlen(realm)));

  while (current[0]) {

    /* figure out expanded form of current name */

    clst = strlen(current) - 1;
    if (current[0] == ' ') {
      strncpy(exp, current+1, sizeof(exp) - 1);
      exp[sizeof(exp) - 1] = '\0';
    }
    else if ((current[0] == '/') && (prev[0] == '/')) {
      strncpy(exp, prev, sizeof(exp) - 1);
      exp[sizeof(exp) - 1] = '\0';
      if (strlen(exp) + strlen(current) + 1 >= MAX_REALM_LN) {
	retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	goto fail;
      }
      strncat(exp, current, sizeof(exp) - 1 - strlen(exp));
    }
    else if (current[clst] == '.') {
      strncpy(exp, current, sizeof(exp) - 1);
      exp[sizeof(exp) - 1] = '\0';
      if (strlen(exp) + strlen(prev) + 1 >= MAX_REALM_LN) {
	retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	goto fail;
      }
      strncat(exp, prev, sizeof(exp) - 1 - strlen(exp));
    }
    else {
      strncpy(exp, current, sizeof(exp) - 1);
      exp[sizeof(exp) - 1] = '\0';
    }

    /* read field into next */
    for (i = 0; *otrans != '\0';) {
	if (*otrans == '\\') {
	    if (*(++otrans) == '\0')
		break;
	    else
		continue;
	}
	if (*otrans == ',') {
	    otrans++;
	    break;
	}
	next[i++] = *otrans++;
	if (i >= MAX_REALM_LN) {
	    retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	    goto fail;
	}
    }
    next[i] = '\0';
    nlst = i - 1;

    if (!strcmp(exp, realm))  added = TRUE;

    /* If we still have to insert the new realm */

    if (!added) {

      /* Is the next field compressed?  If not, and if the new */
      /* realm is a subrealm of the current realm, compress    */
      /* the new realm, and insert immediately following the   */
      /* current one.  Note that we can not do this if the next*/
      /* field is already compressed since it would mess up    */
      /* what has already been done.  In most cases, this is   */
      /* not a problem because the realm to be added will be a */
      /* subrealm of the next field too, and we will catch     */
      /* it in a future iteration.                             */

	/* Note that the second test here is an unsigned comparison,
	   so the first half (or a cast) is also required.  */
      assert(nlst < 0 || nlst < sizeof(next));
      if ((nlst < 0 || next[nlst] != '.') &&
	  (next[0] != '/') &&
	  (pl = subrealm(exp, realm))) {
        added = TRUE;
	current[sizeof(current) - 1] = '\0';
	if (strlen(current) + (pl>0?pl:-pl) + 2 >= MAX_REALM_LN) {
	  retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	  goto fail;
	}
        strncat(current, ",", sizeof(current) - 1 - strlen(current));
        if (pl > 0) {
          strncat(current, realm, (unsigned) pl);
        }
        else {
          strncat(current, realm+strlen(realm)+pl, (unsigned) (-pl));
        }
      }

      /* Whether or not the next field is compressed, if the    */
      /* realm to be added is a superrealm of the current realm,*/
      /* then the current realm can be compressed.  First the   */
      /* realm to be added must be compressed relative to the   */
      /* previous realm (if possible), and then the current     */
      /* realm compressed relative to the new realm.  Note that */
      /* if the realm to be added is also a superrealm of the   */
      /* previous realm, it would have been added earlier, and  */
      /* we would not reach this step this time around.         */

      else if ((pl = subrealm(realm, exp))) {
        added      = TRUE;
        current[0] = '\0';
        if ((pl1 = subrealm(prev,realm))) {
	  if (strlen(current) + (pl1>0?pl1:-pl1) + 1 >= MAX_REALM_LN) {
	    retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	    goto fail;
	  }
          if (pl1 > 0) {
            strncat(current, realm, (unsigned) pl1);
          }
          else {
            strncat(current, realm+strlen(realm)+pl1, (unsigned) (-pl1));
          }
        }
        else { /* If not a subrealm */
          if ((realm[0] == '/') && prev[0]) {
	    if (strlen(current) + 2 >= MAX_REALM_LN) {
	      retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	      goto fail;
	    }
	    strncat(current, " ", sizeof(current) - 1 - strlen(current));
	    current[sizeof(current) - 1] = '\0';
          }
	  if (strlen(current) + strlen(realm) + 1 >= MAX_REALM_LN) {
	    retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	    goto fail;
	  }
          strncat(current, realm, sizeof(current) - 1 - strlen(current));
	  current[sizeof(current) - 1] = '\0';
        }
	if (strlen(current) + (pl>0?pl:-pl) + 2 >= MAX_REALM_LN) {
	  retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	  goto fail;
	}
        strncat(current,",", sizeof(current) - 1 - strlen(current));
	current[sizeof(current) - 1] = '\0';
        if (pl > 0) {
          strncat(current, exp, (unsigned) pl);
        }
        else {
          strncat(current, exp+strlen(exp)+pl, (unsigned)(-pl));
        }
      }
    }

    if (new_trans->length != 0) {
      if (strlen(trans) + 2 >= MAX_REALM_LN) {
	retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	goto fail;
      }
      strcat(trans, ",");
    }
    if (strlen(trans) + strlen(current) + 1 >= MAX_REALM_LN) {
      retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
      goto fail;
    }
    strcat(trans, current);
    new_trans->length = strlen(trans);

    strncpy(prev, exp, sizeof(prev) - 1);
    prev[sizeof(prev) - 1] = '\0';
    strncpy(current, next, sizeof(current) - 1);
    current[sizeof(current) - 1] = '\0';
  }

  if (!added) {
    if (new_trans->length != 0) {
      if (strlen(trans) + 2 >= MAX_REALM_LN) {
	retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	goto fail;
      }
      strcat(trans, ",");
    }
    if((realm[0] == '/') && trans[0]) {
      if (strlen(trans) + 2 >= MAX_REALM_LN) {
	retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
	goto fail;
      }
      strcat(trans, " ");
    }
    if (strlen(trans) + strlen(realm) + 1 >= MAX_REALM_LN) {
      retval = KRB5KRB_AP_ERR_ILL_CR_TKT;
      goto fail;
    }
    strcat(trans, realm);
    new_trans->length = strlen(trans);
  }

  retval = 0;
fail:
  free(realm);
  free(otrans_ptr);
  return (retval);
}

/*
 * Routines that validate a AS request; checks a lot of things.  :-)
 *
 * Returns a Kerberos protocol error number, which is _not_ the same
 * as a com_err error number!
 */
#define AS_INVALID_OPTIONS (KDC_OPT_FORWARDED | KDC_OPT_PROXY |\
KDC_OPT_VALIDATE | KDC_OPT_RENEW | KDC_OPT_ENC_TKT_IN_SKEY)
int
validate_as_request(register krb5_kdc_req *request, krb5_db_entry client,
		    krb5_db_entry server, krb5_timestamp kdc_time,
		    const char **status)
{
    int		errcode;

    /*
     * If an option is set that is only allowed in TGS requests, complain.
     */
    if (request->kdc_options & AS_INVALID_OPTIONS) {
	*status = "INVALID AS OPTIONS";
	return KDC_ERR_BADOPTION;
    }

    /* The client's password must not be expired, unless the server is
      a KRB5_KDC_PWCHANGE_SERVICE. */
    if (client.pw_expiration && client.pw_expiration < kdc_time &&
	!isflagset(server.attributes, KRB5_KDB_PWCHANGE_SERVICE)) {
	*status = "CLIENT KEY EXPIRED";
#ifdef KRBCONF_VAGUE_ERRORS
	return(KRB_ERR_GENERIC);
#else
	return(KDC_ERR_KEY_EXP);
#endif
    }

    /* The client must not be expired */
    if (client.expiration && client.expiration < kdc_time) {
	*status = "CLIENT EXPIRED";
#ifdef KRBCONF_VAGUE_ERRORS
	return(KRB_ERR_GENERIC);
#else
	return(KDC_ERR_NAME_EXP);
#endif
    }

    /* The server must not be expired */
    if (server.expiration && server.expiration < kdc_time) {
	*status = "SERVICE EXPIRED";
	    return(KDC_ERR_SERVICE_EXP);
    }

    /*
     * If the client requires password changing, then only allow the
     * pwchange service.
     */
    if (isflagset(client.attributes, KRB5_KDB_REQUIRES_PWCHANGE) &&
	!isflagset(server.attributes, KRB5_KDB_PWCHANGE_SERVICE)) {
	*status = "REQUIRED PWCHANGE";
	return(KDC_ERR_KEY_EXP);
    }

    /* Client and server must allow postdating tickets */
    if ((isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) ||
	 isflagset(request->kdc_options, KDC_OPT_POSTDATED)) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_POSTDATED) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_POSTDATED))) {
	*status = "POSTDATE NOT ALLOWED";
	return(KDC_ERR_CANNOT_POSTDATE);
    }

    /* Client and server must allow forwardable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_FORWARDABLE) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_FORWARDABLE))) {
	*status = "FORWARDABLE NOT ALLOWED";
	return(KDC_ERR_POLICY);
    }

    /* Client and server must allow renewable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_RENEWABLE) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_RENEWABLE))) {
	*status = "RENEWABLE NOT ALLOWED";
	return(KDC_ERR_POLICY);
    }

    /* Client and server must allow proxiable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE) &&
	(isflagset(client.attributes, KRB5_KDB_DISALLOW_PROXIABLE) ||
	 isflagset(server.attributes, KRB5_KDB_DISALLOW_PROXIABLE))) {
	*status = "PROXIABLE NOT ALLOWED";
	return(KDC_ERR_POLICY);
    }

    /* Check to see if client is locked out */
    if (isflagset(client.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	*status = "CLIENT LOCKED OUT";
	return(KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    /* Check to see if server is locked out */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	*status = "SERVICE LOCKED OUT";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* Check to see if server is allowed to be a service */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_SVR)) {
	*status = "SERVICE NOT ALLOWED";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /*
     * Check against local policy
     */
    errcode = against_local_policy_as(request, server, client,
				      kdc_time, status);
    if (errcode)
	return errcode;

    return 0;
}

#define ASN1_ID_CLASS	(0xc0)
#define ASN1_ID_TYPE    (0x20)
#define ASN1_ID_TAG	(0x1f)
#define ASN1_CLASS_UNIV	(0)
#define ASN1_CLASS_APP	(1)
#define ASN1_CLASS_CTX	(2)
#define ASN1_CLASS_PRIV	(3)
#define asn1_id_constructed(x) 	(x & ASN1_ID_TYPE)
#define asn1_id_primitive(x) 	(!asn1_id_constructed(x))
#define asn1_id_class(x)	((x & ASN1_ID_CLASS) >> 6)
#define asn1_id_tag(x)		(x & ASN1_ID_TAG)

/*
 * asn1length - return encoded length of value.
 *
 * passed a pointer into the asn.1 stream, which is updated
 * to point right after the length bits.
 *
 * returns -1 on failure.
 */
static int
asn1length(unsigned char **astream)
{
    int length;		/* resulting length */
    int sublen;		/* sublengths */
    int blen;		/* bytes of length */
    unsigned char *p;	/* substring searching */

    if (**astream & 0x80) {
        blen = **astream & 0x7f;
	if (blen > 3) {
	   return(-1);
	}
	for (++*astream, length = 0; blen; ++*astream, blen--) {
	    length = (length << 8) | **astream;
	}
	if (length == 0) {
		/* indefinite length, figure out by hand */
	    p = *astream;
	    p++;
	    while (1) {
		/* compute value length. */
		if ((sublen = asn1length(&p)) < 0) {
		    return(-1);
		}
		p += sublen;
                /* check for termination */
		if ((!*p++) && (!*p)) {
		    p++;
		    break;
		}
	    }
	    length = p - *astream;
	}
    } else {
	length = **astream;
	++*astream;
    }
   return(length);
}

/*
 * fetch_asn1_field - return raw asn.1 stream of subfield.
 *
 * this routine is passed a context-dependent tag number and "level" and returns
 * the size and length of the corresponding level subfield.
 *
 * levels and are numbered starting from 1.
 *
 * returns 0 on success, -1 otherwise.
 */
int
fetch_asn1_field(unsigned char *astream, unsigned int level,
		 unsigned int field, krb5_data *data)
{
    unsigned char *estream;	/* end of stream */
    int classes;		/* # classes seen so far this level */
    unsigned int levels = 0;		/* levels seen so far */
    int lastlevel = 1000;       /* last level seen */
    int length;			/* various lengths */
    int tag;			/* tag number */
    unsigned char savelen;      /* saved length of our field */

    classes = -1;
    /* we assume that the first identifier/length will tell us
       how long the entire stream is. */
    astream++;
    estream = astream;
    if ((length = asn1length(&astream)) < 0) {
	return(-1);
    }
    estream += length;
    /* search down the stream, checking identifiers.  we process identifiers
       until we hit the "level" we want, and then process that level for our
       subfield, always making sure we don't go off the end of the stream.  */
    while (astream < estream) {
	if (!asn1_id_constructed(*astream)) {
	    return(-1);
	}
        if (asn1_id_class(*astream) == ASN1_CLASS_CTX) {
            if ((tag = (int)asn1_id_tag(*astream)) <= lastlevel) {
                levels++;
                classes = -1;
            }
            lastlevel = tag;
            if (levels == level) {
	        /* in our context-dependent class, is this the one we're looking for ? */
	        if (tag == field) {
		    /* return length and data */
		    astream++;
		    savelen = *astream;
		    if ((data->length = asn1length(&astream)) < 0) {
		        return(-1);
	 	    }
		    /* if the field length is indefinite, we will have to subtract two
                       (terminating octets) from the length returned since we don't want
                       to pass any info from the "wrapper" back.  asn1length will always return
                       the *total* length of the field, not just what's contained in it */
		    if ((savelen & 0xff) == 0x80) {
		      data->length -=2 ;
		    }
		    data->data = (char *)astream;
		    return(0);
	        } else if (tag <= classes) {
		    /* we've seen this class before, something must be wrong */
		    return(-1);
	        } else {
		    classes = tag;
	        }
	    }
        }
        /* if we're not on our level yet, process this value.  otherwise skip over it */
	astream++;
	if ((length = asn1length(&astream)) < 0) {
	    return(-1);
	}
	if (levels == level) {
	    astream += length;
	}
    }
    return(-1);
}

/*
 * Routines that validate a TGS request; checks a lot of things.  :-)
 *
 * Returns a Kerberos protocol error number, which is _not_ the same
 * as a com_err error number!
 */
#define TGS_OPTIONS_HANDLED (KDC_OPT_FORWARDABLE | KDC_OPT_FORWARDED | \
			     KDC_OPT_PROXIABLE | KDC_OPT_PROXY | \
			     KDC_OPT_ALLOW_POSTDATE | KDC_OPT_POSTDATED | \
			     KDC_OPT_RENEWABLE | KDC_OPT_RENEWABLE_OK | \
			     KDC_OPT_ENC_TKT_IN_SKEY | KDC_OPT_RENEW | \
			     KDC_OPT_VALIDATE)

#define NO_TGT_OPTION (KDC_OPT_FORWARDED | KDC_OPT_PROXY | KDC_OPT_RENEW | \
		       KDC_OPT_VALIDATE)

int
validate_tgs_request(register krb5_kdc_req *request, krb5_db_entry server,
		     krb5_ticket *ticket, krb5_timestamp kdc_time,
		     const char **status)
{
    int		errcode;
    int		st_idx = 0;

    /*
     * If an illegal option is set, ignore it.
     */
    request->kdc_options &= TGS_OPTIONS_HANDLED;

    /* Check to see if server has expired */
    if (server.expiration && server.expiration < kdc_time) {
	*status = "SERVICE EXPIRED";
	return(KDC_ERR_SERVICE_EXP);
    }

    /*
     * Verify that the server principal in authdat->ticket is correct
     * (either the ticket granting service or the service that was
     * originally requested)
     */
    if (request->kdc_options & NO_TGT_OPTION) {
	if (!krb5_principal_compare(kdc_context, ticket->server, request->server)) {
	    *status = "SERVER DIDN'T MATCH TICKET FOR RENEW/FORWARD/ETC";
	    return(KDC_ERR_SERVER_NOMATCH);
	}
    } else {
	/*
	 * OK, we need to validate the krbtgt service in the ticket.
	 *
	 * The krbtgt service is of the form:
	 * 		krbtgt/realm-A@realm-B
	 *
	 * Realm A is the "server realm"; the realm of the
	 * server of the requested ticket must match this realm.
	 * Of course, it should be a realm serviced by this KDC.
	 *
	 * Realm B is the "client realm"; this is what should be
	 * added to the transited field.  (which is done elsewhere)
	 */

	/* Make sure there are two components... */
	if (krb5_princ_size(kdc_context, ticket->server) != 2) {
	    *status = "BAD TGS SERVER LENGTH";
	    return KRB_AP_ERR_NOT_US;
	}
	/* ...that the first component is krbtgt... */
	if (!krb5_is_tgs_principal(ticket->server)) {
	    *status = "BAD TGS SERVER NAME";
	    return KRB_AP_ERR_NOT_US;
	}
	/* ...and that the second component matches the server realm... */
	if ((krb5_princ_size(kdc_context, ticket->server) <= 1) ||
	    (krb5_princ_component(kdc_context, ticket->server, 1)->length !=
	     krb5_princ_realm(kdc_context, request->server)->length) ||
	    memcmp(krb5_princ_component(kdc_context, ticket->server, 1)->data,
		   krb5_princ_realm(kdc_context, request->server)->data,
		   krb5_princ_realm(kdc_context, request->server)->length)) {
	    *status = "BAD TGS SERVER INSTANCE";
	    return KRB_AP_ERR_NOT_US;
	}
	/* XXX add check that second component must match locally
	 * supported realm?
	 */

	/* Server must allow TGS based issuances */
	if (isflagset(server.attributes, KRB5_KDB_DISALLOW_TGT_BASED)) {
	    *status = "TGT BASED NOT ALLOWED";
	    return(KDC_ERR_POLICY);
	}
    }

    /* TGS must be forwardable to get forwarded or forwardable ticket */
    if ((isflagset(request->kdc_options, KDC_OPT_FORWARDED) ||
	 isflagset(request->kdc_options, KDC_OPT_FORWARDABLE)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_FORWARDABLE)) {
	*status = "TGT NOT FORWARDABLE";

	return KDC_ERR_BADOPTION;
    }

    /* TGS must be proxiable to get proxiable ticket */
    if ((isflagset(request->kdc_options, KDC_OPT_PROXY) ||
	 isflagset(request->kdc_options, KDC_OPT_PROXIABLE)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_PROXIABLE)) {
	*status = "TGT NOT PROXIABLE";
	return KDC_ERR_BADOPTION;
    }

    /* TGS must allow postdating to get postdated ticket */
    if ((isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) ||
	  isflagset(request->kdc_options, KDC_OPT_POSTDATED)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_MAY_POSTDATE)) {
	*status = "TGT NOT POSTDATABLE";
	return KDC_ERR_BADOPTION;
    }

    /* can only validate invalid tix */
    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_INVALID)) {
	*status = "VALIDATE VALID TICKET";
	return KDC_ERR_BADOPTION;
    }

    /* can only renew renewable tix */
    if ((isflagset(request->kdc_options, KDC_OPT_RENEW) ||
	  isflagset(request->kdc_options, KDC_OPT_RENEWABLE)) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_RENEWABLE)) {
	*status = "TICKET NOT RENEWABLE";
	return KDC_ERR_BADOPTION;
    }

    /* can not proxy ticket granting tickets */
    if (isflagset(request->kdc_options, KDC_OPT_PROXY) &&
	(!request->server->data ||
	 request->server->data[0].length != KRB5_TGS_NAME_SIZE ||
	 memcmp(request->server->data[0].data, KRB5_TGS_NAME,
		KRB5_TGS_NAME_SIZE))) {
	*status = "CAN'T PROXY TGT";
	return KDC_ERR_BADOPTION;
    }

    /* Server must allow forwardable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_FORWARDABLE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_FORWARDABLE)) {
	*status = "NON-FORWARDABLE TICKET";
	return(KDC_ERR_POLICY);
    }

    /* Server must allow renewable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_RENEWABLE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_RENEWABLE)) {
	*status = "NON-RENEWABLE TICKET";
	return(KDC_ERR_POLICY);
    }

    /* Server must allow proxiable tickets */
    if (isflagset(request->kdc_options, KDC_OPT_PROXIABLE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_PROXIABLE)) {
	*status = "NON-PROXIABLE TICKET";
	return(KDC_ERR_POLICY);
    }

    /* Server must allow postdated tickets */
    if (isflagset(request->kdc_options, KDC_OPT_ALLOW_POSTDATE) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_POSTDATED)) {
	*status = "NON-POSTDATABLE TICKET";
	return(KDC_ERR_CANNOT_POSTDATE);
    }

    /* Server must allow DUP SKEY requests */
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY) &&
	isflagset(server.attributes, KRB5_KDB_DISALLOW_DUP_SKEY)) {
	*status = "DUP_SKEY DISALLOWED";
	return(KDC_ERR_POLICY);
    }

    /* Server must not be locked out */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_ALL_TIX)) {
	*status = "SERVER LOCKED OUT";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* Server must be allowed to be a service */
    if (isflagset(server.attributes, KRB5_KDB_DISALLOW_SVR)) {
	*status = "SERVER NOT ALLOWED";
	return(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* Check the hot list */
    if (check_hot_list(ticket)) {
	*status = "HOT_LIST";
	return(KRB_AP_ERR_REPEAT);
    }

    /* Check the start time vs. the KDC time */
    if (isflagset(request->kdc_options, KDC_OPT_VALIDATE)) {
	if (ticket->enc_part2->times.starttime > kdc_time) {
	    *status = "NOT_YET_VALID";
	    return(KRB_AP_ERR_TKT_NYV);
	}
    }

    /*
     * Check the renew_till time.  The endtime was already
     * been checked in the initial authentication check.
     */
    if (isflagset(request->kdc_options, KDC_OPT_RENEW) &&
	(ticket->enc_part2->times.renew_till < kdc_time)) {
	*status = "TKT_EXPIRED";
	return(KRB_AP_ERR_TKT_EXPIRED);
    }

    /*
     * Checks for ENC_TKT_IN_SKEY:
     *
     * (1) Make sure the second ticket exists
     * (2) Make sure it is a ticket granting ticket
     */
    if (isflagset(request->kdc_options, KDC_OPT_ENC_TKT_IN_SKEY)) {
	if (!request->second_ticket ||
	    !request->second_ticket[st_idx]) {
	    *status = "NO_2ND_TKT";
	    return(KDC_ERR_BADOPTION);
	}
	if (!krb5_principal_compare(kdc_context, request->second_ticket[st_idx]->server,
				    tgs_server)) {
		*status = "2ND_TKT_NOT_TGS";
		return(KDC_ERR_POLICY);
	}
	st_idx++;
    }

    /* Check for hardware preauthentication */
    if (isflagset(server.attributes, KRB5_KDB_REQUIRES_HW_AUTH) &&
	!isflagset(ticket->enc_part2->flags,TKT_FLG_HW_AUTH)) {
	*status = "NO HW PREAUTH";
	return KRB_ERR_GENERIC;
    }

    /* Check for any kind of preauthentication */
    if (isflagset(server.attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
	!isflagset(ticket->enc_part2->flags, TKT_FLG_PRE_AUTH)) {
	*status = "NO PREAUTH";
	return KRB_ERR_GENERIC;
    }

    /*
     * Check local policy
     */
    errcode = against_local_policy_tgs(request, server, ticket, status);
    if (errcode)
	return errcode;


    return 0;
}

/*
 * This function returns 1 if the dbentry has a key for a specified
 * keytype, and 0 if not.
 */
int
dbentry_has_key_for_enctype(krb5_context context, krb5_db_entry *client,
			    krb5_enctype enctype)
{
    krb5_error_code	retval;
    krb5_key_data	*datap;

    retval = krb5_dbe_find_enctype(context, client, enctype,
				   -1, 0, &datap);
    if (retval)
	return 0;
    else
	return 1;
}

/*
 * This function returns 1 if the entity referenced by this
 * structure can support the a particular encryption system, and 0 if
 * not.
 *
 * XXX eventually this information should be looked up in the
 * database.  Since it isn't, we use some hueristics and attribute
 * options bits for now.
 */
int
dbentry_supports_enctype(krb5_context context, krb5_db_entry *client,
			 krb5_enctype enctype)
{
    /*
     * If it's DES_CBC_MD5, there's a bit in the attribute mask which
     * checks to see if we support it.
     *
     * In theory everything's supposed to support DES_CBC_MD5, but
     * that's not the reality....
     */

    /*
     * We are assuming that all entries can support MD5; this information
     * need not be kept in the database.
    */


    if (enctype == ENCTYPE_DES_CBC_MD5)
	return 1;

    /*
     * XXX we assume everything can understand DES_CBC_CRC
     */
    if (enctype == ENCTYPE_DES_CBC_CRC)
	return 1;

    /*
     * If we have a key for the encryption system, we assume it's
     * supported.
     */
    return dbentry_has_key_for_enctype(context, client, enctype);
}

/*
 * This function returns the keytype which should be selected for the
 * session key.  It is based on the ordered list which the user
 * requested, and what the KDC and the application server can support.
 */
krb5_enctype
select_session_keytype(krb5_context context, krb5_db_entry *server,
		       int nktypes, krb5_enctype *ktype)
{
    int		i;

    for (i = 0; i < nktypes; i++) {
	if (!krb5_c_valid_enctype(ktype[i]))
	    continue;

	if (!krb5_is_permitted_enctype(context, ktype[i]))
	    continue;

	if (dbentry_supports_enctype(context, server, ktype[i]))
	    return ktype[i];
    }
    return 0;
}

/*
 * This function returns salt information for a particular client_key
 */
krb5_error_code
get_salt_from_key(krb5_context context, krb5_principal client,
		  krb5_key_data *client_key, krb5_data *salt)
{
    krb5_error_code		retval;
    krb5_data *			realm;

    salt->data = 0;
    salt->length = SALT_TYPE_NO_LENGTH;

    if (client_key->key_data_ver == 1)
	return 0;

    switch (client_key->key_data_type[1]) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	break;
    case KRB5_KDB_SALTTYPE_V4:
	/* send an empty (V4) salt */
	salt->data = 0;
	salt->length = 0;
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	if ((retval = krb5_principal2salt_norealm(context, client, salt)))
	    return retval;
	break;
    case KRB5_KDB_SALTTYPE_AFS3:
	/* send the same salt as with onlyrealm - but with no type info,
	   we just hope they figure it out on the other end. */
	/* fall through to onlyrealm: */
    case KRB5_KDB_SALTTYPE_ONLYREALM:
	realm = krb5_princ_realm(context, client);
	salt->length = realm->length;
	if ((salt->data = malloc(realm->length)) == NULL)
	    return ENOMEM;
	memcpy(salt->data, realm->data, realm->length);
	break;
    case KRB5_KDB_SALTTYPE_SPECIAL:
	salt->length = client_key->key_data_length[1];
	if ((salt->data = malloc(salt->length)) == NULL)
	    return ENOMEM;
	memcpy(salt->data, client_key->key_data_contents[1], salt->length);
	break;
    }
    return 0;
}

/*
 * Limit strings to a "reasonable" length to prevent crowding out of
 * other useful information in the log entry
 */
#define NAME_LENGTH_LIMIT 128

void limit_string(char *name)
{
	int	i;

	if (!name)
		return;

	if (strlen(name) < NAME_LENGTH_LIMIT)
		return;

	i = NAME_LENGTH_LIMIT-4;
	name[i++] = '.';
	name[i++] = '.';
	name[i++] = '.';
	name[i] = '\0';
	return;
}

/*
 * L10_2 = log10(2**x), rounded up; log10(2) ~= 0.301.
 */
#define L10_2(x) ((int)(((x * 301) + 999) / 1000))

/*
 * Max length of sprintf("%ld") for an int of type T; includes leading
 * minus sign and terminating NUL.
 */
#define D_LEN(t) (L10_2(sizeof(t) * CHAR_BIT) + 2)

void
ktypes2str(char *s, size_t len, int nktypes, krb5_enctype *ktype)
{
    int i;
    char stmp[D_LEN(krb5_enctype) + 1];
    char *p;

    if (nktypes < 0
	|| len < (sizeof(" etypes {...}") + D_LEN(int))) {
	*s = '\0';
	return;
    }

    sprintf(s, "%d etypes {", nktypes);
    for (i = 0; i < nktypes; i++) {
	sprintf(stmp, "%s%ld", i ? " " : "", (long)ktype[i]);
	if (strlen(s) + strlen(stmp) + sizeof("}") > len)
	    break;
	strcat(s, stmp);
    }
    if (i < nktypes) {
	/*
	 * We broke out of the loop. Try to truncate the list.
	 */
	p = s + strlen(s);
	while (p - s + sizeof("...}") > len) {
	    while (p > s && *p != ' ' && *p != '{')
		*p-- = '\0';
	    if (p > s && *p == ' ') {
		*p-- = '\0';
		continue;
	    }
	}
	strcat(s, "...");
    }
    strcat(s, "}");
    return;
}

void
rep_etypes2str(char *s, size_t len, krb5_kdc_rep *rep)
{
    char stmp[sizeof("ses=") + D_LEN(krb5_enctype)];

    if (len < (3 * D_LEN(krb5_enctype)
	       + sizeof("etypes {rep= tkt= ses=}"))) {
	*s = '\0';
	return;
    }

    sprintf(s, "etypes {rep=%ld", (long)rep->enc_part.enctype);

    if (rep->ticket != NULL) {
	sprintf(stmp, " tkt=%ld", (long)rep->ticket->enc_part.enctype);
	strcat(s, stmp);
    }

    if (rep->ticket != NULL
	&& rep->ticket->enc_part2 != NULL
	&& rep->ticket->enc_part2->session != NULL) {
	sprintf(stmp, " ses=%ld",
		(long)rep->ticket->enc_part2->session->enctype);
	strcat(s, stmp);
    }
    strcat(s, "}");
    return;
}
