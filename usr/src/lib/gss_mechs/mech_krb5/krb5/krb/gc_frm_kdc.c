/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1994,2003 by the Massachusetts Institute of Technology.
 * Copyright (c) 1994 CyberSAFE Corporation
 * Copyright (c) 1993 Open Computing Security Group
 * Copyright (c) 1990,1991 by the Massachusetts Institute of Technology.
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
 * krb5_get_cred_from_kdc()
 * Get credentials from some KDC somewhere, possibly accumulating tgts
 * along the way.
 */

#include <k5-int.h>
#include <stdio.h>
#include "int-proto.h"

/*
 * Retrieve credentials for principal in_cred->client,
 * server in_cred->server, ticket flags creds->ticket_flags, possibly
 * second_ticket if needed by ticket_flags.
 *
 * Credentials are requested from the KDC for the server's realm.  Any
 * TGT credentials obtained in the process of contacting the KDC are
 * returned in an array of credentials; tgts is filled in to point to an
 * array of pointers to credential structures (if no TGT's were used, the
 * pointer is zeroed).  TGT's may be returned even if no useful end ticket
 * was obtained.
 *
 * The returned credentials are NOT cached.
 *
 * This routine should not be called if the credentials are already in
 * the cache.
 *
 * If credentials are obtained, creds is filled in with the results;
 * creds->ticket and creds->keyblock->key are set to allocated storage,
 * which should be freed by the caller when finished.
 *
 * returns errors, system errors.
 */

/* helper macro: convert flags to necessary KDC options */

#define FLAGS2OPTS(flags) (flags & KDC_TKT_COMMON_MASK)

static krb5_error_code
krb5_get_cred_from_kdc_opt(krb5_context context, krb5_ccache ccache, krb5_creds *in_cred, krb5_creds **out_cred, krb5_creds ***tgts, int kdcopt)
{
  krb5_creds      **ret_tgts = NULL;
  int             ntgts = 0;

  krb5_creds      tgt, tgtq, *tgtr = NULL;
  krb5_error_code retval;
  krb5_principal  int_server = NULL;    /* Intermediate server for request */

  krb5_principal  *tgs_list = NULL;
  krb5_principal  *top_server = NULL;
  krb5_principal  *next_server = NULL;
  unsigned int             nservers = 0;
  krb5_boolean	  old_use_conf_ktypes = context->use_conf_ktypes;

  /* in case we never get a TGT, zero the return */

  *tgts = NULL;

  memset((char *)&tgtq, 0, sizeof(tgtq));
  memset((char *)&tgt, 0, sizeof(tgt));

  /*
   * we know that the desired credentials aren't in the cache yet.
   *
   * To get them, we first need a tgt for the realm of the server.
   * first, we see if we have such a TGT in cache.  if not, then
   * we ask the kdc to give us one.  if that doesn't work, then
   * we try to get a tgt for a realm that is closest to the target.
   * once we have that, then we ask that realm if it can give us
   * tgt for the target.  if not, we do the process over with this
   * new tgt.
   */

  /*
   * (the ticket may be issued by some other intermediate
   *  realm's KDC; so we use KRB5_TC_MATCH_SRV_NAMEONLY)
   */
  if ((retval = krb5_copy_principal(context, in_cred->client, &tgtq.client)))
      goto cleanup;

  /* get target tgt from cache */
  if ((retval = krb5_tgtname(context, krb5_princ_realm(context, in_cred->server),
			     krb5_princ_realm(context, in_cred->client),
			     &int_server))) {
      goto cleanup;
  }

  if ((retval = krb5_copy_principal(context, int_server, &tgtq.server))) {
      goto cleanup;
  }

  /* set endtime to now so krb5_cc_retrieve_cred won't return an expired tik */
  if ((retval = krb5_timeofday(context, &(tgtq.times.endtime))) != 0) {
	goto cleanup;
  }

  context->use_conf_ktypes = 1;
  if ((retval = krb5_cc_retrieve_cred(context, ccache,
				    KRB5_TC_MATCH_SRV_NAMEONLY |
				    KRB5_TC_SUPPORTED_KTYPES |
				    KRB5_TC_MATCH_TIMES,
				    &tgtq, &tgt)) != 0) {

    if (retval != KRB5_CC_NOTFOUND && retval != KRB5_CC_NOT_KTYPE) {
	goto cleanup;
    }

    /*
     * Note that we want to request a TGT from our local KDC, even
     * if we already have a TGT for some intermediate realm.  The
     * reason is that our local KDC may have a shortcut to the
     * destination realm, and if it does we want to use the
     * shortcut because it will provide greater security. - bcn
     */

    /*
     * didn't find it in the cache so it is time to get a local
     * tgt and walk the realms tree.
     */
    krb5_free_principal(context, int_server);
    int_server = NULL;
    if ((retval = krb5_tgtname(context,
			       krb5_princ_realm(context, in_cred->client),
			       krb5_princ_realm(context, in_cred->client),
			       &int_server))) {
	goto cleanup;
    }

    krb5_free_cred_contents(context, &tgtq);
    memset((char *)&tgtq, 0, sizeof(tgtq));
    if ((retval = krb5_copy_principal(context, in_cred->client, &tgtq.client)))
	goto cleanup;
    if ((retval = krb5_copy_principal(context, int_server, &tgtq.server)))
	goto cleanup;

    if ((retval = krb5_timeofday(context, &(tgtq.times.endtime))) != 0) {
	goto cleanup;
    }

    if ((retval = krb5_cc_retrieve_cred(context, ccache,
					KRB5_TC_MATCH_SRV_NAMEONLY |
					KRB5_TC_SUPPORTED_KTYPES |
					KRB5_TC_MATCH_TIMES,
					&tgtq, &tgt)) != 0) {
	goto cleanup;
    }

    /* get a list of realms to consult */

    if ((retval = krb5_walk_realm_tree(context,
				       krb5_princ_realm(context,in_cred->client),
				       krb5_princ_realm(context,in_cred->server),
				       &tgs_list,
				       KRB5_REALM_BRANCH_CHAR))) {
	goto cleanup;
    }

    for (nservers = 0; tgs_list[nservers]; nservers++)
      ;

    /* allocate storage for TGT pointers. */

    if (!(ret_tgts = (krb5_creds **) calloc(nservers+1, sizeof(krb5_creds)))) {
      retval = ENOMEM;
      goto cleanup;
    }
    *tgts = ret_tgts;

    /*
     * step one is to take the current tgt and see if there is a tgt for
     * krbtgt/realmof(target)@realmof(tgt).  if not, try to get one with
     * the tgt.
     *
     * if we don't get a tgt for the target, then try to find a tgt as
     * close to the target realm as possible. at each step if there isn't
     * a tgt in the cache we have to try and get one with our latest tgt.
     * once we have a tgt for a closer realm, we go back to step one.
     *
     * once we have a tgt for the target, we go try and get credentials.
     */

    for (top_server = tgs_list;
         top_server < tgs_list + nservers;
         top_server = next_server) {

      /* look in cache for a tgt for the destination */

      krb5_free_cred_contents(context, &tgtq);
      memset(&tgtq, 0, sizeof(tgtq));
      if ((retval = krb5_copy_principal(context, tgt.client, &tgtq.client)))
	  goto cleanup;

      krb5_free_principal(context, int_server);
      int_server = NULL;
      if ((retval = krb5_tgtname(context,
				 krb5_princ_realm(context, in_cred->server),
				 krb5_princ_realm(context, *top_server),
				 &int_server))) {
	  goto cleanup;
      }

      if ((retval = krb5_copy_principal(context, int_server, &tgtq.server)))
	  goto cleanup;

      if ((retval = krb5_timeofday(context, &(tgtq.times.endtime))) != 0) {
	    goto cleanup;
      }

      if ((retval = krb5_cc_retrieve_cred(context, ccache,
					KRB5_TC_MATCH_SRV_NAMEONLY |
					KRB5_TC_SUPPORTED_KTYPES |
					KRB5_TC_MATCH_TIMES,
					  &tgtq, &tgt)) != 0) {

	if (retval != KRB5_CC_NOTFOUND && retval != KRB5_CC_NOT_KTYPE) {
	    goto cleanup;
	}

	/* didn't find it in the cache so try and get one */
	/* with current tgt.                              */

	if (!krb5_c_valid_enctype(tgt.keyblock.enctype)) {
	    retval = KRB5_PROG_ETYPE_NOSUPP;
	    goto cleanup;
	}

	krb5_free_cred_contents(context, &tgtq);
	memset(&tgtq, 0, sizeof(tgtq));
	tgtq.times        = tgt.times;

	if ((retval = krb5_copy_principal(context, tgt.client, &tgtq.client)))
	    goto cleanup;
	if ((retval = krb5_copy_principal(context, int_server, &tgtq.server)))
	    goto cleanup;
	tgtq.is_skey      = FALSE;
	tgtq.ticket_flags = tgt.ticket_flags;
	retval = krb5_get_cred_via_tkt(context, &tgt,
					    FLAGS2OPTS(tgtq.ticket_flags),
				            tgt.addresses, &tgtq, &tgtr);
	if (retval) {

       /*
	* couldn't get one so now loop backwards through the realms
	* list and try and get a tgt for a realm as close to the
	* target as possible. the kdc should give us a tgt for the
	* closest one it knows about, but not all kdc's do this yet.
	*/

	  for (next_server = tgs_list + nservers - 1;
	       next_server > top_server;
	       next_server--) {
	    krb5_free_cred_contents(context, &tgtq);
	    memset(&tgtq, 0, sizeof(tgtq));
	    if ((retval = krb5_copy_principal(context, tgt.client,
					      &tgtq.client)))
		goto cleanup;

	    krb5_free_principal(context, int_server);
	    int_server = NULL;
	    if ((retval = krb5_tgtname(context,
				       krb5_princ_realm(context, *next_server),
				       krb5_princ_realm(context, *top_server),
				       &int_server))) {
		goto cleanup;
	    }

	    if ((retval = krb5_copy_principal(context, int_server,
					      &tgtq.server)))
		goto cleanup;

	    if ((retval = krb5_timeofday(context,
					&(tgtq.times.endtime))) != 0) {
		goto cleanup;
	    }

	    if ((retval = krb5_cc_retrieve_cred(context, ccache,
						KRB5_TC_MATCH_SRV_NAMEONLY |
						KRB5_TC_SUPPORTED_KTYPES |
						KRB5_TC_MATCH_TIMES,
						&tgtq, &tgt)) != 0) {
	      if (retval != KRB5_CC_NOTFOUND) {
		  goto cleanup;
	      }

	      /* not in the cache so try and get one with our current tgt. */

	      if (!krb5_c_valid_enctype(tgt.keyblock.enctype)) {
		  retval = KRB5_PROG_ETYPE_NOSUPP;
		  goto cleanup;
	      }

	      krb5_free_cred_contents(context, &tgtq);
	      memset(&tgtq, 0, sizeof(tgtq));
	      tgtq.times        = tgt.times;
	      if ((retval = krb5_copy_principal(context, tgt.client,
						&tgtq.client)))
		  goto cleanup;
	      if ((retval = krb5_copy_principal(context, int_server,
						&tgtq.server)))
		  goto cleanup;
	      tgtq.is_skey      = FALSE;
	      tgtq.ticket_flags = tgt.ticket_flags;
	      retval = krb5_get_cred_via_tkt(context, &tgt,
					     FLAGS2OPTS(tgtq.ticket_flags),
					     tgt.addresses,
					     &tgtq, &tgtr);
	      if (retval)
		  continue;
	
	      /* save tgt in return array */
	      if ((retval = krb5_copy_creds(context, tgtr,
					    &ret_tgts[ntgts]))) {
		  goto cleanup;
	      }
	      krb5_free_creds(context, tgtr);
	      tgtr = NULL;
	
	      tgt = *ret_tgts[ntgts++];
	    }

	    /* got one as close as possible, now start all over */

	    break;
	  }

	  if (next_server == top_server) {
	      goto cleanup;
	  }
	  continue;
        }

	/*
	 * Got a tgt.  If it is for the target realm we can go try for the
	 * credentials.  If it is not for the target realm, then make sure it
	 * is in the realms hierarchy and if so, save it and start the loop
	 * over from there.  Note that we only need to compare the instance
	 * names since that is the target realm of the tgt.
	 */

	for (next_server = top_server; *next_server; next_server++) {
            krb5_data *realm_1 = krb5_princ_component(context, next_server[0], 1);
            krb5_data *realm_2 = krb5_princ_component(context, tgtr->server, 1);
            if (realm_1 != NULL &&
		realm_2 != NULL &&
		realm_1->length == realm_2->length &&
                !memcmp(realm_1->data, realm_2->data, realm_1->length)) {
		break;
            }
	}

	if (!next_server) {
	    retval = KRB5_KDCREP_MODIFIED;
	    goto cleanup;
	}

	if ((retval = krb5_copy_creds(context, tgtr, &ret_tgts[ntgts]))) {
	    goto cleanup;
	}
	krb5_free_creds(context, tgtr);
	tgtr = NULL;

        tgt = *ret_tgts[ntgts++];

        /* we're done if it is the target */

        if (!*next_server++) break;
      }
    }
  }

  /* got/finally have tgt!  try for the creds */

  if (!krb5_c_valid_enctype(tgt.keyblock.enctype)) {
    retval = KRB5_PROG_ETYPE_NOSUPP;
    goto cleanup;
  }

  context->use_conf_ktypes = old_use_conf_ktypes;
  retval = krb5_get_cred_via_tkt(context, &tgt,
				 FLAGS2OPTS(tgt.ticket_flags) |
				 kdcopt |
  				 (in_cred->second_ticket.length ?
				  KDC_OPT_ENC_TKT_IN_SKEY : 0),
				 tgt.addresses, in_cred, out_cred);

  /* cleanup and return */

cleanup:

  if (tgtr) krb5_free_creds(context, tgtr);
  if(tgs_list)  krb5_free_realm_tree(context, tgs_list);
  krb5_free_cred_contents(context, &tgtq);
  if (int_server) krb5_free_principal(context, int_server);
  if (ntgts == 0) {
      *tgts = NULL;
      if (ret_tgts)  free(ret_tgts);
      krb5_free_cred_contents(context, &tgt);
  }
  context->use_conf_ktypes = old_use_conf_ktypes;
  return(retval);
}

krb5_error_code
krb5_get_cred_from_kdc(krb5_context context, krb5_ccache ccache, krb5_creds *in_cred, krb5_creds **out_cred, krb5_creds ***tgts)
{

  return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
				    0);
}

krb5_error_code
krb5_get_cred_from_kdc_validate(krb5_context context, krb5_ccache ccache, krb5_creds *in_cred, krb5_creds **out_cred, krb5_creds ***tgts)
{

  return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
				    KDC_OPT_VALIDATE);
}

krb5_error_code
krb5_get_cred_from_kdc_renew(krb5_context context, krb5_ccache ccache, krb5_creds *in_cred, krb5_creds **out_cred, krb5_creds ***tgts)
{

  return krb5_get_cred_from_kdc_opt(context, ccache, in_cred, out_cred, tgts,
				    KDC_OPT_RENEW);
}
