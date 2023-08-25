/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/krb/get_creds.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * krb5_get_credentials()
 */



/*
 Attempts to use the credentials cache or TGS exchange to get an additional
 ticket for the
 client identified by in_creds->client, the server identified by
 in_creds->server, with options options, expiration date specified in
 in_creds->times.endtime (0 means as long as possible), session key type
 specified in in_creds->keyblock.enctype (if non-zero)

 Any returned ticket and intermediate ticket-granting tickets are
 stored in ccache.

 returns errors from encryption routines, system errors
 */

#include "k5-int.h"

/*ARGSUSED*/
static krb5_error_code
krb5_get_credentials_core(krb5_context context, krb5_flags options,
			  krb5_creds *in_creds, krb5_creds *mcreds,
			  krb5_flags *fields)
{
    /* Solaris Kerberos */
    krb5_error_code ret = 0;

    if (!in_creds || !in_creds->server || !in_creds->client)
        return EINVAL;

    memset((char *)mcreds, 0, sizeof(krb5_creds));
    mcreds->magic = KV5M_CREDS;
    /*
     * Solaris Kerberos:
     * Set endtime appropriately to make sure we do not rope in
     * expired creds. If endtime is set to 0 (which it almost always
     * is, courtesy memset/calloc) the krb5_cc_retrieve_cred() call in
     * krb5_get_credentials() with KRB5_TC_MATCH_TIMES will
     * succeed and return the expired cred.
     *
     * Hence, endtime below is set to "now" if in_creds->times.endtime
     * is 0, so that krb5_cc_retrieve_cred fails and we get fresh creds,
     * if necessary. But, if in_creds has a non-zero endtime, we honor it.
     */
    if (in_creds->times.endtime != 0)
	mcreds->times.endtime = in_creds->times.endtime;
    else
	if ((ret = krb5_timeofday(context, &mcreds->times.endtime)) != 0)
		return (ret);

    ret = krb5_copy_keyblock_contents(context, &in_creds->keyblock,
		&mcreds->keyblock);
    if (ret)
	return (ret);

    mcreds->authdata = in_creds->authdata;
    mcreds->server = in_creds->server;
    mcreds->client = in_creds->client;

    *fields = KRB5_TC_MATCH_TIMES /*XXX |KRB5_TC_MATCH_SKEY_TYPE */
	| KRB5_TC_MATCH_AUTHDATA
	| KRB5_TC_SUPPORTED_KTYPES;
    if (mcreds->keyblock.enctype) {
	krb5_enctype *ktypes;
	int i;

	*fields |= KRB5_TC_MATCH_KTYPE;
	ret = krb5_get_tgs_ktypes (context, mcreds->server, &ktypes);
	for (i = 0; ktypes[i]; i++)
	    if (ktypes[i] == mcreds->keyblock.enctype)
		break;
	if (ktypes[i] == 0)
	    ret = KRB5_CC_NOT_KTYPE;
	free (ktypes);
	if (ret) {
	    krb5_free_keyblock_contents(context, &mcreds->keyblock);
	    return ret;
	}
    }
    if (options & KRB5_GC_USER_USER) {
	/* also match on identical 2nd tkt and tkt encrypted in a
	   session key */
	*fields |= KRB5_TC_MATCH_2ND_TKT|KRB5_TC_MATCH_IS_SKEY;
	mcreds->is_skey = TRUE;
	mcreds->second_ticket = in_creds->second_ticket;
	if (!in_creds->second_ticket.length) {
	    krb5_free_keyblock_contents(context, &mcreds->keyblock);
	    return KRB5_NO_2ND_TKT;
	}
    }

    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_get_credentials(krb5_context context, krb5_flags options,
		     krb5_ccache ccache, krb5_creds *in_creds,
		     krb5_creds **out_creds)
{
    krb5_error_code retval;
    krb5_creds mcreds;
    krb5_creds *ncreds;
    krb5_creds **tgts;
    krb5_flags fields;
    int not_ktype;

    retval = krb5_get_credentials_core(context, options,
				       in_creds,
				       &mcreds, &fields);

    if (retval) return retval;

    if ((ncreds = (krb5_creds *)malloc(sizeof(krb5_creds))) == NULL) {
	krb5_free_keyblock_contents(context, &mcreds.keyblock);
	return ENOMEM;
    }

    memset((char *)ncreds, 0, sizeof(krb5_creds));
    ncreds->magic = KV5M_CREDS;

    /* The caller is now responsible for cleaning up in_creds */
    /* Solaris Kerberos */
    if ((retval = krb5_cc_retrieve_cred(context, ccache, fields, &mcreds,
					ncreds)) !=0) {
	krb5_xfree(ncreds);
	ncreds = in_creds;
    } else {
	*out_creds = ncreds;
    }

    if ((retval != KRB5_CC_NOTFOUND && retval != KRB5_CC_NOT_KTYPE)
	|| options & KRB5_GC_CACHED) {
	krb5_free_keyblock_contents(context, &mcreds.keyblock);
	return retval;
    }

    if (retval == KRB5_CC_NOT_KTYPE)
	not_ktype = 1;
    else
	not_ktype = 0;

    retval = krb5_get_cred_from_kdc(context, ccache, ncreds, out_creds, &tgts);
    if (tgts) {
	register int i = 0;
	krb5_error_code rv2;
	while (tgts[i]) {
	    /* Solaris Kerberos */
	    if ((rv2 = krb5_cc_store_cred(context, ccache, tgts[i])) != 0) {
		retval = rv2;
		break;
	    }
	    i++;
	}
	krb5_free_tgt_creds(context, tgts);
    }
    /*
     * Translate KRB5_CC_NOTFOUND if we previously got
     * KRB5_CC_NOT_KTYPE from krb5_cc_retrieve_cred(), in order to
     * handle the case where there is no TGT in the ccache and the
     * input enctype didn't match.  This handling is necessary because
     * some callers, such as GSSAPI, iterate through enctypes and
     * KRB5_CC_NOTFOUND passed through from the
     * krb5_get_cred_from_kdc() is semantically incorrect, since the
     * actual failure was the non-existence of a ticket of the correct
     * enctype rather than the missing TGT.
     */
    if ((retval == KRB5_CC_NOTFOUND || retval == KRB5_CC_NOT_KTYPE)
	&& not_ktype)
	retval = KRB5_CC_NOT_KTYPE;

    if (!retval) {
        /* the purpose of the krb5_get_credentials call is to
         * obtain a set of credentials for the caller.  the
         * krb5_cc_store_cred() call is to optimize performance
         * for future calls.  Ignore any errors, since the credentials
         * are still valid even if we fail to store them in the cache.
         */
	/* Solaris Kerberos */
	retval = krb5_cc_store_cred(context, ccache, *out_creds);
    }

    krb5_free_keyblock_contents(context, &mcreds.keyblock);
    return retval;
}

#define INT_GC_VALIDATE 1
#define INT_GC_RENEW 2

/*ARGSUSED*/
static krb5_error_code
krb5_get_credentials_val_renew_core(krb5_context context, krb5_flags options,
				    krb5_ccache ccache, krb5_creds *in_creds,
				    krb5_creds **out_creds, int which)
{
    krb5_error_code retval;
    krb5_principal tmp;
    krb5_creds **tgts = 0;

    switch(which) {
    case INT_GC_VALIDATE:
	    retval = krb5_get_cred_from_kdc_validate(context, ccache,
					     in_creds, out_creds, &tgts);
	    break;
    case INT_GC_RENEW:
	    retval = krb5_get_cred_from_kdc_renew(context, ccache,
					     in_creds, out_creds, &tgts);
	    break;
    default:
	    /* Should never happen */
	    retval = 255;
	    break;
    }
    if (retval) return retval;
    if (tgts) krb5_free_tgt_creds(context, tgts);

    retval = krb5_cc_get_principal(context, ccache, &tmp);
    if (retval) return retval;

    retval = krb5_cc_initialize(context, ccache, tmp);
    /* Solaris Kerberos */
    if (retval) {
	krb5_free_principal(context, tmp);
	return retval;
    }

    retval = krb5_cc_store_cred(context, ccache, *out_creds);
    krb5_free_principal(context, tmp);
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_get_credentials_validate(krb5_context context, krb5_flags options,
			      krb5_ccache ccache, krb5_creds *in_creds,
			      krb5_creds **out_creds)
{
    return(krb5_get_credentials_val_renew_core(context, options, ccache,
					       in_creds, out_creds,
					       INT_GC_VALIDATE));
}

krb5_error_code KRB5_CALLCONV
krb5_get_credentials_renew(krb5_context context, krb5_flags options,
			   krb5_ccache ccache, krb5_creds *in_creds,
			   krb5_creds **out_creds)
{

    return(krb5_get_credentials_val_renew_core(context, options, ccache,
					       in_creds, out_creds,
					       INT_GC_RENEW));
}

static krb5_error_code
krb5_validate_or_renew_creds(krb5_context context, krb5_creds *creds,
			     krb5_principal client, krb5_ccache ccache,
			     char *in_tkt_service, int validate)
{
    krb5_error_code ret;
    krb5_creds in_creds; /* only client and server need to be filled in */
    krb5_creds *out_creds = 0; /* for check before dereferencing below */
    krb5_creds **tgts;

    memset((char *)&in_creds, 0, sizeof(krb5_creds));

    in_creds.server = NULL;
    tgts = NULL;

    in_creds.client = client;

    if (in_tkt_service) {
	/* this is ugly, because so are the data structures involved.  I'm
	   in the library, so I'm going to manipulate the data structures
	   directly, otherwise, it will be worse. */

        if ((ret = krb5_parse_name(context, in_tkt_service, &in_creds.server)))
	    goto cleanup;

	/* stuff the client realm into the server principal.
	   realloc if necessary */
	if (in_creds.server->realm.length < in_creds.client->realm.length)
	    if ((in_creds.server->realm.data =
		 (char *) realloc(in_creds.server->realm.data,
				  in_creds.client->realm.length)) == NULL) {
		ret = ENOMEM;
		goto cleanup;
	    }

	in_creds.server->realm.length = in_creds.client->realm.length;
	memcpy(in_creds.server->realm.data, in_creds.client->realm.data,
	       in_creds.client->realm.length);
    } else {
	if ((ret = krb5_build_principal_ext(context, &in_creds.server,
					   in_creds.client->realm.length,
					   in_creds.client->realm.data,
					   KRB5_TGS_NAME_SIZE,
					   KRB5_TGS_NAME,
					   in_creds.client->realm.length,
					   in_creds.client->realm.data,
					    0)))
	    goto cleanup;
    }

    if (validate)
	ret = krb5_get_cred_from_kdc_validate(context, ccache,
					      &in_creds, &out_creds, &tgts);
    else
	ret = krb5_get_cred_from_kdc_renew(context, ccache,
					   &in_creds, &out_creds, &tgts);

    /* ick.  copy the struct contents, free the container */
    if (out_creds) {
	*creds = *out_creds;
	krb5_xfree(out_creds);
    }

cleanup:

    if (in_creds.server)
	krb5_free_principal(context, in_creds.server);
    if (tgts)
	krb5_free_tgt_creds(context, tgts);

    return(ret);
}

krb5_error_code KRB5_CALLCONV
krb5_get_validated_creds(krb5_context context, krb5_creds *creds, krb5_principal client, krb5_ccache ccache, char *in_tkt_service)
{
    return(krb5_validate_or_renew_creds(context, creds, client, ccache,
					in_tkt_service, 1));
}

krb5_error_code KRB5_CALLCONV
krb5_get_renewed_creds(krb5_context context, krb5_creds *creds, krb5_principal client, krb5_ccache ccache, char *in_tkt_service)
{
    return(krb5_validate_or_renew_creds(context, creds, client, ccache,
					in_tkt_service, 0));
}
