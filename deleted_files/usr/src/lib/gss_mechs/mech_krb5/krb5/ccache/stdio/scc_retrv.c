/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/stdio/scc_retrv.c
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
 * This file contains the source code for krb5_scc_retrieve.
 */

#if 0

#include "scc.h"

#define set(bits) (whichfields & bits)
#define flags_match(a,b) (((a) & (b)) == (a))

static krb5_boolean
times_match(t1, t2)
register const krb5_ticket_times *t1;
register const krb5_ticket_times *t2;
{
    if (t1->renew_till) {
	if (t1->renew_till > t2->renew_till)
	    return FALSE;		/* this one expires too late */
    }
    if (t1->endtime) {
	if (t1->endtime > t2->endtime)
	    return FALSE;		/* this one expires too late */
    }
    /* only care about expiration on a times_match */
    return TRUE;
}

static krb5_boolean
times_match_exact (t1, t2)
    register const krb5_ticket_times *t1, *t2;
{
    return (t1->authtime == t2->authtime
	    && t1->starttime == t2->starttime
	    && t1->endtime == t2->endtime
	    && t1->renew_till == t2->renew_till);
}

static krb5_boolean
standard_fields_match(context, mcreds, creds)
   krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    return (krb5_principal_compare(context, mcreds->client,creds->client) &&
	    krb5_principal_compare(context, mcreds->server,creds->server));
}

/* only match the server name portion, not the server realm portion */

static krb5_boolean
srvname_match(context, mcreds, creds)
   krb5_context context;
register const krb5_creds *mcreds, *creds;
{
    krb5_boolean retval;
    krb5_principal_data p1, p2;

    retval = krb5_principal_compare(context, mcreds->client,creds->client);
    if (retval != TRUE)
	return retval;
    /*
     * Hack to ignore the server realm for the purposes of the compare.
     */
    p1 = *mcreds->server;
    p2 = *creds->server;
    p1.realm = p2.realm;
    return krb5_principal_compare(context, &p1, &p2);
}


static krb5_boolean
authdata_match(mdata, data)
    krb5_authdata *const *mdata, *const *data;
{
    const krb5_authdata *mdatap, *datap;

    if (mdata == data)
	return TRUE;

    if (mdata == NULL)
	return *data == NULL;

    if (data == NULL)
	return *mdata == NULL;

    while ((mdatap = *mdata)
	   && (datap = *data)
	   && mdatap->ad_type == datap->ad_type
	   && mdatap->length == datap->length
	   && !memcmp ((char *) mdatap->contents, (char *) datap->contents,
		       datap->length)) {
	mdata++;
	data++;
    }

    return !*mdata && !*data;
}

static krb5_boolean
data_match(data1, data2)
register const krb5_data *data1, *data2;
{
    if (!data1) {
	if (!data2)
	    return TRUE;
	else
	    return FALSE;
    }
    if (!data2) return FALSE;

    if (data1->length != data2->length)
	return FALSE;
    else
	return memcmp(data1->data, data2->data, data1->length) ? FALSE : TRUE;
}


/*
 * Effects:
 * Searches the file cred cache is for a credential matching mcreds,
 * with the fields specified by whichfields.  If one if found, it is
 * returned in creds, which should be freed by the caller with
 * krb5_free_credentials().
 *
 * The fields are interpreted in the following way (all constants are
 * preceded by KRB5_TC_).  MATCH_IS_SKEY requires the is_skey field to
 * match exactly.  MATCH_TIMES requires the requested lifetime to be
 * at least as great as that specified; MATCH_TIMES_EXACT requires the
 * requested lifetime to be exactly that specified.  MATCH_FLAGS
 * requires only the set bits in mcreds be set in creds;
 * MATCH_FLAGS_EXACT requires all bits to match.
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_CC_NOMEM
 */
krb5_error_code
krb5_scc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
     /* This function could be considerably faster if it kept indexing */
     /* information.. sounds like a "next version" idea to me. :-) */

     krb5_cc_cursor cursor;
     krb5_error_code kret;
     krb5_creds fetchcreds;

     kret = krb5_scc_start_seq_get(context, id, &cursor);
     if (kret != KRB5_OK)
	  return kret;

     while ((kret = krb5_scc_next_cred(context, id, &cursor, &fetchcreds)) == KRB5_OK) {
	  if (((set(KRB5_TC_MATCH_SRV_NAMEONLY) &&
		   srvname_match(context, mcreds, &fetchcreds)) ||
	       standard_fields_match(context, mcreds, &fetchcreds))
	      &&
	      (! set(KRB5_TC_MATCH_IS_SKEY) ||
	       mcreds->is_skey == fetchcreds.is_skey)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS_EXACT) ||
	       mcreds->ticket_flags == fetchcreds.ticket_flags)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS) ||
	       flags_match(mcreds->ticket_flags, fetchcreds.ticket_flags))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES_EXACT) ||
	       times_match_exact(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES) ||
	       times_match(&mcreds->times, &fetchcreds.times))
	      &&
	      (! set(KRB5_TC_MATCH_AUTHDATA) ||
	       authdata_match (mcreds->authdata, fetchcreds.authdata))
	      &&
	      (! set(KRB5_TC_MATCH_2ND_TKT) ||
	       data_match (&mcreds->second_ticket, &fetchcreds.second_ticket))
	      &&
	      ((! set(KRB5_TC_MATCH_KTYPE))||
		  (mcreds->keyblock.enctype == fetchcreds.keyblock.enctype))
	      )
	  {
	       krb5_scc_end_seq_get(context, id, &cursor);
	       *creds = fetchcreds;
	       return KRB5_OK;
	  }

	  /* This one doesn't match */
	  krb5_free_cred_contents(context, &fetchcreds);
     }

     /* If we get here, a match wasn't found */
     krb5_scc_end_seq_get(context, id, &cursor);
     return KRB5_CC_NOTFOUND;
}

#else

#include <k5-int.h>

krb5_error_code KRB5_CALLCONV
krb5_scc_retrieve(context, id, whichfields, mcreds, creds)
   krb5_context context;
   krb5_ccache id;
   krb5_flags whichfields;
   krb5_creds *mcreds;
   krb5_creds *creds;
{
    return krb5_cc_retrieve_cred_default (context, id, whichfields,
					  mcreds, creds);
}

#endif
