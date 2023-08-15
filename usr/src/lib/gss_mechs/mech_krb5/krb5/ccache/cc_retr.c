/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/ccache/cc_retr.c
 *
 * Copyright 1990,1991,1999 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include "cc-int.h"

#define KRB5_OK 0

#define set(bits) (whichfields & bits)
#define flags_match(a,b) (((a) & (b)) == (a))
#define times_match_exact(t1,t2) (memcmp((char *)(t1), (char *)(t2), sizeof(*(t1))) == 0)

static krb5_boolean
times_match(const krb5_ticket_times *t1, const krb5_ticket_times *t2)
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
standard_fields_match(krb5_context context, const krb5_creds *mcreds, const krb5_creds *creds)
{
  return (krb5_principal_compare(context, mcreds->client,creds->client)
	  && krb5_principal_compare(context, mcreds->server,creds->server));
}

/* only match the server name portion, not the server realm portion */

static krb5_boolean
srvname_match(krb5_context context, const krb5_creds *mcreds, const krb5_creds *creds)
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
authdata_match(krb5_authdata *const *mdata, krb5_authdata *const *data)
{
    const krb5_authdata *mdatap, *datap;

    if (mdata == data)
      return TRUE;

    if (mdata == NULL)
	return *data == NULL;

    if (data == NULL)
	return *mdata == NULL;

    /*LINTED*/
    while ((mdatap = *mdata) && (datap = *data)) {
      if ((mdatap->ad_type != datap->ad_type) ||
          (mdatap->length != datap->length) ||
          (memcmp ((char *)mdatap->contents,
		 (char *)datap->contents, (unsigned) mdatap->length) != 0))
          return FALSE;
      mdata++;
      data++;
    }
    return (*mdata == NULL) && (*data == NULL);
}

static krb5_boolean
data_match(const krb5_data *data1, const krb5_data *data2)
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
	return memcmp(data1->data, data2->data, (unsigned) data1->length)
	  ? FALSE : TRUE;
}

static int
pref (krb5_enctype my_ktype, int nktypes, krb5_enctype *ktypes)
{
  int i;
  for (i = 0; i < nktypes; i++)
    if (my_ktype == ktypes[i])
      return i;
  return -1;
}

/*
 * Effects:
 * Searches the credentials cache for a credential matching mcreds,
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
 * Flag SUPPORTED_KTYPES means check all matching entries that have
 * any supported enctype (according to tgs_enctypes) and return the one
 * with the enctype listed earliest.  Return CC_NOT_KTYPE if a match
 * is found *except* for having a supported enctype.
 *
 * Errors:
 * system errors
 * permission errors
 * KRB5_CC_NOMEM
 * KRB5_CC_NOT_KTYPE
 */

krb5_boolean
krb5int_cc_creds_match_request(krb5_context context, krb5_flags whichfields, krb5_creds *mcreds, krb5_creds *creds)
{
    if (((set(KRB5_TC_MATCH_SRV_NAMEONLY) &&
		   srvname_match(context, mcreds, creds)) ||
	       standard_fields_match(context, mcreds, creds))
	      &&
	      (! set(KRB5_TC_MATCH_IS_SKEY) ||
	       mcreds->is_skey == creds->is_skey)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS_EXACT) ||
	       mcreds->ticket_flags == creds->ticket_flags)
	      &&
	      (! set(KRB5_TC_MATCH_FLAGS) ||
	       flags_match(mcreds->ticket_flags, creds->ticket_flags))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES_EXACT) ||
	       times_match_exact(&mcreds->times, &creds->times))
	      &&
	      (! set(KRB5_TC_MATCH_TIMES) ||
	       times_match(&mcreds->times, &creds->times))
	      &&
	      ( ! set(KRB5_TC_MATCH_AUTHDATA) ||
	       authdata_match(mcreds->authdata, creds->authdata))
	      &&
	      (! set(KRB5_TC_MATCH_2ND_TKT) ||
	       data_match (&mcreds->second_ticket, &creds->second_ticket))
	      &&
	     ((! set(KRB5_TC_MATCH_KTYPE))||
		(mcreds->keyblock.enctype == creds->keyblock.enctype)))
        return TRUE;
    return FALSE;
}

static krb5_error_code
krb5_cc_retrieve_cred_seq (krb5_context context, krb5_ccache id,
			   krb5_flags whichfields, krb5_creds *mcreds,
			   krb5_creds *creds, int nktypes, krb5_enctype *ktypes)
{
     /* This function could be considerably faster if it kept indexing */
     /* information.. sounds like a "next version" idea to me. :-) */

     krb5_cc_cursor cursor;
     krb5_error_code kret;
     krb5_error_code nomatch_err = KRB5_CC_NOTFOUND;
     struct {
       krb5_creds creds;
       int pref;
     } fetched, best;
     int have_creds = 0;
     krb5_flags oflags = 0;
#define fetchcreds (fetched.creds)

     /* Solaris Kerberos */
     memset(&best, 0, sizeof (best));
     memset(&fetched, 0, sizeof (fetched));

     kret = krb5_cc_get_flags(context, id, &oflags);
     if (kret != KRB5_OK)
	  return kret;
     if (oflags & KRB5_TC_OPENCLOSE)
	 (void) krb5_cc_set_flags(context, id, oflags & ~KRB5_TC_OPENCLOSE);
     kret = krb5_cc_start_seq_get(context, id, &cursor);
     if (kret != KRB5_OK) {
	  if (oflags & KRB5_TC_OPENCLOSE)
	       krb5_cc_set_flags(context, id, oflags);
	  return kret;
     }

     while ((kret = krb5_cc_next_cred(context, id, &cursor, &fetchcreds)) == KRB5_OK) {
      if (krb5int_cc_creds_match_request(context, whichfields, mcreds, &fetchcreds))
      {
	      if (ktypes) {
		  fetched.pref = pref (fetchcreds.keyblock.enctype,
				       nktypes, ktypes);
		  if (fetched.pref < 0)
		      nomatch_err = KRB5_CC_NOT_KTYPE;
		  else if (!have_creds || fetched.pref < best.pref) {
		      if (have_creds)
			  krb5_free_cred_contents (context, &best.creds);
		      else
			  have_creds = 1;
		      best = fetched;
		      continue;
		  }
	      } else {
		  krb5_cc_end_seq_get(context, id, &cursor);
		  *creds = fetchcreds;
		  /* Solaris Kerberos */
		  creds->keyblock.hKey = CK_INVALID_HANDLE;
		  if (oflags & KRB5_TC_OPENCLOSE)
		      krb5_cc_set_flags(context, id, oflags);
		  return KRB5_OK;
	      }
	  }

	  /* This one doesn't match */
	  krb5_free_cred_contents(context, &fetchcreds);
     }

     /* If we get here, a match wasn't found */
     krb5_cc_end_seq_get(context, id, &cursor);
     if (oflags & KRB5_TC_OPENCLOSE)
	 krb5_cc_set_flags(context, id, oflags);
     if (have_creds) {
	 *creds = best.creds;
	 /* Solaris Kerberos */
	 creds->keyblock.hKey = CK_INVALID_HANDLE;
	 return KRB5_OK;
     } else
	 return nomatch_err;
}

krb5_error_code KRB5_CALLCONV
krb5_cc_retrieve_cred_default (krb5_context context, krb5_ccache id, krb5_flags flags, krb5_creds *mcreds, krb5_creds *creds)
{
    krb5_enctype *ktypes;
    int nktypes;
    krb5_error_code ret;

    if (flags & KRB5_TC_SUPPORTED_KTYPES) {
	ret = krb5_get_tgs_ktypes (context, mcreds->server, &ktypes);
	if (ret)
	    return ret;
	nktypes = 0;
	while (ktypes[nktypes])
	    nktypes++;

	ret = krb5_cc_retrieve_cred_seq (context, id, flags, mcreds, creds,
					 nktypes, ktypes);
	free (ktypes);
	return ret;
    } else {
	/* Solaris Kerberos */
	return krb5_cc_retrieve_cred_seq (context, id, flags, mcreds, creds,
					  0, (krb5_enctype *)NULL);
    }
}

/* The following function duplicates some of the functionality above and */
/* should probably be merged with it at some point.  It is used by the   */
/* CCAPI krb5_cc_remove to figure out if the opaque credentials object   */
/* returned by the CCAPI is the same creds as the caller passed in.      */
/* Unlike the code above it requires that all structures be identical.   */

krb5_boolean KRB5_CALLCONV
krb5_creds_compare (krb5_context in_context,
                    krb5_creds *in_creds,
                    krb5_creds *in_compare_creds)
{
    /* Set to 0 when we hit the first mismatch and then fall through */
    int equal = 1;

    if (equal) {
        equal = krb5_principal_compare (in_context, in_creds->client,
                                        in_compare_creds->client);
    }

    if (equal) {
        equal = krb5_principal_compare (in_context, in_creds->server,
                                        in_compare_creds->server);
    }

    if (equal) {
        equal = (in_creds->keyblock.enctype == in_compare_creds->keyblock.enctype &&
                 in_creds->keyblock.length  == in_compare_creds->keyblock.length &&
                 (!in_creds->keyblock.length ||
                  !memcmp (in_creds->keyblock.contents, in_compare_creds->keyblock.contents,
                           in_creds->keyblock.length)));
    }

    if (equal) {
        equal = (in_creds->times.authtime   == in_compare_creds->times.authtime &&
                 in_creds->times.starttime  == in_compare_creds->times.starttime &&
                 in_creds->times.endtime    == in_compare_creds->times.endtime &&
                 in_creds->times.renew_till == in_compare_creds->times.renew_till);
    }

    if (equal) {
        equal = (in_creds->is_skey == in_compare_creds->is_skey);
    }

    if (equal) {
        equal = (in_creds->ticket_flags == in_compare_creds->ticket_flags);
    }

    if (equal) {
        krb5_address **addresses = in_creds->addresses;
        krb5_address **compare_addresses = in_compare_creds->addresses;
        unsigned int i;

        if (addresses && compare_addresses) {
            for (i = 0; (equal && addresses[i] && compare_addresses[i]); i++) {
                equal = krb5_address_compare (in_context, addresses[i],
                                              compare_addresses[i]);
            }
            if (equal) { equal = (!addresses[i] && !compare_addresses[i]); }
        } else {
            if (equal) { equal = (!addresses && !compare_addresses); }
        }
    }

    if (equal) {
        equal = (in_creds->ticket.length  == in_compare_creds->ticket.length &&
                 (!in_creds->ticket.length ||
                  !memcmp (in_creds->ticket.data, in_compare_creds->ticket.data,
                           in_creds->ticket.length)));
    }

    if (equal) {
        equal = (in_creds->second_ticket.length  == in_compare_creds->second_ticket.length &&
                 (!in_creds->second_ticket.length ||
                  !memcmp (in_creds->second_ticket.data, in_compare_creds->second_ticket.data,
                           in_creds->second_ticket.length)));
    }

    if (equal) {
        krb5_authdata **authdata = in_creds->authdata;
        krb5_authdata **compare_authdata = in_compare_creds->authdata;
        unsigned int i;

        if (authdata && compare_authdata) {
            for (i = 0; (equal && authdata[i] && compare_authdata[i]); i++) {
                equal = (authdata[i]->ad_type == compare_authdata[i]->ad_type &&
                         authdata[i]->length  == compare_authdata[i]->length &&
                         (!authdata[i]->length ||
                          !memcmp (authdata[i]->contents, compare_authdata[i]->contents,
                                   authdata[i]->length)));
            }
            if (equal) { equal = (!authdata[i] && !compare_authdata[i]); }
        } else {
            if (equal) { equal = (!authdata && !compare_authdata); }
        }
    }

    return equal;
}
