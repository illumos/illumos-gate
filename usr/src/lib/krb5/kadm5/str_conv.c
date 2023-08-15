/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * lib/kadm/str_conv.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/*
 * str_conv.c - Convert between strings and Kerberos internal data.
 */

/*
 * Table of contents:
 *
 * String decoding:
 * ----------------
 * krb5_string_to_flags()	- Convert string to krb5_flags.
 *
 * String encoding:
 * ----------------
 * krb5_flags_to_string()	- Convert krb5_flags to string.
 */

#include "k5-int.h"
#include "admin_internal.h"
#include "adm_proto.h"

/*
 * Local data structures.
 */
struct flags_lookup_entry {
    krb5_flags		fl_flags;		/* Flag			*/
    krb5_boolean	fl_sense;		/* Sense of the flag	*/
    const char *	fl_specifier;		/* How to recognize it	*/
    const char *	fl_output;		/* How to spit it out	*/
};

/*
 * Local strings
 */

static const char default_tupleseps[]   = ", \t";
static const char default_ksaltseps[]   = ":.";

/* Keytype strings */
/* Flags strings */
static const char flags_pdate_in[]	= "postdateable";
static const char flags_fwd_in[]	= "forwardable";
static const char flags_tgtbased_in[]	= "tgt-based";
static const char flags_renew_in[]	= "renewable";
static const char flags_proxy_in[]	= "proxiable";
static const char flags_dup_skey_in[]	= "dup-skey";
static const char flags_tickets_in[]	= "allow-tickets";
static const char flags_preauth_in[]	= "preauth";
static const char flags_hwauth_in[]	= "hwauth";
static const char flags_pwchange_in[]	= "pwchange";
static const char flags_service_in[]	= "service";
static const char flags_pwsvc_in[]	= "pwservice";
static const char flags_md5_in[]	= "md5";
static const char flags_pdate_out[]	= "Not Postdateable";
static const char flags_fwd_out[]	= "Not Forwardable";
static const char flags_tgtbased_out[]	= "No TGT-based requests";
static const char flags_renew_out[]	= "Not renewable";
static const char flags_proxy_out[]	= "Not proxiable";
static const char flags_dup_skey_out[]	= "No DUP_SKEY requests";
static const char flags_tickets_out[]	= "All Tickets Disallowed";
static const char flags_preauth_out[]	= "Preauthorization required";
static const char flags_hwauth_out[]	= "HW Authorization required";
static const char flags_pwchange_out[]	= "Password Change required";
static const char flags_service_out[]	= "Service Disabled";
static const char flags_pwsvc_out[]	= "Password Changing Service";
static const char flags_md5_out[]	= "RSA-MD5 supported";
static const char flags_default_neg[]	= "-";
static const char flags_default_sep[]	= " ";

/*
 * Lookup tables.
 */

static const struct flags_lookup_entry flags_table[] = {
/* flag				sense	input specifier	   output string     */
/*----------------------------- -------	------------------ ------------------*/
{ KRB5_KDB_DISALLOW_POSTDATED,	0,	flags_pdate_in,	   flags_pdate_out   },
{ KRB5_KDB_DISALLOW_FORWARDABLE,0,	flags_fwd_in,	   flags_fwd_out     },
{ KRB5_KDB_DISALLOW_TGT_BASED,	0,	flags_tgtbased_in, flags_tgtbased_out},
{ KRB5_KDB_DISALLOW_RENEWABLE,	0,	flags_renew_in,	   flags_renew_out   },
{ KRB5_KDB_DISALLOW_PROXIABLE,	0,	flags_proxy_in,	   flags_proxy_out   },
{ KRB5_KDB_DISALLOW_DUP_SKEY,	0,	flags_dup_skey_in, flags_dup_skey_out},
{ KRB5_KDB_DISALLOW_ALL_TIX,	0,	flags_tickets_in,  flags_tickets_out },
{ KRB5_KDB_REQUIRES_PRE_AUTH,	1,	flags_preauth_in,  flags_preauth_out },
{ KRB5_KDB_REQUIRES_HW_AUTH,	1,	flags_hwauth_in,   flags_hwauth_out  },
{ KRB5_KDB_REQUIRES_PWCHANGE,	1,	flags_pwchange_in, flags_pwchange_out},
{ KRB5_KDB_DISALLOW_SVR,	0,	flags_service_in,  flags_service_out },
{ KRB5_KDB_PWCHANGE_SERVICE,	1,	flags_pwsvc_in,	   flags_pwsvc_out   },
{ KRB5_KDB_SUPPORT_DESMD5,	1,	flags_md5_in,	   flags_md5_out     }
};
static const int flags_table_nents = sizeof(flags_table)/
				     sizeof(flags_table[0]);


krb5_error_code
krb5_string_to_flags(string, positive, negative, flagsp)
    char	* string;
    const char	* positive;
    const char	* negative;
    krb5_flags	* flagsp;
{
    int 	i;
    int 	found;
    const char	*neg;
    size_t	nsize, psize;
    int		cpos;
    int		sense;

    found = 0;
    /* We need to have a way to negate it. */
    neg = (negative) ? negative : flags_default_neg;
    nsize = strlen(neg);
    psize = (positive) ? strlen(positive) : 0;

    cpos = 0;
    sense = 1;
    /* First check for positive or negative sense */
    if (!strncasecmp(neg, string, nsize)) {
	sense = 0;
	cpos += (int) nsize;
    }
    else if (psize && !strncasecmp(positive, string, psize)) {
	cpos += (int) psize;
    }

    for (i=0; i<flags_table_nents; i++) {
	if (!strcasecmp(&string[cpos], flags_table[i].fl_specifier)) {
	    found = 1;
	    if (sense == (int) flags_table[i].fl_sense)
		*flagsp |= flags_table[i].fl_flags;
	    else
		*flagsp &= ~flags_table[i].fl_flags;

	    break;
	}
    }
    return((found) ? 0 : EINVAL);
}

krb5_error_code
krb5_flags_to_string(flags, sep, buffer, buflen)
    krb5_flags	flags;
    const char	* sep;
    char	* buffer;
    size_t	buflen;
{
    int			i;
    krb5_flags		pflags;
    const char		*sepstring;
    char		*op;
    int			initial;
    krb5_error_code	retval;

    retval = 0;
    op = buffer;
    pflags = 0;
    initial = 1;
    sepstring = (sep) ? sep : flags_default_sep;
    /* Blast through the table matching all we can */
    for (i=0; i<flags_table_nents; i++) {
	if (flags & flags_table[i].fl_flags) {
	    /* Found a match, see if it'll fit into the output buffer */
	    if ((op+strlen(flags_table[i].fl_output)+strlen(sepstring)) <
		(buffer + buflen)) {
		if (!initial) {
		    strcpy(op, sep);
		    op += strlen(sep);
		}
		initial = 0;
		strcpy(op, flags_table[i].fl_output);
		op += strlen(flags_table[i].fl_output);
	    }
	    else {
		retval = ENOMEM;
		break;
	    }
	    /* Keep track of what we matched */
	    pflags |= flags_table[i].fl_flags;
	}
    }
    if (!retval) {
	/* See if there's any leftovers */
	if (flags & ~pflags)
	    retval = EINVAL;
	else if (initial)
	    *buffer = '\0';
    }
    return(retval);
}

krb5_error_code
krb5_input_flag_to_string(flag, buffer, buflen)
    int		flag;
    char	* buffer;
    size_t	buflen;
{
    if(flag < 0 || flag >= flags_table_nents) return ENOENT; /* End of list */
    if(strlen(flags_table[flag].fl_specifier) > buflen) return ENOMEM;
    strcpy(buffer, flags_table[flag].fl_specifier);
    return  0;
}

/*
 * krb5_keysalt_is_present()	- Determine if a key/salt pair is present
 *				  in a list of key/salt tuples.
 *
 *	Salttype may be negative to indicate a search for only a enctype.
 */
krb5_boolean
krb5_keysalt_is_present(ksaltlist, nksalts, enctype, salttype)
    krb5_key_salt_tuple	*ksaltlist;
    krb5_int32		nksalts;
    krb5_enctype	enctype;
    krb5_int32		salttype;
{
    krb5_boolean	foundit;
    int			i;

    foundit = 0;
    if (ksaltlist) {
	for (i=0; i<nksalts; i++) {
	    if ((ksaltlist[i].ks_enctype == enctype) &&
		((ksaltlist[i].ks_salttype == salttype) ||
		 (salttype < 0))) {
		foundit = 1;
		break;
	    }
	}
    }
    return(foundit);
}

/*
 * krb5_string_to_keysalts()	- Convert a string representation to a list
 *				  of key/salt tuples.
 */
krb5_error_code
krb5_string_to_keysalts(string, tupleseps, ksaltseps, dups, ksaltp, nksaltp)
    char		*string;
    const char		*tupleseps;
    const char		*ksaltseps;
    krb5_boolean	dups;
    krb5_key_salt_tuple	**ksaltp;
    krb5_int32		*nksaltp;
{
    krb5_error_code	kret;
    char 		*kp, *sp, *ep;
    char		sepchar, trailchar;
    krb5_enctype	ktype;
    krb5_int32		stype;
    krb5_key_salt_tuple	*savep;
    const char		*tseplist;
    const char		*ksseplist;
    const char		*septmp;
    size_t		len;

    kret = 0;
    kp = string;
    tseplist = (tupleseps) ? tupleseps : default_tupleseps;
    ksseplist = (ksaltseps) ? ksaltseps : default_ksaltseps;
    while (kp) {
	/* Attempt to find a separator */
	ep = (char *) NULL;
	if (*tseplist) {
	    septmp = tseplist;
	    for (ep = strchr(kp, (int) *septmp);
		 *(++septmp) && !ep;
		 ep = strchr(kp, (int) *septmp));
	}

	if (ep) {
	    trailchar = *ep;
	    *ep = '\0';
	    ep++;
	}
	/*
	 * kp points to something (hopefully) of the form:
	 *	<enctype><ksseplist><salttype>
	 *	or
	 *	<enctype>
	 */
	sp = (char *) NULL;
	/* Attempt to find a separator */
	septmp = ksseplist;
	for (sp = strchr(kp, (int) *septmp);
	     *(++septmp) && !sp;
	     sp = strchr(kp, (int)*septmp)); /* Solaris Kerberos */

	if (sp) {
	    /* Separate enctype from salttype */
	    sepchar = *sp;
	    *sp = '\0';
	    sp++;
	}
	else
	    stype = -1;

	/*
	 * Attempt to parse enctype and salttype.  If we parse well
	 * then make sure that it specifies a unique key/salt combo
	 */
	if (!(kret = krb5_string_to_enctype(kp, &ktype)) &&
	    (!sp || !(kret = krb5_string_to_salttype(sp, &stype))) &&
	    (dups ||
	     !krb5_keysalt_is_present(*ksaltp, *nksaltp, ktype, stype))) {

	    /* Squirrel away old keysalt array */
	    savep = *ksaltp;
	    len = (size_t) *nksaltp;

	    /* Get new keysalt array */
	    *ksaltp = (krb5_key_salt_tuple *)
		malloc((len + 1) * sizeof(krb5_key_salt_tuple));
	    if (*ksaltp) {

		/* Copy old keysalt if appropriate */
		if (savep) {
		    memcpy(*ksaltp, savep,
			   len * sizeof(krb5_key_salt_tuple));
		    krb5_xfree(savep);
		}

		/* Save our values */
		(*ksaltp)[(*nksaltp)].ks_enctype = ktype;
		(*ksaltp)[(*nksaltp)].ks_salttype = stype;
		(*nksaltp)++;
	    }
	    else {
		*ksaltp = savep;
		break;
	    }
	}
	/*
	 * Solaris Kerberos
	 * If the string did not yield a valid enctype/keysalt
	 * just ignore it and continue on.  MIT kerberos stops
	 * searching when if finds an unknown string.
	 */
	if (sp)
	    sp[-1] = sepchar;
	if (ep)
	    ep[-1] = trailchar;
	kp = ep;

	/* Skip over extra separators - like spaces */
	if (kp && *tseplist) {
	  septmp = tseplist;
	  while(*septmp && *kp) {
	    if(*septmp == *kp) {
	      /* Increment string - reset separator list */
	      kp++;
	      septmp = tseplist;
	    } else {
	      septmp++;
	    }
	  }
	  if (!*kp) kp = NULL;
	}
    } /* while kp */
    return(kret);
}

/*
 * krb5_keysalt_iterate()	- Do something for each unique key/salt
 *				  combination.
 *
 * If ignoresalt set, then salttype is ignored.
 */
krb5_error_code
krb5_keysalt_iterate(ksaltlist, nksalt, ignoresalt, iterator, arg)
    krb5_key_salt_tuple	*ksaltlist;
    krb5_int32		nksalt;
    krb5_boolean	ignoresalt;
    krb5_error_code	(*iterator) (krb5_key_salt_tuple *, krb5_pointer);
    krb5_pointer	arg;
{
    int			i;
    krb5_error_code	kret;
    krb5_key_salt_tuple	scratch;

    kret = 0;
    for (i=0; i<nksalt; i++) {
	scratch.ks_enctype = ksaltlist[i].ks_enctype;
	scratch.ks_salttype = (ignoresalt) ? -1 : ksaltlist[i].ks_salttype;
	if (!krb5_keysalt_is_present(ksaltlist,
				     i,
				     scratch.ks_enctype,
				     scratch.ks_salttype)) {
	    kret = (*iterator)(&scratch, arg);
	    if (kret)
		break;
	}
    }
    return(kret);
}
