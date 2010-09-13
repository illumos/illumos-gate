#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/ser_rc.c
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
 * ser_rcdfl.c - Serialize replay cache context.
 */
#include "k5-int.h"

/*
 * Routines to deal with externalizing krb5_ccache.
 *	krb5_ccache_size();
 *	krb5_ccache_externalize();
 *	krb5_ccache_internalize();
 */
static krb5_error_code krb5_ccache_size
	(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_ccache_externalize
	(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_ccache_internalize
	(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/*
 * Serialization entry for this type.
 */
static const krb5_ser_entry krb5_ccache_ser_entry = {
    KV5M_CCACHE,			/* Type			*/
    krb5_ccache_size,			/* Sizer routine	*/
    krb5_ccache_externalize,		/* Externalize routine	*/
    krb5_ccache_internalize		/* Internalize routine	*/
};

/*
 * krb5_ccache_size()	- Determine the size required to externalize
 *				  this krb5_ccache variant.
 */
static krb5_error_code
krb5_ccache_size(krb5_context kcontext, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_ccache		ccache;
    size_t		required;

    kret = EINVAL;
    if ((ccache = (krb5_ccache) arg)) {
	/*
	 * Saving FILE: variants of krb5_ccache requires at minimum:
	 *	krb5_int32	for KV5M_CCACHE
	 *	krb5_int32	for length of ccache name.
	 *	krb5_int32	for KV5M_CCACHE
	 */
	required = sizeof(krb5_int32) * 3;
	if (ccache->ops && ccache->ops->prefix)
	    required += (strlen(ccache->ops->prefix)+1);

	/*
	 * The ccache name is formed as follows:
	 *	<prefix>:<name>
	 */
	required += strlen(krb5_cc_get_name(kcontext, ccache));

	kret = 0;
	*sizep += required;
    }
    return(kret);
}

/*
 * krb5_ccache_externalize()	- Externalize the krb5_ccache.
 */
static krb5_error_code
krb5_ccache_externalize(krb5_context kcontext, krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_ccache		ccache;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;
    char		*ccname;
    size_t		namelen;
    const char		*fnamep;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((ccache = (krb5_ccache) arg)) {
	kret = ENOMEM;
	if (!krb5_ccache_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KV5M_CCACHE, &bp, &remain);

	    /* Calculate the length of the name */
	    namelen = (ccache->ops && ccache->ops->prefix) ?
		strlen(ccache->ops->prefix)+1 : 0;
	    fnamep = krb5_cc_get_name(kcontext, ccache);
	    namelen += (strlen(fnamep)+1);

	    if ((ccname = (char *) malloc(namelen))) {
		/* Format the ccache name. */
		if (ccache->ops && ccache->ops->prefix)
		    sprintf(ccname, "%s:%s", ccache->ops->prefix, fnamep);
		else
		    strcpy(ccname, fnamep);

		/* Put the length of the file name */
		(void) krb5_ser_pack_int32((krb5_int32) strlen(ccname),
					   &bp, &remain);
		
		/* Put the name */
		(void) krb5_ser_pack_bytes((krb5_octet *) ccname,
					   strlen(ccname),
					   &bp, &remain);

		/* Put the trailer */
		(void) krb5_ser_pack_int32(KV5M_CCACHE, &bp, &remain);
		kret = 0;
		*buffer = bp;
		*lenremain = remain;
		free(ccname);
	    }
	}
    }
    return(kret);
}

/*
 * krb5_ccache_internalize()	- Internalize the krb5_ccache.
 */
static krb5_error_code
krb5_ccache_internalize(krb5_context kcontext, krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_ccache		ccache;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    char		*ccname;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KV5M_CCACHE) {
	kret = ENOMEM;

	/* Get the length of the ccache name */
	kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain);

	if (!kret &&
	    (ccname = (char *) malloc((size_t) (ibuf+1))) &&
	    !(kret = krb5_ser_unpack_bytes((krb5_octet *) ccname,
					   (size_t) ibuf,
					   &bp, &remain))) {
	    ccname[ibuf] = '\0';
	    if (!(kret = krb5_cc_resolve(kcontext, ccname, &ccache)) &&
		!(kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain)) &&
		(ibuf == KV5M_CCACHE)) {
		*buffer = bp;
		*lenremain = remain;
		*argp = (krb5_pointer) ccache;
	    }
	    free(ccname);
	}
    }
    return(kret);
}

/*
 * Register the ccache serializer.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_ccache_init(krb5_context kcontext)
{
    return(krb5_register_serializer(kcontext, &krb5_ccache_ser_entry));
}
