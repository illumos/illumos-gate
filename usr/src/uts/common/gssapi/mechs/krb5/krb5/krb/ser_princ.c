/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/krb/ser_princ.c
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
 * ser_princ.c - Serialize a krb5_principal structure.
 */
#include "k5-int.h"
#include "int-proto.h"

/*
 * Routines to deal with externalizing the krb5_principal:
 *	krb5_principal_size();
 *	krb5_principal_externalize();
 *	krb5_principal_internalize();
 */
static krb5_error_code krb5_principal_size
	(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_principal_externalize
	(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_principal_internalize
	(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/* Local data */
static const krb5_ser_entry krb5_principal_ser_entry = {
    KV5M_PRINCIPAL,			/* Type			*/
    krb5_principal_size,		/* Sizer routine	*/
    krb5_principal_externalize,		/* Externalize routine	*/
    krb5_principal_internalize		/* Internalize routine	*/
};

/*
 * krb5_principal_size()	- Determine the size required to externalize
 *				  the krb5_principal.
 */
static krb5_error_code
krb5_principal_size(krb5_context kcontext, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_principal	principal;
    char		*fname;

    /*
     * krb5_principal requires:
     *	krb5_int32			for KV5M_PRINCIPAL
     *	krb5_int32			for flattened name size
     *	strlen(name)			for name.
     *	krb5_int32			for KV5M_PRINCIPAL
     */
    kret = EINVAL;
    /* Solaris Kerberos */
    principal = (krb5_principal) arg;
    if ((principal) &&
	!(kret = krb5_unparse_name(kcontext, principal, &fname))) {
	*sizep += (3*sizeof(krb5_int32)) + strlen(fname);
	/* Solaris Kerberos */
	krb5_xfree_wrap(fname, strlen(fname) + 1);
    }
    return(kret);
}

/*
 * krb5_principal_externalize()	- Externalize the krb5_principal.
 */
static krb5_error_code
krb5_principal_externalize(krb5_context kcontext, krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_principal	principal;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;
    char		*fname;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Solaris Kerberos */
    principal = (krb5_principal) arg;
    if (principal) {
	kret = ENOMEM;
	if (!krb5_principal_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    if (!(kret = krb5_unparse_name(kcontext, principal, &fname))) {

		(void) krb5_ser_pack_int32(KV5M_PRINCIPAL, &bp, &remain);
		(void) krb5_ser_pack_int32((krb5_int32) strlen(fname),
					   &bp, &remain);
		(void) krb5_ser_pack_bytes((krb5_octet *) fname,
					   strlen(fname), &bp, &remain);
		(void) krb5_ser_pack_int32(KV5M_PRINCIPAL, &bp, &remain);
		*buffer = bp;
		*lenremain = remain;

		/* Solaris Kerberos */
		krb5_xfree_wrap(fname, strlen(fname) + 1);
	    }
	}
    }
    return(kret);
}

/*
 * krb5_principal_internalize()	- Internalize the krb5_principal.
 */
static krb5_error_code
krb5_principal_internalize(krb5_context kcontext, krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_principal	principal;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    char		*tmpname;
    /* Solaris Kerberos */
    int			tmpsize;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KV5M_PRINCIPAL) {
	kret = ENOMEM;

	/* See if we have enough data for the length */
	if (!(kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain))) {
	    /* Get the string */
	    /* Solaris Kerberos */
	    tmpsize = ibuf+1;
	    tmpname = (char *) MALLOC(tmpsize);
	    if ((tmpname) &&
		!(kret = krb5_ser_unpack_bytes((krb5_octet *) tmpname,
					       (size_t) ibuf,
					       &bp, &remain))) {
		tmpname[ibuf] = '\0';

		/* Parse the name to a principal structure */
		principal = (krb5_principal) NULL;
		kret = krb5_parse_name(kcontext, tmpname, &principal);
		if (!kret) {
		    kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
		    if (!kret && (ibuf == KV5M_PRINCIPAL)) {
			*buffer = bp;
			*lenremain = remain;
			*argp = principal;
		    }
		    else
			kret = EINVAL;
		}
		if (kret && principal)
		    krb5_free_principal(kcontext, principal);
		/* Solaris Kerberos */
		FREE(tmpname,tmpsize);
	    }
	}
    }
    return(kret);
}

/*
 * Register the context serializer.
 */
krb5_error_code
krb5_ser_principal_init(krb5_context kcontext)
{
    return(krb5_register_serializer(kcontext, &krb5_principal_ser_entry));
}
