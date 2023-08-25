/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/serialize.c
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
 * Base routines to deal with serialization of Kerberos metadata.
 */
#include "k5-int.h"

/* Solaris Kerberos */
#include <k5-platform.h>
#include <k5-platform-store_64.h>
#include <k5-platform-load_64.h>

/*
 * krb5_find_serializer()	- See if a particular type is registered.
 */
krb5_ser_handle
krb5_find_serializer(krb5_context kcontext, krb5_magic odtype)
{
    krb5_ser_handle	res;
    krb5_ser_handle	sctx;
    int			i;

    res = (krb5_ser_handle) NULL;
    sctx = (krb5_ser_handle) kcontext->ser_ctx;
    for (i=0; i<kcontext->ser_ctx_count; i++) {
	if (sctx[i].odtype == odtype) {
	    res = &sctx[i];
	    break;
	}
    }
    return(res);
}

/*
 * krb5_register_serializer()	- Register a particular serializer.
 */
krb5_error_code
krb5_register_serializer(krb5_context kcontext, const krb5_ser_entry *entry)
{
    krb5_error_code	kret;
    krb5_ser_handle	stable;

    kret = 0;
    /* See if it's already there, if so, we're good to go. */
    if (!(stable = krb5_find_serializer(kcontext, entry->odtype))) {
	/*
	 * Can't find our type.  Create a new entry.
	 */
	if ((stable = (krb5_ser_handle) MALLOC(sizeof(krb5_ser_entry) *
					       (kcontext->ser_ctx_count+1)))) {
	    /* Copy in old table */
	    if (kcontext->ser_ctx_count)
	        (void) memcpy((void*)stable, kcontext->ser_ctx,
		        sizeof(krb5_ser_entry) * kcontext->ser_ctx_count);
	    /* Copy in new entry */
	    (void) memcpy((void*)&stable[kcontext->ser_ctx_count], entry,
		   sizeof(krb5_ser_entry));
	    if (kcontext->ser_ctx)
		krb5_xfree_wrap(kcontext->ser_ctx,
			sizeof(krb5_ser_entry) * (kcontext->ser_ctx_count));
	    kcontext->ser_ctx = (void *) stable;
	    kcontext->ser_ctx_count++;
	}
	else
	    kret = ENOMEM;
    }
    else
	(void) memcpy((void*)stable, entry, sizeof(krb5_ser_entry));
    return(kret);
}

/*
 * krb5_size_opaque()	- Determine the size necessary to serialize a given
 *			  piece of opaque data.
 */
krb5_error_code KRB5_CALLCONV
krb5_size_opaque(krb5_context kcontext, krb5_magic odtype, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_ser_handle	shandle;

    kret = ENOENT;
    /* See if the type is supported, if so, do it */
    if ((shandle = krb5_find_serializer(kcontext, odtype)))
	kret = (shandle->sizer) ? (*shandle->sizer)(kcontext, arg, sizep) : 0;
    return(kret);
}

/*
 * krb5_externalize_opaque()	- Externalize a piece of opaque data.
 */
krb5_error_code KRB5_CALLCONV
krb5_externalize_opaque(krb5_context kcontext, krb5_magic odtype, krb5_pointer arg, krb5_octet **bufpp, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_ser_handle	shandle;

    kret = ENOENT;
    /* See if the type is supported, if so, do it */
    if ((shandle = krb5_find_serializer(kcontext, odtype)))
	kret = (shandle->externalizer) ?
	    (*shandle->externalizer)(kcontext, arg, bufpp, sizep) : 0;
    return(kret);
}

/*
 * Externalize a piece of arbitrary data.
 */
krb5_error_code
krb5_externalize_data(krb5_context kcontext, krb5_pointer arg, krb5_octet **bufpp, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_magic		*mp;
    krb5_octet		*buffer, *bp;
    size_t		bufsize, bsize;

    mp = (krb5_magic *) arg;
    bufsize = 0;
    if (!(kret = krb5_size_opaque(kcontext, *mp, arg, &bufsize))) {
	if ((buffer = (krb5_octet *) MALLOC(bufsize))) {
	    bp = buffer;
	    bsize = bufsize;
	    if (!(kret = krb5_externalize_opaque(kcontext,
						 *mp,
						 arg,
						 &bp,
						 &bsize))) {
		if (bsize != 0)
		    bufsize -= bsize;
		*bufpp = buffer;
		*sizep = bufsize;
	    }
	}
	else
	    kret = ENOMEM;
    }
    return(kret);
}

/*
 * krb5_internalize_opaque()	- Convert external representation into a data
 *				  structure.
 */
krb5_error_code KRB5_CALLCONV
krb5_internalize_opaque(krb5_context kcontext, krb5_magic odtype, krb5_pointer *argp, krb5_octet **bufpp, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_ser_handle	shandle;

    kret = ENOENT;
    /* See if the type is supported, if so, do it */
    if ((shandle = krb5_find_serializer(kcontext, odtype)))
	kret = (shandle->internalizer) ?
	    (*shandle->internalizer)(kcontext, argp, bufpp, sizep) : 0;
    return(kret);
}

/*
 * krb5_ser_pack_int32()	- Pack a 4-byte integer if space is available.
 *				  Update buffer pointer and remaining space.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_pack_int32(krb5_int32 iarg, krb5_octet **bufp, size_t *remainp)
{
    if (*remainp >= sizeof(krb5_int32)) {
	(*bufp)[0] = (krb5_octet) ((iarg >> 24) & 0xff);
	(*bufp)[1] = (krb5_octet) ((iarg >> 16) & 0xff);
	(*bufp)[2] = (krb5_octet) ((iarg >> 8) & 0xff);
	(*bufp)[3] = (krb5_octet) (iarg & 0xff);
	*bufp += sizeof(krb5_int32);
	*remainp -= sizeof(krb5_int32);
	return(0);
    }
    else
	return(ENOMEM);
}

/*
 * krb5_ser_pack_int64()	- Pack an 8-byte integer if space is available.
 *				  Update buffer pointer and remaining space.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_pack_int64(krb5_int64 iarg, krb5_octet **bufp, size_t *remainp)
{
    if (*remainp >= sizeof(krb5_int64)) {
	store_64_be(iarg, (unsigned char *)*bufp);
	*bufp += sizeof(krb5_int64);
	*remainp -= sizeof(krb5_int64);
	return(0);
    }
    else
	return(ENOMEM);
}

/*
 * krb5_ser_pack_bytes()	- Pack a string of bytes.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_pack_bytes(krb5_octet *ostring, size_t osize, krb5_octet **bufp, size_t *remainp)
{
    if (*remainp >= osize) {
	(void) memcpy(*bufp, ostring, osize);
	*bufp += osize;
	*remainp -= osize;
	return(0);
    }
    else
	return(ENOMEM);
}

/*
 * krb5_ser_unpack_int32()	- Unpack a 4-byte integer if it's there.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_unpack_int32(krb5_int32 *intp, krb5_octet **bufp, size_t *remainp)
{
    if (*remainp >= sizeof(krb5_int32)) {
	*intp = (((krb5_int32) ((unsigned char) (*bufp)[0]) << 24) |
		 ((krb5_int32) ((unsigned char) (*bufp)[1]) << 16) |
		 ((krb5_int32) ((unsigned char) (*bufp)[2]) << 8) |
		 ((krb5_int32) ((unsigned char) (*bufp)[3])));
	*bufp += sizeof(krb5_int32);
	*remainp -= sizeof(krb5_int32);
	return(0);
    }
    else
	return(ENOMEM);
}

/*
 * krb5_ser_unpack_int64()	- Unpack an 8-byte integer if it's there.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_unpack_int64(krb5_int64 *intp, krb5_octet **bufp, size_t *remainp)
{
    if (*remainp >= sizeof(krb5_int64)) {
	*intp = load_64_be((unsigned char *)*bufp);
	*bufp += sizeof(krb5_int64);
	*remainp -= sizeof(krb5_int64);
	return(0);
    }
    else
	return(ENOMEM);
}

/*
 * krb5_ser_unpack_bytes()	- Unpack a byte string if it's there.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_unpack_bytes(krb5_octet *istring, size_t isize, krb5_octet **bufp, size_t *remainp)
{
    if (*remainp >= isize) {
	(void) memcpy(istring, *bufp, isize);
	*bufp += isize;
	*remainp -= isize;
	return(0);
    }
    else
	return(ENOMEM);
}
