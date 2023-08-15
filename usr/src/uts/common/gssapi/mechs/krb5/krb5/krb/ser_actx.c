/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/krb/ser_actx.c
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
 * ser_actx.c - Serialize krb5_auth_context structure.
 */
#include "k5-int.h"
#include "int-proto.h"
#include "auth_con.h"

#define	TOKEN_RADDR	950916
#define	TOKEN_RPORT	950917
#define	TOKEN_LADDR	950918
#define	TOKEN_LPORT	950919
#define	TOKEN_KEYBLOCK	950920
#define	TOKEN_LSKBLOCK	950921
#define	TOKEN_RSKBLOCK	950922

/*
 * Routines to deal with externalizing the krb5_auth_context:
 *	krb5_auth_context_size();
 *	krb5_auth_context_externalize();
 *	krb5_auth_context_internalize();
 */
static krb5_error_code krb5_auth_context_size
	(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_auth_context_externalize
	(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_auth_context_internalize
	(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/*
 * Other metadata serialization initializers.
 */

/* Local data */
static const krb5_ser_entry krb5_auth_context_ser_entry = {
    KV5M_AUTH_CONTEXT,			/* Type			*/
    krb5_auth_context_size,		/* Sizer routine	*/
    krb5_auth_context_externalize,	/* Externalize routine	*/
    krb5_auth_context_internalize	/* Internalize routine	*/
};

/*
 * krb5_auth_context_size()	- Determine the size required to externalize
 *				  the krb5_auth_context.
 */
static krb5_error_code
krb5_auth_context_size(krb5_context kcontext, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_auth_context	auth_context;
    size_t		required;

    /*
     * krb5_auth_context requires at minimum:
     *	krb5_int32		for KV5M_AUTH_CONTEXT
     *	krb5_int32		for auth_context_flags
     *	krb5_int32		for remote_seq_number
     *	krb5_int32		for local_seq_number
     *	krb5_int32		for req_cksumtype
     *	krb5_int32		for safe_cksumtype
     *	krb5_int32		for size of i_vector
     *	krb5_int32		for KV5M_AUTH_CONTEXT
     */
    kret = EINVAL;
    /* Solaris Kerberos */
    auth_context = (krb5_auth_context) arg;
    if (auth_context) {
	kret = 0;

	/* Calculate size required by i_vector - ptooey */
	if (auth_context->i_vector && auth_context->keyblock) {
	    kret = krb5_c_block_size(kcontext, auth_context->keyblock->enctype,
				     &required);
	} else {
	    required = 0;
	}

	required += sizeof(krb5_int32)*8;

	/* Calculate size required by remote_addr, if appropriate */
	if (!kret && auth_context->remote_addr) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_ADDRESS,
				    (krb5_pointer) auth_context->remote_addr,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by remote_port, if appropriate */
	if (!kret && auth_context->remote_port) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_ADDRESS,
				    (krb5_pointer) auth_context->remote_port,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by local_addr, if appropriate */
	if (!kret && auth_context->local_addr) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_ADDRESS,
				    (krb5_pointer) auth_context->local_addr,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by local_port, if appropriate */
	if (!kret && auth_context->local_port) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_ADDRESS,
				    (krb5_pointer) auth_context->local_port,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by keyblock, if appropriate */
	if (!kret && auth_context->keyblock) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_KEYBLOCK,
				    (krb5_pointer) auth_context->keyblock,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by send_subkey, if appropriate */
	if (!kret && auth_context->send_subkey) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_KEYBLOCK,
				    (krb5_pointer) auth_context->send_subkey,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by recv_subkey, if appropriate */
	if (!kret && auth_context->recv_subkey) {
	    kret = krb5_size_opaque(kcontext,
				    KV5M_KEYBLOCK,
				    (krb5_pointer) auth_context->recv_subkey,
				    &required);
	    if (!kret)
		required += sizeof(krb5_int32);
	}

	/* Calculate size required by authentp, if appropriate */
	if (!kret && auth_context->authentp)
	    kret = krb5_size_opaque(kcontext,
				    KV5M_AUTHENTICATOR,
				    (krb5_pointer) auth_context->authentp,
				    &required);

    }
    if (!kret)
	*sizep += required;
    return(kret);
}

/*
 * krb5_auth_context_externalize()	- Externalize the krb5_auth_context.
 */
static krb5_error_code
krb5_auth_context_externalize(krb5_context kcontext, krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_auth_context	auth_context;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;
    size_t              obuf;
    krb5_int32		obuf32;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Solaris Kerberos */
    auth_context = (krb5_auth_context) arg;
    if (auth_context) {
	kret = ENOMEM;
	if (!krb5_auth_context_size(kcontext, arg, &required) &&
	    (required <= remain)) {

	    /* Write fixed portion */
	    (void) krb5_ser_pack_int32(KV5M_AUTH_CONTEXT, &bp, &remain);
	    (void) krb5_ser_pack_int32(auth_context->auth_context_flags,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32(auth_context->remote_seq_number,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32(auth_context->local_seq_number,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) auth_context->req_cksumtype,
				       &bp, &remain);
	    (void) krb5_ser_pack_int32((krb5_int32) auth_context->safe_cksumtype,
				       &bp, &remain);

	    kret = 0;

	    /* Now figure out the number of bytes for i_vector and write it */
	    if (auth_context->i_vector) {
		kret = krb5_c_block_size(kcontext,
					 auth_context->keyblock->enctype,
					 &obuf);
	    } else {
		obuf = 0;
	    }

	    /* Convert to signed 32 bit integer */
	    obuf32 = obuf;
	    if (kret == 0 && obuf != obuf32)
		kret = EINVAL;
	    if (!kret)
		(void) krb5_ser_pack_int32(obuf32, &bp, &remain);

	    /* Now copy i_vector */
	    if (!kret && auth_context->i_vector)
		(void) krb5_ser_pack_bytes(auth_context->i_vector,
					   obuf,
					   &bp, &remain);

	    /* Now handle remote_addr, if appropriate */
	    if (!kret && auth_context->remote_addr) {
		(void) krb5_ser_pack_int32(TOKEN_RADDR, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_ADDRESS,
					       (krb5_pointer)
					       auth_context->remote_addr,
					       &bp,
					       &remain);
	    }

	    /* Now handle remote_port, if appropriate */
	    if (!kret && auth_context->remote_port) {
		(void) krb5_ser_pack_int32(TOKEN_RPORT, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_ADDRESS,
					       (krb5_pointer)
					       auth_context->remote_addr,
					       &bp,
					       &remain);
	    }

	    /* Now handle local_addr, if appropriate */
	    if (!kret && auth_context->local_addr) {
		(void) krb5_ser_pack_int32(TOKEN_LADDR, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_ADDRESS,
					       (krb5_pointer)
					       auth_context->local_addr,
					       &bp,
					       &remain);
	    }

	    /* Now handle local_port, if appropriate */
	    if (!kret && auth_context->local_port) {
		(void) krb5_ser_pack_int32(TOKEN_LPORT, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_ADDRESS,
					       (krb5_pointer)
					       auth_context->local_addr,
					       &bp,
					       &remain);
	    }

	    /* Now handle keyblock, if appropriate */
	    if (!kret && auth_context->keyblock) {
		(void) krb5_ser_pack_int32(TOKEN_KEYBLOCK, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_KEYBLOCK,
					       (krb5_pointer)
					       auth_context->keyblock,
					       &bp,
					       &remain);
	    }

	    /* Now handle subkey, if appropriate */
	    if (!kret && auth_context->send_subkey) {
		(void) krb5_ser_pack_int32(TOKEN_LSKBLOCK, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_KEYBLOCK,
					       (krb5_pointer)
					       auth_context->send_subkey,
					       &bp,
					       &remain);
	    }

	    /* Now handle subkey, if appropriate */
	    if (!kret && auth_context->recv_subkey) {
		(void) krb5_ser_pack_int32(TOKEN_RSKBLOCK, &bp, &remain);
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_KEYBLOCK,
					       (krb5_pointer)
					       auth_context->recv_subkey,
					       &bp,
					       &remain);
	    }

	    /* Now handle authentp, if appropriate */
	    if (!kret && auth_context->authentp)
		kret = krb5_externalize_opaque(kcontext,
					       KV5M_AUTHENTICATOR,
					       (krb5_pointer)
					       auth_context->authentp,
					       &bp,
					       &remain);

	    /*
	     * If we were successful, write trailer then update the pointer and
	     * remaining length;
	     */
	    if (!kret) {
		/* Write our trailer */
		(void) krb5_ser_pack_int32(KV5M_AUTH_CONTEXT, &bp, &remain);
		*buffer = bp;
		*lenremain = remain;
	    }
	}
    }
    return(kret);
}

/*
 * krb5_auth_context_internalize()	- Internalize the krb5_auth_context.
 */
static krb5_error_code
krb5_auth_context_internalize(krb5_context kcontext, krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_auth_context	auth_context;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    krb5_int32		ivlen;
    krb5_int32		tag;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KV5M_AUTH_CONTEXT) {
	kret = ENOMEM;

	/* Get memory for the auth_context */
	if ((remain >= (5*sizeof(krb5_int32))) &&
	    (auth_context = (krb5_auth_context)
	     MALLOC(sizeof(struct _krb5_auth_context)))) {
	    (void) memset(auth_context, 0, sizeof(struct _krb5_auth_context));

	    /* Get auth_context_flags */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    auth_context->auth_context_flags = ibuf;

	    /* Get remote_seq_number */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    auth_context->remote_seq_number = ibuf;

	    /* Get local_seq_number */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    auth_context->local_seq_number = ibuf;

	    /* Get req_cksumtype */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    auth_context->req_cksumtype = (krb5_cksumtype) ibuf;

	    /* Get safe_cksumtype */
	    (void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
	    auth_context->safe_cksumtype = (krb5_cksumtype) ibuf;

	    /* Get length of i_vector */
	    (void) krb5_ser_unpack_int32(&ivlen, &bp, &remain);

	    if (ivlen) {
		if ((auth_context->i_vector =
		     (krb5_pointer) MALLOC((size_t)ivlen)))
		    kret = krb5_ser_unpack_bytes(auth_context->i_vector,
						 (size_t) ivlen,
						 &bp,
						 &remain);
		else
		    kret = ENOMEM;
	    }
	    else
		kret = 0;

	    /* Peek at next token */
	    tag = 0;
	    if (!kret)
		kret = krb5_ser_unpack_int32(&tag, &bp, &remain);

	    /* This is the remote_addr */
	    if (!kret && (tag == TOKEN_RADDR)) {
		if (!(kret = krb5_internalize_opaque(kcontext,
						     KV5M_ADDRESS,
						     (krb5_pointer *)
						     &auth_context->
						     remote_addr,
						     &bp,
						     &remain)))
		    kret = krb5_ser_unpack_int32(&tag, &bp, &remain);
	    }

	    /* This is the remote_port */
	    if (!kret && (tag == TOKEN_RPORT)) {
		if (!(kret = krb5_internalize_opaque(kcontext,
						     KV5M_ADDRESS,
						     (krb5_pointer *)
						     &auth_context->
						     remote_port,
						     &bp,
						     &remain)))
		    kret = krb5_ser_unpack_int32(&tag, &bp, &remain);
	    }

	    /* This is the local_addr */
	    if (!kret && (tag == TOKEN_LADDR)) {
		if (!(kret = krb5_internalize_opaque(kcontext,
						     KV5M_ADDRESS,
						     (krb5_pointer *)
						     &auth_context->
						     local_addr,
						     &bp,
						     &remain)))
		    kret = krb5_ser_unpack_int32(&tag, &bp, &remain);
	    }

	    /* This is the local_port */
	    if (!kret && (tag == TOKEN_LPORT)) {
		if (!(kret = krb5_internalize_opaque(kcontext,
						     KV5M_ADDRESS,
						     (krb5_pointer *)
						     &auth_context->
						     local_port,
						     &bp,
						     &remain)))
		    kret = krb5_ser_unpack_int32(&tag, &bp, &remain);
	    }

	    /* This is the keyblock */
	    if (!kret && (tag == TOKEN_KEYBLOCK)) {
		if (!(kret = krb5_internalize_opaque(kcontext,
						     KV5M_KEYBLOCK,
						     (krb5_pointer *)
						     &auth_context->keyblock,
						     &bp,
						     &remain)))
		    kret = krb5_ser_unpack_int32(&tag, &bp, &remain);
	    }

	    /* This is the send_subkey */
	    if (!kret && (tag == TOKEN_LSKBLOCK)) {
		if (!(kret = krb5_internalize_opaque(kcontext,
						     KV5M_KEYBLOCK,
						     (krb5_pointer *)
						     &auth_context->
						     send_subkey,
						     &bp,
						     &remain)))
		    kret = krb5_ser_unpack_int32(&tag, &bp, &remain);
	    }

	    /* This is the recv_subkey */
	    if (!kret) {
		if (tag == TOKEN_RSKBLOCK) {
		    kret = krb5_internalize_opaque(kcontext,
						   KV5M_KEYBLOCK,
						   (krb5_pointer *)
						   &auth_context->
						   recv_subkey,
						   &bp,
						   &remain);
		}
		else {
		    /*
		     * We read the next tag, but it's not of any use here, so
		     * we effectively 'unget' it here.
		     */
		    bp -= sizeof(krb5_int32);
		    remain += sizeof(krb5_int32);
		}
	    }

	    /* Now find the authentp */
	    if (!kret) {
		if ((kret = krb5_internalize_opaque(kcontext,
						    KV5M_AUTHENTICATOR,
						    (krb5_pointer *)
						    &auth_context->authentp,
						    &bp,
						    &remain))) {
		    if (kret == EINVAL)
			kret = 0;
		}
	    }

	    /* Finally, find the trailer */
	    if (!kret) {
		kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
		if (!kret && (ibuf != KV5M_AUTH_CONTEXT))
		    kret = EINVAL;
	    }
	    if (!kret) {
		*buffer = bp;
		*lenremain = remain;
		auth_context->magic = KV5M_AUTH_CONTEXT;
		*argp = (krb5_pointer) auth_context;
	    }
/* We don't import the auth_context into the kernel */
#ifndef _KERNEL
	    else
		krb5_auth_con_free(kcontext, auth_context);
#endif
	}
    }
    return(kret);
}

/*
 * Register the auth_context serializer.
 */
krb5_error_code KRB5_CALLCONV
krb5_ser_auth_context_init(krb5_context kcontext)
{
    krb5_error_code	kret;
    kret = krb5_register_serializer(kcontext, &krb5_auth_context_ser_entry);
    if (!kret)
	kret = krb5_ser_authdata_init(kcontext);
    if (!kret)
	kret = krb5_ser_address_init(kcontext);
    if (!kret)
	kret = krb5_ser_authenticator_init(kcontext);
    if (!kret)
	kret = krb5_ser_checksum_init(kcontext);
    if (!kret)
	kret = krb5_ser_keyblock_init(kcontext);
    if (!kret)
	kret = krb5_ser_principal_init(kcontext);
    return(kret);
}
