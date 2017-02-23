/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>
#include "dh_gssapi.h"

/*
 * This module contains the implementation of the gssapi context support
 * routines for the Diffie-Hellman mechanism.
 *
 * The GSS routines that are supported by this module are:
 *	gss_context_time
 *	gss_delete_sec_context
 *	gss_inquire_context
 *	gss_wrap_size_limit
 *
 * The following routines are not supported for the Diffie-Hellman
 * Mechanism at this time.
 *	gss_export_sec_context
 *	gss_import_sec_context
 *
 * The following routine is not supported since it is obsolete in version 2
 * of the GSS-API.
 *	gss_process_context_token.
 *
 * Note that support for gss_init_sec_context and gss_accept_sec_context is
 * found in context_establish.c
 */

OM_uint32
__dh_gss_context_time(void *ctx, /* Mechanism context (not used) */
		    OM_uint32 * minor, /* GSS minor status */
		    gss_ctx_id_t context, /* GSS context handle */
		    OM_uint32* time_remaining /* Time remaining */)

{
_NOTE(ARGUNUSED(ctx))
	/* Context is a dh context */
	dh_gss_context_t cntx = (dh_gss_context_t)context;
	time_t now = time(0);

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (time_remaining == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Validate context */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* See if it is always valid */
	if (cntx->expire == (time_t)GSS_C_INDEFINITE) {
		*time_remaining = GSS_C_INDEFINITE;
		return (GSS_S_COMPLETE);
	}

	/* Calculate the remainning time */
	*time_remaining = (now < cntx->expire) ? cntx->expire - now : 0;

	/* Return expired if there is no time left */
	return (*time_remaining ? GSS_S_COMPLETE : GSS_S_CONTEXT_EXPIRED);
}

/*
 * Delete a Diffie-Hellman context that is pointed to by context.
 * On a successfull return *context will be NULL.
 */

OM_uint32
__dh_gss_delete_sec_context(void *ctx, /* Mechanism context */
			    OM_uint32 *minor, /* Mechanism status */
			    gss_ctx_id_t *context, /* GSS context */
			    gss_buffer_t token /* GSS token */)
{
_NOTE(ARGUNUSED(ctx))

	dh_gss_context_t cntx;

	if (context == 0)
		return (GSS_S_CALL_INACCESSIBLE_READ |
			GSS_S_CALL_INACCESSIBLE_WRITE);

	/* context is a Diffie-Hellman context */
	cntx = (dh_gss_context_t)*context;

	if (minor == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/*
	 * If token then set the length to zero value to zero to indicate
	 * We indicat a null token since we don't need to send a token to
	 * the other side.
	 */

	if (token) {
		token->length = 0;
		token->value = NULL;
	}

	/* Deleting a null context is OK */
	if (cntx == NULL)
		return (GSS_S_COMPLETE);

	/* Validate the context */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* Zero out the session keys! */
	memset(cntx->keys, 0, cntx->no_keys * sizeof (des_block));

	/* Unregister the context */
	*minor = __dh_remove_context(cntx);

	/* Free storage */
	__dh_destroy_seq_hist(cntx);
	free(cntx->remote);
	free(cntx->local);
	Free(cntx->keys);
	Free(cntx);

	/* Set context to NULL */
	*context = NULL;

	return (GSS_S_COMPLETE);
}


/*
 * Diffie-Hellman mechanism currently does not support exporting and importing
 * gss contexts.
 */

OM_uint32
/*ARGSUSED*/
__dh_gss_export_sec_context(void *ctx, OM_uint32 *minor,
			    gss_ctx_id_t *context, gss_buffer_t token)
{
	return (GSS_S_UNAVAILABLE);
}

OM_uint32
/*ARGSUSED*/
__dh_gss_import_sec_context(void * ctx, OM_uint32 *minor,
			    gss_buffer_t token, gss_ctx_id_t *context)
{
	return (GSS_S_UNAVAILABLE);
}

/*
 * Get the state of a Diffie-Hellman context
 */

OM_uint32
__dh_gss_inquire_context(void *ctx, /* Mechanism context */
			OM_uint32 *minor, /* Mechanism status */
			gss_ctx_id_t context, /* GSS context */
			gss_name_t *initiator, /* Name of initiator */
			gss_name_t *acceptor, /* Name of acceptor */
			OM_uint32 *time_rec, /* Amount of time left */
			gss_OID *mech, /* return OID of mechanism */
			OM_uint32 *flags_rec, /* flags set on context */
			int *local, /* True if we're the initiator */
			int *open /* True if the context is established */)
{
	dh_gss_context_t cntx;
	OM_uint32 stat = GSS_S_COMPLETE;
	OM_uint32 t;

	/* context is a Diffie-Hellman */
	cntx = (dh_gss_context_t)context;

	/* Validate the context */
	if ((*minor = __dh_validate_context(cntx)) != DH_SUCCESS)
		return (GSS_S_NO_CONTEXT);

	/* If the caller wants the mechanism OID set *mech to if we can */
	if (mech) {
		if (ctx == 0) {
			*mech = GSS_C_NO_OID;
			return (GSS_S_CALL_INACCESSIBLE_READ);
		}
		else
			*mech = ((dh_context_t)ctx)->mech;
	}

	/* set t to be the time left on the context */
	if (cntx->expire == GSS_C_INDEFINITE)
		t = GSS_C_INDEFINITE;
	else {
		time_t now = time(0);
		t = now > cntx->expire ? 0 : (OM_uint32)(cntx->expire - now);
	}

	/* If the caller wants the initiator set *initiator to it. */
	if (initiator) {
		dh_principal p = cntx->initiate ? cntx->local : cntx->remote;
		*initiator = (gss_name_t)strdup(p);
	}

	/* If the callers wants the acceptor set *acceptor to it. */
	if (acceptor) {
		dh_principal p = cntx->initiate ? cntx->remote : cntx->local;
		*acceptor = (gss_name_t)strdup(p);
	}

	/* If the caller wants the time remaining set *time_rec to t */
	if (time_rec)
		*time_rec = t;


	/* Return the flags in flags_rec if set */
	if (flags_rec)
		*flags_rec = cntx->flags;

	/* ditto for local */
	if (local)
		*local = cntx->initiate;

	/* ditto for open */
	if (open)
		*open = (cntx->state == ESTABLISHED);


	/* return GSS_S_CONTEXT_EXPIRED if no time is left on the context */
	return ((t == 0 ? GSS_S_CONTEXT_EXPIRED : GSS_S_COMPLETE) | stat);
}

/*
 * __dh_gss_process_context_token.
 * This routine is not implemented. It is depricated in version 2.
 */

OM_uint32
/*ARGSUSED*/
__dh_gss_process_context_token(void *ctx, OM_uint32 *minor,
    gss_ctx_id_t context, gss_buffer_t token)
{
	return (GSS_S_UNAVAILABLE);
}

/*
 * This implements the gss_wrap_size_limit entry point for Diffie-Hellman
 * mechanism. See RFC 2078 for details. The idea here is for a context,
 * qop, whether confidentiality is specified, and an output size, return
 * the maximum input size that will fit in the given output size. Typically
 * the output size would be the MTU of the higher level protocol using the
 * GSS-API.
 */

OM_uint32
__dh_gss_wrap_size_limit(void *ctx, /* Mechanism context (not used) */
			OM_uint32 *minor, /* Mechanism status */
			gss_ctx_id_t context, /* GSS context handle */
			int conf_req, /* True if confidentiality is wanted */
			gss_qop_t qop_req, /* Requested QOP */
			OM_uint32 output_size, /* The maximum ouput size */
			OM_uint32 *input_size /* Input size returned */)
{
_NOTE(ARGUNUSED(ctx))
	OM_uint32 major, stat = GSS_S_COMPLETE;
	unsigned int msgsize, sigsize, pad = 1, size;
	dh_token_desc token;
	dh_wrap_t wrap = &token.ver.dh_version_u.body.dh_token_body_desc_u.seal;
	OM_uint32 left;

	if (input_size == 0)
		stat = GSS_S_CALL_INACCESSIBLE_WRITE;

	/* We check for valid unexpired context by calling gss_context_time. */
	if ((major = stat | __dh_gss_context_time(ctx, minor, context, &left))
	    != GSS_S_COMPLETE)
		return (major | stat);

	/* Find the signature size for this qop. */
	if ((*minor = __get_sig_size(qop_req, &sigsize)) != DH_SUCCESS)
		return (GSS_S_BAD_QOP | stat);

	/* Just return if we can't give the caller what it asked for. */
	if (stat)
		return (stat);

	/*
	 * If we requested confidentiality, get the cipher pad for the
	 * requested qop. Since we can't support privacy the cipher pad
	 * is always 1.
	 */
	if (conf_req)
		pad = 1;

	/*
	 * Set up an empty wrap token to calculate header and signature
	 * overhead.
	 */

	token.ver.verno = DH_PROTO_VERSION;
	token.ver.dh_version_u.body.type = DH_WRAP;
	wrap->mic.qop = qop_req;
	wrap->mic.seqnum = 0;
	wrap->mic.client_flag = 0;
	wrap->body.body_len = 0;
	wrap->body.body_val = 0;
	token.verifier.dh_signature_len = sigsize;
	token.verifier.dh_signature_val = 0;

	/* This is the size of an empy wrap token */
	size =  xdr_sizeof((xdrproc_t)xdr_dh_token_desc, (void *)&token);

	/* This is the amount of space left to put our message. */
	msgsize = (output_size > size) ? output_size - size : 0;

	/* XDR needs to pad to a four byte boundry */
	msgsize = (msgsize / 4) * 4;

	/* We need to pad to pad bytes for encryption (=1 if conf_req = 0) */
	msgsize = (msgsize / pad) * pad;

	/*
	 * The serialization of the inner message includes
	 * the original length.
	 */

	msgsize = (msgsize > sizeof (uint_t)) ? msgsize - sizeof (uint_t) : 0;

	/*
	 * We now have the space for the inner wrap message, which is also
	 * XDR encoded and is padded to a four byte boundry.
	 */

	msgsize = (msgsize / 4) * 4;

	*input_size = msgsize;

	return (GSS_S_COMPLETE);
}
