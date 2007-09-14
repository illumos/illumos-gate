#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/gssapi/krb5/lucid_context.c
 *
 * Copyright 2004 by the Massachusetts Institute of Technology.
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
 * lucid_context.c  -  Externalize a "lucid" security
 * context from a krb5_gss_ctx_id_rec structure.
 */
#include "gssapiP_krb5.h"
#include "gssapi_krb5.h"

/*
 * Local routine prototypes
 */
static void
free_external_lucid_ctx_v1(
    gss_krb5_lucid_context_v1_t *ctx);

static void
free_lucid_key_data(
    gss_krb5_lucid_key_t *key);

static krb5_error_code
copy_keyblock_to_lucid_key(
    krb5_keyblock *k5key,
    gss_krb5_lucid_key_t *lkey);

static krb5_error_code
make_external_lucid_ctx_v1(
    krb5_gss_ctx_id_rec * gctx,
    unsigned int version,
    void **out_ptr);


/*
 * Exported routines
 */

OM_uint32 KRB5_CALLCONV
gss_krb5int_export_lucid_sec_context(
    OM_uint32		*minor_status,
    gss_ctx_id_t	*context_handle,
    OM_uint32		version,
    void		**kctx)
{
    krb5_error_code	kret = 0;
    OM_uint32		retval;
    krb5_gss_ctx_id_t	ctx;
    void		*lctx = NULL;

    /* Assume failure */
    retval = GSS_S_FAILURE;
    *minor_status = 0;

    if (kctx)
	*kctx = NULL;
    else {
	kret = EINVAL;
    	goto error_out;
    }

    if (!kg_validate_ctx_id(*context_handle)) {
	    kret = (OM_uint32) G_VALIDATE_FAILED;
	    retval = GSS_S_NO_CONTEXT;
	    goto error_out;
    }

    ctx = (krb5_gss_ctx_id_t) *context_handle;
    if (kret)
	goto error_out;

    /* Externalize a structure of the right version */
    switch (version) {
    case 1:
	kret = make_external_lucid_ctx_v1((krb5_pointer)ctx,
					      version, &lctx);
        break;
    default:
	kret = (OM_uint32) KG_LUCID_VERSION;
	break;
    }

    if (kret)
	goto error_out;

    /* Success!  Record the context and return the buffer */
    if (! kg_save_lucidctx_id((void *)lctx)) {
	kret = G_VALIDATE_FAILED;
	goto error_out;
    }

    *kctx = lctx;
    *minor_status = 0;
    retval = GSS_S_COMPLETE;

    /* Clean up the context state (it is an error for
     * someone to attempt to use this context again)
     */
    (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
    *context_handle = GSS_C_NO_CONTEXT;

    return (retval);

error_out:
    if (*minor_status == 0) 
	    *minor_status = (OM_uint32) kret;
    return(retval);
}

/*
 * Frees the storage associated with an
 * exported lucid context structure.
 */
OM_uint32 KRB5_CALLCONV
gss_krb5_free_lucid_sec_context(
    OM_uint32 *minor_status,
    void *kctx)
{
    OM_uint32		retval;
    krb5_error_code	kret = 0;
    int			version;

    /* Assume failure */
    retval = GSS_S_FAILURE;
    *minor_status = 0;

    if (!kctx) {
	kret = EINVAL;
	goto error_out;
    }

    /* Verify pointer is valid lucid context */
    if (! kg_validate_lucidctx_id(kctx)) {
	kret = G_VALIDATE_FAILED;
	goto error_out;
    }

    /* Determine version and call correct free routine */
    version = ((gss_krb5_lucid_context_version_t *)kctx)->version;
    switch (version) {
    case 1:
	free_external_lucid_ctx_v1((gss_krb5_lucid_context_v1_t*) kctx);
	break;
    default:
	kret = EINVAL;
	break;
    }

    if (kret)
	goto error_out;

    /* Success! */
    (void)kg_delete_lucidctx_id(kctx);
    *minor_status = 0;
    retval = GSS_S_COMPLETE;

    return (retval);

error_out:
    if (*minor_status == 0) 
	    *minor_status = (OM_uint32) kret;
    return(retval);
}

/*
 * Local routines
 */

static krb5_error_code
make_external_lucid_ctx_v1(
    krb5_gss_ctx_id_rec * gctx,
    unsigned int version,
    void **out_ptr)
{
    gss_krb5_lucid_context_v1_t *lctx = NULL;
    unsigned int bufsize = sizeof(gss_krb5_lucid_context_v1_t);
    krb5_error_code retval;

    /* Allocate the structure */
    if ((lctx = xmalloc(bufsize)) == NULL) {
    	retval = ENOMEM;
	goto error_out;
    }

    memset(lctx, 0, bufsize);

    lctx->version = 1;
    lctx->initiate = gctx->initiate ? 1 : 0;
    lctx->endtime = gctx->endtime;
    lctx->send_seq = gctx->seq_send;
    lctx->recv_seq = gctx->seq_recv;
    lctx->protocol = gctx->proto;
    /* gctx->proto == 0 ==> rfc1964-style key information
       gctx->proto == 1 ==> cfx-style (draft-ietf-krb-wg-gssapi-cfx-07) keys */
    if (gctx->proto == 0) {
	lctx->rfc1964_kd.sign_alg = gctx->signalg;
	lctx->rfc1964_kd.seal_alg = gctx->sealalg;
	/* Copy key */
	if ((retval = copy_keyblock_to_lucid_key(gctx->subkey,
	    				&lctx->rfc1964_kd.ctx_key)))
	    goto error_out;
    }
    else if (gctx->proto == 1) {
	/* Copy keys */
	/* (subkey is always present, either a copy of the kerberos
	   session key or a subkey) */
	if ((retval = copy_keyblock_to_lucid_key(gctx->subkey,
	    				&lctx->cfx_kd.ctx_key)))
	    goto error_out;
	if (gctx->have_acceptor_subkey) {
	    if ((retval = copy_keyblock_to_lucid_key(gctx->enc,
	    				&lctx->cfx_kd.acceptor_subkey)))
		goto error_out;
	    lctx->cfx_kd.have_acceptor_subkey = 1;
	}
    }
    else {
	return EINVAL;	/* XXX better error code? */
    }

    /* Success! */
    *out_ptr = lctx;
    return 0;

error_out:
    if (lctx) {
	free_external_lucid_ctx_v1(lctx);
    }
    return retval;

}

/* Copy the contents of a krb5_keyblock to a gss_krb5_lucid_key_t structure */
static krb5_error_code
copy_keyblock_to_lucid_key(
    krb5_keyblock *k5key,
    gss_krb5_lucid_key_t *lkey)
{
    if (!k5key || !k5key->contents || k5key->length == 0)
	return EINVAL;

    memset(lkey, 0, sizeof(gss_krb5_lucid_key_t));

    /* Allocate storage for the key data */
    if ((lkey->data = xmalloc(k5key->length)) == NULL) {
	return ENOMEM;
    }
    memcpy(lkey->data, k5key->contents, k5key->length);
    lkey->length = k5key->length;
    lkey->type = k5key->enctype;

    return 0;
}


/* Free any storage associated with a gss_krb5_lucid_key_t structure */
static void
free_lucid_key_data(
    gss_krb5_lucid_key_t *key)
{
    if (key) {
	if (key->data && key->length) {
	    memset(key->data, 0, key->length);
	    xfree(key->data);
	    memset(key, 0, sizeof(gss_krb5_lucid_key_t));
	}
    }
}
/* Free any storage associated with a gss_krb5_lucid_context_v1 structure */
static void
free_external_lucid_ctx_v1(
    gss_krb5_lucid_context_v1_t *ctx)
{
    if (ctx) {
	if (ctx->protocol == 0) {
	    free_lucid_key_data(&ctx->rfc1964_kd.ctx_key);
	}
	if (ctx->protocol == 1) {
	    free_lucid_key_data(&ctx->cfx_kd.ctx_key);
	    if (ctx->cfx_kd.have_acceptor_subkey)
		free_lucid_key_data(&ctx->cfx_kd.acceptor_subkey);
	}
	xfree(ctx);
	ctx = NULL;
    }
}
