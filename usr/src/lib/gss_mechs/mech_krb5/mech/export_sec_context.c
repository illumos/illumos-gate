/*
 * lib/gssapi/krb5/export_sec_context.c
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
 * export_sec_context.c	- Externalize the security context.
 */
#include "gssapiP_krb5.h"

OM_uint32
krb5_gss_export_sec_context(minor_status, context_handle, interprocess_token)
    OM_uint32		*minor_status;
    gss_ctx_id_t	*context_handle;
    gss_buffer_t	interprocess_token;
{
    krb5_context	context;
    krb5_error_code	kret;
    OM_uint32		retval;
    size_t		bufsize, blen;
    krb5_gss_ctx_id_t	ctx;
    krb5_octet		*obuffer, *obp;

    /* Assume a tragic failure */
    obuffer = (krb5_octet *) NULL;
    retval = GSS_S_FAILURE;
    *minor_status = 0;

    if (!kg_validate_ctx_id(*context_handle)) {
	    kret = (OM_uint32) G_VALIDATE_FAILED;
	    retval = GSS_S_NO_CONTEXT;
	    goto error_out;
    }

    ctx = (krb5_gss_ctx_id_t) *context_handle;
    context = ctx->k5_context;
    kret = krb5_gss_ser_init(context);
    if (kret)
	goto error_out;

    /* Determine size needed for externalization of context */
    bufsize = 0;
    if ((kret = kg_ctx_size(context, (krb5_pointer) ctx,
			    &bufsize)))
	    goto error_out;

    /* Allocate the buffer */
    if ((obuffer = (krb5_octet *) xmalloc(bufsize)) == NULL) {
	    kret = ENOMEM;
	    goto error_out;
    }

    obp = obuffer;
    blen = bufsize;
    /* Externalize the context */
    if ((kret = kg_ctx_externalize(context,
				   (krb5_pointer) ctx, &obp, &blen)))
	    goto error_out;

    /* Success!  Return the buffer */
    interprocess_token->length = bufsize - blen;
    interprocess_token->value = obuffer;
    *minor_status = 0;
    retval = GSS_S_COMPLETE;

    /* Now, clean up the context state */
    (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);
    *context_handle = GSS_C_NO_CONTEXT;

    return (GSS_S_COMPLETE);

error_out:
    if (obuffer && bufsize) {
	    memset(obuffer, 0, bufsize);
	    xfree(obuffer);
    }
    if (*minor_status == 0) 
	    *minor_status = (OM_uint32) kret;
    return(retval);
}
