/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/gssapi/krb5/import_sec_context.c
 *
 * Copyright 1995,2004 by the Massachusetts Institute of Technology.
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
 * import_sec_context.c	- Internalize the security context.
 */
#include "gssapiP_krb5.h"
/* for serialization initialization functions */
#include "k5-int.h"
#include "mglueP.h"  /* SUNW15resync - for KGSS_ macros */

#ifdef	 _KERNEL
extern OM_uint32 kgss_release_oid(OM_uint32 *, gss_OID *);
#endif


/*
 * Fix up the OID of the mechanism so that uses the static version of
 * the OID if possible.
 */
gss_OID krb5_gss_convert_static_mech_oid(oid)
     gss_OID	oid;
{
	const gss_OID_desc 	*p;
	OM_uint32		minor_status;

	for (p = krb5_gss_oid_array; p->length; p++) {
		if ((oid->length == p->length) &&
		    (memcmp(oid->elements, p->elements, p->length) == 0)) {
		        (void) KGSS_RELEASE_OID(&minor_status, &oid);
			return (gss_OID) p;
		}
	}
	return oid;
}

krb5_error_code
krb5_gss_ser_init (krb5_context context)
{
    krb5_error_code code;
    static krb5_error_code (KRB5_CALLCONV *const fns[])(krb5_context) = {
	krb5_ser_auth_context_init,
#ifndef _KERNEL
	krb5_ser_context_init,
	krb5_ser_ccache_init, krb5_ser_rcache_init, krb5_ser_keytab_init,
#endif
    };
    int i;

    for (i = 0; i < sizeof(fns)/sizeof(fns[0]); i++)
	if ((code = (fns[i])(context)) != 0)
	    return code;
    return 0;
}

OM_uint32
krb5_gss_import_sec_context(minor_status, interprocess_token, context_handle)
    OM_uint32		*minor_status;
    gss_buffer_t	interprocess_token;
    gss_ctx_id_t	*context_handle;
{
    krb5_context	context;
    krb5_error_code	kret = 0;
    size_t		blen;
    krb5_gss_ctx_id_t	ctx;
    krb5_octet		*ibp;

    /* This is a bit screwy.  We create a krb5 context because we need
       one when calling the serialization code.  However, one of the
       objects we're unpacking is a krb5 context, so when we finish,
       we can throw this one away.  */
    kret = KGSS_INIT_CONTEXT(&context);
    if (kret) {
	*minor_status = kret;
	return GSS_S_FAILURE;
    }

    kret = krb5_gss_ser_init(context);
    if (kret) {
	*minor_status = kret;
	save_error_info(*minor_status, context);
	krb5_free_context(context);
	return GSS_S_FAILURE;
    }

    /* Assume a tragic failure */
    ctx = (krb5_gss_ctx_id_t) NULL;
    *minor_status = 0;

    /* Internalize the context */
    ibp = (krb5_octet *) interprocess_token->value;
    blen = (size_t) interprocess_token->length;
    kret = kg_ctx_internalize(context, (krb5_pointer *) &ctx, &ibp, &blen);
    /*
     * SUNW15resync
     *
     *    krb5_free_context(context);
     * Previous versions of MIT(1.2ish)/Solaris did not serialize the
     * k5_context but MIT 1.5 does.  But we don't need all the userspace
     * junk in the kernel so we continue to not serialize it.
     * So we keep this context live here (see it's use in kg_ctx_internalize)
     * and it will get freed by delete_sec_context.
     */
    if (kret) {
       *minor_status = (OM_uint32) kret;
       save_error_info(*minor_status, context);
       krb5_free_context(context);
       return(GSS_S_FAILURE);
    }

    /* intern the context handle */
    if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
       (void)krb5_gss_delete_sec_context(minor_status,
					 (gss_ctx_id_t *) &ctx, NULL
#ifdef _KERNEL
 					,0  /* gssd_ctx_verifier */
#endif
					);
       *minor_status = (OM_uint32) G_VALIDATE_FAILED;
       return(GSS_S_FAILURE);
    }
    ctx->mech_used = krb5_gss_convert_static_mech_oid(ctx->mech_used);

    *context_handle = (gss_ctx_id_t) ctx;

    *minor_status = 0;
    return (GSS_S_COMPLETE);
}
