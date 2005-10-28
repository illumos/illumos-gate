/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/gssapi/krb5/import_sec_context.c
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
 * import_sec_context.c	- Internalize the security context.
 */
#include <gssapiP_krb5.h>
#include <k5-int.h>
#include <gssapi/gssapi.h>

/*
 * Fix up the OID of the mechanism so that uses the static version of
 * the OID if possible.
 *
 * Solaris Kerberos: this is not necessary.  Our mech_used is allocated
 * as part of the context structure.  This function attempts to point to
 * the corresponding gss_OID in the array krb5_gss_oid_array.
 */
#if 0
gss_OID_desc krb5_gss_convert_static_mech_oid(oid)
     gss_OID	FAR oid;
{
	const gss_OID_desc 	*p;
	OM_uint32		minor_status;
	
	for (p = krb5_gss_oid_array; p->length; p++) {
		if ((oid->length == p->length) &&
		    (memcmp(oid->elements, p->elements, p->length) == 0)) {
			gss_release_oid(&minor_status, &oid);
			return *p;
		}
	}
	return *oid;
}
#endif

OM_uint32
krb5_gss_import_sec_context(ct, minor_status, interprocess_token, context_handle)
    void		*ct;
    OM_uint32		*minor_status;
    gss_buffer_t	interprocess_token;
    gss_ctx_id_t	*context_handle;
{
    krb5_context	context;
    krb5_error_code	kret = 0;
    size_t		blen;
    krb5_gss_ctx_id_t	ctx;
    krb5_octet		*ibp;

   /* Solaris Kerberos:  we use the global kg_context for MT safe */
#if 0
    if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return(GSS_S_FAILURE);
#endif

    KRB5_LOG0(KRB5_INFO, "krb5_gss_import_sec_context() start\n");

    mutex_lock(&krb5_mutex);
    context = ct;

    /* Assume a tragic failure */
    ctx = (krb5_gss_ctx_id_t) NULL;
    *minor_status = 0;

    /* Internalize the context */
    ibp = (krb5_octet *) interprocess_token->value;
    blen = (size_t) interprocess_token->length;
    if ((kret = kg_ctx_internalize(context,
				   (krb5_pointer *) &ctx,
				   &ibp, &blen))) {
       *minor_status = (OM_uint32) kret;
       mutex_unlock(&krb5_mutex);
       
       KRB5_LOG(KRB5_ERR, "krb5_gss_import_sec_context() end,"
		"kg_ctx_internalize() error kret = %d\n", kret);

       if (kret == ENOMEM)
           return(GSS_S_FAILURE);
       else
           return(GSS_S_DEFECTIVE_TOKEN);
    }

    /* intern the context handle */
    if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
       (void)krb5_gss_delete_sec_context_no_lock(context, minor_status, 
					 (gss_ctx_id_t *) &ctx, NULL
#ifdef _KERNEL
					,0  /* gssd_ctx_verifier */
#endif
					);
       *minor_status = (OM_uint32) G_VALIDATE_FAILED;
       mutex_unlock(&krb5_mutex);

       KRB5_LOG0(KRB5_ERR, "krb5_gss_import_sec_context() end,"
		"kg_save_ctx_id() error\n");

       return(GSS_S_FAILURE);
    }
    if (! kg_validate_ctx_id((gss_ctx_id_t) ctx)) {
       *minor_status = (OM_uint32) G_VALIDATE_FAILED;
        mutex_unlock(&krb5_mutex);

	KRB5_LOG0(KRB5_ERR, "krb5_gss_import_sec_context() end,"
		"kg_validate_ctx_id() error\n");

        return(GSS_S_FAILURE);
    }

    /* Solaris Kerberos:  our mech_used is part of the ctx structure */
    /* ctx->mech_used = krb5_gss_convert_static_mech_oid(&(ctx->mech_used)); */

    *context_handle = (gss_ctx_id_t) ctx;

    *minor_status = 0;
    mutex_unlock(&krb5_mutex);

    KRB5_LOG0(KRB5_INFO, "krb5_gss_import_sec_context() end\n");

    return (GSS_S_COMPLETE);
}
