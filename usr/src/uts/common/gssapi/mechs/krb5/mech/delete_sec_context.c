/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "gssapiP_krb5.h"
#include "mglueP.h"  /* SUNW15resync - for KGSS_ macros */

/*
 * $Id: delete_sec_context.c 18396 2006-07-25 20:29:43Z lxs $
 */


#ifdef	 _KERNEL
/* SUNW15resync - todo - unify these kernel rel oid funcs with user spc ones */

OM_uint32
krb5_gss_internal_release_oid(minor_status, oid)
    OM_uint32	*minor_status;
    gss_OID	*oid;
{
    /*
     * This function only knows how to release internal OIDs. It will
     * return GSS_S_CONTINUE_NEEDED for any OIDs it does not recognize.
     */

    if ((*oid != gss_mech_krb5) &&
	(*oid != gss_mech_krb5_old) &&
	(*oid != gss_mech_krb5_wrong) &&
	(*oid != gss_nt_krb5_name) &&
	(*oid != gss_nt_krb5_principal)) {
	/* We don't know about this OID */
	return(GSS_S_CONTINUE_NEEDED);
    }
    else {
	*oid = GSS_C_NO_OID;
	*minor_status = 0;
	return(GSS_S_COMPLETE);
    }
}

OM_uint32
generic_gss_release_oid(minor_status, oid)
    OM_uint32	*minor_status;
    gss_OID	*oid;
{
    if (minor_status)
	*minor_status = 0;

    if (*oid == GSS_C_NO_OID)
	return(GSS_S_COMPLETE);


    if ((*oid != GSS_C_NT_USER_NAME) &&
	(*oid != GSS_C_NT_MACHINE_UID_NAME) &&
	(*oid != GSS_C_NT_STRING_UID_NAME) &&
	(*oid != GSS_C_NT_HOSTBASED_SERVICE) &&
	(*oid != GSS_C_NT_ANONYMOUS) &&
	(*oid != GSS_C_NT_EXPORT_NAME) &&
	(*oid != gss_nt_service_name)) {
	FREE((*oid)->elements, (*oid)->length);
	FREE(*oid, sizeof(gss_OID_desc));
    }
    *oid = GSS_C_NO_OID;
    return(GSS_S_COMPLETE);
}

OM_uint32
krb5_gss_release_oid(minor_status, oid)
    OM_uint32	*minor_status;
    gss_OID	*oid;
{

    if (krb5_gss_internal_release_oid(minor_status, oid) != GSS_S_COMPLETE) {
	/* Pawn it off on the generic routine */
	return(generic_gss_release_oid(minor_status, oid));
    }
    else {
	*oid = GSS_C_NO_OID;
	*minor_status = 0;
	return(GSS_S_COMPLETE);
    }
}
#endif

/*ARGSUSED*/
OM_uint32
krb5_gss_delete_sec_context(minor_status,
			    context_handle,
			    output_token
#ifdef	 _KERNEL
			    , gssd_ctx_verifier
#endif
			    )
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_buffer_t output_token;
#ifdef	 _KERNEL
     OM_uint32 gssd_ctx_verifier;
#endif
{
   krb5_context context;
   krb5_gss_ctx_id_rec *ctx;

   if (output_token) {
      output_token->length = 0;
      output_token->value = NULL;
   }

   /*SUPPRESS 29*/
   if (*context_handle == GSS_C_NO_CONTEXT) {
      *minor_status = 0;
      return(GSS_S_COMPLETE);
   }

   /*SUPPRESS 29*/
   /* validate the context handle */
   if (! kg_validate_ctx_id(*context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_t) *context_handle;
   context = ctx->k5_context;

   /* construct a delete context token if necessary */

   if (output_token) {
      OM_uint32 major;
      gss_buffer_desc empty;
      empty.length = 0; empty.value = NULL;

      if ((major = kg_seal(minor_status, *context_handle, 0,
			   GSS_C_QOP_DEFAULT,
			   &empty, NULL, output_token, KG_TOK_DEL_CTX))) {
	 save_error_info(*minor_status, context);
	 return(major);
      }
   }

   /* invalidate the context handle */

   (void)kg_delete_ctx_id(*context_handle);

   /* free all the context state */

   if (ctx->seqstate)
      g_order_free(&(ctx->seqstate));

   if (ctx->enc)
      krb5_free_keyblock(context, ctx->enc);

   if (ctx->seq)
      krb5_free_keyblock(context, ctx->seq);

   if (ctx->here)
      krb5_free_principal(context, ctx->here);
   if (ctx->there)
      krb5_free_principal(context, ctx->there);
   if (ctx->subkey)
      krb5_free_keyblock(context, ctx->subkey);
   if (ctx->acceptor_subkey)
       krb5_free_keyblock(context, ctx->acceptor_subkey);

   /* We never import the auth_context into the kernel */
#ifndef _KERNEL
   if (ctx->auth_context) {
       if (ctx->cred_rcache)
	   (void)krb5_auth_con_setrcache(context, ctx->auth_context, NULL);

       krb5_auth_con_free(context, ctx->auth_context);
   }
#endif

   if (ctx->mech_used)
       (void) KGSS_RELEASE_OID(minor_status, &ctx->mech_used);

   if (ctx->authdata)
	krb5_free_authdata(context, ctx->authdata);

   if (ctx->k5_context)
       krb5_free_context(ctx->k5_context);

   /* Zero out context */
   (void) memset(ctx, 0, sizeof(*ctx));
   xfree_wrap(ctx, sizeof (krb5_gss_ctx_id_rec));

   /* zero the handle itself */

   *context_handle = GSS_C_NO_CONTEXT;

   *minor_status = 0;
   return(GSS_S_COMPLETE);
}
