#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

OM_uint32
krb5_gss_inquire_context(minor_status, context_handle, initiator_name, 
			 acceptor_name, lifetime_rec, mech_type, ret_flags,
			 locally_initiated, open)
     OM_uint32 *minor_status;
     gss_ctx_id_t context_handle;
     gss_name_t *initiator_name;
     gss_name_t *acceptor_name;
     OM_uint32 *lifetime_rec;
     gss_OID *mech_type;
     OM_uint32 *ret_flags;
     int *locally_initiated;
     int *open;
{
   krb5_context context;
   krb5_error_code code;
   krb5_gss_ctx_id_rec *ctx;
   krb5_principal init, accept;
   krb5_timestamp now;
   krb5_deltat lifetime;

   if (initiator_name)
      *initiator_name = (gss_name_t) NULL;
   if (acceptor_name)
      *acceptor_name = (gss_name_t) NULL;

   /* validate the context handle */
   if (! kg_validate_ctx_id(context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_rec *) context_handle;

   if (! ctx->established) {
      *minor_status = KG_CTX_INCOMPLETE;
      return(GSS_S_NO_CONTEXT);
   }

   init = NULL;
   accept = NULL;
   context = ctx->k5_context;

   if ((code = krb5_timeofday(context, &now))) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if ((lifetime = ctx->endtime - now) < 0)
      lifetime = 0;

   if (initiator_name) {
      if ((code = krb5_copy_principal(context, 
				      ctx->initiate?ctx->here:ctx->there,
				      &init))) {
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      if (! kg_save_name((gss_name_t) init)) {
	 krb5_free_principal(context, init);
	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
	 return(GSS_S_FAILURE);
      }
   }

   if (acceptor_name) {
      if ((code = krb5_copy_principal(context, 
				      ctx->initiate?ctx->there:ctx->here,
				      &accept))) {
	 if (init) krb5_free_principal(context, init);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      if (! kg_save_name((gss_name_t) accept)) {
	 krb5_free_principal(context, accept);
	 if (init) {
	    kg_delete_name((gss_name_t) accept);
	    krb5_free_principal(context, init);
	 }
	 *minor_status = (OM_uint32) G_VALIDATE_FAILED;
	 return(GSS_S_FAILURE);
      }
   }

   if (initiator_name)
      *initiator_name = (gss_name_t) init;

   if (acceptor_name)
      *acceptor_name = (gss_name_t) accept;

   if (lifetime_rec)
      *lifetime_rec = lifetime;

   if (mech_type)
      *mech_type = (gss_OID) ctx->mech_used;

   if (ret_flags)
      *ret_flags = ctx->gss_flags;

   if (locally_initiated)
      *locally_initiated = ctx->initiate;

   if (open)
      *open = ctx->established;

   *minor_status = 0;
   return((lifetime == 0)?GSS_S_CONTEXT_EXPIRED:GSS_S_COMPLETE);
}
