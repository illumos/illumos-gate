/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2000,2002, 2003 by the Massachusetts Institute of Technology.
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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Solaris Kerberos */
#include <libintl.h>
#include <locale.h>

#include "k5-int.h"
#include "gss_libinit.h"
#include "gssapiP_krb5.h"
#include "mglueP.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <stdlib.h>
#include <assert.h>

/* Solaris Kerberos start */
static OM_uint32 get_default_cred(OM_uint32 *, void *, gss_cred_id_t *);
/* Solaris Kerberos end */

/*
 * $Id: init_sec_context.c 18721 2006-10-16 16:18:29Z epeisach $
 */

/* XXX This is for debugging only!!!  Should become a real bitfield
   at some point */
int krb5_gss_dbg_client_expcreds = 0;

/*
 * Common code which fetches the correct krb5 credentials from the
 * ccache.
 */
static krb5_error_code get_credentials(context, cred, server, now,
				       endtime, out_creds)
    krb5_context context;
    krb5_gss_cred_id_t cred;
    krb5_principal server;
    krb5_timestamp now;
    krb5_timestamp endtime;
    krb5_creds **out_creds;
{
    krb5_error_code	code;
    krb5_creds 		in_creds;

    k5_mutex_assert_locked(&cred->lock);
    memset((char *) &in_creds, 0, sizeof(krb5_creds));

    if ((code = krb5_copy_principal(context, cred->princ, &in_creds.client)))
	goto cleanup;
    if ((code = krb5_copy_principal(context, server, &in_creds.server)))
	goto cleanup;
    in_creds.times.endtime = endtime;

    in_creds.keyblock.enctype = 0;

    code = krb5_get_credentials(context, 0, cred->ccache,
				&in_creds, out_creds);
    if (code)
	goto cleanup;

    /*
     * Enforce a stricter limit (without timeskew forgiveness at the
     * boundaries) because accept_sec_context code is also similarly
     * non-forgiving.
     */
    if (!krb5_gss_dbg_client_expcreds && *out_creds != NULL &&
	(*out_creds)->times.endtime < now) {
	code = KRB5KRB_AP_ERR_TKT_EXPIRED;
	goto cleanup;
    }
    
cleanup:
    if (in_creds.client)
	    krb5_free_principal(context, in_creds.client);
    if (in_creds.server)
	    krb5_free_principal(context, in_creds.server);
    return code;
}
struct gss_checksum_data {
    krb5_gss_ctx_id_rec *ctx;
    krb5_gss_cred_id_t cred;
    krb5_checksum md5;
    krb5_data checksum_data;
};

#ifdef CFX_EXERCISE
#include "../../krb5/krb/auth_con.h"
#endif
static krb5_error_code KRB5_CALLCONV
make_gss_checksum (krb5_context context, krb5_auth_context auth_context,
		   void *cksum_data, krb5_data **out)
{
    krb5_error_code code;
    krb5_int32 con_flags;
    unsigned char *ptr;
    struct gss_checksum_data *data = cksum_data;
    krb5_data credmsg;
    unsigned int junk;

    data->checksum_data.data = 0;
    credmsg.data = 0;
    /* build the checksum field */

    if (data->ctx->gss_flags & GSS_C_DELEG_FLAG) {
	/* first get KRB_CRED message, so we know its length */

	/* clear the time check flag that was set in krb5_auth_con_init() */
	krb5_auth_con_getflags(context, auth_context, &con_flags);
	krb5_auth_con_setflags(context, auth_context,
			       con_flags & ~KRB5_AUTH_CONTEXT_DO_TIME);

	code = krb5_fwd_tgt_creds(context, auth_context, 0,
				  data->cred->princ, data->ctx->there,
				  data->cred->ccache, 1,
				  &credmsg);

	/* turn KRB5_AUTH_CONTEXT_DO_TIME back on */
	krb5_auth_con_setflags(context, auth_context, con_flags);

	if (code) {
	    /* don't fail here; just don't accept/do the delegation
               request */
	    data->ctx->gss_flags &= ~GSS_C_DELEG_FLAG;

	    data->checksum_data.length = 24;
	} else {
	    if (credmsg.length+28 > KRB5_INT16_MAX) {
		krb5_free_data_contents(context, &credmsg);
		return(KRB5KRB_ERR_FIELD_TOOLONG);
	    }

	    data->checksum_data.length = 28+credmsg.length;
	}
    } else {
	data->checksum_data.length = 24;
    }
#ifdef CFX_EXERCISE
    if (data->ctx->auth_context->keyblock != NULL
	&& data->ctx->auth_context->keyblock->enctype == 18) {
	srand(time(0) ^ getpid());
	/* Our ftp client code stupidly assumes a base64-encoded
	   version of the token will fit in 10K, so don't make this
	   too big.  */
	junk = rand() & 0xff;
    } else
	junk = 0;
#else
    junk = 0;
#endif

    data->checksum_data.length += junk;

    /* now allocate a buffer to hold the checksum data and
       (maybe) KRB_CRED msg */

    if ((data->checksum_data.data =
	 (char *) xmalloc(data->checksum_data.length)) == NULL) {
	if (credmsg.data)
	    krb5_free_data_contents(context, &credmsg);
	return(ENOMEM);
    }
    /* Solaris Kerberos */
    ptr = (uchar_t *)data->checksum_data.data; /* SUNW15resync */

    TWRITE_INT(ptr, data->md5.length, 0);
    TWRITE_STR(ptr, (unsigned char *) data->md5.contents, data->md5.length);
    TWRITE_INT(ptr, data->ctx->gss_flags, 0);

    /* done with this, free it */
    xfree(data->md5.contents);

    if (credmsg.data) {
	TWRITE_INT16(ptr, KRB5_GSS_FOR_CREDS_OPTION, 0);
	TWRITE_INT16(ptr, credmsg.length, 0);
	TWRITE_STR(ptr, (unsigned char *) credmsg.data, credmsg.length);

	/* free credmsg data */
	krb5_free_data_contents(context, &credmsg);
    }
    if (junk)
	memset(ptr, 'i', junk);
    *out = &data->checksum_data;
    return 0;
}
    
static krb5_error_code
make_ap_req_v1(context, ctx, cred, k_cred, chan_bindings, mech_type, token)
    krb5_context context;
    krb5_gss_ctx_id_rec *ctx;
    krb5_gss_cred_id_t cred;
    krb5_creds *k_cred;
    gss_channel_bindings_t chan_bindings;
    gss_OID mech_type;
    gss_buffer_t token;
{
    krb5_flags mk_req_flags = 0;
    krb5_error_code code;
    struct gss_checksum_data cksum_struct;
    krb5_checksum md5;
    krb5_data ap_req;
    krb5_data *checksum_data = NULL;
    unsigned char *ptr;
    unsigned char *t;
    unsigned int tlen;

    k5_mutex_assert_locked(&cred->lock);
    ap_req.data = 0;

    /* compute the hash of the channel bindings */

    if ((code = kg_checksum_channel_bindings(context, chan_bindings, &md5, 0)))
        return(code);

    krb5_auth_con_set_req_cksumtype(context, ctx->auth_context,
				    CKSUMTYPE_KG_CB);
    cksum_struct.md5 = md5;
    cksum_struct.ctx = ctx;
    cksum_struct.cred = cred;
    cksum_struct.checksum_data.data = NULL;
    switch (k_cred->keyblock.enctype) {
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_MD5:
    case ENCTYPE_DES3_CBC_SHA1:
      code = make_gss_checksum(context, ctx->auth_context, &cksum_struct,
				 &checksum_data);
	    if (code)
		goto cleanup;
	break;
    default:
	krb5_auth_con_set_checksum_func(context, ctx->auth_context,
					make_gss_checksum, &cksum_struct);
	    break;
    }


    /* call mk_req.  subkey and ap_req need to be used or destroyed */

    mk_req_flags = AP_OPTS_USE_SUBKEY;

    if (ctx->gss_flags & GSS_C_MUTUAL_FLAG)
	mk_req_flags |= AP_OPTS_MUTUAL_REQUIRED;

    code = krb5_mk_req_extended(context, &ctx->auth_context, mk_req_flags,
				checksum_data, k_cred, &ap_req);
    krb5_free_data_contents(context, &cksum_struct.checksum_data);
    if (code)
	goto cleanup;

   /* store the interesting stuff from creds and authent */
   ctx->endtime = k_cred->times.endtime;
   ctx->krb_flags = k_cred->ticket_flags;

   /* build up the token */

   /* allocate space for the token */
   tlen = g_token_size((gss_OID) mech_type, ap_req.length);

   if ((t = (unsigned char *) xmalloc(tlen)) == NULL) {
      code = ENOMEM;
      goto cleanup;
   }

   /* fill in the buffer */

   ptr = t;

   g_make_token_header(mech_type, ap_req.length,
		       &ptr, KG_TOK_CTX_AP_REQ);

   TWRITE_STR(ptr, (unsigned char *) ap_req.data, ap_req.length);

   /* pass it back */

   token->length = tlen;
   token->value = (void *) t;

   code = 0;
    
 cleanup:
   if (checksum_data && checksum_data->data)
       krb5_free_data_contents(context, checksum_data);
   if (ap_req.data)
       krb5_free_data_contents(context, &ap_req);

   return (code);
}

/*
 * setup_enc
 *
 * Fill in the encryption descriptors.  Called after AP-REQ is made.
 */
static OM_uint32
setup_enc(
   OM_uint32 *minor_status,
   krb5_gss_ctx_id_rec *ctx,
   krb5_context context)
{
   krb5_error_code code;
   int i;
   krb5int_access kaccess;

   code = krb5int_accessor (&kaccess, KRB5INT_ACCESS_VERSION);
   if (code)
       goto fail;

   ctx->have_acceptor_subkey = 0;
   ctx->proto = 0;
   ctx->cksumtype = 0;
   switch(ctx->subkey->enctype) {
   case ENCTYPE_DES_CBC_MD5:
   case ENCTYPE_DES_CBC_MD4:
   case ENCTYPE_DES_CBC_CRC:
      ctx->subkey->enctype = ENCTYPE_DES_CBC_RAW;
      ctx->signalg = SGN_ALG_DES_MAC_MD5;
      ctx->cksum_size = 8;
      ctx->sealalg = SEAL_ALG_DES;

      /* The encryption key is the session key XOR
	 0xf0f0f0f0f0f0f0f0.  */
      if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc)))
	 goto fail;

      for (i=0; i<ctx->enc->length; i++)
	 ctx->enc->contents[i] ^= 0xf0;

      goto copy_subkey_to_seq;

   case ENCTYPE_DES3_CBC_SHA1:
       /* MIT extension */
      ctx->subkey->enctype = ENCTYPE_DES3_CBC_RAW;
      ctx->signalg = SGN_ALG_HMAC_SHA1_DES3_KD;
      ctx->cksum_size = 20;
      ctx->sealalg = SEAL_ALG_DES3KD;

   copy_subkey:
      code = krb5_copy_keyblock (context, ctx->subkey, &ctx->enc);
      if (code)
	 goto fail;
   copy_subkey_to_seq:
      code = krb5_copy_keyblock (context, ctx->subkey, &ctx->seq);
      if (code) {
	 krb5_free_keyblock (context, ctx->enc);
	 goto fail;
      }
      goto success;

   case ENCTYPE_ARCFOUR_HMAC:
       /* Microsoft extension */
      ctx->signalg = SGN_ALG_HMAC_MD5 ;
      ctx->cksum_size = 8;
      ctx->sealalg = SEAL_ALG_MICROSOFT_RC4 ;

      goto copy_subkey;

   default:
       /* Fill some fields we shouldn't be using on this path
	  with garbage.  */
       ctx->signalg = -10;
       ctx->sealalg = -10;

       ctx->proto = 1;
       code = (*kaccess.krb5int_c_mandatory_cksumtype)(context, ctx->subkey->enctype,
					    &ctx->cksumtype);
       if (code)
	   goto fail;
       code = krb5_c_checksum_length(context, ctx->cksumtype,
				     &ctx->cksum_size);
       if (code)
	   goto fail;
       goto copy_subkey;
   }
fail:
   /* SUNW15resync - (as in prev snv code) add if-code and success label fix */
  if (code) {
      *minor_status = code;
      return GSS_S_FAILURE;
  }

success:
   return (GSS_S_COMPLETE);
}

/*
 * new_connection
 *
 * Do the grunt work of setting up a new context.
 */
static OM_uint32
new_connection(
   OM_uint32 *minor_status,
   krb5_gss_cred_id_t cred,
   gss_ctx_id_t *context_handle,
   gss_name_t target_name,
   gss_OID mech_type,
   OM_uint32 req_flags,
   OM_uint32 time_req,
   gss_channel_bindings_t input_chan_bindings,
   gss_buffer_t input_token,
   gss_OID *actual_mech_type,
   gss_buffer_t output_token,
   OM_uint32 *ret_flags,
   OM_uint32 *time_rec,
   krb5_context context,
   int default_mech)
{
   OM_uint32 major_status;
   krb5_error_code code;
   krb5_creds *k_cred;
   krb5_gss_ctx_id_rec *ctx, *ctx_free;
   krb5_timestamp now;
   gss_buffer_desc token;

   k5_mutex_assert_locked(&cred->lock);
   major_status = GSS_S_FAILURE;
   token.length = 0;
   token.value = NULL;

   /* make sure the cred is usable for init */

   if ((cred->usage != GSS_C_INITIATE) &&
       (cred->usage != GSS_C_BOTH)) {
      *minor_status = 0;
      return(GSS_S_NO_CRED);
   }

   /* complain if the input token is non-null */

   if (input_token != GSS_C_NO_BUFFER && input_token->length != 0) {
       *minor_status = 0;
       return(GSS_S_DEFECTIVE_TOKEN);
   }

   /* create the ctx */

   if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
       == NULL) {
      *minor_status = ENOMEM;
      return(GSS_S_FAILURE);
   }

   /* fill in the ctx */
   memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));
   ctx_free = ctx;
   if ((code = krb5_auth_con_init(context, &ctx->auth_context)))
      goto fail;
   krb5_auth_con_setflags(context, ctx->auth_context,
			  KRB5_AUTH_CONTEXT_DO_SEQUENCE);

   /* limit the encryption types negotiated (if requested) */
   if (cred->req_enctypes) {
	if ((code = krb5_set_default_tgs_enctypes(context,
						  cred->req_enctypes))) {
	    goto fail;
	}
   }

   ctx->initiate = 1;
   ctx->gss_flags = (GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG |
                     GSS_C_TRANS_FLAG | 
                     ((req_flags) & (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
                                     GSS_C_SEQUENCE_FLAG | GSS_C_DELEG_FLAG)));
   ctx->seed_init = 0;
   ctx->big_endian = 0;  /* all initiators do little-endian, as per spec */
   ctx->seqstate = 0;

   if ((code = krb5_timeofday(context, &now)))
      goto fail;

   if (time_req == 0 || time_req == GSS_C_INDEFINITE) {
      ctx->endtime = 0;
   } else {
      ctx->endtime = now + time_req;
   }

   if ((code = krb5_copy_principal(context, cred->princ, &ctx->here)))
      goto fail;
      
   if ((code = krb5_copy_principal(context, (krb5_principal) target_name,
				   &ctx->there)))
      goto fail;

   code = get_credentials(context, cred, ctx->there, now,
			  ctx->endtime, &k_cred);
   if (code)
      goto fail;

   if (default_mech) {
      mech_type = (gss_OID) gss_mech_krb5;
   }

   if (generic_gss_copy_oid(minor_status, mech_type, &ctx->mech_used)
       != GSS_S_COMPLETE) {
      code = *minor_status;
      goto fail;
   }
   /*
    * Now try to make it static if at all possible....
    */
   ctx->mech_used = krb5_gss_convert_static_mech_oid(ctx->mech_used);

   {
      /* gsskrb5 v1 */
      krb5_ui_4 seq_temp;
      if ((code = make_ap_req_v1(context, ctx,
				 cred, k_cred, input_chan_bindings, 
				 mech_type, &token))) {
	 if ((code == KRB5_FCC_NOFILE) || (code == KRB5_CC_NOTFOUND) ||
	     (code == KG_EMPTY_CCACHE))
	    major_status = GSS_S_NO_CRED;
	 if (code == KRB5KRB_AP_ERR_TKT_EXPIRED)
	    major_status = GSS_S_CREDENTIALS_EXPIRED;
	 goto fail;
      }

      krb5_auth_con_getlocalseqnumber(context, ctx->auth_context,
			    (krb5_int32 *)&seq_temp); /* SUNW15resync */
      ctx->seq_send = seq_temp;
      krb5_auth_con_getsendsubkey(context, ctx->auth_context,
				  &ctx->subkey);
   }

   major_status = setup_enc(minor_status, ctx, context);

   if (k_cred) {
      krb5_free_creds(context, k_cred);
      k_cred = 0;
   }
      
   /* at this point, the context is constructed and valid,
      hence, releaseable */

   /* intern the context handle */

   if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
      code = G_VALIDATE_FAILED;
      goto fail;
   }
   *context_handle = (gss_ctx_id_t) ctx;
   ctx_free = 0;

   /* compute time_rec */
   if (time_rec) {
      if ((code = krb5_timeofday(context, &now)))
	 goto fail;
      *time_rec = ctx->endtime - now;
   }

   /* set the other returns */
   *output_token = token;

   if (ret_flags)
      *ret_flags = ctx->gss_flags;

   if (actual_mech_type)
      *actual_mech_type = mech_type;

   /* return successfully */

   *minor_status = 0;
   if (ctx->gss_flags & GSS_C_MUTUAL_FLAG) {
      ctx->established = 0;
      return(GSS_S_CONTINUE_NEEDED);
   } else {
      ctx->seq_recv = ctx->seq_send;
      g_order_init(&(ctx->seqstate), ctx->seq_recv,
		   (ctx->gss_flags & GSS_C_REPLAY_FLAG) != 0, 
		   (ctx->gss_flags & GSS_C_SEQUENCE_FLAG) != 0, ctx->proto);
      ctx->gss_flags |= GSS_C_PROT_READY_FLAG;
      ctx->established = 1;
      return(GSS_S_COMPLETE);
   }

fail:
   if (ctx_free) {
       if (ctx_free->auth_context)
	   krb5_auth_con_free(context, ctx_free->auth_context);
       if (ctx_free->here)
	   krb5_free_principal(context, ctx_free->here);
       if (ctx_free->there)
	   krb5_free_principal(context, ctx_free->there);
       if (ctx_free->subkey)
	   krb5_free_keyblock(context, ctx_free->subkey);
       xfree(ctx_free);
   } else
	(void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);

   *minor_status = code;
   return (major_status);
}

/*
 * mutual_auth
 *
 * Handle the reply from the acceptor, if we're doing mutual auth.
 */
static OM_uint32
mutual_auth(
   OM_uint32 *minor_status,
   gss_ctx_id_t *context_handle,
   gss_name_t target_name,
   gss_OID mech_type,
   OM_uint32 req_flags,
   OM_uint32 time_req,
   gss_channel_bindings_t input_chan_bindings,
   gss_buffer_t input_token,
   gss_OID *actual_mech_type,
   gss_buffer_t output_token,
   OM_uint32 *ret_flags,
   OM_uint32 *time_rec,
   krb5_context context)
{
   OM_uint32 major_status;
   unsigned char *ptr;
   char *sptr;
   krb5_data ap_rep;
   krb5_ap_rep_enc_part *ap_rep_data;
   krb5_timestamp now;
   krb5_gss_ctx_id_rec *ctx;
   krb5_error *krb_error;
   krb5_error_code code;
   krb5int_access kaccess;

   major_status = GSS_S_FAILURE;

   code = krb5int_accessor (&kaccess, KRB5INT_ACCESS_VERSION);
   if (code)
       goto fail;

   /* validate the context handle */
   /*SUPPRESS 29*/
   if (! kg_validate_ctx_id(*context_handle)) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_NO_CONTEXT);
   }

   ctx = (krb5_gss_ctx_id_t) *context_handle;

   /* make sure the context is non-established, and that certain
      arguments are unchanged */

   if ((ctx->established) ||
       ((ctx->gss_flags & GSS_C_MUTUAL_FLAG) == 0)) {
      code = KG_CONTEXT_ESTABLISHED;
      goto fail;
   }

   if (! krb5_principal_compare(context, ctx->there, 
				(krb5_principal) target_name)) {
       /* Solaris Kerberos: spruce-up the err msg */
       krb5_principal tname = (krb5_principal) target_name;
       char *s_name = NULL, *s_princ= NULL;
       int kret = krb5_unparse_name(context, tname, &s_name);
       int kret1 = krb5_unparse_name(context, ctx->there, &s_princ);
       code = KRB5_PRINC_NOMATCH;
       if (kret == 0 && kret1 == 0) {
	   krb5_set_error_message(context, code,
				dgettext(TEXT_DOMAIN,
					"Target name principal '%s' does not match '%s'"),
				s_name, s_princ);
	   save_error_info(code, context);
       }
       if (s_name)
	   krb5_free_unparsed_name(context, s_name);
       if (s_princ)
	   krb5_free_unparsed_name(context, s_princ);

       (void)krb5_gss_delete_sec_context(minor_status, 
					context_handle, NULL);
       major_status = GSS_S_BAD_NAME;
       goto fail;
   }

   /* verify the token and leave the AP_REP message in ap_rep */

   if (input_token == GSS_C_NO_BUFFER) {
      (void)krb5_gss_delete_sec_context(minor_status, 
					context_handle, NULL);
      code = 0;
      major_status = GSS_S_DEFECTIVE_TOKEN;
      goto fail;
   }

   ptr = (unsigned char *) input_token->value;

   if (g_verify_token_header(ctx->mech_used,
			     &(ap_rep.length),
			     &ptr, KG_TOK_CTX_AP_REP,
			     input_token->length, 1)) {
      if (g_verify_token_header((gss_OID) ctx->mech_used,
				&(ap_rep.length),
				&ptr, KG_TOK_CTX_ERROR,
				input_token->length, 1) == 0) {

	 /* Handle a KRB_ERROR message from the server */

	 sptr = (char *) ptr;           /* PC compiler bug */
	 TREAD_STR(sptr, ap_rep.data, ap_rep.length);
		      
	 code = krb5_rd_error(context, &ap_rep, &krb_error);
	 if (code)
	    goto fail;
	 if (krb_error->error)
	    code = krb_error->error + ERROR_TABLE_BASE_krb5;
	 else
	    code = 0;
	 krb5_free_error(context, krb_error);
	 goto fail;
      } else {
	 *minor_status = 0;
	 return(GSS_S_DEFECTIVE_TOKEN);
      }
   }

   sptr = (char *) ptr;                      /* PC compiler bug */
   TREAD_STR(sptr, ap_rep.data, ap_rep.length);

   /* decode the ap_rep */
   if ((code = krb5_rd_rep(context, ctx->auth_context, &ap_rep,
			   &ap_rep_data))) {
      /*
       * XXX A hack for backwards compatiblity.
       * To be removed in 1999 -- proven 
       */
      krb5_auth_con_setuseruserkey(context, ctx->auth_context,
				   ctx->subkey);
      if ((krb5_rd_rep(context, ctx->auth_context, &ap_rep,
		       &ap_rep_data)))
	 goto fail;
   }

   /* store away the sequence number */
   ctx->seq_recv = ap_rep_data->seq_number;
   g_order_init(&(ctx->seqstate), ctx->seq_recv,
		(ctx->gss_flags & GSS_C_REPLAY_FLAG) != 0,
		(ctx->gss_flags & GSS_C_SEQUENCE_FLAG) !=0, ctx->proto);

   if (ctx->proto == 1 && ap_rep_data->subkey) {
       /* Keep acceptor's subkey.  */
       ctx->have_acceptor_subkey = 1;
       code = krb5_copy_keyblock(context, ap_rep_data->subkey,
				 &ctx->acceptor_subkey);
       if (code)
	   goto fail;
       code = (*kaccess.krb5int_c_mandatory_cksumtype)(context,
					    ctx->acceptor_subkey->enctype,
					    &ctx->acceptor_subkey_cksumtype);
       if (code)
	   goto fail;
   }

   /* free the ap_rep_data */
   krb5_free_ap_rep_enc_part(context, ap_rep_data);

   /* set established */
   ctx->established = 1;

   /* set returns */

   if (time_rec) {
      if ((code = krb5_timeofday(context, &now)))
	 goto fail;
      *time_rec = ctx->endtime - now;
   }

   if (ret_flags)
      *ret_flags = ctx->gss_flags;

   if (actual_mech_type)
      *actual_mech_type = mech_type;

   /* success */

   *minor_status = 0;
   return GSS_S_COMPLETE;

fail:
   (void)krb5_gss_delete_sec_context(minor_status, context_handle, NULL);

   *minor_status = code;
   return (major_status);
}

OM_uint32
krb5_gss_init_sec_context(minor_status, claimant_cred_handle,
			  context_handle, target_name, mech_type,
			  req_flags, time_req, input_chan_bindings,
			  input_token, actual_mech_type, output_token,
			  ret_flags, time_rec)
    OM_uint32 *minor_status;
    gss_cred_id_t claimant_cred_handle;
    gss_ctx_id_t *context_handle;
    gss_name_t target_name;
    gss_OID mech_type;
    OM_uint32 req_flags;
    OM_uint32 time_req;
    gss_channel_bindings_t input_chan_bindings;
    gss_buffer_t input_token;
    gss_OID *actual_mech_type;
    gss_buffer_t output_token;
    OM_uint32 *ret_flags;
    OM_uint32 *time_rec;
{
   krb5_context context;
   krb5_gss_cred_id_t cred;
   int err;
   krb5_error_code kerr;
   int default_mech = 0;
   OM_uint32 major_status;
   OM_uint32 tmp_min_stat;

   if (*context_handle == GSS_C_NO_CONTEXT) {
       kerr = krb5_gss_init_context(&context);
       if (kerr) {
	   *minor_status = kerr;
	   return GSS_S_FAILURE;
       }
       if (GSS_ERROR(kg_sync_ccache_name(context, minor_status))) {
	   save_error_info(*minor_status, context);
	   krb5_free_context(context);
	   return GSS_S_FAILURE;
       }
   } else {
       context = ((krb5_gss_ctx_id_rec *)*context_handle)->k5_context;
   }

   /* set up return values so they can be "freed" successfully */

   major_status = GSS_S_FAILURE; /* Default major code */
   output_token->length = 0;
   output_token->value = NULL;
   if (actual_mech_type)
      *actual_mech_type = NULL;

   /* verify that the target_name is valid and usable */

   if (! kg_validate_name(target_name)) {
       /* Solaris Kerberos: spruce-up the err msg */
       krb5_principal princ = (krb5_principal) target_name;
       char *s_name = NULL;
       int kret = krb5_unparse_name(context, princ, &s_name);
       *minor_status = (OM_uint32) G_VALIDATE_FAILED;
       if (kret == 0) {
	   krb5_set_error_message(context, *minor_status,
				dgettext(TEXT_DOMAIN,
					"Target name principal '%s' is invalid"),
				s_name);
	   krb5_free_unparsed_name(context, s_name);
	   save_error_info(*minor_status, context);
	}

        if (*context_handle == GSS_C_NO_CONTEXT)
	    krb5_free_context(context);
        return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   /* verify the credential, or use the default */
   /*SUPPRESS 29*/
   if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
      /*
       * Solaris Kerberos: here we are using the Solaris specific
       * function get_default_cred() to handle the special case of a
       * root principal
       */
      major_status = get_default_cred(minor_status, context,
				    (gss_cred_id_t *)&cred);
      if (major_status && GSS_ERROR(major_status)) {
	  save_error_info(*minor_status, context);
	  if (*context_handle == GSS_C_NO_CONTEXT)
	      krb5_free_context(context);
	 return(major_status);
      }
   } else {
      major_status = krb5_gss_validate_cred(minor_status, claimant_cred_handle);
      if (GSS_ERROR(major_status)) {
          save_error_info(*minor_status, context);
	  if (*context_handle == GSS_C_NO_CONTEXT)
	      krb5_free_context(context);
	  return(major_status);
      }
      cred = (krb5_gss_cred_id_t) claimant_cred_handle;
   }
   kerr = k5_mutex_lock(&cred->lock);
   if (kerr) {
       krb5_free_context(context);
       *minor_status = kerr;
       return GSS_S_FAILURE;
   }

   /* verify the mech_type */

   err = 0;
   if (mech_type == GSS_C_NULL_OID) {
       default_mech = 1;
       if (cred->rfc_mech) {
	   mech_type = (gss_OID) gss_mech_krb5;
       } else if (cred->prerfc_mech) {
	   mech_type = (gss_OID) gss_mech_krb5_old;
       } else {
	   err = 1;
       }
   } else if (g_OID_equal(mech_type, gss_mech_krb5)) {
       if (!cred->rfc_mech)
	   err = 1;
   } else if (g_OID_equal(mech_type, gss_mech_krb5_old)) {
       if (!cred->prerfc_mech)
	   err = 1;
   } else if (g_OID_equal(mech_type, gss_mech_krb5_wrong)) {
       if (!cred->rfc_mech)
	   err = 1;
   } else {
       err = 1;
   }
   
   if (err) {
      k5_mutex_unlock(&cred->lock);
      if (claimant_cred_handle == GSS_C_NO_CREDENTIAL)
	 krb5_gss_release_cred(minor_status, (gss_cred_id_t *)&cred);
      *minor_status = 0;
      if (*context_handle == GSS_C_NO_CONTEXT)
	 krb5_free_context(context);
      return(GSS_S_BAD_MECH);
   }

   /* is this a new connection or not? */

   /*SUPPRESS 29*/
   if (*context_handle == GSS_C_NO_CONTEXT) {
      major_status = new_connection(minor_status, cred, context_handle,
				    target_name, mech_type, req_flags,
				    time_req, input_chan_bindings,
				    input_token, actual_mech_type,
				    output_token, ret_flags, time_rec,
				    context, default_mech);
      k5_mutex_unlock(&cred->lock);
      if (*context_handle == GSS_C_NO_CONTEXT) {
          save_error_info (*minor_status, context);
	  krb5_free_context(context);
      } else
	  ((krb5_gss_ctx_id_rec *) *context_handle)->k5_context = context;
   } else {
      /* mutual_auth doesn't care about the credentials */
      k5_mutex_unlock(&cred->lock);
      major_status = mutual_auth(minor_status, context_handle,
				 target_name, mech_type, req_flags,
				 time_req, input_chan_bindings,
				 input_token, actual_mech_type,
				 output_token, ret_flags, time_rec,
				 context);
      /* If context_handle is now NO_CONTEXT, mutual_auth called
	 delete_sec_context, which would've zapped the krb5 context
	 too.  */
   }

   if (claimant_cred_handle == GSS_C_NO_CREDENTIAL)
      krb5_gss_release_cred(&tmp_min_stat, (gss_cred_id_t *)&cred);

   return(major_status);
}

#ifndef _WIN32
k5_mutex_t kg_kdc_flag_mutex = K5_MUTEX_PARTIAL_INITIALIZER;
static int kdc_flag = 0;
#endif

krb5_error_code
krb5_gss_init_context (krb5_context *ctxp)
{
    krb5_error_code err;
#ifndef _WIN32
    int is_kdc;
#endif

    err = gssint_initialize_library();
    if (err)
	return err;
#ifndef _WIN32
    err = k5_mutex_lock(&kg_kdc_flag_mutex);
    if (err)
	return err;
    is_kdc = kdc_flag;
    k5_mutex_unlock(&kg_kdc_flag_mutex);

    if (is_kdc)
	return krb5int_init_context_kdc(ctxp);
#endif

    return krb5_init_context(ctxp);
}

#ifndef _WIN32
krb5_error_code
krb5_gss_use_kdc_context()
{
    krb5_error_code err;

    err = gssint_initialize_library();
    if (err)
	return err;
    err = k5_mutex_lock(&kg_kdc_flag_mutex);
    if (err)
	return err;
    kdc_flag = 1;
    k5_mutex_unlock(&kg_kdc_flag_mutex);
    return 0;
}
#endif

/* Solaris Kerberos specific routines start */

#define ROOT_UID 0
#define KRB5_DEFAULT_LIFE 60*60*10
#define CACHE_FILENAME_LEN 35

extern int
safechown(const char *src, uid_t uid, gid_t gid, int mode);

static krb5_boolean
principal_ignore_inst_compare(context, princ1, princ2)
    krb5_context context;
    krb5_const_principal princ1;
    krb5_const_principal princ2;
{
    krb5_int32 nelem;

    nelem = krb5_princ_size(context, princ1);
    if (nelem != krb5_princ_size(context, princ2))
	return FALSE;

    /*
     * Solaris Kerberos:
     * Don't bother to compare the realms as princ1 will always have a 
     * referral realm set.
     */

    /*
     * Solaris Kerberos
     * If princ1 is elem1/metachar@REALM, compare just elem1 (and REALM).
     */
    if (nelem == 2) {
        const krb5_data *p = krb5_princ_component(context, princ1, 1);
 
	if (p->length == 1) {
	    const char *s = p->data;

	    if (s[0] == '*') {
		const krb5_data *p1 = krb5_princ_component(context, princ1, 0);
		const krb5_data *p2 = krb5_princ_component(context, princ2, 0);

		if (p1->length != p2->length ||
		        memcmp(p1->data, p2->data, p1->length))
		    return FALSE;
 
		return TRUE;
	    }
	}
    }
    
    return FALSE;
}

/*
 * Solaris Kerberos
 * This is a dup of krb5_ktfile_get_entry (sigh) but is necessary to
 * to get a custom princ compare above (principal_ignore_inst_compare)
 * and thus avoid mucking w/important krb5 internal
 * api (krb5_principal_compare)
 */
#include "../krb5/keytab/file/ktfile.h"

static krb5_error_code KRB5_CALLCONV
ktfile_get_entry(context, id, principal, kvno, enctype, entry)
   krb5_context context;
   krb5_keytab id;
   krb5_const_principal principal;
   krb5_kvno kvno;
   krb5_enctype enctype;
   krb5_keytab_entry * entry;
{
    krb5_keytab_entry cur_entry, new_entry;
    krb5_error_code kerror = 0;
    int found_wrong_kvno = 0;
    krb5_boolean similar;
    int kvno_offset = 0;

    KRB5_LOG0(KRB5_INFO, "ktfile_get_entry() start\n");

    /* Open the keyfile for reading */
    if ((kerror = krb5_ktfileint_openr(context, id))){
	KRB5_LOG(KRB5_ERR, "ktfile_get_entry() end, ktfileint_openr() "
		"kerror= %d\n", kerror);
	return(kerror);
    }

    /*
     * For efficiency and simplicity, we'll use a while true that
     * is exited with a break statement.
     */
    cur_entry.principal = 0;
    cur_entry.vno = 0;
    cur_entry.key.contents = 0;
    /*CONSTCOND*/
    while (TRUE) {
	if ((kerror = krb5_ktfileint_read_entry(context, id, &new_entry)))
	    break;

	/*
	 * by the time this loop exits, it must either free cur_entry,
	 * and copy new_entry there, or free new_entry.  Otherwise, it
	 * leaks.
	 */

	/*
	 * if the principal isn't the one requested, free new_entry
	 * and continue to the next.
	 */

	if (!principal_ignore_inst_compare(context, principal,
					new_entry.principal)) {
		krb5_kt_free_entry(context, &new_entry);
	    continue;
	}

	/*
	 * if the enctype is not ignored and doesn't match, free new_entry
	 * and continue to the next
	 */

	if (enctype != IGNORE_ENCTYPE) {
	    if ((kerror = krb5_c_enctype_compare(context, enctype,
						 new_entry.key.enctype,
						 &similar))) {
		krb5_kt_free_entry(context, &new_entry);
		break;
	    }

	    if (!similar) {
		krb5_kt_free_entry(context, &new_entry);
		continue;
	    }
	    /*
	     * Coerce the enctype of the output keyblock in case we
	     * got an inexact match on the enctype.
	     */
	    new_entry.key.enctype = enctype;
	}

	if (kvno == IGNORE_VNO) {
	    /*
	     * if this is the first match, or if the new vno is
	     * bigger, free the current and keep the new.  Otherwise,
	     * free the new.
	     */
	    /*
	     * A 1.2.x keytab contains only the low 8 bits of the key
	     * version number.  Since it can be much bigger, and thus
	     * the 8-bit value can wrap, we need some heuristics to
	     * figure out the "highest" numbered key if some numbers
	     * close to 255 and some near 0 are used.
	     *
	     * The heuristic here:

	     * If we have any keys with versions over 240, then assume
	     * that all version numbers 0-127 refer to 256+N instead.
	     * Not perfect, but maybe good enough?
	     */

#define M(VNO) (((VNO) - kvno_offset + 256) % 256)

	    if (new_entry.vno > 240)
		kvno_offset = 128;
	    if (! cur_entry.principal ||
		M(new_entry.vno) > M(cur_entry.vno)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
	    } else {
		krb5_kt_free_entry(context, &new_entry);
	    }
	} else {
	    /*
	     * if this kvno matches, free the current (will there ever
	     * be one?), keep the new, and break out.  Otherwise, remember
	     * that we were here so we can return the right error, and
	     * free the new
	     */
	    /*
	     * Yuck.  The krb5-1.2.x keytab format only stores one byte
	     * for the kvno, so we're toast if the kvno requested is
	     * higher than that.  Short-term workaround: only compare
	     * the low 8 bits.
	     */

	    if (new_entry.vno == (kvno & 0xff)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
		break;
	    } else {
		found_wrong_kvno++;
		krb5_kt_free_entry(context, &new_entry);
	    }
	}
    }

    if (kerror == KRB5_KT_END) {
	 if (cur_entry.principal)
	      kerror = 0;
	 else if (found_wrong_kvno)
	      kerror = KRB5_KT_KVNONOTFOUND;
	 else
	      kerror = KRB5_KT_NOTFOUND;
    }
    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
	krb5_kt_free_entry(context, &cur_entry);
	KRB5_LOG(KRB5_ERR,"ktfile_get_entry() end, kerror="
		    "%d\n", kerror);
	return kerror;
    }
    if ((kerror = krb5_ktfileint_close(context, id)) != 0) {
	krb5_kt_free_entry(context, &cur_entry);
	KRB5_LOG(KRB5_ERR,"ktfile_get_entry() end, ktfileint_close() "
	       "kerror= %d\n", kerror);
	return kerror;
    }
    *entry = cur_entry;

    /* Let us close the file before we leave */
    (void) krb5_ktfileint_close(context, id);

    KRB5_LOG0(KRB5_INFO, "ktfile_get_entry() end");

    return 0;
}


/*
 * Solaris Kerberos
 * Given a princ of name/instance@LOCALREALM, search the keytab 
 * for a match of name and LOCALREALM and if found, return instance
 * as a string.
 *
 * Caller must free returned string.
 */
static krb5_error_code
get_instance_keytab(
	krb5_context context,
	const char *sname,
	krb5_keytab keytab,
	char  **instance)  /* out */
{
	krb5_error_code ret=0;
	krb5_keytab_entry kt_ent; 
	krb5_int32 nelem, free_kt_ent=0; 
	register const krb5_data *p;
	char *realm=NULL, *s=NULL;
	krb5_principal client=NULL, princ=NULL;
	size_t realm_size = strlen(KRB5_REFERRAL_REALM) + 1;

	if (!keytab)
		return EINVAL;

	realm = malloc(realm_size);
	if (realm == NULL)
		return (ENOMEM);
	strlcpy(realm, KRB5_REFERRAL_REALM, realm_size);

	ret = krb5_build_principal(context, &client, strlen(realm),
				      realm, sname, "*",
				      (char *)0);
	if (ret)
		goto out;

	ret = ktfile_get_entry(context, keytab, client,
				0, /* don't have vno available */ 
				0, &kt_ent);
	if (ret)
		goto out;

	free_kt_ent++;  /* kt_ent is not a ptr */

	princ = kt_ent.principal;
	nelem = krb5_princ_size(context, princ); 
	if (nelem != 2) {
		ret = KRB5_PRINC_NOMATCH;
		goto out;
	}

	p = krb5_princ_component(context, princ, 1); 
	s = calloc(p->length + sizeof(char), sizeof(char));
	if (!s) {
		ret = ENOMEM;
		goto out;
	}

	(void) memcpy(s, p->data, p->length);


out:
	free(realm);
	if (client)
		krb5_free_principal(context, client);
	if (free_kt_ent)
		(void) krb5_kt_free_entry(context, &kt_ent);
		
	if (ret == 0)
		*instance = s;
	return ret;
}

static OM_uint32
load_root_cred_using_keytab(
	OM_uint32 *minor_status,
	krb5_context context,
	const char *sname,
	int use_nodename)
{
	krb5_creds my_creds;
	krb5_principal me;
	krb5_principal server;
	krb5_error_code code;
	krb5_ccache ccache = NULL;
	krb5_keytab keytab = NULL;
	krb5_timestamp now;
	krb5_deltat lifetime = KRB5_DEFAULT_LIFE;   /* -l option */
	krb5_get_init_creds_opt opt;
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		KRB5_TGS_NAME
	};
	char *svcname = NULL;

	KRB5_LOG0(KRB5_INFO, "load_root_cred_using_keytab() start \n");

	if (!sname)
		return (GSS_S_FAILURE);

	memset((char *)&my_creds, 0, sizeof(my_creds));

	if (code = krb5_kt_default(context, &keytab)) {
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	if (!use_nodename) {
		char *instance = NULL;

		code = get_instance_keytab(context, sname, keytab, &instance);
		if (code == 0) {
			code = krb5_sname_to_principal(context,
						    instance, sname,
						    KRB5_NT_UNKNOWN, &me);
			free(instance);
		}
	} else {
		code = krb5_sname_to_principal(context, NULL, sname,
					    KRB5_NT_SRV_HST, &me);
	}

	/* Solaris Kerberos */
	if (code == 0 && krb5_is_referral_realm(&me->realm)) {
		krb5_data realm;
		code = krb5_kt_find_realm(context, keytab, me, &realm);
		if (code == 0) {
			krb5_free_data_contents(context, &me->realm);
			me->realm.length = realm.length;
			me->realm.data = realm.data;
		} else {
			/* Try to set a useful error message */
			char *princ = NULL;
			krb5_error_code ret;
			ret = krb5_unparse_name(context, me, &princ);

			krb5_set_error_message(context, code,
					    dgettext(TEXT_DOMAIN,
						    "Failed to find realm for %s in keytab"),
					    ret == 0 ? princ : "unknown");
			if (princ)
				krb5_free_unparsed_name(context, princ);
		}
	}

	if (code) {
		(void) krb5_kt_close(context, keytab);
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	my_creds.client = me;

	if((code = krb5_build_principal_ext(context, &server,
					krb5_princ_realm(context, me)->length,
					krb5_princ_realm(context, me)->data,
					tgtname.length, tgtname.data,
					krb5_princ_realm(context, me)->length,
					krb5_princ_realm(context, me)->data,
					0))) {
		*minor_status = code;
		krb5_free_cred_contents(context, &my_creds);
		(void) krb5_kt_close(context, keytab);

		return (GSS_S_FAILURE);
	}

	my_creds.server = server;
	my_creds.times.starttime = 0;     /* start timer
					   * when request
					   * gets to KDC
					   */
	if ((code = krb5_timeofday(context, &now))) {
		*minor_status = code;
		krb5_free_cred_contents(context, &my_creds);
		(void) krb5_kt_close(context, keytab);

		return (GSS_S_FAILURE);
	}
	my_creds.times.endtime = now + lifetime;
	my_creds.times.renew_till = 0;

	memset(&opt, 0, sizeof (opt));
	krb5_get_init_creds_opt_init(&opt);
	krb5_get_init_creds_opt_set_tkt_life(&opt, lifetime);

	code = krb5_unparse_name(context, server, &svcname);
	if (code != 0) {
		*minor_status = code;
		krb5_free_cred_contents(context, &my_creds);
		(void) krb5_kt_close(context, keytab);

		return (GSS_S_FAILURE);
	}
	/*
	 * Evidently (sigh), on success, krb5_get_init_creds_keytab
	 * changes the my_creds princ ptrs so we need to free those
	 * princs (me&server) as well as freeing all of my_creds contents.
	 */
	code = krb5_get_init_creds_keytab(context,
                                &my_creds, me, keytab,
                                0, svcname, &opt);

	(void) krb5_kt_close(context, keytab);

	if (svcname != NULL)
		free(svcname);
	if (code) {
		*minor_status = code;
		krb5_free_cred_contents(context, &my_creds);

		return (GSS_S_FAILURE);
	}

	krb5_free_principal(context, server);
	server = NULL;

	code = krb5_cc_resolve (context,
				krb5_cc_default_name(context),
				&ccache);
	if (code != 0) {
		*minor_status = code;
		krb5_free_cred_contents(context, &my_creds);
		krb5_free_principal(context, me);

		return (GSS_S_FAILURE);
	}
	code = krb5_cc_initialize (context, ccache, me);
	krb5_free_principal(context, me);
	me = NULL;
	if (code != 0) {
		*minor_status = code;
		krb5_free_cred_contents(context, &my_creds);
		(void) krb5_cc_close(context, ccache);

		return (GSS_S_FAILURE);
	}

	code = krb5_cc_store_cred(context, ccache,
				  &my_creds);
	krb5_free_cred_contents(context, &my_creds);
	(void) krb5_cc_close(context, ccache);

	if (code) {
		*minor_status = code;

		KRB5_LOG(KRB5_ERR, "load_root_cred_using_keytab() end, error "
			"code = %d\n", code);

		return (GSS_S_FAILURE);
	}
	
	KRB5_LOG0(KRB5_INFO, "load_root_cred_using_keytab() end \n");

	return (GSS_S_COMPLETE);
}

static OM_uint32
renew_ccache(OM_uint32 *minor_status, krb5_context context, uid_t uid)
{
	krb5_principal me;
	krb5_principal server;
	krb5_creds	creds;
	krb5_creds	tmpcreds;
	krb5_creds	*out_creds;
	krb5_error_code code;
	krb5_ccache ccache = NULL;
	static char ccache_name_buf[CACHE_FILENAME_LEN];
	int options = 0;
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		KRB5_TGS_NAME
	};
	gid_t gid = getgid();

	memset((char *)&creds, 0, sizeof(creds));
	memset((char *)&tmpcreds, 0, sizeof(creds));

	if ((code = krb5_cc_default(context, &ccache))) {
		*minor_status = code;
		(void) krb5_cc_close(context, ccache);
		return (GSS_S_FAILURE);
	}

	if ((code = krb5_cc_get_principal(context, ccache, &me)) != 0) {
		*minor_status = code;
		(void) krb5_cc_close(context, ccache);
		return (GSS_S_FAILURE);
	}

	creds.client = me;

	if((code = krb5_build_principal_ext(context, &server,
					krb5_princ_realm(context, me)->length,
					krb5_princ_realm(context, me)->data,
					tgtname.length, tgtname.data,
					krb5_princ_realm(context, me)->length,
					krb5_princ_realm(context, me)->data,
					0))) {
		krb5_free_principal(context, me);
		(void) krb5_cc_close(context, ccache);
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	creds.server = server;
	creds.ticket_flags = TKT_FLG_RENEWABLE;
	
	if ((krb5_cc_retrieve_cred(context, ccache, KRB5_TC_MATCH_FLAGS,
			&creds, &tmpcreds))) {
		(void) krb5_cc_close(context, ccache);
		return (KDC_ERR_BADOPTION);
	}
				
	creds.ticket_flags = 0;
        code = krb5_get_credentials_renew(context, options, ccache,
						&creds, &out_creds);
	krb5_free_cred_contents(context, &creds);
	krb5_free_cred_contents(context, &tmpcreds);

	if (code) {
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	krb5_free_creds(context, out_creds);
	snprintf(ccache_name_buf, CACHE_FILENAME_LEN, "/tmp/krb5cc_%d",
		uid, -1);
	code = safechown(ccache_name_buf, uid, gid, -1);

	if (code == -1) {
		(void) krb5_cc_destroy(context, ccache);
		*minor_status = code;
		return (GSS_S_FAILURE);
	}

	(void) krb5_cc_close(context, ccache);

	return (GSS_S_COMPLETE);

}

/*
 * Solaris Kerberos:
 * We enforce a minimum refresh time on the root cred. This avoids problems for
 * the higher level communication protocol for having valid creds and
 * setting up a valid context, only to have it expire before or while
 * it is being used. For non root users we don't care since we do not refresh
 * there creds, they get what they can get.
 */
#define MIN_REFRESH_TIME 300
#define MIN_RENEW_TIME 1500

/* get_default_cred() must be called with the krb5_mutex lock held */
static OM_uint32
get_default_cred(OM_uint32 *minor_status, void *ct, gss_cred_id_t *cred_handle)
{
	krb5_timestamp now;
	krb5_gss_cred_id_t cred;
	OM_uint32 major;
	OM_uint32 mntmp;
	/*
	 * Solaris Kerberos
	 * Use krb5_getuid() to select the mechanism to obtain the uid.
	 */
	uid_t uid = krb5_getuid();
	krb5_context context = (krb5_context)ct;

	KRB5_LOG0(KRB5_INFO, "get_default_cred() start\n");

	/* Get the default cred for user */
	if (((major = kg_get_defcred(minor_status, cred_handle)) != 0) &&
	    GSS_ERROR(major)) {

		/* If we're not root we're done */
   		if (uid != ROOT_UID)
	 		return (major);

		/*
		 * Try and get root's cred in the cache using keytab.
		 *
		 * First try "root" and then try "host" - this allows
		 * Secure NFS to use the host principal for mounting if
		 * there is no root principal.
		 *
		 * Then try "host/<anything>" to match any instance (needed
		 * for DHCP clients).
		 */
		major = load_root_cred_using_keytab(minor_status,
						    context, "root", 1);

		if (major != GSS_S_COMPLETE)
			major = load_root_cred_using_keytab(minor_status,
							    context, "host", 1);
		if (major != GSS_S_COMPLETE)
			major = load_root_cred_using_keytab(minor_status,
							    context, "host", 0);

		if (major != GSS_S_COMPLETE)
			return (major);

		/* We should have valid tgt now in the cache, so get it. */
		major = kg_get_defcred(minor_status, cred_handle);

		return (major);
      	}

	/* We've got a gss cred handle that is a kerberos cred handle. */
	cred = (krb5_gss_cred_id_t)*cred_handle;
	
	/* If we can't get the time, assume the worst. */
	if (krb5_timeofday(context, &now)) {
		(void) krb5_gss_release_cred(&mntmp, cred_handle);
		return (GSS_S_CREDENTIALS_EXPIRED);
	}

	/* If root's cred has expired re-get it */
	if (cred->tgt_expire < now + MIN_REFRESH_TIME && uid == ROOT_UID) {
		(void) krb5_gss_release_cred(&mntmp, cred_handle);

		major = load_root_cred_using_keytab(minor_status,
						    context, "root", 1);

		if (major != GSS_S_COMPLETE)
			major = load_root_cred_using_keytab(minor_status,
							    context, "host", 1);

		if (major != GSS_S_COMPLETE)
			major = load_root_cred_using_keytab(minor_status,
							    context, "host", 0);

		if (major != GSS_S_COMPLETE)
			return (major);

		major = kg_get_defcred(minor_status, cred_handle);
		if (major != GSS_S_COMPLETE)
			return (major);
		
	/* Any body else is SOL unless we can renew their credential cache */
	} else if ((cred->tgt_expire < now + MIN_RENEW_TIME) &&
			(cred->tgt_expire > now)) {
		(void) krb5_gss_release_cred(&mntmp, cred_handle);

		major = renew_ccache(minor_status, context, uid);
		if ((major != GSS_S_COMPLETE) &&
			(major != KDC_ERR_BADOPTION))
			return (major);

		major = kg_get_defcred(minor_status, cred_handle);
		if (major != GSS_S_COMPLETE)
			return (major);

	}

	/* Otherwise we got non expired creds */

	KRB5_LOG0(KRB5_INFO, "get_default_cred() end\n");

	return (GSS_S_COMPLETE);
}

/* Solaris Kerberos specific routines end */
