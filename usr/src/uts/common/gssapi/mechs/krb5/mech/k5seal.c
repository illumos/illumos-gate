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

#include "gssapiP_krb5.h"
#include <k5-int.h>

static krb5_error_code
make_seal_token_v1 (krb5_context context,
		    krb5_keyblock *enc,
		    krb5_keyblock *seq,
		    gssint_uint64 *seqnum,
		    int direction,
		    gss_buffer_t text,
		    gss_buffer_t token,
		    int signalg,
		    size_t cksum_size,
		    int sealalg,
		    int encrypt,
		    int toktype,
		    int bigend,
		    gss_OID oid)
{
    krb5_error_code code;
    size_t sumlen;
    char *data_ptr;
    krb5_data plaind;
    krb5_checksum md5cksum;
    krb5_checksum cksum;
				/* msglen contains the message length
				 * we are signing/encrypting.  tmsglen
				 * contains the length of the message
				 * we plan to write out to the token.
				 * tlen is the length of the token
				 * including header. */
    unsigned  conflen=0, tmsglen, tlen, msglen;
    unsigned char *t, *ptr;
    unsigned char *plain;
    unsigned char pad;
    krb5_keyusage sign_usage = KG_USAGE_SIGN;
    OM_uint32 seqnum32;

    /* Solaris Kerberos:  check for recognized signalg and sealalg */
    KRB5_LOG0(KRB5_INFO, "make_seal_token_v1() start\n");
#ifdef _KERNEL
	/*
         * Because the ARCFOUR code bypasses the standard
	 * crypto interfaces, we must make sure the kernel
	 * crypto framework mechanism types are properly
	 * initialized here.
	 */
	context->kef_cipher_mt = get_cipher_mech_type(context, seq);
	context->kef_hash_mt = get_hash_mech_type(context, seq);
	if ((code = init_key_kef(context->kef_cipher_mt, seq))) {
		return (code);
	}
        if ((code = init_key_kef(context->kef_cipher_mt, enc))) {
		return (code);
	}
#endif /* _KERNEL */

    /* create the token buffer */
    /* Do we need confounder? */
    if (encrypt || (!bigend && (toktype == KG_TOK_SEAL_MSG)))
      conflen = kg_confounder_size(context, enc);
    else conflen = 0;

    if (toktype == KG_TOK_SEAL_MSG) {
      switch (sealalg) {
      case SEAL_ALG_MICROSOFT_RC4:
	msglen = conflen + text->length+1;
	pad = 1;
	break;
      default:
	/* XXX knows that des block size is 8 */
	msglen = (conflen+text->length+8)&(~7);
	      pad = 8-(text->length%8);
      }
      tmsglen = msglen;
    } else {
      tmsglen = 0;
      msglen = text->length;
      pad = 0;
    }
    tlen = g_token_size((gss_OID) oid, 14+cksum_size+tmsglen);

    if ((t = (unsigned char *) xmalloc(tlen)) == NULL)
      return(ENOMEM);

    /*** fill in the token */

    ptr = t;
    g_make_token_header((gss_OID) oid, 14+cksum_size+tmsglen, &ptr, toktype);

    /* 0..1 SIGN_ALG */
    ptr[0] = (unsigned char) (signalg & 0xff);
    ptr[1] = (unsigned char) ((signalg >> 8) & 0xff);

    /* 2..3 SEAL_ALG or Filler */
    if ((toktype == KG_TOK_SEAL_MSG) && encrypt) {
	ptr[2] = (unsigned char) (sealalg & 0xff);
	ptr[3] = (unsigned char) ((sealalg >> 8) & 0xff);
    } else {
      /* No seal */
      ptr[2] = 0xff;
      ptr[3] = 0xff;
    }

    /* 4..5 Filler */
    ptr[4] = 0xff;
    ptr[5] = 0xff;

    /* pad the plaintext, encrypt if needed, and stick it in the token */

    /* initialize the the cksum */
    switch (signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case SGN_ALG_MD2_5:
      md5cksum.checksum_type = CKSUMTYPE_RSA_MD5;
      break;
    case SGN_ALG_HMAC_SHA1_DES3_KD:
      md5cksum.checksum_type = CKSUMTYPE_HMAC_SHA1_DES3;
      break;
    case SGN_ALG_HMAC_MD5:
      md5cksum.checksum_type = CKSUMTYPE_HMAC_MD5_ARCFOUR;
      if (toktype != KG_TOK_SEAL_MSG)
	sign_usage = 15;
      break;
    default:
	KRB5_LOG(KRB5_ERR, "make_seal_token_v1() end, error2 signalg=%d\n",
		signalg);
#ifndef	_KERNEL
      abort ();
#else
	return (GSS_S_DEFECTIVE_TOKEN);
#endif /* _KERNEL */
    }

    code = krb5_c_checksum_length(context, md5cksum.checksum_type, &sumlen);
    if (code) {
	KRB5_LOG(KRB5_ERR, "make_seal_token_v1() end, krb5_c_checksum_length() "
		"error code=%d\n", code);
      return(code);
    }
    md5cksum.length = sumlen;


    if ((plain = (unsigned char *) xmalloc(msglen ? msglen : 1)) == NULL) {
      xfree_wrap(t, tlen);
      return(ENOMEM);
    }

    if (conflen) {
      if ((code = kg_make_confounder(context, enc, plain))) {
	xfree_wrap(plain, msglen ? msglen : 1);
	xfree_wrap(t, tlen);
	KRB5_LOG(KRB5_ERR, "make_seal_token_v1() end, "
		"kg_make_confounder() error code=%d\n", code);
	return(code);
      }
    }

    (void) memcpy(plain+conflen, text->value, text->length);
    if (pad) (void) memset(plain+conflen+text->length, pad, pad);

    /* compute the checksum */

    /* 8 = head of token body as specified by mech spec */
    if (! (data_ptr = (char *) xmalloc(8 +
		(bigend ? text->length : msglen)))) {
	xfree_wrap(plain, msglen ? msglen : 1);
	xfree_wrap(t, tlen);
	return(ENOMEM);
    }
    (void) memcpy(data_ptr, ptr-2, 8);
    if (bigend)
      (void) memcpy(data_ptr+8, text->value, text->length);
    else
      (void) memcpy(data_ptr+8, plain, msglen);
    plaind.length = 8 + (bigend ? text->length : msglen);
    plaind.data = data_ptr;
    code = krb5_c_make_checksum(context, md5cksum.checksum_type, seq,
				sign_usage, &plaind, &md5cksum);
    xfree_wrap(data_ptr,8 + (bigend ? text->length : msglen));

    if (code) {
      KRB5_LOG(KRB5_ERR, "make_seal_token_v1() end, "
      	"krb5_c_make_checksum() error code=%d\n", code);
      xfree_wrap(plain, msglen ? msglen : 1);
      xfree_wrap(t, tlen);
      return(code);
    }
    switch(signalg) {
    case SGN_ALG_DES_MAC_MD5:
    case 3:

      if ((code = kg_encrypt(context, seq, KG_USAGE_SEAL,
			     (g_OID_equal(oid, gss_mech_krb5_old) ?
			      seq->contents : NULL),
			     md5cksum.contents, md5cksum.contents, 16))) {
	xfree_wrap(md5cksum.contents, md5cksum.length);
	xfree_wrap(t, tlen);

	KRB5_LOG(KRB5_ERR, "make_seal_token_v1() end, kg_encrypt() "
	        "error code=%d\n", code);
	return code;
      }

      cksum.length = cksum_size;
      cksum.contents = md5cksum.contents + 16 - cksum.length;

     (void) memcpy(ptr+14, cksum.contents, cksum.length);
      break;

    case SGN_ALG_HMAC_SHA1_DES3_KD:
      /*
       * Using key derivation, the call to krb5_c_make_checksum
       * already dealt with encrypting.
       */
      if (md5cksum.length != cksum_size)
	{
		KRB5_LOG1(KRB5_ERR, "make_seal_token_v1() end, error "
				   "md5cksum.length %u != "
				   "cksum_size %u\n",
				   (unsigned int)md5cksum.length,
				   (unsigned int) cksum_size);
#ifndef	_KERNEL
	abort ();
#else
	return (GSS_S_DEFECTIVE_TOKEN);
#endif
	}
      (void) memcpy(ptr+14, md5cksum.contents, md5cksum.length);
      break;
    case SGN_ALG_HMAC_MD5:
	KRB5_LOG(KRB5_INFO, "make_seal_token_v1() cksum_size = %u",
		(unsigned int)cksum_size);
	(void) memcpy(ptr+14, md5cksum.contents, cksum_size);
	break;
    }

    xfree_wrap(md5cksum.contents, md5cksum.length);

    /* create the seq_num */
    seqnum32 = (OM_uint32)(*seqnum & 0xFFFFFFFF);
    if ((code = kg_make_seq_num(context, seq, direction?0:0xff, seqnum32,
				ptr+14, ptr+6))) {
	xfree_wrap(t, tlen);

	KRB5_LOG(KRB5_ERR, "make_seal_token_v1() end, kg_make_seq_num() "
		    "error code=%d\n", code);
	return(code);
    }

    if (encrypt) {
      switch(sealalg) {
      case SEAL_ALG_MICROSOFT_RC4:
	{
	  unsigned char bigend_seqnum[4];
	  krb5_keyblock *enc_key;
	  int i;
	  bigend_seqnum[0] = (*seqnum>>24) & 0xff;
	  bigend_seqnum[1] = (*seqnum>>16) & 0xff;
	  bigend_seqnum[2] = (*seqnum>>8) & 0xff;
	  bigend_seqnum[3] = *seqnum & 0xff;
	  code = krb5_copy_keyblock (context, enc, &enc_key);
	  if (code)
	    {
	      xfree_wrap(plain, msglen ? msglen : 1);
	      xfree_wrap(t, tlen);
	      return(code);
	    }
	  for (i = 0; i <= 15; i++)
	    ((char *) enc_key->contents)[i] ^=0xf0;
	  code = kg_arcfour_docrypt (context, enc_key, 0,
				     bigend_seqnum, 4,
				     plain, tmsglen,
				     ptr+14+cksum_size);
	  krb5_free_keyblock (context, enc_key);
	  if (code)
	    {
	      xfree_wrap(plain, msglen ? msglen : 1);
	      xfree_wrap(t, tlen);
	      return(code);
	    }
	}
	break;
      default:
	    if ((code = kg_encrypt(context, enc, KG_USAGE_SEAL, NULL,
				   (krb5_pointer) plain,
				   (krb5_pointer) (ptr+cksum_size+14),
				   tmsglen))) {
	      xfree_wrap(plain, msglen ? msglen : 1);
	      xfree_wrap(t, tlen);
	      return(code);
	    }
      }
    }else {
      if (tmsglen)
	(void) memcpy(ptr+14+cksum_size, plain, tmsglen);
    }
    xfree_wrap(plain, msglen ? msglen : 1);


    /* that's it.  return the token */

    (*seqnum)++;
    *seqnum &= (ulong_t)0xffffffffU;

    token->length = tlen;
    token->value = (void *) t;

    KRB5_LOG0(KRB5_INFO, "make_seal_token_v1() end\n");
    return(0);
}

/* if signonly is true, ignore conf_req, conf_state,
   and do not encode the ENC_TYPE, MSG_LENGTH, or MSG_TEXT fields */

OM_uint32
kg_seal(minor_status, context_handle, conf_req_flag, qop_req,
	input_message_buffer, conf_state, output_message_buffer, toktype)
    OM_uint32 *minor_status;
    gss_ctx_id_t context_handle;
    int conf_req_flag;
    int qop_req;
    gss_buffer_t input_message_buffer;
    int *conf_state;
    gss_buffer_t output_message_buffer;
    int toktype;
{
    krb5_gss_ctx_id_rec *ctx;
    krb5_error_code code;
    krb5_timestamp now;
    krb5_context context;

    KRB5_LOG0(KRB5_INFO, "kg_seal() start");

    output_message_buffer->length = 0;
    output_message_buffer->value = NULL;

    /* Only default qop or matching established cryptosystem is allowed.

       There are NO EXTENSIONS to this set for AES and friends!  The
       new spec says "just use 0".  The old spec plus extensions would
       actually allow for certain non-zero values.  Fix this to handle
       them later.  */
    if (qop_req != 0) {
	*minor_status = (OM_uint32) G_UNKNOWN_QOP;
	KRB5_LOG0(KRB5_ERR, "kg_seal() end, error G_UNKNOWN_QOP\n");
	return (GSS_S_BAD_QOP);
    }

    /* validate the context handle */
    if (! kg_validate_ctx_id(context_handle)) {
	*minor_status = (OM_uint32) G_VALIDATE_FAILED;
	KRB5_LOG0(KRB5_ERR, "kg_seal() kg_validate_ctx_id() end, "
		"error GSS_S_NO_CONTEXT\n");
	return (GSS_S_NO_CONTEXT);
    }

    ctx = (krb5_gss_ctx_id_rec *) context_handle;

    if (ctx->subkey == NULL && !ctx->established) {
	*minor_status = KG_CTX_INCOMPLETE;
	return(GSS_S_NO_CONTEXT);
    }

    context = ctx->k5_context;
    if ((code = krb5_timeofday(context, &now))) {
	*minor_status = code;
        save_error_info(*minor_status, context);
	KRB5_LOG(KRB5_ERR, "kg_seal() end, krb5_timeofday() error code=%d\n", code);
	return (GSS_S_FAILURE);
    }

    switch (ctx->proto)
    {
    case 0:
	code = make_seal_token_v1(context, ctx->enc, ctx->seq,
				  &ctx->seq_send, ctx->initiate,
				  input_message_buffer, output_message_buffer,
				  ctx->signalg, ctx->cksum_size, ctx->sealalg,
				  conf_req_flag, toktype, ctx->big_endian,
				  ctx->mech_used);
	break;
    case 1:
	code = gss_krb5int_make_seal_token_v3(context, ctx,
					      input_message_buffer,
					      output_message_buffer,
					      conf_req_flag, toktype);
	break;
    default:
	code = G_UNKNOWN_QOP;	/* XXX */
	break;
    }

    if (code) {
	*minor_status = code;
        save_error_info(*minor_status, context);
	KRB5_LOG(KRB5_ERR, "kg_seal() end, make_seal_token_v1() "
		"error code=%d\n", code);
	return (GSS_S_FAILURE);
    }

    if (conf_state)
	*conf_state = conf_req_flag;

    *minor_status = 0;
   if (ctx->endtime < now) {
	(void) gss_release_buffer(minor_status, output_message_buffer);
	KRB5_LOG(KRB5_ERR, "kg_seal() end, error GSS_S_CONTEXT_EXPIRED "
		"ctx->endtime = %d\n", ctx->endtime);
	return (GSS_S_CONTEXT_EXPIRED);
   }

   KRB5_LOG0(KRB5_INFO, "kg_seal() end\n");
   return (GSS_S_COMPLETE);
}
