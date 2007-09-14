/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2000, 2004  by the Massachusetts Institute of Technology.
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

#include <k5-int.h>
#include <auth_con.h>
#include <gssapiP_krb5.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <assert.h>

/* Solaris kerberos: XXX kludgy but there is no include file for the
 * krb5_fcc_ops extern declaration.
 */
extern krb5_cc_ops krb5_fcc_ops;

#ifdef CFX_EXERCISE
#define CFX_ACCEPTOR_SUBKEY (time(0) & 1)
#else
#define CFX_ACCEPTOR_SUBKEY 1
#endif

/*
 * Decode, decrypt and store the forwarded creds in the local ccache.
 * and populate the callers delegated credential handle if it
 * was provided.
 */
static krb5_error_code
rd_and_store_for_creds(context, auth_context, inbuf, out_cred)
    krb5_context context;
    krb5_auth_context auth_context; 
    krb5_data *inbuf;
    krb5_gss_cred_id_t *out_cred;
{
    krb5_creds ** creds;
    krb5_error_code retval;
    krb5_ccache template_ccache = NULL;
    krb5_ccache ccache = NULL;
    krb5_gss_cred_id_t cred = NULL;
    krb5_auth_context new_auth_ctx = NULL;
    krb5_int32 flags_org;

    KRB5_LOG0(KRB5_INFO, "rd_and_store_for_creds() start");

    if ((retval = krb5_auth_con_getflags(context, auth_context, &flags_org)))
	return retval;
    krb5_auth_con_setflags(context, auth_context, 0);

	/*
         * By the time krb5_rd_cred is called here (after krb5_rd_req has been
	 * called in krb5_gss_accept_sec_context), the "keyblock" field of
	 * auth_context contains a pointer to the session key, and the
	 * "recv_subkey" field might contain a session subkey.	Either of
	 * these (the "recv_subkey" if it isn't NULL, otherwise the
	 * "keyblock") might have been used to encrypt the encrypted part of
	 * the KRB_CRED message that contains the forwarded credentials.  (The
	 * Java Crypto and Security Implementation from the DSTC in Australia
	 * always uses the session key.	 But apparently it never negotiates a
	 * subkey, so this code works fine against a JCSI client.)  Up to the
	 * present, though, GSSAPI clients linked against the MIT code (which
	 * is almost all GSSAPI clients) don't encrypt the KRB_CRED message at
	 * all -- at this level.  So if the first call to krb5_rd_cred fails,
	 * we should call it a second time with another auth context freshly
	 * created by krb5_auth_con_init.  All of its keyblock fields will be
	 * NULL, so krb5_rd_cred will assume that the KRB_CRED message is
	 * unencrypted.	 (The MIT code doesn't actually send the KRB_CRED
	 * message in the clear -- the "authenticator" whose "checksum" ends up
	 * containing the KRB_CRED message does get encrypted.)
	 */
    if ((retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL))) {
	krb5_enctype enctype = ENCTYPE_NULL;
	/*
	 * If the client is using non-DES enctypes it really ought to
	 * send encrypted KRB-CREDs...
	 */
	if (auth_context->keyblock != NULL)
	    enctype = auth_context->keyblock->enctype;
	switch (enctype) {
	case ENCTYPE_DES_CBC_MD5:
	case ENCTYPE_DES_CBC_CRC:
	case ENCTYPE_DES3_CBC_SHA1:
	    break;
	default:
	    KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
		    "krb5_rd_cred() retval = %d\n", retval);
	    goto cleanup;
	    /* NOTREACHED */
	    break;
	}

	/* Try to krb5_rd_cred() likely unencrypted KRB-CRED */
	if ((retval = krb5_auth_con_init(context, &new_auth_ctx)))
		goto cleanup;
	krb5_auth_con_setflags(context, new_auth_ctx, 0);
	if ((retval = krb5_rd_cred(context, new_auth_ctx, inbuf,
		&creds, NULL))) {
		KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
			"krb5_rd_cred() retval = %d\n", retval);
		goto cleanup;
	}
    }

    /* Lots of kludging going on here... Some day the ccache interface
       will be rewritten though */

    retval = krb5_cc_resolve(context, "MEMORY:GSSAPI", &template_ccache);
    if (retval) {
	KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
		"krb5_cc_resolve() retval = %d\n", retval);
	goto cleanup;
    }

    ccache = template_ccache; /* krb5_cc_gen_new will replace so make a copy */

    retval = krb5_cc_gen_new(context, &ccache);
    if (retval) {
	KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
		"krb5_cc_gen_new() retval = %d\n", retval);
        goto cleanup;
    }

    retval = krb5_cc_initialize(context, ccache, creds[0]->client);
    if (retval != 0) {
	KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
		"krb5_cc_initialize() retval = %d\n", retval);
	goto cleanup;
    }

    retval = krb5_cc_store_cred(context, ccache, creds[0]);
    if (retval != 0){
	KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
		"krb5_cc_store_cred() retval = %d\n", retval);
	goto cleanup;
    }

    /* generate a delegated credential handle */
    if (out_cred) {
	/* allocate memory for a cred_t... */
	if (!(cred =
		(krb5_gss_cred_id_t) xmalloc(sizeof(krb5_gss_cred_id_rec)))) {
	    retval = ENOMEM; /* out of memory? */
	    *out_cred = NULL;
	    goto cleanup;
	}

	/* zero it out... */
	(void) memset(cred, 0, sizeof(krb5_gss_cred_id_rec));

 	retval = k5_mutex_init(&cred->lock);
	if (retval) {
	    xfree(cred);
	    cred = NULL;
	    goto cleanup;
	}

	/* copy the client principle into it... */
	if ((retval = krb5_copy_principal(context, creds[0]->client,
			&(cred->princ)))) {
	    KRB5_LOG(KRB5_ERR, "rd_and_store_for_creds() error "
		    "krb5_copy_principal() retval = %d\n", retval);
	    k5_mutex_destroy(&cred->lock);
	    retval = ENOMEM; /* out of memory? */
	    xfree(cred); /* clean up memory on failure */
	    *out_cred = cred = NULL;
	    goto cleanup;
	}

	cred->usage = GSS_C_INITIATE; /* we can't accept with this */
	/* cred->princ already set */
	cred->prerfc_mech = 1; /* this cred will work with all three mechs */
	cred->rfc_mech = 1;
	cred->keytab = NULL; /* no keytab associated with this... */
        /* The cred expires when the original cred was set to expire */
	cred->tgt_expire = creds[0]->times.endtime;
	cred->ccache = ccache; /* the ccache containing the credential */
	ccache = NULL; /* cred takes ownership so don't destroy */
    }

    /* If there were errors, there might have been a memory leak
       if (!cred)
       if ((retval = krb5_cc_close(context, ccache)))
       goto cleanup;
    */
cleanup:
    if (creds)
        krb5_free_tgt_creds(context, creds);

    if (ccache)
	(void)krb5_cc_destroy(context, ccache);

    /*
     * SUNW15resync
     * Added this cc_destroy for template_cache, w/out it causes memory
     * leak via "ssh -o gssapidelegatecredentials=yes ..."
     */
    if (template_ccache)
	(void)krb5_cc_destroy(context, template_ccache);

    if (out_cred)
	*out_cred = cred; /* return credential */

    if (new_auth_ctx)
	krb5_auth_con_free(context, new_auth_ctx);

    krb5_auth_con_setflags(context, auth_context, flags_org);

    KRB5_LOG(KRB5_INFO, "rd_and_store_for_creds() end retval %d", retval);
    return retval;
}

/*
 * SUNW15resync
 * Most of the logic here left "as is" because of lots of fixes MIT
 * does not have yet
 */
OM_uint32
krb5_gss_accept_sec_context(minor_status, context_handle,
			    verifier_cred_handle, input_token,
			    input_chan_bindings, src_name, mech_type,
			    output_token, ret_flags, time_rec,
			    delegated_cred_handle)
     OM_uint32 *minor_status;
     gss_ctx_id_t *context_handle;
     gss_cred_id_t verifier_cred_handle;
     gss_buffer_t input_token;
     gss_channel_bindings_t input_chan_bindings;
     gss_name_t *src_name;
     gss_OID *mech_type;
     gss_buffer_t output_token;
     OM_uint32 *ret_flags;
     OM_uint32 *time_rec;
     gss_cred_id_t *delegated_cred_handle;
{
   krb5_context context;
   unsigned char *ptr, *ptr2;
   char *sptr;
   long tmp;
   size_t md5len;
   int bigend;
   krb5_gss_cred_id_t cred = 0;
   krb5_data ap_rep, ap_req;
   krb5_ap_req *request = NULL;
   int i;
   krb5_error_code code;
   krb5_address addr, *paddr;
   krb5_authenticator *authdat = 0;
   krb5_checksum reqcksum;
   krb5_principal name = NULL;
   krb5_ui_4 gss_flags = 0;
   krb5_gss_ctx_id_rec *ctx = 0;
   krb5_timestamp now;
   gss_buffer_desc token;
   krb5_auth_context auth_context = NULL;
   krb5_ticket * ticket = NULL;
   int option_id;
   krb5_data option;
   const gss_OID_desc *mech_used = NULL;
   OM_uint32 major_status = GSS_S_FAILURE;
   krb5_error krb_error_data;
   krb5_data scratch;
   gss_cred_id_t cred_handle = NULL;
   krb5_gss_cred_id_t deleg_cred = NULL;
   OM_uint32 saved_ap_options = 0;
   krb5int_access kaccess;
   int cred_rcache = 0;

   KRB5_LOG0(KRB5_INFO,"krb5_gss_accept_sec_context() start");

   code = krb5int_accessor (&kaccess, KRB5INT_ACCESS_VERSION);
   if (code) {
       *minor_status = code;
       return(GSS_S_FAILURE);
   }

   code = krb5_gss_init_context(&context);
   if (code) {
       *minor_status = code;
       return GSS_S_FAILURE;
   }

   /* set up returns to be freeable */

   if (src_name)
      *src_name = (gss_name_t) NULL;
   output_token->length = 0;
   output_token->value = NULL;
   token.value = 0;
   reqcksum.contents = 0;
   ap_req.data = 0;
   ap_rep.data = 0;

   if (mech_type)
      *mech_type = GSS_C_NULL_OID;

   /* initialize the delegated cred handle to NO_CREDENTIAL for now */
   if (delegated_cred_handle)
      *delegated_cred_handle = GSS_C_NO_CREDENTIAL;

   /*
    * Context handle must be unspecified.  Actually, it must be
    * non-established, but currently, accept_sec_context never returns
    * a non-established context handle.
    */
   /*SUPPRESS 29*/
   if (*context_handle != GSS_C_NO_CONTEXT) {
      *minor_status = 0;

       /* Solaris kerberos: the original Solaris code returned GSS_S_NO_CONTEXT
	* for this error.  This conflicts somewhat with RFC2743 which states
	* GSS_S_NO_CONTEXT should be returned only for sucessor calls following
	* GSS_S_CONTINUE_NEEDED status returns.  Note the MIT code doesn't
	* return GSS_S_NO_CONTEXT at all.
	*/

      major_status = GSS_S_NO_CONTEXT;
      KRB5_LOG0(KRB5_ERR,"krb5_gss_accept_sec_context() "
	      "error GSS_S_NO_CONTEXT");
      goto cleanup;
   }

   /* verify the token's integrity, and leave the token in ap_req.
      figure out which mech oid was used, and save it */

   ptr = (unsigned char *) input_token->value;

   if (!(code = g_verify_token_header(gss_mech_krb5,
				      (uint32_t *)&(ap_req.length),
				      &ptr, KG_TOK_CTX_AP_REQ,
				      input_token->length, 1))) {
       mech_used = gss_mech_krb5;
   } else if ((code == G_WRONG_MECH) &&
	      !(code = g_verify_token_header(gss_mech_krb5_old,
				     (uint32_t *)&(ap_req.length),
				     &ptr, KG_TOK_CTX_AP_REQ,
				     input_token->length, 1))) {
       /*
	* Previous versions of this library used the old mech_id
	* and some broken behavior (wrong IV on checksum
	* encryption).  We support the old mech_id for
	* compatibility, and use it to decide when to use the
	* old behavior.
	*/
       mech_used = gss_mech_krb5_old;
   } else {
       major_status = GSS_S_DEFECTIVE_TOKEN;
       goto fail;
   }

   sptr = (char *) ptr;
   TREAD_STR(sptr, ap_req.data, ap_req.length);

   /*
    * Solaris Kerberos: 
    *  We need to decode the request now so that we can get the
    *  service principal in order to try and acquire a cred for it.
    *  below in the "handle default cred handle" code block.
    */
   if (!krb5_is_ap_req(&ap_req)) {
       code = KRB5KRB_AP_ERR_MSG_TYPE;
       goto fail;
   }
   /* decode the AP-REQ into request */
   if ((code = decode_krb5_ap_req(&ap_req, &request))) {
       if (code == KRB5_BADMSGTYPE)
           code = KRB5KRB_AP_ERR_BADVERSION;
       goto fail;
   }

   /* handle default cred handle */
   /* 
    * Solaris Kerberos:
    * If there is no princ associated with the cred then treat it the
    * the same as GSS_C_NO_CREDENTIAL. 
    */
   if (verifier_cred_handle == GSS_C_NO_CREDENTIAL ||
    ((krb5_gss_cred_id_t)verifier_cred_handle)->princ == NULL) {
       /* Note that we try to acquire a cred for the service principal
	* named in the AP-REQ. This allows us to implement option (ii)
	* of the recommended behaviour for GSS_Accept_sec_context() as
	* described in section 1.1.1.3 of RFC2743.

	* This is far more useful that option (i), for which we would
	* acquire a cred for GSS_C_NO_NAME.
	*/
       /* copy the princ from the ap-req or we'll lose it when we free
	  the ap-req */
       krb5_principal princ;
       if ((code = krb5_copy_principal(context, request->ticket->server,
				       &princ))) {
           KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	            "krb5_copy_principal() error code %d", code);
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
       /* intern the acceptor name */
       if (! kg_save_name((gss_name_t) princ)) {
	   code = G_VALIDATE_FAILED;
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
       major_status = krb5_gss_acquire_cred((OM_uint32*) &code,
					    (gss_name_t) princ,
					    GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
					    GSS_C_ACCEPT, &cred_handle,
					    NULL, NULL);

       if (major_status != GSS_S_COMPLETE){

	   /* Solaris kerberos: RFC2743 indicate this should be returned if we
	    * can't aquire a default cred.
	    */
	   KRB5_LOG(KRB5_ERR,"krb5_gss_accept_sec_context() "
		  "krb5_gss_acquire_cred() error"
		   "orig major_status = %d, now = GSS_S_NO_CRED\n",
		   major_status);

	   major_status = GSS_S_NO_CRED;
	   goto fail;
       }

   } else {
       cred_handle = verifier_cred_handle;
   }

   major_status = krb5_gss_validate_cred((OM_uint32*) &code,
						 cred_handle);

   if (GSS_ERROR(major_status)){

       /* Solaris kerberos: RFC2743 indicate GSS_S_NO_CRED should be returned if
	* the supplied cred isn't valid.
	*/

       KRB5_LOG(KRB5_ERR,"krb5_gss_accept_sec_context() "
	      "krb5_gss_validate_cred() error"
	       "orig major_status = %d, now = GSS_S_NO_CRED\n",
	       major_status);

       major_status = GSS_S_NO_CRED;
       goto fail;
   }

   cred = (krb5_gss_cred_id_t) cred_handle;

   /* make sure the supplied credentials are valid for accept */

   if ((cred->usage != GSS_C_ACCEPT) &&
       (cred->usage != GSS_C_BOTH)) {
       code = 0;
      KRB5_LOG0(KRB5_ERR,"krb5_gss_accept_sec_context() "
	      "error GSS_S_NO_CONTEXT");
       major_status = GSS_S_NO_CRED;
       goto fail;
   }

   /* construct the sender_addr */

   if ((input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) &&
       (input_chan_bindings->initiator_addrtype == GSS_C_AF_INET)) {
       /* XXX is this right? */
       addr.addrtype = ADDRTYPE_INET;
       addr.length = input_chan_bindings->initiator_address.length;
       addr.contents = input_chan_bindings->initiator_address.value;

       paddr = &addr;
   } else {
       paddr = NULL;
   }

   /* verify the AP_REQ message - setup the auth_context and rcache */

   if ((code = krb5_auth_con_init(context, &auth_context))) {
       major_status = GSS_S_FAILURE;
       KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "krb5_auth_con_init() error code %d", code);
       goto fail;
   }

   (void) krb5_auth_con_setflags(context, auth_context,
                          KRB5_AUTH_CONTEXT_DO_SEQUENCE);

   if (cred->rcache) {
       cred_rcache = 1;
       if ((code = krb5_auth_con_setrcache(context, auth_context, cred->rcache))) {
	    major_status = GSS_S_FAILURE;
	    KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
		    "krb5_auth_con_setrcache() error code %d", code);
	    goto fail;
       }
   }
   if ((code = krb5_auth_con_setaddrs(context, auth_context, NULL, paddr))) {
       major_status = GSS_S_FAILURE;
       KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "krb5_auth_con_setaddrs() error code %d", code);
       goto fail;
   }

   if ((code = krb5_rd_req_decoded(context, &auth_context, request,
			   cred->princ, cred->keytab, NULL, &ticket))) {
       KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "krb5_rd_req() error code %d", code);
       if (code == KRB5_KT_KVNONOTFOUND || code == KRB5_KT_NOTFOUND) {
           major_status = GSS_S_DEFECTIVE_CREDENTIAL;
	   code = KRB5KRB_AP_ERR_NOKEY;
       }
       else if (code == KRB5KRB_AP_WRONG_PRINC) {
           major_status = GSS_S_NO_CRED;
	   code = KRB5KRB_AP_ERR_NOT_US;
       }
       else if (code == KRB5KRB_AP_ERR_REPEAT)
           major_status = GSS_S_DUPLICATE_TOKEN;
       else
           major_status = GSS_S_FAILURE;
       goto fail;
   }

   krb5_auth_con_getauthenticator(context, auth_context, &authdat);

#if 0
   /* make sure the necessary parts of the authdat are present */

   if ((authdat->authenticator->subkey == NULL) ||
       (authdat->ticket->enc_part2 == NULL)) {
	   code = KG_NO_SUBKEY;
	   major_status = GSS_S_FAILURE;
	   goto fail;
   }
#endif

   {
       /* gss krb5 v1 */

       /* stash this now, for later. */
       if (code = krb5_c_checksum_length(context, CKSUMTYPE_RSA_MD5,
					 &md5len)) {
	   KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
		  "krb5_c_checksum_length() error code %d", code);
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       /* verify that the checksum is correct */

       /*
	 The checksum may be either exactly 24 bytes, in which case
	 no options are specified, or greater than 24 bytes, in which case
	 one or more options are specified. Currently, the only valid
	 option is KRB5_GSS_FOR_CREDS_OPTION ( = 1 ).
       */

       if ((authdat->checksum->checksum_type != CKSUMTYPE_KG_CB) ||
	   (authdat->checksum->length < 24)) {
	   code = 0;
	   major_status = GSS_S_BAD_BINDINGS;
	   goto fail;
       }

       /*
	 "Be liberal in what you accept, and
	 conservative in what you send"
	 -- rfc1123

	 This code will let this acceptor interoperate with an initiator
	 using little-endian or big-endian integer encoding.
       */

       ptr = (unsigned char *) authdat->checksum->contents;
       bigend = 0;

       TREAD_INT(ptr, tmp, bigend);

       if (tmp != md5len) {
	   ptr = (unsigned char *) authdat->checksum->contents;
	   bigend = 1;

	   TREAD_INT(ptr, tmp, bigend);

	   if (tmp != md5len) {
	       code = KG_BAD_LENGTH;
	       major_status = GSS_S_FAILURE;
	       goto fail;
	   }
       }

       /* at this point, bigend is set according to the initiator's
	  byte order */

	/*
          The following section of code attempts to implement the
	  optional channel binding facility as described in RFC2743.

	  Since this facility is optional channel binding may or may
	  not have been provided by either the client or the server.

	  If the server has specified input_chan_bindings equal to
	  GSS_C_NO_CHANNEL_BINDINGS then we skip the check.  If
	  the server does provide channel bindings then we compute
	  a checksum and compare against those provided by the
	  client.  If the check fails we test the clients checksum
	  to see whether the client specified GSS_C_NO_CHANNEL_BINDINGS.
	  If either test succeeds we continue without error.
	*/
       if ((code = kg_checksum_channel_bindings(context, input_chan_bindings,
						&reqcksum, bigend))) {
	   KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
		  "kg_checksum_channel_bindings() error code %d", code);
	   major_status = GSS_S_BAD_BINDINGS;
	   goto fail;
       }

	TREAD_STR(ptr, ptr2, reqcksum.length);
	if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
	   if (memcmp(ptr2, reqcksum.contents, reqcksum.length) != 0) {
		xfree(reqcksum.contents);
		reqcksum.contents = 0;
		if ((code = kg_checksum_channel_bindings(context,
                                                  GSS_C_NO_CHANNEL_BINDINGS,
                                                  &reqcksum, bigend))) {
                   major_status = GSS_S_BAD_BINDINGS;
                   goto fail;
		}
               if (memcmp(ptr2, reqcksum.contents, reqcksum.length) != 0) {
                   code = 0;
                   major_status = GSS_S_BAD_BINDINGS;
                   goto fail;
		}
           }
       }

       TREAD_INT(ptr, gss_flags, bigend);

       /* if the checksum length > 24, there are options to process */

       if (authdat->checksum->length > 24 &&
	   (gss_flags & GSS_C_DELEG_FLAG)) {
	   i = authdat->checksum->length - 24;

	   if (i >= 4) {
	       TREAD_INT16(ptr, option_id, bigend);

	       TREAD_INT16(ptr, option.length, bigend);

		i -= 4;
               if (i < option.length || option.length < 0) {
                   code = KG_BAD_LENGTH;
                   major_status = GSS_S_FAILURE;
                   goto fail;
		}

               /* have to use ptr2, since option.data is wrong type and
		  macro uses ptr as both lvalue and rvalue */

		TREAD_STR(ptr, ptr2, option.length);
		option.data = (char *) ptr2;

		i -= option.length;

		if (option_id != KRB5_GSS_FOR_CREDS_OPTION) {
                   major_status = GSS_S_FAILURE;
                   goto fail;
		}

                   /* store the delegated credential */

		   code = rd_and_store_for_creds(context, auth_context, &option,
			(delegated_cred_handle) ? &deleg_cred : NULL);
		   if (code) {
		       major_status = GSS_S_FAILURE;
		       goto fail;
                   }

	    } /* if i >= 4 */
		/* ignore any additional trailing data, for now */
       } /* if */
   } /* krb5 gssapi v1 */

   /* create the ctx struct and start filling it in */

   if ((ctx = (krb5_gss_ctx_id_rec *) xmalloc(sizeof(krb5_gss_ctx_id_rec)))
       == NULL) {
       code = ENOMEM;
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   memset(ctx, 0, sizeof(krb5_gss_ctx_id_rec));

   ctx->mech_used = (gss_OID) mech_used;
   ctx->auth_context = auth_context;
   ctx->initiate = 0;
   ctx->gss_flags = (GSS_C_TRANS_FLAG |
                     ((gss_flags) & (GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG |
                             GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
                             GSS_C_SEQUENCE_FLAG | GSS_C_DELEG_FLAG)));
   ctx->seed_init = 0;
   ctx->big_endian = bigend;
   ctx->cred_rcache = cred_rcache;

   /* Intern the ctx pointer so that delete_sec_context works */
   if (! kg_save_ctx_id((gss_ctx_id_t) ctx)) {
       xfree(ctx);
       ctx = 0;

       KRB5_LOG0(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "kg_save_ctx_id() error");
       code = G_VALIDATE_FAILED;
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_copy_principal(context, cred->princ, &ctx->here))) {
       KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "krb5_copy_principal() error code %d", code);
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_copy_principal(context, authdat->client, &ctx->there))) {
       KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "krb5_copy_principal() 2 error code %d", code);
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if ((code = krb5_auth_con_getrecvsubkey(context, auth_context,
					   &ctx->subkey))) {
       KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
	      "krb5_auth_con_getremotesubkey() error code %d", code);
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   /* use the session key if the subkey isn't present */

   if (ctx->subkey == NULL) {
       if ((code = krb5_auth_con_getkey(context, auth_context,
					&ctx->subkey))) {
	   KRB5_LOG(KRB5_ERR, "krb5_gss_accept_sec_context() "
		      "krb5_auth_con_getkey() error code %d", code);
           *minor_status = (OM_uint32) KRB5KDC_ERR_NULL_KEY;
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
   }

   if (ctx->subkey == NULL) {
       /* this isn't a very good error, but it's not clear to me this
	  can actually happen */
       major_status = GSS_S_FAILURE;
       code = KRB5KDC_ERR_NULL_KEY;
       goto fail;
   }

   KRB5_LOG(KRB5_ERR,"krb5_gss_accept_sec_context() "
	   "ctx->subkey->enctype=%d", ctx->subkey->enctype);

   ctx->proto = 0;
   switch(ctx->subkey->enctype) {
   case ENCTYPE_DES_CBC_MD5:
   case ENCTYPE_DES_CBC_CRC:
       ctx->subkey->enctype = ENCTYPE_DES_CBC_RAW;
       ctx->signalg = SGN_ALG_DES_MAC_MD5;
       ctx->cksum_size = 8;
       ctx->sealalg = SEAL_ALG_DES;

       /* fill in the encryption descriptors */

       if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       for (i=0; i<ctx->enc->length; i++)
	   /*SUPPRESS 113*/
	   ctx->enc->contents[i] ^= 0xf0;

       goto copy_subkey_to_seq;
       break;

   case ENCTYPE_DES3_CBC_SHA1:
       ctx->subkey->enctype = ENCTYPE_DES3_CBC_RAW;
       ctx->signalg = SGN_ALG_HMAC_SHA1_DES3_KD;
       ctx->cksum_size = 20;
       ctx->sealalg = SEAL_ALG_DES3KD;

       /* fill in the encryption descriptors */

   copy_subkey:
       if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->enc))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

   copy_subkey_to_seq:
       if ((code = krb5_copy_keyblock(context, ctx->subkey, &ctx->seq))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       break;
   case ENCTYPE_ARCFOUR_HMAC:
        ctx->signalg = SGN_ALG_HMAC_MD5 ;
        ctx->cksum_size = 8;
        ctx->sealalg = SEAL_ALG_MICROSOFT_RC4 ;
	goto copy_subkey;

   default:
	ctx->signalg = -1;
	ctx->sealalg = -1;
	ctx->proto = 1;
	code = krb5int_c_mandatory_cksumtype(context, ctx->subkey->enctype,
		&ctx->cksumtype);
	if (code)
           goto fail;
	code = krb5_c_checksum_length(context, ctx->cksumtype,
		(size_t *)&ctx->cksum_size);
	if (code)
           goto fail;
	ctx->have_acceptor_subkey = 0;
	goto copy_subkey;
   }

   KRB5_LOG1(KRB5_ERR, "accept_sec_context:  subkey enctype = %d proto = %d",
	ctx->subkey->enctype, ctx->proto);

   ctx->endtime = ticket->enc_part2->times.endtime;
   ctx->krb_flags = ticket->enc_part2->flags;

   krb5_free_ticket(context, ticket); /* Done with ticket */
   {
	krb5_ui_4 seq_temp;
	krb5_auth_con_getremoteseqnumber(context, auth_context,
		(krb5_int32 *)&seq_temp);
	ctx->seq_recv = seq_temp;
   }

   if ((code = krb5_timeofday(context, &now))) {
       major_status = GSS_S_FAILURE;
       goto fail;
   }

   if (ctx->endtime < now) {
       code = 0;
       major_status = GSS_S_CREDENTIALS_EXPIRED;
       goto fail;
   }

   g_order_init(&(ctx->seqstate), ctx->seq_recv,
		(ctx->gss_flags & GSS_C_REPLAY_FLAG) != 0,
		(ctx->gss_flags & GSS_C_SEQUENCE_FLAG) != 0, ctx->proto);

   /* at this point, the entire context structure is filled in,
      so it can be released.  */

   /* generate an AP_REP if necessary */

   if (ctx->gss_flags & GSS_C_MUTUAL_FLAG) {
       unsigned char * ptr3;
	krb5_ui_4 seq_temp;
	int cfx_generate_subkey;

	if (ctx->proto == 1)
	   cfx_generate_subkey = CFX_ACCEPTOR_SUBKEY;
	else
	   cfx_generate_subkey = 0;

	if (cfx_generate_subkey) {
	   krb5_int32 acflags;
	   code = krb5_auth_con_getflags(context, auth_context, &acflags);
	   if (code == 0) {
		acflags |= KRB5_AUTH_CONTEXT_USE_SUBKEY;
		code = krb5_auth_con_setflags(context, auth_context, acflags);
	   }
           if (code) {
               major_status = GSS_S_FAILURE;
		goto fail;
	   }
       }

       if ((code = krb5_mk_rep(context, auth_context, &ap_rep))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }

       krb5_auth_con_getlocalseqnumber(context, auth_context,
		(krb5_int32 *)&seq_temp);
       ctx->seq_send = seq_temp & 0xffffffffL;

	if (cfx_generate_subkey) {
	   /* Get the new acceptor subkey.  With the code above, there
		should always be one if we make it to this point.	 */
	   code = krb5_auth_con_getsendsubkey(context, auth_context,
		&ctx->acceptor_subkey);
	   if (code != 0) {
		major_status = GSS_S_FAILURE;
		goto fail;
	   }
           code = krb5int_c_mandatory_cksumtype(context,
		ctx->acceptor_subkey->enctype,
		&ctx->acceptor_subkey_cksumtype);
	   if (code) {
               major_status = GSS_S_FAILURE;
		goto fail;
	   }
           ctx->have_acceptor_subkey = 1;
	}

       /* the reply token hasn't been sent yet, but that's ok. */
       ctx->gss_flags |= GSS_C_PROT_READY_FLAG;
       ctx->established = 1;
       token.length = g_token_size(mech_used, ap_rep.length);

       if ((token.value = (unsigned char *) xmalloc(token.length))
	   == NULL) {
	   major_status = GSS_S_FAILURE;
	   code = ENOMEM;
	   goto fail;
       }
       ptr = token.value;
       g_make_token_header(mech_used, ap_rep.length,
			   &ptr, KG_TOK_CTX_AP_REP);

       TWRITE_STR(ptr, ap_rep.data, ap_rep.length);
   } else {
       token.length = 0;
       token.value = NULL;
       ctx->seq_send = ctx->seq_recv;
   }
   ctx->established = 1;

   /* set the return arguments */

   if (src_name) {
       if ((code = krb5_copy_principal(context, ctx->there, &name))) {
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
       /* intern the src_name */
       if (! kg_save_name((gss_name_t) name)) {
	   code = G_VALIDATE_FAILED;
	   major_status = GSS_S_FAILURE;
	   goto fail;
       }
   }

   if (mech_type)
      *mech_type = (gss_OID) mech_used;

   if (time_rec)
      *time_rec = ctx->endtime - now;

   if (ret_flags)
      *ret_flags = ctx->gss_flags;

   *context_handle = (gss_ctx_id_t) ctx;
   *output_token = token;

   if (src_name)
      *src_name = (gss_name_t) name;

   if (delegated_cred_handle && deleg_cred) {
	if (!kg_save_cred_id((gss_cred_id_t) deleg_cred)) {
	   KRB5_LOG0(KRB5_ERR, "krb5_gss_accept_sec_context() "
		      "kg_save_cred_id() error");
	   major_status = GSS_S_FAILURE;
	   code = (OM_uint32) G_VALIDATE_FAILED;
           goto fail;
	}

       *delegated_cred_handle = (gss_cred_id_t) deleg_cred;
   }

   /* finally! */

   *minor_status = 0;
   major_status = GSS_S_COMPLETE;

 fail:
   if (authdat)
       krb5_free_authenticator(context, authdat);
   /* The ctx structure has the handle of the auth_context */
   if (auth_context && !ctx) {
       if (cred_rcache)
	   (void)krb5_auth_con_setrcache(context, auth_context, NULL);

       krb5_auth_con_free(context, auth_context);
   }
   if (reqcksum.contents)
       xfree(reqcksum.contents);
   if (ap_rep.data)
       xfree(ap_rep.data);

   if (request != NULL) {
	saved_ap_options = request->ap_options;
	krb5_free_ap_req(context, request);
	request = NULL;
   }

   if (!GSS_ERROR(major_status) && major_status != GSS_S_CONTINUE_NEEDED) {
	if (!verifier_cred_handle && cred_handle) {
		krb5_gss_release_cred(minor_status, &cred_handle);
	}

	if (ctx)
	    ctx->k5_context = context;

        return(major_status);
   }

   /* from here on is the real "fail" code */

   if (ctx)
	(void) krb5_gss_delete_sec_context(minor_status,
					  (gss_ctx_id_t *) &ctx, NULL);
   if (deleg_cred) { /* free memory associated with the deleg credential */
       if (deleg_cred->ccache)
	   (void)krb5_cc_close(context, deleg_cred->ccache);
       if (deleg_cred->princ)
	   krb5_free_principal(context, deleg_cred->princ);
       xfree(deleg_cred);
   }
   if (token.value)
       xfree(token.value);
   if (name) {
       (void) kg_delete_name((gss_name_t) name);
       krb5_free_principal(context, name);
   }

   *minor_status = code;

   if (saved_ap_options & AP_OPTS_MUTUAL_REQUIRED)
	gss_flags |= GSS_C_MUTUAL_FLAG;

   if (cred && ((gss_flags & GSS_C_MUTUAL_FLAG) ||
	(major_status == GSS_S_CONTINUE_NEEDED))) {
       unsigned int tmsglen;
       int toktype;

       /*
	* The client is expecting a response, so we can send an
	* error token back
	*/
       memset(&krb_error_data, 0, sizeof(krb_error_data));

       code  -= ERROR_TABLE_BASE_krb5;
       if (code < 0 || code > 128)
	   code = 60 /* KRB_ERR_GENERIC */;

       krb_error_data.error = code;
       (void) krb5_us_timeofday(context, &krb_error_data.stime,
				&krb_error_data.susec);
       krb_error_data.server = cred->princ;
	
       code = krb5_mk_error(context, &krb_error_data, &scratch);
       if (code)
           goto cleanup;

       tmsglen = scratch.length;
       toktype = KG_TOK_CTX_ERROR;

       token.length = g_token_size(mech_used, tmsglen);
       token.value = (unsigned char *) xmalloc(token.length);
       if (!token.value)
	  goto cleanup;

       ptr = token.value;
       g_make_token_header(mech_used, tmsglen, &ptr, toktype);

       TWRITE_STR(ptr, scratch.data, scratch.length);
       xfree(scratch.data);

       *output_token = token;
   }

cleanup:
   if (!verifier_cred_handle && cred_handle) {
      krb5_gss_release_cred(minor_status, &cred_handle);
   }

   krb5_free_context(context);

   KRB5_LOG(KRB5_ERR,"krb5_gss_accept_sec_context() end, "
	      "major_status = %d", major_status);
   return (major_status);
}
