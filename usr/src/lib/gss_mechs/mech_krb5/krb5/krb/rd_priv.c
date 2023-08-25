/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * lib/krb5/krb/rd_priv.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 *
 * krb5_rd_priv()
 */

#include "k5-int.h"
#include "cleanup.h"
#include "auth_con.h"


/*

Parses a KRB_PRIV message from inbuf, placing the confidential user
data in *outbuf.

key specifies the key to be used for decryption of the message.

remote_addr and local_addr specify the full
addresses (host and port) of the sender and receiver.

outbuf points to allocated storage which the caller should
free when finished.

i_vector is used as an initialization vector for the
encryption, and if non-NULL its contents are replaced with the last
block of the encrypted data upon exit.

Returns system errors, integrity errors.

*/

static krb5_error_code
krb5_rd_priv_basic(krb5_context context, const krb5_data *inbuf, const krb5_keyblock *keyblock, const krb5_address *local_addr, const krb5_address *remote_addr, krb5_pointer i_vector, krb5_replay_data *replaydata, krb5_data *outbuf)
{
    krb5_error_code 	  retval;
    krb5_priv 		* privmsg;
    krb5_data 		  scratch;
    krb5_priv_enc_part  * privmsg_enc_part;
    size_t		  blocksize;
    krb5_data		  ivdata;

    if (!krb5_is_krb_priv(inbuf))
	return KRB5KRB_AP_ERR_MSG_TYPE;

    /* decode private message */
    if ((retval = decode_krb5_priv(inbuf, &privmsg)))
	return retval;

    if (i_vector) {
	if ((retval = krb5_c_block_size(context, keyblock->enctype,
					&blocksize)))
	    goto cleanup_privmsg;

	ivdata.length = blocksize;
	ivdata.data = i_vector;
    }

    scratch.length = privmsg->enc_part.ciphertext.length;
    if (!(scratch.data = malloc(scratch.length))) {
	retval = ENOMEM;
	goto cleanup_privmsg;
    }

    if ((retval = krb5_c_decrypt(context, keyblock,
				 KRB5_KEYUSAGE_KRB_PRIV_ENCPART,
				 i_vector?&ivdata:0,
				 &privmsg->enc_part, &scratch)))
	goto cleanup_scratch;

    /*  now decode the decrypted stuff */
    if ((retval = decode_krb5_enc_priv_part(&scratch, &privmsg_enc_part)))
        goto cleanup_scratch;

    if (!krb5_address_compare(context,remote_addr,privmsg_enc_part->s_address)){
	retval = KRB5KRB_AP_ERR_BADADDR;
	goto cleanup_data;
    }

    if (privmsg_enc_part->r_address) {
	if (local_addr) {
	    if (!krb5_address_compare(context, local_addr,
				      privmsg_enc_part->r_address)) {
		retval = KRB5KRB_AP_ERR_BADADDR;
		goto cleanup_data;
	    }
	} else {
	    krb5_address **our_addrs;

	    if ((retval = krb5_os_localaddr(context, &our_addrs))) {
		goto cleanup_data;
	    }
	    if (!krb5_address_search(context, privmsg_enc_part->r_address,
				     our_addrs)) {
		krb5_free_addresses(context, our_addrs);
		retval =  KRB5KRB_AP_ERR_BADADDR;
		goto cleanup_data;
	    }
	    krb5_free_addresses(context, our_addrs);
	}
    }

    replaydata->timestamp = privmsg_enc_part->timestamp;
    replaydata->usec = privmsg_enc_part->usec;
    replaydata->seq = privmsg_enc_part->seq_number;

    /* everything is ok - return data to the user */
    *outbuf = privmsg_enc_part->user_data;
    retval = 0;

cleanup_data:;
    if (retval == 0)
	privmsg_enc_part->user_data.data = 0;
    krb5_free_priv_enc_part(context, privmsg_enc_part);

cleanup_scratch:;
    /* Solaris Kerberos */
    (void) memset(scratch.data, 0, scratch.length);
    krb5_xfree(scratch.data);

cleanup_privmsg:;
    krb5_xfree(privmsg->enc_part.ciphertext.data);
    krb5_xfree(privmsg);

    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_rd_priv(krb5_context context, krb5_auth_context auth_context, const krb5_data *inbuf, krb5_data *outbuf, krb5_replay_data *outdata)
{
    krb5_error_code 	  retval;
    krb5_keyblock       * keyblock;
    krb5_replay_data	  replaydata;

    /* Get keyblock */
    if ((keyblock = auth_context->recv_subkey) == NULL)
	keyblock = auth_context->keyblock;

    if (((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
      (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) &&
      (outdata == NULL))
	/* Need a better error */
	return KRB5_RC_REQUIRED;

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) &&
      (auth_context->rcache == NULL))
	return KRB5_RC_REQUIRED;

{
    krb5_address * premote_fulladdr = NULL;
    krb5_address * plocal_fulladdr = NULL;
    krb5_address remote_fulladdr;
    krb5_address local_fulladdr;
    CLEANUP_INIT(2);

    if (auth_context->local_addr) {
    	if (auth_context->local_port) {
            if (!(retval = krb5_make_fulladdr(context, auth_context->local_addr,
                                 	      auth_context->local_port,
					      &local_fulladdr))){
                CLEANUP_PUSH(local_fulladdr.contents, free);
	        plocal_fulladdr = &local_fulladdr;
            } else {
	        return retval;
            }
	} else {
            plocal_fulladdr = auth_context->local_addr;
        }
    }

    if (auth_context->remote_addr) {
    	if (auth_context->remote_port) {
            if (!(retval = krb5_make_fulladdr(context,auth_context->remote_addr,
                                 	      auth_context->remote_port,
					      &remote_fulladdr))){
                CLEANUP_PUSH(remote_fulladdr.contents, free);
	        premote_fulladdr = &remote_fulladdr;
            } else {
                CLEANUP_DONE();
	        return retval;
            }
	} else {
            premote_fulladdr = auth_context->remote_addr;
        }
    }

    if ((retval = krb5_rd_priv_basic(context, inbuf, keyblock,
				     plocal_fulladdr,
				     premote_fulladdr,
				     auth_context->i_vector,
				     &replaydata, outbuf))) {
	CLEANUP_DONE();
	return retval;
    }

    CLEANUP_DONE();
}

    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_TIME) {
	krb5_donot_replay replay;

	if ((retval = krb5int_check_clockskew(context, replaydata.timestamp)))
	    goto error;

	if ((retval = krb5_gen_replay_name(context, auth_context->remote_addr,
					   "_priv", &replay.client)))
	    goto error;

	replay.server = "";		/* XXX */
	replay.cusec = replaydata.usec;
	replay.ctime = replaydata.timestamp;
	if ((retval = krb5_rc_store(context, auth_context->rcache, &replay))) {
	    krb5_xfree(replay.client);
	    goto error;
	}
	krb5_xfree(replay.client);
    }

    if (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
	if (!krb5int_auth_con_chkseqnum(context, auth_context,
					replaydata.seq)) {
	    retval =  KRB5KRB_AP_ERR_BADORDER;
	    goto error;
	}
	auth_context->remote_seq_number++;
    }

    if ((auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_TIME) ||
      (auth_context->auth_context_flags & KRB5_AUTH_CONTEXT_RET_SEQUENCE)) {
	outdata->timestamp = replaydata.timestamp;
	outdata->usec = replaydata.usec;
	outdata->seq = replaydata.seq;
    }

    /* everything is ok - return data to the user */
    return 0;

error:;
    krb5_xfree(outbuf->data);
    return retval;

}

