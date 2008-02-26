/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "includes.h"

#ifdef GSSAPI

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "compat.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "ssh-gss.h"
#include "auth.h"

Gssctxt *xxx_gssctxt;
extern Authctxt *x_authctxt;

static void kex_gss_send_error(Gssctxt *ctxt);

void
kexgss_server(Kex *kex)
{
	OM_uint32 maj_status, min_status;
	gss_buffer_desc gssbuf, send_tok, recv_tok, msg_tok;
	Gssctxt *ctxt = NULL;
	unsigned int klen, kout;
	unsigned int sbloblen = 0;
	unsigned char *kbuf, *hash;
	unsigned char *server_host_key_blob = NULL;
	DH *dh;
	Key *server_host_key = NULL;
	BIGNUM *shared_secret = NULL;
	BIGNUM *dh_client_pub = NULL;
	int type = 0;
	uint_t slen;
	gss_OID oid;

	/*
	 * Load host key to advertise in a SSH_MSG_KEXGSS_HOSTKEY packet
	 * -- unlike KEX_DH/KEX_GEX no host key, no problem since it's
	 * the GSS-API that provides for server host authentication.
	 */
	if (kex->load_host_key != NULL &&
	    !(datafellows & SSH_BUG_GSSKEX_HOSTKEY))
		server_host_key = kex->load_host_key(kex->hostkey_type);
	if (server_host_key != NULL)
		key_to_blob(server_host_key, &server_host_key_blob, &sbloblen);


	/* Initialise GSSAPI */

	ssh_gssapi_oid_of_kexname(kex->name, &oid);
	if (oid == GSS_C_NULL_OID) {
		fatal("Couldn't match the negotiated GSS key exchange");
	}

	ssh_gssapi_build_ctx(&xxx_gssctxt, 0, oid);

	ctxt = xxx_gssctxt;

	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");
		type = packet_read();
		switch (type) {
		case SSH2_MSG_KEXGSS_INIT:
			if (dh_client_pub != NULL)
				fatal("Received KEXGSS_INIT after "
				    "initialising");
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen; /* int vs. size_t */

			dh_client_pub = BN_new();

			if (dh_client_pub == NULL)
				fatal("dh_client_pub == NULL");
			packet_get_bignum2(dh_client_pub);

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			if (sbloblen) {
				packet_start(SSH2_MSG_KEXGSS_HOSTKEY);
				packet_put_string(server_host_key_blob,
				    sbloblen);
				packet_send();
				packet_write_wait();
			}
			break;
		case SSH2_MSG_KEXGSS_CONTINUE:
			recv_tok.value = packet_get_string(&slen);
			recv_tok.length = slen; /* int vs. size_t */
			break;
		default:
			packet_disconnect("Protocol error: didn't expect "
			    "packet type %d", type);
		}

		maj_status = ssh_gssapi_accept_ctx(ctxt, &recv_tok, &send_tok);

		xfree(recv_tok.value); /* We allocated this, not gss */

		if (dh_client_pub == NULL)
			fatal("No client public key");

		if (maj_status == GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
			packet_write_wait();
			(void) gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status == GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		kex_gss_send_error(ctxt);
		if (send_tok.length > 0) {
			packet_start(SSH2_MSG_KEXGSS_CONTINUE);
			packet_put_string(send_tok.value, send_tok.length);
			packet_send();
			packet_write_wait();
			(void) gss_release_buffer(&min_status, &send_tok);
		}
		fatal("accept_ctx died");
	}

	debug("gss_complete");
	if (!(ctxt->flags & GSS_C_MUTUAL_FLAG))
		fatal("Mutual authentication flag wasn't set");

	if (!(ctxt->flags & GSS_C_INTEG_FLAG))
		fatal("Integrity flag wasn't set");

	dh = dh_new_group1();
	dh_gen_key(dh, kex->we_need * 8);

	if (!dh_pub_is_valid(dh, dh_client_pub))
		packet_disconnect("bad client public DH value");

	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	kout = DH_compute_key(kbuf, dh_client_pub, dh);

	shared_secret = BN_new();
	BN_bin2bn(kbuf, kout, shared_secret);
	(void) memset(kbuf, 0, klen);
	xfree(kbuf);

	/* The GSSAPI hash is identical to the Diffie Helman one */
	hash = kex_dh_hash(
	    kex->client_version_string,
	    kex->server_version_string,
	    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
	    buffer_ptr(&kex->my), buffer_len(&kex->my),
	    server_host_key_blob, sbloblen,
	    dh_client_pub,
	    dh->pub_key,
	    shared_secret);

	BN_free(dh_client_pub);

	if (kex->session_id == NULL) {
		kex->session_id_len = 20;
		kex->session_id = xmalloc(kex->session_id_len);
		(void) memcpy(kex->session_id, hash, kex->session_id_len);
	} else if (x_authctxt != NULL && x_authctxt->success) {
		ssh_gssapi_storecreds(ctxt, x_authctxt);
	}

	/* Should fix kex_dh_hash to output hash length */
	gssbuf.length = 20;	/* yes, it's always 20 (SHA-1) */
	gssbuf.value = hash;	/* and it's static constant storage */

	if (GSS_ERROR(ssh_gssapi_get_mic(ctxt, &gssbuf, &msg_tok))) {
		kex_gss_send_error(ctxt);
		fatal("Couldn't get MIC");
	}

	packet_start(SSH2_MSG_KEXGSS_COMPLETE);
	packet_put_bignum2(dh->pub_key);
	packet_put_string((char *)msg_tok.value, msg_tok.length);
	(void) gss_release_buffer(&min_status, &msg_tok);

	if (send_tok.length != 0) {
		packet_put_char(1); /* true */
		packet_put_string((char *)send_tok.value, send_tok.length);
		(void) gss_release_buffer(&min_status, &send_tok);
	} else {
		packet_put_char(0); /* false */
	}
	packet_send();
	packet_write_wait();

	DH_free(dh);

	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
	kex_finish(kex);
}

static void
kex_gss_send_error(Gssctxt *ctxt) {
	char *errstr;
	OM_uint32 maj, min;

	errstr = ssh_gssapi_last_error(ctxt, &maj, &min);
	if (errstr) {
		packet_start(SSH2_MSG_KEXGSS_ERROR);
		packet_put_int(maj);
		packet_put_int(min);
		packet_put_cstring(errstr);
		packet_put_cstring("");
		packet_send();
		packet_write_wait();
		/* XXX - We should probably log the error locally here */
		xfree(errstr);
	}
}
#endif /* GSSAPI */
