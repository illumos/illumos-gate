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
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "canohost.h"
#include "ssh2.h"
#include "ssh-gss.h"

extern char *xxx_host;

Gssctxt *xxx_gssctxt;

static void kexgss_verbose_cleanup(void *arg);

void
kexgss_client(Kex *kex)
{
	gss_buffer_desc gssbuf, send_tok, recv_tok, msg_tok;
	gss_buffer_t token_ptr;
	gss_OID mech = GSS_C_NULL_OID;
	Gssctxt *ctxt = NULL;
	OM_uint32 maj_status, min_status, smaj_status, smin_status;
	unsigned int klen, kout;
	DH *dh;
	BIGNUM *dh_server_pub = 0;
	BIGNUM *shared_secret = 0;
	Key *server_host_key = NULL;
	unsigned char *kbuf;
	unsigned char *hash;
	unsigned char *server_host_key_blob = NULL;
	char *msg, *lang;
	int type = 0;
	int first = 1;
	uint_t sbloblen = 0;
	uint_t strlen;

	/* Map the negotiated kex name to a mech OID */
	ssh_gssapi_oid_of_kexname(kex->name, &mech);
	if (mech == GSS_C_NULL_OID)
		fatal("Couldn't match the negotiated GSS key exchange");

	ssh_gssapi_build_ctx(&ctxt, 1, mech);

	/* This code should match that in ssh_dh1_client */

	/* Step 1 - e is dh->pub_key */
	dh = dh_new_group1();
	dh_gen_key(dh, kex->we_need * 8);

	/* This is f, we initialise it now to make life easier */
	dh_server_pub = BN_new();
	if (dh_server_pub == NULL) {
		fatal("dh_server_pub == NULL");
	}

	token_ptr = GSS_C_NO_BUFFER;

	recv_tok.value = NULL;
	recv_tok.length = 0;

	do {
		debug("Calling gss_init_sec_context");

		maj_status = ssh_gssapi_init_ctx(ctxt, xxx_host,
		    kex->options.gss_deleg_creds, token_ptr, &send_tok);

		if (GSS_ERROR(maj_status)) {
			ssh_gssapi_error(ctxt, "performing GSS-API protected "
			    "SSHv2 key exchange");
			(void) gss_release_buffer(&min_status, &send_tok);
			packet_disconnect("A GSS-API error occurred during "
			    "GSS-API protected SSHv2 key exchange\n");
		}

		/* If we've got an old receive buffer get rid of it */
		if (token_ptr != GSS_C_NO_BUFFER) {
			/* We allocated recv_tok */
			xfree(recv_tok.value);
			recv_tok.value = NULL;
			recv_tok.length = 0;
			token_ptr = GSS_C_NO_BUFFER;
		}

		if (maj_status == GSS_S_COMPLETE) {
			/* If mutual state flag is not true, kex fails */
			if (!(ctxt->flags & GSS_C_MUTUAL_FLAG)) {
				fatal("Mutual authentication failed");
			}
			/* If integ avail flag is not true kex fails */
			if (!(ctxt->flags & GSS_C_INTEG_FLAG)) {
				fatal("Integrity check failed");
			}
		}

		/*
		 * If we have data to send, then the last message that we
		 * received cannot have been a 'complete'.
		 */
		if (send_tok.length != 0) {
			if (first) {
				packet_start(SSH2_MSG_KEXGSS_INIT);
				packet_put_string(send_tok.value,
				    send_tok.length);
				packet_put_bignum2(dh->pub_key);
				first = 0;
			} else {
				packet_start(SSH2_MSG_KEXGSS_CONTINUE);
				packet_put_string(send_tok.value,
				    send_tok.length);
			}
			(void) gss_release_buffer(&min_status, &send_tok);
			packet_send();
			packet_write_wait();


			/*
			 * If we've sent them data, they'd better be polite and
			 * reply.
			 */

next_packet:
			/*
			 * We need to catch connection closing w/o error
			 * tokens or messages so we can tell the user
			 * _something_ more useful than "Connection
			 * closed by ..."
			 *
			 * We use a fatal cleanup function as that's
			 * all, really, that we can do for now.
			 */
			fatal_add_cleanup(kexgss_verbose_cleanup, NULL);
			type = packet_read();
			fatal_remove_cleanup(kexgss_verbose_cleanup, NULL);
			switch (type) {
			case SSH2_MSG_KEXGSS_HOSTKEY:
				debug("Received KEXGSS_HOSTKEY");
				server_host_key_blob =
				    packet_get_string(&sbloblen);
				server_host_key =
				    key_from_blob(server_host_key_blob,
				    sbloblen);
				goto next_packet; /* there MUSt be another */
				break;
			case SSH2_MSG_KEXGSS_CONTINUE:
				debug("Received GSSAPI_CONTINUE");
				if (maj_status == GSS_S_COMPLETE)
					packet_disconnect("Protocol error: "
					    "received GSS-API context token "
					    "though the context was already "
					    "established");
				recv_tok.value = packet_get_string(&strlen);
				recv_tok.length = strlen; /* u_int vs. size_t */
				break;
			case SSH2_MSG_KEXGSS_COMPLETE:
				debug("Received GSSAPI_COMPLETE");
				packet_get_bignum2(dh_server_pub);
				msg_tok.value = packet_get_string(&strlen);
				msg_tok.length = strlen; /* u_int vs. size_t */

				/* Is there a token included? */
				if (packet_get_char()) {
					recv_tok.value =
					    packet_get_string(&strlen);
					/* u_int/size_t */
					recv_tok.length = strlen;
				}
				if (recv_tok.length > 0 &&
				    maj_status == GSS_S_COMPLETE) {
					packet_disconnect("Protocol error: "
					    "received GSS-API context token "
					    "though the context was already "
					    "established");
				} else if (recv_tok.length == 0 &&
				    maj_status == GSS_S_CONTINUE_NEEDED) {
					/* No token included */
					packet_disconnect("Protocol error: "
					    "did not receive expected "
					    "GSS-API context token");
				}
				break;
			case SSH2_MSG_KEXGSS_ERROR:
				smaj_status = packet_get_int();
				smin_status = packet_get_int();
				msg = packet_get_string(NULL);
				lang = packet_get_string(NULL);
				xfree(lang);
				error("Server had a GSS-API error; the "
				    "connection will close (%d/%d):\n%s",
				    smaj_status, smin_status, msg);
				error("Use the GssKeyEx option to disable "
				    "GSS-API key exchange and try again.");
				packet_disconnect("The server had a GSS-API "
				    "error during GSS-API protected SSHv2 "
				    "key exchange\n");
				break;
			default:
				packet_disconnect("Protocol error: "
				    "didn't expect packet type %d", type);
			}
			if (recv_tok.value)
				token_ptr = &recv_tok;
		} else {
			/* No data, and not complete */
			if (maj_status != GSS_S_COMPLETE) {
				fatal("Not complete, and no token output");
			}
		}
	} while (maj_status == GSS_S_CONTINUE_NEEDED);

	/*
	 * We _must_ have received a COMPLETE message in reply from the
	 * server, which will have set dh_server_pub and msg_tok.
	 */
	if (type != SSH2_MSG_KEXGSS_COMPLETE)
		fatal("Expected SSH2_MSG_KEXGSS_COMPLETE never arrived");
	if (maj_status != GSS_S_COMPLETE)
		fatal("Internal error in GSS-API protected SSHv2 key exchange");

	/* Check f in range [1, p-1] */
	if (!dh_pub_is_valid(dh, dh_server_pub))
		packet_disconnect("bad server public DH value");

	/* compute K=f^x mod p */
	klen = DH_size(dh);
	kbuf = xmalloc(klen);
	kout = DH_compute_key(kbuf, dh_server_pub, dh);

	shared_secret = BN_new();
	BN_bin2bn(kbuf, kout, shared_secret);
	(void) memset(kbuf, 0, klen);
	xfree(kbuf);

	/* The GSS hash is identical to the DH one */
	hash = kex_dh_hash(
	    kex->client_version_string,
	    kex->server_version_string,
	    buffer_ptr(&kex->my), buffer_len(&kex->my),
	    buffer_ptr(&kex->peer), buffer_len(&kex->peer),
	    server_host_key_blob, sbloblen, /* server host key */
	    dh->pub_key,	/* e */
	    dh_server_pub,	/* f */
	    shared_secret);	/* K */

	gssbuf.value = hash;
	gssbuf.length = 20;

	/* Verify that H matches the token we just got. */
	if ((maj_status = gss_verify_mic(&min_status, ctxt->context, &gssbuf,
	    &msg_tok, NULL))) {
		packet_disconnect("Hash's MIC didn't verify");
	}

	if (server_host_key && kex->accept_host_key != NULL)
		(void) kex->accept_host_key(server_host_key);

	DH_free(dh);

	xxx_gssctxt = ctxt; /* for gss keyex w/ mic userauth */

	/* save session id */
	if (kex->session_id == NULL) {
		kex->session_id_len = 20;
		kex->session_id = xmalloc(kex->session_id_len);
		(void) memcpy(kex->session_id, hash, kex->session_id_len);
	}

	kex_derive_keys(kex, hash, shared_secret);
	BN_clear_free(shared_secret);
	kex_finish(kex);
}

/* ARGSUSED */
static
void
kexgss_verbose_cleanup(void *arg)
{
	error("The GSS-API protected key exchange has failed without "
	    "indication\nfrom the server, possibly due to misconfiguration "
	    "of the server.");
	error("Use the GssKeyEx option to disable GSS-API key exchange "
	    "and try again.");
}

#endif /* GSSAPI */
