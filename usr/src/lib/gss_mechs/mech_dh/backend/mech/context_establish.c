/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 *	context_establish.c
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include "dh_gssapi.h"

/*
 * The following 2 routines convert a gss_channel_binding to a DH
 * channel_binding and vis versa.  We can no longer assume a simple
 * cast because a GSS buffer_t uses a size_t for the length field wich
 * is 64 bits in a 64 bit process. The xdr encoding always assumes the
 * length to be 32 bits :<.
 */

static dh_channel_binding_t
GSS2DH_channel_binding(dh_channel_binding_t dh_binding,
		    gss_channel_bindings_t gss_binding)
{
	if (gss_binding == GSS_C_NO_CHANNEL_BINDINGS)
		return (NULL);

	dh_binding->initiator_addrtype = gss_binding->initiator_addrtype;
	dh_binding->initiator_address.dh_buffer_desc_len =
		(uint32_t)gss_binding->initiator_address.length;
	if (gss_binding->initiator_address.length !=
		dh_binding->initiator_address.dh_buffer_desc_len)
		return (NULL);
	dh_binding->initiator_address.dh_buffer_desc_val =
		gss_binding->initiator_address.value;
	dh_binding->acceptor_addrtype = gss_binding->acceptor_addrtype;
	dh_binding->acceptor_address.dh_buffer_desc_len =
		(uint32_t)gss_binding->acceptor_address.length;
	dh_binding->acceptor_address.dh_buffer_desc_val =
		gss_binding->acceptor_address.value;
	dh_binding->application_data.dh_buffer_desc_len =
		(uint32_t)gss_binding->application_data.length;
	dh_binding->application_data.dh_buffer_desc_val =
		gss_binding->application_data.value;

	return (dh_binding);
}

static gss_channel_bindings_t
DH2GSS_channel_binding(gss_channel_bindings_t gss_binding,
		    dh_channel_binding_t dh_binding)
{
	if (dh_binding == NULL)
		return (GSS_C_NO_CHANNEL_BINDINGS);

	gss_binding->initiator_addrtype = dh_binding->initiator_addrtype;
	gss_binding->initiator_address.length =
		dh_binding->initiator_address.dh_buffer_desc_len;
	gss_binding->initiator_address.value =
		dh_binding->initiator_address.dh_buffer_desc_val;
	gss_binding->acceptor_addrtype = dh_binding->acceptor_addrtype;
	gss_binding->acceptor_address.length =
		dh_binding->acceptor_address.dh_buffer_desc_len;
	gss_binding->acceptor_address.value =
		dh_binding->acceptor_address.dh_buffer_desc_val;
	gss_binding->application_data.length =
		dh_binding->application_data.dh_buffer_desc_len;
	gss_binding->application_data.value =
		dh_binding->application_data.dh_buffer_desc_val;

	return (gss_binding);
}

/*
 * Routine to compare that two gss_buffers are the same.
 */
static bool_t
gss_buffer_cmp(gss_buffer_t b1, gss_buffer_t b2)
{
	if (b1->length != b2->length)
		return (FALSE);
	if (b1->length == 0)
		return (TRUE);
	if (b1->value == b2->value)
		return (TRUE);
	if (b1->value == 0 || b2->value == 0)
		return (FALSE);

	return (memcmp(b1->value, b2->value, b1->length) == 0);
}

/*
 * Compare if two channel bindings are the same. If the local binding is
 * NULL then we always return TRUE. This indicates that the local host
 * does not care about any bindings.
 */

static bool_t
gss_chanbind_cmp(gss_channel_bindings_t local, gss_channel_bindings_t remote)
{
	if (local == NULL)
		return (TRUE); /* local doesn't care so we won't either */

	if (remote == NULL)
		return (FALSE);

	if (local->initiator_addrtype != remote->initiator_addrtype)
		return (FALSE);

	if (local->initiator_addrtype != GSS_C_AF_NULLADDR)
		if (gss_buffer_cmp(&local->initiator_address,
				    &remote->initiator_address) == FALSE)
			return (FALSE);

	if (local->acceptor_addrtype != remote->acceptor_addrtype)
		return (FALSE);

	if (local->acceptor_addrtype != GSS_C_AF_NULLADDR)
		if (gss_buffer_cmp(&local->acceptor_address,
				    &remote->acceptor_address) == FALSE)
			return (FALSE);

	return (gss_buffer_cmp(&local->application_data,
				&remote->application_data));
}

/*
 * Generate an accept token for a context and channel binding puting the
 * generated token output.
 */

static
OM_uint32
gen_accept_token(dh_gss_context_t ctx, /* Diffie-Hellman context */
		gss_channel_bindings_t channel, /* channel bindings */
		gss_buffer_t output /* The accept token */)
{
	dh_token_desc token;
	/* Grap a pointer to the context_t part of the token */
	dh_cntx_t accept = &token.ver.dh_version_u.
				body.dh_token_body_desc_u.accept_context.cntx;
	dh_key_set keys;
	dh_channel_binding_desc dh_binding;

	/* Set the version number from the context. */
	token.ver.verno = ctx->proto_version;
	/* Set the token type to be an ACCEPT token. */
	token.ver.dh_version_u.body.type = DH_ACCEPT_CNTX;
	/* Set our self as the remote for the other end. */
	accept->remote = ctx->local;
	/* The remote side to us is the local side at the other end. */
	accept->local = ctx->remote;
	/* Our context flags */
	accept->flags = ctx->flags;
	/* When we will expire */
	accept->expire = ctx->expire;
	/* Our channel bindings */
	accept->channel = GSS2DH_channel_binding(&dh_binding, channel);
	/* Package the context session keys into a key_set */
	keys.dh_key_set_len = ctx->no_keys;
	keys.dh_key_set_val = ctx->keys;

	/* Build the token */
	return (__make_token(output, NULL, &token, &keys));
}

/*
 * Check if a credential is valid for the requested usage. Note that
 * Diffie-Hellman only supports credentials based on the callers net
 * name. netname will point to the users rpc netname. It is up to the
 * caller to free the netname.
 */

static OM_uint32
validate_cred(dh_context_t cntx, /* Diffie-Hellman mechanism context */
	    OM_uint32 *minor,	 /* Mechanism status */
	    dh_cred_id_t cred, /* Diffie-Hellman credential */
	    gss_cred_usage_t usage, /* Cred usage */
	    dh_principal *netname /* Cred owner */)
{
	/* Set minor status */
	*minor = DH_SUCCESS;
	*netname = NULL;

	/*
	 * See if the users creditial is available, i.e.,
	 * the user is "key logged" in.
	 */
	if (!cntx->keyopts->key_secretkey_is_set()) {
		*minor = DH_NO_SECRET;
		return (GSS_S_NO_CRED);
	}


	/*
	 * Get the netname.
	 */

	if ((*netname = cntx->keyopts->get_principal()) == NULL) {
		*minor = DH_NO_PRINCIPAL;
		return (GSS_S_NO_CRED);
	}

	/*
	 * Check if the supplied cred is valid for the requested usage.
	 * The default cred never expires and has a usage of GSS_C_BOTH.
	 */

	if ((gss_cred_id_t)cred != GSS_C_NO_CREDENTIAL) {
		if ((cred->usage != usage &&
		    cred->usage != GSS_C_BOTH) ||
		    strcmp(*netname, cred->principal) != 0) {
			free(*netname);
			return (GSS_S_NO_CRED);
		}

		/* See if the cred is still valid */
		if (cred->expire != GSS_C_INDEFINITE &&
		    time(0) > cred->expire) {
			free(*netname);
			return (GSS_S_CREDENTIALS_EXPIRED);
		}
	}
	return (GSS_S_COMPLETE);
}


/*
 * establish_session_keys: This routine decrypts the session keys supplied
 * and uses those keys to verifiy the signature over the input token
 * match the signature in the token.
 */
static OM_uint32
establish_session_keys(dh_context_t dhctx, const char *remote,
		    dh_key_set_t keys, dh_signature_t sig, dh_token_t token)
{
	OM_uint32 stat;
	int i, j;
	des_block *saved_keys;
	char *saved_sig;

	/*
	 * The following variable is used by the keyopts key_decryptsessions
	 * entry point. If this variable is non zero and the underling
	 * mechanism uses a cache of public keys, then get the public key
	 * for the remote out of that cache. When key_decrptsessions return
	 * this variable will be set to non zero if the key did come
	 * out of the cache, otherwise it will be set to zero.
	 */
	int key_was_from_cache = 1;

	/* Save the keyset so if we fail we can try again */
	if ((saved_keys = New(des_block, keys->dh_key_set_len)) == NULL)
		return (DH_NOMEM_FAILURE);

	for (i = 0; i < keys->dh_key_set_len; i++)
		saved_keys[i] = keys->dh_key_set_val[i];

	/* Save the unencrypted signature as well for retry attempt */
	if ((saved_sig = New(char, sig->dh_signature_len)) == NULL) {
		Free(saved_keys);
		return (DH_NOMEM_FAILURE);
	}
	memcpy(saved_sig, sig->dh_signature_val, sig->dh_signature_len);

	/*
	 * We will try to decrypt the session keys up to two times.
	 * The first time will let the underlying mechanism use a
	 * public key cache, if the set of session keys fail to
	 * validate the signature that is reported in the deserialized
	 * token, and those session keys were decrypted by a key
	 * derived from a public key cache, then we will try again but
	 * this time will advise the underlying mechanism not to use
	 * its cache.
	 */

	for (i = 0; key_was_from_cache && i < 2; i++) {
		/*
		 * Decrypt the session keys using the mechanism specific
		 * routine and if this is the second time, don't use
		 * the cache.
		 */
		if (i == 1)
			key_was_from_cache = 0;
		if (dhctx->keyopts->key_decryptsessions(remote,
							keys->dh_key_set_val,
							keys->dh_key_set_len,
							&key_was_from_cache)) {
			Free(saved_keys);
			Free(saved_sig);
			return (DH_SESSION_CIPHER_FAILURE);
		}

#ifdef DH_DEBUG
		fprintf(stderr, "Received session keys %s the cache:\n",
			key_was_form_cache ? "using" : "not using");
		for (i = 0; i < keys->dh_key_set_len; i++)
			fprintf(stderr, "%08.8x%08.8x ",
				keys->dh_key_set_val[i].key.high,
				keys->dh_key_set_val[i].key.low);
		fprintf(stderr, "\n");
#endif

		/*
		 * Now verify that the extracted signature from the
		 * deserialized token is the same as our calculation
		 * of the signature.
		 */
		if ((stat = __verify_sig(token, DH_MECH_QOP, keys, sig)) ==
		    DH_SUCCESS) {
			Free(saved_keys);
			Free(saved_sig);
			return (DH_SUCCESS);

		}

		/* Restore the keys and signature for retry */
		for (j = 0; j < keys->dh_key_set_len; j++)
			keys->dh_key_set_val[j] = saved_keys[j];

		memcpy(sig->dh_signature_val, saved_sig, sig->dh_signature_len);
	}

	Free(saved_keys);
	Free(saved_sig);
	return (stat);
}
/*
 * This is the Diffie-Hellman mechanism entry point for the
 * gss_accept_sec context. See RFC 2078 for details. This
 * routine accepts a context establish token from the initator
 * and optionally produces a token to send back to the initator to
 * establish a GSS security context. The established context will
 * be return via the *gss_ctx paramater.
 */

OM_uint32
__dh_gss_accept_sec_context(void *ctx, /* Per mechanism context */
			    OM_uint32 *minor, /* Mechanism status */
			    gss_ctx_id_t *gss_ctx, /* GSS context */
			    gss_cred_id_t cred, /* GSS credential */
			    gss_buffer_t input, /* Input from initiator */
				/* Local channel bindings  */
			    gss_channel_bindings_t  channel,
			    gss_name_t *principal, /* Initiator name */
			    gss_OID* mech, /* Returned mechanism */
			    gss_buffer_t output, /* Token to send initiator */
			    OM_uint32 *flags, /* flags of context */
			    OM_uint32 *expire, /* Time left on context */
			    gss_cred_id_t *del_cred /* Delegated credential */)
{
	dh_token_desc token;
	/* ctx is a Diffie-Hellman mechanism context */
	dh_context_t dhctx = (dh_context_t)ctx;
	dh_gss_context_t g_cntx = NULL;
	dh_principal netname = NULL;
	dh_init_context_t clnt;
	OM_uint32 stat;
	int i;
	dh_signature sig;
	struct gss_channel_bindings_struct dh_binding_desc;
	gss_channel_bindings_t dh_binding;

	/* Check for required parameters */
	if (input == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);
	if (minor == NULL || output == NULL || gss_ctx == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Give outputs sane values if present */
	*minor = 0;
	if (principal)
		*principal = NULL;
	if (mech)
		*mech = GSS_C_NO_OID;
	if (flags)
		*flags  = 0;
	if (expire)
		*expire = 0;
	if (del_cred)
		*del_cred = GSS_C_NO_CREDENTIAL;

	output->length = 0;
	output->value = 0;

	/*
	 * Diffie-Hellman never returns GSS_S_CONTINUE_NEEDED from a
	 * gss_accept_sec_context so the only context read should be
	 * GSS_C_NO_CONTEXT.
	 */
	if (*gss_ctx != GSS_C_NO_CONTEXT)
		return (GSS_S_NO_CONTEXT);

	/* Valdidate the local credentinal and retrieve then principal name */
	stat = validate_cred(dhctx, minor,
			    (dh_cred_id_t)cred, GSS_C_ACCEPT, &netname);
	if (stat != GSS_S_COMPLETE)
		return (stat);

	/*
	 * Deserialize the input into token, extracting the signature
	 * into sig. Where sig is our calculation of the MD5 check sum
	 * over the input token up to the signature.
	 */
	memset(&sig, 0, sizeof (sig));
	if (*minor = __get_ap_token(input, dhctx->mech, &token, &sig)) {
		free(netname);
		__free_signature(&sig);
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	/* set clnt to point to the init context part of token */
	clnt = &token.ver.dh_version_u.body.dh_token_body_desc_u.init_context;

	/* Check that this context is really for us */
	if (strcmp(clnt->cntx.local, netname) != 0) {
		free(netname);
		*minor = DH_NOT_LOCAL;
		stat = GSS_S_DEFECTIVE_TOKEN;
		goto cleanup;
	}
	free(netname);

	/*
	 * See if this is a DH protocol version that we can handle.
	 * Currently we can handle the one and only DH_PROTO_VERSION.
	 */

	if (token.ver.verno != DH_PROTO_VERSION) {
		*minor = DH_PROTO_MISMATCH;
		stat = GSS_S_DEFECTIVE_TOKEN;
		goto cleanup;
	}

	/* Decrypt the session keys and verify the signature */
	if ((*minor = establish_session_keys(dhctx, clnt->cntx.remote,
					    &clnt->keys,
					    &sig, &token)) != DH_SUCCESS) {
		stat = GSS_S_BAD_SIG;
		goto cleanup;
	}

	/* Check that the channel bindings are the same */
	dh_binding = DH2GSS_channel_binding(&dh_binding_desc,
					    clnt->cntx.channel);
	if (!gss_chanbind_cmp(channel, dh_binding)) {
		stat = GSS_S_BAD_BINDINGS;
		goto cleanup;
	}

	/* Everything is OK, so allocate the context */
	if ((g_cntx = New(dh_gss_context_desc, 1)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		stat = GSS_S_FAILURE;
		goto cleanup;
	}

	/*
	 * The context is now established for us, though we may still
	 * need to send a token if the initiator requested mutual
	 * authentications.
	 */
	g_cntx->state = ESTABLISHED;
	/* We're not the initiator */
	g_cntx->initiate = 0;
	/* Set the protocol version from the token */
	g_cntx->proto_version = token.ver.verno;
	/* Initialize the sequence history */
	__dh_init_seq_hist(g_cntx);
	/* Set debug to false */
	g_cntx->debug = 0;

	/* Set who the initiator is */
	if ((g_cntx->remote = strdup(clnt->cntx.remote)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		stat = GSS_S_FAILURE;
		goto cleanup;
	}

	/* Set who we are */
	if ((g_cntx->local = strdup(clnt->cntx.local)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		stat = GSS_S_FAILURE;
		goto cleanup;
	}

	/* Stash a copy of the session keys for the context */
	g_cntx->no_keys = clnt->keys.dh_key_set_len;
	if ((g_cntx->keys = New(des_block, g_cntx->no_keys)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		stat = GSS_S_FAILURE;
		goto cleanup;
	}

	for (i = 0; i < g_cntx->no_keys; i++)
		g_cntx->keys[i] = clnt->keys.dh_key_set_val[i];

	/* Set the flags and expire time */
	g_cntx->flags = clnt->cntx.flags;
	g_cntx->expire = clnt->cntx.expire;

	/* Create output token if needed */
	if (g_cntx->flags & GSS_C_MUTUAL_FLAG) {
		if (*minor = gen_accept_token(g_cntx, channel, output)) {
			stat = GSS_S_FAILURE;
			goto cleanup;
		}
	}

	/* This is now a valid context */
	if ((*minor = __dh_install_context(g_cntx)) != DH_SUCCESS) {
		stat = GSS_S_FAILURE;
		goto cleanup;
	}

	/* Return the GSS context to the caller */
	*gss_ctx = (gss_ctx_id_t)g_cntx;

	/* Return the remote principal if requested */
	if (principal)
		*principal = (gss_name_t)strdup(g_cntx->remote);
	/* Return the flags if requested */
	if (flags)
		*flags = g_cntx->flags;
	/* Return the expire time if requested */
	if (expire)
		*expire = g_cntx->expire;
	/* Return the mechanism if requested */
	if (mech)
		*mech = dhctx->mech;

	/* Release storage of the signature */
	__free_signature(&sig);

	/* Tear down the deserialize token */
	xdr_free(xdr_dh_token_desc, (char *)&token);

	/* We're done */
	return (GSS_S_COMPLETE);

cleanup:
	/* Destroy incomplete context */
	if (g_cntx) {
		__dh_destroy_seq_hist(g_cntx);
		(void) __dh_remove_context(g_cntx);
		free(g_cntx->remote);
		free(g_cntx->local);
		Free(g_cntx->keys);
		Free(g_cntx);
	}

	/* Release the signature and the deserialized token. */
	__free_signature(&sig);
	xdr_free(xdr_dh_token_desc, (char *)&token);

	return (stat);
}


/*
 * gen_init_token: create a token to pass to the other side
 * to create a GSS context.
 */
static
OM_uint32
gen_init_token(dh_gss_context_t cntx, /* Diffie-Hellman GSS context */
	    dh_context_t dhctx,    /* Diffie-Hellman mechanism context */
	    gss_channel_bindings_t channel, /* local channel bindings */
	    gss_buffer_t result /* The serialized token to send */)
{
	dh_token_desc token;	/* Unserialed token */
	dh_init_context_t remote;  /* init_context in token */
	dh_key_set keys, ukeys;	/* encrypted and unencrypted keys */
	int i, stat;
	dh_channel_binding_desc dh_binding;

	/* Create key_set for session keys */
	if ((keys.dh_key_set_val = New(des_block, cntx->no_keys)) == NULL)
		return (DH_NOMEM_FAILURE);

	keys.dh_key_set_len = cntx->no_keys;
	for (i = 0; i < cntx->no_keys; i++)
		keys.dh_key_set_val[i] = cntx->keys[i];

	/* Initialize token from GSS context */
	memset(&token, 0, sizeof (token));
	token.ver.verno = cntx->proto_version;
	token.ver.dh_version_u.body.type = DH_INIT_CNTX;

	/* Set remote to init_context part of token */
	remote = &token.ver.dh_version_u.body.dh_token_body_desc_u.init_context;
	/* We're the remote to the other side */
	remote->cntx.remote = cntx->local;
	/* And they are the local */
	remote->cntx.local = cntx->remote;
	/* Set our flags */
	remote->cntx.flags = cntx->flags;
	/* Set the expire time */
	remote->cntx.expire = cntx->expire;
	/* hand of our channel bindings */
	remote->cntx.channel = GSS2DH_channel_binding(&dh_binding, channel);
	/* set the tokens keys */
	remote->keys = keys;


	/* Encrypt the keys for the other side */

	if (dhctx->keyopts->key_encryptsessions(cntx->remote,
						keys.dh_key_set_val,
						cntx->no_keys)) {
		Free(keys.dh_key_set_val);
		return (DH_SESSION_CIPHER_FAILURE);
	}

	/* Package up our session keys */
	ukeys.dh_key_set_len = cntx->no_keys;
	ukeys.dh_key_set_val = cntx->keys;
	/*
	 * Make an APPLICATION 0 token and place it in result.
	 * Note that the unecrypted ukeys key_set is used to sign
	 * the token.
	 */
	stat =  __make_ap_token(result, dhctx->mech, &token, &ukeys);

	/* We're don with the encrypted session keys */
	Free(keys.dh_key_set_val);

	/* Return our status */
	return (stat);
}

/*
 * create_context: Builds the initial Diffie-Hellman GSS context.
 * It should always be the case that *gss_ctx == GSS_C_NO_CONTEXT
 * on entering this routine. Given the inputs we created a Diffie-Hellman
 * context from them. This routine will call gen_init_token above to
 * generate the output token to pass to the other side.
 */
static
OM_uint32
create_context(OM_uint32 *minor, /* Diffie-Hellman specific status */
	    dh_context_t cntx, /* Diffie-Hellman mech context */
	    dh_gss_context_t *gss_ctx, /* DH GSS context */
	    dh_principal netname, /* Local principal */
	    dh_principal target, /* Remote principal */
	    gss_channel_bindings_t channel, /* Channel bindings */
	    OM_uint32 flags_req, /* Flags to set on context */
	    OM_uint32 time_req, /* Time to live for context */
	    OM_uint32 *flags_rec, /* Flags that were actually set */
	    OM_uint32 *time_rec, /* Time actually received */
	    gss_buffer_t results /* Output token for the other side */)
{
	dh_gss_context_t dh_gss_ctx; /* The Diffie-Hellman context to create */
	time_t now = time(0);	/* Used to set the expire time */
	OM_uint32 expire;	/* Time left on the context */

	/* Create the Diffie-Hellman context */
	if ((*gss_ctx = dh_gss_ctx = New(dh_gss_context_desc, 1)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		return (GSS_S_FAILURE);
	}

	/* We're not established yet */
	dh_gss_ctx->state = INCOMPLETE;
	/* We're the initiator */
	dh_gss_ctx->initiate = 1;
	/* Set the protocol version for the context */
	dh_gss_ctx->proto_version = DH_PROTO_VERSION;
	/* Initialize the sequence and replay history */
	__dh_init_seq_hist(dh_gss_ctx);
	/* Turn off debugging */
	dh_gss_ctx->debug = 0;

	dh_gss_ctx->local = NULL;

	/* Remember who we want to talk to. */
	if ((dh_gss_ctx->remote = strdup(target)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		goto cleanup;
	}

	/* Rember who we are. */
	if ((dh_gss_ctx->local = strdup(netname)) == NULL) {
		*minor = DH_NOMEM_FAILURE;
		goto cleanup;
	}

	/* Set up the session key */
	dh_gss_ctx->no_keys = 3;
	dh_gss_ctx->keys = New(des_block, 3);
	if (dh_gss_ctx->keys == NULL) {
		*minor = DH_NOMEM_FAILURE;
		goto cleanup;
	}

	/* Call the mechanism specific key generator */
	if (cntx->keyopts->key_gendeskeys(dh_gss_ctx->keys, 3)) {
		*minor = DH_NOMEM_FAILURE;
		goto cleanup;
	}

#ifdef DH_DEBUG
	{
		int i;

		fprintf(stderr, "Generated session keys:\n");
		for (i = 0; i < dh_gss_ctx->no_keys; i++)
			fprintf(stderr, "%08.8x%08.8x ",
				dh_gss_ctx->keys[i].key.high,
				dh_gss_ctx->keys[i].key.low);
		fprintf(stderr, "\n");
	}
#endif

	/*
	 *  We don't support currently support
	 *  GSS_C_ANON_FLAG and GSS_C_DELEG_FLAG and GSS_C_CONF_FLAG
	 */

	dh_gss_ctx->flags = (flags_req &
	    (GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG |
		    GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG));

	/* This mechanism does integrity */
	dh_gss_ctx->flags |=  GSS_C_INTEG_FLAG;

	/* Return flags to the caller if they care */
	if (flags_rec)
		*flags_rec = dh_gss_ctx->flags;

	/* Set expire, 0 is the default, which means indefinite */
	expire = time_req ? time_req : GSS_C_INDEFINITE;
	/* Actually set the expire time for the context */
	dh_gss_ctx->expire = expire == GSS_C_INDEFINITE ?
		expire : expire + now;
	/* Tell the call the time given to the context if they care */
	if (time_rec)
		*time_rec = expire;

	/* Gennerate the output token to send to the other side */
	*minor = gen_init_token(dh_gss_ctx, cntx,
				channel, results);
	if (*minor != DH_SUCCESS)
		goto cleanup;

	/* Recored this context as valid */
	if ((*minor = __dh_install_context(dh_gss_ctx)) != DH_SUCCESS)
		goto cleanup;

	/* If we ask for mutal authentication return continue needed */
	dh_gss_ctx->state = dh_gss_ctx->flags & GSS_C_MUTUAL_FLAG ?
		INCOMPLETE : ESTABLISHED;

	return (dh_gss_ctx->state == ESTABLISHED ?
		GSS_S_COMPLETE : GSS_S_CONTINUE_NEEDED);
cleanup:

	__dh_destroy_seq_hist(dh_gss_ctx);
	free(dh_gss_ctx->remote);
	free(dh_gss_ctx->local);
	Free(dh_gss_ctx->keys);
	Free(dh_gss_ctx);

	/*
	 * Let the caller of gss_init_sec_context know that they don't
	 * have a context.
	 */
	*gss_ctx = (dh_gss_context_t)GSS_C_NO_CONTEXT;

	return (GSS_S_FAILURE);
}

/*
 * continue_context: Proccess the token from the otherside in the case
 * of mutual authentication.
 */
static
OM_uint32
continue_context(OM_uint32 *minor, gss_buffer_t token,
    dh_gss_context_t dh_gss_ctx, gss_channel_bindings_t channel)
{
	dh_key_set keys;
	dh_token_desc tok;
	dh_cntx_t remote_ctx;
	struct gss_channel_bindings_struct remote_chan_desc;
	gss_channel_bindings_t remote_chan;

	/* Set minor to sane state */
	*minor = DH_SUCCESS;

	/* This should never happen */
	if (token == NULL || token->length == 0)
		return (GSS_S_DEFECTIVE_TOKEN);

	/* Package the session keys for __get_token) */
	keys.dh_key_set_len = dh_gss_ctx->no_keys;
	keys.dh_key_set_val = dh_gss_ctx->keys;

	/* Deserialize the input token into tok using the session keys */
	if (*minor = __get_token(token, NULL, &tok, &keys))
		return (*minor == DH_VERIFIER_MISMATCH ?
			GSS_S_BAD_SIG : GSS_S_DEFECTIVE_TOKEN);

	/*
	 * See if this is a Diffie-Hellman protocol version that we
	 * can handle. Currently we can only handle the protocol version that
	 * we initiated.
	 */
	if (tok.ver.verno != dh_gss_ctx->proto_version) {
		*minor = DH_PROTO_MISMATCH;
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	/* Make sure this is the right type of token */
	if (tok.ver.dh_version_u.body.type != DH_ACCEPT_CNTX) {
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	/* Grab a pointer to the context part of the token */
	remote_ctx = &tok.ver.dh_version_u.
			body.dh_token_body_desc_u.accept_context.cntx;

	/* Make sure this is from the remote and for us */
	if (strcmp(remote_ctx->remote, dh_gss_ctx->remote) ||
	    strcmp(remote_ctx->local, dh_gss_ctx->local)) {
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (GSS_S_DEFECTIVE_TOKEN);
	}

	/* Make sure if the optional channel_bindings are the same */
	remote_chan = DH2GSS_channel_binding(&remote_chan_desc,
					    remote_ctx->channel);
	if (!gss_chanbind_cmp(channel, remote_chan)) {
		xdr_free(xdr_dh_token_desc, (char *)&tok);
		return (GSS_S_BAD_BINDINGS);
	}

	/* Update the context flags with what the remote will accept */
	dh_gss_ctx->flags = remote_ctx->flags;

	/* We now have an established context */
	dh_gss_ctx->state = ESTABLISHED;

	/* Release the deserialized token, tok */
	xdr_free(xdr_dh_token_desc, (char *)&tok);

	return (GSS_S_COMPLETE);
}

/*
 * This is the Diffie-Hellman mechanism entry point for the
 * gss_int_sec context. See RFC 2078 for details. This
 * routine creates a new context or continues a previously created
 * context if mutual authentication had been requested on the orignal
 * context. The first call to this routine should set *context to
 * GSS_C_NO_CONTEXT and input_token to GSS_C_NO_BUFFER or input_token->length
 * to zero. To continue a context in the case of mutual authentication
 * gss_ctx should point to the initial context and input_token should point
 * to the token received from the remote. The established context will
 * be return via the *context paramater in all cases.
 */


OM_uint32
__dh_gss_init_sec_context(void *ctx, /* Per Mechananism context */
			OM_uint32 *minor, /* Mech status */
			gss_cred_id_t cred, /* Local credentials */
			gss_ctx_id_t *context, /* The context to create */
			gss_name_t target, /* The server to talk to */
			gss_OID mech, /* The mechanism to use */
			OM_uint32 req_flags, /* Requested context flags */
			OM_uint32 time_req, /* Requested life time */
			gss_channel_bindings_t channel, /* Local bindings */
			gss_buffer_t input_token, /* Token from remote */
			gss_OID *mech_rec, /* Optional mech to return */
			gss_buffer_t output_token, /* Token for remote */
			OM_uint32 *flags_rec, /* Actual flags received */
			OM_uint32 *time_rec /* Actual life time received */)
{
	dh_context_t cntx = (dh_context_t)ctx;
	dh_gss_context_t dh_gss_ctx = (dh_gss_context_t)*context;
	dh_principal netname;
	dh_cred_id_t dh_cred = (dh_cred_id_t)cred;
	OM_uint32 stat;

	/* We need these */
	if (minor == 0 || output_token == 0)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* Set to sane state */
	*minor = DH_SUCCESS;
	output_token->length = 0;
	output_token->value = NULL;
	if (mech_rec)
		*mech_rec = cntx->mech;   /* Note this should not be duped. */

	/* Check that were the right mechanism */
	if ((mech != GSS_C_NULL_OID) &&
	    (!__OID_equal(mech, cntx->mech))) {
		return (GSS_S_BAD_MECH);
	}

	/* Validate the cred and obtain our netname in the process. */
	stat = validate_cred(cntx, minor, dh_cred, GSS_C_INITIATE, &netname);
	if (stat != GSS_S_COMPLETE)
		return (stat);

	/* validate target name */
	/*
	 * we could check that the target is in the proper form and
	 * possibly do a lookup up on the host part.
	 */

	/* checks for new context */
	if (dh_gss_ctx == (dh_gss_context_t)GSS_C_NO_CONTEXT) {

		if (input_token != GSS_C_NO_BUFFER &&
			input_token->length != 0)
			return (GSS_S_DEFECTIVE_TOKEN);

		/* Create a new context */
		stat =  create_context(minor, cntx, &dh_gss_ctx, netname,
				    (dh_principal)target, channel, req_flags,
				    time_req, flags_rec, time_rec,
				    output_token);

		/* Set the GSS context to the Diffie-Hellman context */
		*context = (gss_ctx_id_t)dh_gss_ctx;

	} else {

		/* Validate the context */
		if ((*minor = __dh_validate_context(dh_gss_ctx)) != DH_SUCCESS)
			return (GSS_S_NO_CONTEXT);

		/* Authenticate the server */
		stat = continue_context(minor,
					input_token, dh_gss_ctx, channel);

	}

	free(netname);
	return (stat);
}
