/*
 * Copyright (c) 2001-2003 Simon Wilkinson. All rights reserved. *
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

#include "includes.h"

#ifdef GSSAPI

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "packet.h"
#include "compat.h"
#include <openssl/evp.h>
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "compat.h"

#include <netdb.h>

#include "ssh-gss.h"

void
ssh_gssapi_client_kex_hook(Kex *kex, char **proposal)
{
	gss_OID_set mechs = GSS_C_NULL_OID_SET;

	if (kex == NULL || kex->serverhost == NULL)
		fatal("INTERNAL ERROR (%s)", __func__);

	ssh_gssapi_client_mechs(kex->serverhost, &mechs);
	ssh_gssapi_modify_kex(kex, mechs, proposal);
}

void
ssh_gssapi_client_mechs(const char *server_host, gss_OID_set *mechs)
{
	gss_OID_set	indicated = GSS_C_NULL_OID_SET;
	gss_OID_set	acquired, supported;
	gss_OID		mech;
	gss_cred_id_t	creds;
	Gssctxt		*ctxt = NULL;
	gss_buffer_desc	tok;
	OM_uint32	maj, min;
	int		i;
	char		*errmsg;

	if (!mechs)
		return;
	*mechs = GSS_C_NULL_OID_SET;

	maj = gss_indicate_mechs(&min, &indicated);
	if (GSS_ERROR(maj)) {
		debug("No GSS-API mechanisms are installed");
		return;
	}

	maj = gss_create_empty_oid_set(&min, &supported);
	if (GSS_ERROR(maj)) {
		errmsg = ssh_gssapi_last_error(NULL, &maj, &min);
		debug("Failed to allocate resources (%s) for GSS-API", errmsg);
		xfree(errmsg);
		(void) gss_release_oid_set(&min, &indicated);
		return;
	}
	maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, indicated,
	    GSS_C_INITIATE, &creds, &acquired, NULL);

	if (GSS_ERROR(maj)) {
		errmsg = ssh_gssapi_last_error(NULL, &maj, &min);
		debug("Failed to acquire GSS-API credentials for any "
		    "mechanisms (%s)", errmsg);
		xfree(errmsg);
		(void) gss_release_oid_set(&min, &indicated);
		(void) gss_release_oid_set(&min, &supported);
		return;
	}
	(void) gss_release_cred(&min, &creds);

	for (i = 0; i < acquired->count; i++) {
		mech = &acquired->elements[i];

		if (ssh_gssapi_is_spnego(mech))
			continue;

		ssh_gssapi_build_ctx(&ctxt, 1, mech);
		if (!ctxt)
			continue;

		/*
		 * This is useful for mechs like Kerberos, which can
		 * detect unknown target princs here, but not for
		 * mechs like SPKM, which cannot detect unknown princs
		 * until context tokens are actually exchanged.
		 *
		 * 'Twould be useful to have a test that could save us
		 * the bother of trying this for SPKM and the such...
		 */
		maj = ssh_gssapi_init_ctx(ctxt, server_host, 0, NULL, &tok);
		if (GSS_ERROR(maj)) {
			errmsg = ssh_gssapi_last_error(ctxt, NULL, NULL);
			debug("Skipping GSS-API mechanism %s (%s)",
			    ssh_gssapi_oid_to_name(mech), errmsg);
			xfree(errmsg);
			continue;
		}

		(void) gss_release_buffer(&min, &tok);

		maj = gss_add_oid_set_member(&min, mech, &supported);
		if (GSS_ERROR(maj)) {
			errmsg = ssh_gssapi_last_error(NULL, &maj, &min);
			debug("Failed to allocate resources (%s) for GSS-API",
			    errmsg);
			xfree(errmsg);
		}
	}

	*mechs = supported;
}


/*
 * Wrapper to init_sec_context. Requires that the context contains:
 *
 *	oid
 * 	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, const char *server_host, int deleg_creds,
		    gss_buffer_t recv_tok, gss_buffer_t send_tok)
{
	int flags = GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG;

	debug("%s(%p, %s, %d, %p, %p)", __func__, ctx, server_host,
	    deleg_creds, recv_tok, send_tok);

	if (deleg_creds) {
		flags |= GSS_C_DELEG_FLAG;
		debug("Delegating GSS-API credentials");
	}

	/* Build target principal */
	if (ctx->desired_name == GSS_C_NO_NAME &&
	    !ssh_gssapi_import_name(ctx, server_host)) {
		return (ctx->major);
	}

	ctx->major = gss_init_sec_context(&ctx->minor, GSS_C_NO_CREDENTIAL,
	    &ctx->context, ctx->desired_name, ctx->desired_mech, flags,
	    0, /* default lifetime */
	    NULL, /* no channel bindings */
	    recv_tok,
	    NULL, /* actual mech type */
	    send_tok, &ctx->flags,
	    NULL); /* actual lifetime */

	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx, "calling GSS_Init_sec_context()");

	return (ctx->major);
}
#endif /* GSSAPI */
