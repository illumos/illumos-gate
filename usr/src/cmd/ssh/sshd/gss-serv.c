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

#include "includes.h"

#ifdef GSSAPI

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "includes.h"
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
#include "auth.h"
#include "log.h"
#include "channels.h"
#include "session.h"
#include "dispatch.h"
#include "servconf.h"
#include "uidswap.h"
#include "compat.h"
#include <pwd.h>

#include "ssh-gss.h"

extern char **environ;

extern ServerOptions options;
extern uchar_t *session_id2;
extern int session_id2_len;

Gssctxt	*xxx_gssctxt;

void
ssh_gssapi_server_kex_hook(Kex *kex, char **proposal)
{
	gss_OID_set mechs = GSS_C_NULL_OID_SET;

	if (kex == NULL || !kex->server)
		fatal("INTERNAL ERROR (%s)", __func__);

	ssh_gssapi_server_mechs(&mechs);
	ssh_gssapi_modify_kex(kex, mechs, proposal);
}

void
ssh_gssapi_server_mechs(gss_OID_set *mechs)
{
	static gss_OID_set	supported = GSS_C_NULL_OID_SET;
	gss_OID_set	s, acquired, indicated = GSS_C_NULL_OID_SET;
	gss_cred_id_t	creds;
	OM_uint32	maj, min;
	int		i;

	if (!mechs) {
		(void) gss_release_oid_set(&min, &supported);
		return;
	}

	if (supported != GSS_C_NULL_OID_SET) {
		*mechs = supported;
		return;
	}

	*mechs = GSS_C_NULL_OID_SET;

	maj = gss_create_empty_oid_set(&min, &s);
	if (GSS_ERROR(maj)) {
		debug("Could not allocate GSS-API resources (%s)",
		    ssh_gssapi_last_error(NULL, &maj, &min));
		return;
	}

	maj = gss_indicate_mechs(&min, &indicated);
	if (GSS_ERROR(maj)) {
		debug("No GSS-API mechanisms are installed");
		return;
	}

	maj = gss_acquire_cred(&min, GSS_C_NO_NAME, 0, indicated,
	    GSS_C_ACCEPT, &creds, &acquired, NULL);

	if (GSS_ERROR(maj))
		debug("Failed to acquire GSS-API credentials for any "
		    "mechanisms (%s)", ssh_gssapi_last_error(NULL, &maj, &min));

	(void) gss_release_oid_set(&min, &indicated);
	(void) gss_release_cred(&min, &creds);

	if (acquired == GSS_C_NULL_OID_SET || acquired->count == 0)
		return;

	for (i = 0; i < acquired->count; i++) {
		if (ssh_gssapi_is_spnego(&acquired->elements[i]))
			continue;

		maj = gss_add_oid_set_member(&min, &acquired->elements[i], &s);
		if (GSS_ERROR(maj)) {
			debug("Could not allocate GSS-API resources (%s)",
			    ssh_gssapi_last_error(NULL, &maj, &min));
			return;
		}
	}
	(void) gss_release_oid_set(&min, &acquired);

	if (s->count) {
		supported = s;
		*mechs = s;
	}
}

/*
 * Wrapper around accept_sec_context. Requires that the context contains:
 *
 *    oid
 *    credentials	(from ssh_gssapi_acquire_cred)
 */
/* Priviledged */
OM_uint32
ssh_gssapi_accept_ctx(Gssctxt *ctx, gss_buffer_t recv_tok,
    gss_buffer_t send_tok)
{
	/*
	 * Acquiring a cred for the ctx->desired_mech for GSS_C_NO_NAME
	 * may well be probably better than using GSS_C_NO_CREDENTIAL
	 * and then checking that ctx->desired_mech agrees with
	 * ctx->actual_mech...
	 */
	ctx->major = gss_accept_sec_context(&ctx->minor, &ctx->context,
	    GSS_C_NO_CREDENTIAL, recv_tok, GSS_C_NO_CHANNEL_BINDINGS,
	    &ctx->src_name, &ctx->actual_mech, send_tok, &ctx->flags,
	    NULL, &ctx->deleg_creds);

	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx, "accepting security context");

	if (ctx->major == GSS_S_CONTINUE_NEEDED && send_tok->length == 0)
		fatal("Zero length GSS context token output when "
		    "continue needed");
	else if (GSS_ERROR(ctx->major) && send_tok->length == 0)
		debug2("Zero length GSS context error token output");

	if (ctx->major == GSS_S_COMPLETE &&
	    ctx->desired_mech != GSS_C_NULL_OID &&
	    (ctx->desired_mech->length != ctx->actual_mech->length ||
	    memcmp(ctx->desired_mech->elements, ctx->actual_mech->elements,
	    ctx->desired_mech->length) != 0)) {

		gss_OID_set supported;
		OM_uint32 min;
		int present = 0;

		debug("The client did not use the GSS-API mechanism it "
		    "asked for");

		/* Let it slide as long as the mech is supported */
		ssh_gssapi_server_mechs(&supported);
		if (supported != GSS_C_NULL_OID_SET) {
			(void) gss_test_oid_set_member(&min, ctx->actual_mech,
			    supported, &present);
		}
		if (!present)
			ctx->major = GSS_S_BAD_MECH;
	}

	if (ctx->deleg_creds)
		debug("Received delegated GSS credentials");

	if (ctx->major == GSS_S_COMPLETE) {
		ctx->major = gss_inquire_context(&ctx->minor, ctx->context,
		    NULL, &ctx->dst_name, NULL, NULL, NULL, NULL,
		    &ctx->established);

		if (GSS_ERROR(ctx->major)) {
			ssh_gssapi_error(ctx,
			    "inquiring established sec context");
			return (ctx->major);
		}

		xxx_gssctxt = ctx;
	}

	return (ctx->major);
}


/* As user - called through fatal cleanup hook */
void
ssh_gssapi_cleanup_creds(Gssctxt *ctx)
{
#ifdef HAVE_GSS_STORE_CRED
	/* pam_setcred() will take care of this */
	return;
#else
	return;
/* #error "Portability broken in cleanup of stored creds" */
#endif /* HAVE_GSS_STORE_CRED */
}

void
ssh_gssapi_storecreds(Gssctxt *ctx, Authctxt *authctxt)
{
#ifdef USE_PAM
	char **penv, **tmp_env;
#endif /* USE_PAM */

	if (authctxt == NULL) {
		error("Missing context while storing GSS-API credentials");
		return;
	}

	if (ctx == NULL && xxx_gssctxt == NULL)
		return;

	if (ctx == NULL)
		ctx = xxx_gssctxt;

	if (!options.gss_cleanup_creds ||
	    ctx->deleg_creds == GSS_C_NO_CREDENTIAL) {
		debug3("Not storing delegated GSS credentials"
		    " (none delegated)");
		return;
	}

	if (!authctxt->valid || authctxt->pw == NULL) {
		debug3("Not storing delegated GSS credentials"
		    " for invalid user");
		return;
	}

	debug("Storing delegated GSS-API credentials");

	/*
	 * The GSS-API has a flaw in that it does not provide a
	 * mechanism by which delegated credentials can be made
	 * available for acquisition by GSS_Acquire_cred() et. al.;
	 * gss_store_cred() is the proposed GSS-API extension for
	 * generically storing delegated credentials.
	 *
	 * gss_store_cred() does not speak to how credential stores are
	 * referenced.  Generically this may be done by switching to the
	 * user context of the user in whose default credential store we
	 * wish to place delegated credentials.  But environment
	 * variables could conceivably affect the choice of credential
	 * store as well, and perhaps in a mechanism-specific manner.
	 *
	 * SUNW -- On Solaris the euid selects the current credential
	 * store, but PAM modules could select alternate stores by
	 * setting, for example, KRB5CCNAME, so we also use the PAM
	 * environment temporarily.
	 */

#ifdef HAVE_GSS_STORE_CRED
#ifdef USE_PAM
	/*
	 * PAM may have set mechanism-specific variables (e.g.,
	 * KRB5CCNAME).  fetch_pam_environment() protects against LD_*
	 * and other environment variables.
	 */
	penv = fetch_pam_environment(authctxt);
	tmp_env = environ;
	environ = penv;
#endif /* USE_PAM */
	if (authctxt->pw->pw_uid != geteuid()) {
		temporarily_use_uid(authctxt->pw);
		ctx->major = gss_store_cred(&ctx->minor, ctx->deleg_creds,
		    GSS_C_INITIATE, GSS_C_NULL_OID, 0, ctx->default_creds,
		    NULL, NULL);
		restore_uid();
	} else {
		/* only when logging in as the privileged user used by sshd */
		ctx->major = gss_store_cred(&ctx->minor, ctx->deleg_creds,
		    GSS_C_INITIATE, GSS_C_NULL_OID, 0, ctx->default_creds,
		    NULL, NULL);
	}
#ifdef USE_PAM
	environ = tmp_env;
	free_pam_environment(penv);
#endif /* USE_PAM */
	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx, "storing delegated credentials");

#else
#ifdef KRB5_GSS
#error "MIT/Heimdal krb5-specific code missing in ssh_gssapi_storecreds()"
	if (ssh_gssapi_is_krb5(ctx->mech))
		ssh_gssapi_krb5_storecreds(ctx);
#endif /* KRB5_GSS */
#ifdef GSI_GSS
#error "GSI krb5-specific code missing in ssh_gssapi_storecreds()"
	if (ssh_gssapi_is_gsi(ctx->mech))
		ssh_gssapi_krb5_storecreds(ctx);
#endif /* GSI_GSS */
/* #error "Mechanism-specific code missing in ssh_gssapi_storecreds()" */
	return;
#endif /* HAVE_GSS_STORE_CRED */
}

void
ssh_gssapi_do_child(Gssctxt *ctx, char ***envp, uint_t *envsizep)
{
	/*
	 * MIT/Heimdal/GSI specific code goes here.
	 *
	 * On Solaris there's nothing to do here as the GSS store and
	 * related environment variables are to be set by PAM, if at all
	 * (no environment variables are needed to address the default
	 * credential store -- the euid does that).
	 */
#ifdef KRB5_GSS
#error "MIT/Heimdal krb5-specific code missing in ssh_gssapi_storecreds()"
#endif /* KRB5_GSS */
#ifdef GSI_GSS
#error "GSI krb5-specific code missing in ssh_gssapi_storecreds()"
#endif /* GSI_GSS */
}

int
ssh_gssapi_userok(Gssctxt *ctx, char *user)
{
	if (ctx == NULL) {
		debug3("INTERNAL ERROR: %s", __func__);
		return (0);
	}

	if (user == NULL || *user == '\0')
		return (0);

#ifdef HAVE___GSS_USEROK
	{
		int user_ok = 0;

		ctx->major = __gss_userok(&ctx->minor, ctx->src_name, user,
		    &user_ok);
		if (GSS_ERROR(ctx->major)) {
			debug2("__GSS_userok() failed");
			return (0);
		}

		if (user_ok)
			return (1);

		/* fall through */
	}
#else
#ifdef GSSAPI_SIMPLE_USEROK
	{
		/* Mechanism-generic */
		OM_uint32	min;
		gss_buffer_desc	buf, ename1, ename2;
		gss_name_t	iname, cname;
		int		eql;

		buf.value = user;
		buf.length = strlen(user);
		ctx->major = gss_import_name(&ctx->minor, &buf,
		    GSS_C_NULL_OID, &iname);
		if (GSS_ERROR(ctx->major)) {
			ssh_gssapi_error(ctx,
			    "importing name for authorizing initiator");
			goto failed_simple_userok;
		}

		ctx->major = gss_canonicalize_name(&ctx->minor, iname,
		    ctx->actual_mech, &cname);
		(void) gss_release_name(&min, &iname);
		if (GSS_ERROR(ctx->major)) {
			ssh_gssapi_error(ctx, "canonicalizing name");
			goto failed_simple_userok;
		}

		ctx->major = gss_export_name(&ctx->minor, cname, &ename1);
		(void) gss_release_name(&min, &cname);
		if (GSS_ERROR(ctx->major)) {
			ssh_gssapi_error(ctx, "exporting name");
			goto failed_simple_userok;
		}

		ctx->major = gss_export_name(&ctx->minor, ctx->src_name,
		    &ename2);
		if (GSS_ERROR(ctx->major)) {
			ssh_gssapi_error(ctx,
			    "exporting client principal name");
			(void) gss_release_buffer(&min, &ename1);
			goto failed_simple_userok;
		}

		eql = (ename1.length == ename2.length &&
		    memcmp(ename1.value, ename2.value, ename1.length) == 0);

		(void) gss_release_buffer(&min, &ename1);
		(void) gss_release_buffer(&min, &ename2);

		if (eql)
			return (1);
		/* fall through */
	}
failed_simple_userok:
#endif /* GSSAPI_SIMPLE_USEROK */
#ifdef HAVE_GSSCRED_API
	{
		/* Mechanism-generic, Solaris-specific */
		OM_uint32	 maj;
		uid_t		 uid;
		struct passwd	*pw;

		maj = gsscred_name_to_unix_cred(ctx->src_name,
		    ctx->actual_mech, &uid, NULL, NULL, NULL);

		if (GSS_ERROR(maj))
			goto failed_simple_gsscred_userok;

		if ((pw = getpwnam(user)) == NULL)
			goto failed_simple_gsscred_userok;

		if (pw->pw_uid == uid)
			return (1);
		/* fall through */
	}

failed_simple_gsscred_userok:
#endif /* HAVE_GSSCRED_API */
#ifdef KRB5_GSS
	if (ssh_gssapi_is_krb5(ctx->mech))
		if (ssh_gssapi_krb5_userok(ctx->src_name, user))
			return (1);
#endif /* KRB5_GSS */
#ifdef GSI_GSS
	if (ssh_gssapi_is_gsi(ctx->mech))
		if (ssh_gssapi_gsi_userok(ctx->src_name, user))
			return (1);
#endif /* GSI_GSS */
#endif /* HAVE___GSS_USEROK */

	/* default to not authorized */
	return (0);
}

char *
ssh_gssapi_localname(Gssctxt *ctx)
{
	if (ctx == NULL) {
		debug3("INTERNAL ERROR: %s", __func__);
		return (NULL);
	}

	debug2("Mapping initiator GSS-API principal to local username");
#ifdef HAVE_GSSCRED_API
	{
		/* Mechanism-generic, Solaris-specific */
		OM_uint32	 maj;
		uid_t		 uid;
		struct passwd	*pw;

		if (ctx->src_name == GSS_C_NO_NAME)
			goto failed_gsscred_localname;

		maj = gsscred_name_to_unix_cred(ctx->src_name,
		    ctx->actual_mech, &uid, NULL, NULL, NULL);

		if (GSS_ERROR(maj))
			goto failed_gsscred_localname;

		if ((pw = getpwuid(uid)) == NULL)
			goto failed_gsscred_localname;

		debug2("Mapped the initiator to: %s", pw->pw_name);
		return (xstrdup(pw->pw_name));
	}
failed_gsscred_localname:
#endif /* HAVE_GSSCRED_API */
#ifdef KRB5_GSS
#error "ssh_gssapi_krb5_localname() not implemented"
	if (ssh_gssapi_is_krb5(ctx->mech))
		return (ssh_gssapi_krb5_localname(ctx->src_name));
#endif /* KRB5_GSS */
#ifdef GSI_GSS
#error "ssh_gssapi_gsi_localname() not implemented"
	if (ssh_gssapi_is_gsi(ctx->mech))
		return (ssh_gssapi_gsi_localname(ctx->src_name));
#endif /* GSI_GSS */
	return (NULL);
}
#endif /* GSSAPI */
