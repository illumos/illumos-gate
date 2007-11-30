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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AS IS'' AND ANY EXPRESS OR
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef GSSAPI
#include "auth.h"
#include "ssh2.h"
#include "xmalloc.h"
#include "log.h"
#include "dispatch.h"
#include "servconf.h"
#include "compat.h"
#include "buffer.h"
#include "bufaux.h"
#include "packet.h"

#include <gssapi/gssapi.h>
#include "ssh-gss.h"

extern ServerOptions options;
extern u_char *session_id2;
extern int session_id2_len;
extern Gssctxt *xxx_gssctxt;

static void userauth_gssapi_finish(Authctxt *authctxt, Gssctxt *gssctxt);

static void
userauth_gssapi_keyex(Authctxt *authctxt)
{
        gss_buffer_desc g_mic_data, mic_tok;
	Buffer mic_data;
        OM_uint32 maj_status, min_status;

	if (authctxt == NULL || authctxt->method == NULL)
		fatal("No authentication context during gssapi-keyex userauth");

	if (xxx_gssctxt == NULL || xxx_gssctxt->context == GSS_C_NO_CONTEXT) {
		/* fatal()?  or return? */
		debug("No GSS-API context during gssapi-keyex userauth");
		return;
	}
		
	/* Make data buffer to verify MIC with */
	buffer_init(&mic_data);
	buffer_put_string(&mic_data, session_id2, session_id2_len);
	buffer_put_char(&mic_data, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&mic_data, authctxt->user);
	buffer_put_cstring(&mic_data, authctxt->service);
	buffer_put_cstring(&mic_data, authctxt->method->name);

	g_mic_data.value  = buffer_ptr(&mic_data);
	g_mic_data.length = buffer_len(&mic_data);

	mic_tok.value=packet_get_string(&mic_tok.length);

	maj_status = gss_verify_mic(&min_status, xxx_gssctxt->context,
				&g_mic_data, &mic_tok, NULL);

        packet_check_eom();
	buffer_clear(&mic_data);

	if (maj_status != GSS_S_COMPLETE)
		debug2("MIC verification failed, GSSAPI userauth failed");
	else
		userauth_gssapi_finish(authctxt, xxx_gssctxt);

	/* Leave Gssctxt around for ssh_gssapi_cleanup/storecreds() */
	if (xxx_gssctxt->deleg_creds == GSS_C_NO_CREDENTIAL)
		ssh_gssapi_delete_ctx(&xxx_gssctxt);

        return;
}

static void ssh_gssapi_userauth_error(Gssctxt *ctxt);
static void input_gssapi_token(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_mic(int type, u_int32_t plen, void *ctxt);
static void input_gssapi_errtok(int, u_int32_t, void *);
static void input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt);

static void
userauth_gssapi_abandon(Authctxt *authctxt, Authmethod *method)
{
	ssh_gssapi_delete_ctx((Gssctxt **)&method->method_data);
	xxx_gssctxt = NULL;
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
}

static void
userauth_gssapi(Authctxt *authctxt)
{
	gss_OID_set     supported_mechs;
	int		mechs;
	int		present = 0;
	OM_uint32       min_status;
	u_int		len;
	char 		*doid = NULL;
	gss_OID		oid = GSS_C_NULL_OID;

        if (datafellows & SSH_OLD_GSSAPI) {
                debug("Early drafts of GSSAPI userauth not supported");
                return;
        }

        mechs=packet_get_int();
        if (mechs==0) {
		packet_check_eom();
                debug("Mechanism negotiation is not supported");
                return;
        }

	ssh_gssapi_server_mechs(&supported_mechs);

        do {
                mechs--;

		if (oid != GSS_C_NULL_OID)
			ssh_gssapi_release_oid(&oid);

                doid = packet_get_string(&len);

		/* ick */
               	if (doid[0]!=0x06 || (len > 2 && doid[1]!=len-2)) {
               		log("Mechanism OID received using the old encoding form");
			oid = ssh_gssapi_make_oid(len, doid);
               	} else {
			oid = ssh_gssapi_make_oid(len - 2, doid + 2);
               	}
            	(void) gss_test_oid_set_member(&min_status, oid,
					       supported_mechs, &present);
                debug("Client offered gssapi userauth with %s (%s)",
			ssh_gssapi_oid_to_str(oid),
			present ? "supported" : "unsupported");
        } while (!present && (mechs > 0));

        if (!present) {
		/* userauth_finish() will send SSH2_MSG_USERAUTH_FAILURE */
		debug2("No mechanism offered by the client is available");
                ssh_gssapi_release_oid(&oid);
                return;
        }

	ssh_gssapi_build_ctx((Gssctxt **)&authctxt->method->method_data, 0, oid);
        ssh_gssapi_release_oid(&oid);
        /* Send SSH_MSG_USERAUTH_GSSAPI_RESPONSE */

       	packet_start(SSH2_MSG_USERAUTH_GSSAPI_RESPONSE);

	/* Just return whatever we found -- the matched mech does us no good */
	packet_put_string(doid, len);
	xfree(doid);

        packet_send();
        packet_write_wait();

	/* Setup rest of gssapi userauth conversation */
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, &input_gssapi_token);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, &input_gssapi_errtok);
        authctxt->method->postponed = 1;

        return;
}

static void
input_gssapi_token(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        gss_buffer_desc send_tok,recv_tok;
        OM_uint32 maj_status, min_status;
	u_int len;

        if (authctxt == NULL || authctxt->method == NULL ||
	    (authctxt->method->method_data == NULL))
                fatal("No authentication or GSSAPI context during gssapi-with-mic userauth");

        gssctxt=authctxt->method->method_data;
        recv_tok.value=packet_get_string(&len);
        recv_tok.length=len; /* u_int vs. size_t */

        maj_status = ssh_gssapi_accept_ctx(gssctxt, &recv_tok, &send_tok);
        packet_check_eom();

        if (GSS_ERROR(maj_status)) {
        	ssh_gssapi_userauth_error(gssctxt);
		if (send_tok.length != 0) {
			packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK);
	                packet_put_string(send_tok.value,send_tok.length);
        	        packet_send();
               		packet_write_wait();
               	}
                authctxt->method->postponed = 0;
                dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
                userauth_finish(authctxt, authctxt->method->name);
        } else {
               	if (send_tok.length != 0) {
               		packet_start(SSH2_MSG_USERAUTH_GSSAPI_TOKEN);
               		packet_put_string(send_tok.value,send_tok.length);
               		packet_send();
               		packet_write_wait();
                }
	        if (maj_status == GSS_S_COMPLETE) {
        	        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN,NULL);
                	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC,
                             	     &input_gssapi_mic);
                	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE,
                             	     &input_gssapi_exchange_complete);
                }
        }

        gss_release_buffer(&min_status, &send_tok);
}

static void
input_gssapi_errtok(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;
        gss_buffer_desc send_tok,recv_tok;

        if (authctxt == NULL || authctxt->method == NULL ||
	    (authctxt->method->method_data == NULL))
                fatal("No authentication or GSSAPI context during gssapi-with-mic userauth");

        gssctxt=authctxt->method->method_data;
        recv_tok.value=packet_get_string(&recv_tok.length);
        packet_check_eom();

        /* Push the error token into GSSAPI to see what it says */
        (void) ssh_gssapi_accept_ctx(gssctxt, &recv_tok, &send_tok);

	debug("Client sent GSS-API error token during GSS userauth-- %s",
		ssh_gssapi_last_error(gssctxt, NULL, NULL));

	/* We can't return anything to the client, even if we wanted to */
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
	dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK,NULL);


	/*
	 * The client will have already moved on to the next auth and
	 * will send a new userauth request.  The spec says that the
	 * server MUST NOT send a SSH_MSG_USERAUTH_FAILURE packet in
	 * response to this.
	 *
	 * We leave authctxt->method->postponed == 1 here so that a call
	 * to input_userauth_request() will detect this failure (as
	 * userauth abandonment) and act accordingly.
	 */
}

static void
input_gssapi_mic(int type, u_int32_t plen, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Gssctxt *gssctxt;
        gss_buffer_desc g_mic_data, mic_tok;
	Buffer mic_data;
        OM_uint32 maj_status, min_status;

	if (authctxt == NULL || authctxt->method == NULL ||
	    (authctxt->method->method_data == NULL)) {
		debug3("No authentication or GSSAPI context during gssapi-with-mic userauth");
		return;
	}

	gssctxt=authctxt->method->method_data;

	/* Make data buffer to verify MIC with */
	buffer_init(&mic_data);
	buffer_put_string(&mic_data, session_id2, session_id2_len);
	buffer_put_char(&mic_data, SSH2_MSG_USERAUTH_REQUEST);
	buffer_put_cstring(&mic_data, authctxt->user);
	buffer_put_cstring(&mic_data, authctxt->service);
	buffer_put_cstring(&mic_data, authctxt->method->name);

	g_mic_data.value  = buffer_ptr(&mic_data);
	g_mic_data.length = buffer_len(&mic_data);

	mic_tok.value=packet_get_string(&mic_tok.length);

	maj_status = gss_verify_mic(&min_status, gssctxt->context,
				&g_mic_data, &mic_tok, NULL);

        packet_check_eom();
	buffer_free(&mic_data);

	if (maj_status != GSS_S_COMPLETE)
		debug2("MIC verification failed, GSSAPI userauth failed");
	else
		userauth_gssapi_finish(authctxt, gssctxt);

	/* Delete context from keyex */
	if (xxx_gssctxt != gssctxt)
		ssh_gssapi_delete_ctx(&xxx_gssctxt);

	/* Leave Gssctxt around for ssh_gssapi_cleanup/storecreds() */
	if (gssctxt->deleg_creds == GSS_C_NO_CREDENTIAL)
		ssh_gssapi_delete_ctx(&gssctxt);

	xxx_gssctxt = gssctxt;

        authctxt->method->postponed = 0;
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
        userauth_finish(authctxt, authctxt->method->name);
}

/* This is called when the client thinks we've completed authentication.
 * It should only be enabled in the dispatch handler by the function above,
 * which only enables it once the GSSAPI exchange is complete.
 */
static void
input_gssapi_exchange_complete(int type, u_int32_t plen, void *ctxt)
{
        Authctxt *authctxt = ctxt;
        Gssctxt *gssctxt;

	packet_check_eom();

	if (authctxt == NULL || authctxt->method == NULL ||
	    (authctxt->method->method_data == NULL))
                fatal("No authentication or GSSAPI context");

        gssctxt=authctxt->method->method_data;

	/*
	 * SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE -> gssapi userauth
	 * failure, the client should use SSH2_MSG_USERAUTH_GSSAPI_MIC
	 * instead.
	 *
	 * There's two reasons for this:
	 *
	 * 1) we don't have GSS mechs that don't support integrity
	 * protection, and even if we did we'd not want to use them with
	 * SSHv2, and,
	 *
	 * 2) we currently have no way to dynamically detect whether a
	 * given mechanism does or does not support integrity
	 * protection, so when a context's flags do not indicate
	 * integrity protection we can't know if the client simply
	 * didn't request it, so we assume it didn't and reject the
	 * userauth.
	 *
	 * We could fail partially (i.e., force the use of other
	 * userauth methods without counting this one as failed).  But
	 * this will do for now.
	 */
#if 0
        authctxt->method->authenticated = ssh_gssapi_userok(gssctxt, authctxt->user);
#endif

	if (xxx_gssctxt != gssctxt)
		ssh_gssapi_delete_ctx(&gssctxt);
	ssh_gssapi_delete_ctx(&gssctxt);
        authctxt->method->postponed = 0;
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_TOKEN, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_ERRTOK, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_MIC, NULL);
        dispatch_set(SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE, NULL);
        userauth_finish(authctxt, authctxt->method->name);
}

static void ssh_gssapi_userauth_error(Gssctxt *ctxt) {
	char *errstr;
	OM_uint32 maj,min;

	errstr=ssh_gssapi_last_error(ctxt,&maj,&min);
	if (errstr) {
		packet_start(SSH2_MSG_USERAUTH_GSSAPI_ERROR);
		packet_put_int(maj);
		packet_put_int(min);
		packet_put_cstring(errstr);
		packet_put_cstring("");
		packet_send();
		packet_write_wait();
		xfree(errstr);
	}
}

/*
 * Code common to gssapi-keyex and gssapi-with-mic userauth.
 *
 * Does authorization, figures out how to store delegated creds.
 */
static
void
userauth_gssapi_finish(Authctxt *authctxt, Gssctxt *gssctxt)
{
	char *local_user = NULL;
	gss_buffer_desc dispname;
	OM_uint32 major;

	if (*authctxt->user != '\0' &&
	    ssh_gssapi_userok(gssctxt, authctxt->user)) {

		/*
		 * If the client princ did not map to the requested
		 * username then we don't want to clobber existing creds
		 * for the user with the delegated creds.
		 */
		local_user = ssh_gssapi_localname(gssctxt);
		if (local_user == NULL ||
		    strcmp(local_user, authctxt->user) == 0)
			gssctxt->default_creds = 1; /* store creds as default */

		authctxt->method->authenticated = 
			do_pam_non_initial_userauth(authctxt);

	} else if (*authctxt->user == '\0') {
		/* Requested username == ""; derive username from princ name */
		if ((local_user = ssh_gssapi_localname(gssctxt)) == NULL)
			return;

		/* Changed username (from implicit, '') */
		userauth_user_svc_change(authctxt, local_user, NULL);

		gssctxt->default_creds = 1; /* store creds as default */

		authctxt->method->authenticated =
			do_pam_non_initial_userauth(authctxt);
	}

	if (local_user != NULL)
		xfree(local_user);

	if (*authctxt->user != '\0' && authctxt->method->authenticated != 0) {
		major = gss_display_name(&gssctxt->minor, gssctxt->src_name,
			    &dispname, NULL);
		if (major == GSS_S_COMPLETE) {
			log("Authorized principal %.*s, authenticated with "
			    "GSS mechanism %s, to: %s",
				dispname.length, (char *)dispname.value,
				ssh_gssapi_oid_to_name(gssctxt->actual_mech),
				authctxt->user);
		}
		(void) gss_release_buffer(&gssctxt->minor, &dispname);
	}
}

#if 0
/* Deprecated userauths -- should not be enabled */
Authmethod method_external = {
	"external-keyx",
	&options.gss_authentication,
	userauth_gssapi_keyex,
	NULL,	/* no abandon function */
	NULL,
	NULL,
	/* State counters */
	0, 0, 0, 0,
	/* State flags */
	0, 0, 0, 0, 0, 0
};

Authmethod method_gssapi = {
        "gssapi",
        &options.gss_authentication,
        userauth_gssapi,
	userauth_gssapi_abandon,
	NULL,
	NULL,
	/* State counters */
	0, 0, 0, 0,
	/* State flags */
	0, 0, 0, 0, 0, 0
};
#endif

Authmethod method_external = {
	"gssapi-keyex",
	&options.gss_authentication,
	userauth_gssapi_keyex,
	NULL,	/* no abandon function */
	NULL,
	NULL,
	/* State counters */
	0, 0, 0, 0,
	/* State flags */
	0, 0, 0, 0, 0, 0
};

Authmethod method_gssapi = {
        "gssapi-with-mic",
        &options.gss_authentication,
        userauth_gssapi,
	userauth_gssapi_abandon,
	NULL,
	NULL,
	/* State counters */
	0, 0, 0, 0,
	/* State flags */
	0, 0, 0, 0, 0, 0
};

#endif /* GSSAPI */
