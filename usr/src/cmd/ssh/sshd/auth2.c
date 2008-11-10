/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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
RCSID("$OpenBSD: auth2.c,v 1.95 2002/08/22 21:33:58 markus Exp $");

#include "ssh2.h"
#include "xmalloc.h"
#include "packet.h"
#include "log.h"
#include "servconf.h"
#include "compat.h"
#include "misc.h"
#include "auth.h"
#include "dispatch.h"
#include "sshlogin.h"
#include "pathnames.h"

#ifdef HAVE_BSM
#include "bsmaudit.h"
extern adt_session_data_t *ah;
#endif /* HAVE_BSM */

#ifdef GSSAPI
#include "ssh-gss.h"
#endif

/* import */
extern ServerOptions options;
extern u_char *session_id2;
extern int session_id2_len;

Authctxt *x_authctxt = NULL;

/* methods */

extern Authmethod method_none;
extern Authmethod method_pubkey;
extern Authmethod method_passwd;
extern Authmethod method_kbdint;
extern Authmethod method_hostbased;
extern Authmethod method_external;
extern Authmethod method_gssapi;

static Authmethod *authmethods[] = {
	&method_none,
#ifdef GSSAPI
	&method_external,
	&method_gssapi,
#endif
	&method_pubkey,
	&method_passwd,
	&method_kbdint,
	&method_hostbased,
	NULL
};

/* protocol */

static void input_service_request(int, u_int32_t, void *);
static void input_userauth_request(int, u_int32_t, void *);

/* helper */
static Authmethod *authmethod_lookup(const char *);
static char *authmethods_get(void);
static char *authmethods_check_abandonment(Authctxt *authctxt,
					  Authmethod *method);
static void  authmethod_count_attempt(Authmethod *method);
/*static char *authmethods_get_kbdint(void);*/
int user_key_allowed(struct passwd *, Key *);
int hostbased_key_allowed(struct passwd *, const char *, char *, Key *);
static int   userauth_method_can_run(Authmethod *method);
static void  userauth_reset_methods(void);

/*
 * loop until authctxt->success == TRUE
 */

Authctxt *
do_authentication2(void)
{
	Authctxt *authctxt = authctxt_new();

	x_authctxt = authctxt;		/*XXX*/

#ifdef HAVE_BSM
	fatal_add_cleanup(audit_failed_login_cleanup, authctxt);
#endif /* HAVE_BSM */

	/* challenge-response is implemented via keyboard interactive */
	if (options.challenge_response_authentication)
		options.kbd_interactive_authentication = 1;
	if (options.pam_authentication_via_kbd_int)
		options.kbd_interactive_authentication = 1;

	dispatch_init(&dispatch_protocol_error);
	dispatch_set(SSH2_MSG_SERVICE_REQUEST, &input_service_request);
	dispatch_run(DISPATCH_BLOCK, &authctxt->success, authctxt);

	return (authctxt);
}

static void
input_service_request(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	u_int len;
	int acceptit = 0;
	char *service = packet_get_string(&len);
	packet_check_eom();

	if (authctxt == NULL)
		fatal("input_service_request: no authctxt");

	if (strcmp(service, "ssh-userauth") == 0) {
		if (!authctxt->success) {
			acceptit = 1;
			/* now we can handle user-auth requests */
			dispatch_set(SSH2_MSG_USERAUTH_REQUEST, &input_userauth_request);
		}
	}
	/* XXX all other service requests are denied */

	if (acceptit) {
		packet_start(SSH2_MSG_SERVICE_ACCEPT);
		packet_put_cstring(service);
		packet_send();
		packet_write_wait();
	} else {
		debug("bad service request %s", service);
		packet_disconnect("bad service request %s", service);
	}
	xfree(service);
}

static void
input_userauth_request(int type, u_int32_t seq, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Authmethod *m = NULL;
	char *user, *service, *method, *style = NULL;

	if (authctxt == NULL)
		fatal("input_userauth_request: no authctxt");

	user = packet_get_string(NULL);
	service = packet_get_string(NULL);
	method = packet_get_string(NULL);
	debug("userauth-request for user %s service %s method %s", user,
		service, method);
	debug("attempt %d initial attempt %d failures %d initial failures %d",
		authctxt->attempt, authctxt->init_attempt,
		authctxt->failures, authctxt->init_failures);

	m = authmethod_lookup(method);

	if ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	authctxt->attempt++;
	if (m != NULL && m->is_initial)
		authctxt->init_attempt++;

	if (authctxt->attempt == 1) {
		/* setup auth context */
		authctxt->pw = getpwnamallow(user);
		/* May want to abstract SSHv2 services someday */
		if (authctxt->pw && strcmp(service, "ssh-connection")==0) {
			/* enforced in userauth_finish() below */
			authctxt->valid = 1;
			debug2("input_userauth_request: setting up authctxt for %s", user);
		} else {
			log("input_userauth_request: illegal user %s", user);
		}
		setproctitle("%s", authctxt->pw ? user : "unknown");
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
		authctxt->style = style ? xstrdup(style) : NULL;
		userauth_reset_methods();
	} else {
		char *abandoned;

		/*
		 * Check for abandoned [multi-round-trip] userauths
		 * methods (e.g., kbdint).  Userauth method abandonment
		 * should be treated as userauth method failure and
		 * counted against max_auth_tries.
		 */
		abandoned = authmethods_check_abandonment(authctxt, m);

		if (abandoned != NULL &&
		    authctxt->failures > options.max_auth_tries) {
			/* userauth_finish() will now packet_disconnect() */
			userauth_finish(authctxt, abandoned);
			/* NOTREACHED */
		}

		/* Handle user|service changes, possibly packet_disconnect() */
		userauth_user_svc_change(authctxt, user, service);
	}

	authctxt->method = m;

	/* run userauth method, try to authenticate user */
	if (m != NULL && userauth_method_can_run(m)) {
		debug2("input_userauth_request: try method %s", method);

		m->postponed = 0;
		m->abandoned = 0;
		m->authenticated = 0;

		if (!m->is_initial ||
		    authctxt->init_failures < options.max_init_auth_tries)
			m->userauth(authctxt);

		authmethod_count_attempt(m);

		if (authctxt->unwind_dispatch_loop) {
			/*
			 * Method ran nested dispatch loop but was
			 * abandoned.  Cleanup and return without doing
			 * anything else; we're just unwinding the stack.
			 */
			authctxt->unwind_dispatch_loop = 0;
			goto done;
		}

		if (m->postponed)
			goto done; /* multi-round trip userauth not finished */

		if (m->abandoned) {
			/* multi-round trip userauth abandoned, log failure */
			auth_log(authctxt, 0, method, " ssh2");
			goto done;
		}
	}

	userauth_finish(authctxt, method);

done:
	xfree(service);
	xfree(user);
	xfree(method);
}

void
userauth_finish(Authctxt *authctxt, char *method)
{
	int authenticated, partial;

	if (authctxt == NULL)
		fatal("%s: missing context", __func__);

	/* unknown method handling -- must elicit userauth failure msg */
	if (authctxt->method == NULL) {
		authenticated = 0;
		partial = 0;
		goto done_checking;
	}

#ifndef USE_PAM
	/* Special handling for root (done elsewhere for PAM) */
	if (authctxt->method->authenticated &&
	    authctxt->pw != NULL && authctxt->pw->pw_uid == 0 &&
	    !auth_root_allowed(method))
		authctxt->method->authenticated = 0;
#endif /* USE_PAM */

#ifdef _UNICOS
	if (authctxt->method->authenticated &&
	    cray_access_denied(authctxt->user)) {
		authctxt->method->authenticated = 0;
		fatal("Access denied for user %s.",authctxt->user);
	}
#endif /* _UNICOS */

	partial = userauth_check_partial_failure(authctxt);
	authenticated = authctxt->method->authenticated;

#ifdef USE_PAM
	/*
	 * If the userauth method failed to complete PAM work then force
	 * partial failure.
	 */
	if (authenticated && !AUTHPAM_DONE(authctxt))
		partial = 1;
#endif /* USE_PAM */

	/*
	 * To properly support invalid userauth method names we set
	 * authenticated=0, partial=0 above and know that
	 * authctxt->method == NULL.
	 *
	 * No unguarded reference to authctxt->method allowed from here.
	 * Checking authenticated != 0 is a valid guard; authctxt->method
	 * MUST NOT be NULL if authenticated.
	 */
done_checking:
	if (!authctxt->valid && authenticated) {
		/*
		 * Should never happen -- if it does PAM's at fault
		 * but we need not panic, just treat as a failure.
		 */
		authctxt->method->authenticated = 0;
		authenticated = 0;
		log("Ignoring authenticated invalid user %s",
		    authctxt->user);
		auth_log(authctxt, 0, method, " ssh2");
	}

	/* Log before sending the reply */
	auth_log(authctxt, authenticated, method, " ssh2");

	if (authenticated && !partial) {

		/* turn off userauth */
		dispatch_set(SSH2_MSG_USERAUTH_REQUEST, &dispatch_protocol_ignore);
		packet_start(SSH2_MSG_USERAUTH_SUCCESS);
		packet_send();
		packet_write_wait();
		/* now we can break out */
		authctxt->success = 1;
	} else {
		char *methods;

		if (authctxt->method && authctxt->method->is_initial)
			authctxt->init_failures++;

		authctxt->method = NULL;

#ifdef USE_PAM
		/*
		 * Keep track of last PAM error (or PERM_DENIED) for BSM
		 * login failure auditing, which may run after the PAM
		 * state has been cleaned up.
		 */
		authctxt->pam_retval = AUTHPAM_ERROR(authctxt, PAM_PERM_DENIED);
#endif /* USE_PAM */

		if (authctxt->failures++ > options.max_auth_tries) {
#ifdef HAVE_BSM
			fatal_remove_cleanup(audit_failed_login_cleanup,
				authctxt);
			audit_sshd_login_failure(&ah, PAM_MAXTRIES,
			    authctxt->user);
#endif /* HAVE_BSM */
			packet_disconnect(AUTH_FAIL_MSG, authctxt->user);
		}

#ifdef _UNICOS
		if (strcmp(method, "password") == 0)
			cray_login_failure(authctxt->user, IA_UDBERR);
#endif /* _UNICOS */
		packet_start(SSH2_MSG_USERAUTH_FAILURE);

		/*
		 * If (partial) then authmethods_get() will return only
		 * required methods, likely only "keyboard-interactive;"
		 * (methods == NULL) implies failure, even if (partial == 1)
		 */
		methods = authmethods_get();
		packet_put_cstring(methods);
		packet_put_char((authenticated && partial && methods) ? 1 : 0);
		if (methods)
			xfree(methods);
		packet_send();
		packet_write_wait();
	}
}

/* get current user */

struct passwd*
auth_get_user(void)
{
	return (x_authctxt != NULL && x_authctxt->valid) ? x_authctxt->pw : NULL;
}

#define	DELIM	","

#if 0
static char *
authmethods_get_kbdint(void)
{
	Buffer b;
	int i;

	for (i = 0; authmethods[i] != NULL; i++) {
		if (strcmp(authmethods[i]->name, "keyboard-interactive") != 0)
			continue;
		return xstrdup(authmethods[i]->name);
	}
	return NULL;
}
#endif

void
userauth_user_svc_change(Authctxt *authctxt, char *user, char *service)
{
	/*
	 * NOTE:
	 *
	 * SSHv2 services should be abstracted and service changes during
	 * userauth should be supported as per the userauth draft.  In the PAM
	 * case, support for multiple SSHv2 services means that we have to
	 * format the PAM service name according to the SSHv2 service *and* the
	 * SSHv2 userauth being attempted ("passwd", "kbdint" and "other").
	 *
	 * We'll cross that bridge when we come to it.  For now disallow service
	 * changes during userauth if using PAM, but allow username changes.
	 */

	/* authctxt->service must == ssh-connection here */
	if (service != NULL && strcmp(service, authctxt->service) != 0) {
		packet_disconnect("Change of service not "
				  "allowed: %s and %s",
				  authctxt->service, service);
	}
	if (user != NULL && authctxt->user != NULL &&
	    strcmp(user, authctxt->user) == 0)
		return;

	/* All good; update authctxt */
	xfree(authctxt->user);
	authctxt->user = xstrdup(user);
	pwfree(&authctxt->pw);
	authctxt->pw = getpwnamallow(user);
	authctxt->valid = (authctxt->pw != NULL);

	/* Forget method state; abandon postponed userauths */
	userauth_reset_methods();
}

int
userauth_check_partial_failure(Authctxt *authctxt)
{
	int i;
	int required = 0;
	int sufficient = 0;

	/*
	 * v1 does not set authctxt->method
	 * partial userauth failure is a v2 concept
	 */
	if (authctxt->method == NULL)
		return 0;

	for (i = 0; authmethods[i] != NULL; i++) {
		if (authmethods[i]->required)
			required++;
		if (authmethods[i]->sufficient)
			sufficient++;
	}

	if (required == 0 && sufficient == 0)
		return !authctxt->method->authenticated;

	if (required == 1 && authctxt->method->required)
		return !authctxt->method->authenticated;

	if (sufficient && authctxt->method->sufficient)
		return !authctxt->method->authenticated;

	return 1;
}

int
userauth_method_can_run(Authmethod *method)
{
	if (method->not_again)
		return 0;

	return 1;
}

static
void
userauth_reset_methods(void)
{
	int i;

	for (i = 0; authmethods[i] != NULL; i++) {
		/* note: counters not reset */
		authmethods[i]->required = 0;
		authmethods[i]->sufficient = 0;
		authmethods[i]->authenticated = 0;
		authmethods[i]->not_again = 0;
		authmethods[i]->postponed = 0;
		authmethods[i]->abandoned = 0;
	}
}

void
userauth_force_kbdint(void)
{
	int i;

	for (i = 0; authmethods[i] != NULL; i++) {
		authmethods[i]->required = 0;
		authmethods[i]->sufficient = 0;
	}
	method_kbdint.required = 1;
}

/*
 * Check to see if a previously run multi-round trip userauth method has
 * been abandoned and call its cleanup function.
 *
 * Abandoned userauth method invocations are counted as userauth failures.
 */
static
char *
authmethods_check_abandonment(Authctxt *authctxt, Authmethod *method)
{
	int i;

	/* optimization: check current method first */
	if (method && method->postponed) {
		method->postponed = 0;
		if (method->abandon)
			method->abandon(authctxt, method);
		else
			method->abandons++;
		authctxt->failures++; /* abandonment -> failure */
		if (method->is_initial)
			authctxt->init_failures++;

		/*
		 * Since we check for abandonment whenever a userauth is
		 * requested we know only one method could have been
		 * in postponed state, so we can return now.
		 */
		return (method->name);
	}
	for (i = 0; authmethods[i] != NULL; i++) {
		if (!authmethods[i]->postponed)
			continue;

		/* some method was postponed and a diff one is being started */
		if (method != authmethods[i]) {
			authmethods[i]->postponed = 0;
			if (authmethods[i]->abandon)
				authmethods[i]->abandon(authctxt,
							authmethods[i]);
			else
				authmethods[i]->abandons++;
			authctxt->failures++;
			if (authmethods[i]->is_initial)
				authctxt->init_failures++;
			return (authmethods[i]->name); /* see above */
		}
	}

	return NULL;
}

static char *
authmethods_get(void)
{
	Buffer b;
	char *list;
	int i;
	int sufficient = 0;
	int required = 0;
	int authenticated = 0;
	int partial = 0;

	/*
	 * If at least one method succeeded partially then at least one
	 * authmethod will be required and only required methods should
	 * continue.
	 */
	for (i = 0; authmethods[i] != NULL; i++) {
		if (authmethods[i]->authenticated)
			authenticated++;
		if (authmethods[i]->required)
			required++;
		if (authmethods[i]->sufficient)
			sufficient++;
	}

	partial = (required + sufficient) > 0;

	buffer_init(&b);
	for (i = 0; authmethods[i] != NULL; i++) {
		if (strcmp(authmethods[i]->name, "none") == 0)
			continue;
		if (required && !authmethods[i]->required)
			continue;
		if (sufficient && !required && !authmethods[i]->sufficient)
			continue;
		if (authmethods[i]->not_again)
			continue;

		if (authmethods[i]->required) {
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			buffer_append(&b, authmethods[i]->name,
			    strlen(authmethods[i]->name));
			continue;
		}

		/*
		 * A method can be enabled (marked sufficient)
		 * dynamically provided that at least one other method
		 * has succeeded partially.
		 */
		if ((partial && authmethods[i]->sufficient) ||
		    (authmethods[i]->enabled != NULL &&
		    *(authmethods[i]->enabled) != 0)) {
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			buffer_append(&b, authmethods[i]->name,
			    strlen(authmethods[i]->name));
		}
	}
	buffer_append(&b, "\0", 1);
	list = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	return list;
}

static Authmethod *
authmethod_lookup(const char *name)
{
	int i;

	/*
	 * Method must be sufficient, required or enabled and must not
	 * be marked as not able to run again
	 */
	if (name != NULL)
		for (i = 0; authmethods[i] != NULL; i++)
			if (((authmethods[i]->sufficient ||
			      authmethods[i]->required) ||
			     (authmethods[i]->enabled != NULL &&
			      *(authmethods[i]->enabled) != 0)) &&
			    !authmethods[i]->not_again &&
			    strcmp(name, authmethods[i]->name) == 0)
				return authmethods[i];
	debug2("Unrecognized authentication method name: %s",
	    name ? name : "NULL");
	return NULL;
}

static void
authmethod_count_attempt(Authmethod *method)
{
	if (!method)
		fatal("Internal error in authmethod_count_attempt()");

	if (method->postponed)
		return;

	method->attempts++;

	if (method->abandoned)
		method->abandons++;
	else if (method->authenticated)
		method->successes++;
	else
		method->failures++;

	return;
}
