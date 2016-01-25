/*
 * Copyright (c) 2000 Damien Miller.  All rights reserved.
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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "includes.h"

#ifdef USE_PAM
#include "xmalloc.h"
#include "log.h"
#include "auth.h"
#include "auth-options.h"
#include "auth-pam.h"
#include "buffer.h"
#include "servconf.h"
#include "canohost.h"
#include "compat.h"
#include "misc.h"
#include "sshlogin.h"
#include "ssh-gss.h"

#include <security/pam_appl.h>

extern char *__progname;

extern u_int utmp_len;
extern ServerOptions options;

extern Authmethod method_kbdint;

RCSID("$Id: auth-pam.c,v 1.54 2002/07/28 20:24:08 stevesk Exp $");

#define NEW_AUTHTOK_MSG \
	"Warning: Your password has expired, please change it now."

/* PAM conversation for non-interactive userauth methods */
static int do_pam_conversation(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr);

static void do_pam_cleanup_proc(void *context);

static char *get_method_name(Authctxt *authctxt);

/* PAM conversation for non-interactive userauth methods */
static struct pam_conv conv = {
	(int (*)())do_pam_conversation,
	NULL
};
static char *__pam_msg = NULL;

static
char *
get_method_name(Authctxt *authctxt)
{
	if (!authctxt)
		return "(unknown)";

	if (!compat20)
		return (authctxt->v1_auth_name) ? authctxt->v1_auth_name :
						  "(sshv1-unknown)";

	if (!authctxt->method || !authctxt->method->name)
			return "(sshv2-unknown)";

	return authctxt->method->name;
}

char *
derive_pam_service_name(Authmethod *method)
{
	char *svcname = xmalloc(BUFSIZ);

	/*
	 * If PamServiceName is set we use that for everything, including
	 * SSHv1
	 */
	if (options.pam_service_name != NULL) {
		(void) strlcpy(svcname, options.pam_service_name, BUFSIZ);
		return (svcname);
	}

	if (compat20 && method) {
		char *method_name = method->name;

		if (!method_name)
			fatal("Userauth method unknown while starting PAM");

		/*
		 * For SSHv2 we use "sshd-<userauth name>
		 * The "sshd" prefix can be changed via the PAMServicePrefix
		 * sshd_config option.
		 */
		if (strcmp(method_name, "none") == 0) {
			snprintf(svcname, BUFSIZ, "%s-none",
			    options.pam_service_prefix);
		}
		if (strcmp(method_name, "password") == 0) {
			snprintf(svcname, BUFSIZ, "%s-password",
			    options.pam_service_prefix);
		}
		if (strcmp(method_name, "keyboard-interactive") == 0) {
			/* "keyboard-interactive" is too long, shorten it */
			snprintf(svcname, BUFSIZ, "%s-kbdint",
			    options.pam_service_prefix);
		}
		if (strcmp(method_name, "publickey") == 0) {
			/* "publickey" is too long, shorten it */
			snprintf(svcname, BUFSIZ, "%s-pubkey",
			    options.pam_service_prefix);
		}
		if (strcmp(method_name, "hostbased") == 0) {
			/* "hostbased" can't really be shortened... */
			snprintf(svcname, BUFSIZ, "%s-hostbased",
			    options.pam_service_prefix);
		}
		if (strncmp(method_name, "gss", 3) == 0) {
			/* "gss" is too short, elongate it */
			snprintf(svcname, BUFSIZ, "%s-gssapi",
			    options.pam_service_prefix);
		}
		return svcname;
	} else {
		/* SSHv1 doesn't get to be so cool */
		snprintf(svcname, BUFSIZ, "%s-v1",
		    options.pam_service_prefix);
	}
	return svcname;
}

void
new_start_pam(Authctxt *authctxt, struct pam_conv *conv)
{
	int		retval;
	pam_handle_t	*pamh;
	const char	*rhost;
	char		*svc;
	char		*user = NULL;
	pam_stuff	*pam;

	if (authctxt == NULL)
		fatal("Internal error during userauth");

	if (compat20 && authctxt->method == NULL)
		fatal("Userauth method unknown while starting PAM");

	/* PAM service selected here */
	svc = derive_pam_service_name(authctxt->method);
	debug2("Starting PAM service %s for method %s", svc,
		get_method_name(authctxt));

	if (authctxt->user != NULL)
		user = authctxt->user;

	/* Cleanup previous PAM state */
	if (authctxt->pam != NULL) {
		fatal_remove_cleanup(&do_pam_cleanup_proc, authctxt->pam);
		do_pam_cleanup_proc(authctxt->pam);
	}

	pam = xmalloc(sizeof(pam_stuff));
	(void) memset(pam, 0, sizeof(pam_stuff));

	/*
	 * pam->last_pam_retval has to be and is considered
	 * along with pam->state.
	 *
	 * pam->state = 0; -> no PAM auth, account, etc, work
	 * done yet.  (Set by memset() above.)
	 *
	 * pam->last_pam_retval = PAM_SUCCESS; -> meaningless at
	 * this point.
	 *
	 * See finish_userauth_do_pam() below.
	 */
	pam->authctxt = authctxt;
	pam->last_pam_retval = PAM_SUCCESS;

	authctxt->pam = pam;

	/* Free any previously stored text/error PAM prompts */
	if (__pam_msg) {
		xfree(__pam_msg);
		__pam_msg = NULL;
	}

	if ((retval = pam_start(svc, user, conv, &pamh)) != PAM_SUCCESS) {
		fatal("PAM initialization failed during %s userauth",
			get_method_name(authctxt));
	}

	free(svc);

	fatal_add_cleanup((void (*)(void *)) &do_pam_cleanup_proc,
			  (void *) authctxt->pam);

	rhost = get_remote_name_or_ip(utmp_len, options.verify_reverse_mapping);
	if ((retval = pam_set_item(pamh, PAM_RHOST, rhost)) != PAM_SUCCESS) {
		(void) pam_end(pamh, retval);
		fatal("Could not set PAM_RHOST item during %s userauth",
			get_method_name(authctxt));
	}

	if ((retval = pam_set_item(pamh, PAM_TTY, "sshd")) != PAM_SUCCESS) {
		(void) pam_end(pamh, retval);
		fatal("Could not set PAM_TTY item during %s userauth",
			get_method_name(authctxt));
	}

	if (authctxt->cuser != NULL) 
		if ((retval = pam_set_item(pamh, PAM_AUSER, authctxt->cuser)) != PAM_SUCCESS) {
			(void) pam_end(pamh, retval);
			fatal("Could not set PAM_AUSER item during %s userauth",
				get_method_name(authctxt));
		}

	authctxt->pam->h = pamh;
}

/*
 * To be called from userauth methods, directly (as in keyboard-interactive) or
 * indirectly (from auth_pam_password() or from do_pam_non_initial_userauth().
 *
 * The caller is responsible for calling new_start_pam() first.
 *
 * PAM state is not cleaned up here on error.  This is left to subsequent calls
 * to new_start_pam() or to the cleanup function upon authentication error.
 */
int
finish_userauth_do_pam(Authctxt *authctxt)
{
	int retval;
	char *user, *method;

	/* Various checks; fail gracefully */
	if (authctxt == NULL || authctxt->pam == NULL)
		return PAM_SYSTEM_ERR;	/* shouldn't happen */

	if (compat20) {
		if (authctxt->method == NULL || authctxt->method->name == NULL)
			return PAM_SYSTEM_ERR;	/* shouldn't happen */
		method = authctxt->method->name;
	} else if ((method = authctxt->v1_auth_name) == NULL)
		return PAM_SYSTEM_ERR;	/* shouldn't happen */

	if (AUTHPAM_DONE(authctxt))
		return PAM_SYSTEM_ERR;	/* shouldn't happen */

	if (!(authctxt->pam->state & PAM_S_DONE_ACCT_MGMT)) {
		retval = pam_acct_mgmt(authctxt->pam->h, 0);
		authctxt->pam->last_pam_retval = retval;
		if (retval == PAM_NEW_AUTHTOK_REQD) {
			userauth_force_kbdint();
			return retval;
		}
		if (retval != PAM_SUCCESS)
			return retval;
		authctxt->pam->state |= PAM_S_DONE_ACCT_MGMT;
	}

	/*
	 * Handle PAM_USER change, if any.
	 *
	 * We do this before pam_open_session() because we need the PAM_USER's
	 * UID for:
	 *
	 * a) PermitRootLogin checking
	 * b) to get at the lastlog entry before pam_open_session() updates it.
	 */
	retval = pam_get_item(authctxt->pam->h, PAM_USER, (void **) &user);
	if (retval != PAM_SUCCESS) {
		fatal("PAM failure: pam_get_item(PAM_USER) "
		      "returned %d: %.200s", retval,
		      PAM_STRERROR(authctxt->pam->h, retval));
	}

	if (user == NULL || *user == '\0') {
		debug("PAM set NULL PAM_USER");
		return PAM_PERM_DENIED;
	}

	if (strcmp(user, authctxt->user) != 0) {
		log("PAM changed the SSH username");
		pwfree(&authctxt->pw);
		authctxt->pw = getpwnamallow(user);
		authctxt->valid = (authctxt->pw != NULL);
		xfree(authctxt->user);
		authctxt->user = xstrdup(user);
	}

	if (!authctxt->valid) {
		debug2("PAM set PAM_USER to unknown user");
		/*
		 * Return success, userauth_finish() will catch
		 * this and send back a failure message.
		 */
		return PAM_SUCCESS;
	}

	/* Check PermitRootLogin semantics */
	if (authctxt->pw->pw_uid == 0 && !auth_root_allowed(method))
		return PAM_PERM_DENIED;

	if (!(authctxt->pam->state & PAM_S_DONE_SETCRED)) {
		retval = pam_setcred(authctxt->pam->h,
				     PAM_ESTABLISH_CRED);
		authctxt->pam->last_pam_retval = retval;
		if (retval != PAM_SUCCESS)
			return retval;
		authctxt->pam->state |= PAM_S_DONE_SETCRED;

#ifdef GSSAPI
		/*
		 * Store GSS-API delegated creds after pam_setcred(), which may
		 * have set the current credential store.
		 */
		ssh_gssapi_storecreds(NULL, authctxt);
#endif /* GSSAPI */
	}

	/*
	 * On Solaris pam_unix_session.so updates the lastlog, but does
	 * not converse a PAM_TEXT_INFO message about it.  So we need to
	 * fetch the lastlog entry here and save it for use later.
	 */
	authctxt->last_login_time =
		get_last_login_time(authctxt->pw->pw_uid,
			authctxt->pw->pw_name,
			authctxt->last_login_host,
			sizeof(authctxt->last_login_host));

	if (!(authctxt->pam->state & PAM_S_DONE_OPEN_SESSION)) {
		retval = pam_open_session(authctxt->pam->h, 0);
		authctxt->pam->last_pam_retval = retval;
		if (retval != PAM_SUCCESS)
			return retval;
		authctxt->pam->state |= PAM_S_DONE_OPEN_SESSION;
	}

	/*
	 * All PAM work done successfully.
	 *
	 * PAM handle stays around so we can call pam_close_session() on
	 * it later.
	 */
	return PAM_SUCCESS;
}

/*
 * PAM conversation function for non-interactive userauth methods that
 * really cannot do any prompting.  Password userauth and CHANGEREQ can
 * always set the PAM_AUTHTOK and PAM_OLDAUTHTOK items to avoid
 * conversation (and if they do and nonetheless some module tries to
 * converse, then password userauth / CHANGEREQ MUST fail).
 *
 * Except, PAM_TEXT_INFO and PAM_ERROR_MSG prompts can be squirelled
 * away and shown to the user later.
 *
 * Keyboard-interactive userauth has its own much more interesting
 * conversation function.
 *
 */
static int
do_pam_conversation(int num_msg, const struct pam_message **msg,
	struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *reply;
	int count;

	/* PAM will free this later */
	reply = xmalloc(num_msg * sizeof(*reply));

	(void) memset(reply, 0, num_msg * sizeof(*reply));

	for (count = 0; count < num_msg; count++) {
		/*
		 * We can't use stdio yet, queue messages for 
		 * printing later
		 */
		switch(PAM_MSG_MEMBER(msg, count, msg_style)) {
		case PAM_PROMPT_ECHO_ON:
			xfree(reply);
			return PAM_CONV_ERR;
		case PAM_PROMPT_ECHO_OFF:
			xfree(reply);
			return PAM_CONV_ERR;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			if (PAM_MSG_MEMBER(msg, count, msg) != NULL) {
				message_cat(&__pam_msg, 
				    PAM_MSG_MEMBER(msg, count, msg));
			}
			reply[count].resp = xstrdup("");
			reply[count].resp_retcode = PAM_SUCCESS;
			break;
		default:
			xfree(reply);
			return PAM_CONV_ERR;
		}
	}

	*resp = reply;

	return PAM_SUCCESS;
}

/* Called at exit to cleanly shutdown PAM */
static void
do_pam_cleanup_proc(void *context)
{
	int pam_retval;
	pam_stuff *pam = (pam_stuff *) context;

	if (pam == NULL)
		return;

	if (pam->authctxt != NULL && pam->authctxt->pam == pam) {
		pam->authctxt->pam_retval = pam->last_pam_retval;
		pam->authctxt->pam = NULL;
		pam->authctxt = NULL;
	}

	if (pam->h == NULL)
		return;

	/*
	 * We're in fatal_cleanup() or not in userauth or without a
	 * channel -- can't converse now, too bad.
	 */
	pam_retval = pam_set_item(pam->h, PAM_CONV, NULL);
	if (pam_retval != PAM_SUCCESS) {
		log("Cannot remove PAM conv, close session or delete creds[%d]: %.200s",
			pam_retval, PAM_STRERROR(pam->h, pam_retval));
		goto cleanup;
	}

	if (pam->state & PAM_S_DONE_OPEN_SESSION) {
		pam_retval = pam_close_session(pam->h, 0);
		if (pam_retval != PAM_SUCCESS)
			log("Cannot close PAM session[%d]: %.200s",
			    pam_retval, PAM_STRERROR(pam->h, pam_retval));
	}

	if (pam->state & PAM_S_DONE_SETCRED) {
		pam_retval = pam_setcred(pam->h, PAM_DELETE_CRED);
		if (pam_retval != PAM_SUCCESS)
			debug("Cannot delete credentials[%d]: %.200s", 
			    pam_retval, PAM_STRERROR(pam->h, pam_retval));
	}

cleanup:

	/* Use the previous PAM result, if not PAM_SUCCESS for pam_end() */
	if (pam->last_pam_retval != PAM_SUCCESS)
		pam_retval = pam_end(pam->h, pam->last_pam_retval);
	else if (pam_retval != PAM_SUCCESS)
		pam_retval = pam_end(pam->h, pam_retval);
	else
		pam_retval = pam_end(pam->h, PAM_ABORT);

	if (pam_retval != PAM_SUCCESS)
		log("Cannot release PAM authentication[%d]: %.200s",
		    pam_retval, PAM_STRERROR(pam->h, pam_retval));

	xfree(pam);
}

/* Attempt password authentation using PAM */
int
auth_pam_password(Authctxt *authctxt, const char *password)
{
	int retval;

	/* Ensure we have a fresh PAM handle / state */
	new_start_pam(authctxt, &conv);

	retval = pam_set_item(authctxt->pam->h, PAM_AUTHTOK, password);
	if (retval != PAM_SUCCESS) {
		authctxt->pam->last_pam_retval = retval;
		return 1;
	}

	retval = pam_authenticate(authctxt->pam->h,
			options.permit_empty_passwd ?  0 :
			PAM_DISALLOW_NULL_AUTHTOK);

	if (retval != PAM_SUCCESS) {
		authctxt->pam->last_pam_retval = retval;
		return 0;
	}

	if ((retval = finish_userauth_do_pam(authctxt)) != PAM_SUCCESS)
		return 0;

	if (authctxt->method)
		authctxt->method->authenticated = 1;	/* SSHv2 */

	return 1;
}

int
do_pam_non_initial_userauth(Authctxt *authctxt)
{
	new_start_pam(authctxt, NULL);
	return (finish_userauth_do_pam(authctxt) == PAM_SUCCESS);
}

/* Cleanly shutdown PAM */
void finish_pam(Authctxt *authctxt)
{
	fatal_remove_cleanup(&do_pam_cleanup_proc, authctxt->pam);
	do_pam_cleanup_proc(authctxt->pam);
}

static
char **
find_env(char **env, char *var)
{
	char **p;
	int len;

	if (strchr(var, '=') == NULL)
		len = strlen(var);
	else
		len = (strchr(var, '=') - var) + 1;

	for ( p = env ; p != NULL && *p != NULL ; p++ ) {
		if (strncmp(*p, var, len) == 0)
			return (p);
	}

	return (NULL);
}

/* Return list of PAM environment strings */
char **
fetch_pam_environment(Authctxt *authctxt)
{
#ifdef HAVE_PAM_GETENVLIST
	char	**penv;

	if (authctxt == NULL || authctxt->pam == NULL ||
	    authctxt->pam->h == NULL)
		return (NULL);

	penv = pam_getenvlist(authctxt->pam->h);

	return (penv);
#else /* HAVE_PAM_GETENVLIST */
	return(NULL);
#endif /* HAVE_PAM_GETENVLIST */
}

void free_pam_environment(char **env)
{
	int i;

	if (env != NULL) {
		for (i = 0; env[i] != NULL; i++)
			xfree(env[i]);
	}

	xfree(env);
}

/* Print any messages that have been generated during authentication */
/* or account checking to stderr */
void print_pam_messages(void)
{
	if (__pam_msg != NULL)
		(void) fputs(__pam_msg, stderr);
}

/* Append a message to buffer */
void message_cat(char **p, const char *a)
{
	char *cp;
	size_t new_len;

	new_len = strlen(a);

	if (*p) {
		size_t len = strlen(*p);

		*p = xrealloc(*p, new_len + len + 2);
		cp = *p + len;
	} else
		*p = cp = xmalloc(new_len + 2);

	(void) memcpy(cp, a, new_len);
	cp[new_len] = '\n';
	cp[new_len + 1] = '\0';
}

#endif /* USE_PAM */
