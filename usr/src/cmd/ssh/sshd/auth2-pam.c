/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"

RCSID("$Id: auth2-pam.c,v 1.14 2002/06/28 16:48:12 mouring Exp $");

#ifdef USE_PAM
#include <security/pam_appl.h>

#include "ssh.h"
#include "ssh2.h"
#include "auth.h"
#include "auth-pam.h"
#include "auth-options.h"
#include "packet.h"
#include "xmalloc.h"
#include "dispatch.h"
#include "canohost.h"
#include "log.h"
#include "servconf.h"
#include "misc.h"

#ifdef HAVE_BSM
#include "bsmaudit.h"
#endif /* HAVE_BSM */

extern u_int utmp_len;
extern ServerOptions options;

extern Authmethod method_kbdint;
extern Authmethod method_passwd;

#define SSHD_PAM_KBDINT_SVC "sshd-kbdint"
/* Maximum attempts for changing expired password */
#define DEF_ATTEMPTS 3

static int do_pam_conv_kbd_int(int num_msg, 
    struct pam_message **msg, struct pam_response **resp, 
    void *appdata_ptr);
static void input_userauth_info_response_pam(int type,
					     u_int32_t seqnr,
					     void *ctxt);

static struct pam_conv conv2 = {
	do_pam_conv_kbd_int,
	NULL,
};

static void do_pam_kbdint_cleanup(pam_handle_t *pamh);
static void do_pam_kbdint(Authctxt *authctxt);

void
auth2_pam(Authctxt *authctxt)
{
	if (authctxt->user == NULL)
		fatal("auth2_pam: internal error: no user");
	if (authctxt->method == NULL)
		fatal("auth2_pam: internal error: no method");

	conv2.appdata_ptr = authctxt;
	new_start_pam(authctxt, &conv2);

	authctxt->method->method_data = NULL; /* freed in the conv func */
	dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE,
	    &input_userauth_info_response_pam);

	/*
	 * Since password userauth and keyboard-interactive userauth
	 * both use PAM, and since keyboard-interactive is so much
	 * better than password userauth, we should not allow the user
	 * to try password userauth after trying keyboard-interactive.
	 */
	if (method_passwd.enabled)
		*method_passwd.enabled = 0;

	do_pam_kbdint(authctxt);

	dispatch_set(SSH2_MSG_USERAUTH_INFO_RESPONSE, NULL);
}

static void
do_pam_kbdint(Authctxt *authctxt)
{
	int		 retval, retval2;
	pam_handle_t	*pamh = authctxt->pam->h;
	const char	*where = "authenticating";
	char		*text = NULL;

	debug2("Calling pam_authenticate()");
	retval = pam_authenticate(pamh,
	    options.permit_empty_passwd ? 0 :
	    PAM_DISALLOW_NULL_AUTHTOK);

	if (retval != PAM_SUCCESS)
		goto cleanup;

	debug2("kbd-int: pam_authenticate() succeeded");
	where = "authorizing";
	retval = pam_acct_mgmt(pamh, 0);

	if (retval == PAM_NEW_AUTHTOK_REQD) {
		if (authctxt->valid && authctxt->pw != NULL) {
			/* send password expiration warning */
			message_cat(&text,
			    gettext("Warning: Your password has expired,"
			    " please change it now."));
			packet_start(SSH2_MSG_USERAUTH_INFO_REQUEST);
			packet_put_cstring("");		/* name */
			packet_put_cstring(text);	/* instructions */
			packet_put_cstring("");		/* language, unused */
			packet_put_int(0);
			packet_send();
			packet_write_wait();
			debug("expiration message sent");
			if (text)
				xfree(text);
			/*
			 * wait for the response so it does not mix
			 * with the upcoming PAM conversation
			 */
			packet_read_expect(SSH2_MSG_USERAUTH_INFO_RESPONSE);
			/*
			 * Can't use temporarily_use_uid() and restore_uid()
			 * here because we need (euid == 0 && ruid == pw_uid)
			 * whereas temporarily_use_uid() arranges for
			 * (suid = 0 && euid == pw_uid && ruid == pw_uid).
			 */
			(void) setreuid(authctxt->pw->pw_uid, -1);
			debug2("kbd-int: changing expired password");
			where = "changing authentication tokens (password)";
			/*
			 * Depending on error returned from pam_chauthtok, we
			 * need to try to change password a few times before
			 * we error out and return.
			 */
			int tries = 0;
			while ((retval = pam_chauthtok(pamh,
			    PAM_CHANGE_EXPIRED_AUTHTOK)) != PAM_SUCCESS) {
				if (tries++ < DEF_ATTEMPTS) {
					if ((retval == PAM_AUTHTOK_ERR) ||
					    (retval == PAM_TRY_AGAIN)) {
						continue;
					}
				}
				break;
			}
			audit_sshd_chauthtok(retval, authctxt->pw->pw_uid,
				authctxt->pw->pw_gid);
			(void) setreuid(0, -1);
		} else {
			retval = PAM_PERM_DENIED;
		}
	}

	if (retval != PAM_SUCCESS)
		goto cleanup;

	authctxt->pam->state |= PAM_S_DONE_ACCT_MGMT;

	retval = finish_userauth_do_pam(authctxt);

	if (retval != PAM_SUCCESS)
		goto cleanup;

	/*
	 * PAM handle stays around so we can call pam_close_session()
	 * on it later.
	 */
	authctxt->method->authenticated = 1;
	debug2("kbd-int: success (pam->state == %x)", authctxt->pam->state);
	return;

cleanup:
	/*
	 * Check for abandonment and cleanup.  When kbdint is abandoned
	 * authctxt->pam->h is NULLed and by this point a new handle may
	 * be allocated.
	 */
	if (authctxt->pam->h != pamh) {
		log("Keyboard-interactive (PAM) userauth abandoned "
		    "while %s", where);
		if ((retval2 = pam_end(pamh, retval)) != PAM_SUCCESS) {
			log("Cannot close PAM handle after "
			    "kbd-int userauth abandonment[%d]: %.200s",
			    retval2, PAM_STRERROR(pamh, retval2));
		}
		authctxt->method->abandoned = 1;

		/*
		 * Avoid double counting; these are incremented in
		 * kbdint_pam_abandon() so that they reflect the correct
		 * count when userauth_finish() is called before
		 * unwinding the dispatch_run() loop, but they are
		 * incremented again in input_userauth_request() when
		 * the loop is unwound, right here.
		 */
		if (authctxt->method->abandons)
			authctxt->method->abandons--;
		if (authctxt->method->attempts)
			authctxt->method->attempts--;
	}
	else {
		/* Save error value for pam_end() */
		authctxt->pam->last_pam_retval = retval;
		log("Keyboard-interactive (PAM) userauth failed[%d] "
		    "while %s: %.200s", retval, where,
		    PAM_STRERROR(pamh, retval));
		/* pam handle can be reused elsewhere, so no pam_end() here */
	}

	return;
}

static int
do_pam_conv_kbd_int(int num_msg, struct pam_message **msg,
    struct pam_response **resp, void *appdata_ptr)
{
	int i, j;
	char *text;
	Convctxt *conv_ctxt;
	Authctxt *authctxt = (Authctxt *)appdata_ptr;

	if (!authctxt || !authctxt->method) {
		debug("Missing state during PAM conversation");
		return PAM_CONV_ERR;
	}

	conv_ctxt = xmalloc(sizeof(Convctxt));
	(void) memset(conv_ctxt, 0, sizeof(Convctxt));
	conv_ctxt->finished = 0;
	conv_ctxt->num_received = 0;
	conv_ctxt->num_expected = 0;
	conv_ctxt->prompts = xmalloc(sizeof(int) * num_msg);
	conv_ctxt->responses = xmalloc(sizeof(struct pam_response) * num_msg);
	(void) memset(conv_ctxt->responses, 0, sizeof(struct pam_response) * num_msg);

	text = NULL;
	for (i = 0, conv_ctxt->num_expected = 0; i < num_msg; i++) {
		int style = PAM_MSG_MEMBER(msg, i, msg_style);
		switch (style) {
		case PAM_PROMPT_ECHO_ON:
			debug2("PAM echo on prompt: %s",
				PAM_MSG_MEMBER(msg, i, msg));
			conv_ctxt->num_expected++;
			break;
		case PAM_PROMPT_ECHO_OFF:
			debug2("PAM echo off prompt: %s",
				PAM_MSG_MEMBER(msg, i, msg));
			conv_ctxt->num_expected++;
			break;
		case PAM_TEXT_INFO:
			debug2("PAM text info prompt: %s",
				PAM_MSG_MEMBER(msg, i, msg));
			message_cat(&text, PAM_MSG_MEMBER(msg, i, msg));
			break;
		case PAM_ERROR_MSG:
			debug2("PAM error prompt: %s",
				PAM_MSG_MEMBER(msg, i, msg));
			message_cat(&text, PAM_MSG_MEMBER(msg, i, msg));
			break;
		default:
			/* Capture all these messages to be sent at once */
			message_cat(&text, PAM_MSG_MEMBER(msg, i, msg));
			break;
		}
	}

	if (conv_ctxt->num_expected == 0 && text == NULL) {
		xfree(conv_ctxt->prompts);
		xfree(conv_ctxt->responses);
		xfree(conv_ctxt);
		return PAM_SUCCESS;
	}

	authctxt->method->method_data = (void *) conv_ctxt;

	packet_start(SSH2_MSG_USERAUTH_INFO_REQUEST);
	packet_put_cstring("");	/* Name */
	packet_put_cstring(text ? text : "");	/* Instructions */
	packet_put_cstring("");	/* Language */
	packet_put_int(conv_ctxt->num_expected);

	if (text)
		xfree(text);
	
	for (i = 0, j = 0; i < num_msg; i++) {
		int style = PAM_MSG_MEMBER(msg, i, msg_style);
		
		/* Skip messages which don't need a reply */
		if (style != PAM_PROMPT_ECHO_ON && style != PAM_PROMPT_ECHO_OFF)
			continue;
		
		conv_ctxt->prompts[j++] = i;
		packet_put_cstring(PAM_MSG_MEMBER(msg, i, msg));
		packet_put_char(style == PAM_PROMPT_ECHO_ON);
	}
	packet_send();
	packet_write_wait();

	/*
	 * Here the dispatch_run() loop is nested.  It should be unwound
	 * if keyboard-interactive userauth is abandoned (or restarted;
	 * same thing).
	 *
	 * The condition for breaking out of the nested dispatch_run() loop is
	 *     ((got kbd-int info reponse) || (kbd-int abandoned))
	 *
	 * conv_ctxt->finished is set in either of those cases.
	 *
	 * When abandonment is detected the conv_ctxt->finished is set as
	 * is conv_ctxt->abandoned, causing this function to signal
	 * userauth nested dispatch_run() loop unwinding and to return
	 * PAM_CONV_ERR;
	 */
	debug2("Nesting dispatch_run loop");
	dispatch_run(DISPATCH_BLOCK, &conv_ctxt->finished, appdata_ptr);
	debug2("Nested dispatch_run loop exited");

	if (conv_ctxt->abandoned) {
		authctxt->unwind_dispatch_loop = 1;
		xfree(conv_ctxt->prompts);
		xfree(conv_ctxt->responses);
		xfree(conv_ctxt);
		debug("PAM conv function returns PAM_CONV_ERR");
		return PAM_CONV_ERR;
	}

	if (conv_ctxt->num_received == conv_ctxt->num_expected) {
		*resp = conv_ctxt->responses;
		xfree(conv_ctxt->prompts);
		xfree(conv_ctxt);
		debug("PAM conv function returns PAM_SUCCESS");
		return PAM_SUCCESS;
	}

	debug("PAM conv function returns PAM_CONV_ERR");
	xfree(conv_ctxt->prompts);
	xfree(conv_ctxt->responses);
	xfree(conv_ctxt);
	return PAM_CONV_ERR;
}

static void
input_userauth_info_response_pam(int type, u_int32_t seqnr, void *ctxt)
{
	Authctxt *authctxt = ctxt;
	Convctxt *conv_ctxt;
	unsigned int nresp = 0, rlen = 0, i = 0;
	char *resp;

	if (authctxt == NULL)
		fatal("input_userauth_info_response_pam: no authentication context");

	/* Check for spurious/unexpected info response */
	if (method_kbdint.method_data == NULL) {
		debug("input_userauth_info_response_pam: no method context");
		return;
	}

	conv_ctxt = (Convctxt *) method_kbdint.method_data;

	nresp = packet_get_int();	/* Number of responses. */
	debug("got %d responses", nresp);


#if 0
	if (nresp != conv_ctxt->num_expected)
		fatal("%s: Received incorrect number of responses "
		    "(expected %d, received %u)", __func__, 
		    conv_ctxt->num_expected, nresp);
#endif

	if (nresp > 100)
		fatal("%s: too many replies", __func__);

	for (i = 0; i < nresp && i < conv_ctxt->num_expected ; i++) {
		int j = conv_ctxt->prompts[i];

		resp = packet_get_string(&rlen);
		if (i < conv_ctxt->num_expected) {
			conv_ctxt->responses[j].resp_retcode = PAM_SUCCESS;
			conv_ctxt->responses[j].resp = xstrdup(resp);
			conv_ctxt->num_received++;
		}
		xfree(resp);
	}

	if (nresp < conv_ctxt->num_expected)
		fatal("%s: too few replies (%d < %d)", __func__,
		    nresp, conv_ctxt->num_expected);

	/* XXX - This could make a covert channel... */
	if (nresp > conv_ctxt->num_expected)
		debug("Ignoring additional PAM replies");

	conv_ctxt->finished = 1;

	packet_check_eom();
}

#if 0
int
kbdint_pam_abandon_chk(Authctxt *authctxt, Authmethod *method)
{
	if (!method)
		return 0; /* fatal(), really; it'll happen somewhere else */

	if (!method->method_data)
		return 0;

	return 1;
}
#endif

void
kbdint_pam_abandon(Authctxt *authctxt, Authmethod *method)
{
	Convctxt *conv_ctxt;

	/*
	 * But, if it ever becomes desirable and possible to support
	 * kbd-int userauth abandonment, here's what must be done.
	 */
	if (!method)
		return;

	if (!method->method_data)
		return;

	conv_ctxt = (Convctxt *) method->method_data;

	/* dispatch_run() loop will exit */
	conv_ctxt->abandoned = 1;
	conv_ctxt->finished = 1;

	/*
	 * The method_data will be free in the corresponding, active
	 * conversation function
	 */
	method->method_data = NULL;

	/* update counts that can't be updated elsewhere */
	method->abandons++;
	method->attempts++;

	/* Finally, we cannot re-use the current current PAM handle */
	authctxt->pam->h = NULL;    /* Let the conv function cleanup */
}
#endif
