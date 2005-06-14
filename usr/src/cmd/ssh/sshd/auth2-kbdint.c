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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: auth2-kbdint.c,v 1.2 2002/05/31 11:35:15 markus Exp $");

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "packet.h"
#include "auth.h"
#include "log.h"
#include "servconf.h"
#include "xmalloc.h"

/* import */
extern ServerOptions options;

static void
userauth_kbdint(Authctxt *authctxt)
{
	char *lang, *devs;

	if (!authctxt || !authctxt->method)
		fatal("%s: missing contex", __func__);

	lang = packet_get_string(NULL);
	devs = packet_get_string(NULL);
	packet_check_eom();

	debug("keyboard-interactive devs %s", devs);

#ifdef USE_PAM
	if (options.pam_authentication_via_kbd_int)
		auth2_pam(authctxt);
#else
	if (options.challenge_response_authentication)
		auth2_challenge(authctxt, devs);
#endif /* USE_PAM */
	xfree(devs);
	xfree(lang);
#ifdef HAVE_CYGWIN
	if (check_nt_auth(0, authctxt->pw) == 0) {
		authctxt->method->authenticated = 0;
		return;
	}
#endif
	return;
}

#if 0
static int
userauth_kbdint_abandon_chk(Authctxt *authctxt, Authmethod *method)
{
#ifdef USE_PAM
	return kbdint_pam_abandon_chk(authctxt, method);
#endif /* USE_PAM */
	if (method->method_data || method->postponed)
		return 1;

	return 0;
}
#endif

static void
userauth_kbdint_abandon(Authctxt *authctxt, Authmethod *method)
{
#ifdef USE_PAM
	kbdint_pam_abandon(authctxt, method);
#else
	auth2_challenge_abandon(authctxt);
#endif /* USE_PAM */
}

Authmethod method_kbdint = {
	"keyboard-interactive",
	&options.kbd_interactive_authentication,
	userauth_kbdint,
	userauth_kbdint_abandon,
	NULL, NULL,	    /* method data and historical data */
	1,		    /* initial userauth */
	0, 0, 0,	    /* counters */
	0, 0, 0, 0, 0, 0    /* state */
};
