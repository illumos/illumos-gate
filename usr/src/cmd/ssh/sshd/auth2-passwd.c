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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "includes.h"
RCSID("$OpenBSD: auth2-passwd.c,v 1.2 2002/05/31 11:35:15 markus Exp $");

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "xmalloc.h"
#include "packet.h"
#include "log.h"
#include "auth.h"
#include "servconf.h"

/* import */
extern ServerOptions options;

static void
userauth_passwd(Authctxt *authctxt)
{
	char *password;
	int change;
	u_int len;

	if (!authctxt || !authctxt->method)
		fatal("%s: missing context", __func__);

	change = packet_get_char();
	if (change)
		log("password change not supported");
	password = packet_get_string(&len);
	packet_check_eom();
	if (
#ifdef HAVE_CYGWIN
	    check_nt_auth(1, authctxt->pw) &&
#endif
	    auth_password(authctxt, password) == 1) {
		authctxt->method->authenticated = 1;
	}
	memset(password, 0, len);
	xfree(password);
}

Authmethod method_passwd = {
	"password",
	&options.password_authentication,
	userauth_passwd,
	NULL,		    /* no abandon function */
	NULL, NULL,	    /* method data and hist data */
	1,		    /* initial userauth */
	0, 0, 0,	    /* counters */
	0, 0, 0, 0, 0, 0    /* state */
};
