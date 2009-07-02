/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Routines for interacting with the user to get credentials
 * (workgroup/domain, username, password, etc.)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <libintl.h>
#include <ctype.h>

#include <netsmb/smb_lib.h>
#include "private.h"
#include "ntlm.h"

#if 0 /* not yet */
#define	MAXLINE 	127
static void
smb_tty_prompt(char *prmpt,
	char *buf, size_t buflen)
{
	char temp[MAXLINE+1];
	char *cp;
	int ch;

	memset(temp, 0, sizeof (temp));

	fprintf(stderr, "%s", prmpt);
	cp = temp;
	while ((ch = getc(stdin)) != EOF) {
		if (ch == '\n' || ch == '\r')
			break;
		if (isspace(ch) || iscntrl(ch))
			continue;
		*cp++ = ch;
		if (cp == &temp[MAXLINE])
			break;
	}

	/* If input empty, accept default. */
	if (cp == temp)
		return;

	/* Use input as new value. */
	strncpy(buf, temp, buflen);
}
#endif /* not yet */

/*
 * Prompt for a new password after auth. failure.
 * (and maybe new user+domain, but not yet)
 */
int
smb_get_authentication(struct smb_ctx *ctx)
{
	char *npw;
	int err;

	/*
	 * If we're getting a password, we must be doing
	 * some kind of NTLM, possibly after a failure to
	 * authenticate using Kerberos.  Turn off krb5.
	 */
	ctx->ct_authflags &= ~SMB_AT_KRB5;

	if (ctx->ct_flags & SMBCF_KCFOUND) {
		/* Tried a keychain hash and failed. */
		/* XXX: delete the KC entry? */
		ctx->ct_flags |= SMBCF_KCBAD;
	}

	if (ctx->ct_flags & SMBCF_NOPWD)
		return (ENOTTY);

	if (isatty(STDIN_FILENO)) {

		/* Need command-line prompting. */
		npw = getpassphrase(dgettext(TEXT_DOMAIN, "Password:"));
		if (npw == NULL)
			return (EINTR);
		memset(ctx->ct_password, 0, sizeof (ctx->ct_password));
		strlcpy(ctx->ct_password, npw, sizeof (ctx->ct_password));
	} else {

		/*
		 * XXX: Ask the user for help, possibly via
		 * GNOME dbus or some such... (todo).
		 */
		smb_error(dgettext(TEXT_DOMAIN,
	"Cannot prompt for a password when input is redirected."), 0);
		return (ENOTTY);
	}

	/*
	 * Recompute the password hashes.
	 */
	if (ctx->ct_password[0]) {
		err = ntlm_compute_lm_hash(ctx->ct_lmhash, ctx->ct_password);
		if (err != 0)
			return (err);
		err = ntlm_compute_nt_hash(ctx->ct_nthash, ctx->ct_password);
		if (err != 0)
			return (err);
	}

	return (0);
}

/*ARGSUSED*/
int
smb_browse(struct smb_ctx *ctx, int anon)
{
	/*
	 * Let user pick a share.
	 * Not supported.
	 */
	return (EINTR);
}
