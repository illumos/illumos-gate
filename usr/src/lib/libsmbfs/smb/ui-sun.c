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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <netsmb/smb_keychain.h>

#define	MAXLINE 	127
#define	MAXPASSWD	256	/* from libc:getpass */

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

int
smb_get_authentication(
	char *dom, size_t domlen,
	char *usr, size_t usrlen,
	char *passwd, size_t passwdlen,
	const char *systemname, struct smb_ctx *ctx)
{
	char *npw;
	int error, i, kcask, kcerr;

	if (ctx->ct_flags & SMBCF_KCFOUND || ctx->ct_flags & SMBCF_KCBAD) {
		ctx->ct_flags &= ~SMBCF_KCFOUND;
	} else {
		ctx->ct_flags &= ~(SMBCF_KCFOUND | SMBCF_KCDOMAIN);

		/*
		 * 1st: try lookup using system name
		 */
		kcerr = smbfs_keychain_chk(systemname, usr);
		if (!kcerr) {
			/*
			 * Need passwd to be not empty for existing logic.
			 * The string here is arbitrary (a debugging hint)
			 * and will be replaced in the driver by the real
			 * password from the keychain.
			 */
			strcpy(passwd, "$KC_SYSTEM");
			ctx->ct_flags |= SMBCF_KCFOUND;
			if (smb_debug) {
				printf("found keychain entry for"
				    " server/user: %s/%s\n",
				    systemname, usr);
			}
			return (0);
		}

		/*
		 * 2nd: try lookup using domain name
		 */
		kcerr = smbfs_keychain_chk(dom, usr);
		if (!kcerr) {
			/* Need passwd to be not empty... (see above) */
			strcpy(passwd, "$KC_DOMAIN");
			ctx->ct_flags |= (SMBCF_KCFOUND | SMBCF_KCDOMAIN);
			if (smb_debug) {
				printf("found keychain entry for"
				    " domain/user: %s/%s\n",
				    dom, usr);
			}
			return (0);
		}
	}

	if (isatty(STDIN_FILENO)) { /* need command-line prompting? */
		if (passwd && passwd[0] == '\0') {
			npw = getpassphrase(dgettext(TEXT_DOMAIN, "Password:"));
			strncpy(passwd, npw, passwdlen);
		}
		return (0);
	}

	/*
	 * XXX: Ask the user for help, possibly via
	 * GNOME dbus or some such... (todo).
	 */
	smb_error(dgettext(TEXT_DOMAIN,
	    "Cannot prompt for a password when input is redirected."), 0);

	return (ENOTTY);
}

int
smb_browse(struct smb_ctx *ctx, int anon)
{
	/*
	 * Let user pick a share.
	 * Not supported.
	 */
	return (EINTR);
}
