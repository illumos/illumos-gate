/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: login.c,v 1.8 2004/03/19 01:49:48 lindak Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <err.h>
#include <libintl.h>

#include <netsmb/smb_lib.h>
#include <netsmb/smb_keychain.h>

#include "common.h"

/* defaults */
static char def_dom[256];
static char def_usr[256];
static char tmp_arg[256];


/*
 * Parse the string: domuser, which may be any of:
 * "user@domain" or "domain/user" or "domain\\user"
 * and return pointers to the domain and user parts.
 * Modifies the string domuser in-place.  Returned
 * string pointers are within the string domusr.
 */
int
smbfs_parse_domuser(char *domuser, char **dom, char **usr)
{
	const char sep[] = "@/\\";
	char sc, *p, *s1, *s2;

	p = strpbrk(domuser, sep);
	if (p == NULL) {
		/* No separators - whole string is the user. */
		*dom = NULL;
		*usr = domuser;
		return (0);
	}

	/* Have two strings. */
	s1 = domuser;
	sc = *p;	/* Save the sep. char */
	*p++ = '\0';	/* zap it */
	s2 = p;

	/* Enforce just one separator */
	p = strpbrk(s2, sep);
	if (p)
		return (-1);

	/*
	 * Now, which order are they?
	 * "user@domain" or "domain/user"
	 */
	if (sc == '@') {
		*usr = s1;
		*dom = s2;
	} else {
		*dom = s1;
		*usr = s2;
	}

	return (0);
}

void
login_usage(void)
{
	printf(gettext("usage: smbutil login [-c] [[domain/]user]\n"));
	printf(gettext("       smbutil login [-c] [user[@domain]]\n"));
	exit(1);
}

int
cmd_login(int argc, char *argv[])
{
	static char prompt[64];
	char *dom, *usr, *pass;
	int err, opt;
	int check = 0;

	while ((opt = getopt(argc, argv, "c")) != EOF) {
		switch (opt) {

		case 'c':	/* smbutil login -c ... */
			check = 1;
			break;

		default:
			login_usage();
			break;
		}
	}

	dom = usr = NULL;
	if (optind < argc) {
		strcpy(tmp_arg, argv[optind]);
		err = smbfs_parse_domuser(tmp_arg, &dom, &usr);
		if (err)
			errx(1, gettext("failed to parse %s"), argv[optind]);
		optind++;
	}
	if (optind != argc)
		login_usage();

	if (dom == NULL || usr == NULL) {
		err = smbfs_default_dom_usr(NULL, NULL,
		    def_dom, sizeof (def_dom),
		    def_usr, sizeof (def_usr));
		if (err)
			errx(1, gettext("failed to get defaults"));
	}
	if (dom == NULL)
		dom = def_dom;
	else
		nls_str_upper(dom, dom);
	if (usr == NULL)
		usr = def_usr;

	if (check) {
		err = smbfs_keychain_chk(dom, usr);
		if (!err)
			printf(gettext("Keychain entry exists.\n"));
		else
			printf(gettext("Keychain entry not found.\n"));
		return (0);
	}

	snprintf(prompt, sizeof (prompt),
	    gettext("Password for %s/%s:"), dom, usr);
	pass = getpassphrase(prompt);

	err = smbfs_keychain_add((uid_t)-1, dom, usr, pass);
	if (err)
		errx(1, gettext("failed to add keychain entry"));

	return (0);
}


void
logout_usage(void)
{
	printf(gettext("usage: smbutil logout [[domain/]user]\n"));
	printf(gettext("       smbutil logout [user[@domain]]\n"));
	printf(gettext("       smbutil logout -a\n"));
	exit(1);
}

int
cmd_logout(int argc, char *argv[])
{
	char *dom, *usr;
	int err, opt;

	while ((opt = getopt(argc, argv, "a")) != EOF) {
		switch (opt) {

		case 'a':	/* smbutil logout -a */
			if (optind != argc)
				logout_usage();
			err = smbfs_keychain_del_owner();
			if (err)
				errx(1,
gettext("failed to delete keychain entries"));
			return (0);

		default:
			logout_usage();
			break;
		}
	}

	/* This part is like login. */
	dom = usr = NULL;
	if (optind < argc) {
		strcpy(tmp_arg, argv[optind]);
		err = smbfs_parse_domuser(tmp_arg, &dom, &usr);
		if (err)
			errx(1, gettext("failed to parse %s"), argv[optind]);
		optind++;
	}
	if (optind != argc)
		logout_usage();

	if (dom == NULL || usr == NULL) {
		err = smbfs_default_dom_usr(NULL, NULL,
		    def_dom, sizeof (def_dom),
		    def_usr, sizeof (def_usr));
		if (err)
			errx(1, gettext("failed to get defaults"));
	}
	if (dom == NULL)
		dom = def_dom;
	else
		nls_str_upper(dom, dom);
	if (usr == NULL)
		usr = def_usr;

	err = smbfs_keychain_del((uid_t)-1, dom, usr);
	if (err)
		errx(1, gettext("failed to delete keychain entry"));

	return (0);
}


void
logoutall_usage(void)
{
	printf(gettext("usage: smbutil logoutall\n"));
	exit(1);
}

int
cmd_logoutall(int argc, char *argv[])
{
	int err;

	if (optind != argc)
		logoutall_usage();

	err = smbfs_keychain_del_everyone();
	if (err == EPERM) {
		errx(1,
gettext("You must have super-user privileges to use this sub-command\n"));
	}
	if (err) {
		errx(1, gettext("Failed to delete all keychain entries: %s\n"),
		    smb_strerror(err));
	}

	return (0);
}
