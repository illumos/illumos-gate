/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <locale.h>
#include <libintl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pkgtrans.h>
#include <pkglib.h>
#include <pkglocs.h>
#include <libadm.h>
#include <libinst.h>

static int	options;
static keystore_handle_t	keystore = NULL;

static void	usage(void);
static void	trap(int signo);

#define	PASSWD_CMDLINE \
		"## WARNING: USING <%s> MAKES PASSWORD " \
		"VISIBLE TO ALL USERS."

#define	PASSPHRASE_PROMPT	"Enter keystore password:"
#define	KEYSTORE_OPEN	"Retrieving signing certificates from keystore <%s>"
#define	PARAM_LEN		"Parameter <%s> too long"

int
main(int argc, char *argv[])
{
	int	c;
	void	(*func)();
	extern char	*optarg;
	extern int	optind;
	char		*keystore_alias = NULL;
	char		*keystore_file = NULL;
	boolean_t	create_sig = B_FALSE;
	char		*homedir = NULL;
	PKG_ERR		*err;
	int		ret, len, homelen;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) set_prog_name(argv[0]);

	while ((c = getopt(argc, argv, "ga:P:k:snio?")) != EOF) {
		switch (c) {
		case 'n':
			options |= PT_RENAME;
			break;

		case 'i':
			options |= PT_INFO_ONLY;
			break;

		case 'o':
			options |= PT_OVERWRITE;
			break;

		case 's':
			options |= PT_ODTSTREAM;
			break;

		case 'g':
			/* this should eventually be a PT_ option */
			create_sig = B_TRUE;
			break;

		case 'k':
			keystore_file = optarg;
			break;

		case 'a':
			keystore_alias = optarg;
			break;

		case 'P':
			set_passphrase_passarg(optarg);
			if (ci_strneq(optarg, "pass:", 5)) {
				/*
				 * passwords on the command line are highly
				 * insecure.  complain.
				 */
				logerr(gettext(PASSWD_CMDLINE), "pass:<pass>");
			}
			break;

		default:
			usage();
			return (1);
		}
	}
	func = signal(SIGINT, trap);
	if (func != SIG_DFL)
		(void) signal(SIGINT, func);
	(void) signal(SIGHUP, trap);
	(void) signal(SIGQUIT, trap);
	(void) signal(SIGTERM, trap);
	(void) signal(SIGPIPE, trap);
#ifndef SUNOS41
	(void) signal(SIGPWR, trap);
#endif

	if ((argc-optind) < 2) {
		usage();
		return (1);
	}

	if (create_sig) {
		sec_init();
		err = pkgerr_new();

		/* figure out which keystore to use */
		if (keystore_file == NULL) {
			if (geteuid() == 0) {
				/* we are superuser, so use their keystore */
				keystore_file = PKGSEC;
			} else {
				if ((homedir = getenv("HOME")) == NULL) {
				/*
				 * not superuser, but no home dir, so
				 * use superuser's keystore
				 */
					keystore_file = PKGSEC;
				} else {
				/* $HOME/.pkg/security\0 */
					homelen = strlen(homedir) + 15;
					keystore_file =
					    malloc(strlen(homedir) + 15);
					if (((len = snprintf(keystore_file,
					    homelen, "%s/%s", homedir,
					    ".pkg/security")) < 0) ||
					    (len >= homelen)) {
						logerr(gettext(PARAM_LEN),
						    "$HOME");
						quit(1);
					}
				}
			}
		}

		logerr(gettext(KEYSTORE_OPEN), keystore_file);

		set_passphrase_prompt(gettext(PASSPHRASE_PROMPT));

		/* open keystore for reading */
		if (open_keystore(err, keystore_file, get_prog_name(),
		    pkg_passphrase_cb, KEYSTORE_DFLT_FLAGS, &keystore) != 0) {
			pkgerr(err);
			pkgerr_free(err);
			quit(1);
		}

	} else {
		/* no signature, so don't use a keystore */
		keystore = NULL;
	}

	ret = pkgtrans(flex_device(argv[optind], 1),
	    flex_device(argv[optind+1], 1), &argv[optind+2], options,
	    keystore, keystore_alias);

	if (create_sig) {
		/* close keystore */
		if (close_keystore(err, keystore, NULL) != 0) {
			pkgerr(err);
			pkgerr_free(err);
			quit(1);
		}
		keystore = NULL;
	}

	quit(ret);
	/*NOTREACHED*/
}

void
quit(int retcode)
{
	PKG_ERR	*err;

	err = pkgerr_new();
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);
	(void) ds_close(1);
	(void) pkghead(NULL);
	if (keystore != NULL) {
		(void) close_keystore(err, keystore, NULL);
		pkgerr_free(err);
	}
	exit(retcode);
}

static void
trap(int signo)
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);

	if (signo == SIGINT) {
		progerr(gettext("aborted at user request.\n"));
		quit(3);
	}
	progerr(gettext("aborted by signal %d\n"), signo);
	quit(1);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-ionsg] [-k keystore] " \
	    "[-a alias] [-P password] srcdev dstdev [pkg [pkg...]]\n"),
	    get_prog_name());
}
