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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <locale.h>
#include <netdb.h>
#include <limits.h>
#include <smbsrv/libsmbns.h>

#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

char *whoami = NULL;

static void usage();

static
void
usage()
{
	fprintf(stderr,
	    gettext("Usage: %s [ -d fqdn ] [ -s server ]\n"), whoami);
	fprintf(stderr,
	    gettext("\t-d\tThe fully qualified domain of the client\n"));
	fprintf(stderr, gettext("\t-s\tThe domain controller to join\n"));
	fprintf(stderr,
	    gettext("\tstdin is used to read in the password or \n"));
	fprintf(stderr, gettext("\tthe password is prompted for.\n"));

	exit(1);
}

int
main(int argc, char **argv)
{
	char fqdn[MAXHOSTNAMELEN], server[MAXHOSTNAMELEN];
	char *newpw;
	int c, ret = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	whoami = argv[0];

	while ((c = getopt(argc, argv, "d:s:")) != -1) {
		switch (c) {
		case 'd':
			(void) strncpy(fqdn, optarg, sizeof (fqdn));
			break;
		case 's':
			(void) strncpy(server, optarg, sizeof (server));
			break;
		default:
			usage();
			break;
		}
	}

	if (argc != optind)
		usage();

	if (!isatty(fileno(stdin))) {
		char buf[PASS_MAX + 1];

		if (scanf("%" VAL2STR(PASS_MAX) "s", &buf) != 1) {
			fprintf(stderr,
			    gettext("Couldn't read new password\n"));
			exit(1);
		}

		newpw = strdup(buf);
		if (newpw == NULL) {
			fprintf(stderr, gettext("Couldn't allocate memory\n"));
			exit(1);
		}
	} else {
		newpw = getpassphrase(gettext("Enter new password: "));
		if (newpw == NULL) {
			fprintf(stderr,
			    gettext("Couldn't read new password\n"));
			exit(1);
		}

		newpw = strdup(newpw);
		if (newpw == NULL) {
			fprintf(stderr, gettext("Couldn't allocate memory\n"));
			exit(1);
		}
	}

	/*
	 * Set the SMF properties for smb for later use.
	 */
	ret = smb_setdomainprops(fqdn, server, newpw);

	free(newpw);

	return (ret);
}
