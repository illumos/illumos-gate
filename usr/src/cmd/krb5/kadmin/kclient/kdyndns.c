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
#include <locale.h>
#include <netdb.h>
#include <smbsrv/libsmbns.h>

char *whoami = NULL;

static void usage();

static
void
usage()
{
	fprintf(stderr, gettext("Usage: %s -d fqdn\n"), whoami);
	fprintf(stderr,
	    gettext("\t-d\tThe fully qualified domain of the client\n"));
	exit(1);
}

int
main(int argc, char **argv)
{
	char fqdn[MAXHOSTNAMELEN];
	int c, ret = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	whoami = argv[0];

	while ((c = getopt(argc, argv, "d:")) != -1) {
		switch (c) {
		case 'd':
			(void) strncpy(fqdn, optarg, sizeof (fqdn));
			break;
		default:
			usage();
			break;
		}
	}

	if (argc != optind)
		usage();

	/*
	 * Update DNS RR for the client using DynDNS.  First it tries the
	 * unauthed version then it tries the GSS version.
	 */
	ret = dyndns_update(fqdn);

	return (ret);
}
