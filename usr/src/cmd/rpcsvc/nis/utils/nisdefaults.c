/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * A simple utility to tell you what the defaults are that will be
 * plugged into object creation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <rpcsvc/nis.h>

extern int key_secretkey_is_set_g();

static void
usage(cmd)
	char 	*cmd;
{
	fprintf(stderr, "usage: %s [-pdhgrtsav]\n", cmd);
	fprintf(stderr, " p = default principal name.\n");
	fprintf(stderr, " d = default domain name.\n");
	fprintf(stderr, " h = default host name.\n");
	fprintf(stderr, " g = default group name.\n");
	fprintf(stderr, " r = default access rights.\n");
	fprintf(stderr, " t = default time to live.\n");
	fprintf(stderr, " s = default search path.\n");
	fprintf(stderr, " a = all of the above (default).\n");
	fprintf(stderr, " v = verbose.\n");

	exit(1);
}

extern int optind;
extern char *optarg;

extern nis_object nis_default_obj;

int
main(int argc, char *argv[])
{
	nis_name	*result;
	int	c;
	ulong_t	secs, days, hrs, mins;
	int	i, verbose = 1,
		pa = 1, /* print everything */
		ph = 0,	/* print host */
		pd = 0,	/* print domain */
		pp = 0,	/* print principal */
		pr = 0,	/* print rights */
		pt = 0,	/* print ttl */
		pg = 0,	/* print group */
		ps = 0;	/* print search path */

	while ((c = getopt(argc, argv, "hpartgdsv")) != -1) {
		switch (c) {
		case 'v' :
			verbose = 50;
			break;
		case 'h' :
			pa = 0;
			ph++;
			verbose--;
			break;
		case 'p' :
			pa = 0;
			verbose--;
			pp++;
			break;
		case 'r' :
			pa = 0;
			verbose--;
			pr++;
			break;
		case 't' :
			pa = 0;
			verbose--;
			pt++;
			break;
		case 'g' :
			pa = 0;
			verbose--;
			pg++;
			break;
		case 'd' :
			pa = 0;
			verbose--;
			pd++;
			break;
		case 's' :
			pa = 0;
			verbose--;
			ps++;
			break;
		case 'a' :
			pa++;
			verbose--;
			break;
		case '?' :
			usage(argv[0]);
			break;
		}
	}

	if (verbose < 0)
		verbose = 0;
	nis_defaults_init(NULL);
	if (pa || pp) {
		if (verbose)
			printf("Principal Name : ");
		printf("%s", nis_default_obj.zo_owner);
		if (verbose && ! key_secretkey_is_set_g(0, 0))
			printf(" (not authenticated)");
		printf("\n");
	}
	if (pa || pd) {
		if (verbose)
			printf("Domain Name    : ");
		printf("%s\n", nis_local_directory());
	}
	if (pa || ph) {
		if (verbose)
			printf("Host Name      : ");
		printf("%s\n", nis_local_host());
	}
	if (pa || pg) {
		if (verbose)
			printf("Group Name     : ");
		if (strlen(nis_default_obj.zo_group) != 0)
			printf("%s\n", nis_default_obj.zo_group);
		else
			printf("%s\n", nis_local_group());
	}
	if (pa || pr) {
		if (verbose)
			printf("Access Rights  : ");
		nis_print_rights(nis_default_obj.zo_access);
		printf("\n");
	}
	if (pa || pt) {
		if (verbose)
			printf("Time to live   : ");
		secs = nis_default_obj.zo_ttl;
		days = secs / 86400;
		hrs = (secs - (days * 86400)) / 3600;
		mins = (secs - (days * 86400) - (hrs * 3600)) / 60;
		secs = secs % 60;
		if (verbose) {
			if (days)
				printf("%dD, ", days);
			printf("%02d:%02d:%02d\n", hrs, mins, secs);
		} else
			printf("%d\n", nis_default_obj.zo_ttl);
	}
	if (pa || ps) {
		result = nis_getnames("foo");
		if (verbose)
			printf("Search Path    : ");
		if (result && result[0]) {
			printf("%s\n", nis_domain_of(result[0]));
			i = 1;
			while (result[i]) {
				if (verbose)
					printf("                 ");
				printf("%s\n",
					nis_domain_of(result[i++]));
			}
		} else
			printf("**NONE**\n");
	}
	return (0);
}
