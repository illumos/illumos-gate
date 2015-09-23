/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <uuid/uuid.h>
#include <getopt.h>
#include <locale.h>

static char *progname;
static int rflag, tflag;
static char uu_string[UUID_PRINTABLE_STRING_LENGTH];

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage: %s [-r | -t] [-o filename]\n"), progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	FILE *out;
	uuid_t  uu = { 0 };
	int c;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	progname = basename(argv[0]);
	out = stdout;
	while ((c = getopt(argc, argv, ":rto:")) != EOF) {
		switch ((char)c) {
		case 'r':
			rflag++;
			break;
		case 't':
			tflag++;
			break;
		case 'o':
			if ((out = fopen(optarg, "w")) == NULL) {
				(void) fprintf(stderr, gettext(
				    "%s: cannot open %s\n"),
				    progname, optarg);
				return (1);
			}
			break;
		case '?': /* fallthrough */
		default:
			usage();
		}
	}

	if ((rflag && tflag) || optind != argc) {
		usage();
	}

	if (rflag) {
		/* DCE version 4 */
		uuid_generate_random(uu);
	} else if (tflag) {
		/* DCE version 1 */
		uuid_generate_time(uu);
	} else {
		uuid_generate(uu);
	}

	if (uuid_is_null(uu) != 0) {
		(void) fprintf(stderr, gettext(
		    "%s: failed to "
		    "generate uuid\n"), progname);
		exit(1);
	}

	uuid_unparse(uu, uu_string);

	(void) fprintf(out, "%s\n", uu_string);

	if (out != NULL && out != stdout)
		(void) fclose(out);

	return (0);
}
