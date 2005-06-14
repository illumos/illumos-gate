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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <string.h>

static char options[] = "ghsadlfn:x:w:D:";

static void
usage(void)
{
	(void) fprintf(stderr, "%s\n", gettext("usage:"));
	(void) fprintf(stderr, "\t%s\n",
		gettext("nispasswd [-ghs] [-D domainname] [username]"));
	(void) fprintf(stderr, "\tnispasswd -a\n");
	(void) fprintf(stderr, "\t%s\n",
		gettext("nispasswd [-D domainname] [-d [username] ]"));
	(void) fprintf(stderr, "\t%s\n",
		gettext("nispasswd [-l] -[f] -[n min] [-x max] [-w warn] "
			"[-D domainname] username"));
	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, "%s\n", gettext("NOTE:"));
	(void) fprintf(stderr, "%s\n", gettext("yppasswd and nispasswd have "
			"been replaced by the new passwd command."));
	(void) fprintf(stderr, "%s\n",
		gettext("See passwd(1) for more information."));
}

int
main(int argc, char *argv[])
{
	char **new_argv;
	char **p;
	int c;
	int max_opts, nr_opts;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * reserve space for maximum number of arguments we accept
	 * together with "-r nisplus"
	 */
	max_opts = strlen(options) + 2;

	/* don't forget trailing NULL */
	new_argv = malloc((max_opts + 1) * sizeof (char *));

	if (new_argv == NULL) {
		(void) fprintf(stderr, "%s\n", gettext("Out of memory."));
		exit(1);
	}
	p = new_argv;
	*(p++) = "nispasswd";
	*(p++) = "-r";
	*(p++) = "nisplus";

	nr_opts = 3;

	while ((c = getopt(argc, argv, options)) != EOF) {
		if (nr_opts >= max_opts) {
			usage();
			exit(1);
		}
		nr_opts++;
		switch (c) {
		case 'g':
			*(p++) = "-g";
			break;
		case 's':
			*(p++) = "-e";	/* map -s to -e */
			break;
		case 'h':
			*(p++) = "-h";
			break;
		case 'l':
			*(p++) = "-l";
			break;
		case 'a':
			*(p++) = "-sa";	/* map -a to -sa */
			break;
		case 'd':
			*(p++) = "-s";	/* map -d to -s */
			break;
		case 'f':
			*(p++) = "-f";
			break;
		case 'n':
			*(p++) = "-n";
			nr_opts++;
			if (nr_opts >= max_opts) {
				usage();
				exit(1);
			}
			*(p++) = optarg;
			break;
		case 'x':
			*(p++) = "-x";
			nr_opts++;
			if (nr_opts >= max_opts) {
				usage();
				exit(1);
			}
			*(p++) = optarg;
			break;
		case 'w':
			*(p++) = "-w";
			nr_opts++;
			if (nr_opts >= max_opts) {
				usage();
				exit(1);
			}
			*(p++) = optarg;
			break;
		case 'D':
			*(p++) = "-D";
			nr_opts++;
			if (nr_opts >= max_opts) {
				usage();
				exit(1);
			}
			*(p++) = optarg;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (optind < argc)
		*(p++) = argv[optind];
	*p = NULL;

	(void) execvp("/bin/passwd", new_argv);
	perror("/bin/passwd");
	return (1);
}
